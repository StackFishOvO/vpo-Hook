#!/usr/bin/env node
/*
 * gen_wrappers.js -- 读取 signatures.json，生成二进制 hook 的 wrapper 源码。
 *
 * 与 gen_wrappers.py 完全等价：两个生成器对同一份 signatures.json 必须输出
 * 完全相同的 wrapper.c（这样无论用哪个语言的环境 init 都能得到一致的 hook 库）。
 *
 * 用法：
 *   node gen_wrappers.js signatures.json -o wrapper.c
 */

'use strict';

const fs = require('fs');

// ---------------------------------------------------------------------------
// macOS 平台适配：真实符号名映射（与 gen_wrappers.py 保持一致）。
// ---------------------------------------------------------------------------
const MACOS_REAL_SYMBOL = {
  open: '__open',
  openat: '__openat',
  unlink: '__unlink',
  unlinkat: '__unlinkat',
  rename: '__rename',
  renameat: '__renameat',
  rmdir: '__rmdir',
  connect: '__connect',
  bind: '__bind',
  sendto: '__sendto',
  recvfrom: '__recvfrom',
  fork: '__fork',
  vfork: '__vfork',
  execve: '__execve',
  kill: '__kill',
};

const MACOS_NOCANCEL_SYMBOL = {
  read: 'read$NOCANCEL',
  write: 'write$NOCANCEL',
};

const MACOS_NOCANCEL_INTERPOSE = {
  open: ['open$NOCANCEL', 'open_nocancel', '__open_nocancel'],
  openat: ['openat$NOCANCEL', 'openat_nocancel', '__openat_nocancel'],
};

const MACOS_SKIP = new Set([
  'close', 'mmap', 'mprotect',
  'mkdir', 'socket', 'send', 'recv',
  'execv', 'execvp', 'system', 'popen', 'dlopen',
]);

const HEADER = String.raw`/* 自动生成，请勿手改。来源: signatures.json，生成器: gen_wrappers */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <spawn.h>

/* ---------------------------------------------------------------------------
 * 策略引擎 ABI：见 vpo_hook.h（与策略引擎 policy.c 共用，避免重复定义）。
 * ------------------------------------------------------------------------- */
#include "vpo_hook.h"

/* ---------------------------------------------------------------------------
 * macOS DYLD_INTERPOSE 宏
 * ------------------------------------------------------------------------- */
#define DYLD_INTERPOSE(_replacement, _original) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *original; \
    } _interpose_##_original \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_original \
    };

`;

const LINUX_HEADER = String.raw`/* 自动生成，请勿手改。来源: signatures.json，生成器: gen_wrappers（Linux 版） */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <spawn.h>

/* ---------------------------------------------------------------------------
 * 策略引擎 ABI：见 vpo_hook.h（与策略引擎 policy.c 共用）。
 * ------------------------------------------------------------------------- */
#include "vpo_hook.h"

`;

// ---------------------------------------------------------------------------
function parseSignature(signature) {
  const head = signature.split('(')[0].trim();
  const m = head.match(/([A-Za-z_]\w*)\s*$/);
  if (!m) throw new Error(`cannot parse signature: ${signature}`);
  const name = m[1];
  const ret = head.slice(0, m.index).trim();
  return { ret, name };
}

function normalizeType(t) {
  return t.split('[]').join('*');
}

function isVariadic(meta) {
  return 'variadic_mode' in meta;
}

function platformEnabled(meta, platform) {
  return !meta.platforms || meta.platforms.includes(platform);
}

function genArgsPacking(args) {
  const lines = ['    vpo_args vargs;', '    memset(&vargs, 0, sizeof(vargs));'];
  let pathIdx = 0;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const nxt = i + 1 < args.length ? args[i + 1] : null;
    if (a.check === 'path') {
      const field = pathIdx === 0 ? 'path' : 'path2';
      lines.push(`    vargs.${field} = ${a.name};`);
      pathIdx++;
    } else if (a.check === 'sockaddr') {
      lines.push(`    vargs.addr = ${a.name};`);
      if (nxt) {
        if (nxt.type.includes('*')) lines.push(`    vargs.addrlen = *${nxt.name};`);
        else lines.push(`    vargs.addrlen = ${nxt.name};`);
      }
    } else if (a.check === 'buffer') {
      lines.push(`    vargs.buf = ${a.name};`);
      if (nxt) lines.push(`    vargs.buflen = ${nxt.name};`);
      if (args.length) lines.push(`    vargs.fd = ${args[0].name};`);
    }
  }
  return lines;
}

function envModeParts(meta, argNames, variadic, denyRet, inVar) {
  const mode = meta.env_mode;
  const names = [...argNames];
  let pre = [];
  let post = [];

  if (mode === 'replace') {
    const envp = meta.envp_arg || 'envp';
    for (let i = 0; i < names.length; i++) {
      if (names[i] === envp) names[i] = 'vpo_envp';
    }
    pre = [
      `    char **vpo_envp = vpo_envp_merge(${envp});`,
      '    if (!vpo_envp) {',
      `        ${inVar} = 0;`,
      '        errno = ENOMEM;',
      `        return ${denyRet};`,
      '    }',
    ];
    post = [
      '    int vpo_saved_errno = errno;',
      '    vpo_envp_free(vpo_envp);',
      `    ${inVar} = 0;`,
      '    errno = vpo_saved_errno;',
    ];
  } else if (mode === 'reinject') {
    pre = [
      '    if (vpo_reinject_environ() != 0) {',
      `        ${inVar} = 0;`,
      '        errno = ENOMEM;',
      `        return ${denyRet};`,
      '    }',
    ];
  }

  const callNames = variadic ? [...names, 'mode'] : names;
  return { pre, callArgs: callNames.join(', '), post };
}

function genStaticWrapper(name, meta, realSymbol, interposeCname, asmLabel, suffix) {
  const { ret } = parseSignature(meta.signature);
  const args = meta.args || [];
  const variadic = isVariadic(meta);

  const argTypes = args.map((a) => normalizeType(a.type));
  const argDecls = args.map((a) => `${normalizeType(a.type)} ${a.name}`);
  const argNames = args.map((a) => a.name);

  const typedefArgs = variadic
    ? [...argTypes, 'mode_t'].join(', ')
    : (argTypes.length ? argTypes.join(', ') : 'void');
  const wrapperArgs = variadic
    ? `${argDecls.join(', ')}, ...`
    : (argDecls.length ? argDecls.join(', ') : 'void');
  const callArgs = variadic
    ? [...argNames, 'mode'].join(', ')
    : argNames.join(', ');
  const denyRet = ret.includes('*') ? 'NULL' : '-1';

  const variadicParse = [];
  if (variadic) {
    const lastArg = argNames[argNames.length - 1];
    variadicParse.push(
      '    mode_t mode = 0;',
      '    if (flags & O_CREAT) {',
      '        va_list ap;',
      `        va_start(ap, ${lastArg});`,
      '        mode = (mode_t)va_arg(ap, int);',
      '        va_end(ap);',
      '    }',
    );
  }

  const fnName = `my_${name}${suffix}`;
  const inVar = `vpo_in_${name}${suffix}`;
  const { pre: envPre, callArgs: callArgsMain, post: envPost } = envModeParts(
    meta, argNames, variadic, denyRet, inVar,
  );
  const useFork = !!meta.use_fork;
  const reentryCall = useFork
    ? 'fork()'
    : (variadic
      ? `${realSymbol}(${[...argNames, '0'].join(', ')})`
      : `${realSymbol}(${callArgs})`);
  const mainCall = useFork ? 'fork()' : `${realSymbol}(${callArgsMain})`;

  const lines = [];
  if (asmLabel) {
    lines.push(`extern ${ret} ${interposeCname}(${typedefArgs}) __asm("_" "${asmLabel}");`);
  }
  lines.push(`extern ${ret} ${realSymbol}(${typedefArgs});`);
  lines.push(`static __thread int ${inVar} = 0;`);
  lines.push('');
  lines.push(`${ret} ${fnName}(${wrapperArgs}) {`);
  lines.push(`    if (${inVar}) {`);
  lines.push(`        return ${reentryCall};`);
  lines.push('    }');
  lines.push(`    ${inVar} = 1;`);
  lines.push(...variadicParse);
  lines.push('    vpo_action action = { .allow = 1 };');
  lines.push(...genArgsPacking(args));
  lines.push(`    vpo_check("${name}", &vargs, &action);`);
  const firstPath = args.find((a) => a.check === 'path');
  lines.push('    if (!action.allow) {');
  if (firstPath) {
    lines.push('        if (!action.rewrite) {');
    lines.push(`            ${inVar} = 0;`);
    lines.push('            errno = EPERM;');
    lines.push(`            return ${denyRet};`);
    lines.push('        }');
    lines.push(`        ${firstPath.name} = action.rewrite;`);
  } else {
    lines.push(`        ${inVar} = 0;`);
    lines.push('        errno = EPERM;');
    lines.push(`        return ${denyRet};`);
  }
  lines.push('    }');
  lines.push(...envPre);
  lines.push(`    ${ret} result = ${mainCall};`);
  lines.push(...envPost);
  if (envPost.length === 0) {
    lines.push(`    ${inVar} = 0;`);
  }
  lines.push('    return result;');
  lines.push('}');
  lines.push(`DYLD_INTERPOSE(${fnName}, ${interposeCname})`);
  return lines;
}

function genWrapper(name, meta) {
  const { ret } = parseSignature(meta.signature);
  const args = meta.args || [];
  const variadic = isVariadic(meta);
  const realSymbol = MACOS_REAL_SYMBOL[name];

  const argTypes = args.map((a) => normalizeType(a.type));
  const argDecls = args.map((a) => `${normalizeType(a.type)} ${a.name}`);
  const argNames = args.map((a) => a.name);

  const typedefArgs = variadic
    ? [...argTypes, 'mode_t'].join(', ')
    : (argTypes.length ? argTypes.join(', ') : 'void');
  const wrapperArgs = variadic
    ? `${argDecls.join(', ')}, ...`
    : (argDecls.length ? argDecls.join(', ') : 'void');
  const callArgs = variadic
    ? [...argNames, 'mode'].join(', ')
    : argNames.join(', ');
  const denyRet = ret.includes('*') ? 'NULL' : '-1';
  const inVar = `vpo_in_${name}`;
  const { pre: envPre, callArgs: callArgsMain, post: envPost } = envModeParts(
    meta, argNames, variadic, denyRet, inVar,
  );

  const variadicParse = [];
  if (variadic) {
    const lastArg = argNames[argNames.length - 1];
    variadicParse.push(
      '    mode_t mode = 0;',
      '    if (flags & O_CREAT) {',
      '        va_list ap;',
      `        va_start(ap, ${lastArg});`,
      '        mode = (mode_t)va_arg(ap, int);',
      '        va_end(ap);',
      '    }',
    );
  }

  const lines = [];
  lines.push(`/* ---- ${name} : ${meta.signature} ---- */`);

  if (realSymbol) {
    lines.push(...genStaticWrapper(name, meta, realSymbol, name, null, ''));
    const nocancel = MACOS_NOCANCEL_INTERPOSE[name];
    if (nocancel) {
      const [pub, cname, realNc] = nocancel;
      lines.push(`/* ---- ${name} 的 $NOCANCEL 变体 ---- */`);
      lines.push(...genStaticWrapper(name, meta, realNc, cname, pub, '_nocancel'));
    }
    lines.push('');
  } else {
    lines.push(`typedef ${ret} (*vpo_real_${name}_t)(${typedefArgs});`);
    lines.push(`static vpo_real_${name}_t vpo_real_${name} = NULL;`);
    lines.push(`static __thread int vpo_in_${name} = 0;`);
    lines.push('');
    lines.push(`${ret} my_${name}(${wrapperArgs}) {`);
    lines.push(`    if (vpo_in_${name}) {`);
    lines.push(
      variadic
        ? `        return vpo_real_${name}(${[...argNames, '0'].join(', ')});`
        : `        return vpo_real_${name}(${callArgs});`,
    );
    lines.push('    }');
    lines.push(`    vpo_in_${name} = 1;`);
    lines.push(...variadicParse);
    lines.push('    vpo_action action = { .allow = 1 };');
    lines.push(...genArgsPacking(args));
    lines.push(`    vpo_check("${name}", &vargs, &action);`);
    lines.push('    if (!action.allow) {');
    lines.push(`        vpo_in_${name} = 0;`);
    lines.push('        errno = EPERM;');
    lines.push(`        return ${denyRet};`);
    lines.push('    }');
    lines.push(...envPre);
    const lookupMode = name in MACOS_NOCANCEL_SYMBOL ? 'RTLD_DEFAULT' : 'RTLD_NEXT';
    const lookupSym = MACOS_NOCANCEL_SYMBOL[name] || name;
    lines.push(`    if (!vpo_real_${name}) {`);
    lines.push(`        vpo_real_${name} = (vpo_real_${name}_t)dlsym(${lookupMode}, "${lookupSym}");`);
    lines.push('    }');
    lines.push(`    if (!vpo_real_${name} || (void *)vpo_real_${name} == (void *)my_${name}) {`);
    if (envPost.length > 0) {
      lines.push('        vpo_envp_free(vpo_envp);');
    }
    lines.push(`        ${inVar} = 0;`);
    lines.push('        errno = ENOSYS;');
    lines.push(`        return ${denyRet};`);
    lines.push('    }');
    lines.push(`    ${ret} result = vpo_real_${name}(${callArgsMain});`);
    lines.push(...envPost);
    if (envPost.length === 0) {
      lines.push(`    ${inVar} = 0;`);
    }
    lines.push('    return result;');
    lines.push('}');
    lines.push(`DYLD_INTERPOSE(my_${name}, ${name})`);
    lines.push('');
  }

  return lines.join('\n');
}

function genLinuxWrapper(name, meta, cName = name) {
  const c = cName || name;
  const { ret } = parseSignature(meta.signature);
  const args = meta.args || [];
  const variadic = isVariadic(meta);

  const argTypes = args.map((a) => normalizeType(a.type));
  const argDecls = args.map((a) => `${normalizeType(a.type)} ${a.name}`);
  const argNames = args.map((a) => a.name);

  const typedefArgs = variadic
    ? [...argTypes, 'mode_t'].join(', ')
    : (argTypes.length ? argTypes.join(', ') : 'void');
  const wrapperArgs = variadic
    ? `${argDecls.join(', ')}, ...`
    : (argDecls.length ? argDecls.join(', ') : 'void');
  const callArgs = variadic
    ? [...argNames, 'mode'].join(', ')
    : argNames.join(', ');
  const denyRet = ret.includes('*') ? 'NULL' : '-1';
  const inVar = `vpo_in_${c}`;
  const { pre: envPre, callArgs: callArgsMain, post: envPost } = envModeParts(
    meta, argNames, variadic, denyRet, inVar,
  );
  const useFork = !!meta.use_fork;
  const reentryCall = useFork
    ? 'fork()'
    : (variadic
      ? `vpo_real_${c}(${[...argNames, '0'].join(', ')})`
      : `vpo_real_${c}(${callArgs})`);
  const mainCall = useFork ? 'fork()' : `vpo_real_${c}(${callArgsMain})`;

  const variadicParse = [];
  if (variadic) {
    const lastArg = argNames[argNames.length - 1];
    variadicParse.push(
      '    mode_t mode = 0;',
      '    if (flags & O_CREAT) {',
      '        va_list ap;',
      `        va_start(ap, ${lastArg});`,
      '        mode = (mode_t)va_arg(ap, int);',
      '        va_end(ap);',
      '    }',
    );
  }

  const firstPath = args.find((a) => a.check === 'path');

  const lines = [];
  lines.push(`/* ---- ${c} : ${meta.signature} ---- */`);
  lines.push(`typedef ${ret} (*vpo_real_${c}_t)(${typedefArgs});`);
  lines.push(`static vpo_real_${c}_t vpo_real_${c} = NULL;`);
  lines.push(`static __thread int vpo_in_${c} = 0;`);
  lines.push('');
  lines.push(`${ret} ${c}(${wrapperArgs}) {`);
  lines.push(`    if (vpo_in_${c}) {`);
  lines.push(`        return ${reentryCall};`);
  lines.push('    }');
  lines.push(`    vpo_in_${c} = 1;`);
  lines.push(...variadicParse);
  lines.push('    vpo_action action = { .allow = 1 };');
  lines.push(...genArgsPacking(args));
  lines.push(`    vpo_check("${c}", &vargs, &action);`);
  lines.push('    if (!action.allow) {');
  if (firstPath) {
    lines.push('        if (!action.rewrite) {');
    lines.push(`            vpo_in_${c} = 0;`);
    lines.push('            errno = EPERM;');
    lines.push(`            return ${denyRet};`);
    lines.push('        }');
    lines.push(`        ${firstPath.name} = action.rewrite;`);
  } else {
    lines.push(`        vpo_in_${c} = 0;`);
    lines.push('        errno = EPERM;');
    lines.push(`        return ${denyRet};`);
  }
  lines.push('    }');
  lines.push(...envPre);
  lines.push(`    if (!vpo_real_${c}) {`);
  lines.push(`        vpo_real_${c} = (vpo_real_${c}_t)dlsym(RTLD_NEXT, "${c}");`);
  lines.push('    }');
  lines.push(`    ${ret} result = ${mainCall};`);
  lines.push(...envPost);
  if (envPost.length === 0) {
    lines.push(`    ${inVar} = 0;`);
  }
  lines.push('    return result;');
  lines.push('}');
  return lines.join('\n');
}

function countLinuxWrappers(data) {
  const functions = data.functions || {};
  let n = 0;
  for (const meta of Object.values(functions)) {
    if (!platformEnabled(meta, 'linux')) continue;
    n += 1 + (meta.linux_aliases || []).length;
  }
  return n;
}

function macosSkipped(data) {
  const functions = data.functions || {};
  return Object.keys(functions).filter(
    (name) => MACOS_SKIP.has(name) || !platformEnabled(functions[name], 'darwin'),
  );
}

function generateLinux(data, onlyNames = null) {
  const functions = data.functions || {};
  const body = [LINUX_HEADER];
  for (const [name, meta] of Object.entries(functions)) {
    if (!platformEnabled(meta, 'linux')) continue;
    if (onlyNames && !onlyNames.has(name)) continue;
    body.push(genLinuxWrapper(name, meta));
    for (const alias of meta.linux_aliases || []) {
      body.push(genLinuxWrapper(alias, meta, alias));
    }
  }
  return body.join('');
}

function generate(data, platform, onlyNames = null) {
  if (platform === 'linux') return generateLinux(data, onlyNames);
  const functions = data.functions || {};
  const body = [HEADER];
  const skipped = new Set(macosSkipped(data));
  for (const [name, meta] of Object.entries(functions)) {
    if (skipped.has(name)) continue;
    if (onlyNames && !onlyNames.has(name)) continue;
    body.push(genWrapper(name, meta));
  }
  return body.join('');
}

function main() {
  const argv = process.argv.slice(2);
  let sigPath = null;
  let outPath = 'wrapper.c';
  let platform = 'darwin';
  let only = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '-o') {
      outPath = argv[++i];
    } else if (argv[i] === '-p' || argv[i] === '--platform') {
      platform = argv[++i];
    } else if (argv[i] === '--only') {
      only = new Set((argv[++i] || '').split(',').filter(Boolean));
    } else if (!sigPath) {
      sigPath = argv[i];
    }
  }
  if (!sigPath) {
    console.error('用法: node gen_wrappers.js signatures.json [-o wrapper.c] [-p darwin|linux] [--only a,b,c]');
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
  const code = generate(data, platform, only);
  fs.writeFileSync(outPath, code);

  const names = Object.keys(data.functions || {});
  if (platform === 'linux') {
    const n = countLinuxWrappers(data);
    console.log(`gen_wrappers: 已生成 ${n} 个 wrapper (Linux)${only ? `，subset=${only.size}` : ''} -> ${outPath}`);
  } else {
    const skipped = macosSkipped(data);
    console.log(`gen_wrappers: 已生成 ${names.length - skipped.length} 个 wrapper -> ${outPath}`);
    if (skipped.length) {
      console.log(`gen_wrappers: 跳过 ${skipped.length} 个 (macOS 无法安全 interpose): ${skipped.join(', ')}`);
    }
  }
}

main();
