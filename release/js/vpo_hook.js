#!/usr/bin/env node
/*
 * vpo-hook 启动器（Node 版）。
 *
 * 与 py/vpo_hook.py 完全等价：init / run / status。
 * Node 用户无需 Python 环境即可使用。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// ---------------------------------------------------------------------------
const HERE = __dirname; // js/
const HOOK_DIR = path.join(HERE, 'obj_hook');
const PY_PLAINTEXT = path.join(HERE, 'py_plaintext');
const JS_PLAINTEXT = path.join(HERE, 'plaintext');
const CONFIG_DIR = path.join(os.homedir(), '.vpo-hook');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.yaml');
const TEMPLATE_CONFIG = path.join(HOOK_DIR, 'config.yaml');

// 只匹配 shims 目录本身，不能匹配 /.pyenv/ 整棵子树（否则误伤
// ~/.pyenv/versions/*/bin/python3 这类真实二进制）。
const SHIM_DIR_MARKERS = ['/shims/', '/.asdf/shims/', '/.rbenv/shims/', '/.nodenv/shims/'];

// ---------------------------------------------------------------------------
function findCC() {
  for (const cc of ['clang', 'cc', 'gcc']) {
    const r = spawnSync('which', [cc], { stdio: 'pipe' });
    if (r.status === 0) return cc;
  }
  return null;
}

function buildHook() {
  const plat = process.platform;
  if (plat !== 'darwin' && plat !== 'linux') {
    console.error(`[vpo-hook] 不支持的平台: ${process.platform}（仅支持 macOS / Linux）`);
    process.exit(1);
  }
  const cc = findCC();
  if (!cc) {
    console.error('[vpo-hook] 未找到 C 编译器（需要 clang/gcc/cc），请先安装');
    process.exit(1);
  }

  const gen = path.join(HOOK_DIR, 'gen_wrappers.js');
  const sig = path.join(HOOK_DIR, 'signatures.json');
  const wrapper = path.join(HOOK_DIR, 'wrapper.c');
  const policy = path.join(HOOK_DIR, 'policy.c');

  const genPlatform = plat === 'linux' ? 'linux' : 'darwin';
  const genResult = spawnSync('node', [gen, sig, '-o', wrapper, '-p', genPlatform], {
    stdio: 'inherit',
  });
  if (genResult.error || genResult.status !== 0) {
    console.error('[vpo-hook] wrapper 生成失败');
    process.exit(1);
  }

  const out =
    plat === 'darwin'
      ? path.join(HOOK_DIR, 'libvpo_hook.dylib')
      : path.join(HOOK_DIR, 'libvpo_hook.so');
  const cmd =
    plat === 'darwin'
      ? [cc, '-dynamiclib', '-o', out, wrapper, policy]
      : [cc, '-shared', '-fPIC', '-o', out, wrapper, policy, '-ldl'];
  const buildResult = spawnSync(cmd[0], cmd.slice(1), { stdio: 'inherit', cwd: HOOK_DIR });
  if (buildResult.error || buildResult.status !== 0) {
    console.error('[vpo-hook] hook 库编译失败');
    process.exit(1);
  }
  return out;
}

// ---------------------------------------------------------------------------
function cmdInit() {
  console.log(`[vpo-hook] 平台检测: ${process.platform} ${os.arch()}`);
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.copyFileSync(TEMPLATE_CONFIG, CONFIG_PATH);
    console.log(`[vpo-hook] 已生成默认配置: ${CONFIG_PATH}`);
  } else {
    console.log(`[vpo-hook] 配置已存在: ${CONFIG_PATH}`);
  }
  const honeypotScript = path.join(CONFIG_DIR, 'honeypot.js');
  if (!fs.existsSync(honeypotScript)) {
    fs.copyFileSync(path.join(HOOK_DIR, 'honeypot.js'), honeypotScript);
    console.log(`[vpo-hook] 已生成蜜罐脚本: ${honeypotScript}`);
  }
  const lib = buildHook();
  console.log(`[vpo-hook] hook 库已编译: ${lib}`);
  if (!fs.existsSync(lib)) {
    console.error('[vpo-hook] 自检失败：hook 库未生成');
    return 1;
  }
  console.log('[vpo-hook] 自检通过');
  return 0;
}

function parseDenyPaths(text) {
  const paths = [];
  let inDeny = false;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s.startsWith('deny_paths:')) {
      inDeny = true;
      continue;
    }
    if (inDeny) {
      if (s.startsWith('- ')) {
        const p = s.slice(2).trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
        if (p) paths.push(p);
      } else if (s && !s.startsWith('-')) {
        inDeny = false;
      }
    }
  }
  return paths;
}

function parsePlaintextApis(text, lang) {
  const apis = [];
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length && !lines[i].trim().startsWith('plaintext:')) i++;
  i++;
  while (i < lines.length) {
    const line = lines[i];
    const s = line.trim();
    if (line && !line.startsWith(' ') && !line.startsWith('\t')) break;
    if (s.startsWith(`${lang}:`)) {
      i++;
      while (i < lines.length) {
        const s2 = lines[i].trim();
        if (s2.startsWith('- ')) {
          apis.push(s2.slice(2).trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1'));
          i++;
        } else {
          break;
        }
      }
      break;
    }
    i++;
  }
  return apis;
}

function parseAudit(text, lang) {
  let enabled = false;
  let log = '';
  const classes = [];
  let inAudit = false;
  let inClasses = false;
  let inLang = false;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s.startsWith('audit:')) {
      inAudit = true;
      continue;
    }
    if (!inAudit) continue;
    if (line && !line.startsWith(' ') && !line.startsWith('\t') && s) {
      inAudit = false;
      continue;
    }
    if (s.startsWith('enabled:')) {
      const value = s
        .slice('enabled:'.length)
        .split('#')[0]
        .trim()
        .replace(/^["']|["']$/g, '')
        .toLowerCase();
      enabled = ['true', 'yes', 'on', '1'].includes(value);
    } else if (s.startsWith('log:')) {
      log = s
        .split(':')
        .slice(1)
        .join(':')
        .split('#')[0]
        .trim()
        .replace(/^["']|["']$/g, '');
    } else if (s.startsWith('classes:')) {
      inClasses = true;
    } else if (inClasses && lang && s.startsWith(`${lang}:`)) {
      inLang = true;
    } else if (inLang) {
      if (s.startsWith('- ')) {
        const cls = s
          .slice(2)
          .split('#')[0]
          .trim()
          .replace(/^["']|["']$/g, '');
        if (cls) classes.push(cls);
      } else if (s && !s.startsWith('-')) {
        inLang = false;
      }
    }
  }
  return { enabled, log, classes };
}

function parseYamlList(text, key) {
  const result = [];
  let inSection = false;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s.startsWith(`${key}:`)) {
      inSection = true;
      continue;
    }
    if (inSection) {
      if (s.startsWith('- ')) {
        result.push(s.slice(2).trim().replace(/^["']|["']$/g, ''));
      } else if (s && !s.startsWith('-')) {
        inSection = false;
      }
    }
  }
  return result;
}

function parseHoneypotMap(text) {
  const result = {};
  let inMap = false;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s.startsWith('honeypot_map:')) {
      inMap = true;
      continue;
    }
    if (inMap) {
      if (s.startsWith('"') || s.startsWith("'")) {
        const colonIdx = s.indexOf(':');
        if (colonIdx > 0) {
          const key = s.slice(0, colonIdx).trim().replace(/^["']|["']$/g, '');
          const value = s.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
          if (key && value) result[key] = value;
        }
      } else if (s && !s.startsWith(' ') && !s.startsWith('\t')) {
        inMap = false;
      }
    }
  }
  return result;
}

function expandHome(p) {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

function isShim(cand) {
  if (SHIM_DIR_MARKERS.some((m) => cand.includes(m))) return true;
  let fd = null;
  try {
    fd = fs.openSync(cand, 'r');
    const buf = Buffer.alloc(2);
    const n = fs.readSync(fd, buf, 0, 2, 0);
    return n === 2 && buf.toString() === '#!';
  } catch (_e) {
    return false;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

function resolveExecutable(cmd) {
  if (cmd.startsWith('/')) return cmd;
  if (cmd.includes('/')) return cmd;
  const paths = (process.env.PATH || '').split(':');
  for (const p of paths) {
    if (!p) continue;
    const cand = path.join(p, cmd);
    try {
      fs.accessSync(cand, fs.constants.X_OK);
    } catch (_e) {
      continue;
    }
    if (isShim(cand)) continue;
    return cand;
  }
  return cmd;
}

// ---------------------------------------------------------------------------
function cmdRun(args) {
  let quiet = process.env.VPO_HOOK_QUIET === '1';
  let verbose = process.env.VPO_HOOK_VERBOSE === '1';
  while (args.length && ['-q', '--quiet', '-v', '--verbose'].includes(args[0])) {
    if (args[0] === '-q' || args[0] === '--quiet') quiet = true;
    else verbose = true;
    args.shift();
  }
  if (verbose) quiet = false;
  const log = (...parts) => {
    if (!quiet) console.error(...parts);
  };

  if (args.length === 0) {
    console.error('[vpo-hook] 用法: vpo-hook run [-q|-v] <command...>');
    return 1;
  }
  const plat = process.platform;
  const lib =
    plat === 'darwin'
      ? path.join(HOOK_DIR, 'libvpo_hook.dylib')
      : path.join(HOOK_DIR, 'libvpo_hook.so');
  if (!fs.existsSync(lib)) {
    console.error('[vpo-hook] hook 库不存在，请先运行: vpo-hook init');
    return 1;
  }

  const configText = fs.existsSync(CONFIG_PATH) ? fs.readFileSync(CONFIG_PATH, 'utf8') : '';
  const denyPaths = configText ? parseDenyPaths(configText) : [];
  if (denyPaths.length) {
    log(`[vpo-hook] deny_paths: ${denyPaths.map(expandHome).join(':')}`);
  }

  const honeypotScript = path.join(CONFIG_DIR, 'honeypot.js');
  if (fs.existsSync(honeypotScript)) {
    spawnSync('node', [honeypotScript], {
      stdio: quiet ? ['ignore', 'ignore', 'inherit'] : 'inherit',
    });
  }
  const honeypotMap = configText ? parseHoneypotMap(configText) : {};
  const allowNetwork = configText ? parseYamlList(configText, 'allow_network') : [];
  const riskMarkers = configText ? parseYamlList(configText, 'high_risk_markers') : [];

  const real = resolveExecutable(args[0]);
  const base = path.basename(real);
  const lang = base.includes('python') ? 'python' : base.includes('node') ? 'js' : null;

  const env = { ...process.env };
  if (plat === 'darwin') env.DYLD_INSERT_LIBRARIES = lib;
  else env.LD_PRELOAD = lib;
  env.VPO_HOOK_CONFIG = CONFIG_PATH;
  if (denyPaths.length) env.VPO_DENY_PATHS = denyPaths.map(expandHome).join(':');
  if (Object.keys(honeypotMap).length) {
    env.VPO_REWRITE_MAP = Object.entries(honeypotMap)
      .map(([k, v]) => `${expandHome(k)}=${expandHome(v)}`)
      .join(':');
  }
  if (allowNetwork.length) env.VPO_ALLOW_NETWORK = allowNetwork.join(',');
  if (riskMarkers.length) env.VPO_HIGH_RISK_MARKERS = riskMarkers.join(':');

  if (configText) {
    if (lang === 'python') {
      const apis = parsePlaintextApis(configText, 'python');
      if (apis.length) {
        env.VPO_HOOK_PY_API = apis.join(':');
        env.VPO_PYTHONPATH = PY_PLAINTEXT;
        env.PYTHONPATH = PY_PLAINTEXT + (env.PYTHONPATH ? ':' + env.PYTHONPATH : '');
        log(`[vpo-hook] 名文 hook(python): ${apis.join(', ')}`);
      }
    } else if (lang === 'js') {
      const apis = parsePlaintextApis(configText, 'js');
      if (apis.length) {
        env.VPO_HOOK_JS_API = apis.join(':');
        const preload = path.join(JS_PLAINTEXT, 'preload.js');
        env.VPO_NODE_OPTIONS = `--require ${preload}`;
        env.NODE_OPTIONS = `--require ${preload}` + (env.NODE_OPTIONS ? ' ' + env.NODE_OPTIONS : '');
        log(`[vpo-hook] 名文 hook(js): ${apis.join(', ')}`);
      }
    }
  }

  if (configText) {
    const audit = parseAudit(configText, lang);
    if (audit.enabled && !lang) {
      log('[vpo-hook] 目标不是 Python/Node，审计未启用');
    } else if (audit.enabled && audit.classes.length) {
      env.VPO_AUDIT_CLASSES = audit.classes.join(':');
      env.VPO_AUDIT_LOG = audit.log ? expandHome(audit.log) : path.join(CONFIG_DIR, 'audit.log');
      log(`[vpo-hook] 审计(${lang}): ${audit.classes.join(', ')}`);
    }
  }

  if (quiet) env.VPO_HOOK_QUIET = '1';
  else delete env.VPO_HOOK_QUIET;
  if (verbose) env.VPO_HOOK_VERBOSE = '1';

  log(`[vpo-hook] 启动: ${real}`);
  const result = spawnSync(real, args.slice(1), { stdio: 'inherit', env });
  if (result.error) {
    console.error(`[vpo-hook] 启动失败: ${result.error.message}`);
    return 1;
  }
  return result.status == null ? 1 : result.status;
}

function cmdStatus() {
  const plat = process.platform;
  const lib =
    plat === 'darwin'
      ? path.join(HOOK_DIR, 'libvpo_hook.dylib')
      : path.join(HOOK_DIR, 'libvpo_hook.so');
  console.log(`[vpo-hook] 平台: ${process.platform} ${os.arch()}`);
  console.log(`[vpo-hook] hook 库: ${lib} ${fs.existsSync(lib) ? '(存在)' : '(缺失，请 init)'}`);
  console.log(`[vpo-hook] 配置: ${CONFIG_PATH} ${fs.existsSync(CONFIG_PATH) ? '(存在)' : '(缺失)'}`);
  return 0;
}

// ---------------------------------------------------------------------------
function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  let code = 0;
  if (cmd === 'init') code = cmdInit();
  else if (cmd === 'run') code = cmdRun(args.slice(1));
  else if (cmd === 'status') code = cmdStatus();
  else {
    console.error('用法: vpo-hook init | run [-q|-v] <command...> | status');
    code = 1;
  }
  process.exit(code);
}

main();
