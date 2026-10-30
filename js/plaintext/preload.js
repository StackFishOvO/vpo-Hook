/*
 * preload.js -- VPO-Hook 名文 hook 入口（Node）。
 *
 * 启动器通过 NODE_OPTIONS="--require <path>/preload.js" 让本文件先于 guest 运行，
 * 并设置环境变量。两个功能：
 *
 * 1. 名文拦截：对 VPO_HOOK_JS_API 指定的 API 拦截。
 *    - 文件读取类（fs.readFileSync 等）：按「路径」检查，命中 deny_paths 才 DENY，
 *      其余放行 —— 否则会把 Node 加载器读入口脚本的 fs.readFileSync 也误拦。
 *    - 其他（execSync 等）：默认 DENY。
 * 2. 对象创建审计：对 VPO_AUDIT_CLASSES 指定的类 hook constructor，记录调用链
 *    （只记录，不做鉴权；默认关闭）。
 */

'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { Interposer, Policy } = require('./interpose');

const QUIET = process.env.VPO_HOOK_QUIET === '1';

// L2 信源：仅显式进入 deny 才拒绝
const SOURCES_DENY = (process.env.VPO_SOURCES_DENY || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function packageOf(filename) {
  if (!filename) return null;
  const i = filename.indexOf('node_modules');
  if (i < 0) return null;
  const rest = filename.slice(i + 'node_modules'.length + 1);
  const parts = rest.split('/');
  return parts[0] === '@' ? parts.slice(0, 2).join('/') : parts[0];
}

function callerPackage() {
  const stack = (new Error().stack || '').split('\n').slice(1);
  for (const line of stack) {
    let m = line.match(/\((.*):\d+:\d+\)$/);
    if (!m) m = line.match(/at (.*):\d+:\d+$/);
    if (!m) continue;
    const file = m[1];
    if (/preload\.js|interpose\.js/.test(file)) continue;
    const pkg = packageOf(file);
    if (pkg) return pkg;
  }
  return null;
}

function installSources() {
  if (SOURCES_DENY.length === 0) return;

  const policy = () => {
    const pkg = callerPackage();
    if (pkg && SOURCES_DENY.some((d) => pkg === d || pkg.startsWith(d + '/'))) {
      return Policy.DENY;
    }
    return Policy.ALLOW;
  };

  const sinks = [
    ['child_process', 'exec'], ['child_process', 'spawn'],
    ['child_process', 'fork'], ['child_process', 'execFile'],
    ['child_process', 'execFileSync'],
    ['net', 'connect'], ['net', 'createConnection'],
    ['dns', 'lookup'], ['dns', 'resolve'], ['dns', 'resolve4'], ['dns', 'resolve6'],
    ['http', 'request'], ['http', 'get'], ['https', 'request'], ['https', 'get'],
  ];
  const guard = new Interposer({ defaultPolicy: Policy.ALLOW });
  let installed = 0;
  for (const [modName, name] of sinks) {
    try {
      const mod = require(modName);
      if (typeof mod[name] === 'function') {
        guard.bind(mod, name, `${modName}.${name}`, { policy });
        installed++;
      }
    } catch (_e) {
      // 模块/属性不存在：跳过
    }
  }
  guard.seal();

  if (installed && !QUIET) {
    console.error(`[vpo-sources] 已安装 ${installed} 个信源 hook（deny: ${SOURCES_DENY.join(', ')}）`);
  }
}

// ---------------------------------------------------------------------------
// 名文 hook（拦截）
// ---------------------------------------------------------------------------
function installPlaintext() {
  const raw = process.env.VPO_HOOK_JS_API || '';
  const apis = raw.split(':').map((s) => s.trim()).filter(Boolean);
  if (apis.length === 0) return;

  const denyPaths = (process.env.VPO_DENY_PATHS || '').split(':').filter(Boolean);

  function pathBlocked(p) {
    const s = path.resolve(String(p || ''));
    for (const d of denyPaths) {
      const dd = path.resolve(d);
      if (s === dd) return true;
      if (s.startsWith(dd + path.sep)) return true;
    }
    return false;
  }

  const guard = new Interposer({ defaultPolicy: Policy.DENY });
  const installed = [];

  for (const cap of apis) {
    const idx = cap.lastIndexOf('.');
    if (idx <= 0) continue;
    const modName = cap.slice(0, idx);
    const attr = cap.slice(idx + 1);
    try {
      const mod = require(modName);
      if (typeof mod[attr] !== 'function') continue;

      let spec = { policy: Policy.DENY };
      if (/readFile|readSync|^read$/.test(attr)) {
        spec = {
          policy: (_cap, args) => (pathBlocked(args[0]) ? Policy.DENY : Policy.ALLOW),
        };
      }
      guard.bind(mod, attr, cap, spec);
      installed.push(cap);
    } catch (_e) {
      // 模块/属性不存在或绑定失败：跳过
    }
  }

  guard.seal();

  if (installed.length && !QUIET) {
    console.error(
      `[vpo-plaintext] 已安装 ${installed.length} 个名文 hook: ${installed.join(', ')}`,
    );
  }
}

// ---------------------------------------------------------------------------
// 对象创建审计（只记录，不做鉴权）
// ---------------------------------------------------------------------------
function installAudit() {
  const raw = process.env.VPO_AUDIT_CLASSES || '';
  const classes = [...new Set(raw.split(':').map((s) => s.trim()).filter(Boolean))];
  if (classes.length === 0) return;

  const logPath =
    process.env.VPO_AUDIT_LOG || path.join(os.homedir(), '.vpo-hook', 'audit.log');
  const installed = [];

  for (const clsName of classes) {
    const idx = clsName.lastIndexOf('.');
    if (idx <= 0) continue;
    const modName = clsName.slice(0, idx);
    const attr = clsName.slice(idx + 1);
    try {
      const mod = require(modName);
      const cls = mod[attr];
      if (typeof cls !== 'function') continue;
      if (cls.__vpo_audited__) continue;
      try {
        Object.defineProperty(cls, '__vpo_audited__', { value: true, configurable: true });
      } catch (_e) {
        // 冻结函数无法打标记：继续包装，但可能被重复包装
      }
      mod[attr] = new Proxy(cls, {
        construct(target, args, newTarget) {
          try {
            const stack = (new Error().stack || '').split('\n').slice(1, 9);
            const entry = { ts: Date.now() / 1000, class: clsName, stack };
            const line = JSON.stringify(entry) + '\n';
            const fd = fs.openSync(logPath, 'a', 0o600);
            try {
              fs.writeSync(fd, line);
            } finally {
              fs.closeSync(fd);
            }
          } catch (_e) {
            // 日志失败不影响对象创建
          }
          return Reflect.construct(target, args, newTarget);
        },
      });
      installed.push(clsName);
    } catch (_e) {
      // 模块/类不存在：跳过
    }
  }

  if (installed.length && !QUIET) {
    console.error(
      `[vpo-audit] 已安装 ${installed.length} 个审计 hook: ${installed.join(', ')}`,
    );
  }
}

function installNamespaceGuard() {
  const policyPath = process.env.VPO_NS_POLICY;
  if (!policyPath) return;
  try {
    require('./ns_guard').installFromFile(policyPath);
  } catch (err) {
    if (!QUIET) console.error(`[vpo-ns] 安装失败: ${err.message}`);
  }
}

installPlaintext();
installSources();
installAudit();
installNamespaceGuard();
