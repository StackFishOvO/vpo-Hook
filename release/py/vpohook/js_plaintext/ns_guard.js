/*
 * ns_guard.js -- L3-lite namespace data-flow guard (Node, cooperative).
 *
 * 目标：加密后的 Buffer 里没有 password/token 明文，内容标记扫描看不到。
 * 这里改为在“包边界”给返回值打来源标签，并在 HTTP response sink 检查来源。
 *
 * 范围与边界：
 * - 只覆盖 Node 进程内的 object/Buffer；字符串等原始值无法挂标签。
 * - 只覆盖配置的 source 函数和 http.ServerResponse.write/end。
 * - ctypes/raw syscall/子进程/原生扩展直接写 socket 仍可绕过。
 * - 不是完整 taint 引擎；Buffer.concat/toString 等传播点需要逐步补。
 */

'use strict';

const path = require('path');
const { createRequire } = require('module');

const QUIET = process.env.VPO_HOOK_QUIET === '1';
const ORIGINS = new WeakMap();
const DENY = new Set();
let INSTALLED = false;

class NamespaceDenied extends Error {
  constructor(origin, sink) {
    super(`namespace denied: ${origin} -> ${sink}`);
    this.name = 'NamespaceDenied';
    this.code = 'NAMESPACE_DENIED';
    this.origin = origin;
    this.sink = sink;
  }
}

function taint(value, origin) {
  if (value && (typeof value === 'object' || typeof value === 'function')) {
    const current = ORIGINS.get(value) || new Set();
    current.add(origin);
    ORIGINS.set(value, current);
  }
  return value;
}

function collectOrigins(value, seen = new Set()) {
  const out = new Set();
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return out;
  if (seen.has(value)) return out;
  seen.add(value);

  for (const origin of ORIGINS.get(value) || []) out.add(origin);

  if (Array.isArray(value)) {
    for (const item of value) {
      for (const origin of collectOrigins(item, seen)) out.add(origin);
    }
  } else if (!Buffer.isBuffer(value)) {
    for (const item of Object.values(value)) {
      for (const origin of collectOrigins(item, seen)) out.add(origin);
    }
  }
  return out;
}

function checkSink(value, sink = 'node_http') {
  for (const origin of collectOrigins(value)) {
    if (DENY.has(`${origin}\u0000${sink}`) || DENY.has(`*\u0000${sink}`) || DENY.has(`${origin}\u0000*`)) {
      throw new NamespaceDenied(origin, sink);
    }
  }
}

function resolveAttr(module, dotted) {
  return dotted.split('.').reduce((obj, part) => obj[part], module);
}

function setAttr(module, dotted, value) {
  const parts = dotted.split('.');
  let obj = module;
  for (const part of parts.slice(0, -1)) obj = obj[part];
  obj[parts[parts.length - 1]] = value;
}

function wrapSource(req, moduleName, namespace, functions) {
  let module;
  try {
    module = req(moduleName);
  } catch (err) {
    if (!QUIET) console.error(`[vpo-ns] 无法导入 source ${moduleName}: ${err.message}`);
    return [];
  }

  const installed = [];
  for (const name of functions || []) {
    let original;
    try {
      original = resolveAttr(module, name);
    } catch (_e) {
      continue;
    }
    if (typeof original !== 'function' || original.__vpo_ns_wrapped__) continue;

    const wrapped = function wrappedSource(...args) {
      const result = original.apply(this, args);
      if (result && typeof result.then === 'function') {
        return result.then((value) => taint(value, namespace));
      }
      return taint(result, namespace);
    };
    wrapped.__vpo_ns_wrapped__ = namespace;
    try {
      setAttr(module, name, wrapped);
      installed.push(`${moduleName}.${name}`);
    } catch (_e) {
      // 只读导出：跳过
    }
  }
  return installed;
}

function installNodeHttpSink(sink) {
  let http;
  try {
    http = require('http');
  } catch (_e) {
    return [];
  }

  const installed = [];
  const response = http.ServerResponse;
  if (response && response.prototype) {
    for (const method of ['write', 'end']) {
      const original = response.prototype[method];
      if (!original || original.__vpo_ns_sink__) continue;
      const wrapped = function wrappedSink(chunk, ...rest) {
        checkSink(chunk, sink);
        return original.call(this, chunk, ...rest);
      };
      wrapped.__vpo_ns_sink__ = sink;
      response.prototype[method] = wrapped;
      installed.push(`http.ServerResponse.${method}`);
    }
  }
  return installed;
}

function install(policy, req) {
  if (INSTALLED) return;
  const resolver = req || require;

  const deny = new Set();
  for (const flow of policy.flows || []) {
    if ((flow.action || 'deny') !== 'deny') continue;
    if (flow.from && flow.to) deny.add(`${flow.from}\u0000${flow.to}`);
  }
  DENY.clear();
  for (const item of deny) DENY.add(item);

  const installed = [];
  for (const [name, cfgRaw] of Object.entries(policy.namespaces || {})) {
    const cfg = cfgRaw || {};
    const role = cfg.role || cfg.type;
    if (role === 'source' || role === 'untrusted' || cfg.source) {
      installed.push(...wrapSource(resolver, cfg.module || name, name, cfg.functions || []));
    }
    if (role === 'sink' || cfg.sink) {
      const framework = String(cfg.framework || '').toLowerCase();
      if (framework === 'http' || framework === 'node-http' || /http|node/.test(name.toLowerCase())) {
        installed.push(...installNodeHttpSink(name));
      }
    }
  }

  INSTALLED = true;
  if (installed.length && !QUIET) {
    console.error(`[vpo-ns] 已安装命名空间守卫: ${installed.join(', ')}; deny flows: ${Array.from(deny)}`);
  }
}

function installFromFile(policyPath) {
  const abs = path.resolve(policyPath);
  const base = path.dirname(abs);
  const req = createRequire(path.join(base, 'package.json'));
  const resolver = (name) => {
    // 先按普通包名解析；失败再按 policy 目录下的相对路径解析。
    try {
      return req(name);
    } catch (_e) {
      return req(path.resolve(base, name));
    }
  };
  const policy = JSON.parse(require('fs').readFileSync(abs, 'utf8'));
  install(policy, resolver);
}

module.exports = {
  NamespaceDenied,
  taint,
  collectOrigins,
  checkSink,
  install,
  installFromFile,
};
