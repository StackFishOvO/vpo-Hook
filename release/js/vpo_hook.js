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
const crypto = require('crypto');
const { spawnSync } = require('child_process');

// ---------------------------------------------------------------------------
const HERE = __dirname; // js/
const HOOK_DIR = path.join(HERE, 'obj_hook');
const PY_PLAINTEXT = path.join(HERE, 'py_plaintext');
const JS_PLAINTEXT = path.join(HERE, 'plaintext');
const CONFIG_DIR = path.join(os.homedir(), '.vpo-hook');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.yaml');
const TEMPLATE_CONFIG = path.join(HOOK_DIR, 'config.yaml');
const SIMPLE_TEMPLATE_CONFIG = path.join(HOOK_DIR, 'config.simple.yaml');
const GRANTS_DIR = path.join(CONFIG_DIR, 'grants');
const SIGN_KEY_PATH = path.join(CONFIG_DIR, '.sign_key');
const SIG_PATH = path.join(CONFIG_DIR, 'config.sig');
const CHAIN_LOG = path.join(CONFIG_DIR, 'chain.log');
const CHAIN_HEAD = path.join(CONFIG_DIR, '.chain_head');
const SIGN_TTL = Number(process.env.VPO_SIGN_TTL || 30 * 24 * 3600);

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
function cmdInit(args = []) {
  const simple = args.includes('--profile') && args[args.indexOf('--profile') + 1] === 'simple';
  const template = simple ? SIMPLE_TEMPLATE_CONFIG : TEMPLATE_CONFIG;
  console.log(`[vpo-hook] 平台检测: ${process.platform} ${os.arch()}`);
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const created = !fs.existsSync(CONFIG_PATH);
  if (created) {
    fs.copyFileSync(template, CONFIG_PATH);
    console.log(`[vpo-hook] 已生成默认配置: ${CONFIG_PATH}`);
  } else {
    console.log(`[vpo-hook] 配置已存在: ${CONFIG_PATH}`);
  }
  if (created) {
    const key = loadSignKey(true);
    const env = signEnvelope(fs.readFileSync(CONFIG_PATH), key);
    fs.writeFileSync(SIG_PATH, JSON.stringify(env, null, 2) + '\n');
    try { fs.chmodSync(SIG_PATH, 0o600); } catch (_e) {}
    console.log(`[vpo-hook] 已签名配置: ${SIG_PATH}`);
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

// ---------------------------------------------------------------------------
// 简单安全组（profile: simple）：极简 YAML 子集解析
// ---------------------------------------------------------------------------
function simpleValue(v) {
  v = v.split('#')[0].trim();
  if (v === '[]') return [];
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function parseSimpleYaml(text) {
  const root = {};
  const stack = [{ indent: -1, node: root }];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const stripped = raw.trim();
    if (!stripped || stripped.startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();
    const parent = stack[stack.length - 1].node;

    if (stripped.startsWith('- ')) {
      if (Array.isArray(parent)) parent.push(simpleValue(stripped.slice(2)));
      continue;
    }
    if (stripped.includes(':')) {
      const idx = stripped.indexOf(':');
      let key = stripped.slice(0, idx).trim();
      if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.slice(1, -1);
      }
      let val = stripped.slice(idx + 1).split('#')[0].trim();
      let child;
      if (val === '') {
        let j = i + 1;
        while (j < lines.length) {
          const nxt = lines[j].trim();
          if (!nxt || nxt.startsWith('#')) { j++; continue; }
          break;
        }
        const nIndent = j < lines.length ? lines[j].length - lines[j].trimStart().length : -1;
        if (j < lines.length && lines[j].trimStart().startsWith('- ') && nIndent > indent) {
          child = [];
        } else {
          child = {};
        }
      } else {
        child = simpleValue(val);
      }
      if (parent !== null && typeof parent === 'object' && !Array.isArray(parent)) {
        parent[key] = child;
        if (child && typeof child === 'object') stack.push({ indent, node: child });
      }
    }
  }
  return root;
}

function simpleGet(node, ...keys) {
  let cur = node;
  for (const k of keys) {
    if (!cur || typeof cur !== 'object' || !(k in cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

function simpleScalar(node, dflt, ...keys) {
  const v = simpleGet(node, ...keys);
  if (v === undefined || v === null || typeof v === 'object') return dflt;
  return v;
}

function simpleList(node, ...keys) {
  const v = simpleGet(node, ...keys);
  if (Array.isArray(v)) return v.filter((x) => typeof x === 'string' && x);
  if (typeof v === 'string' && v) return [v];
  return [];
}

function cfgList(cfg, ...keys) {
  return simpleList(cfg, ...keys);
}

function cfgMap(cfg, ...keys) {
  const v = simpleGet(cfg, ...keys);
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function cfgAudit(cfg, lang) {
  const a = cfg.audit;
  if (!a || typeof a !== 'object' || Array.isArray(a)) return { enabled: false, log: '', classes: [] };
  const enabled = ['true', 'yes', 'on', '1'].includes(String(a.enabled || '').trim().toLowerCase());
  const log = a.log || '';
  const classes = lang ? cfgList(a, 'classes', lang) : [];
  return { enabled, log, classes };
}

const RUNTIME_DIRS = [
  '/usr', '/lib', '/lib64', '/bin', '/sbin',
  '/etc', '/proc', '/sys', '/dev', '/run', '/tmp', '/var/tmp',
];

const SIMPLE_DENY_PATHS = [
  '~/.ssh',
  '~/.aws',
  '~/.azure',
  '~/.config/gcloud',
  '~/.kube',
  '~/.npmrc',
  '~/.gitconfig',
  '~/.git-credentials',
  '~/.netrc',
  '~/.gnupg',
  '~/.local/share/keyrings',
  '~/.docker/config.json',
  '~/.config/google-chrome',
  '~/.config/microsoft-edge',
  '~/.mozilla/firefox',
  '~/.vpo-test-data',
];

const SIMPLE_MARKERS = ['token', 'secret', 'password', 'private key', 'BEGIN PRIVATE KEY'];

function detectEnvRoot(real, lang) {
  if (lang === 'python') {
    const p = path.parse(real);
    const binDir = p.dir;
    const parent = path.dirname(binDir);
    if (fs.existsSync(path.join(parent, 'pyvenv.cfg'))) return parent;
    const venv = process.env.VIRTUAL_ENV;
    if (venv) return venv;
    return null;
  }
  if (lang === 'js') {
    let d = process.cwd();
    while (true) {
      if (fs.existsSync(path.join(d, 'package.json'))) return d;
      const parent = path.dirname(d);
      if (parent === d) break;
      d = parent;
    }
    return process.cwd();
  }
  return null;
}

const HONEYPOT_DIR_FILES = [
  'id_rsa', 'id_rsa.pub', 'authorized_keys', 'known_hosts',
  'credentials', 'config', 'config.json',
  'Cookies', 'Login Data', 'cookies.sqlite', 'logins.json',
  'default', 'secret.txt', 'db.txt',
];

function generateSimpleHoneypot(denyPaths) {
  const hdir = path.join(CONFIG_DIR, 'honeypot');
  fs.mkdirSync(hdir, { recursive: true });
  const mapping = {};
  for (const d of denyPaths) {
    if (!d) continue;
    const key = crypto.createHash('sha256').update(d).digest('hex').slice(0, 16);
    const hp = path.join(hdir, key);
    let isDir = false;
    try { isDir = fs.statSync(d).isDirectory(); } catch (_e) {}
    if (isDir) {
      fs.mkdirSync(hp, { recursive: true });
      for (const name of HONEYPOT_DIR_FILES) {
        fs.writeFileSync(path.join(hp, name), 'HONEYPOT_FAKE_DATA\n');
      }
    } else {
      fs.mkdirSync(hdir, { recursive: true });
      fs.writeFileSync(hp, 'HONEYPOT_FAKE_DATA\n');
    }
    mapping[d] = hp;
  }
  return mapping;
}

// ---------------------------------------------------------------------------
// 能力发现（Phase B）：nm -u + Python/JS 正则
// ---------------------------------------------------------------------------
const CAPABILITY_GROUPS = ['file', 'network', 'process', 'code_load'];

const NATIVE_KEYWORDS = {
  file: ['open', 'openat', 'fopen', 'read', 'write', 'unlink', 'rename', 'mkdir', 'rmdir', 'stat', 'fstat', 'lstat', 'truncate'],
  network: ['socket', 'connect', 'sendto', 'recvfrom', 'getaddrinfo', 'gethostbyname', 'send', 'recv'],
  process: ['execve', 'execv', 'execvp', 'posix_spawn', 'system', 'popen', 'fork', 'vfork', 'kill'],
  code_load: ['dlopen'],
};

const JS_RULES = {
  file: [/require\(\s*['"](?:node:)?fs['"]\s*\)/, /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|open|openSync)\b/],
  network: [/require\(\s*['"](?:node:)?(?:net|http|https|dns|tls)['"]\s*\)/, /\bfetch\s*\(/, /require\(\s*['"]undici['"]\s*\)/],
  process: [/require\(\s*['"](?:node:)?child_process['"]\s*\)/, /\b(?:exec|execSync|spawn|spawnSync)\s*\(/],
  code_load: [/\bprocess\.binding\b/, /\bdlopen\b/, /require\(\s*['"]ffi(?:-napi)?['"]\s*\)/],
};

const SCAN_SKIP = new Set(['node_modules', '.venv', 'venv', '__pycache__', 'build', 'dist', '.git']);

function nmUndefined(file) {
  const r = spawnSync('nm', ['-u', file], { stdio: 'pipe', encoding: 'utf8' });
  if (r.error || r.status !== 0) return [];
  return r.stdout
    .split('\n')
    .map((l) => l.trim().split(/\s+/).pop().split('@')[0])
    .filter(Boolean);
}

function scanPythonHits(text) {
  const hits = {};
  const add = (g) => { hits[g] = (hits[g] || 0) + 1; };
  if (/(^|\s)(open\s*\(|os\.(system|popen|fork|exec|spawn|open|remove|unlink|rename|listdir)|subprocess\.)/m.test(text)) {
    if (/(open\s*\(|os\.(open|remove|unlink|rename|listdir)|shutil\.)/.test(text)) add('file');
    if (/(os\.(system|popen|fork|exec|spawn)|subprocess\.)/.test(text)) add('process');
  }
  if (/import\s+(socket|requests|urllib|http|ftplib|smtplib)|from\s+(socket|urllib|http)/.test(text)) add('network');
  if (/ctypes\.CDLL|importlib/.test(text)) add('code_load');
  return hits;
}

function scanJsHits(text) {
  const hits = {};
  for (const group of CAPABILITY_GROUPS) {
    for (const re of JS_RULES[group] || []) {
      const m = text.match(re);
      if (m) hits[group] = (hits[group] || 0) + 1;
    }
  }
  return hits;
}

function walkFiles(root, out, limit) {
  if (out.length >= limit) return;
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (_e) { return; }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) {
      if (SCAN_SKIP.has(e.name)) continue;
      walkFiles(full, out, limit);
    } else if (e.isFile() && /\.(so|dylib|node|py|js|mjs|cjs)$/.test(e.name)) {
      out.push(full);
      if (out.length >= limit) return;
    }
  }
}

function scanCapabilities(rootPath) {
  let files = [];
  const st = fs.statSync(rootPath);
  if (st.isFile()) files = [rootPath];
  else walkFiles(rootPath, files, 500);

  const counts = { file: {}, network: {}, process: {}, code_load: {} };
  const evidence = { file: [], network: [], process: [], code_load: [] };

  for (const file of files) {
    const name = path.basename(file);
    if (/\.(so|dylib|node)$/.test(name)) {
      for (const sym of nmUndefined(file)) {
        for (const group of CAPABILITY_GROUPS) {
          if ((NATIVE_KEYWORDS[group] || []).some((kw) => sym.includes(kw))) {
            counts[group][name] = (counts[group][name] || 0) + 1;
            if (evidence[group].length < 6) evidence[group].push(`${name}: ${sym}`);
            break;
          }
        }
      }
    } else {
      let text = '';
      try { text = fs.readFileSync(file, 'utf8'); } catch (_e) { continue; }
      const hits = /\.py$/.test(name) ? scanPythonHits(text) : scanJsHits(text);
      for (const group of CAPABILITY_GROUPS) {
        if (hits[group]) {
          counts[group][file] = (counts[group][file] || 0) + hits[group];
          if (evidence[group].length < 6) evidence[group].push(file);
        }
      }
    }
  }

  const result = {};
  for (const group of CAPABILITY_GROUPS) {
    const total = Object.values(counts[group]).reduce((a, b) => a + b, 0);
    result[group] = { score: Math.min(1, total / 6), evidence: evidence[group] };
  }
  return result;
}

function cmdScan(args) {
  const target = args[0];
  if (!target) {
    console.error('用法: vpo-hook scan <目录|文件>');
    return 1;
  }
  const caps = scanCapabilities(target);
  console.log(`[vpo-hook] 能力发现: ${target}`);
  for (const group of CAPABILITY_GROUPS) {
    if (caps[group].score <= 0) continue;
    console.log(`  ${group.padEnd(10)} score=${caps[group].score.toFixed(2)}  证据: ${caps[group].evidence.slice(0, 3).join('; ')}`);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 授权（Phase C）：grants 文件 + log/list/grant/revoke
// ---------------------------------------------------------------------------
function grantsPath(envRoot) {
  const h = crypto.createHash('sha256').update(String(envRoot)).digest('hex').slice(0, 16);
  return path.join(GRANTS_DIR, `${h}.json`);
}

function grantsSigPath(envRoot) {
  return grantsPath(envRoot).replace(/\.json$/, '.sig');
}

function loadGrants(envRoot) {
  try {
    const data = JSON.parse(fs.readFileSync(grantsPath(envRoot), 'utf8'));
    return data && typeof data === 'object' ? data : null;
  } catch (_e) {
    return null;
  }
}

function saveGrants(envRoot, grants) {
  fs.mkdirSync(GRANTS_DIR, { recursive: true });
  try { fs.chmodSync(GRANTS_DIR, 0o700); } catch (_e) {}
  const p = grantsPath(envRoot);
  const data = Buffer.from(JSON.stringify(grants, null, 2) + '\n', 'utf8');
  fs.writeFileSync(p, data);
  try { fs.chmodSync(p, 0o600); } catch (_e) {}
  const key = loadSignKey(true);
  const env = signEnvelope(data, key);
  fs.writeFileSync(grantsSigPath(envRoot), JSON.stringify(env, null, 2) + '\n');
  try { fs.chmodSync(grantsSigPath(envRoot), 0o600); } catch (_e) {}
  appendChain({ event: 'grant', env_root: String(envRoot), kind: 'grants' });
}

function verifyGrants(envRoot) {
  const p = grantsPath(envRoot);
  const sp = grantsSigPath(envRoot);
  if (!fs.existsSync(sp)) return [true, ''];
  if (!fs.existsSync(p)) return [false, 'grants 文件缺失但存在签名'];
  const key = loadSignKey(false);
  if (!key) return [false, 'grants 有签名但缺少密钥'];
  let env = null;
  try { env = JSON.parse(fs.readFileSync(sp, 'utf8')); } catch (_e) {
    return [false, 'grants 签名文件损坏'];
  }
  return verifyEnvelope(fs.readFileSync(p), env, key);
}

function defaultGrants(envRoot) {
  return {
    version: 1,
    env_root: String(envRoot),
    files: { extra_read: [], extra_write: [] },
    network: { mode: 'off', allowlist: [], blocklist: [] },
    process: { exec: 'off', exec_allow: [] },
  };
}

function mergeGrantsInto(grants, simpleCfg) {
  const merged = JSON.parse(JSON.stringify(simpleCfg));
  if (!grants) return merged;
  const perms = merged.permissions || (merged.permissions = {});
  const files = perms.files || (perms.files = {});
  files.extra_read = (grants.files && grants.files.extra_read) || files.extra_read || [];
  files.extra_write = (grants.files && grants.files.extra_write) || files.extra_write || [];
  const net = perms.network || (perms.network = {});
  net.mode = (grants.network && grants.network.mode) || net.mode || 'off';
  net.allowlist = (grants.network && grants.network.allowlist) || net.allowlist || [];
  net.blocklist = (grants.network && grants.network.blocklist) || net.blocklist || [];
  const proc = perms.process || (perms.process = {});
  proc.exec = (grants.process && grants.process.exec) || proc.exec || 'off';
  proc.exec_allow = (grants.process && grants.process.exec_allow) || proc.exec_allow || [];
  return merged;
}

function cmdLog(args) {
  const n = args.find((a) => a === '-n') ? Number(args[args.indexOf('-n') + 1]) : 20;
  const denials = path.join(CONFIG_DIR, 'denials.log');
  let lines = [];
  try { lines = fs.readFileSync(denials, 'utf8').trim().split('\n').filter(Boolean); } catch (_e) {}
  const records = lines.slice(-n).map((l) => { try { return JSON.parse(l); } catch (_e) { return null; } }).filter(Boolean);
  if (!records.length) {
    console.log('[vpo-hook] 没有拒绝记录');
    return 0;
  }
  console.log(`[vpo-hook] 最近 ${records.length} 条拒绝记录:`);
  for (const r of records) console.log(`  ${r.func || '?'}  ${r.path || ''}`);
  return 0;
}

function cmdList() {
  if (!fs.existsSync(GRANTS_DIR)) { console.log('[vpo-hook] 没有授权记录'); return 0; }
  const files = fs.readdirSync(GRANTS_DIR).filter((f) => f.endsWith('.json')).sort();
  if (!files.length) { console.log('[vpo-hook] 没有授权记录'); return 0; }
  for (const f of files) {
    let data;
    try { data = JSON.parse(fs.readFileSync(path.join(GRANTS_DIR, f), 'utf8')); } catch (_e) { continue; }
    console.log(`env_root: ${data.env_root || '?'}`);
    console.log(`  network: ${(data.network || {}).mode || 'off'} allowlist=${(data.network || {}).allowlist || []}`);
    console.log(`  process: ${(data.process || {}).exec || 'off'} allow=${(data.process || {}).exec_allow || []}`);
    console.log(`  files: read=${(data.files || {}).extra_read || []} write=${(data.files || {}).extra_write || []}`);
  }
  return 0;
}

function cmdGrant(args) {
  let root = process.cwd();
  const idx = args.indexOf('--root');
  if (idx >= 0 && args[idx + 1]) {
    root = args[idx + 1];
    args.splice(idx, 2);
  }
  const kind = args[0];
  const value = args[1];
  const rest = args.slice(2);
  const grants = loadGrants(root) || defaultGrants(root);
  if (kind === 'network') {
    grants.network.mode = value;
    grants.network.allowlist = value === 'allowlist' ? rest : [];
  } else if (kind === 'process') {
    grants.process.exec = value;
    grants.process.exec_allow = value === 'allowlist' ? rest : [];
  } else if (kind === 'file') {
    const key = value === 'read' ? 'extra_read' : 'extra_write';
    grants.files[key] = Array.from(new Set([...(grants.files[key] || []), ...rest]));
  } else {
    console.error(`[vpo-hook] 未知授权类型: ${kind}`);
    return 1;
  }
  saveGrants(root, grants);
  console.log(`[vpo-hook] 已更新授权: ${grantsPath(root)}`);
  return 0;
}

function cmdRevoke(args) {
  let root = process.cwd();
  const idx = args.indexOf('--root');
  if (idx >= 0 && args[idx + 1]) {
    root = args[idx + 1];
  }
  const p = grantsPath(root);
  if (fs.existsSync(p)) {
    fs.unlinkSync(p);
    const sp = grantsSigPath(root);
    if (fs.existsSync(sp)) fs.unlinkSync(sp);
    appendChain({ event: 'revoke', env_root: String(root) });
    console.log(`[vpo-hook] 已撤销授权: ${p}`);
  } else {
    console.log('[vpo-hook] 没有该环境的授权');
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 配置签名（Phase D）：HMAC-SHA256 + 时间戳/随机数/有效期
// ---------------------------------------------------------------------------
function loadSignKey(create) {
  if (process.env.VPO_SIGN_KEY) return Buffer.from(process.env.VPO_SIGN_KEY, 'utf8');
  if (fs.existsSync(SIGN_KEY_PATH)) return fs.readFileSync(SIGN_KEY_PATH);
  if (create) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    try { fs.chmodSync(CONFIG_DIR, 0o700); } catch (_e) {}
    const key = crypto.randomBytes(32);
    fs.writeFileSync(SIGN_KEY_PATH, key);
    try { fs.chmodSync(SIGN_KEY_PATH, 0o600); } catch (_e) {}
    return key;
  }
  return null;
}

function signEnvelope(data, key) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  const expiry = ts + SIGN_TTL;
  const payload = Buffer.concat([
    data,
    Buffer.from(`\n${ts}\n${nonce}\n${expiry}`),
  ]);
  const sig = crypto.createHmac('sha256', key).update(payload).digest('hex');
  return { scheme: 'hmac-sha256', ts, nonce, expiry, sig };
}

function verifyEnvelope(data, env, key) {
  if (env.scheme !== 'hmac-sha256') return [false, '未知签名方案'];
  if (env.ts == null || !env.nonce || !env.expiry || !env.sig) return [false, '签名字段缺失'];
  const expiry = Number(env.expiry);
  if (!Number.isFinite(expiry)) return [false, '签名有效期非法'];
  if (Math.floor(Date.now() / 1000) > expiry) return [false, '签名已过期，请运行 vpo-hook sign'];
  const payload = Buffer.concat([
    data,
    Buffer.from(`\n${env.ts}\n${env.nonce}\n${env.expiry}`),
  ]);
  const calc = crypto.createHmac('sha256', key).update(payload).digest('hex');
  if (calc !== String(env.sig)) return [false, '配置签名不匹配（配置被修改）'];
  return [true, ''];
}

function cmdSign() {
  if (!fs.existsSync(CONFIG_PATH)) {
    console.error('[vpo-hook] 没有配置文件，请先 init');
    return 1;
  }
  const key = loadSignKey(true);
  const env = signEnvelope(fs.readFileSync(CONFIG_PATH), key);
  fs.writeFileSync(SIG_PATH, JSON.stringify(env, null, 2) + '\n');
  try { fs.chmodSync(SIG_PATH, 0o600); } catch (_e) {}
  appendChain({ event: 'config_sign', path: CONFIG_PATH });
  console.log(`[vpo-hook] 已签名: ${SIG_PATH} (有效期至 ${env.expiry})`);
  return 0;
}

// ---------------------------------------------------------------------------
// 审计哈希链
// ---------------------------------------------------------------------------
const GENESIS_HEAD = '0'.repeat(64);

function chainHead() {
  if (fs.existsSync(CHAIN_HEAD)) {
    const h = fs.readFileSync(CHAIN_HEAD, 'utf8').trim();
    if (h) return h;
  }
  return GENESIS_HEAD;
}

function appendChain(event) {
  const key = loadSignKey(true);
  const prev = chainHead();
  const entry = Object.assign({}, event, { prev });
  const line = JSON.stringify(entry);
  const head = crypto.createHmac('sha256', key)
    .update(crypto.createHash('sha256').update(line).digest('hex'))
    .digest('hex');
  fs.appendFileSync(CHAIN_LOG, line + '\n');
  fs.writeFileSync(CHAIN_HEAD, head);
  try { fs.chmodSync(CHAIN_HEAD, 0o600); } catch (_e) {}
}

function verifyChain() {
  if (!fs.existsSync(CHAIN_LOG)) return [true, ''];
  const key = loadSignKey(false);
  if (!key) return [false, '缺少签名密钥，无法校验链'];
  let lines;
  try { lines = fs.readFileSync(CHAIN_LOG, 'utf8').split('\n'); } catch (_e) {
    return [false, '链日志读取失败'];
  }
  let head = GENESIS_HEAD;
  let idx = 0;
  for (const line of lines) {
    if (!line.trim()) continue;
    idx++;
    let entry;
    try { entry = JSON.parse(line); } catch (_e) { return [false, `第 ${idx} 行不是合法 JSON`]; }
    if (entry.prev !== head) return [false, `第 ${idx} 行 prev 不匹配（链被篡改）`];
    head = crypto.createHmac('sha256', key)
      .update(crypto.createHash('sha256').update(line).digest('hex'))
      .digest('hex');
  }
  if (chainHead() !== head) return [false, '链头不匹配（链被截断/篡改）'];
  return [true, ''];
}

function cmdChain() {
  const [ok, msg] = verifyChain();
  if (ok) {
    console.log('[vpo-hook] 审计链校验通过');
    return 0;
  }
  console.error(`[vpo-hook] 审计链校验失败: ${msg}`);
  return 1;
}

function cmdDiscover(args) {
  const target = args[0];
  if (!target) {
    console.error('用法: vpo-hook discover <目录|模块名>');
    return 1;
  }
  const vpoh = require('./vpoh.js');
  const m = vpoh.discover(target);
  console.log(JSON.stringify(m, null, 2));
  return 0;
}

function cmdGenerate(args) {
  const target = args[0];
  if (!target) {
    console.error('用法: vpo-hook generate <目录|模块名> [--out dir]');
    return 1;
  }
  const outIdx = args.indexOf('--out');
  const out = outIdx >= 0 ? args[outIdx + 1] : null;
  const vpoh = require('./vpoh.js');
  const m = vpoh.discover(target);
  const r = vpoh.generate(m, out);
  console.log(JSON.stringify(r, null, 2));
  return 0;
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

  if (fs.existsSync(SIG_PATH) && configText) {
    const key = loadSignKey(false);
    if (!key) {
      console.error('[vpo-hook] 配置有签名但缺少密钥，拒绝运行');
      return 1;
    }
    let envSig = null;
    try { envSig = JSON.parse(fs.readFileSync(SIG_PATH, 'utf8')); } catch (_e) {
      console.error('[vpo-hook] 配置签名文件损坏，拒绝运行');
      return 1;
    }
    const [ok, msg] = verifyEnvelope(Buffer.from(configText, 'utf8'), envSig, key);
    if (!ok) {
      console.error(`[vpo-hook] ${msg}，拒绝运行`);
      return 1;
    }
  }

  const cfg = configText ? parseSimpleYaml(configText) : {};

  const denyPaths = cfgList(cfg, 'policy', 'deny_paths');
  if (denyPaths.length) {
    log(`[vpo-hook] deny_paths: ${denyPaths.map(expandHome).join(':')}`);
  }

  const honeypotScript = path.join(CONFIG_DIR, 'honeypot.js');
  if (fs.existsSync(honeypotScript)) {
    spawnSync('node', [honeypotScript], {
      stdio: quiet ? ['ignore', 'ignore', 'inherit'] : 'inherit',
    });
  }
  const honeypotMap = cfgMap(cfg, 'policy', 'honeypot_map');
  const allowNetwork = cfgList(cfg, 'policy', 'allow_network');
  const riskMarkers = cfgList(cfg, 'policy', 'high_risk_markers');

  const real = resolveExecutable(args[0]);
  const base = path.basename(real);
  const lang = base.includes('python') ? 'python' : base.includes('node') ? 'js' : null;

  let simpleCfg = null;
  if (cfg.profile === 'simple' && 'permissions' in cfg) {
    simpleCfg = cfg;
  }

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

  if (simpleCfg) {
    try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); } catch (_e) {}
    env.VPO_DENIALS_LOG = path.join(CONFIG_DIR, 'denials.log');
    env.VPO_ENV_ROOT = '';
    const envOpt = simpleScalar(simpleCfg, 'auto', 'env');
    let root = envOpt === 'auto' ? detectEnvRoot(real, lang) : expandHome(envOpt);
    if (root && fs.existsSync(root)) {
      env.VPO_ENV_ROOT = root;
      env.VPO_RUNTIME_DIRS = RUNTIME_DIRS.join(':');
      const [gok, gmsg] = verifyGrants(root);
      if (!gok) {
        console.error(`[vpo-hook] ${gmsg}，拒绝运行`);
        return 1;
      }
      const grants = loadGrants(root);
      if (grants) simpleCfg = mergeGrantsInto(grants, simpleCfg);
      const extra = [
        ...simpleList(simpleCfg, 'permissions', 'files', 'extra_read'),
        ...simpleList(simpleCfg, 'permissions', 'files', 'extra_write'),
      ];
      if (extra.length) env.VPO_EXTRA_PATHS = extra.map(expandHome).join(':');
    } else {
      log('[vpo-hook] 无法判定环境根目录，简单安全组文件作用域未启用');
    }

    const netMode = simpleScalar(simpleCfg, 'off', 'permissions', 'network', 'mode');
    env.VPO_NETWORK_MODE = netMode;
    if (netMode === 'allowlist') {
      const al = simpleList(simpleCfg, 'permissions', 'network', 'allowlist');
      if (al.length) env.VPO_ALLOW_NETWORK = al.join(',');
    }
    const bl = simpleList(simpleCfg, 'permissions', 'network', 'blocklist');
    if (bl.length) env.VPO_NETWORK_BLOCKLIST = bl.join(',');

    const execMode = simpleScalar(simpleCfg, 'off', 'permissions', 'process', 'exec');
    env.VPO_EXEC_MODE = execMode;
    const ea = simpleList(simpleCfg, 'permissions', 'process', 'exec_allow');
    if (ea.length) env.VPO_EXEC_ALLOW = ea.map(expandHome).join(':');

    const sw = simpleList(simpleCfg, 'sensitive_words');
    env.VPO_HIGH_RISK_MARKERS = SIMPLE_MARKERS.concat(sw).join(':');

    const inspect = simpleScalar(simpleCfg, 'true', 'inbound', 'inspect');
    env.VPO_INSPECT_INBOUND = ['true', '1', 'yes', 'on'].includes(inspect) ? '1' : '0';
    env.VPO_INBOUND_ACTION = simpleScalar(simpleCfg, 'audit', 'inbound', 'action');
    const sa = simpleList(simpleCfg, 'sources', 'allow');
    const sd = simpleList(simpleCfg, 'sources', 'deny');
    if (sa.length) env.VPO_SOURCES_ALLOW = sa.join(',');
    if (sd.length) env.VPO_SOURCES_DENY = sd.join(',');

    const deny = SIMPLE_DENY_PATHS.map(expandHome)
      .concat(simpleList(simpleCfg, 'sensitive_files').map(expandHome));
    if (deny.length) {
      env.VPO_DENY_PATHS = deny.join(':');
      const hm = generateSimpleHoneypot(deny);
      const entries = Object.entries(hm);
      if (entries.length) {
        env.VPO_REWRITE_MAP = entries.map(([k, v]) => `${k}=${v}`).join(':');
      }
    }
  }

  if (simpleCfg && !quiet) {
    let scanRoot = env.VPO_ENV_ROOT || process.cwd();
    const caps = scanCapabilities(scanRoot);
    const found = CAPABILITY_GROUPS.filter((g) => caps[g].score > 0);
    if (found.length) log(`[vpo-hook] 发现能力: ${found.join(', ')}`);
    else log('[vpo-hook] 未发现明显能力（默认按简单安全组拒绝）');
  }

  if (configText) {
    if (lang === 'python') {
      const apis = cfgList(cfg, 'plaintext', 'python');
      if (apis.length) {
        if (!fs.existsSync(path.join(PY_PLAINTEXT, 'sitecustomize.py'))) {
          console.error('[vpo-hook] 缺少 sitecustomize.py（打包不完整）');
          return 1;
        }
        env.VPO_HOOK_PY_API = apis.join(':');
        env.VPO_PYTHONPATH = PY_PLAINTEXT;
        env.PYTHONPATH = PY_PLAINTEXT + (env.PYTHONPATH ? ':' + env.PYTHONPATH : '');
        log(`[vpo-hook] 名文 hook(python): ${apis.join(', ')}`);
      }
    } else if (lang === 'js') {
      const apis = cfgList(cfg, 'plaintext', 'js');
      if (apis.length) {
        const preload = path.join(JS_PLAINTEXT, 'preload.js');
        if (!fs.existsSync(preload)) {
          console.error('[vpo-hook] 缺少 preload.js（打包不完整）');
          return 1;
        }
        env.VPO_HOOK_JS_API = apis.join(':');
        env.VPO_NODE_OPTIONS = `--require ${preload}`;
        env.NODE_OPTIONS = `--require ${preload}` + (env.NODE_OPTIONS ? ' ' + env.NODE_OPTIONS : '');
        log(`[vpo-hook] 名文 hook(js): ${apis.join(', ')}`);
      }
    }
  }

  if (configText) {
    const audit = cfgAudit(cfg, lang);
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
  const denialsPath = path.join(CONFIG_DIR, 'denials.log');
  let denialsOffset = 0;
  try { if (fs.existsSync(denialsPath)) denialsOffset = fs.statSync(denialsPath).size; } catch (_e) {}
  const result = spawnSync(real, args.slice(1), { stdio: 'inherit', env });
  if (result.error) {
    console.error(`[vpo-hook] 启动失败: ${result.error.message}`);
    return 1;
  }
  if (!quiet) {
    try {
      if (fs.existsSync(denialsPath)) {
        const tail = fs.readFileSync(denialsPath, 'utf8').slice(denialsOffset);
        const records = tail.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch (_e) { return null; } }).filter(Boolean);
        if (records.length) {
          console.error(`[vpo-hook] 本次被拒绝 ${records.length} 次:`);
          const seen = new Set();
          for (const r of records.slice(0, 20)) {
            const k = `${r.func || ''}|${r.path || ''}`;
            if (seen.has(k)) continue;
            seen.add(k);
            console.error(`  - ${r.func || '?'}  ${r.path || ''}`);
          }
          console.error('[vpo-hook] 授权: vpo-hook grant ... ; 详情: vpo-hook log');
        }
      }
    } catch (_e) {}
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
function dispatch(args) {
  const cmd = args[0];
  let code = 0;
  if (cmd === 'init') code = cmdInit(args.slice(1));
  else if (cmd === 'run') code = cmdRun(args.slice(1));
  else if (cmd === 'status') code = cmdStatus();
  else if (cmd === 'scan') code = cmdScan(args.slice(1));
  else if (cmd === 'log') code = cmdLog(args.slice(1));
  else if (cmd === 'list') code = cmdList();
  else if (cmd === 'grant') code = cmdGrant(args.slice(1));
  else if (cmd === 'revoke') code = cmdRevoke(args.slice(1));
  else if (cmd === 'sign') code = cmdSign();
  else if (cmd === 'chain') code = cmdChain();
  else if (cmd === 'discover') code = cmdDiscover(args.slice(1));
  else if (cmd === 'generate') code = cmdGenerate(args.slice(1));
  else {
    console.error('用法: vpo-hook init [--profile simple|complex] | run [-q|-v] <command...> | status | scan | log | list | grant | revoke | sign | chain | discover | generate');
    code = 1;
  }
  return code;
}

function main() {
  process.exit(dispatch(process.argv.slice(2)));
}

if (require.main === module) {
  main();
}

module.exports = {
  dispatch,
  cmdInit,
  cmdRun,
  cmdStatus,
  cmdScan,
  cmdLog,
  cmdGrant,
  cmdRevoke,
  cmdList,
  cmdSign,
  cmdChain,
  scanCapabilities,
  detectEnvRoot,
};
