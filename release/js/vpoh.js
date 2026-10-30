/* VPO-Hook SDK（Node，运维期使用）。

用法：
    const vpoh = require('./js/vpoh');
    const m = vpoh.discover('my_pkg');       // -> manifest
    const r = vpoh.generate(m);              // -> hook plan + wrapper + sandbox
    vpoh.run(['python3', 'app.py']);         // -> 退出码

SDK 不参与目标进程运行：它只做发现、生成配置/代码、编译。运行时由
`vpo-hook run --config ... --hook ...` 消费生成的产物。
*/

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const hook = require('./vpo_hook');
const HOOK_DIR = path.join(__dirname, 'obj_hook');

const MANIFEST_SCHEMA = 'vpoh.manifest.v1';
const HOOK_PLAN_SCHEMA = 'vpoh.hook_plan.v1';
const SANDBOX_SCHEMA = 'vpoh.sandbox.v1';
const NATIVE_EXTS = new Set(['.so', '.dylib', '.node']);
const SCAN_SKIP = new Set([
  'node_modules', '.venv', 'venv', '__pycache__', 'build', 'dist',
  '.git', '.vpo', '.mypy_cache', '.pytest_cache',
]);
const DEFAULT_DENY_PATHS = [
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
];

// ---------------------------------------------------------------------------
// CLI 薄封装
// ---------------------------------------------------------------------------
function init() { return hook.dispatch(['init']); }
function status() { return hook.dispatch(['status']); }
function scan(p) { return hook.scanCapabilities(String(p)); }
function log(n = 20) { return hook.dispatch(['log', '-n', String(n)]); }
function grant(root, kind, value, ...rest) {
  return hook.dispatch(['grant', '--root', String(root), kind, value, ...rest.map(String)]);
}
function revoke(root) { return hook.dispatch(['revoke', '--root', String(root)]); }
function listGrants() { return hook.dispatch(['list']); }
function sign() { return hook.dispatch(['sign']); }
function chain() { return hook.dispatch(['chain']); }
function run(cmd, quiet = true, hookLib = null, config = null) {
  const argv = ['run'];
  if (quiet) argv.push('-q');
  if (config) argv.push('--config', String(config));
  if (hookLib) argv.push('--hook', String(hookLib));
  return hook.dispatch(argv.concat(cmd.map(String)));
}

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------
function sortedUnique(values) {
  return Array.from(new Set((values || []).filter(Boolean).map(String))).sort();
}

function safeName(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '') || 'pkg';
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortObject(value[key]);
    return out;
  }
  return value;
}

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(sortObject(obj), null, 2) + '\n');
}

function writeExec(file, text) {
  fs.writeFileSync(file, text);
  try { fs.chmodSync(file, 0o755); } catch (_e) {}
}

function pkgInfo(root) {
  let name = path.basename(root);
  let version = null;
  let manager = null;

  const pj = path.join(root, 'package.json');
  if (fs.existsSync(pj)) {
    try {
      const data = JSON.parse(fs.readFileSync(pj, 'utf8'));
      if (data.name) name = data.name;
      if (data.version) version = data.version;
      manager = 'npm';
    } catch (_e) {}
  }

  for (const cand of ['pyproject.toml', 'setup.py', 'setup.cfg']) {
    const f = path.join(root, cand);
    if (!fs.existsSync(f)) continue;
    const txt = fs.readFileSync(f, 'utf8');
    const nm = txt.match(/name\s*=\s*["']([^"']+)/);
    if (nm) name = nm[1];
    const vm = txt.match(/version\s*=\s*["']([^"']+)/);
    if (vm) version = vm[1];
    manager = manager === null ? 'pip' : 'mixed';
    break;
  }

  return { name, version, manager };
}

// ---------------------------------------------------------------------------
// native 符号：nm -D（Linux）/ nm -gU（macOS）
// ---------------------------------------------------------------------------
function nmSymbols(file) {
  const darwin = process.platform === 'darwin';

  function invoke(args) {
    const r = spawnSync('nm', args, { stdio: 'pipe', encoding: 'utf8' });
    if (r.error || r.status !== 0) return [];
    const found = [];
    for (const line of (r.stdout || '').split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (!parts.length || !parts[parts.length - 1]) continue;
      let tok = parts[parts.length - 1].split('@')[0];
      if (darwin && tok.startsWith('_')) tok = tok.slice(1);
      if (tok) found.push(tok);
    }
    return found;
  }

  const exports = darwin ? invoke(['-gU', file]) : invoke(['-D', '--defined-only', file]);
  const undefinedSyms = darwin ? invoke(['-u', file]) : invoke(['-D', '--undefined-only', file]);
  return { exports: sortedUnique(exports), undefined: sortedUnique(undefinedSyms) };
}

// ---------------------------------------------------------------------------
// 静态扫描：Python / JS 明文 API
// ---------------------------------------------------------------------------
function staticPython(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (_e) {
    return { functions: [], classes: {}, deps: [] };
  }
  const functions = new Set();
  const classes = {};
  const deps = new Set();
  let currentClass = null;
  let classIndent = -1;

  for (const line of text.split('\n')) {
    const indentMatch = line.match(/^\s*/);
    const indent = indentMatch ? indentMatch[0].length : 0;
    const classMatch = line.match(/^(\s*)class\s+([A-Za-z_]\w*)/);
    if (classMatch) {
      currentClass = classMatch[2];
      classIndent = classMatch[1].length;
      classes[currentClass] = classes[currentClass] || [];
      continue;
    }
    const defMatch = line.match(/^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)/);
    if (defMatch) {
      const name = defMatch[2];
      const defIndent = defMatch[1].length;
      if (currentClass && defIndent > classIndent) {
        classes[currentClass].push(name);
      } else {
        if (defIndent === 0) currentClass = null;
        functions.add(name);
      }
      continue;
    }
    const imp = line.match(/^\s*import\s+(.+)$/);
    if (imp) {
      for (const part of imp[1].split(',')) {
        const name = part.trim().split(/\s+as\s+/)[0];
        if (name) deps.add(name);
      }
      continue;
    }
    const from = line.match(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+/);
    if (from) deps.add(from[1]);
  }

  const outClasses = {};
  for (const key of Object.keys(classes).sort()) outClasses[key] = sortedUnique(classes[key]);
  return { functions: sortedUnique(Array.from(functions)), classes: outClasses, deps: sortedUnique(Array.from(deps)) };
}

function braceBlock(text, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) return text.slice(openIndex + 1, i);
    }
  }
  return text.slice(openIndex + 1);
}

function staticJs(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (_e) {
    return { exports: [], classes: {}, deps: [] };
  }
  const exportsSet = new Set();
  const classes = {};

  for (const m of text.matchAll(/(?:module\.exports|exports)\.([A-Za-z_$][\w$]*)\s*=/g)) {
    exportsSet.add(m[1]);
  }
  for (const m of text.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) {
    exportsSet.add(m[1]);
  }
  for (const m of text.matchAll(/export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) {
    exportsSet.add(m[1]);
  }

  for (const m of text.matchAll(/module\.exports\s*=\s*\{/g)) {
    const block = braceBlock(text, m.index + m[0].length - 1);
    for (const km of block.matchAll(/^\s*["']?([A-Za-z_$][\w$]*)["']?\s*:/gm)) {
      exportsSet.add(km[1]);
    }
  }

  for (const m of text.matchAll(/\bclass\s+([A-Za-z_$][\w$]*)\s*(?:extends\s+[^{]+)?\{/g)) {
    const name = m[1];
    const block = braceBlock(text, m.index + m[0].length - 1);
    const methods = [];
    for (const mm of block.matchAll(/^\s*(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?([A-Za-z_$][\w$]*)\s*\(/gm)) {
      if (mm[1] !== 'constructor') methods.push(mm[1]);
    }
    classes[name] = sortedUnique(methods);
    exportsSet.add(name);
  }

  for (const m of text.matchAll(/export\s+class\s+([A-Za-z_$][\w$]*)/g)) {
    exportsSet.add(m[1]);
  }

  const deps = new Set();
  for (const m of text.matchAll(/require\(\s*["']([^"']+)["']/g)) deps.add(m[1]);
  for (const m of text.matchAll(/from\s+["']([^"']+)["']/g)) deps.add(m[1]);

  const outClasses = {};
  for (const key of Object.keys(classes).sort()) outClasses[key] = sortedUnique(classes[key]);
  return { exports: sortedUnique(Array.from(exportsSet)), classes: outClasses, deps: sortedUnique(Array.from(deps)) };
}

// ---------------------------------------------------------------------------
// 动态反射（可选）
// ---------------------------------------------------------------------------
function reflectJs(target) {
  const code =
    "const m = require(process.argv[1]); " +
    "const attrs = Object.keys(m).filter((k) => !k.startsWith('_')); " +
    "const classes = {}; " +
    "for (const k of attrs) { " +
    "  const v = m[k]; " +
    "  if (typeof v === 'function' && v.prototype) { " +
    "    classes[k] = Object.getOwnPropertyNames(v.prototype) " +
    "      .filter((x) => x !== 'constructor' && !x.startsWith('_')).sort(); " +
    "  } " +
    "} " +
    "const deps = Object.keys(require.cache).map((f) => { " +
    "  const i = f.indexOf('node_modules'); " +
    "  if (i < 0) return f; " +
    "  const rest = f.slice(i + 'node_modules'.length + 1); " +
    "  const parts = rest.split('/'); " +
    "  return parts[0] === '@' ? parts.slice(0, 2).join('/') : parts[0]; " +
    "}); " +
    "console.log(JSON.stringify({ attrs, classes, deps }));";
  const r = spawnSync(process.execPath, ['-e', code, target], { stdio: 'pipe', encoding: 'utf8', timeout: 20000 });
  try { return JSON.parse(r.stdout.trim() || '{}'); } catch (_e) { return {}; }
}

// ---------------------------------------------------------------------------
// manifest / hook plan / sandbox plan
// ---------------------------------------------------------------------------
function sortClasses(classes) {
  const out = {};
  for (const key of Object.keys(classes || {}).sort()) out[key] = sortedUnique(classes[key]);
  return out;
}

function placeholder() {
  return {
    fake_symbols: { status: 'placeholder', generated: [] },
    rawcalls: { status: 'placeholder', syscalls: [] },
    native_signatures: {
      status: 'placeholder',
      source: 'nm',
      note: 'parameter types unavailable without DWARF/Clang AST',
    },
  };
}

function classMethods(cls) {
  const out = new Set();
  if (cls && cls.prototype) {
    for (const name of Object.getOwnPropertyNames(cls.prototype)) {
      if (name === 'constructor' || name.startsWith('_')) continue;
      let value;
      try { value = cls.prototype[name]; } catch (_e) { continue; }
      if (typeof value === 'function') out.add(name);
    }
  }
  return sortedUnique(Array.from(out));
}

function discoverObject(obj) {
  const label = (typeof obj === 'function' && obj.name) ||
    (obj && obj.constructor && obj.constructor.name) || 'object';
  const apis = new Set();
  const classes = {};

  if (typeof obj === 'function') {
    classes[label] = classMethods(obj);
    apis.add(label);
    for (const method of classes[label]) apis.add(`${label}.${method}`);
  } else {
    for (const key of Object.keys(obj || {})) {
      if (key.startsWith('_')) continue;
      apis.add(key);
      const value = obj[key];
      if (typeof value === 'function' && value.prototype) {
        const methods = classMethods(value);
        if (methods.length) {
          classes[key] = methods;
          for (const method of methods) apis.add(`${key}.${method}`);
        }
      }
    }
    const ctor = obj && obj.constructor;
    if (ctor && ctor.name && ctor.name !== 'Object') {
      const methods = classMethods(ctor);
      if (methods.length) {
        classes[ctor.name] = methods;
        for (const method of methods) apis.add(`${ctor.name}.${method}`);
      }
    }
  }

  return {
    schema: MANIFEST_SCHEMA,
    target: label,
    runtime: 'js',
    pkg: { name: label, version: null, manager: 'npm', root: null },
    apis: { python: [], js: sortedUnique(Array.from(apis)) },
    classes: { python: {}, js: sortClasses(classes) },
    modules: { python: [], js: [] },
    native: [],
    symbols: [],
    exports: [],
    deps: [],
    placeholder: placeholder(),
  };
}

function walkFiles(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    const dir = rel ? path.join(root, rel) : root;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { continue; }
    for (const entry of entries) {
      const childRel = rel ? path.join(rel, entry.name) : entry.name;
      const parts = childRel.split(path.sep);
      if (parts.some((p) => SCAN_SKIP.has(p))) continue;
      if (entry.isDirectory()) stack.push(childRel);
      else if (entry.isFile()) out.push(childRel);
    }
  }
  return out.sort();
}

function discover(target, opts = {}) {
  if (Array.isArray(target)) {
    throw new TypeError('command discovery is not implemented yet; pass an executable path or package path');
  }
  if (target && typeof target === 'object' && typeof target.pid === 'number' && typeof target.kill === 'function') {
    throw new TypeError('attaching to a running process is not supported; pass a command spec or package path');
  }
  if (target !== null && typeof target !== 'string') return discoverObject(target);
  const dynamic = typeof opts === 'boolean' ? opts : !!opts.dynamic;
  const t = String(target);
  let st = null;
  try { st = fs.statSync(t); } catch (_e) {}

  const pyFiles = [];
  const jsFiles = [];
  const pyFunctions = new Set();
  const pyClasses = {};
  const jsExports = new Set();
  const jsClasses = {};
  const deps = new Set();
  const native = [];
  const symbols = new Set();
  const exportsSet = new Set();

  function mergePy(parsed) {
    for (const x of parsed.functions || []) pyFunctions.add(x);
    for (const [cls, methods] of Object.entries(parsed.classes || {})) {
      pyClasses[cls] = pyClasses[cls] || [];
      pyClasses[cls].push(...methods);
    }
    for (const x of parsed.deps || []) deps.add(x);
  }
  function mergeJs(parsed) {
    for (const x of parsed.exports || []) jsExports.add(x);
    for (const [cls, methods] of Object.entries(parsed.classes || {})) {
      jsClasses[cls] = jsClasses[cls] || [];
      jsClasses[cls].push(...methods);
    }
    for (const x of parsed.deps || []) deps.add(x);
  }

  let pkg = { name: st ? path.basename(t).replace(/\.[^.]+$/, '') : t, version: null, manager: null };
  let runtime = 'unknown';

  if (st && st.isDirectory()) {
    const root = path.resolve(t);
    pkg = pkgInfo(root);
    for (const rel of walkFiles(root)) {
      const file = path.join(root, rel);
      const suffix = path.extname(file).toLowerCase();
      if (suffix === '.py') {
        pyFiles.push(rel);
        mergePy(staticPython(file));
      } else if (['.js', '.mjs', '.cjs'].includes(suffix)) {
        jsFiles.push(rel);
        mergeJs(staticJs(file));
      } else if (NATIVE_EXTS.has(suffix)) {
        const found = nmSymbols(file);
        native.push({ path: rel.split(path.sep).join('/'), exports: found.exports, undefined: found.undefined });
        for (const x of found.exports) exportsSet.add(x);
        for (const x of found.undefined) symbols.add(x);
      }
    }

    if (dynamic && pyFiles.length) {
      // JS SDK 不直接 import Python；保留静态结果，避免执行未知代码。
    }
    if (dynamic && jsFiles.length) {
      const r = reflectJs(root);
      for (const x of r.attrs || []) jsExports.add(x);
      for (const [cls, methods] of Object.entries(r.classes || {})) {
        jsClasses[cls] = jsClasses[cls] || [];
        jsClasses[cls].push(...methods);
      }
      for (const x of r.deps || []) deps.add(x);
    }

    pkg.root = root;
    if (pyFiles.length && !pkg.manager) pkg.manager = 'pip';
    if (jsFiles.length) pkg.manager = pkg.manager === 'pip' ? 'mixed' : (pkg.manager || 'npm');
    if (pyFiles.length || jsFiles.length) {
      runtime = pyFiles.length && jsFiles.length ? 'mixed' : (pyFiles.length ? 'python' : 'js');
    } else if (native.length) {
      runtime = 'native';
    }
  } else if (st && st.isFile()) {
    const suffix = path.extname(t).toLowerCase();
    pkg = { name: path.basename(t).replace(/\.[^.]+$/, ''), version: null, manager: null, root: path.dirname(t) };
    if (suffix === '.py') {
      pyFiles.push(path.basename(t));
      mergePy(staticPython(t));
      pkg.manager = 'pip';
      runtime = 'python';
    } else if (['.js', '.mjs', '.cjs'].includes(suffix)) {
      jsFiles.push(path.basename(t));
      mergeJs(staticJs(t));
      pkg.manager = 'npm';
      runtime = 'js';
    } else if (NATIVE_EXTS.has(suffix)) {
      const found = nmSymbols(t);
      native.push({ path: path.basename(t), exports: found.exports, undefined: found.undefined });
      for (const x of found.exports) exportsSet.add(x);
      for (const x of found.undefined) symbols.add(x);
      runtime = 'native';
    }
  } else {
    const r = reflectJs(t);
    pkg = { name: t, version: null, manager: 'npm' };
    for (const x of r.attrs || []) jsExports.add(x);
    for (const [cls, methods] of Object.entries(r.classes || {})) jsClasses[cls] = methods;
    for (const x of r.deps || []) deps.add(x);
    runtime = 'js';
  }

  const pyClassesSorted = sortClasses(pyClasses);
  const jsClassesSorted = sortClasses(jsClasses);
  const pyApis = new Set(pyFunctions);
  for (const [cls, methods] of Object.entries(pyClassesSorted)) {
    for (const method of methods) pyApis.add(`${cls}.${method}`);
  }
  const jsApis = new Set(jsExports);
  for (const [cls, methods] of Object.entries(jsClassesSorted)) {
    for (const method of methods) jsApis.add(`${cls}.${method}`);
  }

  return {
    schema: MANIFEST_SCHEMA,
    target: t,
    runtime,
    pkg,
    apis: { python: sortedUnique(Array.from(pyApis)), js: sortedUnique(Array.from(jsApis)) },
    classes: { python: pyClassesSorted, js: jsClassesSorted },
    modules: { python: sortedUnique(pyFiles), js: sortedUnique(jsFiles) },
    native: native.sort((a, b) => a.path.localeCompare(b.path)),
    symbols: sortedUnique(Array.from(symbols)),
    exports: sortedUnique(Array.from(exportsSet)),
    deps: sortedUnique(Array.from(deps)),
    placeholder: placeholder(),
  };
}

function normalizeManifest(manifest) {
  const m = JSON.parse(JSON.stringify(manifest || {}));
  m.schema = m.schema || MANIFEST_SCHEMA;
  m.target = m.target || (m.pkg && m.pkg.name) || 'unknown';
  m.runtime = m.runtime || 'unknown';
  m.pkg = m.pkg || {};
  m.apis = m.apis || {};
  m.classes = m.classes || {};
  m.modules = m.modules || {};
  m.native = m.native || [];
  m.symbols = sortedUnique(m.symbols);
  m.exports = sortedUnique(m.exports);
  m.deps = sortedUnique(m.deps);
  m.placeholder = m.placeholder || placeholder();
  for (const lang of ['python', 'js']) {
    m.apis[lang] = sortedUnique(m.apis[lang]);
    m.classes[lang] = sortClasses(m.classes[lang]);
    m.modules[lang] = sortedUnique(m.modules[lang]);
  }
  return m;
}

function sandboxPlan(manifest) {
  const pkg = (manifest && manifest.pkg) || {};
  return {
    schema: SANDBOX_SCHEMA,
    backend: 'auto',
    fs: {
      env_root: pkg.root || 'auto',
      deny: DEFAULT_DENY_PATHS.slice(),
      extra_read: [],
      extra_write: [],
    },
    network: { mode: 'off', allowlist: [], blocklist: [] },
    process: { fork: true, exec: 'off', exec_allow: [] },
    native: { cross_package: 'deny', same_package: 'allow' },
    children: 'inherit',
  };
}

function simpleConfigYaml(manifest) {
  const pkg = (manifest && manifest.pkg) || {};
  const name = JSON.stringify(String(pkg.name || 'app'));
  const env = JSON.stringify(pkg.root || 'auto');
  return [
    'version: 1',
    'profile: simple',
    `name: ${name}`,
    `env: ${env}`,
    '',
    'permissions:',
    '  files:',
    '    extra_read: []',
    '    extra_write: []',
    '  network:',
    '    mode: off',
    '    allowlist: []',
    '    blocklist: []',
    '  process:',
    '    fork: true',
    '    exec: off',
    '    exec_allow: []',
    '',
    'inbound:',
    '  inspect: true',
    '  action: audit',
    '',
    'sources:',
    '  allow: []',
    '  deny: []',
    '',
    'sensitive_files: []',
    'audit: on',
    '',
  ].join('\n');
}

function findCC() {
  for (const cc of ['clang', 'cc', 'gcc']) {
    const r = spawnSync('which', [cc], { stdio: 'pipe' });
    if (r.status === 0) return cc;
  }
  return null;
}

function generate(manifest, outDir = null) {
  const m = normalizeManifest(manifest);
  const pkg = (m.pkg && m.pkg.name) || 'pkg';
  const safe = safeName(pkg);
  const out = outDir
    ? path.resolve(outDir)
    : path.join((m.pkg && m.pkg.root) || process.cwd(), '.vpo');
  fs.mkdirSync(out, { recursive: true });

  const sig = JSON.parse(fs.readFileSync(path.join(HOOK_DIR, 'signatures.json'), 'utf8'));
  const funcs = sig.functions || {};
  const aliasMap = {};
  for (const [name, meta] of Object.entries(funcs)) {
    for (const a of meta.linux_aliases || []) aliasMap[a] = name;
  }
  const subset = new Set();
  for (const s of m.symbols || []) {
    const k = aliasMap[s] || s;
    if (funcs[k]) subset.add(k);
  }
  const subsetArr = Array.from(subset).sort();

  writeJson(path.join(out, 'manifest.json'), m);

  const sandbox = sandboxPlan(m);
  writeJson(path.join(out, 'sandbox.json'), sandbox);

  const hookPlan = {
    schema: HOOK_PLAN_SCHEMA,
    target: m.target,
    pkg: m.pkg,
    plaintext: {
      python: (m.apis && m.apis.python) || [],
      js: (m.apis && m.apis.js) || [],
      classes: m.classes || {},
      modules: m.modules || {},
    },
    binary: {
      libc: subsetArr,
      native: {
        exports: m.exports || [],
        fake_symbols: { status: 'placeholder', generated: [] },
        signatures: {
          status: 'placeholder',
          source: 'nm',
          note: 'parameter types unavailable without DWARF/Clang AST',
        },
      },
    },
    sandbox,
    rawcalls: { status: 'placeholder', syscalls: [] },
    artifacts: {
      config: 'config.yaml',
      launch: 'launch.sh',
      sandbox: 'sandbox.json',
    },
  };
  writeJson(path.join(out, 'hook_plan.json'), hookPlan);

  fs.writeFileSync(
    path.join(out, 'policy.yaml'),
    `# complex policy (draft)\npackage: ${pkg}\nfunctions: [${subsetArr.join(', ')}]\n`,
  );
  fs.writeFileSync(path.join(out, 'config.yaml'), simpleConfigYaml(m));

  let so = null;
  if (subsetArr.length) {
    const gen = path.join(HOOK_DIR, 'gen_wrappers.js');
    const wrapper = path.join(out, 'wrapper.c');
    const plat = process.platform === 'linux' ? 'linux' : 'darwin';
    const genResult = spawnSync(
      process.execPath,
      [gen, path.join(HOOK_DIR, 'signatures.json'), '-o', wrapper, '-p', plat, '--only', subsetArr.join(',')],
      { stdio: ['ignore', 'ignore', 'inherit'] },
    );
    if (genResult.error || genResult.status !== 0) {
      throw new Error('wrapper generation failed');
    }
    const cc = findCC();
    if (cc) {
      const ext = process.platform === 'darwin' ? '.dylib' : '.so';
      so = path.join(out, `libvpo_${safe}${ext}`);
      const cmd = process.platform === 'darwin'
        ? [cc, '-dynamiclib', '-I', HOOK_DIR, '-o', so, wrapper, path.join(HOOK_DIR, 'policy.c')]
        : [cc, '-shared', '-fPIC', '-I', HOOK_DIR, '-o', so, wrapper, path.join(HOOK_DIR, 'policy.c'), '-ldl'];
      const build = spawnSync(cmd[0], cmd.slice(1), { stdio: ['ignore', 'ignore', 'inherit'] });
      if (build.error || build.status !== 0) {
        throw new Error('hook library build failed');
      }
    }
  }

  const hookArg = so ? ` --hook "$HERE/${path.basename(so)}"` : '';
  writeExec(
    path.join(out, 'launch.sh'),
    '#!/usr/bin/env bash\n' +
      'set -euo pipefail\n' +
      'HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n' +
      `exec vpo-hook run -q --config "$HERE/config.yaml"${hookArg} "$@"\n`,
  );

  return {
    subset: subsetArr,
    out,
    so: so || null,
    manifest: path.join(out, 'manifest.json'),
    hook_plan: path.join(out, 'hook_plan.json'),
    sandbox: path.join(out, 'sandbox.json'),
    config: path.join(out, 'config.yaml'),
    launch: path.join(out, 'launch.sh'),
  };
}

module.exports = {
  init,
  status,
  scan,
  log,
  grant,
  revoke,
  listGrants,
  sign,
  chain,
  run,
  discover,
  generate,
};
