/* VPO-Hook SDK（Node）。

用法：
    const vpoh = require('./js/vpoh');
    vpoh.discover('my_pkg');            // -> manifest
    vpoh.generate(manifest);            // -> {subset, out, so}
    vpoh.run(['python3', 'app.py']);    // -> 退出码

其余 init/status/scan/log/grant/revoke/list/sign/chain 是 CLI 的薄封装。
*/

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const hook = require('./vpo_hook');
const HOOK_DIR = path.join(__dirname, 'obj_hook');

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
function run(cmd, quiet = true) {
  const argv = ['run'];
  if (quiet) argv.push('-q');
  return hook.dispatch(argv.concat(cmd.map(String)));
}

// ---------------------------------------------------------------------------
// discover / generate
// ---------------------------------------------------------------------------
function findCC() {
  for (const cc of ['clang', 'cc', 'gcc']) {
    const r = spawnSync('which', [cc], { stdio: 'pipe' });
    if (r.status === 0) return cc;
  }
  return null;
}

function nmUndefined(file) {
  const r = spawnSync('nm', ['-u', file], { stdio: 'pipe', encoding: 'utf8' });
  if (r.error || r.status !== 0) return [];
  return r.stdout
    .split('\n')
    .map((l) => l.trim().split(/\s+/).pop().split('@')[0])
    .filter(Boolean);
}

function walkNative(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!['node_modules', '.git', '.venv', 'build', 'dist'].includes(e.name)) walkNative(full, out);
    } else if (['.so', '.dylib', '.node'].includes(path.extname(e.name))) {
      out.push(...nmUndefined(full));
    }
  }
}

function pkgName(root) {
  const pj = path.join(root, 'package.json');
  if (fs.existsSync(pj)) {
    try {
      const j = JSON.parse(fs.readFileSync(pj, 'utf8'));
      if (j.name) return j.name;
    } catch (_e) {}
  }
  return path.basename(root);
}

function reflectJs(target) {
  const code =
    "const m = require(process.argv[1]); " +
    "const attrs = Object.keys(m).filter((k) => !k.startsWith('_')); " +
    "const deps = Object.keys(require.cache).map((f) => { " +
    "  const i = f.indexOf('node_modules'); " +
    "  if (i < 0) return f; " +
    "  const rest = f.slice(i + 'node_modules'.length + 1); " +
    "  const parts = rest.split('/'); " +
    "  return parts[0] === '@' ? parts.slice(0, 2).join('/') : parts[0]; " +
    "}); " +
    "console.log(JSON.stringify({ attrs, deps }));";
  const r = spawnSync(process.execPath, ['-e', code, target], { stdio: 'pipe', encoding: 'utf8' });
  try { return JSON.parse(r.stdout.trim() || '{}'); } catch (_e) { return {}; }
}

function discover(target) {
  const t = String(target);
  const manifest = { target: t, pkg: {}, symbols: [], apis: { python: [], js: [] }, deps: [] };
  const symbols = [];
  const nativeExts = new Set(['.so', '.dylib', '.node']);

  let st = null;
  try { st = fs.statSync(t); } catch (_e) {}

  if (st && st.isDirectory()) {
    const root = path.resolve(t);
    manifest.pkg.root = root;
    const name = pkgName(root);
    manifest.pkg.name = name;
    walkNative(root, symbols);
    const r = reflectJs(root);
    manifest.apis.js = r.attrs || [];
    manifest.deps = r.deps || [];
  } else if (st && st.isFile() && nativeExts.has(path.extname(t))) {
    symbols.push(...nmUndefined(t));
    manifest.pkg.name = path.basename(t);
  } else {
    manifest.pkg.name = t;
    const r = reflectJs(t);
    manifest.apis.js = r.attrs || [];
    manifest.deps = r.deps || [];
  }

  manifest.symbols = Array.from(new Set(symbols)).sort();
  return manifest;
}

function generate(manifest, outDir = null) {
  const pkg = (manifest.pkg && manifest.pkg.name) || 'pkg';
  const out = outDir
    ? path.resolve(outDir)
    : path.join((manifest.pkg && manifest.pkg.root) || process.cwd(), '.vpo');
  fs.mkdirSync(out, { recursive: true });

  const sig = JSON.parse(fs.readFileSync(path.join(HOOK_DIR, 'signatures.json'), 'utf8'));
  const funcs = sig.functions || {};
  const aliasMap = {};
  for (const [name, meta] of Object.entries(funcs)) {
    for (const a of meta.linux_aliases || []) aliasMap[a] = name;
  }
  const subset = new Set();
  for (const s of manifest.symbols || []) {
    const k = aliasMap[s] || s;
    if (funcs[k]) subset.add(k);
  }
  const subsetArr = Array.from(subset).sort();

  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  fs.writeFileSync(
    path.join(out, 'policy.yaml'),
    `# complex policy (draft)\npackage: ${pkg}\nfunctions: [${subsetArr.join(', ')}]\n`,
  );

  let so = null;
  if (subsetArr.length) {
    const gen = path.join(HOOK_DIR, 'gen_wrappers.js');
    const wrapper = path.join(out, 'wrapper.c');
    const plat = process.platform === 'linux' ? 'linux' : 'darwin';
    spawnSync(
      'node',
      [gen, path.join(HOOK_DIR, 'signatures.json'), '-o', wrapper, '-p', plat, '--only', subsetArr.join(',')],
      { stdio: 'inherit' },
    );
    const cc = findCC();
    if (cc) {
      so = path.join(out, `libvpo_${pkg}.so`);
      const cmd = [cc, '-shared', '-fPIC', '-I', HOOK_DIR, '-o', so, wrapper, path.join(HOOK_DIR, 'policy.c')];
      if (process.platform === 'linux') cmd.push('-ldl');
      spawnSync(cmd[0], cmd.slice(1), { stdio: 'inherit' });
    }
  }

  return { subset: subsetArr, out, so: so || null };
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
