#!/usr/bin/env bash
# SDK discover/generate 端到端测试：Python 含 C 扩展 + JS 包。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# 1. 构建 pydemo 的 C 扩展（供 nm 扫描）
cc -shared -fPIC -O2 -o test/sdk_test/pydemo/demo_ext.so test/sdk_test/pydemo/demo_ext.c

# 2. Python SDK：discover（静态反射 + nm）-> generate（裁剪编译 + plan）
PYTHONPATH=py python3 - <<'PY'
import json
import sys
from pathlib import Path
import vpoh

m = vpoh.discover("test/sdk_test/pydemo")
print("DISCOVER_PY", json.dumps(m, ensure_ascii=False)[:400])
assert m["schema"] == "vpoh.manifest.v1", m
assert any(s.startswith("fopen") or s.startswith("open") for s in m["symbols"]), m["symbols"]
assert "read_first" in m["exports"], m["exports"]
assert m["native"], m["native"]
assert "read_file" in m["apis"]["python"] or "run_cmd" in m["apis"]["python"], m["apis"]["python"]
assert m["placeholder"]["fake_symbols"]["status"] == "placeholder", m["placeholder"]

sys.path.insert(0, "test/sdk_test")
import pydemo
m_obj = vpoh.discover(pydemo)
assert "read_file" in m_obj["apis"]["python"], m_obj

class Demo:
    def read(self):
        pass

m_cls = vpoh.discover(Demo)
assert m_cls["classes"]["python"].get("Demo") == ["read"], m_cls
try:
    vpoh.discover(["python3", "server.py"])
except TypeError:
    pass
else:
    raise AssertionError("running-process/command discovery should be rejected for now")

r = vpoh.generate(m, out_dir="test/sdk_test/.vpo")
assert r["so"] and r["subset"], r
assert "fopen" in r["subset"], r
for name in ("manifest.json", "hook_plan.json", "sandbox.json", "config.yaml", "launch.sh"):
    assert (Path(r["out"]) / name).exists(), name

plan = json.loads(Path(r["hook_plan"]).read_text(encoding="utf-8"))
assert plan["schema"] == "vpoh.hook_plan.v1", plan
assert plan["binary"]["native"]["fake_symbols"]["status"] == "placeholder", plan
assert plan["rawcalls"]["status"] == "placeholder", plan
assert plan["sandbox"]["native"]["cross_package"] == "deny", plan
print("GENERATE_PY", r["subset"], r["so"])

ns_policy = {
    "schema": "vpoh.ns_policy.v1",
    "namespaces": {
        "crypto_pkg": {"role": "source", "functions": ["encrypt"]},
        "flask_app": {"role": "sink", "framework": "flask"},
    },
    "flows": [{"from": "crypto_pkg", "to": "flask_app", "action": "deny"}],
}
r_ns = vpoh.generate(m, out_dir="test/sdk_test/.vpo-ns", ns_policy=ns_policy)
assert Path(r_ns["ns_policy"]).exists(), r_ns
assert "--ns-policy" in Path(r_ns["launch"]).read_text(encoding="utf-8"), r_ns
print("NAMESPACE_POLICY", r_ns["ns_policy"])
PY

# 3. JS SDK：discover（静态扫描）-> generate（plan + launch）
node - <<'JS'
const fs = require('fs');
const vpoh = require('./js/vpoh.js');
const m = vpoh.discover('test/sdk_test/jsdemo');
console.log('DISCOVER_JS', JSON.stringify(m).slice(0, 400));
if (m.schema !== 'vpoh.manifest.v1') throw new Error('bad schema');
if (!m.apis.js.includes('readFile') && !m.apis.js.includes('exec')) {
  throw new Error('jsdemo candidate surface missing: ' + JSON.stringify(m.apis.js));
}
const mod = require('./test/sdk_test/jsdemo');
const mObj = vpoh.discover(mod);
if (!mObj.apis.js.includes('readFile') && !mObj.apis.js.includes('exec')) {
  throw new Error('module reflection missing: ' + JSON.stringify(mObj.apis.js));
}
class Demo { read() {} }
const mCls = vpoh.discover(Demo);
if (!(mCls.classes.js.Demo || []).includes('read')) {
  throw new Error('class reflection missing: ' + JSON.stringify(mCls.classes.js));
}
let rejected = false;
try { vpoh.discover(['python3', 'server.py']); } catch (_e) { rejected = true; }
if (!rejected) throw new Error('command discovery should be rejected for now');
const r = vpoh.generate(m, 'test/sdk_test/.vpo-js');
console.log('GENERATE_JS', JSON.stringify(r));
for (const name of ['manifest.json', 'hook_plan.json', 'sandbox.json', 'config.yaml', 'launch.sh']) {
  if (!fs.existsSync(`${r.out}/${name}`)) throw new Error(`missing ${name}`);
}
const plan = JSON.parse(fs.readFileSync(r.hook_plan, 'utf8'));
if (plan.rawcalls.status !== 'placeholder') throw new Error('rawcalls placeholder missing');
const policy = {
  schema: 'vpoh.ns_policy.v1',
  namespaces: {
    crypto_pkg: { role: 'source', functions: ['encrypt'] },
    flask_app: { role: 'sink', framework: 'flask' },
  },
  flows: [{ from: 'crypto_pkg', to: 'flask_app', action: 'deny' }],
};
const rNs = vpoh.generate(m, 'test/sdk_test/.vpo-js-ns', policy);
if (!fs.existsSync(rNs.ns_policy)) throw new Error('missing ns_policy.json');
if (!fs.readFileSync(rNs.launch, 'utf8').includes('--ns-policy')) {
  throw new Error('launch.sh missing --ns-policy');
}
JS

# 4. 校验生成的 subset .so 里确有 fopen/fopen64
nm -D test/sdk_test/.vpo/libvpo_pydemo.so | grep -E ' T (fopen|fopen64)$'

# 5. 校验 --config 可以被运行时消费
out=$(python3 py/vpo_hook.py run -q \
  --config test/sdk_test/.vpo/config.yaml \
  --hook test/sdk_test/.vpo/libvpo_pydemo.so \
  python3 -c 'print("CONFIG_OK")' 2>&1)
printf '%s\n' "$out"
printf '%s' "$out" | grep -q 'CONFIG_OK'

# 6. py/js SDK 对同一个 JS 包的 manifest 必须语义一致
PYTHONPATH=py python3 - <<'PY' > /tmp/vpo_manifest_py.json
import json, vpoh
print(json.dumps(vpoh.discover("test/sdk_test/jsdemo"), ensure_ascii=False, sort_keys=True))
PY
node - <<'JS' > /tmp/vpo_manifest_js.json
const vpoh = require('./js/vpoh.js');
console.log(JSON.stringify(vpoh.discover('test/sdk_test/jsdemo')));
JS
python3 - <<'PY'
import json
a = json.load(open('/tmp/vpo_manifest_py.json'))
b = json.load(open('/tmp/vpo_manifest_js.json'))
assert a == b, (a, b)
print("MANIFEST PARITY OK")
PY

# 7. 清理产物
rm -f test/sdk_test/pydemo/demo_ext.so
rm -rf test/sdk_test/.vpo test/sdk_test/.vpo-js test/sdk_test/.vpo-ns test/sdk_test/.vpo-js-ns
rm -f /tmp/vpo_manifest_py.json /tmp/vpo_manifest_js.json

echo "SDK test OK"
