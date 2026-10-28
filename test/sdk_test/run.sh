#!/usr/bin/env bash
# SDK discover/generate 端到端测试：选一个包（Python 含 C 扩展 + JS）跑 discover/generate。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# 1. 构建 pydemo 的 C 扩展（供 nm 扫描）
cc -shared -fPIC -O2 -o test/sdk_test/pydemo/demo_ext.so test/sdk_test/pydemo/demo_ext.c

# 2. Python SDK：discover（反射候选面 + nm）-> generate（裁剪编译）
PYTHONPATH=py python3 - <<'PY'
import json
import vpoh

m = vpoh.discover("test/sdk_test/pydemo")
print("DISCOVER_PY", json.dumps(m, ensure_ascii=False)[:400])
assert any(s.startswith("fopen") or s.startswith("open") for s in m["symbols"]), m["symbols"]
assert "read_file" in m["apis"]["python"] or "run_cmd" in m["apis"]["python"], m["apis"]["python"]

r = vpoh.generate(m, out_dir="test/sdk_test/.vpo")
assert r["so"] and r["subset"], r
assert "fopen" in r["subset"], r
print("GENERATE_PY", r["subset"], r["so"])
PY

# 3. JS SDK：discover（反射候选面）
node - <<'JS'
const vpoh = require('./js/vpoh.js');
const m = vpoh.discover('test/sdk_test/jsdemo');
console.log('DISCOVER_JS', JSON.stringify(m).slice(0, 400));
if (!m.apis.js.includes('readFile') && !m.apis.js.includes('exec')) {
  throw new Error('jsdemo candidate surface missing: ' + JSON.stringify(m.apis.js));
}
JS

# 4. 校验生成的 subset .so 里确有 fopen/fopen64
nm -D test/sdk_test/.vpo/libvpo_pydemo.so | grep -E ' T (fopen|fopen64)$'

# 5. 清理产物
rm -f test/sdk_test/pydemo/demo_ext.so
rm -rf test/sdk_test/.vpo

echo "SDK test OK"
