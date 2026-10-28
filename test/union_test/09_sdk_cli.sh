#!/usr/bin/env bash
# 09 SDK（discover/generate）+ CLI 子命令 + 模板
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

begin "09 SDK + CLI + 模板"

# 构建 pydemo 的 C 扩展，供 discover 扫描
cc -shared -fPIC -O2 -o test/sdk_test/pydemo/demo_ext.so test/sdk_test/pydemo/demo_ext.c

# SDK discover（Python）
out=$(PYTHONPATH=py python3 -c 'import vpoh; m=vpoh.discover("test/sdk_test/pydemo"); print("PY", "read_file" in m["apis"]["python"], any("fopen" in s for s in m["symbols"]))' 2>&1)
contains "SDK discover pydemo" "PY True True" "$out"

# SDK generate（Python，编译 subset .so）
out=$(PYTHONPATH=py python3 -c 'import vpoh; r=vpoh.generate(vpoh.discover("test/sdk_test/pydemo"), out_dir="'$TMP'/gen"); print("GEN", r["subset"], r["so"])' 2>&1)
contains "SDK generate subset" "GEN ['fopen']" "$out"
[ -f "$TMP/gen/libvpo_pydemo.so" ] && ok "subset .so 生成" || bad "subset .so 缺失"

# CLI discover（Python 包用 py，JS 包用 js）
out=$(python3 py/vpo_hook.py discover test/sdk_test/pydemo 2>&1)
contains "CLI discover pydemo" '"read_file"' "$out"
out=$(node js/vpo_hook.js discover test/sdk_test/jsdemo 2>&1)
contains "JS CLI discover jsdemo" '"exec"' "$out"

# 模板：init --profile simple
S="$(mktemp -d /tmp/vpo_tpl.XXXXXX)"
HOME="$S" python3 py/vpo_hook.py init --profile simple >/dev/null 2>&1
out=$(grep 'profile:' "$S/.vpo-hook/config.yaml")
contains "init --profile simple" "simple" "$out"

rm -f test/sdk_test/pydemo/demo_ext.so
rm -rf "$S"
end
