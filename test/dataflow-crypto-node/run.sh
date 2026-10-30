#!/usr/bin/env bash
# Node 版 namespace 测试：baseline / direct ns_guard / vpo-hook --ns-policy
#
# 依赖：Node.js >= 18（只用内置 http / crypto，不需要 npm install）
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NODE_BIN="${NODE:-$(command -v node)}"
cd "$HERE"

if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "找不到 node" >&2
  exit 2
fi

# 专用配置：env_root 指到测试目录，允许读取测试代码和 vpo-hook preload。
CFG="$(mktemp /tmp/vpo-dataflow-node-config.XXXXXX.yaml)"
trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<EOF
version: 1
profile: simple
name: dataflow-crypto-node
env: $HERE
permissions:
  files:
    extra_read:
      - $ROOT/js
      - $ROOT/js/plaintext
    extra_write: []
  network:
    mode: allowlist
    allowlist:
      - 127.0.0.1
    blocklist: []
  process:
    fork: true
    exec: off
    exec_allow: []
inbound:
  inspect: true
  action: audit
sources:
  allow: []
  deny: []
sensitive_files: []
audit: on
EOF

echo "===== baseline: no guard ====="
"$NODE_BIN" run_baseline.js || exit 1

echo
echo "===== guarded: direct ns_guard ====="
"$NODE_BIN" run_guarded.js || exit 1

echo
echo "===== guarded: vpo-hook --ns-policy ====="
LIB_JS="$ROOT/js/obj_hook/libvpo_hook.so"
LIB_HOME="$HOME/.vpo-hook/lib/libvpo_hook.so"
if [[ ! -f "$LIB_JS" && ! -f "$LIB_HOME" ]]; then
  echo "hook 库还没编译，请先运行：python3 $ROOT/py/vpo_hook.py init" >&2
  exit 2
fi
"$NODE_BIN" "$ROOT/js/vpo_hook.js" run -q \
  --config "$CFG" \
  --ns-policy "$HERE/ns_policy.json" \
  "$NODE_BIN" "$HERE/run_guarded.js"
