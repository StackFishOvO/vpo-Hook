#!/usr/bin/env bash
# 一键验证：baseline / direct guard / vpo-hook + ns_policy
#
# 依赖：
#   python3 -m venv .venv
#   .venv/bin/pip install -r requirements.txt
#   PYTHON=.venv/bin/python ./run.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PYTHON="${PYTHON:-python3}"

# vpo-hook 的简单组会用目标解释器推断 env_root；这里统一用绝对路径，
# 避免相对路径导致 pyvenv.cfg / 测试脚本被判定在 env_root 之外。
if [[ "$PYTHON" != */* ]]; then
  PYTHON="$(command -v "$PYTHON")"
fi
PYTHON="$(cd "$(dirname "$PYTHON")" && pwd)/$(basename "$PYTHON")"
cd "$HERE"

if ! "$PYTHON" -c 'import flask, cryptography' >/dev/null 2>&1; then
  echo "缺少 flask/cryptography，请先：" >&2
  echo "  python3 -m venv .venv" >&2
  echo "  .venv/bin/pip install -r requirements.txt" >&2
  exit 2
fi

# 专用配置：env_root 指到本测试目录，允许读取 app.py / .venv / crypto_pkg。
CFG="$(mktemp /tmp/vpo-dataflow-config.XXXXXX.yaml)"
trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<EOF
version: 1
profile: simple
name: dataflow-crypto-flask
env: $HERE
permissions:
  files:
    extra_read:
      - $ROOT/py
      - $ROOT/py/plaintext
    extra_write: []
  network:
    mode: off
    allowlist: []
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
"$PYTHON" run_baseline.py || exit 1

echo
echo "===== guarded: direct ns_guard ====="
"$PYTHON" run_guarded.py || exit 1

echo
echo "===== guarded: vpo-hook --ns-policy ====="
LIB_PY="$ROOT/py/obj_hook/libvpo_hook.so"
LIB_HOME="$HOME/.vpo-hook/lib/libvpo_hook.so"
if [[ ! -f "$LIB_PY" && ! -f "$LIB_HOME" ]]; then
  echo "hook 库还没编译，请先运行：python3 $ROOT/py/vpo_hook.py init" >&2
  exit 2
fi
"$PYTHON" "$ROOT/py/vpo_hook.py" run -q \
  --config "$CFG" \
  --ns-policy "$HERE/ns_policy.json" \
  "$PYTHON" "$HERE/run_guarded.py"
