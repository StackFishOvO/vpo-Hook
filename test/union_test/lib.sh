#!/usr/bin/env bash
# union_test 公共库：定位项目根 + 断言辅助 + 临时 HOME 配置

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
T=""
TMP=""
SIMPLE_HOME=""

begin() {
  T="$1"
  PASS=0
  FAIL=0
  TMP="$(mktemp -d /tmp/vpo_union.XXXXXX)"
  echo
  echo "########## $T ##########"
}

end() {
  rm -rf "$TMP" "$SIMPLE_HOME" 2>/dev/null
  echo "== $T: PASS=$PASS FAIL=$FAIL =="
  [[ $FAIL -eq 0 ]]
}

ok() { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad() {
  echo "FAIL  $1"
  shift
  printf '%s\n' "$@" | sed 's/^/    /'
  FAIL=$((FAIL + 1))
}

contains() {
  local name="$1" expected="$2" actual="$3"
  if printf '%s' "$actual" | grep -qF -- "$expected"; then ok "$name"; else bad "$name (期望含: $expected)" "$actual"; fi
}

not_contains() {
  local name="$1" unexpected="$2" actual="$3"
  if printf '%s' "$actual" | grep -qF -- "$unexpected"; then bad "$name (不应含: $unexpected)" "$actual"; else ok "$name"; fi
}

ensure_built() {
  if [ ! -f py/obj_hook/libvpo_hook.so ] && [ ! -f "$HOME/.vpo-hook/lib/libvpo_hook.so" ]; then
    python3 py/vpo_hook.py init >/dev/null 2>&1
  fi
}

# 建一个简单安全组测试 HOME（env 作用域 + 敏感文件），路径存到 $SIMPLE_HOME
make_simple_home() {
  SIMPLE_HOME="$(mktemp -d /tmp/vpo_home.XXXXXX)"
  mkdir -p "$SIMPLE_HOME/.vpo-hook" "$SIMPLE_HOME/env" "$SIMPLE_HOME/.ssh" "$SIMPLE_HOME/.config"
  echo 'inside-file' > "$SIMPLE_HOME/env/in.txt"
  echo 'REAL_SSH_KEY' > "$SIMPLE_HOME/.ssh/id_rsa"
  echo 'REAL_NPMRC' > "$SIMPLE_HOME/.npmrc"
  cat > "$SIMPLE_HOME/.vpo-hook/config.yaml" <<EOF
version: 1
profile: simple
env: $SIMPLE_HOME/env
permissions:
  files:
    extra_read: []
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
}
