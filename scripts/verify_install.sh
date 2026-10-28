#!/usr/bin/env bash
# 验证从 release/ 目录本地安装（pip / npm）→ init → run 的完整链路。
#
# 用法:
#   bash scripts/verify_install.sh
#
# 说明:
#   - 不访问 registry，只从 release/py、release/js 本地安装。
#   - 使用临时 venv / npm prefix / HOME，不污染当前环境。
#   - 需要 python3、node、npm，以及 clang/cc/gcc 之一（init 本机编译）。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/vpo_install_verify.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0
FAIL=0

section() { echo; echo "===== $* ====="; }
pass() { echo "PASS  $1"; PASS=$((PASS + 1)); }
fail() {
  echo "FAIL  $1"
  shift
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$*" | sed 's/^/  | /'
  fi
  FAIL=$((FAIL + 1))
}

contains() {
  local name="$1" expected="$2" actual="$3"
  if grep -qF -- "$expected" <<<"$actual"; then
    pass "$name"
  else
    fail "$name (expected: $expected)" "$actual"
  fi
}

check_status() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" -eq "$expected" ]]; then
    pass "$name"
  else
    fail "$name (expected exit $expected, got $actual)"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "缺少命令: $1" >&2
    exit 2
  fi
}

need_cmd python3
need_cmd node
need_cmd npm

CC=""
for cc in clang cc gcc; do
  if command -v "$cc" >/dev/null 2>&1; then
    CC="$cc"
    break
  fi
done
if [[ -z "$CC" ]]; then
  echo "缺少 C 编译器（clang/cc/gcc），无法验证 init 本机编译" >&2
  exit 2
fi

section "environment"
echo "uname: $(uname -a)"
echo "python: $(python3 -V 2>&1)"
echo "node: $(node -v 2>&1)"
echo "npm: $(npm -v 2>&1)"
echo "cc: $CC"

section "release snapshot"
out=$(python3 scripts/release.py --check 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "release.py --check exit" 0 "$rc"
contains "release.py --check result" "release check: OK" "$out"

# ---------------------------------------------------------------------------
# pip install from release/py
# ---------------------------------------------------------------------------
section "pip install from release/py"
python3 -m venv "$TMP/venv" >/dev/null 2>&1
rc=$?
check_status "venv create" 0 "$rc"
PY="$TMP/venv/bin/python"
PIP_BIN="$TMP/venv/bin/vpo-hook"

if [[ -x "$PY" ]]; then
  if ! "$PY" -m pip install --no-deps --no-build-isolation ./release/py >"$TMP/pip.log" 2>&1; then
    echo "WARN: --no-build-isolation 失败，尝试默认 build isolation（可能需要网络）"
    "$PY" -m pip install --no-deps --timeout 10 --retries 0 ./release/py >>"$TMP/pip.log" 2>&1
  fi
  rc=$?
  if [[ $rc -ne 0 ]]; then
    fail "pip install" "$(tail -n 20 "$TMP/pip.log" 2>/dev/null)"
  else
    pass "pip install"
  fi
fi

if [[ -x "$PIP_BIN" ]]; then
  pass "pip console script exists"
else
  fail "pip console script exists"
fi

# ---------------------------------------------------------------------------
# npm install from release/js
# ---------------------------------------------------------------------------
section "npm install from release/js"
mkdir -p "$TMP/npm-prefix" "$TMP/npm-cache"
npm install -g --prefix "$TMP/npm-prefix" --cache "$TMP/npm-cache" --no-audit --no-fund \
  ./release/js >"$TMP/npm.log" 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
  fail "npm install" "$(tail -n 20 "$TMP/npm.log" 2>/dev/null)"
else
  pass "npm install"
fi
NPM_BIN="$TMP/npm-prefix/bin/vpo-hook"
if [[ -x "$NPM_BIN" ]]; then
  pass "npm bin exists"
else
  fail "npm bin exists"
fi

# ---------------------------------------------------------------------------
# 安装后：init + status + run
# ---------------------------------------------------------------------------
verify_runtime() {
  local name="$1" bin="$2"
  local home="$TMP/home-$name"

  mkdir -p "$home/.ssh"
  printf 'REAL_SECRET_VALUE\n' > "$home/.ssh/id_rsa"

  out=$(HOME="$home" "$bin" init --profile simple 2>&1)
  rc=$?
  printf '%s\n' "$out" | sed "s/^/[${name} init] /"
  check_status "$name init exit" 0 "$rc"
  contains "$name init selfcheck" "自检通过" "$out"

  out=$(HOME="$home" "$bin" status 2>&1)
  rc=$?
  printf '%s\n' "$out" | sed "s/^/[${name} status] /"
  check_status "$name status exit" 0 "$rc"
  contains "$name status hook lib" "hook 库" "$out"

  out=$(HOME="$home" "$bin" run -q python3 -c \
    "print(open('$home/.ssh/id_rsa').read().strip())" 2>&1)
  rc=$?
  check_status "$name python run exit" 0 "$rc"
  contains "$name python honeypot" "HONEYPOT_FAKE_DATA" "$out"

  out=$(HOME="$home" "$bin" run -q node -e \
    "console.log(require('fs').readFileSync('$home/.ssh/id_rsa','utf8').trim())" 2>&1)
  rc=$?
  check_status "$name node run exit" 0 "$rc"
  contains "$name node honeypot" "HONEYPOT_FAKE_DATA" "$out"

  out=$(HOME="$home" "$bin" run -q cat "$home/.ssh/id_rsa" 2>&1)
  rc=$?
  check_status "$name cat run exit" 0 "$rc"
  contains "$name cat honeypot" "HONEYPOT_FAKE_DATA" "$out"
}

section "pip package: init + run"
if [[ -x "$PIP_BIN" ]]; then
  verify_runtime "pip" "$PIP_BIN"
else
  fail "pip package: init + run (binary missing)"
fi

section "npm package: init + run"
if [[ -x "$NPM_BIN" ]]; then
  verify_runtime "npm" "$NPM_BIN"
else
  fail "npm package: init + run (binary missing)"
fi

section "SUMMARY"
echo "PASS=$PASS FAIL=$FAIL"
if [[ $FAIL -ne 0 ]]; then
  exit 1
fi
