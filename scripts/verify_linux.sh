#!/usr/bin/env bash
# VPO-Hook Linux 验收脚本。
# 完整输出会同时写终端和 logs/verify-linux-<时间>.log。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/verify-linux-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

PASS=0
FAIL=0
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f /tmp/vpo_write_test.txt /tmp/vpo_pwned_flag "$ROOT/example/malicious.pkl" /tmp/vpo_ctest.c /tmp/vpo_ctest.so 2>/dev/null || true
}
trap cleanup EXIT

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

check_contains() {
  local name="$1" expected="$2" actual="$3"
  if grep -qF -- "$expected" <<<"$actual"; then
    pass "$name"
  else
    fail "$name (expected: $expected)" "$actual"
  fi
}

check_exact() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
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

run_case() {
  local name="$1" expected="$2"
  shift 2
  section "CASE: $name"
  printf '+ '
  printf '%q ' "$@"
  echo
  local out rc
  out=$("$@" 2>&1)
  rc=$?
  printf '%s\n' "$out"
  if [[ $rc -ne 0 ]]; then
    fail "$name (exit $rc)" "$out"
    return
  fi
  check_contains "$name" "$expected" "$out"
}

run_case_any() {
  local name="$1" expected="$2"
  shift 2
  section "CASE: $name"
  printf '+ '
  printf '%q ' "$@"
  echo
  local out
  out=$("$@" 2>&1)
  printf '%s\n' "$out"
  check_contains "$name" "$expected" "$out"
}

section "environment"
echo "log: $LOG"
uname -a
python3 -V
node -v 2>/dev/null || echo "node: missing"
cc --version 2>/dev/null | head -1 || echo "cc: missing"

section "init"
out=$(python3 py/vpo_hook.py init 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "python init exit" 0 "$rc"
check_contains "python init wrappers" "35 个 wrapper" "$out"
check_contains "python init selfcheck" "自检通过" "$out"

out=$(node js/vpo_hook.js init 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "js init exit" 0 "$rc"
check_contains "js init wrappers" "35 个 wrapper" "$out"
check_contains "js init selfcheck" "自检通过" "$out"

section "generator parity"
out=$(python3 py/obj_hook/gen_wrappers.py py/obj_hook/signatures.json -o /tmp/vpo_w_py.c -p linux 2>&1)
printf '%s\n' "$out"
out2=$(node js/obj_hook/gen_wrappers.js py/obj_hook/signatures.json -o /tmp/vpo_w_js.c -p linux 2>&1)
printf '%s\n' "$out2"
if diff -q /tmp/vpo_w_py.c /tmp/vpo_w_js.c >/dev/null; then
  pass "linux generator parity"
else
  fail "linux generator parity"
fi

out=$(python3 py/obj_hook/gen_wrappers.py py/obj_hook/signatures.json -o /tmp/vpo_d_py.c -p darwin 2>&1)
printf '%s\n' "$out"
out2=$(node js/obj_hook/gen_wrappers.js py/obj_hook/signatures.json -o /tmp/vpo_d_js.c -p darwin 2>&1)
printf '%s\n' "$out2"
if diff -q /tmp/vpo_d_py.c /tmp/vpo_d_js.c >/dev/null; then
  pass "darwin generator parity"
else
  fail "darwin generator parity"
fi

section "symbols"
out=$(nm -D py/obj_hook/libvpo_hook.so | grep -E ' T (open|open64|openat|openat64|fopen|fopen64|execve|execv|execvp|posix_spawn|posix_spawnp|vfork)$')
printf '%s\n' "$out"
n=$(printf '%s\n' "$out" | grep -c ' T ')
check_exact "LFS/process symbols" "12" "$n"

section "subprocess escape"
run_case "execve empty env" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; os.execve("/usr/bin/python3", ["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], {})'

run_case "Popen empty env" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import subprocess; subprocess.Popen(["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], env={}).wait()'

run_case "posix_spawn empty env" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; pid=os.posix_spawn("/usr/bin/python3", ["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], {}); os.waitpid(pid, 0)'

run_case "shell env -i" "HONEYPOT" \
  python3 py/vpo_hook.py run -q sh -c 'env -i /usr/bin/python3 -c "print(open(\"/etc/passwd\").read()[:20])"'

run_case "execv after environ.clear" "VPO_HOOK_CONFIG=" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; os.environ.clear(); os.execv("/usr/bin/env", ["env"])'

run_case "execvp after environ.clear" "LD_PRELOAD=" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; os.environ.clear(); os.execvp("env", ["env"])'

section "CASE: vfork/sh regression"
out=$(python3 py/vpo_hook.py run -q sh -c /usr/bin/true 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "sh -c true exit" 0 "$rc"
if grep -q 'stack smashing' <<<"$out"; then
  fail "vfork stack smashing"
else
  pass "vfork stack smashing absent"
fi

section "CASE: libc system after environ.clear"
out=$(python3 py/vpo_hook.py run -q python3 -c 'import ctypes, os; os.environ.clear(); ctypes.CDLL(None).system(b"env | grep VPO_HOOK_CONFIG")' 2>&1)
printf '%s\n' "$out"
check_contains "libc system env" "VPO_HOOK_CONFIG=" "$out"

section "CASE: guest-forged policy env"
run_case "execv clears deny_paths" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; os.environ["VPO_DENY_PATHS"]=""; os.execv("/usr/bin/python3", ["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"])'

run_case "execve forged envp" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; os.execve("/usr/bin/python3", ["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], {"VPO_DENY_PATHS":"", "LD_PRELOAD":"", "VPO_HOOK_CONFIG":"/tmp/nope"})'

section "CASE: environment merge"
out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; os.execve("/usr/bin/env", ["env"], {"PYTHONPATH":"/tmp/mydir"})' 2>&1)
printf '%s\n' "$out"
check_contains "PYTHONPATH merge" "/py/plaintext:/tmp/mydir" "$out"

out=$(python3 py/vpo_hook.py run -q node -e 'require("child_process").execFileSync("/usr/bin/env", ["env"], {env:{NODE_OPTIONS:"--no-warnings"}, stdio:"inherit"})' 2>&1)
printf '%s\n' "$out"
check_contains "NODE_OPTIONS merge" "preload.js --no-warnings" "$out"

section "file/network/write regression"
run_case "python builtins.open" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'print(open("/etc/passwd").read()[:20])'

run_case "python os.open" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import os; fd=os.open("/etc/passwd", os.O_RDONLY); print(os.read(fd, 20))'

run_case "node fs.readFileSync" "HONEYPOT" \
  python3 py/vpo_hook.py run -q node -e 'console.log(require("fs").readFileSync("/etc/passwd", "utf8").slice(0, 20))'

run_case "cat /etc/passwd" "HONEYPOT" \
  python3 py/vpo_hook.py run -q cat /etc/passwd

run_case "allowed read" "# 真实漏洞测试" \
  python3 py/vpo_hook.py run -q python3 -c 'print(open("example/README.md").readline().strip())'

run_case_any "network deny" "PermissionError" \
  python3 py/vpo_hook.py run -q python3 -c 'import socket; socket.create_connection(("1.1.1.1", 80), timeout=2)'

run_case "network allow" "ALLOWED" \
  python3 py/vpo_hook.py run -q python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect(("8.8.8.8", 53)); print("ALLOWED")'

section "CASE: write marker"
rm -f /tmp/vpo_write_test.txt
python3 py/vpo_hook.py run -q python3 -c 'open("/tmp/vpo_write_test.txt", "w").write("password=leak")' >/dev/null 2>&1
size=$(stat -c%s /tmp/vpo_write_test.txt 2>/dev/null || echo missing)
check_exact "write marker bytes" "0" "$size"

section "CASE: pickle RCE"
rm -f /tmp/vpo_pwned_flag example/malicious.pkl
(cd example && python3 exploit/make_malicious_pickle.py >/dev/null)
run_case_any "pickle CapabilityDenied" "CapabilityDenied" \
  python3 py/vpo_hook.py run -q python3 example/victim/vulnerable_unpickle.py example/malicious.pkl
if [[ ! -e /tmp/vpo_pwned_flag ]]; then
  pass "pickle flag absent"
else
  fail "pickle flag present"
fi
rm -f example/malicious.pkl

section "CASE: quiet mode"
out=$(python3 py/vpo_hook.py run -q python3 -c 'print("CHILD")' 2>&1)
printf '%s\n' "$out"
check_exact "quiet python output" "CHILD" "$out"

out=$(node js/vpo_hook.js run -q node -e 'console.log("CHILD")' 2>&1)
printf '%s\n' "$out"
check_exact "quiet node output" "CHILD" "$out"

section "CASE: JS launcher"
run_case "js launcher Popen" "HONEYPOT" \
  node js/vpo_hook.js run -q python3 -c 'import subprocess; subprocess.Popen(["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], env={}).wait()'

run_case "js launcher execve" "HONEYPOT" \
  node js/vpo_hook.js run -q python3 -c 'import os; os.execve("/usr/bin/python3", ["python3", "-c", "print(open(\"/etc/passwd\").read()[:20])"], {})'

section "CASE: CVE-2026-111497"
if command -v curl >/dev/null && command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -q ':3000'; then
  fail "CVE test skipped: port 3000 busy"
else
  cd test/cve-2026-111497
  timeout 6 node server.js >/tmp/vpo_ctrl.log 2>&1 &
  SERVER_PID=$!
  sleep 1
  out=$(curl -s http://localhost:3000/op/readfile)
  printf '%s\n' "$out"
  check_contains "CVE control read" "root:x:0:0:root" "$out"
  out=$(curl -s http://localhost:3000/op/exec)
  printf '%s\n' "$out"
  check_contains "CVE control exec" "RCE_COMMAND_EXECUTED" "$out"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  cd "$ROOT"

  timeout 6 python3 py/vpo_hook.py run -q node test/cve-2026-111497/server.js >/tmp/vpo_prot.log 2>&1 &
  SERVER_PID=$!
  sleep 1.5
  out=$(curl -s http://localhost:3000/op/readfile)
  printf '%s\n' "$out"
  check_contains "CVE protected read" "HONEYPOT" "$out"
  out=$(curl -s http://localhost:3000/op/exec)
  printf '%s\n' "$out"
  check_contains "CVE protected exec" "CAPABILITY_DENIED" "$out"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""

  if ss -ltn 2>/dev/null | grep -q ':3000'; then
    fail "CVE port 3000 not released"
  else
    pass "CVE port 3000 released"
  fi
fi

section "C extension / shell / node addon"
cat > /tmp/vpo_ctest.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
char *read_first(const char *path){ FILE *f=fopen64(path,"r"); if(!f) return ""; static char b[64]; size_t n=fread(b,1,40,f); b[n]=0; fclose(f); return b; }
EOF
cc -shared -fPIC -O2 -o /tmp/vpo_ctest.so /tmp/vpo_ctest.c

run_case "C extension fopen64" "HONEYPOT" \
  python3 py/vpo_hook.py run -q python3 -c 'import ctypes; lib=ctypes.CDLL("/tmp/vpo_ctest.so"); lib.read_first.restype=ctypes.c_char_p; print(lib.read_first(b"/etc/passwd"))'

run_case "shell sh -c cat" "HONEYPOT" \
  python3 py/vpo_hook.py run -q sh -c "cat /etc/passwd | head -1"

if command -v node-gyp >/dev/null 2>&1; then
  (cd test/node_bin_wrapper_test && node-gyp rebuild >/dev/null 2>&1)
  run_case "node native addon readFirst" "HONEYPOT" \
    python3 py/vpo_hook.py run -q node -e 'console.log(require("./test/node_bin_wrapper_test/build/Release/testaddon.node").readFirst("/etc/passwd"))'
else
  echo "SKIP node native addon (node-gyp 未安装)"
fi

section "SDK discover/generate"
out=$(bash test/sdk_test/run.sh 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "SDK test exit" 0 "$rc"
check_contains "SDK test result" "SDK test OK" "$out"

section "release sync"
out=$(python3 scripts/release.py --check 2>&1)
rc=$?
printf '%s\n' "$out"
check_status "release.py --check exit" 0 "$rc"
check_contains "release.py --check result" "release check: OK" "$out"

diff_py=$(diff -rq py/obj_hook release/py/vpohook/obj_hook 2>&1 || true)
printf '%s\n' "$diff_py"
unexpected_py=$(printf '%s\n' "$diff_py" | grep -vE '^Only in py/obj_hook: (libvpo_hook\.(so|dylib)|wrapper\.c)$' | grep -v '^$' || true)
if [[ -z "$unexpected_py" ]]; then
  pass "release py sync"
else
  fail "release py sync" "$unexpected_py"
fi

diff_js=$(diff -rq js/obj_hook release/js/obj_hook 2>&1 || true)
printf '%s\n' "$diff_js"
unexpected_js=$(printf '%s\n' "$diff_js" | grep -vE '^Only in js/obj_hook: (libvpo_hook\.(so|dylib)|wrapper\.c)$' | grep -v '^$' || true)
if [[ -z "$unexpected_js" ]]; then
  pass "release js sync"
else
  fail "release js sync" "$unexpected_js"
fi

python3 release/py/vpohook/obj_hook/gen_wrappers.py \
  release/py/vpohook/obj_hook/signatures.json -o /tmp/vpo_r_py.c -p linux >/dev/null
node release/js/obj_hook/gen_wrappers.js \
  release/js/obj_hook/signatures.json -o /tmp/vpo_r_js.c -p linux >/dev/null
if diff -q /tmp/vpo_r_py.c /tmp/vpo_r_js.c >/dev/null; then
  pass "release generator parity"
else
  fail "release generator parity"
fi

section "SUMMARY"
echo "PASS=$PASS FAIL=$FAIL"
echo "log: $LOG"
if [[ $FAIL -ne 0 ]]; then
  exit 1
fi
