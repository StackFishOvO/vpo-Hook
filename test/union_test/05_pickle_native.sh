#!/usr/bin/env bash
# 05 pickle RCE + 原生扩展（ctypes .so / shell / node addon）蜜罐
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

begin "05 pickle RCE + 原生扩展蜜罐"

# pickle RCE
rm -f /tmp/vpo_pwned_flag example/malicious.pkl
(cd example && python3 exploit/make_malicious_pickle.py >/dev/null)
out=$(python3 py/vpo_hook.py run -q python3 example/victim/vulnerable_unpickle.py example/malicious.pkl 2>&1)
contains "pickle RCE 被拦" "CapabilityDenied" "$out"
[ ! -e /tmp/vpo_pwned_flag ] && ok "pickle 未生成 flag" || bad "pickle 生成了 flag"
rm -f example/malicious.pkl

# C 扩展（ctypes .so，fopen64）
cat > "$TMP/ext.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
char *read_first(const char *path){ FILE*f=fopen64(path,"r"); if(!f)return ""; static char b[64]; size_t n=fread(b,1,40,f); b[n]=0; fclose(f); return b; }
EOF
cc -shared -fPIC -O2 -o "$TMP/ext.so" "$TMP/ext.c"
out=$(python3 py/vpo_hook.py run -q python3 -c "import ctypes; lib=ctypes.CDLL('$TMP/ext.so'); lib.read_first.restype=ctypes.c_char_p; print(lib.read_first(b'/etc/passwd'))" 2>&1)
contains "C 扩展 ctypes fopen64" "HONEYPOT" "$out"

# shell 外部命令
out=$(python3 py/vpo_hook.py run -q sh -c "cat /etc/passwd | head -1" 2>&1)
contains "shell 外部命令 cat" "HONEYPOT" "$out"

# node 原生 addon（N-API，open/read）
if command -v node-gyp >/dev/null 2>&1; then
  (cd test/node_bin_wrapper_test && node-gyp rebuild >/dev/null 2>&1)
  out=$(python3 py/vpo_hook.py run -q node -e 'console.log(require("./test/node_bin_wrapper_test/build/Release/testaddon.node").readFirst("/etc/passwd"))' 2>&1)
  contains "node 原生 addon" "HONEYPOT" "$out"
else
  echo "SKIP node addon（node-gyp 未安装）"
fi

end
