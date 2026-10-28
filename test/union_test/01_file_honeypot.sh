#!/usr/bin/env bash
# 01 文件蜜罐：读敏感路径返回 HONEYPOT（Python open/os.open、Node fs、cat、C fopen64）
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

begin "01 文件读取蜜罐（binary hook）"

out=$(python3 py/vpo_hook.py run -q python3 -c 'print(open("/etc/passwd").read()[:20])' 2>&1)
contains "Python builtins.open" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; fd=os.open("/etc/passwd",os.O_RDONLY); print(os.read(fd,20))' 2>&1)
contains "Python os.open (open64)" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q node -e 'console.log(require("fs").readFileSync("/etc/passwd","utf8").slice(0,20))' 2>&1)
contains "Node fs.readFileSync" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q cat /etc/passwd 2>&1)
contains "cat /etc/passwd" "HONEYPOT" "$out"

# C fopen64
cat > "$TMP/f.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
int main(int argc, char **argv){ FILE*f=fopen64(argv[1],"r"); char b[64]={0}; if(!f) return 1; fread(b,1,40,f); fputs(b,stdout); fclose(f); return 0; }
EOF
cc -O2 -o "$TMP/f" "$TMP/f.c"
out=$(python3 py/vpo_hook.py run -q "$TMP/f" /etc/passwd 2>&1)
contains "C fopen64" "HONEYPOT" "$out"

end
