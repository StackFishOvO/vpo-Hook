#!/usr/bin/env bash
# 04 env 作用域 + 敏感 deny + 蜜罐 + 写标记
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built
make_simple_home

begin "04 env 作用域 / 敏感 deny / 写标记"

# 系统读取不再误拦：python/node 能启动
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'print("PY_OK")' </dev/null 2>&1)
contains "python 启动（/etc 放行）" "PY_OK" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q node -e 'console.log("NODE_OK")' </dev/null 2>&1)
contains "node 启动" "NODE_OK" "$out"

# /etc/passwd 真实可读（系统信息，非 secret）
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat /etc/passwd </dev/null 2>&1)
contains "/etc/passwd 真实" "root:x:0:0:root" "$out"

# env 内放行、env 外拒绝
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat "$SIMPLE_HOME/env/in.txt" </dev/null 2>&1)
contains "env 内文件放行" "inside-file" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat /home/stackfishovo/.bashrc </dev/null 2>&1)
contains "env 外文件拒绝" "Operation not permitted" "$out"

# 敏感 deny：目录（~/.ssh）与文件（~/.npmrc）蜜罐
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat "$SIMPLE_HOME/.ssh/id_rsa" </dev/null 2>&1)
contains "~/.ssh/id_rsa 蜜罐" "HONEYPOT" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat "$SIMPLE_HOME/.npmrc" </dev/null 2>&1)
contains "~/.npmrc 蜜罐" "HONEYPOT" "$out"

# /tmp 可写
rm -f "$TMP/w.txt"
HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c "open('$TMP/w.txt','w').write('ok')" </dev/null >/dev/null 2>&1
[ -f "$TMP/w.txt" ] && ok "/tmp 可写" || bad "/tmp 不可写"

# 写敏感标记 -> 0 字节
rm -f "$TMP/leak.txt"
HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c "open('$TMP/leak.txt','w').write('password=leak')" </dev/null >/dev/null 2>&1
size=$(stat -c%s "$TMP/leak.txt" 2>/dev/null || echo missing)
[ "$size" = "0" ] && ok "写敏感标记被拦（0 字节）" || bad "写敏感标记未被拦（$size 字节）"

# 蜜罐模式：写敏感数据 -> 内容被替换成 HONEYPOT
rm -f "$TMP/hp.txt"
VPO_DATA_MODE=honeypot HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c "open('$TMP/hp.txt','w').write('my password 123')" </dev/null >/dev/null 2>&1
contains "蜜罐模式写被替换" "HONEYPOT" "$(cat "$TMP/hp.txt" 2>/dev/null)"

end
