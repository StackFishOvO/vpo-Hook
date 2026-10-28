#!/usr/bin/env bash
# 06 审计闭环：deny -> denials.log -> 结束摘要 -> log/grant/list/revoke
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built
make_simple_home

begin "06 deny + audit + grant 闭环"

# 触发一次拒绝（读 env 外文件）
HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q cat /home/stackfishovo/.bashrc </dev/null >/dev/null 2>&1

# denials.log 有结构化记录
[ -f "$SIMPLE_HOME/.vpo-hook/denials.log" ] && ok "denials.log 存在" || bad "denials.log 不存在"
out=$(cat "$SIMPLE_HOME/.vpo-hook/denials.log" 2>/dev/null)
contains "denials.log 含 open" '"func":"open"' "$out"

# 结束摘要（不加 -q）
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run cat /home/stackfishovo/.bashrc </dev/null 2>&1)
contains "run 结束打印拒绝摘要" "本次被拒绝" "$out"

# vpo-hook log
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py log 2>&1)
contains "log 显示拒绝记录" "open" "$out"

# grant network internet -> list -> 生效
HOME="$SIMPLE_HOME" python3 py/vpo_hook.py grant --root "$SIMPLE_HOME/env" network internet >/dev/null 2>&1
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py list 2>&1)
contains "list 显示 internet" "internet" "$out"

# revoke -> list 空
HOME="$SIMPLE_HOME" python3 py/vpo_hook.py revoke --root "$SIMPLE_HOME/env" >/dev/null 2>&1
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py list 2>&1)
not_contains "revoke 后无授权" "internet" "$out"

end
