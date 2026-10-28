#!/usr/bin/env bash
# 00 构建：生成 wrapper + 编译 hook 库 + 自检
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

begin "00 构建（init / 35 wrapper / 自检）"
out=$(python3 py/vpo_hook.py init 2>&1); rc=$?
contains "python init 35 wrapper" "35 个 wrapper" "$out"
contains "python init 自检" "自检通过" "$out"
[ $rc -eq 0 ] && ok "python init exit 0" || bad "python init exit $rc" "$out"

out=$(node js/vpo_hook.js init 2>&1); rc=$?
contains "js init 35 wrapper" "35 个 wrapper" "$out"
contains "js init 自检" "自检通过" "$out"
[ $rc -eq 0 ] && ok "js init exit 0" || bad "js init exit $rc" "$out"

end
