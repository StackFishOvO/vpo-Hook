#!/usr/bin/env bash
# 07 配置签名 + 审计链
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

begin "07 配置签名 + 审计链"
S="$(mktemp -d /tmp/vpo_sig.XXXXXX)"
mkdir -p "$S/.vpo-hook"
cp py/obj_hook/config.yaml "$S/.vpo-hook/config.yaml"
cp py/obj_hook/honeypot.py "$S/.vpo-hook/honeypot.py"

# 签名
out=$(HOME="$S" python3 py/vpo_hook.py sign 2>&1)
contains "sign 成功" "已签名" "$out"
[ -f "$S/.vpo-hook/config.sig" ] && ok "config.sig 存在" || bad "config.sig 缺失"

# 正常签名能运行
out=$(HOME="$S" python3 py/vpo_hook.py run -q cat /etc/passwd </dev/null 2>&1)
contains "有效签名可运行" "HONEYPOT" "$out"

# 篡改后被拒
printf '\n# tampered\n' >> "$S/.vpo-hook/config.yaml"
out=$(HOME="$S" python3 py/vpo_hook.py run -q cat /etc/passwd </dev/null 2>&1)
contains "篡改后拒绝运行" "拒绝运行" "$out"

# 重新签名恢复
HOME="$S" python3 py/vpo_hook.py sign >/dev/null 2>&1
out=$(HOME="$S" python3 py/vpo_hook.py run -q cat /etc/passwd </dev/null 2>&1)
contains "重新签名后恢复" "HONEYPOT" "$out"

# 审计链：grant 追加事件，chain 校验通过；篡改后失败
HOME="$S" python3 py/vpo_hook.py grant --root "$S" network internet >/dev/null 2>&1
out=$(HOME="$S" python3 py/vpo_hook.py chain 2>&1)
contains "审计链校验通过" "校验通过" "$out"
printf '\n{"ts":1,"event":"evil","prev":"0000000000000000000000000000000000000000000000000000000000000000"}\n' >> "$S/.vpo-hook/chain.log"
out=$(HOME="$S" python3 py/vpo_hook.py chain 2>&1)
contains "审计链被篡改可检测" "校验失败" "$out"

rm -rf "$S"
end
