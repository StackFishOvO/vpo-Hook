#!/usr/bin/env bash
# 03 网络三态 + exec 模式（简单安全组）
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built
make_simple_home

write_cfg() {
  local netmode="$1" allowlist="$2" execmode="$3" execallow="$4"
  cat > "$SIMPLE_HOME/.vpo-hook/config.yaml" <<EOF
version: 1
profile: simple
env: $SIMPLE_HOME/env
permissions:
  files:
    extra_read: []
    extra_write: []
  network:
    mode: $netmode
    allowlist:
$allowlist
    blocklist: []
  process:
    fork: true
    exec: $execmode
    exec_allow:
$execallow
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

begin "03 网络三态 + exec 模式"

# network off
write_cfg off "" off ""
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import socket; socket.create_connection(("8.8.8.8",80),timeout=2)' 2>&1)
contains "network off 拒绝出站" "Operation not permitted" "$out"

# network internet：loopback 一视同仁拒绝，公网 80 放行
write_cfg internet "" off ""
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import socket; socket.create_connection(("127.0.0.1",80),timeout=2)' 2>&1)
contains "internet 拒绝 loopback" "Operation not permitted" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import socket; socket.create_connection(("8.8.8.8",80),timeout=2)' 2>&1)
not_contains "internet 放行公网 80" "Operation not permitted" "$out"

# network allowlist
write_cfg allowlist '      - "8.8.8.8:53"' off ""
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect(("8.8.8.8",53)); print("ALLOWED")' 2>&1)
contains "allowlist 白名单内放行" "ALLOWED" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect(("1.1.1.1",53)); print("BAD")' 2>&1)
contains "allowlist 白名单外拒绝" "Operation not permitted" "$out"

# exec off
write_cfg off "" off ""
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import subprocess; subprocess.run(["/bin/echo","hi"])' 2>&1)
contains "exec off 拒绝子进程" "Operation not permitted" "$out"

# exec allowlist
write_cfg off "" allowlist '      - "/bin/echo"'
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import subprocess; p=subprocess.run(["/bin/echo","hi"],capture_output=True,text=True); print("OUT", p.stdout.strip())' 2>&1)
contains "exec allowlist 放行 /bin/echo" "OUT hi" "$out"
out=$(HOME="$SIMPLE_HOME" python3 py/vpo_hook.py run -q python3 -c 'import subprocess; subprocess.run(["/bin/sh","-c","echo hi"])' 2>&1)
contains "exec allowlist 拒绝 /bin/sh" "Operation not permitted" "$out"

end
