#!/usr/bin/env bash
# 08 能力扫描 + L2 信源（deny-only）
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

begin "08 能力扫描 + 信源"

# vpo-hook scan
out=$(python3 py/vpo_hook.py scan example/ 2>&1)
contains "scan 识别 file" "file" "$out"
contains "scan 识别 process" "process" "$out"

# L2：deny 包被拒，非 deny 放行（Python）
SP="$(mktemp -d /tmp/vpo_sp.XXXXXX)"
mkdir -p "$SP/site-packages/evilpkg"
cat > "$SP/site-packages/evilpkg/__init__.py" <<'EOF'
import socket, subprocess
def net(): socket.create_connection(('127.0.0.1', 9), timeout=1)
def run(): subprocess.check_output(['true'])
EOF

out=$(PYTHONPATH="py/plaintext:$SP/site-packages" VPO_HOOK_QUIET=1 VPO_SOURCES_DENY=evilpkg python3 -c 'import evilpkg; evilpkg.run()' 2>&1)
contains "Python deny 包 subprocess 被拒" "CapabilityDenied" "$out"
out=$(PYTHONPATH="py/plaintext:$SP/site-packages" VPO_HOOK_QUIET=1 VPO_SOURCES_DENY=other python3 -c 'import evilpkg; evilpkg.run(); print("ALLOWED")' 2>&1)
contains "Python 非 deny 包放行" "ALLOWED" "$out"

# L2 JS
NM="$(mktemp -d /tmp/vpo_nm.XXXXXX)"
mkdir -p "$NM/node_modules/evilpkg"
cat > "$NM/node_modules/evilpkg/index.js" <<'EOF'
const cp = require('child_process');
module.exports = { exec: () => cp.execFileSync('true') };
EOF
P="$ROOT/js/plaintext/preload.js"
out=$(cd "$NM" && VPO_HOOK_QUIET=1 VPO_SOURCES_DENY=evilpkg NODE_OPTIONS="--require $P" node -e "require('evilpkg').exec(); console.log('BAD')" 2>&1)
contains "JS deny 包被拒" "CapabilityDenied" "$out"
out=$(cd "$NM" && VPO_HOOK_QUIET=1 VPO_SOURCES_DENY=other NODE_OPTIONS="--require $P" node -e "require('evilpkg').exec(); console.log('ALLOWED')" 2>&1)
contains "JS 非 deny 包放行" "ALLOWED" "$out"

rm -rf "$SP" "$NM"
end
