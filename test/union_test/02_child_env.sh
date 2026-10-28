#!/usr/bin/env bash
# 02 子进程环境继承：execve/posix_spawn/Popen/env -i/execv/execvp 都继承钩子，读文件仍蜜罐
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ensure_built

begin "02 子进程环境继承（逃逸拦截）"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; os.execve("/usr/bin/python3", ["python3","-c","print(open(\"/etc/passwd\").read()[:20])"], {})' 2>&1)
contains "execve 空环境" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import subprocess; subprocess.Popen(["python3","-c","print(open(\"/etc/passwd\").read()[:20])"], env={}).wait()' 2>&1)
contains "Popen 空环境 (posix_spawn)" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; pid=os.posix_spawn("/usr/bin/python3", ["python3","-c","print(open(\"/etc/passwd\").read()[:20])"], {}); os.waitpid(pid,0)' 2>&1)
contains "posix_spawn 空环境" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q sh -c 'env -i /usr/bin/python3 -c "print(open(\"/etc/passwd\").read()[:20])"' 2>&1)
contains "env -i" "HONEYPOT" "$out"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; os.environ.clear(); os.execv("/usr/bin/env", ["env"])' 2>&1)
contains "execv 清环境后恢复" "VPO_HOOK_CONFIG=" "$out"

out=$(python3 py/vpo_hook.py run -q python3 -c 'import os; os.environ.clear(); os.execvp("env", ["env"])' 2>&1)
contains "execvp 清环境后恢复" "LD_PRELOAD=" "$out"

python3 py/vpo_hook.py run -q sh -c /usr/bin/true >/dev/null 2>&1
[ $? -eq 0 ] && ok "sh -c true 无 stack smashing" || bad "sh -c true 失败"

end
