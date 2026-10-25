# Linux 迁移指南

> 目标：让 VPO-Hook 从 macOS 扩展到标准 Linux（Ubuntu/Debian）及其他发行版（Arch 等）。

---

## 一、迁移目标总览

| 项 | macOS（已完成） | Linux（本指南目标） |
|---|---|---|
| 注入机制 | `DYLD_INSERT_LIBRARIES` | `LD_PRELOAD` |
| 拦截方式 | `DYLD_INTERPOSE` 段 | **同名符号**（直接定义 `open()` 覆盖 libc） |
| 获取真实函数 | `dlsym` 被 interpose 劫持，绕道 `__open`/`$NOCANCEL` | **`dlsym(RTLD_NEXT, "open")` 直接可用** |
| 可拦函数 | 19 个（12 个受限） | **35 个 wrapper**（31 个基础函数 + `open64`/`openat64`/`fopen`/`fopen64` 4 个 LFS 别名） |

**核心结论**：Linux 的机制比 macOS 简单得多——不需要 `__` 私有符号、`$NOCANCEL` 变体、`MACOS_SKIP` 这一整套 hack。

---

## 二、已完成的迁移（已在真实 Linux 实测通过）

| 文件 | 改动 |
|---|---|
| `py/obj_hook/gen_wrappers.py` | `--platform linux` 分支；支持 `linux_aliases` 生成 LFS 别名 wrapper |
| `js/obj_hook/gen_wrappers.js` | 同上，且与 Python 版输出**逐字节一致**（已用 `diff` 验证） |
| `signatures.json` | `open`/`openat` 声明 `open64`/`openat64` 别名；新增 Linux 专用 `fopen`（含 `fopen64`）；新增 `posix_spawn`/`posix_spawnp`；`execve` 用 `env_mode: replace`，`execv`/`execvp`/`system`/`popen` 用 `env_mode: reinject`；`vfork` 改为 `use_fork` |
| `py/vpo_hook.py` / `js/vpo_hook.js` | Linux 编译命令补 `-ldl`；shim 检测改为「只跳过 shims 目录 + shebang 脚本」；设置 `VPO_PYTHONPATH` / `VPO_NODE_OPTIONS` |
| `policy.c` / `vpo_hook.h` | 新增 constructor 缓存 + `vpo_envp_merge`/`vpo_reinject_environ`，用于子进程环境继承 |

**为什么必须补 LFS 别名**：glibc 在 64 位大文件支持下，Python 的 `open()` 实际调用
`open64`，Node 的 `libuv` 也直接绑定 `open64`。只 hook `open` 会导致 Python/Node
的文件读取完全绕过蜜罐（`LD_DEBUG=bindings` 可复现）。补完 `open64`/`openat64`/
`fopen`/`fopen64` 后，`open`、`os.open`、`fopen64`、Node `fs.readFileSync` 均能被改写。

**验证状态**：Linux x86_64 + gcc 13 + Python 3.12 + Node 18 实测通过；
Python/Node/C 的敏感文件读取均返回蜜罐，非敏感文件放行，网络/写标记/pickle RCE 拦截均正常。

**子进程环境继承（P0-B）**：
- `policy.c` 在 constructor 里缓存 `VPO_*`、`LD_PRELOAD`、`VPO_PYTHONPATH`、`VPO_NODE_OPTIONS`，后续只读缓存，guest 先 `unsetenv()` 再 exec 也不会丢策略。
- `execve` / `posix_spawn` / `posix_spawnp` 用 `vpo_envp_merge()` 构造新 envp；`execv` / `execvp` / `system` / `popen` 用 `vpo_reinject_environ()` 写回 environ。
- `vfork` 改为 `fork`：vfork 子进程里调用 `malloc` 是未定义行为，会导致 `*** stack smashing detected ***`；替换为 `fork` 后再注入环境是安全的。
- 已实测：`os.execve(..., {})`、`Popen(env={})`、`os.posix_spawn`、`env -i`、`sh -c`、`environ.clear()` 后的 `execv`/`execvp` 都仍读蜜罐；显式传入的 `PYTHONPATH`/`NODE_OPTIONS`/`LD_PRELOAD` 会与 VPO 值合并。

---

## 三、Linux 实测步骤（已跑通，可复现）

### 1. 拷贝文件

把整个项目（或至少 `py/`、`js/`）用 U 盘拷到 Linux 虚拟机。**只需源码，不需要 macOS 的编译产物**（`wrapper.c`、`*.dylib` 都不需要，Linux 上会重新生成）。

### 2. 确认环境

```bash
gcc --version      # 或 clang
python3 --version  # Python 侧需要
node --version     # Node 侧需要（可选）
```

Ubuntu/Debian 若缺 gcc：`sudo apt install build-essential`。Arch 一般自带。

### 3. 编译 + 初始化

```bash
cd vpoh
python3 py/vpo_hook.py init        # 会生成 Linux 版 wrapper.c + 编译 libvpo_hook.so
```

预期看到 `gen_wrappers: 已生成 35 个 wrapper (Linux) -> ...`（35 = 31 基础 + 4 个 LFS 别名，
macOS 仍是 19 个）。

### 4. 跑通拦截（对照 macOS 那套测试）

```bash
# 路径蜜罐：Python builtins.open -> open64
python3 py/vpo_hook.py run python3 -c "print(open('/etc/passwd').read()[:40])"
# 路径蜜罐：Python os.open -> open64
python3 py/vpo_hook.py run python3 -c "import os; fd=os.open('/etc/passwd',os.O_RDONLY); print(os.read(fd,40))"
# 路径蜜罐：Node fs.readFileSync -> libuv -> open64
python3 py/vpo_hook.py run node -e "console.log(require('fs').readFileSync('/etc/passwd','utf8').slice(0,40))"
# 路径蜜罐：C stdio fopen64
python3 py/vpo_hook.py run cat /etc/passwd
# 名文 hook
python3 py/vpo_hook.py run python3 -c "import os; os.system('echo hi')"
# Node 名文 hook
python3 py/vpo_hook.py run node -e "require('child_process').execSync('echo hi')"
```

正常结果：前 4 条都读到 `HONEYPOT` 假数据；后 2 条抛 `CapabilityDenied`。

**子进程逃逸回归**（都应返回 `HONEYPOT`）：

```bash
# execve 显式空环境
python3 py/vpo_hook.py run python3 -c "import os; os.execve('/usr/bin/python3', ['python3','-c','print(open(\"/etc/passwd\").read()[:20])'], {})"
# Popen 空环境（走 posix_spawn）
python3 py/vpo_hook.py run python3 -c "import subprocess; subprocess.Popen(['python3','-c','print(open(\"/etc/passwd\").read()[:20])'], env={}).wait()"
# posix_spawn 空环境
python3 py/vpo_hook.py run python3 -c "import os; pid=os.posix_spawn('/usr/bin/python3', ['python3','-c','print(open(\"/etc/passwd\").read()[:20])'], {}); os.waitpid(pid,0)"
# environ.clear() 后 execv/execvp
python3 py/vpo_hook.py run python3 -c "import os; os.environ.clear(); os.execv('/usr/bin/env', ['env'])"
# shell + env -i
python3 py/vpo_hook.py run sh -c "env -i /usr/bin/python3 -c 'print(open(\"/etc/passwd\").read()[:20])'"
```

---

## 四、注意事项

1. **`_GNU_SOURCE`**：Linux 生成器已自动加（`RTLD_NEXT` 需要），无需手动。
2. **glibc vs musl**：Ubuntu/Debian/Arch 都是 glibc，没问题；Alpine 用 musl，`dlsym(RTLD_NEXT)` 行为略有差异，先不在目标内。
3. **编译器**：`gcc` 或 `clang` 均可，启动器会自动探测；Linux 链接已加 `-ldl`（兼容 glibc < 2.34）。
4. **静态链接的目标程序**：`LD_PRELOAD` 对静态链接的程序无效（和 macOS 一样的边界）。
5. **`config.yaml` 里的路径**：默认模板已移除 macOS 绝对路径（`~/Desktop/vpoh/...`）。如需保护示例数据，请把其**绝对路径**同时加入 `deny_paths` 与 `honeypot_map`。
6. **LFS 别名**：后续新增文件类函数时，记得在 `signatures.json` 里用 `linux_aliases` 补上 `xxx64` 别名，否则 Python/Node 会走 64 位符号绕过。
7. **验收脚本**：`./scripts/verify_linux.sh`，完整日志写到 `logs/verify-linux-<时间>.log`；失败用例会继续跑完并汇总退出码。
8. **静默模式**：`vpo-hook run -q ...` 只保留目标程序输出；`-v` 显示诊断。所有 `run` 诊断走 stderr。
9. **审计默认值**：`audit.enabled: false` 现在会正确关闭，不会再因为注释里的 `true` 误开；审计日志写入改为 `os.write`/`fs.writeSync` 单次写。

---

## 五、遇到问题记录

如果 Linux 上编译或运行报错，请把：
1. `init` 的完整输出；
2. 报错信息；
3. `gcc --version`、`uname -a`；

贴回来，我据此修。Linux 版的 wrapper 逻辑（同名符号 + RTLD_NEXT）是标准做法，理论上不该有大问题，但「没实测」和「实测通过」之间，通常隔着几个 glibc/编译器的小坑。
