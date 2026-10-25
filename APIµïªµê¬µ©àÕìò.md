# VPO-Hook API 拦截清单（macOS）

> 本文件说明：`signatures.json` 里收录的 31 个 libc 出口函数，哪些在 macOS 上能安全拦截、哪些不能，以及每个函数是干什么的、为什么要监控它。
>
> 2026-10-25 更新：新增 `posix_spawn`/`posix_spawnp`，macOS 生成器已通过，运行时待 macOS 机器实测；总数从 29 变为 31。

---

## 一、总览

| 状态 | 数量 | 说明 |
|---|---|---|
| ✅ 可拦截 | 19 | 17 个已验证；`posix_spawn`/`posix_spawnp` 已生成 wrapper，待 macOS 实测 |
| ❌ 不可拦截 | 12 | macOS 平台限制（原因见第三部分） |

**核心结论**：你关心的核心出口（读文件 `open`、写数据 `write`、网络 `connect/sendto`、执行进程 `execve/fork`）全部在 19 个可拦截里。缺失的 12 个多数能被已拦截的函数间接兜底，实际安全影响比"少了 12 个"听起来小得多。

---

## 二、能拦截的 19 个 API

### 文件 IO 类（读/写/删/改名）

**1. `open` — 打开文件**
```c
int open(const char *pathname, int flags, ...)
```
最核心的入口。程序想读任何文件（`/etc/passwd`、`~/.ssh/id_rsa`、`~/.aws/credentials`）都必须先 `open`。
**监控意义**：拦截敏感路径访问（deny_paths 黑名单）。

**2. `openat` — 打开文件（相对目录版本）**
```c
int openat(int dirfd, const char *pathname, int flags, ...)
```
`open` 的变体，第一个参数是目录句柄，路径相对该目录。现代代码（尤其 Node/Python 运行时）常用它代替 `open`。
**监控意义**：如果只拦 `open` 不拦 `openat`，恶意代码用 `openat` 就能绕过。必须一起拦。

**3. `read` — 读文件内容**
```c
ssize_t read(int fd, void *buf, size_t count)
```
从文件描述符读数据。
**监控意义**：数据入口。配合 open 做"读敏感文件"的完整拦截。

**4. `write` — 写数据**
```c
ssize_t write(int fd, const void *buf, size_t count)
```
往文件/管道/socket 写数据。
**监控意义**：数据出口。这里是 Target.md 说的"数据标记检查"关键点——检查 `buf` 里是否含高危数据（token/secret/password 等标记），防止敏感数据外泄。

**5. `unlink` — 删除文件**
```c
int unlink(const char *pathname)
```
删除一个文件。
**监控意义**：防止恶意代码删掉用户的重要文件。

**6. `unlinkat` — 删除文件（相对目录版本）**
```c
int unlinkat(int dirfd, const char *pathname, int flags)
```
`unlink` 的变体。同上，必须一起拦防止绕过。

**7. `rename` — 重命名 / 移动文件**
```c
int rename(const char *oldpath, const char *newpath)
```
改名或移动文件。
**监控意义**：防止恶意代码把文件挪走（比如把你写的文件改名成它的）。

**8. `renameat` — 重命名（相对目录版本）**
```c
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
```
`rename` 的变体。同上。

**9. `rmdir` — 删除目录**
```c
int rmdir(const char *pathname)
```
删除一个空目录。
**监控意义**：防止恶意代码删目录。

---

### 网络类（连接 / 收发数据）

**10. `connect` — 建立网络连接**
```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
```
主动连到某个 IP/端口。这是网络数据外泄的第一道门。
**监控意义**：拦下"连到白名单之外的地址"（allow_network 白名单）。恶意代码想把数据传回它的服务器，必须 `connect`。

**11. `bind` — 绑定端口**
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
```
在本地绑定一个端口（比如开个后门监听）。
**监控意义**：防止恶意代码偷偷开监听端口。

**12. `sendto` — 发送数据到指定地址**
```c
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
```
往指定地址发数据。
**监控意义**：双重点——① 检查目标地址是否在白名单；② 检查 `buf` 数据是否含高危标记。这是数据外泄的核心出口。

**13. `recvfrom` — 从指定地址接收数据**
```c
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
```
从网络接收数据。
**监控意义**：数据入口，检查来源地址。

---

### 进程类（创建子进程 / 执行程序）

**14. `fork` — 创建子进程**
```c
pid_t fork(void)
```
复制当前进程，产生一个一模一样的子进程。
**监控意义**：防止 fork 炸弹（疯狂 fork 耗尽系统资源）、防止恶意代码偷偷起后台进程。

**15. `vfork` — 创建子进程（共享内存变体）**
```c
pid_t vfork(void)
```
`fork` 的变体，子进程和父进程共享内存（更省资源，通常紧跟着 exec）。用途同上。

**16. `execve` — 执行一个程序（替换当前进程）**
```c
int execve(const char *pathname, char *const argv[], char *const envp[])
```
这是"执行命令"的最终底层——所有 `execv`/`execvp`/`execl` 等最后都走到这里。也是 `system`/`popen` 内部会走的。
**监控意义**：拦截"执行了不该执行的程序"（比如恶意代码去执行 `rm -rf`、下载器、挖矿程序）。

**17. `kill` — 发送信号**
```c
int kill(pid_t pid, int sig)
```
给进程发信号（比如 SIGKILL 杀死进程）。
**监控意义**：防止恶意代码杀掉你的进程，或干扰系统。

---

## 三、拦截不了的 12 个 API（macOS）

分两组，原因不同：

### 第一组：硬限制（3 个）——拦截会导致进程启动就崩

这 3 个函数是 macOS 的动态链接器（dyld）**在加载动态库的过程中自己就会调用**的。一旦拦截它们，进程刚启动、还没来得及运行你的代码，就在"加载库"这一步崩溃。

**1. `close` — 关闭文件描述符**
```c
int close(int fd)
```
关闭一个已打开的文件/socket。
**为什么拦不了**：dyld 加载 dylib 时用它关闭文件。拦截价值本来也极低（只关一个数字 fd，不涉及路径/网络/数据），所以放弃它损失几乎为零。

**2. `mmap` — 内存映射**
```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
```
把文件映射到内存（也用于动态申请内存、JIT 执行代码）。
**为什么拦不了**：dyld 加载 dylib 就是靠 mmap 把文件映射进内存的。

**3. `mprotect` — 修改内存权限**
```c
int mprotect(void *addr, size_t len, int prot)
```
改变一段内存的可读/可写/可执行权限。
**为什么拦不了**：dyld 加载时用它设置代码段的权限。拦截价值在于"防恶意代码改内存执行 shellcode"，但 macOS 硬限制只能放弃。

---

### 第二组：没有"安全符号"（9 个）——技术上还没找到绕过 interpose 的办法

前面说过，macOS 上拦截某函数后，`dlsym` 查同名函数会拿到"我替换后的版本"导致递归，必须绕道用 `__` 私有符号或 `$NOCANCEL` 别名。这 9 个函数**两种符号都没有**，所以暂时拿不到真实实现，只能先跳过。

**4. `mkdir` — 创建目录**
```c
int mkdir(const char *pathname, mode_t mode)
```
创建目录。
**监控意义**：防止恶意代码乱建目录。缺失影响：小（建目录本身危害低，且后续可用 syscall 补）。

**5. `socket` — 创建 socket**
```c
int socket(int domain, int type, int protocol)
```
创建一个网络 socket（通信端点）。
**监控意义**：socket 本身只是"创建个通信对象"，不敏感——真正敏感的是 `connect`/`sendto` 到哪（这两个已拦截）。**缺失影响：几乎为零**，因为创建 socket 不算外泄，外泄发生在 connect/sendto。

**6. `send` — 发送数据（不指定地址）**
```c
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
```
在已连接的 socket 上发数据（`sendto` 的简化版，不写地址）。
**监控意义**：数据出口（buffer 检查）。缺失影响：中等，但它是 `sendto` 的近亲，逻辑上大概率能通过拦 `sendto` 或后续补 syscall 覆盖。

**7. `recv` — 接收数据（不指定地址）**
```c
ssize_t recv(int sockfd, void *buf, size_t len, int flags)
```
在已连接的 socket 上收数据（`recvfrom` 的简化版）。
**监控意义**：数据入口。缺失影响：小。

**8. `execv` — 执行程序（execve 的封装）**
```c
int execv(const char *pathname, char *const argv[])
```
`execve` 的简化版（自动用当前环境变量）。
**监控意义**：执行程序。**但它的底层就是 `execve`（已拦截）**，所以理论上能通过拦 `execve` 兜底。

**9. `execvp` — 执行程序（自动搜 PATH）**
```c
int execvp(const char *file, char *const argv[])
```
`execve` 的变体（自动在 PATH 里找程序）。
**监控意义**：同上，底层走 `execve`（已拦截），大概率被兜底。

**10. `system` — 执行 shell 命令**
```c
int system(const char *command)
```
执行一条 shell 命令（内部是 fork + `/bin/sh -c` + execve）。
**监控意义**：执行恶意命令。**它的底层是 `fork` + `execve`（都已拦截）**，所以会被兜底。

**11. `popen` — 执行命令并打开管道**
```c
FILE *popen(const char *command, const char *type)
```
执行命令并拿到它的输入/输出管道。
**监控意义**：同上。底层 `fork` + `execve` 已拦截，会被兜底。

**12. `dlopen` — 动态加载库**
```c
void *dlopen(const char *filename, int flags)
```
运行时加载一个 .so/.dylib。
**监控意义**：Target.md 里标注的"防绕过"关键点——恶意代码可以用 `dlopen` 动态加载绕过检查。缺失影响：这是 12 个里相对最可惜的一个，后续需要找 dyld 内部 API 来补。

---

## 四、缺失的 12 个，实际影响汇总

| 缺失函数 | 实际影响 | 兜底情况 |
|---|---|---|
| close | 几乎为零 | 拦截价值本来极低 |
| mmap / mprotect | 小 | dyld 硬限制，只能放弃 |
| mkdir | 小 | 后续可用 syscall 补 |
| socket | 几乎为零 | 创建 socket 不敏感，外泄在 connect/sendto（已拦） |
| send / recv | 小 | sendto/recvfrom 近亲，后续补 |
| execv / execvp | 小 | 底层 execve（已拦），会被兜底 |
| system / popen | 小 | 底层 fork+execve（已拦），会被兜底 |
| dlopen | 中等 | 防绕过点，后续找 dyld API 补 |

**一句话**：真正"硬伤"的只有 dlopen 一个（防绕过点暂时补不上），其余要么拦截价值低、要么能被已拦截的函数间接兜住。

---

## 五、附：符号机制速查（为什么会分成"能拦/不能拦"）

- **`DYLD_INTERPOSE`**：macOS 的"函数替换"机制，拦截 `open` 就是靠它。
- **`__` 私有符号**：macOS 给很多函数额外导出一个带 `__` 前缀的名字（`open` ↔ `__open`），指向同一个实现，但 `__open` 不会被拦截劫持 → 用它拿真实实现。
- **`$NOCANCEL` 变体**：read/write/close 额外导出的别名符号（`read$NOCANCEL`），同样不被劫持 → read/write 靠它。
- **"interpose 劫持 dlsym"**：一旦拦了 `open`，连 `dlsym("open")` 都返回"替换后的函数"导致递归，所以必须绕道用上面两种别名符号。
- **"dyld 加载期"**：进程启动时加载库的阶段，close/mmap/mprotect 在这一步被系统调用，所以拦了就崩。

**能拦的 19 个** = 15 个有 `__` 私有符号（open/openat/unlink/unlinkat/rename/renameat/rmdir/connect/bind/sendto/recvfrom/fork/vfork/execve/kill）+ 2 个有 `$NOCANCEL`（read/write）+ 2 个通过 `dlsym` 生成（posix_spawn/posix_spawnp，待 macOS 实测）。
**不能拦的 12 个** = 3 个 dyld 加载期必需（close/mmap/mprotect）+ 9 个既无 `__` 也无 `$NOCANCEL`（mkdir/socket/send/recv/execv/execvp/system/popen/dlopen）。
