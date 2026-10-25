# VPO Hook 工程实施文档

## 一、项目定位

参考手机权限模型，在桌面 Node.js / Python 运行时上提供**接口级 + 出口级**的纵深防御，让用户能够安全地运行未经验证的 npm / pip 包。

- **名文 hook**（已实现）：JS/Python 层的接口级策略，拦截业务 API 调用。
- **二进制 hook**：libc 出口函数拦截，不可被原生模块绕过。
- **分层商业模式**：简单权限组免费（IO / Web / 进程核心出口），复杂权限组商业化。

---

## 二、流水线总体思路

```
┌─────────────────────────────────────────────────────────┐
│ 发布侧（你维护，一次性/按版本）                          │
│                                                          │
│  签名模板表（JSON/YAML，几十个 POSIX 函数）              │
│        ↓                                                 │
│  生成脚本 gen_wrappers.py → wrapper.c                    │
│        ↓                                                 │
│  在旧版 glibc 容器内编译 → 多平台预编译产物              │
│        ↓                                                 │
│  打包进 npm / pip 包                                     │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 用户侧（pip install / npm install 之后）                 │
│                                                          │
│  vpo-hook init   → 生成默认配置 + 平台自检               │
│  编辑配置        → 选择权限组、路径白名单、高危标记       │
│  vpo-hook run python3 app.py                             │
│  vpo-hook run node app.js                                │
│        ↓                                                 │
│  启动器设置 DYLD_INSERT_LIBRARIES / LD_PRELOAD           │
│  设置 VPO_HOOK_CONFIG 指向配置文件                       │
│  exec 目标进程                                           │
│        ↓                                                 │
│  进程启动 → hook 库 constructor 读配置 → 激活拦截        │
│  名文 hook 在 JS/Python 层初始化 → 接口级策略            │
└─────────────────────────────────────────────────────────┘
```

**核心原则：本机编译优先，预编译库兜底（2026-10-25 更新）。** 用户 `init` 默认用本机 C 编译器编译已生成的 wrapper，避免预编译库和本机 libc 版本不匹配；没有编译器或编译失败时，才使用随包分发的预编译产物。`gen_wrappers.py` 仍是发布侧工具，不是用户侧工具。

---

## 三、数据资产：签名模板表

**这是唯一需要新建的核心数据资产。** 格式建议 JSON，结构如下：

```json
{
  "open": {
    "signature": "int open(const char *pathname, int flags, ...)",
    "category": "io",
    "args": [
      {"name": "pathname", "type": "const char *", "check": "path"},
      {"name": "flags", "type": "int", "check": "flags"}
    ],
    "variadic_mode": "O_CREAT"
  },
  "connect": {
    "signature": "int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)",
    "category": "network",
    "args": [
      {"name": "sockfd", "type": "int"},
      {"name": "addr", "type": "const struct sockaddr *", "check": "sockaddr"},
      {"name": "addrlen", "type": "socklen_t"}
    ]
  },
  "execve": {
    "signature": "int execve(const char *pathname, char *const argv[], char *const envp[])",
    "category": "process",
    "args": [
      {"name": "pathname", "type": "const char *", "check": "path"},
      {"name": "argv", "type": "char *const []"},
      {"name": "envp", "type": "char *const []"}
    ]
  }
}
```

**范围**：按类别划分，每类核心函数如下（初版约 30 个）：

- **IO**：`open`、`openat`、`close`、`read`、`write`、`unlink`、`unlinkat`、`rename`、`renameat`、`mkdir`、`rmdir`
- **网络**：`socket`、`connect`、`bind`、`sendto`、`recvfrom`、`send`、`recv`
- **进程**：`fork`、`vfork`、`execve`、`execv`、`execvp`、`posix_spawn`、`posix_spawnp`、`system`、`popen`、`kill`
- **映射**：`mmap`、`mprotect`、`dlopen`（防绕过）

**签名来源**：man page。AI 可以辅助批量整理，但最终需要人工校验一遍，因为变参函数（`open`、`fcntl`、`ioctl`）和结构体参数（`sockaddr`）的处理需要特殊模板。

---

## 四、发布侧流水线

### 4.1 生成 wrapper 源码

`gen_wrappers.py` 读取签名模板表，生成 `wrapper.c`。生成逻辑：

1. 遍历模板表中每个函数。
2. 按函数签名生成同名 wrapper 函数（`const char *` 参数直接转发，结构体指针先做策略检查）。
3. wrapper 函数体：调用策略引擎检查 → 决定放行 / 拒绝 / 改写参数 → 调真实函数。
4. 生成 `DYLD_INTERPOSE`（macOS）或 `__attribute__((visibility("default")))` + 同名符号（Linux）的配对声明。
5. 生成 `thread_local` 重入标志的保护逻辑。
6. 生成 `dlsym(RTLD_NEXT / RTLD_DEFAULT)` 获取真实函数的初始化代码。
7. 生成 `dlsym` 自身的 wrapper（强制包裹，防绕过）。

### 4.2 编译

**Linux**：预编译产物在旧版 glibc 容器内编译（如 Ubuntu 18.04 或 Debian 10 基础镜像），确保能向后兼容较老发行版；本机编译则是默认路径，用户机器上的 gcc/clang 直接编译。目标：`libvpo_hook.so`。

**macOS**：在 macOS 构建机上编译预编译产物，`libvpo_hook.dylib`，分别产出 arm64 和 x86_64 版本（或用 universal binary）；用户本机编译同样是默认路径。

**策略**：`init` 优先本机编译；没有编译器或编译失败时才 fallback 到预编译库。发布侧预编译库的生成细节见 `addition.md` 6.2。

**Windows**：不提供，启动器检测到 Windows 直接报错退出。

### 4.3 打包

npm 包和 pip 包各包含：

- 预编译 hook 库（按平台分目录）
- 签名模板表（供调试和审计用）
- 启动器（Node 脚本 / Python 脚本）
- 默认配置模板
- 名文 hook 的 JS/Python 模块

---

## 五、用户侧安装与启动流程

### 5.1 安装

```bash
pip install vpo-hook
# 或
npm install -g vpo-hook
```

### 5.2 初始化

```bash
vpo-hook init
```

行为：

1. 检测平台（macOS / Linux / 其他）。其他平台报错退出。
2. 在 `~/.vpo-hook/` 下生成 `config.yaml`（默认简单权限组）。
3. 自检：优先用本机 C 编译器编译并加载 hook 库，验证构造函数可执行、符号可解析；本机编译失败或无编译器时 fallback 到预编译 hook 库。失败则报告具体原因（架构不匹配、SIP 限制等）。

### 5.3 配置

```yaml
# ~/.vpo-hook/config.yaml
profile: simple          # simple | custom

intercept:
  io: true
  network: true
  process: true
  mapping: true

policy:
  deny_paths:
    - "/etc/passwd"
    - "~/.ssh"
    - "~/.aws"
  allow_network:
    - "api.example.com:443"
  high_risk_markers:
    - "token"
    - "secret"
    - "password"
  rewrite_on_deny: true    # 拒绝时是否改写参数（如 open 改 /dev/null）

marks:
  js: true                 # 启用名文 hook（JS 层）
  python: true             # 启用名文 hook（Python 层）
```

### 5.4 启动

```bash
vpo-hook run python3 app.py
vpo-hook run node app.js
vpo-hook run python3 -m my_module
```

启动器内部逻辑：

1. 读配置，确认 `profile` 和 `intercept` 组。
2. 定位当前平台的预编译 hook 库路径。
3. 设置环境变量：
   - macOS：`DYLD_INSERT_LIBRARIES=<path>`
   - Linux：`LD_PRELOAD=<path>`
   - 两者：`VPO_HOOK_CONFIG=~/.vpo-hook/config.yaml`
4. `exec` 目标命令（`os.execvp` / `child_process.spawn` + `exec`）。

### 5.5 名文 hook 的接入

启动器在 `exec` 之前，根据目标运行时（`python3` 还是 `node`）注入对应的名文 hook 初始化脚本：

- **Python**：设置 `PYTHONSTARTUP` 或通过 `sitecustomize` 机制加载名文 hook 模块。
- **Node**：设置 `NODE_OPTIONS="--require /path/to/vpo-hook/名文入口.js"`。

名文 hook 从同一个 `config.yaml` 读取策略，和二进制 hook 共享配置。

---

## 六、运行时架构

```
目标进程（python3 app.py / node app.js）
│
├── 名文 hook（JS/Python 层）
│   ├── 拦截业务 API（fs.readFile、subprocess.run 等）
│   ├── 参数审核、接口白名单
│   └── 可被原生模块绕过 → 由二进制 hook 兜底
│
└── 二进制 hook（libc 层，预编译库）
    ├── 出口函数拦截（open/write/connect/execve...）
    ├── 策略引擎（读 config.yaml）
    ├── 数据标记检查（write/sendto 的 buffer 参数）
    ├── 参数改写（deny 时改写路径/地址）
    ├── 递归保护（thread_local 重入标志）
    └── dlsym 强制包裹（防绕过）
```

**两层分工**：

- 名文 hook：业务语义级策略，粒度细，但可绕过。
- 二进制 hook：出口级策略，粒度粗，但不可绕过。

---

## 七、要达到的效果

### 7.1 用户视角

```bash
$ pip install vpo-hook
$ vpo-hook init
[OK] 平台检测: macOS arm64
[OK] 配置已生成: ~/.vpo-hook/config.yaml
[OK] 自检通过

$ vim ~/.vpo-hook/config.yaml   # 编辑策略

$ vpo-hook run python3 untrusted_package_test.py
[VPO] 已加载 hook 库
[VPO] 策略: simple (io, network, process)
[VPO] 名文 hook: python 已启用
[VPO] 拦截: open("/etc/passwd") → 拒绝
[VPO] 拦截: connect(1.2.3.4:443) → 拒绝（不在白名单）
[VPO] 运行完成，退出码 0
```

### 7.2 安全效果

- 未经验证的 `.node` / `.so` 内部调用 `open("/etc/passwd")` → 被拦截。
- 未经验证的包尝试 `connect` 到未知地址 → 被拦截。
- 通过 `dlsym(RTLD_NEXT)` 绕过 → 被 `dlsym` wrapper 拦截。
- 通过 `process.binding`（Node）或 `ctypes`（Python）绕过名文 hook → 在出口函数处被二进制 hook 兜底。
- 包通过 `fork` + `execve` / `posix_spawn` 启动子进程 → 启动器缓存会重新注入 VPO 环境，子进程继续被拦截。
- 包内部自定义函数互相传递高危数据 → 只要最终要出进程，必经过出口函数，被数据标记检查拦截。

### 7.3 性能效果

- 未触发拦截的调用：wrapper 函数做一次策略查表（O(1)），然后跳转真实函数，开销在**微秒级以下**。
- 策略引擎采用内存缓存，配置在进程启动时加载一次，运行时不做文件 IO。
- 不拦截的函数（不在白名单里）零开销。

### 7.4 包大小

- 预编译 hook 库：< 1MB
- 签名模板表：< 100KB
- 启动器 + 名文 hook：< 5MB
- **总计 < 10MB**，远低于 500MB 上限。

---

## 八、工程实施顺序（给 OpenCode 的工作清单）

### Phase 1：数据资产

1. 编写签名模板表 `signatures.json`，覆盖 IO / 网络 / 进程 / 映射四类共约 30 个函数。
2. 每个函数标注：签名、类别、参数类型、检查类型、变参处理方式。

### Phase 2：wrapper 生成器

3. 编写 `gen_wrappers.py`：读 `signatures.json` → 生成 `wrapper.c`。
4. 生成内容包括：wrapper 函数、interpose 配对声明、`dlsym` 真实函数获取、递归保护、`dlsym` 自身 wrapper。
5. 用生成的 `wrapper.c` 在 macOS 上编译，跑通 Node 和 Python 两个最小测试（复用已有的 `testmod` 和 `testaddon`）。

### Phase 3：策略引擎

6. 定义策略引擎 ABI：`int vpo_check(const char *func, void *args, vpo_action *action)`。
7. 实现配置加载（YAML 解析）和内存缓存。
8. 实现路径检查、网络地址检查、数据标记检查。
9. 实现参数改写逻辑（deny 时改写路径/地址）。

### Phase 4：启动器

10. 编写 `vpo-hook` 命令行入口（Python 版和 Node 版）。
11. 实现 `init`：平台检测、配置生成、自检。
12. 实现 `run`：环境变量设置、名文 hook 注入、exec 目标进程。

### Phase 5：名文 hook 接入

13. 将已有的名文 hook 逻辑接入启动器，从同一份配置读策略。
14. Python 侧通过 `sitecustomize` 或 `PYTHONSTARTUP` 加载。
15. Node 侧通过 `NODE_OPTIONS=--require` 加载。

### Phase 6：打包与分发

16. 编写 npm 包的 `package.json` 和 pip 包的 `pyproject.toml`。
17. 按平台组织预编译库目录（`darwin-arm64/`、`linux-x64/` 等）。
18. 编写发布脚本：在旧版 glibc 容器内编译 Linux 产物，在 macOS 构建机编译 macOS 产物。
19. 打包、测试 `pip install` 和 `npm install -g` 全流程。

### Phase 7：验证

20. 用真实的第三方包（如 `numpy`、`cryptography`、某个未经验证的 npm 包）跑端到端测试。
21. 验证：正常功能不受影响、敏感操作被拦截、绕过尝试被兜底。
22. 测试 `dlsym` 绕过、直接 `syscall` 绕过（后者需 seccomp 兜底，属于后续 Phase）。

---

## 九、明确不做的事

- **不把用户侧编译作为唯一路径**：本机编译优先（避免 libc 版本不匹配），预编译库兜底；用户不装 C/Rust 工具链也能用。
- **不扫描每个包的符号表来驱动 wrapper 生成**：wrapper 按白名单全量生成，符号扫描仅用于调试。
- **不支持 Windows**：启动器检测到 Windows 直接报错退出。
- **当前阶段不做配置加密**：配置完整性优先用签名（Ed25519），本机密钥对不能防同 uid guest；加密留到后续用系统密钥对做文件授权时再考虑。详见 `addition.md` 6.8。
- **不做 seccomp 兜底（Phase 1）**：直接 `syscall()` 绕过留到后续 Phase，当前先靠 libc 层覆盖绝大多数场景。

---

## 十、商业模式分层

| 层级 | 内容 | 维护方式 |
|---|---|---|
| 免费（simple） | IO / Web / 进程核心出口拦截，名文 hook 基础策略 | 写死分类，无需 AI |
| 商业（custom） | 自定义策略、未知包行为分析、高危数据流定制 | AI 辅助 + 人工维护 |

AI 的使用范围：复杂策略生成、未知包符号表分析、自定义规则维护。简单权限组的分类和核心函数白名单**不依赖 AI**，由确定性的 POSIX 标准决定。