
---

# VPO-Hook 后续开发指导文档

## 一、项目定位（给 AI 的定调，先读这段）

VPO-Hook 是一个**桌面 Node.js / Python 运行时**的**接口级 + 出口级**纵深防御工具，目标用户是：跑**开源本地 AI Agent** 和**未经验证的 pip/npm 包**的普通用户、没时间审包的技术人、需要合规证据的公司。

核心机制已跑通：macOS 用 `DYLD_INTERPOSE` + 私有符号（`__open`、`$NOCANCEL`），Linux 用同名符号 + `dlsym(RTLD_NEXT)`，名文层用 Python `setattr` 代理 + Node `Proxy`。蜜罐改写、`CapabilityDenied` 已实测生效。

**一句话定调**：这是“提高偷数据成本和失败率”的工具，不是“保证偷不到”的沙箱。对机会主义供应链投毒和开源 Agent 的常规遥测有效，对静态编译、直接 `syscall`、主动反检测、子进程逃逸会漏。**所有开发决策都要围绕“让普通人装上就有保护、技术人能定制、公司能审计”展开，不要追求“防住一切”**。

---

## 二、能做什么 / 不做什么（明确边界，避免 AI 跑偏）

### 应该做（优先级从高到低）

1. **把 `simple` 安全组默认值做狠**。当前 `allow_network` 为空时 `policy.c` 默认放行所有网络，和“防外泄”定位矛盾。要改成：`network_mode: allowlist | denylist | off` 三态，`simple` 默认 `allowlist` + 空列表 = **拒绝所有出站**，用户显式加白名单才放行。`deny_paths` 默认列表要覆盖浏览器 cookie 目录、`~/.config` 下 token 存储、`~/.gitconfig`、`~/.npmrc`。
2. **子进程环境继承**。`execve`/`execv`/`execvp` 的 wrapper 要把 `DYLD_INSERT_LIBRARIES`/`LD_PRELOAD`/`PYTHONPATH`/`VPO_HOOK_PY_API`/`NODE_OPTIONS` 注入子进程 `envp`。这是当前最大的安全洞，Agent 一次 `fork`+`exec` 就逃逸。
3. **结构化审计日志 + `vpo-hook log` 命令**。JSON Lines 格式：`{"ts":..., "pid":..., "exe":..., "func":"open", "path":"~/.ssh/id_rsa", "decision":"REWRITE", "honeypot":"..."}`。日志是**所有人都有权用的基础能力**，不是企业版专属。`vpo-hook log` 打印最近记录，让用户“看见”拦截。
4. **`vpo-hook run --dry-run`**：只记录不拦截，输出“将会被拦截的调用列表”，技术人改配置前先干跑。
5. **`vpo-hook run --non-interactive`**：CI 用，遇 DENY 退出码非零。
6. **预置 profile 组合**：`strict`、`web-only`、`no-network`、`read-only`，每个是 YAML 片段，可 `include` 组合。技术人不用从零写 YAML。
7. **策略包导入导出 + 签名验证**。导入时 schema 校验、显示 diff、验证签名来源（官方/社区区分）。**防的是“导入别人的恶意策略把 deny 清空”**。
8. **弹窗从 `build` 挪到 `run` 首次运行，粒度是“能力组 + 目标类别”**，不是单次调用。二进制层不能同步弹窗（你 `vpo_hook.h` 的判断是对的），只能异步通知 + 本次拒绝 + 下次放行；要有超时默认拒绝。
9. **`nm -u` + AST 扫描做能力发现**，输出“能力清单 + 置信度”。native 模块用 `nm -u`，纯脚本用 `ast`/`acorn`。扫描失败默认“未知能力 = 高危”，不能默认安全。弹窗措辞用能力级（“这个包可以读文件”），不用目标级（“它要读你的 SSH 密钥”）。
10. **反检测脚手架（给框架不给成品）**：对抗点清单文档、符号随机化构建选项、`vpo-hook selfcheck` 命令。让用户 + AI 在这个框架里迭代，不要自己追着 Agent 厂商跑。
11. **AI 生成配置用填空模板约束输出**，不是自由写 YAML。AI 从候选列表（由 `signatures.json` 和预置安全组提供）里选，token 可控、输出可校验。

### 明确不做（避免 AI 浪费精力）

1. **本机编译优先，预编译库兜底**。用户明确要求优先用**用户本机 C 编译器**，避免预编译库和本机 libc 版本不匹配；当前 `init` 本机编译保留并作为默认路径。发布版仍应提供预编译库，作为没装编译器用户的 fallback（或首启下载产物）。`gen_wrappers` 仍是发布侧工具，用户侧只编译已生成的 wrapper。预编译库生成方案见 6.2。
2. **不支持 Windows**。启动器检测到 Windows 直接报错退出。
3. **当前阶段不做配置加密；配置完整性优先用签名**。用户后续希望用本机密钥对做解密/防篡改，但本机私钥对同 uid 的 guest 不构成边界，详见 6.8。先预留 `version`/`signature` 字段，YAML 解析重构独立推进。
4. **不做 `seccomp` 兜底（Phase 1）**。直接 `syscall()` 绕过留到后续 Phase。
5. **不用非对称加密加密 obj/文件数据本身**。非对称只用于**授权凭证签名**或**包装对称密钥**。数据加密走对称（AES）。对象审计只对**日志记录**做签名/加密，不加密运行时对象，详见 6.7。
6. **不做“attach 到运行中进程”**。`ptrace` 在 macOS 受 SIP 限制、Linux 需 `CAP_SYS_PTRACE`，普通人不配。启动器 `exec` 时注入是零权限要求的，优先这个。
7. **不把 taint tracking 定位成“跨进程/跨机器溯源”**。只能做“进程内数据流审计”，性能开销大，放企业版。
8. **不追求“防住定向攻击/主动反检测/静态编译二进制”**。这些是猫鼠游戏，交给用户 + AI 在脚手架里迭代。
9. **不要用 `README` 承诺“防得住”**。用“提高门槛”“审计+污染”“面向本地设计，生产自评”。

---

## 三、待修 bug 清单（按优先级，给 AI 逐个修）

### P0（本周修，影响功能/安全）

**A. 手写 YAML 解析器是最大技术债（保留 YAML，重构待定）**
- **问题**：`vpo_hook.py`/`cli.py` 有 `parse_deny_paths`、`parse_yaml_list`、`parse_honeypot_map`、`parse_audit`、`parse_plaintext_apis` 五个手写解析器，各写各的，假设 block style、缩进、分隔符。用户写 flow style、多行字符串、锚点引用全挂。
- **2026-10-25 决策**：**保留 YAML**，因为它要同时服务“简单安全组”和“复杂安全组”两套配置；不盲目换格式。后续仍应引入 `pyyaml`/`js-yaml`（或自写但更完整的解析）以支持 flow/anchors，但要和配置签名/审计链一起设计；G 随 A 解决。当前先保证默认配置和简单组可用，不阻塞发布工程。

**B. `execve` 子进程环境继承（安全洞）（Linux 已修复；macOS 基线已跑通，新增路径待回归）**
- **问题**：`execve`/`execv`/`execvp` 的 wrapper 只检查 `pathname`，没把 VPO 环境变量注入子进程 `envp`。已实测 `os.execve(..., {})` 和 `subprocess.Popen(..., env={})` 都能让子进程读到真实 `/etc/passwd`。
- **修法**：在 `signatures.json` 用 `env_mode` 标注：`execve`/`posix_spawn`/`posix_spawnp` 为 `replace`（构造新 envp），`execv`/`execvp`/`system`/`popen` 为 `reinject`（写回 environ）；两个生成器在通用 wrapper 里插入注入代码，并调用 `policy.c` 的 `vpo_envp_merge`/`vpo_reinject_environ`。
- **补充（2026-10-25）**：
  - 必须同时覆盖 `posix_spawn`/`posix_spawnp`，否则 Python `subprocess.Popen(env={})` 仍会绕过。
  - 注入值必须来自 constructor 时缓存的策略，不能在 `execve` 时读 `getenv`；guest 可以先 `unsetenv('VPO_DENY_PATHS')` 再 exec。
  - 生成代码要保证 Linux/macOS 都能编译运行：用 `__linux__`/`__APPLE__` 平台宏，Linux 注入 `LD_PRELOAD`，macOS 注入 `DYLD_INSERT_LIBRARIES`；`-ldl` 只在 Linux 加。
  - 处理 `envp == NULL`、分配失败（直接拒绝）、`LD_PRELOAD` 合并去重、`PYTHONPATH`/`NODE_OPTIONS` 注入 VPO 前缀而不是整体覆盖。
  - 详见 6.1。

**C. `resolve_executable` 的 shim 检测误伤 pyenv 真实二进制（已修复）**
- **问题**：`SHIM_MARKERS = ('/shims/', '/.pyenv/', ...)` 用 `in` 判断，会跳过 `~/.pyenv/versions/3.11/bin/python3`（真实二进制），不只跳过 `~/.pyenv/shims/python3`。
- **修法**：marker 改成精确前缀（`/.pyenv/shims/`、`/.nvm/versions/*/bin/`），或检测文件是否是 shell script（读前几字节 `#!/`），是 script 跳过，是 ELF/Mach-O 就用。

**D. `parse_audit` 的 `lang is None` 静默（已修复）**
- **问题**：`lang` 为 `None` 时 `s.startswith(f"{lang}:")` 变成 `startswith("None:")`，永远不匹配，`audit_classes` 空，静默不审计。
- **修法**：解析时 `lang is None` 不匹配任何语言；`cmd_run` 在 `audit enabled` 但目标不是 Python/Node 时打印警告，不再静默。

**E. `sitecustomize.py` 审计 hook 重入（已修复）**
- **问题**：`cls.__init__` 被重复包装时，`orig` 变成上一次 wrapper，调用链嵌套、日志重复。
- **修法**：包装前检查 `getattr(cls.__init__, "__vpo_audited__", False)`，打标记防重入；配置类去重。JS `installAudit` 同步加标记/去重，并用 `Reflect.construct(target, args, newTarget)` 保留 `newTarget`。

**F. `buildHook`（JS 版）不检查 `spawnSync` 退出码（已修复）**
- **问题**：`gen_wrappers.js` 或编译失败时，`buildHook` 继续往下走，`cmdInit` 打印“自检失败”但退出码 0，CI 误判成功。
- **修法**：检查 `spawnSync(...).status`，非零则 `process.exit(1)`。Python 版用 `check=True` 是对的，保持。

**G. `parse_honeypot_map` 的冒号分割**
- **问题**：`partition(":")` / `indexOf(':')` 找第一个冒号，路径含冒号会截错。
- **修法**：pyyaml 重构（A）一并解决。

**H. `normalizeType` 的 `[]` 替换不一致（已修复）**
- **问题**：`gen_wrappers.js` 的 `t.replace('[]', '*')` 只替换第一个（JS `String.replace(string, string)` 语义），Python 的 `str.replace` 替换全部。双 `[]` 类型时两版输出不一致，违反“两个生成器输出必须完全相同”的注释。
- **修法**：JS 用 `t.replaceAll('[]', '*')` 或 `t.split('[]').join('*')`。

**V. 审计 `enabled` 误判（新增，P0，已修复）**
- **问题**：`parse_audit` 用 `enabled = "true" in s.lower()` 检查整行，默认配置 `enabled: false  # ... 设为 true 才启用` 里的注释包含 `true`，导致 `enabled` 被误判为真，`audit.log` 持续写入。
- **复现**：`vpo_hook.parse_audit("audit:\n  enabled: false # true\n", "python")` 返回 `True`。
- **修法**：先去掉行内注释，再判断值：`value = s.split(":", 1)[1].split("#", 1)[0].strip().lower()`，只接受 `true/yes/on/1`。JS 版 `parseAudit` 的 `includes('true')` 一并修。

**W. 验收脚本与可静默日志（新增，P0/P1，已实现）**
- **问题**：`vpo-hook run` 的诊断信息走 stdout，`honeypot.py`/`honeypot.js` 也打印到 stdout，污染目标程序输出；目前没有自动化验收脚本，回归靠手敲。
- **修法**：`run` 诊断统一走 stderr；加 `-q/--quiet`、`-v/--verbose` 和 `VPO_HOOK_QUIET`/`VPO_HOOK_VERBOSE`；`honeypot` 支持静默；新增 `scripts/verify_linux.sh`（macOS 可复用）输出完整日志。详见 6.3。

### P1（下一阶段）

**I. `policy.c` 的 `rewrite_for` 隐式契约（已修复：rewrite_buf 随 vpo_action）**
- **问题**：`action->rewrite` 指向 `__thread buf`，调用方须在下一个 `vpo_check` 前用完。当前安全，但 wrapper 生成逻辑改动会破。
- **修法**：改成 `rewrite_for(path, out_buf, out_len)` 调用方传 buffer，消灭隐式契约。或至少在 `vpo_hook.h` 注释这个约定。

**J. `network_mode` 三态配置**（见“应该做”第 1 条）。
- 默认值不单独拍板：跟随**简单安全组**的最终设计。简单组应按“手机权限”思路给安全默认；复杂组再暴露 allowlist/denylist/off。

**K. `signatures.json` 加 `skip_on`/`noop` 标记（不做：简单组不开放任意 hook，无需 noop 优化）**
- **问题**：Linux 侧 `close`/`mmap` 等函数生成空 wrapper（`vpo_check` 直接放行），高频调用白白增加 `dlsym` + 空转开销。
- **修法**：`signatures.json` 加 `"skip_on": ["linux"]` 或 `"noop": true`，生成器据此跳过。

**L. 审计日志并发安全（已修复）**
- **问题**：`sitecustomize.py` 用 `open(..., "a")` + `f.write`，多线程下 `json.dumps` + `write` 非单次系统调用，可能交错。
- **修法**：Python 用 `os.open(..., O_APPEND)` + `os.write` 单次/循环写完再 `close`；JS 用 `fs.openSync` + `fs.writeSync` 一次写。已实现，日志权限 `0600`。

**M. `installLoader` 的 `isMain` 放行洞（按非安全边界处理，不视为需修）**
- **问题**：注释自认“guest could call `Module._load(..., true)`”。这是**功能上的绕过路径**。
- **修法**：不要当成安全边界，文档写清楚。或者用 `require.main === module` 的启发式收紧（不完美但提高门槛）。

**N. `installAudit` 的 `Reflect.construct(target, args)` 丢 `newTarget`**
- **问题**：`new.target` 在 constructor 里是 `target` 不是 proxy，但 `instanceof proxy` 仍为 true（proxy 的 prototype 是 target 的 prototype），行为正确。记录为“设计正确，无需修”。

**X. 跨运行时支持调研（Bun / C 扩展 / 其他，新增，P1/P2）**
- **背景**：原本只面向 Python 和 Node，但用户已安装 Bun，并指出直接 C 扩展（`.so`）和其他运行时也可能需要覆盖。
- **原则**：二进制 hook 是最终兜底，所有动态链接进程（Bun、C 扩展、native 模块）都应被 `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` 覆盖；名文 hook 仍只承诺 Python/JS。
- **待验证**：
  - 用 Bun 跑同一套文件/网络/写标记测试，确认二进制 hook 生效。
  - Bun 的名文 hook 需要单独的 preload 机制（Bun 支持 `--preload`，但 `NODE_OPTIONS=--require` 不保证兼容），先调研再承诺。
  - 写一个最小 C 扩展（调用 `open64`/`fopen64`），分别加载进 Python 和 Node，确认二进制 hook 仍返回蜜罐。
  - 其他运行时（PyPy、Deno 等）只做调研，不在本期承诺。
- 详见 6.4。

### P2（产品化/发布）

**O. 发布版缺预编译库**
- 当前 `init` 用本机 clang 编译，普通人没装 clang 就用不了。发布版应带 macOS arm64/x86_64、Linux x64/arm64 的预编译 `libvpo_hook.dylib/.so`；`init` 默认本机编译（用户要求，避免 libc 不匹配），无编译器或编译失败时才 fallback 到预编译库。生成方案见 6.2。

**P. `package.json` 缺 `files` 字段（已修复）**
- npm publish 默认带所有非 `.gitignore` 文件，`py_plaintext/` 是否被发布依赖默认行为。必须显式声明 `"files": ["vpo_hook.js", "obj_hook/", "plaintext/", "py_plaintext/"]`，排除 `wrapper.c`、`libvpo_hook.so`、`__pycache__/`。

**Q. `setup.py` 的 `package_data` glob 风险（已修复）**
- `obj_hook/*` 可能匹配 `__pycache__/` 和用户编译产物。改用 `MANIFEST.in` 精确列出，或 `package_data` 精确到文件名。

**R. `python_requires=">=3.8"` 脆弱兼容（已修复为 >=3.10）**
- `str | None` 注解在 `from __future__ import annotations` 下当前 work，但函数体内用 `|` 会崩。改 `>=3.10` 或确保所有 `|` 只在注解位置。

**S. `setup.py` 缺 `zip_safe=False`（已修复）**
- 防御性写法，声明“不能在 zip 里运行”。

**T. `build_hook` 编译失败抛裸 traceback（已修复）**
- 捕获 `CalledProcessError`，打印友好错误（“编译失败，请检查 clang/gcc 是否安装”），退出码非零。

**U. plaintext 文件存在性无检查（已修复）**
- 打包漏了时，Node/Python 目标直接崩。启动器里加 `if not preload.exists(): 报错退出`。

### P3（未来/待设计，先记录不实现）

**Y. 双语运维 SDK（`import vpoh` / `require('vpoh')`）**
- **需求**：运维脚本需要 Python 和 JS 双语，并且两边都能直接导入 `vpoh` 调用，而不是只能走 CLI。
- **范围**：`init`、`status`、`verify`、读/写配置、能力发现、生成示例、调用 run；两边 API 语义一致，输出 JSON 友好。
- **暂不实现**，详见 6.5。

**Z. Hook 发现与自动生成（运维脚本 + 示例）**
- **需求**：通过运维脚本创建一个示例程序，运行后抓到“具体需要 hook 什么”（仅限 Python/JS），让用户勾选要启用的项，再自动生成签名/配置。
- **边界**：C 扩展走二进制 hook，不做自动发现；自动生成结果必须人工确认，不能默认启用。
- **暂不实现**，详见 6.6。

**AA. 对象创建审计与供应链可审计增强**
- **现状**：`VPO_AUDIT_CLASSES` 只记录 `{ts, class, stack}` 到明文 JSONL，不是供应链可审计证明。
- **未来**：事件 schema、包身份/源码 hash、哈希链 + 签名、轮转/限流、隐私脱敏。
- **明确不做**：不加密运行时对象；只对审计记录做签名/加密。详见 6.7。

**AB. 配置完整性：签名优先于加密**
- **需求**：用户希望配置配合本机密钥对做解密/防篡改。
- **决策**：优先 Ed25519 签名；本地私钥对同 uid guest 不构成边界；加密只用于机密性，不用于防篡改。
- **暂不实现**，详见 6.8。

---

## 四、发布脚本（已实现 `scripts/release.py`）

> 2026-10-25：已实现 `scripts/release.py`。`--check` 通过（22 个文件、2 处路径替换、`VERSION=0.1.0`）；实际构建会同步文件、删除 stale 产物、同步版本号并做一致性校验。以下保留原始要求作为验收标准。

### 脚本职责

`scripts/release.py`（Python 写，跨平台）：

1. **从源目录构建发布版**：
   - 源：`py/`、`js/`
   - 目标：`release/py/vpohook/`、`release/js/`
   - 规则：
     - `py/vpo_hook.py` → `release/py/vpohook/cli.py`（改名）
     - `py/obj_hook/*` → `release/py/vpohook/obj_hook/*`
     - `py/plaintext/*` → `release/py/vpohook/plaintext/*`
     - `js/plaintext/*` → `release/py/vpohook/js_plaintext/*`
     - `js/vpo_hook.js` → `release/js/vpo_hook.js`
     - `js/obj_hook/*` → `release/js/obj_hook/*`
     - `js/plaintext/*` → `release/js/plaintext/*`
     - `py/plaintext/*` → `release/js/py_plaintext/*`
   - **路径替换**：源版 `py/vpo_hook.py` 里 `preload = HERE.parent / "js" / "plaintext" / "preload.js"` 要替换成 `HERE / "js_plaintext" / "preload.js"`；源版 `js/vpo_hook.js` 里 `PY_PLAINTEXT = path.join(path.dirname(HERE), 'py', 'plaintext')` 要替换成 `path.join(HERE, 'py_plaintext')`。替换规则用**精确字符串匹配 + 断言**，不要正则模糊替换。

2. **排除规则**：
   - 不拷 `__pycache__/`、`*.pyc`、`*.pyo`、`.DS_Store`、`node_modules/`、`wrapper.c`、`libvpo_hook.dylib`、`libvpo_hook.so`、`*.egg-info/`、`dist/`、`build/`。
   - **断言**：拷贝后检查 `release/py/vpohook/plaintext/` 和 `release/js/py_plaintext/` 下没有 `__pycache__/`，有则报错退出。

3. **一致性校验**：
   - `release/js/obj_hook/policy.c` 和 `release/py/vpohook/obj_hook/policy.c` 必须**逐字节相同**，不同则报错。
   - `signatures.json`、`vpo_hook.h`、`config.yaml`、`honeypot.py`/`honeypot.js` 同理。
   - `release/js/plaintext/interpose.js` 和 `release/py/vpohook/js_plaintext/interpose.js` 必须相同。
   - `release/js/py_plaintext/sitecustomize.py` 和 `release/py/vpohook/plaintext/sitecustomize.py` 必须相同。
   - **断言失败时打印 diff 并退出非零**。

4. **版本号同步**：
   - `package.json` 的 `version` 和 `setup.py` 的 `version` 必须一致。
   - 从单一源（比如 `VERSION` 文件或 `py/pyproject.toml`）读版本号，写入两处。

5. **干跑模式**：
   - `python scripts/release.py --dry-run` 只打印“会拷哪些文件、会做哪些替换”，不实际写。
   - `python scripts/release.py` 实际执行。
   - `python scripts/release.py --check` 只做一致性校验，不拷贝（CI 用）。

6. **输出清单**：
   - 执行完打印“拷了 N 个文件，替换了 M 处路径，一致性校验通过”。
   - 失败时打印“第 X 步失败：<原因>”。

### 脚本不做什么

- 不跑 `npm publish` / `pip upload`，只准备 `release/` 目录。
- 不编译 C 库（预编译是单独的 CI 任务，在旧版 glibc 容器里跑）。
- 不跑测试（测试是 `scripts/test.sh` 的职责）。

### CI 集成建议（给 AI 参考，不强制）

- GitHub Actions 里加一个 job：`python scripts/release.py --check`，确保每次 PR 的 `release/` 和源目录一致，drift 时报错。
- 发布 job：`python scripts/release.py` → 编译预编译库 → `cd release/js && npm publish` → `cd release/py && python setup.py sdist bdist_wheel && twine upload dist/*`。

---

## 五、给 AI 的工作顺序建议（2026-10-25 更新）

1. **P0-B：`execve` + `posix_spawn`/`posix_spawnp` 环境继承（Linux 已完成，macOS 生成通过、运行待实测）**。从 constructor 缓存构造 envp，不读运行时 `getenv`；生成代码用平台宏保证 Linux/macOS 都能编译运行。`vfork` 改为 `fork`，避免 vfork 子进程 malloc 崩溃。
2. **小 P0 一批（已修复）**：D（`lang=None` 显式化 + 警告）、E（审计防重入）、V（审计 `enabled` 误判）、L（审计写入原子性）、F（buildHook 退出码）。
3. **W：验收脚本 + quiet/log 控制（已实现）**：`scripts/verify_linux.sh` + `run -q/-v`，诊断信息走 stderr。
4. **`scripts/release.py`（已实现）**：`--dry-run` / `--check` / 实际构建；`VERSION` 单一来源，`release/` 已可重复生成。
5. **YAML（A/G）与配置完整性（AB）**：按用户节奏推进；先定威胁模型，签名优先于加密，不要阻塞上面几步。
6. **P1/P2/P3**：X（Bun/C 扩展）、J（network_mode 三态）、K（skip_on/noop）、O（预编译库）、P/Q（打包）、Y/Z/AA（双语 SDK、Hook 发现、供应链审计）。

**不要跳步**。不要先做“弹窗”“AI 生成配置”“策略包签名”这些上层功能，因为底层 bug 没修时，上层功能会建立在不可靠的基础上。**先让当前代码“对”，再让它“好用”**。

---

## 六、2026-10-25 新增需求与设计记录

### 6.1 P0-B 跨平台与防清空要求

- **状态（2026-10-25）**：Linux 已实现并实测通过；macOS 生成器输出通过（与 Python 版逐字节一致）。macOS 基线（交接前的 17 个 wrapper）已在 macOS 实机跑通；本次新增的 `posix_spawn`/env 注入/`vfork -> fork`/审计改动仍需在 macOS 上做一次回归。
- **目标**：`execve`/`posix_spawn` 的环境注入在 Linux 和 macOS 都能工作，且 guest 不能通过 `unsetenv` 清掉策略。
- **平台宏**：
  - `#if defined(__linux__)` → 注入 `LD_PRELOAD`
  - `#elif defined(__APPLE__)` → 注入 `DYLD_INSERT_LIBRARIES`
  - `-ldl` 只在 Linux 链接；macOS 的 `dlsym` 在 libSystem 里。
- **缓存**：`policy.c` constructor 启动时缓存 `deny_paths`、`allow_network`、`risk_markers`、`rewrite_paths`，以及 `VPO_HOOK_CONFIG`、`VPO_HOOK_PY_API`、`VPO_HOOK_JS_API`、`VPO_AUDIT_*`、`VPO_PYTHONPATH`、`VPO_NODE_OPTIONS`、`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`。`execve` wrapper 只读缓存。
- **envp 规则**：
  - `envp == NULL` 按空环境处理。
  - 复制原 envp 的非 VPO 键；VPO 键用缓存值覆盖。
  - `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` 合并并去重，VPO 库优先。
  - `PYTHONPATH`/`NODE_OPTIONS` 追加 VPO 前缀，不整体覆盖用户值。
  - `malloc` 失败直接返回失败，不 fallback 到原 envp。
- **vfork**：`vfork` wrapper 改为调用 `fork()`。vfork 子进程里调用 `malloc`/`strdup` 是未定义行为，会触发 `*** stack smashing detected ***`；替换为 fork 后再做 envp 合并才是安全的。
- **覆盖函数**：`execve`、`execv`、`execvp`、`posix_spawn`、`posix_spawnp`（`replace`/`reinject`）；`system`、`popen`（`reinject`）；`execveat` 可选后续补。
- **macOS 限制**：`execv`/`execvp`/`system`/`popen` 仍在 `MACOS_SKIP`（没有安全的真实符号）。这些是 macOS 上已确认无法安全 interpose 的缺口，作为**接受边界**记录，不再当作待修 TODO；`execve`/`posix_spawn`/`posix_spawnp` 已生成，需在 macOS 上回归。
- **验收**：`os.execve(..., {})`、`Popen(env={})`、`os.posix_spawn`、`env -i`、`sh -c` 子进程读 `/etc/passwd` 都必须是蜜罐；`env` 里能看到 `VPO_HOOK_CONFIG`。
- **边界**：直接 raw `syscall(SYS_execve)` 仍可绕过，需在文档写清楚；彻底封死要 seccomp/ptrace，不在本期。

### 6.2 预编译库生成（P2-O）

用户本机是较新的 Linux，**不要用本机生成发布用 `.so`**，否则 `GLIBC_2.xx` 符号版本太新。推荐：

- **Linux x86_64**：用旧 glibc 容器编译，例如 `quay.io/pypa/manylinux2014_x86_64`（glibc 2.17）或 `ubuntu:18.04`（glibc 2.27）。预编译前先按目标平台生成 `wrapper.c`（`-p linux` / `-p darwin`）。
  ```bash
  docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux2014_x86_64 \
    bash -lc 'gcc -shared -fPIC -O2 -o prebuilt/linux-x86_64/libvpo_hook.so \
      py/obj_hook/wrapper.c py/obj_hook/policy.c -ldl'
  ```
- **Linux arm64**：原生 arm64 runner，或 `docker run --platform linux/arm64`（需 QEMU），或用 `aarch64-linux-gnu-gcc` + sysroot 交叉编译。
- **无 Docker 的替代**：`zig cc -target x86_64-linux-gnu.2.17` 可直接生成旧 glibc ABI 的 `.so`；也可以维护一个旧版 sysroot 做交叉编译。生成后仍要验证符号版本。
- **macOS**：GitHub Actions 的 macOS runner 分别构建 arm64/x86_64；需要 universal 时用 `clang -dynamiclib -arch arm64 -arch x86_64`，并在两种架构上各测一次。
- **验证**：
  - `readelf --version-info` / `objdump -T` 检查最高 `GLIBC_*` 符号版本不超过目标。
  - 在旧容器里 `LD_PRELOAD=... /bin/true` 能加载。
  - `nm -D` 确认 `open64/openat64/fopen/fopen64` 等符号存在。
- **目录**：`prebuilt/linux-x86_64/`、`linux-aarch64/`、`darwin-arm64/`、`darwin-x86_64/`。
- **策略**：`init` 默认本机编译（用户要求，避免 libc 不匹配）；本机无编译器或编译失败时，才用预编译库兜底。预编译库要校验 hash/签名。
- **本机新 Linux 的定位**：只用于本地开发和本机编译，不用于生成发布产物。

### 6.3 验收脚本与日志控制（W）

- **状态（2026-10-25）**：已实现 `scripts/verify_linux.sh`，Linux x86_64 跑通（当前 44 项 PASS / 0 FAIL）。
- **脚本**：`scripts/verify_linux.sh`（macOS 可复用或加 `verify_macos.sh`），`set -uo pipefail`（失败继续跑，最后汇总）。
- **完整日志**：
  - `LOG="logs/verify-$(date +%Y%m%d-%H%M%S).log"`
  - 用 `exec > >(tee -a "$LOG") 2>&1` 或每个 `run_case` 同时写 log。
  - 记录环境：`uname -a`、`python3 -V`、`node -v`、`bun --version`、`cc --version`、`nm -D` 符号、生成器数量、配置 hash。
- **用例函数**：`run_case "名称" "命令" "期望"`，记录命令、期望、实际、PASS/FAIL；失败继续跑，最后汇总并非零退出。
- **清理**：`trap` 关闭后台 CVE server、删除临时文件；所有 server 用 `timeout`。
- **日志静默**：
  - `vpo-hook run` 的诊断全部走 **stderr**，目标程序 stdout 保持干净。
  - 加 `-q/--quiet`、`-v/--verbose`；环境变量 `VPO_HOOK_QUIET=1`、`VPO_HOOK_VERBOSE=1`。
  - `honeypot.py`/`honeypot.js` 支持 `--quiet`，或 quiet 模式下 launcher 重定向其 stdout。
  - C 库以后加日志也走 stderr，由 `VPO_VERBOSE` 控制。
  - 测试脚本默认 `-q`，完整细节进 log；调试时 `-v`。
- **不要**在 log 里打印真实 token、密码、私钥。

### 6.4 跨运行时与 C 扩展（X）

- **二进制 hook 是兜底**：Bun、Python/Node 的 C 扩展、其他动态链接 native 模块，只要走 libc，就应被覆盖。
- **Bun**：
  - 用户判断：Bun 的 obj 也是 JS 对象，明文 hook 原则上应能复用；先测 Bun 是否支持现有 `preload.js`（`--preload` / `BUN_OPTIONS` / `NODE_OPTIONS` 的实际效果），能复用就不单独写一套。
  - 如果 Bun 的模块加载/代理语义不同，再补 Bun 适配；不要先假设一定需要新实现。
  - 先验证二进制 hook 对 Bun 的 `fs`/`child_process`/`net` 出口是否生效。
- **C 扩展**：
  - 写一个最小 `.so`，调用 `open64`/`fopen64`，分别加载进 Python 和 Node，确认蜜罐。
  - C 扩展不需要名文 hook；二进制 hook 已覆盖。
- **其他运行时**：PyPy、Deno、GraalPy 等只保证 libc 出口 hook；不承诺名文 hook。
- **libc 绕过**：直接 raw `syscall` / 静态链接 / 主动反检测不在 LD_PRELOAD 能解决的范围内。当前先接受这个边界；如果简单安全组需要更强保证，后续评估 Linux Landlock + seccomp、macOS App Sandbox 作为第二层，而不是继续在 LD_PRELOAD 上叠补丁。

### 6.5 双语运维 SDK（Y）

- **目标**：Python 和 JS 运维脚本都能直接导入并调用，不只依赖 CLI。
- **Python**：`import vpoh`，提供 `init()`、`status()`、`verify()`、`load_config()`、`save_config()`、`run()`、`discover()`。
- **JS**：`require('vpoh')` / `import vpoh`，提供同名/同语义 API。
- **要求**：
  - 两边返回结构一致，便于脚本处理。
  - 不要求两边互相调用；共享同一份配置和生成器。
  - 运维脚本可以用任一语言写，能力对等。
- **暂不实现**，先记录 API 形态。

### 6.6 Hook 发现与自动生成（Z）

- **流程**：
  1. 运维脚本创建一个示例 Python/JS 程序。
  2. 在 observe 模式下运行：记录实际调用的 libc 函数和名文 API。
  3. 输出候选 hook 列表（函数/类、调用次数、调用栈）。
  4. 用户选择要启用的项。
  5. 自动生成 `signatures.json` 条目、wrapper 和配置片段。
- **实现思路**：
  - libc 调用：`strace`/`ltrace`，或给 hook 库加 observe 模式（只记录不拦截）。
  - Python：`sys.audit`、`sys.settrace`、AST 扫描。
  - JS：`diagnostics_channel`、`async_hooks`、AST 扫描。
- **边界**：仅限 Python/JS；C 扩展走二进制 hook；自动生成结果必须人工确认，不能默认启用。

### 6.7 对象审计与供应链可审计（AA，暂不做）

- **现状**：`VPO_AUDIT_CLASSES` 包装 Python `__init__` / JS constructor，记录 `{ts, class, stack}` 到明文 JSONL；没有包身份、签名、哈希链。
- **不建议加密运行时对象**：对象通常不可序列化，guest 需要明文使用，同进程加密没有意义。
- **未来方向**：
  - 事件 schema：`schema_version`、`pid`、`ppid`、`exe`、`class`、`stack`、`module`、`module_hash`、`ts`。
  - 完整性：哈希链 + Ed25519 签名 + 可选可信时间戳。
  - 供应链：包名/版本/源码 hash/SBOM，与对象审计解耦。
  - 运维：轮转、大小上限、采样/限流、隐私脱敏。
- **威胁模型**：同 uid guest 可读日志、可改日志；签名能发现篡改，但不能阻止同 uid 攻击者删除整份日志。需要外部存储/特权守护进程才更强。

### 6.8 配置完整性：签名优先于加密（AB，设计已定，待实现）

- **三个问题分开**：解析（YAML）、完整性（防篡改）、机密性（防读取）。
- **核心结论**：本机私钥如果 launcher 能自动用，同 uid 的 guest 也能用；因此本地密钥对加密/签名**不能防恶意 guest 篡改**。
- **已敲定（2026-10-25）**：
  - 用 **Ed25519** 做快速签名（验证成本低，适合每次启动校验），不要自创弱哈希/HMAC 方案。
  - 签名内容：`version + config_hash + timestamp + nonce + prev_audit_hash`；配合审计链，保证配置和审计记录的一致性。
  - 通过短有效期/定期轮换/审计链防止重放；不要依赖“把 key 藏在 blob 里”这种可提取的混淆。
  - launcher 内置公钥；私钥只在发布侧/签名服务，不能随包分发。
  - 用户可编辑配置用“厂商签名默认配置 + 用户本地覆盖配置”两层；用户层可放 OS keyring。
  - 如果确实要加密：用 `age`/`libsodium sealed box`，私钥放 OS keyring/TPM，解密到 `memfd`/管道，不落盘明文；加密只解决机密性，不解决完整性。
  - YAML 保持给用户编辑；签名对原始字节或规范化后的 canonical 数据做。YAML 重构可以独立进行，先加 `version`/`signature` 字段。
- **注意**：配置最终展开成 `VPO_*` 环境变量，对 guest 可见；所以“防篡改”可以，“防读取”在同进程模型下做不到。

### 6.9 安全组分层与配置保护（2026-10-25 决策）

- **两套安全组是刻意设计**，不是过渡状态：
  - **简单安全组**：面向普通用户，类似手机权限；只暴露少量能力组（IO/网络/进程/敏感路径），默认值安全，配置项尽量少，不开放任意 API hook。
  - **复杂安全组**：面向技术人/运维，开放全部权限、运维脚本、自定义 API hook、Hook 发现和自动生成。必须显式切换到复杂组，并显示高危警告。
- **简单组的路线**：先定“普通用户能理解”的能力组和默认拒绝项；网络默认值（J）跟随简单组一起定，不先拍板。
- **复杂组的 API hook**：不要假设“能 hook 的 API 都有用”。先用 Z（发现/示例/observe）验证真实使用频率和风险，再决定默认开启哪些；自动生成的 hook 必须人工确认。
- **配置保护**：
  - `~/.vpo-hook` 目录 `0700`，`config.yaml`/审计日志 `0600`。
  - launcher 启动时读一次配置并展开成环境变量；运行中改文件不影响当前进程，下次启动由签名/审计校验发现。
  - 防“其他文件/进程修改配置”：文件权限 + 签名 + 审计链 + 可选只读/immutable（`chattr +i` 需 root，不能作为唯一手段）。
  - 同 uid 的恶意 guest 仍是边界：它能读配置/环境变量；签名防的是篡改和重放，不是同进程读取。
  - 不把“进程逃逸已被拦”当成配置保护的全部理由；配置保护要独立成立。
- **供应链/作用域**：用户提出的“以信源为 query、限制信息进入作用域、hook obj/namespace constructor”属于后续 P1/P3 设计，先记录，不阻塞简单组和发布工程。

### 6.10 简单安全组设计定稿（2026-10-25）

> **实现状态（阶段 A）**：已实现 env_root 作用域、网络三态、exec 模式。启用条件：`profile: simple` **且** 存在 `permissions` 块（旧配置 `profile: simple` 但没有 `permissions` 块时保持旧行为）。`policy.c` 已编译通过，`verify_linux.sh` 46/46 通过。
>
> **实现状态（阶段 B）**：已实现 `vpo-hook scan <目录|文件>`（`nm -u` + Python `ast` + JS 正则），输出 `file/network/process/code_load` 四个能力组 + 置信度 + 证据；`run` 在简单安全组下会打印“发现能力”。首次运行弹权限组授权留到阶段 C（TUI/CLI + grants）。
>
> **实现状态（阶段 C）**：已实现“拒绝 + 审计 + 授权闭环”。`policy.c` 用真实 open/write 绕过自身 wrapper 追加 `~/.vpo-hook/denials.log`（结构化为 `{ts,func,path}`）；Python 启动器由 `exec` 改为 `spawn+wait`（转发 SIGTERM），结束后在 stderr 打印本次被拒摘要；新增 `vpo-hook log / grant / revoke / list`；首次运行在 TTY 下交互询问 network/process 并写 grants（`~/.vpo-hook/grants/<hash>.json`，0600/0700）。JS 启动器已有 spawn+wait，同步支持 denials 摘要和 log/list/grant/revoke（不含交互首次授权）。写蜜罐按结论**不做**，写敏感数据仍默认 block。
>
> **实现状态（阶段 D，配置签名 + 审计链）**：已实现 HMAC-SHA256 信封签名（`~/.vpo-hook/config.sig`，含 `ts/nonce/expiry/sig`），密钥 `~/.vpo-hook/.sign_key`（0600），支持 `VPO_SIGN_KEY` 覆盖。`init` 对新生成的配置自动签名；`vpo-hook sign` 显式（重）签名；`run` 在存在 `.sig` 时校验，篡改/过期/缺密钥一律拒绝运行（失败关闭）。无 `.sig` 的旧配置保持不校验。grants 同样签名（`grants/<hash>.sig`），`run` 校验失败拒绝运行；`vpo-hook chain` 校验审计哈希链（`chain.log` + `.chain_head`，链头 HMAC(key, sha256(line))），篡改/截断可检测。
>
> **实现状态（阶段 E，跨运行时）**：C 扩展（ctypes 的 `.so`，`fopen64`）、Node 原生 addon（N-API，`open`/`read`）、shell（`sh -c cat`）均已验证走二进制 hook 返回蜜罐，并加入 `verify_linux.sh`（当前 49 PASS）。**Bun 二进制 hook 无效**（Bun 是 Zig，读文件走 raw syscall 绕过 libc），Bun 名文 hook（Proxy 拦 `fs.readFileSync`）对 JS/TS 都有效但只能 deny、进不了蜜罐；按决定**先不做**，留到设计运维脚本时一起做特殊 syscall hook。macOS 本次新增路径回归仍待 Mac 实机。
>
> **实现状态（简单组可用性）**：`RUNTIME_DIRS` 扩展为 `/usr:/lib:/lib64:/bin:/sbin:/etc:/proc:/sys:/dev:/run:/tmp:/var/tmp`，真实 Python/Node 启动不再误拦 `/etc` 等系统读取；内置 `SIMPLE_DENY_PATHS`（HOME 下 secret：`~/.ssh`、`~/.aws`、`~/.kube`、`~/.npmrc`、`~/.gitconfig`、`~/.gnupg`、浏览器 cookie 目录等）+ 蜜罐生成（文件 deny 精确蜜罐，目录 deny 生成常见文件名蜜罐）。`/etc/passwd` 改为**真实可读**（world-readable 系统信息，非 secret）；敏感保护对象是 HOME secret。用户可用 `sensitive_files` 追加。

**已敲定的四个点**：

1. **Principal/作用域**：只保护“安装这个包的 venv / node 环境”。判定 env_root：
   - Python：目标解释器所在 venv（有 `pyvenv.cfg`），否则 `sys.prefix`
   - Node：从入口模块向上找最近的含 `package.json` + `node_modules` 的目录
   - env_root 内是信任区，可读写；env_root 之外默认拒绝；系统运行时目录只读放行；敏感路径永远拒绝。
2. **网络**：默认 `off`；`internet` 允许公网 80/443 + DNS，阻止私网/link-local/云 metadata。**loopback 一视同仁**：不做隐式放行，和公网站点一样需要显式加入 allowlist（防 `curl http://localhost/...` 静默外泄）。`open` 仅复杂组。
3. **进程**：`fork` 允许、`exec` 默认 `off`；`allowlist`/`shell` 需显式授权。
4. **入站命中**：默认 `audit`（只记录），不默认 `block`。
5. **信源**：第一版只做包级来源（包名/版本/hash/来源域名），对象级 taint 放复杂组。
6. **配置编辑**：优先简单 CLI（`vpo-hook add/remove/list`），只在 CLI 难以表达大量 URL/文件时才上 TUI；TUI 只在配置时运行，不影响 `run` 性能。
7. **AI 审计**：保留 `policy.c` 的 `buffer_has_marker` 空位 + `VPO_AI_AUDIT` 接口，第一版不实现模型。

**简单组 schema 定稿**：

```yaml
version: 1
profile: simple
name: "my-agent"
env: auto            # auto | <env_root>

permissions:
  files:
    extra_read: []
    extra_write: []
  network:
    mode: off        # off | internet | allowlist
    allowlist: []    # host:port
    blocklist: []    # 可疑 URL/域名
  process:
    fork: true
    exec: off        # off | allowlist | shell
    exec_allow: []

inbound:
  inspect: true
  action: audit      # audit | block

sources:
  allow: []
  deny: []

sensitive_words: []
audit: on
```

**简单组编译出的环境变量（阶段 A）**：

```text
VPO_ENV_ROOT
VPO_RUNTIME_DIRS
VPO_NETWORK_MODE          off | internet | allowlist
VPO_ALLOW_NETWORK         逗号分隔 host:port（allowlist 时）
VPO_NETWORK_BLOCKLIST     逗号分隔 可疑 host/域名（internet 时拦截）
VPO_EXEC_MODE             off | allowlist | shell
VPO_EXEC_ALLOW            冒号分隔 可执行文件绝对路径
VPO_DENY_PATHS            敏感路径（永远拒绝）
VPO_HIGH_RISK_MARKERS     数据标记（password/token/secret/private key）
VPO_INSPECT_INBOUND       1/0（recv/recvfrom 是否扫描）
VPO_INBOUND_ACTION        audit | block
```

**实施方式（opt-in）**：只有 `profile: simple` 且带新字段时才启用 env_root 作用域/网络三态/exec 模式；没有 `profile` 的旧配置保持现有行为，不破坏现有测试。阶段 A 改动集中在 `py/vpo_hook.py`、`js/vpo_hook.js`、`py/obj_hook/policy.c`、`js/obj_hook/policy.c` 和两份 `config.yaml` 模板，生成器不动。

### 6.11 信源（L2）与 Hook 发现（Z）的定位（2026-10-27 决策）

- **L2 信源放简单安全组**：重点场景是刚 `npm/pip install` 新包时，用包级来源（包名/版本/hash）做约束；后续再决定是否上对象级 taint。
- **Z 与 L2 合并做**：不做“无保护跑一遍真实 app”的动态观察（会直接漏完），改用**静态符号提取**：
  - 用户给一个 obj / namespace 当参数
  - 不运行（或不完整运行）扫出里面交互的符号（`nm -u` + AST/包级分析），去重
  - 按现有方法编译成只含这些符号的 hook 二进制（类似 CMake，但只做这件事）
  - 用户再勾选哪些当蜜罐
  - 这就是**复杂安全组**：用这套 SDK 做定制化
- **非 libc raw call 怎么 hook**：暂未定。候选方向是 Linux `seccomp` user-notify（监督进程可拦截/改写 syscall，实现 Bun 蜜罐）或 `ptrace`；macOS 是 Endpoint Security/`DYLD`。等做运维脚本/特殊 syscall hook 阶段再定。

### 6.12 复杂安全组 SDK：L2 信源 + Z 定制（2026-10-27 定稿）

- **discover 输入**：目录 / 包名 / namespace 过滤（或已加载的 obj）。
- **discover 方法（只留候选面，不分析实际调用）**：
  - Python：hook `import`（`sys.audit`/import hook）拿 module obj → `dir()` / `inspect.getmembers` 枚举方法
  - JS：hook `Module._load` 拿 module obj → `Reflect.ownKeys` / `Object.getOwnPropertyNames` 枚举方法
  - 原生 `.so/.dylib/.node`：`nm -u` 精确符号
  - 依赖边：记录 `import`/`require` 关系
- **manifest.json**：`{pkg:{name,version,root,hash}, deps:[...], symbols:[...], apis:{python:[...],js:[...]}}`，两语言输出同一份。
- **generate**：候选符号/API 与 `signatures.json` 求交 → 生成 subset `wrapper.c` → 编译 `libvpo_<pkg>.so`；用户勾选 allow / deny / honeypot（文件读可蜜罐，网络/进程只能 deny/audit）。
- **信源 enforce**：py/js 名文 sink 用栈归因到包，按 `sources.allow/deny` 判定。
- **边界（定稿）**：
  - 原生扩展：**二进制粗粒度兜底**（`open/read/write/connect/exec` 都拦，简单组/复杂组都生效），但不按包归因。
  - 文件通道的二进制通信：**已由二进制 hook 覆盖**，不是缺口。
  - 进程内内存传递（函数指针/共享内存）：**L4**，暂不做。
  - **不做符号转接层**（无稳定 ABI，脆弱、易崩，不值得）。
- **两语言**：SDK `import vpoh` / `require('vpoh')`，同名 API，共享同一 `manifest.json`。

---