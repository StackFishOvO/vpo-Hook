# 真实漏洞测试（real_problem_test）

用真实的攻击手法验证 VPO-Hook 的防护能力。所有攻击只针对本目录内的「受害者程序」，
仅用于本地安全测试，**请勿用于攻击任何真实目标**。

## 漏洞 1：任意文件读取（信息泄露）

- **受害者**：`victim/vulnerable_file_reader.py` —— 一个故意不做路径校验的文件读取服务，
  对应大量真实 web 应用（Flask/Django/各类 CMS）的 path traversal / 任意文件读取漏洞。
- **攻击**：攻击者指定任意路径（如 `/etc/passwd`、数据库配置），读到真实内容。
- **vpo-hook 防护**：敏感路径命中 `deny_paths` → 改写为蜜罐假数据。
  默认配置已包含 `/etc/passwd`；若想测试本目录的 `sensitive_data/secret.txt`，
  需要把它的**绝对路径**加入 `~/.vpo-hook/config.yaml` 的 `deny_paths` 和 `honeypot_map`。

## 漏洞 2：pickle 反序列化 RCE（远程控制）

- **受害者**：`victim/vulnerable_unpickle.py` —— 反序列化不受信任的 pickle 数据，
  对应大量真实 Python 应用的 `pickle.loads` 反序列化漏洞（web 缓存、ML 模型加载、
  会话管理，典型如 torch.load / joblib.load 的 RCE 类 CVE）。
- **攻击**：`exploit/make_malicious_pickle.py` 生成恶意 pickle，反序列化时执行
  `os.system` 命令（此处以「写 /tmp/vpo_pwned_flag 文件」作为攻击成功的标志）。
- **vpo-hook 防护**：`os.system` 命中名文 hook → `CapabilityDenied`，命令不执行。

> 说明：这两个漏洞都不是「靠升级 Python 版本修复」的，而是「应用层缺陷 + pickle 本身
> 对不可信输入不安全」，所以对 Python 3.12 / 3.13 依然有效，适合拿来做对照实验。

---

## 测试步骤

先在项目根目录完成 hook 的编译（如果还没 init）：

```bash
python3 py/vpo_hook.py init
```

### 漏洞 1：信息泄露

**① 对照组（不用 vpo-hook，攻击成功，看到真实敏感数据）**

```bash
python3 example/victim/vulnerable_file_reader.py /etc/passwd
```

**② 防护组（用 vpo-hook，攻击被改写为蜜罐）**

```bash
python3 py/vpo_hook.py run python3 example/victim/vulnerable_file_reader.py /etc/passwd
```

### 漏洞 2：远程控制

**③ 生成恶意 pickle**

```bash
cd example && python3 exploit/make_malicious_pickle.py && cd ..
```

**④ 对照组（不用 vpo-hook，命令执行成功）**

```bash
rm -f /tmp/vpo_pwned_flag
python3 example/victim/vulnerable_unpickle.py example/malicious.pkl
ls -l /tmp/vpo_pwned_flag   # 存在 → 攻击成功（RCE 生效）
```

**⑤ 防护组（用 vpo-hook，命令被拦截）**

```bash
rm -f /tmp/vpo_pwned_flag
python3 py/vpo_hook.py run python3 example/victim/vulnerable_unpickle.py example/malicious.pkl
ls -l /tmp/vpo_pwned_flag   # 不存在 → 攻击被拦（CapabilityDenied）
```

---

## 重要发现：名文 hook 的「别名」边界

测试中暴露了一个真实问题：`os.system` 底层其实是 `posix.system` 的别名（`os` 从 `posix`
导入）。恶意 pickle 序列化的是 `posix.system`（用 `pickletools.dis` 可看到 `'posix' + 'system'`），
反序列化时走 `posix.system`，绕过了只替换 `os.system` 的名文 hook。

**修复**：config 的 `plaintext.python` 里把 `posix.system` 也加进拦截列表（已加）。

这正印证了 `test/py_symbol_wrapper_example/README.md` 里写的名文 hook 边界：
「另一个模块导出同一函数（`posix.system`）不会自动覆盖」。这是名文 hook 的固有边界，
**真正兜底还得靠二进制 hook**（本例中命令最终会走 `fork`/`execve`，可由二进制层补上）。
