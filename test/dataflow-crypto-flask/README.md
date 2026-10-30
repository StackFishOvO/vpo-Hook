# 加密数据进入 Flask 的 namespace 隔离测试

这个测试验证的是：

```text
敏感数据 -> crypto_pkg（加密） -> 密文 -> Flask response
```

要求：**密文也不能进入 Flask 出口**。

为什么需要这个测试：二进制/明文 hook 的敏感标记扫描对密文无效。
加密后的数据不再包含 `password/token` 等明文标记，所以必须靠
namespace / taint 来判断“数据来自哪里”，而不是“内容长什么样”。

## 文件

- `crypto_pkg/__init__.py`：真实加密包（`cryptography.Fernet`）
- `app.py`：Flask 应用，`/leak` 返回密文
- `ns_policy.json`：命名空间策略
  - `crypto_pkg` 是 source，wrap `encrypt` / `decrypt`
  - `flask_app` 是 Flask sink
  - 禁止 `crypto_pkg -> flask_app` 的数据流
- `run_baseline.py`：不装 guard，密文正常返回
- `run_guarded.py`：装 guard，密文在 Flask sink 被拒
- `run.sh`：一次跑完三种情况
- `requirements.txt`：flask / cryptography

## 安装依赖

```bash
cd test/dataflow-crypto-flask
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 运行

```bash
cd test/dataflow-crypto-flask
PYTHON=.venv/bin/python ./run.sh
```

预期输出：

```text
===== baseline: no guard =====
BASELINE status=200 body_hex=...

===== guarded: direct ns_guard =====
GUARDED_BLOCKED NAMESPACE_DENIED crypto_pkg -> flask_app
SAFE status=200 body=SAFE

===== guarded: vpo-hook --ns-policy =====
GUARDED_BLOCKED NAMESPACE_DENIED crypto_pkg -> flask_app
SAFE status=200 body=SAFE
```

## 单独跑 vpo-hook

推荐直接用 `./run.sh`：它会生成一个 `env` 指向本目录的临时配置，
避免简单安全组把测试脚本或 `.venv` 判到 env_root 之外。

`sitecustomize.py` 会在用户代码启动前读取 `VPO_NS_POLICY`，安装
`ns_guard`，因此 Flask 不需要改代码。

## SDK 生成

两个运维 SDK 都可以把 `ns_policy` 写进产物：

```python
import json
import vpoh

m = vpoh.discover("crypto_pkg")
policy = json.load(open("ns_policy.json", encoding="utf-8"))
r = vpoh.generate(m, out_dir=".vpo", ns_policy=policy)
# r["ns_policy"] -> .vpo/ns_policy.json
# r["launch"]    -> .vpo/launch.sh（自动带 --ns-policy）
```

JS 侧 `vpoh.generate(m, outDir, policy)` 生成同样的文件。

## 边界（必须明确）

- 这是 Python 进程内的 L3-lite 原型，不是完整 taint 引擎。
- 只覆盖 Python API 边界；`ctypes`、raw socket、子进程、原生扩展直接写数据仍可绕过。
- 如果 app 在把密文交给 Flask 之前执行了 `bytes(ciphertext)` 等“抹掉子类”的操作，
  taint 也可能丢失。生产版需要在更多传播点/容器上维护标签。
- 这个测试证明的是“namespace 策略可以拦住这条路径”，不是“所有加密外泄都能拦住”。
