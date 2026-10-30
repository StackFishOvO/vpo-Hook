# Node.js：加密数据进入 HTTP response 的 namespace 隔离

这是 Python / Flask 版本的 Node 对应测试：

```text
敏感数据 -> crypto_pkg（AES-256-GCM） -> 密文 -> http.ServerResponse
```

要求：**密文也不能进入 Node HTTP response 出口。**

## 文件

- `crypto_pkg/index.js`：真实加密包（Node 内置 `crypto`）
- `server.js`：Node HTTP server，`/leak` 返回密文
- `ns_policy.json`：
  - `crypto_pkg` 是 source，wrap `encrypt` / `decrypt`
  - `node_http` 是 sink，patch `http.ServerResponse.write/end`
  - 禁止 `crypto_pkg -> node_http`
- `run_baseline.js`：不装 guard
- `run_guarded.js`：装 guard
- `run_case.js`：启动 server + 请求 `/leak`、`/safe`
- `run.sh`：一键跑三种情况

## 运行

```bash
cd test/dataflow-crypto-node
./run.sh
```

预期：

```text
===== baseline: no guard =====
BASELINE status=200 body_hex=...
BASELINE_SAFE status=200 body=SAFE

===== guarded: direct ns_guard =====
GUARDED status=403 body_hex=424c4f434b4544
GUARDED_SAFE status=200 body=SAFE

===== guarded: vpo-hook --ns-policy =====
GUARDED status=403 body_hex=424c4f434b4544
GUARDED_SAFE status=200 body=SAFE
```

`424c4f434b4544` 是 `BLOCKED`。

## vpo-hook 做了什么

- `vpo-hook run --ns-policy ...` 设置 `VPO_NS_POLICY`
- `NODE_OPTIONS=--require .../preload.js` 在用户代码前加载
- `preload.js` 读取策略，调用 `ns_guard.installFromFile`
- `ns_guard.js`：
  - 包装 source 函数，把返回值（Buffer）记入 WeakMap 来源标签
  - patch `http.ServerResponse.write/end`
  - 发现 `crypto_pkg -> node_http` 的 deny flow 时抛 `NamespaceDenied`
- `server.js` 捕获后返回 403 `BLOCKED`，所以密文没有进入响应

## 边界

- 只覆盖 Node 进程内的 object/Buffer；字符串无法挂 WeakMap 标签。
- 只 patch 配置的 source 函数和 `http.ServerResponse.write/end`。
- `Buffer.concat`、`toString`、`Buffer.from` 等传播点尚未自动继承标签。
- 原生扩展、raw socket、子进程直接写数据仍可绕过。
- 这是 L3-lite 原型，不是完整 taint 引擎。
