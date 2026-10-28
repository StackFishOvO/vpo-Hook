# 外发蜜罐 demo

演示“复杂安全组 SDK”：用 `vpoh.discover/generate` 生成一个**网络出口 hook**，
把服务器外发消息里的敏感词（`password`）就地替换成 `HONEYPOT`。

## 运行（Python 版）

```bash
cd vpoh
python3 example/ops/hook_server.py 8080
# 另开终端或浏览器打开：
curl http://127.0.0.1:8080/send?msg=my+password+123
```

预期响应：

```text
sent: my HONEYPOT 123
```

## 运行（Node 版）

```bash
cd vpoh
node example/ops/hook_server.js 8080
curl http://127.0.0.1:8080/send?msg=my+password+123
```

预期响应同样是：

```text
sent: my HONEYPOT 123
```

## 原理

1. `hook_server.py/js` 用 `vpoh.generate` 编译一个只含 `send/sendto/write/writev` 的
   `libvpo_net-egress.so`。
2. 设置 `VPO_DATA_MODE=honeypot`，用 `vpoh.run(..., hook=...)` 跑服务器。
3. 服务器响应里包含 `password`，二进制 hook 在 `send`/`write`/`writev` 出口处把
   `password` 就地改成 `HONEYPOT`（长度不变），浏览器看到的就是蜜罐。

## 注意

- 依赖本机 gcc（`init`/`generate` 会编译），以及项目根目录的 `py/`、`js/` 源码。
- 生成产物在 `example/servers/.vpo/`（已 gitignore）。
