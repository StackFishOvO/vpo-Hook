#!/usr/bin/env python3
"""运维脚本示例（Python）：用 vpoh 生成网络出口 hook，跑一个 HTTP 服务，
外发消息里的敏感词（password）会被就地改成 HONEYPOT。

用法（在项目根目录）:
    python3 example/ops/hook_server.py [port]
然后浏览器打开:
    http://127.0.0.1:<port>/send?msg=my+password+123
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "py"))

import vpoh  # noqa: E402

PORT = sys.argv[1] if len(sys.argv) > 1 else "8080"
server = os.path.join(ROOT, "example", "servers", "demo_server.py")

# 1. 定制一个"网络出口"hook：只拦 send/sendto/write/writev
manifest = {
    "pkg": {"name": "net-egress"},
    "symbols": ["send", "sendto", "write", "writev"],
    "apis": {},
    "deps": [],
}
r = vpoh.generate(manifest, out_dir=os.path.join(ROOT, "example", "servers", ".vpo"))
print("hook:", r["so"], flush=True)

# 2. 外发数据改成蜜罐模式（默认是 block）
os.environ["VPO_DATA_MODE"] = "honeypot"

# 3. 用这个定制 hook 跑服务器
print(f"打开浏览器: http://127.0.0.1:{PORT}/send?msg=my+password+123", flush=True)
vpoh.run(["python3", server, PORT], hook=r["so"])
