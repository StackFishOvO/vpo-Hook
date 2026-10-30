"""Flask 应用：故意把 crypto_pkg 的密文作为 HTTP 响应返回。

这个文件模拟“数据跨 namespace 流入 Flask 出口”的场景：
  - /leak：crypto_pkg.encrypt(secret) -> Flask response
  - /safe：普通文本，用于确认普通响应不受影响

注意：这里没有手动检查 taint。真正的拦截由 ns_guard 在 Flask sink 上完成，
用来验证 runtime / SDK 生成策略是否生效。
"""

from flask import Flask

import crypto_pkg

app = Flask(__name__)

SECRET = b"password=REAL_SECRET_123"


@app.route("/leak")
def leak():
    # 密文里没有 password 明文，所以基于内容标记的扫描看不到它。
    ciphertext = crypto_pkg.encrypt(SECRET)
    return ciphertext


@app.route("/safe")
def safe():
    return "SAFE"
