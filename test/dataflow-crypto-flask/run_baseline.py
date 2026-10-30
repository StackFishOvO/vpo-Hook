"""对照组：不安装 namespace guard。

预期：Flask 正常返回 crypto_pkg 的密文。
密文里没有 password 明文，所以“内容标记扫描”无法识别它。
"""

from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from app import app  # noqa: E402

app.testing = True
client = app.test_client()

response = client.get("/leak")
print(f"BASELINE status={response.status_code} body_hex={response.data[:24].hex()}")
assert response.status_code == 200
assert b"password" not in response.data, "ciphertext should not contain plaintext marker"
