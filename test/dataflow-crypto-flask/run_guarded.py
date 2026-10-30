"""防护组：安装 namespace guard，再让 Flask 处理 /leak。

两种运行方式：
  1. 直接运行：脚本自己调用 ns_guard.install_from_file()
  2. 通过 vpo-hook 运行：sitecustomize 根据 VPO_NS_POLICY 自动安装

预期：crypto_pkg 的密文在进入 Flask response sink 时被 NamespaceDenied。
"""

from pathlib import Path
import os
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(ROOT / "py" / "plaintext"))

# 直接运行时手动安装；通过 vpo-hook 运行时 sitecustomize 已安装。
if not os.environ.get("VPO_NS_POLICY"):
    from ns_guard import install_from_file

    install_from_file(str(BASE / "ns_policy.json"))

from ns_guard import NamespaceDenied  # noqa: E402
from app import app  # noqa: E402

app.testing = True
app.config["PROPAGATE_EXCEPTIONS"] = True
client = app.test_client()

try:
    response = client.get("/leak")
except NamespaceDenied as exc:
    print(f"GUARDED_BLOCKED {exc.code} {exc.origin} -> {exc.sink}")
else:
    print(f"GUARDED_LEAKED status={response.status_code} body_hex={response.data[:24].hex()}")
    raise SystemExit(1)

# 普通响应必须不受影响。
response = client.get("/safe")
print(f"SAFE status={response.status_code} body={response.data.decode()}")
assert response.status_code == 200
assert response.data == b"SAFE"
