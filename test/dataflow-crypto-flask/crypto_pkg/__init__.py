"""测试用“具备加密能力的包”。

设计目标：
  1. 真正做加密（cryptography.Fernet），这样密文里不会残留 password/token 等明文标记。
  2. 返回值保持普通 bytes，不在包里手动打 taint 标签。

taint 由 vpo-hook 的 namespace guard 在“包边界”统一加上：
  ns_policy.json 把 crypto_pkg 标成 source，并 wrap encrypt/decrypt。
这样测试的是“运行时策略”，不是测试包自己作弊。
"""

from cryptography.fernet import Fernet

_KEY = Fernet.generate_key()
_FERNET = Fernet(_KEY)


def encrypt(data: bytes) -> bytes:
    """返回密文；密文不再包含原始敏感标记。"""
    return _FERNET.encrypt(data)


def decrypt(token: bytes) -> bytes:
    """解密；解密结果同样应被视为来自 crypto_pkg 的敏感数据。"""
    return _FERNET.decrypt(token)
