#!/usr/bin/env python3
"""
VPO-Hook 蜜罐运维脚本（明文版）。

当某个敏感文件被拦截时，rewrite（改写）会把它替换成本脚本生成的蜜罐数据。
本脚本由启动器在 run 前调用，生成蜜罐文件到 ~/.vpo-hook/honeypot/。

用户可以自由编辑此文件，定制蜜罐数据的内容（诱饵数据源）。
加密版（后续）：内部操控执行某个 terminal 中的东西来生成/管理这些数据。

与 js 侧 honeypot.js 逻辑一致。
"""

from pathlib import Path

HONEYPOT_DIR = Path.home() / ".vpo-hook" / "honeypot"


def generate() -> None:
    HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)

    # /etc/passwd 的蜜罐
    (HONEYPOT_DIR / "passwd").write_text(
        "root:x:0:0:HONEYPOT:/root:/bin/false\n"
        "honeypot:x:1000:1000:HONEYPOT:/home/honeypot:/bin/false\n"
    )

    # ~/.ssh 的蜜罐（目录 + 假私钥）
    ssh = HONEYPOT_DIR / "ssh"
    ssh.mkdir(exist_ok=True)
    (ssh / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "HONEYPOT FAKE KEY\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )

    # ~/.aws 的蜜罐
    aws = HONEYPOT_DIR / "aws"
    aws.mkdir(exist_ok=True)
    (aws / "credentials").write_text(
        "[default]\n"
        "aws_access_key_id = HONEYPOT\n"
        "aws_secret_access_key = HONEYPOT\n"
    )

    # 测试敏感数据 ~/.vpo-test-data 的蜜罐
    testdata = HONEYPOT_DIR / "testdata"
    testdata.mkdir(exist_ok=True)
    (testdata / "secret.txt").write_text("api_token=HONEYPOT_FAKE_000\n")
    (testdata / "db.txt").write_text("password=HONEYPOT_FAKE_111\n")

    # 真实漏洞测试的敏感数据蜜罐
    sensitive = HONEYPOT_DIR / "sensitive"
    sensitive.mkdir(exist_ok=True)
    (sensitive / "secret.txt").write_text(
        "database_password=HONEYPOT_FAKE\n"
        "api_key=HONEYPOT_FAKE\n"
        "aws_secret_access_key=HONEYPOT_FAKE\n"
    )

    print("[honeypot] 蜜罐数据已生成")


if __name__ == "__main__":
    generate()
