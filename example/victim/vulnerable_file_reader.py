"""
受害者程序：任意文件读取漏洞（信息泄露）。

模拟真实 web 应用的 path traversal / 任意文件读取漏洞——没有做路径校验，
攻击者可以读取任意文件（/etc/passwd、数据库配置、密钥等）。

对应真实世界：大量 Flask/Django/各类 CMS 的任意文件读取 CVE。
"""

import sys


def read_file(path: str) -> str:
    # 漏洞：直接信任外部传入的路径，无任何校验
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python3 {sys.argv[0]} <文件路径>")
        sys.exit(1)
    print(read_file(sys.argv[1]), end="")
