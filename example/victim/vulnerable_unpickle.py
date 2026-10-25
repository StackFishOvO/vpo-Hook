"""
受害者程序：pickle 反序列化 RCE（远程控制）。

反序列化「不受信任」的 pickle 数据——这是 Python 生态里最经典的 RCE 类型。
很多真实应用（web 缓存、ML 模型加载 torch.load/joblib.load、会话管理）存在此漏洞，
攻击者传入恶意 pickle 即可远程执行任意命令。

对应真实世界：torch.load / joblib.load 反序列化 RCE 类 CVE。
"""

import pickle
import sys


def load_untrusted(path: str):
    with open(path, "rb") as f:
        data = f.read()
    # 漏洞：pickle.loads 反序列化不可信数据会执行攻击者注入的任意代码
    return pickle.loads(data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: python3 {sys.argv[0]} <pickle文件>")
        sys.exit(1)
    load_untrusted(sys.argv[1])
    print("[*] 反序列化完成")
