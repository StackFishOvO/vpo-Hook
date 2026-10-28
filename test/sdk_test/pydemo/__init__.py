"""SDK 测试包：故意暴露敏感行为，用于验证 discover/generate 流程。"""

import os
import subprocess
import socket


def read_file(path):
    return open(path, "r").read()


def run_cmd(cmd):
    return subprocess.run(cmd, shell=True).returncode


def connect(host, port):
    return socket.create_connection((host, port), timeout=2)
