from setuptools import setup, find_packages

setup(
    name="vpo-hook",
    version="0.1.0",
    description="VPO-Hook: Virtual Private Object Hook — 二进制 + 名文双层纵深防御",
    long_description="在桌面 Node.js / Python 运行时上提供接口级 + 出口级的纵深防御，"
    "让用户安全运行未经验证的 npm / pip 包。",
    author="VPO-Hook",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "vpohook": [
            "obj_hook/*",
            "plaintext/*",
            "js_plaintext/*",
        ],
    },
    entry_points={
        "console_scripts": [
            "vpo-hook=vpohook.cli:main",
        ],
    },
    python_requires=">=3.8",
    install_requires=[],
)
