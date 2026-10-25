"""
sitecustomize.py -- VPO-Hook 名文 hook 入口（Python）。

Python 启动时，site 模块会自动 import sitecustomize（只要它在 sys.path 里）。
启动器把本目录加入 PYTHONPATH 并设置环境变量，于是：

1. 名文拦截：对 VPO_HOOK_PY_API 指定的同名 API（如 os.system）做接口级拦截。
2. 对象创建审计：对 VPO_AUDIT_CLASSES 指定的类 hook __init__，记录创建时的调用链
   （只做记录，不做鉴权；默认关闭，启用时才有开销）。
"""

import functools
import importlib
import json
import os
import sys
import time
import traceback

from interpose import CapabilityDenied, Interposer, Policy

__all__ = ["CapabilityDenied", "Interposer", "Policy"]

QUIET = os.environ.get("VPO_HOOK_QUIET") == "1"


def _install() -> None:
    raw = os.environ.get("VPO_HOOK_PY_API", "")
    apis = [x.strip() for x in raw.split(":") if x.strip()]
    if not apis:
        return

    guard = Interposer(default_policy=Policy.DENY)
    installed: list[str] = []
    for cap in apis:
        if "." not in cap:
            continue
        mod_name, attr = cap.rsplit(".", 1)
        try:
            module = importlib.import_module(mod_name)
        except ImportError:
            continue
        if not hasattr(module, attr):
            continue
        try:
            guard.bind(module, attr, cap, policy=Policy.DENY)
            installed.append(cap)
        except Exception:
            continue
    guard.seal()

    if installed and not QUIET:
        sys.stderr.write(
            f"[vpo-plaintext] 已安装 {len(installed)} 个名文 hook: "
            f"{', '.join(installed)}\n"
        )


def _install_audit() -> None:
    """对象创建审计：记录敏感类创建时的调用链（只记录，不做鉴权）。"""
    raw = os.environ.get("VPO_AUDIT_CLASSES", "")
    classes = [c.strip() for c in raw.split(":") if c.strip()]
    if not classes:
        return

    log_path = os.environ.get(
        "VPO_AUDIT_LOG", os.path.expanduser("~/.vpo-hook/audit.log")
    )

    installed: list[str] = []
    seen: set[str] = set()
    for cls_name in classes:
        if cls_name in seen or "." not in cls_name:
            continue
        seen.add(cls_name)
        mod_name, _, cls_attr = cls_name.rpartition(".")
        try:
            module = importlib.import_module(mod_name)
            cls = getattr(module, cls_attr)
        except (ImportError, AttributeError):
            continue
        if not isinstance(cls, type):
            continue
        orig_init = cls.__init__
        if getattr(orig_init, "__vpo_audited__", False):
            continue

        def make_wrapper(cn: str, orig):
            @functools.wraps(orig)
            def wrapped(self, *args, **kwargs):
                try:
                    stack = traceback.extract_stack()[:-1]  # 去掉当前帧
                    entry = {
                        "ts": time.time(),
                        "class": cn,
                        "stack": [
                            f"{fr.filename}:{fr.lineno} {fr.name}"
                            for fr in stack[-10:]
                        ],
                    }
                    line = (json.dumps(entry) + "\n").encode("utf-8")
                    fd = os.open(
                        log_path,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        view = memoryview(line)
                        while view:
                            n = os.write(fd, view)
                            if n <= 0:
                                break
                            view = view[n:]
                    finally:
                        os.close(fd)
                except Exception:
                    pass
                return orig(self, *args, **kwargs)

            wrapped.__vpo_audited__ = True
            return wrapped

        try:
            cls.__init__ = make_wrapper(cls_name, orig_init)
            installed.append(cls_name)
        except Exception:
            continue

    if installed and not QUIET:
        sys.stderr.write(
            f"[vpo-audit] 已安装 {len(installed)} 个审计 hook: {', '.join(installed)}\n"
        )


_install()
_install_audit()
