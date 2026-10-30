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
from pathlib import Path

from interpose import CapabilityDenied, Interposer, Policy

__all__ = ["CapabilityDenied", "Interposer", "Policy"]

QUIET = os.environ.get("VPO_HOOK_QUIET") == "1"

# L2 信源：仅“显式进入 deny 才拒绝”，未知/allow 一律放行（粗粒度兜底在二进制层）
_SOURCES_DENY = set(
    x.strip() for x in os.environ.get("VPO_SOURCES_DENY", "").split(",") if x.strip()
)


def _package_of(filename: str | None) -> str | None:
    if not filename:
        return None
    parts = Path(filename).parts
    for marker in ("site-packages", "dist-packages"):
        if marker in parts:
            idx = parts.index(marker)
            if idx + 1 < len(parts):
                top = parts[idx + 1]
                return top[:-3] if top.endswith(".py") else top
            return None
    return None


def _caller_package() -> str | None:
    frame = sys._getframe(1)
    while frame is not None:
        fname = frame.f_code.co_filename
        if "interpose.py" in fname or "sitecustomize.py" in fname:
            frame = frame.f_back
            continue
        pkg = _package_of(fname)
        if pkg:
            return pkg
        frame = frame.f_back
    return None


def _install_sources() -> None:
    """L2 信源：命中 sources.deny 的包，其进程/网络出口被拒；其余放行。"""
    if not _SOURCES_DENY:
        return

    def policy(cap, args, kwargs):
        pkg = _caller_package()
        if pkg and (pkg in _SOURCES_DENY or any(pkg == d or pkg.startswith(d + ".") for d in _SOURCES_DENY)):
            return Policy.DENY
        return Policy.ALLOW

    sinks = [
        ("os", "popen"), ("os", "fork"),
        ("os", "execv"), ("os", "execve"), ("os", "execvp"), ("os", "execvpe"),
        ("os", "spawnl"), ("os", "spawnlp"), ("os", "spawnv"), ("os", "spawnvp"),
        ("os", "posix_spawn"), ("os", "posix_spawnp"),
        ("subprocess", "call"), ("subprocess", "check_call"),
        ("subprocess", "check_output"), ("subprocess", "getoutput"),
        ("subprocess", "getstatusoutput"),
        ("socket", "create_connection"), ("socket", "connect"),
    ]
    guard = Interposer(default_policy=Policy.ALLOW)
    installed = []
    for mod_name, attr in sinks:
        try:
            module = importlib.import_module(mod_name)
            if hasattr(module, attr):
                guard.bind(module, attr, f"{mod_name}.{attr}", policy=policy)
                installed.append(f"{mod_name}.{attr}")
        except Exception:
            continue
    guard.seal()
    if installed and not QUIET:
        sys.stderr.write(
            f"[vpo-sources] 已安装 {len(installed)} 个信源 hook（deny: {', '.join(sorted(_SOURCES_DENY))}）\n"
        )


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


def _install_namespace_guard() -> None:
    """L3-lite：按 VPO_NS_POLICY 安装 namespace 数据流守卫。"""
    policy_path = os.environ.get("VPO_NS_POLICY")
    if not policy_path:
        return
    try:
        from ns_guard import install_from_file

        install_from_file(policy_path)
    except Exception as exc:
        if not QUIET:
            sys.stderr.write(f"[vpo-ns] 安装失败: {exc}\n")


_install()
_install_sources()
_install_audit()
_install_namespace_guard()
