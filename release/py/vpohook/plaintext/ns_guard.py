"""L3-lite namespace data-flow guard (Python, cooperative).

This is a small, explicit prototype for the "namespace isolation" requirement:

    sensitive data -> crypto package -> ciphertext -> Flask response

Content-based marker scanning cannot see that the ciphertext came from a
sensitive source, because encryption removes the marker. This module therefore
tracks *origin labels* on Python objects and checks them at a sink.

Scope and limits (intentionally explicit):

- In-process, Python-only. It does not cover native code, raw sockets, or
  child processes.
- It is a cooperative guard: a package can still bypass it with ctypes, raw
  syscalls, or by converting tainted bytes with `bytes(...)` before the sink.
- It is NOT the final L3 taint engine. It is the minimal prototype needed to
  demonstrate that the requirement is achievable at the Python API boundary.

The runtime entry point is `sitecustomize.py`: when `VPO_NS_POLICY` points at a
JSON policy, it imports this module and installs the guard before user code.
"""

from __future__ import annotations

import functools
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Iterable

try:
    from interpose import CapabilityDenied
except Exception:  # pragma: no cover - only for standalone use
    class CapabilityDenied(PermissionError):
        def __init__(self, cap_id: str, reason: str = "") -> None:
            self.cap_id = cap_id
            self.reason = reason
            self.code = "CAPABILITY_DENIED"
            message = f"capability denied: {cap_id}"
            if reason:
                message += f" ({reason})"
            super().__init__(message)


QUIET = os.environ.get("VPO_HOOK_QUIET") == "1"


class NamespaceDenied(CapabilityDenied):
    """Raised when tainted data crosses a denied namespace boundary."""

    def __init__(self, origin: str, sink: str) -> None:
        super().__init__("namespace", f"{origin} -> {sink} denied")
        self.origin = origin
        self.sink = sink
        self.code = "NAMESPACE_DENIED"


class TaintedBytes(bytes):
    """bytes subclass carrying origin labels."""

    def __new__(cls, value=b"", origins: Iterable[str] = ()):  # type: ignore[override]
        obj = bytes.__new__(cls, value)
        obj.__vpo_origins__ = frozenset(origins)
        return obj


class TaintedStr(str):
    """str subclass carrying origin labels."""

    def __new__(cls, value="", origins: Iterable[str] = ()):  # type: ignore[override]
        obj = str.__new__(cls, value)
        obj.__vpo_origins__ = frozenset(origins)
        return obj


def _merge_origins(value, origin: str):
    current = getattr(value, "__vpo_origins__", frozenset())
    return frozenset(current) | {origin}


def taint(value, origin: str):
    """Attach an origin label to bytes/str (and recursively to containers)."""
    if isinstance(value, TaintedBytes):
        return TaintedBytes(value, _merge_origins(value, origin))
    if isinstance(value, TaintedStr):
        return TaintedStr(value, _merge_origins(value, origin))
    if isinstance(value, bytes):
        return TaintedBytes(value, {origin})
    if isinstance(value, bytearray):
        return TaintedBytes(bytes(value), {origin})
    if isinstance(value, str):
        return TaintedStr(value, {origin})
    if isinstance(value, list):
        return [taint(v, origin) for v in value]
    if isinstance(value, tuple):
        return tuple(taint(v, origin) for v in value)
    if isinstance(value, set):
        return {taint(v, origin) for v in value}
    if isinstance(value, dict):
        return {taint(k, origin): taint(v, origin) for k, v in value.items()}
    return value


def collect_origins(value, _seen=None) -> set[str]:
    """Collect origin labels from a value, with cycle/depth protection."""
    if _seen is None:
        _seen = set()
    marker = id(value)
    if marker in _seen:
        return set()
    _seen.add(marker)

    origins = set(getattr(value, "__vpo_origins__", ()))
    if isinstance(value, dict):
        for key, val in value.items():
            origins.update(collect_origins(key, _seen))
            origins.update(collect_origins(val, _seen))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            origins.update(collect_origins(item, _seen))
    return origins


def _resolve_attr(module, dotted: str):
    obj = module
    for part in dotted.split("."):
        obj = getattr(obj, part)
    return obj


def _set_attr(module, dotted: str, value) -> None:
    parts = dotted.split(".")
    obj = module
    for part in parts[:-1]:
        obj = getattr(obj, part)
    setattr(obj, parts[-1], value)


def _wrap_source(module_name: str, namespace: str, functions: Iterable[str]) -> list[str]:
    """Wrap configured source functions so their return values carry a label."""
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        if not QUIET:
            sys.stderr.write(f"[vpo-ns] 无法导入 source {module_name}: {exc}\n")
        return []

    installed: list[str] = []
    for name in functions:
        try:
            original = _resolve_attr(module, name)
        except AttributeError:
            continue
        if not callable(original) or getattr(original, "__vpo_ns_wrapped__", False):
            continue

        @functools.wraps(original)
        def wrapped(*args, __orig=original, __ns=namespace, **kwargs):
            return taint(__orig(*args, **kwargs), __ns)

        wrapped.__vpo_ns_wrapped__ = namespace
        try:
            _set_attr(module, name, wrapped)
            installed.append(f"{module_name}.{name}")
        except Exception:
            continue
    return installed


def _check_sink(value, sink: str, deny: set[tuple[str, str]]) -> None:
    for origin in sorted(collect_origins(value)):
        if (origin, sink) in deny or ("*", sink) in deny or (origin, "*") in deny:
            raise NamespaceDenied(origin, sink)


def _install_flask_sink(sink: str, deny: set[tuple[str, str]]) -> list[str]:
    """Patch Flask response construction so tainted bodies are rejected."""
    try:
        flask = importlib.import_module("flask")
    except Exception as exc:
        if not QUIET:
            sys.stderr.write(f"[vpo-ns] 无法导入 flask sink: {exc}\n")
        return []

    installed: list[str] = []

    original_make_response = getattr(flask, "make_response", None)
    if original_make_response and not getattr(original_make_response, "__vpo_ns_sink__", False):
        @functools.wraps(original_make_response)
        def make_response(*args, **kwargs):
            if args:
                _check_sink(args[0], sink, deny)
            elif "response" in kwargs:
                _check_sink(kwargs["response"], sink, deny)
            return original_make_response(*args, **kwargs)

        make_response.__vpo_ns_sink__ = sink
        flask.make_response = make_response
        installed.append("flask.make_response")

    response_cls = getattr(flask, "Response", None)
    if response_cls is not None:
        original_init = response_cls.__init__
        if not getattr(original_init, "__vpo_ns_sink__", False):
            @functools.wraps(original_init)
            def response_init(self, *args, **kwargs):
                if args:
                    _check_sink(args[0], sink, deny)
                return original_init(self, *args, **kwargs)

            response_init.__vpo_ns_sink__ = sink
            response_cls.__init__ = response_init
            installed.append("flask.Response.__init__")

        original_set_data = getattr(response_cls, "set_data", None)
        if original_set_data and not getattr(original_set_data, "__vpo_ns_sink__", False):
            @functools.wraps(original_set_data)
            def set_data(self, value):
                _check_sink(value, sink, deny)
                return original_set_data(self, value)

            set_data.__vpo_ns_sink__ = sink
            response_cls.set_data = set_data
            installed.append("flask.Response.set_data")

    return installed


_DENY: set[tuple[str, str]] = set()
_INSTALLED = False


def install(policy: dict) -> None:
    """Install source wrappers and sink checks from a policy dict."""
    global _INSTALLED
    if _INSTALLED:
        return

    deny: set[tuple[str, str]] = set()
    for flow in policy.get("flows", []):
        if flow.get("action", "deny") != "deny":
            continue
        src = str(flow.get("from", ""))
        dst = str(flow.get("to", ""))
        if src and dst:
            deny.add((src, dst))

    namespaces = policy.get("namespaces", {})
    installed: list[str] = []
    for name, cfg in namespaces.items():
        cfg = cfg or {}
        role = cfg.get("role") or cfg.get("type")
        if role in ("source", "untrusted") or cfg.get("source"):
            functions = cfg.get("functions") or []
            installed.extend(_wrap_source(cfg.get("module") or name, name, functions))
        if role == "sink" or cfg.get("sink"):
            framework = str(cfg.get("framework") or "").lower()
            if framework == "flask" or "flask" in name.lower():
                installed.extend(_install_flask_sink(name, deny))

    _DENY.clear()
    _DENY.update(deny)
    _INSTALLED = True
    if installed and not QUIET:
        sys.stderr.write(
            f"[vpo-ns] 已安装命名空间守卫: {', '.join(installed)}; "
            f"deny flows: {sorted(deny)}\n"
        )


def install_from_file(path: str) -> None:
    """Load a JSON policy and install the guard.

    The policy file's directory is prepended to sys.path so a local source
    package (e.g. `crypto_pkg`) can be imported before user code runs.
    """
    policy_path = Path(path).expanduser().resolve()
    base = str(policy_path.parent)
    if base not in sys.path:
        sys.path.insert(0, base)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    install(policy)


def check_sink(value, sink: str = "flask_app") -> None:
    """Manual sink check, useful for tests or custom integrations."""
    _check_sink(value, sink, _DENY)
