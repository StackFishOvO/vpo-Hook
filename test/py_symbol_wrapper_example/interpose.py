#!/usr/bin/env python3
"""
interpose.py -- a small, standalone "same-name API interception" core for Python.

The idea
--------
We do NOT ask the guest to call a new API.  We keep the original *name*
(e.g. ``os.system``) and replace the value that the name resolves to with a
proxy:

    module.__dict__["system"] = proxy

The proxy looks like the original (``__name__``, ``__qualname__``, ``__doc__``,
``__module__``, ``__signature__``) but never exposes the original object.  Every
call goes through a decision function:

    ALLOW       -> call the original
    DENY        -> raise CapabilityDenied
    ASK         -> ask a callback; deny unless it says yes
    SUBSTITUTE  -> return a fake value / call a fake function

This is the same mechanism the Python runtime in ``py_runtime`` uses
(``replace_module_attrs`` + ``make_proxy``), but with the runtime, ZMQ and
policy tables removed.  It is intentionally a *library*, not a sandbox: the
original is still reachable in pure Python through introspection.  For a real
security boundary the original must live in native code or in the host process.

Only plaintext names are covered
--------------------------------
``os.system(...)`` is covered because ``os.system`` is looked up again at call
time.  These are not covered unless you add extra bindings:

    from os import system as f   # captured before binding
    posix.system(...)            # another module / another name
    ctypes.CDLL(None).system(...)
    subprocess.Popen(...)        # a sibling API

``sweep()`` can help with aliases captured before binding, but it is a
best-effort traversal, not a proof of coverage.
"""

from __future__ import annotations

import builtins
import importlib
import inspect
import sys
import types
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Optional


class Policy(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"
    SUBSTITUTE = "SUBSTITUTE"


class CapabilityDenied(PermissionError):
    """Raised when a bound call is denied."""

    def __init__(self, cap_id: str, reason: str = "") -> None:
        self.cap_id = cap_id
        self.reason = reason
        self.code = "CAPABILITY_DENIED"
        message = f"capability denied: {cap_id}"
        if reason:
            message += f" ({reason})"
        super().__init__(message)


@dataclass(frozen=True)
class Capability:
    id: str
    policy: Any = Policy.ASK
    substitute: Any = None
    description: str = ""


@dataclass
class Binding:
    container: Any
    name: str
    cap_id: str
    original: Any
    kind: str = "callable"
    description: str = ""


class _Proxy:
    """Callable proxy that keeps the public surface, not the original handle."""

    def __init__(self, interposer: "Interposer", cap_id: str, original: Any) -> None:
        self._interposer = interposer
        self._cap_id = cap_id

        # Copy the "looks like a normal function" metadata.  Do NOT set
        # __wrapped__: that is a direct handle to the original.
        self.__name__ = getattr(original, "__name__", cap_id.rsplit(".", 1)[-1])
        self.__qualname__ = getattr(original, "__qualname__", self.__name__)
        self.__doc__ = getattr(original, "__doc__", None)
        self.__module__ = getattr(original, "__module__", None)
        self.__annotations__ = getattr(original, "__annotations__", {})

        try:
            self.__signature__ = inspect.signature(original)
        except (TypeError, ValueError):
            pass

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._interposer._invoke(self._cap_id, args, kwargs)

    def __get__(self, obj: Any, objtype: Any = None) -> Any:
        # Make the proxy work when placed in a class dictionary.
        if obj is None:
            return self
        return types.MethodType(self, obj)

    def __repr__(self) -> str:
        return f"<interposed {self._cap_id}>"


class Interposer:
    """
    Bind plaintext names to proxies and dispatch calls through a policy.

    Parameters
    ----------
    default_policy:
        Used when ``bind(..., policy=...)`` does not specify one.
    ask:
        ``ask(cap_id, args, kwargs) -> bool`` for ``Policy.ASK``.
        If it is missing or raises, the call is denied (fail closed).
    audit:
        ``audit(event: dict) -> None``.  The event contains the capability id,
        decision and argument *count*, not argument values, so auditing does
        not call user ``__repr__``.
    """

    def __init__(
        self,
        *,
        default_policy: Any = Policy.DENY,
        ask: Optional[Callable[[str, tuple, dict], bool]] = None,
        audit: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._default_policy = default_policy
        self._ask = ask
        self._audit = audit

        self._caps: dict[str, Capability] = {}
        self._originals: dict[str, Any] = {}
        self._proxies: dict[str, _Proxy] = {}
        self._bindings: list[Binding] = []
        self._undo: list[Callable[[], None]] = []
        self._sealed = False

    # ------------------------------------------------------------------
    # Binding
    # ------------------------------------------------------------------
    def bind(
        self,
        container: Any,
        name: str,
        cap_id: str,
        *,
        policy: Any = None,
        substitute: Any = None,
        description: str = "",
    ) -> _Proxy:
        """Bind ``container.name`` to a proxy.  ``container`` may be a module,
        class, instance, or a dotted module name."""

        return self._bind(
            container,
            name,
            cap_id,
            policy=policy,
            substitute=substitute,
            description=description,
            internal=False,
        )

    def bind_module(self, module_name: str, name: str, cap_id: str, **kwargs: Any) -> _Proxy:
        return self.bind(importlib.import_module(module_name), name, cap_id, **kwargs)

    def bind_builtin(self, name: str, cap_id: str, **kwargs: Any) -> _Proxy:
        return self.bind(builtins, name, cap_id, **kwargs)

    def _bind(
        self,
        container: Any,
        name: str,
        cap_id: str,
        *,
        policy: Any = None,
        substitute: Any = None,
        description: str = "",
        internal: bool = False,
    ) -> _Proxy:
        if self._sealed and not internal:
            raise RuntimeError("interposer is sealed; no new bindings are allowed")

        if isinstance(container, str):
            container = importlib.import_module(container)

        if not isinstance(name, str) or not name:
            raise TypeError("name must be a non-empty string")
        if cap_id in self._proxies:
            return self._proxies[cap_id]

        # Handle staticmethod/classmethod descriptors explicitly.  A normal
        # function is fine with _Proxy.__get__.
        raw = None
        if isinstance(container, type):
            raw = container.__dict__.get(name)

        if isinstance(raw, (staticmethod, classmethod)):
            original = raw.__func__
            kind = "descriptor"
        else:
            if not hasattr(container, name):
                raise AttributeError(f"{container!r} has no attribute {name!r}")
            original = getattr(container, name)
            kind = "callable"

        if inspect.isclass(original):
            # Replacing a class with a function breaks isinstance/except/
            # subclassing.  A real implementation needs a metaclass proxy.
            raise TypeError(
                f"refusing to bind class {cap_id!r}; bind its methods instead"
            )
        if not callable(original):
            raise TypeError(f"only callables can be bound; {cap_id!r} is not callable")

        cap = Capability(
            id=cap_id,
            policy=self._default_policy if policy is None else policy,
            substitute=substitute,
            description=description,
        )
        proxy = _Proxy(self, cap_id, original)

        # Install first, then record.  If installation fails, leave no state.
        if isinstance(raw, (staticmethod, classmethod)):
            replacement: Any = type(raw)(proxy)
        else:
            replacement = proxy

        try:
            setattr(container, name, replacement)
        except Exception as exc:  # non-writable module/class dict
            raise RuntimeError(f"cannot install binding {cap_id!r}: {exc}") from exc

        self._caps[cap_id] = cap
        self._originals[cap_id] = original
        self._proxies[cap_id] = proxy
        self._bindings.append(
            Binding(container, name, cap_id, original, kind, description)
        )

        def undo(
            container: Any = container,
            name: str = name,
            raw: Any = raw,
            proxy: _Proxy = proxy,
            original: Any = original,
        ) -> None:
            if isinstance(raw, (staticmethod, classmethod)):
                current = container.__dict__.get(name) if isinstance(container, type) else None
                if isinstance(current, (staticmethod, classmethod)) and current.__func__ is proxy:
                    setattr(container, name, raw)
            else:
                current = getattr(container, name, None)
                if current is proxy:
                    setattr(container, name, original)

        self._undo.append(undo)
        return proxy

    # ------------------------------------------------------------------
    # Alias sweeping
    # ------------------------------------------------------------------
    def sweep(self, module_names: Optional[Iterable[str]] = None) -> int:
        """
        Replace references that are *identical* to a bound original with the
        proxy.  This closes the common ``from os import system`` alias when the
        module was imported before binding.

        It only walks module dictionaries.  It does not walk class dicts,
        closures, instance attributes, C-level tables, or already-copied
        values.  Treat the return value as "aliases found", not "coverage
        complete".
        """

        if isinstance(module_names, str):
            module_names = [module_names]
        wanted = set(module_names) if module_names is not None else None

        by_identity = {
            id(original): (cap_id, self._proxies[cap_id])
            for cap_id, original in self._originals.items()
        }

        replaced = 0
        for mod_name, module in list(sys.modules.items()):
            if module is None:
                continue
            if mod_name.startswith("interpose") or mod_name.startswith("import_hook"):
                continue
            if wanted is not None and mod_name not in wanted:
                continue

            namespace = getattr(module, "__dict__", None)
            if not isinstance(namespace, dict):
                continue

            for attr, value in list(namespace.items()):
                hit = by_identity.get(id(value))
                if hit is None:
                    continue
                cap_id, proxy = hit
                try:
                    namespace[attr] = proxy
                except Exception:
                    continue
                replaced += 1

                def undo(
                    namespace: dict = namespace,
                    attr: str = attr,
                    value: Any = value,
                    proxy: _Proxy = proxy,
                ) -> None:
                    if namespace.get(attr) is proxy:
                        namespace[attr] = value

                self._undo.append(undo)

        return replaced

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def seal(self) -> "Interposer":
        """
        Prevent *external* bind() calls.  Internal import hooks can still bind
        newly loaded modules (they call _bind(..., internal=True)).
        """
        self._sealed = True
        return self

    def restore(self) -> None:
        """Undo bindings/sweeps in reverse order.  Intended for teardown."""
        for undo in reversed(self._undo):
            try:
                undo()
            except Exception:
                pass
        self._undo.clear()
        self._bindings.clear()
        self._caps.clear()
        self._originals.clear()
        self._proxies.clear()
        self._sealed = False

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def _invoke(self, cap_id: str, args: tuple, kwargs: dict) -> Any:
        cap = self._caps.get(cap_id)
        if cap is None:
            raise CapabilityDenied(cap_id, "unknown capability")

        decision = self._decide(cap, args, kwargs)

        if decision is Policy.ASK:
            allowed = False
            try:
                allowed = bool(self._ask and self._ask(cap_id, args, kwargs))
            except Exception:
                allowed = False
            self._emit(cap_id, "ASK_ALLOW" if allowed else "ASK_DENY", args, kwargs)
            if not allowed:
                raise CapabilityDenied(cap_id, "ask denied")
            return self._originals[cap_id](*args, **kwargs)

        self._emit(cap_id, decision.value, args, kwargs)

        if decision is Policy.ALLOW:
            return self._originals[cap_id](*args, **kwargs)
        if decision is Policy.DENY:
            raise CapabilityDenied(cap_id)
        if decision is Policy.SUBSTITUTE:
            substitute = cap.substitute
            return substitute(*args, **kwargs) if callable(substitute) else substitute

        raise CapabilityDenied(cap_id, f"invalid decision: {decision!r}")

    def _decide(self, cap: Capability, args: tuple, kwargs: dict) -> Policy:
        policy = cap.policy
        if callable(policy):
            try:
                policy = policy(cap, args, kwargs)
            except Exception:
                # A broken policy is a deny, never an allow.
                return Policy.DENY
        try:
            return Policy(policy)
        except Exception:
            return Policy.DENY

    def _emit(self, cap_id: str, decision: str, args: tuple, kwargs: dict) -> None:
        if not self._audit:
            return
        try:
            self._audit(
                {
                    "cap": cap_id,
                    "decision": decision,
                    "argc": len(args),
                    "kwargs": tuple(kwargs.keys()),
                }
            )
        except Exception:
            # Auditing must never change the call's behavior.
            pass

    # ------------------------------------------------------------------
    # Introspection for the demo
    # ------------------------------------------------------------------
    def describe(self) -> list[dict]:
        return [
            {
                "cap": binding.cap_id,
                "name": f"{getattr(binding.container, '__name__', type(binding.container).__name__)}.{binding.name}",
                "kind": binding.kind,
                "description": binding.description,
            }
            for binding in self._bindings
        ]
