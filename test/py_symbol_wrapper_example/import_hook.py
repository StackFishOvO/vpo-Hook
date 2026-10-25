#!/usr/bin/env python3
"""
import_hook.py -- bind names on modules that are imported *after* the guard
starts.

This is a minimal version of ``py_runtime/interceptor_ext/interceptor_finder.py``:

    find_spec(fullname) -> wrap spec.loader
    loader.exec_module() -> run the real module, then bind its attributes

The important detail is that the binding happens after the module's own code
has run.  At that point the module dictionary is complete, so aliases and
re-exports that live *inside that module* can be seen by name.

This hook does not protect modules that were already imported.  Use
``Interposer.sweep()`` or an explicit ``bind_module()`` for those.
"""

from __future__ import annotations

import importlib.abc
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from interpose import Interposer, Policy


@dataclass(frozen=True)
class Rule:
    """One attribute to bind after a module has been executed."""

    attr: str
    cap_id: str
    policy: Any = Policy.ASK
    substitute: Any = None
    description: str = ""


class _Loader(importlib.abc.Loader):
    def __init__(
        self,
        original: importlib.abc.Loader,
        fullname: str,
        interposer: Interposer,
        rules: Iterable[Rule],
    ) -> None:
        self._original = original
        self._fullname = fullname
        self._interposer = interposer
        self._rules = tuple(rules)

    def create_module(self, spec: Any) -> Any:
        create = getattr(self._original, "create_module", None)
        if create is not None:
            return create(spec)
        return None

    def exec_module(self, module: Any) -> None:
        self._original.exec_module(module)

        for rule in self._rules:
            if not hasattr(module, rule.attr):
                # A rule that does not match is a configuration error.  Fail
                # loudly instead of silently leaving a hole.
                raise RuntimeError(
                    f"import hook: {self._fullname!r} has no attribute {rule.attr!r}"
                )
            try:
                self._interposer._bind(
                    module,
                    rule.attr,
                    rule.cap_id,
                    policy=rule.policy,
                    substitute=rule.substitute,
                    description=rule.description,
                    internal=True,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"import hook: failed to bind {self._fullname}.{rule.attr}"
                ) from exc

    def __getattr__(self, name: str) -> Any:
        # Preserve loader-specific methods (get_filename, is_package, ...).
        return getattr(self._original, name)


class BindingFinder(importlib.abc.MetaPathFinder):
    def __init__(self, interposer: Interposer, rules: Mapping[str, Iterable[Rule]]) -> None:
        self._interposer = interposer
        self._rules = {name: tuple(items) for name, items in rules.items()}
        self._loading: set[str] = set()

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname not in self._rules:
            return None
        if fullname in self._loading:
            return None
        if fullname.startswith("interpose") or fullname.startswith("import_hook"):
            return None

        # Ask the other finders.  We are inserted at the front of sys.meta_path,
        # so we have to skip ourselves to avoid infinite recursion.
        for finder in sys.meta_path:
            if finder is self:
                continue
            find_spec = getattr(finder, "find_spec", None)
            if find_spec is None:
                continue
            spec = find_spec(fullname, path, target)
            if spec is None or spec.loader is None:
                continue

            self._loading.add(fullname)
            try:
                spec.loader = _Loader(
                    spec.loader, fullname, self._interposer, self._rules[fullname]
                )
            finally:
                self._loading.discard(fullname)
            return spec
        return None


def install(
    interposer: Interposer, rules: Mapping[str, Iterable[Rule]]
) -> BindingFinder:
    finder = BindingFinder(interposer, rules)
    sys.meta_path.insert(0, finder)
    return finder


def uninstall(finder: BindingFinder) -> None:
    try:
        sys.meta_path.remove(finder)
    except ValueError:
        pass
