#!/usr/bin/env python3
"""
guard.py -- install same-name wrappers, then execute a guest script.

This is deliberately the shape of a runtime preload:

    1. import the modules we want to protect
    2. replace their plaintext names with proxies
    3. install an import hook for modules loaded later
    4. seal the guard
    5. execute the guest code in a fresh __main__

Run:

    python3 guard.py guest.py
"""

from __future__ import annotations

import builtins
import sys
import types
from pathlib import Path

from import_hook import Rule, install as install_import_hook, uninstall as uninstall_import_hook
from interpose import CapabilityDenied, Interposer, Policy


def ask(cap_id: str, args: tuple, kwargs: dict) -> bool:
    """A tiny synchronous approval callback for Policy.ASK."""
    if cap_id == "subprocess.run":
        command = args[0] if args else kwargs.get("args")
        if isinstance(command, (list, tuple)) and command:
            return str(command[0]) == "echo"
    return False


def audit(event: dict) -> None:
    """Never log argument values here: that can call guest __repr__."""
    print(
        f"[audit] {event['decision']:<10} {event['cap']} "
        f"argc={event['argc']} kwargs={event['kwargs']}",
        flush=True,
    )


def main() -> None:
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))

    entry = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "guest.py"
    if not entry.is_absolute():
        entry = (Path.cwd() / entry).resolve()
    if not entry.is_file():
        raise SystemExit(f"guest not found: {entry}")

    # The guest may import sibling modules.
    if str(entry.parent) not in sys.path:
        sys.path.insert(0, str(entry.parent))

    # Import this *before* binding so its `from os import system as ...`
    # alias exists.  sweep() will then be able to replace that alias.
    import legacy_alias  # noqa: F401

    # The import hook target must not already be loaded, otherwise the hook
    # has no chance to run.  Fail loudly rather than silently not protecting it.
    if "csv" in sys.modules:
        raise RuntimeError(
            "csv was imported before guard.py installed the hook; "
            "pick a target module that is not already loaded"
        )

    guard = Interposer(default_policy=Policy.DENY, ask=ask, audit=audit)

    # --- bind names on modules that are already imported -----------------
    guard.bind_module(
        "os",
        "system",
        "os.system",
        policy=Policy.DENY,
        description="shell execution",
    )
    guard.bind_module(
        "subprocess",
        "run",
        "subprocess.run",
        policy=Policy.ASK,
        description="process execution needs approval",
    )
    guard.bind_module(
        "os",
        "getcwd",
        "os.getcwd",
        policy=Policy.SUBSTITUTE,
        substitute=lambda *args, **kwargs: "/virtual/cwd",
        description="fake current directory",
    )

    # --- bind names on a module imported later ---------------------------
    # `csv` is not imported by guard.py; guest.py's `import csv` triggers the
    # finder, which runs csv's real loader and then replaces csv.reader.
    finder = install_import_hook(
        guard,
        {
            "csv": [
                Rule(
                    "reader",
                    "csv.reader",
                    policy=Policy.DENY,
                    description="csv.reader disabled for the demo",
                )
            ]
        },
    )

    # --- close the alias that was captured before binding ----------------
    swept = guard.sweep(["legacy_alias"])

    # --- no new external bindings after this point -----------------------
    guard.seal()

    print(
        f"[guard] installed {len(guard.describe())} initial binding(s); "
        f"1 import-hook rule; swept {swept} alias(es)"
    )
    for item in guard.describe():
        print(f"[guard]   {item['cap']:<20} {item['kind']:<10} {item['description']}")
    print("[guard] running guest\n", flush=True)

    old_main = sys.modules.get("__main__")
    old_argv = sys.argv

    guest_module = types.ModuleType("__main__")
    guest_module.__dict__.update(
        {
            "__name__": "__main__",
            "__file__": str(entry),
            "__package__": None,
            "__builtins__": builtins,
        }
    )
    sys.modules["__main__"] = guest_module
    sys.argv = [str(entry)]

    try:
        source = entry.read_text(encoding="utf-8")
        code = compile(source, str(entry), "exec")
        exec(code, guest_module.__dict__)
    except CapabilityDenied as exc:
        print(f"[guard] uncaught CapabilityDenied: {exc}", flush=True)
    finally:
        sys.argv = old_argv
        uninstall_import_hook(finder)
        guard.restore()
        if old_main is not None:
            sys.modules["__main__"] = old_main
        print("\n[guard] bindings restored", flush=True)


if __name__ == "__main__":
    main()
