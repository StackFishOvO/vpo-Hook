# py_symbol_wrapper_example

A standalone, dependency-free extraction of the **plaintext same-name API
interception** mechanism used by `py_runtime` (without pybind11, ZMQ, or the
runtime's policy tables).

The guest writes ordinary Python:

```python
import os
os.system("...")
```

The guard has replaced the value that the name `os.system` resolves to:

```python
os.__dict__["system"] = proxy
```

The proxy has the same public name/metadata, but every call is dispatched
through a policy first. The original callable is kept on the guard side.

## Run

```bash
cd py_symbol_wrapper_example
python3 guard.py guest.py
```

## Files

| File | Purpose |
| --- | --- |
| `interpose.py` | Core: `Interposer`, `Policy`, `CapabilityDenied`, proxy, `sweep()`, `seal()`, `restore()`. |
| `import_hook.py` | Minimal `sys.meta_path` finder/loader hook: bind names after a module is imported. |
| `guard.py` | Preload-style setup: bind, install import hook, sweep aliases, seal, execute guest in a fresh `__main__`. |
| `guest.py` | Plaintext guest calls; includes the allowed paths and the bypasses that are intentionally not covered. |
| `legacy_alias.py` | `from os import system as legacy_system`, imported **before** binding to demonstrate `sweep()`. |

## Mechanism

1. **Resolve and replace the plaintext name.** `bind()` does
   `getattr(container, name)`, stores the original, creates a proxy, and does
   `setattr(container, name, proxy)`. For a class it handles
   `staticmethod`/`classmethod` descriptors explicitly.

2. **Dispatch before calling.** The proxy holds only a capability id. On call,
   `Interposer._invoke()` evaluates the policy:

   | Decision | Behavior |
   | --- | --- |
   | `ALLOW` | call the original |
   | `DENY` | raise `CapabilityDenied` |
   | `ASK` | call `ask(cap_id, args, kwargs)`; deny if false, missing, or raising |
   | `SUBSTITUTE` | return a fake value, or call a fake function |

   A policy may be a fixed `Policy` or a callable
   `(capability, args, kwargs) -> Policy`. Policies receive the **live args**
   before any argument serialization.

3. **Audit without evaluating guest values.** The built-in audit event has
   `cap`, `decision`, `argc`, and keyword names only. It never calls
   `repr(args)`, so auditing cannot run guest code.

4. **Close aliases captured earlier.** `sweep(["legacy_alias"])` walks module
   dictionaries and replaces values whose identity is exactly a bound original.
   That turns `legacy_alias.legacy_system` into the proxy.

5. **Bind future imports.** `import_hook.py` wraps the real loader for a
   configured module. After the real `exec_module()` finishes, it replaces the
   named attributes. In the demo, `guest.py`'s `import csv` causes
   `csv.reader` to be bound.

6. **Seal and restore.** `seal()` blocks external `bind()` calls, while the
   import hook can still bind modules via `_bind(..., internal=True)`.
   `restore()` reverses bindings and sweeps in reverse order.

## What the demo shows

- `os.system` — direct `DENY`.
- `subprocess.run(["echo", ...])` — `ASK` approved.
- `subprocess.run(["rm", ...])` — `ASK` denied before execution.
- `os.getcwd()` — `SUBSTITUTE` returns `/virtual/cwd`.
- `legacy_alias.legacy_system` — repaired alias, `DENY`.
- `csv.reader` — bound by the import hook, `DENY`.
- `posix.system`, `os.popen`, and `subprocess.Popen` — **not bound**, so they
  still run. These are deliberate demonstrations of the boundary.

## Covered vs. not covered

This is the same limitation model as the runtime's `replace_module_attrs`:

- Covered: the exact attribute after it has been replaced, if the guest reaches
  it through the original module/class/instance.
- Not covered automatically: aliases captured before binding but outside the
  swept module dicts; sibling APIs (`os.popen`, `subprocess.Popen`);
  another module exporting the same function (`posix.system`); closures;
  class dictionaries not swept; C-level calls; `ctypes`; native extensions;
  and code that reaches the original through introspection.

`sweep()` is best-effort. It walks module dictionaries only. It does not walk
closures, instances, class dicts, or C tables.

## This is not a security boundary in pure Python

The proxy deliberately does **not** set `__wrapped__`, so this common one-line
bypass is gone:

```python
os.system.__wrapped__(...)
```

However, Python is introspectable. A guest can still find the guard through the
proxy object, for example:

```python
os.system._interposer._originals["os.system"]
```

The example keeps the code readable; it does not pretend that pure Python can
hide a Python object from a Python guest. For a real boundary, the original
must live in native code or in the host process, and the guest should only
receive a proxy that makes an RPC decision. That is exactly what
`py_runtime` does with `py::cpp_function` + the host `ASK` path, but the
native/host split is the security-relevant part.

## Lifting it into `py_runtime`

- Keep `_invoke(cap_id, args, kwargs)` as the single dispatch point.
- Replace the local `ask` callback with the ZMQ/host request and add a request
  id + timeout (the current runtime's ASK protocol has no request id).
- Decide before serializing arguments; the current runtime serializes in
  `make_proxy` before the policy runs.
- Bind after import in the loader wrapper, as `interceptor_finder.py` does.
- Keep the original in native/host memory, not in a Python `dict` on a
  guest-reachable object.
- Add explicit profiles: `compat` (original allowed in the guest) vs `security`
  (original only on the host, default deny).
