# node_symbol_wrapper_example

A standalone, dependency-free extraction of the **plaintext same-name API
interception** mechanism used by `js_runtime` (without the N-API addon, ZMQ, or
the runtime's policy tables).

The guest writes normal CommonJS:

```js
const fs = require('fs');
fs.readFileSync(path);
```

The preload has replaced the value of the plaintext property:

```js
fs.readFileSync = proxy;
```

The proxy keeps the same `name`, `length`, and constructor `prototype`. The
original function is held in a JS closure on the guard side, so ordinary
reflection cannot reach it.

## Run

```bash
cd node_symbol_wrapper_example
./run.sh
# equivalent to:
# node --require ./preload.js ./guest.js
```

## Files

| File | Purpose |
| --- | --- |
| `interpose.js` | Core: `Interposer`, `Policy`, `CapabilityDenied`, proxy, `installLoader()`, `seal()`, `restore()`. |
| `preload.js` | Installs bindings and the require/loader hook before the guest starts. |
| `guest.js` | Normal plaintext guest calls, plus intentional sibling-API bypasses. |
| `run.sh` | `node --require ./preload.js ./guest.js`. |

## Mechanism

1. **Preload before the guest.** `--require ./preload.js` runs before
   `guest.js`. The guest never sees a special API.

2. **Replace the property value.** `bind()` does `container[name]`, stores the
   original in the interposer's closure/maps, builds a proxy, and assigns
   `container[name] = proxy`. `bindModule()` is just
   `bind(require(name), ...)`.

3. **Keep the shape.** The proxy defines `name` and `length`, and for a
   constructor copies `prototype`, so `new` and `instanceof` still behave.
   `new.target` is handled with `Reflect.construct`.

4. **Dispatch.** Every call goes through `_invoke()`:

   | Decision | Behavior |
   | --- | --- |
   | `ALLOW` | `Reflect.apply(original, thisArg, args)` |
   | `DENY` | throw `CapabilityDenied` |
   | `ASK` | call `ask(capId, args)`; deny if false, missing, or throwing |
   | `SUBSTITUTE` | return a fake value, or call a fake function |

   A policy may be a fixed `Policy` or a function
   `(capability, args) -> Policy`.

5. **Audit without evaluating guest values.** `_emit()` logs the capability,
   decision, and argument count. It never calls `String(args)`, which could run
   guest code.

6. **Hook module loading.** `installLoader({ check, bindings })` replaces
   `Module._load` using captured `Reflect.apply`. It:
   - normalizes the `node:` prefix;
   - applies the require policy;
   - after the real load, binds configured attributes on that module
     (the Node equivalent of Python's post-import binding).

   In the demo, `require('zlib')` loads normally and then
   `zlib.deflateSync` is replaced.

7. **Seal and restore.** `seal()` blocks external `bind()` calls, while lazy
   loader bindings use `_bind(..., internal=true)`. `restore()` reverses the
   module hook and all bindings.

## What the demo shows

- `os.hostname()` — `SUBSTITUTE` returns `sandbox-host`.
- `fs.readFileSync('/tmp/symbol-wrapper-demo/hello.txt')` — `ALLOW`.
- `fs.readFileSync('/etc/hosts')` — `DENY`.
- `child_process.execSync('echo ...')` — `ASK` approved.
- `child_process.execSync('rm ...')` — `ASK` denied before execution.
- `zlib.deflateSync` — lazily bound by the loader hook, `DENY`.
- `require('net')`, `require('node:net')`, `require('module')` — `DENY`.
- `fs.readFile`, `fs.promises.readFile`, `spawnSync`, and `exec` — **not
  bound**, so they still run. These are deliberate demonstrations of the
  boundary.

## Covered vs. not covered

- Covered: the exact property after it has been replaced, reached through the
  original module object.
- Not covered automatically: sibling APIs (`fs.readFile`, `fs.promises`,
  `child_process.spawnSync`, `exec`); aliases captured before binding; direct
  `process.binding(...)`; `Module._extensions`; dynamic `import()`;
  `vm`/`Worker`; native addons; and anything that reaches the original through
  a different module or a pre-existing reference.

## Two Node-specific caveats

1. **The CommonJS loader reads the entry file with `fs.readFileSync`.**
   Since preload runs before the entry script, binding `fs.readFileSync`
   immediately would also block Node from loading `guest.js`. `preload.js`
   therefore allows exactly `process.argv[1]` through. This is a concrete
   example of why "bind a built-in" needs loader-aware exceptions.

2. **The main-module load is allowed by `installLoader`.** `--require` runs
   before the entry module, so `Module._load(..., isMain=true)` must be allowed.
   A guest could imitate that call. The require hook is a demonstration, not a
   security boundary.

## Lifting it into `js_runtime`

- Keep `_invoke(capId, thisArg, args)` as the single dispatch point.
- Keep the proxy factory independent of ZMQ; the runtime currently mixes
  `askPermission`, `callRemote`, and event polling into the addon.
- Replace local `ask`/`audit` with an IPC transport that has request ids,
  timeouts, and a host-side decision.
- Bind after `Module._load` returns, as the runtime's
  `interceptor_hook.js` does, but capture `Reflect.apply`/`Module._load` before
  guest code can monkeypatch them.
- Add explicit profiles: `compat` (guest may use the original) vs `security`
  (original only on the host, default deny).
- Do not treat the current fail-open unknown-`env_id` path as a policy result;
  a missing policy should be a deny in a security profile.
