"""VPO-Hook SDK（Python，运维期使用）。

用法：
    import vpoh
    m = vpoh.discover("my_pkg")          # -> manifest
    r = vpoh.generate(m)                 # -> hook plan + wrapper + sandbox
    vpoh.run(["python3", "app.py"])      # -> 退出码

SDK 不参与目标进程运行：它只做发现、生成配置/代码、编译。运行时由
`vpo-hook run --config ... --hook ...` 消费生成的产物。

其余 init/status/scan/log/grant/revoke/list/sign/chain 是 CLI 的薄封装。
"""

from __future__ import annotations

import ast
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import vpo_hook
except ImportError:  # 安装后的包：CLI 在 vpohook.cli
    import vpohook.cli as vpo_hook


MANIFEST_SCHEMA = "vpoh.manifest.v1"
HOOK_PLAN_SCHEMA = "vpoh.hook_plan.v1"
SANDBOX_SCHEMA = "vpoh.sandbox.v1"
NATIVE_EXTS = {".so", ".dylib", ".node"}
SCAN_SKIP = {
    "node_modules", ".venv", "venv", "__pycache__", "build", "dist",
    ".git", ".vpo", ".mypy_cache", ".pytest_cache",
}
DEFAULT_DENY_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.azure",
    "~/.config/gcloud",
    "~/.kube",
    "~/.npmrc",
    "~/.gitconfig",
    "~/.git-credentials",
    "~/.netrc",
    "~/.gnupg",
    "~/.local/share/keyrings",
    "~/.docker/config.json",
    "~/.config/google-chrome",
    "~/.config/microsoft-edge",
    "~/.mozilla/firefox",
)


def _main(args) -> int:
    return vpo_hook.main([str(a) for a in args])


def init() -> int:
    return _main(["init"])


def status() -> int:
    return _main(["status"])


def scan(path) -> dict:
    return vpo_hook.scan_capabilities(str(path))


def log(n: int = 20) -> int:
    return _main(["log", "-n", str(n)])


def grant(root, kind: str, value: str, *rest) -> int:
    return _main(["grant", "--root", str(root), kind, value, *[str(r) for r in rest]])


def revoke(root) -> int:
    return _main(["revoke", "--root", str(root)])


def list_grants() -> int:
    return _main(["list"])


def sign() -> int:
    return _main(["sign"])


def chain() -> int:
    return _main(["chain"])


def run(cmd, quiet: bool = True, hook: str | None = None, config: str | None = None) -> int:
    argv = ["run"]
    if quiet:
        argv.append("-q")
    if config:
        argv += ["--config", str(config)]
    if hook:
        argv += ["--hook", str(hook)]
    argv += [str(c) for c in cmd]
    return vpo_hook.main(argv)


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------
def _sorted_unique(values) -> list[str]:
    return sorted({str(v) for v in values if v})


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "pkg"


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_text_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o755)
    except OSError:
        pass


def _pkg_info(root: Path) -> dict:
    name = root.name
    version = None
    manager = None

    pj = root / "package.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                name = data.get("name") or name
                version = data.get("version") or version
                manager = "npm"
        except Exception:
            pass

    for cand in ("pyproject.toml", "setup.py", "setup.cfg"):
        f = root / cand
        if not f.exists():
            continue
        txt = f.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'name\s*=\s*["\']([^"\']+)', txt)
        if m:
            name = m.group(1)
        m = re.search(r'version\s*=\s*["\']([^"\']+)', txt)
        if m:
            version = m.group(1)
        manager = "pip" if manager is None else "mixed"
        break

    return {"name": name, "version": version, "manager": manager}


# ---------------------------------------------------------------------------
# native 符号：nm -D（Linux）/ nm -gU（macOS）
# ---------------------------------------------------------------------------
def _nm_symbols(path: Path) -> dict:
    nm = shutil.which("nm")
    if not nm:
        return {"exports": [], "undefined": []}

    darwin = platform.system() == "Darwin"

    def run(args: list[str]) -> list[str]:
        proc = subprocess.run([nm, *args], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return []
        found: list[str] = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            tok = parts[-1].split("@")[0]
            if darwin and tok.startswith("_"):
                tok = tok[1:]
            if tok:
                found.append(tok)
        return found

    if darwin:
        exports = run(["-gU", str(path)])
        undefined = run(["-u", str(path)])
    else:
        exports = run(["-D", "--defined-only", str(path)])
        undefined = run(["-D", "--undefined-only", str(path)])

    return {"exports": _sorted_unique(exports), "undefined": _sorted_unique(undefined)}


def _nm_undefined(path: Path) -> list[str]:
    return _nm_symbols(path)["undefined"]


# ---------------------------------------------------------------------------
# 静态扫描：Python / JS 明文 API
# ---------------------------------------------------------------------------
def _static_python(path: Path) -> dict:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {"functions": [], "classes": {}, "deps": []}

    functions: list[str] = []
    classes: dict[str, list[str]] = {}
    deps: list[str] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            methods = [
                item.name
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            classes[node.name] = _sorted_unique(methods)
        elif isinstance(node, ast.Import):
            deps.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            deps.append(node.module)

    return {
        "functions": _sorted_unique(functions),
        "classes": {k: _sorted_unique(v) for k, v in sorted(classes.items())},
        "deps": _sorted_unique(deps),
    }


def _brace_block(text: str, open_index: int) -> str:
    depth = 0
    for i in range(open_index, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:i]
    return text[open_index + 1:]


def _static_js(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"exports": [], "classes": {}, "deps": []}

    exports: set[str] = set()
    classes: dict[str, list[str]] = {}

    for m in re.finditer(r"(?:module\.exports|exports)\.([A-Za-z_$][\w$]*)\s*=", text):
        exports.add(m.group(1))
    for m in re.finditer(r"export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", text):
        exports.add(m.group(1))
    for m in re.finditer(r"export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)", text):
        exports.add(m.group(1))

    for m in re.finditer(r"module\.exports\s*=\s*\{", text):
        block = _brace_block(text, m.end() - 1)
        for key in re.findall(r"(?m)^\s*[\"']?([A-Za-z_$][\w$]*)[\"']?\s*:", block):
            exports.add(key)

    for m in re.finditer(r"\bclass\s+([A-Za-z_$][\w$]*)\s*(?:extends\s+[^{]+)?\{", text):
        name = m.group(1)
        block = _brace_block(text, m.end() - 1)
        methods: set[str] = set()
        for mm in re.finditer(
            r"(?m)^\s*(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?([A-Za-z_$][\w$]*)\s*\(",
            block,
        ):
            if mm.group(1) != "constructor":
                methods.add(mm.group(1))
        classes[name] = _sorted_unique(methods)
        exports.add(name)

    for m in re.finditer(r"export\s+class\s+([A-Za-z_$][\w$]*)", text):
        exports.add(m.group(1))

    deps = set(re.findall(r"require\(\s*[\"']([^\"']+)", text))
    deps.update(re.findall(r"from\s+[\"']([^\"']+)", text))

    return {
        "exports": _sorted_unique(exports),
        "classes": {k: _sorted_unique(v) for k, v in sorted(classes.items())},
        "deps": _sorted_unique(deps),
    }


# ---------------------------------------------------------------------------
# 动态反射（可选：--dynamic）
# ---------------------------------------------------------------------------
def _reflect_python(name: str, cwd: str | None) -> dict:
    code = (
        "import importlib, inspect, json, sys\n"
        "try:\n"
        "    m = importlib.import_module(sys.argv[1])\n"
        "except Exception as e:\n"
        "    print(json.dumps({'error': str(e)}))\n"
        "    raise SystemExit(0)\n"
        "attrs = [a for a in dir(m) if not a.startswith('_') and (\n"
        "    inspect.isclass(getattr(m, a)) or callable(getattr(m, a)))]\n"
        "classes = {}\n"
        "for n in attrs:\n"
        "    o = getattr(m, n)\n"
        "    if inspect.isclass(o):\n"
        "        ms = [x for x, _ in inspect.getmembers(\n"
        "            o, predicate=lambda v: inspect.isfunction(v) or inspect.ismethod(v)\n"
        "        ) if not x.startswith('_')]\n"
        "        classes[n] = sorted(set(ms))\n"
        "deps = [k for k in sys.modules if k and not k.startswith('_')]\n"
        "print(json.dumps({'attrs': attrs, 'classes': classes, 'deps': deps[:200]}))\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code, name],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except Exception:
        return {}
    try:
        return json.loads(proc.stdout.strip() or "{}")
    except Exception:
        return {}


def _reflect_js(target: str) -> dict:
    code = (
        "const m = require(process.argv[1]);\n"
        "const attrs = Object.keys(m).filter((k) => !k.startsWith('_'));\n"
        "const classes = {};\n"
        "for (const k of attrs) {\n"
        "  const v = m[k];\n"
        "  if (typeof v === 'function' && v.prototype) {\n"
        "    const ms = Object.getOwnPropertyNames(v.prototype)\n"
        "      .filter((x) => x !== 'constructor' && !x.startsWith('_'));\n"
        "    classes[k] = ms.sort();\n"
        "  }\n"
        "}\n"
        "const deps = Object.keys(require.cache).map((f) => {\n"
        "  const i = f.indexOf('node_modules');\n"
        "  if (i < 0) return f;\n"
        "  const rest = f.slice(i + 'node_modules'.length + 1);\n"
        "  const parts = rest.split('/');\n"
        "  return parts[0] === '@' ? parts.slice(0, 2).join('/') : parts[0];\n"
        "});\n"
        "console.log(JSON.stringify({ attrs, classes, deps }));\n"
    )
    try:
        proc = subprocess.run(
            ["node", "-e", code, target],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except Exception:
        return {}
    try:
        return json.loads(proc.stdout.strip() or "{}")
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# manifest / hook plan / sandbox plan
# ---------------------------------------------------------------------------
def _sort_classes(classes: dict[str, list[str]]) -> dict[str, list[str]]:
    return {k: _sorted_unique(v) for k, v in sorted(classes.items())}


def _placeholder() -> dict:
    return {
        "fake_symbols": {"status": "placeholder", "generated": []},
        "rawcalls": {"status": "placeholder", "syscalls": []},
        "native_signatures": {
            "status": "placeholder",
            "source": "nm",
            "note": "parameter types unavailable without DWARF/Clang AST",
        },
    }


def _class_methods(obj) -> list[str]:
    import inspect

    return _sorted_unique(
        name
        for name, value in inspect.getmembers(
            obj, predicate=lambda v: inspect.isfunction(v) or inspect.ismethod(v)
        )
        if not name.startswith("_")
    )


def _discover_object(obj) -> dict:
    """反射已经加载到当前进程里的 module / class / instance。"""
    import inspect

    label = getattr(obj, "__name__", None) or type(obj).__name__
    functions: set[str] = set()
    classes: dict[str, list[str]] = {}

    if inspect.ismodule(obj):
        members = [(name, getattr(obj, name)) for name in dir(obj) if not name.startswith("_")]
    elif inspect.isclass(obj):
        classes[label] = _class_methods(obj)
        members = [(label, obj)]
    else:
        classes[type(obj).__name__] = _class_methods(type(obj))
        members = [(name, getattr(obj, name)) for name in dir(obj) if not name.startswith("_")]

    for name, value in members:
        if inspect.isclass(value):
            classes[value.__name__] = _class_methods(value)
        elif callable(value):
            functions.add(name)

    apis = set(functions)
    apis.update(classes.keys())
    for cls, methods in classes.items():
        apis.update(f"{cls}.{method}" for method in methods)

    return {
        "schema": MANIFEST_SCHEMA,
        "target": label,
        "runtime": "python",
        "pkg": {"name": label, "version": None, "manager": "pip", "root": None},
        "apis": {"python": _sorted_unique(apis), "js": []},
        "classes": {"python": _sort_classes(classes), "js": {}},
        "modules": {"python": [], "js": []},
        "native": [],
        "symbols": [],
        "exports": [],
        "deps": [],
        "placeholder": _placeholder(),
    }


def discover(target, dynamic: bool = False) -> dict:
    if isinstance(target, (list, tuple)):
        raise TypeError(
            "command discovery is not implemented yet; pass an executable path or package path"
        )
    if isinstance(target, int) or (
        hasattr(target, "pid") and hasattr(target, "poll")
    ):
        raise TypeError(
            "attaching to a running process is not supported; pass a command spec or package path"
        )
    if not isinstance(target, (str, Path)):
        return _discover_object(target)

    t = str(target)
    p = Path(t)

    py_files: list[str] = []
    js_files: list[str] = []
    py_functions: set[str] = set()
    py_classes: dict[str, set[str]] = {}
    js_exports: set[str] = set()
    js_classes: dict[str, set[str]] = {}
    deps: set[str] = set()
    native: list[dict] = []
    symbols: set[str] = set()
    exports: set[str] = set()

    def merge_py(parsed: dict) -> None:
        py_functions.update(parsed.get("functions", []))
        for cls, methods in parsed.get("classes", {}).items():
            py_classes.setdefault(cls, set()).update(methods)
        deps.update(parsed.get("deps", []))

    def merge_js(parsed: dict) -> None:
        js_exports.update(parsed.get("exports", []))
        for cls, methods in parsed.get("classes", {}).items():
            js_classes.setdefault(cls, set()).update(methods)
        deps.update(parsed.get("deps", []))

    pkg: dict = {"name": p.stem if p.exists() else t, "version": None, "manager": None}
    runtime = "unknown"

    if p.is_dir():
        root = p.resolve()
        pkg = _pkg_info(root)
        py_dynamic_attrs: set[str] = set()
        js_dynamic_attrs: set[str] = set()

        for f in sorted(root.rglob("*")):
            if not f.is_file():
                continue
            try:
                rel = f.relative_to(root).as_posix()
            except ValueError:
                rel = str(f)
            if any(part in SCAN_SKIP for part in Path(rel).parts):
                continue
            suffix = f.suffix.lower()
            if suffix == ".py":
                py_files.append(rel)
                merge_py(_static_python(f))
            elif suffix in (".js", ".mjs", ".cjs"):
                js_files.append(rel)
                merge_js(_static_js(f))
            elif suffix in NATIVE_EXTS:
                found = _nm_symbols(f)
                native.append(
                    {
                        "path": rel,
                        "exports": found["exports"],
                        "undefined": found["undefined"],
                    }
                )
                exports.update(found["exports"])
                symbols.update(found["undefined"])

        if dynamic and py_files:
            r = _reflect_python(pkg.get("name") or "", str(root.parent))
            if r:
                py_dynamic_attrs.update(r.get("attrs", []))
                for cls, methods in r.get("classes", {}).items():
                    py_classes.setdefault(cls, set()).update(methods)
                deps.update(r.get("deps", []))
        if dynamic and js_files:
            r = _reflect_js(str(root))
            if r:
                js_dynamic_attrs.update(r.get("attrs", []))
                for cls, methods in r.get("classes", {}).items():
                    js_classes.setdefault(cls, set()).update(methods)
                deps.update(r.get("deps", []))

        pkg["root"] = str(root)
        if py_files and not pkg.get("manager"):
            pkg["manager"] = "pip"
        if js_files:
            if not pkg.get("manager"):
                pkg["manager"] = "npm"
            elif py_files and pkg.get("manager") != "mixed":
                pkg["manager"] = "mixed"

        if py_files or js_files:
            runtime = "mixed" if py_files and js_files else ("python" if py_files else "js")
        elif native:
            runtime = "native"

        for attrs in (py_dynamic_attrs, js_dynamic_attrs):
            if attrs:
                if attrs is py_dynamic_attrs:
                    py_functions.update(attrs)
                else:
                    js_exports.update(attrs)

    elif p.is_file():
        suffix = p.suffix.lower()
        pkg = {"name": p.stem, "version": None, "manager": None, "root": str(p.parent)}
        if suffix == ".py":
            py_files.append(p.name)
            merge_py(_static_python(p))
            pkg["manager"] = "pip"
            runtime = "python"
        elif suffix in (".js", ".mjs", ".cjs"):
            js_files.append(p.name)
            merge_js(_static_js(p))
            pkg["manager"] = "npm"
            runtime = "js"
        elif suffix in NATIVE_EXTS:
            found = _nm_symbols(p)
            native.append({"path": p.name, "exports": found["exports"], "undefined": found["undefined"]})
            exports.update(found["exports"])
            symbols.update(found["undefined"])
            runtime = "native"
    else:
        r = _reflect_python(t, None)
        pkg = {"name": t, "version": None, "manager": "pip"}
        py_functions.update(r.get("attrs", []))
        for cls, methods in r.get("classes", {}).items():
            py_classes.setdefault(cls, set()).update(methods)
        deps.update(r.get("deps", []))
        runtime = "python"

    py_classes_sorted = _sort_classes({k: sorted(v) for k, v in py_classes.items()})
    js_classes_sorted = _sort_classes({k: sorted(v) for k, v in js_classes.items()})

    py_apis = set(py_functions)
    for cls, methods in py_classes_sorted.items():
        py_apis.update(f"{cls}.{method}" for method in methods)
    js_apis = set(js_exports)
    for cls, methods in js_classes_sorted.items():
        js_apis.update(f"{cls}.{method}" for method in methods)

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "target": t,
        "runtime": runtime,
        "pkg": pkg,
        "apis": {
            "python": _sorted_unique(py_apis),
            "js": _sorted_unique(js_apis),
        },
        "classes": {"python": py_classes_sorted, "js": js_classes_sorted},
        "modules": {"python": _sorted_unique(py_files), "js": _sorted_unique(js_files)},
        "native": sorted(native, key=lambda item: item["path"]),
        "symbols": _sorted_unique(symbols),
        "exports": _sorted_unique(exports),
        "deps": _sorted_unique(deps),
        "placeholder": _placeholder(),
    }
    return manifest


def _normalize_manifest(manifest: dict) -> dict:
    m = json.loads(json.dumps(manifest))
    m.setdefault("schema", MANIFEST_SCHEMA)
    m.setdefault("target", m.get("pkg", {}).get("name") or "unknown")
    m.setdefault("runtime", "unknown")
    m.setdefault("pkg", {})
    m.setdefault("apis", {"python": [], "js": []})
    m.setdefault("classes", {"python": {}, "js": {}})
    m.setdefault("modules", {"python": [], "js": []})
    m.setdefault("native", [])
    m.setdefault("symbols", [])
    m.setdefault("exports", [])
    m.setdefault("deps", [])
    m.setdefault("placeholder", _placeholder())
    for lang in ("python", "js"):
        m["apis"].setdefault(lang, [])
        m["apis"][lang] = _sorted_unique(m["apis"][lang])
        m["classes"].setdefault(lang, {})
        m["classes"][lang] = _sort_classes(m["classes"][lang])
        m["modules"].setdefault(lang, [])
        m["modules"][lang] = _sorted_unique(m["modules"][lang])
    m["symbols"] = _sorted_unique(m["symbols"])
    m["exports"] = _sorted_unique(m["exports"])
    m["deps"] = _sorted_unique(m["deps"])
    return m


def _sandbox_plan(manifest: dict) -> dict:
    pkg = manifest.get("pkg", {})
    return {
        "schema": SANDBOX_SCHEMA,
        "backend": "auto",
        "fs": {
            "env_root": pkg.get("root") or "auto",
            "deny": list(DEFAULT_DENY_PATHS),
            "extra_read": [],
            "extra_write": [],
        },
        "network": {"mode": "off", "allowlist": [], "blocklist": []},
        "process": {"fork": True, "exec": "off", "exec_allow": []},
        "native": {"cross_package": "deny", "same_package": "allow"},
        "children": "inherit",
    }


def _simple_config_yaml(manifest: dict) -> str:
    pkg = manifest.get("pkg", {})
    name = json.dumps(str(pkg.get("name") or "app"), ensure_ascii=False)
    env = json.dumps(pkg.get("root") or "auto", ensure_ascii=False)
    return (
        "version: 1\n"
        "profile: simple\n"
        f"name: {name}\n"
        f"env: {env}\n"
        "\n"
        "permissions:\n"
        "  files:\n"
        "    extra_read: []\n"
        "    extra_write: []\n"
        "  network:\n"
        "    mode: off\n"
        "    allowlist: []\n"
        "    blocklist: []\n"
        "  process:\n"
        "    fork: true\n"
        "    exec: off\n"
        "    exec_allow: []\n"
        "\n"
        "inbound:\n"
        "  inspect: true\n"
        "  action: audit\n"
        "\n"
        "sources:\n"
        "  allow: []\n"
        "  deny: []\n"
        "\n"
        "sensitive_files: []\n"
        "audit: on\n"
    )


def generate(manifest: dict, out_dir: str | None = None, interactive: bool = False) -> dict:
    manifest = _normalize_manifest(manifest)
    pkg = manifest.get("pkg", {}).get("name") or "pkg"
    safe = _safe_name(str(pkg))
    out = Path(out_dir) if out_dir else (
        Path(manifest.get("pkg", {}).get("root") or Path.cwd()) / ".vpo"
    )
    out.mkdir(parents=True, exist_ok=True)

    sig = json.loads((vpo_hook.HOOK_DIR / "signatures.json").read_text(encoding="utf-8"))
    funcs = sig["functions"]
    alias_map: dict[str, str] = {}
    for name, meta in funcs.items():
        for a in meta.get("linux_aliases", []):
            alias_map[a] = name

    subset = set()
    for s in manifest.get("symbols", []):
        key = alias_map.get(s, s)
        if key in funcs:
            subset.add(key)
    subset = sorted(subset)

    _write_json(out / "manifest.json", manifest)

    sandbox = _sandbox_plan(manifest)
    _write_json(out / "sandbox.json", sandbox)

    hook_plan = {
        "schema": HOOK_PLAN_SCHEMA,
        "target": manifest.get("target"),
        "pkg": manifest.get("pkg", {}),
        "plaintext": {
            "python": manifest.get("apis", {}).get("python", []),
            "js": manifest.get("apis", {}).get("js", []),
            "classes": manifest.get("classes", {}),
            "modules": manifest.get("modules", {}),
        },
        "binary": {
            "libc": subset,
            "native": {
                "exports": manifest.get("exports", []),
                "fake_symbols": {"status": "placeholder", "generated": []},
                "signatures": {
                    "status": "placeholder",
                    "source": "nm",
                    "note": "parameter types unavailable without DWARF/Clang AST",
                },
            },
        },
        "sandbox": sandbox,
        "rawcalls": {"status": "placeholder", "syscalls": []},
        "artifacts": {
            "config": "config.yaml",
            "launch": "launch.sh",
            "sandbox": "sandbox.json",
        },
    }
    _write_json(out / "hook_plan.json", hook_plan)

    (out / "policy.yaml").write_text(
        "# complex policy (draft)\n"
        f"package: {pkg}\n"
        f"functions: [{', '.join(subset)}]\n",
        encoding="utf-8",
    )
    (out / "config.yaml").write_text(_simple_config_yaml(manifest), encoding="utf-8")

    so = None
    if subset:
        gen = vpo_hook.HOOK_DIR / "gen_wrappers.py"
        wrapper = out / "wrapper.c"
        plat = vpo_hook.detect_platform() or "linux"
        gen_plat = "linux" if plat == "linux" else "darwin"
        subprocess.run(
            [
                sys.executable, str(gen),
                str(vpo_hook.HOOK_DIR / "signatures.json"),
                "-o", str(wrapper),
                "-p", gen_plat,
                "--only", ",".join(subset),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        cc = vpo_hook.find_cc()
        if cc:
            ext = ".dylib" if plat == "darwin" else ".so"
            so = out / f"libvpo_{safe}{ext}"
            if plat == "darwin":
                cmd = [
                    cc, "-dynamiclib",
                    "-I", str(vpo_hook.HOOK_DIR),
                    "-o", str(so),
                    str(wrapper),
                    str(vpo_hook.HOOK_DIR / "policy.c"),
                ]
            else:
                cmd = [
                    cc, "-shared", "-fPIC",
                    "-I", str(vpo_hook.HOOK_DIR),
                    "-o", str(so),
                    str(wrapper),
                    str(vpo_hook.HOOK_DIR / "policy.c"),
                    "-ldl",
                ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    hook_arg = f' --hook "$HERE/{so.name}"' if so else ""
    launch = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        f'exec vpo-hook run -q --config "$HERE/config.yaml"{hook_arg} "$@"\n'
    )
    _write_text_exec(out / "launch.sh", launch)

    return {
        "subset": subset,
        "out": str(out),
        "so": str(so) if so else None,
        "manifest": str(out / "manifest.json"),
        "hook_plan": str(out / "hook_plan.json"),
        "sandbox": str(out / "sandbox.json"),
        "config": str(out / "config.yaml"),
        "launch": str(out / "launch.sh"),
    }
