"""VPO-Hook SDK（Python）。

用法：
    import vpoh
    vpoh.discover("my_pkg")          # -> manifest
    vpoh.generate(manifest)          # -> {subset, out, so}
    vpoh.run(["python3", "app.py"])  # -> 退出码

其余 init/status/scan/log/grant/revoke/list/sign/chain 是 CLI 的薄封装。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import vpo_hook


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


def run(cmd, quiet: bool = True) -> int:
    argv = ["run"] + (["-q"] if quiet else []) + [str(c) for c in cmd]
    return vpo_hook.main(argv)


# ---------------------------------------------------------------------------
# discover / generate（复杂安全组 SDK）
# ---------------------------------------------------------------------------
def _reflect_python(name: str, cwd: str | None) -> dict:
    code = (
        "import importlib, json, sys\n"
        "try:\n"
        "    m = importlib.import_module(sys.argv[1])\n"
        "except Exception as e:\n"
        "    print(json.dumps({'error': str(e)}))\n"
        "    raise SystemExit(0)\n"
        "attrs = [a for a in dir(m) if not a.startswith('_')]\n"
        "deps = [k for k in sys.modules if k and not k.startswith('_')]\n"
        "print(json.dumps({'attrs': attrs, 'deps': deps[:200]}))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, name],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(proc.stdout.strip() or "{}")
    except Exception:
        return {}


def _pkg_name(root: Path) -> str:
    for cand in ("pyproject.toml", "setup.py", "setup.cfg"):
        f = root / cand
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'name\s*=\s*["\']([^"\']+)', txt)
            if m:
                return m.group(1)
    return root.name


def discover(target) -> dict:
    t = str(target)
    p = Path(t)
    manifest: dict = {
        "target": t,
        "pkg": {},
        "symbols": [],
        "apis": {"python": [], "js": []},
        "deps": [],
    }
    symbols: list[str] = []
    native_exts = {".so", ".dylib", ".node"}

    if p.is_dir():
        root = p.resolve()
        manifest["pkg"]["root"] = str(root)
        name = _pkg_name(root)
        manifest["pkg"]["name"] = name
        for f in root.rglob("*"):
            if f.suffix in native_exts:
                symbols.extend(vpo_hook._nm_undefined(f))
        if name:
            r = _reflect_python(name, str(root))
            manifest["apis"]["python"] = r.get("attrs", [])
            manifest["deps"] = r.get("deps", [])
    elif not p.exists():
        manifest["pkg"]["name"] = t
        r = _reflect_python(t, None)
        manifest["apis"]["python"] = r.get("attrs", [])
        manifest["deps"] = r.get("deps", [])

    manifest["symbols"] = sorted(set(symbols))
    return manifest


def generate(manifest: dict, out_dir: str | None = None, interactive: bool = False) -> dict:
    pkg = manifest.get("pkg", {}).get("name") or "pkg"
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

    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out / "policy.yaml").write_text(
        "# complex policy (draft)\n"
        f"package: {pkg}\n"
        f"functions: [{', '.join(subset)}]\n",
        encoding="utf-8",
    )

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
        )
        cc = vpo_hook.find_cc()
        if cc:
            so = out / f"libvpo_{pkg}.so"
            cmd = [
                cc, "-shared", "-fPIC",
                "-I", str(vpo_hook.HOOK_DIR),
                "-o", str(so),
                str(wrapper),
                str(vpo_hook.HOOK_DIR / "policy.c"),
            ]
            if plat == "linux":
                cmd.append("-ldl")
            subprocess.run(cmd, check=True)

    return {"subset": subset, "out": str(out), "so": str(so) if so else None}
