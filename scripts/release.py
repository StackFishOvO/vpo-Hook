#!/usr/bin/env python3
"""构建并校验 release/ 快照。

用法:
    python3 scripts/release.py --dry-run
    python3 scripts/release.py
    python3 scripts/release.py --check

设计:
    - 源目录: py/、js/
    - 目标: release/py/vpohook/、release/js/
    - 只做文件同步、路径替换、一致性校验、版本号同步
    - 不做 npm publish / pip upload，不编译 C 库，不跑测试
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"

# (source, target, transform)
# transform: None | "python_launcher" | "js_launcher"
MAPPINGS: list[tuple[str, str, str | None]] = [
    ("py/vpo_hook.py", "release/py/vpohook/cli.py", "python_launcher"),
    ("py/vpoh.py", "release/py/vpoh.py", None),
    ("py/obj_hook", "release/py/vpohook/obj_hook", None),
    ("py/plaintext", "release/py/vpohook/plaintext", None),
    ("js/plaintext", "release/py/vpohook/js_plaintext", None),
    ("js/vpo_hook.js", "release/js/vpo_hook.js", "js_launcher"),
    ("js/vpoh.js", "release/js/vpoh.js", None),
    ("js/obj_hook", "release/js/obj_hook", None),
    ("js/plaintext", "release/js/plaintext", None),
    ("py/plaintext", "release/js/py_plaintext", None),
]

# 这些目录由 release.py 完全接管；里面的非预期文件会被删除。
MANAGED_ROOTS = {
    "release/py/vpohook/obj_hook",
    "release/py/vpohook/plaintext",
    "release/py/vpohook/js_plaintext",
    "release/js/obj_hook",
    "release/js/plaintext",
    "release/js/py_plaintext",
}

EXCLUDE_DIRS = {
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    "*.egg-info",
}

EXCLUDE_NAMES = {
    ".DS_Store",
    "wrapper.c",
    "libvpo_hook.so",
    "libvpo_hook.dylib",
}

EXCLUDE_SUFFIXES = {".pyc", ".pyo"}

PY_PRELOAD_OLD = 'preload = HERE.parent / "js" / "plaintext" / "preload.js"'
PY_PRELOAD_NEW = 'preload = HERE / "js_plaintext" / "preload.js"'

JS_PLAINTEXT_OLD = (
    "const PY_PLAINTEXT = path.join(path.dirname(HERE), 'py', 'plaintext'); // ../py/plaintext"
)
JS_PLAINTEXT_NEW = "const PY_PLAINTEXT = path.join(HERE, 'py_plaintext');"

CONSISTENCY_PAIRS = [
    ("release/js/obj_hook/policy.c", "release/py/vpohook/obj_hook/policy.c"),
    ("release/js/obj_hook/signatures.json", "release/py/vpohook/obj_hook/signatures.json"),
    ("release/js/obj_hook/vpo_hook.h", "release/py/vpohook/obj_hook/vpo_hook.h"),
    ("release/js/obj_hook/config.yaml", "release/py/vpohook/obj_hook/config.yaml"),
    ("release/js/plaintext/interpose.js", "release/py/vpohook/js_plaintext/interpose.js"),
    ("release/js/plaintext/preload.js", "release/py/vpohook/js_plaintext/preload.js"),
    ("release/js/py_plaintext/interpose.py", "release/py/vpohook/plaintext/interpose.py"),
    (
        "release/js/py_plaintext/sitecustomize.py",
        "release/py/vpohook/plaintext/sitecustomize.py",
    ),
]


class ReleaseError(Exception):
    pass


def excluded(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return True
    if path.suffix in EXCLUDE_SUFFIXES:
        return True
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
        if part.endswith(".egg-info"):
            return True
    return False


def transform(source: Path, data: bytes) -> tuple[bytes, int]:
    rel = source.relative_to(ROOT).as_posix()
    if rel == "py/vpo_hook.py":
        text = data.decode("utf-8")
        count = text.count(PY_PRELOAD_OLD)
        if count != 1:
            raise ReleaseError(
                f"{rel}: 预期 1 处 preload 路径，实际 {count} 处"
            )
        return text.replace(PY_PRELOAD_OLD, PY_PRELOAD_NEW).encode("utf-8"), 1
    if rel == "js/vpo_hook.js":
        text = data.decode("utf-8")
        count = text.count(JS_PLAINTEXT_OLD)
        if count != 1:
            raise ReleaseError(
                f"{rel}: 预期 1 处 PY_PLAINTEXT 路径，实际 {count} 处"
            )
        return text.replace(JS_PLAINTEXT_OLD, JS_PLAINTEXT_NEW).encode("utf-8"), 1
    return data, 0


def expected_files() -> tuple[dict[Path, bytes], int]:
    expected: dict[Path, bytes] = {}
    replacements = 0

    for src_rel, dst_rel, _kind in MAPPINGS:
        src = ROOT / src_rel
        dst = ROOT / dst_rel
        if not src.exists():
            raise ReleaseError(f"源不存在: {src_rel}")

        if src.is_dir():
            for file in sorted(src.rglob("*")):
                if not file.is_file() or excluded(file):
                    continue
                target = dst / file.relative_to(src)
                expected[target] = file.read_bytes()
        else:
            if excluded(src):
                continue
            data, n = transform(src, src.read_bytes())
            expected[dst] = data
            replacements += n

    return expected, replacements


def read_version() -> str:
    if not VERSION_FILE.exists():
        raise ReleaseError("缺少 VERSION 文件")
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ReleaseError(f"VERSION 不是合法版本号: {version!r}")
    return version


def version_targets() -> list[tuple[Path, str]]:
    return [
        (ROOT / "release/py/setup.py", "setup.py"),
        (ROOT / "release/js/package.json", "package.json"),
    ]


def sync_versions(version: str, dry_run: bool, check: bool) -> list[str]:
    changes: list[str] = []
    for path, kind in version_targets():
        if not path.exists():
            raise ReleaseError(f"缺少版本文件: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")

        if kind == "setup.py":
            pattern = r'(version\s*=\s*")[^"]+(")'
        else:
            pattern = r'("version"\s*:\s*")[^"]+(")'

        matches = re.findall(pattern, text)
        if len(matches) != 1:
            raise ReleaseError(
                f"{path.relative_to(ROOT)}: 预期 1 处 version，实际 {len(matches)} 处"
            )

        new_text = re.sub(pattern, rf"\g<1>{version}\g<2>", text, count=1)
        if new_text != text:
            changes.append(str(path.relative_to(ROOT)))
            if not dry_run and not check:
                path.write_text(new_text, encoding="utf-8")

    return changes


def check_versions() -> None:
    version = read_version()
    for path, kind in version_targets():
        if not path.exists():
            raise ReleaseError(f"缺少版本文件: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        if kind == "setup.py":
            m = re.search(r'version\s*=\s*"([^"]+)"', text)
        else:
            m = re.search(r'"version"\s*:\s*"([^"]+)"', text)
        if not m:
            raise ReleaseError(f"{path.relative_to(ROOT)}: 找不到 version")
        if m.group(1) != version:
            raise ReleaseError(
                f"{path.relative_to(ROOT)}: version={m.group(1)} != VERSION={version}"
            )


def check_consistency() -> None:
    for left_rel, right_rel in CONSISTENCY_PAIRS:
        left = ROOT / left_rel
        right = ROOT / right_rel
        if not left.exists() or not right.exists():
            raise ReleaseError(f"缺少一致性文件: {left_rel} / {right_rel}")
        if left.read_bytes() != right.read_bytes():
            raise ReleaseError(f"不一致: {left_rel} != {right_rel}")

    for root_rel in ["release/py/vpohook/plaintext", "release/js/py_plaintext"]:
        root = ROOT / root_rel
        if root.exists() and any(p.name == "__pycache__" for p in root.rglob("*")):
            raise ReleaseError(f"{root_rel} 下不应有 __pycache__")


def check_expected(expected: dict[Path, bytes]) -> None:
    for target, data in expected.items():
        if not target.exists():
            raise ReleaseError(f"缺少文件: {target.relative_to(ROOT)}")
        if target.read_bytes() != data:
            raise ReleaseError(f"内容不一致: {target.relative_to(ROOT)}")

    for root_rel in sorted(MANAGED_ROOTS):
        root = ROOT / root_rel
        if not root.exists():
            continue
        for file in sorted(root.rglob("*")):
            if not file.is_file():
                continue
            if excluded(file):
                raise ReleaseError(f"release 不应包含构建产物/缓存: {file.relative_to(ROOT)}")
            if file not in expected:
                raise ReleaseError(f"多余文件: {file.relative_to(ROOT)}")


def prune_managed_roots(expected: dict[Path, bytes], dry_run: bool) -> int:
    removed = 0
    for root_rel in sorted(MANAGED_ROOTS):
        root = ROOT / root_rel
        if not root.exists():
            continue
        for file in sorted(root.rglob("*"), reverse=True):
            if not file.is_file():
                continue
            if file in expected:
                continue
            if excluded(file):
                # 构建产物/缓存也应该从 release 清除，避免被打包。
                pass
            removed += 1
            if not dry_run:
                file.unlink()
        if not dry_run:
            for directory in sorted(root.rglob("*"), reverse=True):
                if directory.is_dir() and not any(directory.iterdir()):
                    directory.rmdir()
    return removed


def write_expected(expected: dict[Path, bytes], dry_run: bool) -> int:
    written = 0
    for target, data in sorted(expected.items()):
        if target.exists() and target.read_bytes() == data:
            continue
        written += 1
        if dry_run:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return written


def cmd_check() -> int:
    version = read_version()
    expected, replacements = expected_files()
    check_expected(expected)
    check_consistency()
    check_versions()
    print(
        f"release check: OK ({len(expected)} 个文件, "
        f"{replacements} 处路径替换, VERSION={version})"
    )
    return 0


def cmd_build(dry_run: bool) -> int:
    version = read_version()
    expected, replacements = expected_files()

    if dry_run:
        for target in sorted(expected):
            print(f"[dry-run] {target.relative_to(ROOT)}")
    written = write_expected(expected, dry_run)
    removed = prune_managed_roots(expected, dry_run)
    version_changes = sync_versions(version, dry_run=dry_run, check=False)

    if not dry_run:
        check_expected(expected)
        check_consistency()
        check_versions()

    prefix = "会" if dry_run else "已"
    print(
        f"release {prefix}同步 {len(expected)} 个文件 "
        f"（写入 {written} 个，删除 {removed} 个），"
        f"{replacements} 处路径替换，VERSION={version}"
    )
    if version_changes:
        print(f"{prefix}更新版本号: {', '.join(version_changes)}")
    if not dry_run:
        print("release 一致性校验通过")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建/校验 VPO-Hook release/ 快照")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="只打印，不写文件")
    group.add_argument("--check", action="store_true", help="只做一致性校验，不写文件")
    args = parser.parse_args(argv)

    try:
        if args.check:
            return cmd_check()
        return cmd_build(dry_run=args.dry_run)
    except ReleaseError as exc:
        print(f"[release] 失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
