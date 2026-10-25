#!/usr/bin/env python3
"""
vpo-hook 启动器（Phase 4，Python 版）。

职责：
  init   生成默认配置 + 按配置生成 wrapper + 调用本机编译器编译 hook 库 + 自检
  run    读配置 -> 展开环境变量 -> 注入 hook 库 -> exec 目标进程（处理 shim）
  status 显示当前状态

设计要点：
  - 用户侧编译：hook 库在用户机器上 init 时用本机 clang 现场编译，适配本机 libc/编译器。
  - shim 处理：exec 目标进程时跳过 pyenv/nvm 等 shim，用真实二进制路径，否则
    DYLD_INSERT_LIBRARIES 会被 shim 剥离（已实测）。
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
HOOK_DIR = HERE / "obj_hook"
CONFIG_DIR = Path.home() / ".vpo-hook"
CONFIG_PATH = CONFIG_DIR / "config.yaml"
TEMPLATE_CONFIG = HOOK_DIR / "config.yaml"

# 已知会剥离 LD_PRELOAD / DYLD_INSERT_LIBRARIES 的版本管理器 shim 目录。
# 注意：只能匹配 shims 目录本身，不能匹配 /.pyenv/ 整棵子树，否则会误伤
# ~/.pyenv/versions/3.11/bin/python3 这类真实二进制。
SHIM_DIR_MARKERS = ("/shims/", "/.asdf/shims/", "/.rbenv/shims/", "/.nodenv/shims/")


# ---------------------------------------------------------------------------
# 平台与编译器
# ---------------------------------------------------------------------------
def detect_platform() -> str | None:
    s = platform.system()
    if s == "Darwin":
        return "darwin"
    if s == "Linux":
        return "linux"
    return None


def find_cc() -> str | None:
    for cc in ("clang", "cc", "gcc"):
        if shutil.which(cc):
            return cc
    return None


# ---------------------------------------------------------------------------
# 构建 hook 库
# ---------------------------------------------------------------------------
def build_hook() -> Path:
    """生成 wrapper.c 并调用本机编译器编译成 hook 库，返回库路径。"""
    plat = detect_platform()
    if plat is None:
        raise SystemExit(f"[vpo-hook] 不支持的平台: {platform.system()}（仅支持 macOS / Linux）")

    cc = find_cc()
    if cc is None:
        raise SystemExit("[vpo-hook] 未找到 C 编译器（需要 clang/gcc/cc），请先安装")

    gen = HOOK_DIR / "gen_wrappers.py"
    sig = HOOK_DIR / "signatures.json"
    wrapper = HOOK_DIR / "wrapper.c"
    policy = HOOK_DIR / "policy.c"

    # 1. 生成 wrapper.c（按平台）
    gen_platform = "linux" if plat == "linux" else "darwin"
    subprocess.run(
        [sys.executable, str(gen), str(sig), "-o", str(wrapper), "-p", gen_platform],
        check=True,
        cwd=str(HOOK_DIR),
    )

    # 2. 编译
    if plat == "darwin":
        out = HOOK_DIR / "libvpo_hook.dylib"
        cmd = [cc, "-dynamiclib", "-o", str(out), str(wrapper), str(policy)]
    else:  # linux
        out = HOOK_DIR / "libvpo_hook.so"
        cmd = [cc, "-shared", "-fPIC", "-o", str(out), str(wrapper), str(policy), "-ldl"]

    subprocess.run(cmd, check=True, cwd=str(HOOK_DIR))
    return out


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
def cmd_init(_args: argparse.Namespace) -> int:
    print(f"[vpo-hook] 平台检测: {platform.system()} {platform.machine()}")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        shutil.copyfile(TEMPLATE_CONFIG, CONFIG_PATH)
        print(f"[vpo-hook] 已生成默认配置: {CONFIG_PATH}")
    else:
        print(f"[vpo-hook] 配置已存在: {CONFIG_PATH}")

    # 复制蜜罐运维脚本模板（明文版，用户可编辑）
    honeypot_script = CONFIG_DIR / "honeypot.py"
    if not honeypot_script.exists():
        shutil.copyfile(HOOK_DIR / "honeypot.py", honeypot_script)
        print(f"[vpo-hook] 已生成蜜罐脚本: {honeypot_script}")

    lib = build_hook()
    print(f"[vpo-hook] hook 库已编译: {lib}")

    # 自检：确认产物存在且可加载
    if lib.exists():
        print("[vpo-hook] 自检通过")
    else:
        print("[vpo-hook] 自检失败：hook 库未生成", file=sys.stderr)
        return 1
    return 0


def parse_deny_paths(text: str) -> list[str]:
    """从 config.yaml 文本里提取 deny_paths 列表（极简解析，避免引入 YAML 依赖）。"""
    paths: list[str] = []
    in_deny = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("deny_paths:"):
            in_deny = True
            continue
        if in_deny:
            if stripped.startswith("- "):
                p = stripped[2:].strip().strip('"').strip("'")
                if p:
                    paths.append(p)
            elif stripped and not stripped.startswith("-"):
                # 遇到非列表项，deny_paths 结束
                in_deny = False
    return paths


def parse_yaml_list(text: str, key: str) -> list[str]:
    """从 config.yaml 提取 key 下的 YAML 列表（如 allow_network / high_risk_markers）。"""
    result: list[str] = []
    in_section = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(f"{key}:"):
            in_section = True
            continue
        if in_section:
            if s.startswith("- "):
                result.append(s[2:].strip().strip('"').strip("'"))
            elif s and not s.startswith("-"):
                in_section = False
    return result


def parse_honeypot_map(text: str) -> dict[str, str]:
    """从 config.yaml 提取 honeypot_map：{deny路径: 蜜罐路径}（极简解析）。"""
    result: dict[str, str] = {}
    in_map = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("honeypot_map:"):
            in_map = True
            continue
        if in_map:
            if s.startswith('"') or s.startswith("'"):
                if ":" in s:
                    key, _, value = s.partition(":")
                    key = key.strip().strip('"').strip("'")
                    value = value.strip().strip('"').strip("'")
                    if key and value:
                        result[key] = value
            elif s and not s.startswith((" ", "\t")):
                in_map = False
    return result


def expand_home(p: str) -> str:
    if p == "~":
        return str(Path.home())
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p


def parse_audit(text: str, lang: str | None) -> tuple[bool, str, list[str]]:
    """解析 audit 配置，返回 (enabled, log路径, classes列表)。"""
    enabled = False
    log = ""
    classes: list[str] = []
    in_audit = False
    in_classes = False
    in_lang = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("audit:"):
            in_audit = True
            continue
        if not in_audit:
            continue
        if line and not line.startswith((" ", "\t")) and s:
            in_audit = False
            continue
        if s.startswith("enabled:"):
            value = s.split(":", 1)[1].split("#", 1)[0].strip().strip('"').strip("'").lower()
            enabled = value in ("true", "yes", "on", "1")
        elif s.startswith("log:"):
            log = s.split(":", 1)[1].split("#", 1)[0].strip().strip('"').strip("'")
        elif s.startswith("classes:"):
            in_classes = True
        elif in_classes and lang is not None and s.startswith(f"{lang}:"):
            in_lang = True
        elif in_lang:
            if s.startswith("- "):
                cls = s[2:].split("#", 1)[0].strip().strip('"').strip("'")
                if cls:
                    classes.append(cls)
            elif s and not s.startswith("-"):
                in_lang = False
    return enabled, log, classes


def parse_plaintext_apis(text: str, lang: str) -> list[str]:
    """从 config.yaml 提取 plaintext.<lang> 的 API 列表（极简解析，避免 YAML 依赖）。"""
    apis: list[str] = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    # 定位 plaintext: 块（可能带行内注释，用 startswith）
    while i < n and not lines[i].strip().startswith("plaintext:"):
        i += 1
    i += 1
    # 块内找 lang: 子键，收集其 - 列表
    while i < n:
        line = lines[i]
        s = line.strip()
        if line and not line.startswith((" ", "\t")):
            break  # 顶级项，plaintext 块结束
        if s.startswith(f"{lang}:"):
            i += 1
            while i < n:
                s2 = lines[i].strip()
                if s2.startswith("- "):
                    apis.append(s2[2:].strip().strip('"').strip("'"))
                    i += 1
                else:
                    break
            break
        i += 1
    return apis


# ---------------------------------------------------------------------------
# 目标进程解析（跳过 shim）
# ---------------------------------------------------------------------------
def is_shim(path: Path) -> bool:
    """判断候选可执行文件是否是 shim（会剥离注入环境变量的包装脚本）。"""
    s = str(path)
    if any(m in s for m in SHIM_DIR_MARKERS):
        return True
    # nvm/asdf 等的真实二进制在 versions/*/bin 下；只有 shebang 脚本才按 shim 跳过。
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def resolve_executable(cmd: str) -> str:
    """返回 cmd 的真实二进制路径，跳过 pyenv/nvm 等 shim。"""
    # 已经是绝对路径，直接用
    if cmd.startswith("/"):
        return cmd
    # 含目录分隔符（如 ./foo），直接用
    if "/" in cmd:
        return cmd

    # 遍历 PATH 找所有候选，跳过 shim
    for path in os.environ.get("PATH", "").split(os.pathsep):
        if not path:
            continue
        cand = Path(path) / cmd
        if cand.is_file() and os.access(cand, os.X_OK):
            if is_shim(cand):
                continue
            return str(cand)
    # 兜底：用 shutil.which
    found = shutil.which(cmd)
    return found or cmd


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def cmd_run(args: argparse.Namespace) -> int:
    if not args.cmd:
        print("[vpo-hook] 用法: vpo-hook run [-q|-v] <command...>", file=sys.stderr)
        return 1

    quiet = bool(getattr(args, "quiet", False) or os.environ.get("VPO_HOOK_QUIET") == "1")
    verbose = bool(getattr(args, "verbose", False) or os.environ.get("VPO_HOOK_VERBOSE") == "1")
    if verbose:
        quiet = False

    def log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr)

    plat = detect_platform()
    if plat is None:
        raise SystemExit(f"[vpo-hook] 不支持的平台: {platform.system()}")

    lib = HOOK_DIR / ("libvpo_hook.dylib" if plat == "darwin" else "libvpo_hook.so")
    if not lib.exists():
        print("[vpo-hook] hook 库不存在，请先运行: vpo-hook init", file=sys.stderr)
        return 1

    # 读配置
    config_text = CONFIG_PATH.read_text(encoding="utf-8") if CONFIG_PATH.exists() else ""
    deny_paths = parse_deny_paths(config_text) if config_text else []
    if deny_paths:
        log(f"[vpo-hook] deny_paths: {':'.join(expand_home(p) for p in deny_paths)}")

    # 调用蜜罐运维脚本生成蜜罐数据（明文版脚本，用户可编辑）
    honeypot_script = CONFIG_DIR / "honeypot.py"
    if honeypot_script.exists():
        honeypot_kwargs = {"check": False}
        if quiet:
            honeypot_kwargs["stdout"] = subprocess.DEVNULL
        subprocess.run([sys.executable, str(honeypot_script)], **honeypot_kwargs)

    # 解析 rewrite 映射（deny 路径 -> 蜜罐路径）
    honeypot_map = parse_honeypot_map(config_text) if config_text else {}

    # 解析网络白名单和高危数据标记
    allow_network = parse_yaml_list(config_text, "allow_network") if config_text else []
    risk_markers = parse_yaml_list(config_text, "high_risk_markers") if config_text else []

    # 解析真实路径（跳过 shim）
    real = resolve_executable(args.cmd[0])
    base = os.path.basename(real)
    lang = "python" if "python" in base else ("js" if "node" in base else None)

    # 设置注入环境变量（二进制 hook）
    env = dict(os.environ)
    if plat == "darwin":
        env["DYLD_INSERT_LIBRARIES"] = str(lib)
    else:
        env["LD_PRELOAD"] = str(lib)
    env["VPO_HOOK_CONFIG"] = str(CONFIG_PATH)
    if deny_paths:
        env["VPO_DENY_PATHS"] = ":".join(expand_home(p) for p in deny_paths)
    if honeypot_map:
        env["VPO_REWRITE_MAP"] = ":".join(
            f"{expand_home(k)}={expand_home(v)}" for k, v in honeypot_map.items()
        )
    if allow_network:
        env["VPO_ALLOW_NETWORK"] = ",".join(allow_network)
    if risk_markers:
        env["VPO_HIGH_RISK_MARKERS"] = ":".join(risk_markers)

    # 名文 hook 注入（接口级，按目标语言）
    if config_text:
        if lang == "python":
            apis = parse_plaintext_apis(config_text, "python")
            if apis:
                env["VPO_HOOK_PY_API"] = ":".join(apis)
                env["VPO_PYTHONPATH"] = str(HERE / "plaintext")
                pp = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = str(HERE / "plaintext") + (":" + pp if pp else "")
                log(f"[vpo-hook] 名文 hook(python): {', '.join(apis)}")
        elif lang == "js":
            apis = parse_plaintext_apis(config_text, "js")
            if apis:
                env["VPO_HOOK_JS_API"] = ":".join(apis)
                preload = HERE.parent / "js" / "plaintext" / "preload.js"
                env["VPO_NODE_OPTIONS"] = f"--require {preload}"
                no = env.get("NODE_OPTIONS", "")
                env["NODE_OPTIONS"] = (f"--require {preload} " + no).strip()
                log(f"[vpo-hook] 名文 hook(js): {', '.join(apis)}")

    # 对象创建审计注入（默认关闭，只记录调用链）
    if config_text:
        audit_enabled, audit_log, audit_classes = parse_audit(config_text, lang)
        if audit_enabled and lang is None:
            log("[vpo-hook] 目标不是 Python/Node，审计未启用")
        elif audit_enabled and audit_classes:
            env["VPO_AUDIT_CLASSES"] = ":".join(audit_classes)
            env["VPO_AUDIT_LOG"] = (
                expand_home(audit_log) if audit_log else str(CONFIG_DIR / "audit.log")
            )
            log(f"[vpo-hook] 审计({lang}): {', '.join(audit_classes)}")

    if quiet:
        env["VPO_HOOK_QUIET"] = "1"
    else:
        env.pop("VPO_HOOK_QUIET", None)
    if verbose:
        env["VPO_HOOK_VERBOSE"] = "1"

    log(f"[vpo-hook] 启动: {real}")
    sys.stdout.flush()
    sys.stderr.flush()

    try:
        os.execvpe(real, [real] + list(args.cmd[1:]), env)
    except FileNotFoundError:
        print(f"[vpo-hook] 找不到可执行文件: {args.cmd[0]}", file=sys.stderr)
        return 1
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    plat = detect_platform()
    lib = HOOK_DIR / ("libvpo_hook.dylib" if plat == "darwin" else "libvpo_hook.so")
    print(f"[vpo-hook] 平台: {platform.system()} {platform.machine()}")
    print(f"[vpo-hook] hook 库: {lib} {'(存在)' if lib.exists() else '(缺失，请 init)'}")
    print(f"[vpo-hook] 配置: {CONFIG_PATH} {'(存在)' if CONFIG_PATH.exists() else '(缺失)'}")
    return 0


# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vpo-hook", description="VPO-Hook 启动器")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="生成配置 + 编译 hook 库")
    r = sub.add_parser("run", help="注入 hook 并运行目标进程")
    r.add_argument("-q", "--quiet", action="store_true", help="不输出启动器诊断信息")
    r.add_argument("-v", "--verbose", action="store_true", help="输出详细诊断信息")
    r.add_argument("cmd", nargs=argparse.REMAINDER, help="目标命令及其参数")
    sub.add_parser("status", help="显示当前状态")

    args = p.parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "status":
        return cmd_status(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
