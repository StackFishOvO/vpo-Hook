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
import ast
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
HOOK_DIR = HERE / "obj_hook"
CONFIG_DIR = Path.home() / ".vpo-hook"
CONFIG_PATH = CONFIG_DIR / "config.yaml"
TEMPLATE_CONFIG = HOOK_DIR / "config.yaml"
GRANTS_DIR = CONFIG_DIR / "grants"
DENIALS_LOG = CONFIG_DIR / "denials.log"
SIGN_KEY_PATH = CONFIG_DIR / ".sign_key"
SIG_PATH = CONFIG_DIR / "config.sig"
CHAIN_LOG = CONFIG_DIR / "chain.log"
CHAIN_HEAD = CONFIG_DIR / ".chain_head"
SIGN_TTL = int(os.environ.get("VPO_SIGN_TTL", str(30 * 24 * 3600)))

# 已知会剥离 LD_PRELOAD / DYLD_INSERT_LIBRARIES 的版本管理器 shim 目录。
# 注意：只能匹配 shims 目录本身，不能匹配 /.pyenv/ 整棵子树，否则会误伤
# ~/.pyenv/versions/3.11/bin/python3 这类真实二进制。
SHIM_DIR_MARKERS = ("/shims/", "/.asdf/shims/", "/.rbenv/shims/", "/.nodenv/shims/")

# 简单安全组：系统运行时目录（只读放行，供解释器/系统库加载）
RUNTIME_DIRS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")


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
    created = not CONFIG_PATH.exists()
    if created:
        shutil.copyfile(TEMPLATE_CONFIG, CONFIG_PATH)
        print(f"[vpo-hook] 已生成默认配置: {CONFIG_PATH}")
    else:
        print(f"[vpo-hook] 配置已存在: {CONFIG_PATH}")

    # 复制蜜罐运维脚本模板（明文版，用户可编辑）
    honeypot_script = CONFIG_DIR / "honeypot.py"
    if not honeypot_script.exists():
        shutil.copyfile(HOOK_DIR / "honeypot.py", honeypot_script)
        print(f"[vpo-hook] 已生成蜜罐脚本: {honeypot_script}")

    # 新生成的配置做签名；已有配置若需签名请显式运行 vpo-hook sign
    if created:
        key = load_sign_key(True)
        env = sign_envelope(CONFIG_PATH.read_bytes(), key)
        SIG_PATH.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
        try:
            SIG_PATH.chmod(0o600)
        except Exception:
            pass
        append_chain({"event": "config_sign", "path": str(CONFIG_PATH)})
        print(f"[vpo-hook] 已签名配置: {SIG_PATH}")

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


# ---------------------------------------------------------------------------
# 简单安全组（profile: simple）：极简 YAML 子集解析
# ---------------------------------------------------------------------------
def _simple_value(v: str):
    v = v.split("#", 1)[0].strip()
    if v == "[]":
        return []
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v


def parse_simple_yaml(text: str) -> dict:
    """解析简单安全组需要的 YAML 子集（mapping + 标量 + 行内 [] + block list）。"""
    root: dict = {}
    stack: list[tuple[int, object]] = [(-1, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip())
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if stripped.startswith("- "):
            if isinstance(parent, list):
                parent.append(_simple_value(stripped[2:]))
            i += 1
            continue

        if ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.split("#", 1)[0].strip()
            if val == "":
                # 看下一行判断是 list 还是 dict
                j = i + 1
                while j < len(lines):
                    nxt = lines[j].strip()
                    if not nxt or nxt.startswith("#"):
                        j += 1
                        continue
                    break
                n_indent = len(lines[j]) - len(lines[j].lstrip()) if j < len(lines) else -1
                if j < len(lines) and lines[j].lstrip().startswith("- ") and n_indent > indent:
                    child: object = []
                else:
                    child = {}
            else:
                child = _simple_value(val)
            if isinstance(parent, dict):
                parent[key] = child
                if isinstance(child, (dict, list)):
                    stack.append((indent, child))
        i += 1
    return root


def _simple_get(node, *keys):
    cur = node
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def simple_scalar(node, default, *keys):
    v = _simple_get(node, *keys)
    if v is None or isinstance(v, (dict, list)):
        return default
    return v


def simple_list(node, *keys):
    v = _simple_get(node, *keys)
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str) and x]
    if isinstance(v, str) and v:
        return [v]
    return []


def detect_env_root(real: str, lang: str | None) -> Path | None:
    """判定简单安全组的信任区根目录。"""
    if lang == "python":
        p = Path(real)
        bin_dir = p.parent
        if (bin_dir.parent / "pyvenv.cfg").exists():
            return bin_dir.parent
        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            return Path(venv)
        return None
    if lang == "js":
        d = Path.cwd()
        while True:
            if (d / "package.json").exists():
                return d
            if d.parent == d:
                break
            d = d.parent
        return Path.cwd()
    return None


# ---------------------------------------------------------------------------
# 能力发现（Phase B）：nm -u + Python AST + JS 正则
# ---------------------------------------------------------------------------
CAPABILITY_GROUPS = ("file", "network", "process", "code_load")

_NATIVE_KEYWORDS = {
    "file": ["open", "openat", "fopen", "read", "write", "unlink", "rename",
             "mkdir", "rmdir", "stat", "fstat", "lstat", "truncate"],
    "network": ["socket", "connect", "sendto", "recvfrom", "getaddrinfo",
                "gethostbyname", "send", "recv"],
    "process": ["execve", "execv", "execvp", "posix_spawn", "system", "popen",
                "fork", "vfork", "kill"],
    "code_load": ["dlopen"],
}

_JS_RULES = {
    "file": [
        r"require\(\s*['\"](?:node:)?fs['\"]\s*\)",
        r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|open|openSync)\b",
    ],
    "network": [
        r"require\(\s*['\"](?:node:)?(?:net|http|https|dns|tls)['\"]\s*\)",
        r"\bfetch\s*\(",
        r"require\(\s*['\"]undici['\"]\s*\)",
    ],
    "process": [
        r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)",
        r"\b(?:exec|execSync|spawn|spawnSync)\s*\(",
    ],
    "code_load": [
        r"\bprocess\.binding\b",
        r"\bdlopen\b",
        r"require\(\s*['\"]ffi(?:-napi)?['\"]\s*\)",
    ],
}

_SCAN_SKIP = {"node_modules", ".venv", "venv", "__pycache__", "build", "dist", ".git"}


def _nm_undefined(path: Path) -> list[str]:
    nm = shutil.which("nm")
    if not nm:
        return []
    try:
        proc = subprocess.run(
            [nm, "-u", str(path)], capture_output=True, text=True, check=False
        )
    except Exception:
        return []
    syms: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        tok = line.split()[-1].split("@")[0]
        if tok:
            syms.append(tok)
    return syms


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _classify_py_call(fn: str, group_hits: dict[str, int]) -> None:
    if fn == "open" or fn.startswith("pathlib.") or fn.startswith("shutil."):
        group_hits["file"] = group_hits.get("file", 0) + 1
    if fn.startswith("os.open") or fn.startswith("os.remove") or fn.startswith("os.unlink") \
            or fn.startswith("os.rename") or fn.startswith("os.listdir"):
        group_hits["file"] = group_hits.get("file", 0) + 1
    if fn.startswith("os.system") or fn.startswith("os.popen") or fn.startswith("os.fork") \
            or fn.startswith("os.exec") or fn.startswith("os.spawn") or fn.startswith("subprocess."):
        group_hits["process"] = group_hits.get("process", 0) + 1
    if fn.startswith("socket.") or fn.startswith("requests.") or fn.startswith("urllib.") \
            or fn.startswith("http.") or fn.startswith("ftplib.") or fn.startswith("smtplib."):
        group_hits["network"] = group_hits.get("network", 0) + 1
    if fn.startswith("ctypes.CDLL") or fn.startswith("ctypes.util"):
        group_hits["code_load"] = group_hits.get("code_load", 0) + 1


def _scan_python(path: Path) -> dict[str, int]:
    group_hits: dict[str, int] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
    except Exception:
        return group_hits
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    continue
                if alias.name in ("socket", "requests", "urllib", "http", "ftplib", "smtplib"):
                    group_hits["network"] = group_hits.get("network", 0) + 1
                if alias.name == "subprocess":
                    group_hits["process"] = group_hits.get("process", 0) + 1
                if alias.name in ("ctypes", "importlib"):
                    group_hits["code_load"] = group_hits.get("code_load", 0) + 1
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("os") or mod.startswith("subprocess"):
                group_hits["process"] = group_hits.get("process", 0) + 1
            if mod.startswith(("socket", "urllib", "http", "requests")):
                group_hits["network"] = group_hits.get("network", 0) + 1
        elif isinstance(node, ast.Call):
            _classify_py_call(_call_name(node.func), group_hits)
        elif isinstance(node, ast.Attribute):
            fn = _call_name(node)
            if fn in ("os.system", "os.popen", "os.fork") or fn.startswith(("os.exec", "os.spawn", "subprocess.")):
                group_hits["process"] = group_hits.get("process", 0) + 1
            elif fn.startswith(("os.open", "os.remove", "os.unlink", "os.rename", "os.listdir", "shutil.")):
                group_hits["file"] = group_hits.get("file", 0) + 1
            elif fn.startswith(("socket.", "requests.", "urllib.", "http.", "ftplib.", "smtplib.")):
                group_hits["network"] = group_hits.get("network", 0) + 1
            elif fn.startswith("ctypes.CDLL"):
                group_hits["code_load"] = group_hits.get("code_load", 0) + 1
    return group_hits


def _scan_js(path: Path) -> dict[str, int]:
    group_hits: dict[str, int] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return group_hits
    for group, patterns in _JS_RULES.items():
        count = 0
        for pat in patterns:
            count += len(re.findall(pat, text))
        if count:
            group_hits[group] = group_hits.get(group, 0) + count
    return group_hits


def scan_capabilities(root: str | Path) -> dict[str, dict]:
    """扫描目录/文件，返回 {group: {score, evidence}}。"""
    root = Path(root)
    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in _SCAN_SKIP for part in p.parts):
                continue
            if p.suffix in (".so", ".dylib", ".node", ".py", ".js", ".mjs", ".cjs"):
                files.append(p)
        if len(files) > 500:
            files = files[:500]

    group_hits: dict[str, dict[str, int]] = {g: {} for g in CAPABILITY_GROUPS}
    evidence: dict[str, list[str]] = {g: [] for g in CAPABILITY_GROUPS}

    for p in files:
        if p.suffix in (".so", ".dylib", ".node"):
            for sym in _nm_undefined(p):
                for group, kws in _NATIVE_KEYWORDS.items():
                    if any(kw in sym for kw in kws):
                        group_hits[group][p.name] = group_hits[group].get(p.name, 0) + 1
                        if len(evidence[group]) < 6:
                            evidence[group].append(f"{p.name}: {sym}")
                        break
        elif p.suffix == ".py":
            hits = _scan_python(p)
            rel = str(p)
            for group, n in hits.items():
                group_hits[group][rel] = group_hits[group].get(rel, 0) + n
                if len(evidence[group]) < 6:
                    evidence[group].append(f"{rel}")
        elif p.suffix in (".js", ".mjs", ".cjs"):
            hits = _scan_js(p)
            rel = str(p)
            for group, n in hits.items():
                group_hits[group][rel] = group_hits[group].get(rel, 0) + n
                if len(evidence[group]) < 6:
                    evidence[group].append(rel)

    result: dict[str, dict] = {}
    for group in CAPABILITY_GROUPS:
        total = sum(group_hits[group].values())
        score = min(1.0, total / 6.0)
        result[group] = {"score": round(score, 2), "evidence": evidence[group]}
    return result


def cmd_scan(args: argparse.Namespace) -> int:
    caps = scan_capabilities(args.path)
    if getattr(args, "json", False):
        print(json.dumps(caps, ensure_ascii=False, indent=2))
        return 0
    print(f"[vpo-hook] 能力发现: {args.path}")
    for group in CAPABILITY_GROUPS:
        info = caps[group]
        if info["score"] <= 0:
            continue
        ev = "; ".join(info["evidence"][:3])
        print(f"  {group:<10} score={info['score']:.2f}  证据: {ev}")
    return 0


# ---------------------------------------------------------------------------
# 授权（Phase C）：grants 文件 + 首次交互 + log/grant/revoke/list
# ---------------------------------------------------------------------------
def grants_path(env_root: str | Path) -> Path:
    h = hashlib.sha256(str(env_root).encode("utf-8")).hexdigest()[:16]
    return GRANTS_DIR / f"{h}.json"


def grants_sig_path(env_root: str | Path) -> Path:
    return grants_path(env_root).with_name(grants_path(env_root).stem + ".sig")


def load_grants(env_root: str | Path) -> dict | None:
    p = grants_path(env_root)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_grants(env_root: str | Path, grants: dict) -> None:
    GRANTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        GRANTS_DIR.chmod(0o700)
    except Exception:
        pass
    p = grants_path(env_root)
    data = (json.dumps(grants, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    p.write_bytes(data)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    # 签名 + 审计链
    key = load_sign_key(True)
    env = sign_envelope(data, key)
    grants_sig_path(env_root).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    try:
        grants_sig_path(env_root).chmod(0o600)
    except Exception:
        pass
    append_chain({"event": "grant", "env_root": str(env_root), "kind": "grants"})


# ---------------------------------------------------------------------------
# 配置签名（Phase D）：HMAC-SHA256 + 时间戳/随机数/有效期
# ---------------------------------------------------------------------------
def load_sign_key(create: bool) -> bytes | None:
    if "VPO_SIGN_KEY" in os.environ:
        return os.environ["VPO_SIGN_KEY"].encode("utf-8")
    if SIGN_KEY_PATH.exists():
        return SIGN_KEY_PATH.read_bytes()
    if create:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            CONFIG_DIR.chmod(0o700)
        except Exception:
            pass
        key = secrets.token_bytes(32)
        SIGN_KEY_PATH.write_bytes(key)
        try:
            SIGN_KEY_PATH.chmod(0o600)
        except Exception:
            pass
        return key
    return None


def sign_envelope(data: bytes, key: bytes) -> dict:
    ts = int(time.time())
    nonce = secrets.token_hex(16)
    expiry = ts + SIGN_TTL
    payload = data + b"\n" + str(ts).encode() + b"\n" + nonce.encode() + b"\n" + str(expiry).encode()
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return {"scheme": "hmac-sha256", "ts": ts, "nonce": nonce, "expiry": expiry, "sig": sig}


def verify_envelope(data: bytes, env: dict, key: bytes) -> tuple[bool, str]:
    if env.get("scheme") != "hmac-sha256":
        return False, "未知签名方案"
    ts = env.get("ts")
    nonce = env.get("nonce")
    expiry = env.get("expiry")
    sig = env.get("sig")
    if not all([ts is not None, nonce, expiry, sig]):
        return False, "签名字段缺失"
    try:
        expiry_i = int(expiry)
    except Exception:
        return False, "签名有效期非法"
    if int(time.time()) > expiry_i:
        return False, "签名已过期，请运行 vpo-hook sign"
    payload = data + b"\n" + str(ts).encode() + b"\n" + str(nonce).encode() + b"\n" + str(expiry).encode()
    calc = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, str(sig)):
        return False, "配置签名不匹配（配置被修改）"
    return True, ""


def cmd_sign(_args: argparse.Namespace) -> int:
    if not CONFIG_PATH.exists():
        print("[vpo-hook] 没有配置文件，请先 init", file=sys.stderr)
        return 1
    key = load_sign_key(True)
    env = sign_envelope(CONFIG_PATH.read_bytes(), key)
    SIG_PATH.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    try:
        SIG_PATH.chmod(0o600)
    except Exception:
        pass
    append_chain({"event": "config_sign", "path": str(CONFIG_PATH)})
    print(f"[vpo-hook] 已签名: {SIG_PATH} (有效期至 {env['expiry']})")
    return 0


# ---------------------------------------------------------------------------
# grants 签名校验
# ---------------------------------------------------------------------------
def verify_grants(env_root: str | Path) -> tuple[bool, str]:
    p = grants_path(env_root)
    sp = grants_sig_path(env_root)
    if not sp.exists():
        return True, ""  # 未签名，靠 0600 权限保护
    if not p.exists():
        return False, "grants 文件缺失但存在签名"
    key = load_sign_key(False)
    if key is None:
        return False, "grants 有签名但缺少密钥"
    try:
        env = json.loads(sp.read_text(encoding="utf-8"))
    except Exception:
        return False, "grants 签名文件损坏"
    return verify_envelope(p.read_bytes(), env, key)


# ---------------------------------------------------------------------------
# 审计哈希链：每行 {event..., prev}，链头 HMAC(key, sha256(line))
# ---------------------------------------------------------------------------
_GENESIS_HEAD = "0" * 64


def _chain_head() -> str:
    if CHAIN_HEAD.exists():
        h = CHAIN_HEAD.read_text(encoding="utf-8").strip()
        if h:
            return h
    return _GENESIS_HEAD


def append_chain(event: dict) -> None:
    key = load_sign_key(True)
    prev = _chain_head()
    entry = dict(event)
    entry["prev"] = prev
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    head = hmac.new(key, hashlib.sha256(line.encode("utf-8")).hexdigest().encode(), hashlib.sha256).hexdigest()
    with open(CHAIN_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    CHAIN_HEAD.write_text(head, encoding="utf-8")
    try:
        CHAIN_HEAD.chmod(0o600)
    except Exception:
        pass


def verify_chain() -> tuple[bool, str]:
    if not CHAIN_LOG.exists():
        return True, ""
    key = load_sign_key(False)
    if key is None:
        return False, "缺少签名密钥，无法校验链"
    head = _GENESIS_HEAD
    try:
        lines = CHAIN_LOG.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False, "链日志读取失败"
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except Exception:
            return False, f"第 {idx + 1} 行不是合法 JSON"
        if entry.get("prev") != head:
            return False, f"第 {idx + 1} 行 prev 不匹配（链被篡改）"
        head = hmac.new(key, hashlib.sha256(line.encode("utf-8")).hexdigest().encode(), hashlib.sha256).hexdigest()
    stored = _chain_head()
    if stored != head:
        return False, "链头不匹配（链被截断/篡改）"
    return True, ""


def cmd_chain(_args: argparse.Namespace) -> int:
    ok, msg = verify_chain()
    if ok:
        print("[vpo-hook] 审计链校验通过")
        return 0
    print(f"[vpo-hook] 审计链校验失败: {msg}", file=sys.stderr)
    return 1


def default_grants(env_root: str | Path) -> dict:
    return {
        "version": 1,
        "env_root": str(env_root),
        "files": {"extra_read": [], "extra_write": []},
        "network": {"mode": "off", "allowlist": [], "blocklist": []},
        "process": {"exec": "off", "exec_allow": []},
    }


def prompt_first_run(env_root: str | Path, caps: dict[str, dict]) -> dict:
    """交互式首次授权：只问 network / process，文件保持 env 内。"""
    print(f"[vpo-hook] 首次运行，环境根: {env_root}", file=sys.stderr)
    found = [g for g in CAPABILITY_GROUPS if caps[g]["score"] > 0]
    if found:
        print(f"[vpo-hook] 扫描发现能力: {', '.join(found)}", file=sys.stderr)
    grants = default_grants(env_root)

    if caps["network"]["score"] > 0:
        try:
            ans = input("允许联网（internet，公网 80/443/53）? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans in ("y", "yes"):
            grants["network"]["mode"] = "internet"
    if caps["process"]["score"] > 0:
        try:
            ans = input("允许执行子进程（shell）? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans in ("y", "yes"):
            grants["process"]["exec"] = "shell"

    save_grants(env_root, grants)
    print(f"[vpo-hook] 已保存授权: {grants_path(env_root)}", file=sys.stderr)
    return grants


def _grant_target_env_root() -> Path:
    # grant 默认把 cwd 当作环境根；也可以由调用方显式传入
    return Path.cwd()


def _merge_grants_into(grants: dict | None, simple_cfg: dict) -> dict:
    """返回合并后的 effective 配置（grants 覆盖 config 的 permissions）。"""
    merged = json.loads(json.dumps(simple_cfg))
    if not grants:
        return merged
    perms = merged.setdefault("permissions", {})
    files = perms.setdefault("files", {})
    files["extra_read"] = grants.get("files", {}).get("extra_read", files.get("extra_read", []))
    files["extra_write"] = grants.get("files", {}).get("extra_write", files.get("extra_write", []))
    net = perms.setdefault("network", {})
    net["mode"] = grants.get("network", {}).get("mode", net.get("mode", "off"))
    net["allowlist"] = grants.get("network", {}).get("allowlist", net.get("allowlist", []))
    net["blocklist"] = grants.get("network", {}).get("blocklist", net.get("blocklist", []))
    proc = perms.setdefault("process", {})
    proc["exec"] = grants.get("process", {}).get("exec", proc.get("exec", "off"))
    proc["exec_allow"] = grants.get("process", {}).get("exec_allow", proc.get("exec_allow", []))
    return merged


def _read_denials_tail(n: int = 20) -> list[dict]:
    if not DENIALS_LOG.exists():
        return []
    lines = DENIALS_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _print_denial_summary(offset: int) -> None:
    if not DENIALS_LOG.exists():
        return
    try:
        with open(DENIALS_LOG, encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            tail = f.read()
    except Exception:
        return
    records: list[dict] = []
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    if not records:
        return
    print(f"[vpo-hook] 本次被拒绝 {len(records)} 次:", file=sys.stderr)
    seen: set[tuple[str, str]] = set()
    for r in records[:20]:
        key = (str(r.get("func", "")), str(r.get("path", "")))
        if key in seen:
            continue
        seen.add(key)
        print(f"  - {r.get('func', '?')}  {r.get('path', '')}", file=sys.stderr)
    print("[vpo-hook] 授权: vpo-hook grant ... ; 详情: vpo-hook log", file=sys.stderr)


def cmd_log(args: argparse.Namespace) -> int:
    n = getattr(args, "n", 20)
    records = _read_denials_tail(n)
    if not records:
        print("[vpo-hook] 没有拒绝记录")
        return 0
    print(f"[vpo-hook] 最近 {len(records)} 条拒绝记录:")
    for r in records:
        print(f"  {r.get('func', '?')}  {r.get('path', '')}")
    return 0


def cmd_grant(args: argparse.Namespace) -> int:
    root = Path(args.root) if getattr(args, "root", None) else _grant_target_env_root()
    grants = load_grants(root) or default_grants(root)
    kind = args.kind
    if kind == "network":
        mode = args.value
        grants["network"]["mode"] = mode
        if mode == "allowlist":
            grants["network"]["allowlist"] = list(args.rest)
        elif mode == "internet":
            grants["network"]["allowlist"] = []
    elif kind == "process":
        mode = args.value
        grants["process"]["exec"] = mode
        if mode == "allowlist":
            grants["process"]["exec_allow"] = list(args.rest)
        else:
            grants["process"]["exec_allow"] = []
    elif kind == "file":
        mode = args.value  # read | write
        paths = list(args.rest)
        key = "extra_read" if mode == "read" else "extra_write"
        cur = set(grants["files"].get(key, []))
        cur.update(paths)
        grants["files"][key] = sorted(cur)
    else:
        print(f"[vpo-hook] 未知授权类型: {kind}", file=sys.stderr)
        return 1
    save_grants(root, grants)
    print(f"[vpo-hook] 已更新授权: {grants_path(root)}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    root = Path(args.root) if getattr(args, "root", None) else _grant_target_env_root()
    p = grants_path(root)
    if p.exists():
        p.unlink()
        sp = grants_sig_path(root)
        if sp.exists():
            sp.unlink()
        append_chain({"event": "revoke", "env_root": str(root)})
        print(f"[vpo-hook] 已撤销授权: {p}")
    else:
        print("[vpo-hook] 没有该环境的授权")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    if not GRANTS_DIR.exists():
        print("[vpo-hook] 没有授权记录")
        return 0
    files = sorted(GRANTS_DIR.glob("*.json"))
    if not files:
        print("[vpo-hook] 没有授权记录")
        return 0
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        print(f"env_root: {data.get('env_root', '?')}")
        net = data.get("network", {})
        proc = data.get("process", {})
        files_p = data.get("files", {})
        print(f"  network: {net.get('mode', 'off')} allowlist={net.get('allowlist', [])}")
        print(f"  process: {proc.get('exec', 'off')} allow={proc.get('exec_allow', [])}")
        print(f"  files: read={files_p.get('extra_read', [])} write={files_p.get('extra_write', [])}")
    return 0


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

    # 配置签名校验（有 .sig 才校验；无则旧行为不校验）
    if SIG_PATH.exists() and config_text:
        key = load_sign_key(False)
        if key is None:
            print("[vpo-hook] 配置有签名但缺少密钥，拒绝运行", file=sys.stderr)
            return 1
        try:
            env_sig = json.loads(SIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            print("[vpo-hook] 配置签名文件损坏，拒绝运行", file=sys.stderr)
            return 1
        ok, msg = verify_envelope(config_text.encode("utf-8"), env_sig, key)
        if not ok:
            print(f"[vpo-hook] {msg}，拒绝运行", file=sys.stderr)
            return 1

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

    # 简单安全组：只有 profile: simple 且带 permissions 块才启用（旧配置兼容）
    simple_cfg = None
    if config_text:
        _parsed = parse_simple_yaml(config_text)
        if simple_scalar(_parsed, "", "profile") == "simple" and "permissions" in _parsed:
            simple_cfg = _parsed

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

    if simple_cfg is not None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        env["VPO_DENIALS_LOG"] = str(DENIALS_LOG)
        env["VPO_ENV_ROOT"] = ""  # 先清空，避免继承旧值
        _env_opt = simple_scalar(simple_cfg, "auto", "env")
        if _env_opt == "auto":
            root = detect_env_root(real, lang)
        else:
            root = Path(expand_home(_env_opt))
        if root and root.exists():
            env["VPO_ENV_ROOT"] = str(root)
            env["VPO_RUNTIME_DIRS"] = ":".join(RUNTIME_DIRS)

            ok, gmsg = verify_grants(root)
            if not ok:
                print(f"[vpo-hook] {gmsg}，拒绝运行", file=sys.stderr)
                return 1
            grants = load_grants(root)
            caps = scan_capabilities(root)
            if grants is None and sys.stdin.isatty() and not quiet:
                grants = prompt_first_run(root, caps)
            if grants is not None:
                simple_cfg = _merge_grants_into(grants, simple_cfg)

            extra = simple_list(simple_cfg, "permissions", "files", "extra_read") + \
                simple_list(simple_cfg, "permissions", "files", "extra_write")
            if extra:
                env["VPO_EXTRA_PATHS"] = ":".join(expand_home(p) for p in extra)

            if not quiet:
                found = [g for g in CAPABILITY_GROUPS if caps[g]["score"] > 0]
                if found:
                    log(f"[vpo-hook] 发现能力: {', '.join(found)}")
                else:
                    log("[vpo-hook] 未发现明显能力（默认按简单安全组拒绝）")
        else:
            log("[vpo-hook] 无法判定环境根目录，简单安全组文件作用域未启用")

        net_mode = simple_scalar(simple_cfg, "off", "permissions", "network", "mode")
        env["VPO_NETWORK_MODE"] = net_mode
        if net_mode == "allowlist":
            al = simple_list(simple_cfg, "permissions", "network", "allowlist")
            if al:
                env["VPO_ALLOW_NETWORK"] = ",".join(al)
        bl = simple_list(simple_cfg, "permissions", "network", "blocklist")
        if bl:
            env["VPO_NETWORK_BLOCKLIST"] = ",".join(bl)

        exec_mode = simple_scalar(simple_cfg, "off", "permissions", "process", "exec")
        env["VPO_EXEC_MODE"] = exec_mode
        ea = simple_list(simple_cfg, "permissions", "process", "exec_allow")
        if ea:
            env["VPO_EXEC_ALLOW"] = ":".join(expand_home(p) for p in ea)

        sw = simple_list(simple_cfg, "sensitive_words")
        if sw:
            prev = env.get("VPO_HIGH_RISK_MARKERS", "")
            env["VPO_HIGH_RISK_MARKERS"] = (prev + ":" + ":".join(sw)) if prev else ":".join(sw)

        env["VPO_INSPECT_INBOUND"] = "1" if simple_scalar(simple_cfg, "true", "inbound", "inspect") in ("true", "1", "yes", "on") else "0"
        env["VPO_INBOUND_ACTION"] = simple_scalar(simple_cfg, "audit", "inbound", "action")
        sa = simple_list(simple_cfg, "sources", "allow")
        sd = simple_list(simple_cfg, "sources", "deny")
        if sa:
            env["VPO_SOURCES_ALLOW"] = ",".join(sa)
        if sd:
            env["VPO_SOURCES_DENY"] = ",".join(sd)

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
                preload = HERE / "js_plaintext" / "preload.js"
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

    denials_offset = DENIALS_LOG.stat().st_size if DENIALS_LOG.exists() else 0
    try:
        proc = subprocess.Popen([real] + list(args.cmd[1:]), env=env)
    except FileNotFoundError:
        print(f"[vpo-hook] 找不到可执行文件: {args.cmd[0]}", file=sys.stderr)
        return 1

    def _forward_sigterm(signum: int, _frame) -> None:
        try:
            proc.send_signal(signum)
        except Exception:
            pass
        sys.exit(128 + signum)

    old_sigterm = signal.signal(signal.SIGTERM, _forward_sigterm)
    try:
        rc = proc.wait()
    except KeyboardInterrupt:
        rc = 130
    finally:
        signal.signal(signal.SIGTERM, old_sigterm)

    if not quiet:
        _print_denial_summary(denials_offset)
    return rc


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
    sc = sub.add_parser("scan", help="扫描目录/文件的能力清单")
    sc.add_argument("path", help="目录或文件路径")
    sc.add_argument("--json", action="store_true", help="输出 JSON")

    lg = sub.add_parser("log", help="查看最近拒绝记录")
    lg.add_argument("-n", type=int, default=20, help="显示条数")

    gr = sub.add_parser("grant", help="给某个环境根授权")
    gr.add_argument("--root", help="环境根目录（默认当前目录）")
    gr.add_argument("kind", choices=["network", "process", "file"], help="授权类型")
    gr.add_argument("value", help="network: off|internet|allowlist；process: off|allowlist|shell；file: read|write")
    gr.add_argument("rest", nargs=argparse.REMAINDER, help="allowlist 条目或路径")

    rv = sub.add_parser("revoke", help="撤销某个环境根的全部授权")
    rv.add_argument("--root", help="环境根目录（默认当前目录）")

    sub.add_parser("list", help="列出所有授权")
    sub.add_parser("sign", help="对配置文件签名")
    sub.add_parser("chain", help="校验审计链")

    args = p.parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "log":
        return cmd_log(args)
    if args.command == "grant":
        return cmd_grant(args)
    if args.command == "revoke":
        return cmd_revoke(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "sign":
        return cmd_sign(args)
    if args.command == "chain":
        return cmd_chain(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
