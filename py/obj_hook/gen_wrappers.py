#!/usr/bin/env python3
"""
gen_wrappers.py -- 读取 signatures.json，生成二进制 hook 的 wrapper 源码。

当前目标平台：macOS（DYLD_INTERPOSE 机制）。
Linux（同名符号 + RTLD_NEXT）作为后续 Phase 6 的扩展。

生成逻辑（对应 Target.md 4.1 节）：
  1. 遍历签名模板表每个函数
  2. 按签名生成同名 wrapper 函数（my_ 前缀 + DYLD_INTERPOSE 配对）
  3. wrapper 体内：策略引擎检查(vpo_check) -> 放行/拒绝 -> 调真实函数
  4. 真实函数通过 dlsym 懒加载获取
  5. thread_local 重入标志保护
  6. 变参函数（O_CREAT）特殊处理

用法：
    python3 gen_wrappers.py signatures.json -o wrapper.c
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Optional


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# macOS 平台适配：真实符号名映射。
#
# macOS 上 DYLD_INTERPOSE 会把对 `open` 的引用重定向到 `my_open`，且此时
# dlsym(RTLD_DEFAULT / RTLD_NEXT / 特定 handle, "open") 全部返回 interpose 之后
# 的 replacement（已实测），无法据此获取真实实现。因此获取真实实现只能用
# 「未被 interpose 劫持的别名符号」：
#
#   1. __ 私有符号（libsystem_kernel 的 __name）—— 直接静态调用；
#   2. $NOCANCEL 变体符号（如 read$NOCANCEL）—— dlsym(RTLD_DEFAULT) 懒加载；
#   3. 两者都没有的函数 —— 无法安全 interpose，列入 MACOS_SKIP 跳过。
# ---------------------------------------------------------------------------
MACOS_REAL_SYMBOL: dict[str, str] = {
    "open": "__open",
    "openat": "__openat",
    "unlink": "__unlink",
    "unlinkat": "__unlinkat",
    "rename": "__rename",
    "renameat": "__renameat",
    "rmdir": "__rmdir",
    "connect": "__connect",
    "bind": "__bind",
    "sendto": "__sendto",
    "recvfrom": "__recvfrom",
    "fork": "__fork",
    "vfork": "__vfork",
    "execve": "__execve",
    "kill": "__kill",
}

# $NOCANCEL 变体符号（macOS 为部分系统调用导出的别名，可绕过 interpose）。
MACOS_NOCANCEL_SYMBOL: dict[str, str] = {
    "read": "read$NOCANCEL",
    "write": "write$NOCANCEL",
}

# 需要额外拦截 $NOCANCEL 变体的函数（CPython 等运行时静态链接这些变体，绕过主符号）。
# 值: (公开 $ 符号名, C 别名(经 asm 标签), 真实 __ 私有符号)
MACOS_NOCANCEL_INTERPOSE: dict[str, tuple[str, str, str]] = {
    "open": ("open$NOCANCEL", "open_nocancel", "__open_nocancel"),
    "openat": ("openat$NOCANCEL", "openat_nocancel", "__openat_nocancel"),
}

# 无法安全 interpose 的函数：
#  - close / mmap / mprotect：dyld 加载 dylib 过程中就会调用，interpose 后
#    加载期访问 TLS 变量会崩溃；
#  - 其余：既无 __ 私有符号、也无 $NOCANCEL 变体，dlsym 会被 interpose 劫持。
MACOS_SKIP: frozenset[str] = frozenset({
    "close", "mmap", "mprotect",
    "mkdir", "socket", "send", "recv",
    "execv", "execvp", "system", "popen", "dlopen",
})


HEADER = """\
/* 自动生成，请勿手改。来源: signatures.json，生成器: gen_wrappers */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>
#include <spawn.h>

/* ---------------------------------------------------------------------------
 * 策略引擎 ABI：见 vpo_hook.h（与策略引擎 policy.c 共用，避免重复定义）。
 * ------------------------------------------------------------------------- */
#include "vpo_hook.h"

/* ---------------------------------------------------------------------------
 * macOS DYLD_INTERPOSE 宏
 * ------------------------------------------------------------------------- */
#define DYLD_INTERPOSE(_replacement, _original) \\
    __attribute__((used)) static struct { \\
        const void *replacement; \\
        const void *original; \\
    } _interpose_##_original \\
    __attribute__((section("__DATA,__interpose"))) = { \\
        (const void *)(unsigned long)&_replacement, \\
        (const void *)(unsigned long)&_original \\
    };

"""


LINUX_HEADER = """\
/* 自动生成，请勿手改。来源: signatures.json，生成器: gen_wrappers（Linux 版） */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>
#include <spawn.h>

/* ---------------------------------------------------------------------------
 * 策略引擎 ABI：见 vpo_hook.h（与策略引擎 policy.c 共用）。
 * ------------------------------------------------------------------------- */
#include "vpo_hook.h"

"""


def parse_signature(signature: str) -> tuple[str, str]:
    """从 C 签名字符串解析出 (返回类型, 函数名)。

    正确处理指针返回类型，如 ``FILE *popen`` -> ("FILE *", "popen")、
    ``void *mmap`` -> ("void *", "mmap")。
    """
    head = signature.split("(", 1)[0].strip()
    m = re.search(r"([A-Za-z_]\w*)\s*$", head)
    if not m:
        raise ValueError(f"cannot parse signature: {signature!r}")
    name = m.group(1)
    ret = head[: m.start()].strip()
    return ret, name


def normalize_type(t: str) -> str:
    """把数组参数类型（如 ``char *const []``）归一化为指针形式，便于拼 C 代码。"""
    return t.replace("[]", "*")


def is_variadic(meta: dict) -> bool:
    return "variadic_mode" in meta


def platform_enabled(meta: dict, platform: str) -> bool:
    """函数是否适用于目标平台（未声明 platforms 表示全平台）。"""
    platforms = meta.get("platforms")
    return platforms is None or platform in platforms


def load_signatures(path: str) -> dict:
    """加载签名模板表。

    预留：未来签名表改为加密二进制（bin）+ 系统密钥对解密时，只改此函数，
    其余代码（generate / gen_wrapper）不动。
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def gen_args_packing(args: list[dict]) -> list[str]:
    """根据 check 标注生成 vpo_args 打包代码。

    - check == "path"     -> 填 path / path2（依次）
    - check == "sockaddr" -> 填 addr + addrlen（下一个参数，若是指针则解引用）
    - check == "buffer"   -> 填 buf + buflen（下一个参数为长度）
    """
    lines = ["    vpo_args vargs;", "    memset(&vargs, 0, sizeof(vargs));"]
    path_idx = 0
    for i, a in enumerate(args):
        check = a.get("check")
        nxt = args[i + 1] if i + 1 < len(args) else None
        if check == "path":
            field = "path" if path_idx == 0 else "path2"
            lines.append(f"    vargs.{field} = {a['name']};")
            path_idx += 1
        elif check == "sockaddr":
            lines.append(f"    vargs.addr = {a['name']};")
            if nxt is not None:
                if "*" in nxt["type"]:
                    lines.append(f"    vargs.addrlen = *{nxt['name']};")
                else:
                    lines.append(f"    vargs.addrlen = {nxt['name']};")
        elif check == "buffer":
            lines.append(f"    vargs.buf = {a['name']};")
            if nxt is not None:
                lines.append(f"    vargs.buflen = {nxt['name']};")
            if args:
                lines.append(f"    vargs.fd = {args[0]['name']};")
        elif check == "iovec":
            lines.append(f"    vargs.buf = {a['name']};")
            if nxt is not None:
                lines.append(f"    vargs.buflen = {nxt['name']};")
            if args:
                lines.append(f"    vargs.fd = {args[0]['name']};")
            lines.append("    vargs.iovec = 1;")
        elif check == "inbound_buffer":
            lines.append(f"    vargs.buf = {a['name']};")
            if nxt is not None:
                lines.append(f"    vargs.buflen = {nxt['name']};")
            if args:
                lines.append(f"    vargs.fd = {args[0]['name']};")
            lines.append("    vargs.inbound = 1;")
    return lines


def env_mode_parts(
    meta: dict,
    arg_names: list[str],
    variadic: bool,
    deny_ret: str,
    in_var: str,
) -> tuple[list[str], str, list[str]]:
    """生成 P0-B 的环境注入代码。

    返回 (调用前代码, 真实函数调用参数, 调用后清理代码)。
    """
    mode = meta.get("env_mode")
    names = list(arg_names)
    pre: list[str] = []
    post: list[str] = []

    if mode == "replace":
        envp = meta.get("envp_arg", "envp")
        names = ["vpo_envp" if name == envp else name for name in names]
        pre = [
            f"    char **vpo_envp = vpo_envp_merge({envp});",
            "    if (!vpo_envp) {",
            f"        {in_var} = 0;",
            "        errno = ENOMEM;",
            f"        return {deny_ret};",
            "    }",
        ]
        post = [
            "    int vpo_saved_errno = errno;",
            "    vpo_envp_free(vpo_envp);",
            f"    {in_var} = 0;",
            "    errno = vpo_saved_errno;",
        ]
    elif mode == "reinject":
        pre = [
            "    if (vpo_reinject_environ() != 0) {",
            f"        {in_var} = 0;",
            "        errno = ENOMEM;",
            f"        return {deny_ret};",
            "    }",
        ]

    call_names = names + (["mode"] if variadic else [])
    return pre, ", ".join(call_names), post


def data_rewrite_lines(args: list[dict]) -> list[str]:
    """数据重写（外发消息 -> 蜜罐）：函数含 buffer 检查时，用 action.data_rewrite 替换 buf/长度。"""
    for i, a in enumerate(args):
        if a.get("check") == "buffer" and i + 1 < len(args):
            buf = a["name"]
            length = args[i + 1]["name"]
            return [
                "    if (action.data_rewrite) {",
                f"        {buf} = action.data_rewrite;",
                f"        {length} = action.data_rewrite_len;",
                "    }",
            ]
    return []


def inbound_buf_name(args: list[dict]) -> str | None:
    for a in args:
        if a.get("check") == "inbound_buffer":
            return a["name"]
    return None


def inbound_post_lines(func_name: str, buf_name: str) -> list[str]:
    return [
        f"    if (result > 0 && vpo_check_inbound(\"{func_name}\", {buf_name}, (size_t)result)) {{",
        f"        memset({buf_name}, 0, (size_t)result);",
        "        errno = EPERM;",
        "        result = -1;",
        "    }",
    ]


def gen_static_wrapper(
    name: str,
    meta: dict,
    real_symbol: str,
    interpose_cname: str,
    asm_label: Optional[str],
    suffix: str,
) -> list[str]:
    """生成形态 A（直接静态调用真实符号）的 wrapper。

    主符号（interpose `open`）和 $NOCANCEL 变体（interpose `open$NOCANCEL`）共用。
    asm_label 非空时，为含 `$` 的符号生成 asm 标签别名声明。
    """
    ret, _ = parse_signature(meta["signature"])
    args: list[dict] = meta.get("args", [])
    variadic = "variadic_mode" in meta

    arg_types = [normalize_type(a["type"]) for a in args]
    arg_decls = [f"{normalize_type(a['type'])} {a['name']}" for a in args]
    arg_names = [a["name"] for a in args]

    if variadic:
        typedef_args = ", ".join(arg_types + ["mode_t"])
    else:
        typedef_args = ", ".join(arg_types) if arg_types else "void"

    wrapper_args = ", ".join(arg_decls) + ", ..." if variadic else (", ".join(arg_decls) if arg_decls else "void")
    call_args = ", ".join(arg_names + ["mode"]) if variadic else ", ".join(arg_names)
    deny_ret = "NULL" if "*" in ret else "-1"
    args_packing = gen_args_packing(args)

    variadic_parse: list[str] = []
    if variadic:
        last_arg = arg_names[-1]
        variadic_parse = [
            "    mode_t mode = 0;",
            "    if (flags & O_CREAT) {",
            "        va_list ap;",
            f"        va_start(ap, {last_arg});",
            "        mode = (mode_t)va_arg(ap, int);",
            "        va_end(ap);",
            "    }",
        ]

    fn_name = f"my_{name}{suffix}"
    in_var = f"vpo_in_{name}{suffix}"
    env_pre, call_args_main, env_post = env_mode_parts(
        meta, arg_names, variadic, deny_ret, in_var
    )
    use_fork = bool(meta.get("use_fork"))
    reentry_call = "fork()" if use_fork else (
        f"{real_symbol}({', '.join(arg_names)}, 0)" if variadic else f"{real_symbol}({call_args})"
    )
    main_call = "fork()" if use_fork else f"{real_symbol}({call_args_main})"

    lines: list[str] = []
    if asm_label:
        lines.append(f'extern {ret} {interpose_cname}({typedef_args}) __asm("_" "{asm_label}");')
    lines.append(f"extern {ret} {real_symbol}({typedef_args});")
    lines.append(f"static __thread int {in_var} = 0;")
    lines.append("")
    lines.append(f"{ret} {fn_name}({wrapper_args}) {{")
    lines.append(f"    if ({in_var}) {{")
    lines.append(f"        return {reentry_call};")
    lines.append("    }")
    lines.append(f"    {in_var} = 1;")
    lines.extend(variadic_parse)
    lines.append("    vpo_action action = { .allow = 1 };")
    lines.extend(args_packing)
    lines.append(f'    vpo_check("{name}", &vargs, &action);')
    first_path = next((a for a in args if a.get("check") == "path"), None)
    lines.append("    if (!action.allow) {")
    if first_path:
        lines.append("        if (!action.rewrite) {")
        lines.append(f"            {in_var} = 0;")
        lines.append("            errno = EPERM;")
        lines.append(f"            return {deny_ret};")
        lines.append("        }")
        lines.append(f"        {first_path['name']} = action.rewrite;")
    else:
        lines.append(f"        {in_var} = 0;")
        lines.append("        errno = EPERM;")
        lines.append(f"        return {deny_ret};")
    lines.append("    }")
    lines.extend(env_pre)
    lines.extend(data_rewrite_lines(args))
    lines.append(f"    {ret} result = {main_call};")
    _ib = inbound_buf_name(args)
    if _ib:
        lines.extend(inbound_post_lines(name, _ib))
    lines.extend(env_post)
    if not env_post:
        lines.append(f"    {in_var} = 0;")
    lines.append("    return result;")
    lines.append("}")
    lines.append(f"DYLD_INTERPOSE({fn_name}, {interpose_cname})")
    return lines


def gen_wrapper(name: str, meta: dict) -> str:
    ret, fname = parse_signature(meta["signature"])
    args: list[dict] = meta.get("args", [])
    variadic = is_variadic(meta)

    real_symbol = MACOS_REAL_SYMBOL.get(name)

    arg_types = [normalize_type(a["type"]) for a in args]
    arg_decls = [f"{normalize_type(a['type'])} {a['name']}" for a in args]
    arg_names = [a["name"] for a in args]

    # --- typedef / extern 声明的参数列表 ---
    if variadic:
        typedef_args = ", ".join(arg_types + ["mode_t"])
    else:
        typedef_args = ", ".join(arg_types) if arg_types else "void"

    # --- wrapper 定义参数 ---
    if variadic:
        wrapper_args = ", ".join(arg_decls) + ", ..."
    else:
        wrapper_args = ", ".join(arg_decls) if arg_decls else "void"

    # --- 调用真实函数的参数 ---
    if variadic:
        call_args = ", ".join(arg_names + ["mode"])
    else:
        call_args = ", ".join(arg_names)

    # --- deny 时的返回值 ---
    deny_ret = "NULL" if "*" in ret else "-1"
    in_var = f"vpo_in_{name}"
    env_pre, call_args_main, env_post = env_mode_parts(
        meta, arg_names, variadic, deny_ret, in_var
    )

    lines: list[str] = []
    lines.append(f"/* ---- {name} : {meta['signature']} ---- */")

    # 变参解析代码（O_CREAT -> mode_t）
    variadic_parse: list[str] = []
    if variadic:
        last_arg = arg_names[-1]
        variadic_parse = [
            "    mode_t mode = 0;",
            "    if (flags & O_CREAT) {",
            "        va_list ap;",
            f"        va_start(ap, {last_arg});",
            "        mode = (mode_t)va_arg(ap, int);",
            "        va_end(ap);",
            "    }",
        ]

    args_packing = gen_args_packing(args)

    if real_symbol:
        # ---- 形态 A：主符号 + $NOCANCEL 变体（直接静态调用私有符号）----
        lines.extend(gen_static_wrapper(name, meta, real_symbol, name, None, ""))
        nocancel = MACOS_NOCANCEL_INTERPOSE.get(name)
        if nocancel:
            public, cname, real_nc = nocancel
            lines.append(f"/* ---- {name} 的 $NOCANCEL 变体 ---- */")
            lines.extend(gen_static_wrapper(name, meta, real_nc, cname, public, "_nocancel"))
        lines.append("")
    else:
        # ---- 形态 B：dlsym 懒加载（$NOCANCEL 变体，可绕过 interpose）----
        lines.append(f"typedef {ret} (*vpo_real_{name}_t)({typedef_args});")
        lines.append(f"static vpo_real_{name}_t vpo_real_{name} = NULL;")
        lines.append(f"static __thread int vpo_in_{name} = 0;")
        lines.append("")
        lines.append(f"{ret} my_{name}({wrapper_args}) {{")
        lines.append(f"    if (vpo_in_{name}) {{")
        if variadic:
            lines.append(f"        return vpo_real_{name}({', '.join(arg_names)}, 0);")
        else:
            lines.append(f"        return vpo_real_{name}({call_args});")
        lines.append("    }")
        lines.append(f"    vpo_in_{name} = 1;")
        lines.extend(variadic_parse)
        lines.append("    vpo_action action = { .allow = 1 };")
        lines.extend(args_packing)
        lines.append(f'    vpo_check("{name}", &vargs, &action);')
        lines.append("    if (!action.allow) {")
        lines.append(f"        vpo_in_{name} = 0;")
        lines.append("        errno = EPERM;")
        lines.append(f"        return {deny_ret};")
        lines.append("    }")
        lines.extend(env_pre)
        lines.extend(data_rewrite_lines(args))
        lookup_mode = "RTLD_DEFAULT" if name in MACOS_NOCANCEL_SYMBOL else "RTLD_NEXT"
        lookup_sym = MACOS_NOCANCEL_SYMBOL.get(name, name)
        lines.append(f"    if (!vpo_real_{name}) {{")
        lines.append(
            f'        vpo_real_{name} = (vpo_real_{name}_t)dlsym({lookup_mode}, "{lookup_sym}");'
        )
        lines.append("    }")
        lines.append(
            f"    if (!vpo_real_{name} || (void *)vpo_real_{name} == (void *)my_{name}) {{"
        )
        if env_post:
            lines.append("        vpo_envp_free(vpo_envp);")
        lines.append(f"        {in_var} = 0;")
        lines.append("        errno = ENOSYS;")
        lines.append(f"        return {deny_ret};")
        lines.append("    }")
        lines.append(f"    {ret} result = vpo_real_{name}({call_args_main});")
        _ib = inbound_buf_name(args)
        if _ib:
            lines.extend(inbound_post_lines(name, _ib))
        lines.extend(env_post)
        if not env_post:
            lines.append(f"    {in_var} = 0;")
        lines.append("    return result;")
        lines.append("}")
        lines.append(f"DYLD_INTERPOSE(my_{name}, {name})")
        lines.append("")

    return "\n".join(lines)


def gen_linux_wrapper(name: str, meta: dict, c_name: Optional[str] = None) -> str:
    """生成 Linux 版 wrapper：同名符号 + dlsym(RTLD_NEXT)（LD_PRELOAD 机制）。

    c_name 用于 LFS 别名（如 open64/fopen64）：生成的 C 符号与 dlsym 查询名用
    c_name，但签名、参数检查和策略逻辑复用原函数 meta。
    """
    c_name = c_name or name
    ret, _ = parse_signature(meta["signature"])
    args: list[dict] = meta.get("args", [])
    variadic = is_variadic(meta)

    arg_types = [normalize_type(a["type"]) for a in args]
    arg_decls = [f"{normalize_type(a['type'])} {a['name']}" for a in args]
    arg_names = [a["name"] for a in args]

    typedef_args = ", ".join(arg_types + ["mode_t"]) if variadic else (", ".join(arg_types) if arg_types else "void")
    wrapper_args = ", ".join(arg_decls) + ", ..." if variadic else (", ".join(arg_decls) if arg_decls else "void")
    call_args = ", ".join(arg_names + ["mode"]) if variadic else ", ".join(arg_names)
    deny_ret = "NULL" if "*" in ret else "-1"
    in_var = f"vpo_in_{c_name}"
    env_pre, call_args_main, env_post = env_mode_parts(
        meta, arg_names, variadic, deny_ret, in_var
    )
    use_fork = bool(meta.get("use_fork"))
    reentry_call = "fork()" if use_fork else (
        f"vpo_real_{c_name}({', '.join(arg_names)}, 0)" if variadic else f"vpo_real_{c_name}({call_args})"
    )
    main_call = "fork()" if use_fork else f"vpo_real_{c_name}({call_args_main})"
    args_packing = gen_args_packing(args)

    variadic_parse: list[str] = []
    if variadic:
        last_arg = arg_names[-1]
        variadic_parse = [
            "    mode_t mode = 0;",
            "    if (flags & O_CREAT) {",
            "        va_list ap;",
            f"        va_start(ap, {last_arg});",
            "        mode = (mode_t)va_arg(ap, int);",
            "        va_end(ap);",
            "    }",
        ]

    first_path = next((a for a in args if a.get("check") == "path"), None)

    lines: list[str] = []
    lines.append(f"/* ---- {c_name} : {meta['signature']} ---- */")
    lines.append(f"typedef {ret} (*vpo_real_{c_name}_t)({typedef_args});")
    lines.append(f"static vpo_real_{c_name}_t vpo_real_{c_name} = NULL;")
    lines.append(f"static __thread int vpo_in_{c_name} = 0;")
    lines.append("")
    lines.append(f"{ret} {c_name}({wrapper_args}) {{")
    lines.append(f"    if (vpo_in_{c_name}) {{")
    lines.append(f"        return {reentry_call};")
    lines.append("    }")
    lines.append(f"    vpo_in_{c_name} = 1;")
    lines.extend(variadic_parse)
    lines.append("    vpo_action action = { .allow = 1 };")
    lines.extend(args_packing)
    lines.append(f'    vpo_check("{c_name}", &vargs, &action);')
    lines.append("    if (!action.allow) {")
    if first_path:
        lines.append("        if (!action.rewrite) {")
        lines.append(f"            vpo_in_{c_name} = 0;")
        lines.append("            errno = EPERM;")
        lines.append(f"            return {deny_ret};")
        lines.append("        }")
        lines.append(f"        {first_path['name']} = action.rewrite;")
    else:
        lines.append(f"        vpo_in_{c_name} = 0;")
        lines.append("        errno = EPERM;")
        lines.append(f"        return {deny_ret};")
    lines.append("    }")
    lines.extend(env_pre)
    lines.extend(data_rewrite_lines(args))
    lines.append(f"    if (!vpo_real_{c_name}) {{")
    lines.append(f'        vpo_real_{c_name} = (vpo_real_{c_name}_t)dlsym(RTLD_NEXT, "{c_name}");')
    lines.append("    }")
    lines.append(f"    {ret} result = {main_call};")
    _ib = inbound_buf_name(args)
    if _ib:
        lines.extend(inbound_post_lines(c_name, _ib))
    lines.extend(env_post)
    if not env_post:
        lines.append(f"    {in_var} = 0;")
    lines.append("    return result;")
    lines.append("}")
    return "\n".join(lines)


def count_linux_wrappers(data: dict) -> int:
    """统计 Linux 实际生成的 wrapper 数（主符号 + LFS 别名）。"""
    n = 0
    for _name, meta in data.get("functions", {}).items():
        if not platform_enabled(meta, "linux"):
            continue
        n += 1 + len(meta.get("linux_aliases", []))
    return n


def macos_skipped(data: dict) -> list[str]:
    return [
        name
        for name, meta in data.get("functions", {}).items()
        if name in MACOS_SKIP or not platform_enabled(meta, "darwin")
    ]


def generate_linux(data: dict, only_names: set[str] | None = None) -> str:
    functions: dict = data.get("functions", {})
    body = [LINUX_HEADER]
    for name, meta in functions.items():
        if not platform_enabled(meta, "linux"):
            continue
        if only_names is not None and name not in only_names:
            continue
        body.append(gen_linux_wrapper(name, meta))
        for alias in meta.get("linux_aliases", []):
            body.append(gen_linux_wrapper(alias, meta, c_name=alias))
    return "".join(body)


def generate(data: dict, platform: str = "darwin", only_names: set[str] | None = None) -> str:
    if platform == "linux":
        return generate_linux(data, only_names)
    functions: dict = data.get("functions", {})
    body = [HEADER]
    skipped = set(macos_skipped(data))
    for name, meta in functions.items():
        if name in skipped:
            continue
        if only_names is not None and name not in only_names:
            continue
        body.append(gen_wrapper(name, meta))
    return "".join(body)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="生成 VPO-Hook wrapper 源码")
    parser.add_argument("signatures", help="签名模板表 JSON 路径")
    parser.add_argument("-o", "--output", default="wrapper.c", help="输出 C 文件路径")
    parser.add_argument(
        "-p", "--platform", default="darwin", choices=["darwin", "linux"],
        help="目标平台（darwin=DYLD_INTERPOSE，linux=同名符号+RTLD_NEXT）",
    )
    parser.add_argument(
        "--only", default=None,
        help="只生成这些函数（逗号分隔，用于按包定制）",
    )
    args = parser.parse_args(argv)

    data = load_signatures(args.signatures)
    only_names = set(args.only.split(",")) if args.only else None

    code = generate(data, args.platform, only_names)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(code)

    if args.platform == "linux":
        n = count_linux_wrappers(data)
        label = f"{n} 个 wrapper (Linux)"
        if only_names is not None:
            label += f"，subset={len(only_names)}"
        print(f"gen_wrappers: 已生成 {label} -> {args.output}")
    else:
        skipped = macos_skipped(data)
        n = len(data.get("functions", {})) - len(skipped)
        print(f"gen_wrappers: 已生成 {n} 个 wrapper -> {args.output}")
        if skipped:
            print(
                f"gen_wrappers: 跳过 {len(skipped)} 个 (macOS 无法安全 interpose): "
                f"{', '.join(skipped)}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
