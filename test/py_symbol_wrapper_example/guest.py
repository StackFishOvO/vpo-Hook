#!/usr/bin/env python3
"""Guest code: every call below is plaintext Python.  No special API."""

from __future__ import annotations

import csv
import os
import posix
import subprocess

import legacy_alias


def line(label: str, value: object) -> None:
    print(f"[guest] {label}: {value}", flush=True)


line("os.getcwd()", os.getcwd())
line("os.system has __wrapped__", hasattr(os.system, "__wrapped__"))

# 1. DENY: os.system is bound directly.
try:
    os.system("echo '[guest] os.system should never run'")
except PermissionError as exc:
    line("os.system denied", exc)

# 2. ASK: subprocess.run is allowed only for the command `echo`.
try:
    completed = subprocess.run(
        ["echo", "[guest] subprocess.run allowed by ASK"],
        check=False,
        text=True,
    )
    line("subprocess.run echo returncode", completed.returncode)
except PermissionError as exc:
    line("subprocess.run echo denied", exc)

try:
    subprocess.run(["rm", "-rf", "/tmp/definitely-not-real"], check=False)
except PermissionError as exc:
    line("subprocess.run rm denied", exc)

# 3. SUBSTITUTE: os.getcwd returns a fake value.
line("os.getcwd() again", os.getcwd())

# 4. Alias that existed before binding was repaired by sweep().
try:
    legacy_alias.legacy_system("echo '[guest] legacy alias should never run'")
except PermissionError as exc:
    line("legacy alias denied", exc)

# 5. Module imported after the guard was sealed; import_hook bound csv.reader.
try:
    list(csv.reader(["a,b"]))
except PermissionError as exc:
    line("csv.reader denied", exc)

# 6. Plaintext bypasses: these names were not bound.
proc = subprocess.Popen(
    ["echo", "[guest] subprocess.Popen bypassed (Popen was not bound)"],
    stdout=subprocess.PIPE,
    text=True,
)
out, _ = proc.communicate()
line("Popen output", out.strip())

line("os.popen output", os.popen("echo '[guest] os.popen bypassed (os.popen was not bound)'").read().strip())

if hasattr(posix, "system"):
    posix.system("echo '[guest] posix.system bypassed (another module/name)'")
else:
    line("posix.system", "not available on this platform")
