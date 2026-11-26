# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the SIDE tools: console output, file hashes, folder locks and service runs.

The installer copies this module next to side_service.py, because the service and side_store
import it.

Design notes

- The service and the installer run as SYSTEM or as an administrator, so Windows tools are called
  by their full path under System32.  A bare name would be searched in the current folder and on
  PATH first.
- A console with a non-UTF-8 code page cannot print every character.  A file name outside its
  table would raise UnicodeEncodeError mid-run and end a verification with exit code 1.
  keep_output_alive switches stdout and stderr to backslashreplace instead.
- say flushes each line, so the output keeps its order next to subprocess output.
- run_service with isolated adds -I, so the child ignores the environment and user site-packages
  as the installed service does.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys
from datetime import datetime

SYS32 = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
ICACLS = str(SYS32 / "icacls.exe")
WHOAMI = str(SYS32 / "whoami.exe")
NET = str(SYS32 / "net.exe")
SCHTASKS = str(SYS32 / "schtasks.exe")
POWERSHELL = str(SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")
SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
HASH_BLOCK = 1 << 20
RULE = 62
STAMP = "%Y%m%d_%H%M%S"


def keep_output_alive() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def now_stamp() -> str:
    return datetime.now().strftime(STAMP)


def say(s: str = "") -> None:
    print(s, flush=True)


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for blk in iter(lambda: f.read(HASH_BLOCK), b""):
            h.update(blk)
    return h.hexdigest()


def local_time(s, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not s:
        return "-"
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone().strftime(fmt)
    except ValueError:
        return str(s)


def full_control(*sids: str) -> list[str]:
    return ["*%s:(OI)(CI)F" % s for s in sids]


def lock_folder(path: pathlib.Path, *extra_sids: str) -> subprocess.CompletedProcess:
    return subprocess.run([ICACLS, str(path), "/inheritance:r", "/grant:r",
                           *full_control(SID_SYSTEM, SID_ADMINS, *extra_sids)],
                          capture_output=True, text=True, encoding="mbcs", errors="replace")


def run_service(script: pathlib.Path, *args, store: pathlib.Path | None = None,
                cwd: pathlib.Path | None = None, isolated: bool = False,
                record: list | None = None) -> tuple[int, str]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    if store:
        env["SIDE_STORE"] = str(store)
    flags = ["-I", "-X", "utf8"] if isolated else []
    r = subprocess.run([sys.executable, *flags, str(script), *map(str, args)], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=env,
                       cwd=str(cwd) if cwd else None)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        say("    " + line)
        if record is not None:
            record.append(line)
    return r.returncode, out
