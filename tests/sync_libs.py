# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
r"""Keep the lib\ folders of employee\, organization\ and verifier\ equal, so each role folder works alone.

A file that several roles use must be the same in every lib\ that holds it.  After changing a file in one
lib\, copy it to the others; the end-to-end test fails while copies differ.

  python tests\sync_libs.py                    check only (exit code 1 if anything differs)
  python tests\sync_libs.py --from employee    copy the files of employee\lib\ to the other lib\ folders
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ["side.py", "side_core.py", "side_store.py", "side_util.py", "side_bind.py", "side_verify.py",
        "side_service.py", "run.cmd", "find_python.cmd"]
ROLES = {
    "employee": CORE + ["side_device.py", "elevate.cmd"],
    "organization": CORE + ["side_org.py", "disclose.py", "viewer.py", "side_logo.ico", "check_package.cmd",
                            "viewer.cmd"],
    "verifier": CORE + ["side_org.py", "viewer.py", "side_logo.ico", "check_package.cmd", "viewer.cmd"],
}


def lib(role: str) -> pathlib.Path:
    return ROOT / role / "lib"


def differences() -> list[str]:
    out = []
    for role, names in ROLES.items():
        for n in names:
            if not (lib(role) / n).exists():
                out.append("%s\\lib\\%s is missing" % (role, n))
        if lib(role).is_dir():
            out += ["%s\\lib\\%s does not belong there" % (role, p.name)
                    for p in lib(role).iterdir() if p.is_file() and p.name not in names]
    for n in sorted({n for names in ROLES.values() for n in names}):
        holders = [r for r, names in ROLES.items() if n in names and (lib(r) / n).exists()]
        if len({(lib(r) / n).read_bytes() for r in holders}) > 1:
            out.append("%s differs between %s" % (n, ", ".join("%s\\lib" % r for r in holders)))
    return out


def copy_from(source: str) -> None:
    for n in ROLES[source]:
        data = (lib(source) / n).read_bytes()
        for role, names in ROLES.items():
            if role != source and n in names and (lib(role) / n).read_bytes() != data:
                (lib(role) / n).write_bytes(data)
                print("%s\\lib\\%s  <-  %s\\lib\\%s" % (role, n, source, n))


def main(argv: list[str]) -> int:
    if "--from" in argv:
        i = argv.index("--from")
        source = argv[i + 1] if i + 1 < len(argv) else ""
        if source not in ROLES:
            print("Give the role whose lib\\ you changed: --from %s" % " | ".join(ROLES))
            return 2
        copy_from(source)
    diff = differences()
    for d in diff:
        print(d)
    print("lib folders: %s" % ("differ" if diff else "equal"))
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
