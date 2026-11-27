# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
r"""SIDE: one entry point for the three roles.  The .bat files of each role folder run lib\side.py.

Run it from the role folder (each folder works on its own):
  organization\  python lib\side.py organization seal-key
                 python lib\side.py organization receive <SIDE_collection_*.zip> --custody <SIDE_custody_*>
                                                         --seal-private-key <seal_secret.hex>
                 python lib\side.py organization disclose [--chain N --range 5-9,12] [--lines]
  employee\      python lib\side.py employee install [--employee <account>] [--key-out <folder>]
                 python lib\side.py employee root-key --key-out <folder>
                 python lib\side.py employee status | collect [--include-logs] | uninstall
                 (employee commands need administrator rights)
  verifier\      python lib\side.py verifier                    opens the viewer window
                 python lib\side.py verifier check <SIDE_disclosure_*.json> --seal-public-key <seal_pub.hex>
                                                   [--lines <*.lines.jsonl>]
"""
from __future__ import annotations

import importlib
import pathlib
import sys

SRC = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

ROLES = {"organization": "side_org", "employee": "side_device", "verifier": "side_org"}


def usage(code: int = 2) -> int:
    print(__doc__.strip())
    return code


def load(role: str, module: str):
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as exc:
        if exc.name != module:
            raise
        raise SystemExit("This folder (%s) does not hold the %s tools.  Use the %s\\ folder."
                         % (SRC.parent, role, role)) from None


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        return usage(0 if argv else 2)
    role, rest = argv[0], argv[1:]
    if role not in ROLES:
        print("Unknown role '%s'.  Choose one of: %s\n" % (role, ", ".join(ROLES)))
        return usage()
    if role == "organization":
        sys.argv = ["side.py organization", *rest]
        return load(role, "side_org").main()
    if role == "employee":
        sys.argv = ["side.py employee", *rest]
        return load(role, "side_device").main()
    if not rest:
        if not (SRC / "viewer.py").exists():
            raise SystemExit("This folder (%s) does not hold the viewer.  Use the verifier\\ folder."
                             % SRC.parent)
        try:
            importlib.import_module("tkinter")
        except ImportError as exc:
            raise SystemExit("The viewer window needs tkinter (%s).\n"
                             "Reinstall Python from python.org with 'tcl/tk and IDLE' turned on,\n"
                             "or use: python lib\\side.py verifier check <package> --seal-public-key <key>"
                             % exc)
        import viewer
        viewer.Viewer().mainloop()
        return 0
    if rest[0] == "check":
        sys.argv = ["side.py verifier", "verify-package", *rest[1:]]
        return load(role, "side_org").main()
    print("Unknown verifier command '%s'.\n" % rest[0])
    return usage()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
