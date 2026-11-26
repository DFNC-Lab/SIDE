# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
r"""SIDE: one entry point for the three roles.  The .bat files in each role folder run it.

  python side.py organization seal-key
  python side.py organization receive <SIDE_collection_*.zip> --custody <SIDE_custody_*>
                                      --seal-private-key <seal_secret.hex>
  python side.py organization disclose [--chain N --range 5-9,12] [--lines]

  python side.py employee install [--employee <account>] [--key-out <folder>]   (administrator)
  python side.py employee root-key --key-out <folder>                          (administrator)
  python side.py employee status | collect [--include-logs] | uninstall        (administrator)

  python side.py verifier                                                      opens the viewer window
  python side.py verifier check <SIDE_disclosure_*.json> --seal-public-key <seal_pub.hex>
                                [--lines <*.lines.jsonl>]

Each role keeps its files in its own folder next to this file: organization\, employee\, verifier\.
"""
from __future__ import annotations

import pathlib
import sys

SRC = pathlib.Path(__file__).resolve().parent / "src"
sys.path.insert(0, str(SRC))

ROLES = ("organization", "employee", "verifier")


def usage(code: int = 2) -> int:
    print(__doc__.strip())
    return code


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        return usage(0 if argv else 2)
    role, rest = argv[0], argv[1:]
    if role not in ROLES:
        print("Unknown role '%s'.  Choose one of: %s\n" % (role, ", ".join(ROLES)))
        return usage()
    if role == "organization":
        import side_org
        sys.argv = ["side.py organization", *rest]
        return side_org.main()
    if role == "employee":
        import side_device
        sys.argv = ["side.py employee", *rest]
        return side_device.main()
    if not rest:
        try:
            import viewer
        except ImportError as exc:
            raise SystemExit("The viewer window needs tkinter (%s).\n"
                             "Reinstall Python from python.org with 'tcl/tk and IDLE' turned on,\n"
                             "or use: python side.py verifier check <package> --seal-public-key <key>" % exc)
        viewer.Viewer().mainloop()
        return 0
    if rest[0] == "check":
        import side_org
        sys.argv = ["side.py verifier", "verify-package", *rest[1:]]
        return side_org.main()
    print("Unknown verifier command '%s'.\n" % rest[0])
    return usage()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
