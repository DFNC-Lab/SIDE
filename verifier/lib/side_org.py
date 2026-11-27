# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
r"""SIDE organization tools (Phase 0 and Phase 2): seal key, receive, disclose, verify a package.

Runs on an organization PC, never on the employee PC.

  python lib\side.py organization seal-key
  python lib\side.py organization receive <SIDE_collection_*.zip> --custody <SIDE_custody_*>
                                      --seal-private-key <seal_secret.hex>
  python lib\side.py organization disclose [--chain N --range 5-9,12] [--lines]
  python lib\side.py verifier check <SIDE_disclosure_*.json> --seal-public-key <seal_pub.hex>
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

SRC = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

import side_core as core
import side_store as store
import side_util as util
from side_util import say

HERE = SRC.parent
SERVICE = SRC / "side_service.py"
DISCLOSE = SRC / "disclose.py"
RECEIVED = HERE / "received"
SEAL_PUB_NAME = core.SEAL_PUB_NAME
RESULT_NAME = "verification_result.txt"
RULE = util.RULE


def service(*args, store_dir: pathlib.Path | None = None, record: list | None = None) -> int:
    return util.run_service(SERVICE, *args, store=store_dir, cwd=HERE, record=record)[0]


def match(same: bool) -> str:
    return "match" if same else "mismatch"


def make_seal_key(a) -> int:
    key_dir = pathlib.Path(a.dir) if a.dir else (HERE / "org_keys")
    rc = service("--gen-seal-keypair", key_dir)
    if rc:
        return rc
    public = HERE / SEAL_PUB_NAME
    shutil.copyfile(key_dir / SEAL_PUB_NAME, public)
    say("")
    say("  For the device   : %s" % public)
    say("                     Put it into the employee folder on the employee PC "
        "and run employee\\1_install.bat.")
    say("  For the verifier : the same public key (send it separately from the disclosure package)")
    say("  Private key      : %s.  Never let it leave this machine." % (key_dir / core.SEAL_SECRET_NAME))
    return 0


def receive_collection(a) -> int:
    zp = pathlib.Path(a.zip).resolve()
    custody = pathlib.Path(a.custody).resolve()
    if not zipfile.is_zipfile(zp):
        say("Not a collection zip, or the file does not exist: %s" % zp)
        return 1
    for f in (core.K0_NAME, core.ENROLL_NAME, SEAL_PUB_NAME):
        if not (custody / f).exists():
            say("The organization custody copy has no %s: %s" % (f, custody))
            return 1
    dest = RECEIVED / zp.stem
    if dest.exists():
        say("This archive was already received: %s  (move that folder away to receive it again)" % dest)
        return 1
    dest.mkdir(parents=True)
    say("=" * RULE)
    say("  SIDE receive the collection: %s" % zp.name)
    say("=" * RULE)
    result = ["SIDE receive the collection · %s" % zp.name, ""]

    say("\n[1/4] Extracting and comparing with the manifest")
    with zipfile.ZipFile(zp) as zf:
        for n in zf.namelist():
            t = (dest / n).resolve()
            if dest not in t.parents and t != dest:
                say("    A path in the zip points outside the folder: %s.  Stopping." % n)
                return 1
        zf.extractall(dest)
    manifest = json.loads((dest / "00_manifest.json").read_text(encoding="utf-8"))
    wrong = [f["path"] for f in manifest["files"]
             if not (dest / f["path"]).exists() or util.sha256_file(dest / f["path"]) != f["sha256"]]
    say("    %d files · %d differ from the manifest" % (len(manifest["files"]), len(wrong)))
    result.append("Manifest check: %d files, %d differ %s" % (len(manifest["files"]), len(wrong), wrong[:5]))
    if wrong:
        say("    ! Some files differ from the manifest.  Stopping without the seal signature.")
        (dest / RESULT_NAME).write_text("\n".join(result), encoding="utf-8")
        return 1

    say("\n[2/4] Comparing the enrollment certificate with the organization custody copy")
    a_ = json.loads((dest / core.ENROLL_NAME).read_text(encoding="utf-8"))
    b_ = json.loads((custody / core.ENROLL_NAME).read_text(encoding="utf-8"))
    same = a_ == b_
    packed_pub = store.find_seal_pub(dest)
    try:
        pub_same = bool(packed_pub) and (store.read_seal_public_key(packed_pub)
                                         == store.read_seal_public_key(custody / SEAL_PUB_NAME))
    except ValueError:
        pub_same = False
    say("    enrollment certificate %s · seal public key %s" % (match(same), match(pub_same)))
    result.append("Enrollment certificate: %s, seal public key: %s" % (match(same), match(pub_same)))
    if not (same and pub_same):
        say("    ! This archive did not come from the device of this custody copy, "
            "or its certificate changed.  Stopping.")
        (dest / RESULT_NAME).write_text("\n".join(result), encoding="utf-8")
        return 1

    say("\n[3/4] Adding the organization seal signature")
    rc = service("--countersign", "--seal-secret", pathlib.Path(a.seal_private_key).resolve(),
                 store_dir=dest, record=result)
    if rc:
        return rc

    say("\n[4/4] Verifying with the root key and the seal public key (C1-C4)")
    args = ["--verify", "--org-key", custody / core.K0_NAME, "--seal-pub", custody / SEAL_PUB_NAME,
            "--require-sig"]
    if (dest / core.SESSIONS_DIR).is_dir():
        args += ["--sessions-dir", dest / core.SESSIONS_DIR]
    else:
        args += ["--skip-source"]
        pre = "passed" if manifest.get("precollection_check_passed") else "findings present"
        say("    No session logs received.  "
            "C3 and C4 follow the precollection check of the device (%s)." % pre)
        result.append("Session logs not included: precollection check on the device %s" % pre)
    result.append("")
    rc = service(*args, store_dir=dest, record=result)
    (dest / RESULT_NAME).write_text("\n".join(result) + "\n", encoding="utf-8")
    say("\n" + "-" * RULE)
    say("  Received into       : %s" % dest)
    say("  Verification result : %s  (%s)"
        % ("no findings" if rc == 0 else "findings present, see verification_result.txt",
           dest / RESULT_NAME))
    say("  To disclose only the relevant part: organization\\3_disclose.bat")
    say("-" * RULE)
    return rc


def disclose(a, rest: list) -> int:
    if a.collection:
        dest = pathlib.Path(a.collection).resolve()
    else:
        candidates = sorted((p for p in RECEIVED.glob("*") if (p / core.CHAINS_DIR).is_dir()),
                            key=lambda p: p.stat().st_mtime) if RECEIVED.exists() else []
        if not candidates:
            say("No received collection.  Run organization\\2_receive_collection.bat first.")
            return 1
        dest = candidates[-1]
        say("Collection: %s" % dest)
    env = dict(os.environ, SIDE_STORE=str(dest), PYTHONIOENCODING="utf-8", SIDE_OUT=str(HERE / "disclosures"))
    if (dest / core.SESSIONS_DIR).is_dir():
        env["SIDE_SESSIONS_DIR"] = str(dest / core.SESSIONS_DIR)
    return subprocess.call([sys.executable, str(DISCLOSE), *rest], env=env, cwd=str(HERE))


def verify_package(a) -> int:
    key = pathlib.Path(a.seal_public_key)
    if not key.exists() and not re.fullmatch(r"[0-9a-fA-F]{64}", a.seal_public_key.strip()):
        say("Seal public key file not found, and not a 64-digit value: %s" % a.seal_public_key)
        return 1
    args = ["--verify-package", pathlib.Path(a.package).resolve(), "--seal-pub",
            key.resolve() if key.exists() else a.seal_public_key]
    if a.lines:
        args += ["--lines", pathlib.Path(a.lines).resolve()]
    return service(*args)


def main() -> int:
    ap = argparse.ArgumentParser(description="SIDE organization tools")
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("seal-key")
    s.add_argument("--dir", help="folder for the key pair (default: org_keys\\ in this folder)")
    s = sub.add_parser("receive")
    s.add_argument("zip")
    s.add_argument("--custody", required=True, help="SIDE_custody_* folder moved off the device at install")
    s.add_argument("--seal-private-key", required=True, help="seal_secret.hex")
    s = sub.add_parser("disclose")
    s.add_argument("--collection", help="folder under received\\ (default: the most recent)")
    s = sub.add_parser("verify-package")
    s.add_argument("package")
    s.add_argument("--seal-public-key", required=True, help="seal_pub.hex (or the 64-digit value)")
    s.add_argument("--lines", help="line text file received with the package (*.lines.jsonl)")
    a, rest = ap.parse_known_args()
    if rest and a.command != "disclose":
        ap.error("unrecognized arguments: %s" % " ".join(rest))
    util.keep_output_alive()
    if a.command == "seal-key":
        return make_seal_key(a)
    if a.command == "receive":
        return receive_collection(a)
    if a.command == "disclose":
        return disclose(a, rest)
    return verify_package(a)


if __name__ == "__main__":
    sys.exit(main())
