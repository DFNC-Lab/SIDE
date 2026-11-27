# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE end-to-end test: the whole flow from the seal key to the verdict, with no admin rights.

The service folder points to a temporary folder and side_service runs directly in place of the
scheduled task.  Every other step runs the release code unchanged.

  python tests/test_end_to_end.py        (SIDE_E2E_KEEP=<folder> keeps the temporary files)
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[1]
EMP = REPO / "employee" / "lib"
ORG = REPO / "organization" / "lib"
VER = REPO / "verifier" / "lib"
CD = EMP / "side_service.py"
OUT = REPO / "tests" / "results" / "end_to_end.csv"
results = []


def check(name, ok, detail=""):
    results.append((name, "PASS" if ok else "FAIL", detail))
    print("  %s  %s  %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def cd(store, *args):
    env = dict(os.environ, SIDE_STORE=str(store), PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, str(CD), *map(str, args)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def quietly(f, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = f(*a, **k)
    return rc, buf.getvalue()


def prepare_device(T, name):
    dev = load_module(EMP / "side_device.py", "side_device_" + name)
    base = T / name / "ProgramData" / "SIDE"
    dev.HERE = T / name / "employee"
    dev.BASE, dev.BIN, dev.STORE, dev.ORG = base, base / "bin", base / "store", base / "org"
    dev.ORGKEY, dev.SEAL_PUB = dev.ORG / "k0.hex", dev.ORG / "seal_pub.hex"
    dev.ENROLL_LOG, dev.STOPFILE = dev.ORG / "enroll.log", dev.ORG / "STOP"
    dev.DEVICE, dev.KEYS = dev.STORE / "chains" / "_device.chain.json", dev.STORE / "keys"
    dev.INSTALL_RECORD = base / "install.json"
    dev.stop_service = lambda max_seconds=900: True
    for d in (dev.BIN, dev.ORG, dev.HERE):
        d.mkdir(parents=True, exist_ok=True)
    for n in dev.RUNTIME:
        shutil.copy2(EMP / n, dev.BIN / n)
    return dev


def main() -> int:
    T = pathlib.Path(tempfile.mkdtemp(prefix="side_e2e_"))
    print("temporary folder", T)
    libs = load_module(REPO / "tests" / "sync_libs.py", "sync_libs").differences()
    check("L0 the lib folders of employee, organization and verifier are equal (python tests\\sync_libs.py)",
          not libs, "; ".join(libs[:3]))
    org = load_module(ORG / "side_org.py", "side_org")
    org.HERE = T / "organization"
    org.RECEIVED = org.HERE / "received"
    org.HERE.mkdir(parents=True)

    rc, out = quietly(org.make_seal_key, argparse.Namespace(dir=None))
    pub = (org.HERE / "seal_pub.hex").read_text(encoding="utf-8").strip()
    check("O1 organization seal key pair (public key file name seal_pub.hex)", rc == 0 and len(pub) == 64
          and (org.HERE / "org_keys" / "seal_secret.hex").exists())

    home = T / "home"
    s1 = home / ".claude" / "projects" / "proj" / "s1.jsonl"
    s2 = home / ".codex" / "sessions" / "2026" / "11" / "s2.jsonl"
    for s in (s1, s2):
        s.parent.mkdir(parents=True)
        s.write_bytes(b"".join(b'{"i":%d,"t":"hello %d"}\n' % (i, i) for i in range(12)))

    zips = {}
    for name, include_logs in (("A", False), ("B", True)):
        dev = prepare_device(T, name)
        key_name = "seal_pub.hex" if name == "A" else "seal_pub.key"
        (dev.HERE / key_name).write_text(pub, encoding="utf-8")
        check("D0-%s read seal public key (%s)" % (name, key_name),
              dev.read_seal_pub() == pub)
        pats = dev.session_patterns(home)
        wc = dev.watch_cmd(pathlib.Path(sys.executable), pats)
        check("D1-%s watch.cmd batch file" % name,
              all(x in wc for x in ("-I -X utf8", "--seal-pubkey", "--restart-on-error 5", str(dev.STOPFILE),
                                    "/inheritance:r", "GEQ 1000", "--interval 2")))
        dev.SEAL_PUB.write_text(pub, encoding="utf-8")
        rc, out = cd(dev.STORE, "--enroll", "--org-out", dev.ORGKEY, "--seal-pubkey", dev.SEAL_PUB)
        enroll = json.loads((dev.STORE / "enroll.json").read_text(encoding="utf-8"))
        check("D2-%s enrollment: organization key, K0 not on screen" % name,
              rc == 0 and enroll["seal_key_origin"] == "organization" and dev.ORGKEY.exists()
              and dev.ORGKEY.read_text().strip() not in out and not (dev.STORE / "seal_secret.hex").exists())
        cd(dev.STORE, "--once", "--patterns", *pats)
        with s1.open("ab") as fh:
            fh.write(b'{"i":99,"t":"later"}\n')
        rc, out = cd(dev.STORE, "--once", "--patterns", *pats)
        check("D3-%s binding" % name, rc == 0 and len(list((dev.STORE / "chains").glob("*.chain.json"))) == 3)

        usb = T / ("usb_" + name)
        rc, out = quietly(dev.move_root_key, str(usb))
        custody = next(usb.glob("SIDE_custody_*"))
        check("D4-%s root key moved, device copy erased" % name,
              rc == 0 and not dev.ORGKEY.exists() and (custody / "k0.hex").exists()
              and not list(dev.STORE.rglob("k0.hex")))

        a = argparse.Namespace(include_logs=include_logs, out=None)
        rc, out = quietly(dev.collect, a)
        zp = next((dev.HERE / "collections").glob("SIDE_collection_*.zip"))
        with zipfile.ZipFile(zp) as zf:
            names = zf.namelist()
            manifest = json.loads(zf.read("00_manifest.json"))
        check("D5-%s collection zip" % name,
              rc == 0 and manifest["precollection_check_passed"]
              and not any(n.startswith("keys/") for n in names)
              and (any(n.startswith("sessions/") for n in names) == include_logs)
              and "seal_pub.hex" in names and "seal_pub.key" not in names, "%d files" % len(names))
        rc2, _ = quietly(dev.collect, a)
        check("D6-%s a sealed folder is not collected again" % name, rc2 == 1)
        zips[name] = (zp, custody)

    secret = org.HERE / "org_keys" / "seal_secret.hex"
    for name, (zp, custody) in zips.items():
        a = argparse.Namespace(zip=str(zp), custody=str(custody), seal_private_key=str(secret))
        rc, out = quietly(org.receive_collection, a)
        folder = org.RECEIVED / zp.stem
        txt = (folder / "verification_result.txt").read_text(encoding="utf-8")
        signed = all(json.loads(f.read_text(encoding="utf-8"))["seal"].get("sig")
                     for f in (folder / "chains").glob("*.chain.json"))

        check("O2-%s receive collection: seal signature, C1-C4 verification" % name,
              rc == 0 and signed and "chains with findings: 0" in txt,
              "skip-source" if name == "A" else "sessions-dir")

    folder_b = org.RECEIVED / zips["B"][0].stem
    custody_b = zips["B"][1]
    sess = sorted((folder_b / "sessions").glob("*"))
    check("O3 session log copy name = source_key", len(sess) == 2)
    bak = sess[0].read_bytes()
    sess[0].write_bytes(bak[:5] + (b"X" if bak[5:6] != b"X" else b"Y") + bak[6:])
    rc, out = cd(folder_b, "--verify", "--org-key", custody_b / "k0.hex",
                 "--seal-pub", custody_b / "seal_pub.hex",
                 "--require-sig", "--sessions-dir", folder_b / "sessions")
    check("O4 changed session log -> content mismatch", rc != 0 and "content mismatch" in out)
    sess[0].write_bytes(bak)

    folder_a = org.RECEIVED / zips["A"][0].stem
    moved = home.with_name("home_away")
    home.rename(moved)
    rc, out = cd(folder_a, "--verify", "--org-key", zips["A"][1] / "k0.hex")
    check("O5 without --sessions-dir or --skip-source the verifier reports source absent",
          rc != 0 and "source absent" in out)
    rc, out = cd(folder_a, "--verify", "--org-key", zips["A"][1] / "k0.hex", "--skip-source")
    check("O5b --skip-source gives zero findings without session logs",
          rc == 0 and "source absent" not in out)
    moved.rename(home)

    disclosures = org.HERE / "disclosures"
    env = dict(os.environ, SIDE_STORE=str(folder_b), PYTHONIOENCODING="utf-8", SIDE_OUT=str(disclosures),
               SIDE_SESSIONS_DIR=str(folder_b / "sessions"))
    r = subprocess.run([sys.executable, str(ORG / "disclose.py"),
                        "--chain", "1", "--range", "1-3", "--lines"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
                       cwd=str(org.HERE))
    pk = sorted(disclosures.glob("SIDE_disclosure_*.json"))
    ln = sorted(disclosures.glob("SIDE_disclosure_*.lines.jsonl"))
    check("O6 disclosure package and line text", r.returncode == 0 and len(pk) == 1 and len(ln) == 1,
          (r.stdout or "")[-200:].replace("\n", " ") if r.returncode else "")
    if pk and ln:
        a = argparse.Namespace(package=str(pk[0]), seal_public_key=str(org.HERE / "seal_pub.hex"),
                               lines=str(ln[0]))
        rc, out = quietly(org.verify_package, a)
        check("O7 verifier: package, signature and line text", rc == 0,
              out.strip().splitlines()[-1] if out.strip() else "")
        a.seal_public_key = pub
        rc, out = quietly(org.verify_package, a)
        check("O7b public key given as a 64-digit value gives the same result", rc == 0)
        cd(T / "x", "--gen-seal-keypair", T / "otherkp")
        a.seal_public_key = str(T / "otherkp" / "seal_pub.hex")
        rc, out = quietly(org.verify_package, a)
        check("O8 another public key is rejected", rc != 0)

        viewer = load_module(VER / "viewer.py", "side_viewer")
        pubhex = (org.HERE / "seal_pub.hex").read_text(encoding="utf-8").strip()
        vr = viewer.read_package(pk[0], pubhex, True)

        check("O9 viewer: gap report holds, scope statement", vr["gap"]["present"] and vr["gap"]["ok"]
              and vr["scope"].get("chain") and vr["verdict"]["all_ok"],
              "service intervals %s" % (vr["gap"]["summary"] or {}).get("intervals"))

        f1, f2, f3 = T / "seal_pub.key", T / "bom_pub.hex", T / "wrong.hex"
        f1.write_text(pubhex, encoding="utf-8")
        f2.write_bytes(b"\xef\xbb\xbf" + pubhex.upper().encode() + b"\r\n")
        f3.write_text("ab" * 16, encoding="utf-8")
        try:
            viewer.read_public_key(f3)
            rejected = False
        except ValueError:
            rejected = True
        check("O10 viewer public key file (legacy name, BOM, wrong form rejected)",
              viewer.read_public_key(f1) == pubhex and viewer.read_public_key(f2) == pubhex
              and viewer.read_public_key(None, " " + pubhex + " ") == pubhex and rejected)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8-sig", newline="") as fh:
        csv.writer(fh).writerows([("test", "verdict", "detail"), *results])
    failed = sum(1 for _, p, _ in results if p != "PASS")
    print("\n%d/%d passed  -> %s" % (len(results) - failed, len(results), OUT))
    keep = os.environ.get("SIDE_E2E_KEEP")
    if keep:
        shutil.copytree(T, keep)
        print("kept -> %s" % keep)
    shutil.rmtree(T, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
