# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE service command line: enroll, sweep, seal, verify and disclose.

SIDE_STORE names the service folder (a SYSTEM-only folder in deployment).

  python side_service.py --watch --source claude codex antigravity
  python side_service.py --once --patterns "D:/somewhere/*.jsonl"
  python side_service.py --verify --org-key k0.hex --seal-pub seal_pub.hex
  python side_service.py --disclose <chain file> --seqs 3,5,7
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import side_bind as bind
import side_core as core
import side_store as store
import side_util as util
import side_verify as verify
from side_store import LedgerBroken


def _inside_store(p: pathlib.Path) -> bool:
    s = store.STORE.resolve()
    return p == s or s in p.parents


def cmd_gen_seal_keypair(outdir: str) -> int:
    od = pathlib.Path(outdir).resolve()
    if _inside_store(od):
        print("The --gen-seal-keypair folder must be outside the device service folder.")
        return 1
    od.mkdir(parents=True, exist_ok=True)
    sk, pub = od / core.SEAL_SECRET_NAME, od / core.SEAL_PUB_NAME
    if sk.exists() or pub.exists():
        print(f"A key pair already exists -- not overwriting: {od}")
        return 1
    sk_hex, pub_hex = core.generate_seal_keypair()
    sk.write_text(sk_hex, encoding="utf-8")
    pub.write_text(pub_hex, encoding="utf-8")
    print(f"seal key pair → {od}")
    print(f"  public key {pub_hex}  ({pub})")
    print(f"  the private key is only in {sk} -- not printed on screen")
    return 0


def cmd_enroll(seal_pub_hex: str, org_out: str | None = None) -> int:
    import secrets
    if store.DEVICE.exists() or store.ROOTKEY.exists():
        print("Already enrolled.  Empty the service folder to enroll again.")
        print(f"  service folder: {store.STORE}")
        return 1
    op = pathlib.Path(org_out).resolve() if org_out else None
    if op and _inside_store(op):
        print("--org-out must be outside the service folder.  "
              "The root key must not stay in the device service folder.")
        return 1
    store.STORE.mkdir(parents=True, exist_ok=True)

    k0 = secrets.token_bytes(32)
    device_id = os.environ.get("COMPUTERNAME", "unknown")
    now = datetime.now(timezone.utc)
    enroll = {
        "kind": "device_enroll_certificate",
        "device_id": device_id,
        "issued_at_utc": now.isoformat(timespec="milliseconds"),
        "key_commitment": core.key_commitment(k0),
        "seal_public_key": seal_pub_hex,
        "seal_key_mode": "deferred",
        "seal_key_id": f"{device_id}-{datetime.now(timezone.utc):%Y%m}",
        "seal_key_origin": "organization",
        "key_scheme": core.ENROLL_KEY_SCHEME,
    }

    store.replace_durable(store.SEAL_PUBLIC, seal_pub_hex)
    store.replace_durable(store.ENROLL, json.dumps(enroll, ensure_ascii=False, indent=1))

    if op:
        op.parent.mkdir(parents=True, exist_ok=True)
        store.replace_durable(op, k0.hex())

    bound = ["issued_at_utc", "key_commitment", "seal_public_key", "seal_key_mode",
             "seal_key_id", "seal_key_origin"]
    ch = store.open_device(enroll_extra={
        "enroll_certificate": {k: enroll[k] for k in bound}}, k0=k0)
    store.persist(ch, store.DEVICE)

    print("enrollment complete")
    print(f"  device             : {device_id}")
    print(f"  root key commitment: {enroll['key_commitment'][:32]}…")
    print(f"  seal public key    : {seal_pub_hex}")
    print(f"  seal key mode      : {enroll['seal_key_mode']}")
    print()
    print("  ── the organization must keep these separately ───────")
    if op:
        print(f"  root key K0        : written to the organization's file -- {op}")
    else:
        print(f"  root key K0        : {k0.hex()}")
    print("    (not stored on the device.  Used with --org-key of --verify)")
    print("  seal private key   : created by the organization -- this device never created or saw it")
    if not op:
        print("  The values above appear only on screen.  Copy them now.")
    return 0


def cmd_countersign(seal_secret: str | None) -> int:
    sk_hex = store.key_text(seal_secret) if seal_secret else ""
    if not sk_hex:
        print("No seal private key.  Give it with --seal-secret.")
        return 1
    try:
        pub_hex = core.seal_public_key_of(sk_hex)
    except ValueError:
        print("could not read --seal-secret.  It must be 64 hex digits or a file that holds them.")
        return 2
    enroll = store.load_enroll() or {}
    enrolled = enroll.get("seal_public_key")
    if enrolled and enrolled.lower() != pub_hex:
        print("This seal private key does not belong to the seal public key of the enrollment certificate.")
        print(f"  enrolled public key: {enrolled}")
        print(f"  key given          : {pub_hex}")
        print("Nothing was signed.  Use the private key the organization made for this device.")
        return 1
    key_id = enroll.get("seal_key_id", "")
    done = skipped = 0
    for cp in sorted(store.CHAINS.glob("*.chain.json")):
        d = json.loads(cp.read_text(encoding="utf-8"))
        seal = d.get("seal")
        if not seal or seal.get("sig"):
            skipped += 1
            continue
        before = json.dumps(seal["body"], sort_keys=True), seal["tag"]
        seal["sig"] = core.sign_seal_body(sk_hex, seal["body"], key_id)
        if (json.dumps(seal["body"], sort_keys=True), seal["tag"]) != before:
            raise RuntimeError(f"{cp.name}: signing changed the seal body or the seal tag")
        store.replace_durable(cp, json.dumps(d, ensure_ascii=False, indent=1))
        done += 1
        print(f"signed {cp.name}")
    print(f"\nsigned {done} · skipped {skipped} "
          f"(no seal or already signed)")
    print(f"public key: {pub_hex}")
    return 0


def cmd_verify_package(path: str, pub_hex: str | None, require_gaps: bool,
                       lines_path: str | None) -> int:
    try:
        pkg = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"could not read the disclosure package {path}: {exc}")
        return 1
    if not isinstance(pkg, dict):
        print(f"not a disclosure package: {path}")
        return 1
    res = core.verify_disclosure_package(pkg, seal_public_key=pub_hex, require_signature=True)
    ok = res["all_ok"]
    print(f"disclosure package {path}")
    print(f"  {len(pkg.get('items', []))} of {pkg.get('total_entries')} disclosed · "
          f"proof {'holds' if all(r['ok'] for r in res['items']) else 'does not hold'} · "
          f"root match {res['seal_root_match']} · count match {res['entry_count_match']}")
    print(f"  seal signature {res['seal_sig_status']}"
          + (f" -- {res['seal_sig_reason']}" if res['seal_sig_reason'] else ""))
    if pub_hex is None:
        print("    (the seal is judged genuine only with the public key the organization "
              "published in advance, given with --seal-pub)")
    gr = verify.verify_gap_report(pkg, pub_hex, require_signature=True)
    if gr["present"]:
        s = gr["summary"]
        sc = pkg.get("scope") or {}
        per = sc.get("period_utc") or [None, None]
        print(f"  scope statement · {sc.get('agent') or '-'} · "
              f"period {str(per[0])[:19]} ~ {str(per[-1])[:19]} · "
              f"records {len(sc.get('disclosed_seqs') or [])}/{sc.get('chain_records')}"
              + (f" · rule: {sc['rule']}" if sc.get("rule") else ""))
        print(f"  gap report {'holds' if gr['ok'] else 'does not hold'} · "
              f"service intervals {s['intervals']} · abnormal stops "
              f"{s['unclosed']} · automatic restarts {s['restarts']} · "
              f"read failures {s['read_failures']} · "
              f"observations {s['observations']} · "
              f"ledger records left out of the report {gr['undisclosed_ledger']}")
        for x in s["gaps"]:
            print(f"    - {x}")
    for x in gr["findings"]:
        print(f"  ! {x}")
    if gr["present"]:
        ok = ok and bool(gr["ok"])
    elif require_gaps:
        ok = False
    if lines_path:
        lines = [json.loads(x) for x in
                 pathlib.Path(lines_path).read_text(encoding="utf-8").splitlines() if x.strip()]
        lc = verify.check_disclosed_lines(pkg, lines)
        print(f"  line text compared {lc['checked']} · match {lc['matched']} · "
              f"mismatch {lc['mismatched']} · no text {lc['missing']} · outside the package {lc['extra']}")
        ok = ok and lc["ok"]
    print("verdict: " + ("pass" if ok else "reject"))
    return 0 if ok else 1


def cmd_disclose(chain_file: str, seqs_arg: str | None, rule: str, pub_hex: str | None,
                 require_sig: bool, with_lines: bool, sessions_dir: pathlib.Path | None) -> int:
    cp = pathlib.Path(chain_file)
    d = json.loads(cp.read_text(encoding="utf-8"))
    seqs = [int(x) for x in (seqs_arg or "").split(",") if x.strip()]
    pkg = core.build_disclosure_package(d, seqs)
    lp, scope, why = verify.build_gap_report(d, cp.name, seqs, rule, store.DEVICE)
    pkg["scope"] = scope
    if lp is not None:
        pkg["ledger_package"] = lp
        gs = verify.gap_summary([it["record"] for it in lp["items"]], cp.name, scope["session_file"],
                                tuple(scope["period_utc"]))
        print(f"gap report · ledger records {len(lp['items'])} (total {lp['total_entries']}) · "
              f"gaps {len(gs['gaps'])}")
        for x in gs["gaps"]:
            print(f"  - {x}")
    else:
        print(f"gap report not included -- {why}")
    out = cp.with_suffix(".package.json")
    decl = store.load_enroll() or {}
    if decl:
        pkg["enroll_declaration"] = {
            k: decl.get(k) for k in
            ("device_id", "seal_key_id", "seal_key_mode",
             "key_commitment", "seal_public_key")}
        pkg["enroll_declaration"]["NOTE"] = (
            "Values claimed by the device.  They become evidence only after comparison "
            "with the organization's custody copy.")
    store.replace_durable(out, json.dumps(pkg, ensure_ascii=False, indent=1))
    require = require_sig or decl.get("seal_key_mode") == "local"
    res = core.verify_disclosure_package(pkg, seal_public_key=pub_hex,
                                         require_signature=require)
    if with_lines:
        try:
            lp = verify.write_disclosed_lines(pkg, d, out, sessions_dir)
        except OSError as exc:
            print(f"could not write the line text: {exc}")
            return 1
        print(f"disclosed line text → {lp}")
    print(f"disclosure package → {out}")
    print(f"  {pkg['disclosed_count']} of {pkg['total_entries']} disclosed")
    print(f"  verification {'pass' if res['all_ok'] else 'fail'} · "
          f"root match {res['seal_root_match']} · "
          f"count match {res['entry_count_match']}")
    print(f"  seal signature {res['seal_sig_status']}"
          + (f" -- {res['seal_sig_reason']}" if res['seal_sig_reason'] else ""))
    if res["seal_sig_ok"] is None:
        print("    (with the public key the organization published in advance, given with --seal-pub, "
              "the seal is also checked for authenticity)")
    return 0


def cmd_seal(force_seal: bool) -> int:
    if store.legacy_seal_secret_present():
        try:
            store.note_device("observation", what="legacy_seal_key_present",
                              session_file=str(store.SEAL_SECRET))
        except LedgerBroken as exc:
            return bind.ledger_broken_exit(exc, started=False, mode="seal")
        print(f"  ! an old seal private key file exists -- not used: {store.SEAL_SECRET}")
    if store.DEVICE.exists() and not force_seal:
        try:
            running = verify.still_open(json.loads(store.DEVICE.read_text(encoding="utf-8"))["entries"])
        except (ValueError, OSError, KeyError, TypeError):
            running = False
        if running:
            print("Not sealed -- the last service_start in the ledger has no stop (the service is running or "
                  "was killed).  Stop the service with the stop file.  If it was killed, run --once once, "
                  "then seal again.  To seal anyway, use --force-seal.")
            return 1

    def seal(ch, cp: pathlib.Path) -> None:
        ch.close()
        store.persist(ch, cp)
        print(f"sealed {cp.name} · entry_count={ch.seal['body']['entry_count']} · "
              "no signature (awaiting seal signature)")

    failures = 0
    for cp in sorted(store.CHAINS.glob("*.chain.json")):
        try:
            d = json.loads(cp.read_text(encoding="utf-8"))
            if d.get("seal"):
                continue
            if cp == store.DEVICE:
                continue
            sp = pathlib.Path(d["entries"][0]["record"].get("session_file", "x"))
            seal(bind.load_or_create(cp, sp), cp)
        except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError,
                RuntimeError) as exc:
            failures += 1
            print(f"could not seal {cp.name} -- {type(exc).__name__}: {exc}")
            try:
                store.note_device("observation", what="seal_failed", chain=cp.name,
                                  error=type(exc).__name__)
            except LedgerBroken as exc2:
                print(f"  ! could not record seal_failed in the ledger either -- {exc2}")
    if store.DEVICE.exists() and not json.loads(store.DEVICE.read_text(encoding="utf-8")).get("seal"):
        seal(store.open_device(), store.DEVICE)
    return 1 if failures else 0


def cmd_verify(org_key: str | None, pub_hex: str | None, require_sig: bool,
               sessions_dir: pathlib.Path | None, skip_source: bool) -> int:
    rk_hex = store.key_text(org_key) if org_key else None
    try:
        rk = bytes.fromhex(rk_hex) if rk_hex else None
    except ValueError:
        print("could not read --org-key.  It must be 64 hex digits or a file that holds them.")
        return 2
    if rk is not None and len(rk) != 32:
        print("--org-key must be 32 bytes (64 hex digits).")
        return 2
    if rk is None:
        print("Checking without the root key -- the organization runs tag recomputation (C1) and the "
              "commitment comparison when it receives the collection." + chr(10))
    if skip_source:
        print("Verifying without session logs -- skipping C3 (line hash vs file) and C4 (checkpoint size) "
              "(the device ran them right before collection)." + chr(10))
    chains = sorted(store.CHAINS.glob("*.chain.json"))
    if not chains:
        print("No chains.  Bind first with --once")
        return 1
    bad = 0
    if store.DEVICE.exists():
        try:
            d = verify.verify_device(store.DEVICE, rk)
        except (ValueError, OSError, KeyError, TypeError, IndexError,
                AttributeError) as exc:
            d = {"chain": store.DEVICE.name, "entries": 0, "kinds": {}, "still_running": False,
                 "findings": [f"could not read the ledger: {type(exc).__name__}"], "ok": False}
        mark = "OK  " if d["ok"] else "FAIL"
        print(f"{mark} {d['chain'][:52]:52s} "
              f"records {d['entries']:5d} · {d['kinds']}")
        if d["still_running"]:
            print("       - no service_stop yet (the service is running or died)")
        for f in d["findings"]:
            print(f"       - {f}")
        bad += 0 if d["ok"] else 1
        try:
            iv = verify.service_intervals(json.loads(store.DEVICE.read_text(encoding="utf-8"))["entries"])
            print(f"       service intervals {len(iv['intervals'])} · "
                  f"automatic restarts {iv['restarts']} · "
                  f"intervals ended without a stop {iv['unclosed']}")
            plain_ivs = [x for x in iv["intervals"] if x.get("read") == "plain"]
            if plain_ivs:
                print(f"       · service intervals read without the backup privilege: "
                      f"{len(plain_ivs)} (seq "
                      f"{', '.join(str(x['start_seq']) for x in plain_ivs[:8])}"
                      f"{' …' if len(plain_ivs) > 8 else ''}) -- "
                      "these cannot bypass a read deny (ACL) set by the employee")
        except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
            print(f"       service intervals could not be read ({type(exc).__name__})")
    else:
        print("warning: no device ledger -- the service lifecycle cannot be judged")

    results = []
    for cp in chains:
        if cp == store.DEVICE:
            continue
        try:
            r = verify.verify_chain(cp, rk, sessions_dir, skip_source)
        except (ValueError, OSError, KeyError, TypeError, IndexError,
                AttributeError) as exc:
            r = {"chain": cp.name, "entries": 0, "lines": 0,
                 "findings": [f"could not read the chain file: {type(exc).__name__}"], "ok": False}
        results.append(r)
        bad += 0 if r["ok"] else 1

    for r in results:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"{mark} {r['chain'][:52]:52s} "
              f"records {r['entries']:5d} · lines {r['lines']:5d}")
        for f in r["findings"]:
            print(f"       - {f}")
        for nt in r.get("notes") or []:
            print(f"       · {nt}")
    not_run = sum(1 for r in results if r.get("notes"))
    if not_run:
        print(f"\n{not_run} chains skipped C3·C4 without session logs -- not counted in the verdict")

    enroll = store.load_enroll()
    if enroll and rk is None:
        print(chr(10) + f"enrollment certificate · device {enroll.get('device_id')} · "
              "the organization compares the commitment")
    elif enroll:
        same = core.key_commitment(rk) == enroll.get("key_commitment")
        print(f"\nenrollment certificate · device {enroll.get('device_id')} · "
              f"issued {enroll.get('issued_at_utc', '')[:19]}")
        print(f"  root key commitment {'match' if same else 'mismatch -- the key changed'}")
        if not same:
            bad += 1
        if store.DEVICE.exists():
            bound = verify.certificate_bound(store.DEVICE, enroll)
            print(f"  bound in the first ledger record {'yes' if bound else 'no'}")
            if not bound:
                bad += 1
    else:
        print("\nwarning: no enrollment certificate -- this service folder was not enrolled with --enroll")

    print(f"\nseal signature · public key {'given' if pub_hex else 'none'}")
    if not pub_hex:
        try:
            have = "present" if store.seal_public_hex() else "absent"
        except ValueError:
            have = "present"
        print(f"  public key copy on the device: {have}.  It is not a basis of trust,"
              " so the verdict does not use it.")
        print("  The seal signature is checked with the public key the organization published in advance.")
    mode = (store.load_enroll() or {}).get("seal_key_mode")
    for cp in chains:
        try:
            d = json.loads(cp.read_text(encoding="utf-8"))
            seal = d.get("seal")
        except (ValueError, OSError, AttributeError):
            print(f"  {cp.name[:52]:52s} could not read the chain file")
            continue
        if not seal:
            print(f"  {cp.name[:52]:52s} no seal"
                  + (" -- rejected, signature required" if require_sig else ""))
            bad += 1 if require_sig else 0
            continue
        if require_sig and not seal.get("sig"):
            bad += 1
            print(f"  {cp.name[:52]:52s} no signature -- rejected, signature required")
            continue
        r = verify.seal_signature_status(seal, pub_hex, mode)
        print(f"  {cp.name[:52]:52s} {r['status']}"
              + (f" -- {r['reason']}" if r["reason"] else ""))
        if r["ok"] is False:
            bad += 1

    n = len([c for c in chains if c != store.DEVICE])
    print(f"\n{n} session chains + device ledger · chains with findings: {bad}")
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SIDE binding service and verifier")
    ap.add_argument("--patterns", nargs="*", default=[],
                    help="paths to sweep, given directly")
    ap.add_argument("--source", nargs="*", default=[],
                    choices=sorted(bind.SOURCES) + ["bound"],
                    help="where to sweep, by name.  bound continues only with files "
                         "already bound")
    ap.add_argument("--once", action="store_true", help="sweep once")
    ap.add_argument("--watch", action="store_true", help="run resident")
    ap.add_argument("--interval", type=float, default=bind.SWEEP_INTERVAL_SEC,
                    help="sweep interval (seconds)")
    ap.add_argument("--stopfile",
                    help="stop the resident service normally when this file appears.  "
                         "Replaces Ctrl+C for a service without a console")
    ap.add_argument("--checkpoint-sec", type=float, default=bind.CHECKPOINT_SEC,
                    help="checkpoint interval for files that changed (seconds)")
    ap.add_argument("--heartbeat-sec", type=float, default=bind.HEARTBEAT_SEC,
                    help="checkpoint interval for unchanged files (seconds)")
    ap.add_argument("--verify", action="store_true", help="verify collected chains")
    ap.add_argument("--disclose", help="make a disclosure package from a chain file")
    ap.add_argument("--seqs", help="seqs to disclose (comma separated)")
    ap.add_argument("--seal", action="store_true", help="seal the chains")
    ap.add_argument("--enroll", action="store_true",
                    help="enroll the device (once, before binding)")
    ap.add_argument("--org-out",
                    help="at enrollment, also write K0 to an organization file (outside the service folder)")
    ap.add_argument("--org-key",
                    help="the organization's root key K0 for verification: file or 64 hex digits")
    ap.add_argument("--countersign",
                    action="store_true",
                    help="the organization adds its signature to already sealed chains")
    ap.add_argument("--seal-secret",
                    help="seal private key for --countersign: file or 64 hex digits")
    ap.add_argument("--seal-pub",
                    help="public key that verifies seal signatures: file or 64 hex digits.  The word "
                         "store uses the device copy in the service folder, which is no basis of trust")
    ap.add_argument("--require-sig", action="store_true",
                    help="with --verify or --disclose: count a seal without a signature as a finding "
                         "(the verifier's requirement)")
    ap.add_argument("--verify-package", help="verify a received disclosure package (JSON)")
    ap.add_argument("--lines", help="with --verify-package: disclosed line text file (.lines.jsonl)")
    ap.add_argument("--with-lines", action="store_true",
                    help="with --disclose: also write the line text of disclosed lines to .lines.jsonl")
    ap.add_argument("--seal-pubkey",
                    help="with --enroll (required): seal public key created by the organization with "
                         "--gen-seal-keypair (file or 64 hex digits)")
    ap.add_argument("--gen-seal-keypair", metavar="DIR",
                    help="organization side: create the seal key pair in DIR "
                         "(outside the device service folder)")
    ap.add_argument("--restart-on-error", type=int, default=0, metavar="N",
                    help="with --watch: after an exception that ends the sweep loop, record a stop and a "
                         "restart in the ledger and start again.  Up to N in a row (default 0 = stop)")
    ap.add_argument("--read-mode", choices=("auto", "backup", "plain"), default="auto",
                    help="read path for session logs.  auto uses the backup privilege if it can be "
                         "enabled, else an ordinary open (default)")
    ap.add_argument("--hints-dir",
                    help="optional hook hint drop folder (default: hints/ in the service folder).  Hints "
                         "are untrusted records.  SIDE installs no hooks")
    ap.add_argument("--sessions-dir",
                    help="with --verify or --disclose --with-lines: "
                         "session log folder of a collection (sessions/).  "
                         "Searched before the device path recorded in the chain")
    ap.add_argument("--scope",
                    help="with --disclose: selection rule written into the scope statement")
    ap.add_argument("--require-gaps", action="store_true",
                    help="with --verify-package: reject a package without a gap report")
    ap.add_argument("--force-seal", action="store_true",
                    help="with --seal: seal even if the ledger has no stop "
                         "(only after confirming the service has stopped)")
    ap.add_argument("--skip-source", action="store_true",
                    help="with --verify: a collection without session logs.  Skips C3 and C4")
    return ap


def main() -> int:
    util.keep_output_alive()
    ap = build_parser()
    a = ap.parse_args()
    store.use(os.environ.get("SIDE_STORE") or store.DEFAULT_STORE)
    bind.configure(a.checkpoint_sec, a.heartbeat_sec, a.hints_dir)
    sessions_dir = pathlib.Path(a.sessions_dir) if a.sessions_dir else None

    if a.gen_seal_keypair:
        return cmd_gen_seal_keypair(a.gen_seal_keypair)

    pats: list[str] = []
    if a.once or a.watch:
        pats = bind.resolve_patterns(a.patterns, a.source, store.load_state())
        if not pats:
            bind.explain_sources()
            return 2

    if a.enroll:
        if not a.seal_pubkey:
            print("--enroll needs --seal-pubkey: the seal public key the organization created off the "
                  "device with --gen-seal-keypair.  The seal private key never exists on the device.")
            return 2
        try:
            spub = store.read_seal_public_key(a.seal_pubkey)
        except (ValueError, OSError) as exc:
            print(f"could not read --seal-pubkey: {exc}")
            return 2
        return cmd_enroll(spub, a.org_out)

    if a.once or a.watch:
        try:
            bind.use_read_mode(a.read_mode)
        except ValueError as exc:
            print(f"--read-mode backup: {exc}", file=sys.stderr)
            return 2

    if store.ROOTKEY.exists():
        print("warning: root.key exists in the service folder -- this design keeps no root key on the device")
    try:
        if a.seal_pub == "store":
            pub_hex = store.seal_public_hex()
        else:
            pub_hex = store.read_seal_public_key(a.seal_pub) if a.seal_pub else None
    except (ValueError, OSError) as exc:
        print(f"could not read --seal-pub: {exc}")
        return 2

    if a.countersign:
        return cmd_countersign(a.seal_secret)
    if a.verify_package:
        return cmd_verify_package(a.verify_package, pub_hex, a.require_gaps, a.lines)
    if a.disclose:
        return cmd_disclose(a.disclose, a.seqs, a.scope or "", pub_hex, a.require_sig,
                            a.with_lines, sessions_dir)
    if a.seal:
        return cmd_seal(a.force_seal)
    if a.verify:
        return cmd_verify(a.org_key, pub_hex, a.require_sig, sessions_dir, a.skip_source)

    if a.once or a.watch:
        store.enable_key_wiping()
    if a.once:
        return bind.run_once(pats)
    if a.watch:
        return bind.watch(pats, a.interval, pathlib.Path(a.stopfile) if a.stopfile else None,
                          a.restart_on_error)

    ap.print_help()
    return 1


def run_safely() -> int:
    code = main()
    try:
        sys.stdout.flush()
    except (UnicodeEncodeError, OSError, ValueError) as exc:
        print("Could not flush all output (%s).  The verdict above stands."
              % type(exc).__name__, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(run_safely())
