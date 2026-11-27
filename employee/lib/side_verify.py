# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE verification: checks C1-C4, the device ledger, seals, line text and the gap report.

  C1 tag recomputation      needs the organization's root key K0
  C2 offset continuity      line records continue byte by byte
  C3 line hash vs file      needs the session log
  C4 checkpoint size        the session log never became smaller than an observed size

Each finding carries a stable code; front ends classify findings by code, never by wording.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import unicodedata
from datetime import datetime

import side_core as core
from side_core import LEDGER_NAME


class Finding(str):
    code: str

    def __new__(cls, code: str, text: str) -> "Finding":
        f = super().__new__(cls, text)
        f.code = code
        return f


def first_session_file(entries: list) -> str | None:
    return next((e["record"]["session_file"] for e in entries if e["record"].get("session_file")), None)


def source_key(session_file: str) -> str:
    s = unicodedata.normalize("NFC", str(session_file))
    base = s.replace("\\", "/").rsplit("/", 1)[-1]
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12] + "_" + base


def resolve_source(session_file: str, sessions_dir: pathlib.Path | None = None) -> pathlib.Path:
    if sessions_dir is not None:
        q = sessions_dir / source_key(session_file)
        if q.exists():
            return q
    return pathlib.Path(session_file)


_opens_cache: dict = {}
_keys_cache: dict = {}


def _session_opens(dev: pathlib.Path) -> dict:
    raw = dev.read_bytes()
    if _opens_cache.get("raw") != raw:
        dd = json.loads(raw.decode("utf-8"))
        idx: dict = {}
        for e in dd["entries"]:
            r = e["record"]
            if r.get("kind") == "session_open":
                idx.setdefault(r.get("chain"), []).append((e["seq"], r))
        _opens_cache.clear()
        _opens_cache.update(raw=raw, idx=idx)
    return _opens_cache["idx"]


def _ledger_keys(k0: bytes) -> core.KeySchedule:
    ks = _keys_cache.get(k0)
    if ks is None:
        _keys_cache.clear()
        ks = _keys_cache[k0] = core.KeySchedule(k0, True)
    return ks


def _session_open_choice(cp: pathlib.Path, k0: bytes, d: dict | None = None) -> dict:
    out = {"key": None, "why": "", "seqs": [], "chosen": None, "matched": None}
    dev = cp.parent / LEDGER_NAME
    if not dev.exists():
        out["why"] = "no ledger, so the start key cannot be derived"
        return out
    cands = []
    for seq, r in _session_opens(dev).get(cp.name, []):
        lj = _ledger_keys(k0).at(seq)
        cands.append((seq, core.chain_start_key(lj, r["session_id"])))
    if not cands:
        out["why"] = "the ledger has no session_open record for this chain"
        return out
    out["seqs"] = [s for s, _ in cands]
    chosen = cands[-1]
    if len(cands) > 1:
        out["matched"] = False
        try:
            if d is None:
                d = json.loads(cp.read_text(encoding="utf-8"))
            first = d["entries"][0]
            g = core.Chain(case_id=d["case_id"], custodian=d["custodian"],
                           source=d["source"], forward_secure=True,
                           _root_key=bytes(32)).genesis_tag
            for s, k in cands:
                if core.compute_tag(k, first["record"], g) == first["tag"]:
                    chosen, out["matched"] = (s, k), True
                    break
        except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError):
            pass
    out["chosen"], out["key"] = chosen
    return out


def _tag_findings(d: dict, entries: list, key: bytes) -> list[str]:
    prev = core.Chain(case_id=d["case_id"], custodian=d["custodian"],
                      source=d["source"], forward_secure=True, _root_key=key).genesis_tag
    keys = core.KeySchedule(key, True)
    for i, e in enumerate(entries):
        if core.compute_tag(keys.at(i), e["record"], prev) != e["tag"]:
            return [Finding("tag_mismatch", f"tag mismatch at seq {e['seq']}")]
        prev = e["tag"]
    return []


def seal_findings(d: dict, entries: list, key: bytes | None) -> list[str]:
    seal = d.get("seal")
    if not seal:
        return []
    out = []
    try:
        body = seal["body"]
        n = int(body["entry_count"])
        if n != len(entries):
            out.append(f"seal record count {n} != chain {len(entries)} (deleted or added after the seal)")
        leaves = [core.leaf_hash(e["record"]) for e in entries]
        if body.get("merkle_root") != core.merkle_root(leaves):
            out.append("Merkle root differs from the chain")
        last = entries[-1]["tag"] if entries else None
        if last is not None and body.get("final_tag") != last:
            out.append("final tag of the seal differs from the last tag of the chain")
        if key is not None:
            kn = core.KeySchedule(key, True).at(n)
            if not hmac.compare_digest(core.compute_tag(kn, body, body["final_tag"]), seal["tag"]):
                out.append("K_N does not reproduce the seal tag")
    except (KeyError, TypeError, ValueError) as exc:
        out.append(f"could not read the seal ({type(exc).__name__})")
    return [Finding("seal_mismatch", "seal mismatch: " + x) for x in out]


def verify_chain(cp: pathlib.Path, k0: bytes | None,
                 sessions_dir: pathlib.Path | None = None, skip_source: bool = False) -> dict:
    d = json.loads(cp.read_text(encoding="utf-8"))
    entries = d["entries"]
    findings: list[str] = []
    rk = None
    if k0 is not None:
        so = _session_open_choice(cp, k0, d)
        rk, why = so["key"], so["why"]
        if rk is None:
            findings.append(Finding("start_key", f"start key: {why}"))
        elif len(so["seqs"]) > 1:
            seqs = ", ".join(str(s) for s in so["seqs"])
            if so["matched"]:
                findings.append(Finding(
                    "duplicate_open", f"duplicate session_open (seq {seqs}) -- "
                    "the chain matches the session open "
                    f"at seq {so['chosen']}.  The other open is either a write cut off before the "
                    "chain was saved (retry after an abnormal stop) or a trace of someone holding a "
                    "later ledger key who appended an open and replaced the chain -- compare with "
                    "the service lifecycle in the ledger"))
            else:
                findings.append(Finding(
                    "duplicate_open", f"duplicate session_open (seq {seqs}) -- no session open reproduces "
                    f"the first tag of the chain (recomputed with the last, seq {so['chosen']})"))

    if rk is not None:
        findings += _tag_findings(d, entries, rk)

    lines = [e["record"] for e in entries if e["record"].get("kind") == "line"]
    sf = first_session_file(entries)
    src = resolve_source(sf, sessions_dir) if sf else None
    raw = None
    if not skip_source and src is not None:
        try:
            raw = src.read_bytes() if src.exists() else None
        except OSError:
            raw = None
    prev_line, pending_reset = None, None
    for e in entries:
        r = e["record"]
        kind = r.get("kind")
        if kind == "cursor_reset":
            pending_reset = r
            findings.append(Finding(
                "cursor_reset", f"cursor reset at seq {r.get('seq')}: the file shrank and the cursor "
                f"moved {r.get('from')} → {r.get('to')} (restart after shrink, "
                f"observed size {r.get('observed_size')})"))
            continue
        if kind != "line":
            continue
        if prev_line is not None and prev_line["end"] != r["start"]:
            pr = pending_reset
            restart = (pr is not None and isinstance(pr.get("to"), int)
                       and isinstance(pr.get("from"), int)
                       and pr["to"] == r["start"] and pr["to"] <= pr["from"])
            blank = (raw is not None and prev_line["end"] < r["start"] <= len(raw)
                     and not raw[prev_line["end"]:r["start"]].strip())
            if not restart and not blank:
                findings.append(Finding("offset_gap", f"offset gap {prev_line['seq']} -> {r['seq']}"))
        prev_line, pending_reset = r, None

    notes = []
    if skip_source:
        notes.append("C3·C4 not run -- no session log received "
                     "(a deleted log is invisible to this verification too)")
    elif raw is not None:
        for r in lines:
            seg = raw[r["start"]:r["end"]]
            if hashlib.sha256(seg).hexdigest() != r["sha256"]:
                findings.append(Finding("content_mismatch", f"content mismatch at seq {r['seq']}"))
                break
        for e in entries:
            r = e["record"]
            if r.get("kind") == "checkpoint" and len(raw) < r["size"]:
                findings.append(Finding(
                    "checkpoint_shrank", f"file shrank below checkpoint at seq {r['seq']} "
                    f"({r['size']} -> {len(raw)})"))
    elif src:
        findings.append(Finding("source_absent", f"source absent: {src.name} -- a bound log has disappeared"))

    findings += seal_findings(d, entries, rk)

    res = {"chain": cp.name, "entries": len(entries),
           "lines": len(lines), "findings": findings,
           "tags_checked": rk is not None, "ok": not findings}
    if notes:
        res["notes"] = notes
    return res


def verify_device(cp: pathlib.Path, rk: bytes | None) -> dict:
    d = json.loads(cp.read_text(encoding="utf-8"))
    entries = d["entries"]
    findings: list[str] = []
    if rk is not None:
        findings += _tag_findings(d, entries, rk)
    findings += seal_findings(d, entries, rk)

    life = service_intervals(entries)
    events = [(x["pos"], "start", x) for x in life["intervals"]]
    events += [(x["stop_pos"], "stop", x) for x in life["intervals"] if x.get("closed")]
    events += [(x["pos"], "stop", x) for x in life["stray_stops"]]
    for _, what, x in sorted(events, key=lambda ev: ev[0]):
        if what == "start" and x.get("after"):
            gap = x.get("since_stop_s")
            findings.append(Finding(
                "auto_restart", f"service_start at seq {x['start_seq']} restarted automatically after "
                f"{x.get('after')} (restart {x.get('restart')}) -- the "
                f"{gap if gap is not None else '?'}s between the previous stop and this start were not "
                "bound and have no assurance"))
        elif what == "stop":
            why = str(x.get("reason", ""))
            if why.startswith("exception") or why == "unknown":
                findings.append(Finding(
                    "exception_stop", f"service_stop at seq {x['stop_seq']} reason={why} -- "
                    "ended by an exception, not a normal stop"))
    last = life["intervals"][-1] if life["intervals"] else None
    still_running = last is not None and last.get("closed") is None
    if still_running:
        findings.append(Finding(
            "start_open", f"service_start at seq {last['start_seq']} is still open -- "
            "the service is running or stopped abnormally, and that interval has no assurance"))
    for x in life["intervals"]:
        if x.get("closed") is False:
            findings.append(Finding(
                "start_unclosed", f"service_start at seq {x['start_seq']} has no matching service_stop "
                "-- that interval was an abnormal stop and has no assurance"))

    for o in (e["record"] for e in entries if e["record"].get("kind") == "observation"):
        what = o.get("what")
        if what == "cursor_restored_from_chain":
            detail = (f"cursor file {o.get('state_offset')} → chain {o.get('chain_offset')}, "
                      "restored -- a chain ahead means a stop after saving the chain and before "
                      "saving the cursor, a cursor file ahead means the cursor file was edited")
        elif what == "state_unreadable":
            detail = f"cursor file unreadable, restored from the chain: {o.get('error')}"
        elif what == "legacy_seal_key_present":
            detail = "an old seal private key file was in the service folder at sealing -- not used"
        elif what == "ledger_tail_repaired":
            detail = (f"ledger tail was torn, repaired up to {o.get('kept_entries')} complete records, "
                      f"the cut {o.get('dropped_bytes')} bytes are in {o.get('saved_as')}")
        else:
            detail = f"bound up to {o.get('bound_to')} → observed size {o.get('observed_size')}"
            if o.get("cursor_to") is not None:
                detail += f" · cursor moved to {o.get('cursor_to')}"
        findings.append(Finding(
            f"observation:{what}", f"observation at seq {o['seq']}: {what} on "
            f"{os.path.basename(str(o.get('session_file')))} ({detail})"))

    for x in (e["record"] for e in entries if e["record"].get("kind") == "sweep_error"):
        findings.append(Finding("sweep_error", f"sweep_error at seq {x['seq']}: {x.get('error')}"))

    for e in entries:
        r = e["record"]
        if r.get("kind") == "session_open" and r.get("chain") and not (cp.parent / r["chain"]).exists():
            findings.append(Finding(
                "chain_missing", f"session_open at seq {r['seq']}: chain {r['chain']} missing -- the "
                f"ledger records the session open of {os.path.basename(str(r.get('session_file')))} "
                "but the chain is not in the service folder"))

    opens: dict = {}
    for e in entries:
        r = e["record"]
        if r.get("kind") == "session_open" and r.get("chain"):
            opens.setdefault(r["chain"], []).append(r.get("seq"))
    for ch_name, seqs in sorted(opens.items()):
        if len(seqs) > 1:
            findings.append(Finding("opened_twice", f"session opened twice in ledger: {ch_name} "
                                                    f"(seq {', '.join(map(str, seqs))})"))

    return {"chain": cp.name, "entries": len(entries), "kinds": count_kinds(entries),
            "still_running": still_running,
            "findings": findings, "ok": not findings}


def count_kinds(entries: list) -> dict:
    kinds: dict = {}
    for e in entries:
        k = (e.get("record") or {}).get("kind", "?")
        kinds[k] = kinds.get(k, 0) + 1
    return kinds


def certificate_bound(dev: pathlib.Path, enroll: dict) -> bool:
    try:
        d = json.loads(dev.read_text(encoding="utf-8"))
        first = d["entries"][0]["record"] if d.get("entries") else {}
        cert = (first or {}).get("enroll_certificate") or {}
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError):
        cert = {}
    return cert.get("key_commitment") == enroll.get("key_commitment")


MISSING_SIGNATURE = {
    "removed": ("no signature -- suspected removal",
                "a device enrolled in local mode signs on the spot when it seals"),
    "awaiting": ("no signature -- awaiting seal signature",
                 "enrolled as deferred.  The organization signs it on receipt"),
    "unknown": ("no signature -- cause unknown",
                "no enrollment certificate, so whether a signature is expected cannot be judged"),
}


def seal_signature_status(seal: dict, pub_hex: str | None, mode: str | None) -> dict:
    r = core.verify_seal_signature(seal, pub_hex)
    if r["status"] != "no signature":
        return dict(r, missing=None)
    missing = {"local": "removed", "deferred": "awaiting"}.get(mode, "unknown")
    status, reason = MISSING_SIGNATURE[missing]
    return {"status": status, "reason": reason, "ok": False if missing == "removed" else None,
            "missing": missing}


def write_disclosed_lines(pkg: dict, chain: dict, pkg_path: pathlib.Path,
                          sessions_dir: pathlib.Path | None = None) -> pathlib.Path:
    src = first_session_file(chain.get("entries", []))
    raw = b""
    if src:
        p = resolve_source(src, sessions_dir)
        if sessions_dir is not None and p.parent != sessions_dir:
            raise FileNotFoundError("the collection holds no copy of this session log")
        raw = p.read_bytes()
    out = pkg_path.with_suffix(".lines.jsonl")
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for it in pkg.get("items", []):
            r = it["record"]
            if r.get("kind") != "line":
                continue
            seg = raw[r["start"]:r["end"]]
            fh.write(json.dumps({"seq": it["seq"],
                                 "b64": base64.b64encode(seg).decode("ascii")}) + "\n")
    return out


def check_disclosed_lines(pkg: dict, lines: list[dict]) -> dict:
    recs = {it["seq"]: it["record"] for it in pkg.get("items", [])
            if it.get("record", {}).get("kind") == "line"}
    got = {}
    for x in lines:
        try:
            got[int(x["seq"])] = base64.b64decode(x["b64"], validate=True)
        except (KeyError, ValueError, TypeError):
            got.setdefault(-1, b"")
    matched = mismatched = 0
    for s, r in recs.items():
        seg = got.get(s)
        if seg is None:
            continue
        if (len(seg) == r.get("end", -1) - r.get("start", 0)
                and hashlib.sha256(seg).hexdigest() == r.get("sha256")):
            matched += 1
        else:
            mismatched += 1
    missing = sum(1 for s in recs if s not in got)
    extra = sum(1 for s in got if s not in recs)
    return {"checked": len(recs), "matched": matched, "mismatched": mismatched,
            "missing": missing, "extra": extra,
            "ok": mismatched == 0 and missing == 0 and extra == 0}


LIFE_KINDS = ("service_start", "service_stop")


def _ts(r: dict) -> float | None:
    try:
        return datetime.fromisoformat(str(r.get("ts_recorded"))).timestamp()
    except (TypeError, ValueError):
        return None


def service_intervals(entries: list) -> dict:
    ivs, cur, last_end, last_stop, stray = [], None, None, None, []
    for pos, e in enumerate(entries):
        r = e["record"]
        k = r.get("kind")
        if k == "service_start":
            if cur is not None:
                cur["closed"] = False
                ivs.append(cur)
            t = _ts(r)
            cur = {"pos": pos, "start_seq": r.get("seq"), "start": t, "start_ts": r.get("ts_recorded"),
                   "restart": r.get("restart"),
                   "after": r.get("after"), "read": r.get("read"),
                   "gap_s": (round(t - last_end, 1)
                             if r.get("after") and last_end is not None and t else None),
                   "since_stop_s": (round(t - last_stop, 1)
                                    if last_stop is not None and t is not None else None)}
        elif k == "service_stop":
            last_stop = _ts(r)
            if cur is not None:
                cur.update(stop_seq=r.get("seq"), stop_pos=pos, stop_ts=r.get("ts_recorded"),
                           reason=r.get("reason"), closed=True)
                last_end = last_stop
                ivs.append(cur)
                cur = None
            else:
                stray.append({"pos": pos, "seq": r.get("seq"), "stop_seq": r.get("seq"),
                              "stop_ts": r.get("ts_recorded"), "reason": r.get("reason")})
    if cur is not None:
        cur["closed"] = None
        ivs.append(cur)
    return {"intervals": ivs, "restarts": sum(1 for x in ivs if x.get("after")),
            "unclosed": sum(1 for x in ivs if x.get("closed") is False), "stray_stops": stray}


def still_open(entries: list) -> bool:
    ivs = service_intervals(entries)["intervals"]
    return bool(ivs) and ivs[-1].get("closed") is None


def gap_report_seqs(ledger_entries: list, chain_name: str, session_file: str) -> list[int]:
    out = []
    for e in ledger_entries:
        r = e["record"]
        if (r.get("seq") == 0 or r.get("kind") in LIFE_KINDS
                or r.get("chain") == chain_name or r.get("session_file") == session_file):
            out.append(r["seq"])
    return out


def gap_summary(records: list, chain_name: str, session_file: str,
                period: tuple | None = None) -> dict:
    recs = sorted(records, key=lambda r: r.get("seq", 0))
    iv = service_intervals([{"record": r} for r in recs])
    t0, t1 = (period or (None, None))
    t0 = _ts({"ts_recorded": t0}) if t0 else None
    t1 = _ts({"ts_recorded": t1}) if t1 else None

    def overlaps(x):
        a = x.get("start")
        b = None
        if x.get("stop_seq") is not None:
            b = _ts(next((r for r in recs if r.get("seq") == x["stop_seq"]), {}))
        if t0 is None or t1 is None or a is None:
            return True
        return a <= t1 and (b is None or b >= t0)

    ivs = [x for x in iv["intervals"] if overlaps(x)]
    mine = [r for r in recs if r.get("chain") == chain_name or r.get("session_file") == session_file]
    reads = [r for r in mine if r.get("kind") == "sweep_error"]
    obs = [r for r in mine if r.get("kind") == "observation"]
    opens = [r for r in mine if r.get("kind") == "session_open"]
    gaps = []
    for x in ivs:
        if x.get("closed") is False:
            gaps.append(f"service interval seq {x['start_seq']} ended without a stop record "
                        "(abnormal stop -- nothing bound until the next start)")
        elif x.get("closed") is None:
            gaps.append(f"service interval seq {x['start_seq']} has no stop record "
                        "(it was running until the seal, or died)")
        if x.get("after"):
            gaps.append(f"automatic restart seq {x['start_seq']} ({x.get('after')}) · "
                        f"stopped for {x.get('gap_s')} s")
        if x.get("read") == "plain":
            gaps.append(f"service interval seq {x['start_seq']} was read without the backup "
                        "privilege (it cannot bypass a read deny by the employee)")
    if t0 is not None and ivs and ivs[0].get("start") is not None and ivs[0]["start"] > t0:
        gaps.append("the first record of the session precedes the first start of these intervals")
    if reads:
        gaps.append(f"{len(reads)} read failure records for this session log "
                    f"({str(reads[0].get('ts_recorded', ''))[:19]} ~ "
                    f"{str(reads[-1].get('ts_recorded', ''))[:19]}, "
                    f"stage {sorted({str(r.get('stage')) for r in reads})})")
    for r in obs:
        gaps.append(f"observation seq {r.get('seq')}: {r.get('what')}")
    if len(opens) != 1:
        gaps.append(f"this session has {len(opens)} session open records (there must be 1)")
    return {"intervals": len(ivs), "unclosed": sum(1 for x in ivs if x.get("closed") is False),
            "open_at_seal": sum(1 for x in ivs if x.get("closed") is None),
            "restarts": sum(1 for x in ivs if x.get("after")),
            "read_failures": len(reads), "observations": len(obs), "session_opens": len(opens),
            "gaps": gaps}


def build_gap_report(chain: dict, chain_name: str, seqs: list, rule: str,
                     ledger_path: pathlib.Path):
    ents = chain.get("entries", [])
    sf = first_session_file(ents) or ""
    first = ents[0]["record"] if ents else {}
    scope = {"chain": chain_name, "session_file": sf, "agent": first.get("agent"),
             "disclosed_seqs": sorted(seqs), "chain_records": len(ents),
             "period_utc": [ents[0]["record"].get("ts_recorded") if ents else None,
                            ents[-1]["record"].get("ts_recorded") if ents else None],
             "rule": rule}
    if not ledger_path.exists():
        return None, scope, "no device ledger"
    dev = json.loads(ledger_path.read_text(encoding="utf-8"))
    if not dev.get("seal"):
        return None, scope, "the device ledger is not sealed (seal it at collection, then disclose)"
    lseqs = gap_report_seqs(dev["entries"], chain_name, sf)
    scope["ledger_seqs"] = lseqs
    lp = core.build_disclosure_package(dev, lseqs)
    return lp, scope, ""


def verify_gap_report(pkg: dict, pub_hex, require_signature: bool) -> dict:
    out = {"present": False, "ok": None, "findings": [], "summary": None, "undisclosed_ledger": None}
    lp, scope = pkg.get("ledger_package"), pkg.get("scope")
    if not lp or not scope:
        out["findings"].append("the package has no gap report (ledger proof and scope statement)")
        return out
    out["present"] = True
    res = core.verify_disclosure_package(lp, seal_public_key=pub_hex, require_signature=require_signature)
    ok = res["all_ok"]
    if not res["all_ok"]:
        out["findings"].append("the ledger proof does not hold "
                               "(inclusion proof, seal root, count, or signature)")
    recs = [it["record"] for it in lp.get("items", [])]
    got = sorted(r.get("seq") for r in recs)
    if got != sorted(scope.get("ledger_seqs") or []):
        ok = False
        out["findings"].append("the ledger records in the scope statement differ from the records disclosed")
    if sorted(it.get("seq") for it in pkg.get("items", [])) != sorted(scope.get("disclosed_seqs") or []):
        ok = False
        out["findings"].append("the disclosed records in the scope statement differ "
                               "from the records in the package")
    if pkg.get("total_entries") != scope.get("chain_records"):
        ok = False
        out["findings"].append("the chain record count in the scope statement differs from the package total")
    g = next((r for r in recs if r.get("seq") == 0), None)
    cert = (g or {}).get("enroll_certificate") or {}
    if pub_hex and cert.get("seal_public_key") and cert["seal_public_key"] != pub_hex:
        ok = False
        out["findings"].append("the seal public key in the ledger enrollment certificate "
                               "differs from the public key given")
    s = gap_summary(recs, scope.get("chain", ""), scope.get("session_file", ""),
                    tuple(scope.get("period_utc") or (None, None)))
    if s["session_opens"] != 1:
        ok = False
    out.update(ok=ok, summary=s, undisclosed_ledger=(lp.get("total_entries") or 0) - len(recs))
    return out
