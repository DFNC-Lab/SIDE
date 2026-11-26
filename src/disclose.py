# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
"""SIDE disclosure (organization): build a disclosure package from the incident part of a signed collection.

On the organization machine, `side.py organization disclose` calls this file
(SIDE_STORE = received\\<archive>, SIDE_OUT = disclosures\\).

  python side.py organization disclose                            choose interactively
  python side.py organization disclose --list                     only list the chains and records
  python side.py organization disclose --chain 3 --range 5-9,12   build directly

What the package contains
-------------------------
The chosen records, their Merkle inclusion proofs and the seal.  **The package contains no
conversation text.**  The chain holds only hashes and byte positions.  So the package proves
"this record was at this position", not "someone said this".  With --lines, a separate
.lines.jsonl file carries the text of the chosen lines, and that file does contain conversation text.

Why a part and not everything
-----------------------------
Disclosing everything also sends parts unrelated to the incident.  Disclosing a part invites the
suspicion that only favourable records were chosen.  So the package **also reports the number** of
records not disclosed, and every item carries an inclusion proof.  The receiver can tell whether the
disclosure broke its stated scope.
"""
import argparse
import json
import os
import pathlib
import shutil
import sys

SRC = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

import side_core as core
import side_util as util
from side_util import say

HERE = SRC.parent / "organization"
STORE = pathlib.Path(os.environ.get("SIDE_STORE") or (HERE / core.STORE_DIR_NAME))
CHAINS = STORE / core.CHAINS_DIR
SERVICE = SRC / "side_service.py"
RULE = util.RULE
BROWSE_ROWS = 12
LIST_ROWS = 20
NOTHING_CHOSEN = "  Nothing chosen.  Exiting."


def short_time(s) -> str:
    return util.local_time(s, "%m-%d %H:%M:%S")[:19]


def load_chains():
    chains = []
    if not CHAINS.is_dir():
        return chains
    for cp in sorted(CHAINS.glob("*.chain.json")):
        if cp.name == core.LEDGER_NAME:
            continue
        try:
            d = json.loads(cp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entries = d.get("entries", [])
        chains.append({
            "path": cp, "name": cp.name, "source": d.get("source", "-"),
            "records": len(entries),
            "lines": sum(1 for e in entries if e["record"].get("kind") == "line"),
            "seal": bool(d.get("seal")), "data": d,
        })
    return chains


def parse_range(text: str, limit: int) -> list:
    picked = set()
    for piece in text.replace(" ", "").split(","):
        if not piece:
            continue
        if "-" in piece[1:]:
            a, _, b = piece.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                raise ValueError("Could not read the range: %s" % piece)
            if lo > hi:
                lo, hi = hi, lo
            picked.update(range(lo, hi + 1))
        else:
            try:
                picked.add(int(piece))
            except ValueError:
                raise ValueError("Could not read the number: %s" % piece)
    outside = [s for s in picked if s < 0 or s >= limit]
    if outside:
        raise ValueError("Numbers not in the chain: %s (valid: 0 to %d)"
                         % (sorted(outside)[:5], limit - 1))
    return sorted(picked)


def show_records(d, count=BROWSE_ROWS):
    entries = d.get("entries", [])
    say("    %-5s %-14s %-19s %s" % ("No.", "kind", "time", "byte range"))
    say("    " + "-" * RULE)
    for e in entries[:count]:
        r = e["record"]
        span = ("%s~%s" % (r["start"], r["end"])
                if r.get("start") is not None else "-")
        say("    %-5s %-14s %-19s %s"
            % (r.get("seq"), r.get("kind", "?"), short_time(r.get("ts_recorded")), span))
    if len(entries) > count:
        say("    ... and %d more (numbers 0 to %d)"
            % (len(entries) - count, len(entries) - 1))


def main():
    ap = argparse.ArgumentParser(description="SIDE disclosure package")
    ap.add_argument("--list", action="store_true", help="only list")
    ap.add_argument("--chain", help="chain number or file name")
    ap.add_argument("--range", help="record numbers to disclose, e.g. 5-9,12")
    ap.add_argument("--rule", help="selection rule written into the scope statement "
                                   "(e.g. 'deployment incident of 3 Nov')")
    ap.add_argument("--lines", action="store_true",
                    help="also write the line text of the chosen lines to .lines.jsonl "
                         "(the collection must include the session logs)")
    a = ap.parse_args()
    util.keep_output_alive()

    if not STORE.exists():
        say("No received collection.  Run organization\\2_receive_collection.bat first.")
        say("  Looked in: " + str(STORE))
        return 1

    chains = load_chains()
    if not chains:
        say("The collection holds no chain.")
        return 1

    say("=" * RULE)
    say("  SIDE make disclosure package")
    say("=" * RULE)
    say()
    say("The package contains no conversation text.  It contains the fact that the chosen")
    say("records were at their positions, and the number of records not disclosed.")
    say()
    say("[1/3] Which chain to draw from")
    say()
    for i, c in enumerate(chains, 1):
        say("  [%d] %s" % (i, c["name"]))
        say("      source %s · records %d · lines %d · %s"
            % (c["source"], c["records"], c["lines"],
               "sealed" if c["seal"] else "not sealed"))
    say()

    if a.list:
        for c in chains:
            say()
            say("── %s" % c["name"])
            show_records(c["data"], count=LIST_ROWS)
        return 0

    chosen = None
    if a.chain:
        if a.chain.isdigit() and 1 <= int(a.chain) <= len(chains):
            chosen = chains[int(a.chain) - 1]
        else:
            chosen = next((c for c in chains if c["name"] == a.chain), None)
        if chosen is None:
            say("No such chain: %s" % a.chain)
            return 1
    else:
        try:
            answer = input("  Choose a number (1-%d): " % len(chains)).strip()
        except EOFError:
            say(NOTHING_CHOSEN)
            return 1
        if not (answer.isdigit() and 1 <= int(answer) <= len(chains)):
            say("  Choose a number from 1 to %d." % len(chains))
            return 1
        chosen = chains[int(answer) - 1]

    say()
    say("[2/3] Which records to disclose -- %s" % chosen["name"])
    say()
    if not chosen["seal"]:
        say("  Warning: this chain is not sealed yet.")
        say("           The receiver reads a package without a seal as 'no seal'.")
        say("           Running employee\\4_collect.bat on the device first seals the chain.")
        say()
    show_records(chosen["data"])
    say()

    if a.range:
        range_text = a.range
    else:
        say("  Example: 5-9,12   or   0-%d (all)" % (chosen["records"] - 1))
        try:
            range_text = input("  Numbers to disclose: ").strip()
        except EOFError:
            say(NOTHING_CHOSEN)
            return 1
    if not range_text:
        say(NOTHING_CHOSEN)
        return 1

    try:
        seqs = parse_range(range_text, chosen["records"])
    except ValueError as exc:
        say("  %s" % exc)
        return 1
    rule = a.rule
    if rule is None and not a.range:
        try:
            rule = input("  Selection rule (written into the scope statement, may be empty): ").strip()
        except EOFError:
            rule = ""
    if not seqs:
        say("  No numbers chosen.")
        return 1

    say()
    say("[3/3] Building -- %d disclosed (total %d)"
        % (len(seqs), chosen["records"]))
    rc, _ = util.run_service(
        SERVICE, "--disclose", chosen["path"], "--seqs", ",".join(str(s) for s in seqs),
        *(["--with-lines"] if a.lines else []),
        *(["--scope", rule] if rule else []),
        *(["--sessions-dir", os.environ["SIDE_SESSIONS_DIR"]] if os.environ.get("SIDE_SESSIONS_DIR") else []),
        cwd=HERE)
    if rc != 0:
        say()
        say("  Could not build the package.")
        return 1

    made = chosen["path"].with_suffix(".package.json")
    if not made.exists():
        say("  Could not find the package file: %s" % made)
        return 1

    try:
        device = (json.loads((STORE / core.ENROLL_NAME).read_text(encoding="utf-8")).get("device_id")
                  or "unknown")
    except (OSError, ValueError):
        device = "unknown"
    out_dir = pathlib.Path(os.environ.get("SIDE_OUT") or (HERE / "disclosures"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / ("SIDE_disclosure_%s_%s.json" % (device, util.now_stamp()))
    lines_file = made.with_suffix(".lines.jsonl")
    lines_out = out.with_suffix(".lines.jsonl") if a.lines and lines_file.exists() else None
    taken = [p for p in (out, lines_out) if p is not None and p.exists()]
    if taken:
        say()
        say("  A disclosure file of this name already exists, so nothing was written:")
        for p in taken:
            say("    %s" % p)
        say("  Wait one second and run again, or move the existing file away.")
        return 1
    shutil.copyfile(made, out)
    if lines_out is not None:
        shutil.copyfile(lines_file, lines_out)
        say("  Line text: %s" % lines_out)

    say()
    say("-" * RULE)
    say("  Send only this file.")
    say("    %s" % out)
    say()
    if lines_out is None:
        say("  It contains no conversation text.")
    else:
        say("  The package contains no conversation text, but the line text file next to it does.")
        say("  Send the line text file only to a receiver entitled to read those lines.")
    say("  The receiver opens it with 'package view' in the SIDE viewer.")
    say()
    say("  Warning: do not send the seal public key together with this file.")
    say("           The key is evidence only when the receiver gets it from the organization separately.")
    say("-" * RULE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
