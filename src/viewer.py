# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim, Kookmin University
# SPDX-License-Identifier: Apache-2.0
"""SIDE viewer: it reads collected material and shows it.

This window does not bind.  The binding service binds under the system account, and this
window only reads the result.  A window that runs with user rights and can change a chain
would let the log subject change the chain through it.

The viewer therefore keeps three rules.

  * It only reads files.  This file contains no path that writes to the service folder.
  * It never shows the root key.  It shows only the commitment (a hash).
  * It never shows conversation text.  A chain holds only hashes and byte offsets, so it
    has no text to show.

The viewer has two views for two audiences.

  [Chain view]    The organization or an investigator opens a service folder collected from
                  a device.  If the user picks the root key K0 file that the organization
                  keeps in custody, the viewer runs all four checks (C1-C4).  Without it the
                  viewer runs the checks other than C1.  It also reads the service intervals
                  from the device ledger.  The device does not hold the root key.
  [Package view]  The verifier opens one disclosure package.  The verifier needs only the
                  package, without the whole chain or the root key.  With a seal public key
                  received separately, the viewer also judges the seal signature.

Run
  python side.py verifier                                           opens this window
  python side.py verifier check <package> --seal-public-key <key>   verifies without a window

Design notes
  * side_verify makes every verdict, the same as side_service --verify.  The viewer only lays the
    verdicts out, so the two cannot drift apart.
  * Signals are classed by their stable code (side_verify.Finding), never by their wording.  Only
    some indicate forgery.  If all showed mixed, every collection would open in red, and the reader
    would soon ignore the red.  Names and "other cause" texts follow the paper's table of verifier
    signals.
  * The core's all_ok means "nothing disagrees", not "everything was checked".  A package with no
    records or an empty Merkle root has nothing that can disagree, so it gets no verdict, not a pass.
  * Without a public key the signature result is None, and None does not lower all_ok.  So any
    unjudged layer turns the verdict into "accept (withheld)", and "not judged" is never left blank.
  * The enrollment certificate must commit to the root key in use, and the ledger must bind the
    certificate.
  * The root key is taken only from a file and never shown.  Users often pick the parent of the
    service folder, so the viewer also looks one level down.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    import side_core as core
    import side_verify
    from side_core import CHAINS_DIR, ENROLL_NAME, LEDGER_NAME, SESSIONS_DIR, STORE_DIR_NAME
    from side_util import local_time
except ImportError as exc:
    raise SystemExit(
        "The implementation was not found (%s).\n"
        "side_core.py and side_verify.py must be in the same folder as this file." % exc)

SHOWN_HEX = 32
SHOWN_DECLARED = 48
SHOWN_SIGNALS = 5


def read_json(p: pathlib.Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


_DUPLICATE_OPEN = ("duplicate session open", True,
                   "The same session was opened twice.  Other cause: service failure.  Only the "
                   "session open that reproduces the first tag of the chain is genuine.")
_CURSOR_RESTORE = ("cursor restore", True,
                   "Other cause: service failure.  The service restored its read position from the chain.")
_NO_STOP = ("service interval without a stop record", False,
            "No stop record follows the start.  The service is still running or stopped abnormally. "
            "That interval carries no guarantee.")
SIGNAL_CLASSES = {
    "tag_mismatch": ("C1 tag recomputation mismatch", True,
                     "A record changed or the record order changed after binding."),
    "offset_gap": ("C2 offset gap", True,
                   "The bound byte ranges do not continue.  Other cause: service stop or failure. "
                   "Compare with read failures and stops in the ledger."),
    "content_mismatch": ("C3 line hash mismatch", True,
                         "The session log at that offset differs from the bound line.  Other cause: "
                         "the agent rewrote the file.  Compare with shrink observations in the "
                         "ledger and their times."),
    "checkpoint_shrank": ("C4 shrink after checkpoint", True,
                          "The session log is now smaller than the size the checkpoint recorded.  "
                          "Other cause: the agent rewrote the file.  Compare with shrink "
                          "observations in the ledger and their times."),
    "source_absent": ("session log absent", False,
                      "The session log was deleted or was not collected.  The chain remains, but "
                      "C3 and C4 did not run."),
    "cursor_reset": ("reread after shrink", True,
                     "The service saw the file shrink and set its read position again."),
    "seal_mismatch": ("seal mismatch", True,
                      "The seal does not match the chain.  Records were deleted or added after sealing."),
    "duplicate_open": _DUPLICATE_OPEN,
    "start_key": ("start key missing", True,
                  "The ledger has no session open for this chain, so the tags could not be recomputed."),
    "opened_twice": _DUPLICATE_OPEN,
    "chain_missing": ("session open without a chain (deleted chain)", True,
                      "The ledger recorded a session open, but that chain is not in the service folder."),
    "auto_restart": ("automatic restart", False,
                     "The service stopped on an error and started again.  It bound nothing in between."),
    "start_open": _NO_STOP,
    "start_unclosed": _NO_STOP,
    "exception_stop": ("service interval ended by an exception", True, "The service ended on an error."),
    "observation:file_shrank": ("shrink observation", True,
                                "The service observed the session log shrink."),
    "observation:cursor_restored_from_chain": _CURSOR_RESTORE,
    "observation:state_unreadable": _CURSOR_RESTORE,
    "observation:chain_behind_key": ("unbindable chain", True,
                                     "Other cause: service failure.  The chain file and the key "
                                     "disagree, so the service bound nothing after that point."),
    "observation:chain_key_unreadable": ("unbindable chain", True,
                                         "Other cause: service failure.  The service could not read "
                                         "the chain or the key, so it bound nothing after that point."),
    "sweep_error": ("read failure", False,
                    "The service could not read the session log at that time."),
}
OTHER_OBSERVATIONS = ("other observations", True, "")
OTHER_SIGNALS = ("other signals", True, "")


def signal_class(finding) -> tuple:
    code = getattr(finding, "code", "")
    if code in SIGNAL_CLASSES:
        return SIGNAL_CLASSES[code]
    return OTHER_OBSERVATIONS if code.startswith("observation:") else OTHER_SIGNALS


def classify(findings: list) -> list:
    groups = {}
    order = []
    for f in findings:
        name, severe, explanation = signal_class(f)
        if name not in groups:
            groups[name] = (severe, explanation, [])
            order.append(name)
        groups[name][2].append(f)
    return [(n, groups[n][0], groups[n][1], groups[n][2]) for n in order]


def interval_rows(entries: list) -> list:
    iv = side_verify.service_intervals(entries)
    rows = []
    for x in iv["intervals"]:
        note = {True: x.get("reason") or "", False: "no stop record (abnormal stop)",
                None: "still open"}[x["closed"]]
        rows.append((x["pos"], (x["start_ts"], x.get("stop_ts"), note)))
    for x in iv["stray_stops"]:
        rows.append((x["pos"], (None, x["stop_ts"], x.get("reason") or "")))
    return [row for _, row in sorted(rows, key=lambda r: r[0])]


def signature_text(seal: dict | None, public_key: str, mode: str | None) -> tuple:
    if not seal:
        return "no seal", None
    s = side_verify.seal_signature_status(seal, public_key or None, mode)
    return s["status"] + (" -- " + s["reason"] if s["reason"] else ""), s["ok"]


def read_store(folder: pathlib.Path, public_key: str = "", root_key: bytes | None = None) -> dict:
    chains = folder / CHAINS_DIR
    if not chains.is_dir():
        if (folder / STORE_DIR_NAME / CHAINS_DIR).is_dir():
            folder = folder / STORE_DIR_NAME
            chains = folder / CHAINS_DIR
        else:
            raise RuntimeError(
                "The chains folder is missing.  Pick the service folder that\n"
                "contains chains (usually named store or .side_store).")
    rk = root_key
    certificate = read_json(folder / ENROLL_NAME) if (folder / ENROLL_NAME).exists() else None
    r = {"folder": str(folder), "certificate": certificate,
         "commitment": core.key_commitment(rk) if rk else None}

    dev = chains / LEDGER_NAME
    if certificate:
        r["key_match"] = (certificate.get("key_commitment") == r["commitment"]) if rk else None
        r["bound"] = side_verify.certificate_bound(dev, certificate) if dev.exists() else None

    if dev.exists():
        d = read_json(dev)
        v = side_verify.verify_device(dev, rk)
        r["ledger"] = {"records": v["entries"], "kinds": v["kinds"],
                       "still_running": v["still_running"], "intervals": interval_rows(d["entries"]),
                       "signals": classify(v["findings"])}
    else:
        r["ledger"] = None

    sessions_dir = (folder / SESSIONS_DIR) if (folder / SESSIONS_DIR).is_dir() else None
    mode = (certificate or {}).get("seal_key_mode")
    sessions = []
    for cp in sorted(chains.glob("*.chain.json")):
        if cp.name == LEDGER_NAME:
            continue
        d = read_json(cp)
        v = side_verify.verify_chain(cp, rk, sessions_dir)
        checkpoints = sum(1 for e in d["entries"]
                          if e["record"].get("kind") == "checkpoint")
        sessions.append({"name": cp.name, "source": d.get("source", "-"),
                         "records": v["entries"], "lines": v["lines"],
                         "checkpoints": checkpoints,
                         "signature": signature_text(d.get("seal"), public_key, mode),
                         "signals": classify(v["findings"])})
    r["sessions"] = sessions
    return r


def check_structure(pkg: dict) -> tuple:
    blocking, withheld = [], []
    items = pkg.get("items")
    if not isinstance(items, list) or not items:
        blocking.append("the package discloses no records")
    if not pkg.get("merkle_root"):
        blocking.append("the Merkle root is empty")
    if pkg.get("total_entries") is None:
        withheld.append("total record count not declared")
    if not pkg.get("seal"):
        withheld.append("no seal")
    return blocking, withheld


def read_public_key(path: pathlib.Path | None, value: str | None = None) -> str:
    text = path.read_text(encoding="utf-8-sig") if path is not None else (value or "")
    try:
        return core.parse_seal_public_key(text)
    except ValueError:
        name = path.name if path is not None else "the entered value"
        raise ValueError("%s is not a seal public key.  It must be 64 hex digits (read length %d)."
                         % (name, len(text.strip()))) from None


def read_package(path: pathlib.Path, public_key: str, require_signature: bool) -> dict:
    pkg = read_json(path)
    if "items" not in pkg or "merkle_root" not in pkg:
        raise RuntimeError("This is not a disclosure package.  Pick a JSON file "
                           "made with --disclose.")
    v = core.verify_disclosure_package(pkg, seal_public_key=public_key or None,
                                       require_signature=require_signature)
    body = (pkg.get("seal") or {}).get("body") or {}
    blocking, withheld_structure = check_structure(pkg)
    return {"file": str(path), "verdict": v, "blocking": blocking,
            "withheld_structure": withheld_structure,
            "disclosed": len(pkg.get("items", [])),
            "total": pkg.get("total_entries"),
            "root": pkg.get("merkle_root"),
            "sealed_at": body.get("sealed_at_utc") or body.get("issued_at_utc"),
            "declaration": pkg.get("enroll_declaration") or {},
            "gap": side_verify.verify_gap_report(pkg, public_key or None, require_signature),
            "scope": pkg.get("scope") or {}}


FONT = "Segoe UI" if os.name == "nt" else "DejaVu Sans"
NAME_COLUMN = "170p"
GREY = "#555"


class Viewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SIDE viewer (read only)")
        self.geometry("1000x680")
        self.minsize(840, 560)

        header = ttk.Frame(self, padding=(14, 12, 14, 4))
        header.pack(fill=tk.X)
        ttk.Label(header, text="SIDE viewer",
                  font=(FONT, 15, "bold")).pack(anchor=tk.W)
        ttk.Label(header, foreground=GREY, font=(FONT, 9),
                  text="This window reads collected material and shows it. It changes "
                       "nothing. The binding service binds under the system account.",
                  ).pack(anchor=tk.W)

        buttons = ttk.Frame(self, padding=(14, 8, 14, 4))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Chain view  (collected service folder)",
                   command=self.open_chain).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Package view  (disclosure package)",
                   command=self.open_package).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(buttons, text="Clear",
                   command=lambda: self.write(clear=True)).pack(side=tk.RIGHT)

        options = ttk.LabelFrame(self, text=" Seal public key (seal_pub.hex), received "
                                            "separately from the organization ",
                                 padding=(10, 6))
        options.pack(fill=tk.X, padx=14, pady=(4, 2))
        row = ttk.Frame(options)
        row.pack(fill=tk.X)
        ttk.Button(row, text="Choose file…",
                   command=self.choose_public_key_file).pack(side=tk.LEFT, padx=(0, 6))
        self.public_key = tk.StringVar()
        self.public_key_origin = tk.StringVar(value="")
        self._loaded_key = ""
        self.public_key.trace_add("write", lambda *_: self.public_key_origin.set(
            self.public_key_origin.get() if self.public_key.get().strip() == self._loaded_key else
            ("pasted value" if self.public_key.get().strip() else "")))
        ttk.Entry(row, textvariable=self.public_key, font=(FONT, 9)).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(row, textvariable=self.public_key_origin, foreground=GREY,
                  font=(FONT, 8)).pack(side=tk.LEFT, padx=(6, 0))
        self.require_signature = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Reject if unsigned",
                        variable=self.require_signature).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(options, foreground="#777", font=(FONT, 8),
                  text="A public key inside the package is no basis for trust. Obtain the "
                       "seal_pub.hex the organization published in advance through another "
                       "channel, then choose it or paste its value.",
                  ).pack(anchor=tk.W, pady=(4, 0))

        body = ttk.Frame(self, padding=(14, 4, 14, 6))
        body.pack(fill=tk.BOTH, expand=True)
        self.text = tk.Text(body, wrap="word", font=(FONT, 10), bg="#FCFCFC",
                            relief=tk.SUNKEN, borderwidth=1, padx=10, pady=8,
                            tabs=(NAME_COLUMN, "left"))
        scrollbar = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set, state="disabled")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.text.tag_configure("base", lmargin2=NAME_COLUMN)
        self.text.tag_configure("good", foreground="#14683A")
        self.text.tag_configure("bad", foreground="#B3261E")
        self.text.tag_configure("warn", foreground="#9A6400")
        self.text.tag_configure("dim", foreground="#767676")
        self.text.tag_configure("heading", foreground="#111",
                                font=(FONT, 11, "bold"), spacing1=8, spacing3=3)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, relief=tk.SUNKEN,
                  anchor=tk.W, padding=(10, 3), font=(FONT, 9),
                  ).pack(fill=tk.X, side=tk.BOTTOM)

    def write(self, s: str = "", tag: str = "", clear: bool = False):
        self.text.configure(state="normal")
        if clear:
            self.text.delete("1.0", tk.END)
        else:
            self.text.insert(tk.END, s + "\n",
                             ("base", tag) if tag else ("base",))
        self.text.configure(state="disabled")
        self.text.see(tk.END)

    def field(self, name, value, tag=""):
        self.write("   %s	%s" % (name, value), tag)

    def write_signals(self, signals, indent="   "):
        if not signals:
            self.write(indent + "no signals", "good")
            return
        for name, severe, explanation, raw in signals:
            self.write("%s%s (%d)" % (indent, name, len(raw)),
                       "bad" if severe else "warn")
            if explanation:
                self.write("%s  %s" % (indent, explanation), "dim")
            for f in raw[:SHOWN_SIGNALS]:
                self.write("%s    · %s" % (indent, f), "dim")
            if len(raw) > SHOWN_SIGNALS:
                self.write("%s    … and %d more" % (indent, len(raw) - SHOWN_SIGNALS), "dim")

    def on_error(self, e):
        self.write()
        self.write("The viewer could not read this.", "bad")
        for ln in str(e).splitlines():
            self.write("   " + ln, "bad")
        self.status.set("Failed")

    def run_task(self, task, show):
        def worker():
            try:
                r = task()
            except Exception as exc:
                self.after(0, self.on_error, exc)
                return
            self.after(0, show, r)
        self.status.set("Reading…")
        threading.Thread(target=worker, daemon=True).start()

    def choose_public_key_file(self):
        f = filedialog.askopenfilename(
            title="Choose the seal public key file (seal_pub.hex)",
            filetypes=[("Seal public key", "*.hex *.key *.txt"), ("All files", "*.*")])
        if not f:
            return
        try:
            v = read_public_key(pathlib.Path(f))
        except ValueError as exc:
            messagebox.showerror("SIDE viewer", str(exc))
            return
        self._loaded_key = v
        self.public_key_origin.set("← " + pathlib.Path(f).name)
        self.public_key.set(v)

    def public_key_value(self) -> str | None:
        s = self.public_key.get().strip().strip('"')
        if not s:
            return ""
        try:
            p = pathlib.Path(s)
            if len(s) != 64 and p.is_file():
                return read_public_key(p)
            return read_public_key(None, s)
        except (ValueError, OSError) as exc:
            messagebox.showerror("SIDE viewer", str(exc))
            return None

    def open_chain(self):
        key = self.public_key_value()
        if key is None:
            return
        d = filedialog.askdirectory(
            title="Choose the collected service folder (the folder that contains chains)")
        if d:
            f = filedialog.askopenfilename(
                title="Root key K0 file kept by the organization "
                      "(cancel if absent: tag recomputation is skipped)")
            rk = None
            if f:
                try:
                    rk = bytes.fromhex(pathlib.Path(f).read_text(encoding="utf-8-sig").strip())
                    if len(rk) != 32:
                        raise ValueError("read %d bytes" % len(rk))
                except (ValueError, OSError) as exc:
                    messagebox.showerror("SIDE viewer",
                                         "%s is not a root key file.  It must hold 64 hex digits "
                                         "(%s)." % (pathlib.Path(f).name, exc))
                    return
            self.run_task(lambda: read_store(pathlib.Path(d), key, rk), self.show_chain)

    def show_chain(self, r):
        self.write(clear=True)
        self.write("Chain view", "heading")
        self.field("Service folder", r["folder"])
        if r["commitment"]:
            self.field("Root key commitment", r["commitment"][:SHOWN_HEX] + "…")
            self.write("   The key itself is not shown. The value above is the hash of the key.",
                       "dim")
        else:
            self.field("Root key", "not given: tag recomputation (C1) and the commitment "
                                   "check are skipped", "warn")

        cert = r["certificate"]
        self.write("Enrollment certificate", "heading")
        if not cert:
            self.write("   None. This service folder did not go through enrollment.", "warn")
        else:
            self.field("Device", cert.get("device_id", "-"))
            self.field("Issued", local_time(cert.get("issued_at_utc")))
            self.field("Seal public key", (cert.get("seal_public_key") or "-")[:SHOWN_HEX] + "…")
            if r["key_match"] is not None:
                self.field("Root key check",
                           "match" if r["key_match"] else "mismatch: the key changed",
                           "good" if r["key_match"] else "bad")
            if r["bound"] is not None:
                self.field("Bound in ledger",
                           "yes" if r["bound"] else "no: the certificate changed",
                           "good" if r["bound"] else "bad")

        ledger = r["ledger"]
        self.write("Device ledger", "heading")
        if not ledger:
            self.write("   None. The viewer cannot tell when the service ran.", "warn")
        else:
            self.field("Records", ledger["records"])
            self.field("Kinds", ", ".join("%s %d" % kv
                                          for kv in sorted(ledger["kinds"].items())))
            if ledger["still_running"]:
                self.field("Service state", "an interval is still open", "warn")
                self.write("   The service may still be running, or someone may have killed it. "
                           "The two cannot be told apart at verification time.", "dim")
            else:
                self.field("Service state", "normal stop through the last interval", "good")
            if ledger["intervals"]:
                self.write("   Service intervals")
                for s, e, why in ledger["intervals"]:
                    self.write("     %s  →  %s   %s"
                               % (local_time(s), local_time(e) if e else "(no stop record)",
                                  why),
                               "" if e else "warn")
            self.write_signals(ledger["signals"])

        self.write("%d session chains" % len(r["sessions"]), "heading")
        flagged = 0
        for s in r["sessions"]:
            severe = any(x[1] for x in s["signals"])
            flagged += severe
            self.write("   %s" % s["name"], "bad" if severe else "good")
            self.write("     source %s" % s["source"], "dim")
            self.write("     %d records · %d lines · %d checkpoints · seal %s"
                       % (s["records"], s["lines"], s["checkpoints"], s["signature"][0]),
                       "bad" if s["signature"][1] is False else "")
            self.write_signals(s["signals"], indent="     ")

        self.write("Verdict", "heading")
        self.write("   %d of %d session chains carry a signal that indicates forgery"
                   % (flagged, len(r["sessions"])), "bad" if flagged else "good")
        self.status.set("Done. Nothing was written to the service folder.")

    def open_package(self):
        key = self.public_key_value()
        if key is None:
            return
        f = filedialog.askopenfilename(
            title="Choose the disclosure package",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if f:
            require = self.require_signature.get()
            self.run_task(lambda: read_package(pathlib.Path(f), key, require),
                          self.show_package)

    def show_package(self, r):
        v = r["verdict"]
        self.write(clear=True)
        self.write("Package view", "heading")
        self.field("File", r["file"])
        self.field("Disclosed / total", "%s / %s records" % (r["disclosed"], r["total"]))
        self.field("Merkle root", str(r["root"])[:SHOWN_HEX] + "…")
        self.field("Seal time", local_time(r["sealed_at"]))

        if r["blocking"]:
            self.write("No verdict possible", "heading")
            for m in r["blocking"]:
                self.write("   · " + m, "bad")
            self.write("   The package has nothing to compare, so a pass in the layers below "
                       "means nothing.", "dim")

        self.write("What was confirmed: the three verification layers", "heading")
        items = v["items"]
        attached = sum(1 for x in items if x["ok"])
        self.field("Layer 1 membership", "%d / %d pass" % (attached, len(items)),
                   "good" if items and attached == len(items) else "bad")
        self.write("   Do the disclosed records hang from the root of this package "
                   "(inclusion proof)?", "dim")
        value = v["entry_count_match"]
        self.field("Layer 2 record count", {True: "match", False: "mismatch",
                                            None: "not judged: no seal"}[value],
                   {True: "good", False: "bad"}.get(value, "warn"))
        self.write("   Does the total record count in the package equal the count in the "
                   "seal body?", "dim")
        root_ok, sig_ok = v["seal_root_match"], v["seal_sig_ok"]
        layer3 = (False if False in (root_ok, sig_ok) else None if None in (root_ok, sig_ok)
                  else True)
        self.field("Layer 3 seal authenticity", {True: "pass", False: "fail",
                                                 None: "partly not judged"}[layer3],
                   {True: "good", False: "bad"}.get(layer3, "warn"))
        self.write("   Does this seal point to this package, and did the organization "
                   "sign it?", "dim")
        self.field("    · seal root", {True: "match", False: "mismatch",
                                       None: "not judged: no seal"}[root_ok],
                   {True: "good", False: "bad"}.get(root_ok, "warn"))
        self.field("    · organization signature", v["seal_sig_status"],
                   {True: "good", False: "bad"}.get(sig_ok, "warn"))
        if v["seal_sig_reason"]:
            self.write("      " + v["seal_sig_reason"], "dim")

        g, sc = r["gap"], r["scope"]
        self.write("Gap report and scope statement", "heading")
        if g["present"]:
            self.field("Gap report", "holds" if g["ok"] else "does not hold",
                       "good" if g["ok"] else "bad")
            self.write("   Did the discloser report the windows the service missed, using "
                       "sealed ledger records?", "dim")
            per = sc.get("period_utc") or [None, None]
            self.field("Scope statement", "%s · %s – %s · %d / %s records" % (
                sc.get("agent") or "-", local_time(per[0]), local_time(per[-1]),
                len(sc.get("disclosed_seqs") or []), sc.get("chain_records")))
            if sc.get("rule"):
                self.field("Selection rule", sc["rule"])
            s = g["summary"]
            self.field("Service intervals", "%d · abnormal stop %d · automatic restart %d" % (
                s["intervals"], s["unclosed"], s["restarts"]),
                "good" if not (s["unclosed"] or s["restarts"]) else "warn")
            self.field("Read failures · observations",
                       "%d · %d" % (s["read_failures"], s["observations"]),
                       "good" if not (s["read_failures"] or s["observations"]) else "warn")
            for x in s["gaps"]:
                self.write("   · " + x, "warn")
            for x in g["findings"]:
                self.write("   ! " + x, "bad")
        else:
            self.field("Gap report", "none: the discloser reported no gaps", "warn")

        self.write("What was not confirmed", "heading")
        if g["present"]:
            self.write("   The viewer cannot see ledger records that the discloser left out of "
                       "the report. %s ledger records are not in the report (for example "
                       "records of other sessions)." % g["undisclosed_ledger"], "dim")
        self.write("   The viewer did not recompute the seal tag (HMAC). That needs the "
                   "organization's secret key. A verifier who holds only the package checks "
                   "seal authenticity through the organization signature in layer 3.", "dim")
        if not self.public_key.get().strip():
            self.write("   No public key was entered, so the organization signature in layer 3 "
                       "was not judged.", "warn")
        self.write("   The viewer cannot know what the undisclosed records contained. The three "
                   "layers can only show whether a selective disclosure broke its declared "
                   "scope.", "dim")

        if r["declaration"]:
            self.write("Values declared by the discloser", "heading")
            for k in ("device_id", "seal_key_id", "seal_key_mode",
                      "key_commitment"):
                if k in r["declaration"]:
                    value = str(r["declaration"][k])
                    self.field(k, value[:SHOWN_DECLARED] + ("…" if len(value) > SHOWN_DECLARED else ""))
            self.write("   The discloser wrote these values. They are no evidence until "
                       "someone compares them with the organization's custody copy.", "dim")

        withheld = [name for name, value in (("layer 2 record count", v["entry_count_match"]),
                                             ("layer 3 seal root", v["seal_root_match"]),
                                             ("layer 3 organization signature", v["seal_sig_ok"]))
                    if value is None]
        withheld += r["withheld_structure"]
        if not r["gap"]["present"]:
            withheld.append("gap report")
        overall = v["all_ok"] and r["gap"]["ok"] is not False
        self.write("Verdict", "heading")
        if r["blocking"]:
            self.write("   no verdict possible: %s" % ", ".join(r["blocking"]), "bad")
        elif not overall:
            self.write("   reject: a layer disagrees", "bad")
        elif withheld:
            self.write("   accept (withheld): nothing disagrees, but some items were not "
                       "judged: %s" % ", ".join(withheld), "warn")
        else:
            self.write("   accept: all three layers and the gap report pass", "good")
        self.status.set("Done. Nothing was written to the package.")


if __name__ == "__main__":
    Viewer().mainloop()
