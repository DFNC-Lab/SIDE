# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE binding: find session logs, read complete new lines and bind them (Phase 1).

Each sweep appends a line record (byte range and SHA-256) for every complete new line of every
session log.  The cursor is restored from the chain, never trusted from state.json.  Logs are read
with SeBackupPrivilege, so an employee who denies SYSTEM read access is bypassed.  Problems with one
file go to the ledger; only a broken ledger stops the service.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import pathlib
import sys
import time
import unicodedata

import side_core as core
import side_store as store
from side_store import LedgerBroken

SWEEP_INTERVAL_SEC = 2.0
CHECKPOINT_SEC = 30.0
HEARTBEAT_SEC = 300.0
HINTS_DIR: pathlib.Path | None = None
READ_MODE = "plain"
NL = 0x0A

STATE_SAVES_PER_SWEEP = 256


def configure(checkpoint_sec: float, heartbeat_sec: float, hints_dir: str | None) -> None:
    global CHECKPOINT_SEC, HEARTBEAT_SEC, HINTS_DIR
    CHECKPOINT_SEC = checkpoint_sec
    HEARTBEAT_SEC = max(heartbeat_sec, CHECKPOINT_SEC)
    if hints_dir:
        HINTS_DIR = pathlib.Path(hints_dir)


SOURCES = {
    "claude": ["~/.claude/projects/*/*.jsonl"],
    "codex": ["~/.codex/sessions/**/*.jsonl"],
    "antigravity": ["~/.gemini/antigravity/brain/*/.system_generated/logs/transcript*.jsonl",
                    "~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript*.jsonl"],
}


def normalize_path(p) -> str:
    return unicodedata.normalize("NFC", str(p))


def _antigravity_conv(session_path: pathlib.Path) -> str | None:
    p = session_path.parts
    if (len(p) >= 5 and p[-2] == "logs" and p[-3] == ".system_generated"
            and p[-5] == "brain"):
        return p[-4]
    return None


def session_id_for(session_path: pathlib.Path) -> str:
    conv = _antigravity_conv(session_path)
    if conv:
        return f"{conv}/{session_path.stem}"
    return session_path.stem


def agent_of(session_path: pathlib.Path) -> str:
    parts = [x.lower() for x in session_path.parts]
    if "antigravity-cli" in parts:
        return "antigravity-cli"
    if "antigravity" in parts:
        return "antigravity"
    if ".codex" in parts:
        return "codex-cli"
    if ".claude" in parts:
        return "claude-code"
    return "unknown"


def chain_path_for(session_path: pathlib.Path) -> pathlib.Path:
    name_nfc = normalize_path(session_path)
    h = hashlib.sha256(name_nfc.encode("utf-8")).hexdigest()[:16]
    stem = unicodedata.normalize("NFC", session_path.stem)[:40]
    conv = _antigravity_conv(session_path)
    if conv:
        cli = any(x.lower().endswith("antigravity-cli") for x in session_path.parts)
        stem = f"{'agc' if cli else 'ag'}-{conv[:8]}-{stem}"[:40]
    return store.CHAINS / f"{stem}_{h}.chain.json"


def resolve_patterns(patterns: list[str], sources: list[str],
                     st: dict | None = None) -> list[str]:
    out = list(patterns or [])
    for s in sources or []:
        if s == "bound":
            for key in sorted((st or {}).get("files", {})):
                out.append(glob.escape(key))
        else:
            out.extend(SOURCES[s])
    return out


def explain_sources() -> None:
    print("Choose what to sweep.  Give at least one of the two.")
    print()
    print("  --source claude     ~/.claude/projects/*/*.jsonl")
    print("  --source codex      ~/.codex/sessions/**/*.jsonl")
    print("  --source antigravity  ~/.gemini/antigravity/brain/*/.system_generated/logs/transcript*.jsonl")
    print("                        (also ~/.gemini/antigravity-cli/brain/... of the Antigravity CLI)")
    print("  --source claude codex antigravity   (several together)")
    print("  --source bound      continue only with files already bound")
    print()
    print("  --patterns \"D:/somewhere/*.jsonl\"   to give a path directly")
    print()
    print("There is no default target.  The binding scope never grows without an explicit choice.")


def targets(patterns: list[str]) -> list[pathlib.Path]:
    out = []
    for pat in patterns:
        for f in glob.glob(os.path.expanduser(pat), recursive=True):
            p = pathlib.Path(f)
            if p.is_file():
                out.append(p)
    return sorted(set(out))


def load_or_create(cp: pathlib.Path, session_path: pathlib.Path) -> core.Chain:
    genesis = {
        "kind": "session_start",
        "device_id": os.environ.get("COMPUTERNAME", "unknown"),
        "session_file": str(session_path),
        "session_id": session_id_for(session_path),
        "agent": agent_of(session_path),
    }
    if cp.exists():
        return store.open_chain(cp, f"JSONL: {session_path.name}", genesis)

    sid = session_id_for(session_path)
    try:
        dev = store.open_device()
    except Exception as e:
        raise LedgerBroken(f"could not open the ledger: {type(e).__name__}: {e}") from e
    start = store.pending_start_key(cp, dev)
    if start is None:
        j = len(dev.entries)
        start = core.chain_start_key(dev._key, sid)
        store.save_pending_start_key(cp, start, j)
        dev.append({"kind": "session_open", "session_id": sid,
                    "session_file": str(session_path), "chain": cp.name,
                    "agent": agent_of(session_path)})
        try:
            store.persist(dev, store.DEVICE)
        except Exception as e:
            raise LedgerBroken(f"could not save the ledger: {type(e).__name__}: {e}") from e
    ch = store.open_chain(cp, f"JSONL: {session_path.name}", genesis, start)
    store.persist(ch, cp)
    return ch


def enable_backup_privilege() -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                          ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p]
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED = 0x20, 0x8, 0x2
    h = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(h)):
        return False
    try:
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeBackupPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
        ok = adv.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None)
        return bool(ok) and ctypes.get_last_error() == 0
    finally:
        k32.CloseHandle(h)


def open_backup(path):
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    GENERIC_READ, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS = 0x80000000, 3, 0x02000000
    share = 0x1 | 0x2 | 0x4
    h = k32.CreateFileW(str(path), GENERIC_READ, share, None, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, None)
    if h is None or h == wintypes.HANDLE(-1).value:
        err = ctypes.get_last_error()
        e = ctypes.WinError(err)
        e.filename = str(path)
        raise e
    fd = msvcrt.open_osfhandle(h, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    return os.fdopen(fd, "rb")


def open_source(path: pathlib.Path):
    if READ_MODE == "backup":
        return open_backup(path)
    return path.open("rb")


def use_read_mode(want: str) -> str:
    global READ_MODE
    if want == "plain":
        READ_MODE = "plain"
        return READ_MODE
    on = enable_backup_privilege()
    if want == "backup" and not on:
        raise ValueError("could not enable SeBackupPrivilege (run under the system account or "
                         "as Backup Operators)")
    READ_MODE = "backup" if on else "plain"
    return READ_MODE


def read_complete_lines(path: pathlib.Path, offset: int):
    size = path.stat().st_size
    if size < offset:
        return [], offset, True
    if size == offset:
        return [], offset, False
    with open_source(path) as fh:
        fh.seek(offset)
        buf = fh.read(size - offset)
    end = buf.rfind(bytes([NL]))
    if end == -1:
        return [], offset, False
    usable = buf[: end + 1]
    lines, start = [], offset
    for raw in usable.splitlines(keepends=True):
        if raw.strip():
            lines.append((start, raw))
        start += len(raw)
    return lines, offset + len(usable), False


def _read_range(path: pathlib.Path, a: int, b: int) -> bytes:
    with open_source(path) as fh:
        fh.seek(a)
        return fh.read(max(0, b - a))


def _nonblank_lines(buf: bytes) -> int:
    return sum(1 for seg in buf.split(b"\n") if seg.strip())


def restart_point(path: pathlib.Path, size: int) -> int:
    block = 1 << 16
    pos = size
    with open_source(path) as fh:
        while pos > 0:
            start = max(0, pos - block)
            fh.seek(start)
            buf = fh.read(pos - start)
            i = buf.rfind(bytes([NL]))
            if i != -1:
                return start + i + 1
            pos = start
    return 0


def chain_cursor(cp: pathlib.Path) -> int | None:
    try:
        d = json.loads(cp.read_text(encoding="utf-8"))
        ents = d["entries"]
        kd = json.loads(store.key_path(cp).read_text(encoding="utf-8"))
        if int(kd["seq"]) > len(ents):
            return None
        for e in reversed(ents):
            r = e["record"]
            if r.get("kind") == "line":
                return int(r["end"])
            if r.get("kind") == "cursor_reset":
                return int(r["to"])
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        return None


def _blank_between(path: pathlib.Path, a: int, b: int) -> bool:
    try:
        with open_source(path) as fh:
            fh.seek(a)
            buf = fh.read(b - a)
        return len(buf) == b - a and not buf.strip()
    except OSError:
        return False


def collect_hints() -> list[dict]:
    hints = HINTS_DIR if HINTS_DIR is not None else store.HINTS
    out = []
    if not hints.exists():
        return out
    for f in sorted(hints.glob("*.json")):
        try:
            h = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(h, dict):
                out.append(h)
        except Exception:
            pass
        try:
            f.unlink()
        except OSError:
            pass
    return out


_reconciled: set[str] = set()
_state_noted = False
_state_save_failed = False
_state_pace = 0


def _save_state_safely(st: dict, log=print) -> None:
    global _state_save_failed
    try:
        store.save_state(st)
    except OSError as e:
        if not _state_save_failed:
            _state_save_failed = True
            store.note_device("sweep_error", stage="state", session_file=str(store.STATE),
                              error=type(e).__name__, errno=getattr(e, "errno", None))
            log(f"  ! could not write the cursor file ({type(e).__name__}) -- restoring from the chain")


def _save_state_paced(st: dict, log) -> None:
    global _state_pace
    every = max(1, len(st["files"]) // STATE_SAVES_PER_SWEEP)
    _state_pace += 1
    if _state_pace >= every:
        _state_pace = 0
        _save_state_safely(st, log)


def sweep(patterns: list[str], st: dict,
          checkpoint: bool, log=print, should_stop=None) -> dict:
    global _state_noted
    stat = {"files": 0, "lines": 0, "checkpoints": 0, "hints": 0,
            "shrunk": 0, "errors": 0, "seen": 0}
    if store.state_problem and not _state_noted:
        store.note_device("observation", what="state_unreadable", error=store.state_problem)
        _state_noted = True
    hints = collect_hints()

    for sp in targets(patterns):
        if should_stop is not None and should_stop():
            stat["stopped"] = True
            break
        try:
            _sweep_one(sp, st, checkpoint, hints, stat, log)
        except LedgerBroken:
            raise
        except Exception as e:
            store.note_device("sweep_error", session_file=str(sp), stage="unexpected",
                              error=type(e).__name__, detail=str(e)[:200])
            stat["errors"] += 1
            log(f"  ! skipping this file: {sp.name} ({type(e).__name__})")

    _save_state_safely(st, log)
    return stat


def _sweep_one(sp: pathlib.Path, st: dict, checkpoint: bool, hints: list[dict],
               stat: dict, log) -> None:
    key = normalize_path(sp)
    first_time = key not in st["files"]
    rec = st["files"].setdefault(key, {"offset": 0, "last_cp": 0.0})
    cp = chain_path_for(sp)

    if first_time:
        try:
            size = sp.stat().st_size
        except OSError:
            size = None
        store.note_device("session_seen", session_file=str(sp), size=size)
        stat["seen"] += 1

    if key not in _reconciled:
        _reconciled.add(key)
        c = chain_cursor(cp) if cp.exists() else None
        if c is not None and c != rec["offset"]:
            if c > rec["offset"] or not _blank_between(sp, c, rec["offset"]):
                store.note_device("observation", what="cursor_restored_from_chain",
                                  session_file=str(sp), chain=cp.name,
                                  state_offset=rec["offset"], chain_offset=c)
                log(f"  ! restored the cursor from the chain: {sp.name} "
                    f"({rec['offset']} → {c})")
            rec["offset"] = c
            rec.pop("nl", None)

    off0 = rec["offset"]
    try:
        lines, new_off, shrunk = read_complete_lines(sp, rec["offset"])
    except OSError as e:
        store.note_device("sweep_error", session_file=str(sp),
                          error=type(e).__name__, errno=getattr(e, "errno", None))
        stat["errors"] += 1
        log(f"  ! could not read: {sp.name} ({type(e).__name__})")
        return

    reset = None
    if shrunk:
        stat["shrunk"] += 1
        old = rec["offset"]
        try:
            now = sp.stat().st_size
            to = restart_point(sp, now) if now < old else None
        except OSError:
            now = to = None
        store.note_device("observation", what="file_shrank",
                          session_file=str(sp),
                          bound_to=old, observed_size=now, cursor_to=to)
        log(f"  ! file shrank: {sp.name} ({old} → {now})"
            + (f" · moving the cursor to {to}" if to is not None else ""))
        if to is not None:
            reset = {"kind": "cursor_reset", "session_file": str(sp),
                     "reason": "file_shrank", "from": old, "to": to,
                     "observed_size": now}
            new_off = to

    need_cp = False
    if checkpoint:
        age = time.time() - rec["last_cp"]
        if age >= CHECKPOINT_SEC:
            try:
                s0 = sp.stat()
                same = (rec.get("cp_size") == s0.st_size and rec.get("cp_mtime") == s0.st_mtime)
            except OSError:
                same = False
            need_cp = (not same) or age >= HEARTBEAT_SEC
    if not lines and not need_cp and not hints and reset is None:
        return

    try:
        ch = load_or_create(cp, sp)
    except LedgerBroken:
        raise
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        what = "chain_behind_key" if isinstance(e, RuntimeError) else "chain_key_unreadable"
        store.note_device("observation", what=what,
                          session_file=str(sp), chain=cp.name,
                          error=str(e) if isinstance(e, (RuntimeError, OSError, ValueError))
                          else f"{type(e).__name__}: {e}")
        stat["errors"] += 1
        log(f"  ! no more binding to this chain: {cp.name} ({what})")
        return
    stat["files"] += 1

    if reset is not None:
        ch.append(reset)

    for start, raw in lines:
        ch.append({
            "kind": "line",
            "session_file": str(sp),
            "start": start,
            "end": start + len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        stat["lines"] += 1

    for h in hints:
        if h.get("session_file") in (None, str(sp)):
            ch.append({
                "kind": "hook_report",
                "event": h.get("event"),
                "source": "hook",
                "trusted": False,
            })
            stat["hints"] += 1

    nl_new = None
    if rec.get("nl") is not None and reset is None and new_off >= off0:
        try:
            nl_new = rec["nl"] + (_nonblank_lines(_read_range(sp, off0, new_off))
                                  if new_off > off0 else 0)
        except OSError:
            nl_new = None

    if need_cp:
        try:
            st_now = sp.stat()
            if nl_new is None:
                data = _read_range(sp, 0, st_now.st_size)
                nl_new = _nonblank_lines(data[:new_off])
                frag = data[new_off:]
            else:
                frag = _read_range(sp, new_off, st_now.st_size)
            nlines = nl_new + (1 if frag.strip() else 0)
        except OSError as e:
            store.note_device("sweep_error", session_file=str(sp), stage="checkpoint",
                              error=type(e).__name__, errno=getattr(e, "errno", None))
            stat["errors"] += 1
            st_now = None
        if st_now is not None:
            ch.append({
                "kind": "checkpoint",
                "session_file": str(sp),
                "size": st_now.st_size,
                "lines": nlines,
                "mtime": st_now.st_mtime,
            })
            rec["last_cp"] = time.time()
            rec["cp_size"], rec["cp_mtime"] = st_now.st_size, st_now.st_mtime
            stat["checkpoints"] += 1

    try:
        store.persist(ch, cp)
    except OSError as e:
        store.note_device("sweep_error", session_file=str(sp), stage="persist",
                          error=type(e).__name__, errno=getattr(e, "errno", None))
        stat["errors"] += 1
        log(f"  ! could not save the chain: {cp.name} ({type(e).__name__})")
        return
    rec["offset"] = new_off
    if nl_new is not None:
        rec["nl"] = nl_new
    else:
        rec.pop("nl", None)
    _save_state_paced(st, log)


def ledger_broken_exit(exc: Exception, started: bool | None, mode: str) -> int:
    print(f"Cannot write the device ledger, stopping the service: {exc}", file=sys.stderr)
    print(f"  ledger: {store.DEVICE}", file=sys.stderr)
    print("  The ledger is where observations go, so binding does not continue while it is broken.",
          file=sys.stderr)
    if started:
        try:
            store.note_device("service_stop", mode=mode, reason="exception:LedgerBroken")
        except LedgerBroken:
            print("  service_stop could not be recorded either -- the ledger keeps a start without a stop",
                  file=sys.stderr)
    return 3


def run_once(pats: list[str]) -> int:
    st = store.load_state()
    print(f"sweep patterns {len(pats)} · target files {len(targets(pats))}")
    try:
        store.note_device("service_start", mode="once", pid=os.getpid(),
                          checkpoint_sec=CHECKPOINT_SEC, heartbeat_sec=HEARTBEAT_SEC,
                          revision=core.REVISION, read=READ_MODE)
    except LedgerBroken as exc:
        return ledger_broken_exit(exc, started=False, mode="once")
    try:
        s = sweep(pats, st, checkpoint=True)
    except LedgerBroken as exc:
        return ledger_broken_exit(exc, started=True, mode="once")
    store.note_device("service_stop", mode="once", reason="completed")
    print(f"files {s['files']} · lines {s['lines']} · checkpoints {s['checkpoints']}"
          f" · hook reports {s['hints']} · shrinks detected {s['shrunk']}"
          f" · errors {s['errors']} · new sessions {s['seen']}")
    return 0


def _wait_or_stop(sec: float, stopfile: pathlib.Path | None) -> bool:
    end = time.time() + sec
    while time.time() < end:
        if stopfile and stopfile.exists():
            return True
        time.sleep(min(0.5, max(0.0, end - time.time())))
    return bool(stopfile and stopfile.exists())


def watch(pats: list[str], interval: float, stopfile: pathlib.Path | None,
          restart_on_error: int) -> int:
    st = store.load_state()
    print(f"binding service started · sweep interval {interval}s · "
          f"checkpoint period {CHECKPOINT_SEC}s · service folder {store.STORE}")
    print("sweep patterns: " + " ".join(pats[:4])
          + (f" and {len(pats) - 4} more" if len(pats) > 4 else ""))
    if stopfile:
        stopfile.unlink(missing_ok=True)
        print(f"normal stop: create {stopfile}")
    else:
        print("Ctrl+C stops")
    start_fields = {"mode": "watch", "pid": os.getpid(), "interval": interval,
                    "checkpoint_sec": CHECKPOINT_SEC, "heartbeat_sec": HEARTBEAT_SEC,
                    "revision": core.REVISION,
                    "read": READ_MODE}
    try:
        store.note_device("service_start", **start_fields)
    except LedgerBroken as exc:
        return ledger_broken_exit(exc, started=False, mode="watch")
    restarts = 0
    while True:
        reason = "unknown"
        broken = None
        failure = None
        try:
            while True:
                s = sweep(pats, st, checkpoint=True, log=print,
                          should_stop=(stopfile.exists if stopfile else None))
                restarts = 0
                if any(s[k] for k in ("lines", "checkpoints", "hints",
                                      "shrunk", "errors", "seen")):
                    print(f"  lines {s['lines']} · checkpoints {s['checkpoints']} · "
                          f"hook reports {s['hints']} · shrinks {s['shrunk']} · "
                          f"errors {s['errors']}")
                if stopfile and stopfile.exists():
                    reason = "stopfile"
                    print("\nnormal stop (stop file)")
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            reason = "interrupt"
            print("\nstopped")
        except LedgerBroken as exc:
            reason = "exception:LedgerBroken"
            broken = failure = exc
        except Exception as exc:
            reason = f"exception:{type(exc).__name__}"
            failure = exc
        finally:
            stop_fields = {"mode": "watch", "reason": reason}
            if failure is not None and restarts < restart_on_error:
                stop_fields["detail"] = str(failure)[:200]
            try:
                store.note_device("service_stop", **stop_fields)
            except LedgerBroken as exc2:
                print(f"could not record service_stop in the ledger: {exc2}", file=sys.stderr)
        if failure is None:
            return 0
        if restarts >= restart_on_error:
            if broken is not None:
                return ledger_broken_exit(broken, started=None, mode="watch")
            raise failure

        while True:
            restarts += 1
            wait = min(60.0, 2.0 ** restarts)
            print(f"\nthe sweep ended with an exception ({reason}) -- restarting in {wait:.0f} s "
                  f"(consecutive restart {restarts}/{restart_on_error})", file=sys.stderr)
            try:
                if _wait_or_stop(wait, stopfile):
                    print("\nnormal stop (stop file while waiting to restart)")
                    return 0
            except KeyboardInterrupt:
                return 0
            st = store.load_state()
            _reconciled.clear()
            store.forget_ledger()
            try:
                store.note_device("service_start", **start_fields, restart=restarts, after=reason)
                break
            except LedgerBroken as exc:
                print(f"could not restart: {exc}", file=sys.stderr)
                if restarts >= restart_on_error:
                    return ledger_broken_exit(exc, started=False, mode="watch")
