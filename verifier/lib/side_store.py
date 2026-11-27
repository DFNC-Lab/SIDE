# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE service folder: paths, durable writes, cursor state, stage keys, enrollment and ledger.

    chains/_device.chain.json   device ledger           keys/<chain>.key   current stage key
    chains/<name>.chain.json    one chain per log        state.json        cursor cache (unprotected)
    enroll.json                 enrollment certificate   seal_pub.hex      seal public key copy

The device never stores K0.  A chain is saved before its key, so a crash leaves the key behind the
chain, where it can be evolved forward.  Call use(path) before any other function.
"""
from __future__ import annotations

import ctypes
import json
import os
import pathlib
import subprocess
import sys
import time

import side_core as core
import side_util as util

STORE: pathlib.Path
CHAINS: pathlib.Path
DEVICE: pathlib.Path
HINTS: pathlib.Path
STATE: pathlib.Path
ROOTKEY: pathlib.Path
KEYS: pathlib.Path
SEAL_SECRET: pathlib.Path
SEAL_PUBLIC: pathlib.Path
ENROLL: pathlib.Path

DEFAULT_STORE = pathlib.Path(__file__).resolve().parent / core.STORE_DIR_NAME


def use(path) -> None:
    global STORE, CHAINS, DEVICE, HINTS, STATE, ROOTKEY, KEYS
    global SEAL_SECRET, SEAL_PUBLIC, ENROLL
    STORE = pathlib.Path(path)
    CHAINS = STORE / core.CHAINS_DIR
    DEVICE = CHAINS / core.LEDGER_NAME
    HINTS = STORE / "hints"
    STATE = STORE / core.STATE_NAME
    ROOTKEY = STORE / "root.key"
    KEYS = STORE / "keys"
    SEAL_SECRET = STORE / "seal_sign.key"
    SEAL_PUBLIC = STORE / core.SEAL_PUB_NAME
    ENROLL = STORE / core.ENROLL_NAME
    forget_ledger()


class LedgerBroken(Exception):
    pass


class SealedChain(RuntimeError):
    pass


def write_durable(tmp: pathlib.Path, text: str | None = None, data: bytes | None = None) -> None:
    if data is not None:
        fh = open(tmp, "wb")
    else:
        fh = open(tmp, "w", encoding="utf-8")
    try:
        fh.write(data if data is not None else text)
        fh.flush()
        os.fsync(fh.fileno())
    finally:
        fh.close()


def replace_durable(path: pathlib.Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    write_durable(tmp, text)
    os.replace(tmp, path)


state_problem: str | None = None


def load_state() -> dict:
    global state_problem
    if not STATE.exists():
        return {"files": {}}
    try:
        st = json.loads(STATE.read_text(encoding="utf-8"))
        if not isinstance(st, dict) or not isinstance(st.get("files"), dict):
            raise ValueError("not the shape of state.json")
    except (ValueError, OSError) as e:
        state_problem = f"{type(e).__name__}: {str(e)[:80]}"
        try:
            os.replace(STATE, STATE.with_name(
                f"state.unreadable.{int(time.time())}.json"))
        except OSError as e2:
            state_problem += f" (could not move it aside: {type(e2).__name__})"
        return {"files": {}}
    for k, rec in list(st["files"].items()):
        ok = (isinstance(rec, dict) and isinstance(rec.get("offset"), int)
              and rec["offset"] >= 0
              and isinstance(rec.get("last_cp", 0.0), (int, float)))
        if not ok:
            st["files"][k] = {"offset": 0, "last_cp": 0.0}
            state_problem = state_problem or f"malformed entry: {os.path.basename(k)}"
    return st


def save_state(st: dict) -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    write_durable(tmp, json.dumps(st, ensure_ascii=False, indent=2))
    os.replace(tmp, STATE)


def key_path(cp: pathlib.Path) -> pathlib.Path:
    return KEYS / (cp.name + ".key")


def lock_keys_dir() -> None:
    if os.name != "nt":
        os.chmod(KEYS, 0o700)
        return
    try:
        sid = subprocess.run([util.WHOAMI, "/user", "/fo", "csv", "/nh"], capture_output=True,
                             text=True).stdout.strip().split(",")[-1].strip('"')
    except OSError:
        sid = ""
    r = util.lock_folder(KEYS, *([sid] if sid.startswith("S-1-") else []))
    if r.returncode != 0:
        raise RuntimeError(f"could not lock the access control of keys/: {r.stderr or r.stdout}")


def _write_key_file(cp: pathlib.Path, body: dict) -> None:
    if not KEYS.exists():
        KEYS.mkdir(parents=True)
        lock_keys_dir()
    kp = key_path(cp)
    tmp = kp.with_suffix(".tmp")
    write_durable(tmp, json.dumps(body))
    os.replace(tmp, kp)


def save_key(cp: pathlib.Path, ch: core.Chain) -> None:
    _write_key_file(cp, {"seq": len(ch.entries), "key": ch._key.hex()})


def save_pending_start_key(cp: pathlib.Path, start: bytes, open_seq: int) -> None:
    _write_key_file(cp, {"seq": 0, "key": start.hex(), "open_seq": open_seq})


def pending_start_key(cp: pathlib.Path, dev: core.Chain) -> bytes | None:
    kp = key_path(cp)
    if not kp.exists():
        return None
    try:
        d = json.loads(kp.read_text(encoding="utf-8"))
        j = d.get("open_seq")
        if d.get("seq") != 0 or not isinstance(j, int) or not 0 <= j < len(dev.entries):
            return None
        r = dev.entries[j].record
        if r.get("kind") != "session_open" or r.get("chain") != cp.name:
            return None
        return bytes.fromhex(d["key"])
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        return None


def load_key(cp: pathlib.Path, n_entries: int) -> bytes:
    d = json.loads(key_path(cp).read_text(encoding="utf-8"))
    k, seq = bytes.fromhex(d["key"]), d["seq"]
    if seq > n_entries:
        raise RuntimeError(f"{cp.name}: key is ahead of the chain ({seq} > {n_entries}) "
                           "-- a past key cannot be recovered")
    while seq < n_entries:
        nk = core.evolve(k)
        wipe_key(k)
        k = nk
        seq += 1
    return k


wipe_keys = False


def enable_key_wiping() -> None:
    global wipe_keys
    wipe_keys = True


def wipe_key(b) -> None:
    if not wipe_keys or type(b) is not bytes or len(b) != 32:
        return
    if sys.implementation.name != "cpython":
        return
    try:
        off = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + off, 0, len(b))
    except Exception:
        pass


def _wiping_append(ch: core.Chain):
    orig = ch.append

    def append(body, *a, **k):
        old = ch._key
        e = orig(body, *a, **k)
        if ch._key is not old:
            wipe_key(old)
        return e
    return append


def load_enroll() -> dict | None:
    if ENROLL.exists():
        return json.loads(ENROLL.read_text(encoding="utf-8"))
    return None


def seal_public_hex() -> str | None:
    f = find_seal_pub(STORE)
    if f is not None:
        return read_seal_public_key(f)
    v = (load_enroll() or {}).get("seal_public_key")
    return core.parse_seal_public_key(v) if v else None


def find_seal_pub(folder) -> pathlib.Path | None:
    return next((f for f in (pathlib.Path(folder) / n for n in core.SEAL_PUB_NAMES) if f.exists()), None)


def key_text(source) -> str:
    p = pathlib.Path(source)
    text = p.read_text(encoding="utf-8-sig") if p.is_file() else str(source)
    return text.strip().lstrip("﻿").strip()


def read_seal_public_key(source) -> str:
    return core.parse_seal_public_key(key_text(source))


def legacy_seal_secret_present() -> bool:
    return SEAL_SECRET.exists()


def open_chain(cp: pathlib.Path, source: str, genesis: dict,
               start_key: bytes | None = None) -> core.Chain:
    if cp.exists():
        d = json.loads(cp.read_text(encoding="utf-8"))
        entries = [core.Entry(seq=e["seq"], record=e["record"], tag=e["tag"])
                   for e in d.get("entries", [])]
        k = load_key(cp, len(entries))
        ch = core.Chain(case_id=core.CHAIN_CASE_ID, custodian=core.CHAIN_CUSTODIAN,
                        source=source, forward_secure=True, _root_key=k)
        ch.entries = entries
        ch.seal = d.get("seal")
        ch._key = k
        if ch.seal:
            def _sealed(*_a, **_k):
                raise SealedChain(f"{cp.name}: no appending to a sealed chain")
            ch.append = _sealed
        elif wipe_keys:
            ch.append = _wiping_append(ch)
        return ch
    if start_key is None:
        raise RuntimeError(f"{cp.name}: no start key to open a new chain")
    ch = core.Chain(case_id=core.CHAIN_CASE_ID, custodian=core.CHAIN_CUSTODIAN,
                    source=source, forward_secure=True, _root_key=start_key)
    if wipe_keys:
        ch.append = _wiping_append(ch)
    ch.append(genesis)
    return ch


def open_device(enroll_extra: dict | None = None,
                k0: bytes | None = None) -> core.Chain:
    if enroll_extra is None and k0 is None:
        ch = _ledger_cached()
        if ch is not None:
            return ch
    genesis = {
        "kind": "device_enroll",
        "device_id": os.environ.get("COMPUTERNAME", "unknown"),
        "installed_by": core.LEDGER_INSTALLED_BY,
    }
    if enroll_extra:
        genesis.update(enroll_extra)
    repaired = None
    try:
        ch = open_chain(DEVICE, core.LEDGER_SOURCE, genesis, k0)
    except ValueError:
        repaired = _repair_torn_ledger()
        if repaired is None:
            raise
        ch = open_chain(DEVICE, core.LEDGER_SOURCE, genesis, k0)
    if DEVICE.exists():
        _ledger_remember(ch)
    if repaired is not None:
        ch.append({"kind": "observation", "what": "ledger_tail_repaired", **repaired})
        persist(ch, DEVICE)
    return ch


_ledger: dict = {}
_LEDGER_TRAILER = "\n ],\n \"seal\": null\n}"


def forget_ledger() -> None:
    _ledger.clear()


def _nl(s: str) -> bytes:
    return s.replace("\n", os.linesep).encode("utf-8")


def _ledger_entry_text(e: core.Entry) -> str:
    return "\n  " + json.dumps(e.to_dict(), ensure_ascii=False, indent=1).replace("\n", "\n  ")


def _ledger_remember(ch: core.Chain) -> None:
    try:
        st = DEVICE.stat()
    except OSError:
        _ledger.clear()
        return
    try:
        ks = key_path(DEVICE).stat()
        kst = (ks.st_size, ks.st_mtime_ns)
    except OSError:
        kst = None
    _ledger.clear()
    _ledger.update(ch=ch, n=len(ch.entries), size=st.st_size, mtime=st.st_mtime_ns, kst=kst)


def _ledger_cached() -> core.Chain | None:
    ch = _ledger.get("ch")
    if ch is None or ch.seal is not None or len(ch.entries) != _ledger["n"]:
        return None
    try:
        st = DEVICE.stat()
        if (st.st_size, st.st_mtime_ns) != (_ledger["size"], _ledger["mtime"]):
            return None
        ks = key_path(DEVICE).stat()
        if _ledger.get("kst") is None or (ks.st_size, ks.st_mtime_ns) != _ledger["kst"]:
            return None
    except (OSError, ValueError, AttributeError):
        return None
    return ch


def _ledger_append(ch: core.Chain) -> bool:
    if _ledger.get("ch") is not ch or ch.seal is not None:
        return False
    n = _ledger["n"]
    if len(ch.entries) <= n:
        return False
    try:
        st = DEVICE.stat()
    except OSError:
        return False
    if (st.st_size, st.st_mtime_ns) != (_ledger["size"], _ledger["mtime"]):
        return False
    tail = _nl(_LEDGER_TRAILER)
    add = _nl("".join("," + _ledger_entry_text(e) for e in ch.entries[n:]) + _LEDGER_TRAILER)
    with DEVICE.open("r+b") as fh:
        fh.seek(st.st_size - len(tail))
        if fh.read(len(tail)) != tail:
            return False
        fh.seek(st.st_size - len(tail))
        fh.write(add)
        fh.flush()
        os.fsync(fh.fileno())
    return True


def _repair_torn_ledger() -> dict | None:
    try:
        raw = DEVICE.read_bytes()
    except OSError:
        return None
    end = _nl("\n  }")
    tail = _nl(_LEDGER_TRAILER)
    i = raw.rfind(end)
    for _ in range(4):
        if i == -1:
            return None
        cut = i + len(end)
        try:
            d = json.loads((raw[:cut] + tail).decode("utf-8"))
            if isinstance(d, dict) and isinstance(d.get("entries"), list) and d["entries"]:
                break
        except (ValueError, UnicodeDecodeError):
            pass
        i = raw.rfind(end, 0, i)
    else:
        return None
    saved = STORE / f"ledger.torn.{int(time.time())}.bin"
    saved.write_bytes(raw[cut:])
    tmp = DEVICE.with_suffix(".tmp")
    write_durable(tmp, data=raw[:cut] + tail)
    os.replace(tmp, DEVICE)
    return {"dropped_bytes": len(raw) - cut, "kept_entries": len(d["entries"]),
            "saved_as": saved.name}


def note_device(kind: str, **fields) -> None:
    try:
        ch = open_device()
        body = {"kind": kind}
        body.update(fields)
        ch.append(body)
        persist(ch, DEVICE)
    except LedgerBroken:
        raise
    except Exception as e:
        raise LedgerBroken(f"could not record {kind} in the ledger: "
                           f"{type(e).__name__}: {e}") from e


def persist(ch: core.Chain, cp: pathlib.Path) -> None:
    CHAINS.mkdir(parents=True, exist_ok=True)
    is_dev = cp == DEVICE
    try:
        if not (is_dev and _ledger_append(ch)):
            tmp = cp.with_suffix(".tmp")
            write_durable(tmp, json.dumps(ch.to_dict(), ensure_ascii=False, indent=1))
            os.replace(tmp, cp)
        save_key(cp, ch)
    except BaseException:
        if is_dev:
            _ledger.clear()
        raise
    if is_dev:
        _ledger_remember(ch)
