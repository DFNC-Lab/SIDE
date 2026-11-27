# SPDX-FileCopyrightText: 2026 Soojin Kang, Donghwoo Cho, Jongsung Kim (DF&C Lab., Department of Cyber Security, Kookmin University, Republic of Korea)
# SPDX-License-Identifier: Apache-2.0
"""SIDE core: canonical JSON, the forward-secure HMAC chain, Merkle proofs and the Ed25519 seal.

    T_i = HMAC(K_i, JCS(R_i) || "|" || T_{i-1}),    K_{i+1} = HMAC(K_i, EVOLVE_LABEL)

The writer overwrites K_i after use, so a later key holder cannot forge earlier tags.  A seal closes
a chain with its record count, Merkle root and final tag; the organization signs the seal body.
Labels, prefixes and file names here are part of the wire format: changing one breaks existing chains.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SPEC_VERSION = "coc-hmac-sha256/2.7"
EVOLVE_LABEL = b"coc-evolve-v1"
CHAIN_KEY_LABEL = b"coc-chain-v1|"
GENESIS_LABEL = b"COC-GENESIS|"
KEY_COMMIT_LABEL = b"COC-KEY-COMMIT-v1|"
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
SEAL_SIG_SPEC = "coc-seal-sig/1"
SEAL_SIG_ALG = "ed25519"
SEAL_SIG_CONTEXT = b"COC-SEAL-SIG-v1|"
CHAIN_CASE_ID = "CUSTODYD-PROTOTYPE"
CHAIN_CUSTODIAN = "custodyd"
LEDGER_SOURCE = "device ledger"
LEDGER_INSTALLED_BY = "custodyd-prototype"
REVISION = "custodyd-20261123-fix13"
ENROLL_KEY_SCHEME = ("K0 held by the organization, the device keeps only the current stage "
                     "key of each chain (coc-evolve-v1, coc-chain-v1)")

STORE_DIR_NAME = ".side_store"
CHAINS_DIR = "chains"
SESSIONS_DIR = "sessions"
LEDGER_NAME = "_device.chain.json"
STATE_NAME = "state.json"
ENROLL_NAME = "enroll.json"
K0_NAME = "k0.hex"
SEAL_SECRET_NAME = "seal_secret.hex"
SEAL_PUB_NAME = "seal_pub.hex"
SEAL_PUB_NAMES = (SEAL_PUB_NAME, "seal_pub.key")


def nfc(obj: Any) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {nfc(k): nfc(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [nfc(v) for v in obj]
    return obj


def jcs(obj: Any) -> bytes:
    return json.dumps(
        nfc(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def evolve(key: bytes) -> bytes:
    return hmac.new(key, EVOLVE_LABEL, hashlib.sha256).digest()


def derive_key(root_key: bytes, seq: int, forward_secure: bool = True) -> bytes:
    if not forward_secure:
        return root_key
    k = root_key
    for _ in range(seq):
        k = evolve(k)
    return k


KEY_SCHEDULE_MEMO_LIMIT = 1 << 20


class KeySchedule:
    def __init__(self, root_key: bytes, forward_secure: bool = True) -> None:
        self.root_key = root_key
        self.forward_secure = forward_secure
        self._keys: list[bytes] = [root_key]

    def at(self, index: int) -> bytes:
        if not self.forward_secure:
            return self.root_key
        if index <= 0:
            return self.root_key
        if index > KEY_SCHEDULE_MEMO_LIMIT:
            return derive_key(self.root_key, index, True)
        while len(self._keys) <= index:
            self._keys.append(evolve(self._keys[-1]))
        return self._keys[index]


def compute_tag(key: bytes, record: dict, prev_tag: str) -> str:
    return hmac.new(
        key, jcs(record) + b"|" + prev_tag.encode("ascii"), hashlib.sha256
    ).hexdigest()


def chain_start_key(ledger_key: bytes, session_id: str) -> bytes:
    return hmac.new(ledger_key, CHAIN_KEY_LABEL + session_id.encode("utf-8"),
                    hashlib.sha256).digest()


def key_commitment(k0: bytes) -> str:
    return sha256_hex(KEY_COMMIT_LABEL + k0)


_ED_P = 2 ** 255 - 19
_ED_Q = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_sha512_int(b: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _ed_add(P: tuple, Q: tuple) -> tuple:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _ED_P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _ED_P
    C = 2 * P[3] * Q[3] * _ED_D % _ED_P
    D = 2 * P[2] * Q[2] % _ED_P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _ED_P, G * H % _ED_P, F * G % _ED_P, E * H % _ED_P)


def _ed_mul(s: int, P: tuple) -> tuple:
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_GX = _ed_recover_x(_ED_GY, 0)
_ED_G = (_ED_GX, _ED_GY, 1, _ED_GX * _ED_GY % _ED_P)


def _ed_equal(P: tuple, Q: tuple) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _ED_P != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _ED_P == 0


def _ed_compress(P: tuple) -> bytes:
    zinv = pow(P[2], _ED_P - 2, _ED_P)
    x = P[0] * zinv % _ED_P
    y = P[1] * zinv % _ED_P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ed_decompress(s: bytes) -> tuple | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


def _ed_expand(secret: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("An Ed25519 secret key must be 32 bytes.")
    a, _ = _ed_expand(secret)
    return _ed_compress(_ed_mul(a, _ED_G))


def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("An Ed25519 secret key must be 32 bytes.")
    a, prefix = _ed_expand(secret)
    A = _ed_compress(_ed_mul(a, _ED_G))
    r = _ed_sha512_int(prefix + msg) % _ED_Q
    Rs = _ed_compress(_ed_mul(r, _ED_G))
    h = _ed_sha512_int(Rs + A + msg) % _ED_Q
    return Rs + int.to_bytes((r + h * a) % _ED_Q, 32, "little")


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _ed_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _ed_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_Q:
        return False
    h = _ed_sha512_int(Rs + public + msg) % _ED_Q
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(R, _ed_mul(h, A)))


def seal_signing_input(body: dict) -> bytes:
    return SEAL_SIG_CONTEXT + jcs(body)


def generate_seal_keypair() -> tuple[str, str]:
    sk = secrets.token_bytes(32)
    return sk.hex(), ed25519_public_key(sk).hex()


def seal_public_key_of(secret_key_hex: str) -> str:
    return ed25519_public_key(bytes.fromhex(secret_key_hex)).hex()


def parse_seal_public_key(text: str) -> str:
    s = text.strip().lstrip("﻿").strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("the seal public key must be 64 hex digits (32 bytes)")
    return s


def sign_seal_body(secret_key_hex: str, body: dict, key_id: str = "") -> dict:
    sk = bytes.fromhex(secret_key_hex)
    return {
        "sig_spec": SEAL_SIG_SPEC,
        "alg": SEAL_SIG_ALG,
        "key_id": key_id,
        "public_key": ed25519_public_key(sk).hex(),
        "value": ed25519_sign(sk, seal_signing_input(body)).hex(),
    }


def verify_seal_signature(seal: dict | None,
                          expected_public_key: str | None) -> dict:
    sig = (seal or {}).get("sig")
    if not sig:
        return {"status": "no signature", "ok": None, "reason": ""}
    if not expected_public_key:
        return {"status": "unverified (no public key)", "ok": None,
                "reason": "the verifier did not present the organization's public key"}
    if sig.get("alg") != SEAL_SIG_ALG:
        return {"status": "mismatch", "ok": False,
                "reason": f"unknown signature algorithm: {sig.get('alg')}"}
    embedded = sig.get("public_key")
    if embedded and embedded != expected_public_key:
        return {"status": "mismatch", "ok": False,
                "reason": "the public key in the seal differs from the one the verifier presented"}
    try:
        ok = ed25519_verify(bytes.fromhex(expected_public_key),
                            seal_signing_input(seal.get("body") or {}),
                            bytes.fromhex(sig.get("value") or ""))
    except (ValueError, TypeError) as exc:
        return {"status": "mismatch", "ok": False, "reason": f"malformed signature: {exc}"}
    if ok:
        return {"status": "valid", "ok": True, "reason": ""}
    return {"status": "mismatch", "ok": False, "reason": "signature verification failed"}


def leaf_hash(record: dict) -> str:
    return sha256_hex(LEAF_PREFIX + jcs(record))


def node_hash(left: str, right: str) -> str:
    return sha256_hex(NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


def merkle_levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return [[sha256_hex(b"")]]
    levels, cur = [leaves], leaves
    while len(cur) > 1:
        nxt = [
            node_hash(cur[i], cur[i + 1] if i + 1 < len(cur) else cur[i])
            for i in range(0, len(cur), 2)
        ]
        levels.append(nxt)
        cur = nxt
    return levels


def merkle_root(leaves: list[str]) -> str:
    return merkle_levels(leaves)[-1][0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    levels, proof, idx = merkle_levels(leaves), [], index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sib = level[idx + 1] if idx + 1 < len(level) else level[idx]
            proof.append(("R", sib))
        else:
            proof.append(("L", level[idx - 1]))
        idx //= 2
    return proof


def verify_merkle_proof(record: dict, proof: list[tuple[str, str]], root: str) -> bool:
    h = leaf_hash(record)
    for side, sib in proof:
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == root


@dataclass
class Entry:
    seq: int
    record: dict
    tag: str

    def to_dict(self) -> dict:
        return {"seq": self.seq, "record": self.record, "tag": self.tag}


@dataclass
class Chain:
    case_id: str
    custodian: str
    source: str
    forward_secure: bool = True
    entries: list[Entry] = field(default_factory=list)
    seal: dict | None = None
    _key: bytes = field(default=b"", repr=False)
    _root_key: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if not self._root_key:
            self._root_key = secrets.token_bytes(32)
        self._key = self._root_key

    @property
    def genesis_tag(self) -> str:
        meta = {"spec": SPEC_VERSION, "case_id": self.case_id,
                "custodian": self.custodian, "source": self.source}
        return sha256_hex(GENESIS_LABEL + jcs(meta))

    def append(self, body: dict) -> Entry:
        seq = len(self.entries)
        prev_tag = self.entries[-1].tag if self.entries else self.genesis_tag
        record: dict[str, Any] = {"seq": seq}
        record["ts_recorded"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        record["custodian"] = self.custodian
        record["prev_tag"] = prev_tag
        record.update(body)

        tag = compute_tag(self._key, record, prev_tag)
        if self.forward_secure:
            self._key = evolve(self._key)
        e = Entry(seq=seq, record=record, tag=tag)
        self.entries.append(e)
        return e

    def close(self, anchor_authority: str = "none") -> dict:
        leaves = [leaf_hash(e.record) for e in self.entries]
        body = {
            "spec": SPEC_VERSION, "case_id": self.case_id,
            "entry_count": len(self.entries),
            "merkle_root": merkle_root(leaves),
            "final_tag": self.entries[-1].tag if self.entries else self.genesis_tag,
            "sealed_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "anchor_authority": anchor_authority,
        }
        self.seal = {"body": body,
                     "tag": compute_tag(self._key, body, body["final_tag"])}
        return self.seal

    def to_dict(self) -> dict:
        return {
            "spec": SPEC_VERSION, "case_id": self.case_id,
            "custodian": self.custodian, "source": self.source,
            "forward_secure": self.forward_secure,
            "genesis_tag": self.genesis_tag,
            "entries": [e.to_dict() for e in self.entries],
            "seal": self.seal,
        }


def build_disclosure_package(chain_dict: dict, seqs: list[int]) -> dict:
    entries = chain_dict["entries"]
    leaves = [leaf_hash(e["record"]) for e in entries]
    root = merkle_root(leaves)
    by_seq = {e["record"].get("seq"): i for i, e in enumerate(entries)}

    items = []
    for s in sorted(set(seqs)):
        idx = by_seq.get(s)
        if idx is None:
            continue
        items.append({
            "seq": s,
            "record": entries[idx]["record"],
            "tag": entries[idx]["tag"],
            "proof": merkle_proof(leaves, idx),
        })
    return {
        "spec": SPEC_VERSION,
        "type": "selective_disclosure",
        "case_id": chain_dict.get("case_id"),
        "genesis_tag": chain_dict.get("genesis_tag"),
        "merkle_root": root,
        "seal": chain_dict.get("seal"),
        "total_entries": len(entries),
        "disclosed_count": len(items),
        "items": items,
        "issued_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "NOTE": "The Merkle inclusion proof of each item verifies its membership in the source chain. "
                "Undisclosed messages take part only as hashes, so their content stays hidden.",
    }


def verify_disclosure_package(pkg: dict,
                              seal_public_key: str | None = None,
                              require_signature: bool = False) -> dict:
    root = pkg.get("merkle_root")
    results = []
    for it in pkg.get("items", []):
        proof = [(d, h) for d, h in it["proof"]]
        results.append({
            "seq": it["seq"],
            "ok": verify_merkle_proof(it["record"], proof, root),
            "proof_len": len(proof),
        })
    seal_ok = count_ok = None
    seal = pkg.get("seal")
    if seal:
        body = seal.get("body") or {}
        seal_ok = body.get("merkle_root") == root
        if "entry_count" in body:
            count_ok = body["entry_count"] == pkg.get("total_entries")
    sig = verify_seal_signature(seal, seal_public_key)
    if require_signature and sig["status"] == "no signature":
        sig = {"status": "no signature (required)", "ok": False,
               "reason": "the verifier required a seal signature but the package has none"}
    return {"all_ok": (all(r["ok"] for r in results)
                       and seal_ok is not False
                       and count_ok is not False
                       and sig["ok"] is not False),
            "seal_sig_required": require_signature,
            "items": results,
            "seal_root_match": seal_ok,
            "entry_count_match": count_ok,
            "seal_tag_checked": False,
            "seal_sig_status": sig["status"],
            "seal_sig_ok": sig["ok"],
            "seal_sig_reason": sig["reason"]}
