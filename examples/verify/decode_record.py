#!/usr/bin/env python3
"""Independent, second-language reference decoder for an Elara record.

Decodes ``sample-record.wire`` from the binary wire format (PROTOCOL-SPEC §4.3),
reconstructs the signature preimage (§4.4 ``signable_bytes``), and recomputes the
record's content address ``record_hash = SHA3-256(signable_bytes)`` — using ONLY
the Python standard library (``hashlib``, ``struct``, ``json``). No Elara code, no
Rust, no node, no network.

This is the worked "implement Elara in any language" reference for the record
layer. The hash *primitives* are pinned by ``verify_conformance.py``; this script
proves the harder thing — that the documented **wire decode + canonicalization**
are reproducible from scratch and yield the same ``record_hash`` the reference
implementation published in ``conformance-vectors.json`` (the ``record-hash``
vector). If the byte layout in §4.3/§4.4 were wrong or incompletely specified,
this would not reproduce; that it does is the proof the spec is implementable.

Run:   python3 examples/verify/decode_record.py
       python3 examples/verify/decode_record.py path/to/record.wire
Exit:  0 = decoded and record_hash matched the published vector
       1 = a mismatch (the decode or the spec drifted — never a fake green)
       2 = could not read / parse inputs

Scope note (honest): this decodes exactly the fields that enter ``signable_bytes``
(§4.4) plus enough of the frame to locate them, and the primary ML-DSA signature
that follows them (surfaced as ``rec["signature"]`` for ``verify_pq.py`` — it is
not itself signed, so it never affects ``record_hash``); it is NOT a full record
parser (it does not decode the secondary SLH-DSA signature, itc_stamp, zone refs,
etc. — none of which are signed). For a v5 record the slot ``nonce`` is the final
field appended by ``to_bytes`` (§4.3), so it is read from the wire tail; a full
streaming decoder would reach it in sequence at the end of the v5 extension. This
script itself stays pure-stdlib (no signature math); the anchor/creator signature
over ``signable_bytes`` is checked independently by ``verify_pq.py`` (liboqs
ML-DSA-65) and by the Rust ``elara-verify`` binary (see README).
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_WIRE = HERE / "sample-record.wire"
VECTORS = HERE / "conformance-vectors.json"

MAGIC = b"ELRA"  # §4.3 frame magic

# Binary-metadata type tags (§4.3, src/wire.rs) — v4+ records carry typed TLV
# metadata on the wire; §4.4 re-serializes it to compact JSON for signing.
META_NULL, META_BOOL, META_INT, META_FLOAT, META_STRING, META_ARRAY, META_OBJECT = range(7)
MAX_METADATA_ENTRIES = 256
MAX_METADATA_DEPTH = 8

# Classification (§4) u8 → name, for the human-readable dump only.
CLASSIFICATION = {0: "Public", 1: "Restricted", 2: "Confidential", 3: "Secret"}


def sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


class Reader:
    """Cursor over the wire bytes — mirrors src/wire.rs WireReader (all BE)."""

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ValueError(f"short read: need {n} at offset {self.i}, have {len(self.d) - self.i}")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def f64(self) -> float:
        # timestamp / META_FLOAT: f64 BE — Rust to_be_bytes == Python struct ">d".
        return struct.unpack(">d", self.take(8))[0]

    def u8_prefixed(self) -> bytes:
        return self.take(self.u8())

    def u16_prefixed(self) -> bytes:
        return self.take(self.u16())

    def optional_u32(self):
        # zk_proof: u32 length, 0 == absent (src/wire.rs read_optional_u32).
        n = self.u32()
        return self.take(n) if n else None


def decode_value(r: Reader, depth: int = 0):
    """Decode one TLV metadata value into its JSON-equivalent Python object."""
    if depth > MAX_METADATA_DEPTH:
        raise ValueError(f"metadata nesting depth {depth} exceeds {MAX_METADATA_DEPTH}")
    tag = r.u8()
    if tag == META_NULL:
        return None
    if tag == META_BOOL:
        return r.u8() != 0
    if tag == META_INT:
        return struct.unpack(">q", r.take(8))[0]  # i64 BE
    if tag == META_FLOAT:
        f = r.f64()
        if f != f or f in (float("inf"), float("-inf")):
            raise ValueError("metadata float is non-finite")
        return f
    if tag == META_STRING:
        return r.u16_prefixed().decode("utf-8")
    if tag == META_ARRAY:
        n = r.u16()
        if n > MAX_METADATA_ENTRIES:
            raise ValueError(f"metadata array too large: {n}")
        return [decode_value(r, depth + 1) for _ in range(n)]
    if tag == META_OBJECT:
        n = r.u16()
        if n > MAX_METADATA_ENTRIES:
            raise ValueError(f"metadata object too large: {n}")
        obj = {}
        for _ in range(n):
            k = r.u8_prefixed().decode("utf-8")
            obj[k] = decode_value(r, depth + 1)
        return obj
    raise ValueError(f"unknown metadata tag {tag}")


def decode_metadata(r: Reader) -> dict:
    n = r.u16()
    if n > MAX_METADATA_ENTRIES:
        raise ValueError(f"too many metadata entries: {n}")
    meta = {}
    for _ in range(n):
        k = r.u8_prefixed().decode("utf-8")
        meta[k] = decode_value(r)
    return meta


def decode_record(wire: bytes) -> dict:
    """Decode the §4.4-relevant fields of a record from its §4.3 wire bytes."""
    r = Reader(wire)
    # Header: ELRA + version(u16) + rec_type(u8) + reserved(u8) = 8 bytes.
    if r.take(4) != MAGIC:
        raise ValueError("bad magic — not an Elara record frame")
    version = r.u16()
    r.u8()  # rec_type (0x01)
    r.u8()  # reserved (0x00)

    rec_id = r.u8_prefixed().decode("utf-8")
    content_hash = r.take(32)
    creator_public_key = r.u16_prefixed()
    timestamp = r.f64()

    num_parents = r.u16()
    parents = [r.u8_prefixed().decode("utf-8") for _ in range(num_parents)]

    classification = r.u8()
    metadata = decode_metadata(r) if version >= 4 else _legacy_json_metadata(r)
    zk_proof = r.optional_u32()

    # Primary signature (optional_u16) — the field that follows zk_proof in the
    # §4.3 to_bytes order (src/record.rs). It is NOT part of signable_bytes, so it
    # never affects record_hash; we read it here only so a PQ verifier
    # (verify_pq.py) can check the creator/anchor signature over signable_bytes
    # without re-walking the frame. Bulletproofed: any short/absent tail leaves
    # signature=None and the record-hash self-check below is unaffected.
    try:
        siglen = r.u16()
        signature = r.take(siglen) if siglen else None
    except ValueError:
        signature = None

    # v5 slot nonce is the final field appended by to_bytes (§4.3) — read it from
    # the tail. (A full streaming decoder would reach it after the v2/v3 fields.)
    nonce = struct.unpack(">Q", wire[-8:])[0] if version >= 5 else 0

    return {
        "id": rec_id,
        "version": version,
        "nonce": nonce,
        "content_hash": content_hash,
        "creator_public_key": creator_public_key,
        "timestamp": timestamp,
        "parents": parents,
        "classification": classification,
        "metadata": metadata,
        "zk_proof": zk_proof,
        "signature": signature,
    }


def _legacy_json_metadata(r: Reader) -> dict:
    # v1–v3 path: u32 length + compact JSON (not exercised by the v5 sample).
    n = r.u32()
    raw = r.take(n)
    return json.loads(raw) if raw else {}


def signable_bytes(rec: dict) -> bytes:
    """Reconstruct the signature preimage per PROTOCOL-SPEC §4.4 (NORMATIVE)."""
    buf = bytearray()
    buf += rec["id"].encode("utf-8")                       # id (no length prefix)
    buf += struct.pack(">H", rec["version"])               # version u16 BE
    if rec["version"] >= 5:
        buf += struct.pack(">Q", rec["nonce"])             # nonce u64 BE (v5+)
    buf += rec["content_hash"]                             # 32 bytes
    buf += rec["creator_public_key"]                       # raw bytes
    buf += struct.pack(">d", rec["timestamp"])             # f64 BE
    parents = sorted(rec["parents"])                       # sorted for signing (§4.4 inv.2)
    buf += struct.pack(">H", len(parents))                 # num_parents u16 BE
    for pid in parents:
        buf += pid.encode("utf-8")                         # no per-parent prefix
    buf += struct.pack("B", rec["classification"])         # classification u8
    # metadata: ALWAYS compact sorted JSON (§4.4 inv.1), even when the wire form
    # is binary TLV. ensure_ascii=False to match Rust serde_json's UTF-8 output.
    meta_json = json.dumps(rec["metadata"], sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    buf += struct.pack(">I", len(meta_json)) + meta_json   # metadata_len u32 BE + json
    zk = rec["zk_proof"]
    if zk:
        buf += struct.pack(">I", len(zk)) + zk             # zk_proof_len u32 BE + bytes
    else:
        buf += struct.pack(">I", 0)                        # 0 if absent
    return bytes(buf)


def _vector(name: str):
    """Return the named vector from conformance-vectors.json, or None."""
    try:
        doc = json.loads(VECTORS.read_text())
    except (OSError, ValueError):
        return None
    return next((v for v in doc.get("vectors", []) if v.get("name") == name), None)


def main(argv: list) -> int:
    wire_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_WIRE
    try:
        wire = wire_path.read_bytes()
    except OSError as e:
        print(f"ERROR: cannot read {wire_path}: {e}", file=sys.stderr)
        return 2
    try:
        rec = decode_record(wire)
        sb = signable_bytes(rec)
    except (ValueError, KeyError, UnicodeDecodeError) as e:
        print(f"ERROR: decode failed: {e}", file=sys.stderr)
        return 2

    record_hash = sha3(sb)
    identity = sha3(rec["creator_public_key"])

    print("Elara record — independent Python decode (no Rust, no node)")
    print(f"  wire:           {wire_path.name} ({len(wire)} bytes)")
    print(f"  id:             {rec['id']}")
    print(f"  version:        {rec['version']}   nonce: {rec['nonce']}")
    print(f"  timestamp:      {rec['timestamp']}")
    print(f"  classification: {CLASSIFICATION.get(rec['classification'], rec['classification'])}")
    print(f"  parents:        {len(rec['parents'])}")
    print(f"  metadata:       {json.dumps(rec['metadata'], sort_keys=True, separators=(',', ':'), ensure_ascii=False)}")
    print(f"  content_hash:   {rec['content_hash'].hex()}")
    print(f"  creator pk:     {len(rec['creator_public_key'])} bytes")
    print(f"  signable_bytes: {len(sb)} bytes")
    print(f"  identity:       {identity}")
    print(f"  record_hash:    {record_hash}")

    # Self-check against the published vectors — the non-tautological proof.
    failed = 0
    rv = _vector("record-hash")
    if rv:
        if record_hash == rv["expected"]:
            print(f"\n  OK   record-hash matches the published vector")
        else:
            print(f"\n  FAIL record-hash {record_hash} != published {rv['expected']}")
            failed += 1
        want_wire = rv.get("input", {}).get("wire_sha3_256")
        if want_wire and sha3(wire) != want_wire:
            print(f"  FAIL wire sha3 {sha3(wire)} != published {want_wire}")
            failed += 1
        want_id = rv.get("input", {}).get("record_id")
        if want_id and rec["id"] != want_id:
            print(f"  FAIL record_id {rec['id']} != published {want_id}")
            failed += 1
    else:
        print("\n  (no record-hash vector found to check against — decoded only)")

    iv = _vector("identity-derivation")
    if iv and identity != iv["expected"]:
        print(f"  FAIL identity {identity} != published {iv['expected']}")
        failed += 1
    elif iv:
        print(f"  OK   identity-derivation matches the published vector")

    if failed:
        print("\nMISMATCH — the independent decode did not reproduce the published bytes.")
        return 1
    print("\nMATCH — wire decode + §4.4 canonicalization reproduce the record_hash in pure Python.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
