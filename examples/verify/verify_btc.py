#!/usr/bin/env python3
"""Independent Bitcoin existed-by verification for the Elara conformance set.

The trustless time bracket is the most distinctive claim in this directory — a
drand BLS not-before below, a **Bitcoin existed-by above**. Until now that upper
bound was reproducible only through the Rust ``elara-verify`` binary (legs 1-4 of
``verify.sh``). This leg closes that gap for the *upper* bound the way
``verify_pq.py`` (leg 0c) closed it for the PQ signatures: it re-derives the whole
existed-by chain in a **second, non-Rust toolchain** — the
``opentimestamps`` reference Python library (independent of Elara's hand-rolled
OTS walker in ``src/bin/elara_verify.rs``) plus stdlib SHA-256 — and proves the
seal was committed into a real Bitcoin block, trusting nobody.

What it checks (all offline — no node, no calendar server, no network syscall):

  1. ARTIFACT BINDING   ``SHA-256(epoch-41340-zone-0.json)`` equals the digest the
                        ``.ots`` proof commits to — so the proof is for *this*
                        anchor (which names seal ``826306…``), not some other file.
  2. OTS FOLD           the ``opentimestamps`` library walks the proof from that
                        digest through its sha256/append/prepend path to a
                        **Bitcoin block-header attestation** → (block height,
                        the committed merkle root).
  3. HEADER PIN         the archived 80-byte block header double-SHA-256s to the
                        block hash **pinned in this script** (the same pin the Rust
                        binary compiles in — never a hash read from the bundle).
                        THIS is what makes the bound trustless.
  4. ROOT BIND          the header's own merkle-root field (bytes 36..68) equals
                        the merkle root the OTS proof folded to — so the proof
                        genuinely lands in *that* pinned block.
  5. UPPER BOUND        the block's header timestamp is the existed-by upper bound.

Fail-closed throughout: a header that does not match the pin, an OTS root absent
from that header, or a proof for a different artifact all return exit 1 — never a
fake green. Skips transparently (exit 3) when ``opentimestamps`` is not installed,
exactly like the liboqs leg when ``oqs`` is absent; the Rust binary's legs 1-4
remain the reference in that case.

Run:   python3 examples/verify/verify_btc.py
Exit:  0 = the Bitcoin existed-by bound was independently reproduced
       1 = a mismatch (header not pinned, OTS root not in that block, or the proof
           is for a different artifact) — a forgery signal, never a fake green
       2 = could not read / parse inputs
       3 = SKIPPED (no ``opentimestamps`` library) — transparent; the Rust
           elara-verify legs 1-4 in verify.sh remain the reference
"""

import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Trustless pins — the SAME double-SHA-256 block hashes the Rust elara-verify binary
# compiles in (src/bin/elara_verify.rs :: PINNED_BTC_HEADER_HASHES). The existed-by
# bound is trustless ONLY because the archived header is authenticated against THIS
# pin, never against a hash read from the (operator-supplied) bundle. Display
# (big-endian) form, exactly as a Bitcoin explorer shows it; the stored block hash
# is the byte-reverse. Extend as new epochs anchor.
PINNED_BTC_BLOCK_HASHES = {
    # pre-re-genesis demo anchor (epoch 3217) — superseded here, timelessly valid
    953657: "00000000000000000000d2d19c330bfca44c19de152b6c1e7edc2a05271a9d44",
    # the bundled demo anchor (epoch 41340, zone 0)
    957487: "000000000000000000016be5b78cad8d66b755feea252ee460e22e42a6288319",
}

# The anchor artifact + its OpenTimestamps proof this leg checks — the
# examples/verify demo seal (epoch 41340, zone 0; the seal verify.sh legs 1-4 use).
ANCHOR_JSON = HERE / "epoch-41340-zone-0.json"
OTS_PROOF = HERE / "epoch-41340-zone-0.json.ots"


def _skip(msg: str) -> int:
    print("── Bitcoin existed-by — SKIPPED ──")
    print("  " + msg)
    print("  (the Rust elara-verify legs 1-4 in verify.sh remain the reference for")
    print("   the Bitcoin existed-by bound when the opentimestamps library is absent.)")
    return 3


def _load_ots():
    """Import the independent opentimestamps reference library, or explain why not."""
    try:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except Exception as e:  # ImportError or a load failure
        return None, "python-opentimestamps not importable ({})".format(e)
    return (DetachedTimestampFile, BitcoinBlockHeaderAttestation, StreamDeserializationContext), None


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _collect_bitcoin_attestations(timestamp, btc_cls):
    """Walk the timestamp tree (mirrors the manual walk in elara_verify.rs::ots_walk):
    at every node, ``timestamp.msg`` is the committed digest; a Bitcoin attestation
    pins that digest as a block's merkle root. Pending/calendar attestations are NOT
    a trustless bound and are ignored. Returns [(block_height, committed_root_bytes)]."""
    found = []
    for att in timestamp.attestations:
        if isinstance(att, btc_cls):
            found.append((att.height, bytes(timestamp.msg)))
    for _op, sub in timestamp.ops.items():
        found.extend(_collect_bitcoin_attestations(sub, btc_cls))
    return found


def _parse_header(height: int) -> bytes:
    """Read btc-header-<height>.txt and return its 80-byte header (the
    blockstream_header line, or mempool_header) — same source elara_verify.rs uses."""
    path = HERE / "btc-header-{}.txt".format(height)
    text = path.read_text()
    hdr_hex = None
    for line in text.splitlines():
        line = line.strip()
        for key in ("blockstream_header:", "mempool_header:"):
            if line.startswith(key):
                hdr_hex = line[len(key):].strip()
                break
        if hdr_hex:
            break
    if not hdr_hex:
        raise ValueError("no blockstream_header/mempool_header line in {}".format(path.name))
    raw = bytes.fromhex(hdr_hex)
    if len(raw) != 80:
        raise ValueError("{}: header is {} bytes, expected 80".format(path.name, len(raw)))
    return raw


def main() -> int:
    mods, why = _load_ots()
    if mods is None:
        return _skip(why)
    DetachedTimestampFile, BitcoinBlockHeaderAttestation, StreamDeserializationContext = mods

    print("Elara conformance — independent Bitcoin existed-by verification (opentimestamps)")
    print("  artifact: {}".format(ANCHOR_JSON.name))
    print("  proof:    {} via python-opentimestamps (independent of the Rust OTS walker)".format(OTS_PROOF.name))
    print()

    try:
        artifact = ANCHOR_JSON.read_bytes()
        anchor_obj = json.loads(artifact)
        with open(OTS_PROOF, "rb") as f:
            det = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    except (OSError, ValueError) as e:
        print("ERROR: cannot read artifact / proof: {}".format(e), file=sys.stderr)
        return 2

    seal_hash = anchor_obj.get("seal_hash", "?")

    # 1. ARTIFACT BINDING — the .ots proof is for THIS anchor file.
    file_sha = hashlib.sha256(artifact).digest()
    bind_ok = bytes(det.file_digest) == file_sha
    print("  {} artifact binding   SHA-256({}) {} the digest the .ots proof commits to".format(
        "OK  " if bind_ok else "FAIL", ANCHOR_JSON.name, "==" if bind_ok else "!="))
    if not bind_ok:
        print("       proof commits {}…, artifact hashes to {}…".format(
            det.file_digest.hex()[:16], file_sha.hex()[:16]))
        print("\nMISMATCH — the proof is for a different file. Never a fake green.")
        return 1

    # 2. OTS FOLD — independent library walks to the Bitcoin attestation(s).
    try:
        attestations = _collect_bitcoin_attestations(det.timestamp, BitcoinBlockHeaderAttestation)
    except Exception as e:  # defensive: malformed tree
        print("ERROR: walking the OTS tree failed: {}".format(e), file=sys.stderr)
        return 2
    if not attestations:
        print("  FAIL Bitcoin attestation  none in the proof — no trustless Bitcoin bound")
        print("       (only pending/calendar attestations: the proof is not yet Bitcoin-confirmed)")
        print("\nNo Bitcoin existed-by bound to reproduce. Never a fake green.")
        return 1

    # 3+4. For each Bitcoin attestation: authenticate the header against the pin and
    #      bind the OTS-committed root to the header's own merkle-root field.
    verified = []  # (height, block_unix_time, display_hash)
    for height, committed_root in attestations:
        pin = PINNED_BTC_BLOCK_HASHES.get(height)
        if pin is None:
            print("  ⚠   reference-only       block {} is not pinned in this verifier — "
                  "cannot authenticate offline (skipped, not trusted)".format(height))
            continue
        try:
            raw = _parse_header(height)
        except (OSError, ValueError) as e:
            print("  FAIL header load         block {}: {}".format(height, e))
            return 1
        display_hash = _sha256d(raw)[::-1].hex()
        if display_hash != pin:
            print("  FAIL header pin          block {}: double-SHA256 {} != pinned {}".format(
                height, display_hash[:16] + "…", pin[:16] + "…"))
            print("\nMISMATCH — archived header is NOT the pinned block. Never a fake green.")
            return 1
        header_merkle = raw[36:68]
        if header_merkle != committed_root:
            print("  FAIL root bind           block {}: header merkle root {} != OTS-committed {}".format(
                height, header_merkle.hex()[:16] + "…", committed_root.hex()[:16] + "…"))
            print("\nMISMATCH — the OTS proof does not land in that block. Never a fake green.")
            return 1
        block_time = struct.unpack("<I", raw[68:72])[0]
        verified.append((height, block_time, display_hash))
        print("  OK   header pin          block {} double-SHA256 == pinned hash {}…".format(
            height, pin[:16]))
        print("  OK   root bind           OTS-committed root == header merkle field {}…".format(
            committed_root.hex()[:16]))

    if not verified:
        print("\nNo PINNED Bitcoin attestation could be authenticated offline. Never a fake green.")
        return 1

    # 5. UPPER BOUND — earliest confirming block gives the tightest existed-by.
    height, block_time, display_hash = min(verified, key=lambda v: v[1])
    when = datetime.datetime.fromtimestamp(block_time, datetime.timezone.utc)
    print()
    print("EXISTED-BY VERIFIED — independently, in a second toolchain (no Rust):")
    print("  seal {}…".format(seal_hash[:16]))
    print("  was committed into Bitcoin block {} (pinned {}…)".format(height, display_hash[:16]))
    print("  whose header timestamp is {} UTC.".format(when.strftime("%Y-%m-%d %H:%M:%S")))
    print("  ⇒ the sealed content existed BY {} UTC — trustless upper bound, proven".format(
        when.strftime("%Y-%m-%d %H:%M:%S")))
    print("    against a block hash this script pins, not Elara's word.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
