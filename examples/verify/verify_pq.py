#!/usr/bin/env python3
"""Independent post-quantum signature verification for the Elara conformance set.

``verify_conformance.py`` is pure-stdlib and therefore *skips* the four ML-DSA-65
(FIPS 204) vectors — Python's standard library has no PQ verifier, so it can only
size-pin them (pk=1952, sig=3309). This leg closes that gap: it feeds the same
committed vectors to **liboqs** (the Open Quantum Safe reference C library, via
its ``oqs`` Python binding) — a second, non-Rust ML-DSA-65 implementation, fully
independent of the Rust ``fips204`` crate that generated the vectors. It proves
the security-critical claim the size-pins cannot: that a conformant FIPS 204
verifier *accepts* each valid signature and *rejects* each must-reject twin.

Vectors checked (Appendix A.6 / A.8):
  * ``mldsa65-sig``                 — valid ML-DSA-65 KAT over an ASCII message
  * ``mldsa65-sig-reject``          — same key/message, one signature byte flipped
  * ``seal-anchor-sig``             — the light-client TRUST ROOT: the bundled
                                      real anchor-signed epoch seal; verify the
                                      anchor's signature over the seal's OWN §4.4
                                      ``signable_bytes`` (not an arbitrary string)
  * ``seal-anchor-sig-reject``      — the SAME valid seal pinned to the WRONG
                                      anchor → must reject at the trust gate
                                      (``creator_public_key != trusted anchor``),
                                      NOT because the signature is bad

The seal legs reuse ``decode_record.py`` to reconstruct the §4.4 preimage and to
surface the primary signature from the wire — so this script trusts no Elara code
to *produce* the bytes it verifies.

Run:   python3 examples/verify/verify_pq.py
Exit:  0 = every PQ vector behaved as the committed ``expected`` says
       1 = a mismatch (a valid vector failed, or a reject twin was accepted) —
           never a fake green
       2 = could not read / parse inputs
       3 = SKIPPED (no ``oqs`` / liboqs, or it lacks ML-DSA-65) — transparent,
           like the account legs in verify.sh; the pure-stdlib size-pins in
           verify_conformance.py still apply
"""

import binascii
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
VECTORS = HERE / "conformance-vectors.json"
MECH = "ML-DSA-65"

sys.path.insert(0, str(HERE))
import decode_record as dr  # noqa: E402  (Reader, decode_record, signable_bytes, sha3)


def _skip(msg: str) -> int:
    print("── PQ signature vectors — SKIPPED ──")
    print("  " + msg)
    print("  (verify_conformance.py still size-pins pk=1952, sig=3309; this leg")
    print("   upgrades that to a real accept/reject check when liboqs is present.)")
    return 3


def _load_oqs():
    try:
        import oqs  # type: ignore
    except Exception as e:  # ImportError or a liboqs load failure
        return None, "python-oqs / liboqs not importable ({})".format(e)
    try:
        if MECH not in oqs.get_enabled_sig_mechanisms():
            return None, "liboqs present but {} not enabled".format(MECH)
    except Exception as e:
        return None, "liboqs present but mechanism probe failed ({})".format(e)
    return oqs, None


def _vectors():
    doc = json.loads(VECTORS.read_text())
    return {it["name"]: it for it in doc.get("vectors", [])}


def _expected(it) -> bool:
    return str(it["expected"]).strip().lower() == "true"


def _verify_raw(oqs, msg: bytes, sig: bytes, pk: bytes) -> bool:
    with oqs.Signature(MECH) as ver:
        return bool(ver.verify(msg, sig, pk))


def _check_mldsa(oqs, vecs, name: str):
    """Generic ML-DSA-65 KAT: verify(message_ascii, signature, public_key)."""
    it = vecs[name]
    inp = it["input"]
    msg = inp["message_ascii"].encode("ascii")
    pk = binascii.unhexlify(inp["public_key"])
    sig = binascii.unhexlify(inp["signature"])
    got = _verify_raw(oqs, msg, sig, pk)
    exp = _expected(it)
    ok = got == exp
    print("  {:<4} {:<28} liboqs verify={!s:<5} expected={!s:<5}{}".format(
        "OK" if ok else "FAIL", name, got, exp,
        "" if ok else "   *** MISMATCH ***"))
    return ok


def _read_seal_wire(inp) -> bytes:
    rel = inp["seal_wire_file"]
    for cand in (REPO / rel, HERE / Path(rel).name, Path(rel)):
        if cand.exists():
            return cand.read_bytes()
    raise FileNotFoundError(rel)


def _check_seal(oqs, vecs, name: str):
    """Trust-root seal: decode wire → §4.4 preimage + primary sig + creator pk;
    gate on creator==trusted anchor; verify the anchor sig over the preimage.
    A valid verdict requires ALL THREE: record_hash pin, trust gate, sig."""
    it = vecs[name]
    inp = it["input"]
    wire = _read_seal_wire(inp)
    if dr.sha3(wire) != inp["seal_wire_sha3_256"]:
        print("  FAIL {:<28} seal wire sha3 != pinned (file drifted)".format(name))
        return False
    rec = dr.decode_record(wire)
    preimage = dr.signable_bytes(rec)
    sig = rec.get("signature")
    creator = rec["creator_public_key"]
    trusted = binascii.unhexlify(inp["trusted_anchor_public_key"])

    rh_ok = dr.sha3(preimage) == inp["seal_record_hash"]
    gate_ok = creator == trusted
    sig_ok = bool(sig) and _verify_raw(oqs, preimage, sig, creator)
    verdict = rh_ok and gate_ok and sig_ok
    exp = _expected(it)
    ok = verdict == exp
    print("  {:<4} {:<28} record_hash={!s:<5} gate={!s:<5} sig={!s:<5} "
          "verdict={!s:<5} expected={!s:<5}{}".format(
              "OK" if ok else "FAIL", name, rh_ok, gate_ok, sig_ok, verdict, exp,
              "" if ok else "   *** MISMATCH ***"))
    return ok


def main() -> int:
    oqs, why = _load_oqs()
    if oqs is None:
        return _skip(why)

    try:
        vecs = _vectors()
    except (OSError, ValueError) as e:
        print("ERROR: cannot read vectors: {}".format(e), file=sys.stderr)
        return 2

    print("Elara conformance — independent ML-DSA-65 verification (liboqs)")
    print("  vectors: {}".format(VECTORS))
    print("  liboqs:  {} via python-oqs (independent of the Rust fips204 crate)".format(MECH))
    print()

    required = ["mldsa65-sig", "mldsa65-sig-reject",
                "seal-anchor-sig/zone-0", "seal-anchor-sig-reject/wrong-anchor"]
    missing = [n for n in required if n not in vecs]
    if missing:
        print("ERROR: vectors missing: {}".format(", ".join(missing)), file=sys.stderr)
        return 2

    try:
        results = [
            _check_mldsa(oqs, vecs, "mldsa65-sig"),
            _check_mldsa(oqs, vecs, "mldsa65-sig-reject"),
            _check_seal(oqs, vecs, "seal-anchor-sig/zone-0"),
            _check_seal(oqs, vecs, "seal-anchor-sig-reject/wrong-anchor"),
        ]
    except (ValueError, KeyError, OSError, FileNotFoundError) as e:
        print("ERROR: verification setup failed: {}".format(e), file=sys.stderr)
        return 2

    print()
    if all(results):
        print("ALL PQ VECTORS VERIFIED — liboqs independently accepts the valid")
        print("signatures and rejects the must-reject twins (the trust root holds).")
        return 0
    print("MISMATCH — liboqs disagrees with a committed vector. Never a fake green.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
