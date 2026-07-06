#!/usr/bin/env python3
"""Independent, second-language conformance check for the Elara Protocol.

Reads ``conformance-vectors.json`` and recomputes every deterministic vector
from the documented byte layouts using ONLY the Python standard library
(``hashlib`` SHA3-256) — no Elara code, no Rust, no node, no network.

This is the actual proof behind the spec's *"implement Elara in any language"*
promise. The Rust unit tests in ``src/conformance.rs`` derive the vectors from
the reference implementation and pin them against the committed JSON — but both
sides call the same Rust hashing helpers, so that guard is a derive-vs-derive
check by construction. This script is the genuinely independent leg: a
from-scratch reimplementation, in a different language with a different SHA3
implementation, that reproduces the same published bytes purely from the spec.

Run:   python3 examples/verify/verify_conformance.py
       python3 examples/verify/verify_conformance.py path/to/conformance-vectors.json
Exit:  0 = every reproducible vector matched
       1 = a mismatch (drift or a real bug — fail loudly, never a fake green)
       2 = could not read / parse inputs

Primitives reproduced here (the self-contained deterministic set):
  sha3-256             SHA3-256(ascii bytes)
  smt-empty            SHA3-256("")                     (empty-subtree sentinel)
  smt-leaf             SHA3-256(0x00 || key || value)   (domain tag 0x00, §6.2)
  smt-interior         SHA3-256(0x01 || left || right)  (domain tag 0x01, §6.2)
  smt-proof            fold compressed inclusion proof → root  (256-level, §6.2)
  smt-proof-reject     tampered proof MUST NOT fold to the claimed root (fail-closed)
  identity-derivation  SHA3-256(creator_public_key)     (§3.1)
  merkle-inclusion     fold record-membership proof → root  (NO tags: SHA3(left||right), §11.22.1)
  merkle-inclusion-reject  tampered proof MUST NOT fold to the claimed root (fail-closed)
  account-binding      fold proof → root, THEN bind to header's signed account_smt_root (§11.22)
  account-binding-reject   a VALID proof against the WRONG signed root MUST be rejected (fail-closed)

``record-hash`` is not reproduced from primitives *here* — it needs the full §4.4
record decode + canonicalization (the record codec). That full second-language
decode lives in ``decode_record.py`` (run as ``verify.sh`` leg 0b), which
reproduces ``record_hash`` end-to-end from the wire bytes. This script only pins
the wire INPUT (``input.wire_sha3_256 == SHA3-256(bytes of input.wire_file)``), so
the two scripts together independently cover every vector in the set.

``mldsa65-sig`` / ``mldsa65-sig-reject`` are the post-quantum signature
verification KAT (ML-DSA-65 / FIPS 204). The Python standard library has no PQ
verifier, so this script does NOT run the cryptographic check — it pins the FIPS
204 byte sizes (public key 1952, signature 3309) and then SKIPs. The contract an
independent implementation must satisfy: feed ``(public_key, message_ascii,
signature)`` to its own FIPS 204 ML-DSA-65 Verify with an EMPTY context string —
``mldsa65-sig`` MUST be accepted, ``mldsa65-sig-reject`` (one byte flipped) MUST
be rejected. Signing is randomized, so signatures are verified, never reproduced.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DEFAULT_VECTORS = HERE / "conformance-vectors.json"


def sha3(data: bytes) -> str:
    """SHA3-256 (FIPS-202) of ``data``, as lowercase hex."""
    return hashlib.sha3_256(data).hexdigest()


def unhex(s: str) -> bytes:
    """Decode bare lowercase hex (the form ``hex::encode`` emits)."""
    return bytes.fromhex(s)


def tag_byte(tag: str) -> bytes:
    """Parse a ``"0x00"``-style domain tag string into its single byte."""
    return bytes([int(tag, 16)])


def smt_fold_to_root(
    account_id: bytes, state_hash: bytes, present: bytes, siblings: list
) -> str:
    """Fold a compressed account-SMT inclusion proof to its root, from scratch.

    A faithful pure-``hashlib`` reimplementation of the spec's §6.2 fold (the
    reference is ``elara_smt::verify_proof``) — the single most error-prone thing
    an external light-client implementer must get right, with no Elara code:

      * leaf   = SHA3-256(0x00 || account_id || state_hash)
      * path   = SHA3-256(account_id)                       (the key is hashed)
      * fold parent_depth 255 → 0, consuming a sibling only where present-bit is
        set (else EMPTY_HASH); bit order is MSB-first
      * (left, right) = (sibling, current) if bit(path, depth) else (current, sibling)
      * parent = SHA3-256(0x01 || left || right), unless both children are
        EMPTY_HASH (then EMPTY_HASH — the empty-subtree collapse)
    """
    empty = hashlib.sha3_256(b"").digest()

    def bit(b: bytes, i: int) -> int:
        # MSB-first: bit 0 is the most-significant bit of byte 0.
        return (b[i // 8] >> (7 - (i % 8))) & 1

    current = hashlib.sha3_256(b"\x00" + account_id + state_hash).digest()  # leaf
    path = hashlib.sha3_256(account_id).digest()  # 256-bit path
    idx = 0
    parent_depth = 256
    while parent_depth > 0:
        parent_depth -= 1  # 255 .. 0
        if bit(present, parent_depth):
            sib = siblings[idx]
            idx += 1
        else:
            sib = empty
        if bit(path, parent_depth):  # we are the right child
            left, right = sib, current
        else:  # we are the left child
            left, right = current, sib
        if left == empty and right == empty:
            current = empty  # empty-subtree collapse (inert for inclusion)
        else:
            current = hashlib.sha3_256(b"\x01" + left + right).digest()
    if idx != len(siblings):
        raise ValueError(f"leftover siblings: consumed {idx} of {len(siblings)}")
    return current.hex()


def merkle_inclusion_fold(leaf: bytes, siblings: list) -> str:
    """Fold a zone record-membership inclusion proof (``network::merkle``) to its root.

    The protocol's SECOND Merkle structure, deliberately DIFFERENT from the
    account-SMT fold above — and the divergence an external implementer is most
    likely to get wrong. Here there are NO domain tags: the leaf is the record
    hash verbatim (not ``SHA3(0x00 || …)``) and an interior node is
    ``SHA3(left || right)`` (not ``SHA3(0x01 || …)``). Sibling order is explicit
    per node via ``is_right`` (not derived from a key path as in the SMT):

      * start ``current = leaf``
      * for each sibling bottom-up: ``combined = current || hash`` when
        ``is_right`` else ``hash || current``; then ``current = SHA3-256(combined)``
      * the final ``current`` is the root

    This is a faithful pure-``hashlib`` reimplementation of
    ``network::merkle::verify_proof`` — the fold ``elara-verify verify-inclusion``
    runs over a cross-zone inclusion proof, with no Elara code.
    """
    current = leaf
    for node in siblings:
        sib = unhex(node["hash"])
        combined = current + sib if node["is_right"] else sib + current
        current = hashlib.sha3_256(combined).digest()
    return current.hex()


class Skip(Exception):
    """Raised by a reproducer that intentionally does not recompute a vector."""


def reproduce(vec: dict) -> str:
    """Independently recompute a vector's ``expected`` from its documented layout.

    Raises ``Skip`` for vectors not reproducible from hash primitives alone
    (currently only ``record-hash``), and ``ValueError`` for an unknown
    primitive (so a newly-added primitive can never silently go unchecked).
    """
    prim = vec["primitive"]
    inp = vec["input"]

    if prim == "sha3-256":
        return sha3(inp["ascii"].encode("ascii"))

    if prim == "smt-empty":
        # Empty-subtree sentinel: SHA3-256("").
        return sha3(b"")

    if prim == "smt-leaf":
        # Leaf hash binds key+value under domain tag 0x00.
        assert tag_byte(inp["tag"]) == b"\x00", f"smt-leaf tag != 0x00: {inp['tag']}"
        return sha3(b"\x00" + unhex(inp["key"]) + unhex(inp["value"]))

    if prim == "smt-interior":
        # Interior node combines two children under domain tag 0x01.
        assert tag_byte(inp["tag"]) == b"\x01", f"smt-interior tag != 0x01: {inp['tag']}"
        return sha3(b"\x01" + unhex(inp["left"]) + unhex(inp["right"]))

    if prim in ("smt-proof", "smt-proof-reject"):
        # Fold a compressed inclusion proof to its root — the full §6.2 traversal.
        # For `smt-proof` the fold MUST equal `expected`; for `smt-proof-reject`
        # (a tampered proof) it MUST NOT — main() inverts the comparison so a
        # tampered proof that still reaches the claimed sealed root fails loudly.
        return smt_fold_to_root(
            unhex(inp["account_id"]),
            unhex(inp["state_hash"]),
            unhex(inp["present"]),
            [unhex(s) for s in inp["siblings"]],
        )

    if prim in ("merkle-inclusion", "merkle-inclusion-reject"):
        # Fold a zone record-membership inclusion proof (network::merkle) — the
        # cross-zone evidence path, the SECOND Merkle tree, with NO domain tags.
        # For `merkle-inclusion` the fold MUST equal `expected`; for
        # `merkle-inclusion-reject` (a tampered proof) it MUST NOT — main()
        # inverts the comparison for `*-reject`, so a tampered proof that still
        # reaches the claimed sealed root fails loudly.
        return merkle_inclusion_fold(unhex(inp["leaf"]), inp["siblings"])

    if prim == "identity-derivation":
        # identity = SHA3-256(creator_public_key).
        return sha3(unhex(inp["creator_public_key"]))

    if prim == "record-hash":
        # Not a hash-primitive vector — needs the full §4.4 record codec. We can
        # still pin the wire INPUT independently: the embedded wire_sha3_256 must
        # equal SHA3-256 of the referenced wire file's bytes. If that holds we
        # raise Skip (the final record_hash is left to a full record impl); if it
        # does NOT hold, the bundled wire file drifted from the vector — fail.
        wire_path = REPO_ROOT / inp["wire_file"]
        got = sha3(wire_path.read_bytes())
        want = inp["wire_sha3_256"]
        if got != want:
            raise ValueError(
                f"wire file {inp['wire_file']} hashes to {got}, "
                f"but the vector pins wire_sha3_256={want}"
            )
        raise Skip("record_hash reproduced end-to-end by decode_record.py (verify.sh leg 0b); wire input pinned ✓")

    if prim in ("mldsa65-sig", "mldsa65-sig-reject"):
        # ML-DSA-65 (FIPS 204) signature verification KAT. Pure-stdlib Python has
        # no post-quantum verifier, so this script cannot run the cryptographic
        # check — that is the implementer's job against their own FIPS 204
        # ML-DSA-65 Verify (with an EMPTY context string): `mldsa65-sig` MUST
        # verify, `mldsa65-sig-reject` MUST be rejected. We still pin the FIPS 204
        # byte sizes independently here — a real drift signal stdlib *can* check —
        # so a wrong-length key or signature fails loudly rather than skipping.
        pk = unhex(inp["public_key"])
        sig = unhex(inp["signature"])
        if len(pk) != 1952:
            raise ValueError(f"ML-DSA-65 public_key is {len(pk)} bytes, expected 1952 (FIPS 204)")
        if len(sig) != 3309:
            raise ValueError(f"ML-DSA-65 signature is {len(sig)} bytes, expected 3309 (FIPS 204)")
        verb = "rejected" if prim.endswith("-reject") else "accepted"
        raise Skip(
            f"ML-DSA-65 (FIPS 204) sig — feed to your PQ Verify (ctx=empty); MUST be "
            f"{verb}. sizes pinned pk=1952, sig=3309"
        )

    if prim in ("account-binding", "account-binding-reject"):
        # The light-client KEYSTONE: a folded account-proof root is only
        # trustworthy once BOUND to the account_smt_root the trusted, anchor-signed
        # epoch header commits to. Reproduce in pure stdlib: (1) fold the proof to
        # a root exactly as `smt-proof`, then (2) accept iff the fold reconstructs
        # `proof_root` AND `proof_root == header_account_smt_root`. The reject twin
        # is a VALID proof (fold succeeds) against a DIFFERENT signed root, so the
        # bind fails — the fail-open class the per-tree `*-reject` folds can't
        # catch (there the fold breaks; here only the header context is wrong).
        # `expected` is the boolean verify result, so main() direct-compares it
        # (never the root-inversion the hash `*-reject` vectors use).
        folded = smt_fold_to_root(
            unhex(inp["account_id"]),
            unhex(inp["state_hash"]),
            unhex(inp["present"]),
            [unhex(s) for s in inp["siblings"]],
        )
        bound = folded == inp["proof_root"] and (
            inp["proof_root"] == inp["header_account_smt_root"]
        )
        return "true" if bound else "false"

    if prim in ("seal-anchor-sig", "seal-anchor-sig-reject"):
        # Epoch-seal anchor-signature verification — the light-client trust ROOT.
        # Like mldsa65-sig this needs a FIPS 204 ML-DSA-65 verifier, which
        # pure-stdlib Python lacks, so this script SKIPs the cryptographic check. It
        # still pins what stdlib CAN: the anchor pubkey size (1952) and the seal
        # wire's SHA3-256 against the on-disk file — a real drift signal. The
        # contract for an independent implementation: decode the seal record (the
        # decode_record.py recipe), require record_hash == seal_record_hash AND
        # creator_public_key == trusted_anchor_public_key, rebuild §4.4
        # signable_bytes, and run ML-DSA-65 Verify (empty context). `seal-anchor-sig`
        # MUST be accepted; the wrong-anchor twin MUST be rejected (its
        # creator_public_key is not the pinned anchor — the trust-root fail-open).
        pk = unhex(inp["trusted_anchor_public_key"])
        if len(pk) != 1952:
            raise ValueError(f"anchor public_key is {len(pk)} bytes, expected 1952 (FIPS 204)")
        wire_path = REPO_ROOT / inp["seal_wire_file"]
        got = sha3(wire_path.read_bytes())
        want = inp["seal_wire_sha3_256"]
        if got != want:
            raise ValueError(
                f"seal wire {inp['seal_wire_file']} hashes to {got}, "
                f"but the vector pins seal_wire_sha3_256={want}"
            )
        verb = "rejected (creator_public_key != pinned anchor)" if prim.endswith("-reject") else "accepted"
        raise Skip(
            f"epoch-seal anchor-sig — feed the seal record to your PQ Verify (ctx=empty); "
            f"MUST be {verb}. anchor size pinned 1952, seal wire hash pinned ✓"
        )

    raise ValueError(f"unknown primitive {prim!r} — verifier is missing a reproducer")


def main(argv: list) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_VECTORS
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        print(f"ERROR: cannot read/parse {path}: {e}", file=sys.stderr)
        return 2

    vectors = doc.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        print(f"ERROR: {path} has no vectors", file=sys.stderr)
        return 2

    print(f"Elara conformance — independent Python reimplementation")
    print(f"  vectors: {path}")
    print(f"  python:  {sys.version.split()[0]}  (hashlib SHA3-256)\n")

    matched = skipped = failed = 0
    for vec in vectors:
        name = vec.get("name", "<unnamed>")
        expected = vec.get("expected", "")
        try:
            got = reproduce(vec)
        except Skip as why:
            print(f"  SKIP {name:24} ({why})")
            skipped += 1
            continue
        except (KeyError, ValueError, AssertionError) as e:
            print(f"  FAIL {name:24} {e}")
            failed += 1
            continue
        # A hash-fold `*-reject` vector is a MUST-NOT-verify case: `expected` is
        # the sealed root the (tampered) proof falsely claims, and a sound
        # reproduction must NOT reconstruct it. Invert the check — reaching
        # `expected` is fail-open. This inversion applies ONLY to hash folds:
        # a boolean VERIFY vector (mldsa65*, account-binding*) already returns the
        # accept/reject decision and is direct-compared (`expected = "false"` for
        # its reject twin), so gate the inversion on a non-boolean `expected`.
        is_reject = vec.get("primitive", "").endswith("-reject") and expected not in (
            "true",
            "false",
        )
        if is_reject:
            if got != expected:
                print(f"  OK   {name:24} rejected ✓ (fold ≠ the claimed sealed root)")
                matched += 1
            else:
                print(f"  FAIL {name:24} FAIL-OPEN: tampered proof folded to the claimed root {got}")
                failed += 1
        elif got == expected:
            print(f"  OK   {name:24} {got}")
            matched += 1
        else:
            print(f"  FAIL {name:24} reproduced {got}")
            print(f"       {'':24} expected   {expected}")
            failed += 1

    print(
        f"\n{matched} reproduced, {skipped} skipped (record-hash — see decode_record.py), "
        f"{failed} failed."
    )
    if failed:
        print("MISMATCH — a vector did not reproduce independently.")
        return 1
    print("ALL REPRODUCED — the deterministic primitives are byte-identical in Python.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
