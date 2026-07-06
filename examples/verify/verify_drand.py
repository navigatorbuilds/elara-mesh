#!/usr/bin/env python3
"""Independent drand not-before (BLS) verification for the Elara conformance set.

The trustless time bracket has two ends. ``verify_btc.py`` (leg 0d) reproduces the
**Bitcoin existed-by** upper bound in a second, non-Rust toolchain; this leg does
the same for the **drand not-before** lower bound — the half that, until now, only
the Rust ``elara-verify`` binary (legs 1-4 of ``verify.sh``, via the ``drand-verify``
crate) could check.

It re-derives the not-before with **no Rust**, using ``py_ecc.bls`` — the Ethereum
Foundation's pure-Python BLS12-381 reference (independent of the Rust ``drand-verify``
backend) — and proves the League-of-Entropy beacon genuinely signed the round the
anchor cites, so the round's randomness could not have existed before its scheduled
publication. Everything offline: no drand API, no network syscall.

What it checks (all against pins compiled INTO this script, never the bundle):

  1. CHAIN + PARAMS  the anchor's ``drand_chain_hash`` / genesis / period equal the
                     pinned League-of-Entropy **default** chain — so the round→time
                     map is trustless, not read from the (operator-supplied) bundle.
  2. KEY PIN         the anchor's ``drand_public_key`` equals the pinned LoE group
                     key — an artifact that ships its own (key, signature) pair
                     cannot pass; THIS is what makes the not-before trustless.
  3. BLS VERIFY      ``py_ecc`` verifies the beacon signature over the chained-beacon
                     message ``SHA-256(previous_signature ‖ round_be_u64)`` against
                     the pinned key — the proof the round was really published.
  4. FAIL-CLOSED     a one-byte-tampered signature MUST verify False on every run —
                     the leg proves it is not fake-accepting, inline.
  5. RANDOMNESS      ``SHA-256(signature)`` equals the anchor's ``drand_randomness``.
  6. NOT-BEFORE      ``genesis + (round-1)·period`` is the trustless lower bound.

Skips transparently (exit 3) when no BLS library is installed — exactly like the
liboqs leg without ``oqs`` — leaving the Rust legs 1-4 as the reference; never a
fake green. (``pip install py_ecc`` enables it; BLS is common in the drand /
Ethereum / Filecoin ecosystems.)

Run:   python3 examples/verify/verify_drand.py
Exit:  0 = the drand not-before was independently reproduced
       1 = a mismatch (bad signature, substituted key/params, or a tampered sig that
           verified) — a forgery signal, never a fake green
       2 = could not read / parse inputs
       3 = SKIPPED (no BLS library) — transparent; the Rust elara-verify legs 1-4
           in verify.sh remain the reference
"""

import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Trustless pins — the League-of-Entropy default `pedersen-bls-chained` beacon, the
# SAME constants the Rust elara-verify binary compiles in (src/bin/elara_verify.rs ::
# LOE_DEFAULT_*). The not-before is trustless ONLY because the signature is verified
# against THIS pinned key and the round→time map uses THESE pinned chain params —
# never values read from the (operator-supplied) bundle. Public, auditable against
# `curl https://api.drand.sh/info`.
LOE_CHAIN_HASH = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
LOE_PUBKEY_HEX = (
    "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"
)
LOE_GENESIS_UNIX = 1595431050
LOE_PERIOD_SECS = 30

# The anchor artifact this leg checks — the examples/verify demo seal (epoch 3217,
# zone 0; the seal verify.sh legs 1-4 use), which carries the beacon signature.
ANCHOR_JSON = HERE / "epoch-3217-zone-0.json"


def _skip(msg: str) -> int:
    print("── drand not-before (BLS) — SKIPPED ──")
    print("  " + msg)
    print("  (the Rust elara-verify legs 1-4 in verify.sh remain the reference for the")
    print("   drand not-before bound when no BLS library is installed.)")
    return 3


def _load_bls():
    """Import an independent BLS12-381 verifier. py_ecc is the Ethereum Foundation's
    pure-Python reference (a different implementation from the Rust drand-verify
    backend). Returns a verify(pk48, msg, sig96)->bool, or (None, why)."""
    try:
        from py_ecc.bls import G2Basic  # type: ignore
    except Exception as e:
        return None, "py_ecc not importable ({})".format(e)

    def _verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            return bool(G2Basic.Verify(pk, msg, sig))
        except Exception:
            # py_ecc raises on malformed group elements — that is a rejection.
            return False

    return _verify, None


def _chained_message(prev_sig: bytes, rnd: int) -> bytes:
    """drand default chain: the signed message is SHA-256(previous_signature ‖ round),
    round as 8-byte big-endian (mirrors drand-verify's message construction)."""
    return hashlib.sha256(prev_sig + struct.pack(">Q", rnd)).digest()


def _not_before_unix(rnd: int) -> int:
    """Round publication time: round 1 is emitted at genesis (rounds are 1-indexed)."""
    return LOE_GENESIS_UNIX + (rnd - 1) * LOE_PERIOD_SECS


def main() -> int:
    verify, why = _load_bls()
    if verify is None:
        return _skip(why)

    print("Elara conformance — independent drand not-before verification (py_ecc BLS12-381)")
    print("  artifact: {}".format(ANCHOR_JSON.name))
    print("  BLS:      py_ecc.bls.G2Basic (Ethereum Foundation reference, no Rust)")
    print()

    try:
        a = json.loads(ANCHOR_JSON.read_bytes())
        rnd = int(a["drand_round"])
        sig = bytes.fromhex(a["drand_signature"])
        prev = bytes.fromhex(a["drand_previous_signature"])
    except (OSError, ValueError, KeyError) as e:
        print("ERROR: cannot read / parse anchor: {}".format(e), file=sys.stderr)
        return 2

    # 1. CHAIN + PARAMS — the round→time map must rest on the pinned default chain.
    chain_ok = str(a.get("drand_chain_hash", "")).lower() == LOE_CHAIN_HASH
    params_ok = (int(a.get("drand_genesis_unix", -1)) == LOE_GENESIS_UNIX
                 and int(a.get("drand_period_secs", -1)) == LOE_PERIOD_SECS)
    print("  {} chain + params     drand_chain_hash / genesis / period {} the pinned LoE default chain".format(
        "OK  " if (chain_ok and params_ok) else "FAIL", "==" if (chain_ok and params_ok) else "!="))
    if not (chain_ok and params_ok):
        print("\nMISMATCH — not the pinned chain; the round→time map cannot be trusted. Never a fake green.")
        return 1

    # 2. KEY PIN — verify against the pinned key, never the artifact's own.
    pk_art = str(a.get("drand_public_key", "")).lower()
    key_ok = pk_art == LOE_PUBKEY_HEX
    print("  {} key pin            artifact drand_public_key {} the pinned LoE group key".format(
        "OK  " if key_ok else "FAIL", "==" if key_ok else "!="))
    if not key_ok:
        print("\nMISMATCH — substituted beacon key; a forged (key,sig) pair cannot pass. Never a fake green.")
        return 1
    pinned_pk = bytes.fromhex(LOE_PUBKEY_HEX)

    # 3. BLS VERIFY — the round was really published by the League of Entropy.
    msg = _chained_message(prev, rnd)
    sig_ok = verify(pinned_pk, msg, sig)
    print("  {} BLS signature      py_ecc verifies the beacon sig over SHA-256(prev‖round) = {}".format(
        "OK  " if sig_ok else "FAIL", sig_ok))
    if not sig_ok:
        print("\nMISMATCH — the beacon signature does not verify against the pinned key. Never a fake green.")
        return 1

    # 4. FAIL-CLOSED — prove, inline, that a tampered signature is rejected.
    tampered = bytearray(sig)
    tampered[10] ^= 0x01
    if verify(pinned_pk, msg, bytes(tampered)):
        print("  FAIL fail-closed        a one-byte-tampered signature VERIFIED — the check is fake-accepting")
        print("\nThe verifier accepted a forged signature. Never a fake green.")
        return 1
    print("  OK   fail-closed        a one-byte-tampered signature is rejected (not fake-accepting)")

    # 5. RANDOMNESS — drand randomness is SHA-256 of the signature.
    rand_ok = hashlib.sha256(sig).hexdigest() == str(a.get("drand_randomness", "")).lower()
    print("  {} randomness         SHA-256(signature) {} the anchor's drand_randomness".format(
        "OK  " if rand_ok else "FAIL", "==" if rand_ok else "!="))
    if not rand_ok:
        print("\nMISMATCH — randomness is not SHA-256(signature). Never a fake green.")
        return 1

    # 6. NOT-BEFORE — the trustless lower bound.
    nb = _not_before_unix(rnd)
    when = datetime.datetime.fromtimestamp(nb, datetime.timezone.utc)
    print()
    print("NOT-BEFORE VERIFIED — independently, in a second toolchain (no Rust):")
    print("  the League of Entropy signed drand round {} (chain 8990e7a9…),".format(rnd))
    print("  whose randomness could not exist before its scheduled publication at")
    print("  {} UTC.".format(when.strftime("%Y-%m-%d %H:%M:%S")))
    print("  ⇒ the seal that cites this round existed NO EARLIER THAN {} UTC —".format(
        when.strftime("%Y-%m-%d %H:%M:%S")))
    print("    trustless lower bound, proven against a beacon key this script pins.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
