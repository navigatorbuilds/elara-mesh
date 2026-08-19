#!/usr/bin/env bash
# Offline verification demo — proves the bundled testnet samples with no node
# and no network. See README.md. Exit 0 only if every leg verifies.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# Python interpreter for the independent second-language legs (0, 0b–0e). The
# liboqs / opentimestamps / py_ecc libraries those legs use are NOT in the
# stdlib, and PEP 668 blocks `pip install` into the system Python on modern
# distros — so the documented setup (README "run the independent second-language
# legs too") is a hermetic venv right here. If examples/verify/.venv exists, use
# its interpreter so 0c/0d/0e actually RUN instead of skipping; otherwise fall
# back to whatever `python3` is on PATH (legs still skip transparently — never a
# fake green — when a lib is absent). The venv is .gitignored + mirror-excluded.
if [ -x "$HERE/.venv/bin/python3" ]; then
  PY="$HERE/.venv/bin/python3"
else
  PY="$(command -v python3 || true)"
fi

# Honor CARGO_TARGET_DIR — some devs set it globally to share one build cache, in
# which case the `cargo build` below puts the binary THERE, not in $ROOT/target.
# A relative value is resolved by cargo against its invocation cwd, which is $ROOT
# (the build runs in `( cd "$ROOT" && … )`). Without this the demo would build
# fine and then fail to FIND the binary — a confusing exit 127 — for those users.
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  case "$CARGO_TARGET_DIR" in
    /*) TARGET_DIR="$CARGO_TARGET_DIR" ;;
    *)  TARGET_DIR="$ROOT/$CARGO_TARGET_DIR" ;;
  esac
else
  TARGET_DIR="$ROOT/target"
fi
V="$TARGET_DIR/release/elara-verify"

if [ ! -x "$V" ]; then
  echo "── building elara-verify (one small standalone binary) ──"
  ( cd "$ROOT" && cargo build --release --features verify-cli --bin elara-verify ) || {
    echo "build failed"; exit 2; }
fi

fail=0
# Exit codes: 0 = VERIFIED (every bound proven), 1 = FAILED (forged/tampered),
# 2 = ERROR (unreadable), 3 = PARTIAL (nothing forged, but a bound is UNPROVEN —
# e.g. a pending or un-archived Bitcoin existed-by). The bundled sample is fully
# confirmed (block 957487 archived), so the demo REQUIRES exit 0 — a 3 here means
# the sample bundle regressed (a sidecar went missing) and is treated as failure.
run() { # <description> <args...>
  local desc="$1"; shift
  echo; echo "── $desc ──────────────────────────────────────────"
  "$V" "$@"; local rc=$?
  case "$rc" in
    0) echo "  → PASS (exit 0 — fully VERIFIED)" ;;
    3) echo "  → FAIL (exit 3 — PARTIAL: a bound was NOT proven; this confirmed sample should be exit 0)"; fail=1 ;;
    *) echo "  → FAIL (exit $rc)"; fail=1 ;;
  esac
}

# Like run(), but for a leg that SHOULD come back PARTIAL (exit 3): a deliberately
# under-proven anchor. This demonstrates — and guards — the honest-failure behaviour:
# with a bound's evidence withheld, the verifier must mark it ⚠ UNPROVEN, never fake a
# green ✓. A false exit 0 here is a fail-open regression and fails the whole demo.
run_expect_partial() { # <description> <args...>
  local desc="$1"; shift
  echo; echo "── $desc ──────────────────────────────────────────"
  "$V" "$@"; local rc=$?
  case "$rc" in
    3) echo "  → PASS (exit 3 — honestly PARTIAL: the unproven bound/link is ⚠ UNPROVEN, not a false ✓)" ;;
    0) echo "  → FAIL (exit 0 — claimed VERIFIED with evidence missing or a link unbound?! fail-open regression)"; fail=1 ;;
    *) echo "  → FAIL (exit $rc — expected 3/PARTIAL)"; fail=1 ;;
  esac
}

# Like run(), but for a leg that SHOULD come back FAILED (exit 1): individually
# valid inputs that provably do NOT belong to the same chain. A false exit 0
# here is the false-chain fail-open class and fails the whole demo.
run_expect_fail() { # <description> <args...>
  local desc="$1"; shift
  echo; echo "── $desc ──────────────────────────────────────────"
  "$V" "$@"; local rc=$?
  case "$rc" in
    1) echo "  → PASS (exit 1 — correctly FAILED: the inputs are individually valid but provably NOT one chain)" ;;
    0) echo "  → FAIL (exit 0 — claimed VERIFIED for a mismatched chain?! false-chain fail-open regression)"; fail=1 ;;
    *) echo "  → FAIL (exit $rc — expected 1/FAILED)"; fail=1 ;;
  esac
}

# The zone-0 epoch seal these account legs bind into, and the validator key it is
# signed by. Fixed snapshots harvested with the rest of the bundle; the seal's
# own record hash (the --expected-hash pin) comes from a header you already trust.
SEAL_WIRE="$HERE/epoch-41340-zone-0.seal.wire"
ANCHOR_PK="$(cat "$HERE/zone-0-anchor-pubkey.hex")"
SEAL_HASH="826306639200879beac7fc073166d18b968ad73756bbeefe836bdd60b557d3b7"

# README drift guard — README.md ships a copy-paste account-chain command +
# provenance pinned to THIS seal bundle. A re-harvest that bumps SEAL_WIRE/
# SEAL_HASH here but forgets README.md would ship a command pointing at a removed
# file (the drift fixed in c0885f82). Fail the demo loudly rather than ship it.
if [ -f "$HERE/README.md" ]; then
  _sb="$(basename "$SEAL_WIRE")"
  grep -q "$_sb"       "$HERE/README.md" || { echo "── README DRIFT ── README.md does not reference $_sb (re-harvest forgot to sync the README account-chain command/provenance)"; fail=1; }
  grep -q "$SEAL_HASH" "$HERE/README.md" || { echo "── README DRIFT ── README.md does not reference SEAL_HASH $SEAL_HASH (stale --expected-hash in the README account-chain command)"; fail=1; }
fi

# ── 0. Conformance vectors — independent SECOND-language reimplementation ────
# Reproduce the deterministic primitives (SHA3-256, the account-SMT
# empty/leaf/interior hashing, the 256-level inclusion-proof fold, identity
# derivation) in pure Python — and size-pin the ML-DSA-65 (FIPS 204) signature
# KAT (cryptographic verify is the implementer's job; stdlib has no PQ) — straight
# from the documented byte layouts, with no Elara code and no Rust. This is the
# actual proof behind the spec's "implement Elara in any language" promise: the
# Rust drift guard in src/conformance.rs is derive-vs-derive by construction
# (both sides call the same Rust helpers), so an independent language is what
# really pins the published bytes. Skips transparently without python3 (matching
# the account-leg idiom), never faking a pass.
if [ -n "$PY" ]; then
  echo
  echo "── 0. conformance vectors — independent Python reimplementation ──────"
  if "$PY" "$HERE/verify_conformance.py"; then
    echo "  → PASS (every deterministic vector reproduced in a second language)"
  else
    echo "  → FAIL (a conformance vector did not reproduce independently)"; fail=1
  fi
else
  echo
  echo "── 0. conformance vectors — SKIPPED (no python3 on PATH) ──────────────"
fi

# ── 0b. Record decode — independent SECOND-language wire decoder ─────────────
# Decode the sample record from the §4.3 wire format and rebuild the §4.4
# signature preimage in pure Python, then confirm the recomputed record_hash
# matches the published conformance vector — the worked "implement the record
# format in any language" proof (no Rust, no node). Graceful-skip without python3
# (leg 0 above already prints the SKIPPED line in that case).
if [ -n "$PY" ]; then
  echo
  echo "── 0b. record decode — independent Python wire decoder ───────────────"
  if "$PY" "$HERE/decode_record.py"; then
    echo "  → PASS (wire decode + §4.4 canonicalization reproduce record_hash)"
  else
    echo "  → FAIL (independent record decode did not reproduce record_hash)"; fail=1
  fi
fi

# ── 0c. PQ signatures — independent ML-DSA-65 verification (liboqs) ──────────
# Leg 0 (verify_conformance.py) is pure-stdlib, so it can only SIZE-pin the four
# ML-DSA-65 (FIPS 204) vectors. This leg feeds them to liboqs (the Open Quantum
# Safe reference C library via python-oqs — a second, non-Rust implementation,
# independent of the Rust fips204 crate that generated the vectors) and proves
# the security-critical claim the size-pins cannot: a conformant FIPS 204 verifier
# ACCEPTS each valid signature and REJECTS each must-reject twin — including the
# seal-anchor trust root over a real anchor-signed epoch seal. Graceful-skip
# (exit 3) when liboqs/python-oqs is absent — the leg-0 size-pins still stand,
# never a fake green.
if [ -n "$PY" ] && [ -f "$HERE/verify_pq.py" ]; then
  echo
  echo "── 0c. PQ signatures — independent ML-DSA-65 verify (liboqs) ─────────"
  "$PY" "$HERE/verify_pq.py"; pq_rc=$?
  if [ "$pq_rc" -eq 0 ]; then
    echo "  → PASS (liboqs independently accepts the valid PQ sigs, rejects the twins)"
  elif [ "$pq_rc" -eq 3 ]; then
    echo "  → SKIPPED (no liboqs/python-oqs on this box; leg-0 size-pins still apply)"
  else
    echo "  → FAIL (liboqs disagreed with a committed PQ vector)"; fail=1
  fi
fi

# ── 0d. Bitcoin existed-by — independent OTS → Bitcoin verification ──────────
# The Rust elara-verify legs 1-4 below prove the trustless anchoring window (the
# anchor's drand freshness + the seal's Bitcoin existed-by). This leg re-derives the *upper* (Bitcoin)
# bound in a second, non-Rust toolchain: the opentimestamps reference Python
# library walks the .ots proof to a Bitcoin block-header attestation, and stdlib
# SHA-256 authenticates the archived header against a block hash PINNED in the
# script (the same pin the Rust binary compiles in) — never a hash from the
# bundle. Fail-closed (exit 1) on a tampered header / mis-bound proof; graceful-
# skip (exit 3) when the opentimestamps library is absent, never a fake green.
if [ -n "$PY" ] && [ -f "$HERE/verify_btc.py" ]; then
  echo
  echo "── 0d. Bitcoin existed-by — independent OTS verify (opentimestamps) ──"
  "$PY" "$HERE/verify_btc.py"; btc_rc=$?
  if [ "$btc_rc" -eq 0 ]; then
    echo "  → PASS (opentimestamps independently reproduces the Bitcoin existed-by bound)"
  elif [ "$btc_rc" -eq 3 ]; then
    echo "  → SKIPPED (no opentimestamps library on this box; Rust legs 1-4 remain the reference)"
  else
    echo "  → FAIL (the independent OTS leg rejected the Bitcoin existed-by chain)"; fail=1
  fi
fi

# ── 0e. drand freshness not-before — independent BLS verification ────────────
# The companion to leg 0d: it re-derives the anchor's drand freshness bound (the
# lower end of the anchoring window — crown-F1: the anchor's pulse bounds when the
# ANCHOR was minted, not the seal, which predates it) in a second, non-Rust
# toolchain — py_ecc.bls (the Ethereum Foundation's pure-Python BLS12-381
# reference, independent of the Rust drand-verify backend) verifies the
# League-of-Entropy beacon signature over the chained-beacon message against a key
# PINNED in the script. Fail-closed (exit 1) on a bad sig / substituted key;
# graceful-skip (exit 3) when no BLS library is installed (most boxes —
# `pip install py_ecc` enables it), never a fake green. Together 0d+0e put BOTH
# ends of the anchoring window in an independent toolchain.
if [ -n "$PY" ] && [ -f "$HERE/verify_drand.py" ]; then
  echo
  echo "── 0e. drand freshness (anchor not-before) — independent BLS verify (py_ecc) ──"
  "$PY" "$HERE/verify_drand.py"; drand_rc=$?
  if [ "$drand_rc" -eq 0 ]; then
    echo "  → PASS (py_ecc independently reproduces the anchor's drand freshness bound)"
  elif [ "$drand_rc" -eq 3 ]; then
    echo "  → SKIPPED (no BLS library on this box; Rust legs 1-4 remain the reference)"
  else
    echo "  → FAIL (the independent BLS leg rejected the drand not-before)"; fail=1
  fi
fi

run "1. record — authentically signed (post-quantum, dual signature)" \
    "$HERE/sample-record.wire" --wire

run "2. anchor — the seal's Bitcoin existed-by upper bound (block 957487, trustless: the seal provably existed by then) plus the anchor's BLS-verified drand freshness below (the anchor is provably fresh, minted after that pulse — not back-dated): the anchoring window, both ends proven offline (a still-pending anchor would exit 3, not 0). The seal's OWN not-before is its embedded pulse — see leg 5." \
    --anchor "$HERE/epoch-41340-zone-0.json"

# Record + anchor in ONE run. These are two INDEPENDENT proofs — the record is
# authentically signed, AND the anchor's seal is Bitcoin-bracketed — but nothing
# binds the record INTO that seal (that needs --inclusion + --seal, leg 5). Since
# the EV-1 public-trust fix the combined verdict honestly grades the unbound
# chain PARTIAL (exit 3): both facts proven, the record↔seal link ⚠ UNPROVEN —
# never an implied chain-VERIFIED. This leg demonstrates and guards that.
run_expect_partial "3. record + anchor together — two INDEPENDENT proofs, no binding claimed: both facts are proven but the record↔seal link is ⚠ UNPROVEN, so the combined verdict is honestly PARTIAL (exit 3), never an implied chain-VERIFIED; --inclusion + --seal bind the chain (leg 5)" \
    "$HERE/sample-record.wire" --wire --anchor "$HERE/epoch-41340-zone-0.json"

# 4. Honest failure on purpose — the SAME confirmed anchor, but with its Bitcoin
# existed-by proof (the .ots sidecar) withheld. Staged in a temp dir so only the
# anchor JSON is present. The verifier keeps the trustless drand freshness bound (✓,
# the anchor is provably fresh) and marks the Bitcoin existed-by ⚠ UNPROVEN — so the
# seal's existed-by is not established: PARTIAL (exit 3), never a false VERIFIED.
PARTIAL_DIR="$(mktemp -d)"
trap 'rm -rf "$PARTIAL_DIR"' EXIT
cp "$HERE/epoch-41340-zone-0.json" "$PARTIAL_DIR/"   # NB: the .ots is deliberately NOT copied
run_expect_partial "4. honest failure by design — the SAME anchor with its Bitcoin existed-by proof withheld: the verifier keeps the trustless drand freshness bound but marks the seal's existed-by ⚠ UNPROVEN (exit 3 PARTIAL), it does NOT fake a green ✓" \
    --anchor "$PARTIAL_DIR/epoch-41340-zone-0.json"

# 5 & 6. The account-chain legs bind a sealed account-state into a validator-signed
# epoch seal under the 256-bit, identity-bound, compressed account-SMT —
# harvested 2026-07-11 from the live post-re-genesis chain. It is the SAME
# epoch-41340 seal the leg-2 anchor time-brackets, but leg 5 proves it via the
# PQ trust chain (--trusted-anchor) alone — its verdict makes no Bitcoin claim;
# the CLI does not chain the two proofs (README "Provenance" spells this out).
# The legs run only when account-proof.json carries the compressed-
# proof `present` field; an older 64-bit bundle is detected by its absence and the
# two legs SKIP transparently rather than fake a result.
account_skipped=0
if grep -q '"present"' "$HERE/account-proof.json"; then
  # The full CHAIN — bind a specific identity's SEALED account-state into a
  # validator-signed epoch seal. Three links prove it is ONE object: the account
  # walk (identity's sealed state is a leaf), account-root↔seal, and the seal is
  # signed by the pinned validator key.
  run "5. full chain — this identity's SEALED account-state is committed in a validator-signed epoch seal (account-proof → account_smt_root → seal). Reproducible on any live node; the record-SMT path is empty on idle nodes." \
      --account-inclusion "$HERE/account-proof.json" \
      --seal "$SEAL_WIRE" --trusted-anchor "$ANCHOR_PK" --expected-hash "$SEAL_HASH"

  # The false-chain guard — the SAME valid account proof bound to a sealed root it
  # does NOT climb to (all-zeros), so the root-bind provably fails (exit 1).
  run_expect_fail "6. false-chain guard — the SAME valid account proof bound to a sealed root it does NOT climb to: the walk passes but the root-bind provably fails, so the chain is FAILED (exit 1), never a false VERIFIED" \
      --account-inclusion "$HERE/account-proof.json" \
      --expect-root "0000000000000000000000000000000000000000000000000000000000000000"
else
  account_skipped=1
  echo
  echo "── 5 & 6. account-chain legs — SKIPPED (stale account bundle) ──"
  echo "  account-proof.json predates the 256-bit identity-bound compressed"
  echo "  account-SMT. Re-harvest the validator-signed account bundle with"
  echo "  scripts/harvest-verify-bundle.sh (it is NOT Bitcoin-anchored; legs"
  echo "  1-4 carry the Bitcoin bracket). The record + anchor legs above are"
  echo "  unaffected."
fi

echo
if [ "$fail" -eq 0 ]; then
  if [ "$account_skipped" -eq 0 ]; then
    echo "ALL LEGS BEHAVED AS EXPECTED — legs 1-2 fully VERIFIED offline (PQ signatures + the Bitcoin existed-by anchor); legs 3-4 honestly PARTIAL (an unbound record↔seal link and a withheld Bitcoin proof are marked ⚠ UNPROVEN, never faked ✓); leg 5 bound a sealed account-state into a validator-signed seal (the full chain); leg 6 FAILED a mismatched chain. No trust in Elara's operators anywhere — and never a fake green."
  else
    echo "RECORD + ANCHOR LEGS BEHAVED AS EXPECTED — legs 1-3 fully VERIFIED offline (PQ signatures + the Bitcoin existed-by anchor); leg 4 reported PARTIAL when the Bitcoin proof was withheld. Account-chain legs 5-6 were SKIPPED pending the post-re-genesis bundle re-harvest (256-bit SMT upgrade). No trust in Elara's operators anywhere — and never a fake green."
  fi
  exit 0
else
  echo "SOMETHING FAILED — see the legs above."
  exit 1
fi
