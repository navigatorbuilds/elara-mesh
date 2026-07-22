#!/usr/bin/env bash
# Harvest the examples/verify account-chain bundle (legs 5-6) from a LIVE node
# running the 256-bit identity-bound compressed account-SMT (commit 188f5b57+).
#
# Produces, into $OUT_DIR:
#   account-proof.json            — /proof/account/{id} in the compressed `present` format
#   epoch-<N>-zone-<Z>.seal.wire  — the ELRA-framed seal that committed proof.root
#   <hash>                        — printed SEAL_HASH pin (the seal's canonical record_hash)
# and reuses the existing zone-0-anchor-pubkey.hex (valid iff the seal CREATOR is
# the identity whose key that file holds — true on a single-authority node).
#
# It then runs the real elara-verify legs 5 + 6 and refuses to declare success
# unless leg 5 is VERIFIED (exit 0) AND leg 6 is the false-chain FAILED (exit 1).
#
# Why a node and not a fixture: every account is sealed every epoch, so this
# reproduces against any live node — the per-zone RECORD SMT is empty on idle
# nodes and has nothing to harvest (see examples/verify/README.md).
#
# Usage:
#   scripts/harvest-verify-bundle.sh <identity-hex> [PUBLIC_PORT] [DATAPLANE_PORT] [OUT_DIR]
# Defaults: PUBLIC_PORT=9474  DATAPLANE_PORT=9472  OUT_DIR=examples/verify
#
# PUBLIC_PORT serves /proof/account (the dual-router PUBLIC plane); record/seal
# wire fetch (/records/fetch) lives on the internal DATAPLANE_PORT only.
set -uo pipefail

ID="${1:?usage: harvest-verify-bundle.sh <identity-hex> [public_port] [dataplane_port] [out_dir]}"
PUB="${2:-9474}"
DP="${3:-9472}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${4:-$ROOT/examples/verify}"
V="$ROOT/target/release/elara-verify"
ANCHOR_PK_FILE="$OUT/zone-0-anchor-pubkey.hex"

die() { echo "harvest: $*" >&2; exit 1; }

[ -x "$V" ] || die "elara-verify not built — run: cargo build --release --features verify-cli --bin elara-verify"
[ -f "$ANCHOR_PK_FILE" ] || die "missing $ANCHOR_PK_FILE (the seal creator's Dilithium3 pubkey)"

echo "── 1. account proof (must be the compressed 'present' format) ──"
PROOF_RESP="$(mktemp)"; trap 'rm -f "$PROOF_RESP" "${WIRE_RESP:-}"' EXIT
curl -s --max-time 10 "http://127.0.0.1:$PUB/proof/account/$ID" > "$PROOF_RESP" || die "proof fetch failed on :$PUB"
python3 - "$OUT" "$PROOF_RESP" <<'PY' || exit 1
import sys, json
out = sys.argv[1]
d = json.load(open(sys.argv[2]))
if "present" not in d:
    sys.exit("proof has no 'present' field — node is on the OLD 64-level construction (stale binary?), or the account is not yet sealed")
if not d.get("exists"):
    sys.exit("proof reports exists:false — nothing to harvest")
lsa = d.get("latest_sealed_account") or {}
if not lsa.get("matches_proof_root"):
    sys.exit("latest_sealed_account.matches_proof_root is false — re-query after the next seal")
json.dump(d, open(f"{out}/account-proof.json", "w"), indent=2)
print(f"   seal_id={lsa['seal_id']} epoch={lsa['epoch_number']} zone={lsa['zone']} root={d['root'][:16]}…")
# stash the routing facts for the shell
open("/tmp/.harvest-facts", "w").write(f"{lsa['seal_id']}\n{lsa['epoch_number']}\n{lsa['zone']}\n")
PY
read -r SEAL_ID EPOCH ZONE < <(tr '\n' ' ' < /tmp/.harvest-facts); rm -f /tmp/.harvest-facts
SEAL_WIRE="$OUT/epoch-${EPOCH}-zone-${ZONE}.seal.wire"

echo "── 2. seal wire (ELRA-framed) from internal data-plane :$DP ──"
WIRE_RESP="$(mktemp)"
curl -s --max-time 10 -X POST "http://127.0.0.1:$DP/records/fetch" \
  -H 'content-type: application/json' -d "[\"$SEAL_ID\"]" > "$WIRE_RESP" || die "seal fetch failed on :$DP"
python3 - "$SEAL_WIRE" "$WIRE_RESP" <<'PY' || exit 1
import sys, json
arr = json.load(open(sys.argv[2]))
if not arr or not arr[0]:
    sys.exit("seal wire empty — is the data-plane port correct? (/records/fetch is internal-only)")
b = bytes.fromhex(arr[0])
if b[:4] != b"ELRA":
    sys.exit(f"not an ELRA-framed record (head={b[:4]!r})")
open(sys.argv[1], "wb").write(b)
print(f"   {len(b)} bytes -> {sys.argv[1]}")
PY

echo "── 3. SEAL_HASH (canonical record_hash the verifier recomputes) ──"
PK="$(cat "$ANCHOR_PK_FILE")"
# NB: this extraction trick proves NOTHING about the pubkey — the verifier's
# record_hash check fires BEFORE anchor membership, so a wrong key still
# yields 'actual <hash>'. The key is validated by the explicit check below.
SEAL_HASH="$("$V" --seal "$SEAL_WIRE" --trusted-anchor "$PK" \
  --expected-hash 0000000000000000000000000000000000000000000000000000000000000000 2>&1 \
  | grep -oE 'actual [0-9a-f]{64}' | awk '{print $2}')"
[ -n "$SEAL_HASH" ] || die "could not extract SEAL_HASH (seal wire undecodable?)"
echo "   SEAL_HASH=$SEAL_HASH"
# Anchor-membership check with the CORRECT hash: exit 0 iff the seal's creator
# key equals the pinned pubkey AND its ML-DSA-65 signature verifies. This is
# where a wrong/stale zone-0-anchor-pubkey.hex is actually caught.
"$V" --seal "$SEAL_WIRE" --trusted-anchor "$PK" --expected-hash "$SEAL_HASH" >/dev/null 2>&1 \
  || die "seal is NOT signed by the pinned anchor key ($ANCHOR_PK_FILE is wrong or stale)"
echo "   anchor-membership OK (seal creator == pinned pubkey, signature verifies)"

# Pulse-presence gate: public claim sites (README, KNOWN-LIMITATIONS §2, the
# launch post, examples/verify/README.md) say the committed sample seal EMBEDS
# a drand pulse. A re-harvest against a producer with drand_pulse_enabled=false
# would silently ship a pulse-less seal and strand every one of those claims.
# Fail closed; override only if you are ALSO downgrading the claim sites.
if ! grep -aq "drand_signature" "$SEAL_WIRE"; then
  [ "${HARVEST_ALLOW_PULSELESS:-0}" = "1" ] \
    || die "harvested seal carries NO embedded drand pulse (drand_pulse_enabled off on the producer?) — public claim sites depend on a pulse-carrying sample; enable the fetcher and wait a seal, or set HARVEST_ALLOW_PULSELESS=1 AND downgrade the claim sites listed above"
  echo "   WARNING: pulse-less seal accepted via HARVEST_ALLOW_PULSELESS=1 — downgrade the claim sites!"
else
  echo "   pulse-presence OK (seal embeds drand_* keys incl. signature)"
fi

echo "── 4. VALIDATE — leg 5 must VERIFY, leg 6 must FAIL ──"
"$V" --account-inclusion "$OUT/account-proof.json" --seal "$SEAL_WIRE" \
     --trusted-anchor "$PK" --expected-hash "$SEAL_HASH" >/dev/null 2>&1
L5=$?
"$V" --account-inclusion "$OUT/account-proof.json" \
     --expect-root 0000000000000000000000000000000000000000000000000000000000000000 >/dev/null 2>&1
L6=$?
echo "   leg5 (full chain)      exit=$L5 (want 0 VERIFIED)"
echo "   leg6 (false-chain guard) exit=$L6 (want 1 FAILED)"
if [ "$L5" -eq 0 ] && [ "$L6" -eq 1 ]; then
  echo
  echo "HARVEST OK — bundle in $OUT"
  echo "  next: set SEAL_WIRE/SEAL_HASH in examples/verify/verify.sh to:"
  echo "    SEAL_WIRE=\$HERE/epoch-${EPOCH}-zone-${ZONE}.seal.wire"
  echo "    SEAL_HASH=$SEAL_HASH"
  echo "  AND sync examples/verify/README.md (account-chain command + provenance):"
  echo "    --seal epoch-${EPOCH}-zone-${ZONE}.seal.wire"
  echo "    --expected-hash $SEAL_HASH"
  echo "  then run ./examples/verify/verify.sh (expects full 6/6; it self-guards README drift)."
  exit 0
else
  die "validation failed (leg5=$L5 leg6=$L6) — bundle NOT trustworthy, do not commit"
fi
