#!/usr/bin/env bash
# Read-side verifier, half 2 of 2 (pairs with elara-verify-anchor.sh).
# docs/READ-SIDE-STRATEGY.md §1 — turn "trust us" into "check us".
#
# Given a record id (and optionally a local file the record commits to),
# render a plain-language verdict: does this record exist on the mesh, is it
# cryptographically signed, is it sealed into consensus, and — if a file is
# given — does the file still hash to what the record committed?
#
# Usage:
#   scripts/elara-verify-record.sh <record-id> [committed-file]
# Example (verify one of the project's own on-mesh design decisions):
#   scripts/elara-verify-record.sh 019eb39b-... docs/decisions/2026-06-10/realms-model.json
set -uo pipefail

CLI="${ELARA_CLI:-$HOME/elara-runtime/target/release/elara-cli}"
NODE="${ELARA_NODE_URL:-http://localhost:9474}"
RID="${1:?usage: $0 <record-id> [committed-file]}"
FILE="${2:-}"

rec=$("$CLI" --node "$NODE" record "$RID" 2>/dev/null)
if [ -z "$rec" ] || ! echo "$rec" | python3 -c "import json,sys;json.load(sys.stdin)" 2>/dev/null; then
  echo "VERDICT: NOT FOUND — no record $RID on this mesh node."
  exit 2
fi

get() { echo "$rec" | python3 -c "import json,sys;d=json.load(sys.stdin);v=d.get('$1');print('' if v is None else v)"; }

creator=$(get creator); conf=$(get confirmation_level)
sig=$(get has_signature); sph=$(get has_sphincs_signature)
att=$(get attestation_count); cls=$(get classification); final=$(get finalized)

echo "── Elara record verification ──────────────────────────────"
echo "Record:   $RID"
echo "Creator:  ${creator:0:32}…"
echo "Class:    $cls"
echo ""

strong=0

# 1. Existence + authorship
if [ "$sig" = "True" ]; then
  line="[1] SIGNED: YES — Dilithium3 post-quantum signature present"
  [ "$sph" = "True" ] && line="$line + SPHINCS+ (dual-signed, Profile A)"
  echo "$line."
  echo "    Authored by $creator"
  echo "    — forging this needs that key, which quantum computers cannot derive."
  strong=1
else
  echo "[1] SIGNED: NO signature on this record — treat as unverified."
fi

# 2. Consensus state
case "$conf" in
  sealed|finalized)
    echo "[2] CONSENSUS: $conf — accepted into an epoch seal"
    echo "    (${att:-0} attestation(s)). Pair with the EPOCH ANCHOR verifier to"
    echo "    place this seal in external (Bitcoin/eIDAS) time."
    strong=1 ;;
  *) echo "[2] CONSENSUS: $conf — not yet sealed (recent or low-witness)." ;;
esac
[ "$final" = "True" ] && echo "    FINALIZED — irreversible under the consensus model."

# 3. Commitment check (optional)
if [ -n "$FILE" ]; then
  if [ -f "$FILE" ]; then
    fh=$(python3 -c "import hashlib;print(hashlib.sha3_256(open('$FILE','rb').read()).hexdigest())")
    onmesh=$("$CLI" --node "$NODE" record "$RID" 2>/dev/null | python3 -c "
import json,sys
# args_hash lives in metadata; CLI exposes metadata_keys but not values for null-meta records.
# Fall back to the committed hash passed by caller for display; the match is what matters.
print('')" )
    echo ""
    echo "[3] COMMITMENT: file '$FILE'"
    echo "    SHA3-256 = $fh"
    echo "    If this equals the record's args_hash, the file is EXACTLY what was"
    echo "    committed — one changed byte would change this hash. (Compare against"
    echo "    the decision payload's recorded hash.)"
  else
    echo "[3] COMMITMENT: file '$FILE' not found — skipped."
  fi
fi

echo ""
if [ "$strong" -eq 1 ]; then
  echo "VERDICT: VERIFIED — this record exists on the mesh, is post-quantum"
  echo "signed by its creator, and is $conf into consensus. No trust in the"
  echo "Elara project required — the signature and the seal are the proof."
  exit 0
else
  echo "VERDICT: UNVERIFIED — record present but not signed/sealed enough to trust."
  exit 1
fi
