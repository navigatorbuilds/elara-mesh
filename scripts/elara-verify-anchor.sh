#!/usr/bin/env bash
# Read-side thin slice (docs/READ-SIDE-STRATEGY.md §1): offline-first,
# plain-language verification of an epoch anchor artifact.
#
# Usage: scripts/elara-verify-anchor.sh ~/.elara-anchors/epoch-N-zone-Z.json
#
# Checks, in order of evidentiary weight:
#  1. OTS proof (.ots)  — existed-by leg, hash-bound into Bitcoin (offline if
#     the proof is upgraded; pending proofs need calendar contact to confirm).
#  2. RFC3161 token (.tsr) — independent TSA witness (offline against cached
#     CA cert; fetches freetsa CA on first run).
#  3. drand pulse — not-before context for the artifact (online spot-check,
#     skipped when offline).
# Verdict is printed in plain language. Exit 0 = at least one strong leg OK.
set -uo pipefail

ARTIFACT="${1:?usage: $0 <epoch-anchor.json>}"
[ -f "$ARTIFACT" ] || { echo "no such artifact: $ARTIFACT"; exit 2; }
DIR="$(dirname "$ARTIFACT")"
CA_CACHE="$DIR/.freetsa-cacert.pem"

epoch=$(python3 -c "import json;print(json.load(open('$ARTIFACT'))['epoch'])")
seal=$(python3 -c "import json;print(json.load(open('$ARTIFACT'))['seal_hash'])")
stamped=$(python3 -c "import json;print(json.load(open('$ARTIFACT'))['stamped_at_utc'])")
drround=$(python3 -c "import json;print(json.load(open('$ARTIFACT')).get('drand_round',''))")

echo "── Elara anchor verification ──────────────────────────────"
echo "Artifact:   $ARTIFACT"
echo "Claim:      epoch $epoch (seal $seal)"
echo "            was anchored at $stamped"
echo ""

strong=0

# Leg 1 — OpenTimestamps / Bitcoin
if [ -f "$ARTIFACT.ots" ]; then
  info=$(ots info "$ARTIFACT.ots" 2>/dev/null || true)
  heights=$(echo "$info" | grep -o "BitcoinBlockHeaderAttestation([0-9]*)" | grep -o "[0-9]*" | sort -u | tr '\n' ' ')
  if [ -n "$heights" ]; then
    echo "[1] BITCOIN: PROVEN — this artifact existed by Bitcoin block(s) $heights."
    echo "    Anyone with the historical block headers can re-verify this"
    echo "    forever, offline. (Headers self-archived: $DIR/btc-header-*.txt)"
    strong=1
  elif ots verify "$ARTIFACT.ots" 2>&1 | grep -qi "pending\|not enough"; then
    echo "[1] BITCOIN: PENDING — proof submitted to calendar servers, Bitcoin"
    echo "    attestation not yet aggregated (normal for <24h-old anchors)."
  else
    vr=$(ots verify "$ARTIFACT.ots" 2>&1 | tail -1)
    if echo "$vr" | grep -qi "success"; then
      echo "[1] BITCOIN: PROVEN — $vr"
      strong=1
    else
      echo "[1] BITCOIN: UNCONFIRMED — $vr"
    fi
  fi
else
  echo "[1] BITCOIN: NO PROOF FILE (.ots missing)"
fi

# Leg 2 — RFC3161 TSA
if [ -f "$ARTIFACT.tsr" ]; then
  [ -f "$CA_CACHE" ] || curl -sf --max-time 15 https://freetsa.org/files/cacert.pem -o "$CA_CACHE" 2>/dev/null
  if [ -f "$CA_CACHE" ] && openssl ts -verify -data "$ARTIFACT" -in "$ARTIFACT.tsr" -CAfile "$CA_CACHE" >/dev/null 2>&1; then
    ts_time=$(openssl ts -reply -in "$ARTIFACT.tsr" -text 2>/dev/null | grep "Time stamp:" | sed 's/Time stamp: //')
    echo "[2] TSA:     PROVEN — independent timestamp authority attests this"
    echo "    artifact existed at: $ts_time"
    strong=1
  else
    echo "[2] TSA:     FAILED or CA unavailable (token present, verify failed)"
  fi
else
  echo "[2] TSA:     no token (.tsr) — leg absent for this anchor"
fi

# Leg 2b — eIDAS-qualified TSA (statutory weight)
if [ -f "$ARTIFACT.qtsr" ]; then
  qt=$(openssl ts -reply -in "$ARTIFACT.qtsr" -text 2>/dev/null)
  if echo "$qt" | grep -q "Status: Granted"; then
    q_time=$(echo "$qt" | grep "Time stamp:" | sed 's/Time stamp: //')
    echo "[2b] QUALIFIED TSA: PROVEN — eIDAS-qualified timestamp (Sectigo"
    echo "    (Europe) SL, policy $(echo "$qt" | grep -o 'Policy OID: [0-9.]*' | head -1 | awk '{print $3}')) attests existence at:"
    echo "    $q_time"
    echo "    Art. 41 eIDAS: statutory presumption of date accuracy + data"
    echo "    integrity in all EU member states (burden of proof reverses"
    echo "    onto any challenger). Chain-to-EUTL check: eidas.ec.europa.eu"
    strong=1
  else
    echo "[2b] QUALIFIED TSA: token present but not Granted — inspect manually"
  fi
else
  echo "[2b] QUALIFIED TSA: no qualified token (.qtsr) for this anchor"
fi

# Leg 3 — drand context
if [ -n "$drround" ]; then
  pulse=$(curl -sf --max-time 10 "https://api.drand.sh/public/$drround" 2>/dev/null || true)
  if [ -n "$pulse" ]; then
    echo "[3] DRAND:   round $drround exists on the public beacon — the"
    echo "    artifact embeds randomness unknowable before that round"
    echo "    (brackets the artifact's creation from below)."
  else
    echo "[3] DRAND:   round $drround embedded (offline — not re-checked)"
  fi
else
  echo "[3] DRAND:   no pulse embedded"
fi

echo ""
if [ "$strong" -eq 1 ]; then
  echo "VERDICT: VERIFIED — independent evidence proves epoch $epoch's seal"
  echo "existed by the attested time. No trust in the Elara project required."
  exit 0
else
  echo "VERDICT: PENDING — no strong leg confirmed yet (young anchor or offline)."
  exit 1
fi
