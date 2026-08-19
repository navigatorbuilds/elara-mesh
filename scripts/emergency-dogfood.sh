#!/usr/bin/env bash
#
# emergency-dogfood.sh — exercise the signed EmergencyHalt circuit-breaker on a
# live Elara node, end-to-end: observe un-halted → HALT → a new write is refused
# (429) → RESUME → the write is accepted again.
#
# What this proves (vs. ssh-ing in and killing the process):
#   - the halt is a SIGNED, content-addressed, gossip-propagating record — every
#     node that verifies the authority signature pauses, and it is auditable;
#   - it is RESUMABLE without restarting anything;
#   - it carries a wall-clock auto-expiry (continuity backstop), so a lost
#     authority key cannot brick the chain forever;
#   - it is node-local: it refuses NEW non-authority writes only — already-sealed
#     history, sync, and the authority's own records keep flowing, and the halt is
#     never folded into a seal / SMT root / snapshot checksum.
#
# IMPORTANT: only the GENESIS AUTHORITY's signature is honored. Point AUTHORITY at
# the authority identity JSON. If it is encrypted at rest, export
# ELARA_IDENTITY_PASSPHRASE first (the CLI decrypts on load).
#
# Usage:
#   NODE=http://127.0.0.1:9474 NETWORK=testnet \
#   AUTHORITY=$HOME/.elara/authority-identity.json scripts/emergency-dogfood.sh
#
set -euo pipefail

NODE="${NODE:-http://127.0.0.1:9474}"
NETWORK="${NETWORK:-testnet}"
CLI="${CLI:-./target/release/elara-cli}"
AUTHORITY="${AUTHORITY:-$HOME/.elara/authority-identity.json}"
# A NON-authority key to prove a normal user's write is refused while halted.
USERKEY="${USERKEY:-$HOME/.elara/build-agent-identity.json}"
MAXDUR="${MAXDUR:-3600}"   # 1h auto-expiry for the demo

halted() { curl -s "$NODE/metrics" | sed -n 's/^elara_emergency_halted \([0-9]*\).*/\1/p' | head -1; }

echo "== 1. baseline =="
echo "   elara_emergency_halted = $(halted) (expect 0)"

echo "== 2. issue EmergencyHalt (authority-signed) =="
"$CLI" --network "$NETWORK" emergency-halt \
  --identity "$AUTHORITY" --reason "dogfood: circuit-breaker drill" --max-duration-secs "$MAXDUR"

echo "   waiting for local apply…"; sleep 3
echo "   elara_emergency_halted = $(halted) (expect 1)"

echo "== 3. a NON-authority write must be refused (HTTP 429) while halted =="
set +e
"$CLI" --network "$NETWORK" submit --identity "$USERKEY" --data "halted-write-attempt" 2>&1 | tail -2
set -e

echo "== 4. RESUME (authority-signed) =="
"$CLI" --network "$NETWORK" emergency-resume --identity "$AUTHORITY"
echo "   waiting for local apply…"; sleep 3
echo "   elara_emergency_halted = $(halted) (expect 0)"

echo "== 5. the same write is accepted again =="
"$CLI" --network "$NETWORK" submit --identity "$USERKEY" --data "resumed-write-attempt" 2>&1 | tail -2

echo "== done — halt drill complete =="
