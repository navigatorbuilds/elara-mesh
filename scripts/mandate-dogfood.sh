#!/usr/bin/env bash
#
# mandate-dogfood.sh — issue → act → revoke → re-query the FIRST real
# agent-mandate on a live Elara chain, demonstrating authority-to-act
# provenance that OpenTimestamps + a bare PQ signature CANNOT express.
#
# What this proves, end-to-end, on the live ledger (not a demo harness):
#   1. a PRINCIPAL (a maintainer/operator delegation key — deliberately NOT the
#      genesis consensus key; key separation is good hygiene) issues a wildcard,
#      time-bounded, revocable mandate to a BUILD-AGENT key          → mandate_id
#   2. the build-agent emits act #1 carrying that mandate_ref         → status: valid
#   3. the principal revokes the mandate
#   4. the build-agent emits act #2 under the now-revoked mandate     → status: post_revocation
#   5. re-querying act #1 STILL returns valid — every act is judged at its OWN
#      signed timestamp, so the verdict is stable forever (the
#      "queryable-over-time" accountability property that is the whole point
#      vs OTS+sig: "agent A was authorized by principal P, valid at signing,
#      later revoked").
#
# The mandate layer is OBSERVATIONAL (v0): the flag never enters consensus
# weight / the SMT leaf / the seal root — consensus-weight enforcement is
# deferred to S3 (≥2 staked validators + a signed canonical op/zone taxonomy);
# see docs/AGENT-DELEGATION.md. Nothing here touches a consensus rule; a mistake
# is corrected by revoking + re-issuing.
#
# Prerequisites (one-time):
#   elara-keygen gen --output ~/.elara/elara-maintainer-identity.json --profile A --entity organization
#   elara-keygen gen --output ~/.elara/build-agent-identity.json       --profile A --entity ai
#
# Usage:
#   NODE=http://127.0.0.1:9474 NETWORK=testnet scripts/mandate-dogfood.sh
#
set -euo pipefail

NODE="${NODE:-http://127.0.0.1:9474}"          # HTTP base; PQ port = +ELARA_PQ_PORT_OFFSET (100)
HTTP="${HTTP:-$NODE}"                            # /mandate/* read API (same host:port)
NETWORK="${NETWORK:-testnet}"                    # MUST match the target node's network_id
CLI="${CLI:-./target/release/elara-cli}"
PRINCIPAL="${PRINCIPAL:-$HOME/.elara/elara-maintainer-identity.json}"
AGENT="${AGENT:-$HOME/.elara/build-agent-identity.json}"
HOURS="${HOURS:-4380}"                           # ~6-month validity window
INDEX_WAIT="${INDEX_WAIT:-3}"                    # seconds to let ingest+index settle

for f in "$PRINCIPAL" "$AGENT"; do
  [ -f "$f" ] || { echo "missing identity: $f (see Prerequisites in this script)"; exit 1; }
done
command -v python3 >/dev/null || { echo "python3 required (hashing + JSON)"; exit 1; }

jqflag() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1','(absent)'))"; }
sha3()   { python3 -c "import hashlib,sys;print(hashlib.sha3_256(sys.argv[1].encode()).hexdigest())" "$1"; }

AGENT_HASH="$(python3 -c "import json;print(json.load(open('$AGENT'))['identity_hash'])")"

echo "== 1. issue mandate  (principal → agent ${AGENT_HASH:0:16}…) =="
ISSUE="$("$CLI" --node "$NODE" --network "$NETWORK" mandate-issue \
  --identity "$PRINCIPAL" --agent "$AGENT_HASH" --hours "$HOURS" --ops '*')"
echo "$ISSUE"
MANDATE_ID="$(sed -n 's/.*mandate_id=\([0-9a-f]\{64\}\).*/\1/p' <<<"$ISSUE" | head -1)"
[ -n "$MANDATE_ID" ] || { echo "FAILED to parse mandate_id"; exit 1; }
sleep "$INDEX_WAIT"

echo "== 2. act #1         (build-agent acts under the mandate) =="
ACT1_OUT="$("$CLI" --node "$NODE" --network "$NETWORK" agent-emit \
  --identity "$AGENT" --tool mandate-dogfood --action act-1 \
  --args-hash "$(sha3 mandate-dogfood-act-1)" --agent-id elara-build-agent \
  --mandate-ref "$MANDATE_ID")"
ACT1="$(sed -n 's/^accepted: //p' <<<"$ACT1_OUT" | head -1)"
echo "  act #1 = $ACT1"
sleep "$INDEX_WAIT"
echo -n "  status act #1 → flag="
curl -fsS --max-time 5 "$HTTP/mandate/status/$ACT1" | jqflag flag    # expect: valid

echo "== 3. revoke         (principal revokes the mandate) =="
"$CLI" --node "$NODE" --network "$NETWORK" mandate-revoke \
  --identity "$PRINCIPAL" --mandate-id "$MANDATE_ID" \
  --reason "dogfood: demonstrate post-revocation flag" | sed 's/^/  /'
sleep "$INDEX_WAIT"

echo "== 4. act #2         (build-agent acts AFTER revocation) =="
ACT2_OUT="$("$CLI" --node "$NODE" --network "$NETWORK" agent-emit \
  --identity "$AGENT" --tool mandate-dogfood --action act-2-post-revoke \
  --args-hash "$(sha3 mandate-dogfood-act-2)" --agent-id elara-build-agent \
  --mandate-ref "$MANDATE_ID")"
ACT2="$(sed -n 's/^accepted: //p' <<<"$ACT2_OUT" | head -1)"
echo "  act #2 = $ACT2"
sleep "$INDEX_WAIT"
echo -n "  status act #2 → flag="
curl -fsS --max-time 5 "$HTTP/mandate/status/$ACT2" | jqflag flag    # expect: post_revocation

echo "== 5. over-time      (re-query act #1 AFTER revocation) =="
echo -n "  status act #1 → flag="
curl -fsS --max-time 5 "$HTTP/mandate/status/$ACT1" | jqflag flag    # expect: STILL valid

cat <<EOF

── summary ──────────────────────────────────────────────────────────────────
  mandate_id : $MANDATE_ID
  act #1     : $ACT1   (valid           — signed before revocation)
  act #2     : $ACT2   (post_revocation — signed after  revocation)
  Inspect:  curl $HTTP/mandate/\$MANDATE_ID
            curl $HTTP/mandate/status/\$ACT_ID
  This authority-to-act record is what OpenTimestamps + a bare PQ signature
  structurally cannot express. v0 is observational — see docs/AGENT-DELEGATION.md.
EOF
