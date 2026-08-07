#!/usr/bin/env bash
# docker-entrypoint.sh — Auto-generate identity and resolve genesis authority.
#
# Makes `docker compose up --build` work with zero manual steps:
#   1. Generates identity if missing
#   2. Sets ELARA_GENESIS from own hash (genesis node) or seed peer (witness)
#   2.5. Stakes the genesis authority (ELARA_GENESIS_VALIDATORS) so its epoch
#        seals can FINALIZE — settlement is attesting_stake/total_zone_stake >= 2/3,
#        so with zero stake the anchor seals but nothing ever finalizes. The live
#        dev-net seed carries the identical [[genesis_validators]] stake in its TOML;
#        the demo had balance (pre-mint) but no stake, so it sealed empty epochs
#        forever at 0 finalized (docker-finality run 4, 2026-07-04).
#   3. Execs elara-node with all original args

set -euo pipefail

DATA_DIR="${ELARA_DATA_DIR:-/data}"
IDENTITY_FILE="$DATA_DIR/identity.json"

# ── Step 1: Generate identity if missing ────────────────────────────────

if [ ! -f "$IDENTITY_FILE" ]; then
    echo "[entrypoint] generating identity..."
    elara-node --data-dir "$DATA_DIR" --generate-identity
fi

# ── Step 2: Resolve genesis authority ───────────────────────────────────

if [ -z "${ELARA_GENESIS:-}" ]; then
    if [ "${ELARA_IS_GENESIS:-false}" = "true" ]; then
        # Genesis node: use own identity hash
        ELARA_GENESIS=$(jq -r '.identity_hash' "$IDENTITY_FILE")
        export ELARA_GENESIS
        echo "[entrypoint] genesis node — authority: ${ELARA_GENESIS:0:16}..."
    elif [ -n "${ELARA_SEEDS:-}" ]; then
        # Witness/leaf node: poll first seed peer until it's up
        SEED="${ELARA_SEEDS%%,*}"  # first seed only
        echo "[entrypoint] waiting for seed peer $SEED..."
        MAX_WAIT=60
        WAITED=0
        while [ $WAITED -lt $MAX_WAIT ]; do
            # Try to get genesis_authority from seed's /status
            GENESIS=$(curl -sf "http://$SEED/status" 2>/dev/null \
                | jq -r '.genesis_authority // empty' 2>/dev/null || true)
            if [ -n "$GENESIS" ]; then
                export ELARA_GENESIS="$GENESIS"
                echo "[entrypoint] discovered genesis: ${ELARA_GENESIS:0:16}..."
                break
            fi
            sleep 2
            WAITED=$((WAITED + 2))
        done
        if [ -z "${ELARA_GENESIS:-}" ]; then
            echo "[entrypoint] WARNING: could not discover genesis after ${MAX_WAIT}s, starting without"
        fi
    else
        echo "[entrypoint] WARNING: no ELARA_GENESIS, not genesis node, no seeds — starting unconfigured"
    fi
fi

# ── Step 2.5: Stake the genesis authority so seals can finalize ────────
#
# genesis_validators STAKES from the authority's existing pre-mint balance (it
# does NOT mint — apply_genesis_validators in ledger.rs), so this changes no
# supply and every node applies it identically (deterministic genesis state —
# it cannot fork; nodes that can't resolve the authority just skip it). Set the
# SAME list on every node (genesis + witnesses) so all compute one genesis root.
# Stake 1e15 base units (matches the dev-net seed's TOML), well under the 1e19
# pre-mint. Operator override respected: only set when unset.
if [ -z "${ELARA_GENESIS_VALIDATORS:-}" ] && [ -n "${ELARA_GENESIS:-}" ]; then
    export ELARA_GENESIS_VALIDATORS="${ELARA_GENESIS}:1000000000000000"
    echo "[entrypoint] staking genesis authority ${ELARA_GENESIS:0:16}... (1e15) so seals finalize"
fi

# ── Step 3: Exec the node ──────────────────────────────────────────────

exec elara-node "$@"
