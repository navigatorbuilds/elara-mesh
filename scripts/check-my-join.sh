#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# check-my-join.sh — friend-facing "did my join actually work?" self-check.
#
# You ran the JOIN-DEVNET.md steps and your node is up. This tells you — in
# plain language with a clear verdict — whether you are a SYNCED member of the
# network, or what is still wrong and exactly where to look. It is the runnable
# companion to JOIN-DEVNET.md §5 ("What syncing looks like"), which otherwise
# asks you to eyeball a status JSON.
#
# READ-ONLY & SAFE: only ever does GET /status, /metrics, /headers on your own
# node and (if you give its address) the seed. Changes nothing, spawns nothing,
# needs no admin token. Run it as often as you like while you wait to sync.
#
# Usage:
#   scripts/check-my-join.sh [my_url] [seed_url]
#     my_url    your node's HTTP address      (default http://localhost:9473)
#     seed_url  the operator's SEED-ADDRESS    (optional, but recommended)
#               as a URL, e.g. http://100.84.x.y:9473 — with it you get the
#               two strongest checks: "am I caught up to the seed?" and the
#               definitive "is my state byte-identical to the seed's?".
#
# Exit code: 0 if you are synced (all core checks pass), 1 otherwise — so you
# can poll it:  until scripts/check-my-join.sh http://localhost:9473 \
#                       http://<seed>:9473; do sleep 15; done
#
# Requires: curl, jq  (jq: `sudo apt install -y jq`).
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

MY="${1:-http://localhost:9473}"
SEED="${2:-}"
# "Caught up" = within this many epochs of the seed head (the chain advances
# on wall-clock; being a few epochs back mid-tick is normal, not behind).
TIP_LAG=5

c_green=$'\033[32m'; c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ok()   { echo "  ${c_green}✓${c_off} $1"; }
bad()  { echo "  ${c_red}✗${c_off} $1"; CORE_OK=0; HARD_FAIL=1; }
# pbad — peers=0 only. Rendered like a hard ✗ (it IS the #1 first-join snag for a
# node that hasn't synced), but its verdict severity is decided at the end: a real
# blocker UNLESS we later prove byte-identical state, where peer count is liveness,
# not sync. So it sets PEERS_DOWN, NOT HARD_FAIL (promoted to hard at verdict time).
pbad() { echo "  ${c_red}✗${c_off} $1"; CORE_OK=0; PEERS_DOWN=1; }
warn() { echo "  ${c_yellow}…${c_off} $1"; CORE_OK=0; }
info() { echo "  ${c_dim}·${c_off} $1"; }

for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "need '$tool' — install it first (e.g. sudo apt install -y $tool)"; exit 2; }
done

# CORE_OK   — all soft+hard checks passed (clean)
# HARD_FAIL — a genuine fault (network/authority/zone mismatch, snapshot-root
#             mismatch, state-differs) — always blocks the verdict.
# PEERS_DOWN — peers_connected=0. A real blocker for a node that is NOT yet a
#             proven replica (you cannot sync with no peers), but only a LIVENESS
#             note once DEFINITIVE_SYNCED holds: a byte-identical replica whose
#             seed link momentarily drops is still synced. Promoted to HARD_FAIL
#             at verdict time ONLY when DEFINITIVE_SYNCED==0.
# DEFINITIVE_SYNCED — byte-identical account-SMT root to the seed: the strongest
#             possible proof of sync. Overrides SOFT warnings (e.g. "no snapshot
#             this boot" on a delta-synced/restarted replica) AND a peers=0
#             PEERS_DOWN, but NOT a real HARD_FAIL.
# CAUGHT_UP   — epoch within TIP_LAG of a REACHABLE seed, with no state mismatch:
#             a green-worthy sync proof on its own (overrides the soft "no snapshot
#             this boot" warn, exactly as DEFINITIVE_SYNCED does).
# SEED_OK     — the seed's /status was reachable, so a sync cross-check actually
#             ran. When 0 (no seed URL, or seed down) we CANNOT prove sync — that's
#             "unconfirmed from here", NOT "you're not synced".
CORE_OK=1; HARD_FAIL=0; DEFINITIVE_SYNCED=0; PEERS_DOWN=0; CAUGHT_UP=0; SEED_OK=0

# ── Your node responding? ───────────────────────────────────────────────────
if ! curl -s -f -m 5 -o /tmp/_cmj_my.json "$MY/status" 2>/dev/null; then
    echo
    echo "${c_red}✗ Your node isn't answering on $MY${c_off}"
    echo "  • Is it running?  pgrep -a elara-node   (or: systemctl status elara-node)"
    echo "  • Did it bind the port you passed as my_url? Check listen_addr in your TOML."
    echo "  • Look at the boot log:  journalctl -u elara-node --since '-10 min'  (or stdout)"
    echo "  See JOIN-DEVNET.md §4 (first boot) and §7 (troubleshooting)."
    exit 1
fi

my_epoch=$(jq -r '.current_epoch // 0' /tmp/_cmj_my.json)
peers=$(jq -r '.peers_connected // 0' /tmp/_cmj_my.json)
net=$(jq -r '.network_id // "?"' /tmp/_cmj_my.json)
auth=$(jq -r '.genesis_authority // "?"' /tmp/_cmj_my.json)
myzone=$(jq -r '.zone_count // "?"' /tmp/_cmj_my.json)
ident=$(jq -r '.identity_hash // "?"' /tmp/_cmj_my.json)
ntype=$(jq -r '.node_type // "?"' /tmp/_cmj_my.json)
uptime=$(jq -r '.uptime_secs // 0' /tmp/_cmj_my.json)

echo
echo "── Your node ───────────────────────────────────────────────────────────"
echo "  network=$net  node_type=$ntype  your_epoch=$my_epoch  peers=$peers"
echo "  identity=${ident:0:16}…  authority=${auth:0:8}…  up=$(printf '%.0f' "$uptime")s"
echo "── Checks ──────────────────────────────────────────────────────────────"

# ── 1. Connected to a peer? (the #1 silent failure) ─────────────────────────
if [[ "$peers" =~ ^[0-9]+$ ]] && (( peers >= 1 )); then
    ok "Connected — peers_connected=$peers (your handshake with the seed succeeded)"
else
    pbad "NOT connected — peers_connected=0. This is the most common first-join snag."
    # The cause is almost always the seed's PQ port (HTTP port + 100) being
    # unreachable — all sync/gossip rides it, there is NO HTTP fallback, so a
    # working /ping but a blocked PQ port sits at peers=0 silently forever. If we
    # were given the seed URL, don't just describe that — TEST it, turning a
    # paragraph of guesses into a definitive verdict. (Same /dev/tcp probe as
    # JOIN-DEVNET.md §7.1; opens+closes one TCP connection, changes nothing.)
    probed=0
    if [[ -n "$SEED" ]]; then
        hostport="${SEED#*://}"; hostport="${hostport%%/*}"
        if [[ "$hostport" == *:* ]]; then
            seed_host="${hostport%:*}"; seed_http_port="${hostport##*:}"
            if [[ "$seed_http_port" =~ ^[0-9]+$ ]]; then
                pq_port=$(( seed_http_port + 100 )); probed=1
                if timeout 5 bash -c "echo > /dev/tcp/$seed_host/$pq_port" 2>/dev/null; then
                    echo "      → PQ probe: the seed's PQ port :$pq_port IS reachable from here, so a"
                    echo "        blocked PQ port is RULED OUT. peers=0 is then most likely your"
                    echo "        network_id/seed_peers config, or you're still mid-handshake — wait"
                    echo "        ~30s and re-run. (Config mismatches are cross-checked below.)"
                else
                    echo "      → PQ probe: ${c_red}CONFIRMED${c_off} — the seed's PQ port :$pq_port is UNREACHABLE"
                    echo "        from here. That IS why peers=0 (all sync rides it; no HTTP fallback)."
                    echo "        Fix: the operator must expose :$pq_port — or, if the seed is a 100.x"
                    echo "        Tailscale IP, you're not on their tailnet yet (run: tailscale status)."
                    echo "        (JOIN-DEVNET.md §7.1)"
                fi
            fi
        fi
    fi
    if [[ "$probed" -eq 0 ]]; then
        echo "      Almost always the seed's PQ port (its HTTP port + 100, e.g. :9473→:9573)"
        echo "      is blocked, OR — if the seed is a 100.x Tailscale IP — you're not on the"
        echo "      operator's tailnet yet. There is NO HTTP fallback, so a reachable /ping but"
        echo "      blocked PQ port sits here silently forever. Diagnose with JOIN-DEVNET.md §7.1."
        [[ -z "$SEED" ]] && echo "      Tip: re-run with the seed URL to auto-test that port:  scripts/check-my-join.sh $MY http://<SEED-ADDRESS>"
    fi
fi

# ── 2. Snapshot bootstrap verified? (took the fast path, self-checked root) ──
curl -s -f -m 5 -o /tmp/_cmj_metrics "$MY/metrics" 2>/dev/null || true
mtr() { grep -E "^$1 " /tmp/_cmj_metrics 2>/dev/null | awk '{print $2}' | head -1; }
rootv=$(mtr elara_snapshot_bootstrap_root_verified_total); rootv=${rootv:-0}
rootm=$(mtr elara_snapshot_bootstrap_root_mismatch_total); rootm=${rootm:-0}
rep=$(mtr elara_chain_divergence_repair_attempts_total); rep=${rep:-0}
divg=$(mtr elara_chain_divergence_epochs); divg=${divg:-0}

# A recorded root MISMATCH is a HARD fault on its OWN — checked FIRST and
# INDEPENDENTLY of whether any bootstrap also verified. The single-shot first-join
# failure is rootv=0 + rootm=1 (your one bootstrap's reconstructed account-root did
# NOT match the authority's signed root). That case MUST NOT fall through to the
# "harmless, no verified snapshot" branch below — which is exactly what happened
# while this check was nested inside `rootv>=1`.
if awk -v m="$rootm" 'BEGIN{exit !(m+0>0)}'; then
    bad "Snapshot root MISMATCH recorded ($rootm) — your loaded state did NOT match the"
    echo "      authority's signed account-root. Do NOT stake or trust this node: stop it,"
    echo "      send the operator your journalctl, and re-pull from the seed. This is a hard"
    echo "      fault on its own, regardless of any other check below."
fi
if awk -v v="$rootv" 'BEGIN{exit !(v+0>=1)}'; then
    ok "Snapshot bootstrap verified — you loaded a signed state snapshot and its"
    echo "      SMT-root checked out (no genesis replay). [root_verified=$rootv]"
elif awk -v m="$rootm" 'BEGIN{exit !(m+0>0)}'; then
    : # mismatch already reported above as a hard fault; don't also print "harmless"
else
    warn "No verified snapshot this boot [root_verified=0]. Harmless on its own if the"
    echo "      DEFINITIVE state-root check below passes — a node that restarted from"
    echo "      local data, or delta-synced because the seed is too old to serve"
    echo "      snapshots, shows 0 here yet is still a true replica. Only act on this if"
    echo "      you're ALSO not caught up: then it's still bootstrapping — wait ~30s and"
    echo "      re-run."
fi

# ── 3. Clean bootstrap (no fork / no spurious repair)? ──────────────────────
if awk -v r="$rep" -v d="$divg" 'BEGIN{exit !(r+0==0 && d+0==0)}'; then
    ok "Clean bootstrap — no fork detected, no repair needed [repair=$rep divergence=$divg]"
else
    info "Bootstrap recovery activity seen [repair_attempts=$rep divergence_epochs=$divg] —"
    echo "      benign if it settles; re-run in a minute. If repair_attempts climbs every"
    echo "      run with peers≥1, capture journalctl and send it to the operator."
fi

# ── 4 & 5. Seed cross-checks (only if you gave the seed URL) ────────────────
if [[ -n "$SEED" ]]; then
    if curl -s -f -m 5 -o /tmp/_cmj_seed.json "$SEED/status" 2>/dev/null; then
        SEED_OK=1
        seed_epoch=$(jq -r '.current_epoch // 0' /tmp/_cmj_seed.json)
        seed_net=$(jq -r '.network_id // "?"' /tmp/_cmj_seed.json)
        seed_auth=$(jq -r '.genesis_authority // "?"' /tmp/_cmj_seed.json)
        seed_zone=$(jq -r '.zone_count // "?"' /tmp/_cmj_seed.json)
        if [[ "$seed_net" != "$net" ]]; then
            bad "Network mismatch — you are on '$net' but the seed is '$seed_net'."
            echo "      Fix network_id in your TOML to match the seed, then restart. (§7.2)"
        fi
        # Genesis authority must match the seed — a different authority is a different
        # chain. You'll still peer (the handshake checks network_id + version, not the
        # authority), then silently reject every seal the seed serves (signed by an
        # authority you don't trust) → snapshot never verifies, epoch never advances.
        if [[ "$seed_auth" != "?" && "$auth" != "?" && "$seed_auth" != "$auth" ]]; then
            bad "Genesis-authority mismatch — yours ${auth:0:8}… vs seed ${seed_auth:0:8}…."
            echo "      That is a different chain: you peer but reject the seed's seals."
            echo "      Set genesis_authority in your TOML to the seed's value, then restart."
        fi
        # zone_count is consensus topology, not a local preference: records route by
        # hash(record_id) % zone_count. If yours disagrees with the network you route the
        # same record to a different zone and SILENTLY FORK — even while epochs look caught
        # up and the state-root check below can still pass at low traffic. Catch it here at
        # config time, not later as a divergence. (JOIN-DEVNET.md §3.)
        if [[ "$seed_zone" =~ ^[0-9]+$ && "$myzone" =~ ^[0-9]+$ && "$seed_zone" != "$myzone" ]]; then
            bad "zone_count mismatch — yours is $myzone but the network's is $seed_zone."
            echo "      Records route by hash % zone_count; disagreeing silently forks you."
            echo "      Set zone_count=$seed_zone in your TOML, then restart. (JOIN-DEVNET.md §3)"
        fi
        # PQ-wire compatibility (pre-dial). The PQ handshake binds WIRE_VERSION into
        # its transcript, so a joiner built on a different PQ wire version fails the
        # handshake CLEANLY but silently from your side (peers=0 forever, "looks like
        # the network is dead"); the seed attributes it as
        # elara_pq_handshake_wire_mismatch_total. Catch it here over plain HTTP —
        # /version answers even when the PQ port rejects you. This is the #1 first-join
        # failure, ruled in/out before you ever dial. (JOIN-DEVNET.md §7.2/§7.3)
        seed_pqw=$(jq -r '.pq_wire_version // empty' < <(curl -s -f -m 5 "$SEED/version" 2>/dev/null) 2>/dev/null)
        my_pqw=$(jq -r '.pq_wire_version // empty' < <(curl -s -f -m 5 "$MY/version" 2>/dev/null) 2>/dev/null)
        if [[ -z "$seed_pqw" || -z "$my_pqw" ]]; then
            info "PQ-wire version check skipped — a node's /version omits pq_wire_version"
            echo "      (built before this field existed). Make sure BOTH you and the seed build"
            echo "      the same recent commit; uniform binaries are required across any PQ wire change."
        elif [[ "$seed_pqw" != "$my_pqw" ]]; then
            bad "PQ-wire version mismatch — yours is $my_pqw but the seed speaks $seed_pqw."
            echo "      The handshake binds this into its transcript, so you will fail to peer"
            echo "      (silent peers=0 from your side; the seed counts it as wire_mismatch)."
            echo "      Rebuild to the seed's commit:  git fetch && git checkout <seed-commit> &&"
            echo "      cargo build --release --features node, then restart. (JOIN-DEVNET.md §7.2/§7.3)"
        else
            ok "PQ-wire compatible — you and the seed both speak PQ wire version $my_pqw"
        fi
        # 4. Caught up to the head?
        if awk -v l="$my_epoch" -v r="$seed_epoch" -v lag="$TIP_LAG" 'BEGIN{exit !(l+0>=r-lag)}'; then
            ok "Caught up — your epoch $my_epoch vs seed $seed_epoch (within $TIP_LAG)"
            CAUGHT_UP=1
            # 5. Definitive: byte-identical state at a common settled epoch.
            cmp=$(( my_epoch - 2 )); (( cmp < 1 )) && cmp=$my_epoch
            ra=$(curl -s -m 5 "$SEED/headers/from/$cmp" 2>/dev/null | jq -r --argjson e "$cmp" '.headers[]? | select(.epoch_number==$e) | .account_smt_root' 2>/dev/null | head -1)
            rl=$(curl -s -m 5 "$MY/headers/from/$cmp" 2>/dev/null | jq -r --argjson e "$cmp" '.headers[]? | select(.epoch_number==$e) | .account_smt_root' 2>/dev/null | head -1)
            if [[ -n "$rl" && "$rl" != "null" && "$rl" == "$ra" ]]; then
                ok "DEFINITIVE: your account state is byte-identical to the seed at epoch $cmp"
                echo "      (account_smt_root ${rl:0:16}… matches). You are a true replica."
                DEFINITIVE_SYNCED=1
            elif [[ -n "$rl" && "$rl" != "null" && -n "$ra" && "$ra" != "null" ]]; then
                bad "State DIFFERS from the seed at epoch $cmp (yours ${rl:0:12}… vs seed ${ra:0:12}…)."
                echo "      Re-run in a minute; if it persists, capture journalctl for the operator."
            else
                info "Couldn't compare state roots at epoch $cmp yet (header not served on both"
                echo "      sides) — harmless this early; the caught-up check above is what matters."
            fi
        else
            warn "Still catching up — you're at $my_epoch, seed is at $seed_epoch (behind ~$(( seed_epoch - my_epoch ))). Wait and re-run."
        fi
    else
        info "Seed $SEED not reachable from here for the cross-check (that's the seed's"
        echo "      reachability, separate from your sync). Skipping caught-up/state checks."
    fi
else
    info "No seed URL given — skipped the 'caught up to seed' and 'identical state' checks."
    echo "      Re-run with the seed address for the strongest proof:"
    echo "      scripts/check-my-join.sh $MY http://<SEED-ADDRESS>"
fi

# ── Verdict ─────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────────────────────────────────"
# peers=0 is a hard blocker ONLY for a node we did NOT prove byte-identical: you
# cannot sync with no peers. But a proven replica (DEFINITIVE_SYNCED) whose seed
# link momentarily dropped is still synced — peer count is liveness, not sync —
# so there it stays a non-blocking liveness note. (zone_count / snapshot-root
# mismatches stay HARD even when byte-identical: those are real silent-fork /
# integrity faults, NOT overridden by a currently-matching root.)
(( PEERS_DOWN == 1 && DEFINITIVE_SYNCED == 0 )) && HARD_FAIL=1
# Synced iff no HARD fault AND (everything clean OR we have the definitive
# byte-identical-state proof). The definitive proof overrides soft warnings
# like "no snapshot this boot" — a delta-synced/restarted replica is still in.
if (( HARD_FAIL == 0 && ( CORE_OK == 1 || DEFINITIVE_SYNCED == 1 || CAUGHT_UP == 1 ) )); then
    echo "${c_green}🎉 You're in — your node is a synced member of '$net'.${c_off}"
    if (( PEERS_DOWN == 1 )); then
        echo
        echo "  ${c_yellow}Note:${c_off} peers_connected=0 right now — but your account-SMT root is"
        echo "  byte-identical to the seed, which PROVES you are a synced replica."
        echo "  Peer count is liveness, not sync: reconnect (seed PQ port / tailnet —"
        echo "  JOIN-DEVNET.md §7.1) to keep receiving new epochs. You are in."
    fi
    echo
    echo "Next:"
    echo "  • You joined as a non-staked FOLLOWER (by design) — no day-one staking step."
    echo "      /rpc/stake is self-stake only; the operator cannot stake you remotely. (JOIN-DEVNET.md §6)"
    echo "  • Age gate: for the first ~1h after first boot your attestations ride the"
    echo "      slower pull path (records still settle). Full push participation begins"
    echo "      ~1h in — you're $(printf '%.0f' "$uptime")s along. (JOIN-DEVNET.md §6)"
    exit 0
elif (( HARD_FAIL == 0 && PEERS_DOWN == 0 && SEED_OK == 0 )); then
    # Connected and fault-free — we simply had no reachable seed to compare
    # against (none given, or it's down right now), so sync is UNCONFIRMED, not
    # failed. Don't send a healthy operator chasing PQ-port ghosts. Still exit 1
    # so a poll loop keeps going until it CAN prove sync against a live seed.
    echo "${c_yellow}Healthy locally, but sync is UNCONFIRMED — I had no reachable seed to compare"
    echo "against (none given, or it's down right now). Your node answered fine with"
    echo "peers=$peers and no faults, so it's connected and pulling epochs — but the"
    echo "definitive 'caught up + identical state' proof needs a reachable seed.${c_off}"
    echo "  • Re-run WITH the seed URL once it's reachable (the strongest proof):"
    echo "      scripts/check-my-join.sh $MY http://<SEED-ADDRESS>"
    echo "  • Meanwhile, quick liveness:  curl -s $MY/status   — peers≥1 and a rising"
    echo "      current_epoch means you are connected and syncing."
    exit 1
else
    echo "${c_yellow}Not fully synced yet — see the ✗/… lines above and the referenced"
    echo "JOIN-DEVNET.md sections. Most first-join issues are the seed's PQ port (§7.1)"
    echo "or simply needing another minute. Re-run this script to recheck.${c_off}"
    exit 1
fi
