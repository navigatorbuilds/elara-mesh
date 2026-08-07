#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# init-join.sh — the pre-build bookend to check-my-join.sh.
#
# You have the operator's triple (SEED / AUTHORITY-HASH / NETWORK-ID) and a
# fresh clone of elara-mesh. Run this BEFORE you build. It does the two things
# JOIN-DEVNET.md asks you to do by hand — and which are the actual ways a first
# join goes wrong:
#
#   1. Proves the seed is reachable on BOTH ports (HTTP and the PQ port =
#      HTTP+100) *before* you spend 20 minutes building. A blocked PQ port is
#      the #1 silent failure: the node boots clean and then sits at
#      peers_connected:0 forever, because all sync runs over PQ and there is no
#      HTTP fallback. Catching it now saves the wasted build.
#   2. Writes a correct elara-node.toml from the triple — so a typo in the
#      64-char authority hash can't quietly fork or reject your handshake. The
#      hash is format-checked, then cross-checked against what the seed itself
#      reports, and zone_count is read live from the seed (it is network
#      topology, not a local preference — JOIN-DEVNET.md §3).
#
# READ-ONLY against the network: only ever does GET /status on the seed and a
# TCP-connect probe of the PQ port. The only thing it writes is your local
# elara-node.toml (and it refuses to clobber an existing one without --force).
# Needs no binary built yet, no admin token, no jq (falls back to grep).
#
# Usage:
#   scripts/init-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID> [options]
#     SEED-ADDRESS    host:port of the operator's seed, e.g. 100.x.y.z:9473
#                     (a tailnet IP; bare host defaults to :9473)
#     AUTHORITY-HASH  the 64-char hex genesis-authority hash from the operator
#     NETWORK-ID      the realm name from the operator, e.g. testnet
#   options:
#     --out <path>    config file to write   (default ./elara-node.toml)
#     --http-port N   your node's HTTP port  (default 9473; PQ auto = N+100)
#     --force         overwrite an existing config file
#
# Exit code: 0 = ready to build (config written, seed reachable, triple agrees);
#            non-zero = stop and read the message (nothing half-written).
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

c_green=$'\033[32m'; c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_dim=$'\033[2m'; c_bold=$'\033[1m'; c_off=$'\033[0m'
ok()   { echo "  ${c_green}✓${c_off} $1"; }
bad()  { echo "  ${c_red}✗${c_off} $1"; }
warn() { echo "  ${c_yellow}…${c_off} $1"; }
info() { echo "  ${c_dim}·${c_off} $1"; }
die()  { echo; echo "${c_red}✗ $1${c_off}"; shift; for l in "$@"; do echo "    $l"; done; exit 1; }

usage() {
    echo "usage: scripts/init-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID> [--out path] [--http-port N] [--force]"
    echo "  e.g. scripts/init-join.sh 100.x.y.z:9473 <64-hex-hash> testnet"
    exit 2
}

# ── Parse args ───────────────────────────────────────────────────────────────
SEED_RAW=""; AUTH=""; NET=""; OUT="./elara-node.toml"; HTTP_PORT="9473"; FORCE=0
POS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out)       OUT="${2:-}"; shift 2 ;;
        --http-port) HTTP_PORT="${2:-}"; shift 2 ;;
        --force)     FORCE=1; shift ;;
        -h|--help)   usage ;;
        --*)         echo "unknown option: $1"; usage ;;
        *)           POS+=("$1"); shift ;;
    esac
done
[ "${#POS[@]}" -eq 3 ] || usage
SEED_RAW="${POS[0]}"; AUTH="${POS[1]}"; NET="${POS[2]}"

command -v curl >/dev/null 2>&1 || die "curl is required (it's the one hard dependency here)." \
    "Install it:  sudo apt install -y curl"

# ── Normalise + validate the triple (cheap checks first, before any network) ──
echo
echo "${c_bold}── Checking the triple the operator gave you ───────────────────────────${c_off}"

# SEED: strip any scheme, split host:port, default port 9474.
SEED="${SEED_RAW#http://}"; SEED="${SEED#https://}"; SEED="${SEED%/}"
if [[ "$SEED" == *:* ]]; then
    SEED_HOST="${SEED%:*}"; SEED_PORT="${SEED##*:}"
else
    SEED_HOST="$SEED"; SEED_PORT="9473"
    info "no port in SEED-ADDRESS — assuming :9473 (the compiled default HTTP port)."
fi
[[ "$SEED_PORT" =~ ^[0-9]+$ ]] || die "SEED port '$SEED_PORT' is not a number." \
    "Expected host:port, e.g. 100.x.y.z:9474"
PQ_PORT=$((SEED_PORT + 100))
ok "seed parsed: HTTP ${SEED_HOST}:${SEED_PORT}  ·  PQ ${SEED_HOST}:${PQ_PORT}  (PQ = HTTP+100)"

# AUTHORITY-HASH: exactly 64 hex chars. This single check kills the typo class.
AUTH_LC="$(printf '%s' "$AUTH" | tr 'A-F' 'a-f')"
if ! [[ "$AUTH_LC" =~ ^[0-9a-f]{64}$ ]]; then
    n=${#AUTH}
    die "AUTHORITY-HASH isn't 64 hex characters (you gave ${n})." \
        "It must be exactly 64 chars, 0-9/a-f — copy it from the operator verbatim," \
        "with no spaces or line breaks. A wrong hash = silent handshake rejection."
fi
ok "authority hash is well-formed (64 hex chars)"

# NETWORK-ID: non-empty, no whitespace.
[[ -n "$NET" && "$NET" != *[[:space:]]* ]] || die "NETWORK-ID '$NET' is empty or contains spaces." \
    "Use the exact realm name the operator gave you, e.g. testnet"
ok "network id: ${NET}"

# ── Reachability: BOTH ports, before the build ───────────────────────────────
echo
echo "${c_bold}── Is the seed reachable? (do this before the 20-minute build) ─────────${c_off}"

STATUS_JSON="$(curl -s -f -m 6 "http://${SEED_HOST}:${SEED_PORT}/status" 2>/dev/null)" || STATUS_JSON=""
if [ -z "$STATUS_JSON" ]; then
    EXTRA=()
    if [[ "$SEED_HOST" =~ ^100\. ]]; then
        EXTRA=( "That ${SEED_HOST} looks like a Tailscale overlay IP. Most likely you are not on" \
                "the operator's tailnet yet (not a port problem):" \
                "  • run:  tailscale status   and confirm the seed node is listed and online" \
                "  • if it isn't, ask the operator to (re-)share their node with your tailnet" )
    fi
    die "Seed HTTP port ${SEED_HOST}:${SEED_PORT} is NOT reachable from here." \
        "Nothing was written. Fix reachability, then re-run — don't build yet." \
        "${EXTRA[@]}"
fi
ok "seed HTTP ${SEED_HOST}:${SEED_PORT} reachable (/status answered)"

if timeout 6 bash -c "exec 3<>/dev/tcp/${SEED_HOST}/${PQ_PORT}" 2>/dev/null; then
    ok "seed PQ ${SEED_HOST}:${PQ_PORT} OPEN — the channel every sync/snapshot/gossip runs over"
else
    die "Seed PQ port ${SEED_HOST}:${PQ_PORT} is BLOCKED (HTTP works, PQ doesn't)." \
        "This is the #1 silent first-join failure: your node would boot clean and then sit" \
        "at peers_connected:0 forever — all sync runs over PQ and there is no HTTP fallback." \
        "Nothing was written. Tell the operator the PQ port (HTTP+100) isn't reachable;" \
        "if the seed is a Tailscale node, both ports bind 0.0.0.0 so it's a tailnet/share issue."
fi

# ── Ground-truth cross-check: does the seed agree with your triple? ──────────
echo
echo "${c_bold}── Cross-checking your triple against what the seed actually reports ───${c_off}"
json_field() { # json_field <key>  — string or bare number, no jq needed
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$STATUS_JSON" | jq -r --arg k "$1" '.[$k] // empty' 2>/dev/null
    else
        printf '%s' "$STATUS_JSON" \
          | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" \
          | head -1 | sed -E "s/\"$1\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"$//"
    fi
}
SEED_AUTH="$(json_field genesis_authority | tr 'A-F' 'a-f')"
SEED_NET="$(json_field network_id)"
SEED_ZC="$(json_field zone_count)"
SEED_EPOCH="$(json_field current_epoch)"

# genesis_authority is your TRUST ANCHOR — it must come from the operator, never
# from the seed. We don't auto-adopt the seed's value; we STOP if they disagree,
# because a mismatch is either your typo or a seed that isn't the realm you think.
if [ -n "$SEED_AUTH" ] && [ "$SEED_AUTH" != "$AUTH_LC" ]; then
    die "AUTHORITY-HASH MISMATCH — your value is not what this seed reports." \
        "you entered : ${AUTH_LC}" \
        "seed reports: ${SEED_AUTH}" \
        "Stopping. Either you have a typo, or this seed is not the realm the operator named." \
        "Re-confirm the hash with the operator out-of-band before joining (don't just trust the seed)."
fi
[ -n "$SEED_AUTH" ] && ok "authority hash matches the seed's self-report" \
    || warn "seed didn't expose genesis_authority to cross-check (using your operator value)"

if [ -n "$SEED_NET" ] && [ "$SEED_NET" != "$NET" ]; then
    die "NETWORK-ID MISMATCH — your '${NET}' ≠ the seed's '${SEED_NET}'." \
        "The handshake rejects on network_id mismatch, so this would fail at first contact." \
        "Use the operator's realm name exactly. Stopping (nothing written)."
fi
[ -n "$SEED_NET" ] && ok "network id matches the seed (${NET})"

# zone_count IS safe to read from the seed (JOIN-DEVNET.md §3 endorses it).
if [[ "$SEED_ZC" =~ ^[0-9]+$ ]] && [ "$SEED_ZC" -ge 1 ]; then
    ZC="$SEED_ZC"
    ok "zone_count read live from the seed: ${ZC} (pinning it — topology, not a preference)"
else
    ZC="1"
    warn "couldn't read zone_count from the seed; defaulting to 1 (today's value) — confirm with the operator"
fi
[ -n "$SEED_EPOCH" ] && info "seed is live at epoch ${SEED_EPOCH} (it's advancing, good)"

# ── Write the config ─────────────────────────────────────────────────────────
echo
echo "${c_bold}── Writing your node config ────────────────────────────────────────────${c_off}"
if [ -e "$OUT" ] && [ "$FORCE" -ne 1 ]; then
    die "$OUT already exists — refusing to overwrite." \
        "Re-run with --force to replace it, or pass --out <other-path>."
fi
SETUP_DATE="$(date -u '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo 'setup time')"
cat > "$OUT" <<EOF || die "couldn't write $OUT (check directory permissions)."
# elara-node.toml — generated by scripts/init-join.sh on ${SETUP_DATE}.
# Joining realm "${NET}" via seed ${SEED_HOST}:${SEED_PORT}.
# Every value below was verified live against the seed at setup time. Only edit
# if the operator gives you NEW values — and re-run init-join.sh if you change
# the seed, so reachability is re-proved.
network_id        = "${NET}"
genesis_authority = "${AUTH_LC}"   # your trust anchor — from the operator, cross-checked vs the seed
seed_peers        = ["${SEED_HOST}:${SEED_PORT}"]
node_type         = "witness"
auto_witness      = true
zone_count        = ${ZC}            # network topology, read live from the seed — pin, do not set 0
data_dir          = "./data"
dns_seeds         = []             # no public DNS seed yet — silences the benign fallback warn
listen_addr       = "0.0.0.0:${HTTP_PORT}"  # your node's HTTP/public port (PQ auto-binds at +100; data-plane stays on loopback :9472)
# Outbound-only is fine (NAT/WSL2): a follower connects out to the seed and needn't be inbound-reachable.
EOF
ok "wrote ${OUT}"

# ── Done — tell them exactly what to run next ────────────────────────────────
echo
echo "${c_green}${c_bold}✓ READY TO BUILD.${c_off} The seed is reachable on both ports and your config agrees with it."
echo
echo "${c_bold}NEXT — build, create your identity, boot (run from the repo root):${c_off}"
echo "  cargo build --release --features node            ${c_dim}# ~10-20 min first time${c_off}"
echo "  ${c_dim}# optional but recommended — encrypt your key at rest before creating it:${c_off}"
echo "  export ELARA_IDENTITY_PASSPHRASE='<a strong passphrase you won't lose>'"
echo "  ./target/release/elara-node --config ${OUT} --generate-identity   ${c_dim}# PoW, ~30-90 s${c_off}"
echo "  ./target/release/elara-node --config ${OUT}                       ${c_dim}# boot + sync${c_off}"
echo
echo "${c_bold}THEN — watch yourself sync (green = you're in), and get staked:${c_off}"
echo "  until scripts/check-my-join.sh http://localhost:${HTTP_PORT} http://${SEED_HOST}:${SEED_PORT}; do sleep 15; done"
echo "  ${c_dim}# send the operator your identity hash so they can stake you:${c_off}"
echo "  curl -s http://localhost:${HTTP_PORT}/status | grep -o '\"identity_hash\":\"[^\"]*\"'"
echo
