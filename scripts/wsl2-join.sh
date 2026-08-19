#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# wsl2-join.sh — the WSL2-on-Windows on-ramp that sits in FRONT of
# scripts/init-join.sh.
#
# A node running inside WSL2 is NAT'd to an internal 172.x vSwitch IP that is
# invisible off-box, and Win11's firewall blocks all inbound — so the laptop
# being powered on does NOT make the node reachable. The fix is to give the
# WSL2 guest a stable identity on the operator's tailnet (Tailscale), after
# which it is a first-class follower that connects OUT to the seed (outbound-
# only is fine — init-join.sh writes exactly that config).
#
# This script does the three WSL2-specific things that trip people up, then
# hands the triple straight to init-join.sh:
#   1. Installs Tailscale and starts tailscaled in --tun=userspace-networking
#      mode — the WSL2-safe path that does NOT need /dev/net/tun (which WSL2
#      lacks). Works whether or not the distro has systemd enabled.
#   2. `tailscale up` (this is the ONE manual gate — open the printed URL once).
#   3. Re-uses init-join.sh verbatim for the real join: triple validation,
#      both-ports reachability proof, and a correct elara-node.toml.
#
# It bakes in NO operator addresses or hashes — you pass the triple as args, so
# this file is generic on-ramp tooling (mirror-safe, reusable for any WSL2 join).
#
# Usage (run INSIDE the WSL2 Ubuntu shell, from the repo root):
#   scripts/wsl2-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID> [--http-port N] [--force]
#     e.g. scripts/wsl2-join.sh 100.x.y.z:9474 <64-hex-hash> testnet
#
# Exit 0 = on the tailnet, seed reachable, config written → ready to build.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

c_green=$'\033[32m'; c_red=$'\033[31m'; c_yellow=$'\033[33m'; c_dim=$'\033[2m'; c_bold=$'\033[1m'; c_off=$'\033[0m'
ok()   { echo "  ${c_green}✓${c_off} $1"; }
bad()  { echo "  ${c_red}✗${c_off} $1"; }
warn() { echo "  ${c_yellow}…${c_off} $1"; }
info() { echo "  ${c_dim}·${c_off} $1"; }
die()  { echo; echo "${c_red}✗ $1${c_off}"; shift; for l in "$@"; do echo "    $l"; done; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ $# -ge 3 ] || die "need the operator's triple." \
    "usage: scripts/wsl2-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID> [--http-port N] [--force]" \
    "e.g.   scripts/wsl2-join.sh 100.x.y.z:9474 <64-hex-hash> testnet"
SEED_RAW="$1"; AUTH="$2"; NET="$3"; shift 3
INIT_EXTRA=("$@")   # passes through --http-port / --force / --out to init-join.sh

# ── 0. Sanity: are we actually in WSL2? (not fatal — just informs the path) ──
echo
echo "${c_bold}── WSL2 on-ramp ────────────────────────────────────────────────────────${c_off}"
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
    ok "running inside WSL ($(grep -oiE 'wsl[0-9]*' /proc/version | head -1 || echo wsl))"
else
    warn "this doesn't look like WSL — script still works, but you may not need the userspace-networking path."
fi

# ── 1. Install Tailscale if missing ──────────────────────────────────────────
if command -v tailscale >/dev/null 2>&1; then
    ok "tailscale already installed ($(tailscale version 2>/dev/null | head -1))"
else
    warn "installing Tailscale (curl | sh from tailscale.com) …"
    curl -fsSL https://tailscale.com/install.sh | sh || die "Tailscale install failed." \
        "Install it by hand, then re-run:  curl -fsSL https://tailscale.com/install.sh | sh"
    ok "tailscale installed"
fi

# ── 2. Ensure tailscaled is running (WSL2-safe userspace-networking mode) ────
daemon_up() { tailscale status >/dev/null 2>&1 || tailscale status 2>&1 | grep -qiE 'logged out|stopped|NeedsLogin'; }
if daemon_up; then
    ok "tailscaled is already running"
else
    # Prefer systemd if the distro actually has it running; else userspace daemon.
    if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
        sudo systemctl enable --now tailscaled >/dev/null 2>&1 || true
        sleep 2
    fi
    if ! daemon_up; then
        warn "starting tailscaled in userspace-networking mode (the WSL2 path — no /dev/net/tun needed) …"
        sudo mkdir -p /var/lib/tailscale /var/run/tailscale 2>/dev/null || true
        sudo nohup tailscaled \
            --tun=userspace-networking \
            --state=/var/lib/tailscale/tailscaled.state \
            --socket=/var/run/tailscale/tailscaled.sock \
            >/tmp/tailscaled.log 2>&1 &
        for _ in $(seq 1 10); do daemon_up && break; sleep 1; done
    fi
    daemon_up && ok "tailscaled is up" || die "tailscaled didn't come up." \
        "Check /tmp/tailscaled.log, then re-run. (You may need: sudo tailscaled --tun=userspace-networking &)"
fi

# ── 3. tailscale up — the one manual gate ────────────────────────────────────
# `tailscale status` exits 0 only when the daemon is up AND this node is logged
# in to a tailnet — the reliable "already joined" signal (don't parse its text,
# which carries extra health/version lines that fool a grep).
if tailscale status >/dev/null 2>&1; then
    TS_IP="$(tailscale ip -4 2>/dev/null | head -1)"
    ok "already on the tailnet${TS_IP:+ as ${TS_IP}}"
else
    echo
    echo "${c_bold}${c_yellow}── ACTION NEEDED: authenticate to the tailnet ──${c_off}"
    echo "  A login URL will print below. Open it in any browser, approve this machine,"
    echo "  then come back here — the script continues automatically."
    echo
    sudo tailscale up || die "tailscale up failed / was not completed." \
        "Re-run this script once you've approved the machine in the Tailscale admin console."
    TS_IP="$(tailscale ip -4 2>/dev/null | head -1)"
    [ -n "$TS_IP" ] && ok "on the tailnet as ${TS_IP}" || warn "couldn't read tailnet IP yet (continuing — init-join will prove reachability)"
fi

# ── 4. Hand off to the canonical joiner (proves both ports, writes config) ───
echo
echo "${c_bold}── Handing off to init-join.sh (validate triple + prove seed + write config) ─${c_off}"
[ -x "${SCRIPT_DIR}/init-join.sh" ] || die "init-join.sh not found next to this script." \
    "Run from a full clone of the repo (scripts/init-join.sh must exist)."
"${SCRIPT_DIR}/init-join.sh" "$SEED_RAW" "$AUTH" "$NET" "${INIT_EXTRA[@]}"
