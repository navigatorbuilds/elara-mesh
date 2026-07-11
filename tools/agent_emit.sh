#!/usr/bin/env bash
# agent_emit.sh — PostToolUse hook wrapper for agent action audit trails.
#
# Called by Claude Code's PostToolUse hook with a JSON payload on stdin:
#   {"tool_name": "...", "tool_input": {...}, "tool_response": {...}, ...}
#
# Extracts the tool name + a SHA3-256 hash of the input, then fires
# `elara-cli agent-emit` in the background so the hook returns instantly
# (must be sub-100ms to avoid slowing the agent).
#
# Record is submitted to the local elara-node on https://127.0.0.1:9474
# with metadata `{kind:"agent_audit", tool, action, args_hash, agent_id}`.
#
# Failures are silently swallowed — this hook MUST NOT block the agent.
# View emitted acts (when emitted with --mandate-ref; on-box data plane):
#   curl -s http://127.0.0.1:9472/mandate/<mandate_id>/acts
# or a single record from any node: curl <node>/record/<record_id>

set -u

# Default CLI path is repo-relative (this script lives in <repo>/tools/);
# override with ELARA_CLI for out-of-tree installs.
_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${ELARA_CLI:-$_REPO_DIR/target/release/elara-cli}"
NODE="${ELARA_NODE:-https://127.0.0.1:9474}"
IDENTITY="${ELARA_IDENTITY:-$HOME/.elara/identity.json}"
AGENT_ID="${ELARA_AGENT_ID:-claude-code}"

# Hook disabled unless the binary + identity exist. No-op on clean checkouts.
[[ -x "$CLI" ]] || exit 0
[[ -f "$IDENTITY" ]] || exit 0

# Read the hook JSON from stdin (non-blocking fallback if no stdin available).
PAYLOAD=""
if [ ! -t 0 ]; then
    PAYLOAD="$(cat)"
fi

# Extract tool name — fall back to "unknown" rather than fail.
TOOL="unknown"
if [[ -n "$PAYLOAD" ]]; then
    TOOL="$(printf '%s' "$PAYLOAD" | python3 -c 'import sys,json
try:
    d = json.loads(sys.stdin.read())
    print(d.get("tool_name") or d.get("tool") or "unknown")
except Exception:
    print("unknown")
' 2>/dev/null || echo unknown)"
fi

# SHA3-256 hash of the full payload as the args_hash.
# Python hashlib.sha3_256 is available since 3.6; zero external deps.
ARGS_HASH="$(printf '%s' "$PAYLOAD" | python3 -c 'import sys,hashlib
print(hashlib.sha3_256(sys.stdin.buffer.read()).hexdigest())' 2>/dev/null)"
[[ -n "$ARGS_HASH" ]] || ARGS_HASH="0000000000000000000000000000000000000000000000000000000000000000"

# Session id from env var if the agent surface exposes one.
SESSION_ARG=()
if [[ -n "${CLAUDE_SESSION_ID:-}" ]]; then
    SESSION_ARG=(--session-id "${CLAUDE_SESSION_ID}")
fi

# Fire in background — emit is fire-and-forget. nohup + disown so the
# hook returns immediately even if the node is slow.
(
    ELARA_TLS_INSECURE=true "$CLI" \
        --node "$NODE" \
        agent-emit \
        --identity "$IDENTITY" \
        --tool "$TOOL" \
        --action post \
        --args-hash "$ARGS_HASH" \
        --agent-id "$AGENT_ID" \
        --quiet \
        "${SESSION_ARG[@]}" \
        >/dev/null 2>&1
) &
disown 2>/dev/null || true

exit 0
