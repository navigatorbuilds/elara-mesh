#!/usr/bin/env bash
# install-receipt-hooks.sh — install the git post-commit hook that receipts
# every commit on the mesh (dogfood).
#
# The hook is a strict no-op (instant exit 0) until ALL THREE exist:
#   1. target/release/elara-cli            (built with --features node)
#   2. $ELARA_RECEIPTS_IDENTITY            (default ~/.elara/maintainer-identity.json —
#                                           the DEDICATED non-staker maintainer identity,
#                                           minted at public genesis)
#   3. $ELARA_MAINTAINER_MANDATE           (mandate_id of the maintainer mandate;
#                                           its scope must cover action "commit" —
#                                           scopes match exact-and-lowercase;
#                                           inspect via GET /mandate/{mandate_id})
# so installing it today is safe on any checkout.
#
# Binding: args_hash = SHA3-256(full 40-char commit sha). Anyone can recompute
# it from the public repo — see site/receipts.html "Check a receipt yourself".
# Emission is backgrounded + silently swallowed on failure: the hook MUST
# never block or fail a commit.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$REPO_DIR/.git/hooks/post-commit"
MARKER="# elara-receipt-hook v1"

if [[ -f "$HOOK" ]] && ! grep -q "$MARKER" "$HOOK"; then
    echo "REFUSING: $HOOK exists and is not the elara receipt hook." >&2
    echo "Merge manually — the receipt block is idempotent and self-guarding:" >&2
    echo "append the body of this installer's heredoc to your existing hook." >&2
    exit 1
fi

cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# elara-receipt-hook v1 — receipt this commit on the mesh (best-effort).
# No-op unless CLI + maintainer identity + mandate are all present.
set -u
REPO_DIR="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
CLI="$REPO_DIR/target/release/elara-cli"
# Durable env (mandate id, network id): git hooks run in whatever shell state
# the committer had — often WITHOUT ~/.bashrc exports (non-interactive shells
# return early). ~/.elara/receipts.env is the canonical source; shell exports
# still win when present.
[[ -f "$HOME/.elara/receipts.env" ]] && . "$HOME/.elara/receipts.env"
IDENTITY="${ELARA_RECEIPTS_IDENTITY:-$HOME/.elara/maintainer-identity.json}"
MANDATE="${ELARA_MAINTAINER_MANDATE:-}"
[[ -x "$CLI" && -f "$IDENTITY" && -n "$MANDATE" ]] || exit 0
SHA="$(git rev-parse HEAD 2>/dev/null)" || exit 0
AH="$(printf '%s' "$SHA" | python3 -c 'import sys,hashlib;print(hashlib.sha3_256(sys.stdin.buffer.read()).hexdigest())' 2>/dev/null)" || exit 0
# --node must be explicit: the CLI's built-in default (localhost:9473) is NOT
# this machine's node port. ELARA_NETWORK_ID rides via the CLI's env fallback.
NODE_URL="${ELARA_NODE:-http://127.0.0.1:9474}"
(
    "$CLI" --node "$NODE_URL" agent-emit \
        --identity "$IDENTITY" \
        --tool git \
        --action commit \
        --args-hash "$AH" \
        --agent-id elara-maintainer \
        --mandate-ref "$MANDATE" \
        --quiet \
        >/dev/null 2>&1
) &
disown 2>/dev/null || true
exit 0
HOOKEOF

chmod +x "$HOOK"
echo "installed: $HOOK (inert until maintainer identity + mandate exist)"
