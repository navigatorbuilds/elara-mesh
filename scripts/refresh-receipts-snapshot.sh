#!/usr/bin/env bash
# refresh-receipts-snapshot.sh — regenerate site/receipts.json (the maintainer's
# public receipts feed) from the local node's PUBLIC mandate-acts routes.
#
# Receipts model (dogfood):
#   human principal --issues on-mesh--> maintainer MANDATE --covers--> agent acts
#   Every commit/deploy the AI maintainer performs is emitted as an agent_audit
#   record carrying --mandate-ref <MANDATE_ID>. The PUBLIC routes
#   /mandate/{id}/acts + /mandate/status/{record_id} + /record/{id} make the
#   feed independently checkable from ANY mesh node — this script only
#   AGGREGATES that public data into a static site/receipts.json so the
#   GitHub Pages site (static hosting, no mesh access) can render it.
#   The snapshot is a convenience copy, NOT a trust root: the page tells
#   readers how to check every row against the mesh and offline elara-verify.
#
#   (The by-AGENT enumeration /agent/{hash}/acts stays loopback-only by design —
#   deanon surface. The by-MANDATE feed is the deliberate public disclosure.)
#
# NO-OP until ELARA_MAINTAINER_MANDATE is set: the dedicated maintainer
# identity + mandate are minted at public genesis (post re-genesis,
# operator-supervised). The mandate's scope must cover the emitted action
# values ("commit", "deploy") — scopes match exact-and-lowercase on the
# action axis; check yours with GET /mandate/{mandate_id}.
#
# Env:
#   ELARA_MAINTAINER_MANDATE  mandate_id of the maintainer mandate (required)
#   ELARA_NODE_DATAPLANE      default http://127.0.0.1:9472
#   RECEIPTS_LIMIT            max acts in the snapshot (default 50)
#   RECEIPTS_OUT              default <repo>/site/receipts.json

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ELARA_NODE_DATAPLANE:-http://127.0.0.1:9472}"
LIMIT="${RECEIPTS_LIMIT:-50}"
OUT="${RECEIPTS_OUT:-$REPO_DIR/site/receipts.json}"
MANDATE="${ELARA_MAINTAINER_MANDATE:-}"

if [[ -z "$MANDATE" ]]; then
    echo "receipts: ELARA_MAINTAINER_MANDATE not set — maintainer mandate not minted yet (post-genesis step). Nothing to do."
    exit 0
fi

ACTS_JSON="$(curl -sf --max-time 15 "$NODE/mandate/$MANDATE/acts?limit=$LIMIT")" || {
    echo "receipts: FAILED to fetch $NODE/mandate/$MANDATE/acts — node down or route error. Snapshot left unchanged." >&2
    exit 1
}

TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

# NOTE: acts page goes in via env (NOT stdin — the heredoc IS python's stdin).
if ! ACTS_JSON="$ACTS_JSON" NODE="$NODE" MANDATE="$MANDATE" TMP_OUT="$TMP" \
    python3 <<'PYEOF'
import json, os, subprocess, sys, datetime

node = os.environ["NODE"]
mandate = os.environ["MANDATE"]
tmp = os.environ["TMP_OUT"]
acts_page = json.loads(os.environ["ACTS_JSON"])

# The route answers 200 with an "error" field for unknown/malformed mandates —
# that is NOT a feed, refuse to write a snapshot for it.
if acts_page.get("error"):
    print(f"receipts: route error for mandate {mandate}: {acts_page['error']}",
          file=sys.stderr)
    sys.exit(1)

def fetch(url):
    try:
        raw = subprocess.run(
            ["curl", "-sf", "--max-time", "10", url],
            capture_output=True, timeout=15,
        ).stdout
        return json.loads(raw) if raw else None
    except Exception:
        return None

entries = []
for item in acts_page.get("acts") or []:
    rid = item if isinstance(item, str) else (item.get("record_id") or item.get("id") or "")
    if not rid:
        continue
    entry = {"record_id": rid}
    detail = fetch(f"{node}/record/{rid}")
    if isinstance(detail, dict):
        rec = detail.get("record", detail)
        meta = rec.get("metadata") or {}
        for k in ("tool", "action", "args_hash", "agent_id", "session_id", "kind", "mandate_ref"):
            if k in meta:
                entry[k] = meta[k]
        for k in ("timestamp", "created_at", "epoch", "zone"):
            if k in rec:
                entry[k] = rec[k]
        if "content_hash" in rec:
            entry["content_hash"] = rec["content_hash"]
    status = fetch(f"{node}/mandate/status/{rid}")
    if isinstance(status, dict):
        entry["mandate_status"] = status.get("status") or status.get("verdict") or status
    entries.append(entry)

snapshot = {
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mandate_id": mandate,
    "authoritative_complete": bool(acts_page.get("authoritative_complete", False)),
    "count": len(entries),
    "acts": entries,
    "note": ("Static convenience snapshot of the PUBLIC mandate-acts feed. "
             "Not a trust root: check any row against a mesh node via "
             "/record/{record_id} and /mandate/status/{record_id}, or fully "
             "offline with elara-verify."),
}
with open(tmp, "w") as f:
    json.dump(snapshot, f, indent=1, sort_keys=True)
    f.write("\n")
print(f"receipts: {len(entries)} acts aggregated")
PYEOF
then
    echo "receipts: snapshot build FAILED — $OUT left unchanged." >&2
    exit 1
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "receipts: wrote $OUT"
