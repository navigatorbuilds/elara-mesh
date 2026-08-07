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
#   RECEIPTS_VERIFY_N         newest N acts ALSO get a browser-verifiable
#                             .elara-receipt v1 envelope (record+seal wire, hex)
#                             + a pins file harvested into site/receipts/
#                             (default 8; bounded — files outside the window
#                             are deleted each refresh). Every envelope is
#                             re-verified with elara-verify BEFORE it ships;
#                             a non-VERIFIED envelope is discarded, never linked.

set -u

# Canonical arming env (mandate id + network). Sourced FIRST so a non-interactive
# run (cron/CI, which skips ~/.bashrc) doesn't silently no-op with a stale
# snapshot reported as success — the same reason the git hook sources it.
# A caller-set ELARA_MAINTAINER_MANDATE still wins (only fills unset vars).
[[ -f "$HOME/.elara/receipts.env" ]] && . "$HOME/.elara/receipts.env"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="${ELARA_NODE_DATAPLANE:-http://127.0.0.1:9472}"
LIMIT="${RECEIPTS_LIMIT:-50}"
OUT="${RECEIPTS_OUT:-$REPO_DIR/site/receipts.json}"
MANDATE="${ELARA_MAINTAINER_MANDATE:-}"
VERIFY_N="${RECEIPTS_VERIFY_N:-8}"
VERIFY_DIR="$(dirname "$OUT")/receipts"
DECODER="$REPO_DIR/examples/verify/decode_record.py"
VERIFY_BIN="$REPO_DIR/target/release/elara-verify"
ANCHOR_PK=""
[[ -f "$REPO_DIR/examples/verify/zone-0-anchor-pubkey.hex" ]] && \
    ANCHOR_PK="$(tr -d '[:space:]' < "$REPO_DIR/examples/verify/zone-0-anchor-pubkey.hex")"

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
    VERIFY_N="$VERIFY_N" VERIFY_DIR="$VERIFY_DIR" DECODER="$DECODER" \
    VERIFY_BIN="$VERIFY_BIN" ANCHOR_PK="$ANCHOR_PK" LIMIT="$LIMIT" \
    OUT_PATH="$OUT" \
    python3 <<'PYEOF'
import json, os, re, subprocess, sys, datetime, tempfile

node = os.environ["NODE"]
mandate = os.environ["MANDATE"]
tmp = os.environ["TMP_OUT"]
verify_n = max(0, int(os.environ.get("VERIFY_N") or "0"))
verify_dir = os.environ.get("VERIFY_DIR") or ""
decoder = os.environ.get("DECODER") or ""
verify_bin = os.environ.get("VERIFY_BIN") or ""
anchor_pk = os.environ.get("ANCHOR_PK") or ""
acts_page = json.loads(os.environ["ACTS_JSON"])

# The route answers 200 with an "error" field for unknown/malformed mandates —
# that is NOT a feed, refuse to write a snapshot for it.
if acts_page.get("error"):
    print(f"receipts: route error for mandate {mandate}: {acts_page['error']}",
          file=sys.stderr)
    sys.exit(1)

def fetch_bytes(url):
    try:
        r = subprocess.run(["curl", "-sf", "--max-time", "10", url],
                           capture_output=True, timeout=15)
        return r.stdout if (r.returncode == 0 and r.stdout) else None
    except Exception:
        return None

def fetch(url):
    raw = fetch_bytes(url)
    try:
        return json.loads(raw) if raw else None
    except Exception:
        return None

def decode_wire(wire):
    """record_hash + metadata via the independent reference decoder
    (examples/verify/decode_record.py). Its EXIT CODE compares the hash
    against the published conformance fixture — nonzero for any other
    record, so ignore it and parse stdout."""
    if not (decoder and os.path.isfile(decoder)):
        return None, None
    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".wire", delete=False) as t:
            t.write(wire)
            path = t.name
        out = subprocess.run(["python3", decoder, path],
                             capture_output=True, timeout=30, text=True).stdout
        rh = re.search(r"^\s*record_hash:\s*([0-9a-f]{64})\s*$", out, re.M)
        md = re.search(r"^\s*metadata:\s*(\{.*)$", out, re.M)
        meta = None
        if md:
            try:
                meta = json.loads(md.group(1))
            except Exception:
                meta = None
        return (rh.group(1) if rh else None), meta
    except Exception:
        return None, None
    finally:
        if path:
            try: os.unlink(path)
            except OSError: pass

# The acts feed is ASCENDING keyset-paginated (oldest first). A single
# `?limit=N` page is therefore the OLDEST N acts — so past N total acts the
# "Latest receipts" page would freeze on ancient rows and never show a new
# commit again. Page forward to the tail keeping only the newest LIMIT raw
# items in a bounded deque; enrichment (record/status/wire fetches) then runs
# ONLY on that window, never the whole history. O(total/limit) cheap loopback
# pages, memory O(limit). `next_from: null` ends the walk.
from collections import deque
limit = max(1, int(os.environ.get("LIMIT") or "50"))
window = deque(maxlen=limit)
auth_complete = True
page = acts_page
pages_walked = 0
MAX_PAGES = 10000  # backstop against a pathological/looping next_from
while True:
    for it in page.get("acts") or []:
        window.append(it)
    auth_complete = auth_complete and bool(page.get("authoritative_complete", False))
    nxt = page.get("next_from")
    pages_walked += 1
    if not nxt or pages_walked >= MAX_PAGES:
        break
    nextpage = fetch(f"{node}/mandate/{mandate}/acts?from={nxt}&limit={limit}")
    if not isinstance(nextpage, dict) or nextpage.get("error"):
        # Mid-walk fetch failure: stop with the newest-seen window rather than
        # write a torn snapshot. Mark not-authoritative so the page says so.
        auth_complete = False
        break
    page = nextpage
# Feed is oldest-first; emit newest-first for the page.
windowed_items = list(window)[::-1]

entries = []
wires = {}      # rid -> record wire bytes (for the harvest step)
seal_ids = {}   # rid -> covering seal record id
for item in windowed_items:
    rid = item if isinstance(item, str) else (item.get("record_id") or item.get("id") or "")
    if not rid:
        continue
    entry = {"record_id": rid}
    # The acts-feed item itself carries the authority verdict fields — lift
    # them so the page can render flag/authorized/time without extra fetches.
    if isinstance(item, dict):
        for k in ("flag", "authorized", "act_timestamp_ms", "mandate_ref", "scope_deferred"):
            if k in item:
                entry[k] = item[k]
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
        sp = rec.get("seal_progress") or {}
        if isinstance(sp, dict) and sp.get("seal_id"):
            seal_ids[rid] = sp["seal_id"]  # transient tracker — present only briefly post-seal
    # The /record route exposes metadata KEY NAMES only — the values live in
    # the wire bytes. Decode the wire (independent reference decoder) so rows
    # carry tool/action labels; the wire is reused by the harvest step below.
    if not entry.get("action"):
        wire = fetch_bytes(f"{node}/record/{rid}/wire")
        if wire:
            wires[rid] = wire
            _, meta = decode_wire(wire)
            if isinstance(meta, dict):
                for k in ("tool", "action", "args_hash", "agent_id", "session_id", "kind", "mandate_ref"):
                    if k in meta and k not in entry:
                        entry[k] = meta[k]
    status = fetch(f"{node}/mandate/status/{rid}")
    if isinstance(status, dict):
        entry["mandate_status"] = status.get("status") or status.get("verdict") or status
    entries.append(entry)

# ── Browser-verify harvest: newest N acts ship a real .elara-receipt v1 ──────
# envelope (record + covering seal, hex wire — the audited v1 format) plus a
# pins file (zone-0 anchor key + the seal's canonical record_hash). The page
# offers these as PREFILLS for the in-browser verifier; pins provenance is
# disclosed on the page and the reader can drop them and watch the verdict
# downgrade honestly. Every envelope is re-verified with elara-verify before
# it ships; anything not VERIFIED is discarded and the row simply carries no
# browser_verify flag (curl/CLI instructions still apply to it).
harvested = set()
if verify_n and verify_dir and anchor_pk and os.path.isfile(verify_bin):
    os.makedirs(verify_dir, exist_ok=True)
    # Durable per-zone seal lookup: /epochs serves the latest seal id + its
    # canonical record_hash per zone (seal_progress on the record detail is a
    # transient tracker that empties once the epoch moves on). The covering
    # seal id from seal_progress is used when still visible; otherwise the
    # zone's current seal rides as the chain-state leg — either way the
    # producer text discloses that record↔seal chain binding needs the
    # inclusion leg (not present) and the verifier grades that honestly.
    zone_seals = {}
    epochs = fetch(f"{node}/epochs")
    if isinstance(epochs, dict):
        for ep in epochs.get("epochs") or []:
            if isinstance(ep, dict) and ep.get("latest_seal_id"):
                zone_seals[str(ep.get("zone", "0"))] = (
                    ep["latest_seal_id"], ep.get("latest_seal_hash") or "")
    def ts(e):
        v = e.get("timestamp") or e.get("created_at") or 0
        return v if isinstance(v, (int, float)) else 0
    for entry in sorted(entries, key=ts, reverse=True)[:verify_n]:
        rid = entry["record_id"]
        zone = str(entry.get("zone", "0") or "0")
        seal_id = seal_ids.get(rid) or (zone_seals.get(zone) or (None, ""))[0]
        if not seal_id:
            continue
        wire = wires.get(rid) or fetch_bytes(f"{node}/record/{rid}/wire")
        seal_wire = fetch_bytes(f"{node}/record/{seal_id}/wire")
        if not (wire and seal_wire):
            continue
        seal_hash, _ = decode_wire(seal_wire)
        if not seal_hash:  # decoder unavailable → fall back to the route's hash
            seal_hash = (zone_seals.get(zone) or (None, ""))[1]
        if not seal_hash:
            continue
        envelope = {
            "receipt_version": 1,
            "producer": {"origin": (
                f"elara-mesh maintainer receipts feed — act {rid}; assembled "
                f"from /record/{{id}}/wire: the signed act record + an epoch "
                f"seal current at snapshot time (on today's single-zone mesh "
                f"that is the zone-0 seal; per-act zone resolution lands with "
                f"multi-zone). Record-to-seal chain binding needs the "
                f"inclusion leg, which this envelope does not carry — the "
                f"verifier grades that honestly. Self-declared, like every "
                f"producer field.")},
            "legs": {"record": wire.hex(), "seal": seal_wire.hex()},
        }
        pins = {"trusted_anchor": [anchor_pk], "expected_hash": seal_hash}
        rpath = os.path.join(verify_dir, f"{rid}.receipt.json")
        ppath = os.path.join(verify_dir, f"{rid}.pins.json")
        with open(rpath, "w") as f:
            json.dump(envelope, f, separators=(",", ":"))
            f.write("\n")
        with open(ppath, "w") as f:
            json.dump(pins, f, indent=1)
            f.write("\n")
        # Ship-gate: the exact envelope+pins FILES the page will offer must
        # grade VERIFIED (exit 0) with the same core the browser runs — or it
        # ships nothing (never a link whose happy path isn't proven). The pin
        # values are read BACK from the pins file just written, not from this
        # script's locals: the browser consumes the file, so a serialization
        # or key-shape drift in it must fail the gate, not ship silently.
        try:
            with open(ppath) as pf:
                pin_data = json.load(pf)
            ok = subprocess.run(
                [verify_bin, "--receipt", rpath,
                 "--trusted-anchor", pin_data["trusted_anchor"][0],
                 "--expected-hash", pin_data["expected_hash"]],
                capture_output=True, timeout=60,
            ).returncode == 0
        except Exception:
            ok = False
        if ok:
            entry["browser_verify"] = True
            harvested.add(rid)
        else:
            for p in (rpath, ppath):
                try: os.unlink(p)
                except OSError: pass
            print(f"receipts: envelope for {rid} did not grade VERIFIED — not shipped",
                  file=sys.stderr)
elif verify_n:
    print("receipts: browser-verify harvest skipped "
          f"(dir={bool(verify_dir)} anchor={bool(anchor_pk)} "
          f"elara-verify={os.path.isfile(verify_bin)})", file=sys.stderr)

# ── Cumulative archive merge (2026-07-14, publish-day finding) ──────────────
# The node hot-tier GC prunes finalized records past retention, and
# delete_record drops the mandate-act entry + both reverse indexes in LOCKSTEP
# (rocks.rs C4 slices 1/4: acts are ordinary GC-eligible records) — so the
# LIVE /mandate/{id}/acts feed self-empties as acts age into sealed history.
# Rows already published in the committed snapshot must never vanish from the
# public page: merge prior rows back in (by record_id) marked archived:true,
# and keep their envelope files — the envelopes are self-contained and verify
# offline forever; only the live-node curl path ages out. The page renders
# archived rows with an honest "sealed history / offline check" block instead
# of dead curl instructions. Node-side acts-permanence fix (make act entries
# a GC-exempt class) is a QUEUED design item — audit before building.
live_ids = {e["record_id"] for e in entries}
prior_acts = []
out_path = os.environ.get("OUT_PATH") or ""
if out_path and os.path.isfile(out_path):
    try:
        with open(out_path) as f:
            prior_acts = json.load(f).get("acts") or []
    except Exception as e:
        # A torn/unreadable prior snapshot must not silently shrink the feed.
        print(f"receipts: prior snapshot at {out_path} unreadable ({e}) — "
              "refusing to overwrite it with a merge-less snapshot", file=sys.stderr)
        sys.exit(1)
archived_n = 0
for a in prior_acts:
    rid = a.get("record_id")
    if not rid or rid in live_ids:
        continue
    a["archived"] = True
    if a.get("browser_verify"):
        # The flag survives only while its envelope pair is still on disk.
        if (verify_dir
                and os.path.isfile(os.path.join(verify_dir, f"{rid}.receipt.json"))
                and os.path.isfile(os.path.join(verify_dir, f"{rid}.pins.json"))):
            harvested.add(rid)  # protect the pair from the deletion pass below
        else:
            a.pop("browser_verify", None)
    entries.append(a)
    archived_n += 1

def _sort_ms(e):
    v = e.get("act_timestamp_ms") or 0
    if not v:
        t = e.get("timestamp") or 0
        v = t * 1000 if isinstance(t, (int, float)) else 0
    return v
entries.sort(key=_sort_ms, reverse=True)

# Bounded window: drop harvested files whose act left the newest-N set AND is
# not a protected archived row. Runs even when the harvest branch above was
# SKIPPED: a skipped harvest writes no browser_verify flags into this snapshot,
# so files left on disk are envelopes the page no longer references — dead
# weight the mirror would keep shipping (and a stale-envelope trap if a reader
# deep-links one). Snapshot flags and on-disk files must leave this script
# consistent on every path.
if verify_dir and os.path.isdir(verify_dir):
    for fn in os.listdir(verify_dir):
        m = re.match(r"^([0-9a-f-]+)\.(receipt|pins)\.json$", fn)
        if m and m.group(1) not in harvested:
            try: os.unlink(os.path.join(verify_dir, fn))
            except OSError: pass

snapshot = {
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mandate_id": mandate,
    "authoritative_complete": auth_complete,
    "count": len(entries),
    "archived_count": archived_n,
    "acts": entries,
    "note": ("Static convenience snapshot of the PUBLIC mandate-acts feed. "
             "Not a trust root: check any live row against a mesh node via "
             "/record/{record_id} and /mandate/status/{record_id}, or fully "
             "offline with elara-verify. Rows marked archived have aged out "
             "of the node's bounded hot tier (records prune into sealed "
             "history by design) — the live routes no longer serve them; "
             "their offline envelopes, where present, remain verifiable."),
}
with open(tmp, "w") as f:
    json.dump(snapshot, f, indent=1, sort_keys=True)
    f.write("\n")
print(f"receipts: {len(entries)} acts aggregated ({archived_n} archived)")
PYEOF
then
    echo "receipts: snapshot build FAILED — $OUT left unchanged." >&2
    exit 1
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "receipts: wrote $OUT"
