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
#   RECEIPTS_VERIFY_N         newest N acts get a freshly-minted browser-verifiable
#                             .elara-receipt v1 envelope (record+seal wire, hex)
#                             + a pins file harvested into site/receipts/
#                             (default 8). Coverage is CUMULATIVE (2026-08-09,
#                             queue R4): pairs minted by prior runs persist for
#                             as long as their row stays in the snapshot, and
#                             rows without a pair get a bounded backfill mint
#                             while the node still serves their wire; only
#                             files for rids absent from the snapshot are
#                             deleted. Every envelope is re-verified with
#                             elara-verify BEFORE it ships; a non-VERIFIED
#                             envelope is discarded, never linked.
#   RECEIPTS_BACKFILL_MAX     per-run cap on backfill mints (default 400) —
#                             a backstop; steady-state backfill work is only
#                             acts the newest-N harvest missed between runs.

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
VERIFY_BIN="${RECEIPTS_VERIFY_BIN:-$REPO_DIR/target/release/elara-verify}"
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

# T94 (2026-08-20): the public feed is the UNION of the maintainer mandate (human-facing
# acts) and the build mandate (commit/deploy bookkeeping, build-agent identity). The union
# happens INSIDE the pagination walker below — both chains are walked to their tails and
# the newest LIMIT across BOTH survive (a bash-level first-page merge gets evicted by the
# walker's deque; found in anger 2026-08-20). Build-chain fetch failure is fail-CLOSED
# there: no partial feed that silently drops commit rows.

TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

# NOTE: acts page goes in via env (NOT stdin — the heredoc IS python's stdin).
if ! ACTS_JSON="$ACTS_JSON" NODE="$NODE" MANDATE="$MANDATE" BUILD_MANDATE="${ELARA_BUILD_MANDATE:-}" TMP_OUT="$TMP" \
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
# Coverage-active: the ONE predicate for minting/adopting envelope pairs.
# Hoisted 2026-08-19 (fusion-audit fix): the membership-bound deletion pass
# near the end MUST share this exact predicate. Before the hoist, a missing
# elara-verify binary skipped harvest+backfill (leaving `harvested` empty)
# while the deletion pass still ran — unlinking every previously-published
# pair (measured: −100 files, 86 git-tracked/public, exit 0, feed count
# still growing). Skipped coverage now PRESERVES existing pairs; the next
# healthy run re-adopts them for free via the persisted-pair branch.
coverage_active = bool(verify_n and verify_dir and anchor_pk
                       and os.path.isfile(verify_bin))
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

def fetch_bytes_code(url):
    """fetch_bytes plus the HTTP status — the backfill needs to tell a
    definitive 404 (row pruned; cache the negative) from a transient
    failure (mark nothing, retry next run)."""
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".dl")
        os.close(fd)
        r = subprocess.run(["curl", "-s", "-o", path, "-w", "%{http_code}",
                            "--max-time", "10", url],
                           capture_output=True, timeout=15, text=True)
        if r.returncode != 0:
            return None, 0
        code = int((r.stdout or "").strip() or 0)
        if code == 200:
            with open(path, "rb") as f:
                data = f.read()
            return (data if data else None), code
        return None, code
    except Exception:
        return None, 0
    finally:
        if path:
            try: os.unlink(path)
            except OSError: pass

def producer_origin(rid):
    return (
        f"elara-mesh maintainer receipts feed — act {rid}; assembled "
        f"from /record/{{id}}/wire: the signed act record + an epoch "
        f"seal current at snapshot time (on today's single-zone mesh "
        f"that is the zone-0 seal; per-act zone resolution lands with "
        f"multi-zone). Record-to-seal chain binding needs the "
        f"inclusion leg, which this envelope does not carry — the "
        f"verifier grades that honestly. Self-declared, like every "
        f"producer field.")

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
MAX_PAGES = 10000  # backstop against a pathological/looping next_from

def walk_mandate(mid, first_page):
    """Walk one mandate's acts feed to its tail; return (newest-limit items, complete)."""
    w = deque(maxlen=limit)
    complete = True
    page = first_page
    pages_walked = 0
    while True:
        for it in page.get("acts") or []:
            w.append(it)
        complete = complete and bool(page.get("authoritative_complete", False))
        nxt = page.get("next_from")
        pages_walked += 1
        if not nxt or pages_walked >= MAX_PAGES:
            break
        nextpage = fetch(f"{node}/mandate/{mid}/acts?from={nxt}&limit={limit}")
        if not isinstance(nextpage, dict) or nextpage.get("error"):
            # Mid-walk fetch failure: stop with the newest-seen window rather than
            # write a torn snapshot. Mark not-authoritative so the page says so.
            complete = False
            break
        page = nextpage
    return list(w), complete

maint_items, auth_complete = walk_mandate(mandate, acts_page)

# T94: union the build mandate's chain (commit/deploy bookkeeping). Fail-CLOSED on a
# missing first page — a feed written without the build chain silently drops every
# commit row, the exact regression the T94 audit forbade.
build_mandate = os.environ.get("BUILD_MANDATE") or ""
build_items = []
if build_mandate:
    bpage = fetch(f"{node}/mandate/{build_mandate}/acts?limit={limit}")
    if not isinstance(bpage, dict) or bpage.get("error"):
        print(f"receipts: FAILED to fetch build-mandate acts — refusing partial feed",
              file=sys.stderr)
        sys.exit(1)
    build_items, bcomplete = walk_mandate(build_mandate, bpage)
    auth_complete = auth_complete and bcomplete

# Merge both chains, keep the newest `limit` overall, emit newest-first for the page.
merged = maint_items + build_items
merged.sort(key=lambda it: (it.get("act_timestamp_ms") or 0) if isinstance(it, dict) else 0)
windowed_items = merged[-limit:][::-1]

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
if coverage_active:
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
            "producer": {"origin": producer_origin(rid)},
            "legs": {"record": wire.hex(), "seal": seal_wire.hex()},
        }
        pins = {"trusted_anchor": [anchor_pk], "expected_hash": seal_hash}
        rpath = os.path.join(verify_dir, f"{rid}.receipt.json")
        ppath = os.path.join(verify_dir, f"{rid}.pins.json")
        # Mint to TEMP, gate, then atomically replace (2026-08-19 fusion-audit
        # fix): writing the live paths first meant a present-but-FAILING
        # verifier overwrote a previously-good published pair and then
        # unlinked it (measured: the 8 newest pairs destroyed). A failing
        # gate must leave the prior pair untouched.
        rtmp, ptmp = rpath + ".tmp", ppath + ".tmp"
        with open(rtmp, "w") as f:
            json.dump(envelope, f, separators=(",", ":"))
            f.write("\n")
        with open(ptmp, "w") as f:
            json.dump(pins, f, indent=1)
            f.write("\n")
        # Ship-gate: the exact envelope+pins FILES the page will offer must
        # grade VERIFIED (exit 0) with the same core the browser runs — or it
        # ships nothing (never a link whose happy path isn't proven). The pin
        # values are read BACK from the pins file just written, not from this
        # script's locals: the browser consumes the file, so a serialization
        # or key-shape drift in it must fail the gate, not ship silently.
        try:
            with open(ptmp) as pf:
                pin_data = json.load(pf)
            ok = subprocess.run(
                [verify_bin, "--receipt", rtmp,
                 "--trusted-anchor", pin_data["trusted_anchor"][0],
                 "--expected-hash", pin_data["expected_hash"]],
                capture_output=True, timeout=60,
            ).returncode == 0
        except Exception:
            ok = False
        if ok:
            os.replace(rtmp, rpath)
            os.replace(ptmp, ppath)
            entry["browser_verify"] = True
            harvested.add(rid)
        else:
            for p in (rtmp, ptmp):
                try: os.unlink(p)
                except OSError: pass
            if (os.path.isfile(rpath) and os.path.isfile(ppath)):
                # Prior good pair survives the failed re-mint — keep shipping it.
                entry["browser_verify"] = True
                harvested.add(rid)
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

# ── Cumulative coverage: persist + backfill (2026-08-09, queue R4) ──────────
# Coverage policy: an envelope pair, once minted and ship-gated, PERSISTS for
# as long as its row stays in the snapshot — the deletion pass below keys on
# snapshot membership, not the newest-N harvest window. Rows still lacking a
# pair get a backfill mint here: the node's hot tier serves record wire far
# deeper than the newest-N window (measured 2026-08-09: 305 of 355 snapshot
# acts still served), so most archived rows can carry a self-contained
# offline envelope. The seal leg is the zone's current seal — same
# chain-state shape and producer disclosure as the harvest above. A
# definitive HTTP 404 on an ARCHIVED row's wire marks it wire_gone:true, a
# cached negative that stops re-probing pruned history every run
# (steady-state backfill work = only acts the harvest missed between runs);
# transient failures mark nothing and retry next run. Every minted pair
# passes the same read-back ship-gate; failures are discarded, never linked.
backfill_max = max(0, int(os.environ.get("RECEIPTS_BACKFILL_MAX") or "400"))
if coverage_active:
    os.makedirs(verify_dir, exist_ok=True)
    seal_cache = {}  # seal_id -> (seal_wire, seal_hash); one zone today
    def seal_leg(zone):
        sid, route_hash = zone_seals.get(zone) or (None, "")
        if not sid:
            return None, None
        if sid not in seal_cache:
            sw = fetch_bytes(f"{node}/record/{sid}/wire")
            sh = None
            if sw:
                sh, _ = decode_wire(sw)
            seal_cache[sid] = (sw, (sh or route_hash or None))
        return seal_cache[sid]
    minted = wire_gone_n = 0
    for entry in entries:
        rid = entry["record_id"]
        if rid in harvested:
            continue
        if (os.path.isfile(os.path.join(verify_dir, f"{rid}.receipt.json"))
                and os.path.isfile(os.path.join(verify_dir, f"{rid}.pins.json"))):
            entry["browser_verify"] = True  # minted by a prior run — persists
            harvested.add(rid)
            continue
        if entry.get("wire_gone") or minted >= backfill_max:
            continue
        wire, code = fetch_bytes_code(f"{node}/record/{rid}/wire")
        if code == 404 and entry.get("archived"):
            entry.pop("browser_verify", None)
            entry["wire_gone"] = True
            wire_gone_n += 1
            continue
        if not wire:
            continue
        seal_wire, seal_hash = seal_leg(str(entry.get("zone", "0") or "0"))
        if not (seal_wire and seal_hash):
            continue
        envelope = {
            "receipt_version": 1,
            "producer": {"origin": producer_origin(rid)},
            "legs": {"record": wire.hex(), "seal": seal_wire.hex()},
        }
        pins = {"trusted_anchor": [anchor_pk], "expected_hash": seal_hash}
        rpath = os.path.join(verify_dir, f"{rid}.receipt.json")
        ppath = os.path.join(verify_dir, f"{rid}.pins.json")
        # Mint-to-temp + atomic replace — same rationale as the harvest block.
        rtmp, ptmp = rpath + ".tmp", ppath + ".tmp"
        with open(rtmp, "w") as f:
            json.dump(envelope, f, separators=(",", ":"))
            f.write("\n")
        with open(ptmp, "w") as f:
            json.dump(pins, f, indent=1)
            f.write("\n")
        # Same read-back ship-gate as the harvest: the exact FILES the page
        # will offer must grade VERIFIED with the same core, or ship nothing.
        try:
            with open(ptmp) as pf:
                pin_data = json.load(pf)
            ok = subprocess.run(
                [verify_bin, "--receipt", rtmp,
                 "--trusted-anchor", pin_data["trusted_anchor"][0],
                 "--expected-hash", pin_data["expected_hash"]],
                capture_output=True, timeout=60,
            ).returncode == 0
        except Exception:
            ok = False
        if ok:
            os.replace(rtmp, rpath)
            os.replace(ptmp, ppath)
            entry["browser_verify"] = True
            harvested.add(rid)
            minted += 1
        else:
            for p in (rtmp, ptmp):
                try: os.unlink(p)
                except OSError: pass
            print(f"receipts: backfill envelope for {rid} did not grade "
                  "VERIFIED — not shipped", file=sys.stderr)
    if minted or wire_gone_n:
        print(f"receipts: backfill minted {minted} envelope pair(s); "
              f"{wire_gone_n} pruned row(s) marked wire_gone", file=sys.stderr)

# Membership bound: drop files whose rid carries no coverage in THIS snapshot
# (harvested = fresh newest-N mints + persisted/backfilled pairs) — keeps the
# dir O(snapshot rows) and never ships an envelope the page doesn't reference.
# GUARDED on coverage_active (2026-08-19 fusion-audit fix, replaces the old
# "runs even when the harvest was skipped" rule): when coverage is INACTIVE,
# `harvested` is empty by construction and this pass would delete every
# previously-published pair — the measured −100-file failure. Orphaned files
# during a skipped-coverage run are harmless: receipts.html links envelopes
# only through each row's browser_verify flag (never a directory listing),
# and the next healthy run re-adopts the pairs for free. Mid-run .tmp files
# are cleaned on every path — they are never referenced by anything.
if verify_dir and os.path.isdir(verify_dir):
    for fn in os.listdir(verify_dir):
        if fn.endswith(".tmp"):
            try: os.unlink(os.path.join(verify_dir, fn))
            except OSError: pass
            continue
        if not coverage_active:
            continue
        m = re.match(r"^([0-9a-f-]+)\.(receipt|pins)\.json$", fn)
        if m and m.group(1) not in harvested:
            try: os.unlink(os.path.join(verify_dir, fn))
            except OSError: pass
    if not coverage_active:
        print("receipts: WARNING — envelope coverage INACTIVE "
              f"(n={verify_n} dir={bool(verify_dir)} anchor={bool(anchor_pk)} "
              f"bin={os.path.isfile(verify_bin)}); existing pairs PRESERVED, "
              "membership deletion skipped", file=sys.stderr)

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
covered = sum(1 for e in entries if e.get("browser_verify"))
print(f"receipts: {len(entries)} acts aggregated "
      f"({archived_n} archived, {covered} with offline envelopes)")
PYEOF
then
    echo "receipts: snapshot build FAILED — $OUT left unchanged." >&2
    exit 1
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "receipts: wrote $OUT"
