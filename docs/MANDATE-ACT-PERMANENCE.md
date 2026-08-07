# Mandate-Act Permanence + `/mandate/status` Honesty (B5)

**Status: code complete** (shipped 2026-07-19); design audited before build.

## The problem

A mandate **act** is an ordinary record that carries a `mandate_ref` — it is
GC-eligible like any other record. The derived act index
(`CF_MANDATE_ACT` + its by-mandate / by-agent reverse indexes) let
`GET /mandate/status/{record_id}` recompute an accountability verdict without
re-reading the (large) act body. But two gaps let that verdict **lie**:

1. **Retention GC deleted the act index with the body.** Once a node pruned an
   act record, `/mandate/status` answered a confident *"not a mandate act"* — a
   false negative that erased a real, signed accountability fact.
2. **A snapshot follower / zone-scoped node has no pre-baseline index**, yet the
   old miss-path could still read as authoritative on restart
   (`ledger_loaded_from_snapshot` is memory-only).

B5 makes the act index **permanent by policy** and the absence answer **honest
about coverage** — a pruned or absent act can never again read as an
authoritative *"not a mandate act"*.

## Design

### 1. GC-scoped index permanence (`DeleteIntent`)

`delete_record(record_id, intent)` now takes an explicit intent — there is no
defaulting wrapper, so every call site declares why it deletes:

| Intent | Body | Act index | Marker |
|--------|------|-----------|--------|
| `GcPrune` (retention GC) | deleted | **preserved** | — |
| `ZonePurge` (resharding) | deleted | **preserved** | — |
| `AdminEvict` (operator takedown) | deleted | **removed** | `__act_removed__:{rid}` |

The tiny per-act index (~0.6 KB) outlives the ~5.4 KB body, so a pruned act
still answers an authoritative found verdict with `record_present:false`. Only a
deliberate operator evict removes it — and leaves a rid-keyed removed-marker so
the absence reads as `removed_by_operator`, never a coverage gap.

`AdminEvict` reads the entry via `get_mandate_act_checked` (a *Result*-returning
getter): a storage read error **aborts** the delete before any key is touched,
so a transient fault can never leak the reverse keys or drop the entry silently.

### 2. Boundedness — the budget evictor

Permanence is bounded **by config**, never by ingest rejection. A new
time-ordered index `CF_MANDATE_ACTS_BY_TIME` (`ts ++ record_id`) drives an
oldest-first evictor:

- `evict_acts_over_budget(budget_bytes, max_per_tick)` runs once per GC cycle.
- Over budget → delete the oldest acts (all four keys each), `O(evicted)` via the
  time index — never a full scan; the budget check is one `O(1)` property read.
- The evictor **never rejects a sealed record** — over-budget nodes still accept
  acts via submit / gossip / sync (rejecting would be the documented fleet-trap
  fork shape). It just trims the oldest tail and advances the coverage floor.
- `acts_budget_bytes` is profile-aware: **full_zone 2 GiB** (~3.5–6M
  per-rid-queryable acts), **light ≤256 MiB**, **archive 0 (unlimited)**, and is
  clamped to **≤25 % of `disk_cap_bytes`** so the exempt mass can never saturate
  the GC size governor. Env: `ELARA_ACTS_BUDGET_BYTES`.

The GC size governor subtracts the GC-exempt mandate mass from the disk cap
(`effective_disk_cap = saturating(disk_cap − exempt), floor 1 GiB`) so it never
livelocks record retention chasing bytes it cannot compress.

### 3. The coverage floor — honest absence

A single durable, monotone millisecond floor
(`__acts_index_complete_from_ms__` in `CF_METADATA`) records the boundary at/after
which this node's act coverage is complete:

- **Init policy:** `now_ms` on any DB missing the key (an upgraded seed that
  already GC'd acts, or a virgin pull-join that can never re-ingest pruned
  carriers — safe direction). A fresh **genesis-ceremony** chain would want `0`
  via `force_acts_coverage_floor_genesis`, but **that path is not yet wired into
  any ceremony** (a future re-genesis must call it); today every DB inits to
  `now_ms`. The boot-init write is retried + synced; if it still fails the floor
  stays **uninitialized**, which is read **fail-CLOSED** — an uninitialized floor
  (key absent or malformed) is treated as non-authoritative (`basis:"uninitialized"`),
  never collapsed to the `0` that means genuine full coverage, so a failed init can
  never resurrect the false-negative. (`elara_mandate_acts_coverage_floor_initialized`
  metric = 0 while uninitialized.)
- **Advanced (never regressed)** at snapshot bootstrap (to the snapshot baseline)
  and by the budget evictor (past the newest evicted act). Serialized by a mutex
  so concurrent advances can't regress it.

### 4. Three-state `/mandate/status/{record_id}`

Exactly one of:

- **STATE 1 — INDEXED**: act entry present → the recomputed verdict + anti-libel
  principal echo + verified lineage, plus `record_present` and (if pruned) a
  `record_note`. `authoritative_complete: true` (entry-driven; never reads body).
- **STATE 2 — RECORD-ONLY**: no entry but the body is present. If it carries a
  non-empty `mandate_ref` (the exact ingest guard) → reconstruct the entry and
  serve the found shape with `index_entry_present:false` (read-pure, no healing
  writes). Otherwise the signed record itself is an authoritative refutation
  (`absence_basis:"record_checked"`) on every node, snapshot follower included.
- **STATE 3 — ABSENT**: both miss. `absence_basis` ∈
  `removed_by_operator` (authoritative) / `full_coverage` (authoritative) /
  `outside_coverage` (non-authoritative, carries an `acts_coverage` window) /
  `storage_error` (non-authoritative). Authoritative absence requires
  `floor == 0` **and** the node accepts all zones **and** it did not bootstrap
  from a snapshot **and** no read faulted. A zone-scoped node never claims
  authoritative absence (its `basis` carries `zone_subset`).

Absence-authority is a **window, not a bool**: a verifier holding a receipt with
`claimed_ts ≥ complete_from_ms` and an absent answer has an authoritative
refutation; below the floor it is genuinely unknowable on this node. The two
`/mandate/{id}/acts` and `/agent/{hash}/acts` list endpoints carry the same
`acts_coverage` object + per-row `record_present`, and fold coverage into their
page `authoritative_complete`.

## SDK (`mandate_sdk`)

- `Coverage` is `#[non_exhaustive]`: `Authoritative | Incomplete { basis:
  CoverageBasis, acts_complete_from_ms: Option<u64> }`.
- New verdict `UnknownOutsideCoverage` replaces the old absent+non-authoritative →
  `NotAMandateAct` misclassification; unknown basis strings map to it.
- `classify_with_claimed_time(claimed_ms)` → `RefutedForClaim` at/above the floor,
  `UnknownOutsideCoverage` below it.
- A missing `authoritative_complete` is a parse error (never defaulted). The
  legacy three-field response is a strict subset of every state, so old SDKs read
  a pruned answer as non-definitive (safe direction).

## Audit binary (`elara-mandate-audit`) exit codes

`0` authorized · `1` definitive not-authorized · `2` usage/network/parse error ·
`3` **authoritative** not-a-mandate-act (proven absent) or unverified chain ·
`4` **unknown-outside-coverage** (absent but coverage incomplete — pruned /
out-of-window / zone-scoped / storage fault). A script gating on `3` must not
treat a `4` as proven-absent.

## Metrics

- `elara_mandate_acts_coverage_floor_ms` (gauge)
- `elara_mandate_exempt_live_bytes` (gauge)
- `elara_mandate_act_entries_deleted_total{reason=gc|zone_purge|admin_evict|budget_evict}`
  — **`reason=gc` and `reason=zone_purge` MUST stay 0** (retention GC and zone
  purge preserve the index); a non-zero reading there is the B5 regression alarm.

## Consensus safety

The act CFs are **consensus-inert** — they never enter a seal, account root, or
snapshot checksum. No wire-format change, no delta-sync change, no re-genesis. A
re-genesis (G5) orphans the rid-keyed entries and writes `floor := 0` on the
fresh chain; the old DB's pre-fix holes remain archive-only and are now honestly
labelled.

## Ops

- DELL (always-on authority seed) runs `node_profile=archive` as the interim
  network-permanence anchor (retention effectively infinite; node-local policy,
  non-fork). Combined with the public receipts archive, this guarantees the
  signed record survives even where a full-zone node's body ages out.
