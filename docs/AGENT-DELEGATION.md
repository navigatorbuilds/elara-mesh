# Agent Delegation — design seed

**The missing protocol mechanics behind the project's positioning** ("proof of
who — or what — did what, when, for any actor: human, device, or AI agent"). A signature proves
*which key* acted; for AI agents (minted by the thousand, copied, revoked,
redeployed) the question that matters is **under whose authority, within what
mandate**. Sibling design to `REALMS-SELF-ASSEMBLY.md` — same PKI machinery
(realm certs ≈ membership; delegation certs ≈ agency), same inside-out
enforcement (no global registry; verifiers check chains at the edges).

> **Not `accounting::delegation`.** A different in-tree system already owns the word
> "delegation": `src/accounting/delegation.rs` is **device-fleet stake-sharing** — a
> parent key signs FOR a child, the child inherits the parent's trust-tier and
> shares its stake, and an unauthorized child op is *rejected at ingest*. This
> mandate layer is the opposite axis: **scoped, revocable agent authority with
> record-and-flag forensics** — the agent signs AS ITSELF and *references* its
> mandate, and out-of-mandate acts are *recorded and flagged*, never rejected.
> To keep the two unambiguous, the mandate layer uses `mandate_*` names
> throughout (`mandate.rs`, `MandateRecord`, `mandate_op`, `CF_MANDATE`) and
> never the `delegation_*` namespace (which would collide with the ingest
> routing key `DELEGATION_OP_KEY`).

## Delegation records

A principal key (human, org) issues a signed **mandate** to an agent key:

- **Scope:** record types it may create, zones, quantitative limits.
- **Validity window** + **revocable** (revocation is itself a record).
- **Sub-delegation:** allowed only if the mandate permits it; depth-capped;
  every hop must be narrower than (a subset of) the hop above.
- Records signed by agent keys carry/reference their delegation chain. Every
  record then answers: this act, by this agent, for this principal, inside
  this mandate, valid at this moment — with the anchor trail proving the
  "moment" (see bootstrap-of-truth in REALMS doc).
- Rogue containment: revoke the mandate → everything the key signs afterward
  is visibly outside authority, timestamped. The ledger shows the exact
  moment authority ended and the agent kept acting — liability evidence, not
  just containment.
- Copies (same model, three datacenters): each runtime instance gets its own
  key + sibling mandate from the same principal — identity = the mandate
  lineage, not the weights. (Open sub-question: standard fields for
  model/version attestation inside the mandate.)

## Out-of-mandate records: RECORD AND FLAG

The mesh **records** unauthorized acts and flags them; it never silently
rejects (a truth ledger records what happened, including violations —
rejection blinds the victim and destroys the evidence). Flagged records carry
**zero weight**: no trust, no consensus standing, no activity credit, never
counted in any committee/stake/reputation metric.

**Flag taxonomy (load-bearing — this is what defeats framing):**

| Flag | Meaning | Binds whom |
|------|---------|-----------|
| `NO_CHAIN` | claimed principal never signed any mandate for this key — the chain does not verify | **the signer only** — the named principal is cryptographically uninvolved |
| `LAPSED` | mandate existed, expired before signing time | signer + (weakly) principal's hygiene |
| `POST_REVOCATION` | mandate revoked before signing time | signer; principal's revocation was the *correct* act |
| `OVER_SCOPE` | valid mandate, act outside its scope | signer + principal's scoping |

## The attribution law (answers "who guarantees it's not a frame-up?")

**Reputation flows only along verified signature chains; claims without
chains bind only their signer.** You cannot frame a network you cannot sign
for:

1. Attacker mints keys and spawns "rogue records claiming to be Org P" →
   chain contains no P-signed mandate → `NO_CHAIN` → the records are
   *cryptographically unattributable to P* — indexes/explorers MUST NOT list
   P as an involved party (P appears only as a victim of impersonation, on
   P's own query). Reputational effect on P: exactly zero.
2. Genuine mandate, agent acts after revocation → the record involves P's
   *past* authority, and simultaneously proves P did the right thing
   (revoked). Reputation measures what P controls — revocation speed,
   scoping discipline — never the fact of being targeted.
3. P's actual keys stolen → not framing but compromise; the protocol's job is
   a visible compromise timeline: incident → revocation record (the live
   compromised-key tombstone; key rotation is specified but not yet operational,
   see KNOWN-LIMITATIONS) → everything after is flagged. Recovery speed is provable.

Framing therefore requires possessing the victim's private keys — at which
point it is a compromise with a provable, bounded timeline, not an
unanswerable smear.

## Spam / DoS economics (the flood vector)

An unauthorized record is just a record with a failed-authority flag — so the
**existing** OPEN-realm anti-spam machinery applies unchanged: stake-gated
ingestion throughput, rate limits per signer, sybil layers.
Flooding flagged records costs an attacker exactly what flooding any records
costs. Additionally:

- **Retention class by flag:** flagged records keep full integrity but may be
  GC-eligible under node retention policy — UNLESS **pinned** (staked) as
  evidence by any party (victim, signer, disputant) within the retention
  window. Real incidents get pinned by whoever needs them; spam nobody pins
  ages out. Evidence economics instead of unbounded spam storage.
- Open question (numbers, not design): retention window length, pin stake
  size, whether `NO_CHAIN` defaults to a shorter window than the
  principal-involved flags.

## Status / sequencing

**Act-index permanence + `/mandate/status` honesty — LANDED 2026-07-19 (B5).**
The derived act index is now permanent across retention GC and zone purge (a
pruned act still answers an authoritative verdict with `record_present:false`),
bounded by a per-profile budget evictor, and `/mandate/status` is a three-state
honesty contract so a pruned or absent act can never read as a confident
"not a mandate act". Full design + SDK/audit-binary contract:
[`MANDATE-ACT-PERMANENCE.md`](MANDATE-ACT-PERMANENCE.md).

**v0 core — LANDED 2026-06-19** (`src/mandate.rs`). Fusion-audited before code
(the project's internal adversarial-review process: several independent AI
reviewers + a result-checking pass, all claims verified against source — *not*
an external third-party audit; "fusion-audited" below always means this). The
slice is the **pure, deterministic, dependency-light core**: `MandateRecord` /
`RevocationRecord` wire types with a domain-separated (`ELARA_MANDATE_V1`),
network-bound, length-prefixed canonical encoding (cloned from
`network::realm`'s cert pattern); content-addressed `mandate_id`; the
`MandateFlag` taxonomy (the doc's 4 flags + `AgentMismatch` / `Malformed` /
`NotYetValid` / `UnverifiedChain`, plus reserved v1 slots) with a fixed,
test-pinned precedence order; and the pure verifier `evaluate_mandate` (judged
against the act's *own signed timestamp*, never wall-clock). 18 unit tests incl.
a byte-pinned encoding lock. **v0 is observational** — the flag is computed and
(next slice) query-served, NOT yet wired into consensus weight; this keeps it
inert w.r.t. the consensus root and safe on the live authority chain.

Audited one-way-door locks baked in now (permanent the instant a mandate is
signed): domain tag + format version byte; `network_id` bound into the signed
bytes (a ledger-resident mandate has no handshake to check the network
out-of-band, unlike a realm cert); single canonicalization shared by id /
signing / `mandate_ref`; sub-delegation **fields frozen** (`parent_mandate_id`,
`sub_delegation_max_depth`) ahead of the chain-walk that consumes them (landed
in Slice 2 below); revocation
monotonic + terminal (no un-revoke — re-authorization is a fresh mandate).

**Slice 1 (node wiring) — LANDED 2026-06-19.** Fusion-audited before code (4 Opus
panel + 1 result-checker). Shipped: ingest
parse/validate + observational apply (`network/mandate_node.rs`), `CF_MANDATE` /
`CF_REVOCATION` / `CF_MANDATE_ACT` (`storage/rocks.rs`), GC-exemption (both gc
blocks), snapshot carry with content-hash checksum, and public `/mandate/{id}` +
`/mandate/status/{record_id}` endpoints. Two audit-driven changes from the plan
below: revocation authority is **read-time** (index keyed by `(mandate_id,
revoker)`, front-run-proof) not ingest-gated; **scope enforcement is deferred**
(`evaluate_mandate_v0` enforces scope only for wildcard mandates — a node-
invariant op/zone derivation needs a signed canonical taxonomy that doesn't exist
yet). The flag is RECOMPUTED at query (revocation-aware, never stale).
A reverse-lookup endpoint (`/mandate/agent`, listing the mandates that name a
given agent) is intentionally not exposed: enumerating the agent→mandate graph is
a privacy and abuse surface, so reverse queries are deferred behind a scoped,
authorization-aware access model (loopback-only or principal-authenticated).

**Demo — LANDED 2026-06-20** (`examples/mandate_demo.rs`). The structural
differentiator made runnable, with **zero infrastructure and no feature flags**
— `cargo run --example mandate_demo` builds against the core verifier alone
(`crate::mandate`), so it runs from a clean clone in seconds. It uses three real
Dilithium3 identities (principal / agent / impostor), really signs and verifies
every carrier record, and judges five acts through `evaluate_mandate_v0` — the
*same* pure function `GET /mandate/status/{record_id}` calls (only the storage
backend is swapped for an in-memory `MandateResolver`, which is exactly what the
trait exists for). The verdicts a timestamp + a signature cannot give you:

| Act | Verdict | What OTS+sig miss |
|-----|---------|-------------------|
| mandated agent acts, in window | `VALID` | *was* authorized, at signing time |
| a different AI uses the agent's mandate | `AGENT_MISMATCH` | wrong signer — principal **exonerated** |
| agent claims a mandate that never existed | `NO_CHAIN` | unauthorized; binds the signer only |
| agent acts after the principal revoked | `POST_REVOCATION` | authority had ended |
| re-judge the in-window act after revocation | `VALID` | revocation is **not retroactive** |

This is the "AI-agent accountability" grant/Show-HN artifact (tasks C4/C16): the
answer to *"why not just a timestamp + PQ signatures?"* is now a 60-second
command, not a paragraph. The honest scope line holds — op/zone scope is
*recorded* but enforcement is deferred (see slice 1 above); the demo never claims
a scope check it does not run.

**Slice 2 (sub-delegation chain verification) — LANDED 2026-06-21.** Fusion-audited
before code (high-stakes tier: 3 Sonnet + 1 Opus panel → Opus synthesis → 1 Opus
adversarial final-verify). The `evaluate_mandate` walk now replaces the
`parent_mandate_id.is_some() → UnverifiedChain` short-circuit with a recursive
leaf→root walk ([`walk_chain`], `src/mandate.rs`). Still **observational** (a
flag, never consensus weight) and pure/deterministic/integer-only. Per hop:

- **Genealogy link** `child.principal == parent.agent` (`eq_ignore_ascii_case`).
  Sound because ingest binds `sha3(carrier_pk) == principal` (so a stored mandate
  proves its principal signed it) — the walk only needs the *structural* link.
- **Scope monotone-narrowing** (child ⊆ parent), reusing the same
  `allows_op`/`allows_zone` matchers as act-vs-scope enforcement, so a child `"*"`
  needs a parent `"*"` and the zone-prefix direction is correct (`zone/A` under
  `zone/A/0` is a BROADENING). Amount uses an explicit `None`-is-unlimited match
  (an unlimited child under a capped parent is broadening). The act-validity
  window must be `⊆` the parent's (inclusive bounds) — a sub-delegation may not
  outlive its grant. This is a pure mandate-vs-mandate struct comparison, so it is
  enforced **even in v0** (unlike the deferred leaf-scope-vs-ACT check).
- **Depth**: each ancestor independently caps the hops below it (the binding
  constraint is the *minimum* down the chain — an intermediate cannot override a
  stingy root), PLUS a hard `MANDATE_MAX_CHAIN_DEPTH = 16` bound independent of
  the attacker-settable `sub_delegation_max_depth`. The hard bound is the
  load-bearing termination guard on attacker-controlled `parent_mandate_id`
  pointers AND the `/mandate/status` public-endpoint read-fan-out (DoS) bound.
- **Per-hop revocation**: every hop checked against its OWN principal at the
  single leaf act timestamp — revoking a mid-chain mandate kills the whole subtree.
- **Missing/malformed/cross-network ancestor, or a broken link → `UnverifiedChain`**
  (reused, not a new flag). Post-slice, `UnverifiedChain` means exactly "the chain
  could not be verified on this node" — non-authorizing, non-attributing. The
  missing-ancestor case is **node-local-state-dependent** (varies by sync); this
  is safe only while observational. **Invariant for the future enforcement slice:
  `UnverifiedChain` MUST map to zero weight (= `NoChain` class), never a penalty,
  and enforcement MUST gate on a protocol-version bump so all nodes walk
  identically — else sync-skew becomes a consensus fork.**
- **Precedence** (sequence of checks, not discriminant values):
  `Malformed > NoChain > AgentMismatch > DepthExceeded > ScopeBroadened >
  UnverifiedChain > PostRevocation > Lapsed > NotYetValid > OverScope > Valid`.
  The leaf agent-binding check stays FIRST (cheapest decisive check; keeps
  `AgentMismatch` outranking chain verdicts; bounds the DoS fan-out).

**Snapshot-trust boundary (from the final-verify).** The walk's soundness rests on
*"resolver `Some` ⇒ content-addressed + well-formed."* On live ingest this is
cryptographic; on the snapshot-bootstrap path the storage bulk-apply
(`apply_mandates`/`apply_revocations`, `storage/rocks.rs`) previously keyed by a
producer-supplied id without recompute. This slice adds a consumer-enforced guard:
each snapshot mandate is rejected unless its key equals its recomputed
`mandate_id()` and it is well-formed (revocations: composite-key format checked);
rejections bump `MANDATE_SNAPSHOT_REJECTED_TOTAL`. This restores content-addressing
as an invariant and makes a snapshot storage-cycle infeasible — but **cannot**
restore principal-binding (the payload carries no pubkey), so snapshot-carried
mandate *authenticity* remains bounded by snapshot-signer trust, consistent with
the rest of the ledger. Never add an on-demand *unauthenticated* parent fetch — it
would void the invariant and make the chain forgeable.

**Anti-libel for verified chains.** A `Valid` chain attributes to the LEAF
mandate's principal (the immediate authorizer), not the root — naming the root
would over-claim ("authorized this act" vs "started a chain"). Any non-`Valid`
chain verdict names no one (`attributes_to_principal == false`). Exposing the full
lineage as labeled non-accusatory metadata is an additive follow-on.

**Slice 3 (chain-lineage attribution metadata) — LANDED 2026-06-21.** Fusion-audited
(3 Sonnet + 1 Opus panel → synthesis → 1 Opus final-verify). `GET /mandate/status/{id}`
now surfaces the verified sub-delegation chain (leaf→root) as a `lineage` array
(`hop_index`, `mandate_id`, `principal_identity_hash`, `agent_identity_hash`) plus
`chain_depth` and a non-accusatory `lineage_note`. The anti-libel rule is enforced
in the **pure function**, not the handler: `evaluate_mandate_v0_with_lineage`
(`mandate.rs`) returns a non-empty chain ONLY on the `Valid` verdict — every other
flag (incl. a fully-walked-but-revoked `PostRevocation`) returns an empty chain, so
a non-authorizing or unverifiable chain never names an ancestor. `evaluate_mandate`
/ `evaluate_act_entry` are now `.0` projections of one body (the flag and the
lineage are computed in a single resolver pass → they can never disagree, no
re-walk, no drift). No new disclosure: each hop is already public per-hop via `GET
/mandate/{id}`; this is the pre-walked, pre-verified form, bounded by
`MANDATE_MAX_CHAIN_DEPTH` (≤16). 3 tests in `mandate.rs`.

**Self-mandate reject (`principal == agent`) — DEFERRED 2026-06-21 (audit verdict).**
The same fusion audit unanimously rejected building this now. (1) It is gold-plating
a harmless case: a self-mandate forges no privilege — `INV-A` binds
`child.principal == sha3(carrier_pk)`, and `scope_within` + depth caps still bind, so
a self-mandate-as-parent cannot broaden authority; self-attribution (X→X) is
tautological, not libel; and self-mandates are a legitimate self-attenuation pattern
(it is even a test fixture for the cycle-termination guard). (2) Every shippable form
is unsafe: the mandate **carrier record is a merkle leaf of its zone's epoch seal**
(`record_hash` binds the `mandate_op` metadata), so rejecting it at
`validate_mandate_ingest` — which runs on the **Sync/replay path** too — perturbs the
seal-covered record set; the `"mandate…"` reject string is non-retryable
(`gossip.rs` `is_retryable_ingest_rejection`) so it **permanent-reject-caches** on
sync; and the snapshot-bootstrap bulk-apply bypasses the ingest gate entirely. If
ever wanted, it belongs as an **effect-level read-time rule behind the v0→v1
protocol-version bump**, never a carrier-record ingest reject.

**Consensus-weight enforcement — DEFERRED TO S3 (fusion-audited 2026-06-22:
3 Sonnet + 1 Opus panel → synthesis → 1 Opus adversarial verify; unanimous
DEFER-WITH-SHIP-NOW-SUBSET).** The "next slice" was framed as *"the flag gates
trust/stake/committee standing."* The audit corrected that framing and the
target:

- **The "stake/committee standing" framing is a category error (Model B rejected).**
  Gating a *validator's* committee eligibility / attestation weight on holding a
  `Valid` mandate gates consensus on node-local, sync-dependent resolver state
  (the missing-ancestor → `UnverifiedChain` case) — the documented #1 silent-fork
  vector (`docs/MULTI-VALIDATOR-EMITTER-AUTH.md` §5). It is also incoherent on the
  live chain: the sole staked identity is the genesis authority — a *principal*,
  not an agent-under-mandate — so it would self-mandate tautologically.
- **Act/effect-level gating (Model A) is the right target but is premature.** The
  acts a mandate governs are already authority-gated (`is_privileged_emitter`) or
  conservation-checked; there is no consensus surface today where a
  `Valid`/`NoChain` distinction changes an accept/reject without *inventing* one.
  And gating ledger-effect on the flag would contradict this layer's founding
  rule (above): *record and flag, never silently reject* — rejection blinds the
  victim and destroys the evidence.
- **Two hard prerequisites (the unblock triggers):** (1) the S3 multi-validator/
  multi-emitter stage is live (≥2 staked attesting validators), so enforcement
  has real objects and a real consensus surface; AND (2) a **signed canonical
  op/zone taxonomy** exists — without it `OverScope` is uncomputable for
  non-wildcard mandates (the slice-1 Q3 blocker), so any "enforcement" would be a
  dead `OverScope`-unreachable seam that only *looks* live.
- **Activation mechanism (pinned recommendation, no constants until S3):** the
  v0→v1 gate MUST be the **epoch-sealed `effective_epoch` + dispute-window
  pattern** (as shipped in `src/network/auto_scale.rs` / `src/network/sunset.rs`),
  NOT a node-local config flag (two operators, two configs → fork — the same
  reason `use_committee_v2` is fleet-coordination, not a safety gate) and NOT
  `protocol_upgrade.rs` (clock-time-keyed windows, no runtime callers). The
  invariant stands: `UnverifiedChain` MUST map to **exactly** `NoChain`'s
  zero-weight class, never a penalty.
- **Explicitly NOT shipped now:** a `use_mandate_v1_enforcement` config-flag stub
  or any wire reservation. A no-consumer flag mimics the safe `use_committee_v2`
  precedent yet bakes in the node-local-state dependency that forks the moment a
  2nd validator joins — inert-on-a-singleton is not fork-safe, and the v1
  discriminants (9–11) already reserve the only wire space needed.

**Ship-now subset (landed 2026-06-22; all reversible, zero consensus surface):**
(1) the `MANDATE_FLAG_TOTAL` histogram is now surfaced on `/metrics` as
`elara_mandate_flag_total{flag="…"}` — **label-free by discriminant only** (the
12 fixed flag variants; never an agent/principal/mandate_id label, which would
reopen the withheld agent→mandate enumeration surface), classified P1 (stripped
at phone-tier P0), plus the five scalar `elara_mandate_{records,revocations,acts,
malformed_ref,snapshot_rejected}_total` counters — the last, sourced from the
snapshot bootstrap apply-path (`apply_mandates`/`apply_revocations`), is the
virgin-join tamper signal: non-zero means a bootstrap snapshot carried a mandate
or revocation that failed the consumer-side content-address/well-formed guard
(producer bug or tampered-but-signed snapshot); (2) `MandateFlag::ALL` + two
pinning tests lock
the zero-weight invariant (`unverified_chain_and_no_chain_share_the_zero_weight_class`)
and the discriminant↔array correspondence so a future enforcement diff that
mis-weights `UnverifiedChain` is a build failure, not a field incident.

**Slice 4 (acts-under-a-mandate enumeration) — LANDED 2026-06-26.** Fusion-audited
before code (high-stakes tier: 3 read-only adversarial panelists — consensus/
one-way-door, storage-correctness, scale/DoS lenses — grounded against source →
synthesis). `GET /mandate/{id}/acts?from=&limit=` answers the query the layer
exists for: *"what did this agent do under this authority?"* — the bounded,
keyset-paginated list of act records that reference the mandate, each with its
recomputed [`MandateFlag`] and the same anti-framing principal-echo as
`/mandate/status` (the compact view; drill into `/mandate/status/{record_id}` for
per-act lineage). Backed by a new reverse index `CF_MANDATE_ACTS_BY_MANDATE`
(key `mandate_id(64 hex) ++ act_timestamp_ms(8 BE) ++ record_id`, empty value)
written/deleted in **lockstep with `CF_MANDATE_ACT` in one `WriteBatch`**, so the
two indexes can never diverge. **Consensus-INERT** — the same class as the forward
act index: never in a seal/account root or the snapshot checksum (the existing
`mandate_effects_are_inert_wrt_account_seal_root` pin is extended to assert the
account seal-root is byte-identical with the reverse CF populated). Audit-driven
properties baked in: only well-formed 64-hex refs are reverse-indexed (a fixed-
width prefix defuses the attacker-controlled `mandate_ref`); the URL id is
lowercased before the seek; pagination is exclusive-on-resume (the cursor is the
last suffix `++ 0x00`, so RocksDB's inclusive `From` seek never re-emits or skips
a row); reads go through `range_scan_cf` + a `starts_with` guard (NEVER
`prefix_scan` — no `prefix_extractor` is installed), O(`limit`) per page with
`limit` hard-capped at `MANDATE_ACTS_PAGE_MAX = 200`; `delete_record` reconstructs
the reverse key from the forward entry's `(mandate_ref, act_timestamp_ms)` so GC
leaves no orphan, idempotent under double-delete. **Coverage is baseline-relative — and, as of 2026-06-26, self-describing:**
acts are not snapshot-carried, so a snapshot-bootstrapped node is *eventually-
complete*, not authoritative-complete — identical coverage to `/mandate/status`.
Both endpoints surface this in their response as an `authoritative_complete`
boolean so the gap is machine-readable, not just a documented caveat:
`/mandate/{id}/acts` reports `!ledger_loaded_from_snapshot` (node-level
enumeration completeness); `/mandate/status/{record_id}` reports `true` for any
*found* act (its flag is judged from snapshot-carried mandate+revocation state, so
it is authoritative on any node) and `!ledger_loaded_from_snapshot` on the
not-found path. A snapshot follower's `{count:0}` / `{is_mandate_act:false}`
carrying `authoritative_complete:false` therefore reads as "this node bootstrapped
past it, query an archive" — never "the agent never acted".
Adding a CF is the same accepted downgrade-trap as the three slice-1 mandate CFs
(no version bump; a node must not be rolled back to a pre-CF binary after the CF
is created). 1 storage test (ordering / isolation / keyset pagination / non-64-hex
exclusion / delete-orphan + double-delete / uppercase-normalization).

**Agent-acts (acts-by-signer enumeration) — LANDED 2026-06-26.** The complement of
slice 4: where `/mandate/{id}/acts` lists acts under one *authority*, the
LOOPBACK-ONLY `GET /agent/{agent_hash}/acts?from=&limit=` lists the acts *signed by
one identity*, across all mandates — *"everything this key did that referenced a
mandate, and under whose authority"*. Fusion-audited before code (high-stakes tier:
3 Sonnet + 1 Opus read-only panel → synthesis → direct source-verify of the
decision-flipping facts). The panel split; verdict = **build it, but loopback-only**,
on two grounds the audit verified in source: (1) by-creator enumeration is *already*
gated in-tree — `/records/search?creator=` is not in `PUBLIC_ROUTE_PREFIXES` — and a
by-signer act index is the same surface; making per-identity behavioral aggregation
*cheap* (an O(`limit`) keyset seek vs the SCALE-RULE-forbidden O(all_records) scan)
is the deanonymization harm, not its mere possibility — the same line the protocol
draws for bare `/balances`; (2) gating now is the safe side of a one-way door before
the public mirror — a gate relaxes later to principal-authenticated (the "scoped,
authorization-aware access model" this doc always envisioned), but a public
surveillance surface cannot be un-shipped. The agent→**mandate** issuance/delegation
graph stays withheld entirely (a pure relationship disclosure slice 4 never crossed).

Backed by a third reverse index `CF_MANDATE_ACTS_BY_AGENT` (key
`signer_hash(64 hex) ++ act_timestamp_ms(8 BE) ++ record_id`, empty value), written
and deleted in the **same `WriteBatch`** as the forward and by-mandate indexes, so
all three have byte-identical coverage and cannot diverge across a crash. No wire
change — `signer_identity_hash` is already persisted on `MandateActEntry`. Same
hardening as slice 4 (fixed-width hex prefix, lowercased seek, exclusive `+0x00`
cursor, `range_scan_cf` + `starts_with`, `MANDATE_ACTS_PAGE_MAX = 200`, GC-lockstep
delete), **consensus-INERT and NOT snapshot-carried**, with `authoritative_complete`
coverage honesty identical to `/mandate/status`. Existing acts are backfilled by a
bounded, idempotent, crash-safe boot migration (`migrate_7_to_8`, `CURRENT_DB_VERSION`
7→8) scanning the bounded `CF_MANDATE_ACT` — never `CF_RECORDS`. Two permanent
choices the audit pinned: the path is **outside `/mandate`** (that prefix is public
and prefix-matched, so a `/mandate/agent/...` route would be public-by-accident *and*
would panic at router construction against `/mandate/{id}/acts`); and the response
carries an explicit anti-libel framing — the list is the **signer's own**
mandate-referencing claims and their verdicts (it deliberately includes
`NoChain`/`AgentMismatch` acts the key was never authorized for — the forensic
point), with a principal named only when the flag genuinely attributes the act.
**Honest-claims:** describe it as "mandate-referencing acts signed by this agent",
never "everything this agent did" (only records carrying a `mandate_ref` are
indexed); it is an operator/forensic surface, not a public claim. 2 tests (storage
cross-mandate-aggregation + isolation + pagination + delete-orphan; loopback-gating +
auto-public-trap guard) + 1 migration-backfill test.

**Other next slices** (each its own audit): retention/pinning; the agent→mandate
issuance graph (still withheld — needs a principal-authenticated access model).
(Self-mandate handling, if ever pursued, batches behind the S3 version gate — see
the DEFERRED note above.)

**Dogfood — LANDED 2026-06-26** (the first REAL agent-mandate on the live chain).
Fusion-audited before building (high-stakes tier: 3 Sonnet + 1 Opus panel →
synthesis → 1 Opus adversarial final-verify). The panel independently
**re-confirmed the 2026-06-22 DEFER-TO-S3 verdict** still holds against HEAD for
consensus-weight enforcement, and rejected a "configurable ingest-admission"
option as the *same* sync-skew/`permanent-reject-cache` fork hazard relabeled
"local policy" — so the live frontier is **demonstration, not enforcement**: the
observational layer already expresses revocable authority-to-act, which is the
whole differentiator. Shipped (client-side only — zero consensus surface, the
node side was already wired): `elara-cli mandate-issue` / `mandate-revoke`
subcommands + a `--mandate-ref` flag on `agent-emit`, and the runbook
`scripts/mandate-dogfood.sh`. A dedicated **maintainer/delegation key** (NOT the
genesis consensus key — key separation is deliberate hygiene; the consensus root
signs seals, not routine delegations) issued the first on-chain mandate to a
build-agent key, and the full lifecycle was proven against the live authority:
act-before-revocation → `valid`, principal revokes, act-after-revocation →
`post_revocation`, and re-querying the first act STILL returns `valid` (each act
judged at its own signed timestamp — the queryable-over-time property). The
answer to *"why not just a timestamp + PQ signatures?"* is now a live chain
record anyone can `GET /mandate/status/{id}`, not only a demo script.
