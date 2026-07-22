# MESH-BFT Merge Semantics — disjoint-DAG merge and cross-realm publication

**Status: design-first, paper-and-spec only.** This document states the
conflict-resolution rules for merging disjoint DAGs, the finality-preservation
argument across the `NETWORK_PUBLISH` boundary, and the safety case for
*publication-as-attested-bundle* with zero standing. It introduces **no
protocol code changes pre-publication**. It is the formal companion to the
2026-06-14 DAG-merge audit that hard-disabled `NETWORK_PUBLISH`
(`src/network/publish.rs:51`, `NETWORK_PUBLISH_ENABLED = false`) and the
intellectual core of the "verifiable disclosure of long-running private
provenance networks" grant line.

Honest-claims rule applies throughout: this is *designed-for*, not
*proven-at*. Where an argument is a sketch rather than a machine-checked proof,
it says so.

Related artifacts:
- `docs/REALMS-SELF-ASSEMBLY.md` — realm model + the "Open formal problem —
  multi-root settlement semantics" seed this formalizes; the four design laws.
- `src/network/publish.rs` — the disabled per-record model + killswitch.
- the economics specification §18.4 (Validation-IPO) / §18.7 (anti-gaming) —
  the spec text (now bannered DISABLED).
- `docs/whitepaper/MESH-BFT-PAPER.pdf` — the single-network safety/liveness theorems.
- the 2026-06-14 DAG-merge design audit — the internal review whose gates this
  resolves.

---

## 1. The problem, precisely

A "realm" is one MESH-BFT instance: one identity set, one stake universe, one
genesis (`docs/REALMS-SELF-ASSEMBLY.md`, OPEN / FEDERATED / SOVEREIGN). The
"Validation IPO" / `NETWORK_PUBLISH` event is supposed to let a private realm
disclose its history into the public mesh. The original design (now dead) had
imported records **enter public consensus** and accrue **retroactive
witnessing** (`ProcessedPublication.retroactive_witnessing: true`,
`publish.rs:298`). The 2026-06-14 audit found that unsound on three
code-verified facts:

**F1 — records carry no realm/network binding in their signed bytes.**
`ValidationRecord::signable_bytes` (`src/record.rs:270-332`) signs exactly:
`id`, `version`, `nonce` (v5+), `content_hash`, `creator_public_key`,
`timestamp`, `num_parents`, sorted `parents`, `classification`, `metadata`,
`zk_proof`. There is **no** `network_id`, realm id, or chain id in the
pre-image. The code is explicit (`record.rs:327`): zone and ITC stamp are *not*
signed — "they are added by nodes during insertion, not by the record creator."
A record's signature therefore proves *who* and *what*, never *which network*.
An imported record is byte-for-byte indistinguishable, under signature
verification, from a record native to the importing mesh.

**F2 — MESH-BFT's safety theorem is stated over a single stake universe.**
Theorem 1 (Diversity-Weighted Safety, `docs/whitepaper/MESH-BFT-PAPER.pdf`)
fixes one DAM `M` with one identity set `I`, one total staked supply
`S_total`, and one diversity function `d(·,·)`. The proof partitions `I` into
honest `H` and Byzantine `B` *within that single universe* and concludes a
conflicting pair `r, r'` cannot both reach `ES(r) ≥ ⅔·S_total`. Liveness
(Theorem 3, §5) likewise assumes "honest stake > ⅔ persists
globally" and "no Byzantine correlation across zones." Nothing in either proof
covers two independent realms with two different `S_total` values. Adopting a
foreign realm's records as **native settlement parents** would let a stake
universe the public mesh never measured determine public finality — outside
the theorem entirely.

**F3 — epoch seals carry no network binding either.** `ParsedEpochSeal`
(`src/network/epoch.rs:1562-1612`) commits zone, epoch number, start/end,
record count, `merkle_root`, `previous_seal_hash`, VRF output/proof, the
record-hash set, zone-balance/registry roots, and the global
`account_smt_root` — but **no** `network_id`. A seal proves "these records
were sealed at this epoch in this zone," not "in this network." The chain-link
(`previous_seal_hash`) is internal to one realm's seal chain.

**Conclusion.** The settlement graph and the stake universe are the same
object. You cannot splice a second realm's records into the first realm's
settlement DAG without either (a) importing its stake universe (which the
public mesh has no way to measure or trust) or (b) letting unbacked records sit
as settlement parents of native records (which breaks the ⅔ argument, since
their "finality" was decided by a quorum the public mesh never counted). Both
are unsound. Hence `NETWORK_PUBLISH_ENABLED = false`, fail-closed, until the
model below lands.

---

## 2. What IS sound today — the contrast case

Merging is not categorically forbidden. It is sound **iff both sides are the
same MESH-BFT instance** — one `I`, one `S_total`. The mesh already does this,
two ways, both inside Theorem 1:

**Partition-heal / DAG-fragment merge.** The DAM is a DAG, not a chain
(`docs/REALMS-SELF-ASSEMBLY.md:48-51`). When one network partitions, fragments
keep writing locally and **merge on re-contact**. This is sound because every
fragment shares the *same* identity set and stake universe — re-contact is
ordinary DAG operation, not a foreign import. Conflicting records across the
heal are resolved by the existing settlement rule: whichever reaches
`ES(r) ≥ ⅔·S_total` first wins, and Theorem 1 guarantees not both.

**Cross-zone settlement (`src/accounting/cross_zone.rs`).** A debit seals in zone A
and finalizes on A's local epoch inclusion; the credit applies reactively in
zone B on observing the debit's seal-inclusion Merkle proof
(`PendingTransfer { source_zone, dest_zone, merkle_proof, lock_record_hash,
source_merkle_root, source_seal_signers }`). This async-optimistic settlement
spans zones but **not networks**: zones A and B draw on one `S_total`, and the
proof B verifies is a Merkle path into A's epoch seal signed by *the same
network's* witnesses. Cross-zone parents are a same-network concept
(`register_cross_zone_parents`, `cross_zone_parents_finalized`,
`src/network/consensus.rs:1919-1937`); there is no realm field in any of it,
because there was never meant to be cross-realm settlement here.

**The boundary, stated once:** *one network = one MESH-BFT instance = one stake
universe. Merge of settlement graphs is sound within a stake universe and
undefined across stake universes.* Everything below is about crossing that
boundary **without** merging the settlement graphs at all.

---

## 3. The merge model — inert-import (publication-as-attested-bundle)

The reframe sidesteps the unsolved multi-root reconciliation by **never merging
the settlement DAGs**. Disclosure is modelled as a single native object that
*points at* foreign history without *adopting* it.

A **publication bundle** is one native record in the public mesh, signed by a
public-mesh participant, that commits to:

1. **`source_realm_root`** — the foreign realm's genesis/anchor identity (its
   root of trust), so the disclosure is attributable.
2. **`bundle_merkle_root`** — a Merkle root over the imported record set. The
   bundle commits to *exactly* this set of bytes; tampering is detectable.
3. **`completeness_proof`** — optional Merkle-style attestation that the
   published subset is complete w.r.t. some declared scope (defeats *selective
   omission*, per spec §18.7; does **not** defeat backdating — see §6).
4. **`time_bracket`** — the external `[T1, T2]` anchor bracket
   (`docs/REALMS-SELF-ASSEMBLY.md`, "Bootstrap of truth"): a drand not-before
   pulse (`src/network/time_bracket.rs`, `DrandPulse::not_before_unix`) and a
   Bitcoin/OTS existed-by stamp. This — not consensus — is what gives the
   imported history any age credibility.
5. **`publisher` + key-rotation chain** — the public identity making the
   disclosure and its continuity proof.

**What public consensus attests about a bundle:** that *this bundle, with this
root, existed and was published by this identity at this anchored time.* That
is one native record reaching native finality. Nothing more.

**What public consensus never attests:** the internal truth, internal
finality, or true age of any imported record. The imported records are
**inert**:

- not settlement parents of any native record;
- not entered into the account-state SMT (`account_smt_root`);
- not witnessable, not eligible for attestation weight;
- conferring zero stake, zero trust score, zero witness eligibility — a
  publisher "arrives as a newcomer with a verifiable past, never as a veteran"
  (`REALMS-SELF-ASSEMBLY.md:117-119`, the Zero-standing rule).

The imported records hang *beneath* the bundle as content addressed by
`bundle_merkle_root`. They are bytes a verifier can check against external
anchors offline (`elara-verify --inclusion … --anchor …`, the read-side tool);
they are not consensus participants.

---

## 4. Conflict-resolution rules for disjoint-DAG merge

These are the formal merge rules. They are deliberately restrictive: the only
"merge" permitted across a realm boundary is attestation-of-existence.

- **M1 — no cross-boundary settlement parents.** A native record MUST NOT name
  an imported record as a parent. The DAG edge that publication creates points
  *from* the public bundle *to* the imported set as content reference, never as
  a causal settlement parent. Enforcement: the bundle's `bundle_merkle_root` is
  data; imported record ids never appear in a native record's signed `parents`
  list. (Contrast: same-network cross-zone parents *are* allowed and finalized
  via `cross_zone_parents_finalized`, `consensus.rs:1928` — because they are
  one stake universe. Cross-*realm* parents have no representation and must
  gain none.)

- **M2 — the bundle is a leaf, not a root.** A publication enters as a single
  attested object. Imported records do not extend the public seal chain, do not
  alter `previous_seal_hash` linkage, and do not appear in any zone's
  `merkle_root` of *settled* records. They are committed *by* a record, not
  *as* records.

- **M3 — disjoint sub-DAGs are never reconciled (the key move).** Because
  imported records never enter the settlement set, two *conflicting* imported
  records — even two bundles that disagree about the same logical slot in the
  foreign realm — cannot create a public fork. They are just bytes inside two
  different attested bundles. The conflict-resolution rule for disjoint-DAG
  merge is therefore: **there is no reconciliation.** The public mesh does not
  adjudicate foreign conflicts; it attests only that each bundle existed. This
  is what makes the unsolved multi-root reconciliation problem *irrelevant to
  safety* rather than *blocking* — we don't solve cross-realm conflict
  resolution, we make it impossible to express in the public settlement graph.

- **M4 — idempotent / non-exclusive existence.** Re-publishing the same bundle
  root deduplicates (existence is already attested). The same imported record
  appearing in two different bundles is not a conflict: both bundles attest its
  existence under their own anchors, neither confers standing, and a verifier
  reading both simply sees two disclosures of the same bytes. Existence is
  monotone and non-exclusive; only native settlement is exclusive.

- **M5 — anchors travel with the bundle.** A bundle without a valid
  `time_bracket` is a bundle whose imported history has *no defended age*. M5
  does not reject such a bundle (existence is still attestable), but verifiers
  MUST surface "age unproven" for any record whose bracket is absent or whose
  anchor density is inconsistent with its claimed span (Anchor-density law,
  §6). Age credibility is a verifier-side verdict over external media, never a
  consensus claim.

---

## 5. Finality-preservation across the boundary — stated theorem (G3)

This section discharges gate **G3**: it hardens the prior sketch into a **stated
reduction** with an explicit assumption list and a *split* safety/liveness
conclusion, reviewed against Theorem 1 (Diversity-Weighted Safety) and
§5 (Theorem 3, Per-Record Causal Finality) of `docs/whitepaper/MESH-BFT-PAPER.pdf`. It is pen-and-paper, **not a
machine-checked proof** (mechanization is post-flip residue, §8). The assumption
list and the safety/liveness split are the product of an independent
adversarial review (fusion panel, 2026-06-15); each assumption carries its
enforcement status honestly — several are design-first gates, not invariants the
code upholds today.

### 5.1 The formal device — the settlement projection

For a mesh state `G` (the record DAG plus consensus bookkeeping), define the
**settlement projection**

> `π(G) = ⟨ V_s, E_s, I, S_total, d, A, Slot ⟩`

where `V_s` is the set of *settlement-relevant* records — those eligible to be
named as a parent of a settled record, to be witnessed/attested, or to enter the
account-state SMT or any seal `merkle_root`; `E_s` is the settlement-parent
relation restricted to `V_s`; `I`, `S_total`, `d` are the identity set, staked
supply, and diversity function; `A : V_s → 2^{I×stake}` is the attestation
assignment; and `Slot : V_s → LogicalSlot` is the conflict map (two records
conflict iff equal `Slot`, different value).

**The leverage:** both base theorems are predicates over `π(G)` *alone*. Theorem
2.1 quantifies over conflicting elements of `V_s` and sums `ES` over `A` against
`S_total`; Theorem 3 is about zones, committees, and the sealing of
`V_s`-records. Neither theorem mentions anything outside `π(G)`. So preservation
reduces to: *show bundle insertion leaves the relevant structure of `π`
invariant.*

### 5.2 Key lemma — bundle insertion is a conservative extension

Inserting a bundle `B` carrying foreign content set `F` is a transition
`G ↦ G' = insert(G, B, F)`: `B` is one native record; `F` hangs under
`bundle_merkle_root` as content.

> **Lemma 5.1 (Settlement-Projection Invariance).** Under A1–A9 (§5.3),
> `π(G') = π(G) ⊕ {B}` — insertion adds the single native vertex `B` (with its
> native parents and native attestations, occupying a *fresh* slot) and changes
> nothing else:
> (a) `F ∩ V_s(G') = ∅` — no foreign record is settlement-relevant;
> (b) `I, S_total, d` are identical in `π(G)` and `π(G')`;
> (c) `Slot` on `V_s(G') \ {B}` is unchanged, and `B` occupies a fresh native
> slot no prior record contends — so `B` adds no new conflict *pair* among prior
> records, and `B` itself conflicts with nothing, because publication existence
> is non-exclusive (M4, **subject to A4**);
> (d) `E_s(G') = E_s(G) ∪ {(B, p) : p ∈ native_parents(B)}` with
> `native_parents(B) ⊆ V_s(G)` — no settlement edge touches `F`.

### 5.3 Explicit assumptions (with enforcement status)

Legend: **✓** architecture upholds it today · **⚠** design-first, rides a gate ·
**✗** fork-sensitive / not yet enforced.

| # | Assumption | Enforcing rule / site | Status |
|---|------------|-----------------------|--------|
| **A1** | **Zero-standing** — no element of `F` adds to `S_total` or `I`, nor gains stake/trust/witness-eligibility. | Settlement reads native stake tables only (`is_settled_diverse`, `consensus.rs:2381`); `F` is never registered. | ✓ |
| **A2** | **No foreign settlement parents** — no native record's signed `parents` names an element of `F`. | M1, enforced as an *ingest predicate* (foreign/unknown parent ids rejected, not silently tolerated). `parents` is in `signable_bytes`, so this must be an enforced check, not a convention. | ⚠ G1 |
| **A3** | **No foreign state entries** — `F` enters no account SMT, `previous_seal_hash`, or settled `merkle_root`. | M2; the seal/SMT builder iterates settled *native* records only, and `F` lives under `bundle_merkle_root` *inside* `B`. | ✓ (once G1 types `B` as content-carrier) |
| **A4** | **No exclusive disclosure key** (M4 integrity) — bundle insertion writes **no** native key two bundles can contend: no `source_realm_root` uniqueness registry, no per-publisher exclusive counter. Re-publication dedups by *content-equality*, never by exclusive slot. | A *prohibition* on the bundle schema. If violated, two bundles claiming the same exclusive key are conflicting records — Lemma 5.1(c) breaks and 2.1's conflict-set is no longer invariant. | ⚠ G1 (stated ban) |
| **A5** | **Consensus-inert anchors** — consensus attests existence+publication of `B` only; `time_bracket` and `completeness_proof` are verifier-side. The drand not-before is **reference-only** (BLS unverified in-protocol); the Bitcoin/OTS existed-by is the trustless leg when its block header is pin-authenticated by the verifier (else reference). | M5; `ParsedEpochSeal` carries no bracket. In-protocol drand BLS verify is gate G2. | ✓ (reference-only honestly labelled) |
| **A6** | **Bounded ingestion** — bundle admission is rate/size-limited so `{B_i}` cannot exhaust a zone's per-epoch sealing budget (Theorem 3's *implicit* resource premise). | `assess_mega_publication` / `max_records_per_day` (`publish.rs`) — **retained but ADVISORY-ONLY today** (both call sites are tests). Must be wired as an enforcing admission gate. | ✗ new gate G6 |
| **A7** | **Bounded `F`-storage** — each `F` payload counts against the disk-pressure budget so no mega-bundle drives `under_avail_pressure()` true and starves **native** ingest. (The shared `insert_record_inner` funnel rejects *all* ingest under avail-pressure — `ingest.rs:473`.) Decide: `F` in-band (`⊆ B`, capped by `MAX_RECORD_BYTES = 64 KB`, so a large realm is *many* bundles — re-raising A6 at bundle granularity) vs out-of-band (content-addressed, needs its own bound the disk gate can see). | Open design decision + storage gate. | ✗ new gate G6 |
| **A8** | **No replay-as-native** (the dangling premise) — no foreign-origin record settles **natively** outside a bundle. Enforced *today at the settlement layer*: a foreign creator not staked in `P` cannot reach `⅔·S_total`, so a replayed foreign record ingests as inert spam (an A6/A7 concern) but **never settles**. It FAILS only under **cross-realm key reuse** — an identity staked in `P` that also signs in a foreign realm — where the replayed record is a bona-fide native record that *can* settle, re-importing foreign history through the back door the killswitch blocks. `signable_bytes` carries no realm (`record.rs:270`); the ingest funnel has no realm gate (verified). | **Operational** today: no `P`-staked identity may sign in a replayable foreign realm. Protocol fix: a realm/network domain-separator in `signable_bytes`. | ✗ new gate G5 (fork-sensitive) |
| **A9** | **Light-client / checkpoint inertness** — checkpoints commit native state roots only (M2/A3), so `F` cannot enter a light client's settled-state view; SDKs that *render* `B`'s content apply the three-attestor separation and never upgrade `F` to settled/witnessed status. | M2 + a read-side discipline note (the G4 verifier surface). | ✓ |

### 5.4 Theorem (safety unconditional, liveness conditional)

> **Theorem M1 (Inert-Import Finality Preservation — stated reduction).** Let
> `P` be a public MESH-BFT realm satisfying Theorem 1 and Theorem 3 of the
> paper. Let `{B_i}` be publication bundles, each a single native record of `P`
> carrying foreign content `F_i` under `bundle_merkle_root`. Then under A1–A9:
>
> **(Safety — unconditional given A1–A5, A8, A9.)** `P` continues to satisfy
> Theorem 1: no two conflicting native records both reach `is_settled_diverse`;
> each `B_i`'s existence-and-publication is settled by `P`'s own `S_total`
> exactly as any native record. Foreign conflicts *within* `F_i` lie outside
> `V_s` and are neither created nor adjudicated by `P`.
>
> **(Liveness — conditional on A6–A7.)** `P` continues to satisfy Theorem 3:
> every live zone's epochs seal within `(2^d − 1)·T_base` (plus the residual
> cross-zone round), **provided** bundle ingestion and `F`-storage are bounded so
> they neither exhaust a zone's per-epoch sealing budget nor trip the
> disk-pressure gate against native ingest.

**Proof structure.** Lemma 5.1 establishes that `insert(G, B, F)` is a
conservative extension of `π`. Since 2.1 and 5.2 are predicates over `π` alone:
*safety* transfers by π-invariance of `(I, S_total, d, conflict-relation,
attestation-map)` plus the fact that `B` settles under `is_settled_diverse` as a
native record (2.1 verbatim) and — by A4 — creates no new conflict slot;
*liveness* transfers because π's zone/committee structure is unchanged,
**conditional on** the sealing/ingest budget remaining adequate (A6/A7). ∎
*(stated reduction; not machine-checked.)*

**Why safety and liveness must be stated separately.** Safety reduces *cleanly*:
the settlement graph is closed under one `S_total` and a bundle adds no foreign
stake, no foreign parent, no foreign state, and — by A4 — no new exclusive slot.
Liveness does **not**: "settlement-inert" ≠ "liveness-inert." `B` rides the
*same* `insert_record_inner` funnel as any record and competes for ingest,
storage, and the per-epoch seal window with native traffic. The base theorem
bounds per-**epoch** sealing, not per-**record** wait — so under a bundle flood
concentrated in one zone (violating A6), native records in that zone can be
deferred behind the `MAX_SEAL_RECORDS = 1M` window *without any epoch failing to
seal*. That record-level liveness loss is real and is bounded only by A6/A7, not
by the inert-import structure.

### 5.5 The honest separation of attestations

Three distinct claims, three distinct attestors:
- `P`'s consensus attests: *this bundle existed and was published* (native
  finality of `B`).
- The anchor braid attests: *the underlying records existed by `T2`* (Bitcoin/OTS
  existed-by — trustless when the block header is pin-authenticated, offline) and *not before `T1`* (drand not-before —
  **reference-only** until the in-protocol BLS verify of G2 ships; see A5.
  Anchor trust model: existed-by is trustless only against a pin-authenticated
  Bitcoin header; not-before inherits drand's beacon trust).
- **Nobody** attests: *the imported records are true.* Publication ≠ endorsement
  (`REALMS-SELF-ASSEMBLY.md:122-123`, Attestation-semantics law).

This is why inert-import is sound where retroactive-witnessing was not: the old
model collapsed all three into "public consensus vouches for imported history,"
importing a foreign stake universe by the back door. Inert-import keeps them
separate and keeps the settlement graph closed under one `S_total`.

### 5.6 Scope — what the theorem does NOT guarantee

A careful reviewer (or a grant reader) must not over-read it. The theorem says
**nothing** about: the *truth* of any imported record; its *age* beyond the
anchor bracket (backdating within inter-anchor granularity is bounded, not
eliminated — §8); the *completeness* of `F_i` (`completeness_proof` is optional
and consensus-inert); *per-record* liveness under an A6-violating flood; and it
is **not** itself the guarantee that no foreign record can ever settle natively —
that is the separate A8 obligation, currently operational pending the G5
domain-separator. The guarantee is *settlement safety of `P`* and *conditional
liveness*, nothing more.

---

## 6. The four design laws as merge invariants

The `REALMS-SELF-ASSEMBLY.md` design laws map one-to-one onto this model:

| Law | Merge invariant |
|-----|-----------------|
| **Anchor-density** | Imported age is credible only to the density of the bundle's external anchor trail. Internal consistency proves nothing about *when*; backdating window = inter-anchor interval. Verifiers reject spans inconsistent with anchor density (M5). |
| **Zero-standing** | Imported records confer no stake, witness eligibility, or trust (§3). They never enter `S_total`, so they cannot perturb Theorem 1 (§5). |
| **Attestation-semantics** | Consensus attests existence + identity continuity + the publication event — never internal truth (§5, three-attestor separation). |
| **Ingestion-caps** | Bundle ingestion stays protocol-rate-limited, not publisher-voluntary (the `assess_mega_publication` / `max_records_per_day` machinery in `publish.rs:529-641` is retained for the bundle-rate dimension even though per-record import is dead). |

---

## 7. Gates to lift `NETWORK_PUBLISH_ENABLED`

`publish.rs` points re-enablement at "the gates in the audit memo." They are,
verbatim from the 2026-06-14 DAG-merge design audit:

- **G1 — inert-import object exists.** A publication-bundle record kind (§3)
  defined in the wire format and parser, distinct from per-record import; the
  imported set is content under `bundle_merkle_root`, never native records.
  (Rides REALMS task **P1.5(b)** — "anchor proofs as first-class records.")
- **G2 — external time anchoring is mandatory and enforced.** The `[T1, T2]`
  bracket (drand not-before inside the seal + Bitcoin/OTS existed-by) is
  required on every bundle and verified, not advisory. (Rides **P1.5(a2/a3)** —
  wire the drand pulse into `ParsedEpochSeal` + producer fetch; a2/a3 have
  landed — the opt-in `drand_pulse_enabled` fetcher populates the
  `time_bracket.rs` primitive on enabled producers — but in-protocol BLS
  verification stays unshipped, so this gate remains OPEN: consensus still
  treats the pulse as reference-only per A5.)
- **G3 — multi-root merge theorem stated and reviewed.** ✓ **STATED.** §5 is the
  hardened theorem (Theorem M1, *Inert-Import Finality Preservation*) with the
  explicit assumption list A1–A9, the settlement-projection lemma, and the
  split safety/liveness conclusion, reviewed against the paper's Theorem 1 +
  Theorem 3 via an independent adversarial fusion panel (2026-06-15). The
  *theorem statement* gate is met; the review **surfaced that three of its
  assumptions need their own enforcement gates** (G5, G6 below) before the
  theorem's hypotheses hold at runtime. Machine-checking is post-flip (§8).
- **G4 — honest age-proof shipped read-side.** The verifier surfaces "signatures
  carry no time; age is the anchor bracket, internal-truth is not attested"
  (spec §18.7). Largely shipped in `elara-verify` (`--anchor`/`--inclusion`);
  the bundle verdict path is the remaining slice.
- **G5 — realm domain-separator in the signed pre-image (closes A8).** A
  realm/network-id bound into `ValidationRecord::signable_bytes` (`record.rs:308`,
  which carries none today) so a signature is realm-scoped and a foreign record
  cannot be replayed as a *native* record under cross-realm key reuse. Until
  this ships, A8 holds only operationally (no `P`-staked identity signs in a
  replayable foreign realm). **Fork-sensitive** (changes the signing pre-image) —
  a supervised landing, not a pre-flip change.

  **DECISION (2026-06-22, pre-public-flip blocker review): SHIP G5 — but it is NOT
  reachable at the single-network public launch and is therefore gated to land
  before multi-realm federation interop, not before the initial flip.** Reasoning:
  the A8 replay vector requires a *foreign realm* whose records an identity also
  signs with its `P`-staked key; day-1 launch is a single network with the
  inert-import killswitch (`NETWORK_PUBLISH_ENABLED=false`) on, so no foreign realm
  exists to replay from. Implementation path (the version-gate mechanism already in
  `signable_bytes`, cf. the `version >= 5` nonce branch): add a `version >= 6`
  branch that binds a `network_id` domain tag, then enforce a **minimum wire
  version** at ingest (rejecting un-tagged records — the genuinely fork-sensitive
  step). Because it rewrites the signing pre-image and needs a re-genesis / flag-day
  to take effect, G5 is its **own fusion-audited work item**, not bundled into a
  hardening pass. **Interim published gate:** the single-network operating
  assumption (no cross-realm key reuse) is stated as an explicit, recorded design
  decision so the deferral is honest in public-facing docs, satisfying the
  "decide-before-genesis" obligation.
- **G6 — bounded-ingestion enforcement (closes A6/A7).** Wire the retained
  `assess_mega_publication` / `max_records_per_day` machinery (`publish.rs`,
  advisory-only today — both call sites are tests) into an *enforcing* admission
  gate, and bound the `F` payload against the disk-pressure budget (in-band vs
  out-of-band decision, A7). This is what makes the §5 *liveness* conclusion
  unconditional rather than conditional.

G1–G4 are design-first / read-side; G5 is a fork-sensitive seal/wire change and
G6 is an ingest-gate change. The kill-switch flips on only when **G1–G6** are all
green, by a supervised commit. (G5/G6 were promoted out of the G3 review on
2026-06-15: the theorem is only as true as the assumptions its hypotheses name,
and A6/A7/A8 were the assumptions the sketch left unenforced.)

---

## 8. Out of scope — honest residue

This document defines **disclosure**, not **interoperation**. The following
remain genuinely open and are explicitly *not* solved here:

- **True cross-realm settlement.** A value transfer that must be final in *both*
  realms (atomic cross-realm commit) is a strictly harder problem than
  disclosure and has no model here. Inert-import is one-way, read-only, and
  confers no standing — it is the antithesis of two-way settlement.
- **Federation gateways (REALMS P4).** Policy-gated *bidirectional* bridges
  between realms reopen the multi-`S_total` question and need their own
  treatment.
- **Backdating within the anchor interval.** The Anchor-density law bounds, but
  does not eliminate, backdating: a realm can fabricate history up to its
  inter-anchor granularity. The defense is denser anchoring, stated honestly,
  not a cryptographic impossibility claim.
- **Per-record liveness under a bundle flood.** The §5 liveness conclusion is
  conditional on A6/A7 and bounds *per-epoch* sealing, not *per-record* wait. A
  flood concentrated in one zone can defer native records behind the
  `MAX_SEAL_RECORDS = 1M` window without any epoch failing. Closing this is G6
  (enforced bounded ingestion); a per-record bounded-wait corollary to the
  paper's Theorem 3 does not exist and is not attempted here.
- **Replay-as-native under cross-realm key reuse.** A8 is enforced today only at
  the settlement layer (an unstaked foreign creator cannot reach `⅔·S_total`)
  and operationally (no `P`-staked identity signs in a replayable foreign realm).
  The protocol-level closure — a realm domain-separator in the signed pre-image —
  is G5, fork-sensitive and deferred. Until then it is a stated operational
  assumption, not an invariant.
- **A machine-checked safety proof.** §5 is now a *stated reduction* with explicit
  assumptions (discharging the G3 *statement*), not a Coq/TLA+ proof. The
  projection-invariance lemma's clauses are claims about what the ingest/seal/SMT
  paths uphold; mechanization — and the G5/G6 enforcement that makes the
  hypotheses true at runtime — is post-flip work.

The intent is conservative by construction: when in doubt, the public mesh
attests *less*, never more. A disclosure that cannot be safely modelled is
simply not expressible in the settlement graph — which is exactly why the merge
problem stops being a safety risk.
