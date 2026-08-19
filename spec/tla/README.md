# Elara consensus — TLA+ formal model

A machine-checked TLA+ specification of the Elara MESH-BFT (Adaptive Witness
Consensus, "AWC") **settlement core** and its **cross-zone conservation core**,
model-checked with TLC.

This implements the safety phases of the project's formal-verification design
doc (Phase A + single-zone Phase B in `ElaraConsensus.tla`; cross-zone Phase C
in `ElaraXZone.tla`; supply-conservation Phase D in `Conservation.tla`) **plus
the cross-zone settlement LIVENESS phase** (Phase E in `ElaraXZoneLive.tla`)
**and the in-zone epoch-seal LIVENESS phase** (Phase E.2 in `Liveness.tla`),
**and the CROSS-EPOCH seal-recurrence phase** (Phase E.3 in
`LivenessRecurrence.tla` — the chain seals *forever*, not just once). It
turns the "formal verification — planned" line in the audit history into a real,
runnable artifact: `./run-tlc.sh` exhaustively checks the safety properties of
all three safety cores — proving the Byzantine-fault threshold is tight on the
two consensus cores, and that the two known partition-tail fixes are each
necessary for supply conservation — and the two liveness theorems of the
cross-zone core, proving a sealed transfer is never stuck in-flight forever.

## What is proved

| Property | Meaning | Doc ref |
|----------|---------|---------|
| **DiversitySoundness** | The AWC novelty. Diversity-weighting is *deflationary only*: a record's diversity-adjusted ("effective") stake can never exceed its raw attesting stake. If it could, a small correlated set could forge a 2/3 quorum — a catastrophic break. | §4.2 |
| **NoConflictingFinalization** | BFT *agreement*. Two conflicting records (claiming the same logical slot) can never both reach settlement while Byzantine stake stays below 1/3. | §4.1 |
| **NoAbortAndClaim** *(Phase C)* | Cross-zone *conservation*. A sealed transfer is never both claimed in the destination zone and aborted via a B-committee non-inclusion quorum — the cross-zone double-credit (recipient credited in zone B **and** sender refunded in zone A) can never happen while Byzantine stake in zone B's committee stays below 1/3. | §4.3 |
| **SealGateSound** *(Phase C)* | Structural conservation. Claim and abort require a *sealed* lock; the unsealed-refund paths (cancel/reject/passive-24h) require an *unsealed* lock. This code-path partition makes the "passive refund races a claim" double-credit impossible **without any** Byzantine-fraction assumption — it holds in every model, including the broken one. | §4.3 |
| **SupplyInvariant** *(Phase D)* | beat **conservation**: the four-bucket supply sum `Σbal + in-flight + staked + pool` — the *exact* equation enforced at `ledger.rs:206` — is invariant. The **normal** lifecycle (lock/seal/claim, sealed-abort, unsealed-refund, stake/mint/burn) conserves on every reachable path. Crucially, Phase D also proves the two known **partition tails** are genuine supply-inflation breaks *without* their fixes — with **zero Byzantine nodes**: `MCConsRevertBreak` inflates supply by `Amt` when `XZoneRevert` is absent (it is design-only / unimplemented today); `MCConsReapBreak` inflates by `Amt` when the 30-day reap/claim exclusion is defeated by a >30-day partition. These are *guard-necessity* proofs, not threshold-tightness; Phase D does **not** claim the live protocol conserves under partition. | §4.4 |
| **LiveFast** *(Phase E)* | Cross-zone **liveness**, fast path — the temporal DUAL of `NoAbortAndClaim`. With a live ≥2/3-honest zone-B committee AND partial synchrony (after GST), a sealed transfer eventually reaches a terminal state via the committee (Claimed or Aborted). This is the liveness dual of the Phase C bound: safety needs `f < 1/3` so Byzantine cannot forge TWO quorums; liveness needs `f < 1/3` so the honest remainder CAN form ONE. Convergence is *earned* (per-witness views resolved by weak-fair gossip-delivery actions after GST), not assumed by a global oracle. | §4.6 |
| **LiveBackstop** *(Phase E)* | Cross-zone **liveness**, unconditional. A sealed transfer eventually reaches a terminal state in **every** scenario — even with no GST and even at `f = 2` — because the quorum-FREE 30-day stale-reap (`REAP_HORIZON_SECS`) refunds the lock. The code is explicit that without a quorum a sealed transfer "stays Locked indefinitely" (`epoch.rs:5805`, `cross_zone.rs:768`), so the real *never-stuck-forever* guarantee is the reaper — it bounds the stuck window at ~30 days, NOT the abort quorum. This is the discriminating result: Byzantine/asynchrony can deny the fast path but cannot deny eventual reap. | §4.6 |
| **LiveLocal** *(Phase E.2)* | In-zone **liveness**, committee path. A zone eventually PRODUCES its epoch seal when some honest proposer is eligible in the VRF rank ladder AND honest attesting stake reaches 2/3 under local GST. Covers both the rank-0 fast sub-case (`MCInZoneLiveSafe`) and the *ladder* sub-case (`MCInZoneLiveLadder`: rank-0 Byzantine, a later honest rank unlocks by elapsed and still seals). This is the precondition Phase E folds into its `Sealed == TRUE`. Broken by no-GST, all-Byzantine-proposers, or honest attesting stake < 2/3. | §4.5 |
| **LiveWithEscalation** *(Phase E.2)* | In-zone **liveness** with the cross-zone escalation backstop. Even with **all** local proposers Byzantine, the zone still seals IF global GST holds and a 2/3-honest cross-zone quorum exists — modelled as an **explicit external committee**, not a `globalQuorumHealthy` flag (which would make it a vacuous two-state tautology). The headline asymmetry vs Phase E: there is **NO quorum-free in-zone floor** — an epoch seal *is itself* a 2/3 certificate, so global asynchrony (`MCInZoneLiveNoEscGST`) or global `f ≥ 1/3` (`MCInZoneLiveEscByz`) leaves the zone stuck, and the `staked < 3` freeze trap (`MCInZoneLiveBootstrap`) has no safety net at all. | §4.5 |
| **RecurSealed** *(Phase E.3)* | Cross-epoch **liveness**: the chain seals *forever* (`[]<>sealed`), not just once. Phase E.2 bounds the worst *single* epoch; this proves the worst case cannot **recur** indefinitely. Holds whenever every epoch seals by some path (local when the beacon makes the committee viable, escalation otherwise). Violated only when a pinned worst-case recurs with **no** escalation floor (`MCRecurGrindStall`) — the cross-epoch restatement of the no-quorum-free-floor asymmetry. | §4.5 |
| **RecurLocalSealed** *(Phase E.3)* | Cross-epoch **liveness**, fast path: the local committee path *recurs* (`[]<>(sealed ∧ ¬escalated)`). The headline contribution — it machine-checks that the **chained VRF beacon** (`chained_beacon`, `aggregator.rs:310`) re-randomizing proposer ranks each epoch is what keeps the protocol on its fast path. Holds under a re-randomizing beacon (`MCRecurSafe`, `MCRecurLadder`); **violated under a grindable / adversary-pinned beacon** (`MCRecurGrind`: the chain still seals, but only via escalation forever — a permanent liveness degradation). | §4.5 |

`DiversitySoundness` is the load-bearing one: it is the property unique to
Elara's correlation-discounted aggregation, and once it holds the classical BFT
argument carries the rest. It holds because `independence_q = Q²/(Q+Σcorr) ≤ Q`
for any non-negative correlation sum, so `effective = Σ stake·independence ≤
Q·raw`. TLC confirms this across every reachable attestation state.

## Why it has teeth — the tightness triples

A safety property is only meaningful if the model can also *violate* it. For
**each** core a safe/at-bound/broken triple pins the Byzantine threshold from
both sides at the canonical `n = 3f+1` boundary.

**In-zone settlement** (`ElaraConsensus.tla`):

| Model | n | Byzantine f | Result |
|-------|---|-------------|--------|
| `MCSafe` | 5 | 1 (`< 1/3`) | ✅ both invariants hold (incl. a maximally-correlated witness pair) |
| `MCTightSafe` | 4 | 1 (`= ⌊n/3⌋`) | ✅ agreement holds at the bound |
| `MCTightBreak` | 4 | 2 (`> 1/3`) | ❌ agreement **violated** — TLC prints the counterexample |

The `MCTightBreak` counterexample is the textbook double-finalization: two
Byzantine witnesses equivocate onto *both* conflicting records, each pairing
with one honest witness to manufacture a 3-of-4 quorum for two records at once.
This is the proof that the 1/3 bound is **necessary**, not merely sufficient
(the design doc's acceptance gate 3). `DiversitySoundness`
holds even in this broken run — it is a universal arithmetic truth, independent
of the Byzantine fraction.

**Cross-zone settlement** (`ElaraXZone.tla`, Phase C):

| Model | n | Byzantine f | Result |
|-------|---|-------------|--------|
| `MCXZoneSafe` | 5 | 1 (`< 1/3`) | ✅ both invariants hold |
| `MCXZoneTight` | 4 | 1 (`= ⌊n/3⌋`) | ✅ mutual exclusion holds at the bound |
| `MCXZoneBreak` | 4 | 2 (`> 1/3`) | ❌ `NoAbortAndClaim` **violated** — TLC prints the double-credit |
| `MCXZoneUnsealed` | 4 | 1 | ✅ seal-gate: claim/abort unreachable when unsealed (no BFT needed) |

The `MCXZoneBreak` counterexample is the cross-zone double-credit, structurally
identical to the in-zone double-finalization. The two Byzantine **zone-B**
committee members equivocate, signing *both* the claim seal and the XZoneAbort
non-inclusion proof; each pairs with one honest witness to forge a 3-of-4 quorum
for the claim (recipient credited in zone B) **and** the abort (sender refunded
in zone A) at once — value conjured from nothing. TLC's trace:

```
claimAtt = {w1, w3, w4}   \* 3/4 -> claim quorum  (w3,w4 Byzantine; w1 honest)
abortAtt = {w2, w3, w4}   \* 3/4 -> abort quorum  (w3,w4 Byzantine; w2 honest)
```

`SealGateSound` holds even in this broken run — like `DiversitySoundness`, it is
a structural code-path truth, independent of the Byzantine fraction. The
`MCXZoneUnsealed` model (Sealed = FALSE) collapses to 2 states: claim and abort
are both unreachable, so only the unsealed `Refund` path fires — the proof that
the seal-gate alone (no quorum, no honesty assumption) excludes the
passive-refund-races-claim double-credit.

### Why Phase C is a faithful specialization of Phase B

Both a global **claim** and a global **abort** require a 2/3 quorum of zone B's
committee: "Claimed" globally means zone B's consensus sealed the recipient's
claim record (a 2/3 zone-B quorum), and "Aborted" means ≥2/3 of zone B's
committee signed a non-inclusion attestation. An honest zone-B member that
sealed the claim will not also sign the non-inclusion abort — so it contributes
to **at most one side**, exactly as an honest witness in Phase B signs at most
one of two conflicting records. The quorum arithmetic is identical (note the
state counts: 324 / 108, the same as the in-zone triple), which is why the same
`n = 3f+1` bound governs both.

### Phase D — guard-necessity, not threshold-tightness

The Phase A/B/C triples pin a *Byzantine threshold*: each break needs `f > 1/3`.
Phase D's two breaks are a **different shape** — both counterexample traces
contain **zero Byzantine witnesses**. They are reachability proofs under a
network **partition** with a named protocol guard removed, proving each fix is
*individually necessary* for conservation:

| Model | Guards | Result |
|-------|--------|--------|
| `MCConsSafe` | XZoneRevert + reap/claim-exclusion **both ON** | ✅ SupplyInvariant holds (84 states) — the normal lifecycle conserves |
| `MCConsRevertBreak` | XZoneRevert **OFF** | ❌ supply `+Amt` via `Lock→Seal→Claim→SealDemote→ResolveSealDemotion` |
| `MCConsReapBreak` | reap/claim-exclusion **OFF** | ❌ supply `+Amt` via `Lock→Seal→Claim→SetStale→Reap` |

`XZoneRevert` is design-only / unimplemented in the live protocol;
the reap/claim exclusion holds under normal synchrony via the 24h claim-expiry
gate (`cross_zone.rs:420`) but is defeated by a >30-day partition where a
pre-expiry claim record applies after a reap. Phase D therefore formalizes
exactly *what conservation requires* — it does **not** assert the live protocol
already has it. The saturating-`sub` decrement is load-bearing in both breaks: a
double-release clamps the in-flight bucket to 0 instead of panicking, so the
double-credit surfaces as the supply inflation the invariant catches (rather
than a crash that would mask it).

### Phase E — liveness: the fast path vs the unconditional backstop

Phases A–D are *safety* ("nothing bad happens"). Phase E (`ElaraXZoneLive.tla`)
is the first *liveness* phase ("something good eventually happens") — the
temporal companion to Phase C. Where `NoAbortAndClaim` proves a sealed transfer
is never **both** claimed and aborted, Phase E proves it is never **stuck
in-flight forever**: it eventually reaches a terminal state. This is the formal
companion to the OPS-56 gauge `elara_xzone_sealed_locked_past_expiry_count`
(`cross_zone.rs:973`), which exists precisely to detect stuck-sealed transfers.

It is **two discriminating theorems**, not one:

| Model | Scenario | `LiveFast` (committee) | `LiveBackstop` (reap) |
|-------|----------|------------------------|-----------------------|
| `MCXZoneLiveSafe`     | n=4, f=1, GST eventually | ✅ holds | ✅ holds |
| `MCXZoneLiveNoGST`    | n=4, f=1, GST never      | ❌ **violated** | ✅ holds |
| `MCXZoneLiveByzStall` | n=4, f=2 (Byzantine removed) | ❌ **violated** | ✅ holds |

Each break breaks `LiveFast` for a **different** reason — no synchrony
(FLP-respecting) vs too few honest (`f ≥ 1/3`) — while `LiveBackstop` survives
in all three. That is the point: **Byzantine behaviour or asynchrony can deny
the fast committee path, but cannot deny the eventual quorum-free 30-day reap.**
The two `LiveFast` breaks are the liveness DUAL of the Phase C safety bound:
safety needs `f < 1/3` so the adversary cannot forge *two* quorums; liveness
needs `f < 1/3` so the honest remainder can form *one*. (TLC checks each theorem
in a separate invocation — `_Fast` with the reaper off so it cannot pre-empt the
committee terminal, `_Back` with the reaper on where a terminal of any kind,
including `Refunded`, satisfies the property.)

**Convergence is earned, not assumed.** There is no global "all honest agree
which side" oracle — that would assume the very thing liveness must establish.
Each honest witness has its own local `view ∈ {Unseen, SawClaim, PastTimeout}`,
resolved only *after* GST by weak-fair per-witness delivery actions that model
claim-gossip propagation. Pre-GST no view resolves, so honest cannot converge —
exactly the partial-synchrony premise.

**Faithfulness and honest scoping.** The honest weak-fairness abstracts the
best-effort retry-on-next-tick emitter (`epoch.rs:5808` uses `try_read`/
`try_lock` and "re-attempts on the next tick") which under a fair scheduler
eventually wins its locks — **not** a "deterministic per-tick emission." Phase E
covers the post-seal cross-zone lifecycle ONLY; the in-zone precondition (that
the source zone seals the lock at all) is the separate **Phase E.2** model
(`Liveness.tla`, §4.5 EventualFinalization), now landed (see below). GST is
abstracted to a flag (no message-level delivery bounds), and the unsealed
(pre-seal) refund path is out of scope.

### Phase E.2 — in-zone liveness: rank ladder, attestation snapshot, escalation

Phase E assumes a sealed transfer; Phase E.2 (`Liveness.tla`) proves a zone
eventually *produces* that seal. The in-zone mechanism is a **hybrid**, modelled
faithfully (NOT the textbook leader/view-change the code does not have):

1. **VRF rank ladder** (`aggregator.rs:290`) — a per-(zone,epoch) proposer order
   where rank-k becomes eligible only after `elapsed ≥ (2^k − 1)·base` (collapsed
   to a monotone unit ladder `phase`, since only the *order* matters for
   liveness). `LiveLocal` holds in both the rank-0 fast case and the *ladder*
   case (rank-0 Byzantine, a later honest rank unlocks and seals) — the latter is
   what makes the ladder guarantee distinct from the fast path.
2. **Leaderless 2/3 attestation snapshot** (`is_settled`, `consensus.rs:2515`) —
   any honest witness attests; the proposer's identity is irrelevant to
   settlement. GST-gated delivery is a weak-fairness obligation, exactly as Phase
   E's `DeliverClaim`.
3. **Cross-zone global-escalation backstop** (`escalation_decision`,
   `aggregator.rs:350`) — once the local ladder is exhausted, honest anchors in
   OTHER zones emit a global quorum seal. Modelled as an **explicit external 2/3
   committee** (`ExternalAnchors` / `extGst` / `QuorumExt`), NOT a
   `globalQuorumHealthy` flag — a flag would make `LiveWithEscalation` a vacuous
   two-state tautology that *assumes* the cross-zone liveness it should reduce to.

**The headline finding — no quorum-free floor.** Phase E's `LiveBackstop` is
*unconditional* (the quorum-free 30-day reaper refunds with no quorum). In-zone
liveness has **no analogue**: an epoch seal *is* a 2/3 quorum certificate, so it
cannot exist without a quorum. The weakest sufficient condition for `<>sealed`
is therefore global GST + global `f < 1/3` (the escalation path); both
`MCInZoneLiveNoEscGST` and `MCInZoneLiveEscByz` violate it, and the `staked < 3`
**freeze trap** (`MCInZoneLiveBootstrap`) is a liveness counterexample with no
safety net at all — the formal statement of the operational rule "never sit at 2
stakers; re-genesis 1 → 3 atomically." Cross-epoch chain progress (`[]<>sealed`)
rests on the chained VRF beacon re-randomizing ranks each epoch (anti-grinding) —
machine-checked in **Phase E.3** below.

### Phase E.3 — cross-epoch seal recurrence: the chained VRF beacon

Phase E.2 proves a *single* epoch eventually seals; a single epoch can be
adversarially stuck (all low ranks Byzantine) and need escalation.
`LivenessRecurrence.tla` proves the worst case cannot **recur** indefinitely:
the chain seals **forever** (`RecurSealed == []<>sealed`) and stays on its
**fast local path forever** (`RecurLocalSealed == []<>(sealed ∧ ¬escalated)`).

The mechanism under test is the **chained VRF beacon**
`chained_beacon(prev_seal_hash, epoch, zone)` (`aggregator.rs:310`): proposer
ranks are re-derived every epoch off the *previous* seal hash, which is not
known until that epoch seals and is honest-influenced — so an adversary cannot
predict or steer which identities land in eligible ranks next epoch, and so
cannot grind or *sustain* a worst-case rank assignment. The model folds the
only liveness-relevant per-epoch fact — is the local committee path viable this
epoch? (Phase E.2's proven `LiveLocal` precondition) — into one bit
`LocalViable == epoch ∈ ViableEpochs`, with `epoch` a counter that **wraps mod
`BeaconPeriod`**. `ViableEpochs` is therefore the beacon's coverage pattern over
one rotation, and it is a **constant the adversary does not choose** (it is the
hash output, not an adversary move). A deterministic wrapping counter is the
canonical adversary-*independent* witness of "coverage that recurs"; modelling
the choice as a fair non-deterministic action would be **wrong** — TLA+ weak
fairness does not force a fair resolution of a non-deterministic existential, so
worst-case-forever would be an admitted behaviour (the very thing the beacon
rules out). The grindable twin (`ViableEpochs = {}`) *is* that worst-case-
forever, and its property violation is what proves the re-randomization is
load-bearing.

| Scenario | Beacon / floor | `RecurSealed` | `RecurLocalSealed` |
| --- | --- | --- | --- |
| `MCRecurSafe` | re-randomizing (every slot viable), escalation up | holds | holds |
| `MCRecurLadder` | re-randomizing with a *periodic* worst-case slot, escalation up | holds | **holds** — the direct check that a captured rank cannot persist: the rotation always cycles an honest identity back into an eligible rank |
| `MCRecurGrind` | **grindable** (no slot viable), escalation up | holds (escalation seals every epoch) | **violated** — the fast path is lost forever; the chain degrades to escalation-only. Proves the beacon is load-bearing |
| `MCRecurGrindStall` | **grindable** + **no escalation floor** | **violated** — permanent stall | — |

The two violations are genuine fair lassos (TLC: `MCRecurGrind_Local` → "Back
to state 1" via `NextEpoch`, the escalate-every-epoch cycle; `MCRecurGrindStall`
→ "Stuttering", the stuck epoch). `MCRecurGrindStall`'s violation is the
**cross-epoch restatement of Phase E.2's no-quorum-free-floor asymmetry**: an
in-zone seal *is* a 2/3 certificate, so a sustained worst-case with no
escalation has nothing to rescue it.

**Composition, not re-derivation.** Phase E.3 takes Phase E.2's per-epoch
sealing conditions as established (local GST necessity, honest ≥ 2/3, the
escalation reduction, the bootstrap freeze trap all fold into `LocalViable` /
`EscalationAvailable`) and isolates the *new* cross-epoch beacon dimension —
re-expanding the witness-by-witness attestation here would only multiply the
state space without adding a guarantee. `EscalSeal` is gated on `¬LocalViable`
(faithful timing: `is_zone_stuck` fires only after the whole ladder times out,
so a viable epoch always seals locally far earlier than escalation unlocks).

## Fidelity to the implementation

The model mirrors the **deterministic fixed-point settlement path** in
`src/network/consensus.rs` (the `*_q` functions) — the path that actually gates
consensus. The float path is RPC/explorer-only and is deliberately not modelled.

| TLA+ operator | Rust function | Location |
|---------------|---------------|----------|
| `CorrQ` | `correlation_weighted_q` | `consensus.rs:2829` |
| `IndependenceQ` | `independence_q` | `consensus.rs:2862` |
| `EffStakeQ` | `effective_stake_q` | `consensus.rs:2884` |
| `DiverseSettled` | `diverse_threshold_met_q` (via `is_settled_diverse`) | `consensus.rs:2906`, `:2583` |
| `AttestHonest` / `AttestByz` | honest vs. equivocating attestation | — |

The correlation weights (`ALPHA:BETA:GAMMA = 0.5:0.3:0.2`, summing to the
`1.0` ceiling) match `consensus.rs:53–68`. The model scales the `SETTLEMENT_Q`
fixed-point base to **1000ths** instead of the code's `1e9` — TLC uses 32-bit
integers, and the settlement decision depends only on the ratios, so this is a
faithful re-scaling, not an approximation (anticipated in the design doc §3).

The **cross-zone** model (`ElaraXZone.tla`) mirrors `src/accounting/cross_zone.rs`:

| TLA+ operator | Rust function | Location |
|---------------|---------------|----------|
| `Quorum(S)` | the `n*3 >= size*2` count gate shared by **both** quorum verifiers | `verify_finality_quorum:1404`, `verify_abort_quorum:1523` |
| `Claimed` | `claim_transfer` → `status = Claimed` | `cross_zone.rs:464` |
| `Aborted` | `abort_transfer` → `status = Aborted` (B2-anchored dest committee) | `cross_zone.rs:657` |
| `unsealedRefund` | `cancel_transfer` / `reject_transfer` / passive `process_expired` | `cross_zone.rs:590`, `:699` |
| `SignClaim`/`SignAbort` | a zone-B committee member adding its attestation | — |

Both abort and seal-finality quorums are **plain count-based 2/3** in the code
(not diversity-weighted), so the cross-zone model's uniform "one witness = one
vote" is **exact**, not an abstraction (unlike the in-zone diversity math).

### Deliberate abstractions (documented)

- **Uniform stake** in the models — the BFT bound is a stake-*fraction*
  argument, so uniform stake exercises the `n = 3f+1` boundary crisply.
- **Full gamma** — the geo-diversity honest-degradation (`gamma_effective → 0`)
  is abstracted to full `GAMMA_Q`, which is the *conservative* direction (more
  correlation ⇒ lower effective stake ⇒ strictly harder for an adversary).
- **`creator_stake = 0`** — record creators are not modelled as witnesses.

### Cross-zone abstractions (Phase C, audited 2026-06-28)

- The honest "signs at most one side" rule is a **behavioral trust assumption**,
  not a code-enforced check — the same epistemic status as the in-zone model's
  `HonestFree`. The code relies on claim-record propagation so an honest zone-B
  member that sealed a claim sees the transfer is `Claimed` before the
  abort-signing loop selects it. Modeling it as an honest invariant is the
  standard BFT idealization.
- The zone-A seal-finality proof (a *separate* zone-A committee) is folded into
  the `Sealed` precondition: it makes the lock real and claimable, but the
  claim-vs-abort *conflict* lives entirely on zone B's committee. `claimAtt`
  models zone B's committee **view**, not the zone-A finality signers.
- Legacy/pre-B2 locks (`dest_finality_committee = None`) **cannot** be aborted
  (`verify_abort_quorum:1479` is fail-closed) — strictly safer (one fewer
  terminal). The model deliberately covers the harder anchored case where abort
  *is* possible, the conservative worst case for mutual exclusion.

> **Phase D update (2026-06-28).** `Sum(balances)+staked+in_flight+pool =
> TotalSupply` is now machine-checked in `Conservation.tla`, and both
> partition-tail breaks — **partition-merge seal demotion** (`XZoneRevert`)
> and **30-day stale-reap**
> (`cross_zone.rs:936`) — are modelled as reachable, zero-Byzantine
> supply-inflation counterexamples (see "Phase D — guard-necessity" above).

### Not yet modelled (future phases of the design doc)

- **Multi-transfer aggregate supply.** `Conservation.tla` models a *single*
  transfer; `transfer_id`s are independent so per-transfer conservation
  composes, but the cross-transfer `saturating_sub` masking aggregate (two
  transfers' in-flight decrements interacting) is a multi-transfer extension.
- **The cross-zone demotion-handling window.** `ResolveSealDemotion` is atomic
  in the model; the real-world window between the zone-A lock-debit revert and
  the zone-B `XZoneRevert` clawback is a *liveness/timing* concern, not a
  settled-state supply property — `SupplyInvariant` is checked on settled states.
  Phase E models claim/abort/reap progress for a sealed transfer; the
  demotion-window timing is not yet modelled.
- **In-zone epoch-seal liveness Phase E.2 — NOW MODELLED** (`Liveness.tla`,
  2026-06-28). The complementary in-zone liveness — that a zone's consensus
  eventually *produces* the seal Phase E folds into `Sealed == TRUE` — is
  machine-checked via the actual hybrid mechanism (VRF rank ladder + leaderless
  2/3 attestation + cross-zone escalation; the code has NO leader/view-change).
  Two sub-parts remain documented abstractions, not yet modelled: **(a) pre-GST
  multi-candidate attestation splitting** — competing per-rank seal candidates
  can split honest attestation below 2/3 until the weight-reconciler
  (`register_seal_with_reconcile`) collapses them post-GST; `Liveness.tla` models
  the single post-GST canonical candidate (the in-zone analogue of Phase E's
  `claimGossiped` branch) — this sub-part remains a documented abstraction.
- **Cross-epoch seal recurrence Phase E.3 — NOW MODELLED**
  (`LivenessRecurrence.tla`, 2026-06-29). `Liveness.tla` checks ONE epoch's
  seal; chain progress across epochs (`[]<>sealed`) rests on the chained VRF
  beacon (`chained_beacon(prev_seal_hash, …)`, `aggregator.rs:310`)
  re-randomizing proposer ranks every epoch so an adversary cannot *sustain* a
  worst-case rank assignment. Phase E.3 machine-checks exactly that: under a
  re-randomizing beacon the fast local path **recurs** (`RecurLocalSealed`),
  and the grindable-beacon twin **violates** it (the chain degrades to
  escalation-only forever) — proving the beacon is load-bearing. See *Phase
  E.3* below. The remaining sub-abstraction is the **per-epoch worst-case bound
  itself** (E.3 folds Phase E.2's proven sealing conditions into the single bit
  `LocalViable` rather than re-expanding the witness-by-witness attestation).

## Running it

```sh
./run-tlc.sh          # downloads tla2tools.jar to a cache if absent, then checks all 36 model invocations
```

Requires a JVM (Java 11+). The gate passes iff every model produces its
*expected* outcome — including the intentional `MCTightBreak` /
`MCConsRevertBreak` / `MCConsReapBreak` violations, so the runner asserts the
specific result rather than a bare exit code. Runs in seconds; each model is a
few hundred states or fewer.

```
--- Phase A/B: in-zone settlement core ---
PASS  MCSafe         (safety holds, 324 distinct states)
PASS  MCTightSafe    (safety holds, 108 distinct states)
PASS  MCTightBreak   (expected violation of NoConflictingFinalization reproduced - 1/3 bound is tight)
--- Phase C: cross-zone sealed-abort / claim mutual exclusion ---
PASS  MCXZoneSafe    (safety holds, 324 distinct states)
PASS  MCXZoneTight   (safety holds, 108 distinct states)
PASS  MCXZoneBreak   (expected violation of NoAbortAndClaim reproduced - 1/3 bound is tight)
PASS  MCXZoneUnsealed (safety holds, 2 distinct states)
--- Phase D: supply conservation / guard-necessity (zero-Byzantine, partition-reachable) ---
PASS  MCConsSafe        (safety holds, 84 distinct states)
PASS  MCConsRevertBreak (expected violation of SupplyInvariant reproduced - XZoneRevert guard is necessary)
PASS  MCConsReapBreak   (expected violation of SupplyInvariant reproduced - reap/claim-exclusion guard is necessary)
--- Phase E: cross-zone settlement liveness (partial synchrony + GST, 30d reap backstop) ---
PASS  MCXZoneLiveSafe_Fast      (LiveFast holds, 344 distinct states found)
PASS  MCXZoneLiveSafe_Back      (LiveBackstop holds, 760 distinct states found)
PASS  MCXZoneLiveNoGST_Fast     (expected violation of LiveFast reproduced - GST is necessary for the fast path)
PASS  MCXZoneLiveNoGST_Back     (LiveBackstop holds, 32 distinct states found)
PASS  MCXZoneLiveByzStall_Fast  (expected violation of LiveFast reproduced - honest >= 2/3 is necessary for the fast path)
PASS  MCXZoneLiveByzStall_Back  (LiveBackstop holds, 72 distinct states found)
--- Phase E.2: IN-ZONE epoch-seal liveness (VRF rank ladder + cross-zone escalation; NO quorum-free floor) ---
PASS  MCInZoneLiveSafe_Local      (LiveLocal holds, 96 distinct states found)
PASS  MCInZoneLiveSafe_Esc        (LiveWithEscalation holds, 143 distinct states found)
PASS  MCInZoneLiveLadder_Local    (LiveLocal holds, 76 distinct states found)
PASS  MCInZoneLiveLadder_Esc      (LiveWithEscalation holds, 123 distinct states found)
PASS  MCInZoneLiveNoGST_Local     (expected violation of LiveLocal reproduced - local GST is necessary for the committee path)
PASS  MCInZoneLiveNoGST_Esc       (LiveWithEscalation holds, 24 distinct states found)
PASS  MCInZoneLiveAllByz_Local    (expected violation of LiveLocal reproduced - an honest proposer is necessary for the committee path)
PASS  MCInZoneLiveAllByz_Esc      (LiveWithEscalation holds, 24 distinct states found)
PASS  MCInZoneLiveByzWit_Local    (expected violation of LiveLocal reproduced - honest >= 2/3 attesting stake is necessary)
PASS  MCInZoneLiveByzWit_Esc      (LiveWithEscalation holds, 84 distinct states found)
PASS  MCInZoneLiveNoEscGST_Esc    (expected violation of LiveWithEscalation reproduced - no quorum-free floor: global GST is necessary)
PASS  MCInZoneLiveEscByz_Esc      (expected violation of LiveWithEscalation reproduced - escalation needs a 2/3 cross-zone quorum)
PASS  MCInZoneLiveBootstrap_Esc   (expected violation of LiveWithEscalation reproduced - staked<3 freeze trap has no safety net)
--- Phase E.3: CROSS-EPOCH seal recurrence ([]<>sealed) — the chained VRF beacon re-randomizes ranks ---
PASS  MCRecurSafe_Any        (RecurSealed holds, 18 distinct states found)
PASS  MCRecurSafe_Local      (RecurLocalSealed holds, 18 distinct states found)
PASS  MCRecurLadder_Any      (RecurSealed holds, 16 distinct states found)
PASS  MCRecurLadder_Local    (RecurLocalSealed holds, 16 distinct states found)
PASS  MCRecurGrind_Any       (RecurSealed holds, 12 distinct states found)
PASS  MCRecurGrind_Local     (expected violation of RecurLocalSealed reproduced - a re-randomizing beacon is necessary for the fast path to recur)
PASS  MCRecurGrindStall_Any  (expected violation of RecurSealed reproduced - no quorum-free floor: a pinned worst-case with no escalation stalls forever)
ALL MODELS BEHAVED AS EXPECTED
```

## Files

- `ElaraConsensus.tla` — in-zone settlement spec (diversity math, state machine, invariants)
- `MCSafe.tla` / `.cfg` — safety + diversity model
- `MCTightSafe.tla` / `.cfg` — tightness, safe side (`f = 1`)
- `MCTightBreak.tla` / `.cfg` — tightness, broken side (`f = 2`, expected violation)
- `ElaraXZone.tla` — cross-zone conservation spec (Phase C: claim/abort mutual exclusion)
- `MCXZoneSafe.tla` / `.cfg` — cross-zone safety (`n = 5`, `f = 1`)
- `MCXZoneTight.tla` / `.cfg` — cross-zone tightness, safe side (`f = 1`)
- `MCXZoneBreak.tla` / `.cfg` — cross-zone tightness, broken side (`f = 2`, expected violation)
- `MCXZoneUnsealed.tla` / `.cfg` — seal-gate structural exclusion (`Sealed = FALSE`)
- `Conservation.tla` — supply-conservation spec (Phase D: four-bucket `SupplyInvariant`, two partition tails)
- `MCConsSafe.tla` / `.cfg` — conservation safety, both guards on (expected clean)
- `MCConsRevertBreak.tla` / `.cfg` — Tail 1: `XZoneRevert` absent (expected `SupplyInvariant` violation)
- `MCConsReapBreak.tla` / `.cfg` — Tail 2: reap/claim exclusion defeated by >30d partition (expected violation)
- `ElaraXZoneLive.tla` — cross-zone settlement LIVENESS spec (Phase E: `LiveFast` + `LiveBackstop`, per-witness views, GST, 30-day reap backstop)
- `MCXZoneLiveSafe.tla` — liveness safe scenario (`n = 4`, `f = 1`, GST reachable)
- `MCXZoneLiveNoGST.tla` — liveness no-GST scenario (GST never arrives)
- `MCXZoneLiveByzStall.tla` — liveness Byzantine-stall scenario (`f = 2`, Byzantine removed)
- `MCXZoneLive*_Fast.cfg` — `LiveFast` per scenario (reap off): safe holds; no-GST / Byz-stall expected violations
- `MCXZoneLive*_Back.cfg` — `LiveBackstop` per scenario (reap on): all three hold (the reaper always terminates)
- `Liveness.tla` — in-zone epoch-seal LIVENESS spec (Phase E.2: `LiveLocal` + `LiveWithEscalation`, VRF rank ladder + leaderless 2/3 attestation + explicit cross-zone escalation quorum; the no-quorum-free-floor asymmetry vs Phase E)
- `MCInZoneLiveSafe.tla` — E.2 safe baseline (rank-0 honest, GST reachable)
- `MCInZoneLiveLadder.tla` — E.2 ladder (rank-0 Byzantine, a later honest rank unlocks by elapsed)
- `MCInZoneLiveNoGST.tla` — E.2 no-local-GST (FLP: committee path violated, escalation holds)
- `MCInZoneLiveAllByz.tla` — E.2 all-proposers-Byzantine (committee dead, escalation rescues)
- `MCInZoneLiveByzWit.tla` — E.2 insufficient honest attesters (< 2/3 honest stake)
- `MCInZoneLiveNoEscGST.tla` — E.2 no-global-GST (no quorum-free floor: escalation violated)
- `MCInZoneLiveEscByz.tla` — E.2 escalation quorum too Byzantine (global `f ≥ 1/3`)
- `MCInZoneLiveBootstrap.tla` — E.2 `staked < 3` freeze trap (no safety net)
- `MCInZoneLive*_Local.cfg` — `LiveLocal` per scenario (escalation off): the committee path
- `MCInZoneLive*_Esc.cfg` — `LiveWithEscalation` per scenario (escalation on): full path incl. backstop
- `LivenessRecurrence.tla` — cross-epoch seal-recurrence LIVENESS spec (Phase E.3: `RecurSealed` + `RecurLocalSealed`, the chained VRF beacon re-randomizing ranks each epoch; the worst case cannot recur indefinitely)
- `MCRecurSafe.tla` — E.3 re-randomizing beacon, every epoch viable (both properties hold)
- `MCRecurLadder.tla` — E.3 periodic worst-case epoch, escalation covers it (both hold — a captured rank cannot persist)
- `MCRecurGrind.tla` — E.3 grindable / adversary-pinned beacon (`RecurSealed` holds via escalation; `RecurLocalSealed` violated — fast path lost forever)
- `MCRecurGrindStall.tla` — E.3 grindable beacon + no escalation floor (`RecurSealed` violated — permanent stall)
- `MCRecur*_Any.cfg` — `RecurSealed` per scenario (`[]<>sealed`)
- `MCRecur*_Local.cfg` — `RecurLocalSealed` per scenario (`[]<>(sealed ∧ ¬escalated)`)
- `run-tlc.sh` — the model-check gate (also runs in CI)
