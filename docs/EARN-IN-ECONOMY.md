# Earn-In Economy — post-pivot participation design

**The beat economy answers a structural question: with no sale, no airdrop,
and no exchange, how does anyone get in?** As implemented it is a locked room
with the keys inside — witnessing requires stake, throughput requires stake,
and every beat already exists (fixed supply, conservation invariant). A
tradeable coin would have had an implicit door ("they'll buy in"); that door
is gone on purpose. This document designs the replacement.

> **Status: design-first.** The free floor, the apprentice tier, and the
> cost-to-misbehave wiring below are *not yet built*. What exists today is the
> staking/witness machinery, idle-decay-fed pool recycling, a genesis-authority-
> gated `Slash` op, and equivocation detection (`ConflictProof`). This doc is the
> target; the "Honest open problems" section names what is unsolved. Per the
> project's honest-claims rule, nothing here is a security guarantee until it
> ships with tests.

**Principle: instant residency, slow citizenship.** You earn your way in by
verifying, not by paying. (Caveat, stated up front so the claim is honest: the
*first* beats a newcomer holds are seeded by the protocol's public endowment —
see "Where the first beats come from." You cannot *buy* your way in with money;
you can be *seeded* a starter balance and must then earn the rest. "Verify your
way in" describes the path past residency, not a claim that the network is
self-funding from beat zero.)

## The three doors

1. **Free participation floor (instant residency).** Every verified-unique
   identity gets a small base record-creation rate at zero beat cost — enough
   for a person, a sensor, or an agent doing real work; never enough for a
   farm. Inclusion mission: a $30 phone validates its own work free, forever.
   (Builds on the existing `base_rate` term in stake-gated throughput.)
   **Two guards make "never enough for a farm" true rather than asserted:**
   - The diversity/ASN fingerprint discount applies to the *creation floor
     itself*, not only to rewards and weight: N identities behind one
     fingerprint share one floor, they do not get N floors. (Today the
     diversity discount caps reward/weight only — extending it to free
     creation is design work, and is the difference between a bounded floor
     and an unbounded storage-DoS amplifier.)
   - Floor-tier records are **idle-decay/TTL-eligible**: a record from an
     identity that never earns its way to stake ages out of the hot tier
     unless pinned (staked) by some party who needs it. Free creation is not
     free *permanent* storage. The aggregate free-floor write rate per epoch
     is capped network-wide, not only per identity.

2. **Unstaked apprentice witnessing (the on-ramp).** New nodes may witness
   without stake. Their attestations carry **zero consensus weight** during
   apprenticeship (practicing, not voting) and are kept off the consensus
   committee hot path entirely — recorded in an observation log for reputation
   scoring, never aggregated into the weight tally (so a flood of zero-weight
   attestations cannot DoS the committee). Apprentices are *paid* for useful
   verification, which is what turns work into the stake that buys full weight.
   To make "useful" protocol-verifiable instead of self-declared (and to close
   the wash-trade ring):
   - An apprentice earns only for attestations that **match the eventual
     sealed outcome** — verifying records the real stake-weighted committee
     also finalized. A colluding ring that invents its own records and attests
     them to each other earns nothing, because those records never reach
     settlement by a non-colluding committee.
   - Probe/verification counterparties are **VRF-assigned, not self-selected**,
     so a ring cannot pre-arrange its signing pairs.
   - Apprentice rewards are **escrowed until citizenship and forfeit on
     misbehavior** — the apprenticeship year is skin-in-the-game, not a
     cash-flow-positive farm subsidy (see "Cost to attack while present").

3. **Genesis pools as a transparent public endowment.** The genesis
   allocations (`GenesisPool::{Bootstrap, Development, Community, Team,
   Contributors, Reserve}`) are the protocol's visible operational endowment:
   seeding community nodes, grants-in-kind, first-cohort funding. Every outflow
   is a public record. **Transparency is not the same as non-discretion**, and
   this doc does not pretend otherwise — see "Honest open problems: faucet
   governance."

## Where the first beats come from (closing the bootstrap loop)

The naive story "creators pay witness rewards" is **circular and, today,
false**: a brand-new creator holds zero beats, and in the current code witness
rewards are not paid by creators at all — they are debited from the
`conservation_pool` and authored by the genesis authority
(`accounting/validate.rs`). So the honest mechanism is:

**Rewards are protocol-funded redistribution from a finite conservation
endowment, not peer-to-peer payments and not new issuance.** The chain
recycles a fixed supply; it does not mint. The loop closes as:

```
endowment / conservation pool
      │  (protocol-authored reward for sealed-outcome-matching verification)
      ▼
apprentice earns beats  ──►  stakes  ──►  gains weight over the long clock
      │                                         │
      │ idle-decay (50%) + dormancy reclaim + slashed stake
      ▼                                         │
conservation pool  ◄─────────────────────────────┘  (recycle)
```

A newcomer's *very first* beats — enough to begin staking — come from a small
per-identity seed drawn from the endowment at verified-unique enrollment, OR
from apprentice rewards funded the same way. Either path is an endowment
draw, so the endowment runway is a real, boundable quantity, not an
afterthought.

## The reward budget is finite and self-throttling

This is the correction the original draft most needed. Under fixed supply,
"beats flow from day one for everyone, forever" is an **unfunded promise**. The
conservation pool is a *reservoir*, not a spring:

- **Inflow:** idle-decay redirected to the pool (50% of 0.005–0.30%/day on
  churning balances, `accounting/idle_decay.rs`), dormancy reclaims, and the pool's
  share of slashed stake. This is a small percentage of *circulating* beats per
  day — on the order of a tenth of a percent, not unbounded.
- **Outflow:** every reward paid. If outflow exceeds inflow, the pool drains;
  when it hits zero, rewards stop for everyone — a bank run that would freeze
  the network into whoever was already inside.

**Therefore reward rate must be a function of pool balance and trailing inflow,
not a flat constant.** Per-epoch total payout = `min(target, k · pool_inflow_
trailing_window)`, so payout auto-throttles to the recycling rate and the pool
never drains to zero. The bootstrap multiplier (higher early rewards while the
pool is full and participants are few) must be sized against the *real* pool,
not issued at a fixed 100× and hoped.

**The honest equilibrium statement:** at maturity, per-participant yield ≈
`pool_inflow / N_participants`. The more successful the network (the inclusion
goal is *billions* of devices), the smaller each participant's reward. This is
fine for a non-coin — the goal was never wealth, it is earning *enough* to
cross the stake threshold for full participation. But it imposes a hard design
constraint the original draft missed: **the stake threshold for citizenship
must scale down as N grows (or the floor must be generous enough) so a late
joiner in year 3 can still earn their way to full weight.** If the threshold
is fixed while yields shrink, "earn your way in" silently closes behind the
first cohort. Keeping that door open at scale is an open calibration problem,
named below.

## Calibration

Time + consistency are the entire sybil cost (capital purchase is removed by
design), so citizenship runs on institutional time, not consumer-app time:

- **Rewards earned fast, withdrawable slow, power slowest.** Beats accrue from
  the first useful attestation, but apprentice earnings are escrowed (forfeit
  on misbehavior) until citizenship. Consensus WEIGHT runs the longest clock.
- **Full citizenship: ~12 months sustained** — time served AND work volume AND
  ≥~80% epoch-consistency, on a non-linear ramp (effectively weightless for the
  first quarter; slow climb; full vote only after a year). Commit to one
  functional form (e.g. logistic) with published parameters so no join-timing
  strategy dominates honest continuous participation. **Time alone is not a
  cost** to a patient adversary, so the clock is paired with ongoing cost and
  escrow-forfeit (below) — it is a delay multiplier on top of a real cost, not
  the cost itself.
- **Weight decays continuously, not on a cliff.** Weight at epoch T is a
  function of the rolling mean of stake-weighted contribution over the trailing
  K epochs — a node at 60% uptime holds ~60% of earned weight, with no
  threshold band to duty-cycle against. The composition with liveness-decay
  (which ages dark stake out of the quorum *denominator*) must be specified and
  tested so a partially-dark fleet cannot *inflate* its relative weight by
  shrinking the denominator faster than its own numerator.
- **Diversity discount caps same-org/ASN fleets** regardless of citizenship —
  applied to creation, reward, and weight alike.

## Cost to attack while present (the biggest gap the audit found)

Every mechanism above gates the *entry path*. None of them constrain a
full-citizen actor who misbehaves *while present* — equivocating, selectively
attesting, censoring specific creators. A sophisticated adversary never goes
dark, so weight-decay never fires on it. Honest behavior costs effort
continuously; un-penalized misbehavior costs nothing. That asymmetry is fatal
and the original draft was silent on it.

The primitives exist but are not wired to participation:
- A `Slash` op exists (`accounting/validate.rs`, capped at 50% of stake,
  `MAX_SLASH_PERCENTAGE`), but it is **genesis-authority-gated** — discretionary,
  not automatic, and a single-key dependency.
- Equivocation/double-signing **is detected** (`ConflictProof`,
  `accounting/types.rs`), producing a self-evident proof at every honest node.

**Design need:** close the loop between detection and consequence. A
consensus-proven `ConflictProof` (or a proven conflicting attestation) should
**automatically** slash staked beats and forfeit accumulated weight + escrowed
apprentice earnings — no genesis-authority discretion in the path. Citizenship
must be *stake-at-risk*, not a one-way door. Until that lands, the network's
defense against a patient, present adversary is social exclusion plus
discretionary slashing, which is weaker than the entry gating implies.

## Honest open problems (design-first, unsolved)

1. **Endowment runway.** Bootstrap and floor seeding are endowment draws. The
   runway must be bounded against pessimistic enrollment curves; if it is
   reachable, the floor is a sunset subsidy and must say so.
2. **Late-joiner reachability at scale.** Per-participant yield → small as N
   grows; the stake threshold for citizenship must scale down (or the floor up)
   or the door closes behind the first cohort.
3. **Patient/sleeper farm.** Time + diversity + ongoing cost + escrow-forfeit
   raise the cost of a 10k-node year-long sleeper farm, but do not make it
   infinite for a state-scale adversary that can acquire genuine ASN diversity
   over a year. Rate-limiting network-wide *weight activation* per epoch (so N
   sleepers cannot wake into voting weight simultaneously) is a candidate
   backstop. This is mitigation, not a proof.
4. **Identity-gate strength is load-bearing and external.** The whole floor is
   only as strong as "verified-unique." State the required gate cost as a
   derived constraint: the floor is safe iff `cost_to_mint_identity` exceeds the
   marginal storage/throughput an identity can extract before it must stake.
5. **Non-transferability must be enforced in-protocol.** Beats must be
   identity-bound and non-transferable, or a fiat secondary market in
   *aged accounts* (private-key sale) reproduces "buy your way in" out of band.
6. **Faucet decentralization.** Reward authoring and endowment outflow are
   genesis-authority / multisig-gated today (a capturable, single-point-of-
   failure faucet). The target is *deterministic, permissionless* reward
   authoring — any node may author a reward record that carries a valid
   committee-attested proof of the work, with the pool debit validated by
   consensus, not authorized by one key. Discretionary grants stay discretionary
   and labeled; protocol rewards must not be.

**Why it matters strategically:** "you can only verify your way in" is the
anti-speculation positioning with teeth — the pivot as a feature, not a
renunciation. But it only survives contact with a skeptical reviewer if the
finite-budget math, the cost-to-misbehave wiring, and the open problems are
stated honestly rather than hand-waved. The first question every reviewer asks
("how does anyone join with no sale?") now has a real, bounded answer instead
of a circular one.

Related: docs/REALMS-SELF-ASSEMBLY.md (realm certs gate WHO may connect;
earn-in gates WEIGHT/throughput — orthogonal), docs/AGENT-DELEGATION.md,
docs/READ-SIDE-STRATEGY.md, docs/PROTOCOL-ECONOMICS.md (the implemented
fixed-supply / conservation / staking / slashing mechanics this design builds
on).
