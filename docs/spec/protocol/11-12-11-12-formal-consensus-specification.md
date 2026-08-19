### 11.12 Formal Consensus Specification

**The gap:** "Witness accumulation" is described conceptually throughout this paper but not formally specified. A reviewer expects Byzantine fault tolerance analysis, safety and liveness guarantees, and formal proofs or at minimum, precise algorithm specification.

**Specification: Adaptive Witness Consensus (AWC) — diversity-discount BFT on a DAG**

The Elara Protocol uses a consensus mechanism designed for its unique properties: threshold settlement with continuous trust accumulation, partition tolerance. AWC is an **Attestation-Weighted Consensus** layered over a DAG ledger with a diversity-weighted discount (§11.15) on correlated stake; it is internally also called **MESH-BFT** in code and tests (the `mesh-bft` cluster in the runtime is this mechanism).

**How it relates to prior art.** AWC is not a new Byzantine-fault-tolerance family; it is a composition of three well-studied building blocks applied to a DAG-sealed ledger:

1. **Stake-weighted probabilistic witness selection** — weighted reservoir sampling via Efraimidis & Spirakis (2006, *Information Processing Letters* 97(5)), used here for per-zone VRF committee picks (§11.18) without floating-point drift (u128 cross-multiplication).
2. **Per-record / per-epoch Byzantine agreement at the 1/3 safety bound** — directly descended from Castro & Liskov's Practical Byzantine Fault Tolerance (OSDI 1999), adapted so the "primary" is replaced by a VRF-selected witness committee and the "replicas" are the attestors of a given epoch seal.
3. **Two-layer finality** — a settlement/finality split analogous to Buterin & Griffith's finality gadget (Casper FFG, 2017): Layer-1 is per-record causal attestation (optimistic, ~seconds), Layer-2 is epoch-seal settlement at ≥2/3 diversity-weighted attested stake (durable, ~epoch interval).

AWC's novel contribution is (4) the **diversity discount** `d(n, W)` (§11.15): a scalar in [0, 1] that shrinks effective stake as the attestor set shows correlation in `WitnessProfile` fields (same org, same ASN, same subnet). A correlated-stake attacker with a majority of raw stake but a single profile collapses to a minority of *effective* stake, so the 2/3 threshold they cross is not a safety threshold. This is what makes AWC a meaningful strengthening of stake-weighted BFT for open-membership DAM deployments, not a rebrand of PBFT.

**Definitions:**

- **Record r** — a validation record on the DAM
- **Witness set W(r)** — the set of nodes that have attested to record r
- **Record trust score T(r)** — a continuous value in [0, 1] representing network confidence in a specific record
- **Node trust score T(n)** — a continuous value in [0, 1] representing a node's accumulated reputation, defined as T(n) = 1 - 1/(1 + attestation_count) where attestation_count is the number of honest attestations by that node. Node trust is earned through sustained honest behavior and cannot be purchased.
- **Witness weight w(n)** — the trust weight of node n's attestation, derived from its node trust score, stake, and age

> **Two levels of trust:** The protocol distinguishes between **node trust** (a node's reputation, earned over time) and **record trust** (network confidence in a specific record, computed from its witness set). Node trust feeds into record trust — a record witnessed by high-trust nodes accumulates record trust faster. The node-level formula is specified separately; this section specifies the record-level formula.

**Trust score computation:**

```
T(r) = 1 - ∏(1 - w(n) × d(n, W))  for all n in W(r)
```

Where d(n, W) is a **correlation discount** factor in (0, 1] that reduces a witness's marginal contribution based on its independence from other witnesses in the set:

```
d(n, W) = 1 / (1 + Σ corr(n, m) for all m ≠ n in W(r))

corr(n, m) = α × same_org(n,m) + β × same_subnet(n,m) + γ × same_zone(n,m)
             where α=0.5, β=0.3, γ=0.2
```

Witnesses from the same organization, IP subnet, or geographic zone contribute progressively less marginal trust. This prevents trust inflation through correlated attestation (e.g., a company running 1,000 witness nodes in one datacenter).

This formulation means:
- Zero witnesses → T = 0 (local only)
- One high-weight independent witness (w=0.5, d=1.0) → T = 0.5
- Multiple independent witnesses → T approaches 1 asymptotically
- Correlated witnesses (same org/subnet) → diminishing returns
- Trust never reaches exactly 1 (absolute certainty is impossible)

**Layered Consensus Model (v0.7.2)**

At production scale (quintillions of records across millions of zones), per-record attestation tracking becomes infeasible — unbounded state accumulation. The protocol uses a three-layer consensus model that preserves the per-record trust formula while achieving bounded-state epoch-level finalization.

**Layer 1 — Immediate Validation (per-record, sub-second):**

When a record arrives at a zone's witnesses, they perform immediate validation:
- Dilithium3 / SPHINCS+ signature verification
- Wire format and schema validation
- Balance sufficiency (for beat operations)
- Entropy score assessment (anti-spam)
- Duplicate detection

The per-record trust formula T(r) applies here. Each witness that validates a record contributes to its trust score. Records that pass Layer 1 are assigned status **Pending** and enter the current epoch's candidate set.

**Layer 2 — Epoch Finalization (per-batch, anchor-proposed):**

Each zone designates anchor nodes (high-trust witnesses with sealing authority, selected by VRF). At regular intervals (the anchor's seal loop ticks at a fixed configured interval, default 60s; a load-driven per-zone *adaptive* interval of 5–60s is computed and displayed but does not yet gate sealing, so quiet zones currently seal at the fixed interval — load-driven per-zone cadence is a design-stage item), the anchor proposes an epoch seal:

```
EpochSeal {
    epoch_number,           // per-zone counter (no cross-zone conflicts)
    zone_path,              // hierarchical zone identifier
    merkle_root,            // SHA3-256 Merkle root over all records in this epoch
    record_count,           // number of records in this epoch
    zone_balance_total,     // sum of all account balances in this zone
    previous_seal_hash,     // chain of seals back to genesis
    zone_registry_root,     // Merkle root of all known zones (not full list)
    zone_registry_delta,    // only zone changes since last seal
    vrf_output + proof,     // per-epoch seal seed (Dilithium3 hash-based selection, alg=0x11; output is publicly computable — unpredictable only until the prior epoch's seal is known)
    anchor_dilithium3_sig   // post-quantum signed by proposing anchor
}
```

The anchor proposes which records are in the epoch. Witnesses verify: (a) they have the same records, (b) all records pass Layer 1 validation, (c) the Merkle root matches their independent computation, (d) the zone_balance_total matches their ledger. If verified, witnesses attest to the seal by signing it.

The epoch boundary is deterministic by construction — the anchor's proposal defines what's in the epoch. Records arriving after the proposal go into the next epoch. This eliminates clock-drift consensus failures.

A record's status advances to **Sealed** upon inclusion in a proposed epoch seal, and to **Finalized** when the epoch seal accumulates attestations from witnesses controlling >67% of the zone's staked weight.

**Layer 3 — Post-Epoch Challenges (per-record, fisherman):**

After an epoch is sealed, fisherman nodes can challenge individual records within it:
- Challenge specifies: epoch number, zone, challenged record hash, evidence, Merkle proof of inclusion
- Jury selected via VRF (existing fisherman mechanism, Section 11.1)
- If upheld: the anchor that proposed the epoch receives FULL slash (they included the bad record). Attesting witnesses receive REDUCED slash (10-20% of standard, recognizing they attested to a batch). Non-attesting witnesses receive no penalty.
- A record surviving the challenge window (e.g., 24 hours) without challenge advances to **Anchored** status — the highest confirmation level.

**Confirmation levels:**

| Level | Definition |
|-------|-----------|
| **Pending** | Layer 1 validated, not yet in an epoch seal |
| **Sealed** | Included in an anchor-proposed epoch seal |
| **Finalized** | Epoch seal has >67% stake-weighted diverse attestations |
| **Anchored** | Finalized + challenge window elapsed with no upheld challenges |

**Safety guarantee:**

An epoch seal attested by witnesses controlling >67% of staked weight in a zone is considered **zone-settled**. All records within a zone-settled epoch are finalized. No conflicting epoch seal (different Merkle root for the same epoch number) can achieve settlement — the standard BFT bound applies to epoch seals exactly as it applied to per-record attestation. The MESH-BFT diversity-weighted safety property (stated as Theorem 1 in the formal specification; a TLA+ machine-checked proof is pending — see the implementation-status box below) is expected to hold because the diversity function d(n, W) applies to the set of epoch seal attestors.

**Liveness guarantee (honest-majority, observed):**

Under honest-majority (>50% of staked weight in a zone held by honest, online, non-correlated nodes) and partially-synchronous network assumptions, epoch seals reach 2/3 diversity-weighted attestation in **O(log_d N) × epoch_interval**, where `d` is the average out-degree of the gossip overlay and `N` is the zone's attestor count. The anchor-proposed model ensures deterministic epoch boundaries even under network asynchrony; seal propagation and quorum accumulation are the dominant terms.

*Observed on the testnet (2026-04-22 to 2026-04-23, 129-sample reading):* P50 seal settlement was ~2 × `epoch_interval` in practice (mean ~365s against the then-default 120s epoch; the default/cap has been 60s since 2026-04-29), with a long tail of witness-propagation lag on NAT'd peers. The `O(log_d N)` bound is the asymptotic ceiling under honest majority; the 2× observed constant is the small-network operational cost of gossip propagation rather than a violation of the bound. See the §11.12 implementation-status box and the seal-attestation-latency histogram on each node's `/metrics`.

**Partition behavior:**

During a network partition, each partition continues sealing epochs independently. Zone-scoped epoch numbers are per-zone, so different partitions' epochs do not conflict. When partitions merge:

1. DAM tips connect across fragments (W.parents = [tip_A, tip_B])
2. Epoch seal chains from both partitions are preserved and verifiable
3. Cross-partition records become verifiable via Merkle proofs from either partition's epoch seals
4. No fork choice — both histories are valid by the mesh property of the DAM

**Formal properties (preserved from MESH-BFT):**

- **Agreement:** If honest node A considers epoch E zone-settled, all honest nodes in the same zone will eventually consider E zone-settled (assuming partition heals)
- **Validity:** Only records signed by valid keypairs can be included in epoch seals
- **Termination:** Every record propagated to honest nodes will be included in an epoch seal within bounded time — O(log_d N) × epoch_interval under honest majority; observed P50 was ~2 × epoch_interval on the testnet
- **Partition safety:** Epochs settled before a partition remain settled in all resulting partitions

**Formal-proof status (honest).** This section is a *specification*, not a formal proof. Three safety/liveness properties are targeted for machine-checked proof work:

1. **Diversity-weighted safety** — correlated adversaries with k ≥ 2 Sybil identities sharing a `WitnessProfile` cannot achieve double settlement regardless of stake, because the diversity discount reduces effective stake exponentially.
2. **Post-quantum safety under one-algorithm break** — dual-algorithm signing (ML-DSA-65 + SLH-DSA) keeps consensus safe even if one of the two primitives is completely broken, with composite security λ_d + λ_s.
3. **Per-record causal finality** — under the layered model, records reach confirmation in O(1) epoch rounds and O(log n) wall-clock time, independent of total network size.

A TLA+ specification and Monte Carlo simulator are queued as follow-on artifacts (target 4Q 2026); a companion paper will be published alongside the formal specification once proofs are mechanized. Until then readers should treat §11.12 as the protocol's *design intent* under the honest-majority / diversity-weighted assumption, and audit a testnet's observed behavior (AWC settlement rate, seal-attestation-latency histogram, diversity counters on `/metrics`) for empirical evidence. No "simulation, 3600 scenarios, 0 violations" result is claimed here — the simulator has not been run on this codebase yet.

**Correlation discount in zone-scoped attestation:** Within a zone, the same_zone correlation discount (γ=0.2) does not apply to epoch seal attestation — all witnesses are necessarily in the same zone. The same_org (α=0.5) and same_subnet (β=0.3) discounts remain active and prevent trust inflation from correlated witnesses within a zone. Cross-zone diversity is achieved through the zone registry mechanism and cross-zone Merkle proof verification, not through within-zone attestation diversity.

**Scalability:** Consensus state is bounded by `pending_epochs × subscribed_zones`, not by total records. If the design targets of 10T records/day across 1M zones are reached, epoch length adapts within a 5-second floor (saturated zones above ~20 rec/s) to 60-second ceiling (quiet zones) band: a quiet zone produces 1,440 epoch seals per day, a saturated zone at most 17,280. A witness node in 3 saturated zones tracks at most ~52,000 epoch seals/day — trivially manageable, since only `pending_epochs` are unsettled at any moment and each seal is a small fixed-size record.

**Super-seal checkpoint consolidation (v0.7.9+).** Per-epoch seals are still O(time) — at 60-second P50 epochs, a zone produces 1,440 seals per day and 525,600 per year. Light clients verifying historical state from genesis to today would need to fetch every seal. The protocol consolidates seals into **super-seals**: every `N` epochs (default N=64, the `SUPER_SEAL_INTERVAL` constant), the anchor pool aggregates the Merkle roots of those N epoch seals into one super-seal, Dilithium3-signed once over the combined root. A light client verifying super-seals skips `(N-1)/N` signature verifications — at N=64, that's 63/64 ≈ 98.4% fewer signatures, or ~64× compression for a year-long chain. A super-seal includes: `super_seal_id`, `zone`, `start_epoch`, `end_epoch`, `epoch_seal_merkle_root` (SHA3-256 root over the N epoch seals' canonical bytes), `creator_public_key`, and the Dilithium3 signature. Super-seals are emitted by anchors and propagated like any other record. Light clients doing cold-start fetch `/super-seals/latest`, verify the signature against the anchor registry, then fetch per-epoch Merkle proofs for only those records they care about (e.g., their own account). The composition is sound under §4.2 post-quantum assumptions: SHA3-256 is treated as a random oracle, Dilithium3 is EUF-CMA-secure under MLWE, and a super-seal's `epoch_seal_merkle_root` being a correct commitment to N valid epoch seals reduces (by Merkle-tree soundness) to the verifier seeing at most 2^128 effective bits of adversarial work.

**Super-seal cross-peer verification.** A bootstrapping light client cross-verifies each super-seal's `epoch_seal_merkle_root` against up to 3 secondary peers' `/super-seals/{id}/integrity` endpoint. A peer with an incompatible root at the same `(zone, start_epoch, end_epoch)` triggers rejection — the client aborts the cold-start and retries with a different primary. Silence (peer has no super-seal for that range) is not disagreement. For tamper-resistance beyond Merkle-root agreement, the client also fetches the super-seal's wire bytes via `/records/fetch`, recomputes `record_hash`, and verifies the Dilithium3 signature against `creator_public_key` — this catches a colluding-seed set that all agree on a forged root but whose signatures don't verify. If record-bytes fetch fails, the skip is aborted rather than proceeding with unverified marks.

> **Implementation status:** AWC/MESH-BFT is implemented in the Elara Runtime (Rust, ~350k LOC, 5,700+ tests in the full suite). A multi-node testnet validated zone-based consensus with correlation discounting, dual-signature verification (Dilithium3 + SPHINCS+), gossip propagation (p50≈250ms, p90≈500ms on the small co-located testnet), beat transfers and staking, snapshot-based bootstrap (~3 seconds), and failure recovery; all nodes maintained identical supply (10B beats) across kills and restarts. The layered epoch-seal model is implemented: the first layered seal reached 2/3 diversity-weighted settlement on the testnet, and the Layer-2 settlement histogram accumulates samples while the same-zone diversity discount γ sits at its automatic honest-degradation value of 0 — for a single-bucket witness set γ is 0 by construction (`gamma_effective_scaled`: γ activates only once the witness set spans ≥2 distinct geographic buckets and ramps to its full 0.2 by 12 witnesses), so it engages automatically as the set diversifies toward mainnet. ZK proof scaffolding is in place with a fail-closed verifier; the STARK / lattice migration is tracked separately and is not yet deployed.

