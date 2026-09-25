### 11.12 Formal Consensus Specification

**The gap:** "Witness accumulation" is described conceptually throughout this paper but not formally specified. A reviewer expects Byzantine fault tolerance analysis, safety and liveness guarantees, and formal proofs or at minimum, precise algorithm specification.

**Specification: Adaptive Witness Consensus (AWC)**

The Elara Protocol uses a consensus mechanism designed for its unique properties: threshold settlement with continuous trust accumulation, partition tolerance. AWC is an **Attestation-Weighted Consensus** layered over a DAG ledger with a discount on correlated attestors (the correlation discount defined below); it is internally also called **MESH-BFT** in code and tests (the `mesh-bft` cluster in the runtime is this mechanism).

**How it relates to prior art.** AWC is not a new Byzantine-fault-tolerance family; it is a composition of three well-studied building blocks applied to a DAG-sealed ledger:

1. **Stake-weighted pseudo-random witness selection** — each candidate's priority is a hash of the epoch's VRF output and its identity divided by a stake weight, the lowest priorities win, and the arithmetic is integer (u128), so every node computes the same committee without floating-point drift. The shipped committee divides by the square root of stake, which is not split-neutral: splitting stake across identities raises the chance of selection (Section 11.12.3 of the whitepaper). An alternative that divides by stake itself (`use_committee_v2`, off by default) is modelled on the weighted sampling of Efraimidis & Spirakis (2006, *Information Processing Letters* 97(5)) but does not reproduce it: their key, −ln(u)/w, selects in proportion to stake, while u/w favours larger stakes more than proportionally.
2. **Per-record / per-epoch Byzantine agreement at the 1/3 safety bound** — directly descended from Castro & Liskov's Practical Byzantine Fault Tolerance (OSDI 1999), adapted so the "primary" is replaced by a stake-ranked proposer (ranked by a beacon chained from the previous seal, Section 11.12.3 of the whitepaper) and the "replicas" are the attestors of a given epoch seal.
3. **Two-layer finality** — a settlement/finality split analogous to Buterin & Griffith's finality gadget (Casper FFG, 2017): Layer-1 is per-record attestation, durable once attesting stake reaches at least 2/3 of the zone's eligible stake, excluding the creator; Layer-2 is epoch-seal settlement at ≥2/3 diversity-weighted attested stake (~epoch interval), which is not live in the current implementation (see the safety guarantee below).

AWC's distinguishing addition is (4) the **diversity discount** `d(n, W)` (defined below): a factor in (0, 1] that lowers the weight of attestors that share an organization, subnet or location. The organization, subnet and location fields of a `WitnessProfile` are self-reported; the node also observes each witness's network prefix and provider. The discount does not raise the 1/3 bound against an adversary whose identities are spread across distinct organizations, subnets and locations. In the current implementation it is reported as a confirmation level and does not gate finality, so the safety bound is the stake-weighted one: Byzantine stake below one third.

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

corr(n, m) = α × same_org(n,m) + β × same_subnet(n,m) + γ × same_geo(n,m)
             where α=0.5, β=0.3, γ=0.2 (ramped — see below)
```

Witnesses from the same organization or IP subnet contribute progressively less marginal trust. This prevents trust inflation through correlated attestation (e.g., a company running 1,000 witness nodes in one datacenter). The third term weights *geographic* overlap (`same_geo`), not consensus-zone membership: a zone-membership discount would be meaningless because all epoch-seal attestors necessarily share a consensus zone. The shipped runtime sets γ=0.2 with an honest-degradation ramp — γ reads 0 with fewer than 2 distinct geographic buckets (or no more than 2 witnesses), rises linearly with witness-set size, and reaches the full 0.2 at 12 or more witnesses, so a thin witness set never manufactures a false diversity signal. A fully-correlated witness pair reaches the maximum discount α+β+γ = 1.0. (This supersedes the v0.7.3 "audit E2" text that set the third term to 0.0 as a zone-membership discount; the geographic meaning is detailed under "Correlation discount in zone-scoped attestation" below.)

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

Each zone designates anchor nodes (high-trust witnesses with sealing authority; which anchor proposes is set by the stake-weighted rank of Section 11.12.3 of the whitepaper). At regular intervals (the anchor's seal loop ticks at a fixed configured interval, default 60s; a load-driven per-zone *adaptive* interval of 5–60s is computed and displayed; a gate that applies it to sealing is implemented but off by default (`ELARA_USE_ADAPTIVE_SEAL_GATE`), so with default settings every zone seals at the fixed interval), the anchor proposes an epoch seal:

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

A record's status advances to **Sealed** upon inclusion in a proposed epoch seal, and to **Finalized** when the epoch seal accumulates attestations from witnesses controlling at least 2/3 of the zone's staked weight. (Status: seal settlement is not live in the current implementation — see the safety guarantee below; records finalize through per-record settlement.)

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
| **Finalized** | Epoch seal has ≥ 2/3 stake-weighted diverse attestations |
| **Anchored** | Finalized + challenge window elapsed with no upheld challenges |

**Safety guarantee:**

An epoch seal attested by witnesses controlling at least 2/3 of staked weight in a zone is considered **zone-settled**. All records within a zone-settled epoch are finalized. No conflicting epoch seal (different Merkle root for the same epoch number) can achieve settlement — the standard BFT bound applies to epoch seals exactly as it applied to per-record attestation. The MESH-BFT diversity-weighted safety theorem (Theorem 1 of the companion paper) holds because the diversity function d(n, W) applies to the set of epoch seal attestors. Theorem 1 holds only while Byzantine stake stays below one third. **Status:** seal settlement is not live in the current implementation: with default configuration a seal with two or more attesters cannot reach the diversity-weighted threshold, and a stuck seal does not escalate. Records finalize through per-record settlement.

**Liveness guarantee:**

As long as >50% of staked weight in a zone is held by honest, online nodes, new epochs will be sealed and attested within one epoch interval, provided the proposer ranking cannot be steered by the previous sealer, which the shipped beacon does not guarantee (Section 11.12.3 of the whitepaper). Seal *finality* is not live in the current implementation (see the safety guarantee above). The anchor-proposed model ensures deterministic epoch boundaries even under network asynchrony. Note the gap between the two thresholds: with honest-online weight between 50% and 2/3, the zone keeps *producing* seals but cannot *finalize* them (finalization requires ≥ 2/3 attesting weight) — safety is preserved while finality liveness degrades until enough weight returns.

**Partition behavior:**

During a network partition, each partition continues sealing epochs independently. Zone-scoped epoch numbers are per-zone, so different partitions' epochs do not conflict. When partitions merge:

1. DAM tips connect across fragments (W.parents = [tip_A, tip_B])
2. Epoch seal chains from both partitions are preserved and verifiable
3. Cross-partition records become verifiable via Merkle proofs from either partition's epoch seals
4. No fork choice — both histories are valid by the mesh property of the DAM

**Formal properties (preserved from MESH-BFT):**

- **Agreement:** If honest node A considers epoch E zone-settled, all honest nodes in the same zone will eventually consider E zone-settled (assuming partition heals)
- **Validity:** Only records signed by valid keypairs can be included in epoch seals
- **Termination:** Every record propagated to honest nodes will be included in an epoch seal within bounded time (one epoch interval)
- **Partition safety:** Epochs settled before a partition remain settled in all resulting partitions

These properties are those of the design. Agreement and partition safety assume Byzantine stake below one third; termination assumes an unsteered proposer ranking, which the shipped beacon provides only while the previous sealer is honest (Section 11.12.3 of the whitepaper). As shipped, seal settlement is not live (safety guarantee above), so Agreement and Partition safety currently hold trivially for epoch seals.

Formal proofs are provided in the companion paper: "MESH-BFT: Diversity-Weighted Post-Quantum Byzantine Fault Tolerance for Directed Acyclic Meshes" (Vasic, 2026). The companion paper states four theorems. Theorems 1–3 carry proofs (Theorem 1 relies on a slot-mutex lemma that is only sketched); Theorem 4, bounded-view liveness (Section 11.12.3, Part F, of the whitepaper), has a proof sketch only. As corrected in v0.7.38: (1) *safety* — two conflicting records cannot both settle while the total stake of Byzantine identities stays below one third of all stake. Diversity weighting lowers the weight of witnesses that share an organization, subnet or location; it does not raise the 1/3 bound against an adversary whose identities are spread across distinct ones; (2) *post-quantum unforgeability of Profile A records* — the AND-composition of ML-DSA-65 and SPHINCS+ is at least as strong as the stronger scheme (about 192 bits), assuming each SPHINCS+ key is bound to its identity (not yet done; Section 4.3). Witness attestations carry one ML-DSA-65 signature, so if ML-DSA-65 is broken, attestations and therefore settlement can be forged; Profile A protects record authorship, not consensus; (3) *per-record causal finality* — records achieve confirmation in O(1) epoch rounds and O(log n) wall-clock time, independent of total network size. The theorem's settlement rule is diversity-weighted; the current implementation settles on eligible stake without the diversity weighting (Section 3.2, Layer 2). A Monte Carlo safety simulation (`tools/mesh-bft-sim` in the reference implementation: a 64-combination adversary grid — network sizes 10–500, Byzantine fraction up to 0.33, sybil cluster size up to 50 — with zero double-settlement violations) supports the diversity-discount result; it runs at the companion paper's original correlation parameterization (γ = 0.1), and re-validation at the shipped runtime constants (γ = 0.2, correlation cap 1.0) is pending.

Bounded instances are model-checked in TLA+ (`spec/tla/`, a 36-model gate). The liveness models use uniform stake, set the record creator's stake to zero and let Byzantine proposers only withhold; their passing configurations assume an unsteerable beacon, and their failing twins show that the fast path is lost when the beacon can be steered, as the shipped one can.

**Correlation discount in zone-scoped attestation:** The γ term weights *geographic* overlap, not consensus-zone membership (all epoch-seal attestors necessarily share a consensus zone, which would make a zone-membership discount meaningless). The shipped runtime sets γ=0.2 over geographic buckets with an honest-degradation ramp: γ reads 0 when fewer than 2 distinct geographic buckets (or no more than 2 witnesses) are present, ramps linearly with witness-set size, and reaches the full 0.2 at 12 or more witnesses — a thin witness set never manufactures a false diversity signal. The same_org (α=0.5) and same_subnet (β=0.3) discounts remain active and prevent trust inflation from correlated witnesses within a zone; a fully-correlated witness pair reaches the maximum discount α+β+γ=1.0. Cross-zone diversity is additionally achieved through the zone registry mechanism and cross-zone Merkle proof verification.

**Scalability:** Consensus state is bounded by `pending_epochs × subscribed_zones`, not by total records. If the design targets of 10T records/day across 1M zones are reached, and once the adaptive interval gates sealing (its gate is off by default; see Layer 2 above), epoch length adapts between a 5-second floor (saturated zones, above ~20 rec/s) and a 60-second ceiling (quiet zones): a quiet zone produces 1,440 epoch seals per day, a saturated zone at most 17,280. A witness node in 3 saturated zones tracks at most ~52,000 epoch seals/day, and only `pending_epochs` are unsettled at any moment.

**Super-seal checkpoint consolidation (v0.7.9+).** Per-epoch seals are still O(time) — at 60-second P50 epochs, a zone produces 1,440 seals per day and 525,600 per year. Light clients verifying historical state from genesis to today would need to fetch every seal. The protocol consolidates seals into **super-seals**: every `N` epochs (default N=64, the `SUPER_SEAL_INTERVAL` constant), the anchor pool aggregates the Merkle roots of those N epoch seals into one super-seal, Dilithium3-signed once over the combined root. A light client verifying super-seals skips `(N-1)/N` signature verifications — at N=64, that's 63/64 ≈ 98.4% fewer signatures, or ~64× compression for a year-long chain. A super-seal includes: `super_seal_id`, `zone`, `start_epoch`, `end_epoch`, `epoch_seal_merkle_root` (SHA3-256 root over the N epoch seals' canonical bytes), `creator_public_key`, and the Dilithium3 signature. Super-seals are emitted by anchors and propagated like any other record. Light clients doing cold-start fetch `/super-seals/latest`, verify the signature against the anchor registry, then fetch per-epoch Merkle proofs for only those records they care about (e.g., their own account). The composition is sound under §4.2 post-quantum assumptions: SHA3-256 is treated as a random oracle, Dilithium3 is EUF-CMA-secure under MLWE, and a super-seal's `epoch_seal_merkle_root` being a correct commitment to N valid epoch seals reduces (by Merkle-tree soundness) to the verifier seeing at most 2^128 effective bits of adversarial work.

**Super-seal cross-peer verification.** A bootstrapping light client cross-verifies each super-seal's `epoch_seal_merkle_root` against up to 3 secondary peers' `/super-seals/{id}/integrity` endpoint. A peer with an incompatible root at the same `(zone, start_epoch, end_epoch)` triggers rejection — the client aborts the cold-start and retries with a different primary. Silence (peer has no super-seal for that range) is not disagreement. For tamper-resistance beyond Merkle-root agreement, the client also fetches the super-seal's wire bytes via `/records/fetch`, recomputes `record_hash`, and verifies the Dilithium3 signature against `creator_public_key` — this catches a colluding-seed set that all agree on a forged root but whose signatures don't verify. If record-bytes fetch fails, the skip is aborted rather than proceeding with unverified marks.

> **Implementation status:** AWC/MESH-BFT is implemented in the Elara Runtime (Rust, ~410k lines, 7,000+ tests). A multi-node development testnet (since retired) validated: zone-based consensus with correlation discounting (zone_count=2 forced), dual-signature verification (ML-DSA-65 + SPHINCS+), gossip propagation (p50=250ms, p90=500ms), ZK proof scaffolding with a fail-closed verifier, beat transfers and staking, checkpoint-based startup (31µs replay), cross-zone transfers, and failure recovery. All nodes maintained identical supply (10B beats) across kills, restarts, partitions, and re-genesis, with 12K–21K settled records per node across 5+ days of continuous operation. The layered consensus model — epoch sealing, multi-anchor proposals, differentiated fisherman penalties, peer liveness probes, zone-scoped gossip, cross-zone transfers, batch consensus processing, per-peer attestation watermarks, and priority eviction — is implemented. Epoch-seal settlement is implemented but not yet live (Section 11.12, safety guarantee). The current test network has one staked node, the genesis authority, so it tolerates no Byzantine fault yet; below three staked anchors only the genesis authority proposes seals (bootstrap carve-out, Section 11.12.3 Part B.2 of the whitepaper).

