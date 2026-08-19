#### 7.5.1 Zone Model: Semantic Subscription with Stake-Gated Consensus

Zones use hierarchical semantic paths that reflect real-world organizational and geographic structure:

```
"medical/eu/west/germany/bavaria"
"finance/global"
"iot/manufacturing/toyota/plant-7"
"personal/alice"
```

**Record routing** is determined by the record's `zone_refs` field — records go to zones based on their purpose and context. A medical record from a Bavarian hospital naturally belongs in `medical/eu/west/germany/bavaria`.

**Zone subscription** is voluntary — nodes choose which zones to store and process. A hospital server subscribes to `medical/eu/west`, a Toyota factory subscribes to `iot/manufacturing/toyota/*`, a phone subscribes only to its owner's personal zone. Nodes never store records for zones they don't subscribe to, enabling each node to hold a fraction of the global dataset.

**Consensus participation** is stake-gated — while any node can subscribe to store records, participating as a witness (attesting to epoch seals) requires:
- Minimum 100 beats staked
- PoW-verified identity with `min_pow_difficulty` (currently 16 bits)
- Identity age ≥ 48 hours
- Diversity check: no single entity or /24 IP subnet may control >33% of a zone's total staked weight

This separates Sybil resistance from zone assignment. The earlier hash-based model (`SHA3-256(public_key) mod NUM_ZONES`) provided Sybil-resistant zone assignment but created semantically meaningless groupings — a hospital might share a zone with unrelated IoT sensors. At quintillion-record scale, zone-scoped gossip REQUIRES semantic grouping to bound bandwidth. Sybil defense now operates at the witness admission layer through the existing mechanisms (PoW, stake, age, diversity scoring) rather than at the zone assignment layer.

**Zone splitting:** Zones split like biological cells when they grow too large. A zone exceeding a threshold of witnesses (>N) or records per epoch (>M) can split into sub-zones. Parent zone anchor nodes authorize the split through governance (Section 10.2). The hierarchical path naturally accommodates splitting: `medical/eu` can split into `medical/eu/west` and `medical/eu/east` without restructuring.

**Wire format:** Zone identifiers use variable-length hierarchical paths (wire format v3), replacing the previous `u8 zone_id` which limited the network to 256 zones.

#### 7.5.1.a Zone Transition Seals (v0.7.9+)

A zone split or merge is not a local decision. It changes the mapping from record IDs to leaf zones, and any attestation produced under the old mapping must be verifiable under the new mapping — otherwise the network forks. The protocol defines a **TransitionSeal** as the authoritative, anchor-co-signed record of a split or merge event.

A TransitionSeal is a record of kind `zone_transition` carrying:

- `transition_id` — UUIDv7 identifying the event.
- `kind` — `split` or `merge`.
- `parent_zone` — the zone being split, or for a merge, the set of zones being unified.
- `child_zones` — the resulting leaf zones. For a split, `|child_zones| ≥ 2`; for a merge, `|child_zones| = 1`.
- `boundary_function` — the invariant that defines how account identities route to child zones. The canonical form is `account_belongs_to_child(account_hash, child_zone) = SHA3(account_hash || parent_zone) ∈ child_range(child_zone)`, where each child_zone is allocated a contiguous range over the 2^256 hash space. This is deterministic, stateless, and verifiable by any light client given the TransitionSeal.
- `effective_epoch` — the epoch at which the transition takes effect. All records with timestamp `< effective_epoch × epoch_interval` route under the old mapping; records at or after route under the new mapping.
- `proposer` — the anchor node proposing the transition.
- `anchor_signatures` — an M-of-N Dilithium3 multi-signature over the canonical bytes, where M = 2/3 of the anchor pool at proposal time, and N is the pool size. Under 2^128 quantum attack models, M-of-N over Dilithium3 is the same security level as a single Dilithium3 signature (per §4.2), so the multi-sig is for trust distribution, not additional cryptographic strength.

**Invariants.** A TransitionSeal is valid iff:

1. `|child_zones| ≥ 2` (split) or `|parent_zones| ≥ 2 ∧ |child_zones| = 1` (merge).
2. `anchor_signatures.len() ≥ ceil(2 × N / 3)`.
3. Every signature in `anchor_signatures` verifies against a key in the anchor registry at `effective_epoch - dispute_window`.
4. The `boundary_function` partitions the parent's account-hash space without overlap or gap.
5. For a merge, the merged `child_zone` absorbs the union of every parent's records.

**Dispute window.** A TransitionSeal has a 3-epoch dispute window starting at `effective_epoch`. During the window, any anchor or witness can submit a counter-TransitionSeal (same `effective_epoch`, incompatible `boundary_function` or `child_zones`). If a counter-seal with ≥ M valid anchor signatures arrives before `effective_epoch + 3`, the original is rejected and the network continues under the pre-transition mapping. Only after the dispute window closes does the transition become part of the canonical zone registry.

**Replay through attestations.** Any attestation produced before `effective_epoch` attests to records under the pre-transition mapping. After `effective_epoch`, attestations are verified against the new mapping. A record created before `effective_epoch` but arriving at a peer after it is routed using a resolver: the peer walks the zone registry from the record's timestamp forward, applying each TransitionSeal's `boundary_function` in effective_epoch order. This is `resolve_current_leaf(record_id)` — O(log(transitions)) and free of locks.

**Light-client verification.** A light client fetches TransitionSeals alongside epoch seals during header-only sync. Given any account identity and the TransitionSeal chain, a light client can deterministically compute the current leaf zone for that account without ever storing records — just apply the boundary functions in order.

**Why M-of-N, not a single anchor signature.** A zone split redirects future records and retroactively re-partitions attestation validity. A compromised anchor could propose a malicious split to hijack a profitable zone's rewards. The 2/3-anchor threshold matches the witness-committee finality threshold and ensures no single anchor can unilaterally alter the zone topology.

