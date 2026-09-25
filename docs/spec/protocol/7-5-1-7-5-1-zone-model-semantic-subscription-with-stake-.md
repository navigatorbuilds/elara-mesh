#### 7.5.1 Zone Model: Semantic Subscription with Stake-Gated Consensus

Zones use hierarchical semantic paths that reflect real-world organizational and geographic structure:

```
"medical/eu/west/germany/bavaria"
"finance/global"
"iot/manufacturing/automotive/plant-7"
"personal/alice"
```

**Record routing** is determined by the record's `zone_refs` field — records go to zones based on their purpose and context. A medical record from a Bavarian hospital naturally belongs in `medical/eu/west/germany/bavaria`.

**Zone subscription** is voluntary — nodes choose which zones to store and process. A hospital server subscribes to `medical/eu/west`, a car factory subscribes to `iot/manufacturing/automotive/*`, a phone subscribes only to its owner's personal zone. Nodes never store records for zones they don't subscribe to, enabling each node to hold a fraction of the global dataset.

**Consensus participation** is stake-gated — while any node can subscribe to store records, participating as a witness (attesting to epoch seals) requires:
- Minimum 100 beats staked
- PoW-verified identity with `min_pow_difficulty` (default 20 bits)
- Identity age ≥ 48 hours
- Diversity check: no single entity or /24 IP subnet may control >33% of a zone's total staked weight

*Implementation-status note: the current runtime enforces these requirements only in part. Attestations pushed to a node are checked for the minimum stake and for identity age; attestations pulled from peers, or deferred until their record arrives, skip both checks. The age check requires one hour, not 48, counted from when the checking node first saw the identity, and exempts genesis validators. The `min_pow_difficulty` proof of work is checked when a node admits a peer to its peer table, not for the witness an attestation names; an attestation's own optional proof of work (PoWaS, Section 11.1) is verified when present, on the push paths and the batch pull. The diversity cap is defined in code but not applied. The runtime's `docs/KNOWN-LIMITATIONS.md` (limitations 23 and 34) gives the details.*

This separates Sybil resistance from zone assignment. The earlier hash-based model (`SHA3-256(public_key) mod NUM_ZONES`) provided Sybil-resistant zone assignment but created semantically meaningless groupings — a hospital might share a zone with unrelated IoT sensors. At quintillion-record scale, zone-scoped gossip REQUIRES semantic grouping to bound bandwidth. Sybil defense now operates at the witness admission layer through the existing mechanisms (PoW, stake, age, diversity scoring) rather than at the zone assignment layer.

**Zone splitting:** Zones split like biological cells when they grow too large. A zone exceeding a threshold of witnesses (>N) or records per epoch (>M) can split into sub-zones. Parent zone anchor nodes authorize the split through governance (Section 10.2). The hierarchical path naturally accommodates splitting: `medical/eu` can split into `medical/eu/west` and `medical/eu/east` without restructuring.

**Wire format:** Zone identifiers use variable-length hierarchical paths (wire format v3), replacing the previous `u8 zone_id` which limited the network to 256 zones.

*Implementation-status note: the semantic routing and storage model above is design-stage. In the current runtime a record's zone is derived from a SHA3-256 hash of its record id, not from its purpose or context. A record may also carry an explicit zone path (wire format v3); it is not covered by the creator's signature. `zone_refs` are causal anchors that nodes add after signing (Section 11.9), not a routing input. A node configured with zone subscriptions rejects records for other zones; with none configured, the default, it accepts every zone. Zone splits and merges are proposed as transition seals (Section 7.5.3), not through a governance vote.*

