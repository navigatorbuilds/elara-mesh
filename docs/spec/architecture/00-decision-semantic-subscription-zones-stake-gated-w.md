### Decision: Semantic subscription zones + stake-gated witnessing

**Why not hash-based (Protocol §7.5.1):** Hash-based distributes uniformly but creates meaningless groupings. A hospital querying medical records would share a zone with random IoT sensors. Zone-scoped gossip REQUIRES semantic grouping to reduce bandwidth. At quintillion scale, you need `iot/manufacturing/toyota/plant-7` to gossip only Toyota data, not random traffic.

**Why not pure subscription:** An attacker creates 10,000 identities all subscribing to `finance/global` and takes over that zone's consensus.

**Solution:** Semantic zones for routing and storage. Stake-gated admission for consensus.

- Records go to zones based on their PURPOSE (zone_refs field)
- Anyone can READ from any zone (Merkle proof verification, no trust needed)
- Anyone can STORE records in zones they're subscribed to
- To WITNESS a zone (consensus participation), you need:
  - Minimum 100 beats staked (existing requirement)
  - PoW identity with min_pow_difficulty (existing)
  - 48-hour identity age (existing)
  - Diversity check: no more than 33% of zone stake from any single entity/subnet

**Sybil defense transfers from zone assignment to witness admission.** The existing defenses (PoW, stake, age, diversity scoring) prevent zone takeover without requiring deterministic hash assignment.

**Protocol WP §7.5.1 needs updating:** Replace hash-based zone assignment with semantic subscription model. Document the stake-gated witness admission requirements.

