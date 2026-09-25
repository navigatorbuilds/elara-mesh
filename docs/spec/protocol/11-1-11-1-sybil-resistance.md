### 11.1 Sybil Resistance

**The attack:** An adversary generates one million keypairs and creates one million fake "witness" nodes. Every validation record they publish instantly accumulates a million witnesses, making fraudulent claims appear globally trusted.

This is the oldest problem in decentralized systems. The Elara Protocol addresses it through layered defense:

**Layer 1: Proof of Work-at-Stake (PoWaS)**

Witness attestation is not free. To attest to a validation record, a witness node must:

1. Stake a minimum amount of beats (economic cost)
2. Solve a lightweight proof-of-work puzzle calibrated to the attestation (computational cost — not industrial-scale mining, but enough to make mass attestation expensive)
3. Maintain a reputation score based on attestation history (time cost)

**PoWaS puzzle construction:**

```
puzzle_input  = SHA3-256(record_id || witness_pubkey || nonce)
difficulty    = BASE_DIFFICULTY × 1000 / sqrt(stake_base_units)
target        = 2^256 / difficulty
valid_if      = puzzle_input < target
```

The difficulty is inversely proportional to the square root of the witness's staked amount, bounded by a minimum and maximum difficulty to prevent both trivial solutions by large stakers and impossible puzzles for small stakers:

```
effective_difficulty = clamp(difficulty, MIN_DIFFICULTY, MAX_DIFFICULTY)
where MIN_DIFFICULTY = BASE_DIFFICULTY / 10 (no one gets a free pass)
      MAX_DIFFICULTY = BASE_DIFFICULTY × 10 (minimum stake is viable)
```

With stake measured in base units (10⁹ per beat), the unclamped inverse-sqrt curve differentiates only sub-floor stakes: every witness at or above the 100-beat admission floor clamps to MIN_DIFFICULTY, so all admitted witnesses perform the same minimum work — the curve's differentiation is a property of the sub-floor band, not of the admitted set. The bounds ensure that very large stakers still perform meaningful computation and very small stakers are not excluded entirely. This creates a combined economic-computational barrier: attacking cheaply requires massive computation; attacking with minimal computation requires massive stake.

Per-zone, per-epoch difficulty retargeting toward a target attestation rate is a design-stage extension — the shipped runtime uses the static clamp above, and difficulty does not currently adjust at runtime.

An adversary creating a million Sybil nodes would need to acquire beats for each (economic barrier), solve puzzles for each attestation (computational barrier), and build reputation over time for each node (temporal barrier). The cost of attack scales linearly; the defense is multiplicative.

**Layer 2: Social Graph Analysis**

The AI-assisted analysis layer (Layer 3 of the protocol architecture) monitors witness patterns:

- Nodes that only attest to each other's records (closed clusters) receive reduced trust weight
- Nodes with attestation patterns inconsistent with their stated geography or entity type are flagged
- Sudden spikes in new witnesses for a specific creator trigger anomaly alerts

This is not a centralized filter — it is a distributed heuristic that each node can independently compute from the DAM's public data.

**Layer 3: Trust Decay for New Identities**

New keypairs start with zero trust. Their attestations carry minimal weight. Trust accumulates through:

- Duration of existence (older keys are harder to fake at scale)
- Diversity of attestation partners (attesting to many unrelated creators)
- Consistency of behavior (regular, plausible patterns)
- Cross-zone attestation (a key attested by nodes in multiple geographic zones is harder to Sybil)

A Sybil army of fresh keys carries near-zero attestation weight. By the time they've aged enough to matter, the temporal and economic costs make the attack unprofitable. A related variant — Sybil amplification through physical device recycling (wiping and re-enrolling the same hardware) — is addressed in Section 11.33.

**Layer 4: Leaf Node Independence**

Critically, Layer 1 validation (local, offline) is immune to Sybil attacks entirely. The poem on the phone in Nairobi is cryptographically valid regardless of how many fake witnesses exist on the network. Sybil attacks can pollute trust scores, but they cannot invalidate a legitimate local validation. The creator's signature is the ground truth; witnesses are corroboration, not authority.

