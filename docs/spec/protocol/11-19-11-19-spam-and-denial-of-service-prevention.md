### 11.19 Spam and Denial-of-Service Prevention

**The attack:** Layer 1 validation is free. An attacker generates millions of garbage validation records — random hashes, signed by valid keys — flooding the network. Each record is individually valid (correctly signed, properly formatted). The DAM fills with noise, relay and witness nodes waste bandwidth and storage, and legitimate records are drowned out.

This is the cost of "Layer 1 is always free." Free creation means free spam.

**Defense 1: Stake-Scaled Propagation Rate Limiting**

Layer 1 (local validation) is unrestricted — an attacker can fill their own local DAG with garbage. But Layer 2 (network propagation) applies rate limits per identity:

$$\text{effective\_limit} = \text{base\_rate} + \left\lfloor \frac{\text{staked\_base}}{\text{stake\_ratio} \times 24} \right\rfloor$$

Where `base_rate` is the unstaked floor (default: 120 records/hour, a governance parameter; a node never applies less than its configured floor, default 100) and `stake_ratio` is base units of stake (10^9 per beat) per daily record (default: 100,000,000 = 0.1 beats, governance-adjustable). The formula converts the daily stake allowance to an hourly propagation ceiling.

| Stake | Hourly Limit | Records/sec | With 60× Batch |
|-------|-------------|-------------|-----------------|
| 0 beats (unstaked) | 120 | 0.03 | 2/sec |
| 100 beats | ~161 | ~0.04 | ~3/sec |
| 1,000 beats | ~536 | ~0.15 | ~9/sec |
| 10,000 beats | ~4,286 | ~1.19 | ~71/sec |

Key properties:

- **Unstaked identities get the base floor.** Fresh or anonymous identities can still participate — 120 records/hour is sufficient for individual use. This preserves the "Layer 1 is always free" guarantee.
- **Stake scales linearly.** No tiered jumps. Staking 100 beats and staking 101 beats produce proportionally different limits. Industrial users get throughput in proportion to what they stake.
- **Batching multiplies effective throughput.** A single record can contain multiple data points (Protocol §4.2 batch records). Combined with stake-scaling, a factory staking 1,000 beats with 60-reading batches achieves ~9 verified data points per second (~770,000 per day).
- **Gossip relay is exempt.** Records arriving via gossip pull or push relay from known peers are not rate-limited — only direct submissions from the record creator. This prevents sync failures between nodes with different propagation histories.
- **Both parameters are governance parameters.** Beat stakers can vote to change `stake_ratio`, or to raise `base_rate` above each node's configured floor, without protocol upgrades, adapting to network growth or shifts in beat earning economics.

An attacker generating 1 million records per hour from an unstaked identity would see 120 propagate and the rest rejected. To sustain that rate, they would need to stake ~2.4 million beats — a real economic commitment. (No slashing offence covers a creator's own records in the current runtime; slashing covers epoch-seal equivocation and challenged witness misbehaviour.)

**Defense 2: Proof-of-Work for Burst Propagation**

If a node needs to propagate more than its rate limit (legitimate use case: IoT gateway syncing a batch of sensor readings), the design lets it solve a lightweight proof-of-work puzzle for each excess record (not implemented: the current node rejects records over the limit; staking raises the limit instead). The puzzle difficulty would be calibrated so that:

- Normal usage (under rate limit): zero computational cost
- Moderate burst (2–10x limit): seconds of compute
- Spam-scale burst (1000x+ limit): hours/days of compute — economically infeasible

This is the same approach used by Hashcash [24] (email anti-spam, 2002) and later adopted by blockchain networks. It adds no cost to honest users and makes spam expensive.

**Defense 3: Content-Independent Duplicate Detection**

Zone-level Bloom filters would detect records with identical content hashes. If the same hash were submitted by different identities simultaneously (a classic spam pattern — resubmitting the same garbage with different keys), only the first propagation would proceed; subsequent duplicates would be annotated as conflicts but not relayed further. (Design; not implemented. The current node's entropy check looks at each identity's own submissions; it does not hold back a record because another identity submitted the same content hash.)

**Defense 4: Economic Filtering at Layer 2**

Witness nodes choose what to attest. They are rational economic actors — attesting costs computational resources (PoWaS). No witness will spend resources attesting to records from identities with zero trust, anomalous patterns, or rate-limit violations. Spam records exist on the DAM but accumulate zero witnesses and zero trust. They are dead weight — present but invisible to anyone querying the DAM with a minimum trust threshold.

