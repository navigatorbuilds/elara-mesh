### 11.6 Timestamp Gaming (Offline Backdating)

**The attack:** A malicious actor sets their device clock to January 2024, validates stolen work, then syncs to the network in February 2026. The validation record shows a 2024 timestamp, granting false priority over the actual creator.

This is a fundamental weakness of any system that allows offline validation with local timestamps. The Elara Protocol addresses it through three mechanisms:

**Mechanism 1: Causal Anchoring**

When an offline node syncs to the network, its validation records must reference existing DAM records as parents. The sync protocol automatically inserts a **causal anchor** — a reference to the most recent record the node received during synchronization.

This creates an ironclad constraint: a record with a causal anchor from February 2026 cannot have been created in January 2024, regardless of what the local timestamp claims. The DAG structure itself disproves the backdated timestamp.

**Mechanism 2: Temporal Witness Scoring**

Trust scores weight the gap between claimed creation time and first network appearance:

```
trust_penalty = f(time_claimed, time_first_witnessed)

If first_witnessed - time_claimed < 24 hours:  no penalty
If first_witnessed - time_claimed < 7 days:    minor penalty (0.9x trust)
If first_witnessed - time_claimed < 30 days:   moderate penalty (0.5x trust)
If first_witnessed - time_claimed > 30 days:   severe penalty (0.1x trust)
If first_witnessed - time_claimed > 1 year:    near-zero trust (0.01x)
```

A record that claims to be two years old but was first seen today carries almost no trust weight. It exists on the DAM (nothing is deleted), but its trust score reflects the suspicion.

**Mechanism 3: Concurrent Priority Protocol**

When two records claim the same content hash at different times, the protocol does not automatically award priority to the earlier timestamp. Instead, it evaluates:

1. **Causal anchoring** — which record has DAM-verifiable temporal context?
2. **Witness accumulation speed** — a legitimate record from a connected device accumulates witnesses in real-time; a backdated record arrives in a burst
3. **Device attestation history** — a device that has been consistently online and validating is more credible than one that appears with years of backdated records
4. **Cross-reference** — do other records from the same creator show consistent timelines, or is there a suspicious gap?

The result: local timestamps remain useful (and honest nodes produce accurate ones), but they are never the sole basis for priority claims. These three mechanisms work in concert — causal anchoring provides structural proof, temporal witness scoring applies economic penalties, and the concurrent priority protocol evaluates the full context. No single mechanism is sufficient alone, but together they make timestamp gaming detectable, penalized, and ultimately unprofitable. The DAG's causal structure serves as the primary authoritative clock; timestamps are supplementary metadata.

