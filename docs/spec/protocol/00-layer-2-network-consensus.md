#### Layer 2: Network Consensus

When network connectivity is available, nodes propagate validation records to peers. The DAG structure allows:

- **Asynchronous propagation** — no block intervals, no mining, no waiting
- **Parallel validation** — multiple branches of the DAG grow simultaneously
- **Conflict preservation** — if two nodes validate conflicting claims (e.g., two people claim authorship of the same work), both records are preserved with timestamps. The DAG does not resolve the conflict — it records it for human or legal resolution.

Consensus is achieved through **witness accumulation**: as more nodes receive and acknowledge a validation record, its trust score increases. A validation witnessed by 1 node is locally valid. A validation witnessed by 1,000 nodes across 50 countries is globally attested.

Settlement provides threshold guarantees: once a record accumulates attestations from witnesses holding at least 2/3 of the zone's eligible stake (excluding the record's creator), it is considered settled; a conflicting record could settle only if witnesses holding at least one third of the stake attested to both. Diversity weighting is reported as a confirmation level and does not gate settlement in the current implementation. However, trust continues accumulating beyond settlement. A record with 100 diverse witnesses is more trusted than one with the minimum settlement threshold, even though both are settled. Trust is continuous, not binary. A record is always valid from the moment of local signing, with increasing levels of network attestation building confidence over time.

