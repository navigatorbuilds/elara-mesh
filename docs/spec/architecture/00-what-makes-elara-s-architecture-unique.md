## What Makes Elara's Architecture Unique

1. **Post-quantum from discovery layer up** — Dilithium3 signed peer records, epoch seals, bootstrap lists. As of this writing, to our knowledge no major P2P network has publicly documented PQ signatures in its discovery protocol (an unsourced survey claim — corrections welcome).
2. **The DAM as its own bootstrap** — peer advertisements as DAM records. Any copy of the DAM is a bootstrap source.
3. **Zone-native from genesis** — semantic hierarchical zones, not bolted-on sharding.
4. **Hardware-tier-aware discovery** — DHT routes requests to appropriate tier.
5. **Epoch seals = zone registry = consensus = Merkle root = balance reporting** — one data structure does five jobs.
6. **Native catastrophe recovery** — DAM mesh merges fragments without fork choice rules.
7. **Layered consensus** — immediate validation + epoch finalization + post-epoch challenges. Not per-record OR per-batch — both, layered.
8. **Cross-zone transfers via Merkle proofs** — two-phase lock/claim with cryptographic bridge. No coordinator.
9. **Fraud-provable conservation** — zones self-report totals, any node can submit fraud proofs.

---

