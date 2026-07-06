## Design Principles

1. **Records are self-verifiable.** A record carries its own proof (signature + Merkle path + epoch seal reference). Any node, anywhere, can verify it without contacting the original zone.
2. **Zones are semantic and subscription-based, with stake-gated consensus.** Nodes choose which zones to store/witness. But to participate in consensus, you need minimum stake + PoW identity + diversity requirements.
3. **The DAM handles fragmentation natively.** No fork choice rule. No "longest chain wins." Fragments merge by connecting DAG tips. The mesh grows.
4. **Genesis is the root of trust.** Everything traces back to one signing key. Like X.509 — genesis = root CA, zone anchors = intermediate CAs, witnesses = leaf certificates.
5. **Archive nodes are the memory of the network.** They hold full history and serve proofs. Without archives, the network functions but can't prove ancient history.
6. **No record lives in RAM unless actively being processed.** Everything on disk, LRU cache for hot data, bounded RAM budget.
7. **Layered consensus.** Immediate per-record validation + epoch batch finalization + post-epoch challenges. Not binary — not either/or.
8. **Conservation is verifiable at every layer.** Per-zone balance totals + global aggregation + fraud proofs. The invariant holds even when no single node holds all state.

---

