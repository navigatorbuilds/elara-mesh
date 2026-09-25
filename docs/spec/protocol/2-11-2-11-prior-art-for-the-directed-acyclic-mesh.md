### 2.11 Prior Art for the Directed Acyclic Mesh

Versions of this paper up to v0.7.35 called the DAM "a novel data structure". That claim was made without a prior-art search. A search was done on 12 September 2026, and the claim is withdrawn: each element of the DAM as built maps to published work, listed here so that a reader can check the mapping rather than take the paper's word for it. The list is what one search found; it is not a proof that nothing closer exists.

| DAM element (as built) | Prior work | Year | Ref. |
|---|---|---|---|
| Content-addressed objects linked by hash to their parents | Git object model | 2005 | [39] |
| The same, generalised as a Merkle DAG for arbitrary data | IPFS | 2014 | [32] |
| A ledger with no blocks, where each new record references earlier records | IOTA Tangle | 2016 (v1.4.3: 2018) | [6], [40] |
| Events carrying two parent hashes, consensus derived from the graph | Swirlds Hashgraph | 2016 | [41] |
| A DAG of record batches as the mempool, with ordering layered on top | Narwhal and Tusk | 2021 | [42] |
| Survey of DAG-based ledgers (the family as a whole) | SoK: Diving into DAG-based Blockchain Systems | 2020 | [43] |
| Partitioning the network into shards that process records in parallel | Zilliqa | 2017 | [44] |
| Adaptive state sharding with shard splitting and merging | MultiversX (formerly Elrond) | 2019 | [45] |
| Checkpoints finalised by staked validators, overlaid on a base ledger | Casper the Friendly Finality Gadget | 2017 | [46] |
| Concurrent updates that merge without coordination and converge | Conflict-Free Replicated Data Types | 2011 | [47] |
| CRDTs whose logical clock is a Merkle-DAG | Merkle-CRDTs | 2020 | [48] |
| Append-only Merkle log with inclusion proofs, independently auditable | Certificate Transparency | 2013 / 2021 | [49], [50] |
| Signed statements recorded by a transparency service that issues receipts | SCITT architecture (RFC 9943) | 2026 | [51] |
| Timestamps anchored to Bitcoin | OpenTimestamps | 2016 | [30] |
| Publicly verifiable randomness rounds usable as a time beacon | drand (League of Entropy) | live service | [52] |
| Logical time and causal order | Lamport clocks; Interval Tree Clocks | 1978; 2008 | [7], [13] |
| Verifiable credentials that authorise an agent's action (mandates) | Agent Payments Protocol (AP2) | live spec | [53] |

The three structural dimensions of Section 3.3 map onto this list directly: time as causal parents and concurrency as a graph rather than a chain are the Git, IPFS, Tangle and Hashgraph line; zone topology is the Zilliqa and MultiversX sharding line. Any sharded DAG ledger has all three.

What the project still puts forward is the composition and the choices made inside it: a ledger that stores signed evidence of acts rather than balances, so that records from a healed partition are merged as a union rather than resolved by one side winning (Section 7.3); post-quantum signatures from genesis rather than as a later migration (Section 4); a standalone verifier that re-checks a record from bytes alone (`crates/elara-verify` in the runtime source); and the mandate bracket of Section 2.10, which records who authorised an act. None of these is claimed as novel either. No prior-art search has been done for them, and this section will be extended when one is.

A US provisional patent application (No. 63/983,064) described the same composition. It was filed without a prior-art search, has not been examined, and is being allowed to lapse in favour of open publication (see the prior-art-and-priority note at the end of this document).

---

