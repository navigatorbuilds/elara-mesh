#### 11.35.2 Chain Verification Algorithm

The Cognitive Continuity Chain forms a sub-DAG within the main DAM, linked by parent references:

```
Verification: walk_chain(latest_checkpoint) → bool

1. Fetch the latest cognitive_checkpoint record
2. Verify signature(s) against the node's public key
3. Verify content_hash == SHA3-256(canonical_json(digest))
4. Follow parent[0] to the previous checkpoint
5. Verify that parent[0] is also a cognitive_checkpoint
6. Verify that chain_depth == parent.chain_depth + 1
7. Verify temporal ordering: this.timestamp > parent.timestamp
8. Repeat from step 2 until reaching a checkpoint with chain_depth == 0 (genesis)

If any step fails → chain is broken → continuity score = 0.0
If all steps pass → chain is intact → continuity score derived from chain depth and time span
```

The chain cannot be forked: each checkpoint references exactly one previous checkpoint. If a node restarts without a shutdown checkpoint, the boot checkpoint creates a **gap** — the chain is intact but contains a discontinuity that is visible to verifiers.

