### Catastrophe recovery — network fragmentation and reassembly

Global disaster. Network shatters. Surviving fragments run independently.

**Reconnection protocol:**

1. **Identity verification** — Dilithium3 signatures are self-verifiable. No network needed.
2. **Genesis chain verification** — each fragment traces epoch seal chain back to genesis. Same genesis_authority → same network → safe to merge.
3. **DAM merge** — the DAM is a MESH. Fragments merge by connecting DAG tips:
```
  Brazil:      A → B → C → D (tip)
  Montenegro:  X → Y → Z (tip)
  After reconnection, new record W:
  W.parents = [D, Z]    ← mesh grows
```
No conflict resolution. No "which chain wins." Both histories are valid by design.
4. **Epoch seal reconciliation** — zone-scoped epoch numbers. No conflicts between zones.
5. **Archive restoration** — data centers serve historical Merkle proofs for pre-disaster records.

**What can't be recovered:** If all copies of a record are destroyed, content is gone. Merkle roots prove it EXISTED (hash is in the tree) but content cannot be reconstructed. The protocol proves absence honestly.

---

