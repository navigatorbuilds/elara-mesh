#### 3.3.3 Formal Definition: Directed Acyclic Mesh (DAM)

A **Directed Acyclic Mesh** is a distributed data structure defined as a tuple **M = (Z, V, E, C, π, A)** where Z is a set of zones, V is a set of validation records, E ⊂ V × V is a set of directed causal edges (acyclic), C is a classification function C: V × Observer → View, π is the partition-merge operator, and A is the cross-zone analytics function. The DAM satisfies the following properties:

1. **Locally flat** — for any zone z ∈ Z, the restriction M|z = (V_z, E_z) is a standard DAG. Nodes create validation records that reference parent records. Edges are directed. Cycles are impossible (enforced: a record's hash includes its parents' hashes, making cycles computationally infeasible). Any engineer who understands a DAG understands a local view of the DAM.

2. **Globally interconnected** — across zones, the structure forms a self-healing mesh topology. Zone-DAGs operate independently during partitions and merge when connectivity resumes via the partition-merge operator π: M|z₁ × M|z₂ → M|z₁∪z₂. The merge operation preserves both branches — the mesh routes around the partition rather than breaking. π is commutative (merge order doesn't matter) and idempotent (re-merging is a no-op).

3. **Observer-dependent** — the classification function C(v, o) projects a validation record v into an observer-specific view based on cryptographic clearance level. This is analogous to projection in geometry: a 3D object casts different 2D shadows depending on the angle of light. The DAM casts different "shadows" depending on the observer's cryptographic clearance. Formally: for observers o₁, o₂ with clearance levels l₁ < l₂, the information in C(v, o₁) ⊆ C(v, o₂) — higher clearance strictly reveals more.

4. **Analytically connected** — the analytics function A operates across the full mesh A: M → Insights, detecting patterns that span zones, classification levels, and time periods — connections that no single-zone view can reveal. A has read access to the full DAM but cannot modify records.

5. **Partition-preserving** — unlike blockchain (which resolves forks by deletion) or basic DAGs (which assume continuous connectivity), the DAM treats partitions as expected topology changes. Formally: if the network partitions into zones {z₁, z₂}, both M|z₁ and M|z₂ grow independently, and upon reconnection π(M|z₁, M|z₂) preserves all records from both branches with no data loss. Disconnected zones are segments of the mesh growing independently, destined to reconnect.

The name is chosen deliberately. In networking, a mesh is a topology where nodes interconnect directly, creating multiple paths and self-healing capability — if one link fails, traffic routes around it. The Elara DAM is a trust mesh: locally simple (each zone is a standard DAG), globally resilient (zones operate independently during partitions and merge seamlessly when connectivity returns).

