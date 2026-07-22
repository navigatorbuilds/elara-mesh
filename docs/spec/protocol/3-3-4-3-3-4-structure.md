#### 3.3.4 Structure

Within each zone, the DAM operates as a standard DAG:

**Blockchain (1D):**
```
[Block N] → [Block N+1] → [Block N+2] → ...
(linear, sequential, one branch at a time)
```

**Elara DAM (local view — DAG within a zone):**
```
       [A] ← [C] ← [E] ← [G]
      ↗         ↖       ↗
[root]           [F] ←
      ↘         ↗       ↘
       [B] ← [D]         [H]
```

The "2D" label some earlier drafts used for the local view is shorthand: within a single zone the DAM is a directed acyclic graph with time-ordering as its single structural axis, and concurrency encoded through **parent edges** of each record (`parents: [record_id, ...]`). Parallel branches are topological properties of the edge set, not values on a second coordinate axis. Across zones the mesh gains a second, genuinely independent structural axis — zone partitioning — which is what makes the global view below a *mesh* rather than just a DAG.

**Elara DAM (global view, multi-zone):**
```
Zone: Earth          Zone: Mars          Zone: Luna
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  ●──●──●──●  │    │  ●──●──●     │    │  ●──●        │
│ ↗       ↖  ↗ │    │ ↗     ↖     │    │ ↗    ↖      │
│●    ●──   ●  │    │●   ●──      │    │●      ●     │
│ ↘  ↗  ↘      │    │ ↘  ↗        │    │ ↘    ↗      │
│  ●──●     ●  │    │  ●──●       │    │  ●──●        │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
              Cross-zone merge (when links available)
```

Each validation record references one or more previous records (its "parents"). Within and across zones:

- Multiple branches grow in parallel (no bottleneck)
- Branches merge naturally when nodes synchronize
- Partitioned zones develop independent branches that reconnect when communication resumes
- The full history is preserved — nothing is pruned, rewritten, or discarded
- Classification projections ensure observers see only what their clearance permits

