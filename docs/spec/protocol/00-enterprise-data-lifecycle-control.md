#### Enterprise Data Lifecycle Control

> **Status:** the **"Publish selectively" / `NETWORK_PUBLISH`** row below is
> **DISABLED in code** (`NETWORK_PUBLISH_ENABLED = false`, compile-time guarded —
> `src/network/publish.rs`; see §10.6.3/§10.6.4). Cross-realm publication is
> design-stage only: records carry no realm/network binding and MESH-BFT is a
> single stake-universe, so the mechanism is unsound until those gates ship. The
> other three lifecycle paths are live.

Every decision above is made **per record, post-validation.** The enterprise validates first — establishing cryptographic proof of integrity, authenticity, and timing — then decides what happens to each record afterward. This is not an all-or-nothing choice. Different records within the same organization can follow different lifecycle paths simultaneously:

| Lifecycle | What Persists | What's Gone | Use Case |
|-----------|--------------|-------------|----------|
| **Keep everything (private)** | Content + proof + metadata | Nothing destroyed | Internal audit trails, compliance archives, sensor history |
| **Keep proof, destroy content** | DAM record (hash, signature, timestamp) | Original content | Mission logs after review, expired trade secrets, completed drug trials |
| **Destroy everything** | Nothing | Content + DAM record + all traces | Classified operations, intelligence activities, time-limited sensitive data |
| **Publish selectively** | Selected records move to public network via NETWORK_PUBLISH | Enterprise controls what moves | Safety certifications, regulatory filings, voluntary transparency |

**"Destroy everything" is architecturally guaranteed for private networks.** On the public network, records cannot be deleted — other nodes hold copies. On a private network, the enterprise controls every node. There are no external copies, no external witnesses, no blockchain record, no beats, no central reporting. If the enterprise destroys their private DAM, there is zero protocol-level evidence that any validation ever occurred. The protocol does not phone home. It does not leak metadata to external systems. A private network that is destroyed leaves no trace that the protocol can reconstruct.

**The decision is reversible in one direction only.** An enterprise can always move from more secrecy to more transparency — publishing a previously private record, or revealing content behind a zero-knowledge proof. But it cannot move from transparency back to secrecy — once a record exists on the public network or content has been revealed, it cannot be retracted. This asymmetry is deliberate: it prevents enterprises from selectively rewriting history while allowing them to voluntarily increase transparency when circumstances change (regulatory requirements, declassification timelines, strategic disclosure).

