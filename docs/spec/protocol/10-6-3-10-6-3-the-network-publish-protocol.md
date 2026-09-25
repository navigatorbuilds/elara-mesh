#### 10.6.3 The NETWORK_PUBLISH Protocol

> **Implementation-status note (honest-claims rule): the NETWORK_PUBLISH transition described in this section is DISABLED in the current runtime** (`NETWORK_PUBLISH_ENABLED = false`, compile-time guarded). The per-record model below — imported records *entering* public consensus and gaining *retroactive* native standing (step 5 and §10.6.4) — was found unsound: when it was disabled, a validation record's signed bytes carried no realm/network binding (Assumption A8 of the MESH-BFT merge semantics), so an imported record was consensus-indistinguishable from a native one, and the single-network safety theorem does not cover adopting a foreign network's records as native settlement parents. (Since wire format v6 each new record signs its network identifier and a node rejects a record that names a different network; records at v4 and v5, which nodes still accept, and records that name no network, carry no binding.) The mechanism is being reframed to **inert-import** — public consensus attests only that a publication *bundle* (source root + Merkle root of the imported set + completeness proof + external time anchors) existed at an anchored time, conferring **zero native standing** (no settlement-parent role, no stake, no witness weight, no cross-zone debit basis). This section documents the original design, retained for reference pending that reframe and a proven multi-root merge theorem.

When a private network transitions records to the public network — partially or fully — the protocol defines a **NETWORK_PUBLISH** record type:

```
Record Type: NETWORK_PUBLISH (0x0E)

Fields:
  source_network_id    bytes     Public key of private network root authority
  published_records    RecordSet Record ID range, classification filter, or DAG subtree
  publication_scope    enum      FULL | SELECTIVE | FEDERATED
  target_zone          ZoneID    Destination zone in the public network
  historical_depth     uint64    How far back (in records or time) to publish
  redaction_policy     Policy    Which metadata fields are stripped before publication
  transition_mode      enum      SNAPSHOT | STREAMING | GRADUAL
  completeness_proof   bytes     Optional Merkle proof that published set is complete
                                 relative to the source DAG (prevents selective omission)
  anchor_trail         AnchorProof[]  Chain of external state-root commitments made
                                 DURING private operation (public-mesh seals, independent
                                 timestamping services, or other widely-witnessed media).
                                 Determines the age credibility of the published history.
```

**Transition modes:**

- **SNAPSHOT** — Publish entire DAG subtree at once. Immediate verifiability, high bandwidth cost.
- **STREAMING** — Publish records chronologically over a defined period. Allows the public network to absorb and verify incrementally.
- **GRADUAL** — Begin with recent records, extend historical depth over time. Lowest initial exposure.

**Verification process:**

When the public network receives published records:

1. **Signature verification.** Every record's post-quantum signature is verified independently. Signatures are self-contained — they do not depend on network state.
2. **Causal chain verification.** Parent references are followed to ensure the DAG structure is internally consistent. Missing parents (unpublished records referenced by published records) are flagged as known gaps, not errors.
3. **Temporal consistency (internal only).** Timestamps are checked for monotonicity within causal chains — a child cannot predate its parent. This proves internal ordering only, **never calendar time**: every clock and key inside a private network belongs to its operator, so a fabricated DAG can satisfy this check perfectly.
4. **Completeness check.** If a completeness proof is provided, it is verified against the published record set. This proves the organization is not selectively omitting unfavorable records from a subtree.
5. **Retroactive witnessing.** Public nodes can witness historical records, adding new trust attestations that reference the original (unchanged) records.
6. **Anchor-trail verification.** Each `anchor_trail` entry is verified against its external medium (a public-mesh epoch seal, an independent timestamp proof). Each verified anchor proves the committed state — and every record beneath it — **existed by** the anchor's time.

**Age credibility and the anchor-density law.** External anchoring is the *only* mechanism that makes a published history's age verifiable. Internal evidence cannot prevent backdating (a fabricator controls all keys and clocks in its own realm); beacon references at key generation prove only freshness (*no older than*), while anchors prove existence (*no younger than*) — age claims require the latter. The maximum undetectable backdating window equals the largest gap between consecutive anchors, so **publication credibility is proportional to anchor density**. A private network that never anchored may still publish: its records receive structural verification (steps 1–4) and prospective trust from retroactive witnessing (step 5), but the network MUST treat its declared age as zero. Operators intending a future Validation IPO should anchor from day one.

**Anchor-media requirements (no single foundation).** An anchor's evidentiary value MUST rest on hash structure — a Merkle path into a widely-replicated hash chain — never on the host medium's signatures. Quantum adversaries break signature schemes (Shor), not 256-bit hash preimages (Grover leaves ~2^128 work), so a hash-bound anchor survives even the collapse of its host's signature economy; witnesses whose value rests on a signature (e.g., RFC 3161 credits) diversify the set but MUST themselves be re-wrapped by hash-based media over time. Anchors MUST span multiple independent media; verifiers SHOULD archive the host-chain headers their proofs traverse, removing dependence on the host's future availability or canonical-chain consensus. Finally, the running state root MUST be re-anchored continuously: each new anchor re-witnesses the entire history beneath it under every newer, stronger medium — including, eventually, the public mesh itself — which is how the system migrates off any bootstrap medium without losing its past.

