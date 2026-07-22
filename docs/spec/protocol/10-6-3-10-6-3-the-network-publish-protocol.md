#### 10.6.3 The NETWORK_PUBLISH Protocol

> **Status (2026-06-22): the NETWORK_PUBLISH / Validation-IPO transition described in this section is DISABLED in code** (`NETWORK_PUBLISH_ENABLED = false`, compile-time guarded in `src/network/publish.rs`). The per-record publication model — imported records *entering* public consensus and gaining *retroactive* public attestations — was found unsound: a `ValidationRecord`'s signed bytes carry no realm/network binding (Assumption A8, `docs/MESH-BFT-MERGE-SEMANTICS.md`), so an imported record is consensus-indistinguishable from a native one, and MESH-BFT's single-network safety theorem does not cover adopting a foreign network's records as native settlement parents. The mechanism is being reframed to **inert-import**: public consensus will attest only that a publication *bundle* (source root + Merkle root of the imported set + completeness proof + external time anchors) existed at an anchored time — conferring **zero native standing** (no settlement-parent role, no stake, no witness weight, no cross-zone debit basis). The text below describes the original design and is retained for reference pending that reframe and a proven multi-root merge theorem.

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
```

**Transition modes:**

- **SNAPSHOT** — Publish entire DAG subtree at once. Immediate verifiability, high bandwidth cost.
- **STREAMING** — Publish records chronologically over a defined period. Allows the public network to absorb and verify incrementally.
- **GRADUAL** — Begin with recent records, extend historical depth over time. Lowest initial exposure.

**Verification process:**

When the public network receives published records:

1. **Signature verification.** Every record's post-quantum signature is verified independently. Signatures are self-contained — they do not depend on network state.
2. **Causal chain verification.** Parent references are followed to ensure the DAG structure is internally consistent. Missing parents (unpublished records referenced by published records) are flagged as known gaps, not errors.
3. **Temporal consistency.** Timestamps are checked for monotonicity within causal chains. A child record cannot have a timestamp earlier than its parent.
4. **Completeness check.** If a completeness proof is provided, it is verified against the published record set. This proves the organization is not selectively omitting unfavorable records from a subtree.
5. **Retroactive witnessing.** Public nodes can witness historical records, adding new trust attestations that reference the original (unchanged) records.

