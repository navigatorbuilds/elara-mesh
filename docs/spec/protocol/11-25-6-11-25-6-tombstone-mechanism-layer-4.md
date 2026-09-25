#### 11.25.6 Tombstone Mechanism (Layer 4)

The genesis authority can mark a record for suppression by creating a tombstone record. The design suppresses the target from future propagation; the shipped runtime does not yet do so (third bullet):

- Tombstone records contain `tombstone_op: "remove"` and `tombstone_target: "<record_id>"`
- Only the genesis authority identity can create tombstones
- Tombstoned records remain in storage (immutability is preserved). In the shipped runtime the tombstone marker is consulted only at the ingest ledger gate; exclusion from gossip responses and API queries is designed but not yet implemented, so a tombstoned record still propagates and is still served today
- Tombstone records themselves propagate normally, so all nodes learn about suppression decisions

**Limitation — race condition:** If a target record propagates to a node before the tombstone arrives, that node will have already stored and indexed the record. Even once propagation filtering is built, the tombstone will prevent future propagation only; it will not un-index already-processed records. Identity bans (Layer 7) are the primary proactive defense; tombstoning is reactive cleanup.

**Immutability guarantee:** Tombstoning does NOT delete records. The record remains in storage as an audit trail. Tombstoning is designed to suppress propagation — to control what the network carries forward, not what it has already stored. This distinction preserves the immutability guarantee of Section 11.5.

