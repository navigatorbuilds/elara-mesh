#### 11.25.6 Tombstone Mechanism (Layer 4)

The genesis authority can suppress records from future propagation by creating a tombstone record:

- Tombstone records contain `tombstone_op: "remove"` and `tombstone_target: "<record_id>"`
- Only the genesis authority identity can create tombstones
- Tombstoned records remain in storage (immutability is preserved) but are excluded from gossip responses and API queries
- Tombstone records themselves propagate normally, so all nodes learn about suppression decisions

**Limitation — race condition:** If a target record propagates to a node before the tombstone arrives, that node will have already stored and indexed the record. The tombstone prevents future propagation but does not un-index already-processed records. Identity bans (Layer 7) are the primary proactive defense; tombstoning is reactive cleanup.

**Immutability guarantee:** Tombstoning does NOT delete records. The record remains in storage as an audit trail. Tombstoning suppresses propagation — it controls what the network carries forward, not what it has already stored. This distinction preserves the immutability guarantee of Section 11.5.

