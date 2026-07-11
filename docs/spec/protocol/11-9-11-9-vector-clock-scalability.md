### 11.9 Vector Clock Scalability

**The problem:** Traditional vector clocks maintain one counter per node in the system. With 1 million nodes, each validation record would carry a vector of 1 million integers. At 4 bytes each, that is **4 MB per record** — orders of magnitude larger than the content hash it validates.

**Solution: Zone-Scoped Interval Tree Clocks**

The Elara Protocol replaces traditional vector clocks with a two-tier temporal ordering system:

**Intra-zone: Interval Tree Clocks (ITCs)**

Interval Tree Clocks (Almeida et al., 2008) provide the same causal ordering guarantees as vector clocks but with O(log n) space complexity instead of O(n). ITCs work by dynamically splitting and joining identity intervals as nodes enter and leave the system:

- New node joins → receives a split of an existing node's interval
- Node leaves → its interval is available for merger
- Causal ordering is maintained through interval comparisons

For a zone with 100,000 active nodes, the ITC overhead per record is ~40 bytes instead of ~400 KB. This is acceptable even for IoT devices.

**Inter-zone: Zone Sequence Numbers**

Cross-zone ordering does not require per-node granularity. Each zone maintains a **zone sequence number** — a monotonically increasing counter incremented with each epoch summary. Cross-zone causal ordering uses these sequence numbers:

```
ZoneCausalReference {
    zone_id:        zone identifier
    zone_sequence:  sequence number at time of last sync
    epoch:          epoch number
}
```

A record from Mars that references Earth zone_sequence 45,892 is causally after all Earth records up to that sequence. The overhead is ~20 bytes per cross-zone reference, regardless of how many nodes exist in the referenced zone.

**Combined overhead per validation record:**

| Component                    | Size                          |
|------------------------------|-------------------------------|
| ITC (intra-zone ordering)    | ~40 bytes                     |
| Zone references (inter-zone) | ~20 bytes per referenced zone |
| Total (3 zones referenced)   | ~100 bytes                    |

Compare to naive vector clocks at 1M nodes: **100 bytes vs. 4 MB** — a 40,000x improvement.

