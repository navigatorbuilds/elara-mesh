### 11.29 Long-Range Attacks with Historical Keys

**The attack:** An adversary obtains old private keys — from a decommissioned device, a leaked backup, a compromised archive, or (eventually) quantum cryptanalysis of old algorithms. They use these keys to create validation records that appear to originate from the legitimate key holder at a past date.

This is more subtle than simple key compromise (Section 11.2): the attacker is not impersonating the current identity, but fabricating historical records using keys that were legitimately valid at some point.

**Defense 1: Epoch Sealing**

Epoch summaries (Section 11.8) create cryptographic snapshots of the DAM at regular intervals. Each epoch summary includes a Merkle root of ALL records in the epoch, signed by multiple anchor nodes. **Clarification on epoch sealing authority:** Anchor nodes are the subset of witness nodes designated as epoch sealers for their zone. The sealing mechanism is witness-signed Merkle roots — the same witnesses that attest records also seal epochs. There is no separate "zone authority" or "epoch authority" — anchor nodes ARE witnesses with additional sealing responsibility.

A fabricated historical record would not be included in any existing epoch summary. If an attacker produces a record claiming to be from epoch 42, but epoch 42's sealed Merkle root does not include it — the forgery is detected instantly.

**Implication:** The window for historical forgery is limited to the current unsealed epoch (typically hours to days). Once an epoch is sealed, its contents are cryptographically frozen.

**Defense 2: Key Epoch Binding**

The protocol records the epoch in which each identity key was first seen. A key first observed in epoch 100 cannot produce records claiming to be from epoch 50. Key-epoch bindings are established when a node's identity registration record is first witnessed by anchor nodes and included in an epoch summary. Since epoch summaries are signed by multiple geographically distributed anchors and sealed with Merkle roots, retroactively altering a key's first-seen epoch would require compromising the sealed epoch — which is equivalent to breaking the Merkle chain.

For keys that pre-date the network (bootstrapping phase), the genesis epoch explicitly lists all founding keys — preventing backdated claims from before the network existed.

**Defense 3: Algorithm Sunset Enforcement**

When a cryptographic algorithm transitions from ACTIVE to DEPRECATED (Section 11.18), a **sunset record** is created:

```
AlgorithmSunset {
    algorithm:      "dilithium3"
    status:         DEPRECATED
    effective_epoch: 10000
    reason:         "Lattice cryptanalysis advance, see CVE-2035-XXXX"
    signed_by:      [multiple anchor nodes]
}
```

After the sunset epoch, nodes enforce rejection as follows: when a new record arrives, the node checks its signature algorithm against the active sunset records. If the algorithm's status is DEPRECATED and the record's epoch exceeds the effective_epoch, the record is dropped during gossip propagation and excluded from the local DAG. Witness nodes will not attest to records with deprecated signatures. This enforcement is local — each node independently applies the sunset rules from the DAM's sunset records, requiring no central coordinator.

Old records (pre-sunset) remain verifiable for historical purposes but cannot be used as the basis for new claims. Nodes maintain a legacy verification path for deprecated algorithms to validate historical records while rejecting new ones.

