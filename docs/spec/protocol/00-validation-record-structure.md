#### Validation Record Structure

```
ValidationRecord {
    id:            UUID v7 (time-ordered)
    version:       wire format version
    network_id:    network the record belongs to (wire format v6)
    nonce:         per-account slot nonce (wire format v5)
    content_hash:  SHA3-256(content)
    creator:       public key (ML-DSA-65, FIPS 204)
    timestamp:     creator's clock, seconds since the Unix epoch
    parents:       [record_id, ...] (DAG references)
    classification: PUBLIC | PRIVATE | RESTRICTED | SOVEREIGN
    metadata:      extensible key-value (content type, device info, etc.)
    zk_proof:      privacy proof for PRIVATE and RESTRICTED (Phase 1: a SHA3-256 commitment; Section 5.3)
    signature:     ML-DSA-65 signature over all above fields
    sphincs_signature: optional SPHINCS+ signature (Profile A)
    zone:          optional hierarchical zone path (wire format v3; not signed)
}
```

Nodes add causal-order stamps (`itc_stamp`, `zone_refs`; Section 11.9) outside the signature.

