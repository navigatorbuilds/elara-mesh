#### Validation Record Structure

```
ValidationRecord {
    id:            UUID v7 (time-ordered)
    version:       protocol version
    content_hash:  SHA3-256(content)
    creator:       public key (CRYSTALS-Dilithium)
    timestamp:     local ISO-8601 + vector clock position
    parents:       [record_id, ...] (DAG references)
    classification: PUBLIC | PRIVATE | RESTRICTED | SOVEREIGN
    zk_proof:      optional zero-knowledge proof (for non-PUBLIC)
    metadata:      extensible key-value (content type, device info, etc.)
    signature:     CRYSTALS-Dilithium signature over all above fields
}
```

