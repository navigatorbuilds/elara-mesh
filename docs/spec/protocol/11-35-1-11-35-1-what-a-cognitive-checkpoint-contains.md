#### 11.35.1 What a Cognitive Checkpoint Contains

A `cognitive_checkpoint` ValidationRecord contains a `CognitiveDigest` in its metadata:

```
cognitive_checkpoint ValidationRecord {
    id:             UUID v7
    content_hash:   SHA3-256(canonical_json(CognitiveDigest))
    creator:        node identity (Dilithium3 public key)
    timestamp:      ISO-8601 + vector clock
    parents:        [previous_checkpoint_id, latest_dag_record_id]
    classification: PUBLIC (default) or PRIVATE
    metadata: {
        record_type:    "cognitive_checkpoint"
        trigger:        "boot" | "shutdown" | "milestone" | "drift" | "manual" | "periodic"
        chain_depth:    integer (number of checkpoints in chain)
        digest_version: "1.0"
    }
    signature:      Dilithium3 (primary)
    signature_alt:  SPHINCS+ (secondary, for Tier 2+ nodes)
}

CognitiveDigest {
    mood:           [valence, energy, openness]   // 3 floats
    memories:       integer                       // total memory count
    models:         integer                       // cognitive model count
    predictions:    integer                       // active predictions
    principles:     integer                       // crystallized principles
    corrections:    integer                       // recorded corrections
    goals_active:   integer                       // active goals
    goals_done:     integer                       // completed goals
    allostatic_load: float                        // cognitive stress metric
    session_number: integer                       // current session
}
```

The `content_hash` is computed over a **canonical JSON serialization** of the `CognitiveDigest` — keys sorted alphabetically, no whitespace, deterministic float formatting. This ensures that any node can independently verify the hash from the digest fields.

