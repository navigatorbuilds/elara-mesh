#### 11.25.2 Metadata Key Allowlist (Layer 1)

Every metadata key in a validation record must appear in the protocol's allowlist. The allowlist contains the complete set of keys used by all protocol operations: beat transfers, staking, governance, disputes, fisherman challenges, key rotation, algorithm sunset, epoch management, versioning, tombstoning, and collaboration.

Records with unknown keys are rejected at ingestion — they are never stored, never gossiped, never processed. This prevents arbitrary data injection through the metadata layer.

Six anti-rehypothecation keys are explicitly blocked: `derivative_op`, `wrap_op`, `collateral_op`, `tokenize_op`, `synthetic_op`, `lend_op`. Records containing these keys are rejected at ingestion.

