### 5.2 Classification Levels

Every validation record carries a classification level that determines what the network can see:

**PUBLIC** — Full content hash visible. Anyone can verify the exact content. Default for open-source code, published work, public sensor data.

**PRIVATE** — Content hash wrapped in a SHA3-256 commitment (Phase-1 stand-in; genuine zero-knowledge proofs are design-stage — see §5.3). The network validates that:
- A valid content hash exists
- It was signed by a valid keypair
- The timestamp is consistent with the DAG
- No conflicting claim exists

...without learning what the content is. The creator can selectively reveal the content later (e.g., in a legal dispute or patent filing) by providing the pre-image.

**RESTRICTED** — Key-group access. The content hash is encrypted to a set of public keys. Only designated parties can verify the content. The network validates the structural integrity of the record without accessing the encrypted payload.

**SOVEREIGN** — Maximum privacy. Multi-key authorization required for any access. Time-locked release optional. Validator nodes process the proof without any visibility into the content or the classification metadata. (SOVEREIGN additionally *specifies* wrapping the creator's identity in a ZKP — design-stage; in Phase 1 identity is bound by the record's Dilithium3 signature. See §5.3.)

