#### 11.25.3 Text Field Byte Limits (Layer 2)

User-writable text fields have per-field byte limits:

| Field | Max bytes | Purpose |
|-------|-----------|---------|
| `beat_memo` | 256 | Transfer/burn memo |
| `beat_reason` | 256 | Mint/slash/reclaim reason |
| `governance_title` | 128 | Proposal title |
| `governance_description` | 1024 | Proposal description |
| `dispute_reason` | 512 | Dispute opening reason |
| `dispute_evidence` | 1024 | Evidence submission |
| `challenge_evidence[]` | 512/entry | Fisherman evidence (array) |
| `challenge_appeal_reason` | 512 | Appeal text |
| `revocation_reason` | 128 | Key revocation reason |
| `rotation_reason` | 128 | Key rotation reason |
| `change_summary` | 512 | Version change description |
| `sunset_reason` | 256 | Algorithm sunset reason |

These limits make the network unsuitable for embedding images (even base64-encoded), documents, or bulk content. A 256-byte memo field holds approximately 200 characters of text — enough for a transaction description, insufficient for meaningful content distribution.

