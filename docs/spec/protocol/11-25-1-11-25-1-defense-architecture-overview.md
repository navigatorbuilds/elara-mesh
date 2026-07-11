#### 11.25.1 Defense Architecture Overview

The protocol implements eight independent defense layers, applied at the record ingestion gate (`insert_record_with_origin()`). All layers enforce on ALL entry paths — HTTP POST, WebSocket submission, gossip propagation, and internal record creation (faucet, rewards, epoch seals). No code path bypasses the gate.

| Layer | Type | Action | Applied At |
|-------|------|--------|------------|
| 1. Metadata key allowlist | Structural | Reject unknown keys | Ingestion |
| 2. Text field byte limits | Structural | Reject oversized text | Ingestion |
| 3. URL rejection | Structural | Reject URLs in text | Ingestion |
| 4. Tombstone suppression | Reactive | Suppress gossiped records | Post-storage |
| 5. Browser-side enforcement | Defense-in-depth | Client-side validation | Pre-submit |
| 6. Propagation bounds | Structural | 24 entries, 2KB values | Ingestion |
| 7. Identity ban list | Proactive | Block all records from identity | Ingestion (first check) |
| 8. Content blocklist | Proactive | Block records matching terms | Ingestion |

Layers 1–3 and 6 are **structural constraints** — they limit the protocol's capacity to carry content, like TCP's maximum segment size limits the payload of a single packet. They are engineering constraints, not content judgments.

Layers 4, 7, and 8 are **operator tools** — they give node operators the means to comply with their jurisdiction's laws and protect themselves from criminal liability. They are not centralized censorship.

Layer 5 is **defense-in-depth** — client-side validation that prevents user confusion but is not a security boundary. Server-side enforcement is authoritative.

