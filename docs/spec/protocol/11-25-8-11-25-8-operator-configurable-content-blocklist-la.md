#### 11.25.8 Operator-Configurable Content Blocklist (Layer 8)

Node operators can configure a term blocklist applied to all user-writable text fields. Records containing blocked terms are rejected at ingestion — never stored, never gossiped.

- Case-insensitive substring matching
- Minimum term length: 2 characters (prevents false positives from single-character matches)
- Persisted in storage, hot-reloadable via admin API
- Genesis authority only (on managed nodes)

**Critical design decisions:**

1. **No default terms are shipped with the protocol.** The blocklist is empty at genesis. Operators add terms relevant to their jurisdiction and legal obligations. This prevents the protocol from encoding a single cultural standard or becoming a vehicle for centralized censorship.

2. **Operators control their own nodes.** Each node's blocklist is independent. Node A may block terms that Node B does not. This mirrors how different jurisdictions have different content laws — a node operated in Germany applies German law, a node in Singapore applies Singaporean law.

3. **The blocklist operates on metadata text fields, not on content hashes.** The protocol does not implement a forbidden-hash blacklist. Hash-based blacklists are content-agnostic censorship mechanisms that can suppress any record regardless of its content. Term-based filtering operates on the small set of user-writable text fields (memos, descriptions, reasons) and is transparent — operators and users can see exactly what terms are filtered.

