### 11.18 Protocol Upgrade Mechanism

**The gap:** A protocol designed to outlive its creators must evolve. New cryptographic algorithms, new ZKP systems, new device types, unforeseen requirements. How does the protocol upgrade without breaking the network?

**Solution: Semantic Versioning with Soft Fork Default**

**Version field in every record:**

Every validation record includes a protocol version number. Nodes advertise the versions they support. This enables:

**Soft forks (backward-compatible changes):**
- New optional fields in validation records
- New classification levels
- New entity types
- Optimized encoding formats

Soft forks require no coordination. New nodes produce new-format records. Old nodes ignore fields they don't recognize. Both coexist on the DAM. Governance vote recommends adoption; individual nodes upgrade at their own pace.

**Hard forks (breaking changes):**
- Changes to the consensus mechanism
- New required fields in validation records
- Deprecation of cryptographic algorithms

Hard forks require governance approval (>67% supermajority per Section 10.3) and follow a strict process:

```
1. Proposal published (with reference implementation)
2. 90-day discussion period
3. Governance vote
4. If approved: 180-day transition window
5. During transition: both old and new formats accepted
6. After transition: old format deprecated (but old records remain valid)
```

**Emergency upgrades (critical security patches):**

If a cryptographic algorithm is broken or a critical vulnerability is discovered, the protocol supports **emergency governance** — a fast-track process:

1. Security advisory published by any anchor node
2. Emergency vote: 48-hour window, >75% supermajority required
3. If approved: 30-day transition (vs. normal 180 days)
4. Anchor nodes enforce the new version; other nodes have 30 days to upgrade

The emergency mechanism is intentionally rare and high-threshold. It exists for true existential threats (e.g., quantum computing breaks Dilithium earlier than expected), not for feature additions.

**Algorithm deprecation lifecycle:**

```
ACTIVE     → algorithm used for new signatures
LEGACY     → algorithm accepted for verification, not recommended for new signatures
DEPRECATED → algorithm accepted for verification of old records only, rejected for new
ARCHIVED   → algorithm documented in protocol history, old records still verifiable
             through algorithm agility (Section 4.4)
```

No algorithm is ever deleted from the protocol's specification. A record signed with Dilithium3 in 2026 must be verifiable in 3026 — even if Dilithium3 was deprecated in 2050. The verification code for every algorithm ever used is preserved in the protocol's reference implementation, explicitly tagged as archival.

