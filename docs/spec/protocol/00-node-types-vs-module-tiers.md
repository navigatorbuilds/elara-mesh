#### Node Types vs. Module Tiers vs. Storage Profiles

A node's behavior on the Elara network is described by **three orthogonal axes** — confusing any two of them leads to operator-side miscapacity-planning. The Elara Core reference implementation (v0.15.0) introduces a **module tier system** that controls what cognitive capabilities a node activates. This is orthogonal to both the node's consensus role AND its storage profile: the tier controls what a node *thinks*, the consensus role controls what it *does on the network*, and the storage profile controls what it *retains on disk*.

| Axis | Values | Source of truth | Controls |
|------|--------|-----------------|----------|
| **Module tier** | VALIDATE / REMEMBER / THINK / CONNECT | Self-assessed at boot from hardware | Cognitive capability (signing → memory → reasoning → full network cognition) |
| **Node consensus role** | leaf / relay / gateway / witness / archive / anchor | `network/peer.rs::NodeType` (operator-configured) | Consensus participation surface (attestation eligibility, seal-loop role, gossip topology position) |
| **Storage profile** | Light / FullZone / Archive | `network/node_profile.rs::NodeProfile` (operator-configured) | Retention window (Light=tip only; FullZone=full history within home zone; Archive=full history across all zones) |

All three axes are first-class. A hardware-rich leaf node may run Tier 3 CONNECT cognition while still being consensus-leaf and storage-Light. A modest VPS anchor may be Tier 2 THINK + consensus-anchor + storage-FullZone. The metrics `elara_node_type_info`, `elara_node_profile_info`, and the tier-info label series each expose one axis independently so operators can attribute correctly.

| Core Module Tier | Capability Level | Typical Node Type | What It Unlocks |
|------------------|------------------|-------------------|-----------------|
| **Tier 0: VALIDATE** | Cryptographic signing only | Leaf node (Profile C gateway, IoT) | Layer 1 operations: hash, sign, verify, DAG append |
| **Tier 1: REMEMBER** | Memory and persistence | Leaf, Relay | + episodic memory, corrections, handoff, basic recall |
| **Tier 2: THINK** | Reasoning and analysis | Witness, Relay | + cognitive models, predictions, principles, reasoning trails, Cognitive Continuity Chain |
| **Tier 3: CONNECT** | Full network cognition | Anchor, Bridge | + network tools, Layer 3 AI, dream/overnight processing, full inter-node cognitive exchange |

A Tier 0 node on a $4 ESP32 is a leaf that validates sensor readings. A Tier 3 node on a server is an anchor that runs full cognitive analysis and generates Cognitive Continuity Chain snapshots. The same protocol, the same DAM, the same cryptographic proof — scaled by hardware capability rather than by price tier or permission level.

The tier system is **self-assessed** — each node selects its tier based on available hardware resources (RAM, storage, compute). There is no central authority assigning tiers, and a node can change its tier at any time by upgrading or downgrading its hardware.

