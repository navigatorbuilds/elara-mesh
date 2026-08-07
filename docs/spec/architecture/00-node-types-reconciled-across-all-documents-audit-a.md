### Node Types

| Type | Hardware Tier | Role | Stores Records? | Participates in Consensus? |
|------|-------------|------|----------------|--------------------------|
| leaf | Tier 1 (MCU) | Creates records, submits to nearest relay | No | No |
| relay | Tier 2 (phone/laptop) | Light client, verifies Merkle proofs, holds own records | Own only | No |
| witness | Tier 3 (VPS) | Holds 1-N zones on disk, attests to epoch seals | Yes (subscribed zones) | Yes |
| anchor | Tier 3-4 (high-trust VPS) | Witness + epoch seal proposer for assigned zones | Yes | Yes + proposes epochs |
| archive | Tier 4 (data center) | Holds full history for a region/industry, serves proofs | Yes (broad) | Yes |
| gateway | Tier 1-2 (IoT hub) | Bridges constrained devices to the network (Profile C delegation) | Delegated | Delegated |

**Simplified naming:** Light Node = relay; Full Node = witness/anchor; Storage Node = archive.

All six node types are preserved; the gateway bridges Profile C (constrained) devices.

---

