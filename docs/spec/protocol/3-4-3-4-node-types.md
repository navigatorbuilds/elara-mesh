### 3.4 Node Types

| Type             | Hardware Tier | Role | Stores Records? | Consensus? | Example |
|------------------|-------------|------|----------------|------------|---------|
| **Leaf node**    | Tier 1 (MCU) | Creates records, signs directly (Profile A/B) or delegates to gateway (Profile C) | No (submits to nearest relay/witness) | No | IoT sensor, $4 ESP32 |
| **Relay node**   | Tier 2 (phone/laptop) | Light client, propagates records, verifies Merkle proofs, holds own records | Own records only | No | Phone app, laptop |
| **Witness node** | Tier 3 (VPS) | Attests to epoch seals, validates records, holds subscribed zones on disk | Yes (subscribed zones) | Yes | Cloud VM, mini PC |
| **Anchor node**  | Tier 3-4 (high-trust) | Witness + epoch seal proposer for assigned zones (VRF-selected) | Yes | Yes + proposes epochs | Hardened VPS, data center |
| **Archive node** | Tier 4 (data center) | Full history for a region/industry, serves Merkle proofs and historical queries | Yes (broad/full) | Yes | Cold storage facility |
| **Gateway node** | Tier 1-2 (IoT hub) | Bridges constrained devices (Profile C) to the network via delegation | Delegated | Delegated | Home hub, factory edge |

Any node can serve multiple roles simultaneously. A laptop can be a relay and witness. A $4 microcontroller can only be a leaf, but that is sufficient for its purpose. Gateway nodes enable Profile C devices (too constrained for PQC key generation) to participate via delegated signing.

**Node incentive mapping:** Light Node = relay. Full Node = witness/anchor. Storage Node = archive. Node-specific incentive structures are specified separately.

