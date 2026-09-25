### 11.16 Censorship Resistance

**The threat:** A government orders all ISPs within its jurisdiction to block Elara Protocol traffic. Or mandates that all domestic nodes refuse records from certain creators (political dissidents, journalists, specific organizations). State-level censorship is the most powerful adversary the protocol faces.

**Defense Layer 1: Traffic Obfuscation**

The design allows for **pluggable transports** — the same concept used by Tor to operate in jurisdictions with restrictive internet policies. None is built into the current node; an operator can already carry node traffic through an external tunnel (WireGuard, SSH or Tor), since the transport is ordinary TCP:

- **Tunnels:** Elara traffic carried inside an allowlisted outer protocol (WireGuard, SSH, or a Tor pluggable transport such as obfs4 or Snowflake)
- **Steganographic encoding:** Validation records embedded in innocent-looking traffic (images, video calls, DNS queries)
- **Bridge relays:** Unlisted relay nodes operated by volunteers outside the censoring jurisdiction, accessible via out-of-band key exchange

The techniques are proven at scale by the Tor Project and Signal; for Elara, steganographic encoding and bridge relays are designs, not implemented.

The protocol explicitly does **not** support a "domain-fronting mode" that masquerades as classical HTTPS to a permitted CDN. Earlier drafts of this section listed domain fronting as a pluggable transport; that recommendation is retired by §4.7. Domain fronting requires a classical TLS outer layer, which leaks per-connection metadata (TLS ClientHello fingerprints, SNI when not encrypted via ECH) and breaks the post-quantum forward-secrecy goal of the transport. Operators who need DPI bypass in a censored environment should use the carriers above, not bake classical TLS into the protocol.

**Defense Layer 2: Partition Resilience (Already Built-In)**

The DAM's partition tolerance (Section 7.3) means censorship IS a partition. If a government blocks cross-border traffic:

1. The domestic zone continues operating independently
2. Domestic validations remain cryptographically valid
3. When the censorship lifts (regime change, policy reversal, VPN access), the zones merge
4. Nothing is lost — the domestic branch of the DAM is fully preserved

A government can slow the network. It cannot kill records that already exist on the DAM, and it cannot prevent domestic validation from continuing.

**Defense Layer 3: Mesh Networking Fallback**

In extreme censorship scenarios (internet shutdown), devices could form local mesh networks. These are design directions; Bluetooth and LoRa meshes are not implemented:

- **Bluetooth mesh:** Phone-to-phone, ~100 meter range, chain across a city
- **LoRa mesh:** 10+ km range, low bandwidth but sufficient for compact validation payloads (full PQC records require gateway relay)
- **Sneakernet:** Physical transfer of DAM data via USB drives, SD cards. Records are self-contained signed objects that verify offline (`elara-verify`), and a node can export its records (`/admin/export`) for another to ingest (`POST /records`); a dedicated offline sync tool is not built yet

Records validated during an internet blackout propagate when any node in the mesh eventually reaches the global network. The DAM is patient. It can wait.

**Defense Layer 4: Geographic Distribution of Anchor Nodes**

The design places anchor nodes on at least three continents at network launch (roadmap, Phase 2), and Section 11.4 sets the decentralization threshold at 1,000 active witness nodes across at least 10 geographic regions; neither is enforced in code, and the pre-launch network, which runs on a single-region development fleet, has not reached either. Once they hold, no single government can compel all anchor nodes to comply. Even if a government seizes all domestic anchor nodes, the global DAM continues — and the domestic zone's records are already replicated internationally.

