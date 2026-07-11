### 11.16 Censorship Resistance

**The threat:** A government orders all ISPs within its jurisdiction to block Elara Protocol traffic. Or mandates that all domestic nodes refuse records from certain creators (political dissidents, journalists, specific organizations). State-level censorship is the most powerful adversary the protocol faces.

**Defense Layer 1: Traffic Obfuscation**

The protocol supports tunneling ElaraPQ frames inside outer carriers so that deep-packet-inspection middleboxes cannot easily fingerprint Elara traffic. The ElaraPQ handshake and AEAD (§4.7) remain unchanged in every case; only the outer wrapper differs:

- **Tor pluggable transports:** Elara nodes can speak ElaraPQ inside a Tor obfs4 / Snowflake / meek tunnel, hiding the fact that the underlying traffic is Elara at all.
- **WireGuard / Tailscale / SSH tunneling:** ElaraPQ inside a WireGuard datagram or SSH port-forward — useful in network environments where the outer protocol is allowlisted.
- **Steganographic encoding:** Validation records embedded in innocent-looking traffic (images, video calls, DNS queries) for extreme cases. Per-message overhead is high; reserved for one-shot record exfiltration, not bulk gossip.
- **Bridge relays:** Unlisted relay nodes operated by volunteers outside the censoring jurisdiction, accessible via out-of-band key exchange. The bridge speaks ElaraPQ inward and any allowlisted outer transport outward.

The protocol explicitly does **not** support a "domain-fronting mode" that masquerades as classical HTTPS to a permitted CDN. Earlier drafts of this section listed domain fronting as a pluggable transport; that recommendation is retired by §4.7. Domain fronting requires a classical TLS outer layer, which leaks per-connection metadata (TLS ClientHello fingerprints, SNI when not encrypted via ECH) and breaks the post-quantum forward-secrecy goal of the transport. Operators who need DPI bypass in a censored environment should use the carriers above, not bake classical TLS into the protocol.

**Defense Layer 2: Partition Resilience (Already Built-In)**

The DAM's partition tolerance (Section 7.3) means censorship IS a partition. If a government blocks cross-border traffic:

1. The domestic zone continues operating independently
2. Domestic validations remain cryptographically valid
3. When the censorship lifts (regime change, policy reversal, VPN access), the zones merge
4. Nothing is lost — the domestic branch of the DAM is fully preserved

A government can slow the network. It cannot kill records that already exist on the DAM, and it cannot prevent domestic validation from continuing.

**Defense Layer 3: Mesh Networking Fallback**

In extreme censorship scenarios (internet shutdown), devices can form local mesh networks:

- **Bluetooth mesh:** Phone-to-phone, ~100 meter range, chain across a city
- **LoRa mesh:** 10+ km range, low bandwidth but sufficient for compact validation payloads (full PQC records require gateway relay)
- **Sneakernet:** Physical transfer of DAM data via USB drives, SD cards — the protocol supports offline sync by design

Records validated during an internet blackout propagate when any node in the mesh eventually reaches the global network. The DAM is patient. It can wait.

**Defense Layer 4: Geographic Distribution of Anchor Nodes**

The protocol requires anchor nodes on at least 3 continents for the decentralization threshold (Section 11.4). Once that threshold is reached, no single government can compel all anchor nodes to comply — though the pre-launch network currently runs on a single-region development fleet and has not yet reached it. Even if a government seizes all domestic anchor nodes, the global DAM continues — and the domestic zone's records are already replicated internationally.

