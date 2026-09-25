#### 11.25.5 Propagation Bounds (Layer 6)

Hard limits at the gossip layer constrain record size:

- **Maximum metadata entries:** 64 per record — sized so a fully-populated epoch seal (~26 keys today) carries years of additive headroom, while staying under the wire decoder's independent 256-entry bound
- **Maximum value size:** 8 KB per metadata value (sized so hex-encoded Dilithium3 public keys and VRF proofs fit)
- **Maximum record size:** 64 KB total wire size

The binding cap is the 64 KB total record size — the per-field limits intentionally sum above it, so the aggregate bound is what holds. In practice, a record with a few metadata keys is about 6 KB, most of it the ML-DSA-65 signature and public key, or about 41 KB with the optional SPHINCS+ signature (Section 11.32). These bounds prevent weaponization of the metadata layer as a distributed storage system.

