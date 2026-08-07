#### 11.25.5 Propagation Bounds (Layer 6)

Hard limits at the gossip layer constrain record size:

- **Maximum metadata entries:** 24 per record
- **Maximum value size:** 2 KB per metadata value
- **Maximum record size:** 64 KB total wire size

Theoretical maximum: 24 entries × 2 KB = 48 KB per record. In practice, most records are 200–500 bytes (a few metadata keys plus a signature). These bounds prevent weaponization of the metadata layer as a distributed storage system.

