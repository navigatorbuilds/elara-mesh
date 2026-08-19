#### 7.5.2 Interplanetary Extensions (Aspirational)

As humanity expands beyond Earth, the zone model naturally extends to geographic/planetary boundaries where communication latency makes cross-zone synchronization physically constrained:

```
Zone: Earth-Primary
├── Subzone: North America
├── Subzone: Europe
├── Subzone: Asia-Pacific
└── Subzone: Africa

Zone: Luna
├── Subzone: Artemis-Base
└── Subzone: FarSide-Observatory

Zone: Mars
├── Subzone: Ares-Colony-1
└── Subzone: Orbital-Relay

Zone: Deep-Space
└── Subzone: Voyager-Relay
```

In this model, zone assignment transitions from hash-based to latency-based: nodes physically located on Mars would join the Mars zone because cross-planet consensus with Earth nodes is impractical at 3-22 minute one-way delays. The hash-based zone model described in Section 7.5.1 would operate *within* each planetary zone, providing intra-planet shard distribution. This architecture is specified but untested — it is included to demonstrate that the protocol's partition tolerance (Section 7.3) and asynchronous design accommodate interplanetary operation without structural changes.

---

