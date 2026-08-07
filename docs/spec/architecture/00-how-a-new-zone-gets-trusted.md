### How a NEW zone gets trusted

Genesis chain verification:
```
genesis_authority (root of trust, hardcoded in every binary)
  ↓ signed first epoch seal
zone "global" anchor nodes
  ↓ authorized new zones via governance (Protocol §10.2)
zone "medical/eu" anchor
  ↓ authorized sub-zone creation
zone "medical/eu/south/montenegro" witnesses
  ↓ signed epoch seal containing the record
the person's record
```

Like X.509 certificate chains. Genesis = root CA. Zone anchors = intermediate CAs.
Witnesses = leaf certificates. The hospital verifies the chain — no direct
communication with Montenegro needed. Just math.

