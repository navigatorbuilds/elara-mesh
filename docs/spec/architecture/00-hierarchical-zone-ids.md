### Hierarchical Zone IDs

Current: zone_id is u8 (256 zones max). Production: variable-length hierarchical path.

```
"medical/eu/west/germany/bavaria"
"finance/global"
"iot/manufacturing/toyota/plant-7"
"personal/alice"
```

Zones split like cells when they grow too large. A zone with >N witnesses or >M records per epoch can split into sub-zones. Parent zone anchors authorize the split via governance (Protocol §10.2).

Wire format v3: variable-length zone path replacing u8 zone_id.

---

