### 11.22 Cross-Zone Trust Reconciliation

**The problem:** Earth zone has 100,000 witnesses. Mars zone has 50. When zones merge after a partition, a record with 10,000 Earth witnesses and a record with 45 Mars witnesses have vastly different absolute trust scores — but within their zones, both may represent near-universal consensus. How do trust scores combine meaningfully?

**Solution: Relative Trust Normalization**

Trust scores are computed **relative to zone size**, not as absolute witness counts:

```
T_zone(r) = 1 - ∏(1 - w(n) × d(n, W_zone))  for all n in W(r) ∩ zone

T_global(r) = weighted_average(T_zone_i(r) for each zone i that has witnessed r)
              where weight_i = ln(zone_size_i + 1) / Σ ln(zone_size_j + 1)
```

Where d(n, W_zone) is the same correlation discount defined in Section 11.12, computed within the zone's witness set. This ensures that correlated witnesses within a zone do not inflate per-zone trust scores.

**Interpretation:**

- A record witnessed by 45 of 50 Mars nodes has T_mars = ~0.95 (very high within Mars)
- A record witnessed by 10,000 of 100,000 Earth nodes has T_earth = ~0.85
- Upon merge, T_global reflects both: ~0.87 (weighted by zone size logarithmically)

The logarithmic weighting prevents Earth's massive node count from completely dominating. Mars's consensus matters proportionally — a smaller zone with near-unanimous agreement is a strong signal.

**Edge case — conflicting records across zones:**

If Earth and Mars both validated records claiming the same content hash by different creators during a partition:

1. Both records are preserved (no deletion)
2. Each record carries its zone-relative trust score
3. The conflict is flagged with a **partition conflict** annotation
4. Resolution follows the dispute framework (Section 11.13): temporal priority via causal anchoring where possible, arbitration where not

**Zone trust calibration:**

Each zone publishes a **zone health metric** in its trust headers:

```
ZoneHealth {
    active_witnesses:    count
    total_staked:        beat amount
    median_reputation:   reputation score
    uptime_30d:          percentage
}
```

This allows global trust calculations to discount zones with low participation or unhealthy metrics, preventing a tiny zone with 3 colluding nodes from injecting high-trust records.

