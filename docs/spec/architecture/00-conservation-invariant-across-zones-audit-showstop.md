### Conservation Invariant Across Zones

**Per-zone invariant:** Each zone maintains:
```
sum(zone_account_balances) + sum(zone_pending_outbound_xzone) = zone_total
```
This is locally verifiable by any node holding the zone.

**Zone-total reporting:** Each epoch seal includes `zone_balance_total`. This is the zone's self-reported aggregate.

**Global invariant verification:**
```
sum(all_zone_balance_totals) + sum(all_pending_xzone) + conservation_pool == GENESIS_SUPPLY
```
Any archive node (or any node subscribed to a global monitoring zone) can verify this by collecting epoch seals from all zones and summing their reported totals.

**Fraud proof:** If a zone lies about its `zone_balance_total` (inflating to create beats from nothing), any node holding that zone's records can:
1. Compute the real total from the zone's ledger
2. Submit a fraud proof: "Zone X claims balance_total=Y but actual is Z, here's the Merkle proof of every account"
3. Zone's anchor node gets slashed for submitting a false epoch seal

