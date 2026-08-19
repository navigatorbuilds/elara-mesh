### Dormancy

`last_active` is tracked per-identity in the ledger CF. Activity in ANY zone updates it (the zone reports identity activity in its epoch seal metadata). Dormancy is global — if an identity is active in any zone, it's not dormant.
