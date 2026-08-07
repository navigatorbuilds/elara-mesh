### Staking

Staking is GLOBAL, not per-zone. A witness stakes beats once. That stake allows them to participate in consensus for any zone they subscribe to. If slashed in one zone, their global stake is reduced — affecting all zones they witness.

Stakes are tracked in the ledger CF with a `staked` field per identity. Staking/unstaking records go in the zone where the identity's primary activity is (or the `global` zone).
