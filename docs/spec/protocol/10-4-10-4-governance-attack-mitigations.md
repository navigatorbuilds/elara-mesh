### 10.4 Governance Attack Mitigations

The conviction voting mechanism (Section 10.3) is designed to resist several known governance attacks:

**Sybil resistance:** Governance weight grows with the square root of stake (below), so it is *not* split-neutral: dividing a stake across k identities multiplies its total weight by up to √k. What limits this is the cost of each extra identity (Section 11.1), not the weighting; the runtime's docs/KNOWN-LIMITATIONS.md (limitation 26) records the same effect in proposer ranking. The economic cost of acquiring sufficient beats to dominate governance scales with network value.

**Flash-vote attacks:** The 7-day unstaking cooldown prevents an attacker from borrowing beats, voting, and returning them in a single transaction: staked beats stay locked for at least 7 days. The conviction curve then discounts late votes: a vote cast less than 7 days before the tally carries less than 63% of its stake's conviction (less than about 79% of its full weight). The curve does not lengthen the lock: a vote keeps the weight of the stake it was cast with even if that stake is unstaked after the cooldown, so the capital an attacker must commit is a 7-day lock, not 30 days of sustained staking. Re-checking the voter's stake at settlement is an open defect.

**Vote buying:** While the protocol cannot prevent off-chain vote buying, the 30-day implementation delay (Section 10.3) allows the community to detect and respond to suspicious voting patterns before changes take effect. The design lets zones invoke an emergency veto (requiring >75% of anchor nodes) to block proposals that passed through suspected manipulation; the veto is not yet wired into the network (see below).

**Plutocracy mitigation:** Raw beat-weighted voting favors wealthy participants. The protocol applies a **square-root dampening** to conviction weight. The combined governance weight formula is:

```
governance_weight = min(√(stake × (1 - e^(-t/τ))), W / √N)
where τ = 7 days, t = time since the vote was cast, N = number of identities
voting on the proposal, W = the sum of all their weights before the cap,
and the cap is per identity
```

An entity staking 10,000 beats has √10 ≈ 3.16× the influence of an entity staking 1,000 beats, not 10×. The conviction curve then weights each vote by the time since it was cast (a vote's weight reaches about 99.3% of its full value at 30 days), and the cap limits any single identity's weight to `1/√N` of the proposal's total weight before the cap (N = identities voting on the proposal — at 100 voters the cap is 10%, at 10,000 it's 1%, at 1M it's 0.1%; a proposal with a single voter has no cap). The cap is per identity, so a holder who splits stake across identities can exceed it in total.

**Emergency veto abuse:** The emergency veto (>75% of anchor nodes) is a powerful mechanism that could itself be gamed. Constraints: (1) a veto can only block, never propose — it cannot be used to force changes, only prevent them; (2) vetoes are rate-limited to 2 per zone per quarter; (3) any veto triggers a mandatory public disclosure of the veto rationale within 72 hours; (4) if a vetoed proposal passes a second vote with >80% conviction after the disclosure period, the veto is overridden. This ensures the veto is a circuit breaker, not a permanent kill switch. **Status:** the runtime's governance state machine implements the veto threshold and constraints (1) and (2), but no record type carries a veto signal yet, so the veto cannot be invoked on the network; constraints (3) and (4) are not implemented.

