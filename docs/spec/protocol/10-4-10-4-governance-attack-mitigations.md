### 10.4 Governance Attack Mitigations

The conviction voting mechanism (Section 10.3) is designed to resist several known governance attacks:

**Sybil resistance:** Voting power is proportional to staked beats, not identity count. Creating 1,000 identities with 1 beat each provides the same voting power as 1 identity with 1,000 beats — Sybil attacks gain nothing. The economic cost of acquiring sufficient beats to dominate governance scales with network value.

**Flash loan / flash vote attacks:** Conviction voting's time-weighted staking prevents an attacker from borrowing beats, voting, and returning them in a single transaction. The exponential conviction curve means beats staked for less than 7 days carry less than 63% weight, and full conviction (~98.6%) requires 30 days of sustained staking. This makes flash attacks economically pointless — the capital lockup cost exceeds any governance manipulation benefit.

**Vote buying:** While the protocol cannot prevent off-chain vote buying, the 30-day implementation delay (Section 10.3) allows the community to detect and respond to suspicious voting patterns before changes take effect. Zones can invoke emergency veto (requiring >75% of anchor nodes) to block proposals that passed through suspected manipulation.

**Plutocracy mitigation:** Raw beat-weighted voting favors wealthy participants. The protocol applies a **square-root dampening** to conviction weight. The combined governance weight formula is:

```
governance_weight = min(√stake × (1 - e^(-t/τ)), (1/√N) × TOTAL_STAKED)
where τ = 7 days, N = total active stakers, and the cap is per-identity
```

An entity staking 10,000 beats has √10 ≈ 3.16× the influence of an entity staking 1,000 beats, not 10×. The conviction curve then weights by lock duration (reaching ~98.6% at 30 days), and the scaling cap ensures no single identity exceeds `1/√N` of total governance weight regardless of stake size (where N = total active stakers — at 100 stakers the cap is 10%, at 10,000 it's 1%, at 1M it's 0.1%). Extended analysis of pool-centralization risks and additional anti-centralization mechanisms is specified separately.

**Emergency veto abuse:** The emergency veto (>75% of anchor nodes) is a powerful mechanism that could itself be gamed. Constraints: (1) a veto can only block, never propose — it cannot be used to force changes, only prevent them; (2) vetoes are rate-limited to 2 per zone per quarter; (3) any veto triggers a mandatory public disclosure of the veto rationale within 72 hours; (4) if a vetoed proposal passes a second vote with >80% conviction after the disclosure period, the veto is overridden. This ensures the veto is a circuit breaker, not a permanent kill switch.

