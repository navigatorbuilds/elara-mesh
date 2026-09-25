### 10.3 Voting Mechanism

Cross-zone decisions use a **conviction voting** model [36] (inspired by conviction voting mechanisms pioneered by Commons Stack and 1Hive, 2019):

- Beat stakers vote For, Against or Abstain on proposals. A vote carries the voter's governance stake as it was when the vote was cast; stake delegated to the voter is added when the proposal is settled.
- Voting weight accrues over time according to: conviction(t) = stake × (1 - e^(-t/τ)) where t is the time since the vote was cast and τ = 7 days (time constant). Conviction reaches ~63% of the stake at 7 days, ~86% at 14 days, ~95% at 21 days and ~98.6% at 30 days; after the square-root dampening of Section 10.4, a vote's weight reaches about 79%, 93%, 97.5% and 99.3% of its full value. The voting period is 14 days, so the ramp favours votes cast early in it. Staked beats cannot be unstaked until 7 days after they were staked, so a vote cannot be backed by beats borrowed and returned within a single transaction; the ramp itself does not keep the stake locked (Section 10.4).
- Proposals require both a **supermajority** (For weight at least 67% of the For plus Against weight, after dampening and the per-identity cap; abstentions do not count) and a **quorum** (the stake behind the votes, before dampening, at least 25% of all beats staked for governance)
- Implementation is delayed 30 days after passing (allowing zones to prepare)

> **Implementation status:** Governance does not yet work on a live network. A running node validates governance records when they arrive but does not apply them to its ledger. They are applied only when the node replays records into its ledger: a full rebuild applies them all, but a restart from a ledger checkpoint replays only records newer than the newest one already in the checkpoint, so earlier governance records are skipped. A vote therefore fails validation on any node that has not applied its proposal. Separately, the runtime settles a proposal when the first governance record after its voting deadline is applied, and computes the tally at that record's timestamp rather than at the deadline, so conviction keeps growing after the deadline. Both are open defects, listed in the runtime's docs/KNOWN-LIMITATIONS.md.

> **Note:** The conviction-voting model described here is complemented by the identity-based voting cap (Section 10.4), which also applies to a delegate voting with delegated stake. Trust-weighted random committee selection for critical proposals is implemented in the governance state machine but not yet wired into the network.

