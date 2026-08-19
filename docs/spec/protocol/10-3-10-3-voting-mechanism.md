### 10.3 Voting Mechanism

Cross-zone decisions use a **conviction voting** model [36] (inspired by conviction voting mechanisms pioneered by Commons Stack and 1Hive, 2019):

- Beat holders express preferences by staking beats toward proposals
- Voting weight accrues over time according to: conviction(t) = stake × (1 - e^(-t/τ)) where t is days staked and τ = 7 days (time constant). Weight reaches ~63% at 7 days, ~86% at 14 days, ~95% at 21 days, and ~98.6% (effectively full conviction) at 30 days. The exponential ramp makes flash-vote attacks economically pointless — meaningful conviction requires sustained commitment.
- Proposals require both **supermajority** (>67% of conviction-weighted stake) and **quorum** (>25% of all staked beats participating)
- Implementation is delayed 30 days after passing (allowing zones to prepare)

> **Note:** Additional governance mechanisms — including trust-weighted random committee selection, identity-based voting caps, and anti-pooling measures — complement the conviction voting model described here and are specified separately.

