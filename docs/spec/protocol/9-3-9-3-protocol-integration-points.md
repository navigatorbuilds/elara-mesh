### 9.3 Protocol Integration Points

The beat interacts with the protocol at these specific points:

- **PoWaS attestation** (Section 11.1) — witnesses stake beats to participate; difficulty scales with stake
- **Priority propagation** (Section 11.10) — paid tier for faster global reach and requested witnessing
- **Dispute arbitration** (Section 11.13) — parties stake beats to invoke arbitration panels
- **Conviction voting** (Section 10.3) — beat-weighted governance with time-locked conviction
- **Zone health metrics** (Section 11.22) — total staked beats as a zone health indicator
- **Storage delegation** — nodes delegate record storage to storage-specialized nodes in exchange for beats

The mechanisms summarized here are specified in detail elsewhere in this document: the supply model in Section 11.17, governance and anti-centralization measures in Sections 10.3–10.4, the participation faucet in Section 9.5 of the whitepaper, and Sybil-cost analysis in Section 11.1.

**Validation beats are not a financial instrument — by design.** Beats exist only to meter participation — staking for sybil-resistance, witnessing, and storage delegation. They are never sold, issued for money, listed, or traded: no market, no price, no monetary claim. The unit is built for granular accounting, not value — each beat divides into **one billion base units** (10⁹ — nine decimal places), for a total of about **ten quintillion** base units (10¹⁹) across the whole network: enough to meter fractional work across billions of devices. Each base unit is economically meaningless **not because there are so many, but because beats are never traded** — they are accounting entries for work done, not an asset to hold. That is deliberate: a unit of account, never a store of value.

