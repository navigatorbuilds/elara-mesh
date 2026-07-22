# Protocol Economics — Validation Beats

> **Beats are an internal protocol mechanism — not a cryptocurrency.
> No sale, no listing, no monetary claim.** The unit is called the *beat*
> It exists to make sybil resistance
> and throughput allocation expensive to attack, and for nothing else.

This document describes **only what the code actually does today**. Every
mechanism below is grounded in a source reference you can read and check.
Forward-looking participation design that is *not yet implemented* (the
free-participation floor, apprentice witnessing) lives separately in
[`EARN-IN-ECONOMY.md`](EARN-IN-ECONOMY.md) and is labelled as design there —
nothing in this file is aspirational.

The defining property is simple: **after genesis, the beat supply is a
strict constant.** Nothing is minted, nothing is destroyed. Every operation
that looks "destructive" — slashing, idle decay, dormancy reclaim, even an
explicit burn — *recycles* beats into a transparent on-ledger pool rather
than removing them. There is no emission curve, no inflation, no fee burn.

---

## 1. Unit and supply

| Property | Value | Source |
|----------|-------|--------|
| Base atomic unit | 1 beat = 1,000,000,000 units (9 decimals) | `src/accounting/types.rs` (`BASE_UNITS_PER_BEAT`) |
| Maximum supply | 10,000,000,000 beats (10¹⁹ atomic units, fits u64) | `src/accounting/types.rs` (`MAX_SUPPLY`) |
| Supply after genesis | Fixed — never increases, never decreases | `src/accounting/ledger.rs` (mint cap + burn recycle) |

Supply is fixed for headroom across billions of staking devices, governance,
and storage delegation — not as a market-cap target.

## 2. The conservation invariant

The ledger maintains, at all times:

```
sum(available balances) + total_staked + pending_xzone_locked + conservation_pool
    == total_supply
```

This equality is the protocol's central economic property — beats are
neither created nor destroyed after genesis, only moved between these four
buckets. It is asserted in the ledger and exercised by the conservation tests.
*Source: `src/accounting/ledger.rs` (invariant comment + `apply_op`; conservation
assertions in the ledger test module).*

## 3. Genesis allocation

The entire supply is allocated once, at genesis, across six pools. There is no
ICO, pre-sale, airdrop, or listing campaign — pools are designed to be
governance-controlled, multisig-held, or reserved, and the largest is *earned*, not granted.

| Pool | Share | Control | Source |
|------|-------|---------|--------|
| Network Bootstrap | 30% | **Earned** by the first 10,000 participating nodes † | `genesis.rs` (`BOOTSTRAP_FRACTION`, `BOOTSTRAP_TARGET_NODES`) |
| Development Fund | 20% | 3-of-5 multisig | `genesis.rs` (`DEVELOPMENT_FRACTION`) |
| Community / Governance | 20% | Conviction voting | `genesis.rs` (`COMMUNITY_FRACTION`) |
| Founding Team | 15% | Reserved genesis pool — no active distribution path ‡ | `genesis.rs` (`TEAM_FRACTION`) |
| Early Contributors | 10% | Reserved genesis pool — no active distribution path ‡ | `genesis.rs` (`CONTRIBUTORS_FRACTION`) |
| Reserve | 5% | 4-of-5 multisig, emergency only | `genesis.rs` (`RESERVE_FRACTION`) |

*The **Control** column describes the *intended* governance model. Except for the
Bootstrap pool's earned first-come faucet, these controls (multisig thresholds,
conviction voting) are governance-layer policy and are **not yet enforced in
protocol code** — today `genesis.rs` distributes from these pools on a
"caller-verifies" basis.*

Allocation math uses `u128` intermediates so the six shares sum *exactly* to
`MAX_SUPPLY` with no rounding loss (the reserve absorbs the remainder), and
`GenesisAllocation::verify()` checks the sum. *Source: `genesis.rs`
(`GenesisAllocation::compute`/`verify`).*

† **Network Bootstrap is allocated at genesis, but its earn-and-distribute
mechanism is designed, not yet active.** On the current single-authority
network the genesis allocation is fully minted to the genesis authority (pool
balances are bookkeeping), and `/bootstrap/claim` is inert by design — a
genesis-tagged mint is rejected once supply is at the cap (§4). Distributing
the pool to participating nodes, with anti-sybil gating so one operator cannot
farm it under many keys, is a mainnet-path milestone, not a property of the
network today. *Source: `src/accounting/genesis.rs`; `src/network/routes/token.rs`
(`bootstrap_claim` guard).*

‡ **Founding Team and Early Contributors are reserved genesis pools with no
active distribution path.** An earlier coin-era design vested these allocations
(4-year team / 2-year contributor schedules); that genesis-vesting machinery was
removed when beats were repositioned as a non-tradeable internal protocol
mechanism (not-a-coin pivot, 2026-06-09). The shares remain in the split as
reserved accounting only. *Source: `src/accounting/genesis.rs` (`TEAM_FRACTION`,
`CONTRIBUTORS_FRACTION`; vesting consts removed).*

## 4. No emission

Minting is **genesis-authority-only** and **capped**: any mint that would push
`total_supply` past `MAX_SUPPLY` is rejected, and a genesis-tagged mint is
rejected outright once supply is already at the cap (idempotent / replay-safe
across a storage wipe + gossip re-delivery). There is no time-based emission
schedule, no block reward, and no staking yield minted from nothing. *Source:
`src/accounting/ledger.rs` (`Mint` arm).*

## 5. The Conservation Pool

A virtual identity with no private key — it can only receive beats through
protocol operations, never spend arbitrarily. It is the recycling sink that
keeps the supply constant. *Source: `src/accounting/types.rs`
(`CONSERVATION_POOL_IDENTITY`), `src/accounting/ledger.rs`.*

- **Hard cap: 10% of supply** (`CONSERVATION_POOL_MAX_FRACTION`). Overflow above
  the cap is redistributed proportionally to stakers, never stranded.
- **Inflows (all recycle, none destroy supply):**
  - Slashing — 50% of each slash (§7)
  - Idle decay — 50% of each assessment (§8)
  - Dormancy reclaim — 100% of reclaimed beats (§9)
  - Burn — 100%; a `Burn` op debits the actor and credits the pool, leaving
    `total_supply` unchanged (genesis-authority-only). *Source: `ledger.rs`
    `Burn` arm: "Beats recycled, not destroyed."*

## 6. Staking and throughput

Participation rights are stake-gated, but a free floor keeps the network open
to a $30 phone doing real work.

| Parameter | Value | Source |
|-----------|-------|--------|
| Minimum stake | 100 beats | `types.rs` (`MIN_STAKE`) |
| Free tier | 5 records/day, no stake required | `limits.rs` (`MIN_FREE_TIER_PER_DAY`) |
| Stake → throughput | `effective_limit = base_rate + staked / stake_throughput_ratio / 24` per hour | `network/ingest.rs` |
| `stake_throughput_ratio` | governance-tunable (default 100,000,000 base units = 0.1 beats per daily record → 100 beats stake buys 1,000 records/day) | `governance.rs` default, `limits.rs` bounds |
| Unstake cooldown | 7 days | `types.rs` (`UNSTAKE_COOLDOWN`) |
| Witness bond | 100 beats, locked until unregister | `types.rs` (`WITNESS_BOND_MIN`) |

Stake buys throughput headroom, not consensus weight by itself — sybil
diversity limits and committee selection are enforced elsewhere in consensus.

## 7. Witness rewards

A witness attestation pays the witness from the **conservation pool**, authored
by the genesis authority — beats move, they are not minted. (Manual
creator-funded rewards were removed as a theft vector.) *Source:
`src/accounting/ledger.rs` (`WitnessReward` apply arm: `state.conservation_pool -= amount`).*

| Parameter | Value |
|-----------|-------|
| Default reward | 1 beat / attestation |
| Maximum reward | 10 beats / attestation (hard limit) |
| Minimum reward | 0 (free witnessing is allowed) |

## 8. Slashing

Slashing is **challenge-triggered** (fisherman dispute), not automatic
per-block validator penalty. *Source: `src/accounting/types.rs` (`Slash`,
`MAX_SLASH_PERCENTAGE`, `SLASH_*_FRACTION`).*

- **Hard cap: 50% of stake per violation** (`MAX_SLASH_PERCENTAGE`).
- **Distribution of a slash:** 50% → Conservation Pool · 30% → challenger ·
  20% → jury (sums to 1.0; recycled, supply unchanged).

## 9. Idle decay and dormancy

**Idle decay** is a holding cost that applies **only to exchange-classified
identities, never to end-users.** It scales with churn (7-day inflow+outflow
over average balance) across five tiers, so a quiet custodian pays ~1.8%/yr
while a pump-dump pattern pays ~110%/yr. *Source: `src/accounting/idle_decay.rs`.*

| Churn (7-day) | Rate/day | Annualized |
|---------------|----------|------------|
| < 0.3 | 0.005% | 1.83% |
| 0.3 – 0.7 | 0.01% | 3.65% |
| 0.7 – 1.5 | 0.05% | 18.25% |
| 1.5 – 3.0 | 0.15% | 54.75% |
| > 3.0 | 0.30% | 109.5% |

Each assessment splits 50% → Conservation Pool, 50% → active stakers — nothing
is burned.

**Dormancy reclaim:** after a 5-year dormancy threshold (with a 2-year wake-up
window), an idle account's beats can be reclaimed 100% to the Conservation
Pool. *Source: `src/accounting/types.rs` (`DORMANCY_THRESHOLD`,
`DORMANCY_WAKEUP_WINDOW`, `DormancyReclaim`).*

## 10. Cross-zone beat movement

Beats move between zones by an async-optimistic lock/claim protocol (not a
synchronous two-phase commit), never by minting on one side and trusting the
other: a `XZoneLock` debits the sender and moves
the amount into `pending_xzone_locked`; the destination zone applies a
`XZoneClaim` only against a Merkle proof that the lock was sealed and finalized
(≥2/3 source-committee quorum). Unsealed locks refund passively after 24h;
sealed locks refund via a destination-committee abort proof, backstopped by a
30-day `XZoneStaleReap` hard refund for aborts that never arrive. The locked
amount is counted in the conservation invariant throughout, so supply stays
constant across zone boundaries. *Source: `src/accounting/cross_zone.rs`.*

---

## Appendix A — Rejected alternatives (NOT in the code)

These coin-era mechanisms were designed away by the 2026 pivot and are **absent
from the implementation**. They are listed so a reviewer can confirm the code
matches the posture.

| Mechanism | Status | Why it is absent |
|-----------|--------|------------------|
| Ongoing emission / inflation curve | **Not in code** | Mint is genesis-only and supply-capped; no time-based schedule |
| EIP-1559-style fee burn | **Not in code** | No base-fee mechanism; rewards move existing beats, never burn |
| Per-record creation fee | **Not in code** | Layer-1 validation is free up to the stake-gated limit |
| Exchange listing / liquidity pools / AMM | **Not in code** | Beats are non-tradeable; no DEX/CEX integration exists |
| Liquid-staking derivatives | **Not in code** | Staking is an account-side lock only; no derivative token |
| Dynamic treasury emission | **Not in code** | Treasury is a fixed genesis pool, not an emitting faucet |
| Deflationary burn (supply reduction) | **Not in code** | `Burn` recycles to the Conservation Pool; `total_supply` is unchanged |

## Appendix B — Design-stage, not yet implemented

The following are **design proposals**, not running code. They are documented
in [`EARN-IN-ECONOMY.md`](EARN-IN-ECONOMY.md) and must not be read as current
behaviour:

- Unstaked apprentice witnessing at zero consensus weight (the on-ramp).
- A generous identity-gated free-participation floor beyond the current 5
  records/day tier.
- Genesis pools reframed as a transparently governed public faucet.

---

## Verify this yourself

Every constant above is a `pub const` you can read directly:

```bash
grep -n 'MAX_SUPPLY\|BASE_UNITS_PER_BEAT\|MIN_STAKE\|MAX_SLASH_PERCENTAGE\|SLASH_.*_FRACTION\|CONSERVATION_POOL_MAX_FRACTION' src/accounting/types.rs
grep -n 'FRACTION\|BOOTSTRAP_TARGET' src/accounting/genesis.rs
grep -n 'RATE_\|POOL_FRACTION\|STAKER_FRACTION' src/accounting/idle_decay.rs
```

The conservation invariant is exercised by the ledger test module
(`sum(available) + total_staked + conservation_pool == total_supply`).
