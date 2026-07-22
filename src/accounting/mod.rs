//! beat — the Elara Protocol's internal accounting unit (validation credits).
//!
//! beat is protocol plumbing — witness staking, sybil resistance, and resource
//! accounting. It is not a cryptocurrency: there is no sale, no listing, and no
//! transfer market. Credit operations are stored as regular ValidationRecords
//! with specific metadata fields; balances are derived by replaying all credit
//! records in DAG order — there is no separate balance database.
//!
//! Design principles (Protocol Whitepaper Section 9):
//! - Conservation over inflation (fixed genesis supply, no post-genesis minting)
//! - No gas fees (Layer 1 validation is always free)
//! - Utility over speculation (credits are non-transferable)
//! - Witness staking, priority services, storage delegation, governance

pub mod acquisition;
pub mod authority;
pub mod uptime_vesting;
pub mod batch;
pub mod cross_zone;
pub mod bootstrap;
pub mod circuit_breaker;
pub mod delegation;
pub mod idle_decay;
pub mod dormancy;
pub mod entity;
pub mod custodial;
pub mod genesis;
pub mod governance;
pub mod ledger;
pub mod limits;
pub mod pending_delta;
pub mod pending_ledger;
pub mod storage_market;
pub mod trust;
pub mod types;
pub mod validate;
pub mod velocity;
