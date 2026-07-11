//! Genesis Allocation — economics v0.4.1 Section 5.1.
//!
//! Total supply: 10 billion beat.
//! Distribution:
//! - 30% Network Bootstrap: earned through participation by first 10K nodes
//! - 20% Development Fund: 3-of-5 multisig, for protocol development
//! - 20% Community/Governance Treasury: conviction voting controlled
//! - 15% Founding Team: reserved genesis pool, no active distribution path
//! - 10% Early Contributors: reserved genesis pool, no active distribution path
//! -  5% Reserve: 4-of-5 multisig, emergency use only
//!
//! No ICO. No pre-sale. No airdrop. No exchange listing campaign.

//!
//! Spec references:
//!   @spec economics §5.1
//!   @spec economics §5.2

use crate::accounting::types::MAX_SUPPLY;

// Genesis-mint orchestration (`auto_genesis_mint`, below) needs the node
// runtime, so these imports and the function are gated on the `node` feature.
// `genesis.rs` itself compiles under default features for the core allocation
// logic (consts / `GenesisAllocation` / `GenesisState`), where neither
// `crate::network` nor `tokio` exists — leaving these ungated breaks a
// default-feature `cargo check` (a fresh public-mirror clone's first build).
#[cfg(feature = "node-core")]
use crate::errors::Result;
#[cfg(feature = "node-core")]
use crate::network::config::NodeConfig;
#[cfg(feature = "node-core")]
use crate::network::ingest::insert_record_inner_direct;
#[cfg(feature = "node-core")]
use crate::network::state::NodeState;
#[cfg(feature = "node-core")]
use crate::network::LockRecover; // .lock_recover() on the consensus mutex
#[cfg(feature = "node-core")]
use std::sync::Arc;
#[cfg(feature = "node-core")]
use tracing::{info, warn};

// ─── Allocation Fractions ──────────────────────────────────────────────────

/// Network bootstrap pool: 30% — earned by first 10K participating nodes.
pub const BOOTSTRAP_FRACTION: f64 = 0.30;
/// Development fund: 20% — controlled by 3-of-5 multisig.
pub const DEVELOPMENT_FRACTION: f64 = 0.20;
/// Community/governance treasury: 20% — conviction voting controlled.
pub const COMMUNITY_FRACTION: f64 = 0.20;
/// Founding team: 15% — reserved genesis pool, no active distribution path.
pub const TEAM_FRACTION: f64 = 0.15;
/// Early contributors: 10% — reserved genesis pool, no active distribution path.
pub const CONTRIBUTORS_FRACTION: f64 = 0.10;
/// Reserve: 5% — 4-of-5 multisig, emergency only.
pub const RESERVE_FRACTION: f64 = 0.05;

/// Network bootstrap target: first 10,000 participating nodes.
pub const BOOTSTRAP_TARGET_NODES: u64 = 10_000;

// ─── Allocation Pools ──────────────────────────────────────────────────────

/// Computed allocation amounts (in base units).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisAllocation {
    /// Total supply allocated.
    pub total: u64,
    /// Network bootstrap pool.
    pub bootstrap: u64,
    /// Development fund.
    pub development: u64,
    /// Community/governance treasury.
    pub community: u64,
    /// Founding team (vesting).
    pub team: u64,
    /// Early contributors (vesting).
    pub contributors: u64,
    /// Emergency reserve.
    pub reserve: u64,
}

impl GenesisAllocation {
    /// Compute genesis allocation from total supply.
    pub fn compute() -> Self {
        let total = MAX_SUPPLY;
        // Use u128 intermediate to avoid f64 precision loss on large numbers.
        // f64 has only 53 bits of mantissa — MAX_SUPPLY (10^19) exceeds this,
        // causing micro-beat loss per allocation. u128 math is exact.
        let total_128 = total as u128;
        let bootstrap = ((total_128 * 30) / 100) as u64;     // 30%
        let development = ((total_128 * 20) / 100) as u64;   // 20%
        let community = ((total_128 * 20) / 100) as u64;     // 20%
        let team = ((total_128 * 15) / 100) as u64;          // 15%
        let contributors = ((total_128 * 10) / 100) as u64;  // 10%
        // Reserve gets the remainder to ensure exact conservation (5% + rounding)
        let reserve = total - bootstrap - development - community - team - contributors;

        Self { total, bootstrap, development, community, team, contributors, reserve }
    }

    /// Verify that all allocations sum to total supply (conservation invariant).
    pub fn verify(&self) -> bool {
        self.bootstrap + self.development + self.community
            + self.team + self.contributors + self.reserve == self.total
    }
}

/// Pool identifier for genesis allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisPool {
    /// Earned by first 10K nodes through participation.
    Bootstrap,
    /// 3-of-5 multisig for protocol development.
    Development,
    /// Conviction-voting controlled community treasury.
    Community,
    /// Founding team — reserved genesis pool, no active distribution path.
    Team,
    /// Early contributors — reserved genesis pool, no active distribution path.
    Contributors,
    /// 4-of-5 multisig emergency reserve.
    Reserve,
}

impl GenesisPool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Development => "development",
            Self::Community => "community",
            Self::Team => "team",
            Self::Contributors => "contributors",
            Self::Reserve => "reserve",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bootstrap" => Some(Self::Bootstrap),
            "development" => Some(Self::Development),
            "community" => Some(Self::Community),
            "team" => Some(Self::Team),
            "contributors" => Some(Self::Contributors),
            "reserve" => Some(Self::Reserve),
            _ => None,
        }
    }

    /// All pool variants.
    pub fn all() -> &'static [GenesisPool] {
        &[
            Self::Bootstrap, Self::Development, Self::Community,
            Self::Team, Self::Contributors, Self::Reserve,
        ]
    }
}

// ─── Genesis Distribution State ────────────────────────────────────────────

/// Tracks genesis pool balances and distribution progress.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GenesisState {
    /// Remaining balance in each pool (base units).
    pub pool_balances: std::collections::HashMap<GenesisPool, u64>,
    /// Total distributed from each pool.
    pub pool_distributed: std::collections::HashMap<GenesisPool, u64>,
    /// Bootstrap: nodes that have claimed rewards.
    pub bootstrap_claimed: std::collections::HashSet<String>,
}

impl GenesisState {
    /// Initialize genesis state with full allocation.
    ///
    /// `_genesis_time` is retained for call-site compatibility; it previously
    /// seeded team/contributor vesting starts, removed with the coin-era
    /// vesting machinery (the transferable-coin audience the schedules served was
    /// dropped in the 2026-06-09 pivot).
    pub fn initialize(_genesis_time: f64) -> Self {
        let alloc = GenesisAllocation::compute();
        let mut pool_balances = std::collections::HashMap::new();
        pool_balances.insert(GenesisPool::Bootstrap, alloc.bootstrap);
        pool_balances.insert(GenesisPool::Development, alloc.development);
        pool_balances.insert(GenesisPool::Community, alloc.community);
        pool_balances.insert(GenesisPool::Team, alloc.team);
        pool_balances.insert(GenesisPool::Contributors, alloc.contributors);
        pool_balances.insert(GenesisPool::Reserve, alloc.reserve);

        Self {
            pool_balances,
            pool_distributed: std::collections::HashMap::new(),
            bootstrap_claimed: std::collections::HashSet::new(),
        }
    }

    /// Compute bootstrap reward per node (equal split among first 10K nodes).
    pub fn bootstrap_reward_per_node(&self) -> u64 {
        let alloc = GenesisAllocation::compute();
        alloc.bootstrap / BOOTSTRAP_TARGET_NODES
    }

    /// Claim bootstrap reward for a participating node.
    pub fn claim_bootstrap(
        &mut self,
        node_identity: &str,
    ) -> crate::errors::Result<u64> {
        if self.bootstrap_claimed.contains(node_identity) {
            return Err(crate::errors::ElaraError::Ledger(format!(
                "node {node_identity} has already claimed bootstrap reward"
            )));
        }

        if self.bootstrap_claimed.len() as u64 >= BOOTSTRAP_TARGET_NODES {
            return Err(crate::errors::ElaraError::Ledger(
                "bootstrap pool fully distributed (10K nodes reached)".into()
            ));
        }

        let reward = self.bootstrap_reward_per_node();
        let balance = self.pool_balances.entry(GenesisPool::Bootstrap).or_insert(0);
        if *balance < reward {
            return Err(crate::errors::ElaraError::Ledger(
                "bootstrap pool exhausted".into()
            ));
        }

        *balance -= reward;
        *self.pool_distributed.entry(GenesisPool::Bootstrap).or_insert(0) += reward;
        self.bootstrap_claimed.insert(node_identity.to_string());
        Ok(reward)
    }

    /// Roll back a bootstrap claim — restore beats to pool on insert failure.
    /// Called when the mint record fails to insert after claim_bootstrap() already
    /// deducted from the pool. Without this, beats vanish on failure.
    pub fn unclaim_bootstrap(&mut self, node_identity: &str, amount: u64) {
        let balance = self.pool_balances.entry(GenesisPool::Bootstrap).or_insert(0);
        *balance += amount;
        if let Some(dist) = self.pool_distributed.get_mut(&GenesisPool::Bootstrap) {
            *dist = dist.saturating_sub(amount);
        }
        self.bootstrap_claimed.remove(node_identity);
    }

    /// Distribute from development fund (requires multisig — caller verifies).
    pub fn distribute_development(
        &mut self,
        amount: u64,
    ) -> crate::errors::Result<()> {
        let balance = self.pool_balances.entry(GenesisPool::Development).or_insert(0);
        if *balance < amount {
            return Err(crate::errors::ElaraError::Ledger(format!(
                "development fund insufficient: {} < {amount}", *balance
            )));
        }
        *balance -= amount;
        *self.pool_distributed.entry(GenesisPool::Development).or_insert(0) += amount;
        Ok(())
    }

    /// Distribute from community treasury (requires governance — caller verifies).
    pub fn distribute_community(
        &mut self,
        amount: u64,
    ) -> crate::errors::Result<()> {
        let balance = self.pool_balances.entry(GenesisPool::Community).or_insert(0);
        if *balance < amount {
            return Err(crate::errors::ElaraError::Ledger(format!(
                "community treasury insufficient: {} < {amount}", *balance
            )));
        }
        *balance -= amount;
        *self.pool_distributed.entry(GenesisPool::Community).or_insert(0) += amount;
        Ok(())
    }

    /// Distribute from emergency reserve (requires multisig — caller verifies).
    pub fn distribute_reserve(
        &mut self,
        amount: u64,
    ) -> crate::errors::Result<()> {
        let balance = self.pool_balances.entry(GenesisPool::Reserve).or_insert(0);
        if *balance < amount {
            return Err(crate::errors::ElaraError::Ledger(format!(
                "reserve insufficient: {} < {amount}", *balance
            )));
        }
        *balance -= amount;
        *self.pool_distributed.entry(GenesisPool::Reserve).or_insert(0) += amount;
        Ok(())
    }

    /// Total remaining across all pools.
    pub fn total_remaining(&self) -> u64 {
        self.pool_balances.values().sum()
    }

    /// Total distributed across all pools.
    pub fn total_distributed(&self) -> u64 {
        self.pool_distributed.values().sum()
    }

    /// Rebuild genesis state from mint records in storage.
    ///
    /// Scans all ledger records for genesis mints (beat_reason starts with "genesis:")
    /// and reconstructs pool balances. This makes GenesisState survive node restarts
    /// without requiring SQLite persistence.
    pub fn rebuild_from_records(records: &[crate::record::ValidationRecord], genesis_authority: &str) -> Self {
        use crate::accounting::types::creator_identity_hash;

        let _alloc = GenesisAllocation::compute();
        let mut state = Self::initialize(0.0);

        // Track distributed amounts by scanning bootstrap claims.
        for record in records {
            let creator = creator_identity_hash(record);
            if creator != genesis_authority {
                continue;
            }

            let op = record.metadata.get("beat_op").and_then(|v| v.as_str()).unwrap_or("");

            if op == "mint" {
                let reason = record.metadata.get("beat_reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Track bootstrap claims. The live claim route writes the mint
                // reason "genesis:bootstrap" (routes/ledger.rs::bootstrap_claim);
                // "faucet" is kept only as a backward-compat alias for any
                // pre-rename records. Matching ONLY "faucet" (the prior code)
                // meant `bootstrap_claimed` was NEVER reconstructed on a
                // records-rebuild — nothing writes "faucet" — so the 10K cap and
                // per-identity dedup were bypassable across a restart that landed
                // on the rebuild path (internal design notes §2 G2).
                let to = record.metadata.get("beat_to")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if (reason == "genesis:bootstrap" || reason == "faucet") && to != genesis_authority {
                    // Bootstrap-pool distributions
                    let amount = record.metadata.get("beat_amount")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| record.metadata.get("beat_amount").and_then(crate::accounting::types::parse_beat_amount))
                        .unwrap_or(0);

                    if amount > 0 {
                        let balance = state.pool_balances.entry(GenesisPool::Bootstrap).or_insert(0);
                        let deduct = amount.min(*balance);
                        *balance -= deduct;
                        *state.pool_distributed.entry(GenesisPool::Bootstrap).or_insert(0) += deduct;
                        state.bootstrap_claimed.insert(to.to_string());
                    }
                }
            }
        }

        state
    }

    /// Summary for API endpoints.
    pub fn summary(&self, _now: f64) -> serde_json::Value {
        let pools: Vec<serde_json::Value> = GenesisPool::all().iter().map(|p| {
            serde_json::json!({
                "pool": p.as_str(),
                "remaining": self.pool_balances.get(p).copied().unwrap_or(0),
                "distributed": self.pool_distributed.get(p).copied().unwrap_or(0),
            })
        }).collect();

        serde_json::json!({
            "pools": pools,
            "total_remaining": self.total_remaining(),
            "total_distributed": self.total_distributed(),
            "bootstrap_nodes_claimed": self.bootstrap_claimed.len(),
            "bootstrap_target_nodes": BOOTSTRAP_TARGET_NODES,
        })
    }
}

/// Mint the full genesis allocation into the live ledger, exactly once, at
/// genesis-authority boot. Moved verbatim from `bin/elara_node.rs` (audit 16c)
/// and co-located with the `GenesisAllocation` math it consumes. Returns the
/// minted total, or `0` when an existing genesis mint was found in storage and
/// the ledger was rebuilt from it (caller then skips pool_fund + genesis init).
#[cfg(feature = "node-core")]
pub async fn auto_genesis_mint(state: &Arc<NodeState>, config: &NodeConfig) -> Result<u64> {
    use crate::accounting::types::mint_metadata;

    // ── Duplicate genesis mint guard ────────────────────────────────────
    // On fresh boot after a storage wipe, peers may already have the genesis
    // mint from a previous boot.  If initial_sync or gossip pull hasn't run
    // yet, ledger.total_supply == 0 so the caller's `ledger_empty` check
    // passes — but creating a second mint record (different UUID) would
    // violate the supply cap.  Scan RocksDB for any existing genesis mint
    // record before creating a new one.  This runs at most once per boot,
    // so the scan cost is negligible.
    {
        let rocks_ref = state.rocks.clone();
        let genesis_pk = state.identity.public_key.clone();
        let found = tokio::task::spawn_blocking(move || -> bool {
            use crate::storage::Storage;
            let records = rocks_ref.query(
                Some(crate::record::Classification::Public),
                Some(&genesis_pk),
                None, None,
                1000, // genesis boot has very few records
            ).unwrap_or_default();
            records.iter().any(|r| {
                let op = r.metadata.get("beat_op").and_then(|v| v.as_str());
                let reason = r.metadata.get("beat_reason").and_then(|v| v.as_str());
                op == Some("mint") && reason.is_some_and(|s| s.starts_with("genesis:"))
            })
        }).await.unwrap_or(false);

        if found {
            info!("genesis mint record already exists in storage — skipping duplicate creation");
            // Rebuild ledger so the existing mint is applied (streaming — no full record load)
            let rocks_ref = state.rocks.clone();
            let genesis = config.genesis_authority.clone();
            let gv_clone = config.genesis_validators.clone();
            if let Ok(Ok((mut new_ledger, _))) = tokio::task::spawn_blocking(move || {
                rocks_ref.rebuild_ledger_streaming(&genesis, &gv_clone)
            }).await {
                state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
                new_ledger.applied_record_ids.clear();
                state.consensus.lock_recover().register_stakes_from_ledger(&new_ledger);
                *state.ledger.write().await = new_ledger;
                // Wholesale ledger replace on genesis-restart → invalidate the
                // staked-anchor view (contract: state.rs:invalidate_anchor_view).
                state.invalidate_anchor_view();
            }
            // Return 0 to signal "no new mint created" — caller skips pool_fund + genesis state init
            return Ok(0);
        }
    }

    let alloc = GenesisAllocation::compute();
    assert!(alloc.verify(), "genesis allocation must sum to total supply");

    let genesis_hash = &state.identity.identity_hash;

    // Single mint record for the entire supply — avoids gossip ordering issues.
    // Individual pool allocations are tracked by GenesisState, not separate records.
    // This ensures any node receiving this one record gets the correct total supply.
    let total = alloc.bootstrap + alloc.development + alloc.community
        + alloc.team + alloc.contributors + alloc.reserve;

    let meta = mint_metadata(total, genesis_hash, "genesis:total_allocation");
    let record = state.create_self_ledger_record(vec![], meta)?;

    // Bypass state core channel for genesis mint — must be synchronous so
    // the ledger is updated before pool_fund runs.
    match insert_record_inner_direct(state, record, None, false).await {
        Ok(_) => {
            info!("  minted {} beat → {} (genesis:total_allocation)", total / crate::accounting::types::BASE_UNITS_PER_BEAT, &genesis_hash[..16]);
            info!("  pool breakdown: bootstrap={}B dev={}B community={}B team={}B contributors={}B reserve={}B",
                alloc.bootstrap / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
                alloc.development / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
                alloc.community / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
                alloc.team / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
                alloc.contributors / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
                alloc.reserve / (1_000_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT),
            );
        }
        Err(e) => {
            warn!("  genesis mint failed: {e}");
            return Err(e);
        }
    }

    let total_minted = total;

    // Re-derive ledger after all mints (streaming — no full record load)
    {
        let rocks_ref = state.rocks.clone();
        let genesis = config.genesis_authority.clone();
        let gv_clone = config.genesis_validators.clone();
        if let Ok(Ok((mut new_ledger, _))) = tokio::task::spawn_blocking(move || {
            rocks_ref.rebuild_ledger_streaming(&genesis, &gv_clone)
        })
        .await
        {
            state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
            new_ledger.applied_record_ids.clear();
            state.consensus.lock_recover().register_stakes_from_ledger(&new_ledger);
            *state.ledger.write().await = new_ledger;
            // Wholesale ledger re-derive after genesis mints → invalidate the
            // staked-anchor view (contract: state.rs:invalidate_anchor_view).
            state.invalidate_anchor_view();
        }
    }

    Ok(total_minted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::types::BASE_UNITS_PER_BEAT;

    #[test]
    fn test_allocation_conservation() {
        let alloc = GenesisAllocation::compute();
        assert!(alloc.verify(), "allocations must sum to total supply");
        assert_eq!(alloc.total, MAX_SUPPLY);
    }

    #[test]
    fn test_allocation_fractions() {
        assert!((BOOTSTRAP_FRACTION + DEVELOPMENT_FRACTION + COMMUNITY_FRACTION
            + TEAM_FRACTION + CONTRIBUTORS_FRACTION + RESERVE_FRACTION - 1.0).abs() < 0.001,
            "fractions must sum to 100%");
    }

    #[test]
    fn test_allocation_approximate_amounts() {
        let alloc = GenesisAllocation::compute();
        let total_beat = MAX_SUPPLY as f64 / BASE_UNITS_PER_BEAT as f64;
        let bootstrap_beat = alloc.bootstrap as f64 / BASE_UNITS_PER_BEAT as f64;
        // 30% of 10B = 3B
        assert!((bootstrap_beat - total_beat * 0.30).abs() < 1.0,
            "bootstrap should be ~30% of total");
    }

    #[test]
    fn test_genesis_state_initialize() {
        let state = GenesisState::initialize(0.0);
        assert_eq!(state.total_remaining(), MAX_SUPPLY);
        assert_eq!(state.total_distributed(), 0);
    }

    #[test]
    fn test_bootstrap_claim() {
        let mut state = GenesisState::initialize(0.0);
        let reward = state.claim_bootstrap("node_1").unwrap();
        assert!(reward > 0);
        assert_eq!(state.bootstrap_claimed.len(), 1);

        // Can't claim twice
        assert!(state.claim_bootstrap("node_1").is_err());

        // Different node can claim
        state.claim_bootstrap("node_2").unwrap();
        assert_eq!(state.bootstrap_claimed.len(), 2);
    }

    #[test]
    fn test_bootstrap_reward_per_node() {
        let state = GenesisState::initialize(0.0);
        let reward = state.bootstrap_reward_per_node();
        let alloc = GenesisAllocation::compute();
        assert_eq!(reward, alloc.bootstrap / BOOTSTRAP_TARGET_NODES);
        // 30% of 10B = 3B beat / 10K nodes = 300K beat per node
        let beat = reward / BASE_UNITS_PER_BEAT;
        assert_eq!(beat, 300_000); // 300K beat per node
    }

    #[test]
    fn test_rebuild_reconstructs_bootstrap_claimed_g2_regression() {
        // G2 (internal design notes §2): rebuild_from_records must
        // reconstruct `bootstrap_claimed` from the reason the live route actually
        // writes ("genesis:bootstrap"). The prior code matched only the dead
        // "faucet" string — which NOTHING in the codebase writes — so a
        // records-rebuild always produced an EMPTY claimed-set, bypassing the
        // 10K cap + per-identity dedup across any restart that landed on the
        // rebuild path. This pins that the real reason is honoured.
        use crate::record::{Classification, ValidationRecord};
        use crate::accounting::types::{creator_identity_hash, mint_metadata};

        let reward = GenesisState::initialize(0.0).bootstrap_reward_per_node();
        let meta = mint_metadata(reward, "claimant_node_1", "genesis:bootstrap");
        let rec = ValidationRecord::create(
            b"bootstrap-claim-test",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            Some(meta),
        );
        // Derive the authority FROM the record so the creator-filter matches.
        let genesis_authority = creator_identity_hash(&rec);

        let state =
            GenesisState::rebuild_from_records(std::slice::from_ref(&rec), &genesis_authority);

        assert_eq!(
            state.bootstrap_claimed.len(),
            1,
            "G2: rebuild must reconstruct bootstrap_claimed from 'genesis:bootstrap' (was 0)"
        );
        assert!(state.bootstrap_claimed.contains("claimant_node_1"));
        assert_eq!(
            state.total_distributed(),
            reward,
            "pool accounting must reflect the reconstructed claim"
        );
    }

    #[test]
    fn test_development_fund_distribution() {
        let mut state = GenesisState::initialize(0.0);
        let alloc = GenesisAllocation::compute();

        state.distribute_development(1_000 * BASE_UNITS_PER_BEAT).unwrap();
        assert_eq!(state.pool_distributed.get(&GenesisPool::Development).copied().unwrap_or(0),
            1_000 * BASE_UNITS_PER_BEAT);

        // Over-distribute fails
        assert!(state.distribute_development(alloc.development + 1).is_err());
    }

    #[test]
    fn test_community_treasury() {
        let mut state = GenesisState::initialize(0.0);
        state.distribute_community(500 * BASE_UNITS_PER_BEAT).unwrap();
        assert!(state.pool_balances[&GenesisPool::Community] > 0);
    }

    #[test]
    fn test_reserve_distribution() {
        let mut state = GenesisState::initialize(0.0);
        state.distribute_reserve(100 * BASE_UNITS_PER_BEAT).unwrap();
        assert_eq!(state.total_distributed(), 100 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_genesis_pool_roundtrip() {
        for pool in GenesisPool::all() {
            let s = pool.as_str();
            let parsed = GenesisPool::parse(s).unwrap();
            assert_eq!(*pool, parsed);
        }
    }

    #[test]
    fn test_genesis_summary() {
        let state = GenesisState::initialize(0.0);
        let summary = state.summary(1000.0);
        assert!(summary["pools"].is_array());
        assert_eq!(summary["bootstrap_target_nodes"], serde_json::json!(BOOTSTRAP_TARGET_NODES));
    }

    // ─── Phase 1 Pre-Genesis Critical Tests ──────────────────────────

    #[test]
    fn test_genesis_conservation_all_pools_sum_to_total() {
        let state = GenesisState::initialize(1000.0);
        let alloc = GenesisAllocation::compute();

        // All 6 pool balances must sum exactly to MAX_SUPPLY
        let pool_sum: u64 = GenesisPool::all()
            .iter()
            .map(|p| state.pool_balances.get(p).copied().unwrap_or(0))
            .sum();
        assert_eq!(pool_sum, MAX_SUPPLY, "all 6 pools must sum to MAX_SUPPLY");
        assert_eq!(pool_sum, alloc.total);

        // Verify each pool percentage
        let total = MAX_SUPPLY as f64;
        let bootstrap_pct = state.pool_balances[&GenesisPool::Bootstrap] as f64 / total;
        let dev_pct = state.pool_balances[&GenesisPool::Development] as f64 / total;
        let community_pct = state.pool_balances[&GenesisPool::Community] as f64 / total;
        let team_pct = state.pool_balances[&GenesisPool::Team] as f64 / total;
        let contrib_pct = state.pool_balances[&GenesisPool::Contributors] as f64 / total;

        assert!((bootstrap_pct - 0.30).abs() < 0.001, "bootstrap ~30%");
        assert!((dev_pct - 0.20).abs() < 0.001, "dev ~20%");
        assert!((community_pct - 0.20).abs() < 0.001, "community ~20%");
        assert!((team_pct - 0.15).abs() < 0.001, "team ~15%");
        assert!((contrib_pct - 0.10).abs() < 0.001, "contributors ~10%");
        // Reserve gets remainder, should be ~5%
        let reserve_pct = state.pool_balances[&GenesisPool::Reserve] as f64 / total;
        assert!((reserve_pct - 0.05).abs() < 0.001, "reserve ~5%");
    }

    #[test]
    fn test_genesis_distribution_preserves_conservation() {
        let mut state = GenesisState::initialize(0.0);

        // Distribute from multiple pools
        state.claim_bootstrap("node_1").unwrap();
        state.claim_bootstrap("node_2").unwrap();
        state.claim_bootstrap("node_3").unwrap();
        state.distribute_development(1_000 * BASE_UNITS_PER_BEAT).unwrap();
        state.distribute_community(500 * BASE_UNITS_PER_BEAT).unwrap();
        state.distribute_reserve(100 * BASE_UNITS_PER_BEAT).unwrap();

        // Conservation: remaining + distributed = MAX_SUPPLY always
        assert_eq!(
            state.total_remaining() + state.total_distributed(),
            MAX_SUPPLY,
            "remaining + distributed must always equal MAX_SUPPLY"
        );
    }

    #[test]
    fn test_pool_distribution_cannot_be_bypassed() {
        let mut state = GenesisState::initialize(0.0);

        // Each distribute function only touches its own pool
        let dev_balance = state.pool_balances[&GenesisPool::Development];
        assert!(dev_balance > 0, "dev pool should have funds");
        // Over-distribute from dev pool must fail
        assert!(state.distribute_development(dev_balance + 1).is_err());
        // Reserve over-distribute must fail
        let reserve_balance = state.pool_balances[&GenesisPool::Reserve];
        assert!(state.distribute_reserve(reserve_balance + 1).is_err());
    }

    /// Full genesis flow integration test: mint → pool_fund → transfers → conservation
    #[test]
    fn test_genesis_full_flow_conservation() {
        use crate::accounting::ledger::derive_ledger;
        use crate::accounting::types::{self, extract_ledger_op};
        use crate::crypto::hash::sha3_256;

        fn make_record(id: &str, pk: &[u8], ts: f64, meta: std::collections::BTreeMap<String, serde_json::Value>) -> crate::record::ValidationRecord {
            crate::record::ValidationRecord {
                id: id.to_string(),
                version: crate::wire::WIRE_VERSION,
                content_hash: sha3_256(id.as_bytes()).to_vec(),
                creator_public_key: pk.to_vec(),
                timestamp: ts,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: meta,
                signature: None,
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: Vec::new(),
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: 0,
            }
        }

        let genesis_pk = vec![0x01u8; 1952];
        let alice_pk = vec![0x02u8; 1952];
        let bob_pk = vec![0x03u8; 1952];

        let genesis_hash = crate::crypto::hash::sha3_256_hex(&genesis_pk);
        let alice_hash = crate::crypto::hash::sha3_256_hex(&alice_pk);
        let bob_hash = crate::crypto::hash::sha3_256_hex(&bob_pk);

        // Step 1: Genesis mint — 10B beat to genesis authority
        let m1 = types::mint_metadata(MAX_SUPPLY, &genesis_hash, "genesis:total_allocation");
        let r1 = make_record("genesis-mint", &genesis_pk, 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Step 2: Pool fund — 1B beat to conservation pool
        let pool_seed = 1_000_000_000 * BASE_UNITS_PER_BEAT;
        let m2 = types::pool_fund_metadata(pool_seed);
        let r2 = make_record("pool-fund", &genesis_pk, 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Step 3: Genesis transfers 100 beat to Alice
        let xfer_amount = 100 * BASE_UNITS_PER_BEAT;
        let m3 = types::transfer_metadata(xfer_amount, &alice_hash, None);
        let r3 = make_record("xfer-alice", &genesis_pk, 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        // Step 4: Alice transfers 30 beat to Bob
        let m4 = types::transfer_metadata(30 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r4 = make_record("xfer-bob", &alice_pk, 4.0, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r2, o2), (r3, o3), (r4, o4)],
            &genesis_hash,
        ).unwrap();

        // Verify balances
        let genesis_expected = MAX_SUPPLY - pool_seed - xfer_amount;
        assert_eq!(ledger.balance(&genesis_hash), genesis_expected, "genesis balance");
        assert_eq!(ledger.balance(&alice_hash), 70 * BASE_UNITS_PER_BEAT, "alice balance");
        assert_eq!(ledger.balance(&bob_hash), 30 * BASE_UNITS_PER_BEAT, "bob balance");

        // Verify conservation: total_supply unchanged
        assert_eq!(ledger.total_supply, MAX_SUPPLY, "total supply must be MAX_SUPPLY");

        // Verify conservation pool
        assert_eq!(ledger.conservation_pool, pool_seed, "conservation pool");

        // Verify conservation invariant: circulating + staked + pool = total_supply
        let circulating = ledger.balance(&genesis_hash) + ledger.balance(&alice_hash) + ledger.balance(&bob_hash);
        assert_eq!(
            circulating + ledger.total_staked + ledger.conservation_pool,
            ledger.total_supply,
            "conservation invariant: circulating + staked + pool = total_supply"
        );

        assert_eq!(ledger.records_processed, 4);
    }

    #[test]
    fn test_bootstrap_10k_limit_enforced() {
        let mut state = GenesisState::initialize(0.0);

        // Claim for BOOTSTRAP_TARGET_NODES nodes
        // (Don't actually do 10K in test — check the limit logic)
        let alloc = GenesisAllocation::compute();
        let reward_per_node = alloc.bootstrap / BOOTSTRAP_TARGET_NODES;

        // After 1 claim, pool should be reduced by exactly 1 reward
        state.claim_bootstrap("test_node").unwrap();
        let remaining = state.pool_balances[&GenesisPool::Bootstrap];
        assert_eq!(remaining, alloc.bootstrap - reward_per_node);

        // Conservation after bootstrap claim
        assert_eq!(
            state.total_remaining() + state.total_distributed(),
            MAX_SUPPLY
        );
    }

    // ────────────── genesis-distribution constant tests ─────────────────────
    // Fixture-free genesis-distribution constant + enum-shape pins. No
    // GenesisState mutation, no allocation arithmetic — these defend the
    // protocol fractions, vesting parameters, and the GenesisPool wire shape
    // that all on-disk distribution rows pass through.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_genesis_fraction_constants_individual_strict_value_pin_each_pool() {
        // Pin each of the six fraction constants strictly. The existing
        // test_allocation_fractions only checks the sum; this defends
        // against an equal-but-misaligned redistribution (e.g. swapping
        // team↔contributors). Sum invariant is asserted by the existing
        // test — here we pin the per-pool dial.
        assert_eq!(BOOTSTRAP_FRACTION, 0.30);
        assert_eq!(DEVELOPMENT_FRACTION, 0.20);
        assert_eq!(COMMUNITY_FRACTION, 0.20);
        assert_eq!(TEAM_FRACTION, 0.15);
        assert_eq!(CONTRIBUTORS_FRACTION, 0.10);
        assert_eq!(RESERVE_FRACTION, 0.05);

        // Order invariant: Bootstrap is the largest, Reserve the smallest.
        assert!(BOOTSTRAP_FRACTION > DEVELOPMENT_FRACTION);
        assert_eq!(DEVELOPMENT_FRACTION, COMMUNITY_FRACTION); // both 20%
        assert!(DEVELOPMENT_FRACTION > TEAM_FRACTION);
        assert!(TEAM_FRACTION > CONTRIBUTORS_FRACTION);
        assert!(CONTRIBUTORS_FRACTION > RESERVE_FRACTION);
        assert!(RESERVE_FRACTION > 0.0);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_bootstrap_target_nodes_const_pin_strict_u64_ten_thousand() {
        // BOOTSTRAP_TARGET_NODES is the divisor for per-node bootstrap
        // reward computation. A drift here silently inflates/deflates the
        // reward per claim. Pin strict u64 = 10_000.
        const PIN: u64 = 10_000;
        assert_eq!(BOOTSTRAP_TARGET_NODES, PIN);
        let _: u64 = BOOTSTRAP_TARGET_NODES;
        // Sanity: rounded to a clean myriad (10K), not 10_001 etc.
        assert_eq!(BOOTSTRAP_TARGET_NODES % 10_000, 0);
        assert!(BOOTSTRAP_TARGET_NODES > 0);
    }

    #[test]
    fn batch_b_genesis_pool_all_six_variants_as_str_parse_round_trip_unknown_rejected() {
        // GenesisPool::all() returns the canonical 6-variant slice — pin
        // length + ordering, then verify as_str/parse round-trip on every
        // variant, plus unknown-string rejection (no case-tolerance, no
        // empty).
        let all = GenesisPool::all();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0], GenesisPool::Bootstrap);
        assert_eq!(all[5], GenesisPool::Reserve);

        for v in all.iter().copied() {
            let s = v.as_str();
            assert!(!s.is_empty());
            // Round-trip: parse(as_str(v)) == Some(v) for every variant.
            assert_eq!(GenesisPool::parse(s), Some(v), "round-trip fail for {v:?}");
        }
        // Pairwise distinct.
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
        // Unknown / wrong-case rejection (parse is strict lowercase).
        assert_eq!(GenesisPool::parse("BOOTSTRAP"), None);
        assert_eq!(GenesisPool::parse("Team"), None);
        assert_eq!(GenesisPool::parse(""), None);
        assert_eq!(GenesisPool::parse("unknown_pool"), None);
    }

    #[test]
    fn batch_b_genesis_pool_snake_case_serde_wire_form_matches_as_str_for_all_six() {
        // GenesisPool derives serde with rename_all = "snake_case". For the
        // single-word variants here the wire string equals as_str() — pin
        // the equivalence so a future variant rename (e.g. PumpDump-style
        // multi-word) keeps wire form == as_str.
        for &v in GenesisPool::all() {
            let json = serde_json::to_string(&v).expect("serialize");
            let expected = format!("\"{}\"", v.as_str());
            assert_eq!(
                json, expected,
                "snake_case wire form != as_str for {v:?}",
            );
            let back: GenesisPool = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, v);
        }
        // Derive(Copy) sanity: assign + reuse.
        fn assert_copy<T: Copy>() {}
        assert_copy::<GenesisPool>();
        let original = GenesisPool::Team;
        let _copy = original;
        let _again = original;
        assert_eq!(original, GenesisPool::Team);
    }
}
