//! Seed Vault — Multi-Tier Identity Recovery (Protocol §11.2, §11.27).
//!
//! Three independent recovery tiers, any of which can restore identity:
//!
//! - **Tier 1 (Paper):** BIP-39 seed phrase (12-word mnemonic) encoding the
//!   root key, stored offline on paper or metal backup.
//!
//! - **Tier 2 (Hardware Key):** USB or NFC hardware account binding. The root
//!   key (or a derived recovery key) is stored on a tamper-resistant device.
//!
//! - **Tier 3 (Social Recovery):** M-of-N Shamir secret sharing across trusted
//!   contacts. Any M shares reconstruct the recovery key.
//!
//! Each tier operates independently. Recovery via any single tier is sufficient
//! to revoke compromised device keys and enroll new devices.

//!
//! Spec references:
//!   @spec Protocol §12.3

use std::collections::HashMap;

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default social recovery threshold: 3-of-5.
pub const DEFAULT_SOCIAL_M: usize = 3;
pub const DEFAULT_SOCIAL_N: usize = 5;

/// Maximum number of social recovery guardians.
pub const MAX_GUARDIANS: usize = 9;

/// Minimum number of social recovery guardians.
pub const MIN_GUARDIANS: usize = 3;

/// Minimum threshold (M) for social recovery.
pub const MIN_THRESHOLD: usize = 2;

/// Recovery cooldown: time after recovery claim before it takes effect (seconds).
/// 24 hours — gives the legitimate owner time to contest.
pub const RECOVERY_COOLDOWN_SECS: f64 = 86_400.0;

/// Operation key for seed vault records.
pub const SEED_VAULT_OP_KEY: &str = "seed_vault_op";

// ─── Types ─────────────────────────────────────────────────────────────────

/// Recovery tier identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RecoveryTier {
    /// BIP-39 paper backup.
    Paper,
    /// Hardware key (USB/NFC).
    HardwareKey,
    /// M-of-N social recovery via Shamir shares.
    Social,
}

impl RecoveryTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Paper => "paper",
            Self::HardwareKey => "hardware_key",
            Self::Social => "social",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "paper" => Some(Self::Paper),
            "hardware_key" => Some(Self::HardwareKey),
            "social" => Some(Self::Social),
            _ => None,
        }
    }
}

/// Status of a recovery tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TierStatus {
    /// Configured and active.
    Active,
    /// Not yet configured.
    Unconfigured,
    /// Revoked (compromised or replaced).
    Revoked,
}

/// Social recovery guardian.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Guardian {
    /// Guardian's identity hash.
    pub identity: String,
    /// Share index (1-based).
    pub share_index: usize,
    /// When this guardian was added.
    pub added_at: f64,
}

/// Configuration for a single recovery tier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TierConfig {
    /// Which tier.
    pub tier: RecoveryTier,
    /// Current status.
    pub status: TierStatus,
    /// Hash of the recovery key / seed for this tier.
    /// Stored on-chain so the protocol can verify recovery claims.
    pub key_hash: String,
    /// When configured.
    pub configured_at: f64,
    /// Social recovery: guardians.
    pub guardians: Vec<Guardian>,
    /// Social recovery: threshold M.
    pub threshold: usize,
}

/// A pending recovery claim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryClaim {
    /// Record ID of the claim.
    pub record_id: String,
    /// Identity being recovered.
    pub target_identity: String,
    /// Which tier is being used.
    pub tier: RecoveryTier,
    /// New device key to authorize.
    pub new_key_hash: String,
    /// When the claim was submitted.
    pub claimed_at: f64,
    /// When the cooldown expires (claim can be executed).
    pub executable_at: f64,
    /// Whether contested by the current key holder.
    pub contested: bool,
    /// Social recovery: guardian shares submitted.
    pub shares_submitted: usize,
}

/// Parsed seed vault operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedSeedVaultOp {
    /// Configure a recovery tier.
    Configure {
        tier: RecoveryTier,
        key_hash: String,
        guardians: Vec<(String, usize)>,
        threshold: usize,
    },
    /// Initiate recovery via a tier.
    Recover {
        tier: RecoveryTier,
        new_key_hash: String,
        shares_submitted: usize,
    },
    /// Contest a pending recovery claim.
    Contest {
        claim_record_id: String,
    },
    /// Execute a recovery after cooldown.
    Execute {
        claim_record_id: String,
    },
    /// Revoke a tier.
    Revoke {
        tier: RecoveryTier,
    },
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Per-identity vault configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IdentityVault {
    /// Tier configurations.
    pub tiers: HashMap<RecoveryTier, TierConfig>,
    /// Active recovery claims.
    pub pending_claims: Vec<RecoveryClaim>,
    /// Number of successful recoveries.
    pub recovery_count: u64,
}

/// Global seed vault state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SeedVaultState {
    /// Per-identity vaults.
    vaults: HashMap<String, IdentityVault>,
    /// Total recoveries processed.
    total_recoveries: u64,
}

impl SeedVaultState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a recovery tier for an identity.
    pub fn configure_tier(
        &mut self,
        identity: &str,
        tier: RecoveryTier,
        key_hash: &str,
        guardians: Vec<Guardian>,
        threshold: usize,
        now: f64,
    ) -> bool {
        // Validate social recovery params
        if tier == RecoveryTier::Social {
            if guardians.len() < MIN_GUARDIANS || guardians.len() > MAX_GUARDIANS {
                return false;
            }
            if threshold < MIN_THRESHOLD || threshold > guardians.len() {
                return false;
            }
        }

        let vault = self.vaults.entry(identity.to_string()).or_default();
        vault.tiers.insert(
            tier,
            TierConfig {
                tier,
                status: TierStatus::Active,
                key_hash: key_hash.to_string(),
                configured_at: now,
                guardians,
                threshold,
            },
        );
        true
    }

    /// Initiate recovery for an identity.
    pub fn initiate_recovery(
        &mut self,
        identity: &str,
        record_id: &str,
        tier: RecoveryTier,
        new_key_hash: &str,
        shares_submitted: usize,
        now: f64,
    ) -> Option<&RecoveryClaim> {
        let vault = self.vaults.get_mut(identity)?;
        let config = vault.tiers.get(&tier)?;

        if config.status != TierStatus::Active {
            return None;
        }

        // Social recovery: check threshold
        if tier == RecoveryTier::Social && shares_submitted < config.threshold {
            return None;
        }

        let claim = RecoveryClaim {
            record_id: record_id.to_string(),
            target_identity: identity.to_string(),
            tier,
            new_key_hash: new_key_hash.to_string(),
            claimed_at: now,
            executable_at: now + RECOVERY_COOLDOWN_SECS,
            contested: false,
            shares_submitted,
        };

        vault.pending_claims.push(claim);
        vault.pending_claims.last()
    }

    /// Contest a pending recovery claim.
    pub fn contest(&mut self, identity: &str, claim_record_id: &str) -> bool {
        let vault = match self.vaults.get_mut(identity) {
            Some(v) => v,
            None => return false,
        };

        for claim in &mut vault.pending_claims {
            if claim.record_id == claim_record_id && !claim.contested {
                claim.contested = true;
                return true;
            }
        }
        false
    }

    /// Execute a recovery claim after cooldown.
    /// Returns the new key hash if successful.
    pub fn execute_recovery(
        &mut self,
        identity: &str,
        claim_record_id: &str,
        now: f64,
    ) -> Option<String> {
        let vault = self.vaults.get_mut(identity)?;

        let idx = vault
            .pending_claims
            .iter()
            .position(|c| c.record_id == claim_record_id)?;

        let claim = &vault.pending_claims[idx];

        // Must be past cooldown and not contested
        if now < claim.executable_at || claim.contested {
            return None;
        }

        let new_key = claim.new_key_hash.clone();
        vault.pending_claims.remove(idx);
        vault.recovery_count += 1;
        self.total_recoveries += 1;

        Some(new_key)
    }

    /// Revoke a recovery tier.
    pub fn revoke_tier(&mut self, identity: &str, tier: RecoveryTier) -> bool {
        let vault = match self.vaults.get_mut(identity) {
            Some(v) => v,
            None => return false,
        };

        match vault.tiers.get_mut(&tier) {
            Some(config) if config.status == TierStatus::Active => {
                config.status = TierStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    /// Get vault for an identity.
    pub fn vault(&self, identity: &str) -> Option<&IdentityVault> {
        self.vaults.get(identity)
    }

    /// Check if a tier is active for an identity.
    pub fn is_tier_active(&self, identity: &str, tier: RecoveryTier) -> bool {
        self.vaults
            .get(identity)
            .and_then(|v| v.tiers.get(&tier))
            .is_some_and(|c| c.status == TierStatus::Active)
    }

    /// Count of configured tiers for an identity.
    pub fn configured_tier_count(&self, identity: &str) -> usize {
        self.vaults
            .get(identity)
            .map(|v| {
                v.tiers
                    .values()
                    .filter(|c| c.status == TierStatus::Active)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Total recoveries.
    pub fn total_recoveries(&self) -> u64 {
        self.total_recoveries
    }

    /// Total identities with vaults.
    pub fn vault_count(&self) -> usize {
        self.vaults.len()
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for tier configuration.
pub fn configure_metadata(
    tier: RecoveryTier,
    key_hash: &str,
    threshold: usize,
) -> Vec<(String, String)> {
    vec![
        (SEED_VAULT_OP_KEY.to_string(), "configure".to_string()),
        ("tier".to_string(), tier.as_str().to_string()),
        ("key_hash".to_string(), key_hash.to_string()),
        ("threshold".to_string(), threshold.to_string()),
    ]
}

/// Build metadata for a recovery claim.
pub fn recover_metadata(
    tier: RecoveryTier,
    new_key_hash: &str,
    shares: usize,
) -> Vec<(String, String)> {
    vec![
        (SEED_VAULT_OP_KEY.to_string(), "recover".to_string()),
        ("tier".to_string(), tier.as_str().to_string()),
        ("new_key_hash".to_string(), new_key_hash.to_string()),
        ("shares_submitted".to_string(), shares.to_string()),
    ]
}

/// Extract a seed vault operation from record metadata.
pub fn extract_seed_vault_op(metadata: &HashMap<String, String>) -> Option<ParsedSeedVaultOp> {
    let op = metadata.get(SEED_VAULT_OP_KEY)?;
    match op.as_str() {
        "configure" => {
            let tier = RecoveryTier::parse(metadata.get("tier")?)?;
            let key_hash = metadata.get("key_hash")?.clone();
            let threshold = metadata
                .get("threshold")
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            Some(ParsedSeedVaultOp::Configure {
                tier,
                key_hash,
                guardians: Vec::new(),
                threshold,
            })
        }
        "recover" => {
            let tier = RecoveryTier::parse(metadata.get("tier")?)?;
            let new_key_hash = metadata.get("new_key_hash")?.clone();
            let shares_submitted = metadata
                .get("shares_submitted")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            Some(ParsedSeedVaultOp::Recover {
                tier,
                new_key_hash,
                shares_submitted,
            })
        }
        "contest" => {
            let claim_record_id = metadata.get("claim_record_id")?.clone();
            Some(ParsedSeedVaultOp::Contest { claim_record_id })
        }
        "execute" => {
            let claim_record_id = metadata.get("claim_record_id")?.clone();
            Some(ParsedSeedVaultOp::Execute { claim_record_id })
        }
        "revoke" => {
            let tier = RecoveryTier::parse(metadata.get("tier")?)?;
            Some(ParsedSeedVaultOp::Revoke { tier })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure_paper_tier() {
        let mut state = SeedVaultState::new();
        assert!(state.configure_tier(
            "alice",
            RecoveryTier::Paper,
            "hash_seed_phrase",
            Vec::new(),
            0,
            1000.0,
        ));
        assert!(state.is_tier_active("alice", RecoveryTier::Paper));
        assert_eq!(state.configured_tier_count("alice"), 1);
    }

    #[test]
    fn test_configure_hardware_tier() {
        let mut state = SeedVaultState::new();
        assert!(state.configure_tier(
            "alice",
            RecoveryTier::HardwareKey,
            "hash_hw_key",
            Vec::new(),
            0,
            1000.0,
        ));
        assert!(state.is_tier_active("alice", RecoveryTier::HardwareKey));
    }

    #[test]
    fn test_configure_social_tier() {
        let mut state = SeedVaultState::new();
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 1000.0 },
            Guardian { identity: "carol".into(), share_index: 2, added_at: 1000.0 },
            Guardian { identity: "dave".into(), share_index: 3, added_at: 1000.0 },
        ];
        assert!(state.configure_tier(
            "alice",
            RecoveryTier::Social,
            "hash_shamir_root",
            guardians,
            2,
            1000.0,
        ));
        assert!(state.is_tier_active("alice", RecoveryTier::Social));
    }

    #[test]
    fn test_social_tier_rejects_bad_params() {
        let mut state = SeedVaultState::new();
        // Too few guardians
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 1000.0 },
        ];
        assert!(!state.configure_tier(
            "alice",
            RecoveryTier::Social,
            "hash",
            guardians,
            1,
            1000.0,
        ));

        // Threshold > N
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 1000.0 },
            Guardian { identity: "carol".into(), share_index: 2, added_at: 1000.0 },
            Guardian { identity: "dave".into(), share_index: 3, added_at: 1000.0 },
        ];
        assert!(!state.configure_tier(
            "alice",
            RecoveryTier::Social,
            "hash",
            guardians,
            4,
            1000.0,
        ));
    }

    #[test]
    fn test_paper_recovery() {
        let mut state = SeedVaultState::new();
        state.configure_tier("alice", RecoveryTier::Paper, "seed_hash", Vec::new(), 0, 0.0);

        let claim = state
            .initiate_recovery("alice", "rec-1", RecoveryTier::Paper, "new_key", 0, 100.0)
            .unwrap();
        assert!(!claim.contested);
        assert_eq!(claim.executable_at, 100.0 + RECOVERY_COOLDOWN_SECS);

        // Too early
        assert!(state.execute_recovery("alice", "rec-1", 100.0).is_none());

        // After cooldown
        let new_key = state
            .execute_recovery("alice", "rec-1", 100.0 + RECOVERY_COOLDOWN_SECS + 1.0)
            .unwrap();
        assert_eq!(new_key, "new_key");
        assert_eq!(state.total_recoveries(), 1);
    }

    #[test]
    fn test_social_recovery_below_threshold() {
        let mut state = SeedVaultState::new();
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 0.0 },
            Guardian { identity: "carol".into(), share_index: 2, added_at: 0.0 },
            Guardian { identity: "dave".into(), share_index: 3, added_at: 0.0 },
        ];
        state.configure_tier("alice", RecoveryTier::Social, "hash", guardians, 2, 0.0);

        // Only 1 share — below threshold of 2
        let result = state.initiate_recovery("alice", "rec-1", RecoveryTier::Social, "new_key", 1, 100.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_social_recovery_meets_threshold() {
        let mut state = SeedVaultState::new();
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 0.0 },
            Guardian { identity: "carol".into(), share_index: 2, added_at: 0.0 },
            Guardian { identity: "dave".into(), share_index: 3, added_at: 0.0 },
        ];
        state.configure_tier("alice", RecoveryTier::Social, "hash", guardians, 2, 0.0);

        // 2 shares — meets threshold
        let claim = state
            .initiate_recovery("alice", "rec-1", RecoveryTier::Social, "new_key", 2, 100.0)
            .unwrap();
        assert_eq!(claim.shares_submitted, 2);
    }

    #[test]
    fn test_contest_blocks_recovery() {
        let mut state = SeedVaultState::new();
        state.configure_tier("alice", RecoveryTier::Paper, "seed_hash", Vec::new(), 0, 0.0);
        state.initiate_recovery("alice", "rec-1", RecoveryTier::Paper, "new_key", 0, 100.0);

        assert!(state.contest("alice", "rec-1"));

        // Contested claim cannot execute even after cooldown
        let result = state.execute_recovery("alice", "rec-1", 100.0 + RECOVERY_COOLDOWN_SECS + 1.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_revoke_tier() {
        let mut state = SeedVaultState::new();
        state.configure_tier("alice", RecoveryTier::Paper, "hash", Vec::new(), 0, 0.0);
        assert!(state.revoke_tier("alice", RecoveryTier::Paper));
        assert!(!state.is_tier_active("alice", RecoveryTier::Paper));

        // Cannot recover via revoked tier
        let result = state.initiate_recovery("alice", "rec-1", RecoveryTier::Paper, "new", 0, 100.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_all_three_tiers() {
        let mut state = SeedVaultState::new();
        state.configure_tier("alice", RecoveryTier::Paper, "h1", Vec::new(), 0, 0.0);
        state.configure_tier("alice", RecoveryTier::HardwareKey, "h2", Vec::new(), 0, 0.0);
        let guardians = vec![
            Guardian { identity: "bob".into(), share_index: 1, added_at: 0.0 },
            Guardian { identity: "carol".into(), share_index: 2, added_at: 0.0 },
            Guardian { identity: "dave".into(), share_index: 3, added_at: 0.0 },
        ];
        state.configure_tier("alice", RecoveryTier::Social, "h3", guardians, 2, 0.0);
        assert_eq!(state.configured_tier_count("alice"), 3);
    }

    #[test]
    fn test_extract_configure() {
        let meta: HashMap<String, String> =
            configure_metadata(RecoveryTier::Paper, "seed_hash", 0)
                .into_iter()
                .collect();
        let op = extract_seed_vault_op(&meta).unwrap();
        match op {
            ParsedSeedVaultOp::Configure { tier, key_hash, .. } => {
                assert_eq!(tier, RecoveryTier::Paper);
                assert_eq!(key_hash, "seed_hash");
            }
            _ => panic!("expected Configure"),
        }
    }

    #[test]
    fn test_extract_recover() {
        let meta: HashMap<String, String> =
            recover_metadata(RecoveryTier::Social, "new_key_hash", 3)
                .into_iter()
                .collect();
        let op = extract_seed_vault_op(&meta).unwrap();
        match op {
            ParsedSeedVaultOp::Recover { tier, new_key_hash, shares_submitted } => {
                assert_eq!(tier, RecoveryTier::Social);
                assert_eq!(new_key_hash, "new_key_hash");
                assert_eq!(shares_submitted, 3);
            }
            _ => panic!("expected Recover"),
        }
    }

    #[test]
    fn test_tier_parse_roundtrip() {
        for tier in [RecoveryTier::Paper, RecoveryTier::HardwareKey, RecoveryTier::Social] {
            assert_eq!(RecoveryTier::parse(tier.as_str()), Some(tier));
        }
    }

    // ============================================================
    // fixture-free, pure helpers
    // ============================================================

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_seed_vault_constants_strict_pin_with_social_default_and_threshold_invariants() {
        // Strict-pin each constant.
        assert_eq!(DEFAULT_SOCIAL_M, 3);
        assert_eq!(DEFAULT_SOCIAL_N, 5);
        assert_eq!(MAX_GUARDIANS, 9);
        assert_eq!(MIN_GUARDIANS, 3);
        assert_eq!(MIN_THRESHOLD, 2);
        assert_eq!(RECOVERY_COOLDOWN_SECS, 86_400.0);
        assert_eq!(SEED_VAULT_OP_KEY, "seed_vault_op");

        // Cross-relations — the social-recovery defaults MUST satisfy:
        //   (a) threshold ≤ total: 3 ≤ 5 (M ≤ N).
        assert!(DEFAULT_SOCIAL_M <= DEFAULT_SOCIAL_N);
        //   (b) default M ≥ MIN_THRESHOLD: 3 ≥ 2.
        assert!(DEFAULT_SOCIAL_M >= MIN_THRESHOLD);
        //   (c) default N within [MIN_GUARDIANS, MAX_GUARDIANS]: 3 ≤ 5 ≤ 9.
        assert!(DEFAULT_SOCIAL_N >= MIN_GUARDIANS);
        assert!(DEFAULT_SOCIAL_N <= MAX_GUARDIANS);
        //   (d) MIN_THRESHOLD < MIN_GUARDIANS: you can have 2-of-3 but not 2-of-2.
        assert!(MIN_THRESHOLD < MIN_GUARDIANS);
        //   (e) MAX_GUARDIANS > MIN_GUARDIANS: real range exists.
        assert!(MAX_GUARDIANS > MIN_GUARDIANS);

        // RECOVERY_COOLDOWN_SECS == 24h exactly.
        assert_eq!(RECOVERY_COOLDOWN_SECS, 24.0 * 60.0 * 60.0);
        assert!(RECOVERY_COOLDOWN_SECS.is_finite());
        assert!(RECOVERY_COOLDOWN_SECS > 0.0);
        assert_eq!(RECOVERY_COOLDOWN_SECS.fract(), 0.0);

        // SEED_VAULT_OP_KEY ASCII snake_case + cross-module disjointness.
        assert!(SEED_VAULT_OP_KEY.is_ascii());
        assert!(SEED_VAULT_OP_KEY
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'));
        assert!(!SEED_VAULT_OP_KEY.starts_with('_'));
        assert!(!SEED_VAULT_OP_KEY.ends_with('_'));
        // Must not collide with other metadata-key constants.
        for other in &[
            "vrf_registration",
            "delegation",
            "beat_op",
            "tier",
            "key_hash",
            "threshold",
        ] {
            assert_ne!(SEED_VAULT_OP_KEY, *other);
        }
    }

    #[test]
    fn batch_b_recovery_tier_three_variant_as_str_parse_roundtrip_and_ascii_snake_case_pin() {
        // 3-variant pairwise distinctness via PartialEq + Copy.
        let p = RecoveryTier::Paper;
        let h = RecoveryTier::HardwareKey;
        let s = RecoveryTier::Social;
        assert_ne!(p, h);
        assert_ne!(p, s);
        assert_ne!(h, s);
        let _copy = [p, h, s, p, h, s]; // Copy semantics

        // as_str byte-exact pin.
        assert_eq!(RecoveryTier::Paper.as_str(), "paper");
        assert_eq!(RecoveryTier::HardwareKey.as_str(), "hardware_key");
        assert_eq!(RecoveryTier::Social.as_str(), "social");

        // All as_str values are ASCII lowercase snake_case.
        for tier in [p, h, s] {
            let s = tier.as_str();
            assert!(s.is_ascii());
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
            assert!(!s.starts_with('_'));
            assert!(!s.ends_with('_'));
            assert!(!s.is_empty());
        }
        // 3 strings pairwise distinct.
        assert_ne!(p.as_str(), h.as_str());
        assert_ne!(p.as_str(), s.as_str());
        assert_ne!(h.as_str(), s.as_str());

        // parse() roundtrip exhaustive.
        for tier in [p, h, s] {
            assert_eq!(RecoveryTier::parse(tier.as_str()), Some(tier));
        }

        // parse() rejects unknowns (case-sensitive, no aliasing).
        assert_eq!(RecoveryTier::parse(""), None);
        assert_eq!(RecoveryTier::parse("Paper"), None, "case-sensitive");
        assert_eq!(RecoveryTier::parse("hardware"), None);
        assert_eq!(RecoveryTier::parse("hw_key"), None);
        assert_eq!(RecoveryTier::parse("Social"), None);
        assert_eq!(RecoveryTier::parse("unknown"), None);
        assert_eq!(RecoveryTier::parse("paper_key"), None);
    }

    #[test]
    fn batch_b_tier_status_three_variant_pairwise_distinct_with_copy_eq_serde_roundtrip() {
        // 3 variants pairwise distinct.
        let a = TierStatus::Active;
        let u = TierStatus::Unconfigured;
        let r = TierStatus::Revoked;
        assert_ne!(a, u);
        assert_ne!(a, r);
        assert_ne!(u, r);

        // Copy semantics.
        let _copy = [a, u, r, a];
        assert_eq!(a, TierStatus::Active);

        // Serde roundtrip for each variant.
        for status in [a, u, r] {
            let json = serde_json::to_string(&status).expect("serialize");
            let back: TierStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, back, "roundtrip preserves variant");
        }

        // Serde representations pairwise distinct (string-tag enum convention).
        let ja = serde_json::to_string(&a).unwrap();
        let ju = serde_json::to_string(&u).unwrap();
        let jr = serde_json::to_string(&r).unwrap();
        assert_ne!(ja, ju);
        assert_ne!(ja, jr);
        assert_ne!(ju, jr);
    }

    #[test]
    fn batch_b_configure_and_recover_metadata_builder_shape_and_key_order_pin() {
        // configure_metadata: 4 entries, exact key+value pin.
        let meta = configure_metadata(RecoveryTier::HardwareKey, "hex_hash_abc", 0);
        assert_eq!(meta.len(), 4, "configure builds exactly 4 metadata entries");
        // First entry is always SEED_VAULT_OP_KEY -> "configure".
        assert_eq!(meta[0].0, SEED_VAULT_OP_KEY);
        assert_eq!(meta[0].1, "configure");
        // Second: tier as_str.
        assert_eq!(meta[1].0, "tier");
        assert_eq!(meta[1].1, "hardware_key");
        // Third: key_hash.
        assert_eq!(meta[2].0, "key_hash");
        assert_eq!(meta[2].1, "hex_hash_abc");
        // Fourth: threshold (numeric → Display).
        assert_eq!(meta[3].0, "threshold");
        assert_eq!(meta[3].1, "0");

        // Threshold non-zero is propagated via Display.
        let meta = configure_metadata(RecoveryTier::Social, "h", 3);
        assert_eq!(meta[3].1, "3");

        // recover_metadata: 4 entries, exact key+value pin.
        let meta = recover_metadata(RecoveryTier::Social, "new_hex", 5);
        assert_eq!(meta.len(), 4);
        assert_eq!(meta[0].0, SEED_VAULT_OP_KEY);
        assert_eq!(meta[0].1, "recover");
        assert_eq!(meta[1].0, "tier");
        assert_eq!(meta[1].1, "social");
        assert_eq!(meta[2].0, "new_key_hash");
        assert_eq!(meta[2].1, "new_hex");
        assert_eq!(meta[3].0, "shares_submitted");
        assert_eq!(meta[3].1, "5");

        // configure and recover op-strings are disjoint (cannot mis-parse).
        let cfg_meta = configure_metadata(RecoveryTier::Paper, "x", 0);
        let rec_meta = recover_metadata(RecoveryTier::Paper, "x", 0);
        assert_ne!(cfg_meta[0].1, rec_meta[0].1, "configure != recover");
        // And both share the same op-key (SEED_VAULT_OP_KEY).
        assert_eq!(cfg_meta[0].0, rec_meta[0].0);
    }

    #[test]
    fn batch_b_extract_seed_vault_op_five_op_dispatch_and_negative_paths_fixture_free() {
        use std::collections::HashMap;

        // (a) Missing SEED_VAULT_OP_KEY → None.
        let m = HashMap::new();
        assert!(extract_seed_vault_op(&m).is_none());

        // (b) Unknown op string → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "unknown_op".into());
        assert!(extract_seed_vault_op(&m).is_none());

        // (c) "configure" with missing tier → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "configure".into());
        m.insert("key_hash".into(), "h".into());
        assert!(extract_seed_vault_op(&m).is_none());

        // (d) "configure" with invalid tier string → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "configure".into());
        m.insert("tier".into(), "not_a_tier".into());
        m.insert("key_hash".into(), "h".into());
        assert!(extract_seed_vault_op(&m).is_none());

        // (e) "configure" with missing key_hash → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "configure".into());
        m.insert("tier".into(), "paper".into());
        assert!(extract_seed_vault_op(&m).is_none());

        // Positive: each of 5 op variants dispatches correctly fixture-free.

        // configure
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "configure".into());
        m.insert("tier".into(), "paper".into());
        m.insert("key_hash".into(), "khash".into());
        m.insert("threshold".into(), "2".into());
        match extract_seed_vault_op(&m).expect("configure") {
            ParsedSeedVaultOp::Configure { tier, key_hash, threshold, .. } => {
                assert_eq!(tier, RecoveryTier::Paper);
                assert_eq!(key_hash, "khash");
                assert_eq!(threshold, 2);
            }
            _ => panic!("expected Configure"),
        }

        // recover
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "recover".into());
        m.insert("tier".into(), "social".into());
        m.insert("new_key_hash".into(), "newkey".into());
        m.insert("shares_submitted".into(), "3".into());
        match extract_seed_vault_op(&m).expect("recover") {
            ParsedSeedVaultOp::Recover { tier, new_key_hash, shares_submitted } => {
                assert_eq!(tier, RecoveryTier::Social);
                assert_eq!(new_key_hash, "newkey");
                assert_eq!(shares_submitted, 3);
            }
            _ => panic!("expected Recover"),
        }

        // contest
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "contest".into());
        m.insert("claim_record_id".into(), "claim-1".into());
        match extract_seed_vault_op(&m).expect("contest") {
            ParsedSeedVaultOp::Contest { claim_record_id } => {
                assert_eq!(claim_record_id, "claim-1");
            }
            _ => panic!("expected Contest"),
        }

        // execute
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "execute".into());
        m.insert("claim_record_id".into(), "claim-2".into());
        match extract_seed_vault_op(&m).expect("execute") {
            ParsedSeedVaultOp::Execute { claim_record_id } => {
                assert_eq!(claim_record_id, "claim-2");
            }
            _ => panic!("expected Execute"),
        }

        // revoke
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "revoke".into());
        m.insert("tier".into(), "hardware_key".into());
        match extract_seed_vault_op(&m).expect("revoke") {
            ParsedSeedVaultOp::Revoke { tier } => {
                assert_eq!(tier, RecoveryTier::HardwareKey);
            }
            _ => panic!("expected Revoke"),
        }

        // Missing claim_record_id for contest/execute → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "contest".into());
        assert!(extract_seed_vault_op(&m).is_none());
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "execute".into());
        assert!(extract_seed_vault_op(&m).is_none());

        // Missing tier for revoke → None.
        let mut m = HashMap::new();
        m.insert(SEED_VAULT_OP_KEY.into(), "revoke".into());
        assert!(extract_seed_vault_op(&m).is_none());
    }
}
