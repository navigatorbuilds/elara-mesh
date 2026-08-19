//! Hard Protocol Limits — non-governable enforcement layer (economics §13.15).
//!
//! These constants represent absolute invariants of the Elara Protocol.
//! Governance proposals CANNOT modify these values. They are enforced at
//! compile time (as constants) and validated at runtime before any
//! governance parameter change is applied.
//!
//! Rationale: Without hard limits, a compromised governance process could
//! destroy the economic guarantees of the network. These limits exist to
//! bound the damage surface even in the worst case.

//!
//! Spec references:
//!   @spec economics §13

use crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Supply & Economic Invariants ──────────────────────────────────────────

/// Maximum total beat supply: 10 billion beat (immutable).
pub const MAX_SUPPLY: u64 = 10_000_000_000 * BASE_UNITS_PER_BEAT;

/// Minimum free tier records per identity per day.
/// Governance can increase this but NEVER decrease below 5.
pub const MIN_FREE_TIER_PER_DAY: u64 = 5;

/// Maximum witness fee: 10 beat.
/// Governance can decrease but NEVER exceed this.
pub const MAX_WITNESS_FEE: u64 = 10 * BASE_UNITS_PER_BEAT;

/// Maximum slash percentage: 50%.
/// No fisherman challenge can slash more than half a stake.
pub const MAX_SLASH_FRACTION: f64 = 0.50;

// ─── Staking & Governance Invariants ───────────────────────────────────────

/// Maximum unstake cooldown: 30 days in seconds.
/// Governance can decrease but NEVER exceed this.
pub const MAX_UNSTAKE_COOLDOWN_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// Maximum governance voting power cap formula: 1/√N.
/// This prevents plutocratic domination. Non-negotiable.
pub const GOVERNANCE_CAP_FORMULA: &str = "1/sqrt(N)";

/// Minimum governance supermajority threshold: 60%.
/// Governance can increase this but NEVER decrease below 60%.
pub const MIN_SUPERMAJORITY_THRESHOLD: f64 = 0.60;

/// Maximum governance supermajority threshold: 90%.
/// Prevents governance deadlocks.
pub const MAX_SUPERMAJORITY_THRESHOLD: f64 = 0.90;

/// Minimum governance participation fraction: 5%.
/// Governance can increase this but NEVER decrease below 5%.
pub const MIN_PARTICIPATION_FRACTION_FLOOR: f64 = 0.05;

// ─── Cryptographic Invariants ──────────────────────────────────────────────

/// Identity algorithm: SHA3-256 ONLY.
/// This is the foundation of the identity layer. Cannot be changed.
pub const IDENTITY_ALGORITHM: &str = "SHA3-256";

/// Allowed signature algorithms.
/// Only post-quantum algorithms are permitted.
pub const ALLOWED_SIG_ALGORITHMS: &[&str] = &["Dilithium3", "SPHINCS+"];

// ─── Rate Limiting Invariants ──────────────────────────────────────────────

/// Maximum Proof-of-Work difficulty (D_max).
/// Prevents PoW from becoming a barrier to entry.
pub const MAX_POW_DIFFICULTY: u32 = 24;

/// Minimum velocity window: 1 hour in seconds.
/// Governance cannot shrink the velocity tracking window below this.
pub const MIN_VELOCITY_WINDOW_SECS: f64 = 3600.0;

/// Maximum propagation rate limit: 10,000 records/hour per identity.
/// Governance can set it lower but NEVER higher.
pub const MAX_PROPAGATION_RATE_PER_HOUR: u64 = 10_000;

// ─── Retention & Storage Invariants ────────────────────────────────────────

/// Minimum record retention: 7 days in seconds.
/// Records cannot be GC'd faster than this.
pub const MIN_RECORD_RETENTION_SECS: f64 = 7.0 * 24.0 * 3600.0;

/// Maximum dormancy threshold: 365 days in seconds.
/// Accounts are never considered dormant before this period.
pub const MAX_DORMANCY_THRESHOLD_SECS: f64 = 365.0 * 24.0 * 3600.0;

// ─── Conservation Invariants ───────────────────────────────────────────────

/// Conservation pool minimum: 10% of total supply.
/// The conservation pool can never be drained below this.
pub const CONSERVATION_POOL_MIN_FRACTION: f64 = 0.10;

/// Maximum epoch seal interval: 1 hour in seconds.
/// Epochs cannot be longer than this (data integrity guarantee).
pub const MAX_EPOCH_SEAL_INTERVAL_SECS: f64 = 3600.0;

/// Minimum witness reward: 0 (free witnessing is allowed).
/// Cannot go negative (that would penalize witnesses).
pub const MIN_WITNESS_REWARD_MICROS: u64 = 0;

/// Maximum witness reward: 100 beat per attestation.
pub const MAX_WITNESS_REWARD_MICROS: u64 = 100 * BASE_UNITS_PER_BEAT;

// ─── Validation ────────────────────────────────────────────────────────────

/// A hard-limit violation reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitViolation {
    pub param_name: String,
    pub violation: String,
}

impl std::fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hard limit violation on '{}': {}", self.param_name, self.violation)
    }
}

/// Validate that a proposed governance parameter change does not violate
/// any hard protocol limits.
///
/// Returns `Ok(())` if the change is within bounds, or `Err(LimitViolation)`.
pub fn validate_param_change(name: &str, value: &str) -> Result<(), LimitViolation> {
    match name {
        "propagation_rate_limit_per_hour" => {
            let v: u64 = value.parse().map_err(|_| LimitViolation {
                param_name: name.into(),
                violation: format!("invalid u64: {value}"),
            })?;
            if v > MAX_PROPAGATION_RATE_PER_HOUR {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: format!(
                        "value {v} exceeds hard limit of {MAX_PROPAGATION_RATE_PER_HOUR}/hour"
                    ),
                });
            }
        }
        "epoch_seal_interval_secs" => {
            let v: f64 = value.parse().map_err(|_| LimitViolation {
                param_name: name.into(),
                violation: format!("invalid f64: {value}"),
            })?;
            if v > MAX_EPOCH_SEAL_INTERVAL_SECS {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: format!(
                        "value {v}s exceeds hard limit of {MAX_EPOCH_SEAL_INTERVAL_SECS}s"
                    ),
                });
            }
            if v <= 0.0 {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: "must be positive".into(),
                });
            }
        }
        "witness_reward_micros" => {
            let v: u64 = value.parse().map_err(|_| LimitViolation {
                param_name: name.into(),
                violation: format!("invalid u64: {value}"),
            })?;
            if v > MAX_WITNESS_REWARD_MICROS {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: format!(
                        "value {} exceeds hard limit of {} base units (10^9 = 1 beat)",
                        v, MAX_WITNESS_REWARD_MICROS
                    ),
                });
            }
        }
        "record_retention_secs" => {
            let v: f64 = value.parse().map_err(|_| LimitViolation {
                param_name: name.into(),
                violation: format!("invalid f64: {value}"),
            })?;
            // 0 means infinite (OK), but if set, must be >= minimum
            if v > 0.0 && v < MIN_RECORD_RETENTION_SECS {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: format!(
                        "retention {v}s below hard minimum of {MIN_RECORD_RETENTION_SECS}s (7 days)"
                    ),
                });
            }
        }
        "stake_throughput_ratio" => {
            let v: u64 = value.parse().map_err(|_| LimitViolation {
                param_name: name.into(),
                violation: format!("invalid u64: {value}"),
            })?;
            if v == 0 {
                return Err(LimitViolation {
                    param_name: name.into(),
                    violation: "stake throughput ratio cannot be zero".into(),
                });
            }
        }
        _ => {
            // Unknown parameter — governance module will reject it
        }
    }
    Ok(())
}

/// Validate a slash amount against the hard limit.
pub fn validate_slash_fraction(slash_amount: u64, total_stake: u64) -> Result<(), LimitViolation> {
    if total_stake == 0 {
        return Ok(());
    }
    let fraction = slash_amount as f64 / total_stake as f64;
    if fraction > MAX_SLASH_FRACTION {
        return Err(LimitViolation {
            param_name: "slash_fraction".into(),
            violation: format!(
                "slash {slash_amount} is {:.1}% of stake {total_stake}, exceeds max {:.0}%",
                fraction * 100.0,
                MAX_SLASH_FRACTION * 100.0
            ),
        });
    }
    Ok(())
}

/// Return all hard limit constants as a JSON-serializable map.
pub fn all_limits() -> serde_json::Value {
    serde_json::json!({
        "max_supply": MAX_SUPPLY,
        "min_free_tier_per_day": MIN_FREE_TIER_PER_DAY,
        "max_witness_fee": MAX_WITNESS_FEE,
        "max_slash_fraction": MAX_SLASH_FRACTION,
        "max_unstake_cooldown_secs": MAX_UNSTAKE_COOLDOWN_SECS,
        "governance_cap_formula": GOVERNANCE_CAP_FORMULA,
        "min_supermajority_threshold": MIN_SUPERMAJORITY_THRESHOLD,
        "max_supermajority_threshold": MAX_SUPERMAJORITY_THRESHOLD,
        "min_participation_fraction_floor": MIN_PARTICIPATION_FRACTION_FLOOR,
        "identity_algorithm": IDENTITY_ALGORITHM,
        "allowed_sig_algorithms": ALLOWED_SIG_ALGORITHMS,
        "max_pow_difficulty": MAX_POW_DIFFICULTY,
        "min_velocity_window_secs": MIN_VELOCITY_WINDOW_SECS,
        "max_propagation_rate_per_hour": MAX_PROPAGATION_RATE_PER_HOUR,
        "min_record_retention_secs": MIN_RECORD_RETENTION_SECS,
        "max_dormancy_threshold_secs": MAX_DORMANCY_THRESHOLD_SECS,
        "conservation_pool_min_fraction": CONSERVATION_POOL_MIN_FRACTION,
        "max_epoch_seal_interval_secs": MAX_EPOCH_SEAL_INTERVAL_SECS,
        "min_witness_reward_micros": MIN_WITNESS_REWARD_MICROS,
        "max_witness_reward_micros": MAX_WITNESS_REWARD_MICROS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_propagation_rate_within_limit() {
        assert!(validate_param_change("propagation_rate_limit_per_hour", "5000").is_ok());
        assert!(validate_param_change("propagation_rate_limit_per_hour", "10000").is_ok());
    }

    #[test]
    fn test_validate_propagation_rate_exceeds_limit() {
        let err = validate_param_change("propagation_rate_limit_per_hour", "10001").unwrap_err();
        assert!(err.violation.contains("exceeds hard limit"));
    }

    #[test]
    fn test_validate_epoch_seal_interval_within() {
        assert!(validate_param_change("epoch_seal_interval_secs", "300").is_ok());
        assert!(validate_param_change("epoch_seal_interval_secs", "3600").is_ok());
    }

    #[test]
    fn test_validate_epoch_seal_interval_exceeds() {
        let err = validate_param_change("epoch_seal_interval_secs", "7200").unwrap_err();
        assert!(err.violation.contains("exceeds hard limit"));
    }

    #[test]
    fn test_validate_epoch_seal_interval_zero() {
        let err = validate_param_change("epoch_seal_interval_secs", "0").unwrap_err();
        assert!(err.violation.contains("positive"));
    }

    #[test]
    fn test_validate_witness_reward_within() {
        assert!(validate_param_change("witness_reward_micros", "0").is_ok());
        let max = (100 * BASE_UNITS_PER_BEAT).to_string();
        assert!(validate_param_change("witness_reward_micros", &max).is_ok());
    }

    #[test]
    fn test_validate_witness_reward_exceeds() {
        let over = (101 * BASE_UNITS_PER_BEAT).to_string();
        let err = validate_param_change("witness_reward_micros", &over).unwrap_err();
        assert!(err.violation.contains("exceeds hard limit"));
    }

    #[test]
    fn test_validate_record_retention_infinite() {
        assert!(validate_param_change("record_retention_secs", "0").is_ok());
    }

    #[test]
    fn test_validate_record_retention_valid() {
        assert!(validate_param_change("record_retention_secs", "604800").is_ok()); // 7 days
        assert!(validate_param_change("record_retention_secs", "1000000").is_ok());
    }

    #[test]
    fn test_validate_record_retention_too_short() {
        let err = validate_param_change("record_retention_secs", "3600").unwrap_err(); // 1 hour
        assert!(err.violation.contains("below hard minimum"));
    }

    #[test]
    fn test_validate_stake_throughput_nonzero() {
        assert!(validate_param_change("stake_throughput_ratio", "100000").is_ok());
    }

    #[test]
    fn test_validate_stake_throughput_zero() {
        let err = validate_param_change("stake_throughput_ratio", "0").unwrap_err();
        assert!(err.violation.contains("cannot be zero"));
    }

    #[test]
    fn test_validate_unknown_param() {
        // Unknown params are not our responsibility — governance rejects them
        assert!(validate_param_change("nonexistent_param", "42").is_ok());
    }

    #[test]
    fn test_slash_fraction_within_limit() {
        assert!(validate_slash_fraction(500_000, 1_000_000).is_ok()); // 50%
        assert!(validate_slash_fraction(100_000, 1_000_000).is_ok()); // 10%
    }

    #[test]
    fn test_slash_fraction_exceeds_limit() {
        let err = validate_slash_fraction(500_001, 1_000_000).unwrap_err(); // >50%
        assert!(err.violation.contains("exceeds max"));
    }

    #[test]
    fn test_slash_fraction_zero_stake() {
        assert!(validate_slash_fraction(0, 0).is_ok());
    }

    #[test]
    fn test_all_limits_json() {
        let limits = all_limits();
        assert_eq!(limits["max_supply"], serde_json::json!(MAX_SUPPLY));
        assert_eq!(limits["identity_algorithm"], serde_json::json!("SHA3-256"));
        assert!(limits["allowed_sig_algorithms"].is_array());
    }

    #[test]
    fn test_max_supply_value() {
        assert_eq!(MAX_SUPPLY, 10_000_000_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(MAX_SUPPLY, crate::accounting::types::MAX_SUPPLY); // Must match types.rs
    }

    // ─── fixture-free tests ─────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_token_amount_constants_strict_pin_with_arithmetic_cross_checks() {
        // Supply-side amount constants — all pinned in base units units.
        // (MAX_SUPPLY already covered by test_max_supply_value; pin the rest.)

        // MAX_WITNESS_FEE = 10 beat = 10 × 1B micros = 10_000_000_000
        assert_eq!(MAX_WITNESS_FEE, 10 * BASE_UNITS_PER_BEAT);
        assert_eq!(MAX_WITNESS_FEE, 10_000_000_000_u64);

        // MIN/MAX witness reward: 0..=100 beat
        assert_eq!(MIN_WITNESS_REWARD_MICROS, 0);
        assert_eq!(MAX_WITNESS_REWARD_MICROS, 100 * BASE_UNITS_PER_BEAT);
        assert_eq!(MAX_WITNESS_REWARD_MICROS, 100_000_000_000_u64);
        assert!(MIN_WITNESS_REWARD_MICROS < MAX_WITNESS_REWARD_MICROS);

        // MAX_WITNESS_REWARD = 10 × MAX_WITNESS_FEE (reward up to 10× a fee)
        assert_eq!(MAX_WITNESS_REWARD_MICROS, 10 * MAX_WITNESS_FEE);

        // MIN_FREE_TIER_PER_DAY — UNITLESS record count (NOT micros)
        assert_eq!(MIN_FREE_TIER_PER_DAY, 5);
        assert!(MIN_FREE_TIER_PER_DAY < 1_000, "free-tier floor is a record count, not a micro amount");

        // MAX_PROPAGATION_RATE_PER_HOUR — record count (NOT micros)
        assert_eq!(MAX_PROPAGATION_RATE_PER_HOUR, 10_000);

        // MAX_POW_DIFFICULTY = 24 — bits-of-difficulty (24 ≈ 16M attempts target)
        assert_eq!(MAX_POW_DIFFICULTY, 24);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_time_window_constants_strict_pin_with_day_multiples() {
        const DAY: f64 = 24.0 * 3600.0;

        // 30 days
        assert_eq!(MAX_UNSTAKE_COOLDOWN_SECS, 30.0 * DAY);
        assert_eq!(MAX_UNSTAKE_COOLDOWN_SECS, 2_592_000.0);

        // 1 hour (twice — different load-bearing minima/maxima)
        assert_eq!(MIN_VELOCITY_WINDOW_SECS, 3600.0);
        assert_eq!(MAX_EPOCH_SEAL_INTERVAL_SECS, 3600.0);
        // Both pinned to exactly one hour
        assert_eq!(MIN_VELOCITY_WINDOW_SECS, MAX_EPOCH_SEAL_INTERVAL_SECS);

        // 7 days
        assert_eq!(MIN_RECORD_RETENTION_SECS, 7.0 * DAY);
        assert_eq!(MIN_RECORD_RETENTION_SECS, 604_800.0);

        // 365 days
        assert_eq!(MAX_DORMANCY_THRESHOLD_SECS, 365.0 * DAY);
        assert_eq!(MAX_DORMANCY_THRESHOLD_SECS, 31_536_000.0);

        // Structural ordering: the 1-hour window is the smallest, then 7d, 30d, 365d
        assert!(MIN_VELOCITY_WINDOW_SECS < MIN_RECORD_RETENTION_SECS);
        assert!(MIN_RECORD_RETENTION_SECS < MAX_UNSTAKE_COOLDOWN_SECS);
        assert!(MAX_UNSTAKE_COOLDOWN_SECS < MAX_DORMANCY_THRESHOLD_SECS);

        // Cross-relation: MAX_DORMANCY ≈ 365/30 × MAX_UNSTAKE (12.166...)
        let ratio = MAX_DORMANCY_THRESHOLD_SECS / MAX_UNSTAKE_COOLDOWN_SECS;
        assert!((ratio - 365.0 / 30.0).abs() < 1e-9);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_fraction_threshold_constants_strict_pin_with_min_less_max_ordering() {
        // Slash ceiling — 50%
        assert_eq!(MAX_SLASH_FRACTION, 0.50);

        // Supermajority band — 60..=90%
        assert_eq!(MIN_SUPERMAJORITY_THRESHOLD, 0.60);
        assert_eq!(MAX_SUPERMAJORITY_THRESHOLD, 0.90);
        assert!(
            MIN_SUPERMAJORITY_THRESHOLD < MAX_SUPERMAJORITY_THRESHOLD,
            "min supermajority must be strictly below max"
        );
        // Band span = 0.30
        assert!((MAX_SUPERMAJORITY_THRESHOLD - MIN_SUPERMAJORITY_THRESHOLD - 0.30).abs() < 1e-9);

        // The governance-module SUPERMAJORITY_THRESHOLD (0.67) must lie INSIDE
        // this hard-limit band — otherwise a runtime constant violates the
        // protocol invariant.
        let gov = crate::accounting::governance::SUPERMAJORITY_THRESHOLD;
        assert!(gov >= MIN_SUPERMAJORITY_THRESHOLD, "{gov} below MIN");
        assert!(gov <= MAX_SUPERMAJORITY_THRESHOLD, "{gov} above MAX");

        // Participation floor — 5%
        assert_eq!(MIN_PARTICIPATION_FRACTION_FLOOR, 0.05);
        // The governance MIN_PARTICIPATION (0.25) must be at/above this floor
        assert!(
            crate::accounting::governance::MIN_PARTICIPATION_FRACTION
                >= MIN_PARTICIPATION_FRACTION_FLOOR
        );

        // Conservation pool floor — 10% of total supply
        assert_eq!(CONSERVATION_POOL_MIN_FRACTION, 0.10);

        // All fractions are in (0,1] open lower bound, inclusive upper
        for (name, val) in [
            ("MAX_SLASH_FRACTION", MAX_SLASH_FRACTION),
            ("MIN_SUPERMAJORITY_THRESHOLD", MIN_SUPERMAJORITY_THRESHOLD),
            ("MAX_SUPERMAJORITY_THRESHOLD", MAX_SUPERMAJORITY_THRESHOLD),
            ("MIN_PARTICIPATION_FRACTION_FLOOR", MIN_PARTICIPATION_FRACTION_FLOOR),
            ("CONSERVATION_POOL_MIN_FRACTION", CONSERVATION_POOL_MIN_FRACTION),
        ] {
            assert!(val > 0.0 && val <= 1.0, "{name}={val} not in (0,1]");
        }
    }

    #[test]
    fn batch_b_string_and_array_constants_strict_pin_with_post_quantum_invariants() {
        // Identity algorithm — pinned to SHA3-256
        assert_eq!(IDENTITY_ALGORITHM, "SHA3-256");

        // Governance cap formula — string literal that operators may display
        assert_eq!(GOVERNANCE_CAP_FORMULA, "1/sqrt(N)");

        // ALLOWED_SIG_ALGORITHMS — exactly 2 post-quantum schemes
        assert_eq!(ALLOWED_SIG_ALGORITHMS.len(), 2);
        assert_eq!(ALLOWED_SIG_ALGORITHMS[0], "Dilithium3");
        assert_eq!(ALLOWED_SIG_ALGORITHMS[1], "SPHINCS+");

        // Post-quantum invariant: classical schemes (Ed25519, ECDSA, RSA)
        // MUST NOT appear in the allow-list — if they did, a Shor-able key
        // would be accepted for genesis-class operations.
        for forbidden in ["Ed25519", "ECDSA", "RSA", "secp256k1", "BLS12-381"] {
            assert!(
                !ALLOWED_SIG_ALGORITHMS.contains(&forbidden),
                "{forbidden} must NOT be in ALLOWED_SIG_ALGORITHMS (post-quantum invariant)"
            );
        }

        // Both allowed schemes are NIST post-quantum signature winners.
        // Verify they're distinct (no duplicate entries).
        assert_ne!(ALLOWED_SIG_ALGORITHMS[0], ALLOWED_SIG_ALGORITHMS[1]);
    }

    #[test]
    fn batch_b_limit_violation_struct_equality_clone_display_with_all_limits_completeness() {
        // LimitViolation has Debug+Clone+PartialEq+Eq derives — exercise all.
        let lv = LimitViolation {
            param_name: "foo".to_string(),
            violation: "bar".to_string(),
        };
        let lv_clone = lv.clone();
        assert_eq!(lv, lv_clone, "Clone must preserve equality");

        // Display format: "hard limit violation on 'NAME': VIOLATION"
        let s = format!("{lv}");
        assert!(s.contains("hard limit violation"));
        assert!(s.contains("'foo'"));
        assert!(s.contains("bar"));

        // Differing param_name or violation string breaks equality
        let lv_other_param = LimitViolation {
            param_name: "foo2".to_string(),
            violation: "bar".to_string(),
        };
        assert_ne!(lv, lv_other_param);
        let lv_other_violation = LimitViolation {
            param_name: "foo".to_string(),
            violation: "bar2".to_string(),
        };
        assert_ne!(lv, lv_other_violation);

        // all_limits() JSON object must surface every constant by snake_case key.
        // test_all_limits_json only covers max_supply + identity_algorithm + the
        // allowed_sig_algorithms type — this pins the remaining keys.
        let limits = all_limits();
        for key in [
            "max_supply", "identity_algorithm", "allowed_sig_algorithms",
            "max_witness_fee", "max_slash_fraction", "max_unstake_cooldown_secs",
            "min_supermajority_threshold", "max_supermajority_threshold",
            "min_participation_fraction_floor", "max_pow_difficulty",
            "min_velocity_window_secs", "max_propagation_rate_per_hour",
            "min_record_retention_secs", "max_dormancy_threshold_secs",
            "conservation_pool_min_fraction", "max_epoch_seal_interval_secs",
            "min_witness_reward_micros", "max_witness_reward_micros",
            "governance_cap_formula",
        ] {
            assert!(
                limits.get(key).is_some(),
                "all_limits() JSON must contain key {key}"
            );
        }
    }
}
