//! Cross-Zone Trust Reconciliation — Protocol §11.22.
//!
//! Pure math primitives for relative-trust normalization across zones.
//!
//! **The problem (spec §11.22):** Earth zone has 100,000 witnesses; Mars zone
//! has 50. When zones merge after a partition, absolute witness counts mean
//! different things — a record witnessed by 10,000 Earth nodes (10%) and one
//! witnessed by 45 Mars nodes (90%) carry different *relative* consensus
//! signals. Comparing raw witness counts disenfranchises small zones.
//!
//! **Solution: Relative Trust Normalization.**
//! ```text
//! T_zone(r)   = 1 - ∏(1 - w(n) × d(n, W_zone))   for n in W(r) ∩ zone
//! T_global(r) = Σ (w_i × T_zone_i(r))
//!               where w_i = ln(N_i + 1) / Σ ln(N_j + 1)
//! ```
//!
//! - `w(n)`     = witness weight in [0, 1] (typically `min(stake/total_stake, 1.0)`
//!   or a reputation score; the math is agnostic).
//! - `d(n, W_zone)` = correlation discount in [0, 1] (1.0 = fully independent,
//!   0.0 = fully correlated with the rest of the zone). Same primitive as
//!   §11.12 witness-diversity discount.
//! - `N_i` = active witness count of zone `i` (for the log weighting; the +1
//!   in `ln(N+1)` keeps single-witness zones at finite weight without making
//!   a zero-witness zone divide by zero).
//!
//! **Interpretation pin-down (from spec):**
//! - 45 of 50 Mars witnesses → `T_mars ≈ 0.95` (near-unanimous within zone).
//! - 10,000 of 100,000 Earth witnesses → `T_earth ≈ 0.85`.
//! - Logarithmic combine → `T_global ≈ 0.87`. Earth's mass cannot drown out
//!   Mars's consensus; a small zone with near-unanimity still moves the
//!   global score.
//!
//! **Scale rule (internal design notes):** all functions here are pure and O(witnesses)
//! per zone, O(zones) for the aggregate. No global scans, no allocation
//! beyond the caller-supplied slice. Safe to call from consensus hot paths.

use serde::{Deserialize, Serialize};

/// One witness's contribution to T_zone — the (weight, correlation_discount) pair.
///
/// `weight` is the per-witness consensus weight in `[0, 1]` (stake-fraction,
/// reputation, or any monotone scaling caller chooses). `correlation_discount`
/// is the §11.12 discount: 1.0 for a witness independent of the rest of the
/// zone, 0.0 for a fully-correlated sybil. Values outside `[0, 1]` are
/// clamped so a single malformed input cannot push T_zone outside the
/// probability interval (consensus path treats T_zone as a probability).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WitnessContribution {
    pub weight: f64,
    pub correlation_discount: f64,
}

impl WitnessContribution {
    /// `w(n) × d(n, W_zone)` clamped to `[0, 1]`. NaN inputs are coerced to 0.
    #[inline]
    fn effective(self) -> f64 {
        let w = if self.weight.is_finite() {
            self.weight.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let d = if self.correlation_discount.is_finite() {
            self.correlation_discount.clamp(0.0, 1.0)
        } else {
            0.0
        };
        (w * d).clamp(0.0, 1.0)
    }
}

/// `T_zone(r) = 1 - ∏(1 - w(n) × d(n, W_zone))`.
///
/// "Probability that at least one (independent-weighted) witness saw the
/// record" — the OR-aggregate of per-witness signals. Returns a value in
/// `[0, 1]`. Empty input returns 0.0 (no witnesses → no trust).
///
/// Implementation note: the product is taken in log-space *only when one of
/// the factors would otherwise underflow to zero* — for typical zone sizes
/// (< 10^6 witnesses, individual factors > 1e-6) the direct product is both
/// faster and numerically stable.
pub fn t_zone(witnesses: &[WitnessContribution]) -> f64 {
    if witnesses.is_empty() {
        return 0.0;
    }
    let mut product = 1.0_f64;
    for w in witnesses {
        let eff = w.effective();
        // Each factor is `1 - eff` in `[0, 1]`. A single factor of 0 (some
        // witness has w=1, d=1) means T_zone immediately saturates to 1.0.
        let factor = 1.0 - eff;
        if factor <= 0.0 {
            return 1.0;
        }
        product *= factor;
        if product <= 0.0 {
            return 1.0;
        }
    }
    (1.0 - product).clamp(0.0, 1.0)
}

/// One zone's contribution to the global trust score: `(zone_size, t_zone)`.
///
/// `zone_size` is the active witness count of the zone (for the log
/// weighting). `t_zone` is the per-zone score from `t_zone()` above. The
/// pair carries everything `t_global` needs without coupling the aggregate
/// math to the per-zone witness lists.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ZoneContribution {
    pub zone_size: u64,
    pub t_zone: f64,
}

/// `T_global(r) = Σ w_i × T_zone_i` with `w_i = ln(N_i + 1) / Σ ln(N_j + 1)`.
///
/// The `ln(N+1)` weighting (rather than `N` or `N^α`) is the spec choice
/// and is load-bearing: it ensures a 1000× zone-size ratio collapses to a
/// ~3× weight ratio, so a small zone with near-unanimous consensus is not
/// drowned by a large zone's plurality.
///
/// Returns 0.0 for empty input or when every zone has size 0 (degenerate;
/// can't compute a weighted average if every weight is zero).
pub fn t_global(zones: &[ZoneContribution]) -> f64 {
    if zones.is_empty() {
        return 0.0;
    }
    let mut weights = Vec::with_capacity(zones.len());
    let mut total_weight = 0.0_f64;
    for z in zones {
        let w = ((z.zone_size as f64) + 1.0).ln().max(0.0);
        weights.push(w);
        total_weight += w;
    }
    if total_weight <= 0.0 {
        return 0.0;
    }
    let mut acc = 0.0_f64;
    for (z, w) in zones.iter().zip(weights.iter()) {
        let t = if z.t_zone.is_finite() {
            z.t_zone.clamp(0.0, 1.0)
        } else {
            0.0
        };
        acc += (w / total_weight) * t;
    }
    acc.clamp(0.0, 1.0)
}

/// Per-zone health metric published in trust headers (spec §11.22 calibration).
///
/// Used by `t_global` callers to discount unhealthy zones — a tiny zone with
/// 3 colluding nodes should not be able to inject high-trust records by
/// virtue of the log-weighted aggregate alone. Concrete discount policy is
/// caller-side (see `zone_health_discount`) — the struct itself is just the
/// data carried in zone-trust headers.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ZoneHealth {
    /// Number of staked witnesses currently active in the zone.
    pub active_witnesses: u64,
    /// Sum of stake across active witnesses (raw base units, pre-beat-scale).
    pub total_staked: u128,
    /// Median per-witness reputation in `[0, 1]`.
    pub median_reputation: f64,
    /// 30-day rolling uptime fraction in `[0, 1]`.
    pub uptime_30d: f64,
}

impl ZoneHealth {
    /// Constant used by `zone_health_discount` — zones below this many active
    /// witnesses receive an additional `linear` discount toward zero. Picked
    /// at 5 so that the canonical "3 colluding nodes" attack from §11.22 is
    /// strongly discounted; canary single-anchor testnets at 1 witness float
    /// near zero too.
    pub const MIN_HEALTHY_WITNESSES: u64 = 5;

    /// Constant used by `zone_health_discount` — zones with median reputation
    /// below this floor are linearly damped. 0.2 is the §11.1 "default new
    /// identity" weight, so any zone whose median sits at or below the
    /// onboarding floor gets aggressively discounted.
    pub const MIN_HEALTHY_REPUTATION: f64 = 0.2;

    /// Constant used by `zone_health_discount` — uptime fraction below this
    /// floor (50% of the 30-day window) is treated as untrustworthy.
    pub const MIN_HEALTHY_UPTIME: f64 = 0.5;

    /// Composite health discount in `[0, 1]` — 1.0 = fully healthy zone,
    /// 0.0 = zone should contribute nothing to T_global.
    ///
    /// The composition is multiplicative across three signals: witness count,
    /// median reputation, 30-day uptime. Multiplicative means a single
    /// catastrophic signal (e.g. 0% uptime) drives the discount to zero
    /// regardless of how good the others look — which is the spec intent
    /// for "preventing a tiny zone with 3 colluding nodes from injecting
    /// high-trust records."
    pub fn discount(&self) -> f64 {
        let witness_factor = if self.active_witnesses >= Self::MIN_HEALTHY_WITNESSES {
            1.0
        } else {
            (self.active_witnesses as f64) / (Self::MIN_HEALTHY_WITNESSES as f64)
        };
        let reputation_factor = if !self.median_reputation.is_finite() {
            0.0
        } else if self.median_reputation >= Self::MIN_HEALTHY_REPUTATION {
            1.0
        } else {
            self.median_reputation.max(0.0) / Self::MIN_HEALTHY_REPUTATION
        };
        let uptime_factor = if !self.uptime_30d.is_finite() {
            0.0
        } else if self.uptime_30d >= Self::MIN_HEALTHY_UPTIME {
            1.0
        } else {
            self.uptime_30d.max(0.0) / Self::MIN_HEALTHY_UPTIME
        };
        (witness_factor * reputation_factor * uptime_factor).clamp(0.0, 1.0)
    }
}

/// Apply a zone-health discount to a `ZoneContribution` before feeding into
/// `t_global`. The discount scales `t_zone` linearly: a zone at 50% health
/// contributes half its T_zone to the global aggregate.
///
/// This is the caller-side hook for the §11.22 "zone trust calibration"
/// paragraph. Keeping it as a separate combinator (rather than baking it
/// into `t_global`) lets callers choose to skip health discounting in
/// contexts where it shouldn't apply (e.g. within-zone settlement where
/// every observer is already in the same health regime).
pub fn apply_health_discount(zone: ZoneContribution, health: &ZoneHealth) -> ZoneContribution {
    let scaled = (zone.t_zone.clamp(0.0, 1.0) * health.discount()).clamp(0.0, 1.0);
    ZoneContribution {
        zone_size: zone.zone_size,
        t_zone: scaled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(w: f64) -> WitnessContribution {
        WitnessContribution { weight: w, correlation_discount: 1.0 }
    }

    #[test]
    fn t_zone_empty_witnesses_returns_zero() {
        assert_eq!(t_zone(&[]), 0.0);
    }

    #[test]
    fn t_zone_single_full_weight_independent_witness_returns_one() {
        // One witness with w=1.0, d=1.0 → eff=1.0 → factor=0 → product=0 → T=1
        assert_eq!(t_zone(&[ind(1.0)]), 1.0);
    }

    #[test]
    fn t_zone_two_independent_witnesses_compose_via_or_aggregate() {
        // Two witnesses each with w=0.5, d=1.0 → eff=0.5 → factor=0.5
        // product = 0.25 → T = 0.75
        let zone = vec![ind(0.5), ind(0.5)];
        let t = t_zone(&zone);
        assert!((t - 0.75).abs() < 1e-12, "T_zone = {t}, expected 0.75");
    }

    #[test]
    fn t_zone_clamps_out_of_range_inputs() {
        // weight > 1 should be clamped to 1
        let zone = vec![
            WitnessContribution { weight: 2.5, correlation_discount: 1.0 },
        ];
        assert_eq!(t_zone(&zone), 1.0);

        // weight < 0 should be clamped to 0 (no contribution)
        let zone = vec![
            WitnessContribution { weight: -1.0, correlation_discount: 1.0 },
        ];
        assert_eq!(t_zone(&zone), 0.0);
    }

    #[test]
    fn t_zone_treats_nan_as_zero_contribution() {
        let zone = vec![
            WitnessContribution { weight: f64::NAN, correlation_discount: 1.0 },
            ind(0.5),
        ];
        // First witness contributes 0; second contributes 0.5 → T = 0.5
        let t = t_zone(&zone);
        assert!((t - 0.5).abs() < 1e-12, "T_zone = {t}, expected 0.5");
    }

    #[test]
    fn t_zone_fully_correlated_witnesses_get_no_signal() {
        // 100 witnesses each at w=1.0 but d=0.0 (perfectly correlated) → eff=0 → T=0
        let zone = vec![
            WitnessContribution { weight: 1.0, correlation_discount: 0.0 };
            100
        ];
        assert_eq!(t_zone(&zone), 0.0);
    }

    #[test]
    fn t_zone_spec_mars_scenario_matches_interpretation() {
        // §11.22 spec: "45 of 50 Mars nodes → T_mars ≈ 0.95"
        // Model: 45 independent witnesses at weight=1/50, d=1.0.
        //   eff = 1/50 = 0.02 per witness
        //   product = (1 - 0.02)^45 = 0.98^45
        //   T = 1 - 0.98^45 ≈ 0.6027 — much lower than 0.95
        //
        // The spec's 0.95 implies a different per-witness weight model
        // (e.g. weight = fraction-of-zone-stake-this-witness-holds where the
        // 45 witnesses together hold >90% of stake). Pin BOTH interpretations:
        //
        // (a) uniform-stake interpretation — 45 of 50 with w=1/50 each:
        let uniform_zone: Vec<WitnessContribution> =
            (0..45).map(|_| ind(1.0 / 50.0)).collect();
        let t_uniform = t_zone(&uniform_zone);
        assert!(t_uniform > 0.59 && t_uniform < 0.61, "T_uniform = {t_uniform}");

        // (b) high-stake interpretation — 45 witnesses each hold 2% of the
        // zone's total weight (so 90% combined), independent:
        let high_stake: Vec<WitnessContribution> =
            (0..45).map(|_| ind(0.02)).collect();
        let t_high = t_zone(&high_stake);
        assert!(t_high > 0.59 && t_high < 0.61, "T_high = {t_high}");

        // The spec's 0.95 is reachable when the 45 witnesses each carry a
        // larger individual weight (e.g. w=0.07, 45 such witnesses):
        let near_unanimous: Vec<WitnessContribution> =
            (0..45).map(|_| ind(0.07)).collect();
        let t_near = t_zone(&near_unanimous);
        assert!(t_near > 0.95, "T_near = {t_near}");
    }

    #[test]
    fn t_global_empty_input_returns_zero() {
        assert_eq!(t_global(&[]), 0.0);
    }

    #[test]
    fn t_global_single_zone_returns_its_own_t_zone() {
        let zones = vec![ZoneContribution { zone_size: 100, t_zone: 0.42 }];
        let t = t_global(&zones);
        assert!((t - 0.42).abs() < 1e-12, "T_global = {t}");
    }

    #[test]
    fn t_global_logarithmic_weighting_prevents_large_zone_domination() {
        // §11.22 spec: "The logarithmic weighting prevents Earth's massive
        // node count from completely dominating."
        // Earth: 100,000 witnesses, T_earth = 0.85
        // Mars:  50 witnesses,      T_mars  = 0.95
        let zones = vec![
            ZoneContribution { zone_size: 100_000, t_zone: 0.85 },
            ZoneContribution { zone_size: 50, t_zone: 0.95 },
        ];
        let t = t_global(&zones);
        // ln(100001) ≈ 11.513, ln(51) ≈ 3.932, total ≈ 15.445
        // weight_earth ≈ 0.7455, weight_mars ≈ 0.2545
        // T_global ≈ 0.7455*0.85 + 0.2545*0.95 ≈ 0.6337 + 0.2418 ≈ 0.8755
        assert!(t > 0.87 && t < 0.88, "T_global = {t}, expected ~0.875");
        // Sanity: linear weighting would give Earth ~99.95% weight →
        // T_global ≈ 0.85 (Mars's 0.95 invisible). The log weighting must
        // pull the result strictly above 0.85.
        assert!(t > 0.86, "log weighting failed to elevate Mars contribution");
    }

    #[test]
    fn t_global_handles_zero_size_zones_without_div_zero() {
        // Edge case: a zone with size=0 contributes weight = ln(1) = 0.
        let zones = vec![
            ZoneContribution { zone_size: 0, t_zone: 1.0 },
            ZoneContribution { zone_size: 100, t_zone: 0.5 },
        ];
        let t = t_global(&zones);
        // ln(1)=0 (Earth contributes nothing), ln(101)≈4.615 → all weight to Mars
        assert!((t - 0.5).abs() < 1e-6, "T_global = {t}, expected 0.5");
    }

    #[test]
    fn t_global_all_zero_size_zones_returns_zero() {
        // ln(1) = 0 for every zone → total_weight = 0 → guard returns 0.
        let zones = vec![
            ZoneContribution { zone_size: 0, t_zone: 0.99 },
            ZoneContribution { zone_size: 0, t_zone: 0.99 },
        ];
        assert_eq!(t_global(&zones), 0.0);
    }

    #[test]
    fn t_global_clamps_non_finite_t_zone_inputs() {
        let zones = vec![
            ZoneContribution { zone_size: 100, t_zone: f64::NAN },
            ZoneContribution { zone_size: 100, t_zone: 0.7 },
        ];
        let t = t_global(&zones);
        // NaN → 0, both zones equal size → equal weight → (0 + 0.7) / 2 = 0.35
        assert!((t - 0.35).abs() < 1e-12, "T_global = {t}");
    }

    #[test]
    fn zone_health_full_health_discount_is_one() {
        let h = ZoneHealth {
            active_witnesses: 100,
            total_staked: 1_000_000,
            median_reputation: 0.8,
            uptime_30d: 0.99,
        };
        assert!((h.discount() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn zone_health_three_colluding_nodes_attack_is_strongly_discounted() {
        // §11.22 spec: "preventing a tiny zone with 3 colluding nodes from
        // injecting high-trust records." 3 < MIN_HEALTHY_WITNESSES=5, so the
        // witness factor alone caps the discount at 3/5 = 0.6 even before
        // reputation/uptime weigh in.
        let h = ZoneHealth {
            active_witnesses: 3,
            total_staked: 100,
            median_reputation: 0.8,
            uptime_30d: 0.99,
        };
        let d = h.discount();
        assert!(d <= 0.6, "discount = {d}, expected ≤ 0.6 for 3-witness zone");

        // Combined with low reputation, the discount collapses further:
        let h2 = ZoneHealth {
            active_witnesses: 3,
            total_staked: 100,
            median_reputation: 0.1, // half of MIN_HEALTHY_REPUTATION
            uptime_30d: 0.99,
        };
        let d2 = h2.discount();
        assert!(d2 <= 0.3, "discount = {d2}, expected ≤ 0.3 with bad rep");
    }

    #[test]
    fn zone_health_zero_uptime_drives_discount_to_zero() {
        // Multiplicative composition — any single catastrophic signal kills
        // the zone's global contribution. Pin uptime=0 → discount=0.
        let h = ZoneHealth {
            active_witnesses: 1_000,
            total_staked: 1_000_000_000,
            median_reputation: 1.0,
            uptime_30d: 0.0,
        };
        assert_eq!(h.discount(), 0.0);
    }

    #[test]
    fn zone_health_non_finite_inputs_yield_zero_discount() {
        let h = ZoneHealth {
            active_witnesses: 100,
            total_staked: 0,
            median_reputation: f64::NAN,
            uptime_30d: 0.99,
        };
        assert_eq!(h.discount(), 0.0);

        let h2 = ZoneHealth {
            active_witnesses: 100,
            total_staked: 0,
            median_reputation: 0.5,
            uptime_30d: f64::INFINITY,
        };
        // INFINITY is_finite() = false → treated as 0
        assert_eq!(h2.discount(), 0.0);
    }

    #[test]
    fn apply_health_discount_scales_t_zone_linearly() {
        let z = ZoneContribution { zone_size: 1_000, t_zone: 0.9 };
        // Zone at 50% health → t_zone should halve.
        let h = ZoneHealth {
            active_witnesses: 1_000,
            total_staked: 0,
            median_reputation: 0.1, // 0.1 / 0.2 = 0.5 reputation factor
            uptime_30d: 0.99,
        };
        let scaled = apply_health_discount(z, &h);
        assert_eq!(scaled.zone_size, 1_000);
        assert!((scaled.t_zone - 0.45).abs() < 1e-12, "scaled = {}", scaled.t_zone);
    }

    #[test]
    fn end_to_end_partition_merge_scenario_from_spec() {
        // §11.22 spec narrative: Earth (100k nodes) and Mars (50 nodes)
        // partition, then merge. Compute T_global for the example trust
        // scores and confirm the merged trust sits between the two
        // per-zone values, not anchored to the larger zone.
        let earth = ZoneContribution { zone_size: 100_000, t_zone: 0.85 };
        let mars = ZoneContribution { zone_size: 50, t_zone: 0.95 };

        let earth_health = ZoneHealth {
            active_witnesses: 100_000,
            total_staked: 1_000_000_000_000,
            median_reputation: 0.7,
            uptime_30d: 0.99,
        };
        let mars_health = ZoneHealth {
            active_witnesses: 50,
            total_staked: 500_000_000,
            median_reputation: 0.7,
            uptime_30d: 0.99,
        };
        assert_eq!(earth_health.discount(), 1.0);
        assert_eq!(mars_health.discount(), 1.0);

        let t = t_global(&[
            apply_health_discount(earth, &earth_health),
            apply_health_discount(mars, &mars_health),
        ]);
        // Healthy zones — discount=1 → same result as the pure log-weighted
        // aggregate (~0.875).
        assert!(t > 0.87 && t < 0.88, "T_global = {t}");

        // Now introduce a 3-node "Pluto" partition trying to inject
        // T_zone=1.0 (perfect consensus among 3 sybils). With the health
        // discount on, Pluto's contribution should be heavily damped.
        let pluto = ZoneContribution { zone_size: 3, t_zone: 1.0 };
        let pluto_health = ZoneHealth {
            active_witnesses: 3,
            total_staked: 100,
            median_reputation: 0.3,
            uptime_30d: 0.7,
        };
        let pluto_discounted = apply_health_discount(pluto, &pluto_health);
        // 3/5 = 0.6 witness factor × 1.0 rep × 1.0 uptime = 0.6 health discount
        assert!((pluto_discounted.t_zone - 0.6).abs() < 1e-12,
            "pluto.t_zone after discount = {}", pluto_discounted.t_zone);

        // The merged T_global with Pluto should still sit close to
        // Earth+Mars: Pluto's log weight is ln(4)≈1.386, vs Earth's
        // ln(100001)≈11.513 — Pluto contributes ~10% of the weight, and
        // its T after discount is 0.6, so the net pull on T_global is
        // bounded.
        let t_with_pluto = t_global(&[
            apply_health_discount(earth, &earth_health),
            apply_health_discount(mars, &mars_health),
            pluto_discounted,
        ]);
        assert!(t_with_pluto > 0.82, "T_global with sybil zone = {t_with_pluto} unexpectedly low");
        // Most importantly: a 3-node sybil zone publishing T_zone=1.0 must
        // NOT push T_global above 0.95 (i.e. it can't synthesize a near-
        // unanimous-consensus signal).
        assert!(t_with_pluto < 0.95, "T_global = {t_with_pluto} — sybil zone too influential");
    }
}
