//! Hysteresis-based zone auto-scaling: split hot zones, merge cold zones.
//!
//! A sharded network keeps per-zone load inside a healthy band by changing the
//! global `zone_count`. This crate is the pure decision layer:
//!
//! * [`recommend_zone_count`] takes a snapshot of per-zone activity (rec/s) and
//!   returns a coarse [`ScalingDecision`] (double / halve / hold).
//! * [`AutoScaler`] wraps that with hysteresis so a single spike or lull can't
//!   flap the network — a direction must hold for [`HYSTERESIS_TICKS`]
//!   consecutive observations before it fires.
//! * [`pick_transition_target`] narrows a global decision to the concrete
//!   zone(s) a transition must reference, with a deterministic tie-break so two
//!   honest peers observing the same snapshot always pick the same target.
//!
//! Everything here is pure, deterministic, and dependency-free. The crate is
//! generic over the zone-identifier type `Z`: it only requires the standard
//! ordering/cloning bounds where a concrete zone must be named, never any
//! protocol-specific trait. Decisions are coarse by design (double / halve) —
//! the goal is a few transitions per hour, not continuous churn.
//!
//! Extracted from the Elara Protocol node; the node wires these primitives to
//! its storage, identity, committee-VRF and transition-seal machinery.

#![forbid(unsafe_code)]

use std::collections::HashMap;

/// Per-zone target record rate (rec/s) at the minimum epoch interval. Above
/// this a zone is saturated (already sealing as fast as it can).
///
/// In the Elara node this equals `TARGET_RECORDS_PER_EPOCH /
/// MIN_ADAPTIVE_EPOCH_SECS` (100 rec/epoch ÷ 5 s/epoch = 20.0 rec/s). The
/// value is baked here so the crate stays dependency-free; the node carries a
/// drift-guard test that fails the build if its epoch constants ever diverge
/// from this number.
pub const TARGET_ZONE_RATE: f64 = 20.0;

/// Average zone rec/s above this triggers a split recommendation.
/// 2× target captures zones that are already saturated AND still climbing.
pub const SPLIT_RATE_MULTIPLIER: f64 = 2.0;

/// Average zone rec/s below this triggers a merge recommendation.
/// 0.1× target captures zones that are using <10% of their capacity.
pub const MERGE_RATE_MULTIPLIER: f64 = 0.1;

/// Minimum consecutive ticks the split/merge condition must hold before
/// the scaler acts. Prevents one-tick spikes from flipping the network.
pub const HYSTERESIS_TICKS: u32 = 4;

/// Absolute floor on zone count. We never scale below this.
pub const MIN_ZONE_COUNT: u64 = 1;

/// Absolute ceiling on zone count. Matches the mainnet scale target; operators
/// can lower this via config when rolling out.
pub const MAX_ZONE_COUNT: u64 = 1_000_000;

/// Split-key boundary used for every split: the midpoint of the 32-byte hash
/// space. Accounts with `hash(account_id) < 0x80...` route to the left child;
/// others to the right. A fixed boundary keeps the picker honest — two anchors
/// observing the same parent always produce byte-identical seals.
///
/// Future work: a weighted boundary that balances the child account counts.
/// The midpoint is a safe conservative default; the worst-case imbalance is
/// the natural skew of the account-hash distribution, which is ~uniform at
/// scale.
pub const SPLIT_KEY_MIDPOINT: [u8; 32] = [0x80u8; 32];

/// Decision produced by the autoscale calculator.
#[derive(Debug, Clone, PartialEq)]
pub enum ScalingDecision {
    /// Keep zone_count unchanged. Carries the observed `avg_rate` and reason
    /// (Hot/Cold/Balanced) so caller telemetry reflects what was seen even
    /// when no transition fires.
    NoChange { avg_rate: f64, reason: ScalingReason },
    /// Recommend growing zone_count to `new_count` (always ≥ current + 1).
    Split { new_count: u64, avg_rate: f64 },
    /// Recommend shrinking zone_count to `new_count` (always ≤ current - 1).
    Merge { new_count: u64, avg_rate: f64 },
}

/// Why no-change fired. Useful for logs and operator telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalingReason {
    /// Within healthy band: MERGE_RATE ≤ avg_rate ≤ SPLIT_RATE.
    Balanced,
    /// Above split threshold but at MAX_ZONE_COUNT — can't grow further.
    AtMaxZones,
    /// Below merge threshold but at MIN_ZONE_COUNT — can't shrink further.
    AtMinZones,
    /// No active zones in the input (network idle or just bootstrapped).
    NoData,
}

/// Compute the recommended zone count from a per-zone activity snapshot.
///
/// Pure, deterministic, O(zones). Does not consult shared state. The caller
/// is responsible for passing a sensible max_zones cap (e.g. from config)
/// and the current zone_count.
///
/// Rules:
/// * avg_rate > SPLIT_RATE and current_zone_count < max → recommend 2 × current (capped at max)
/// * avg_rate < MERGE_RATE and current_zone_count > min → recommend max(min, current / 2)
/// * otherwise → NoChange
pub fn recommend_zone_count<Z>(
    per_zone_activity: &HashMap<Z, f64>,
    current_zone_count: u64,
    max_zones: u64,
) -> ScalingDecision {
    if per_zone_activity.is_empty() {
        return ScalingDecision::NoChange {
            avg_rate: 0.0,
            reason: ScalingReason::NoData,
        };
    }

    let max_zones = max_zones.clamp(MIN_ZONE_COUNT, MAX_ZONE_COUNT);
    let current = current_zone_count.max(MIN_ZONE_COUNT);

    // Average the observed rates. Zones with no activity contribute 0 as
    // long as they appear in the input; caller decides whether to include
    // idle zones or only active ones.
    let total: f64 = per_zone_activity.values().copied().sum();
    let avg_rate = total / per_zone_activity.len() as f64;

    // A non-finite (NaN/inf) or negative average means the caller's metrics
    // pipeline produced garbage (e.g. 0.0/0.0, or a miscomputed delta). Do not
    // let it drive a spurious Split/Merge — surface it as NoData and hold.
    if !avg_rate.is_finite() || avg_rate < 0.0 {
        return ScalingDecision::NoChange {
            avg_rate,
            reason: ScalingReason::NoData,
        };
    }

    let split_threshold = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER;
    let merge_threshold = TARGET_ZONE_RATE * MERGE_RATE_MULTIPLIER;

    if avg_rate > split_threshold {
        if current >= max_zones {
            return ScalingDecision::NoChange {
                avg_rate,
                reason: ScalingReason::AtMaxZones,
            };
        }
        let new_count = current.saturating_mul(2).min(max_zones);
        if new_count == current {
            return ScalingDecision::NoChange {
                avg_rate,
                reason: ScalingReason::AtMaxZones,
            };
        }
        return ScalingDecision::Split { new_count, avg_rate };
    }

    if avg_rate < merge_threshold {
        if current <= MIN_ZONE_COUNT {
            return ScalingDecision::NoChange {
                avg_rate,
                reason: ScalingReason::AtMinZones,
            };
        }
        let new_count = (current / 2).max(MIN_ZONE_COUNT);
        if new_count == current {
            return ScalingDecision::NoChange {
                avg_rate,
                reason: ScalingReason::AtMinZones,
            };
        }
        return ScalingDecision::Merge { new_count, avg_rate };
    }

    ScalingDecision::NoChange {
        avg_rate,
        reason: ScalingReason::Balanced,
    }
}

/// Stateful autoscaler. Wraps [`recommend_zone_count`] with hysteresis so a
/// transient burst or lull doesn't cause flapping. Caller drives it with
/// [`observe`](AutoScaler::observe) once per health tick; it returns
/// `Some(decision)` only when the same direction has fired
/// [`hysteresis_ticks`](AutoScaler::hysteresis_ticks) consecutive times.
#[derive(Debug, Clone)]
pub struct AutoScaler {
    /// Consecutive ticks we've seen Split recommendations.
    consecutive_hot: u32,
    /// Consecutive ticks we've seen Merge recommendations.
    consecutive_cold: u32,
    /// Hysteresis depth — caller can override default HYSTERESIS_TICKS.
    pub hysteresis_ticks: u32,
    /// Maximum zone count. Caller typically wires this from config.
    pub max_zones: u64,
    /// Last non-NoChange decision, for telemetry.
    pub last_decision: Option<ScalingDecision>,
}

impl AutoScaler {
    pub fn new(hysteresis_ticks: u32, max_zones: u64) -> Self {
        Self {
            consecutive_hot: 0,
            consecutive_cold: 0,
            hysteresis_ticks: hysteresis_ticks.max(1),
            max_zones,
            last_decision: None,
        }
    }

    /// Observe one tick of per-zone activity. Returns a decision ONLY when
    /// hysteresis is satisfied (i.e., the same direction has fired on
    /// `hysteresis_ticks` consecutive calls). Otherwise returns `None`.
    ///
    /// On a fire, the internal counter for the opposite direction is reset
    /// and the firing counter drops back to zero so the next cycle starts
    /// fresh.
    pub fn observe<Z>(
        &mut self,
        per_zone_activity: &HashMap<Z, f64>,
        current_zone_count: u64,
    ) -> Option<ScalingDecision> {
        let rec = recommend_zone_count(per_zone_activity, current_zone_count, self.max_zones);

        match &rec {
            ScalingDecision::Split { .. } => {
                self.consecutive_hot = self.consecutive_hot.saturating_add(1);
                self.consecutive_cold = 0;
                if self.consecutive_hot >= self.hysteresis_ticks {
                    self.consecutive_hot = 0;
                    self.last_decision = Some(rec.clone());
                    return Some(rec);
                }
            }
            ScalingDecision::Merge { .. } => {
                self.consecutive_cold = self.consecutive_cold.saturating_add(1);
                self.consecutive_hot = 0;
                if self.consecutive_cold >= self.hysteresis_ticks {
                    self.consecutive_cold = 0;
                    self.last_decision = Some(rec.clone());
                    return Some(rec);
                }
            }
            ScalingDecision::NoChange { .. } => {
                self.consecutive_hot = 0;
                self.consecutive_cold = 0;
            }
        }

        None
    }

    /// Current hysteresis counters `(consecutive_hot, consecutive_cold)`, for
    /// telemetry.
    pub fn counters(&self) -> (u32, u32) {
        (self.consecutive_hot, self.consecutive_cold)
    }
}

/// Which specific zone(s) a [`ScalingDecision`] targets. The global
/// Split/Merge decision is coarse ("too hot overall, split something"); this
/// narrows it to the concrete parent zone(s) a transition seal must reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionTarget<Z> {
    /// Split this single zone into two children. Chosen as the hottest zone
    /// in the observed activity map (tie-break: smallest `zone_id` under
    /// `Z: Ord`, for determinism across peers that see the same snapshot).
    Split { parent: Z },
    /// Merge these two zones into one child. Chosen as the two coldest zones.
    /// Ordering is deterministic (sorted by `zone_id`) so all honest peers
    /// pick the same pair from the same activity snapshot.
    Merge { a: Z, b: Z },
}

/// Translate a global [`ScalingDecision`] plus a per-zone activity snapshot
/// into a concrete [`TransitionTarget`].
///
/// Pure, deterministic, O(zones log zones) worst case (one sort). Uses the
/// smallest `zone_id` (under `Z: Ord`) as the tie-break for both Split and
/// Merge so two honest nodes observing the same snapshot always pick the same
/// target — essential for M-of-N signature collection to converge on one
/// proposal rather than split across multiple equally-valid ones.
///
/// Returns `None` if:
/// * the decision is `NoChange` (caller shouldn't be asking)
/// * the activity map is empty (no zones to split)
/// * a Merge is requested but there are <2 zones in the map
pub fn pick_transition_target<Z: Ord + Clone>(
    decision: &ScalingDecision,
    per_zone_activity: &HashMap<Z, f64>,
) -> Option<TransitionTarget<Z>> {
    match decision {
        ScalingDecision::NoChange { .. } => None,
        ScalingDecision::Split { .. } => {
            // Hottest zone wins; ties → smallest zone_id.
            per_zone_activity
                .iter()
                .max_by(|(a_id, a_rate), (b_id, b_rate)| {
                    (*a_rate)
                        .total_cmp(b_rate)
                        // Flip the zone_id compare so max picks the smallest.
                        .then_with(|| b_id.cmp(a_id))
                })
                .map(|(id, _)| TransitionTarget::Split { parent: id.clone() })
        }
        ScalingDecision::Merge { .. } => {
            if per_zone_activity.len() < 2 {
                return None;
            }
            // Sort by (rate asc, zone_id asc) and take the two coldest.
            let mut sorted: Vec<(&Z, &f64)> = per_zone_activity.iter().collect();
            sorted.sort_by(|(a_id, a_rate), (b_id, b_rate)| {
                (*a_rate).total_cmp(b_rate).then_with(|| a_id.cmp(b_id))
            });
            // Emit the pair sorted so (a,b) == (b,a) doesn't create two
            // competing proposals.
            let z0 = sorted[0].0.clone();
            let z1 = sorted[1].0.clone();
            let (a, b) = if z0 <= z1 { (z0, z1) } else { (z1, z0) };
            Some(TransitionTarget::Merge { a, b })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The crate is generic over the zone-id type; these tests exercise it
    // with `String` keys (which carry the same `Ord + Clone + Eq + Hash`
    // bounds the node's `ZoneId` provides). The node's own test suite re-runs
    // the integration path with the real `ZoneId`.
    fn zid(n: u64) -> String {
        n.to_string()
    }

    fn activity(entries: &[(u64, f64)]) -> HashMap<String, f64> {
        entries.iter().map(|(z, r)| (zid(*z), *r)).collect()
    }

    // ── recommend_zone_count ────────────────────────────────────────

    #[test]
    fn recommend_no_change_when_empty() {
        let rec = recommend_zone_count::<String>(&HashMap::new(), 2, 100);
        assert!(matches!(
            rec,
            ScalingDecision::NoChange {
                reason: ScalingReason::NoData,
                ..
            }
        ));
    }

    #[test]
    fn recommend_split_when_hot() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let act = activity(&[(0, hot), (1, hot)]);
        match recommend_zone_count(&act, 2, 100) {
            ScalingDecision::Split { new_count, .. } => assert_eq!(new_count, 4),
            other => panic!("expected Split, got {other:?}"),
        }
    }

    #[test]
    fn recommend_merge_when_cold() {
        let act = activity(&[(0, 0.001), (1, 0.001), (2, 0.001), (3, 0.001)]);
        match recommend_zone_count(&act, 4, 100) {
            ScalingDecision::Merge { new_count, .. } => assert_eq!(new_count, 2),
            other => panic!("expected Merge, got {other:?}"),
        }
    }

    #[test]
    fn recommend_balanced_in_healthy_band() {
        let act = activity(&[(0, TARGET_ZONE_RATE), (1, TARGET_ZONE_RATE)]);
        match recommend_zone_count(&act, 2, 100) {
            ScalingDecision::NoChange {
                reason: ScalingReason::Balanced,
                ..
            } => {}
            other => panic!("expected Balanced NoChange, got {other:?}"),
        }
    }

    #[test]
    fn recommend_clamped_at_max() {
        let hot = TARGET_ZONE_RATE * 100.0;
        let act = activity(&[(0, hot), (1, hot)]);
        match recommend_zone_count(&act, 100, 100) {
            ScalingDecision::NoChange {
                reason: ScalingReason::AtMaxZones,
                ..
            } => {}
            other => panic!("expected AtMaxZones NoChange, got {other:?}"),
        }
    }

    #[test]
    fn recommend_clamped_at_min() {
        let act = activity(&[(0, 0.0)]);
        match recommend_zone_count(&act, 1, 100) {
            ScalingDecision::NoChange {
                reason: ScalingReason::AtMinZones,
                ..
            } => {}
            other => panic!("expected AtMinZones NoChange, got {other:?}"),
        }
    }

    #[test]
    fn split_doubles_but_caps() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 10.0;
        let act = activity(&[(0, hot)]);
        match recommend_zone_count(&act, 60, 100) {
            ScalingDecision::Split { new_count, .. } => assert_eq!(new_count, 100),
            other => panic!("expected Split capped at max, got {other:?}"),
        }
    }

    // ── AutoScaler hysteresis ───────────────────────────────────────

    #[test]
    fn autoscaler_needs_hysteresis_ticks() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let act = activity(&[(0, hot), (1, hot)]);
        let mut scaler = AutoScaler::new(4, 100);

        for _ in 0..3 {
            assert!(scaler.observe(&act, 2).is_none());
        }
        match scaler.observe(&act, 2) {
            Some(ScalingDecision::Split { new_count, .. }) => assert_eq!(new_count, 4),
            other => panic!("expected Split on 4th tick, got {other:?}"),
        }
        // After firing, counter resets — next tick does NOT re-fire.
        assert!(scaler.observe(&act, 4).is_none());
    }

    #[test]
    fn autoscaler_resets_on_balanced() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let hot_act = activity(&[(0, hot)]);
        let cool_act = activity(&[(0, TARGET_ZONE_RATE)]);

        let mut scaler = AutoScaler::new(4, 100);
        scaler.observe(&hot_act, 2); // +1 hot
        scaler.observe(&hot_act, 2); // +2 hot
        scaler.observe(&cool_act, 2); // reset
        assert!(scaler.observe(&hot_act, 2).is_none());
        assert!(scaler.observe(&hot_act, 2).is_none());
        assert!(scaler.observe(&hot_act, 2).is_none());
        assert!(scaler.observe(&hot_act, 2).is_some());
    }

    #[test]
    fn autoscaler_opposite_signals_cancel() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let cold = activity(&[(0, 0.001), (1, 0.001)]);

        let mut scaler = AutoScaler::new(4, 100);
        scaler.observe(&activity(&[(0, hot)]), 4); // +1 hot
        scaler.observe(&cold, 4); // hot reset, +1 cold
        scaler.observe(&cold, 4); // +2 cold
        scaler.observe(&cold, 4); // +3 cold
        match scaler.observe(&cold, 4) {
            Some(ScalingDecision::Merge { new_count, .. }) => assert_eq!(new_count, 2),
            other => panic!("expected Merge, got {other:?}"),
        }
    }

    #[test]
    fn autoscaler_records_last_decision() {
        let hot = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let act = activity(&[(0, hot)]);
        let mut scaler = AutoScaler::new(2, 100);
        scaler.observe(&act, 2);
        scaler.observe(&act, 2);
        assert!(matches!(
            scaler.last_decision,
            Some(ScalingDecision::Split { .. })
        ));
    }

    #[test]
    fn autoscaler_new_clamps_zero_hysteresis_to_one_and_pins_initial_state() {
        // hysteresis=0 MUST clamp to 1 — fire-every-tick is catastrophic at scale.
        assert_eq!(AutoScaler::new(0, 100).hysteresis_ticks, 1);
        // 1 stays 1 (no over-clamp); u32::MAX passes through.
        assert_eq!(AutoScaler::new(1, 100).hysteresis_ticks, 1);
        assert_eq!(AutoScaler::new(u32::MAX, 100).hysteresis_ticks, u32::MAX);
        // max_zones is the caller's number, no constructor clamp.
        assert_eq!(AutoScaler::new(4, 12_345).max_zones, 12_345);
        // Initial state: counters (0,0), last_decision None.
        let s = AutoScaler::new(4, 100);
        assert_eq!(s.counters(), (0, 0));
        assert!(s.last_decision.is_none());
    }

    #[test]
    fn autoscaler_counters_track_hot_buildup_then_reset_on_fire() {
        let hot_rate = TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 2.0;
        let hot = activity(&[(0, hot_rate)]);
        let mut scaler = AutoScaler::new(3, 100);

        assert!(scaler.observe(&hot, 2).is_none());
        assert_eq!(scaler.counters(), (1, 0));
        assert!(scaler.observe(&hot, 2).is_none());
        assert_eq!(scaler.counters(), (2, 0));
        let fired = scaler.observe(&hot, 2).expect("tick 3 fires at hysteresis=3");
        assert!(matches!(fired, ScalingDecision::Split { .. }));
        assert_eq!(scaler.counters(), (0, 0), "both counters reset after fire");
        assert!(matches!(
            scaler.last_decision,
            Some(ScalingDecision::Split { .. })
        ));
        // Restarts buildup at 1, not at 0 (no immediate re-fire).
        assert!(scaler.observe(&hot, 4).is_none());
        assert_eq!(scaler.counters(), (1, 0));
    }

    // ── pick_transition_target ──────────────────────────────────────

    #[test]
    fn pick_target_nochange_returns_none() {
        let act = activity(&[(0, 1.0)]);
        let dec = ScalingDecision::NoChange {
            avg_rate: 1.0,
            reason: ScalingReason::Balanced,
        };
        assert_eq!(pick_transition_target(&dec, &act), None);
    }

    #[test]
    fn pick_target_split_picks_hottest_zone() {
        let act = activity(&[(0, 1.0), (1, 5.0), (2, 2.0)]);
        let dec = ScalingDecision::Split {
            new_count: 6,
            avg_rate: 8.0 / 3.0,
        };
        assert_eq!(
            pick_transition_target(&dec, &act),
            Some(TransitionTarget::Split { parent: zid(1) }),
        );
    }

    #[test]
    fn pick_target_split_ties_go_to_smallest() {
        // Equal rates — smallest zone_id must win so two peers converge.
        let act = activity(&[(0, 3.0), (1, 3.0), (2, 3.0)]);
        let dec = ScalingDecision::Split {
            new_count: 6,
            avg_rate: 3.0,
        };
        assert_eq!(
            pick_transition_target(&dec, &act),
            Some(TransitionTarget::Split { parent: zid(0) }),
        );
    }

    #[test]
    fn pick_target_split_empty_activity_returns_none() {
        let act: HashMap<String, f64> = HashMap::new();
        let dec = ScalingDecision::Split {
            new_count: 2,
            avg_rate: 10.0,
        };
        assert_eq!(pick_transition_target(&dec, &act), None);
    }

    #[test]
    fn pick_target_merge_picks_two_coldest() {
        let act = activity(&[(0, 10.0), (1, 0.1), (2, 0.2), (3, 20.0)]);
        let dec = ScalingDecision::Merge {
            new_count: 2,
            avg_rate: 7.575,
        };
        assert_eq!(
            pick_transition_target(&dec, &act),
            Some(TransitionTarget::Merge {
                a: zid(1),
                b: zid(2)
            }),
        );
    }

    #[test]
    fn pick_target_merge_ties_resolve_to_smallest() {
        let act = activity(&[(0, 0.0), (1, 0.0), (2, 0.0), (3, 0.0)]);
        let dec = ScalingDecision::Merge {
            new_count: 2,
            avg_rate: 0.0,
        };
        assert_eq!(
            pick_transition_target(&dec, &act),
            Some(TransitionTarget::Merge {
                a: zid(0),
                b: zid(1)
            }),
        );
    }

    #[test]
    fn pick_target_merge_output_pair_is_sorted() {
        let act = activity(&[(5, 0.1), (2, 0.2)]);
        let dec = ScalingDecision::Merge {
            new_count: 1,
            avg_rate: 0.15,
        };
        let Some(TransitionTarget::Merge { a, b }) = pick_transition_target(&dec, &act) else {
            panic!("expected Merge");
        };
        assert!(a <= b, "Merge pair must be sorted: got a={a:?}, b={b:?}");
        assert_eq!((a, b), (zid(2), zid(5)));
    }

    #[test]
    fn pick_target_merge_single_zone_returns_none() {
        let act = activity(&[(0, 0.1)]);
        let dec = ScalingDecision::Merge {
            new_count: 1,
            avg_rate: 0.1,
        };
        assert_eq!(pick_transition_target(&dec, &act), None);
    }

    #[test]
    fn pick_target_merge_one_hot_one_cold_picks_both() {
        // After the caller enriches the activity map with rate=0 entries for
        // silent zones, the picker must select both for the merge.
        let act = activity(&[(0, 0.062), (1, 0.0)]);
        let dec = ScalingDecision::Merge {
            new_count: 1,
            avg_rate: 0.031,
        };
        assert_eq!(
            pick_transition_target(&dec, &act),
            Some(TransitionTarget::Merge {
                a: zid(0),
                b: zid(1)
            }),
        );
    }

    #[test]
    fn pick_target_is_deterministic_across_hashmap_orders() {
        // HashMap iteration order is non-deterministic; two honest nodes on the
        // same snapshot must pick the same target regardless of insertion order.
        let mut act1: HashMap<String, f64> = HashMap::new();
        act1.insert(zid(7), 2.0);
        act1.insert(zid(3), 5.0);
        act1.insert(zid(11), 2.0);

        let mut act2: HashMap<String, f64> = HashMap::new();
        act2.insert(zid(11), 2.0);
        act2.insert(zid(7), 2.0);
        act2.insert(zid(3), 5.0);

        let dec_split = ScalingDecision::Split {
            new_count: 6,
            avg_rate: 3.0,
        };
        assert_eq!(
            pick_transition_target(&dec_split, &act1),
            pick_transition_target(&dec_split, &act2),
        );

        let dec_merge = ScalingDecision::Merge {
            new_count: 1,
            avg_rate: 3.0,
        };
        assert_eq!(
            pick_transition_target(&dec_merge, &act1),
            pick_transition_target(&dec_merge, &act2),
        );
    }

    // ── constant invariants ─────────────────────────────────────────

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_pin_band_hysteresis_and_zone_bounds() {
        // TARGET_ZONE_RATE is baked at 20.0 (node's 100 rec/epoch ÷ 5 s/epoch);
        // the node carries the drift-guard back to its epoch constants.
        assert!((TARGET_ZONE_RATE - 20.0).abs() < f64::EPSILON);
        assert!(TARGET_ZONE_RATE > 0.0);

        assert!((SPLIT_RATE_MULTIPLIER - 2.0).abs() < f64::EPSILON);
        assert!((MERGE_RATE_MULTIPLIER - 0.1).abs() < f64::EPSILON);
        // Inverted band would oscillate every tick.
        assert!(MERGE_RATE_MULTIPLIER < SPLIT_RATE_MULTIPLIER);

        assert_eq!(HYSTERESIS_TICKS, 4);

        assert_eq!(MIN_ZONE_COUNT, 1);
        assert_eq!(MAX_ZONE_COUNT, 1_000_000);
        assert!(MIN_ZONE_COUNT < MAX_ZONE_COUNT);

        // SPLIT_KEY_MIDPOINT: load-bearing for cross-anchor seal byte-identity.
        assert_eq!(SPLIT_KEY_MIDPOINT, [0x80u8; 32]);
        assert_ne!(SPLIT_KEY_MIDPOINT, [0u8; 32]);
        assert_ne!(SPLIT_KEY_MIDPOINT, [0xFFu8; 32]);
    }

    #[test]
    fn scaling_decision_partial_eq_distinguishes_variants_and_fields() {
        let a = ScalingDecision::Split {
            new_count: 2,
            avg_rate: 50.0,
        };
        assert_eq!(
            a,
            ScalingDecision::Split {
                new_count: 2,
                avg_rate: 50.0
            }
        );
        assert_ne!(
            a,
            ScalingDecision::Split {
                new_count: 4,
                avg_rate: 50.0
            }
        );
        assert_ne!(
            a,
            ScalingDecision::Split {
                new_count: 2,
                avg_rate: 51.0
            }
        );
        assert_ne!(
            a,
            ScalingDecision::Merge {
                new_count: 2,
                avg_rate: 50.0
            }
        );
        let bal = ScalingDecision::NoChange {
            avg_rate: 1.0,
            reason: ScalingReason::Balanced,
        };
        assert_ne!(
            bal,
            ScalingDecision::NoChange {
                avg_rate: 1.0,
                reason: ScalingReason::AtMaxZones
            }
        );
    }

    #[test]
    fn scaling_reason_and_transition_target_partial_eq_pin_full_variant_set() {
        let reasons = [
            ScalingReason::Balanced,
            ScalingReason::AtMaxZones,
            ScalingReason::AtMinZones,
            ScalingReason::NoData,
        ];
        for (i, a) in reasons.iter().enumerate() {
            for (j, b) in reasons.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }

        let split_z0 = TransitionTarget::Split { parent: zid(0) };
        assert_eq!(split_z0, TransitionTarget::Split { parent: zid(0) });
        assert_ne!(split_z0, TransitionTarget::Split { parent: zid(1) });
        let merge_01 = TransitionTarget::Merge {
            a: zid(0),
            b: zid(1),
        };
        assert_ne!(split_z0, merge_01);
        assert_ne!(
            merge_01,
            TransitionTarget::Merge {
                a: zid(1),
                b: zid(2)
            }
        );
    }
}
