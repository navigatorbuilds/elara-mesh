//! Witness liveness tracking — monitors active vs idle witnesses.
//!
//! Every attestation updates the witness's last-seen timestamp.
//! Witnesses inactive beyond the configured threshold are flagged
//! for inactivity leak (gradual stake drain).

//!
//! Spec references:
//!   @spec Protocol §11.12

use std::collections::HashMap;

/// Tracks the last attestation time for each witness identity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WitnessLiveness {
    /// witness_hash → last attestation timestamp.
    last_seen: HashMap<String, f64>,
}

impl Default for WitnessLiveness {
    fn default() -> Self {
        Self::new()
    }
}

impl WitnessLiveness {
    pub fn new() -> Self {
        Self {
            last_seen: HashMap::new(),
        }
    }

    /// Record an attestation from a witness.
    pub fn record_attestation(&mut self, witness_hash: &str, timestamp: f64) {
        let entry = self.last_seen.entry(witness_hash.to_string()).or_insert(0.0);
        if timestamp > *entry {
            *entry = timestamp;
        }
    }

    /// Get the last attestation time for a witness, if known.
    pub fn last_seen(&self, witness_hash: &str) -> Option<f64> {
        self.last_seen.get(witness_hash).copied()
    }

    /// Returns witness hashes that haven't attested within the threshold.
    ///
    /// Only returns witnesses that ARE tracked (have attested at least once).
    /// Witnesses who staked but never attested are not tracked here — they
    /// are caught by the staking system separately.
    pub fn inactive_witnesses(&self, threshold_secs: f64, now: f64) -> Vec<(String, f64)> {
        self.last_seen
            .iter()
            .filter_map(|(hash, &last)| {
                let idle = now - last;
                if idle > threshold_secs {
                    Some((hash.clone(), idle))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of witnesses active within the threshold.
    pub fn active_count(&self, threshold_secs: f64, now: f64) -> usize {
        self.last_seen
            .values()
            .filter(|&&last| (now - last) <= threshold_secs)
            .count()
    }

    /// Total tracked witnesses.
    pub fn tracked_count(&self) -> usize {
        self.last_seen.len()
    }

    /// Remove a witness from tracking (e.g., after full unstake).
    pub fn remove(&mut self, witness_hash: &str) {
        self.last_seen.remove(witness_hash);
    }
}

/// Rebuild liveness from stored attestations.
///
/// Uses an aggregated SQL query to find the latest attestation time per witness.
pub fn rebuild_liveness(
    witness_mgr: &crate::network::witness::WitnessManager,
) -> WitnessLiveness {
    let mut liveness = WitnessLiveness::new();
    if let Ok(pairs) = witness_mgr.latest_per_witness() {
        for (witness_hash, timestamp) in pairs {
            liveness.record_attestation(&witness_hash, timestamp);
        }
    }
    liveness
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_liveness() {
        let l = WitnessLiveness::new();
        assert_eq!(l.tracked_count(), 0);
        assert!(l.last_seen("w1").is_none());
    }

    #[test]
    fn test_record_attestation() {
        let mut l = WitnessLiveness::new();
        l.record_attestation("w1", 100.0);
        assert_eq!(l.last_seen("w1"), Some(100.0));
        assert_eq!(l.tracked_count(), 1);

        // Later attestation updates
        l.record_attestation("w1", 200.0);
        assert_eq!(l.last_seen("w1"), Some(200.0));

        // Earlier attestation does NOT overwrite
        l.record_attestation("w1", 50.0);
        assert_eq!(l.last_seen("w1"), Some(200.0));
    }

    #[test]
    fn test_inactive_witnesses() {
        let mut l = WitnessLiveness::new();
        l.record_attestation("active", 900.0);
        l.record_attestation("idle", 100.0);
        l.record_attestation("dead", 10.0);

        let now = 1000.0;
        let threshold = 200.0;

        let inactive = l.inactive_witnesses(threshold, now);
        assert_eq!(inactive.len(), 2);

        let hashes: Vec<&str> = inactive.iter().map(|(h, _)| h.as_str()).collect();
        assert!(hashes.contains(&"idle"));
        assert!(hashes.contains(&"dead"));
        assert!(!hashes.contains(&"active"));
    }

    #[test]
    fn test_active_count() {
        let mut l = WitnessLiveness::new();
        l.record_attestation("w1", 900.0);
        l.record_attestation("w2", 950.0);
        l.record_attestation("w3", 100.0);

        assert_eq!(l.active_count(200.0, 1000.0), 2);
        assert_eq!(l.active_count(1000.0, 1000.0), 3);
        assert_eq!(l.active_count(10.0, 1000.0), 0);
    }

    #[test]
    fn test_remove() {
        let mut l = WitnessLiveness::new();
        l.record_attestation("w1", 100.0);
        assert_eq!(l.tracked_count(), 1);
        l.remove("w1");
        assert_eq!(l.tracked_count(), 0);
        assert!(l.last_seen("w1").is_none());
    }

    #[test]
    fn test_multiple_witnesses() {
        let mut l = WitnessLiveness::new();
        l.record_attestation("w1", 100.0);
        l.record_attestation("w2", 200.0);
        l.record_attestation("w3", 300.0);
        assert_eq!(l.tracked_count(), 3);
        assert_eq!(l.last_seen("w2"), Some(200.0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fixture-free pure-helper coverage.
    // 5 axes targeting distinct invariants:
    //   1. WitnessLiveness::new == default initial-state pin + Serde JSON
    //      round-trip preserves empty + non-empty state.
    //   2. record_attestation HIGH-WATER-MARK semantics (later updates;
    //      equal-ts no-op via strict > check; earlier rejected; first insert
    //      seeds at any timestamp incl 0.0 / negative / huge).
    //   3. inactive_witnesses strict > threshold boundary vs active_count
    //      strict <= threshold boundary — off-by-one regression guard;
    //      pairwise tracked = active(thresh,now) + inactive(thresh,now)
    //      partition at boundary.
    //   4. remove() decrements tracked_count by 1 on existing + no-op on
    //      missing (idempotent + no panic) + last_seen None after remove.
    //   5. tracked_count is HashMap.len() (no overcounting on duplicate
    //      attestations of same witness) + record_attestation on same
    //      witness 10x leaves tracked_count==1.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_liveness_new_default_initial_state_and_serde_roundtrip() {
        // Axis 1: new() == default + serde JSON round-trip.

        let l1 = WitnessLiveness::new();
        let l2 = WitnessLiveness::default();
        assert_eq!(l1.tracked_count(), 0);
        assert_eq!(l2.tracked_count(), 0);
        // Empty-state accessor invariants.
        assert!(l1.last_seen("any").is_none());
        assert_eq!(l1.active_count(1000.0, 1000.0), 0);
        assert!(l1.inactive_witnesses(0.0, 1000.0).is_empty());

        // Serde JSON round-trip preserves empty state.
        let s = serde_json::to_string(&l1).expect("serialize empty");
        let l_back: WitnessLiveness = serde_json::from_str(&s).expect("deserialize empty");
        assert_eq!(l_back.tracked_count(), 0);

        // Non-empty state round-trip.
        let mut l3 = WitnessLiveness::new();
        l3.record_attestation("w-alpha", 100.5);
        l3.record_attestation("w-beta", 200.25);
        l3.record_attestation("w-gamma", 300.125);
        let s3 = serde_json::to_string(&l3).expect("serialize 3");
        let l3_back: WitnessLiveness = serde_json::from_str(&s3).expect("deserialize 3");
        assert_eq!(l3_back.tracked_count(), 3);
        assert_eq!(l3_back.last_seen("w-alpha"), Some(100.5));
        assert_eq!(l3_back.last_seen("w-beta"), Some(200.25));
        assert_eq!(l3_back.last_seen("w-gamma"), Some(300.125));
        // Missing witness still None after deser.
        assert!(l3_back.last_seen("w-missing").is_none());
    }

    #[test]
    fn batch_b_liveness_record_attestation_high_water_mark_semantics() {
        // Axis 2: high-water-mark via strict > check.

        let mut l = WitnessLiveness::new();

        // First insert seeds the entry at the given timestamp (even 0.0).
        l.record_attestation("w", 0.0);
        assert_eq!(l.last_seen("w"), Some(0.0));
        assert_eq!(l.tracked_count(), 1);

        // Later timestamp updates (high-water-mark advances).
        l.record_attestation("w", 100.0);
        assert_eq!(l.last_seen("w"), Some(100.0));

        // EQUAL timestamp does NOT update (strict > check):
        // entry == 100.0, attestation at 100.0 → no change (vacuous; same value).
        l.record_attestation("w", 100.0);
        assert_eq!(l.last_seen("w"), Some(100.0));

        // Earlier timestamp does NOT overwrite.
        l.record_attestation("w", 50.0);
        assert_eq!(l.last_seen("w"), Some(100.0));
        l.record_attestation("w", 99.99);
        assert_eq!(l.last_seen("w"), Some(100.0));
        l.record_attestation("w", -1.0); // negative
        assert_eq!(l.last_seen("w"), Some(100.0));

        // Strictly larger timestamps advance.
        l.record_attestation("w", 100.000001);
        assert!(l.last_seen("w").unwrap() > 100.0);

        // Huge values accepted (no overflow on f64).
        l.record_attestation("w", 1e15);
        assert_eq!(l.last_seen("w"), Some(1e15));

        // First-insert for a NEW witness with a NEGATIVE timestamp.
        // record_attestation does or_insert(0.0), then checks `ts > 0.0`.
        // -100.0 > 0.0 is false → entry stays at the or_insert default 0.0.
        // tracked_count still grows because or_insert always inserts.
        // This is the documented monotonic-clock invariant: negative or
        // pre-epoch timestamps cannot poison the high-water mark.
        l.record_attestation("w-new", -100.0);
        assert_eq!(l.last_seen("w-new"), Some(0.0),
            "negative ts on new entry: or_insert(0.0) wins because ts > 0.0 is false");
        assert_eq!(l.tracked_count(), 2);

        // After negative-attest seeding, a positive ts updates normally.
        l.record_attestation("w-new", 5.0);
        assert_eq!(l.last_seen("w-new"), Some(5.0));

        // Same logic for ts == 0.0: brand-new witness, or_insert(0.0) then
        // 0.0 > 0.0 is false. Entry stays at 0.0.
        let mut l2 = WitnessLiveness::new();
        l2.record_attestation("z", 0.0);
        assert_eq!(l2.last_seen("z"), Some(0.0));
        // Same witness, same 0.0 — entry already at 0.0 from the prior call.
        l2.record_attestation("z", 0.0);
        assert_eq!(l2.last_seen("z"), Some(0.0));
        // Positive ts AFTER the 0.0 seeding does advance.
        l2.record_attestation("z", 1.0);
        assert_eq!(l2.last_seen("z"), Some(1.0));
    }

    #[test]
    fn batch_b_liveness_inactive_strict_gt_vs_active_le_boundary_partition() {
        // Axis 3: inactive_witnesses uses > threshold; active_count uses <=.
        // Together they partition tracked witnesses at the boundary.

        let now = 1000.0;
        let threshold = 100.0;

        let mut l = WitnessLiveness::new();
        // idle = now - last > threshold ⟺ last < now - threshold = 900.
        // last == 900: idle = 100, NOT > 100 (strict >); active_count: 100 <= 100, counted.
        l.record_attestation("at_boundary", 900.0);
        // idle > 100: last < 900: idle > 100 → in inactive.
        l.record_attestation("past_boundary", 899.0);
        // active: last > 900: idle < 100 → in active.
        l.record_attestation("fresh", 999.0);

        // inactive_witnesses: strict > check.
        let inactive = l.inactive_witnesses(threshold, now);
        let inactive_hashes: HashMap<String, f64> = inactive.into_iter().collect();
        assert_eq!(inactive_hashes.len(), 1);
        assert!(inactive_hashes.contains_key("past_boundary"));
        // boundary witness NOT in inactive list (strict >, not >=).
        assert!(!inactive_hashes.contains_key("at_boundary"));
        assert!(!inactive_hashes.contains_key("fresh"));

        // active_count: <= threshold check.
        let active = l.active_count(threshold, now);
        assert_eq!(active, 2, "boundary + fresh active; past_boundary not");

        // Partition invariant: tracked = active + inactive at the boundary
        // (boundary case goes to active; idle case goes to inactive).
        assert_eq!(l.tracked_count(), active + inactive_hashes.len());

        // Boundary divergence: at threshold == 0, no witness can be active
        // (every last < now), all tracked go to inactive.
        let active_zero = l.active_count(0.0, now);
        // Special: any witness with last == now would be active (0 <= 0).
        // Our 3 witnesses have last < now, so all idle.
        assert_eq!(active_zero, 0);
        let inactive_zero = l.inactive_witnesses(0.0, now);
        assert_eq!(inactive_zero.len(), 3);

        // Boundary divergence: at threshold == infinity, all are active.
        let active_inf = l.active_count(f64::INFINITY, now);
        assert_eq!(active_inf, 3);
        let inactive_inf = l.inactive_witnesses(f64::INFINITY, now);
        assert!(inactive_inf.is_empty());

        // Active partition: distinct from `tracked - inactive.len()` only when
        // boundary witnesses exist. Pin with explicit calculation.
        let mut l2 = WitnessLiveness::new();
        l2.record_attestation("a", now - threshold); // boundary
        l2.record_attestation("b", now - threshold - 0.001); // just past
        assert_eq!(l2.active_count(threshold, now), 1, "boundary in active");
        assert_eq!(l2.inactive_witnesses(threshold, now).len(), 1, "just-past in inactive");
    }

    #[test]
    fn batch_b_liveness_remove_idempotent_and_no_panic_on_missing() {
        // Axis 4: remove() decrement on existing + silent no-op on missing.

        let mut l = WitnessLiveness::new();
        l.record_attestation("w1", 100.0);
        l.record_attestation("w2", 200.0);
        l.record_attestation("w3", 300.0);
        assert_eq!(l.tracked_count(), 3);

        // Remove existing decrements.
        l.remove("w2");
        assert_eq!(l.tracked_count(), 2);
        assert!(l.last_seen("w2").is_none());

        // Idempotent: removing again no-op + no panic.
        l.remove("w2");
        assert_eq!(l.tracked_count(), 2);
        assert!(l.last_seen("w2").is_none());

        // Missing key no-op + no panic.
        l.remove("never-existed");
        assert_eq!(l.tracked_count(), 2);

        // Empty string is treated as a valid key (no panic; either present or
        // absent based on prior inserts).
        l.remove("");
        assert_eq!(l.tracked_count(), 2);

        // Remove all + verify post-remove gauges.
        l.remove("w1");
        l.remove("w3");
        assert_eq!(l.tracked_count(), 0);
        assert!(l.last_seen("w1").is_none());
        assert!(l.last_seen("w3").is_none());
        assert_eq!(l.active_count(1e9, 1e9), 0);
        assert!(l.inactive_witnesses(1e9, 1e9).is_empty());

        // Empty cache; remove still no-panic.
        l.remove("anything");
        assert_eq!(l.tracked_count(), 0);
    }

    #[test]
    fn batch_b_liveness_tracked_count_is_set_cardinality_not_attestation_count() {
        // Axis 5: tracked_count = HashMap.len() — distinct witnesses, NOT
        // total attestations. 10 attestations on the same witness → 1.

        let mut l = WitnessLiveness::new();
        for ts in 0..10 {
            l.record_attestation("w", (ts as f64) * 10.0);
        }
        assert_eq!(l.tracked_count(), 1, "10 attestations of one witness => count 1");
        assert_eq!(l.last_seen("w"), Some(90.0));

        // 10 distinct witnesses → 10.
        let mut l2 = WitnessLiveness::new();
        for i in 0..10 {
            let id = format!("w{i}");
            l2.record_attestation(&id, (i as f64) * 100.0);
        }
        assert_eq!(l2.tracked_count(), 10);

        // Mixed: 5 distinct + many duplicates → 5.
        let mut l3 = WitnessLiveness::new();
        for _ in 0..3 {
            l3.record_attestation("a", 100.0);
            l3.record_attestation("b", 200.0);
            l3.record_attestation("c", 300.0);
            l3.record_attestation("d", 400.0);
            l3.record_attestation("e", 500.0);
        }
        assert_eq!(l3.tracked_count(), 5,
            "5 distinct witnesses * 3 duplicate rounds => count 5");
        assert_eq!(l3.last_seen("a"), Some(100.0));
        assert_eq!(l3.last_seen("e"), Some(500.0));

        // Cardinality is independent of timestamp values — even identical
        // timestamps across distinct witnesses still distinguish.
        let mut l4 = WitnessLiveness::new();
        l4.record_attestation("x", 42.0);
        l4.record_attestation("y", 42.0);
        l4.record_attestation("z", 42.0);
        assert_eq!(l4.tracked_count(), 3);
    }

    #[test]
    fn ops_53_tracked_vs_active_axes_diverge_for_idle_witnesses() {
        // Metric semantics: tracked_count counts distinct
        // witnesses ever observed (HashMap len, monotonic until
        // explicit remove); active_count(threshold) counts the
        // SUBSET attesting within the threshold window. The two
        // gauges must support divergence — that divergence IS the
        // operator dashboard alarm "fleet shedding witnesses."
        let now = 1_000_000.0;
        let day = 86400.0;
        let threshold_48h = 2.0 * day;

        // I1: empty liveness → both gauges report 0.
        let l = WitnessLiveness::new();
        assert_eq!(l.tracked_count(), 0);
        assert_eq!(l.active_count(threshold_48h, now), 0);

        // I2: 5 fresh attestations within the 48h window →
        //     tracked=5 AND active_48h=5 (ratio = 1.0, healthy fleet).
        let mut l = WitnessLiveness::new();
        for w in &["w1", "w2", "w3", "w4", "w5"] {
            l.record_attestation(w, now - 100.0);
        }
        assert_eq!(l.tracked_count(), 5);
        assert_eq!(l.active_count(threshold_48h, now), 5);

        // I3: 3 idle witnesses (last attested 72h ago, outside the
        //     48h window) + 2 fresh — tracked=5 (still seen),
        //     active_48h=2 (only the fresh ones). This is the
        //     canonical dashboard alarm condition the gauges exist
        //     to surface.
        let mut l = WitnessLiveness::new();
        l.record_attestation("idle1", now - 3.0 * day); // 72h ago
        l.record_attestation("idle2", now - 3.0 * day);
        l.record_attestation("idle3", now - 3.0 * day);
        l.record_attestation("fresh1", now - 100.0);
        l.record_attestation("fresh2", now - 100.0);
        assert_eq!(l.tracked_count(), 5);
        assert_eq!(l.active_count(threshold_48h, now), 2);
        // Ratio = 0.4 — below the 0.5 dashboard alarm threshold.

        // I4: re-attesting an idle witness with a current timestamp
        //     brings it back into the active window. Tracked count
        //     unchanged; active count climbs as the witness rejoins.
        l.record_attestation("idle1", now - 50.0);
        assert_eq!(l.tracked_count(), 5);
        assert_eq!(l.active_count(threshold_48h, now), 3);

        // I5: removed witnesses (post full-unstake) drop from BOTH
        //     gauges simultaneously. Distinct from going-idle: the
        //     active gauge collapses but tracked persists for idle;
        //     for remove() they decay together.
        l.remove("fresh1");
        assert_eq!(l.tracked_count(), 4);
        assert_eq!(l.active_count(threshold_48h, now), 2);

        // I6: threshold is the active-window cutoff — exactly at the
        //     boundary the witness is active (the predicate is `<=`),
        //     one second past the boundary it falls out. Pin this to
        //     prevent off-by-one regressions in the gauge meaning.
        let mut l = WitnessLiveness::new();
        l.record_attestation("boundary", now - threshold_48h);
        assert_eq!(l.active_count(threshold_48h, now), 1);
        l.record_attestation("past_boundary", now - threshold_48h - 1.0);
        // past_boundary is OUTSIDE the window, so active stays at 1
        // (boundary was already counted), but tracked grew to 2.
        assert_eq!(l.tracked_count(), 2);
        assert_eq!(l.active_count(threshold_48h, now), 1);
    }
}
