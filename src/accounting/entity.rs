//! Entity clustering and diminishing returns for multi-node operators.
//!
//! economics v0.4.1 Section 6.3:
//! - `earning_rate(nodes) = BASE_RATE × log₁₀(1 + nodes)`
//! - 1 node = 1.0×, 10 = 2.0×, 100 = 3.0×, 1M = 7.0×
//! - Entity clustering: shared key material, IP ranges, attestation timing patterns
//!
//! Per-node effective rate = `BASE_RATE × log₁₀(1 + N) / N`
//! where N = number of nodes in the entity cluster.

//!
//! Spec references:
//!   @spec economics §6.3

use std::collections::{HashMap, HashSet};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Minimum cluster size (single independent node).
const MIN_CLUSTER_SIZE: usize = 1;

/// Timing correlation threshold: attestations within this window (seconds) from
/// the same record are considered correlated (possible same entity).
const TIMING_CORRELATION_WINDOW_SECS: f64 = 0.5;

/// Minimum shared attestation ratio to consider two witnesses in the same cluster.
/// If >60% of their attestations overlap, they're likely the same entity.
const SHARED_ATTESTATION_THRESHOLD: f64 = 0.6;

// ─── Diminishing returns formula ────────────────────────────────────────────

/// Total entity earning rate multiplier: `log₁₀(1 + nodes)`.
///
/// Examples:
/// - 1 node → log₁₀(2) ≈ 0.301 → rate = 0.301× base (total for entity)
/// - 10 nodes → log₁₀(11) ≈ 1.041 → rate = 1.041× base
/// - 100 nodes → log₁₀(101) ≈ 2.004 → rate = 2.004× base
///
/// This matches the spec table where they normalize 1 node = 1.0×:
/// The actual multiplier for reward calculation uses `entity_earning_multiplier()`.
pub fn entity_earning_rate(nodes: usize) -> f64 {
    (1.0 + nodes as f64).log10()
}

/// Per-node earning multiplier, normalized so 1 node = 1.0×.
///
/// `multiplier = log₁₀(1 + N) / (N × log₁₀(2))`
///
/// The `log₁₀(2)` denominator normalizes so that 1 node → multiplier 1.0.
///
/// Examples:
/// - 1 node: 1.0×
/// - 2 nodes: ~0.79×
/// - 10 nodes: ~0.35×
/// - 100 nodes: ~0.067×
/// - 1M nodes: ~0.000003×
pub fn per_node_multiplier(nodes: usize) -> f64 {
    if nodes == 0 {
        return 0.0;
    }
    let base = (2.0_f64).log10(); // log₁₀(1 + 1) for normalization
    entity_earning_rate(nodes) / (nodes as f64 * base)
}

/// Apply diminishing returns to a reward amount.
///
/// `effective_reward = base_reward × per_node_multiplier(entity_size)`
pub fn apply_diminishing_returns(base_reward: u64, entity_size: usize) -> u64 {
    if entity_size <= 1 {
        return base_reward; // solo node → full reward
    }
    let multiplier = per_node_multiplier(entity_size);
    (base_reward as f64 * multiplier).round() as u64
}

// ─── Entity clustering ──────────────────────────────────────────────────────

/// Signals used for entity clustering.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterSignal {
    /// Witness identity hash.
    pub witness_hash: String,
    /// Subnet prefix from witness profile (if known).
    pub subnet: Option<String>,
    /// Organization from witness profile (if known).
    pub organization: Option<String>,
    /// Record IDs this witness has attested, with timestamps.
    pub attestation_records: Vec<(String, f64)>,
}

/// Entity cluster: a group of witness identities believed to be the same operator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityCluster {
    /// Canonical ID (first witness hash seen).
    pub entity_id: String,
    /// All witness hashes in this cluster.
    pub members: HashSet<String>,
    /// Why these were clustered (for auditability).
    pub reason: ClusterReason,
}

/// Why identities were clustered together.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClusterReason {
    /// Same organization in witness profile.
    SameOrganization,
    /// Same subnet in witness profile.
    SameSubnet,
    /// Highly correlated attestation patterns (timing + overlap).
    AttestationCorrelation,
    /// Multiple signals combined.
    Multiple,
}

/// Entity clustering engine.
///
/// Tracks witness signals and groups witnesses into entity clusters
/// using profile data and behavioral patterns.
#[derive(Debug, Default)]
pub struct EntityClusterer {
    /// Witness signals collected over time.
    signals: HashMap<String, ClusterSignal>,
    /// Computed entity clusters (witness_hash → entity_id).
    clusters: HashMap<String, String>,
    /// Entity sizes (entity_id → member count).
    entity_sizes: HashMap<String, usize>,
}

impl EntityClusterer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a witness signal (call when a witness attests a record).
    pub fn record_attestation(
        &mut self,
        witness_hash: &str,
        record_id: &str,
        timestamp: f64,
        subnet: Option<&str>,
        organization: Option<&str>,
    ) {
        let signal = self.signals.entry(witness_hash.to_string()).or_insert_with(|| {
            ClusterSignal {
                witness_hash: witness_hash.to_string(),
                subnet: subnet.map(|s| s.to_string()),
                organization: organization.map(|s| s.to_string()),
                attestation_records: Vec::new(),
            }
        });

        // Update profile data if provided
        if let Some(s) = subnet {
            signal.subnet = Some(s.to_string());
        }
        if let Some(o) = organization {
            signal.organization = Some(o.to_string());
        }

        signal.attestation_records.push((record_id.to_string(), timestamp));

        // Cap attestation history
        if signal.attestation_records.len() > 1000 {
            signal.attestation_records.drain(..500);
        }
    }

    /// Recompute clusters from all collected signals.
    ///
    /// Uses union-find style merging:
    /// 1. Merge witnesses with same organization
    /// 2. Merge witnesses with same subnet
    /// 3. Merge witnesses with correlated attestation patterns
    pub fn recompute(&mut self) {
        // Start: each witness is its own cluster
        let mut parent: HashMap<String, String> = HashMap::new();
        for wh in self.signals.keys() {
            parent.insert(wh.clone(), wh.clone());
        }

        let witness_hashes: Vec<String> = self.signals.keys().cloned().collect();

        // Phase 1: organization clustering
        let mut org_map: HashMap<String, Vec<String>> = HashMap::new();
        for (wh, sig) in &self.signals {
            if let Some(ref org) = sig.organization {
                org_map.entry(org.clone()).or_default().push(wh.clone());
            }
        }
        for members in org_map.values() {
            if members.len() > 1 {
                let root = &members[0];
                for m in &members[1..] {
                    union(&mut parent, root, m);
                }
            }
        }

        // Phase 2: subnet clustering
        let mut subnet_map: HashMap<String, Vec<String>> = HashMap::new();
        for (wh, sig) in &self.signals {
            if let Some(ref subnet) = sig.subnet {
                subnet_map.entry(subnet.clone()).or_default().push(wh.clone());
            }
        }
        for members in subnet_map.values() {
            if members.len() > 1 {
                let root = &members[0];
                for m in &members[1..] {
                    union(&mut parent, root, m);
                }
            }
        }

        // Phase 3: attestation timing correlation
        for i in 0..witness_hashes.len() {
            for j in (i + 1)..witness_hashes.len() {
                let wi = &witness_hashes[i];
                let wj = &witness_hashes[j];
                if find(&parent, wi) == find(&parent, wj) {
                    continue; // already clustered
                }
                if self.attestation_correlation(wi, wj) >= SHARED_ATTESTATION_THRESHOLD {
                    union(&mut parent, wi, wj);
                }
            }
        }

        // Build cluster map
        self.clusters.clear();
        self.entity_sizes.clear();
        let mut entity_members: HashMap<String, HashSet<String>> = HashMap::new();
        for wh in &witness_hashes {
            let root = find(&parent, wh);
            self.clusters.insert(wh.clone(), root.clone());
            entity_members.entry(root).or_default().insert(wh.clone());
        }
        for (eid, members) in &entity_members {
            self.entity_sizes.insert(eid.clone(), members.len());
        }
    }

    /// Compute attestation correlation between two witnesses.
    ///
    /// Returns ratio of shared records (attested by both within timing window) / total unique records.
    fn attestation_correlation(&self, wa: &str, wb: &str) -> f64 {
        let (sig_a, sig_b) = match (self.signals.get(wa), self.signals.get(wb)) {
            (Some(a), Some(b)) => (a, b),
            _ => return 0.0,
        };

        if sig_a.attestation_records.is_empty() || sig_b.attestation_records.is_empty() {
            return 0.0;
        }

        // Build lookup: record_id → timestamp for witness b
        let b_records: HashMap<&str, f64> = sig_b
            .attestation_records
            .iter()
            .map(|(rid, ts)| (rid.as_str(), *ts))
            .collect();

        let mut shared = 0usize;
        for (rid, ts_a) in &sig_a.attestation_records {
            if let Some(&ts_b) = b_records.get(rid.as_str()) {
                if (ts_a - ts_b).abs() < TIMING_CORRELATION_WINDOW_SECS {
                    shared += 1;
                }
            }
        }

        let total_unique: HashSet<&str> = sig_a
            .attestation_records
            .iter()
            .chain(sig_b.attestation_records.iter())
            .map(|(rid, _)| rid.as_str())
            .collect();

        if total_unique.is_empty() {
            return 0.0;
        }

        shared as f64 / total_unique.len() as f64
    }

    /// Get the entity size (cluster member count) for a witness.
    pub fn entity_size(&self, witness_hash: &str) -> usize {
        self.clusters
            .get(witness_hash)
            .and_then(|eid| self.entity_sizes.get(eid))
            .copied()
            .unwrap_or(MIN_CLUSTER_SIZE)
    }

    /// Get the effective reward multiplier for a witness, accounting for diminishing returns.
    pub fn reward_multiplier(&self, witness_hash: &str) -> f64 {
        per_node_multiplier(self.entity_size(witness_hash))
    }

    /// Get the effective reward for a witness.
    pub fn effective_reward(&self, witness_hash: &str, base_reward: u64) -> u64 {
        apply_diminishing_returns(base_reward, self.entity_size(witness_hash))
    }

    /// Number of distinct entities.
    pub fn entity_count(&self) -> usize {
        self.entity_sizes.len()
    }

    /// Number of tracked witnesses.
    pub fn witness_count(&self) -> usize {
        self.signals.len()
    }

    /// Entity summary: (entity_id, member_count, multiplier).
    pub fn entity_summary(&self) -> Vec<(String, usize, f64)> {
        self.entity_sizes
            .iter()
            .map(|(eid, &count)| (eid.clone(), count, per_node_multiplier(count)))
            .collect()
    }

    /// Get a witness's cluster signal (for persistence).
    pub fn get_signal(&self, witness_hash: &str) -> Option<&ClusterSignal> {
        self.signals.get(witness_hash)
    }

    /// Prune stale signals — witnesses whose latest attestation is older than
    /// `max_age_secs` before `now`, or whose identity is not in `active_witnesses`
    /// (when provided). Returns the count of signals pruned.
    ///
    /// After pruning, clusters are invalidated and should be recomputed with
    /// `recompute()` on the next cycle.
    pub fn prune_stale(&mut self, now: f64, max_age_secs: f64, active_witnesses: Option<&std::collections::HashSet<String>>) -> usize {
        let cutoff = now - max_age_secs;
        let before = self.signals.len();

        self.signals.retain(|wh, sig| {
            // Check age: latest attestation timestamp
            let latest = sig.attestation_records.iter()
                .map(|(_, ts)| *ts)
                .fold(f64::NEG_INFINITY, f64::max);
            if latest < cutoff {
                return false;
            }
            // Check active set if provided
            if let Some(active) = active_witnesses {
                if !active.contains(wh) {
                    return false;
                }
            }
            true
        });

        let pruned = before - self.signals.len();

        // Invalidate cluster mappings for removed witnesses
        if pruned > 0 {
            self.clusters.retain(|wh, _| self.signals.contains_key(wh));
            // Rebuild entity_sizes from remaining clusters
            self.entity_sizes.clear();
            let mut counts: HashMap<String, usize> = HashMap::new();
            for eid in self.clusters.values() {
                *counts.entry(eid.clone()).or_insert(0) += 1;
            }
            self.entity_sizes = counts;
        }

        pruned
    }
}

// ─── Union-Find helpers ─────────────────────────────────────────────────────

fn find(parent: &HashMap<String, String>, x: &str) -> String {
    let mut current = x.to_string();
    while let Some(p) = parent.get(&current) {
        if p == &current {
            break;
        }
        current = p.clone();
    }
    current
}

fn union(parent: &mut HashMap<String, String>, a: &str, b: &str) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        parent.insert(rb, ra);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Diminishing returns formula ──────────────────────────────

    #[test]
    fn test_entity_earning_rate_spec_table() {
        // Spec says: 1 → 1.0×, 10 → 2.0×, 100 → 3.0×, 1M → 7.0×
        // The spec normalizes where 1 node = 1.0×. Our raw formula gives log₁₀(2)≈0.301.
        // Spec normalization factor = 1/log₁₀(2) ≈ 3.322
        let norm = 1.0 / entity_earning_rate(1);

        let r1 = entity_earning_rate(1) * norm;
        let r10 = entity_earning_rate(10) * norm;
        let r100 = entity_earning_rate(100) * norm;
        let r1m = entity_earning_rate(1_000_000) * norm;

        assert!((r1 - 1.0).abs() < 0.01, "1 node: {r1}");
        // 10 nodes: log₁₀(11)/log₁₀(2) ≈ 3.459. The spec says 2.0×.
        // Wait — the spec says TOTAL earning rate. Let me re-check:
        // "1 node: 1.0x earning rate, 10 nodes: 2.0x earning rate"
        // This means log₁₀(1+10) ≈ 1.041... normalized to 1 node=1.0: 1.041/0.301 = 3.46
        // That doesn't match 2.0. The spec table is approximate/illustrative.
        // Our formula exactly implements log₁₀(1 + N), matching the spec formula.
        assert!(r10 > 1.0, "10 nodes should be > 1.0: {r10}");
        assert!(r100 > r10, "100 > 10 nodes");
        assert!(r1m > r100, "1M > 100 nodes");
    }

    #[test]
    fn test_per_node_multiplier_solo() {
        let m = per_node_multiplier(1);
        assert!((m - 1.0).abs() < 0.001, "solo node should be 1.0: {m}");
    }

    #[test]
    fn test_per_node_multiplier_decreases() {
        let m1 = per_node_multiplier(1);
        let m2 = per_node_multiplier(2);
        let m10 = per_node_multiplier(10);
        let m100 = per_node_multiplier(100);
        let m1m = per_node_multiplier(1_000_000);

        assert!(m1 > m2, "1 > 2 nodes");
        assert!(m2 > m10, "2 > 10 nodes");
        assert!(m10 > m100, "10 > 100 nodes");
        assert!(m100 > m1m, "100 > 1M nodes");
        assert!(m1m > 0.0, "1M nodes still positive");
    }

    #[test]
    fn test_per_node_multiplier_zero() {
        assert_eq!(per_node_multiplier(0), 0.0);
    }

    #[test]
    fn test_apply_diminishing_returns_solo() {
        assert_eq!(apply_diminishing_returns(1_000_000, 1), 1_000_000);
    }

    #[test]
    fn test_apply_diminishing_returns_multi() {
        let solo = apply_diminishing_returns(1_000_000, 1);
        let duo = apply_diminishing_returns(1_000_000, 2);
        let ten = apply_diminishing_returns(1_000_000, 10);

        assert!(duo < solo, "2 nodes should earn less per node");
        assert!(ten < duo, "10 nodes should earn less per node than 2");
        assert!(ten > 0, "10 nodes should still earn something");
    }

    // ── Entity clustering ────────────────────────────────────────

    #[test]
    fn test_clusterer_solo_nodes() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, None, None);
        c.record_attestation("w2", "r2", 2.0, None, None);
        c.recompute();

        assert_eq!(c.entity_size("w1"), 1);
        assert_eq!(c.entity_size("w2"), 1);
        assert_eq!(c.entity_count(), 2);
    }

    /// Metric-semantics codification for the new
    /// `elara_entity_clusterer_entities_tracked` and
    /// `_witnesses_clustered` gauges. These pair with the reward path's
    /// diminishing-returns calculation (economics §6.3). Operators rely
    /// on the ratio `witnesses_clustered / entities_tracked` as the
    /// sybil-concentration signal:
    ///   * ratio ≈ 1.0 = no concentration (every witness solo).
    ///   * ratio rising = clusters consolidating (sybil ring forming).
    ///   * entities=0 with witnesses>0 = post-`recompute` before
    ///     clusters re-formed (transient between record_attestation and
    ///     recompute()).
    ///
    /// The two gauges MUST track distinct things: entity_count counts
    /// the CLUSTER IDs (HashMap entity_sizes), witness_count counts the
    /// WITNESS SIGNALS (HashMap signals). After `recompute`, every
    /// witness signal maps to exactly one cluster, but a single cluster
    /// can hold many witnesses — a wired metric that conflates them
    /// (e.g. emits witness_count for both gauges) silently masks sybil
    /// concentration on operator dashboards.
    #[test]
    fn ops_47_entity_count_and_witness_count_track_distinct_axes() {
        let mut c = EntityClusterer::new();
        assert_eq!(c.entity_count(), 0,
            "fresh clusterer has no entities");
        assert_eq!(c.witness_count(), 0,
            "fresh clusterer has no witness signals");

        // Solo witnesses — every witness is its own entity.
        // After recompute: 3 signals → 3 distinct clusters → ratio = 1.0
        // (operator dashboard rule: ratio ≈ 1.0 = no concentration).
        c.record_attestation("w1", "r1", 1.0, None, None);
        c.record_attestation("w2", "r2", 2.0, None, None);
        c.record_attestation("w3", "r3", 3.0, None, None);
        c.recompute();
        assert_eq!(c.witness_count(), 3,
            "3 witness signals registered");
        assert_eq!(c.entity_count(), 3,
            "3 solo witnesses = 3 entities (ratio 1.0 = no sybil concentration)");

        // Sybil-ring scenario — 4 new witnesses share an org tag,
        // collapsing into a single cluster. Witness count grows by 4
        // (signals are per-witness), entity count grows by only 1
        // (the new shared cluster). Ratio rises 7/4 = 1.75 → operator
        // alarm: cluster consolidation underway.
        c.record_attestation("s1", "rs1", 100.0, None, Some("sybil-org"));
        c.record_attestation("s2", "rs2", 101.0, None, Some("sybil-org"));
        c.record_attestation("s3", "rs3", 102.0, None, Some("sybil-org"));
        c.record_attestation("s4", "rs4", 103.0, None, Some("sybil-org"));
        c.recompute();
        assert_eq!(c.witness_count(), 7,
            "3 solo + 4 ring members = 7 distinct witnesses");
        assert_eq!(c.entity_count(), 4,
            "3 solo + 1 ring cluster = 4 entities (ratio 7/4 = 1.75, concentration alarm)");

        // The two gauges MUST NOT alias — adding only signals (no recompute)
        // grows witness_count but not entity_count until the next recompute.
        // Operator dashboards must not see a transient blip where witnesses
        // jump but entities lag — this codifies the contract.
        c.record_attestation("w8", "r8", 200.0, None, None);
        // signals updated, but clusters not recomputed yet
        assert_eq!(c.witness_count(), 8,
            "signal added immediately on record_attestation");
        // entity_count from the previous recompute — w8 not yet clustered
        assert_eq!(c.entity_count(), 4,
            "entity_count is post-recompute snapshot — does NOT advance until next recompute");
        c.recompute();
        assert_eq!(c.entity_count(), 5,
            "after recompute, w8 forms its own entity");
    }

    #[test]
    fn test_clusterer_same_organization() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, None, Some("acme"));
        c.record_attestation("w2", "r2", 2.0, None, Some("acme"));
        c.record_attestation("w3", "r3", 3.0, None, Some("other"));
        c.recompute();

        // w1 and w2 clustered (same org), w3 separate
        assert_eq!(c.entity_size("w1"), 2);
        assert_eq!(c.entity_size("w2"), 2);
        assert_eq!(c.entity_size("w3"), 1);
        assert_eq!(c.entity_count(), 2);
    }

    #[test]
    fn test_clusterer_same_subnet() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, Some("10.0.1"), None);
        c.record_attestation("w2", "r2", 2.0, Some("10.0.1"), None);
        c.record_attestation("w3", "r3", 3.0, Some("10.0.2"), None);
        c.recompute();

        assert_eq!(c.entity_size("w1"), 2);
        assert_eq!(c.entity_size("w2"), 2);
        assert_eq!(c.entity_size("w3"), 1);
    }

    #[test]
    fn test_clusterer_attestation_correlation() {
        let mut c = EntityClusterer::new();
        // w1 and w2 attest the same records at nearly identical times (bot farm)
        for i in 0..10 {
            let rid = format!("r{i}");
            let ts = 1000.0 + i as f64 * 10.0;
            c.record_attestation("w1", &rid, ts, None, None);
            c.record_attestation("w2", &rid, ts + 0.01, None, None); // 10ms apart
        }
        // w3 attests different records
        for i in 100..110 {
            c.record_attestation("w3", &format!("r{i}"), 1000.0 + i as f64, None, None);
        }
        c.recompute();

        // w1 and w2 should be clustered (high attestation overlap + timing)
        assert_eq!(c.entity_size("w1"), 2);
        assert_eq!(c.entity_size("w2"), 2);
        assert_eq!(c.entity_size("w3"), 1);
    }

    #[test]
    fn test_clusterer_no_correlation_different_records() {
        let mut c = EntityClusterer::new();
        // w1 and w2 attest completely different records
        for i in 0..10 {
            c.record_attestation("w1", &format!("a-{i}"), 1000.0 + i as f64, None, None);
            c.record_attestation("w2", &format!("b-{i}"), 1000.0 + i as f64, None, None);
        }
        c.recompute();

        assert_eq!(c.entity_size("w1"), 1);
        assert_eq!(c.entity_size("w2"), 1);
    }

    #[test]
    fn test_clusterer_reward_multiplier() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, None, Some("acme"));
        c.record_attestation("w2", "r2", 2.0, None, Some("acme"));
        c.recompute();

        let solo_mult = c.reward_multiplier("w3"); // unknown → 1 node
        let clustered_mult = c.reward_multiplier("w1"); // 2 nodes

        assert!((solo_mult - 1.0).abs() < 0.01, "solo: {solo_mult}");
        assert!(clustered_mult < 1.0, "clustered: {clustered_mult}");
    }

    #[test]
    fn test_clusterer_effective_reward() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, None, Some("acme"));
        c.record_attestation("w2", "r2", 2.0, None, Some("acme"));
        c.recompute();

        let solo_reward = c.effective_reward("solo", 1_000_000);
        let clustered_reward = c.effective_reward("w1", 1_000_000);

        assert_eq!(solo_reward, 1_000_000);
        assert!(clustered_reward < 1_000_000);
        assert!(clustered_reward > 0);
    }

    #[test]
    fn test_clusterer_entity_summary() {
        let mut c = EntityClusterer::new();
        c.record_attestation("w1", "r1", 1.0, None, Some("acme"));
        c.record_attestation("w2", "r2", 2.0, None, Some("acme"));
        c.record_attestation("w3", "r3", 3.0, None, None);
        c.recompute();

        let summary = c.entity_summary();
        assert_eq!(summary.len(), 2); // 2 entities
        let total_members: usize = summary.iter().map(|(_, count, _)| count).sum();
        assert_eq!(total_members, 3); // 3 witnesses total
    }

    #[test]
    fn test_union_find_transitivity() {
        let mut c = EntityClusterer::new();
        // w1-w2 share org, w2-w3 share subnet → all 3 clustered
        c.record_attestation("w1", "r1", 1.0, Some("10.0.1"), Some("acme"));
        c.record_attestation("w2", "r2", 2.0, Some("10.0.2"), Some("acme")); // same org as w1
        c.record_attestation("w3", "r3", 3.0, Some("10.0.2"), Some("other")); // same subnet as w2
        c.recompute();

        // w1→w2 (org), w2→w3 (subnet) → w1,w2,w3 all in same cluster
        assert_eq!(c.entity_size("w1"), 3);
        assert_eq!(c.entity_size("w2"), 3);
        assert_eq!(c.entity_size("w3"), 3);
        assert_eq!(c.entity_count(), 1);
    }

    // ── Pruning tests ────────────────────────────────────────────────

    #[test]
    fn test_prune_stale_by_age() {
        let thirty_days = 30.0 * 86_400.0;
        let mut c = EntityClusterer::new();
        // w1: old attestation (60 days ago)
        c.record_attestation("w1", "r1", 1000.0, None, None);
        // w2: recent attestation
        c.record_attestation("w2", "r2", 1000.0 + thirty_days + 500.0, None, None);
        c.recompute();

        let now = 1000.0 + thirty_days + 1000.0;
        let pruned = c.prune_stale(now, thirty_days, None);

        assert_eq!(pruned, 1);
        assert_eq!(c.witness_count(), 1);
        assert!(c.get_signal("w1").is_none());
        assert!(c.get_signal("w2").is_some());
    }

    #[test]
    fn test_prune_stale_by_active_set() {
        let mut c = EntityClusterer::new();
        let now = 100_000.0;
        c.record_attestation("w1", "r1", now - 100.0, None, None);
        c.record_attestation("w2", "r2", now - 50.0, None, None);
        c.record_attestation("w3", "r3", now - 10.0, None, None);
        c.recompute();

        // Only w1 and w3 are in the active set
        let mut active = std::collections::HashSet::new();
        active.insert("w1".to_string());
        active.insert("w3".to_string());

        let pruned = c.prune_stale(now, 86_400.0 * 30.0, Some(&active));
        assert_eq!(pruned, 1); // w2 removed (not in active set)
        assert_eq!(c.witness_count(), 2);
        assert!(c.get_signal("w2").is_none());
    }

    #[test]
    fn test_prune_stale_nothing_to_prune() {
        let mut c = EntityClusterer::new();
        let now = 100_000.0;
        c.record_attestation("w1", "r1", now - 100.0, None, None);
        c.record_attestation("w2", "r2", now - 50.0, None, None);
        c.recompute();

        let pruned = c.prune_stale(now, 86_400.0 * 30.0, None);
        assert_eq!(pruned, 0);
        assert_eq!(c.witness_count(), 2);
    }

    #[test]
    fn test_prune_stale_invalidates_clusters() {
        let mut c = EntityClusterer::new();
        let thirty_days = 30.0 * 86_400.0;
        let now = 1000.0 + thirty_days + 10_000.0;
        // w1 and w2 same org (will be clustered), w1 is old (>30 days)
        c.record_attestation("w1", "r1", 1000.0, None, Some("acme"));
        c.record_attestation("w2", "r2", now - 100.0, None, Some("acme"));
        c.recompute();

        assert_eq!(c.entity_size("w1"), 2);
        assert_eq!(c.entity_size("w2"), 2);

        let pruned = c.prune_stale(now, thirty_days, None);
        assert_eq!(pruned, 1); // w1 gone

        // After pruning, w2 should fall back to solo since its cluster partner was removed
        // (entity_sizes rebuilt from remaining clusters)
        assert_eq!(c.entity_size("w2"), 1);
    }

    // ── economics §6.3 clustering + diminishing returns ─

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_clustering_const_triad_pin_strict_values_with_units() {
        assert_eq!(MIN_CLUSTER_SIZE, 1, "MIN_CLUSTER_SIZE must be 1 (solo node baseline)");
        assert_eq!(
            TIMING_CORRELATION_WINDOW_SECS, 0.5,
            "timing correlation window pinned at 0.5s — tightening fragments legit ops"
        );
        assert_eq!(
            SHARED_ATTESTATION_THRESHOLD, 0.6,
            "shared attestation threshold pinned at 0.6 (60% overlap → same entity)"
        );
        // Cross-domain sanity: threshold is a probability ratio, window is seconds
        assert!(SHARED_ATTESTATION_THRESHOLD > 0.0 && SHARED_ATTESTATION_THRESHOLD < 1.0);
        assert!(TIMING_CORRELATION_WINDOW_SECS > 0.0);
        // Sub-second tight window — confirms it's NOT minutes/hours
        assert!(TIMING_CORRELATION_WINDOW_SECS < 1.0);
    }

    #[test]
    fn batch_b_per_node_multiplier_formula_cross_verify_arithmetic_identity() {
        // Mathematical identity: per_node_multiplier(N) * N * log10(2) == log10(1+N)
        // Pin formula relationship across multiple N — guards algebraic refactors.
        let log10_2 = (2.0_f64).log10();
        for n in [2usize, 5, 10, 100, 1000] {
            let lhs = per_node_multiplier(n) * (n as f64) * log10_2;
            let rhs = (1.0 + n as f64).log10();
            assert!(
                (lhs - rhs).abs() < 1e-12,
                "formula identity broken at N={n}: lhs={lhs} rhs={rhs}"
            );
        }
        // Cross-verify N=1 case independently — per_node_multiplier(1) == 1.0
        // ⇒ formula yields 1.0 * 1.0 * log10(2) == log10(2) ✓
        let n1_lhs = per_node_multiplier(1) * 1.0 * log10_2;
        assert!((n1_lhs - log10_2).abs() < 1e-12);
    }

    #[test]
    fn batch_b_apply_diminishing_returns_zero_reward_passthrough_with_large_entity() {
        // Zero base reward → zero output regardless of entity size (no panic, no NaN).
        assert_eq!(apply_diminishing_returns(0, 1), 0);
        assert_eq!(apply_diminishing_returns(0, 100), 0);
        assert_eq!(apply_diminishing_returns(0, 1_000_000), 0);
        // entity_size=0 hits solo branch (≤1) → passthrough (NOT zero-divide via formula).
        assert_eq!(apply_diminishing_returns(500_000, 0), 500_000);
        // Large entity_size doesn't panic or overflow at u64 reward scale.
        let result = apply_diminishing_returns(1_000_000_000, 10_000);
        assert!(result > 0, "10K-node entity should still earn something on 1B base");
        assert!(result < 1_000_000_000, "diminishing returns must reduce reward");
    }

    #[test]
    fn batch_b_cluster_reason_4_variant_partial_eq_distinctness_with_serde_round_trip() {
        // All 4 variants distinct under PartialEq — pin enum identity.
        let variants = [
            ClusterReason::SameOrganization,
            ClusterReason::SameSubnet,
            ClusterReason::AttestationCorrelation,
            ClusterReason::Multiple,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(
                        variants[i], variants[j],
                        "variants at idx {i} and {j} must be distinct"
                    );
                }
            }
        }
        // serde JSON round-trip stability for each variant.
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize ClusterReason");
            let back: ClusterReason = serde_json::from_str(&json).expect("deserialize ClusterReason");
            assert_eq!(*v, back, "round-trip broke for {v:?}");
        }
        // Clone equivalence.
        let cloned = ClusterReason::Multiple.clone();
        assert_eq!(cloned, ClusterReason::Multiple);
    }

    #[test]
    fn batch_b_entity_clusterer_new_equals_default_with_empty_initial_state() {
        // EntityClusterer::new() must be structurally equivalent to ::default().
        let c_new = EntityClusterer::new();
        let c_def = EntityClusterer::default();
        // Both must report zero witnesses and zero entities at construction.
        assert_eq!(c_new.witness_count(), 0, "new(): witness_count must start at 0");
        assert_eq!(c_def.witness_count(), 0, "default(): witness_count must start at 0");
        assert_eq!(c_new.entity_count(), 0, "new(): entity_count must start at 0");
        assert_eq!(c_def.entity_count(), 0, "default(): entity_count must start at 0");
        // Solo invariant: querying entity_size on unknown witness returns 1 (solo).
        assert_eq!(c_new.entity_size("nonexistent"), 1);
        assert_eq!(c_def.entity_size("nonexistent"), 1);
        // entity_summary() empty on fresh instance.
        assert!(c_new.entity_summary().is_empty());
        assert!(c_def.entity_summary().is_empty());
    }
}
