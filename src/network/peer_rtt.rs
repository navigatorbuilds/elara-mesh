//! Per-peer RTT estimator — rolling median RTT per peer identity.
//!
//! Distinct from [`zone_rtt`](super::zone_rtt), which tracks p95 per ZONE.
//! This tracker keys by peer identity so the geographic-fraud detector can
//! cross-reference a peer's claimed `geo_zone` against measured RTT to other
//! peers claiming the same zone.
//!
//! # Scale
//! - Per-peer memory: 64 × 4 bytes (u32 microseconds) + head/len/tick = ~264 bytes.
//! - Capped at [`MAX_PEERS`]. Beyond that, LRU evicts the least-recently-updated
//!   peer. Memory is bounded at `MAX_PEERS × 264 ≈ 2.6 MB` even with 10K churn.
//!
//! # Sampling policy
//! Feed only **successful** gossip round-trips (PqStream push/pull OK with bytes).
//! Connection failures and timeouts are connectivity signals, not RTT.
//! Clamp samples to `[1 µs, MAX_SAMPLE_US]` (30s) so a single stuck peer cannot
//! poison the median.
//!
//! # Median, not p95
//! The per-peer tracker exposes **median** (p50) instead of p95 because the
//! geographic-fraud detector compares per-peer typical RTT against a claimed
//! geographic distance. p95 over-weights transient jitter that does not
//! reflect geography (desktop peer going under 4K video load, etc.). The p50
//! median is the honest "typical" RTT for that peer.
//!
//! # Spec
//! @spec Protocol §11.12 (geographic diversity, Theorem 3.1)
//! @spec MESH-BFT §5 (geographic fraud proofs)

use std::collections::HashMap;
use std::time::Duration;

use super::zone_rtt::{RollingP95, MAX_SAMPLE_US};

/// Maximum peers tracked concurrently. 10K matches the mainnet node target
/// (see internal design notes). Beyond this, LRU evicts the least-recently-updated entry.
pub const MAX_PEERS: usize = 10_000;

/// Peer identity key. Uses the peer's Dilithium3 identity hash (hex) — same
/// string used throughout the attestation/consensus layer. Typed as a newtype
/// so callers can't accidentally key by IP or URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded map of `PeerId -> RollingP95` with LRU eviction at [`MAX_PEERS`].
///
/// Reuses [`RollingP95`] from [`zone_rtt`](super::zone_rtt) — 64-slot ring,
/// integer-only, nearest-rank percentile. No re-implementation.
#[derive(Debug, Default)]
pub struct PeerRttEstimator {
    peers: HashMap<PeerId, RollingP95>,
    /// Monotonic counter used as pseudo-clock for LRU eviction. Wraps on
    /// overflow; safe as long as we evict long before a full u64 cycle.
    tick: u64,
}

impl PeerRttEstimator {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            tick: 0,
        }
    }

    /// Record an RTT sample for `peer`. Amortized O(1); O(MAX_PEERS) only on
    /// the rare eviction step.
    pub fn observe(&mut self, peer: &PeerId, rtt: Duration) {
        self.tick = self.tick.wrapping_add(1);
        let now = self.tick;

        if !self.peers.contains_key(peer) && self.peers.len() >= MAX_PEERS {
            self.evict_oldest();
        }

        self.peers
            .entry(peer.clone())
            .or_default()
            .observe(rtt, now);
    }

    /// Median (p50) RTT for `peer`, or `None` if no samples.
    pub fn median(&self, peer: &PeerId) -> Option<Duration> {
        self.peers
            .get(peer)
            .and_then(|r| r.p50_us())
            .map(|us| Duration::from_micros(u64::from(us)))
    }

    /// Sample count for `peer` — diagnostics / fraud-detector gating.
    pub fn sample_count(&self, peer: &PeerId) -> usize {
        self.peers.get(peer).map(RollingP95::len).unwrap_or(0)
    }

    /// Number of peers currently tracked.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Snapshot — `(peer_id, median_rtt)` for every peer with ≥1 sample.
    /// Allocates; not hot-path. Used by `/status`, diagnostics, fraud detector
    /// batch pass.
    pub fn snapshot(&self) -> Vec<(PeerId, Duration)> {
        self.peers
            .iter()
            .filter_map(|(p, r)| {
                r.p50_us()
                    .map(|us| (p.clone(), Duration::from_micros(u64::from(us))))
            })
            .collect()
    }

    /// Maximum sample value honored by the underlying ring — exposed so
    /// geo-fraud callers can short-circuit on clamped samples (peer is
    /// flaky, not far).
    pub const fn max_sample_us() -> u32 {
        MAX_SAMPLE_US
    }

    fn evict_oldest(&mut self) {
        // Evict peer with greatest wrapped distance from current tick.
        let current = self.tick;
        let oldest = self
            .peers
            .iter()
            .max_by_key(|(_, r)| current.wrapping_sub(r.last_update()))
            .map(|(p, _)| p.clone());
        if let Some(p) = oldest {
            self.peers.remove(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    fn p(s: &str) -> PeerId {
        PeerId::new(s)
    }

    #[test]
    fn empty_returns_none() {
        let est = PeerRttEstimator::new();
        assert!(est.median(&p("a")).is_none());
        assert_eq!(est.sample_count(&p("a")), 0);
        assert_eq!(est.peer_count(), 0);
    }

    #[test]
    fn single_sample_is_median() {
        let mut est = PeerRttEstimator::new();
        est.observe(&p("peer1"), us(5_000));
        assert_eq!(est.median(&p("peer1")), Some(us(5_000)));
        assert_eq!(est.sample_count(&p("peer1")), 1);
    }

    #[test]
    fn median_stable_under_single_outlier() {
        // 63 samples at 1ms + 1 outlier at 10s → median MUST stay near 1ms.
        let mut est = PeerRttEstimator::new();
        let peer = p("helsinki");
        for _ in 0..63 {
            est.observe(&peer, us(1_000));
        }
        est.observe(&peer, us(10_000_000));
        let med = est.median(&peer).unwrap();
        assert_eq!(med, us(1_000), "outlier must not shift median");
    }

    #[test]
    fn tracks_multiple_peers_independently() {
        let mut est = PeerRttEstimator::new();
        for _ in 0..10 {
            est.observe(&p("close"), us(500));
            est.observe(&p("far"), us(80_000));
        }
        assert_eq!(est.median(&p("close")), Some(us(500)));
        assert_eq!(est.median(&p("far")), Some(us(80_000)));
        assert_eq!(est.peer_count(), 2);
    }

    #[test]
    fn snapshot_excludes_empty() {
        let est = PeerRttEstimator::new();
        assert!(est.snapshot().is_empty());
    }

    #[test]
    fn snapshot_returns_all_peers_with_samples() {
        let mut est = PeerRttEstimator::new();
        for i in 0..5u64 {
            est.observe(&p(&format!("peer{i}")), us((i + 1) * 1_000));
        }
        let snap = est.snapshot();
        assert_eq!(snap.len(), 5);
    }

    /// Metric-semantics codification for the
    /// `elara_peer_rtt_peers_tracked` gauge. The gauge value MUST equal
    /// the number of distinct peers that have observed at least one
    /// sample — never the sample count, never zero when samples exist.
    /// Operators rely on:
    ///   * gauge == 0 AND `elara_peer_rtt_samples_total > 0` =>
    ///     LRU eviction wave wiped the working set (peer churn faster
    ///     than retention).
    ///   * gauge climbing toward MAX_PEERS => estimator near cap;
    ///     fraud-detector coverage starts dropping the least-recently-
    ///     active peers.
    ///   * gauge stable + samples_total climbing => healthy steady state.
    #[test]
    fn ops_42_peer_count_pins_distinct_key_residency_for_gauge() {
        let mut est = PeerRttEstimator::new();
        assert_eq!(est.peer_count(), 0, "fresh estimator has no tracked peers");

        // Re-observing the same peer 5× must NOT inflate the residency count
        // — operators dashboard distinguishes "5 samples on 1 peer" (concentrated)
        // from "1 sample on each of 5 peers" (spread).
        for _ in 0..5 {
            est.observe(&p("peer-A"), us(500));
        }
        assert_eq!(est.peer_count(), 1,
            "5 observations on one peer = 1 tracked peer (gauge counts distinct keys, not events)");

        // Fan out to additional peers.
        for n in 1..=4u64 {
            est.observe(&p(&format!("peer-{n}")), us(500 + n));
        }
        assert_eq!(est.peer_count(), 5,
            "after 5 distinct keys observed at least once, gauge == 5");

        // Re-observing existing peers preserves count exactly.
        for _ in 0..10 {
            est.observe(&p("peer-A"), us(700));
            est.observe(&p("peer-2"), us(800));
        }
        assert_eq!(est.peer_count(), 5,
            "re-observation never grows OR shrinks the count");
    }

    #[test]
    fn evicts_oldest_at_max_peers() {
        let mut est = PeerRttEstimator::new();
        // Fill to MAX_PEERS with distinct peer ids.
        for i in 0..MAX_PEERS as u64 {
            est.observe(&p(&format!("peer{i}")), us(100));
        }
        assert_eq!(est.peer_count(), MAX_PEERS);

        // Touch peer0 → most recently updated.
        est.observe(&p("peer0"), us(100));

        // Add a brand new peer → oldest (peer1) must be evicted; peer0 survives.
        est.observe(&p("new"), us(100));
        assert_eq!(est.peer_count(), MAX_PEERS);
        assert!(est.median(&p("new")).is_some());
        assert!(est.median(&p("peer0")).is_some(), "recently touched survives");
        assert!(est.median(&p("peer1")).is_none(), "oldest evicted");
    }

    #[test]
    fn sample_clamping_survives_u64_us_conversion() {
        // Feed a Duration near u32::MAX µs — must clamp to MAX_SAMPLE_US (30s)
        // rather than wrap or panic. Underlying RollingP95 clamp is the source
        // of truth; this test just proves the wrapper surface honors it.
        let mut est = PeerRttEstimator::new();
        est.observe(&p("weird"), Duration::from_secs(3600)); // 1h
        let med = est.median(&p("weird")).unwrap();
        assert!(
            med <= Duration::from_micros(u64::from(MAX_SAMPLE_US)),
            "clamped to ≤ 30s, got {med:?}"
        );
    }

    #[test]
    fn ring_wraps_past_64_samples() {
        // 128 samples, second half at 50ms — median must reflect the newer
        // values because the ring only holds 64.
        let mut est = PeerRttEstimator::new();
        let peer = p("churn");
        for _ in 0..64 {
            est.observe(&peer, us(1_000));
        }
        for _ in 0..64 {
            est.observe(&peer, us(50_000));
        }
        assert_eq!(est.median(&peer), Some(us(50_000)));
        assert_eq!(est.sample_count(&peer), 64);
    }

    #[test]
    fn max_sample_us_surface_matches_underlying() {
        assert_eq!(PeerRttEstimator::max_sample_us(), MAX_SAMPLE_US);
    }

    // --- Public-surface tests ---
    //
    // Five orthogonal axes around the public surface — pin invariants that the
    // existing higher-level tests assume but do not directly assert:
    //   1. MAX_PEERS literal value (phone-tier memory ceiling).
    //   2. PeerId eq/hash semantics — same string keys collapse, distinct strings stay distinct.
    //   3. PeerId constructor covers Into<String> for both &str and String + as_str round-trip.
    //   4. Default::default() and ::new() both yield zero-state across the full surface.
    //   5. sample_count saturates at RING_SIZE=64 — wrapper surface honors the ring cap.

    #[test]
    fn batch_b_max_peers_literal_pin_10000() {
        // Pin: phone-tier memory ceiling = MAX_PEERS * ~264 B ≈ 2.6 MB.
        // Bumping silently breaks the phone-tier hardware floor (see internal design notes
        // mainnet mandate). Any future change must be intentional + audited.
        assert_eq!(MAX_PEERS, 10_000);
    }

    #[test]
    fn batch_b_peer_id_eq_hash_string_equality_collapses_keys() {
        use std::collections::HashMap;
        // Two PeerId values built from the same string MUST compare equal AND
        // hash to the same bucket — otherwise the LRU eviction + observe()
        // re-entry path inserts duplicates and the residency gauge double-counts.
        let a = p("identity-hex");
        let b = PeerId::new(String::from("identity-hex"));
        assert_eq!(a, b);
        let mut map: HashMap<PeerId, u32> = HashMap::new();
        map.insert(a.clone(), 1);
        map.insert(b.clone(), 2);
        assert_eq!(map.len(), 1, "same-string PeerId must hash + eq into one slot");
        assert_eq!(map.get(&a), Some(&2), "second insert overwrote, proving hash collapse");

        // Distinct strings must not collide.
        assert_ne!(p("id-1"), p("id-2"));
    }

    #[test]
    fn batch_b_peer_id_ctor_accepts_str_and_string_with_as_str_roundtrip() {
        // Both Into<String> sources are valid — &str AND owned String.
        // as_str round-trips bytes exactly (no normalization / trim).
        let from_str: PeerId = PeerId::new("alpha");
        let from_string: PeerId = PeerId::new(String::from("alpha"));
        assert_eq!(from_str, from_string);
        assert_eq!(from_str.as_str(), "alpha");
        assert_eq!(from_string.as_str(), "alpha");

        // Whitespace + casing are PRESERVED (not normalized) — geo-fraud
        // detector keys must be byte-exact against the attestation layer.
        let raw = "  Mixed-Case-ID  ";
        let pid = PeerId::new(raw);
        assert_eq!(pid.as_str(), raw, "no normalization: hex/case/whitespace untouched");
    }

    #[test]
    fn batch_b_default_equals_new_zero_state_full_surface() {
        // Default derive must agree with ::new() across the whole reader surface.
        // Catches a future field addition that derive-defaults but new() forgets,
        // or vice-versa.
        let a = PeerRttEstimator::new();
        let b = PeerRttEstimator::default();
        assert_eq!(a.peer_count(), 0);
        assert_eq!(b.peer_count(), 0);
        assert!(a.median(&p("anyone")).is_none());
        assert!(b.median(&p("anyone")).is_none());
        assert_eq!(a.sample_count(&p("anyone")), 0);
        assert_eq!(b.sample_count(&p("anyone")), 0);
        assert!(a.snapshot().is_empty());
        assert!(b.snapshot().is_empty());
    }

    #[test]
    fn batch_b_sample_count_saturates_at_ring_cap_64() {
        // RollingP95 ring holds 64 slots; sample_count() exposes that residency
        // through the wrapper. 100 observations on the same peer MUST report
        // sample_count == 64 (not 100). Pins the surface against a future
        // refactor that exposes total-observations-ever instead of ring length.
        let mut est = PeerRttEstimator::new();
        let peer = p("churn-loop");
        for _ in 0..100 {
            est.observe(&peer, us(1_000));
        }
        assert_eq!(
            est.sample_count(&peer),
            64,
            "sample_count is ring residency, capped at RING_SIZE=64"
        );
        // peer_count is unrelated to sample_count — 1 peer, 64 sample slots.
        assert_eq!(est.peer_count(), 1);
    }
}
