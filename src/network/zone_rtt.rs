//! Per-zone RTT estimator — rolling p95 of gossip round-trip times.
//!
//! Used by the MESH-BFT aggregator chain (Stage 3) to size per-rank
//! timeouts: `base_timeout = max(2 * p95_rtt, 5s)`. Integer-only; no
//! allocations in the hot path beyond the fixed 64-slot ring per zone.
//!
//! # Scale
//! - Per-zone memory: 64 * 4 bytes (u32 microseconds) + 2 * u8 (head / len) = 258 bytes.
//! - Capped at `MAX_ZONES` active zones. When full, the least-recently-updated
//!   zone is evicted. This keeps total memory bounded at ~16 KB regardless of
//!   how many zones the node transiently observes.
//!
//! # Sampling policy
//! Only observe **successful** round-trips (push OK, pull OK with bytes).
//! Connection-refused, timeout, and 429s are connectivity signals, not RTT.
//! Clamp samples to `[1 µs, MAX_SAMPLE_US]` so a single stuck peer cannot poison
//! the p95.
//!
//! # Spec
//! @spec Protocol §11.13 (aggregator chain — RTT-aware timeouts)

use std::collections::HashMap;
use std::time::Duration;

use super::zone::ZoneId;

/// Maximum active zones tracked at once. Beyond this, least-recently-updated
/// entries are evicted. 256 matches the legacy hash-byte zone space and is
/// more than enough for all realistic fleet topologies (today: ~4 zones on
/// testnet; at 10K nodes, zone count scales with network size but each node
/// only witnesses a small slice).
pub const MAX_ZONES: usize = 256;

/// Ring buffer size — matches Stage 3 design spec (last 64 samples per zone).
pub const RING_SIZE: usize = 64;

/// Hard ceiling on a single sample. 30 seconds is already 10x the worst
/// healthy inter-continent RTT; anything above that is a stuck connection,
/// not a representative RTT. Clamping prevents one pathological peer from
/// pulling the p95 into uselessness.
pub const MAX_SAMPLE_US: u32 = 30_000_000;

/// Fixed-size ring of microsecond RTT samples. O(1) insert, O(RING_SIZE log RING_SIZE)
/// percentile computation (rare, only when a proposer checks its backoff).
#[derive(Debug, Clone)]
pub struct RollingP95 {
    /// Ring buffer. Zero means "slot unfilled" — never a real sample because
    /// we clamp to min 1 µs on insert.
    samples: [u32; RING_SIZE],
    /// Next write position (wraps at RING_SIZE).
    head: u16,
    /// Number of valid samples (saturates at RING_SIZE).
    len: u16,
    /// Monotonic update counter — used for LRU eviction in `ZoneRttEstimator`.
    /// Wraps on overflow; eviction compares wrapped-distance which is safe
    /// so long as we evict long before a full u64 cycle (effectively never).
    last_update: u64,
}

impl RollingP95 {
    pub const fn new() -> Self {
        Self {
            samples: [0; RING_SIZE],
            head: 0,
            len: 0,
            last_update: 0,
        }
    }

    /// Record an RTT sample. Clamps to `[1 µs, MAX_SAMPLE_US]`.
    pub fn observe_us(&mut self, mut us: u32, now_counter: u64) {
        if us == 0 {
            us = 1;
        }
        if us > MAX_SAMPLE_US {
            us = MAX_SAMPLE_US;
        }
        self.samples[self.head as usize] = us;
        self.head = (self.head + 1) % (RING_SIZE as u16);
        if (self.len as usize) < RING_SIZE {
            self.len += 1;
        }
        self.last_update = now_counter;
    }

    /// Record an RTT sample from a `Duration`.
    pub fn observe(&mut self, d: Duration, now_counter: u64) {
        let us = d.as_micros().min(u128::from(u32::MAX)) as u32;
        self.observe_us(us, now_counter);
    }

    /// Number of samples currently held.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// p95 of the samples currently in the ring, or `None` if empty.
    ///
    /// Uses partial sort of a stack copy — no heap allocation. At RING_SIZE=64
    /// this is ~256 bytes on the stack and takes microseconds.
    pub fn p95_us(&self) -> Option<u32> {
        self.percentile_us(95)
    }

    /// p50 (median) — useful for diagnostics only; timeouts use p95.
    pub fn p50_us(&self) -> Option<u32> {
        self.percentile_us(50)
    }

    /// Arbitrary percentile in [0, 100]. Returns `None` if no samples.
    pub fn percentile_us(&self, percentile: u32) -> Option<u32> {
        let n = self.len as usize;
        if n == 0 {
            return None;
        }
        let mut buf = [0u32; RING_SIZE];
        buf[..n].copy_from_slice(&self.samples[..n]);
        buf[..n].sort_unstable();
        // nearest-rank method: index = ceil(p/100 * n) - 1, clamped
        let p = percentile.min(100) as usize;
        let idx = if p == 0 {
            0
        } else {
            // ceil(p * n / 100) - 1, guaranteed in [0, n-1]
            let num = p * n;
            let raw = num.div_ceil(100);
            raw.saturating_sub(1).min(n - 1)
        };
        Some(buf[idx])
    }

    /// p95 as a `Duration`.
    pub fn p95(&self) -> Option<Duration> {
        self.p95_us().map(|us| Duration::from_micros(u64::from(us)))
    }

    /// Monotonic last-update tick — used by bounded-map wrappers
    /// (`ZoneRttEstimator`, `PeerRttEstimator`) to pick the LRU entry.
    pub fn last_update(&self) -> u64 {
        self.last_update
    }
}

impl Default for RollingP95 {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded map of `ZoneId -> RollingP95` with LRU eviction at `MAX_ZONES`.
#[derive(Debug, Default)]
pub struct ZoneRttEstimator {
    zones: HashMap<ZoneId, RollingP95>,
    /// Monotonic counter used as a pseudo-clock for LRU eviction.
    tick: u64,
}

impl ZoneRttEstimator {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            tick: 0,
        }
    }

    /// Record an RTT observation for `zone`. O(1) amortized; O(MAX_ZONES)
    /// only on the eviction step, which is rare.
    pub fn observe(&mut self, zone: &ZoneId, rtt: Duration) {
        self.tick = self.tick.wrapping_add(1);
        let now = self.tick;

        if !self.zones.contains_key(zone) && self.zones.len() >= MAX_ZONES {
            self.evict_oldest();
        }

        self.zones
            .entry(zone.clone())
            .or_default()
            .observe(rtt, now);
    }

    /// p95 RTT for `zone`, or `None` if no samples yet.
    pub fn p95(&self, zone: &ZoneId) -> Option<Duration> {
        self.zones.get(zone).and_then(RollingP95::p95)
    }

    /// Sample count for `zone` (for diagnostics / testing).
    pub fn sample_count(&self, zone: &ZoneId) -> usize {
        self.zones.get(zone).map(RollingP95::len).unwrap_or(0)
    }

    /// Number of zones currently tracked.
    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    /// Snapshot view: (zone, p95) for every zone with at least one sample.
    /// Used by the `/status` endpoint and diagnostics. Allocates — not hot-path.
    pub fn snapshot(&self) -> Vec<(ZoneId, Duration)> {
        self.zones
            .iter()
            .filter_map(|(z, r)| r.p95().map(|d| (z.clone(), d)))
            .collect()
    }

    fn evict_oldest(&mut self) {
        // Evict the zone with the greatest wrapped distance from `self.tick`
        // — i.e. the one not touched for the longest stretch.
        // Wrapped subtraction is safe across u64 overflow; in practice we
        // never approach 2^64 ticks.
        let current = self.tick;
        let oldest = self
            .zones
            .iter()
            .max_by_key(|(_, r)| current.wrapping_sub(r.last_update))
            .map(|(z, _)| z.clone());
        if let Some(z) = oldest {
            self.zones.remove(&z);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn us(n: u32) -> Duration {
        Duration::from_micros(u64::from(n))
    }

    #[test]
    fn rolling_empty_returns_none() {
        let r = RollingP95::new();
        assert!(r.p95().is_none());
        assert!(r.p50_us().is_none());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn rolling_single_sample_is_p95() {
        let mut r = RollingP95::new();
        r.observe(us(1_000), 1);
        assert_eq!(r.p95(), Some(us(1_000)));
    }

    #[test]
    fn rolling_p95_nearest_rank() {
        // 100 samples 1..=100 us. p95 should be 95 us (nearest-rank).
        let mut r = RollingP95::new();
        for i in 1..=RING_SIZE as u32 {
            r.observe_us(i, u64::from(i));
        }
        // With exactly 64 samples, p95 index = ceil(95*64/100)-1 = ceil(60.8)-1 = 60.
        // sorted[60] = 61.
        assert_eq!(r.p95_us(), Some(61));
        assert_eq!(r.p50_us(), Some(32)); // ceil(50*64/100)-1 = 31 → sorted[31] = 32
    }

    #[test]
    fn rolling_ring_evicts_oldest() {
        let mut r = RollingP95::new();
        // Fill ring with 1s
        for i in 0..RING_SIZE {
            r.observe_us(1, i as u64);
        }
        assert_eq!(r.p95_us(), Some(1));
        // Now push 64 samples of 1000. Old 1s should be evicted.
        for i in 0..RING_SIZE {
            r.observe_us(1_000, (RING_SIZE + i) as u64);
        }
        assert_eq!(r.p95_us(), Some(1_000));
        assert_eq!(r.len(), RING_SIZE);
    }

    #[test]
    fn rolling_clamps_zero_and_overflow() {
        let mut r = RollingP95::new();
        r.observe_us(0, 1); // becomes 1
        r.observe_us(u32::MAX, 2); // clamped to MAX_SAMPLE_US
        assert_eq!(r.p95_us(), Some(MAX_SAMPLE_US));
        assert_eq!(r.p50_us(), Some(1));
    }

    #[test]
    fn estimator_returns_none_for_unknown_zone() {
        let est = ZoneRttEstimator::new();
        assert!(est.p95(&ZoneId::from_legacy(0)).is_none());
    }

    #[test]
    fn estimator_tracks_per_zone() {
        let mut est = ZoneRttEstimator::new();
        let z0 = ZoneId::from_legacy(0);
        let z1 = ZoneId::from_legacy(1);
        for _ in 0..10 {
            est.observe(&z0, us(500));
            est.observe(&z1, us(5_000));
        }
        assert_eq!(est.p95(&z0), Some(us(500)));
        assert_eq!(est.p95(&z1), Some(us(5_000)));
        assert_eq!(est.zone_count(), 2);
        assert_eq!(est.sample_count(&z0), 10);
    }

    #[test]
    fn estimator_evicts_at_max_zones() {
        let mut est = ZoneRttEstimator::new();
        // Fill to MAX_ZONES, each with a distinct sample value.
        for i in 0..MAX_ZONES as u64 {
            est.observe(&ZoneId::from_legacy(i), us(100));
        }
        assert_eq!(est.zone_count(), MAX_ZONES);
        // Touch zone 0 to make it the most recently updated.
        est.observe(&ZoneId::from_legacy(0), us(100));
        // Add one more zone — oldest (zone 1) should be evicted.
        let new_zone = ZoneId::from_legacy(999);
        est.observe(&new_zone, us(100));
        assert_eq!(est.zone_count(), MAX_ZONES);
        assert!(est.p95(&new_zone).is_some());
        assert!(est.p95(&ZoneId::from_legacy(0)).is_some(), "recently touched zone must survive");
        assert!(est.p95(&ZoneId::from_legacy(1)).is_none(), "oldest zone must be evicted");
    }

    #[test]
    fn estimator_snapshot_excludes_empty() {
        let est = ZoneRttEstimator::new();
        assert!(est.snapshot().is_empty());
    }

    #[test]
    fn estimator_snapshot_returns_all_with_samples() {
        let mut est = ZoneRttEstimator::new();
        for i in 0..5u64 {
            est.observe(&ZoneId::from_legacy(i), us((i + 1) as u32 * 1_000));
        }
        let snap = est.snapshot();
        assert_eq!(snap.len(), 5);
    }

    #[test]
    fn p95_rejects_single_outlier_with_enough_samples() {
        // Production-lens test: with 63 samples of 1ms and 1 outlier of 10s,
        // p95 must NOT jump to the outlier value — it should remain near 1ms.
        // With 64 samples, p95 index = 60, so 60 of the 63 1ms values sort
        // into index 60. The outlier sits at index 63.
        let mut r = RollingP95::new();
        for i in 0..63 {
            r.observe_us(1_000, i as u64);
        }
        r.observe_us(10_000_000, 63);
        let p95 = r.p95_us().unwrap();
        assert_eq!(p95, 1_000, "single outlier must not contaminate p95");
    }

    #[test]
    fn p95_tracks_tail_when_tail_is_real() {
        // If 10% of samples are slow, p95 should reflect the tail.
        let mut r = RollingP95::new();
        for i in 0..58 {
            r.observe_us(1_000, i as u64);
        }
        for i in 58..64 {
            r.observe_us(50_000, i as u64);
        }
        // 6/64 ≈ 9.4% tail. p95 index = 60 → sorted[60] = 50_000.
        assert_eq!(r.p95_us(), Some(50_000));
    }

    // ─── constants + RollingP95 / percentile / LRU tests ──────────────────
    // Pins surface invariants not covered by the legacy tests above:
    //  (1) 3 module constants strict-pin + memory-budget + type pins
    //  (2) RollingP95 initial state + observe_us clamp boundary matrix
    //  (3) percentile_us nearest-rank formula matrix + p95/p50 aliasing + Duration conversion
    //  (4) Ring buffer wraparound + sliding-window eviction + last_update monotonic
    //  (5) ZoneRttEstimator LRU eviction semantics + tick wrapping_add monotonic

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_zone_rtt_constants_strict_pin_and_memory_budget() {
        // 3 module constants. Any drift changes the memory floor or
        // the timeout-sizing semantics on every gossip path.
        assert_eq!(MAX_ZONES, 256usize,
            "MAX_ZONES=256 (== 2^8, legacy hash-byte zone space)");
        assert_eq!(RING_SIZE, 64usize,
            "RING_SIZE=64 — Stage 3 design spec (last 64 samples per zone)");
        assert_eq!(MAX_SAMPLE_US, 30_000_000u32,
            "MAX_SAMPLE_US=30_000_000 (30 seconds in microseconds)");
        assert_eq!(MAX_SAMPLE_US, 30 * 1_000_000,
            "MAX_SAMPLE_US arithmetic form == 30 seconds * 1_000_000 us/s");
        assert_eq!(u64::from(MAX_SAMPLE_US) / 1_000_000, 30,
            "MAX_SAMPLE_US in seconds = 30");

        // Type pins.
        let _z: usize = MAX_ZONES;
        let _r: usize = RING_SIZE;
        let _s: u32 = MAX_SAMPLE_US;

        // Cross-relations: positives.
        assert!(MAX_ZONES > 0, "0 zones would brick all per-zone tracking");
        assert!(RING_SIZE > 0, "0-slot ring would crash percentile_us on empty buf");
        assert!(MAX_SAMPLE_US > 0, "0-sample clamp would erase all RTT data");

        // RING_SIZE is a power of two — load-bearing for cheap modulo
        // arithmetic (though current code uses `% (RING_SIZE as u16)`).
        assert!(RING_SIZE.is_power_of_two(),
            "RING_SIZE must be a power of two");
        // RING_SIZE fits in u16 (head/len are u16).
        assert!(RING_SIZE <= u16::MAX as usize,
            "RING_SIZE must fit in u16 (head/len bounds)");

        // Per-RollingP95 memory: RING_SIZE * 4 bytes (u32) + 2*u16 + u64.
        // Documented as 258 bytes in module doc — pin numerically.
        let per_zone_samples_bytes = RING_SIZE * std::mem::size_of::<u32>();
        assert_eq!(per_zone_samples_bytes, 256,
            "RingP95 sample-buf footprint = 64 * 4 = 256 bytes");

        // MAX_ZONES * RING_SIZE * 4 bytes = 65_536 bytes = 64 KB total
        // sample storage at saturation. Module doc claims "~16 KB" but that
        // appears to be a stale figure — pin the actual computation.
        let total_sample_storage = MAX_ZONES * per_zone_samples_bytes;
        assert_eq!(total_sample_storage, 65_536,
            "Total sample storage at MAX_ZONES saturation = 64 KB");

        // MAX_ZONES > RING_SIZE — more zones can be tracked than samples
        // per zone (load-bearing for typical 4-zone testnet × 64 samples).
        assert!(MAX_ZONES > RING_SIZE,
            "MAX_ZONES > RING_SIZE — more zones than samples-per-zone");
    }

    #[test]
    fn batch_b_rolling_p95_initial_state_and_observe_us_clamp_boundary_matrix() {
        // new() initial state — all fields zero.
        let r = RollingP95::new();
        assert_eq!(r.len(), 0,
            "new() RollingP95 has 0 samples");
        assert!(r.is_empty(),
            "is_empty()==true on new()");
        assert_eq!(r.last_update(), 0,
            "last_update starts at 0");
        assert!(r.p95_us().is_none());
        assert!(r.p50_us().is_none());
        assert!(r.p95().is_none());
        assert!(r.percentile_us(50).is_none());
        assert!(r.percentile_us(0).is_none());
        assert!(r.percentile_us(100).is_none());

        // Default::default() == new().
        let d = RollingP95::default();
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
        assert_eq!(d.last_update(), 0);

        // observe_us(0, _) -> clamped UP to 1 (per source line 72).
        let mut r = RollingP95::new();
        r.observe_us(0, 42);
        assert_eq!(r.len(), 1);
        assert_eq!(r.last_update(), 42,
            "observe_us records the now_counter as last_update");
        assert_eq!(r.p95_us(), Some(1),
            "observe_us(0) clamps to 1 (zero is reserved as 'unfilled' sentinel)");

        // observe_us(1, _) — exact lower bound passes through unchanged.
        let mut r = RollingP95::new();
        r.observe_us(1, 100);
        assert_eq!(r.p95_us(), Some(1));
        assert_eq!(r.last_update(), 100);

        // observe_us(MAX_SAMPLE_US, _) — exact upper bound passes through.
        let mut r = RollingP95::new();
        r.observe_us(MAX_SAMPLE_US, 1);
        assert_eq!(r.p95_us(), Some(MAX_SAMPLE_US),
            "MAX_SAMPLE_US at exact boundary passes through unchanged");

        // observe_us(MAX_SAMPLE_US + 1, _) — clamped DOWN to MAX_SAMPLE_US.
        let mut r = RollingP95::new();
        r.observe_us(MAX_SAMPLE_US + 1, 1);
        assert_eq!(r.p95_us(), Some(MAX_SAMPLE_US),
            "MAX_SAMPLE_US + 1 clamps to MAX_SAMPLE_US");

        // observe_us(u32::MAX, _) — clamped DOWN to MAX_SAMPLE_US.
        let mut r = RollingP95::new();
        r.observe_us(u32::MAX, 1);
        assert_eq!(r.p95_us(), Some(MAX_SAMPLE_US),
            "u32::MAX clamps to MAX_SAMPLE_US (no overflow)");

        // observe(Duration) overflow protection: huge Duration -> u32::MAX
        // first, then clamps to MAX_SAMPLE_US per observe_us gate.
        let mut r = RollingP95::new();
        // 1 hour = 3600s = 3_600_000_000 us > u32::MAX (4_294_967_295)
        // Actually 3.6e9 < 4.29e9 so it fits. Use 2 hours to overflow.
        r.observe(Duration::from_secs(7200), 1);
        assert_eq!(r.p95_us(), Some(MAX_SAMPLE_US),
            "huge Duration clamps via u128.min(u32::MAX) cast then MAX_SAMPLE_US gate");

        // last_update updated on each observe (last writer wins).
        let mut r = RollingP95::new();
        r.observe_us(100, 1);
        assert_eq!(r.last_update(), 1);
        r.observe_us(200, 5);
        assert_eq!(r.last_update(), 5);
        r.observe_us(300, 3); // earlier tick — still recorded as new last_update
        assert_eq!(r.last_update(), 3,
            "observe_us unconditionally overwrites last_update (no monotonic check)");

        // is_empty / len transition on first sample.
        let mut r = RollingP95::new();
        assert!(r.is_empty());
        r.observe_us(50, 1);
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn batch_b_percentile_nearest_rank_formula_matrix_and_aliasing() {
        // percentile_us implements nearest-rank: idx = ceil(p*n/100) - 1
        // clamped to [0, n-1]. Pins formula across n and p values.

        // Empty -> None for every percentile.
        let r = RollingP95::new();
        for p in [0u32, 1, 50, 95, 100, 200] {
            assert!(r.percentile_us(p).is_none(),
                "empty.percentile_us({p}) == None");
        }

        // Single sample -> every percentile returns that sample.
        let mut r = RollingP95::new();
        r.observe_us(42, 1);
        for p in [0u32, 1, 50, 95, 100, 200] {
            assert_eq!(r.percentile_us(p), Some(42),
                "single sample: percentile_us({p}) == Some(42)");
        }

        // Percentile > 100 clamps to 100 (per .min(100)).
        let mut r = RollingP95::new();
        for v in 1..=10u32 {
            r.observe_us(v, u64::from(v));
        }
        assert_eq!(r.percentile_us(200), r.percentile_us(100),
            "percentile > 100 clamps to 100");
        assert_eq!(r.percentile_us(u32::MAX), r.percentile_us(100),
            "percentile == u32::MAX clamps to 100");

        // Percentile 0 -> sorted[0] (smallest).
        // For samples 1..=10, sorted[0] = 1.
        assert_eq!(r.percentile_us(0), Some(1),
            "percentile 0 returns smallest sample");

        // Percentile 100 -> sorted[n-1] (largest).
        assert_eq!(r.percentile_us(100), Some(10),
            "percentile 100 returns largest sample");

        // Percentile 50 with n=10: idx = ceil(500/100) - 1 = 5 - 1 = 4.
        // sorted = [1,2,3,4,5,6,7,8,9,10]; sorted[4] = 5.
        assert_eq!(r.percentile_us(50), Some(5),
            "percentile 50 of 1..=10 nearest-rank == 5");

        // Percentile 95 with n=10: idx = ceil(950/100) - 1 = 10 - 1 = 9.
        // sorted[9] = 10.
        assert_eq!(r.percentile_us(95), Some(10),
            "percentile 95 of 1..=10 nearest-rank == 10");

        // p95_us() == percentile_us(95) — aliasing pin.
        assert_eq!(r.p95_us(), r.percentile_us(95));

        // p50_us() == percentile_us(50) — aliasing pin.
        assert_eq!(r.p50_us(), r.percentile_us(50));

        // p95() returns Duration from p95_us() value.
        // p95_us = 10 us -> Duration::from_micros(10).
        assert_eq!(r.p95(), Some(Duration::from_micros(10)));

        // Percentile invariants over a known dataset:
        // [10, 20, 30, ..., 100] — sorted, n=10.
        let mut r = RollingP95::new();
        for v in 1..=10u32 {
            r.observe_us(v * 10, u64::from(v));
        }
        // p25: idx = ceil(250/100)-1 = 3-1 = 2; sorted[2] = 30.
        assert_eq!(r.percentile_us(25), Some(30),
            "p25 of [10..=100 step 10] == 30");
        // p75: idx = ceil(750/100)-1 = 8-1 = 7; sorted[7] = 80.
        assert_eq!(r.percentile_us(75), Some(80),
            "p75 of [10..=100 step 10] == 80");
        // p99: idx = ceil(990/100)-1 = 10-1 = 9; sorted[9] = 100.
        assert_eq!(r.percentile_us(99), Some(100),
            "p99 of [10..=100 step 10] == 100");

        // Duration conversion is microseconds (not millis, not seconds).
        let mut r = RollingP95::new();
        r.observe_us(1_000_000, 1); // 1 second in microseconds
        assert_eq!(r.p95(), Some(Duration::from_secs(1)),
            "p95() converts microseconds -> Duration::from_micros");
    }

    #[test]
    fn batch_b_ring_buffer_wraparound_sliding_window_and_last_update_monotonic() {
        // The ring buffer is fixed-size; after RING_SIZE writes the
        // oldest sample is evicted on the next write. Pins the sliding
        // window invariant + the head wraparound.

        // Fill ring with N values where N == RING_SIZE.
        let mut r = RollingP95::new();
        for i in 0..RING_SIZE {
            r.observe_us((i + 1) as u32, i as u64);
        }
        assert_eq!(r.len(), RING_SIZE,
            "len() saturates at RING_SIZE after RING_SIZE writes");

        // Write one more — len() must NOT exceed RING_SIZE.
        r.observe_us(999, 999);
        assert_eq!(r.len(), RING_SIZE,
            "len() does NOT grow past RING_SIZE on additional writes");

        // After RING_SIZE+1 writes, oldest sample (value 1) is GONE.
        // The lowest remaining value is 2 (since 1 was overwritten).
        assert_eq!(r.percentile_us(0), Some(2),
            "after wraparound, smallest sample is 2 (1 was overwritten)");

        // Sliding-window pin: fully replace all samples with new values.
        let mut r = RollingP95::new();
        for i in 0..RING_SIZE {
            r.observe_us(10, i as u64);
        }
        assert_eq!(r.percentile_us(100), Some(10),
            "initial fill: max sample = 10");
        // Now overwrite all 64 slots with 999.
        for i in 0..RING_SIZE {
            r.observe_us(999, (RING_SIZE + i) as u64);
        }
        assert_eq!(r.percentile_us(0), Some(999),
            "after full sliding-window replacement, smallest == 999 (all 10s evicted)");
        assert_eq!(r.percentile_us(100), Some(999),
            "max also == 999");
        assert_eq!(r.len(), RING_SIZE,
            "len stays at RING_SIZE");

        // last_update is recorded as-given (no monotonic enforcement).
        // observe_us with a non-monotonic now_counter still records that
        // value as last_update — pinning the documented behavior.
        let mut r = RollingP95::new();
        r.observe_us(1, 100);
        r.observe_us(2, 50);  // backwards in time
        assert_eq!(r.last_update(), 50,
            "last_update follows observe_us argument verbatim (no max enforcement)");

        // Going forward in time is the normal pattern.
        let mut r = RollingP95::new();
        for i in 0..10u64 {
            r.observe_us(100, i);
        }
        assert_eq!(r.last_update(), 9,
            "last_update tracks the most recent observe_us now_counter argument");
    }

    #[test]
    fn batch_b_estimator_lru_eviction_tick_monotonic_and_per_zone_isolation() {
        // ZoneRttEstimator::new() initial state.
        let est = ZoneRttEstimator::new();
        assert_eq!(est.zone_count(), 0,
            "new() ZoneRttEstimator tracks 0 zones");
        assert!(est.snapshot().is_empty(),
            "new() snapshot is empty");
        assert!(est.p95(&ZoneId::from_legacy(42)).is_none(),
            "p95(unknown zone) -> None");
        assert_eq!(est.sample_count(&ZoneId::from_legacy(42)), 0,
            "sample_count(unknown zone) -> 0");

        // Default::default() (derived) matches new().
        let d = ZoneRttEstimator::default();
        assert_eq!(d.zone_count(), 0);

        // Per-zone isolation: observe on zone A does NOT touch zone B counters.
        let mut est = ZoneRttEstimator::new();
        let za = ZoneId::from_legacy(1);
        let zb = ZoneId::from_legacy(2);
        est.observe(&za, us(1_000));
        est.observe(&za, us(2_000));
        est.observe(&za, us(3_000));
        assert_eq!(est.sample_count(&za), 3);
        assert_eq!(est.sample_count(&zb), 0,
            "zone B unchanged by zone A observes");
        assert!(est.p95(&zb).is_none(),
            "zone B p95 unchanged by zone A observes");
        assert_eq!(est.zone_count(), 1,
            "zone_count() reflects ONLY zones with at least one observe");

        // snapshot only includes zones with samples.
        let snap = est.snapshot();
        assert_eq!(snap.len(), 1,
            "snapshot includes only zones with >=1 sample");
        // observe on zone B grows the snapshot.
        est.observe(&zb, us(500));
        let snap = est.snapshot();
        assert_eq!(snap.len(), 2);

        // LRU eviction: fill to MAX_ZONES with distinct zones, then touch
        // zone A to make it the most recently updated, then add a new zone.
        // Expected: zone A SURVIVES; some other zone is evicted.
        let mut est = ZoneRttEstimator::new();
        for i in 0..MAX_ZONES as u64 {
            est.observe(&ZoneId::from_legacy(i), us(100));
        }
        assert_eq!(est.zone_count(), MAX_ZONES,
            "filled to MAX_ZONES = {MAX_ZONES}");

        // Touch zone 0 -> becomes most-recently-updated.
        est.observe(&ZoneId::from_legacy(0), us(100));
        // Add a NEW zone, beyond MAX_ZONES capacity.
        let new_zone = ZoneId::from_legacy(9999);
        est.observe(&new_zone, us(100));
        assert_eq!(est.zone_count(), MAX_ZONES,
            "zone_count caps at MAX_ZONES");
        assert!(est.p95(&new_zone).is_some(),
            "new zone is admitted");
        assert!(est.p95(&ZoneId::from_legacy(0)).is_some(),
            "recently-touched zone survives eviction");
        // Zone 1 was the oldest (touched only once at the very beginning)
        // — should be evicted.
        assert!(est.p95(&ZoneId::from_legacy(1)).is_none(),
            "oldest zone (zone 1) is evicted at MAX_ZONES saturation");

        // Adding more observes to an existing zone does NOT change zone_count.
        let mut est = ZoneRttEstimator::new();
        for _ in 0..10 {
            est.observe(&ZoneId::from_legacy(5), us(1_000));
        }
        assert_eq!(est.zone_count(), 1,
            "10 observes on same zone -> zone_count still 1");
        assert_eq!(est.sample_count(&ZoneId::from_legacy(5)), 10);

        // observe() on existing zone does NOT trigger eviction path even
        // when at MAX_ZONES — only NEW zones can trigger eviction.
        let mut est = ZoneRttEstimator::new();
        for i in 0..MAX_ZONES as u64 {
            est.observe(&ZoneId::from_legacy(i), us(100));
        }
        assert_eq!(est.zone_count(), MAX_ZONES);
        // Re-observe each zone — no eviction.
        for i in 0..MAX_ZONES as u64 {
            est.observe(&ZoneId::from_legacy(i), us(200));
        }
        assert_eq!(est.zone_count(), MAX_ZONES,
            "re-observing existing zones does NOT trigger eviction");
        // All zones still present.
        for i in 0..MAX_ZONES as u64 {
            assert!(est.p95(&ZoneId::from_legacy(i)).is_some(),
                "zone {i} present after re-observing");
        }
    }
}
