//! Per-peer outbound token-bucket limiter (Stage 6 cooperative scheduler).
//!
//! The global `gossip_semaphore` (16 permits) caps total in-flight HTTP
//! requests, but it doesn't enforce per-peer fairness: one peer that's
//! faster / lower-latency can monopolise all 16 slots, starving others.
//! On mainnet this lets a well-provisioned hub dominate the gossip tree
//! at the expense of small peers (laptops, mobile).
//!
//! Per-peer token bucket:
//!   - `capacity` tokens, refills at `refill_per_sec` tokens/sec
//!   - Each outbound push / attestation / delta-sync request costs 1 token
//!   - If the bucket is empty, the call returns `false` and the caller SKIPS
//!     the push to that peer (sqrt(n) fan-out already tolerates drops)
//!
//! Bounded to [`MAX_PEERS`] with monotonic-tick LRU eviction, matching the
//! existing `peer_rtt::PeerRttEstimator` convention — no new dependency.
//! At 10K peers × ~40 bytes per bucket ≈ 400 KB, fits on a 2 GB node.
//!
//! @spec Protocol §11.10 (user-hardware mandate — fairness under load)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Maximum peers tracked. Matches `peer_rtt::MAX_PEERS` so per-peer
/// structures share the same upper bound on memory footprint.
pub const MAX_PEERS: usize = 10_000;

/// Default bucket capacity per peer (burst tolerance in push-slots).
/// Chosen so that sqrt(n) fan-out at a 100-peer network (≈ 10 pushes/round)
/// fits with burst headroom.
pub const DEFAULT_CAPACITY: f64 = 20.0;

/// Default refill rate (tokens/sec). 10/sec sustained covers hot gossip
/// plus attestations and delta-sync overlap for a single peer.
pub const DEFAULT_REFILL_PER_SEC: f64 = 10.0;

#[derive(Clone, Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    /// Pseudo-clock tick of the most recent access. Used for LRU eviction.
    last_tick: u64,
}

impl TokenBucket {
    fn new(now: Instant, capacity: f64, tick: u64) -> Self {
        Self { tokens: capacity, last_refill: now, last_tick: tick }
    }

    fn refill(&mut self, now: Instant, capacity: f64, refill_per_sec: f64) {
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        if dt <= 0.0 { return; }
        self.tokens = (self.tokens + dt * refill_per_sec).min(capacity);
        self.last_refill = now;
    }

    fn try_take(&mut self, cost: f64) -> bool {
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Per-peer outbound token-bucket limiter with LRU eviction.
pub struct PeerBandwidthLimiter {
    inner: std::sync::Mutex<Inner>,
    capacity: f64,
    refill_per_sec: f64,
    max_peers: usize,
    /// Pushes that WERE rate-limited (skipped) — surfaced in /status.
    pub skipped_total: AtomicU64,
}

struct Inner {
    peers: HashMap<String, TokenBucket>,
    /// Monotonic counter for LRU eviction. Wraps on overflow; safe as long as
    /// we evict long before a full u64 cycle.
    tick: u64,
}

impl PeerBandwidthLimiter {
    pub fn new() -> Self {
        Self::with_params(DEFAULT_CAPACITY, DEFAULT_REFILL_PER_SEC, MAX_PEERS)
    }

    pub fn with_params(capacity: f64, refill_per_sec: f64, max_peers: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(Inner {
                peers: HashMap::new(),
                tick: 0,
            }),
            capacity,
            refill_per_sec,
            max_peers,
            skipped_total: AtomicU64::new(0),
        }
    }

    /// Try to acquire 1 token for `peer_id`. Returns true → caller may
    /// proceed with the outbound push; false → caller must skip.
    pub fn try_acquire(&self, peer_id: &str) -> bool {
        self.try_acquire_cost(peer_id, 1.0)
    }

    /// Try to acquire `cost` tokens. For delta-sync or large batch ops a
    /// caller may charge >1 token per request. Callers without a reason
    /// to customise should use `try_acquire`.
    pub fn try_acquire_cost(&self, peer_id: &str, cost: f64) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.tick = inner.tick.wrapping_add(1);
        let tick = inner.tick;

        // LRU eviction if at cap and peer unknown.
        if !inner.peers.contains_key(peer_id) && inner.peers.len() >= self.max_peers {
            Self::evict_oldest(&mut inner);
        }

        let capacity = self.capacity;
        let refill = self.refill_per_sec;
        let bucket = inner.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket::new(now, capacity, tick));
        bucket.last_tick = tick;
        bucket.refill(now, capacity, refill);
        let ok = bucket.try_take(cost);
        if !ok {
            self.skipped_total.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    fn evict_oldest(inner: &mut Inner) {
        let current = inner.tick;
        let oldest = inner
            .peers
            .iter()
            .max_by_key(|(_, b)| current.wrapping_sub(b.last_tick))
            .map(|(p, _)| p.clone());
        if let Some(p) = oldest {
            inner.peers.remove(&p);
        }
    }

    pub fn tracked_peers(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).peers.len()
    }

    #[cfg(test)]
    pub fn peek_tokens(&self, peer_id: &str) -> Option<f64> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .get(peer_id)
            .map(|b| b.tokens)
    }
}

impl Default for PeerBandwidthLimiter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_gets_full_bucket_minus_cost_on_first_acquire() {
        let lim = PeerBandwidthLimiter::new();
        assert!(lim.try_acquire("peerA"));
        let t = lim.peek_tokens("peerA").unwrap();
        assert!((t - (DEFAULT_CAPACITY - 1.0)).abs() < 0.01, "expected ~19.0, got {t}");
    }

    #[test]
    fn exhausting_bucket_returns_false_and_increments_skipped() {
        let lim = PeerBandwidthLimiter::with_params(3.0, 0.0, 100);
        assert!(lim.try_acquire("peerA"));
        assert!(lim.try_acquire("peerA"));
        assert!(lim.try_acquire("peerA"));
        assert!(!lim.try_acquire("peerA"));
        assert!(!lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn bucket_refills_over_time() {
        let lim = PeerBandwidthLimiter::with_params(2.0, 10.0, 100);
        assert!(lim.try_acquire("peerA"));
        assert!(lim.try_acquire("peerA"));
        assert!(!lim.try_acquire("peerA"));
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(lim.try_acquire("peerA"), "bucket should have refilled");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let lim = PeerBandwidthLimiter::with_params(5.0, 100.0, 100);
        for _ in 0..5 { assert!(lim.try_acquire("peerA")); }
        std::thread::sleep(std::time::Duration::from_millis(500));
        // 50 tokens would have arrived; cap is 5.
        for _ in 0..5 { assert!(lim.try_acquire("peerA")); }
        assert!(!lim.try_acquire("peerA"), "cap enforced");
    }

    #[test]
    fn separate_peers_have_independent_buckets() {
        let lim = PeerBandwidthLimiter::with_params(1.0, 0.0, 100);
        assert!(lim.try_acquire("peerA"));
        assert!(!lim.try_acquire("peerA"));
        assert!(lim.try_acquire("peerB"));
    }

    #[test]
    fn max_peers_enforces_lru_eviction() {
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        lim.try_acquire("peerA");
        lim.try_acquire("peerB");
        lim.try_acquire("peerC");
        assert_eq!(lim.tracked_peers(), 3);
        lim.try_acquire("peerD");
        assert_eq!(lim.tracked_peers(), 3);
        assert!(lim.peek_tokens("peerA").is_none(), "peerA evicted");
        assert!(lim.peek_tokens("peerD").is_some());
    }

    #[test]
    fn accessing_peer_refreshes_lru_position() {
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        lim.try_acquire("peerA");
        lim.try_acquire("peerB");
        lim.try_acquire("peerC");
        // Touch peerA again → peerB becomes LRU.
        lim.try_acquire("peerA");
        lim.try_acquire("peerD");
        assert!(lim.peek_tokens("peerA").is_some(), "peerA refreshed");
        assert!(lim.peek_tokens("peerB").is_none(), "peerB evicted");
    }

    #[test]
    fn cost_greater_than_available_returns_false_without_deduction() {
        let lim = PeerBandwidthLimiter::with_params(3.0, 0.0, 100);
        assert!(!lim.try_acquire_cost("peerA", 5.0));
        let t = lim.peek_tokens("peerA").unwrap();
        assert!((t - 3.0).abs() < 0.01, "tokens unchanged");
    }

    #[test]
    fn tracked_peers_reports_current_size() {
        let lim = PeerBandwidthLimiter::new();
        assert_eq!(lim.tracked_peers(), 0);
        lim.try_acquire("peerA");
        lim.try_acquire("peerB");
        assert_eq!(lim.tracked_peers(), 2);
    }

    // ─── constants + limiter / LRU-eviction tests ────────────────────────
    // Pins surface invariants not covered by the legacy tests above:
    //  (1) 3 module constants strict-pin + cross-relations
    //  (2) new() == Default::default() observable state + with_params field-binding
    //  (3) try_acquire == try_acquire_cost(_, 1.0) alias + cost-arg edge cases
    //  (4) LRU eviction tie-break under MAX_PEERS saturation — exact-victim pin
    //  (5) skipped_total monotonicity + per-call boundary on success vs failure

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_constants_strict_pin_and_cross_relations() {
        // The 3 module constants are the public API surface for default
        // limiter sizing — operators read them, callers rely on them, and
        // memory-budget math (4 KB × 10K peers → 40 MB ceiling) keys off
        // MAX_PEERS specifically. Strict-equality pin so a refactor cannot
        // silently widen the bucket or raise the peer cap.
        assert_eq!(MAX_PEERS, 10_000usize,
            "MAX_PEERS = 10_000 (matches peer_rtt::MAX_PEERS)");
        assert_eq!(DEFAULT_CAPACITY, 20.0f64,
            "DEFAULT_CAPACITY = 20.0 — burst tolerance: ≈10-peer fan-out + headroom");
        assert_eq!(DEFAULT_REFILL_PER_SEC, 10.0f64,
            "DEFAULT_REFILL_PER_SEC = 10.0 tok/sec — sustained gossip + attest + delta-sync");

        // Type-pin: usize for MAX_PEERS (not u32, not u64). Load-bearing for
        // HashMap::len() >= max_peers comparison.
        let _usize_check: usize = MAX_PEERS;
        // Type-pin: f64 for capacity + refill. Load-bearing for token math.
        let _f64_capacity: f64 = DEFAULT_CAPACITY;
        let _f64_refill: f64 = DEFAULT_REFILL_PER_SEC;

        // Cross-relations.
        assert!(MAX_PEERS > 0, "0 peer cap would brick all gossip");
        assert!(DEFAULT_CAPACITY > 0.0, "0-capacity rejects every acquire");
        assert!(DEFAULT_REFILL_PER_SEC > 0.0,
            "0-refill creates a one-shot pool that never recovers");

        // Burst-over-sustained ratio = CAPACITY / REFILL = 2.0 (exact).
        // Load-bearing: refill-saturation time in seconds for a fully drained
        // bucket. A future refactor lowering CAPACITY < REFILL would mean the
        // bucket can't sustain even a single burst — a regression bait.
        assert!(DEFAULT_CAPACITY > DEFAULT_REFILL_PER_SEC,
            "burst tolerance must exceed sustained rate");
        let refill_saturation_secs = DEFAULT_CAPACITY / DEFAULT_REFILL_PER_SEC;
        assert!((refill_saturation_secs - 2.0).abs() < 1e-9,
            "refill-saturation = capacity/refill = 2.0s exact, got {refill_saturation_secs}");

        // MAX_PEERS upper-bound — pins the 40-byte-per-bucket × 10K = 400 KB
        // memory budget claim from the source-comment (line 17).
        // The bucket-size proxy here is `MAX_PEERS <= 100_000`: a 10× drift
        // would put the limiter at 4 MB which is still fine on phone-tier
        // (2 GB target), but a 100× drift to 1M peers (40 MB) breaks the
        // "fits on 2 GB node" invariant if other buffers are sized similarly.
        assert!(MAX_PEERS <= 100_000,
            "MAX_PEERS must stay within 10× headroom of the documented 10K cap");
    }

    #[test]
    fn batch_b_new_eq_default_and_with_params_observable_state() {
        // new() and Default::default() must produce limiters with
        // observably-identical state. Callers rely on `Default` semantics
        // for type integration (`#[derive(Default)]` on parent state).
        let new = PeerBandwidthLimiter::new();
        let default = PeerBandwidthLimiter::default();
        assert_eq!(new.tracked_peers(), 0,
            "new() limiter has zero tracked peers");
        assert_eq!(default.tracked_peers(), 0,
            "default() limiter has zero tracked peers");
        assert_eq!(new.skipped_total.load(Ordering::Relaxed), 0,
            "new() skipped counter starts at 0");
        assert_eq!(default.skipped_total.load(Ordering::Relaxed), 0,
            "default() skipped counter starts at 0");
        assert!(new.peek_tokens("never_inserted").is_none(),
            "new() returns None for unknown peer");
        assert!(default.peek_tokens("never_inserted").is_none(),
            "default() returns None for unknown peer");

        // Both fields default to DEFAULT_CAPACITY and DEFAULT_REFILL_PER_SEC
        // — verified by behavior: first acquire on a new peer should leave
        // tokens at exactly DEFAULT_CAPACITY - 1.0.
        new.try_acquire("peerA");
        let tokens = new.peek_tokens("peerA").unwrap();
        assert!((tokens - (DEFAULT_CAPACITY - 1.0)).abs() < 0.01,
            "new() limiter starts buckets at DEFAULT_CAPACITY (=20); after 1 acquire tokens≈19, got {tokens}");

        // with_params binds the three fields. A custom-capacity limiter
        // should leave its own custom value (NOT DEFAULT_CAPACITY) after a
        // first acquire.
        let custom = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        custom.try_acquire("peerA");
        let tokens = custom.peek_tokens("peerA").unwrap();
        assert!((tokens - 4.0).abs() < 0.01,
            "with_params(5.0, ...) starts buckets at 5.0; after 1 acquire tokens≈4, got {tokens}");

        // with_params honors max_peers — verify by behavior (saturation).
        let small = PeerBandwidthLimiter::with_params(5.0, 0.0, 2);
        small.try_acquire("a");
        small.try_acquire("b");
        small.try_acquire("c");
        assert_eq!(small.tracked_peers(), 2,
            "with_params max_peers=2 enforces 2-peer cap under flood");
    }

    #[test]
    fn batch_b_try_acquire_alias_and_cost_edge_cases() {
        // try_acquire is the 1-token alias for try_acquire_cost. Pin that
        // it has the SAME effect: same skipped_total delta, same tokens delta.
        let lim_a = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        let lim_b = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        let ret_a = lim_a.try_acquire("peerA");
        let ret_b = lim_b.try_acquire_cost("peerA", 1.0);
        assert_eq!(ret_a, ret_b,
            "try_acquire(p) and try_acquire_cost(p, 1.0) must have same return");
        assert_eq!(lim_a.peek_tokens("peerA"), lim_b.peek_tokens("peerA"),
            "post-call tokens must be identical");

        // cost=0.0 edge case: returns true unconditionally AND does NOT
        // consume tokens AND does NOT increment skipped_total. The
        // condition `tokens >= 0.0` is true for any non-negative bucket,
        // and `self.tokens -= 0.0` is a no-op.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        lim.try_acquire("peerA"); // tokens now 4
        assert!(lim.try_acquire_cost("peerA", 0.0),
            "cost=0 must return true");
        let tokens = lim.peek_tokens("peerA").unwrap();
        assert!((tokens - 4.0).abs() < 0.01,
            "cost=0 must not consume tokens; got {tokens}");

        // cost=INFINITY edge case: returns false on any finite bucket. The
        // condition `tokens >= INFINITY` is false for any finite tokens.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        lim.try_acquire("peerA");
        assert!(!lim.try_acquire_cost("peerA", f64::INFINITY),
            "cost=INFINITY must return false on any finite bucket");
        let tokens = lim.peek_tokens("peerA").unwrap();
        assert!((tokens - 4.0).abs() < 0.01,
            "cost=INFINITY rejection must NOT deduct; got {tokens}");

        // cost=NaN edge case: IEEE-754 `tokens >= NaN` is false; returns
        // false AND does NOT deduct. Pinned to catch a refactor that swaps
        // the comparison or uses ordered-equal.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 100);
        lim.try_acquire("peerA");
        assert!(!lim.try_acquire_cost("peerA", f64::NAN),
            "cost=NaN must return false per IEEE-754 (NaN comparison)");
        let tokens = lim.peek_tokens("peerA").unwrap();
        assert!((tokens - 4.0).abs() < 0.01,
            "cost=NaN rejection must NOT deduct; got {tokens}");

        // Cost greater than bucket on a fresh bucket: returns false AND
        // does NOT deduct. Existing `cost_greater_than_available...` test
        // covers AFTER existing peer is set up; this pins fresh-bucket
        // behavior.
        let lim = PeerBandwidthLimiter::with_params(3.0, 0.0, 100);
        assert!(!lim.try_acquire_cost("peerNew", 100.0),
            "cost > fresh-bucket capacity must return false");
        let tokens = lim.peek_tokens("peerNew").unwrap();
        assert!((tokens - 3.0).abs() < 0.01,
            "fresh bucket inserted at full capacity even when call returns false; got {tokens}");
    }

    #[test]
    fn batch_b_lru_eviction_exact_victim_under_saturation() {
        // Pin the EXACT victim selected by evict_oldest under saturation,
        // not just "some peer was evicted". The selection rule is
        // `max_by_key(current.wrapping_sub(b.last_tick))` — the peer with
        // the largest wrap-around distance from current tick (= oldest).
        //
        // Fill cap=3, then trigger eviction with a 4th peer. Pin: A is the
        // victim (oldest by insertion order), B and C survive.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        lim.try_acquire("peerA"); // tick 1
        lim.try_acquire("peerB"); // tick 2
        lim.try_acquire("peerC"); // tick 3
        assert_eq!(lim.tracked_peers(), 3);
        lim.try_acquire("peerD"); // tick 4 — A evicted (distance 4-1=3)
        assert_eq!(lim.tracked_peers(), 3,
            "tracked_peers stays at cap=3 under saturation");
        assert!(lim.peek_tokens("peerA").is_none(), "peerA (oldest) evicted");
        assert!(lim.peek_tokens("peerB").is_some(), "peerB survives");
        assert!(lim.peek_tokens("peerC").is_some(), "peerC survives");
        assert!(lim.peek_tokens("peerD").is_some(), "peerD inserted");

        // Touch-refresh: re-accessing a peer updates last_tick so it moves
        // to the most-recently-touched slot, displacing the eviction
        // candidate.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        lim.try_acquire("peerA"); // tick 1
        lim.try_acquire("peerB"); // tick 2
        lim.try_acquire("peerC"); // tick 3
        lim.try_acquire("peerA"); // tick 4 — refreshes A's last_tick to 4
        lim.try_acquire("peerD"); // tick 5 — B is now oldest (distance 5-2=3)
        assert_eq!(lim.tracked_peers(), 3);
        assert!(lim.peek_tokens("peerA").is_some(),
            "peerA refreshed at tick 4; survives over older B");
        assert!(lim.peek_tokens("peerB").is_none(),
            "peerB (now oldest at tick 2) is the eviction victim");
        assert!(lim.peek_tokens("peerC").is_some(), "peerC at tick 3 survives");
        assert!(lim.peek_tokens("peerD").is_some(), "peerD inserted");

        // Cap stays at MAX_PEERS exactly (not MAX-1, not MAX+1) under
        // sustained flood. Insert 10 distinct peers into a cap-3 limiter
        // and verify tracked_peers never overshoots.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        for i in 0..10 {
            lim.try_acquire(&format!("peer{i}"));
            assert!(lim.tracked_peers() <= 3,
                "tracked_peers must never exceed cap; got {} at i={i}",
                lim.tracked_peers());
        }
        assert_eq!(lim.tracked_peers(), 3,
            "post-flood tracked_peers must equal cap exactly");

        // Re-acquiring an EXISTING peer does NOT trigger eviction (only
        // NEW peers trigger the contains_key-gated eviction path). The
        // tick still advances and refreshes last_tick.
        let lim = PeerBandwidthLimiter::with_params(5.0, 0.0, 3);
        lim.try_acquire("peerA");
        lim.try_acquire("peerB");
        lim.try_acquire("peerC");
        let before = lim.tracked_peers();
        lim.try_acquire("peerA"); // existing — no eviction
        let after = lim.tracked_peers();
        assert_eq!(before, after,
            "re-acquiring existing peer must NOT change tracked_peers");
    }

    #[test]
    fn batch_b_skipped_total_monotonicity_and_per_call_boundary() {
        // skipped_total starts at 0 on construction (covered in §1 above)
        // and is the operator-observable counter exposed in /status.
        //
        // SUCCESS path does NOT increment; FAILURE path increments by
        // exactly 1 per call. A refactor to fetch_max or store(1) would
        // break the monotonic-counter invariant — pinned here.
        let lim = PeerBandwidthLimiter::with_params(2.0, 0.0, 100);
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 0);

        // 2 successes — counter stays at 0.
        assert!(lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 0);
        assert!(lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 0);

        // 3 failures — counter increments by exactly 3 (not 1, not 6, not 0).
        assert!(!lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 1);
        assert!(!lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 2);
        assert!(!lim.try_acquire("peerA"));
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 3);

        // Mix of success+failure across peers — counter tracks failures only.
        let lim = PeerBandwidthLimiter::with_params(1.0, 0.0, 100);
        lim.try_acquire("a"); // success
        lim.try_acquire("a"); // FAILURE — counter→1
        lim.try_acquire("b"); // success (b is new, full bucket)
        lim.try_acquire("b"); // FAILURE — counter→2
        lim.try_acquire("c"); // success
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 2,
            "counter tracks failures across peers, not per-peer");

        // cost=0.0 success does NOT increment (covered behaviorally in §3
        // — pinned again here on the counter axis).
        let lim = PeerBandwidthLimiter::with_params(3.0, 0.0, 100);
        lim.try_acquire("a"); // success, counter 0
        lim.try_acquire_cost("a", 0.0); // success (always), counter must stay 0
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 0,
            "cost=0 success must NOT increment skipped_total");

        // INFINITY/NaN failure DOES increment (failure-path increments,
        // regardless of failure reason).
        let lim = PeerBandwidthLimiter::with_params(3.0, 0.0, 100);
        lim.try_acquire("a"); // success
        lim.try_acquire_cost("a", f64::INFINITY); // FAILURE — counter→1
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 1);
        lim.try_acquire_cost("a", f64::NAN); // FAILURE — counter→2
        assert_eq!(lim.skipped_total.load(Ordering::Relaxed), 2,
            "NaN-cost failure increments counter");
    }
}
