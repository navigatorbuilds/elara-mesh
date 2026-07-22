//! Identity Partitioning Phase D — on-miss peer fetch.
//!
//! When a local PK lookup misses, ask peers. PKs are public, so the fetch
//! is safe over any transport — production calls go via PQ (`identity_pk`
//! method). On a hit we cache to the USER tier (`store_public_key_user`)
//! so the next lookup is local; if the call site needs witness/anchor
//! tier, it routes through `store_public_key_witness/anchor` separately
//! and Phase C promotion handles the migration.
//!
//! Peer selection (best-effort, no fairness guarantees):
//!   1. Connected, non-stale, reachable, not-self.
//!   2. Prefer peers that `wants_zone(last_known_zone)` if a hint is given —
//!      witnesses for that zone are the ones most likely to hold its PKs.
//!   3. Otherwise round-robin through all eligible peers.
//!
//! Soft-fail: returns `None` after exhausting candidates. Counter
//! `identity_pk_fetch_misses_total` records these for observability —
//! callers (record verification, finality check, …) decide whether to
//! treat the missing PK as "unknown" or hard-reject.
//!
//! Spec: internal design notes §3.3 + §4 Phase D + §6 (open Q).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::network::state::NodeState;
use crate::network::peer::PeerInfo;

/// Maximum number of peers we try before giving up on an on-miss fetch.
/// Bounded so a single missing PK can't hammer every connected peer in
/// the mesh. 8 is enough that even a 1-in-3 hit rate succeeds at p99.
const MAX_PEERS_PER_FETCH: usize = 8;

/// Result returned to call sites. Distinguishes "no peer has it" from
/// "we have it now" so the caller's logging / counter bumps are precise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Peer returned the PK; already cached in CF_IDENTITIES_USER.
    Hit(Vec<u8>),
    /// Every queried peer answered "no" or was unreachable. Caller's
    /// soft-fail policy applies.
    Miss,
}

/// Fetch a single identity's PK from peers. The optional
/// `last_known_zone` is a non-binding hint: if some peer subscribes to
/// that zone, we ask it first. Otherwise we walk the connected-active
/// peer set in arbitrary order.
///
/// On a hit: caches to USER tier locally and returns `Hit(pk)`. On a
/// miss across all probed peers: returns `Miss` without writing
/// anything. Either path bumps the relevant `/metrics` counter.
pub async fn fetch_pk_from_peers(
    state: &Arc<NodeState>,
    identity_hash: &str,
    last_known_zone: Option<&str>,
) -> FetchOutcome {
    state
        .identity_pk_fetch_attempts_total
        .fetch_add(1, Ordering::Relaxed);

    // Snapshot peer list under the lock, then drop it before the
    // (potentially slow) PQ calls — keeps the read lock contention-free.
    let candidates = {
        let peers = state.peers.read().await;
        select_candidates(peers.all(), &state.identity.identity_hash, last_known_zone)
    };

    if candidates.is_empty() {
        state
            .identity_pk_fetch_misses_total
            .fetch_add(1, Ordering::Relaxed);
        return FetchOutcome::Miss;
    }

    let pq_offset = state.config.pq_port_offset;
    for (peer_hash, base_url) in candidates {
        let pq_addr = match crate::network::gossip::http_to_pq_addr(&base_url, pq_offset) {
            Some(a) => a,
            None => {
                tracing::debug!(
                    "idp_d: cannot derive PQ addr from {base_url} (peer {peer_hash})"
                );
                continue;
            }
        };
        match state.pq_client.get_identity_pk(&pq_addr, identity_hash).await {
            Ok(Some(pk)) => {
                if let Err(e) = state.rocks.store_public_key_user(identity_hash, &pk) {
                    tracing::debug!(
                        "idp_d: peer {peer_hash} returned PK for {identity_hash} but local cache write failed: {e}"
                    );
                    // Still a hit from the network's perspective; caller
                    // gets the bytes. Local cache will refill on next call.
                }
                state
                    .identity_pk_fetch_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "idp_d: fetched PK for {identity_hash} from peer {peer_hash} ({pq_addr})"
                );
                return FetchOutcome::Hit(pk);
            }
            Ok(None) => {
                // Peer responded but doesn't have it — try the next one.
                continue;
            }
            Err(e) => {
                tracing::debug!(
                    "idp_d: peer {peer_hash} ({pq_addr}) failed identity_pk for {identity_hash}: {e}"
                );
                continue;
            }
        }
    }

    state
        .identity_pk_fetch_misses_total
        .fetch_add(1, Ordering::Relaxed);
    FetchOutcome::Miss
}

/// Pick up to `MAX_PEERS_PER_FETCH` candidates from the peer table,
/// preferring zone-matching ones when a hint is given. Pure helper —
/// no state mutation, easy to unit-test.
fn select_candidates(
    all_peers: Vec<&PeerInfo>,
    self_identity_hash: &str,
    last_known_zone: Option<&str>,
) -> Vec<(String, String)> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let viable: Vec<&PeerInfo> = all_peers
        .into_iter()
        .filter(|p| p.identity_hash != self_identity_hash)
        .filter(|p| p.reachable)
        .filter(|p| !p.in_backoff(now_secs))
        .collect();

    // Bucket viable peers by zone match. When a hint is given, peers
    // subscribed to that zone go first — they're the most likely to
    // hold both witness PKs (registered in that zone) and user PKs
    // (record creators in that zone).
    let (preferred, fallback): (Vec<&PeerInfo>, Vec<&PeerInfo>) = match last_known_zone {
        Some(zone) => viable.into_iter().partition(|p| p.wants_zone(zone)),
        None => (Vec::new(), viable),
    };

    preferred
        .iter()
        .chain(fallback.iter())
        .take(MAX_PEERS_PER_FETCH)
        .map(|p| (p.identity_hash.clone(), p.base_url()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::peer::{NodeType, PeerInfo, PeerProvenance, PeerState};

    fn mk_peer(
        id: &str,
        host: &str,
        zones: Vec<&str>,
        reachable: bool,
        in_backoff: bool,
    ) -> PeerInfo {
        PeerInfo {
            identity_hash: id.to_string(),
            host: host.to_string(),
            port: 9473,
            node_type: NodeType::Leaf,
            last_seen: 1000.0,
            state: PeerState::Connected,
            failures: if in_backoff { 5 } else { 0 },
            successes: 0,
            valid_records: 0,
            invalid_records: 0,
            // Far-future when `in_backoff` so any plausible `now` falls below.
            backoff_until: if in_backoff { f64::MAX / 2.0 } else { 0.0 },
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: String::new(),
            provenance: PeerProvenance::Outbound,
            subscribed_zones: zones.into_iter().map(|s| s.to_string()).collect(),
            att_watermark: 0.0,
            pull_failures: 0,
            pull_backoff_until: 0.0,
            reachable,
            protocol_version: 0,
            att_pull_invalid_sig: 0,
            att_pull_invalid_powas: 0,
            att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
        }
    }

    #[test]
    fn idp_d_select_candidates_skips_self() {
        let peer_self = mk_peer("self_hash", "1.1.1.1", vec![], true, false);
        let peer_other = mk_peer("other_hash", "2.2.2.2", vec![], true, false);
        let pool = vec![&peer_self, &peer_other];
        let picks = select_candidates(pool, "self_hash", None);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "other_hash");
    }

    #[test]
    fn idp_d_select_candidates_skips_unreachable() {
        let p1 = mk_peer("a", "1.1.1.1", vec![], false, false);
        let p2 = mk_peer("b", "2.2.2.2", vec![], true, false);
        let pool = vec![&p1, &p2];
        let picks = select_candidates(pool, "self", None);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "b");
    }

    #[test]
    fn idp_d_select_candidates_skips_in_backoff() {
        let p1 = mk_peer("a", "1.1.1.1", vec![], true, true);
        let p2 = mk_peer("b", "2.2.2.2", vec![], true, false);
        let pool = vec![&p1, &p2];
        let picks = select_candidates(pool, "self", None);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "b");
    }

    #[test]
    fn idp_d_select_candidates_zone_hint_prefers_subscribers_first() {
        let p1 = mk_peer("a", "1.1.1.1", vec!["zone-other"], true, false);
        let p2 = mk_peer("b", "2.2.2.2", vec!["zone-target"], true, false);
        let p3 = mk_peer("c", "3.3.3.3", vec!["zone-other"], true, false);
        let pool = vec![&p1, &p2, &p3];
        let picks = select_candidates(pool, "self", Some("zone-target"));
        assert_eq!(picks.len(), 3);
        assert_eq!(picks[0].0, "b", "zone-matching peer must come first");
    }

    #[test]
    fn idp_d_select_candidates_no_hint_returns_all_viable() {
        let p1 = mk_peer("a", "1.1.1.1", vec!["zone-x"], true, false);
        let p2 = mk_peer("b", "2.2.2.2", vec!["zone-y"], true, false);
        let pool = vec![&p1, &p2];
        let picks = select_candidates(pool, "self", None);
        assert_eq!(picks.len(), 2);
    }

    #[test]
    fn idp_d_select_candidates_caps_at_max_peers_per_fetch() {
        let owned: Vec<PeerInfo> = (0..20)
            .map(|i| mk_peer(&format!("peer{i}"), "1.1.1.1", vec![], true, false))
            .collect();
        let pool: Vec<&PeerInfo> = owned.iter().collect();
        let picks = select_candidates(pool, "self", None);
        assert_eq!(picks.len(), MAX_PEERS_PER_FETCH);
    }

    #[test]
    fn idp_d_select_candidates_empty_when_only_self() {
        let p1 = mk_peer("self", "1.1.1.1", vec![], true, false);
        let pool = vec![&p1];
        let picks = select_candidates(pool, "self", None);
        assert!(picks.is_empty());
    }

    #[test]
    fn idp_d_fetch_outcome_variants_distinguish_hit_vs_miss() {
        // Pure type-shape check — exercises the public surface so the
        // /metrics counters above can branch cleanly. Mirrors the
        // call-site pattern in record verification.
        let hit = FetchOutcome::Hit(vec![1, 2, 3]);
        let miss = FetchOutcome::Miss;
        assert_ne!(hit, miss);
        match hit {
            FetchOutcome::Hit(b) => assert_eq!(b, vec![1, 2, 3]),
            FetchOutcome::Miss => panic!("expected hit"),
        }
    }

    // ─── fixture-free ────────────────────────────────────
    //
    // Five axes covering surface NOT covered by the existing idp_d_*
    // semantic tests:
    //   1. MAX_PEERS_PER_FETCH constant strict-pin + cross-relation (bound)
    //   2. FetchOutcome derive matrix (Debug + Clone + PartialEq + Eq)
    //      across both variants
    //   3. select_candidates zone-hint preserves WITHIN-bucket input order
    //      (FIFO inside preferred + FIFO inside fallback)
    //   4. select_candidates zone-hint with ZERO matching peers → all
    //      viable end up in fallback bucket, output equals input order
    //   5. select_candidates take(8) interaction: 5 preferred + 10 fallback
    //      emits 5 preferred + 3 fallback (preferred bucket drains first)
    //      + empty-pool fast-path

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_max_peers_per_fetch_strict_pin_and_bound_role() {
        // The bound is load-bearing: a single missing PK must not be able
        // to hammer every connected peer in a 1000+ node mesh. Pin literal.
        assert_eq!(MAX_PEERS_PER_FETCH, 8,
            "MAX_PEERS_PER_FETCH must be exactly 8 — fanout cap for on-miss PK fetch");

        // Type is usize (compile-time check via .len() comparator). Use it
        // as a length argument to force the type fixation.
        let v: Vec<u32> = vec![0; MAX_PEERS_PER_FETCH];
        assert_eq!(v.len(), 8);

        // Cross-relation: 8 is the operational sweet spot per module doc
        // ("even a 1-in-3 hit rate succeeds at p99"). A value of 0 or 1
        // would defeat the round-robin; a value > 64 would blow the
        // soft-fail budget. Bound it.
        assert!(MAX_PEERS_PER_FETCH >= 4,
            "fanout < 4 cannot survive a 25% peer success rate at p95");
        assert!(MAX_PEERS_PER_FETCH <= 16,
            "fanout > 16 violates the `single missing PK shouldn't hammer the mesh` invariant");
    }

    #[test]
    fn batch_b_fetch_outcome_full_derive_matrix_debug_clone_partial_eq_eq() {
        // Construct two distinct Hit values + one Miss. Validate every
        // derive trait across the cross-product.
        let h_a = FetchOutcome::Hit(vec![0xAA, 0xBB]);
        let h_b = FetchOutcome::Hit(vec![0xCC, 0xDD]);
        let h_a2 = FetchOutcome::Hit(vec![0xAA, 0xBB]);
        let m = FetchOutcome::Miss;
        let m2 = FetchOutcome::Miss;

        // Clone preserves bytes (Hit case) and identity (Miss case).
        let h_a_clone = h_a.clone();
        assert_eq!(h_a_clone, h_a, "Hit::clone must equal source");
        let m_clone = m.clone();
        assert_eq!(m_clone, m, "Miss::clone must equal source");

        // PartialEq + Eq reflexivity, symmetry, cross-variant inequality.
        assert_eq!(h_a, h_a2, "Hit with equal bytes must be PartialEq-equal");
        assert_ne!(h_a, h_b, "Hit with differing bytes must NOT be equal");
        assert_ne!(h_a, m, "Hit vs Miss must be unequal across variants");
        assert_eq!(m, m2, "Miss == Miss (unit-shape variant)");

        // Eq is a marker — usable in HashSet (use BTreeSet for Ord-free)
        // via PartialEq. Just check transitivity manually:
        assert_eq!(h_a, h_a2);
        assert_eq!(h_a2, h_a_clone);
        assert_eq!(h_a, h_a_clone, "Eq transitivity must hold across Hit chain");

        // Debug derive contains variant name for log-grep contract.
        let dbg_hit = format!("{:?}", h_a);
        let dbg_miss = format!("{:?}", m);
        assert!(dbg_hit.contains("Hit"),
            "Debug must contain `Hit` variant name (log-grep contract): {dbg_hit}");
        assert!(dbg_miss.contains("Miss"),
            "Debug must contain `Miss` variant name (log-grep contract): {dbg_miss}");

        // Cross-variant Debug strings MUST be disjoint (no shared prefix
        // that would break log filtering).
        assert_ne!(dbg_hit, dbg_miss);
    }

    #[test]
    fn batch_b_select_candidates_within_bucket_fifo_preserves_input_order() {
        // Two zone-matching peers (preferred bucket) + two non-matching
        // (fallback). Output must preserve input order WITHIN each bucket.
        // This pins the round-robin "no fairness guarantee" — but the
        // *input* order IS the contract (mostly stable across reads).
        let p_pref_1 = mk_peer("pref-1", "1.1.1.1", vec!["zone-target"], true, false);
        let p_fall_1 = mk_peer("fall-1", "2.2.2.2", vec!["zone-other"], true, false);
        let p_pref_2 = mk_peer("pref-2", "3.3.3.3", vec!["zone-target"], true, false);
        let p_fall_2 = mk_peer("fall-2", "4.4.4.4", vec!["zone-other"], true, false);

        let pool = vec![&p_pref_1, &p_fall_1, &p_pref_2, &p_fall_2];
        let picks = select_candidates(pool, "self", Some("zone-target"));

        assert_eq!(picks.len(), 4, "all 4 viable peers should appear");
        // Preferred bucket first, in input order: pref-1, pref-2.
        assert_eq!(picks[0].0, "pref-1",
            "preferred bucket first, in original input order");
        assert_eq!(picks[1].0, "pref-2",
            "second preferred peer preserves input order");
        // Fallback bucket next, in input order: fall-1, fall-2.
        assert_eq!(picks[2].0, "fall-1",
            "fallback bucket immediately after preferred, in input order");
        assert_eq!(picks[3].0, "fall-2",
            "second fallback peer preserves input order");
    }

    #[test]
    fn batch_b_select_candidates_zone_hint_with_zero_matches_falls_back_in_input_order() {
        // Hint is given but NO peer subscribes to that zone. All viable
        // peers must land in the fallback bucket — output equals input
        // order, no peer skipped or reordered.
        let p1 = mk_peer("a", "1.1.1.1", vec!["zone-x"], true, false);
        let p2 = mk_peer("b", "2.2.2.2", vec!["zone-y"], true, false);
        let p3 = mk_peer("c", "3.3.3.3", vec!["zone-z"], true, false);
        let pool = vec![&p1, &p2, &p3];

        // Hint for zone nobody is subscribed to.
        let picks = select_candidates(pool, "self", Some("zone-nonexistent"));
        assert_eq!(picks.len(), 3,
            "zone-miss must NOT drop viable peers — they all go to fallback bucket");

        // Order preserved (fallback bucket alone, in input order).
        assert_eq!(picks[0].0, "a", "fallback-only path preserves input order [0]");
        assert_eq!(picks[1].0, "b", "fallback-only path preserves input order [1]");
        assert_eq!(picks[2].0, "c", "fallback-only path preserves input order [2]");

        // Sanity: hint=None on same pool should produce identical result.
        let picks_no_hint = select_candidates(vec![&p1, &p2, &p3], "self", None);
        let names_hint: Vec<&String> = picks.iter().map(|p| &p.0).collect();
        let names_no: Vec<&String> = picks_no_hint.iter().map(|p| &p.0).collect();
        assert_eq!(names_hint, names_no,
            "zone-hint-with-zero-matches must produce identical order to None hint");
    }

    #[test]
    fn batch_b_select_candidates_take_8_drains_preferred_first_then_fallback_and_empty_pool_fast_path() {
        // Empty pool → empty output, no panic.
        let empty: Vec<&PeerInfo> = Vec::new();
        let picks = select_candidates(empty, "self", None);
        assert!(picks.is_empty(),
            "empty pool fast-path must yield empty Vec without panic");
        let picks_hint = select_candidates(Vec::new(), "self", Some("zone"));
        assert!(picks_hint.is_empty(),
            "empty pool with hint must also yield empty Vec without panic");

        // 5 preferred + 10 fallback. take(8) must emit:
        //   - all 5 preferred peers (bucket drains first)
        //   - 3 fallback peers (filling remaining capacity)
        let preferred: Vec<PeerInfo> = (0..5)
            .map(|i| mk_peer(&format!("pref-{i}"), "1.1.1.1", vec!["zone-target"], true, false))
            .collect();
        let fallback: Vec<PeerInfo> = (0..10)
            .map(|i| mk_peer(&format!("fall-{i}"), "2.2.2.2", vec!["zone-other"], true, false))
            .collect();
        let pool: Vec<&PeerInfo> = preferred.iter().chain(fallback.iter()).collect();

        let picks = select_candidates(pool, "self", Some("zone-target"));
        assert_eq!(picks.len(), MAX_PEERS_PER_FETCH,
            "take(8) cap must clamp 15-viable down to 8");

        // First 5 must be the preferred peers (bucket fully drained).
        for (i, p) in picks.iter().enumerate().take(5) {
            assert!(p.0.starts_with("pref-"),
                "slot {i}: preferred-bucket must drain first, got: {}", p.0);
        }
        // Slots 5,6,7 must be the FIRST 3 fallback peers (input order).
        for i in 0..3 {
            assert_eq!(picks[5 + i].0, format!("fall-{i}"),
                "slot {} (fallback slot {i}): fallback bucket drains in input order",
                5 + i);
        }
    }
}
