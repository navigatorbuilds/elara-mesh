//! §11.23 Layer A slice 1 — on-miss peer-relay for content-hash lookups.
//!
//! When `/records/by-hash/{content_hash}` misses the local CF_IDX_HASH and
//! the caller has opted into relay (axum `?relay=1`, PQ header `relay=1`),
//! this module fans out a small concurrent batch of peer PQ requests over
//! `resolve_content_hash`. First successful peer wins; misses are tallied
//! to the `records_by_hash_peer_relay_*` counters so operators can decide
//! whether the relay is doing useful work.
//!
//! Why a bounded fan-out (not flood):
//!   * At 10K+ peers a flood would amplify a single 64-byte content-hash
//!     query into ~10K PQ round-trips per call — DoS-class amplification.
//!   * 8 peers covers the realistic Zipfian distribution of record-holders:
//!     popular records are everywhere (first peer hits), rare records live
//!     on a small archive set (the operator's job is to make sure their
//!     local peer table includes one). Beyond 8 the marginal hit-rate is
//!     under the egress budget at 10K-node scale.
//!
//! Peer selection mirrors `identity_fetcher::select_candidates`:
//!   1. Connected, non-stale, reachable, not-self.
//!   2. No zone hint — content hashes are zone-agnostic; the producer's
//!      zone is recoverable from the record body only AFTER we have it.
//!   3. FIFO over the viable set, capped at `MAX_PEERS_PER_FETCH`.
//!
//! Soft-fail: returns `Miss` after exhausting candidates. Counters:
//!   - `records_by_hash_peer_relay_attempts_total` — every entry
//!   - `records_by_hash_peer_relay_hits_total`     — first peer that had it
//!   - `records_by_hash_peer_relay_misses_total`   — exhausted, no peer had it
//!
//! Responder side: `pq_transport/router.rs::handle_resolve_content_hash`
//! does a LOCAL-ONLY `compute_record_by_hash_with_relay(_, _, relay=false)`
//! — it MUST NOT recursively peer-relay or a network of empty nodes would
//! generate exponential request amplification.
//!
//! Spec: internal design notes §11.23 Layer A slice 1.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::network::state::NodeState;
use crate::network::peer::PeerInfo;

/// Maximum peers contacted per relay attempt. Same value as
/// `identity_fetcher::MAX_PEERS_PER_FETCH` — the cap is load-bearing for
/// DoS containment at fleet scale (10K+ peers), not a tunable.
const MAX_PEERS_PER_FETCH: usize = 8;

/// Result returned to the caller. Distinguishes "every peer said no" from
/// "we found it" so axum's hit/miss counter bookkeeping stays clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Some peer returned the record body. The full JSON shape matches
    /// `compute_record_detail` — caller forwards it verbatim.
    Hit(serde_json::Value),
    /// Every queried peer answered "no" or was unreachable.
    Miss,
}

/// Fan out a `resolve_content_hash` PQ request to up to
/// `MAX_PEERS_PER_FETCH` peers. First peer that returns a record wins.
///
/// Sequential (not parallel) for two reasons:
///   1. Most lookups hit in the first 1-2 peers; parallel fan-out wastes
///      bandwidth on follow-ups that arrive after we already have the body.
///   2. Sequential gives us natural circuit-breaker semantics — if peer 1
///      hangs we move on, no need for a custom JoinSet abort path.
///
/// `content_hash` must already be lowercase-hex 64 chars; the caller
/// (axum / PQ handler) validates that shape before reaching here so this
/// fn doesn't re-validate.
pub async fn fetch_record_from_peers(
    state: &Arc<NodeState>,
    content_hash: &str,
) -> FetchOutcome {
    state
        .records_by_hash_peer_relay_attempts_total
        .fetch_add(1, Ordering::Relaxed);

    let candidates = {
        let peers = state.peers.read().await;
        select_candidates(peers.all(), &state.identity.identity_hash)
    };

    if candidates.is_empty() {
        state
            .records_by_hash_peer_relay_misses_total
            .fetch_add(1, Ordering::Relaxed);
        return FetchOutcome::Miss;
    }

    let pq_offset = state.config.pq_port_offset;
    for (peer_hash, base_url) in candidates {
        let pq_addr = match crate::network::gossip::http_to_pq_addr(&base_url, pq_offset) {
            Some(a) => a,
            None => {
                tracing::debug!(
                    "by_hash_relay: cannot derive PQ addr from {base_url} (peer {peer_hash})"
                );
                continue;
            }
        };
        match state.pq_client.get_record_by_hash(&pq_addr, content_hash).await {
            Ok(Some(body)) => {
                state
                    .records_by_hash_peer_relay_hits_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "by_hash_relay: peer {peer_hash} ({pq_addr}) resolved {content_hash}"
                );
                return FetchOutcome::Hit(body);
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(
                    "by_hash_relay: peer {peer_hash} ({pq_addr}) failed resolve_content_hash for {content_hash}: {e}"
                );
                continue;
            }
        }
    }

    state
        .records_by_hash_peer_relay_misses_total
        .fetch_add(1, Ordering::Relaxed);
    FetchOutcome::Miss
}

/// Pure helper — pick up to `MAX_PEERS_PER_FETCH` viable peers. Mirrors
/// `identity_fetcher::select_candidates` minus the zone-hint axis (content
/// hashes are zone-agnostic — the producer's zone is only knowable AFTER
/// the record body is in hand).
fn select_candidates(
    all_peers: Vec<&PeerInfo>,
    self_identity_hash: &str,
) -> Vec<(String, String)> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    all_peers
        .into_iter()
        .filter(|p| p.identity_hash != self_identity_hash)
        .filter(|p| p.reachable)
        .filter(|p| !p.in_backoff(now_secs))
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
            backoff_until: if in_backoff { f64::MAX / 2.0 } else { 0.0 },
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: String::new(),
            provenance: PeerProvenance::Outbound,
            subscribed_zones: Default::default(),
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
    fn s1123_la1_select_candidates_skips_self() {
        let s = mk_peer("self_hash", "1.1.1.1", true, false);
        let other = mk_peer("other_hash", "2.2.2.2", true, false);
        let pool = vec![&s, &other];
        let picks = select_candidates(pool, "self_hash");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "other_hash");
    }

    #[test]
    fn s1123_la1_select_candidates_skips_unreachable() {
        let a = mk_peer("a", "1.1.1.1", false, false);
        let b = mk_peer("b", "2.2.2.2", true, false);
        let pool = vec![&a, &b];
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "b");
    }

    #[test]
    fn s1123_la1_select_candidates_skips_in_backoff() {
        let a = mk_peer("a", "1.1.1.1", true, true);
        let b = mk_peer("b", "2.2.2.2", true, false);
        let pool = vec![&a, &b];
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "b");
    }

    #[test]
    fn s1123_la1_select_candidates_caps_at_max_peers_per_fetch() {
        let owned: Vec<PeerInfo> = (0..20)
            .map(|i| mk_peer(&format!("p{i}"), "1.1.1.1", true, false))
            .collect();
        let pool: Vec<&PeerInfo> = owned.iter().collect();
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), MAX_PEERS_PER_FETCH);
    }

    #[test]
    fn s1123_la1_select_candidates_empty_pool_yields_empty() {
        let empty: Vec<&PeerInfo> = Vec::new();
        let picks = select_candidates(empty, "self");
        assert!(picks.is_empty());
    }

    #[test]
    fn s1123_la1_select_candidates_preserves_input_order_fifo() {
        let p_a = mk_peer("a", "1.1.1.1", true, false);
        let p_b = mk_peer("b", "2.2.2.2", true, false);
        let p_c = mk_peer("c", "3.3.3.3", true, false);
        let pool = vec![&p_c, &p_a, &p_b];
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 3);
        assert_eq!(picks[0].0, "c", "FIFO must preserve input order");
        assert_eq!(picks[1].0, "a");
        assert_eq!(picks[2].0, "b");
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn s1123_la1_max_peers_per_fetch_strict_pin() {
        // DoS-containment constant — load-bearing at fleet scale.
        assert_eq!(MAX_PEERS_PER_FETCH, 8,
            "MAX_PEERS_PER_FETCH must be exactly 8 — DoS-amplification cap");
        // Cross-relation: 8 mirrors identity_fetcher; flood would 10K× a
        // 64-byte query into 10K PQ round-trips at fleet scale.
        assert!(MAX_PEERS_PER_FETCH >= 4,
            "fanout < 4 cannot survive 25% peer success rate");
        assert!(MAX_PEERS_PER_FETCH <= 16,
            "fanout > 16 violates single-lookup-shouldn't-flood invariant");
    }

    #[test]
    fn s1123_la1_fetch_outcome_full_derive_matrix() {
        let h_a = FetchOutcome::Hit(serde_json::json!({"id": "abc"}));
        let h_b = FetchOutcome::Hit(serde_json::json!({"id": "xyz"}));
        let h_a2 = FetchOutcome::Hit(serde_json::json!({"id": "abc"}));
        let m1 = FetchOutcome::Miss;
        let m2 = FetchOutcome::Miss;

        // Clone preserves Hit payload AND Miss identity.
        assert_eq!(h_a.clone(), h_a);
        assert_eq!(m1.clone(), m1);

        // PartialEq matrix.
        assert_eq!(h_a, h_a2, "Hit with equal JSON must be equal");
        assert_ne!(h_a, h_b, "Hit with different JSON must NOT be equal");
        assert_ne!(h_a, m1, "Hit vs Miss must be unequal across variants");
        assert_eq!(m1, m2);

        // Debug must contain variant name (log-grep contract).
        let dbg_hit = format!("{:?}", h_a);
        let dbg_miss = format!("{:?}", m1);
        assert!(dbg_hit.contains("Hit"));
        assert!(dbg_miss.contains("Miss"));
        assert_ne!(dbg_hit, dbg_miss);
    }

    #[test]
    fn s1123_la1_select_candidates_mixed_filters_compose() {
        // Composition of all 3 filters: self + unreachable + backoff, only
        // the clean peer survives.
        let s = mk_peer("self", "1.1.1.1", true, false);
        let unreach = mk_peer("unreach", "2.2.2.2", false, false);
        let backoff = mk_peer("backoff", "3.3.3.3", true, true);
        let clean = mk_peer("clean", "4.4.4.4", true, false);
        let pool = vec![&s, &unreach, &backoff, &clean];
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, "clean");
        assert_eq!(picks[0].1, "http://4.4.4.4:9473",
            "base_url() must reflect host:port from PeerInfo");
    }

    #[test]
    fn s1123_la1_select_candidates_exact_cap_eight_returns_eight() {
        // Boundary at MAX_PEERS_PER_FETCH itself: 8 viable peers → exactly 8 picks.
        // The over-cap test (N=20) cannot catch a `take(N-1)` off-by-one because
        // 20 > 7 still passes; this one pins that `take(8)` returns 8, not 7.
        let owned: Vec<PeerInfo> = (0..MAX_PEERS_PER_FETCH)
            .map(|i| mk_peer(&format!("p{i}"), "1.1.1.1", true, false))
            .collect();
        let pool: Vec<&PeerInfo> = owned.iter().collect();
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), MAX_PEERS_PER_FETCH,
            "exact-cap input must yield exactly MAX_PEERS_PER_FETCH picks");
        // And the picks must be in input order.
        for (i, p) in picks.iter().enumerate() {
            assert_eq!(p.0, format!("p{i}"),
                "exact-cap path must preserve input FIFO at slot {i}");
        }
    }

    #[test]
    fn s1123_la1_select_candidates_under_cap_returns_all_no_pad() {
        // 7 viable peers (one below cap) → exactly 7 picks. Pins that
        // `take(MAX_PEERS_PER_FETCH)` does NOT pad — it returns the full
        // viable set when the pool is smaller than the cap.
        let owned: Vec<PeerInfo> = (0..7)
            .map(|i| mk_peer(&format!("p{i}"), "1.1.1.1", true, false))
            .collect();
        let pool: Vec<&PeerInfo> = owned.iter().collect();
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 7,
            "under-cap input must return all viable peers, not pad to cap");
        assert!(picks.len() < MAX_PEERS_PER_FETCH,
            "sanity: under-cap path is exercised");
    }

    #[test]
    fn s1123_la1_select_candidates_fifo_preserved_through_skip_filters() {
        // Skip-class peers (self / unreachable / backoff) INTERLEAVED with
        // viable ones. Relative input order of the viable peers must be
        // preserved post-filter — the chain is `filter().filter().filter().take()`
        // which is FIFO over the surviving stream.
        let s        = mk_peer("self",    "0.0.0.0", true,  false);
        let unreach1 = mk_peer("u1",      "1.1.1.1", false, false);
        let viable_a = mk_peer("vA",      "2.2.2.2", true,  false);
        let backoff1 = mk_peer("b1",      "3.3.3.3", true,  true );
        let viable_b = mk_peer("vB",      "4.4.4.4", true,  false);
        let unreach2 = mk_peer("u2",      "5.5.5.5", false, false);
        let viable_c = mk_peer("vC",      "6.6.6.6", true,  false);

        let pool = vec![&s, &unreach1, &viable_a, &backoff1, &viable_b, &unreach2, &viable_c];
        let picks = select_candidates(pool, "self");

        assert_eq!(picks.len(), 3,
            "exactly 3 viable peers must survive the 3-filter chain");
        assert_eq!(picks[0].0, "vA", "slot 0: first viable in input must come first");
        assert_eq!(picks[1].0, "vB", "slot 1: second viable in input must come second");
        assert_eq!(picks[2].0, "vC", "slot 2: third viable in input must come third");
    }

    // ── 3 orthogonal axes on select_candidates not covered by the
    //    cap-boundary trio. ──

    #[test]
    fn s1123_la1_select_candidates_all_skip_classes_yields_empty() {
        // Distinct from `empty_pool_yields_empty`: there the input pool is
        // empty, here every peer is a skip-class instance (one self + one
        // unreachable + one in-backoff). Pins that the
        // filter().filter().filter().take() chain correctly collapses a
        // NON-empty pool to an empty Vec when no element survives — without
        // panicking, without falling back to "pass-through unfiltered", and
        // without the off-by-one of e.g. `Iterator::take` on an empty
        // iterator. The hit/miss counter bookkeeping in
        // `fetch_record_from_peers` depends on this empty-Vec path firing
        // the miss-counter early-return at line ~84.
        let me      = mk_peer("self",  "1.1.1.1", true,  false);
        let unreach = mk_peer("u",     "2.2.2.2", false, false);
        let backoff = mk_peer("b",     "3.3.3.3", true,  true);
        let pool = vec![&me, &unreach, &backoff];
        let picks = select_candidates(pool, "self");
        assert!(picks.is_empty(),
            "all-skip non-empty pool must yield empty post-filter, not panic or pass-through");
    }

    #[test]
    fn s1123_la1_select_candidates_base_url_reflects_peer_port_not_hardcode() {
        // Pins that `p.base_url()` interpolates the peer's actual `port`
        // field into the URL, not a hardcoded `:9473` (the default in
        // `mk_peer`). A regression that wrote `format!("http://{}:9473", host)`
        // literally would pass the existing `mixed_filters_compose` and
        // `skips_self/unreachable/backoff` tests (all use port 9473) but
        // must fail here with the non-default port.
        let mut p = mk_peer("p", "10.0.0.1", true, false);
        p.port = 31337;
        let pool = vec![&p];
        let picks = select_candidates(pool, "self");
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, "http://10.0.0.1:31337",
            "base_url must interpolate peer.port (31337), not hardcode :9473");
    }

    #[test]
    fn s1123_la1_select_candidates_self_filter_uses_exact_string_equality() {
        // Pins that the self-identity skip is EXACT-string equality (`==`),
        // not a `starts_with`/`contains`/`ends_with` mutation. Three peers
        // whose identity_hash is a prefix/suffix/extension of the self
        // string must NOT be filtered out — only the exact-match peer is
        // skipped. Catches mutations like `p.identity_hash.contains(self)`
        // that would silently drop peers sharing a substring with the
        // local identity hash (high-impact at 10K-peer scale where short
        // identity-hash prefixes are non-rare).
        let prefix     = mk_peer("self",        "1.1.1.1", true, false);
        let suffix     = mk_peer("xself",       "2.2.2.2", true, false);
        let extension  = mk_peer("selfish",     "3.3.3.3", true, false);
        let exact      = mk_peer("self_hash",   "4.4.4.4", true, false);
        let pool = vec![&prefix, &suffix, &extension, &exact];
        let picks = select_candidates(pool, "self_hash");
        assert_eq!(picks.len(), 3,
            "only the exact-match self peer must be skipped — 3 peers must remain");
        // The exact-match peer must NOT appear in picks.
        for p in &picks {
            assert_ne!(p.0, "self_hash",
                "exact-match self peer must be filtered out");
        }
        // FIFO over surviving peers must preserve input order.
        assert_eq!(picks[0].0, "self");
        assert_eq!(picks[1].0, "xself");
        assert_eq!(picks[2].0, "selfish");
    }
}
