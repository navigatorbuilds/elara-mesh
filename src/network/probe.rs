//! Peer liveness probes — three-in-one protocol.
//!
//! Each probe performs three functions in a single round trip:
//! 1. **Liveness check** — peer responds → alive, no response → reputation penalty
//! 2. **Record exchange** — response includes a recent record the prober might not have
//! 3. **Trust scoring** — successful probes generate positive reputation signals
//!
//! Probes keep the network alive with zero user traffic. The probe IS the traffic.
//! Interval scales with network size: ~1 probe/node/hour regardless of node count.

//!
//! Spec references:
//!   @spec Protocol §11.14

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};

use crate::record::ValidationRecord;

use super::state::NodeState;
use super::LockRecover;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Base probe interval for a 5-node network (seconds).
/// Scales: interval = BASE × sqrt(connected_peers / 5)
const BASE_PROBE_INTERVAL_SECS: u64 = 300; // 5 minutes for 5 nodes

/// Minimum probe interval (floor).
const MIN_PROBE_INTERVAL_SECS: u64 = 60;

/// Maximum probe interval (ceiling).
const MAX_PROBE_INTERVAL_SECS: u64 = 3600;

/// Timeout for a single probe request.
const PROBE_TIMEOUT_SECS: u64 = 10;

// ─── Probe Request/Response ─────────────────────────────────────────────────

/// A liveness probe request sent to a peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeRequest {
    /// A random record ID from the prober's DAG.
    /// The peer responds with this record's parents (proving they have it).
    pub record_id: String,
    /// The prober's identity hash (for reputation tracking).
    pub prober_identity: String,
}

/// Response to a liveness probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeResponse {
    /// Whether the peer has the requested record.
    pub has_record: bool,
    /// Parents of the requested record (if the peer has it).
    pub parents: Vec<String>,
    /// A recent record the prober might not have.
    /// Recent records are where sync gaps typically appear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_record: Option<Vec<u8>>,
    /// Peer's current DAG size (for sync status comparison).
    pub dag_size: usize,
    /// Peer's identity hash.
    pub responder_identity: String,
}

// ─── Probe handling (server side) ───────────────────────────────────────────

/// Handle an incoming probe request. Called from the HTTP server.
///
/// Returns the peer's parents for the requested record plus a recent record
/// that the prober might be missing.
pub async fn handle_probe(
    state: &Arc<NodeState>,
    request: &ProbeRequest,
) -> ProbeResponse {
    let dag = state.dag.read().await;
    let dag_size = dag.len();

    // Check if we have the requested record
    let (has_record, parents) = if dag.contains(&request.record_id) {
        let parents = dag.parents(&request.record_id)
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        (true, parents)
    } else {
        (false, vec![])
    };

    // Pick a recent record to send back — recent records are where gaps form.
    // Use the most recent tip (highest timestamp) that isn't the probed record.
    let recent_record = {
        let tips = dag.tips();
        let mut best: Option<(&str, f64)> = None;
        for tip in &tips {
            if *tip == request.record_id {
                continue;
            }
            if let Some(ts) = dag.timestamps.get(tip.as_str()) {
                if best.is_none_or(|(_, best_ts)| *ts > best_ts) {
                    best = Some((tip, *ts));
                }
            }
        }

        // Fetch the full record from storage
        if let Some((tip_id, _)) = best {
            state.rocks.get_record(tip_id)
                .ok()
                .flatten()
                .map(|rec| rec.to_bytes())
        } else {
            None
        }
    };

    ProbeResponse {
        has_record,
        parents,
        recent_record,
        dag_size,
        responder_identity: state.identity.identity_hash.clone(),
    }
}

// ─── Probe execution (client side) ──────────────────────────────────────────

/// Execute a single probe against a peer via PQ transport (AUDIT-10).
///
/// Returns true if the probe succeeded (peer responded with valid data).
async fn execute_probe(
    state: &Arc<NodeState>,
    peer_url: &str,
    peer_identity: &str,
) -> bool {
    // Pick a random record from our DAG
    let record_id = {
        let dag = state.dag.read().await;
        let tips = dag.tips();
        if tips.is_empty() {
            debug!("probe: no records in DAG, skipping");
            return false;
        }
        // Pick a random tip using a simple hash of current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let idx = (now as usize) % tips.len();
        tips[idx].to_string()
    };

    let request = ProbeRequest {
        record_id: record_id.clone(),
        prober_identity: state.identity.identity_hash.clone(),
    };

    // AUDIT-10: PQ-only. No HTTPS fallback.
    let pq_addr = match super::gossip::http_to_pq_addr(peer_url, state.config.pq_port_offset) {
        Some(a) => a,
        None => {
            debug!("probe: no PQ addr for {peer_url}, skipping");
            return false;
        }
    };
    let request_bytes = match serde_json::to_vec(&request) {
        Ok(b) => b,
        Err(e) => {
            debug!("probe: failed to serialize request: {e}");
            return false;
        }
    };
    let _ = PROBE_TIMEOUT_SECS; // preserved constant, PQ call has its own timeout

    match state.pq_client.probe(&pq_addr, &request_bytes).await {
        Ok(resp_value) => {
            let probe_resp: ProbeResponse = match serde_json::from_value(resp_value) {
                Ok(r) => r,
                Err(e) => {
                    debug!("probe: {} response parse failed: {e}", &peer_identity[..peer_identity.len().min(16)]);
                    return false;
                }
            };
            debug!(
                "probe: {} responded — has_record={}, dag_size={}, recent={}",
                &peer_identity[..peer_identity.len().min(16)],
                probe_resp.has_record,
                probe_resp.dag_size,
                probe_resp.recent_record.is_some()
            );

            // Insert the recent record if we got one
            if let Some(record_bytes) = probe_resp.recent_record {
                if let Ok(record) = ValidationRecord::from_bytes(&record_bytes) {
                    // Check if we already have it
                    let already_have = {
                        let dag = state.dag.read().await;
                        dag.contains(&record.id)
                    };
                    if !already_have {
                        match super::gossip::insert_record_synced(state, record).await {
                            Ok(id) => {
                                debug!("probe: inserted new record {} from {}", &id[..16.min(id.len())], &peer_identity[..16.min(peer_identity.len())]);
                                state.gossip_pull_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                debug!("probe: failed to insert record from {}: {e}", &peer_identity[..16.min(peer_identity.len())]);
                            }
                        }
                    }
                }
            }

            // Positive reputation signal
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                let mut rep = state.reputation.lock_recover();
                rep.apply_event(peer_identity, super::reputation::ReputationEvent::Undisputed, now);
            }

            true
        }
        Err(e) => {
            debug!("probe: {} unreachable: {e}", &peer_identity[..peer_identity.len().min(16)]);
            // No harsh penalty for probe failure — peer might just be temporarily offline.
            // The peer table's failure tracking handles connection issues.
            false
        }
    }
}

// ─── Background probe loop ──────────────────────────────────────────────────

/// Compute probe interval based on network size.
/// More peers = less frequent probes per node, same total network activity.
fn probe_interval(connected_peers: usize) -> Duration {
    if connected_peers == 0 {
        return Duration::from_secs(MAX_PROBE_INTERVAL_SECS);
    }

    // interval = BASE × sqrt(peers / 5)
    let factor = (connected_peers as f64 / 5.0).sqrt();
    let secs = (BASE_PROBE_INTERVAL_SECS as f64 * factor) as u64;
    let clamped = secs.clamp(MIN_PROBE_INTERVAL_SECS, MAX_PROBE_INTERVAL_SECS);
    Duration::from_secs(clamped)
}

/// Background loop that periodically probes random peers.
///
/// Runs on all nodes. Keeps the network alive with zero user traffic.
/// Each probe round: pick a random connected peer, send a probe, process response.
pub async fn probe_loop(
    state: Arc<NodeState>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
    hb: Arc<super::supervision::LoopStatus>,
) {
    info!("probe loop started (base interval: {}s)", BASE_PROBE_INTERVAL_SECS);

    // Initial delay — let the node finish startup and discover peers
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        _ = shutdown.changed() => { return; }
    }

    let mut probes_sent: u64 = 0;
    let mut probes_succeeded: u64 = 0;

    loop {
        // Compute interval based on current peer count
        let peer_count = {
            let peers = state.peers.read().await;
            peers.connected().len()
        };
        let interval = probe_interval(peer_count);

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("probe loop shutting down (sent={probes_sent}, succeeded={probes_succeeded})");
                return;
            }
        }
        hb.heartbeat(); // hang-detection: stamp each tick (adaptive ≤3600s « 7200s stale_after)

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host is saturated. Probes are health-only — they MUST yield
        // to seal signing and ingest under load, even at the cost of
        // delayed liveness signal.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        // Pick a random connected peer
        let peer_info = {
            let peers = state.peers.read().await;
            let connected: Vec<_> = peers.connected()
                .into_iter()
                .filter(|p| p.last_seen > 0.0)
                .collect();

            if connected.is_empty() {
                debug!("probe: no connected peers, skipping");
                continue;
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let idx = (now as usize) % connected.len();
            let peer = &connected[idx];
            (
                peer.base_url(),
                peer.identity_hash.clone(),
            )
        };

        let (peer_url, peer_identity) = peer_info;

        probes_sent += 1;
        if execute_probe(&state, &peer_url, &peer_identity).await {
            probes_succeeded += 1;
        }

        if probes_sent.is_multiple_of(10) {
            info!(
                "probe stats: sent={probes_sent} succeeded={probes_succeeded} rate={:.0}%",
                if probes_sent > 0 { probes_succeeded as f64 / probes_sent as f64 * 100.0 } else { 0.0 }
            );
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_interval_scaling() {
        // 5 nodes = base interval
        let d5 = probe_interval(5);
        assert_eq!(d5.as_secs(), BASE_PROBE_INTERVAL_SECS);

        // 0 nodes = max interval
        let d0 = probe_interval(0);
        assert_eq!(d0.as_secs(), MAX_PROBE_INTERVAL_SECS);

        // 20 nodes = 2× base (sqrt(20/5) = 2)
        let d20 = probe_interval(20);
        assert_eq!(d20.as_secs(), BASE_PROBE_INTERVAL_SECS * 2);

        // 1 node = shorter than base
        let d1 = probe_interval(1);
        assert!(d1.as_secs() < BASE_PROBE_INTERVAL_SECS);
        assert!(d1.as_secs() >= MIN_PROBE_INTERVAL_SECS);
    }

    #[test]
    fn test_probe_interval_bounds() {
        // Very large network — capped at max
        let d_huge = probe_interval(10_000);
        assert!(d_huge.as_secs() <= MAX_PROBE_INTERVAL_SECS);

        // Minimum floor
        let d_min = probe_interval(1);
        assert!(d_min.as_secs() >= MIN_PROBE_INTERVAL_SECS);
    }

    #[test]
    fn test_probe_request_serialization() {
        let req = ProbeRequest {
            record_id: "test-123".to_string(),
            prober_identity: "abc123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ProbeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.record_id, "test-123");
        assert_eq!(parsed.prober_identity, "abc123");
    }

    #[test]
    fn test_probe_response_serialization() {
        let resp = ProbeResponse {
            has_record: true,
            parents: vec!["p1".to_string(), "p2".to_string()],
            recent_record: None,
            dag_size: 22918,
            responder_identity: "def456".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ProbeResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.has_record);
        assert_eq!(parsed.parents.len(), 2);
        assert_eq!(parsed.dag_size, 22918);
    }

    // ─── probe-interval constant pin tests ──────────────────────────────

    /// Module-level constants are the SLA contract for probe traffic at
    /// 10K-node scale. BASE=300s and MAX=3600s together define the per-node
    /// probe rate budget; silently shifting any of these doubles network
    /// overhead. Existing tests use the symbols but never pin the literal —
    /// a coordinated edit (constant + test reference) would slip through.
    #[test]
    fn batch_b_probe_module_constants_pinned_to_literal_values() {
        assert_eq!(
            BASE_PROBE_INTERVAL_SECS, 300,
            "BASE drives per-peer rate at 5 connected peers — bumping = halving liveness rate"
        );
        assert_eq!(
            MIN_PROBE_INTERVAL_SECS, 60,
            "MIN floor is the densest-network safety budget"
        );
        assert_eq!(
            MAX_PROBE_INTERVAL_SECS, 3600,
            "MAX ceiling is the sparsest-network keepalive budget (1h)"
        );
        assert_eq!(
            PROBE_TIMEOUT_SECS, 10,
            "TIMEOUT is the per-probe blocking budget"
        );
    }

    /// `probe_interval` MAX-cap onset boundary. Math: 300*sqrt(p/5)=3600 at
    /// p=720 exactly (sqrt(144)=12, 300*12=3600). Existing `test_probe_interval_bounds`
    /// only asserts p=10000 is capped — doesn't pin the cap-onset point. A
    /// future BASE/MAX recalibration would silently move where probes stop
    /// scaling with network size; pinning the 720-peer boundary catches it.
    #[test]
    fn batch_b_probe_interval_max_cap_onset_at_720_peers() {
        // p=719 — formula naturally below cap (3597s)
        let d_below = probe_interval(719);
        assert_eq!(
            d_below.as_secs(),
            3597,
            "p=719 must naturally compute 3597s (one tick below cap)"
        );

        // p=720 — formula exactly at cap (300*12 = 3600s, clamp no-op)
        let d_at = probe_interval(720);
        assert_eq!(
            d_at.as_secs(),
            MAX_PROBE_INTERVAL_SECS,
            "p=720 must hit the cap exactly (sqrt(144)=12, 300*12=3600)"
        );

        // p=721 — formula would yield 3602s, clamped to 3600
        let d_above = probe_interval(721);
        assert_eq!(
            d_above.as_secs(),
            MAX_PROBE_INTERVAL_SECS,
            "p=721 must be clamped down to the 3600s cap"
        );

        // Far-above sanity (already in test_probe_interval_bounds, but
        // re-pinned here to lock the cap-equal-not-greater invariant)
        let d_huge = probe_interval(1_000_000);
        assert_eq!(d_huge.as_secs(), MAX_PROBE_INTERVAL_SECS);
    }

    /// `probe_interval` f64→u64 truncation matrix. The fn casts the float
    /// product to u64 with `as u64` (truncates, never rounds). A silent
    /// shift to `.round() as u64` would change ALL non-integer-sqrt cases
    /// by ~0.5s — invisible to coarse boundary tests but visible here.
    /// Locks the truncation semantics across 7 distinct integer-sqrt and
    /// non-integer-sqrt cases.
    #[test]
    fn batch_b_probe_interval_truncation_matrix_seven_peer_counts() {
        // Integer-sqrt cases (no truncation possible since product is exact):
        assert_eq!(probe_interval(5).as_secs(), 300, "p=5 → sqrt(1)*300 = 300");
        assert_eq!(probe_interval(20).as_secs(), 600, "p=20 → sqrt(4)*300 = 600");
        assert_eq!(probe_interval(80).as_secs(), 1200, "p=80 → sqrt(16)*300 = 1200");
        assert_eq!(
            probe_interval(125).as_secs(),
            1500,
            "p=125 → sqrt(25)*300 = 1500"
        );
        assert_eq!(
            probe_interval(500).as_secs(),
            3000,
            "p=500 → sqrt(100)*300 = 3000"
        );

        // Non-integer-sqrt cases (truncation matters):
        // p=1 → 300 * 0.4472135... = 134.164... → 134 (truncate, NOT 134.5→135)
        assert_eq!(
            probe_interval(1).as_secs(),
            134,
            "p=1 → as-u64 truncates 134.164 to 134, NOT rounds to 134"
        );
        // p=2 → 300 * 0.6324555... = 189.736... → 189 (truncate, NOT 189.7→190)
        assert_eq!(
            probe_interval(2).as_secs(),
            189,
            "p=2 → as-u64 truncates 189.737 to 189, NOT rounds to 190"
        );
    }

    /// `ProbeResponse.recent_record: Some(bytes)` MUST round-trip through
    /// serde without dropping the inner bytes. Existing
    /// `test_probe_response_serialization` only covers `None`. The
    /// `#[serde(skip_serializing_if = "Option::is_none")]` attribute
    /// applies to `None` only; `Some(empty_vec)` and `Some(non_empty_vec)`
    /// MUST serialize the field. A regression that bumped the skip to
    /// `Option::is_none_or_empty` (no such fn but easy to mistype) would
    /// drop empty vecs silently — pinning catches it.
    #[test]
    fn batch_b_probe_response_some_recent_record_round_trip_preserves_bytes() {
        let raw_bytes: Vec<u8> = (0u8..=200).collect();
        let resp = ProbeResponse {
            has_record: false,
            parents: vec![],
            recent_record: Some(raw_bytes.clone()),
            dag_size: 0,
            responder_identity: "id_responder".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // The serialized JSON MUST contain the "recent_record" key.
        assert!(
            json.contains("\"recent_record\":"),
            "Some(bytes) variant must NOT be skip-serialized"
        );
        let parsed: ProbeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recent_record, Some(raw_bytes));
        assert!(!parsed.has_record);
        assert!(parsed.parents.is_empty());

        // Edge case: Some(empty_vec) — still NOT skipped (the attribute
        // only checks for None, not emptiness).
        let resp_empty = ProbeResponse {
            has_record: false,
            parents: vec![],
            recent_record: Some(vec![]),
            dag_size: 0,
            responder_identity: "x".to_string(),
        };
        let json_empty = serde_json::to_string(&resp_empty).unwrap();
        assert!(
            json_empty.contains("\"recent_record\":"),
            "Some(empty_vec) must STILL serialize the field key"
        );
    }

    /// `ProbeResponse.recent_record: None` MUST be ABSENT from the
    /// serialized JSON (not serialized as `"recent_record": null`). The
    /// `#[serde(skip_serializing_if = "Option::is_none")]` attribute is
    /// load-bearing for wire-size economy at probe scale — without it,
    /// every probe response carries 22 wasted bytes for the null marker.
    /// At 1 probe/peer/5min × 10K nodes × ~0.1 hit rate that's ~360
    /// pointless bytes/sec fleet-wide. Pinning JSON-shape catches a silent
    /// attribute removal.
    #[test]
    fn batch_b_probe_response_none_recent_record_is_absent_from_json() {
        let resp = ProbeResponse {
            has_record: true,
            parents: vec!["pp".to_string()],
            recent_record: None,
            dag_size: 42,
            responder_identity: "rid".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("recent_record"),
            "None variant must be skip-serialized — got json: {json}"
        );
        // Sanity: the other 4 fields must still be present (so the test
        // isn't trivially passing on a totally empty JSON object).
        assert!(json.contains("\"has_record\":true"));
        assert!(json.contains("\"parents\":[\"pp\"]"));
        assert!(json.contains("\"dag_size\":42"));
        assert!(json.contains("\"responder_identity\":\"rid\""));

        // Round-trip preserves the None.
        let parsed: ProbeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recent_record, None);
    }
}
