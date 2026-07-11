//! Auto-witness loop — background task that counter-signs incoming records.

//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec economics §11.1

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::accounting::types::creator_identity_hash;

use super::gossip;
use super::state::NodeState;
use super::witness::{AttestationRecord, WitnessManager};
use super::{LockRecover, RwLockRecover};

/// Re-push age guard. Attestations older than this are zombies — the record
/// is GC'd from active disk on most peers and will never settle, so re-pushing
/// just generates `att-push REJECTED pq-status=400` cycles forever.
///
/// Empirical tuning (2026-04-27): finality stuck-records on testnet observed
/// ~28 days old (2026-03-31 → today). 24h is a generous "settlement should
/// have happened by now" cutoff: in-zone target is 60s (P50), worst-case
/// adaptive epoch is 120s, hard-discard ceiling is 20 min (1200s, 2026-04-29
/// resize). 24h gives 72× headroom over the hard-discard ceiling — anything
/// past it is definitely never going to settle organically.
pub const REPUSH_MAX_AGE_SECS: f64 = 86_400.0;

/// Pure predicate for the re-push zombie guard. Extracted so the loop logic
/// can be tested without spinning up NodeState/WitnessManager.
#[inline]
pub fn is_repush_zombie(now_secs: f64, att_timestamp: f64) -> bool {
    now_secs - att_timestamp > REPUSH_MAX_AGE_SECS
}

/// Run the auto-witness loop. Periodically checks for unwitnessed records
/// and counter-signs them if this node has sufficient stake.
pub async fn auto_witness_loop(
    state: Arc<NodeState>,
    witness_mgr: Arc<WitnessManager>,
    mut shutdown: mpsc::Receiver<()>,
) {
    if !state.config.auto_witness {
        debug!("auto-witness disabled");
        return;
    }

    // Role enforcement: only Witness and Anchor nodes can attest records (Protocol v0.6.2)
    let node_type = super::peer::NodeType::from_str(&state.config.node_type);
    if !node_type.can_witness() {
        debug!("auto-witness skipped — node type '{}' cannot witness", node_type.as_str());
        return;
    }

    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    // 1-CPU nodes: 300s interval (was 60s) — auto-witness spawn_blocking calls
    // saturate the 2-thread blocking pool for 50-85s per cycle, starving record
    // ingest. 300s gives compaction and ingest breathing room.
    let interval_secs = if cpus <= 1 {
        state.config.auto_witness_interval_secs.max(300)
    } else {
        state.config.auto_witness_interval_secs
    };
    // 1-CPU nodes: cap batch to 15 to avoid TLS handshake storm from att-push.
    // 50 attestations × 3 peers = 150 concurrent TLS attempts on a single thread.
    let batch_size = if cpus <= 1 {
        state.config.auto_witness_batch_size.min(15)
    } else {
        state.config.auto_witness_batch_size
    };
    info!("auto-witness loop started (interval={interval_secs}s, batch={batch_size}, cpus={cpus})");
    let interval = Duration::from_secs(interval_secs);
    let our_hash = state.identity.identity_hash.clone();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("auto-witness loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host CPU/load is saturated. No-op on idle hosts.
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        // Catch-up guard: skip witnessing when node is significantly behind on sync.
        // With tighter eviction windows, normal operation creates orphan edges
        // (evicted records leave orphan parent references). Threshold must be high
        // enough to not block normal witnessing while still protecting against
        // initial-sync CPU starvation on 2-core machines.
        {
            let dag = state.dag.read().await;
            let orphan_count = dag.orphan_count();
            if orphan_count > 1000 {
                debug!("auto-witness: skipping cycle — node catching up ({orphan_count} orphan edges)");
                state.auto_witness_skips_orphan_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
        }

        // Check we're staked. Build stake-weighted list for MAINNET gap #5
        // committee selection (priority ∝ stake via `hash / isqrt(stake)`).
        //
        // Iterate `staker_index` (incrementally maintained set of
        // active stakers) instead of all accounts. At 1M accounts × ~1%
        // staker rate this drops a per-cycle O(accounts) scan to O(stakers).
        // auto_witness fires every loop tick so this compounds.
        let (staked_amount, staked_weighted) = {
            let ledger = state.ledger.read().await;
            let our_stake = ledger.staked(&our_hash);
            let mut staked: Vec<(String, u64)> = Vec::with_capacity(ledger.staker_index.len());
            for hash in ledger.staker_index.keys() {
                if let Some(acct) = ledger.accounts.get(hash.as_str()) {
                    if acct.staked > 0 {
                        staked.push((hash.clone(), acct.staked));
                    }
                }
            }
            (our_stake, staked)
        };

        if staked_amount == 0 {
            debug!("auto-witness: not staked, skipping cycle");
            state.auto_witness_skips_not_staked_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }

        // Per-zone VRF committee (Protocol §7.4, MAINNET gap #5): check
        // committee membership per-zone, filtered by the zone subscription
        // registry and size-capped at MAINNET_COMMITTEE_SIZE. Stake-weighted
        // — higher-stake witnesses get more selection weight. Bootstrap
        // fallback (sparse zones / no VRF yet) preserves the old jury
        // behavior so settlement never stalls.
        //
        // Scale (Gap 5): mirrors the epoch-tick loop
        // (`epoch.rs:3331-3398`). Build a `CommitteeSelectionIndex` once
        // (O(|staked| log |staked|), amortized), then stage VRF + subs
        // tuples under the epoch/subscription locks, drop the locks, and
        // parallelize per-zone membership checks via rayon. Indexed lookup
        // makes the per-zone work O(|subs|) — no per-call O(|staked|) scan.
        let index = super::consensus::CommitteeSelectionIndex::build(&staked_weighted);
        let allowed_zones: std::collections::HashSet<crate::ZoneId> = {
            let zone_count = super::consensus::get_zone_count();

            // `Option<[u8;32]>` preserves the bootstrap distinction (None
            // = no VRF emitted yet → everyone attests) without conflating
            // it with a legitimate all-zero VRF output.
            let inputs: Vec<(crate::ZoneId, Option<[u8; 32]>, std::collections::HashSet<String>)> = {
                let epoch = state.epoch.read_recover();
                let subs_mgr = state.zone_subscriptions.lock_recover();
                (0..zone_count)
                    .map(|i| {
                        let zone = crate::ZoneId::from_legacy(i);
                        let vrf = epoch.vrf_output(&zone).copied();
                        let subs = subs_mgr.subscribers(&zone);
                        (zone, vrf, subs)
                    })
                    .collect()
            };

            use rayon::prelude::*;
            inputs
                .par_iter()
                .filter_map(|(zone, vrf, subs)| {
                    let vrf_slice: &[u8] = vrf.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
                    if super::consensus::is_in_epoch_committee_scoped_indexed(
                        vrf_slice,
                        &index,
                        zone,
                        subs,
                        &our_hash,
                    ) {
                        Some(zone.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if allowed_zones.is_empty() {
            debug!("auto-witness: not in epoch jury for any zone, skipping cycle");
            state.auto_witness_skips_no_jury_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }

        state.auto_witness_cycles_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cycle = state.auto_witness_cycles_total.load(std::sync::atomic::Ordering::Relaxed);

        // Priority: witness records closest to settlement first.
        // Records with attestations but below 66.7% threshold benefit most
        // from additional witnesses — especially from high-stake nodes.
        // Then fill remaining batch with any unwitnessed DAG records.
        //
        // IMPORTANT: MutexGuard (witness_mgr) must NOT be held across .await.
        // Split into two phases to keep the future Send-safe.

        // Phase 1: unsettled records (no .await needed — both are std::sync locks)
        // Pre-filter own records: we can't attest records we created.
        let mut candidates = Vec::with_capacity(batch_size);
        let (unsettled_count, _already_witnessed_p1) = {
            let mgr = witness_mgr.as_ref();
            let consensus = state.consensus.lock_recover();
            let unsettled = consensus.unsettled_summary();
            let unsettled_total = unsettled.len();
            let mut aw_count = 0usize;
            for (rid, _att_count, _trust) in &unsettled {
                if candidates.len() >= batch_size {
                    break;
                }
                // Skip own records early — can't self-attest (checked in inner loop too,
                // but filtering here prevents batch from filling with un-attestable records)
                if let Ok(rec) = state.get_record(rid) {
                    if creator_identity_hash(&rec) == our_hash {
                        continue;
                    }
                }
                let already_witnessed = mgr.get_attestations(rid)
                    .is_ok_and(|atts| atts.iter().any(|a| a.witness_hash == our_hash));
                if !already_witnessed {
                    candidates.push(rid.clone());
                } else {
                    aw_count += 1;
                }
            }
            (unsettled_total, aw_count)
        }; // mgr + consensus dropped BEFORE any .await
        let p1_candidates = candidates.len();

        // Phase 2: fill remaining batch from DAG tips (newest records first).
        //
        // Previous approach scanned dag.record_ids() (HashSet, arbitrary order)
        // with a tiny take(batch_size+10) window. On a 3000-record DAG, the same
        // ~20 already-witnessed records were returned every cycle and new records
        // were never reached. Auto-witness was effectively dead for new records.
        //
        // Fix: scan DAG tips (sorted newest-first) — these are records with no
        // children yet, i.e., the frontier that most needs attestation. Scan up to
        // 200 tips to find batch_size unwitnessed candidates.
        let (_dag_total, already_witnessed_p2, _own_skipped) = if candidates.len() < batch_size {
            // Collect tip IDs under the read lock, then drop it BEFORE doing
            // RocksDB lookups. Previously held dag.read() during up to 200
            // get_record calls — blocking dag.write() for 10-23s.
            let (dag_count, tip_ids) = {
                let dag = state.dag.read().await;
                let count = dag.len();
                let tips: Vec<String> = dag.tips().into_iter()
                    .filter(|rid| !candidates.contains(rid))
                    .take(200)
                    .collect();
                (count, tips)
            }; // dag read lock dropped here

            // Now filter with RocksDB lookups — no lock held
            let dag_rids: Vec<String> = tip_ids.into_iter()
                .filter(|rid| {
                    // Pre-filter: skip records we created (can't self-attest)
                    state.get_record(rid)
                        .map(|r| creator_identity_hash(&r) != our_hash)
                        .unwrap_or(true)
                })
                .collect();

            let mut aw_count = 0usize;
            let own_count = 0usize;
            let mgr = witness_mgr.as_ref();
            for rid in dag_rids {
                if candidates.len() >= batch_size {
                    break;
                }
                let already_witnessed = mgr.get_attestations(&rid)
                    .is_ok_and(|atts| atts.iter().any(|a| a.witness_hash == our_hash));
                if !already_witnessed {
                    candidates.push(rid);
                } else {
                    aw_count += 1;
                }
            }
            (dag_count, aw_count, own_count)
        } else {
            (0, 0, 0)
        };

        // Phase 2b: scan DAG roots (oldest first) for unfinalized records with
        // no attestation from us.
        //
        // Genesis-era and full_pull-synced parentless records are roots. Once
        // they have children they are never tips (invisible to Phase 2), with
        // zero attestations they are not in consensus (invisible to Phase 1),
        // and once the chain outgrows the newest-500 window they are invisible
        // to Phase 3 (fresh-chain wall #5, board 0g: the genesis pool_fund
        // record predates every peer's boot and structurally never finalized).
        //
        // Bounded: O(min(roots, 100)) per cycle; the root set shrinks as
        // records finalize and GC evicts them. The is_finalized filter keeps
        // late-joining nodes from burning PoWaS solves on already-settled
        // history.
        let p2b_added = if candidates.len() < batch_size {
            let root_ids: Vec<String> = {
                let dag = state.dag.read().await;
                dag.roots()
                    .into_iter()
                    .filter(|rid| !dag.is_finalized(rid))
                    .take(100)
                    .collect()
            }; // dag read lock dropped before RocksDB lookups

            let mut added = 0usize;
            let mgr = witness_mgr.as_ref();
            for rid in root_ids {
                if candidates.len() >= batch_size { break; }
                if candidates.contains(&rid) { continue; }
                // Skip own records (can't self-attest)
                if let Ok(rec) = state.get_record(&rid) {
                    if creator_identity_hash(&rec) == our_hash { continue; }
                }
                // Only take records we haven't witnessed
                match mgr.get_attestations(&rid) {
                    Ok(atts) if atts.iter().any(|a| a.witness_hash == our_hash) => continue,
                    _ => {}
                }
                candidates.push(rid);
                added += 1;
            }
            added
        } else {
            0
        };

        // Phase 3: fill remaining batch from timestamp index (newest first).
        //
        // Phase 1 only sees records with ≥1 attestation. Phase 2 only sees DAG
        // tips. Records that are NOT tips AND have zero attestations fall through
        // both phases and never get witnessed → never finalize → never GC'd.
        //
        // Fix: scan the timestamp index in reverse, skipping records already
        // found by Phase 1/2. This catches interior DAG nodes with no attestations.
        let (p3_scanned, p3_added) = if candidates.len() < batch_size {
            let since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
                - state.config.record_retention_secs.max(86400.0); // scan back 1 retention window (min 1 day)

            let scan_limit = if cpus <= 1 { 100 } else { 500 }; // limit scan on 1-core to reduce spawn_blocking time
            let rocks = state.rocks.clone();
            let recent_ids = match tokio::task::spawn_blocking(move || {
                rocks.recent_record_ids(since, scan_limit)
            }).await {
                Ok(Ok(ids)) => ids,
                Ok(Err(e)) => {
                    warn!("auto-witness phase 3: timestamp scan failed: {e}");
                    Vec::new()
                }
                Err(_) => Vec::new(),
            };

            let mut scanned = 0usize;
            let mut added = 0usize;
            let mgr = witness_mgr.as_ref();
            for rid in recent_ids {
                if candidates.len() >= batch_size { break; }
                scanned += 1;

                // Skip if already a candidate from Phase 1 or 2
                if candidates.contains(&rid) { continue; }

                // Skip own records
                if let Ok(rec) = state.get_record(&rid) {
                    if creator_identity_hash(&rec) == our_hash { continue; }
                }

                // Check attestation status via WitnessManager. Skip only when
                // we already witnessed it; attestations from others without
                // ours = a Phase 1 miss (take it), zero attestations = the
                // Phase 3 sweet spot (take it).
                match mgr.get_attestations(&rid) {
                    Ok(atts)
                        if !atts.is_empty()
                            && atts.iter().any(|a| a.witness_hash == our_hash) =>
                    {
                        continue; // already witnessed by us
                    }
                    _ => {}
                }

                candidates.push(rid);
                added += 1;
            }
            (scanned, added)
        } else {
            (0, 0)
        };

        // Phase 3b: scan OLDER records from a random point in the retention window.
        // Skip on 1-core — each spawn_blocking call holds the blocking pool for
        // seconds, causing 50-85s queue stalls for record ingest.
        //
        // Phase 3 only sees the 500 newest records. Records synced via full_pull
        // with old timestamps (days ago) are at positions >10K in the reverse scan
        // and never become auto-witness candidates. This phase picks a random
        // timestamp in the retention window and scans forward, catching old records
        // that full_pull brought in but auto-witness Phase 3 missed.
        let p3b_added = if candidates.len() < batch_size && cycle.is_multiple_of(2) && cpus > 1 {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let retention = state.config.record_retention_secs.max(86400.0);
            // Random offset: hash the cycle number to get a pseudo-random position
            let hash_input = cycle.wrapping_mul(2_654_435_761); // Knuth multiplicative hash
            let frac = (hash_input % 1000) as f64 / 1000.0;
            let random_ts = now_ts - retention + (frac * retention * 0.9); // 0-90% into retention window

            let rocks = state.rocks.clone();
            let old_ids = match tokio::task::spawn_blocking(move || {
                rocks.record_ids_from(random_ts, 200)
            }).await {
                Ok(Ok(ids)) => ids,
                _ => Vec::new(),
            };

            let mut added = 0usize;
            let mgr = witness_mgr.as_ref();
            for rid in old_ids {
                if candidates.len() >= batch_size { break; }
                if candidates.contains(&rid) { continue; }
                // Skip own records
                if let Ok(rec) = state.get_record(&rid) {
                    if creator_identity_hash(&rec) == our_hash { continue; }
                }
                // Only take records we haven't witnessed
                match mgr.get_attestations(&rid) {
                    Ok(atts) if atts.iter().any(|a| a.witness_hash == our_hash) => continue,
                    _ => {}
                }
                candidates.push(rid);
                added += 1;
            }
            added
        } else {
            0
        };

        // Phase 4: attestation discovery — pull attestations from peers for local
        // records that have 0 attestations in WitnessManager.
        //
        // Problem: after restart or NAT propagation failure, a node may have records
        // in RocksDB but zero attestations (WitnessManager has nothing, consensus
        // doesn't track them). These records are invisible to Phase 1 (needs consensus
        // entry) and can't be locally witnessed (already created by us, or already
        // witnessed but attestation lost). The only fix is outbound pull from a peer.
        //
        // This is NAT-safe: uses outbound PQ transport, no inbound connectivity needed.
        // Runs every 3rd cycle to limit overhead.
        let p4_discovered = if cycle.is_multiple_of(3) && cpus > 1 {
            // Get connected peer URLs
            let peer_urls: Vec<String> = {
                let peers = state.peers.read().await;
                peers.connected().iter().map(|p| p.base_url()).collect()
            };

            if peer_urls.is_empty() {
                0usize
            } else {
                let pq_offset = state.config.pq_port_offset;
                // Derive PQ addrs; skip any peer without a derivable addr (AUDIT-10: no HTTPS fallback).
                let peer_pq_addrs: Vec<String> = peer_urls
                    .iter()
                    .filter_map(|u| super::gossip::http_to_pq_addr(u, pq_offset))
                    .collect();
                if peer_pq_addrs.is_empty() {
                    0usize
                } else {

                // Sample records from RocksDB timestamp index with 0 attestations
                let since = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0)
                    - state.config.record_retention_secs.max(86400.0);

                let rocks = state.rocks.clone();
                let recent_ids = match tokio::task::spawn_blocking(move || {
                    rocks.recent_record_ids(since, 200)
                }).await {
                    Ok(Ok(ids)) => ids,
                    _ => Vec::new(),
                };

                // Filter to records with 0 attestations in WitnessManager
                let zero_att_rids: Vec<String> = {
                    let mgr = witness_mgr.as_ref();
                    recent_ids.into_iter()
                        .filter(|rid| {
                            // Skip own records
                            if let Ok(rec) = state.get_record(rid) {
                                if creator_identity_hash(&rec) == our_hash { return false; }
                            }
                            // Only records with 0 attestations locally
                            match mgr.get_attestations(rid) {
                                Ok(atts) if atts.is_empty() => true,
                                Err(_) => true,  // no entry = 0 attestations
                                _ => false,
                            }
                        })
                        .take(15)
                        .collect()
                }; // mgr dropped

                let mut discovered = 0usize;
                let mut all_feed: Vec<(String, String, f64)> = Vec::new();

                for rid in &zero_att_rids {
                    let peer_idx = (rid.as_bytes().first().copied().unwrap_or(0) as usize) % peer_pq_addrs.len();
                    let pq_addr = &peer_pq_addrs[peer_idx];
                    let body = match state.pq_client.query_attestations_for_record(pq_addr, rid).await {
                        Ok(Some(v)) => v,
                        _ => continue,
                    };
                    let atts = match body["attestations"].as_array() {
                        Some(a) if !a.is_empty() => a,
                        _ => continue,
                    };

                    // Verify and store attestations (sync block — drops mgr before next .await)
                    let new_atts: Vec<(String, String, f64)> = {
                        let mgr = witness_mgr.as_ref();
                        let mut batch = Vec::new();
                        for att in atts {
                            let wh = att["witness_hash"].as_str().unwrap_or("");
                            let sig_hex = att["signature"].as_str().unwrap_or("");
                            let ts = att["timestamp"].as_f64().unwrap_or(0.0);
                            let pk_hex = att["witness_public_key"].as_str().unwrap_or("");
                            if wh.is_empty() || sig_hex.is_empty() { continue; }
                            // Dedup: already stored?
                            if let Ok(existing) = mgr.get_attestations(rid) {
                                if existing.iter().any(|a| a.witness_hash == wh) { continue; }
                            }
                            let sig = match hex::decode(sig_hex) { Ok(s) => s, _ => continue };
                            let pk = match hex::decode(pk_hex) { Ok(p) if !p.is_empty() => p, _ => continue };
                            // Verify Dilithium3 signature
                            let signable = match state.get_record(rid) {
                                Ok(rec) => rec.signable_bytes(),
                                _ => continue,
                            };
                            match crate::crypto::pqc::dilithium3_verify(&signable, &sig, &pk) {
                                Ok(true) => {}
                                _ => continue,
                            }
                            let powas_nonce = att["powas_nonce"].as_u64();
                            let powas_difficulty = att["powas_difficulty"].as_u64();
                            let _ = mgr.store_attestation_with_powas(
                                rid, wh, &sig, ts, Some(&pk), powas_nonce, powas_difficulty,
                            );
                            batch.push((rid.clone(), wh.to_string(), ts));
                        }
                        batch
                    }; // mgr dropped

                    discovered += new_atts.len();
                    all_feed.extend(new_atts);
                }

                // Feed all discovered attestations to consensus
                if !all_feed.is_empty() {
                    let record_count = all_feed.iter()
                        .map(|(r, _, _)| r.as_str())
                        .collect::<std::collections::HashSet<_>>()
                        .len();
                    let outcome = state.batch_feed_attestations(&all_feed).await;
                    info!(
                        "auto-witness phase 4: discovered {discovered} attestations for {record_count} records from peers, {} settled",
                        outcome.settled.len()
                    );
                    super::reward::finalization_effects(&state, outcome.newly_finalized);
                }

                discovered
                }
            }
        } else {
            0
        };

        // Phase 5: settlement reconciliation — pull attestations by record_id
        // for UNSETTLED records that have some but not enough attestations.
        //
        // ROOT CAUSE: att-pull uses a watermark that advances forward.
        // Once the watermark passes an attestation's timestamp, that attestation can
        // never be pulled again. If the initial att-push failed and the watermark has
        // moved past it, the attestation is permanently lost in transit. Records get
        // stuck at <66.7% settlement forever with missing attestations that exist on
        // other nodes but this node will never see via normal att-pull.
        //
        // Fix: bypass the watermark entirely by requesting attestations for specific
        // record IDs from peers. This closes the propagation gap.
        // Runs every 2nd cycle. Samples up to 50 unsettled records per batch.
        // At ~1 min/cycle × 50 records/run = ~25 records/min throughput.
        // Skip Phase 5 on 1-core — HTTP requests to all peers + consensus lock
        // are too heavy when combined with the other phases.
        let p5_reconciled = if cycle.is_multiple_of(2) && unsettled_count > 0 && cpus > 1 {
            let peer_urls: Vec<String> = {
                let peers = state.peers.read().await;
                peers.connected().iter().map(|p| p.base_url()).collect()
            };
            let pq_offset = state.config.pq_port_offset;
            let peer_pq_addrs: Vec<String> = peer_urls
                .iter()
                .filter_map(|u| super::gossip::http_to_pq_addr(u, pq_offset))
                .collect();

            if peer_pq_addrs.is_empty() {
                0usize
            } else {
                // Get unsettled record IDs from consensus (already fetched in Phase 1)
                let unsettled_rids: Vec<String> = {
                    let consensus = state.consensus.lock_recover();
                    consensus.unsettled_summary()
                        .into_iter()
                        .take(50)
                        .map(|(rid, _, _)| rid)
                        .collect()
                };

                let mut reconciled = 0usize;
                let mut all_feed: Vec<(String, String, f64)> = Vec::new();
                let p5_start = std::time::Instant::now();

                for rid in &unsettled_rids {
                    // Time-box Phase 5 to 30s — don't block auto-witness loop
                    if p5_start.elapsed().as_secs() > 30 { break; }
                    // Query ALL connected peers for this record's attestations
                    // (not just one peer like Phase 4 — we need to find which peer
                    // has the missing attestation)
                    for pq_addr in &peer_pq_addrs {
                        let body = match state.pq_client.query_attestations_for_record(pq_addr, rid).await {
                            Ok(Some(v)) => v,
                            _ => continue,
                        };
                        let atts = match body["attestations"].as_array() {
                            Some(a) if !a.is_empty() => a,
                            _ => continue,
                        };

                        let new_atts: Vec<(String, String, f64)> = {
                            let mgr = witness_mgr.as_ref();
                            let mut batch = Vec::new();
                            for att in atts {
                                let wh = att["witness_hash"].as_str().unwrap_or("");
                                let sig_hex = att["signature"].as_str().unwrap_or("");
                                let ts = att["timestamp"].as_f64().unwrap_or(0.0);
                                let pk_hex = att["witness_public_key"].as_str().unwrap_or("");
                                if wh.is_empty() || sig_hex.is_empty() { continue; }
                                // Dedup: already stored?
                                if let Ok(existing) = mgr.get_attestations(rid) {
                                    if existing.iter().any(|a| a.witness_hash == wh) { continue; }
                                }
                                let sig = match hex::decode(sig_hex) { Ok(s) => s, _ => continue };
                                let pk = match hex::decode(pk_hex) { Ok(p) if !p.is_empty() => p, _ => continue };
                                // Verify Dilithium3 signature
                                let signable = match state.get_record(rid) {
                                    Ok(rec) => rec.signable_bytes(),
                                    _ => continue,
                                };
                                match crate::crypto::pqc::dilithium3_verify(&signable, &sig, &pk) {
                                    Ok(true) => {}
                                    _ => continue,
                                }
                                let powas_nonce = att["powas_nonce"].as_u64();
                                let powas_difficulty = att["powas_difficulty"].as_u64();
                                let _ = mgr.store_attestation_with_powas(
                                    rid, wh, &sig, ts, Some(&pk), powas_nonce, powas_difficulty,
                                );
                                batch.push((rid.clone(), wh.to_string(), ts));
                            }
                            batch
                        }; // mgr dropped

                        reconciled += new_atts.len();
                        all_feed.extend(new_atts);
                    }
                }

                // Feed all reconciled attestations to consensus
                if !all_feed.is_empty() {
                    let record_count = all_feed.iter()
                        .map(|(r, _, _)| r.as_str())
                        .collect::<std::collections::HashSet<_>>()
                        .len();
                    let outcome = state.batch_feed_attestations(&all_feed).await;
                    info!(
                        "auto-witness phase 5: reconciled {reconciled} attestations for {record_count} unsettled records from peers, {} settled",
                        outcome.settled.len()
                    );
                    super::reward::finalization_effects(&state, outcome.newly_finalized);
                }

                reconciled
            }
        } else {
            0
        };

        let to_witness = candidates;

        // Diagnostic log: trace candidate selection every 10th cycle
        if to_witness.is_empty() || cycle % 10 == 1 {
            info!(
                "auto-witness diag: cycle={cycle} zones={} unsettled={unsettled_count} p1={p1_candidates} p2_aw={already_witnessed_p2} p2b={p2b_added} p3_scan={p3_scanned} p3_add={p3_added} p3b={p3b_added} p4_disc={p4_discovered} p5_recon={p5_reconciled} to_witness={}",
                allowed_zones.len(), to_witness.len()
            );
        }

        let mut witnessed = 0u32;
        let mut skip_own = 0u32;
        let mut skip_zone = 0u32;
        let mut skip_dup = 0u32;
        let mut skip_miss = 0u32;
        let mut skip_seal_verify = 0u32;

        for record_id in &to_witness {
            // Check if we already witnessed this record
            {
                let mgr = witness_mgr.as_ref();
                if mgr.attestation_count(record_id).is_ok() {
                    // Simple check: if we already have our attestation, skip
                    if let Ok(atts) = mgr.get_attestations(record_id) {
                        if atts.iter().any(|a| a.witness_hash == our_hash) {
                            skip_dup += 1;
                            continue;
                        }
                    }
                }
            }

            // Get the record from storage (RocksDB first, SQLite fallback)
            let rid = record_id.clone();
            let record = match state.get_record(&rid) {
                Ok(rec) => rec,
                Err(e) => {
                    skip_miss += 1;
                    debug!("auto-witness storage miss for {}: {e}", &record_id[..record_id.len().min(16)]);
                    continue;
                }
            };

            // Don't witness our own records
            if creator_identity_hash(&record) == our_hash {
                skip_own += 1;
                continue;
            }

            // Skip sandbox zone records — trust earned there doesn't propagate (EMERGENT-MIND §5)
            if let Some(zone) = &record.zone {
                if zone.is_sandbox() {
                    continue;
                }
            }

            // Per-zone jury check: only attest records in zones we're selected for.
            // Gap 4 Phase C: resolve through the active ZoneRegistry so post-split
            // child zones route correctly; falls back to naive flat-modulo when
            // registry has no matching split.
            let record_zone = state.resolve_record_zone(&record.id);
            if !allowed_zones.contains(&record_zone) {
                skip_zone += 1;
                continue;
            }

            // R3-9 Decision B (ratified 2026-07-02): verify-before-co-sign for
            // epoch seals. Decline to co-sign a seal whose enumerated (or
            // re-derived, R3-8 absent-enumeration) record list disagrees with
            // our local view: definite omission (we hold MORE records in the
            // window than the seal claims), root mismatch at equal counts, or
            // we're still behind (candidate is naturally retried next cycle).
            // Declining is always safe — a co-signature is additive and honest
            // nodes still reach the 2/3 threshold. Balance intentionally None:
            // scope is record-list consistency, not balance reconciliation.
            match super::epoch::extract_epoch_seal(&record) {
                Ok(None) => {} // not an epoch seal — attest normally
                Ok(Some(seal)) => {
                    use super::epoch::WitnessVerification as WV;
                    let rocks = state.rocks.clone();
                    let verdict = tokio::task::spawn_blocking(move || {
                        super::epoch::witness_verify_seal(&seal, &*rocks, None)
                    })
                    .await;
                    match verdict {
                        Ok(WV::Verified) => {} // consistent — proceed to PoWaS + sign
                        Ok(other) => {
                            // `other` is never Verified here (prior arm), so the
                            // default bucket below can only be reached by the
                            // mismatch variants.
                            let ctr = match &other {
                                WV::MissingRecords { .. } => {
                                    &state.seal_verify_before_attest_withheld_behind_total
                                }
                                WV::RecordCountMismatch { local, proposed } if local < proposed => {
                                    &state.seal_verify_before_attest_withheld_behind_total
                                }
                                WV::RecordCountMismatch { .. } => {
                                    &state.seal_verify_before_attest_withheld_omission_total
                                }
                                _ => {
                                    &state.seal_verify_before_attest_withheld_root_mismatch_total
                                }
                            };
                            ctr.fetch_add(1, Ordering::Relaxed);
                            skip_seal_verify += 1;
                            debug!(
                                "auto-witness: withheld seal co-signature for {}: {other:?}",
                                &record_id[..record_id.len().min(16)]
                            );
                            continue;
                        }
                        Err(e) => {
                            // Verify task panicked/cancelled — never co-sign
                            // what we couldn't verify.
                            state
                                .seal_verify_before_attest_withheld_malformed_total
                                .fetch_add(1, Ordering::Relaxed);
                            skip_seal_verify += 1;
                            warn!("auto-witness: seal verify task failed for {}: {e}",
                                &record_id[..record_id.len().min(16)]);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // Carries epoch_op but doesn't parse as a seal — never
                    // co-sign what can't be parsed. Near-unreachable: ingest
                    // validation rejects malformed seals before storage.
                    state
                        .seal_verify_before_attest_withheld_malformed_total
                        .fetch_add(1, Ordering::Relaxed);
                    skip_seal_verify += 1;
                    debug!("auto-witness: withheld co-signature for unparseable seal {}: {e}",
                        &record_id[..record_id.len().min(16)]);
                    continue;
                }
            }

            // Solve PoWaS puzzle (Protocol v0.6.1 Section 11.1)
            let our_stake = {
                let ledger = state.ledger.read().await;
                ledger.staked(&our_hash)
            };
            let our_pk_clone = state.identity.public_key.clone();
            let rid_clone = record_id.clone();
            let powas_proof = match tokio::task::spawn_blocking(move || {
                super::powas::solve(&rid_clone, &our_pk_clone, our_stake)
            })
            .await
            {
                Ok(Some(proof)) => proof,
                Ok(None) => {
                    warn!("PoWaS puzzle unsolvable for {}", &record_id[..record_id.len().min(16)]);
                    state.auto_witness_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                Err(e) => {
                    warn!("PoWaS solve spawn failed: {e}");
                    continue;
                }
            };

            // Counter-sign the record's signable bytes (deterministic, unlike to_bytes())
            let signable = record.signable_bytes();
            match state.identity.sign(&signable) {
                Ok(sig) => {
                    // Jitter attestation timestamp by 0-2s to decorrelate witnesses.
                    // Without jitter, all witnesses in the same auto-witness cycle produce
                    // timestamps within <10ms, causing TIMING_CLUSTER_THRESHOLD_SECS (0.5s)
                    // to merge them into one cluster. With 3 witnesses per zone and
                    // CONFIRMED_MIN_CLUSTERS=3, settlement becomes unreachable.
                    // Jitter ensures independent witnesses produce distinct timing clusters.
                    let jitter = {
                        let hash = crate::crypto::hash::sha3_256(
                            format!("jitter:{}:{}", record_id, state.identity.identity_hash).as_bytes()
                        );
                        // Use first 4 bytes of hash as u32, scale to 0.0-2.0 seconds
                        let raw = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
                        (raw as f64 / u32::MAX as f64) * 2.0
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0)
                        + jitter;

                    let our_pk = state.identity.public_key.clone();
                    let stored = {
                        let mgr = witness_mgr.as_ref();
                        mgr.store_attestation_with_powas(
                            record_id, &our_hash, &sig, now, Some(&our_pk),
                            Some(powas_proof.nonce), Some(powas_proof.difficulty),
                        )
                    };
                    match stored {
                        Ok(true) => {
                            witnessed += 1;
                            state.auto_witness_records_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Feed into consensus engine
                            let outcome = state.feed_attestation(record_id, &our_hash, now).await;
                            if outcome.first_finalization {
                                super::reward::finalization_effects(
                                    &state,
                                    vec![record_id.clone()],
                                );
                            }
                            // Push attestation to peers (fire-and-forget)
                            let att = AttestationRecord {
                                record_id: record_id.clone(),
                                witness_hash: our_hash.clone(),
                                signature: sig.clone(),
                                timestamp: now,
                                witness_public_key: Some(our_pk.clone()),
                                powas_nonce: Some(powas_proof.nonce),
                                powas_difficulty: Some(powas_proof.difficulty),
                            };
                            let s = state.clone();
                            tokio::spawn(async move {
                                gossip::push_attestation_to_peers(&s, &att).await;
                            });
                        }
                        Ok(false) => {} // duplicate, already witnessed
                        Err(e) => {
                            warn!("failed to store attestation: {e}");
                        }
                    }
                }
                Err(e) => {
                    state.auto_witness_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!("failed to sign for witness: {e}");
                }
            }
        }

        if witnessed > 0 {
            info!("auto-witnessed {witnessed} records this cycle");
        }
        if witnessed == 0 && !to_witness.is_empty() {
            info!(
                "auto-witness: 0 attested from {} candidates (skip_own={skip_own} skip_zone={skip_zone} skip_dup={skip_dup} skip_miss={skip_miss} skip_seal_verify={skip_seal_verify})"
                , to_witness.len()
            );
        }

        // ── Re-push attestations for unsettled records with low counts ──
        // After restart, attestations from previous sessions may be in local
        // WitnessManager but never reached other peers (push was fire-and-forget,
        // peer was unreachable, fast-forward skipped the time range, etc.).
        // Every 5th cycle, pick a sample of unsettled records where we already
        // have an attestation and re-push it to peers.
        if cycle.is_multiple_of(5) {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let repush_atts: Vec<AttestationRecord> = {
                let mgr = witness_mgr.as_ref();
                let consensus = state.consensus.lock_recover();
                let unsettled = consensus.unsettled_summary();
                let mut atts = Vec::new();
                for (rid, att_count, _) in &unsettled {
                    if atts.len() >= 20 { break; }
                    if *att_count >= 5 { continue; }
                    if let Ok(wm_atts) = mgr.get_attestations(rid) {
                        for a in wm_atts {
                            if a.witness_hash == our_hash {
                                // Zombie guard: don't re-push attestations for records
                                // that are past the settlement horizon. Re-pushing them
                                // produces `att-push REJECTED 400` storms because the
                                // underlying record has been GC'd from peers' active
                                // disk, so signature verification fails on every peer.
                                if is_repush_zombie(now_secs, a.timestamp) {
                                    state
                                        .auto_witness_zombie_repush_skipped_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                atts.push(a);
                                break;
                            }
                        }
                    }
                }
                atts
            }; // locks dropped
            if !repush_atts.is_empty() {
                let count = repush_atts.len();
                // Clear dedup entries so push_attestation_to_peers doesn't skip them
                {
                    let mut seen = state.attestation_seen.lock_recover();
                    for att in &repush_atts {
                        let key = format!("{}:{}", att.record_id, att.witness_hash);
                        seen.remove(&key);
                    }
                }
                for att in repush_atts {
                    let s = state.clone();
                    tokio::spawn(async move {
                        gossip::push_attestation_to_peers(&s, &att).await;
                    });
                }
                debug!("auto-witness: re-pushed {count} attestations for unsettled records");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_attestation_is_not_zombie() {
        let now = 1_700_000_000.0_f64;
        let att = now - 30.0; // 30s old, well within in-zone finality
        assert!(!is_repush_zombie(now, att));
    }

    #[test]
    fn one_hour_old_attestation_is_not_zombie() {
        // Hard-discard ceiling territory but not yet a zombie — the record
        // *might* still settle on slow peers, so we still try.
        let now = 1_700_000_000.0_f64;
        let att = now - 3_600.0;
        assert!(!is_repush_zombie(now, att));
    }

    #[test]
    fn just_past_24h_attestation_is_zombie() {
        let now = 1_700_000_000.0_f64;
        let att = now - REPUSH_MAX_AGE_SECS - 1.0;
        assert!(is_repush_zombie(now, att));
    }

    #[test]
    fn week_old_attestation_is_zombie() {
        // 28-day-old testnet zombies (the actual failure mode that motivated
        // the guard) must hit the cutoff with margin.
        let now = 1_700_000_000.0_f64;
        let att = now - (28.0 * 86_400.0);
        assert!(is_repush_zombie(now, att));
    }

    #[test]
    fn future_dated_attestation_is_not_zombie() {
        // Clock skew: peer wrote a slightly-future timestamp. Subtraction
        // goes negative; should NOT trigger the guard.
        let now = 1_700_000_000.0_f64;
        let att = now + 60.0;
        assert!(!is_repush_zombie(now, att));
    }

    // Lift `is_repush_zombie` coverage with the boundary-precision +
    // algebraic-invariant tests that round out the existing five scenario
    // tests. Same fixture-free pattern (no NodeState,
    // no WitnessManager) — each test exercises a previously-unpinned property
    // of the pure helper or its `REPUSH_MAX_AGE_SECS` constant.

    #[test]
    fn batch_ff_exactly_at_twenty_four_hour_boundary_is_not_zombie_strict_inequality() {
        // Pins the `>` strict inequality at auto_witness.rs:38. At age ==
        // REPUSH_MAX_AGE_SECS exactly, the predicate must return false — a
        // record's attestation 24h00m00s old is still re-pushable. A future
        // refactor that flips `>` to `>=` would silently widen the zombie
        // window by one f64 ULP and start reaping records that are right at
        // the published cutoff. Distinct from `just_past_24h_attestation_is_zombie`
        // which uses `- 1.0` (strictly past) — this pin is the exact-equal
        // case that the strict-inequality semantics protect.
        let now = 1_700_000_000.0_f64;
        let att = now - REPUSH_MAX_AGE_SECS;
        assert!(
            !is_repush_zombie(now, att),
            "age == REPUSH_MAX_AGE_SECS is NOT a zombie under strict `>` semantics"
        );
    }

    #[test]
    fn batch_ff_subsecond_past_twenty_four_hour_boundary_is_zombie_pins_f64_precision() {
        // Pins f64 sub-second precision at the cutoff. At age == REPUSH_MAX_AGE_SECS + 1ms,
        // the predicate MUST flip to true — even though the difference is below
        // the integer-second `as u64` cast the operator log uses. Pins that the
        // pure helper's resolution is finer than the log's display resolution
        // (the helper must trigger before the operator sees the threshold cross).
        // f64 mantissa at 1.7e9 still resolves ~1e-6 ulp — 1e-3 is well within.
        let now = 1_700_000_000.0_f64;
        let att = now - REPUSH_MAX_AGE_SECS - 0.001;
        assert!(
            is_repush_zombie(now, att),
            "age == REPUSH_MAX_AGE_SECS + 1ms must trip the zombie guard despite int-second log resolution"
        );
    }

    #[test]
    fn batch_ff_zero_age_attestation_is_not_zombie() {
        // Degenerate boundary: attestation timestamp == now exactly (age == 0).
        // A just-emitted attestation is the freshest possible signal and MUST
        // NOT be classified as a zombie. Pins the (now - att == 0) case which
        // sits below every other scenario test in the file (the others all
        // use `now - K` with K > 0). Catches a future refactor that flips the
        // predicate to `now - att != 0` or otherwise treats zero-age as "no
        // signal" by accident.
        let now = 1_700_000_000.0_f64;
        let att = now;
        assert_eq!(now - att, 0.0, "age must be exactly zero for this pin");
        assert!(
            !is_repush_zombie(now, att),
            "zero-age attestation must NOT trigger the zombie guard"
        );
    }

    #[test]
    fn batch_ff_repush_max_age_secs_equals_twenty_four_hours_in_seconds_exactly() {
        // Pins the documented constant value at auto_witness.rs:32 — 24h in
        // seconds = 86_400. Decomposed via 24 × 3600 to surface a future
        // tuner who flips the literal to e.g. 86_000 (24h minus a typo) or
        // 864_000 (10× off by digit-shift): both would compile fine but
        // silently widen / narrow the zombie window by hours-to-days. The
        // existing tests only use `REPUSH_MAX_AGE_SECS` symbolically — none
        // pin its numerical value.
        assert_eq!(
            REPUSH_MAX_AGE_SECS, 86_400.0_f64,
            "REPUSH_MAX_AGE_SECS must equal exactly 24h in seconds (86_400.0)"
        );
        // Decompose via 24 × 3600 to surface a value mismatch via either factor.
        assert_eq!(
            REPUSH_MAX_AGE_SECS,
            24.0_f64 * 3600.0_f64,
            "REPUSH_MAX_AGE_SECS must decompose to 24h × 3600s/h"
        );
        // Lossless cast to u64 — the operator-facing log surface formats ages
        // as integer seconds; a fractional constant would silently round.
        assert_eq!(
            REPUSH_MAX_AGE_SECS as u64, 86_400_u64,
            "REPUSH_MAX_AGE_SECS must cast losslessly to 86_400 as u64"
        );
        assert_eq!(
            (REPUSH_MAX_AGE_SECS as u64) as f64,
            REPUSH_MAX_AGE_SECS,
            "REPUSH_MAX_AGE_SECS f64→u64→f64 round-trip must be lossless (no fractional part)"
        );
    }

    #[test]
    fn batch_ff_repush_max_age_secs_is_seventy_two_times_hard_discard_ceiling() {
        // Pins the documented "72× headroom over the hard-discard ceiling"
        // algebraic invariant from auto_witness.rs:30-31. Hard-discard
        // ceiling = `PENDING_HARD_DISCARD_TIMEOUT_SECS` = 1200s
        // (pending_drain.rs:204). 86_400 / 1200 = 72 exactly. A tuner who
        // bumps the hard-discard ceiling from 1200 → e.g. 2400 (2× tighter
        // settlement window) without also adjusting REPUSH_MAX_AGE_SECS
        // shrinks the documented headroom from 72× to 36× — the pin catches
        // the drift between the two modules at compile-cycle test time
        // instead of audit-doc proofread time.
        use super::super::pending_drain::PENDING_HARD_DISCARD_TIMEOUT_SECS;
        assert_eq!(
            PENDING_HARD_DISCARD_TIMEOUT_SECS, 1200.0_f64,
            "hard-discard ceiling pinned at 1200s for the 72× ratio to hold"
        );
        let headroom = REPUSH_MAX_AGE_SECS / PENDING_HARD_DISCARD_TIMEOUT_SECS;
        assert_eq!(
            headroom, 72.0_f64,
            "REPUSH_MAX_AGE_SECS / PENDING_HARD_DISCARD_TIMEOUT_SECS must equal 72.0 (doc-comment invariant)"
        );
    }

    // LOCAL-vs-aggregate stake pins. An earlier reading framed the
    // genesis anchor as a "bootstrap-stake
    // pathology" on `aw_ns>0` + `ledger_staked=0`. The correction
    // established that the auto_witness skip path at
    // `auto_witness.rs:118` calls `ledger.staked(&our_hash)` — LOCAL
    // identity stake — NOT `ledger.total_staked` — the whole-ledger
    // aggregate. A future refactor that confuses the two (e.g. reads
    // the aggregate for the skip decision) would silently turn the
    // genesis-anchor case into a false-positive "we're staked, attest!"
    // and reintroduce that misread at runtime. These pins make
    // that regression break loudly at test-time.
    //
    // Fixture-free pure-state tests on `LedgerState::staked()` — the
    // same predicate the loop calls. No NodeState, no WitnessManager.

    #[test]
    fn batch_440_staked_returns_local_identity_stake_not_aggregate() {
        // PIN: `staked(our_hash)` returns the per-account `Account.staked`,
        // distinct from the whole-ledger `total_staked` aggregate. Build a
        // ledger where the two values diverge (our 1M vs aggregate 51M),
        // and assert the per-identity read returns 1M, not 51M.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        let our_hash = "our_identity_hash_hex_string";
        let peer_hash = "peer_identity_hash_hex_string";
        ledger.accounts.insert(
            our_hash.to_string(),
            AccountState { staked: 1_000_000, ..Default::default() },
        );
        ledger.accounts.insert(
            peer_hash.to_string(),
            AccountState { staked: 50_000_000, ..Default::default() },
        );
        ledger.total_staked = 51_000_000;

        let our_stake = ledger.staked(our_hash);
        assert_eq!(
            our_stake, 1_000_000,
            "staked(our_hash) must return our account's per-identity staked field"
        );
        assert_ne!(
            our_stake, ledger.total_staked,
            "staked(our_hash) MUST differ from total_staked aggregate when peers exist — §440 invariant"
        );
    }

    #[test]
    fn batch_440_staked_zero_for_unstaked_local_identity_even_when_aggregate_nonzero() {
        // PIN: the genesis-anchor case. The cluster
        // shows `ledger_staked > 0` (50.4T cluster aggregate) but the local
        // identity (anchor) has zero stake. The skip-not-staked path MUST
        // fire under this configuration — the earlier "peer-rejection"
        // framing was wrong; the mechanism is local-stake-is-zero.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        let our_hash = "anchor_genesis_authority_hash";
        let peer_hash = "witness_with_stake_hash";
        ledger.accounts.insert(
            our_hash.to_string(),
            AccountState {
                staked: 0,
                available: 10_000_000_000_000,
                ..Default::default()
            },
        );
        ledger.accounts.insert(
            peer_hash.to_string(),
            AccountState { staked: 50_400_000_000_000, ..Default::default() },
        );
        ledger.total_staked = 50_400_000_000_000;

        assert_eq!(
            ledger.staked(our_hash),
            0,
            "anchor with zero own-stake returns 0 from staked() — triggers skip-not-staked path"
        );
        assert!(
            ledger.total_staked > 0,
            "aggregate must be non-zero to pin the divergence — this is the genesis-anchor configuration"
        );
        // The auto_witness.rs:130 skip decision is `staked_amount == 0`.
        // Verify the predicate evaluates true here (skip fires) despite
        // the aggregate being huge.
        assert!(
            ledger.staked(our_hash) == 0,
            "skip-not-staked predicate (staked_amount == 0) must evaluate true for this configuration"
        );
    }

    #[test]
    fn batch_440_staked_zero_for_unknown_hash() {
        // PIN: `staked()` for a hash with NO account entry returns 0 — not
        // panic, not lookup-fail. Bootstrap nodes have `our_hash` set but
        // no ledger entry yet; the skip path must fire cleanly without
        // error. Catches a refactor that swaps the `unwrap_or(0)` for
        // `unwrap()` or `expect(...)` on missing accounts.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        ledger.accounts.insert(
            "peer".to_string(),
            AccountState { staked: 1_000_000, ..Default::default() },
        );
        ledger.total_staked = 1_000_000;

        assert_eq!(
            ledger.staked("never_seen_hash"),
            0,
            "unknown hash returns 0 from staked() — no panic on missing account"
        );
        assert_eq!(
            ledger.staked(""),
            0,
            "empty-string hash returns 0 — no panic on degenerate lookup"
        );
    }

    #[test]
    fn batch_440_staked_independent_of_total_staked_field_value() {
        // PIN: `staked(hash)` reads `accounts.get(hash).map(|a| a.staked)`.
        // The `total_staked` field is independent — mutated at
        // ledger.rs:1148/1203/1332 on stake/unstake/slash events, but
        // `staked()` never consults it. Set `total_staked` to a wildly
        // wrong value and verify the per-account read is unaffected. Pins
        // that the skip decision is robust to aggregate-counter drift
        // (which can happen during slash/unstake-replay races) — the
        // skip decision derives from the per-account truth, not the
        // potentially-stale aggregate.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        let our_hash = "our_hash";
        ledger.accounts.insert(
            our_hash.to_string(),
            AccountState { staked: 7_777_777, ..Default::default() },
        );
        ledger.total_staked = u64::MAX;

        assert_eq!(
            ledger.staked(our_hash),
            7_777_777,
            "staked() reads per-account field, NOT the aggregate — even when aggregate is u64::MAX"
        );
    }

    #[test]
    fn batch_440_fresh_ledger_returns_zero_staked_for_any_hash() {
        // PIN: a freshly-constructed `LedgerState::new()` returns 0 from
        // `staked()` for any input. Bootstrap-genesis case: before any
        // stake records are applied, the auto_witness skip-not-staked
        // path must fire for ALL hashes. Pins that the empty-ledger path
        // is well-defined — no default-staked, no implicit genesis stake.
        use crate::accounting::ledger::LedgerState;
        let ledger = LedgerState::new();
        assert_eq!(ledger.staked("any_hash"), 0);
        assert_eq!(ledger.staked(""), 0);
        assert_eq!(ledger.staked("a"), 0);
        assert_eq!(
            ledger.total_staked, 0,
            "fresh ledger has zero aggregate — pins the bootstrap-genesis baseline"
        );
    }
}
