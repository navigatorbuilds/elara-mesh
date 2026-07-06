//! Sync route handlers: /merkle_root, /delta_sync, /attestations, /slash,
//! /snapshot, /snapshot/latest, /snapshot/fast.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use tracing::{debug, warn};

use crate::ZoneId;
use crate::crypto::hash::sha3_256_hex;
use crate::crypto::pqc::dilithium3_verify;
use crate::errors::ElaraError;
use crate::network::gossip;
use crate::network::state::NodeState;
use crate::network::sync::BloomFilter;
use crate::network::LockRecover;
use crate::network::RwLockRecover;

use super::super::server::AppError;

// ─── /merkle_root ────────────────────────────────────────────────────────────

pub async fn merkle_root(State(state): State<Arc<NodeState>>) -> Result<Json<serde_json::Value>, AppError> {
    let state2 = state.clone();
    let root = tokio::task::spawn_blocking(move || {
        // O(zone_count) RocksDB reads via SparseMerkleTree — replaces O(all_records) scan
        crate::network::merkle::global_merkle_root(&state2.rocks)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    Ok(Json(serde_json::json!({
        "root": hex::encode(root),
    })))
}

// ─── /convergence ────────────────────────────────────────────────────────────
//
// Read-only endpoint that exposes per-peer DAG divergence to operators.
//
// For each connected peer it reports:
//   * our merkle root + record count (computed once)
//   * the peer's merkle root + record count (live PQ /status + /merkle_root)
//   * `in_sync` flag and a count-based delta estimate
//
// Per NETWORK-HARDENING-ROADMAP Tier 1.2 — gives ops a single curl to detect
// fork divergence across the fleet without grepping logs. Reuses existing
// `network::fork::check_forks_with_lock_timeout()` so behavior matches the
// periodic fork monitor but bounds slot-mutex waits. The
// fork-monitor / heal path keeps the unbounded variant — it must serialize.
//
// Performance: hits each connected peer over PQ (one /merkle_root + one
// /status RPC). The 2s slot-lock timeout caps worst-case wait at 4s/peer
// when a heal cycle is mid-flight on the same peer; the call itself remains
// behind the existing 30s DEFAULT_CALL_TIMEOUT once the slot is acquired.

const CONVERGENCE_LOCK_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(2);

pub async fn convergence(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut checks = crate::network::fork::check_forks_with_lock_timeout(
        &state,
        CONVERGENCE_LOCK_TIMEOUT,
    )
    .await;

    let our_root = hex::encode(crate::network::merkle::global_merkle_root(&state.rocks));
    let our_count = state.record_count().unwrap_or(0);

    let total_checked = checks.len();
    let in_sync = checks.iter().filter(|c| c.in_sync).count();
    let diverged = total_checked.saturating_sub(in_sync);

    // Cap the serialized per-peer array so the response can't balloon with a
    // node's full connection set at 10K+ peers. `peers_checked`/`in_sync`/
    // `diverged` are computed over ALL peers BEFORE the cap, so they stay honest
    // (truncation detectable as `peers.len() < peers_checked`). The fork check
    // itself stays uncapped — the heal path needs every peer; only the JSON view
    // is bounded. SCALE RULE: bounded, always.
    const MAX_PEERS_IN_RESPONSE: usize = 1000;
    checks.truncate(MAX_PEERS_IN_RESPONSE);

    Ok(Json(serde_json::json!({
        "our_root": our_root,
        "our_record_count": our_count,
        "peers_checked": total_checked,
        "peers_in_sync": in_sync,
        "peers_diverged": diverged,
        "peers": checks,
    })))
}

// ─── /delta_sync ─────────────────────────────────────────────────────────────

pub async fn delta_sync(
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    // Defense-in-depth twin of handle_delta_sync's `guard_command_body`: the
    // `delta_sync_body_cap()` route layer (`DefaultBodyLimit`) already 413s an
    // oversized body at the extractor, but this in-handler check makes the cap
    // routing-independent (HTTP/PQ parity) so a future re-registration that drops
    // the layer can't silently un-cap the bloom decode. Precedes the served bump.
    if body.len() > crate::network::sync::MAX_DELTA_SYNC_BLOOM_BODY {
        return Err(ElaraError::Wire(format!(
            "delta_sync bloom body too large: {} bytes (max {})",
            body.len(),
            crate::network::sync::MAX_DELTA_SYNC_BLOOM_BODY
        ))
        .into());
    }
    let their_bloom = BloomFilter::from_bytes(&body)?;
    // Server-side serve telemetry: count every delta_sync request we actually
    // process (valid bloom), including the low-RAM skip path below — the seed's
    // primary "am I serving sync?" signal. CLIENT-side attempts (pulls this node
    // initiates) live in delta_sync_attempts_total. Relaxed: monotonic counter.
    state
        .delta_sync_served_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.stamp_inbound_sync();

    // Scale default batch size by available RAM to limit peak memory.
    let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();

    // On ≤2GB nodes, skip the full record_ids() scan entirely.
    // record_ids() iterates ALL entries in CF_RECORDS, decompressing 6GB+ of
    // stale SST files through a 32MB block cache. The allocation churn causes
    // ~1.5GB jemalloc fragmentation that never gets returned to the OS.
    // Peers will still sync from this node via /records (timestamp-paginated).
    if ram_gb <= 2 {
        return Ok(Json(serde_json::json!({
            "records": Vec::<String>::new(),
            "total_missing": 0,
            "offset": 0,
            "batch_size": 0,
            "has_more": false,
            "scan_hit_cap": false,
        })));
    }

    let default_batch = if ram_gb <= 4 { 200 } else { 500 };
    let max_batch = if ram_gb <= 4 { 500 } else { 2000 };
    let batch_size: usize = headers
        .get("x-delta-batch-size")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_batch)
        .min(max_batch);

    let offset: usize = headers
        .get("x-delta-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Mirror of the PQ-side server bound, applied to the HTTP
    // delta_sync path. Previously this used `for_each_record_id` (O(all_records)
    // CF_RECORDS sweep), which at 10M records burned 30s+ and timed out HTTP
    // clients before the response could land. Now seek CF_IDX_TIMESTAMP from
    // `since` (sent by the client; defaults to 0 = full sweep for legacy
    // clients) and hard-cap at MAX_SCAN entries. `scan_hit_cap` flips true and
    // increments `elara_delta_sync_scan_hit_cap_total` whenever the cap binds —
    // operator signal that a peer's window exceeds 50K records and snapshot
    // sync (gap #7) is the right catch-up path.
    let since: f64 = headers
        .get("x-delta-since")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    // Scan consts + page assembly live in network/sync.rs::build_delta_page
    // (shared with the PQ twin — parity by construction).

    // Cursor parse (delta-sync cross-page cursor, audit 2026-07-05) happens
    // BEFORE spawn_blocking: malformed → 400, counted, never a silent
    // fallback to offset paging.
    let cursor_raw: Option<Vec<u8>> = match headers
        .get("x-delta-cursor")
        .and_then(|v| v.to_str().ok())
    {
        Some(hex_str) => match crate::network::sync::parse_sync_cursor(hex_str) {
            Ok(raw) => Some(raw),
            Err(e) => {
                state
                    .delta_sync_cursor_reject_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e.into());
            }
        },
        None => None,
    };
    if cursor_raw.is_some() {
        state
            .delta_sync_cursor_pages_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    let state2 = state.clone();
    let page = tokio::task::spawn_blocking(
        move || -> Result<crate::network::sync::DeltaPage, ElaraError> {
            crate::network::sync::build_delta_page(
                &state2.rocks,
                &their_bloom,
                since,
                offset,
                batch_size,
                cursor_raw.as_deref(),
            )
        },
    )
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    if page.scan_hit_cap == Some(true) {
        state
            .delta_sync_scan_hit_cap_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    let hex_records: Vec<String> = page.records_wire.iter().map(hex::encode).collect();
    state
        .delta_sync_served_records_total
        .fetch_add(hex_records.len() as u64, std::sync::atomic::Ordering::Relaxed);

    // Twin response shape lives in delta_page_json (network/sync.rs) so the
    // PQ handler can't drift from this one (I5).
    Ok(Json(crate::network::sync::delta_page_json(
        &page,
        hex_records,
        offset,
    )))
}

// ─── /attestations ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AttestationQuery {
    record_id: Option<String>,
    since: Option<f64>,
    limit: Option<usize>,
}

pub async fn query_attestations(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<AttestationQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mgr = state.witness_mgr.as_ref();

    if let Some(record_id) = &params.record_id {
        // Bounded page, not the unbounded internal read: per-record cardinality
        // is attacker-controlled (any verifying keypair is stored), so an
        // uncapped by-record response is an amplification surface. The since
        // branch below has always been limit-capped; this is its parity.
        let (atts, capped) = mgr.get_attestations_page(
            record_id,
            crate::network::witness::MAX_ATTESTATIONS_PER_RECORD_READ,
        )?;
        let list: Vec<serde_json::Value> = atts.iter().map(|a| {
            let mut v = serde_json::json!({
                "record_id": a.record_id,
                "witness_hash": a.witness_hash,
                "signature": hex::encode(&a.signature),
                "timestamp": a.timestamp,
            });
            if let Some(pk) = &a.witness_public_key {
                v["witness_public_key"] = serde_json::json!(hex::encode(pk));
            }
            v
        }).collect();
        Ok(Json(serde_json::json!({
            "record_id": record_id,
            "attestations": list,
            "capped": capped,
        })))
    } else {
        let since = params.since.unwrap_or(0.0);
        let limit = params.limit.unwrap_or(100).min(10_000);
        let atts = mgr.get_attestations_since(since, limit)?;
        let list: Vec<serde_json::Value> = atts.iter().map(|a| {
            let mut v = serde_json::json!({
                "record_id": a.record_id,
                "witness_hash": a.witness_hash,
                "signature": hex::encode(&a.signature),
                "timestamp": a.timestamp,
            });
            if let Some(pk) = &a.witness_public_key {
                v["witness_public_key"] = serde_json::json!(hex::encode(pk));
            }
            v
        }).collect();
        Ok(Json(serde_json::json!({
            "attestations": list,
        })))
    }
}

#[derive(serde::Deserialize)]
pub struct AttestationSubmit {
    record_id: String,
    witness_hash: String,
    signature: String,
    timestamp: f64,
    witness_public_key: Option<String>,
    powas_nonce: Option<u64>,
    powas_difficulty: Option<u64>,
}

pub async fn receive_attestation(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<AttestationSubmit>,
) -> Result<Json<serde_json::Value>, AppError> {
    use std::sync::atomic::Ordering::Relaxed;

    let sig_bytes = hex::decode(&body.signature)
        .map_err(|e| {
            state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
            ElaraError::Wire(format!("bad signature hex: {e}"))
        })?;

    if sig_bytes.is_empty() {
        state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
        return Err(ElaraError::InvalidSignature.into());
    }

    // Check negative cache for known-bad attestation signatures
    {
        let bad = state.attestation_bad_sigs.lock_recover();
        let key = format!("{}:{}", body.record_id, body.witness_hash);
        if bad.contains(&key) {
            state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
            return Err(ElaraError::InvalidSignature.into());
        }
    }

    // Resolve the witness public key. Either the submitter supplies it inline
    // (hex-encoded) or we look it up from the identity registry (CF_IDENTITIES)
    // by witness_hash. If neither source yields a pubkey we MUST reject —
    // accepting an attestation without Dilithium3 verification lets any peer
    // forge witness signatures (AUDIT-1, 2026-04-22).
    let pk: Vec<u8> = if let Some(pk_hex) = &body.witness_public_key {
        let pk = hex::decode(pk_hex)
            .map_err(|e| {
                state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
                ElaraError::Wire(format!("bad public key hex: {e}"))
            })?;
        let computed_hash = sha3_256_hex(&pk);
        if computed_hash != body.witness_hash {
            warn!(
                "attestation rejected: pubkey hash {} != witness_hash {}",
                &computed_hash[..16], body.witness_hash.chars().take(16).collect::<String>()
            );
            state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
            return Err(ElaraError::InvalidSignature.into());
        }
        pk
    } else {
        match state.rocks.get_public_key(&body.witness_hash) {
            Some(pk) => pk,
            None => {
                warn!(
                    "attestation rejected: no public key provided and witness {} not in identity registry",
                    body.witness_hash.chars().take(16).collect::<String>()
                );
                state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
                return Err(ElaraError::InvalidSignature.into());
            }
        }
    };

    // Verify Dilithium3 signature against the record's signable bytes. If the
    // record isn't local yet, buffer the attestation with the resolved pubkey
    // so the verification runs when the record arrives.
    let record_id = body.record_id.clone();
    let signable_result = state.get_record(&record_id)
        .map(|rec| rec.signable_bytes());

    match signable_result {
        Ok(signable) => {
            if !dilithium3_verify(&signable, &sig_bytes, &pk)? {
                warn!(
                    "attestation rejected: invalid signature from {}",
                    body.witness_hash.chars().take(16).collect::<String>()
                );
                let mut bad = state.attestation_bad_sigs.lock_recover();
                bad.insert(format!("{}:{}", body.record_id, body.witness_hash));
                state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
                return Err(ElaraError::InvalidSignature.into());
            }
        }
        Err(_) => {
            // Record not in local storage — can't verify signature yet.
            // Buffer the attestation so it can be verified when the record arrives.
            // This is critical for NAT'd nodes: they push attestations to VPS nodes
            // that may not have the record yet. Without buffering, those attestations
            // are permanently lost (VPS can't pull from NAT'd nodes).
            let deferred = crate::network::state::DeferredAttestation {
                witness_hash: body.witness_hash.clone(),
                signature: sig_bytes,
                timestamp: body.timestamp,
                witness_public_key: Some(pk.clone()),
                powas_nonce: body.powas_nonce,
                powas_difficulty: body.powas_difficulty,
                received_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            };
            {
                let now_ts = deferred.received_at;
                let mut buf = state.deferred_attestations.lock().unwrap_or_else(|e| e.into_inner());
                // Amortized TTL sweep + witness-dedup'd bounded push + O(1)
                // saturation eviction — shared with the PQ twin via
                // DeferredAttestationBuf. This HTTP path had drifted: it swept
                // O(buckets × atts) on EVERY message and had NO per-record cap
                // (dedup only), both fixed by going through the shared buffer
                // (2026-07-02 post-handshake audit).
                buf.maybe_sweep_expired(now_ts);
                if buf.push_bounded(
                    &record_id,
                    deferred,
                    now_ts,
                    crate::network::state::MAX_DEFERRED_ATTS_PER_RECORD,
                ) {
                    state.attestation_deferred_evicted_total.fetch_add(1, Relaxed);
                }
                buf.evict_oldest_if_saturated();
            }
            debug!(
                "attestation deferred: record {} not in local storage, buffered sig from {}",
                &record_id[..record_id.len().min(16)],
                body.witness_hash.chars().take(16).collect::<String>()
            );
            state.attestation_receive_deferred_total.fetch_add(1, Relaxed);
            return Ok(Json(serde_json::json!({
                "status": "deferred",
                "record_id": record_id,
            })));
        }
    }

    let pubkey_bytes: Option<Vec<u8>> = Some(pk);

    // Verify PoWaS proof if present
    if let (Some(nonce), Some(difficulty)) = (body.powas_nonce, body.powas_difficulty) {
        if let Some(pk) = &pubkey_bytes {
            let witness_stake = {
                let ledger = state.ledger.read().await;
                ledger.staked(&body.witness_hash)
            };
            if witness_stake > 0 {
                let proof = crate::network::powas::PoWaSProof { nonce, difficulty };
                if !crate::network::powas::verify(&body.record_id, pk, witness_stake, &proof) {
                    warn!(
                        "attestation rejected: invalid PoWaS proof from {}",
                        body.witness_hash.chars().take(16).collect::<String>()
                    );
                    state.attestation_receive_rejected_bad_powas_total.fetch_add(1, Relaxed);
                    return Err(ElaraError::Wire("invalid PoWaS proof".into()).into());
                }
            }
        }
    }

    // Sybil defense gate
    if body.witness_hash != state.config.genesis_authority {
        // Extract stake from ledger then DROP the read lock before acquiring trust.
        // Previously held ledger.read() across trust.read().await — on 1-core nodes
        // this blocked state_core's ledger.write() for 5-12s per attestation.
        let witness_staked = {
            let ledger = state.ledger.read().await;
            ledger.staked(&body.witness_hash)
        };
        const MIN_WITNESS_STAKE: u64 = crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;
        if witness_staked < MIN_WITNESS_STAKE {
            // Tier 4.6 bootstrap-pathology: defer instead of reject. Sig was already
            // verified above, so the only thing missing is the witness's stake row
            // reaching this node's local ledger. The replay sweep re-checks the gate
            // when stake updates land, so sybil defense is preserved end-to-end.
            state.attestation_receive_rejected_low_stake_total.fetch_add(1, Relaxed);
            let received_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let entry = crate::network::state::DeferredLowStakeAttestation {
                record_id: body.record_id.clone(),
                witness_hash: body.witness_hash.clone(),
                signature: sig_bytes.clone(),
                timestamp: body.timestamp,
                witness_public_key: pubkey_bytes.clone(),
                powas_nonce: body.powas_nonce,
                powas_difficulty: body.powas_difficulty,
                received_at,
            };
            crate::network::low_stake_replay::buffer_low_stake_attestation(
                &state, entry,
            );
            state.attestation_receive_low_stake_deferred_total.fetch_add(1, Relaxed);
            return Ok(Json(serde_json::json!({
                "status": "deferred",
                "reason": "low_stake",
                "record_id": body.record_id,
            })));
        }

        // Identity age requirement: staked witnesses need less time because
        // the stake itself is sybil resistance. Unstaked (if they somehow pass
        // the MIN_WITNESS_STAKE check) need the full 48h window.
        // Note: trust.identity_age() is per-node (when THIS node first saw the
        // identity), so it resets on restart if the trust snapshot is stale.
        // With staking as primary defense, 1h is sufficient to prevent
        // instant sybil while avoiding 48h bootstrap stalls.
        //
        // GENESIS EXEMPTION: config-pinned
        // genesis validators are the chain's trust root — byte-identical in
        // every node's genesis params. On a fresh chain every node's trust DB
        // starts empty, so WITHOUT this exemption ALL witness pushes
        // (including the genesis validators carrying 100% of stake) bounce
        // off the age gate for the first hour after the ceremony and the
        // network can only settle via the slower att-pull path. Age proves
        // nothing about identities the operator pinned at genesis.
        let is_genesis_validator = state
            .config
            .genesis_validators
            .iter()
            .any(|v| v.identity == body.witness_hash);
        let min_age_secs: f64 = if witness_staked >= MIN_WITNESS_STAKE {
            3600.0 // 1 hour for staked witnesses
        } else {
            48.0 * 3600.0 // 48 hours for unstaked
        };
        let trust = state.trust.read().await;
        let age_secs = trust.identity_age(&body.witness_hash, body.timestamp);
        if !is_genesis_validator && age_secs < min_age_secs {
            let hours_remaining = (min_age_secs - age_secs) / 3600.0;
            state.attestation_receive_rejected_too_young_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "witness {} too young ({:.1}h old, need {:.0}h, {:.1}h remaining)",
                body.witness_hash.chars().take(16).collect::<String>(),
                age_secs / 3600.0, min_age_secs / 3600.0, hours_remaining,
            )).into());
        }
    }

    let stored = {
        let mgr = state.witness_mgr.as_ref();
        mgr.store_attestation_with_powas(
            &body.record_id,
            &body.witness_hash,
            &sig_bytes,
            body.timestamp,
            pubkey_bytes.as_deref(),
            body.powas_nonce,
            body.powas_difficulty,
        )?
    };

    match stored {
        true => {
            debug!("received attestation from {} for {}", body.witness_hash.chars().take(12).collect::<String>(), body.record_id.chars().take(12).collect::<String>());

            // Note: slashing detection is now in epoch seal ingest path
            // (seal equivocation detection, not record attestation).

            let outcome = state.feed_attestation(&body.record_id, &body.witness_hash, body.timestamp).await;

            // Exactly-once edge: rewards/credit/events fire only for the call
            // that won the durable FinalizedIndex insert, never on re-pushed
            // attestations for an already-finalized record.
            if outcome.first_finalization {
                crate::network::reward::finalization_effects(
                    &state,
                    vec![body.record_id.clone()],
                );
            }

            let att = crate::network::witness::AttestationRecord {
                record_id: body.record_id.clone(),
                witness_hash: body.witness_hash.clone(),
                signature: sig_bytes.clone(),
                timestamp: body.timestamp,
                witness_public_key: pubkey_bytes,
                powas_nonce: body.powas_nonce,
                powas_difficulty: body.powas_difficulty,
            };
            let state2 = state.clone();
            tokio::spawn(async move {
                gossip::push_attestation_to_peers(&state2, &att).await;
            });

            Ok(Json(serde_json::json!({"accepted": true, "finalized": outcome.settled})))
        }
        false => Ok(Json(serde_json::json!({"accepted": false, "reason": "duplicate"}))),
    }
}

// ─── /snapshot ───────────────────────────────────────────────────────────────

/// Circuit-breaker: maximum accounts a single `/snapshot` or any
/// full-state fallback through `/snapshot/state-delta` (since_epoch=0 OR
/// since_epoch>0 + no archive baseline) may serve before the request is
/// rejected with 429 `RateLimited`. Above this threshold the response body
/// would be hundreds of megabytes — `ledger.accounts.clone()` (~200 B/account) +
/// `collect_applied_ids` HashSet (~70 B/record × 10M = 700 MB) + JSON
/// serialization push 4 GB VPSes into swap. Bootstrappers above the cap must
/// switch to `/snapshot/state-delta?since_epoch=N` *with* an archive baseline
/// the server already holds — incremental deltas stay bounded by the changeset
/// and pay no full-state heap cost.
pub(crate) const MAX_SNAPSHOT_FULL_ACCOUNTS: usize = 100_000;

/// Second gate on `/snapshot`: applied-records cap. Above this, the
/// `collect_applied_ids` HashSet alone is the OOM driver — `/snapshot` walks
/// the entire CF_APPLIED column family and materializes every record-id
/// `String` (~64 B/id × 10M = 640 MB) into one heap allocation independent
/// of `accounts.len()`. A chain can sit comfortably below
/// MAX_SNAPSHOT_FULL_ACCOUNTS (10K busy accounts × 1K records/account =
/// 10M applied) and still trip this. Cap at 1M so a 4 GB VPS stays well
/// inside its budget (~64 MB applied-ids + ~20 MB accounts + JSON overhead).
/// Same `snapshot_size_rejected_total` counter — operator views one
/// "switch to incremental" signal regardless of which gate tripped.
// `pub` (not `pub(crate)`): the `elara_node` bin's archive-snapshot loop
// references this to cap its `collect_applied_ids_capped` call — the loop has
// no request-path early-return guard of its own.
pub const MAX_SNAPSHOT_APPLIED_RECORDS: u64 = 1_000_000;

// Both `/snapshot` caps must be non-zero — a zero cap silently disables the
// circuit-breaker and lets a 4 GB VPS OOM under a /snapshot full-state pull.
// Compile-time static assertions replace the runtime asserts at
// batch_a_max_snapshot_constants_pin_mainnet_defaults_and_10x_ratio
// (clippy::assertions_on_constants — both sides are pub const, so the runtime
// version was tautological at every test invocation).
const _: () = assert!(MAX_SNAPSHOT_FULL_ACCOUNTS > 0);
const _: () = assert!(MAX_SNAPSHOT_APPLIED_RECORDS > 0);

/// Live high-water marks of accounts.len() and
/// approximate CF_APPLIED size sampled at every `/snapshot` request,
/// before either snapshot-size cap fires. Surfaces distance-to-cap so
/// operators see "we're at 80K accounts / 100K cap" before the next
/// bootstrap dial trips RateLimited. Distance signal trumps the
/// existing `snapshot_size_rejected_total` counter, which only fires
/// AFTER the cap has been hit and a peer has already been told to
/// switch to incremental. CAS-loop max keeps these monotonic across
/// requests; `seal_window_metrics`-shaped accessor mirrors the seal-window gauges.
static SNAPSHOT_SERVE_ACCOUNTS_MAX: AtomicU64 = AtomicU64::new(0);
static SNAPSHOT_SERVE_APPLIED_MAX: AtomicU64 = AtomicU64::new(0);

pub(crate) fn observe_snapshot_serve_size(accounts: usize, applied: u64) {
    let a = accounts as u64;
    let mut current = SNAPSHOT_SERVE_ACCOUNTS_MAX.load(Ordering::Relaxed);
    while a > current {
        match SNAPSHOT_SERVE_ACCOUNTS_MAX.compare_exchange_weak(
            current, a, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
    let mut current = SNAPSHOT_SERVE_APPLIED_MAX.load(Ordering::Relaxed);
    while applied > current {
        match SNAPSHOT_SERVE_APPLIED_MAX.compare_exchange_weak(
            current, applied, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

pub fn snapshot_serve_pressure_metrics() -> (u64, u64) {
    (
        SNAPSHOT_SERVE_ACCOUNTS_MAX.load(Ordering::Relaxed),
        SNAPSHOT_SERVE_APPLIED_MAX.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
pub(crate) fn reset_snapshot_serve_pressure_metrics() {
    SNAPSHOT_SERVE_ACCOUNTS_MAX.store(0, Ordering::Relaxed);
    SNAPSHOT_SERVE_APPLIED_MAX.store(0, Ordering::Relaxed);
}

pub async fn serve_snapshot(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Sample both pressure dimensions BEFORE
    // either cap check so the high-water observation captures the value
    // that tripped the gate (otherwise the rejection counter goes up
    // with no record of which dimension blew or by how much). Both
    // reads are bounded: ledger.accounts.len() is an O(1) HashMap len,
    // approximate_cf_size reads `estimate-num-keys` (one property
    // lookup, no scan).
    let accounts_count = state.ledger.read().await.accounts.len();
    let applied_count = state.rocks.approximate_cf_size(crate::storage::rocks::CF_APPLIED);
    observe_snapshot_serve_size(accounts_count, applied_count);

    // Fail fast above MAX_SNAPSHOT_FULL_ACCOUNTS so we don't OOM.
    if accounts_count > MAX_SNAPSHOT_FULL_ACCOUNTS {
        state
            .snapshot_size_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError(ElaraError::RateLimited));
    }

    // Second gate. `approximate_cf_size` reads RocksDB
    // `estimate-num-keys`, which is O(1) (a property lookup, no scan). The
    // estimate can lag truth by up to one compaction cycle but is monotonic
    // enough for a circuit-breaker — a slightly-late trip is still safe.
    if applied_count > MAX_SNAPSHOT_APPLIED_RECORDS {
        state
            .snapshot_size_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError(ElaraError::RateLimited));
    }

    let state2 = state.clone();
    let identity = state.identity.clone();

    // Use the live in-memory ledger — never rebuild from storage on a peer request.
    // At 10M+ records, a full rebuild takes minutes and any peer could trigger it.
    let mut ledger = state.ledger.read().await.clone();
    // Gap 7 (2026-04-21): Clone() deliberately skips applied_record_ids (hot-path
    // optimization — 135K+ entries). But the bootstrapping peer needs this set
    // so records arriving via delta-sync are recognized as already-applied and
    // skip re-apply. Pull it from CF_APPLIED (authoritative) and attach.
    ledger.applied_record_ids = state.rocks.collect_applied_ids();
    drop(state2); // not needed anymore

    let snapshot = tokio::task::spawn_blocking(move || {
        let finalized: std::collections::HashSet<String> = std::collections::HashSet::new();
        let epoch = crate::network::epoch::EpochState::new();

        let merkle_root = crate::network::merkle::global_merkle_root(&state.rocks);
        let record_count = state.record_count().unwrap_or(0) as u64;

        let genesis_state = state.genesis_state.read_recover().clone();
        let bootstrap_state = state.bootstrap_state.read_recover().clone();

        // Gap 7 post-apply verify: advertise the root over the SAME in-memory
        // `ledger.accounts` set being serialized below, so the bootstrap consumer
        // reproduces it exactly. NOT the persisted CF_ACCOUNT_SMT root — that is
        // only advanced by flush_dirty at seal time and lags the live ledger
        // whenever records landed since the last flush, which made the joiner's
        // post-apply verify false-fail on every legitimate bootstrap. The
        // rebuild is pure in-memory (no rocks read, no smt_dirty flush, no race
        // with the seal loop) — see account_merkle::root_over_accounts.
        let account_state_root = crate::network::account_merkle::root_over_accounts(&ledger.accounts)
            .ok();

        crate::network::snapshot::create_signed_snapshot(crate::network::snapshot::SignedSnapshotInputs {
            ledger: &ledger,
            finalized: &finalized,
            epoch: &epoch,
            genesis_state: Some(&genesis_state),
            bootstrap_state: Some(&bootstrap_state),
            merkle_root,
            record_count,
            identity: &identity,
            account_state_root,
            // C4 slice 1: carry the mandate registries so a bootstrapped
            // follower doesn't flag NoChain for pre-baseline mandates.
            mandates: state.rocks.collect_mandates(),
            revocations: state.rocks.collect_revocations(),
            emergency: state.emergency_snapshot_carry(),
        })
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    Ok(Json(serde_json::json!(snapshot)))
}

// ─── /snapshot/latest ────────────────────────────────────────────────────────

pub async fn serve_snapshot_metadata(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ledger = state.ledger.read().await;
    let supply = ledger.total_supply;
    let staked = ledger.total_staked;
    let accounts = ledger.accounts.len();
    drop(ledger);

    let signer = state.identity.identity_hash.clone();
    let state2 = state.clone();
    let (merkle_root, record_count) = tokio::task::spawn_blocking(move || {
        let root = hex::encode(crate::network::merkle::global_merkle_root(&state2.rocks));
        let count = state2.record_count().unwrap_or(0) as u64;
        (root, count)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    let metadata = serde_json::json!({
        "merkle_root": merkle_root,
        "record_count": record_count,
        "snapshot_timestamp": crate::record::now_timestamp(),
        "signer_identity": signer,
        "accounts": accounts,
        "total_supply": supply,
        "total_staked": staked,
    });

    Ok(Json(metadata))
}

// ─── /snapshot/fast ──────────────────────────────────────────────────────────

pub async fn serve_snapshot_fast(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let meta_only = params.get("meta_only").is_some_and(|v| v == "true");
    let cursor_owned: Option<String> = params.get("cursor").cloned();
    let since_epoch = params.get("since_epoch").and_then(|s| s.parse::<u64>().ok());

    let state2 = state.clone();

    let result = tokio::task::spawn_blocking(move || -> std::result::Result<serde_json::Value, ElaraError> {
        let since_ts = if let Some(epoch_num) = since_epoch {
            // Stream through records one at a time to find the epoch seal timestamp.
            // Previous code loaded ALL records via query(usize::MAX) — ~1.5GB on 60K records.
            state2.rocks.find_epoch_seal_timestamp(epoch_num)?
        } else {
            None
        };

        if meta_only {
            let merkle_root = hex::encode(crate::network::merkle::global_merkle_root(&state2.rocks));
            let record_count = state2.record_count().unwrap_or(0) as u64;
            let epoch_number = state2.epoch.read_recover()
                .latest_epoch.get(&ZoneId::from_legacy(0)).copied().unwrap_or(0);

            let meta = crate::network::sync::SnapshotFastMeta {
                total_records: record_count,
                merkle_root,
                epoch_number,
            };
            Ok(serde_json::json!(meta))
        } else {
            let chunk = crate::network::sync::build_snapshot_chunk(
                &state2,
                cursor_owned.as_deref(),
                since_ts,
                crate::network::sync::SNAPSHOT_CHUNK_SIZE,
            )?;
            Ok(serde_json::json!(chunk))
        }
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    Ok(Json(result))
}

// ─── Gap 7: /snapshot/epochs and /snapshot/epoch/{N} ─────────────────────────
//
// Archive nodes persist signed snapshots at epoch boundaries (see
// `archive_snapshot_loop` in elara_node.rs). New nodes bootstrap by:
//   1. GET /snapshot/epochs              → list available epoch numbers
//   2. GET /snapshot/epoch/{N}           → download that specific snapshot
//   3. (existing) GET /snapshot/fast     → pull records after epoch N
//
// Non-archive nodes simply return empty lists / 404s — the endpoints are
// always safe to call, and clients fall through to the live /snapshot path.

/// Shared compute: list available epoch snapshots on this node.
///
/// Extracted so axum (`list_epoch_snapshots_route`) and PQ transport
/// (`handle_list_epoch_snapshots`) return byte-identical JSON.
pub async fn compute_list_epoch_snapshots(
    state: &Arc<NodeState>,
) -> Result<serde_json::Value, ElaraError> {
    let dir = state.config.data_dir.join("snapshots");
    let epochs = tokio::task::spawn_blocking(move || {
        crate::network::snapshot::list_epoch_snapshots(&dir)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    Ok(serde_json::json!({
        "epochs": epochs,
        "count": epochs.len(),
        "latest": epochs.last().copied(),
        "archive_snapshot_every_n_epochs": state.config.archive_snapshot_every_n_epochs,
        "archive_snapshot_retention": state.config.archive_snapshot_retention,
    }))
}

/// List available epoch snapshots on this node.
pub async fn list_epoch_snapshots_route(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_list_epoch_snapshots(&state).await?))
}

/// Shared compute: load a specific epoch snapshot from disk. Returns
/// `ElaraError::Storage` when missing so both surfaces produce the same
/// not-found error.
pub async fn compute_get_epoch_snapshot(
    state: &Arc<NodeState>,
    epoch_num: u64,
) -> Result<crate::network::snapshot::NodeSnapshot, ElaraError> {
    let dir = state.config.data_dir.join("snapshots");
    let snap = tokio::task::spawn_blocking(move || {
        crate::network::snapshot::load_epoch_snapshot(&dir, epoch_num)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    snap.ok_or_else(|| ElaraError::Storage(format!(
        "epoch snapshot not found for epoch {}", epoch_num
    )))
}

/// Serve a specific epoch snapshot from disk. Returns 404 when missing.
pub async fn serve_epoch_snapshot(
    State(state): State<Arc<NodeState>>,
    axum::extract::Path(epoch_num): axum::extract::Path<u64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let snap = compute_get_epoch_snapshot(&state, epoch_num).await?;
    Ok(Json(serde_json::json!(snap)))
}

// ─── Audit #3: /snapshot/state-delta ─────────────────────────────────────────
//
// Incremental state-delta snapshot path. Returns only the accounts that
// changed since the client's baseline epoch — vastly cheaper than the full
// `/snapshot` clone when the active set is small relative to the total set.
//
// Query: `?since_epoch={N}` (required). When the serving node has the
// archive snapshot at epoch N on disk (via Gap 7 archive snapshots), the
// delta is computed against that baseline and `baseline_available=true`.
// When N=0 or no archive snapshot exists at N, the response carries the
// full current ledger state with `baseline_available=false` so the client
// still makes progress; the next call (with a more recent baseline they
// now have) will run incrementally.
//
// Verification chain: the delta is Dilithium3-signed by the serving node's
// identity — that signature + the signer trust-gate is the binding integrity
// fence. The included `account_state_root` is read from the PERSISTED on-disk
// AccountStateSMT (advanced only by flush_dirty at seal time), so it LAGS the
// live in-memory ledger and is node-local — NOT a cross-node-stable quantity.
// Repair consumers therefore treat the post-apply live-root comparison as
// advisory only (see apply_state_delta_for_repair); the consensus-stable
// cross-node anchor is `latest_sealed_account_smt_root` (witness-signed into
// the seal), which clients cross-check against a super-seal record-hash they
// already trust.

/// Shared compute: build a signed `StateDelta` from current state.
///
/// Returns the unwrapped `StateDelta` so the axum + PQ-WS surfaces produce
/// byte-identical bodies (after `serde_json::to_value` on the same struct).
pub async fn compute_state_delta(
    state: &Arc<NodeState>,
    since_epoch: u64,
) -> Result<crate::network::snapshot::StateDelta, ElaraError> {
    // 1. Load archive baseline FIRST. Archive lookup is cheap (one
    //    file open + JSON deserialize ≤ baseline_size). We need to know
    //    whether baseline is available BEFORE deciding to pay the
    //    `accounts.clone()` heap cost — at scale, !baseline_available + 10M
    //    accounts = 2 GB clone, the same OOM risk the account cap closes for the
    //    explicit since_epoch=0 case.
    //
    //    Archive-snapshot cadence is `archive_snapshot_every_n_epochs` (default
    //    10), so an exact-match lookup would miss most client epochs. We use
    //    `load_epoch_snapshot_at_or_before` so any since_epoch finds the most
    //    recent baseline ≤ since_epoch — diffing extra accounts that didn't
    //    change between baseline_epoch and since_epoch is harmless because the
    //    signed `account_state_root` proves correctness end-to-end.
    let (prior_accounts, baseline_epoch_used) = if since_epoch > 0 {
        let dir = state.config.data_dir.join("snapshots");
        let load_result = tokio::task::spawn_blocking(move || {
            crate::network::snapshot::load_epoch_snapshot_at_or_before(&dir, since_epoch)
        })
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
        match load_result? {
            Some((e, snap)) => (Some(snap.ledger.accounts), Some(e)),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let baseline_available = prior_accounts.is_some();

    // 2. Single read-lock pass — circuit-break + diff + totals.
    //    The previous shape cloned `ledger.accounts` (line 827) before diffing.
    //    At ~250 B/AccountState × 10M accounts that's a 2.5 GB heap spike
    //    every state-delta request — independent of changeset size, and
    //    bypassing the size cap on the baseline-available path. We
    //    now hold the read-lock across `diff_account_states` itself, which
    //    is O(|prior| + |current|) iteration + O(|changed|) allocation —
    //    bounded by the actual change rate, not total account count.
    //
    //    Trade-off: ledger writers block during the diff (~80 ms at 1M
    //    accounts on a 4 GB VPS). Acceptable: this endpoint is
    //    bootstrap-only, not steady-state. The size-check stays
    //    in the same lock pass so we still fail-fast above the cap.
    //
    //    When no baseline, treat prior as empty — every account is "changed",
    //    producing a full-ledger payload while leaving the client on the
    //    same code path next call.
    //
    //    Response-size fence below is ASYMMETRIC BY DESIGN: it caps only the
    //    !baseline_available full-dump path. The baseline-available path serves
    //    the delta uncapped (pinned by `state_delta_since_nonzero_with_baseline_
    //    above_cap_succeeds`) since the common active-set-since-baseline is small.
    //    Mainnet caveat: the `O(|changed|)` allocation is bounded by change rate
    //    only when the baseline is RECENT — an attacker requesting an OLD
    //    since_epoch (oldest retained archive baseline) forces a delta approaching
    //    the full account count, the same O(N)-account JSON this cap prevents,
    //    reached via the delta route. A symmetric delta-size cap would break
    //    legit large-incremental sync (clients then fall to /snapshot, also
    //    capped — the streaming archive path is the large-ledger route), so it is
    //    a deliberate design decision, not a mechanical fix: audit before adding.
    let (changed, removed, total_supply, total_staked, total_accounts) = {
        let ledger = state.ledger.read().await;
        if !baseline_available && ledger.accounts.len() > MAX_SNAPSHOT_FULL_ACCOUNTS {
            state
                .snapshot_size_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(ElaraError::RateLimited);
        }
        let empty: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        let prior_ref = prior_accounts.as_ref().unwrap_or(&empty);
        let (changed, removed) =
            crate::network::snapshot::diff_account_states(prior_ref, &ledger.accounts);
        (
            changed,
            removed,
            ledger.total_supply,
            ledger.total_staked,
            ledger.accounts.len() as u64,
        )
    };

    // 4. Compute the AccountStateSMT root + global record-merkle root in
    //    one spawn_blocking — both are RocksDB reads.
    let state_for_root = state.clone();
    let (account_state_root, merkle_root) = tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32]), ElaraError> {
        let smt = crate::network::account_merkle::AccountStateSMT::new(&state_for_root.rocks);
        let acct_root = smt.root()?;
        let merk_root = crate::network::merkle::global_merkle_root(&state_for_root.rocks);
        Ok((acct_root, merk_root))
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    // 5. Latest super-seal across all zones (highest end_epoch wins). When no
    //    super-seal has formed yet (testnet today), both fields are None.
    //    Slice 7.1: also pull latest_sealed_account binding (epoch + SMT root)
    //    in the same lock pass so the delta carries an end-to-end-verifiable
    //    chain head. Single read_recover for both reads — locked once.
    let (
        latest_super_seal_epoch,
        latest_super_seal_record_hash,
        latest_sealed_account_epoch,
        latest_sealed_account_smt_root,
        current_epoch,
    ) = {
        use crate::network::RwLockRecover;
        let epoch_state = state.epoch.read_recover();
        let (sse, ssh) = epoch_state
            .latest_super_seal
            .values()
            .max_by_key(|(e, _, _, _)| *e)
            .map(|(e, _, h, _)| (Some(*e), Some(*h)))
            .unwrap_or((None, None));
        let (lsae, lsar) = epoch_state
            .latest_sealed_account
            .as_ref()
            .map(|(e, _z, _id, root, _ts)| (Some(*e), Some(*root)))
            .unwrap_or((None, None));
        // 6. current_epoch = max latest_epoch across all zones (highest local
        //    high-watermark — gives the client a "you're behind by ~K epochs"
        //    hint without the client needing /epochs).
        let cur = epoch_state.latest_epoch.values().copied().max().unwrap_or(0);
        (sse, ssh, lsae, lsar, cur)
    };

    let delta = crate::network::snapshot::create_signed_state_delta(
        crate::network::snapshot::StateDeltaInputs {
            since_epoch,
            current_epoch,
            baseline_available,
            account_state_root,
            merkle_root,
            latest_super_seal_epoch,
            latest_super_seal_record_hash,
            latest_sealed_account_epoch,
            latest_sealed_account_smt_root,
            changed_accounts: changed,
            removed_accounts: removed,
            total_accounts,
            total_supply,
            total_staked,
            identity: &state.identity,
        },
    )?;

    debug!(
        "/snapshot/state-delta since={} current={} baseline_available={} baseline_epoch_used={:?} changed={} removed={} total_accounts={}",
        since_epoch,
        current_epoch,
        baseline_available,
        baseline_epoch_used,
        delta.changed_accounts.len(),
        delta.removed_accounts.len(),
        total_accounts,
    );

    Ok(delta)
}

/// Serve a signed incremental state-delta snapshot. Required query param
/// `since_epoch` is the baseline the client claims to already trust.
pub async fn serve_state_delta(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let since_epoch = params.get("since_epoch")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ElaraError::Wire(
            "/snapshot/state-delta requires `since_epoch` query parameter".into()
        ))?;

    let delta = compute_state_delta(&state, since_epoch).await?;
    Ok(Json(serde_json::json!(delta)))
}

// ─── /slot-conflicts (POST) ─────────────────────────────────────────────────
//
// Accept a gossiped `ConflictProof`. Verify cryptographically, then:
//   1. Mark the slot conflicted in CF_SLOT_CONFLICTS (so the settlement gate
//      blocks both records locally).
//   2. Re-gossip to our fan-out (propagates through network in O(log n) hops).
//
// This is the receive-side of MESH-BFT Phase 3 Stage 1D.2. The matching
// send-side lives in `gossip::push_conflict_proof_to_peers`.
//
// # Dedup
// We use the SeenSet in `NodeState.conflict_proof_seen` (keyed by slot_key)
// to avoid infinite gossip loops. If we've already processed this slot, we
// drop the request silently with a 200 so the sender doesn't retry.
//
// # Trust model
// We verify the proof's signatures end-to-end before acting on it — an
// attacker forwarding a malformed proof cannot grief a node into marking an
// honest slot. See `ConflictProof::verify()`.
pub async fn receive_conflict_proof(
    State(state): State<Arc<NodeState>>,
    Json(proof): Json<crate::network::conflict_proof::ConflictProof>,
) -> Result<Json<serde_json::Value>, AppError> {
    let slot_key = match proof.slot_key() {
        Some(k) => k,
        None => {
            state.conflict_proof_rejected_total.fetch_add(
                1, std::sync::atomic::Ordering::Relaxed);
            return Err(ElaraError::Wire(
                "ConflictProof: records do not agree on a slot".into()
            ).into());
        }
    };

    // Dedup: already processed this slot → no-op.
    {
        let seen = state.conflict_proof_seen.lock_recover();
        if seen.contains(&slot_key) {
            return Ok(Json(serde_json::json!({
                "status": "duplicate",
                "slot_key": slot_key,
            })));
        }
    }

    state.conflict_proof_received_total.fetch_add(
        1, std::sync::atomic::Ordering::Relaxed);

    // Verify cryptographically — this is O(2) signature verifications.
    if let Err(e) = proof.verify() {
        state.conflict_proof_rejected_total.fetch_add(
            1, std::sync::atomic::Ordering::Relaxed);
        warn!("received malformed ConflictProof at {}: {}", slot_key, e);
        return Err(ElaraError::Wire(format!("ConflictProof verify failed: {e}")).into());
    }

    // Mark the slot conflicted. Key: slot_key. Value: short marker (ids of
    // both records) for post-hoc reconstruction.
    let marker = format!("{}:{}", proof.record_a.id, proof.record_b.id);
    state.rocks.slot_mark_conflict(&slot_key, &marker)
        .map_err(|e| ElaraError::Storage(format!("slot_mark_conflict: {e}")))?;

    warn!(
        "SLOT EQUIVOCATION (gossip): slot {} marked conflicted via peer-pushed ConflictProof \
         ({} vs {})",
        slot_key,
        &proof.record_a.id[..proof.record_a.id.len().min(16)],
        &proof.record_b.id[..proof.record_b.id.len().min(16)],
    );

    // Re-gossip. The push function is internally-deduped (marks the slot in
    // conflict_proof_seen before pushing), so this terminates after one hop
    // per node even under pathological peer topologies.
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        gossip::push_conflict_proof_to_peers(&state_clone, &proof).await;
    });

    Ok(Json(serde_json::json!({
        "status": "accepted",
        "slot_key": slot_key,
    })))
}

// ─── /peers/offline_notification ─────────────────────────────────────────────

/// Payload for the going-offline broadcast.
#[derive(serde::Deserialize)]
pub struct OfflineNotification {
    pub node_id: String,
    pub timestamp_secs: u64,
    pub sig: String,
}

/// Receive a signed going-offline notification from a peer.
///
/// Verifies the Dilithium3 signature using the peer's stored public key, then
/// marks the peer as `PeerState::Offline` — no failure count increment, no
/// backoff.  The peer will be re-promoted to `Connected` on the next
/// successful exchange (heartbeat / gossip push).
///
/// Unknown or unsigned peers are silently accepted (we can't verify them, but
/// the worst case is we skip the optimisation; no attack surface opened).
pub async fn receive_offline_notification(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<OfflineNotification>,
) -> Result<Json<serde_json::Value>, AppError> {
    let v = compute_receive_offline_notification(&state, body).await?;
    Ok(Json(v))
}

/// Shared offline-notification service-fn.
/// Verifies the Dilithium3 signature using the peer's stored public key, then
/// marks the peer as Offline. Unknown peers are silently accepted with
/// `{"status": "unknown_peer"}` (can't verify, but no attack surface).
pub async fn compute_receive_offline_notification(
    state: &Arc<NodeState>,
    body: OfflineNotification,
) -> crate::errors::Result<serde_json::Value> {
    // Look up the sender's stored public key.
    let pk_hex = {
        let peers = state.peers.read().await;
        match peers.get(&body.node_id) {
            Some(p) if !p.public_key_hex.is_empty() => p.public_key_hex.clone(),
            _ => {
                // Unknown peer — can't verify, ignore gracefully.
                return Ok(serde_json::json!({"status": "unknown_peer"}));
            }
        }
    };

    // Verify Dilithium3 signature against the canonical signable.
    let signable = format!("going_offline:{}:{}", body.node_id, body.timestamp_secs);
    let sig_bytes = hex::decode(&body.sig)
        .map_err(|_| ElaraError::Wire("offline_notification: invalid sig hex".into()))?;
    let pk_bytes = hex::decode(&pk_hex)
        .map_err(|_| ElaraError::Wire("offline_notification: invalid pk hex".into()))?;

    // Bug-fix: `dilithium3_verify` returns
    // `Result<bool>`. The previous `?` after `.map_err(...)` propagated the
    // Err arm but treated `Ok(false)` (correctly-shaped but cryptographically
    // invalid signature) as success — letting an attacker mark any peer with
    // a known public key as `PeerState::Offline` by submitting a forged-but-
    // length-valid sig. Blast radius is small (peer auto-recovers on next
    // heartbeat, no reputation penalty per the docstring), but the verify
    // gate exists to prevent unauthorized state mutation. Match the
    // `if !dilithium3_verify(...)?` pattern used at sync.rs:331,
    // ingest.rs:771, core.rs:1133, router.rs:867/1129, witness.rs:147,
    // handshake.rs:377/435 — all other call sites check the bool.
    let valid = dilithium3_verify(signable.as_bytes(), &sig_bytes, &pk_bytes)
        .map_err(|e| ElaraError::Wire(format!("offline_notification: sig verify failed: {e}")))?;
    if !valid {
        return Err(ElaraError::Wire(
            "offline_notification: sig verify returned false".into(),
        ));
    }

    // Mark offline — no reputation penalty, no backoff.
    {
        let mut peers = state.peers.write().await;
        peers.mark_offline(&body.node_id);
    }

    tracing::info!(
        "peer {} signaled going offline — marked Offline (no penalty)",
        &body.node_id[..body.node_id.len().min(16)]
    );

    Ok(serde_json::json!({"status": "ok"}))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;

    /// Serializes the pressure-gauge tests so concurrent `reset()` /
    /// `observe()` calls don't race on the module-level static atomics
    /// (`SNAPSHOT_SERVE_ACCOUNTS_MAX` / `SNAPSHOT_SERVE_APPLIED_MAX`).
    /// `cargo test` runs unit tests in parallel by default; an interleaved
    /// `reset()` from a sibling test would clobber a high-water assertion
    /// mid-flight. Pattern mirrored from `state_core::tests::*` watchdog
    /// suites (state_core.rs:1634/1669/1706).
    static OPS141_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Snapshot-serve pressure gauges.
    /// `observe_snapshot_serve_size` MUST track per-dimension high-water
    /// marks via CAS-loop max — later smaller samples must NOT regress
    /// either gauge, and the two dimensions must update independently
    /// (a request with high accounts but low applied must not freeze
    /// the applied gauge).
    #[test]
    fn observe_snapshot_serve_size_tracks_max_per_dimension() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();
        let (a0, p0) = snapshot_serve_pressure_metrics();
        assert_eq!(a0, 0);
        assert_eq!(p0, 0);

        observe_snapshot_serve_size(50_000, 200_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 50_000);
        assert_eq!(p, 200_000);

        // Smaller sample: neither gauge regresses.
        observe_snapshot_serve_size(10_000, 50_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 50_000, "smaller accounts must not regress");
        assert_eq!(p, 200_000, "smaller applied must not regress");

        // Mixed: accounts grows, applied shrinks. Only accounts moves.
        observe_snapshot_serve_size(80_000, 100_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 80_000);
        assert_eq!(p, 200_000, "lower applied with higher accounts must not regress applied");

        // Mixed reverse: accounts shrinks, applied grows. Only applied moves.
        observe_snapshot_serve_size(40_000, 500_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 80_000, "lower accounts with higher applied must not regress accounts");
        assert_eq!(p, 500_000);

        // At-cap and above-cap both record (cap-rejection is a separate path,
        // counted by snapshot_size_rejected_total — this gauge captures the value).
        observe_snapshot_serve_size(MAX_SNAPSHOT_FULL_ACCOUNTS + 1, MAX_SNAPSHOT_APPLIED_RECORDS + 1);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, (MAX_SNAPSHOT_FULL_ACCOUNTS + 1) as u64);
        assert_eq!(p, MAX_SNAPSHOT_APPLIED_RECORDS + 1);

        reset_snapshot_serve_pressure_metrics();
    }

    /// Axis 1: saturation safety. Passing `usize::MAX` /
    /// `u64::MAX` MUST NOT panic — the function casts `accounts as u64`
    /// (line 584), which on the 64-bit production targets we ship lands
    /// at `u64::MAX` losslessly. A refactor to `u64::try_from(accounts)`
    /// would panic on usize::MAX (no surface above u64), and this test
    /// catches that regression at the input boundary. After saturation,
    /// a subsequent (1, 1) call MUST NOT regress either gauge — the
    /// CAS-loop's `a > current` guard correctly handles the u64::MAX
    /// fixed point (1 > u64::MAX == false).
    #[test]
    fn batch_ops141_saturation_usize_max_u64_max_does_not_panic() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();

        observe_snapshot_serve_size(usize::MAX, u64::MAX);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, u64::MAX, "usize::MAX as u64 saturates to u64::MAX on 64-bit targets");
        assert_eq!(p, u64::MAX, "u64::MAX passes through identity");

        // Sub-saturation sample MUST NOT regress the gauges.
        observe_snapshot_serve_size(1, 1);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, u64::MAX, "saturation high-water survives a (1, _) call");
        assert_eq!(p, u64::MAX, "saturation high-water survives a (_, 1) call");

        // Zero sub-sample MUST also no-op (strict-`>` guard).
        observe_snapshot_serve_size(0, 0);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, u64::MAX, "(0, _) at saturation no-ops");
        assert_eq!(p, u64::MAX, "(_, 0) at saturation no-ops");

        reset_snapshot_serve_pressure_metrics();
    }

    /// Axis 2: concurrent CAS-loop correctness. The existing
    /// test exercises only sequential calls — the `compare_exchange_weak`
    /// retry branch at lines 587/596 is never observed under single-thread
    /// load. Spawn 16 threads × 100 observations each with asymmetric values
    /// (accounts = t*100+i, applied = (t*100+i)*2) and assert the global
    /// max lands deterministically. Validates the CAS retry handles
    /// contention without lost updates — a refactor to plain `store()`
    /// (which would silently lose concurrent updates) would surface here.
    #[test]
    fn batch_ops141_concurrent_observe_converges_to_global_max() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();

        const THREADS: u64 = 16;
        const PER_THREAD: u64 = 100;
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 1..=PER_THREAD {
                        let v = t * PER_THREAD + i;
                        observe_snapshot_serve_size(v as usize, v * 2);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("concurrent observe thread must not panic");
        }

        let (a, p) = snapshot_serve_pressure_metrics();
        let expected_max = THREADS * PER_THREAD;
        assert_eq!(
            a, expected_max,
            "concurrent observe must converge to global accounts-max ({THREADS}*{PER_THREAD})"
        );
        assert_eq!(
            p,
            expected_max * 2,
            "concurrent observe must converge to global applied-max (2× scale)"
        );

        reset_snapshot_serve_pressure_metrics();
    }

    /// Axis 3: tuple-order semantic pin. The function returns
    /// `(accounts_max, applied_max)` at line 605-610 — `.0` is accounts,
    /// `.1` is applied. The caller at `server.rs:6605` indexes the tuple
    /// by position to wire it into the Prometheus `elara_snapshot_serve_*`
    /// gauge family; a refactor swapping the return order would silently
    /// mis-label Grafana alarms (accounts cap fire would report on the
    /// applied gauge dashboard and vice versa). Asymmetric population
    /// (99_999, 1) makes the swap regression observable — a swapped impl
    /// would yield (1, 99_999) and fail both assertions in one call.
    #[test]
    fn batch_ops141_pressure_metrics_tuple_order_is_accounts_then_applied() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();

        observe_snapshot_serve_size(99_999, 1);
        let metrics = snapshot_serve_pressure_metrics();
        assert_eq!(metrics.0, 99_999, "tuple.0 MUST be accounts_max");
        assert_eq!(metrics.1, 1, "tuple.1 MUST be applied_max");

        // Mirror: a (1, 99_999) population yields the inverse tuple,
        // proving the indices follow the input semantic, not insertion order.
        reset_snapshot_serve_pressure_metrics();
        observe_snapshot_serve_size(1, 99_999);
        let metrics = snapshot_serve_pressure_metrics();
        assert_eq!(metrics.0, 1, "tuple.0 MUST be accounts_max even when smaller");
        assert_eq!(metrics.1, 99_999, "tuple.1 MUST be applied_max");

        reset_snapshot_serve_pressure_metrics();
    }

    /// Axis 4: `reset_snapshot_serve_pressure_metrics()`
    /// zeros BOTH dimensions in a single call AND is idempotent. The
    /// existing test calls reset at start (when gauges are presumed clean)
    /// and end (cleanup), but never (a) populates THEN resets THEN reads
    /// to confirm zeroing, NOR (b) calls reset twice in a row. A refactor
    /// that accidentally only resets one of the two atomics — e.g. a
    /// copy-paste error duplicating `SNAPSHOT_SERVE_ACCOUNTS_MAX.store(0,...)`
    /// twice instead of touching SNAPSHOT_SERVE_APPLIED_MAX — would leave
    /// one dimension stale; this pins the dual-zero invariant. Second
    /// reset on already-zero state MUST be a no-op (no panic, no underflow,
    /// no spurious atomic write that could surface under TSAN).
    #[test]
    fn batch_ops141_reset_zeros_both_dimensions_and_is_idempotent() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();

        observe_snapshot_serve_size(123_456, 789_012);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 123_456);
        assert_eq!(p, 789_012);

        // First reset zeros BOTH atomics in a single call.
        reset_snapshot_serve_pressure_metrics();
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 0, "reset MUST zero accounts gauge");
        assert_eq!(p, 0, "reset MUST zero applied gauge");

        // Idempotent: second reset on zero state is safe.
        reset_snapshot_serve_pressure_metrics();
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 0, "reset is idempotent on already-zero accounts gauge");
        assert_eq!(p, 0, "reset is idempotent on already-zero applied gauge");

        // After reset, the global atomics are still usable for fresh observations.
        observe_snapshot_serve_size(42, 42);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 42, "post-reset observations land on fresh atomics");
        assert_eq!(p, 42, "post-reset observations land on fresh atomics");

        reset_snapshot_serve_pressure_metrics();
    }

    /// Axis 5: zero-arg no-op on populated gauges. The CAS
    /// guard `a > current` at line 586 is STRICT-greater; observing
    /// (0, _) when accounts gauge is at 50_000 means `0 > 50_000` is
    /// false → CAS loop never enters → atomic untouched. This is the
    /// sharpest lower-boundary case: any regression weakening the guard
    /// to `a >= current` would still produce the same observable state
    /// here (the existing test's (10_000, 50_000) sample doesn't hit
    /// the zero edge), but the strict-`>` contract is load-bearing
    /// because /metrics scrapes 12×/min — a `>=` regression would
    /// cause spurious atomic writes under sustained zero-load (no
    /// /snapshot requests but periodic ledger.accounts.len() polls),
    /// inflating CAS traffic on a hot static for no benefit. Symmetric
    /// pin on BOTH dimensions independently — a refactor that special-cased
    /// zero on ONE dimension only (e.g. an early-return for `accounts == 0`)
    /// would break the other dimension's update.
    #[test]
    fn batch_ops141_observe_zero_on_populated_gauges_is_no_op_per_dimension() {
        let _g = OPS141_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_snapshot_serve_pressure_metrics();

        // Populate both gauges to non-zero.
        observe_snapshot_serve_size(50_000, 200_000);

        // (0, 0) on populated gauges: both stay at high-water.
        observe_snapshot_serve_size(0, 0);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 50_000, "observe(0, _) MUST NOT regress accounts");
        assert_eq!(p, 200_000, "observe(_, 0) MUST NOT regress applied");

        // (0, applied>current) — accounts skipped; applied advances if larger.
        observe_snapshot_serve_size(0, 300_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 50_000, "zero-accounts dim is a strict no-op even when applied grows");
        assert_eq!(p, 300_000, "applied dim advances independently of zero-accounts dim");

        // (accounts>current, 0) — applied skipped; accounts advances if larger.
        observe_snapshot_serve_size(75_000, 0);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 75_000, "accounts dim advances independently of zero-applied dim");
        assert_eq!(p, 300_000, "zero-applied dim is a strict no-op even when accounts grows");

        // (0, applied<current) — both no-op.
        observe_snapshot_serve_size(0, 100_000);
        let (a, p) = snapshot_serve_pressure_metrics();
        assert_eq!(a, 75_000, "(0, sub-watermark) accounts stays");
        assert_eq!(p, 300_000, "(0, sub-watermark) applied stays");

        reset_snapshot_serve_pressure_metrics();
    }

    fn test_state() -> (Arc<NodeState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "audit1-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    /// AUDIT-1 (2026-04-22): attestation ingest MUST refuse when the submitter
    /// omits `witness_public_key` AND the witness is unknown to the local
    /// identity registry. Previously the handler silently accepted such
    /// submissions into consensus without Dilithium3 verification.
    #[tokio::test]
    async fn test_receive_attestation_rejects_missing_pubkey_when_not_in_registry() {
        let (state, _tmp) = test_state();
        let body = super::AttestationSubmit {
            record_id: "rec_audit1".into(),
            witness_hash: "deadbeef".repeat(8), // 64 hex chars, NOT in registry
            signature: hex::encode([0x42u8; 3293]),
            timestamp: 1700000000.0,
            witness_public_key: None,
            powas_nonce: None,
            powas_difficulty: None,
        };
        let err = super::receive_attestation(
            axum::extract::State(state.clone()),
            axum::Json(body),
        )
        .await
        .expect_err("must reject — unverifiable attestation");
        assert!(
            matches!(err.0, ElaraError::InvalidSignature),
            "expected InvalidSignature, got {:?}",
            err.0
        );
    }

    /// Complement: when the registry DOES know the witness, the handler
    /// looks the pubkey up and attempts verification. A forged signature
    /// must still be rejected with InvalidSignature (not silently accepted).
    #[tokio::test]
    async fn test_receive_attestation_rejects_forged_sig_even_with_registered_pubkey() {
        let (state, _tmp) = test_state();
        // Register a dummy pubkey under a known witness_hash.
        let pk = vec![0xAAu8; 1952];
        let witness_hash = sha3_256_hex(&pk);
        state.rocks.store_public_key(&witness_hash, &pk).expect("store pk");

        // Seed a record so signable_bytes() resolves (otherwise we hit the
        // deferred branch and never exercise dilithium3_verify).
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;
        let rec = ValidationRecord {
            id: "rec_audit1b".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0xBB; 1952],
            timestamp: 1700000000.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xCC; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: vec![],
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };
        state.rocks.put_record(&rec.id.clone(), &rec).expect("put record");

        let body = super::AttestationSubmit {
            record_id: "rec_audit1b".into(),
            witness_hash: witness_hash.clone(),
            signature: hex::encode([0x42u8; 3309]), // bogus but right-sized ML-DSA-65 sig
            timestamp: 1700000000.0,
            witness_public_key: None, // force registry lookup
            powas_nonce: None,
            powas_difficulty: None,
        };
        let err = super::receive_attestation(
            axum::extract::State(state.clone()),
            axum::Json(body),
        )
        .await
        .expect_err("must reject — forged sig must not verify");
        // Either InvalidSignature (verify returned false) or a Crypto error
        // (PQ library rejected the malformed artifact) is acceptable — both
        // reject the attestation. What matters is that the handler didn't
        // silently accept it into consensus.
        assert!(
            matches!(err.0, ElaraError::InvalidSignature | ElaraError::Crypto(_)),
            "expected InvalidSignature or Crypto(..), got {:?}",
            err.0
        );
    }

    /// AUDIT-3 (2026-04-30): /snapshot/state-delta with `since_epoch=0` must
    /// emit the full current ledger as a fallback (`baseline_available=false`)
    /// — the client always makes progress even on a non-archive node. The
    /// delta must round-trip through `verify_signed_state_delta` so the wire
    /// shape is exercised end-to-end against a live RocksDB + ledger fixture.
    #[tokio::test]
    async fn test_compute_state_delta_no_baseline_returns_full_ledger() {
        use crate::accounting::ledger::AccountState;

        let (state, _tmp) = test_state();

        // Seed two accounts directly in the ledger. Mirrors how the apply path
        // mutates accounts; we don't go through record replay because this
        // test is about the snapshot path, not consensus.
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "acct_alpha".to_string(),
                AccountState {
                    available: 1_000_000,
                    staked: 500_000,
                    total_received: 1_500_000,
                    tx_count: 3,
                    last_active: 1_700_000_000.5,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                "acct_beta".to_string(),
                AccountState {
                    available: 250_000,
                    total_received: 250_000,
                    tx_count: 1,
                    last_active: 1_700_000_100.25,
                    ..Default::default()
                },
            );
            ledger.total_supply = 1_750_000;
            ledger.total_staked = 500_000;
        }

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed");

        // since_epoch=0 → server has no baseline → fallback = full ledger.
        assert_eq!(delta.since_epoch, 0);
        assert!(
            !delta.baseline_available,
            "since_epoch=0 must report baseline_available=false"
        );
        assert_eq!(delta.total_accounts, 2);
        assert_eq!(delta.total_supply, 1_750_000);
        assert_eq!(delta.total_staked, 500_000);
        assert_eq!(
            delta.changed_accounts.len(),
            2,
            "fallback must carry the full current ledger"
        );
        assert!(delta.changed_accounts.contains_key("acct_alpha"));
        assert!(delta.changed_accounts.contains_key("acct_beta"));
        assert!(delta.removed_accounts.is_empty());

        // Roots must be hex-encoded 32-byte values.
        assert_eq!(delta.account_state_root.len(), 64);
        assert!(hex::decode(&delta.account_state_root).is_ok());
        assert_eq!(delta.merkle_root.len(), 64);
        assert!(hex::decode(&delta.merkle_root).is_ok());

        // Signing chain must close: checksum, sig, pk→identity binding.
        let signer = crate::network::snapshot::verify_signed_state_delta(&delta)
            .expect("signed state-delta must verify");
        assert_eq!(signer, delta.signer_identity);

        // JSON wire round-trip must preserve the signed payload (the f64
        // checksum bug class — caught upstream in snapshot.rs unit tests, but
        // we re-assert here at the route boundary so a future regression in
        // the route handler doesn't slip through).
        let json = serde_json::to_string(&delta).expect("serialize");
        let parsed: crate::network::snapshot::StateDelta =
            serde_json::from_str(&json).expect("deserialize");
        crate::network::snapshot::verify_signed_state_delta(&parsed)
            .expect("round-tripped delta must still verify");
    }

    // ─── compute_state_delta orthogonal-axis tests ────
    //
    // The baseline `test_compute_state_delta_no_baseline_returns_full_ledger`
    // covers the populated since_epoch=0 fallback. These five pins are each
    // orthogonal to that test AND to each other, each catching a distinct
    // class of regression that wouldn't trip the baseline:
    //   1. Empty-ledger degenerate path — counters at zero, signing chain
    //      still closes (regression that crashes on empty input would slip).
    //   2. `current_epoch = MAX(epoch_state.latest_epoch.values())` not
    //      min/first/sum — catches an iter().next() or iter().sum() regression.
    //   3. `latest_super_seal_*` BOTH come from the SAME zone (the one with
    //      max end_epoch), not split-sourced — catches the worst form of
    //      regression where epoch and hash come from different zones.
    //   4. `latest_sealed_account_smt_root` is hex-encoded round-trippable —
    //      catches a regression that drops the field or emits a non-hex string.
    //   5. JSON wire numeric-type purity — pins the exact JSON type for each
    //      field so a future serde rename/repr change is caught at compile of
    //      the test, not at the wire boundary on a live client.

    /// Axis 1: degenerate empty-ledger path — fresh state
    /// with zero accounts, since_epoch=0. The signed delta MUST still emit
    /// with all counter fields at 0 and changed/removed maps empty, AND the
    /// signing chain MUST still close so a client bootstrapping against a
    /// fresh-genesis node makes progress instead of hitting a hard error.
    #[tokio::test]
    async fn batch_kkkk_compute_state_delta_empty_ledger_yields_zero_counters_with_valid_sig() {
        let (state, _tmp) = test_state();

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed even on empty ledger");

        assert_eq!(delta.total_accounts, 0, "empty ledger ⇒ total_accounts=0");
        assert_eq!(delta.total_supply, 0, "empty ledger ⇒ total_supply=0");
        assert_eq!(delta.total_staked, 0, "empty ledger ⇒ total_staked=0");
        assert!(
            delta.changed_accounts.is_empty(),
            "empty ledger ⇒ changed_accounts must be empty (not a clone of an empty map sentinel)"
        );
        assert!(
            delta.removed_accounts.is_empty(),
            "empty ledger ⇒ removed_accounts must be empty"
        );
        assert!(
            !delta.baseline_available,
            "since_epoch=0 ⇒ baseline_available=false even on empty ledger"
        );

        // The signing chain MUST close even when the payload is degenerate.
        let signer = crate::network::snapshot::verify_signed_state_delta(&delta)
            .expect("signed empty-ledger delta must verify");
        assert_eq!(signer, delta.signer_identity);
    }

    /// Axis 2: `current_epoch` is the MAX value across all
    /// zones in `epoch_state.latest_epoch`, never min/first/sum. Seed three
    /// distinct zones at non-monotone epoch values so iter().next() (arbitrary
    /// HashMap order), iter().sum() (= 148), and iter().min() (= 7) all
    /// produce visibly-wrong answers; the correct max picks 99 every time.
    #[tokio::test]
    async fn batch_kkkk_compute_state_delta_current_epoch_picks_max_across_zones() {
        let (state, _tmp) = test_state();
        {
            use crate::network::RwLockRecover;
            let mut epoch = state.epoch.write_recover();
            epoch.latest_epoch.insert(crate::ZoneId::new("zone-a"), 7);
            epoch.latest_epoch.insert(crate::ZoneId::new("zone-b"), 99);
            epoch.latest_epoch.insert(crate::ZoneId::new("zone-c"), 42);
        }

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed");

        assert_eq!(
            delta.current_epoch, 99,
            "current_epoch must be MAX across latest_epoch values, not min/first/sum"
        );
        assert_eq!(delta.since_epoch, 0, "since_epoch echoes input verbatim");
    }

    /// Axis 3: `latest_super_seal_epoch` and
    /// `latest_super_seal_record_hash` are BOTH sourced from the SAME zone —
    /// the one with the max end_epoch. Catches the worst-case regression
    /// where the handler picks epoch from one zone but hash from another
    /// (e.g., via two separate iter() chains), producing a hash that doesn't
    /// match the epoch on the client side.
    #[tokio::test]
    async fn batch_kkkk_compute_state_delta_latest_super_seal_fields_pair_from_max_epoch_zone() {
        let (state, _tmp) = test_state();
        // Two zones with super-seals: zone_old at epoch 1024 (hash AB...),
        // zone_new at epoch 2048 (hash CD...). The handler MUST return the
        // (epoch=2048, hash=CD..) pair, never (epoch=2048, hash=AB..) or
        // (epoch=1024, hash=CD..).
        let hash_old: [u8; 32] = [0xAB; 32];
        let hash_new: [u8; 32] = [0xCD; 32];
        {
            use crate::network::RwLockRecover;
            let mut epoch = state.epoch.write_recover();
            epoch.latest_super_seal.insert(
                crate::ZoneId::new("zone-old"),
                (1024, "rec_old".to_string(), hash_old, [0u8; 32]),
            );
            epoch.latest_super_seal.insert(
                crate::ZoneId::new("zone-new"),
                (2048, "rec_new".to_string(), hash_new, [0u8; 32]),
            );
        }

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed");

        assert_eq!(
            delta.latest_super_seal_epoch,
            Some(2048),
            "latest_super_seal_epoch must come from the max-epoch zone (2048)"
        );
        assert_eq!(
            delta.latest_super_seal_record_hash,
            Some(hex::encode(hash_new)),
            "latest_super_seal_record_hash MUST come from the SAME zone as the picked epoch (not split-sourced)"
        );
    }

    /// Axis 4: `latest_sealed_account_*` populated path —
    /// when `EpochState::latest_sealed_account` is `Some((epoch, _, _, root, _))`,
    /// the delta carries both fields. The smt_root field must be the hex
    /// encoding of the in-state [u8; 32] root (not raw bytes, not base64).
    /// Round-trip through JSON + verify_signed_state_delta proves the field
    /// survives the wire boundary intact and the checksum binds it.
    #[tokio::test]
    async fn batch_kkkk_compute_state_delta_latest_sealed_account_round_trips_hex_root() {
        let (state, _tmp) = test_state();
        let root: [u8; 32] = [0xDE; 32];
        {
            use crate::network::RwLockRecover;
            let mut epoch = state.epoch.write_recover();
            epoch.latest_sealed_account = Some((
                512,
                crate::ZoneId::new("zone-payments"),
                "rec_sealed_acct".to_string(),
                root,
                1_700_000_000.0,
            ));
        }

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed");

        assert_eq!(
            delta.latest_sealed_account_epoch,
            Some(512),
            "latest_sealed_account_epoch must come from EpochState.latest_sealed_account.0"
        );
        assert_eq!(
            delta.latest_sealed_account_smt_root,
            Some(hex::encode(root)),
            "latest_sealed_account_smt_root must be the hex-encoded in-state [u8;32] root"
        );

        // Cross-check: the field survives JSON round-trip AND the
        // signature still verifies (proves the field is bound into the
        // checksum — a regression that adds the field but doesn't include
        // it in `compute_state_delta_checksum` would still pass the
        // direct-equality asserts above, but fail this verify-after-round-trip).
        let json = serde_json::to_string(&delta).expect("serialize");
        let parsed: crate::network::snapshot::StateDelta =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.latest_sealed_account_epoch, Some(512));
        assert_eq!(parsed.latest_sealed_account_smt_root, Some(hex::encode(root)));
        crate::network::snapshot::verify_signed_state_delta(&parsed)
            .expect("round-tripped delta with sealed_account must still verify");
    }

    /// Axis 5: wire numeric-type purity on the JSON repr.
    /// A future serde rename / repr change (e.g., u64-as-string for big-int
    /// JS compat, or bool-as-int) would silently break clients. Pin every
    /// primitive field's exact JSON type so the regression trips here, not
    /// on a downstream account's decoder.
    #[tokio::test]
    async fn batch_kkkk_compute_state_delta_wire_json_type_purity() {
        use crate::accounting::ledger::AccountState;
        let (state, _tmp) = test_state();
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "acct_x".to_string(),
                AccountState {
                    available: 100,
                    staked: 50,
                    total_received: 150,
                    tx_count: 1,
                    last_active: 1_700_000_000.5,
                    ..Default::default()
                },
            );
            ledger.total_supply = 150;
            ledger.total_staked = 50;
        }

        let delta = super::compute_state_delta(&state, 0)
            .await
            .expect("compute_state_delta must succeed");
        let v = serde_json::to_value(&delta).expect("delta → JSON value");
        let obj = v.as_object().expect("StateDelta serializes to JSON object");

        // u64 fields — must be JSON Number with is_u64()=true.
        for k in [
            "since_epoch",
            "current_epoch",
            "total_accounts",
            "total_supply",
            "total_staked",
        ] {
            assert!(obj[k].is_u64(), "field `{k}` must be JSON u64 (got {:?})", obj[k]);
            assert!(!obj[k].is_string(), "field `{k}` must NOT be string-encoded big-int");
        }

        // u32 field (protocol_version) — JSON has no u32; serde_json
        // promotes to u64. Assert is_u64() (which is_u32 also satisfies).
        assert!(obj["protocol_version"].is_u64());

        // bool field — must be JSON Boolean, not 0/1 integer.
        assert!(obj["baseline_available"].is_boolean());
        assert!(!obj["baseline_available"].is_number());

        // String fields — must be JSON String, not byte array.
        for k in [
            "account_state_root",
            "merkle_root",
            "signer_identity",
            "signer_public_key",
            "checksum",
            "signature",
        ] {
            assert!(obj[k].is_string(), "field `{k}` must be JSON string (got {:?})", obj[k]);
        }

        // Collection-typed fields.
        assert!(
            obj["changed_accounts"].is_object(),
            "changed_accounts is a BTreeMap → JSON Object"
        );
        assert!(
            obj["removed_accounts"].is_array(),
            "removed_accounts is a Vec → JSON Array"
        );

        // snapshot_timestamp is f64 — JSON Number (either is_f64 or, when
        // the quantized value happens to be an integer, is_i64/is_u64).
        assert!(obj["snapshot_timestamp"].is_number());
    }

    // ─── bounded HTTP delta_sync scan ─────────────────
    //
    // Mirrors the PQ-side closure to the HTTP delta_sync route. The
    // route used to call `for_each_record_id` (full CF_RECORDS sweep), which
    // at 10M records times out HTTP clients before any response. Now it reads
    // `x-delta-since` and seeks CF_IDX_TIMESTAMP from that floor, hard-capped
    // at MAX_SCAN entries. Tests pin: (a) backward compat when the header is
    // missing (defaults to 0 = full sweep, server still bounds), (b) the
    // since-floor actually filters older records, (c) `scan_hit_cap` is
    // present in the response shape so operators can see when the cap binds.

    fn ops124_test_record(timestamp: f64, id: &str) -> crate::record::ValidationRecord {
        crate::record::ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: crate::crypto::hash::sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: vec![0u8; 32],
            timestamp,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: std::collections::BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    fn ops124_empty_bloom_bytes() -> Vec<u8> {
        // An empty bloom filter (capacity 100, 1% FPR) — never matches any ID
        // → server returns every scanned record as "missing on the client".
        // Used to assert the *full set* of records the server scanned.
        BloomFilter::new(100, 0.01).to_bytes()
    }

    #[tokio::test]
    async fn test_ops124_delta_sync_missing_since_header_defaults_to_full_sweep() {
        // Backward compat: a legacy client that doesn't send `x-delta-since`
        // still works — server treats `since=0` as a full sweep (still capped
        // by MAX_SCAN, so this is bounded work even on a 10M-record DB).
        let (state, _tmp) = test_state();
        for i in 0..3 {
            let id = format!("ops124-back-{i}");
            let rec = ops124_test_record(1_700_000_000.0 + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        let body = ops124_empty_bloom_bytes();
        let resp = super::delta_sync(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::body::Bytes::from(body),
        )
        .await
        .map_err(|e| format!("{:?}", e.0))
        .expect("delta_sync must succeed without x-delta-since");

        let v = resp.0;
        assert_eq!(v["total_missing"], 3, "no since header → all 3 records returned");
        assert_eq!(v["scan_hit_cap"], false, "3 records < MAX_SCAN=50K cap");
    }

    #[tokio::test]
    async fn test_ops124_delta_sync_since_floor_filters_old_records() {
        // The bounded-scan invariant: server scans CF_IDX_TIMESTAMP from `since`
        // forward, never iterating older records. With 5 records spread across
        // a 4-hour window and `since` set between record #2 and #3, only the
        // 3 newer records should appear in the response.
        let (state, _tmp) = test_state();
        let base_ts = 1_700_000_000.0;
        for i in 0..5 {
            let id = format!("ops124-floor-{i}");
            let rec = ops124_test_record(base_ts + i as f64 * 3600.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        let mut headers = HeaderMap::new();
        // since = base_ts + 2.5h → records 0, 1, 2 excluded; 3, 4 included.
        headers.insert(
            "x-delta-since",
            format!("{}", base_ts + 2.5 * 3600.0).parse().unwrap(),
        );

        let body = ops124_empty_bloom_bytes();
        let resp = super::delta_sync(
            axum::extract::State(state.clone()),
            headers,
            axum::body::Bytes::from(body),
        )
        .await
        .map_err(|e| format!("{:?}", e.0))
        .expect("delta_sync must succeed with x-delta-since");

        let v = resp.0;
        assert_eq!(
            v["total_missing"], 2,
            "since=2.5h → only records #3 and #4 (≥ 2.5h) returned"
        );
        assert_eq!(v["scan_hit_cap"], false, "2 records < MAX_SCAN=50K");
    }

    #[tokio::test]
    async fn test_ops124_delta_sync_response_carries_scan_hit_cap_field() {
        // Forward-compat for operator tooling: the response shape must always
        // include `scan_hit_cap` as a boolean, even on the trivial empty-DB
        // path. Operators key off this field to detect "this peer's window
        // exceeds 50K records and snapshot sync is the right catch-up path."
        let (state, _tmp) = test_state();
        let body = ops124_empty_bloom_bytes();
        let resp = super::delta_sync(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::body::Bytes::from(body),
        )
        .await
        .map_err(|e| format!("{:?}", e.0))
        .expect("delta_sync must succeed on empty DB");

        let v = resp.0;
        assert!(
            v.get("scan_hit_cap").and_then(|b| b.as_bool()).is_some(),
            "response must always carry scan_hit_cap as a boolean"
        );
        assert_eq!(v["total_missing"], 0, "empty DB → no missing records");
    }

    #[tokio::test]
    async fn delta_sync_served_counters_track_serve_side_throughput() {
        // Server-side serve telemetry: delta_sync_served_total counts every
        // request this node serves to a puller; delta_sync_served_records_total
        // accumulates the records returned. Distinct from the client-side
        // delta_sync_attempts_total (pulls this node initiates). This is the
        // seed/anchor's primary "am I serving sync?" signal — verifies the wiring
        // in routes/sync.rs::delta_sync end-to-end on the real handler.
        use std::sync::atomic::Ordering;
        let (state, _tmp) = test_state();

        // Fresh NodeState: both counters start at 0.
        assert_eq!(
            state.delta_sync_served_total.load(Ordering::Relaxed),
            0,
            "delta_sync_served_total must init to 0 on fresh NodeState"
        );
        assert_eq!(
            state.delta_sync_served_records_total.load(Ordering::Relaxed),
            0,
            "delta_sync_served_records_total must init to 0 on fresh NodeState"
        );

        for i in 0..3 {
            let id = format!("served-{i}");
            let rec = ops124_test_record(1_700_000_000.0 + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // First serve: empty bloom → all records "missing" and returned.
        let resp = super::delta_sync(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::body::Bytes::from(ops124_empty_bloom_bytes()),
        )
        .await
        .map_err(|e| format!("{:?}", e.0))
        .expect("delta_sync must succeed");
        let returned = resp.0["batch_size"].as_u64().expect("batch_size is u64");

        assert_eq!(
            state.delta_sync_served_total.load(Ordering::Relaxed),
            1,
            "one served request → served_total == 1"
        );
        // served_records accumulates exactly the batch the handler returned —
        // robust to the low-RAM skip branch (which returns 0) and to pagination.
        assert_eq!(
            state.delta_sync_served_records_total.load(Ordering::Relaxed),
            returned,
            "served_records_total must equal the records returned in the response batch"
        );

        // Second serve: counter is monotonic across requests.
        let _ = super::delta_sync(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::body::Bytes::from(ops124_empty_bloom_bytes()),
        )
        .await
        .map_err(|e| format!("{:?}", e.0))
        .expect("second delta_sync must succeed");
        assert_eq!(
            state.delta_sync_served_total.load(Ordering::Relaxed),
            2,
            "two served requests → served_total == 2 (monotonic)"
        );
    }

    /// /convergence on a node with no peers must return our own root + counts
    /// and an empty peers array — never panic, never fail. Operators rely on
    /// this for first-touch sanity checks before peers are connected.
    #[tokio::test]
    async fn test_convergence_no_peers() {
        let (state, _tmp) = test_state();
        // AppError doesn't impl Debug — match instead of .expect() (matches the
        // pattern used by other tests in this module).
        let v = match super::convergence(axum::extract::State(state.clone())).await {
            Ok(j) => j.0,
            Err(_) => panic!("convergence handler must succeed with zero peers"),
        };

        assert!(v["our_root"].is_string(), "our_root must be present");
        assert_eq!(v["our_record_count"], 0);
        assert_eq!(v["peers_checked"], 0);
        assert_eq!(v["peers_in_sync"], 0);
        assert_eq!(v["peers_diverged"], 0);
        assert!(v["peers"].is_array());
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);
    }

    // ─── Static-data surface pins ─────────────────────
    //
    // These three #[test] entries pin load-bearing static-data surfaces of
    // `routes/sync.rs` that have no global gauge state (so they race-freely
    // with the existing pressure-gauge test in this mod) and exercise wire-
    // shape + circuit-breaker constants the rest of the file relies on.

    /// Mainnet circuit-breaker thresholds for `/snapshot`.
    /// Both caps are non-zero; applied = 10 × accounts, reflecting the
    /// "10K busy accounts × 1K records/account = 10M, cap at 1M" 4 GB-VPS
    /// safety budget in the comments at L548-560. If anyone bumps these
    /// without bumping the docs + the pressure-gauge test, this fails first.
    #[test]
    fn batch_a_max_snapshot_constants_pin_mainnet_defaults_and_10x_ratio() {
        assert_eq!(MAX_SNAPSHOT_FULL_ACCOUNTS, 100_000);
        assert_eq!(MAX_SNAPSHOT_APPLIED_RECORDS, 1_000_000);
        // The two `> 0` non-zero invariants are now `const _: () = assert!(..)`
        // static assertions at module scope near the const declarations (see
        // L562-L568) — they fire at compile time instead of test runtime.
        // Their former runtime-assert versions were clippy::assertions_on_constants
        // tautological since both sides are compile-time constants.
        assert!(
            MAX_SNAPSHOT_APPLIED_RECORDS > MAX_SNAPSHOT_FULL_ACCOUNTS as u64,
            "applied cap must exceed accounts cap (records-per-account > 1)"
        );
        assert_eq!(
            MAX_SNAPSHOT_APPLIED_RECORDS,
            10 * MAX_SNAPSHOT_FULL_ACCOUNTS as u64,
            "applied/accounts ratio must remain 10x — see L548-560 comment"
        );
    }

    /// `AttestationSubmit` is the wire body for `POST /attestation`. Pin the
    /// JSON field names and the optional/required split — flipping any name
    /// or making a required field optional silently breaks every existing
    /// witness signer in the fleet.
    #[test]
    fn batch_a_attestation_submit_wire_shape_pins_required_and_optional_fields() {
        // All seven fields populated.
        let full = serde_json::json!({
            "record_id": "rec-abc",
            "witness_hash": "deadbeef".repeat(8),
            "signature": "00".repeat(3293),
            "timestamp": 1_700_000_000.0,
            "witness_public_key": "AA".repeat(1952),
            "powas_nonce": 42u64,
            "powas_difficulty": 8u64,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(full).expect("full attestation must deserialize");
        assert_eq!(parsed.record_id, "rec-abc");
        assert_eq!(parsed.witness_hash.len(), 64);
        assert_eq!(parsed.signature.len(), 6586);
        assert!((parsed.timestamp - 1_700_000_000.0).abs() < 1e-9);
        assert!(parsed.witness_public_key.is_some());
        assert_eq!(parsed.powas_nonce, Some(42));
        assert_eq!(parsed.powas_difficulty, Some(8));

        // Only the four required fields — the three optionals MUST default to None.
        let minimal = serde_json::json!({
            "record_id": "rec-xyz",
            "witness_hash": "0".repeat(64),
            "signature": "0".repeat(6586),
            "timestamp": 0.0,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(minimal).expect("minimal attestation must deserialize");
        assert_eq!(parsed.record_id, "rec-xyz");
        assert!(parsed.witness_public_key.is_none());
        assert!(parsed.powas_nonce.is_none());
        assert!(parsed.powas_difficulty.is_none());

        // Missing required field rejects — `record_id` absent.
        let bad = serde_json::json!({
            "witness_hash": "0".repeat(64),
            "signature": "0".repeat(6586),
            "timestamp": 0.0,
        });
        let err = match serde_json::from_value::<AttestationSubmit>(bad) {
            Ok(_) => panic!("missing record_id must reject"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("record_id"),
            "error must name the missing field, got: {err}"
        );
    }

    /// `OfflineNotification` is the wire body for the peer "I'm going down"
    /// RPC. Field name `timestamp_secs` (NOT `timestamp` / `ts`) and the
    /// integer type (`u64`, NOT `f64`) are both load-bearing — a negative
    /// or fractional value MUST refuse to deserialize so a malicious peer
    /// can't poison the offline list with a sentinel timestamp.
    #[test]
    fn batch_a_offline_notification_wire_shape_pins_field_names_and_u64_type() {
        let happy = serde_json::json!({
            "node_id": "peer-abc",
            "timestamp_secs": 1_777_000_000u64,
            "sig": "00".repeat(3293),
        });
        let parsed: OfflineNotification =
            serde_json::from_value(happy).expect("happy-path offline notify must parse");
        assert_eq!(parsed.node_id, "peer-abc");
        assert_eq!(parsed.timestamp_secs, 1_777_000_000);
        assert_eq!(parsed.sig.len(), 6586);

        // Wrong field name — `timestamp` (no `_secs`) MUST be rejected.
        let wrong_name = serde_json::json!({
            "node_id": "peer-abc",
            "timestamp": 1_777_000_000u64,
            "sig": "00".repeat(3293),
        });
        assert!(
            serde_json::from_value::<OfflineNotification>(wrong_name).is_err(),
            "wire-name `timestamp` (without `_secs`) must NOT parse — old name still locked out"
        );

        // Negative timestamp rejected by u64 deserializer.
        let negative = serde_json::json!({
            "node_id": "peer-abc",
            "timestamp_secs": -1i64,
            "sig": "00".repeat(3293),
        });
        assert!(
            serde_json::from_value::<OfflineNotification>(negative).is_err(),
            "negative timestamp must NOT parse — u64 wire type rejects it"
        );
    }

    // ─── Pure-surface pins ───────────────────────
    //
    // An earlier pass pinned the snapshot
    // caps + AttestationSubmit + OfflineNotification deserialize shape. These
    // five fixture-free tests pin the rest of the pure surface that did NOT
    // already have a guard: `AttestationQuery` wire shape (the read-side
    // counterpart to AttestationSubmit), `CONVERGENCE_LOCK_TIMEOUT` constant,
    // the `AttestationSubmit::signature` responsibility-boundary (struct =
    // String container, handler = hex+length validation), the
    // `OfflineNotification` field-order / extra-keys behaviour, and the
    // Some(0) vs explicit-None distinguishability on the powas pair (which
    // gates the optional PoWAS verification branch at L400).

    #[test]
    fn batch_b_attestation_query_wire_shape_pins_all_optional_fields_and_field_names() {
        // All three fields populated.
        let full = serde_json::json!({
            "record_id": "rec-target",
            "since": 1_700_000_000.5,
            "limit": 250usize,
        });
        let parsed: AttestationQuery =
            serde_json::from_value(full).expect("full query must deserialize");
        assert_eq!(parsed.record_id.as_deref(), Some("rec-target"));
        assert!(matches!(parsed.since, Some(t) if (t - 1_700_000_000.5).abs() < 1e-9));
        assert_eq!(parsed.limit, Some(250));

        // Empty object — ALL three fields MUST default to None. The handler
        // at query_attestations selects the "by-record" branch only when
        // record_id is Some; an empty body falls through to "by-time" with
        // since=0.0 + limit=100 defaults. Pin all-None so a future
        // #[serde(default = "...")] on any field would surface here.
        let empty: AttestationQuery =
            serde_json::from_value(serde_json::json!({})).expect("empty query must parse");
        assert!(empty.record_id.is_none());
        assert!(empty.since.is_none());
        assert!(empty.limit.is_none());

        // Limit-only — pins per-field independence (record_id+since still None).
        let limit_only: AttestationQuery =
            serde_json::from_value(serde_json::json!({"limit": 50})).expect("limit-only");
        assert!(limit_only.record_id.is_none());
        assert!(limit_only.since.is_none());
        assert_eq!(limit_only.limit, Some(50));

        // Since accepts integer (JSON number → f64 via serde coercion). Many
        // operator scripts write `since: 0` not `since: 0.0` — flipping the
        // wire type to a strict f64 would silently break them.
        let since_int: AttestationQuery =
            serde_json::from_value(serde_json::json!({"since": 0})).expect("integer since");
        assert!(matches!(since_int.since, Some(t) if t == 0.0));

        // Zero limit + huge limit BOTH parse at the struct layer — the
        // clamping (`.unwrap_or(100).min(10_000)`) lives in the handler, so
        // the wire layer accepts anything the type can hold. A regression
        // that added #[serde(deserialize_with = clamp)] at the struct layer
        // would surface here.
        let zero_limit: AttestationQuery =
            serde_json::from_value(serde_json::json!({"limit": 0})).expect("zero limit");
        assert_eq!(zero_limit.limit, Some(0));
        let huge_limit: AttestationQuery =
            serde_json::from_value(serde_json::json!({"limit": 5_000_000usize})).expect("huge");
        assert_eq!(huge_limit.limit, Some(5_000_000));

        // Unknown extra fields tolerated (no #[serde(deny_unknown_fields)]).
        // Operators often append diagnostic fields on the wire; rejecting
        // them would break those scripts.
        let extra: AttestationQuery = serde_json::from_value(
            serde_json::json!({"record_id": "r", "operator_note": "hello"}),
        )
        .expect("extra fields tolerated");
        assert_eq!(extra.record_id.as_deref(), Some("r"));

        // Wrong type on `limit` (string instead of number) MUST reject — pin
        // the type discipline; a future "permissive" relax that coerced
        // numeric strings would silently allow malformed peers.
        let wrong_type =
            serde_json::from_value::<AttestationQuery>(serde_json::json!({"limit": "fifty"}));
        assert!(wrong_type.is_err(), "string-typed limit must NOT parse");
    }

    #[test]
    fn batch_b_convergence_lock_timeout_pins_2s_and_strict_subset_of_default_call_timeout() {
        // The 2 s slot-lock timeout caps worst-case wait at 4 s/peer when a
        // heal cycle is mid-flight (L58-60 comment). Drift would either
        // tighten and false-positive on legit heal cycles (e.g. 500 ms) or
        // loosen and let the /convergence endpoint stall past the 30 s
        // DEFAULT_CALL_TIMEOUT for downstream callers.
        assert_eq!(
            CONVERGENCE_LOCK_TIMEOUT,
            std::time::Duration::from_secs(2),
            "CONVERGENCE_LOCK_TIMEOUT drift breaks the 4 s/peer worst-case wait budget"
        );

        // The lock timeout MUST be strictly less than the per-call timeout.
        // If `lock >= call`, the slot-lock would eat the entire RPC budget
        // and the actual /merkle_root + /status round-trips would have no
        // headroom. Pin this relationship so a future bump to either
        // constant surfaces the regression.
        assert!(
            CONVERGENCE_LOCK_TIMEOUT < crate::network::pq_client::DEFAULT_CALL_TIMEOUT,
            "lock timeout ({:?}) must be < DEFAULT_CALL_TIMEOUT ({:?}) — \
             otherwise slot acquisition can consume the entire RPC budget",
            CONVERGENCE_LOCK_TIMEOUT,
            crate::network::pq_client::DEFAULT_CALL_TIMEOUT
        );

        // And at least 1 s — anything tighter would false-positive on
        // healthy heal cycles where the inner mutex is legitimately held
        // for hundreds of ms during PQ handshake.
        assert!(
            CONVERGENCE_LOCK_TIMEOUT >= std::time::Duration::from_secs(1),
            "lock timeout below 1 s would false-positive on healthy heal cycles"
        );
    }

    #[test]
    fn batch_b_attestation_submit_signature_field_is_string_zero_length_parses_at_struct_layer() {
        // Responsibility boundary: `AttestationSubmit::signature` is a
        // String container. ALL hex/length/cryptographic validation lives
        // in `receive_attestation` (hex::decode → empty check → Dilithium3
        // verify). A regression that moved validation to the wire layer
        // (e.g. #[serde(deserialize_with = hex_decode)]) would change the
        // error path from `ElaraError::Wire("bad signature hex")` to a
        // serde JSON parse error — operators searching log lines for the
        // former would silently miss the same condition.

        // Zero-length signature parses at the struct layer (handler rejects
        // it via the `if sig_bytes.is_empty()` branch at L272-275).
        let empty_sig = serde_json::json!({
            "record_id": "r1",
            "witness_hash": "0".repeat(64),
            "signature": "",
            "timestamp": 0.0,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(empty_sig).expect("empty signature must parse");
        assert!(parsed.signature.is_empty());

        // Non-hex signature ALSO parses at the struct layer (handler rejects
        // via the `hex::decode` Err branch). A peer that submits "not-hex"
        // gets a Wire error from the handler, not a JSON parse error.
        let bad_hex = serde_json::json!({
            "record_id": "r2",
            "witness_hash": "0".repeat(64),
            "signature": "GG_NOT_HEX_!@#",
            "timestamp": 0.0,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(bad_hex).expect("non-hex signature must parse at struct layer");
        assert_eq!(parsed.signature, "GG_NOT_HEX_!@#");

        // Short signature (1 byte hex → 2 chars) also parses — length is
        // NOT validated at the struct layer. Sub-Dilithium3-size sigs are
        // caught only at the verify step where ML-DSA-65 length check fires.
        let short_sig = serde_json::json!({
            "record_id": "r3",
            "witness_hash": "0".repeat(64),
            "signature": "AB",
            "timestamp": 0.0,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(short_sig).expect("short signature must parse");
        assert_eq!(parsed.signature.len(), 2);

        // Wrong type — signature as a JSON number MUST reject (type discipline).
        let wrong_type = serde_json::json!({
            "record_id": "r4",
            "witness_hash": "0".repeat(64),
            "signature": 12345,
            "timestamp": 0.0,
        });
        assert!(
            serde_json::from_value::<AttestationSubmit>(wrong_type).is_err(),
            "numeric signature MUST NOT parse — String type discipline"
        );
    }

    #[test]
    fn batch_b_offline_notification_field_order_agnostic_with_extra_fields_ignored() {
        // JSON object members are unordered by RFC 8259, and serde-default
        // follows that. Pin so a future #[serde(rename_all)] or strict-order
        // attribute doesn't silently rebind field associations by position.
        let reordered = serde_json::json!({
            "sig": "0".repeat(6586),
            "timestamp_secs": 1_777_000_000u64,
            "node_id": "peer-reord",
        });
        let parsed: OfflineNotification =
            serde_json::from_value(reordered).expect("reordered fields must parse");
        assert_eq!(parsed.node_id, "peer-reord");
        assert_eq!(parsed.timestamp_secs, 1_777_000_000);

        // Extra unknown field is tolerated (no #[serde(deny_unknown_fields)]).
        // The protocol may grow forward-compat hints (e.g. "version": 2);
        // rejecting unknowns would silently break those upgrades on old peers.
        let with_extra = serde_json::json!({
            "node_id": "peer-extra",
            "timestamp_secs": 1u64,
            "sig": "0".repeat(6586),
            "future_hint": "should-be-ignored",
            "version": 99,
        });
        let parsed: OfflineNotification =
            serde_json::from_value(with_extra).expect("extra fields must be ignored");
        assert_eq!(parsed.node_id, "peer-extra");

        // Empty node_id IS accepted at the wire layer — there's no
        // #[serde(deserialize_with=non_empty)] guard. The handler's peer
        // lookup `peers.get("")` fails the unknown-peer branch and returns
        // a graceful `{"status": "unknown_peer"}` without verifying, so an
        // empty id can't poison the offline list — but the wire layer must
        // accept it. Pin so a future strict-wire validation would surface.
        let empty_id = serde_json::json!({
            "node_id": "",
            "timestamp_secs": 1u64,
            "sig": "0".repeat(6586),
        });
        let parsed: OfflineNotification =
            serde_json::from_value(empty_id).expect("empty node_id must parse at wire layer");
        assert!(parsed.node_id.is_empty());

        // Required field absent — `node_id` missing MUST reject and error
        // must name the field (parsable by operator log scripts).
        // (OfflineNotification doesn't derive Debug, so use match instead
        // of expect_err which requires Debug on the Ok variant.)
        let missing_node_id = serde_json::json!({
            "timestamp_secs": 1u64,
            "sig": "0".repeat(6586),
        });
        let err = match serde_json::from_value::<OfflineNotification>(missing_node_id) {
            Ok(_) => panic!("missing node_id must reject"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("node_id"),
            "error must name missing required field, got: {err}"
        );
    }

    #[test]
    fn batch_b_attestation_submit_powas_pair_some_zero_distinguishable_from_explicit_null() {
        // The PoWAS verification branch at L400 reads
        // `if let (Some(nonce), Some(difficulty)) = (body.powas_nonce, body.powas_difficulty)`.
        // Some(0)+Some(0) DOES trigger the branch (and the handler's
        // difficulty check then rejects difficulty<min_pow_difficulty);
        // None+None SKIPS the branch entirely. So Some(0) and None are
        // semantically distinguishable in the consensus path — pin that
        // serde does NOT collapse them.
        let zero_pair = serde_json::json!({
            "record_id": "r-zero",
            "witness_hash": "0".repeat(64),
            "signature": "0".repeat(6586),
            "timestamp": 0.0,
            "powas_nonce": 0u64,
            "powas_difficulty": 0u64,
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(zero_pair).expect("Some(0) powas pair must parse");
        assert_eq!(parsed.powas_nonce, Some(0), "Some(0) MUST NOT collapse to None");
        assert_eq!(parsed.powas_difficulty, Some(0), "Some(0) MUST NOT collapse to None");

        // Explicit JSON null on Option<u64> deserializes to None — pin
        // this is identical to the field being absent. A future serde
        // shift that distinguished "null" from "absent" would break
        // every peer that explicitly sends `"powas_nonce": null`.
        let explicit_null = serde_json::json!({
            "record_id": "r-null",
            "witness_hash": "0".repeat(64),
            "signature": "0".repeat(6586),
            "timestamp": 0.0,
            "powas_nonce": serde_json::Value::Null,
            "powas_difficulty": serde_json::Value::Null,
        });
        let parsed: AttestationSubmit = serde_json::from_value(explicit_null)
            .expect("explicit null powas pair must parse");
        assert_eq!(parsed.powas_nonce, None);
        assert_eq!(parsed.powas_difficulty, None);

        // Asymmetric pair — only one side Some. The handler's `if let
        // (Some, Some)` branch is a CONJUNCTION; if only one is Some, the
        // branch is NOT taken (PoWAS skipped). Pin that the wire layer
        // accepts this asymmetric shape — it's the handler that decides
        // whether to evaluate PoWAS.
        let asymmetric = serde_json::json!({
            "record_id": "r-asym",
            "witness_hash": "0".repeat(64),
            "signature": "0".repeat(6586),
            "timestamp": 0.0,
            "powas_nonce": 42u64,
            // powas_difficulty deliberately absent
        });
        let parsed: AttestationSubmit =
            serde_json::from_value(asymmetric).expect("asymmetric pair must parse");
        assert_eq!(parsed.powas_nonce, Some(42));
        assert_eq!(parsed.powas_difficulty, None);
    }

    // ─── compute_receive_offline_notification
    // orthogonal-branch pins + sig-verify-bool-bypass regression ─────────────
    //
    // `compute_receive_offline_notification` (sync.rs:1160) is the service-fn
    // shared between (a) the HTTP `/peers/offline_notification` POST handler
    // (sync.rs:1148) and (b) the PQ-transport `handle_receive_offline_notification`
    // verb (pq_transport/router.rs:2909). Both paths drop here, so a single
    // covering test pair pins both wire surfaces.
    //
    // The five tests below cover four orthogonal early-exit branches plus the
    // regression that motivated the same-commit code fix: the previous
    // `dilithium3_verify(...).map_err(...)?` pattern propagated the Err arm
    // but ignored `Ok(false)`, so a forged-but-length-valid signature would
    // bypass the verification gate and mark the named peer as
    // `PeerState::Offline`. Blast radius is small (peer auto-recovers on the
    // next gossip exchange, no reputation penalty per the docstring) but the
    // verify gate exists to prevent unauthorized state mutation; the fix
    // rejects `Ok(false)` explicitly, mirroring the `if !verify(...)?` shape
    // used at sync.rs:331 / ingest.rs:771 / core.rs:1133 / router.rs:867 /
    // router.rs:1129 / witness.rs:147 / handshake.rs:377 / handshake.rs:435.
    //
    // The unknown-peer branch is a deliberate `{"status": "unknown_peer"}`
    // Ok response (NOT an Err), so an attacker can't trigger error-path
    // metrics by spamming bogus node_ids — pinned here so a future refactor
    // that "tightens" the API by returning Err on unknown peers would
    // surface as a test failure, not a silent ops-alert spam regression.

    fn batch_dddd_make_peer_with_pk_hex(id: &str, pk_hex: String) -> crate::network::peer::PeerInfo {
        crate::network::peer::PeerInfo {
            identity_hash: id.to_string(),
            host: "127.0.0.1".to_string(),
            port: 9473,
            node_type: crate::network::peer::NodeType::Leaf,
            last_seen: 1000.0,
            state: crate::network::peer::PeerState::Connected,
            failures: 0,
            successes: 0,
            valid_records: 0,
            invalid_records: 0,
            backoff_until: 0.0,
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: pk_hex,
            provenance: crate::network::peer::PeerProvenance::Outbound,
            subscribed_zones: Vec::new(),
            att_watermark: 0.0,
            pull_failures: 0,
            pull_backoff_until: 0.0,
            reachable: true,
            protocol_version: 0,
            att_pull_invalid_sig: 0,
            att_pull_invalid_powas: 0,
            att_push_low_stake_deferred: 0,
            recent_bad_sig_record_ids: std::collections::VecDeque::new(),
        }
    }

    #[tokio::test]
    async fn batch_dddd_compute_receive_offline_notification_unknown_peer_returns_status_envelope_not_error() {
        // PIN: PeerTable empty → `compute_receive_offline_notification` MUST
        // return `Ok({"status": "unknown_peer"})`. NOT `Err(InvalidSignature)`,
        // NOT `Err(Wire)`, NOT a panic. Operators rely on this graceful path
        // so that random bogus offline-broadcasts (e.g. from a peer that
        // never connected to us) don't generate sig-verify-error noise.
        let (state, _tmp) = test_state();
        let body = super::OfflineNotification {
            node_id: "peer-never-seen".to_string(),
            timestamp_secs: 1_777_000_000,
            sig: "00".repeat(3309), // length-valid hex; never reached
        };
        let result = super::compute_receive_offline_notification(&state, body).await;
        let v = result.expect("unknown peer MUST return Ok, not Err");
        assert_eq!(
            v.get("status").and_then(|s| s.as_str()),
            Some("unknown_peer"),
            "unknown-peer branch wire shape MUST be {{\"status\": \"unknown_peer\"}}",
        );
        // Strict single-key envelope — pins the response is JUST {status},
        // not {status, ..._extra_fields}. A future addition of an `attempted_at`
        // timestamp would be a wire-shape change that operator scripts must
        // adopt explicitly.
        let obj = v.as_object().expect("response MUST be a JSON Object");
        assert_eq!(obj.len(), 1, "unknown_peer envelope MUST have exactly 1 key, got {:?}", obj.keys().collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn batch_dddd_compute_receive_offline_notification_known_peer_with_empty_pubkey_falls_into_unknown_branch() {
        // PIN: `match peers.get(&body.node_id) { Some(p) if !p.public_key_hex.is_empty() => ... }`
        // is a guarded match arm. A peer present in the table but with an
        // empty stored public_key_hex (the pre-PoW / pre-handshake state)
        // MUST fall through to the wildcard `_ =>` branch and return
        // `Ok({"status": "unknown_peer"})`. This pins that the guard is on
        // the OPTION + KEY shape, not on the presence of the peer alone —
        // a regression that dropped the `!is_empty()` guard would attempt
        // hex-decode of `""` (success: empty vec) → dilithium3_verify with
        // an empty pubkey → Wire("sig verify failed: ...") error to the
        // peer, which would surface as a SPURIOUS error-path log for the
        // legitimate empty-pk-known-peer case during early handshake.
        let (state, _tmp) = test_state();
        {
            let mut peers = state.peers.write().await;
            assert!(
                peers.insert(batch_dddd_make_peer_with_pk_hex(
                    "peer-known-no-pk",
                    String::new(),
                )),
                "peer insert MUST succeed (min_pow_difficulty=0 in test fixture)",
            );
        }
        let body = super::OfflineNotification {
            node_id: "peer-known-no-pk".to_string(),
            timestamp_secs: 1_777_000_000,
            sig: "00".repeat(3309),
        };
        let result = super::compute_receive_offline_notification(&state, body).await;
        let v = result.expect("empty-pk-known-peer MUST return Ok, not Err");
        assert_eq!(
            v.get("status").and_then(|s| s.as_str()),
            Some("unknown_peer"),
            "empty-pk guard MUST route to unknown_peer wire response",
        );
    }

    #[tokio::test]
    async fn batch_dddd_compute_receive_offline_notification_invalid_sig_hex_returns_wire_error_naming_field() {
        // PIN: body.sig contains non-hex characters → `hex::decode` errors →
        // `ElaraError::Wire("offline_notification: invalid sig hex")`.
        // Critical: error message MUST name "sig hex" specifically (not
        // generic "invalid hex" or "decode error") so operator log scripts
        // can distinguish from `invalid pk hex` (different remediation:
        // sig-hex points to a buggy CLIENT, pk-hex points to a CORRUPT
        // local peer-table entry).
        let (state, _tmp) = test_state();
        // Need a peer with a non-empty pk to escape the unknown-peer
        // short-circuit and reach the sig hex::decode at sync.rs:1200.
        // Inject directly: this test pins the HANDLER's sig-hex branch, not
        // insert() admission — and post-B5 insert() rejects a peer whose
        // identity_hash is not sha3(pubkey) (F2). insert() policy is covered
        // separately by the b5_* tests in peer.rs.
        {
            let mut peers = state.peers.write().await;
            peers.insert_unchecked(batch_dddd_make_peer_with_pk_hex(
                "peer-good-pk",
                "ab".repeat(1952), // valid hex, length-irrelevant for the SIG-hex test path
            ));
        }
        let body = super::OfflineNotification {
            node_id: "peer-good-pk".to_string(),
            timestamp_secs: 1_777_000_000,
            sig: "GG_definitely_not_hex_ZZ".to_string(),
        };
        let err = super::compute_receive_offline_notification(&state, body)
            .await
            .expect_err("non-hex sig MUST surface as Wire error, not silently succeed");
        match err {
            ElaraError::Wire(msg) => {
                assert!(
                    msg.contains("invalid sig hex"),
                    "Wire error MUST name 'invalid sig hex' for operator log triage, got: {msg}",
                );
            }
            other => panic!("expected Wire error variant, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_dddd_compute_receive_offline_notification_peer_with_invalid_pubkey_hex_returns_wire_error_naming_field() {
        // PIN (defense-in-depth): a table entry with a non-hex stored
        // `public_key_hex` must surface in the handler as
        // `ElaraError::Wire("offline_notification: invalid pk hex")` at
        // sync.rs:1202. Post-B5, insert() unconditionally REJECTS such a peer
        // (F2 identity-binding hex-decodes every non-empty pk), so this corrupt
        // entry can only reach the table via a non-insert() path — we simulate
        // that with insert_unchecked. The handler keeps the decode guard as a
        // safety net (the in-memory table is insert()-only today, but the guard
        // must not assume that holds forever). Critical: the error MUST say
        // "invalid pk hex" so operators can tell the corrupt-local-state path
        // apart from the bad-client sig-hex path (different remediation).
        let (state, _tmp) = test_state();
        {
            let mut peers = state.peers.write().await;
            peers.insert_unchecked(batch_dddd_make_peer_with_pk_hex(
                "peer-bad-pk-hex",
                "ZZ_corrupted_pk_storage_NOT_HEX_".to_string(),
            ));
        }
        let body = super::OfflineNotification {
            node_id: "peer-bad-pk-hex".to_string(),
            timestamp_secs: 1_777_000_000,
            // Length-valid hex sig; we want the FAILURE to come from pk hex
            // decode at sync.rs:1180, not sig hex decode at sync.rs:1178.
            sig: "00".repeat(3309),
        };
        let err = super::compute_receive_offline_notification(&state, body)
            .await
            .expect_err("corrupt-pk-hex peer MUST surface as Wire error");
        match err {
            ElaraError::Wire(msg) => {
                assert!(
                    msg.contains("invalid pk hex"),
                    "Wire error MUST name 'invalid pk hex' for operator log triage, got: {msg}",
                );
                assert!(
                    !msg.contains("invalid sig hex"),
                    "pk-hex error MUST NOT mention sig hex — wire-shape distinguishability invariant: {msg}",
                );
            }
            other => panic!("expected Wire error variant, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_dddd_compute_receive_offline_notification_forged_sig_with_valid_pubkey_returns_sig_verify_returned_false() {
        // PIN (regression for same-commit bug-fix): a length-valid (3309-byte)
        // Dilithium3 signature that fails CRYPTOGRAPHIC verification MUST
        // surface as `ElaraError::Wire("...sig verify returned false")`.
        //
        // The bug: pre-fix, `dilithium3_verify(...).map_err(...)?` only
        // propagated the Err arm; `Ok(false)` was treated as success and
        // the handler proceeded to mark the named peer as
        // `PeerState::Offline`. An attacker who knew a target peer's
        // public key could forge a length-valid sig and trigger
        // unauthorized state mutation. Auto-recovery on next heartbeat
        // limits blast radius, but the verify gate exists to prevent
        // exactly this. Same-commit fix at sync.rs:1183 explicitly
        // rejects the `Ok(false)` arm.
        //
        // Test construction: generate a real Dilithium3 keypair, install
        // it under a peer, then SIGN A DIFFERENT MESSAGE (the wrong
        // signable) — this yields a sig that:
        //   (a) is exactly 3309 bytes (passes the length precondition in
        //       dilithium3_verify at pqc.rs:108),
        //   (b) returns `Ok(false)` from DilithiumKeyPair::verify when
        //       checked against the canonical "going_offline:{id}:{ts}"
        //       signable.
        // Pre-fix: handler would succeed → peer.state becomes Offline.
        // Post-fix: handler returns Wire error → peer.state stays
        // Connected. We assert both: the Err shape AND that the peer
        // was NOT marked offline.
        let (state, _tmp) = test_state();
        // Generate a real keypair for an arbitrary identity. We use it as
        // the peer's stored pk and to sign a deliberately-wrong signable.
        let kp = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .expect("generate identity");
        let pk_hex = hex::encode(&kp.public_key);

        {
            // Inject directly: insert() would reject this fixture post-B5 (the
            // human-readable id is not sha3(pk), F2). This test pins the
            // HANDLER's forged-sig verify branch, not insert() admission.
            let mut peers = state.peers.write().await;
            peers.insert_unchecked(batch_dddd_make_peer_with_pk_hex(
                "peer-forge-target",
                pk_hex,
            ));
        }

        // Sign a DIFFERENT signable than what the handler will
        // canonicalize. The handler builds:
        //   format!("going_offline:{}:{}", body.node_id, body.timestamp_secs)
        // We sign a wrong-id variant — same shape, different node_id, so
        // the sig length is correct (3309 bytes) but verify returns false.
        let wrong_signable = b"going_offline:peer-different-id:0";
        let forged_sig = kp.sign(wrong_signable).expect("sign wrong message");
        assert_eq!(
            forged_sig.len(),
            3309,
            "Dilithium3 ML-DSA-65 signature MUST be exactly 3309 bytes — \
             precondition for hitting the verify-bool branch rather than \
             the length-check Err arm at pqc.rs:108",
        );

        let body = super::OfflineNotification {
            node_id: "peer-forge-target".to_string(),
            timestamp_secs: 1_777_000_000,
            sig: hex::encode(&forged_sig),
        };
        let err = super::compute_receive_offline_notification(&state, body)
            .await
            .expect_err(
                "forged-but-length-valid sig MUST surface as Wire error after \
                 same-commit fix to reject Ok(false) from dilithium3_verify",
            );
        match err {
            ElaraError::Wire(msg) => {
                assert!(
                    msg.contains("sig verify returned false"),
                    "Wire error MUST surface the verify-bool-false branch \
                     distinctly from the length-precondition Err arm \
                     ('sig verify failed: ...'), got: {msg}",
                );
            }
            other => panic!("expected Wire error variant, got: {other:?}"),
        }

        // Peer state invariant: forged-sig MUST NOT have flipped the peer
        // to Offline. This is the bug's external symptom — pre-fix the
        // peer would be Offline here.
        let peers = state.peers.read().await;
        let p = peers.get("peer-forge-target").expect("peer still in table");
        assert_eq!(
            p.state,
            crate::network::peer::PeerState::Connected,
            "forged-sig MUST NOT mutate peer.state — pre-fix this would be Offline",
        );
    }

    // ─── compute_list_epoch_snapshots orthogonal pins ─────
    //
    // The pure helper at routes/sync.rs:798 is the read-side of the Gap 7
    // archive-snapshot wire surface. Two callers: (1) `list_epoch_snapshots_route`
    // serves `/snapshot/epochs/list` for operator dashboards + bootstrap clients,
    // (2) potential PQ /snapshot/epochs surface. It previously had zero direct
    // tests — earlier work covered the gauges-side observability surface
    // but never touched this helper. The five tests below pin the JSON
    // envelope, sort order, filename-filter semantics, and config-mirroring
    // contracts so a refactor that silently changes any of them surfaces here.

    #[tokio::test]
    async fn batch_yyy_compute_list_epoch_snapshots_empty_dir_baseline() {
        // No snapshots directory created → the helper must still succeed with
        // a structured "zero state" envelope. Pins (a) no panic on missing
        // dir (the underlying `list_epoch_snapshots` short-circuits via
        // `!dir.exists()`), (b) `epochs` is an empty JSON array (NOT null),
        // (c) `count == 0` strict u64, (d) `latest` is JSON null (operator
        // dashboards iterate the array and read latest separately — a null
        // marker is the documented "no snapshot yet" wire signal vs an
        // accidental `latest = 0` which would falsely indicate epoch-0).
        let (state, _tmp) = test_state();
        let v = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute_list_epoch_snapshots must succeed on missing dir");
        assert!(v.is_object(), "top-level wire is a JSON Object");
        let epochs = v["epochs"]
            .as_array()
            .expect("epochs must be an Array, not null");
        assert!(epochs.is_empty(), "fresh tempdir has zero snapshots");
        assert_eq!(
            v["count"].as_u64(),
            Some(0),
            "count must be strict u64 == 0"
        );
        assert!(
            v["latest"].is_null(),
            "latest is JSON null when no snapshots exist (NOT 0 — that would falsely indicate epoch-0)"
        );
    }

    #[tokio::test]
    async fn batch_yyy_compute_list_epoch_snapshots_top_level_five_key_contract() {
        // Top-level JSON envelope MUST carry exactly 5 keys:
        //   epochs / count / latest /
        //   archive_snapshot_every_n_epochs / archive_snapshot_retention.
        // A silent 6th-key bloat (e.g., accidentally adding "total_size_bytes")
        // would inflate every dashboard scrape; a missing key would break
        // operator runbooks that iterate by name. This pins the set strictly.
        let (state, _tmp) = test_state();
        let v = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute ok");
        let obj = v.as_object().expect("top-level must be Object");
        let got: std::collections::BTreeSet<&str> =
            obj.keys().map(|s| s.as_str()).collect();
        let want: std::collections::BTreeSet<&str> = [
            "epochs",
            "count",
            "latest",
            "archive_snapshot_every_n_epochs",
            "archive_snapshot_retention",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            got, want,
            "top-level key set must match exactly (no addition, no removal)"
        );
    }

    #[tokio::test]
    async fn batch_yyy_compute_list_epoch_snapshots_multi_strict_ascending_sort() {
        // Files written out-of-numeric-order in the directory must surface
        // ascending by epoch number. Pins (a) sort stability across
        // arbitrary insertion order, (b) `count` matches the array length,
        // (c) `latest` is the max (not the most-recently-written file),
        // (d) every element parses as u64 (strict type, not string).
        // A regression sorting lexicographically over the raw filenames
        // would happen to work here because the {:012} zero-padding makes
        // numeric and lex order coincide — but a regression sorting by
        // file mtime would surface here (5 disjoint values can't all be
        // both numerically sorted AND chronologically sorted).
        use std::fs;
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        fs::create_dir_all(&dir).expect("mkdir snapshots");
        // Write in scrambled order with deliberate delays-by-creation so
        // mtime != numeric epoch order.
        for n in [42u64, 7, 100, 1, 99] {
            fs::write(
                dir.join(crate::network::snapshot::epoch_snapshot_filename(n)),
                b"{}",
            )
            .expect("write epoch file");
        }
        let v = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute ok");
        let epochs: Vec<u64> = v["epochs"]
            .as_array()
            .expect("epochs array")
            .iter()
            .map(|e| e.as_u64().expect("each element strict u64"))
            .collect();
        assert_eq!(
            epochs,
            vec![1u64, 7, 42, 99, 100],
            "epochs must be ascending by numeric value"
        );
        assert_eq!(v["count"].as_u64(), Some(5), "count == array length");
        assert_eq!(
            v["latest"].as_u64(),
            Some(100),
            "latest == max(epoch), not last-written-file"
        );
    }

    #[tokio::test]
    async fn batch_yyy_compute_list_epoch_snapshots_non_matching_filenames_ignored() {
        // The directory scan filter (`parse_epoch_snapshot_filename`) must
        // silently ignore any file whose name doesn't match the canonical
        // `epoch-{N:012}.json` pattern. Pins (a) the .json suffix is
        // mandatory (no extension-less match), (b) the "epoch-" prefix is
        // mandatory (no other prefix matches), (c) the numeric body must
        // be parse-as-u64 (no `not_a_number`, no negative). A regression
        // that loosened the parser (e.g., dropping the `.json` suffix check
        // or accepting alpha-numeric IDs) would surface here as extra
        // entries in the epochs array.
        use std::fs;
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        fs::create_dir_all(&dir).expect("mkdir snapshots");
        // Non-matching: wrong prefix, wrong suffix, alpha body.
        fs::write(dir.join("snapshot.json"), b"{}").expect("write snapshot.json");
        fs::write(dir.join("epoch-not_a_number.json"), b"{}")
            .expect("write epoch-not_a_number.json");
        fs::write(dir.join("README.md"), b"hello").expect("write README.md");
        fs::write(dir.join("epoch-000000000007"), b"{}")
            .expect("write epoch-000000000007 (missing .json)");
        // The one valid match in the noise.
        fs::write(
            dir.join(crate::network::snapshot::epoch_snapshot_filename(7)),
            b"{}",
        )
        .expect("write canonical epoch file");
        let v = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute ok");
        let epochs: Vec<u64> = v["epochs"]
            .as_array()
            .expect("epochs array")
            .iter()
            .map(|e| e.as_u64().expect("each element strict u64"))
            .collect();
        assert_eq!(
            epochs,
            vec![7u64],
            "only the canonical `epoch-{{N:012}}.json` filename is picked up; the 4 non-matching files are silently ignored"
        );
        assert_eq!(v["count"].as_u64(), Some(1));
        assert_eq!(v["latest"].as_u64(), Some(7));
    }

    #[tokio::test]
    async fn batch_yyy_compute_list_epoch_snapshots_config_fields_propagate_live() {
        // `archive_snapshot_every_n_epochs` + `archive_snapshot_retention`
        // MUST be sourced from `state.config` at call time — NOT from
        // hardcoded constants in the helper. This lets operators tune the
        // archive cadence via NodeConfig and have the live value reflected
        // on every `/snapshot/epochs/list` poll. Pins (a) the every_n field
        // comes from config (strict u64 type match), (b) the retention
        // field comes from config (strict u64 type for usize-via-as-u64
        // serde), (c) determinism across two back-to-back calls (no
        // side-effect that mutates the gauge in between).
        let (state, _tmp) = test_state();
        let v1 = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute ok 1");
        let v2 = super::compute_list_epoch_snapshots(&state)
            .await
            .expect("compute ok 2");
        assert_eq!(
            v1["archive_snapshot_every_n_epochs"].as_u64(),
            Some(state.config.archive_snapshot_every_n_epochs),
            "every_n_epochs MUST mirror state.config (live read, not constant)"
        );
        assert_eq!(
            v1["archive_snapshot_retention"].as_u64(),
            Some(state.config.archive_snapshot_retention as u64),
            "retention MUST mirror state.config (usize→u64 cast preserves value at any sane retention size)"
        );
        // Determinism: byte-identical wire across consecutive calls on the
        // same state. A future side-effect (e.g., a cache-warm tick) would
        // surface here as a v1 != v2 fail.
        assert_eq!(
            serde_json::to_string(&v1).expect("serialize v1"),
            serde_json::to_string(&v2).expect("serialize v2"),
            "back-to-back compute_list_epoch_snapshots must produce byte-identical JSON"
        );
    }

    // ─── compute_get_epoch_snapshot orthogonal pins ──────
    //
    // The pure helper at routes/sync.rs:827 is the read-side of the Gap 7
    // per-epoch archive-snapshot wire surface. Caller is `serve_epoch_snapshot`
    // at routes/sync.rs:844 → /snapshot/epochs/{N} for operator dashboards +
    // bootstrap clients pulling a specific historical epoch. The
    // helper previously had ZERO direct test coverage (only 3 references: definition,
    // doc comment, handler call); earlier work pinned the LIST helper but
    // not this single-epoch GET helper. The five tests below pin the missing-
    // file error contract, the path-derivation-from-state.config.data_dir
    // contract, the epoch-routing contract (no cross-talk between distinct
    // epochs), and the corrupt-checksum fall-through contract — so a refactor
    // that silently changes any of them surfaces here.

    #[tokio::test]
    async fn batch_cccc_compute_get_epoch_snapshot_missing_dir_returns_storage_error_with_epoch_in_message() {
        // Fresh tempdir state: no `snapshots/` directory exists. The helper
        // must surface ElaraError::Storage (NOT ElaraError::NotFound, NOT a
        // panic, NOT a network error) with the requested epoch number
        // embedded literally in the message. Pins (a) the error variant
        // routing at routes/sync.rs:838 (`ElaraError::Storage(format!(...))`),
        // (b) the format string at routes/sync.rs:839 includes the literal
        // requested epoch — operator runbooks pattern-match on this message
        // to extract the epoch number for retry, and a regression that
        // dropped the `{}` interpolation (e.g., a refactor to a static
        // `&str` literal) would break those runbooks silently.
        let (state, _tmp) = test_state();
        let err = super::compute_get_epoch_snapshot(&state, 7)
            .await
            .expect_err("missing snapshot dir must produce an error, not Ok");
        match err {
            ElaraError::Storage(msg) => {
                assert!(
                    msg.contains("epoch snapshot not found for epoch 7"),
                    "Storage message must echo the requested epoch literally; got: {msg}"
                );
            }
            other => panic!(
                "expected ElaraError::Storage with epoch-7 message, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn batch_cccc_compute_get_epoch_snapshot_existing_dir_missing_file_returns_storage_error() {
        // Adversarial case: the `snapshots/` directory exists (e.g.,
        // created by a prior save_epoch_snapshot of a DIFFERENT epoch, or
        // by the auto-scale watchdog) but the file for the requested epoch
        // doesn't. The helper must return the same Storage error as the
        // missing-dir case — directory existence alone is NOT sufficient.
        // Pins (a) the file-existence gate at snapshot.rs:776 propagates
        // through load_epoch_snapshot → load_snapshot → ok_or_else, (b)
        // there's no silent fallback to a default snapshot when the file
        // is absent (a regression that returned `NodeSnapshot::default()`
        // would let bootstrap clients consume a zeroed-out ledger and
        // re-anchor to a fictional baseline).
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        std::fs::create_dir_all(&dir).expect("mkdir snapshots");
        // Also drop a snapshot at a DIFFERENT epoch (42) — its presence
        // must not satisfy the requested epoch (7).
        let other_snap = crate::network::snapshot::NodeSnapshot::new(
            crate::accounting::ledger::LedgerState::new(),
            std::collections::HashSet::new(),
            Default::default(),
        );
        crate::network::snapshot::save_epoch_snapshot(&dir, 42, &other_snap)
            .expect("seed other-epoch snapshot");

        let err = super::compute_get_epoch_snapshot(&state, 7)
            .await
            .expect_err("missing file for requested epoch must error");
        match err {
            ElaraError::Storage(msg) => {
                assert!(
                    msg.contains("epoch 7"),
                    "Storage message must echo the requested epoch (7), not the seeded epoch (42); got: {msg}"
                );
                assert!(
                    !msg.contains("epoch 42"),
                    "Storage message must NOT leak the seeded other-epoch number; got: {msg}"
                );
            }
            other => panic!(
                "expected ElaraError::Storage, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn batch_cccc_compute_get_epoch_snapshot_round_trips_saved_snapshot_path_derived_from_data_dir() {
        // Happy path: save a snapshot via the canonical save_epoch_snapshot
        // helper at `state.config.data_dir/snapshots/`, then load via the
        // route helper. The round-trip pins (a) the path the route helper
        // resolves to is exactly `state.config.data_dir.join("snapshots")`
        // at call time — NOT a hardcoded path, NOT cached from a prior
        // call, (b) the load returns Ok(NodeSnapshot) directly (NOT
        // Ok(Option<NodeSnapshot>)) — the `ok_or_else` at routes/sync.rs:838
        // unwraps the Some-branch into the Ok value, (c) all the carried
        // fields survive the JSON round-trip (using
        // total_supply=12345 as a unique tag that's vanishingly unlikely
        // to be a default).
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        std::fs::create_dir_all(&dir).expect("mkdir snapshots");

        let mut ledger = crate::accounting::ledger::LedgerState::new();
        ledger.total_supply = 12_345; // unique tag
        ledger.total_staked = 6_789;  // distinct second-axis tag
        let saved = crate::network::snapshot::NodeSnapshot::new(
            ledger,
            std::collections::HashSet::new(),
            Default::default(),
        );
        crate::network::snapshot::save_epoch_snapshot(&dir, 50, &saved)
            .expect("save epoch snapshot");

        let loaded = super::compute_get_epoch_snapshot(&state, 50)
            .await
            .expect("compute_get_epoch_snapshot must return Ok for an existing valid file");
        assert_eq!(
            loaded.ledger.total_supply, 12_345,
            "total_supply must survive JSON round-trip via state.config.data_dir/snapshots/"
        );
        assert_eq!(
            loaded.ledger.total_staked, 6_789,
            "total_staked must survive JSON round-trip — second-axis tag"
        );
        // Also pin that the protocol_version came along (NodeSnapshot::new
        // populates it from PROTOCOL_VERSION at snapshot.rs:243).
        assert!(
            loaded.protocol_version.is_some(),
            "protocol_version must be Some after NodeSnapshot::new round-trip"
        );
    }

    #[tokio::test]
    async fn batch_cccc_compute_get_epoch_snapshot_distinct_epochs_route_to_distinct_files_no_cross_talk() {
        // Anti-aliasing pin: seed two snapshots at DIFFERENT epochs with
        // DIFFERENT carried payloads. Then load each via the helper and
        // assert (a) both succeed, (b) each returns its own data — never
        // the other's. A regression that hardcoded the epoch to a constant
        // (or used `latest_epoch_snapshot` instead of the requested-epoch
        // lookup) would surface here as either both calls returning the
        // same payload (constant collapse) or the wrong payload (wrong
        // routing). This pins the epoch_num parameter at
        // routes/sync.rs:829 is the live routing key.
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        std::fs::create_dir_all(&dir).expect("mkdir snapshots");

        let mut led_a = crate::accounting::ledger::LedgerState::new();
        led_a.total_supply = 1_000_007;
        let snap_a = crate::network::snapshot::NodeSnapshot::new(
            led_a,
            std::collections::HashSet::new(),
            Default::default(),
        );
        crate::network::snapshot::save_epoch_snapshot(&dir, 7, &snap_a)
            .expect("save epoch 7");

        let mut led_b = crate::accounting::ledger::LedgerState::new();
        led_b.total_supply = 1_000_100;
        let snap_b = crate::network::snapshot::NodeSnapshot::new(
            led_b,
            std::collections::HashSet::new(),
            Default::default(),
        );
        crate::network::snapshot::save_epoch_snapshot(&dir, 100, &snap_b)
            .expect("save epoch 100");

        let got_a = super::compute_get_epoch_snapshot(&state, 7)
            .await
            .expect("load epoch 7 must succeed");
        let got_b = super::compute_get_epoch_snapshot(&state, 100)
            .await
            .expect("load epoch 100 must succeed");
        assert_eq!(
            got_a.ledger.total_supply, 1_000_007,
            "epoch 7 lookup must return epoch-7 payload, not epoch-100"
        );
        assert_eq!(
            got_b.ledger.total_supply, 1_000_100,
            "epoch 100 lookup must return epoch-100 payload, not epoch-7"
        );
        // Belt-and-braces: the two values are distinct (proves the test
        // setup isn't collapsing under an aliasing default).
        assert_ne!(
            got_a.ledger.total_supply, got_b.ledger.total_supply,
            "the two payloads must be observably distinct"
        );
    }

    #[tokio::test]
    async fn batch_cccc_compute_get_epoch_snapshot_corrupt_checksum_falls_through_to_storage_error_and_renames_file() {
        // Defense-in-depth: write a snapshot file at the canonical path
        // with a checksum field set to a value that does NOT match the
        // recomputed checksum. load_snapshot at snapshot.rs:786-802
        // detects the mismatch, RENAMES the file to `.json.corrupt` (so
        // it doesn't slow down every future restart), and returns
        // Ok(None). The route helper at routes/sync.rs:838 maps None to
        // ElaraError::Storage. This test pins (a) the public surface is
        // identical for missing-file vs corrupt-file (operators learn one
        // 404 → "snapshot missing" wire signal), (b) the rename side-effect
        // is observable in the filesystem after the failed load (so the
        // operator who pulled this can know the file was quarantined,
        // not silently ignored). A regression that surfaced a distinct
        // checksum-mismatch error variant would break the unified
        // not-found wire contract; a regression that DIDN'T rename the
        // file would leave a corrupt artifact that triggers a checksum-
        // verify cost on every future load.
        let (state, _tmp) = test_state();
        let dir = state.config.data_dir.join("snapshots");
        std::fs::create_dir_all(&dir).expect("mkdir snapshots");

        // Build a snapshot, set checksum to a deliberately-wrong hex
        // string (64 zero chars), then write it directly (bypassing
        // save_epoch_snapshot which would compute the correct checksum).
        let mut snap = crate::network::snapshot::NodeSnapshot::new(
            crate::accounting::ledger::LedgerState::new(),
            std::collections::HashSet::new(),
            Default::default(),
        );
        snap.checksum = Some("0".repeat(64)); // strictly-wrong checksum
        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let canonical_path = dir.join(
            crate::network::snapshot::epoch_snapshot_filename(13)
        );
        std::fs::write(&canonical_path, &json).expect("write corrupt snapshot");
        assert!(canonical_path.exists(), "test setup precondition: file exists pre-load");

        let err = super::compute_get_epoch_snapshot(&state, 13)
            .await
            .expect_err("corrupt-checksum snapshot must produce an error at the public surface");
        match err {
            ElaraError::Storage(msg) => {
                assert!(
                    msg.contains("epoch 13"),
                    "Storage message must echo the requested epoch; got: {msg}"
                );
            }
            other => panic!(
                "expected ElaraError::Storage (unified not-found surface), got {:?}",
                other
            ),
        }
        // Rename side-effect: original file is gone, .corrupt variant
        // exists in the dir. with_extension("json.corrupt") on
        // `epoch-000000000013.json` produces `epoch-000000000013.json.corrupt`.
        assert!(
            !canonical_path.exists(),
            "corrupt snapshot must have been renamed away from the canonical path"
        );
        let corrupt_path = canonical_path.with_extension("json.corrupt");
        assert!(
            corrupt_path.exists(),
            "corrupt snapshot must be preserved at the .json.corrupt path for operator debugging; \
             expected {} to exist",
            corrupt_path.display()
        );
    }

    // ─── receive_conflict_proof handler orthogonal pins ─
    //
    // receive_conflict_proof (sync.rs:1064) was the only `pub async
    // fn` handler in routes/sync.rs without a direct unit test, despite being
    // the gossip-side entry point for SLOT-EQUIVOCATION evidence — a load-
    // bearing forensic surface in MESH-BFT consensus (equivocation detection
    // is what lets the cluster slash a creator who double-signed two records
    // for the same (account, nonce) slot). The handler's behavior fans
    // across three load-bearing branches that any zero-coverage hides:
    //
    //   (1) slot_key() == None  → 400 Wire + rejected_total += 1
    //       (malformed input: records don't share a slot)
    //   (2) seen.contains(slot_key) → 200 "duplicate" + ZERO counter ticks
    //       (dedup short-circuit must fire BEFORE the expensive verify())
    //   (3) Valid first-time proof → 200 "accepted" + received_total += 1 +
    //       rocks.slot_mark_conflict() invoked + re-gossip spawned
    //
    // All three axes wire through the SAME SeenSet mutex + the SAME counter
    // pair on NodeState. A refactor that swapped a counter, dropped the
    // dedup branch, or moved an increment site would silently change what
    // operator dashboards see on a live equivocation incident.

    fn batch_eeeee_signed_v5(
        identity: &Identity,
        nonce: u64,
        content: &[u8],
    ) -> crate::record::ValidationRecord {
        let mut rec = crate::record::ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            Some(std::collections::BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = nonce;
        rec.zone = Some(crate::ZoneId::from_legacy(0));
        identity.sign_record_light(&mut rec).unwrap();
        rec
    }

    #[tokio::test]
    async fn batch_eeeee_receive_conflict_proof_slot_disagreement_returns_wire_error_and_increments_rejected_only() {
        // Distinct-nonce records ⇒ distinct slot_keys ⇒ ConflictProof::slot_key()
        // returns None ⇒ handler's fast-fail path. Asserts: 400 Wire with
        // "slot" in the message; rejected_total ticks to 1; received_total
        // stays at 0 (the fast-fail returns BEFORE the receive-tick); the
        // SeenSet stays empty (fast-fail never reaches dedup mutation).
        let (state, _tmp) = test_state();
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
                .expect("generate identity");
        let a = batch_eeeee_signed_v5(&identity, 1, b"content-alpha");
        let b = batch_eeeee_signed_v5(&identity, 2, b"content-beta");
        let proof =
            crate::network::conflict_proof::ConflictProof::new(a, b);
        assert!(
            proof.slot_key().is_none(),
            "precondition: distinct-nonce records must yield no shared slot_key"
        );

        let result = super::receive_conflict_proof(
            axum::extract::State(state.clone()),
            axum::Json(proof),
        )
        .await;

        match result {
            Ok(_) => panic!("must reject — slot disagreement"),
            Err(app_err) => assert!(
                matches!(app_err.0, ElaraError::Wire(ref s) if s.contains("slot")),
                "expected Wire('...slot...') error, got {:?}",
                app_err.0
            ),
        }

        assert_eq!(
            state
                .conflict_proof_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "rejected_total MUST tick once on slot-disagreement fast-fail"
        );
        assert_eq!(
            state
                .conflict_proof_received_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "received_total MUST stay at 0 — fast-fail returns BEFORE the receive tick"
        );
        let seen = state.conflict_proof_seen.lock_recover();
        assert!(
            seen.is_empty(),
            "SeenSet MUST stay empty — fast-fail never reaches dedup mutation"
        );
    }

    #[tokio::test]
    async fn batch_eeeee_receive_conflict_proof_valid_first_time_returns_accepted_envelope_and_increments_received() {
        // Same-slot, distinct-content records on a fresh state (empty
        // SeenSet) ⇒ ConflictProof::slot_key() Some + verify() Ok ⇒
        // handler returns 200 with {"status":"accepted", "slot_key": ...}.
        // Asserts: envelope key set + value pins; received_total ticks
        // to 1; rejected_total stays at 0.
        let (state, _tmp) = test_state();
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
                .expect("generate identity");
        let a = batch_eeeee_signed_v5(&identity, 100, b"alpha-content");
        let b = batch_eeeee_signed_v5(&identity, 100, b"beta-content");
        let proof =
            crate::network::conflict_proof::ConflictProof::new(a, b);
        let expected_slot = proof
            .slot_key()
            .expect("precondition: same-nonce records share a slot_key");

        let body = match super::receive_conflict_proof(
            axum::extract::State(state.clone()),
            axum::Json(proof),
        )
        .await
        {
            Ok(j) => j.0,
            Err(_) => panic!("valid first-time proof must accept"),
        };

        assert_eq!(
            body["status"].as_str(),
            Some("accepted"),
            "first-time valid proof MUST surface status=\"accepted\""
        );
        assert_eq!(
            body["slot_key"].as_str(),
            Some(expected_slot.as_str()),
            "slot_key in body MUST equal ConflictProof::slot_key()"
        );
        assert_eq!(
            state
                .conflict_proof_received_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "received_total MUST tick once on accept path"
        );
        assert_eq!(
            state
                .conflict_proof_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "rejected_total MUST stay at 0 on the accept path"
        );
    }

    #[tokio::test]
    async fn batch_eeeee_receive_conflict_proof_duplicate_slot_short_circuits_with_no_counter_double_tick() {
        // Pre-populate the SeenSet with the slot the proof carries, then
        // submit a valid byte-identical proof. The handler MUST short-
        // circuit at the dedup branch BEFORE the receive-tick or verify()
        // step. Envelope flips to {"status":"duplicate", "slot_key": ...}
        // and BOTH counters stay at 0 — defends a refactor that re-orders
        // the dedup-check below received_total.fetch_add (which would
        // double-count replay attacks on operator dashboards).
        let (state, _tmp) = test_state();
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
                .expect("generate identity");
        let a = batch_eeeee_signed_v5(&identity, 42, b"alpha-content");
        let b = batch_eeeee_signed_v5(&identity, 42, b"beta-content");
        let proof =
            crate::network::conflict_proof::ConflictProof::new(a, b);
        let slot_key = proof
            .slot_key()
            .expect("precondition: same-nonce records share a slot_key");

        {
            let mut seen = state.conflict_proof_seen.lock_recover();
            assert!(
                seen.insert(slot_key.clone()),
                "precondition: slot MUST be newly-inserted into the SeenSet"
            );
        }

        let body = match super::receive_conflict_proof(
            axum::extract::State(state.clone()),
            axum::Json(proof),
        )
        .await
        {
            Ok(j) => j.0,
            Err(_) => panic!("duplicate path must return Ok — handler short-circuits cleanly"),
        };

        assert_eq!(
            body["status"].as_str(),
            Some("duplicate"),
            "pre-seen slot MUST surface status=\"duplicate\""
        );
        assert_eq!(
            body["slot_key"].as_str(),
            Some(slot_key.as_str()),
            "slot_key in body MUST equal the pre-seeded slot"
        );
        assert_eq!(
            state
                .conflict_proof_received_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "received_total MUST stay at 0 — dedup short-circuit precedes the tick"
        );
        assert_eq!(
            state
                .conflict_proof_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "rejected_total MUST stay at 0 — dedup is NOT a rejection class"
        );
    }

    // ─── bad-sig: 4th orthogonal axis on receive_conflict_proof ─
    //
    // The 3 earlier tests cover the slot-disagree fast-fail,
    // the valid-first-time accept, and the seen-set dedup short-circuit — but
    // leave the bad-signature rejection branch (sync.rs:1094-1098) untested.
    // That branch fires when slot_key() is Some + SeenSet is fresh + verify()
    // fails (e.g. tampered Dilithium3 signature, mismatched creator_public_key,
    // identical content_hash). The handler's counter discipline on this path
    // is structurally distinct from the other three branches:
    //
    //   slot-disagree  → rejected_total += 1, received_total stays 0
    //   accept         → received_total += 1, rejected_total stays 0
    //   dedup          → both stay 0 (short-circuit before either tick)
    //   BAD-SIG        → BOTH += 1 — the unconditional received_total tick at
    //                    sync.rs:1090 fires BEFORE the verify() check at :1094,
    //                    and the rejected_total tick at :1095 fires INSIDE the
    //                    verify-failed branch
    //
    // So the bad-sig path is the ONLY branch where both counters surface +1.
    // A refactor that (a) moved the unconditional received_total tick BELOW
    // the verify() check, (b) omitted the rejected_total tick inside the
    // verify-failed branch, or (c) changed the error message format to drop
    // the "verify failed" prefix (ops grep patterns key off this string in
    // fleet incident response) would surface here as a counter-shape or
    // error-shape regression.
    #[tokio::test]
    async fn batch_eeeee_bad_sig_receive_conflict_proof_bad_signature_increments_both_counters_and_returns_verify_failed_wire() {
        // Same-slot, distinct-content records under the SAME identity. After
        // signing both via `sign_record_light`, XOR 0xFF on byte 0 of
        // record_b's signature. ConflictProof::verify() will pass steps
        // (1)-(4) (wire v5+, same slot, same creator_public_key, distinct
        // ids + content_hashes) but reject at step (5) — Dilithium3
        // signature verification. The handler reaches the rejection branch
        // at sync.rs:1094, ticking rejected_total after the unconditional
        // received_total tick at :1090.
        let (state, _tmp) = test_state();
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
                .expect("generate identity");
        let a = batch_eeeee_signed_v5(&identity, 7777, b"alpha-bad-sig");
        let mut b = batch_eeeee_signed_v5(&identity, 7777, b"beta-bad-sig");
        // Tamper record_b's Dilithium3 signature post-sign — XOR the first
        // byte. Dilithium3 sigs are ~3293 bytes; flipping one byte breaks
        // verification under the matched public key without changing wire
        // shape (still a Some(Vec<u8>) of correct length).
        let sig_b = b.signature.as_mut().expect("post-sign signature must be Some");
        assert!(
            !sig_b.is_empty(),
            "precondition: signature must be non-empty before tamper"
        );
        sig_b[0] ^= 0xFF;

        let proof =
            crate::network::conflict_proof::ConflictProof::new(a, b);
        // Precondition: slot_key still passes (tampering byte 0 of the
        // signature doesn't affect the slot tuple, which is derived from
        // creator_public_key + nonce on the record itself).
        assert!(
            proof.slot_key().is_some(),
            "precondition: same-nonce same-creator records must share a slot_key — sig tamper doesn't change slot derivation"
        );

        let result = super::receive_conflict_proof(
            axum::extract::State(state.clone()),
            axum::Json(proof),
        )
        .await;

        match result {
            Ok(_) => panic!("must reject — record_b carries a tampered signature"),
            Err(app_err) => assert!(
                matches!(app_err.0, ElaraError::Wire(ref s) if s.contains("verify failed")),
                "expected Wire('...verify failed...') error (ops grep depends on this prefix), got {:?}",
                app_err.0
            ),
        }

        assert_eq!(
            state
                .conflict_proof_received_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "received_total MUST tick once — the unconditional tick at sync.rs:1090 fires BEFORE the verify() check"
        );
        assert_eq!(
            state
                .conflict_proof_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "rejected_total MUST tick once on the bad-sig path — the verify-failed branch at sync.rs:1095"
        );
        // SeenSet is NOT mutated on the bad-sig rejection path. The handler
        // only inserts into conflict_proof_seen inside the re-gossip helper
        // `push_conflict_proof_to_peers` (which is spawned on the accept
        // branch only). A refactor that pre-inserted the slot into the
        // SeenSet BEFORE verify() would silently swallow a subsequent
        // re-submission of a CORRECTLY-signed proof for the same slot
        // (the dedup short-circuit would fire on the second submission).
        let seen = state.conflict_proof_seen.lock_recover();
        assert!(
            seen.is_empty(),
            "SeenSet MUST stay empty on the bad-sig rejection path — pre-insert would swallow a correctly-signed retry"
        );
    }

    // ─── dup-content: 5th orthogonal axis on receive_conflict_proof ─
    //
    // SEMANTICS FLIP (audit 2026-07-06): two DISTINCT signed records with
    // identical content bytes on one slot were previously rejected at
    // verify() gate (4b) as "share content_hash — duplicate, not conflict".
    // That discriminator was creator-supplied and gameable: an equivocator
    // could hand-set equal content_hashes on two genuinely different
    // transfers and make the pair unprovable. The discriminator is now
    // `record_hash()` (sha3 over signable bytes), under which a re-signed
    // same-content pair IS equivocation — two distinct signed records claim
    // one slot (a well-behaved client re-submits the SAME record, it never
    // re-signs a new one). So the handler now ACCEPTS this pair: marks the
    // slot conflicted and re-gossips. The only remaining "duplicate" reject
    // is gate (4a) record_id equality (a true relay duplicate). The old
    // ops-grep phrase "share content_hash" no longer exists; operator
    // runbooks attribute duplicates via "share record_id".
    //
    // Counter-discipline:
    //   slot-disagree     → rejected_total += 1, received_total stays 0
    //   accept            → received_total += 1, rejected_total stays 0
    //   dedup             → both stay 0 (short-circuit before either tick)
    //   bad-sig           → BOTH += 1
    //   same-content pair → received_total += 1 ONLY (accept path)
    #[tokio::test]
    async fn batch_eeeee_same_content_resigned_pair_receive_conflict_proof_accepts_as_equivocation() {
        let (state, _tmp) = test_state();
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
                .expect("generate identity");

        // Two records under the SAME (zone, creator, nonce) AND identical
        // content. uuid7() in `ValidationRecord::create` makes distinct ids
        // per call (passes gate 4a); identical content bytes give equal
        // content_hash — which no longer blocks the proof.
        let a = batch_eeeee_signed_v5(&identity, 8888, b"identical-content");
        let b = batch_eeeee_signed_v5(&identity, 8888, b"identical-content");

        assert_ne!(a.id, b.id, "precondition: uuid7() distinct ids per call");
        assert_eq!(
            a.content_hash, b.content_hash,
            "precondition: same content bytes → same content_hash — the old gate 4b target"
        );

        let proof =
            crate::network::conflict_proof::ConflictProof::new(a, b);
        let slot_key = proof
            .slot_key()
            .expect("precondition: same-(creator,nonce) records share slot_key");

        let result = super::receive_conflict_proof(
            axum::extract::State(state.clone()),
            axum::Json(proof),
        )
        .await;

        let body = match result {
            Ok(json) => json.0,
            Err(app_err) => panic!(
                "re-signed same-content pair must verify as conflict post-audit, got: {:?}",
                app_err.0
            ),
        };
        assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("accepted"));
        assert_eq!(
            body.get("slot_key").and_then(|v| v.as_str()),
            Some(slot_key.as_str())
        );

        assert_eq!(
            state
                .conflict_proof_received_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "received_total MUST tick once on the accept path"
        );
        assert_eq!(
            state
                .conflict_proof_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "rejected_total MUST stay 0 — this pair is a valid equivocation proof now"
        );
    }

    /// Above MAX_SNAPSHOT_FULL_ACCOUNTS, both /snapshot and the
    /// full-state fallback through /snapshot/state-delta must short-circuit
    /// before the 200 MB clone with a 429 RateLimited and bump the counter
    /// exactly once. Below the cap, /snapshot serves normally; above the cap,
    /// only the bounded-incremental delta path (with archive baseline) is
    /// allowed to proceed.
    mod ops128_snapshot_size_circuit_breaker {
        use super::*;
        use crate::accounting::ledger::{AccountState, LedgerState};

        async fn seed_accounts(state: &Arc<NodeState>, n: usize) {
            let mut ledger = state.ledger.write().await;
            for i in 0..n {
                let id = format!("{:064x}", i as u64);
                ledger.accounts.insert(
                    id,
                    AccountState {
                        available: i as u64,
                        ..Default::default()
                    },
                );
            }
            ledger.total_supply = n as u64;
        }

        /// Helper: persist an archive snapshot at `epoch` so
        /// `compute_state_delta(state, since_epoch=epoch)` finds a baseline
        /// and serves the bounded-incremental delta path instead of falling
        /// through to full state. Snapshot ledger contents don't have to
        /// match `state.ledger` — the diff just shows everything as
        /// "changed", and the delta still carries a small payload because
        /// the test seeds a tiny baseline on purpose.
        async fn seed_archive_snapshot(state: &Arc<NodeState>, epoch: u64) {
            let dir = state.config.data_dir.join("snapshots");
            let baseline_ledger = LedgerState::new();
            let snap = crate::network::snapshot::NodeSnapshot::new(
                baseline_ledger,
                std::collections::HashSet::new(),
                Default::default(),
            );
            crate::network::snapshot::save_epoch_snapshot(&dir, epoch, &snap)
                .expect("seed archive snapshot");
        }

        #[tokio::test]
        async fn snapshot_below_cap_serves_normally() {
            let (state, _tmp) = test_state();
            // 5 accounts is well below the 100K cap.
            seed_accounts(&state, 5).await;

            let res = super::serve_snapshot(axum::extract::State(state.clone())).await;
            assert!(res.is_ok(), "below-cap /snapshot must succeed");
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "below-cap path must NOT bump the rejection counter"
            );
        }

        #[tokio::test]
        async fn snapshot_above_cap_returns_rate_limited() {
            let (state, _tmp) = test_state();
            // Seed exactly cap+1 to exercise the > comparison without paying
            // the cost of allocating 100K AccountStates we don't need.
            seed_accounts(&state, MAX_SNAPSHOT_FULL_ACCOUNTS + 1).await;

            let err = super::serve_snapshot(axum::extract::State(state.clone()))
                .await
                .expect_err("above-cap /snapshot must reject");
            assert!(
                matches!(err.0, ElaraError::RateLimited),
                "expected RateLimited (429), got {:?}",
                err.0
            );
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "rejection counter must bump exactly once per rejected call"
            );

            // Sanity: another rejected call bumps a second time.
            let _ = super::serve_snapshot(axum::extract::State(state.clone())).await;
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                2,
                "each rejection bumps the counter independently"
            );
        }

        #[tokio::test]
        async fn state_delta_since_zero_above_cap_rejects() {
            let (state, _tmp) = test_state();
            seed_accounts(&state, MAX_SNAPSHOT_FULL_ACCOUNTS + 1).await;

            // since_epoch=0 → no baseline path → must reject above cap.
            let err = super::compute_state_delta(&state, 0)
                .await
                .expect_err("since_epoch=0 above cap must reject");
            assert!(
                matches!(err, ElaraError::RateLimited),
                "expected RateLimited, got {:?}",
                err
            );
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
        }

        #[tokio::test]
        async fn state_delta_since_nonzero_no_baseline_above_cap_rejects() {
            // Closes the baseline-miss hole: a client
            // could send since_epoch=N where the server lacked the archive
            // baseline at-or-before N, fall through to full-state, and trigger
            // a 200 MB - 2 GB clone on a 4 GB VPS. Now the
            // !baseline_available check fires the same circuit-breaker.
            let (state, _tmp) = test_state();
            seed_accounts(&state, MAX_SNAPSHOT_FULL_ACCOUNTS + 1).await;
            // No archive snapshot seeded → load_epoch_snapshot_at_or_before
            // returns None for any since_epoch.

            let err = super::compute_state_delta(&state, 42)
                .await
                .expect_err("since_epoch>0 + no baseline + above cap must reject");
            assert!(
                matches!(err, ElaraError::RateLimited),
                "expected RateLimited, got {:?}",
                err
            );
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "OPS-129 baseline-miss path must bump the same counter as OPS-128"
            );
        }

        #[tokio::test]
        async fn state_delta_since_nonzero_with_baseline_above_cap_succeeds() {
            // The baseline-miss check must NOT regress the legitimate incremental delta path:
            // when the archive baseline IS available, even a >cap accounts
            // count should serve the bounded-incremental delta. The diff is
            // bounded by the changeset, not the total accounts.
            let (state, _tmp) = test_state();
            seed_accounts(&state, MAX_SNAPSHOT_FULL_ACCOUNTS + 1).await;
            seed_archive_snapshot(&state, 42).await;

            let delta = super::compute_state_delta(&state, 42)
                .await
                .expect("since_epoch>0 + with baseline must succeed even above cap");
            assert!(
                delta.baseline_available,
                "delta must report baseline_available=true"
            );
            assert_eq!(
                state
                    .snapshot_size_rejected_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "incremental-delta path must NOT bump the rejection counter"
            );
        }

        /// `approximate_cf_size` must reflect mark_applied writes
        /// promptly enough that the snapshot circuit-breaker can rely on it.
        /// This is the storage-side invariant — without it, the gate at
        /// MAX_SNAPSHOT_APPLIED_RECORDS=1M would never trip on a real chain
        /// because the estimate would lag arbitrarily behind ingestion.
        ///
        /// Why "tolerance for monotonicity, not exact": RocksDB
        /// `estimate-num-keys` is approximate. The gate uses `>`, so as long
        /// as the estimate is non-zero after writes we know it scales with
        /// applied count and the cap fires at the right magnitude.
        #[tokio::test]
        async fn ops131_approximate_applied_count_reflects_writes() {
            let (state, _tmp) = test_state();
            let baseline = state
                .rocks
                .approximate_cf_size(crate::storage::rocks::CF_APPLIED);

            let ids: std::collections::HashSet<String> =
                (0..256).map(|i| format!("rec-{:016x}", i)).collect();
            state.rocks.bulk_mark_applied(&ids);

            let after = state
                .rocks
                .approximate_cf_size(crate::storage::rocks::CF_APPLIED);
            assert!(
                after > baseline,
                "approximate_cf_size(CF_APPLIED) must rise after bulk_mark_applied (baseline={baseline}, after={after})"
            );
        }
    }
}
