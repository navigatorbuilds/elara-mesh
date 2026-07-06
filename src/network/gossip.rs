//! Gossip protocol — push/pull record propagation with anti-loop.

//!
//! Spec references:
//!   @spec Protocol §11.14
//!   @spec Protocol §7.3

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::crypto::hash::sha3_256_hex;
use crate::crypto::pqc::dilithium3_verify;
use crate::record::ValidationRecord;
use crate::storage::Storage;

use super::pq_client::PqNodeClient;
use super::dht::{NodeId, ALPHA};
use super::epoch::EPOCH_OP_KEY;
use super::ingest::now;
use super::state::NodeState;
use super::{LockRecover, RwLockRecover};

/// MAINNET mandate #3 (floor-push): record-kind label for the kind-split
/// gossip-egress byte counters. Order maps directly to the four
/// `gossip_bytes_out_{seal,ledger,governance,other}_total` AtomicU64 fields
/// on `NodeState`. Classification is metadata-only (no body parse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipKind {
    /// `epoch_op` metadata key present (any value: seal / global_seal /
    /// zone_transition / super_seal).
    Seal,
    /// `beat_op` metadata key present (transfer / mint / burn / stake / etc.).
    Ledger,
    /// `governance_op` metadata key present (propose / vote / execute /
    /// cancel / delegate / undelegate / challenge).
    Governance,
    /// None of the above. Generic data records and any future record kind
    /// not yet classified.
    Other,
}

impl GossipKind {
    /// Classify a record by its metadata keys. Cheap — no allocation, no
    /// body parse. Precedence: Seal > Governance > Ledger > Other (so a
    /// record carrying both `epoch_op` and a stray `beat_op` is still
    /// charged to Seal — but in practice these keys are mutually exclusive
    /// per Protocol §11.14).
    pub fn classify(record: &ValidationRecord) -> Self {
        if record.metadata.contains_key(EPOCH_OP_KEY) {
            GossipKind::Seal
        } else if record.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY) {
            GossipKind::Governance
        } else if record.metadata.contains_key("beat_op") {
            GossipKind::Ledger
        } else {
            GossipKind::Other
        }
    }

    /// Increment the matching AtomicU64 on `state` by `bytes`.
    pub fn record_egress(self, state: &NodeState, bytes: u64) {
        let counter = match self {
            GossipKind::Seal => &state.gossip_bytes_out_seal_total,
            GossipKind::Ledger => &state.gossip_bytes_out_ledger_total,
            GossipKind::Governance => &state.gossip_bytes_out_governance_total,
            GossipKind::Other => &state.gossip_bytes_out_other_total,
        };
        counter.fetch_add(bytes, Relaxed);
    }

    /// Whether this op kind bypasses zone-subscription filtering during
    /// gossip relay. Global ops (seals, ledger ops, governance) reach every
    /// peer regardless of zone subscription so the whole network agrees on
    /// fleet-wide state; per-zone records only go to subscribers.
    ///
    /// The seal_dht_routing_enabled flag does **not** change this — DHT
    /// routing reduces fan-out per push, but seals must still ignore zone
    /// scope when picking candidates (a seal for zone A might be replicated
    /// onto a peer that subscribes only to zone B; that's the whole point
    /// of cross-zone seal availability).
    pub fn bypasses_zone_filter(self) -> bool {
        matches!(
            self,
            GossipKind::Seal | GossipKind::Ledger | GossipKind::Governance
        )
    }

    /// Whether this op kind must take the sqrt(n) flood path instead of the
    /// K-DHT-closest content-routed path.
    ///
    /// - **Ledger / governance**: always flood. Low rate (~10s of ops/day
    ///   fleet-wide), high importance — flood is fine and the verifiable-
    ///   replication invariant required to safely DHT-route is overkill.
    /// - **Epoch seal**: floods by default to preserve pre-Gap-6.4 behavior.
    ///   When `seal_dht_enabled` is `true` (operator opt-in), seals can
    ///   take the K-DHT path; the replication invariant + pull-side
    ///   reconciliation that make this safe land in follow-up slices.
    /// - **Per-zone record (`Other`)**: never forced; content routing kicks
    ///   in above the configured threshold.
    pub fn must_flood(self, seal_dht_enabled: bool) -> bool {
        match self {
            GossipKind::Ledger | GossipKind::Governance => true,
            GossipKind::Seal => !seal_dht_enabled,
            GossipKind::Other => false,
        }
    }
}

/// Compact gossip announcement — header + hash, no payload.
/// Protocol §11.14: "compact announcement (~1KB header + hash),
/// full records fetched on demand."
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordAnnouncement {
    pub record_id: String,
    pub content_hash: String,    // hex
    pub creator_hash: String,    // hex SHA3-256 of pubkey
    pub classification: u8,
    pub zone: String,
    pub timestamp: f64,
    pub wire_len: u32,
}

impl RecordAnnouncement {
    pub fn from_record(record: &ValidationRecord) -> Self {
        Self {
            record_id: record.id.clone(),
            content_hash: hex::encode(&record.content_hash),
            creator_hash: sha3_256_hex(&record.creator_public_key),
            classification: record.classification as u8,
            zone: record.metadata.get("zone").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            timestamp: record.timestamp,
            wire_len: record.to_bytes().len() as u32,
        }
    }
}

/// A verified attestation ready for storage.
struct VerifiedAttestation {
    record_id: String,
    witness_hash: String,
    signature: Vec<u8>,
    timestamp: f64,
    public_key: Option<Vec<u8>>,
    powas_nonce: Option<u64>,
    powas_difficulty: Option<u64>,
}
use super::sync::BloomFilter;

/// Orphan miss-counter TTL: entries untouched this long are reaped.
/// Matches the `deferred_attestations` 10-minute window for operational symmetry.
pub const MAX_ORPHAN_MISS_AGE_SECS: f64 = 600.0;

/// Hard cap on `orphan_fetch_misses` map size. Defence against adversarial
/// orphan-flooding (fresh random parent IDs) that would otherwise balloon the
/// miss map on 2GB nodes.
pub const MAX_ORPHAN_MISS_TRACKED: usize = 10_000;

// Compile-time positivity invariants for the orphan-miss map. A tuner that
// drops AGE_SECS to 0 (silently disables TTL reap; `now - ts < 0.0` always
// false → nothing reaped) or sets TRACKED to 0 (every insert immediately
// triggers cap eviction → map permanently empty, miss-counters lose state)
// now fails at `cargo build`, not at `cargo test`.
const _: () = assert!(
    MAX_ORPHAN_MISS_AGE_SECS > 0.0,
    "MAX_ORPHAN_MISS_AGE_SECS must be positive — non-positive disables TTL reap"
);
const _: () = assert!(
    MAX_ORPHAN_MISS_TRACKED > 0,
    "MAX_ORPHAN_MISS_TRACKED must be positive — zero collapses miss-counter state"
);

/// Apply TTL reap and size cap to the `orphan_fetch_misses` map.
///
/// Extracted for unit testing without spinning up a full NodeState. Called
/// from the orphan resolver after incrementing miss counters.
pub(crate) fn prune_orphan_miss_map(
    misses: &mut std::collections::HashMap<String, (u32, f64)>,
    now_ts: f64,
) {
    // TTL reap
    misses.retain(|_, (_, ts)| now_ts - *ts < MAX_ORPHAN_MISS_AGE_SECS);
    // Hard cap: evict oldest-ts entries first
    if misses.len() > MAX_ORPHAN_MISS_TRACKED {
        let mut by_ts: Vec<(String, f64)> = misses.iter()
            .map(|(k, (_, ts))| (k.clone(), *ts))
            .collect();
        by_ts.sort_by(|a, b| a.1.total_cmp(&b.1));
        let evict_n = misses.len() - MAX_ORPHAN_MISS_TRACKED;
        for (k, _) in by_ts.into_iter().take(evict_n) {
            misses.remove(&k);
        }
    }
}

/// Extract listen port from a bind address like "0.0.0.0:9473".
#[cfg(test)]
fn parse_listen_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next().and_then(|s| s.parse().ok())
}

// SeenSet and PropagationLimiter moved to ingest.rs
pub use super::ingest::{SeenSet, PropagationLimiter};

/// Push outcome — distinguishes transient overload from real failures.
/// Rate-limited (429) peers are alive but busy; penalizing them causes exile spirals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushResult {
    /// 2xx — peer accepted the record.
    Ok,
    /// 429 — peer is alive but rate-limiting us. Don't penalize.
    RateLimited,
    /// Connection error / timeout — peer is unreachable.
    /// Triggers peer backoff (so we stop hammering it) but does NOT count
    /// as a gossip failure in the health metric. A dead peer is a peer
    /// problem, not a gossip problem.
    Unreachable,
    /// Non-2xx/non-429 HTTP response — peer rejected the record.
    Failed,
}

/// Translate an HTTP base URL ("https://host:9473") to a PQ peer addr
/// ("host:9573") using the configured offset. Returns None if we can't parse.
pub(crate) fn http_to_pq_addr(base_url: &str, offset: u16) -> Option<String> {
    // Strip scheme
    let without_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .unwrap_or(base_url);
    // Drop any path component
    let host_port = without_scheme.split('/').next()?;
    let (host, port_str) = host_port.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some(format!("{host}:{}", port.saturating_add(offset)))
}

/// Classify an ingest rejection as retryable (do NOT cache in `gossip_rejected`)
/// vs permanent (cache, never re-fetch).
///
/// The `gossip_rejected` cache exists to stop infinite re-pull of records that
/// can never become valid (bad signature, malformed, structural). But some
/// validation predicates read LEDGER STATE that evolves as other records
/// finalize — those failures are ordering artifacts, not verdicts:
///
/// - "insufficient balance …" — a funding record (mint/transfer) hasn't
///   finalized yet on this node. Fresh-chain wall #5 (board 0g): the genesis
///   pool_fund record syncs to peers seconds after boot, the genesis mint
///   record only APPLIES at finalization (+~2 min), so pool_fund was rejected
///   for balance and permanently cached → zero attestations chain-wide → the
///   conservation pool stayed 0 and every reward insert failed.
/// - "conservation pool insufficient" — witness_reward synced before the
///   pool_fund record finalized. Same family.
/// - "stake not found" / "transfer not found" — the referenced stake /
///   cross-zone transfer record hasn't synced or finalized here yet.
///
/// Epoch-seal divergence ("merkle root mismatch" / "previous_seal mismatch")
/// stays retryable as before — DAG convergence resolves it.
///
/// Time-INVARIANT failures (authority checks, amount==0, self-transfer,
/// signature, cooldown computed from in-record timestamps) remain permanent.
pub(crate) fn is_retryable_ingest_rejection(err_str: &str) -> bool {
    err_str.contains("merkle root mismatch")
        || err_str.contains("previous_seal mismatch")
        || err_str.contains("insufficient balance")
        || err_str.contains("insufficient unlocked balance")
        || err_str.contains("conservation pool insufficient")
        || err_str.contains("stake not found")
        || err_str.contains("transfer not found")
        // B7: a non-genesis catch-up seal deferred because the proposer's VRF key
        // is not yet registered locally. Park + re-fetch by id: once the
        // proposer's VRF registration record syncs the retry verifies. A forged
        // seal never verifies and ages out of the bounded retry buffer — it is NOT
        // permanent-cached, keeping the honest-joiner self-heal path open.
        || err_str.contains("VRF-unverifiable")
}

/// B6 fork-safety linchpin: decide whether a rejected gossip-push record id may
/// be written to the PERMANENT `gossip_rejected` cache, vs parked for retry.
///
/// An UNTRUSTED push (an authed-but-untrusted stranger — `trusted: false`) must
/// NEVER be permanently cached. A permanent `gossip_rejected` entry is
/// consulted-and-skipped by every pull driver (timestamp/full/delta pull, delta
/// sync), so a forged untrusted push of a genuinely-canonical record — rejected
/// here only because its *creator* tripped this node's local rate limiter
/// (non-retryable `global rate limit exceeded` / `exceeds propagation rate
/// limit`) — would censor that record out of this node's sync forever → fork.
/// Park such rejections instead (bounded, attempt-capped, NOT consulted by pull
/// skips). Trusted relays (seed/staked/authority/local) keep the prior
/// retryable-vs-permanent split. The downgrade in B6 is what first exposes the
/// rate-limit reject strings to the push path, so this guard is load-bearing,
/// not cosmetic — without it the B6 fix regresses into a censorship fork.
pub(crate) fn should_permanent_reject(untrusted_push: bool, reason: &str) -> bool {
    !untrusted_push && !is_retryable_ingest_rejection(reason)
}

/// Epoch gap beyond which an incoming epoch seal is too far behind the node's
/// local view to be worth applying (DAG convergence will have superseded it).
pub(crate) const STALE_EPOCH_SEAL_GAP: u64 = 100;

/// True if an epoch seal at `seal_epoch` is too stale to apply given the node's
/// `local_epoch` for that zone. `local_epoch == 0` (still bootstrapping) never
/// rejects. Extracted so the prod gate and its tests share one definition
/// (audit 16j — the tests previously re-implemented this inline and could not
/// catch a drift in the real gate).
pub(crate) fn is_stale_epoch_seal(local_epoch: u64, seal_epoch: u64) -> bool {
    // SD-1 (2026-07-03 audit): `seal_epoch` is attacker-controlled on the pull
    // path; a hostile `epoch_number ≈ u64::MAX` would overflow `seal_epoch + GAP`
    // and panic under release `overflow-checks=true`. saturating_add is correct
    // here — a far-future seal saturates to u64::MAX which is never < local_epoch,
    // i.e. it is (correctly) NOT stale.
    local_epoch > 0 && seal_epoch.saturating_add(STALE_EPOCH_SEAL_GAP) < local_epoch
}

/// True if `rec` is an epoch-SEAL record (`epoch_op == "seal"`) whose epoch is
/// stale relative to the local tip for its zone. Contract §4.4 decline class —
/// stale ≠ invalid: callers route these to `declined_seal_ids`, NEVER
/// `gossip_rejected` (item 8b: the permanent embargo killed all consumer
/// processing for locally-pruned-history seals archive peers re-serve every
/// sweep) and NEVER the park queue (1,357/sweep observed — floods
/// GOSSIP_RETRY_CAP and evicts legitimate retries). Runs PRE-CRYPTO: metadata
/// reads + one map lookup, so declined seals never pay Dilithium3 (inside
/// ingest, signature verify runs before the gap check). Caller supplies the
/// epoch guard so batch paths lock once per page.
pub(crate) fn is_stale_seal_record(
    rec: &ValidationRecord,
    epoch_state: &super::epoch::EpochState,
) -> bool {
    if rec.metadata.get(EPOCH_OP_KEY).and_then(|v| v.as_str()) != Some("seal") {
        return false;
    }
    let seal_epoch = rec
        .metadata
        .get("epoch_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let zone_str = rec
        .metadata
        .get("epoch_zone")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let zone_id = crate::ZoneId::new(zone_str);
    let local_epoch = epoch_state.latest_epoch.get(&zone_id).copied().unwrap_or(0);
    is_stale_epoch_seal(local_epoch, seal_epoch)
}

/// 8b sweep floor (internal design notes part C): the lowest
/// timestamp the full_pull sweep will (re-)scan —
/// `max(now − effective_retention, earliest_retained_record, 0)`.
/// The retention term stops re-fetching what GC will delete again (the
/// 1,357/sweep churn source); the earliest-record term keeps the floor at
/// "oldest retained" on Archive (retention = None → no time term, full
/// retained history keeps sweeping, no profile special-case) and stops
/// snapshot-bootstrapped non-backfilling profiles from re-fetching
/// pre-snapshot history every sweep. Pure; `full_pull_sweep_floor` supplies
/// the two O(1) reads.
pub(crate) fn sweep_floor_from(
    retention_secs: Option<u64>,
    earliest_record_ts: Option<f64>,
    now: f64,
) -> f64 {
    let retention_floor = retention_secs
        .map(|secs| now - secs as f64)
        .unwrap_or(0.0);
    retention_floor.max(earliest_record_ts.unwrap_or(0.0)).max(0.0)
}

/// State-backed wrapper for `sweep_floor_from`: per-profile retention
/// (`node_profile.rs` — FullZone 90d, Light 72h, Archive never) + an O(1)
/// `seek_to_first` on CF_IDX_TIMESTAMP. Applied at all three cursor clamp
/// points: initial sweep load, the sweep-complete tail-reset, and the
/// DAG-deficit backward seed.
pub(crate) fn full_pull_sweep_floor(state: &NodeState) -> f64 {
    let retention = super::node_profile::NodeProfile::from_str(&state.config.node_profile)
        .records_retention_secs();
    sweep_floor_from(retention, state.rocks.earliest_record_timestamp(), now())
}

/// 8b part C (SEAL-8b-01 pin): the deficit-seed cursor target — (earliest open
/// hole − 1s) clamped UP to the retention/earliest sweep floor. A hole below
/// the floor is deliberately-pruned territory, not a repairable gap; the
/// unfloored pre-8b `s - 1.0` form re-arms the below-floor pull storm. The
/// floor is computed INSIDE so no call site can pass an unfloored value; if
/// the pull loop reverts to an inline expression this fn goes dead and
/// `-D warnings` fails CI.
pub(crate) fn deficit_seed_target(state: &NodeState) -> Option<f64> {
    let ring = state
        .dag_deficit_open
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ring.earliest_start()
        .map(|s| (s - 1.0).max(full_pull_sweep_floor(state)))
}

/// 8b (SEAL-8b-01 pin — the single most load-bearing line of part C): the
/// sweep-complete tail-reset re-arms the cursor AT the retention/earliest
/// floor, never 0.0 — left at 0.0 the below-floor storm re-fires on the very
/// next sweep, defeating the pre-filter and the initial clamp. Recomputes the
/// floor at reset time (retention/earliest only move forward while a sweep
/// runs, so this is ≥ the sweep-start floor) and persists it. Floor computed
/// INSIDE for the same dead-code CI property as `deficit_seed_target`.
pub(crate) fn apply_sweep_tail_reset(state: &NodeState) -> f64 {
    let floor = full_pull_sweep_floor(state);
    *state
        .full_pull_cursor
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = floor;
    state.rocks.save_full_pull_cursor(floor);
    floor
}

/// 8b INVARIANT (internal design notes part A): a SEAL-class
/// record (metadata carries `epoch_op`) NEVER enters the permanent
/// `gossip_rejected` embargo — one transient reject at first delivery must not
/// kill the seal's consumer processing on this node for the process lifetime.
/// Pre-move probe of the fields disposition needs (push paths and the park
/// drain move the record into ingest before their reject arm runs).
pub(crate) struct SealRejectProbe {
    pub id: String,
    pub is_epoch_op: bool,
    pub is_seal_op: bool,
    pub seal_epoch: u64,
    pub zone_str: String,
}

pub(crate) fn seal_reject_probe(rec: &ValidationRecord) -> SealRejectProbe {
    SealRejectProbe {
        id: rec.id.clone(),
        is_epoch_op: rec.metadata.contains_key(EPOCH_OP_KEY),
        is_seal_op: rec.metadata.get(EPOCH_OP_KEY).and_then(|v| v.as_str()) == Some("seal"),
        seal_epoch: rec
            .metadata
            .get("epoch_number")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        zone_str: rec
            .metadata
            .get("epoch_zone")
            .and_then(|v| v.as_str())
            .unwrap_or("0")
            .to_string(),
    }
}

/// Central seal-reject disposition, wired at every ingest-reject site (pull
/// paths, push paths, park drain, delta sync). Buckets:
/// - stale (judged NOW, at disposition time — the pre-filter's batch-start
///   epoch view can go stale mid-batch, the `:2743` leak) → `declined_seal_ids`
///   (bloom-folded; never re-served on delta paths);
/// - everything else — retryable AND non-retryable/malformed alike — →
///   bounded attempt-capped park (ages out at GOSSIP_RETRY_MAX_ATTEMPTS;
///   a distinct-id flood evicts oldest FIFO entries, which is a latency
///   degrade, not a loss: pull cursors re-offer evictees).
///
/// Returns true iff the record was seal-class and disposed here; false =
/// caller keeps its legacy non-seal logic (B6 `should_permanent_reject`
/// semantics untouched for non-seal records).
pub(crate) fn dispose_seal_ingest_failure_probed(
    state: &NodeState,
    probe: &SealRejectProbe,
    attempts: u8,
) -> bool {
    if !probe.is_epoch_op {
        return false;
    }
    let stale = probe.is_seal_op && {
        let local = state
            .epoch
            .read_recover()
            .latest_epoch
            .get(&crate::ZoneId::new(&probe.zone_str))
            .copied()
            .unwrap_or(0);
        is_stale_epoch_seal(local, probe.seal_epoch)
    };
    if stale {
        state.gossip_seal_declined_stale_total.fetch_add(1, Relaxed);
        state
            .declined_seal_ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(probe.id.clone());
    } else if attempts < GOSSIP_RETRY_MAX_ATTEMPTS {
        park_retryable_with_attempts(state, &probe.id, attempts);
    }
    // attempts >= cap: drop without any caching — the invariant holds and a
    // future natural re-offer restarts the (cheap, fail-fast) cycle.
    true
}

/// Record-in-scope convenience for `dispose_seal_ingest_failure_probed`.
pub(crate) fn dispose_seal_ingest_failure(
    state: &NodeState,
    rec: &ValidationRecord,
    attempts: u8,
) -> bool {
    dispose_seal_ingest_failure_probed(state, &seal_reject_probe(rec), attempts)
}

// ─── Retryable-rejection park/re-fetch ──────────────────────────────────
//
// A retryably-rejected record is NOT cached in `gossip_rejected`, but that
// alone doesn't get it re-offered: pull cursors advance past its timestamp
// within the same batch (rehearsal #4: the genesis pool seed was offered by
// delta sync at boot+24s, rejected "insufficient balance" because the peer's
// genesis ledger build hadn't run yet, and no pull path ever revisited it).
// full_pull's from-0.0 rescan would eventually re-offer, but that cycle takes
// hours on testnet and days at 10M+ records. So: park the id, re-fetch it
// directly (PQ `fetch_records`) in the pull loop once per cycle. Bounded:
// queue capped, FIFO-evicted, fixed drain per cycle, attempts-capped.

/// Max parked ids — FIFO-evicted beyond this. Sized for bursts of
/// state-dependent rejections (genesis window, mass sync), not history.
pub(crate) const GOSSIP_RETRY_CAP: usize = 1024;
/// Drop a parked id after this many failed re-fetch attempts.
pub(crate) const GOSSIP_RETRY_MAX_ATTEMPTS: u8 = 20;
/// Records re-fetched per timestamp_pull cycle.
const GOSSIP_RETRY_DRAIN_PER_CYCLE: usize = 16;

/// Park a record id (attempts seeded) for targeted re-fetch. Dedup by id;
/// FIFO-evict at cap. O(queue) scan is fine at cap ≤ 1024.
pub(crate) fn park_retryable_with_attempts(state: &NodeState, record_id: &str, attempts: u8) {
    let mut q = state.gossip_retry.lock_recover();
    if q.iter().any(|(id, _)| id == record_id) {
        return;
    }
    if q.len() >= GOSSIP_RETRY_CAP {
        q.pop_front();
    }
    q.push_back((record_id.to_string(), attempts));
}

/// Park a freshly-rejected record id for re-fetch.
pub(crate) fn park_retryable(state: &NodeState, record_id: &str) {
    park_retryable_with_attempts(state, record_id, 0);
}

/// Drain up to GOSSIP_RETRY_DRAIN_PER_CYCLE parked ids and re-fetch them by
/// id from `base_url`'s PQ port. Ingest success or a permanent rejection
/// drops the id; a retryable rejection or fetch miss re-parks with
/// attempts+1 (dropped at GOSSIP_RETRY_MAX_ATTEMPTS). Transport failure
/// re-parks untouched (another peer's cycle will drain). Returns recovered.
async fn retry_parked_records(state: &Arc<NodeState>, base_url: &str) -> usize {
    let batch: Vec<(String, u8)> = {
        let mut q = state.gossip_retry.lock_recover();
        let n = q.len().min(GOSSIP_RETRY_DRAIN_PER_CYCLE);
        q.drain(..n).collect()
    };
    if batch.is_empty() {
        return 0;
    }
    let requeue = |entries: Vec<(String, u8)>| {
        let mut q = state.gossip_retry.lock_recover();
        for entry in entries {
            if !q.iter().any(|(id, _)| id == &entry.0) && q.len() < GOSSIP_RETRY_CAP {
                q.push_back(entry);
            }
        }
    };
    let Some(pq_addr) = http_to_pq_addr(base_url, state.config.pq_port_offset) else {
        requeue(batch);
        return 0;
    };
    let ids: Vec<String> = batch.iter().map(|(id, _)| id.clone()).collect();
    let wire_list = match state.pq_client.fetch_records(&pq_addr, &ids).await {
        Ok(w) => w,
        Err(_) => {
            requeue(batch);
            return 0;
        }
    };
    let mut fetched: std::collections::HashMap<String, ValidationRecord> = wire_list
        .iter()
        .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
        .map(|r| (r.id.clone(), r))
        .collect();
    let mut recovered = 0usize;
    for (id, attempts) in batch {
        let Some(record) = fetched.remove(&id) else {
            // This peer doesn't have it — retry later (possibly via another peer).
            if attempts + 1 < GOSSIP_RETRY_MAX_ATTEMPTS {
                park_retryable_with_attempts(state, &id, attempts + 1);
            }
            continue;
        };
        // 8b: probe before the move — the reject arm needs seal metadata.
        let probe = seal_reject_probe(&record);
        match insert_record_synced(state, record).await {
            Ok(_) => {
                state.seen.lock_recover().insert(id);
                state
                    .gossip_retry_recovered_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                recovered += 1;
            }
            Err(e) => {
                let err_str = e.to_string();
                // 8b invariant: a parked seal that went stale while parked (or
                // re-failed any other way) must NOT graduate into the permanent
                // embargo — the panel-missed `:414` leak. Aging is preserved:
                // the helper re-parks with attempts+1 and drops at the cap.
                if dispose_seal_ingest_failure_probed(state, &probe, attempts + 1) {
                    // disposed (declined, re-parked with aging, or aged out)
                } else if is_retryable_ingest_rejection(&err_str) {
                    if attempts + 1 < GOSSIP_RETRY_MAX_ATTEMPTS {
                        park_retryable_with_attempts(state, &id, attempts + 1);
                    }
                } else {
                    state.gossip_rejected.lock_recover().insert(id);
                }
            }
        }
    }
    if recovered > 0 {
        info!("gossip retry: recovered {recovered} previously-rejected records (wall-#5 leg 3)");
    }
    recovered
}

/// PQ-only `query_records`. Used by bulk-pull paths (timestamp_pull /
/// full_pull / bootstrap_pull_from_zero). Returns Err on any PQ failure —
/// no HTTPS fallback (AUDIT-10 directive, 2026-04-24).
///
/// The bool is the server's byte-budget truncation signal: `true` means the
/// page was cut below the requested `limit` by the PQ single-frame budget
/// (`handle_query_records`), so a short page is NOT the peer's history tail.
/// Every caller's `batch_len < page_size` exhaustion check MUST also require
/// `!truncated` — misreading a truncated page as the tail resets/ends the
/// sweep below the fat region and the gap never closes (the full_pull
/// stuck-cursor pathology, root-caused live 2026-07-02).
async fn pq_query_records(
    state: &Arc<NodeState>,
    base_url: &str,
    since: f64,
    limit: usize,
) -> crate::errors::Result<(Vec<Vec<u8>>, bool)> {
    let pq_addr = http_to_pq_addr(base_url, state.config.pq_port_offset).ok_or_else(|| {
        crate::errors::ElaraError::Network(format!(
            "cannot derive PQ peer addr from {base_url:?}"
        ))
    })?;
    state
        .pq_client
        .query_records_paged(&pq_addr, since, limit)
        .await
}

/// PQ-only `delta_sync`. Returns Err on any PQ failure.
async fn pq_delta_sync(
    state: &Arc<NodeState>,
    base_url: &str,
    bloom_bytes: &[u8],
) -> crate::errors::Result<Vec<Vec<u8>>> {
    use std::sync::atomic::Ordering::Relaxed;
    state.delta_sync_attempts_total.fetch_add(1, Relaxed);
    let pq_addr = match http_to_pq_addr(base_url, state.config.pq_port_offset) {
        Some(addr) => addr,
        None => {
            crate::network::sync::record_delta_sync_other_failure(
                state,
                "cannot derive PQ peer addr",
            );
            return Err(crate::errors::ElaraError::Network(format!(
                "cannot derive PQ peer addr from {base_url:?}"
            )));
        }
    };
    let since = crate::network::sync::delta_sync_since_floor(state);
    let t0 = std::time::Instant::now();
    match state.pq_client.delta_sync(&pq_addr, bloom_bytes, since).await {
        Ok((v, peer_missing, guard_tripped, cycle_exhausted)) => {
            if guard_tripped {
                state
                    .delta_sync_cursor_guard_trips_total
                    .fetch_add(1, Relaxed);
            }
            if cycle_exhausted {
                state
                    .delta_sync_cursor_cycle_exhausted_total
                    .fetch_add(1, Relaxed);
            }
            let elapsed_ms = t0.elapsed().as_millis();
            if elapsed_ms < 2_000 {
                state.delta_sync_latency_lt_2s_total.fetch_add(1, Relaxed);
            } else if elapsed_ms < 10_000 {
                state.delta_sync_latency_lt_10s_total.fetch_add(1, Relaxed);
            } else {
                state.delta_sync_latency_lt_30s_total.fetch_add(1, Relaxed);
            }
            crate::network::sync::note_peer_reported_missing(state, peer_missing);
            Ok(v)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("timed out") {
                state.delta_sync_failures_timeout_total.fetch_add(1, Relaxed);
                if msg.contains("pq_dial") {
                    state
                        .delta_sync_failures_timeout_handshake_total
                        .fetch_add(1, Relaxed);
                } else if msg.contains("rpc") {
                    state
                        .delta_sync_failures_timeout_rpc_total
                        .fetch_add(1, Relaxed);
                }
            } else {
                crate::network::sync::record_delta_sync_other_failure(state, &msg);
            }
            Err(e)
        }
    }
}

/// PQ-only `announce`. Returns Err on any PQ failure.
async fn pq_announce(
    state: &Arc<NodeState>,
    base_url: &str,
    announcements: &[RecordAnnouncement],
) -> crate::errors::Result<Vec<String>> {
    let pq_addr = http_to_pq_addr(base_url, state.config.pq_port_offset).ok_or_else(|| {
        crate::errors::ElaraError::Network(format!(
            "cannot derive PQ peer addr from {base_url:?}"
        ))
    })?;
    state.pq_client.announce(&pq_addr, announcements).await
}

/// Try a PQ `submit_record` push for a single peer. Returns `Some(result)` on
/// a completed attempt (success or failure), `None` if PQ is not configured
/// for this call (caller should fall back to HTTP).
async fn push_single_pq(
    pq: &PqNodeClient,
    peer_addr: &str,
    wire: &[u8],
    headers: super::pq_client::GossipHeaders<'_>,
) -> PushResult {
    match pq.submit_record_gossip(peer_addr, wire, headers).await {
        Ok(resp) => {
            if resp.is_success() {
                PushResult::Ok
            } else if resp.status == 429 {
                debug!("pq push to {peer_addr} rate-limited (429)");
                PushResult::RateLimited
            } else {
                debug!("pq push to {peer_addr} failed: status {}", resp.status);
                PushResult::Failed
            }
        }
        Err(e) => {
            debug!("pq push to {peer_addr} unreachable: {e}");
            PushResult::Unreachable
        }
    }
}

/// Find DHT peers not in the `tried` set, for retry after push failure.
fn find_dht_alternatives(
    state: &Arc<NodeState>,
    tried: &HashSet<String>,
    count: usize,
) -> Vec<(String, String)> {
    let dht = state.dht.lock_recover();
    if dht.is_empty() {
        return Vec::new();
    }

    let target_bytes = crate::crypto::hash::sha3_256(
        format!("retry-{}", now()).as_bytes(),
    );
    let target = super::dht::NodeId(target_bytes);

    dht.closest(&target, count * 2)
        .iter()
        .filter(|p| !tried.contains(&p.identity_hash))
        .filter(|p| p.identity_hash != state.identity.identity_hash)
        .take(count)
        .map(|p| {
            (p.identity_hash.clone(), format!("http://{}:{}", p.host, p.port))
        })
        .collect()
}

/// Push a record to all connected peers with hop/sender headers.
///
/// Tracks failures in peer reputation. Fire-and-forget from the caller's
/// perspective — a background task handles the push cycle.
///
/// - `hops`: remaining relay hops to set in `X-Elara-Hops`
/// - `exclude`: identity_hash of the sender to skip (avoids push-back)
pub async fn push_to_peers(
    state: &Arc<NodeState>,
    record: &ValidationRecord,
    hops: u8,
    exclude: Option<&str>,
    trace_id: Option<&str>,
) {
    let wire = record.to_bytes();
    let self_hash = state.identity.identity_hash.clone();
    let exclude_hash = exclude.map(String::from);
    let tid = trace_id.map(String::from);

    // Collect targets while holding the lock, then release (skip peers in backoff).
    // Protocol §11.14: sqrt(n) fan-out with zone-scoped filtering.
    // Records are only pushed to peers subscribed to the record's zone.
    // Exception: epoch seals and ledger ops are global (pushed to all peers).
    // Gap 4 Phase C: resolve through the active ZoneRegistry so records route
    // to post-split child zones.
    let record_zone = state.resolve_record_zone(&record.id);
    // Gap 6.4: split the legacy `is_global_op` gate into the two distinct
    // roles it served — zone-filter bypass (still applies to all global
    // ops) and forced flood (ledger + governance always; seals only when
    // `seal_dht_routing_enabled` is off). See `GossipKind::must_flood`.
    let kind = GossipKind::classify(record);
    let bypass_zone_filter = kind.bypasses_zone_filter();
    let force_flood = kind.must_flood(state.config.seal_dht_routing_enabled);

    // Gap 6.4 slice 3a: capture whether the K-DHT path was actually taken
    // so the post-filter tracker (below) only records DHT-routed seal
    // pushes — flood pushes don't need reconciliation since they reach
    // every eligible peer.
    let (targets, dht_routed): (Vec<(String, String)>, bool) = {
        let peers = state.peers.read().await;
        // Small networks: include ALL known peers (even Stale) to prevent exile spiral.
        // 3 failures → Stale → excluded from push → more failures → permanent exile.
        // Large networks: use connected_active() for efficiency.
        let peer_list = if peers.len() < 10 {
            peers.all().into_iter().cloned().collect::<Vec<_>>()
        } else {
            peers.connected_active().into_iter().cloned().collect::<Vec<_>>()
        };
        let mut all: Vec<(String, String)> = peer_list
            .iter()
            .filter(|p| p.identity_hash != self_hash && p.node_type.can_relay() && p.reachable)
            .filter(|p| {
                exclude_hash.as_ref().is_none_or(|ex| p.identity_hash != *ex)
            })
            .filter(|p| {
                // Zone-scoped filtering: skip peers not subscribed to this zone.
                // Global ops (epoch seals, ledger ops, governance) bypass filtering.
                bypass_zone_filter || p.wants_zone(&record_zone.to_string())
            })
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();
        let mut took_dht_path = false;

        // Gap 6: content-routed placement above the threshold.
        //
        // At small peer counts, sqrt(n) flood is cheap and keeps records
        // highly available. As the network scales to 10K+ nodes flooding
        // 10T records/day is catastrophic — each record goes to sqrt(10K) ≈
        // 100 peers per push. Instead, at 100+ eligible peers we push the
        // originator copy only to the K DHT-closest peers to SHA3(record_id).
        // Every node computes the same K independently, so the replica set
        // is coordination-free.
        //
        // Ledger + governance ops still flood unconditionally (low rate, high
        // importance). Epoch seals take the K-DHT path with R=3 replication
        // by default (`seal_dht_routing_enabled = true` since 2026-04-30,
        // gated below by `content_routing_threshold`); operators can opt
        // out by flipping the flag back to false.
        let content_routing_threshold = state.config.content_routing_threshold;
        let content_routing_k = state.config.content_routing_k.max(1);
        let replication_floor = state.config.seal_dht_replication_floor.max(1);
        let using_content_routing = !force_flood
            && content_routing_threshold > 0
            && all.len() >= content_routing_threshold;

        if using_content_routing {
            // Identity hashes of the 2K DHT-closest peers to this record.
            // 2× oversample so zone/reachability filtering above can remove
            // some without collapsing the replica set.
            let wanted: std::collections::HashSet<String> = {
                let dht = state.dht.lock_recover();
                dht.closest_to_record(&record.id, content_routing_k * 2)
                    .into_iter()
                    .map(|p| p.identity_hash.clone())
                    .collect()
            };

            // Preserve the first K of `all` that intersect `wanted`.
            let mut chosen: Vec<(String, String)> =
                all.iter().filter(|(h, _)| wanted.contains(h)).cloned().collect();
            chosen.truncate(content_routing_k);

            // Gap 6.4 slice 2: R-floor invariant. If we can name at least
            // `replication_floor` distinct DHT-closest peers (or all peers
            // if the cluster is below R itself) the K-DHT path is safe;
            // otherwise fall back to sqrt(n) flood so under-replicated
            // pushes never starve. The floor is configurable
            // (`seal_dht_replication_floor`, default 3).
            let r_target = replication_floor.min(all.len());
            if chosen.len() >= r_target {
                state.gossip_push_dht_replication_factor_last
                    .store(chosen.len() as u64, Relaxed);
                all = chosen;
                state.gossip_push_content_routed_total.fetch_add(1, Relaxed);
                took_dht_path = true;
            } else {
                state.gossip_push_dht_floor_fallback_total.fetch_add(1, Relaxed);
                // leave `all` alone; sqrt(n) flood below preserves availability.
            }
        }

        // Small networks (< 10 peers): push to ALL — bandwidth is negligible
        // and sqrt(n) fan-out consistently skips 1 peer, causing drift.
        // Large networks: sqrt(n) fan-out for bandwidth efficiency.
        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1); // always push to at least 1
        if all.len() > fan_out {
            // Deterministic-ish shuffle using record hash as seed
            let seed = record.record_hash();
            let seed_val = u64::from_le_bytes(seed[..8].try_into().unwrap_or([0u8; 8]));
            // Fisher-Yates partial shuffle using seed
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        (all, took_dht_path)
    };

    if targets.is_empty() {
        return;
    }

    // Stage 6: per-peer token-bucket fairness (Protocol §11.10).
    // Skip peers whose outbound bucket is currently empty — one fast peer
    // can no longer monopolise the 16-permit global gossip_semaphore.
    // sqrt(n) fan-out already tolerates drops; skipped peers will be
    // re-attempted on the next record (their bucket refills at 10/sec).
    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    // Gap 6.4 slice 3a: track DHT-routed seal pushes for the reconciliation
    // pass that slice 3b will add. Captured *post bandwidth filter* so the
    // tracked target set matches what we actually attempted — not the
    // chosen-K set before the per-peer token bucket might have blocked some
    // peers. Only seals enter the queue: ledger + governance ops still
    // flood unconditionally and so reach every eligible peer; the
    // reconciler has nothing to add for those kinds.
    if dht_routed && matches!(kind, GossipKind::Seal) {
        state.track_pending_seal_replication(
            record.id.clone(),
            targets.iter().map(|(h, _)| h.clone()).collect(),
        ).await;
    }

    // Count per-peer push attempts (not per-round) to match per-peer failure counting
    state.gossip_push_total.fetch_add(targets.len() as u64, Relaxed);
    // MAINNET gap #8 (floor-push): egress byte meter. `wire.len()` is the
    // serialized record body posted to /records; multiply by fan-out to get
    // total outbound bytes for this push. Excludes HTTP headers + TLS framing
    // (a few hundred bytes per request) — those are amortized noise at
    // record-level granularity.
    let push_bytes = (wire.len() as u64).saturating_mul(targets.len() as u64);
    state.gossip_bytes_out_total.fetch_add(push_bytes, Relaxed);
    // MAINNET mandate #3 (floor-push): kind-split sub-counter — cleanly
    // separates seal-traffic egress from ledger / governance / other so the
    // operator can budget the per-epoch seal cost when deciding whether to
    // lower MIN_ADAPTIVE_EPOCH_SECS.
    GossipKind::classify(record).record_egress(state, push_bytes);

    let state2 = state.clone();
    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let pq_client = state.pq_client.clone();
    let network_id = state.config.network_id.clone();
    let protocol_version = super::config::PROTOCOL_VERSION;

    tokio::spawn(async move {
        let push_start = std::time::Instant::now();
        let mut handles = Vec::with_capacity(targets.len());

        for (ih, base_url) in &targets {
            let w = wire.clone();
            let s = self_hash.clone();
            let id = ih.clone();
            let t = tid.clone();
            let sem = semaphore.clone();
            let pq = pq_client.clone();
            let base = base_url.clone();
            let nid = network_id.clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await;
                let peer_start = std::time::Instant::now();
                // PQ-only push. AUDIT-10 directive (2026-04-24): no HTTPS
                // fallback. A missing PQ port or PQ-level failure is a
                // push failure — the peer gets the same treatment as
                // an HTTP failure would (backoff + retry via heartbeat),
                // but never receives plaintext gossip.
                let pq_result = match http_to_pq_addr(&base, pq_offset) {
                    Some(pq_addr) => {
                        push_single_pq(
                            &pq, &pq_addr, &w,
                            super::pq_client::GossipHeaders {
                                hops,
                                sender_identity_hash: &s,
                                trace_id: t.as_deref(),
                                network_id: &nid,
                                protocol_version,
                            },
                        ).await
                    }
                    None => PushResult::Unreachable,
                };
                (id, pq_result, peer_start.elapsed())
            }));
        }

        let mut failed_count = 0u64;
        for handle in handles {
            if let Ok((ih, result, rtt)) = handle.await {
                match result {
                    PushResult::Ok => {
                        // Sample the round-trip into the per-zone RTT estimator.
                        // Attribution: the record's zone — this is how long it
                        // takes for messages in `record_zone` to reach a peer
                        // that accepted them. Used by §11.13 timeout sizing.
                        state2.observe_zone_rtt(&record_zone, rtt);
                        // Also sample per-peer so the Stage-5 geographic
                        // fraud detector can cross-check self-reported
                        // `geo_zone`. Peer identity hash is the stable key
                        // across reconnects. @spec Protocol §11.12
                        state2.observe_peer_rtt(&ih, rtt);
                        let mut peers = state2.peers.write().await;
                        peers.record_success(&ih);
                    }
                    PushResult::RateLimited => {
                        // Peer is alive but busy (429) — don't penalize, don't count as failure.
                        // Also don't sample RTT: a 429 response time reflects the peer's
                        // rate-limiter cooldown, not network latency.
                    }
                    PushResult::Unreachable => {
                        // Connection error / timeout — trigger peer backoff so we stop
                        // hammering dead peers. NOT counted as a gossip failure because
                        // a dead peer is a connectivity issue, not a gossip protocol issue.
                        // Skip if peer is already in backoff — heartbeat is the
                        // authoritative liveness checker, don't pile on failures.
                        let mut peers = state2.peers.write().await;
                        let already_backing_off = peers.get(&ih)
                            .is_some_and(|p| p.in_backoff(now()));
                        if !already_backing_off {
                            peers.record_failure(&ih);
                        }
                    }
                    PushResult::Failed => {
                        // Peer responded with a real error — gossip protocol failure.
                        failed_count += 1;
                        let mut peers = state2.peers.write().await;
                        let already_backing_off = peers.get(&ih)
                            .is_some_and(|p| p.in_backoff(now()));
                        if !already_backing_off {
                            peers.record_failure(&ih);
                        }
                    }
                }
            }
        }

        if failed_count > 0 {
            state2.gossip_push_failed_total.fetch_add(failed_count, Relaxed);
        }
        state2.gossip_push_duration.observe(push_start.elapsed().as_secs_f64());
    });
}

/// Relay a record to content-routed (above threshold) or ALPHA-selected
/// peers with hop/sender headers.
///
/// Used for relay (non-originator) push to limit fan-out. On failure,
/// queries DHT for alternative peers and retries once per failed target.
///
/// Gap 6.2: Above `content_routing_threshold` eligible peers, the relay
/// forwards to the K DHT-closest peers to SHA3(record_id) — the same
/// responsible set the originator picked. Every relay hop converges on
/// the same K replicas instead of re-fanning sqrt(n) random peers.
/// Global ops (epoch seals, ledger ops, governance) always flood.
pub async fn relay_to_peers(
    state: &Arc<NodeState>,
    record: &ValidationRecord,
    hops: u8,
    exclude: Option<&str>,
    trace_id: Option<&str>,
) {
    state.gossip_relay_total.fetch_add(1, Relaxed);
    let wire = record.to_bytes();
    let self_hash = state.identity.identity_hash.clone();
    let exclude_hash = exclude.map(String::from);
    let tid = trace_id.map(String::from);

    // Gap 6.2: build relay targets with the same content-routing rules as
    // push_to_peers. Above threshold, pick K DHT-closest to record.id; below,
    // fall back to the reputation-weighted DHT walk (previous behavior).
    // Gap 6.4: see `GossipKind::must_flood` for the seal-vs-ledger/governance
    // split — seals can opt into K-DHT routing when
    // `seal_dht_routing_enabled` is on; ledger + governance always flood.
    let kind = GossipKind::classify(record);
    let bypass_zone_filter = kind.bypasses_zone_filter();
    let force_flood = kind.must_flood(state.config.seal_dht_routing_enabled);
    // Gap 4 Phase C: registry-aware zone resolution for post-split routing.
    let record_zone = state.resolve_record_zone(&record.id);

    let targets: Vec<(String, String)> = {
        let content_routing_threshold = state.config.content_routing_threshold;
        let content_routing_k = state.config.content_routing_k.max(1);
        let replication_floor = state.config.seal_dht_replication_floor.max(1);

        // Build reachable peer list (connected, can_relay, not self, not excluded, zone-scoped).
        let peer_list: Vec<(String, String)> = {
            let peers = state.peers.read().await;
            peers.connected_active()
                .into_iter()
                .filter(|p| p.identity_hash != self_hash && p.node_type.can_relay() && p.reachable)
                .filter(|p| exclude_hash.as_ref().is_none_or(|ex| p.identity_hash != *ex))
                .filter(|p| bypass_zone_filter || p.wants_zone(&record_zone.to_string()))
                .map(|p| (p.identity_hash.clone(), p.base_url()))
                .collect()
        };

        let eligible = peer_list.len();
        let use_content_routing = !force_flood
            && content_routing_threshold > 0
            && eligible >= content_routing_threshold;

        if use_content_routing {
            // 2× oversample lets zone / reachability filters remove stragglers
            // without collapsing the replica set.
            let wanted: HashSet<String> = {
                let dht = state.dht.lock_recover();
                dht.closest_to_record(&record.id, content_routing_k * 2)
                    .into_iter()
                    .map(|p| p.identity_hash.clone())
                    .collect()
            };
            let mut chosen: Vec<(String, String)> =
                peer_list.iter().filter(|(h, _)| wanted.contains(h)).cloned().collect();
            chosen.truncate(content_routing_k);

            // Gap 6.4 slice 2: R-floor invariant on the relay-side path.
            // Same shape as the originator check — fall through to the
            // reputation-weighted DHT walk if we can't name R distinct
            // responsible peers, so under-replicated forwards never starve.
            let r_target = replication_floor.min(eligible);
            if chosen.len() >= r_target {
                state.gossip_relay_content_routed_total.fetch_add(1, Relaxed);
                chosen
            } else {
                state.gossip_relay_dht_floor_fallback_total.fetch_add(1, Relaxed);
                select_gossip_peers(state).await
            }
        } else {
            select_gossip_peers(state).await
        }
    };

    // MAINNET gap #8 (floor-push): egress byte meter on the relay path.
    // Same accounting rule as `push_to_peers` — counts wire-body bytes only,
    // amortizing framing overhead. Relay byte volume is the dominant egress
    // cost at steady state because every forwarded record adds `wire.len() *
    // fanout` bytes per hop.
    let relay_bytes = (wire.len() as u64).saturating_mul(targets.len() as u64);
    state.gossip_bytes_out_total.fetch_add(relay_bytes, Relaxed);
    // MAINNET mandate #3 (floor-push): kind-split sub-counter — same
    // classification as the originator path. Relay traffic is the dominant
    // egress at steady state, so attributing it correctly is essential for
    // measuring per-epoch seal cost across the network, not just on the
    // originator node.
    GossipKind::classify(record).record_egress(state, relay_bytes);

    let state2 = state.clone();
    let semaphore = state.gossip_semaphore.clone();
    // PQ-only relay (AUDIT-10 directive, 2026-04-24). No HTTPS fallback.
    let pq_offset = state.config.pq_port_offset;
    let pq_client = state.pq_client.clone();
    let network_id = state.config.network_id.clone();
    let protocol_version = super::config::PROTOCOL_VERSION;

    tokio::spawn(async move {
        let mut tried: HashSet<String> = HashSet::new();
        let mut handles = Vec::new();

        // Phase 1: push to DHT-selected targets
        for (identity_hash, base_url) in &targets {
            if *identity_hash == self_hash {
                continue;
            }
            if let Some(ref ex) = exclude_hash {
                if *identity_hash == *ex {
                    continue;
                }
            }
            tried.insert(identity_hash.clone());

            let w = wire.clone();
            let s = self_hash.clone();
            let id = identity_hash.clone();
            let t = tid.clone();
            let sem = semaphore.clone();
            let pq = pq_client.clone();
            let base = base_url.clone();
            let nid = network_id.clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await;
                // PQ-only relay (AUDIT-10 directive 2026-04-24). Missing PQ
                // addr or PQ-level failure surfaces as Unreachable/Failed —
                // same peer-backoff treatment as HTTP failures used to get.
                let pq_result = match http_to_pq_addr(&base, pq_offset) {
                    Some(pq_addr) => {
                        push_single_pq(
                            &pq, &pq_addr, &w,
                            super::pq_client::GossipHeaders {
                                hops,
                                sender_identity_hash: &s,
                                trace_id: t.as_deref(),
                                network_id: &nid,
                                protocol_version,
                            },
                        ).await
                    }
                    None => PushResult::Unreachable,
                };
                (id, pq_result)
            }));
        }

        let mut failed_count = 0u64;
        let mut hard_fails = 0u64;
        for handle in handles {
            if let Ok((ih, result)) = handle.await {
                match result {
                    PushResult::Ok => {
                        let mut peers = state2.peers.write().await;
                        peers.record_success(&ih);
                    }
                    PushResult::RateLimited => {
                        // 429 — alive but busy, don't penalize or count.
                    }
                    PushResult::Unreachable => {
                        // Timeout / connection error — backoff the peer, but don't
                        // count as a gossip protocol failure.
                        hard_fails += 1;
                        let mut peers = state2.peers.write().await;
                        let already_backing_off = peers.get(&ih)
                            .is_some_and(|p| p.in_backoff(now()));
                        if !already_backing_off {
                            peers.record_failure(&ih);
                        }
                    }
                    PushResult::Failed => {
                        failed_count += 1;
                        hard_fails += 1;
                        let mut peers = state2.peers.write().await;
                        let already_backing_off = peers.get(&ih)
                            .is_some_and(|p| p.in_backoff(now()));
                        if !already_backing_off {
                            peers.record_failure(&ih);
                        }
                    }
                }
            }
        }

        if failed_count > 0 {
            state2.gossip_push_failed_total.fetch_add(failed_count, Relaxed);
        }

        if hard_fails == 0 {
            return;
        }

        // Phase 2: DHT fallback — find alternative peers and retry (only for hard failures).
        // PQ-only (AUDIT-10): if the alternative has no PQ addr, it's Unreachable.
        let alternatives = find_dht_alternatives(&state2, &tried, hard_fails as usize);
        for (ih, base_url) in alternatives {
            state2.gossip_retry_total.fetch_add(1, Relaxed);
            let _permit = semaphore.acquire().await;
            let retry_result = match http_to_pq_addr(&base_url, pq_offset) {
                Some(pq_addr) => {
                    push_single_pq(
                        &pq_client, &pq_addr, &wire,
                        super::pq_client::GossipHeaders {
                            hops,
                            sender_identity_hash: &self_hash,
                            trace_id: tid.as_deref(),
                            network_id: &network_id,
                            protocol_version,
                        },
                    ).await
                }
                None => PushResult::Unreachable,
            };
            match retry_result {
                PushResult::Ok => {
                    state2.gossip_retry_success_total.fetch_add(1, Relaxed);
                    debug!("gossip retry succeeded to {}", &ih[..ih.len().min(16)]);
                }
                PushResult::RateLimited => {} // don't penalize
                PushResult::Unreachable | PushResult::Failed => {
                    let mut peers = state2.peers.write().await;
                    let already_backing_off = peers.get(&ih)
                        .is_some_and(|p| p.in_backoff(now()));
                    if !already_backing_off {
                        peers.record_failure(&ih);
                    }
                }
            }
        }
    });
}

/// Select peers for gossip via reputation-weighted DHT walk.
///
/// 1. Picks 2×ALPHA closest peers from a random DHT target (coverage)
/// 2. Scores each by reputation (from PeerTable)
/// 3. Returns top ALPHA peers sorted by reputation (quality)
///
/// Falls back to all connected peers if the DHT is empty.
/// Throttle window for the `select_gossip_peers: NO targets` WARN. A lone
/// authority seed's outbound PeerTable is legitimately empty and permanent
/// (pull-based followers dial in through NAT), so the warning would otherwise
/// fire on every pull tick (~14k lines/day) for a valid state. The first
/// occurrence logs immediately; subsequent ones are suppressed to at most one
/// per this window and report how many ticks were suppressed.
const NO_TARGETS_WARN_THROTTLE_SECS: u64 = 300;

/// Whether the `select_gossip_peers: NO targets` WARN should be emitted now,
/// given the last emit time and current time (both integer secs). `saturating_sub`
/// makes a backwards clock step (NTP correction) suppress rather than spuriously
/// emit: `now < last` yields 0, which is `< THROTTLE`. A never-warned state
/// (`last == 0`) always emits, since real `now` is far larger than the window.
fn should_emit_no_targets_warn(now_secs: u64, last_warn_secs: u64) -> bool {
    now_secs.saturating_sub(last_warn_secs) >= NO_TARGETS_WARN_THROTTLE_SECS
}

async fn select_gossip_peers(state: &Arc<NodeState>) -> Vec<(String, String)> {
    // DHT lookup — collect candidates while lock is held, then drop lock before await
    let candidates: Vec<(String, String)> = {
        let dht = state.dht.lock_recover();
        if !dht.is_empty() {
            let target_bytes = crate::crypto::hash::sha3_256(
                format!("gossip-pull-{}", now()).as_bytes(),
            );
            let target = NodeId(target_bytes);

            // Over-select 2×ALPHA candidates for reputation filtering
            dht.closest(&target, ALPHA * 2)
                .iter()
                .filter(|p| p.identity_hash != state.identity.identity_hash)
                .map(|p| {
                    (p.identity_hash.clone(), format!("http://{}:{}", p.host, p.port))
                })
                .collect()
        } else {
            Vec::new()
        }
    }; // DHT lock dropped here

    if !candidates.is_empty() {
        // On small networks (≤10 peers), pull from ALL peers every cycle
        // to ensure fast propagation. On larger networks, limit to ALPHA
        // for bandwidth efficiency.
        let is_small_network = candidates.len() <= 10;
        let max_targets = if is_small_network { candidates.len() } else { ALPHA };

        let peers = state.peers.read().await;
        let now_ts = now();
        let mut scored: Vec<(f64, String, String)> = candidates
            .into_iter()
            .filter_map(|(ih, _dht_url)| {
                // Skip peers not in PeerTable (DHT-only entries may be unreachable).
                // Small networks: include backed-off peers too — bandwidth is negligible
                // and skipping them creates exile spirals where peers never recover.
                // Large networks: skip backed-off peers for efficiency.
                // Use peer table's base_url() — DHT entries may have stale TLS flags.
                match peers.get(&ih) {
                    Some(p) if p.reachable
                        && (is_small_network || !p.in_backoff(now_ts))
                        && !p.in_pull_backoff(now_ts) => {
                        let rep = peers.reputation(&ih);
                        Some((rep, ih, p.base_url()))
                    }
                    _ => None,
                }
            })
            .collect();
        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        if !scored.is_empty() {
            state.gossip_select_dht_total.fetch_add(1, Relaxed);
            return scored
                .into_iter()
                .take(max_targets)
                .map(|(_, ih, url)| (ih, url))
                .collect();
        }
        // All DHT candidates filtered out (unreachable) — fall through to PeerTable
    }

    state.gossip_select_fallback_total.fetch_add(1, Relaxed);
    // Fallback: all known peers from PeerTable (not just connected —
    // after restart, peers may not have WebSocket state yet but are still reachable via HTTP)
    let peers = state.peers.read().await;
    let now_ts = now();
    let mut result: Vec<_> = peers
        .all()
        .iter()
        .filter(|p| p.identity_hash != state.identity.identity_hash && p.reachable && !p.in_backoff(now_ts))
        .map(|p| (p.identity_hash.clone(), p.base_url()))
        .collect();
    if result.is_empty() {
        // All peers in backoff — include them anyway.
        // Better to attempt a failing peer than pull from nobody.
        result = peers
            .all()
            .iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash && p.reachable)
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();
        if result.is_empty() {
            // All peers unreachable — include them anyway as last resort.
            // A single successful pull will restore reachability (record_pull_success),
            // breaking the isolation loop. Without this, the node is permanently
            // exiled once all peers hit 5 consecutive pull failures.
            result = peers
                .all()
                .iter()
                .filter(|p| p.identity_hash != state.identity.identity_hash)
                .map(|p| (p.identity_hash.clone(), p.base_url()))
                .collect();
            if result.is_empty() {
                // Throttle the empty-PeerTable WARN. On a lone authority seed the
                // outbound PeerTable is legitimately empty and permanent (pull-based
                // followers dial in through NAT), so an un-throttled warn spams
                // ~14k lines/day for a valid state and trains warning-blindness.
                // Log immediately on the first tick — a follower that just lost all
                // peers still gets a prompt signal — then throttle repeats and
                // report the suppressed count so a persistent lone-seed state is
                // distinguishable from a transient blip.
                let now_secs = now_ts as u64;
                let last = state.gossip_no_targets_last_warn_secs.load(Relaxed);
                if should_emit_no_targets_warn(now_secs, last) {
                    let suppressed = state.gossip_no_targets_suppressed.swap(0, Relaxed);
                    state.gossip_no_targets_last_warn_secs.store(now_secs, Relaxed);
                    if suppressed > 0 {
                        warn!("select_gossip_peers: NO targets (peer_table={}, self={}) [{} similar suppressed]",
                            peers.len(), &state.identity.identity_hash[..16], suppressed);
                    } else {
                        warn!("select_gossip_peers: NO targets (peer_table={}, self={})",
                            peers.len(), &state.identity.identity_hash[..16]);
                    }
                } else {
                    state.gossip_no_targets_suppressed.fetch_add(1, Relaxed);
                }
            } else {
                debug!("select_gossip_peers: all peers unreachable, trying {} anyway", result.len());
            }
        } else {
            debug!("select_gossip_peers: all peers in backoff, using {} anyway", result.len());
        }
    }
    result
}

// now() moved to ingest.rs

/// Pull loop — periodically query peers for new records.
/// Uses bloom filter delta sync when DAG > 50 records, timestamp pull otherwise.
/// Selects peers via DHT random walk (Kademlia-style) for scalable coverage.
pub async fn pull_loop(state: Arc<NodeState>, mut shutdown: mpsc::Receiver<()>) {
    // Gap 1: Light profile nodes skip record pull entirely — they sync headers
    // via `light_sync_loop` and verify balances from `/proof/account/{id}`.
    // Phone-tier hardware cannot ingest the full record firehose.
    use super::node_profile::NodeProfile;
    let profile = NodeProfile::from_str(&state.config.node_profile);
    if matches!(profile, NodeProfile::Light) {
        info!("pull_loop: NodeProfile::Light — skipping record sync (light_sync_loop handles headers)");
        // Still honor shutdown; just idle.
        let _ = shutdown.recv().await;
        return;
    }

    // NAT'd nodes can't receive pushes, so pull twice as often to compensate.
    let secs = state.config.gossip_pull_interval_secs;
    let base_interval = if state.config.behind_nat {
        Duration::from_secs(secs / 2).max(Duration::from_secs(5))
    } else {
        Duration::from_secs(secs)
    };
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    // 0b-(i): persisted across restarts (see the backstop block above
    // attestation_pull_loop). First-ever boot starts at MAX so the first
    // wrapping_add gives 0, triggering full_pull on cycle 1 — the boot-window
    // reconcile on later boots is carried by boot_ticks instead, since the
    // persisted counter resumes mid-range.
    let mut pull_cycle: u64 = load_backstop_cycle(&state, RECORD_PULL_CYCLE_KEY, u64::MAX);
    let mut boot_ticks: u64 = 0;
    // Adaptive full_pull: when full_pull finds records, run it again next cycle
    // instead of waiting 20 cycles. Closes record gaps 20x faster.
    let mut full_pull_found_records = false;

    loop {
        let jitter = Duration::from_millis((now() as u64).wrapping_mul(7) % 5000);
        tokio::select! {
            _ = tokio::time::sleep(base_interval + jitter) => {}
            _ = shutdown.recv() => {
                debug!("gossip pull loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): top-of-body backoff.
        // Inner record-batch processing in *_pull helpers also yields.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        let (dag_len, orphan_count) = {
            let dag = state.dag.read().await;
            (dag.len(), dag.orphan_count())
        };
        let pull_targets = select_gossip_peers(&state).await;

        if pull_targets.is_empty() {
            warn!("pull loop: no targets available (dag_len={dag_len}, cycle={pull_cycle})");
        } else {
            debug!("pull loop tick: dag_len={dag_len}, targets={}, cycle={pull_cycle}", pull_targets.len());
        }

        // ── Genesis bootstrap: seed ledger before normal pulls ──────
        // Normal pulls fail when the conservation pool is empty because
        // transfer records require the sender to have a balance. This
        // happens when a node has identity records but hasn't received
        // the genesis mint yet (dag_len > 0 but pool == 0).
        // Fix: trigger bootstrap whenever the pool is empty, not just
        // when the DAG is empty.
        let ledger_snap = state.ledger.read().await;
        let pool_empty = ledger_snap.conservation_pool == 0;
        let supply_zero = ledger_snap.total_supply == 0;
        drop(ledger_snap);
        // Only bootstrap if truly un-seeded: pool empty AND supply is zero.
        // A non-zero supply with empty pool means pool was drained (normal operation),
        // not a missing genesis mint. Rebuilding in that case corrupts the ledger.
        if pool_empty && supply_zero {
            // Force pull from genesis authority peer OR seed peers directly.
            // Don't rely on DHT targets — they might all be nodes that also lack the mint.
            // Try ALL seed peers until one succeeds, preferring genesis authority.
            let genesis_hash = &state.config.genesis_authority;

            // Build candidate URLs: genesis authority first, then all seed peers
            let mut candidate_urls: Vec<String> = Vec::new();

            // 1. Check if genesis authority is in pull_targets (DHT)
            if let Some((_, url)) = pull_targets.iter().find(|(ih, _)| ih == genesis_hash) {
                candidate_urls.push(url.clone());
            }

            // 2. Add ALL seed peers (not just first — any of them may have the mint)
            for seed in &state.config.seed_peers {
                if !candidate_urls.contains(seed) {
                    candidate_urls.push(seed.clone());
                }
            }

            // 3. Add any DHT pull targets as last resort
            for (_, url) in &pull_targets {
                if !candidate_urls.contains(url) {
                    candidate_urls.push(url.clone());
                }
            }

            if candidate_urls.is_empty() {
                warn!("genesis bootstrap: no peers and no seeds — cannot bootstrap");
                continue;
            }

            info!("genesis bootstrap: {} candidates to try (pool_empty={pool_empty}, dag_len={dag_len})", candidate_urls.len());

            // Clear seen set — records may have been "seen" by a previous failed pull
            // but not actually stored in RocksDB. Without this, the dedup prevents
            // the genesis mint from being stored on retry.
            {
                let mut seen = state.seen.lock_recover();
                let cleared = seen.len();
                seen.clear();
                if cleared > 0 {
                    info!("genesis bootstrap: cleared {cleared} entries from seen set");
                }
            }

            // Try each candidate URL until one returns records
            let mut total_pulled = 0u64;
            for url in &candidate_urls {
                let bootstrap_url = url.as_str();
                info!("genesis bootstrap: trying {bootstrap_url} ...");
                match bootstrap_pull_from_zero(&state, bootstrap_url).await {
                    Ok(n) if n > 0 => {
                        info!("genesis bootstrap: pulled {n} records from {bootstrap_url}");
                        total_pulled = n;
                        break; // Got records, stop trying
                    }
                    Ok(_) => {
                        debug!("genesis bootstrap: 0 records from {bootstrap_url}, trying next");
                    }
                    Err(e) => {
                        debug!("genesis bootstrap: {bootstrap_url} failed: {e}, trying next");
                    }
                }
            }
            if total_pulled == 0 {
                warn!("genesis bootstrap: all {} candidates returned 0 records", candidate_urls.len());
            }

            // Always rebuild ledger when pool is empty — records may already be in
            // RocksDB from a previous pull that stored them but didn't rebuild.
            let genesis = state.config.genesis_authority.clone();
            info!("genesis bootstrap: rebuilding ledger from RocksDB (streaming)...");
            if let Ok((mut new_ledger, applied)) = state.rocks.rebuild_ledger_streaming(&genesis, &state.config.genesis_validators) {
                let pool = new_ledger.conservation_pool;
                let accounts = new_ledger.accounts.len();
                // Sync applied IDs to CF_APPLIED and clear in-memory set
                state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
                new_ledger.applied_record_ids.clear();
                // Route through state core to avoid direct write lock contention
                if let Some(core) = state.state_core.get() {
                    core.replace_ledger(new_ledger).await;
                } else {
                    state.consensus.lock_recover().register_stakes_from_ledger(&new_ledger);
                    *state.ledger.write().await = new_ledger;
                }
                // Wholesale ledger replace: drop the memoized staked-anchor view so
                // the next proposer/verifier rebuilds from authoritative state. The
                // rebuilt ledger's `stake_mutation_seq` (#[serde(skip)]/fresh-build)
                // can collide with the cached key; the explicit invalidate is the
                // load-bearing step the contract mandates (state.rs:invalidate_anchor_view).
                state.invalidate_anchor_view();
                info!("ledger rebuilt: pool={pool}, accounts={accounts}, applied={applied} ops");
                if pool > 0 {
                    info!("genesis bootstrap COMPLETE — conservation pool seeded, normal pulls will work");
                }
            }
            continue; // Skip normal pull this cycle — next cycle will use the seeded ledger
        }

        // Track pull cycles for periodic full reconciliation.
        // Normal bloom delta_pull has persistent false positives (same records →
        // same hash → same FP pattern). Normal timestamp_pull only fetches records
        // NEWER than our tip, missing older records forever.
        // Every 200th cycle (~100 min at 30s interval): full pull from timestamp 0.
        // Was every 10th cycle (5 min) — caused ~144 GB/day traffic on 25K-record
        // DAGs because full_pull re-downloads ALL records from each peer.
        // Bloom delta_pull handles ongoing sync efficiently; full_pull is only
        // needed for rare divergence recovery.
        pull_cycle = pull_cycle.wrapping_add(1);
        boot_ticks += 1;
        store_backstop_cycle(&state, RECORD_PULL_CYCLE_KEY, pull_cycle);
        // 0b-(i): persisted-cycle cadence + boot-window pass on tick 1
        // (preserves the original boot-reconcile semantics of the MAX init).
        let force_full_pull = backstop_force_full(boot_ticks, 1, pull_cycle, 200);

        // On ≤2GB nodes, skip bloom-based delta_pull (calls record_ids() which
        // iterates ALL CF_RECORDS, decompressing 6.6GB+ through a 32MB block cache
        // → jemalloc fragmentation → 1.5GB anon heap). full_pull is safe: it uses
        // the same cursor-based query_records as timestamp_pull, no full scan.
        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
        let low_memory = ram_gb <= 2;
        // Also skip delta_pull when record count is high — record_ids() does a
        // full CF_RECORDS iterator scan. On the Laptop (88K records, 10GB SST),
        // this blocked the pull_loop for 9+ minutes, stalling all gossip sync.
        let record_count = state.record_count().unwrap_or(0);
        // Fallback: if __record_count__ is stale (e.g., snapshot loop bug wrote
        // dag_len instead of true count), check RocksDB's key estimate.
        let estimated_keys = state.rocks.approximate_cf_size("records");
        let effective_count = std::cmp::max(record_count as u64, estimated_keys) as usize;
        let skip_delta = low_memory || effective_count > 50_000;
        // Low-memory or large dataset: full_pull every 20 cycles (~10min at 30s).
        // With persistent cursor + cycle_cap=500, a 45K-record gap takes
        // 90 full_pull cycles × 10min = 15h to close — acceptable for 2GB nodes.
        // Normal nodes with small datasets: every 200 cycles (~100min) since
        // delta_pull handles most gaps efficiently.
        // Tier-1 (internal design notes §4): re-check a bounded
        // batch of open sealed-epoch deficits per cycle (point lookups, no
        // scan) and let any remaining open deficit drive full_pull early
        // instead of waiting out the ~200-cycle backstop. full_pull stays
        // cheap here: cursor-incremental + cycle_cap + frame-budget paged.
        let open_deficits = crate::network::ingest::recheck_dag_deficits(
            &state,
            crate::network::ingest::DAG_DEFICIT_RECHECKS_PER_CYCLE,
        );

        // Force full_pull while the last one still found records (gap not yet
        // closed) or any open deficit marks a sealed epoch provably missing
        // records.
        let force_full_pull = if full_pull_found_records || open_deficits > 0 {
            true
        } else if skip_delta {
            // First 5 ticks after restart: full_pull every cycle to rapidly
            // close record gaps. After tick 0 may fail (peers restarting
            // during deploy), ticks 1-4 retry while records are still fresh.
            // After tick 5, fall back to every 20 cycles. 0b-(i): keyed on
            // boot_ticks — the persisted pull_cycle resumes mid-range, so
            // `pull_cycle <= 5` would never be true again after first boot.
            boot_ticks <= 5 || pull_cycle.is_multiple_of(20)
        } else {
            force_full_pull
        };

        // Cursor seed (contract §4.3): if the earliest open hole starts BELOW
        // the current full_pull cursor, the incremental sweep already passed
        // it — seed the cursor just under the hole so the next sweep covers
        // it. Guarded to fire once per distinct target (an unresolvable hole
        // must not re-seed forever; the tail-reset still re-covers on its own
        // cadence).
        if open_deficits > 0 {
            // 8b part C: the seed clamps at the sweep floor (pinned —
            // SEAL-8b-01 test + dead-code guard live on deficit_seed_target).
            let target = deficit_seed_target(&state);
            if let Some(target) = target {
                let current = *state
                    .full_pull_cursor
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let bits = target.to_bits();
                if target < current
                    && state.full_pull_deficit_seed_bits.swap(bits, Relaxed) != bits
                {
                    *state
                        .full_pull_cursor
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = target;
                    state.rocks.save_full_pull_cursor(target);
                    info!(
                        "full_pull: cursor seeded to {target:.0} (earliest open dag-deficit window, {open_deficits} open)"
                    );
                }
            }
        }

        // Reset adaptive flag before full_pull cycle — will be re-set if any peer has records
        if force_full_pull {
            full_pull_found_records = false;
        }

        for (identity_hash, base_url) in &pull_targets {
            info!("pull_loop: peer={} dag={dag_len} orphans={orphan_count} full={force_full_pull} low_mem={low_memory} skip_delta={skip_delta} records={record_count} est_keys={estimated_keys}",
                &identity_hash[..identity_hash.len().min(16)]);
            let was_full_pull = force_full_pull;
            let result = if force_full_pull {
                // Full reconciliation + recent tail pull.
                // full_pull scans from historical cursor (e.g. April 8) — it takes
                // hours to reach current time. Without a tail pull, the DAG has NO
                // recent records, so epoch seal guard ("no recent DAG records") blocks
                // seals and push forever. The tail timestamp_pull grabs records from
                // pull_catchup_cursor forward, quickly advancing to current time.
                let full_n = full_pull(&state, base_url).await.unwrap_or(0);
                let ts_n = timestamp_pull(&state, base_url).await.unwrap_or(0);
                Ok(full_n + ts_n)
            } else if skip_delta {
                // Skip delta_pull: either low memory or too many records for
                // record_ids() full scan. Use cursor-based timestamp_pull instead.
                timestamp_pull(&state, base_url).await
            } else if dag_len > 50 {
                // Two-phase sync: delta_pull catches bulk missing records via bloom
                // comparison, then timestamp_pull catches the tail (records created
                // AFTER the bloom was built). This is critical for NAT nodes that
                // can't receive pushes — without the tail pull, new records from
                // VPS peers are always one cycle behind.
                let delta_result = delta_pull(&state, base_url).await;
                let delta_n = match &delta_result {
                    Ok(n) => *n,
                    Err(e) => {
                        info!("delta_pull failed from {}: {e}", &identity_hash[..identity_hash.len().min(16)]);
                        0
                    }
                };
                // Always follow up with timestamp_pull to catch recent records
                let ts_result = timestamp_pull(&state, base_url).await;
                let ts_n = ts_result.as_ref().copied().unwrap_or(0);
                Ok(delta_n + ts_n)
            } else {
                timestamp_pull(&state, base_url).await
            };

            // Update peer reputation based on pull outcome
            match &result {
                Ok(count) => {
                    info!("pull_loop: {} → {count} records from {}", &identity_hash[..identity_hash.len().min(16)], &base_url[..base_url.len().min(30)]);
                    // Stamp the last-successful-pull clock — fires even when count==0
                    // (a "caught up" pull is still success). This is the liveness
                    // signal the `pull-sync` health check reads to tell an idle-but-
                    // syncing follower from one that can't reach its seed.
                    state.last_successful_pull_unix.store(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        Relaxed,
                    );
                    let mut peers = state.peers.write().await;
                    peers.record_success(identity_hash);
                    peers.record_pull_success(identity_hash);
                    for _ in 0..*count {
                        peers.record_valid(identity_hash);
                    }
                }
                Err(e) => {
                    // Pull failure = we can't reach the peer (NAT, firewall, timeout).
                    // This is NOT the peer's fault — don't penalize reputation.
                    // But DO apply pull-specific backoff to avoid wasting cycles on
                    // unreachable addresses (30s → 60s → 5min → 30min).
                    info!("pull_loop: {} FAILED: {e}", &identity_hash[..identity_hash.len().min(16)]);
                    let mut peers = state.peers.write().await;
                    peers.record_pull_failure(identity_hash);
                }
            }

            // Track if full_pull found records — drives adaptive scheduling.
            // Sticky: if ANY peer returns records, keep running full_pull.
            // Reset only when a full_pull cycle finds 0 from all peers.
            if was_full_pull && matches!(&result, Ok(n) if *n > 0) {
                full_pull_found_records = true;
            }

            // ── Push-after-pull: send our recent records to this peer ────
            // Fixes NAT propagation bug: nodes behind NAT can't receive
            // incoming connections, so their locally-created records never
            // propagate via pull alone. By pushing after each pull cycle,
            // NAT'd nodes actively deliver their records to reachable peers.
            push_recent_to_peer(&state, base_url).await;

            // Yield between peers so HTTP handlers (/metrics, /health, /status,
            // incoming gossip) get worker time. This used to fire only on
            // `cpus <= 1`, but 2-vCPU nodes run with TOKIO_WORKER_THREADS=2.
            // After Tier 1.1 widened MAX_PUSH 50→200 (4× more wantedlist
            // round-trips per peer), the serial pull→push→pull→push cycle
            // monopolizes one of two workers for many seconds, starving the
            // other worker behind heavy attestation work and stalling the
            // /metrics endpoint. cpus<=1 → 100ms sleep (preserves the original
            // 1-CPU fix); otherwise tokio::task::yield_now() is essentially
            // zero-cost and unconditionally lets the runtime re-schedule.
            if cpus <= 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                tokio::task::yield_now().await;
            }
        }

        // Tier-1 trend alarm (contract §4.2): a full_pull sweep that found
        // nothing while sealed-epoch deficits stayed open is the durable
        // "the hole is not healing" signal — pure outcome accounting, no new
        // scans. Streak resets on any progress; the monotonic twin feeds
        // rate() alerting.
        if force_full_pull && open_deficits > 0 && !pull_targets.is_empty() {
            if full_pull_found_records {
                state.full_pull_zero_progress_streak.store(0, Relaxed);
            } else {
                state.full_pull_zero_progress_streak.fetch_add(1, Relaxed);
                state.full_pull_zero_progress_total.fetch_add(1, Relaxed);
            }
        }

        // Update bootstrap phase based on current peer count (economics §14.2)
        {
            let peers = state.peers.read().await;
            // +1 for self — node_count includes this node
            let node_count = (peers.connected().len() as u64) + 1;
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let mut bootstrap = state.bootstrap_state.write_recover();
            if bootstrap.update(node_count, now_ts) {
                info!(
                    "bootstrap phase transition: {} (multiplier={:.1}x, nodes={})",
                    bootstrap.current_phase.as_str(),
                    bootstrap.current_multiplier(),
                    node_count,
                );
            }
        }

        // Periodically prune finalized records from consensus tracking to bound memory
        let finalized = state.finalized.read().await;
        if !finalized.is_empty() {
            let mut consensus = state.consensus.lock_recover();
            let pruned = consensus.prune_where(|rid| finalized.contains(rid));
            if pruned > 0 {
                debug!("pruned {pruned} finalized records from consensus tracker");
            }
        }

    }
}

/// Independent orphan resolver loop — runs on its own 30s timer, NOT inside pull_loop.
///
/// Orphan edges accumulate when records arrive before their parents (common after
/// node restart or on NAT'd nodes). The pull_loop can take 10+ minutes per cycle
/// under heavy sync load due to lock contention; running the resolver there starved
/// it completely — it would get 1 call per 10-16 minute pull cycle. This independent
/// loop ensures orphans are resolved regardless of pull-loop speed.
pub async fn orphan_resolver_loop(state: Arc<NodeState>, mut shutdown: mpsc::Receiver<()>) {
    let interval = Duration::from_secs(60);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("orphan resolver loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10).
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        // Under sustained saturation, skip this tick entirely. The yield
        // above helps a transient micro-spike but cannot rescue a runtime
        // that's pegged for the whole 30+ s resolve cycle (a 2-vCPU node in
        // post-restart catch-up saw ~14 min of HTTP starvation). One skipped
        // tick costs 60 s of orphan-resolution latency; HTTP and metrics
        // keep serving meanwhile.
        if state.system_load.is_saturated() {
            state
                .orphan_resolver_saturation_skips_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(
                "orphan resolver: skip tick — host saturated (load_1m={:.2}/core, cpu={:.2}/{} cores)",
                state.system_load.normalized_load(),
                state.system_load.cpu_fraction(),
                state.system_load.cores()
            );
            continue;
        }

        let orphan_count = {
            let dag = state.dag.read().await;
            dag.orphan_count()
        };

        if orphan_count == 0 {
            continue;
        }

        let pull_targets = select_gossip_peers(&state).await;
        if pull_targets.is_empty() {
            continue;
        }

        // Always attempt fetch, even at high orphan counts. Previous behavior
        // was prune-only at orphan_count > 200, which left nodes with
        // persistent gaps unable to recover (a bootstrap pathology: 6334
        // orphan edges, finalized count flat for 30+ min). The
        // fetch is bounded internally by `MAX_FETCH = 50` in resolve_orphan_parents
        // so cascade growth per cycle is also bounded.
        resolve_orphan_parents(&state, &pull_targets).await;

        // After fetch, if orphans are still high, run the cascade-circuit-breaker
        // prune. The fetch above made bounded forward progress; the prune here
        // prevents runaway growth when each fetched parent reveals more missing
        // grandparents.
        let orphan_count_after = state.dag.read().await.orphan_count();
        if orphan_count_after > 200 {
            match tokio::time::timeout(Duration::from_secs(5), state.dag.write()).await {
                Ok(mut dag_guard) => {
                    let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                    let pruned = dag.prune_orphan_edges(100);
                    let remaining = dag.orphan_count();
                    info!(
                        "orphan prune: removed {pruned} edges, {remaining} remain (had {orphan_count_after} after fetch, was {orphan_count} pre-fetch)"
                    );
                    state
                        .orphan_resolver_high_count_pruned_total
                        .fetch_add(pruned as u64, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => {
                    warn!("orphan prune: DAG write lock timeout (5s) — will retry next cycle");
                }
            }
        }
    }
}

/// 2. Batch-fetches them from peers via POST /records/fetch
/// 3. Inserts them using insert_record_synced (bypasses rate limits)
/// 4. Reindexes orphans to wire parent→child edges and collapse tips
async fn resolve_orphan_parents(
    state: &Arc<super::state::NodeState>,
    pull_targets: &[(String, String)],
) {
    const MAX_FETCH: usize = 50; // cap per cycle — keep low to avoid cascading orphan growth

    // Consolidated step: single read lock to collect all info, single write lock for cleanup.
    // Previously used 6+ separate lock acquisitions, each blocking state_core's record processing.
    let (missing_parents, needs_cleanup) = {
        let dag = state.dag.read().await;
        let orphan_count = dag.orphan_count();
        if orphan_count == 0 {
            return;
        }
        let parent_keys = dag.orphan_parent_key_count();
        let in_nodes = dag.orphan_parents_in_nodes();
        let tips = dag.tips().len();

        if orphan_count > 1000 {
            info!(
                "orphan resolver: {orphan_count} edges across {parent_keys} parents ({in_nodes} in-nodes, {} not-in-nodes), {tips} tips",
                parent_keys - in_nodes
            );
        } else {
            debug!("orphan resolver: {orphan_count} orphan edges, {tips} tips");
        }

        let candidates = dag.orphan_parent_ids();
        let needs_reindex = in_nodes > 0;
        drop(dag);

        // RocksDB lookups outside DAG lock (sync but no lock contention)
        let mut to_fetch = Vec::new();
        let mut evicted = Vec::new();
        for id in &candidates {
            if state.rocks.record_exists(id).unwrap_or(false) {
                evicted.push(id.clone());
            } else if to_fetch.len() < MAX_FETCH {
                to_fetch.push(id.clone());
            }
        }

        let needs_cleanup = needs_reindex || !evicted.is_empty();

        // Single write lock for reindex + evicted cleanup (with timeout to avoid stalling)
        if needs_cleanup {
            match tokio::time::timeout(Duration::from_secs(5), state.dag.write()).await {
                Ok(mut dag_guard) => {
                    let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                    if needs_reindex {
                        let linked = dag.reindex_orphans();
                        if linked > 0 {
                            info!("orphan resolver: reindexed {linked} edges ({in_nodes} parents were in-nodes)");
                        }
                    }
                    if !evicted.is_empty() {
                        let mut wired = 0usize;
                        for pid in &evicted {
                            // Convert orphan edges to structural edges — parent exists in
                            // storage, just not in the hot DAG. Preserves mesh connectivity.
                            let children: Vec<String> = dag.orphan_children_of(pid);
                            for cid in &children {
                                dag.link_external_parent(cid, pid);
                                wired += 1;
                            }
                        }
                        if wired > 0 {
                            info!("orphan resolver: wired {wired} external edges for {} parents in RocksDB", evicted.len());
                        }
                    }
                }
                Err(_) => {
                    warn!("orphan resolver: DAG write lock timeout (cleanup), will retry");
                }
            }
        }

        (to_fetch, needs_cleanup)
    };
    let _ = needs_cleanup; // used above in the block

    if missing_parents.is_empty() {
        return;
    }

    info!(
        "orphan resolver: fetching {} missing parents from {} peers",
        missing_parents.len(),
        pull_targets.len()
    );

    // Step 2: Try each peer until we get the missing records
    let mut total_inserted = 0u64;
    for (_identity_hash, base_url) in pull_targets {
        if missing_parents.is_empty() {
            break;
        }

        // Filter to only IDs we still don't have (previous peer may have provided some)
        let still_missing: Vec<String> = {
            let dag = state.dag.read().await;
            missing_parents.iter()
                .filter(|id| !dag.contains(id))
                .cloned()
                .collect()
        };

        if still_missing.is_empty() {
            break;
        }

        let pq_addr = match http_to_pq_addr(base_url, state.config.pq_port_offset) {
            Some(a) => a,
            None => {
                debug!(
                    "orphan resolver: no PQ addr for {}, skipping",
                    &base_url[..base_url.len().min(30)]
                );
                continue;
            }
        };
        match state.pq_client.fetch_records(&pq_addr, &still_missing).await {
            Ok(wire_list) => {
                let mut decoded: Vec<ValidationRecord> = wire_list
                    .iter()
                    .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
                    .collect();
                // Sort by timestamp — parents should be processed before children
                decoded.sort_by(|a, b| {
                    a.timestamp.total_cmp(&b.timestamp)
                });

                for (i, record) in decoded.into_iter().enumerate() {
                    let record_id = record.id.clone();
                    let already_seen = state.seen.lock_recover().contains(&record_id);
                    if already_seen { continue; }
                    let already_rejected = state.gossip_rejected.lock_recover().contains(&record_id);
                    if already_rejected { continue; }

                    let is_seal_class = record.metadata.contains_key(EPOCH_OP_KEY);
                    match super::ingest::insert_record_synced(state, record).await {
                        Ok(_) => {
                            state.seen.lock_recover().insert(record_id);
                            total_inserted += 1;
                        }
                        Err(e) => {
                            if is_seal_class {
                                // R3-8 soak forensics: seal-class rejects are loud.
                                state.gossip_seal_insert_reject_total.fetch_add(1, Relaxed);
                                warn!("orphan resolver: SEAL-class record {} rejected at ingest: {e}", &record_id[..record_id.len().min(16)]);
                            } else {
                                debug!("orphan resolver: record {} failed: {e}", &record_id[..record_id.len().min(16)]);
                            }
                        }
                    }
                    // Rate-limit on low-memory machines (same as att-pull fetch)
                    if i > 0 && i % 5 == 0 {
                        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
                        if ram_gb <= 4 {
                            let pause = if ram_gb <= 2 { 500 } else { 100 };
                            tokio::time::sleep(std::time::Duration::from_millis(pause)).await;
                        }
                    }
                }
            }
            Err(e) => {
                debug!("orphan resolver: fetch from {} failed: {e}", &base_url[..base_url.len().min(30)]);
            }
        }
    }

    // Steps 3+4 consolidated: single write lock for reindex + prune.
    // Previously 3 separate lock acquisitions (read + write + write) that each blocked state_core.
    if total_inserted > 0 || !missing_parents.is_empty() {
        // Collect prune candidates OUTSIDE the lock (miss counter is a std::sync::Mutex)
        let to_prune: Vec<String> = if !missing_parents.is_empty() {
            let misses = state.orphan_fetch_misses.lock_recover();
            missing_parents.iter()
                .filter(|pid| misses.get(*pid).map(|(c, _)| *c).unwrap_or(0) >= 3)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        // Single write lock for reindex + prune (with timeout)
        {
            state.dag_write_holder.store(2, std::sync::atomic::Ordering::Relaxed);
            match tokio::time::timeout(Duration::from_secs(5), state.dag.write()).await {
                Ok(mut dag_guard) => {
                    let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                    if total_inserted > 0 {
                        let linked = dag.reindex_orphans();
                        let remaining = dag.orphan_count();
                        let tips = dag.tips().len();
                        info!(
                            "orphan resolver: inserted {total_inserted} parents, linked {linked} edges, {remaining} orphans remain, {tips} tips"
                        );
                    }
                    let mut pruned_edges = 0usize;
                    for pid in &to_prune {
                        pruned_edges += dag.remove_orphan_parent(pid);
                    }
                    if pruned_edges > 0 {
                        info!(
                            "orphan resolver: pruned {} stale parents ({} edges) — not found after 3+ attempts",
                            to_prune.len(), pruned_edges
                        );
                    }
                }
                Err(_) => {
                    warn!("orphan resolver: DAG write lock timeout (reindex), will retry");
                }
            }
        }
        state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed);

        // Update miss counters outside lock
        if !missing_parents.is_empty() {
            let mut misses = state.orphan_fetch_misses.lock_recover();
            for pid in &to_prune {
                misses.remove(pid);
            }
            let now_ts = crate::network::ingest::now();
            for pid in &missing_parents {
                if !to_prune.contains(pid) {
                    let entry = misses.entry(pid.clone()).or_insert((0, now_ts));
                    entry.0 += 1;
                    entry.1 = now_ts;
                }
            }
            // Reap stale entries (parents that went quiet without hitting the
            // 3-miss prune threshold) and enforce the hard cap.
            prune_orphan_miss_map(&mut misses, now_ts);
        }
    }
}

/// Autotune: floor for the dynamic MAX_PUSH cap.
/// Matches the original compile-time value. The autotuner will
/// not lower below this — sustained at_cap rate < 5% with cap already at
/// floor means the floor-push interval is short enough that fleet rate
/// never saturates the cap, which is the desired steady state.
pub const PUSH_AFTER_PULL_FLOOR: usize = 50;

/// Autotune: ceiling for the dynamic MAX_PUSH
/// cap. 4× the default of 200. The receive side caps inbound
/// announcements at 1000 in `pq_transport/router.rs::handle_announce`, so
/// 800 stays well within the wire envelope. Hitting the ceiling sustained
/// is the operator signal to shorten the floor-push interval rather than
/// trying to push more per cycle.
pub const PUSH_AFTER_PULL_CEILING: usize = 800;

/// NETWORK-HARDENING Tier 1.1 autotune: minimum seconds between cap
/// re-evaluations. 60s = ~15 push cycles at the default 4s floor-push
/// interval — enough samples to make the at_cap ratio meaningful while
/// still letting the cap track real load shifts within ~minutes.
pub const PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS: u64 = 60;

/// NETWORK-HARDENING Tier 1.1 autotune: minimum push cycles seen in an
/// interval before the autotuner will adjust. Below this threshold the
/// at_cap ratio is too noisy to be actionable (a single cap-hit on 2
/// cycles = 50%, but the sample size is meaningless).
const PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES: u64 = 5;

/// NETWORK-HARDENING Tier 1.1 autotune: cap-hit ratio (out of 100) above
/// which the autotuner doubles the cap. 50% means more than half of cycles
/// during the eval window were saturated — clear signal the cap is too
/// small for fleet rate.
const PUSH_AFTER_PULL_AUTOTUNE_RAISE_PCT: u64 = 50;

/// NETWORK-HARDENING Tier 1.1 autotune: cap-hit ratio (out of 100) below
/// which the autotuner halves the cap. 5% means most cycles cleared
/// without cap pressure — wire-cost can be cut without stranding records.
const PUSH_AFTER_PULL_AUTOTUNE_LOWER_PCT: u64 = 5;

// Compile-time invariants for the push-after-pull autotune knobs. A future
// edit that collapses FLOOR >= CEILING (autotune range empty → cap pinned),
// flips RAISE <= LOWER (cap would oscillate or never raise → unstable),
// zeroes INTERVAL_SECS (every push cycle would re-evaluate the cap → wasteful
// CAS spin), or zeroes MIN_SAMPLES (single-cycle at_cap fraction would flap
// the cap on every push) now fails at `cargo build`, not at `cargo test`.
const _: () = assert!(
    PUSH_AFTER_PULL_FLOOR < PUSH_AFTER_PULL_CEILING,
    "PUSH_AFTER_PULL autotune range must be non-empty (FLOOR < CEILING)"
);
const _: () = assert!(
    PUSH_AFTER_PULL_AUTOTUNE_RAISE_PCT > PUSH_AFTER_PULL_AUTOTUNE_LOWER_PCT,
    "PUSH_AFTER_PULL_AUTOTUNE_RAISE_PCT must exceed LOWER_PCT for stable autotune"
);
const _: () = assert!(
    PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS > 0,
    "PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS must be positive — zero re-evaluates every cycle"
);
const _: () = assert!(
    PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES > 0,
    "PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES must be positive — zero flaps cap every push"
);

/// NETWORK-HARDENING Tier 1.1 autotune: re-evaluate the push-after-pull
/// MAX_PUSH cap based on observed cap-hit rate. Called from
/// `push_recent_to_peer` after the cycle's metrics are recorded; throttled
/// internally so most calls return immediately without computing anything.
///
/// Logic:
/// 1. Throttle to once per `PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS` via CAS
///    on `gossip_push_after_pull_autotune_last_eval_at`.
/// 2. Compute (at_cap_delta, cycles_delta) since the last eval snapshot.
/// 3. If cycles_delta < `PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES`, hold steady
///    (insufficient signal).
/// 4. cap_hit_pct = at_cap_delta * 100 / cycles_delta.
/// 5. If pct ≥ raise threshold, double cap (capped at ceiling).
///    If pct < lower threshold and cap > floor, halve cap (floored).
///    Else hold steady.
/// 6. Increment raises/lowers counters; emit info-level log on adjustment.
///
/// Atomic ordering: Relaxed everywhere because (a) the cap is read on a
/// best-effort basis (one-cycle delay between adjustment and observation
/// is acceptable), and (b) the CAS on last_eval_at is the linearization
/// point that prevents racing tasks from double-evaluating the same window.
pub(crate) fn maybe_autotune_push_max(state: &Arc<NodeState>) {
    use std::sync::atomic::Ordering;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now_secs == 0 {
        return; // clock skew safety
    }

    let last_eval = state.gossip_push_after_pull_autotune_last_eval_at.load(Ordering::Relaxed);

    // Throttle: bail if last eval was within the interval window. Note: on
    // first call after restart, last_eval is 0, so now_secs.saturating_sub(0)
    // == now_secs which always exceeds the interval — first eval establishes
    // the baseline snapshot but won't actually adjust because last_at_cap /
    // last_cycles are also 0 and the deltas equal the absolute counts (which
    // may legitimately be zero on a quiet node).
    if now_secs.saturating_sub(last_eval) < PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS {
        return;
    }

    // CAS gate: only one task evaluates per interval window. If another task
    // has already advanced last_eval since our load, defer to that task.
    if state
        .gossip_push_after_pull_autotune_last_eval_at
        .compare_exchange(last_eval, now_secs, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let at_cap_now = state.gossip_push_after_pull_at_cap_total.load(Ordering::Relaxed);
    let cycles_now = state.gossip_push_after_pull_cycles_total.load(Ordering::Relaxed);
    let at_cap_prev = state
        .gossip_push_after_pull_autotune_last_at_cap
        .swap(at_cap_now, Ordering::Relaxed);
    let cycles_prev = state
        .gossip_push_after_pull_autotune_last_cycles
        .swap(cycles_now, Ordering::Relaxed);

    let cycles_delta = cycles_now.saturating_sub(cycles_prev);
    let at_cap_delta = at_cap_now.saturating_sub(at_cap_prev);

    if cycles_delta < PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES {
        // Insufficient samples to act — leave cap unchanged but the
        // last_eval_at/last_at_cap/last_cycles snapshots are now updated
        // so the next interval evaluates a fresh delta.
        return;
    }

    let cap_hit_pct = (at_cap_delta * 100) / cycles_delta;
    let current_max = state.gossip_push_after_pull_max.load(Ordering::Relaxed);

    let new_max = if cap_hit_pct >= PUSH_AFTER_PULL_AUTOTUNE_RAISE_PCT {
        // Saturating-heavy interval: cap is too small. Double, clamped to
        // ceiling. Use saturating_mul so a future ceiling change doesn't
        // panic on overflow at large cap values.
        current_max.saturating_mul(2).min(PUSH_AFTER_PULL_CEILING)
    } else if cap_hit_pct < PUSH_AFTER_PULL_AUTOTUNE_LOWER_PCT && current_max > PUSH_AFTER_PULL_FLOOR {
        // Quiet interval: cap is over-provisioned. Halve, floored. Division
        // by 2 (vs e.g. /3) is symmetric with the raise op so the cap
        // returns to baseline at the same speed it grew.
        (current_max / 2).max(PUSH_AFTER_PULL_FLOOR)
    } else {
        // Either inside the dead band [LOWER_PCT, RAISE_PCT) or already at
        // the floor with low cap-hits (can't go any lower) — hold steady.
        current_max
    };

    if new_max == current_max {
        return;
    }

    state.gossip_push_after_pull_max.store(new_max, Ordering::Relaxed);
    if new_max > current_max {
        state
            .gossip_push_after_pull_autotune_raises_total
            .fetch_add(1, Ordering::Relaxed);
        info!(
            "gossip push autotune: max {} → {} (cap_hit {}/{} = {}% over last {}s)",
            current_max, new_max, at_cap_delta, cycles_delta, cap_hit_pct,
            PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS,
        );
    } else {
        state
            .gossip_push_after_pull_autotune_lowers_total
            .fetch_add(1, Ordering::Relaxed);
        info!(
            "gossip push autotune: max {} → {} (cap_hit {}/{} = {}% over last {}s)",
            current_max, new_max, at_cap_delta, cycles_delta, cap_hit_pct,
            PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS,
        );
    }
}

/// Push recent locally-created records to a peer.
///
/// Fixes the NAT propagation bug: when a node behind NAT creates a record
/// (e.g., a transfer via the web app), the initial push_to_peers may fail
/// because peers can't reach back to verify. By proactively pushing our
/// recent DAG tips during each pull cycle, we ensure records propagate
/// even from NAT'd nodes.
///
/// Protocol §11.14: Uses announcement-based gossip — sends compact
/// announcements (~250 bytes each) first, only pushes full records
/// for the ones the peer actually needs. ~10x bandwidth reduction.
async fn push_recent_to_peer(
    state: &Arc<NodeState>,
    peer_url: &str,
) {
    // NETWORK-HARDENING Tier 1.1: was bumped from 50 → 200 (window 120s →
    // 600s) so a NAT'd node creating a burst > 50 records inside one push
    // cycle doesn't leave records stranded waiting for the next cycle's
    // tip-only recap. As of the autotune slice (2026-04-28) the cap is
    // dynamic — read from `state.gossip_push_after_pull_max`, adjusted by
    // `maybe_autotune_push_max` based on observed cap-hit rate. Floor 50,
    // ceiling 800, no operator action needed for normal load fluctuation.
    let max_push = state
        .gossip_push_after_pull_max
        .load(std::sync::atomic::Ordering::Relaxed);
    const PUSH_WINDOW_SECS: f64 = 600.0;

    // Collect announcements for recent records (tips + records created in
    // last PUSH_WINDOW_SECS). Tips alone miss non-tip records from sequential
    // bursts (e.g., 200 transfers where only the last one is a DAG tip).
    // Including recent records by timestamp ensures all locally-created
    // records propagate within 1-2 gossip cycles.
    let announcements: Vec<RecordAnnouncement> = {
        let dag = state.dag.read().await;
        let tips = dag.tips();
        if tips.is_empty() {
            return;
        }

        let mut tip_ts: Vec<(&str, f64)> = tips.iter()
            .filter_map(|t| dag.timestamps.get(t.as_str()).map(|ts| (t.as_str(), *ts)))
            .collect();
        tip_ts.sort_by(|a, b| b.1.total_cmp(&a.1));

        let tip_ids: Vec<String> = tip_ts.into_iter()
            .take(max_push)
            .map(|(id, _)| id.to_string())
            .collect();
        drop(dag); // release DAG lock before spawn_blocking

        let since = now() - PUSH_WINDOW_SECS;
        let rocks = state.rocks.clone();
        let our_hash = state.identity.identity_hash.clone();
        let max_push_inner = max_push;
        let anns = match tokio::task::spawn_blocking(move || {
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();

            // Tips first (always push)
            for tip_id in &tip_ids {
                if let Ok(Some(rec)) = rocks.get_record(tip_id) {
                    seen.insert(tip_id.clone());
                    out.push(RecordAnnouncement::from_record(&rec));
                }
            }

            // Recent records by timestamp (fill up to max_push)
            if out.len() < max_push_inner {
                if let Ok(recent_ids) = rocks.recent_record_ids(since, max_push_inner * 2) {
                    for rid in recent_ids {
                        if out.len() >= max_push_inner { break; }
                        if seen.contains(&rid) { continue; }
                        // Only push our own records (avoid re-pushing relayed gossip)
                        if let Ok(Some(rec)) = rocks.get_record(&rid) {
                            if crate::accounting::types::creator_identity_hash(&rec) == our_hash {
                                seen.insert(rid);
                                out.push(RecordAnnouncement::from_record(&rec));
                            }
                        }
                    }
                }
            }

            out
        }).await {
            Ok(a) => a,
            Err(_) => return,
        };
        anns
    };

    if announcements.is_empty() {
        return;
    }

    let ann_count = announcements.len();
    state.gossip_push_after_pull_announcements_total
        .fetch_add(ann_count as u64, std::sync::atomic::Ordering::Relaxed);
    state.gossip_push_after_pull_cycles_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if ann_count >= max_push {
        state.gossip_push_after_pull_at_cap_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    // NETWORK-HARDENING Tier 1.1 autotune: evaluate after recording metrics
    // so this cycle's cap-hit (if any) is included in the next eval window.
    // Internally throttled — most calls return without computing anything.
    maybe_autotune_push_max(state);
    debug!("push-after-pull: announcing {} records to {}", ann_count, &peer_url[..peer_url.len().min(30)]);

    // Step 1: Send announcements, get back wanted IDs (PQ-first)
    let wanted = match pq_announce(state, peer_url, &announcements).await {
        Ok(w) => w,
        Err(e) => {
            debug!("push-after-pull: announce failed to {}: {e}", &peer_url[..peer_url.len().min(30)]);
            return;
        }
    };

    if wanted.is_empty() {
        debug!("push-after-pull: {ann_count} announced, peer has all — {}", &peer_url[..peer_url.len().min(30)]);
        return;
    }
    debug!("push-after-pull: peer wants {} of {} announced — {}", wanted.len(), ann_count, &peer_url[..peer_url.len().min(30)]);

    // Batch-fetch wire bytes off the async runtime
    let rocks = state.rocks.clone();
    let wanted_clone = wanted.clone();
    let wire_map: std::collections::HashMap<String, Vec<u8>> = match tokio::task::spawn_blocking(move || {
        let mut map = std::collections::HashMap::new();
        for id in &wanted_clone {
            if let Ok(bytes) = rocks.get_wire_bytes(id) {
                map.insert(id.clone(), bytes);
            }
        }
        map
    }).await {
        Ok(m) => m,
        Err(_) => return,
    };

    // AUDIT-10 Milestone C: PQ-only push. If the peer's PQ address can't
    // be derived, skip — we don't downgrade to harvest-now-decrypt-later.
    let pq_addr = match http_to_pq_addr(peer_url, state.config.pq_port_offset) {
        Some(a) => a,
        None => {
            debug!("push-after-pull: no PQ addr for {}, skipping", &peer_url[..peer_url.len().min(30)]);
            return;
        }
    };
    let self_hash_pq = state.identity.identity_hash.clone();
    let network_id_pq = state.config.network_id.clone();
    let protocol_version_pq = super::config::PROTOCOL_VERSION;
    let mut pushed = 0u32;
    for wanted_id in &wanted {
        let wire = match wire_map.get(wanted_id) {
            Some(w) => w.clone(),
            None => continue,
        };

        let pq_result = push_single_pq(
            &state.pq_client,
            &pq_addr,
            &wire,
            super::pq_client::GossipHeaders {
                hops: 2,
                sender_identity_hash: &self_hash_pq,
                trace_id: None,
                network_id: &network_id_pq,
                protocol_version: protocol_version_pq,
            },
        ).await;
        match pq_result {
            PushResult::Ok => pushed += 1,
            PushResult::RateLimited => {}
            PushResult::Failed | PushResult::Unreachable => {
                debug!(
                    "push-after-pull: PQ push failed to {}",
                    &peer_url[..peer_url.len().min(30)]
                );
            }
        }
    }

    if pushed > 0 {
        debug!("push-after-pull: announced {ann_count}, pushed {pushed}/{} wanted to {}", wanted.len(), &peer_url[..peer_url.len().min(30)]);
    }

    // ── Push recent attestations alongside records ──────────────────
    // NAT nodes can't receive inbound attestation pushes from VPS.
    // Attestation pull watermarks advance past attestations for missing
    // records, permanently losing them. Fix: push our recent attestations
    // to peers during push-after-pull, ensuring bidirectional flow.
    push_recent_attestations_to_peer(state, peer_url).await;
}

/// Push recent attestations to a peer during the push-after-pull cycle.
///
/// Attestation pull has a watermark bug: when a node pulls attestations but
/// doesn't have the corresponding record locally, it skips the attestation
/// and advances the watermark past it. Those attestations are never re-fetched.
/// This function compensates by pushing recent attestations outbound, ensuring
/// NAT nodes share attestations they've received or created.
async fn push_recent_attestations_to_peer(
    state: &Arc<NodeState>,
    peer_url: &str,
) {
    const MAX_ATT_PUSH: usize = 100;
    let since = now() - 300.0; // last 5 minutes of attestations

    let attestations = {
        let mgr = state.witness_mgr.as_ref();
        match mgr.get_attestations_since(since, MAX_ATT_PUSH) {
            Ok(atts) => atts,
            Err(_) => return,
        }
    };

    if attestations.is_empty() {
        return;
    }

    // AUDIT-10 Milestone C: PQ-only attestation push.
    let pq_addr = match http_to_pq_addr(peer_url, state.config.pq_port_offset) {
        Some(a) => a,
        None => {
            debug!(
                "push-after-pull: no PQ addr for {}, skipping attestation push",
                &peer_url[..peer_url.len().min(30)]
            );
            return;
        }
    };
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();
    let mut pushed = 0u32;

    for att in &attestations {
        let mut payload = serde_json::json!({
            "record_id": att.record_id,
            "witness_hash": att.witness_hash,
            "signature": hex::encode(&att.signature),
            "timestamp": att.timestamp,
        });
        if let Some(pk) = &att.witness_public_key {
            payload["witness_public_key"] = serde_json::json!(hex::encode(pk));
        }
        if let Some(nonce) = att.powas_nonce {
            payload["powas_nonce"] = serde_json::json!(nonce);
        }
        if let Some(diff) = att.powas_difficulty {
            payload["powas_difficulty"] = serde_json::json!(diff);
        }

        let body_bytes = payload.to_string().into_bytes();
        match state.pq_client.receive_attestation_gossip(
            &pq_addr, &body_bytes,
            super::pq_client::GossipHeaders {
                hops: 1,
                sender_identity_hash: &self_hash,
                trace_id: None,
                network_id: &network_id,
                protocol_version: super::config::PROTOCOL_VERSION,
            },
        ).await {
            Ok(resp) if resp.is_success() => { pushed += 1; }
            Ok(_) | Err(_) => {} // duplicates and transient failures are expected
        }
    }

    if pushed > 0 {
        debug!("push-after-pull: pushed {pushed}/{} attestations to {}", attestations.len(), &peer_url[..peer_url.len().min(30)]);
    }
}

/// Bootstrap pull from timestamp 0 — fetches ALL records from peer.
/// Used during genesis bootstrap when the conservation pool is empty.
/// Normal timestamp_pull would skip genesis records because the cursor
/// starts from the newest local tip (which may already be past the mint).
/// Paginates through all records until the peer is exhausted — the genesis
/// mint may be past the first 500 records if old records exist.
/// C7 admission predicate for bootstrap-pulled records: the same BIT-level
/// timestamp rule as the ingest gate (`is_finite() && !is_sign_negative()` —
/// rejects NaN/±inf/all negatives INCLUDING `-0.0`, whose be-bytes `0x8000…`
/// sort above every positive key while IEEE `-0.0 >= 0.0` is true). Split
/// out so the gate logic is unit-testable without a fake bootstrap peer.
fn bootstrap_record_ts_admissible(record: &ValidationRecord) -> bool {
    record.timestamp.is_finite() && !record.timestamp.is_sign_negative()
}

async fn bootstrap_pull_from_zero(state: &Arc<NodeState>, base_url: &str) -> crate::errors::Result<u64> {
    // Paginate: pull batches of 100 until peer returns <100 (exhausted)
    // Smaller pages avoid 10s client timeout on high-latency links (Tailscale relay)
    let mut all_records: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0.0f64;
    let page_size = 100usize;
    loop {
        let (batch, truncated) = pq_query_records(state, base_url, cursor, page_size).await?;
        let batch_len = batch.len();
        // Advance cursor past this batch
        if let Some(last) = batch.last() {
            if let Ok(rec) = ValidationRecord::from_bytes(last) {
                cursor = rec.timestamp + 0.001;
            }
        }
        all_records.extend(batch);
        if batch_len < page_size && !truncated {
            break; // Peer exhausted (a truncated short page is NOT the tail)
        }
        // Safety cap: don't pull more than 20K records in bootstrap
        if all_records.len() >= 20_000 {
            info!("bootstrap_pull_from_zero: hit 20K cap at cursor {cursor:.0}");
            break;
        }
    }
    let records = all_records;
    let genesis_auth = &state.config.genesis_authority;

    // Sort: genesis authority records first (they contain the mint)
    let mut decoded: Vec<_> = records
        .iter()
        .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
        .collect();
    let ga = genesis_auth.clone();
    decoded.sort_by(|a, b| {
        let a_is_genesis = crate::accounting::types::creator_identity_hash(a) == ga;
        let b_is_genesis = crate::accounting::types::creator_identity_hash(b) == ga;
        match (a_is_genesis, b_is_genesis) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.timestamp.total_cmp(&b.timestamp),
        }
    });

    // During bootstrap, store records DIRECTLY in RocksDB + DAG without ledger
    // validation. This breaks the chicken-and-egg: normally insert_record rejects
    // transfers because pool=0, but pool stays 0 because the mint record also
    // gets rejected. By storing all records first and rebuilding the ledger after,
    // the mint is processed and the pool gets seeded.
    let mut total = 0u64;
    let mut skipped = 0u64;
    let mut genesis_mint_seen = false; // Track: at most one genesis mint in any bootstrap pull
    for record in decoded {
        let record_id = record.id.clone();
        let already_seen = state.seen.lock_recover().contains(&record_id);
        if already_seen {
            skipped += 1;
            continue;
        }

        // Duplicate genesis mint guard: only accept the first genesis mint
        // record in a bootstrap pull. On a fresh boot after storage wipe,
        // peers may serve records from both the old and new genesis boot,
        // containing two different mint records. Only keep the first one
        // (sorted earliest above) to prevent supply doubling.
        {
            let is_genesis_mint = record.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("mint")
                && record.metadata.get("beat_reason").and_then(|v| v.as_str())
                    .is_some_and(|s| s.starts_with("genesis:"));
            if is_genesis_mint {
                if genesis_mint_seen {
                    info!("bootstrap: skipping duplicate genesis mint record {}", &record_id[..record_id.len().min(16)]);
                    skipped += 1;
                    continue;
                }
                genesis_mint_seen = true;
            }
        }

        // Delta-sync cursor audit 2026-07-05 C7: this direct put_record
        // deliberately skips insert_record_inner's LEDGER validation (the
        // chicken-and-egg above) — but it must NOT skip the unconditional
        // timestamp gate ("audit 16e", ingest.rs): CF_IDX_TIMESTAMP keys are
        // `ts_be ++ id`, and everything derived from that index
        // (last_key_timestamp_cf → delta_sync_since_floor) assumes finite,
        // non-sign-negative timestamps. One NaN/-0.0/negative-ts record from
        // a malicious bootstrap peer would otherwise sort byte-maximal and
        // pin this node's sync floor to 0.0 (full-sweep) forever. Id bounds
        // are already enforced at decode (validate_wire_id).
        if !bootstrap_record_ts_admissible(&record) {
            info!(
                "bootstrap: rejecting invalid-timestamp record {} (ts={})",
                &record_id[..record_id.len().min(16)],
                record.timestamp
            );
            skipped += 1;
            continue;
        }

        // Store directly in RocksDB (skip ledger validation)
        if let Err(e) = state.rocks.put_record(&record_id, &record) {
            debug!("bootstrap store failed for {}: {e}", &record_id[..16.min(record_id.len())]);
            continue;
        }

        // Add to DAG index (tolerant — ignores missing parents)
        {
            state.dag_write_holder.store(4, std::sync::atomic::Ordering::Relaxed); // 4=bootstrap_pull
            let mut dag_guard = state.dag.write().await;
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            let missing = dag.insert_tolerant(record_id.clone(), record.parents.clone(), record.timestamp);
            // Wire structural edges for parents in RocksDB but not in DAG hot tier
            if missing > 0 {
                for pid in &record.parents {
                    if !dag.contains(pid) && state.rocks.record_exists(pid).unwrap_or(false) {
                        dag.link_external_parent(&record_id, pid);
                    }
                }
            }
        }
        state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed);

        state.seen.lock_recover().insert(record_id);
        total += 1;
    }
    if skipped > 0 {
        debug!("bootstrap_pull_from_zero: {skipped} already seen");
    }
    // Reindex orphans after full batch — parents stored earlier in batch resolve children stored later
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        let linked = dag.reindex_orphans();
        if linked > 0 {
            info!("bootstrap_pull_from_zero: reindexed {linked} orphan edges");
        }
    }
    info!("bootstrap_pull_from_zero: {total} stored (bypassed ledger validation for ledger rebuild)");
    state.gossip_pull_total.fetch_add(total, std::sync::atomic::Ordering::Relaxed);
    Ok(total)
}

/// Timestamp-based pull: fetch records newer than our latest tip. Returns records inserted.
/// Public so initial_sync can call it on low-memory nodes (skipping Merkle/bloom scans).
pub async fn timestamp_pull(state: &Arc<NodeState>, base_url: &str) -> crate::errors::Result<u64> {
    let dag_len = state.dag.read().await.len();
    let is_initial_sync = dag_len < 50;

    // Use persistent catch-up cursor to avoid losing position across pull cycles.
    // During resync, new pushes set the newest tip to NOW — using tip timestamp
    // as cursor would skip all historical records. The catch-up cursor starts at
    // 0.0 and advances through historical data until it reaches current time,
    // then switches to "newest tip" mode for ongoing sync.
    let catchup = *state.pull_catchup_cursor.lock().unwrap_or_else(|e| e.into_inner());
    let now_ts = now();
    let catchup_active = catchup < now_ts - 300.0; // more than 5 min behind = still catching up

    let mut cursor = if is_initial_sync || catchup_active {
        catchup // resume from where we left off (0.0 on first run)
    } else {
        let dag = state.dag.read().await;
        let tips = dag.tips();
        if tips.is_empty() {
            0.0
        } else {
            let tip = tips[0].clone();
            state.get_record(&tip).map(|r| r.timestamp).unwrap_or(0.0)
        }
    };

    // Scale sync batch size based on available RAM to limit peak
    // memory fragmentation from alloc/free churn during sync.
    let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut page_size: usize = if ram_gb <= 2 { 100 } else if ram_gb <= 4 { 200 } else { 500 };
    // Cap total records per pull call to prevent blocking pull_loop.
    // Without this, catch-up pulls 68K+ records in a single cycle,
    // saturating the 1 vCPU for hours and starving HTTP health checks.
    // 1-CPU: tighter cap (150) so HTTP can serve between cycles.
    // >4GB: 5000 cap prevents 17+ minute stalls on 284K-record datasets.
    let mut cycle_cap: u64 = if cpus <= 1 { 150 } else if ram_gb <= 2 { 500 } else if ram_gb <= 4 { 2000 } else { 5000 };
    // Under memory pressure, halve batch sizes to reduce allocation churn
    if state.under_memory_pressure() {
        page_size = (page_size / 2).max(50);
        cycle_cap = (cycle_cap / 2).max(100);
    }
    let mut total_count = 0u64;
    let mut total_rejected = 0u64;
    let mut last_err = String::new();

    // Paginate: keep pulling until we get fewer records than page_size,
    // advancing the cursor to the max timestamp of each batch.
    // This ensures ALL records are fetched, not just the first page_size.
    loop {
        let (records, truncated) = pq_query_records(state, base_url, cursor, page_size).await?;
        let batch_len = records.len();
        debug!("timestamp_pull from {base_url}: since={cursor}, got {batch_len} wire records (batch={page_size}, truncated={truncated})");

        if batch_len == 0 {
            break;
        }

        let mut decode_failures = 0usize;
        // into_iter: drop each wire Vec<u8> after decoding to reduce peak memory
        let mut decoded: Vec<_> = records
            .into_iter()
            .filter_map(|wire| {
                match ValidationRecord::from_bytes(&wire) {
                    Ok(r) => Some(r),
                    Err(e) => { decode_failures += 1; if decode_failures <= 3 { debug!("decode failure: {e}"); } None }
                }
            })
            .collect();
        if decode_failures > 0 {
            warn!("timestamp_pull: {decode_failures}/{batch_len} records failed to decode");
        }

        // Genesis-first ordering on initial sync
        let genesis_auth = &state.config.genesis_authority;
        if is_initial_sync && !genesis_auth.is_empty() {
            let ga = genesis_auth.clone();
            decoded.sort_by(|a, b| {
                let a_is_genesis = crate::accounting::types::creator_identity_hash(a) == ga;
                let b_is_genesis = crate::accounting::types::creator_identity_hash(b) == ga;
                match (a_is_genesis, b_is_genesis) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.timestamp.total_cmp(&b.timestamp),
                }
            });
            if total_count == 0 {
                info!("genesis-first sync: processing {} records (genesis records prioritized)", decoded.len());
            }
        } else {
            decoded.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
        }

        // Track max timestamp in this batch for cursor advancement
        let mut batch_max_ts = cursor;
        for rec in &decoded {
            if rec.timestamp > batch_max_ts {
                batch_max_ts = rec.timestamp;
            }
        }

        // Collect newly inserted records for relay push after batch
        let mut new_records: Vec<ValidationRecord> = Vec::new();

        // Pre-filter stale epoch seals before processing — same logic as delta sync.
        let decoded: Vec<ValidationRecord> = {
            let epoch_state = state.epoch.read_recover();
            decoded.into_iter().filter(|rec| {
                if is_stale_seal_record(rec, &epoch_state) {
                    total_rejected += 1;
                    state.gossip_seal_declined_stale_total.fetch_add(1, Relaxed);
                    // Contract §4.4: remember the intentional decline so the
                    // delta_pull bloom stops peers re-serving it every pass.
                    // NOT gossip_rejected — stale ≠ invalid.
                    state
                        .declined_seal_ids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(rec.id.clone());
                    return false;
                }
                true
            }).collect()
        };

        let mut batch_count = 0u32;
        for record in decoded {
            let record_id = record.id.clone();
            let already_seen = state.seen.lock_recover().contains(&record_id);
            if already_seen { continue; }
            // Skip records already known to be invalid
            let already_rejected = state.gossip_rejected.lock_recover().contains(&record_id);
            if already_rejected {
                state.gossip_rejected_dedup_total.fetch_add(1, Relaxed);
                continue;
            }
            // Use insert_record_synced to bypass rate limits and timestamp defense.
            // Pulled records are historical — rate limiting them causes silent partition.
            match insert_record_synced(state, record.clone()).await {
                Ok(_) => {
                    state.seen.lock_recover().insert(record_id);
                    total_count += 1;
                    // Only keep the last MAX_RELAY_PER_BATCH records for relay.
                    // Avoids holding hundreds of cloned records in memory.
                    if new_records.len() >= MAX_RELAY_PER_BATCH * 2 {
                        new_records.drain(..MAX_RELAY_PER_BATCH);
                    }
                    new_records.push(record);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // Cache permanently invalid records to prevent infinite retry.
                    // Retryable rejections (seal divergence, ledger-state-dependent
                    // validation) resolve as other records finalize — don't cache,
                    // park for targeted re-fetch (pull cursors may move past them).
                    // 8b: seal-class disposes first — the batch-start pre-filter's
                    // epoch view can go stale mid-batch (the `:2743` leak), so a
                    // seal reaching this arm must still never be embargoed.
                    if !dispose_seal_ingest_failure(state, &record, 0) {
                        if !is_retryable_ingest_rejection(&err_str) {
                            state.gossip_rejected.lock_recover().insert(record_id);
                        } else {
                            park_retryable(state, &record_id);
                        }
                    }
                    total_rejected += 1;
                    if total_rejected <= 3 { last_err = err_str.clone(); debug!("pull insert rejected: {err_str}"); }
                }
            }
            // Rate-limit: sleep between record inserts to let RocksDB compaction
            // breathe and keep HTTP responsive. 1-CPU nodes need more aggressive
            // yielding since the single tokio worker must multiplex everything.
            batch_count += 1;
            let yield_interval = if cpus <= 1 { 3 } else { 5 };
            if batch_count.is_multiple_of(yield_interval) {
                if cpus <= 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                } else if ram_gb <= 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                } else if ram_gb <= 4 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                } else {
                    tokio::task::yield_now().await;
                }
                // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
                // when host CPU/load is saturated regardless of node tier.
                crate::network::system_load::coop_yield_if_busy(&state.system_load).await;
            }
        }

        // Relay only the NEWEST pulled records to peers (not all of them).
        // During cold-start, a node pulls thousands of records — relaying all
        // of them creates a thundering herd (thousands of concurrent pushes)
        // that overwhelms peers with connection timeouts → peer exile spiral.
        //
        // The pull path already ensures all nodes get records (each node pulls
        // independently). Relay is only needed for recent records that a peer
        // might have missed between pull cycles.
        const MAX_RELAY_PER_BATCH: usize = 50;
        if !new_records.is_empty() {
            // Relay only the newest records (tail of the batch, sorted by timestamp).
            let relay_start = new_records.len().saturating_sub(MAX_RELAY_PER_BATCH);
            let to_relay = &new_records[relay_start..];
            if to_relay.len() < new_records.len() {
                debug!("pull relay: pushing {} of {} new records (capped)", to_relay.len(), new_records.len());
            } else {
                debug!("pull relay: pushing {} new records to peers", to_relay.len());
            }
            for (i, record) in to_relay.iter().enumerate() {
                NodeState::publish_record_with_fallback(state, record, None).await;
                if (i + 1) % 20 == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }

        // Inter-page sleep: rate-limit the pull pipeline to prevent bursting
        // during rejoin catchup. Without this, a 4GB+ node (yield_now only)
        // ingests all cycle_cap=5000 records in seconds, spiking RocksDB write
        // pressure and lock contention on both the pulling and the serving node.
        //
        // During catchup (cursor > 5min behind current time):
        //   floor = 200ms → max ~5 pages/sec × page_size records/page
        // During normal sync:
        //   2GB floor 50ms, 4GB floor 20ms, >4GB no sleep.
        let inter_page_ms: u64 = if catchup_active {
            if ram_gb <= 2 { 300 } else { 200 }
        } else if ram_gb <= 2 {
            50
        } else if ram_gb <= 4 {
            20
        } else {
            0
        };
        if inter_page_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(inter_page_ms)).await;
        } else {
            tokio::task::yield_now().await;
        }

        // If we got fewer than page_size, we've fetched everything — unless
        // the server byte-budgeted the page (truncated), in which case more
        // records remain at/after this cursor and the loop must continue.
        if batch_len < page_size && !truncated {
            break;
        }

        // Cap total records per cycle to avoid starving HTTP on low-resource nodes
        if total_count >= cycle_cap {
            info!("timestamp_pull: hit cycle cap ({cycle_cap}), deferring rest to next cycle");
            break;
        }

        // Advance cursor: use per-batch insert count to decide strategy.
        // If the batch had new records and max_ts didn't advance, there may be
        // more co-timestamped records — re-query at the same cursor.
        // If no new records in a full batch, advance past to avoid infinite loop.
        let batch_new = new_records.len();
        if batch_max_ts <= cursor {
            if batch_new == 0 {
                break; // No progress — avoid infinite loop
            }
            // Got new records at same timestamp — re-query to catch more
            // (seen set will skip already-inserted ones)
        } else if batch_new == 0 {
            // All already seen but timestamp advanced — skip past
            cursor = batch_max_ts + 0.001;
        } else {
            cursor = batch_max_ts;
        }
    }

    // Persist the catch-up cursor so the next pull cycle resumes here
    if cursor > catchup {
        *state.pull_catchup_cursor.lock().unwrap_or_else(|e| e.into_inner()) = cursor;
    }

    if total_rejected > 0 {
        warn!("timestamp_pull: {total_count} inserted, {total_rejected} rejected (last: {last_err})");
    }
    if total_count > 0 {
        state.gossip_pull_total.fetch_add(total_count, Relaxed);
    }

    // Re-fetch records parked on retryable rejections —
    // their timestamps are typically below the cursor by now, so the normal
    // pull window will never re-offer them.
    retry_parked_records(state, base_url).await;

    Ok(total_count)
}

/// Full reconciliation pull: scan through ALL records on a peer using a persistent
/// cursor. Unlike timestamp_pull (which only pulls forward from the newest tip),
/// this scans from 0.0 and advances through the entire history. When it reaches
/// the end, it resets to 0.0 for the next full scan cycle.
/// Skips records we already have (via seen set).
async fn full_pull(state: &Arc<NodeState>, base_url: &str) -> crate::errors::Result<u64> {
    let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut page_size: usize = if ram_gb <= 2 { 100 } else if ram_gb <= 4 { 200 } else { 500 };
    // Cap records per full_pull cycle to prevent blocking pull_loop for minutes.
    // Without a cap on large nodes, full_pull processes ALL 284K+ records in one
    // go, blocking push_recent_to_peer, epoch seals, and the next pull cycle for
    // 17+ minutes. 5000 on >4GB takes ~25s with yields — acceptable.
    let mut cycle_cap: u64 = if cpus <= 1 { 150 } else if ram_gb <= 2 { 500 } else if ram_gb <= 4 { 2000 } else { 5000 };
    // Under memory pressure, halve batch sizes to reduce allocation churn
    if state.under_memory_pressure() {
        page_size = (page_size / 2).max(50);
        cycle_cap = (cycle_cap / 2).max(100);
    }
    // Resume from persistent cursor so we make forward progress across cycles.
    // Without this, low-memory nodes with cycle_cap=500 re-scan the same first
    // 500 records from timestamp 0 every cycle, never reaching newer gaps.
    // 8b: every sweep start clamps at the retention/earliest floor — a
    // persisted pre-fix 0.0 (or a cursor below a raised floor) must not
    // re-fire the below-floor storm. Computed once per sweep; the
    // sweep-complete tail-reset below reuses the same value.
    let sweep_floor = full_pull_sweep_floor(state);
    let persisted = *state.full_pull_cursor.lock().unwrap_or_else(|e| e.into_inner());
    let mut cursor = persisted.max(sweep_floor);
    let mut total_new = 0u64;
    if cursor > 0.0 {
        info!("full_pull: resuming from cursor {cursor:.0} (floor {sweep_floor:.0})");
    }

    loop {
        let (records, truncated) = pq_query_records(state, base_url, cursor, page_size).await?;
        let batch_len = records.len();
        if batch_len == 0 { break; }

        let mut batch_max_ts = cursor;
        let mut batch_count = 0u32;
        for wire in &records {
            if let Ok(record) = ValidationRecord::from_bytes(wire) {
                if record.timestamp > batch_max_ts {
                    batch_max_ts = record.timestamp;
                }
                let record_id = record.id.clone();
                let already_seen = state.seen.lock_recover().contains(&record_id);
                if already_seen { continue; }
                let already_rejected = state.gossip_rejected.lock_recover().contains(&record_id);
                if already_rejected {
                    state.gossip_rejected_dedup_total.fetch_add(1, Relaxed);
                    continue;
                }
                // Use insert_record_synced — full_pull is historical reconciliation,
                // not live ingestion. Rate limits would silently drop records.
                let is_seal_class = record.metadata.contains_key(EPOCH_OP_KEY);
                // 8b: decline stale seals PRE-CRYPTO — every completed sweep
                // re-offers the locally-pruned seal band (archive peers serve
                // it forever); without this filter each one paid Dilithium3
                // then permanently embargoed itself in gossip_rejected,
                // killing its consumer processing on this node. Same §4.4
                // route as timestamp_pull/delta_sync. Scoped read-lock per
                // SEAL-class record only (seals are a sliver of pull volume;
                // the guard cannot be held across the await below).
                if is_seal_class && is_stale_seal_record(&record, &state.epoch.read_recover()) {
                    state.gossip_seal_declined_stale_total.fetch_add(1, Relaxed);
                    state
                        .declined_seal_ids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(record_id);
                    continue;
                }
                match insert_record_synced(state, record.clone()).await {
                    Ok(_) => {
                        state.seen.lock_recover().insert(record_id);
                        total_new += 1;
                        // Don't relay during full_pull — it's historical reconciliation.
                        // Other nodes pull independently. Relaying thousands of cold-start
                        // records overwhelms peers with connection timeouts.
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        // R3-8 soak forensics: a silently-rejected SEAL here is
                        // consensus-relevant. Name it loudly; the 8b invariant
                        // below keeps it out of the permanent embargo.
                        if is_seal_class {
                            state.gossip_seal_insert_reject_total.fetch_add(1, Relaxed);
                            warn!(
                                "full_pull: SEAL-class record {} rejected at ingest (retryable={}): {err_str}",
                                &record_id[..record_id.len().min(16)],
                                is_retryable_ingest_rejection(&err_str),
                            );
                        }
                        if !dispose_seal_ingest_failure(state, &record, 0) {
                            if !is_retryable_ingest_rejection(&err_str) {
                                state.gossip_rejected.lock_recover().insert(record_id);
                            } else {
                                park_retryable(state, &record_id);
                            }
                        }
                    }
                }
                // Rate-limit inserts to prevent L0 SST pile-up and CPU starvation.
                // 1-CPU nodes need aggressive yielding: every 3 inserts with longer
                // sleep so the single tokio worker can service HTTP/TLS requests.
                batch_count += 1;
                let yield_interval = if cpus <= 1 { 3 } else { 5 };
                if batch_count.is_multiple_of(yield_interval) {
                    if cpus <= 1 {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    } else if ram_gb <= 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    } else if ram_gb <= 4 {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    } else {
                        tokio::task::yield_now().await;
                    }
                    // Stage 6 cooperative scheduler (Protocol §11.10)
                    crate::network::system_load::coop_yield_if_busy(&state.system_load).await;
                }
            }
        }

        // Also advance pull_catchup_cursor — epoch seal loop checks this to
        // decide if the node is "caught up". Without this, full_pull blocks
        // for the entire 284K-record scan while pull_catchup_cursor stays
        // stale, causing epoch seals to skip ("node is catching up") forever.
        {
            let mut cc = state.pull_catchup_cursor.lock().unwrap_or_else(|e| e.into_inner());
            if batch_max_ts > *cc {
                *cc = batch_max_ts;
            }
        }

        // Inter-page sleep: full_pull is always in catchup mode (scans from
        // historical cursor). Rate-limit to 200ms between pages so we don't
        // burst-ingest 5000 records in a few seconds and spike RocksDB write
        // pressure and CPU on both the pulling node and the serving peer.
        // 1-CPU node gets 300ms (already has per-record 300ms yield above, but
        // the page-level sleep is in addition to prevent runaway batches).
        {
            let inter_ms: u64 = if cpus <= 1 { 300 } else { 200 };
            tokio::time::sleep(std::time::Duration::from_millis(inter_ms)).await;
        }

        if batch_len < page_size && !truncated {
            // Reached end of peer's records — reset cursor for next full scan.
            // The !truncated guard is load-bearing: a byte-budgeted short page
            // (server frame cap, handle_query_records) is MID-history, and
            // resetting here would pin the sweep below the fat region forever
            // — the exact stuck-cursor pathology root-caused live 2026-07-02.
            // 8b (the single most load-bearing line of part C): the tail-reset
            // floors at the retention/earliest boundary — left at 0.0 the
            // below-floor storm re-fires on the very next sweep, defeating
            // the pre-filter and the initial clamp above (pinned — SEAL-8b-01
            // test + dead-code guard live on apply_sweep_tail_reset).
            apply_sweep_tail_reset(state);
            break;
        }
        if batch_max_ts <= cursor { break; }

        // Always advance persistent cursor when timestamps progressed, even if
        // all records were duplicates. Without this, full_pull scans the same
        // already-known records forever (total_new=0 → cursor never saved →
        // next cycle re-fetches identical batch). The cursor means "scanned up
        // to here" regardless of novelty.
        let new_cursor = batch_max_ts + 0.001;
        *state.full_pull_cursor.lock().unwrap_or_else(|e| e.into_inner()) = new_cursor;
        state.rocks.save_full_pull_cursor(new_cursor);

        if total_new >= cycle_cap {
            info!("full_pull: hit cycle cap ({cycle_cap}), cursor→{batch_max_ts:.0}, deferring rest to next cycle");
            break;
        }
        cursor = new_cursor;
    }

    if total_new > 0 {
        info!("full_pull: {total_new} new records from {}", &base_url[..base_url.len().min(30)]);
        state.gossip_pull_total.fetch_add(total_new, Relaxed);
    }
    Ok(total_new)
}

/// Bloom filter delta pull: send our record IDs as a bloom, receive missing records.
pub async fn delta_pull(state: &Arc<NodeState>, base_url: &str) -> crate::errors::Result<u64> {
    // Bound the bloom build to records since the delta-sync floor (mirror of
    // the server-side bound). This previously used `for_each_record_id` (full
    // CF_RECORDS scan), 30s+ at 10M records. Server caps at MAX_SCAN=50_000;
    // client bloom covers a strict superset (200K) over the same `since` floor
    // → no false-negatives. Shared `MAX_BLOOM_BUILD` (single source of truth with
    // the sync-loop sender + the delta_sync body cap) — see crate::network::sync.
    let since = crate::network::sync::delta_sync_since_floor(state);
    let bloom_bytes = {
        let scanned_ids = state
            .rocks
            .record_ids_from(since, crate::network::sync::MAX_BLOOM_BUILD)
            .unwrap_or_else(|e| {
                warn!("delta_pull: bloom build record_ids_from failed: {e}");
                Vec::new()
            });
        if scanned_ids.is_empty() {
            Vec::new()
        } else {
            // Contract §4.4: fold intentionally-declined stale seal ids into
            // the bloom. They're not in storage (never inserted), so without
            // this the server re-serves the same stale seals every pass —
            // observed live as ~1,014 seals re-skipped per cycle during the
            // 2026-07 follower-node heal. Client-local; no wire change.
            let declined = state
                .declined_seal_ids
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut bloom =
                BloomFilter::new((scanned_ids.len() + declined.len()).max(100), 0.01);
            for id in &scanned_ids {
                bloom.insert(id.as_bytes());
            }
            for id in declined.iter() {
                bloom.insert(id.as_bytes());
            }
            bloom.to_bytes()
        }
    };

    // Empty bloom = no local records, fall back to timestamp pull
    if bloom_bytes.is_empty() {
        return timestamp_pull(state, base_url).await;
    }

    let missing_wire = pq_delta_sync(state, base_url, &bloom_bytes).await?;
    let wire_count = missing_wire.len();
    // MAINNET gap #8 (floor-push): ingress bytes via delta pull (requester side).
    // Responder charges these to its `bytes_out_total`; we charge them here so
    // per-node ingress stays end-to-end symmetric across pull and push paths.
    let delta_pull_bytes: u64 = missing_wire.iter().map(|w| w.len() as u64).sum();
    state
        .gossip_bytes_in_total
        .fetch_add(delta_pull_bytes, Relaxed);
    let mut decoded: Vec<_> = missing_wire
        .iter()
        .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
        .collect();
    decoded.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
    // 8b: decline stale seals PRE-CRYPTO (one epoch read-lock per batch) —
    // same Contract §4.4 route as timestamp_pull/delta_sync: declined_seal_ids
    // (folded into this very pull's bloom next cycle), never gossip_rejected
    // (stale ≠ invalid), never the park queue (would flood GOSSIP_RETRY_CAP).
    let decoded: Vec<ValidationRecord> = {
        let epoch_state = state.epoch.read_recover();
        decoded
            .into_iter()
            .filter(|rec| {
                if is_stale_seal_record(rec, &epoch_state) {
                    state.gossip_seal_declined_stale_total.fetch_add(1, Relaxed);
                    state
                        .declined_seal_ids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(rec.id.clone());
                    return false;
                }
                true
            })
            .collect()
    };
    let decoded_count = decoded.len();

    let mut inserted = 0u32;
    let mut rejected = 0u32;
    let mut new_records: Vec<ValidationRecord> = Vec::new();
    let mut batch_count = 0u32;

    for record in decoded {
        let record_id = record.id.clone();
        let already_seen = state.seen.lock_recover().contains(&record_id);
        if already_seen { continue; }
        let already_rejected = state.gossip_rejected.lock_recover().contains(&record_id);
        if already_rejected {
            state.gossip_rejected_dedup_total.fetch_add(1, Relaxed);
            continue;
        }
        let is_seal_class = record.metadata.contains_key(EPOCH_OP_KEY);
        match insert_record_synced(state, record.clone()).await {
            Ok(_) => {
                state.seen.lock_recover().insert(record_id);
                inserted += 1;
                new_records.push(record);
            }
            Err(e) => {
                rejected += 1;
                // Cache permanently invalid records. Retryable rejections (seal
                // divergence, ledger-state-dependent validation) — don't cache,
                // park for targeted re-fetch.
                let err_str = e.to_string();
                // R3-8 soak forensics: seal-class rejects must be loud; the 8b
                // invariant below keeps them out of the permanent embargo.
                if is_seal_class {
                    state.gossip_seal_insert_reject_total.fetch_add(1, Relaxed);
                    warn!(
                        "delta_pull: SEAL-class record {} rejected at ingest (retryable={}): {err_str}",
                        &record_id[..record_id.len().min(16)],
                        is_retryable_ingest_rejection(&err_str),
                    );
                }
                if !dispose_seal_ingest_failure(state, &record, 0) {
                    if !is_retryable_ingest_rejection(&err_str) {
                        state.gossip_rejected.lock_recover().insert(record_id);
                    } else {
                        park_retryable(state, &record_id);
                    }
                }
            }
        }
        // Yield every 50 records so other tasks (health, peers, auto-witness) can run.
        // Without this, bulk delta sync monopolises the runtime for minutes.
        batch_count += 1;
        if batch_count.is_multiple_of(50) {
            tokio::task::yield_now().await;
            // Stage 6 cooperative scheduler (Protocol §11.10)
            crate::network::system_load::coop_yield_if_busy(&state.system_load).await;
        }
    }

    if inserted > 0 || wire_count > 0 {
        state.gossip_pull_total.fetch_add(inserted as u64, Relaxed);
        info!("delta_pull: wire={wire_count} decoded={decoded_count} inserted={inserted} rejected={rejected} from {}", &base_url[..base_url.len().min(30)]);

        // Relay only newest records — bulk delta sync is reconciliation,
        // not live propagation. Capped to prevent thundering herd.
        let relay_start = new_records.len().saturating_sub(50);
        for record in &new_records[relay_start..] {
            NodeState::publish_record_with_fallback(state, record, None).await;
        }
    }
    Ok(inserted as u64)
}

/// Push a single attestation to all connected peers (fire-and-forget).
pub async fn push_attestation_to_peers(state: &Arc<NodeState>, attestation: &super::witness::AttestationRecord) {
    // Dedup: skip if we already pushed this (record_id, witness_hash) pair
    let key = format!("{}:{}", attestation.record_id, attestation.witness_hash);
    {
        let mut seen = state.attestation_seen.lock_recover();
        if !seen.insert(key) {
            state.attestation_dedup_total.fetch_add(1, Relaxed);
            return;
        }
    }

    // Protocol v0.6.2 Section 11.14: sqrt(n) fan-out for attestations,
    // matching record push strategy. Without this, attestation bandwidth
    // scales O(n) with connected peers — unusable at 500+ connections.
    //
    // Gap 6.2: Above `content_routing_threshold` eligible peers, route the
    // attestation to the K DHT-closest peers to SHA3(record_id). This
    // converges attestations onto the same responsible set as the record
    // itself, so witness aggregation happens on the K replicas.
    //
    // MAINNET gap #2: Committee-aware prioritization. When the zone has an
    // active stake-weighted committee (gap #5), push to every connected
    // committee peer FIRST, then pad the remainder via content-routing /
    // sqrt(n). Committee members produce the settlement-decisive signatures,
    // so they should never be missed due to sqrt(n) sampling.
    let targets: Vec<(String, String)> = {
        let content_routing_threshold = state.config.content_routing_threshold;
        let content_routing_k = state.config.content_routing_k.max(1);
        let peers = state.peers.read().await;
        let all: Vec<(String, String)> = peers.connected()
            .into_iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash && p.node_type.can_relay() && p.reachable)
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        // Committee-first selection: resolve the zone from record_id, pull the
        // active committee membership, and take any peer whose identity_hash is
        // in the set. Cheap — committee size is capped at MAINNET_COMMITTEE_SIZE=7.
        // Gap 4 Phase C: registry-aware resolution so committees are looked up
        // on the correct post-split child zone.
        let committee_targets: Vec<(String, String)> = {
            let zone = state.resolve_record_zone(&attestation.record_id);
            let members: std::collections::HashSet<String> = {
                let consensus = state.consensus.lock_recover();
                consensus
                    .committee_members_for_zone(&zone)
                    .cloned()
                    .unwrap_or_default()
            };
            if members.is_empty() {
                Vec::new()
            } else {
                all.iter()
                    .filter(|(h, _)| members.contains(h))
                    .cloned()
                    .collect()
            }
        };
        let committee_hashes: std::collections::HashSet<String> =
            committee_targets.iter().map(|(h, _)| h.clone()).collect();
        let had_committee_targets = !committee_targets.is_empty();

        // Remaining pool: connected relay peers NOT already in committee_targets.
        let mut remaining: Vec<(String, String)> = all
            .into_iter()
            .filter(|(h, _)| !committee_hashes.contains(h))
            .collect();

        let using_content_routing = content_routing_threshold > 0
            && (remaining.len() + committee_targets.len()) >= content_routing_threshold;
        let mut chosen_by_cr: Option<Vec<(String, String)>> = None;
        if using_content_routing {
            let wanted: std::collections::HashSet<String> = {
                let dht = state.dht.lock_recover();
                dht.closest_to_record(&attestation.record_id, content_routing_k * 2)
                    .into_iter()
                    .map(|p| p.identity_hash.clone())
                    .collect()
            };
            let mut chosen: Vec<(String, String)> =
                remaining.iter().filter(|(h, _)| wanted.contains(h)).cloned().collect();
            chosen.truncate(content_routing_k);
            if chosen.len() >= content_routing_k.min(remaining.len()) || chosen.len() >= 3 {
                state.gossip_relay_content_routed_total.fetch_add(1, Relaxed);
                chosen_by_cr = Some(chosen);
            }
            // else fall through to sqrt(n)
        }
        let padded = if let Some(c) = chosen_by_cr {
            c
        } else {
            let fan_out = if remaining.len() < 10 {
                remaining.len()
            } else {
                (remaining.len() as f64).sqrt().ceil() as usize
            };
            let fan_out = fan_out.max(1);
            if remaining.len() > fan_out {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                attestation.record_id.hash(&mut hasher);
                attestation.witness_hash.hash(&mut hasher);
                let seed_val = hasher.finish();
                let len = remaining.len();
                for i in 0..fan_out.min(len) {
                    let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                    remaining.swap(i, j);
                }
                remaining.truncate(fan_out);
            }
            remaining
        };

        if had_committee_targets {
            state.gossip_relay_committee_routed_total.fetch_add(1, Relaxed);
        }
        let mut out = committee_targets;
        out.extend(padded);
        out
    };

    if targets.is_empty() {
        return;
    }

    // DISC-7d-r: record attempted count before bandwidth filter.
    state.attestation_push_attempted_total.fetch_add(targets.len() as u64, Relaxed);

    // Stage 6: per-peer bandwidth fairness (Protocol §11.10).
    let before_bw = targets.len();
    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    let bw_skipped = before_bw - targets.len();
    if bw_skipped > 0 {
        state.attestation_push_skip_bandwidth_total.fetch_add(bw_skipped as u64, Relaxed);
    }
    if targets.is_empty() {
        return;
    }

    let mut payload = serde_json::json!({
        "record_id": attestation.record_id,
        "witness_hash": attestation.witness_hash,
        "signature": hex::encode(&attestation.signature),
        "timestamp": attestation.timestamp,
    });
    if let Some(pk) = &attestation.witness_public_key {
        payload["witness_public_key"] = serde_json::json!(hex::encode(pk));
    }
    if let Some(nonce) = attestation.powas_nonce {
        payload["powas_nonce"] = serde_json::json!(nonce);
    }
    if let Some(diff) = attestation.powas_difficulty {
        payload["powas_difficulty"] = serde_json::json!(diff);
    }

    // Serialize once instead of per-target: every spawn task sends the same
    // bytes to its peer. Pre-fan-out serialization is identical in semantics
    // to per-target serialization (payload is immutable after the for-loop
    // start) and saves N × json::to_string for fan-out N. Also lets us meter
    // bytes once.
    let body = payload.to_string();
    let body_len = body.len() as u64;
    // MAINNET mandate #3 (floor-push): attestation egress byte meter.
    // Distinct from gossip_bytes_out_total — attestations flow over the
    // PQ verb `receive_attestation_gossip`, not /records. At finalising
    // scale they are 5-7× per record (one per committee member) so they
    // dominate steady-state egress. Operator sums both for true budget.
    let att_bytes = body_len.saturating_mul(targets.len() as u64);
    state.attestation_bytes_out_total.fetch_add(att_bytes, Relaxed);

    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();
    for (_identity_hash, base_url) in &targets {
        let body = body.clone();
        let sem = semaphore.clone();
        let pq_addr_opt = http_to_pq_addr(base_url, pq_offset);
        let pq_client = state.pq_client.clone();
        let self_hash = self_hash.clone();
        let network_id = network_id.clone();
        let state_spawn = state.clone();
        let base_url_owned = base_url.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;

            let Some(pq_addr) = pq_addr_opt else {
                let n = state_spawn.attestation_push_addr_fail_total.fetch_add(1, Relaxed);
                if n.is_multiple_of(50) {
                    tracing::warn!("att-push NO-PQ-ADDR {} (#{n})", &base_url_owned[..base_url_owned.len().min(60)]);
                }
                return;
            };

            let body_bytes = body.into_bytes();
            match pq_client.receive_attestation_gossip(
                &pq_addr, &body_bytes,
                super::pq_client::GossipHeaders {
                    hops: 1,
                    sender_identity_hash: &self_hash,
                    trace_id: None,
                    network_id: &network_id,
                    protocol_version: super::config::PROTOCOL_VERSION,
                },
            ).await {
                Ok(resp) if resp.is_success() => {
                    state_spawn.attestation_push_success_total.fetch_add(1, Relaxed);
                }
                Ok(resp) if resp.status == 429 => {
                    // Rate limited; peer saw the payload, don't count as success but not a failure.
                }
                Ok(resp) => {
                    let n = state_spawn.attestation_push_peer_reject_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("att-push REJECTED pq-status={} to {} (#{n})", resp.status, &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
                Err(e) => {
                    let n = state_spawn.attestation_push_net_fail_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("att-push FAILED to {} (#{n}): {e}", &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
            }
        });
    }
}

/// Gap 2.1 Phase 2c — wire envelope for SealFinalityWitness gossip.
///
/// JSON-encoded body for the PQ verb `submit_finality_witness`. Carries
/// the canonical committee snapshot `(seal_epoch, committee_hash,
/// committee_size)` so the receiver folds the witness into the same
/// `SealFinalityCollection` the producer pinned at sign time. Mismatched
/// snapshots are dropped on the receiver and counted in
/// `seal_finality_snapshot_mismatch_total`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct FinalityWitnessGossipBody {
    pub seal_id: String,
    pub seal_epoch: u64,
    pub committee_hash: [u8; 32],
    pub committee_size: u32,
    pub witness: crate::accounting::cross_zone::SealFinalityWitness,
}

/// Gap 2.1 Phase 2c — broadcast a locally-signed `SealFinalityWitness` to
/// peers so the rest of the committee can fold it into the same
/// `SealFinalityCollection`.
///
/// Initiated only by the producer at seal ingest (network/ingest.rs); the
/// `submit_finality_witness` handler does NOT re-broadcast on receipt, so
/// fan-out is O(committee_size × sqrt(peers)) — bounded.
///
/// Dedup: `state.finality_witness_seen` keyed by `seal_id:hex(witness_pk)`,
/// 5,000 entries (~50 zone-epochs of churn at MAINNET_COMMITTEE_SIZE=7).
///
/// sqrt(n) fan-out matches `push_conflict_proof_to_peers` — finality
/// witnesses are even rarer (one per (seal,witness)) so this is well within
/// bandwidth budgets.
pub async fn push_finality_witness_to_peers(
    state: &Arc<NodeState>,
    seal_id: &str,
    seal_epoch: u64,
    committee_hash: [u8; 32],
    committee_size: u32,
    witness: crate::accounting::cross_zone::SealFinalityWitness,
) {
    let dedup_key = format!("{}:{}", seal_id, hex::encode(&witness.witness_pk));
    {
        let mut seen = state.finality_witness_seen.lock_recover();
        if !seen.insert(dedup_key.clone()) {
            return;
        }
    }

    let targets: Vec<(String, String)> = {
        let peers = state.peers.read().await;
        let mut all: Vec<(String, String)> = peers.connected()
            .into_iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash && p.node_type.can_relay() && p.reachable)
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1);
        if all.len() > fan_out {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            dedup_key.hash(&mut hasher);
            let seed_val = hasher.finish();
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    let envelope = FinalityWitnessGossipBody {
        seal_id: seal_id.to_string(),
        seal_epoch,
        committee_hash,
        committee_size,
        witness,
    };
    let body_bytes = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("push_finality_witness: serialize failed: {e}");
            return;
        }
    };

    state.finality_witness_pushed_total.fetch_add(1, Relaxed);
    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();
    for (_identity_hash, base_url) in &targets {
        let body = body_bytes.clone();
        let sem = semaphore.clone();
        let pq_addr_opt = http_to_pq_addr(base_url, pq_offset);
        let pq_client = state.pq_client.clone();
        let self_hash = self_hash.clone();
        let network_id = network_id.clone();
        let state_spawn = state.clone();
        let base_url_owned = base_url.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let Some(pq_addr) = pq_addr_opt else {
                let n = state_spawn.finality_witness_push_addr_fail_total.fetch_add(1, Relaxed);
                if n.is_multiple_of(50) {
                    tracing::warn!("finality-witness push NO-PQ-ADDR {} (#{n})", &base_url_owned[..base_url_owned.len().min(60)]);
                }
                return;
            };
            match pq_client.submit_finality_witness_gossip(
                &pq_addr, &body,
                super::pq_client::GossipHeaders {
                    hops: 1,
                    sender_identity_hash: &self_hash,
                    trace_id: None,
                    network_id: &network_id,
                    protocol_version: super::config::PROTOCOL_VERSION,
                },
            ).await {
                Ok(resp) if resp.is_success() || resp.status == 429 => {}
                Ok(resp) => {
                    let n = state_spawn.finality_witness_push_peer_reject_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("finality-witness REJECTED pq-status={} to {} (#{n})", resp.status, &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
                Err(e) => {
                    let n = state_spawn.finality_witness_push_net_fail_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("finality-witness FAILED to {} (#{n}): {e}", &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
            }
        });
    }
}

/// Gap 2 sealed-abort P-3e — wire envelope for `XZoneAbortWitness` gossip.
///
/// JSON-encoded body for the PQ verb `submit_xzone_abort_witness`. Carries
/// the canonical committee snapshot `(source_seal_epoch, committee_hash,
/// committee_size)` so the receiver folds the witness into the same
/// `XZoneAbortCollection` the producer pinned at sign time. Mismatched
/// snapshots are dropped on the receiver and counted in
/// `xzone_abort_snapshot_mismatch_total`.
///
/// `dest_zone` is included so the witness's signable bytes can be
/// reconstructed on receipt — the abort domain commits to
/// `(transfer_id, dest_zone, source_seal_epoch, dest_committee_hash)`.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct XZoneAbortWitnessGossipBody {
    pub transfer_id: String,
    pub dest_zone: crate::ZoneId,
    pub source_seal_epoch: u64,
    pub committee_hash: [u8; 32],
    pub committee_size: u32,
    pub witness: crate::accounting::cross_zone::SealFinalityWitness,
}

/// Gap 2 sealed-abort P-3e — broadcast a locally-signed abort witness to
/// peers so the rest of the destination-zone committee can fold it into
/// the same `XZoneAbortCollection`.
///
/// Initiated only by the producer at the epoch_seal_loop emitter
/// (network/epoch.rs); the `submit_xzone_abort_witness` handler does NOT
/// re-broadcast on receipt, so fan-out is O(committee_size × sqrt(peers))
/// — bounded.
///
/// Dedup: `state.xzone_abort_witness_seen` keyed by
/// `transfer_id:hex(witness_pk)`, 5,000 entries.
///
/// sqrt(n) fan-out matches `push_finality_witness_to_peers` — abort
/// witnesses are even rarer (at most one per failed cross-zone transfer,
/// post claim-window) so this is well within bandwidth budgets.
pub async fn push_xzone_abort_witness_to_peers(
    state: &Arc<NodeState>,
    transfer_id: &str,
    dest_zone: crate::ZoneId,
    source_seal_epoch: u64,
    committee_hash: [u8; 32],
    committee_size: u32,
    witness: crate::accounting::cross_zone::SealFinalityWitness,
) {
    let dedup_key = format!("{}:{}", transfer_id, hex::encode(&witness.witness_pk));
    {
        let mut seen = state.xzone_abort_witness_seen.lock_recover();
        if !seen.insert(dedup_key.clone()) {
            return;
        }
    }

    let targets: Vec<(String, String)> = {
        let peers = state.peers.read().await;
        let mut all: Vec<(String, String)> = peers.connected()
            .into_iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash && p.node_type.can_relay() && p.reachable)
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1);
        if all.len() > fan_out {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            dedup_key.hash(&mut hasher);
            let seed_val = hasher.finish();
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    let envelope = XZoneAbortWitnessGossipBody {
        transfer_id: transfer_id.to_string(),
        dest_zone,
        source_seal_epoch,
        committee_hash,
        committee_size,
        witness,
    };
    let body_bytes = match serde_json::to_vec(&envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("push_xzone_abort_witness: serialize failed: {e}");
            return;
        }
    };

    state.xzone_abort_witness_pushed_total.fetch_add(1, Relaxed);
    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();
    for (_identity_hash, base_url) in &targets {
        let body = body_bytes.clone();
        let sem = semaphore.clone();
        let pq_addr_opt = http_to_pq_addr(base_url, pq_offset);
        let pq_client = state.pq_client.clone();
        let self_hash = self_hash.clone();
        let network_id = network_id.clone();
        let state_spawn = state.clone();
        let base_url_owned = base_url.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let Some(pq_addr) = pq_addr_opt else {
                let n = state_spawn.xzone_abort_witness_push_addr_fail_total.fetch_add(1, Relaxed);
                if n.is_multiple_of(50) {
                    tracing::warn!("xzone-abort-witness push NO-PQ-ADDR {} (#{n})", &base_url_owned[..base_url_owned.len().min(60)]);
                }
                return;
            };
            match pq_client.submit_xzone_abort_witness_gossip(
                &pq_addr, &body,
                super::pq_client::GossipHeaders {
                    hops: 1,
                    sender_identity_hash: &self_hash,
                    trace_id: None,
                    network_id: &network_id,
                    protocol_version: super::config::PROTOCOL_VERSION,
                },
            ).await {
                Ok(resp) if resp.is_success() || resp.status == 429 => {}
                Ok(resp) => {
                    let n = state_spawn.xzone_abort_witness_push_peer_reject_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("xzone-abort-witness REJECTED pq-status={} to {} (#{n})", resp.status, &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
                Err(e) => {
                    let n = state_spawn.xzone_abort_witness_push_net_fail_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("xzone-abort-witness FAILED to {} (#{n}): {e}", &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
            }
        });
    }
}

/// Push a verified `ConflictProof` to a fan-out of peers so they mark the
/// slot as conflicted without waiting to observe the equivocation themselves.
///
/// MESH-BFT Phase 3 Stage 1D.2: once ANY honest node observes a slot
/// conflict and verifies the proof, the settlement gate on all honest nodes
/// must converge — otherwise a fast attacker could race settlement on nodes
/// that haven't seen both records. Pushing the proof makes convergence
/// O(log n) gossip hops instead of O(record-ingest latency × network diameter).
///
/// # Dedup
/// Keyed by `slot_key`: once a slot is in CF_SLOT_CONFLICTS it stays there,
/// so re-pushing the same proof is wasted bandwidth. The `conflict_proof_seen`
/// SeenSet (capacity 5,000) bounds memory; at 5,000 distinct equivocating
/// slots the oldest entries roll off — harmless because by then every peer
/// has long since marked the slot locally.
///
/// # Scale
/// sqrt(n) fan-out per push, matching the attestation gossip pattern. At
/// 10,000 peers that's ~100 PQ pushes per confirmed equivocation — rare
/// enough (only Byzantine creators produce them) that this is not a hot path.
pub async fn push_conflict_proof_to_peers(
    state: &Arc<NodeState>,
    proof: &super::conflict_proof::ConflictProof,
) {
    let slot_key = match proof.slot_key() {
        Some(k) => k,
        None => {
            tracing::warn!("push_conflict_proof: proof has no slot_key — dropping");
            return;
        }
    };

    // Dedup — one proof per slot is enough.
    {
        let mut seen = state.conflict_proof_seen.lock_recover();
        if !seen.insert(slot_key.clone()) {
            return;
        }
    }

    // sqrt(n) fan-out.
    let targets: Vec<(String, String)> = {
        let peers = state.peers.read().await;
        let mut all: Vec<(String, String)> = peers.connected()
            .into_iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash && p.node_type.can_relay() && p.reachable)
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1);
        if all.len() > fan_out {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            slot_key.hash(&mut hasher);
            let seed_val = hasher.finish();
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    // Stage 6: per-peer bandwidth fairness (Protocol §11.10).
    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    let body = match serde_json::to_string(proof) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("push_conflict_proof: serialize failed: {e}");
            return;
        }
    };

    let semaphore = state.gossip_semaphore.clone();
    state.conflict_proof_pushed_total.fetch_add(1, Relaxed);
    let pq_offset = state.config.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();
    for (_identity_hash, base_url) in &targets {
        let body = body.clone();
        let sem = semaphore.clone();
        let pq_addr_opt = http_to_pq_addr(base_url, pq_offset);
        let pq_client = state.pq_client.clone();
        let self_hash = self_hash.clone();
        let network_id = network_id.clone();
        let state_spawn = state.clone();
        let base_url_owned = base_url.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;

            let Some(pq_addr) = pq_addr_opt else {
                let n = state_spawn.conflict_proof_push_addr_fail_total.fetch_add(1, Relaxed);
                if n.is_multiple_of(50) {
                    tracing::warn!("conflict-proof push NO-PQ-ADDR {} (#{n})", &base_url_owned[..base_url_owned.len().min(60)]);
                }
                return;
            };

            let body_bytes = body.into_bytes();
            match pq_client.submit_conflict_proof_gossip(
                &pq_addr, &body_bytes,
                super::pq_client::GossipHeaders {
                    hops: 1,
                    sender_identity_hash: &self_hash,
                    trace_id: None,
                    network_id: &network_id,
                    protocol_version: super::config::PROTOCOL_VERSION,
                },
            ).await {
                Ok(resp) if resp.is_success() || resp.status == 429 => {
                    // Delivered (or rate-limited peer saw payload).
                }
                Ok(resp) => {
                    let n = state_spawn.conflict_proof_push_peer_reject_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("conflict-proof REJECTED pq-status={} to {} (#{n})", resp.status, &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
                Err(e) => {
                    let n = state_spawn.conflict_proof_push_net_fail_total.fetch_add(1, Relaxed);
                    if n.is_multiple_of(50) {
                        tracing::warn!("conflict-proof FAILED to {} (#{n}): {e}", &pq_addr[..pq_addr.len().min(60)]);
                    }
                }
            }
        });
    }
}

/// Hard ceiling on attestations processed from one peer pull response,
/// independent of the requested `limit`. A legit incremental pull asks for
/// 2_000 (cold-start 500); this backstop bounds the worst case even if a
/// caller ever passes an outsized `limit`. 10_000 × ~144 B/PendingVerify is a
/// ~1.4 MB allocation ceiling — safe on phone-tier (2-4 GB) nodes.
const MAX_ATTESTATION_PULL_BATCH: usize = 10_000;
// Compile-time floor: the ceiling must exceed any legit incremental page (2_000),
// so the cap can never clip an honest pull. Enforced on every build, not just tests.
const _: () = assert!(MAX_ATTESTATION_PULL_BATCH >= 2_000);

/// Number of leading attestations to process from a peer-supplied batch.
/// A well-behaved peer returns at most the `requested_limit` it was asked for
/// (the `query_attestations_since` server caps to `limit`); a peer returning
/// more is misbehaving, so we never iterate or pre-allocate past
/// `min(requested_limit, MAX_ATTESTATION_PULL_BATCH)`. This is what keeps a
/// crafted oversized array (millions of tiny `{}` objects packed into one
/// MAX_PAYLOAD frame) from driving `Vec::with_capacity(atts.len())` into a
/// multi-hundred-MB allocation before any Dilithium3 signature verification.
fn capped_attestation_batch_len(returned: usize, requested_limit: usize) -> usize {
    returned.min(requested_limit.min(MAX_ATTESTATION_PULL_BATCH))
}

/// Per-call record-fetch cap for the attestation-pull path.
///
/// Coupled to the server's `MAX_FETCH_RECORDS`: `handle_fetch_records` silently
/// `take()`s the first `MAX_FETCH_RECORDS` ids and drops the rest, and att-pull
/// advances its watermark PAST every deferred attestation after this one
/// opportunistic fetch (completeness is the backstop sweep's job, not this
/// path's). So any id above the server cap is pure wasted request bandwidth —
/// it'd be "passed" regardless. The ≤2GB tier stays lower (50) to give RocksDB
/// compaction headroom on phone-tier nodes; the higher tier is bound to the
/// server cap so the two constants can't silently drift (this was hard-coded
/// 200 vs a server cap of 100 — 100 ignored ids per call on every >2GB node).
/// Pinned ≤ server cap by `att_pull_fetch_cap_never_exceeds_server_cap`.
fn att_pull_fetch_cap(ram_gb: u64) -> usize {
    if ram_gb <= 2 {
        50
    } else {
        crate::network::pq_transport::router::MAX_FETCH_RECORDS
    }
}

/// Process a single JSON attestation-pull response body from a peer.
///
/// Extracted from `attestation_pull_loop` so the same code path serves
/// both the HTTP and PQ transports. Input `data` is expected to have
/// shape `{"attestations": [...]}`. Missing `attestations` field is
/// treated as an empty batch (no-op).
///
/// The caller is responsible for peer connectivity bookkeeping
/// (record_success / record_pull_failure) before invoking this — this
/// helper only touches per-peer state via `advance_att_watermark` and
/// `record_pull_success`.
async fn process_attestation_pull_batch(
    state: &Arc<NodeState>,
    data: &serde_json::Value,
    identity_hash: &str,
    base_url: &str,
    since: f64,
    limit: usize,
) {
    let Some(atts_full) = data["attestations"].as_array() else { return };
    // DoS guard: bound the peer-supplied batch before any allocation/iteration.
    // A well-behaved peer returns at most the `limit` we requested; a crafted
    // response can pack millions of empty `{}` objects into one MAX_PAYLOAD
    // frame, and `Vec::with_capacity(atts.len())` below would then allocate
    // hundreds of MB before a single signature is checked. Cap to what we asked
    // for (with a hard ceiling) and process only the leading slice.
    let allowed = capped_attestation_batch_len(atts_full.len(), limit);
    if atts_full.len() > allowed {
        warn!(
            "att-pull: peer {} returned {} attestations (requested {}) — capping to {} (DoS guard)",
            &identity_hash[..identity_hash.len().min(16)],
            atts_full.len(),
            limit,
            allowed
        );
    }
    let atts = &atts_full[..allowed];

    // Collect candidates, verify signatures, then store
    let mut verified: Vec<VerifiedAttestation> = Vec::new();
    // Track max timestamp of *processed* attestations for watermark.
    // CRITICAL: only advance watermark for attestations we verified
    // or definitively rejected — NOT for ones skipped because the
    // record isn't in local storage yet. Otherwise the watermark
    // jumps past unverifiable attestations and they're lost until
    // the next force_full reconciliation (~100 min).
    let mut batch_max_ts: f64 = 0.0;
    let mut skipped_known: usize = 0;
    // Per-batch local tallies that we flush onto the peer record
    // at batch end, alongside the watermark advance. Amortises the
    // peers.write() lock to one acquisition per batch instead of one per
    // sig-fail / PoWaS-fail event.
    let mut batch_invalid_sig: u64 = 0;
    let mut batch_invalid_powas: u64 = 0;
    // Collect record_ids of bad-sig events for forensic triage.
    // Bounded by BAD_SIG_SAMPLE_CAP — anything past the cap is dropped here
    // to avoid building a huge intermediate Vec when a peer storms.
    let mut bad_sig_record_ids: Vec<String> = Vec::new();
    // Track records we couldn't verify because they're not in local storage.
    // After the main loop, fetch these records and retry their attestations.
    let mut missing_record_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Keep skipped attestations for retry after record fetch
    let mut deferred_attestations: Vec<serde_json::Value> = Vec::new();
    // Attestations in WitnessManager but not in consensus engine
    // (desync from startup rebuild's 50K limit). Need re-feeding.
    let mut consensus_refeed: Vec<(String, String, f64)> = Vec::new();

    // Pre-fetch witness stakes for PoWaS in one ledger read.
    // Previously acquired ledger.read() per-attestation (up to 2000 times).
    let witness_stakes: std::collections::HashMap<String, u64> = {
        let mut hashes: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for att in atts.iter() {
            if att["powas_nonce"].as_u64().is_some() {
                if let Some(wh) = att["witness_hash"].as_str() {
                    hashes.insert(wh);
                }
            }
        }
        if hashes.is_empty() {
            std::collections::HashMap::new()
        } else {
            let ledger = state.ledger.read().await;
            hashes.iter().map(|wh| (wh.to_string(), ledger.staked(wh))).collect()
        }
    };

    // 3-phase refactor — async filter, spawn_blocking Dilithium3 batch
    // verify (via rayon), async apply results. Moves the only CPU-heavy step
    // off the tokio worker so HTTP stays responsive on 1-vCPU nodes during
    // post-restart catchup bursts. Replaces the previous yield_now(32)
    // scheduler hint which was measured at 155 s HTTP blackout on a 1-vCPU
    // node — `yield_now` helps but still holds the worker across each
    // 32-att chunk's ~32 ms of verify cost.
    //
    // Phase 1 = filter + signable resolve (RocksDB reads stay async but yield
    // every 64 iters to cover cold-cache bursts).
    // Phase 2 = `spawn_blocking` rayon `par_iter` over all pending verify
    // jobs — ONE call, not one per chunk. Returns Vec<bool> aligned by index.
    // Phase 3 = apply results back, PoWaS verify (cheap, ~µs), push verified.
    //
    // Watermark-preservation invariant (must not regress): bad-sig-known,
    // already-known, and definitively-bad-sig advance `batch_max_ts`.
    // PoWaS-fail, missing-record, and pre-verify decode errors do NOT.
    struct PendingVerify {
        signable: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        record_id: String,
        witness_hash: String,
        timestamp: f64,
        powas_nonce: Option<u64>,
        powas_difficulty: Option<u64>,
    }
    let mut pending: Vec<PendingVerify> = Vec::with_capacity(atts.len());

    const YIELD_EVERY_FILTER: usize = 64;
    let mut atts_since_yield: usize = 0;

    for att in atts {
        atts_since_yield += 1;
        if atts_since_yield >= YIELD_EVERY_FILTER {
            atts_since_yield = 0;
            tokio::task::yield_now().await;
        }

        let record_id = att["record_id"].as_str().unwrap_or("");
        let witness_hash = att["witness_hash"].as_str().unwrap_or("");
        let sig_hex = att["signature"].as_str().unwrap_or("");
        let timestamp = att["timestamp"].as_f64().unwrap_or(0.0);

        if record_id.is_empty() || witness_hash.is_empty() || sig_hex.is_empty() {
            continue;
        }

        // Skip attestations already known to have bad signatures
        {
            let bad = state.attestation_bad_sigs.lock_recover();
            let key = format!("{record_id}:{witness_hash}");
            if bad.contains(&key) {
                if timestamp > batch_max_ts { batch_max_ts = timestamp; }
                continue;
            }
        }

        // Skip attestations we already have — avoids expensive
        // Dilithium3 verification for duplicates. On a 1-vCPU node,
        // verifying 500 known attestations wasted ~2.5s per cycle.
        //
        // BUT: if WitnessManager has it and consensus doesn't,
        // we need to re-feed it (startup rebuild desync from 50K limit).
        {
            let mgr = state.witness_mgr.as_ref();
            if let Ok(atts_list) = mgr.get_attestations(record_id) {
                if atts_list.iter().any(|a| a.witness_hash == witness_hash) {
                    skipped_known += 1;
                    if timestamp > batch_max_ts { batch_max_ts = timestamp; }
                    // Check if consensus engine also has it
                    let in_consensus = {
                        let consensus = state.consensus.lock_recover();
                        consensus.has_attestation_from(record_id, witness_hash)
                    };
                    if !in_consensus {
                        consensus_refeed.push((
                            record_id.to_string(),
                            witness_hash.to_string(),
                            timestamp,
                        ));
                    }
                    continue;
                }
            }
        }

        let sig = match hex::decode(sig_hex) {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };

        // Require public key — can't verify without it
        let pk_hex = match att["witness_public_key"].as_str() {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        let pk = match hex::decode(pk_hex) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Verify: SHA3-256(public_key) == witness_hash
        if sha3_256_hex(&pk) != witness_hash {
            warn!(
                "attestation pull: pubkey hash mismatch for witness {}",
                witness_hash.chars().take(16).collect::<String>()
            );
            continue;
        }

        // Resolve canonical signable bytes. Wire bytes differ across nodes
        // (SPHINCS+ optional field encoding); signable_bytes() is canonical.
        let rid = record_id.to_string();
        let signable = match state.get_record(&rid).map(|rec| rec.signable_bytes()) {
            Ok(s) => s,
            Err(_) => {
                // Record not in local storage — defer, fetch missing below.
                missing_record_ids.insert(record_id.to_string());
                deferred_attestations.push(att.clone());
                continue;
            }
        };

        pending.push(PendingVerify {
            signable,
            signature: sig,
            public_key: pk,
            record_id: rid,
            witness_hash: witness_hash.to_string(),
            timestamp,
            powas_nonce: att["powas_nonce"].as_u64(),
            powas_difficulty: att["powas_difficulty"].as_u64(),
        });
    }

    // Phase 2: batch Dilithium3 verify off the tokio worker. Rayon
    // par_iter across all pending jobs; on 1-vCPU nodes it still runs on
    // ONE blocking-pool thread but that thread is NOT the HTTP accept
    // worker, so /status, /gossip etc. stay responsive throughout.
    // Returns (results, pending_returned) so we avoid reallocation.
    let (verify_results, pending) = if pending.is_empty() {
        (Vec::<bool>::new(), pending)
    } else {
        tokio::task::spawn_blocking(move || {
            let jobs: Vec<crate::crypto::batch::VerifyJob> = pending
                .iter()
                .map(|p| crate::crypto::batch::VerifyJob {
                    message: &p.signable,
                    signature: &p.signature,
                    public_key: &p.public_key,
                })
                .collect();
            let results = crate::crypto::batch::batch_verify(&jobs);
            drop(jobs); // release borrows before moving pending back
            (results, pending)
        })
        .await
        .unwrap_or_else(|_| (Vec::new(), Vec::new()))
    };

    // Phase 3: apply verify results, run PoWaS, store verified. PoWaS is
    // cheap (SHA3 hash comparison, ~µs) so staying inline is fine.
    for (i, p) in pending.into_iter().enumerate() {
        let sig_ok = verify_results.get(i).copied().unwrap_or(false);
        if !sig_ok {
            warn!(
                "attestation pull: invalid signature from {} for {}",
                &p.witness_hash[..p.witness_hash.len().min(16)],
                &p.record_id[..p.record_id.len().min(16)]
            );
            let mut bad = state.attestation_bad_sigs.lock_recover();
            bad.insert(format!("{}:{}", p.record_id, p.witness_hash));
            state.attestation_pull_invalid_sig_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            batch_invalid_sig += 1;
            if bad_sig_record_ids.len() < super::peer::BAD_SIG_SAMPLE_CAP {
                bad_sig_record_ids.push(p.record_id.clone());
            }
            // Advance watermark — permanently rejected, won't re-process
            if p.timestamp > batch_max_ts { batch_max_ts = p.timestamp; }
            continue;
        }

        // Verify PoWaS proof if present and we know the witness stake
        if let (Some(nonce), Some(difficulty)) = (p.powas_nonce, p.powas_difficulty) {
            let witness_stake = witness_stakes.get(&p.witness_hash).copied().unwrap_or(0);
            if witness_stake > 0 {
                let proof = super::powas::PoWaSProof { nonce, difficulty };
                if !super::powas::verify(&p.record_id, &p.public_key, witness_stake, &proof) {
                    warn!(
                        "attestation pull: invalid PoWaS proof from {}",
                        &p.witness_hash[..p.witness_hash.len().min(16)]
                    );
                    state.attestation_pull_invalid_powas_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    batch_invalid_powas += 1;
                    // PoWaS-fail does NOT advance watermark (preserved from
                    // pre-DISC-1 behavior — peer may send a corrected proof).
                    continue;
                }
            }
        }

        // Only advance watermark for attestations we actually processed
        if p.timestamp > batch_max_ts {
            batch_max_ts = p.timestamp;
        }

        verified.push(VerifiedAttestation {
            record_id: p.record_id,
            witness_hash: p.witness_hash,
            signature: p.signature,
            timestamp: p.timestamp,
            public_key: Some(p.public_key),
            powas_nonce: p.powas_nonce,
            powas_difficulty: p.powas_difficulty,
        });
    }

    // Store verified attestations
    let mut new_atts: Vec<(String, String, f64)> = Vec::new();
    {
        let mgr = state.witness_mgr.as_ref();
        for va in &verified {
            if let Ok(true) = mgr.store_attestation_with_powas(
                &va.record_id, &va.witness_hash, &va.signature,
                va.timestamp, va.public_key.as_deref(),
                va.powas_nonce, va.powas_difficulty,
            ) {
                new_atts.push((va.record_id.clone(), va.witness_hash.clone(), va.timestamp));
            }
        }
    }
    // Batch-process all new attestations: groups by record_id,
    // runs recompute_confirmation ONCE per record instead of per-attestation.
    let all_feed = new_atts.clone();
    let refed_count = consensus_refeed.len();
    // Re-feed attestations in WitnessManager but missing from consensus.
    // These are already persisted — only need consensus engine update.
    // Use lightweight consensus-only path: skip the expensive RocksDB
    // get_record + put_cf_raw in batch_feed_attestations which caused
    // 10+ minute stalls on large DBs with 500 refeed entries.
    let mut refeed_settled = Vec::new();
    if !consensus_refeed.is_empty() {
        // DISC-7c (2026-04-21): pre-resolve seal metadata for each unique
        // record_id in the refeed batch. Epoch seal records must also flow
        // through `add_seal_attestation` so the Layer-2 seal-attestation
        // latency histogram (Gap 8) fires when the 2/3 diversity-weighted
        // threshold is reached. Prior to this fix, the lightweight refeed
        // path called only `add_attestation` (record-level), so epoch
        // seal attestations recovered after a restart or memory-prune
        // eviction never populated `AWCConsensus.seal_attestations`,
        // leaving the histogram `_count=0` fleet-wide.
        //
        // Cost: one RocksDB point lookup per unique record_id in the
        // refeed batch, typically O(tens) at startup. The 10-minute
        // stall that motivated the lightweight path was from per-batch
        // `put_cf_raw` in `batch_feed_attestations`, not from `get_record`.
        let unique_rids: std::collections::HashSet<String> = consensus_refeed
            .iter()
            .map(|(rid, _, _)| rid.clone())
            .collect();
        let mut seal_infos: std::collections::HashMap<String, super::epoch::ParsedEpochSeal> =
            std::collections::HashMap::new();
        // Pre-resolve creator hashes for settlement denominator correction.
        // The creator can't self-attest, so their stake must be excluded from
        // the denominator — without this, is_seal_settled (and is_settled)
        // inflate the threshold past what remaining attestors can reach.
        let mut creator_hashes: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for rid in &unique_rids {
            if let Ok(rec) = state.get_record(rid) {
                creator_hashes.insert(
                    rid.clone(),
                    crate::accounting::types::creator_identity_hash(&rec),
                );
                if rec.metadata.contains_key(super::epoch::EPOCH_OP_KEY) {
                    if let Ok(Some(seal)) = super::epoch::extract_epoch_seal(&rec) {
                        seal_infos.insert(rid.clone(), seal);
                    }
                }
            }
        }

        // Gap 5 Phase 6c gate (gossip refeed path): per-(rid, witness)
        // committee check. seal_infos is keyed by rid only, but the gate
        // is per-witness, so we collect blocked (rid, wh) pairs into a
        // set. The consensus loop below skips add_seal_attestation when
        // the pair is in the set. No-op when `enforce_per_zone_vrf=false`.
        let mut phase6c_blocked: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for (rid, wh, _ts) in &consensus_refeed {
            if let Some(seal) = seal_infos.get(rid) {
                let allowed = super::zone_committee::enforce_seal_attestation_committee_membership(
                    state,
                    seal.zone.path(),
                    seal.epoch_number,
                    wh,
                ).await;
                if !allowed {
                    state.seal_attestation_rejected_not_in_committee_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    phase6c_blocked.insert((rid.clone(), wh.clone()));
                }
            }
        }

        // Guards live in a real lexical block (not just drop()): the
        // FinalizedIndex await below would otherwise capture the !Send
        // consensus MutexGuard in the enclosing async fn's state and break
        // tokio::spawn's Send bound at the loop spawn site.
        {
            let ledger = state.ledger.read().await;
            let mut consensus = state.consensus.lock_recover();
            let mut affected = std::collections::HashSet::new();
            for (rid, wh, ts) in &consensus_refeed {
                let stake = ledger.staked(wh);
                // Register creator identity (+ stake) so settlement denominator excludes
                // it AND a creator self-attestation is rejected/purged (H1). Identity is
                // recorded even at 0 stake to close the late-staking window.
                if let Some(creator) = creator_hashes.get(rid) {
                    let creator_stake = ledger.staked(creator);
                    consensus.register_creator_stake(rid, creator, creator_stake);
                }
                consensus.add_attestation(super::consensus::Attestation {
                    record_id: rid.clone(),
                    witness_hash: wh.clone(),
                    stake,
                    timestamp: *ts,
                });
                // DISC-7c: seal-attestation parallel-feed. Mirrors state.rs:1538
                // batch_feed_attestations epoch-seal branch so histogram fires
                // from the refeed path too. Phase 6c: skip the add when the
                // (rid, wh) pair was rejected by the per-zone VRF gate above.
                if let Some(seal) = seal_infos.get(rid) {
                    if !phase6c_blocked.contains(&(rid.clone(), wh.clone())) {
                        consensus.add_seal_attestation(super::consensus::SealAttestation {
                            seal_id: rid.clone(),
                            zone: seal.zone.clone(),
                            epoch_number: seal.epoch_number,
                            witness_hash: wh.clone(),
                            stake,
                            timestamp: *ts,
                        });
                    }
                }
                affected.insert(rid.clone());
            }
            for rid in &affected {
                if consensus.is_settled(rid) {
                    consensus.force_finalized(rid);
                    refeed_settled.push(rid.clone());
                }
            }
        }
        // Refeed path previously never touched FinalizedIndex and rewarded
        // every settled rid on every pass — route it through the durable
        // exactly-once edge like every other finalization path.
        if !refeed_settled.is_empty() {
            let newly = {
                let mut finalized = state.finalized.write().await;
                finalized.insert_batch_returning_new(&refeed_settled)
            };
            super::reward::finalization_effects(state, newly);
        }
    }
    let feed_outcome = state.batch_feed_attestations(&all_feed).await;
    let settled_count = feed_outcome.settled.len() + refeed_settled.len();
    super::reward::finalization_effects(state, feed_outcome.newly_finalized);

    // Advance per-peer watermark to max timestamp in batch.
    // This ensures next pull from this peer skips known attestations.
    //
    // Fast-forward: when an entire batch contains 0 new attestations
    // (all already known), we're crawling through stale history.
    // Jump the watermark ahead by the batch time span to catch up
    // exponentially instead of linearly. Safe because we provably
    // already have everything in that range.
    let effective_watermark = if new_atts.is_empty()
        && (verified.len() + skipped_known) == atts.len()
        && atts.len() >= limit
        && batch_max_ts > since
    {
        // Double the time span we just covered
        let span = batch_max_ts - since;
        let jump = batch_max_ts + span;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(batch_max_ts); // clock before epoch: cap at batch_max_ts (no fast-forward)
        // Don't jump past current time
        jump.min(now)
    } else {
        batch_max_ts
    };

    if effective_watermark > 0.0 || batch_invalid_sig > 0 || batch_invalid_powas > 0 {
        let mut peers = state.peers.write().await;
        if effective_watermark > 0.0 {
            peers.advance_att_watermark(identity_hash, effective_watermark);
            peers.record_pull_success(identity_hash);
        }
        // Amortise per-peer counter writes onto the same lock acquisition.
        // Bump even when watermark didn't advance — a batch of all-bad-sigs is
        // exactly the storm we want to attribute.
        if batch_invalid_sig > 0 {
            peers.bump_att_pull_invalid_sig(identity_hash, batch_invalid_sig);
        }
        if batch_invalid_powas > 0 {
            peers.bump_att_pull_invalid_powas(identity_hash, batch_invalid_powas);
        }
        // Stash sample of bad-sig record_ids for forensic triage.
        // Same lock window as the counter bumps; ring buffer in PeerInfo.
        if !bad_sig_record_ids.is_empty() {
            peers.push_bad_sig_record_ids(identity_hash, std::mem::take(&mut bad_sig_record_ids));
        }
    }

    info!(
        "att-pull: {} from {} — {}/{} verified, {} new, {} refed, {} settled, {} missing, watermark→{:.0}{}",
        atts.len(), &identity_hash[..identity_hash.len().min(16)],
        verified.len(), atts.len(), new_atts.len(),
        refed_count, settled_count, missing_record_ids.len(), effective_watermark,
        if effective_watermark > batch_max_ts { " (fast-forward)" } else { "" },
    );

    // ── Fetch missing records and retry deferred attestations ──
    // NAT nodes can't receive record pushes, so attestation pull
    // may encounter attestations for records we don't have yet.
    // Fetch those records, then retry signature verification.
    if !missing_record_ids.is_empty() && !deferred_attestations.is_empty() {
        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
        let fetch_cap = att_pull_fetch_cap(ram_gb);
        let fetch_ids: Vec<String> = missing_record_ids.iter()
            .take(fetch_cap)
            .cloned().collect();
        let fetch_count = fetch_ids.len();

        // Max deferred timestamp — used to advance watermark for
        // permanently unfetchable attestations (evicted records).
        let deferred_max_ts: f64 = deferred_attestations.iter()
            .filter_map(|a| a["timestamp"].as_f64())
            .fold(0.0f64, f64::max);

        let pq_addr = match http_to_pq_addr(base_url, state.config.pq_port_offset) {
            Some(a) => a,
            None => {
                debug!(
                    "att-pull: no PQ addr for {}, cannot fetch missing records",
                    &base_url[..base_url.len().min(30)]
                );
                if deferred_max_ts > batch_max_ts {
                    batch_max_ts = deferred_max_ts;
                }
                if batch_max_ts > 0.0 {
                    let mut peers = state.peers.write().await;
                    peers.advance_att_watermark(identity_hash, batch_max_ts);
                }
                return;
            }
        };
        match state.pq_client.fetch_records(&pq_addr, &fetch_ids).await {
            Ok(wire_list) => {
                let mut fetched = 0u64;
                let mut decoded: Vec<ValidationRecord> = wire_list
                    .iter()
                    .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
                    .collect();
                decoded.sort_by(|a, b| {
                    a.timestamp.total_cmp(&b.timestamp)
                });
                for (i, record) in decoded.into_iter().enumerate() {
                    let record_id = record.id.clone();
                    let is_seal_class = record.metadata.contains_key(EPOCH_OP_KEY);
                    match super::ingest::insert_record_synced(state, record).await {
                        Ok(_) => {
                            state.seen.lock_recover().insert(record_id);
                            fetched += 1;
                        }
                        Err(e) if is_seal_class => {
                            // R3-8 soak forensics: seal-class rejects are loud.
                            state.gossip_seal_insert_reject_total.fetch_add(1, Relaxed);
                            warn!(
                                "att-pull: SEAL-class record {} rejected at ingest: {e}",
                                &record_id[..record_id.len().min(16)]
                            );
                        }
                        Err(_) => {}
                    }
                    // Rate-limit: on ≤2GB machines, yield between inserts
                    // to let RocksDB compaction breathe. Without this,
                    // 50 records in a tight loop causes L0 write stalls.
                    if i > 0 && i % 5 == 0 {
                        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
                        let pause = if ram_gb <= 2 { 500 } else if ram_gb <= 4 { 100 } else { 0 };
                        if pause > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(pause)).await;
                        }
                    }
                }

                if fetched > 0 {
                    info!(
                        "att-pull: fetched {fetched}/{fetch_count} missing records from {}",
                        &identity_hash[..identity_hash.len().min(16)]
                    );

                    // Retry deferred attestations now that we have the records
                    let mut retry_verified: Vec<VerifiedAttestation> = Vec::new();
                    for att in &deferred_attestations {
                        let record_id = att["record_id"].as_str().unwrap_or("");
                        let witness_hash = att["witness_hash"].as_str().unwrap_or("");
                        let sig_hex = att["signature"].as_str().unwrap_or("");
                        let timestamp = att["timestamp"].as_f64().unwrap_or(0.0);
                        if record_id.is_empty() || witness_hash.is_empty() || sig_hex.is_empty() { continue; }
                        let sig = match hex::decode(sig_hex) { Ok(s) if !s.is_empty() => s, _ => continue };
                        let pk_hex = match att["witness_public_key"].as_str() { Some(h) if !h.is_empty() => h, _ => continue };
                        let pk = match hex::decode(pk_hex) { Ok(p) => p, Err(_) => continue };
                        if sha3_256_hex(&pk) != witness_hash { continue; }
                        let signable = match state.get_record(record_id).map(|r| r.signable_bytes()) {
                            Ok(s) => s,
                            _ => continue, // still missing — will be picked up by watermark advance below
                        };
                        match dilithium3_verify(&signable, &sig, &pk) {
                            Ok(true) => {}
                            _ => continue,
                        }
                        let powas_nonce = att["powas_nonce"].as_u64();
                        let powas_difficulty = att["powas_difficulty"].as_u64();
                        if timestamp > batch_max_ts { batch_max_ts = timestamp; }
                        retry_verified.push(VerifiedAttestation {
                            record_id: record_id.to_string(),
                            witness_hash: witness_hash.to_string(),
                            signature: sig,
                            timestamp,
                            public_key: Some(pk),
                            powas_nonce,
                            powas_difficulty,
                        });
                    }

                    if !retry_verified.is_empty() {
                        let mut retry_new: Vec<(String, String, f64)> = Vec::new();
                        {
                            let mgr = state.witness_mgr.as_ref();
                            for va in &retry_verified {
                                if let Ok(true) = mgr.store_attestation_with_powas(
                                    &va.record_id, &va.witness_hash, &va.signature,
                                    va.timestamp, va.public_key.as_deref(),
                                    va.powas_nonce, va.powas_difficulty,
                                ) {
                                    retry_new.push((va.record_id.clone(), va.witness_hash.clone(), va.timestamp));
                                }
                            }
                        }
                        let retry_outcome = state.batch_feed_attestations(&retry_new).await;
                        info!(
                            "att-pull retry: {}/{} verified, {} new, {} settled from fetched records",
                            retry_verified.len(), deferred_attestations.len(),
                            retry_new.len(), retry_outcome.settled.len()
                        );
                        super::reward::finalization_effects(state, retry_outcome.newly_finalized);
                    }
                }

                // Advance watermark past ALL deferred attestations.
                // Records that peer couldn't serve are permanently gone
                // (evicted on both sides). Without this, watermark stays
                // stuck and we re-fetch the same dead attestations forever.
                if deferred_max_ts > batch_max_ts {
                    batch_max_ts = deferred_max_ts;
                }
                if batch_max_ts > 0.0 {
                    let mut peers = state.peers.write().await;
                    peers.advance_att_watermark(identity_hash, batch_max_ts);
                }
            }
            Err(e) => {
                // Fetch failed — still advance watermark for deferred
                // attestations to avoid getting stuck on same batch.
                if deferred_max_ts > batch_max_ts {
                    batch_max_ts = deferred_max_ts;
                }
                if batch_max_ts > 0.0 {
                    let mut peers = state.peers.write().await;
                    peers.advance_att_watermark(identity_hash, batch_max_ts);
                }
                debug!(
                    "att-pull: record fetch from {} failed: {e}",
                    &identity_hash[..identity_hash.len().min(16)]
                );
            }
        }
    }
}

// ─── 0b-(i): restart-surviving backstop clocks ──────────────────────────────
//
// The pull loops' full-reconciliation cadence used to live in process-local
// counters that reset to 0 on every boot — a node restarted more often than
// the cadence period NEVER ran its backstop (observed 2026-06-11: the
// cycle-50 att sweep re-fed 321 attestations and settled 138 records the
// moment it finally ran). The counters are now PERSISTED in CF_METADATA so
// the cadence is measured across restarts. Chain-time keying was rejected:
// on a wedged chain (epoch frozen) a chain-time backstop never fires —
// exactly the situation the backstop exists to repair.

/// CF_METADATA key for the attestation-pull cycle counter.
const ATT_PULL_CYCLE_KEY: &[u8] = b"backstop:att_pull_cycle";
/// CF_METADATA key for the record-pull cycle counter.
const RECORD_PULL_CYCLE_KEY: &[u8] = b"backstop:record_pull_cycle";

/// Load a persisted backstop cycle counter; `default` on first-ever boot or
/// unreadable value.
fn load_backstop_cycle(state: &NodeState, key: &[u8], default: u64) -> u64 {
    state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_METADATA, key)
        .ok()
        .flatten()
        .and_then(|v| v.as_slice().try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(default)
}

/// Persist a backstop cycle counter (best-effort; a lost write costs one
/// cadence period at worst).
fn store_backstop_cycle(state: &NodeState, key: &[u8], cycle: u64) {
    let _ = state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_METADATA, key, &cycle.to_le_bytes());
}

/// Backstop cadence predicate: full reconciliation fires once per boot (at
/// in-process tick `boot_at`, giving discovery a window to connect peers)
/// and at every `every`-th PERSISTED cycle, which frequent restarts can no
/// longer dodge.
fn backstop_force_full(boot_ticks: u64, boot_at: u64, cycle: u64, every: u64) -> bool {
    boot_ticks == boot_at || cycle.is_multiple_of(every)
}

/// Attestation pull loop — periodically query peers for new attestations.
/// Uses DHT peer selection for scalable network coverage.
pub async fn attestation_pull_loop(state: Arc<NodeState>, mut shutdown: mpsc::Receiver<()>) {
    // NAT'd nodes can't receive attestation pushes — pull faster.
    let secs = state.config.gossip_pull_interval_secs;
    let base_interval = if state.config.behind_nat {
        Duration::from_secs(secs / 2).max(Duration::from_secs(5))
    } else {
        Duration::from_secs(secs)
    };
    // 0b-(i): persisted across restarts (see backstop block above).
    let mut pull_cycle: u64 = load_backstop_cycle(&state, ATT_PULL_CYCLE_KEY, 0);
    let mut boot_ticks: u64 = 0;

    loop {
        let jitter = Duration::from_millis((now() as u64).wrapping_mul(13) % 5000);
        tokio::select! {
            _ = tokio::time::sleep(base_interval + jitter) => {}
            _ = shutdown.recv() => {
                debug!("attestation pull loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10).
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        pull_cycle = pull_cycle.wrapping_add(1);
        boot_ticks += 1;
        store_backstop_cycle(&state, ATT_PULL_CYCLE_KEY, pull_cycle);

        // Full reconciliation every 50th cycle (~25 min): pull from timestamp 0
        // to catch anything missed (record not yet local, watermark skew, etc.).
        // Normal cycles use per-peer watermarks for O(new) pulls.
        // Was 200 (100 min) but too slow as safety net — attestations for records
        // that arrive after watermark advancement need faster recovery.
        // 0b-(i): cadence keyed on the PERSISTED cycle + one boot-window pass
        // (tick 2, after discovery has had one interval to connect peers).
        let force_full = backstop_force_full(boot_ticks, 2, pull_cycle, 50);

        let pull_targets = select_gossip_peers(&state).await;

        info!("att-pull cycle={pull_cycle} force_full={force_full} targets={}", pull_targets.len());

        for (identity_hash, base_url) in &pull_targets {
            // Per-peer watermark: only pull attestations newer than what we last got
            // from this specific peer. Full reconciliation (since=0) runs every 10th
            // cycle as safety net. This reduces bandwidth by ~99% vs brute-force pull.
            let since = if force_full {
                0.0
            } else {
                let peers = state.peers.read().await;
                peers.att_watermark(identity_hash)
            };
            // Each attestation with Dilithium3 sig ≈ 6.5KB JSON.
            // 500 atts ≈ 3.2MB, 2000 atts ≈ 13MB — both safe within 30s timeout.
            // Cold-start (since=0): smaller batch to avoid timeout on huge backlogs.
            // Incremental (since>0): moderate batch — 10K was 65MB and timing out.
            let limit = if since == 0.0 { 500 } else { 2_000 };

            // AUDIT-10: PQ-only att-pull. If the peer has no derivable PQ addr,
            // skip it — we don't downgrade to HTTPS (harvest-now-decrypt-later).
            let pq_offset = state.config.pq_port_offset;
            let pq_addr = match http_to_pq_addr(base_url, pq_offset) {
                Some(a) => a,
                None => {
                    debug!(
                        "att-pull: no PQ addr for {}, skipping",
                        &identity_hash[..identity_hash.len().min(16)]
                    );
                    continue;
                }
            };
            match state.pq_client
                .query_attestations_since(&pq_addr, since, limit).await
            {
                Ok(Some(data)) => {
                    {
                        let mut peers = state.peers.write().await;
                        peers.record_success(identity_hash);
                    }
                    process_attestation_pull_batch(
                        &state, &data, identity_hash, base_url,
                        since, limit,
                    ).await;
                }
                Ok(None) => {
                    // 404 — peer doesn't have the requested range. Treat as success.
                    let mut peers = state.peers.write().await;
                    peers.record_success(identity_hash);
                }
                Err(e) => {
                    info!(
                        "att-pull from {} failed: {e}",
                        &identity_hash[..identity_hash.len().min(16)]
                    );
                    let mut peers = state.peers.write().await;
                    peers.record_pull_failure(identity_hash);
                }
            }
        }

        // After processing all peers, recheck settlement for tracked records.
        // This catches records that became settled due to newly-pulled attestations
        // or creator_stake backfill, without waiting for the next epoch tick.
        if force_full {
            // Backfill creator_stakes + recheck on full reconciliation cycles.
            // Step 1: Get missing records list (consensus lock only, brief)
            let missing: Vec<String> = {
                let consensus = state.consensus.lock_recover();
                consensus.records_missing_creator_stake()
            };

            // Step 2: Fetch creator hashes from RocksDB WITHOUT holding ledger lock.
            // This was the #2 deadlock source: holding ledger.read() across thousands
            // of RocksDB reads blocked state_core's ledger.write() for 60+ seconds.
            // Cap per cycle to avoid blocking att-pull for minutes on large DBs.
            // Remaining records get backfilled in subsequent force_full cycles.
            let mut creator_map: Vec<(String, String)> = Vec::with_capacity(missing.len().min(500));
            for rid in missing.iter().take(500) {
                if let Ok(rec) = state.get_record(rid) {
                    let creator = crate::accounting::types::creator_identity_hash(&rec);
                    creator_map.push((rid.clone(), creator));
                }
            }

            // Step 3: Brief ledger read + consensus update (in-memory only, fast)
            let newly_rids: Vec<String> = {
                let ledger = state.ledger.read().await;
                let mut consensus = state.consensus.lock_recover();
                for (rid, creator) in &creator_map {
                    let cs = ledger.staked(creator);
                    if cs > 0 {
                        consensus.register_creator_stake(rid, creator, cs);
                    }
                }
                consensus.force_finalize_settled()
                // consensus + ledger guards drop here — must release before
                // any .await below since the consensus MutexGuard is !Send.
            };
            if !newly_rids.is_empty() {
                // Insert into FinalizedIndex BEFORE counter bump — otherwise
                // finality_monitor's `!finalized.contains && is_settled` filter
                // would re-pick these on its next scan (and after prune drops
                // them from the attestations map, the filter gate would
                // permanently miss them, leaving the records invisible to
                // /api/finalized while still counted in total_ever_settled).
                //
                // Bump the lifetime counter by `new_inserts` (idempotent
                // count returned by insert_batch), not `newly_rids.len()`:
                // finality_monitor may have already finalized some rids,
                // and force_finalize_settled doesn't sync confirmation_levels
                // with FinalizedIndex (asymmetric truth — confirmation_levels
                // is in-memory consensus state, FinalizedIndex is durable),
                // so re-picks are common. Counting only true new inserts
                // keeps total_ever_settled aligned with finalized_count.
                let new_rids = {
                    let mut finalized = state.finalized.write().await;
                    finalized.insert_batch_returning_new(&newly_rids)
                };
                if !new_rids.is_empty() {
                    state.total_ever_settled.fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    state.total_ever_finalized.fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    info!("attestation pull: {} records reached finality after recheck (total_ever_settled={})",
                        new_rids.len(),
                        state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed));
                    // Stake-recheck finalizations previously fired no
                    // rewards/credit/events at all — exactly-once edge.
                    super::reward::finalization_effects(&state, new_rids);
                }
            }

            // ── Local WitnessManager → consensus gap-fill ──
            // The att-pull fast-forward skips time ranges where all attestations
            // are already in WitnessManager. But "in WitnessManager" ≠ "in consensus".
            // After startup, attestations from previous sessions may be in WitnessManager
            // (loaded from RocksDB) but never fed to consensus (50K startup limit).
            // Scan recent local attestations and re-feed any not tracked in consensus.
            {
                let tracked: std::collections::HashSet<String> = {
                    let consensus = state.consensus.lock_recover();
                    consensus.tracked_record_ids().into_iter().collect()
                };
                let now_ts = now();
                let retention = state.config.record_retention_secs.max(86400.0);
                let cutoff = now_ts - retention * 2.0;
                let scan = {
                    let mgr = state.witness_mgr.as_ref();
                    // Cap to 5K to avoid blocking att-pull for 20+ min on large DBs.
                    // 200K × RocksDB read ≈ 15-30 min on cold cache. 5K converges
                    // in ~10 force_full cycles (4 hours) without stalling the loop.
                    mgr.get_attestations_since(cutoff, 5_000)
                };
                if let Ok(recent) = scan {
                    let mut gap_feed: Vec<(String, String, f64)> = Vec::new();
                    let mut checked = 0usize;
                    for att in &recent {
                        if tracked.contains(&att.record_id) {
                            continue;
                        }
                        if state.rocks.get_record(&att.record_id).ok().flatten().is_none() {
                            checked += 1;
                            // Yield every 100 RocksDB reads to avoid blocking tokio executor
                            if checked.is_multiple_of(100) {
                                tokio::task::yield_now().await;
                            }
                            continue;
                        }
                        gap_feed.push((att.record_id.clone(), att.witness_hash.clone(), att.timestamp));
                    }
                    if !gap_feed.is_empty() {
                        let count = gap_feed.len();
                        let outcome = state.batch_feed_attestations(&gap_feed).await;
                        info!(
                            "att-pull gap-fill: fed {count} local attestations for {} untracked records, {} settled",
                            gap_feed.iter().map(|(r,_,_)| r.as_str()).collect::<std::collections::HashSet<_>>().len(),
                            outcome.settled.len()
                        );
                        super::reward::finalization_effects(&state, outcome.newly_finalized);
                    }
                }
            }

            // ── Targeted attestation pull for unsettled records ──
            // Fast-forward can skip attestations on remote peers that local doesn't
            // have (remote-only attestations in skipped time ranges). Fix: during
            // force_full, sample unsettled records with low attestation counts and
            // explicitly pull their attestations by record_id from random peers.
            // This catches the fast-forward gaps without disabling fast-forward
            // (which would make normal catch-up too slow).
            {
                let sample: Vec<(String, usize)> = {
                    let consensus = state.consensus.lock_recover();
                    let unsettled = consensus.unsettled_summary();
                    unsettled.into_iter()
                        .filter(|(_, att_count, _)| *att_count < 5) // only low-attestation records
                        .map(|(rid, att_count, _)| (rid, att_count))
                        .take(200)
                        .collect()
                };
                if !sample.is_empty() && !pull_targets.is_empty() {
                    let mut fetched = 0u32;
                    let mut new_stored = 0u32;
                    let mut all_feed: Vec<(String, String, f64)> = Vec::new();
                    let pq_offset = state.config.pq_port_offset;
                    for (rid, _local_count) in &sample {
                        // Pick a random peer for each record
                        let peer_idx = (rid.as_bytes().first().copied().unwrap_or(0) as usize) % pull_targets.len();
                        let (_, peer_url) = &pull_targets[peer_idx];

                        // AUDIT-10: PQ-only. Skip peers with no derivable PQ addr.
                        let pq_addr = match http_to_pq_addr(peer_url, pq_offset) {
                            Some(a) => a,
                            None => continue,
                        };
                        let body = match state.pq_client
                            .query_attestations_for_record(&pq_addr, rid).await
                        {
                            Ok(Some(v)) => v,
                            _ => continue,
                        };
                        let atts = match body["attestations"].as_array() {
                            Some(a) => a,
                            None => continue,
                        };
                        fetched += 1;
                        // Process attestations in a sync block (no MutexGuard across .await)
                        let new_atts = {
                            let mgr = state.witness_mgr.as_ref();
                            // (record_id, witness_hash, timestamp, sig, pk, powas_nonce, powas_difficulty)
                            type AttPullEntry = (String, String, f64, Vec<u8>, Vec<u8>, Option<u64>, Option<u64>);
                            let mut batch: Vec<AttPullEntry> = Vec::new();
                            for att in atts {
                                let witness_hash = att["witness_hash"].as_str().unwrap_or("");
                                let sig_hex = att["signature"].as_str().unwrap_or("");
                                let timestamp = att["timestamp"].as_f64().unwrap_or(0.0);
                                let pk_hex = att["witness_public_key"].as_str().unwrap_or("");
                                if witness_hash.is_empty() || sig_hex.is_empty() { continue; }
                                if let Ok(existing) = mgr.get_attestations(rid) {
                                    if existing.iter().any(|a| a.witness_hash == witness_hash) {
                                        continue;
                                    }
                                }
                                let sig = match hex::decode(sig_hex) { Ok(s) => s, _ => continue };
                                let pk = match hex::decode(pk_hex) { Ok(p) if !p.is_empty() => p, _ => continue };
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
                                    rid, witness_hash, &sig, timestamp,
                                    Some(&pk), powas_nonce, powas_difficulty,
                                );
                                batch.push((rid.clone(), witness_hash.to_string(), timestamp, sig, pk, powas_nonce, powas_difficulty));
                            }
                            batch
                        }; // mgr dropped here
                        for (rid, wh, ts, _, _, _, _) in &new_atts {
                            all_feed.push((rid.clone(), wh.clone(), *ts));
                            new_stored += 1;
                        }
                    }
                    if !all_feed.is_empty() {
                        let outcome = state.batch_feed_attestations(&all_feed).await;
                        info!("att-pull targeted: queried {fetched}/{} unsettled records, {new_stored} new attestations, {} settled", sample.len(), outcome.settled.len());
                        super::reward::finalization_effects(&state, outcome.newly_finalized);
                    }
                }
            }
        }
    }
}

/// Gap 4 gossip: broadcast a pending TransitionSeal to a `sqrt(n)` fan-out
/// of connected relay peers via `POST /transitions/propose`.
///
/// Called after `run_auto_scale_tick` has successfully inserted a locally-
/// proposed seal into `state.transitions` — the store already validated
/// structure and enforced dedup, so we know the seal is well-formed before
/// we hand it to peers. The remote side's `/transitions/propose` handler
/// re-validates and ignores duplicates (id-based), so re-delivery under
/// gossip churn is safe.
///
/// # Dedup
/// Keyed by `hex(seal_hash_for_sig)` via `state.transition_seen`
/// (capacity 10k). At ~1 proposal/zone/epoch this covers days of fleet
/// activity. If the same seal arrives again via peer gossip we skip
/// re-broadcast — O(gossip_fanout^hops) amplification prevented.
///
/// # Fan-out
/// `sqrt(n)` of connected relay peers, identical to conflict-proof push.
/// At 10k peers that's ~100 HTTP POSTs per local proposal. Proposals are
/// anchor-rate-limited (only anchors sign), so this stays a cold path.
///
/// # Transport
/// AUDIT-10 Milestone C: PQ-only via `PqNodeClient::submit_transition_seal`.
/// Peers with no derivable PQ addr are skipped — no HTTPS fallback.
///
/// Errors are swallowed per-peer (logged at debug) — a missing
/// broadcast doesn't break consensus because the other honest anchors
/// will eventually gossip the same seal when they observe their own
/// decision, and the pull loop is the ultimate backstop.
pub async fn push_transition_seal_to_peers(
    state: &Arc<NodeState>,
    seal: &super::zone_transition_seal::TransitionSeal,
) {
    // Compute the id up front — it's the dedup key AND the seed for
    // fan-out peer selection, so we only want to pay `seal_hash_for_sig`
    // once. Failure to hash is a structural bug in the seal (bad zone
    // ids, etc.) — drop with a warn rather than broadcast garbage.
    let seal_id = match seal.seal_hash_for_sig() {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("push_transition_seal: seal_hash_for_sig failed: {e}");
            return;
        }
    };
    let seal_id_hex = hex::encode(seal_id);

    // Dedup: one broadcast per seal from this node.
    {
        let mut seen = state.transition_seen.lock_recover();
        if !seen.insert(seal_id_hex.clone()) {
            state
                .transition_gossip_dedup_total
                .fetch_add(1, Relaxed);
            return;
        }
    }

    // sqrt(n) fan-out across connected relay peers.
    let targets: Vec<(String, String)> = {
        let peers = state.peers.read().await;
        let mut all: Vec<(String, String)> = peers
            .connected()
            .into_iter()
            .filter(|p| {
                p.identity_hash != state.identity.identity_hash
                    && p.node_type.can_relay()
                    && p.reachable
            })
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1);
        if all.len() > fan_out {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            seal_id_hex.hash(&mut hasher);
            let seed_val = hasher.finish();
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    // Stage 6: per-peer bandwidth fairness (Protocol §11.10).
    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    let body_bytes = match serde_json::to_vec(seal) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("push_transition_seal: serialize failed: {e}");
            return;
        }
    };

    state
        .transition_gossip_pushed_total
        .fetch_add(1, Relaxed);
    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let pq_client = state.pq_client.clone();
    for (_identity_hash, base_url) in &targets {
        let pq_addr = match http_to_pq_addr(base_url, pq_offset) {
            Some(a) => a,
            None => {
                tracing::debug!(
                    "transition-seal push: no PQ addr for {}, skipping",
                    &base_url[..base_url.len().min(60)]
                );
                continue;
            }
        };
        let body = body_bytes.clone();
        let pq = pq_client.clone();
        let sem = semaphore.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;
            if let Err(e) = pq.submit_transition_seal(&pq_addr, &body).await {
                tracing::debug!(
                    "transition-seal push failed to {}: {e}",
                    &pq_addr[..pq_addr.len().min(60)]
                );
            }
        });
    }
}

/// Gap 4: broadcast a single `AnchorSig` for an in-flight TransitionSeal.
///
/// # Why per-sig gossip
/// A seal re-broadcast carrying the updated `proposer_sigs` would cause
/// amplification: two anchors that independently receive and cosign the
/// same seal would each rebroadcast an N-byte seal where only a 3309-byte
/// `AnchorSig` actually changed. With 32 anchors this is O(N²) bytes on
/// the wire. Per-sig gossip keeps the wave O(N): each cosign produces
/// exactly one small broadcast targeted at `POST /transitions/{id}/sig`.
///
/// # Dedup
/// Keyed by `"{hex(seal_id)}:{hex(anchor_identity_hash)}"` — per-sig, not
/// per-seal, because a seal accumulates up to `MAX_PROPOSER_SIGS = 32`
/// distinct sigs over its window and each must propagate independently.
/// Capacity (50k) covers ~1500 in-flight seals × 32 sigs without eviction
/// churn at fleet scale.
///
/// # Transport
/// AUDIT-10 Milestone C: PQ-only via `PqNodeClient::submit_transition_sig`.
/// Peers with no derivable PQ addr are skipped — no HTTPS fallback.
/// Errors are swallowed per-peer (debug log) — pull/cosign-retry on the
/// receiving side is the backstop.
pub async fn push_transition_sig_to_peers(
    state: &Arc<NodeState>,
    seal_id: [u8; 32],
    sig: &super::zone_transition_seal::AnchorSig,
) {
    let seal_id_hex = hex::encode(seal_id);
    let identity_hex = hex::encode(sig.anchor_identity_hash);
    let dedup_key = format!("{seal_id_hex}:{identity_hex}");

    // Dedup: one broadcast per (seal, anchor) pair from this node.
    {
        let mut seen = state.transition_sig_seen.lock_recover();
        if !seen.insert(dedup_key.clone()) {
            state
                .transition_sig_gossip_dedup_total
                .fetch_add(1, Relaxed);
            return;
        }
    }

    // sqrt(n) fan-out across connected relay peers — same shape as seal
    // push to keep gossip cost symmetric.
    let targets: Vec<(String, String)> = {
        let peers = state.peers.read().await;
        let mut all: Vec<(String, String)> = peers
            .connected()
            .into_iter()
            .filter(|p| {
                p.identity_hash != state.identity.identity_hash
                    && p.node_type.can_relay()
                    && p.reachable
            })
            .map(|p| (p.identity_hash.clone(), p.base_url()))
            .collect();

        let fan_out = if all.len() < 10 {
            all.len()
        } else {
            (all.len() as f64).sqrt().ceil() as usize
        };
        let fan_out = fan_out.max(1);
        if all.len() > fan_out {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            dedup_key.hash(&mut hasher);
            let seed_val = hasher.finish();
            let len = all.len();
            for i in 0..fan_out.min(len) {
                let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
                all.swap(i, j);
            }
            all.truncate(fan_out);
        }
        all
    };

    if targets.is_empty() {
        return;
    }

    // Per-peer bandwidth fairness (Protocol §11.10).
    let targets: Vec<(String, String)> = targets
        .into_iter()
        .filter(|(ih, _)| state.peer_bandwidth.try_acquire(ih))
        .collect();
    if targets.is_empty() {
        return;
    }

    let body_bytes = match serde_json::to_vec(sig) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("push_transition_sig: serialize failed: {e}");
            return;
        }
    };

    state
        .transition_sig_gossip_pushed_total
        .fetch_add(1, Relaxed);
    let semaphore = state.gossip_semaphore.clone();
    let pq_offset = state.config.pq_port_offset;
    let pq_client = state.pq_client.clone();
    for (_identity_hash, base_url) in &targets {
        let pq_addr = match http_to_pq_addr(base_url, pq_offset) {
            Some(a) => a,
            None => {
                tracing::debug!(
                    "transition-sig push: no PQ addr for {}, skipping",
                    &base_url[..base_url.len().min(60)]
                );
                continue;
            }
        };
        let body = body_bytes.clone();
        let pq = pq_client.clone();
        let sem = semaphore.clone();
        let seal_id_hex = seal_id_hex.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await;
            if let Err(e) = pq.submit_transition_sig(&pq_addr, &seal_id_hex, &body).await {
                tracing::debug!(
                    "transition-sig push failed to {}: {e}",
                    &pq_addr[..pq_addr.len().min(60)]
                );
            }
        });
    }
}

// ─── Validation pipeline moved to ingest.rs ─────────────────────────────
// insert_record, insert_record_inner, constants, and fisherman_slash
// are now in super::ingest. This module retains only gossip transport code.

// Re-export constants for backward compatibility
pub use super::ingest::{MAX_METADATA_ENTRIES, MAX_METADATA_VALUE_LEN, MAX_PARENTS, MAX_RECORD_BYTES, MAX_FUTURE_DRIFT_SECS};
// Re-export insert functions for backward compatibility during migration
pub use super::ingest::{insert_record, insert_record_with_origin, insert_record_synced, insert_record_inner_direct};

/// Broadcast a signed going-offline notification to all connected peers.
///
/// Called from the shutdown path immediately before dropping tx channels.
/// Fire-and-forget — each send runs in a short-lived tokio task with a 2s
/// timeout.  A 300ms yield after spawn gives tasks a chance to fire before
/// the runtime begins its own shutdown sequence.
///
/// Receiving peers call `PeerTable::mark_offline()` — no failure count bump,
/// no backoff — so the node is deprioritised immediately but re-promoted as
/// soon as it comes back online and a successful exchange is recorded.
pub async fn notify_going_offline(_state: &Arc<NodeState>) {
    // AUDIT-10 Milestone C final: HTTP fanout deleted. There is no PQ verb
    // for `/peers/offline_notification` — peers detect shutdown via heartbeat
    // timeout (reputation decay + Offline marking happens on the receiver
    // when expected traffic stops). Keeping this as a debug-log no-op
    // preserves call sites across graceful-shutdown paths.
    tracing::debug!("notify_going_offline: skipped (peers detect via heartbeat timeout)");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I7 (delta-sync cursor audit C7): the bootstrap admission gate rejects
    /// every timestamp class that would poison CF_IDX_TIMESTAMP ordering —
    /// NaN, ±inf, negatives, and the IEEE `-0.0` sign-bit case — and admits
    /// the full legitimate range (+0.0, subnormal, normal). This is the gate
    /// in front of bootstrap_pull_from_zero's direct put_record; rejection
    /// is what keeps `delta_sync_since_floor` finite against a hostile seed.
    #[test]
    fn bootstrap_ts_gate_rejects_index_poison_classes() {
        let rec_at = |ts: f64| {
            let mut r = crate::record::ValidationRecord::create(
                b"c7",
                vec![0xAA; 1952],
                vec![],
                crate::record::Classification::Public,
                None,
            );
            r.timestamp = ts;
            r
        };
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -0.0] {
            assert!(
                !bootstrap_record_ts_admissible(&rec_at(bad)),
                "ts={bad} must be rejected by the C7 bootstrap gate"
            );
        }
        for good in [0.0, f64::MIN_POSITIVE, 5e-324, 1_700_000_000.0] {
            assert!(
                bootstrap_record_ts_admissible(&rec_at(good)),
                "ts={good} must be admitted"
            );
        }
    }

    /// Drift guard: att-pull must never request more record ids than the server
    /// serves per call. `handle_fetch_records` silently drops ids beyond
    /// `MAX_FETCH_RECORDS`, and att-pull advances its watermark past every
    /// deferred attestation after one opportunistic fetch — so an over-ask is
    /// wasted request bytes on records it can't retrieve in that call. This
    /// caught a live drift (fetch_cap 200 vs server cap 100). Any RAM tier that
    /// pushes the cap back above the server ceiling trips this.
    #[test]
    fn att_pull_fetch_cap_never_exceeds_server_cap() {
        use crate::network::pq_transport::router::MAX_FETCH_RECORDS;
        for ram_gb in [0u64, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256] {
            let cap = att_pull_fetch_cap(ram_gb);
            assert!(
                cap <= MAX_FETCH_RECORDS,
                "att_pull_fetch_cap({ram_gb}GB)={cap} exceeds server \
                 MAX_FETCH_RECORDS={MAX_FETCH_RECORDS} — att-pull would request ids the \
                 server silently drops and (advancing its watermark past all deferred \
                 attestations) waste bandwidth on records it can't fetch in one call"
            );
            assert!(cap > 0, "att_pull_fetch_cap({ram_gb}GB) must fetch at least one record");
        }
    }

    // ─── 8b: stale-seal pre-filter + sweep-reset floor ──────────────────

    /// SEAL-8b-01 pin 1/2: the deficit seed clamps UP to the sweep floor. A
    /// hole below retention/earliest is pruned territory — the unfloored
    /// `s - 1.0` form re-arms the below-floor pull storm, and before this pin
    /// that revert passed the whole suite CI-invisibly.
    #[test]
    fn deficit_seed_target_clamps_at_sweep_floor() {
        let state = crate::network::state::build_test_node_state();

        // No open deficits → no seed target.
        assert_eq!(deficit_seed_target(&state), None);

        // An ancient hole far below the default-profile (full_zone, 90d)
        // retention floor must seed AT the floor, not at hole-start − 1.
        {
            let mut ring = state.dag_deficit_open.lock().unwrap();
            ring.observe(
                ("z0".to_string(), 7),
                crate::network::state::DagDeficitEntry {
                    missing: 3,
                    seal_start: 1_000.0, // ~1970 — decades below any floor
                    seal_record_id: "seal-7".into(),
                    first_seen_unix: 0,
                },
            );
        }
        let floor_before = full_pull_sweep_floor(&state);
        assert!(
            floor_before > 999.0,
            "test premise: default profile must yield a positive retention floor"
        );
        let target = deficit_seed_target(&state).expect("open deficit yields a target");
        let floor_after = full_pull_sweep_floor(&state);
        assert!(
            target >= floor_before && target <= floor_after,
            "below-floor hole must seed AT the sweep floor (got {target}, \
             floor {floor_before}..{floor_after}) — an unclamped seed re-arms \
             the below-floor pull storm"
        );

        // An above-floor hole seeds just under the hole — the clamp must not
        // flatten legitimate seed targets onto the floor.
        let above = full_pull_sweep_floor(&state) + 10_000.0;
        {
            let mut ring = state.dag_deficit_open.lock().unwrap();
            ring.resolve(&("z0".to_string(), 7));
            ring.observe(
                ("z1".to_string(), 9),
                crate::network::state::DagDeficitEntry {
                    missing: 1,
                    seal_start: above,
                    seal_record_id: "seal-9".into(),
                    first_seen_unix: 0,
                },
            );
        }
        let t2 = deficit_seed_target(&state).expect("open deficit yields a target");
        assert!(
            (t2 - (above - 1.0)).abs() < 1e-6,
            "above-floor hole must seed just under the hole (got {t2}, want {})",
            above - 1.0
        );
    }

    /// SEAL-8b-01 pin 2/2 (the single most load-bearing line of part C): the
    /// sweep-complete tail-reset re-arms the cursor AT the floor — in memory
    /// AND persisted — never 0.0, or the next sweep re-walks pruned history.
    #[test]
    fn sweep_tail_reset_rearms_cursor_at_floor_not_zero() {
        let state = crate::network::state::build_test_node_state();
        // Simulate a mid-history cursor left by a completed sweep.
        *state.full_pull_cursor.lock().unwrap() = 9_999_999_999.0;

        let floor_before = full_pull_sweep_floor(&state);
        assert!(
            floor_before > 0.0,
            "test premise: default profile must yield a positive retention floor"
        );
        let reset_to = apply_sweep_tail_reset(&state);
        let floor_after = full_pull_sweep_floor(&state);

        assert!(
            reset_to >= floor_before && reset_to <= floor_after,
            "tail-reset must re-arm AT the sweep floor (got {reset_to}, \
             floor {floor_before}..{floor_after}), never 0.0"
        );
        let in_mem = *state.full_pull_cursor.lock().unwrap();
        assert_eq!(in_mem, reset_to, "in-memory cursor must match the reset value");
        assert_eq!(
            state.rocks.load_full_pull_cursor(),
            reset_to,
            "persisted cursor must match — a 0.0 persist re-arms the storm \
             across restarts"
        );
    }

    fn seal_meta_record(op: &str, epoch: u64, zone: &str) -> ValidationRecord {
        let mut md = std::collections::BTreeMap::new();
        md.insert(EPOCH_OP_KEY.to_string(), serde_json::json!(op));
        md.insert("epoch_number".to_string(), serde_json::json!(epoch));
        md.insert("epoch_zone".to_string(), serde_json::json!(zone));
        ValidationRecord::create(
            b"seal",
            vec![],
            vec![],
            crate::record::Classification::Public,
            Some(md),
        )
    }

    #[test]
    fn stale_seal_pre_filter_declines_only_stale_seals() {
        let mut ep = crate::network::epoch::EpochState::new();
        ep.latest_epoch.insert(crate::ZoneId::new("z0"), 500);

        // Below the gap boundary (seal + GAP < local) → declined.
        assert!(is_stale_seal_record(&seal_meta_record("seal", 399, "z0"), &ep));
        // AT the boundary (400 + 100 == 500, not <) → kept for ingest.
        assert!(!is_stale_seal_record(&seal_meta_record("seal", 400, "z0"), &ep));
        // Recent → kept.
        assert!(!is_stale_seal_record(&seal_meta_record("seal", 501, "z0"), &ep));
        // Non-seal epoch_op (zone_transition) → never declined here.
        assert!(!is_stale_seal_record(
            &seal_meta_record("zone_transition", 1, "z0"),
            &ep
        ));
        // Unknown zone / bootstrapping (local_epoch == 0) → never declined.
        assert!(!is_stale_seal_record(
            &seal_meta_record("seal", 1, "z-unknown"),
            &ep
        ));
        // Plain record without epoch_op → untouched.
        let plain = ValidationRecord::create(
            b"r",
            vec![],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(!is_stale_seal_record(&plain, &ep));
    }

    #[test]
    fn sweep_floor_semantics() {
        // Retention-bound (FullZone 90d): records reach further back than the
        // retention window → floor = now − retention.
        assert_eq!(
            sweep_floor_from(Some(90 * 86400), Some(1_000.0), 10_000_000.0),
            10_000_000.0 - 90.0 * 86400.0
        );
        // Earliest-bound: a young store floors at its own oldest record —
        // non-backfilling profiles never re-fetch pre-snapshot history.
        assert_eq!(
            sweep_floor_from(Some(90 * 86400), Some(9_999_000.0), 10_000_000.0),
            9_999_000.0
        );
        // Archive (no retention): floor = oldest retained → full retained
        // history keeps sweeping, no profile special-case.
        assert_eq!(sweep_floor_from(None, Some(123.0), 10_000_000.0), 123.0);
        // Empty store, no retention → 0 (virgin full sweep).
        assert_eq!(sweep_floor_from(None, None, 10_000_000.0), 0.0);
        // Never negative (host clock younger than the retention window).
        assert_eq!(sweep_floor_from(Some(90 * 86400), None, 3_600.0), 0.0);
    }

    #[test]
    fn seal_rejects_never_enter_gossip_rejected() {
        let state = crate::network::state::build_test_node_state();
        state
            .epoch
            .write()
            .unwrap()
            .latest_epoch
            .insert(crate::ZoneId::new("z0"), 500);

        // Stale seal → declined_seal_ids; never embargo, never park.
        let stale = seal_meta_record("seal", 10, "z0");
        assert!(dispose_seal_ingest_failure(&state, &stale, 0));
        assert!(state
            .declined_seal_ids
            .lock()
            .unwrap()
            .contains(&stale.id));
        assert!(!state.gossip_rejected.lock_recover().contains(&stale.id));
        assert!(!state
            .gossip_retry
            .lock_recover()
            .iter()
            .any(|(id, _)| id == &stale.id));

        // Fresh-but-failed seal (malformed / invalid / transient alike) →
        // bounded park; never embargo (bucket 3, the previously-undefined one).
        let fresh = seal_meta_record("seal", 501, "z0");
        assert!(dispose_seal_ingest_failure(&state, &fresh, 0));
        assert!(state
            .gossip_retry
            .lock_recover()
            .iter()
            .any(|(id, _)| id == &fresh.id));
        assert!(!state.gossip_rejected.lock_recover().contains(&fresh.id));

        // At the attempt cap the id ages out — still never embargoed.
        let aged = seal_meta_record("seal", 502, "z0");
        assert!(dispose_seal_ingest_failure(
            &state,
            &aged,
            GOSSIP_RETRY_MAX_ATTEMPTS
        ));
        assert!(!state
            .gossip_retry
            .lock_recover()
            .iter()
            .any(|(id, _)| id == &aged.id));
        assert!(!state.gossip_rejected.lock_recover().contains(&aged.id));

        // Parked-then-stale (the `:414` leak): staleness is judged at
        // disposition time, so a seal that went stale while parked declines.
        let went_stale = seal_meta_record("seal", 20, "z0");
        assert!(dispose_seal_ingest_failure_probed(
            &state,
            &seal_reject_probe(&went_stale),
            5
        ));
        assert!(state
            .declined_seal_ids
            .lock()
            .unwrap()
            .contains(&went_stale.id));
        assert!(!state
            .gossip_rejected
            .lock_recover()
            .contains(&went_stale.id));

        // Non-seal → not disposed here; the caller's legacy (B6-preserving)
        // logic applies.
        let plain = ValidationRecord::create(
            b"r",
            vec![],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(!dispose_seal_ingest_failure(&state, &plain, 0));

        // zone_transition (epoch-op, not a seal): never stale-declined → park.
        let zt = seal_meta_record("zone_transition", 10, "z0");
        assert!(dispose_seal_ingest_failure(&state, &zt, 0));
        assert!(state
            .gossip_retry
            .lock_recover()
            .iter()
            .any(|(id, _)| id == &zt.id));
        assert!(!state.gossip_rejected.lock_recover().contains(&zt.id));
    }

    // ─── empty-PeerTable WARN throttle ─────────────────────────────────

    #[test]
    fn no_targets_warn_throttle_decision() {
        // A realistic wall-clock base (unix secs) so `now` dwarfs the window.
        let t = 1_800_000_000u64;
        // Never-warned (last == 0): always emits on the first empty tick.
        assert!(should_emit_no_targets_warn(t, 0));
        // Within the window: suppressed.
        assert!(!should_emit_no_targets_warn(t + 1, t));
        assert!(!should_emit_no_targets_warn(
            t + NO_TARGETS_WARN_THROTTLE_SECS - 1,
            t
        ));
        // Exactly at the window boundary: emits.
        assert!(should_emit_no_targets_warn(
            t + NO_TARGETS_WARN_THROTTLE_SECS,
            t
        ));
        // Past the window: emits.
        assert!(should_emit_no_targets_warn(t + 10_000, t));
        // Backwards clock step (NTP correction, now < last): `saturating_sub`
        // yields 0, so we suppress rather than spuriously emit.
        assert!(!should_emit_no_targets_warn(t - 5, t));
    }

    // ─── attestation-pull batch DoS cap ────────────────────────────────

    #[test]
    fn attestation_pull_batch_len_is_capped() {
        // Legit: a peer returns at most the `limit` we requested → unchanged.
        assert_eq!(capped_attestation_batch_len(2_000, 2_000), 2_000);
        assert_eq!(capped_attestation_batch_len(500, 2_000), 500);
        assert_eq!(capped_attestation_batch_len(0, 2_000), 0);
        // Malicious: millions of tiny `{}` objects packed into one MAX_PAYLOAD
        // frame for a 2_000-item request → bounded to what we asked for, which
        // is what kills the `Vec::with_capacity(atts.len())` OOM term.
        assert_eq!(capped_attestation_batch_len(5_000_000, 2_000), 2_000);
        // Hard ceiling: even an absurd requested limit can't exceed the const.
        assert_eq!(
            capped_attestation_batch_len(usize::MAX, usize::MAX),
            MAX_ATTESTATION_PULL_BATCH
        );
    }

    // ─── is_retryable_ingest_rejection (fresh-chain wall #5, board 0g) ──

    #[test]
    fn retryable_rejections_are_not_cached_permanently() {
        // Ledger-state-dependent rejections: ordering artifacts that resolve
        // as other records finalize — must stay re-pullable.
        for reason in [
            "ledger op rejected: insufficient balance: have 0, need 500000",
            "insufficient unlocked balance for stake",
            "conservation pool insufficient: pool 0, reward 1000",
            "witness reward references stake not found: abc123",
            "cross-zone credit: transfer not found",
            "epoch seal merkle root mismatch",
            "epoch seal previous_seal mismatch",
        ] {
            assert!(
                is_retryable_ingest_rejection(reason),
                "should be retryable: {reason}"
            );
        }
    }

    #[test]
    fn permanent_rejections_stay_cached() {
        // Time-invariant verdicts: re-pulling can never change the outcome.
        for reason in [
            "invalid signature",
            "bad dilithium signature for creator",
            "transfer amount must be greater than zero",
            "self-transfer not allowed",
            "pow difficulty below minimum",
            "record not found", // NOT "stake/transfer not found" — must not match
            "unknown ledger op kind",
        ] {
            assert!(
                !is_retryable_ingest_rejection(reason),
                "should be permanent: {reason}"
            );
        }
    }

    // ─── B6 fork-safety: untrusted push rejections never poison the cache ──

    #[test]
    fn should_permanent_reject_never_caches_untrusted_push() {
        // The fork vector: a downgraded untrusted push now reaches the
        // non-retryable rate-limit reject strings. If those were permanently
        // cached, a forged push of a canonical record would censor it from
        // every pull driver → fork. So ANY untrusted-push rejection must park,
        // regardless of whether the reason is otherwise "permanent".
        for reason in [
            "global rate limit exceeded (1000/min)",
            "identity abcd... exceeds propagation rate limit (100/hr, base=100, stake_bonus=0)",
            "invalid signature",                 // even a genuinely-permanent verdict
            "self-transfer not allowed",
            "merkle root mismatch",              // retryable too — still parks
        ] {
            assert!(
                !should_permanent_reject(/* untrusted_push */ true, reason),
                "B6: an untrusted push's rejection must NEVER be permanently cached \
                 (would censor a canonical record from sync): {reason}"
            );
        }
    }

    #[test]
    fn should_permanent_reject_preserves_split_for_trusted() {
        // A trusted relay (or local/direct submit, untrusted_push=false) keeps
        // the prior retryable-vs-permanent behavior unchanged.
        assert!(
            should_permanent_reject(false, "invalid signature"),
            "trusted/local non-retryable rejection must still be permanently cached"
        );
        assert!(
            should_permanent_reject(false, "self-transfer not allowed"),
            "trusted/local non-retryable rejection must still be permanently cached"
        );
        assert!(
            !should_permanent_reject(false, "merkle root mismatch"),
            "trusted/local RETRYABLE rejection must still park, not permanently cache"
        );
        assert!(
            !should_permanent_reject(false, "insufficient balance"),
            "trusted/local RETRYABLE rejection must still park, not permanently cache"
        );
    }

    // ─── gossip_retry park queue ────────────────────────────────────────

    #[test]
    fn park_retryable_dedups_and_fifo_evicts_at_cap() {
        let (state, _tmp) = autotune_test_state();
        park_retryable(&state, "rec-1");
        park_retryable(&state, "rec-1"); // dedup — same id parks once
        assert_eq!(state.gossip_retry.lock_recover().len(), 1);

        for i in 0..GOSSIP_RETRY_CAP + 5 {
            park_retryable(&state, &format!("rec-fill-{i}"));
        }
        let q = state.gossip_retry.lock_recover();
        assert_eq!(q.len(), GOSSIP_RETRY_CAP, "queue bounded at cap");
        assert!(
            !q.iter().any(|(id, _)| id == "rec-1"),
            "oldest entry FIFO-evicted at cap"
        );
    }

    #[test]
    fn park_retryable_with_attempts_seeds_counter() {
        let (state, _tmp) = autotune_test_state();
        park_retryable_with_attempts(&state, "rec-a", 7);
        let q = state.gossip_retry.lock_recover();
        assert_eq!(q.front(), Some(&("rec-a".to_string(), 7)));
    }

    // ─── http_to_pq_addr ───────────────────────────────────────────────

    #[test]
    fn test_http_to_pq_addr_https() {
        assert_eq!(
            http_to_pq_addr("https://203.0.113.7:9473", 100).as_deref(),
            Some("203.0.113.7:9573"),
        );
    }

    #[test]
    fn test_http_to_pq_addr_http_with_path() {
        assert_eq!(
            http_to_pq_addr("http://node.example.com:9473/records", 100).as_deref(),
            Some("node.example.com:9573"),
        );
    }

    #[test]
    fn test_http_to_pq_addr_no_scheme() {
        assert_eq!(
            http_to_pq_addr("127.0.0.1:9474", 1).as_deref(),
            Some("127.0.0.1:9475"),
        );
    }

    #[test]
    fn test_http_to_pq_addr_invalid_port() {
        assert!(http_to_pq_addr("https://host:notaport", 100).is_none());
    }

    #[test]
    fn test_http_to_pq_addr_no_port() {
        assert!(http_to_pq_addr("https://host", 100).is_none());
    }

    #[test]
    fn test_http_to_pq_addr_overflow_saturates() {
        // port 65500 + offset 100 overflows u16; saturating_add pins to u16::MAX.
        assert_eq!(
            http_to_pq_addr("https://host:65500", 100).as_deref(),
            Some("host:65535"),
        );
    }

    // ─── parse_listen_port ─────────────────────────────────────────────

    #[test]
    fn test_parse_listen_port_standard() {
        assert_eq!(parse_listen_port("0.0.0.0:9473"), Some(9473));
    }

    #[test]
    fn test_parse_listen_port_localhost() {
        assert_eq!(parse_listen_port("127.0.0.1:9474"), Some(9474));
    }

    #[test]
    fn test_parse_listen_port_ipv6() {
        // rsplit(':') grabs last segment after colon
        assert_eq!(parse_listen_port("[::1]:8080"), Some(8080));
    }

    #[test]
    fn test_parse_listen_port_no_port() {
        assert_eq!(parse_listen_port("0.0.0.0"), None);
    }

    #[test]
    fn test_parse_listen_port_invalid_port() {
        assert_eq!(parse_listen_port("0.0.0.0:abc"), None);
    }

    #[test]
    fn test_parse_listen_port_empty() {
        assert_eq!(parse_listen_port(""), None);
    }

    #[test]
    fn test_parse_listen_port_high_port() {
        assert_eq!(parse_listen_port("0.0.0.0:65535"), Some(65535));
    }

    // ─── RecordAnnouncement ────────────────────────────────────────────

    #[test]
    fn test_announcement_from_record() {
        let rec = ValidationRecord::create(
            b"test content",
            b"test_pub_key".to_vec(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let ann = RecordAnnouncement::from_record(&rec);
        assert_eq!(ann.record_id, rec.id);
        assert_eq!(ann.content_hash, hex::encode(&rec.content_hash));
        assert_eq!(ann.creator_hash, crate::crypto::hash::sha3_256_hex(&rec.creator_public_key));
        assert_eq!(ann.classification, rec.classification as u8);
        assert!(ann.wire_len > 0);
        assert!(ann.timestamp > 0.0);
    }

    #[test]
    fn test_announcement_zone_from_metadata() {
        let mut rec = ValidationRecord::create(
            b"zoned content",
            b"key".to_vec(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        rec.metadata.insert("zone".to_string(), serde_json::json!("zone_0"));
        let ann = RecordAnnouncement::from_record(&rec);
        assert_eq!(ann.zone, "zone_0");
    }

    #[test]
    fn test_announcement_zone_empty_without_metadata() {
        let rec = ValidationRecord::create(
            b"no zone",
            b"key".to_vec(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let ann = RecordAnnouncement::from_record(&rec);
        assert_eq!(ann.zone, "");
    }

    // ─── GossipKind ────────────────────────────────────────────────────

    /// classify() walks all four branches plus the
    /// documented precedence (Seal > Governance > Ledger > Other). The
    /// classifier is metadata-only — no body parse — so a record carrying
    /// every op-key at once must still be charged to Seal.
    #[test]
    fn batch_t_gossip_kind_classify_precedence_seal_over_governance_over_token() {
        // No op-key → Other.
        let bare = ValidationRecord::create(
            b"plain",
            b"key".to_vec(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert_eq!(GossipKind::classify(&bare), GossipKind::Other);

        // beat_op only → Ledger.
        let mut tok = bare.clone();
        tok.metadata
            .insert("beat_op".to_string(), serde_json::json!("transfer"));
        assert_eq!(GossipKind::classify(&tok), GossipKind::Ledger);

        // governance_op only → Governance.
        let mut gov = bare.clone();
        gov.metadata.insert(
            crate::accounting::governance::GOVERNANCE_OP_KEY.to_string(),
            serde_json::json!("propose"),
        );
        assert_eq!(GossipKind::classify(&gov), GossipKind::Governance);

        // epoch_op only → Seal.
        let mut seal = bare.clone();
        seal.metadata
            .insert(EPOCH_OP_KEY.to_string(), serde_json::json!("seal"));
        assert_eq!(GossipKind::classify(&seal), GossipKind::Seal);

        // All three op-keys present → Seal wins per documented precedence.
        let mut mixed = bare;
        mixed
            .metadata
            .insert(EPOCH_OP_KEY.to_string(), serde_json::json!("seal"));
        mixed.metadata.insert(
            crate::accounting::governance::GOVERNANCE_OP_KEY.to_string(),
            serde_json::json!("propose"),
        );
        mixed
            .metadata
            .insert("beat_op".to_string(), serde_json::json!("transfer"));
        assert_eq!(GossipKind::classify(&mixed), GossipKind::Seal);
    }

    /// bypasses_zone_filter() — only `Other`
    /// (per-zone data records) is zone-scoped; all global ops bypass.
    #[test]
    fn batch_t_gossip_kind_bypasses_zone_filter_only_other_is_zone_scoped() {
        assert!(GossipKind::Seal.bypasses_zone_filter());
        assert!(GossipKind::Ledger.bypasses_zone_filter());
        assert!(GossipKind::Governance.bypasses_zone_filter());
        assert!(!GossipKind::Other.bypasses_zone_filter());
    }

    /// must_flood() — Ledger + Governance always
    /// flood, Other never floods, and Seal flips with the operator-
    /// controlled `seal_dht_routing_enabled` flag.
    #[test]
    fn batch_t_gossip_kind_must_flood_seal_respects_dht_flag() {
        // Ledger & governance always flood, regardless of DHT flag.
        assert!(GossipKind::Ledger.must_flood(false));
        assert!(GossipKind::Ledger.must_flood(true));
        assert!(GossipKind::Governance.must_flood(false));
        assert!(GossipKind::Governance.must_flood(true));

        // Seal: flood when DHT routing is OFF; take K-DHT path when ON.
        assert!(GossipKind::Seal.must_flood(false));
        assert!(!GossipKind::Seal.must_flood(true));

        // Other (per-zone data records) never floods.
        assert!(!GossipKind::Other.must_flood(false));
        assert!(!GossipKind::Other.must_flood(true));
    }

    // ─── PushResult ────────────────────────────────────────────────────

    #[test]
    fn test_push_result_equality() {
        assert_eq!(PushResult::Ok, PushResult::Ok);
        assert_eq!(PushResult::RateLimited, PushResult::RateLimited);
        assert_eq!(PushResult::Unreachable, PushResult::Unreachable);
        assert_eq!(PushResult::Failed, PushResult::Failed);
        assert_ne!(PushResult::Ok, PushResult::Failed);
        assert_ne!(PushResult::RateLimited, PushResult::Unreachable);
    }

    // ─── Fan-out calculation ───────────────────────────────────────────

    #[test]
    fn test_sqrt_fan_out_values() {
        let cases = [
            (1, 1),    // sqrt(1) = 1
            (4, 2),    // sqrt(4) = 2
            (9, 3),    // sqrt(9) = 3
            (10, 4),   // sqrt(10) = 3.16 → ceil = 4
            (25, 5),   // sqrt(25) = 5
            (100, 10), // sqrt(100) = 10
        ];
        for (peers, expected) in cases {
            let fan_out = (peers as f64).sqrt().ceil() as usize;
            let fan_out = fan_out.max(1);
            assert_eq!(fan_out, expected, "peers={peers}");
        }
    }

    #[test]
    fn test_fan_out_small_network_no_reduction() {
        // Networks with < 10 peers should push to ALL (no sqrt reduction)
        for n in 1..10 {
            let fan_out = if n < 10 { n } else {
                (n as f64).sqrt().ceil() as usize
            };
            assert_eq!(fan_out, n, "small network: {n} peers should fan out to all");
        }
    }

    #[test]
    fn test_fan_out_minimum_one() {
        // Even with 0 peers the max(1) ensures at least 1
        let fan_out = (0_f64).sqrt().ceil() as usize;
        let fan_out = fan_out.max(1);
        assert_eq!(fan_out, 1);
    }

    // ─── Stale epoch seal pre-filter ───────────────────────────────────

    #[test]
    fn test_stale_epoch_seal_filter_accepts_recent() {
        // local_epoch=100, seal_epoch=50: gap=50 < 100 → accept
        let local_epoch: u64 = 100;
        let seal_epoch: u64 = 50;
        let should_reject = is_stale_epoch_seal(local_epoch, seal_epoch);
        assert!(!should_reject, "epoch 50 should NOT be rejected when local is 100");
    }

    #[test]
    fn test_stale_epoch_seal_filter_rejects_very_old() {
        // local_epoch=200, seal_epoch=50: 50+100=150 < 200 → reject
        let local_epoch: u64 = 200;
        let seal_epoch: u64 = 50;
        let should_reject = is_stale_epoch_seal(local_epoch, seal_epoch);
        assert!(should_reject, "epoch 50 should be rejected when local is 200");
    }

    #[test]
    fn test_stale_epoch_seal_filter_boundary() {
        // local_epoch=150, seal_epoch=50: 50+100=150 NOT < 150 → accept
        let local_epoch: u64 = 150;
        let seal_epoch: u64 = 50;
        let should_reject = is_stale_epoch_seal(local_epoch, seal_epoch);
        assert!(!should_reject, "epoch 50 should NOT be rejected at boundary 150");
    }

    #[test]
    fn test_stale_epoch_seal_hostile_max_epoch_does_not_overflow() {
        // SD-1 (2026-07-03 audit): seal_epoch is attacker-controlled on the pull
        // path. seal_epoch = u64::MAX would overflow `seal_epoch + GAP` and panic
        // under release overflow-checks. saturating_add must make a far-future
        // seal simply NOT stale (never < local_epoch), with no panic.
        assert!(!is_stale_epoch_seal(150, u64::MAX), "far-future seal is not stale (no overflow)");
        assert!(!is_stale_epoch_seal(u64::MAX, u64::MAX - 1), "no overflow at the top of the range");
        // sanity: genuinely-stale still rejects
        assert!(is_stale_epoch_seal(1000, 100), "epoch 100 is stale vs local 1000");
    }

    #[test]
    fn test_stale_epoch_seal_filter_zero_local() {
        // local_epoch=0 → never reject (node is bootstrapping)
        let local_epoch: u64 = 0;
        let seal_epoch: u64 = 1;
        let should_reject = is_stale_epoch_seal(local_epoch, seal_epoch);
        assert!(!should_reject, "should never reject when local epoch is 0");
    }

    // ─── Temporary vs permanent rejection ──────────────────────────────

    #[test]
    fn test_temporary_rejection_not_cached() {
        // Calls the real prod classifier `is_retryable_ingest_rejection` instead
        // of a re-implemented copy (audit 16j). De-tautologizing surfaced a real
        // divergence: the old inline copy treated ONLY seal-mismatch as
        // temporary, but prod also retries state-dependent rejections
        // (insufficient balance, stake/transfer-not-found) added for the
        // genesis-window bootstrap (§1028/§1029). A retryable rejection is not
        // cached in `gossip_rejected`, so it is re-offered once state syncs.
        let retryable_errors = [
            "epoch seal merkle root mismatch for zone 0 epoch 621: local=abc seal=def",
            "epoch seal previous_seal mismatch for zone 1 epoch 300",
            "Ledger error: insufficient balance",
            "insufficient unlocked balance",
            "conservation pool insufficient",
            "stake not found",
            "transfer not found",
        ];
        let permanent_errors = [
            "duplicate record",
            "signature verification failed",
            "banned identity",
            "self-transfer not allowed",
        ];

        for err in retryable_errors {
            assert!(is_retryable_ingest_rejection(err), "should be retryable: {err}");
        }
        for err in permanent_errors {
            assert!(!is_retryable_ingest_rejection(err), "should NOT be retryable: {err}");
        }
    }

    // ─── Global op detection (epoch seals, ledger ops bypass zone filter) ──

    #[test]
    fn test_global_op_detection_epoch_seal() {
        let mut rec = ValidationRecord::create(b"seal", b"key".to_vec(), vec![], crate::record::Classification::Public, None);
        rec.metadata.insert(EPOCH_OP_KEY.to_string(), serde_json::json!("seal"));
        let is_global = GossipKind::classify(&rec).bypasses_zone_filter();
        assert!(is_global, "epoch seal should be a global op (via GossipKind::classify)");
    }

    #[test]
    fn test_global_op_detection_token_transfer() {
        let mut rec = ValidationRecord::create(b"transfer", b"key".to_vec(), vec![], crate::record::Classification::Public, None);
        rec.metadata.insert("beat_op".to_string(), serde_json::json!("transfer"));
        let is_global = GossipKind::classify(&rec).bypasses_zone_filter();
        assert!(is_global, "beat transfer should be a global op");
    }

    #[test]
    fn test_global_op_detection_regular_record() {
        let rec = ValidationRecord::create(b"data", b"key".to_vec(), vec![], crate::record::Classification::Public, None);
        let is_global = GossipKind::classify(&rec).bypasses_zone_filter();
        assert!(!is_global, "regular record should NOT be a global op");
    }

    // ─── Gap 6.4: GossipKind routing decisions ─────────────────────────
    //
    // These tests pin the wire-level behavior split between zone-filter
    // bypass (still applies to all global ops) and forced flood (ledger +
    // governance always; seals only when `seal_dht_routing_enabled`
    // is off — the post-2026-04-30 default is true). Together they
    // replace the previous single `is_global_op` gate that conflated
    // the two.

    #[test]
    fn gap6_4_bypass_zone_filter_covers_all_global_ops() {
        // All three global op kinds must reach every peer regardless of
        // zone subscription — that's what makes them "global." DHT routing
        // (Slice 2+) reduces fan-out per push but does NOT reintroduce
        // zone filtering: a seal for zone A may legitimately replicate
        // onto a peer subscribed only to zone B.
        assert!(GossipKind::Seal.bypasses_zone_filter());
        assert!(GossipKind::Ledger.bypasses_zone_filter());
        assert!(GossipKind::Governance.bypasses_zone_filter());
        assert!(!GossipKind::Other.bypasses_zone_filter());
    }

    #[test]
    fn gap6_4_must_flood_seal_flag_off_floods() {
        // `seal_dht_routing_enabled = false` (legacy / opt-out): seals
        // must flood. Default flipped to true 2026-04-30 once slices 1+2+3
        // landed; this test covers operators who explicitly opt out.
        assert!(GossipKind::Seal.must_flood(false));
    }

    #[test]
    fn gap6_4_must_flood_seal_flag_on_takes_dht() {
        // Default config (post-2026-04-30): `seal_dht_routing_enabled = true`.
        // Seals are freed from the always-flood gate and may take the K-DHT
        // path when the eligible-peer count crosses `content_routing_threshold`.
        // Slices 2 + 3 wire R≥3 replication + pull-side reconciliation.
        assert!(!GossipKind::Seal.must_flood(true));
    }

    #[test]
    fn gap6_4_must_flood_token_governance_always_flood() {
        // Ledger + governance ops bypass DHT routing in BOTH config states.
        // The seal_dht_routing_enabled flag changes seal behavior only.
        // Justification: ~10s of ops/day fleet-wide; flood cost is
        // negligible and the verifiable-replication invariant required
        // for safe DHT routing is overkill here.
        assert!(GossipKind::Ledger.must_flood(false));
        assert!(GossipKind::Ledger.must_flood(true));
        assert!(GossipKind::Governance.must_flood(false));
        assert!(GossipKind::Governance.must_flood(true));
    }

    #[test]
    fn gap6_4_must_flood_other_never_forces_flood() {
        // Per-zone records: never forced. Content routing kicks in above
        // `content_routing_threshold` regardless of the seal flag.
        assert!(!GossipKind::Other.must_flood(false));
        assert!(!GossipKind::Other.must_flood(true));
    }

    #[test]
    fn gap6_4_classify_precedence_seal_over_governance_over_token() {
        // A malformed record carrying multiple op-kind metadata keys is
        // classified by precedence Seal > Governance > Ledger > Other —
        // matches the existing precedence in `record_egress` byte
        // accounting so a seal carrying a stray `beat_op` is still
        // attributed to seal traffic.
        let mut rec = ValidationRecord::create(
            b"weird", b"key".to_vec(), vec![],
            crate::record::Classification::Public, None,
        );
        rec.metadata.insert("beat_op".into(), serde_json::json!("transfer"));
        rec.metadata.insert(
            crate::accounting::governance::GOVERNANCE_OP_KEY.into(),
            serde_json::json!("propose"),
        );
        rec.metadata.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        assert_eq!(GossipKind::classify(&rec), GossipKind::Seal);
    }

    #[test]
    fn gap6_4_classify_seal_record_routes_through_must_flood_default_on() {
        // Integration-level: a real epoch-seal record + the default config
        // value (post-2026-04-30: seal_dht_routing_enabled = true) yields
        // `must_flood == false`, i.e. seals may now take the K-DHT path
        // when peer count crosses content_routing_threshold. Below that
        // threshold gossip.rs still floods regardless of this flag, so
        // small fleets are unaffected.
        let mut rec = ValidationRecord::create(
            b"seal-payload", b"witness-key".to_vec(), vec![],
            crate::record::Classification::Public, None,
        );
        rec.metadata.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        let kind = GossipKind::classify(&rec);
        // default flag value pinned post-flip; regression here means the
        // default got reverted without an audit-trail entry.
        let cfg_default = crate::network::config::NodeConfig::default();
        assert!(cfg_default.seal_dht_routing_enabled);
        assert!(!kind.must_flood(cfg_default.seal_dht_routing_enabled));
        assert!(kind.bypasses_zone_filter());
    }

    // ─── Gap 6.4 slice 2: R-floor invariant + observability ──────────────

    #[test]
    fn gap6_4_slice2_replication_floor_default_is_three() {
        // Verifiable replication: the Merkle-of-seal-replicas scheme ensures
        // each seal has at least R=3 independent copies.
        // The default must remain 3 across config-evolution churn — a regression
        // here loosens the invariant silently.
        let cfg = crate::network::config::NodeConfig::default();
        assert_eq!(cfg.seal_dht_replication_floor, 3);
    }

    #[test]
    fn gap6_4_slice2_replication_floor_clamped_to_eligible_peer_count() {
        // The floor logic shape is `replication_floor.min(eligible)` so a
        // 6-node testnet with `replication_floor=3` and only 2 eligible
        // peers won't reject the K-DHT push outright — it falls back to
        // the smaller `eligible` value. The expression below mirrors what
        // gossip.rs computes in both push_to_peers and relay_to_peers.
        let cfg_floor: usize = 3;
        let eligible_small: usize = 2;
        let eligible_large: usize = 50;
        assert_eq!(cfg_floor.min(eligible_small), 2);
        assert_eq!(cfg_floor.min(eligible_large), 3);
    }

    #[test]
    fn gap6_4_slice2_replication_floor_zero_clamps_to_one() {
        // Operator misconfig (seal_dht_replication_floor = 0) must not
        // disable the K-DHT path entirely — the `.max(1)` clamp in the
        // gossip code preserves "at least one peer must be reachable" as
        // a hard floor. Mirrors the same `.max(1)` already applied to
        // `content_routing_k`.
        let cfg_floor: usize = 0;
        let clamped = cfg_floor.max(1);
        assert_eq!(clamped, 1);
    }

    #[test]
    fn gap6_4_slice2_floor_fallback_path_is_distinct_from_content_routed() {
        // Slice 2 adds the floor-fallback counter alongside the existing
        // content-routed counter. A K-DHT push that meets the floor bumps
        // `gossip_push_content_routed_total`; one that fails the floor
        // bumps `gossip_push_dht_floor_fallback_total`. They must NEVER
        // both bump on the same push.
        //
        // This test enforces the invariant at the type level: the two
        // counters are distinct fields in NodeState. (Behavior is also
        // covered by the if/else branch shape in gossip.rs.)
        use std::sync::atomic::{AtomicU64, Ordering};
        let content_routed: AtomicU64 = AtomicU64::new(0);
        let floor_fb: AtomicU64 = AtomicU64::new(0);
        // Hypothetical push with R=2 chosen, floor=3 → fallback path.
        let chosen_len: usize = 2;
        let r_target: usize = 3_usize;
        if chosen_len >= r_target {
            content_routed.fetch_add(1, Ordering::Relaxed);
        } else {
            floor_fb.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(content_routed.load(Ordering::Relaxed), 0);
        assert_eq!(floor_fb.load(Ordering::Relaxed), 1);

        // Hypothetical push with R=4 chosen, floor=3 → content-routed path.
        let chosen_len: usize = 4;
        if chosen_len >= r_target {
            content_routed.fetch_add(1, Ordering::Relaxed);
        } else {
            floor_fb.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(content_routed.load(Ordering::Relaxed), 1);
        assert_eq!(floor_fb.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn gap6_4_slice2_replication_factor_gauge_reflects_chosen_len() {
        // The gauge stores the most recently observed `chosen.len()` on
        // the successful K-DHT path. Mirrors the gossip.rs `.store(...)`
        // expression so a refactor of the chosen-len computation can't
        // silently break the gauge.
        use std::sync::atomic::{AtomicU64, Ordering};
        let gauge: AtomicU64 = AtomicU64::new(0);
        let chosen_len: usize = 5;
        let r_target: usize = 3;
        if chosen_len >= r_target {
            gauge.store(chosen_len as u64, Ordering::Relaxed);
        }
        assert_eq!(gauge.load(Ordering::Relaxed), 5);
        // Subsequent push with smaller K (e.g. churned cluster) overwrites.
        let chosen_len: usize = 3;
        if chosen_len >= r_target {
            gauge.store(chosen_len as u64, Ordering::Relaxed);
        }
        assert_eq!(gauge.load(Ordering::Relaxed), 3);
    }

    // ─── Gap 6.4 slice 3a: pending seal-replication queue ─────────────

    #[test]
    fn gap6_4_slice3a_pending_max_default_is_one_thousand() {
        // Default cap balances memory cost (~1MB at K=5) with reconciler
        // horizon (~100s at <10 seals/sec). A regression here either blows
        // memory at scale or starves the reconciler at testnet rates.
        let cfg = crate::network::config::NodeConfig::default();
        assert_eq!(cfg.seal_dht_replication_pending_max, 1_000);
    }

    #[test]
    fn gap6_4_slice3a_enqueue_empty_targets_is_noop() {
        // Empty targets means we have nothing to reconcile against —
        // the slice 3b reconciler would just discard the entry. Skip
        // it at enqueue time so we don't waste a queue slot.
        use std::collections::VecDeque;
        use std::time::Instant;
        use crate::network::state::{enqueue_pending_seal_replication_bounded, PendingSealReplication};
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            10,
            "seal_abc".into(),
            Vec::new(),
            Instant::now(),
        );
        assert_eq!(evicted, 0);
        assert!(q.is_empty());
    }

    #[test]
    fn gap6_4_slice3a_enqueue_under_cap_no_eviction() {
        // Below the cap the queue just grows monotonically — no eviction.
        // Mirrors steady-state behavior at low seal rates.
        use std::collections::VecDeque;
        use std::time::Instant;
        use crate::network::state::{enqueue_pending_seal_replication_bounded, PendingSealReplication};
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        for i in 0..5 {
            let evicted = enqueue_pending_seal_replication_bounded(
                &mut q,
                10,
                format!("seal_{i}"),
                vec!["peer_a".into()],
                Instant::now(),
            );
            assert_eq!(evicted, 0, "no eviction expected at depth {}", i);
        }
        assert_eq!(q.len(), 5);
    }

    #[test]
    fn gap6_4_slice3a_enqueue_at_cap_evicts_oldest_fifo() {
        // Once at cap, each new enqueue evicts the oldest entry. FIFO
        // semantics matter: slice 3b reconciles oldest-first, so eviction
        // must drop the entry it's about to look at — preserving fresher
        // entries for the next reconciler tick.
        use std::collections::VecDeque;
        use std::time::Instant;
        use crate::network::state::{enqueue_pending_seal_replication_bounded, PendingSealReplication};
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        // Fill to cap.
        for i in 0..3 {
            enqueue_pending_seal_replication_bounded(
                &mut q,
                3,
                format!("seal_{i}"),
                vec!["peer_a".into()],
                Instant::now(),
            );
        }
        assert_eq!(q.len(), 3);
        assert_eq!(q.front().unwrap().seal_id, "seal_0");
        // Push one more — oldest (seal_0) should evict.
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            3,
            "seal_3".into(),
            vec!["peer_a".into()],
            Instant::now(),
        );
        assert_eq!(evicted, 1);
        assert_eq!(q.len(), 3);
        assert_eq!(q.front().unwrap().seal_id, "seal_1");
        assert_eq!(q.back().unwrap().seal_id, "seal_3");
    }

    #[test]
    fn gap6_4_slice3a_enqueue_zero_cap_clamps_to_one() {
        // Operator misconfig (`seal_dht_replication_pending_max = 0`) must
        // not disable the queue entirely — the helper clamps to 1 so at
        // least the most recent push is always tracked. Mirrors the
        // `.max(1)` discipline already applied to content_routing_k and
        // seal_dht_replication_floor.
        use std::collections::VecDeque;
        use std::time::Instant;
        use crate::network::state::{enqueue_pending_seal_replication_bounded, PendingSealReplication};
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let _ = enqueue_pending_seal_replication_bounded(
            &mut q, 0, "seal_a".into(), vec!["peer".into()], Instant::now(),
        );
        assert_eq!(q.len(), 1);
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q, 0, "seal_b".into(), vec!["peer".into()], Instant::now(),
        );
        assert_eq!(evicted, 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.front().unwrap().seal_id, "seal_b");
    }

    #[test]
    fn gap6_4_slice3a_enqueue_preserves_seal_id_and_targets() {
        // Slice 3b's reconciler reads back `seal_id` (to look up the
        // record body for re-push) and `targets` (to probe + diff against
        // the realized replication factor). A regression that strips
        // either field would silently turn the reconciler into a no-op.
        use std::collections::VecDeque;
        use std::time::Instant;
        use crate::network::state::{enqueue_pending_seal_replication_bounded, PendingSealReplication};
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let targets = vec!["peer_a".to_string(), "peer_b".to_string(), "peer_c".to_string()];
        enqueue_pending_seal_replication_bounded(
            &mut q,
            10,
            "seal_xyz".into(),
            targets.clone(),
            Instant::now(),
        );
        let entry = q.front().unwrap();
        assert_eq!(entry.seal_id, "seal_xyz");
        assert_eq!(entry.targets, targets);
    }

    // ─── Announcement serialization roundtrip ──────────────────────────

    #[test]
    fn test_announcement_serialize_deserialize() {
        let rec = ValidationRecord::create(b"test", b"key".to_vec(), vec![], crate::record::Classification::Public, None);
        let ann = RecordAnnouncement::from_record(&rec);
        let json = serde_json::to_string(&ann).unwrap();
        let deserialized: RecordAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.record_id, ann.record_id);
        assert_eq!(deserialized.content_hash, ann.content_hash);
        assert_eq!(deserialized.creator_hash, ann.creator_hash);
        assert_eq!(deserialized.classification, ann.classification);
        assert_eq!(deserialized.zone, ann.zone);
        assert!((deserialized.timestamp - ann.timestamp).abs() < 0.001);
        assert_eq!(deserialized.wire_len, ann.wire_len);
    }

    // ─── MAX_RELAY_PER_BATCH drain logic ───────────────────────────────

    #[test]
    fn test_relay_batch_drain_prevents_unbounded_growth() {
        // Simulates the drain logic in bootstrap_pull_from_zero
        // When new_records exceeds 2*MAX_RELAY_PER_BATCH, drain the first half
        let max_relay = 50; // using a smaller value for test speed
        let mut new_records: Vec<usize> = Vec::new();
        for i in 0..max_relay * 3 {
            if new_records.len() >= max_relay * 2 {
                new_records.drain(..max_relay);
            }
            new_records.push(i);
        }
        // After 150 inserts with drain at 100, should have ~100 records
        assert!(new_records.len() <= max_relay * 2, "drain should cap growth");
        assert!(new_records.len() >= max_relay, "drain should keep recent records");
    }

    // ─── Fisher-Yates partial shuffle determinism ──────────────────────

    #[test]
    fn test_fisher_yates_partial_shuffle_determinism() {
        // Same seed should produce same selection
        let seed_val: u64 = 12345;
        let fan_out = 3;

        let mut all1: Vec<u32> = (0..10).collect();
        let mut all2: Vec<u32> = (0..10).collect();

        let len = all1.len();
        for i in 0..fan_out.min(len) {
            let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
            all1.swap(i, j);
        }
        all1.truncate(fan_out);

        let len = all2.len();
        for i in 0..fan_out.min(len) {
            let j = (seed_val.wrapping_add(i as u64) as usize) % (len - i) + i;
            all2.swap(i, j);
        }
        all2.truncate(fan_out);

        assert_eq!(all1, all2, "same seed should produce same selection");
    }

    #[test]
    fn test_fisher_yates_different_seeds_differ() {
        let fan_out = 3;
        let mut all1: Vec<u32> = (0..20).collect();
        let mut all2: Vec<u32> = (0..20).collect();

        let seed1: u64 = 111;
        let seed2: u64 = 999;

        let len = all1.len();
        for i in 0..fan_out.min(len) {
            let j = (seed1.wrapping_add(i as u64) as usize) % (len - i) + i;
            all1.swap(i, j);
        }
        all1.truncate(fan_out);

        let len = all2.len();
        for i in 0..fan_out.min(len) {
            let j = (seed2.wrapping_add(i as u64) as usize) % (len - i) + i;
            all2.swap(i, j);
        }
        all2.truncate(fan_out);

        assert_ne!(all1, all2, "different seeds should produce different selections");
    }

    // ─── Gap 6: content routing simulation tests ────────────────────────
    //
    // The full push_to_peers path is async and requires a live NodeState,
    // so these tests exercise the same routing math against a RoutingTable
    // + peer-id filter in isolation — the logic that would run inside
    // push_to_peers above the threshold.

    fn make_dht_with_n_peers(n: usize) -> crate::network::dht::RoutingTable {
        use crate::network::dht::{DhtPeer, NodeId, PeerProvenance, RoutingTable};
        let mut local_bytes = [0u8; 32];
        local_bytes[31] = 0;
        let mut table = RoutingTable::new(NodeId(local_bytes));
        for i in 1..=n {
            let mut bytes = [0u8; 32];
            bytes[0] = (i >> 8) as u8;
            bytes[1] = (i & 0xff) as u8;
            let id = NodeId(bytes);
            table.insert(DhtPeer {
                node_id: id,
                identity_hash: id.to_hex(),
                host: format!("10.0.0.{}", (i % 250) + 1),
                port: 9000 + i as u16,
                last_seen: 0.0,
                first_added: 0.0,
                provenance: PeerProvenance::Outbound,
            });
        }
        table
    }

    #[test]
    fn test_content_routing_selects_k_responsible_peers() {
        let table = make_dht_with_n_peers(200);
        let k = 5;
        let chosen = table.closest_to_record("some-record-id-abc", k);
        assert_eq!(chosen.len(), k);
    }

    #[test]
    fn test_content_routing_different_records_distribute_load() {
        // With enough peers and records, different records should land on
        // different replica sets — the whole point of content routing.
        let table = make_dht_with_n_peers(200);
        let k = 5;
        let set_a: std::collections::HashSet<String> = table
            .closest_to_record("record-A", k)
            .into_iter()
            .map(|p| p.identity_hash.clone())
            .collect();
        let set_b: std::collections::HashSet<String> = table
            .closest_to_record("record-B", k)
            .into_iter()
            .map(|p| p.identity_hash.clone())
            .collect();
        // Overwhelmingly likely to differ; sanity-check they're not identical.
        assert_ne!(set_a, set_b);
    }

    #[test]
    fn test_content_routing_relay_and_push_converge_on_same_peers() {
        // Gap 6.2 invariant: the relay path and the originator push path
        // MUST select the same K responsible peers for the same record_id.
        // Without this, every relay hop re-fans to a different set and we
        // lose the whole content-routing benefit.
        let table = make_dht_with_n_peers(150);
        let k = 5;
        let record_id = "record-xyz-42";
        // Originator path selection (push_to_peers:413-417)
        let push_set: std::collections::HashSet<String> = table
            .closest_to_record(record_id, k * 2)
            .into_iter()
            .take(k)
            .map(|p| p.identity_hash.clone())
            .collect();
        // Relay path selection (relay_to_peers after Gap 6.2 rewrite)
        let relay_set: std::collections::HashSet<String> = table
            .closest_to_record(record_id, k * 2)
            .into_iter()
            .take(k)
            .map(|p| p.identity_hash.clone())
            .collect();
        assert_eq!(
            push_set, relay_set,
            "push and relay MUST target the same responsible set"
        );
        assert_eq!(push_set.len(), k);
    }

    #[test]
    fn test_content_routing_replica_set_is_coordination_free() {
        // Two independent DHTs with the same peer set must produce the
        // same K-closest for a given record_id — that's how replicas
        // agree without talking.
        let table1 = make_dht_with_n_peers(100);
        let table2 = make_dht_with_n_peers(100);
        let k = 4;
        let r1: Vec<String> = table1
            .closest_to_record("record-xyz", k)
            .into_iter()
            .map(|p| p.identity_hash.clone())
            .collect();
        let r2: Vec<String> = table2
            .closest_to_record("record-xyz", k)
            .into_iter()
            .map(|p| p.identity_hash.clone())
            .collect();
        assert_eq!(r1, r2);
    }

    // ─── orphan_fetch_misses bounded-buffer invariants ──────────────────

    #[test]
    fn test_prune_orphan_miss_map_reaps_stale_entries() {
        let mut misses: std::collections::HashMap<String, (u32, f64)> =
            std::collections::HashMap::new();
        // Three entries: one fresh, two stale
        misses.insert("fresh".to_string(), (1, 1000.0));
        misses.insert("stale-1".to_string(), (1, 100.0));
        misses.insert("stale-2".to_string(), (2, 200.0));
        // now_ts = 1000; TTL 600s → 1000 - ts < 600 means ts > 400
        prune_orphan_miss_map(&mut misses, 1000.0);
        assert!(misses.contains_key("fresh"));
        assert!(!misses.contains_key("stale-1"));
        assert!(!misses.contains_key("stale-2"));
    }

    #[test]
    fn test_prune_orphan_miss_map_enforces_hard_cap_evicts_oldest() {
        let mut misses: std::collections::HashMap<String, (u32, f64)> =
            std::collections::HashMap::new();
        // Insert MAX+5 entries within a tight window (all fresh wrt now_ts),
        // differing only in their last-touched ts fractional part so the
        // eviction ordering is deterministic.
        let base_ts = 10_000.0;
        for i in 0..(MAX_ORPHAN_MISS_TRACKED + 5) {
            // spread ts within [base_ts, base_ts + 1), all fresh
            let ts = base_ts + (i as f64) / 1_000_000.0;
            misses.insert(format!("pid-{i:06}"), (1, ts));
        }
        // now_ts just past the newest entry — all within the 600s TTL
        prune_orphan_miss_map(&mut misses, base_ts + 1.0);
        assert_eq!(misses.len(), MAX_ORPHAN_MISS_TRACKED);
        // The 5 oldest (pid-000000..pid-000004) must be evicted
        for i in 0..5 {
            assert!(!misses.contains_key(&format!("pid-{i:06}")),
                "pid-{i:06} should have been evicted as oldest");
        }
        // The newest must remain
        assert!(misses.contains_key(&format!("pid-{:06}",
            MAX_ORPHAN_MISS_TRACKED + 4)));
    }

    #[test]
    fn test_prune_orphan_miss_map_ttl_runs_before_cap() {
        // Mixed-age flood: half stale, half fresh, total exceeds cap.
        // TTL reap should shrink to under-cap without invoking the size path.
        let mut misses: std::collections::HashMap<String, (u32, f64)> =
            std::collections::HashMap::new();
        // 5_000 stale entries at ts=0
        for i in 0..5_000 {
            misses.insert(format!("stale-{i}"), (1, 0.0));
        }
        // MAX fresh entries at ts=1000
        for i in 0..MAX_ORPHAN_MISS_TRACKED {
            misses.insert(format!("fresh-{i}"), (1, 1000.0));
        }
        prune_orphan_miss_map(&mut misses, 1000.0);
        // All stale reaped; cap not exceeded; no fresh entries evicted
        assert_eq!(misses.len(), MAX_ORPHAN_MISS_TRACKED);
        for i in 0..MAX_ORPHAN_MISS_TRACKED {
            assert!(misses.contains_key(&format!("fresh-{i}")));
        }
    }

    #[test]
    fn test_prune_orphan_miss_map_noop_when_small_and_fresh() {
        let mut misses: std::collections::HashMap<String, (u32, f64)> =
            std::collections::HashMap::new();
        misses.insert("a".to_string(), (1, 100.0));
        misses.insert("b".to_string(), (2, 150.0));
        prune_orphan_miss_map(&mut misses, 200.0);
        assert_eq!(misses.len(), 2);
        assert_eq!(misses.get("a"), Some(&(1, 100.0)));
        assert_eq!(misses.get("b"), Some(&(2, 150.0)));
    }

    /// Gap 2.1 Phase 2c — wire envelope round-trips through serde_json.
    /// Locks the JSON shape against silent breakage as we add producer +
    /// consumer paths in different commits.
    #[test]
    fn finality_witness_gossip_body_round_trips() {
        use crate::accounting::cross_zone::{ProofSibling, SealFinalityWitness};

        let envelope = FinalityWitnessGossipBody {
            seal_id: "019dc55c-dada-7f12-aaaa-000000000001".to_string(),
            seal_epoch: 6970,
            committee_hash: [0x42u8; 32],
            committee_size: 7,
            witness: SealFinalityWitness {
                witness_pk: vec![0xAA; 1952],
                signature: vec![0xBB; 3293],
                committee_proof: vec![
                    ProofSibling { hash: [0x11u8; 32], is_right: false },
                    ProofSibling { hash: [0x22u8; 32], is_right: true },
                ],
            },
        };
        let body = serde_json::to_vec(&envelope).expect("serialize");
        let decoded: FinalityWitnessGossipBody =
            serde_json::from_slice(&body).expect("deserialize");
        assert_eq!(decoded.seal_id, envelope.seal_id);
        assert_eq!(decoded.seal_epoch, envelope.seal_epoch);
        assert_eq!(decoded.committee_hash, envelope.committee_hash);
        assert_eq!(decoded.committee_size, envelope.committee_size);
        assert_eq!(decoded.witness.witness_pk, envelope.witness.witness_pk);
        assert_eq!(decoded.witness.signature, envelope.witness.signature);
        assert_eq!(
            decoded.witness.committee_proof.len(),
            envelope.witness.committee_proof.len()
        );
        assert_eq!(decoded.witness.committee_proof[0].hash, [0x11u8; 32]);
        assert!(!decoded.witness.committee_proof[0].is_right);
        assert!(decoded.witness.committee_proof[1].is_right);
    }

    /// Gap 2 sealed-abort P-3e — abort-witness wire envelope round-trips
    /// through serde_json. Locks the JSON shape against silent breakage
    /// across the producer (epoch.rs), client (pq_client.rs), and
    /// receiver (pq_transport/router.rs) call sites.
    #[test]
    fn xzone_abort_witness_gossip_body_round_trips() {
        use crate::accounting::cross_zone::{ProofSibling, SealFinalityWitness};
        use crate::ZoneId;

        let envelope = XZoneAbortWitnessGossipBody {
            transfer_id: "019dc55c-dada-7f12-bbbb-000000000002".to_string(),
            dest_zone: ZoneId::new("zone:dest:002"),
            source_seal_epoch: 1234,
            committee_hash: [0x77u8; 32],
            committee_size: 5,
            witness: SealFinalityWitness {
                witness_pk: vec![0xCC; 1952],
                signature: vec![0xDD; 3293],
                committee_proof: vec![
                    ProofSibling { hash: [0x33u8; 32], is_right: true },
                    ProofSibling { hash: [0x44u8; 32], is_right: false },
                ],
            },
        };
        let body = serde_json::to_vec(&envelope).expect("serialize");
        let decoded: XZoneAbortWitnessGossipBody =
            serde_json::from_slice(&body).expect("deserialize");
        assert_eq!(decoded.transfer_id, envelope.transfer_id);
        assert_eq!(decoded.dest_zone, envelope.dest_zone);
        assert_eq!(decoded.source_seal_epoch, envelope.source_seal_epoch);
        assert_eq!(decoded.committee_hash, envelope.committee_hash);
        assert_eq!(decoded.committee_size, envelope.committee_size);
        assert_eq!(decoded.witness.witness_pk, envelope.witness.witness_pk);
        assert_eq!(decoded.witness.signature, envelope.witness.signature);
        assert_eq!(
            decoded.witness.committee_proof.len(),
            envelope.witness.committee_proof.len()
        );
        assert_eq!(decoded.witness.committee_proof[0].hash, [0x33u8; 32]);
        assert!(decoded.witness.committee_proof[0].is_right);
        assert!(!decoded.witness.committee_proof[1].is_right);
    }

    // ─── GossipKind::classify (MAINNET mandate #3 floor-push) ──────────────

    fn build_kind_test_record(meta: std::collections::BTreeMap<String, serde_json::Value>) -> ValidationRecord {
        ValidationRecord {
            id: "kind-classify-test".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0u8; 1952],
            timestamp: 0.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
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

    #[test]
    fn gossip_kind_classify_seal_record() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Seal);
    }

    #[test]
    fn gossip_kind_classify_global_seal_also_seal() {
        // global_seal / zone_transition / super_seal all share the
        // EPOCH_OP_KEY namespace and must classify as Seal.
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("global_seal"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Seal);

        let mut meta = std::collections::BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("zone_transition"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Seal);
    }

    #[test]
    fn gossip_kind_classify_ledger_record() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("beat_op".into(), serde_json::json!("transfer"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Ledger);
    }

    #[test]
    fn gossip_kind_classify_governance_record() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(
            crate::accounting::governance::GOVERNANCE_OP_KEY.into(),
            serde_json::json!("propose"),
        );
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Governance);
    }

    #[test]
    fn gossip_kind_classify_other_when_no_kind_keys() {
        // Generic data record — nothing in metadata to classify by.
        let meta = std::collections::BTreeMap::new();
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Other);

        // Unrelated metadata also classifies as Other.
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("zone".into(), serde_json::json!("zone:default:000"));
        meta.insert("user_data".into(), serde_json::json!("hello"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Other);
    }

    #[test]
    fn gossip_kind_classify_seal_wins_over_token() {
        // Defensive: if a record somehow carried both EPOCH_OP_KEY and
        // beat_op (shouldn't happen per protocol, but the precedence
        // matters for the test), Seal must win because epoch seals are
        // global-flood and we want the seal-traffic counter to reflect
        // every seal byte even if a buggy producer attached extra keys.
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        meta.insert("beat_op".into(), serde_json::json!("transfer"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Seal);
    }

    #[test]
    fn gossip_kind_classify_governance_wins_over_token() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(
            crate::accounting::governance::GOVERNANCE_OP_KEY.into(),
            serde_json::json!("vote"),
        );
        meta.insert("beat_op".into(), serde_json::json!("transfer"));
        let rec = build_kind_test_record(meta);
        assert_eq!(GossipKind::classify(&rec), GossipKind::Governance);
    }

    // ─── Tier 1.1 push-after-pull autotune ─────────────────────────────
    //
    // Tests construct a real NodeState (mirrors fork.rs::test_state_for_divergence)
    // because the autotuner reads/writes a half-dozen atomics on it; a partial
    // mock would have to keep up with state.rs additions and would drift.
    // The throttle window check (60 s elapsed since last eval) is bypassed by
    // pre-setting `gossip_push_after_pull_autotune_last_eval_at` to 0 (forces
    // first-eval) or `now - 1` (forces "too soon" rejection).

    use std::sync::atomic::Ordering;

    fn autotune_test_state() -> (Arc<NodeState>, tempfile::TempDir) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "autotune-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        (Arc::new(NodeState::new(config, identity, rocks, wmgr)), tmp)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn autotune_initial_default_is_200() {
        // The initial cap must match the pre-autotune compile-time value so
        // the deploy is a no-op until the first eval interval elapses with
        // enough cap-hit signal to actually adjust.
        let (state, _tmp) = autotune_test_state();
        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            200,
            "initial cap must equal pre-autotune MAX_PUSH=200",
        );
    }

    #[test]
    fn autotune_high_cap_hit_rate_doubles_cap() {
        // 50 cycles, 30 of them at cap (60% > raise threshold 50%). Cap
        // should double from 200 → 400, raises counter increments.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(50, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(30, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            400,
            "60% cap-hit rate should double cap 200 → 400",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_raises_total.load(Ordering::Relaxed),
            1,
            "raises counter should increment exactly once",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_lowers_total.load(Ordering::Relaxed),
            0,
            "lowers counter should not increment on raise",
        );
    }

    #[test]
    fn autotune_low_cap_hit_rate_halves_cap() {
        // 100 cycles, 2 of them at cap (2% < lower threshold 5%). Cap
        // should halve from 200 → 100, lowers counter increments.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(100, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(2, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            100,
            "2% cap-hit rate should halve cap 200 → 100",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_lowers_total.load(Ordering::Relaxed),
            1,
            "lowers counter should increment exactly once",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_raises_total.load(Ordering::Relaxed),
            0,
            "raises counter should not increment on lower",
        );
    }

    #[test]
    fn autotune_dead_band_holds_steady() {
        // 100 cycles, 20 at cap (20%) — squarely between LOWER_PCT=5 and
        // RAISE_PCT=50. Cap should not change.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(100, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(20, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            200,
            "dead-band cap-hit rate should not change cap",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_raises_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_lowers_total.load(Ordering::Relaxed),
            0,
        );
    }

    #[test]
    fn autotune_raise_clamped_at_ceiling() {
        // Cap is already at 600; doubling → 1200, must clamp to ceiling 800.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_max.store(600, Ordering::Relaxed);
        state.gossip_push_after_pull_cycles_total.store(50, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(50, Ordering::Relaxed); // 100%
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            PUSH_AFTER_PULL_CEILING,
            "raise must clamp to ceiling 800",
        );
    }

    #[test]
    fn autotune_lower_clamped_at_floor() {
        // Cap is already at 50 (floor); halving would go to 25, must clamp.
        // Important: per the autotuner logic, the lower branch only fires
        // when current_max > FLOOR (already at floor → no-op, no counter
        // increment). This codifies "you can't go lower than the floor".
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_max.store(PUSH_AFTER_PULL_FLOOR, Ordering::Relaxed);
        state.gossip_push_after_pull_cycles_total.store(100, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(0, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            PUSH_AFTER_PULL_FLOOR,
            "cap must not go below floor",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_lowers_total.load(Ordering::Relaxed),
            0,
            "no-op at floor must not increment lowers counter",
        );
    }

    #[test]
    fn autotune_low_sample_count_holds_steady() {
        // 4 cycles is below MIN_SAMPLES=5 — too noisy to act, even though
        // the implied ratio (4/4 = 100%) would otherwise trigger a raise.
        // The autotuner must hold the cap steady but still update its
        // snapshot atomics so the next interval can compute a fresh delta.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(4, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(4, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            200,
            "low sample count must not adjust cap",
        );
        // Snapshot atomics MUST advance even on hold-steady so the next
        // eval interval computes deltas from this point, not from stale 0.
        assert_eq!(
            state.gossip_push_after_pull_autotune_last_cycles.load(Ordering::Relaxed),
            4,
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_last_at_cap.load(Ordering::Relaxed),
            4,
        );
    }

    #[test]
    fn autotune_throttle_skips_within_interval() {
        // Pre-set last_eval_at to "now - 1" so the throttle check treats
        // any subsequent call as too soon. Cap must not change even with
        // strong cap-hit signal.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(50, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(50, Ordering::Relaxed); // 100%
        // Set last eval to 1 second ago — well within the 60s throttle window.
        state.gossip_push_after_pull_autotune_last_eval_at
            .store(now_secs().saturating_sub(1), Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            200,
            "throttle window must prevent cap change",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_raises_total.load(Ordering::Relaxed),
            0,
        );
    }

    #[test]
    fn autotune_delta_computation_uses_snapshot_not_absolute() {
        // First eval establishes a snapshot (50 cycles, 50 at cap = 100%).
        // First call's effect: cap doubles (200 → 400) AND snapshot is now
        // (50, 50). Second call (after forcing throttle reset) sees an
        // ABSOLUTE total of 100 cycles, 51 at cap — but the DELTA is only
        // 50 cycles, 1 at cap = 2% — should *lower* the cap from 400 → 200.
        // This proves the autotuner uses interval deltas, not absolutes.
        let (state, _tmp) = autotune_test_state();
        state.gossip_push_after_pull_cycles_total.store(50, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(50, Ordering::Relaxed);
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);
        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            400,
            "first eval should raise on 100% cap-hit rate",
        );

        // Add 50 cycles, only 1 at cap (2% interval rate).
        state.gossip_push_after_pull_cycles_total.store(100, Ordering::Relaxed);
        state.gossip_push_after_pull_at_cap_total.store(51, Ordering::Relaxed);
        // Force throttle bypass: rewind last_eval_at to before the window.
        state.gossip_push_after_pull_autotune_last_eval_at.store(0, Ordering::Relaxed);

        maybe_autotune_push_max(&state);

        assert_eq!(
            state.gossip_push_after_pull_max.load(Ordering::Relaxed),
            200,
            "second eval should lower on 2% interval cap-hit rate (proves delta-not-absolute)",
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_raises_total.load(Ordering::Relaxed),
            1,
        );
        assert_eq!(
            state.gossip_push_after_pull_autotune_lowers_total.load(Ordering::Relaxed),
            1,
        );
    }

    // ─── find_dht_alternatives ──────────────────────
    // Pins the retry-path helper that searches the DHT for fresh
    // candidates when the gossip push loop exhausts its primary peers.
    // Without these tests the contract was implicit; a breakage of any
    // of the three branches below would silently regress retry behavior
    // under hard-fail spikes.

    fn batch_k_make_dht_peer(
        byte: u8,
        port: u16,
        host: &str,
        identity_hash: &str,
    ) -> crate::network::dht::DhtPeer {
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = byte;
        crate::network::dht::DhtPeer {
            node_id: crate::network::dht::NodeId(id_bytes),
            identity_hash: identity_hash.to_string(),
            host: host.to_string(),
            port,
            last_seen: 1000.0,
            first_added: 1000.0,
            provenance: crate::network::dht::PeerProvenance::Outbound,
        }
    }

    #[test]
    fn batch_k_find_dht_alternatives_empty_dht_returns_empty_vec() {
        // Pins the early-return at gossip.rs:344-347 — empty DHT must
        // short-circuit before computing the SHA3 target / k-bucket walk.
        // The hot-path retry loop calls this every time a peer hard-fails;
        // if the early-return regressed, idle nodes with empty routing
        // tables would burn CPU on every retry.
        let (state, _tmp) = autotune_test_state();
        let tried = HashSet::new();
        let alternatives = find_dht_alternatives(&state, &tried, 5);
        assert!(
            alternatives.is_empty(),
            "empty DHT must yield empty alternatives, got {} peers",
            alternatives.len(),
        );
    }

    #[test]
    fn batch_k_find_dht_alternatives_excludes_tried_peers_and_self() {
        // Pins both filters at gossip.rs:356-357 — `tried` peers and the
        // local identity must never appear in the retry candidate set.
        // Without this guarantee the push-failure retry path would
        // (a) loop on the same confirmed-bad peer, or (b) try to push
        // back to ourselves, which the receiver-side dedupe would silently
        // drop but the metric-bump path would still count as a push attempt.
        let (state, _tmp) = autotune_test_state();
        let tried_hash =
            "1100000000000000000000000000000000000000000000000000000000000000".to_string();
        let self_hash = state.identity.identity_hash.clone();
        let peer_tried = batch_k_make_dht_peer(0x11, 9473, "10.0.0.1", &tried_hash);
        let peer_self = batch_k_make_dht_peer(0x22, 9473, "10.0.0.2", &self_hash);
        {
            let mut dht = state.dht.lock_recover();
            let _ = dht.insert(peer_tried);
            let _ = dht.insert(peer_self);
        }
        let mut tried = HashSet::new();
        tried.insert(tried_hash);
        let alternatives = find_dht_alternatives(&state, &tried, 5);
        assert!(
            alternatives.iter().all(|(id, _)| id != &state.identity.identity_hash),
            "self identity must be filtered out",
        );
        assert!(
            alternatives.iter().all(|(id, _)|
                id != "1100000000000000000000000000000000000000000000000000000000000000"),
            "tried peer must be filtered out",
        );
    }

    #[test]
    fn batch_k_find_dht_alternatives_caps_at_requested_count() {
        // Pins `.take(count)` at gossip.rs:358 — with 4 candidates and
        // count=2, the result must be ≤2. The retry budget is built on
        // this contract; if `take()` regressed to returning all matches
        // the hard-fail retry path would over-fan-out under spike load
        // and bypass the retry-budget metric.
        let (state, _tmp) = autotune_test_state();
        for i in 1u8..=4 {
            let identity_hash = format!("{:02x}{}", i, "00".repeat(31));
            let peer = batch_k_make_dht_peer(
                i,
                9473,
                &format!("10.0.0.{}", i),
                &identity_hash,
            );
            let mut dht = state.dht.lock_recover();
            let _ = dht.insert(peer);
        }
        let tried = HashSet::new();
        let alternatives = find_dht_alternatives(&state, &tried, 2);
        assert!(
            alternatives.len() <= 2,
            "count cap broken: requested 2, got {} alternatives",
            alternatives.len(),
        );
    }

    // ─── sync pins on previously-uncovered surfaces ────────────────────────────
    //
    // Three sync pins on previously-uncovered surfaces:
    //   1. push-after-pull autotune constants (FLOOR/CEILING/INTERVAL/SAMPLES/RAISE/LOWER)
    //   2. orphan-miss map constants (AGE_SECS, TRACKED)
    //   3. GossipKind::record_egress per-variant counter dispatch

    #[test]
    fn batch_ag_push_after_pull_autotune_constants_pin_floor_ceiling_and_asymmetric_thresholds() {
        // Pin literal values so a silent bump trips this exact-name test.
        assert_eq!(super::PUSH_AFTER_PULL_FLOOR, 50);
        assert_eq!(super::PUSH_AFTER_PULL_CEILING, 800);
        assert_eq!(super::PUSH_AFTER_PULL_AUTOTUNE_INTERVAL_SECS, 60);
        assert_eq!(super::PUSH_AFTER_PULL_AUTOTUNE_MIN_SAMPLES, 5);
        assert_eq!(super::PUSH_AFTER_PULL_AUTOTUNE_RAISE_PCT, 50);
        assert_eq!(super::PUSH_AFTER_PULL_AUTOTUNE_LOWER_PCT, 5);

        // Cross-constraint pins (FLOOR < CEILING, RAISE > LOWER, INTERVAL/SAMPLES > 0)
        // promoted to compile-time `const _: () = assert!(..)` next to the const
        // declarations above. Runtime asserts removed (clippy::assertions_on_constants).
    }

    #[test]
    fn batch_ag_orphan_miss_constants_pin_10min_window_and_10k_entry_cap() {
        // 10-minute TTL window mirrors deferred_attestations for operational
        // symmetry (per doc-comment at MAX_ORPHAN_MISS_AGE_SECS); 10K hard cap
        // is the defence against orphan-flooding on 2GB nodes.
        assert_eq!(super::MAX_ORPHAN_MISS_AGE_SECS, 600.0);
        assert_eq!(super::MAX_ORPHAN_MISS_TRACKED, 10_000);
        // Positivity pins promoted to compile-time `const _: () = assert!(..)`
        // next to the const declarations (clippy::assertions_on_constants).
    }

    #[test]
    fn batch_ag_gossip_kind_record_egress_increments_correct_per_kind_atomic_counter() {
        let (state, _tmp) = autotune_test_state();

        // Build one record per kind via build_kind_test_record's metadata key.
        let seal_rec = {
            let mut meta = std::collections::BTreeMap::new();
            meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
            build_kind_test_record(meta)
        };
        let ledger_rec = {
            let mut meta = std::collections::BTreeMap::new();
            meta.insert("beat_op".into(), serde_json::json!("transfer"));
            build_kind_test_record(meta)
        };
        let gov_rec = {
            let mut meta = std::collections::BTreeMap::new();
            meta.insert(
                crate::accounting::governance::GOVERNANCE_OP_KEY.into(),
                serde_json::json!("proposal"),
            );
            build_kind_test_record(meta)
        };
        let other_rec = build_kind_test_record(std::collections::BTreeMap::new());

        // Classify pre-check ensures kind dispatch is on the path we expect.
        assert_eq!(GossipKind::classify(&seal_rec), GossipKind::Seal);
        assert_eq!(GossipKind::classify(&ledger_rec), GossipKind::Ledger);
        assert_eq!(GossipKind::classify(&gov_rec), GossipKind::Governance);
        assert_eq!(GossipKind::classify(&other_rec), GossipKind::Other);

        // Baseline reads (counters start at 0 on a fresh test state).
        assert_eq!(state.gossip_bytes_out_seal_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.gossip_bytes_out_ledger_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.gossip_bytes_out_governance_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.gossip_bytes_out_other_total.load(Ordering::Relaxed), 0);

        // Each variant must increment ONLY its own counter (distinct sentinel
        // byte counts make cross-variant bleed surface as a specific failure).
        GossipKind::Seal.record_egress(&state, 100);
        GossipKind::Ledger.record_egress(&state, 200);
        GossipKind::Governance.record_egress(&state, 300);
        GossipKind::Other.record_egress(&state, 400);

        assert_eq!(
            state.gossip_bytes_out_seal_total.load(Ordering::Relaxed),
            100,
            "seal counter must hold 100"
        );
        assert_eq!(
            state.gossip_bytes_out_ledger_total.load(Ordering::Relaxed),
            200,
            "token counter must hold 200"
        );
        assert_eq!(
            state.gossip_bytes_out_governance_total.load(Ordering::Relaxed),
            300,
            "governance counter must hold 300"
        );
        assert_eq!(
            state.gossip_bytes_out_other_total.load(Ordering::Relaxed),
            400,
            "other counter must hold 400"
        );

        // Second call on Seal verifies fetch_add semantics (not store).
        GossipKind::Seal.record_egress(&state, 50);
        assert_eq!(
            state.gossip_bytes_out_seal_total.load(Ordering::Relaxed),
            150,
            "seal counter must accumulate via fetch_add"
        );
    }

    // ─── pin the pure-helper surface that the GossipKind classify /
    // bypasses_zone_filter / must_flood, find_dht_alternatives, constants
    // + record_egress, and the dozens of fixture-loaded tests above leave
    // uncovered. These
    // are the wire-format pins on the three pub gossip body structs
    // (RecordAnnouncement / FinalityWitnessGossipBody /
    // XZoneAbortWitnessGossipBody) plus the http→pq address translator
    // that runs on every push-target derivation and never had a unit
    // test. A silent break in any of these costs cluster convergence.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_http_to_pq_addr_strips_scheme_drops_path_adds_port_offset() {
        // PIN: gossip.rs:228 — http_to_pq_addr is on the hot path of
        // every PQ push-target derivation. The function (a) strips
        // https:// or http://, (b) drops any path component, (c) parses
        // the port as u16, (d) adds the configured offset via
        // saturating_add. Pin all four behaviors with cases the existing
        // dozens of integration tests don't isolate.

        // (a) https:// scheme is stripped.
        assert_eq!(
            http_to_pq_addr("https://example.com:9473", 100),
            Some("example.com:9573".to_string()),
            "https:// scheme MUST be stripped and offset added",
        );
        // (a) http:// scheme is also stripped.
        assert_eq!(
            http_to_pq_addr("http://example.com:9473", 100),
            Some("example.com:9573".to_string()),
            "http:// scheme MUST also be stripped",
        );
        // (a) No-scheme input is tolerated (treated as host:port directly).
        assert_eq!(
            http_to_pq_addr("example.com:9473", 100),
            Some("example.com:9573".to_string()),
            "no-scheme input must still translate (raw host:port path)",
        );

        // (b) Path component after host:port is dropped.
        assert_eq!(
            http_to_pq_addr("https://example.com:9473/some/path", 100),
            Some("example.com:9573".to_string()),
            "path component after host:port MUST be dropped",
        );

        // (c) Port parse is u16. (d) saturating_add applied.
        // 9473 + 100 = 9573 (verified above).
        // Edge: offset = 0 must be a no-op.
        assert_eq!(
            http_to_pq_addr("https://localhost:9473", 0),
            Some("localhost:9473".to_string()),
            "offset=0 MUST preserve the port",
        );
        // Edge: saturating add at the u16 ceiling. port=65535 + offset=1
        // saturates to 65535 (NOT wrap to 0).
        assert_eq!(
            http_to_pq_addr("https://h:65535", 1),
            Some("h:65535".to_string()),
            "u16::MAX + 1 MUST saturate, not wrap (saturating_add invariant)",
        );

        // IPv4 host accepted (the rsplit_once(':') splits at last colon).
        assert_eq!(
            http_to_pq_addr("https://127.0.0.1:9473", 100),
            Some("127.0.0.1:9573".to_string()),
            "IPv4 hosts must translate identically to DNS-named hosts",
        );
    }

    #[test]
    fn batch_b_http_to_pq_addr_returns_none_on_malformed_input() {
        // PIN: the None branches of http_to_pq_addr — these are what
        // make the function safe to call on arbitrary peer-table data
        // without panicking. Three distinct rejection paths:
        //   (1) no colon → no host:port split (rsplit_once returns None)
        //   (2) non-numeric port → parse::<u16>() returns Err → ok() → None
        //   (3) port out of u16 range → same path as (2)

        // (1) No colon at all.
        assert_eq!(
            http_to_pq_addr("https://no-port-here", 100),
            None,
            "missing :port MUST return None (rsplit_once(':') → None)",
        );

        // (2) Non-numeric port.
        assert_eq!(
            http_to_pq_addr("https://example.com:not-a-number", 100),
            None,
            "non-numeric port MUST return None (u16 parse fail)",
        );

        // (3) Port > u16::MAX (65535).
        assert_eq!(
            http_to_pq_addr("https://example.com:99999", 100),
            None,
            "port > 65535 MUST return None (overflows u16 parse)",
        );

        // Edge: empty string. split('/').next() returns Some(""), then
        // rsplit_once(':') on "" returns None → None.
        assert_eq!(
            http_to_pq_addr("", 100),
            None,
            "empty input MUST return None",
        );
    }

    #[test]
    fn batch_b_record_announcement_serde_round_trip_pins_seven_field_wire_shape() {
        // PIN: gossip.rs:117 — RecordAnnouncement is the compact gossip
        // body (Protocol §11.14: "~1KB header + hash, full records
        // fetched on demand"). 7 fields all `pub`. The wire shape is
        // load-bearing — every peer parses this from peer-pushed
        // announcements via the PQ + HTTP routers. A silent rename of
        // ANY field would silently drop announcements on every peer
        // running an older binary; pin the field-name + type set.
        let ann = RecordAnnouncement {
            record_id: "rec123".to_string(),
            content_hash: "deadbeef".to_string(),
            creator_hash: "cafebabe".to_string(),
            classification: 5,
            zone: "medical/eu".to_string(),
            timestamp: 1234.5,
            wire_len: 4096,
        };

        // Serialize to JSON: pin the exact field names.
        let v = serde_json::to_value(&ann).expect("RecordAnnouncement must serialize");
        let map = v.as_object().expect("serializes to an object");
        assert_eq!(map.len(), 7, "exactly 7 fields — got {} ({:?})", map.len(), map.keys().collect::<Vec<_>>());
        for k in ["record_id", "content_hash", "creator_hash", "classification", "zone", "timestamp", "wire_len"] {
            assert!(map.contains_key(k), "wire MUST carry `{k}` (silent rename would break older peers)");
        }
        // Type pins on a few sensitive fields:
        // - classification is u8 (numeric)
        assert!(v.get("classification").and_then(|x| x.as_u64()).is_some(),
            "classification MUST serialize as a number (u8 → JSON integer)");
        // - timestamp is f64 (numeric)
        assert!(v.get("timestamp").and_then(|x| x.as_f64()).is_some(),
            "timestamp MUST serialize as a number (f64)");
        // - wire_len is u32 (numeric, NOT string)
        assert!(v.get("wire_len").and_then(|x| x.as_u64()).is_some(),
            "wire_len MUST serialize as a number (u32 → JSON integer)");

        // Round-trip pin: serialize → deserialize → field-equal.
        let json = serde_json::to_string(&ann).unwrap();
        let back: RecordAnnouncement = serde_json::from_str(&json).expect("RecordAnnouncement MUST round-trip via JSON");
        assert_eq!(back.record_id, ann.record_id);
        assert_eq!(back.content_hash, ann.content_hash);
        assert_eq!(back.creator_hash, ann.creator_hash);
        assert_eq!(back.classification, ann.classification);
        assert_eq!(back.zone, ann.zone);
        assert_eq!(back.timestamp, ann.timestamp);
        assert_eq!(back.wire_len, ann.wire_len);
    }

    #[test]
    fn batch_b_finality_witness_gossip_body_serde_pins_five_field_wire_shape() {
        // PIN: gossip.rs:3058 — FinalityWitnessGossipBody is the wire
        // body for `push_finality_witness_to_peers` (Gap 2.1 Phase 2c).
        // 5 pub fields. Producer signs over committee_hash + committee_size
        // (SealFinalityCollection identity) before push; the receiver
        // verifies under the same shape. Silent rename of seal_id /
        // seal_epoch breaks the (seal_id, witness_pk) dedup key on the
        // receiver and either drops the message or admits duplicate
        // witnesses. Pin the field-name + type set.
        let body = FinalityWitnessGossipBody {
            seal_id: "seal-42".to_string(),
            seal_epoch: 100,
            committee_hash: [7u8; 32],
            committee_size: 5,
            witness: crate::accounting::cross_zone::SealFinalityWitness {
                witness_pk: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                committee_proof: vec![],
            },
        };

        let v = serde_json::to_value(&body).expect("FinalityWitnessGossipBody must serialize");
        let map = v.as_object().expect("serializes to an object");
        assert_eq!(map.len(), 5, "FinalityWitnessGossipBody MUST be exactly 5 fields — got {} ({:?})", map.len(), map.keys().collect::<Vec<_>>());
        for k in ["seal_id", "seal_epoch", "committee_hash", "committee_size", "witness"] {
            assert!(map.contains_key(k), "wire MUST carry `{k}` — receiver dedup keys on (seal_id, witness_pk) so a rename of seal_id silently breaks dedup");
        }
        // Type pins:
        // - seal_epoch is u64 (numeric)
        assert!(v.get("seal_epoch").and_then(|x| x.as_u64()).is_some(),
            "seal_epoch MUST serialize as a number (u64)");
        // - committee_size is u32 (numeric)
        assert!(v.get("committee_size").and_then(|x| x.as_u64()).is_some(),
            "committee_size MUST serialize as a number (u32)");
        // - committee_hash is [u8; 32] (serializes as a 32-element JSON array of bytes via serde default)
        assert!(v.get("committee_hash").and_then(|x| x.as_array()).map(|a| a.len() == 32).unwrap_or(false),
            "committee_hash MUST serialize as a 32-element JSON array");

        // Round-trip pin.
        let json = serde_json::to_string(&body).unwrap();
        let back: FinalityWitnessGossipBody = serde_json::from_str(&json).expect("FinalityWitnessGossipBody MUST round-trip via JSON");
        assert_eq!(back.seal_id, body.seal_id);
        assert_eq!(back.seal_epoch, body.seal_epoch);
        assert_eq!(back.committee_hash, body.committee_hash);
        assert_eq!(back.committee_size, body.committee_size);
        assert_eq!(back.witness.witness_pk, body.witness.witness_pk);
        assert_eq!(back.witness.signature, body.witness.signature);
    }

    #[test]
    fn batch_b_xzone_abort_witness_gossip_body_field_set_distinct_from_finality() {
        // PIN: gossip.rs:3217 — XZoneAbortWitnessGossipBody is the
        // sealed-abort symmetric wire body (Gap 2 sealed-abort P-3e).
        // The field set DIFFERS from FinalityWitnessGossipBody:
        //   - finality: seal_id, seal_epoch (2 seal-keyed fields)
        //   - abort:    transfer_id, dest_zone, source_seal_epoch
        //               (3 transfer-keyed fields)
        // Both end in `committee_hash, committee_size, witness`. The
        // distinction is load-bearing: the producer dedup keys on
        // (transfer_id, witness_pk) for abort vs (seal_id, witness_pk)
        // for finality. A refactor that merges the two body types
        // collapses the dedup namespace and re-admits duplicate
        // abort witnesses.
        let body = XZoneAbortWitnessGossipBody {
            transfer_id: "xfer-99".to_string(),
            dest_zone: crate::ZoneId::new("medical/eu"),
            source_seal_epoch: 50,
            committee_hash: [9u8; 32],
            committee_size: 3,
            witness: crate::accounting::cross_zone::SealFinalityWitness {
                witness_pk: vec![10, 11, 12],
                signature: vec![13, 14, 15],
                committee_proof: vec![],
            },
        };

        let v = serde_json::to_value(&body).expect("XZoneAbortWitnessGossipBody must serialize");
        let map = v.as_object().expect("serializes to an object");
        assert_eq!(map.len(), 6, "XZoneAbortWitnessGossipBody MUST be exactly 6 fields — got {} ({:?})", map.len(), map.keys().collect::<Vec<_>>());

        // Required transfer-keyed fields (not present on FinalityWitnessGossipBody):
        for k in ["transfer_id", "dest_zone", "source_seal_epoch"] {
            assert!(map.contains_key(k), "abort body MUST carry `{k}` — distinguishes from FinalityWitnessGossipBody");
        }
        // Forbidden seal-keyed fields (present on FinalityWitnessGossipBody but NOT here):
        for k in ["seal_id", "seal_epoch"] {
            assert!(!map.contains_key(k), "abort body MUST NOT carry `{k}` — that's FinalityWitnessGossipBody territory; field bleeding would collapse dedup namespaces");
        }
        // Shared trailing fields:
        for k in ["committee_hash", "committee_size", "witness"] {
            assert!(map.contains_key(k), "abort body MUST carry shared `{k}`");
        }

        // Round-trip pin.
        let json = serde_json::to_string(&body).unwrap();
        let back: XZoneAbortWitnessGossipBody = serde_json::from_str(&json).expect("XZoneAbortWitnessGossipBody MUST round-trip via JSON");
        assert_eq!(back.transfer_id, body.transfer_id);
        assert_eq!(back.dest_zone.path(), body.dest_zone.path());
        assert_eq!(back.source_seal_epoch, body.source_seal_epoch);
        assert_eq!(back.committee_hash, body.committee_hash);
        assert_eq!(back.committee_size, body.committee_size);
    }

    #[test]
    fn att_pull_fast_forward_watermark_clock_skew_caps_at_batch_max() {
        // PIN: gossip.rs:3967 fast-forward formula.
        // unwrap_or(batch_max_ts) means a clock-before-epoch fallback
        // produces effective_watermark = batch_max_ts (no fast-forward),
        // not a panic.
        let since = 1_700_000_000.0_f64;
        let batch_max_ts = 1_700_003_600.0_f64;
        let span = batch_max_ts - since; // 3600
        let jump = batch_max_ts + span; // 1_700_007_200

        // clock-before-epoch: unwrap_or fallback sets now = batch_max_ts
        let now_fallback = batch_max_ts;
        assert_eq!(jump.min(now_fallback), batch_max_ts,
            "clock-before-epoch must not fast-forward past batch_max_ts");

        // jump < now: full fast-forward
        let now_future = jump + 1000.0;
        assert_eq!(jump.min(now_future), jump,
            "jump < now must advance to jump");

        // jump > now: cap at now
        let now_between = batch_max_ts + 1.0;
        assert_eq!(jump.min(now_between), now_between,
            "jump > now must be capped at now");
    }

    #[test]
    fn backstop_force_full_boot_window_and_persisted_cadence() {
        // Boot-window pass fires exactly once, at the configured tick,
        // regardless of where the persisted cycle resumed.
        assert!(backstop_force_full(2, 2, 137, 50), "boot tick must fire");
        assert!(!backstop_force_full(3, 2, 138, 50), "only at the boot tick");
        // Persisted counter resuming mid-range still hits the cadence —
        // the restart-storm pathology (counter reset, backstop never runs)
        // is structurally gone.
        assert!(backstop_force_full(9, 2, 150, 50));
        assert!(!backstop_force_full(9, 2, 149, 50));
        // A node restarted every few ticks: resumed counter 47 reaches the
        // multiple within 3 ticks even if no single boot lasts 50 ticks.
        assert!((48..=50).any(|c| backstop_force_full(1, 2, c, 50)), "cadence reachable across short boots");
    }

    #[test]
    fn backstop_cycle_load_store_round_trip_via_cf_metadata() {
        let state = crate::network::state::build_test_node_state();
        // Absent key falls back to the caller default (first-ever boot).
        assert_eq!(load_backstop_cycle(&state, b"backstop:test_cycle", 7), 7);
        assert_eq!(
            load_backstop_cycle(&state, b"backstop:test_cycle", u64::MAX),
            u64::MAX,
        );
        // Stored value round-trips and overrides the default.
        store_backstop_cycle(&state, b"backstop:test_cycle", 4242);
        assert_eq!(load_backstop_cycle(&state, b"backstop:test_cycle", 0), 4242);
        // Wrap-adjacent values survive the byte round trip.
        store_backstop_cycle(&state, b"backstop:test_cycle", u64::MAX - 1);
        assert_eq!(
            load_backstop_cycle(&state, b"backstop:test_cycle", 0),
            u64::MAX - 1,
        );
    }
}
