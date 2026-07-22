//! Record ingestion — validation pipeline for incoming records.
//!
//! Extracted from gossip.rs to decouple the validation pipeline from
//! the transport layer. All record insertion enters through this module
//! regardless of whether the record arrived via HTTP gossip,
//! HTTP API, WebSocket, or sync protocol.
//!
//! Spec references:
//!   @spec Protocol §11.14
//!   @spec Protocol §7.3

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::Ordering::Relaxed;

use tracing::{debug, info, warn};

/// Test-only observer for record propagation across the in-process
/// `elara-simulate` cluster (L1543 stress scenario).
///
/// Fires once per node per record at the success path of `insert_record_inner`.
/// In production this is a single uncontended atomic load that returns `None`
/// — no allocations, no branch the optimiser can't lift. The harness sets
/// it once at simulator startup via `set_propagation_observer`.
///
/// **Why a static, not a `NodeState` field**: the simulator has dozens of
/// `Arc<NodeState>` instances and a single shared sink that needs to
/// timestamp `(node_id, record_id)` tuples. A static is the only place a
/// single sink can sit without threading an `Arc` through every constructor.
/// Setter is `set` (not `set_unchecked`) so a second harness run in the
/// same process is a no-op rather than a panic.
type PropagationObserver = Arc<dyn Fn(&str, &str) + Send + Sync>;
static PROPAGATION_OBSERVER: OnceLock<PropagationObserver> = OnceLock::new();

/// Install a one-shot observer that fires `(creator_node_identity_hash, record_id)`
/// every time a record reaches the success path of `insert_record_inner`.
///
/// Returns `Err` if an observer is already installed.
pub fn set_propagation_observer<F>(f: F) -> std::result::Result<(), &'static str>
where
    F: Fn(&str, &str) + Send + Sync + 'static,
{
    PROPAGATION_OBSERVER
        .set(Arc::new(f))
        .map_err(|_| "propagation observer already installed")
}

use crate::crypto::pqc::dilithium3_verify;
use crate::errors::ElaraError;
use crate::itc::Stamp;
use crate::record::ValidationRecord;
use crate::accounting::batch::BATCH_OP_KEY;
use crate::accounting::delegation::{self, DELEGATION_OP_KEY};
use crate::accounting::trust::content_fingerprint;
use crate::accounting::types::{creator_identity_hash, extract_ledger_op};
use crate::accounting::validate::validate_op;

use super::epoch::{self, EPOCH_OP_KEY};
use super::state::NodeState;
use super::sunset::{self, SUNSET_OP_KEY};
use super::{LockRecover, RwLockRecover};

/// Resolve a seal's `record_hashes` (each entry is a `record.record_hash()`,
/// i.e. SHA3 of `signable_bytes()`) to local `record_id`s by point-reading
/// `CF_IDX_RECORD_HASH` for each. Returns the resolved IDs in input order;
/// misses are dropped, not gap-filled.
///
/// Both seal-handling paths use this:
///   * `network/ingest.rs` — post-attestation, every node that ingests
///     a seal needs to populate the consensus seal-record map so
///     `is_seal_settled` can fire when 2/3 attestations arrive.
///   * `network/epoch.rs::epoch_seal_loop` — the creator node's
///     post-creation register call.
///
/// **Index choice — the load-bearing detail.** Pre-v7 this code probed
/// `CF_IDX_HASH` (keyed by `content_hash`), which is a different value
/// from `record_hash` and never matched. The v5→v6 migration fixed
/// CF_IDX_HASH's key format consistency but didn't repair the call-site
/// semantic. The v6→v7 migration adds CF_IDX_RECORD_HASH, keyed on
/// `record_hash` exactly to serve this lookup; the helper below switches
/// to it. Counters (`seal_record_hashes_resolved_total` /
/// `_missing_total`, surfaced on `/metrics`) are the operator alarm if
/// this regression ever recurs — pre-v7, `resolved_total` would have
/// been pinned at zero on every node.
///
/// **Why a free function, not a `NodeState` method**: keeps `state.rs`
/// from depending on `Storage` trait shapes; the helper can be unit-tested
/// in isolation by constructing a lightweight `NodeState` with an
/// in-memory storage backend.
pub fn resolve_seal_record_ids(
    state: &NodeState,
    record_hashes: &[[u8; 32]],
) -> Vec<String> {
    resolve_seal_record_ids_with_unresolved(state, record_hashes).0
}

/// Like [`resolve_seal_record_ids`] but also returns the hex-encoded hashes
/// that did NOT resolve to a local record — the R2 late-member set the
/// registration sites park in consensus (`register_unresolved_seal_members`)
/// so the member can be appended + promoted when its record finally ingests.
pub fn resolve_seal_record_ids_with_unresolved(
    state: &NodeState,
    record_hashes: &[[u8; 32]],
) -> (Vec<String>, Vec<String>) {
    use std::sync::atomic::Ordering::Relaxed;

    let mut record_ids: Vec<String> = Vec::with_capacity(record_hashes.len());
    let mut unresolved: Vec<String> = Vec::new();
    for h in record_hashes {
        let hash_hex = hex::encode(h);
        match state.rocks.record_id_by_record_hash(&hash_hex) {
            Some(rid) => {
                state.seal_record_hashes_resolved_total.fetch_add(1, Relaxed);
                record_ids.push(rid);
            }
            None => {
                state.seal_record_hashes_missing_total.fetch_add(1, Relaxed);
                unresolved.push(hash_hex);
            }
        }
    }
    (record_ids, unresolved)
}

/// KR-3 S2 wiring-(c) c3: derive a rotation-class hop's routing pin —
/// `(record_id, record_hash_hex, lineage_id)` — or `None` for a non-hop record.
/// This is the ONE derivation source shared by the in-memory pin publish (done
/// at admission BEFORE the record's own `resolve_record_zone` calls, so the hop
/// routes+stores under its lineage zone) and the durable CF pin write in
/// `put_record_with_pk_zone` (`rotation_batch_op_for` below) — so the two can
/// never drift: both compute the lineage from the SAME durable predecessor
/// newkey-index via §6.1's rule (a root hop's `prev_key_hash` IS `sha3(pk₀)` =
/// the lineage id; a deeper hop inherits its introducing predecessor's lineage,
/// guaranteed present-and-Final at admission by the §5-H3b gate — wiring-(d)).
/// `record_id == record.id` (`rotation_hop_fields`), so it is exactly the key
/// `resolve_record_zone(&record.id)` looks up.
fn rotation_hop_pin(
    rocks: &crate::storage::rocks::StorageEngine,
    record: &ValidationRecord,
) -> Option<(String, String, String)> {
    let hop = crate::network::rotation_finality::rotation_hop_fields(record)?;
    // Derive the lineage through the SAME shared `rotation_routing_id` the
    // consensus seal-membership filters (c3-ii-2a) use — one derivation source,
    // so the admission pin and the sealer/witness routing can never drift
    // (R-2/R-8 anti-fork). `hop` is already `Some`, so this `?` never diverges.
    let lineage_id = crate::network::rotation_finality::rotation_routing_id(record, |pk| {
        rocks.get_rotation_newkey_index(pk)
    })?;
    Some((hop.record_id, hop.record_hash, lineage_id))
}

/// KR-3 S2 (W2-A): the rotation-finality side-write for a record's Phase-2 store
/// batch (§3-3), or `None` when the record is neither a rotation-class hop nor a
/// rotation-covering seal. Mutually exclusive by construction (a record cannot be
/// both a seal and a rotation hop). Callers MUST gate on
/// `s2_rotation_ordering_enabled` before invoking — kept flag-free here so it is
/// unit-testable in isolation.
///
/// - A rotation-class hop marks its own `record_hash` pending-CF, so a later
///   seal's arm decision can detect coverage with an index point-lookup.
/// - A seal arms its `(zone, epoch)` sweep marker IFF it covers ≥1 currently-
///   pending rotation hash. `has_any_rotation_pending` short-circuits the common
///   (no rotation activity) seal to O(1) — never a member record load (SCALE).
fn rotation_batch_op_for(
    rocks: &crate::storage::rocks::StorageEngine,
    record: &ValidationRecord,
) -> Option<crate::storage::rocks::RotationBatchOp> {
    use crate::storage::rocks::RotationBatchOp;
    // A rotation-class hop → admit it with BOTH side-writes: (1) its pending-CF
    // hash for the seal marker-arm gate AND (2) its routing pin, so the hop stores
    // under its lineage zone (wiring-(c) c2). Derivation via `rotation_hop_pin` —
    // the shared source with the c3 in-memory publish — keyed on the DURABLE
    // predecessor newkey-index per §6.1.
    if let Some((record_id, record_hash_hex, lineage_id)) = rotation_hop_pin(rocks, record) {
        return Some(RotationBatchOp::RotationHopAdmit {
            record_hash_hex,
            record_id,
            lineage_id,
        });
    }
    // A seal covering ≥1 currently-pending rotation hop → arm its slot marker.
    if let Ok(Some(seal)) = crate::network::epoch::extract_epoch_seal(record) {
        if rocks.has_any_rotation_pending()
            && seal
                .record_hashes
                .iter()
                .any(|h| rocks.rotation_hash_pending(&hex::encode(h)))
        {
            return Some(RotationBatchOp::ArmSealMarker {
                zone: seal.zone.path().to_string(),
                epoch: seal.epoch_number,
            });
        }
    }
    None
}

/// Per-branch retry classification for a rotation-class admission reject (KR-3 S2
/// v4 slice-0 / Q5). A `Transient` decline names a not-yet-present / not-yet-final
/// *durable dependency*: the IDENTICAL record admits on a later retry once the
/// dependency lands here, so the gossip/sync driver parks + re-fetches it (bounded,
/// attempt-capped) rather than writing it to the permanent `gossip_rejected`
/// embargo. A `Permanent` decline names a structural defect (out-of-vocabulary
/// reason, no cited parents, past an age/depth cap) the same record can never clear,
/// so it is embargoed. Threading the class OUT of each pure gate — one bit per
/// reject branch — is what closes C2: the shipped H3b interim collapsed its
/// transient `reject-transient` into a bare error string that
/// `gossip::is_retryable_ingest_rejection`'s allowlist did not recognise, so a
/// rotation hop whose predecessor had merely not finalized yet was permanent-cached
/// forever instead of parked for retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectClass {
    Transient,
    Permanent,
}

impl RejectClass {
    /// Lift a rotation-admission reject `reason` into the `ElaraError` that carries
    /// its retry class to the gossip/sync driver and the HTTP/PQ surfaces:
    /// `Transient` → `TransientReject` (parked + re-fetched; 503) and `Permanent` →
    /// `Wire` (embargoed; 400) — the latter preserves the prior `ElaraError::Wire`
    /// mapping, so flag-ON permanent rejects are behaviourally unchanged.
    fn into_reject(self, reason: String) -> crate::errors::ElaraError {
        match self {
            RejectClass::Transient => crate::errors::ElaraError::TransientReject(reason),
            RejectClass::Permanent => crate::errors::ElaraError::Wire(reason),
        }
    }
}

/// KR-3 S2 §5-H2 + §5-H3: rotation-class parent-grounding admission gate.
///
/// **H2 — parents required, non-empty** (audit spine #1): a rotation-class op is
/// never a global/genesis op, so it MUST cite ≥1 DAG parent for causal grounding.
///
/// **H3 — parent-age cap + durable-parent gate:** every cited parent that is
/// locally loadable must have a timestamp within `ROTATION_PARENT_MAX_AGE_SECS`
/// (24 h) of `node_now` (bounds graft-depth games, keeps dispute-window forensics
/// shallow), AND ≥1 cited parent must be DURABLY finalized at admission — checked
/// per parent class, NEVER the transient attestation map. A rotation-*hop* parent
/// grounds only when its rotation-CF entry has reached `state ≥ Final` (resolve the
/// hop's `new_key_hash` through the durable newkey-index to its `(lineage,
/// hop_index)`, then read the entry — a `Pending` snapshot-inherited entry does NOT
/// ground). Any other parent (ordinary, or a revocation tombstone) grounds via its
/// `FinalizedIndex` (`finalized:` prefix) row, `finalized::contains_in_rocks`.
///
/// **Defense-in-depth ONLY** — S2 ordering never reads parent data, so the per-node
/// `node_now` age clock is correct here; a reject is loud + transient (the author
/// re-parents onto a fresh, finalized parent — a liveness nick, never a safety
/// hole; known caveat: a seal-fast-tracked ordinary parent that lacks its
/// `FinalizedIndex` row until the FIN-1 lane lands rejects here and is re-parented).
/// An unloadable parent can be neither age-checked nor counted durable, so it is
/// skipped — an all-unloadable/all-unfinalized parent set therefore rejects on the
/// durable leg. Returns `Ok(())` for a NON-rotation-class record (gate n/a —
/// ordinary traffic untouched). Reads only durable, finality-derived storage
/// (parent records + rotation CF + FinalizedIndex), so every admitting node agrees.
fn validate_rotation_parent_grounding(
    rocks: &crate::storage::rocks::StorageEngine,
    record: &ValidationRecord,
    node_now: f64,
) -> Result<(), (RejectClass, String)> {
    use crate::network::rotation_finality::{
        rotation_hop_fields, RotationState, ROTATION_PARENT_MAX_AGE_SECS,
    };
    if !crate::network::key_rotation::is_rotation_class_record(record) {
        return Ok(()); // not a rotation-class record — H2/H3 do not apply
    }
    // H2: parents required, non-empty. Structural (the cited-parent set is signed
    // into this record) ⇒ Permanent: retrying the identical record never adds a
    // parent.
    if record.parents.is_empty() {
        return Err((
            RejectClass::Permanent,
            "rotation-class record cites no parents (H2)".to_string(),
        ));
    }
    // H3: per-parent age cap + ≥1 durably-finalized parent.
    let max_age = ROTATION_PARENT_MAX_AGE_SECS as f64;
    let mut any_durable = false;
    for pid in &record.parents {
        // Unloadable parent: no timestamp to age-check, no finality to count — skip.
        // The durable leg below still requires ≥1 loadable, finalized parent, so an
        // all-unloadable parent set rejects.
        let parent = match rocks.get_record(pid) {
            Ok(Some(p)) => p,
            _ => continue,
        };
        // Age leg: EVERY loadable parent must be within the 24 h cap. A cited parent
        // that is too old is fixed for this signed record ⇒ Permanent (the author
        // must re-parent, which is a NEW record, not a retry of this one).
        let age = node_now - parent.timestamp;
        if age > max_age {
            return Err((
                RejectClass::Permanent,
                format!(
                    "parent {} is {age:.0}s old, past the {max_age:.0}s cap (H3 age)",
                    &pid[..pid.len().min(16)]
                ),
            ));
        }
        // Durable leg (per class): rotation-hop parent → CF `state ≥ Final`; any
        // other parent → FinalizedIndex row. `rotation_hop_fields` returns `Some`
        // only for the clean prev→new hops (rotation/sphincs), so a revocation
        // tombstone parent grounds via the FinalizedIndex branch — correct, it has
        // no hop CF entry.
        if let Some(hop) = rotation_hop_fields(&parent) {
            if let Some((lineage, hop_idx)) = rocks.get_rotation_newkey_index(&hop.new_key_hash) {
                if let Some(entry) = rocks.get_rotation_entry(&lineage, hop_idx) {
                    if entry.state as u8 >= RotationState::Final as u8 {
                        any_durable = true;
                    }
                }
            }
        } else if crate::network::finalized::contains_in_rocks(rocks, pid) {
            any_durable = true;
        }
    }
    if !any_durable {
        // Transient: a cited parent may finalize (or sync) later, at which point the
        // IDENTICAL record grounds on retry — so park + re-fetch, never embargo.
        return Err((
            RejectClass::Transient,
            "no cited parent is durably finalized (H3 durable-parent leg)".to_string(),
        ));
    }
    Ok(())
}

/// KR-3 S2 §5-H3b — predecessor-finality gate for rotation hops, **FAIL-CLOSED interim**.
///
/// A rotation *hop* (rotation / sphincs, a clean prev→new pair) is admitted only when its
/// `prev_key`'s introducing hop is already in the durable rotation CF at `state ≥ Final` —
/// i.e. `get_rotation_newkey_index(prev_key)` returns `Some`. Then §6.1 derives the hop's
/// `lineage_id` from that finalized predecessor, identically on every node.
///
/// **Why fail-closed on `None`, not "treat as root".** [`derive_lineage_position`] maps a
/// `None` lookup to `(prev_key, 0)` — "this is a lineage root". But `None` is AMBIGUOUS: (a) a
/// genuine root (`prev_key = pk₀`, never rotated into) vs (b) a deep hop whose introducing
/// predecessor has not finalized yet / this node has not received it. The two are
/// indistinguishable from local state — the rotation payload carries no depth/root field
/// (`KeyRotation`/`SphincsKeyRotation` hold only new_key/reason/id), the newkey index is
/// finalized-only, and admission is async per node. Silently pinning case (b) as a root writes
/// an IMMUTABLE `rotation_zone_pin`; a node that had already finalized the predecessor pins the
/// true lineage instead ⇒ two zones for one record ⇒ **consensus fork by honest actors alone**
/// (audit `docs/AUDIT-REPORTS/kr3-s2-h3b-fork-an internal audit).
///
/// Distinguishing (a) from (b) fork-freely requires a positive, finalized, per-anchor
/// ORIGIN-KEY predicate that does not yet exist (the deferred KR-3 stable-identity work — see
/// the `key_rotation.rs` banner). Until it lands this gate is deliberately fail-closed: `Some`
/// ⇒ admit (deep hop, grounded); `None` ⇒ reject-transient (loud; the author retries once the
/// predecessor finalizes). The interim cost — a genuine ROOT hop is ALSO rejected, so no
/// lineage can bootstrap under flag-ON — is exactly why the network-wide flag flip stays
/// blocked on the origin primitive. Fork-safety over feature-liveness, by design.
///
/// Scope: rotation/sphincs HOPS only (`rotation_hop_fields` → `Some`). A revocation is
/// rotation-class but not a prev→new hop (`rotation_hop_fields` → `None` here, and it is never
/// pinned as a rotation hop — `rotation_routing_id` short-circuits on it); its lineage grounding
/// belongs to the §6.3 resolver slice. Returns `Ok(())` for any non-hop record (gate n/a).
/// Reads only durable, finalized storage, so every admitting node agrees on accept/reject.
fn validate_rotation_predecessor_grounding(
    rocks: &crate::storage::rocks::StorageEngine,
    record: &ValidationRecord,
) -> Result<(), (RejectClass, String)> {
    use crate::network::rotation_finality::{
        rotation_hop_fields, RotationState, ROTATION_MAX_CHAIN_DEPTH,
    };
    let hop = match rotation_hop_fields(record) {
        Some(h) => h,
        None => return Ok(()), // not a rotation/sphincs hop — H3b n/a
    };
    match rocks.get_rotation_newkey_index(&hop.prev_key_hash) {
        Some((lineage, pred_hop)) => {
            // Predecessor is indexed. Entries only ever exist at state ≥ Final, but check
            // defensively — fail closed if a future writer ever lands a non-Final entry.
            // Transient: the predecessor is present and will reach Final, so a retry
            // grounds the identical record.
            match rocks.get_rotation_entry(&lineage, pred_hop) {
                Some(e) if e.state as u8 >= RotationState::Final as u8 => {}
                _ => {
                    return Err((
                        RejectClass::Transient,
                        "predecessor hop indexed but not durably Final (H3b)".to_string(),
                    ))
                }
            }
            // Depth cap is an admission-time (H3b) policy — `derive_lineage_position` stays
            // faithful and never truncates silently, so the ceiling is enforced here.
            // Permanent: a chain that reaches the depth ceiling never shortens on retry.
            let this_hop = pred_hop.saturating_add(1);
            if this_hop >= ROTATION_MAX_CHAIN_DEPTH {
                return Err((
                    RejectClass::Permanent,
                    format!(
                        "rotation chain depth {this_hop} reaches the {ROTATION_MAX_CHAIN_DEPTH} cap (H3b)"
                    ),
                ));
            }
            Ok(())
        }
        // Ungroundable: genuine root OR pending/unseen predecessor — indistinguishable without
        // the origin-key primitive. Fail closed (never silently pin-as-root). Transient: if it
        // is the pending-predecessor case, a retry grounds once the predecessor finalizes here;
        // a genuine root parks (bounded) and ages out rather than being embargoed — the
        // fork-safe interim cost until the origin primitive lands.
        None => Err((
            RejectClass::Transient,
            "rotation hop prev_key has no durably-final introducing hop — genuine-root vs \
             pending-predecessor is indistinguishable until the origin-key primitive lands \
             (H3b, reject-transient; retry after the predecessor finalizes)"
                .to_string(),
        )),
    }
}

/// Tier-1 deficit capture (internal design notes §4.1): a seal
/// arrived whose `record_hashes` (committed on the wire) contained entries
/// with no local record. Rides the point lookups `resolve_seal_record_ids`
/// already did — zero extra storage work. Legacy seals (empty hash list)
/// carry no completeness claim and are skipped.
///
/// Free function for the same reason as `resolve_seal_record_ids`: keeps
/// `state.rs` free of `ParsedEpochSeal` shapes and unit-testable in isolation.
pub fn record_seal_deficit(
    state: &NodeState,
    seal: &crate::network::epoch::ParsedEpochSeal,
    seal_record_id: &str,
    resolved_count: usize,
    window_count_on_empty: Option<u64>,
) {
    use std::sync::atomic::Ordering::Relaxed;

    let missing = if seal.record_hashes.is_empty() {
        // R3-8 slice 5 (P3 count-degrade): with no enumeration — bounded
        // emission above SEAL_INLINE_ENUM_MAX plus a derive miss — degrade
        // to the signed record_count minus the local window count the
        // pass's derive attempt already measured. Coarser than per-hash
        // naming but the recovery action (full_pull) is identical. `None`
        // = no completeness claim (legacy seal or record_count == 0): skip,
        // exactly the pre-R3-8 behavior.
        match window_count_on_empty {
            Some(local) => seal.record_count.saturating_sub(local),
            None => return,
        }
    } else {
        seal.record_hashes.len().saturating_sub(resolved_count) as u64
    };
    if missing == 0 {
        return;
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key = (seal.zone.path().to_string(), seal.epoch_number);
    let is_new = {
        let mut ring = state
            .dag_deficit_open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ring.observe(
            key,
            crate::network::state::DagDeficitEntry {
                missing,
                seal_start: seal.start,
                seal_record_id: seal_record_id.to_string(),
                first_seen_unix: now_unix,
            },
        )
    };
    if is_new {
        state.dag_deficit_epochs_total.fetch_add(1, Relaxed);
        tracing::info!(
            "dag deficit opened: zone {} epoch {} missing {} of {} sealed records",
            seal.zone,
            seal.epoch_number,
            missing,
            seal.record_hashes.len(),
        );
    }
}

/// Per-pull-cycle deficit re-check batch size. During bulk catch-up, seals
/// often arrive BEFORE their covered records, so the ring fills with
/// transient deficits that heal as pulls land; draining one per 30 s cycle
/// would keep /health warning hours after the heal. 8 seals × point lookups
/// per cycle stays trivially bounded and drains a full 512-ring in ~32 min.
pub const DAG_DEFICIT_RECHECKS_PER_CYCLE: usize = 8;

/// Per-pull-cycle deficit re-check (contract §4.1): re-load up to
/// `max_checks` open deficits' seals (round-robin), re-probe their
/// `record_hashes` by point lookup, and close/update each entry.
/// Deliberately does NOT touch the
/// `seal_record_hashes_{resolved,missing}_total` counters — those are the
/// v7-index regression alarm and must reflect first-ingest outcomes only.
/// A seal record that no longer exists locally (pruned below the super-seal
/// floor) closes its deficit: the records are unprovable AND unpullable by
/// design (contract §2 — pruning is not a hole).
///
/// Returns the number of deficits still open (the escalation signal).
pub fn recheck_dag_deficits(state: &NodeState, max_checks: usize) -> usize {
    use std::sync::atomic::Ordering::Relaxed;

    let mut open = state
        .dag_deficit_open
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    for _ in 0..max_checks.min(open) {
        let picked = {
            let mut ring = state
                .dag_deficit_open
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            ring.next_for_recheck()
        };
        let Some((key, seal_record_id)) = picked else {
            // Ring drained ⇒ no open deficits (invariant debug_assert'd at
            // `DagDeficitRing::next_for_recheck`'s drain exit).
            return 0;
        };

        // Point lookups only — bounded by the seal's own hash-list length.
        let missing_now: Option<u64> = state
            .rocks
            .get_record(&seal_record_id)
            .ok()
            .flatten()
            .and_then(|rec| {
                crate::network::epoch::extract_epoch_seal(&rec)
                    .ok()
                    .flatten()
                    .map(|seal| {
                        if seal.record_hashes.is_empty() && seal.record_count > 0 {
                            // R3-8 slice 5: an empty enumeration is NOT evidence
                            // of health — bounded emission above the inline cap
                            // parses as empty, so counting misses over it
                            // FALSE-CLOSED real deficits as healed. Re-DERIVE
                            // (bounded window scan, root-gated): a root match
                            // proves every sealed record is local (healed);
                            // otherwise degrade to the signed record_count
                            // minus the local window size.
                            use crate::network::epoch::{derive_seal_enumeration, DeriveOutcome};
                            match derive_seal_enumeration(&*state.rocks, &seal) {
                                Some(DeriveOutcome::Derived(_)) => 0,
                                Some(DeriveOutcome::Incomplete { local_window_count }) => {
                                    seal.record_count.saturating_sub(local_window_count)
                                }
                                None => 0,
                            }
                        } else {
                            seal.record_hashes
                                .iter()
                                .filter(|h| {
                                    state
                                        .rocks
                                        .record_id_by_record_hash(&hex::encode(h))
                                        .is_none()
                                })
                                .count() as u64
                        }
                    })
            });

        let mut ring = state
            .dag_deficit_open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match missing_now {
            Some(0) | None => {
                // Fully healed, or the seal itself is gone/unparseable (pruned).
                if ring.resolve(&key) {
                    state.dag_deficit_resolved_total.fetch_add(1, Relaxed);
                    tracing::info!("dag deficit closed: zone {} epoch {}", key.0, key.1);
                }
            }
            Some(n) => ring.update_missing(&key, n),
        }
        open = ring.len();
    }
    open
}

/// Bounded set for deduplicating seen record IDs. Evicts oldest on overflow.
pub struct SeenSet {
    set: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl SeenSet {
    pub fn new(capacity: usize) -> Self {
        Self {
            set: HashSet::with_capacity(capacity.min(1024)),
            order: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Clear all entries — used during genesis bootstrap retry.
    pub fn clear(&mut self) {
        self.set.clear();
        self.order.clear();
    }

    /// Insert an ID. Returns `true` if newly seen, `false` if already known.
    pub fn insert(&mut self, id: String) -> bool {
        if self.set.contains(&id) {
            return false;
        }
        if self.set.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(id.clone());
        self.order.push_back(id);
        true
    }

    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    /// Remove an ID from the set (used during initial sync to allow retry).
    pub fn remove(&mut self, id: &str) {
        self.set.remove(id);
        // Note: we don't remove from `order` VecDeque (O(n)) — the eviction
        // logic handles stale entries gracefully since set.remove is the gate.
    }

    /// Iterate live entries — bounded by `capacity`. Used to fold the
    /// declined-seal LRU into the delta_pull bloom (contract §4.4).
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.set.iter()
    }
}

/// Per-identity propagation rate limiter.
///
/// Protocol v0.6.2 Section 11.19: each identity is limited to N records/hour.
/// Sliding window: tracks (identity_hash → Vec<timestamp>), prunes expired entries.
pub struct PropagationLimiter {
    /// identity_hash → list of record timestamps within the current window.
    windows: HashMap<String, VecDeque<f64>>,
    /// Max records per identity per window.
    limit: u32,
    /// Window duration in seconds (1 hour).
    window_secs: f64,
}

impl PropagationLimiter {
    pub fn new(limit: u32) -> Self {
        Self {
            windows: HashMap::new(),
            limit,
            window_secs: 3600.0,
        }
    }

    /// Check if an identity is allowed to propagate a record at the given timestamp.
    /// Returns `true` if allowed (and records the event), `false` if rate-limited.
    pub fn check_and_record(&mut self, identity_hash: &str, timestamp: f64) -> bool {
        self.check_and_record_scaled(identity_hash, timestamp, self.limit as u64)
    }

    /// Check with a per-identity effective limit (stake-scaled).
    ///
    /// `effective_limit`: base_rate + stake_bonus. Allows staked identities to
    /// exceed the flat base rate proportional to their economic commitment.
    /// Returns `(allowed, effective_limit)` — callers can log the actual limit.
    pub fn check_and_record_scaled(&mut self, identity_hash: &str, timestamp: f64, effective_limit: u64) -> bool {
        if effective_limit == 0 {
            return true; // disabled
        }

        let window = self.windows
            .entry(identity_hash.to_string())
            .or_default();

        // Prune expired entries
        let cutoff = timestamp - self.window_secs;
        while window.front().is_some_and(|t| *t < cutoff) {
            window.pop_front();
        }

        if window.len() >= effective_limit as usize {
            return false; // rate limited
        }

        window.push_back(timestamp);
        true
    }

    /// Number of identities being tracked.
    pub fn tracked_identities(&self) -> usize {
        self.windows.len()
    }

    /// Periodic cleanup: remove identities with no recent activity.
    pub fn cleanup(&mut self, now: f64) {
        let cutoff = now - self.window_secs;
        self.windows.retain(|_, timestamps| {
            timestamps.back().is_some_and(|t| *t >= cutoff)
        });
    }
}

/// Authoritative per-identity HARD daily emission cap (trust-tier day limit).
///
/// Non-skippable counterpart to the trust-tier daily cap. The COUNT lives here
/// under a dedicated short-lived lock that only ever contends with other O(1)
/// ingest holders — NEVER with `feed_attestation` / trust prune (which hold
/// `state.trust`) — so, unlike the old `try_read`/`try_write` on `state.trust`
/// (which drop the check+increment under contention, the exact window an
/// attacker floods), the cap here cannot be skipped. The LIMIT is computed
/// best-effort from the trust profile at the call site; on contention the caller
/// falls back to the STRICTEST tier cap (fails CLOSED). Non-consensus, per-node,
/// in-memory; O(active identities) with periodic cleanup — mirrors
/// `PropagationLimiter` above.
pub struct DailyCapCounter {
    /// identity_hash → (day_start_timestamp, count in the current 24h window).
    counts: HashMap<String, (f64, u32)>,
}

impl Default for DailyCapCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl DailyCapCounter {
    pub fn new() -> Self {
        Self { counts: HashMap::new() }
    }

    /// ATOMIC check-and-increment: returns `true` iff the identity was under
    /// `limit` (and is now incremented), `false` if already at/over its daily cap.
    ///
    /// Rollover, the `>= limit` comparison, and the `+= 1` ALL execute under the
    /// single `Mutex` acquisition the caller holds — this is the indivisible gate.
    /// NEVER split the check from the increment: two concurrent submissions from
    /// one identity would both observe `count == limit-1`, both pass, both
    /// increment → the cap over-admits by the concurrency factor with no error.
    pub fn check_and_increment(&mut self, identity_hash: &str, now: f64, limit: u32) -> bool {
        let entry = self.counts.entry(identity_hash.to_string()).or_insert((now, 0));
        if now - entry.0 >= crate::accounting::trust::DAILY_WINDOW_SECS {
            *entry = (now, 0); // day rolled over (mirrors EntropyProfile::daily_count)
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Number of identities being tracked.
    pub fn tracked_identities(&self) -> usize {
        self.counts.len()
    }

    /// Periodic cleanup — drop entries whose 24h window has fully elapsed. O(active).
    pub fn cleanup(&mut self, now: f64) {
        let w = crate::accounting::trust::DAILY_WINDOW_SECS;
        self.counts.retain(|_, (day_start, _)| now - *day_start < w);
    }
}

/// Info collected under sync lock for async fisherman slash execution.
struct PendingSlash {
    accused: String,
    challenger: String,
    jury: Vec<String>,          // jurors who voted guilty
    challenge_type: super::fisherman::ChallengeType,
}

/// Current time as Unix epoch seconds.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Global fixed-window rate admission: returns true if this request is within
/// the per-minute budget, resetting the window when 60 s have elapsed.
///
/// The window reset uses compare-exchange so only ONE racer zeroes the counter
/// at the minute boundary. A plain store-store reset let every thread that
/// observed the stale window re-zero the counter, wiping increments that had
/// already landed in the fresh window (small over-admission burst each minute
/// under concurrency). Admission itself is increment-then-check — `fetch_add`
/// returns the pre-increment count — so at most `limit` requests are admitted
/// per window with no check-then-act gap.
pub(crate) fn global_rate_window_admit(
    window_start: &std::sync::atomic::AtomicU64,
    counter: &std::sync::atomic::AtomicU64,
    limit: u64,
    now_secs: u64,
) -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    let ws = window_start.load(Relaxed);
    if now_secs >= ws.saturating_add(60)
        && window_start.compare_exchange(ws, now_secs, Relaxed, Relaxed).is_ok()
    {
        counter.store(0, Relaxed);
    }
    counter.fetch_add(1, Relaxed) < limit
}

/// Max metadata entries per record. Public for test access.
/// Raised 24 → 64 pre-v0.1.0 (Decision A, R3-7 fusion audit 2026-07-02): a
/// fully-populated epoch seal carries 26 keys (18 `seal_metadata`, 7 `drand_*`,
/// 1 xzone committee map) and would stall on the producer's own insert at 24.
/// Junk resistance is unaffected — `MAX_RECORD_BYTES` (64 KiB) is the binding
/// aggregate cap; entry count adds nothing. 64 stays well under the wire
/// decoder's separate 256-entry DoS cap, so no wire-version bump. Freezes into
/// v0.1.0 as a one-way door: raising later re-stalls frozen binaries, lowering
/// later self-stalls the raiser.
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Max metadata value length. Must accommodate:
/// - Hex-encoded Dilithium3 public keys (1,952 bytes raw = 3,904 bytes hex)
/// - Dilithium3-VRF proofs in epoch seals (~6,600 bytes hex-encoded)
/// - Key rotation records with PQ signatures
pub const MAX_METADATA_VALUE_LEN: usize = 8_192;

/// Dilithium3-VRF proof hex-encoded budget (load-bearing reason for the 8,192
/// `MAX_METADATA_VALUE_LEN` ceiling — epoch seals carry Dilithium3-VRF proofs
/// in metadata). A future shrinkage of `MAX_METADATA_VALUE_LEN` below
/// this would silently break epoch-seal VRF metadata storage.
const DILITHIUM3_VRF_HEX_BUDGET: usize = 6_600;

/// Dilithium3 public key hex-encoded budget (second load-bearing reason
/// for the 8,192 ceiling — key-rotation records carry hex pubkeys).
const DILITHIUM3_PK_HEX_BUDGET: usize = 3_904;

// Compile-time invariants. A future edit that shrinks
// `MAX_METADATA_VALUE_LEN` below either budget would silently break
// epoch seal VRF metadata storage (Dilithium3-VRF proof) or key-rotation
// records (Dilithium3 pubkey case). Fail at `cargo build`, not at `cargo test`.
const _: () = assert!(
    MAX_METADATA_VALUE_LEN >= DILITHIUM3_VRF_HEX_BUDGET,
    "MAX_METADATA_VALUE_LEN must accommodate Dilithium3-VRF hex (~6,600 B) per the docstring rationale — shrinking below this silently breaks epoch seal VRF metadata storage"
);
const _: () = assert!(
    MAX_METADATA_VALUE_LEN >= DILITHIUM3_PK_HEX_BUDGET,
    "MAX_METADATA_VALUE_LEN must accommodate Dilithium3 PK hex (3,904 B) per the docstring rationale"
);

/// Max parents per record. Canonical definition lives in the core wire module
/// (`crate::record`) so the record decoder can bound `num_parents` at the decode
/// boundary without depending on this `node-core`-gated module; re-exported here
/// so post-decode ingest validation enforces the identical ceiling.
pub use crate::record::MAX_PARENTS;
/// Max serialized record size: 64 KiB. Enforced FIRST in `insert_record_inner`
/// (before the per-field metadata checks), so it is the binding AGGREGATE cap on
/// every ingest path — local creation, gossip push, and sync alike — which makes
/// it a uniform hard ceiling, never a fork vector (no node can build/seal a record
/// its peers would reject). Sized to hold the worst-case STRUCTURAL dual-signed
/// (Profile A) record: Dilithium3 sig 3.3 KB + PK 1.9 KB, SPHINCS+ sig 35.7 KB +
/// PK 48 B, `MAX_PARENTS`=256 (~9.5 KB) and 256 zone_refs (~4.4 KB) = 54.9 KB
/// measured (`worst_case_profile_a_record_size_vs_wire_cap`), leaving ~10 KB for
/// the load-bearing metadata case (one ~6.6 KB hex VRF proof per epoch-seal record
/// fits at 60.1 KB). NOTE: the per-field metadata bounds (`MAX_METADATA_ENTRIES`=64
/// × `MAX_METADATA_VALUE_LEN`=8192 = 512 KB) SUM ABOVE this aggregate by design —
/// they are independent sub-limits; a record that maxes them is rejected here first
/// ("record too large") before the per-field checks ever run. The drift-guard test
/// pins structural ≤ cap so a future `MAX_PARENTS`/zone_refs bump (or a cap shrink)
/// can't silently make dual-signed dense-DAG records un-insertable. Typical
/// records are 2–10 KB.
pub const MAX_RECORD_BYTES: usize = 65_536;
/// Timestamp drift tolerance: 5 minutes into the future.
pub const MAX_FUTURE_DRIFT_SECS: f64 = 300.0;

/// Insert a record with an optional origin hint for entropy tracking.
/// When `origin_hint` is Some, it overrides the default creator-hash-based
/// origin hash, providing real IP-based origin diversity for WebSocket clients.
pub async fn insert_record(state: &Arc<NodeState>, record: ValidationRecord) -> crate::errors::Result<String> {
    // Route through state core channel if available (eliminates lock contention)
    if let Some(core) = state.state_core.get() {
        return match core.insert_record(record, super::state_core::RecordSource::Local).await {
            super::state_core::InsertResult::Accepted { record_id } => Ok(record_id),
            super::state_core::InsertResult::Rejected { reason } => {
                Err(crate::errors::ElaraError::Storage(reason))
            }
            super::state_core::InsertResult::Error { message } => {
                // P0: a state-core channel failure is TRANSIENT infra (worker
                // down/restarting), never a content rejection. Render as the
                // typed transient marker so downstream classifiers
                // (is_retryable_ingest_rejection) PARK for retry instead of
                // permanent-caching the rid in gossip_rejected — which is
                // consult-and-skip on every pull driver, i.e. un-repullable.
                Err(crate::errors::ElaraError::TransientReject(message))
            }
        };
    }
    insert_record_inner(state, record, None, false).await
}

pub async fn insert_record_with_origin(state: &Arc<NodeState>, record: ValidationRecord, origin_hint: Option<u64>) -> crate::errors::Result<String> {
    // Route through state core channel if available
    if let Some(core) = state.state_core.get() {
        return match core.insert_record(record, super::state_core::RecordSource::Local).await {
            super::state_core::InsertResult::Accepted { record_id } => Ok(record_id),
            super::state_core::InsertResult::Rejected { reason } => {
                Err(crate::errors::ElaraError::Storage(reason))
            }
            super::state_core::InsertResult::Error { message } => {
                // P0: a state-core channel failure is TRANSIENT infra (worker
                // down/restarting), never a content rejection. Render as the
                // typed transient marker so downstream classifiers
                // (is_retryable_ingest_rejection) PARK for retry instead of
                // permanent-caching the rid in gossip_rejected — which is
                // consult-and-skip on every pull driver, i.e. un-repullable.
                Err(crate::errors::ElaraError::TransientReject(message))
            }
        };
    }
    insert_record_inner(state, record, origin_hint, false).await
}

/// Insert a record received during initial/delta sync (historical data).
/// Routes through state core channel if available, with skip_timestamp_defense=true
/// since synced records have old timestamps that would poison the zone drift estimator.
pub async fn insert_record_synced(state: &Arc<NodeState>, record: ValidationRecord) -> crate::errors::Result<String> {
    if let Some(core) = state.state_core.get() {
        return match core.insert_record(record, super::state_core::RecordSource::Sync).await {
            super::state_core::InsertResult::Accepted { record_id } => Ok(record_id),
            super::state_core::InsertResult::Rejected { reason } => {
                Err(crate::errors::ElaraError::Storage(reason))
            }
            super::state_core::InsertResult::Error { message } => {
                // P0: a state-core channel failure is TRANSIENT infra (worker
                // down/restarting), never a content rejection. Render as the
                // typed transient marker so downstream classifiers
                // (is_retryable_ingest_rejection) PARK for retry instead of
                // permanent-caching the rid in gossip_rejected — which is
                // consult-and-skip on every pull driver, i.e. un-repullable.
                Err(crate::errors::ElaraError::TransientReject(message))
            }
        };
    }
    insert_record_inner(state, record, None, true).await
}

/// Direct insert — bypasses the state core channel. Only called BY the state core itself.
pub async fn insert_record_inner_direct(state: &Arc<NodeState>, record: ValidationRecord, origin_hint: Option<u64>, skip_timestamp_defense: bool) -> crate::errors::Result<String> {
    insert_record_inner(state, record, origin_hint, skip_timestamp_defense).await
}

/// Build, log, and gossip a `ConflictProof` for a slot collision, then return
/// the slot-conflict error to bubble back up `insert_record_inner`. Used by
/// the early (pre-verify) reject path. The proof's `verify` returns Ok only
/// when both records' signatures verify under the current wire formula —
/// callers gossip it only on Ok, so we never emit an unverifiable claim.
fn handle_slot_conflict(
    state: &Arc<NodeState>,
    slot_key: &str,
    existing_id: String,
    incoming: &ValidationRecord,
) -> ElaraError {
    state.gossip_seen_dedup_total.fetch_add(1, Relaxed);

    if let Ok(Some(existing)) = state.rocks.get_record(&existing_id) {
        let proof = super::conflict_proof::ConflictProof::new(existing, incoming.clone());
        match proof.verify() {
            Ok(()) => {
                let offender = proof.offender_identity_hash();
                let marker = format!("{}:{}", existing_id, incoming.id);
                if let Err(e) = state.rocks.slot_mark_conflict(slot_key, &marker) {
                    warn!("slot_mark_conflict failed for {}: {}", slot_key, e);
                }
                warn!(
                    "SLOT EQUIVOCATION: creator {} claimed slot {} with \
                     both {} and {} — ConflictProof verified, slot marked conflicted",
                    &offender[..offender.len().min(16)],
                    slot_key,
                    &existing_id[..existing_id.len().min(16)],
                    &incoming.id[..incoming.id.len().min(16)],
                );
                // Defense-in-depth (F-9 follow-up): never gossip a proof that
                // names OURSELVES as the offender. The self branch only fires
                // on re-ingest of our own records; a genuine broadcast
                // equivocation is independently detectable by any peer that
                // received both records, so self-naming gossip adds no
                // accountability — it only spams the mesh (production Helsinki
                // fired one every 1-3 min from a nonce-reuse bug). The local
                // slot-mark above still stands so we don't build further on the
                // conflicted slot.
                if offender == state.identity.identity_hash {
                    state
                        .conflict_proof_self_suppressed_total
                        .fetch_add(1, Relaxed);
                    warn!(
                        "self-equivocation at slot {} — ConflictProof gossip \
                         SUPPRESSED (would name our own identity); slot marked \
                         locally. Investigate the latent self-conflict path.",
                        slot_key,
                    );
                } else {
                    let state_clone = Arc::clone(state);
                    let proof_clone = proof.clone();
                    tokio::spawn(async move {
                        super::gossip::push_conflict_proof_to_peers(
                            &state_clone, &proof_clone,
                        )
                        .await;
                    });
                }
            }
            Err(e) => {
                // Canary (audit 2026-07-06): with the record_hash
                // discriminator any two distinct signed records on one slot
                // verify, so this branch should stay ~silent — growth means
                // a conflict class is escaping accountability again.
                state
                    .conflict_proof_local_unverifiable_total
                    .fetch_add(1, Relaxed);
                warn!(
                    "slot conflict at {} but proof did not verify: {} \
                     (existing={}, incoming={})",
                    slot_key,
                    e,
                    &existing_id[..existing_id.len().min(16)],
                    &incoming.id[..incoming.id.len().min(16)],
                );
            }
        }
    }

    ElaraError::Wire(format!(
        "slot conflict: {} already claimed by {} (incoming {})",
        slot_key,
        &existing_id[..existing_id.len().min(16)],
        &incoming.id[..incoming.id.len().min(16)],
    ))
}

/// 8b design B guard (successor-re-admission): a stored record re-enters the
/// full pipeline ONLY when it is a parseable epoch SEAL whose epoch is the
/// STRICT immediate successor of its zone's canonical tip. Every other stored
/// record keeps the dedup short-circuit:
/// - extract-Err → deterministic metadata parse failure; re-flow can never
///   heal it (and looping on it would re-tick the extract-err counter).
/// - `Ok(None)` → epoch_op present but not a seal (zone_transition etc.).
/// - epoch ≤ tip → already canonical, an equal-epoch twin (lex-min/weight
///   reconcile domain), or a fork-loser the tip passed — re-admitting a
///   fork-loser would be a safety regression.
/// - epoch > tip+1 → catch-up territory; the B7 VRF-guarded path owns it.
///
/// Cheap: one metadata parse + one map read, only for already-stored records.
pub(crate) fn should_reenter_stored_seal(
    record: &ValidationRecord,
    epoch_state: &epoch::EpochState,
) -> bool {
    if !record.metadata.contains_key(EPOCH_OP_KEY) {
        return false;
    }
    match epoch::extract_epoch_seal(record) {
        Ok(Some(seal)) => {
            let local = epoch_state
                .latest_epoch
                .get(&seal.zone)
                .copied()
                .unwrap_or(0);
            seal.epoch_number == local + 1
        }
        _ => false,
    }
}

/// Phase 4 of ingest: apply the record's ledger op to the committed ledger via
/// the ARCH-1 tentative path (park in `PendingLedger` + `CF_PENDING_DELTAS`,
/// committed at finality by `pending_drain`), or the direct-apply fallback if the
/// park is rejected (cap/duplicate) — plus creator-stake registration (H1).
///
/// Extracted verbatim from `insert_record_inner` (F2 fix, 2026-07-20) so it can
/// ALSO run for a tombstoned record: under tombstone semantic (A) a tombstone has
/// ZERO ledger effect, so the live path must apply the op exactly as the rebuild
/// folds + `rederive_swept_delta` already do (which never consult `is_tombstoned`).
/// Only the CONTENT-side processing (trust-feed, zone-setup, propagation) stays
/// suppressed for a tombstoned record — those live before/after this block and are
/// skipped by its caller. Behavior-preserving move of the former ingest.rs Phase-4
/// block; see internal design notes.
async fn apply_ledger_op_phase4(
    state: &Arc<NodeState>,
    record: &ValidationRecord,
    creator_hash: String,
    parsed_ledger_op: Option<crate::accounting::types::ParsedLedgerOp>,
) {
    // Apply ledger/governance operation to ledger after successful storage.
    // Dedup check uses RocksDB CF_APPLIED (O(1) key lookup) instead of the in-memory
    // HashSet, which grew to 135K+ entries and made every ledger clone take seconds.
    // Check BEFORE acquiring the write lock to avoid contention on already-applied records.
    let was_already_applied = state.rocks.is_applied(&record.id);
    if was_already_applied {
        debug!("skipping ledger apply for {} (already in CF_APPLIED)", &record.id[..record.id.len().min(16)]);
    }

    // Phase 4: ledger write lock (skip entirely if already applied)
    state.insert_phase.store(4, std::sync::atomic::Ordering::Relaxed);
    // Fall-through flag: when ARCH-1 tentative-apply rejects an insert
    // (per-identity cap, global quota, duplicate), we direct-apply to the
    // committed ledger so the record still lands. Set true only when the
    // tentative path failed but the record is otherwise valid.
    let mut tentative_fallback_to_direct = false;
    if !was_already_applied {
        // ARCH-1 tentative path: mirror the ledger op into PendingLedger +
        // CF_PENDING_DELTAS instead of mutating the committed ledger.
        // The committed ledger is updated later, in
        // `pending_drain::drain_and_commit_pending`, only after consensus
        // promotes the record to `Finalized`. See
        // internal design notes.
        if let Some(parsed) = parsed_ledger_op.clone() {
            use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};
            let op = PendingOp::from_parsed(parsed, &creator_hash, &record.id);
            let delta = PendingLedgerDelta::new(
                record.id.clone(),
                creator_hash.clone(),
                record.timestamp,
                now(),
                op,
            );
            let insert_res = {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(delta.clone())
            };
            match insert_res {
                Ok(()) => match delta.to_json() {
                    Ok(bytes) => {
                        if let Err(e) = state.rocks.put_cf_raw(
                            crate::storage::rocks::CF_PENDING_DELTAS,
                            record.id.as_bytes(),
                            &bytes,
                        ) {
                            warn!(
                                "CF_PENDING_DELTAS put failed for {}: {e}",
                                &record.id[..record.id.len().min(16)]
                            );
                        }
                    }
                    Err(e) => warn!(
                        "pending delta serialize failed for {}: {e}",
                        &record.id[..record.id.len().min(16)]
                    ),
                },
                Err(reject) => {
                    state
                        .pending_ledger_rejections_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    state
                        .pending_ledger_fallback_direct_apply_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        "pending insert rejected for {}: {reject} — falling back to direct apply",
                        &record.id[..record.id.len().min(16)]
                    );
                    tentative_fallback_to_direct = true;
                }
            }
        }

        if !tentative_fallback_to_direct {
            // Creator-stake registration must still fire pre-finality so the
            // settlement threshold uses the right denominator. Reads committed
            // stake only — the tentative delta, even for a Stake op, isn't
            // counted until it commits.
            let ledger = state.ledger.read().await;
            let creator_staked = ledger.staked(&creator_hash);
            // F5: register the creator identity UNCONDITIONALLY (even at 0 stake)
            // so a self-attestation is always purge-eligible — closes the corner
            // where a creator staked at attest-time is slashed to 0 before its
            // record ingests. register_creator_stake stores the stake row only
            // when >0 and clears it at 0 (F4). Bounded: creator_identity is
            // purged on finalization, so it stays O(active window).
            {
                let mut consensus = state.consensus.lock_recover();
                consensus.register_creator_stake(&record.id, &creator_hash, creator_staked);
            }
            drop(ledger);
        }
    }
    if !was_already_applied && tentative_fallback_to_direct {
        let ledger_lock_t0 = std::time::Instant::now();
        let mut ledger = state.ledger.write().await;
        let ledger_lock_ms = ledger_lock_t0.elapsed().as_millis();
        if ledger_lock_ms > 5000 {
            warn!("ledger.write() lock took {ledger_lock_ms}ms for {} — possible contention", &record.id[..record.id.len().min(16)]);
        }
        if let Err(e) = ledger.apply_single_record(record, &state.config.genesis_authority) {
            warn!("ledger apply failed for {}: {e}", &record.id[..record.id.len().min(16)]);
        } else {
            // Gap 2: bump cross-zone counters on successful ledger apply.
            // Read xzone_op from record metadata — set by the RPC builders in
            // `cross_zone::lock_metadata` / `claim_metadata`.
            if let Some(op) = record
                .metadata
                .get(crate::accounting::cross_zone::XZONE_OP_KEY)
                .and_then(|v| v.as_str())
            {
                match op {
                    "lock" => {
                        state
                            .xzone_locks_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    "claim" => {
                        state
                            .xzone_claims_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {}
                }
            }

            // Transfer velocity counters — increment on successful transfer apply.
            if let Some(crate::accounting::types::ParsedLedgerOp::Transfer { amount, .. }) = parsed_ledger_op {
                state.beat_transfers_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                state.beat_volume_micros_total.fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
            }

            // Mark as applied in RocksDB for persistence across restarts.
            // spawn_blocking offloads the put_cf — under L0 compaction backlog
            // (DISC-4) this single write can stall 30-60s+, and on 1-vCPU
            // canaries that stall blocks the same tokio worker that serves
            // HTTP. Move it off the async runtime so axum stays responsive.
            let rocks = state.rocks.clone();
            let rid = record.id.clone();
            tokio::task::spawn_blocking(move || rocks.mark_applied(&rid));
        }

        // Register creator's stake for settlement threshold (MESH-BFT Def 18 amended).
        // Creator can't self-attest, so exclude their stake from settlement denominator.
        {
            let creator_staked = ledger.staked(&creator_hash);
            // F5: register creator identity unconditionally (see above).
            let mut consensus = state.consensus.lock_recover();
            consensus.register_creator_stake(&record.id, &creator_hash, creator_staked);
        }

        // Refresh consensus zone stakes after stake-affecting ops (stake/unstake/slash)
        if let Some(op_str) = record.metadata.get("beat_op").and_then(|v| v.as_str()) {
            if matches!(op_str, "stake" | "unstake" | "slash") {
                let mut consensus = state.consensus.lock_recover();
                consensus.register_stakes_from_ledger(&ledger);
            }

            // Mark slashed identities as abandoned for reincarnation detection (Protocol §6.4).
            // When an identity is slashed, any future identity with a similar behavioral
            // fingerprint will be flagged as a suspected reincarnation.
            if op_str == "slash" {
                if let Some(offender) = record.metadata.get("beat_offender").and_then(|v| v.as_str()) {
                    if let Ok(mut reinc) = state.reincarnation.try_lock() {
                        reinc.mark_abandoned(offender);
                        info!("reincarnation: marked {} as abandoned (slashed)", offender.chars().take(16).collect::<String>());
                    }
                }
            }
        }

        // Release ledger write lock immediately — everything below doesn't need it.
        drop(ledger);
    } else if was_already_applied {
        // Already-applied records still need creator stake registration for consensus.
        // Use a brief read lock instead of write lock.
        let ledger = state.ledger.read().await;
        let creator_staked = ledger.staked(&creator_hash);
        // F5: register creator identity unconditionally (see above).
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_creator_stake(&record.id, &creator_hash, creator_staked);
        }
        drop(ledger);
    }
}

async fn insert_record_inner(state: &Arc<NodeState>, mut record: ValidationRecord, origin_hint: Option<u64>, skip_timestamp_defense: bool) -> crate::errors::Result<String> {
    let ingest_t0 = std::time::Instant::now();
    // ── Bounds validation ────────────────────────────────────────────────
    // Wire size check: reject oversized records before expensive validation
    let wire_len = record.to_bytes().len();
    if wire_len > MAX_RECORD_BYTES {
        return Err(ElaraError::Wire(format!(
            "record too large: {} bytes (max {})", wire_len, MAX_RECORD_BYTES
        )));
    }
    if record.metadata.len() > MAX_METADATA_ENTRIES {
        return Err(ElaraError::Wire(format!(
            "too many metadata entries: {} (max {})", record.metadata.len(), MAX_METADATA_ENTRIES
        )));
    }
    for (key, val) in &record.metadata {
        let val_len = val.to_string().len();
        if val_len > MAX_METADATA_VALUE_LEN {
            return Err(ElaraError::Wire(format!(
                "metadata value for '{key}' too large: {val_len} bytes (max {MAX_METADATA_VALUE_LEN})"
            )));
        }
    }

    // ── Ledger content-hash v2 enforcement (audit 2026-07-06) ───────────
    // A beat_op record's content_hash must commit to its signed metadata
    // via the canonical v2 preimage, else an equivocator hand-sets equal
    // hashes on conflicting records / poisons the by-hash index. DEFAULT
    // OFF: catch-up paths re-ingest pre-v2 history and would wedge — the
    // flag flips ON at the re-genesis (fresh chain, all records v2).
    if state.config.enforce_ledger_content_hash_v2 {
        if let Err(e) = crate::accounting::types::verify_ledger_content_hash_v2(&record) {
            state
                .ledger_content_hash_v2_rejected_total
                .fetch_add(1, Relaxed);
            return Err(e);
        }
    }
    // ── Storage-backed dedup (catches records that fell out of SeenSet FIFO) ──
    // SeenSet is 50K entries per node. Once evicted, records pass the in-memory
    // check and go through the full pipeline (sig verify ~2-15ms, RocksDB write,
    // Merkle insert). This O(1) RocksDB key lookup (~0.01ms from block cache)
    // short-circuits the entire pipeline for already-stored records.
    if state.rocks.record_exists(&record.id).unwrap_or(false) {
        // 8b design B (successor-re-admission — closes the 2026-07-01 §2b gap
        // documented at the chain-link reject in Phase 5): "stored ⇒
        // processed" is FALSE for seals. Phase-2 storage and Phase-5
        // canonicalization are not atomic, and a chain-link-rejected
        // sequential seal returns Ok — so once its honest re-offer lands
        // here it would dedup away forever, even after the phantom tip it
        // failed to chain to is corrected. Re-flow the FULL pipeline (every
        // registration primitive is idempotent) for exactly the healable
        // class; everything else short-circuits as before.
        if should_reenter_stored_seal(&record, &state.epoch.read_recover()) {
            state.seal_ingest_reentry_total.fetch_add(1, Relaxed);
            info!(
                "seal re-entry: stored seal {} is the uncanonicalized strict successor — re-flowing full pipeline",
                &record.id[..record.id.len().min(16)]
            );
        } else {
            // Re-populate SeenSet so future checks avoid even the RocksDB lookup
            state.seen.lock_recover().insert(record.id.clone());
            state.gossip_seen_dedup_total.fetch_add(1, Relaxed);
            debug!("storage dedup: {} already in RocksDB, skipping full pipeline", &record.id[..record.id.len().min(16)]);
            return Ok(record.id);
        }
    }

    // Disk-pressure gate covers ALL ingest sources (RPC, gossip pull,
    // gossip push, sync). An earlier version checked `disk_pressure` only on
    // `/records` POST; peer pushes kept writing through the gate and ate the
    // last GB of disk → daemon exited at ENOSPC. Placed AFTER the dedup check
    // so already-stored records still ack with their existing id (a re-push of
    // a record we already have allocates no disk). Rejection is non-fatal —
    // disk_pressure_loop self-clears when avail > 1GB and live < 80% cap, and
    // ingest resumes immediately.
    //
    // Only avail-based pressure rejects ingest now. Cap-based
    // pressure (live > 95% × disk_cap_bytes) drives GC compaction and
    // retention compression but does not block ingest, because the cap is
    // operator policy, not real disk-full safety. An earlier
    // trap fired because cap-based pressure was hard-rejecting ingest on
    // small VPS volumes whose legitimate working set exceeded the 70% FS
    // clamp — even though FS still had headroom.
    if state.under_avail_pressure() {
        state.disk_pressure_rejected_ingest_total.fetch_add(1, Relaxed);
        return Err(ElaraError::Storage("disk pressure: ingest rejected".into()));
    }

    // ── Content safety gate (reject before any expensive validation) ────
    // 1. Identity ban check — banned creators' records never enter the system
    let creator_hash_early = crate::accounting::types::creator_identity_hash(&record);

    // ── Emergency-halt ingest gate (signed consensus circuit-breaker) ──────
    // When a signed EmergencyHalt is active, refuse NEW non-authority external
    // writes (retryable 429). Admitted while halted: synced records
    // (skip_timestamp_defense — followers keep tracking sealed history), the
    // authority's own records (it issued the halt — seals / governance / the resume
    // itself), and any emergency op (so resume/halt always flow). Node-local +
    // wall-clock self-clearing — identical fork-character to the disk-pressure gate.
    // A spoofed authority pubkey passes this cheap sha3 check but dies at the
    // downstream signature verify, so the carve-out cannot be abused.
    if state.emergency_halted_now(now() as u64) {
        let is_authority =
            creator_hash_early.eq_ignore_ascii_case(&state.config.genesis_authority);
        let is_emergency_op = record
            .metadata
            .contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
            || record
                .metadata
                .contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY);
        if !skip_timestamp_defense && !is_authority && !is_emergency_op {
            state.emergency_rejected_ingest_total.fetch_add(1, Relaxed);
            return Err(ElaraError::RateLimited);
        }
    }
    {
        let banned = state.banned_identities.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        if let Err(e) = crate::content_safety::check_banned_identity(&creator_hash_early, &banned) {
            state.banned_rejections_total.fetch_add(1, Relaxed);
            return Err(e);
        }
    }
    // 2. Key admission (forward-compat) + text sanitization + URL rejection
    crate::content_safety::validate_metadata_keys(&record.metadata)?;
    // Forward-compat observability: count admitted keys this binary's schema
    // registry doesn't know. Growth = peers run a newer schema than us; the
    // node stays in sync (unknown keys are inert) but an upgrade is due.
    let unknown_keys = record
        .metadata
        .keys()
        .filter(|k| !crate::content_safety::is_known_key(k))
        .count() as u64;
    if unknown_keys > 0 {
        state
            .unknown_metadata_keys_admitted_total
            .fetch_add(unknown_keys, Relaxed);
    }
    crate::content_safety::sanitize_text_fields(&record.metadata)?;
    // 3. Content blocklist scan — reject records with blocked terms
    {
        let blocklist = state.content_blocklist.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        if let Err(e) = crate::content_safety::scan_blocked_content(&record.metadata, &blocklist) {
            state.content_rejections_total.fetch_add(1, Relaxed);
            return Err(e);
        }
    }
    // 3b. Agent-mandate ingest gate (C4 slice 1). Runs here — before the
    // skip_timestamp_defense rate-limit bypass — so the per-record size cap also
    // bounds relayed/synced floods into the GC-exempt mandate CFs. Rejects a
    // malformed/oversized/cross-network/principal-mismatched issuance or
    // revocation; act records (mandate_ref) always pass (flagged at query).
    crate::network::mandate_node::validate_mandate_ingest(&record, &state.config.network_id)?;
    // 3c. Emergency halt/resume ingest gate — reject a malformed / oversized /
    // cross-network / non-authority-signed circuit-breaker op (the op ACTS, so it
    // authorizes at ingest, unlike a read-time-inert mandate revocation).
    crate::network::emergency_node::validate_emergency_ingest(
        &record,
        &state.config.network_id,
        &state.config.genesis_authority,
    )?;

    if record.parents.len() > MAX_PARENTS {
        return Err(ElaraError::Wire(format!(
            "too many parents: {} (max {})", record.parents.len(), MAX_PARENTS
        )));
    }
    // Reject non-finite timestamps (NaN/Infinity) and any negative-sign value.
    // `is_sign_negative()` rejects all negatives AND -0.0 — the latter matters
    // because -0.0's big-endian bytes (0x8000…) sort ABOVE every positive in the
    // CF_IDX_TIMESTAMP index, but f64::total_cmp orders -0.0 BELOW +0.0. The
    // streaming ledger rebuild trusts the index byte-order; allowing -0.0 would
    // let a crafted record desync the streamed rebuild from a total_cmp sort
    // (audit 16e). +0.0 stays allowed (it sorts smallest, matching total_cmp).
    if !record.timestamp.is_finite() || record.timestamp.is_sign_negative() {
        return Err(ElaraError::Wire(format!(
            "invalid timestamp: {}", record.timestamp
        )));
    }
    // Reject records with timestamps significantly in the future
    let now_ts = now();
    if record.timestamp > now_ts + MAX_FUTURE_DRIFT_SECS {
        return Err(ElaraError::Wire(format!(
            "timestamp too far in future: {} (now: {:.0}, max drift: {}s)",
            record.timestamp, now_ts, MAX_FUTURE_DRIFT_SECS
        )));
    }
    // Warn on old records but accept them — offline-first nodes may submit
    // records created days or weeks ago when they finally get connectivity.
    // Replay protection is handled by storage dedup (duplicate IDs rejected)
    // and ledger validation (stale ops fail against current ledger state).
    let max_age = state.config.max_record_age_secs;
    if max_age > 0.0 && (now_ts - record.timestamp) > max_age {
        warn!(
            "old record accepted: timestamp {:.0} is {:.1} days old (threshold: {:.1} days)",
            record.timestamp,
            (now_ts - record.timestamp) / 86400.0,
            max_age / 86400.0,
        );
    }

    // ── Timestamp defense (causal ordering + zone consensus + rate limit) ──
    // Runs BEFORE expensive signature verification.
    // Skipped for synced (historical) records — old timestamps would poison
    // the zone drift estimator and cause all new records to be rejected.
    if !skip_timestamp_defense {
        let parent_ts = if record.parents.is_empty() {
            None
        } else {
            // Look up the latest parent timestamp from the DAG index
            let dag = state.dag.read().await;
            record.parents.iter()
                .filter_map(|pid| dag.timestamps.get(pid).copied())
                .reduce(f64::max)
        };
        // Gap 4 routing-application: walk the zone registry from the naive
        // flat-modulo zone so timestamp defense keys on the same leaf that
        // the record will ultimately live in post-split.
        let record_zone = state.resolve_record_zone(&record.id);
        let creator_hash_td = crate::accounting::types::creator_identity_hash(&record);
        let mut defense = state.timestamp_defense.lock_recover();
        let verdict = defense.validate(
            record.timestamp,
            now_ts,
            parent_ts,
            &creator_hash_td,
            record_zone,
        );
        if !verdict.is_valid() {
            return Err(ElaraError::Wire(format!(
                "timestamp defense rejected: {}", verdict.as_str()
            )));
        }
    }

    // ── Slot mutual exclusion (MESH-BFT Phase 3 Stage 1C) ────────────────
    // At most one record per (account, nonce) slot may enter the DAG.
    // A second record for the same slot is equivocation — reject at ingest
    // and (Stage 1D) emit a ConflictProof for gossip-based slashing.
    //
    // Only wire v5+ records carry a signed nonce. v4 records have no slot
    // and are grandfathered through this check (they'll migrate in Stage 1F).
    //
    // ARCH-4(b) split: this block now ONLY rejects against an existing
    // claimant — it does not register the slot. The actual claim happens
    // atomically with the record write inside `put_record_with_pk_zone`'s
    // WriteBatch (see "ARCH-4(b) atomic slot claim" below). Pre-verify
    // claiming was the source of orphan slot index entries on bad-sig
    // ingests (the slot pointer persisted while the record payload was
    // dropped on `dilithium3_verify` failure → fleet zombies, see
    // ARCH-4(a) eviction sweep 2026-04-28).
    if let Some(slot_key) = record.slot_key() {
        match state.rocks.slot_lookup(&slot_key) {
            Ok(Some(existing_id)) => {
                if existing_id != record.id {
                    return Err(handle_slot_conflict(
                        state,
                        &slot_key,
                        existing_id,
                        &record,
                    ));
                }
                // Same record_id — idempotent re-ingest, fall through.
            }
            Ok(None) => {
                // First-seen: do NOT claim here. The slot is registered
                // atomically with the record write further down so a
                // sig-verify failure can never leak an orphan slot entry.
            }
            Err(e) => {
                return Err(ElaraError::Storage(format!(
                    "slot_lookup failed for {}: {}", slot_key, e
                )));
            }
        }
    }

    // ── Zone-scoped gossip filtering (Steps 3+4) ──────────────────────────
    // Only process records for zones this node is subscribed to.
    // Epoch seals and ledger ops bypass zone filtering (global operations).
    {
        // Gap 4 routing-application: subscribe-check uses the resolved leaf
        // so zone-scoped subscribers don't drop records destined for their
        // post-split leaf just because the naive modulo zone hasn't been
        // their subscription since the parent split.
        let record_zone = state.resolve_record_zone(&record.id);
        let is_global_op = record.metadata.contains_key(EPOCH_OP_KEY)
            || record.metadata.contains_key("beat_op")
            // Emergency halt/resume is a network-wide signal — it must reach every
            // node regardless of zone subscription, else a zone-scoped follower
            // drops the halt before store/gossip and never pauses.
            || record.metadata.contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
            || record.metadata.contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY);

        if !is_global_op {
            let zone_mgr = state.zone_manager.lock_recover();
            if !zone_mgr.subscribed_zones().is_empty() && !zone_mgr.is_subscribed(&record_zone) {
                return Err(ElaraError::Wire(format!(
                    "record zone {} not in subscribed zones (zone-scoped filtering)",
                    record_zone
                )));
            }
            // If no subscriptions set, accept all zones (backward compat / testnet)
        }

        // ── DAM-3D Phase A: same-zone parents gate ─────────────────────────
        // Spec: internal design notes §3 Gap A. Every record's parents must resolve
        // to the same zone as the record, or to an ancestor zone (soft-split
        // model). Genesis (empty parents) and global ops (epoch seals, token
        // mints, governance) bypass — they're authority records, not zone
        // traffic. Default config soft-warns; mainnet
        // (`allow_cross_zone_parents=false`) hard-rejects.
        if !is_global_op && !record.parents.is_empty() {
            let parent_zones: Vec<super::zone::ZoneId> = record
                .parents
                .iter()
                .map(|pid| state.resolve_record_zone(pid))
                .collect();
            match super::zone::check_cross_zone_parents(&record_zone, &parent_zones) {
                super::zone::CrossZoneParentsDecision::AllSameOrAncestorZone => {}
                super::zone::CrossZoneParentsDecision::HasCrossZoneParents { count } => {
                    state
                        .cross_zone_parent_observed_total
                        .fetch_add(1, Relaxed);
                    if !state.config.allow_cross_zone_parents {
                        state
                            .cross_zone_parent_rejected_total
                            .fetch_add(1, Relaxed);
                        return Err(ElaraError::Wire(format!(
                            "DAM-3D Phase A: record {} in zone {} has {} parent(s) in non-ancestor zones; allow_cross_zone_parents=false",
                            &record.id[..record.id.len().min(16)],
                            record_zone,
                            count,
                        )));
                    }
                    debug!(
                        "DAM-3D Phase A soft-warn: record {} in zone {} has {} cross-zone parents (allow_cross_zone_parents=true)",
                        &record.id[..record.id.len().min(16)],
                        record_zone,
                        count,
                    );
                }
            }
        }

        // ── DAM-3D Phase C Slice 1: zone_refs observability ────────────────
        // Spec: internal design notes §3 Gap C. Delegated to
        // `super::zone::classify_and_count_zone_refs` so the loop body
        // is unit-testable independently of NodeState fixtures.
        if !record.zone_refs.is_empty() {
            let counters = super::zone::ZoneRefCounters {
                observed: &state.zone_ref_observed_total,
                anchored: &state.zone_ref_anchored_total,
                ghost: &state.zone_ref_ghost_total,
                deferred: &state.zone_ref_deferred_total,
            };
            super::zone::classify_and_count_zone_refs(
                &record.zone_refs,
                counters,
                |zone_id| state.zone_manager.lock_recover().is_subscribed(zone_id),
                |epoch, path| state.rocks.seal_exists_at_zone_epoch(epoch, path),
            );
        }
    }

    // ── DAG hot tier management — evict old finalized records if needed ──
    // Read lock first for the common case (not full). Write lock only if eviction needed.
    // Previously took a write lock on EVERY record — caused contention spikes up to 21s.
    {
        let dag_read_t0 = std::time::Instant::now();
        let needs_eviction = state.dag.read().await.is_full();
        let dag_read_ms = dag_read_t0.elapsed().as_millis();
        // Lock-contention observability: early-warning
        // counter at 500ms surfaces contention as a Prometheus signal BEFORE
        // the 5000ms warn-level threshold is reached. See state.rs HELP text.
        if dag_read_ms > 500 {
            state
                .lock_acquire_dag_read_slow_total
                .fetch_add(1, Relaxed);
        }
        if dag_read_ms > 5000 {
            warn!("dag.read() for eviction check took {dag_read_ms}ms — possible contention");
        }
        if needs_eviction {
            // Tiered DAG: snapshot the FinalizedIndex hot set
            // BEFORE taking the DAG write lock so the cascade-fallback predicate
            // is a pure HashSet lookup — no RocksDB I/O while holding DAG. Cheap
            // (≤10K strings); only allocated when DAG is full, which is rare.
            let finalized_snapshot = state.finalized.read().await.hot_set_clone();

            let mut dag_guard = state.dag.write().await;
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            // Double-check after acquiring write lock (another task may have evicted)
            if dag.is_full() {
                let evicted = dag.evict_old_epochs();
                if evicted > 0 {
                    debug!("dag hot tier: evicted {evicted} old finalized records");
                }
                if dag.is_full() {
                    // Cascade: epoch-window eviction didn't free room.
                    // Fall through to FinalizedIndex-driven eviction — catches
                    // records finalized externally but never `mark_finalized`'d
                    // in the DAG (legacy snapshot reload, finality-monitor wiring
                    // gap). Predicate is the snapshot taken above so this is
                    // O(dag_size) HashSet lookups, no RocksDB I/O.
                    let cascade_evicted = dag.evict_finalized(|id| finalized_snapshot.contains(id));
                    state
                        .dag_evict_finalized_cascade_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if cascade_evicted > 0 {
                        info!(
                            "dag hot tier cascade eviction: {cascade_evicted} records evicted via FinalizedIndex hot snapshot"
                        );
                    }
                    if dag.is_full() {
                        state
                            .dag_hot_tier_full_rejections_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Err(ElaraError::Wire(format!(
                            "DAG hot tier full: {} records after epoch+cascade eviction (max {})",
                            dag.len(),
                            crate::dag::HOT_MAX_FALLBACK,
                        )));
                    }
                }
            }
        }
    }

    // DISC-4 Phase D-2: checkpoint after validation + DAG hot-tier eviction.
    // Splits the opaque "pre" bucket into (val, sig, rest) so slow-record
    // warns pinpoint whether the stall is in await-lock contention on
    // `state.dag.read()` / content-safety gates (val), pure-Rust Dilithium3
    // + SPHINCS+ verify (sig), or the ledger-snapshot + ITC window (rest).
    let val_end_ms = ingest_t0.elapsed().as_millis();

    // Verify creator's Dilithium3 (1-4 ms) + optional SPHINCS+ (~10 ms)
    // signatures in ONE spawn_blocking hop off the async workers
    // (internal design notes — supersedes the old
    // deliberate-inline choice: on the PQ path the dispatch-level
    // `pq_verify_semaphore` permit bounds the aggregate, with permits ≈ CPU
    // count so healthy-node throughput is unchanged; the field clones are KiBs
    // against multi-ms verifies). Error precedence preserved exactly:
    // missing/bad Dilithium3 → InvalidSignature, then incomplete Profile A →
    // Wire, then bad SPHINCS+ → InvalidSignature.
    let sig = record
        .signature
        .as_ref()
        .ok_or(ElaraError::InvalidSignature)?
        .clone();
    let signable = record.signable_bytes();
    let dil_pk = record.creator_public_key.clone();
    let sphincs_sig = record.sphincs_signature.clone();
    let sphincs_pk = record.creator_sphincs_pk.clone();
    tokio::task::spawn_blocking(move || -> crate::errors::Result<()> {
        if !dilithium3_verify(&signable, &sig, &dil_pk)? {
            return Err(ElaraError::InvalidSignature);
        }

        // Profile enforcement: SPHINCS+ pk and sig must be consistent (both or neither)
        if sphincs_pk.is_some() && sphincs_sig.is_none() {
            return Err(ElaraError::Wire(
                "SPHINCS+ public key present but no SPHINCS+ signature (incomplete Profile A)".to_string()
            ));
        }

        // Verify SPHINCS+ signature if present (Profile A dual-sig)
        if let Some(ssig) = &sphincs_sig {
            let spk = sphincs_pk.as_ref()
                .ok_or_else(|| ElaraError::Wire(
                    "SPHINCS+ signature present but no SPHINCS+ public key in record".to_string()
                ))?;
            if !crate::crypto::pqc::sphincs_verify(&signable, ssig, spk)? {
                return Err(ElaraError::InvalidSignature);
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    // DISC-4 Phase D-2: checkpoint after Dilithium3 + SPHINCS+ verify.
    // Anything after this and before `pre_phase2_ms` is the ledger-snapshot
    // window (`state.ledger.read().await`), trust-tier + ledger-op validation,
    // ITC stamping, and relevance tracking. Lock-contention stalls in this
    // range usually point at the ledger RwLock (contended by the phase-4
    // ledger write lock on heavy-write paths).
    let sig_end_ms = ingest_t0.elapsed().as_millis();

    // Profile B transfer cap: single-sig identities limited to 1,000 beat per transfer.
    // Profile A (dual-sig) has no cap. PQ security boundary.
    if record.sphincs_signature.is_none() {
        if let Some(amount_val) = record.metadata.get("beat_amount").and_then(crate::accounting::types::parse_beat_amount) {
            use crate::accounting::types::{PROFILE_B_TRANSFER_CAP, BASE_UNITS_PER_BEAT};
            if amount_val > PROFILE_B_TRANSFER_CAP {
                let op = record.metadata.get("beat_op").and_then(|v| v.as_str()).unwrap_or("?");
                if op == "transfer" || op == "stake" {
                    return Err(ElaraError::Wire(format!(
                        "Profile B (single-sig) limited to {} beat per {op} (got {} beat)",
                        PROFILE_B_TRANSFER_CAP / BASE_UNITS_PER_BEAT,
                        amount_val / BASE_UNITS_PER_BEAT,
                    )));
                }
            }
        }
    }

    // Step 2.5: Reject records signed by revoked keys (Protocol §11.2)
    {
        let registry = state.key_registry.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        if registry.is_revoked(&record.creator_public_key) {
            state.revocations_rejected_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(
                "record signed by revoked key".to_string(),
            ));
        }
    }

    // Profile C Gap A: gate `delegation_op` records on creator's NodeType
    // (gossiped via heartbeat) or stake. Without this, a Leaf could publish
    // authorize records and inflate its child count to game trust scoring.
    // Spec: internal design notes §3 Gap A, economics §4.3.
    if record.metadata.contains_key(crate::accounting::delegation::DELEGATION_OP_KEY) {
        let creator_hash_da = creator_identity_hash(&record);
        // Resolve creator's role: peer-table lookup (gossiped heartbeat),
        // fall back to local config when the creator IS this node — the peer
        // table never holds self (set_local_identity rejects self-inserts).
        let role_str: Option<String> = if creator_hash_da == state.identity.identity_hash {
            Some(state.config.node_type.clone())
        } else {
            state.peers.read().await
                .get(&creator_hash_da)
                .map(|p| p.node_type.as_str().to_string())
        };
        // Single ledger snapshot for both Gap A balance check and Gap C attestation lookup.
        let (balance, ledger_attestation) = {
            let l = state.ledger.read().await;
            (l.account(&creator_hash_da).total(), l.attestation_level(&creator_hash_da))
        };
        use crate::accounting::delegation::{
            check_delegation_authorization, check_gateway_attestation, extract_attestation_level,
            DelegationAuthDecision, GatewayAttestationDecision, MIN_STAKE_TO_DELEGATE,
        };
        if matches!(
            check_delegation_authorization(role_str.as_deref(), balance),
            DelegationAuthDecision::Rejected
        ) {
            state.delegation_op_rejected_role_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "delegation_op rejected: creator {} is not Gateway/Anchor and stake {} beat < {} beat minimum",
                &creator_hash_da[..creator_hash_da.len().min(16)],
                balance / crate::accounting::types::BASE_UNITS_PER_BEAT,
                MIN_STAKE_TO_DELEGATE / crate::accounting::types::BASE_UNITS_PER_BEAT,
            )));
        }

        // Profile C Gap C: gateway attestation gate. Only applies on
        // `authorize` (parents adding children); revocations are intentionally
        // ungated so emergency revoke works in degraded hardware. The gate
        // takes the higher of the ledger-recorded level and the current
        // record's metadata so a parent can self-bootstrap by including
        // `attestation_level` on its first authorize.
        // Spec: internal design notes §3 Gap C, economics §11.33.
        if let Some(op_str) = record
            .metadata
            .get(crate::accounting::delegation::DELEGATION_OP_KEY)
            .and_then(|v| v.as_str())
        {
            if op_str == "authorize" {
                let inline_level = extract_attestation_level(&record)
                    .unwrap_or(crate::identity::AttestationLevel::None);
                let effective = if inline_level.rank() > ledger_attestation.rank() {
                    inline_level
                } else {
                    ledger_attestation
                };
                let floor = state.config.min_attestation_for_gateway;
                if matches!(
                    check_gateway_attestation(effective, floor),
                    GatewayAttestationDecision::Rejected
                ) {
                    state.attestation_gate_rejected_total.fetch_add(1, Relaxed);
                    return Err(ElaraError::Wire(format!(
                        "delegation_op authorize rejected: gateway {} attestation {} below required floor {} \
                         (advertise via attestation_level metadata; testnet operators may set ELARA_MIN_ATTESTATION_FOR_GATEWAY=NONE)",
                        &creator_hash_da[..creator_hash_da.len().min(16)],
                        effective.as_str(),
                        floor.as_str(),
                    )));
                }

                // Profile C Gap E: per-parent capacity gate. One write lock
                // batches the child_count read, the rate-window prune, and
                // the rate-window record so concurrent ingest tasks see a
                // consistent view (no double-commit past the cap).
                // Spec: internal design notes §3 Gap E.
                use crate::accounting::delegation::{
                    check_authorize_caps, AuthorizeCapDecision,
                    MAX_AUTHORIZE_PER_PARENT_PER_HOUR, MAX_CHILDREN_PER_PARENT,
                };
                let cap_decision = {
                    let mut reg = state
                        .delegations
                        .write()
                        .map_err(|e| ElaraError::Storage(e.to_string()))?;
                    let child_count = reg.child_count(&creator_hash_da);
                    let in_window =
                        reg.authorize_count_in_window(&creator_hash_da, record.timestamp);
                    let decision = check_authorize_caps(child_count, in_window);
                    if matches!(decision, AuthorizeCapDecision::Allowed) {
                        reg.record_authorize_event(&creator_hash_da, record.timestamp);
                    }
                    decision
                };
                match cap_decision {
                    AuthorizeCapDecision::Allowed => {}
                    AuthorizeCapDecision::ChildCapExceeded => {
                        state
                            .delegation_child_cap_rejected_total
                            .fetch_add(1, Relaxed);
                        return Err(ElaraError::Wire(format!(
                            "delegation_op authorize rejected: parent {} already at MAX_CHILDREN_PER_PARENT={}",
                            &creator_hash_da[..creator_hash_da.len().min(16)],
                            MAX_CHILDREN_PER_PARENT,
                        )));
                    }
                    AuthorizeCapDecision::RateCapExceeded => {
                        state
                            .delegation_rate_cap_rejected_total
                            .fetch_add(1, Relaxed);
                        return Err(ElaraError::Wire(format!(
                            "delegation_op authorize rejected: parent {} exceeded MAX_AUTHORIZE_PER_PARENT_PER_HOUR={}",
                            &creator_hash_da[..creator_hash_da.len().min(16)],
                            MAX_AUTHORIZE_PER_PARENT_PER_HOUR,
                        )));
                    }
                }
            } else if op_str == "revoke_all" {
                // Profile C Gap D: mass-revocation authorization gate.
                // Two paths:
                //   (1) Voluntary — creator IS the parent_to_disarm (self-signed handoff).
                //   (2) Involuntary (fisherman) — sum of cosigner ledger stakes
                //       crosses the 2/3 supply threshold; each cosigner sig
                //       must verify against the canonical message via Dilithium3.
                // Spec: internal design notes §3 Gap D.
                use crate::accounting::delegation::{
                    check_revoke_all_authorization, extract_revoke_all,
                    revoke_all_canonical_message, verify_cosigner_proof,
                    RevokeAllAuthDecision,
                };
                let parsed = extract_revoke_all(&record).inspect_err(|_e| {
                    state.revoke_all_rejected_total.fetch_add(1, Relaxed);
                })?;
                let parsed = match parsed {
                    Some(p) => p,
                    None => {
                        // Op string says revoke_all but extractor returned
                        // None — should be impossible given the str check.
                        state.revoke_all_rejected_total.fetch_add(1, Relaxed);
                        return Err(ElaraError::Wire(
                            "revoke_all parser returned None despite op string match".into(),
                        ));
                    }
                };

                // Verify each cosigner Dilithium3 sig over the canonical message,
                // collect the sum of their ledger balances. We deliberately do
                // NOT trust caller-supplied stake claims; only the live ledger.
                let canonical = revoke_all_canonical_message(
                    &parsed.parent_to_disarm,
                    parsed.reason,
                    record.timestamp,
                );
                let total_supply = {
                    let l = state.ledger.read().await;
                    l.total_supply as u128
                };
                let mut valid_stake_sum: u128 = 0;
                let mut seen_cosigners: HashSet<String> = HashSet::new();
                if !parsed.cosigners.is_empty() {
                    let l = state.ledger.read().await;
                    for proof in &parsed.cosigners {
                        let cosigner_hash = match verify_cosigner_proof(proof, &canonical) {
                            Ok(h) => h,
                            Err(_) => continue, // skip invalid sigs silently for sum
                        };
                        if !seen_cosigners.insert(cosigner_hash.clone()) {
                            continue; // duplicate cosigner — count once
                        }
                        let bal = l.account(&cosigner_hash).total() as u128;
                        valid_stake_sum = valid_stake_sum.saturating_add(bal);
                    }
                }

                let decision = check_revoke_all_authorization(
                    &creator_hash_da,
                    &parsed.parent_to_disarm,
                    valid_stake_sum,
                    total_supply,
                );
                match decision {
                    RevokeAllAuthDecision::Voluntary => {
                        state.revoke_all_voluntary_total.fetch_add(1, Relaxed);
                    }
                    RevokeAllAuthDecision::Involuntary => {
                        state.revoke_all_involuntary_total.fetch_add(1, Relaxed);
                    }
                    RevokeAllAuthDecision::Rejected => {
                        state.revoke_all_rejected_total.fetch_add(1, Relaxed);
                        return Err(ElaraError::Wire(format!(
                            "revoke_all rejected: creator {} is not parent {} and cosigner stake {} beat < 2/3 of supply {} beat",
                            &creator_hash_da[..creator_hash_da.len().min(16)],
                            &parsed.parent_to_disarm[..parsed.parent_to_disarm.len().min(16)],
                            valid_stake_sum / crate::accounting::types::BASE_UNITS_PER_BEAT as u128,
                            total_supply / crate::accounting::types::BASE_UNITS_PER_BEAT as u128,
                        )));
                    }
                }
            }
        }
    }

    // Trust tier check — daily record limit per identity (stake-gated: economics 9.4)
    // Delegation (Protocol v0.6.2 Section 6.2): delegated children inherit parent's trust/stake.
    let creator_hash = creator_identity_hash(&record);
    let is_batch = record.metadata.contains_key(BATCH_OP_KEY);

    // Profile C Gap B: registered children must use parent proxy-sign — they
    // cannot directly sign records with their own key. The DelegationRegistry
    // entry IS the on-chain ProfileC marker today (an identity that's a
    // registered child is, by protocol intent, a constrained device with no
    // PQ keys; the parent signs on its behalf). If the wire's
    // `creator_public_key` hashes to a registered child, that means the child
    // signed with its own key, defeating the IoT delegation premise.
    // Allowed exception: the establishment delegation_op authorize/revoke
    // record itself — it carries delegation_op metadata so it skips this gate
    // (Gap A handles authorization for those).
    // Spec: internal design notes §3 Gap B, §7 acceptance criterion 2.
    let is_delegation_op = record.metadata.contains_key(crate::accounting::delegation::DELEGATION_OP_KEY);
    {
        use crate::accounting::delegation::{check_profile_c_gate, ProfileCGateDecision};
        let is_registered_child = {
            let deleg = state.delegations.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
            deleg.parent_of(&creator_hash).is_some()
        };
        if matches!(
            check_profile_c_gate(is_registered_child, is_delegation_op),
            ProfileCGateDecision::Rejected
        ) {
            state.profile_c_gate_rejected_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "ProfileC gate: registered delegation child {} cannot directly sign records — parent must proxy-sign",
                &creator_hash[..creator_hash.len().min(16)]
            )));
        }
    }

    let trust_identity = {
        let deleg = state.delegations.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        if is_batch {
            deleg.check_batch_submission(&creator_hash)?
        } else {
            deleg.check_submission(&creator_hash)?
        }
    };
    // If delegated, use parent for trust/stake; otherwise use creator directly
    let effective_identity = trust_identity.as_deref().unwrap_or(&creator_hash);
    // ── Single ledger read snapshot — consolidates 4 separate reads into 1 ──
    // Extracts all validation data in one tokio RwLock read, then drops the lock.
    // Previously acquired the ledger read lock 4 separate times (trust check,
    // ledger validation, governance validation, fisherman stake check), each
    // potentially contending with the ledger write lock during commit.
    let parsed_ledger_op = extract_ledger_op(&record)?;
    let parsed_gov_op = {
        use crate::accounting::governance::{extract_governance_op, GOVERNANCE_OP_KEY};
        if record.metadata.contains_key(GOVERNANCE_OP_KEY) {
            extract_governance_op(&record.metadata)?
        } else {
            None
        }
    };
    let parsed_dispute_op = if record.metadata.contains_key(super::dispute::DISPUTE_OP_KEY) {
        super::dispute::extract_dispute_op(&record.metadata).ok().flatten()
    } else {
        None
    };
    let parsed_challenge_op = if record.metadata.contains_key(super::fisherman::CHALLENGE_OP_KEY) {
        super::fisherman::extract_challenge_op(&record.metadata).ok().flatten()
    } else {
        None
    };

    // DISC-4 D-7: checkpoint right before the contended ledger snapshot.
    // Pattern A's "rest=34s" hot path is most likely a stall on this RwLock
    // when Phase 4 ledger write holds it. Splitting rest into (rpre, ldg, tail)
    // pinpoints the bucket so the next warn says whether the stall is here
    // or somewhere else in the sig_end→pre_phase2 window.
    let rest_rpre_end_ms = ingest_t0.elapsed().as_millis();

    // Capture staked amount and governance params for stake-scaled rate limiting.
    // These must survive past the ledger lock scope.
    let (staked_micro, stake_ratio, gov_prop_rate) = {
        let ledger = state.ledger.read().await;
        let staked_micro = ledger.staked(effective_identity);
        let stake_ratio = ledger.governance.params.stake_throughput_ratio;
        let gov_prop_rate = ledger.governance.params.propagation_rate_limit_per_hour;

        // Trust-tier HARD daily cap + reincarnation clamp MOVED to the non-skippable
        // `NodeState::daily_caps` gate below (after the propagation limiter). The old
        // try_read on `state.trust` here dropped BOTH the check and the counter update
        // whenever feed_attestation / trust-prune held the trust lock — exactly the
        // window a flood exploits — so the per-identity 20/day cap leaked under load.
        // The authoritative count now lives in DailyCapCounter (its own short-lived
        // lock); the tier/entropy LIMIT is still read best-effort from the trust
        // profile there, falling back to the strictest tier on contention.

        // Ledger op validation.
        // `enforce_rate_limits = !skip_timestamp_defense`: the circuit-breaker /
        // velocity / acquisition gates inside validate_op read `#[serde(skip)]`
        // per-node trackers, so running them as an accept/reject gate on a
        // synced/sealed record forks a snapshot-bootstrapped follower from a
        // since-genesis node (replay-audit finding 3 / Track D). `skip_timestamp_defense`
        // is true for BOTH Sync and GossipPush sources — both carry records that
        // already passed the origin's admission and flow toward consensus, so both
        // must skip these node-local rate-limiters (re-enforcing on gossip would
        // reintroduce the fork on the gossip path). apply_op still enforces the
        // deterministic validity rules on every path.
        if let Some(ref parsed_op) = parsed_ledger_op {
            let result = validate_op(&ledger, &creator_hash, &state.config.genesis_authority, parsed_op, record.timestamp, !skip_timestamp_defense);
            if !result.valid {
                return Err(ElaraError::Ledger(
                    result.error.unwrap_or_else(|| "invalid ledger operation".into()),
                ));
            }
            // Observability-only (design-audit verdict 2026-06-15, 3-agent fusion):
            // a cross-zone lock's DECLARED source_zone is never re-derived because a
            // wrong value is self-defeating — the claim's verify_finality_quorum binds
            // the zone path, so a forged zone can't be claimed and refunds after 24h.
            // A hard reject would fork ingest across the zone-split migration window
            // for zero security gain. We only COUNT the divergence so a buggy
            // account/SDK (stale zone count) is diagnosable. resolve_record_zone is
            // registry-aware (O(split-depth)); never zone-labelled.
            if let crate::accounting::types::ParsedLedgerOp::XZoneLock { source_zone, .. } = parsed_op {
                let resolved = state.resolve_record_zone(&record.id);
                if resolved.path() != source_zone.as_str() {
                    state
                        .xzone_lock_declared_zone_mismatch_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // Governance op validation
        if let Some(ref gov_op) = parsed_gov_op {
            let result = crate::accounting::validate::validate_governance_op(
                &ledger, &creator_hash, gov_op, record.timestamp,
            );
            if !result.valid {
                return Err(ElaraError::Governance(
                    result.error.unwrap_or_else(|| "invalid governance operation".into()),
                ));
            }
        }

        // Fisherman challenge stake check
        if let Some(super::fisherman::ParsedChallengeOp::File { .. }) = &parsed_challenge_op {
            let challenger_stake = ledger.staked(&creator_hash);
            if challenger_stake < super::fisherman::MIN_CHALLENGE_STAKE {
                return Err(ElaraError::Wire(format!(
                    "challenger must stake at least {} base units (10^9 = 1 beat, has {})",
                    super::fisherman::MIN_CHALLENGE_STAKE, challenger_stake,
                )));
            }
        }

        (staked_micro, stake_ratio, gov_prop_rate)
    }; // ledger read lock dropped — single acquire for all validation

    // DISC-4 D-7: ledger snapshot released. The `rpre → rest_ldg_end_ms`
    // delta is the lock-acquire + read-snapshot cost; `rest_tail` covers
    // rate-limit, ITC, and relevance work after the lock.
    let rest_ldg_end_ms = ingest_t0.elapsed().as_millis();

    // Global node-wide rate limit — prevents sybil flood via many identities.
    // Skip for synced records and genesis authority (epoch seals + faucet + rewards
    // can exceed the limit during normal operation — this was blocking
    // the faucet when 25+ epoch seals fired in one cycle).
    if !skip_timestamp_defense && creator_hash != state.config.genesis_authority {
        let now_secs = now_ts as u64;
        if !global_rate_window_admit(
            &state.global_rate_window_start,
            &state.global_records_this_minute,
            state.global_rate_limit_per_minute,
            now_secs,
        ) {
            state.global_rate_limited_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(ElaraError::Wire(format!(
                "global rate limit exceeded ({}/min)",
                state.global_rate_limit_per_minute,
            )));
        }
    }

    // Per-identity hourly propagation rate limit — stake-scaled.
    // Base rate from config (default 100/hr). Staked identities get bonus:
    //   stake_bonus = staked_micro / stake_throughput_ratio / 24
    //   effective_limit = max(base, governance_rate) + stake_bonus
    // This means: unstaked identities get the base floor, staked identities
    // scale linearly with economic commitment. Governance can raise the base.
    // Skip for synced/relayed records (gossip pull/push relay).
    if !skip_timestamp_defense && effective_identity != state.config.genesis_authority {
        let base_rate = (state.config.propagation_rate_limit_per_hour as u64).max(gov_prop_rate);
        let stake_bonus = if staked_micro > 0 && stake_ratio > 0 {
            // daily records from stake, converted to hourly
            staked_micro / stake_ratio / 24
        } else {
            0
        };
        let effective_limit = base_rate.saturating_add(stake_bonus);

        let mut limiter = state.propagation_limiter.lock_recover();
        if !limiter.check_and_record_scaled(effective_identity, now_ts, effective_limit) {
            return Err(ElaraError::Wire(format!(
                "identity {} exceeds propagation rate limit ({}/hr, base={}, stake_bonus={})",
                &effective_identity[..effective_identity.len().min(16)],
                effective_limit,
                base_rate,
                stake_bonus,
            )));
        }
    }

    // Authoritative per-identity HARD daily emission cap (trust tiers, Protocol §11.35).
    // The COUNT is enforced under `NodeState::daily_caps` — a dedicated short-lived lock
    // that only contends with O(1) ingest holders, NEVER feed_attestation / trust prune
    // — so it can't be dropped under flood (unlike the old try_read on `state.trust`,
    // which skipped the check+increment exactly when contended). The LIMIT is
    // best-effort: on trust-lock contention we fall back to the STRICTEST tier cap
    // (fails CLOSED — the inverse of the old skip-on-contention). Staked identities
    // derive their limit from ledger-captured stake (no trust lock), so a flood can't
    // falsely cap them.
    if !skip_timestamp_defense && effective_identity != state.config.genesis_authority {
        let cont_score = state.continuity.try_lock()
            .map(|c| c.score(effective_identity, now_ts))
            .unwrap_or(1.0);
        let mut limit = if staked_micro > 0 {
            let er = if stake_ratio > 0 { stake_ratio } else { crate::accounting::trust::BASE_UNITS_PER_DAILY_RECORD };
            ((staked_micro / er) as u32).max(crate::accounting::trust::TIER_0_DAILY)
        } else {
            match state.trust.try_read() {
                Ok(t) => t.daily_limit_for(effective_identity, now_ts, cont_score),
                Err(_) => crate::accounting::trust::TIER_0_DAILY, // contended → strictest, fail closed
            }
        };
        // Reincarnation penalty (Protocol §6.4): suspected reset → clamp to Tier 0.
        if let Ok(reinc) = state.reincarnation.try_lock() {
            if reinc.trust_multiplier(effective_identity) < 1.0 {
                limit = limit.min(crate::accounting::trust::TIER_0_DAILY);
            }
        }
        // ONE atomic check-and-increment — see DailyCapCounter (never split the two).
        if !state.daily_caps.lock_recover().check_and_increment(effective_identity, now_ts, limit) {
            return Err(ElaraError::Ledger(format!(
                "daily record limit exceeded: identity limited to {}/day", limit
            )));
        }
    }

    // ZK proof enforcement for Private/Restricted records (Protocol §5.3).
    // PRIVATE = "I can prove I know the content without revealing it."
    // Records with these classifications MUST carry a valid ZK proof.
    // Without enforcement, "PRIVATE" is just a label with no cryptographic guarantee.
    //
    // Skip enforcement for synced/historical records (skip_timestamp_defense=true)
    // to avoid rejecting pre-existing Private records created before this enforcement.
    if matches!(record.classification, crate::record::Classification::Private | crate::record::Classification::Restricted) {
        match record.zk_proof {
            None => {
                // Genesis authority exempt — creates system records that may use Private
                // classification for internal ops (key rotation, sunset, etc.)
                // Synced records exempt — historical records predate enforcement.
                if creator_hash != state.config.genesis_authority && !skip_timestamp_defense {
                    return Err(ElaraError::Wire(format!(
                        "classified record ({}) requires a ZK proof (Protocol §5.3)",
                        record.classification.name(),
                    )));
                }
            }
            Some(ref zk_bytes) => {
                let valid = if crate::crypto::zk::is_groth16_format(zk_bytes) {
                    // Fail-closed: Groth16-format proofs (version 0x02) are always
                    // rejected — no Groth16 verifier exists (design-stage only; see
                    // whitepaper §5.3). 2026-04-19: a prior `{ true }` here let
                    // unverified classified records onto the DAG via a trivial
                    // version-byte spoof (0x02).
                    false
                } else {
                    // 0x03 (SHA3 commitment, COMMITMENT_VERSION) and 0x01 (legacy SHA3)
                    // both route to the real verifier. There is no STARK prover — 0x03 is
                    // the commitment wire format — so a 0x03 proof is checked as a
                    // commitment, never blind-accepted. Closes the 0x03 twin of the 0x02
                    // spoof above: this branch previously returned bare `true` for any
                    // 0x03-prefixed bytes, letting unverified classified records onto the DAG.
                    crate::crypto::zk::verify_record_proof(zk_bytes)
                };
                if !valid {
                    return Err(ElaraError::Wire("invalid ZK proof on classified record".into()));
                }
                state.zk_proofs_verified_total.fetch_add(1, Relaxed);
            }
        }
    }

    // Validate dispute/challenge ops (pure parsing, no ledger needed)
    if let Some(ref op) = parsed_dispute_op {
        super::dispute::verify_dispute(op)?;
    }
    if let Some(ref op) = parsed_challenge_op {
        super::fisherman::verify_challenge(op)?;
    }

    // Validate sunset records before storage insert (genesis authority only)
    if record.metadata.contains_key(SUNSET_OP_KEY) {
        let genesis = state.config.genesis_authority.clone();
        sunset::verify_sunset(&record, &genesis)?;
    }

    // Check record algorithm against sunset state (Protocol v0.6.1 Section 11.29)
    {
        let algo = sunset::record_algorithm(&record);
        let current_epoch = {
            let epoch_state = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
            // Use the highest sealed epoch across all zones as current epoch
            epoch_state.latest_epoch.values().copied().max().unwrap_or(0)
        };
        let sunset_state = state.sunset.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        sunset_state.check_algorithm(algo, current_epoch)?;
    }

    // Validate epoch seal operations before storage insert.
    // Only verify records where epoch_op == "seal". Other epoch ops (zone_transition)
    // are handled later in the pipeline.
    let is_epoch_seal = record.metadata.get(EPOCH_OP_KEY)
        .and_then(|v| v.as_str())
        .is_some_and(|op| op == "seal");
    // Stage 3c.1: cross-zone escalation seals verified separately.
    let is_global_seal = record.metadata.get(EPOCH_OP_KEY)
        .and_then(|v| v.as_str())
        .is_some_and(|op| op == epoch::EPOCH_OP_GLOBAL_SEAL);
    // Phase 1: epoch seal validation (merkle pre-fetch may involve network I/O)
    state.insert_phase.store(1, std::sync::atomic::Ordering::Relaxed);
    if is_epoch_seal {
        let rec = record.clone();
        let genesis = state.config.genesis_authority.clone();
        let seal_creator = creator_identity_hash(&rec);
        // Look up per-anchor VRF key from registry (no global fallback —
        // each anchor has its own key, using another anchor's key causes mismatch)
        let vrf_pk = if let Ok(registry) = state.vrf_registry.read() {
            registry.get_public_key(&seal_creator)
        } else {
            None
        };
        // Gather inputs for aggregator-rank verification (Stage 3b.6).
        // Stakers and per-zone RTT must be snapshotted BEFORE taking the
        // epoch_state read lock to avoid holding multiple locks across awaits.
        //
        // LIVENESS-1 (2026-05-11): staker view is filtered to VRF-registered
        // anchor identities ONLY — mirrors the proposer-side filter in
        // `epoch::should_propose_seal`. Symmetric construction is what
        // keeps the rank-derivation consensus rule consistent across the
        // proposer/verifier boundary.
        // Shared staked-anchor view (verifier side) — the SAME memoized
        // accessor the proposer (`epoch::should_propose_seal`) reads, so the
        // rank this verifier derives uses a bit-identical staked set. Symmetry
        // by construction is the LIVENESS-1 invariant (a divergent view freezes
        // the chain). Only the flat list is needed here.
        let (staked_amounts, _) = state.staked_anchor_view().await;
        // Parse the zone once for RTT lookup. Match the zone-decoding logic
        // in `extract_epoch_seal` so string/legacy-numeric both work.
        let seal_zone: Option<crate::ZoneId> = rec.metadata.get("epoch_zone")
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(crate::ZoneId::new(s))
                } else {
                    v.as_u64().map(crate::ZoneId::from_legacy)
                }
            });
        // Base timeout via `state.effective_base_timeout_ms` — single source
        // of truth that mirrors `should_propose_seal` and the seal loop, so
        // proposer and verifier agree on the rank-unlock schedule.
        let base_timeout_ms: u64 = seal_zone
            .as_ref()
            .map(|z| state.effective_base_timeout_ms(z))
            .unwrap_or(5_000);
        let rank_check = epoch::RankCheck {
            stakers: &staked_amounts[..],
            base_timeout_ms,
        };
        // Verify epoch seal — capture result, then drop lock before any async work
        let seal_verify_result = {
            let epoch_state = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
            epoch::verify_epoch_seal_no_merkle(
                &rec,
                &*state.rocks,
                &epoch_state,
                &genesis,
                vrf_pk.as_ref(),
                Some(&rank_check),
            )
        }; // epoch_state lock dropped here

        match seal_verify_result {
            Ok(_) => {}
            Err(ref e) if e.to_string().contains("VRF") => {
                // VRF verification failed — accept the seal if creator is self
                // (we just signed it) or VRF key not yet fully available.
                // The Dilithium3 signature was already verified above.
                let is_self = seal_creator == state.identity.identity_hash;
                // B7 (fusion-audited 2026-06-19): a non-genesis seal that the
                // verifier could not VRF-verify on the catch-up FAST-FORWARD arm
                // is DEFERRED, never accepted. Accepting it (the pre-B7 behaviour
                // of the `vrf_pk.is_none()` branch below) would let a forged
                // high-epoch seal advance our `latest_epoch` and wedge this node
                // off the canonical chain. The error carries the "VRF-unverifiable"
                // marker, classified retryable by gossip::is_retryable_ingest_rejection
                // → the seal is parked and re-tried once the proposer's VRF
                // registration syncs (honest self-heal), while a forged seal simply
                // never verifies and ages out of the bounded retry buffer. Our own
                // freshly-signed seal (is_self) is still accepted unconditionally.
                if !is_self && e.to_string().contains("VRF-unverifiable") {
                    state.epoch_seal_fastforward_vrf_deferred_total.fetch_add(1, Relaxed);
                    return Err(ElaraError::Ledger(e.to_string()));
                }
                // Accept if: self-created, no VRF key registered, or registry only
                // has the 32-byte hash (can't verify without full 1,952-byte key).
                // Dilithium3 signature was already verified — identity is proven.
                // NOTE (B7): this `vrf_pk.is_none()` acceptance survives only for
                // the NON-fast-forward classes (sequential / partition-merge), which
                // cannot wedge the tip; the fast-forward class is intercepted above.
                let has_full_pk = vrf_pk.as_ref().is_some_and(|pk| !pk.full_pk().is_empty());
                if is_self || vrf_pk.is_none() || !has_full_pk {
                    debug!(
                        "epoch seal from {} accepted without VRF verification (self={}, vrf_pk={}, full_pk={})",
                        &seal_creator[..seal_creator.len().min(16)],
                        is_self,
                        vrf_pk.is_some(),
                        has_full_pk,
                    );
                } else {
                    // Remote node with full VRF key but verification failed — reject
                    return Err(ElaraError::Ledger(format!(
                        "epoch seal VRF verification failed for {}: {}",
                        &seal_creator[..seal_creator.len().min(16)], e
                    )));
                }
            }
            Err(ref e) if e.to_string().contains("merkle root mismatch") => {
                // H3: Merkle mismatch — we're missing records for this epoch.
                let zone_str = rec.metadata.get("epoch_zone")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();

                // If the seal has a zero/empty merkle root, it was created from
                // incomplete state (e.g., genesis authority catching up). Don't
                // waste resources prefetching — the seal itself is bad.
                let seal_root = rec.metadata.get("epoch_merkle_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_zero_root = seal_root.is_empty()
                    || seal_root.chars().all(|c| c == '0');
                if is_zero_root {
                    debug!("epoch seal with zero merkle root for zone {zone_str} — rejecting (bad seal from incomplete state)");
                    return Err(ElaraError::Ledger(format!(
                        "epoch seal has zero merkle root for zone {zone_str} — created from incomplete state"
                    )));
                }

                // Spawn background prefetch (non-blocking) and reject the seal.
                // The seal will be retried on the next gossip/sync cycle after
                // the prefetch completes. This prevents state_core from blocking
                // for 30-60s on inline network I/O (root cause of deadlock #2).
                // Cap at 2 concurrent prefetches to prevent CPU starvation.
                let active = state.active_prefetches.load(std::sync::atomic::Ordering::Relaxed);
                if active >= 2 {
                    debug!("epoch seal merkle mismatch for zone {zone_str} — skipping prefetch ({active} already active)");
                } else {
                    warn!(
                        "epoch seal merkle mismatch for zone {zone_str} — spawning background prefetch",
                    );
                    state.active_prefetches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let state_bg = state.clone();
                    let rec_bg = rec.clone();
                    let genesis_bg = genesis.clone();
                    tokio::spawn(async move {
                        match merkle_prefetch_and_retry(&state_bg, &rec_bg, &genesis_bg, None).await {
                            Ok(()) => info!("background merkle prefetch: recovered records for zone {zone_str}"),
                            Err(e) => warn!("background merkle prefetch failed for zone {zone_str}: {e}"),
                        }
                        state_bg.active_prefetches.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
                return Err(ElaraError::Ledger(format!(
                    "epoch seal merkle mismatch (prefetch spawned, will retry): {e}"
                )));
            }
            Err(e) => return Err(e),
        }

        // Protocol §4.3: epoch seals from Profile A anchors MUST have dual signatures.
        // If the seal has a SPHINCS+ public key (Profile A), the SPHINCS+ signature
        // must also be present. The signature itself is verified earlier in this function.
        if record.creator_sphincs_pk.is_some() && record.sphincs_signature.is_none() {
            return Err(ElaraError::Wire(
                "epoch seal from Profile A anchor must include SPHINCS+ dual signature".into()
            ));
        }
    }

    // Stage 3c.1: verify cross-zone escalation seals before storage insert.
    // Structure mirrors the `is_epoch_seal` branch above.
    if is_global_seal {
        let seal_creator = creator_identity_hash(&record);
        // Emitter's VRF public key from the per-anchor registry — required.
        // Unlike regular epoch seals we do not fall back to sig-only accept:
        // a global seal is a liveness artifact with higher blast radius
        // (it retires an epoch for a whole zone) so we demand the full
        // VRF proof path. An anchor without a registered VRF key cannot
        // emit escalations.
        let emitter_vrf_pk = state
            .vrf_registry
            .read()
            .ok()
            .and_then(|r| r.get_public_key(&seal_creator))
            .ok_or_else(|| ElaraError::Ledger(format!(
                "global_seal: emitter {} has no registered VRF public key",
                &seal_creator[..seal_creator.len().min(16)]
            )))?;

        // Bucket staked anchors by their deterministic home zone so the
        // verifier can confirm the emitter is registered with non-zero stake
        // in the claimed `emitter_zone`. The shared `staked_anchor_view`
        // accessor — the SAME one the proposer (`epoch::should_propose_seal`)
        // reads — provides the partition.
        //
        // LIVENESS-1 (2026-05-11): the per-zone staker view used for
        // escalation verification is filtered to VRF-registered anchor
        // identities ONLY, mirroring the proposer-side construction. Routing
        // it through the shared accessor (anchors → accounts join, partitioned
        // by `resolve_identity_zone`) makes the verifier's partition
        // bit-identical to the proposer's — and removes the prior
        // `staker_index ∩ anchors` construction, which could diverge from the
        // proposer if `staker_index` was stale (e.g. empty post-snapshot
        // restore). Only the partition is needed here.
        let (_, stakers_by_zone) = state.staked_anchor_view().await;

        // Parse once to grab (stuck_zone, stuck_epoch); pull the matching
        // local prev_seal_hash / next_epoch out of EpochState under a
        // single read lock.
        let preview = epoch::extract_global_quorum_seal(&record)?
            .ok_or_else(|| ElaraError::Ledger(
                "global_seal record has no global_seal metadata".into(),
            ))?;

        let (local_prev, local_next) = {
            let epoch_state = state
                .epoch
                .read()
                .map_err(|e| ElaraError::Storage(e.to_string()))?;
            let prev = epoch_state
                .latest_seal_hash
                .get(&preview.stuck_zone)
                .copied()
                .unwrap_or([0u8; 32]);
            let next = epoch_state.next_epoch(&preview.stuck_zone);
            (prev, next)
        };

        let ctx = epoch::GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: local_prev,
            local_next_epoch: local_next,
            emitter_vrf_pk: &emitter_vrf_pk,
        };
        epoch::verify_global_quorum_seal(&record, &ctx)
            .map_err(|e| ElaraError::Ledger(format!("global_seal verification failed: {e}")))?;

        info!(
            "global_seal accepted: stuck_zone={} stuck_epoch={} emitter={} emitter_zone={}",
            preview.stuck_zone,
            preview.stuck_epoch,
            &seal_creator[..seal_creator.len().min(16)],
            preview.emitter_zone,
        );
    }

    // ── KR-3 S2 §5-H5 [R-7]: validated reason vocabulary ─────────────────
    // Flag-gated, rotation-class-scoped admission hygiene: reject a rotation or
    // revocation whose `reason` is outside its documented vocabulary, loud, so
    // the §6.2/§6.3 cascade (which triggers on `reason == "compromise"`) can
    // never be half-fired by "Compromise" / "compromise " / a typo. Runs after
    // signature verification (:1222) and the epoch-seal/zk gates — all of which
    // early-return on failure — so only otherwise-valid records are checked and
    // a reject is attributable to a signed author; and BEFORE the c3 pin below,
    // so a rejected record is never pinned. `validate_rotation_class_reason`
    // returns Ok(()) for non-rotation records ⇒ ordinary traffic untouched.
    // Flag-OFF: the guard is false ⇒ skipped ⇒ byte-identical.
    if state.config.s2_rotation_ordering_enabled {
        if let Err(bad_reason) = super::key_rotation::validate_rotation_class_reason(&record) {
            state.rotation_reason_rejected_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "rotation-class reason not in vocabulary: {bad_reason:?}"
            )));
        }
        // KR-3 S2 §5-H1 [R-4]: absolute recent-floor. The general path above (:979)
        // only WARNS on old records — offline-first submitters need that leniency —
        // but a stale rotation-class record left admitted sits Pending forever
        // (zombie spam) and burdens the §3-3 sweep / witness-coverage machinery.
        // Reject loud past the FIXED 3600 s floor so the author re-signs fresh.
        // `now_ts` (per-node, from :967) is correct here: H1 is honest-user
        // protection, never an ordering input — the deterministic ordering bound is
        // the seal-committed witness coverage check (§4), not this. Same placement
        // rationale as H5 (after sig-verify ⇒ reject attributable; before the c3 pin
        // ⇒ a rejected record is never pinned). Flag-OFF: skipped ⇒ byte-identical.
        if let Err(why) = super::key_rotation::validate_rotation_recent_floor(&record, now_ts) {
            state.rotation_recent_floor_rejected_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "rotation-class record past recent-floor: {why}"
            )));
        }
        // KR-3 S2 §5-H2 + §5-H3: rotation-class parent grounding. A rotation-class
        // record must cite ≥1 parent (H2); every locally-loadable parent must be
        // within the 24 h age cap and ≥1 cited parent must be durably finalized at
        // admission (H3) — ordinary/revocation parents via the FinalizedIndex row,
        // rotation-hop parents via a rotation-CF entry at state ≥ Final, never the
        // transient attestation map. Defense-in-depth (S2 ordering never reads
        // parent data) so the per-node clock is fine; a reject is loud + transient
        // (the author re-parents). Same placement rationale as H5/H1 — after
        // sig-verify ⇒ reject attributable to a signed author; before the c3 pin ⇒
        // a rejected record is never pinned. Flag-OFF: skipped ⇒ byte-identical.
        if let Err((class, why)) = validate_rotation_parent_grounding(&state.rocks, &record, now_ts)
        {
            state
                .rotation_parent_grounding_rejected_total
                .fetch_add(1, Relaxed);
            return Err(class.into_reject(format!("rotation-class parent grounding failed: {why}")));
        }
        // KR-3 S2 §5-H3b: predecessor-finality gate (rotation hops), FAIL-CLOSED. A rotation
        // hop is admitted only when its prev_key's introducing hop is durably Final
        // (get_rotation_newkey_index = Some) — then §6.1 derives its lineage from that finalized
        // predecessor, identical on every node. An ungroundable None (genuine root OR
        // not-yet-final/unseen predecessor — indistinguishable from local state) is
        // reject-transient, NEVER silently pinned as a root: pinning the pending-predecessor case
        // as a root writes an immutable rotation_zone_pin that forks against a node which
        // finalized the predecessor first (audit kr3-s2-h3b-fork-an internal audit). The
        // fork-free root branch needs a positive origin-key predicate (deferred KR-3
        // stable-identity), so roots stay blocked and the flag stays blocked; this gate ships
        // fork-SAFETY now. Same placement/attribution as H5/H1/H2-3 — after sig-verify (reject
        // attributable) and before the c3 pin (a rejected record is never pinned). Flag-OFF:
        // skipped ⇒ byte-identical.
        if let Err((class, why)) = validate_rotation_predecessor_grounding(&state.rocks, &record) {
            state
                .rotation_predecessor_ungrounded_rejected_total
                .fetch_add(1, Relaxed);
            return Err(
                class.into_reject(format!("rotation-class predecessor finality failed: {why}")),
            );
        }
    }

    // ── KR-3 S2 wiring-(c) c3: fork-risk ORDERING ────────────────────────
    // Publish this rotation hop's in-memory zone pin BEFORE the two
    // admission-path `resolve_record_zone(&record.id)` calls below — the ITC
    // stamp (immediately after) and the SMT/storage insert key (Phase-2). Both
    // fire BEFORE `put_record_with_pk_zone` commits the durable pin row (c2), so
    // without this in-memory precede a same-admission resolve misses the pin and
    // the rotation record routes+stores under its NAIVE zone — a silent misroute
    // (fork) under flag-ON. Placed HERE — after signature verification (:1222)
    // and all epoch-seal/zk validation, each of which early-returns on failure —
    // so only fully-validated records ever pin: the set is bounded to legitimate
    // rotations (no attacker-unbounded growth) and matches the durable CF pin,
    // which is likewise written only on a successful store. Derived from the SAME
    // predecessor newkey-index as that durable write (`rotation_hop_pin`), so the
    // pin is identical on every node. Flag-OFF: the guard is false ⇒ nothing runs
    // ⇒ byte-identical. (The earlier resolves at :986 timestamp-defense — a local
    // heuristic, skipped for synced records — and :1053 zone-scoped-subscriber
    // drop-filter run pre-sig-verify and stay naive; both are dormant here: the
    // flag is OFF and no node uses zone-scoped subscriptions. Closing the
    // subscription filter for rotation-class is a follow-up, not a fork risk.)
    if state.config.s2_rotation_ordering_enabled {
        if let Some((rid, _record_hash, lineage_id)) = rotation_hop_pin(&state.rocks, &record) {
            state.insert_rotation_pin(&rid, &lineage_id);
            // c3-ii: mirror the pin into the consensus settlement-zone override, so
            // the naive `is_settled`/`is_settled_diverse` denominators (AWCConsensus
            // has no NodeState/zone_registry to reach `resolve_record_zone`) count
            // this hop's stake against its lineage zone (§6.1 item 2). Derived from
            // the SAME `rotation_hop_pin` result as the pin above ⇒ can't drift. No
            // consensus lock is held here (the first is at :2482), so this brief
            // acquire is deadlock-free; released at the statement end before ITC.
            state
                .consensus
                .lock_recover()
                .insert_rotation_zone_override(&rid, &lineage_id);
        }
    }

    // ── ITC stamping (Protocol §11.9) ────────────────────────────────────
    // Determine the zone for this record.
    // Gap 4 routing-application: ITC clocks are per-zone; a post-split
    // record must stamp against the new leaf's clock, not the parent's.
    let record_zone = state.resolve_record_zone(&record.id);
    {
        let mut clocks = state.zone_clocks.lock_recover();
        if let Some(itc_bytes) = &record.itc_stamp {
            // Received record — join their clock with ours
            if let Ok(received_stamp) = Stamp::from_bytes(itc_bytes) {
                clocks.receive(record_zone.clone(), &received_stamp);
                state.itc_joins_total.fetch_add(1, Relaxed);
            }
        } else {
            // Locally created record — stamp it with our clock event
            let stamp = clocks.record_event(record_zone.clone());
            record.itc_stamp = Some(stamp.to_bytes());
            state.itc_events_total.fetch_add(1, Relaxed);
        }
    }

    // SECURITY (pre-flip audit 2026-06-22): do NOT inject `expires` metadata here.
    // `metadata` is covered by `signable_bytes()` → `record_hash()` → the per-zone
    // epoch-seal Merkle root (epoch.rs `MerkleTree::root(&hashes)`). Injecting a
    // wall-clock `expires` after signature verification made the sealed hash diverge
    // across nodes (each node stamps its own clock for the same wire record) → a
    // consensus fork, AND invalidated the creator's signature for every later
    // re-verifier (sync re-check, fisherman audit, light-client inclusion proof).
    // `record.zone` is unauthenticated wire input (decoded at record.rs `version>=3`,
    // intentionally NOT in `signable_bytes`), so this branch was reachable by any
    // pre-stake peer posting a `zone="sandbox/…"` record with no `expires` — pure
    // attack surface with zero legitimate producer (no production path creates a
    // sandbox record). A real sandbox-expiry feature MUST set `expires` in metadata
    // BEFORE signing (deterministic, signature-covered), never as a node-side mutation.
    // GC's `metadata["expires"]` path (gc.rs `is_expired`) is unaffected — it still
    // honors a creator-set `expires`.

    // Track record relevance for forgetting (EMERGENT-MIND §3)
    {
        let mut relevance = state.relevance.lock_recover();
        // Don't track records GC never prunes by relevance: beat_op and
        // governance_op are integrity-critical and unconditionally exempt from
        // pruning (storage/rocks.rs gc_scan_and_delete), so they never enter the
        // GC's deleted_ids and a relevance entry for them would leak forever
        // (audit 16g). They can still boost their parents' relevance below.
        if !record.metadata.contains_key("beat_op")
            && !record.metadata.contains_key("governance_op")
        {
            relevance.track(&record.id, record.timestamp);
        }
        // Record parent references
        for parent_id in &record.parents {
            relevance.reference(parent_id, record.timestamp);
        }
    }

    // Measure pre-phase2 time (validation + eviction + Dilithium + ITC + relevance)
    let pre_phase2_ms = ingest_t0.elapsed().as_millis();

    // Phase 2: storage (spawn_blocking for RocksDB + Merkle)
    state.insert_phase.store(2, std::sync::atomic::Ordering::Relaxed);
    let state2 = state.clone();
    let rec = record.clone();
    // Gap 4 routing-application: the sparse-Merkle tree is keyed per zone,
    // so the record must insert into the resolved leaf's tree. Resolved
    // outside `spawn_blocking` so the async registry read lock isn't held
    // across the blocking boundary.
    let record_zone_merkle = state.resolve_record_zone(&record.id);
    let zone_key_for_idx = record_zone_merkle.to_key_bytes();
    // ARCH-4(b) atomic slot claim: thread the slot key (None for v4 records,
    // Some(...) for v5+) through to the WriteBatch in `put_record_with_pk_zone`
    // so the slot index entry and record payload land together. This is the
    // first and only point at which a sig-verified record can claim a slot.
    let slot_key_for_claim = rec.slot_key();
    // F-1 crash-consistency: derive the DISC-5 CF_EPOCHS index key for seal
    // records HERE so it rides the record's own Phase-2 WriteBatch (atomic with
    // the seal in CF_RECORDS). `extract_epoch_seal` is the same deterministic,
    // metadata-only parse the post-insert block uses, so the indexed key is
    // byte-identical to the prior standalone put — only the atomicity changes.
    // `Ok(None)` for every non-seal record (one HashMap lookup, no parse).
    let disc5_epoch_key: Option<Vec<u8>> = match super::epoch::extract_epoch_seal(&record) {
        Ok(Some(seal)) => Some(super::epoch::disc5_index_key(
            seal.epoch_number,
            seal.zone.path(),
            &record.id,
        )),
        _ => None,
    };
    // KR-3 S2 (W2-A): rotation-finality side-write for this record's Phase-2
    // batch — armed crash-atomically with the record store (§3-3), the DISC-5
    // precedent above. Flag-gated: `None` when OFF ⇒ the store batch is
    // byte-identical to a pre-feature one.
    let rotation_op = if state.config.s2_rotation_ordering_enabled {
        rotation_batch_op_for(&state.rocks, &record)
    } else {
        None
    };
    let phase2_t0 = std::time::Instant::now();
    let hash = tokio::task::spawn_blocking(move || -> crate::errors::Result<String> {
        let queue_ms = phase2_t0.elapsed().as_millis();
        let sb_t0 = std::time::Instant::now();

        // Combined put_record + store_public_key in one WriteBatch (1 WAL sync, not 2).
        // ZSP Phase B: pass the registry-resolved leaf zone so post-split records
        // index under their current leaf, not the parent zone they used to live in.
        let id_hash = crate::accounting::types::creator_identity_hash(&rec);
        state2.rocks.put_record_with_pk_zone(
            &rec.id,
            &rec,
            &id_hash,
            &rec.creator_public_key,
            zone_key_for_idx,
            slot_key_for_claim.as_deref(),
            disc5_epoch_key.as_deref(),
            rotation_op,
        )?;
        let put_ms = sb_t0.elapsed().as_millis();

        // Incremental record-stats counters. Bumped here, after the
        // record is durably persisted by `put_record_with_pk_zone` and only on
        // the happy ingest path; replaces the O(all_records) scan in the
        // explorer `/dag/stats` route. Zone-purge / zone-merge writes go
        // through `rocks.put_record` directly and do NOT bump (totals stay
        // stable when records move zones).
        state2.record_stats_bump(&rec);

        // Insert record hash into the zone's sparse Merkle tree.
        // Skip epoch seals (meta-records) and skip entirely on ≤2GB machines
        // (they use timestamp_pull, not Merkle sync, so these writes are pure waste).
        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
        let mut merkle_ms = 0u128;
        if ram_gb > 2 && !rec.metadata.contains_key(super::epoch::EPOCH_OP_KEY) {
            let merkle_t0 = std::time::Instant::now();
            let record_hash = rec.record_hash();
            let mut tree = super::merkle::SparseMerkleTree::new(&state2.rocks, record_zone_merkle);
            tree.insert(&record_hash)?;
            tree.commit()?;
            merkle_ms = merkle_t0.elapsed().as_millis();
        }

        let total_sb = sb_t0.elapsed().as_millis();
        if total_sb > 5000 || queue_ms > 5000 {
            tracing::warn!("phase2 spawn_blocking slow: queue={queue_ms}ms put={put_ms}ms merkle={merkle_ms}ms total={total_sb}ms");
        }

        Ok(rec.id.clone())
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking failed: {e}")))??;
    let phase2_wall_ms = ingest_t0.elapsed().as_millis();

    // ── Backpressure: yield proportionally to stall severity ──
    // Without this, continuous writes starve compaction threads and L0 SST files
    // pile up → write stalls escalate from 3s to 30s+. On multi-core machines,
    // 200ms suffices. On 1-core machines, 20s stalls need 1-3s yields to
    // give compaction real CPU time between writes.
    //
    // DISC-4 Phase D-2: gate on the actual spawn_blocking duration
    // (`phase2_wall_ms - pre_phase2_ms`), not the cumulative total. Previous
    // implementation triggered the 3s sleep whenever `pre` was slow for any
    // reason (lock contention on `state.ledger.read()` / `state.dag.read()`),
    // compounding an upstream stall with a sleep that has nothing to do with
    // RocksDB compaction. Fleet histogram showed `dag=3002ms` exactly on
    // every pre-dominated slow record — that was this backpressure misfire,
    // not a real DB write stall.
    let phase2_duration_ms = phase2_wall_ms.saturating_sub(pre_phase2_ms);
    if phase2_duration_ms > 5000 {
        let stall_secs = (phase2_duration_ms.saturating_sub(5000) / 1000) as u64;
        let yield_ms = (200 + stall_secs * 100).min(3000);
        tokio::time::sleep(std::time::Duration::from_millis(yield_ms)).await;
    }

    // Yield to Tokio scheduler between phases so HTTP can breathe on 1-core nodes.
    // Without this, phases 3-5 run ~10s of synchronous work back-to-back,
    // starving the HTTP accept task and causing TLS handshake timeouts.
    tokio::task::yield_now().await;

    // ── DAG insert (before tombstone check — DAG is structural, not propagation) ─
    // Phase 3: DAG write lock
    state.insert_phase.store(3, std::sync::atomic::Ordering::Relaxed);
    {
        let dag_lock_t0 = std::time::Instant::now();
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        state.dag_write_holder.store(1, std::sync::atomic::Ordering::Relaxed); // 1=state_core
        let dag_lock_ms = dag_lock_t0.elapsed().as_millis();
        // Same 500ms early-warning threshold as the
        // dag.read() site at ~586. Distinct counter per lock direction so
        // dashboards can attribute read-lock vs. write-lock contention.
        if dag_lock_ms > 500 {
            state
                .lock_acquire_dag_write_slow_total
                .fetch_add(1, Relaxed);
        }
        if dag_lock_ms > 5000 {
            warn!("dag.write() lock took {dag_lock_ms}ms for {} — possible contention", &record.id[..record.id.len().min(16)]);
        }
        // DAM-3D Phase B: register the zone alongside DAG insert so the
        // per-zone tip frontier shadow stays consistent with `tips_idx`.
        let missing = dag.insert_tolerant_with_zone(
            record.id.clone(),
            record.parents.clone(),
            record.timestamp,
            record_zone.clone(),
        );
        if missing > 0 {
            // On ≤2GB nodes, skip synchronous RocksDB parent lookups while holding
            // the DAG write lock. These block the Tokio worker for 100ms+ per parent
            // on resource-constrained machines. The orphan resolver handles this
            // asynchronously every 30s instead.
            let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
            if ram_gb > 2 {
                let mut cleared = 0usize;
                for pid in &record.parents {
                    if !dag.contains(pid) && state.rocks.record_exists(pid).unwrap_or(false) {
                        dag.link_external_parent(&record.id, pid);
                        cleared += 1;
                    }
                }
                let real_missing = missing - cleared;
                if real_missing > 0 {
                    debug!("dag insert: {} has {real_missing} missing parents (orphan edges queued)", &record.id[..record.id.len().min(16)]);
                }
            } else {
                debug!("dag insert: {} has {missing} orphan parents (deferred to resolver, ram={ram_gb}GB)", &record.id[..record.id.len().min(16)]);
            }
        }
        // Re-link orphans whose parent is THIS record (O(1) lookup vs O(n) full scan).
        // Full reindex_orphans() runs in the orphan_resolver_loop every 30s.
        let linked = dag.relink_single_parent(&record.id);
        if linked > 0 {
            debug!("dag reindex: linked {linked} orphan edges for {}", &record.id[..record.id.len().min(16)]);
        }
    }
    state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed); // released
    // DISC-4 Phase D-1: fine-grained timing markers inside the "dag+ledger"
    // bucket so the next slow-record warn pinpoints which sub-phase stalled.
    let dag_end_ms = ingest_t0.elapsed().as_millis();

    // Yield after DAG write to let HTTP/TLS handshakes complete.
    tokio::task::yield_now().await;

    // ── Content safety: tombstone processing ─────────────────────────────
    {
        let rec_id = record.id.clone();
        let rec_meta = record.metadata.clone();
        let ch = creator_hash.clone();
        let ga = state.config.genesis_authority.clone();

        // If this record IS a tombstone, mark the target as tombstoned
        if let Some(target_id) = crate::content_safety::extract_tombstone_target(&rec_meta, &ch, &ga)? {
            let reason = rec_meta
                .get("tombstone_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("no reason");
            state.mark_tombstoned(&target_id, &rec_id, reason)?;
            info!("tombstoned record {target_id} by {rec_id}");
        }

        // Check if this record itself is tombstoned. F2 fix (semantic A): a
        // tombstone has ZERO ledger effect — apply its ledger op here (the same
        // Phase-4 work the non-tombstoned path runs below) so the live committed
        // ledger converges with the rebuild folds + `rederive_swept_delta`, which
        // already apply it unconditionally. THEN return: the content-side
        // processing (trust-feed, zone-setup, propagation) stays suppressed for a
        // tombstoned record, exactly as before. Separable from the propagation fix.
        // See internal design notes.
        let tombstoned = state.is_tombstoned(&rec_id)?;

        if tombstoned {
            info!("tombstoned record: ledger op applied (F2-A); content-propagation suppression is a separate, currently-unbuilt concern (see TOMBSTONE-PROPAGATION-FILTER brief): {}", &record.id[..record.id.len().min(16)]);
            apply_ledger_op_phase4(state, &record, creator_hash.clone(), parsed_ledger_op.clone()).await;
            return Ok(hash);
        }
    }
    let tomb_end_ms = ingest_t0.elapsed().as_millis();

    // Record submission in trust engine (after successful storage insert)
    // Feed all 6 entropy signals: content hash, timestamp, wire size, origin hash
    {
        let fingerprint = content_fingerprint(&record.metadata);
        let wire_size = record.to_bytes().len() as u32;
        // Origin hash: use real IP-based hint if provided (WS connections),
        // otherwise fall back to FNV-1a of creator hash (gossip/HTTP).
        let origin_hash = origin_hint.unwrap_or_else(|| {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in creator_hash.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h
        });
        // Use try_write to avoid blocking the state core if feed_attestation
        // or trust prune holds the trust write lock on another task.
        let trust_bytes = match state.trust.try_write() {
            Ok(mut trust) => {
                trust.record_submission_full(
                    &creator_hash, fingerprint, record.timestamp, wire_size, origin_hash,
                );
                trust.get_profile(&creator_hash)
                    .and_then(|p| serde_json::to_vec(p).ok())
            }
            Err(_) => {
                tracing::debug!("trust.write contended, deferring trust update for {}", &creator_hash[..creator_hash.len().min(16)]);
                None
            }
        };
        // RocksDB dual-write OUTSIDE lock — no I/O under contention.
        // Skip on ≤2GB nodes — each write adds to L0 SST pressure and the
        // single compaction thread can't keep up, causing 60s+ write stalls.
        // Trust profiles survive in memory and the snapshot loop writes them periodically.
        //
        // On >2GB nodes we still persist per-record, but offload via spawn_blocking.
        // During a 2000-record full_pull burst (Helsinki 2026-04-19 16:08-16:15
        // CET, 4-min HTTP blackout) the synchronous put_cf_raw on the tokio
        // worker piled 2000 sequential I/Os onto the same thread serving HTTP
        // accept, stalling TLS handshakes once L0 compaction backlog kicked in.
        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
        if ram_gb > 2 {
            if let Some(bytes) = trust_bytes {
                let rocks = state.rocks.clone();
                let creator_hash_clone = creator_hash.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = rocks.put_cf_raw(
                        crate::storage::rocks::CF_TRUST,
                        creator_hash_clone.as_bytes(),
                        &bytes,
                    );
                });
            }
        }

        // ── Continuity + Reincarnation tracking (Protocol §11.33, §6.4) ──
        // Feed every accepted record into both subsystems so they build up
        // behavioral profiles incrementally. O(1) per record, no I/O.
        let hour = ((record.timestamp as u64) % 86400) / 3600;
        let record_size = wire_size as usize;
        let metadata_keys = record.metadata.len();

        // Continuity: record activity for this identity
        if let Ok(mut cont) = state.continuity.try_lock() {
            cont.record_activity(&creator_hash, record.timestamp);
        }

        // Reincarnation: observe behavioral fingerprint + periodic detection check
        if let Ok(mut reinc) = state.reincarnation.try_lock() {
            reinc.observe(&creator_hash, hour as usize, record_size, metadata_keys);
            reinc.set_network_origin(&creator_hash, &format!("{:016x}", origin_hash));

            // Check for reincarnation every 10th observation (fingerprint needs 10+ to mature).
            // O(abandoned_count) per check, amortized O(1) per record.
            if let Some(rfp) = reinc.fingerprints().get(&creator_hash) {
                if rfp.observation_count % 10 == 0 && rfp.is_mature() {
                    let candidates = reinc.check_reincarnation(&creator_hash, record.timestamp);
                    for c in &candidates {
                        warn!(
                            "REINCARNATION DETECTED: {} matches abandoned {} (sim={:.2}, signals={:?})",
                            &c.new_identity[..c.new_identity.len().min(16)],
                            &c.old_identity[..c.old_identity.len().min(16)],
                            c.similarity, c.signals,
                        );
                    }
                }
            }
        }
    }
    let trust_end_ms = ingest_t0.elapsed().as_millis();

    // Cross-zone parent detection: identify parents from different zones.
    // Used for shared-witness bridging — finalized cross-zone parents
    // accelerate this record's settlement (Protocol §7.5).
    // Gap 4 routing-application: compare resolved leaves so a post-split
    // record doesn't falsely flag its parent as cross-zone when they share
    // a leaf, and doesn't miss a real cross-zone parent because both naive
    // modulos happen to collide on a pre-split zone.
    let record_zone = state.resolve_record_zone(&record.id);
    let xzone_parents: Vec<String> = record.parents.iter()
        .filter(|pid| state.resolve_record_zone(pid) != record_zone)
        .cloned()
        .collect();
    if !xzone_parents.is_empty() {
        debug!(
            "cross-zone parents: {} (zone {}) references {} parents from other zones",
            &record.id[..record.id.len().min(16)], record_zone, xzone_parents.len()
        );
        let mut consensus = state.consensus.lock_recover();
        consensus.register_cross_zone_parents(&record.id, xzone_parents);
    }

    // Track zone insertion for coverage analysis (Protocol §7.5)
    {
        let mut zone_state = state.zone_state.lock_recover();
        zone_state.record_inserted(&record.id);
    }

    // F2 fix (semantic A): a tombstone has ZERO ledger effect. This applies the
    // record's ledger op via the ARCH-1 park (or direct-apply fallback) + creator-
    // stake registration — the SAME work a tombstoned record now also runs at the
    // content-safety gate above, so live converges with the rebuild folds + drain.
    apply_ledger_op_phase4(state, &record, creator_hash.clone(), parsed_ledger_op.clone()).await;
    // Note: when tentative path took the record (no fallback), creator-stake
    // registration already fired inside the tentative block.
    let ledger_end_ms = ingest_t0.elapsed().as_millis();

    // Yield between ledger and post-processing to let HTTP breathe.
    tokio::task::yield_now().await;

    // Phase 5: post-processing (epoch, equivocation, fisherman, etc.)
    state.insert_phase.store(5, std::sync::atomic::Ordering::Relaxed);

    // R2 (late seal member): an earlier-registered seal may have listed THIS
    // record's hash as a member the node didn't hold yet — append it to the
    // seal's member list and, if the seal already settled, promote + route it
    // durably. Gated on map emptiness so the common case costs one brief
    // mutex acquisition and no hash encode.
    {
        let late_member_rids = {
            let mut consensus = state.consensus.lock_recover();
            if consensus.has_unresolved_seal_members() {
                let hash_hex = hex::encode(record.record_hash());
                consensus.resolve_late_seal_member(&hash_hex, &record.id)
            } else {
                Vec::new()
            }
        };
        super::reward::route_member_finality(state, late_member_rids).await;
    }

    // Update epoch state if this was an epoch seal
    // seal_equivocation carries info out of sync context for async slash execution.
    let mut seal_equivocation: Option<(String, crate::ZoneId, u64, String, [u8; 32])> = None;
    if record.metadata.contains_key(EPOCH_OP_KEY) {
        // R3-8 soak forensics (2026-07-02): 4 above-cap seals on the follower
        // were stored with ZERO Phase-5 side effects (no derive attempt, no
        // deficit, no epoch registration) and no log trace — this entry/exit
        // counter pair plus the loud extract-Err arm turn that silent class
        // into a named, countable branch. entered ticks ONLY on a successful
        // seal parse; completed ticks at the end of the seal block, so
        // entered > completed exposes any mid-block abort.
        let extracted = epoch::extract_epoch_seal(&record);
        match &extracted {
            Ok(Some(_)) => {
                state.seal_ingest_phase5_entered_total.fetch_add(1, Relaxed);
            }
            Ok(None) => {} // epoch_op present but not a seal (zone_transition etc.)
            Err(e) => {
                // Previously a SILENT skip of the entire seal-consumer block.
                state.seal_ingest_extract_err_total.fetch_add(1, Relaxed);
                warn!(
                    "seal ingest: extract_epoch_seal FAILED at phase 5 for {} — consumer processing skipped: {e}",
                    &record.id[..record.id.len().min(16)]
                );
            }
        }
        if let Ok(Some(mut seal)) = extracted {
            // R3-8 slice 4 — derive-when-absent, ONCE per seal-processing
            // pass. An empty enumeration on a non-empty window means the
            // inline array was omitted (bounded emission above
            // SEAL_INLINE_ENUM_MAX) or dropped (parse-time root gate). Derive
            // it from the local zone+window (root-verified against the signed
            // merkle_root) and repair the in-pass seal value so every
            // consumer below — witness-SMT flush, finality registration,
            // deficit capture, demotion capture, xzone proof attachment —
            // shares the one derived value. On None (window incomplete) the
            // pass keeps legacy-empty semantics and self-heals via full_pull.
            // Never persisted: the enumeration is reconstructible on demand.
            // On Incomplete, the local window count feeds the P3 count-based
            // deficit degrade below (record_seal_deficit) — no second scan.
            let mut derive_local_count: Option<u64> = None;
            if seal.record_hashes.is_empty() && seal.record_count > 0 {
                state.seal_ingest_derive_hook_attempts_total.fetch_add(1, Relaxed);
                match epoch::derive_seal_enumeration(&*state.rocks, &seal) {
                    Some(epoch::DeriveOutcome::Derived(derived)) => {
                        seal.record_hashes = derived;
                    }
                    Some(epoch::DeriveOutcome::Incomplete { local_window_count }) => {
                        derive_local_count = Some(local_window_count);
                    }
                    None => {}
                }
            }
            // Check for epoch seal equivocation (same anchor, same zone+epoch, different content).
            // BFT safety violation — economics §10. Detection is sync; slash is deferred.
            {
                let mut monitor = state.slashing.lock_recover();
                let seal_creator = creator_identity_hash(&record);
                let content_hash = record.record_hash();
                if let Some((conflicting_id, _)) = monitor.record_seal(
                    &seal_creator, &seal.zone, seal.epoch_number,
                    &record.id, content_hash,
                ) {
                    if !monitor.already_slashed(&seal_creator, &record.id, &conflicting_id) {
                        warn!(
                            "EPOCH SEAL EQUIVOCATION: {} produced conflicting seals for zone {} epoch {}",
                            &seal_creator[..seal_creator.len().min(16)],
                            seal.zone, seal.epoch_number,
                        );
                        seal_equivocation = Some((
                            seal_creator, seal.zone.clone(), seal.epoch_number,
                            record.id.clone(), content_hash,
                        ));
                    }
                }
            }

            // PARTITION-MERGE Phase B Slice 3: weight-aware same-epoch
            // reconciliation. Pre-compute incoming + existing attestation
            // weights outside the epoch write lock so we never hold
            // consensus + epoch mutably at the same time. TOCTOU risk on
            // existing_weight is benign — `register_seal_with_reconcile`
            // re-reads the existing seal_id under the write lock and
            // applies the comparison against the *current* state; a stale
            // existing_weight just means the comparison may slightly favor
            // the wrong side until the next attestation tick re-runs the
            // reconciler. Conservation is preserved either way (records
            // covered by an orphaned seal stay in the DAG; only the seal
            // mapping is rewritten).
            let weights = if state.config.partition_merge_weight_reconcile {
                let consensus = state.consensus.lock_recover();
                let incoming = consensus.attestation_weight_for_seal(&record.id);
                let existing_id = state
                    .epoch
                    .read_recover()
                    .latest_seal_id
                    .get(&seal.zone)
                    .cloned();
                let existing = existing_id
                    .as_deref()
                    .map(|id| consensus.attestation_weight_for_seal(id))
                    .unwrap_or(0);
                Some((incoming, existing))
            } else {
                None
            };
            // PARTITION-MERGE conservation trip-wire (xzone_demotion_probe):
            // populated below if seal registration demotes a same-epoch seal.
            // Built under the epoch write lock, enqueued once it is released.
            let mut demoted_capture: Option<super::xzone_demotion_probe::DemotedSealScan> = None;
            // Phantom-freeze detector: set to the canonical tip seal-id under the
            // epoch lock at a C2 chain-link reject; its external-attestation weight
            // is resolved AFTER the lock releases (never hold consensus+epoch).
            let mut phantom_reject_tip_id: Option<String> = None;
            // Chain-existence probe capture (deferred Mechanism-B primitive,
            // counter-only): the rejected successor's declared predecessor hash +
            // our tip's (zone, epoch). Resolved against CF_EPOCHS AFTER the lock
            // releases, gated on the phantom signature (tip_weight == 0) so it
            // measures the healable subset, not Byzantine forge-probes.
            let mut phantom_reject_probe: Option<(String, u64, [u8; 32])> = None;
            if let Ok(mut epoch_state) = state.epoch.write() {
                // C2: AUTHORITATIVE chain-link enforcement under the WRITE lock. The
                // verify-time check (epoch.rs) is advisory — it reads the tip under a
                // READ lock that races register_seal's write, so it cannot reject
                // without false-rejecting honest seals whose predecessor hasn't
                // registered yet. Here the tip is read under the SAME write lock that
                // mutates it (no TOCTOU). A STRICTLY-SEQUENTIAL seal (epoch == our
                // tip+1) MUST chain off our canonical tip; a Byzantine anchor with a
                // valid Dilithium3 key that points a sequential seal at a different
                // fork is rejected here, before it can advance latest_seal_hash.
                // Scoped tightly so nothing honest is wedged:
                //   • catch-up (epoch > tip+1) → not sequential, VRF-guarded at verify (B7);
                //   • same-epoch collision → lex-min / weight reconcile decides;
                //   • [0;32] baseline (genesis / cold-start / fresh zone, no prior seal)
                //     → cannot be enforced, left to the snapshot+VRF trust path, so the
                //     first honest seal and every bootstrap path is never falsely rejected.
                if epoch_state.is_forged_sequential_seal(&seal) {
                    // SUCCESSOR-RE-ADMISSION GAP (audit 2026-07-01,
                    // internal design notes §2b):
                    // this rejects the tip UPDATE only — the record is already in
                    // RocksDB (Phase 2) and ingest returns Ok, so the seal is NOT
                    // parked for retry and future re-gossip dedups it away
                    // (ingest.rs record_exists short-circuit). If our tip was a
                    // crash-before-broadcast PHANTOM, an honest E+1 dropped here is
                    // never re-evaluated after the phantom is later corrected → the
                    // freeze survives the correction. CLOSED 2026-07-03 (8b design
                    // B, internal design notes): the record_exists
                    // short-circuit now re-flows a stored seal that is the strict
                    // immediate successor of the zone tip (should_reenter_stored_seal),
                    // so the next natural re-offer after the tip corrects heals it.
                    // Do NOT rely on partition_merge_weight_reconcile for this.
                    state
                        .epoch_seal_chain_link_rejected_total
                        .fetch_add(1, Relaxed);
                    // Capture the tip this seal failed to chain to; a tip at 0
                    // external attestations (resolved post-lock) is the
                    // crash-before-broadcast phantom, not a Byzantine forge-probe.
                    phantom_reject_tip_id =
                        epoch_state.latest_seal_id.get(&seal.zone).cloned();
                    let tip_epoch =
                        epoch_state.latest_epoch.get(&seal.zone).copied().unwrap_or(0);
                    phantom_reject_probe =
                        Some((seal.zone.to_string(), tip_epoch, seal.previous_seal_hash));
                    tracing::warn!(
                        "REJECTED sequential epoch seal {} for zone {} — previous_seal_hash \
                         does not chain to our canonical tip (forged chain-link / fork attempt)",
                        seal.epoch_number, seal.zone
                    );
                } else {
                    // Snapshot canonical (epoch, seal_id) for this zone BEFORE
                    // registration so a same-epoch DEMOTION can be detected from the
                    // outcome afterward — covers both register_seal (default lex-min,
                    // which does not orphan-track) and register_seal_with_reconcile,
                    // without duplicating the canonicalization decision logic.
                    let prev_epoch =
                        epoch_state.latest_epoch.get(&seal.zone).copied().unwrap_or(0);
                    let prev_seal_id = epoch_state.latest_seal_id.get(&seal.zone).cloned();
                    match weights {
                        Some((incoming, existing)) => {
                            let _won = epoch_state.register_seal_with_reconcile(
                                &seal,
                                &record.id,
                                record.record_hash(),
                                incoming,
                                existing,
                            );
                            // Slice 4 will gate downstream attestation push on the
                            // bool to avoid attesting to seals we've just orphaned.
                        }
                        None => {
                            epoch_state.register_seal(&seal, &record.id, record.record_hash());
                        }
                    }
                    // Outcome-based same-epoch demotion detection. See
                    // xzone_demotion_probe for why this is a detector, not a revert.
                    if seal.epoch_number == prev_epoch {
                        if let Some(prev_id) = prev_seal_id {
                            let new_id =
                                epoch_state.latest_seal_id.get(&seal.zone).cloned();
                            if let Some((demoted_seal_id, incoming_demoted)) =
                                super::xzone_demotion_probe::classify_demotion(
                                    &prev_id,
                                    new_id.as_deref(),
                                    &record.id,
                                )
                            {
                                demoted_capture =
                                    Some(super::xzone_demotion_probe::DemotedSealScan {
                                        zone: seal.zone.to_string(),
                                        epoch: seal.epoch_number,
                                        // incoming seal object is in hand → pass its
                                        // record_hashes; prev-demoted → scan re-fetches.
                                        record_hashes: if incoming_demoted {
                                            Some(seal.record_hashes.clone())
                                        } else {
                                            None
                                        },
                                        seal_id: demoted_seal_id,
                                    });
                            }
                        }
                    }
                }
            }
            if let Some(d) = demoted_capture {
                super::xzone_demotion_probe::push_demoted_seal_scan(state, d);
            }
            // Phantom-freeze detector resolve (OUTSIDE the epoch lock): if the tip
            // a strictly-sequential seal failed to chain to carries 0 external
            // attestations, this is the crash-before-broadcast phantom (a tip no
            // peer ever attested → self-inflicted freeze), NOT a Byzantine
            // forged-successor probe of an attested tip. The two demand opposite
            // operator responses. Counter-only: the tempting attestation-gated
            // auto-heal is UNSAFE (it also demotes an honest just-created tip,
            // which sits at 0 external attestations for ~1 RTT since a proposer
            // cannot self-attest). See internal design notes.
            if let Some(tip_id) = phantom_reject_tip_id {
                let tip_weight = state
                    .consensus
                    .lock_recover()
                    .attestation_weight_for_seal(&tip_id);
                if tip_weight == 0 {
                    state.epoch_phantom_tip_suspected_total.fetch_add(1, Relaxed);
                    // Chain-existence probe (deferred Mechanism-B primitive,
                    // counter-only): does the rejected sequential successor chain
                    // off a real-but-non-canonical seal we already hold at
                    // (zone, tip_epoch)? If so, the honest E-seal that lost the
                    // lex-min tiebreak to the phantom is still durable in
                    // CF_EPOCHS, and this freeze is HEALABLE by the deferred
                    // provisional-self-tip chain-existence C2 relaxation; if not,
                    // the predecessor is unknown/forged (must NOT be admitted).
                    // Read-only CF_EPOCHS scan, already outside the epoch lock.
                    if let Some((ref zone_path, tip_epoch, ref prev_hash)) = phantom_reject_probe {
                        if state
                            .rocks
                            .seal_record_hash_present_at_zone_epoch(tip_epoch, zone_path, prev_hash)
                        {
                            state.epoch_successor_chainable_total.fetch_add(1, Relaxed);
                        }
                    }
                }
            }

            // Gap 1 (witness-side flush): every node — not just the seal
            // creator — must advance its on-disk account SMT so light
            // clients querying THIS node receive proofs that verify
            // against the seal's `account_smt_root`. The seal creator's
            // `epoch_seal_loop` flushes pre-sign; non-creator witnesses
            // had no equivalent step until now, so their SMT root stayed
            // frozen and `bound_to_seal` was always false except on the
            // sealing node. See cross-fleet probe in commit c3c8e45.
            flush_witness_smt_for_seal(state, &seal).await;

            // Gap 8: populate the seal-attestation latency histogram on every
            // node, not just the anchor that produced the seal. The post-seal-
            // creation path in `epoch_seal_loop` also calls register_seal_records
            // with the same (seal_id, record_ids) pair, but only on the creator.
            // Non-anchor nodes need their own stamp so is_seal_settled → observe
            // fires locally when attestations reach the 2/3 threshold. Without
            // this, the histogram stays at count=0 fleet-wide post-restart on
            // zones where the local node isn't the current anchor.
            let registration_member_rids = {
                let (record_ids, unresolved_hashes) =
                    resolve_seal_record_ids_with_unresolved(state, &seal.record_hashes);
                // Tier-1 (contract §4.1): unresolved hashes = a sealed-epoch
                // completeness deficit — capture it while it's already computed.
                // R3-8 slice 5: when the enumeration is absent AND the derive
                // missed, the captured local window count degrades the deficit
                // to record_count − local (coarser, same full_pull recovery).
                record_seal_deficit(state, &seal, &record.id, record_ids.len(), derive_local_count);
                let mut consensus = state.consensus.lock_recover();
                // R1: if the seal's attestations already crossed 2/3 before
                // this registration (routine under peer-driven catchup), the
                // members promote HERE — this is the primary registration
                // site fleet-wide, so its return must be routed durably.
                let newly = consensus.register_seal_records(&record.id, record_ids);
                consensus.register_unresolved_seal_members(&record.id, unresolved_hashes);
                consensus.register_seal_epoch(&record.id, seal.epoch_number, seal.zone.clone());
                newly
            };
            super::reward::route_member_finality(state, registration_member_rids).await;

            // DISC-5: the CF_EPOCHS index entry for this seal is now written
            // ATOMICALLY with the seal record in `put_record_with_pk_zone`'s
            // Phase-2 WriteBatch (see the `disc5_epoch_key` thread above), so a
            // crash can no longer strand the seal in CF_RECORDS with a missing
            // index. The key is byte-identical to the prior standalone put; only
            // the atomicity changed (the old "backfill repairs it" path was
            // false — the boot backfill is gated on cf_epochs_size==0 and never
            // repaired a partial gap). Encoding: internal design notes
            //   key = epoch:u64_be(8) || zone_path_utf8 || 0x00 || record_id_utf8
            //   value = empty (presence is the signal; CF_RECORDS holds the data).

            // Gap 2.1 Phase 2b.3 — producer-side sign hook.
            // Every node that ingests this seal checks whether IT is a
            // finality-committee member for (zone, epoch). If yes, it
            // signs a SealFinalityWitness over the canonical message
            // (xzone_finality_signable_bytes) and feeds the signature
            // into its own consensus collection. The collection is
            // bundled onto outgoing transfers downstream by
            // attach_xzone_proofs_from_seal_with_finality (below).
            //
            // Multi-node propagation of these signatures via gossip is
            // a follow-up; for now the local node's own signature is
            // already useful: a node that creates a seal AND ingests
            // the same record back will populate its own witness
            // entry, and bundle it onto any locked-from-this-zone
            // transfers it later observes.
            //
            // Best-effort: if any of {finality_committee_pks lookup,
            // build_committee_proofs, sign, consensus mutation} fails
            // we skip silently — the seal is still valid, just lacks
            // this node's finality witness this epoch. A retry on the
            // next seal (or via gossip from another committee member)
            // will catch up.
            {
                use crate::network::zone_committee::{
                    finality_committee_pks, DEFAULT_COMMITTEE_SIZE,
                };
                use crate::accounting::cross_zone::{
                    build_committee_proofs, sign_finality_witness,
                };
                let (pks, committee_hash, committee_size) = finality_committee_pks(
                    state,
                    seal.zone.path(),
                    seal.epoch_number,
                    DEFAULT_COMMITTEE_SIZE,
                )
                .await;
                let am_member = pks.iter().any(|pk| pk == &state.identity.public_key);
                if am_member && committee_size > 0 {
                    let (proof_root, proofs_by_pk) = build_committee_proofs(&pks);
                    if proof_root == committee_hash {
                        if let Some(witness) = sign_finality_witness(
                            &state.identity,
                            &seal.zone,
                            seal.epoch_number,
                            &seal.merkle_root,
                            &committee_hash,
                            &proofs_by_pk,
                        ) {
                            // Local fold + peer broadcast of the witness.
                            // Clone for the gossip path; consensus consumes by value.
                            {
                                let mut consensus = state.consensus.lock_recover();
                                consensus.add_seal_finality_signature(
                                    &record.id,
                                    seal.epoch_number,
                                    committee_hash,
                                    committee_size,
                                    witness.clone(),
                                );
                            }
                            // Phase 2c: gossip to peers so the rest of the
                            // committee can fold this signer into their
                            // SealFinalityCollection. sqrt(n) fan-out, dedup
                            // by (seal,witness_pk) — see
                            // gossip::push_finality_witness_to_peers.
                            let state_clone = Arc::clone(state);
                            let seal_id = record.id.clone();
                            let seal_epoch = seal.epoch_number;
                            tokio::spawn(async move {
                                crate::network::gossip::push_finality_witness_to_peers(
                                    &state_clone,
                                    &seal_id,
                                    seal_epoch,
                                    committee_hash,
                                    committee_size,
                                    witness,
                                )
                                .await;
                            });
                            debug!(
                                "seal-finality: signed seal={} zone={} epoch={} committee_size={}",
                                &record.id[..record.id.len().min(16)],
                                seal.zone.path(),
                                seal.epoch_number,
                                committee_size,
                            );
                        }
                    }
                }
            }

            // Evaluate predictions + Gap 2: attach cross-zone lock proofs.
            // Must run on the INGEST path, not only local seal creation, so any
            // node can verify a subsequent XZoneClaim without having sealed the
            // lock itself. Uses try_write to avoid blocking state core.
            if let Ok(mut ledger) = state.ledger.try_write() {
                let zone_str = seal.zone.path();
                let (correct, wrong, rewarded, confiscated) =
                    ledger.evaluate_predictions(zone_str, seal.epoch_number, seal.record_count, 0);
                if correct + wrong > 0 {
                    info!(
                        "predictions evaluated (ingest): zone={} epoch={} correct={} wrong={} rewarded={} confiscated={}",
                        zone_str, seal.epoch_number, correct, wrong, rewarded, confiscated,
                    );
                }
                // Gap 2.1 Phase 2b: bundle seal-finality witness signatures
                // (when collected) onto the same transfers, so claim_transfer
                // can enforce 2/3 zone-A finality on the consumer side.
                let proofed = match state.consensus.try_lock() {
                    Ok(awc) => epoch::attach_xzone_proofs_from_seal_with_finality(
                        &mut ledger, &seal, Some(&record.id), Some(&*awc),
                    ),
                    Err(_) => {
                        // Fallback attaches proof WITHOUT finality witnesses:
                        // post-Phase-5 that bakes committee_size=0 =
                        // unclaimable-until-reattach. Count it — this was a
                        // fully silent minting path (B1 audit 2026-07-12).
                        state
                            .xzone_attach_finality_lock_contended_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        epoch::attach_xzone_proofs_from_seal(&mut ledger, &seal)
                    }
                };
                if proofed > 0 {
                    info!("epoch seal (ingest): attached merkle proofs to {proofed} pending xzone transfers");
                }
                // Refresh the fleet-divergence digest while the ledger write
                // lock is already held (once per applied seal).
                state.xzone_state_digest.store(
                    ledger.cross_zone.state_digest(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                state
                    .xzone_state_digest_epoch
                    .store(seal.epoch_number, std::sync::atomic::Ordering::Relaxed);
            }

            // Update DAG epoch cursor — use try_write to avoid blocking.
            // Only advance from active zones (< zone_count) to prevent stale
            // zone epochs from inflating the DAG cursor and causing premature eviction.
            let zone_count = super::consensus::get_zone_count();
            let is_active_zone = seal.zone.path().parse::<u64>()
                .ok()
                .is_none_or(|n| n < zone_count);
            if is_active_zone {
                if let Ok(mut dag_guard) = state.dag.try_write() {
                    let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                    dag.set_current_epoch(seal.epoch_number);
                }
            }

            // Pairs with seal_ingest_phase5_entered_total at the block top —
            // entered > completed means a seal died mid-block (panic caught
            // upstream / early exit), the silent class the R3-8 soak surfaced.
            state.seal_ingest_phase5_completed_total.fetch_add(1, Relaxed);
        }
    }

    // Gap 3: Register ingested super-seals so ingesting nodes know the
    // canonical checkpoint per zone. Super-seals are emitted by the seal
    // creator and propagate via gossip like any record.
    if record.metadata.contains_key(EPOCH_OP_KEY) {
        if let Ok(Some(ss)) = epoch::extract_super_seal(&record) {
            let mut minted = false;
            if let Ok(mut epoch_state) = state.epoch.write() {
                minted = epoch_state.register_super_seal(
                    ss.zone.clone(),
                    ss.end_epoch,
                    record.id.clone(),
                    record.record_hash(),
                    ss.committee_hash,
                );
            }
            if minted {
                state
                    .super_seals_minted_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            info!(
                "super-seal ingested: zone={} epochs=[{}..={}] count={} id={} minted={}",
                ss.zone, ss.start_epoch, ss.end_epoch, ss.seal_count, record.id, minted,
            );
        }
    }

    // Gap 5: Recognize zone_subscription records and update the per-zone
    // witness subscription registry. Scale: O(zones_in_sub) per observation,
    // no I/O.
    if record.metadata.contains_key(EPOCH_OP_KEY) {
        if let Ok(Some(sub)) = super::zone_subscription::extract_subscription(&record) {
            let identity = sub.identity_hash.clone();
            let zone_count = sub.zones.len();
            let valid_until = sub.valid_until;
            let accepted = {
                let mut reg = state.zone_subscriptions.lock_recover();
                reg.observe(sub)
            };
            if accepted {
                info!(
                    "zone_subscription accepted: identity={} zones={} valid_until_epoch={}",
                    identity, zone_count, valid_until,
                );
            }
        }
    }

    // Stage 3c.1: register verified global quorum seals.
    // Pre-insert verification already happened for is_global_seal records;
    // this block wires the accepted seal into epoch state (unsticks the
    // chain) and tags it for cross-zone settlement in consensus.
    if record.metadata.contains_key(EPOCH_OP_KEY) {
        if let Ok(Some(gseal)) = epoch::extract_global_quorum_seal(&record) {
            if let Ok(mut epoch_state) = state.epoch.write() {
                epoch_state.register_global_seal(
                    &gseal,
                    &record.id,
                    record.record_hash(),
                );
            }
            {
                let mut consensus = state.consensus.lock_recover();
                consensus.register_global_seal(&record.id, gseal.stuck_zone.clone());
            }
            info!(
                "global_seal registered: stuck_zone={} stuck_epoch={} seal_id={}",
                gseal.stuck_zone,
                gseal.stuck_epoch,
                &record.id[..record.id.len().min(16)],
            );
        }
    }

    // Check for zone transition announcement (epoch_op = "zone_transition").
    // Only accepted from genesis authority. Stores the schedule for epoch-gated application.
    if record.metadata.contains_key(EPOCH_OP_KEY) {
        if let Ok(Some(transition)) = epoch::extract_zone_transition(&record) {
            let creator = creator_identity_hash(&record);
            if creator == state.config.genesis_authority {
                // Validate: target epoch must be in the future
                let current_max_epoch = {
                    let epoch_state = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
                    epoch_state.latest_epoch.values().copied().max().unwrap_or(0)
                };
                if transition.target_epoch > current_max_epoch {
                    info!(
                        "zone_transition scheduled: epoch {} → zone_count {} (from {}), announced by {}",
                        transition.target_epoch, transition.new_count, transition.old_count,
                        &transition.announced_by[..transition.announced_by.len().min(16)]
                    );
                    let mut zt = state.zone_transition.lock_recover();
                    *zt = Some(transition);
                } else {
                    // LIVENESS-2: target_epoch is already past — the chain advanced
                    // beyond it (frozen-chain recovery, restart-lost cache, or late
                    // gossip replay). If we still hold the old zone_count, apply
                    // immediately; otherwise the transition was already absorbed.
                    let our_zc = super::consensus::get_zone_count();
                    if our_zc == transition.old_count {
                        super::consensus::set_zone_count(transition.new_count);
                        info!(
                            "LIVENESS-2: zone_transition late-applied via ingest: \
                             zone_count {} → {} (target_epoch {} ≤ current_max {})",
                            transition.old_count, transition.new_count,
                            transition.target_epoch, current_max_epoch
                        );
                    } else {
                        debug!(
                            "zone_transition stale: target_epoch {} ≤ current_max {}, \
                             our zone_count {} ≠ transition.old_count {} — already applied",
                            transition.target_epoch, current_max_epoch,
                            our_zc, transition.old_count
                        );
                    }
                }
            } else {
                warn!(
                    "zone_transition rejected: creator {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                );
            }
        }
    }

    // Execute seal equivocation slash after all sync locks are released (economics §10).
    // Box::pin to break async recursion (slash record → insert_record → insert_record_inner).
    if let Some((creator, zone, epoch, seal_id, chash)) = seal_equivocation {
        if state.identity.identity_hash == state.config.genesis_authority {
            Box::pin(super::slashing::check_seal_equivocation(
                state, &creator, &zone, epoch, &seal_id, chash,
            )).await;
        }
    }

    // DISC-4 Phase D-3: checkpoint after epoch-related work (seal registration,
    // equivocation detection, super-seal, global-seal, zone transition,
    // equivocation slash). Everything above this runs epoch.write() locks and
    // potentially the recursive slashing.check_seal_equivocation await.
    let post_epoch_end_ms = ingest_t0.elapsed().as_millis();

    // Register key revocation if this record carries one (Protocol §11.2).
    // KR-1 (2026-07-03 audit): only a self-revocation (revoked key == the key
    // that signed this record) is honored — otherwise any actor could carry a
    // victim's pubkey and lock that identity out fleet-wide.
    if record.metadata.contains_key(super::key_rotation::REVOCATION_OP_KEY) {
        if super::key_rotation::revocation_authorized(&record) {
            if let Some(entry) = super::key_rotation::extract_revocation(&record) {
                if let Ok(mut registry) = state.key_registry.write() {
                    registry.register_revocation(entry);
                }
            }
        } else {
            warn!(
                "rejected unauthorized key revocation in record {} (revoked key != signer key)",
                record.id
            );
        }
    }

    // Register key rotation if this record carries one
    if record.metadata.contains_key(super::key_rotation::KEY_ROTATION_KEY) {
        if let Some(rotation) = super::key_rotation::extract_key_rotation(&record) {
            let identity_hash = creator_identity_hash(&record);
            if let Ok(mut registry) = state.key_registry.write() {
                registry.register_rotation(&identity_hash, rotation);
            }
        }
    }

    // Register VRF key if this record carries one (Protocol §11.12)
    // Only anchor nodes can register VRF keys — extract_vrf_registration
    // returns None for non-anchor node_type.
    if record.metadata.contains_key(super::vrf_registry::VRF_REGISTRATION_KEY) {
        if let Some(reg) = super::vrf_registry::extract_vrf_registration(&record) {
            let identity_hash = creator_identity_hash(&record);
            if let Ok(mut registry) = state.vrf_registry.write() {
                registry.register(&identity_hash, reg.clone());
            }
            // Persist so a restart rehydrates the registry from disk
            // rather than relying on fresh re-gossip of registration records.
            if let Err(e) = super::vrf_registry::persist_registration(
                &state.rocks,
                &identity_hash,
                &reg,
            ) {
                tracing::warn!("VRF registration persist failed: {e}");
            }
            state.vrf_registration_records_accepted_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            state.vrf_registration_records_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!("VRF registration rejected (non-anchor or malformed): {}", record.id);
        }
    }

    // Register witness profile if this record carries one (Protocol §7.5)
    if record.metadata.contains_key(super::consensus::WITNESS_PROFILE_KEY) {
        if let Some(profile) = super::consensus::extract_witness_profile(&record) {
            let identity_hash = creator_identity_hash(&record);
            let mut consensus = state.consensus.lock_recover();
            consensus.register_profile(&identity_hash, profile);
        }
    }

    // Agent-mandate effects (C4 slice 1) — OBSERVATIONAL, post-store, NO ledger
    // mutation: persist issuance/revocation into their CFs and index a
    // mandate-bearing act for flag recomputation. Best-effort (never fails the
    // already-committed record); first-apply gated so gossip replay can't
    // double-count. The mandate flag never enters consensus weight / the SMT
    // leaf / the seal root — that is what keeps v0 inert on the live chain.
    super::mandate_node::apply_mandate_effects(&record, &state.rocks, &state.config.network_id);
    // Fold an emergency halt/resume into the node-local atomics (persist-before-
    // publish). Post-store + observational — never mutates the ledger/SMT/seal.
    super::emergency_node::apply_emergency_effects(state, &record);

    // Apply delegation if this record carries one (Protocol v0.6.2 Section 6.2)
    if record.metadata.contains_key(DELEGATION_OP_KEY) {
        let op_for_metric = record
            .metadata
            .get(DELEGATION_OP_KEY)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Ok(mut deleg) = state.delegations.write() {
            match delegation::apply_delegation(&record, &mut deleg) {
                Ok(()) => {
                    // Profile C Gap E: count successful extends (one per child
                    // whose lease was prolonged). authorize/revoke/revoke_all
                    // are counted at ingest gate time on the rejected path.
                    if op_for_metric.as_deref() == Some("extend") {
                        state.delegation_extend_total.fetch_add(1, Relaxed);
                    }
                }
                Err(e) => {
                    if op_for_metric.as_deref() == Some("extend") {
                        state
                            .delegation_extend_rejected_total
                            .fetch_add(1, Relaxed);
                    }
                    warn!(
                        "delegation apply failed for {}: {e}",
                        &record.id[..record.id.len().min(16)]
                    );
                }
            }
        }
    }

    // Apply dispute operation after storage insert (Protocol §11.13)
    if record.metadata.contains_key(super::dispute::DISPUTE_OP_KEY) {
        if let Some(op) = super::dispute::extract_dispute_op(&record.metadata).ok().flatten() {
            let mut disputes = state.disputes.write_recover();
            match &op {
                super::dispute::ParsedDisputeOp::Open { contested_record_id, reason } => {
                    if let Err(e) = disputes.open_dispute(
                        record.id.clone(),
                        contested_record_id.clone(),
                        creator_identity_hash(&record),
                        reason.clone(),
                        record.timestamp,
                    ) {
                        warn!("dispute open failed for {}: {e}", &record.id[..record.id.len().min(16)]);
                    } else {
                        state.disputes_opened_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Dual-write dispute to RocksDB
                        if let Some(d) = disputes.get(&record.id) {
                            if let Ok(bytes) = serde_json::to_vec(d) {
                                let _ = state.rocks.put_cf_raw(
                                    crate::storage::rocks::CF_DISPUTES,
                                    record.id.as_bytes(),
                                    &bytes,
                                );
                            }
                        }
                    }
                }
                super::dispute::ParsedDisputeOp::Evidence { dispute_id, evidence_data: _ } => {
                    let window = state.config.dispute_evidence_window_secs;
                    if let Err(e) = disputes.add_evidence(dispute_id, record.id.clone(), record.timestamp, window) {
                        warn!("dispute evidence failed for {}: {e}", &record.id[..record.id.len().min(16)]);
                    }
                }
                super::dispute::ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                    let resolver = if creator_identity_hash(&record) == state.config.genesis_authority {
                        "genesis"
                    } else {
                        "governance"
                    };
                    // Collect attestors for the contested record BEFORE resolving
                    let contested_rid = disputes.get(dispute_id)
                        .map(|d| d.contested_record_id.clone());
                    if let Err(e) = disputes.resolve(dispute_id, resolver, outcome, record.timestamp) {
                        warn!("dispute resolve failed for {}: {e}", &record.id[..record.id.len().min(16)]);
                    } else {
                        // Dual-write resolved dispute to RocksDB
                        if let Some(d) = disputes.get(dispute_id) {
                            if let Ok(bytes) = serde_json::to_vec(d) {
                                let _ = state.rocks.put_cf_raw(
                                    crate::storage::rocks::CF_DISPUTES,
                                    dispute_id.as_bytes(),
                                    &bytes,
                                );
                            }
                        }
                        if let Some(contested) = contested_rid {
                        // Apply reputation effects based on dispute outcome (economics §11.2)
                        let attestors: Vec<String> = {
                            let consensus = state.consensus.lock_recover();
                            consensus.attestors(&contested)
                        };
                        if !attestors.is_empty() {
                            let mut rep = state.reputation.lock_recover();
                            rep.process_dispute_resolution(outcome, &attestors, record.timestamp);
                        }
                    }
                    }
                }
            }
        }
    }

    // Apply fisherman challenge operation after storage insert (economics §10.2)
    // pending_slash carries slash info out of the sync lock for async execution.
    #[allow(unused_assignments)]
    let mut pending_slash: Option<PendingSlash> = None;
    if record.metadata.contains_key(super::fisherman::CHALLENGE_OP_KEY) {
        if let Some(op) = super::fisherman::extract_challenge_op(&record.metadata).ok().flatten() {
            // Pre-fetch stakers BEFORE acquiring challenges write lock to avoid
            // holding std::sync::RwLockWriteGuard across .await (breaks Send).
            let needs_stakers = matches!(
                &op,
                super::fisherman::ParsedChallengeOp::File { .. }
                | super::fisherman::ParsedChallengeOp::Appeal { .. }
            );
            let eligible: Vec<String> = if needs_stakers {
                if let Ok(ledger_r) = state.ledger.try_read() {
                    ledger_r.all_stakers()
                } else {
                    Vec::new() // Skip jury selection if ledger locked
                }
            } else {
                Vec::new()
            };

            // Get epoch VRF output for the record's zone (for jury seeding).
            // Gap 4 routing-application: fisherman jury is drawn from the
            // resolved leaf's epoch state, not the naive modulo zone.
            // AUDIT-6: use time-indexed lookup (`vrf_output_at_or_before`) so the
            // VRF seed is a pure function of (record.timestamp, zone, DAG) — rebuild
            // and live paths select the same jury.
            //
            // Fisherman ring fork step 5: NO `.or_else(vrf_output)` fallback. The
            // old fallback seeded the jury from each node's CURRENT tip when the
            // time-indexed lookup missed — divergent mid-flight across nodes →
            // divergent 13-juror set → divergent verdict → replicated slash fork.
            // On a miss we now pass `None`; `file_challenge` then uses an empty
            // (deterministic) epoch seed, so every node selects the same jury.
            let record_zone_fish = state.resolve_record_zone(&record.id);
            let epoch_vrf = {
                let epoch_r = state.epoch.read_recover();
                epoch_r.vrf_output_at_or_before(&record_zone_fish, record.timestamp)
            };

            let mut ch = state.challenges.write_recover();
            match op {
                super::fisherman::ParsedChallengeOp::File { accused, challenge_type, evidence } => {
                    if let Some(ct) = super::fisherman::ChallengeType::parse_str(&challenge_type) {
                        match ch.file_challenge(
                            record.id.clone(), creator_identity_hash(&record),
                            accused, ct, evidence, record.timestamp, &eligible,
                            epoch_vrf.as_ref(),
                        ) {
                            Ok(jury) => {
                                state.challenges_filed_total.fetch_add(1, Relaxed);
                                debug!("fisherman challenge filed: {} ({} jurors)", &record.id[..record.id.len().min(16)], jury.len());
                            }
                            Err(e) => warn!("fisherman challenge failed for {}: {e}", &record.id[..record.id.len().min(16)]),
                        }
                    }
                }
                super::fisherman::ParsedChallengeOp::Vote { challenge_id, guilty } => {
                    match ch.cast_vote(&challenge_id, &creator_identity_hash(&record), guilty, record.timestamp) {
                        Ok(Some(true)) => {
                            debug!("fisherman verdict: GUILTY for challenge {}", challenge_id.chars().take(16).collect::<String>());
                            // Collect info for slash + reputation (done after lock drop)
                            if let Some(challenge) = ch.get(&challenge_id) {
                                let mut rep = state.reputation.lock_recover();
                                // Accused: spam-flagged for guilty verdict
                                rep.apply_event(
                                    &challenge.accused,
                                    super::reputation::ReputationEvent::SpamFlagged,
                                    record.timestamp,
                                );
                                // Challenger: successful accusation → reputation reward
                                rep.record_challenge_outcome(
                                    &challenge.challenger, true, record.timestamp,
                                );
                                // Prepare slash data for async execution after lock release
                                pending_slash = Some(PendingSlash {
                                    accused: challenge.accused.clone(),
                                    challenger: challenge.challenger.clone(),
                                    jury: challenge.jury.iter()
                                        .filter(|j| challenge.votes.iter().any(|v| &v.juror == *j && v.guilty))
                                        .cloned()
                                        .collect(),
                                    challenge_type: challenge.challenge_type.clone(),
                                });
                            }
                        }
                        Ok(Some(false)) => {
                            debug!("fisherman verdict: NOT GUILTY for challenge {}", challenge_id.chars().take(16).collect::<String>());
                            // Challenger filed a false accusation → reputation penalty
                            if let Some(challenge) = ch.get(&challenge_id) {
                                let mut rep = state.reputation.lock_recover();
                                rep.record_challenge_outcome(
                                    &challenge.challenger, false, record.timestamp,
                                );
                            }
                        }
                        Ok(None) => {} // Vote recorded, no verdict yet
                        Err(e) => warn!("fisherman vote failed: {e}"),
                    }
                }
                super::fisherman::ParsedChallengeOp::Appeal { challenge_id, reason } => {
                    match ch.file_appeal(
                        &challenge_id, &creator_identity_hash(&record),
                        reason, record.timestamp, &eligible, epoch_vrf.as_ref(),
                    ) {
                        Ok(jury) => debug!("fisherman appeal filed: {} ({} jurors)", challenge_id.chars().take(16).collect::<String>(), jury.len()),
                        Err(e) => warn!("fisherman appeal failed: {e}"),
                    }
                }
            }
        }
    }

    // Execute fisherman slash after releasing challenges lock (economics §10.3)
    // Only genesis authority auto-creates slash records.
    if let Some(slash) = pending_slash {
        if state.identity.identity_hash == state.config.genesis_authority {
            fisherman_slash(state, slash).await;
        }
    }

    // Register algorithm sunset if this record carries one
    if record.metadata.contains_key(SUNSET_OP_KEY) {
        if let Ok(Some(entry)) = sunset::extract_sunset(&record) {
            if let Ok(mut sunset_state) = state.sunset.write() {
                sunset_state.register(entry);
            }
        }
    }

    // DISC-4 Phase D-3: checkpoint after admin/governance work (key rotation,
    // delegation, dispute open/evidence/resolve + its RocksDB put_cf_raw,
    // fisherman challenge/vote/appeal + recursive fisherman_slash await,
    // sunset). This is the heaviest sub-phase — has the recursive
    // fisherman_slash await that can reenter the state_core path.
    let post_admin_end_ms = ingest_t0.elapsed().as_millis();

    // ── Content versioning (Protocol §11.30) ──────────────────────────────
    // Register version/diff records into the in-memory VersionState so
    // the /versions/* RPCs can serve chain/fork queries. O(1) per insert,
    // no I/O. try_lock to avoid blocking the ingest hot path if another
    // thread holds the lock (rare — only concurrent inserts contend).
    if record.metadata.get(crate::versioning::VERSION_OP_KEY)
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "version")
    {
        let version_number = record.metadata.get(crate::versioning::VERSION_NUMBER_KEY)
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
        if let Some(vnum) = version_number {
            let creator_hash_v = crate::accounting::types::creator_identity_hash(&record);
            let content_hash_v = hex::encode(record.record_hash());
            let prev = record.metadata.get(crate::versioning::PREV_VERSION_KEY)
                .and_then(|v| v.as_str())
                .map(String::from);
            let summary = record.metadata.get(crate::versioning::CHANGE_SUMMARY_KEY)
                .and_then(|v| v.as_str())
                .map(String::from);
            let ver = crate::versioning::VersionRecord {
                record_id: record.id.clone(),
                previous_version: prev,
                version_number: vnum,
                change_summary: summary,
                creator: creator_hash_v,
                content_hash: content_hash_v,
            };
            if let Ok(mut vs) = state.version_state.try_lock() {
                if let Err(e) = vs.register_version(ver) {
                    tracing::debug!("version register skipped for {}: {e}", &record.id[..record.id.len().min(16)]);
                }
            }
        }
    }
    if record.metadata.get(crate::versioning::DIFF_OP_KEY)
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "diff")
    {
        let from = record.metadata.get(crate::versioning::DIFF_FROM_KEY)
            .and_then(|v| v.as_str()).map(String::from);
        let to = record.metadata.get(crate::versioning::DIFF_TO_KEY)
            .and_then(|v| v.as_str()).map(String::from);
        if let (Some(from_v), Some(to_v)) = (from, to) {
            let creator_hash_d = crate::accounting::types::creator_identity_hash(&record);
            let diff = crate::versioning::DiffRecord {
                record_id: record.id.clone(),
                from_version: from_v,
                to_version: to_v,
                creator: creator_hash_d,
            };
            if let Ok(mut vs) = state.version_state.try_lock() {
                if let Err(e) = vs.register_diff(diff) {
                    tracing::debug!("diff register skipped for {}: {e}", &record.id[..record.id.len().min(16)]);
                }
            }
        }
    }

    // Emit real-time event for SSE subscribers
    let _ = state.events.send(super::state::NodeEvent::RecordInserted {
        record_id: record.id.clone(),
        creator_hash,
        beat_op: record.metadata.get("beat_op").and_then(|v| v.as_str()).map(String::from),
        beat_amount: record.metadata.get("beat_amount").and_then(crate::accounting::types::parse_beat_amount),
        timestamp: record.timestamp,
    });

    // ── Attestation recovery ─────────────────────────────────────────────
    // When a record arrives via gossip sync (full_pull, timestamp_pull), the
    // WitnessManager may already have attestations for it — received earlier
    // via att-pull/att-push but skipped during consensus rebuild because the
    // record wasn't in local storage yet. Feed them to consensus now.
    //
    // Split att into 3 sub-buckets. Earlier profiling
    // showed att dominates the slow path (a node spent 121s in att); this split
    // pins which of the three async awaits is the real stall so we don't
    // guess the fix.
    let att_gr_t0 = ingest_t0.elapsed().as_millis();
    let att_gr_end_ms;
    let att_lr_end_ms;
    {
        // The att split pinned `gr` at 100% of att on a
        // 1-vCPU node (att=14586ms [gr=14586ms lr=0ms bf=0ms]). Root cause: std
        // Mutex + RocksDB prefix_scan under lock_recover() blocks the
        // 1-vCPU tokio worker. Pattern matches the 1-vCPU async starvation rule.
        // Offload to spawn_blocking so the axum/state_core
        // tasks on the same worker stay responsive.
        //
        // A later profiling pass showed slow-record histograms still
        // reported `att=gr=15-30s` because spawn_blocking moved the work off
        // the tokio worker but the Mutex still serialized this scan against
        // unrelated attestation writers. A follow-up then dropped the Mutex
        // entirely — WitnessManager wraps no mutable state — so this path
        // now calls the manager directly under spawn_blocking.
        let witness_mgr = state.witness_mgr.clone();
        let hash_for_scan = hash.clone();
        let existing_atts = tokio::task::spawn_blocking(move || {
            witness_mgr.get_attestations(&hash_for_scan).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        att_gr_end_ms = ingest_t0.elapsed().as_millis();
        if !existing_atts.is_empty() {
            let creator_hash_for_att = crate::accounting::types::creator_identity_hash(&record);
            let batch: Vec<(String, String, f64)> = existing_atts.iter()
                .map(|a| (a.record_id.clone(), a.witness_hash.clone(), a.timestamp))
                .collect();
            let n = batch.len();
            // Register creator stake so settlement denominator is correct
            {
                let creator_staked = state.ledger.read().await.staked(&creator_hash_for_att);
                // F5: register creator identity unconditionally (see above).
                state.consensus.lock_recover()
                    .register_creator_stake(&hash, &creator_hash_for_att, creator_staked);
            }
            att_lr_end_ms = ingest_t0.elapsed().as_millis();
            let outcome = state.batch_feed_attestations(&batch).await;
            if !outcome.settled.is_empty() || n > 0 {
                info!("attestation recovery: fed {} existing attestations for {}, {} settled",
                    n, &hash[..hash.len().min(16)], outcome.settled.len());
            }
            // Previously this path never fired rewards/events for records it
            // finalized — closed by routing through the exactly-once edge.
            crate::network::reward::finalization_effects(state, outcome.newly_finalized);
            crate::network::reward::finalization_effects(state, outcome.seal_members_finalized);
        } else {
            att_lr_end_ms = att_gr_end_ms;
        }
    }
    let _ = att_gr_t0; // retain for clarity; covered by att_gr_end_ms - post_admin_end_ms

    let total_ingest_ms = ingest_t0.elapsed().as_millis();
    if total_ingest_ms > 10000 {
        // DISC-4 observability: bucket every slow record by dominant sub-phase.
        // Counters feed /metrics so Pattern A (pre) regression vs Pattern B
        // (post) residual is visible without grepping journalctl.
        let sb_ms = phase2_wall_ms.saturating_sub(pre_phase2_ms);
        let post_ms = total_ingest_ms.saturating_sub(ledger_end_ms);
        let half = total_ingest_ms / 2;
        use std::sync::atomic::Ordering::Relaxed;
        let mut dominated = true;
        if pre_phase2_ms > half {
            state.ingest_slow_records_pre_total.fetch_add(1, Relaxed);
        } else if post_ms > half {
            state.ingest_slow_records_post_total.fetch_add(1, Relaxed);
        } else if sb_ms > half {
            state.ingest_slow_records_sb_total.fetch_add(1, Relaxed);
        } else {
            state.ingest_slow_records_other_total.fetch_add(1, Relaxed);
            dominated = false;
        }
        // Per-phase MAX gauge. Each slow record bumps its actual
        // sub-times (pre/post/sb) regardless of which dominated, so an 11s
        // record with 6s pre + 5s post bumps both. `_other` only fires on
        // mixed-stall (no >50% dominance) and records total_ingest_ms.
        crate::network::state::store_max_atomic(
            &state.ingest_record_phase_max_ms_pre, pre_phase2_ms as u64,
        );
        crate::network::state::store_max_atomic(
            &state.ingest_record_phase_max_ms_post, post_ms as u64,
        );
        crate::network::state::store_max_atomic(
            &state.ingest_record_phase_max_ms_sb, sb_ms as u64,
        );
        if !dominated {
            crate::network::state::store_max_atomic(
                &state.ingest_record_phase_max_ms_other, total_ingest_ms as u64,
            );
        }
        // DISC-4 Phase D-1/D-2/D-3: break the ingest timeline into its real sub-phases.
        // - pre (val + sig + rest): everything before phase 2 storage.
        //     val  = validation + content safety + DAG hot-tier eviction read
        //            (contended by phase-3 DAG write lock)
        //     sig  = Dilithium3 + SPHINCS+ verify (inline, pure Rust, bounded)
        //     rest = ledger-snapshot read + trust/ledger/gov validation + ITC stamp
        //            (contended by phase-4 ledger write lock)
        // - sb: phase-2 spawn_blocking (RocksDB put_record + Merkle)
        // - dag: backpressure-sleep + yield_now + DAG write hold
        //        (backpressure fires only when sb itself >5s — see DISC-4 D-2)
        // - tomb/trust/ledger: phase-3/4 sync writes inside locks
        // - rest (DISC-4 D-7 split):
        //     rpre = post-sig CPU: revoke check, trust look-up, delegation,
        //            op parsing (val/gov/dispute/challenge)
        //     ldg  = state.ledger.read().await + in-block validation +
        //            fisherman stake check. Contends with phase-4 write lock.
        //     tail = rate limits, ITC stamping, relevance tracking,
        //            post-ledger work up to phase-2 spawn_blocking.
        // - post (ep + adm + att): phase-5 post-processing.
        //     ep   = epoch seal + equivocation detect + super/global seal +
        //            zone transition + equivocation slash (Box::pin await)
        //     adm  = key rotation + delegation + dispute + fisherman
        //            (includes recursive fisherman_slash await — heaviest)
        //     att  = event emit + attestation recovery + ledger.read await
        //       DISC-4 D-4 split:
        //       gr = witness_mgr.get_attestations (std Mutex + RocksDB prefix_scan)
        //       lr = ledger.read().await.staked + consensus register_creator_stake
        //       bf = batch_feed_attestations (multiple locks + ledger.read + get_record)
        warn!(
            "slow record {}: total={}ms (pre={}ms [val={}ms sig={}ms rest={}ms [rpre={}ms ldg={}ms tail={}ms]] sb={}ms dag={}ms tomb={}ms trust={}ms ledger={}ms post={}ms [ep={}ms adm={}ms att={}ms [gr={}ms lr={}ms bf={}ms]])",
            &hash[..hash.len().min(16)],
            total_ingest_ms,
            pre_phase2_ms,
            val_end_ms,
            sig_end_ms.saturating_sub(val_end_ms),
            pre_phase2_ms.saturating_sub(sig_end_ms),
            rest_rpre_end_ms.saturating_sub(sig_end_ms),
            rest_ldg_end_ms.saturating_sub(rest_rpre_end_ms),
            pre_phase2_ms.saturating_sub(rest_ldg_end_ms),
            phase2_wall_ms.saturating_sub(pre_phase2_ms),
            dag_end_ms.saturating_sub(phase2_wall_ms),
            tomb_end_ms.saturating_sub(dag_end_ms),
            trust_end_ms.saturating_sub(tomb_end_ms),
            ledger_end_ms.saturating_sub(trust_end_ms),
            total_ingest_ms.saturating_sub(ledger_end_ms),
            post_epoch_end_ms.saturating_sub(ledger_end_ms),
            post_admin_end_ms.saturating_sub(post_epoch_end_ms),
            total_ingest_ms.saturating_sub(post_admin_end_ms),
            att_gr_end_ms.saturating_sub(post_admin_end_ms),
            att_lr_end_ms.saturating_sub(att_gr_end_ms),
            total_ingest_ms.saturating_sub(att_lr_end_ms),
        );
    }

    if let Some(observer) = PROPAGATION_OBSERVER.get() {
        observer(&state.identity.identity_hash, &hash);
    }

    Ok(hash)
}

/// Execute a fisherman-triggered slash (economics §10.3).
///
/// Called as a spawned task to avoid async recursion in `insert_record`.
/// Distribution: 50% conservation pool, 30% challenger, 20% jury (split equally).
async fn fisherman_slash(state: &Arc<NodeState>, slash: PendingSlash) {
    // Find accused's largest active stake
    let stake_info = {
        let ledger = state.ledger.read().await;
        let stakes = ledger.stakes_for(&slash.accused);
        stakes.iter().max_by_key(|s| s.amount).map(|s| (s.record_id.clone(), s.amount))
    };
    let Some((stake_record_id, stake_amount)) = stake_info else {
        warn!(
            "fisherman slash: {} has no active stake — cannot slash",
            &slash.accused[..slash.accused.len().min(16)]
        );
        return;
    };

    let slash_pct = super::fisherman::slash_percent(&slash.challenge_type);
    let slash_amount = ((stake_amount as f64) * slash_pct) as u64;
    if slash_amount == 0 {
        return;
    }

    // Jury = jurors who voted guilty (they did the work)
    let jury = if slash.jury.is_empty() { vec![slash.challenger.clone()] } else { slash.jury };
    let reason = format!(
        "fisherman:{:?}:challenger={}",
        slash.challenge_type, &slash.challenger[..slash.challenger.len().min(16)]
    );

    match super::slashing::create_slash_record(super::slashing::SlashRecordParams {
        identity: &state.identity,
        amount: slash_amount,
        offender: &slash.accused,
        challenger: &slash.challenger,
        jury: &jury,
        stake_record_id: &stake_record_id,
        reason: &reason,
        light_mode: state.config.light_mode,
        slot_nonce: state.next_slot_nonce(),
    }) {
        Ok(slash_record) => {
            // Use insert_record_inner_direct to avoid state_core deadlock — this code
            // runs inside insert_record_inner (via state_core), so routing back through
            // the state_core channel would self-deadlock.
            match Box::pin(insert_record_inner_direct(state, slash_record.clone(), None, false)).await {
                Ok(_) => {
                    info!(
                        "FISHERMAN SLASH: {} slashed {} base units ({:.0}%), 30% to {}, 20% to {} jurors",
                        &slash.accused[..slash.accused.len().min(16)],
                        slash_amount, slash_pct * 100.0,
                        &slash.challenger[..slash.challenger.len().min(16)],
                        jury.len(),
                    );
                    // Publish the slash record to the network
                    super::state::NodeState::publish_record_with_fallback(state, &slash_record, None).await;
                }
                Err(e) => warn!("fisherman slash insert failed: {e}"),
            }
        }
        Err(e) => warn!("fisherman slash record creation failed: {e}"),
    }
}

/// H3: Pre-fetch missing records from peers when epoch seal merkle verification fails.
///
/// When a seal's merkle root doesn't match our local state, we're missing records
/// for that epoch's time range. This function:
/// 1. Parses the seal's time range (start..end)
/// 2. Fetches records in that range from connected peers
/// 3. Inserts them locally (skipping duplicates)
/// 4. Retries merkle verification
///
/// Returns Ok(()) if retry succeeds, or the original error if it still fails.
async fn merkle_prefetch_and_retry(
    state: &Arc<NodeState>,
    seal_record: &ValidationRecord,
    _genesis_authority: &str,
    _vrf_pk: Option<&crate::crypto::vrf::VrfPublicKey>,
) -> crate::errors::Result<()> {
    // Parse seal time range from metadata
    let start = seal_record.metadata.get("epoch_start")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let end = seal_record.metadata.get("epoch_end")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let zone_str = seal_record.metadata.get("epoch_zone")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();

    if start == 0.0 || end == 0.0 {
        return Err(ElaraError::Ledger("merkle pre-fetch: seal missing start/end timestamps".into()));
    }

    // Collect all peer URLs — try multiple, not just the first
    let peer_urls: Vec<String> = {
        let peers = state.peers.read().await;
        peers.all().into_iter()
            .filter(|p| p.identity_hash != state.identity.identity_hash)
            .map(|p| p.base_url())
            .collect()
    };

    if peer_urls.is_empty() {
        return Err(ElaraError::Network("merkle pre-fetch: no peers available".into()));
    }

    // AUDIT-10: PQ-only fetch. Derive per-peer PQ addr; skip peers without one.
    let pq_offset = state.config.pq_port_offset;

    // Try each peer until one returns records
    let mut wire_records: Vec<Vec<u8>> = Vec::new();
    let mut fetch_peer = String::new();
    for url in &peer_urls {
        let pq_addr = match super::gossip::http_to_pq_addr(url, pq_offset) {
            Some(a) => a,
            None => {
                debug!("merkle pre-fetch: no PQ addr for {}, skipping", url.chars().take(30).collect::<String>());
                continue;
            }
        };
        match state.pq_client.query_records(&pq_addr, start, 5000).await {
            Ok(records) if !records.is_empty() => {
                fetch_peer = url.chars().take(30).collect::<String>();
                wire_records = records;
                break;
            }
            Ok(_) => continue, // empty response, try next peer
            Err(e) => {
                debug!("merkle pre-fetch: {} failed: {e}", url.chars().take(30).collect::<String>());
                continue;
            }
        }
    }

    if wire_records.is_empty() {
        return Err(ElaraError::Network(format!(
            "merkle pre-fetch: no peer returned records for zone {zone_str} [{start:.0}..{end:.0}]"
        )));
    }

    // Insert fetched records through normal ingest path (DAG + ledger).
    let mut inserted = 0u32;
    let mut skipped = 0u32;
    for wire_bytes in &wire_records {
        let decoded = match ValidationRecord::from_bytes(wire_bytes) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip records outside the seal's time window
        if decoded.timestamp > end || decoded.timestamp < start {
            continue;
        }

        // Skip if we already have it in RocksDB
        if state.rocks.get_record(&decoded.id).ok().flatten().is_some() {
            skipped += 1;
            continue;
        }

        // Insert through state_core channel — full DAG + ledger processing.
        // This runs in a tokio::spawn (not inside state_core), so routing
        // through the channel won't self-deadlock.
        if let Some(core) = state.state_core.get() {
            // skip individual failures (dedup, validation)
            if let super::state_core::InsertResult::Accepted { .. } =
                core.insert_record(decoded, super::state_core::RecordSource::Sync).await
            {
                inserted += 1;
            }
        }
    }

    if inserted > 0 {
        info!(
            "merkle pre-fetch: inserted {inserted} records ({skipped} already had) for zone {zone_str} [{start:.0}..{end:.0}] from {fetch_peer}",
        );
    }

    // Retry: re-ingest the seal record through state_core.
    // Now that missing records are in DAG+ledger, the seal's merkle
    // verification should pass on the next attempt.
    if let Some(core) = state.state_core.get() {
        match core.insert_record(seal_record.clone(), super::state_core::RecordSource::Sync).await {
            super::state_core::InsertResult::Accepted { record_id } => {
                info!("merkle pre-fetch: seal {} accepted after prefetch", &record_id[..record_id.len().min(16)]);
                return Ok(());
            }
            super::state_core::InsertResult::Rejected { reason } => {
                warn!(
                    "merkle pre-fetch: seal retry rejected after inserting {inserted} records for zone {zone_str}: {reason}"
                );
                return Err(ElaraError::Ledger(reason));
            }
            super::state_core::InsertResult::Error { message } => {
                warn!(
                    "merkle pre-fetch: seal retry error after inserting {inserted} records for zone {zone_str}: {message}"
                );
                // P0 parity: transient state-core failure renders as TransientReject.
                return Err(ElaraError::TransientReject(message));
            }
        }
    }

    Err(ElaraError::Storage("merkle pre-fetch: state_core not initialized".into()))
}

/// Gap 1 (witness-side flush): apply the seal-creator's account-SMT scope to
/// this node's persistent SMT, so a witness — not just the rotating creator —
/// can serve account proofs that verify against the seal's signed
/// `account_smt_root`.
///
/// Scope-bounded: the witness reads the records the seal references
/// (`seal.record_hashes`), enumerates the identities each op touches via
/// [`account_merkle::record_touched_identities`], and snapshots EXACTLY that
/// set — instead of draining the whole `smt_dirty` set. Draining the full
/// set leaks per-node ingest-order divergence into the on-disk root: a
/// witness that gossiped a future-seal record before the current seal
/// arrived would otherwise flush its accounts state at the post-future point
/// and land at a root the seal's signature can never match. Scope-bounding
/// keeps out-of-seal identities in `smt_dirty` for the next seal that
/// actually covers them.
///
/// Snapshot-and-offload pattern (DISC-8) preserved: scope build + dirty
/// drain run under a brief `ledger.write().await` lock; the RocksDB writes
/// run in `spawn_blocking` so concurrent phase-1 seal validation (which
/// takes `ledger.read()`) does not stall. Mirrors the seal-creator path in
/// `epoch_seal_loop` (epoch.rs:3403-3467) — except the creator's pre-seal
/// drain is naturally bounded to its own dirty set, which on a healthy node
/// equals identities touched since the last seal.
///
/// On root mismatch (witness lacks records the seal references, or has
/// applied records out-of-order beyond the seal scope) we log at debug —
/// the witness will catch up on the next seal. Failure of either the
/// snapshot or the apply step is non-fatal: the seal itself was already
/// accepted, and a later flush retries the dirty set.
pub(super) async fn flush_witness_smt_for_seal(
    state: &Arc<NodeState>,
    seal: &super::epoch::ParsedEpochSeal,
) {
    let scope = compute_witness_smt_scope(state, seal);
    let snapshot = {
        let mut ledger = state.ledger.write().await;
        // Witness flush never removes accounts — empty delete set keeps an
        // in-scope-but-not-yet-committed recipient on its zero-state leaf
        // (the tolerated, self-healing transient), byte-identical to before.
        super::account_merkle::snapshot_scoped(&mut ledger, &scope, &std::collections::HashSet::new())
    };
    if snapshot.is_empty() && seal.account_smt_root.is_none() {
        return;
    }
    let rocks = state.rocks.clone();
    let zone = seal.zone.clone();
    let epoch_num = seal.epoch_number;
    let expected = seal.account_smt_root;
    // CF_ACCOUNT_SMT writer gate (leaf lock — see NodeState field doc). Held
    // across the blocking apply; a wait behind a concurrent writer is safe
    // here: the scope is re-derived from the seal's record_hashes on every
    // call, so nothing is lost by waiting.
    let _smt_gate = state.account_smt_write_gate.lock().await;
    let res = tokio::task::spawn_blocking(move || {
        super::account_merkle::apply_snapshot(&rocks, &snapshot)
    })
    .await;
    match res {
        Ok(Ok((flushed, actual))) => {
            if let Some(want) = expected {
                if actual != want {
                    tracing::debug!(
                        "witness_smt: root mismatch zone={} epoch={} flushed={} expected={} got={} (catching up)",
                        zone, epoch_num, flushed,
                        hex::encode(&want[..8]), hex::encode(&actual[..8]),
                    );
                }
            }
        }
        Ok(Err(e)) => warn!(
            "witness_smt: apply_snapshot failed zone={} epoch={}: {e}",
            zone, epoch_num,
        ),
        Err(e) => warn!(
            "witness_smt: spawn_blocking failed zone={} epoch={}: {e}",
            zone, epoch_num,
        ),
    }
}

/// Build the witness-side SMT-flush scope from a seal's record_hashes:
/// scan record IDs in the seal's zone+time-window, stream-load each record,
/// filter by record-hash membership in `seal.record_hashes`, union the
/// identities each op references, and stop as soon as every target hash has
/// been matched.
///
/// An earlier version materialised every record in the zone+window into a
/// `Vec<ValidationRecord>` (`query_zone(..usize::MAX)`) — at 1M-zone scale a
/// hot zone with ~13K records/epoch carries ~110 MB transient heap per seal,
/// which OOMs phone-tier nodes. The streaming path holds at most one decoded
/// record on the heap at a time, plus the `Vec<String>` of zone-window IDs
/// (~50 B each, capped at MAX_WITNESS_SCOPE_SCAN to bound the index read
/// itself). Memory drops from O(records × 8 KB) to O(IDs × 50 B + 1 record).
///
/// Records the witness has not yet received simply don't appear in the
/// window scan; those identities will be picked up at the next seal that
/// references them once the records propagate.
///
/// We deliberately do NOT use the `CF_IDX_HASH`-based `record_id_by_hash`
/// lookup. That index is keyed by `sha3_256_hex(content_hash)`, not
/// `hex(record_hash())`, so a direct point lookup against `seal.record_hashes`
/// would silently miss every record. The zone+time-window scan is the
/// established correct path and matches the witness validation flow.
fn compute_witness_smt_scope(
    state: &Arc<NodeState>,
    seal: &super::epoch::ParsedEpochSeal,
) -> std::collections::HashSet<String> {
    // Defensive cap on the zone-window index read. At healthy
    // scale a single epoch covers ≤ ~10K records per zone; the cap is 10×
    // that to absorb burst zones without unbounded RAM. If the cap fires,
    // the scope rebuild may miss late-window records — the next seal that
    // references them will rebuild the scope correctly once they are in
    // range.
    const MAX_WITNESS_SCOPE_SCAN: usize = 100_000;

    let mut scope = std::collections::HashSet::new();
    if seal.record_hashes.is_empty() {
        return scope;
    }

    let targets: std::collections::HashSet<[u8; 32]> =
        seal.record_hashes.iter().copied().collect();
    let target_count = targets.len();

    let zone_key = seal.zone.to_key_bytes();
    let ids = state.rocks.iter_zone(
        &zone_key,
        Some(seal.start),
        Some(seal.end),
        MAX_WITNESS_SCOPE_SCAN,
    );
    if ids.len() >= MAX_WITNESS_SCOPE_SCAN {
        state
            .witness_smt_scope_scan_hit_cap_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        warn!(
            "compute_witness_smt_scope: zone-window scan hit cap ({MAX_WITNESS_SCOPE_SCAN}) zone={} epoch={} — late-window records will be picked up by the next seal",
            seal.zone, seal.epoch_number,
        );
    }

    let mut matched = 0usize;
    for id in &ids {
        let rec = match state.rocks.get_record(id) {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                warn!(
                    "compute_witness_smt_scope: get_record failed id={id} zone={} epoch={}: {e}",
                    seal.zone, seal.epoch_number,
                );
                continue;
            }
        };
        if !targets.contains(&rec.record_hash()) {
            continue;
        }
        for identity in super::account_merkle::record_touched_identities(&rec) {
            scope.insert(identity);
        }
        matched += 1;
        if matched >= target_count {
            break;
        }
    }
    // Fewer matches than the seal references means the witness has not yet
    // received every covered record: the flushed scope is a strict subset of
    // the seal's, so its on-disk root cannot match the sealed root this round.
    // Surface it (the loop is otherwise silent on a partial result) so an
    // operator can distinguish propagation lag from the scan-cap case above.
    if matched < target_count {
        state
            .witness_smt_scope_incomplete_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    scope
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── DailyCapCounter: non-skippable per-identity hard daily cap ──────

    #[test]
    fn daily_cap_admits_exactly_limit_then_rejects() {
        let mut c = DailyCapCounter::new();
        let now = 1_700_000_000.0;
        for i in 0..5 {
            assert!(c.check_and_increment("id-a", now, 5), "submission {i} should admit");
        }
        assert!(!c.check_and_increment("id-a", now, 5), "the 6th over a cap of 5 must reject");
        // A distinct identity has its own independent budget.
        assert!(c.check_and_increment("id-b", now, 5), "distinct identity is unaffected");
    }

    #[test]
    fn daily_cap_rolls_over_after_window() {
        let mut c = DailyCapCounter::new();
        let day0 = 1_700_000_000.0;
        for _ in 0..3 {
            assert!(c.check_and_increment("id", day0, 3));
        }
        assert!(!c.check_and_increment("id", day0, 3), "capped within the window");
        // Past the 24h window the counter resets in place and admits again.
        let day1 = day0 + crate::accounting::trust::DAILY_WINDOW_SECS;
        assert!(c.check_and_increment("id", day1, 3), "new day → fresh budget");
    }

    #[test]
    fn daily_cap_cleanup_drops_rolled_over_entries() {
        let mut c = DailyCapCounter::new();
        let t0 = 1_700_000_000.0;
        for n in 0..10 {
            c.check_and_increment(&format!("id-{n}"), t0, 20);
        }
        assert_eq!(c.tracked_identities(), 10);
        // A full window later every entry is stale → cleanup evicts them (O(active)).
        c.cleanup(t0 + crate::accounting::trust::DAILY_WINDOW_SECS + 1.0);
        assert_eq!(c.tracked_identities(), 0, "stale daily-cap entries must be pruned");
    }

    // ─── global rate window: CAS reset + exact admission ────────────────

    #[test]
    fn global_rate_window_admits_exactly_limit_per_window() {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        let ws = AtomicU64::new(1000);
        let count = AtomicU64::new(0);
        // Same window: exactly `limit` admissions, then rejection.
        for _ in 0..5 {
            assert!(global_rate_window_admit(&ws, &count, 5, 1010));
        }
        assert!(!global_rate_window_admit(&ws, &count, 5, 1010));
        assert!(!global_rate_window_admit(&ws, &count, 5, 1059));
        // Window rolls at +60s: budget refreshed.
        assert!(global_rate_window_admit(&ws, &count, 5, 1060));
        assert_eq!(ws.load(Relaxed), 1060);
        assert_eq!(count.load(Relaxed), 1);
    }

    #[test]
    fn global_rate_window_reset_is_single_shot_per_boundary() {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        let ws = AtomicU64::new(1000);
        let count = AtomicU64::new(9);
        // First observer of the elapsed window wins the CAS and zeroes.
        assert!(global_rate_window_admit(&ws, &count, 100, 1060));
        assert_eq!(count.load(Relaxed), 1);
        // A racer that also saw the OLD window_start (simulated by a stale
        // CAS expectation) must NOT re-zero: hand-roll its CAS failure by
        // calling again — window_start is already 1060, so no reset path,
        // and increments landed after the reset survive.
        count.store(7, Relaxed);
        assert!(global_rate_window_admit(&ws, &count, 100, 1060));
        assert_eq!(
            count.load(Relaxed),
            8,
            "second same-boundary caller must not wipe the fresh window's count"
        );
    }

    // ─── 8b design B: successor-re-admission guard ──────────────────────

    fn stored_seal_record(zone: &str, epoch: u64, drop_field: Option<&str>) -> ValidationRecord {
        let mut md = std::collections::BTreeMap::new();
        md.insert(EPOCH_OP_KEY.to_string(), serde_json::json!("seal"));
        md.insert("epoch_zone".to_string(), serde_json::json!(zone));
        md.insert("epoch_number".to_string(), serde_json::json!(epoch));
        md.insert("epoch_start".to_string(), serde_json::json!(0.0));
        md.insert("epoch_end".to_string(), serde_json::json!(1.0));
        md.insert("epoch_record_count".to_string(), serde_json::json!(0u64));
        md.insert(
            "epoch_merkle_root".to_string(),
            serde_json::json!("00".repeat(32)),
        );
        md.insert(
            "epoch_previous_seal".to_string(),
            serde_json::json!("00".repeat(32)),
        );
        if let Some(f) = drop_field {
            md.remove(f);
        }
        ValidationRecord::create(
            b"seal",
            vec![],
            vec![],
            crate::record::Classification::Public,
            Some(md),
        )
    }

    #[test]
    fn seal_reentry_guard_admits_only_the_strict_successor() {
        let mut ep = crate::network::epoch::EpochState::new();
        ep.latest_epoch.insert(crate::ZoneId::new("z8b"), 41);

        // Strict immediate successor of the tip → re-flow (the healable
        // chain-link-rejected class from the 2026-07-01 §2b note).
        assert!(should_reenter_stored_seal(
            &stored_seal_record("z8b", 42, None),
            &ep
        ));
        // Already canonical at the tip → dedup as before.
        assert!(!should_reenter_stored_seal(
            &stored_seal_record("z8b", 41, None),
            &ep
        ));
        // Fork-loser the tip has passed → NEVER re-admitted (safety).
        assert!(!should_reenter_stored_seal(
            &stored_seal_record("z8b", 7, None),
            &ep
        ));
        // Catch-up territory (tip+2) → the B7 VRF-guarded path owns it.
        assert!(!should_reenter_stored_seal(
            &stored_seal_record("z8b", 43, None),
            &ep
        ));
        // extract-Err (missing mandatory field) is deterministic — never loop.
        assert!(!should_reenter_stored_seal(
            &stored_seal_record("z8b", 42, Some("epoch_merkle_root")),
            &ep
        ));
        // Bootstrapping zone (no canonical seal yet): a stored seal #1 whose
        // registration never landed is exactly the healable case.
        assert!(should_reenter_stored_seal(
            &stored_seal_record("z-new", 1, None),
            &ep
        ));
        // Non-seal records keep the plain dedup path.
        let plain = ValidationRecord::create(
            b"r",
            vec![],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(!should_reenter_stored_seal(&plain, &ep));
    }

    #[test]
    fn test_seen_set_basic() {
        let mut set = SeenSet::new(3);
        assert!(set.is_empty());
        assert!(set.insert("a".into()));
        assert!(!set.insert("a".into())); // duplicate
        assert!(set.insert("b".into()));
        assert!(set.insert("c".into()));
        assert_eq!(set.len(), 3);
        // Overflow: "a" evicted
        assert!(set.insert("d".into()));
        assert!(!set.contains("a"));
        assert!(set.contains("d"));
    }

    #[test]
    fn self_offender_conflict_proof_gossip_suppressed_but_slot_marked() {
        // F-9 follow-up: a slot conflict whose offender is OUR OWN identity
        // must NOT gossip a proof to peers (self-naming spam — production
        // Helsinki fired one every 1-3 min from a nonce-reuse bug), yet must
        // STILL mark the slot conflicted locally so we never build further on
        // it. A peer's genuine equivocation is unaffected (offender != self →
        // gossip spawns as before). The self branch has no tokio::spawn, so
        // this exercises the real emission path deterministically.
        use std::collections::BTreeMap;
        use std::sync::atomic::Ordering::Relaxed;

        let state = crate::network::state::build_test_node_state();

        // Two self-signed v5 records claiming the SAME slot (same nonce) with
        // distinct content → a valid ConflictProof whose offender == us.
        let mk = |nonce: u64, content: &[u8]| {
            let mut rec = ValidationRecord::create(
                content,
                state.identity.public_key.clone(),
                vec![],
                crate::record::Classification::Public,
                Some(BTreeMap::new()),
            );
            rec.version = 5;
            rec.nonce = nonce;
            rec.zone = Some(crate::ZoneId::from_legacy(0));
            state.identity.sign_record_light(&mut rec).unwrap();
            rec
        };
        let existing = mk(7, b"self-content-alpha");
        let incoming = mk(7, b"self-content-beta");

        // handle_slot_conflict reads `existing` back from rocks by id.
        state.rocks.put_record(&existing.id, &existing).unwrap();

        let slot_key = existing.slot_key().expect("v5 record has a slot_key");
        // Both records agree on the slot; offender resolves to our identity.
        assert_eq!(incoming.slot_key().as_deref(), Some(slot_key.as_str()));

        let before_pushed = state.conflict_proof_pushed_total.load(Relaxed);

        let err = handle_slot_conflict(&state, &slot_key, existing.id.clone(), &incoming);
        // Caller still gets the slot-conflict Wire rejection.
        assert!(matches!(err, ElaraError::Wire(_)));

        // Self-offender → gossip suppressed, counter bumped, nothing pushed.
        assert_eq!(state.conflict_proof_self_suppressed_total.load(Relaxed), 1);
        assert_eq!(state.conflict_proof_pushed_total.load(Relaxed), before_pushed);
        // …but the slot IS still marked conflicted locally.
        assert!(state.rocks.slot_is_conflicted(&slot_key).unwrap());
    }

    #[test]
    fn test_propagation_limiter_basic() {
        let mut limiter = PropagationLimiter::new(3);
        let t = 1000.0;
        assert!(limiter.check_and_record("alice", t));
        assert!(limiter.check_and_record("alice", t + 1.0));
        assert!(limiter.check_and_record("alice", t + 2.0));
        // 4th should be rate-limited
        assert!(!limiter.check_and_record("alice", t + 3.0));
        // Different identity is fine
        assert!(limiter.check_and_record("bob", t + 3.0));
    }

    #[test]
    fn test_propagation_limiter_window_expiry() {
        let mut limiter = PropagationLimiter::new(2);
        let t = 1000.0;
        assert!(limiter.check_and_record("alice", t));
        assert!(limiter.check_and_record("alice", t + 1.0));
        assert!(!limiter.check_and_record("alice", t + 2.0)); // blocked

        // After window expires (1 hour), should be allowed again
        let t2 = t + 3601.0;
        assert!(limiter.check_and_record("alice", t2));
    }

    #[test]
    fn test_propagation_limiter_disabled() {
        let mut limiter = PropagationLimiter::new(0);
        // limit=0 means disabled, should always allow
        for i in 0..1000 {
            assert!(limiter.check_and_record("alice", 1000.0 + i as f64));
        }
    }

    #[test]
    fn test_propagation_limiter_cleanup() {
        let mut limiter = PropagationLimiter::new(100);
        limiter.check_and_record("alice", 1000.0);
        limiter.check_and_record("bob", 1000.0);
        assert_eq!(limiter.tracked_identities(), 2);

        // Cleanup with time far in the future
        limiter.cleanup(1000.0 + 7200.0);
        assert_eq!(limiter.tracked_identities(), 0);
    }

    #[test]
    fn test_max_record_bytes_constant() {
        // Verify the constant is 64KB
        assert_eq!(MAX_RECORD_BYTES, 65_536);
    }

    // ─── Global rate limit (sybil flood via many identities) ──

    #[test]
    fn test_propagation_limiter_sybil_flood() {
        // 100 distinct identities each sending 1 record/hr — should all pass
        let mut limiter = PropagationLimiter::new(100);
        let t = 1_000_000.0;
        for i in 0..100u32 {
            assert!(limiter.check_and_record(&format!("sybil_{i}"), t + i as f64),
                "identity sybil_{i} should be allowed its first record");
        }
        assert_eq!(limiter.tracked_identities(), 100);

        // Each identity tries a 2nd burst — should still pass (limit=100)
        for i in 0..100u32 {
            assert!(limiter.check_and_record(&format!("sybil_{i}"), t + 200.0 + i as f64));
        }

        // After window expiry (latest record was at t+299), all slots freed
        let future = t + 3600.0 + 300.0;
        limiter.cleanup(future);
        assert_eq!(limiter.tracked_identities(), 0);
    }

    #[test]
    fn test_propagation_limiter_single_identity_exhaustion() {
        // Single identity hitting the exact limit boundary
        let mut limiter = PropagationLimiter::new(100);
        let t = 1_000_000.0;
        for i in 0..100u32 {
            assert!(limiter.check_and_record("attacker", t + i as f64));
        }
        // 101st is rejected
        assert!(!limiter.check_and_record("attacker", t + 100.0));
        // Other identity unaffected
        assert!(limiter.check_and_record("legit_user", t + 100.0));
    }

    #[test]
    fn test_propagation_limiter_stake_scaled() {
        // Unstaked identity gets flat base limit
        let mut limiter = PropagationLimiter::new(100);
        let t = 1_000_000.0;
        for i in 0..100u64 {
            assert!(limiter.check_and_record_scaled("unstaked", t + i as f64, 100));
        }
        assert!(!limiter.check_and_record_scaled("unstaked", t + 100.0, 100));

        // Staked identity with higher effective limit
        // Simulate: 100 beat staked, ratio 100K, hourly bonus = 100*10^9 / 100K / 24 = 41,666
        // effective_limit = 100 + 41,666 = 41,766
        let effective = 41_766;
        for i in 0..500u64 {
            assert!(limiter.check_and_record_scaled("staked_factory", t + i as f64, effective),
                "staked identity should handle 500 records easily with limit {effective}");
        }

        // Verify the staked identity can go well past the base 100/hr
        for i in 500..1000u64 {
            assert!(limiter.check_and_record_scaled("staked_factory", t + i as f64, effective));
        }
    }

    #[test]
    fn test_propagation_limiter_stake_bonus_formula() {
        // Verify the stake bonus math matches the design (100 beat → 1000/day).
        // Tied to the real constants so it can't regress on a unit-scale change.
        let ratio = crate::accounting::trust::BASE_UNITS_PER_DAILY_RECORD; // 10^8 base units/record
        let beat = crate::accounting::types::BASE_UNITS_PER_BEAT;          // 10^9 base units/beat

        // 100 beat staked → 1000/day
        let staked = 100 * beat;
        let daily = staked / ratio;
        let hourly_bonus = daily / 24;
        assert_eq!(daily, 1_000);     // 1000 records/day
        assert_eq!(hourly_bonus, 41); // ~41.6 records/hr

        // 1,000 beat staked → 10,000/day
        let staked = 1_000 * beat;
        let hourly_bonus = staked / ratio / 24;
        assert_eq!(hourly_bonus, 416); // ~416 records/hr

        // 0 beat = no bonus
        let staked: u64 = 0;
        let hourly_bonus = staked / ratio / 24;
        assert_eq!(hourly_bonus, 0);
    }

    #[test]
    fn test_seen_set_capacity_50k() {
        // Verify dedup set can handle 50K entries without panic
        let mut set = SeenSet::new(50_000);
        for i in 0..50_000 {
            assert!(set.insert(format!("record_{i}")));
        }
        assert_eq!(set.len(), 50_000);
        // 50001st entry evicts the oldest
        assert!(set.insert("overflow".into()));
        assert!(!set.contains("record_0")); // evicted
        assert!(set.contains("overflow"));
        assert_eq!(set.len(), 50_000);
    }

    #[test]
    fn test_seen_set_remove() {
        let mut set = SeenSet::new(10);
        set.insert("a".into());
        set.insert("b".into());
        assert!(set.contains("a"));
        set.remove("a");
        assert!(!set.contains("a"));
        // Re-inserting after remove should succeed
        assert!(set.insert("a".into()));
        assert!(set.contains("a"));
    }

    #[test]
    fn test_seen_set_clear() {
        let mut set = SeenSet::new(10);
        set.insert("a".into());
        set.insert("b".into());
        set.insert("c".into());
        assert_eq!(set.len(), 3);
        set.clear();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        // Can insert again after clear
        assert!(set.insert("a".into()));
    }

    #[test]
    fn test_seen_set_capacity_one() {
        let mut set = SeenSet::new(1);
        assert!(set.insert("a".into()));
        assert_eq!(set.len(), 1);
        // Second insert evicts first
        assert!(set.insert("b".into()));
        assert!(!set.contains("a"));
        assert!(set.contains("b"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_propagation_limiter_scaled_zero_bypasses() {
        let mut limiter = PropagationLimiter::new(5);
        // effective_limit=0 should always allow (bypass mode)
        for i in 0..100 {
            assert!(limiter.check_and_record_scaled("id", 1000.0 + i as f64, 0));
        }
    }

    #[test]
    fn test_propagation_limiter_cleanup_retains_active() {
        let mut limiter = PropagationLimiter::new(100);
        limiter.check_and_record("old", 1000.0);
        limiter.check_and_record("recent", 5000.0);
        // Cleanup at 4601: old (1000) is > 3600s ago, recent (5000) is within window
        limiter.cleanup(4601.0);
        assert_eq!(limiter.tracked_identities(), 1);
        // recent should still be tracked
        assert!(limiter.check_and_record("recent", 5001.0));
    }

    #[test]
    fn test_seen_set_remove_nonexistent_is_noop() {
        // Defensive: remove on a missing key must not panic and must not
        // perturb len/contains for keys that ARE present. The hot path during
        // initial sync calls `remove` speculatively to allow retry — if the
        // entry was already evicted by FIFO churn, that path must stay silent.
        let mut set = SeenSet::new(8);
        set.remove("never-inserted"); // empty set, no-op
        assert!(set.is_empty());

        set.insert("a".into());
        set.insert("b".into());
        let before = set.len();
        set.remove("ghost"); // populated set, missing key — no-op
        assert_eq!(set.len(), before);
        assert!(set.contains("a"));
        assert!(set.contains("b"));
    }

    #[test]
    fn test_seen_set_fifo_eviction_order() {
        // Insertion order = eviction order. Beyond `test_seen_set_basic` (which
        // pins one eviction) we want to verify that *successive* evictions
        // proceed strictly FIFO across multiple overflows — guards against an
        // accidental swap to LIFO / random eviction in the dedup hot path.
        let mut set = SeenSet::new(3);
        for k in ["a", "b", "c", "d", "e"] {
            assert!(set.insert(k.into()));
        }
        assert_eq!(set.len(), 3);
        // a, b evicted (oldest first); c, d, e retained.
        assert!(!set.contains("a"));
        assert!(!set.contains("b"));
        assert!(set.contains("c"));
        assert!(set.contains("d"));
        assert!(set.contains("e"));

        // Next insert must evict c (the new oldest), not e (the newest).
        assert!(set.insert("f".into()));
        assert!(!set.contains("c"));
        assert!(set.contains("d"));
        assert!(set.contains("e"));
        assert!(set.contains("f"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_propagation_limiter_window_boundary_inclusive() {
        // Pin the prune predicate: entries are dropped strictly when `t < cutoff`
        // (cutoff = now - 3600s). An entry at exactly `cutoff` is RETAINED.
        // This matters because flipping `<` to `<=` would silently amplify the
        // effective limit by one across every identity at every check.
        let mut limiter = PropagationLimiter::new(2);

        // Fill the bucket at t=1000 and t=1001.
        assert!(limiter.check_and_record("alice", 1000.0));
        assert!(limiter.check_and_record("alice", 1001.0));

        // At t=4600: cutoff = 1000. Entry at t=1000 has 1000 < 1000 == false,
        // so it is RETAINED. Bucket is still full → reject.
        assert!(!limiter.check_and_record("alice", 4600.0));

        // At t=4601: cutoff = 1001. Entry at t=1000 has 1000 < 1001 == true,
        // so it IS pruned. Bucket drops to 1 → accept.
        assert!(limiter.check_and_record("alice", 4601.0));
    }

    #[test]
    fn test_ingest_constants_invariants() {
        // Lock the protocol-critical constants against accidental retuning.
        // These bound worst-case record size, parent fan-in, metadata weight,
        // and the timestamp-drift gate that the v0.6.2 ingress pipeline relies
        // on. Each is referenced from gossip, RPC, and the slot-conflict path —
        // changing one in isolation would silently widen an attack surface.
        assert_eq!(MAX_METADATA_ENTRIES, 64, "metadata entry cap (24→64 Decision A pre-v0.1.0; frozen one-way door)");
        assert_eq!(MAX_METADATA_VALUE_LEN, 8_192, "metadata value byte cap");
        assert_eq!(MAX_PARENTS, 256, "max parents per record");
        assert_eq!(MAX_RECORD_BYTES, 65_536, "max serialized record size");
        // Future drift tolerance is 5 minutes — must not regress to a wider
        // window that would let an attacker pre-mint records.
        assert!(
            (MAX_FUTURE_DRIFT_SECS - 300.0).abs() < f64::EPSILON,
            "future drift must be exactly 300s (5min)"
        );
    }

    /// MEASUREMENT: how a worst-case Profile A (dual-signed) record sizes against
    /// the `MAX_RECORD_BYTES` wire cap. The cap is enforced FIRST in
    /// `insert_record_inner` (before the per-field metadata checks), so it is the
    /// binding aggregate constraint on every path. This prints the real
    /// `to_bytes()` size at the structural extremes so the cap and the per-field
    /// bounds (`MAX_PARENTS`, `MAX_ZONE_REFS`, `MAX_METADATA_*`) can be kept
    /// mutually consistent — a per-field bound that lets a record exceed the
    /// aggregate cap is a dead bound (the wire cap rejects it first).
    #[test]
    fn worst_case_profile_a_record_size_vs_wire_cap() {
        use std::collections::BTreeMap;
        // Synthetic sizes (contents irrelevant to byte length):
        //   Dilithium3 sig = 3309, Dilithium3 PK = 1952 (FIPS 204)
        //   SPHINCS+-SHA2-192f sig = 35664, PK = 48 (FIPS 205)
        let build = |n_parents: usize, n_refs: usize, meta: BTreeMap<String, serde_json::Value>| {
            crate::record::ValidationRecord {
                id: "0".repeat(36),
                version: 5,
                content_hash: vec![0u8; 32],
                creator_public_key: vec![0u8; 1952],
                timestamp: 1.0,
                parents: (0..n_parents).map(|i| format!("{i:036}")).collect(),
                classification: crate::record::Classification::Public,
                metadata: meta,
                signature: Some(vec![0u8; 3309]),
                sphincs_signature: Some(vec![0u8; 35664]),
                zk_proof: None,
                itc_stamp: None,
                zone_refs: (0..n_refs).map(|_| vec![0u8; 17]).collect(),
                creator_sphincs_pk: Some(vec![0u8; 48]),
                sig_algorithm: 1,
                sphincs_algorithm: Some(2),
                zone: None,
                identity_hash_wire: None,
                nonce: 0,
            }
        };
        let cap = MAX_RECORD_BYTES;
        // Case 1: minimal Profile A — 1 parent, no refs, no metadata.
        let minimal = build(1, 0, BTreeMap::new()).to_bytes().len();
        // Case 2: worst-case STRUCTURE — full parents + refs, no metadata.
        let structural = build(MAX_PARENTS, 256, BTreeMap::new()).to_bytes().len();
        // Case 3: structural + one realistic large metadata value (VRF-proof-sized).
        let mut one_big = BTreeMap::new();
        one_big.insert("vrf".into(), serde_json::Value::String("a".repeat(6600)));
        let structural_plus_vrf = build(MAX_PARENTS, 256, one_big).to_bytes().len();
        // Case 4: structural + the MAX metadata the per-field bounds permit
        //         (64 entries x 8192-byte values — each legal by MAX_METADATA_*).
        let mut max_meta = BTreeMap::new();
        for i in 0..MAX_METADATA_ENTRIES {
            max_meta.insert(format!("k{i:02}"), serde_json::Value::String("x".repeat(MAX_METADATA_VALUE_LEN)));
        }
        let structural_plus_maxmeta = build(MAX_PARENTS, 256, max_meta).to_bytes().len();

        println!("WIRE CAP            = {cap} bytes ({} KiB)", cap / 1024);
        println!("minimal Profile A   = {minimal} bytes  (headroom {})", cap as i64 - minimal as i64);
        println!("worst structural    = {structural} bytes  (headroom {})", cap as i64 - structural as i64);
        println!("structural + 1 vrf  = {structural_plus_vrf} bytes  (headroom {})", cap as i64 - structural_plus_vrf as i64);
        println!("structural + maxmeta= {structural_plus_maxmeta} bytes  (headroom {})", cap as i64 - structural_plus_maxmeta as i64);

        // The load-bearing invariant: a worst-case STRUCTURAL dual-signed record
        // (full parents + refs, no user metadata) MUST fit the wire cap, else the
        // protocol's own MAX_PARENTS/MAX_ZONE_REFS legitimacy bounds are
        // unreachable for Profile A records and the cap silently caps validity.
        assert!(
            structural <= cap,
            "worst-case structural Profile A record ({structural} B) exceeds wire cap ({cap} B) \
             — MAX_PARENTS/MAX_ZONE_REFS are inconsistent with MAX_RECORD_BYTES for dual-signed records"
        );
    }

    fn fake_seal_with_root(
        root: Option<[u8; 32]>,
        record_hashes: Vec<[u8; 32]>,
    ) -> super::super::epoch::ParsedEpochSeal {
        super::super::epoch::ParsedEpochSeal {
            zone: crate::ZoneId::new("test/zone"),
            epoch_number: 1,
            start: 0.0,
            end: 30.0,
            record_count: record_hashes.len() as u64,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: root,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    /// Build a ledger-op record with a deterministic creator pubkey, store it
    /// in `state.rocks`, and return the creator's identity hash plus the
    /// record's `record_hash()`. Used by the scope-bounded witness-flush tests
    /// to wire up `seal.record_hashes` → real records → identities the scope
    /// picks up via the zone+time-window query in `compute_witness_smt_scope`.
    fn store_ledger_record(
        state: &Arc<crate::network::state::NodeState>,
        record_id: &str,
        creator_seed: &[u8],
        zone: crate::ZoneId,
        timestamp: f64,
        metadata: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> (String, [u8; 32]) {
        let mut creator_pk = vec![0u8; 1952];
        creator_pk[..creator_seed.len().min(1952)]
            .copy_from_slice(&creator_seed[..creator_seed.len().min(1952)]);
        let identity = crate::crypto::hash::sha3_256_hex(&creator_pk);

        // content_hash mirrors what `ValidationRecord::create` does — sha3 of
        // a unique, deterministic per-record byte string.
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(record_id.as_bytes());
        hash_input.extend_from_slice(&serde_json::to_vec(&metadata).unwrap_or_default());
        let content_hash = crate::crypto::hash::sha3_256(&hash_input);

        let record = crate::record::ValidationRecord {
            id: record_id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: content_hash.to_vec(),
            creator_public_key: creator_pk,
            timestamp,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: Some(zone),
            identity_hash_wire: None,
            nonce: 0,
        };

        state.rocks.put_record(record_id, &record).unwrap();
        let record_hash = record.record_hash();
        (identity, record_hash)
    }

    #[tokio::test]
    async fn f2_r1_tombstoned_record_ledger_op_is_applied_not_suppressed() {
        // F2 R1 regression pin (semantic A): a tombstoned ledger-op record's op is
        // APPLIED on the live path — parked in PendingLedger like any record — so the
        // live committed ledger converges with the rebuild folds + rederive_swept_delta
        // (which already apply it unconditionally). `apply_ledger_op_phase4` is the
        // extracted chain the tombstone gate now runs (the
        // `if tombstoned { apply_ledger_op_phase4(...).await; return }` branch). Before
        // R1 the op was SUPPRESSED (the 2752 early-return skipped Phase 4) — the F2
        // fork bug. This is the red->green anchor. See
        // internal design notes.
        let state = crate::network::state::build_test_node_state();
        let alice = crate::crypto::hash::sha3_256_hex(b"alice-f2-r1");
        let rec_id = "f2-r1-tomb-mint";
        store_ledger_record(
            &state,
            rec_id,
            b"creator-f2-r1",
            crate::ZoneId::new("test/zone"),
            1_800_000_000.0,
            crate::accounting::types::mint_metadata(1_000, &alice, "test"),
        );
        let record = state.rocks.get_record(rec_id).unwrap().unwrap();
        let creator_hash = crate::accounting::types::creator_identity_hash(&record);
        let parsed = crate::accounting::types::extract_ledger_op(&record).unwrap();
        assert!(parsed.is_some(), "mint record must carry a ledger op");

        // Tombstone-first ordering: the marker is present before the op is applied.
        state
            .mark_tombstoned(rec_id, "tombstoner-id", "content-safety test")
            .unwrap();
        assert!(state.is_tombstoned(rec_id).unwrap());
        assert!(
            !state.pending_ledger.read().await.contains(rec_id),
            "precondition: nothing parked before the apply"
        );

        // R1: the tombstone gate runs exactly this for a tombstoned record.
        super::apply_ledger_op_phase4(&state, &record, creator_hash, parsed).await;

        // GREEN under R1 (was RED before it): the tombstoned record's ledger op is
        // parked on the live path — it will commit at finality and match the rebuild
        // folds. Suppressing it (the pre-R1 behavior) is the F2 divergence/fork.
        assert!(
            state.pending_ledger.read().await.contains(rec_id),
            "F2 R1: a tombstoned ledger-op record's op MUST be applied (parked) on the \
             live path, converging with rebuild+drain; suppressing it is the fork bug"
        );
    }

    #[tokio::test]
    async fn f2_r2_tombstoning_op_record_invalidates_ledger_checkpoint() {
        // F2 R2: tombstoning a ledger/governance-op-carrying record deletes the "ledger"
        // checkpoint so the next boot full-rebuilds (which honors the governance
        // is_tombstoned skip in the folds) instead of fast-booting from a checkpoint
        // that already baked in the now-tombstoned op's effect. This is the SCALE-SAFE
        // alternative to an O(all_records) governance rescan per boot (there is no
        // gov-record index). See TOMBSTONE-LEDGER-REDERIVE brief (R2 scale correction).
        let state = crate::network::state::build_test_node_state();
        let alice = crate::crypto::hash::sha3_256_hex(b"alice-f2-r2");
        let rec_id = "f2-r2-op-record";
        store_ledger_record(
            &state,
            rec_id,
            b"creator-f2-r2",
            crate::ZoneId::new("test/zone"),
            1_800_000_100.0,
            crate::accounting::types::mint_metadata(500, &alice, "test"),
        );

        // A saved ledger checkpoint exists (as after a periodic snapshot save).
        let ledger = state.ledger.read().await.clone();
        state.rocks.save_snapshot("ledger", &ledger).unwrap();
        assert!(
            state
                .rocks
                .load_snapshot::<crate::accounting::ledger::LedgerState>("ledger")
                .unwrap()
                .is_some(),
            "precondition: checkpoint saved"
        );

        // Tombstone the op-carrying record.
        state
            .mark_tombstoned(rec_id, "tombstoner-id", "content-safety test")
            .unwrap();

        // R2: the checkpoint is invalidated so the next boot full-rebuilds (which skips
        // the tombstoned governance op) rather than inheriting the stale tally.
        assert!(
            state
                .rocks
                .load_snapshot::<crate::accounting::ledger::LedgerState>("ledger")
                .unwrap()
                .is_none(),
            "F2 R2: tombstoning an op-carrying record MUST invalidate the ledger \
             checkpoint so the next boot full-rebuilds; a stale checkpoint is the \
             silent, permanent governance-staleness fork"
        );
    }

    #[tokio::test]
    async fn f2_r1_cap_rejected_tombstoned_op_takes_direct_apply_fallback_not_stranded() {
        // F2 R1 — seat-2's "single biggest risk": a tombstoned record whose ARCH-1 park
        // is REJECTED (cap/duplicate) must take the direct-apply FALLBACK, NOT be
        // stranded. R1 extracts the FULL Phase-4 chain (incl. the fallback at
        // ingest.rs:2967-3058), so a rejected op still reaches apply. A narrow
        // park-only hoist would leave it neither parked nor applied → F2 recurrence for
        // the cap-rejected + never-finalized case. This pins that the fallback fires for
        // a tombstoned record. See TOMBSTONE-LEDGER-REDERIVE brief (R1 §B / review R1).
        let state = crate::network::state::build_test_node_state();
        let alice = crate::crypto::hash::sha3_256_hex(b"alice-cap");
        let rec_id = "f2-cap-mint";
        store_ledger_record(
            &state,
            rec_id,
            b"creator-cap",
            crate::ZoneId::new("test/zone"),
            1_800_000_300.0,
            crate::accounting::types::mint_metadata(100, &alice, "test"),
        );
        let record = state.rocks.get_record(rec_id).unwrap().unwrap();
        let ch = crate::accounting::types::creator_identity_hash(&record);
        let parsed = crate::accounting::types::extract_ledger_op(&record).unwrap();
        state.mark_tombstoned(rec_id, "tomb", "test").unwrap();

        let before = state
            .pending_ledger_fallback_direct_apply_total
            .load(std::sync::atomic::Ordering::Relaxed);
        // First apply parks the op.
        super::apply_ledger_op_phase4(&state, &record, ch.clone(), parsed.clone()).await;
        assert!(
            state.pending_ledger.read().await.contains(rec_id),
            "first apply parks the tombstoned op"
        );
        // Second apply: the park insert is a DUPLICATE → rejected → direct-apply fallback.
        super::apply_ledger_op_phase4(&state, &record, ch, parsed).await;
        let after = state
            .pending_ledger_fallback_direct_apply_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "F2 R1: a tombstoned record whose park is REJECTED takes the direct-apply \
             fallback (not stranded) — the full-chain extraction closes the cap-rejected \
             fork-gap the review caught"
        );
    }

    #[tokio::test]
    async fn f2_psr1_gov_op_tombstone_sets_marker_beat_only_does_not() {
        // F2 PSR-1 CHANGE-3: tombstoning a GOVERNANCE-op record sets the durable
        // gov_rebuild_required marker (forces the next boot onto the full rebuild that
        // drops it from the out-of-seal tally, surviving the unconditional ledger
        // re-save that defeats delete_snapshot alone); a BEAT-only (mint/transfer)
        // tombstone must NOT set it (ledger ops apply unconditionally under R1 — a
        // forced O(all) rebuild there would be a pointless scale cost).
        let state = crate::network::state::build_test_node_state();
        assert!(!state.rocks.gov_rebuild_required(), "precondition: marker clear");

        let mut gov_meta = std::collections::BTreeMap::new();
        gov_meta.insert("governance_op".to_string(), serde_json::json!("propose"));
        store_ledger_record(
            &state, "psr1-gov-rec", b"gov-creator",
            crate::ZoneId::new("test/zone"), 1_800_000_200.0, gov_meta,
        );
        state.mark_tombstoned("psr1-gov-rec", "tomb", "gov takedown").unwrap();
        assert!(
            state.rocks.gov_rebuild_required(),
            "F2 PSR-1: tombstoning a GOVERNANCE-op record MUST set gov_rebuild_required"
        );
        state.rocks.clear_gov_rebuild_required();

        let alice = crate::crypto::hash::sha3_256_hex(b"alice-psr1");
        store_ledger_record(
            &state, "psr1-beat-rec", b"beat-creator",
            crate::ZoneId::new("test/zone"), 1_800_000_201.0,
            crate::accounting::types::mint_metadata(500, &alice, "test"),
        );
        state.mark_tombstoned("psr1-beat-rec", "tomb", "content takedown").unwrap();
        assert!(
            !state.rocks.gov_rebuild_required(),
            "F2 PSR-1 CHANGE-3: a BEAT-only tombstone must NOT set gov_rebuild_required"
        );
    }

    #[tokio::test]
    async fn f2_psr2_sibling_op_tombstone_suppressed_predicate() {
        // F2 PSR-2: the boot-rebuild suppression predicate. A tombstoned delegation/
        // dispute/challenge-op record is suppressed (converging rebuild with the live
        // ingest early-return); a non-tombstoned op record and any non-op record are not.
        let state = crate::network::state::build_test_node_state();

        let mut deleg_meta = std::collections::BTreeMap::new();
        deleg_meta.insert("delegation_op".to_string(), serde_json::json!("delegate"));
        store_ledger_record(
            &state, "psr2-deleg", b"dc",
            crate::ZoneId::new("test/zone"), 1_800_000_300.0, deleg_meta,
        );
        let rec = state.rocks.get_record("psr2-deleg").unwrap().unwrap();
        assert!(
            !state.sibling_op_tombstone_suppressed(&rec),
            "not tombstoned yet → not suppressed (rebuild applies it)"
        );
        state.mark_tombstoned("psr2-deleg", "tomb", "test").unwrap();
        assert!(
            state.sibling_op_tombstone_suppressed(&rec),
            "F2 PSR-2: a tombstoned delegation-op record MUST be suppressed on rebuild"
        );

        // A non-op record: even tombstoned, never sibling-suppressed (the sib_op
        // short-circuit means the is_tombstoned CF read is not even paid — the scale gate).
        let mut plain_meta = std::collections::BTreeMap::new();
        plain_meta.insert("note".to_string(), serde_json::json!("hi"));
        store_ledger_record(
            &state, "psr2-plain", b"pc",
            crate::ZoneId::new("test/zone"), 1_800_000_301.0, plain_meta,
        );
        state.mark_tombstoned("psr2-plain", "tomb", "test").unwrap();
        let plain = state.rocks.get_record("psr2-plain").unwrap().unwrap();
        assert!(
            !state.sibling_op_tombstone_suppressed(&plain),
            "a non-op record is never sibling-suppressed"
        );
    }

    #[test]
    fn resolve_seal_record_ids_increments_counters_per_outcome() {
        // Pin Protocol §11.12 observability: every entry in seal.record_hashes
        // (each a `record.record_hash()`, i.e. SHA3(signable_bytes)) must
        // increment exactly one of resolved/missing depending on whether
        // CF_IDX_RECORD_HASH has a local record for it.
        //
        // This is the regression alarm for the pre-v7 bug where the call
        // site probed CF_IDX_HASH (keyed on content_hash) — a hash with
        // a different domain — so every resolution missed regardless of
        // what records the node held. Migration v6→v7 added the right
        // index; this test pins the wiring.
        use std::sync::atomic::Ordering::Relaxed;

        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("counter/test");

        // Plant two real records. store_ledger_record returns the
        // record_hash() value — exactly what seal.record_hashes carries
        // in production.
        let (_creator_a, rh_a) = store_ledger_record(
            &state,
            "rec-counter-a",
            b"creator_a",
            zone.clone(),
            1.0,
            crate::accounting::types::transfer_metadata(
                1,
                &"aa".repeat(32),
                None,
            ),
        );
        let (_creator_b, rh_b) = store_ledger_record(
            &state,
            "rec-counter-b",
            b"creator_b",
            zone.clone(),
            2.0,
            crate::accounting::types::transfer_metadata(
                2,
                &"bb".repeat(32),
                None,
            ),
        );

        // A hash that resolves to no record — pure misses bucket.
        let miss_hash = [0xCDu8; 32];

        // Mixed input: 2 hits, 1 miss, 1 more hit (a repeats).
        let input = vec![rh_a, miss_hash, rh_b, rh_a];

        // Pre-state: both counters at zero.
        assert_eq!(state.seal_record_hashes_resolved_total.load(Relaxed), 0);
        assert_eq!(state.seal_record_hashes_missing_total.load(Relaxed), 0);

        let resolved_ids = resolve_seal_record_ids(&state, &input);

        // 3 of 4 hashes resolved; the order matches input order
        // (filter-style — misses are dropped, not gap-filled).
        assert_eq!(
            resolved_ids,
            vec![
                "rec-counter-a".to_string(),
                "rec-counter-b".to_string(),
                "rec-counter-a".to_string(),
            ],
        );

        assert_eq!(state.seal_record_hashes_resolved_total.load(Relaxed), 3);
        assert_eq!(state.seal_record_hashes_missing_total.load(Relaxed), 1);

        // Empty input: counters unchanged.
        let _ = resolve_seal_record_ids(&state, &[]);
        assert_eq!(state.seal_record_hashes_resolved_total.load(Relaxed), 3);
        assert_eq!(state.seal_record_hashes_missing_total.load(Relaxed), 1);

        // Pure-miss input: only `missing_total` advances.
        let _ = resolve_seal_record_ids(&state, &[[0xEEu8; 32], [0xFFu8; 32]]);
        assert_eq!(state.seal_record_hashes_resolved_total.load(Relaxed), 3);
        assert_eq!(state.seal_record_hashes_missing_total.load(Relaxed), 3);

        // Probing CF_IDX_HASH directly with the same record_hash MUST miss
        // — that's the bug we just fixed. content_hash and record_hash are
        // different domains; a record_hash collision against a content_hash
        // entry would only happen by accident at 2^-128 probability.
        let probe_hex = hex::encode(rh_a);
        assert!(
            state.rocks.record_id_by_hash(&probe_hex).is_none(),
            "record_hash MUST NOT resolve via the content_hash index — \
             that's the pre-v7 bug. Use record_id_by_record_hash."
        );
    }

    #[tokio::test]
    async fn flush_witness_smt_for_seal_advances_on_disk_root() {
        // Pin: when a witness ingests a Gap-1 seal, its on-disk SMT must
        // advance to reflect the accounts the seal's records touched.
        // Without this, /proof/account/{id} returns proofs whose root never
        // matches `latest_sealed_account.account_smt_root`, and light
        // clients reject the binding (cross-fleet probe at c3c8e45).
        //
        // Scope-bounded: seal.record_hashes points at real records; the
        // witness derives the touched-identity scope from those records and
        // flushes only those identities (not its full smt_dirty set).
        use crate::accounting::ledger::AccountState;

        let state = crate::network::state::build_test_node_state();

        // Three records — Mint, Transfer, Stake — each with its own creator.
        // Mint and Transfer are recipient-touching; Stake is creator-only.
        let alice_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..7].copy_from_slice(b"alice_r"); pk
        });
        let bob_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..5].copy_from_slice(b"bob_r"); pk
        });

        let zone = crate::ZoneId::new("test/zone");
        let (alice_creator, mint_hash) = store_ledger_record(
            &state,
            "rec-mint",
            b"alice_creator",
            zone.clone(),
            5.0,
            crate::accounting::types::mint_metadata(1_000, &alice_to, "test"),
        );
        let (bob_creator, transfer_hash) = store_ledger_record(
            &state,
            "rec-transfer",
            b"bob_creator",
            zone.clone(),
            10.0,
            crate::accounting::types::transfer_metadata(500, &bob_to, None),
        );
        let (carol_creator, stake_hash) = store_ledger_record(
            &state,
            "rec-stake",
            b"carol_creator",
            zone.clone(),
            15.0,
            crate::accounting::types::stake_metadata(100, &crate::accounting::types::StakePurpose::Witness),
        );

        // Seed ledger with all five identities (and one out-of-scope dave to
        // verify scope-bounding leaves him alone).
        let dave_hex = "dd".repeat(32);
        {
            let mut ledger = state.ledger.write().await;
            for (id, st) in [
                (&alice_creator, AccountState { available: 1_000, tx_count: 3, ..Default::default() }),
                (&alice_to, AccountState { available: 1_000, tx_count: 0, ..Default::default() }),
                (&bob_creator, AccountState { available: 42, tx_count: 1, ..Default::default() }),
                (&bob_to, AccountState { available: 42, tx_count: 0, ..Default::default() }),
                (&carol_creator, AccountState { available: 7, staked: 11, tx_count: 2, ..Default::default() }),
                (&dave_hex, AccountState { available: 99, tx_count: 1, ..Default::default() }),
            ] {
                ledger.accounts.insert(id.clone(), st);
                ledger.smt_dirty.insert(id.clone());
            }
        }

        // Pre-compute expected root using the SAME scope (5 in-seal identities;
        // dave is excluded).
        let dir = tempfile::tempdir().unwrap();
        let parallel =
            crate::storage::rocks::StorageEngine::open(dir.path().join("rocks")).unwrap();
        let mut ref_ledger = crate::accounting::ledger::LedgerState::new();
        let ledger_snap = state.ledger.read().await.accounts.clone();
        for id in [&alice_creator, &alice_to, &bob_creator, &bob_to, &carol_creator] {
            ref_ledger.accounts.insert(id.clone(), ledger_snap.get(id).cloned().unwrap_or_default());
            ref_ledger.smt_dirty.insert(id.clone());
        }
        let ref_snapshot = super::super::account_merkle::snapshot_dirty(&mut ref_ledger);
        let (_flushed, expected_root) =
            super::super::account_merkle::apply_snapshot(&parallel, &ref_snapshot).unwrap();

        // Pre-condition: on-disk root is empty.
        let pre = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();
        assert_ne!(pre, expected_root, "test setup: on-disk root must start empty");

        // Trigger the witness flush via the seal-ingest path helper.
        let seal = fake_seal_with_root(
            Some(expected_root),
            vec![mint_hash, transfer_hash, stake_hash],
        );
        super::flush_witness_smt_for_seal(&state, &seal).await;

        // Post-condition: on-disk SMT root now matches the seal's binding.
        let post = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();
        assert_eq!(post, expected_root, "witness on-disk root must match seal binding");

        // In-scope identities drained; out-of-scope `dave` retained for the
        // next seal that actually references him.
        let ledger = state.ledger.read().await;
        for id in [&alice_creator, &alice_to, &bob_creator, &bob_to, &carol_creator] {
            assert!(
                !ledger.smt_dirty.contains(id),
                "in-scope identity {id} must be drained from smt_dirty",
            );
        }
        assert!(
            ledger.smt_dirty.contains(&dave_hex),
            "out-of-scope identity must remain dirty for next seal scope",
        );
    }

    #[tokio::test]
    async fn flush_witness_smt_for_seal_pre_gap1_seal_with_empty_scope_is_noop() {
        // Pin: legacy seals (account_smt_root = None) on a witness whose
        // smt_dirty is empty AND whose seal references no records must
        // short-circuit before touching RocksDB. Wasted scheduler hops per
        // seal would sum to real CPU at 1M-zone scale.
        let state = crate::network::state::build_test_node_state();
        let pre = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();

        let seal = fake_seal_with_root(None, vec![]);
        super::flush_witness_smt_for_seal(&state, &seal).await;

        let post = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();
        assert_eq!(pre, post, "no-op flush must not change on-disk root");
    }

    #[tokio::test]
    async fn flush_witness_smt_for_seal_idempotent_on_repeat() {
        // Pin: invoking the witness flush twice in a row (same seal,
        // already-drained scope) is a no-op on the second call. The sealing
        // node ingests its own seal back through this same path after
        // `epoch_seal_loop` has already drained smt_dirty — that second-pass
        // invocation must not corrupt or re-write the SMT.
        use crate::accounting::ledger::AccountState;

        let state = crate::network::state::build_test_node_state();

        // Build one record + matching ledger state so the first flush has
        // something to drain.
        let alice_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..7].copy_from_slice(b"alice_r"); pk
        });
        let zone = crate::ZoneId::new("test/zone");
        let (alice_creator, mint_hash) = store_ledger_record(
            &state,
            "rec-mint",
            b"alice_creator",
            zone,
            10.0,
            crate::accounting::types::mint_metadata(100, &alice_to, "test"),
        );
        {
            let mut ledger = state.ledger.write().await;
            for id in [&alice_creator, &alice_to] {
                ledger.accounts.insert(
                    id.clone(),
                    AccountState { available: 100, tx_count: 1, ..Default::default() },
                );
                ledger.smt_dirty.insert(id.clone());
            }
        }

        // First pass: drains scope + writes SMT.
        let first_seal = fake_seal_with_root(None, vec![mint_hash]);
        super::flush_witness_smt_for_seal(&state, &first_seal).await;
        let first_root = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();
        let dirty_after_first = state.ledger.read().await.smt_dirty.len();

        // Second pass: scope identities already drained, account_smt_root None
        // → re-snapshots zero-changed accounts (idempotent), no root change.
        super::flush_witness_smt_for_seal(&state, &first_seal).await;
        let second_root = super::super::account_merkle::AccountStateSMT::new(&state.rocks)
            .root()
            .unwrap();
        assert_eq!(first_root, second_root, "repeat flush must not perturb root");
        let dirty_after_second = state.ledger.read().await.smt_dirty.len();
        assert_eq!(
            dirty_after_first, dirty_after_second,
            "repeat flush must not change dirty set",
        );
    }

    #[tokio::test]
    async fn compute_witness_smt_scope_skips_unknown_record_hashes() {
        // Records the witness has not yet received (record_id_by_hash
        // returns None) must be silently dropped from the scope rather
        // than poisoning the flush. Those identities will be picked up
        // on a later seal once the records propagate.
        let state = crate::network::state::build_test_node_state();
        let alice_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..7].copy_from_slice(b"alice_r"); pk
        });
        let zone = crate::ZoneId::new("test/zone");
        let (alice_creator, known_hash) = store_ledger_record(
            &state,
            "rec-known",
            b"alice_creator",
            zone,
            10.0,
            crate::accounting::types::transfer_metadata(50, &alice_to, None),
        );
        let unknown_hash: [u8; 32] = [0xFFu8; 32];

        let seal = fake_seal_with_root(None, vec![known_hash, unknown_hash]);
        let scope = super::compute_witness_smt_scope(&state, &seal);
        assert!(scope.contains(&alice_creator), "known record's creator must be in scope");
        assert!(scope.contains(&alice_to), "known record's recipient must be in scope");
        assert_eq!(scope.len(), 2, "unknown record hash must be silently skipped");
    }

    #[tokio::test]
    async fn compute_witness_smt_scope_unions_identities_across_records() {
        // Multi-record seal: scope is the union of every record's touched
        // identities. Duplicates collapse — one identity = one entry.
        let state = crate::network::state::build_test_node_state();

        let shared_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..6].copy_from_slice(b"shared"); pk
        });
        let zone = crate::ZoneId::new("test/zone");
        let (alice_creator, h1) = store_ledger_record(
            &state,
            "rec-1",
            b"alice_creator",
            zone.clone(),
            8.0,
            crate::accounting::types::transfer_metadata(10, &shared_to, None),
        );
        let (bob_creator, h2) = store_ledger_record(
            &state,
            "rec-2",
            b"bob_creator",
            zone,
            12.0,
            crate::accounting::types::transfer_metadata(20, &shared_to, None),
        );

        let seal = fake_seal_with_root(None, vec![h1, h2]);
        let scope = super::compute_witness_smt_scope(&state, &seal);
        // {alice_creator, bob_creator, shared_to} — three distinct entries
        // even though shared_to appears in both records.
        assert!(scope.contains(&alice_creator));
        assert!(scope.contains(&bob_creator));
        assert!(scope.contains(&shared_to));
        assert_eq!(scope.len(), 3, "duplicate identities must collapse in the scope set");
    }

    #[tokio::test]
    async fn compute_witness_smt_scope_increments_incomplete_counter_on_missing_record() {
        // Observability pin: when the witness has NOT received every record a
        // seal references, the scope build matches fewer than target_count and
        // `witness_smt_scope_incomplete_total` advances — the load-bearing
        // signal that a witness's account-root mismatch is propagation lag, not
        // a fault. The complementary complete case must leave the counter flat.
        use std::sync::atomic::Ordering;
        let state = crate::network::state::build_test_node_state();
        let alice_to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952]; pk[..7].copy_from_slice(b"alice_r"); pk
        });
        let zone = crate::ZoneId::new("test/zone");
        let (_creator, known_hash) = store_ledger_record(
            &state,
            "rec-known",
            b"alice_creator",
            zone,
            10.0,
            crate::accounting::types::transfer_metadata(50, &alice_to, None),
        );
        let unknown_hash: [u8; 32] = [0xFFu8; 32];

        // Incomplete: seal references one record the witness lacks -> +1.
        assert_eq!(state.witness_smt_scope_incomplete_total.load(Ordering::Relaxed), 0);
        let incomplete_seal = fake_seal_with_root(None, vec![known_hash, unknown_hash]);
        super::compute_witness_smt_scope(&state, &incomplete_seal);
        assert_eq!(
            state.witness_smt_scope_incomplete_total.load(Ordering::Relaxed), 1,
            "missing seal-referenced record must increment the incomplete counter",
        );

        // Complete: seal references only the record the witness has -> flat.
        let complete_seal = fake_seal_with_root(None, vec![known_hash]);
        super::compute_witness_smt_scope(&state, &complete_seal);
        assert_eq!(
            state.witness_smt_scope_incomplete_total.load(Ordering::Relaxed), 1,
            "a fully-matched scope must NOT increment the incomplete counter",
        );

        // Empty-record-hash seal short-circuits before the match loop -> flat.
        let empty_seal = fake_seal_with_root(None, vec![]);
        super::compute_witness_smt_scope(&state, &empty_seal);
        assert_eq!(
            state.witness_smt_scope_incomplete_total.load(Ordering::Relaxed), 1,
            "empty record_hashes must short-circuit before the incomplete check",
        );
    }

    // ─── disk-pressure ingest gate ─────────────────────────────────────────
    // Pin: when state.disk_pressure=1, insert_record_inner_direct rejects
    // ALL ingest sources (RPC, gossip pull, gossip push, sync) before any
    // expensive validation work, and the rejection counter advances. An
    // earlier version checked the flag only on `/records` POST; gossip wrote
    // through the gate and ate the last GB of disk.

    #[tokio::test]
    async fn ops157_disk_pressure_blocks_new_record_ingest() {
        use std::sync::atomic::Ordering;

        let state = crate::network::state::build_test_node_state();
        // Ingest gates check disk_avail_pressure (real disk-full
        // safety). Cap-pressure is operator policy and no longer rejects
        // ingest. Tests preserved for the avail path; cap-only behavior is
        // covered by the cap-pressure cases below.
        state.disk_avail_pressure.store(true, Ordering::Relaxed);

        let record = crate::record::ValidationRecord::create(
            b"ops157_payload",
            vec![0u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let before = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);

        let result = super::insert_record_inner_direct(&state, record, None, false).await;
        assert!(result.is_err(), "insert must fail under disk pressure");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("disk pressure"),
            "error must cite disk pressure (got: {})", msg
        );
        let after = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);
        assert_eq!(after, before + 1, "rejection counter must advance exactly once");
    }

    #[tokio::test]
    async fn emergency_halt_gate_blocks_nonauthority_admits_sync() {
        use crate::emergency::EmergencyState;
        use std::sync::atomic::Ordering;

        let state = crate::network::state::build_test_node_state();
        // Activate a halt directly in the atomics with a far-future expiry so the
        // gate is within-window deterministically (independent of wall-clock).
        state.emergency_load_state(&EmergencyState {
            latest_halt_nonce: 1,
            latest_resume_nonce: 0,
            active_expiry_unix: u64::MAX,
            active_reason: "test halt".into(),
        });
        assert!(state.emergency_halted_now(super::now() as u64));

        // A NEW non-authority write (skip_timestamp_defense=false) is refused at the
        // halt gate with a retryable error.
        let rec = crate::record::ValidationRecord::create(
            b"halt_gate_payload",
            vec![7u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let before = state.emergency_rejected_ingest_total.load(Ordering::Relaxed);
        let result = super::insert_record_inner_direct(&state, rec, None, false).await;
        assert!(result.is_err(), "non-authority write must be refused while halted");
        assert!(matches!(result.unwrap_err(), crate::errors::ElaraError::RateLimited));
        assert_eq!(
            state.emergency_rejected_ingest_total.load(Ordering::Relaxed),
            before + 1,
            "halt-rejection counter advances exactly once"
        );

        // A SYNCED record (skip_timestamp_defense=true) is admitted PAST the halt
        // gate (it may fail downstream, but never at the halt gate → counter flat).
        let rec2 = crate::record::ValidationRecord::create(
            b"sync_payload",
            vec![9u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let before2 = state.emergency_rejected_ingest_total.load(Ordering::Relaxed);
        let _ = super::insert_record_inner_direct(&state, rec2, None, true).await;
        assert_eq!(
            state.emergency_rejected_ingest_total.load(Ordering::Relaxed),
            before2,
            "synced records bypass the halt gate (carve-out)"
        );

        // Resume (nonce 1 >= 1) lifts the halt.
        state.emergency_load_state(&EmergencyState {
            latest_halt_nonce: 1,
            latest_resume_nonce: 1,
            active_expiry_unix: u64::MAX,
            active_reason: String::new(),
        });
        assert!(
            !state.emergency_halted_now(super::now() as u64),
            "resume (1 > 1 is false) un-halts"
        );
    }

    #[tokio::test]
    async fn emergency_fold_halt_bounds_future_dated_issued_ts() {
        // Node-layer regression for the continuity-backstop bypass: folding an authority
        // halt whose issued_ts is 10y in the future must NOT freeze ingest for a decade.
        // emergency_fold_halt stores the BOUNDED expiry (~now + MAX_HALT_DURATION_SECS),
        // so the gate self-clears at the 30d backstop instead of the issuer-anchored 10y.
        use crate::emergency::{EmergencyHalt, EMERGENCY_FORMAT_VERSION, MAX_HALT_DURATION_SECS};

        let state = crate::network::state::build_test_node_state();
        let now = super::now() as u64;
        let ten_years = 10 * 365 * 24 * 3600u64;
        let h = EmergencyHalt {
            version: EMERGENCY_FORMAT_VERSION,
            network_id: state.config.network_id.clone(),
            nonce: 1,
            issued_ts: now + ten_years, // far-future issuer timestamp (the attack)
            max_duration_secs: 3600,
            reason: "future-dated".into(),
        };
        assert!(state.emergency_fold_halt(&h), "halt wins the nonce race + persists");
        assert!(state.emergency_halted_now(now), "gate closed right now");
        // Self-clears at the ~30d backstop (+10s slack for a second-boundary race),
        // NOT 10y out as the unbounded issuer expiry would dictate.
        assert!(
            !state.emergency_halted_now(now + MAX_HALT_DURATION_SECS + 10),
            "gate must self-clear at the 30d backstop, not in 10y"
        );
        let stored = state.emergency_snapshot_state().active_expiry_unix;
        assert!(
            stored < now + ten_years,
            "stored expiry must be bounded far below the 10y issuer-anchored value (got {stored})"
        );
    }

    #[tokio::test]
    async fn ops157_dedup_still_acks_during_disk_pressure() {
        // Already-stored records short-circuit at the dedup check, which fires
        // BEFORE the disk_pressure gate. A peer re-pushing a record we already
        // hold must still ack — it allocates no disk and pinning the gate
        // above dedup would force the peer into endless retry.
        use std::sync::atomic::Ordering;

        let state = crate::network::state::build_test_node_state();

        let record = crate::record::ValidationRecord::create(
            b"ops157_dedup_payload",
            vec![0u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        // Seed the storage layer directly to simulate a record that's already
        // on disk, then trip disk_pressure and re-submit. The dedup branch
        // must short-circuit on `record_exists` and return Ok before the
        // disk_pressure gate is reached, so the rejection counter stays flat.
        state.rocks.put_record(&record.id, &record).expect("seed record");
        // Ingest gates check disk_avail_pressure (real disk-full
        // safety). Cap-pressure is operator policy and no longer rejects
        // ingest. Tests preserved for the avail path; cap-only behavior is
        // covered by the cap-pressure cases below.
        state.disk_avail_pressure.store(true, Ordering::Relaxed);

        let before = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);
        let result = super::insert_record_inner_direct(&state, record.clone(), None, false).await;
        assert!(result.is_ok(), "dedup must short-circuit before disk_pressure gate");
        assert_eq!(result.unwrap(), record.id);
        let after = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);
        assert_eq!(after, before, "dedup path must NOT bump the rejection counter");
    }

    #[tokio::test]
    async fn ops157_disk_pressure_clears_when_flag_drops() {
        // After the operator frees space, disk_pressure_loop flips the flag
        // back to false. The gate must self-clear immediately on the next
        // ingest — no daemon restart required. We can't easily run the full
        // happy-path through validation here, but we can pin that flipping
        // the flag back removes the disk-pressure-specific error path.
        use std::sync::atomic::Ordering;

        let state = crate::network::state::build_test_node_state();
        // Ingest gates check disk_avail_pressure (real disk-full
        // safety). Cap-pressure is operator policy and no longer rejects
        // ingest. Tests preserved for the avail path; cap-only behavior is
        // covered by the cap-pressure cases below.
        state.disk_avail_pressure.store(true, Ordering::Relaxed);

        let record = crate::record::ValidationRecord::create(
            b"ops157_clears_payload",
            vec![0u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );

        let pressed = super::insert_record_inner_direct(&state, record.clone(), None, false).await;
        let pressed_msg = format!("{:?}", pressed.unwrap_err());
        assert!(pressed_msg.contains("disk pressure"));

        state.disk_avail_pressure.store(false, Ordering::Relaxed);
        let cleared = super::insert_record_inner_direct(&state, record, None, false).await;
        // The record will fail later validation (no real signature), but the
        // failure must NOT be a disk-pressure error any more.
        if let Err(e) = cleared {
            let cleared_msg = format!("{:?}", e);
            assert!(
                !cleared_msg.contains("disk pressure"),
                "post-clear error must not cite disk pressure (got: {})", cleared_msg
            );
        }
        // Counter only advanced once (during the pressure hit, not after).
        assert_eq!(state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed), 1);
    }

    /// Cap-based pressure (live > 95% × disk_cap_bytes) is operator
    /// policy and must NOT reject ingest. This test pins that behavior so a
    /// future "let's reuse `disk_pressure` again" edit can't reintroduce the
    /// earlier fleet trap, where cap-pressure on small VPS volumes
    /// silently 429'd legitimate writes despite the FS still having
    /// headroom.
    #[tokio::test]
    async fn ops169_cap_pressure_does_not_reject_ingest() {
        use std::sync::atomic::Ordering;

        let state = crate::network::state::build_test_node_state();
        // Cap-pressure on, avail-pressure off. The combined back-compat
        // `disk_pressure` is true, but the avail-only ingest gate must let
        // the record through (it'll fail later validation; that's fine —
        // the assertion is that the failure path is NOT the disk-pressure
        // counter).
        state.disk_cap_pressure.store(true, Ordering::Relaxed);
        state.disk_pressure.store(true, Ordering::Relaxed);
        assert!(state.under_disk_pressure(), "combined flag set");
        assert!(state.under_cap_pressure(), "cap flag set");
        assert!(!state.under_avail_pressure(), "avail flag NOT set");

        let record = crate::record::ValidationRecord::create(
            b"ops169_cap_only_payload",
            vec![0u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let before = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);
        let result = super::insert_record_inner_direct(&state, record, None, false).await;
        // Whatever the outcome, it must not be a disk-pressure rejection.
        if let Err(e) = result {
            let msg = format!("{:?}", e);
            assert!(
                !msg.contains("disk pressure"),
                "cap-only pressure must not cite disk pressure (got: {})", msg
            );
        }
        let after = state.disk_pressure_rejected_ingest_total.load(Ordering::Relaxed);
        assert_eq!(
            after, before,
            "cap-only pressure must NOT advance disk_pressure_rejected_ingest_total"
        );
    }

    // ─── ingest signature gate: accept valid, reject tampered (audit 16b) ───
    // The Dilithium3 accept/reject gate (~ingest.rs:770) had ZERO integration
    // coverage — none of the ingest tests signed a real record, so "a forged
    // record is rejected" was proven nowhere. This pins BOTH branches with two
    // two fresh records, EACH FROM ITS OWN IDENTITY (the creator+nonce slot
    // mutex precedes the signature gate, so a shared identity would slot-reject
    // the second record before its signature is ever checked): a validly-signed
    // record clears the gate (never InvalidSignature), and one whose signature
    // has a single flipped byte is rejected with InvalidSignature.
    #[tokio::test]
    async fn ingest_accepts_valid_signature_rejects_tampered() {
        use crate::errors::ElaraError;
        let gen = || {
            crate::identity::Identity::generate(
                crate::identity::EntityType::Device,
                crate::identity::CryptoProfile::ProfileB,
            )
            .unwrap()
        };
        let state = crate::network::state::build_test_node_state();

        // Accept branch — a real Dilithium3 signature must clear the gate. It
        // may still fail a LATER gate (stake, zone) in this minimal test state,
        // but it must never be rejected as InvalidSignature.
        let id_a = gen();
        let mut good = crate::record::ValidationRecord::create(
            b"ingest_sig_gate_valid",
            id_a.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        id_a.sign_record(&mut good).unwrap();
        assert!(good.signature.is_some(), "record must carry a signature");
        let accepted = super::insert_record_inner_direct(&state, good, None, false).await;
        assert!(
            !matches!(accepted, Err(ElaraError::InvalidSignature)),
            "validly-signed record must clear the signature gate (got: {:?})",
            accepted
        );

        // Reject branch — distinct identity (free slot), flip one signature byte.
        let id_b = gen();
        let mut bad = crate::record::ValidationRecord::create(
            b"ingest_sig_gate_tampered",
            id_b.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        id_b.sign_record(&mut bad).unwrap();
        bad.signature.as_mut().unwrap()[0] ^= 0x01;
        let rejected = super::insert_record_inner_direct(&state, bad, None, false).await;
        assert!(
            matches!(rejected, Err(ElaraError::InvalidSignature)),
            "one-byte-tampered signature must be rejected as InvalidSignature (got: {:?})",
            rejected
        );
    }

    // ─── pre-flip audit 2026-06-22: ingest must NOT mutate signed bytes ─────
    // A wire record carrying a sandbox zone (`record.zone`, decoded from v3+ wire
    // bytes, intentionally NOT in signable_bytes) used to get a wall-clock `expires`
    // injected into its metadata at ingest. Because metadata IS covered by
    // signable_bytes → record_hash → the per-zone epoch-seal Merkle root, that
    // post-signature mutation forked the seal across nodes (each stamps its own
    // clock for the same wire record) and invalidated the creator's signature for
    // any later re-verifier (sync re-check / fisherman audit / light-client proof).
    // This pins the invariant: ingest leaves a sandbox record's metadata,
    // record_hash, and signature byte-identical to what the creator signed.
    #[tokio::test]
    async fn ingest_does_not_mutate_sandbox_record_metadata() {
        let id = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let state = crate::network::state::build_test_node_state();

        let mut rec = crate::record::ValidationRecord::create(
            b"sandbox_no_mutate_payload",
            id.public_key.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        // Attacker-style: a sandbox zone arrives on the wire. `zone` is excluded
        // from signable_bytes, so the signature stays valid regardless of its value.
        rec.zone = Some(crate::ZoneId::sandbox("audit/no-mutate"));
        assert!(rec.zone.as_ref().unwrap().is_sandbox(), "precondition: sandbox zone");
        assert!(
            !rec.metadata.contains_key("expires"),
            "precondition: creator set no expires"
        );
        id.sign_record(&mut rec).unwrap();

        let hash_before = rec.record_hash();
        let meta_before = rec.metadata.clone();
        let rec_id = rec.id.clone();

        let res = super::insert_record_inner_direct(&state, rec, None, false).await;
        assert!(
            res.is_ok(),
            "validly-signed public sandbox record must ingest (got: {:?})",
            res
        );

        let stored = state
            .rocks
            .get_record(&rec_id)
            .expect("storage read ok")
            .expect("record must be persisted");

        assert!(
            !stored.metadata.contains_key("expires"),
            "ingest must NOT inject `expires` into a sandbox record's metadata \
             (consensus-fork + signature-invalidation vector — pre-flip audit 2026-06-22)"
        );
        assert_eq!(
            stored.metadata, meta_before,
            "metadata must be byte-identical to the signed form"
        );
        assert_eq!(
            stored.record_hash(),
            hash_before,
            "record_hash must be stable through ingest — it feeds the epoch-seal Merkle root"
        );
        let sig = stored.signature.as_ref().expect("signature present");
        assert!(
            crate::identity::Identity::verify(
                &stored.signable_bytes(),
                sig,
                &stored.creator_public_key
            )
            .unwrap_or(false),
            "stored record's signature must still verify — ingest left signed bytes intact"
        );
    }

    // ─── SeenSet / PropagationLimiter / MAX_RECORD_BYTES edge-case tests ────
    //
    // The existing tests cover the happy-path semantics
    // of SeenSet (basic insert+eviction), PropagationLimiter (basic + window
    // expiry + disabled + cleanup + sybil + exhaustion), and MAX_RECORD_BYTES
    // alone. The three tests below pin:
    //   1. SeenSet::remove — the retry-allowance contract from initial sync.
    //   2. PropagationLimiter::check_and_record_scaled — stake-weighted
    //      per-identity effective_limit (the API used by the live limiter).
    //   3. The four constants whose drift would silently break wire format,
    //      and the docstring-asserted cross-constraint that
    //      MAX_METADATA_VALUE_LEN >= Dilithium3-VRF hex budget (~6600 B).

    #[test]
    fn batch_ad_seen_set_remove_allows_retry_during_initial_sync() {
        // Pins the L165 contract: `remove()` clears an id from the set so
        // a subsequent `insert(same_id)` returns Ok(true) (i.e. is treated
        // as newly seen, not deduped). Used during initial sync when a
        // record arrives, fails validation, and the sync loop wants to
        // accept the retry. A future refactor that conflated `remove` with
        // a no-op or kept the entry in `set` would silently break sync.
        let mut s = SeenSet::new(8);
        assert!(s.insert("rec-a".into()));
        assert!(!s.insert("rec-a".into()), "duplicate insert must dedup");
        assert!(s.contains("rec-a"));
        s.remove("rec-a");
        assert!(!s.contains("rec-a"), "remove must clear set membership");
        assert!(
            s.insert("rec-a".into()),
            "after remove, the same id must re-insert as newly-seen — \
             otherwise retry during initial sync would silently dedupe"
        );

        // Removing an id that was never inserted is a no-op (idempotent).
        s.remove("never-inserted");
        assert!(!s.contains("never-inserted"));
    }

    #[test]
    fn batch_ad_propagation_limiter_scaled_respects_per_identity_effective_limit() {
        // Pins the L205 stake-weighted API: the `effective_limit` argument
        // overrides the base `self.limit` for a single check call. This is
        // the path used by the live pipeline — base rate + stake bonus per
        // identity. A future refactor that ignored the parameter and used
        // `self.limit` would silently rate-limit staked identities at the
        // base rate, defeating the economic incentive.
        let mut limiter = PropagationLimiter::new(2);
        let t = 5000.0;
        // base limit=2, but this identity has effective_limit=5 (stake bonus)
        for i in 0..5 {
            assert!(
                limiter.check_and_record_scaled("staker", t + i as f64, 5),
                "staker with effective_limit=5 must allow record {i}"
            );
        }
        // 6th request rejected — effective_limit is the binding ceiling.
        assert!(!limiter.check_and_record_scaled("staker", t + 5.0, 5));

        // effective_limit=0 path is the disabled sentinel — allow unconditionally
        // regardless of base `self.limit`. Confirms parity with the base
        // `check_and_record` disabled path (already tested at L3451).
        let mut limiter2 = PropagationLimiter::new(1);
        for i in 0..50 {
            assert!(
                limiter2.check_and_record_scaled("anyone", t + i as f64, 0),
                "effective_limit=0 must allow unconditionally (disabled sentinel)"
            );
        }
    }

    #[test]
    fn batch_ad_metadata_and_drift_constants_pin_protocol_documented_values() {
        // Pin the four constants that operator runbooks + wire-format docs
        // depend on. Drift here is a silent wire-compat break — a record
        // that was valid yesterday rejects today.
        assert_eq!(
            MAX_METADATA_ENTRIES, 64,
            "MAX_METADATA_ENTRIES drift breaks the per-record metadata cap \
             baked into validate_record_metadata (24→64 Decision A; v0.1.0 one-way door)"
        );
        assert_eq!(
            MAX_METADATA_VALUE_LEN, 8_192,
            "MAX_METADATA_VALUE_LEN drift breaks metadata-value gates"
        );
        assert_eq!(
            MAX_PARENTS, 256,
            "MAX_PARENTS drift breaks parent-set validation"
        );
        // f64 equality on a literal is safe — the constant is defined as
        // `300.0`, not derived from arithmetic; this is a wire pin.
        assert_eq!(
            MAX_FUTURE_DRIFT_SECS, 300.0,
            "MAX_FUTURE_DRIFT_SECS drift breaks the 5-minute future-clock \
             tolerance baked into timestamp validation"
        );
        assert!(
            MAX_FUTURE_DRIFT_SECS.is_finite() && MAX_FUTURE_DRIFT_SECS > 0.0,
            "MAX_FUTURE_DRIFT_SECS must be finite-positive"
        );

        // Cross-constant invariants between MAX_METADATA_VALUE_LEN and
        // the Dilithium3-VRF / Dilithium3-pubkey hex budgets are pinned at compile
        // time via the `const _: () = assert!(..)` block next to
        // MAX_METADATA_VALUE_LEN (ingest.rs ~L283). The local
        // DILITHIUM3_VRF_HEX_BUDGET and DILITHIUM3_PK_HEX_BUDGET consts moved
        // to module scope alongside the assertions. A regression now
        // fails at `cargo build`, not at `cargo test`. Runtime asserts
        // removed (clippy::assertions_on_constants — both operands
        // const-eval).
    }

    /// Pin `SeenSet::new` extreme-capacity behavior (ingest.rs:114-127). The
    /// constructor uses `HashSet::with_capacity(capacity.min(1024))` to bound
    /// the pre-allocation memory regardless of how huge `capacity` is, while
    /// storing the original `capacity` for eviction. This is a SCALE-RULE
    /// invariant: a 10K-node fleet with many SeenSet instances must not
    /// blow memory if any one caller passes a huge capacity hint. Pin both
    /// extremes: (a) `new(usize::MAX)` doesn't panic and starts empty (the
    /// `.min(1024)` clamp is what keeps that safe — a regression dropping
    /// the clamp would attempt an impossible HashSet pre-alloc); (b) the
    /// eviction policy at L150-153 is keyed on the ORIGINAL `capacity`, not
    /// the clamped pre-alloc — so `new(0)` collapses to single-slot LRU
    /// (zero-cap means every insert evicts the prior, leaving exactly one
    /// entry — the freshest).
    #[test]
    fn batch_ae_seen_set_new_with_extreme_capacities_does_not_panic_and_preserves_eviction_semantics() {
        // (a) usize::MAX must not panic — the .min(1024) pre-alloc clamp
        //     is the only thing keeping this from attempting an impossible
        //     HashSet allocation.
        let huge = super::SeenSet::new(usize::MAX);
        assert!(huge.is_empty(), "fresh SeenSet must be empty");
        assert_eq!(huge.len(), 0, "fresh SeenSet len() must be 0");

        // (b) capacity=0 → single-slot LRU. Eviction at L150 fires on every
        //     insert (set.len() >= 0 is always true). The first insert can't
        //     evict (order is empty), so set ends with 1 entry. The second
        //     insert evicts the first then inserts the second — final state
        //     is len=1, contains only the most recent.
        let mut zero = super::SeenSet::new(0);
        assert_eq!(zero.len(), 0);
        assert!(zero.insert("first".into()));
        assert_eq!(zero.len(), 1, "first insert at cap=0 retains one slot");
        assert!(zero.contains("first"));
        assert!(zero.insert("second".into()));
        assert_eq!(
            zero.len(), 1,
            "second insert at cap=0 evicts the prior and retains only the freshest"
        );
        assert!(
            !zero.contains("first"),
            "the prior entry must have been evicted at cap=0"
        );
        assert!(zero.contains("second"), "the freshest entry must be retained");
    }

    /// Pin `PropagationLimiter::new` window duration (ingest.rs:186-192) at
    /// exactly 3600.0 seconds (1 hour) per Protocol v0.6.2 §11.19. The field
    /// is private so this test pins the *behavior* rather than reading the
    /// constant directly: at limit=1, a record at t=0 must still be in-window
    /// at t=3599.999 (rate-limit hits) but pruned at t=3600.001 (rate-limit
    /// releases). This bracket-test pins the exact 3600-second boundary —
    /// a future-self changing the window to e.g. 1800s (30min, the audit-
    /// 2026-04-30 suggestion that was rejected) would fail this test.
    #[test]
    fn batch_ae_propagation_limiter_window_secs_pinned_at_one_hour_per_protocol_section_11_19() {
        let mut limiter = super::PropagationLimiter::new(1);
        // First record at t=0 — accepted.
        assert!(
            limiter.check_and_record("identity-a", 0.0),
            "first record must be accepted by a fresh limiter"
        );
        // At t=3599.999 (epsilon inside the 1-hour window from t=0):
        // cutoff = 3599.999 - 3600.0 = -0.001, so t=0 is NOT pruned (0 < -0.001 is false).
        // Bucket has 1 entry, limit is 1 → REJECT.
        assert!(
            !limiter.check_and_record("identity-a", 3599.999),
            "record at t=3599.999 must hit rate-limit — t=0 still in 3600s window"
        );
        // At t=3601.0 (epsilon outside the window): cutoff = 1.0,
        // t=0 < 1.0 is TRUE → pruned. Bucket empty, limit 1 → ACCEPT.
        assert!(
            limiter.check_and_record("identity-a", 3601.0),
            "record at t=3601.0 must be accepted — t=0 has aged out of 3600s window"
        );
    }

    /// Pin `PropagationLimiter::tracked_identities` (ingest.rs:228-231) — the
    /// observability getter operator dashboards read for sybil-detection. Pins
    /// three invariants: (a) fresh limiter reports 0, (b) two records from the
    /// SAME identity report 1 (entry deduplication by identity-hash key), and
    /// (c) records from DIFFERENT identities increment the count linearly. A
    /// regression that key'd the HashMap on record-id instead of identity-hash
    /// would fail (c)→pass-too-large or (b)→pass-instead-of-1.
    #[test]
    fn batch_ae_propagation_limiter_tracked_identities_returns_zero_post_new_then_increments_per_distinct() {
        let mut limiter = super::PropagationLimiter::new(100);
        assert_eq!(
            limiter.tracked_identities(), 0,
            "fresh limiter must report 0 tracked identities"
        );
        // Two records from the same identity — count stays at 1.
        assert!(limiter.check_and_record("alice", 0.0));
        assert_eq!(
            limiter.tracked_identities(), 1,
            "first record from a new identity must bump count to 1"
        );
        assert!(limiter.check_and_record("alice", 10.0));
        assert_eq!(
            limiter.tracked_identities(), 1,
            "second record from SAME identity must NOT bump count — \
             keying must be by identity-hash, not record"
        );
        // Distinct identity — count increments.
        assert!(limiter.check_and_record("bob", 20.0));
        assert_eq!(
            limiter.tracked_identities(), 2,
            "first record from a distinct identity must bump count to 2"
        );
        // Third distinct.
        assert!(limiter.check_and_record("carol", 30.0));
        assert_eq!(limiter.tracked_identities(), 3);
    }

    /// Pin `now()` (ingest.rs:253-258) contract that every hot-path timestamp
    /// in the ingress pipeline depends on. Three invariants:
    /// (a) returns a finite-positive f64 — the `unwrap_or(0.0)` fallback would
    ///     fail this in the impossible "pre-1970 system clock" branch, but in
    ///     practice this pins that the SystemTime path is reached and produces
    ///     a real timestamp,
    /// (b) the unit is **seconds** (not milliseconds) — Protocol §11.19 rate-
    ///     limiter math, `MAX_FUTURE_DRIFT_SECS=300.0` drift gate, and the
    ///     1-hour propagation window all assume `now()` returns seconds. A
    ///     regression to `as_millis()` would silently widen every gate by 1000×,
    ///     breaking ingress validation,
    /// (c) sub-second precision is preserved — the f64 fractional component
    ///     must be non-zero across two successive calls separated by a short
    ///     sleep (would fail if a refactor coerced to `as u64` and lost the
    ///     fractional part, which the limiter's prune predicate `t < cutoff`
    ///     relies on for boundary-correctness).
    #[test]
    fn batch_ag_now_returns_finite_positive_unix_seconds_with_subsecond_precision() {
        let t1 = super::now();

        // (a) finite-positive
        assert!(t1.is_finite(), "now() must return a finite f64");
        assert!(t1 > 0.0, "now() must return a positive Unix timestamp");

        // (b) seconds, not millis: the 2026-01-01 floor is 1_735_689_600 seconds
        //     and a billion-record/sec future cap is ~10^10 seconds (~year 2286).
        //     If `now()` ever switches to millis, the value would be ~1.7e12 —
        //     outside this band by 3 orders of magnitude.
        const UNIX_2026_01_01: f64 = 1_735_689_600.0;
        const UNIX_YEAR_2286_FLOOR: f64 = 10_000_000_000.0; // 10^10 s
        assert!(
            t1 >= UNIX_2026_01_01,
            "now()={t1} must be ≥ 2026-01-01 ({UNIX_2026_01_01}) — clock skew or refactor"
        );
        assert!(
            t1 < UNIX_YEAR_2286_FLOOR,
            "now()={t1} must be < 10^10 seconds — value above suggests a \
             silent switch to milliseconds, which would break every \
             timestamp gate in the ingress pipeline"
        );

        // (c) sub-second precision: between two calls the value must have
        //     advanced strictly forward (wall-clock monotonicity is NOT
        //     guaranteed at the SystemTime level, but on a non-pathological
        //     test runner two back-to-back calls measure forward progress).
        //     A regression to `as u64` would make this assertion sometimes
        //     pass spuriously when the call falls within the same integer
        //     second; we use a sleep to make the assertion deterministic.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let t2 = super::now();
        assert!(
            t2 > t1,
            "now() second call (t2={t2}) must be strictly later than first \
             (t1={t1}) after a 1ms sleep — would fail if precision was \
             coerced to whole seconds"
        );
        assert!(
            (t2 - t1) < 1.0,
            "now() advance over 1ms sleep ({}s) must be < 1s — a larger \
             jump suggests a unit mismatch (e.g. ms-as-seconds)",
            t2 - t1
        );
    }

    /// Pin `SeenSet::clear` (ingest.rs:140-143) idempotency on the bootstrap-
    /// retry path. The genesis-restart loop in `state.rs` calls `clear` then
    /// `insert` to re-seed the dedup set after a node restart. Two regressions
    /// would silently break this:
    /// (a) a defensive `assert!(!self.set.is_empty())` inside `clear` would
    ///     panic on the second consecutive call — the test fires `clear`
    ///     three times in a row including once on a fresh empty set, and
    ///     pins that no panic occurs and `len == 0` is preserved;
    /// (b) a regression that forgot to clear `order` (the FIFO queue) would
    ///     leak stale entries that influence eviction on the next `insert`.
    ///     This test inserts → clears → re-inserts beyond capacity and
    ///     verifies the eviction order reflects the FRESH inserts only.
    #[test]
    fn batch_ag_seen_set_clear_is_idempotent_across_repeated_calls() {
        // (a) Triple-clear on a fresh empty set — must not panic.
        let mut s = super::SeenSet::new(3);
        s.clear();
        s.clear();
        s.clear();
        assert!(s.is_empty(), "triple-clear on fresh set must leave empty");
        assert_eq!(s.len(), 0, "triple-clear must keep len at 0");

        // (b) Insert past cap, clear, re-insert past cap — eviction must reflect
        //     the FRESH order, not the stale pre-clear order.
        s.insert("stale-a".into());
        s.insert("stale-b".into());
        s.insert("stale-c".into());
        assert_eq!(s.len(), 3);
        s.clear();
        assert_eq!(s.len(), 0, "clear after fills must drop everything");

        // Fresh inserts; the FIFO queue must NOT retain stale eviction order.
        s.insert("fresh-x".into());
        s.insert("fresh-y".into());
        s.insert("fresh-z".into());
        // Overflow: if `order` wasn't cleared, the next insert would attempt
        // to evict "stale-a" (which is no longer in `set`), then add. Either
        // way the user-visible state must be the freshest 3 keys.
        s.insert("fresh-w".into());
        assert_eq!(s.len(), 3, "post-clear FIFO must still cap at 3");
        assert!(!s.contains("fresh-x"), "oldest fresh entry must be evicted");
        assert!(s.contains("fresh-y"));
        assert!(s.contains("fresh-z"));
        assert!(s.contains("fresh-w"));
    }

    /// Pin `PropagationLimiter::cleanup` (ingest.rs:234-239) defensive
    /// behavior on a fresh limiter with zero tracked identities. The periodic
    /// cleanup loop in `state.rs` calls this on a fixed timer regardless of
    /// whether any records have arrived yet — boot-time calls hit a limiter
    /// where `self.windows` is empty. A regression to e.g.
    /// `self.windows.values().next().unwrap()` would panic on this path;
    /// `HashMap::retain` on an empty map is intrinsically safe but the test
    /// nails the contract so a refactor can't accidentally introduce a
    /// panic. Also pins idempotency: three successive cleanups on the empty
    /// limiter all leave tracked_identities at 0.
    #[test]
    fn batch_ag_propagation_limiter_cleanup_on_fresh_limiter_is_safe_no_op() {
        let mut limiter = super::PropagationLimiter::new(5);
        assert_eq!(limiter.tracked_identities(), 0, "fresh limiter starts empty");

        // Three back-to-back cleanups on the empty limiter — must not panic.
        // Three distinct `now` values exercise the f64 cutoff arithmetic
        // (each `cutoff = now - 3600` produces a different value) so a
        // regression that mishandled a NaN/Inf-producing arithmetic path
        // would surface here too.
        limiter.cleanup(0.0);
        limiter.cleanup(1_700_000_000.0);
        limiter.cleanup(f64::MAX / 2.0);

        assert_eq!(
            limiter.tracked_identities(), 0,
            "cleanup on a fresh empty limiter must not invent entries"
        );

        // Sanity: limiter is still functional post-cleanup-spam.
        assert!(
            limiter.check_and_record("alice", 1_700_000_000.0),
            "fresh limiter post-cleanup must accept first record"
        );
        assert_eq!(limiter.tracked_identities(), 1);
    }

    /// Pin `PropagationLimiter::cleanup` idempotency on a stable populated
    /// state — three successive calls with the SAME `now` value (or values
    /// that don't cross any record's TTL) must leave `tracked_identities`
    /// unchanged. Guards against a refactor that turned `retain` into a
    /// destructive partition operation that consumed entries across calls.
    /// Distinct from `test_propagation_limiter_cleanup` (single call) and
    /// `test_propagation_limiter_cleanup_retains_active` (single call across
    /// the cutoff boundary).
    #[test]
    fn batch_ag_propagation_limiter_cleanup_is_idempotent_when_nothing_expired() {
        let mut limiter = super::PropagationLimiter::new(10);

        // Three identities, all timestamped at t=1000.0.
        limiter.check_and_record("alice", 1000.0);
        limiter.check_and_record("bob", 1000.0);
        limiter.check_and_record("carol", 1000.0);
        assert_eq!(limiter.tracked_identities(), 3);

        // Cleanup at t=1500.0: cutoff=1500-3600=-2100, all timestamps
        // (1000.0) are ≥ -2100 → none expire. Call three times.
        for i in 0..3 {
            limiter.cleanup(1500.0);
            assert_eq!(
                limiter.tracked_identities(), 3,
                "cleanup pass {i} below TTL boundary must retain all 3 \
                 identities — idempotency regression would drop entries"
            );
        }

        // Each identity must still have its bucket entry (limit=10, so
        // a second record is accepted without rate-limit).
        for id in ["alice", "bob", "carol"] {
            assert!(
                limiter.check_and_record(id, 1500.0),
                "identity {id} must still be tracked post-3x cleanup"
            );
        }
    }

    /// Pin `PropagationLimiter::cleanup` retention predicate (ingest.rs:236-
    /// 238) which uses `timestamps.back()` — the **most recent** record per
    /// identity — to decide whether the bucket survives. An identity whose
    /// bucket holds `[old, fresh]` where `old < cutoff < fresh` must be
    /// retained. A regression that swapped `.back()` for `.front()` would
    /// silently drop active identities whose first record was stale, even
    /// though they have recent activity — directly hostile to bursty real
    /// traffic where a account's first record this hour is followed by an
    /// hour of regular activity.
    #[test]
    fn batch_ag_propagation_limiter_cleanup_uses_back_timestamp_not_front_for_retention() {
        let mut limiter = super::PropagationLimiter::new(10);

        // Identity "burst" has two records: one stale (t=1000), one fresh (t=5000).
        // Bucket order is FIFO insertion: [1000.0, 5000.0]. front=1000, back=5000.
        limiter.check_and_record("burst", 1000.0);
        limiter.check_and_record("burst", 5000.0);

        // Identity "all-stale" has two records both old.
        limiter.check_and_record("all-stale", 1000.0);
        limiter.check_and_record("all-stale", 1100.0);

        assert_eq!(limiter.tracked_identities(), 2);

        // Cleanup at t=5200: cutoff=5200-3600=1600.
        //   burst.back() = 5000.0  → 5000 ≥ 1600 → RETAIN
        //   all-stale.back() = 1100.0 → 1100 < 1600 → DROP
        // If the predicate used .front() instead, burst.front()=1000 < 1600
        // would (wrongly) DROP burst — that's the regression class this
        // test pins against.
        limiter.cleanup(5200.0);

        assert_eq!(
            limiter.tracked_identities(), 1,
            "exactly one identity should survive — burst (recent back-ts) \
             retained, all-stale (back-ts < cutoff) dropped"
        );

        // The surviving identity must be `burst` — confirm via the side-effect
        // of re-recording. Post-cleanup burst.bucket=[1000.0, 5000.0]; the
        // first new check_and_record at t=5300 prunes the 1000 entry inside
        // `check_and_record_scaled` (cutoff=5300-3600=1700, 1000<1700), so
        // the bucket effectively starts new probes at len=1 (just [5000]).
        // To pin "burst was retained and the 5000 entry survived", we fill
        // the bucket exactly to limit=10 and then verify the +1th rejects.
        // 9 successful inserts at t=5300..5308 take the bucket from
        // [5000] → [5000, 5300, ..., 5308] = 10 entries.
        for i in 0..9u32 {
            assert!(
                limiter.check_and_record("burst", 5300.0 + i as f64),
                "burst (presumed surviving) must accept up to 9 more records \
                 — got rejected at i={i}, suggesting wrong identity survived"
            );
        }
        // 10th post-cleanup record for burst: bucket already at limit=10
        // (5000 + nine 5300..5308 entries), reject.
        assert!(
            !limiter.check_and_record("burst", 5320.0),
            "burst's 10th post-cleanup record at limit=10 must be rate-limited \
             — confirms cleanup did NOT silently drop burst (which would \
             reset the count to 0) and that the 5000.0 entry was preserved"
        );
    }

    // ─── compute_witness_smt_scope edge cases ────────────
    // Pins five distinct decision points in `compute_witness_smt_scope` that
    // existing tests only cover transitively: empty-record-hashes early-exit,
    // zone-key gate, temporal window bounds, record-hash filter under a window
    // hit, and the `zone: None` fallback path inside `record_zone_key`.
    // Plus one all-miss pin on `resolve_seal_record_ids`. Each test owns its
    // setup so a single regression does not chain across the slice.

    fn fake_seal_full(
        zone: crate::ZoneId,
        start: f64,
        end: f64,
        record_hashes: Vec<[u8; 32]>,
    ) -> super::super::epoch::ParsedEpochSeal {
        super::super::epoch::ParsedEpochSeal {
            zone,
            epoch_number: 1,
            start,
            end,
            record_count: record_hashes.len() as u64,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    /// R3-8 slice 4 — derive-when-absent (`epoch::derive_seal_enumeration`).
    /// Three phases in ONE test so the process-global derive counters are
    /// read without cross-test races: (1) DAG-complete window derives the
    /// exact sorted enumeration; (2) incomplete window (missing sealed
    /// record) → None + miss counter; (3) record_count==0 → None with no
    /// counter movement (no scan fires). Uses seal_zone_count=Some(1) so
    /// `for_record_dynamic` maps every record id to legacy zone 0 — the
    /// scan's zone-membership filter.
    #[test]
    fn derive_seal_enumeration_complete_incomplete_and_empty_windows() {
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::from_legacy(0);

        // Phase 1: complete window.
        let mut hashes = Vec::new();
        for (i, id) in ["rec-derive-a", "rec-derive-b", "rec-derive-c"].iter().enumerate() {
            let (_ident, rh) = store_ledger_record(
                &state,
                id,
                id.as_bytes(),
                zone.clone(),
                1.0 + i as f64,
                crate::accounting::types::transfer_metadata(i as u64 + 1, &"aa".repeat(32), None),
            );
            hashes.push(rh);
        }
        hashes.sort();
        let root = crate::network::sync::MerkleTree::root(&hashes);

        let mut seal = fake_seal_full(zone.clone(), 0.5, 4.5, vec![]);
        seal.record_count = 3;
        seal.merkle_root = root;
        seal.seal_zone_count = Some(1);

        let (derived_before, miss_before) = super::super::epoch::seal_enum_derive_metrics();
        let derived = match super::super::epoch::derive_seal_enumeration(&*state.rocks, &seal) {
            Some(super::super::epoch::DeriveOutcome::Derived(d)) => d,
            other => panic!("complete window must derive, got {other:?}"),
        };
        assert_eq!(derived, hashes, "derived enumeration = sorted window set");
        let (derived_after, miss_after) = super::super::epoch::seal_enum_derive_metrics();
        assert!(derived_after > derived_before, "derived counter must increment");
        assert_eq!(miss_after, miss_before, "no miss on complete window");

        // Phase 2: incomplete window — producer sealed a record we don't hold.
        // The outcome carries the local window count (1 record in [0.5, 1.5])
        // for the P3 count-degrade.
        let mut sealed = vec![hashes[0], [0x5Au8; 32]];
        sealed.sort();
        let mut incomplete = fake_seal_full(zone.clone(), 0.5, 1.5, vec![]);
        incomplete.record_count = 2;
        incomplete.merkle_root = crate::network::sync::MerkleTree::root(&sealed);
        incomplete.seal_zone_count = Some(1);
        assert_eq!(
            super::super::epoch::derive_seal_enumeration(&*state.rocks, &incomplete),
            Some(super::super::epoch::DeriveOutcome::Incomplete { local_window_count: 1 }),
            "incomplete window must report Incomplete with the local count"
        );
        let (_, miss_now) = super::super::epoch::seal_enum_derive_metrics();
        assert!(miss_now > miss_after, "miss counter must increment");

        // Phase 3: record_count == 0 → None before any scan.
        let mut empty_seal = fake_seal_full(zone, 0.5, 2.5, vec![]);
        empty_seal.record_count = 0;
        empty_seal.seal_zone_count = Some(1);
        let before = super::super::epoch::seal_enum_derive_metrics();
        assert!(
            super::super::epoch::derive_seal_enumeration(&*state.rocks, &empty_seal).is_none(),
            "record_count=0 has nothing to derive"
        );
        assert_eq!(
            super::super::epoch::seal_enum_derive_metrics(),
            before,
            "empty seal must not move derive counters (no scan)"
        );
    }

    #[tokio::test]
    async fn batch_k_compute_witness_smt_scope_empty_record_hashes_short_circuits() {
        // Early-return: when seal.record_hashes is empty, the function
        // must return before iter_zone fires. The alternative (a 100K-record
        // bounded scan per empty seal) is a per-seal CPU regression at 1M-zone
        // scale. Plant a real record so iter_zone WOULD yield work if called;
        // the test pins that the scope stays empty regardless.
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("test/zone");
        let to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952];
            pk[..6].copy_from_slice(b"target");
            pk
        });
        let _ = store_ledger_record(
            &state,
            "rec-empty-seal-bait",
            b"creator_empty",
            zone.clone(),
            5.0,
            crate::accounting::types::transfer_metadata(1, &to, None),
        );

        let seal = fake_seal_with_root(None, vec![]);
        let scope = super::compute_witness_smt_scope(&state, &seal);

        assert!(
            scope.is_empty(),
            "empty record_hashes must yield empty scope — bait record's identities must NOT leak in"
        );
    }

    #[tokio::test]
    async fn batch_k_compute_witness_smt_scope_excludes_records_in_different_zone() {
        // Pin the zone-key gate inside iter_zone. A seal binds a specific zone;
        // records stored under a DIFFERENT zone must not contribute identities
        // even if their record_hash is listed in seal.record_hashes. Without
        // this gate a cross-zone hash collision (or a misrouted record) would
        // pollute a witness's account-SMT scope on the wrong shard.
        let state = crate::network::state::build_test_node_state();
        let zone_a = crate::ZoneId::new("zone/A");
        let zone_b = crate::ZoneId::new("zone/B");

        let to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952];
            pk[..3].copy_from_slice(b"zb1");
            pk
        });
        let (_creator_b, hash_in_b) = store_ledger_record(
            &state,
            "rec-in-zone-b",
            b"creator_in_b",
            zone_b,
            5.0,
            crate::accounting::types::transfer_metadata(7, &to, None),
        );

        // Seal binds zone A; references the hash of the record stored in zone B.
        let seal = fake_seal_full(zone_a, 0.0, 30.0, vec![hash_in_b]);
        let scope = super::compute_witness_smt_scope(&state, &seal);

        assert!(
            scope.is_empty(),
            "record stored in zone B must NOT appear in zone-A scope — iter_zone's zone-key prefix gate must exclude it"
        );
    }

    #[tokio::test]
    async fn batch_k_compute_witness_smt_scope_excludes_records_outside_time_window() {
        // Pin the temporal window: iter_zone's `since`/`until` bounds must
        // exclude records whose timestamp falls outside [seal.start, seal.end].
        // Without this a late-arriving record in the same zone could leak into
        // an earlier seal's witness scope and force the SMT into a divergent
        // root. Three records: below start, inside, above end.
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("test/window");

        let mk_to = |seed: &[u8]| {
            crate::crypto::hash::sha3_256_hex(&{
                let mut pk = vec![0u8; 1952];
                pk[..seed.len().min(1952)].copy_from_slice(&seed[..seed.len().min(1952)]);
                pk
            })
        };
        let to_before = mk_to(b"to_before");
        let to_inside = mk_to(b"to_inside");
        let to_after = mk_to(b"to_after");

        let (creator_before, hash_before) = store_ledger_record(
            &state,
            "rec-before",
            b"creator_before",
            zone.clone(),
            2.0, // below seal.start=10.0
            crate::accounting::types::transfer_metadata(1, &to_before, None),
        );
        let (creator_inside, hash_inside) = store_ledger_record(
            &state,
            "rec-inside",
            b"creator_inside",
            zone.clone(),
            15.0, // inside [10.0, 20.0]
            crate::accounting::types::transfer_metadata(2, &to_inside, None),
        );
        let (creator_after, hash_after) = store_ledger_record(
            &state,
            "rec-after",
            b"creator_after",
            zone.clone(),
            25.0, // above seal.end=20.0
            crate::accounting::types::transfer_metadata(3, &to_after, None),
        );

        let seal = fake_seal_full(zone, 10.0, 20.0, vec![hash_before, hash_inside, hash_after]);
        let scope = super::compute_witness_smt_scope(&state, &seal);

        assert!(scope.contains(&creator_inside), "in-window record's creator must be in scope");
        assert!(scope.contains(&to_inside), "in-window record's recipient must be in scope");
        assert!(!scope.contains(&creator_before), "pre-window record must be excluded");
        assert!(!scope.contains(&to_before), "pre-window record's recipient must be excluded");
        assert!(!scope.contains(&creator_after), "post-window record must be excluded");
        assert!(!scope.contains(&to_after), "post-window record's recipient must be excluded");
        assert_eq!(scope.len(), 2, "only the in-window record contributes (creator + recipient)");
    }

    #[tokio::test]
    async fn batch_k_compute_witness_smt_scope_record_hash_filter_excludes_unrelated_in_window() {
        // Pin the `targets.contains(&rec.record_hash())` filter at line 3391:
        // iter_zone returns ALL records in the (zone, time) window, but only
        // those whose record_hash is in `seal.record_hashes` contribute. A
        // sibling record in the same zone+window with an unrelated hash must
        // not leak its identities into the scope. Without this filter the
        // witness flush would over-snapshot at every seal.
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("test/filter");

        let mk_to = |seed: &[u8]| {
            crate::crypto::hash::sha3_256_hex(&{
                let mut pk = vec![0u8; 1952];
                pk[..seed.len().min(1952)].copy_from_slice(&seed[..seed.len().min(1952)]);
                pk
            })
        };
        let to_in_seal = mk_to(b"in_seal");
        let to_sibling = mk_to(b"sibling");

        let (creator_in_seal, hash_in_seal) = store_ledger_record(
            &state,
            "rec-in-seal",
            b"creator_in_seal",
            zone.clone(),
            5.0,
            crate::accounting::types::transfer_metadata(1, &to_in_seal, None),
        );
        let (creator_sibling, _hash_sibling_unused) = store_ledger_record(
            &state,
            "rec-sibling",
            b"creator_sibling",
            zone.clone(),
            6.0, // same window, but its hash isn't in the seal
            crate::accounting::types::transfer_metadata(2, &to_sibling, None),
        );

        // Seal references ONLY the first record's hash.
        let seal = fake_seal_full(zone, 0.0, 30.0, vec![hash_in_seal]);
        let scope = super::compute_witness_smt_scope(&state, &seal);

        assert!(scope.contains(&creator_in_seal), "seal-referenced creator must be in scope");
        assert!(scope.contains(&to_in_seal), "seal-referenced recipient must be in scope");
        assert!(!scope.contains(&creator_sibling), "sibling record's creator must NOT be in scope");
        assert!(!scope.contains(&to_sibling), "sibling record's recipient must NOT be in scope");
        assert_eq!(scope.len(), 2, "only the seal-referenced record contributes");
    }

    #[tokio::test]
    async fn batch_k_compute_witness_smt_scope_uses_fallback_zone_when_record_zone_unset() {
        // Pin `Storage::record_zone_key` fallback at rocks.rs:741 — when a
        // record carries `zone: None` (legacy / sync-replayed records before
        // the explicit zone field landed), iter_zone keys it under
        // `ZoneId::for_record(record_id)`, the content-defined 256-zone hash.
        // A seal bound to that derived zone must still see the record's
        // identities; otherwise legacy chains stop converging the SMT root.
        let state = crate::network::state::build_test_node_state();

        let to = crate::crypto::hash::sha3_256_hex(&{
            let mut pk = vec![0u8; 1952];
            pk[..6].copy_from_slice(b"legacy");
            pk
        });
        let mut creator_pk = vec![0u8; 1952];
        creator_pk[..15].copy_from_slice(b"legacy_creator_");
        let creator_id = crate::crypto::hash::sha3_256_hex(&creator_pk);

        let record_id = "rec-legacy-no-zone";
        let metadata = crate::accounting::types::transfer_metadata(9, &to, None);
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(record_id.as_bytes());
        hash_input.extend_from_slice(&serde_json::to_vec(&metadata).unwrap_or_default());
        let content_hash = crate::crypto::hash::sha3_256(&hash_input);

        let record = crate::record::ValidationRecord {
            id: record_id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: content_hash.to_vec(),
            creator_public_key: creator_pk,
            timestamp: 5.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None, // the load-bearing detail
            identity_hash_wire: None,
            nonce: 0,
        };
        let record_hash = record.record_hash();
        state.rocks.put_record(record_id, &record).unwrap();

        // Derived fallback zone — must match `record_zone_key` for zone=None.
        let fallback_zone = crate::ZoneId::for_record(record_id);
        let seal = fake_seal_full(fallback_zone, 0.0, 30.0, vec![record_hash]);
        let scope = super::compute_witness_smt_scope(&state, &seal);

        assert!(
            scope.contains(&creator_id),
            "fallback-zoned record's creator must be in scope when seal binds the derived zone"
        );
        assert!(
            scope.contains(&to),
            "fallback-zoned record's recipient must be in scope when seal binds the derived zone"
        );
        assert_eq!(scope.len(), 2, "creator + recipient for the single transfer");
    }

    #[test]
    fn batch_k_resolve_seal_record_ids_pure_miss_returns_empty_vec_and_advances_only_missing_counter() {
        // Pin the all-miss branch as a standalone assertion. The compound test
        // `resolve_seal_record_ids_increments_counters_per_outcome` exercises
        // this path mid-sequence but discards the return value; the missing
        // counter delta is asserted only against a mixed-input baseline. A
        // dedicated pin matters because pre-v7 CF_IDX_RECORD_HASH was absent
        // and EVERY input was a miss — that's the exact regression signature
        // this test would catch in isolation.
        use std::sync::atomic::Ordering::Relaxed;

        let state = crate::network::state::build_test_node_state();

        assert_eq!(state.seal_record_hashes_resolved_total.load(Relaxed), 0);
        assert_eq!(state.seal_record_hashes_missing_total.load(Relaxed), 0);

        let inputs = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let resolved = super::resolve_seal_record_ids(&state, &inputs);

        assert!(resolved.is_empty(), "all-miss input must return an empty Vec");
        assert_eq!(
            state.seal_record_hashes_resolved_total.load(Relaxed),
            0,
            "resolved counter must stay at zero when every input misses"
        );
        assert_eq!(
            state.seal_record_hashes_missing_total.load(Relaxed),
            inputs.len() as u64,
            "missing counter must advance by exactly one per input"
        );
    }

    // ─── ingest constants + metadata-budget tests ────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_ingest_constants_strict_pin_and_metadata_value_len_geq_load_bearing_budgets() {
        assert_eq!(MAX_METADATA_ENTRIES, 64);
        assert_eq!(MAX_METADATA_VALUE_LEN, 8_192);
        assert_eq!(MAX_PARENTS, 256);
        assert_eq!(MAX_RECORD_BYTES, 65_536);
        assert_eq!(MAX_RECORD_BYTES, 64 * 1024);
        assert_eq!(MAX_FUTURE_DRIFT_SECS, 300.0);
        assert!(MAX_FUTURE_DRIFT_SECS.is_finite());
        assert_eq!(MAX_FUTURE_DRIFT_SECS as u64 % 60, 0);
        assert_eq!((MAX_FUTURE_DRIFT_SECS as u64) / 60, 5);
        // Compile-time-asserted ordering — verify at runtime too. The const _: () = assert!
        // checks lock the invariants, but a deliberate runtime check guards against
        // a future edit that shrinks the constant without re-running the compile-time gates.
        assert!(MAX_METADATA_VALUE_LEN >= 6_600, "must accommodate Dilithium3-VRF hex budget");
        assert!(MAX_METADATA_VALUE_LEN >= 3_904, "must accommodate Dilithium3 PK hex budget");
        // Sanity bounds — ceilings reasonable, not zero, not absurdly large
        assert!(MAX_METADATA_ENTRIES > 0 && MAX_METADATA_ENTRIES < 1_000);
        assert!(MAX_METADATA_VALUE_LEN > 0 && MAX_METADATA_VALUE_LEN < 1_000_000);
        assert!(MAX_PARENTS > 0 && MAX_PARENTS < 10_000);
    }

    #[test]
    fn batch_b_now_returns_finite_positive_in_plausible_real_time_band_and_monotone() {
        let t = super::now();
        assert!(t.is_finite(), "now() must be finite, got {t}");
        assert!(t > 0.0, "now() must be positive, got {t}");
        assert!(t > 1_735_689_600.0, "now()={t} predates 2025-01-01");
        assert!(t < 4_102_444_800.0, "now()={t} past 2100-01-01");
        // Sub-second precision — back-to-back calls should be monotone non-decreasing.
        let t2 = super::now();
        assert!(t2 >= t, "now() monotone non-decreasing across back-to-back calls: t={t}, t2={t2}");
    }

    #[test]
    fn batch_b_seen_set_capacity_strict_upper_bound_across_diverse_capacity_sizes() {
        for &cap in &[1usize, 2, 4, 8, 16, 32, 64, 128, 256] {
            let mut set = SeenSet::new(cap);
            // Insert 4× capacity distinct ids — len must clamp to cap exactly
            for i in 0..(cap * 4) {
                set.insert(format!("id_{i}"));
            }
            assert_eq!(set.len(), cap, "capacity={cap} expected len {cap} got {}", set.len());
            // The most-recent cap ids should still be present; earliest evicted
            for i in (cap * 4 - cap)..(cap * 4) {
                assert!(set.contains(&format!("id_{i}")), "cap={cap} missing recent id_{i}");
            }
            assert!(!set.contains("id_0"), "cap={cap} should have evicted id_0");
        }
    }

    #[test]
    fn batch_b_seen_set_insert_duplicate_returns_false_and_does_not_grow_len() {
        let mut set = SeenSet::new(16);
        assert!(set.insert("alpha".to_string()), "first insert returns true");
        assert_eq!(set.len(), 1);
        // 10 repeat inserts of the same id — all return false, len stays at 1
        for round in 0..10 {
            let result = set.insert("alpha".to_string());
            assert!(!result, "round {round}: duplicate insert must return false");
            assert_eq!(set.len(), 1, "round {round}: len must stay 1");
            assert!(set.contains("alpha"));
        }
        // Insert distinct id — returns true, len grows to 2
        assert!(set.insert("beta".to_string()));
        assert_eq!(set.len(), 2);
        // Repeat insert of beta is still false
        assert!(!set.insert("beta".to_string()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn batch_b_propagation_limiter_window_boundary_strict_less_than_cutoff_precision() {
        // window_secs = 3600. cutoff = timestamp - 3600. Entry at T_0 stays while
        // T_0 >= cutoff (i.e. T_q - T_0 <= 3600); pruned when T_0 < cutoff.
        // limit=1 isolates: one entry only, second check fails unless prior is pruned.
        let mut limiter = PropagationLimiter::new(1);
        let t0: f64 = 1_000_000.0;
        assert!(limiter.check_and_record("id", t0), "first record always allowed");
        // At exactly t0 + 3600.0: cutoff = t0, entry T_0 = t0 — NOT strictly < cutoff,
        // so entry stays counted, second record rejected.
        assert!(
            !limiter.check_and_record("id", t0 + 3600.0),
            "at exactly window boundary, prior entry must remain counted"
        );
        // At t0 + 3600.0 + tiny δ: cutoff = t0 + δ, entry T_0 = t0 < cutoff → pruned.
        // δ must be representable in f64 at magnitude ~1e6 — use 0.001 (1 ms).
        assert!(
            limiter.check_and_record("id", t0 + 3600.001),
            "past window boundary by 1ms, prior entry must be pruned"
        );
        // Limiter limit==0 → bypass always (idempotent over many checks)
        let mut bypass = PropagationLimiter::new(0);
        for i in 0..50 {
            assert!(bypass.check_and_record("any", t0 + i as f64), "limit=0 always allows iter {i}");
        }
    }

    #[test]
    fn pending_slash_fields_pin() {
        // Pins that PendingSlash carries exactly the fields consumed by fisherman_slash.
        // A compile error here means a field was added or removed without updating the caller.
        use crate::network::fisherman::ChallengeType;
        let s = PendingSlash {
            accused: "accused-id".into(),
            challenger: "challenger-id".into(),
            jury: vec!["juror-1".into(), "juror-2".into()],
            challenge_type: ChallengeType::DoubleSigning,
        };
        assert_eq!(s.accused, "accused-id");
        assert_eq!(s.challenger, "challenger-id");
        assert_eq!(s.jury.len(), 2);
        assert!(matches!(s.challenge_type, ChallengeType::DoubleSigning));
    }

    // ── Tier-1 DAG-completeness deficit tests (contract §4) ──────────

    /// Store a parseable epoch-seal record whose `record_hashes` are the
    /// given list. Returns the seal's record id.
    fn store_seal_record(
        state: &crate::network::state::NodeState,
        seal_id: &str,
        zone: &crate::ZoneId,
        epoch: u64,
        start: f64,
        record_hashes: &[[u8; 32]],
    ) -> String {
        // merkle_root must recompute from record_hashes: the R3-8 slice-2
        // parse-time root gate drops mismatched inline arrays to empty,
        // which would silently defeat every deficit assertion downstream.
        let merkle_root = crate::network::sync::MerkleTree::root(record_hashes);
        let metadata = crate::network::epoch::seal_metadata(
            crate::network::epoch::SealMetadataParams {
                zone: zone.clone(),
                epoch_number: epoch,
                start,
                end: start + 120.0,
                record_count: record_hashes.len() as u64,
                merkle_root: &merkle_root,
                previous_seal_hash: &[0x22u8; 32],
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: Some(record_hashes),
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            },
        );
        let record = crate::record::ValidationRecord {
            id: seal_id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0xABu8; 32],
            creator_public_key: b"seal-creator".to_vec(),
            timestamp: start + 120.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: Some(zone.clone()),
            identity_hash_wire: None,
            nonce: 0,
        };
        state.rocks.put_record(seal_id, &record).unwrap();
        seal_id.to_string()
    }

    #[test]
    fn dag_deficit_ring_lifecycle_and_bounds() {
        use crate::network::state::{DagDeficitEntry, DagDeficitRing};
        let entry = |missing: u64, start: f64| DagDeficitEntry {
            missing,
            seal_start: start,
            seal_record_id: format!("seal-{start}"),
            first_seen_unix: 1,
        };

        let mut ring = DagDeficitRing::new(2);
        assert!(ring.is_empty());
        assert_eq!(ring.earliest_start(), None);
        assert_eq!(ring.next_for_recheck(), None);

        // New key → true; re-observe same key → false, missing refreshed.
        assert!(ring.observe(("z".into(), 5), entry(3, 500.0)));
        assert!(!ring.observe(("z".into(), 5), entry(2, 500.0)));
        assert_eq!(ring.len(), 1);

        // Second key; earliest_start picks the min seal_start.
        assert!(ring.observe(("z".into(), 4), entry(1, 400.0)));
        assert_eq!(ring.earliest_start(), Some(400.0));

        // Capacity 2: a third key evicts the OLDEST-observed (epoch 5).
        assert!(ring.observe(("z".into(), 6), entry(9, 600.0)));
        assert_eq!(ring.len(), 2);
        assert!(!ring.resolve(&("z".into(), 5)), "epoch 5 must be evicted");
        assert_eq!(ring.earliest_start(), Some(400.0));

        // update_missing touches only live keys (no panic on dead ones).
        ring.update_missing(&("z".into(), 4), 7);
        ring.update_missing(&("z".into(), 5), 7);

        // resolve → true once, false after.
        assert!(ring.resolve(&("z".into(), 4)));
        assert!(!ring.resolve(&("z".into(), 4)));
        assert_eq!(ring.len(), 1);

        // next_for_recheck skips the stale order entries of resolved keys
        // and round-robins the live one.
        let picked = ring.next_for_recheck().expect("one live entry");
        assert_eq!(picked.0, ("z".into(), 6));
        assert_eq!(picked.1, "seal-600");
        let picked_again = ring.next_for_recheck().expect("round-robin");
        assert_eq!(picked_again.0, ("z".into(), 6));
    }

    #[test]
    fn record_seal_deficit_opens_updates_and_ignores_complete() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("deficit/test");

        let seal_id = store_seal_record(
            &state,
            "seal-deficit-1",
            &zone,
            10,
            1_000.0,
            &[[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]],
        );
        let seal = crate::network::epoch::extract_epoch_seal(
            &state.rocks.get_record(&seal_id).unwrap().unwrap(),
        )
        .unwrap()
        .unwrap();

        // All resolved → no deficit.
        record_seal_deficit(&state, &seal, &seal_id, 3, None);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 0);

        // 1 of 3 resolved → deficit of 2 opens.
        record_seal_deficit(&state, &seal, &seal_id, 1, None);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 1);
        {
            let ring = state.dag_deficit_open.lock().unwrap();
            assert_eq!(ring.len(), 1);
            assert_eq!(ring.earliest_start(), Some(1_000.0));
        }

        // Same (zone, epoch) again → counter unchanged (refresh, not reopen).
        record_seal_deficit(&state, &seal, &seal_id, 2, None);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 1);

        // Legacy seal (empty record_hashes, no window count) → never a deficit.
        let mut legacy = seal.clone();
        legacy.record_hashes = Vec::new();
        legacy.epoch_number = 11;
        record_seal_deficit(&state, &legacy, "seal-legacy", 0, None);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 1);

        // R3-8 slice 5: empty enumeration WITH a derive-miss window count →
        // count-degrade deficit (record_count − local) opens.
        let mut degraded = seal.clone();
        degraded.record_hashes = Vec::new();
        degraded.record_count = 3;
        degraded.epoch_number = 12;
        record_seal_deficit(&state, &degraded, "seal-degraded", 0, Some(1));
        assert_eq!(
            state.dag_deficit_epochs_total.load(Relaxed),
            2,
            "count-degrade (3 sealed − 1 local = 2 missing) must open a deficit"
        );

        // Count-degrade with a COMPLETE local window (local >= sealed) → no
        // deficit (saturating_sub → 0).
        let mut complete = seal.clone();
        complete.record_hashes = Vec::new();
        complete.record_count = 3;
        complete.epoch_number = 13;
        record_seal_deficit(&state, &complete, "seal-complete", 0, Some(3));
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 2);
    }

    #[test]
    fn recheck_dag_deficits_closes_pruned_seal() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();

        // Deficit whose seal record does NOT exist locally (pruned below the
        // super-seal floor): the re-check must close it — those records are
        // unprovable AND unpullable by design (contract §2).
        {
            let mut ring = state.dag_deficit_open.lock().unwrap();
            ring.observe(
                ("gone".into(), 3),
                crate::network::state::DagDeficitEntry {
                    missing: 5,
                    seal_start: 100.0,
                    seal_record_id: "seal-that-was-pruned".into(),
                    first_seen_unix: 1,
                },
            );
        }
        let open = recheck_dag_deficits(&state, DAG_DEFICIT_RECHECKS_PER_CYCLE);
        assert_eq!(open, 0);
        assert_eq!(state.dag_deficit_resolved_total.load(Relaxed), 1);
    }

    #[test]
    fn recheck_dag_deficits_updates_then_closes_when_records_arrive() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("deficit/heal");

        // One record present, one referenced-but-absent.
        let (_id_a, rh_a) = store_ledger_record(
            &state,
            "rec-heal-a",
            b"creator_a",
            zone.clone(),
            2_000.5,
            crate::accounting::types::transfer_metadata(1, &"aa".repeat(32), None),
        );
        // Build (but do NOT store yet) the record whose hash the seal names.
        let pending = crate::record::ValidationRecord {
            id: "rec-heal-b".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0xBBu8; 32],
            creator_public_key: b"creator_b".to_vec(),
            timestamp: 2_000.7,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: crate::accounting::types::transfer_metadata(2, &"bb".repeat(32), None),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: Some(zone.clone()),
            identity_hash_wire: None,
            nonce: 0,
        };
        let rh_b = pending.record_hash();

        let seal_id = store_seal_record(
            &state,
            "seal-heal-1",
            &zone,
            20,
            2_000.0,
            &[rh_a, rh_b],
        );
        let seal = crate::network::epoch::extract_epoch_seal(
            &state.rocks.get_record(&seal_id).unwrap().unwrap(),
        )
        .unwrap()
        .unwrap();
        record_seal_deficit(&state, &seal, &seal_id, 1, None);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 1);

        // Re-check while still missing → stays open, missing updated to 1.
        let open = recheck_dag_deficits(&state, DAG_DEFICIT_RECHECKS_PER_CYCLE);
        assert_eq!(open, 1);
        assert_eq!(state.dag_deficit_resolved_total.load(Relaxed), 0);

        // The named record arrives (e.g. via escalated full_pull) → the next
        // re-check closes the deficit.
        state.rocks.put_record("rec-heal-b", &pending).unwrap();
        let open = recheck_dag_deficits(&state, DAG_DEFICIT_RECHECKS_PER_CYCLE);
        assert_eq!(open, 0);
        assert_eq!(state.dag_deficit_resolved_total.load(Relaxed), 1);
        assert_eq!(
            state.dag_deficit_epochs_total.load(Relaxed),
            1,
            "close must not re-open"
        );
    }

    /// R3-8 slice 5 — the false-close regression. A deficit opened for an
    /// above-cap seal (empty inline enumeration, signed record_count > 0)
    /// must NOT be closed by recheck_dag_deficits counting misses over the
    /// empty array (the pre-fix behavior healed it instantly); it must
    /// re-derive, keep the deficit open at the count-degrade size, and close
    /// only when the window actually completes.
    #[test]
    fn recheck_dag_deficits_rederives_instead_of_false_closing_on_empty_enum() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::from_legacy(0);

        // Two records held locally, a third built but NOT stored yet.
        let (_ia, rh_a) = store_ledger_record(
            &state, "rec-fc-a", b"fc_a", zone.clone(), 10.5,
            crate::accounting::types::transfer_metadata(1, &"aa".repeat(32), None),
        );
        let (_ib, rh_b) = store_ledger_record(
            &state, "rec-fc-b", b"fc_b", zone.clone(), 11.0,
            crate::accounting::types::transfer_metadata(2, &"bb".repeat(32), None),
        );
        let pending = crate::record::ValidationRecord {
            id: "rec-fc-c".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0xCCu8; 32],
            creator_public_key: b"fc_c".to_vec(),
            timestamp: 11.5,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: crate::accounting::types::transfer_metadata(3, &"cc".repeat(32), None),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: Some(zone.clone()),
            identity_hash_wire: None,
            nonce: 0,
        };
        let rh_c = pending.record_hash();

        // Producer sealed all three; the inline enumeration was OMITTED
        // (bounded emission). Metadata is hand-built so epoch_zone_count=1 is
        // pinned — the derive scan's for_record_dynamic filter then maps every
        // record id to legacy zone 0 regardless of the process-global count.
        let mut sealed = vec![rh_a, rh_b, rh_c];
        sealed.sort();
        let root = crate::network::sync::MerkleTree::root(&sealed);
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("epoch_op".to_string(), serde_json::json!("seal"));
        meta.insert("epoch_zone".to_string(), serde_json::json!(0));
        meta.insert("epoch_number".to_string(), serde_json::json!(40));
        meta.insert("epoch_start".to_string(), serde_json::json!(10.0));
        meta.insert("epoch_end".to_string(), serde_json::json!(12.0));
        meta.insert("epoch_record_count".to_string(), serde_json::json!(3));
        meta.insert(
            "epoch_merkle_root".to_string(),
            serde_json::json!(hex::encode(root)),
        );
        meta.insert(
            "epoch_previous_seal".to_string(),
            serde_json::json!(hex::encode([0u8; 32])),
        );
        meta.insert("epoch_zone_count".to_string(), serde_json::json!(1));
        let seal_rec = crate::record::ValidationRecord {
            id: "seal-fc-1".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0xABu8; 32],
            creator_public_key: b"fc-sealer".to_vec(),
            timestamp: 12.5,
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
            zone: Some(zone.clone()),
            identity_hash_wire: None,
            nonce: 0,
        };
        state.rocks.put_record("seal-fc-1", &seal_rec).unwrap();
        let seal = crate::network::epoch::extract_epoch_seal(&seal_rec)
            .unwrap()
            .unwrap();
        assert!(seal.record_hashes.is_empty(), "premise: no inline enumeration");
        assert_eq!(seal.record_count, 3);

        // Ingest-pass deficit capture (count-degrade): local window = 2 of 3.
        record_seal_deficit(&state, &seal, "seal-fc-1", 0, Some(2));
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 1, "deficit opened");

        // THE REGRESSION: pre-fix recheck counted misses over the EMPTY array
        // → 0 missing → closed as healed while a sealed record was absent.
        // Post-fix it re-derives, the root mismatches (window incomplete),
        // and the deficit STAYS OPEN at the count-degrade size.
        let open = recheck_dag_deficits(&state, DAG_DEFICIT_RECHECKS_PER_CYCLE);
        assert_eq!(open, 1, "must NOT false-close while the window is incomplete");
        assert_eq!(state.dag_deficit_resolved_total.load(Relaxed), 0);

        // The missing record arrives (full_pull) → re-derive succeeds (root
        // match proves every sealed record is local) → deficit closes.
        state.rocks.put_record("rec-fc-c", &pending).unwrap();
        let open = recheck_dag_deficits(&state, DAG_DEFICIT_RECHECKS_PER_CYCLE);
        assert_eq!(open, 0, "derive success = healed");
        assert_eq!(state.dag_deficit_resolved_total.load(Relaxed), 1);
    }

    /// R3-8 slice 6 — synthetic above-cap integration. The REAL producer
    /// emission path (`seal_metadata`) omits the inline enumeration above
    /// SEAL_INLINE_ENUM_MAX, and the consumer chain — derive → P2
    /// resolve → P3 deficit → P4 witness scope — recovers the full set
    /// from local storage over real RocksDB.
    #[test]
    fn synthetic_above_cap_seal_derives_and_feeds_consumers() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::from_legacy(0);
        let n = crate::network::epoch::SEAL_INLINE_ENUM_MAX + 1; // 97

        let mut hashes = Vec::with_capacity(n);
        for i in 0..n {
            let (_ident, rh) = store_ledger_record(
                &state,
                &format!("rec-cap-{i:03}"),
                format!("cap_creator_{i}").as_bytes(),
                zone.clone(),
                100.0 + i as f64,
                crate::accounting::types::transfer_metadata(i as u64 + 1, &"aa".repeat(32), None),
            );
            hashes.push(rh);
        }
        hashes.sort();
        let root = crate::network::sync::MerkleTree::root(&hashes);
        let prev = [0u8; 32];

        // REAL emission path: 97 hashes → key omitted by bounded emission.
        let mut meta = crate::network::epoch::seal_metadata(
            crate::network::epoch::SealMetadataParams {
                zone: zone.clone(),
                epoch_number: 50,
                start: 99.0,
                end: 100.0 + n as f64 + 0.5,
                record_count: n as u64,
                merkle_root: &root,
                previous_seal_hash: &prev,
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: Some(&hashes),
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            },
        );
        assert!(
            !meta.contains_key("epoch_record_hashes"),
            "above-cap emission must omit the inline enumeration"
        );
        // Pin the zone mapping for the derive scan (seal_metadata wrote the
        // process-global zone count; the records above were stored under
        // legacy zone 0).
        meta.insert("epoch_zone_count".to_string(), serde_json::json!(1));

        let seal_rec = crate::record::ValidationRecord {
            id: "seal-cap-1".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0xAAu8; 32],
            creator_public_key: b"cap-sealer".to_vec(),
            timestamp: 100.0 + n as f64 + 1.0,
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
            zone: Some(zone.clone()),
            identity_hash_wire: None,
            nonce: 0,
        };
        let mut seal = crate::network::epoch::extract_epoch_seal(&seal_rec)
            .unwrap()
            .unwrap();
        assert!(seal.record_hashes.is_empty(), "wire shape: absent enumeration");

        // The ingest-pass hook (mirrored): derive once, share in-pass.
        let mut derive_local_count: Option<u64> = None;
        match crate::network::epoch::derive_seal_enumeration(&*state.rocks, &seal) {
            Some(crate::network::epoch::DeriveOutcome::Derived(d)) => seal.record_hashes = d,
            Some(crate::network::epoch::DeriveOutcome::Incomplete { local_window_count }) => {
                derive_local_count = Some(local_window_count);
            }
            None => {}
        }
        assert_eq!(
            seal.record_hashes, hashes,
            "derive must recover the full {n}-record enumeration"
        );

        // P2: every derived hash resolves to a local record id.
        let ids = resolve_seal_record_ids(&state, &seal.record_hashes);
        assert_eq!(ids.len(), n, "all sealed records resolve locally");

        // P3: no deficit opens on a complete window.
        record_seal_deficit(&state, &seal, "seal-cap-1", ids.len(), derive_local_count);
        assert_eq!(state.dag_deficit_epochs_total.load(Relaxed), 0);

        // P4: the witness-SMT scope sees the sealed records' identities.
        let scope = compute_witness_smt_scope(&state, &seal);
        assert!(
            !scope.is_empty(),
            "witness scope must be non-empty for a derived enumeration"
        );
    }

    #[test]
    fn declined_seal_ids_fold_into_delta_pull_bloom() {
        // Contract §4.4: a stale-declined seal id folded into the bloom must
        // test positive so the server stops re-serving it. Mirrors the fold
        // in gossip::delta_pull (scanned storage ids + declined LRU).
        let mut declined = SeenSet::new(4096);
        declined.insert("stale-seal-1".into());
        declined.insert("stale-seal-2".into());
        assert_eq!(declined.iter().count(), 2);

        let scanned_ids = vec!["rec-1".to_string(), "rec-2".to_string()];
        let mut bloom = crate::network::sync::BloomFilter::new(
            (scanned_ids.len() + declined.len()).max(100),
            0.01,
        );
        for id in &scanned_ids {
            bloom.insert(id.as_bytes());
        }
        for id in declined.iter() {
            bloom.insert(id.as_bytes());
        }
        assert!(bloom.contains(b"stale-seal-1"));
        assert!(bloom.contains(b"stale-seal-2"));
        assert!(bloom.contains(b"rec-1"));
    }

    /// W2-A decision policy (`rotation_batch_op_for`): a rotation-class hop marks
    /// its own hash pending; a plain record is `None`; a seal arms ONLY when it
    /// actually covers a currently-pending rotation hash — never merely because
    /// some unrelated rotation is in flight (the per-hash check, not just the
    /// emptiness short-circuit). The positive arm over a real (merkle-valid) seal
    /// is exercised end-to-end by the W2-B sweep integration tests.
    #[test]
    fn rotation_batch_op_for_classifies_records() {
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::{RotationBatchOp, StorageEngine};
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();

        // 1. Rotation-class hop → RotationHopAdmit(record_hash, record_id, lineage).
        //    Fresh rocks ⇒ empty predecessor index ⇒ this pk0→pk1 hop derives as a
        //    ROOT: lineage_id == prev_key_hash == creator_identity_hash(rot).
        let rot = ValidationRecord::create(
            b"c",
            b"pk0".to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(b"pk1", "periodic")),
        );
        assert_eq!(
            rotation_batch_op_for(&rocks, &rot),
            Some(RotationBatchOp::RotationHopAdmit {
                record_hash_hex: hex::encode(rot.record_hash()),
                record_id: rot.id.clone(),
                lineage_id: format!("d:{}", crate::accounting::types::creator_identity_hash(&rot)),
            })
        );

        // 2. Plain (non-rotation, non-seal) record → None.
        let plain =
            ValidationRecord::create(b"x", b"k".to_vec(), vec![], Classification::Public, None);
        assert_eq!(rotation_batch_op_for(&rocks, &plain), None);

        // 3. A seal covering nothing pending → None (emptiness short-circuit).
        let mut m = std::collections::BTreeMap::new();
        m.insert("epoch_op".to_string(), serde_json::json!("seal"));
        m.insert("epoch_zone".to_string(), serde_json::json!("default"));
        m.insert("epoch_number".to_string(), serde_json::json!(5u64));
        m.insert("epoch_start".to_string(), serde_json::json!(1.0));
        m.insert("epoch_end".to_string(), serde_json::json!(2.0));
        m.insert("epoch_record_count".to_string(), serde_json::json!(0u64));
        m.insert(
            "epoch_merkle_root".to_string(),
            serde_json::json!(hex::encode([0u8; 32])),
        );
        m.insert(
            "epoch_previous_seal".to_string(),
            serde_json::json!(hex::encode([0u8; 32])),
        );
        let seal =
            ValidationRecord::create(b"seal", b"anchor".to_vec(), vec![], Classification::Public, Some(m));
        assert!(!rocks.has_any_rotation_pending());
        assert_eq!(rotation_batch_op_for(&rocks, &seal), None);

        // 4. Precision: with an UNRELATED rotation pending, a seal that does not
        //    cover it still does NOT arm — arms on per-hash coverage, not on
        //    "any rotation active".
        rocks
            .put_record_with_pk_zone(
                &rot.id,
                &rot,
                "id-rot",
                &rot.creator_public_key,
                [0; 8],
                None,
                None,
                Some(RotationBatchOp::RotationHopAdmit {
                    record_hash_hex: hex::encode(rot.record_hash()),
                    record_id: rot.id.clone(),
                    lineage_id: crate::accounting::types::creator_identity_hash(&rot),
                }),
            )
            .unwrap();
        assert!(rocks.has_any_rotation_pending());
        assert_eq!(
            rotation_batch_op_for(&rocks, &seal),
            None,
            "a seal not covering the pending hash must not arm"
        );
    }

    /// §9 pin-determinism (deep hop): a hop whose predecessor has finalized
    /// derives its pin from the DURABLE predecessor newkey-index, so the whole
    /// lineage shares ONE `lineage_id` (the root `sha3(pk₀)`) — never the hop's
    /// own `prev_key`. This is the R-2/R-8 invariant that keeps a rotated
    /// identity's rotation chain co-zoned as the signing key changes.
    #[test]
    fn rotation_hop_admit_derives_deep_hop_lineage_from_predecessor() {
        use crate::network::rotation_finality::{build_rotation_entry, FinalityEvidence};
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::{RotationBatchOp, StorageEngine};
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();

        let rot = |old: &[u8], new: &[u8]| {
            ValidationRecord::create(
                b"c",
                old.to_vec(),
                vec![],
                Classification::Public,
                Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
            )
        };
        let pulse = crate::network::time_bracket::DrandPulse {
            round: 7,
            randomness: "beef".into(),
            genesis_unix: 1,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: None,
            previous_signature: None,
        };
        let root_prev = crate::crypto::hash::sha3_256_hex(b"pk0");
        // Root hop's lineage_id carries the RotationKind tag ("d:" Dilithium);
        // prev_key_hash stays the raw hash, so keep both forms.
        let lineage = format!("d:{root_prev}");

        // Finalize the ROOT hop pk0→pk1 exactly as W1/W2 would: derive over the
        // durable index (empty ⇒ root) then persist, which writes the forward
        // newkey-index row sha3(pk1) → (lineage, 0).
        let root = rot(b"pk0", b"pk1");
        let entry = build_rotation_entry(
            &root,
            Some("cA".into()),
            100,
            "default".into(),
            0,
            "seal-0".into(),
            pulse,
            FinalityEvidence::Quorum,
            |k| rocks.get_rotation_newkey_index(k),
        )
        .expect("root hop builds");
        assert_eq!(entry.lineage_id, lineage);
        rocks.put_rotation_entry(&entry).unwrap();

        // Admit the DEEPER hop pk1→pk2: its prev_key = sha3(pk1) resolves THROUGH
        // the index to the root lineage, not to sha3(pk1).
        let deep = rot(b"pk1", b"pk2");
        assert_ne!(
            crate::accounting::types::creator_identity_hash(&deep),
            root_prev,
            "the deep hop's own prev_key differs from the lineage root (test is meaningful)"
        );
        assert_eq!(
            rotation_batch_op_for(&rocks, &deep),
            Some(RotationBatchOp::RotationHopAdmit {
                record_hash_hex: hex::encode(deep.record_hash()),
                record_id: deep.id.clone(),
                lineage_id: lineage.clone(),
            }),
            "deep hop pins to the ROOT lineage via the predecessor index"
        );
    }

    /// §9 H3b (fail-closed): the reason `validate_rotation_predecessor_grounding` exists —
    /// a `None` from the finalized-only introducing-hop index is ambiguous between a genuine
    /// root and a pending/unseen predecessor, so admission must NOT pin either as a root
    /// (that forks). Both the genuine-root shape (`pk0→pk1` on a fresh engine) and the
    /// pending-predecessor shape (`pk1→pk2` with no finalized predecessor) present as `None`
    /// and are rejected identically. A NON-rotation record is n/a.
    #[test]
    fn h3b_rejects_ungroundable_rotation_hops_fail_closed() {
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();
        let rot = |old: &[u8], new: &[u8]| {
            ValidationRecord::create(
                b"c",
                old.to_vec(),
                vec![],
                Classification::Public,
                Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
            )
        };
        // Genuine root pk0→pk1: prev_key = sha3(pk0), never rotated into ⇒ None ⇒ reject.
        // Classified Transient: it parks (bounded, ages out) rather than being embargoed —
        // the C2 fix, so an origin-reg that later grounds the root is not censored forever.
        let root_err = validate_rotation_predecessor_grounding(&rocks, &rot(b"pk0", b"pk1"))
            .expect_err("a genuine root is fail-closed until the origin primitive lands");
        assert_eq!(root_err.0, RejectClass::Transient, "None-arm is retryable, never embargoed");
        // Pending predecessor pk1→pk2 with no finalized pk0→pk1: also None ⇒ reject. Same
        // path, same verdict — that indistinguishability IS why we fail closed.
        let pending_err = validate_rotation_predecessor_grounding(&rocks, &rot(b"pk1", b"pk2"))
            .expect_err("a hop whose predecessor has not finalized is rejected");
        assert_eq!(
            pending_err.0,
            RejectClass::Transient,
            "pending-predecessor is retryable: the identical hop grounds once it finalizes"
        );
        // Non-rotation record: gate n/a.
        let plain =
            ValidationRecord::create(b"x", b"k".to_vec(), vec![], Classification::Public, None);
        assert!(validate_rotation_predecessor_grounding(&rocks, &plain).is_ok());
    }

    /// §9 H3b (grounded): once the predecessor hop is durably Final (its `new_key_hash` is in
    /// the CF index at `state ≥ Final`), the deep hop is admitted — this is the case the
    /// derivation resolves deterministically on every node. Built exactly as W1/W2 finalize.
    #[test]
    fn h3b_admits_deep_hop_with_finalized_predecessor() {
        use crate::network::rotation_finality::{build_rotation_entry, FinalityEvidence};
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();
        let rot = |old: &[u8], new: &[u8]| {
            ValidationRecord::create(
                b"c",
                old.to_vec(),
                vec![],
                Classification::Public,
                Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
            )
        };
        let pulse = crate::network::time_bracket::DrandPulse {
            round: 7,
            randomness: "beef".into(),
            genesis_unix: 1,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: None,
            previous_signature: None,
        };
        // Finalize root pk0→pk1 (writes newkey-index sha3(pk1) → (lineage, 0)).
        let entry = build_rotation_entry(
            &rot(b"pk0", b"pk1"),
            Some("cA".into()),
            100,
            "default".into(),
            0,
            "seal-0".into(),
            pulse,
            FinalityEvidence::Quorum,
            |k| rocks.get_rotation_newkey_index(k),
        )
        .expect("root hop builds");
        rocks.put_rotation_entry(&entry).unwrap();
        // Now the deep hop pk1→pk2 grounds: prev_key = sha3(pk1) resolves Some(Final).
        assert!(
            validate_rotation_predecessor_grounding(&rocks, &rot(b"pk1", b"pk2")).is_ok(),
            "a deep hop whose predecessor is durably Final is admitted"
        );
    }

    /// §9 H3b (depth cap): a hop whose predecessor sits at `ROTATION_MAX_CHAIN_DEPTH - 1`
    /// would be hop `ROTATION_MAX_CHAIN_DEPTH` — rejected. H3b owns the ceiling so
    /// `derive_lineage_position` never truncates silently.
    #[test]
    fn h3b_rejects_at_max_chain_depth() {
        use crate::network::rotation_finality::{
            FinalityCoord, FinalityEvidence, RotationChainEntry, RotationKind, RotationState,
            ROTATION_MAX_CHAIN_DEPTH,
        };
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();
        // Hand-place a Final predecessor entry at the last legal hop index whose
        // introduced key is sha3(pk_last), so the next hop lands exactly at the cap.
        let last = ROTATION_MAX_CHAIN_DEPTH - 1;
        let new_key_hash = crate::crypto::hash::sha3_256_hex(b"pk_last");
        let entry = RotationChainEntry {
            lineage_id: crate::crypto::hash::sha3_256_hex(b"pk0"),
            hop_index: last,
            record_id: "rec-last".into(),
            record_hash: "hh".into(),
            prev_key_hash: crate::crypto::hash::sha3_256_hex(b"pk_prev"),
            new_key_hash: new_key_hash.clone(),
            kind: RotationKind::Rotation,
            coord: FinalityCoord {
                chain_hash: "cA".into(),
                round: 1,
                zone_path: "default".into(),
                epoch: 0,
                record_id: "rec-last".into(),
            },
            seal_record_id: "seal-x".into(),
            pulse: crate::network::time_bracket::DrandPulse {
                round: 1,
                randomness: "aa".into(),
                genesis_unix: 1,
                period_secs: 30,
                chain_hash: Some("cA".into()),
                signature: None,
                previous_signature: None,
            },
            state: RotationState::Final,
            evidence: FinalityEvidence::Quorum,
            dispute_outcome: None,
        };
        rocks.put_rotation_entry(&entry).unwrap();
        // A hop signed by pk_last (prev_key = sha3(pk_last)) would be hop `last + 1` == cap.
        let over = ValidationRecord::create(
            b"pk_last",
            b"pk_last".to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(b"pk_over", "periodic")),
        );
        let cap_err = validate_rotation_predecessor_grounding(&rocks, &over)
            .expect_err("a hop at ROTATION_MAX_CHAIN_DEPTH is rejected (H3b owns the cap)");
        // Permanent: the chain never shortens on retry, so this embargoes rather than parks.
        assert_eq!(cap_err.0, RejectClass::Permanent, "depth-cap is structural ⇒ permanent");
        assert!(cap_err.1.contains("cap"), "err names the cap: {}", cap_err.1);
    }

    /// §9 H3b (predecessor indexed but not yet Final): the introducing hop is present in the
    /// newkey index but its CF entry has not reached `state ≥ Final` (e.g. a snapshot-inherited
    /// `Pending`). The hop is declined Transient — it grounds on retry once the predecessor
    /// finalizes here — NOT embargoed. Distinct from the depth-cap (Permanent) branch.
    #[test]
    fn h3b_predecessor_indexed_but_pending_is_transient() {
        use crate::network::rotation_finality::{
            FinalityCoord, FinalityEvidence, RotationChainEntry, RotationKind, RotationState,
        };
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("rocks")).unwrap();
        // Hand-place the root pk0→pk1 introducing entry at state Pending (index present,
        // but not durably Final) so the deep hop pk1→pk2 hits the not-Final branch.
        let entry = RotationChainEntry {
            lineage_id: crate::crypto::hash::sha3_256_hex(b"pk0"),
            hop_index: 0,
            record_id: "rec-root".into(),
            record_hash: "hh".into(),
            prev_key_hash: crate::crypto::hash::sha3_256_hex(b"pk0"),
            new_key_hash: crate::crypto::hash::sha3_256_hex(b"pk1"),
            kind: RotationKind::Rotation,
            coord: FinalityCoord {
                chain_hash: "cA".into(),
                round: 1,
                zone_path: "default".into(),
                epoch: 0,
                record_id: "rec-root".into(),
            },
            seal_record_id: "seal-x".into(),
            pulse: crate::network::time_bracket::DrandPulse {
                round: 1,
                randomness: "aa".into(),
                genesis_unix: 1,
                period_secs: 30,
                chain_hash: Some("cA".into()),
                signature: None,
                previous_signature: None,
            },
            state: RotationState::Pending,
            evidence: FinalityEvidence::Quorum,
            dispute_outcome: None,
        };
        rocks.put_rotation_entry(&entry).unwrap();
        let deep = ValidationRecord::create(
            b"c",
            b"pk1".to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(b"pk2", "periodic")),
        );
        let err = validate_rotation_predecessor_grounding(&rocks, &deep)
            .expect_err("a Pending predecessor must not ground");
        assert_eq!(err.0, RejectClass::Transient, "not-yet-Final predecessor is retryable");
        assert!(err.1.contains("not durably Final"), "err names the leg: {}", err.1);
    }

    /// §9 pin-determinism (cross-node): two independent engines with byte-identical
    /// predecessor state derive byte-identical admit ops for the same record. This
    /// is the anti-fork core — every node computes the SAME pin, so a rotation
    /// record routes to the same lineage zone everywhere. Covers BOTH the root
    /// path (no predecessor) and the index-backed deep path.
    #[test]
    fn rotation_hop_admit_pin_is_deterministic_across_engines() {
        use crate::network::rotation_finality::{build_rotation_entry, FinalityEvidence};
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;

        let rot = |old: &[u8], new: &[u8]| {
            ValidationRecord::create(
                b"c",
                old.to_vec(),
                vec![],
                Classification::Public,
                Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
            )
        };
        let mk_pulse = || crate::network::time_bracket::DrandPulse {
            round: 7,
            randomness: "beef".into(),
            genesis_unix: 1,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: None,
            previous_signature: None,
        };
        // Seed an engine with the finalized root pk0→pk1 so a later pk1→pk2 hop
        // resolves through the index (the non-trivial path).
        let seed = |engine: &StorageEngine| {
            let root = rot(b"pk0", b"pk1");
            let entry = build_rotation_entry(
                &root,
                Some("cA".into()),
                100,
                "default".into(),
                0,
                "seal-0".into(),
                mk_pulse(),
                FinalityEvidence::Quorum,
                |k| engine.get_rotation_newkey_index(k),
            )
            .expect("root hop builds");
            engine.put_rotation_entry(&entry).unwrap();
        };

        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let e1 = StorageEngine::open(d1.path().join("r")).unwrap();
        let e2 = StorageEngine::open(d2.path().join("r")).unwrap();
        seed(&e1);
        seed(&e2);

        let deep = rot(b"pk1", b"pk2");
        let op1 = rotation_batch_op_for(&e1, &deep);
        let op2 = rotation_batch_op_for(&e2, &deep);
        assert_eq!(
            op1, op2,
            "identical predecessor state ⇒ identical pin on every node (no fork)"
        );
        assert!(op1.is_some(), "the deep hop admits");

        // And the root path (unseeded engines) is likewise engine-independent.
        let d3 = tempfile::tempdir().unwrap();
        let d4 = tempfile::tempdir().unwrap();
        let e3 = StorageEngine::open(d3.path().join("r")).unwrap();
        let e4 = StorageEngine::open(d4.path().join("r")).unwrap();
        let fresh = rot(b"pkA", b"pkB");
        assert_eq!(
            rotation_batch_op_for(&e3, &fresh),
            rotation_batch_op_for(&e4, &fresh),
            "root-path pin is deterministic across nodes too"
        );
    }

    // ── KR-3 S2 §5-H2 + §5-H3: parent-grounding gate ─────────────────────────
    // Storage-backed (parent records + rotation CF + FinalizedIndex). Deterministic:
    // `node_now` is derived from the parent's own `timestamp`, never the wall clock.

    /// Build a rotation-class record citing `parents`.
    fn pg_rot(old: &[u8], new: &[u8], parents: Vec<String>) -> crate::record::ValidationRecord {
        crate::record::ValidationRecord::create(
            b"c",
            old.to_vec(),
            parents,
            crate::record::Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
        )
    }
    /// Build an ordinary (non-rotation-class) record citing `parents`.
    fn pg_plain(parents: Vec<String>) -> crate::record::ValidationRecord {
        crate::record::ValidationRecord::create(
            b"data",
            b"k".to_vec(),
            parents,
            crate::record::Classification::Public,
            None,
        )
    }
    /// Store `rec` AND mark it durably finalized as an ORDINARY parent (its
    /// `finalized:{id}` FinalizedIndex row) — the `contains_in_rocks` leg of H3.
    fn pg_finalize_ordinary(
        rocks: &crate::storage::rocks::StorageEngine,
        rec: &crate::record::ValidationRecord,
    ) {
        rocks.put_record(&rec.id, rec).unwrap();
        rocks
            .put_cf_raw(
                crate::storage::rocks::CF_METADATA,
                format!("finalized:{}", rec.id).as_bytes(),
                b"1",
            )
            .unwrap();
    }
    /// Store `rec` AND land its rotation-CF hop entry in `state` (Final grounds,
    /// Pending does not) — exercises the rotation-hop leg of H3.
    fn pg_finalize_rotation(
        rocks: &crate::storage::rocks::StorageEngine,
        rec: &crate::record::ValidationRecord,
        state: crate::network::rotation_finality::RotationState,
    ) {
        use crate::network::rotation_finality::{build_rotation_entry, FinalityEvidence};
        rocks.put_record(&rec.id, rec).unwrap();
        let pulse = crate::network::time_bracket::DrandPulse {
            round: 7,
            randomness: "beef".into(),
            genesis_unix: 1,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: None,
            previous_signature: None,
        };
        let mut entry = build_rotation_entry(
            rec,
            Some("cA".into()),
            100,
            "default".into(),
            0,
            "seal-0".into(),
            pulse,
            FinalityEvidence::Quorum,
            |k| rocks.get_rotation_newkey_index(k),
        )
        .expect("rotation entry builds");
        entry.state = state;
        rocks.put_rotation_entry(&entry).unwrap();
    }

    /// H2: a rotation-class record MUST cite ≥1 parent. Empty ⇒ rejected.
    #[test]
    fn pg_h2_empty_parents_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let rec = pg_rot(b"pk0", b"pk1", vec![]);
        let err = validate_rotation_parent_grounding(&rocks, &rec, rec.timestamp + 10.0)
            .expect_err("no parents must reject (H2)");
        assert_eq!(err.0, RejectClass::Permanent, "H2 no-parents is structural ⇒ permanent");
        assert!(err.1.contains("H2"), "err names the gate: {}", err.1);
    }

    /// A NON-rotation-class record is n/a even with empty parents (ordinary/global
    /// ops legitimately have none) ⇒ Ok, gate untouched.
    #[test]
    fn pg_non_rotation_class_is_not_applicable() {
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let plain = pg_plain(vec![]);
        assert!(validate_rotation_parent_grounding(&rocks, &plain, plain.timestamp + 10.0).is_ok());
    }

    /// H3 durable leg — an ORDINARY parent with its FinalizedIndex row grounds.
    #[test]
    fn pg_h3_ordinary_finalized_parent_grounds() {
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let parent = pg_plain(vec![]);
        pg_finalize_ordinary(&rocks, &parent);
        let child = pg_rot(b"pk0", b"pk1", vec![parent.id.clone()]);
        let node_now = parent.timestamp + 100.0; // fresh (< 24 h)
        assert!(validate_rotation_parent_grounding(&rocks, &child, node_now).is_ok());
    }

    /// H3 durable leg — a rotation-HOP parent whose CF entry is `Final` grounds.
    #[test]
    fn pg_h3_rotation_cf_final_parent_grounds() {
        use crate::network::rotation_finality::RotationState;
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let parent = pg_rot(b"pk0", b"pk1", vec![]);
        pg_finalize_rotation(&rocks, &parent, RotationState::Final);
        let child = pg_rot(b"childold", b"childnew", vec![parent.id.clone()]);
        let node_now = parent.timestamp + 100.0;
        assert!(validate_rotation_parent_grounding(&rocks, &child, node_now).is_ok());
    }

    /// H3 durable leg — a rotation-hop parent whose CF entry is only `Pending`
    /// (snapshot-inherited, locally unconfirmed) does NOT ground: the gate checks
    /// `state ≥ Final`, not mere index-presence. Sole parent Pending ⇒ rejected.
    #[test]
    fn pg_h3_pending_cf_entry_does_not_ground() {
        use crate::network::rotation_finality::RotationState;
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let parent = pg_rot(b"pk0", b"pk1", vec![]);
        pg_finalize_rotation(&rocks, &parent, RotationState::Pending);
        // Sanity: the newkey-index IS present (put unconditionally), so this really
        // tests the state guard, not an absent index.
        let hop = crate::network::rotation_finality::rotation_hop_fields(&parent).unwrap();
        assert!(rocks.get_rotation_newkey_index(&hop.new_key_hash).is_some());
        let child = pg_rot(b"childold", b"childnew", vec![parent.id.clone()]);
        let err = validate_rotation_parent_grounding(&rocks, &child, parent.timestamp + 100.0)
            .expect_err("Pending CF parent must not ground");
        assert_eq!(err.0, RejectClass::Transient, "durable-parent leg is retryable");
        assert!(err.1.contains("durable-parent"), "err names the leg: {}", err.1);
    }

    /// H3 durable leg — cited parents that are stored but NOT finalized (no
    /// FinalizedIndex row, no CF entry) ⇒ no durable parent ⇒ rejected.
    #[test]
    fn pg_h3_all_unfinalized_parents_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        // Two DISTINCT non-durable parents of different classes: an ordinary record
        // (no FinalizedIndex row) and a rotation hop (no CF entry). Neither grounds.
        let p1 = pg_plain(vec![]);
        let p2 = pg_rot(b"unfin_old", b"unfin_new", vec![]);
        rocks.put_record(&p1.id, &p1).unwrap();
        rocks.put_record(&p2.id, &p2).unwrap(); // stored, but never finalized
        assert_ne!(p1.id, p2.id, "the two unfinalized parents are distinct");
        let child = pg_rot(b"pk0", b"pk1", vec![p1.id.clone(), p2.id.clone()]);
        let node_now = p1.timestamp + 100.0;
        let err = validate_rotation_parent_grounding(&rocks, &child, node_now)
            .expect_err("no durable parent must reject");
        assert_eq!(err.0, RejectClass::Transient, "durable-parent leg is retryable");
        assert!(err.1.contains("durable-parent"), "err names the leg: {}", err.1);
    }

    /// H3 age leg — a cited parent older than the 24 h cap ⇒ rejected, even if it
    /// IS durably finalized (age is checked for every loadable parent).
    #[test]
    fn pg_h3_parent_past_age_cap_rejected() {
        use crate::network::rotation_finality::ROTATION_PARENT_MAX_AGE_SECS;
        let dir = tempfile::tempdir().unwrap();
        let rocks = crate::storage::rocks::StorageEngine::open(dir.path().join("r")).unwrap();
        let parent = pg_plain(vec![]);
        pg_finalize_ordinary(&rocks, &parent); // durable AND fresh-by-content…
        let child = pg_rot(b"pk0", b"pk1", vec![parent.id.clone()]);
        // …but node_now is > 24 h past the parent ⇒ the age leg fires first.
        let node_now = parent.timestamp + ROTATION_PARENT_MAX_AGE_SECS as f64 + 100.0;
        let err = validate_rotation_parent_grounding(&rocks, &child, node_now)
            .expect_err("parent past the age cap must reject");
        assert_eq!(err.0, RejectClass::Permanent, "age-cap is structural ⇒ permanent");
        assert!(err.1.contains("age"), "err names the age leg: {}", err.1);
    }

    /// Anti-fork: two independent engines with byte-identical durable parent state
    /// reach the byte-identical grounding decision for the same record — the H3
    /// inputs are durable finality, so admission never diverges by node.
    #[test]
    fn pg_h3_grounding_is_deterministic_across_engines() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let e1 = crate::storage::rocks::StorageEngine::open(d1.path().join("r")).unwrap();
        let e2 = crate::storage::rocks::StorageEngine::open(d2.path().join("r")).unwrap();
        let parent = pg_plain(vec![]);
        pg_finalize_ordinary(&e1, &parent);
        pg_finalize_ordinary(&e2, &parent);
        let child = pg_rot(b"pk0", b"pk1", vec![parent.id.clone()]);
        let node_now = parent.timestamp + 100.0;
        let r1 = validate_rotation_parent_grounding(&e1, &child, node_now);
        let r2 = validate_rotation_parent_grounding(&e2, &child, node_now);
        assert_eq!(r1.is_ok(), r2.is_ok(), "identical durable state ⇒ identical decision");
        assert!(r1.is_ok(), "the grounded child admits on both nodes");
    }
}
