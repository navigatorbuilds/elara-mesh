//! Gap 4 HTTP routes: zone-split/merge TransitionSeal proposal, fetch, veto.
//!
//! These endpoints give the network (and light clients) a first-class way
//! to observe a pending split or merge. The endpoints are intentionally
//! thin — validation, signature verification, and lifecycle enforcement
//! live in [`super::super::zone_transition_seal::TransitionSeal`] and
//! [`super::super::transition_store::TransitionStore`]. Handlers translate
//! HTTP ↔ store and report errors back as the expected status codes.
//!
//! # Endpoints
//!
//! * `POST /transitions/propose` — body: `TransitionSeal` JSON. Inserts the
//!   proposal into the pending store. Structural validation and Dilithium3
//!   signature verification against the local anchor-pubkey registry
//!   (`CF_IDENTITIES`) are enforced. Unknown anchor identities are rejected
//!   at 400 so forged sigs never accumulate against the M-of-N threshold.
//!   Returns `{ "id": "<hex>", "status": "AwaitingSigs" | "DisputeWindow" }`.
//!
//! * `POST /transitions/{id}/sig` — body: `AnchorSig` JSON. Fans in a
//!   single anchor signature to an existing proposal. Crosses the M-of-N
//!   threshold → status flips to `DisputeWindow` in the same round-trip.
//!
//! * `GET /transitions/{id}` — returns the pending proposal, its current
//!   lifecycle status, accumulated signatures, and any vetoes. `id` is the
//!   hex of [`TransitionSeal::seal_hash_for_sig`]. 404 if unknown.
//!
//! * `POST /transitions/{id}/veto` — body: `TransitionVeto` JSON. Rejects
//!   if the seal id doesn't match, if the dispute window is closed, or if
//!   the vetoer has already submitted one. Returns the updated status.
//!
//! * `GET /transitions` — lists every pending proposal the local store
//!   knows about. Returns a compact summary per entry (id, kind, status,
//!   zones, threshold, sigs_collected, epoch bounds) so callers can
//!   discover open proposals without knowing ids in advance. Clients that
//!   want the full seal call `GET /transitions/{id}`.
//!
//! * `GET /transitions/{id}/resolve/{account_hash_hex}` — for a Split
//!   proposal, returns the child `ZoneId` that the given account hash
//!   routes to after `effective_epoch`. For a Merge, returns the single
//!   merged child. Light clients use this to rebuild balance-proof paths
//!   after a transition finalizes without having to replay
//!   `account_belongs_to_child` locally.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;

use crate::crypto::pqc;
use crate::errors::ElaraError;

use super::super::server::AppError;
use super::super::state::NodeState;
use super::super::transition_store::{
    KindCounts, PendingStatus, StatusCounts, TransitionVeto, VetoReasonCounts,
};
use super::super::zone_transition_seal::{AnchorSig, TransitionKind, TransitionSeal};

/// Look up an anchor's Dilithium3 public key from the identity CF.
///
/// `AnchorSig::anchor_identity_hash` is a raw 32-byte SHA3-256 of the
/// anchor's pubkey; the RocksDB `CF_IDENTITIES` map is keyed by the
/// hex form (that's what every sealing path stores). Returns None if
/// the anchor isn't registered on this node.
fn resolve_anchor_pubkey(state: &NodeState, identity_hash: &[u8; 32]) -> Option<Vec<u8>> {
    let hex_key = hex::encode(identity_hash);
    state.rocks.get_public_key(&hex_key)
}

/// Verify a single `AnchorSig` against the seal hash using the registered
/// pubkey from `CF_IDENTITIES`. Returns Ok(()) iff:
///   - the signer is in the staked-anchor trust set (Transitions-F1),
///   - the anchor's pubkey is registered locally,
///   - the sig bytes are a valid Dilithium3 signature over `seal_hash`.
///
/// `trust` is the memoized [`NodeState::transition_trust_view`] set — the
/// ledger staker set at the witness floor plus the genesis authority.
/// Callers fetch it ONCE per request/tick and pass it through; the
/// parameter (rather than an internal fetch) is what makes the stake gate
/// compiler-enforced at every ingest site and keeps this fn sync + free of
/// per-sig ledger locks. The stake check runs BEFORE the Dilithium3
/// verify so unstaked spam can't burn signature-verify CPU, and it applies
/// unconditionally — no grandfather epoch (`effective_epoch` is
/// attacker-controlled, so any epoch-conditioned skip is a standing
/// bypass channel; F1 audit 2026-07-05 §2.5).
///
/// Unknown anchors, unstaked signers, and bad sigs all map to
/// `ElaraError::Wire` — the HTTP handler reports this as a 400 so the
/// caller can re-try with a different sig or after the pubkey/stake is
/// propagated.
pub(crate) fn verify_anchor_sig(
    state: &NodeState,
    sig: &AnchorSig,
    seal_hash: &[u8; 32],
    trust: &std::collections::HashSet<[u8; 32]>,
) -> Result<(), ElaraError> {
    if !trust.contains(&sig.anchor_identity_hash) {
        state
            .transition_sig_stake_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ElaraError::Wire(format!(
            "anchor not in staked trust set: {}",
            hex::encode(sig.anchor_identity_hash),
        )));
    }
    let pubkey = resolve_anchor_pubkey(state, &sig.anchor_identity_hash)
        .ok_or_else(|| ElaraError::Wire(format!(
            "anchor pubkey not registered: {}",
            hex::encode(sig.anchor_identity_hash),
        )))?;
    match pqc::dilithium3_verify(seal_hash, &sig.dilithium3_sig, &pubkey) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ElaraError::Wire("anchor sig invalid".into())),
        Err(e) => Err(ElaraError::Wire(format!("anchor sig verify failed: {e}"))),
    }
}

/// Body accepted by `POST /transitions/propose`. Right now the handler
/// expects the full [`TransitionSeal`] as JSON — anchor signatures, if any,
/// are carried in `proposer_sigs` just like they appear at rest.
pub type ProposeBody = TransitionSeal;

/// Mirror an in-memory `PendingTransition` to `CF_TRANSITIONS_PENDING`.
///
/// Called from every successful mutation handler (propose / sig / veto)
/// so a restart mid-window doesn't silently drop the proposal. If the
/// entry has reached a terminal state (`Vetoed`), the CF entry is
/// *deleted* instead — a Vetoed proposal should not replay on restart.
/// `Finalized` and `Expired` cleanups land via `run_transition_tick`'s
/// `clear_pending_mirror`, not this path.
///
/// Errors are logged and swallowed — failing the HTTP call because a
/// durable mirror couldn't write would be worse than losing one-epoch-
/// of-vetoes recovery value on a rare rocks error.
pub(crate) fn persist_pending_entry(state: &NodeState, id: &[u8; 32]) {
    let store = match state.transitions.read() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("persist_pending: transitions lock poisoned: {e}");
            return;
        }
    };
    let Some(pending) = store.get(id) else {
        // Entry was evicted between mutation and mirror — not an error,
        // just a race. The next mutation (or the tick's delete) will
        // reconcile.
        return;
    };

    // Vetoed entries become synchronously terminal (no tick path flips
    // DisputeWindow → Vetoed — `add_veto` does). Delete rather than
    // write so a restart doesn't rehydrate a dead proposal.
    if pending.status == PendingStatus::Vetoed {
        if let Err(e) = state.rocks.delete_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_PENDING,
            id,
        ) {
            tracing::warn!(
                "persist_pending: delete for Vetoed {} failed: {e}",
                hex::encode(id),
            );
            state.transitions_mirror_write_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return;
    }

    match serde_json::to_vec(pending) {
        Ok(bytes) => {
            if let Err(e) = state.rocks.put_cf_raw(
                crate::storage::rocks::CF_TRANSITIONS_PENDING,
                id,
                &bytes,
            ) {
                tracing::warn!(
                    "persist_pending: put_cf_raw failed for {}: {e}",
                    hex::encode(id),
                );
                state.transitions_mirror_write_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::warn!(
                "persist_pending: serialize failed for {}: {e}",
                hex::encode(id),
            );
            state.transitions_mirror_write_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Gap 4 anchor cosign: if this node's identity is configured as an
/// Anchor and hasn't already signed the pending proposal at `id`, produce
/// a Dilithium3 signature over `seal_hash_for_sig`, push it into the
/// store via `add_sig`, and return the freshly-produced `AnchorSig` so
/// the caller can gossip it to peers. Returns `None` if:
///   - this node is not configured as an Anchor (can't seal epochs), or
///   - the identity's pubkey isn't registered locally (so other peers
///     couldn't verify anyway — silently skip rather than produce a sig
///     nobody can use), or
///   - this anchor already contributed a sig to this proposal, or
///   - the proposal is past its dispute window / not in the store.
///
/// Any internal error is logged and yields `None` — cosign is a
/// best-effort optimisation, not a consensus-critical path. Pull + manual
/// fan-in via `POST /transitions/{id}/sig` remains the backstop.
pub(crate) fn maybe_cosign_transition(
    state: &Arc<NodeState>,
    id: &[u8; 32],
) -> Option<AnchorSig> {
    // Is this node configured as an anchor? Non-anchor nodes never co-sign.
    let node_type = super::super::peer::NodeType::from_str(&state.config.node_type);
    if !node_type.can_seal_epochs() {
        return None;
    }

    // Anchor pubkey must be registered under this node's own identity_hash —
    // otherwise peers receiving the sig can't verify it and will reject.
    // (Registration lives in identity-announce / CF_IDENTITIES population,
    //  not in the cosign path.)
    let own_id_bytes = match hex::decode(&state.identity.identity_hash) {
        Ok(b) if b.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(&b);
            h
        }
        _ => return None,
    };
    resolve_anchor_pubkey(state, &own_id_bytes)?;

    // Build the signed seal copy under the write lock, extract the sig,
    // and hand it to the store's add_sig path. Doing the sign inside
    // `sign_as_anchor` + then add_sig keeps the two representations
    // (seal.proposer_sigs vs PendingTransition.seal.proposer_sigs) in
    // lock-step: the add_sig call is what actually persists into the
    // store; sign_as_anchor is just used as a convenient wrapper to
    // produce the AnchorSig we need to gossip.
    let mut store = match state.transitions.write() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cosign: transitions lock poisoned: {e}");
            return None;
        }
    };
    let pending = store.get(id)?;
    // Bail if we're already in the sig set (avoids a redundant sign op
    // and the `add_sig` duplicate-rejection path).
    if pending
        .seal
        .proposer_sigs
        .iter()
        .any(|s| s.anchor_identity_hash == own_id_bytes)
    {
        return None;
    }
    // Only cosign while the window is still open. add_sig rejects past
    // Finalized/Expired/Vetoed anyway, but checking here skips the
    // Dilithium3 sign (expensive) when the verdict is already decided.
    if !matches!(
        pending.status,
        PendingStatus::AwaitingSigs | PendingStatus::DisputeWindow
    ) {
        return None;
    }

    // Clone the seal out of the pending entry so we can sign a local
    // copy without holding a &mut into the store's internals.
    let mut scratch = pending.seal.clone();
    if let Err(e) = scratch.sign_as_anchor(&state.identity) {
        tracing::debug!("cosign: sign_as_anchor failed: {e}");
        return None;
    }
    // The newest sig is the one we just appended (sign_as_anchor sorts
    // by anchor_identity_hash but we filter on our own hash).
    let our_sig = scratch
        .proposer_sigs
        .iter()
        .find(|s| s.anchor_identity_hash == own_id_bytes)?
        .clone();

    if let Err(e) = store.add_sig(id, our_sig.clone()) {
        tracing::debug!("cosign: add_sig failed: {e}");
        return None;
    }
    state
        .transition_cosigns_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(our_sig)
}

/// Gap 4 pull backstop: one tick of the transition-pull loop.
///
/// # Why
/// Both seal-gossip and per-sig anchor-gossip are fire-and-forget broadcasts
/// to sqrt(N) peers. On a healthy fleet every anchor sees every seal and
/// every sig within two hops, but that assumption breaks on transient
/// partitions, peer backoff, or an anchor that just joined the mesh.
/// Without a pull backstop:
///   - an anchor that lost the SEAL push never learns about the proposal
///     and the M-of-N collection stalls until dispute expiry, and
///   - an anchor that has the seal but lost a peer's SIG push stays one
///     cosign short of threshold and the proposal expires in
///     `AwaitingSigs` even though the cosign exists elsewhere on the
///     network.
///
/// # What this does
///   1. Gate: only anchors run (non-anchors have nothing to contribute).
///   2. Pick one random reachable relay peer.
///   3. `GET /transitions?status=awaitingsigs` — bounded response
///      (≤ `MAX_PENDING_TRANSITIONS` = 1024 summaries).
///   4. For up to `MAX_PULLS_PER_TICK` ids that are EITHER unknown to us
///      OR known but still under-threshold in `AwaitingSigs`, `GET
///      /transitions/{id}` for the full seal. The under-threshold case
///      is the sig-loss recovery — `insert` folds the peer's sig set
///      into our existing entry, so one round-trip can deliver multiple
///      missed cosigns at once.
///   5. Verify every attached `AnchorSig` against the local pubkey
///      registry — same contract as `propose_transition`, so a
///      malicious peer can't smuggle unsigned proposals into our store.
///   6. Insert into store, persist to CF_TRANSITIONS_PENDING, then
///      cosign + gossip if this node is eligible.
///
/// # Scale
/// Bounded per tick: 1 peer × 1 list fetch × ≤ N per-id fetches. At
/// N = 16 and typical 3 KB seal payload, worst case ≈ 50 KB + 1 list
/// response ≈ 300 KB per tick per anchor. Health tick = 30 s (see
/// `health_check_interval_secs`) → ≤ 10 KB/s average even in a
/// saturation scenario. Cheap vs. the seal-gossip path itself.
///
/// Errors are swallowed per-call and counted in
/// `transition_pull_errors_total` — a rare gossip-loss recovery should
/// not crash the health loop.
pub(crate) async fn run_transition_pull_tick(state: &Arc<NodeState>) {
    use std::sync::atomic::Ordering::Relaxed;

    // Hard cap so a peer returning a thousand pending ids can't turn a
    // single tick into a multi-second fetch storm.
    const MAX_PULLS_PER_TICK: usize = 16;

    // Gate 1: only anchors benefit from pulling pending proposals —
    // they're the ones that need to cosign. Light / witness nodes get
    // the seal through regular gossip when it finalizes.
    let node_type = super::super::peer::NodeType::from_str(&state.config.node_type);
    if !node_type.can_seal_epochs() {
        return;
    }

    // Gate 2: own pubkey must be registered, else cosign skips anyway
    // (`maybe_cosign_transition` bails on the same condition). Saves
    // the round-trip on nodes that still haven't announced.
    let own_id_bytes = match hex::decode(&state.identity.identity_hash) {
        Ok(b) if b.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(&b);
            h
        }
        _ => return,
    };
    if resolve_anchor_pubkey(state, &own_id_bytes).is_none() {
        return;
    }

    // Pick one random reachable relay peer. Rotate by seconds so a
    // 30-s tick cadence spreads pull traffic across the peer set over
    // minutes (not always hitting the same peer).
    let peer_url = {
        let peers = state.peers.read().await;
        let candidates: Vec<String> = peers
            .connected()
            .into_iter()
            .filter(|p| {
                p.identity_hash != state.identity.identity_hash
                    && p.node_type.can_relay()
                    && p.reachable
            })
            .map(|p| p.base_url())
            .collect();
        if candidates.is_empty() {
            return;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let idx = (ts as usize) % candidates.len();
        candidates[idx].clone()
    };

    // AUDIT-10: PQ-only transition pull. If PQ addr can't be derived, skip.
    let pq_addr = match super::super::gossip::http_to_pq_addr(&peer_url, state.config.pq_port_offset) {
        Some(a) => a,
        None => {
            tracing::debug!("transition pull: no PQ addr for {peer_url}, skipping");
            return;
        }
    };

    // Step 1: list pending-awaitingsigs proposals on the peer. We
    // filter to AwaitingSigs because that's the set where cosigns
    // still accumulate; DisputeWindow is sealed threshold-wise and
    // Finalized/Expired/Vetoed are terminal.
    let list_value = match state.pq_client.list_transitions(&pq_addr, Some("awaitingsigs")).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("transition pull: fetch list from {peer_url}: {e}");
            state.transition_pull_errors_total.fetch_add(1, Relaxed);
            return;
        }
    };
    let list: TransitionListResponse = match serde_json::from_value(list_value) {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!("transition pull: decode list from {peer_url}: {e}");
            state.transition_pull_errors_total.fetch_add(1, Relaxed);
            return;
        }
    };

    // Step 2: compute the set of ids worth pulling from this peer:
    //   (a) ids we don't have locally (gossip-loss SEAL recovery), and
    //   (b) ids we have but that are still in `AwaitingSigs` and below
    //       threshold — sig-loss recovery. `insert` folds incoming sigs
    //       into the existing entry, so re-pulling a known seal lets us
    //       merge any cosigns the peer has accumulated that never
    //       reached us via the (push-only) sig-gossip path. Without this
    //       branch a single dropped sig push keeps a proposal stuck in
    //       AwaitingSigs until effective_epoch and it expires, even when
    //       the network has the cosigns elsewhere.
    // Capped at MAX_PULLS_PER_TICK so a large backlog bleeds off over
    // ceil(backlog / 16) ticks rather than flooding in one shot.
    let target_ids: Vec<[u8; 32]> = {
        let store = match state.transitions.read() {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("transition pull: store lock poisoned: {e}");
                return;
            }
        };
        list.transitions
            .iter()
            .filter_map(|s| {
                let bytes = hex::decode(&s.id).ok()?;
                let mut id32 = [0u8; 32];
                if bytes.len() != 32 {
                    return None;
                }
                id32.copy_from_slice(&bytes);
                match store.get(&id32) {
                    None => Some(id32),
                    Some(p) => {
                        if matches!(p.status, PendingStatus::AwaitingSigs)
                            && p.seal.proposer_sigs.len() < p.seal.required_threshold()
                        {
                            Some(id32)
                        } else {
                            None
                        }
                    }
                }
            })
            .take(MAX_PULLS_PER_TICK)
            .collect()
    };

    if target_ids.is_empty() {
        return;
    }

    // Current epoch for the effective_epoch freshness gate below. The
    // propose (`:585`) and PQ-submit (`router.rs`) ingest paths both reject a
    // seal whose effective_epoch has already passed; the pull path must too,
    // else an untrusted relay peer can serve a NEVER-SEEN back-dated seal
    // (effective_epoch << current) that `TransitionStore::insert` accepts
    // (validate_structure only checks the RELATIVE proposed+window==effective
    // invariant, not absolute freshness) and `tick` then flips straight to
    // Finalized on the next sweep — zero real dispute window. Read once here,
    // not per-id. If state_core isn't up yet, skip the whole tick (we can't
    // safely freshness-gate without a clock).
    let current_epoch = match state.state_core.get() {
        Some(core) => core.read_snapshot().current_epoch,
        None => return,
    };

    // Transitions-F1: staked-anchor trust set, fetched ONCE for the whole
    // tick (≤ MAX_PULLS_PER_TICK seals × ≤ MAX_PROPOSER_SIGS sigs share
    // this one memoized read — never per-sig).
    let trust = state.transition_trust_view().await;

    // Step 3: fetch, verify, insert each target seal. Keep verify +
    // insert per-id so one malformed seal doesn't abort the whole tick.
    for id in target_ids {
        let id_hex = hex::encode(id);

        let view_value = match state.pq_client.get_transition(&pq_addr, &id_hex).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("transition pull: fetch view {id_hex}: {e}");
                state.transition_pull_errors_total.fetch_add(1, Relaxed);
                continue;
            }
        };
        let view: TransitionView = match serde_json::from_value(view_value) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!("transition pull: decode view {id_hex}: {e}");
                state.transition_pull_errors_total.fetch_add(1, Relaxed);
                continue;
            }
        };

        // Sanity: peer must serve the seal whose id matches the one we
        // asked for. Any mismatch means we'd accept forged attribution
        // of sigs to a different proposal.
        let computed_id = match view.seal.seal_hash_for_sig() {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("transition pull: seal_hash_for_sig {id_hex}: {e}");
                state.transition_pull_errors_total.fetch_add(1, Relaxed);
                continue;
            }
        };
        if computed_id != id {
            tracing::debug!(
                "transition pull: peer {peer_url} served id mismatch for {id_hex}"
            );
            state.transition_pull_errors_total.fetch_add(1, Relaxed);
            continue;
        }

        // Freshness gate (parity with the propose/PQ-submit ingest paths): a
        // legitimately-pullable seal is `AwaitingSigs`, i.e. its effective_epoch
        // is still in the FUTURE. A seal whose effective_epoch has already
        // passed is either terminal (shouldn't be in an awaitingsigs list) or
        // a back-dated forgery aimed at the zero-dispute-window finalize race.
        // Reject it here so it never reaches `insert` — a peer cannot inject a
        // never-seen stale seal that finalizes on the next tick.
        if view.seal.effective_epoch <= current_epoch {
            tracing::warn!(
                "transition pull: peer {peer_url} served stale seal {id_hex} \
                 (effective_epoch {} <= current {current_epoch}) — rejecting",
                view.seal.effective_epoch
            );
            state.transition_pull_errors_total.fetch_add(1, Relaxed);
            continue;
        }

        // Verify every attached sig — untrusted peer can serve garbage.
        let mut sigs_ok = true;
        for sig in &view.seal.proposer_sigs {
            if verify_anchor_sig(state, sig, &computed_id, &trust).is_err() {
                sigs_ok = false;
                break;
            }
        }
        if !sigs_ok {
            tracing::debug!(
                "transition pull: peer {peer_url} served seal {id_hex} with \
                 unverifiable sig — rejecting"
            );
            state.transition_pull_errors_total.fetch_add(1, Relaxed);
            continue;
        }

        // Insert into store. `insert` handles the "already present" case
        // by folding incoming sigs into the existing entry; a concurrent
        // gossip push could land the same seal between our check and
        // here, and that's fine.
        let inserted_new = {
            let mut store = match state.transitions.write() {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("transition pull: store write lock: {e}");
                    continue;
                }
            };
            // If the entry appeared between our read and write, insert
            // still succeeds (it folds sigs in), but we count this as a
            // no-op "pull" (not a recovery). Cheapest way to tell: does
            // the entry exist before insert?
            let existed = store.get(&id).is_some();
            match store.insert(view.seal.clone()) {
                Ok(_) => !existed,
                Err(e) => {
                    tracing::debug!("transition pull: insert {id_hex}: {e}");
                    state.transition_pull_errors_total.fetch_add(1, Relaxed);
                    continue;
                }
            }
        };

        persist_pending_entry(state, &id);

        if inserted_new {
            state.transition_pulled_total.fetch_add(1, Relaxed);
        }

        // Same cosign + per-sig gossip path as the /propose handler.
        if let Some(our_sig) = maybe_cosign_transition(state, &id) {
            super::super::gossip::push_transition_sig_to_peers(state, id, &our_sig).await;
            persist_pending_entry(state, &id);
        }
    }
}

/// Response returned by `POST /transitions/propose`.
#[derive(serde::Serialize)]
pub struct ProposeResponse {
    pub id: String,
    pub status: String,
    pub threshold: usize,
    pub sigs_collected: usize,
}

pub async fn propose_transition(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<ProposeBody>,
) -> Result<Json<ProposeResponse>, AppError> {
    let threshold = body.required_threshold();

    // Structural validation first — cheap, and `seal_hash_for_sig` requires
    // a well-formed seal to produce stable bytes.
    body.validate_structure().map_err(AppError::from)?;

    // Temporal validation — structural checks can't catch a client that
    // submits a seal with `proposed_at_epoch` far in the future (DoS: fill
    // MAX_PENDING_TRANSITIONS with never-closing windows) or far in the
    // past (replay: effective_epoch already behind current_epoch). Both
    // cases get a 400 here so they never touch the store.
    //
    // Only enforced when state_core is initialised — on a pre-boot node
    // we don't know the epoch, so we can't compare. Production nodes
    // have state_core set before HTTP accepts traffic; this shape keeps
    // the test harness (which may construct NodeState without a state
    // core) wiring-free.
    if let Some(core) = state.state_core.get() {
        let current_epoch = core.read_snapshot().current_epoch;
        if body.proposed_at_epoch > current_epoch.saturating_add(PROPOSAL_MAX_LEAD_EPOCHS) {
            return Err(AppError::from(ElaraError::Wire(format!(
                "proposed_at_epoch {} is more than {} epochs ahead of current_epoch {}",
                body.proposed_at_epoch, PROPOSAL_MAX_LEAD_EPOCHS, current_epoch
            ))));
        }
        if body.effective_epoch <= current_epoch {
            return Err(AppError::from(ElaraError::Wire(format!(
                "effective_epoch {} is not in the future (current_epoch {})",
                body.effective_epoch, current_epoch
            ))));
        }
    }

    // Verify every attached anchor sig against the seal hash using the
    // locally-registered pubkeys. Unknown anchors and bad sigs are both
    // rejected so the store never accumulates forged threshold weight.
    // Empty sig sets are fine — the proposal enters AwaitingSigs and other
    // anchors fan in via `POST /transitions/{id}/sig`.
    let seal_hash = body.seal_hash_for_sig().map_err(AppError::from)?;
    let trust = state.transition_trust_view().await;
    for sig in &body.proposer_sigs {
        verify_anchor_sig(&state, sig, &seal_hash, &trust).map_err(AppError::from)?;
    }
    let sigs_collected = body.proposer_sigs.len();

    // Clone the seal before move-insert so we can hand it to the
    // gossip push below without a second CF read. Cloning is cheap
    // relative to the Dilithium3 verify already done above.
    let seal_for_gossip = body.clone();
    let id = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store
            .insert(body)
            .map_err(AppError::from)?
    };

    // Mirror to CF_TRANSITIONS_PENDING so a restart mid-window doesn't
    // drop the proposal. Best-effort — durability failure is logged but
    // doesn't fail the HTTP call.
    persist_pending_entry(&state, &id);

    // Gap 4 gossip: forward freshly-accepted proposals to peers so the
    // anchor set converges on the same seal. SeenSet dedup inside the
    // push fn prevents re-broadcast if the same seal loops back via
    // peer gossip. Spawned tasks run in the background — this does NOT
    // block the HTTP response. Skip in tests: with no connected peers
    // the fn early-returns anyway, but the `peers.read().await` is
    // enough to make the contract explicit.
    super::super::gossip::push_transition_seal_to_peers(&state, &seal_for_gossip).await;

    // Gap 4 anchor cosign: if we're an anchor and haven't signed this
    // proposal yet, add our sig locally and gossip it to peers. Without
    // this, orchestrator-proposed seals land 1-of-N on each anchor and
    // never reach threshold — they all expire. Cosign convergence is
    // what makes the M-of-N collection happen without a coordinator.
    if let Some(our_sig) = maybe_cosign_transition(&state, &id) {
        super::super::gossip::push_transition_sig_to_peers(&state, id, &our_sig).await;
        // Mirror the newly-signed entry so the cosigned state survives
        // a restart.
        persist_pending_entry(&state, &id);
    }

    let status = {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store
            .get(&id)
            .map(|p| status_label(p.status))
            .unwrap_or_else(|| "Unknown".into())
    };

    Ok(Json(ProposeResponse {
        id: hex::encode(id),
        status,
        threshold,
        sigs_collected,
    }))
}

/// Response shape for `GET /transitions/{id}`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransitionView {
    pub id: String,
    pub status: String,
    pub seal: TransitionSeal,
    pub vetoes: Vec<TransitionVeto>,
    pub threshold: usize,
    pub sigs_collected: usize,
    pub window_open: bool,
    pub current_epoch: u64,
}

pub async fn fetch_transition(
    State(state): State<Arc<NodeState>>,
    Path(id_hex): Path<String>,
) -> Result<Json<TransitionView>, AppError> {
    let id = decode_id(&id_hex)?;
    let current_epoch = best_effort_current_epoch(&state);

    // Fast path: still in the in-memory pending store (AwaitingSigs /
    // DisputeWindow / just-Finalized-pre-prune / Vetoed / Expired).
    {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        if let Some(pending) = store.get(&id) {
            let window_open = current_epoch < pending.seal.effective_epoch
                && current_epoch >= pending.seal.proposed_at_epoch
                && !matches!(
                    pending.status,
                    PendingStatus::Vetoed
                        | PendingStatus::Expired
                        | PendingStatus::Finalized
                );

            return Ok(Json(TransitionView {
                id: pending.id_hex(),
                status: status_label(pending.status),
                seal: pending.seal.clone(),
                vetoes: pending.vetoes.clone(),
                threshold: pending.seal.required_threshold(),
                sigs_collected: pending.seal.proposer_sigs.len(),
                window_open,
                current_epoch,
            }));
        }
    }

    // Fallback: the proposal has been pruned from the hot store but the
    // applied seal lives on in CF_TRANSITIONS_FINAL. Fetch it so clients
    // can deep-link by id long after the dispute window closed without
    // needing to paginate through /transitions/finalized.
    //
    // Vetoes are intentionally not retained on the finalized CF row —
    // once a proposal finalizes, any accumulated vetoes were below the
    // halt threshold and no longer have causal effect.
    if let Some(bytes) = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id)
        .map_err(AppError::from)?
    {
        let seal: TransitionSeal = serde_json::from_slice(&bytes)
            .map_err(|e| ElaraError::Storage(format!("finalized seal decode: {e}")))?;
        let threshold = seal.required_threshold();
        let sigs_collected = seal.proposer_sigs.len();
        return Ok(Json(TransitionView {
            id: id_hex,
            status: "Finalized".to_string(),
            seal,
            vetoes: Vec::new(),
            threshold,
            sigs_collected,
            window_open: false,
            current_epoch,
        }));
    }

    Err(ElaraError::RecordNotFound(format!("transition {id_hex}")).into())
}

/// Compact per-entry summary returned by `GET /transitions`.
/// Keeps the response small — clients wanting the full seal call
/// `GET /transitions/{id}`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransitionSummary {
    pub id: String,
    pub status: String,
    /// "Split" or "Merge" — matches `TransitionKind` Debug.
    pub kind: String,
    pub proposed_at_epoch: u64,
    pub effective_epoch: u64,
    pub threshold: usize,
    pub sigs_collected: usize,
    pub vetoes_count: usize,
    /// Parent zone ids in canonical order.
    pub parents: Vec<String>,
    /// Child zone ids in canonical order.
    pub children: Vec<String>,
    pub window_open: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransitionListResponse {
    pub count: usize,
    pub current_epoch: u64,
    pub transitions: Vec<TransitionSummary>,
    /// Total entries matched before pagination was applied. Only populated
    /// by paginated endpoints (`/transitions/finalized`); `None` for the
    /// pending list where `count` is already total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Query params for `GET /transitions/finalized`. All fields optional —
/// a bare request returns the default page size from offset 0.
///
/// `kind` narrows the response to just Split or just Merge seals,
/// applied BEFORE pagination so `total` reflects the filtered set. This
/// keeps pagination pointers coherent for clients iterating by kind.
///
/// `since_epoch` returns only seals whose `effective_epoch >=
/// since_epoch`. Lets clients (light-client followers, explorer UIs)
/// incrementally poll "anything new since my last pull" without
/// re-scanning history. Applied BEFORE pagination + sort so `total` is
/// the filtered count.
///
/// `until_epoch` returns only seals whose `effective_epoch <=
/// until_epoch`. Inclusive upper bound. Combined with `since_epoch`
/// gives clients epoch-range queries — e.g. "show me all transitions
/// that took effect between epoch N and M" for timeline views.
///
/// `zone` returns only seals that reference the given zone_id in either
/// their `parents` or `children` list. Lets zone-operators filter the
/// history to "transitions that affected MY zone" — including splits
/// that produced it and merges that consumed it. Query value is
/// normalized via `ZoneId::new`, so case/trailing-slash variants match.
///
/// All filters combine with AND semantics.
#[derive(serde::Deserialize, Default)]
pub struct ListFinalizedParams {
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub since_epoch: Option<u64>,
    #[serde(default)]
    pub until_epoch: Option<u64>,
    #[serde(default)]
    pub zone: Option<String>,
}

/// Query params for `GET /transitions`. Optional `kind` filter narrows
/// the response to just Split or just Merge proposals — operators see
/// "N splits pending" in `/transitions/stats` and can drill into just
/// those without client-side filtering of the full list.
///
/// Optional `status` filter narrows the response to a specific lifecycle
/// stage (`awaitingsigs`, `disputewindow`, `vetoed`, `finalized`,
/// `expired`). Symmetric to `kind`: case-insensitive, unknown values 400.
///
/// Optional `zone` filter narrows to proposals whose `parents` or
/// `children` list references the given zone_id. Symmetric to the
/// filter on `/transitions/finalized`. Normalized via `ZoneId::new`.
///
/// All filters AND together when multiple are set.
///
/// Values are case-insensitive ("split", "Split", "SPLIT" all accepted).
/// Unknown values are rejected at 400 to catch typos early rather than
/// silently returning an empty list.
#[derive(serde::Deserialize, Default)]
pub struct ListPendingParams {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
}

pub async fn list_transitions(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<ListPendingParams>,
) -> Result<Json<TransitionListResponse>, AppError> {
    let current_epoch = best_effort_current_epoch(&state);

    // Parse `?kind=` up-front so a typo is a 400 rather than a silent
    // empty list. None means "all kinds" (no filter).
    let kind_filter: Option<TransitionKind> = match params.kind.as_deref() {
        None => None,
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "split" => Some(TransitionKind::Split),
            "merge" => Some(TransitionKind::Merge),
            other => {
                return Err(AppError::from(ElaraError::Wire(format!(
                    "unknown kind filter '{other}' — expected 'split' or 'merge'"
                ))));
            }
        },
    };

    // Parse `?zone=` up-front. Normalize via ZoneId::new so case /
    // trailing-slash variants match. None means "all zones".
    let zone_filter: Option<crate::network::zone::ZoneId> = params
        .zone
        .as_deref()
        .map(crate::network::zone::ZoneId::new);

    // Parse `?status=` the same way. Mirrors the lifecycle stages emitted
    // by `status_label`, case-insensitive. Operators drilling into "which
    // proposals are stuck in AwaitingSigs" don't have to client-side-filter
    // the full list.
    let status_filter: Option<PendingStatus> = match params.status.as_deref() {
        None => None,
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "awaitingsigs" => Some(PendingStatus::AwaitingSigs),
            "disputewindow" => Some(PendingStatus::DisputeWindow),
            "vetoed" => Some(PendingStatus::Vetoed),
            "finalized" => Some(PendingStatus::Finalized),
            "expired" => Some(PendingStatus::Expired),
            other => {
                return Err(AppError::from(ElaraError::Wire(format!(
                    "unknown status filter '{other}' — expected one of \
                     'awaitingsigs', 'disputewindow', 'vetoed', 'finalized', 'expired'"
                ))));
            }
        },
    };

    let store = state
        .transitions
        .read()
        .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;

    // Snapshot ids first, then build summaries. The ids() call is O(N)
    // but bounded by MAX_PENDING_TRANSITIONS (1024).
    let mut transitions: Vec<TransitionSummary> = store
        .ids()
        .into_iter()
        .filter_map(|id| {
            let pending = store.get(&id)?;
            // `?kind=` filter — skip entries whose kind doesn't match.
            if let Some(k) = kind_filter {
                if pending.seal.kind != k {
                    return None;
                }
            }
            // `?status=` filter — AND with kind when both set.
            if let Some(s) = status_filter {
                if pending.status != s {
                    return None;
                }
            }
            // `?zone=` filter — match zone_id in either parents or
            // children. Matches the semantics on /transitions/finalized.
            if let Some(needle) = zone_filter.as_ref() {
                let hit = pending.seal.parents.iter().any(|s| &s.zone_id == needle)
                    || pending.seal.children.iter().any(|s| &s.zone_id == needle);
                if !hit {
                    return None;
                }
            }
            let window_open = current_epoch < pending.seal.effective_epoch
                && current_epoch >= pending.seal.proposed_at_epoch
                && !matches!(
                    pending.status,
                    PendingStatus::Vetoed
                        | PendingStatus::Expired
                        | PendingStatus::Finalized
                );
            Some(TransitionSummary {
                id: pending.id_hex(),
                status: status_label(pending.status),
                kind: format!("{:?}", pending.seal.kind),
                proposed_at_epoch: pending.seal.proposed_at_epoch,
                effective_epoch: pending.seal.effective_epoch,
                threshold: pending.seal.required_threshold(),
                sigs_collected: pending.seal.proposer_sigs.len(),
                vetoes_count: pending.vetoes.len(),
                parents: pending
                    .seal
                    .parents
                    .iter()
                    .map(|z| z.zone_id.to_string())
                    .collect(),
                children: pending
                    .seal
                    .children
                    .iter()
                    .map(|z| z.zone_id.to_string())
                    .collect(),
                window_open,
            })
        })
        .collect();

    // Stable ordering: soonest-effective first, then by id hex for ties.
    // Operators scanning the list for urgency want near-window proposals
    // at the top.
    transitions.sort_by(|a, b| {
        a.effective_epoch
            .cmp(&b.effective_epoch)
            .then_with(|| a.id.cmp(&b.id))
    });

    Ok(Json(TransitionListResponse {
        count: transitions.len(),
        current_epoch,
        transitions,
        total: None,
        offset: None,
        limit: None,
    }))
}

/// Hard cap on the number of finalized entries read from the CF in a
/// single request. At ~4096, a full scan is still a few MB and bounded.
/// Real fleet usage per-zone stays well below this for a long time.
/// How far ahead of `current_epoch` a client may propose a transition.
/// A modest lead absorbs operator clock skew between anchors without
/// letting an attacker park DoS proposals hundreds of epochs in the
/// future to churn through `MAX_PENDING_TRANSITIONS` store capacity.
///
/// Concrete semantics enforced in `propose_transition`:
/// * `proposed_at_epoch <= current_epoch + PROPOSAL_MAX_LEAD_EPOCHS`
/// * `effective_epoch > current_epoch` (a proposal whose window already
///   closed is indistinguishable from attacker replay — reject upfront
///   rather than let tick() silently expire it).
pub const PROPOSAL_MAX_LEAD_EPOCHS: u64 = 2;

pub const FINALIZED_LIST_MAX: usize = 4096;

/// Default page size when the client doesn't pass `?limit=`. Chosen to
/// keep a single response modest (a few hundred KB of JSON).
pub const FINALIZED_PAGE_DEFAULT: usize = 128;

/// Upper bound on a single page even if the client asks for more.
pub const FINALIZED_PAGE_MAX: usize = 1024;

// Compile-time invariants on the finalized-listing page-size ladder.
// FINALIZED_PAGE_DEFAULT must fit inside FINALIZED_PAGE_MAX (the
// no-`?limit=` default cannot exceed the explicit cap), and
// FINALIZED_PAGE_MAX must fit inside FINALIZED_LIST_MAX (a single page
// cannot exceed the bounded CF-scan budget that gates the storage
// layer scan). A future bump that violates either ordering would let
// one page silently overflow the bounded scan — surface that as a
// build error, not a runtime test failure.
const _: () = assert!(
    FINALIZED_PAGE_DEFAULT <= FINALIZED_PAGE_MAX,
    "FINALIZED_PAGE_DEFAULT <= FINALIZED_PAGE_MAX — default page must not exceed page max"
);
const _: () = assert!(
    FINALIZED_PAGE_MAX <= FINALIZED_LIST_MAX,
    "FINALIZED_PAGE_MAX <= FINALIZED_LIST_MAX — single-page cap must not exceed the bounded CF-scan list cap"
);

pub async fn list_finalized_transitions(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<ListFinalizedParams>,
) -> Result<Json<TransitionListResponse>, AppError> {
    let current_epoch = best_effort_current_epoch(&state);

    // Normalize pagination. Clients can pass oversized limits and we'll
    // silently cap — this matches how list_transitions already hard-caps
    // MAX_PENDING_TRANSITIONS at the store level.
    let offset = params.offset.unwrap_or(0);
    let limit = params
        .limit
        .unwrap_or(FINALIZED_PAGE_DEFAULT)
        .min(FINALIZED_PAGE_MAX);

    // Parse `?kind=` the same way `list_transitions` does — case-
    // insensitive, unknown values 400 out rather than silently returning
    // an empty page.
    let kind_filter: Option<TransitionKind> = match params.kind.as_deref() {
        None => None,
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "split" => Some(TransitionKind::Split),
            "merge" => Some(TransitionKind::Merge),
            other => {
                return Err(AppError::from(ElaraError::Wire(format!(
                    "unknown kind filter '{other}' — expected 'split' or 'merge'"
                ))));
            }
        },
    };

    // Scan CF_TRANSITIONS_FINAL. This CF is persisted by run_transition_tick
    // when a DisputeWindow entry passes effective_epoch with no halting
    // veto; it's the orchestrator's (and light client's) source of truth
    // for applied transitions that outlive the in-memory store.
    let rows = state
        .rocks
        .list_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_FINAL,
            FINALIZED_LIST_MAX,
        )
        .map_err(AppError::from)?;

    let mut transitions: Vec<TransitionSummary> = Vec::with_capacity(rows.len());
    for (_key, value) in rows {
        let Ok(seal) = serde_json::from_slice::<TransitionSeal>(&value) else {
            // On-disk corruption — skip the row rather than fail the whole
            // response. `run_transition_tick` will re-persist if the seal
            // is still in the hot store; otherwise this is a manual-fix
            // situation for an operator.
            continue;
        };
        // Kind filter applied BEFORE push so `total` reflects the
        // filtered set — clients paging by kind get stable pointers.
        if let Some(k) = kind_filter {
            if seal.kind != k {
                continue;
            }
        }
        // `since_epoch` filter — inclusive lower bound. Clients polling
        // for "anything new since my last_seen" set since_epoch=last_seen+1
        // (or equal to last_seen if they want to replay the boundary).
        if let Some(since) = params.since_epoch {
            if seal.effective_epoch < since {
                continue;
            }
        }
        // `until_epoch` filter — inclusive upper bound. Combined with
        // `since_epoch` gives clients epoch-range queries for timeline
        // views.
        if let Some(until) = params.until_epoch {
            if seal.effective_epoch > until {
                continue;
            }
        }
        // `zone` filter — normalize via ZoneId::new to match the same
        // case/whitespace rules the seal itself was built with. Matches
        // when the zone appears in EITHER parents or children (splits
        // that produced it, merges that consumed it).
        if let Some(raw_zone) = params.zone.as_deref() {
            let needle = crate::network::zone::ZoneId::new(raw_zone);
            let hit = seal.parents.iter().any(|s| s.zone_id == needle)
                || seal.children.iter().any(|s| s.zone_id == needle);
            if !hit {
                continue;
            }
        }
        let id = match seal.seal_hash_for_sig() {
            Ok(h) => h,
            Err(_) => continue,
        };
        transitions.push(TransitionSummary {
            id: hex::encode(id),
            // By construction — the CF only receives seals after tick()
            // flipped them to Finalized.
            status: "Finalized".to_string(),
            kind: format!("{:?}", seal.kind),
            proposed_at_epoch: seal.proposed_at_epoch,
            effective_epoch: seal.effective_epoch,
            threshold: seal.required_threshold(),
            sigs_collected: seal.proposer_sigs.len(),
            vetoes_count: 0,
            parents: seal
                .parents
                .iter()
                .map(|z| z.zone_id.to_string())
                .collect(),
            children: seal
                .children
                .iter()
                .map(|z| z.zone_id.to_string())
                .collect(),
            window_open: false,
        });
    }

    // Most-recent-effective-first ordering — operators inspecting the
    // recent finality log usually want the newest applied transition at
    // the top of the response. Sort BEFORE paginating so pages remain
    // stable against CF key-order (which is random seal-hash bytes).
    transitions.sort_by(|a, b| {
        b.effective_epoch
            .cmp(&a.effective_epoch)
            .then_with(|| a.id.cmp(&b.id))
    });

    let total = transitions.len();
    let page: Vec<TransitionSummary> = transitions
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    Ok(Json(TransitionListResponse {
        count: page.len(),
        current_epoch,
        transitions: page,
        total: Some(total),
        offset: Some(offset),
        limit: Some(limit),
    }))
}

/// Response for `GET /transitions/stats`. Aggregates in-memory store
/// counts with the durable `CF_TRANSITIONS_FINAL` count so operators can
/// watch Gap 4 lifecycle health in one request.
#[derive(serde::Serialize)]
pub struct TransitionStatsResponse {
    pub current_epoch: u64,
    /// Protocol parameter — epochs a TransitionSeal spends in the
    /// dispute window after `proposed_at_epoch` before becoming
    /// applicable. Echoed back so client tooling can render
    /// "time until effective" / "dispute window closes in N" without
    /// hardcoding the constant. Sourced from
    /// `zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS`.
    pub dispute_window_epochs: u64,
    /// Hard cap on in-memory pending-store entries across all
    /// statuses (AwaitingSigs / DisputeWindow / Vetoed / Finalized /
    /// Expired combined — the pre-prune slice that shares the
    /// MAX_PENDING_TRANSITIONS budget). Echoed back so dashboards
    /// can render `pending_total / pending_capacity` saturation
    /// without hardcoding the constant. Once saturation approaches
    /// 1.0 honest proposals start getting rejected with
    /// `store_full` — an operator-visible red flag. Sourced from
    /// `transition_store::MAX_PENDING_TRANSITIONS`.
    pub pending_capacity: usize,
    /// Monotone count of entries evicted from the in-memory store
    /// because capacity was hit at insert time. Zero in steady state.
    /// Non-zero means the pending store is under pressure — usually
    /// a flood of future-dated or duplicate seals. The counter
    /// resets on process restart (lives in RAM next to the store);
    /// compare to `boot_replayed_total` to reason about
    /// restart-adjacent churn.
    pub evictions_total: u64,
    /// Monotone count of fresh proposals accepted into the in-memory
    /// store since process start (re-inserts that only merge sigs do
    /// NOT count). Paired with `evictions_total`, the ratio
    /// `evictions_total / proposals_accepted_total` is the eviction
    /// rate — the share of all seen proposals that lost their slot
    /// to capacity pressure. Resets on process restart.
    pub proposals_accepted_total: u64,
    /// Snapshot of pending-store status counts (includes pre-prune
    /// Finalized/Vetoed entries still retained in the hot store).
    pub pending: StatusCounts,
    /// Total pending-store entries across all statuses.
    pub pending_total: usize,
    /// Split vs Merge breakdown of the same pending-store entries.
    /// `pending_by_kind.total()` equals `pending_total`.
    pub pending_by_kind: KindCounts,
    /// Per-reason breakdown of every veto currently attached to any
    /// pending entry. Empty (all zeros) when no vetoes are outstanding.
    /// `Other`-reason vetoes are lumped into the `other` bucket.
    pub pending_vetoes_by_reason: VetoReasonCounts,
    /// Number of pending entries that carry at least one veto —
    /// distinct from `pending.vetoed`, which only counts entries whose
    /// veto total reached `MIN_VETOES_TO_HALT`. A proposal with one
    /// veto is still AwaitingSigs/DisputeWindow but being contested;
    /// surfacing it lets operators see "contested but not yet halted"
    /// at a glance ("watch for the second veto").
    pub proposals_with_vetoes: usize,
    /// Durable count from `CF_TRANSITIONS_FINAL`. May exceed
    /// `pending.finalized` because the CF retains entries past the
    /// in-memory retention window.
    pub finalized_durable: usize,
    /// Number of pending entries re-hydrated from `CF_TRANSITIONS_PENDING`
    /// at the last boot. Zero on a clean restart (no in-flight proposals)
    /// or on the first-ever boot of this node. Non-zero means the
    /// durability mirror caught mid-window proposals that would otherwise
    /// have been lost — useful for confirming Gap 4 persistence after a
    /// restart.
    pub boot_replayed_total: u64,
    /// Count of failures writing to or deleting from
    /// `CF_TRANSITIONS_PENDING` during `persist_pending_entry`. Zero
    /// in steady state. Non-zero means the durability mirror is
    /// degrading — a restart mid-window would lose the dropped
    /// mutations. Each failure is individually logged; this counter
    /// exists for alerting against a trend, not per-incident debug.
    pub mirror_write_failures_total: u64,
    /// Soonest `effective_epoch` across active-lifecycle pending entries
    /// (`AwaitingSigs` | `DisputeWindow`). `None` when no active entries
    /// remain — no window to watch. Operators diff this against
    /// `current_epoch` to get "next window closes in N epochs" at a
    /// glance without fetching the full list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nearest_effective_epoch: Option<u64>,
    /// Oldest `proposed_at_epoch` across active-lifecycle pending
    /// entries (`AwaitingSigs` | `DisputeWindow`). `None` when no
    /// active entries remain. Operators diff this against
    /// `current_epoch` to flag stuck in-flight proposals that have
    /// been waiting unusually long without flipping terminal — the
    /// companion to `nearest_effective_epoch`, which answers "how
    /// soon does the NEXT window close?" where this answers "how
    /// long has the LONGEST-WAITING one been sitting?"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_active_proposed_at_epoch: Option<u64>,
    /// Latest `effective_epoch` across the durable finalized CF page.
    /// `None` when the CF is empty or decoding of every row failed.
    /// Answers "when did our most recent zone transition actually take
    /// effect?" without the client paging through /transitions/finalized.
    /// Bounded by the same FINALIZED_LIST_MAX page the count uses, so
    /// the answer is authoritative for the current operator view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_durable_latest_epoch: Option<u64>,
    /// Oldest `effective_epoch` across the durable finalized CF page.
    /// `None` on the same conditions as the latest counterpart. Diffed
    /// against `finalized_durable_latest_epoch` gives the operator the
    /// epoch-span of the local CF view — useful for reasoning about
    /// checkpoint consolidation windows (Gap 3) and how much history a
    /// restarting node already has on disk vs. still needs to sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_durable_oldest_epoch: Option<u64>,
    /// Split vs Merge breakdown across the durable finalized CF page.
    /// Aggregated from the same scan that produces `finalized_durable`,
    /// so `finalized_durable_by_kind.total()` equals `finalized_durable`
    /// when every row decodes cleanly. Lets operators see the
    /// long-run mix of zone splits vs merges without paging through
    /// `/transitions/finalized?kind=...` twice.
    pub finalized_durable_by_kind: KindCounts,
    /// Monotone count of TransitionSeals proposed by the local
    /// auto-scale orchestrator (`propose_transition_from_decision`)
    /// and successfully inserted into the in-memory pending store.
    /// Distinct from `proposals_accepted_total`, which counts every
    /// accepted proposal regardless of origin (gossip, API, or
    /// orchestrator). Ratio `orchestrator_proposed_total /
    /// proposals_accepted_total` is the share of pending traffic
    /// this node originated — useful for diagnosing whether a
    /// single anchor is over-participating. Resets on process
    /// restart (lives next to the counter on `NodeState`).
    pub orchestrator_proposed_total: u64,
    /// Monotone count of orchestrator proposal attempts rejected at
    /// insert time (duplicate seal, store full, or any other
    /// `TransitionStore::insert` failure). Zero in steady state.
    /// Paired with `orchestrator_proposed_total`, the ratio reveals
    /// how often the local orchestrator is stepping on an already
    /// in-flight proposal — a gossip-in-flight race, not a bug. A
    /// sustained high ratio means the orchestrator is rescheduling
    /// work other anchors already proposed; a decision-cadence
    /// review is in order.
    pub orchestrator_insert_rejected_total: u64,
    /// Monotone count of orchestrator ticks where the local node would
    /// have proposed a Split or Merge but the registered+staked anchor
    /// pool is below the kind's M-of-N threshold (4 for Split, 7 for
    /// Merge). The proposal would expire dead-on-arrival without ever
    /// reaching threshold, so we skip it. A persistently growing value
    /// means operators must add more anchors before that transition
    /// kind can finalize on this fleet — e.g. the testnet has 2 anchors
    /// vs `MERGE_ANCHOR_THRESHOLD = 7` so live merges are blocked
    /// until the anchor pool grows.
    #[serde(default)]
    pub orchestrator_skipped_undersized_pool_total: u64,
    /// Monotone count of TransitionSeals that this node observed
    /// flipping `DisputeWindow → Finalized` in `run_transition_tick`.
    /// Local-node, not consensus-global — peers may flip the same
    /// seal at different ticks if clocks drift or gossip lags. Equals
    /// `finalized_split_total + finalized_merge_total` after each
    /// tick completes.
    pub finalized_total: u64,
    /// Split-kind subset of `finalized_total`.
    pub finalized_split_total: u64,
    /// Merge-kind subset of `finalized_total`.
    pub finalized_merge_total: u64,
    /// Monotone count of TransitionSeals that this node observed
    /// flipping `AwaitingSigs → Expired` (proposal reached
    /// `effective_epoch` without the sig threshold). Zero in steady
    /// state. A non-zero and growing value signals the anchor set
    /// is failing to collect signatures inside the window — either
    /// anchor reachability is broken, the dispute window is too
    /// tight, or anchor rotation hasn't caught up with current
    /// epoch registrations.
    pub expired_total: u64,
    /// Monotone count of TransitionSeals broadcast by this node via
    /// `push_transition_seal_to_peers` (once per unique seal, not per
    /// peer). Incremented whether the orchestrator or the HTTP
    /// `/transitions/propose` handler originated the broadcast — both
    /// share the `transition_seen` dedup set. Zero on a node that
    /// has never originated or forwarded a proposal.
    pub gossip_pushed_total: u64,
    /// Monotone count of broadcast attempts skipped because the seal
    /// was already in `transition_seen`. Paired with
    /// `gossip_pushed_total`, a high ratio means peers re-broadcast
    /// seals we already forwarded — expected under normal gossip
    /// convergence, not a bug. A sustained >10× ratio vs `pushed`
    /// suggests tuning fan-out or TTL.
    pub gossip_dedup_total: u64,
    /// Monotone count of per-anchor `AnchorSig` broadcasts this node
    /// originated or relayed — once per unique (seal, anchor) pair.
    /// Incremented whether the cosign path (proposer end) or the
    /// `submit_sig` handler (relay end) produced it. Paired with
    /// `sig_gossip_dedup_total` to gauge sig-convergence cost.
    pub sig_gossip_pushed_total: u64,
    /// Monotone count of sig-broadcast attempts skipped because the
    /// (seal, anchor) pair was already seen. Non-zero in steady state
    /// is normal — the same sig reaches each peer via its sqrt(n)
    /// neighbors, and dedup caps the fan-out.
    pub sig_gossip_dedup_total: u64,
    /// Monotone count of gossiped TransitionSeals this node auto-cosigned
    /// because its own identity is an Anchor. Zero on non-anchor nodes.
    /// A non-zero value proves the anchor rotation + cosign pipeline is
    /// live — without it, orchestrator proposals land 1-of-N on each
    /// anchor, never reach threshold, and expire.
    pub cosigns_total: u64,
    /// Monotone count of TransitionSeals this node pulled from a peer's
    /// `/transitions` list and inserted into the local store. Non-zero
    /// means gossip dropped a seal and the pull backstop recovered it.
    /// On a healthy fleet this should stay near zero; a sustained
    /// non-zero rate flags gossip-fan-out regressions or partitions.
    pub pulled_total: u64,
    /// Monotone count of pull failures: list fetch errors, per-id
    /// fetch errors, decode errors, id-mismatch served by peer, or
    /// sigs that failed local registry verification. Per-peer
    /// misbehaviour signal.
    pub pull_errors_total: u64,
}

pub async fn transition_stats(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<TransitionStatsResponse>, AppError> {
    let current_epoch = best_effort_current_epoch(&state);

    let (
        pending,
        pending_total,
        pending_by_kind,
        pending_vetoes_by_reason,
        proposals_with_vetoes,
        nearest,
        oldest,
        evictions_total,
        proposals_accepted_total,
    ) = {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        let counts = store.status_counts();
        let kinds = store.kind_counts();
        let reasons = store.veto_reason_counts();
        let contested = store.proposals_with_vetoes_count();
        let nearest = store.nearest_effective_epoch();
        let oldest = store.oldest_active_proposed_at_epoch();
        let evictions = store.evictions_total();
        let accepted = store.proposals_accepted_total();
        let total = counts.total();
        (
            counts, total, kinds, reasons, contested, nearest, oldest, evictions, accepted,
        )
    };

    // CF scan is bounded by FINALIZED_LIST_MAX so a huge history doesn't
    // turn /stats into a latency cliff. Real-world fleet CF size stays
    // well under that cap. One pass computes count, latest + oldest
    // effective_epoch, and the Split/Merge breakdown across the page —
    // four operator-visible dimensions from the same I/O.
    let (
        finalized_durable,
        finalized_durable_latest_epoch,
        finalized_durable_oldest_epoch,
        finalized_durable_by_kind,
    ) = state
        .rocks
        .list_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_FINAL,
            FINALIZED_LIST_MAX,
        )
        .map(|rows| {
            let count = rows.len();
            let mut latest: Option<u64> = None;
            let mut oldest: Option<u64> = None;
            let mut kinds = KindCounts::default();
            for (_k, v) in rows.iter() {
                if let Ok(seal) = serde_json::from_slice::<TransitionSeal>(v) {
                    latest = Some(latest.map_or(seal.effective_epoch, |m| m.max(seal.effective_epoch)));
                    oldest = Some(oldest.map_or(seal.effective_epoch, |m| m.min(seal.effective_epoch)));
                    match seal.kind {
                        crate::network::zone_transition_seal::TransitionKind::Split => {
                            kinds.split += 1;
                        }
                        crate::network::zone_transition_seal::TransitionKind::Merge => {
                            kinds.merge += 1;
                        }
                    }
                }
            }
            (count, latest, oldest, kinds)
        })
        .unwrap_or((0, None, None, KindCounts::default()));

    let boot_replayed_total = state
        .transitions_boot_replayed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let mirror_write_failures_total = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let orchestrator_proposed_total = state
        .transitions_proposed_by_orchestrator_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let orchestrator_insert_rejected_total = state
        .transitions_orchestrator_insert_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let orchestrator_skipped_undersized_pool_total = state
        .transitions_orchestrator_skipped_undersized_pool_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let finalized_total = state
        .transitions_finalized_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let finalized_split_total = state
        .transitions_finalized_split_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let finalized_merge_total = state
        .transitions_finalized_merge_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let expired_total = state
        .transitions_expired_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pushed_total = state
        .transition_gossip_pushed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_dedup_total = state
        .transition_gossip_dedup_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sig_gossip_pushed_total = state
        .transition_sig_gossip_pushed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sig_gossip_dedup_total = state
        .transition_sig_gossip_dedup_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cosigns_total = state
        .transition_cosigns_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let pulled_total = state
        .transition_pulled_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let pull_errors_total = state
        .transition_pull_errors_total
        .load(std::sync::atomic::Ordering::Relaxed);

    Ok(Json(TransitionStatsResponse {
        current_epoch,
        dispute_window_epochs:
            crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS,
        pending_capacity: crate::network::transition_store::MAX_PENDING_TRANSITIONS,
        evictions_total,
        proposals_accepted_total,
        pending,
        pending_total,
        pending_by_kind,
        pending_vetoes_by_reason,
        proposals_with_vetoes,
        finalized_durable,
        boot_replayed_total,
        mirror_write_failures_total,
        nearest_effective_epoch: nearest,
        oldest_active_proposed_at_epoch: oldest,
        finalized_durable_latest_epoch,
        finalized_durable_oldest_epoch,
        finalized_durable_by_kind,
        orchestrator_proposed_total,
        orchestrator_insert_rejected_total,
        orchestrator_skipped_undersized_pool_total,
        finalized_total,
        finalized_split_total,
        finalized_merge_total,
        expired_total,
        gossip_pushed_total,
        gossip_dedup_total,
        sig_gossip_pushed_total,
        sig_gossip_dedup_total,
        cosigns_total,
        pulled_total,
        pull_errors_total,
    }))
}

/// Response for `GET /transitions/{id}/resolve/{account_hash}`.
#[derive(serde::Serialize)]
pub struct ResolveResponse {
    pub id: String,
    pub status: String,
    /// Hex of the queried account hash, echoed for client sanity.
    pub account_hash: String,
    /// Zone id this account routes to after `effective_epoch`. For Merge
    /// seals this is always the single child zone.
    pub post_transition_zone: String,
    /// `true` only for `Finalized` proposals. Clients should treat a
    /// resolution from a non-final seal as speculative — the underlying
    /// proposal may still veto or expire.
    pub final_binding: bool,
    pub effective_epoch: u64,
    pub current_epoch: u64,
}

pub async fn resolve_account(
    State(state): State<Arc<NodeState>>,
    Path((id_hex, account_hex)): Path<(String, String)>,
) -> Result<Json<ResolveResponse>, AppError> {
    let id = decode_id(&id_hex)?;
    let account_hash = decode_id(&account_hex)?;
    let current_epoch = best_effort_current_epoch(&state);

    // Phase 1: hot store. Pending proposals live here and carry
    // lifecycle state (AwaitingSigs / DisputeWindow / Vetoed /
    // Finalized / Expired) that only this store tracks.
    let hot = {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store.get(&id).map(|p| (p.seal.clone(), p.status, p.id_hex()))
    };

    if let Some((seal, status, id_hex_from_store)) = hot {
        let zone = seal
            .account_belongs_to_child(&account_hash)
            .ok_or_else(|| {
                ElaraError::Wire(
                    "seal structurally invalid — account_belongs_to_child returned None".into(),
                )
            })?
            .to_string();

        let final_binding = matches!(status, PendingStatus::Finalized);

        return Ok(Json(ResolveResponse {
            id: id_hex_from_store,
            status: status_label(status),
            account_hash: account_hex,
            post_transition_zone: zone,
            final_binding,
            effective_epoch: seal.effective_epoch,
            current_epoch,
        }));
    }

    // Phase 2: durable CF fallback. The hot store prunes old
    // Finalized / Expired entries to stay within MAX_PENDING_TRANSITIONS,
    // but CF_TRANSITIONS_FINAL retains applied seals long past that
    // window. A account holding an old transition id must still be able
    // to resolve "which zone do I route to?" — this is the whole point
    // of the seal being durable. Without this fallback the endpoint
    // 404s as soon as the hot store prunes the entry, even though the
    // answer is trivially derivable from the persisted seal.
    let seal_bytes = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id)
        .map_err(|e| ElaraError::Storage(format!("cf lookup: {e}")))?
        .ok_or_else(|| ElaraError::RecordNotFound(format!("transition {id_hex}")))?;
    let seal: TransitionSeal = serde_json::from_slice(&seal_bytes)
        .map_err(|e| ElaraError::Wire(format!("decode persisted seal: {e}")))?;

    let zone = seal
        .account_belongs_to_child(&account_hash)
        .ok_or_else(|| {
            ElaraError::Wire(
                "seal structurally invalid — account_belongs_to_child returned None".into(),
            )
        })?
        .to_string();

    // Seals in CF_TRANSITIONS_FINAL are Finalized by construction
    // (tick() only persists them after status flipped Finalized).
    // Clients reading this response can treat the routing as binding.
    Ok(Json(ResolveResponse {
        id: hex::encode(id),
        status: "Finalized".to_string(),
        account_hash: account_hex,
        post_transition_zone: zone,
        final_binding: true,
        effective_epoch: seal.effective_epoch,
        current_epoch,
    }))
}

/// Body accepted by `POST /transitions/{id}/veto`.
pub type VetoBody = TransitionVeto;

#[derive(serde::Serialize)]
pub struct VetoResponse {
    pub id: String,
    pub status: String,
    pub vetoes_count: usize,
}

pub async fn submit_veto(
    State(state): State<Arc<NodeState>>,
    Path(id_hex): Path<String>,
    Json(body): Json<VetoBody>,
) -> Result<Json<VetoResponse>, AppError> {
    let resp = compute_submit_veto(&state, id_hex, body).await?;
    Ok(Json(resp))
}

/// Shared veto-submit service-fn.
/// Verifies the vetoer's Dilithium3 signature, admits the veto into the
/// pending store, and persists the updated entry. Returns the post-state
/// status label and total veto count for this transition.
pub async fn compute_submit_veto(
    state: &Arc<NodeState>,
    id_hex: String,
    body: VetoBody,
) -> crate::errors::Result<VetoResponse> {
    let id = decode_id(&id_hex)?;
    let current_epoch = best_effort_current_epoch(state);

    // Cheap existence check before the expensive Dilithium3 verify. Without
    // this, an attacker who floods `/veto` with bogus ids burns ~ms per
    // request on signature verification before we reject at the store.
    {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        if store.get(&id).is_none() {
            return Err(ElaraError::RecordNotFound(format!(
                "transition {id_hex}"
            )));
        }
    }

    // Verify the vetoer's Dilithium3 signature before the store admits it.
    // `TransitionVeto::verify_sig` takes the pubkey bytes; resolve from the
    // identity CF the same way anchor sigs do.
    let vetoer_pk = state
        .rocks
        .get_public_key(&hex::encode(body.vetoer_identity_hash))
        .ok_or_else(|| ElaraError::Wire(format!(
            "vetoer pubkey not registered: {}",
            hex::encode(body.vetoer_identity_hash),
        )))?;
    body.verify_sig(&vetoer_pk)?;

    let (status, vetoes_count) = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store.add_veto(&id, body, current_epoch)?;
        let p = store
            .get(&id)
            .ok_or_else(|| ElaraError::RecordNotFound(format!("transition {id_hex}")))?;
        (status_label(p.status), p.vetoes.len())
    };

    // Mirror the updated entry (new veto, possibly new status) to the
    // pending CF so durability survives a restart.
    persist_pending_entry(state, &id);

    Ok(VetoResponse {
        id: id_hex,
        status,
        vetoes_count,
    })
}

/// Body accepted by `POST /transitions/{id}/sig`. A single anchor's
/// Dilithium3 signature over [`TransitionSeal::seal_hash_for_sig`] of the
/// targeted proposal.
pub type SigBody = AnchorSig;

#[derive(serde::Serialize)]
pub struct SigResponse {
    pub id: String,
    pub status: String,
    pub sigs_collected: usize,
    pub threshold: usize,
}

pub async fn submit_sig(
    State(state): State<Arc<NodeState>>,
    Path(id_hex): Path<String>,
    Json(body): Json<SigBody>,
) -> Result<Json<SigResponse>, AppError> {
    let id = decode_id(&id_hex)?;

    // Cheap existence check before the expensive Dilithium3 verify. Prevents
    // a flood of bogus-id /sig requests from burning signature-verify CPU
    // under gossip spam at fleet scale. Also closes a late-finalization race:
    // a sig arriving AFTER effective_epoch but BEFORE the next tick() could
    // otherwise flip AwaitingSigs → DisputeWindow → Finalized, even though
    // the dispute window has already closed. Rejecting past-window sigs
    // here — before add_sig runs — mirrors add_veto's `current_epoch >=
    // effective_epoch` guard so signatures and vetoes share the same
    // temporal semantics: no mutation of the seal after its window closed.
    //
    // Only enforced when state_core is initialized — in tests without one
    // the guard would always fire (current_epoch = 0). Production nodes
    // initialize state_core before HTTP accepts traffic, so the guard is
    // always live in prod.
    {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        let Some(pending) = store.get(&id) else {
            return Err(AppError::from(ElaraError::RecordNotFound(format!(
                "transition {id_hex}"
            ))));
        };
        if let Some(core) = state.state_core.get() {
            let current_epoch = core.read_snapshot().current_epoch;
            if current_epoch >= pending.seal.effective_epoch {
                return Err(AppError::from(ElaraError::Wire(format!(
                    "dispute window closed — sig rejected (current_epoch {} >= effective_epoch {})",
                    current_epoch, pending.seal.effective_epoch
                ))));
            }
        }
    }

    // The id IS `seal_hash_for_sig()` of the target proposal — that's what
    // anchors signed. Verify before the store accepts the sig.
    let trust = state.transition_trust_view().await;
    verify_anchor_sig(&state, &body, &id, &trust).map_err(AppError::from)?;

    // Clone for gossip forwarding — the sig we just received is both
    // what goes into the store and what we fan out to peers. The
    // per-(seal,anchor) dedup inside push_transition_sig_to_peers
    // ensures a sig that looped back to us doesn't re-broadcast.
    let sig_for_gossip = body.clone();

    let (status, sigs_collected, threshold) = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store.add_sig(&id, body).map_err(AppError::from)?;
        let p = store
            .get(&id)
            .ok_or_else(|| ElaraError::RecordNotFound(format!("transition {id_hex}")))?;
        (
            status_label(p.status),
            p.seal.proposer_sigs.len(),
            p.seal.required_threshold(),
        )
    };

    // Mirror the updated entry (new sig, possibly status promoted to
    // DisputeWindow) to the pending CF for restart durability.
    persist_pending_entry(&state, &id);

    // Gap 4 sig gossip: relay the fresh sig to peers so anchors behind
    // us in the gossip tree also learn it. Per-(seal, anchor) dedup
    // prevents re-broadcast if the same sig arrives via multiple paths.
    super::super::gossip::push_transition_sig_to_peers(&state, id, &sig_for_gossip).await;

    Ok(Json(SigResponse {
        id: id_hex,
        status,
        sigs_collected,
        threshold,
    }))
}

pub(crate) fn status_label(s: PendingStatus) -> String {
    match s {
        PendingStatus::AwaitingSigs => "AwaitingSigs",
        PendingStatus::DisputeWindow => "DisputeWindow",
        PendingStatus::Vetoed => "Vetoed",
        PendingStatus::Finalized => "Finalized",
        PendingStatus::Expired => "Expired",
    }
    .to_string()
}

// ─── AUDIT-10 PQ-pure-client: compute fns for PQ router ──────────────────────
//
// Shared with `pq_transport::router::handle_list_transitions` and
// `handle_get_transition` so both the axum and PQ transports return
// byte-identical JSON without duplicating the store-walking logic.

/// PQ router helper: mirror of `list_transitions` filtered by optional
/// lifecycle status only. The PQ caller is the transition pull tick which
/// only filters by status; `kind` + `zone` filters aren't used over the PQ
/// wire today.
pub(crate) fn compute_list_transitions(
    state: &Arc<NodeState>,
    status_filter_raw: Option<String>,
) -> Result<TransitionListResponse, ElaraError> {
    let current_epoch = best_effort_current_epoch(state);

    let status_filter: Option<PendingStatus> = match status_filter_raw.as_deref() {
        None => None,
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "awaitingsigs" => Some(PendingStatus::AwaitingSigs),
            "disputewindow" => Some(PendingStatus::DisputeWindow),
            "vetoed" => Some(PendingStatus::Vetoed),
            "finalized" => Some(PendingStatus::Finalized),
            "expired" => Some(PendingStatus::Expired),
            other => {
                return Err(ElaraError::Wire(format!(
                    "unknown status filter '{other}'"
                )));
            }
        },
    };

    let store = state
        .transitions
        .read()
        .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;

    let mut transitions: Vec<TransitionSummary> = store
        .ids()
        .into_iter()
        .filter_map(|id| {
            let pending = store.get(&id)?;
            if let Some(s) = status_filter {
                if pending.status != s {
                    return None;
                }
            }
            let window_open = current_epoch < pending.seal.effective_epoch
                && current_epoch >= pending.seal.proposed_at_epoch
                && !matches!(
                    pending.status,
                    PendingStatus::Vetoed
                        | PendingStatus::Expired
                        | PendingStatus::Finalized
                );
            Some(TransitionSummary {
                id: pending.id_hex(),
                status: status_label(pending.status),
                kind: format!("{:?}", pending.seal.kind),
                proposed_at_epoch: pending.seal.proposed_at_epoch,
                effective_epoch: pending.seal.effective_epoch,
                threshold: pending.seal.required_threshold(),
                sigs_collected: pending.seal.proposer_sigs.len(),
                vetoes_count: pending.vetoes.len(),
                parents: pending.seal.parents.iter().map(|z| z.zone_id.to_string()).collect(),
                children: pending.seal.children.iter().map(|z| z.zone_id.to_string()).collect(),
                window_open,
            })
        })
        .collect();

    transitions.sort_by(|a, b| {
        a.effective_epoch
            .cmp(&b.effective_epoch)
            .then_with(|| a.id.cmp(&b.id))
    });

    Ok(TransitionListResponse {
        count: transitions.len(),
        current_epoch,
        transitions,
        total: None,
        offset: None,
        limit: None,
    })
}

/// PQ router helper: mirror of `fetch_transition`. Accepts a hex id and
/// returns the `TransitionView` JSON the axum route builds.
pub(crate) fn compute_get_transition(
    state: &Arc<NodeState>,
    id_hex: &str,
) -> Result<TransitionView, ElaraError> {
    let bytes = hex::decode(id_hex)
        .map_err(|e| ElaraError::Wire(format!("invalid id hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ElaraError::Wire(format!(
            "id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    let current_epoch = best_effort_current_epoch(state);

    {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        if let Some(pending) = store.get(&id) {
            let window_open = current_epoch < pending.seal.effective_epoch
                && current_epoch >= pending.seal.proposed_at_epoch
                && !matches!(
                    pending.status,
                    PendingStatus::Vetoed
                        | PendingStatus::Expired
                        | PendingStatus::Finalized
                );
            return Ok(TransitionView {
                id: pending.id_hex(),
                status: status_label(pending.status),
                seal: pending.seal.clone(),
                vetoes: pending.vetoes.clone(),
                threshold: pending.seal.required_threshold(),
                sigs_collected: pending.seal.proposer_sigs.len(),
                window_open,
                current_epoch,
            });
        }
    }

    if let Some(bytes) = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id)
        .map_err(|e| ElaraError::Storage(format!("finalized cf read: {e}")))?
    {
        let seal: TransitionSeal = serde_json::from_slice(&bytes)
            .map_err(|e| ElaraError::Storage(format!("finalized seal decode: {e}")))?;
        let threshold = seal.required_threshold();
        let sigs_collected = seal.proposer_sigs.len();
        return Ok(TransitionView {
            id: id_hex.to_string(),
            status: "Finalized".to_string(),
            seal,
            vetoes: Vec::new(),
            threshold,
            sigs_collected,
            window_open: false,
            current_epoch,
        });
    }

    Err(ElaraError::RecordNotFound(format!("transition {id_hex}")))
}

fn decode_id(id_hex: &str) -> crate::errors::Result<[u8; 32]> {
    let bytes = hex::decode(id_hex)
        .map_err(|_| ElaraError::Wire(format!("invalid id hex: {id_hex}")))?;
    if bytes.len() != 32 {
        return Err(ElaraError::Wire(format!(
            "id must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Best-effort "current epoch" for the running node. Uses the state_core
/// snapshot when available; falls back to 0 during cold-boot (the store
/// treats `current_epoch < proposed_at_epoch` as "clock skew — reject veto",
/// which is a safer default than letting a pre-bootstrap node silently
/// accept or reject out-of-window vetoes).
fn best_effort_current_epoch(state: &NodeState) -> u64 {
    if let Some(core) = state.state_core.get() {
        return core.read_snapshot().current_epoch;
    }
    0
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
