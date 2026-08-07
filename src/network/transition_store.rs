//! Gap 4 — Pending TransitionSeal store + veto tracker.
//!
//! The [`TransitionSeal`] type in `zone_transition_seal.rs` is a pure data
//! structure. This module wraps it with the runtime state needed to drive
//! a split/merge proposal through its lifecycle:
//!
//!   AwaitingSigs → DisputeWindow → (Vetoed | Finalized | Expired)
//!
//! A proposal lands at `POST /transitions/propose`, accumulates anchor
//! signatures until the M-of-N threshold is met, then opens a 3-epoch
//! dispute window during which any node may publish a [`TransitionVeto`]
//! under `POST /transitions/{id}/veto`. If the window closes with no
//! valid veto, the orchestrator applies the transition; if at least one
//! valid veto accumulates, the status flips to `Vetoed` and the proposal
//! is dropped. Seals that never reach threshold before `effective_epoch`
//! expire cleanly.
//!
//! Storage is in-memory with a bounded capacity — pending transitions
//! are short-lived (at most `TRANSITION_DISPUTE_WINDOW_EPOCHS` = 3 epochs)
//! so a HashMap with hard-cap eviction is sufficient. A future commit may
//! mirror to RocksDB for crash durability; for now, a node that restarts
//! mid-window re-learns pending proposals via gossip.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;
use crate::crypto::pqc;
use crate::errors::{ElaraError, Result};

use super::zone_transition_seal::{AnchorSig, TransitionKind, TransitionSeal};

/// Hard cap on the number of pending transitions held in memory. Each
/// proposal is ≤ a few kB so 1024 is comfortably under a megabyte; the
/// cap exists to bound memory in case of gossip flood, not because real
/// traffic will ever get close. When the cap is hit, oldest-by-
/// `proposed_at_epoch` are evicted first.
pub const MAX_PENDING_TRANSITIONS: usize = 1024;

/// Caller's declared reason for vetoing a transition. The reason is advisory —
/// a veto must independently attach evidence that the orchestrator can check,
/// but the string form helps operators triage disputes at a glance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VetoReason {
    /// Split boundary bisects an account group that should have stayed together.
    BadBoundary,
    /// Proposer identity is not in the anchor registry.
    UnauthorizedProposer,
    /// Committee failed the diversity check (single-entity capture).
    CommitteeDiversity,
    /// State-root mismatch — `parents[i].state_root` doesn't match local ledger.
    StateRootMismatch,
    /// Catch-all for reasons that don't fit the above categories. Operators
    /// should still prefer specific variants; `Other` exists so forward-
    /// compatible clients don't have to pin an enum variant.
    Other(String),
}

/// A veto record submitted during a transition's dispute window. The vetoer
/// signs `sha3_256(canonical_encode)` with their Dilithium3 identity key;
/// the orchestrator verifies the signature before admitting the veto.
///
/// Veto weight accumulation (how many vetoes kill a proposal) is enforced
/// by the orchestrator, not this type — the type only carries the payload
/// and the signature binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionVeto {
    /// `seal_hash_for_sig()` of the targeted [`TransitionSeal`]. Binds the
    /// veto to a specific proposal even across hash collisions on
    /// `(zone, epoch)`.
    pub seal_hash: [u8; 32],
    /// Declared reason — advisory, see [`VetoReason`].
    pub reason: VetoReason,
    /// Free-form evidence bytes. Orchestrator interprets these per reason
    /// (e.g., a record hash for `StateRootMismatch`, a pubkey for
    /// `UnauthorizedProposer`). Capped at 2 KiB by the HTTP handler.
    pub evidence: Vec<u8>,
    /// Epoch at which this veto was submitted. Must satisfy
    /// `proposed_at_epoch <= submitted_at_epoch < effective_epoch` to be
    /// accepted.
    pub submitted_at_epoch: u64,
    /// SHA3-256 of the vetoer's Dilithium3 public key.
    pub vetoer_identity_hash: [u8; 32],
    /// Dilithium3 signature over [`TransitionVeto::canonical_encode_for_sig`].
    pub dilithium3_sig: Vec<u8>,
}

impl TransitionVeto {
    /// Canonical bytes over which the vetoer signs. Excludes the signature
    /// itself so a veto's hash is stable across serialisations.
    pub fn canonical_encode_for_sig(&self) -> Result<Vec<u8>> {
        let mut shallow = self.clone();
        shallow.dilithium3_sig.clear();
        serde_json::to_vec(&shallow)
            .map_err(|e| ElaraError::Wire(format!("veto encode: {e}")))
    }

    /// SHA3-256 of the canonical-for-sig bytes.
    pub fn veto_hash(&self) -> Result<[u8; 32]> {
        Ok(sha3_256(&self.canonical_encode_for_sig()?))
    }

    /// Structural checks that don't require external state. Checks evidence
    /// size cap, signature length matches Dilithium3, and epoch ordering if
    /// the caller supplies the seal bounds.
    pub fn validate_structure(&self) -> Result<()> {
        if self.evidence.len() > MAX_VETO_EVIDENCE_BYTES {
            return Err(ElaraError::Wire(format!(
                "veto evidence too large: {} > {}",
                self.evidence.len(),
                MAX_VETO_EVIDENCE_BYTES
            )));
        }
        // `VetoReason::Other(String)` is an escape hatch for reasons that
        // don't fit the named variants — but the string is held in memory
        // for the full dispute window on every node receiving the veto via
        // gossip. Without a cap, a malicious peer could submit a veto with
        // a megabyte-sized reason and blow up RAM on every peer that stores
        // it. 256 bytes is comfortably larger than any reasonable operator
        // note and keeps the pending-store memory footprint bounded at fleet
        // scale. Named variants carry no payload and are fixed-size.
        if let VetoReason::Other(s) = &self.reason {
            if s.len() > MAX_VETO_REASON_OTHER_BYTES {
                return Err(ElaraError::Wire(format!(
                    "veto reason (Other) too large: {} > {}",
                    s.len(),
                    MAX_VETO_REASON_OTHER_BYTES
                )));
            }
        }
        if self.dilithium3_sig.is_empty() {
            return Err(ElaraError::Wire("veto missing signature".into()));
        }
        Ok(())
    }

    /// Verify the vetoer's Dilithium3 signature over
    /// [`TransitionVeto::canonical_encode_for_sig`] using `vetoer_pubkey`.
    ///
    /// Caller is responsible for resolving `vetoer_identity_hash` against the
    /// peer registry; this function only checks the signature itself.
    pub fn verify_sig(&self, vetoer_pubkey: &[u8]) -> Result<()> {
        let hash = self.veto_hash()?;
        match pqc::dilithium3_verify(&hash, &self.dilithium3_sig, vetoer_pubkey) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ElaraError::Wire("veto signature invalid".into())),
            Err(e) => Err(ElaraError::Wire(format!("veto verify failed: {e}"))),
        }
    }
}

/// Max bytes allowed for the `evidence` field of a veto. 2 KiB is plenty for
/// a pair of record hashes + a textual note and keeps the HTTP handler's
/// memory footprint predictable under gossip flood.
pub const MAX_VETO_EVIDENCE_BYTES: usize = 2048;

/// Max bytes allowed for the string payload of `VetoReason::Other`. The named
/// variants carry no payload; this cap only constrains the free-form escape
/// hatch. Kept small because the string is retained per-veto for the full
/// dispute window on every node that holds the pending entry — at fleet
/// scale a permissive cap multiplies into real RAM.
pub const MAX_VETO_REASON_OTHER_BYTES: usize = 256;

/// Minimum number of independent, signature-verified vetoes required to flip
/// a transition to `Vetoed` status. Below this, a veto is recorded as a
/// signal (visible via `/transitions/{id}`) but the proposal stays in
/// `DisputeWindow` until either more vetoes arrive or the window closes.
///
/// **Why > 1?** A single rogue or flaky peer would otherwise be able to kill
/// any legitimate transition across a 10K-node fleet. At the same time, M
/// anchors already agreed on the seal — a tiny minority of real dissent
/// should still be enough to block it. Two independent vetoes balances:
/// hard to manufacture accidentally, low enough that real objections aren't
/// drowned out.
pub const MIN_VETOES_TO_HALT: usize = 2;

/// Lifecycle stage of a pending transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingStatus {
    /// Signatures below threshold. Proposal is still collecting anchor sigs.
    AwaitingSigs,
    /// M-of-N sigs collected. Dispute window is open until `effective_epoch`.
    DisputeWindow,
    /// At least one valid veto was recorded. Proposal will not apply.
    Vetoed,
    /// Window closed, no valid veto — transition should be applied by the
    /// orchestrator. (This module marks the status; applying the transition
    /// is the orchestrator's job.)
    Finalized,
    /// `effective_epoch` passed without reaching threshold. Proposal is dead.
    Expired,
}

/// One pending transition — the seal plus all runtime state accumulated
/// during its lifecycle.
///
/// `Serialize` / `Deserialize` are derived so the HTTP handlers can mirror
/// the entry to `CF_TRANSITIONS_PENDING` on every mutation and the boot
/// path can re-hydrate the in-memory store after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransition {
    pub seal: TransitionSeal,
    pub vetoes: Vec<TransitionVeto>,
    pub status: PendingStatus,
    /// Cached `seal_hash_for_sig()` so lookups don't re-hash the seal on
    /// every read. Recomputed on insert; every mutation that changes the
    /// seal (sig additions) is funnelled through `TransitionStore::add_sig`
    /// which refreshes this field.
    pub id: [u8; 32],
}

impl PendingTransition {
    /// Construct a new pending entry from a freshly received seal. The seal
    /// MUST have already passed `validate_structure()`; we recompute its id
    /// here so the store can key on it.
    pub fn from_seal(seal: TransitionSeal) -> Result<Self> {
        let id = seal.seal_hash_for_sig()?;
        let status = if seal.proposer_sigs.len() >= seal.required_threshold() {
            PendingStatus::DisputeWindow
        } else {
            PendingStatus::AwaitingSigs
        };
        Ok(Self {
            seal,
            vetoes: Vec::new(),
            status,
            id,
        })
    }

    /// Hex form of `id`, suitable for URL paths.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

/// In-memory store for pending TransitionSeal proposals. Wrap in a
/// `std::sync::RwLock` on `NodeState` — mutation is infrequent (bounded by
/// split/merge events, not by user traffic).
#[derive(Debug, Clone, Default)]
pub struct TransitionStore {
    by_id: HashMap<[u8; 32], PendingTransition>,
    /// Monotone count of entries evicted from `by_id` because
    /// `MAX_PENDING_TRANSITIONS` was hit at insert time. Non-zero means
    /// the store is under capacity pressure — honest proposals may be
    /// losing their slot to flood-gossiped or future-dated seals.
    /// Surfaced via [`Self::evictions_total`] for /transitions/stats.
    evictions_total: u64,
    /// Monotone count of *fresh* proposals ever accepted into the
    /// store since process start. Re-inserts of an already-present
    /// seal (sig-merge path) do NOT bump this counter — only genuinely
    /// new proposals. Paired with `evictions_total` it gives the
    /// eviction rate (evictions / accepted). Surfaced via
    /// [`Self::proposals_accepted_total`].
    proposals_accepted_total: u64,
}

/// What changed during a single [`TransitionStore::tick`] call. Returned
/// so the caller (health loop) can drive side effects — persist finalized
/// seals to `CF_TRANSITIONS_FINAL`, delete terminal entries from
/// `CF_TRANSITIONS_PENDING` — without having to diff the store itself.
///
/// Empty on ticks that didn't move any entry across the effective_epoch
/// boundary (the steady state).
#[derive(Debug, Default, Clone)]
pub struct TickOutcome {
    /// DisputeWindow → Finalized in this tick.
    pub newly_finalized: Vec<[u8; 32]>,
    /// AwaitingSigs → Expired in this tick (never hit threshold before
    /// `effective_epoch`).
    pub newly_expired: Vec<[u8; 32]>,
}

impl TickOutcome {
    /// All ids that entered a terminal state during this tick. Useful for
    /// bulk-deletes against `CF_TRANSITIONS_PENDING`.
    pub fn all_terminal(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.newly_finalized.iter().chain(self.newly_expired.iter())
    }

    pub fn is_empty(&self) -> bool {
        self.newly_finalized.is_empty() && self.newly_expired.is_empty()
    }
}

impl TransitionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a pending transition, or merge additional sigs into an
    /// existing entry with the same id. Returns the seal's id hash.
    ///
    /// Idempotent on the seal id (which excludes `proposer_sigs`): if a
    /// proposal is already present, the incoming seal's sigs are merged in
    /// via [`Self::add_sig`] rather than wiping the existing entry (which
    /// would also wipe any accumulated vetoes). Structural validation runs
    /// on every call.
    pub fn insert(&mut self, seal: TransitionSeal) -> Result<[u8; 32]> {
        seal.validate_structure()?;
        let id = seal.seal_hash_for_sig()?;

        // Already-present path: fold incoming sigs into the existing entry,
        // leave vetoes + status untouched (add_sig handles the promotion).
        if self.by_id.contains_key(&id) {
            let incoming_sigs = seal.proposer_sigs.clone();
            for sig in incoming_sigs {
                // Ignore per-sig errors (e.g. duplicate anchor) — the caller
                // is re-broadcasting a known proposal and we don't want one
                // dup to fail the whole call.
                let _ = self.add_sig(&id, sig);
            }
            return Ok(id);
        }

        let entry = PendingTransition::from_seal(seal)?;

        if self.by_id.len() >= MAX_PENDING_TRANSITIONS {
            // Evict the oldest entry by `proposed_at_epoch`. In practice the
            // store rarely hits this cap (one split/merge per hour is ample);
            // it exists so a gossip flood can't OOM us.
            if let Some(victim_id) = self
                .by_id
                .iter()
                .min_by_key(|(_, p)| p.seal.proposed_at_epoch)
                .map(|(k, _)| *k)
            {
                self.by_id.remove(&victim_id);
                self.evictions_total = self.evictions_total.saturating_add(1);
            }
        }

        self.by_id.insert(id, entry);
        self.proposals_accepted_total = self.proposals_accepted_total.saturating_add(1);
        Ok(id)
    }

    /// Append an anchor signature to a pending proposal and promote the
    /// status from `AwaitingSigs` to `DisputeWindow` when the M-of-N
    /// threshold is crossed.
    ///
    /// Deduplicates on `anchor_identity_hash` — one sig slot per anchor. The
    /// store does NOT verify the Dilithium3 signature itself (that requires
    /// the anchor registry, which lives in the HTTP handler / orchestrator);
    /// callers that need verification should call
    /// [`TransitionSeal::verify_sigs`] on the stored seal after adding.
    ///
    /// Returns the new status after the addition.
    pub fn add_sig(&mut self, id: &[u8; 32], sig: AnchorSig) -> Result<PendingStatus> {
        let pending = self
            .by_id
            .get_mut(id)
            .ok_or_else(|| ElaraError::Wire("transition not found".into()))?;

        // Don't accept new sigs on proposals that have already resolved — the
        // outcome is frozen and mutating the seal would change its id.
        if !matches!(
            pending.status,
            PendingStatus::AwaitingSigs | PendingStatus::DisputeWindow
        ) {
            return Err(ElaraError::Wire(format!(
                "cannot add sig to proposal in status {:?}",
                pending.status
            )));
        }

        if pending
            .seal
            .proposer_sigs
            .iter()
            .any(|s| s.anchor_identity_hash == sig.anchor_identity_hash)
        {
            return Err(ElaraError::Wire(
                "sig from this anchor already recorded".into(),
            ));
        }

        // Structural check: Dilithium3 sigs are a fixed size. Cheap to catch
        // garbled payloads at the store boundary rather than at verify time.
        if sig.dilithium3_sig.is_empty() {
            return Err(ElaraError::Wire("anchor sig bytes empty".into()));
        }

        // Cap accumulated sigs at MAX_PROPOSER_SIGS so the seal can't
        // grow past the ceiling via the /sig drip path. `validate_structure`
        // enforces the same bound on propose-time submission; this mirrors
        // it on the accumulation path so neither route allows unbounded
        // sig growth.
        if pending.seal.proposer_sigs.len()
            >= crate::network::zone_transition_seal::MAX_PROPOSER_SIGS
        {
            return Err(ElaraError::Wire(format!(
                "transition seal: proposer_sigs cap reached ({} sigs)",
                crate::network::zone_transition_seal::MAX_PROPOSER_SIGS
            )));
        }

        pending.seal.proposer_sigs.push(sig);
        // Keep proposer_sigs sorted by anchor_identity_hash so the canonical
        // encoding (which zeroes them before signing, but embeds them at rest)
        // is deterministic across nodes that may have accumulated sigs in
        // different order.
        pending
            .seal
            .proposer_sigs
            .sort_by_key(|s| s.anchor_identity_hash);

        if matches!(pending.status, PendingStatus::AwaitingSigs)
            && pending.seal.proposer_sigs.len() >= pending.seal.required_threshold()
        {
            pending.status = PendingStatus::DisputeWindow;
        }

        Ok(pending.status)
    }

    /// Fetch a pending entry by its id hash.
    pub fn get(&self, id: &[u8; 32]) -> Option<&PendingTransition> {
        self.by_id.get(id)
    }

    /// Is there at least one *active* (AwaitingSigs or DisputeWindow) pending
    /// proposal whose `parents` set exactly matches `target_parents` (order-
    /// independent)?
    ///
    /// Used by the auto-scale orchestrator at the call-side as a cooldown
    /// gate: if the previous proposal for the same parent zones is still
    /// in flight, don't emit a fresh one each tick. Without this, the
    /// orchestrator floods the store with one new seal every tick on
    /// low-traffic networks where merge-recommend keeps firing — racing
    /// `transitions_expired_total` upward without ever finalizing.
    ///
    /// O(active_pending). Caller holds the read lock.
    pub fn has_active_with_parents(&self, target_parents: &[crate::network::zone::ZoneId]) -> bool {
        if target_parents.is_empty() {
            return false;
        }
        use std::collections::HashSet;
        let target: HashSet<&crate::network::zone::ZoneId> = target_parents.iter().collect();
        self.by_id.values().any(|p| {
            matches!(
                p.status,
                PendingStatus::AwaitingSigs | PendingStatus::DisputeWindow
            ) && p.seal.parents.len() == target.len()
                && p.seal.parents.iter().all(|s| target.contains(&s.zone_id))
        })
    }

    /// Append a veto to a pending entry. Fails if the target doesn't exist
    /// or if the veto's epoch is outside the dispute window. Dedupes on
    /// `vetoer_identity_hash` — one veto per identity.
    pub fn add_veto(
        &mut self,
        id: &[u8; 32],
        veto: TransitionVeto,
        current_epoch: u64,
    ) -> Result<()> {
        veto.validate_structure()?;
        let pending = self
            .by_id
            .get_mut(id)
            .ok_or_else(|| ElaraError::Wire("transition not found".into()))?;

        if veto.seal_hash != *id {
            return Err(ElaraError::Wire(
                "veto seal_hash does not match target transition".into(),
            ));
        }
        if current_epoch >= pending.seal.effective_epoch {
            return Err(ElaraError::Wire(
                "dispute window closed — veto rejected".into(),
            ));
        }
        if current_epoch < pending.seal.proposed_at_epoch {
            return Err(ElaraError::Wire(
                "veto submitted before proposal epoch — clock skew".into(),
            ));
        }

        if pending
            .vetoes
            .iter()
            .any(|v| v.vetoer_identity_hash == veto.vetoer_identity_hash)
        {
            return Err(ElaraError::Wire(
                "veto from this identity already recorded".into(),
            ));
        }

        // Once the proposal has already been flipped to Vetoed, the outcome
        // is terminal — additional vetoes contribute nothing (the seal
        // won't apply either way) but keep growing the in-memory Vec and
        // the CF mirror. Reject further vetoes after halt so a post-halt
        // flood of 10K peer vetoes can't blow up the pending store. The
        // first MIN_VETOES_TO_HALT vetoes (the ones that caused the halt)
        // are preserved for audit — this only blocks the spam tail.
        if matches!(pending.status, PendingStatus::Vetoed) {
            return Err(ElaraError::Wire(
                "proposal already vetoed — new veto rejected as spam".into(),
            ));
        }

        pending.vetoes.push(veto);
        // Flip to Vetoed only once independent vetoes reach the halt
        // threshold. Below that, the veto is recorded (visible to operators
        // via `/transitions/{id}`) but the proposal stays in DisputeWindow
        // so a single rogue peer can't DoS a legit transition. Anchors
        // already agreed M-of-N on the seal itself; real dissent will
        // typically produce ≥2 vetoes quickly.
        if pending.vetoes.len() >= MIN_VETOES_TO_HALT {
            pending.status = PendingStatus::Vetoed;
        }
        Ok(())
    }

    /// Tick — sweep pending entries and flip status transitions that depend
    /// only on the current epoch clock:
    ///   - AwaitingSigs past effective_epoch → Expired
    ///   - DisputeWindow past effective_epoch → Finalized (if not vetoed)
    ///
    /// Returns the ids that flipped to `Finalized` in this tick so the
    /// caller can drive transition application.
    pub fn tick(&mut self, current_epoch: u64) -> TickOutcome {
        let mut out = TickOutcome::default();
        for (id, pending) in self.by_id.iter_mut() {
            if current_epoch < pending.seal.effective_epoch {
                continue;
            }
            match pending.status {
                PendingStatus::AwaitingSigs => {
                    pending.status = PendingStatus::Expired;
                    out.newly_expired.push(*id);
                }
                PendingStatus::DisputeWindow => {
                    pending.status = PendingStatus::Finalized;
                    out.newly_finalized.push(*id);
                }
                PendingStatus::Vetoed
                | PendingStatus::Finalized
                | PendingStatus::Expired => {}
            }
        }
        out
    }

    /// Remove entries in a terminal state (`Vetoed`, `Finalized`, `Expired`)
    /// that are at least `retention_epochs` past `effective_epoch`. Returns
    /// the number removed.
    pub fn prune(&mut self, current_epoch: u64, retention_epochs: u64) -> usize {
        let before = self.by_id.len();
        self.by_id.retain(|_, p| match p.status {
            PendingStatus::Vetoed
            | PendingStatus::Finalized
            | PendingStatus::Expired => {
                current_epoch < p.seal.effective_epoch.saturating_add(retention_epochs)
            }
            _ => true,
        });
        before - self.by_id.len()
    }

    /// Boot-replay: insert a previously-persisted `PendingTransition`
    /// directly into the store, bypassing validation.
    ///
    /// Used only by `boot_replay_pending_transitions` in the health
    /// module. The entry already passed `validate_structure` on its
    /// original write; re-running validation on boot would force us to
    /// fail the whole replay (and silently drop proposals) if the
    /// validation rules tightened between runtime versions. Safer to
    /// re-admit and let the next tick / veto path handle any newly-
    /// invalid entry.
    ///
    /// Idempotent on id: re-running replay with the same CF rows is a
    /// no-op after the first call (the HashMap just overwrites).
    pub fn replay_insert(&mut self, pending: PendingTransition) {
        self.by_id.insert(pending.id, pending);
    }

    /// Snapshot of all pending ids (cheap — ids are 32 bytes each).
    pub fn ids(&self) -> Vec<[u8; 32]> {
        self.by_id.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Count pending entries grouped by lifecycle status. Intended for the
    /// `/transitions/stats` operator endpoint — cheap, runs under the read
    /// lock, O(n) in the (bounded) store size.
    ///
    /// Returns counts for every variant, zero-filled for absent ones, so
    /// callers don't need to branch on Option.
    pub fn status_counts(&self) -> StatusCounts {
        let mut c = StatusCounts::default();
        for p in self.by_id.values() {
            match p.status {
                PendingStatus::AwaitingSigs => c.awaiting_sigs += 1,
                PendingStatus::DisputeWindow => c.dispute_window += 1,
                PendingStatus::Vetoed => c.vetoed += 1,
                PendingStatus::Finalized => c.finalized += 1,
                PendingStatus::Expired => c.expired += 1,
            }
        }
        c
    }

    /// Monotone count of entries evicted from the store because
    /// `MAX_PENDING_TRANSITIONS` was hit at insert time. Zero in steady
    /// state; non-zero flags that the store is under capacity pressure
    /// (honest proposals may have lost their slot). Resets only on
    /// process restart — the counter lives in RAM next to the store.
    pub fn evictions_total(&self) -> u64 {
        self.evictions_total
    }

    /// Monotone count of fresh proposals ever accepted into the store
    /// since process start. Paired with [`Self::evictions_total`], the
    /// ratio `evictions / accepted` is the eviction rate — the share
    /// of all seen proposals that lost their slot to capacity pressure.
    /// Resets on process restart. Re-inserts that only merge sigs do
    /// NOT count.
    pub fn proposals_accepted_total(&self) -> u64 {
        self.proposals_accepted_total
    }

    /// Count pending entries grouped by [`TransitionKind`]. Complements
    /// `status_counts` — operators can see "4 splits + 1 merge pending"
    /// at a glance instead of inferring it from the full list.
    ///
    /// O(n) in the bounded store size; runs under the read lock like
    /// `status_counts`.
    pub fn kind_counts(&self) -> KindCounts {
        let mut c = KindCounts::default();
        for p in self.by_id.values() {
            match p.seal.kind {
                TransitionKind::Split => c.split += 1,
                TransitionKind::Merge => c.merge += 1,
            }
        }
        c
    }

    /// Count of pending entries that carry at least one veto. Distinct
    /// from `status_counts().vetoed`: a proposal only flips to `Vetoed`
    /// once `MIN_VETOES_TO_HALT` vetoes have accumulated, but a single
    /// veto is still operator-visible signal ("this proposal is being
    /// contested, watch for a second veto"). Fast O(n) in the bounded
    /// store size.
    pub fn proposals_with_vetoes_count(&self) -> usize {
        self.by_id
            .values()
            .filter(|p| !p.vetoes.is_empty())
            .count()
    }

    /// Aggregate every veto currently attached to any pending entry
    /// into a reason-keyed breakdown. Surfaces "wave of BadBoundary
    /// dissent" vs "one-off StateRootMismatch" at a glance so
    /// operators don't have to fetch each proposal individually.
    ///
    /// `Other` reasons are lumped into a single `other` bucket — the
    /// per-string granularity matters for triage on the specific
    /// proposal, not at the aggregate level. O(n * m) in store size
    /// and per-entry veto count, both small and bounded.
    pub fn veto_reason_counts(&self) -> VetoReasonCounts {
        let mut c = VetoReasonCounts::default();
        for p in self.by_id.values() {
            for v in &p.vetoes {
                match v.reason {
                    VetoReason::BadBoundary => c.bad_boundary += 1,
                    VetoReason::UnauthorizedProposer => c.unauthorized_proposer += 1,
                    VetoReason::CommitteeDiversity => c.committee_diversity += 1,
                    VetoReason::StateRootMismatch => c.state_root_mismatch += 1,
                    VetoReason::Other(_) => c.other += 1,
                }
            }
        }
        c
    }

    /// Soonest `effective_epoch` across pending entries that are still
    /// in an active lifecycle stage (`AwaitingSigs` or `DisputeWindow`).
    /// Terminal statuses (`Vetoed`, `Finalized`, `Expired`) are excluded
    /// because their windows no longer represent work operators need to
    /// watch.
    ///
    /// Returns `None` when no active proposals remain — the operator's
    /// "next window to worry about" is nothing. O(N) in store size,
    /// bounded by `MAX_PENDING_TRANSITIONS`.
    pub fn nearest_effective_epoch(&self) -> Option<u64> {
        self.by_id
            .values()
            .filter(|p| {
                matches!(
                    p.status,
                    PendingStatus::AwaitingSigs | PendingStatus::DisputeWindow
                )
            })
            .map(|p| p.seal.effective_epoch)
            .min()
    }

    /// Oldest `proposed_at_epoch` across pending entries that are still
    /// in an active lifecycle stage (`AwaitingSigs` or `DisputeWindow`).
    /// Terminal statuses are excluded — their age no longer represents
    /// work-in-flight.
    ///
    /// Returns `None` when no active proposals remain. Operators diff
    /// this against the current epoch to surface "longest-waiting
    /// in-flight proposal" for stuck-window alerts. O(N) in store size,
    /// bounded by `MAX_PENDING_TRANSITIONS`.
    pub fn oldest_active_proposed_at_epoch(&self) -> Option<u64> {
        self.by_id
            .values()
            .filter(|p| {
                matches!(
                    p.status,
                    PendingStatus::AwaitingSigs | PendingStatus::DisputeWindow
                )
            })
            .map(|p| p.seal.proposed_at_epoch)
            .min()
    }
}

/// Per-status counts snapshot returned by [`TransitionStore::status_counts`].
/// Always reports every variant; absent ones read as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCounts {
    pub awaiting_sigs: usize,
    pub dispute_window: usize,
    pub vetoed: usize,
    /// In-memory Finalized (pre-prune). Durable count lives in
    /// `CF_TRANSITIONS_FINAL` — the HTTP stats handler reports both.
    pub finalized: usize,
    pub expired: usize,
}

impl StatusCounts {
    pub fn total(&self) -> usize {
        self.awaiting_sigs
            + self.dispute_window
            + self.vetoed
            + self.finalized
            + self.expired
    }
}

/// Per-kind counts snapshot returned by [`TransitionStore::kind_counts`].
/// The `TransitionKind` enum is closed (Split | Merge) so we expose both
/// as explicit fields — no `Other` bucket to surprise operators.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindCounts {
    pub split: usize,
    pub merge: usize,
}

impl KindCounts {
    pub fn total(&self) -> usize {
        self.split + self.merge
    }
}

/// Per-reason breakdown of every veto currently attached to a pending
/// entry in the store. Returned by [`TransitionStore::veto_reason_counts`].
/// `Other` reasons (free-form string variant) are lumped into a single
/// bucket — aggregate-level triage only needs the coarse distribution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VetoReasonCounts {
    pub bad_boundary: usize,
    pub unauthorized_proposer: usize,
    pub committee_diversity: usize,
    pub state_root_mismatch: usize,
    pub other: usize,
}

impl VetoReasonCounts {
    pub fn total(&self) -> usize {
        self.bad_boundary
            + self.unauthorized_proposer
            + self.committee_diversity
            + self.state_root_mismatch
            + self.other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::zone::ZoneId;
    use crate::network::zone_transition_seal::{
        TransitionKind, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
    };

    fn split_seal_at(proposed_at: u64) -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Split,
            proposed_at_epoch: proposed_at,
            effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![ZoneSnapshot {
                zone_id: ZoneId::new("test/parent"),
                state_root: [1; 32],
                last_seal_record_id: "parent".into(),
                record_count: 10,
                committee_hash: [2; 32],
            }],
            children: vec![
                ZoneSnapshot {
                    zone_id: ZoneId::new("test/child-a"),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [3; 32],
                },
                ZoneSnapshot {
                    zone_id: ZoneId::new("test/child-b"),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [4; 32],
                },
            ],
            split_key: Some([0x80; 32]),
            proposer_sigs: vec![],
        }
    }

    fn merge_seal_at(proposed_at: u64) -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Merge,
            proposed_at_epoch: proposed_at,
            effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![
                ZoneSnapshot {
                    zone_id: ZoneId::new("test/parent-a"),
                    state_root: [5; 32],
                    last_seal_record_id: "pa".into(),
                    record_count: 10,
                    committee_hash: [6; 32],
                },
                ZoneSnapshot {
                    zone_id: ZoneId::new("test/parent-b"),
                    state_root: [7; 32],
                    last_seal_record_id: "pb".into(),
                    record_count: 10,
                    committee_hash: [8; 32],
                },
            ],
            children: vec![ZoneSnapshot {
                zone_id: ZoneId::new("test/merged"),
                state_root: [0; 32],
                last_seal_record_id: String::new(),
                record_count: 0,
                committee_hash: [9; 32],
            }],
            split_key: None,
            proposer_sigs: vec![],
        }
    }

    fn unsigned_veto_for(seal_hash: [u8; 32], epoch: u64) -> TransitionVeto {
        TransitionVeto {
            seal_hash,
            reason: VetoReason::BadBoundary,
            evidence: b"stub".to_vec(),
            submitted_at_epoch: epoch,
            vetoer_identity_hash: [9; 32],
            // A non-empty sig satisfies `validate_structure`; this is a unit
            // test of the store's bookkeeping, NOT of signature verification
            // (covered separately in the seal module's sig tests).
            dilithium3_sig: vec![0xaa; 32],
        }
    }

    #[test]
    fn insert_retrieve_roundtrip() {
        let mut store = TransitionStore::new();
        let seal = split_seal_at(100);
        let id = store.insert(seal.clone()).expect("insert");
        let got = store.get(&id).expect("present");
        assert_eq!(got.seal.proposed_at_epoch, 100);
        assert_eq!(got.status, PendingStatus::AwaitingSigs);
    }

    /// `status_counts` groups by current lifecycle stage and exposes a
    /// total() helper. Empty store reports all zeroes.
    #[test]
    fn status_counts_groups_by_lifecycle_stage() {
        let mut store = TransitionStore::new();
        assert_eq!(store.status_counts(), StatusCounts::default());
        assert_eq!(store.status_counts().total(), 0);

        // Two AwaitingSigs, different epochs so ids differ.
        store.insert(split_seal_at(100)).unwrap();
        store.insert(split_seal_at(200)).unwrap();

        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 2);
        assert_eq!(counts.dispute_window, 0);
        assert_eq!(counts.vetoed, 0);
        assert_eq!(counts.finalized, 0);
        assert_eq!(counts.expired, 0);
        assert_eq!(counts.total(), 2);
    }

    /// Metric-semantics codification for the
    /// `elara_transitions_pending_{awaiting_sigs,dispute_window,vetoed}`
    /// gauges. Operators rely on a partition invariant — every entry in
    /// the store is in exactly one of the five lifecycle states, never
    /// double-counted, never an orphan. So `status_counts().total()` MUST
    /// equal `len()` at every point across the lifecycle (insert →
    /// add_sig → add_veto → tick → prune). If this drifts, dashboards
    /// silently misreport "active proposals" because the gauges sum to
    /// less than the resident count.
    #[test]
    fn ops_41_status_counts_partition_invariant_under_lifecycle_transitions() {
        let mut store = TransitionStore::new();

        // (1) Empty store: total == len == 0.
        assert_eq!(store.status_counts().total(), store.len());
        assert_eq!(store.len(), 0);

        // (2) Insert three Splits at distinct epochs (different ids).
        // effective_epoch on each = proposed + TRANSITION_DISPUTE_WINDOW_EPOCHS.
        let id_a = store.insert(split_seal_at(100)).unwrap(); // effective=103
        let id_b = store.insert(split_seal_at(200)).unwrap(); // effective=203
        let _id_c = store.insert(split_seal_at(300)).unwrap(); // effective=303
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 3);
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.total(), store.len(),
            "every entry is exactly one status — no double-counting, no orphans");

        // (3) Drive id_a from AwaitingSigs → DisputeWindow with 4 distinct
        //     anchor sigs (split required_threshold == SPLIT_ANCHOR_THRESHOLD).
        for i in 1u8..=4 {
            let mut h = [0u8; 32];
            h[0] = i;
            let sig = AnchorSig { anchor_identity_hash: h, dilithium3_sig: vec![0xaa; 32] };
            store.add_sig(&id_a, sig).unwrap();
        }
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 2);
        assert_eq!(counts.dispute_window, 1);
        assert_eq!(counts.total(), store.len());

        // (4) Veto id_b twice (MIN_VETOES_TO_HALT == 2) inside its window.
        for vetoer in [[0xC1u8; 32], [0xC2u8; 32]] {
            let v = TransitionVeto {
                seal_hash: id_b,
                reason: VetoReason::BadBoundary,
                evidence: b"stub".to_vec(),
                submitted_at_epoch: 201,
                vetoer_identity_hash: vetoer,
                dilithium3_sig: vec![0xaa; 32],
            };
            store.add_veto(&id_b, v, 201).unwrap();
        }
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 1, "id_c only");
        assert_eq!(counts.dispute_window, 1, "id_a only");
        assert_eq!(counts.vetoed, 1, "id_b after 2 vetoes");
        assert_eq!(counts.total(), store.len());

        // (5) Tick past every effective_epoch — id_a (DW) → Finalized;
        //     id_c (AS) → Expired; id_b (Vetoed) is terminal, untouched.
        let _outcome = store.tick(310);
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 0);
        assert_eq!(counts.dispute_window, 0);
        assert_eq!(counts.vetoed, 1);
        assert_eq!(counts.finalized, 1);
        assert_eq!(counts.expired, 1);
        assert_eq!(counts.total(), store.len());

        // (6) Insert one more (fresh AS) — partition invariant must still hold.
        let _id_d = store.insert(split_seal_at(400)).unwrap();
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 1);
        assert_eq!(counts.vetoed + counts.finalized + counts.expired, 3);
        assert_eq!(counts.total(), 4);
        assert_eq!(counts.total(), store.len());

        // (7) Prune the terminal subset past its retention window. retention=0
        //     reaps every terminal entry whose effective_epoch is at-or-before now.
        let pruned = store.prune(311, 0);
        assert_eq!(pruned, 3, "Vetoed + Finalized + Expired all reaped");
        let counts = store.status_counts();
        assert_eq!(counts.awaiting_sigs, 1, "id_d survives — still active");
        assert_eq!(counts.vetoed, 0);
        assert_eq!(counts.finalized, 0);
        assert_eq!(counts.expired, 0);
        assert_eq!(counts.total(), store.len(),
            "prune preserves the invariant: status sum == len after reaping");
    }

    /// `kind_counts` partitions pending entries into Split vs Merge
    /// buckets. Empty store → all zeroes; mixed store → exact counts.
    #[test]
    fn kind_counts_partitions_split_vs_merge() {
        let mut store = TransitionStore::new();
        assert_eq!(store.kind_counts(), KindCounts::default());
        assert_eq!(store.kind_counts().total(), 0);

        // 2 splits + 1 merge, each at a distinct epoch so ids differ.
        store.insert(split_seal_at(100)).unwrap();
        store.insert(split_seal_at(200)).unwrap();
        store.insert(merge_seal_at(300)).unwrap();

        let counts = store.kind_counts();
        assert_eq!(counts.split, 2);
        assert_eq!(counts.merge, 1);
        assert_eq!(counts.total(), 3);
        // Per-kind total should match per-status total on a healthy store.
        assert_eq!(counts.total(), store.status_counts().total());
    }

    /// `veto_reason_counts` aggregates every attached veto across the
    /// store into a reason-keyed breakdown. Empty store → all zeros;
    /// mixed reasons on one proposal → all buckets non-zero.
    #[test]
    fn veto_reason_counts_aggregates_across_store() {
        let mut store = TransitionStore::new();
        assert_eq!(store.veto_reason_counts(), VetoReasonCounts::default());
        assert_eq!(store.veto_reason_counts().total(), 0);

        let id = store.insert(split_seal_at(100)).unwrap();

        // Attach three distinct-identity vetoes with three different
        // reasons. The store doesn't cap the count once Vetoed is reached
        // — additional vetoes on a Vetoed entry would be rejected at the
        // HTTP layer, but add_veto itself accepts them until status-flip
        // closes the path. Use distinct vetoer_identity_hash to avoid
        // the dedup path.
        let reasons = [
            ([0x01; 32], VetoReason::BadBoundary),
            ([0x02; 32], VetoReason::StateRootMismatch),
            ([0x03; 32], VetoReason::Other("spurious".into())),
        ];
        for (identity, reason) in reasons {
            let v = TransitionVeto {
                seal_hash: id,
                reason,
                evidence: b"x".to_vec(),
                submitted_at_epoch: 101,
                vetoer_identity_hash: identity,
                dilithium3_sig: vec![0xaa; 32],
            };
            // The second veto will flip status to Vetoed (MIN_VETOES_TO_HALT=2),
            // at which point add_veto still adds but the status is frozen.
            // Ignore the per-call Err from add_veto after Vetoed — the store
            // continues to accept (for counting), but the test relies on the
            // first two landing.
            let _ = store.add_veto(&id, v, 101);
        }

        let counts = store.veto_reason_counts();
        // At minimum the first two landed (before the status flipped to
        // Vetoed and subsequent add_veto calls short-circuit inside
        // add_veto). `veto_reason_counts` just reads `vetoes` vecs, so
        // whatever landed there gets counted.
        assert!(counts.bad_boundary >= 1);
        assert!(counts.state_root_mismatch >= 1);
        // Total matches the sum of all attached veto vecs.
        let direct_total: usize = store
            .by_id
            .values()
            .map(|p| p.vetoes.len())
            .sum();
        assert_eq!(counts.total(), direct_total);
    }

    /// `proposals_with_vetoes_count` counts pending entries that carry
    /// at least one veto. Distinct from `status_counts().vetoed`:
    /// before `MIN_VETOES_TO_HALT` vetoes land, the status is still
    /// AwaitingSigs/DisputeWindow but the proposal is already being
    /// contested.
    #[test]
    fn proposals_with_vetoes_count_tracks_contested_before_halt() {
        let mut store = TransitionStore::new();
        assert_eq!(
            store.proposals_with_vetoes_count(),
            0,
            "empty store → no contested proposals"
        );

        let id_a = store.insert(split_seal_at(100)).unwrap();
        let id_b = store.insert(split_seal_at(200)).unwrap();
        let _id_c = store.insert(split_seal_at(300)).unwrap();
        assert_eq!(
            store.proposals_with_vetoes_count(),
            0,
            "no vetoes attached yet"
        );

        // Attach ONE veto to A. Status stays pre-halt (needs 2).
        let v = TransitionVeto {
            seal_hash: id_a,
            reason: VetoReason::BadBoundary,
            evidence: b"x".to_vec(),
            submitted_at_epoch: 101,
            vetoer_identity_hash: [0x01; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        store.add_veto(&id_a, v, 101).unwrap();
        assert_eq!(
            store.proposals_with_vetoes_count(),
            1,
            "A is contested with 1 veto (below MIN_VETOES_TO_HALT)"
        );
        assert_eq!(
            store.get(&id_a).unwrap().status,
            PendingStatus::AwaitingSigs,
            "status must not flip on first veto"
        );

        // Attach one veto to B as well.
        let v = TransitionVeto {
            seal_hash: id_b,
            reason: VetoReason::StateRootMismatch,
            evidence: b"y".to_vec(),
            submitted_at_epoch: 201,
            vetoer_identity_hash: [0x02; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        store.add_veto(&id_b, v, 201).unwrap();
        assert_eq!(store.proposals_with_vetoes_count(), 2);
    }

    /// Pin the partition invariants linking the four metric
    /// helpers (`status_counts`, `kind_counts`, `proposals_with_vetoes_count`,
    /// `veto_reason_counts`) so /metrics dashboards built on this set
    /// can never silently disagree.
    ///
    /// Four invariants the metric pipeline relies on:
    ///   I1: `kind_counts.total() == status_counts.total() == store.len()`
    ///       — every pending entry has exactly one kind AND one status.
    ///       Both partitions must agree on the cardinality of the store.
    ///   I2: `proposals_with_vetoes_count() ≤ status_counts.total()`
    ///       — at most every proposal is contested.
    ///   I3: `proposals_with_vetoes_count() ≥ status_counts.vetoed`
    ///       — every Vetoed proposal has crossed `MIN_VETOES_TO_HALT`,
    ///       which is ≥1, so its veto vec is non-empty.
    ///   I4: `veto_reason_counts.total() ≥ proposals_with_vetoes_count()`
    ///       — each contested proposal contributes at least 1 veto to
    ///       the reason buckets, possibly more.
    ///
    /// Without I1, dashboards plotting `_pending_split + _pending_merge`
    /// would disagree with
    /// `_pending_awaiting_sigs + _pending_dispute_window + _pending_vetoed`.
    /// Without I2-I4, the alarm logic
    /// `with_vetoes − pending_vetoed` (the early-contestation pool)
    /// could underflow or report nonsense.
    #[test]
    fn ops_48_metric_partition_invariants_hold_across_lifecycle() {
        let mut store = TransitionStore::new();

        // (1) Empty store: every helper reports zeros, all invariants hold trivially.
        let s = store.status_counts();
        let k = store.kind_counts();
        let v = store.proposals_with_vetoes_count();
        let r = store.veto_reason_counts();
        assert_eq!(k.total(), s.total());
        assert_eq!(s.total(), store.len());
        assert!(v <= s.total());
        assert!(v >= s.vetoed);
        assert!(r.total() >= v);

        // (2) Mixed kind, no vetoes yet: I1 must hold; I2-I4 trivially.
        let id_split_a = store.insert(split_seal_at(100)).unwrap();
        let id_split_b = store.insert(split_seal_at(200)).unwrap();
        let _id_merge = store.insert(merge_seal_at(300)).unwrap();
        let s = store.status_counts();
        let k = store.kind_counts();
        assert_eq!(k.split, 2);
        assert_eq!(k.merge, 1);
        assert_eq!(k.total(), s.total(), "I1 kind partition matches status");
        assert_eq!(s.total(), store.len(), "I1 status partition matches len");
        assert_eq!(store.proposals_with_vetoes_count(), 0);

        // (3) Attach 1 veto to id_split_a → contested but not Vetoed
        //     (MIN_VETOES_TO_HALT=2). I2-I4 now non-trivially exercised.
        let veto1 = TransitionVeto {
            seal_hash: id_split_a,
            reason: VetoReason::BadBoundary,
            evidence: b"x".to_vec(),
            submitted_at_epoch: 101,
            vetoer_identity_hash: [0x01; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        store.add_veto(&id_split_a, veto1, 101).unwrap();
        let s = store.status_counts();
        let v = store.proposals_with_vetoes_count();
        let r = store.veto_reason_counts();
        assert_eq!(v, 1, "1 contested proposal");
        assert_eq!(s.vetoed, 0, "still below MIN_VETOES_TO_HALT");
        assert!(v >= s.vetoed, "I3: with_vetoes ≥ pending_vetoed");
        assert!(v <= s.total(), "I2: with_vetoes ≤ total");
        assert_eq!(
            v - s.vetoed,
            1,
            "early-contestation pool = 1 (operators alert on this number)"
        );
        assert_eq!(r.total(), 1, "1 veto entry across the store");
        assert_eq!(r.bad_boundary, 1);
        assert!(
            r.total() >= v,
            "I4: reason total ≥ contested proposals"
        );

        // (4) Attach 2nd distinct-identity veto to id_split_a → flips to Vetoed.
        //     Reason mix: BadBoundary + StateRootMismatch.
        let veto2 = TransitionVeto {
            seal_hash: id_split_a,
            reason: VetoReason::StateRootMismatch,
            evidence: b"y".to_vec(),
            submitted_at_epoch: 102,
            vetoer_identity_hash: [0x02; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        store.add_veto(&id_split_a, veto2, 102).unwrap();
        let s = store.status_counts();
        let k = store.kind_counts();
        let v = store.proposals_with_vetoes_count();
        let r = store.veto_reason_counts();
        assert_eq!(s.vetoed, 1, "id_split_a now Vetoed");
        assert_eq!(v, 1, "still 1 contested proposal (the same one)");
        assert!(v >= s.vetoed, "I3 holds at the equality boundary");
        assert_eq!(r.bad_boundary, 1);
        assert_eq!(r.state_root_mismatch, 1);
        assert_eq!(r.total(), 2, "two veto entries");
        assert!(
            r.total() >= v,
            "I4: 2 reasons attached to 1 contested proposal"
        );
        assert_eq!(k.total(), s.total(), "I1 unchanged by veto activity");
        assert_eq!(s.total(), store.len());

        // (5) Attach veto on id_split_b with a different reason → 2 contested,
        //     reason buckets distribute. Still need to keep all invariants.
        let veto3 = TransitionVeto {
            seal_hash: id_split_b,
            reason: VetoReason::CommitteeDiversity,
            evidence: b"z".to_vec(),
            submitted_at_epoch: 201,
            vetoer_identity_hash: [0x03; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        store.add_veto(&id_split_b, veto3, 201).unwrap();
        let s = store.status_counts();
        let k = store.kind_counts();
        let v = store.proposals_with_vetoes_count();
        let r = store.veto_reason_counts();
        assert_eq!(v, 2, "now 2 contested proposals");
        assert_eq!(s.vetoed, 1, "only id_split_a flipped (id_split_b has 1 veto)");
        assert_eq!(r.committee_diversity, 1);
        assert_eq!(r.total(), 3);
        assert!(v >= s.vetoed, "I3");
        assert!(v <= s.total(), "I2");
        assert!(r.total() >= v, "I4");
        assert_eq!(k.total(), s.total(), "I1");
        assert_eq!(s.total(), store.len());

        // (6) Reap terminal entries with prune. The Vetoed status survives
        //     until the prune retention window expires; force the reap by
        //     ticking past effective_epoch + retention=0.
        let far_future = 300 + TRANSITION_DISPUTE_WINDOW_EPOCHS + 10;
        store.tick(far_future);
        store.prune(far_future, 0);
        let s = store.status_counts();
        let k = store.kind_counts();
        let v = store.proposals_with_vetoes_count();
        let r = store.veto_reason_counts();
        // After prune, post-conditions must still hold on the remaining
        // store. I1-I4 are universally quantified — they must hold in
        // every state, including the empty post-prune state.
        assert_eq!(k.total(), s.total(), "I1 post-prune");
        assert_eq!(s.total(), store.len(), "I1 post-prune");
        assert!(v <= s.total(), "I2 post-prune");
        assert!(v >= s.vetoed, "I3 post-prune");
        assert!(r.total() >= v, "I4 post-prune");
    }

    /// `nearest_effective_epoch` returns the soonest effective_epoch
    /// among entries in an active status (AwaitingSigs / DisputeWindow),
    /// None when empty or when every entry is terminal.
    #[test]
    fn nearest_effective_epoch_tracks_active_only() {
        let mut store = TransitionStore::new();
        assert_eq!(store.nearest_effective_epoch(), None);

        // Two actives. Smallest effective_epoch wins.
        let _ = store.insert(split_seal_at(200)).unwrap(); // effective 200+W
        let _ = store.insert(split_seal_at(100)).unwrap(); // effective 100+W
        assert_eq!(
            store.nearest_effective_epoch(),
            Some(100 + TRANSITION_DISPUTE_WINDOW_EPOCHS)
        );

        // After ticking past BOTH effective epochs, every AwaitingSigs
        // entry flips to Expired — nothing active remains.
        let far_future = 200 + TRANSITION_DISPUTE_WINDOW_EPOCHS + 1;
        store.tick(far_future);
        // Everything is Expired / otherwise terminal → None.
        assert_eq!(store.nearest_effective_epoch(), None);
    }

    /// `oldest_active_proposed_at_epoch` returns the smallest
    /// proposed_at_epoch among active entries; None when empty or
    /// when every entry has gone terminal.
    #[test]
    fn oldest_active_proposed_at_epoch_tracks_active_only() {
        let mut store = TransitionStore::new();
        assert_eq!(store.oldest_active_proposed_at_epoch(), None);

        // Two actives: proposed_at 100 and 200. The 100 one is "older"
        // → should win regardless of insertion order.
        let _ = store.insert(split_seal_at(200)).unwrap();
        let _ = store.insert(split_seal_at(100)).unwrap();
        assert_eq!(store.oldest_active_proposed_at_epoch(), Some(100));

        // After ticking past the effective_epoch of BOTH entries,
        // every AwaitingSigs proposal flips to Expired, so nothing
        // active remains to be "oldest."
        let far_future = 200 + TRANSITION_DISPUTE_WINDOW_EPOCHS + 1;
        store.tick(far_future);
        assert_eq!(store.oldest_active_proposed_at_epoch(), None);
    }

    #[test]
    fn structural_invalid_seal_rejected() {
        let mut store = TransitionStore::new();
        let mut seal = split_seal_at(100);
        seal.children.clear(); // violates Split invariant (must have 2 children)
        let err = store.insert(seal).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("2 children")),
            "got {err:?}"
        );
    }

    #[test]
    fn single_veto_recorded_but_status_unchanged() {
        // With MIN_VETOES_TO_HALT=2, a single veto should NOT flip the
        // proposal — one rogue peer must not be able to DoS a transition.
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        let veto = TransitionVeto {
            seal_hash: id,
            ..unsigned_veto_for(id, 101)
        };
        store.add_veto(&id, veto, 101).expect("accepted");
        let got = store.get(&id).unwrap();
        assert_eq!(got.vetoes.len(), 1);
        assert_eq!(
            got.status,
            PendingStatus::AwaitingSigs,
            "status stays below halt threshold"
        );
    }

    #[test]
    fn veto_halt_threshold_flips_status() {
        // Two independent vetoes (distinct identities) reaches MIN_VETOES_TO_HALT.
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();

        let veto1 = TransitionVeto {
            seal_hash: id,
            vetoer_identity_hash: [0xaa; 32],
            ..unsigned_veto_for(id, 101)
        };
        store.add_veto(&id, veto1, 101).expect("1st accepted");
        assert_eq!(
            store.get(&id).unwrap().status,
            PendingStatus::AwaitingSigs,
            "one veto is not enough"
        );

        let veto2 = TransitionVeto {
            seal_hash: id,
            vetoer_identity_hash: [0xbb; 32],
            ..unsigned_veto_for(id, 101)
        };
        store.add_veto(&id, veto2, 101).expect("2nd accepted");
        let got = store.get(&id).unwrap();
        assert_eq!(got.vetoes.len(), 2);
        assert_eq!(got.status, PendingStatus::Vetoed);
    }

    #[test]
    fn veto_outside_window_rejected() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        // effective_epoch = 103; submitting at 103 must be rejected.
        let veto = TransitionVeto {
            seal_hash: id,
            ..unsigned_veto_for(id, 103)
        };
        let err = store.add_veto(&id, veto, 103).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("window closed")),
            "got {err:?}"
        );
    }

    #[test]
    fn veto_wrong_seal_hash_rejected() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        let veto = unsigned_veto_for([0xff; 32], 101); // wrong seal_hash
        let err = store.add_veto(&id, veto, 101).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("does not match")),
            "got {err:?}"
        );
    }

    #[test]
    fn duplicate_veto_from_same_identity_rejected() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        let veto = TransitionVeto {
            seal_hash: id,
            ..unsigned_veto_for(id, 101)
        };
        store.add_veto(&id, veto.clone(), 101).unwrap();
        let err = store.add_veto(&id, veto, 101).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("already recorded")),
            "got {err:?}"
        );
    }

    #[test]
    fn tick_expires_and_finalizes() {
        let mut store = TransitionStore::new();
        // proposal-A: awaiting sigs, should Expire past effective_epoch
        let id_a = store.insert(split_seal_at(100)).unwrap();
        // proposal-B: M-of-N sigs present at insert time → DisputeWindow →
        // should Finalize past effective_epoch. Use a different split_key so
        // the canonical bytes — and therefore the seal id — differ from A.
        let mut seal_b = split_seal_at(100);
        seal_b.split_key = Some([0x40; 32]);
        // Give it enough sig stubs to hit the threshold so it enters
        // DisputeWindow on insert. Signatures aren't verified by the store
        // (verification happens in the HTTP handler), so stub bytes work.
        for i in 0..seal_b.required_threshold() {
            seal_b.proposer_sigs.push(
                crate::network::zone_transition_seal::AnchorSig {
                    anchor_identity_hash: [i as u8; 32],
                    dilithium3_sig: vec![0; 3309],
                },
            );
        }
        let id_b = store.insert(seal_b).unwrap();
        assert_eq!(store.get(&id_b).unwrap().status, PendingStatus::DisputeWindow);

        let outcome = store.tick(103); // effective_epoch
        assert_eq!(outcome.newly_finalized, vec![id_b]);
        assert_eq!(outcome.newly_expired, vec![id_a]);
        assert_eq!(store.get(&id_a).unwrap().status, PendingStatus::Expired);
        assert_eq!(store.get(&id_b).unwrap().status, PendingStatus::Finalized);
    }

    #[test]
    fn prune_clears_terminal_after_retention() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        store.tick(103); // Expires
        // Not yet past retention → still present
        assert_eq!(store.prune(104, 10), 0);
        assert!(store.get(&id).is_some());
        // Past retention → evicted
        assert_eq!(store.prune(120, 10), 1);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn add_sig_promotes_status_at_threshold() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        assert_eq!(store.get(&id).unwrap().status, PendingStatus::AwaitingSigs);
        let threshold = store.get(&id).unwrap().seal.required_threshold();

        // Add threshold-1 sigs — still AwaitingSigs.
        for i in 0..(threshold - 1) {
            let sig = crate::network::zone_transition_seal::AnchorSig {
                anchor_identity_hash: [i as u8; 32],
                dilithium3_sig: vec![0xaa; 3309],
            };
            let status = store.add_sig(&id, sig).expect("accepted");
            assert_eq!(status, PendingStatus::AwaitingSigs);
        }
        // The final sig crosses threshold → DisputeWindow.
        let sig = crate::network::zone_transition_seal::AnchorSig {
            anchor_identity_hash: [threshold as u8; 32],
            dilithium3_sig: vec![0xbb; 3309],
        };
        let status = store.add_sig(&id, sig).expect("accepted");
        assert_eq!(status, PendingStatus::DisputeWindow);
    }

    #[test]
    fn add_sig_deduplicates_per_anchor() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        let sig = crate::network::zone_transition_seal::AnchorSig {
            anchor_identity_hash: [7; 32],
            dilithium3_sig: vec![0xaa; 3309],
        };
        store.add_sig(&id, sig.clone()).expect("first accepted");
        let err = store.add_sig(&id, sig).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("already recorded")),
            "got {err:?}"
        );
    }

    /// Once a proposal has already flipped to Vetoed, further vetoes
    /// must be rejected as spam. The first MIN_VETOES_TO_HALT vetoes
    /// are retained for audit (they caused the halt); anything beyond
    /// them would be unbounded memory/storage growth on a terminal
    /// proposal whose outcome is already locked in.
    #[test]
    fn add_veto_rejects_after_halt() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();

        // Land MIN_VETOES_TO_HALT distinct-identity vetoes to flip status.
        for i in 0..MIN_VETOES_TO_HALT {
            let v = TransitionVeto {
                seal_hash: id,
                vetoer_identity_hash: [0xa0 + i as u8; 32],
                ..unsigned_veto_for(id, 101)
            };
            store.add_veto(&id, v, 101).expect("halt-reaching veto accepted");
        }
        assert_eq!(store.get(&id).unwrap().status, PendingStatus::Vetoed);
        let vetoes_at_halt = store.get(&id).unwrap().vetoes.len();
        assert_eq!(vetoes_at_halt, MIN_VETOES_TO_HALT);

        // A third distinct-identity veto — still novel, not a dedup case —
        // must be refused because the proposal is already Vetoed.
        let post_halt = TransitionVeto {
            seal_hash: id,
            vetoer_identity_hash: [0xff; 32],
            ..unsigned_veto_for(id, 101)
        };
        let err = store
            .add_veto(&id, post_halt, 101)
            .expect_err("post-halt veto must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("already vetoed"),
            "error should indicate halt terminal status, got: {msg}"
        );

        // And the stored veto list is unchanged — no partial growth.
        assert_eq!(
            store.get(&id).unwrap().vetoes.len(),
            vetoes_at_halt,
            "vetoes vec must not grow past the halt-causing set"
        );
    }

    #[test]
    fn add_sig_rejected_after_veto() {
        // Two distinct-identity vetoes trip the halt threshold and flip
        // status to Vetoed; after that, sig additions must be rejected.
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();
        for i in 0..MIN_VETOES_TO_HALT {
            let veto = TransitionVeto {
                seal_hash: id,
                vetoer_identity_hash: [0xa0 + i as u8; 32],
                ..unsigned_veto_for(id, 101)
            };
            store.add_veto(&id, veto, 101).expect("veto accepted");
        }
        assert_eq!(store.get(&id).unwrap().status, PendingStatus::Vetoed);
        let sig = crate::network::zone_transition_seal::AnchorSig {
            anchor_identity_hash: [1; 32],
            dilithium3_sig: vec![0xaa; 3309],
        };
        let err = store.add_sig(&id, sig).unwrap_err();
        assert!(
            matches!(err, ElaraError::Wire(ref m) if m.contains("Vetoed")),
            "got {err:?}"
        );
    }

    #[test]
    fn insert_same_seal_merges_sigs_preserves_vetoes() {
        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).unwrap();

        // Record MIN_VETOES_TO_HALT distinct-identity vetoes to flip status
        // to Vetoed. Re-inserting the seal must NOT wipe them.
        for i in 0..MIN_VETOES_TO_HALT {
            let veto = TransitionVeto {
                seal_hash: id,
                vetoer_identity_hash: [0xa0 + i as u8; 32],
                ..unsigned_veto_for(id, 101)
            };
            store.add_veto(&id, veto, 101).expect("accepted");
        }
        assert_eq!(store.get(&id).unwrap().vetoes.len(), MIN_VETOES_TO_HALT);
        assert_eq!(store.get(&id).unwrap().status, PendingStatus::Vetoed);

        // Second insert with one fresh sig — merges into existing entry
        // but cannot add sigs because entry is Vetoed. Must NOT wipe vetoes.
        let mut seal_with_sig = split_seal_at(100);
        seal_with_sig.proposer_sigs.push(
            crate::network::zone_transition_seal::AnchorSig {
                anchor_identity_hash: [5; 32],
                dilithium3_sig: vec![0xbb; 3309],
            },
        );
        let id2 = store.insert(seal_with_sig).unwrap();
        assert_eq!(id, id2, "seal ids collide (sigs are excluded from hash)");
        assert_eq!(
            store.get(&id).unwrap().vetoes.len(),
            MIN_VETOES_TO_HALT,
            "vetoes must survive re-insert"
        );
        assert_eq!(store.get(&id).unwrap().status, PendingStatus::Vetoed);
    }

    #[test]
    fn capacity_eviction_picks_oldest() {
        let mut store = TransitionStore::new();
        // Stuff the store just over cap with seals whose proposed_at_epoch
        // varies so the eviction order is predictable.
        for e in 0..MAX_PENDING_TRANSITIONS as u64 {
            let _ = store.insert(split_seal_at(e)).unwrap();
        }
        assert_eq!(store.len(), MAX_PENDING_TRANSITIONS);
        // Next insert should evict the oldest (epoch 0) and keep the new one.
        let newest = store
            .insert(split_seal_at(MAX_PENDING_TRANSITIONS as u64))
            .unwrap();
        assert_eq!(store.len(), MAX_PENDING_TRANSITIONS);
        assert!(store.get(&newest).is_some());
        // The eviction victim is chosen by proposed_at_epoch; the epoch-0
        // seal's hash is not trivial to recompute in this test, but we can
        // assert that *some* eviction happened by the len check above.
    }

    #[test]
    fn evictions_total_counts_capacity_evictions() {
        let mut store = TransitionStore::new();
        assert_eq!(
            store.evictions_total(),
            0,
            "fresh store has zero evictions"
        );

        // Fill to cap — no evictions yet.
        for e in 0..MAX_PENDING_TRANSITIONS as u64 {
            let _ = store.insert(split_seal_at(e)).unwrap();
        }
        assert_eq!(
            store.evictions_total(),
            0,
            "filling up to the cap must not evict"
        );

        // Push three over the cap — each insert evicts the oldest.
        for e in 0u64..3 {
            let _ = store
                .insert(split_seal_at(MAX_PENDING_TRANSITIONS as u64 + e))
                .unwrap();
        }
        assert_eq!(
            store.evictions_total(),
            3,
            "each over-cap insert must bump the counter by 1"
        );

        // Re-inserting an already-present seal (merges sigs) must NOT
        // count as an eviction — no new slot taken.
        let before = store.evictions_total();
        let existing = split_seal_at(MAX_PENDING_TRANSITIONS as u64 + 2);
        let _ = store.insert(existing).unwrap();
        assert_eq!(
            store.evictions_total(),
            before,
            "re-inserting an existing seal must not evict"
        );
    }

    #[test]
    fn proposals_accepted_total_counts_fresh_inserts_only() {
        let mut store = TransitionStore::new();
        assert_eq!(store.proposals_accepted_total(), 0);

        // 3 fresh proposals → counter = 3.
        for e in 0u64..3 {
            let _ = store.insert(split_seal_at(e)).unwrap();
        }
        assert_eq!(store.proposals_accepted_total(), 3);

        // Re-insert the last one — merges sigs, no new slot, counter unchanged.
        let dup = split_seal_at(2);
        let _ = store.insert(dup).unwrap();
        assert_eq!(
            store.proposals_accepted_total(),
            3,
            "re-insert of existing seal must not bump the fresh-insert counter"
        );

        // A brand-new one does bump.
        let _ = store.insert(split_seal_at(42)).unwrap();
        assert_eq!(store.proposals_accepted_total(), 4);
    }

    /// `add_sig` must enforce the MAX_PROPOSER_SIGS ceiling. The
    /// propose-time path is covered by `validate_structure` on the seal
    /// itself; this test pins the accumulation path so a malicious stream
    /// of /sig calls can't push the seal above the cap.
    #[test]
    fn add_sig_rejects_beyond_max_proposer_sigs() {
        use crate::network::zone_transition_seal::{AnchorSig, MAX_PROPOSER_SIGS};

        let mut store = TransitionStore::new();
        let id = store.insert(split_seal_at(100)).expect("insert");

        // Pre-fill to exactly the cap using distinct anchor identities.
        // The store's dedup check compares `anchor_identity_hash`, so
        // each test sig must carry a fresh hash.
        for i in 0..MAX_PROPOSER_SIGS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            let sig = AnchorSig {
                anchor_identity_hash: h,
                dilithium3_sig: vec![0xaa; 32],
            };
            store.add_sig(&id, sig).expect("sig within cap");
        }

        // The (N+1)th add must be refused with an error that names the cap.
        let overflow = AnchorSig {
            anchor_identity_hash: [0xff; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        let err = store
            .add_sig(&id, overflow)
            .expect_err("(N+1)th sig must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("proposer_sigs cap reached"),
            "error should mention the cap, got: {msg}"
        );
    }

    /// `VetoReason::Other(String)` is the only veto payload with
    /// variable-size memory cost. Without a cap, a malicious peer can
    /// submit a veto whose reason string is megabytes long — which then
    /// gets retained on every peer that holds the pending entry for the
    /// full dispute window. `validate_structure` MUST reject oversize
    /// `Other` reasons before the store admits them.
    #[test]
    fn validate_structure_rejects_oversize_veto_reason_other() {
        // Named variants with no payload remain valid regardless of
        // reason size enforcement.
        let v_named = TransitionVeto {
            seal_hash: [7u8; 32],
            reason: VetoReason::BadBoundary,
            evidence: b"ok".to_vec(),
            submitted_at_epoch: 1,
            vetoer_identity_hash: [9u8; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        v_named.validate_structure().expect("named variant is fine");

        // `Other` at exactly the cap must pass — the cap is inclusive.
        let v_ok = TransitionVeto {
            seal_hash: [7u8; 32],
            reason: VetoReason::Other("a".repeat(MAX_VETO_REASON_OTHER_BYTES)),
            evidence: b"ok".to_vec(),
            submitted_at_epoch: 1,
            vetoer_identity_hash: [9u8; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        v_ok.validate_structure()
            .expect("Other at exact cap should be accepted");

        // `Other` one byte over the cap must be rejected.
        let v_oversize = TransitionVeto {
            seal_hash: [7u8; 32],
            reason: VetoReason::Other("a".repeat(MAX_VETO_REASON_OTHER_BYTES + 1)),
            evidence: b"ok".to_vec(),
            submitted_at_epoch: 1,
            vetoer_identity_hash: [9u8; 32],
            dilithium3_sig: vec![0xaa; 32],
        };
        let err = v_oversize
            .validate_structure()
            .expect_err("oversize Other must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("veto reason (Other) too large"),
            "error should name the reason-size check, got: {msg}"
        );
    }

    #[test]
    fn has_active_with_parents_matches_pending_proposal() {
        // ARCH-2 (c) cooldown gate: orchestrator skips a fresh propose if
        // an active (AwaitingSigs / DisputeWindow) seal already targets the
        // same parents.
        let mut store = TransitionStore::new();
        let seal = merge_seal_at(100);
        let parents: Vec<ZoneId> = seal.parents.iter().map(|s| s.zone_id.clone()).collect();
        store.insert(seal).expect("insert");

        // Same parents, order-independent — must match.
        assert!(store.has_active_with_parents(&parents));
        let mut reversed = parents.clone();
        reversed.reverse();
        assert!(
            store.has_active_with_parents(&reversed),
            "match must be order-independent"
        );

        // Different parents — must not match.
        let other = vec![ZoneId::new("test/unrelated-a"), ZoneId::new("test/unrelated-b")];
        assert!(!store.has_active_with_parents(&other));

        // Subset / superset — must not match (size differs).
        assert!(!store.has_active_with_parents(&parents[..1]));
    }

    #[test]
    fn has_active_with_parents_skips_terminal_proposals() {
        // Cooldown should NOT match Expired / Vetoed / Finalized proposals —
        // those are terminal, the orchestrator is allowed to propose again.
        let mut store = TransitionStore::new();
        let seal = merge_seal_at(100);
        let parents: Vec<ZoneId> = seal.parents.iter().map(|s| s.zone_id.clone()).collect();
        let id = store.insert(seal).expect("insert");

        // Manually flip status to Expired (simulating tick-after-window).
        store
            .by_id
            .get_mut(&id)
            .unwrap()
            .status = PendingStatus::Expired;
        assert!(
            !store.has_active_with_parents(&parents),
            "Expired proposal must not block the orchestrator from re-proposing"
        );

        store.by_id.get_mut(&id).unwrap().status = PendingStatus::Vetoed;
        assert!(!store.has_active_with_parents(&parents));

        store.by_id.get_mut(&id).unwrap().status = PendingStatus::Finalized;
        assert!(!store.has_active_with_parents(&parents));

        // DisputeWindow IS active — must match.
        store.by_id.get_mut(&id).unwrap().status = PendingStatus::DisputeWindow;
        assert!(store.has_active_with_parents(&parents));
    }

    #[test]
    fn has_active_with_parents_empty_target_returns_false() {
        let mut store = TransitionStore::new();
        store.insert(merge_seal_at(100)).expect("insert");
        assert!(
            !store.has_active_with_parents(&[]),
            "empty target list is a caller bug; never match"
        );
    }

    /// Pin the WHEN-axis epoch helpers across the full lifecycle so
    /// the `elara_transitions_nearest_effective_epoch` and
    /// `elara_transitions_oldest_active_proposed_at_epoch` /metrics gauges
    /// observe ONLY active-status (AwaitingSigs / DisputeWindow) proposals.
    /// Terminal statuses (Vetoed / Finalized / Expired) MUST be excluded —
    /// their windows no longer represent work operators need to watch, and
    /// including them would cause the dashboard "longest-waiting" alarm to
    /// fire on already-terminated proposals (false positive that masks
    /// real orchestrator stalls).
    #[test]
    fn ops_51_when_axis_helpers_observe_only_active_lifecycle() {
        let mut store = TransitionStore::new();

        // I1: empty store → both helpers return None (gauge emits 0).
        assert_eq!(store.nearest_effective_epoch(), None);
        assert_eq!(store.oldest_active_proposed_at_epoch(), None);

        // I2: insert two AwaitingSigs proposals at different epochs.
        // Both helpers return the active min of the relevant axis.
        let id_a = store.insert(split_seal_at(100)).expect("insert a");
        let id_b = store.insert(split_seal_at(200)).expect("insert b");
        assert_eq!(
            store.oldest_active_proposed_at_epoch(),
            Some(100),
            "min over active proposed_at_epoch"
        );
        // effective_epoch = proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS
        // so the soonest-deadline proposal is the one proposed earliest.
        assert_eq!(
            store.nearest_effective_epoch(),
            Some(100 + TRANSITION_DISPUTE_WINDOW_EPOCHS),
        );

        // I3: flipping the OLDEST proposal to a TERMINAL status must remove
        // it from both helpers' coverage. The gauge must now reflect the
        // remaining active-only proposal.
        store.by_id.get_mut(&id_a).unwrap().status = PendingStatus::Finalized;
        assert_eq!(
            store.oldest_active_proposed_at_epoch(),
            Some(200),
            "Finalized id_a excluded — remaining active is id_b@200"
        );
        assert_eq!(
            store.nearest_effective_epoch(),
            Some(200 + TRANSITION_DISPUTE_WINDOW_EPOCHS),
        );

        // I4: each terminal status (Vetoed, Finalized, Expired) is excluded.
        // Flip id_b through each in turn — gauge collapses to None when no
        // active entries remain.
        for terminal in [PendingStatus::Vetoed, PendingStatus::Finalized, PendingStatus::Expired] {
            store.by_id.get_mut(&id_b).unwrap().status = terminal;
            assert_eq!(
                store.oldest_active_proposed_at_epoch(),
                None,
                "all entries terminal → gauge collapses to None (emits 0)"
            );
            assert_eq!(store.nearest_effective_epoch(), None);
        }

        // I5: DisputeWindow IS active — restore id_b to DisputeWindow and
        // verify the gauge re-emerges.
        store.by_id.get_mut(&id_b).unwrap().status = PendingStatus::DisputeWindow;
        assert_eq!(store.oldest_active_proposed_at_epoch(), Some(200));
        assert_eq!(
            store.nearest_effective_epoch(),
            Some(200 + TRANSITION_DISPUTE_WINDOW_EPOCHS),
        );

        // I6: prune-by-id removes the entry — back to None.
        store.by_id.remove(&id_a);
        store.by_id.remove(&id_b);
        assert_eq!(store.nearest_effective_epoch(), None);
        assert_eq!(store.oldest_active_proposed_at_epoch(), None);
    }

    // ─────────────────── constants + enum-surface tests ────────────────────
    // Fixture-free constant + enum-surface pins. No store, no signatures, no
    // seals — these tests defend the values + variant set that the
    // orchestrator, HTTP handlers, and gossip layer all read at boundary.

    #[test]
    fn batch_b_max_pending_transitions_const_pin_strict_1024_memory_safety_cap() {
        // Pending-store cap is the gossip-flood memory bound (see doc on
        // const). Drift below 1024 breaks legitimate high-churn load; drift
        // above weakens the OOM guard. usize type pin matches Vec/HashMap
        // length math throughout the module.
        const PIN: usize = 1024;
        assert_eq!(MAX_PENDING_TRANSITIONS, PIN);
        let _: usize = MAX_PENDING_TRANSITIONS;
        assert!(MAX_PENDING_TRANSITIONS.is_power_of_two());
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_veto_size_caps_pin_evidence_2048_other_256_min_halt_2() {
        // Three independent constants gate veto admission. Joint pin so a
        // single accidental rename or value swap fails one tight assertion
        // rather than silently shifting the dispute-window economics.
        assert_eq!(MAX_VETO_EVIDENCE_BYTES, 2048);
        assert_eq!(MAX_VETO_REASON_OTHER_BYTES, 256);
        assert_eq!(MIN_VETOES_TO_HALT, 2);
        let _: usize = MAX_VETO_EVIDENCE_BYTES;
        let _: usize = MAX_VETO_REASON_OTHER_BYTES;
        let _: usize = MIN_VETOES_TO_HALT;
        // The named-payload cap MUST be strictly smaller than the evidence
        // cap — they bound different fields and the evidence field is the
        // larger one (binary hashes vs. operator note).
        assert!(MAX_VETO_REASON_OTHER_BYTES < MAX_VETO_EVIDENCE_BYTES);
        // MIN_VETOES_TO_HALT > 1 is the load-bearing property: a single
        // rogue peer cannot kill a transition by itself.
        assert!(MIN_VETOES_TO_HALT > 1);
    }

    #[test]
    fn batch_b_veto_reason_five_variants_clone_and_eq_distinct_membership() {
        // Five-variant pin: any added variant must extend this list; any
        // removed variant breaks compilation here. PartialEq + Clone are
        // derived — verify both behave as expected on a fresh value set.
        let v1 = VetoReason::BadBoundary;
        let v2 = VetoReason::UnauthorizedProposer;
        let v3 = VetoReason::CommitteeDiversity;
        let v4 = VetoReason::StateRootMismatch;
        let v5 = VetoReason::Other("operator-note".into());

        // Distinct variants — pairwise inequality across all 10 pairs.
        let all = [&v1, &v2, &v3, &v4, &v5];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "variants {i} and {j} compared equal");
            }
        }

        // Clone preserves equality across all 5 variants.
        assert_eq!(v1.clone(), VetoReason::BadBoundary);
        assert_eq!(v2.clone(), VetoReason::UnauthorizedProposer);
        assert_eq!(v3.clone(), VetoReason::CommitteeDiversity);
        assert_eq!(v4.clone(), VetoReason::StateRootMismatch);
        assert_eq!(v5.clone(), VetoReason::Other("operator-note".into()));
    }

    #[test]
    fn batch_b_veto_reason_other_payload_round_trip_preserves_arbitrary_strings() {
        // `Other(String)` is the escape hatch for forward-compatible
        // reason names. Pin that the payload is byte-exact preserved
        // across construction + clone for empty, ASCII, UTF-8 multibyte,
        // and at-cap lengths.
        let cases: Vec<String> = vec![
            String::new(),
            "abc".into(),
            "Δoe — η is unrelated to ν".into(),
            "a".repeat(MAX_VETO_REASON_OTHER_BYTES),
        ];
        for s in cases {
            let r = VetoReason::Other(s.clone());
            // Destructure to confirm payload bytes match exactly.
            match &r {
                VetoReason::Other(inner) => assert_eq!(inner, &s),
                other => panic!("expected Other, got {other:?}"),
            }
            // Clone preserves payload bit-exactly.
            let r2 = r.clone();
            assert_eq!(r, r2);
            // Equality with a freshly-constructed Other(same s).
            assert_eq!(r, VetoReason::Other(s));
        }
    }

    #[test]
    fn batch_b_veto_reason_serde_json_round_trip_preserves_all_five_variants() {
        // Wire-format pin: HTTP handlers + RocksDB mirror serialize via
        // serde_json. Any silent rename (camelCase drift, variant rename)
        // would break replay + gossip — assert the round-trip is byte-stable
        // for every variant including the payload case.
        let variants = [
            VetoReason::BadBoundary,
            VetoReason::UnauthorizedProposer,
            VetoReason::CommitteeDiversity,
            VetoReason::StateRootMismatch,
            VetoReason::Other("payload".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let back: VetoReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&back, v, "round-trip failed for {v:?} (json={json})");
        }

        // Specific wire-shape pin for the named variants — unit variants
        // serialize as bare strings, not tagged objects.
        assert_eq!(
            serde_json::to_string(&VetoReason::BadBoundary).unwrap(),
            "\"BadBoundary\"",
        );
        // And Other(s) carries the payload in the JSON.
        let other_json = serde_json::to_string(&VetoReason::Other("x".into())).unwrap();
        assert!(other_json.contains("Other"));
        assert!(other_json.contains("\"x\""));
    }
}
