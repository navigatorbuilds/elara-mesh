//! Cross-zone transfers — two-phase lock/claim with Merkle proof bridge.
//!
//! Transfers beats between zones using a lock/claim mechanism:
//! 1. Sender zone: LOCK record moves beats to pending_outbound
//! 2. Recipient zone: CLAIM record credits beats to receiver, with Merkle proof
//! 3. At any moment: locked beats exist in exactly one place
//! 4. Timeout: unclaimed locks auto-refund after 24 hours
//!
//! Conservation invariant (economics §16):
//! `sum(zone_balances) + sum(pending_xzone) + pool = GENESIS_SUPPLY`

//!
//! Spec references:
//!   @spec economics §16.1
//!   @spec Protocol §7.5
//!   @spec Protocol §11.22.1 (cross-zone Merkle proof bridge for lock/claim)

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::ZoneId;
use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default timeout for unclaimed cross-zone transfers (seconds).
pub const CLAIM_TIMEOUT_SECS: f64 = 24.0 * 3600.0; // 24 hours

/// Far-horizon reap deadline for a SEALED transfer stuck in `Locked` under a
/// dead/partitioned destination committee (co-fix (b),
/// internal design notes). A sealed lock is never
/// passively refunded (its CLAIM could race), so a committee that never gathers
/// quorum for an `XZoneAbort` leaves the lock — and the `pending_xzone_locked`
/// supply behind it — stuck forever, bloating every state snapshot unbounded.
/// At 30 days the 24h CLAIM window has been closed for 29 days (no node will
/// admit a claim past `expires_at`), so the reaper can safely HARD-REFUND the
/// sender. Set well beyond any clock-skew / partition-heal window.
pub const REAP_HORIZON_SECS: f64 = 30.0 * 24.0 * 3600.0; // 30 days

/// Metadata key for cross-zone transfer operations.
pub const XZONE_OP_KEY: &str = "xzone_op";

/// Domain separator for cross-zone seal-finality attestation signatures.
///
/// Witnesses in zone A sign `XZONE_FINALITY_DOMAIN || zone_path || epoch ||
/// merkle_root || committee_hash` to attest that the seal at `merkle_root`
/// has reached finality in zone A. Zone B verifies these signatures at
/// `claim_transfer` time. The domain tag prevents the same signature from
/// being replayed against any other Elara protocol message (record sigs,
/// liveness attestations, conflict proofs, …).
pub const XZONE_FINALITY_DOMAIN: &[u8] = b"ELARA/XZONE_SEAL_FINALITY/v1";

/// Domain separator for cross-zone abort attestation signatures (Gap 2 sealed-abort).
///
/// Once a transfer's lock has been sealed in zone A (`merkle_proof` populated),
/// sender-cancel and recipient-reject become unsafe — a claim record may be
/// in flight in zone B. The recovery path is a non-inclusion attestation from
/// zone B's committee: each B-witness signs
/// `XZONE_ABORT_DOMAIN || transfer_id || dest_zone_path || source_seal_epoch ||
/// dest_committee_hash`, asserting "the recipient never claimed this transfer
/// before the abort window closed." When ≥ 2/3 of the B-committee sign,
/// the source-zone ledger refunds the sender atomically. The domain tag
/// keeps these sigs distinct from `XZONE_FINALITY_DOMAIN` so a finality
/// witness can never be replayed as an abort proof and vice-versa.
pub const XZONE_ABORT_DOMAIN: &[u8] = b"ELARA/XZONE_ABORT/v1";

// ─── Types ──────────────────────────────────────────────────────────────────

/// A sibling node in a Merkle inclusion proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSibling {
    /// Sibling hash at this tree level.
    pub hash: [u8; 32],
    /// True if this sibling is on the right side of the pair.
    pub is_right: bool,
}

/// One witness's signed attestation that zone-A's epoch seal has reached
/// finality. Bundled into `PendingTransfer.source_seal_signers` and replayed
/// by zone B at claim time.
///
/// Verification (`XZoneFinalityProof::verify_quorum`):
///   1. `witness_pk` is a member of `source_committee_hash` (Merkle proof).
///   2. `signature` verifies against `XZoneFinalityProof::signable_bytes`
///      under `witness_pk` (Dilithium3).
///   3. ≥ ceil(2 · committee_size / 3) distinct witnesses pass (1) and (2).
///
/// The committee Merkle membership proof lives alongside the signature so
/// zone B can verify against zone A's published committee root without
/// needing to materialize the whole committee — light-client friendly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealFinalityWitness {
    /// Dilithium3 public key of the attesting witness (1952 bytes).
    pub witness_pk: Vec<u8>,
    /// Dilithium3 signature over [`XZoneFinalityProof::signable_bytes`].
    pub signature: Vec<u8>,
    /// Merkle membership proof: walks `sha3_256(witness_pk)` up to
    /// `source_committee_hash`. Empty if the committee has only one member.
    pub committee_proof: Vec<ProofSibling>,
}

/// Status of a pending cross-zone transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    /// Beats locked in sender zone, waiting for claim.
    Locked,
    /// Beats claimed in recipient zone. Transfer complete.
    Claimed,
    /// Claim window expired. Beats refunded to sender.
    Refunded,
    /// Sealed transfer aborted via B-committee non-inclusion proof — sender refunded.
    /// Distinguishable from `Refunded` so the caller can tell a 24h-passive
    /// refund (`Refunded`) apart from an active committee-attested abort
    /// (`Aborted`); both result in the sender's balance being credited back.
    Aborted,
}

/// A pending cross-zone transfer.
///
/// Lives in the in-memory `CrossZoneState.pending` map, persisted ONLY via
/// node-snapshot serde. `CF_PENDING_XZONE` exists but is a dead store on the
/// live path today — nothing writes it — so proof/witness material attached
/// here does NOT survive `rebuild_ledger_streaming` or
/// `incremental_ledger_replay` (B1, internal design notes;
/// the audited "D5-CF" fix makes the CF live).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransfer {
    /// Unique transfer ID (= record ID of the LOCK record).
    pub transfer_id: String,
    /// Sender identity hash.
    pub sender: String,
    /// Recipient identity hash.
    pub recipient: String,
    /// Amount in base units.
    pub amount: u64,
    /// Source zone.
    pub source_zone: ZoneId,
    /// Destination zone.
    pub dest_zone: ZoneId,
    /// When the lock was created.
    pub locked_at: f64,
    /// When the claim window expires (locked_at + CLAIM_TIMEOUT_SECS).
    pub expires_at: f64,
    /// Current status.
    pub status: TransferStatus,
    /// Merkle inclusion proof from source zone's epoch seal.
    /// Empty until the lock record is committed to an epoch seal.
    /// Claims are rejected while this is empty (M7 fix).
    pub merkle_proof: Vec<ProofSibling>,
    /// SHA3-256 hash of the lock record (leaf in the Merkle tree).
    #[serde(default)]
    pub lock_record_hash: [u8; 32],
    /// Merkle root from the epoch seal that committed this lock.
    /// Set by `set_proof()` after epoch seal creation.
    #[serde(default)]
    pub source_merkle_root: [u8; 32],
    /// Gap 2.1: signed attestations from zone-A witnesses proving the seal
    /// at `source_merkle_root` has reached finality (≥ 2/3 of committee).
    /// Empty until `set_finality_witnesses()` is called by the producer side.
    /// When `source_committee_size > 0` the claim path enforces quorum;
    /// when zero, the legacy inclusion-only path is used (back-compat for
    /// in-flight transfers and pre-Gap-2.1 deployments).
    #[serde(default)]
    pub source_seal_signers: Vec<SealFinalityWitness>,
    /// Gap 2.1: Merkle root of zone-A's witness committee at `source_seal_epoch`.
    /// Each `SealFinalityWitness` carries a membership proof against this root.
    #[serde(default)]
    pub source_committee_hash: [u8; 32],
    /// Gap 2.1: zone-A epoch number that produced the seal. Signed by witnesses
    /// to prevent cross-epoch replay of an attestation against a re-used root.
    #[serde(default)]
    pub source_seal_epoch: u64,
    /// Gap 2.1: total size of zone-A's committee at `source_seal_epoch`. Used
    /// to compute the 2/3 quorum threshold. Zero means "finality not enforced
    /// for this transfer" (legacy / pre-Gap-2.1 producer side).
    #[serde(default)]
    pub source_committee_size: u32,
    /// B2 fix (internal design notes): the CANONICAL
    /// finality-committee `(Merkle root, size)` for THIS transfer's DEST zone,
    /// frozen from the source-zone epoch seal that committed the lock
    /// (`attach_xzone_proofs_from_seal_with_finality` reads
    /// `ParsedEpochSeal.xzone_dest_finality_committees[dest_zone]`). The
    /// `XZoneAbort` apply/validate path gates the wire `dest_committee_hash`
    /// against the root AND uses the anchored size as the 2/3 denominator, so
    /// neither a forged 1-member abort committee nor a `size=1` sub-quorum claim
    /// can force-refund a sealed transfer. `None` for legacy/pre-fix locks →
    /// abort is fail-closed (rejected) for them. MUST be `#[serde(default)]` and
    /// never `serde(skip)` so a snapshot-bootstrapped node reads the identical
    /// anchor (else cross-node abort divergence = fork).
    #[serde(default)]
    pub dest_finality_committee: Option<([u8; 32], u32)>,
    /// Record ID of the claim record (set when claimed).
    pub claim_record_id: Option<String>,
}

/// A frozen batch of cross-zone timeout refunds (co-fix (c),
/// internal design notes). The genesis authority selects
/// the expired-unsealed transfers at its local wall-clock, freezes the explicit
/// `(transfer_id, sender, amount)` list (canonically sorted by `transfer_id`),
/// and emits it as a signed `XZoneTimeoutRefund` record. Every node then applies
/// the SAME frozen list via the standard record path, so the passive 24h refund
/// no longer mutates `account.available` / `last_active` / `pending_xzone_locked`
/// out-of-band from a per-node wall clock — closing the ungated
/// producer-only-mutation fork (each seal-eligible node ticked at a different
/// `now`, and followers never ran the in-loop sweep at all). Same Option-A
/// pattern as `IdleDecayBatch`.
///
/// `sender`/`amount` are frozen for the explorer / audit surface; the apply path
/// reads them from the live `pending` entry so a forged emitter amount is
/// structurally inert (see [`CrossZoneState::apply_refund_batch`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XZoneRefundBatch {
    /// Epoch number this batch was emitted at (monotone-guard key + audit).
    pub epoch: u64,
    /// Source zone whose pending set this batch was computed from (audit label).
    pub zone: String,
    /// Frozen selection set: `(transfer_id, sender, amount)`, sorted by transfer_id.
    pub refunds: Vec<(String, String, u64)>,
}

impl XZoneRefundBatch {
    /// Total refund value across all listed entries. For explorer display +
    /// record content-hash diversity only — it is NOT the conservation source on
    /// apply (the actually-applied subset is, since entries can be skipped).
    pub fn total_refund(&self) -> u128 {
        self.refunds.iter().map(|(_, _, a)| *a as u128).sum()
    }

    /// True when there is nothing to refund (emitter suppresses the record).
    pub fn is_empty(&self) -> bool {
        self.refunds.is_empty()
    }
}

/// State tracker for pending cross-zone transfers.
///
/// Persisted (`#[serde(default)]` on `LedgerState.cross_zone`,
/// internal design notes): the apply path reads `pending` to
/// accept/reject `XZoneClaim`/`Cancel`/`Abort`/`Reject` (and to resolve the
/// refund sender), so a snapshot-bootstrapped node that started with an empty
/// `pending` would reject claims a since-genesis node accepts → divergent
/// balances + `pending_xzone_locked` + account-SMT root → permanent silent
/// fork. Every field is serde-capable (`PendingTransfer` already derives
/// `Serialize`/`Deserialize`); pre-fix snapshots deserialize to `default()`
/// (= the old empty-on-bootstrap behavior, migration-safe).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossZoneState {
    /// transfer_id → PendingTransfer
    pub pending: HashMap<String, PendingTransfer>,
    /// Total amount currently locked in pending transfers (conservation tracking).
    pub total_locked: u64,
    /// Gap 2.1 Phase 5a observability: claims accepted with `source_committee_size > 0`
    /// AND quorum verified successfully. This is the path Phase 5 will keep.
    /// Bumped from inside `claim_transfer` so it's replay-deterministic.
    pub claim_finality_enforced_total: u64,
    /// Gap 2.1 Phase 5a observability: claims accepted via the legacy
    /// `source_committee_size == 0` inclusion-only path. Phase 5 (2026-04-28)
    /// deleted that path — `claim_transfer` now always calls
    /// `verify_finality_quorum`, which rejects `committee_size == 0`. This
    /// counter is therefore FROZEN: it persists for serialization back-compat
    /// (so a pre-Phase-5 on-disk ledger with a historical non-zero value
    /// keeps that value across boots), and `/metrics` keeps emitting it as a
    /// historical gauge, but it's never incremented anymore. A non-zero
    /// reading on a fleet node means the field was carried forward from
    /// before the cutover.
    pub claim_finality_legacy_total: u64,
    /// Per-status pending counts. Maintained incrementally by
    /// every status-mutating method (`lock_transfer`, `claim_transfer`,
    /// `cancel_transfer`, `abort_transfer`, `reject_transfer`,
    /// `process_expired`, `prune_completed`). Stats endpoint
    /// (`/xzone/stats`) reads these in O(1) instead of scanning
    /// `pending.values()`. At 1M concurrent transfers an O(n) scan under
    /// `ledger.read()` blocks state_core writes for hundreds of ms on
    /// every Prometheus scrape (~30s).
    ///
    /// **Invariant:** `locked_count + claimed_count + refunded_count +
    /// aborted_count == pending.len()` at every observable point —
    /// pinned by `ops152_status_counters_match_pending_after_lifecycle`
    /// and `ops152_status_counters_invariant_under_random_ops`.
    ///
    /// `CrossZoneState` now persists in the snapshot (`#[serde(default)]` on
    /// `LedgerState.cross_zone`), so these counters round-trip with `pending`.
    /// [`Self::recount_status`] stays wired as a belt-and-braces reconcile in
    /// `bin/elara_node.rs` post-load — idempotent on a populated snapshot, and
    /// it correctly zeroes them for a pre-fix snapshot that lands `pending`
    /// empty via `default()`.
    pub locked_count: u64,
    pub claimed_count: u64,
    pub refunded_count: u64,
    pub aborted_count: u64,
    /// Secondary index: `lock_record_hash` → transfer IDs currently
    /// `Locked` with an EMPTY `merkle_proof` — exactly the set the per-seal
    /// attach scan wants. Turns `attach_xzone_proofs_from_seal*` from
    /// O(total_pending) per applied seal (epoch.rs:3750, flagged §4.2-D of
    /// internal design notes) into O(seal_size).
    /// `Vec` value: two distinct transfers sharing a leaf hash would both be
    /// proofed by the old scan, so the index must hold both (in practice
    /// len 1 — transfer_id IS the lock record's ID).
    ///
    /// **Invariant:** `needs_proof_index` holds (hash → id) iff
    /// `pending[id].status == Locked && pending[id].merkle_proof.is_empty()`
    /// — maintained by `lock_transfer` (insert), `set_proof` (remove), and
    /// every unsealed status-flip (`cancel_transfer`, `reject_transfer`,
    /// `process_expired`, `apply_refund_batch`). Sealed transitions
    /// (`claim_transfer`, `abort_transfer`, `apply_reap_batch`) and
    /// `prune_completed` (never prunes Locked) can't touch indexed entries.
    /// Derived state: serde-skipped, rebuilt post-load by
    /// [`Self::recount_status`] at every snapshot-deserialize site. A stale
    /// entry is fail-safe — consumers re-check `pending` before use.
    #[serde(skip)]
    needs_proof_index: HashMap<[u8; 32], Vec<String>>,
}

impl CrossZoneState {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            total_locked: 0,
            claim_finality_enforced_total: 0,
            claim_finality_legacy_total: 0,
            locked_count: 0,
            claimed_count: 0,
            refunded_count: 0,
            aborted_count: 0,
            needs_proof_index: HashMap::new(),
        }
    }

    /// Transfer IDs awaiting a merkle proof for this lock-record hash
    /// (`Locked` + empty `merkle_proof`). O(1); empty slice when none.
    /// Callers must still re-check the `pending` entry — the index is
    /// derived state and a stale hit is skipped, never trusted.
    pub fn needs_proof_ids(&self, lock_record_hash: &[u8; 32]) -> &[String] {
        self.needs_proof_index
            .get(lock_record_hash)
            .map_or(&[], |v| v.as_slice())
    }

    fn index_needs_proof(&mut self, lock_record_hash: [u8; 32], transfer_id: &str) {
        let ids = self.needs_proof_index.entry(lock_record_hash).or_default();
        if !ids.iter().any(|t| t == transfer_id) {
            ids.push(transfer_id.to_string());
        }
    }

    fn unindex_needs_proof(&mut self, lock_record_hash: &[u8; 32], transfer_id: &str) {
        if let Some(ids) = self.needs_proof_index.get_mut(lock_record_hash) {
            ids.retain(|t| t != transfer_id);
            if ids.is_empty() {
                self.needs_proof_index.remove(lock_record_hash);
            }
        }
    }

    /// Re-derive ALL derived state from `self.pending`: the per-status
    /// pending counters AND the serde-skipped `needs_proof_index` (which
    /// deserializes empty on every snapshot load and must be rebuilt before
    /// the first seal-apply). One-time O(n) sweep — call from boot recovery
    /// after deserializing a ledger snapshot; already wired at every load
    /// site (bin/elara_node.rs post-load, sync.rs bootstrap apply, ledger
    /// boot paths). Idempotent at steady state (same input → same output).
    pub fn recount_status(&mut self) {
        let mut locked = 0u64;
        let mut claimed = 0u64;
        let mut refunded = 0u64;
        let mut aborted = 0u64;
        let mut index: HashMap<[u8; 32], Vec<String>> = HashMap::new();
        for t in self.pending.values() {
            match t.status {
                TransferStatus::Locked => locked += 1,
                TransferStatus::Claimed => claimed += 1,
                TransferStatus::Refunded => refunded += 1,
                TransferStatus::Aborted => aborted += 1,
            }
            if t.status == TransferStatus::Locked && t.merkle_proof.is_empty() {
                index
                    .entry(t.lock_record_hash)
                    .or_default()
                    .push(t.transfer_id.clone());
            }
        }
        self.locked_count = locked;
        self.claimed_count = claimed;
        self.refunded_count = refunded;
        self.aborted_count = aborted;
        self.needs_proof_index = index;
    }

    /// Lock beats for a cross-zone transfer.
    ///
    /// Creates a pending transfer in Locked state. The sender's balance
    /// should be debited by the caller before calling this.
    /// `lock_record_hash` is the SHA3-256 of the lock record's signable bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn lock_transfer(
        &mut self,
        transfer_id: String,
        sender: String,
        recipient: String,
        amount: u64,
        source_zone: ZoneId,
        dest_zone: ZoneId,
        timestamp: f64,
        lock_record_hash: [u8; 32],
    ) -> Result<()> {
        if self.pending.contains_key(&transfer_id) {
            return Err(ElaraError::Ledger(format!(
                "cross-zone transfer {} already exists", transfer_id
            )));
        }

        if amount == 0 {
            return Err(ElaraError::Ledger("cross-zone transfer amount must be > 0".into()));
        }

        if source_zone == dest_zone {
            return Err(ElaraError::Ledger("cross-zone transfer source and dest must differ".into()));
        }

        let transfer = PendingTransfer {
            transfer_id: transfer_id.clone(),
            sender,
            recipient,
            amount,
            source_zone,
            dest_zone,
            locked_at: timestamp,
            expires_at: timestamp + CLAIM_TIMEOUT_SECS,
            status: TransferStatus::Locked,
            merkle_proof: vec![], // populated by set_proof() after epoch seal
            lock_record_hash,
            source_merkle_root: [0u8; 32],
            source_seal_signers: vec![],
            source_committee_hash: [0u8; 32],
            source_seal_epoch: 0,
            source_committee_size: 0,
            // B2: no committee anchor at lock time — frozen at seal-ingest when
            // the lock is proofed into a source-zone seal carrying the map.
            dest_finality_committee: None,
            claim_record_id: None,
        };

        // Saturating to match the saturating_sub decrements below — `total_locked`
        // is a conservation tracker; an unchecked +=/-= would panic in debug and,
        // worse, WRAP in release (a corrupted pending-locked total). Deterministic,
        // so no cross-node divergence.
        self.total_locked = self.total_locked.saturating_add(amount);
        self.index_needs_proof(lock_record_hash, &transfer_id);
        self.pending.insert(transfer_id, transfer);
        self.locked_count += 1;
        Ok(())
    }

    /// Claim a pending cross-zone transfer.
    ///
    /// The recipient's balance should be credited by the caller after this returns Ok.
    /// Rejects claims where the lock has not yet been committed to an epoch seal
    /// (merkle_proof is empty). This prevents claims on unsealed locks (M7).
    pub fn claim_transfer(
        &mut self,
        transfer_id: &str,
        claimer: &str,
        claim_record_id: &str,
        timestamp: f64,
    ) -> Result<PendingTransfer> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, not Locked", transfer_id, transfer.status
            )));
        }

        if claimer != transfer.recipient {
            return Err(ElaraError::Ledger(format!(
                "claimer {} is not the recipient {}", claimer, transfer.recipient
            )));
        }

        if timestamp > transfer.expires_at {
            return Err(ElaraError::Ledger(format!(
                "transfer {} has expired (locked_at={}, expires_at={}, now={})",
                transfer_id, transfer.locked_at, transfer.expires_at, timestamp
            )));
        }

        // M7: Require merkle proof — lock must be committed to an epoch seal
        if transfer.merkle_proof.is_empty() {
            return Err(ElaraError::Ledger(format!(
                "transfer {} lock not yet committed to epoch seal (no merkle proof)",
                transfer_id
            )));
        }

        // Verify the merkle proof: walk from leaf (lock_record_hash) up the
        // sibling path, confirm we arrive at source_merkle_root.
        if !verify_inclusion_proof(
            &transfer.lock_record_hash,
            &transfer.merkle_proof,
            &transfer.source_merkle_root,
        ) {
            return Err(ElaraError::Ledger(format!(
                "transfer {} merkle proof invalid (root mismatch)", transfer_id
            )));
        }

        // Gap 2.1 Phase 5 (CLOSED 2026-04-28): zone-A seal finality is mandatory.
        // The legacy `committee_size == 0` bypass is gone. `verify_finality_quorum`
        // itself rejects committee_size==0 with "committee_size must be > 0 to
        // enforce quorum"; an inclusion-only proof is no longer sufficient. The
        // 24h Phase 5a soak (2026-04-27 → 2026-04-28) showed `legacy_total` flat
        // at 0 fleet-wide — no legitimate path relied on the bypass.
        verify_finality_quorum(
            &transfer.source_zone,
            transfer.source_seal_epoch,
            &transfer.source_merkle_root,
            &transfer.source_committee_hash,
            transfer.source_committee_size,
            &transfer.source_seal_signers,
        ).map_err(|e| ElaraError::Ledger(format!(
            "transfer {} seal not finalized in source zone: {}", transfer_id, e
        )))?;

        transfer.status = TransferStatus::Claimed;
        transfer.claim_record_id = Some(claim_record_id.to_string());
        let result = transfer.clone();
        self.total_locked = self.total_locked.saturating_sub(result.amount);
        self.locked_count = self.locked_count.saturating_sub(1);
        self.claimed_count += 1;

        // Replay-deterministic: bumped only on accept, after every check passes.
        // `claim_finality_legacy_total` (the field below) is frozen at its
        // deploy value (0) post-Phase-5 — kept for serialization back-compat,
        // never incremented. A pre-Phase-5 ledger that already has a non-zero
        // legacy counter keeps that historical value across boots.
        self.claim_finality_enforced_total += 1;

        Ok(result)
    }

    /// Attach a Merkle inclusion proof to a pending transfer after epoch seal.
    ///
    /// Called by the epoch seal loop when a lock record is committed to a seal.
    /// Once set, the transfer becomes claimable.
    pub fn set_proof(
        &mut self,
        transfer_id: &str,
        proof: Vec<ProofSibling>,
        merkle_root: [u8; 32],
    ) -> Result<()> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found for proof attachment", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, cannot attach proof", transfer_id, transfer.status
            )));
        }

        transfer.merkle_proof = proof;
        transfer.source_merkle_root = merkle_root;
        let lock_hash = transfer.lock_record_hash;
        self.unindex_needs_proof(&lock_hash, transfer_id);
        Ok(())
    }

    /// Gap 2.1: attach zone-A finality witnesses to a pending transfer.
    ///
    /// Called by the producer side (`attach_xzone_proofs_from_seal` analog,
    /// see `network::epoch`) once 2/3 of zone A's committee has signed the
    /// seal. `committee_size` is the *full* committee size at that epoch —
    /// zone B uses it to compute the 2/3 quorum threshold from witnesses
    /// alone, without needing zone A's full committee membership.
    ///
    /// Phase 5 (2026-04-28) REMOVED the legacy inclusion-only claim path:
    /// `claim_transfer` unconditionally calls `verify_finality_quorum`,
    /// which hard-rejects `committee_size == 0`. A transfer left at (or set
    /// to) zero is therefore UNCLAIMABLE — its only exit is a refund (24h
    /// passive while unsealed; the 30-day `XZoneStaleReap` once a proof is
    /// attached). Supply a nonzero `committee_size` AND enough signers to
    /// satisfy quorum, or don't call this at all.
    pub fn set_finality_witnesses(
        &mut self,
        transfer_id: &str,
        signers: Vec<SealFinalityWitness>,
        committee_hash: [u8; 32],
        seal_epoch: u64,
        committee_size: u32,
    ) -> Result<()> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found for finality witnesses", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, cannot attach finality witnesses",
                transfer_id, transfer.status
            )));
        }

        transfer.source_seal_signers = signers;
        transfer.source_committee_hash = committee_hash;
        transfer.source_seal_epoch = seal_epoch;
        transfer.source_committee_size = committee_size;
        Ok(())
    }

    /// Order-independent digest of live cross-zone state, for cross-node
    /// fleet comparison. This is the only divergence detector that works in
    /// multi-zone, where the boot sealed-root cross-check is structurally
    /// skipped — a dropped claim or lost proof is supply-neutral, so nothing
    /// else surfaces it. Two nodes reporting the same digest epoch but
    /// different digests persistently have baked divergent transfer state.
    ///
    /// SHA3-256 over `(transfer_id, status, proof_present, committee_size)`
    /// sorted by transfer_id, truncated to 53 bits so the value round-trips
    /// Prometheus' f64 text format exactly. `source_seal_signers` is
    /// deliberately EXCLUDED: signer sets are node-local non-consensus state
    /// (gossip-timing dependent) and would false-positive diverge.
    /// O(pending log pending) per call — invoked once per applied seal, and
    /// `pending` is drained by the 24h refund / 30-day reap horizons.
    pub fn state_digest(&self) -> u64 {
        use sha3::{Digest, Sha3_256};
        let mut entries: Vec<(&String, &PendingTransfer)> = self.pending.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut h = Sha3_256::new();
        for (id, t) in entries {
            h.update(id.as_bytes());
            h.update([0u8]); // separator: transfer ids are record ids, never NUL
            h.update([match t.status {
                TransferStatus::Locked => 0u8,
                TransferStatus::Claimed => 1,
                TransferStatus::Refunded => 2,
                TransferStatus::Aborted => 3,
            }]);
            h.update([u8::from(!t.merkle_proof.is_empty())]);
            h.update(t.source_committee_size.to_le_bytes());
        }
        let out = h.finalize();
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&out[..8]);
        u64::from_le_bytes(eight) & ((1u64 << 53) - 1)
    }

    /// Sender-initiated cancel of an unsealed cross-zone transfer.
    ///
    /// Gap 2 atomic-rollback: lets the sender reclaim locked beats early
    /// when the lock has not yet been committed to an epoch seal. Once the
    /// lock IS sealed (`set_proof` populated `merkle_proof`), the recipient
    /// could be in flight to claim and sender-cancel is unsafe — the caller
    /// must instead wait for either claim or 24h timeout, or accept a
    /// recipient-zone abort proof (separate path).
    ///
    /// Returns the refund tuple `(transfer_id, sender, amount)` so the
    /// caller (ledger apply path) can credit `amount` back to the sender's
    /// available balance. Status moves to `Refunded` (same terminal state
    /// as `process_expired`).
    pub fn cancel_transfer(
        &mut self,
        transfer_id: &str,
        canceller: &str,
    ) -> Result<(String, String, u64)> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, cannot cancel", transfer_id, transfer.status
            )));
        }

        if canceller != transfer.sender {
            return Err(ElaraError::Ledger(format!(
                "canceller {} is not the sender {}", canceller, transfer.sender
            )));
        }

        if !transfer.merkle_proof.is_empty() {
            return Err(ElaraError::Ledger(format!(
                "transfer {} already sealed in source zone — sender-initiated cancel \
                 unsafe (recipient may be in flight); wait for claim/timeout or use \
                 recipient-zone abort proof",
                transfer_id
            )));
        }

        transfer.status = TransferStatus::Refunded;
        self.total_locked = self.total_locked.saturating_sub(transfer.amount);
        self.locked_count = self.locked_count.saturating_sub(1);
        self.refunded_count += 1;
        let lock_hash = transfer.lock_record_hash;
        let refund = (
            transfer.transfer_id.clone(),
            transfer.sender.clone(),
            transfer.amount,
        );
        self.unindex_needs_proof(&lock_hash, transfer_id);
        Ok(refund)
    }

    /// Reject an unsealed cross-zone transfer (recipient-initiated early refund).
    ///
    /// Mirror of `cancel_transfer` for the recipient side. Same safety
    /// constraints: must be Locked, must be unsealed (`merkle_proof.is_empty()`),
    /// and `rejector` must match `transfer.recipient` (creator on the wire).
    /// Once sealed the recipient may have submitted a claim in zone B; rejection
    /// becomes a double-spend window and is the domain of the recipient-zone
    /// abort proof or 24h passive timeout.
    ///
    /// Returns the refund tuple `(transfer_id, sender, amount)` — caller
    /// credits `amount` to `sender.available`, NOT to the rejector's balance
    /// (the recipient never had the funds; they were locked in the sender's
    /// account at lock time).
    /// Abort a *sealed* cross-zone transfer using a B-committee quorum proof
    /// (Gap 2 sealed-abort).
    ///
    /// Called from the source-zone (zone-A) ledger after the caller has already
    /// verified the abort proof via [`verify_abort_quorum`]. This method only
    /// performs the *state-transition* checks — it deliberately does NOT
    /// re-verify the proof, because:
    ///   * the apply path (`token::ledger::apply_op`) has the canonical
    ///     `(dest_zone, dest_committee_hash, dest_committee_size)` snapshot
    ///     resolved against the zone registry already, and
    ///   * keeping verification in the apply path lets the validate-pre-flight
    ///     run the same code without mutable state.
    ///
    /// Constraints:
    ///   * Transfer must be `Locked` (cannot abort an already-Claimed/Refunded/Aborted one)
    ///   * Transfer must be *sealed* (`merkle_proof` non-empty AND
    ///     `source_seal_epoch > 0`) — for unsealed transfers the simpler
    ///     `cancel_transfer` / `reject_transfer` paths apply.
    ///
    /// Returns `(transfer_id, sender, amount)` so the caller can credit the
    /// sender's `available` balance. Status moves to `Aborted` (terminal).
    pub fn abort_transfer(
        &mut self,
        transfer_id: &str,
    ) -> Result<(String, String, u64)> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, cannot abort", transfer_id, transfer.status
            )));
        }

        if transfer.merkle_proof.is_empty() || transfer.source_seal_epoch == 0 {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is not sealed yet — use cancel/reject (unsealed path)",
                transfer_id
            )));
        }

        transfer.status = TransferStatus::Aborted;
        self.total_locked = self.total_locked.saturating_sub(transfer.amount);
        self.locked_count = self.locked_count.saturating_sub(1);
        self.aborted_count += 1;
        Ok((
            transfer.transfer_id.clone(),
            transfer.sender.clone(),
            transfer.amount,
        ))
    }

    pub fn reject_transfer(
        &mut self,
        transfer_id: &str,
        rejector: &str,
    ) -> Result<(String, String, u64)> {
        let transfer = self.pending.get_mut(transfer_id)
            .ok_or_else(|| ElaraError::Ledger(format!(
                "cross-zone transfer {} not found", transfer_id
            )))?;

        if transfer.status != TransferStatus::Locked {
            return Err(ElaraError::Ledger(format!(
                "transfer {} is {:?}, cannot reject", transfer_id, transfer.status
            )));
        }

        if rejector != transfer.recipient {
            return Err(ElaraError::Ledger(format!(
                "rejector {} is not the recipient {}", rejector, transfer.recipient
            )));
        }

        if !transfer.merkle_proof.is_empty() {
            return Err(ElaraError::Ledger(format!(
                "transfer {} already sealed in source zone — recipient-initiated \
                 reject unsafe (recipient may have already claimed in dest zone); \
                 wait for claim/timeout or use recipient-zone committee abort proof",
                transfer_id
            )));
        }

        transfer.status = TransferStatus::Refunded;
        self.total_locked = self.total_locked.saturating_sub(transfer.amount);
        self.locked_count = self.locked_count.saturating_sub(1);
        self.refunded_count += 1;
        let lock_hash = transfer.lock_record_hash;
        let refund = (
            transfer.transfer_id.clone(),
            transfer.sender.clone(),
            transfer.amount,
        );
        self.unindex_needs_proof(&lock_hash, transfer_id);
        Ok(refund)
    }

    /// Gap 2 sealed-abort producer side: list transfers where this node's
    /// zone is the destination, the lock has been sealed in the source zone,
    /// and the claim window has expired without an admitted claim.
    ///
    /// A B-committee witness calls this to find transfers it should sign an
    /// abort attestation for. The caller is responsible for the membership
    /// check (witness must be in `dest_zone`'s finality committee at the
    /// relevant epoch) — this helper is pure observation.
    ///
    /// Skips:
    ///   * unsealed transfers (`merkle_proof` empty) — those use the
    ///     `cancel_transfer` / `reject_transfer` paths, not abort.
    ///   * transfers whose `dest_zone` is not `my_zone`.
    ///   * any non-`Locked` status (`Claimed`/`Refunded`/`Aborted` are
    ///     terminal).
    ///   * transfers still inside their claim window (`now <= expires_at`).
    ///     `expires_at` matches the same 24h deadline `process_expired` uses
    ///     so the active-abort path and passive-refund path can never both
    ///     fire on the same transfer.
    pub fn pending_abort_candidates(
        &self,
        my_zone: &ZoneId,
        now: f64,
    ) -> Vec<&PendingTransfer> {
        self.pending
            .values()
            .filter(|t| {
                t.status == TransferStatus::Locked
                    && t.dest_zone == *my_zone
                    && !t.merkle_proof.is_empty()
                    && now > t.expires_at
            })
            .collect()
    }

    /// Process expired transfers — refund locked beats to senders.
    ///
    /// **Gap 2 close:** sealed transfers are NOT eligible for
    /// passive refund. Once a lock has been committed to an epoch seal
    /// (`merkle_proof` non-empty), the recipient may have submitted a CLAIM
    /// record in the dest zone that has not yet propagated to this node.
    /// Refunding here can race a CLAIM in flight: zone A flips Locked →
    /// Refunded based on its local view, then receives the CLAIM gossip and
    /// rejects it ("transfer is Refunded, not Locked"); meanwhile zone B has
    /// already credited the recipient. The result is a global double-credit
    /// (sender + recipient both hold the beats), which violates the
    /// conservation invariant tracked in `pending_xzone_locked`.
    ///
    /// The only safe refund path for sealed transfers is `abort_transfer`,
    /// which requires a 2/3-quorum non-inclusion attestation from the dest
    /// zone's committee at `source_seal_epoch`. That cryptographic agreement
    /// is the dest zone saying "we never claimed and never will," eliminating
    /// the race. The abort signing loop runs in `epoch_seal_loop` (see
    /// `network::epoch.rs:4265` "Gap 2 sealed-abort P-3d producer-side
    /// abort-witness emitter") and produces an `XZoneAbort` record that flips
    /// status to `Aborted` on every node atomically with the standard apply
    /// path.
    ///
    /// Trade-off: liveness depends on the dest zone's committee signing
    /// either CLAIM or ABORT within a reasonable window. If the dest zone is
    /// permanently partitioned, the lock stays in `pending_xzone_locked`
    /// indefinitely. Operators monitor this via the
    /// `xzone_sealed_locked_past_expiry_count` gauge — sustained non-zero is
    /// the signal that the dest committee is not signing abort proofs and
    /// needs investigation. This is preferred to the previous behavior where
    /// the timeout could violate conservation under adversarial timing.
    ///
    /// Unsealed transfers (lock not yet committed to a seal) are still
    /// refunded here at expiry — they are race-free because no CLAIM can
    /// succeed against an unsealed lock (`claim_transfer` rejects unsealed
    /// claims via M7).
    ///
    /// Returns list of (transfer_id, sender, amount) for the caller to
    /// credit back to sender accounts.
    pub fn process_expired(&mut self, now: f64) -> Vec<(String, String, u64)> {
        let mut refunds = Vec::new();
        let mut unindex: Vec<([u8; 32], String)> = Vec::new();

        for transfer in self.pending.values_mut() {
            if transfer.status == TransferStatus::Locked
                && now > transfer.expires_at
                && transfer.merkle_proof.is_empty()
            {
                transfer.status = TransferStatus::Refunded;
                self.total_locked = self.total_locked.saturating_sub(transfer.amount);
                unindex.push((transfer.lock_record_hash, transfer.transfer_id.clone()));
                refunds.push((
                    transfer.transfer_id.clone(),
                    transfer.sender.clone(),
                    transfer.amount,
                ));
            }
        }

        // Counters are field-disjoint from `pending`, but the
        // mutable iterator above held the borrow for the whole loop —
        // bookkeep the transition deltas after the loop ends.
        let n = refunds.len() as u64;
        self.locked_count = self.locked_count.saturating_sub(n);
        self.refunded_count += n;
        for (hash, tid) in &unindex {
            self.unindex_needs_proof(hash, tid);
        }

        refunds
    }

    /// Pure, read-only computation of the expired-unsealed refund batch (co-fix
    /// (c), internal design notes). Mirrors
    /// `compute_idle_decay_batch`: the caller holds a read lock, this mutates
    /// nothing, and returns `None` when there is nothing to refund. The `now`
    /// cutoff is the emitter's local wall-clock — it decides WHICH transfers the
    /// emitter proposes, but the resulting frozen list is what every node
    /// applies, so the wall-clock never enters any node's state transition (the
    /// apply path does no time comparison).
    ///
    /// Predicate is byte-identical to [`Self::process_expired`]'s:
    /// `Locked && now > expires_at && merkle_proof.is_empty()` — UNSEALED
    /// transfers only. Sealed transfers refund solely via the `XZoneAbort`
    /// committee path; the far-horizon sealed-stuck case is reaped separately
    /// (co-fix (b)).
    pub fn compute_expired_refund_batch(
        &self,
        now: f64,
        epoch: u64,
        zone: &str,
    ) -> Option<XZoneRefundBatch> {
        let mut refunds: Vec<(String, String, u64)> = self
            .pending
            .values()
            .filter(|t| {
                t.status == TransferStatus::Locked
                    && now > t.expires_at
                    && t.merkle_proof.is_empty()
            })
            .map(|t| (t.transfer_id.clone(), t.sender.clone(), t.amount))
            .collect();
        if refunds.is_empty() {
            return None;
        }
        // Canonical order — `HashMap` iteration is non-deterministic, so the wire
        // encoding must be sorted or two emitters selecting the identical set
        // would still produce different record bytes (and a different record id).
        refunds.sort_by(|a, b| a.0.cmp(&b.0));
        Some(XZoneRefundBatch { epoch, zone: zone.to_string(), refunds })
    }

    /// Apply a frozen [`XZoneRefundBatch`] — runs on EVERY node via the
    /// `XZoneTimeoutRefund` record's apply path. Returns the subset of
    /// `(sender, amount)` ACTUALLY refunded (read from the live `pending` entry,
    /// never the frozen field) so the ledger can credit accounts and decrement
    /// `pending_xzone_locked` by the identical subset.
    ///
    /// SKIP-MISSING semantics (the determinism crux): a listed transfer that is
    /// no longer `Locked`-unsealed in this node's `pending` — a CLAIM / Cancel /
    /// Abort landed first, it was pruned, it got sealed since emit, or a
    /// bootstrapped node never had it — is silently skipped. NOT an error, NOT a
    /// whole-record reject (a late CLAIM would otherwise fork applied-vs-rejected
    /// nodes; idle_decay can reject-whole because its debit set is
    /// recompute-deterministic, this selection set is not). The skip is a pure
    /// function of node-replicated `pending` status, so every node converges on
    /// the same applied/skipped partition once it has applied the same canonical
    /// record ordering. Conservation stays exact because the credit and BOTH
    /// lock-tracker decrements derive from the applied subset, never
    /// `batch.total_refund()`. Idempotent on re-delivery: the second pass finds
    /// every entry already `Refunded` (status ≠ Locked) → empty applied set.
    pub fn apply_refund_batch(&mut self, batch: &XZoneRefundBatch) -> Vec<(String, u64)> {
        let mut applied: Vec<(String, u64)> = Vec::new();
        for (transfer_id, _frozen_sender, _frozen_amount) in &batch.refunds {
            let mut unindex: Option<[u8; 32]> = None;
            if let Some(t) = self.pending.get_mut(transfer_id) {
                // Re-check against replicated state. `merkle_proof.is_empty()` is
                // a SAFETY gate too: a transfer sealed since emit must NOT be
                // timeout-refunded (a CLAIM may be in flight) — it falls to the
                // abort path instead.
                if t.status == TransferStatus::Locked && t.merkle_proof.is_empty() {
                    let sender = t.sender.clone();
                    let amount = t.amount;
                    t.status = TransferStatus::Refunded;
                    self.total_locked = self.total_locked.saturating_sub(amount);
                    self.locked_count = self.locked_count.saturating_sub(1);
                    self.refunded_count += 1;
                    unindex = Some(t.lock_record_hash);
                    applied.push((sender, amount));
                }
            }
            if let Some(hash) = unindex {
                self.unindex_needs_proof(&hash, transfer_id);
            }
        }
        applied
    }

    /// Pure, read-only computation of the far-horizon SEALED-stuck reap batch
    /// (co-fix (b), internal design notes). Mirrors
    /// [`Self::compute_expired_refund_batch`] but selects the OPPOSITE set:
    /// `Locked && !merkle_proof.is_empty() && now > expires_at + REAP_HORIZON_SECS`
    /// — SEALED transfers stuck ~30d past their claim deadline under a
    /// dead/partitioned dest committee (the `XZoneAbort` quorum never formed).
    /// Reusing `XZoneRefundBatch` as the payload; the DISTINCT
    /// `ParsedLedgerOp::XZoneStaleReap` op keeps the sealed-reap and unsealed-timeout
    /// predicates from ever being confused at apply time. Returns `None` when
    /// nothing is reap-eligible (the overwhelmingly common case).
    pub fn compute_stale_reap_batch(
        &self,
        now: f64,
        epoch: u64,
        zone: &str,
    ) -> Option<XZoneRefundBatch> {
        let mut refunds: Vec<(String, String, u64)> = self
            .pending
            .values()
            .filter(|t| {
                t.status == TransferStatus::Locked
                    && !t.merkle_proof.is_empty()
                    && now > t.expires_at + REAP_HORIZON_SECS
            })
            .map(|t| (t.transfer_id.clone(), t.sender.clone(), t.amount))
            .collect();
        if refunds.is_empty() {
            return None;
        }
        refunds.sort_by(|a, b| a.0.cmp(&b.0));
        Some(XZoneRefundBatch { epoch, zone: zone.to_string(), refunds })
    }

    /// Apply a frozen sealed-stuck reap batch — runs on EVERY node via the
    /// `XZoneStaleReap` record's apply path. Same skip-missing semantics and
    /// applied-subset conservation as [`Self::apply_refund_batch`], but the
    /// per-entry eligibility re-check requires the transfer to still be
    /// `Locked` AND SEALED (`!merkle_proof.is_empty()`). Flips to the existing
    /// `Refunded` terminal status (a reaped lock IS a refund to the sender) so
    /// `prune_completed` can finally evict it — the operator-facing distinction
    /// of "30d forced reap vs 24h passive timeout" lives at the record/op level
    /// (`XZoneStaleReap`), not the status level. Returns the actually-reaped
    /// `(sender, amount)` subset for the ledger to credit.
    pub fn apply_reap_batch(&mut self, batch: &XZoneRefundBatch) -> Vec<(String, u64)> {
        let mut applied: Vec<(String, u64)> = Vec::new();
        for (transfer_id, _frozen_sender, _frozen_amount) in &batch.refunds {
            if let Some(t) = self.pending.get_mut(transfer_id) {
                if t.status == TransferStatus::Locked && !t.merkle_proof.is_empty() {
                    let sender = t.sender.clone();
                    let amount = t.amount;
                    t.status = TransferStatus::Refunded;
                    self.total_locked = self.total_locked.saturating_sub(amount);
                    self.locked_count = self.locked_count.saturating_sub(1);
                    self.refunded_count += 1;
                    applied.push((sender, amount));
                }
            }
        }
        applied
    }

    /// Count of sealed transfers past their `expires_at` deadline that are
    /// still `Locked`. Mainnet-honest Gap 2 close: these
    /// transfers are awaiting an abort proof from the dest zone's committee
    /// and will NOT be passively refunded by `process_expired` — `process_expired`
    /// skips sealed transfers because passive refund would race an
    /// in-flight CLAIM and could break global conservation.
    ///
    /// Operator semantics:
    ///   * **Healthy state:** 0. The abort signing loop in `epoch_seal_loop`
    ///     gathers 2/3 of the dest committee within an epoch and submits the
    ///     abort bundle. Both passive timeout and abort path land on Refunded
    ///     /Aborted within seconds of expiry under normal operation.
    ///   * **Sustained non-zero (>10 min):** dest committee not gathering quorum
    ///     for abort. Causes: dest zone partitioned, dest committee fewer
    ///     than 2/3 online, or aggregator stuck (`xzone_abort_bundles_submitted_total`
    ///     not climbing). Page operator and investigate dest-zone health.
    ///   * **Distinct from `xzone_locked_past_expiry_count`:** that gauge
    ///     includes both unsealed (cleared next tick by passive refund) and
    ///     sealed (this gauge). Use this gauge for the unsafe-stuck signal.
    pub fn sealed_locked_past_expiry_count(&self, now: f64) -> u64 {
        self.pending
            .values()
            .filter(|t| {
                t.status == TransferStatus::Locked
                    && now > t.expires_at
                    && !t.merkle_proof.is_empty()
            })
            .count() as u64
    }

    /// Prune completed/refunded transfers older than cutoff.
    pub fn prune_completed(&mut self, cutoff: f64) -> usize {
        let before = self.pending.len();
        // Bookkeep dropped-by-status inside the retain closure
        // so the per-status counters stay in sync with `pending` after
        // pruning. Locked entries are never pruned (per the predicate),
        // so the Locked arm is unreachable.
        let mut dropped_claimed = 0u64;
        let mut dropped_refunded = 0u64;
        let mut dropped_aborted = 0u64;
        self.pending.retain(|_, t| {
            let keep = t.status == TransferStatus::Locked || t.locked_at > cutoff;
            if !keep {
                match t.status {
                    TransferStatus::Claimed => dropped_claimed += 1,
                    TransferStatus::Refunded => dropped_refunded += 1,
                    TransferStatus::Aborted => dropped_aborted += 1,
                    TransferStatus::Locked => {}
                }
            }
            keep
        });
        self.claimed_count = self.claimed_count.saturating_sub(dropped_claimed);
        self.refunded_count = self.refunded_count.saturating_sub(dropped_refunded);
        self.aborted_count = self.aborted_count.saturating_sub(dropped_aborted);
        before - self.pending.len()
    }

    /// Count of currently locked (in-flight) transfers.
    pub fn locked_count(&self) -> usize {
        self.pending.values().filter(|t| t.status == TransferStatus::Locked).count()
    }

    /// Age of the oldest still-Locked transfer, in seconds. Returns 0 if no
    /// Locked transfers exist (healthy idle state). Used by `/metrics` to
    /// surface a stuck-transfer early warning before the 24h `CLAIM_TIMEOUT_SECS`
    /// expiry sweeps the lock to refund. Healthy churn keeps this in the
    /// minutes-to-low-hours range as senders' counterparties claim; sustained
    /// climb toward 24h means a recipient zone is unable to claim (witness
    /// quorum can't form, recipient lost key, lock-zone seal stuck pre-finality).
    /// Mirrors the `pending_ledger_oldest_age_seconds` pattern (commit `7befbf3`).
    pub fn oldest_locked_age_secs(&self, now: f64) -> u64 {
        self.pending
            .values()
            .filter(|t| t.status == TransferStatus::Locked)
            .map(|t| (now - t.locked_at).max(0.0) as u64)
            .max()
            .unwrap_or(0)
    }

    /// Count of transfers that are still `Locked` *and* past their
    /// `expires_at` deadline. Includes BOTH unsealed (refunded passively
    /// next tick by `process_expired_xzone`, race-free per M7) AND sealed
    /// (refunded ONLY via dest-committee abort proof,
    /// because passive refund of sealed could race an in-flight CLAIM and
    /// break conservation). For the unsafe-stuck operator alarm, see
    /// `sealed_locked_past_expiry_count` — that gauge filters to the
    /// sealed subset which represents the actual conservation-risk window.
    /// In a healthy fleet this is at most a thin transient: unsealed
    /// transfers clear next epoch tick; sealed transfers clear once an
    /// XZoneAbort record gossiped by the dest-zone committee flips them
    /// to Aborted on every node. Distinct signal from
    /// `oldest_pending_age_seconds` (a healthy 23h-old lock raises that
    /// gauge but not this one).
    pub fn locked_past_expiry_count(&self, now: f64) -> u64 {
        self.pending
            .values()
            .filter(|t| t.status == TransferStatus::Locked && now > t.expires_at)
            .count() as u64
    }

    /// Get a pending transfer by ID.
    pub fn get(&self, transfer_id: &str) -> Option<&PendingTransfer> {
        self.pending.get(transfer_id)
    }
}

// ─── Merkle proof verification ──────────────────────────────────────────────

/// Verify a Merkle inclusion proof: walk from leaf hash up the sibling path,
/// confirm the computed root matches the expected root.
pub fn verify_inclusion_proof(
    leaf: &[u8; 32],
    proof: &[ProofSibling],
    expected_root: &[u8; 32],
) -> bool {
    let mut current = *leaf;
    for sibling in proof {
        let mut combined = [0u8; 64];
        if sibling.is_right {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(&sibling.hash);
        } else {
            combined[..32].copy_from_slice(&sibling.hash);
            combined[32..].copy_from_slice(&current);
        }
        current = sha3_256(&combined);
    }
    current == *expected_root
}

// ─── Gap 2.1: seal-finality proof verification ──────────────────────────────

/// Canonical signable bytes for an XZone seal-finality attestation.
///
/// Layout (length-prefixed to prevent ambiguity):
/// ```text
/// XZONE_FINALITY_DOMAIN
/// | zone_path           (u32 BE length || UTF-8 bytes)
/// | seal_epoch          (u64 BE)
/// | merkle_root         (32 bytes)
/// | committee_hash      (32 bytes)
/// ```
pub fn xzone_finality_signable_bytes(
    zone: &ZoneId,
    seal_epoch: u64,
    merkle_root: &[u8; 32],
    committee_hash: &[u8; 32],
) -> Vec<u8> {
    let zone_bytes = zone.path();
    let zone_bytes = zone_bytes.as_bytes();
    let mut out = Vec::with_capacity(
        XZONE_FINALITY_DOMAIN.len() + 4 + zone_bytes.len() + 8 + 32 + 32,
    );
    out.extend_from_slice(XZONE_FINALITY_DOMAIN);
    out.extend_from_slice(&(zone_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(zone_bytes);
    out.extend_from_slice(&seal_epoch.to_be_bytes());
    out.extend_from_slice(merkle_root);
    out.extend_from_slice(committee_hash);
    out
}

/// Build the canonical PK-leaf committee tree and return `(root,
/// proofs_by_pk)` — the producer-side helper for Gap 2.1 Phase 2b.3.
///
/// `pks` is the committee membership; this function:
/// 1. Hashes each PK via [`committee_leaf_hash`].
/// 2. Sorts leaves by hash, then dedupes (a witness signs each seal once).
/// 3. Builds a binary Merkle tree with "duplicate-last" padding for
///    odd levels (matches the verifier in [`verify_inclusion_proof`]).
/// 4. Records the inclusion proof for every leaf.
///
/// The returned root **equals** [`crate::network::zone_committee::committee_hash_from_pks`]
/// applied to the same `pks`. The returned proofs are the values the
/// witness packs into `SealFinalityWitness.committee_proof` — they
/// replay through `verify_inclusion_proof` against the pinned root,
/// which is exactly what [`verify_finality_quorum`] does on the
/// consumer side.
///
/// Empty input panics — a committee of size zero cannot form a quorum
/// and signing against `[0u8; 32]` would be a protocol error. Callers
/// should check `pks.is_empty()` before invoking.
///
/// Returns proofs keyed by the witness PK bytes so a node can look up
/// its own proof by `state.identity.public_key.clone()` without
/// caring about sort position.
pub fn build_committee_proofs(
    pks: &[Vec<u8>],
) -> ([u8; 32], std::collections::HashMap<Vec<u8>, Vec<ProofSibling>>) {
    assert!(!pks.is_empty(), "committee must be non-empty");

    // Sort + dedupe by leaf hash so the tree shape matches
    // committee_hash_from_pks. Track each unique PK alongside its
    // leaf hash so we can return per-PK proofs.
    let mut paired: Vec<([u8; 32], Vec<u8>)> = pks
        .iter()
        .cloned()
        .map(|pk| (committee_leaf_hash(&pk), pk))
        .collect();
    paired.sort_by_key(|a| a.0);
    paired.dedup_by(|a, b| a.0 == b.0);

    let leaves: Vec<[u8; 32]> = paired.iter().map(|p| p.0).collect();
    let pks_sorted: Vec<Vec<u8>> = paired.into_iter().map(|p| p.1).collect();
    let n = leaves.len();
    let mut proofs: Vec<Vec<ProofSibling>> = vec![Vec::new(); n];
    let mut level: Vec<[u8; 32]> = leaves.clone();
    let mut indices: Vec<usize> = (0..n).collect();

    while level.len() > 1 {
        let padded = if level.len() % 2 == 1 {
            let mut p = level.clone();
            // Invariant: while-guard holds level.len() > 1, so last() is Some;
            // spelled panic-free so a future refactor can't turn it into a DoS.
            if let Some(last) = p.last().copied() {
                p.push(last);
            }
            p
        } else {
            level.clone()
        };

        for (leaf_idx, cur_pos) in indices.iter().enumerate() {
            let pair_pos = if cur_pos % 2 == 0 { cur_pos + 1 } else { cur_pos - 1 };
            let sibling = padded[pair_pos.min(padded.len() - 1)];
            proofs[leaf_idx].push(ProofSibling {
                hash: sibling,
                is_right: cur_pos % 2 == 0,
            });
        }

        let mut next = Vec::with_capacity(padded.len() / 2);
        for chunk in padded.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&chunk[0]);
            buf[32..].copy_from_slice(&chunk[1]);
            next.push(sha3_256(&buf));
        }
        level = next;
        indices = indices.iter().map(|i| i / 2).collect();
    }

    let root = level[0];
    let proofs_by_pk: std::collections::HashMap<Vec<u8>, Vec<ProofSibling>> = pks_sorted
        .into_iter()
        .zip(proofs)
        .collect();
    (root, proofs_by_pk)
}

/// Producer-side helper: sign a seal-finality witness with `signer`
/// over the canonical message and bundle the signature with `signer`'s
/// committee proof.
///
/// Returns `None` if the signer's PK is not in `proofs_by_pk` —
/// callers should treat that as "this node is not in the committee
/// for this seal" and not gossip a useless witness.
///
/// Production callers pass `proofs_by_pk` from
/// [`build_committee_proofs`] (or a cached copy of it pinned at the
/// same `committee_hash`). The signed message is identical to what
/// [`verify_finality_quorum`] reconstructs on the consumer side.
pub fn sign_finality_witness(
    signer: &crate::identity::Identity,
    zone: &ZoneId,
    seal_epoch: u64,
    merkle_root: &[u8; 32],
    committee_hash: &[u8; 32],
    proofs_by_pk: &std::collections::HashMap<Vec<u8>, Vec<ProofSibling>>,
) -> Option<SealFinalityWitness> {
    let proof = proofs_by_pk.get(&signer.public_key)?.clone();
    let msg = xzone_finality_signable_bytes(zone, seal_epoch, merkle_root, committee_hash);
    let signature = signer.sign(&msg).ok()?;
    Some(SealFinalityWitness {
        witness_pk: signer.public_key.clone(),
        signature,
        committee_proof: proof,
    })
}

/// Sign an abort attestation over [`xzone_abort_signable_bytes`].
///
/// Mirrors [`sign_finality_witness`] for the Gap 2 sealed-abort path. A
/// B-committee witness calls this *only* after [`pending_abort_candidates`]
/// surfaces a transfer AND the witness has confirmed its membership in
/// the destination zone's committee at the relevant epoch.
///
/// Returns `None` if the signer's PK is not in `proofs_by_pk` — that is
/// the canonical "this node is not in the committee for the dest zone at
/// `source_seal_epoch`" signal; callers must drop the candidate, never
/// gossip a witness without a membership proof.
///
/// The output is wire-identical to a SealFinalityWitness produced by
/// `sign_finality_witness`, but signed over the abort domain so it is
/// non-replayable as a finality attestation. The receiver disambiguates
/// finality vs abort via the wrapping [`XZoneAbortBundle`] envelope, not
/// the signature shape.
pub fn sign_abort_witness(
    signer: &crate::identity::Identity,
    transfer_id: &str,
    dest_zone: &ZoneId,
    source_seal_epoch: u64,
    dest_committee_hash: &[u8; 32],
    proofs_by_pk: &std::collections::HashMap<Vec<u8>, Vec<ProofSibling>>,
) -> Option<SealFinalityWitness> {
    let proof = proofs_by_pk.get(&signer.public_key)?.clone();
    let msg = xzone_abort_signable_bytes(
        transfer_id,
        dest_zone,
        source_seal_epoch,
        dest_committee_hash,
    );
    let signature = signer.sign(&msg).ok()?;
    Some(SealFinalityWitness {
        witness_pk: signer.public_key.clone(),
        signature,
        committee_proof: proof,
    })
}

/// Gap 2 sealed-abort producer-side P-3c: orchestration helper that runs
/// the full "decide whether to sign and sign" pipeline against an in-hand
/// committee snapshot.
///
/// Mirrors the inline pattern at `src/network/ingest.rs:1726` (the seal-
/// finality sign hook) so the producer-side abort emitter can reuse it
/// without duplicating five lines of logic per call site.
///
/// Inputs:
///   * `signer`: the local node's identity.
///   * `transfer_id`, `dest_zone`, `source_seal_epoch`: the canonical
///     fields the abort signature commits to (replay-safe across zones
///     and source seals).
///   * `committee_pks`: ordered list of dest-zone finality committee PKs
///     for the relevant epoch. Pass exactly what
///     [`crate::network::zone_committee::finality_committee_pks`]
///     returned — the helper rebuilds the Merkle proofs locally rather
///     than threading a precomputed map through.
///   * `expected_committee_hash`: the dest-zone committee Merkle root
///     the caller pinned at observation time. Sanity-checked here:
///     if `build_committee_proofs(committee_pks)` does not produce this
///     root, the committee data is internally inconsistent and we
///     refuse to sign (otherwise the resulting signature would never
///     `verify_abort_quorum` against any other signer's view).
///
/// Returns `Some((witness, dest_committee_hash, dest_committee_size))`
/// when this node IS a member, the committee data is consistent, and
/// the Dilithium3 sign succeeds. Returns `None` otherwise (non-member,
/// committee mismatch, or sign failure) — none of which warrants an
/// error log because they are all expected: most nodes are not in any
/// given committee.
pub fn try_sign_xzone_abort(
    signer: &crate::identity::Identity,
    transfer_id: &str,
    dest_zone: &ZoneId,
    source_seal_epoch: u64,
    committee_pks: &[Vec<u8>],
    expected_committee_hash: &[u8; 32],
) -> Option<(SealFinalityWitness, [u8; 32], u32)> {
    if committee_pks.is_empty() {
        return None;
    }
    let am_member = committee_pks.iter().any(|pk| pk == &signer.public_key);
    if !am_member {
        return None;
    }
    let (computed_hash, proofs_by_pk) = build_committee_proofs(committee_pks);
    if &computed_hash != expected_committee_hash {
        // Internally-inconsistent committee data: caller pinned a hash
        // that doesn't match the PK list. Refuse to sign — a sig over
        // computed_hash would not satisfy verify_abort_quorum against
        // any aggregator that accepted expected_committee_hash, and
        // a sig over expected_committee_hash needs a Merkle proof we
        // can't produce.
        return None;
    }
    let witness = sign_abort_witness(
        signer,
        transfer_id,
        dest_zone,
        source_seal_epoch,
        expected_committee_hash,
        &proofs_by_pk,
    )?;
    let committee_size = committee_pks.len() as u32;
    Some((witness, computed_hash, committee_size))
}

/// Compute the leaf hash of a witness PK in the committee Merkle tree.
/// Domain-separated so a raw PK byte sequence cannot collide with a
/// non-leaf node.
pub fn committee_leaf_hash(witness_pk: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(witness_pk.len() + 16);
    buf.extend_from_slice(b"ELARA/COMMITTEE_LEAF/v1");
    buf.extend_from_slice(witness_pk);
    sha3_256(&buf)
}

/// Verify zone-A seal-finality quorum on the consumer side (zone B).
///
/// Steps:
/// 1. Compute the canonical signable message once.
/// 2. For each `SealFinalityWitness`:
///    - verify Merkle membership of `witness_pk` in `committee_hash`;
///    - verify Dilithium3 signature against the message;
///    - record the witness PK as a distinct verified signer.
/// 3. Require `3 * verified_count ≥ 2 * committee_size`.
///
/// Duplicate witness PKs are counted once. Bad signatures and non-committee
/// signers are silently dropped (they don't poison the proof — they just
/// don't contribute), to keep the quorum check forgiving when callers
/// over-include witnesses.
pub fn verify_finality_quorum(
    zone: &ZoneId,
    seal_epoch: u64,
    merkle_root: &[u8; 32],
    committee_hash: &[u8; 32],
    committee_size: u32,
    signers: &[SealFinalityWitness],
) -> Result<()> {
    if committee_size == 0 {
        return Err(ElaraError::Wire(
            "xzone finality: committee_size must be > 0 to enforce quorum".into(),
        ));
    }

    let msg = xzone_finality_signable_bytes(zone, seal_epoch, merkle_root, committee_hash);
    let mut verified: HashSet<Vec<u8>> = HashSet::with_capacity(signers.len());

    for w in signers {
        if verified.contains(&w.witness_pk) {
            continue; // dedupe duplicate signers
        }
        // (1) Committee membership
        let leaf = committee_leaf_hash(&w.witness_pk);
        if !verify_inclusion_proof(&leaf, &w.committee_proof, committee_hash) {
            continue;
        }
        // (2) Signature
        let ok = crate::identity::Identity::verify(&msg, &w.signature, &w.witness_pk)
            .unwrap_or(false);
        if !ok {
            continue;
        }
        verified.insert(w.witness_pk.clone());
    }

    let n = verified.len() as u128;
    let denom = committee_size as u128;
    if n.saturating_mul(3) < denom.saturating_mul(2) {
        return Err(ElaraError::Wire(format!(
            "xzone finality: {}/{} verified signers, need ≥2/3 of committee",
            n, denom
        )));
    }
    Ok(())
}

/// Canonical message that B-committee witnesses sign for a sealed-transfer
/// abort attestation (Gap 2 sealed-abort).
///
/// Layout (length-prefixed):
/// ```text
/// XZONE_ABORT_DOMAIN
/// | transfer_id          (u32 BE length || UTF-8 bytes)
/// | dest_zone_path       (u32 BE length || UTF-8 bytes)
/// | source_seal_epoch    (u64 BE)
/// | dest_committee_hash  (32 bytes)
/// ```
/// The dest_zone path + dest_committee_hash pin the sig to a specific
/// B-committee snapshot; the source_seal_epoch pins it to the seal that
/// caused the lock to become un-cancellable on the source side.
pub fn xzone_abort_signable_bytes(
    transfer_id: &str,
    dest_zone: &ZoneId,
    source_seal_epoch: u64,
    dest_committee_hash: &[u8; 32],
) -> Vec<u8> {
    let tid_bytes = transfer_id.as_bytes();
    let zone_path = dest_zone.path();
    let zone_bytes = zone_path.as_bytes();
    let mut out = Vec::with_capacity(
        XZONE_ABORT_DOMAIN.len() + 4 + tid_bytes.len() + 4 + zone_bytes.len() + 8 + 32,
    );
    out.extend_from_slice(XZONE_ABORT_DOMAIN);
    out.extend_from_slice(&(tid_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(tid_bytes);
    out.extend_from_slice(&(zone_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(zone_bytes);
    out.extend_from_slice(&source_seal_epoch.to_be_bytes());
    out.extend_from_slice(dest_committee_hash);
    out
}

/// Verify zone-B's committee abort attestation quorum on the source side.
///
/// Mirrors [`verify_finality_quorum`] but with the abort domain and pinned
/// against the destination zone's committee. Each signer is checked for
/// (1) committee membership against `dest_committee_hash`, (2) Dilithium3
/// signature over [`xzone_abort_signable_bytes`]. Quorum is ≥ 2/3 of
/// `dest_committee_size`. Duplicate signers are deduped; bad sigs and
/// non-members are silently dropped (forgiving overinclusion, same shape
/// as `verify_finality_quorum`).
///
/// `dest_committee_size == 0` is rejected — abort proof must be enforceable;
/// no "legacy back-compat" path for this signature, since we are creating
/// the type from scratch in Slice 1.
pub fn verify_abort_quorum(
    transfer_id: &str,
    dest_zone: &ZoneId,
    source_seal_epoch: u64,
    dest_committee_hash: &[u8; 32],
    dest_committee_size: u32,
    signers: &[SealFinalityWitness],
    anchored_dest_committee: Option<([u8; 32], u32)>,
) -> Result<()> {
    // B2 fix (internal design notes): the wire
    // `dest_committee_hash`/`dest_committee_size` are an attacker-controllable
    // CLAIM (the `XZoneAbort` record is unauthenticated wire input). Gate them
    // against the CANONICAL `(committee_hash, size)` frozen from the source-zone
    // seal at lock-ingest (`PendingTransfer.dest_finality_committee`), which is
    // read — never recomputed — so first-apply and historical replay verify the
    // identical value. Fail-closed when no anchor exists (legacy/pre-fix lock):
    // an unanchored abort is unenforceable and MUST NOT refund a sealed transfer.
    let (canon_hash, canon_size) = anchored_dest_committee.ok_or_else(|| {
        ElaraError::Wire(
            "xzone abort: no sealed dest-committee anchor for transfer; abort unenforceable (legacy/pre-fix lock)".into(),
        )
    })?;
    if dest_committee_hash != &canon_hash {
        return Err(ElaraError::Wire(
            "xzone abort: dest_committee_hash does not match the seal-anchored canonical committee — forged or stale".into(),
        ));
    }
    // The anchored size is authoritative for the 2/3 denominator; reject a wire
    // size that disagrees (a `size=1` sub-quorum claim against the real root).
    if dest_committee_size != canon_size {
        return Err(ElaraError::Wire(
            "xzone abort: dest_committee_size does not match the seal-anchored canonical committee".into(),
        ));
    }
    if canon_size == 0 {
        return Err(ElaraError::Wire(
            "xzone abort: dest_committee_size must be > 0 to enforce quorum".into(),
        ));
    }

    let msg = xzone_abort_signable_bytes(transfer_id, dest_zone, source_seal_epoch, &canon_hash);
    let mut verified: HashSet<Vec<u8>> = HashSet::with_capacity(signers.len());

    for w in signers {
        if verified.contains(&w.witness_pk) {
            continue;
        }
        let leaf = committee_leaf_hash(&w.witness_pk);
        if !verify_inclusion_proof(&leaf, &w.committee_proof, &canon_hash) {
            continue;
        }
        let ok = crate::identity::Identity::verify(&msg, &w.signature, &w.witness_pk)
            .unwrap_or(false);
        if !ok {
            continue;
        }
        verified.insert(w.witness_pk.clone());
    }

    let n = verified.len() as u128;
    let denom = canon_size as u128;
    if n.saturating_mul(3) < denom.saturating_mul(2) {
        return Err(ElaraError::Wire(format!(
            "xzone abort: {}/{} verified signers, need ≥2/3 of dest committee",
            n, denom
        )));
    }
    Ok(())
}

// ─── Gap 2.2: client-side transfer bundle ──────────────────────────────────

/// Self-contained, client-verifiable proof that a cross-zone transfer has
/// reached finality in its source zone — the wire form a account, light client,
/// or destination-zone validator replays through [`XZoneTransferBundle::verify`]
/// to confirm "the lock is real, sealed, and finalized" without holding the
/// source-zone DAG.
///
/// Mirrors the verification side of `claim_transfer`: bundles together the
/// lock-leaf + inclusion proof + seal root + the seal-finality witness
/// collection (Phase 2c), so callers can run the same checks
/// [`verify_inclusion_proof`] + [`verify_finality_quorum`] do, in one call.
///
/// Construction:
/// * Server-side: [`XZoneTransferBundle::from_pending`] assembles a bundle
///   from a `PendingTransfer` after `set_proof` + `set_finality_witnesses`
///   have populated the Phase-2c fields. Caller serves it via RPC.
/// * Client-side: deserialize from JSON / bincode, call
///   [`XZoneTransferBundle::verify`].
///
/// Wire-stable: every field is `serde`-tagged so the bundle round-trips as
/// JSON without precision loss. Vec<u8> fields go to a base64-ish JSON array
/// of u8 (same approach as Phase 2c gossip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XZoneTransferBundle {
    /// Lock record id (= `transfer_id` in `PendingTransfer`).
    pub transfer_id: String,
    /// Sender identity hash.
    pub sender: String,
    /// Recipient identity hash.
    pub recipient: String,
    /// Amount in base units.
    pub amount: u64,
    /// Source zone (where the lock was sealed).
    pub source_zone: ZoneId,
    /// Destination zone (where the claim will land).
    pub dest_zone: ZoneId,
    /// Lock record's leaf hash in the source-zone seal Merkle tree.
    pub lock_record_hash: [u8; 32],
    /// Inclusion proof: walks `lock_record_hash` up to `source_merkle_root`.
    pub merkle_proof: Vec<ProofSibling>,
    /// Source-zone epoch seal Merkle root that committed the lock.
    pub source_merkle_root: [u8; 32],
    /// Source-zone epoch number.
    pub source_seal_epoch: u64,
    /// Source-zone committee Merkle root at `source_seal_epoch`.
    pub source_committee_hash: [u8; 32],
    /// Source-zone committee size (denominator for the 2/3 quorum check).
    pub source_committee_size: u32,
    /// Witness signatures attesting `source_merkle_root` reached finality.
    pub source_seal_signers: Vec<SealFinalityWitness>,
}

impl XZoneTransferBundle {
    /// Assemble a bundle from a [`PendingTransfer`] that has already been
    /// sealed (`set_proof`) and finalized (`set_finality_witnesses`).
    ///
    /// Returns `None` if the transfer hasn't reached the sealed-and-finalized
    /// state yet — callers should retry after the next epoch boundary rather
    /// than try to verify a half-built bundle.
    pub fn from_pending(pt: &PendingTransfer) -> Option<Self> {
        if pt.merkle_proof.is_empty() || pt.source_committee_size == 0 {
            return None;
        }
        Some(Self {
            transfer_id: pt.transfer_id.clone(),
            sender: pt.sender.clone(),
            recipient: pt.recipient.clone(),
            amount: pt.amount,
            source_zone: pt.source_zone.clone(),
            dest_zone: pt.dest_zone.clone(),
            lock_record_hash: pt.lock_record_hash,
            merkle_proof: pt.merkle_proof.clone(),
            source_merkle_root: pt.source_merkle_root,
            source_seal_epoch: pt.source_seal_epoch,
            source_committee_hash: pt.source_committee_hash,
            source_committee_size: pt.source_committee_size,
            source_seal_signers: pt.source_seal_signers.clone(),
        })
    }

    /// Verify the bundle end-to-end:
    /// 1. The lock leaf is included in the source-zone seal (Merkle proof).
    /// 2. ≥ 2/3 of the source-zone committee signed the seal (finality quorum).
    ///
    /// On success the caller knows the transfer is atomically settled in the
    /// source zone — the funds are debited and the seal is final, so the
    /// destination zone (or a recipient account) can credit safely.
    ///
    /// Does NOT verify the destination-side claim record — that's the caller's
    /// concern (e.g., account checks the claim has been observed in zone B's
    /// DAG and signed by the recipient).
    pub fn verify(&self) -> Result<()> {
        if !verify_inclusion_proof(
            &self.lock_record_hash,
            &self.merkle_proof,
            &self.source_merkle_root,
        ) {
            return Err(ElaraError::Wire(format!(
                "xzone bundle {}: merkle inclusion proof invalid",
                self.transfer_id
            )));
        }
        verify_finality_quorum(
            &self.source_zone,
            self.source_seal_epoch,
            &self.source_merkle_root,
            &self.source_committee_hash,
            self.source_committee_size,
            &self.source_seal_signers,
        )
        .map_err(|e| {
            ElaraError::Wire(format!(
                "xzone bundle {}: finality quorum failed: {}",
                self.transfer_id, e
            ))
        })
    }
}

// ─── Gap 2 sealed-abort: client-side abort bundle ──────────────────────────

/// Self-contained, off-chain-verifiable proof that a sealed cross-zone transfer
/// was *not* claimed in zone B before its abort window closed — the wire form
/// a account, light client, or relayer hands to the source zone via
/// `/rpc/xzone_abort` to trigger an atomic refund.
///
/// Mirrors [`XZoneTransferBundle`] (which proves the lock IS sealed in zone A
/// to permit a claim in zone B). This bundle proves zone B's committee has
/// attested non-inclusion, so zone A can release the locked funds back to the
/// sender without a claim ever landing.
///
/// Construction:
/// * Producer-side (zone B witness): each B-committee witness signs
///   [`xzone_abort_signable_bytes`] with its Dilithium3 key after observing
///   that the abort deadline passed without a claim being admitted, then
///   gossips its `SealFinalityWitness` (PK + sig + Merkle inclusion proof).
/// * Aggregator (anyone): collects ≥2/3 of B-committee witness signatures
///   into a `Vec<SealFinalityWitness>` and assembles them into this bundle.
/// * Client-side: deserialize from JSON, call [`XZoneAbortBundle::verify`].
/// * Submitter (anyone): POST to `/rpc/xzone_abort` on a source-zone node.
///
/// Wire-stable: every field is `serde`-tagged so the bundle round-trips as
/// JSON. Nothing in the bundle is privileged — the proof itself is the
/// authorization, so any third party can submit it (mirrors the public-good
/// nature of /rpc/xzone_claim).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XZoneAbortBundle {
    /// The transfer to abort (= LOCK record id in zone A).
    pub transfer_id: String,
    /// Destination zone whose committee signed the non-inclusion attestation.
    /// Pinned into [`xzone_abort_signable_bytes`] so a B-committee sig
    /// from one zone cannot be replayed against a different zone's transfer.
    pub dest_zone: ZoneId,
    /// The source-zone seal epoch in which the lock became sealed —
    /// the moment after which sender-cancel/recipient-reject became unsafe.
    /// Pinned into the signed message so a B-committee attestation for one
    /// epoch cannot be replayed against an abort raised at a different epoch.
    pub source_seal_epoch: u64,
    /// Destination-zone committee Merkle root at the time the witnesses signed.
    pub dest_committee_hash: [u8; 32],
    /// Destination-zone committee size — denominator for the 2/3 quorum check.
    pub dest_committee_size: u32,
    /// Witness signatures attesting non-inclusion.
    pub signers: Vec<SealFinalityWitness>,
}

impl XZoneAbortBundle {
    /// Verify the bundle: ≥ 2/3 of `dest_committee_size` produced valid
    /// Dilithium3 sigs over [`xzone_abort_signable_bytes`], each signer
    /// proven a member of `dest_committee_hash` via Merkle inclusion proof.
    ///
    /// Wraps [`verify_abort_quorum`] so accounts and submitters can sanity-
    /// check before paying the on-chain submission cost.
    ///
    /// B2 note: this is a STRUCTURAL self-consistency check (signers are a 2/3
    /// quorum of the bundle's OWN claimed committee), NOT the canonical-anchor
    /// security gate — it passes the bundle's own `(hash, size)` as the anchor.
    /// The authoritative gate against the seal-frozen
    /// `PendingTransfer.dest_finality_committee` runs in `validate_op`/`apply_op`
    /// (which hold the local pending state); a forged bundle that passes this
    /// pre-flight is still rejected there.
    pub fn verify(&self) -> Result<()> {
        verify_abort_quorum(
            &self.transfer_id,
            &self.dest_zone,
            self.source_seal_epoch,
            &self.dest_committee_hash,
            self.dest_committee_size,
            &self.signers,
            Some((self.dest_committee_hash, self.dest_committee_size)),
        )
        .map_err(|e| {
            ElaraError::Wire(format!(
                "xzone abort bundle {}: quorum check failed: {}",
                self.transfer_id, e
            ))
        })
    }
}

// ─── Metadata builders ─────────────────────────────────────────────────────

/// Build LOCK metadata for a cross-zone transfer record.
pub fn lock_metadata(
    sender: &str,
    recipient: &str,
    amount: u64,
    source_zone: &ZoneId,
    dest_zone: &ZoneId,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(XZONE_OP_KEY.into(), serde_json::json!("lock"));
    m.insert("xzone_sender".into(), serde_json::json!(sender));
    m.insert("xzone_recipient".into(), serde_json::json!(recipient));
    m.insert("xzone_amount".into(), serde_json::json!(amount));
    m.insert("xzone_source_zone".into(), serde_json::json!(source_zone.path()));
    m.insert("xzone_dest_zone".into(), serde_json::json!(dest_zone.path()));
    m
}

/// Build CLAIM metadata for a cross-zone transfer record.
pub fn claim_metadata(
    transfer_id: &str,
    recipient: &str,
    amount: u64,
    merkle_proof: &[ProofSibling],
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(XZONE_OP_KEY.into(), serde_json::json!("claim"));
    m.insert("xzone_transfer_id".into(), serde_json::json!(transfer_id));
    m.insert("xzone_recipient".into(), serde_json::json!(recipient));
    m.insert("xzone_amount".into(), serde_json::json!(amount));
    let proof_json: Vec<serde_json::Value> = merkle_proof.iter().map(|s| {
        serde_json::json!({"hash": hex::encode(s.hash), "is_right": s.is_right})
    }).collect();
    m.insert("xzone_merkle_proof".into(), serde_json::json!(proof_json));
    m
}


// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a simple 2-leaf Merkle tree and return (leaf_hash, proof, root).
    fn make_test_proof(leaf_data: &[u8]) -> ([u8; 32], Vec<ProofSibling>, [u8; 32]) {
        let leaf = sha3_256(leaf_data);
        let sibling = sha3_256(b"sibling-leaf");

        // Tree: root = H(leaf || sibling)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf);
        combined[32..].copy_from_slice(&sibling);
        let root = sha3_256(&combined);

        let proof = vec![ProofSibling { hash: sibling, is_right: true }];
        (leaf, proof, root)
    }

    /// Lock a transfer and attach a valid inclusion proof + 1-of-1 finality
    /// witness, so `claim_transfer` accepts it under Phase 5 rules. The
    /// 1-witness committee is the smallest quorum-satisfying shape (1/1 ≥ 2/3),
    /// which keeps the helper cheap (one Dilithium3 keygen per call) while
    /// still exercising the real finality path. Tests that need to assert
    /// rejection at the inclusion or finality layer should NOT use this
    /// helper — they use `lock_with_inclusion_proof` directly.
    fn lock_with_proof(state: &mut CrossZoneState, id: &str, sender: &str, recipient: &str, amount: u64) {
        let (leaf, proof, root) = make_test_proof(id.as_bytes());
        state.lock_transfer(
            id.into(), sender.into(), recipient.into(),
            amount, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        state.set_proof(id, proof, root).unwrap();
        attach_test_finality(state, id, &root);
    }

    /// Sign a 1-of-1 finality quorum on the given transfer using a fresh
    /// witness identity. Committee size = 1, seal epoch = 1, source zone = "a"
    /// (matches `lock_with_proof`). Test-only; production builds attach
    /// real attestations via `attach_xzone_proofs_from_seal_with_finality`.
    fn attach_test_finality(state: &mut CrossZoneState, id: &str, root: &[u8; 32]) {
        let w = make_witness();
        let zone = ZoneId::new("a");
        let pks = vec![w.public_key.clone()];
        let (committee_hash, proofs) = build_committee(&pks);
        let sig = sign_finality(&w, &zone, 1, root, &committee_hash, proofs[0].clone());
        state
            .set_finality_witnesses(id, vec![sig], committee_hash, 1, 1)
            .unwrap();
    }

    /// The fleet-divergence digest must be a pure function of transfer
    /// state, independent of HashMap insertion/iteration order (obligation
    /// (e) hygiene for the detector itself; `source_seal_signers` exempt).
    #[test]
    fn state_digest_is_insertion_order_independent() {
        let build = |ids: &[&str]| {
            let mut s = CrossZoneState::new();
            for id in ids {
                let leaf = sha3_256(id.as_bytes());
                s.lock_transfer(
                    (*id).into(), "alice".into(), "bob".into(),
                    100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
                ).unwrap();
            }
            s
        };
        let forward = build(&["t-aa", "t-bb", "t-cc"]);
        let reverse = build(&["t-cc", "t-bb", "t-aa"]);
        assert_eq!(forward.state_digest(), reverse.state_digest());
        assert_ne!(forward.state_digest(), CrossZoneState::new().state_digest());
        // 53-bit mask: value must survive an f64 round-trip (Prometheus text).
        let d = forward.state_digest();
        assert_eq!(d, d as f64 as u64);
    }

    /// The digest must move when any tracked dimension moves: proof
    /// attachment, finality committee, and status transitions.
    #[test]
    fn state_digest_tracks_status_proof_and_committee() {
        let mut s = CrossZoneState::new();
        let (leaf, proof, root) = make_test_proof(b"t-digest");
        s.lock_transfer(
            "t-digest".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        let locked_bare = s.state_digest();

        s.set_proof("t-digest", proof, root).unwrap();
        let with_proof = s.state_digest();
        assert_ne!(locked_bare, with_proof, "proof_present must be tracked");

        attach_test_finality(&mut s, "t-digest", &root);
        let with_finality = s.state_digest();
        assert_ne!(with_proof, with_finality, "committee_size must be tracked");

        // Signer-set churn alone must NOT move the digest (node-local,
        // non-consensus): re-attach a different witness at the same
        // committee_size and expect equality.
        if let Some(t) = s.pending.get_mut("t-digest") {
            t.source_seal_signers.clear();
        }
        assert_eq!(
            with_finality,
            s.state_digest(),
            "source_seal_signers must be EXCLUDED from the digest"
        );
    }

    #[test]
    fn test_lock_and_claim() {
        // Phase 5 (2026-04-28): claim now requires a finality witness, so
        // this test attaches one over the cross-zone source zone (matches
        // the `finance/us` source we lock in). 1-of-1 quorum, signed by
        // a fresh test witness — same shape `lock_with_proof` uses.
        let mut state = CrossZoneState::new();
        let (leaf, proof, root) = make_test_proof(b"tx-1");
        let source_zone = ZoneId::new("finance/us");

        state.lock_transfer(
            "tx-1".into(), "alice".into(), "bob".into(),
            1_000_000, source_zone.clone(), ZoneId::new("finance/eu"), 1000.0, leaf,
        ).unwrap();

        assert_eq!(state.locked_count(), 1);
        assert_eq!(state.total_locked, 1_000_000);

        // Must set proof before claiming (M7)
        state.set_proof("tx-1", proof, root).unwrap();

        // Phase 5: attach a 1-of-1 finality witness so claim_transfer accepts.
        let w = make_witness();
        let pks = vec![w.public_key.clone()];
        let (committee_hash, proofs) = build_committee(&pks);
        let sig = sign_finality(&w, &source_zone, 1, &root, &committee_hash, proofs[0].clone());
        state.set_finality_witnesses("tx-1", vec![sig], committee_hash, 1, 1).unwrap();

        let claimed = state.claim_transfer("tx-1", "bob", "claim-rec-1", 2000.0).unwrap();
        assert_eq!(claimed.amount, 1_000_000);
        assert_eq!(claimed.status, TransferStatus::Claimed);
        assert_eq!(state.total_locked, 0);
    }

    #[test]
    fn test_claim_without_proof_rejected() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-1");

        state.lock_transfer(
            "tx-1".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        // No set_proof — claim should fail
        let result = state.claim_transfer("tx-1", "bob", "claim-1", 100.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not yet committed to epoch seal"));
    }

    #[test]
    fn test_claim_with_invalid_proof_rejected() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-1");

        state.lock_transfer(
            "tx-1".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        // Set a bogus proof that doesn't match the root
        let bogus_proof = vec![ProofSibling { hash: [99u8; 32], is_right: true }];
        let bogus_root = [0u8; 32]; // wrong root
        state.set_proof("tx-1", bogus_proof, bogus_root).unwrap();

        let result = state.claim_transfer("tx-1", "bob", "claim-1", 100.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("merkle proof invalid"));
    }

    #[test]
    fn test_lock_duplicate_fails() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-1");

        state.lock_transfer("tx-1".into(), "alice".into(), "bob".into(), 100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf).unwrap();
        let result = state.lock_transfer("tx-1".into(), "alice".into(), "bob".into(), 100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_same_zone_fails() {
        let mut state = CrossZoneState::new();
        let zone = ZoneId::new("finance");
        let leaf = sha3_256(b"tx-1");
        let result = state.lock_transfer("tx-1".into(), "alice".into(), "bob".into(), 100, zone.clone(), zone, 0.0, leaf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must differ"));
    }

    #[test]
    fn test_claim_wrong_recipient_fails() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-1", "alice", "bob", 100);
        let result = state.claim_transfer("tx-1", "charlie", "claim-1", 100.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not the recipient"));
    }

    #[test]
    fn test_claim_expired_fails() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-1", "alice", "bob", 100);

        // Try to claim after timeout
        let result = state.claim_transfer("tx-1", "bob", "claim-1", CLAIM_TIMEOUT_SECS + 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_process_expired_refunds() {
        let mut state = CrossZoneState::new();
        let leaf1 = sha3_256(b"tx-1");
        let leaf2 = sha3_256(b"tx-2");
        state.lock_transfer("tx-1".into(), "alice".into(), "bob".into(), 500, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf1).unwrap();
        state.lock_transfer("tx-2".into(), "alice".into(), "carol".into(), 300, ZoneId::new("a"), ZoneId::new("c"), 100.0, leaf2).unwrap();

        assert_eq!(state.total_locked, 800);

        // Expire tx-1 but not tx-2
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 1.0);
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].0, "tx-1");
        assert_eq!(refunds[0].2, 500);
        assert_eq!(state.total_locked, 300); // only tx-2 still locked
    }

    #[test]
    fn test_prune_completed() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-1", "alice", "bob", 100);
        state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap();

        assert_eq!(state.pending.len(), 1);
        let pruned = state.prune_completed(200.0);
        assert_eq!(pruned, 1);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn pending_abort_candidates_returns_sealed_unclaimed_past_deadline() {
        // Gap 2 sealed-abort producer side (P-1).
        // Setup: a sealed transfer (proof attached) where dest_zone matches
        // this node ("b") and the claim window has expired without a claim.
        // The detector must surface it as an abort candidate.
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-abort", "alice", "bob", 100);
        let dest = ZoneId::new("b");

        let candidates = state.pending_abort_candidates(&dest, CLAIM_TIMEOUT_SECS + 1.0);
        assert_eq!(candidates.len(), 1, "sealed-but-unclaimed must surface");
        assert_eq!(candidates[0].transfer_id, "tx-abort");
    }

    #[test]
    fn pending_abort_candidates_skips_unsealed_transfers() {
        // No merkle_proof attached → cancel/reject path applies, not abort.
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-unsealed");
        state.lock_transfer(
            "tx-unsealed".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        let dest = ZoneId::new("b");
        let candidates = state.pending_abort_candidates(&dest, CLAIM_TIMEOUT_SECS + 1.0);
        assert!(candidates.is_empty(), "unsealed must NOT surface for abort");
    }

    #[test]
    fn pending_abort_candidates_skips_other_zone() {
        // dest_zone is "b" but the witness asking is in zone "c". Witness
        // must not sign aborts for transfers it has no committee authority
        // over.
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-elsewhere", "alice", "bob", 100);

        let other = ZoneId::new("c");
        let candidates = state.pending_abort_candidates(&other, CLAIM_TIMEOUT_SECS + 1.0);
        assert!(candidates.is_empty(), "wrong-zone witness must not match");
    }

    #[test]
    fn pending_abort_candidates_skips_terminal_status() {
        // Already-Claimed, Refunded, Aborted transfers are terminal —
        // re-emitting an abort attestation would be a replay against the
        // existing dedup, but the detector should filter them upstream.
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-claimed", "alice", "bob", 100);
        // Claim in-window (claimer = recipient) so status flips to Claimed.
        state.claim_transfer("tx-claimed", "bob", "claim-1", 1.0).unwrap();

        let dest = ZoneId::new("b");
        let candidates = state.pending_abort_candidates(&dest, CLAIM_TIMEOUT_SECS + 1.0);
        assert!(candidates.is_empty(), "Claimed must not surface as abort candidate");
    }

    #[test]
    fn pending_abort_candidates_skips_in_window_transfers() {
        // Lock window has not yet elapsed. Aborting before the deadline
        // would race a still-valid claim; helper must wait.
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-fresh", "alice", "bob", 100);

        let dest = ZoneId::new("b");
        let candidates = state.pending_abort_candidates(&dest, CLAIM_TIMEOUT_SECS - 1.0);
        assert!(candidates.is_empty(), "in-window transfer must not surface");
    }

    #[test]
    fn test_conservation_invariant() {
        let mut state = CrossZoneState::new();

        // Lock 1000 across 3 transfers
        for i in 0..3 {
            let leaf = sha3_256(format!("tx-{i}").as_bytes());
            state.lock_transfer(
                format!("tx-{i}"), "alice".into(), "bob".into(),
                1000, ZoneId::new("a"), ZoneId::new("b"), i as f64, leaf,
            ).unwrap();
        }
        assert_eq!(state.total_locked, 3000);

        // Attach proof to tx-0 so it can be claimed
        let leaf = sha3_256(b"tx-0");
        let sibling = sha3_256(b"sibling-cons");
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf);
        combined[32..].copy_from_slice(&sibling);
        let root = sha3_256(&combined);
        state.pending.get_mut("tx-0").unwrap().lock_record_hash = leaf;
        state.set_proof("tx-0", vec![ProofSibling { hash: sibling, is_right: true }], root).unwrap();

        // Phase 5: attach finality witness so the claim path accepts.
        attach_test_finality(&mut state, "tx-0", &root);

        state.claim_transfer("tx-0", "bob", "claim-0", 100.0).unwrap();
        assert_eq!(state.total_locked, 2000);

        state.process_expired(CLAIM_TIMEOUT_SECS + 10.0);
        // tx-1 and tx-2 expired (locked_at=1.0 and 2.0)
        assert_eq!(state.total_locked, 0);
    }

    #[test]
    fn test_verify_inclusion_proof() {
        let (leaf, proof, root) = make_test_proof(b"test-leaf");
        assert!(verify_inclusion_proof(&leaf, &proof, &root));

        // Wrong leaf fails
        let wrong = sha3_256(b"wrong");
        assert!(!verify_inclusion_proof(&wrong, &proof, &root));

        // Tampered proof fails
        let mut bad_proof = proof.clone();
        bad_proof[0].hash = [0u8; 32];
        assert!(!verify_inclusion_proof(&leaf, &bad_proof, &root));
    }

    #[test]
    fn test_set_proof() {
        let mut state = CrossZoneState::new();
        let (leaf, proof, root) = make_test_proof(b"tx-1");

        state.lock_transfer(
            "tx-1".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        // Proof not set yet
        assert!(state.get("tx-1").unwrap().merkle_proof.is_empty());

        // Set proof
        state.set_proof("tx-1", proof, root).unwrap();
        assert!(!state.get("tx-1").unwrap().merkle_proof.is_empty());

        // Phase 5: claim now requires finality too — attach 1-of-1.
        attach_test_finality(&mut state, "tx-1", &root);

        // Now claim succeeds
        state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap();
    }

    #[test]
    fn test_lock_metadata() {
        let meta = lock_metadata("alice", "bob", 1000, &ZoneId::new("us"), &ZoneId::new("eu"));
        assert_eq!(meta.get(XZONE_OP_KEY).unwrap().as_str().unwrap(), "lock");
        assert_eq!(meta.get("xzone_amount").unwrap().as_u64().unwrap(), 1000);
    }

    #[test]
    fn test_claim_metadata() {
        let proof = vec![ProofSibling { hash: [1u8; 32], is_right: true }];
        let meta = claim_metadata("tx-1", "bob", 1000, &proof);
        assert_eq!(meta.get(XZONE_OP_KEY).unwrap().as_str().unwrap(), "claim");
        assert_eq!(meta.get("xzone_transfer_id").unwrap().as_str().unwrap(), "tx-1");
    }

    // ─── Gap 2.1: seal-finality quorum tests ────────────────────────────

    use crate::identity::{CryptoProfile, EntityType, Identity};

    /// Build a committee Merkle tree from a slice of witness PKs and return
    /// `(committee_hash, per-witness membership proofs)` aligned 1:1 with the
    /// input. Uses the same hash construction as `verify_inclusion_proof` so
    /// the proofs replay exactly.
    fn build_committee(witness_pks: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<ProofSibling>>) {
        assert!(!witness_pks.is_empty(), "committee must be non-empty");
        let leaves: Vec<[u8; 32]> = witness_pks.iter()
            .map(|pk| committee_leaf_hash(pk))
            .collect();

        // Rebuild the tree level by level, recording each node's level-mate
        // for proof construction. A level with an odd count duplicates the
        // last node (standard pad-to-power-of-2 trick). Proofs follow the
        // same rule when consumed by `verify_inclusion_proof`.
        let n = leaves.len();
        let mut proofs: Vec<Vec<ProofSibling>> = vec![Vec::new(); n];
        let mut level: Vec<[u8; 32]> = leaves.clone();
        let mut indices: Vec<usize> = (0..n).collect(); // current index of each leaf at this level

        while level.len() > 1 {
            let padded = if level.len() % 2 == 1 {
                let mut p = level.clone();
                p.push(*level.last().unwrap());
                p
            } else {
                level.clone()
            };

            for (leaf_idx, cur_pos) in indices.iter().enumerate() {
                let pair_pos = if cur_pos % 2 == 0 { cur_pos + 1 } else { cur_pos - 1 };
                let sibling = padded[pair_pos.min(padded.len() - 1)];
                proofs[leaf_idx].push(ProofSibling {
                    hash: sibling,
                    is_right: cur_pos % 2 == 0, // sibling is on the right when we are at even index
                });
            }

            // Build next level
            let mut next = Vec::with_capacity(padded.len() / 2);
            for chunk in padded.chunks(2) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&chunk[0]);
                buf[32..].copy_from_slice(&chunk[1]);
                next.push(sha3_256(&buf));
            }
            level = next;
            indices = indices.iter().map(|i| i / 2).collect();
        }

        (level[0], proofs)
    }

    fn make_witness() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    /// Sign a finality attestation and bundle it into a `SealFinalityWitness`.
    fn sign_finality(
        witness: &Identity,
        zone: &ZoneId,
        seal_epoch: u64,
        merkle_root: &[u8; 32],
        committee_hash: &[u8; 32],
        committee_proof: Vec<ProofSibling>,
    ) -> SealFinalityWitness {
        let msg = xzone_finality_signable_bytes(zone, seal_epoch, merkle_root, committee_hash);
        let sig = witness.sign(&msg).unwrap();
        SealFinalityWitness {
            witness_pk: witness.public_key.clone(),
            signature: sig,
            committee_proof,
        }
    }

    #[test]
    fn test_committee_proof_builds_and_verifies() {
        // Build a committee of 3 witnesses; verify each membership proof
        // round-trips through verify_inclusion_proof.
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (root, proofs) = build_committee(&pks);

        for (i, pk) in pks.iter().enumerate() {
            let leaf = committee_leaf_hash(pk);
            assert!(verify_inclusion_proof(&leaf, &proofs[i], &root),
                "committee proof for witness {i} must verify");
        }
    }

    fn lock_with_inclusion_proof(state: &mut CrossZoneState, id: &str, sender: &str, recipient: &str, amount: u64) {
        let (leaf, proof, root) = make_test_proof(id.as_bytes());
        state.lock_transfer(
            id.into(), sender.into(), recipient.into(),
            amount, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        state.set_proof(id, proof, root).unwrap();
    }

    #[test]
    fn test_xzone_claim_rejects_unattested_seal() {
        // Producer side declares a committee of size 3 but supplies zero
        // signers. Claim must be rejected — this is the Gap 2.1 core case
        // (seal published but not yet finalized).
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);
        state.set_finality_witnesses("tx-1", vec![], [9u8; 32], 42, 3).unwrap();

        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized in source zone"),
            "expected finality rejection, got: {err}");
    }

    #[test]
    fn test_xzone_claim_rejects_under_quorum() {
        // Committee of 3, only 1 signer (1/3 < 2/3) → reject.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);
        let signers = vec![sign_finality(&ws[0], &zone, 7, &root, &committee_hash, proofs[0].clone())];

        state.set_finality_witnesses("tx-1", signers, committee_hash, 7, 3).unwrap();
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized in source zone"),
            "got: {err}");
    }

    #[test]
    fn test_xzone_claim_accepts_at_quorum() {
        // Committee of 3, 2 signers (2/3 ≥ 2/3) → accept.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);
        let signers = vec![
            sign_finality(&ws[0], &zone, 7, &root, &committee_hash, proofs[0].clone()),
            sign_finality(&ws[1], &zone, 7, &root, &committee_hash, proofs[1].clone()),
        ];

        state.set_finality_witnesses("tx-1", signers, committee_hash, 7, 3).unwrap();
        let claimed = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap();
        assert_eq!(claimed.status, TransferStatus::Claimed);
    }

    #[test]
    fn test_xzone_claim_rejects_forged_attestation() {
        // 3 signers reach 2/3 in count, but one signs a bogus message
        // (wrong root) → only 2 verify, which is exactly quorum. Twist:
        // bump the bad signature so we drop below quorum (1/3 verifies).
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);

        // Two signers sign over a *wrong* root (substitution attempt).
        let bogus_root = [0xFFu8; 32];
        let mut bad0 = sign_finality(&ws[0], &zone, 7, &bogus_root, &committee_hash, proofs[0].clone());
        let mut bad1 = sign_finality(&ws[1], &zone, 7, &bogus_root, &committee_hash, proofs[1].clone());
        // Force the witness PKs to remain — only the signature is over the wrong msg
        bad0.committee_proof = proofs[0].clone();
        bad1.committee_proof = proofs[1].clone();
        // Third witness signs correctly — that's only 1/3, below 2/3 quorum.
        let good = sign_finality(&ws[2], &zone, 7, &root, &committee_hash, proofs[2].clone());

        state.set_finality_witnesses("tx-1", vec![bad0, bad1, good], committee_hash, 7, 3).unwrap();
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized in source zone"),
            "got: {err}");
    }

    #[test]
    fn test_xzone_claim_rejects_non_committee_signer() {
        // Committee of 3 known witnesses; attestations come from a 4th
        // (unrelated) witness — must fail membership check, no quorum.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, _proofs) = build_committee(&pks);

        let outsider = make_witness();
        // Build a fake committee containing the outsider, get its proof
        let outsider_pks = vec![outsider.public_key.clone()];
        let (_outsider_root, outsider_proofs) = build_committee(&outsider_pks);
        let fake_signer = sign_finality(
            &outsider,
            &zone,
            7,
            &root,
            &committee_hash, // signs against the real committee root, but isn't a member
            outsider_proofs[0].clone(), // membership proof against a different root
        );

        state.set_finality_witnesses("tx-1", vec![fake_signer], committee_hash, 7, 3).unwrap();
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized in source zone"),
            "got: {err}");
    }

    #[test]
    fn test_xzone_claim_rejects_when_committee_size_zero() {
        // Gap 2.1 Phase 5 (2026-04-28): the legacy bypass is gone. A claim
        // with committee_size=0 (producer never attached finality witnesses,
        // or attached them with a zero-sized committee) MUST be rejected.
        // This is the conservation-invariant safety net: an inclusion-only
        // proof can be forged from an orphaned source seal.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);
        // Don't call set_finality_witnesses — committee_size stays 0.
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(
            err.to_string().contains("seal not finalized"),
            "expected finality-rejection, got: {err}"
        );
        // Transfer must still be Locked — not flipped to Claimed by the
        // failed attempt — so the refund path can recover the funds at expiry.
        assert_eq!(state.get("tx-1").unwrap().status, TransferStatus::Locked);
    }

    #[test]
    fn test_xzone_claim_rejects_replay_across_epochs() {
        // Witness signs over (zone, epoch=7, root). Producer attaches the
        // signature with epoch=8 (replay attempt) — signature must fail
        // because the message bytes differ.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);

        // Two signers sign for epoch 7 — but we attach with epoch 8.
        let s0 = sign_finality(&ws[0], &zone, 7, &root, &committee_hash, proofs[0].clone());
        let s1 = sign_finality(&ws[1], &zone, 7, &root, &committee_hash, proofs[1].clone());

        state.set_finality_witnesses("tx-1", vec![s0, s1], committee_hash, 8, 3).unwrap();
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized in source zone"),
            "got: {err}");
    }

    #[test]
    fn conservation_holds_under_orphaned_source_seal() {
        // Gap 2.1 Phase 4 e2e + Gap 2 close — the
        // headline conservation case, post-passive-refund-removal.
        //
        // Scenario: zone-A publishes a tentative seal containing the LOCK
        // record (set_proof populated) but the seal is orphaned before
        // reaching 2/3 attestation. Producer-side declares the committee
        // size (committee_size=3) but never bundles enough signers — this
        // mimics the fork-and-abandon attack from the design doc.
        //
        // PRE-AUDIT-2026-05-01 BEHAVIOR (UNSAFE — REMOVED): the orphaned
        // seal would be passively refunded via `process_expired` after 24h.
        // That path raced an in-flight CLAIM record and could double-credit
        // under hostile timing (zone B credits, zone A refunds). Audit
        // identified this as Gap 2's actual hole.
        //
        // POST-AUDIT-2026-05-01 BEHAVIOR (SAFE):
        //   1. claim_transfer rejects with "seal not finalized" — zone B
        //      MUST NOT credit on an orphaned seal (unchanged).
        //   2. After expiry, `process_expired` does NOT refund the sealed
        //      transfer — it skips, deferring to the abort proof path
        //      (`abort_transfer`, requires a 2/3-quorum non-inclusion
        //      attestation from the dest committee at source_seal_epoch).
        //   3. The `xzone_sealed_locked_past_expiry_count` gauge surfaces
        //      the stuck transfer as the operator alarm.
        //   4. Conservation invariant is preserved: beats stay locked,
        //      not double-credited.
        //   5. Refund happens via `abort_transfer` once the dest committee
        //      signs an abort bundle (test continues below).
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-orphan", "alice", "bob", 100);
        assert_eq!(state.total_locked, 100, "lock should bump total_locked");

        // Producer declares committee_size=3 but supplies zero signers
        // (orphaned seal — consensus never converged on the LOCK's seal).
        state
            .set_finality_witnesses("tx-orphan", vec![], [0xAAu8; 32], 42, 3)
            .unwrap();

        // (1) claim is rejected even though inclusion proof is valid.
        let err = state
            .claim_transfer("tx-orphan", "bob", "claim-orphan", 50.0)
            .unwrap_err();
        assert!(
            err.to_string().contains("seal not finalized in source zone"),
            "orphaned-seal claim must be rejected, got: {err}"
        );
        assert_eq!(state.total_locked, 100, "rejection must not move funds");
        assert_eq!(
            state.get("tx-orphan").unwrap().status,
            TransferStatus::Locked,
            "rejection must leave status Locked, not advance to Claimed"
        );

        // (2) Time advances past the 24h claim window. Sweeper SKIPS this
        //     sealed transfer — passive refund of
        //     a sealed transfer would race an in-flight CLAIM and break
        //     conservation.
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 1.0);
        assert!(
            refunds.is_empty(),
            "an internal audit: process_expired must NOT refund sealed \
             transfers — got: {refunds:?}"
        );

        // (3) The unsafe-stuck signal: this transfer is sealed AND past
        //     expiry, the operator alarm.
        assert_eq!(
            state.sealed_locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 1.0),
            1,
            "sealed_locked_past_expiry_count must surface the stuck transfer"
        );

        // (4) Conservation under stuck-state: beats are still in
        //     pending_xzone (`total_locked == 100`); recipient doesn't have
        //     them either (`claim_transfer` rejected). No double-credit.
        assert_eq!(
            state.total_locked, 100,
            "beats stay locked until abort proof clears them"
        );
        assert_eq!(
            state.get("tx-orphan").unwrap().status,
            TransferStatus::Locked,
            "stuck transfer remains Locked, awaiting abort proof"
        );

        // (5) Abort path clears it — this is the only safe refund route
        //     for sealed transfers. The dest
        //     committee signs a non-inclusion proof; production wires
        //     this through `try_sign_xzone_abort` + `verify_abort_quorum`
        //     in `apply_op`. Here we exercise the state-transition only.
        let (tid, sender, amount) = state.abort_transfer("tx-orphan").unwrap();
        assert_eq!(tid, "tx-orphan");
        assert_eq!(sender, "alice");
        assert_eq!(amount, 100);

        // Conservation now holds: lock cleared, sender's beats recoverable
        // by the apply path's account-credit step.
        assert_eq!(
            state.total_locked, 0,
            "conservation invariant: total_locked zeros out after abort"
        );
        assert_eq!(
            state.get("tx-orphan").unwrap().status,
            TransferStatus::Aborted,
            "orphaned-seal terminates as Aborted (active B-committee path)"
        );

        // Re-running the sweeper is still a no-op.
        let again = state.process_expired(CLAIM_TIMEOUT_SECS * 2.0);
        assert!(again.is_empty(), "sweeper must not refund anything");
    }

    #[test]
    fn process_expired_skips_sealed_transfers_audit_2026_05_01() {
        // Gap 2 safety property: passive refund must NOT
        // run on sealed transfers. Sealed transfers are only refundable
        // via the abort proof path; passive refund races an in-flight
        // CLAIM and could break global conservation.
        //
        // Setup: two transfers, both past expiry, one unsealed and one
        // sealed. After process_expired:
        //   * Unsealed → Refunded (race-free; no CLAIM can succeed
        //     against an unsealed lock per M7).
        //   * Sealed → still Locked (audit close).
        let mut state = CrossZoneState::new();

        // Unsealed lock — passive refund eligible.
        let leaf_u = sha3_256(b"tx-unsealed");
        state
            .lock_transfer(
                "tx-unsealed".into(), "alice".into(), "bob".into(),
                100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf_u,
            )
            .unwrap();

        // Sealed lock — passive refund must skip post-audit.
        lock_with_inclusion_proof(&mut state, "tx-sealed", "alice", "bob", 200);

        assert_eq!(state.total_locked, 300, "both locks counted");

        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 100.0);

        // Exactly one refund — the unsealed transfer.
        assert_eq!(
            refunds.len(), 1,
            "exactly one transfer (unsealed) refunded, got: {refunds:?}"
        );
        assert_eq!(refunds[0].0, "tx-unsealed", "unsealed must be refunded");

        // Sealed remains Locked — must use abort path.
        assert_eq!(
            state.get("tx-sealed").unwrap().status,
            TransferStatus::Locked,
            "sealed transfer must NOT be refunded by process_expired"
        );
        assert_eq!(
            state.total_locked, 200,
            "200 base units remain locked in the sealed transfer"
        );

        // Operator alarm gauge surfaces the stuck transfer.
        assert_eq!(
            state.sealed_locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 100.0),
            1,
            "sealed_locked_past_expiry_count surfaces the stuck transfer"
        );

        // The broader past-expiry gauge no longer counts the unsealed
        // (it's been Refunded) — both gauges agree on 1.
        assert_eq!(
            state.locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 100.0),
            1,
            "broader gauge counts the same stuck transfer"
        );
    }

    #[test]
    fn sealed_locked_past_expiry_count_only_counts_sealed_locked() {
        // Axis test for the gauge: the count must filter on
        // (status==Locked) AND (now > expires_at) AND (merkle_proof
        // non-empty). Other combinations are 0 — the gauge is the precise
        // unsafe-stuck signal, distinct from `locked_past_expiry_count`
        // (which includes unsealed transients).
        let mut state = CrossZoneState::new();

        // (a) sealed + past-expiry + Locked → counted.
        lock_with_inclusion_proof(&mut state, "tx-stuck", "alice", "bob", 1);
        // (b) sealed + past-expiry + Aborted → not counted (terminal).
        //     `lock_with_proof` adds finality witnesses (sets
        //     `source_seal_epoch>0`) which `abort_transfer` requires.
        lock_with_proof(&mut state, "tx-aborted", "alice", "bob", 1);
        state.abort_transfer("tx-aborted").unwrap();
        // (c) unsealed + past-expiry + Locked → not counted (passive
        //     refund eligible).
        let leaf_c = sha3_256(b"tx-c");
        state
            .lock_transfer(
                "tx-c".into(), "alice".into(), "bob".into(),
                1, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf_c,
            )
            .unwrap();
        // (d) sealed + still-in-window + Locked → not counted (no
        //     deadline pressure).
        lock_with_inclusion_proof(&mut state, "tx-fresh", "alice", "bob", 1);

        // Run the gauge AT a time past expiry for tx-stuck/tx-aborted/tx-c
        // but BEFORE expiry for tx-fresh (locked_at = locked_at_for_fresh).
        // Using a single timestamp `CLAIM_TIMEOUT_SECS + 100` means
        // tx-fresh (locked_at=0) is also past expiry — to keep tx-fresh
        // in-window, set its locked_at recent. Reset its lock_at:
        if let Some(t) = state.pending.get_mut("tx-fresh") {
            t.locked_at = CLAIM_TIMEOUT_SECS;
            t.expires_at = CLAIM_TIMEOUT_SECS + CLAIM_TIMEOUT_SECS;
        }

        let now = CLAIM_TIMEOUT_SECS + 100.0;
        assert_eq!(
            state.sealed_locked_past_expiry_count(now),
            1,
            "only tx-stuck matches all three filter conditions"
        );
    }

    // ─── Gap 2.1 Phase 2b.3: production helpers ────────────────────────

    #[cfg(feature = "node-core")]
    #[test]
    fn build_committee_proofs_root_matches_committee_hash_from_pks() {
        // Round-trip invariant: the production helper's root must equal
        // the network::zone_committee::committee_hash_from_pks output
        // for the same committee. If these ever diverge, witness
        // signatures pinned to one root would never verify against the
        // other.
        use crate::network::zone_committee::committee_hash_from_pks;
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (root, _proofs) = build_committee_proofs(&pks);
        let expected = committee_hash_from_pks(&pks);
        assert_eq!(root, expected, "production root must match standalone hash");
    }

    #[test]
    fn build_committee_proofs_is_order_independent() {
        let ws: Vec<Identity> = (0..4).map(|_| make_witness()).collect();
        let pks_a: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let mut pks_b = pks_a.clone();
        pks_b.reverse();

        let (root_a, _) = build_committee_proofs(&pks_a);
        let (root_b, _) = build_committee_proofs(&pks_b);
        assert_eq!(root_a, root_b, "input ordering must not affect root");
    }

    #[test]
    fn build_committee_proofs_returns_membership_for_every_pk() {
        let ws: Vec<Identity> = (0..6).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (root, proofs_by_pk) = build_committee_proofs(&pks);

        for pk in &pks {
            let proof = proofs_by_pk.get(pk).expect("every committee pk has a proof");
            let leaf = committee_leaf_hash(pk);
            assert!(
                verify_inclusion_proof(&leaf, proof, &root),
                "membership proof must verify for committee member"
            );
        }
    }

    #[test]
    fn sign_finality_witness_round_trips_through_verify_finality_quorum() {
        // End-to-end: build → sign with 4-of-5 → verify_finality_quorum
        // accepts (≥ 2/3 of 5 = 4 verified signatures).
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let zone = ZoneId::new("medical/eu");
        let merkle_root = [0xCDu8; 32];
        let seal_epoch = 42;

        let signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                sign_finality_witness(
                    w,
                    &zone,
                    seal_epoch,
                    &merkle_root,
                    &committee_hash,
                    &proofs_by_pk,
                )
                .expect("signer is in committee")
            })
            .collect();

        verify_finality_quorum(
            &zone,
            seal_epoch,
            &merkle_root,
            &committee_hash,
            5,
            &signers,
        )
        .expect("4-of-5 must satisfy 2/3 quorum");
    }

    #[test]
    fn sign_finality_witness_returns_none_for_non_member() {
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let outsider = make_witness();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let zone = ZoneId::new("a");
        let merkle_root = [0u8; 32];
        let result = sign_finality_witness(
            &outsider,
            &zone,
            1,
            &merkle_root,
            &committee_hash,
            &proofs_by_pk,
        );
        assert!(result.is_none(), "non-member must not produce a witness");
    }

    // ─── Gap 2 sealed-abort producer-side P-2: sign_abort_witness ──────

    #[test]
    fn sign_abort_witness_round_trips_through_verify_abort_quorum() {
        // 5-member B-committee. 4 sign — that's 4/5 ≥ 2/3 → accept.
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let dest_zone = ZoneId::new("medical/eu");
        let transfer_id = "tx-abort-roundtrip";
        let source_seal_epoch = 1337;

        let signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                sign_abort_witness(
                    w,
                    transfer_id,
                    &dest_zone,
                    source_seal_epoch,
                    &committee_hash,
                    &proofs_by_pk,
                )
                .expect("signer is in committee")
            })
            .collect();

        verify_abort_quorum(
            transfer_id,
            &dest_zone,
            source_seal_epoch,
            &committee_hash,
            5,
            &signers,
            Some((committee_hash, 5)),
        )
        .expect("4-of-5 must satisfy 2/3 quorum");
    }

    #[test]
    fn sign_abort_witness_returns_none_for_non_member() {
        // Outsider is not in the committee — no membership proof — must
        // return None so the caller drops the candidate without gossiping
        // an unverifiable witness.
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let outsider = make_witness();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let result = sign_abort_witness(
            &outsider,
            "tx-outsider",
            &ZoneId::new("a"),
            1,
            &committee_hash,
            &proofs_by_pk,
        );
        assert!(result.is_none(), "non-member must not produce an abort witness");
    }

    #[test]
    fn sign_abort_witness_signature_is_not_replayable_as_finality() {
        // Critical safety invariant: an abort signature must NOT verify
        // as a finality attestation. The two paths share the
        // SealFinalityWitness shape but use different domain prefixes —
        // if an attacker scoops up an abort witness and submits it as a
        // finality proof for the same (zone, epoch, root), the conservation
        // bug returns. Pin the cross-domain rejection.
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let dest_zone = ZoneId::new("a");
        let transfer_id = "tx-cross-domain";
        let epoch = 7u64;
        // The merkle_root chosen below is what verify_finality_quorum
        // will hash into its candidate message. The abort signers signed
        // over a totally different message (XZONE_ABORT_DOMAIN || tid ||
        // zone || epoch || committee_hash). Even if we hand verify_finality
        // the same committee, the signatures must NOT verify because the
        // signed bytes differ.
        let merkle_root = [0xAAu8; 32];

        let abort_signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                sign_abort_witness(
                    w,
                    transfer_id,
                    &dest_zone,
                    epoch,
                    &committee_hash,
                    &proofs_by_pk,
                )
                .expect("member")
            })
            .collect();

        let err = verify_finality_quorum(
            &dest_zone,
            epoch,
            &merkle_root,
            &committee_hash,
            5,
            &abort_signers,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("verified signers, need ≥2/3"),
            "abort sigs must not satisfy finality quorum, got: {err}"
        );
    }

    // ─── Gap 2 sealed-abort producer-side P-3c: try_sign_xzone_abort ──

    #[test]
    fn try_sign_xzone_abort_round_trips_through_verify() {
        // 5-member dest committee; orchestration helper wraps membership
        // check + proof rebuild + sign. 4 signers cross 2/3 threshold.
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, _proofs) = build_committee_proofs(&pks);

        let dest_zone = ZoneId::new("eu");
        let transfer_id = "tx-orch";
        let epoch = 99u64;

        let signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                let (witness, hash, size) = try_sign_xzone_abort(
                    w,
                    transfer_id,
                    &dest_zone,
                    epoch,
                    &pks,
                    &committee_hash,
                )
                .expect("committee member must produce a witness");
                assert_eq!(hash, committee_hash);
                assert_eq!(size, 5);
                witness
            })
            .collect();

        verify_abort_quorum(
            transfer_id,
            &dest_zone,
            epoch,
            &committee_hash,
            5,
            &signers,
            Some((committee_hash, 5)),
        )
        .expect("4-of-5 must satisfy 2/3 abort quorum");
    }

    #[test]
    fn try_sign_xzone_abort_returns_none_for_non_member() {
        // Outsider's PK is absent from the committee — helper must drop
        // the candidate without gossiping a witness it cannot prove
        // membership for.
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let outsider = make_witness();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, _proofs) = build_committee_proofs(&pks);

        let result = try_sign_xzone_abort(
            &outsider,
            "tx-outsider",
            &ZoneId::new("a"),
            1,
            &pks,
            &committee_hash,
        );
        assert!(result.is_none(), "non-member must return None");
    }

    #[test]
    fn try_sign_xzone_abort_rejects_committee_hash_mismatch() {
        // Caller pinned a hash that doesn't match the supplied PK list —
        // signing would produce a witness that no aggregator could
        // verify against the same expected_committee_hash. Refuse.
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let bogus_hash = [0xDEu8; 32];

        let result = try_sign_xzone_abort(
            &ws[0],
            "tx-mismatch",
            &ZoneId::new("a"),
            1,
            &pks,
            &bogus_hash,
        );
        assert!(
            result.is_none(),
            "committee data must be internally consistent; mismatch refused"
        );
    }

    #[test]
    fn try_sign_xzone_abort_rejects_empty_committee() {
        // Edge case: an empty committee has no members and no Merkle root —
        // helper must fail closed.
        let signer = make_witness();
        let result = try_sign_xzone_abort(
            &signer,
            "tx-empty",
            &ZoneId::new("a"),
            1,
            &[],
            &[0u8; 32],
        );
        assert!(result.is_none(), "empty committee must refuse");
    }

    #[test]
    fn try_sign_xzone_abort_signature_is_not_replayable_as_finality() {
        // Same cross-domain safety pin as P-2 but exercised via the
        // orchestration helper — guards against an aggregator collecting
        // try_sign_xzone_abort outputs and submitting them as finality
        // attestations.
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);

        let dest_zone = ZoneId::new("a");
        let transfer_id = "tx-cross-orch";
        let epoch = 11u64;
        let merkle_root = [0xAAu8; 32];

        let abort_signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                try_sign_xzone_abort(
                    w,
                    transfer_id,
                    &dest_zone,
                    epoch,
                    &pks,
                    &committee_hash,
                )
                .map(|(witness, _, _)| witness)
                .unwrap()
            })
            .collect();

        // Same 4 abort signers handed to verify_finality_quorum — the
        // domain prefix differs so the sigs must NOT verify against the
        // finality canonical message.
        let err = verify_finality_quorum(
            &dest_zone,
            epoch,
            &merkle_root,
            &committee_hash,
            5,
            &abort_signers,
        )
        .unwrap_err();
        let _ = &proofs_by_pk; // silence unused
        assert!(
            err.to_string().contains("verified signers, need ≥2/3"),
            "orchestrated abort sigs must not satisfy finality quorum, got: {err}"
        );
    }

    // ─── Gap 2.2: client-side bundle ──────────────────────────────────

    /// Build a fully-finalized PendingTransfer (sealed + 4-of-5 signed)
    /// suitable for assembling a bundle. Returns the state and the
    /// transfer_id.
    fn lock_seal_finalize(state: &mut CrossZoneState, id: &str) -> ([u8; 32], u32) {
        lock_with_inclusion_proof(state, id, "alice", "bob", 100);
        let zone = ZoneId::new("a");
        let root = state.get(id).unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..5).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs_by_pk) = build_committee_proofs(&pks);
        let signers: Vec<SealFinalityWitness> = ws[..4]
            .iter()
            .map(|w| {
                sign_finality_witness(w, &zone, 7, &root, &committee_hash, &proofs_by_pk)
                    .expect("member")
            })
            .collect();
        state
            .set_finality_witnesses(id, signers, committee_hash, 7, 5)
            .unwrap();
        (committee_hash, 5)
    }

    #[test]
    fn xzone_bundle_round_trips_through_json() {
        let mut state = CrossZoneState::new();
        let _ = lock_seal_finalize(&mut state, "tx-1");
        let pt = state.get("tx-1").unwrap();
        let bundle = XZoneTransferBundle::from_pending(pt).expect("sealed+finalized");

        let json = serde_json::to_string(&bundle).expect("serialize");
        let decoded: XZoneTransferBundle = serde_json::from_str(&json).expect("deserialize");

        decoded.verify().expect("round-tripped bundle must verify");
        assert_eq!(decoded.transfer_id, "tx-1");
        assert_eq!(decoded.amount, 100);
    }

    #[test]
    fn xzone_bundle_from_pending_none_before_seal() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-1");
        state
            .lock_transfer(
                "tx-1".into(),
                "alice".into(),
                "bob".into(),
                100,
                ZoneId::new("a"),
                ZoneId::new("b"),
                0.0,
                leaf,
            )
            .unwrap();
        // No set_proof / set_finality_witnesses — bundle must refuse.
        let pt = state.get("tx-1").unwrap();
        assert!(
            XZoneTransferBundle::from_pending(pt).is_none(),
            "must not bundle pre-seal transfers"
        );
    }

    #[test]
    fn xzone_bundle_verify_rejects_tampered_root() {
        let mut state = CrossZoneState::new();
        lock_seal_finalize(&mut state, "tx-1");
        let pt = state.get("tx-1").unwrap();
        let mut bundle = XZoneTransferBundle::from_pending(pt).unwrap();

        // Flip the seal root — inclusion proof must fail.
        bundle.source_merkle_root[0] ^= 0xFF;
        let err = bundle.verify().unwrap_err();
        assert!(
            err.to_string().contains("merkle inclusion proof invalid"),
            "got: {err}"
        );
    }

    #[test]
    fn xzone_bundle_verify_rejects_dropped_witnesses() {
        let mut state = CrossZoneState::new();
        lock_seal_finalize(&mut state, "tx-1");
        let pt = state.get("tx-1").unwrap();
        let mut bundle = XZoneTransferBundle::from_pending(pt).unwrap();

        // Drop signers below 2/3 — quorum must fail. 5-member committee
        // needs ≥ 4 verified; truncating to 2 leaves us at 2/5 < 2/3.
        bundle.source_seal_signers.truncate(2);
        let err = bundle.verify().unwrap_err();
        assert!(
            err.to_string().contains("finality quorum failed"),
            "got: {err}"
        );
    }

    // ─── Gap 2 atomic-rollback (cancel_transfer) ─────────────────────────

    #[test]
    fn cancel_unsealed_transfer_refunds_sender() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-cancel");
        state.lock_transfer(
            "tx-cancel".into(), "alice".into(), "bob".into(),
            500_000, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        assert_eq!(state.total_locked, 500_000);

        // Lock has not been sealed (no set_proof called) — cancel succeeds.
        let (tid, sender, amount) = state.cancel_transfer("tx-cancel", "alice").unwrap();
        assert_eq!(tid, "tx-cancel");
        assert_eq!(sender, "alice");
        assert_eq!(amount, 500_000);
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-cancel").unwrap().status,
            TransferStatus::Refunded
        );
    }

    #[test]
    fn cancel_after_seal_rejected() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-sealed", "alice", "bob", 100);

        // Once set_proof has run, recipient could be in-flight to claim —
        // sender-initiated cancel must refuse.
        let err = state.cancel_transfer("tx-sealed", "alice").unwrap_err();
        assert!(
            err.to_string().contains("already sealed"),
            "expected 'already sealed' error, got: {err}"
        );
        // total_locked unchanged.
        assert_eq!(state.total_locked, 100);
    }

    #[test]
    fn cancel_by_non_sender_rejected() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-other");
        state.lock_transfer(
            "tx-other".into(), "alice".into(), "bob".into(),
            42, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        // Bob is the recipient, not the canceller. Even mallory pretending
        // to be alice can't — the canceller string must match exactly.
        let err = state.cancel_transfer("tx-other", "bob").unwrap_err();
        assert!(
            err.to_string().contains("not the sender"),
            "got: {err}"
        );
        let err = state.cancel_transfer("tx-other", "mallory").unwrap_err();
        assert!(err.to_string().contains("not the sender"), "got: {err}");
        assert_eq!(state.total_locked, 42);
    }

    #[test]
    fn cancel_already_terminal_rejected() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-claimed", "alice", "bob", 7);
        // Claim it.
        state.claim_transfer("tx-claimed", "bob", "claim-rec", 1.0).unwrap();
        // Cannot cancel a Claimed transfer.
        let err = state.cancel_transfer("tx-claimed", "alice").unwrap_err();
        assert!(err.to_string().contains("cannot cancel"), "got: {err}");

        // Same for an already-Refunded transfer (timeout path).
        let leaf = sha3_256(b"tx-refunded");
        state.lock_transfer(
            "tx-refunded".into(), "alice".into(), "bob".into(),
            8, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 100.0);
        assert_eq!(refunds.len(), 1);
        let err = state.cancel_transfer("tx-refunded", "alice").unwrap_err();
        assert!(err.to_string().contains("cannot cancel"), "got: {err}");
    }

    #[test]
    fn cancel_unknown_transfer_rejected() {
        let mut state = CrossZoneState::new();
        let err = state.cancel_transfer("missing", "alice").unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    // ─── Gap 2 atomic-rollback (reject_transfer — recipient side) ────────

    #[test]
    fn reject_unsealed_transfer_refunds_sender() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-reject");
        state.lock_transfer(
            "tx-reject".into(), "alice".into(), "bob".into(),
            500_000, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        assert_eq!(state.total_locked, 500_000);

        // Lock has not been sealed — recipient bob can reject.
        let (tid, sender, amount) = state.reject_transfer("tx-reject", "bob").unwrap();
        assert_eq!(tid, "tx-reject");
        // Refund destination is the SENDER, not the rejector.
        assert_eq!(sender, "alice");
        assert_eq!(amount, 500_000);
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-reject").unwrap().status,
            TransferStatus::Refunded
        );
    }

    #[test]
    fn reject_after_seal_rejected() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-sealed-r", "alice", "bob", 100);

        // Once set_proof has run, recipient could already have submitted a
        // claim in zone B — recipient-side reject must refuse.
        let err = state.reject_transfer("tx-sealed-r", "bob").unwrap_err();
        assert!(
            err.to_string().contains("already sealed"),
            "expected 'already sealed' error, got: {err}"
        );
        assert_eq!(state.total_locked, 100);
    }

    #[test]
    fn reject_by_non_recipient_rejected() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-rj-wrong");
        state.lock_transfer(
            "tx-rj-wrong".into(), "alice".into(), "bob".into(),
            42, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();

        // Sender alice is NOT the rejector path (use cancel_transfer for that).
        let err = state.reject_transfer("tx-rj-wrong", "alice").unwrap_err();
        assert!(
            err.to_string().contains("not the recipient"),
            "got: {err}"
        );
        let err = state.reject_transfer("tx-rj-wrong", "mallory").unwrap_err();
        assert!(err.to_string().contains("not the recipient"), "got: {err}");
        assert_eq!(state.total_locked, 42);
    }

    #[test]
    fn reject_already_terminal_rejected() {
        let mut state = CrossZoneState::new();
        lock_with_proof(&mut state, "tx-rj-claimed", "alice", "bob", 7);
        state.claim_transfer("tx-rj-claimed", "bob", "claim-rec", 1.0).unwrap();
        // Claimed transfers cannot be rejected.
        let err = state.reject_transfer("tx-rj-claimed", "bob").unwrap_err();
        assert!(err.to_string().contains("cannot reject"), "got: {err}");

        // Refunded transfers cannot be rejected either.
        let leaf = sha3_256(b"tx-rj-refunded");
        state.lock_transfer(
            "tx-rj-refunded".into(), "alice".into(), "bob".into(),
            8, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 100.0);
        assert_eq!(refunds.len(), 1);
        let err = state.reject_transfer("tx-rj-refunded", "bob").unwrap_err();
        assert!(err.to_string().contains("cannot reject"), "got: {err}");
    }

    #[test]
    fn reject_unknown_transfer_rejected() {
        let mut state = CrossZoneState::new();
        let err = state.reject_transfer("missing", "bob").unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    // ─── Gap 2 sealed-abort ──────────────────────────────────────────────

    /// Promote a sealed transfer into the "finalized in zone A" state so
    /// `abort_transfer`'s gate (`merkle_proof != [] && source_seal_epoch > 0`)
    /// is satisfied. Lock with inclusion proof then attach a 1-of-1 finality
    /// witness signed for the requested `epoch` (so a subsequent `claim_transfer`
    /// — used by `abort_already_terminal_rejected` to flip status to Claimed —
    /// passes the Phase 5 quorum check). Production sets the epoch via
    /// `set_finality_witnesses` from the AWC snapshot.
    fn seal_and_finalize(state: &mut CrossZoneState, id: &str, sender: &str, recipient: &str, amount: u64, epoch: u64) {
        // lock_with_inclusion_proof leaves committee_size=0 so we control
        // the finality attach ourselves at the requested epoch.
        let (leaf, proof, root) = make_test_proof(id.as_bytes());
        state.lock_transfer(
            id.into(), sender.into(), recipient.into(),
            amount, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        state.set_proof(id, proof, root).unwrap();

        let w = make_witness();
        let zone = ZoneId::new("a");
        let pks = vec![w.public_key.clone()];
        let (committee_hash, c_proofs) = build_committee(&pks);
        let sig = sign_finality(&w, &zone, epoch, &root, &committee_hash, c_proofs[0].clone());
        state.set_finality_witnesses(id, vec![sig], committee_hash, epoch, 1).unwrap();
    }

    #[test]
    fn abort_sealed_transfer_refunds_sender() {
        let mut state = CrossZoneState::new();
        seal_and_finalize(&mut state, "tx-abort", "alice", "bob", 750_000, 42);
        assert_eq!(state.total_locked, 750_000);

        let (tid, sender, amount) = state.abort_transfer("tx-abort").unwrap();
        assert_eq!(tid, "tx-abort");
        assert_eq!(sender, "alice");
        assert_eq!(amount, 750_000);
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-abort").unwrap().status,
            TransferStatus::Aborted
        );
    }

    #[test]
    fn abort_unsealed_transfer_rejected() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-unsealed");
        state.lock_transfer(
            "tx-unsealed".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
        ).unwrap();
        // No set_proof → unsealed → abort path must refuse.
        let err = state.abort_transfer("tx-unsealed").unwrap_err();
        assert!(
            err.to_string().contains("not sealed yet"),
            "expected 'not sealed yet' error, got: {err}"
        );
        assert_eq!(state.total_locked, 100);
    }

    #[test]
    fn abort_sealed_but_not_finalized_rejected() {
        let mut state = CrossZoneState::new();
        // set_proof ran (merkle_proof non-empty) but source_seal_epoch is still 0
        // (no set_finality_witnesses call) — abort proof has no epoch to sign against.
        // Use lock_with_inclusion_proof so finality stays unset (post-Phase-5
        // lock_with_proof attaches a 1-of-1 finality witness).
        lock_with_inclusion_proof(&mut state, "tx-half", "alice", "bob", 999);
        let err = state.abort_transfer("tx-half").unwrap_err();
        assert!(
            err.to_string().contains("not sealed yet"),
            "expected 'not sealed yet' error, got: {err}"
        );
        assert_eq!(state.total_locked, 999);
    }

    #[test]
    fn abort_already_terminal_rejected() {
        let mut state = CrossZoneState::new();
        // Aborted-then-aborted-again
        seal_and_finalize(&mut state, "tx-2x", "alice", "bob", 50, 11);
        state.abort_transfer("tx-2x").unwrap();
        let err = state.abort_transfer("tx-2x").unwrap_err();
        assert!(err.to_string().contains("cannot abort"), "got: {err}");

        // Claimed-then-aborted
        seal_and_finalize(&mut state, "tx-claimed", "alice", "bob", 60, 12);
        state.claim_transfer("tx-claimed", "bob", "claim-r", 1.0).unwrap();
        let err = state.abort_transfer("tx-claimed").unwrap_err();
        assert!(err.to_string().contains("cannot abort"), "got: {err}");
    }

    #[test]
    fn abort_unknown_transfer_rejected() {
        let mut state = CrossZoneState::new();
        let err = state.abort_transfer("missing").unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[test]
    fn xzone_abort_signable_bytes_domain_separated() {
        // Same arguments under two different domains must produce different
        // bytes — i.e. an XZoneFinality sig can never replay as an Abort sig.
        let zone = ZoneId::new("finance/eu");
        let cthash = [9u8; 32];
        let abort_msg = xzone_abort_signable_bytes("tx-1", &zone, 100, &cthash);
        let finality_msg = xzone_finality_signable_bytes(&zone, 100, &cthash, &cthash);
        assert_ne!(abort_msg, finality_msg);
        // Domain prefix is the only invariant we need to assert.
        assert!(abort_msg.starts_with(XZONE_ABORT_DOMAIN));
        assert!(finality_msg.starts_with(XZONE_FINALITY_DOMAIN));
    }

    #[test]
    fn verify_abort_quorum_rejects_zero_committee() {
        let zone = ZoneId::new("b");
        let cthash = [0u8; 32];
        let err = verify_abort_quorum("tx-z", &zone, 1, &cthash, 0, &[], Some((cthash, 0))).unwrap_err();
        assert!(err.to_string().contains("dest_committee_size must be > 0"), "got: {err}");
    }

    #[test]
    fn verify_abort_quorum_rejects_below_threshold() {
        // committee_size=3, supply 1 verified signer — needs ≥2.
        let signer = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let other1 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let other2 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let pks = vec![
            signer.public_key.clone(),
            other1.public_key.clone(),
            other2.public_key.clone(),
        ];
        let (root, proofs) = build_committee_proofs(&pks);
        let zone = ZoneId::new("b");
        let epoch = 7u64;
        let msg = xzone_abort_signable_bytes("tx-q", &zone, epoch, &root);
        let sig = signer.sign(&msg).unwrap();
        let proof = proofs.get(&signer.public_key).cloned().unwrap();
        let signers = vec![SealFinalityWitness {
            witness_pk: signer.public_key.clone(),
            signature: sig,
            committee_proof: proof,
        }];
        let err = verify_abort_quorum("tx-q", &zone, epoch, &root, 3, &signers, Some((root, 3))).unwrap_err();
        assert!(err.to_string().contains("verified signers"), "got: {err}");
    }

    #[test]
    fn verify_abort_quorum_accepts_at_threshold() {
        // committee_size=3, 2 verified sigs = exactly 2/3 → accepted.
        let s1 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let s2 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let s3 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let pks = vec![s1.public_key.clone(), s2.public_key.clone(), s3.public_key.clone()];
        let (root, proofs) = build_committee_proofs(&pks);
        let zone = ZoneId::new("b");
        let epoch = 9u64;
        let msg = xzone_abort_signable_bytes("tx-ok", &zone, epoch, &root);
        let mk = |s: &crate::identity::Identity| SealFinalityWitness {
            witness_pk: s.public_key.clone(),
            signature: s.sign(&msg).unwrap(),
            committee_proof: proofs.get(&s.public_key).cloned().unwrap(),
        };
        let signers = vec![mk(&s1), mk(&s2)];
        verify_abort_quorum("tx-ok", &zone, epoch, &root, 3, &signers, Some((root, 3))).unwrap();
    }

    #[test]
    fn verify_abort_quorum_rejects_finality_sig_replay() {
        // Sig produced over xzone_finality_signable_bytes must NOT verify as an
        // abort sig — the domain tag is what guarantees this.
        let s1 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let s2 = crate::identity::Identity::generate(crate::identity::EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let pks = vec![s1.public_key.clone(), s2.public_key.clone()];
        let (root, proofs) = build_committee_proofs(&pks);
        let zone = ZoneId::new("b");
        let epoch = 5u64;
        // Sign the FINALITY message instead of the abort message.
        let finality_msg = xzone_finality_signable_bytes(&zone, epoch, &root, &root);
        let sig1 = s1.sign(&finality_msg).unwrap();
        let sig2 = s2.sign(&finality_msg).unwrap();
        let bad_signers = vec![
            SealFinalityWitness {
                witness_pk: s1.public_key.clone(),
                signature: sig1,
                committee_proof: proofs.get(&s1.public_key).cloned().unwrap(),
            },
            SealFinalityWitness {
                witness_pk: s2.public_key.clone(),
                signature: sig2,
                committee_proof: proofs.get(&s2.public_key).cloned().unwrap(),
            },
        ];
        // Quorum size = 2, two signers — would pass on count, but sigs are
        // over the wrong domain so each Identity::verify returns false → 0 verified.
        let err = verify_abort_quorum("tx-replay", &zone, epoch, &root, 2, &bad_signers, Some((root, 2))).unwrap_err();
        assert!(err.to_string().contains("verified signers"), "got: {err}");
    }

    // ─── B2 fix: seal-anchored committee gate (internal design notes) ──

    fn b2_gen() -> crate::identity::Identity {
        crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap()
    }

    #[test]
    fn b2_verify_abort_quorum_rejects_forged_committee_vs_seal_anchor() {
        // The forgery B2 closes: an attacker submits an abort whose committee is
        // a 1-member tree of their OWN key, with a valid self-signed witness +
        // inclusion proof (internally consistent). The seal-frozen anchor is the
        // REAL dest committee. wire hash != anchor → rejected. A forged abort can
        // no longer force-refund a sealed transfer.
        let zone = ZoneId::new("b");
        let epoch = 11u64;
        let (g1, g2, g3) = (b2_gen(), b2_gen(), b2_gen());
        let real_pks = vec![g1.public_key.clone(), g2.public_key.clone(), g3.public_key.clone()];
        let (real_root, _r) = build_committee_proofs(&real_pks);
        let attacker = b2_gen();
        let forged_pks = vec![attacker.public_key.clone()];
        let (forged_root, forged_proofs) = build_committee_proofs(&forged_pks);
        let forged_msg = xzone_abort_signable_bytes("tx-forge", &zone, epoch, &forged_root);
        let forged_witness = SealFinalityWitness {
            witness_pk: attacker.public_key.clone(),
            signature: attacker.sign(&forged_msg).unwrap(),
            committee_proof: forged_proofs.get(&attacker.public_key).cloned().unwrap(),
        };
        // anchor = REAL committee (root, size 3); wire = forged (root, size 1).
        let err = verify_abort_quorum(
            "tx-forge", &zone, epoch, &forged_root, 1, &[forged_witness],
            Some((real_root, 3)),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the seal-anchored canonical committee"),
            "got: {err}"
        );
    }

    #[test]
    fn b2_verify_abort_quorum_fail_closed_without_seal_anchor() {
        // A legacy/pre-fix lock has no frozen committee anchor (None). Even a
        // perfectly valid 2/3 quorum MUST be rejected — an unanchored abort is
        // unenforceable and must not refund a sealed transfer (fail-closed).
        let zone = ZoneId::new("b");
        let epoch = 12u64;
        let s1 = b2_gen();
        let s2 = b2_gen();
        let s3 = b2_gen();
        let pks = vec![s1.public_key.clone(), s2.public_key.clone(), s3.public_key.clone()];
        let (root, proofs) = build_committee_proofs(&pks);
        let msg = xzone_abort_signable_bytes("tx-none", &zone, epoch, &root);
        let mk = |s: &crate::identity::Identity| SealFinalityWitness {
            witness_pk: s.public_key.clone(),
            signature: s.sign(&msg).unwrap(),
            committee_proof: proofs.get(&s.public_key).cloned().unwrap(),
        };
        let signers = vec![mk(&s1), mk(&s2)];
        let err = verify_abort_quorum("tx-none", &zone, epoch, &root, 3, &signers, None).unwrap_err();
        assert!(err.to_string().contains("no sealed dest-committee anchor"), "got: {err}");
    }

    #[test]
    fn b2_verify_abort_quorum_rejects_committee_size_downgrade() {
        // Sub-quorum forgery via size: attacker uses the REAL committee root but
        // claims size=1 to collapse the 2/3 threshold (one colluding member).
        // The anchored size (3) is authoritative → wire size 1 != 3 → rejected.
        let zone = ZoneId::new("b");
        let epoch = 13u64;
        let s1 = b2_gen();
        let s2 = b2_gen();
        let s3 = b2_gen();
        let pks = vec![s1.public_key.clone(), s2.public_key.clone(), s3.public_key.clone()];
        let (root, proofs) = build_committee_proofs(&pks);
        let msg = xzone_abort_signable_bytes("tx-dg", &zone, epoch, &root);
        let one = SealFinalityWitness {
            witness_pk: s1.public_key.clone(),
            signature: s1.sign(&msg).unwrap(),
            committee_proof: proofs.get(&s1.public_key).cloned().unwrap(),
        };
        let err = verify_abort_quorum("tx-dg", &zone, epoch, &root, 1, &[one], Some((root, 3))).unwrap_err();
        assert!(
            err.to_string().contains("dest_committee_size does not match"),
            "got: {err}"
        );
    }

    // ─── Gap 2 abort-path adversarial timing ──
    //
    // The happy-path and terminal-rejection tests above prove that
    // each individual gate (status==Locked, sealed, finalized, sender/recipient
    // identity) refuses the wrong call. These additional tests pin the
    // *cross-path* race orderings that show up when CLAIM, ABORT, and
    // process_expired() arrive in adversarial sequences against the same
    // transfer. The conservation invariant `total_locked` must end at the
    // arithmetic right answer regardless of order; whichever path "wins"
    // the race, the others must no-op cleanly.

    #[test]
    fn claim_after_abort_rejected_audit_2026_05_02() {
        // Race: ABORT proof landed first (status flipped Locked → Aborted),
        // then a stale CLAIM record arrives (perhaps gossiped from a node
        // that never observed the abort quorum). The claim path must reject
        // the late CLAIM — otherwise the recipient gets credited AFTER the
        // sender has already been refunded, double-counting the supply.
        let mut state = CrossZoneState::new();
        seal_and_finalize(&mut state, "tx-race", "alice", "bob", 100, 7);
        assert_eq!(state.total_locked, 100);

        // Abort lands first.
        let (tid, sender, amount) = state.abort_transfer("tx-race").unwrap();
        assert_eq!(tid, "tx-race");
        assert_eq!(sender, "alice");
        assert_eq!(amount, 100);
        assert_eq!(state.total_locked, 0, "abort decremented total_locked");
        assert_eq!(
            state.pending.get("tx-race").unwrap().status,
            TransferStatus::Aborted
        );

        // Stale CLAIM arrives. Must be rejected on status check, not on
        // proof/finality (those are still valid — the abort doesn't
        // invalidate the seal). The "is Aborted, not Locked" message is
        // the canonical signal an aggregator can trace.
        let err = state
            .claim_transfer("tx-race", "bob", "claim-late", 100.0)
            .unwrap_err();
        assert!(
            err.to_string().contains("not Locked"),
            "stale CLAIM after ABORT must be refused, got: {err}"
        );
        // total_locked must still be 0 — the rejected claim didn’t move beats.
        assert_eq!(state.total_locked, 0, "rejected claim must not touch total_locked");
        assert_eq!(
            state.pending.get("tx-race").unwrap().status,
            TransferStatus::Aborted,
            "status stays Aborted after rejected claim"
        );
    }

    #[test]
    fn process_expired_after_abort_is_noop_audit_2026_05_02() {
        // Race: ABORT lands at second 5, CLAIM_TIMEOUT_SECS expires at
        // second 86_400, the operator's process_expired() sweeper runs.
        // The sweeper must NOT touch an Aborted transfer (it would
        // re-decrement `total_locked` and corrupt accounting).
        let mut state = CrossZoneState::new();
        seal_and_finalize(&mut state, "tx-sweep", "alice", "bob", 250, 11);
        assert_eq!(state.total_locked, 250);

        state.abort_transfer("tx-sweep").unwrap();
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-sweep").unwrap().status,
            TransferStatus::Aborted
        );

        // Run the passive sweeper well past expiry — sealed transfers were
        // already excluded by `process_expired_skips_sealed_transfers_*`,
        // and Aborted transfers are status-filtered too. Refunds list MUST
        // be empty.
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 1.0);
        assert!(
            refunds.is_empty(),
            "process_expired must not double-refund an Aborted transfer, got: {refunds:?}"
        );
        // Conservation: total_locked still 0, no new debit.
        assert_eq!(state.total_locked, 0);
        // The stuck-sealed gauge does not pick up Aborted entries.
        assert_eq!(
            state.sealed_locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 1.0),
            0,
            "Aborted transfer is terminal and must drop off the stuck gauge"
        );
    }

    /// C10c: the sister emit-watermark `last_xzone_refund_emit_epoch` needs NO
    /// boot seed (unlike `last_idle_decay_emit_epoch`) precisely because
    /// `apply_refund_batch` is idempotent on re-delivery — the `Locked→Refunded`
    /// one-way flip makes a post-restart re-emit of an already-applied batch an
    /// unconditional no-op. This pins that load-bearing claim directly (no prior
    /// test called `apply_refund_batch` twice). `apply_reap_batch` is structurally
    /// identical (same flip, `cross_zone.rs:915`).
    #[test]
    fn apply_refund_batch_is_idempotent_on_redelivery_c10c() {
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-r");
        state
            .lock_transfer(
                "tx-r".into(), "alice".into(), "bob".into(), 100,
                ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf,
            )
            .unwrap();
        assert_eq!(state.total_locked, 100);

        let batch = XZoneRefundBatch {
            epoch: 7,
            zone: "a".into(),
            refunds: vec![("tx-r".into(), "alice".into(), 100)],
        };

        // First apply: refunds alice, flips Locked→Refunded.
        let applied1 = state.apply_refund_batch(&batch);
        assert_eq!(applied1, vec![("alice".to_string(), 100)]);
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-r").unwrap().status,
            TransferStatus::Refunded
        );

        // Re-delivery (the post-restart re-emit the unseeded watermark allows):
        // every entry is already Refunded → empty applied set, no second debit.
        let applied2 = state.apply_refund_batch(&batch);
        assert!(applied2.is_empty(), "re-emit must be a no-op, got {applied2:?}");
        assert_eq!(state.total_locked, 0, "no second decrement on re-emit");
    }

    #[test]
    fn abort_after_passive_refund_rejected_audit_2026_05_02() {
        // Boundary: an unsealed transfer expires and gets passively
        // refunded. Then a stale ABORT proof arrives (perhaps the source
        // committee signed an abort attestation against a transfer that,
        // from this node's view, was already refunded via the unsealed
        // timeout path). abort_transfer must refuse — status is Refunded,
        // not Locked, and refunding again would double-credit the sender.
        let mut state = CrossZoneState::new();
        let leaf = sha3_256(b"tx-stale-abort");
        state
            .lock_transfer(
                "tx-stale-abort".into(),
                "alice".into(),
                "bob".into(),
                42,
                ZoneId::new("a"),
                ZoneId::new("b"),
                0.0,
                leaf,
            )
            .unwrap();
        assert_eq!(state.total_locked, 42);

        // Passive timeout fires (unsealed → eligible for refund).
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 1.0);
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].0, "tx-stale-abort");
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-stale-abort").unwrap().status,
            TransferStatus::Refunded
        );

        // Stale ABORT arrives. abort_transfer's status guard refuses; even
        // before that, the merkle_proof.is_empty() guard would refuse since
        // this transfer was never sealed. Both gates must hold. Pin the
        // first one (status) — the abort path is the canonical refund and
        // must never run twice on the same transfer regardless of why.
        let err = state.abort_transfer("tx-stale-abort").unwrap_err();
        assert!(
            err.to_string().contains("cannot abort") || err.to_string().contains("not sealed"),
            "stale abort must refuse on terminal status or unsealed gate, got: {err}"
        );
        assert_eq!(state.total_locked, 0, "stale abort must not double-decrement");
    }

    #[test]
    fn conservation_holds_under_mixed_abort_claim_expire_audit_2026_05_02() {
        // Property: total_locked is exactly the sum of (Locked) transfer
        // amounts after any sequence of lock/claim/abort/process_expired
        // operations. The four terminal states (Claimed, Aborted, Refunded,
        // and the Locked-but-past-expiry sealed-stuck case) each subtract
        // exactly once from total_locked at transition time and never again.
        //
        // Sequence under test: 5 transfers, each follows a different
        // terminal path. Final total_locked must equal the one stuck
        // sealed-but-unaborted transfer's amount.
        let mut state = CrossZoneState::new();

        // (1) tx-claim — sealed + finalized + claimed
        seal_and_finalize(&mut state, "tx-claim", "alice", "bob", 100, 1);
        // (2) tx-abort — sealed + finalized + aborted
        seal_and_finalize(&mut state, "tx-abort", "alice", "bob", 200, 2);
        // (3) tx-refund — unsealed + passively refunded
        let leaf3 = sha3_256(b"tx-refund");
        state
            .lock_transfer(
                "tx-refund".into(), "alice".into(), "bob".into(),
                300, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf3,
            )
            .unwrap();
        // (4) tx-cancel — unsealed + sender-cancelled
        let leaf4 = sha3_256(b"tx-cancel");
        state
            .lock_transfer(
                "tx-cancel".into(), "alice".into(), "bob".into(),
                400, ZoneId::new("a"), ZoneId::new("b"), 0.0, leaf4,
            )
            .unwrap();
        // (5) tx-stuck — sealed but no abort yet (the stuck-sealed case)
        seal_and_finalize(&mut state, "tx-stuck", "alice", "bob", 500, 5);

        // All 5 locks counted:
        assert_eq!(state.total_locked, 100 + 200 + 300 + 400 + 500);

        // Apply the five terminal transitions in mixed order:
        state.abort_transfer("tx-abort").unwrap();           // 200 → 0 locked
        state.cancel_transfer("tx-cancel", "alice").unwrap();// 400 → 0 locked
        state.claim_transfer("tx-claim", "bob", "rec-1", 1.0).unwrap(); // 100 → 0 locked
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 1.0);
        // The sweeper must refund tx-refund (unsealed, expired) and skip
        // tx-stuck (sealed, expired but not aborted) and the three terminal
        // transfers. Exactly one refund.
        assert_eq!(refunds.len(), 1, "only tx-refund eligible, got: {refunds:?}");
        assert_eq!(refunds[0].0, "tx-refund");

        // tx-stuck is the last transfer still consuming `total_locked`.
        assert_eq!(
            state.total_locked, 500,
            "exactly tx-stuck (500) remains; conservation invariant holds"
        );
        assert_eq!(
            state.sealed_locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 1.0),
            1,
            "OPS-56 gauge surfaces the one stuck sealed transfer"
        );

        // Now abort tx-stuck — total_locked must decrement to exactly 0.
        state.abort_transfer("tx-stuck").unwrap();
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.sealed_locked_past_expiry_count(CLAIM_TIMEOUT_SECS + 1.0),
            0,
            "no stuck transfers remain"
        );

        // Re-running the sweeper after every transfer is terminal must be
        // a no-op forever. Idempotency is the safety property for replay.
        for _ in 0..3 {
            let later = state.process_expired(CLAIM_TIMEOUT_SECS * 10.0);
            assert!(later.is_empty(), "idempotent sweep must be empty");
            assert_eq!(state.total_locked, 0);
        }
    }

    #[test]
    fn double_abort_at_same_instant_only_decrements_once_audit_2026_05_02() {
        // Concurrency: two valid abort proofs from the same dest committee
        // for the same transfer arrive in quick succession. The first call
        // flips status to Aborted and decrements total_locked. The second
        // must be a clean no-op — the status gate refuses, total_locked
        // stays put. Even if both calls were on the same epoch boundary
        // (committee re-broadcast, dual-witness gossip), only one
        // accounting effect lands.
        let mut state = CrossZoneState::new();
        seal_and_finalize(&mut state, "tx-twin-abort", "alice", "bob", 999, 3);
        assert_eq!(state.total_locked, 999);

        let first = state.abort_transfer("tx-twin-abort").unwrap();
        assert_eq!(first.2, 999);
        assert_eq!(state.total_locked, 0);

        let err = state.abort_transfer("tx-twin-abort").unwrap_err();
        assert!(
            err.to_string().contains("cannot abort"),
            "second abort must refuse on terminal status, got: {err}"
        );
        // No second decrement, no underflow (saturating_sub) — total_locked
        // stays at 0, matching the single-effect accounting contract.
        assert_eq!(state.total_locked, 0);
        assert_eq!(
            state.pending.get("tx-twin-abort").unwrap().status,
            TransferStatus::Aborted,
            "status stays Aborted after redundant call"
        );
    }

    // ─── XZoneAbortBundle (Gap 2 sealed-abort, Slice 3) ────────────────────

    fn build_signed_abort(
        transfer_id: &str,
        dest_zone: &ZoneId,
        epoch: u64,
        n_signers: usize,
    ) -> XZoneAbortBundle {
        let identities: Vec<crate::identity::Identity> = (0..n_signers)
            .map(|_| {
                crate::identity::Identity::generate(
                    crate::identity::EntityType::Device,
                    crate::identity::CryptoProfile::ProfileB,
                )
                .unwrap()
            })
            .collect();
        let pks: Vec<Vec<u8>> = identities.iter().map(|i| i.public_key.clone()).collect();
        let (root, proofs) = build_committee_proofs(&pks);
        let msg = xzone_abort_signable_bytes(transfer_id, dest_zone, epoch, &root);
        let signers = identities
            .iter()
            .map(|s| SealFinalityWitness {
                witness_pk: s.public_key.clone(),
                signature: s.sign(&msg).unwrap(),
                committee_proof: proofs.get(&s.public_key).cloned().unwrap(),
            })
            .collect();
        XZoneAbortBundle {
            transfer_id: transfer_id.into(),
            dest_zone: dest_zone.clone(),
            source_seal_epoch: epoch,
            dest_committee_hash: root,
            dest_committee_size: n_signers as u32,
            signers,
        }
    }

    #[test]
    fn xzone_abort_bundle_round_trips_json_and_verifies() {
        let zone = ZoneId::new("b");
        let bundle = build_signed_abort("tx-bundle-1", &zone, 12, 3);
        bundle.verify().expect("3-of-3 bundle verifies");

        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: XZoneAbortBundle = serde_json::from_str(&json).unwrap();
        decoded.verify().expect("decoded bundle verifies");
        assert_eq!(decoded.transfer_id, "tx-bundle-1");
        assert_eq!(decoded.dest_committee_size, 3);
        assert_eq!(decoded.signers.len(), 3);
    }

    #[test]
    fn xzone_abort_bundle_rejects_under_quorum() {
        // Construct a bundle where dest_committee_size says 5 but we only
        // collected 1 signature → fails 2/3 threshold.
        let zone = ZoneId::new("b");
        let mut bundle = build_signed_abort("tx-bundle-low", &zone, 7, 5);
        bundle.signers.truncate(1);
        let err = bundle.verify().unwrap_err();
        assert!(
            err.to_string().contains("quorum check failed"),
            "got: {err}"
        );
    }

    #[test]
    fn xzone_abort_bundle_rejects_tampered_transfer_id() {
        // Sigs were produced over "tx-real". If a relayer flips the
        // transfer_id field to "tx-other" without re-signing, the message
        // hash changes and Identity::verify rejects every sig.
        let zone = ZoneId::new("b");
        let mut bundle = build_signed_abort("tx-real", &zone, 4, 3);
        bundle.transfer_id = "tx-other".into();
        let err = bundle.verify().unwrap_err();
        assert!(
            err.to_string().contains("quorum check failed"),
            "got: {err}"
        );
    }

    // Gap 2.1 Phase 5a: counter coverage. The two counters are the
    // load-bearing signal we'll use to decide when Phase 5 (delete the
    // legacy bypass) is safe to ship. Tests below pin the bookkeeping so
    // a future refactor can't silently break the cutover criterion.

    #[test]
    fn xzone_claim_legacy_path_rejects_post_cutover() {
        // Phase 5 (2026-04-28): committee_size==0 must be rejected. Both
        // counters stay 0 because we only bump on accept, not on attempt.
        // This pins the cutover behavior so a future revert to the bypass
        // can't sneak in unnoticed.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized"), "got: {err}");
        assert_eq!(state.claim_finality_legacy_total, 0);
        assert_eq!(state.claim_finality_enforced_total, 0);
    }

    #[test]
    fn xzone_claim_enforced_path_bumps_enforced_counter() {
        // committee_size>0 with valid 2/3 quorum → claim succeeds via
        // finality-enforced path → enforced counter +1, legacy 0.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);
        let signers = vec![
            sign_finality(&ws[0], &zone, 7, &root, &committee_hash, proofs[0].clone()),
            sign_finality(&ws[1], &zone, 7, &root, &committee_hash, proofs[1].clone()),
        ];

        state.set_finality_witnesses("tx-1", signers, committee_hash, 7, 3).unwrap();
        let claimed = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap();
        assert_eq!(claimed.status, TransferStatus::Claimed);
        assert_eq!(state.claim_finality_enforced_total, 1);
        assert_eq!(state.claim_finality_legacy_total, 0);
    }

    #[test]
    fn xzone_claim_failed_quorum_bumps_neither_counter() {
        // committee_size>0 but quorum fails → claim rejected → both
        // counters stay 0. Confirms we only bump on accept, not on
        // attempt — otherwise the legacy gauge would race up under attack.
        let mut state = CrossZoneState::new();
        lock_with_inclusion_proof(&mut state, "tx-1", "alice", "bob", 100);

        let zone = ZoneId::new("a");
        let root = state.get("tx-1").unwrap().source_merkle_root;
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);
        // Only 1/3 — under quorum.
        let signers = vec![
            sign_finality(&ws[0], &zone, 7, &root, &committee_hash, proofs[0].clone()),
        ];

        state.set_finality_witnesses("tx-1", signers, committee_hash, 7, 3).unwrap();
        let err = state.claim_transfer("tx-1", "bob", "claim-1", 100.0).unwrap_err();
        assert!(err.to_string().contains("seal not finalized"), "got: {err}");
        assert_eq!(state.claim_finality_enforced_total, 0);
        assert_eq!(state.claim_finality_legacy_total, 0);
    }

    #[test]
    fn xzone_oldest_locked_age_zero_when_idle() {
        // No transfers at all — gauge reads 0 (healthy idle).
        let state = CrossZoneState::new();
        assert_eq!(state.oldest_locked_age_secs(1000.0), 0);
    }

    #[test]
    fn xzone_oldest_locked_age_returns_max_across_locked() {
        // Three Locked transfers at t=100, 500, 800; now=1000 → oldest is
        // the t=100 one with age 900s.
        let mut state = CrossZoneState::new();
        for (id, t) in [("a", 100.0), ("b", 500.0), ("c", 800.0)] {
            state.lock_transfer(
                id.into(), "alice".into(), "bob".into(),
                10, ZoneId::new("a"), ZoneId::new("b"), t, [0u8; 32],
            ).unwrap();
        }
        assert_eq!(state.oldest_locked_age_secs(1000.0), 900);
    }

    #[test]
    fn xzone_oldest_locked_age_skips_terminal_transfers() {
        // Mix of Locked + Claimed: gauge reflects the oldest *Locked*, not
        // the oldest entry in the map. A claim that landed an hour ago
        // shouldn't pin the gauge — we only care about in-flight risk.
        let mut state = CrossZoneState::new();
        // `lock_with_proof` attaches finality (Phase 5), so claim succeeds.
        lock_with_proof(&mut state, "tx-claimed", "alice", "bob", 10);
        // Claim it — flips status to Claimed.
        state.claim_transfer("tx-claimed", "bob", "claim-1", 100.0).unwrap();

        // Add a still-Locked transfer at t=500.
        state.lock_transfer(
            "tx-still-locked".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("a"), ZoneId::new("b"), 500.0, [0u8; 32],
        ).unwrap();
        // now=1000, only the locked one counts → 500s, not 1000s.
        assert_eq!(state.oldest_locked_age_secs(1000.0), 500);
    }

    #[test]
    fn xzone_oldest_locked_age_clamps_negative_to_zero() {
        // Pathological clock skew: locked_at is in the future (e.g., a peer
        // gossiped a record with a clock ahead of ours). Don't panic / wrap;
        // just report 0 so the gauge stays sensible.
        let mut state = CrossZoneState::new();
        state.lock_transfer(
            "tx-future".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("a"), ZoneId::new("b"), 9999.0, [0u8; 32],
        ).unwrap();
        assert_eq!(state.oldest_locked_age_secs(1000.0), 0);
    }

    #[test]
    fn xzone_claim_counters_are_cumulative_across_transfers() {
        // Phase 5 post-cutover: only the enforced path can succeed. Two
        // claims with full quorum, one with under-quorum signers (rejected),
        // one with no finality witnesses at all (rejected). Replay-deterministic:
        // each apply_op of the same Claim record reaches the same branch on
        // every node, so counter values converge fleet-wide.
        let mut state = CrossZoneState::new();
        let zone = ZoneId::new("a");
        let ws: Vec<Identity> = (0..3).map(|_| make_witness()).collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, proofs) = build_committee(&pks);

        // Two enforced claims — both succeed and bump enforced_total.
        for i in 0..2 {
            let id = format!("tx-enf-{i}");
            lock_with_inclusion_proof(&mut state, &id, "alice", "bob", 10);
            let root = state.get(&id).unwrap().source_merkle_root;
            let signers = vec![
                sign_finality(&ws[0], &zone, 9 + i as u64, &root, &committee_hash, proofs[0].clone()),
                sign_finality(&ws[1], &zone, 9 + i as u64, &root, &committee_hash, proofs[1].clone()),
            ];
            state.set_finality_witnesses(&id, signers, committee_hash, 9 + i as u64, 3).unwrap();
            state.claim_transfer(&id, "bob", &format!("claim-enf-{i}"), 100.0).unwrap();
        }

        // One under-quorum claim — rejected, neither counter moves.
        lock_with_inclusion_proof(&mut state, "tx-under", "alice", "bob", 10);
        let root_u = state.get("tx-under").unwrap().source_merkle_root;
        let under_signers = vec![
            sign_finality(&ws[0], &zone, 11, &root_u, &committee_hash, proofs[0].clone()),
        ];
        state.set_finality_witnesses("tx-under", under_signers, committee_hash, 11, 3).unwrap();
        assert!(state.claim_transfer("tx-under", "bob", "claim-under", 100.0).is_err());

        // One legacy/no-finality claim — rejected (Phase 5 cutover), neither
        // counter moves. Confirms the bypass is truly gone.
        lock_with_inclusion_proof(&mut state, "tx-leg", "alice", "bob", 10);
        assert!(state.claim_transfer("tx-leg", "bob", "claim-leg", 100.0).is_err());

        assert_eq!(state.claim_finality_enforced_total, 2);
        assert_eq!(state.claim_finality_legacy_total, 0);
    }

    #[test]
    fn xzone_locked_past_expiry_zero_when_idle() {
        // No transfers anywhere → 0 (healthy idle).
        let state = CrossZoneState::new();
        assert_eq!(state.locked_past_expiry_count(1_000_000.0), 0);
    }

    #[test]
    fn xzone_locked_past_expiry_zero_when_all_inside_window() {
        // Three Locked transfers at locked_at=100; now=500. expires_at is
        // locked_at + 86400 = 86500, well past now. None counted.
        let mut state = CrossZoneState::new();
        for id in ["a", "b", "c"] {
            state.lock_transfer(
                id.into(), "alice".into(), "bob".into(),
                10, ZoneId::new("za"), ZoneId::new("zb"), 100.0, [0u8; 32],
            ).unwrap();
        }
        assert_eq!(state.locked_past_expiry_count(500.0), 0);
        assert_eq!(state.locked_count(), 3, "still 3 active locks, just not expired");
    }

    #[test]
    fn xzone_locked_past_expiry_counts_only_past_deadline() {
        // Two locks at t=100 (expire at 86500), one at t=200000 (expires at
        // 286400). At now=200000 the first two are past expiry; the third is
        // still inside its window → exactly 2.
        let mut state = CrossZoneState::new();
        state.lock_transfer(
            "early-1".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("za"), ZoneId::new("zb"), 100.0, [0u8; 32],
        ).unwrap();
        state.lock_transfer(
            "early-2".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("za"), ZoneId::new("zb"), 100.0, [0u8; 32],
        ).unwrap();
        state.lock_transfer(
            "late".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("za"), ZoneId::new("zb"), 200_000.0, [0u8; 32],
        ).unwrap();
        assert_eq!(state.locked_past_expiry_count(200_000.0), 2);
    }

    #[test]
    fn xzone_locked_past_expiry_skips_terminal_states() {
        // Two locks past expiry: one Refunded by process_expired, one still
        // Locked. Gauge counts only the Locked one (the one still stuck).
        let mut state = CrossZoneState::new();
        state.lock_transfer(
            "tx-swept".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("za"), ZoneId::new("zb"), 100.0, [0u8; 32],
        ).unwrap();
        state.lock_transfer(
            "tx-stuck".into(), "alice".into(), "bob".into(),
            10, ZoneId::new("za"), ZoneId::new("zb"), 100.0, [0u8; 32],
        ).unwrap();
        // Sweep half via process_expired (mirrors anchor's epoch-tick path).
        let now = CLAIM_TIMEOUT_SECS + 200.0;
        // Manually set first one's status to Refunded — leaves second still
        // Locked. Faster than wiring a partial-process_expired path.
        if let Some(t) = state.pending.get_mut("tx-swept") {
            t.status = TransferStatus::Refunded;
        }
        assert_eq!(state.locked_past_expiry_count(now), 1, "only tx-stuck counted");
    }

    // ── incremental per-status pending counters ──────────────

    /// Every status transition through the public API must
    /// keep the four per-status counters consistent with the live
    /// `pending` map's status distribution. Without this invariant, the
    /// `/xzone/stats` endpoint returns stale counts.
    ///
    /// Walks one transfer through Locked → Claimed (one happy path)
    /// and one through Locked → Aborted (one terminal-failure path),
    /// asserting counters at every step. The full-coverage random-walk
    /// test below pins the invariant under arbitrary mutation
    /// sequences.
    #[test]
    fn ops152_status_counters_match_pending_after_lifecycle() {
        let mut state = CrossZoneState::new();
        assert_eq!(state.locked_count, 0);
        assert_eq!(state.claimed_count, 0);
        assert_eq!(state.refunded_count, 0);
        assert_eq!(state.aborted_count, 0);

        // Lock 3 transfers. locked=3, others=0.
        for i in 0..3 {
            let id = format!("tx-{i}");
            lock_with_proof(&mut state, &id, "alice", "bob", 100);
        }
        assert_eq!(state.locked_count, 3);
        assert_eq!(state.claimed_count, 0);
        assert_eq!(state.aborted_count, 0);
        assert_eq!(state.refunded_count, 0);
        assert_eq!(
            state.locked_count
                + state.claimed_count
                + state.refunded_count
                + state.aborted_count,
            state.pending.len() as u64,
            "invariant: counters sum to pending.len()"
        );

        // Claim tx-0 → Locked: 2, Claimed: 1.
        state.claim_transfer("tx-0", "bob", "tx-0-claim", 100.0).unwrap();
        assert_eq!(state.locked_count, 2);
        assert_eq!(state.claimed_count, 1);

        // Abort tx-1 (sealed terminal-failure path) → Locked: 1, Aborted: 1.
        state.abort_transfer("tx-1").unwrap();
        assert_eq!(state.locked_count, 1);
        assert_eq!(state.aborted_count, 1);

        // tx-2 still Locked.
        assert_eq!(state.locked_count, 1);
        assert_eq!(state.pending.len(), 3);
        assert_eq!(
            state.locked_count
                + state.claimed_count
                + state.refunded_count
                + state.aborted_count,
            state.pending.len() as u64,
            "invariant must hold after mixed lifecycle ops"
        );

        // Recount must match the maintained counters byte-for-byte.
        let (l, c, r, a) = (
            state.locked_count,
            state.claimed_count,
            state.refunded_count,
            state.aborted_count,
        );
        state.recount_status();
        assert_eq!(state.locked_count, l, "recount must agree with maintained locked");
        assert_eq!(state.claimed_count, c);
        assert_eq!(state.refunded_count, r);
        assert_eq!(state.aborted_count, a);
    }

    /// Under a long sequence of arbitrary public-API
    /// mutations (lock + claim + abort + cancel + reject + expire +
    /// prune), the maintained counters must equal `recount_status`
    /// every single step. If any mutation site forgets to update its
    /// counter, this test diverges immediately.
    #[test]
    fn ops152_status_counters_invariant_under_random_ops() {
        let mut state = CrossZoneState::new();

        // Lock a fixed set, then exercise every terminal path.
        for i in 0..10 {
            let id = format!("tx-{i:02}");
            lock_with_proof(&mut state, &id, "alice", "bob", 100);
        }

        let assert_invariant = |s: &mut CrossZoneState, label: &str| {
            let (l, c, r, a) = (
                s.locked_count,
                s.claimed_count,
                s.refunded_count,
                s.aborted_count,
            );
            assert_eq!(
                l + c + r + a,
                s.pending.len() as u64,
                "[{label}] counters sum != pending.len()"
            );
            // Recount and compare. Counter maintenance and recount must agree.
            let mut shadow = s.clone();
            shadow.recount_status();
            assert_eq!(shadow.locked_count, l, "[{label}] recount disagrees on locked");
            assert_eq!(shadow.claimed_count, c, "[{label}] recount disagrees on claimed");
            assert_eq!(shadow.refunded_count, r, "[{label}] recount disagrees on refunded");
            assert_eq!(shadow.aborted_count, a, "[{label}] recount disagrees on aborted");
        };
        assert_invariant(&mut state, "after 10 locks");

        // Claim some.
        state.claim_transfer("tx-00", "bob", "claim-00", 100.0).unwrap();
        state.claim_transfer("tx-01", "bob", "claim-01", 100.0).unwrap();
        assert_invariant(&mut state, "after 2 claims");

        // Abort some (sealed terminal-failure path).
        state.abort_transfer("tx-02").unwrap();
        state.abort_transfer("tx-03").unwrap();
        assert_invariant(&mut state, "after 2 aborts");

        // Lock more, then cancel some via the unsealed-cancel path.
        // cancel_transfer rejects sealed transfers, so use the bare
        // `lock_transfer` (no set_proof) to keep them unsealed.
        for i in 10..13 {
            let id = format!("tx-{i:02}");
            state.lock_transfer(
                id, "alice".into(), "bob".into(),
                50, ZoneId::new("a"), ZoneId::new("b"), 0.0, [0u8; 32],
            ).unwrap();
        }
        assert_invariant(&mut state, "after 3 unsealed locks");

        state.cancel_transfer("tx-10", "alice").unwrap();
        state.reject_transfer("tx-11", "bob").unwrap();
        assert_invariant(&mut state, "after cancel+reject");

        // Expire the remaining unsealed lock past CLAIM_TIMEOUT_SECS.
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 100.0);
        assert_eq!(refunds.len(), 1, "tx-12 was the only remaining unsealed Locked");
        assert_invariant(&mut state, "after process_expired");

        // Prune terminal entries past cutoff. cutoff < locked_at means
        // *all* non-Locked entries get dropped (their locked_at=0.0 for
        // the unsealed batch and varied for the sealed batch).
        let dropped = state.prune_completed(f64::MAX);
        assert!(dropped > 0, "prune must drop the terminal entries");
        assert_invariant(&mut state, "after prune_completed");

        // Final state: only the un-touched tx-04..tx-09 remain Locked
        // (sealed path, never expired because process_expired skips sealed).
        assert_eq!(state.locked_count, 6, "tx-04..tx-09 still locked");
        assert_eq!(state.claimed_count, 0, "claimed entries pruned");
        assert_eq!(state.refunded_count, 0, "refunded entries pruned");
        assert_eq!(state.aborted_count, 0, "aborted entries pruned");
        assert_eq!(state.pending.len(), 6);
    }

    /// Boot-side migration. A ledger snapshot that predates these counters
    /// has `pending` populated but all four counters at 0
    /// (`serde(default)`). After `recount_status` runs once, counters
    /// must reflect the live state and the invariant must hold. This
    /// pins the migration shim wired in `bin/elara_node.rs`.
    #[test]
    fn ops152_recount_status_migrates_legacy_snapshot() {
        let mut state = CrossZoneState::new();
        // Simulate a legacy snapshot: pending is populated but
        // counters are all 0 (as serde(default) would produce).
        state.pending.insert(
            "tx-l".into(),
            PendingTransfer {
                transfer_id: "tx-l".into(), sender: "a".into(), recipient: "b".into(),
                amount: 10, source_zone: ZoneId::new("a"), dest_zone: ZoneId::new("b"),
                locked_at: 0.0, expires_at: 1.0, status: TransferStatus::Locked,
                merkle_proof: vec![], lock_record_hash: [0u8; 32],
                source_merkle_root: [0u8; 32], source_seal_signers: vec![],
                source_committee_hash: [0u8; 32], source_seal_epoch: 0,
                source_committee_size: 0, dest_finality_committee: None,
                claim_record_id: None,
            },
        );
        state.pending.insert(
            "tx-c".into(),
            PendingTransfer {
                status: TransferStatus::Claimed,
                ..state.pending.get("tx-l").unwrap().clone()
            },
        );
        state.pending.insert(
            "tx-r".into(),
            PendingTransfer {
                status: TransferStatus::Refunded,
                ..state.pending.get("tx-l").unwrap().clone()
            },
        );
        state.pending.insert(
            "tx-a".into(),
            PendingTransfer {
                status: TransferStatus::Aborted,
                ..state.pending.get("tx-l").unwrap().clone()
            },
        );

        // Counters all zero — invariant violated (legacy state).
        assert_eq!(state.locked_count, 0);
        assert_eq!(state.pending.len(), 4);

        // Migrate.
        state.recount_status();

        assert_eq!(state.locked_count, 1);
        assert_eq!(state.claimed_count, 1);
        assert_eq!(state.refunded_count, 1);
        assert_eq!(state.aborted_count, 1);
        assert_eq!(
            state.locked_count + state.claimed_count + state.refunded_count + state.aborted_count,
            state.pending.len() as u64
        );

        // Idempotent: a second recount returns the same numbers.
        state.recount_status();
        assert_eq!(state.locked_count, 1);
        assert_eq!(state.claimed_count, 1);
        assert_eq!(state.refunded_count, 1);
        assert_eq!(state.aborted_count, 1);
    }

    /// The needs-proof index must hold exactly the {Locked ∧ proofless}
    /// set through every public state transition — the per-seal attach
    /// scan trusts it for candidate discovery (O(seal_size) live path).
    #[test]
    fn needs_proof_index_tracks_full_lifecycle() {
        let mut state = CrossZoneState::new();
        let ids = ["tx-a", "tx-b", "tx-c", "tx-d"];
        let mut leaves = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let (leaf, _, _) = make_test_proof(id.as_bytes());
            // Zones "a"/"b": attach_test_finality signs for source zone "a".
            state.lock_transfer(
                (*id).into(), "alice".into(), "bob".into(),
                100, ZoneId::new("a"), ZoneId::new("b"), i as f64, leaf,
            ).unwrap();
            leaves.push(leaf);
        }
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(state.needs_proof_ids(&leaves[i]), &[(*id).to_string()]);
        }

        // set_proof drains tx-a (proof attached; claim later is index-inert).
        let (leaf_a, proof_a, root_a) = make_test_proof(b"tx-a");
        state.set_proof("tx-a", proof_a, root_a).unwrap();
        assert!(state.needs_proof_ids(&leaf_a).is_empty(), "set_proof must unindex");

        // Sender cancel drains tx-b; recipient reject drains tx-c.
        state.cancel_transfer("tx-b", "alice").unwrap();
        assert!(state.needs_proof_ids(&leaves[1]).is_empty(), "cancel must unindex");
        state.reject_transfer("tx-c", "bob").unwrap();
        assert!(state.needs_proof_ids(&leaves[2]).is_empty(), "reject must unindex");

        // Passive 24h expiry drains tx-d.
        let refunds = state.process_expired(CLAIM_TIMEOUT_SECS + 100.0);
        assert_eq!(refunds.len(), 1, "only tx-d was still Locked-unsealed");
        assert!(state.needs_proof_ids(&leaves[3]).is_empty(), "expiry must unindex");

        // Claim of the proofed transfer never touches the index.
        attach_test_finality(&mut state, "tx-a", &root_a);
        state.claim_transfer("tx-a", "bob", "claim-a", 100.0).unwrap();
        assert!(state.needs_proof_ids(&leaf_a).is_empty());

        // Distinct code path: the frozen-batch refund apply must unindex too.
        let mut s2 = CrossZoneState::new();
        let leaf_e = sha3_256(b"tx-e");
        s2.lock_transfer(
            "tx-e".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("za"), ZoneId::new("zb"), 0.0, leaf_e,
        ).unwrap();
        let batch = s2
            .compute_expired_refund_batch(CLAIM_TIMEOUT_SECS + 100.0, 7, "za")
            .expect("tx-e is expired-unsealed");
        let applied = s2.apply_refund_batch(&batch);
        assert_eq!(applied.len(), 1);
        assert!(s2.needs_proof_ids(&leaf_e).is_empty(), "apply_refund_batch must unindex");
    }

    /// `#[serde(skip)]` lands the index EMPTY on snapshot load;
    /// `recount_status` (wired at every load site) must rebuild exactly
    /// the {Locked ∧ proofless} set. Pins the load-path migration shim.
    #[test]
    fn needs_proof_index_rebuilt_by_recount_after_serde() {
        let mut state = CrossZoneState::new();
        let (leaf_p, proof, root) = make_test_proof(b"tx-proofed");
        state.lock_transfer(
            "tx-proofed".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("za"), ZoneId::new("zb"), 0.0, leaf_p,
        ).unwrap();
        state.set_proof("tx-proofed", proof, root).unwrap();
        let leaf_u = sha3_256(b"tx-unproofed");
        state.lock_transfer(
            "tx-unproofed".into(), "alice".into(), "bob".into(),
            100, ZoneId::new("za"), ZoneId::new("zb"), 0.0, leaf_u,
        ).unwrap();
        assert_eq!(state.needs_proof_ids(&leaf_u), &["tx-unproofed".to_string()]);

        let json = serde_json::to_string(&state).unwrap();
        let mut booted: CrossZoneState = serde_json::from_str(&json).unwrap();
        assert!(
            booted.needs_proof_ids(&leaf_u).is_empty(),
            "serde(skip) ⇒ index empty on load, until recount_status runs"
        );

        booted.recount_status();
        assert_eq!(booted.needs_proof_ids(&leaf_u), &["tx-unproofed".to_string()]);
        assert!(
            booted.needs_proof_ids(&leaf_p).is_empty(),
            "proofed transfer must stay out of the rebuilt index"
        );
    }

    // ─── fixture-free pure-helper coverage ──────────────

    #[test]
    fn batch_b_constants_pin_claim_timeout_op_key_and_domain_disjointness() {
        // PIN: cross_zone.rs:29 — CLAIM_TIMEOUT_SECS is the 24h passive-refund
        // window; a regression that changed the unit (e.g. ms vs s) or the
        // multiplier would silently delay or accelerate refund eligibility
        // across every in-flight xzone transfer. Pin the literal value.
        assert!(
            (CLAIM_TIMEOUT_SECS - 86_400.0).abs() < f64::EPSILON,
            "CLAIM_TIMEOUT_SECS MUST be 24h=86400s — got {}",
            CLAIM_TIMEOUT_SECS,
        );

        // PIN: cross_zone.rs:32 — XZONE_OP_KEY is the BTreeMap metadata key
        // that downstream consumers (lock detector, claim detector,
        // metadata-builders, audit log) match exactly. A spelling change
        // here would silently drop all xzone records from the pipeline.
        assert_eq!(XZONE_OP_KEY, "xzone_op", "XZONE_OP_KEY wire-key MUST be 'xzone_op'");

        // PIN: cross_zone.rs:42 + cross_zone.rs:56 — finality and abort domain
        // separators are the load-bearing replay-safety boundary. If they
        // accidentally collide (or one is renamed to match the other), an
        // attacker can replay a finality sig as an abort proof or vice-versa.
        assert_eq!(
            XZONE_FINALITY_DOMAIN, b"ELARA/XZONE_SEAL_FINALITY/v1",
            "finality domain literal MUST be pinned",
        );
        assert_eq!(
            XZONE_ABORT_DOMAIN, b"ELARA/XZONE_ABORT/v1",
            "abort domain literal MUST be pinned",
        );
        assert_ne!(
            XZONE_FINALITY_DOMAIN, XZONE_ABORT_DOMAIN,
            "finality and abort domain separators MUST be distinct (cross-domain replay barrier)",
        );
        // The domain prefixes must not be substrings of each other; a strict-
        // prefix relation would let length-extension across domains.
        assert!(
            !XZONE_FINALITY_DOMAIN.starts_with(XZONE_ABORT_DOMAIN),
            "FINALITY domain must not start with ABORT prefix",
        );
        assert!(
            !XZONE_ABORT_DOMAIN.starts_with(XZONE_FINALITY_DOMAIN),
            "ABORT domain must not start with FINALITY prefix",
        );
    }

    #[test]
    fn batch_b_xzone_finality_signable_bytes_pins_length_prefixed_canonical_layout() {
        // PIN: cross_zone.rs:874 — canonical signable bytes for the finality
        // attestation. Wire layout is:
        //   XZONE_FINALITY_DOMAIN
        //   | u32 BE zone_path length | zone path bytes
        //   | u64 BE seal_epoch
        //   | 32 bytes merkle_root
        //   | 32 bytes committee_hash
        // A regression that switches byte order, drops a length prefix, or
        // re-orders fields would invalidate every in-flight signature.
        let zone = ZoneId::new("east");
        let zone_bytes = zone.path();
        let zone_path_bytes = zone_bytes.as_bytes();
        let zone_len = zone_path_bytes.len();
        let mut merkle_root = [0u8; 32];
        for (i, b) in merkle_root.iter_mut().enumerate() { *b = i as u8; }
        let mut committee_hash = [0u8; 32];
        for (i, b) in committee_hash.iter_mut().enumerate() { *b = 0x80 | (i as u8); }
        let seal_epoch: u64 = 0x0102_0304_0506_0708;

        let out = xzone_finality_signable_bytes(&zone, seal_epoch, &merkle_root, &committee_hash);

        // Total length pin.
        let expected_len = XZONE_FINALITY_DOMAIN.len() + 4 + zone_len + 8 + 32 + 32;
        assert_eq!(out.len(), expected_len, "finality signable byte-length pin");

        // Domain prefix.
        assert_eq!(
            &out[..XZONE_FINALITY_DOMAIN.len()],
            XZONE_FINALITY_DOMAIN,
            "first {} bytes MUST be XZONE_FINALITY_DOMAIN",
            XZONE_FINALITY_DOMAIN.len(),
        );

        // u32 BE zone path length.
        let mut pos = XZONE_FINALITY_DOMAIN.len();
        assert_eq!(
            &out[pos..pos+4],
            &(zone_len as u32).to_be_bytes(),
            "zone_path length MUST be u32 BE",
        );
        pos += 4;

        // Zone path bytes.
        assert_eq!(&out[pos..pos+zone_len], zone_path_bytes, "zone path bytes pin");
        pos += zone_len;

        // u64 BE seal_epoch.
        assert_eq!(
            &out[pos..pos+8],
            &seal_epoch.to_be_bytes(),
            "seal_epoch MUST be u64 BE",
        );
        pos += 8;

        // 32 bytes merkle_root + 32 bytes committee_hash.
        assert_eq!(&out[pos..pos+32], &merkle_root, "merkle_root 32B pin");
        pos += 32;
        assert_eq!(&out[pos..pos+32], &committee_hash, "committee_hash 32B pin");

        // Determinism: two calls with same inputs MUST yield identical bytes.
        let out2 = xzone_finality_signable_bytes(&zone, seal_epoch, &merkle_root, &committee_hash);
        assert_eq!(out, out2, "finality signable bytes MUST be deterministic");
    }

    #[test]
    fn batch_b_xzone_abort_signable_bytes_pins_layout_distinct_from_finality_domain() {
        // PIN: cross_zone.rs:1204 — abort signable bytes. Layout is:
        //   XZONE_ABORT_DOMAIN
        //   | u32 BE transfer_id length | transfer_id bytes
        //   | u32 BE dest_zone path length | dest_zone path bytes
        //   | u64 BE source_seal_epoch
        //   | 32 bytes dest_committee_hash
        // Distinct from finality: NO merkle_root field, AND domain prefix
        // differs. Pin (a) byte-exact layout, (b) cross-domain disjointness
        // even when zone/epoch/committee_hash collide with a finality sig.
        let transfer_id = "tx-abc-123";
        let dest_zone = ZoneId::new("west");
        let source_seal_epoch: u64 = 0xAABB_CCDD_EEFF_0011;
        let mut dest_committee_hash = [0u8; 32];
        for (i, b) in dest_committee_hash.iter_mut().enumerate() { *b = (i * 3) as u8; }

        let out = xzone_abort_signable_bytes(
            transfer_id, &dest_zone, source_seal_epoch, &dest_committee_hash,
        );

        // Total length pin.
        let tid_bytes = transfer_id.as_bytes();
        let zone_path_owned = dest_zone.path();
        let zone_path_bytes = zone_path_owned.as_bytes();
        let expected_len =
            XZONE_ABORT_DOMAIN.len()
            + 4 + tid_bytes.len()
            + 4 + zone_path_bytes.len()
            + 8 + 32;
        assert_eq!(out.len(), expected_len, "abort signable byte-length pin");

        // Domain prefix.
        assert_eq!(
            &out[..XZONE_ABORT_DOMAIN.len()],
            XZONE_ABORT_DOMAIN,
            "first {} bytes MUST be XZONE_ABORT_DOMAIN",
            XZONE_ABORT_DOMAIN.len(),
        );

        // u32 BE transfer_id length + bytes.
        let mut pos = XZONE_ABORT_DOMAIN.len();
        assert_eq!(
            &out[pos..pos+4],
            &(tid_bytes.len() as u32).to_be_bytes(),
            "transfer_id length MUST be u32 BE",
        );
        pos += 4;
        assert_eq!(&out[pos..pos+tid_bytes.len()], tid_bytes, "transfer_id bytes pin");
        pos += tid_bytes.len();

        // u32 BE zone path length + bytes.
        assert_eq!(
            &out[pos..pos+4],
            &(zone_path_bytes.len() as u32).to_be_bytes(),
            "dest_zone path length MUST be u32 BE",
        );
        pos += 4;
        assert_eq!(&out[pos..pos+zone_path_bytes.len()], zone_path_bytes, "zone path bytes pin");
        pos += zone_path_bytes.len();

        // u64 BE source_seal_epoch + 32B dest_committee_hash.
        assert_eq!(
            &out[pos..pos+8],
            &source_seal_epoch.to_be_bytes(),
            "source_seal_epoch MUST be u64 BE",
        );
        pos += 8;
        assert_eq!(&out[pos..pos+32], &dest_committee_hash, "dest_committee_hash 32B pin");

        // Cross-domain disjointness: feeding the same zone/epoch/committee
        // through xzone_finality_signable_bytes (with a synthetic merkle_root)
        // MUST produce different bytes — replay barrier holds.
        let synthetic_root = [0u8; 32];
        let finality_bytes = xzone_finality_signable_bytes(
            &dest_zone, source_seal_epoch, &synthetic_root, &dest_committee_hash,
        );
        assert_ne!(
            out, finality_bytes,
            "abort signable bytes MUST be distinct from finality (replay barrier)",
        );
    }

    #[test]
    fn batch_b_committee_leaf_hash_domain_separated_from_raw_pk_hash() {
        // PIN: cross_zone.rs:1123 — committee_leaf_hash domain-separates leaf
        // hashes from inner-node hashes in the Merkle tree. Layout is:
        //   sha3_256("ELARA/COMMITTEE_LEAF/v1" || witness_pk)
        // A regression that drops the domain tag would allow an attacker to
        // present a raw PK hash as an inner-node digest (length-extension /
        // second-preimage style attack on the committee Merkle tree).
        let pk: Vec<u8> = (0..64).map(|i| i as u8).collect();

        let leaf = committee_leaf_hash(&pk);
        let naive = sha3_256(&pk);
        assert_ne!(
            leaf, naive,
            "committee_leaf_hash MUST domain-separate vs raw sha3_256(pk) — no leaf/inner collision",
        );

        // Determinism: same input → same hash.
        let leaf2 = committee_leaf_hash(&pk);
        assert_eq!(leaf, leaf2, "committee_leaf_hash MUST be deterministic");

        // Domain tag pin: recomputing manually with the exact tag MUST match.
        let mut buf = Vec::with_capacity(b"ELARA/COMMITTEE_LEAF/v1".len() + pk.len());
        buf.extend_from_slice(b"ELARA/COMMITTEE_LEAF/v1");
        buf.extend_from_slice(&pk);
        let manual = sha3_256(&buf);
        assert_eq!(leaf, manual, "committee_leaf_hash domain-tag literal MUST be 'ELARA/COMMITTEE_LEAF/v1'");

        // Different PK → different leaf (collision resistance, smoke).
        let other_pk: Vec<u8> = (0..64).map(|i| 0xFF - i as u8).collect();
        let other_leaf = committee_leaf_hash(&other_pk);
        assert_ne!(leaf, other_leaf, "distinct PKs MUST yield distinct leaves");

        // Empty PK is still hashable (no panic) and produces a stable digest
        // — degenerate but well-defined.
        let empty = committee_leaf_hash(&[]);
        assert_ne!(
            empty, [0u8; 32],
            "empty-PK leaf MUST NOT collide with the zero hash",
        );
    }

    #[test]
    fn batch_b_transfer_status_serde_snake_case_round_trip_pins_all_four_variants() {
        // PIN: cross_zone.rs:94 — TransferStatus is `#[serde(rename_all = "snake_case")]`
        // so on-wire shape is lowercase. A regression that drops the rename
        // attribute would emit PascalCase names ("Locked", "Claimed", …) and
        // break every existing on-disk pending ledger AND every external
        // account integration that depends on the documented snake_case form.
        // Pin all 4 variants serialize to the exact lowercase string and
        // deserialize back symmetrically.
        let cases = [
            (TransferStatus::Locked, "locked"),
            (TransferStatus::Claimed, "claimed"),
            (TransferStatus::Refunded, "refunded"),
            (TransferStatus::Aborted, "aborted"),
        ];

        for (variant, wire) in cases {
            let v = serde_json::to_value(&variant)
                .expect("TransferStatus MUST serialize");
            let s = v.as_str()
                .expect("TransferStatus MUST serialize to a plain string");
            assert_eq!(s, wire, "{:?} MUST serialize to snake_case '{}'", variant, wire);

            // Round-trip back.
            let back: TransferStatus = serde_json::from_value(v)
                .expect("TransferStatus MUST round-trip via JSON");
            assert_eq!(back, variant, "snake_case '{}' MUST deserialize back to {:?}", wire, variant);
        }

        // Negative pin: PascalCase variant names MUST NOT deserialize — that
        // would mean the snake_case rename is silently broken in one
        // direction.
        let pascal = serde_json::Value::String("Locked".into());
        assert!(
            serde_json::from_value::<TransferStatus>(pascal).is_err(),
            "PascalCase 'Locked' MUST NOT deserialize — snake_case is the wire form",
        );
    }
}
