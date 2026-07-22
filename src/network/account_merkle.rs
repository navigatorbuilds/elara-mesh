//! Key-addressed sparse Merkle tree over account state.
//!
//! Distinct from `merkle.rs` (which is per-zone and content-addressed):
//!   - **One global tree** over all accounts.
//!   - **Key-addressed**: leaf position is derived from `SHA3-256(account_id)`,
//!     *not* from the leaf value. The same account always occupies the same
//!     path; its leaf hash changes as its state changes.
//!
//! Light clients verify a balance by fetching a leaf + O(log N) siblings,
//! recomputing the root, and comparing to the root signed in the latest
//! epoch seal. This gives constant-size state proofs independent of total
//! record count — critical for the Light Node Profile (Phase 3 Stage 2C).
//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec MESH-BFT Phase 3 Stage 2A
//!
//! Scale notes:
//!   - 10B accounts ≈ 34 populated tree levels (log2 10B ≈ 33).
//!   - Each update touches O(log N) nodes (~30 writes at 10B accounts).
//!   - Storage: O(N log N) nodes total — trivial vs the record store itself.

use std::collections::HashSet;

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;
use crate::storage::rocks::{StorageEngine, CF_ACCOUNT_SMT};
use crate::accounting::types::{creator_identity_hash, extract_ledger_op, ParsedLedgerOp};

// The pure 256-level sparse-Merkle engine — identity-bound domain-separated
// node/leaf hashing, full-SHA3 path math, compressed proof build/verify
// (inclusion + exclusion), root fold — lives in the standalone `elara-smt`
// crate (MIT/Apache). Re-exported so existing `account_merkle::{...}` paths
// resolve. The proof type keeps its node name `AccountStateProof` for wire +
// consumer parity (its `account_id`/`state_hash` fields are the SMT key + leaf
// value; the leaf hash itself binds `account_id` inside the crate).
pub use elara_smt::{
    account_path, empty_hash, leaf_hash, verify_exclusion_proof, verify_proof, SmtExclusionProof,
    SmtProof as AccountStateProof, EMPTY_HASH, MAX_DEPTH,
};

use elara_smt::{SmtStore, SparseMerkleTree};

// ─── RocksDB store adapter ───────────────────────────────────────────────────

/// Adapts `StorageEngine`'s `CF_ACCOUNT_SMT` column family to the crate's
/// [`SmtStore`] trait. The crate owns the tree algorithm; this owns the bytes.
/// Values are always 32 bytes; a wrong-length read is reported as absent
/// (treated as an empty node), preserving the pre-extraction behaviour.
struct RocksSmtStore<'a> {
    storage: &'a StorageEngine,
}

impl<'a> SmtStore for RocksSmtStore<'a> {
    type Error = ElaraError;

    fn get(&self, key: &[u8]) -> Result<Option<[u8; 32]>> {
        match self.storage.get_cf_raw(CF_ACCOUNT_SMT, key)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes);
                Ok(Some(h))
            }
            _ => Ok(None),
        }
    }

    fn write_batch(&mut self, puts: &[(Vec<u8>, [u8; 32])], deletes: &[Vec<u8>]) -> Result<()> {
        let mut batch = self.storage.new_batch();
        let cf = self
            .storage
            .cf_handle(CF_ACCOUNT_SMT)
            .ok_or_else(|| ElaraError::Storage("CF_ACCOUNT_SMT not registered".into()))?;
        for (key, hash) in puts {
            batch.put_cf(&cf, key, hash);
        }
        for key in deletes {
            batch.delete_cf(&cf, key);
        }
        self.storage.write_batch(batch)
    }
}

// ─── Account-state SMT ───────────────────────────────────────────────────────

/// Account-state sparse Merkle tree backed by RocksDB (`CF_ACCOUNT_SMT`).
///
/// Thin node-side wrapper binding the generic [`SparseMerkleTree`] to the
/// RocksDB store; the tree algorithm itself lives in the `elara-smt` crate.
pub struct AccountStateSMT<'a> {
    inner: SparseMerkleTree<RocksSmtStore<'a>>,
}

impl<'a> AccountStateSMT<'a> {
    pub fn new(storage: &'a StorageEngine) -> Self {
        Self {
            inner: SparseMerkleTree::new(RocksSmtStore { storage }),
        }
    }

    /// Current root hash. `EMPTY_HASH` for a fresh tree.
    pub fn root(&self) -> Result<[u8; 32]> {
        self.inner.root()
    }

    /// Current state hash recorded for an account, or `None` if absent.
    pub fn get(&self, account_id: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        self.inner.get(account_id)
    }

    /// Upsert `account_id -> state_hash`. Touches O(log N) interior nodes.
    pub fn update(&mut self, account_id: &[u8; 32], state_hash: &[u8; 32]) -> Result<()> {
        self.inner.update(account_id, state_hash)
    }

    /// Tombstone `account_id`: collapse its leaf to `EMPTY_HASH` and drop the
    /// backing value-key, so the slot is byte-identical to one that was never
    /// inserted (`delete(A)` ≡ a fresh tree without A — `elara_smt` test
    /// `delete_root_matches_fresh_tree_over_survivors`). A no-op on an absent
    /// key. Used by the repair path to tombstone an account the producer's
    /// authoritative set does not carry, instead of writing `hash(default)` (a
    /// non-empty "ghost" leaf that would diverge a repaired node's
    /// `account_smt_root` from canonical and break light-client exclusion proofs
    /// for that slot — the F-5 V2 vector). NOT used on the seal hot path, which
    /// never removes accounts.
    pub fn delete(&mut self, account_id: &[u8; 32]) -> Result<()> {
        self.inner.delete(account_id)
    }

    /// Produce a compressed inclusion proof for `account_id`. Returns `None` if absent.
    pub fn proof(&self, account_id: &[u8; 32]) -> Result<Option<AccountStateProof>> {
        self.inner.proof(account_id)
    }

    /// Produce a compressed exclusion (non-membership) proof for `account_id`.
    /// Returns `None` if the account is present (use [`proof`](Self::proof) then).
    /// This is a sound cryptographic proof of absence — the leaf slot
    /// `SHA3-256(account_id)` is genuinely empty (full-width path → no collision
    /// can occupy it), so folding `EMPTY_HASH` up the siblings to the signed
    /// root proves the account does not exist, without trusting the server.
    pub fn exclusion_proof(&self, account_id: &[u8; 32]) -> Result<Option<SmtExclusionProof>> {
        self.inner.exclusion_proof(account_id)
    }

    /// Persist pending writes atomically.
    pub fn commit(&mut self) -> Result<()> {
        self.inner.commit()
    }
}

// ─── Ledger integration (Stage 2B) ────────────────────────────────────────

/// Deterministic hash of an `AccountState` — the value stored as the SMT leaf.
///
/// Uses fixed-width little-endian field concatenation (no framing, no length
/// prefixes — the layout is fixed so ambiguity is impossible) so the hash is
/// stable across versions and independent of serde's wire format. Any
/// balance / stake / counter change flips this hash, which flips the account's
/// leaf and propagates to the root.
///
/// CONSENSUS-DETERMINISM CONTRACT (C11, internal design notes).
/// This leaf is embedded in every seal's `account_smt_root` and is verified by
/// snapshot-bootstrap (`sync.rs`), light clients (`light.rs`), and the offline
/// verifier (`verify_core.rs`), so it MUST stay a pure function of the record
/// DAG — every field reproducible by replaying records, with NO per-node
/// wall-clock input. Today it holds:
///   - `available`/`staked`/`total_received`/`total_sent`/`tx_count`: pure
///     record-driven integers (conservation-bearing) — safe.
///   - `last_active` (f64 timestamp): a verbatim copy of `record.timestamp` at
///     every apply site (the one `= now` write, `ledger.rs` `process_expired_xzone`,
///     is superseded dead code), so it is reproducible. It is consensus-LOAD-
///     BEARING — the dormancy gate (`validate.rs`, `ledger.rs` reclaim/declare)
///     rejects records on a ±1s mismatch vs this value — so it must NOT be pruned.
///   - `vested_locked`/`uptime_secs`/`inactive_days`: INERT (always 0) only
///     because the out-of-band `uptime_vesting_loop` is permanently gated off
///     (`elara_node.rs`). These are the determinism LANDMINE: re-enabling that
///     wall-clock loop mutates them with NO record, forking the root across
///     followers. Before vesting may change any of them, it MUST flow through
///     signed records (the idle_decay pattern, `epoch.rs`); the loop stays off
///     until then. Pruning `uptime_secs`/`inactive_days` from this leaf is a
///     re-genesis-class one-way-door deferred to that work.
pub fn hash_account_state(state: &crate::accounting::ledger::AccountState) -> [u8; 32] {
    let mut buf = [0u8; 8 * 8 + 4]; // 7×u64 + 1×f64 + 1×u32 = 68 bytes
    let mut off = 0;
    macro_rules! put_u64 { ($v:expr) => {{
        buf[off..off + 8].copy_from_slice(&($v as u64).to_le_bytes());
        off += 8;
    }}; }
    put_u64!(state.available);
    put_u64!(state.staked);
    put_u64!(state.total_received);
    put_u64!(state.total_sent);
    put_u64!(state.tx_count);
    // last_active is f64 timestamp; to_bits() gives stable bytes.
    buf[off..off + 8].copy_from_slice(&state.last_active.to_bits().to_le_bytes());
    off += 8;
    put_u64!(state.vested_locked);
    put_u64!(state.uptime_secs);
    buf[off..off + 4].copy_from_slice(&state.inactive_days.to_le_bytes());
    off += 4;
    // NOTE: `witness_bonded` is intentionally NOT hashed — it is escrow debited
    // out of the already-committed `available` field (see
    // AccountState::witness_bonded), so the leaf still commits to every
    // spendable unit. Adding it here is a re-genesis-class consensus change.
    // Pinned by `hash_account_state_is_sensitive_to_every_field`.
    debug_assert_eq!(off, buf.len());
    sha3_256(&buf)
}

// ─── Canonical compressed-proof wire encoding (single source of truth) ───────
//
// Every endpoint and SDK MUST build/parse account proofs through these helpers
// so the node, the PQ SDK, the light SDK, the offline verifier, and the
// `elara-light-client` crate agree byte-for-byte. Shape (all 32-byte fields as
// 64-char hex):
//   inclusion: { account_id, identity, state_hash, root, present, siblings: [hex…] }
//   exclusion: { account_id, identity,             root, present, siblings: [hex…] }
// `identity` duplicates `account_id` for endpoints that key on it; the
// light-client crate accepts either via `alias = "identity"`.

/// JSON object for a compressed inclusion proof. Callers merge endpoint-specific
/// fields (`exists`, `account_state`, epoch binding) into the returned object.
pub fn proof_to_wire(proof: &AccountStateProof) -> serde_json::Value {
    serde_json::json!({
        "account_id": hex::encode(proof.account_id),
        "identity": hex::encode(proof.account_id),
        "state_hash": hex::encode(proof.state_hash),
        "root": hex::encode(proof.root),
        "present": hex::encode(proof.present),
        "siblings": proof.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

/// JSON object for a compressed exclusion (non-membership) proof.
pub fn exclusion_to_wire(proof: &SmtExclusionProof) -> serde_json::Value {
    serde_json::json!({
        "account_id": hex::encode(proof.account_id),
        "identity": hex::encode(proof.account_id),
        "root": hex::encode(proof.root),
        "present": hex::encode(proof.present),
        "siblings": proof.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

fn wire_hex32(body: &serde_json::Value, key: &str) -> Result<[u8; 32]> {
    let s = body
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Network(format!("account proof: missing/non-string `{key}`")))?;
    let bytes = hex::decode(s)
        .map_err(|_| ElaraError::Network(format!("account proof: `{key}` not hex")))?;
    if bytes.len() != 32 {
        return Err(ElaraError::Network(format!(
            "account proof: `{key}` is {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn wire_account_id(body: &serde_json::Value) -> Result<[u8; 32]> {
    // Accept either `account_id` (storage shape) or `identity` (REST shape).
    if body.get("account_id").and_then(|v| v.as_str()).is_some() {
        wire_hex32(body, "account_id")
    } else {
        wire_hex32(body, "identity")
    }
}

fn wire_siblings(body: &serde_json::Value) -> Result<Vec<[u8; 32]>> {
    let arr = body
        .get("siblings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ElaraError::Network("account proof: missing `siblings` array".into()))?;
    // A valid compressed proof carries exactly one sibling per set bit in the
    // 256-bit `present` bitmap, so `siblings.len() <= MAX_DEPTH` (256) always.
    // The array length is peer-supplied: without this cap a crafted body (e.g.
    // a million empty elements) pre-allocates megabytes off a few KB of wire —
    // a remote memory-amplification vector against any client decoding a proof
    // served by a malicious node. Reject before allocating; `elara_smt::fold`
    // independently rejects shape-mismatched proofs, but only after decode.
    if arr.len() > MAX_DEPTH as usize {
        return Err(ElaraError::Network(format!(
            "account proof: {} siblings exceeds SMT depth {MAX_DEPTH}",
            arr.len()
        )));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, e) in arr.iter().enumerate() {
        let s = e
            .as_str()
            .ok_or_else(|| ElaraError::Network(format!("account proof: sibling[{i}] not a string")))?;
        let bytes = hex::decode(s)
            .map_err(|_| ElaraError::Network(format!("account proof: sibling[{i}] not hex")))?;
        if bytes.len() != 32 {
            return Err(ElaraError::Network(format!(
                "account proof: sibling[{i}] is {} bytes, expected 32",
                bytes.len()
            )));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        out.push(h);
    }
    Ok(out)
}

/// Parse a compressed inclusion proof from its canonical wire JSON.
pub fn parse_wire_proof(body: &serde_json::Value) -> Result<AccountStateProof> {
    Ok(AccountStateProof {
        account_id: wire_account_id(body)?,
        state_hash: wire_hex32(body, "state_hash")?,
        root: wire_hex32(body, "root")?,
        present: wire_hex32(body, "present")?,
        siblings: wire_siblings(body)?,
    })
}

/// Parse a compressed exclusion proof from its canonical wire JSON.
pub fn parse_wire_exclusion(body: &serde_json::Value) -> Result<SmtExclusionProof> {
    Ok(SmtExclusionProof {
        account_id: wire_account_id(body)?,
        root: wire_hex32(body, "root")?,
        present: wire_hex32(body, "present")?,
        siblings: wire_siblings(body)?,
    })
}

/// Decode a hex identity hash into the 32-byte account id used as the SMT key.
fn decode_account_id(identity_hash_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(identity_hash_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Flush the ledger's `smt_dirty` set into the persistent account SMT.
///
/// For each dirty identity hash:
///   - Compute `state_hash = hash_account_state(current_account)`
///   - Update the tree at the account's key-addressed path
///
/// After all dirty entries are processed the tree is committed atomically.
/// Returns `(flushed_count, new_root)`.
///
/// Scale note: O(dirty × log N) RocksDB writes. At 10K tx/s with ~2 accounts
/// per op, flushed per-epoch (~30s), that's ~600K account updates × 30 nodes =
/// ~18M writes per epoch flush — batched into a single WriteBatch.
///
/// **TEST-PARITY ONLY — not for production paths.** Superseded in production by
/// the `snapshot_dirty` + `apply_snapshot` split (so the RocksDB walk runs in
/// `spawn_blocking` without holding `ledger`); kept as the reference oracle
/// proving the split path produces identical roots. A production caller would
/// bypass `NodeState::account_smt_write_gate` (the CF_ACCOUNT_SMT writer
/// serialization) — if this is ever needed live, route it through the gate.
pub fn flush_dirty(
    storage: &crate::storage::rocks::StorageEngine,
    ledger: &mut crate::accounting::ledger::LedgerState,
) -> Result<(usize, [u8; 32])> {
    let mut tree = AccountStateSMT::new(storage);
    let mut flushed = 0usize;

    // Drain into a Vec first so we don't hold a reference while mutating.
    let dirty: Vec<String> = ledger.smt_dirty.drain().collect();
    for identity_hex in &dirty {
        let Some(account_id) = decode_account_id(identity_hex) else {
            // Malformed identity hash — skip silently. This should never
            // happen because creator_identity_hash always produces 64 hex chars.
            continue;
        };
        let account = ledger.accounts
            .get(identity_hex)
            .cloned()
            .unwrap_or_default();
        let state_hash = hash_account_state(&account);
        tree.update(&account_id, &state_hash)?;
        flushed += 1;
    }
    tree.commit()?;
    let root = tree.root()?;
    Ok((flushed, root))
}

/// DISC-8: Drain `ledger.smt_dirty` and pre-compute `(account_id, state_hash)` pairs.
///
/// Cheap, pure in-memory — no RocksDB. Intended to run under `ledger.write()`
/// just long enough to snapshot the dirty set and clear the flags. The
/// returned snapshot is then fed to [`apply_snapshot`] from `spawn_blocking`
/// without holding any async lock.
///
/// Why this exists: the original `flush_dirty` walks O(dirty × log N) RocksDB
/// paths while holding `ledger.write().await`. Under compaction pressure each
/// walk can take seconds, which blocks every concurrent `ledger.read()` —
/// every incoming epoch seal's phase-1 validation stalls, and state_core's
/// record queue backs up. Snapshot-and-offload cuts the lock hold to the
/// drain + clone cost (microseconds at testnet scale).
///
/// Every entry is `Some(state_hash)` (an upsert) — this path NEVER tombstones.
/// The seal/bootstrap callers never remove accounts, so a dirty-but-absent
/// identity here is the legitimate "not-yet-created recipient" / "full-drain"
/// case that must keep getting its zero-state leaf (see
/// `flush_dirty_missing_account_hashes_as_default`), not a deletion. Only the
/// repair path deletes, via [`snapshot_scoped`]'s explicit delete set.
pub fn snapshot_dirty(
    ledger: &mut crate::accounting::ledger::LedgerState,
) -> Vec<([u8; 32], Option<[u8; 32]>)> {
    let dirty: Vec<String> = ledger.smt_dirty.drain().collect();
    let mut out = Vec::with_capacity(dirty.len());
    for identity_hex in &dirty {
        let Some(account_id) = decode_account_id(identity_hex) else {
            continue;
        };
        let account = ledger.accounts
            .get(identity_hex)
            .cloned()
            .unwrap_or_default();
        out.push((account_id, Some(hash_account_state(&account))));
    }
    out
}

/// DISC-8: Apply a pre-snapshotted dirty set to the persistent SMT.
///
/// Pure storage work — safe to run in `spawn_blocking` with no ledger lock.
/// Must be paired with [`snapshot_dirty`] / [`snapshot_scoped`]: the caller
/// drains under a brief async write lock, then hands the snapshot here.
///
/// **Writer serialization contract:** the SMT `commit()` writes its private
/// node cache with no conflict detection, and every real write touches the
/// shared root/near-root keys — two unserialized `apply_snapshot` calls
/// clobber each other last-writer-wins. Every LIVE caller must hold
/// `NodeState::account_smt_write_gate` across this call (acquired in the
/// async caller, held over the `spawn_blocking` await). Test callers with an
/// exclusive tempdir store are exempt.
///
/// Each entry is `(account_id, Some(state_hash))` to upsert the leaf, or
/// `(account_id, None)` to tombstone it (collapse to `EMPTY_HASH`). Only the
/// repair path emits `None`; every seal/bootstrap caller emits all-`Some` (the
/// snapshot helpers only return `None` when the *repair caller* names the id in
/// its explicit delete set). The mixed update+delete commit is one atomic
/// `WriteBatch`.
pub fn apply_snapshot(
    storage: &crate::storage::rocks::StorageEngine,
    snapshot: &[([u8; 32], Option<[u8; 32]>)],
) -> Result<(usize, [u8; 32])> {
    let mut tree = AccountStateSMT::new(storage);
    for (account_id, state_hash) in snapshot {
        match state_hash {
            Some(h) => tree.update(account_id, h)?,
            None => tree.delete(account_id)?,
        }
    }
    tree.commit()?;
    let root = tree.root()?;
    Ok((snapshot.len(), root))
}

/// Non-mutating account-SMT root over a ledger's CURRENT in-memory accounts.
///
/// Computes the root a bootstrapping peer's post-apply verify will reproduce —
/// the root over the EXACT `accounts` set serialized into a snapshot — WITHOUT
/// touching the persisted `CF_ACCOUNT_SMT` and WITHOUT flushing `smt_dirty`.
///
/// Producer-side snapshot emit (`serve_snapshot`, `archive_snapshot_loop`) must
/// use this instead of `AccountStateSMT::new(rocks).root()`. The persisted root
/// is only advanced by `flush_dirty` / `apply_snapshot` at seal time, so on a
/// busy seal-creator it lags the in-memory ledger whenever any record landed
/// since the last flush — reading it makes the snapshot advertise a stale root,
/// and the joiner's rebuild over the serialized accounts (`sync.rs` post-apply
/// verify) mismatches it on every legitimate bootstrap (false ROOT MISMATCH /
/// alert fatigue). See `snapshot.rs` "read root AFTER flushing smt_dirty".
///
/// Deterministic and store-independent: it inserts the same
/// `{decode_account_id(id) -> hash_account_state(acct)}` set that `snapshot_dirty` +
/// `apply_snapshot` apply, and the SMT root is a pure function of that set
/// (`deterministic_root_across_engines`, `disc8_snapshot_apply_matches_flush_dirty_root`),
/// so it is byte-identical to the joiner's `apply_snapshot` rebuild. Pure
/// in-memory: O(accounts × log N), no RocksDB I/O and no lock — safe to call
/// inside the snapshot `spawn_blocking`.
pub fn root_over_accounts(
    accounts: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
) -> Result<[u8; 32]> {
    let mut tree = SparseMerkleTree::new(elara_smt::MemorySmtStore::new());
    for (identity_hex, account) in accounts {
        let Some(account_id) = decode_account_id(identity_hex) else {
            // Malformed identity hash — skip, exactly as flush_dirty/snapshot_dirty do.
            continue;
        };
        let state_hash = hash_account_state(account);
        tree.update(&account_id, &state_hash)
            .map_err(|e| ElaraError::Storage(format!("in-mem account SMT update: {e}")))?;
    }
    tree.root()
        .map_err(|e| ElaraError::Storage(format!("in-mem account SMT root: {e}")))
}

/// Gap-1 architectural follow-up: enumerate the identities a record's op
/// touches, so the witness-side SMT flush can be scoped to exactly the
/// identities the seal's records affected — instead of draining the whole
/// `smt_dirty` set (which can include records the witness has applied that
/// belong to FUTURE seals, leaking divergence into THIS seal's root).
///
/// Always includes the record creator. For ops with explicit recipient /
/// counterparty fields we add those too (Mint, Transfer, WitnessReward,
/// XZoneLock, XZoneClaim, Slash, DormancyReclaim, DormancyDeclare,
/// DormancyProofOfLife). Ops whose effects are mediated by lookups
/// (XZoneReject / XZoneAbort via pending sender) are intentionally
/// creator-only here:
/// those identities stay in `smt_dirty` and get flushed at the next seal.
/// The conservative scope keeps the helper pure (no ledger / cross-zone
/// reads) and matches the well-formed steady-state case where `smt_dirty`
/// at seal time ≡ identities touched by records in that seal.
pub fn record_touched_identities(record: &ValidationRecord) -> Vec<String> {
    let mut out = Vec::with_capacity(2);
    out.push(creator_identity_hash(record));
    if let Ok(Some(op)) = extract_ledger_op(record) {
        match op {
            ParsedLedgerOp::Mint { to, .. } | ParsedLedgerOp::Transfer { to, .. } => {
                out.push(to);
            }
            ParsedLedgerOp::WitnessReward { from, to, .. } => {
                out.push(from);
                out.push(to);
            }
            ParsedLedgerOp::XZoneLock { recipient, .. }
            | ParsedLedgerOp::XZoneClaim { recipient, .. } => {
                out.push(recipient);
            }
            ParsedLedgerOp::Slash {
                offender,
                challenger,
                jury,
                ..
            } => {
                out.push(offender);
                out.push(challenger);
                out.extend(jury);
            }
            ParsedLedgerOp::DormancyReclaim {
                dormant_identity, ..
            } => {
                out.push(dormant_identity);
            }
            ParsedLedgerOp::DormancyDeclare {
                target_identity, ..
            }
            | ParsedLedgerOp::DormancyProofOfLife {
                target_identity, ..
            } => {
                out.push(target_identity);
            }
            ParsedLedgerOp::IdleDecay { batch } => {
                // Every debited exchange + credited staker moves. MUST equal the
                // set marked dirty in apply_op + mutated in apply_idle_decay_batch,
                // or the witness seal scope misses leaves the producer updated.
                for (id, _) in batch.debits {
                    out.push(id);
                }
                for (id, _) in batch.staker_credits {
                    out.push(id);
                }
            }
            ParsedLedgerOp::XZoneTimeoutRefund { batch }
            | ParsedLedgerOp::XZoneStaleReap { batch } => {
                // Every refunded/reaped sender moves its `available` (+ total_sent/
                // tx_count/last_active). MUST equal the set marked dirty in apply_op
                // (= every listed sender), or the witness seal scope misses leaves
                // the producer updated → account-SMT root divergence at this seal.
                // (Listed superset of the actually-applied subset — harmless: an
                // unmutated leaf re-hashes to the same value.)
                for (_tid, sender, _amt) in batch.refunds {
                    out.push(sender);
                }
            }
            _ => {}
        }
    }
    out
}

/// Scope-bounded variant of [`snapshot_dirty`]: only snapshots accounts in
/// `scope`, and only drains those identities from `smt_dirty` (entries
/// outside scope stay dirty for the next flush). Used by witnesses to
/// converge on the seal-creator's signed `account_smt_root` even when their
/// own `smt_dirty` has accumulated entries beyond the seal's actual reach.
///
/// False positives (in-scope identities not actually touched) are harmless —
/// the SMT update is idempotent on identical state hashes. False negatives
/// (touched identities outside scope) are the well-known residual: those
/// identities stay dirty and get flushed at the next seal's scope.
///
/// Counterpart on the storage side is the existing [`apply_snapshot`].
///
/// `deletes` is the explicit tombstone set: any in-scope identity also present
/// in `deletes` is emitted as `None` so [`apply_snapshot`] collapses its leaf
/// to `EMPTY_HASH` (F-5 V2). ONLY the chain-repair path passes a non-empty
/// `deletes` (the accounts it removed from the ledger because the producer's
/// authoritative set does not carry them); the witness seal-flush passes `∅`,
/// so its behaviour is byte-identical to before — an in-scope-but-absent
/// identity that is NOT in `deletes` (the not-yet-committed recipient) still
/// gets its `hash(default)` zero-state leaf. This explicit set, rather than
/// inferring delete from `accounts.get(id).is_none()`, is what keeps the
/// shared witness path unperturbed while letting repair tombstone correctly.
pub fn snapshot_scoped(
    ledger: &mut crate::accounting::ledger::LedgerState,
    scope: &HashSet<String>,
    deletes: &HashSet<String>,
) -> Vec<([u8; 32], Option<[u8; 32]>)> {
    let mut out = Vec::with_capacity(scope.len());
    for identity_hex in scope {
        // Drop from smt_dirty regardless — this entry is now reflected on disk.
        ledger.smt_dirty.remove(identity_hex);
        let Some(account_id) = decode_account_id(identity_hex) else {
            continue;
        };
        if deletes.contains(identity_hex) {
            // Explicit removal (repair path only): tombstone to EMPTY_HASH.
            out.push((account_id, None));
            continue;
        }
        let account = ledger
            .accounts
            .get(identity_hex)
            .cloned()
            .unwrap_or_default();
        out.push((account_id, Some(hash_account_state(&account))));
    }
    out
}

/// F-2 boot reconcile: ensure the persistent account SMT carries a leaf for
/// every genesis-config identity (authority + each validator).
///
/// `apply_genesis_validators` mutates these accounts WITHOUT marking `smt_dirty`
/// on the path that matters for an already-running node: its idempotency guard
/// (`if state.stakes.contains_key(rid)`) skips every validator on a warm
/// restart, so the dirty marks added at the mutation site never fire there.
/// `smt_dirty` is also `#[serde(skip)]`, so a restored ledger starts with it
/// empty. The upshot: a node that genesised before the dirty-mark fix never
/// wrote its genesis-validator leaves to the persistent SMT, so every seal's
/// `account_smt_root` omitted them while `root_over_accounts` (the boot replay
/// root) includes them — a guaranteed false §6a boot mismatch every restart.
///
/// This flushes exactly the genesis-config identities (present in the ledger)
/// into the persistent SMT, reusing the proven [`snapshot_scoped`] +
/// [`apply_snapshot`] path. The next seal then advertises a root that includes
/// them, so subsequent boots verify clean.
///
/// **Scoped to config identities ONLY — never "all accounts on mismatch".** A
/// real supply-neutral drop in a NON-genesis account must still surface as
/// `Mismatch` rather than be silently reconciled away. Genesis-validator leaves
/// are config-derived and deterministic, so re-flushing them cannot mask a drop.
///
/// O(genesis_validators) SMT writes — a trivial one-shot at boot.
pub fn reconcile_genesis_accounts_into_smt(
    storage: &crate::storage::rocks::StorageEngine,
    ledger: &mut crate::accounting::ledger::LedgerState,
    genesis_authority: &str,
    validators: &[crate::accounting::types::GenesisValidator],
) -> Result<usize> {
    let mut scope: HashSet<String> = HashSet::new();
    if ledger.accounts.contains_key(genesis_authority) {
        scope.insert(genesis_authority.to_string());
    }
    for v in validators {
        // Only reconcile identities that actually exist in the ledger — never
        // synthesise a default (zero) leaf for a missing one.
        if ledger.accounts.contains_key(&v.identity) {
            scope.insert(v.identity.clone());
        }
    }
    if scope.is_empty() {
        return Ok(0);
    }
    // Genesis reconcile only scopes identities present in the ledger (guarded
    // above) — it never tombstones, so the delete set is empty.
    let pairs = snapshot_scoped(ledger, &scope, &HashSet::new());
    let (n, _root) = apply_snapshot(storage, &pairs)?;
    Ok(n)
}

/// F-2 boot diagnostic: when [`crate::network::epoch::check_boot_sealed_root`]
/// reports a `Mismatch`, turn the opaque root divergence into an actionable
/// identity list by finding which in-memory account leaves differ from the
/// persisted SMT.
///
/// Returns `(total_diverged, sample)` where `sample` holds up to `limit`
/// `(identity, in_mem_leaf, on_disk_leaf_or_"ABSENT")` tuples for accounts whose
/// `hash_account_state` does not equal the SMT's stored leaf. A leaf present in
/// the ledger but missing from the SMT shows `"ABSENT"` — the never-flushed
/// class (e.g. an off-apply_op mutation that never marked `smt_dirty`).
///
/// **Directionality:** this is a LEDGER-side scan. If it returns `(0, [])` while
/// the roots still differ, the divergence is the opposite class — a phantom SMT
/// leaf (an identity in the SMT but absent from the ledger: a dirtied-then-
/// removed account, or a `smt_dirty` mark for a recipient whose op never created
/// the account, flushed as `unwrap_or_default()`). The caller should log that
/// inference so the phantom class is observable.
///
/// O(accounts · log N) one-shot — same cost class as `root_over_accounts`, and
/// only on a mismatch.
pub fn diagnose_account_smt_divergence(
    storage: &crate::storage::rocks::StorageEngine,
    accounts: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
    limit: usize,
) -> (usize, Vec<(String, String, String)>) {
    let tree = AccountStateSMT::new(storage);
    let mut diverged = 0usize;
    let mut sample: Vec<(String, String, String)> = Vec::new();
    for (id, acct) in accounts {
        let Some(account_id) = decode_account_id(id) else {
            continue;
        };
        let in_mem = hash_account_state(acct);
        let on_disk = tree.get(&account_id).ok().flatten();
        if on_disk != Some(in_mem) {
            diverged += 1;
            if sample.len() < limit {
                sample.push((
                    id.clone(),
                    hex::encode(in_mem),
                    on_disk.map(hex::encode).unwrap_or_else(|| "ABSENT".to_string()),
                ));
            }
        }
    }
    (diverged, sample)
}

/// Result of an SMT-side orphan-leaf scan ([`scan_orphan_smt_leaves`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrphanLeafScan {
    /// Value-leaves whose account_id has no matching ledger account.
    pub orphan_count: usize,
    /// Total `v:` value-leaves enumerated (bounded by `max_scan`).
    pub scanned_leaves: usize,
    /// `true` if the scan hit `max_scan` and may have stopped early.
    pub truncated: bool,
    /// Up to `sample_limit` orphans as `(account_id_hex, leaf_state_hash_hex)`.
    /// The account_id_hex is the exact key `AccountStateSMT::delete` takes.
    pub sample: Vec<(String, String)>,
}

/// **SMT-side** phantom / ghost-leaf scan (F-5). Enumerates the persisted
/// account-SMT value-leaves and returns those whose 32-byte account_id is **not**
/// present in `accounts` — i.e. a leaf the ledger has no account for (the
/// *SMT-ahead* "phantom": a clean-crash V1 transient, a repair-path V2 ghost, or a
/// pre-256-bit-re-genesis orphan).
///
/// This is the complement of [`diagnose_account_smt_divergence`], which iterates
/// the **ledger** and therefore structurally cannot see an SMT leaf whose account
/// is absent (it returns `(0, [])` for this direction even while the roots differ).
/// Naming the orphan by account_id is the prerequisite for any targeted
/// reconcile/`delete` remedy — you cannot safely tombstone a leaf you have not
/// identified.
///
/// Read-only; **one-shot / admin only** (O(populated leaves), excluded from the
/// SCALE RULE's runtime-hot-path clause exactly as the bootstrap post-apply verify
/// is). `max_scan` bounds the enumeration; `sample_limit` bounds the returned list.
/// Takes the ledger **account-id set** (not the full `AccountState` map): the
/// cross-reference needs only identity, so callers can pass a cheap key-clone
/// across a `spawn_blocking` boundary instead of cloning every account's state.
pub fn scan_orphan_smt_leaves(
    storage: &crate::storage::rocks::StorageEngine,
    ledger_account_ids: &std::collections::HashSet<String>,
    max_scan: usize,
    sample_limit: usize,
) -> OrphanLeafScan {
    // The authoritative leaf set is the path of every live ledger account.
    let ledger_paths: std::collections::HashSet<[u8; 32]> = ledger_account_ids
        .iter()
        .filter_map(|id| decode_account_id(id))
        .collect();

    let leaves = storage
        .account_smt_value_leaves(max_scan)
        .unwrap_or_default();
    let scanned_leaves = leaves.len();
    let truncated = scanned_leaves >= max_scan;

    let mut orphan_count = 0usize;
    let mut sample: Vec<(String, String)> = Vec::new();
    for (account_id, leaf_hash) in leaves {
        if !ledger_paths.contains(&account_id) {
            orphan_count += 1;
            if sample.len() < sample_limit {
                sample.push((hex::encode(account_id), hex::encode(leaf_hash)));
            }
        }
    }
    OrphanLeafScan {
        orphan_count,
        scanned_leaves,
        truncated,
        sample,
    }
}

/// Outcome of [`reconcile_orphan_leaves_to_ledger`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrphanReconcileOutcome {
    /// Orphan value-leaves tombstoned (0 unless `committed`).
    pub deleted: usize,
    /// Total `v:` value-leaves enumerated (bounded by `max_scan`).
    pub scanned_leaves: usize,
    /// SMT root BEFORE the op (hex) — the committed CF root at entry.
    pub pre_root: String,
    /// SMT root AFTER the buffered deletes (hex). Committed iff it equals
    /// `target_root`; on abort this is the *candidate* that was rejected.
    pub post_root: String,
    /// The ledger-rebuild root `root_over_accounts(accounts)` (hex) — the gate
    /// target the post-delete root must match to commit.
    pub target_root: String,
    /// `true` iff the gate passed and the tombstones were COMMITTED. When
    /// `false`, `CF_ACCOUNT_SMT` is byte-for-byte untouched.
    pub committed: bool,
    /// Reason the op refused to commit (only when `!committed`).
    pub aborted_reason: Option<String>,
    /// Tombstoned account_ids (hex) — populated only when `committed`.
    pub tombstoned: Vec<String>,
}

/// F-5 one-time cleanup: reconcile the persisted account SMT to the live ledger by
/// tombstoning every value-leaf whose account_id is **absent** from `accounts` —
/// the SMT-ahead phantom class (a repair-path V2 ghost, a clean-crash V1
/// transient, or a pre-256-bit-re-genesis orphan). Complement of the shipped
/// repair-path fix (142ff677): that stops *new* phantoms; this removes *historical*
/// ones already committed into a node's `account_smt_root`.
///
/// **GATE (the entire safety argument).** The deletes are applied to a *buffered*
/// tree; the batch is committed **iff** the resulting root equals
/// `root_over_accounts(accounts)`. The SMT leaf position is the full 256-bit
/// `SHA3-256(account_id)` and the leaf hash binds the key, so root-equality ⟹
/// leaf-set-equality under SHA3-256 collision-resistance. Therefore a passing gate
/// certifies the post-op leaf set is byte-identical to the live ledger account set:
/// the op can neither **miss** a phantom (a leftover leaf would keep the root ≠
/// target) nor **over-delete** a live account (a removed live leaf would likewise
/// diverge the root). On a mismatch — a truncated scan or an additionally-stale
/// *live* leaf — it commits nothing and returns `committed:false` with a reason.
///
/// **The root-equality gate is only sound under the writer gate.** Both sides
/// of the comparison (target from the cloned ledger, candidate from CF reads
/// made while buffering) predate the commit — a concurrent SMT writer landing
/// between buffer and commit is invisible here (stale-vs-stale still passes)
/// and its near-root interior nodes would be clobbered by this commit, leaving
/// the persisted root inconsistent with the persisted leaves (fusion-audited
/// 2026-07-05). The async caller therefore MUST hold
/// `NodeState::account_smt_write_gate` across the entire call; with the gate
/// held, the worst case is a spurious abort + operator re-run, never a wrong
/// commit.
///
/// **Run on the seal-producing node.** `account_smt_root` is non-finality-gating
/// (witnesses reject on the record `merkle_root`, not this), and the *next* seal
/// re-binds whatever root is on disk (`epoch.rs` seal loop reads
/// `AccountStateSMT::root()` / `apply_snapshot`), so after commit the producer's
/// next seal (≤ the quiet-zone seal cap) advertises the clean root and boot §6a
/// then verifies. On a non-producing witness the on-disk root would converge but
/// its last-registered seal would keep pointing at the old root.
///
/// Bounded / **admin-recovery-only** (excluded from the SCALE RULE's runtime
/// hot-path clause exactly as `scan_orphan_smt_leaves` and bootstrap post-apply
/// verify are): enumerates ≤ `max_scan` leaves and refuses (no mutation) if the
/// orphan set is truncated or exceeds `max_delete` — a large orphan set is an
/// operator escalation, not an auto-delete. O(orphans · log N) writes; call from
/// `spawn_blocking`.
pub fn reconcile_orphan_leaves_to_ledger(
    storage: &StorageEngine,
    accounts: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
    max_scan: usize,
    max_delete: usize,
) -> Result<OrphanReconcileOutcome> {
    // The gate target: the clean root over EXACTLY the live ledger accounts
    // (pure in-memory, no CF I/O — identical set to what a bootstrap joiner and
    // the seal's `snapshot_dirty` path reproduce).
    let target = root_over_accounts(accounts)?;
    let target_hex = hex::encode(target);

    // Committed CF root at entry (for the report / operator diff).
    let pre_root = AccountStateSMT::new(storage).root()?;
    let pre_hex = hex::encode(pre_root);

    let ledger_ids: HashSet<String> = accounts.keys().cloned().collect();
    // Reuse the shipped scan; `sample_limit = max_delete` so `sample` carries the
    // FULL orphan set whenever `orphan_count <= max_delete`.
    let scan = scan_orphan_smt_leaves(storage, &ledger_ids, max_scan, max_delete);

    let abort = |reason: String, post_hex: String| OrphanReconcileOutcome {
        deleted: 0,
        scanned_leaves: scan.scanned_leaves,
        pre_root: pre_hex.clone(),
        post_root: post_hex,
        target_root: target_hex.clone(),
        committed: false,
        aborted_reason: Some(reason),
        tombstoned: Vec::new(),
    };

    if scan.truncated {
        return Ok(abort(
            format!(
                "scan truncated at max_scan={max_scan} (scanned {}) — raise max_scan for a \
                 complete pre-image before reconciling",
                scan.scanned_leaves
            ),
            pre_hex.clone(),
        ));
    }
    if scan.orphan_count == 0 {
        return Ok(abort(
            "no orphan leaves — persisted SMT id-set already matches the ledger".into(),
            pre_hex.clone(),
        ));
    }
    if scan.orphan_count > max_delete {
        return Ok(abort(
            format!(
                "orphan_count={} exceeds max_delete={max_delete} — operator escalation, not \
                 auto-deleted",
                scan.orphan_count
            ),
            pre_hex.clone(),
        ));
    }

    // Apply the tombstones to a buffered tree (no CF write until `commit`).
    let mut tree = AccountStateSMT::new(storage);
    let mut tombstoned: Vec<String> = Vec::with_capacity(scan.sample.len());
    for (acct_hex, _leaf_hex) in &scan.sample {
        let Some(account_id) = decode_account_id(acct_hex) else {
            // The scan already decoded these; a failure here is a real anomaly —
            // abort rather than commit a partial reconcile.
            return Err(ElaraError::Storage(format!(
                "orphan account_id not decodable during reconcile: {acct_hex}"
            )));
        };
        tree.delete(&account_id)?;
        tombstoned.push(acct_hex.clone());
    }

    // Pre-commit gate: the buffered root must equal the ledger-rebuild target.
    let candidate = tree.root()?;
    let candidate_hex = hex::encode(candidate);
    if candidate != target {
        // Drop the buffered tree — CF_ACCOUNT_SMT is untouched.
        return Ok(abort(
            "post-delete root != root_over_accounts(ledger) — the orphan set does not exactly \
             explain the divergence (an additional live leaf is stale, or the scan is \
             incomplete); refusing to commit"
                .into(),
            candidate_hex,
        ));
    }

    tree.commit()?;
    Ok(OrphanReconcileOutcome {
        deleted: tombstoned.len(),
        scanned_leaves: scan.scanned_leaves,
        pre_root: pre_hex,
        post_root: candidate_hex,
        target_root: target_hex,
        committed: true,
        aborted_reason: None,
        tombstoned,
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;

    #[test]
    fn wire_siblings_rejects_oversized_array() {
        // Memory-amplification guard: a peer-supplied siblings array longer than
        // the SMT depth (MAX_DEPTH=256) is rejected BEFORE allocation. Elements
        // are null so this also proves rejection happens before per-element
        // parsing (the length check is the first thing wire_siblings does).
        let body = serde_json::json!({
            "siblings": vec![serde_json::Value::Null; MAX_DEPTH as usize + 1]
        });
        let err = wire_siblings(&body).unwrap_err();
        assert!(
            format!("{err}").contains("exceeds SMT depth"),
            "expected depth-cap rejection, got: {err}"
        );
    }

    #[test]
    fn wire_siblings_accepts_exactly_max_depth() {
        // Boundary: exactly MAX_DEPTH valid siblings must still parse (the cap is
        // `> MAX_DEPTH`, not `>=`) — a maximally-dense proof carries one sibling
        // per set bit in the 256-bit `present` bitmap.
        let h = "00".repeat(32); // 32-byte hex hash
        let arr: Vec<serde_json::Value> = (0..MAX_DEPTH as usize)
            .map(|_| serde_json::Value::String(h.clone()))
            .collect();
        let body = serde_json::json!({ "siblings": arr });
        let out = wire_siblings(&body).expect("MAX_DEPTH siblings must parse");
        assert_eq!(out.len(), MAX_DEPTH as usize);
    }

    fn test_storage() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn acc(id: &[u8]) -> [u8; 32] {
        sha3_256(id)
    }

    #[test]
    fn empty_tree_root_is_sentinel() {
        let (storage, _dir) = test_storage();
        let tree = AccountStateSMT::new(&storage);
        assert_eq!(tree.root().unwrap(), EMPTY_HASH);
    }

    #[test]
    fn empty_hash_equals_sha3_of_empty() {
        assert_eq!(EMPTY_HASH, sha3_256(b""));
    }

    #[test]
    fn single_update_changes_root() {
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);
        let before = tree.root().unwrap();
        tree.update(&acc(b"alice"), &sha3_256(b"balance=100")).unwrap();
        let after = tree.root().unwrap();
        assert_ne!(before, after);
        assert_ne!(after, EMPTY_HASH);
    }

    #[test]
    fn update_is_key_addressed_not_value_addressed() {
        // The defining property vs the content-addressed tree:
        // updating the same account's state should change ONLY that leaf's path,
        // and a subsequent update overwrites in place (no new path allocated).
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);

        let a = acc(b"alice");
        tree.update(&a, &sha3_256(b"state_v1")).unwrap();
        let root_v1 = tree.root().unwrap();

        tree.update(&a, &sha3_256(b"state_v2")).unwrap();
        let root_v2 = tree.root().unwrap();

        assert_ne!(root_v1, root_v2, "changing account state must change root");
        assert_eq!(tree.get(&a).unwrap(), Some(sha3_256(b"state_v2")));

        // Revert — root returns to v1 because path is determined by identity,
        // not by value. This is impossible in the content-addressed tree.
        tree.update(&a, &sha3_256(b"state_v1")).unwrap();
        assert_eq!(tree.root().unwrap(), root_v1);
    }

    #[test]
    fn proof_roundtrip_single_account() {
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);
        let a = acc(b"solo");
        tree.update(&a, &sha3_256(b"s")).unwrap();
        tree.commit().unwrap();

        let tree = AccountStateSMT::new(&storage);
        let proof = tree.proof(&a).unwrap().expect("account should exist");
        assert_eq!(proof.account_id, a);
        assert_eq!(proof.state_hash, sha3_256(b"s"));
        assert_eq!(proof.root, tree.root().unwrap());
        // Compressed proof: a lone account has no non-empty siblings.
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.present, [0u8; 32]);
        assert!(verify_proof(&proof));
    }

    #[test]
    fn proof_roundtrip_many_accounts() {
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);
        let accounts: Vec<[u8; 32]> = (0..50u32)
            .map(|i| acc(&i.to_be_bytes()))
            .collect();
        for (i, a) in accounts.iter().enumerate() {
            tree.update(a, &sha3_256(&(i as u64).to_be_bytes())).unwrap();
        }
        tree.commit().unwrap();

        let tree = AccountStateSMT::new(&storage);
        let root = tree.root().unwrap();
        assert_ne!(root, EMPTY_HASH);

        for (i, a) in accounts.iter().enumerate() {
            let proof = tree.proof(a).unwrap().unwrap();
            assert_eq!(proof.root, root);
            assert_eq!(proof.state_hash, sha3_256(&(i as u64).to_be_bytes()));
            assert!(verify_proof(&proof), "proof #{i} should verify");
        }
    }

    #[test]
    fn proof_for_missing_account_is_none() {
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);
        tree.update(&acc(b"present"), &sha3_256(b"x")).unwrap();
        tree.commit().unwrap();

        let tree = AccountStateSMT::new(&storage);
        assert!(tree.proof(&acc(b"absent")).unwrap().is_none());
    }

    #[test]
    fn tampered_proof_fails() {
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);
        for i in 0..8u8 {
            tree.update(&acc(&[i]), &sha3_256(&[i, i])).unwrap();
        }
        tree.commit().unwrap();

        let tree = AccountStateSMT::new(&storage);
        let mut p = tree.proof(&acc(&[0])).unwrap().unwrap();
        // Flip a bit in the first (non-empty) sibling.
        assert!(!p.siblings.is_empty(), "8 co-resident accounts yield siblings");
        p.siblings[0][0] ^= 0x01;
        assert!(!verify_proof(&p));

        // Wrong state hash
        let mut q = tree.proof(&acc(&[0])).unwrap().unwrap();
        q.state_hash[0] ^= 0x01;
        assert!(!verify_proof(&q));

        // Wrong root
        let mut r = tree.proof(&acc(&[0])).unwrap().unwrap();
        r.root = [0xFFu8; 32];
        assert!(!verify_proof(&r));
    }

    #[test]
    fn commit_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let a = acc(b"persist");
        let root_before;
        {
            let storage = StorageEngine::open(dir.path()).unwrap();
            let mut tree = AccountStateSMT::new(&storage);
            tree.update(&a, &sha3_256(b"persist_state")).unwrap();
            tree.commit().unwrap();
            root_before = tree.root().unwrap();
        }
        {
            let storage = StorageEngine::open(dir.path()).unwrap();
            let tree = AccountStateSMT::new(&storage);
            assert_eq!(tree.root().unwrap(), root_before);
            let p = tree.proof(&a).unwrap().unwrap();
            assert!(verify_proof(&p));
        }
    }

    #[test]
    fn hash_account_state_is_sensitive_to_every_field() {
        use crate::accounting::ledger::AccountState;
        let base = AccountState::default();
        let h0 = hash_account_state(&base);

        // Every field bound into the consensus SMT leaf MUST move the hash.
        // This is the regression net for the account-state seam: if a future
        // refactor silently drops a field from `hash_account_state`, the leaf —
        // and thus the account-SMT root every node signs — would stop
        // committing to it, a cross-node divergence / soundness hazard. The
        // 2026-06-18 determinism audit certified this function as THE leaf seam;
        // assert all 9 hashed fields, not the 3 the original test covered.
        macro_rules! assert_field_sensitive {
            ($field:ident = $val:expr) => {{
                let mut s = base.clone();
                s.$field = $val;
                assert_ne!(
                    hash_account_state(&s),
                    h0,
                    concat!(
                        "hash_account_state must be sensitive to `",
                        stringify!($field),
                        "`",
                    ),
                );
            }};
        }
        assert_field_sensitive!(available = 1);
        assert_field_sensitive!(staked = 1);
        assert_field_sensitive!(total_received = 1);
        assert_field_sensitive!(total_sent = 1);
        assert_field_sensitive!(tx_count = 1);
        assert_field_sensitive!(last_active = 1.0);
        assert_field_sensitive!(vested_locked = 1);
        assert_field_sensitive!(uptime_secs = 1);
        assert_field_sensitive!(inactive_days = 1);

        // `witness_bonded` is DELIBERATELY excluded from the leaf (see
        // AccountState::witness_bonded): the bond is debited out of the
        // already-committed `available` field, so it is a conservation-safe
        // escrow memo, not independently spendable. Pin the exclusion so that
        // binding it into the leaf — a re-genesis-class consensus change — must
        // be a conscious edit to this test, never an accidental refactor.
        let mut wb = base.clone();
        wb.witness_bonded = 1;
        assert_eq!(
            hash_account_state(&wb),
            h0,
            "witness_bonded is intentionally NOT bound into the SMT leaf; \
             changing this is a re-genesis-class fork — update deliberately",
        );
    }

    #[test]
    fn flush_dirty_updates_smt_to_match_ledger_state() {
        use crate::accounting::ledger::{AccountState, LedgerState};

        let (storage, _dir) = test_storage();

        // Set up a ledger with two accounts and mark them dirty.
        let mut ledger = LedgerState::new();
        // identity_hash is hex(SHA3-256(pubkey)) — here we just craft valid hex.
        let alice_hex = hex::encode(acc(b"alice"));
        let bob_hex = hex::encode(acc(b"bob"));

        ledger.accounts.insert(
            alice_hex.clone(),
            AccountState { available: 1_000, tx_count: 1, ..Default::default() },
        );
        ledger.accounts.insert(
            bob_hex.clone(),
            AccountState { available: 42, tx_count: 1, ..Default::default() },
        );
        ledger.smt_dirty.insert(alice_hex.clone());
        ledger.smt_dirty.insert(bob_hex.clone());

        let (flushed, root1) = flush_dirty(&storage, &mut ledger).unwrap();
        assert_eq!(flushed, 2);
        assert!(ledger.smt_dirty.is_empty(), "flush must drain the dirty set");
        assert_ne!(root1, EMPTY_HASH);

        // Both accounts should have valid proofs matching their current state.
        let tree = AccountStateSMT::new(&storage);
        for hex_id in [&alice_hex, &bob_hex] {
            let mut account_id = [0u8; 32];
            account_id.copy_from_slice(&hex::decode(hex_id).unwrap());
            let expected_state = ledger.accounts.get(hex_id).unwrap();

            let proof = tree.proof(&account_id).unwrap()
                .expect("flushed account must have a proof");
            assert_eq!(proof.state_hash, hash_account_state(expected_state));
            assert_eq!(proof.root, root1);
            assert!(verify_proof(&proof));
        }

        // Mutate alice's balance, re-dirty, flush → root should move and the
        // new proof should reflect the new state.
        ledger.accounts.get_mut(&alice_hex).unwrap().available = 9_999;
        ledger.smt_dirty.insert(alice_hex.clone());
        let (flushed2, root2) = flush_dirty(&storage, &mut ledger).unwrap();
        assert_eq!(flushed2, 1);
        assert_ne!(root1, root2);

        let tree = AccountStateSMT::new(&storage);
        let mut alice_id = [0u8; 32];
        alice_id.copy_from_slice(&hex::decode(&alice_hex).unwrap());
        let proof = tree.proof(&alice_id).unwrap().unwrap();
        assert_eq!(proof.state_hash, hash_account_state(ledger.accounts.get(&alice_hex).unwrap()));
        assert_eq!(proof.root, root2);
        assert!(verify_proof(&proof));
    }

    #[test]
    fn disc8_snapshot_apply_matches_flush_dirty_root() {
        // DISC-8: the split (snapshot under lock + apply in spawn_blocking)
        // must produce the same SMT root as the inline flush_dirty path.
        use crate::accounting::ledger::{AccountState, LedgerState};

        let alice_hex = hex::encode(acc(b"alice"));
        let bob_hex = hex::encode(acc(b"bob"));
        let carol_hex = hex::encode(acc(b"carol"));

        let mut ledger_a = LedgerState::new();
        ledger_a.accounts.insert(alice_hex.clone(), AccountState { available: 1_000, tx_count: 3, ..Default::default() });
        ledger_a.accounts.insert(bob_hex.clone(), AccountState { available: 42, tx_count: 1, ..Default::default() });
        ledger_a.accounts.insert(carol_hex.clone(), AccountState { available: 7, staked: 11, tx_count: 2, ..Default::default() });
        ledger_a.smt_dirty.insert(alice_hex.clone());
        ledger_a.smt_dirty.insert(bob_hex.clone());
        ledger_a.smt_dirty.insert(carol_hex.clone());

        // Path A: inline flush_dirty.
        let (storage_a, _dir_a) = test_storage();
        let (flushed_a, root_a) = flush_dirty(&storage_a, &mut ledger_a).unwrap();

        // Path B: snapshot under lock, apply from spawn_blocking equivalent.
        let mut ledger_b = LedgerState::new();
        ledger_b.accounts.insert(alice_hex.clone(), AccountState { available: 1_000, tx_count: 3, ..Default::default() });
        ledger_b.accounts.insert(bob_hex.clone(), AccountState { available: 42, tx_count: 1, ..Default::default() });
        ledger_b.accounts.insert(carol_hex.clone(), AccountState { available: 7, staked: 11, tx_count: 2, ..Default::default() });
        ledger_b.smt_dirty.insert(alice_hex);
        ledger_b.smt_dirty.insert(bob_hex);
        ledger_b.smt_dirty.insert(carol_hex);

        let (storage_b, _dir_b) = test_storage();
        let snapshot = snapshot_dirty(&mut ledger_b);
        assert!(ledger_b.smt_dirty.is_empty(), "snapshot must drain the dirty set");
        let (flushed_b, root_b) = apply_snapshot(&storage_b, &snapshot).unwrap();

        assert_eq!(flushed_a, flushed_b, "flushed count must match");
        assert_eq!(root_a, root_b, "SMT root must match between inline and offloaded paths");
        assert_eq!(flushed_b, 3);
    }

    #[test]
    fn root_over_accounts_matches_joiner_rebuild_and_differs_from_stale_persisted() {
        // DISC: serve_snapshot / archive_snapshot_loop must advertise the root
        // over the CURRENT in-memory accounts (what the joiner reproduces), NOT
        // the persisted CF_ACCOUNT_SMT root, which is only advanced by flush_dirty
        // at seal time and lags the live ledger whenever records landed since the
        // last flush. Reading the stale persisted root made the joiner's
        // post-apply verify false-fail on every legitimate bootstrap.
        use crate::accounting::ledger::{AccountState, LedgerState};

        let id1 = hex::encode(acc(b"acct-1"));
        let id2 = hex::encode(acc(b"acct-2"));

        // Baseline: one account, flushed → persisted root committed to rocks.
        let (storage, _dir) = test_storage();
        let mut ledger = LedgerState::new();
        ledger.accounts.insert(id1.clone(), AccountState { available: 100, ..Default::default() });
        ledger.smt_dirty.insert(id1.clone());
        flush_dirty(&storage, &mut ledger).unwrap();

        // Records land since that flush: a new account + a balance change on id1.
        // smt_dirty is non-empty; the persisted root is now stale vs the ledger.
        ledger.accounts.insert(id2.clone(), AccountState { available: 50, ..Default::default() });
        ledger.accounts.get_mut(&id1).unwrap().available = 999;
        ledger.smt_dirty.insert(id1.clone());
        ledger.smt_dirty.insert(id2.clone());

        // The OLD producer read THIS stale persisted root.
        let stale_persisted = AccountStateSMT::new(&storage).root().unwrap();
        let in_mem = root_over_accounts(&ledger.accounts).unwrap();
        assert_ne!(
            in_mem, stale_persisted,
            "root_over_accounts must reflect the live in-mem set, not the stale persisted root"
        );

        // Fidelity: byte-identical to what the bootstrapping joiner computes —
        // mark every loaded account dirty, snapshot_dirty, apply_snapshot on a
        // fresh rocks store (the network/sync.rs post-apply verify path). Proves
        // the in-mem (MemorySmtStore) root == the rocks rebuild for the same set.
        for id in ledger.accounts.keys().cloned().collect::<Vec<_>>() {
            ledger.smt_dirty.insert(id);
        }
        let pairs = snapshot_dirty(&mut ledger);
        let (joiner_store, _jdir) = test_storage();
        let (_n, joiner_root) = apply_snapshot(&joiner_store, &pairs).unwrap();
        assert_eq!(
            in_mem, joiner_root,
            "producer in-mem root must equal the joiner's rocks apply_snapshot rebuild"
        );
    }

    #[test]
    fn reconcile_genesis_accounts_writes_missing_validator_leaf_f2() {
        // F-2: reproduce the pre-fix state — a genesis validator with a staked
        // balance, present in the in-memory ledger but NEVER written to the
        // persistent SMT (genesis stake mutates accounts outside apply_op, so
        // smt_dirty was never set, and it does not survive restart). The boot
        // reconcile must flush exactly the genesis-config identities so the
        // persistent root converges on the full-set root_over_accounts.
        use crate::accounting::ledger::{AccountState, LedgerState};
        use crate::accounting::types::GenesisValidator;

        let (storage, _dir) = test_storage();
        let auth_hex = hex::encode(acc(b"authority"));
        let val_hex = hex::encode(acc(b"validator"));

        let mut ledger = LedgerState::new();
        ledger
            .accounts
            .insert(auth_hex.clone(), AccountState { available: 5_000, ..Default::default() });
        ledger
            .accounts
            .insert(val_hex.clone(), AccountState { staked: 3_000, ..Default::default() });
        // As after a restart: dirty set empty, validator leaf absent from disk.
        assert!(ledger.smt_dirty.is_empty());
        let empty_root = AccountStateSMT::new(&storage).root().unwrap();

        let validators = vec![GenesisValidator { identity: val_hex.clone(), stake_micros: 3_000 }];
        let n =
            reconcile_genesis_accounts_into_smt(&storage, &mut ledger, &auth_hex, &validators).unwrap();
        assert_eq!(n, 2, "authority + validator reconciled into the SMT");

        let new_root = AccountStateSMT::new(&storage).root().unwrap();
        assert_ne!(new_root, empty_root, "reconcile must advance the persistent root");
        // The whole point: the persistent root now equals the full-set root the
        // boot check (root_over_accounts) computes — so the §6a comparison agrees.
        assert_eq!(
            new_root,
            root_over_accounts(&ledger.accounts).unwrap(),
            "reconciled persistent SMT must match the full-set root_over_accounts"
        );

        // A genesis identity absent from the ledger is never synthesised as a
        // zero leaf (would corrupt the root).
        let mut ledger2 = LedgerState::new();
        let ghost = vec![GenesisValidator { identity: hex::encode(acc(b"ghost")), stake_micros: 1 }];
        let n2 = reconcile_genesis_accounts_into_smt(
            &storage,
            &mut ledger2,
            &hex::encode(acc(b"nobody")),
            &ghost,
        )
        .unwrap();
        assert_eq!(n2, 0, "no leaf synthesised for identities absent from the ledger");
    }

    #[test]
    fn diagnose_account_smt_divergence_finds_absent_and_stale_leaves_f2() {
        use crate::accounting::ledger::{AccountState, LedgerState};
        let (storage, _dir) = test_storage();
        let flushed_id = hex::encode(acc(b"flushed"));
        let absent_id = hex::encode(acc(b"absent"));

        let mut ledger = LedgerState::new();
        ledger
            .accounts
            .insert(flushed_id.clone(), AccountState { available: 100, ..Default::default() });
        ledger
            .accounts
            .insert(absent_id.clone(), AccountState { staked: 7, ..Default::default() });
        // Flush ONLY the first account into the SMT.
        ledger.smt_dirty.insert(flushed_id.clone());
        flush_dirty(&storage, &mut ledger).unwrap();

        // absent_id is in the ledger but never reached the SMT → reported ABSENT.
        let (diverged, sample) = diagnose_account_smt_divergence(&storage, &ledger.accounts, 16);
        assert_eq!(diverged, 1, "exactly the unflushed account diverges");
        assert_eq!(sample.len(), 1);
        assert_eq!(sample[0].0, absent_id);
        assert_eq!(sample[0].2, "ABSENT", "unflushed leaf reported ABSENT");

        // Mutate the flushed account in-memory without re-flushing → stale leaf.
        ledger.accounts.get_mut(&flushed_id).unwrap().available = 999;
        let (diverged2, sample2) = diagnose_account_smt_divergence(&storage, &ledger.accounts, 16);
        assert_eq!(diverged2, 2, "now both diverge (one absent, one stale)");
        let stale = sample2.iter().find(|(id, _, _)| id == &flushed_id).unwrap();
        assert_ne!(stale.2, "ABSENT");
        assert_ne!(stale.1, stale.2, "in-mem leaf must differ from the stale on-disk leaf");
    }

    #[test]
    fn account_smt_value_leaves_enumerates_only_value_keys() {
        // The enumerator must seek to the `v:` keyspace and return exactly one
        // pair per populated leaf — NOT the far-larger `n:` interior-node set that
        // sorts before it. Two leaves in → two pairs out, account_ids verbatim.
        use crate::accounting::ledger::AccountState;
        let (storage, _dir) = test_storage();
        let a = acc(b"leaf-a");
        let b = acc(b"leaf-b");
        let ha = hash_account_state(&AccountState { available: 1, ..Default::default() });
        let hb = hash_account_state(&AccountState { available: 2, ..Default::default() });
        apply_snapshot(&storage, &[(a, Some(ha)), (b, Some(hb))]).unwrap();

        let mut leaves = storage.account_smt_value_leaves(1000).unwrap();
        leaves.sort();
        let mut want = vec![(a, ha), (b, hb)];
        want.sort();
        assert_eq!(leaves, want, "exactly the two value-leaves, account_ids recovered from key[2..34]");
    }

    #[test]
    fn scan_orphan_smt_leaves_finds_smt_ahead_ghost() {
        // The F-5 phantom: a leaf persisted in CF_ACCOUNT_SMT for an account the
        // ledger has no record of. The ledger-side diagnostic can't see it; this
        // SMT-side scan names it by account_id.
        use crate::accounting::ledger::AccountState;
        let (storage, _dir) = test_storage();
        let alive = acc(b"alive");
        let orphan = acc(b"orphan-ghost");
        apply_snapshot(
            &storage,
            &[
                (alive, Some(hash_account_state(&AccountState { available: 50, ..Default::default() }))),
                (orphan, Some(hash_account_state(&AccountState::default()))),
            ],
        )
        .unwrap();

        // Ledger knows ONLY about `alive`.
        let ledger_ids: std::collections::HashSet<String> =
            std::iter::once(hex::encode(alive)).collect();

        let scan = scan_orphan_smt_leaves(&storage, &ledger_ids, 1000, 16);
        assert_eq!(scan.scanned_leaves, 2, "both value-leaves enumerated (n: nodes skipped)");
        assert_eq!(scan.orphan_count, 1, "exactly the ledger-absent leaf is an orphan");
        assert!(!scan.truncated);
        assert_eq!(scan.sample.len(), 1);
        assert_eq!(scan.sample[0].0, hex::encode(orphan), "orphan named by its account_id");
        assert!(
            !scan.sample.iter().any(|(id, _)| id == &hex::encode(alive)),
            "the live account is never flagged"
        );
    }

    #[test]
    fn scan_orphan_smt_leaves_clean_when_every_leaf_has_an_account() {
        // No-false-positive guard: when every persisted leaf maps to a live ledger
        // account, orphan_count is 0. This is the healthy steady state.
        use crate::accounting::ledger::AccountState;
        let (storage, _dir) = test_storage();
        let a = acc(b"acct-1");
        let b = acc(b"acct-2");
        apply_snapshot(
            &storage,
            &[
                (a, Some(hash_account_state(&AccountState { available: 5, ..Default::default() }))),
                (b, Some(hash_account_state(&AccountState { staked: 9, ..Default::default() }))),
            ],
        )
        .unwrap();
        let ledger_ids: std::collections::HashSet<String> =
            [hex::encode(a), hex::encode(b)].into_iter().collect();

        let scan = scan_orphan_smt_leaves(&storage, &ledger_ids, 1000, 16);
        assert_eq!(scan.scanned_leaves, 2);
        assert_eq!(scan.orphan_count, 0, "no orphans when the ledger covers every leaf");
        assert!(scan.sample.is_empty());
    }

    #[test]
    fn scan_orphan_smt_leaves_respects_max_scan_truncation() {
        // A tight max_scan bounds the enumeration and flags truncation, so an
        // operator knows the count is a floor, not a total.
        use crate::accounting::ledger::AccountState;
        let (storage, _dir) = test_storage();
        for i in 0u8..5 {
            let id = acc(&[b'x', i]);
            apply_snapshot(
                &storage,
                &[(id, Some(hash_account_state(&AccountState { available: i as u64, ..Default::default() })))],
            )
            .unwrap();
        }
        // Empty ledger → every leaf is an orphan, but the scan stops at max_scan=3.
        let ledger_ids = std::collections::HashSet::<String>::new();
        let scan = scan_orphan_smt_leaves(&storage, &ledger_ids, 3, 16);
        assert_eq!(scan.scanned_leaves, 3, "enumeration capped at max_scan");
        assert!(scan.truncated, "truncation flagged when the cap is hit");
        assert_eq!(scan.orphan_count, 3, "orphan_count is over the capped set (a floor)");
    }

    #[test]
    fn disc8_snapshot_dirty_empty_returns_empty_vec() {
        use crate::accounting::ledger::LedgerState;
        let mut ledger = LedgerState::new();
        let snapshot = snapshot_dirty(&mut ledger);
        assert!(snapshot.is_empty());
    }

    #[test]
    fn disc8_apply_snapshot_empty_is_empty_root() {
        let (storage, _dir) = test_storage();
        let (flushed, root) = apply_snapshot(&storage, &[]).unwrap();
        assert_eq!(flushed, 0);
        assert_eq!(root, EMPTY_HASH);
    }

    #[test]
    fn flush_dirty_with_empty_set_is_noop() {
        use crate::accounting::ledger::LedgerState;
        let (storage, _dir) = test_storage();
        let mut ledger = LedgerState::new();
        let (flushed, root) = flush_dirty(&storage, &mut ledger).unwrap();
        assert_eq!(flushed, 0);
        assert_eq!(root, EMPTY_HASH);
    }

    #[test]
    fn flush_dirty_missing_account_hashes_as_default() {
        // apply_op can mark an identity dirty and immediately have its account
        // drained to zero (full-drain slash). The flush must still produce a
        // valid proof for the zero-state leaf, not skip it.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let (storage, _dir) = test_storage();
        let mut ledger = LedgerState::new();
        let ghost_hex = hex::encode(acc(b"ghost"));

        ledger.smt_dirty.insert(ghost_hex.clone());
        let (flushed, _root) = flush_dirty(&storage, &mut ledger).unwrap();
        assert_eq!(flushed, 1);

        let tree = AccountStateSMT::new(&storage);
        let mut ghost_id = [0u8; 32];
        ghost_id.copy_from_slice(&hex::decode(&ghost_hex).unwrap());
        let proof = tree.proof(&ghost_id).unwrap().unwrap();
        assert_eq!(proof.state_hash, hash_account_state(&AccountState::default()));
        assert!(verify_proof(&proof));
    }

    // ─── Gap-1 architectural follow-up: scope-bounded witness flush ────────
    //
    // record_touched_identities() must enumerate exactly the identities that
    // apply_op writes through (creator + per-op recipients), so the witness
    // can scope-bound its flush to converge on the seal-creator's signed root.

    fn make_record_with_creator(
        creator_pk: Vec<u8>,
        metadata: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> crate::record::ValidationRecord {
        crate::record::ValidationRecord {
            id: "test-rec".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(b"scope-test").to_vec(),
            creator_public_key: creator_pk,
            timestamp: 1700000000.0,
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
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    fn creator_pk(seed: &[u8]) -> Vec<u8> {
        // Identity hash is sha3_256_hex(creator_public_key); using a unique
        // pubkey per actor lets the tests assert by explicit hex.
        let mut pk = vec![0u8; 1952];
        pk[..seed.len().min(1952)].copy_from_slice(&seed[..seed.len().min(1952)]);
        pk
    }

    fn id_of(seed: &[u8]) -> String {
        crate::crypto::hash::sha3_256_hex(&creator_pk(seed))
    }

    #[test]
    fn record_touched_identities_no_op_metadata_is_creator_only() {
        // Non-ledger record: creator only, no op fields.
        let rec = make_record_with_creator(creator_pk(b"alice"), Default::default());
        let touched = record_touched_identities(&rec);
        assert_eq!(touched, vec![id_of(b"alice")]);
    }

    #[test]
    fn record_touched_identities_stake_is_creator_only() {
        use crate::accounting::types::{stake_metadata, StakePurpose};
        let meta = stake_metadata(100, &StakePurpose::Witness);
        let rec = make_record_with_creator(creator_pk(b"alice"), meta);
        let touched = record_touched_identities(&rec);
        // Stake reaches only the creator; the `_ => {}` arm covers it.
        assert_eq!(touched, vec![id_of(b"alice")]);
    }

    #[test]
    fn record_touched_identities_transfer_includes_recipient() {
        use crate::accounting::types::transfer_metadata;
        let bob_id = id_of(b"bob");
        let meta = transfer_metadata(500, &bob_id, Some("payment"));
        let rec = make_record_with_creator(creator_pk(b"alice"), meta);
        let mut touched = record_touched_identities(&rec);
        touched.sort();
        let mut expected = vec![id_of(b"alice"), bob_id];
        expected.sort();
        assert_eq!(touched, expected);
    }

    #[test]
    fn record_touched_identities_mint_includes_recipient() {
        use crate::accounting::types::mint_metadata;
        let to_id = id_of(b"genesis_recv");
        let meta = mint_metadata(1_000_000, &to_id, "genesis");
        let rec = make_record_with_creator(creator_pk(b"genesis_authority"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"genesis_authority")));
        assert!(touched.contains(&to_id));
        assert_eq!(touched.len(), 2);
    }

    #[test]
    fn record_touched_identities_witness_reward_pair() {
        use crate::accounting::types::witness_reward_metadata;
        let from_id = id_of(b"sender");
        let to_id = id_of(b"witness");
        let meta = witness_reward_metadata(10, &from_id, &to_id, "rec-1");
        let rec = make_record_with_creator(creator_pk(b"settler"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"settler")));
        assert!(touched.contains(&from_id));
        assert!(touched.contains(&to_id));
        assert_eq!(touched.len(), 3);
    }

    #[test]
    fn record_touched_identities_xzone_lock_includes_recipient() {
        use crate::accounting::types::xzone_lock_metadata;
        let recv = id_of(b"xzone_recv");
        let meta = xzone_lock_metadata(42, &recv, "0", "1");
        let rec = make_record_with_creator(creator_pk(b"sender"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"sender")));
        assert!(touched.contains(&recv));
        assert_eq!(touched.len(), 2);
    }

    #[test]
    fn record_touched_identities_xzone_claim_includes_recipient() {
        use crate::accounting::types::xzone_claim_metadata;
        let recv = id_of(b"xzone_recv");
        let meta = xzone_claim_metadata("transfer-001", 42, &recv);
        let rec = make_record_with_creator(creator_pk(b"claim_anchor"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"claim_anchor")));
        assert!(touched.contains(&recv));
    }

    #[test]
    fn record_touched_identities_slash_includes_jury() {
        use crate::accounting::types::slash_metadata;
        let offender = id_of(b"offender");
        let challenger = id_of(b"challenger");
        let jury = vec![id_of(b"j1"), id_of(b"j2"), id_of(b"j3")];
        let meta = slash_metadata(
            500, &offender, &challenger, &jury, "stake-001", "double-sign",
        );
        let rec = make_record_with_creator(creator_pk(b"settler"), meta);
        let touched: std::collections::HashSet<String> =
            record_touched_identities(&rec).into_iter().collect();
        assert!(touched.contains(&id_of(b"settler")));
        assert!(touched.contains(&offender));
        assert!(touched.contains(&challenger));
        for j in &jury {
            assert!(touched.contains(j), "jury {j} must be in touched scope");
        }
    }

    #[test]
    fn record_touched_identities_dormancy_reclaim_includes_target() {
        use crate::accounting::types::dormancy_reclaim_metadata;
        let dormant = id_of(b"dormant");
        let meta = dormancy_reclaim_metadata(99, &dormant, 1700000000.0);
        let rec = make_record_with_creator(creator_pk(b"reclaimer"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"reclaimer")));
        assert!(touched.contains(&dormant));
    }

    #[test]
    fn record_touched_identities_dormancy_declare_includes_target() {
        use crate::accounting::types::dormancy_declare_metadata;
        let target = id_of(b"sleeper");
        let meta = dormancy_declare_metadata(&target, 1700000000.0);
        let rec = make_record_with_creator(creator_pk(b"observer"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"observer")));
        assert!(touched.contains(&target));
    }

    #[test]
    fn record_touched_identities_dormancy_proof_of_life_includes_target() {
        use crate::accounting::types::dormancy_proof_of_life_metadata;
        let target = id_of(b"alive");
        let meta = dormancy_proof_of_life_metadata(&target, "deadbeef");
        let rec = make_record_with_creator(creator_pk(b"relayer"), meta);
        let touched = record_touched_identities(&rec);
        assert!(touched.contains(&id_of(b"relayer")));
        assert!(touched.contains(&target));
    }

    #[test]
    fn snapshot_scoped_drains_only_in_scope_identities() {
        use crate::accounting::ledger::{AccountState, LedgerState};

        let alice_hex = hex::encode(acc(b"alice"));
        let bob_hex = hex::encode(acc(b"bob"));
        let carol_hex = hex::encode(acc(b"carol"));

        let mut ledger = LedgerState::new();
        ledger.accounts.insert(
            alice_hex.clone(),
            AccountState { available: 100, ..Default::default() },
        );
        ledger.accounts.insert(
            bob_hex.clone(),
            AccountState { available: 200, ..Default::default() },
        );
        ledger.accounts.insert(
            carol_hex.clone(),
            AccountState { available: 300, ..Default::default() },
        );
        ledger.smt_dirty.insert(alice_hex.clone());
        ledger.smt_dirty.insert(bob_hex.clone());
        ledger.smt_dirty.insert(carol_hex.clone());

        // Scope only includes alice + carol; bob must remain dirty.
        let mut scope = HashSet::new();
        scope.insert(alice_hex.clone());
        scope.insert(carol_hex.clone());

        let snapshot = snapshot_scoped(&mut ledger, &scope, &HashSet::new());
        assert_eq!(snapshot.len(), 2);
        assert!(!ledger.smt_dirty.contains(&alice_hex));
        assert!(!ledger.smt_dirty.contains(&carol_hex));
        assert!(
            ledger.smt_dirty.contains(&bob_hex),
            "out-of-scope identity must remain dirty for next seal flush",
        );

        // Scope identities map to the correct hashed account state.
        let mut alice_id = [0u8; 32];
        alice_id.copy_from_slice(&hex::decode(&alice_hex).unwrap());
        let alice_entry = snapshot.iter().find(|(id, _)| id == &alice_id);
        assert!(alice_entry.is_some());
        let alice_state = ledger.accounts.get(&alice_hex).unwrap();
        assert_eq!(alice_entry.unwrap().1, Some(hash_account_state(alice_state)));
    }

    #[test]
    fn snapshot_scoped_with_full_dirty_set_matches_snapshot_dirty_root() {
        // Regression guard: when scope == dirty set, the on-disk root must
        // match the legacy snapshot_dirty path. This is the property that
        // makes scope-bounding safe to land — same input → same root.
        use crate::accounting::ledger::{AccountState, LedgerState};

        let alice_hex = hex::encode(acc(b"alice"));
        let bob_hex = hex::encode(acc(b"bob"));
        let carol_hex = hex::encode(acc(b"carol"));

        let build_ledger = || {
            let mut l = LedgerState::new();
            l.accounts.insert(
                alice_hex.clone(),
                AccountState { available: 1_000, tx_count: 3, ..Default::default() },
            );
            l.accounts.insert(
                bob_hex.clone(),
                AccountState { available: 42, tx_count: 1, ..Default::default() },
            );
            l.accounts.insert(
                carol_hex.clone(),
                AccountState { available: 7, staked: 11, tx_count: 2, ..Default::default() },
            );
            l.smt_dirty.insert(alice_hex.clone());
            l.smt_dirty.insert(bob_hex.clone());
            l.smt_dirty.insert(carol_hex.clone());
            l
        };

        // Path A: legacy full-drain snapshot_dirty.
        let mut ledger_a = build_ledger();
        let snap_a = snapshot_dirty(&mut ledger_a);
        let (storage_a, _dir_a) = test_storage();
        let (_, root_a) = apply_snapshot(&storage_a, &snap_a).unwrap();

        // Path B: scope-bounded with scope = full dirty set.
        let mut ledger_b = build_ledger();
        let mut scope = HashSet::new();
        scope.insert(alice_hex);
        scope.insert(bob_hex);
        scope.insert(carol_hex);
        let snap_b = snapshot_scoped(&mut ledger_b, &scope, &HashSet::new());
        let (storage_b, _dir_b) = test_storage();
        let (_, root_b) = apply_snapshot(&storage_b, &snap_b).unwrap();

        assert_eq!(
            root_a, root_b,
            "scope-bounded path with full-coverage scope must produce the legacy root",
        );
        assert!(ledger_b.smt_dirty.is_empty(), "full-coverage scope must drain dirty");
    }

    #[test]
    fn snapshot_scoped_skips_invalid_hex_identity() {
        // decode_account_id returns None for non-hex identities; those must
        // not appear in the snapshot but should still be drained from dirty.
        use crate::accounting::ledger::LedgerState;
        let mut ledger = LedgerState::new();
        let bad_hex = "not_hex".to_string();
        ledger.smt_dirty.insert(bad_hex.clone());

        let mut scope = HashSet::new();
        scope.insert(bad_hex.clone());
        let snap = snapshot_scoped(&mut ledger, &scope, &HashSet::new());
        assert!(snap.is_empty());
        assert!(!ledger.smt_dirty.contains(&bad_hex));
    }

    #[test]
    fn snapshot_scoped_missing_account_hashes_as_default() {
        // Same invariant as flush_dirty_missing_account_hashes_as_default:
        // an in-scope identity with no AccountState entry is hashed at the
        // zero state — never skipped, since apply_op may have full-drained it.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let (storage, _dir) = test_storage();
        let mut ledger = LedgerState::new();
        let ghost_hex = hex::encode(acc(b"ghost-scoped"));
        ledger.smt_dirty.insert(ghost_hex.clone());

        let mut scope = HashSet::new();
        scope.insert(ghost_hex.clone());
        let snap = snapshot_scoped(&mut ledger, &scope, &HashSet::new());
        assert_eq!(snap.len(), 1);
        let (flushed, _root) = apply_snapshot(&storage, &snap).unwrap();
        assert_eq!(flushed, 1);

        let tree = AccountStateSMT::new(&storage);
        let mut ghost_id = [0u8; 32];
        ghost_id.copy_from_slice(&hex::decode(&ghost_hex).unwrap());
        let proof = tree.proof(&ghost_id).unwrap().unwrap();
        assert_eq!(proof.state_hash, hash_account_state(&AccountState::default()));
    }

    #[test]
    fn snapshot_scoped_empty_scope_is_noop() {
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        let alice_hex = hex::encode(acc(b"alice"));
        ledger.accounts.insert(
            alice_hex.clone(),
            AccountState { available: 10, ..Default::default() },
        );
        ledger.smt_dirty.insert(alice_hex.clone());

        let snap = snapshot_scoped(&mut ledger, &HashSet::new(), &HashSet::new());
        assert!(snap.is_empty());
        assert!(
            ledger.smt_dirty.contains(&alice_hex),
            "empty scope must not drain anything from smt_dirty",
        );
    }

    #[test]
    fn snapshot_scoped_delete_set_tombstones_only_listed() {
        // F-5 V2: the explicit `deletes` set distinguishes "removed" (→ None
        // tombstone) from "not-yet-created" (→ Some(default), the witness
        // transient that must stay byte-identical). A PRESENT account is never
        // tombstoned even when in scope.
        use crate::accounting::ledger::{AccountState, LedgerState};
        let mut ledger = LedgerState::new();
        let present_hex = hex::encode(acc(b"present"));
        let removed_hex = hex::encode(acc(b"removed"));
        let notyet_hex = hex::encode(acc(b"not-yet-created"));
        ledger.accounts.insert(
            present_hex.clone(),
            AccountState { available: 500, tx_count: 2, ..Default::default() },
        );
        let present_hash = hash_account_state(ledger.accounts.get(&present_hex).unwrap());
        // `removed` and `not-yet-created` are absent from `accounts`.

        let mut scope = HashSet::new();
        scope.insert(present_hex.clone());
        scope.insert(removed_hex.clone());
        scope.insert(notyet_hex.clone());
        let mut deletes = HashSet::new();
        deletes.insert(removed_hex.clone());

        let pairs = snapshot_scoped(&mut ledger, &scope, &deletes);

        let id_of = |h: &str| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&hex::decode(h).unwrap());
            b
        };
        let entry = |id: [u8; 32]| pairs.iter().find(|(i, _)| *i == id).map(|(_, v)| *v);
        assert_eq!(
            entry(id_of(&present_hex)),
            Some(Some(present_hash)),
            "present account → real-hash upsert, never tombstoned",
        );
        assert_eq!(
            entry(id_of(&removed_hex)),
            Some(None),
            "id in deletes → tombstone (None)",
        );
        assert_eq!(
            entry(id_of(&notyet_hex)),
            Some(Some(hash_account_state(&AccountState::default()))),
            "absent but NOT in deletes → zero-state leaf (witness transient preserved)",
        );
    }

    #[test]
    fn apply_snapshot_delete_on_rocks_matches_fresh_over_survivors() {
        // F-5 V2 cross-store: the repair path deletes against the PERSISTED
        // RocksDB-backed tree, not the MemorySmtStore the elara-smt delete tests
        // use. Pin that delete(A) on a persisted tree (committed in a prior,
        // separate apply_snapshot) yields a root byte-identical to a fresh tree
        // over only the survivors, drops the value-key (get→None), and yields a
        // valid exclusion proof — i.e. a tombstone, not a hash(default) ghost.
        let a = acc(b"acct-A");
        let b = acc(b"acct-B");
        let ha = sha3_256(b"state-A");
        let hb = sha3_256(b"state-B");

        // Tree 1: commit {A,B}, then in a SEPARATE apply_snapshot delete A.
        let (s1, _d1) = test_storage();
        apply_snapshot(&s1, &[(a, Some(ha)), (b, Some(hb))]).unwrap();
        let (_n, root_after_delete) = apply_snapshot(&s1, &[(a, None)]).unwrap();

        // Tree 2: fresh store, insert only the survivor B.
        let (s2, _d2) = test_storage();
        let (_m, fresh_root) = apply_snapshot(&s2, &[(b, Some(hb))]).unwrap();

        assert_eq!(
            root_after_delete, fresh_root,
            "delete(A) on persisted rocks tree == fresh rocks tree over survivors",
        );

        let tree = AccountStateSMT::new(&s1);
        assert_eq!(tree.get(&a).unwrap(), None, "deleted leaf value-key dropped");
        assert!(tree.proof(&a).unwrap().is_none(), "no inclusion proof for deleted slot");
        let xp = tree
            .exclusion_proof(&a)
            .unwrap()
            .expect("exclusion proof for the deleted slot");
        assert_eq!(xp.root, root_after_delete, "exclusion proof anchors at the new root");
        assert!(verify_exclusion_proof(&xp), "exclusion proof for deleted slot must verify");
        // Survivor untouched and still provable.
        assert_eq!(tree.get(&b).unwrap(), Some(hb), "survivor leaf intact");
    }

    #[test]
    fn apply_snapshot_mixed_update_and_delete_one_atomic_root() {
        // The repair path hands apply_snapshot a mix of Some (changed accounts)
        // and None (removed). Pin the mixed batch lands one atomic, correct root.
        let a = acc(b"mix-A");
        let b = acc(b"mix-B");
        let c = acc(b"mix-C");
        let (s1, _d1) = test_storage();
        // Seed {A,B}; then in one snapshot update A, delete B, add C.
        apply_snapshot(&s1, &[(a, Some(sha3_256(b"a0"))), (b, Some(sha3_256(b"b0")))]).unwrap();
        let (_n, mixed_root) = apply_snapshot(
            &s1,
            &[(a, Some(sha3_256(b"a1"))), (b, None), (c, Some(sha3_256(b"c0")))],
        )
        .unwrap();
        // Equivalent fresh tree over the post-state {A=a1, C=c0}.
        let (s2, _d2) = test_storage();
        let (_m, fresh_root) =
            apply_snapshot(&s2, &[(a, Some(sha3_256(b"a1"))), (c, Some(sha3_256(b"c0")))]).unwrap();
        assert_eq!(mixed_root, fresh_root, "mixed update+delete batch == fresh over survivors");
    }

    #[test]
    fn concurrent_smt_handles_clobber_without_writer_gate() {
        // The mechanism behind NodeState::account_smt_write_gate (fusion-audited
        // 2026-07-05): commit() writes each handle's private cache with no
        // conflict detection, and every real write propagates to the shared
        // near-root keys — so two handles over one store, interleaved
        // buffer→commit, lose the first committer's update. This pins the
        // PRIMITIVE's lack of cross-handle protection (the reason every live
        // caller must hold the gate); it deliberately uses no gate.
        let a = acc(b"gate-A");
        let b = acc(b"gate-B");
        let orphan = acc(b"gate-ghost");
        let (storage, _dir) = test_storage();
        apply_snapshot(&storage, &[
            (a, Some(sha3_256(b"a0"))),
            (b, Some(sha3_256(b"b0"))),
            (orphan, Some(sha3_256(b"ghost"))),
        ]).unwrap();

        // Handle 1 (reconcile-shaped): buffer the orphan delete — its cache
        // now pins pre-flush near-root ancestors.
        let mut t1 = AccountStateSMT::new(&storage);
        t1.delete(&orphan).unwrap();

        // Handle 2 (flush-shaped): update B and commit first.
        let mut t2 = AccountStateSMT::new(&storage);
        t2.update(&b, &sha3_256(b"b1")).unwrap();
        t2.commit().unwrap();

        // Handle 1 commits its stale cache — clobbers t2's near-root nodes.
        t1.commit().unwrap();

        // Torn state: B's LEAF says b1 (t1 never touched it) while the
        // persisted ROOT reflects the b0 world t1 buffered against.
        let torn = AccountStateSMT::new(&storage);
        assert_eq!(
            torn.get(&b).unwrap(),
            Some(sha3_256(b"b1")),
            "B's leaf must carry t2's committed update"
        );
        let (clean, _d2) = test_storage();
        let (_n, clean_root) = apply_snapshot(&clean, &[
            (a, Some(sha3_256(b"a0"))),
            (b, Some(sha3_256(b"b1"))),
        ]).unwrap();
        assert_ne!(
            torn.root().unwrap(),
            clean_root,
            "unserialized interleave must tear (persisted root inconsistent \
             with persisted leaves). If this ever holds equal, the SMT gained \
             cross-handle conflict safety and the writer gate can be revisited."
        );
    }

    // ── F-5 one-time orphan reconcile (reconcile_orphan_leaves_to_ledger) ──

    /// Persist the live-account leaves + a set of orphan ghost leaves (ids absent
    /// from `accounts`, each a `hash_account_state(default)` ghost) into a fresh CF.
    fn seed_ledger_and_orphans(
        accounts: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
        orphans: &[String],
    ) -> (StorageEngine, tempfile::TempDir) {
        let (storage, dir) = test_storage();
        let ghost = hash_account_state(&crate::accounting::ledger::AccountState::default());
        let mut pairs: Vec<([u8; 32], Option<[u8; 32]>)> = accounts
            .iter()
            .map(|(id, a)| (decode_account_id(id).unwrap(), Some(hash_account_state(a))))
            .collect();
        for g in orphans {
            pairs.push((decode_account_id(g).unwrap(), Some(ghost)));
        }
        apply_snapshot(&storage, &pairs).unwrap();
        (storage, dir)
    }

    #[test]
    fn reconcile_orphan_leaves_tombstones_ghosts_and_converges() {
        use crate::accounting::ledger::AccountState;
        use std::collections::HashMap;

        let alice = hex::encode(acc(b"alice"));
        let bob = hex::encode(acc(b"bob"));
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(alice.clone(), AccountState { available: 100, tx_count: 2, ..Default::default() });
        accounts.insert(bob.clone(), AccountState { available: 50, ..Default::default() });

        // Three SMT-ahead ghosts with no live account (the authority-node F-5 shape).
        let ghosts = vec![
            hex::encode(acc(b"ghost-1")),
            hex::encode(acc(b"ghost-2")),
            hex::encode(acc(b"ghost-3")),
        ];
        let (storage, _dir) = seed_ledger_and_orphans(&accounts, &ghosts);

        // Pre-state: 3 orphans, persisted root ≠ the clean ledger root.
        let target = root_over_accounts(&accounts).unwrap();
        let pre = AccountStateSMT::new(&storage).root().unwrap();
        assert_ne!(pre, target, "persisted root carries the ghosts (≠ clean root)");
        let scan_before = scan_orphan_smt_leaves(&storage, &accounts.keys().cloned().collect(), 1_000_000, 64);
        assert_eq!(scan_before.orphan_count, 3);

        let out = reconcile_orphan_leaves_to_ledger(&storage, &accounts, 1_000_000, 10_000).unwrap();
        assert!(out.committed, "gate passes: ghosts fully explain the divergence");
        assert_eq!(out.deleted, 3);
        assert_eq!(out.post_root, hex::encode(target), "converged to root_over_accounts");
        assert_eq!(out.target_root, hex::encode(target));
        assert_eq!(out.tombstoned.len(), 3);

        // Post-state: persisted root == clean root, zero orphans remain.
        assert_eq!(AccountStateSMT::new(&storage).root().unwrap(), target);
        let scan_after = scan_orphan_smt_leaves(&storage, &accounts.keys().cloned().collect(), 1_000_000, 64);
        assert_eq!(scan_after.orphan_count, 0, "no ghost survives the reconcile");

        // Each removed slot yields a valid exclusion proof; live accounts intact.
        let tree = AccountStateSMT::new(&storage);
        for g in &ghosts {
            let id = decode_account_id(g).unwrap();
            assert_eq!(tree.get(&id).unwrap(), None, "ghost value-key dropped");
            let xp = tree.exclusion_proof(&id).unwrap().expect("exclusion proof for cleaned slot");
            assert!(verify_exclusion_proof(&xp), "cleaned slot proves absence");
        }
        assert_eq!(
            tree.get(&decode_account_id(&alice).unwrap()).unwrap(),
            Some(hash_account_state(accounts.get(&alice).unwrap())),
            "live account leaf untouched",
        );
    }

    #[test]
    fn reconcile_orphan_leaves_refuses_when_a_live_leaf_is_also_stale() {
        // The gate's no-over-delete / no-wrong-commit property: if the divergence
        // is NOT fully explained by orphans (a live leaf is also stale), the
        // post-delete root ≠ root_over_accounts, so it must commit NOTHING.
        use crate::accounting::ledger::AccountState;
        use std::collections::HashMap;

        let alice = hex::encode(acc(b"alice"));
        let bob = hex::encode(acc(b"bob"));
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(alice.clone(), AccountState { available: 100, ..Default::default() });
        accounts.insert(bob.clone(), AccountState { available: 50, ..Default::default() });

        // Seed alice correctly, bob STALE (wrong leaf value), plus one orphan.
        let (storage, _dir) = test_storage();
        let ghost = hex::encode(acc(b"ghost-x"));
        apply_snapshot(
            &storage,
            &[
                (decode_account_id(&alice).unwrap(), Some(hash_account_state(accounts.get(&alice).unwrap()))),
                (decode_account_id(&bob).unwrap(), Some(sha3_256(b"stale-bob-leaf"))),
                (decode_account_id(&ghost).unwrap(), Some(hash_account_state(&AccountState::default()))),
            ],
        )
        .unwrap();
        let root_before = AccountStateSMT::new(&storage).root().unwrap();

        let out = reconcile_orphan_leaves_to_ledger(&storage, &accounts, 1_000_000, 10_000).unwrap();
        assert!(!out.committed, "must not commit when orphans don't fully explain the divergence");
        assert_eq!(out.deleted, 0);
        assert!(out.aborted_reason.unwrap().contains("does not exactly explain"));

        // CF is byte-for-byte untouched: the orphan still present, root unchanged.
        assert_eq!(AccountStateSMT::new(&storage).root().unwrap(), root_before, "CF untouched on abort");
        let scan = scan_orphan_smt_leaves(&storage, &accounts.keys().cloned().collect(), 1_000_000, 64);
        assert_eq!(scan.orphan_count, 1, "orphan NOT deleted on a refused reconcile");
    }

    #[test]
    fn reconcile_orphan_leaves_noop_when_clean() {
        use crate::accounting::ledger::AccountState;
        use std::collections::HashMap;

        let alice = hex::encode(acc(b"alice"));
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(alice.clone(), AccountState { available: 7, ..Default::default() });
        let (storage, _dir) = seed_ledger_and_orphans(&accounts, &[]);

        let out = reconcile_orphan_leaves_to_ledger(&storage, &accounts, 1_000_000, 10_000).unwrap();
        assert!(!out.committed);
        assert_eq!(out.deleted, 0);
        assert!(out.aborted_reason.unwrap().contains("no orphan leaves"));
    }

    #[test]
    fn reconcile_orphan_leaves_refuses_above_max_delete() {
        use crate::accounting::ledger::AccountState;
        use std::collections::HashMap;

        let alice = hex::encode(acc(b"alice"));
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(alice.clone(), AccountState { available: 1, ..Default::default() });
        let ghosts = vec![
            hex::encode(acc(b"g1")),
            hex::encode(acc(b"g2")),
            hex::encode(acc(b"g3")),
        ];
        let (storage, _dir) = seed_ledger_and_orphans(&accounts, &ghosts);

        // Cap below the orphan count → operator escalation, no mutation.
        let out = reconcile_orphan_leaves_to_ledger(&storage, &accounts, 1_000_000, 2).unwrap();
        assert!(!out.committed);
        assert_eq!(out.deleted, 0);
        assert!(out.aborted_reason.unwrap().contains("exceeds max_delete"));
        let scan = scan_orphan_smt_leaves(&storage, &accounts.keys().cloned().collect(), 1_000_000, 64);
        assert_eq!(scan.orphan_count, 3, "orphans untouched when over the cap");
    }

    #[test]
    fn deterministic_root_across_engines() {
        let (s1, _d1) = test_storage();
        let (s2, _d2) = test_storage();
        let mut t1 = AccountStateSMT::new(&s1);
        let mut t2 = AccountStateSMT::new(&s2);
        // Insert the same accounts in different orders.
        let a = acc(b"alice");
        let b = acc(b"bob");
        let c = acc(b"carol");
        t1.update(&a, &sha3_256(b"1")).unwrap();
        t1.update(&b, &sha3_256(b"2")).unwrap();
        t1.update(&c, &sha3_256(b"3")).unwrap();
        t2.update(&c, &sha3_256(b"3")).unwrap();
        t2.update(&a, &sha3_256(b"1")).unwrap();
        t2.update(&b, &sha3_256(b"2")).unwrap();
        assert_eq!(t1.root().unwrap(), t2.root().unwrap(),
            "key-addressed SMT is order-independent");
    }

    // ─── Stage 2E soak: 10K rec/s sustained ingest, <300 MB RSS ────────────
    //
    // Gated `#[ignore]` so a default `cargo test` run stays fast. Invoke via:
    //   cargo test --features node --lib --release -- --ignored smt_soak
    //
    // The target ("4GB node sustaining 10K records/sec ingest without swap,
    // <300 MB RSS") is a node-level claim. The dominant cost on the ingest
    // hot path that Stage 2 introduces is the per-tx account touch plus the
    // batched flush. We simulate that here in isolation: ~2 account touches
    // per logical "record" (sender + recipient), epoch flushes every 1s, and
    // a churn window that keeps the working set bounded (the opposite of an
    // unbounded-growth microbenchmark — hot set is what RSS tracks).

    /// Read `VmRSS` from /proc/self/status. Returns bytes, or `None` on
    /// non-linux or parse failure.
    #[cfg(target_os = "linux")]
    fn read_rss_bytes() -> Option<u64> {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let num: u64 = rest
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()?;
                // VmRSS is reported in kB.
                return Some(num * 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    fn read_rss_bytes() -> Option<u64> { None }

    #[test]
    #[ignore]
    fn smt_soak_10k_records_per_sec_under_300mb_rss() {
        use crate::accounting::ledger::{AccountState, LedgerState};
        use std::time::{Duration, Instant};

        // Knobs — scaled so the test runs in ~5s wall time but measures
        // sustained throughput, not a single burst.
        const TARGET_RECORDS_PER_SEC: u64 = 10_000;
        const SOAK_DURATION_SECS: u64 = 5;
        const FLUSH_INTERVAL_MS: u64 = 1_000;
        const ACCOUNT_POOL: u64 = 50_000; // working-set bound
        const RSS_CEILING_BYTES: u64 = 300 * 1024 * 1024;

        let (storage, _dir) = test_storage();
        let mut ledger = LedgerState::new();

        // Pre-seed ACCOUNT_POOL accounts so the tree is already populated
        // and we measure in-place updates (steady state), not cold inserts.
        for i in 0..ACCOUNT_POOL {
            let hex_id = hex::encode(sha3_256(&i.to_be_bytes()));
            ledger.accounts.insert(
                hex_id.clone(),
                AccountState { available: 1_000, tx_count: 0, ..Default::default() },
            );
            ledger.smt_dirty.insert(hex_id);
        }
        flush_dirty(&storage, &mut ledger).unwrap();

        let rss_at_start = read_rss_bytes().unwrap_or(0);

        let soak_start = Instant::now();
        let deadline = soak_start + Duration::from_secs(SOAK_DURATION_SECS);
        let mut next_flush = soak_start + Duration::from_millis(FLUSH_INTERVAL_MS);
        let mut total_records: u64 = 0;
        let mut total_flushed: u64 = 0;
        let mut peak_rss: u64 = rss_at_start;
        let mut cursor: u64 = 0;

        while Instant::now() < deadline {
            // Simulate 1ms worth of records: TARGET_RECORDS_PER_SEC / 1000.
            let burst = TARGET_RECORDS_PER_SEC / 1_000;
            for _ in 0..burst {
                // Each "record" touches two accounts (sender + recipient).
                let sender = cursor % ACCOUNT_POOL;
                let recipient = (cursor + 1) % ACCOUNT_POOL;
                let s_hex = hex::encode(sha3_256(&sender.to_be_bytes()));
                let r_hex = hex::encode(sha3_256(&recipient.to_be_bytes()));
                {
                    let a = ledger.accounts.get_mut(&s_hex).unwrap();
                    a.tx_count += 1;
                    a.available = a.available.saturating_sub(1);
                }
                {
                    let a = ledger.accounts.get_mut(&r_hex).unwrap();
                    a.tx_count += 1;
                    a.available += 1;
                }
                ledger.smt_dirty.insert(s_hex);
                ledger.smt_dirty.insert(r_hex);
                cursor += 1;
                total_records += 1;
            }

            if Instant::now() >= next_flush {
                let (flushed, _root) = flush_dirty(&storage, &mut ledger).unwrap();
                total_flushed += flushed as u64;
                if let Some(rss) = read_rss_bytes() {
                    if rss > peak_rss { peak_rss = rss; }
                }
                next_flush += Duration::from_millis(FLUSH_INTERVAL_MS);
            }
        }

        // Final flush so the last dirty set is accounted for.
        let (flushed, _root) = flush_dirty(&storage, &mut ledger).unwrap();
        total_flushed += flushed as u64;
        if let Some(rss) = read_rss_bytes() {
            if rss > peak_rss { peak_rss = rss; }
        }

        let elapsed = soak_start.elapsed();
        let records_per_sec = total_records as f64 / elapsed.as_secs_f64();

        eprintln!(
            "SMT soak:\n  elapsed: {:.3}s\n  records: {}\n  rec/s: {:.0}\n  flushed: {}\n  RSS start: {:.1} MB\n  RSS peak:  {:.1} MB",
            elapsed.as_secs_f64(),
            total_records,
            records_per_sec,
            total_flushed,
            rss_at_start as f64 / 1_048_576.0,
            peak_rss as f64 / 1_048_576.0,
        );

        // Throughput assertion — must sustain 10K rec/s (allow 10% slack for
        // CI jitter; anything lower is a real regression).
        assert!(
            records_per_sec >= TARGET_RECORDS_PER_SEC as f64 * 0.9,
            "throughput regression: {:.0} rec/s < target {}",
            records_per_sec, TARGET_RECORDS_PER_SEC,
        );

        // RSS ceiling — only enforce on linux where the read succeeded.
        if peak_rss > 0 {
            assert!(
                peak_rss < RSS_CEILING_BYTES,
                "RSS ceiling exceeded: peak {:.1} MB >= cap {:.1} MB",
                peak_rss as f64 / 1_048_576.0,
                RSS_CEILING_BYTES as f64 / 1_048_576.0,
            );
        }
    }

    // ─── B13: cache-cold (disk-resident) SMT proof-gen seek cost ───────────
    //
    // `bench_account_smt::bench_smt_proof_generation` (criterion) measures proof
    // generation with a WARM cache: the SST blocks were just written by the same
    // process, so RocksDB's block cache + the OS page cache serve every sibling
    // read at memory speed. At mainnet scale (10M+ accounts) the SMT does NOT fit
    // in RAM — each proof pays real device-seek latency per cold sibling block.
    // Criterion's many-warm-iterations model cannot measure that (a per-iteration
    // cache drop would be dominated by the RocksDB reopen). This characterization
    // quantifies the warm-vs-cold gap so scale claims cite a MEASURED ratio, not
    // an unqualified design target (the internal roadmap B13 + honest-claims).
    //
    // Method: populate N accounts → compact to SST → drop the engine (a clean
    // RocksDB close flushes memtables to SST, so the reopen starts empty-memtable
    // with all data on disk) → evict the OS page cache for the data dir
    // (`posix_fadvise(POSIX_FADV_DONTNEED)`, best-effort, clean pages only — we
    // `sync()` first) → reopen (cold block cache) → time the SAME proof set warm
    // then cold. Index/filter blocks are re-read at open (realistic: a live node
    // keeps those warm); the cold number is dominated by DATA-block seeks, which
    // is the scale-relevant cost. CHARACTERIZATION, not a regression gate — the
    // timings are box/FS-specific; only proof correctness under a cold reopen is
    // asserted. Invoke (override scale via env):
    //   ELARA_SMT_COLD_N=2000000 ELARA_SMT_COLD_PROOFS=5000 \
    //     cargo test --features node --lib --release -- --ignored smt_cold_seek

    /// Best-effort eviction of the OS page cache for every file under `dir`.
    /// `POSIX_FADV_DONTNEED` only drops CLEAN pages, so we `sync()` first (the
    /// engine was already dropped, so its SSTs are durable). Returns the count of
    /// files successfully advised — purely informational.
    #[cfg(target_os = "linux")]
    fn evict_os_page_cache(dir: &std::path::Path) -> usize {
        use std::os::unix::io::AsRawFd;
        // Flush dirty pages to disk so DONTNEED can actually reclaim them.
        unsafe { libc::sync() };
        fn walk(dir: &std::path::Path, evicted: &mut usize) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, evicted);
                } else if let Ok(f) = std::fs::File::open(&p) {
                    // (fd, offset=0, len=0) → advise the whole file.
                    let rc = unsafe {
                        libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED)
                    };
                    if rc == 0 {
                        *evicted += 1;
                    }
                }
            }
        }
        let mut evicted = 0;
        walk(dir, &mut evicted);
        evicted
    }

    /// Total bytes of every file under `dir` (the on-disk SST + metadata size).
    #[cfg(target_os = "linux")]
    fn dir_total_bytes(dir: &std::path::Path) -> u64 {
        let mut total = 0;
        let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += dir_total_bytes(&p);
            } else if let Ok(m) = entry.metadata() {
                total += m.len();
            }
        }
        total
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn smt_cold_seek_cost_characterization() {
        use crate::accounting::ledger::AccountState;
        use std::time::Instant;

        let n: u64 = std::env::var("ELARA_SMT_COLD_N")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(200_000);
        let m: u64 = std::env::var("ELARA_SMT_COLD_PROOFS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000)
            .clamp(1, n.max(1));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        // 1. Populate N accounts, commit, compact to SST. The clean drop at the
        //    end of this scope flushes the memtable, so the reopen reads disk.
        {
            let storage = StorageEngine::open(&path).unwrap();
            let mut tree = AccountStateSMT::new(&storage);
            for i in 0..n {
                let st = AccountState { available: i, tx_count: 1, ..Default::default() };
                tree.update(&acc(&i.to_be_bytes()), &hash_account_state(&st)).unwrap();
            }
            tree.commit().unwrap();
            storage.compact_cf(CF_ACCOUNT_SMT);
        }

        // Evenly-spaced target keys across the populated range.
        let step = (n / m).max(1);
        let targets: Vec<[u8; 32]> =
            (0..m).map(|j| acc(&((j * step) % n).to_be_bytes())).collect();

        let on_disk = dir_total_bytes(&path);

        // 2. WARM baseline — reopen, prime every target once, then time them warm.
        let warm_ns_per: u128 = {
            let storage = StorageEngine::open(&path).unwrap();
            let tree = AccountStateSMT::new(&storage);
            for t in &targets {
                let _ = tree.proof(t).unwrap();
            }
            let start = Instant::now();
            for t in &targets {
                let _ = tree.proof(t).unwrap();
            }
            start.elapsed().as_nanos() / m as u128
        };

        // 3. COLD — evict the page cache, reopen (cold block cache), time the
        //    SAME set, and verify every cold proof against the reopened root.
        let evicted = evict_os_page_cache(&path);
        let mut cold_ok: u64 = 0;
        let mut all_verify = true;
        let cold_ns_per: u128 = {
            let storage = StorageEngine::open(&path).unwrap();
            let tree = AccountStateSMT::new(&storage);
            let start = Instant::now();
            for t in &targets {
                let p = tree.proof(t).unwrap().expect("proof for a populated key");
                if !verify_proof(&p) {
                    all_verify = false;
                }
                cold_ok += 1;
            }
            start.elapsed().as_nanos() / m as u128
        };

        let ratio = cold_ns_per as f64 / warm_ns_per.max(1) as f64;
        eprintln!(
            "SMT cold-seek characterization (NOT a regression gate — box/FS-specific):\n  \
             accounts (N):       {n}\n  \
             proofs timed (M):   {m}\n  \
             on-disk SST+meta:   {:.1} MB\n  \
             page-cache evicted: {evicted} files\n  \
             warm proof-gen:     {warm_ns_per} ns/proof  ({:.0} proofs/s)\n  \
             cold proof-gen:     {cold_ns_per} ns/proof  ({:.0} proofs/s)\n  \
             cold/warm ratio:    {ratio:.2}x  (the disk-resident scale penalty)",
            on_disk as f64 / 1_048_576.0,
            1e9 / warm_ns_per.max(1) as f64,
            1e9 / cold_ns_per.max(1) as f64,
        );

        // The only hard assertion is correctness under a cold reopen — the
        // timings are data, not a threshold. Every populated key must yield a
        // proof that verifies against the freshly-reopened root.
        assert_eq!(cold_ok, m, "every populated key must yield a cold proof");
        assert!(all_verify, "every cold-cache proof must verify against the reopened root");
    }


    #[test]
    fn smt_root_and_proof_exact_hex_pins() {
        // CONSENSUS-RELEVANT EXACT PINS. The account-state SMT root is bound
        // into the snapshot v5 checksum and signed into epoch seals, so the
        // whole fleet must compute byte-identical roots. These exact-hex
        // vectors lock the root-fold and proof-gen so the `elara-smt` crate —
        // or any future refactor — cannot silently shift the root the network
        // agrees on. RE-BAKED 2026-06-16 for the consensus-root change to the
        // 256-bit / identity-bound / domain-separated / compressed construction
        // (intentional one-time divergence from the old 64-bit roots). After
        // this, if the test fails the wire/hash behaviour changed; do not
        // re-bake to match — find what diverged. These MUST match the
        // crate-side pins in elara-smt::tests::root_hex_pins_match_node (a store
        // is just a KV map, so RocksDB and memory agree byte-for-byte).
        let (storage, _dir) = test_storage();
        let mut tree = AccountStateSMT::new(&storage);

        // Empty tree → SHA3-256("") sentinel.
        assert_eq!(
            hex::encode(tree.root().unwrap()),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        );

        // One account.
        tree.update(&acc(b"alice"), &sha3_256(b"balance=100")).unwrap();
        assert_eq!(
            hex::encode(tree.root().unwrap()),
            "95329e81b5c68a435cd984e67b3e5d4129c085bd41cb63b2315138b8eb9bfb16",
        );

        // Three accounts. Key-addressed, so root is insertion-order independent
        // (covered by deterministic_root_across_engines); this pins the value.
        tree.update(&acc(b"bob"), &sha3_256(b"balance=200")).unwrap();
        tree.update(&acc(b"carol"), &sha3_256(b"balance=300")).unwrap();
        assert_eq!(
            hex::encode(tree.root().unwrap()),
            "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba",
        );

        // Pin bob's proof: leaf value, root, and the compressed-proof invariants
        // (popcount == sibling count, far fewer than MAX_DEPTH). Locks that the
        // proof generator and verify_proof fold back to the pinned root.
        let p = tree.proof(&acc(b"bob")).unwrap().expect("bob present");
        assert_eq!(p.state_hash, sha3_256(b"balance=200"));
        assert_eq!(
            hex::encode(p.root),
            "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba",
        );
        // Compressed: bob co-resident with alice/carol → a few non-empty siblings.
        let popcount: u32 = p.present.iter().map(|b| b.count_ones()).sum();
        assert_eq!(popcount as usize, p.siblings.len());
        assert!(!p.siblings.is_empty() && p.siblings.len() < (MAX_DEPTH as usize));
        assert!(verify_proof(&p), "pinned proof must verify against pinned root");

        // Exclusion proof for an absent account folds to the same signed root.
        let xp = tree.exclusion_proof(&acc(b"absent")).unwrap().expect("absent");
        assert_eq!(
            hex::encode(xp.root),
            "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba",
        );
        assert!(verify_exclusion_proof(&xp), "exclusion proof must verify");
    }
}
