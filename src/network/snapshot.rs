//! Node snapshot — JSON checkpoint for fast node startup.
//!
//! Persists ledger state, finalized record set, and epoch sealing state.
//! On startup, if a snapshot exists, state is restored from it.
//!
//! Backward compatible: old snapshots containing only `LedgerState` are
//! transparently loaded (finalized set + epoch state start empty).

//!
//! Spec references:
//!   @spec Protocol §12.2

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use tracing::info;

use crate::errors::{ElaraError, Result};
use crate::accounting::bootstrap::BootstrapState;
use crate::accounting::genesis::GenesisState;
use crate::accounting::ledger::LedgerState;
use super::epoch::{EpochState, EpochStateSnapshot};

/// Default cadence for `archive_snapshot_loop` — emit one signed JSON snapshot
/// every N epochs on archival nodes. At the protocol's default 120s epoch
/// cadence this is one snapshot every ~20 minutes per zone, matching the Gap-7
/// design budget (internal design notes §PRODUCTION PATH gap 7). Pinned as a `pub
/// const` so the `Config` field default and the operator-facing spec wording
/// share a single source of truth — a future config-schema refactor that
/// silently changed the integer literal would surface as a test-diff in
/// `default_archive_snapshot_every_n_epochs_constant_pins_to_documented_value`.
pub const ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT: u64 = 10;

// Compile-time invariant: a value of 0 here would disable the archival
// snapshot loop entirely (see `bin/elara_node.rs:3885` warning log), so
// light clients would onboard from an increasingly stale snapshot —
// silent and slow failure. Surface that as a build error, not a runtime
// test failure.
const _: () = assert!(
    ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT > 0,
    "ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT must be > 0 — 0 disables the archival snapshot loop entirely (see bin/elara_node.rs:3885 warning log)"
);

/// Compute a deterministic checksum of snapshot data.
///
/// Uses JSON serialization of sorted collections (not `{:?}` Debug format)
/// to ensure stability across Rust versions and binary rebuilds.
///
/// v3 format: switched from Debug to JSON after checksum mismatches on every
/// restart due to `{:?}` producing subtly different output across recompilations.
///
/// v4 format (2026-04-28): drops `zone_activity_rate` from the hash input. It
/// was the only f64-valued field in the checksum, and serde_json's f64 parse
/// path is not always inverse to ryu's f64 serialize path: the writer hashes
/// `ryu(X) = "0.11168954035834365"`, the reader parses that back to `Y` and
/// re-serializes via ryu to `"0.11168954035834364"` (off by 1 ulp), giving a
/// different hash for the *same* state on disk. Confirmed root cause of
/// "snapshot checksum mismatch" warnings on testnet nodes per restart
/// batch. Beyond the bit-exactness
/// issue, `zone_activity_rate` is a transient per-node EMA observation that
/// is not load-bearing for state correctness — two synced nodes can legitimately
/// have slightly different rate values without the chain being divergent.
/// Excluding it keeps the checksum focused on consensus-determined state
/// (supply, staked, accounts cardinality, finalized set, epoch heights, seal
/// IDs/hashes, VRF outputs, governance counts).
///
/// One-time v3→v4 mismatch on this deploy: existing v3 snapshots are renamed
/// `.json.corrupt` and the boot path falls back to RocksDB CF_METADATA
/// rehydration (572187a) — no data loss.
///
/// v5 format (Gap 7 slice 7.3, 2026-04-30): folds the
/// `EpochStateSnapshot::latest_sealed_account` Gap-1 binding into the checksum
/// so a malicious archive node serving `/snapshot/latest` cannot swap the
/// `(epoch, zone, record_id, account_smt_root)` tuple under a still-valid
/// signature. Excludes the `sealed_at` f64 timestamp from the hash for the
/// same reason `zone_activity_rate` was dropped in v4 — ryu↔serde_json round-
/// trip is not bit-exact for f64 — so the binding's load-bearing fields are
/// covered while the timestamp stays purely informational. One-time v4→v5
/// mismatch on this deploy follows the same `.json.corrupt` rename + RocksDB
/// rebuild fallback as v3→v4.
fn compute_checksum(snapshot: &NodeSnapshot) -> String {
    let finalized_sorted: BTreeSet<&String> = snapshot.finalized.iter().collect();

    // Sort epoch HashMaps into BTreeMaps for deterministic JSON serialization.
    let epoch_json = if let Some(ref ep) = snapshot.epoch {
        let epochs: BTreeMap<_, _> = ep.latest_epoch.iter().collect();
        let seals: BTreeMap<_, _> = ep.latest_seal_id.iter().collect();
        let hashes: BTreeMap<_, _> = ep.latest_seal_hash.iter().collect();
        let vrfs: BTreeMap<_, _> = ep.latest_vrf_output.iter().collect();
        // Slice 7.3: 4-tuple of (epoch, zone, record_id, root_hex) — sealed_at
        // f64 deliberately excluded (see rustdoc: ryu↔serde_json 1-ulp risk).
        // None binding hashes as `"null"` so pre-Gap-1 chains have a stable
        // checksum independent of when the first Gap-1 seal lands.
        let sealed_account = ep
            .latest_sealed_account
            .as_ref()
            .map(|(epoch_number, zone, record_id, root_hex, _sealed_at)| {
                format!(
                    "{}|{}|{}|{}",
                    epoch_number,
                    zone.path(),
                    record_id,
                    root_hex,
                )
            })
            .unwrap_or_else(|| "null".to_string());
        // serde_json on BTreeMap produces keys in sorted order — deterministic.
        // zone_activity_rate intentionally excluded — see rustdoc above.
        format!("{},{},{},{},sealed_account={}",
            serde_json::to_string(&epochs).unwrap_or_default(),
            serde_json::to_string(&seals).unwrap_or_default(),
            serde_json::to_string(&hashes).unwrap_or_default(),
            serde_json::to_string(&vrfs).unwrap_or_default(),
            sealed_account,
        )
    } else {
        "null".to_string()
    };

    let mut data = format!(
        "v5:supply={},staked={},accounts={},finalized={},epoch={},proposals={},delegations={}",
        snapshot.ledger.total_supply,
        snapshot.ledger.total_staked,
        snapshot.ledger.accounts.len(),
        serde_json::to_string(&finalized_sorted).unwrap_or_default(),
        epoch_json,
        snapshot.ledger.governance.proposals.len(),
        snapshot.ledger.governance.delegations.len(),
    );
    // Gap 7 post-apply SMT-root verify (additive, back-compat). Older
    // snapshots without `account_state_root` (the field is Optional with
    // serde default = None) compute the bare v5 checksum exactly as before,
    // so signature verification on legacy peers keeps working. New snapshots
    // that *do* populate the field bind it under the Dilithium3 signature: a
    // MITM that strips the field changes the verifier's computed checksum
    // (None → no suffix), breaking sig verify; a MITM that flips the hex
    // value also breaks sig verify. The field is therefore both
    // wire-tamper-resistant and back-compat.
    if let Some(ref root_hex) = snapshot.account_state_root {
        data.push_str(&format!("|account_state_root={}", root_hex));
    }
    // C4 slice 1: bind the carried mandate/revocation registries by CONTENT
    // (sha3 over their deterministic BTreeMap serialization), not by count — a
    // count-only bind would let a trusted-but-buggy archive ship a different
    // mandate set of the same cardinality under a valid signature. Conditional
    // (only when non-empty) so a legacy / pre-mandate snapshot reproduces the
    // identical checksum and still verifies — exactly the account_state_root
    // back-compat pattern above.
    if !snapshot.mandates.is_empty() {
        let h = crate::crypto::hash::sha3_256_hex(
            serde_json::to_string(&snapshot.mandates).unwrap_or_default().as_bytes(),
        );
        data.push_str(&format!("|mandates_root={h}"));
    }
    if !snapshot.revocations.is_empty() {
        let h = crate::crypto::hash::sha3_256_hex(
            serde_json::to_string(&snapshot.revocations).unwrap_or_default().as_bytes(),
        );
        data.push_str(&format!("|revocations_root={h}"));
    }
    // Emergency circuit-breaker state — conditional bind (only a non-default state)
    // so a pre-feature snapshot reproduces the identical checksum, and a
    // trusted-but-tampered snapshot cannot strip an active halt from a bootstrapping
    // joiner under a valid signature.
    if let Some(es) = &snapshot.emergency {
        if *es != crate::emergency::EmergencyState::default() {
            let h = crate::crypto::hash::sha3_256_hex(
                serde_json::to_string(es).unwrap_or_default().as_bytes(),
            );
            data.push_str(&format!("|emergency_root={h}"));
        }
    }
    // SNAP-1 (2026-07-03 audit): genesis_state and bootstrap_state are installed
    // wholesale on bootstrap (`apply_bootstrap_snapshot_full` in sync.rs) but were
    // NOT bound into the checksum, so a trusted-but-tampered/buggy snapshot could
    // swap pool balances / `bootstrap_claimed` (the G3 sybil gate) / the reward
    // phase-multiplier under a still-valid Dilithium3 signature. Bind them by
    // CONTENT, conditionally (only when present) so a ledger-only / pre-feature
    // snapshot reproduces the identical checksum — the same back-compat pattern
    // as account_state_root/mandates/emergency above.
    if let Some(gs) = &snapshot.genesis_state {
        // Deterministic digest — GenesisState holds HashMaps/HashSet whose
        // iteration order is not stable, so a raw serde_json would make the
        // checksum non-reproducible across sign/verify and across the wire.
        // Sort every collection by a stable key before hashing.
        let mut pb: Vec<(String, u64)> = gs
            .pool_balances
            .iter()
            .map(|(k, v)| (format!("{k:?}"), *v))
            .collect();
        pb.sort();
        let mut pd: Vec<(String, u64)> = gs
            .pool_distributed
            .iter()
            .map(|(k, v)| (format!("{k:?}"), *v))
            .collect();
        pd.sort();
        let mut claimed: Vec<&String> = gs.bootstrap_claimed.iter().collect();
        claimed.sort();
        let canon = format!("pb={pb:?}|pd={pd:?}|claimed={claimed:?}");
        let h = crate::crypto::hash::sha3_256_hex(canon.as_bytes());
        data.push_str(&format!("|genesis_state_root={h}"));
    }
    if let Some(bs) = &snapshot.bootstrap_state {
        let h = crate::crypto::hash::sha3_256_hex(
            serde_json::to_string(bs).unwrap_or_default().as_bytes(),
        );
        data.push_str(&format!("|bootstrap_state_root={h}"));
    }
    hex::encode(crate::crypto::hash::sha3_256(data.as_bytes()))
}

/// Full node snapshot — ledger + finalized records + epoch state + genesis/bootstrap.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshot {
    /// Ledger state (accounts, balances, stakes).
    pub ledger: LedgerState,
    /// Record IDs that reached consensus finality.
    #[serde(default)]
    pub finalized: HashSet<String>,
    /// Epoch sealing state per zone.
    #[serde(default)]
    pub epoch: Option<EpochStateSnapshot>,
    /// SHA3-256 checksum of the serialized data (set during save, verified on load).
    #[serde(default)]
    pub checksum: Option<String>,
    /// Genesis allocation state (pool balances, vesting, distributions).
    #[serde(default)]
    pub genesis_state: Option<GenesisState>,
    /// Bootstrap phase detection state (phase transitions, multiplier).
    #[serde(default)]
    pub bootstrap_state: Option<BootstrapState>,
    /// Merkle root of all records at snapshot time (for cross-node verification).
    #[serde(default)]
    pub merkle_root: Option<String>,
    /// Total record count at snapshot time.
    #[serde(default)]
    pub record_count: Option<u64>,
    /// Timestamp when snapshot was created.
    #[serde(default)]
    pub snapshot_timestamp: Option<f64>,
    /// Identity hash of the node that created this snapshot.
    #[serde(default)]
    pub signer_identity: Option<String>,
    /// Signer's Dilithium3 public key (hex). Required for signature verification.
    /// SHA3-256 of these bytes MUST equal `signer_identity`.
    #[serde(default)]
    pub signer_public_key: Option<String>,
    /// Signer's SPHINCS+ public key (hex). Required when `sphincs_signature` is present.
    #[serde(default)]
    pub signer_sphincs_public_key: Option<String>,
    /// Dilithium3 signature over the checksum (proves snapshot authenticity).
    #[serde(default)]
    pub signature: Option<String>,
    /// SPHINCS+ signature (dual-sig for Profile A nodes).
    #[serde(default)]
    pub sphincs_signature: Option<String>,
    /// Protocol version of the node that created this snapshot.
    /// Used by `enforce_snapshot_protocol_version` to reject snapshots
    /// from nodes running protocol versions older than the local minimum.
    /// Tier 1.3 (Old Node Contamination): None on legacy snapshots
    /// (treated as version 0); always populated by current code.
    #[serde(default)]
    pub protocol_version: Option<u32>,
    /// Gap 7: producer-side AccountStateSMT
    /// root at snapshot-creation time (hex-encoded). Lets the bootstrap
    /// consumer cross-check that its reconstructed SMT after applying the
    /// loaded ledger matches the producer's view — catches local-apply bugs,
    /// version skew, and on-wire mutation that didn't trip the
    /// Dilithium3 verify (e.g., bit flip inside `checksum`-covered bytes
    /// followed by a forged checksum — defeated by the trust gate on the
    /// signer side, but verify is the deep-integrity layer).
    ///
    /// Optional for back-compat with legacy snapshots (treated as
    /// "no verify available"); consumer side skips the check when None.
    #[serde(default)]
    pub account_state_root: Option<String>,
    /// Agent-mandate registry carried for bootstrap (C4 slice 1). A
    /// snapshot-bootstrapped follower does NOT replay pre-baseline records, so
    /// without this it would flag `NoChain` for a mandate issued before its
    /// baseline where an archive flags `Valid`. Keyed by `mandate_id`; values are
    /// canonicalized. `#[serde(default)]` → legacy snapshots load as empty and
    /// reproduce the identical (pre-mandate) checksum. DERIVED act-flag index is
    /// NOT carried (recomputable from these two maps).
    #[serde(default)]
    pub mandates: BTreeMap<String, crate::mandate::MandateRecord>,
    /// Revocation index carried for bootstrap (C4 slice 1). Keyed by the 128-hex
    /// `mandate_id ++ revoker` composite (matches `CF_REVOCATION`).
    #[serde(default)]
    pub revocations: BTreeMap<String, crate::mandate::RevocationEntry>,
    /// EmergencyHalt circuit-breaker state carried for bootstrap (B1). Without it a
    /// snapshot-bootstrapped node comes up un-halted while replay nodes are frozen
    /// (split-brain). `#[serde(default)]` → legacy snapshots load as `None`
    /// (un-halted) and reproduce the identical pre-feature checksum.
    #[serde(default)]
    pub emergency: Option<crate::emergency::EmergencyState>,
}

/// Signed snapshot metadata — lightweight version for `GET /snapshot/latest`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMetadata {
    pub merkle_root: String,
    pub record_count: u64,
    pub snapshot_timestamp: f64,
    pub signer_identity: String,
    pub checksum: String,
    pub accounts: usize,
    pub total_supply: u64,
    pub total_staked: u64,
}

impl NodeSnapshot {
    pub fn new(ledger: LedgerState, finalized: HashSet<String>, epoch: EpochState) -> Self {
        Self {
            ledger,
            finalized,
            epoch: Some(epoch.to_snapshot()),
            checksum: None,
            genesis_state: None,
            bootstrap_state: None,
            merkle_root: None,
            record_count: None,
            snapshot_timestamp: None,
            signer_identity: None,
            signer_public_key: None,
            signer_sphincs_public_key: None,
            account_state_root: None,
            signature: None,
            sphincs_signature: None,
            protocol_version: Some(crate::network::config::PROTOCOL_VERSION),
            mandates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            emergency: None,
        }
    }

    /// Extract the epoch state, falling back to empty if not present.
    pub fn epoch_state(&self) -> EpochState {
        self.epoch.as_ref()
            .map(EpochState::from_snapshot)
            .unwrap_or_default()
    }
}

/// Save the full node snapshot to a JSON file.
///
/// The checksum is computed over the snapshot data (with checksum field
/// set to None), then embedded in the final output.
pub fn save_snapshot(
    ledger: &LedgerState,
    finalized: &HashSet<String>,
    epoch: &EpochState,
    path: impl AsRef<Path>,
) -> Result<()> {
    save_snapshot_full(ledger, finalized, epoch, None, None, path)
}

/// Save with optional genesis + bootstrap state.
pub fn save_snapshot_full(
    ledger: &LedgerState,
    finalized: &HashSet<String>,
    epoch: &EpochState,
    genesis_state: Option<&GenesisState>,
    bootstrap_state: Option<&BootstrapState>,
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut ledger_for_snap = ledger.clone();
    // Gap 7 (2026-04-21): Clone() skips applied_record_ids (hot-path opt).
    // Restore it here so the snapshot carries the set for wire transfer.
    ledger_for_snap.applied_record_ids = ledger.applied_record_ids.clone();
    let mut snapshot = NodeSnapshot {
        ledger: ledger_for_snap,
        finalized: finalized.clone(),
        epoch: Some(epoch.to_snapshot()),
        checksum: None,
        genesis_state: genesis_state.cloned(),
        bootstrap_state: bootstrap_state.cloned(),
        merkle_root: None,
        record_count: None,
        snapshot_timestamp: None,
        signer_identity: None,
        signer_public_key: None,
        signer_sphincs_public_key: None,
        signature: None,
        sphincs_signature: None,
        protocol_version: Some(crate::network::config::PROTOCOL_VERSION),
        account_state_root: None,
        // Local disk snapshot: the mandate CFs persist across restart natively
        // (RocksDB), so the on-disk snapshot need not carry them. Empty maps
        // leave the checksum unchanged.
        mandates: BTreeMap::new(),
        revocations: BTreeMap::new(),
        emergency: None,
    };

    // Compute deterministic checksum
    snapshot.checksum = Some(compute_checksum(&snapshot));

    // Serialize final version with checksum
    let json = serde_json::to_string(&snapshot)
        .map_err(|e| ElaraError::Storage(format!("snapshot serialize: {e}")))?;

    // Write to temp file first, then rename for atomic update
    let tmp = path.as_ref().with_extension("tmp");
    std::fs::write(&tmp, &json)
        .map_err(|e| ElaraError::Storage(format!("snapshot write: {e}")))?;
    std::fs::rename(&tmp, path.as_ref())
        .map_err(|e| ElaraError::Storage(format!("snapshot rename: {e}")))?;
    info!(
        "snapshot saved: {} accounts, {} supply, {} finalized, {} epoch zones, {} proposals, {} delegations",
        ledger.accounts.len(),
        ledger.total_supply,
        finalized.len(),
        epoch.latest_epoch.len(),
        ledger.governance.proposals.len(),
        ledger.governance.delegations.len(),
    );
    Ok(())
}

/// Inputs to [`create_signed_snapshot`].
///
/// Bundled to keep the snapshot-emit path under the
/// `too_many_arguments` threshold; same parameter-struct pattern used
/// elsewhere in this crate. Borrowed fields stay borrowed; the resulting
/// `NodeSnapshot` owns deep clones of the ledger / finalized / state
/// references.
#[cfg(not(target_arch = "wasm32"))]
pub struct SignedSnapshotInputs<'a> {
    pub ledger: &'a LedgerState,
    pub finalized: &'a HashSet<String>,
    pub epoch: &'a EpochState,
    pub genesis_state: Option<&'a GenesisState>,
    pub bootstrap_state: Option<&'a BootstrapState>,
    pub merkle_root: [u8; 32],
    pub record_count: u64,
    pub identity: &'a crate::identity::Identity,
    /// Gap 7 (post-apply SMT-root verify): producer-side AccountStateSMT
    /// root at snapshot-creation time. Producer reads this from
    /// `AccountStateSMT::new(&rocks).root()` after ensuring ledger.smt_dirty
    /// is flushed. Optional for back-compat — callers that don't have a
    /// storage handle can pass `None` and the consumer-side verify is then a
    /// no-op (no producer root to compare against).
    pub account_state_root: Option<[u8; 32]>,
    /// Agent-mandate registry to carry (C4 slice 1) — the producer collects these
    /// from its CFs (`rocks.collect_mandates()` / `collect_revocations()`).
    /// Callers without a storage handle (or pre-mandate) pass empty maps, which
    /// leave the checksum unchanged (back-compat).
    pub mandates: BTreeMap<String, crate::mandate::MandateRecord>,
    pub revocations: BTreeMap<String, crate::mandate::RevocationEntry>,
    /// EmergencyHalt state to carry (B1). `None` (or default) leaves the checksum
    /// unchanged. The producer reads `state.emergency_snapshot_state()`.
    pub emergency: Option<crate::emergency::EmergencyState>,
}

/// Create a signed snapshot for serving to other nodes (bootstrap sync).
///
/// Includes merkle root, record count, timestamp, and dual-sig from the
/// creating node's identity. New nodes can verify authenticity before
/// trusting the snapshot state.
#[cfg(not(target_arch = "wasm32"))]
pub fn create_signed_snapshot(
    inputs: SignedSnapshotInputs<'_>,
) -> Result<NodeSnapshot> {
    let SignedSnapshotInputs {
        ledger,
        finalized,
        epoch,
        genesis_state,
        bootstrap_state,
        merkle_root,
        record_count,
        identity,
        account_state_root,
        mandates,
        revocations,
        emergency,
    } = inputs;
    let now = crate::record::now_timestamp();

    let mut ledger_for_snap = ledger.clone();
    // Gap 7 (2026-04-21): Clone() skips applied_record_ids; restore for wire.
    ledger_for_snap.applied_record_ids = ledger.applied_record_ids.clone();
    let mut snapshot = NodeSnapshot {
        ledger: ledger_for_snap,
        finalized: finalized.clone(),
        epoch: Some(epoch.to_snapshot()),
        checksum: None,
        genesis_state: genesis_state.cloned(),
        bootstrap_state: bootstrap_state.cloned(),
        merkle_root: Some(hex::encode(merkle_root)),
        record_count: Some(record_count),
        snapshot_timestamp: Some(now),
        signer_identity: Some(identity.identity_hash.clone()),
        signer_public_key: Some(hex::encode(&identity.public_key)),
        signer_sphincs_public_key: identity.sphincs_public_key().map(hex::encode),
        signature: None,
        sphincs_signature: None,
        protocol_version: Some(crate::network::config::PROTOCOL_VERSION),
        account_state_root: account_state_root.map(hex::encode),
        mandates,
        revocations,
        emergency,
    };

    // Compute checksum first (without signature fields)
    let checksum = compute_checksum(&snapshot);
    snapshot.checksum = Some(checksum.clone());

    // Sign the checksum with node's identity (Dilithium3)
    let checksum_bytes = checksum.as_bytes();
    if let Ok(sig) = identity.sign(checksum_bytes) {
        snapshot.signature = Some(hex::encode(&sig));
    }

    // SPHINCS+ signature for Profile A nodes (dual-sig)
    if let Ok(sphincs_sig) = identity.sign_sphincs(checksum_bytes) {
        snapshot.sphincs_signature = Some(hex::encode(&sphincs_sig));
    }

    info!(
        "signed snapshot: {} accounts, {} records, merkle={}..., signer={}...",
        snapshot.ledger.accounts.len(),
        record_count,
        &hex::encode(merkle_root)[..16],
        &identity.identity_hash[..16],
    );

    Ok(snapshot)
}

/// Verify a signed snapshot's authenticity.
///
/// Enforces the full chain: checksum → data, Dilithium3 sig → checksum,
/// signer_public_key → signer_identity (SHA3-256 binding). Returns the
/// signer's identity hash on success.
///
/// When `signer_sphincs_public_key` + `sphincs_signature` are both present
/// (Profile A dual-sig), both signatures must verify — either alone is a
/// reject. When only the Dilithium3 pair is present, Profile B is assumed.
pub fn verify_signed_snapshot(snapshot: &NodeSnapshot) -> Result<String> {
    let checksum = snapshot.checksum.as_ref()
        .ok_or_else(|| ElaraError::Wire("snapshot missing checksum".into()))?;

    // 1. Checksum must match the data.
    let mut verify_snap = snapshot.clone();
    verify_snap.checksum = None;
    verify_snap.signature = None;
    verify_snap.sphincs_signature = None;
    let computed = compute_checksum(&verify_snap);
    if computed != *checksum {
        return Err(ElaraError::Wire("snapshot checksum mismatch".into()));
    }

    // 2. Claimed identity must be bound to a public key.
    let signer = snapshot.signer_identity.as_ref()
        .ok_or_else(|| ElaraError::Wire("snapshot missing signer identity".into()))?;
    let pk_hex = snapshot.signer_public_key.as_ref()
        .ok_or_else(|| ElaraError::Wire("snapshot missing signer_public_key".into()))?;
    let pk = hex::decode(pk_hex)
        .map_err(|e| ElaraError::Wire(format!("bad signer_public_key hex: {e}")))?;

    // Tier 1.3 — Old Node Contamination: signer's Dilithium3 public key must
    // be exactly 1952 bytes. Rejects snapshots whose signer was minted under
    // a different signature algorithm or parameter set (defense against an
    // old or migrated node leaking incompatible state into the network).
    if pk.len() != crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN {
        return Err(ElaraError::Wire(format!(
            "snapshot signer_public_key wrong size for Dilithium3: expected {} bytes, got {}",
            crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN,
            pk.len(),
        )));
    }

    // 3. SHA3-256(pk) must equal the claimed signer_identity.
    let pk_hash = crate::crypto::hash::sha3_256_hex(&pk);
    if &pk_hash != signer {
        return Err(ElaraError::Wire(format!(
            "snapshot signer_identity does not match hash of signer_public_key (claimed {}..., derived {}...)",
            &signer[..16.min(signer.len())],
            &pk_hash[..16.min(pk_hash.len())],
        )));
    }

    // 4. Dilithium3 signature must verify over checksum bytes.
    let sig_hex = snapshot.signature.as_ref()
        .ok_or_else(|| ElaraError::Wire("snapshot missing signature".into()))?;
    let sig = hex::decode(sig_hex)
        .map_err(|e| ElaraError::Wire(format!("bad signature hex: {e}")))?;
    let checksum_bytes = checksum.as_bytes();
    match crate::crypto::pqc::dilithium3_verify(checksum_bytes, &sig, &pk) {
        Ok(true) => {}
        Ok(false) => return Err(ElaraError::Wire("snapshot Dilithium3 signature invalid".into())),
        Err(e) => return Err(ElaraError::Wire(format!("snapshot Dilithium3 verify error: {e}"))),
    }

    // 5. SPHINCS+ dual-sig — when present, both sig + pk must be present and verify.
    match (&snapshot.sphincs_signature, &snapshot.signer_sphincs_public_key) {
        (Some(sphincs_sig_hex), Some(sphincs_pk_hex)) => {
            let sphincs_sig = hex::decode(sphincs_sig_hex)
                .map_err(|e| ElaraError::Wire(format!("bad sphincs_signature hex: {e}")))?;
            let sphincs_pk = hex::decode(sphincs_pk_hex)
                .map_err(|e| ElaraError::Wire(format!("bad signer_sphincs_public_key hex: {e}")))?;
            // Tier 1.3 — Old Node Contamination: SPHINCS+ pk must be exactly
            // 48 bytes for SLH-DSA-SHA2-192f. Rejects mismatched SPHINCS+
            // parameter sets (-128f, -256f, etc.) from incompatible nodes.
            if sphincs_pk.len() != crate::crypto::pqc::SPHINCS_SHA2_192F_PUBLIC_KEY_LEN {
                return Err(ElaraError::Wire(format!(
                    "snapshot signer_sphincs_public_key wrong size for SPHINCS+-SHA2-192f: expected {} bytes, got {}",
                    crate::crypto::pqc::SPHINCS_SHA2_192F_PUBLIC_KEY_LEN,
                    sphincs_pk.len(),
                )));
            }
            match crate::identity::Identity::verify_sphincs(checksum_bytes, &sphincs_sig, &sphincs_pk) {
                Ok(true) => {}
                Ok(false) => return Err(ElaraError::Wire("snapshot SPHINCS+ signature invalid".into())),
                Err(e) => return Err(ElaraError::Wire(format!("snapshot SPHINCS+ verify error: {e}"))),
            }
        }
        (Some(_), None) => {
            return Err(ElaraError::Wire(
                "snapshot has sphincs_signature but missing signer_sphincs_public_key".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(ElaraError::Wire(
                "snapshot has signer_sphincs_public_key but missing sphincs_signature".into(),
            ));
        }
        (None, None) => { /* Profile B — Dilithium3-only is acceptable */ }
    }

    Ok(signer.clone())
}

/// PQ-R2: verify the snapshot's signer identity is in our trust set.
///
/// Cryptographic verification (`verify_signed_snapshot`) only proves the
/// snapshot was signed by *whoever* holds the published public key — it
/// does NOT prove that signer is authoritative. Any peer running a
/// modified ledger can produce a syntactically-valid signed snapshot.
/// Onboarding nodes must additionally pin the signer to a known-trusted
/// identity (genesis authority, or operator-configured anchors).
///
/// `trust_set` is the unioned `{genesis_authority} ∪ trusted_snapshot_signers`
/// from `NodeConfig`. Empty trust_set is rejected — a node with no trust
/// anchor cannot safely bootstrap from a remote snapshot.
pub fn enforce_snapshot_signer_trust(signer: &str, trust_set: &[&str]) -> Result<()> {
    if trust_set.is_empty() {
        return Err(ElaraError::Wire(
            "snapshot signer trust gate: no trusted signers configured \
             (genesis_authority empty and trusted_snapshot_signers empty)".into(),
        ));
    }
    if trust_set.contains(&signer) {
        return Ok(());
    }
    let preview = &signer[..16.min(signer.len())];
    Err(ElaraError::Wire(format!(
        "snapshot signer {preview}... is not in the trusted-signer set \
         ({} entries) — refusing to bootstrap from untrusted state",
        trust_set.len(),
    )))
}

/// Tier 1.3 — Old Node Contamination: reject snapshots whose creating node
/// reports a protocol version below the local minimum. `min_version == 0`
/// disables the gate (default in the wild). Snapshots with a missing
/// `protocol_version` field (legacy snapshots from before this gate) are
/// treated as version 0 — they pass when `min_version == 0` and fail
/// otherwise. This is informational/cooperative defense: a malicious peer
/// is rejected by the trust-set gate; this guard catches the honest-but-old
/// case where one of our trusted signers is running outdated software.
pub fn enforce_snapshot_protocol_version(snapshot: &NodeSnapshot, min_version: u32) -> Result<()> {
    if min_version == 0 {
        return Ok(());
    }
    let snapshot_version = snapshot.protocol_version.unwrap_or(0);
    if snapshot_version < min_version {
        return Err(ElaraError::Wire(format!(
            "snapshot protocol_version {} < required minimum {} — refusing to bootstrap from old node",
            snapshot_version, min_version,
        )));
    }
    Ok(())
}

/// Extract lightweight metadata from a snapshot (for GET /snapshot/latest).
pub fn snapshot_metadata(snapshot: &NodeSnapshot) -> Option<SnapshotMetadata> {
    Some(SnapshotMetadata {
        merkle_root: snapshot.merkle_root.clone()?,
        record_count: snapshot.record_count?,
        snapshot_timestamp: snapshot.snapshot_timestamp?,
        signer_identity: snapshot.signer_identity.clone()?,
        checksum: snapshot.checksum.clone()?,
        accounts: snapshot.ledger.accounts.len(),
        total_supply: snapshot.ledger.total_supply,
        total_staked: snapshot.ledger.total_staked,
    })
}

// ─── Gap 7: epoch-indexed snapshot store ─────────────────────────────────────
//
// Archive nodes persist *historical* signed snapshots to disk, one per
// advancing epoch boundary. New nodes bootstrap by fetching the latest
// epoch snapshot + incremental delta from that epoch — no genesis replay.
//
// Filename convention: `epoch-{epoch:012}.json`
//   - zero-padded so lexicographic file-listing sort matches numeric sort
//   - collision-free as long as epoch numbers monotonically increase
//
// Storage layout:
//   {data_dir}/snapshots/epoch-000000000100.json
//   {data_dir}/snapshots/epoch-000000000200.json
//   ...
//
// At 1M zones × 10-epoch cadence × 20 snapshots retained = ~20 files.
// Disk cost bounded by `archive_snapshot_retention` config knob.

/// Build the canonical filename for an epoch snapshot: `epoch-{N:012}.json`.
pub fn epoch_snapshot_filename(epoch_num: u64) -> String {
    format!("epoch-{:012}.json", epoch_num)
}

/// Parse the epoch number out of a filename. Returns None if the file name
/// doesn't match the `epoch-{N:012}.json` convention.
pub fn parse_epoch_snapshot_filename(name: &str) -> Option<u64> {
    let base = name.strip_suffix(".json")?;
    let rest = base.strip_prefix("epoch-")?;
    rest.parse::<u64>().ok()
}

/// Save a signed epoch snapshot to `{dir}/epoch-{N:012}.json`.
///
/// Creates the directory if it doesn't exist. Uses the usual
/// write-to-tmp-then-rename pattern for atomic replacement.
///
/// Returns the full path written.
pub fn save_epoch_snapshot(
    dir: impl AsRef<Path>,
    epoch_num: u64,
    snapshot: &NodeSnapshot,
) -> Result<std::path::PathBuf> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)
        .map_err(|e| ElaraError::Storage(format!("epoch snapshot mkdir: {e}")))?;

    let path = dir.join(epoch_snapshot_filename(epoch_num));
    let json = serde_json::to_string(snapshot)
        .map_err(|e| ElaraError::Storage(format!("epoch snapshot serialize: {e}")))?;

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json)
        .map_err(|e| ElaraError::Storage(format!("epoch snapshot write: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| ElaraError::Storage(format!("epoch snapshot rename: {e}")))?;

    info!(
        "epoch snapshot saved: epoch={} accounts={} records={} path={}",
        epoch_num,
        snapshot.ledger.accounts.len(),
        snapshot.record_count.unwrap_or(0),
        path.display(),
    );
    Ok(path)
}

/// Load a specific epoch snapshot from disk. Returns None if missing or
/// checksum-corrupted (same semantics as `load_snapshot`).
pub fn load_epoch_snapshot(
    dir: impl AsRef<Path>,
    epoch_num: u64,
) -> Result<Option<NodeSnapshot>> {
    let path = dir.as_ref().join(epoch_snapshot_filename(epoch_num));
    load_snapshot(path)
}

/// List all epoch snapshot numbers available on disk, ascending.
///
/// Scans `{dir}` for files matching `epoch-{N:012}.json`. Missing dir → empty
/// list. Non-matching files are ignored. O(directory-size), not O(all-records).
pub fn list_epoch_snapshots(dir: impl AsRef<Path>) -> Result<Vec<u64>> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut epochs = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ElaraError::Storage(format!("list epoch snapshots: {e}")))?;
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Some(n) = parse_epoch_snapshot_filename(name) {
                epochs.push(n);
            }
        }
    }
    epochs.sort();
    Ok(epochs)
}

/// Find the highest epoch snapshot at or before `target_epoch`. Returns the
/// loaded snapshot + its epoch number, or `None` if no snapshot ≤ target
/// exists.
///
/// Why we need this: `archive_snapshot_every_n_epochs` defaults to 10 (≈20 min
/// at 120s epochs). A client claiming `since_epoch=53` won't find an exact
/// match — only `epoch-50` exists. Without this helper, /snapshot/state-delta
/// falls back to a full-ledger payload every time the client's epoch isn't on
/// the snapshot stride, defeating the incremental path. With it, we diff
/// against epoch-50 and emit only what changed since then. Any account
/// unchanged between 50→53 gets sent in the diff but the client overwrites
/// with the same value — correctness via signed `account_state_root`, not via
/// minimum diff size.
///
/// O(directory-size) for the listing + O(1) for the load. No new I/O beyond
/// the existing `latest_epoch_snapshot` cost shape.
pub fn load_epoch_snapshot_at_or_before(
    dir: impl AsRef<Path>,
    target_epoch: u64,
) -> Result<Option<(u64, NodeSnapshot)>> {
    let dir = dir.as_ref();
    let epochs = list_epoch_snapshots(dir)?;
    // list is ascending; rev() + find() gives the largest e ≤ target.
    let baseline = match epochs.iter().rev().find(|&&e| e <= target_epoch).copied() {
        Some(e) => e,
        None => return Ok(None),
    };
    match load_epoch_snapshot(dir, baseline)? {
        Some(snap) => Ok(Some((baseline, snap))),
        None => Ok(None),
    }
}

/// Return the most recent epoch snapshot (by epoch number), loaded from disk.
pub fn latest_epoch_snapshot(
    dir: impl AsRef<Path>,
) -> Result<Option<(u64, NodeSnapshot)>> {
    let dir = dir.as_ref();
    let epochs = list_epoch_snapshots(dir)?;
    if let Some(&n) = epochs.last() {
        if let Some(snap) = load_epoch_snapshot(dir, n)? {
            return Ok(Some((n, snap)));
        }
    }
    Ok(None)
}

/// Prune epoch snapshots, keeping only the `keep_n` most recent.
///
/// Returns the number of files deleted. If `keep_n == 0`, no-ops (disabled).
pub fn prune_old_epoch_snapshots(
    dir: impl AsRef<Path>,
    keep_n: usize,
) -> Result<usize> {
    if keep_n == 0 {
        return Ok(0);
    }
    let dir = dir.as_ref();
    let epochs = list_epoch_snapshots(dir)?;
    if epochs.len() <= keep_n {
        return Ok(0);
    }
    let to_delete = &epochs[..epochs.len() - keep_n];
    let mut deleted = 0usize;
    for &n in to_delete {
        let path = dir.join(epoch_snapshot_filename(n));
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!("failed to prune epoch snapshot {}: {}", path.display(), e);
        } else {
            deleted += 1;
        }
    }
    if deleted > 0 {
        info!("pruned {} old epoch snapshots (kept last {})", deleted, keep_n);
    }
    Ok(deleted)
}

/// Load a node snapshot from a JSON file.
///
/// Backward compatible: if the file contains an old-format ledger-only
/// snapshot, it's transparently promoted to a full NodeSnapshot.
///
/// If the checksum field is present and doesn't match, returns None
/// with a warning (caller should fall back to full rebuild).
pub fn load_snapshot(path: impl AsRef<Path>) -> Result<Option<NodeSnapshot>> {
    if !path.as_ref().exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(path.as_ref())
        .map_err(|e| ElaraError::Storage(format!("snapshot read: {e}")))?;

    // Try new format first
    if let Ok(snapshot) = serde_json::from_str::<NodeSnapshot>(&data) {
        // Verify checksum if present
        if let Some(expected) = &snapshot.checksum {
            let actual = compute_checksum(&snapshot);
            if actual != *expected {
                tracing::warn!(
                    "snapshot checksum mismatch: expected {}..., got {}... — renaming corrupt snapshot",
                    &expected[..16.min(expected.len())],
                    &actual[..16],
                );
                // Rename corrupt file so it doesn't slow down every future restart.
                // Preserved as .corrupt for debugging.
                let corrupt_path = path.as_ref().with_extension("json.corrupt");
                if let Err(e) = std::fs::rename(path.as_ref(), &corrupt_path) {
                    tracing::warn!("failed to rename corrupt snapshot: {e}");
                } else {
                    tracing::info!("corrupt snapshot moved to {}", corrupt_path.display());
                }
                return Ok(None);
            }
        }

        info!(
            "snapshot loaded: {} accounts, {} supply, {} finalized, {} epoch zones, {} proposals, {} delegations{}",
            snapshot.ledger.accounts.len(),
            snapshot.ledger.total_supply,
            snapshot.finalized.len(),
            snapshot.epoch.as_ref().map(|e| e.latest_epoch.len()).unwrap_or(0),
            snapshot.ledger.governance.proposals.len(),
            snapshot.ledger.governance.delegations.len(),
            if snapshot.checksum.is_some() { " (checksum verified)" } else { "" },
        );
        return Ok(Some(snapshot));
    }

    // Fall back to old ledger-only format
    let ledger: LedgerState = serde_json::from_str(&data)
        .map_err(|e| ElaraError::Storage(format!("snapshot deserialize: {e}")))?;
    info!(
        "legacy snapshot loaded: {} accounts, {} supply (no finalized/epoch data)",
        ledger.accounts.len(),
        ledger.total_supply,
    );
    Ok(Some(NodeSnapshot {
        ledger,
        finalized: HashSet::new(),
        epoch: None,
        checksum: None,
        genesis_state: None,
        bootstrap_state: None,
        merkle_root: None,
        record_count: None,
        snapshot_timestamp: None,
        signer_identity: None,
        signer_public_key: None,
        signer_sphincs_public_key: None,
        signature: None,
        sphincs_signature: None,
        protocol_version: None,
        account_state_root: None,
        mandates: BTreeMap::new(),
        revocations: BTreeMap::new(),
        emergency: None,
    }))
}

// ─── Gap 7: incremental state-delta snapshot ──────────────────────
//
// A full-ledger
// clone every snapshot can't onboard 10M-record chains in minutes. This struct
// carries only the accounts that *changed* since a baseline epoch the client
// already trusts — a fraction of the full ledger when the active set is small
// relative to the total set.
//
// Verification chain end-to-end:
//   1. New node trusts a baseline `NodeSnapshot` at epoch B (signed, validated).
//   2. New node fetches `StateDelta` for `since_epoch = B`. The delta is
//      Dilithium3-signed by the serving node's identity (`signer_*` fields)
//      and its `account_state_root` is anchored to the latest super-seal
//      via the live AccountStateSMT root the serving node currently has.
//   3. New node applies (changed_accounts, removed_accounts) on top of its
//      baseline ledger and re-derives the AccountStateSMT root locally;
//      mismatch with `account_state_root` rejects the delta. Match plus a
//      cryptographic chain to a super-seal observed independently means the
//      delta is end-to-end verifiable, not just signer-trust.
//
// This is the "first-byte response" path; it reuses the existing on-disk
// archive snapshots (`compute_get_epoch_snapshot`) as the baseline lookup.
// When the server does not have the archive snapshot at `since_epoch`, the
// response carries `baseline_available=false` — clients fall through to
// full `/snapshot` and pay the one-time onboarding cost; the next delta will
// run incrementally.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateDelta {
    /// Baseline epoch the client claims to already trust.
    pub since_epoch: u64,
    /// Latest epoch known to the serving node at delta-build time.
    pub current_epoch: u64,
    /// Whether the server could compute an incremental delta — false means
    /// the server didn't have the archive snapshot at `since_epoch` and the
    /// `changed_accounts` field carries the *full* current ledger as a fallback.
    pub baseline_available: bool,
    /// Hex-encoded current AccountStateSMT root. End-to-end verifier: client
    /// must reconstruct this after applying the delta.
    pub account_state_root: String,
    /// Hex-encoded global record-merkle root at delta-build time (same as
    /// `/merkle_root`). Lets the client validate the delta against a seal it
    /// already has independently.
    pub merkle_root: String,
    /// Latest super-seal end-epoch known to the serving node, if any.
    /// `None` when no super-seal has formed yet (testnet today).
    pub latest_super_seal_epoch: Option<u64>,
    /// Hex-encoded record-hash of that latest super-seal, if any. Lets the
    /// client cross-check the super-seal it already trusts.
    pub latest_super_seal_record_hash: Option<String>,
    /// Gap 7: epoch of the latest sealed
    /// `account_smt_root` binding the serving node observed. Lets a light
    /// client refuse a delta whose latest-sealed binding is older than the
    /// seal they already trust — defense against a stale-replay server
    /// quietly serving a delta from an outdated chain head. `None` until the
    /// first Gap-1-capable seal registers (testnet pre-instrumentation).
    #[serde(default)]
    pub latest_sealed_account_epoch: Option<u64>,
    /// Gap 7 slice 7.1: hex-encoded SMT root from the latest sealed binding
    /// (`EpochState::latest_sealed_account.account_smt_root`). Witness-signed
    /// in the seal record; the client fetches that seal independently and
    /// compares this field. Mismatch = server is signing a different chain
    /// head than the one the client trusts. `None` mirrors
    /// `latest_sealed_account_epoch`. Bound by the delta checksum + Dilithium3
    /// signature so a malicious server cannot drop the field to bypass the
    /// chain-head check.
    #[serde(default)]
    pub latest_sealed_account_smt_root: Option<String>,
    /// Accounts that exist now and either didn't exist at the baseline or
    /// have a different `AccountState`. Map: identity hash -> current state.
    pub changed_accounts: BTreeMap<String, crate::accounting::ledger::AccountState>,
    /// Accounts that existed at the baseline but no longer exist. Rare — beat
    /// accounts decay to zero balance rather than disappearing — but covered
    /// for completeness so the client's diff is closed.
    pub removed_accounts: Vec<String>,
    /// Total accounts at delta-build time (sanity counter for the client).
    pub total_accounts: u64,
    /// Total supply at delta-build time.
    pub total_supply: u64,
    /// Total staked at delta-build time.
    pub total_staked: u64,
    /// Wall-clock timestamp the delta was built (server-side now()).
    pub snapshot_timestamp: f64,
    /// Identity hash of the serving node.
    pub signer_identity: String,
    /// Dilithium3 public key of the serving node (hex).
    pub signer_public_key: String,
    /// Optional SPHINCS+ public key (Profile A nodes; hex).
    #[serde(default)]
    pub signer_sphincs_public_key: Option<String>,
    /// SHA3-256 checksum over the canonical-serialization of the delta
    /// (with all signature fields cleared). Same hashing pattern as
    /// `compute_checksum` for `NodeSnapshot`.
    pub checksum: String,
    /// Dilithium3 signature over `checksum` (hex).
    pub signature: String,
    /// Optional SPHINCS+ signature for Profile A dual-sig (hex).
    #[serde(default)]
    pub sphincs_signature: Option<String>,
    /// Protocol version of the serving node.
    pub protocol_version: u32,
}

/// Compute a deterministic checksum over a `StateDelta` with all signature
/// fields blanked. Mirrors the canonical-JSON pattern used by
/// `compute_checksum`. BTreeMap key sort gives stable output.
///
/// f64 fields are hashed via `to_bits()` rather than their `Display` form —
/// the same root cause behind the v3→v4 `compute_checksum` migration:
/// `serde_json::Value::F64(x).to_string()` is not always inverse to
/// `f64::from_str(s)`, so a round-trip through JSON can produce a
/// different `Display` repr by 1 ulp. `to_bits()` is bit-exact regardless
/// of what a deserializer does in the middle.
fn compute_state_delta_checksum(delta: &StateDelta) -> String {
    let mut removed_sorted = delta.removed_accounts.clone();
    removed_sorted.sort();

    // changed_accounts is already a BTreeMap, so JSON output is sorted-key
    // deterministic. AccountState has only u64/u32 fields except `last_active`
    // (f64), which is the same f64-round-trip risk — `account_state_eq`
    // handles that with `to_bits()`. For the checksum, we hash account fields
    // individually here rather than relying on serde_json::to_string to give
    // bit-exact output across rebuilds.
    let mut changed_canonical = String::new();
    for (id, st) in &delta.changed_accounts {
        use std::fmt::Write;
        let _ = write!(
            changed_canonical,
            "{id}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{};",
            st.available,
            st.staked,
            st.total_received,
            st.total_sent,
            st.tx_count,
            st.last_active.to_bits(),
            st.vested_locked,
            st.uptime_secs,
            st.inactive_days,
            st.witness_bonded,
        );
    }

    // v2 (slice 7.1): includes `latest_sealed_account_epoch` +
    // `latest_sealed_account_smt_root`. Both `Option<…>` so the {:?} format
    // hashes None as "None" and Some(x) as "Some(x)" — same pattern as the
    // existing `latest_super_seal_*` fields below — backwards-compatible at
    // the wire level (extra fields hash deterministically; Option default = None
    // means a v1 producer would have appended "None" anyway, but we bump to
    // v2 for explicit format-version clarity). v1 deltas in flight at deploy
    // time are signed by witnesses on the old format and are still verifiable
    // under the v1 codepath; the verify side reads the same struct shape and
    // `compute_state_delta_checksum` always runs on the live struct so the
    // version bump is purely a domain-separation tag, not a migration.
    let data = format!(
        "v2:since_epoch={},current_epoch={},baseline={},account_root={},merkle_root={},super_seal_epoch={:?},super_seal_hash={:?},sealed_account_epoch={:?},sealed_account_root={:?},changed={},removed={},total_accounts={},total_supply={},total_staked={},timestamp_bits={},signer={},protocol_version={}",
        delta.since_epoch,
        delta.current_epoch,
        delta.baseline_available,
        delta.account_state_root,
        delta.merkle_root,
        delta.latest_super_seal_epoch,
        delta.latest_super_seal_record_hash,
        delta.latest_sealed_account_epoch,
        delta.latest_sealed_account_smt_root,
        changed_canonical,
        serde_json::to_string(&removed_sorted).unwrap_or_default(),
        delta.total_accounts,
        delta.total_supply,
        delta.total_staked,
        delta.snapshot_timestamp.to_bits(),
        delta.signer_identity,
        delta.protocol_version,
    );
    hex::encode(crate::crypto::hash::sha3_256(data.as_bytes()))
}

/// Inputs for [`create_signed_state_delta`]. Borrowed-style consistent with
/// `SignedSnapshotInputs` so both helpers share the same call shape.
#[cfg(not(target_arch = "wasm32"))]
pub struct StateDeltaInputs<'a> {
    pub since_epoch: u64,
    pub current_epoch: u64,
    pub baseline_available: bool,
    pub account_state_root: [u8; 32],
    pub merkle_root: [u8; 32],
    pub latest_super_seal_epoch: Option<u64>,
    pub latest_super_seal_record_hash: Option<[u8; 32]>,
    /// Gap 7 slice 7.1: epoch of the latest sealed `account_smt_root` binding
    /// known to the serving node (`EpochState::latest_sealed_account.0`).
    /// `None` until the first Gap-1-capable seal registers.
    pub latest_sealed_account_epoch: Option<u64>,
    /// Gap 7 slice 7.1: account-SMT root from that latest sealed binding
    /// (`EpochState::latest_sealed_account.3`).
    pub latest_sealed_account_smt_root: Option<[u8; 32]>,
    pub changed_accounts: BTreeMap<String, crate::accounting::ledger::AccountState>,
    pub removed_accounts: Vec<String>,
    pub total_accounts: u64,
    pub total_supply: u64,
    pub total_staked: u64,
    pub identity: &'a crate::identity::Identity,
}

/// Build a signed `StateDelta`. Same dual-sig posture as
/// `create_signed_snapshot`: Dilithium3 always; SPHINCS+ when the identity
/// supports it (Profile A).
#[cfg(not(target_arch = "wasm32"))]
pub fn create_signed_state_delta(inputs: StateDeltaInputs<'_>) -> Result<StateDelta> {
    let StateDeltaInputs {
        since_epoch,
        current_epoch,
        baseline_available,
        account_state_root,
        merkle_root,
        latest_super_seal_epoch,
        latest_super_seal_record_hash,
        latest_sealed_account_epoch,
        latest_sealed_account_smt_root,
        changed_accounts,
        removed_accounts,
        total_accounts,
        total_supply,
        total_staked,
        identity,
    } = inputs;
    // Quantize to milliseconds: full f64 sub-microsecond precision from
    // `now_timestamp()` is NOT preserved through serde_json round-trip even
    // though `to_bits()` hashing is bit-exact. Concretely, values like
    // `1777525526.9393907` print as their own Display, but
    // `f64::from_str("1777525526.9393907")` parses to a different bit pattern
    // (1 ulp off), so the client's checksum recompute fails. 1ms precision is
    // more than enough for client freshness/staleness logic and round-trips
    // cleanly. Same problem class as the v3→v4 NodeSnapshot migration.
    let now = (crate::record::now_timestamp() * 1000.0).round() / 1000.0;

    let mut delta = StateDelta {
        since_epoch,
        current_epoch,
        baseline_available,
        account_state_root: hex::encode(account_state_root),
        merkle_root: hex::encode(merkle_root),
        latest_super_seal_epoch,
        latest_super_seal_record_hash: latest_super_seal_record_hash.map(hex::encode),
        latest_sealed_account_epoch,
        latest_sealed_account_smt_root: latest_sealed_account_smt_root.map(hex::encode),
        changed_accounts,
        removed_accounts,
        total_accounts,
        total_supply,
        total_staked,
        snapshot_timestamp: now,
        signer_identity: identity.identity_hash.clone(),
        signer_public_key: hex::encode(&identity.public_key),
        signer_sphincs_public_key: identity.sphincs_public_key().map(hex::encode),
        checksum: String::new(),
        signature: String::new(),
        sphincs_signature: None,
        protocol_version: crate::network::config::PROTOCOL_VERSION,
    };

    let checksum = compute_state_delta_checksum(&delta);
    delta.checksum = checksum.clone();

    let checksum_bytes = checksum.as_bytes();
    delta.signature = identity.sign(checksum_bytes)
        .map(hex::encode)
        .map_err(|e| ElaraError::Wire(format!("state-delta Dilithium3 sign: {e}")))?;
    if let Ok(sphincs_sig) = identity.sign_sphincs(checksum_bytes) {
        delta.sphincs_signature = Some(hex::encode(sphincs_sig));
    }

    info!(
        "signed state-delta: since={} current={} changed={} removed={} root={}... signer={}...",
        since_epoch,
        current_epoch,
        delta.changed_accounts.len(),
        delta.removed_accounts.len(),
        &delta.account_state_root[..16.min(delta.account_state_root.len())],
        &identity.identity_hash[..16],
    );

    Ok(delta)
}

/// Verify a signed `StateDelta`. Returns the signer identity on success.
/// Same chain as `verify_signed_snapshot`: checksum → data, sig → checksum,
/// signer_public_key → signer_identity (SHA3-256 binding), optional SPHINCS+.
pub fn verify_signed_state_delta(delta: &StateDelta) -> Result<String> {
    // 1. Checksum recomputed on a copy with signature fields cleared.
    let mut verify_copy = delta.clone();
    verify_copy.checksum = String::new();
    verify_copy.signature = String::new();
    verify_copy.sphincs_signature = None;
    let computed = compute_state_delta_checksum(&verify_copy);
    if computed != delta.checksum {
        return Err(ElaraError::Wire("state-delta checksum mismatch".into()));
    }

    // 2. signer_public_key → signer_identity binding.
    let pk = hex::decode(&delta.signer_public_key)
        .map_err(|e| ElaraError::Wire(format!("bad state-delta signer_public_key hex: {e}")))?;
    if pk.len() != crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN {
        return Err(ElaraError::Wire(format!(
            "state-delta signer_public_key wrong size for Dilithium3: expected {} bytes, got {}",
            crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN,
            pk.len(),
        )));
    }
    let pk_hash = crate::crypto::hash::sha3_256_hex(&pk);
    if pk_hash != delta.signer_identity {
        return Err(ElaraError::Wire(format!(
            "state-delta signer_identity does not match hash of signer_public_key (claimed {}..., derived {}...)",
            &delta.signer_identity[..16.min(delta.signer_identity.len())],
            &pk_hash[..16.min(pk_hash.len())],
        )));
    }

    // 3. Dilithium3 signature must verify over checksum bytes.
    let sig = hex::decode(&delta.signature)
        .map_err(|e| ElaraError::Wire(format!("bad state-delta signature hex: {e}")))?;
    let checksum_bytes = delta.checksum.as_bytes();
    match crate::crypto::pqc::dilithium3_verify(checksum_bytes, &sig, &pk) {
        Ok(true) => {}
        Ok(false) => return Err(ElaraError::Wire("state-delta Dilithium3 signature invalid".into())),
        Err(e) => return Err(ElaraError::Wire(format!("state-delta Dilithium3 verify error: {e}"))),
    }

    // 4. SPHINCS+ dual-sig — when present, must verify; sig+pk must match.
    match (&delta.sphincs_signature, &delta.signer_sphincs_public_key) {
        (Some(sphincs_sig_hex), Some(sphincs_pk_hex)) => {
            let sphincs_sig = hex::decode(sphincs_sig_hex)
                .map_err(|e| ElaraError::Wire(format!("bad state-delta sphincs_signature hex: {e}")))?;
            let sphincs_pk = hex::decode(sphincs_pk_hex)
                .map_err(|e| ElaraError::Wire(format!("bad state-delta signer_sphincs_public_key hex: {e}")))?;
            if sphincs_pk.len() != crate::crypto::pqc::SPHINCS_SHA2_192F_PUBLIC_KEY_LEN {
                return Err(ElaraError::Wire(format!(
                    "state-delta signer_sphincs_public_key wrong size: expected {} bytes, got {}",
                    crate::crypto::pqc::SPHINCS_SHA2_192F_PUBLIC_KEY_LEN,
                    sphincs_pk.len(),
                )));
            }
            match crate::identity::Identity::verify_sphincs(checksum_bytes, &sphincs_sig, &sphincs_pk) {
                Ok(true) => {}
                Ok(false) => return Err(ElaraError::Wire("state-delta SPHINCS+ signature invalid".into())),
                Err(e) => return Err(ElaraError::Wire(format!("state-delta SPHINCS+ verify error: {e}"))),
            }
        }
        (Some(_), None) => {
            return Err(ElaraError::Wire(
                "state-delta has sphincs_signature but missing signer_sphincs_public_key".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(ElaraError::Wire(
                "state-delta has signer_sphincs_public_key but missing sphincs_signature".into(),
            ));
        }
        (None, None) => { /* Profile B */ }
    }

    Ok(delta.signer_identity.clone())
}

/// Diff two ledgers' account maps and return (changed, removed). "Changed"
/// includes accounts that are new (existed in `current` but not in `prior`).
/// O(|prior| + |current|) — no allocation per unchanged account.
pub fn diff_account_states(
    prior: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
    current: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
) -> (BTreeMap<String, crate::accounting::ledger::AccountState>, Vec<String>) {
    let mut changed = BTreeMap::new();
    for (id, cur) in current.iter() {
        match prior.get(id) {
            Some(p) if account_state_eq(p, cur) => { /* unchanged */ }
            _ => {
                changed.insert(id.clone(), cur.clone());
            }
        }
    }
    let mut removed = Vec::new();
    for id in prior.keys() {
        if !current.contains_key(id) {
            removed.push(id.clone());
        }
    }
    removed.sort();
    (changed, removed)
}

/// Field-by-field equality on AccountState. Avoids deriving `PartialEq` on
/// the production type (which has many fields and may grow without affecting
/// delta-equality semantics — those are state-fields only).
fn account_state_eq(
    a: &crate::accounting::ledger::AccountState,
    b: &crate::accounting::ledger::AccountState,
) -> bool {
    a.available == b.available
        && a.staked == b.staked
        && a.total_received == b.total_received
        && a.total_sent == b.total_sent
        && a.tx_count == b.tx_count
        && a.last_active.to_bits() == b.last_active.to_bits()
        && a.vested_locked == b.vested_locked
        && a.uptime_secs == b.uptime_secs
        && a.inactive_days == b.inactive_days
        && a.witness_bonded == b.witness_bonded
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZoneId;
    use tempfile::TempDir;

    #[test]
    fn archive_snapshot_every_n_epochs_default_constant_pins_to_documented_value() {
        // Pins the documented value: the `Config` default for archival snapshot
        // cadence MUST equal the public constant, which in turn MUST equal the
        // documented spec value (10 epochs ≈ 20 min at 120s epoch cadence per
        // internal design notes Gap 7). A regression that flipped either side to 0 would
        // silently disable archival snapshot emission cluster-wide on every
        // archival node — the chain keeps producing, light clients keep
        // onboarding from an increasingly stale snapshot, failure is silent
        // and slow.
        assert_eq!(ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT, 10);
        assert_eq!(
            crate::network::config::NodeConfig::default().archive_snapshot_every_n_epochs,
            ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT,
            "Config default drifted from ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT — \
             update the constant or restore the Config default; a 0 here would silently \
             disable archival snapshot emission."
        );
        // Lower-bound `> 0` invariant pinned at compile time via the
        // `const _: () = assert!(..)` block next to the const declaration
        // (snapshot.rs ~L38). A regression to `0` now fails at `cargo
        // build`, not at `cargo test`. Runtime assert removed
        // (clippy::assertions_on_constants — both operands const-eval).
    }

    fn make_ledger() -> LedgerState {
        LedgerState {
            total_supply: 1_000_000,
            records_processed: 42,
            ..Default::default()
        }
    }

    fn make_epoch() -> EpochState {
        let mut epoch = EpochState::new();
        epoch.latest_epoch.insert(ZoneId::from_legacy(0), 5);
        epoch.latest_seal_id.insert(ZoneId::from_legacy(0), "seal-id-5".to_string());
        epoch.latest_seal_hash.insert(ZoneId::from_legacy(0), [0xAA; 32]);
        epoch
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snapshot.json");
        let ledger = make_ledger();
        let mut finalized = HashSet::new();
        finalized.insert("rec-1".to_string());
        finalized.insert("rec-2".to_string());
        let epoch = make_epoch();

        save_snapshot(&ledger, &finalized, &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.ledger.total_supply, 1_000_000);
        assert_eq!(loaded.finalized.len(), 2);
        assert!(loaded.finalized.contains("rec-1"));
        assert!(loaded.checksum.is_some(), "should have checksum");
        let epoch_restored = loaded.epoch_state();
        assert_eq!(epoch_restored.latest_epoch[&ZoneId::from_legacy(0)], 5);
        assert_eq!(epoch_restored.latest_seal_id[&ZoneId::from_legacy(0)], "seal-id-5");
        assert_eq!(epoch_restored.latest_seal_hash[&ZoneId::from_legacy(0)], [0xAA; 32]);
    }

    #[test]
    fn test_applied_record_ids_roundtrip() {
        // Gap 7 (2026-04-21): applied_record_ids must survive a JSON roundtrip
        // so a bootstrapping peer can populate CF_APPLIED from a served snapshot.
        // Before the flip of skip_serializing → default, this set was dropped
        // on the wire and every new node had to do an O(all_records) replay.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snapshot_applied.json");
        let mut ledger = make_ledger();
        ledger.applied_record_ids.insert("rec-applied-1".to_string());
        ledger.applied_record_ids.insert("rec-applied-2".to_string());
        ledger.applied_record_ids.insert("rec-applied-3".to_string());
        let finalized = HashSet::new();
        let epoch = make_epoch();

        save_snapshot(&ledger, &finalized, &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.ledger.applied_record_ids.len(), 3,
            "applied_record_ids must survive wire serialization");
        assert!(loaded.ledger.applied_record_ids.contains("rec-applied-1"));
        assert!(loaded.ledger.applied_record_ids.contains("rec-applied-2"));
        assert!(loaded.ledger.applied_record_ids.contains("rec-applied-3"));
    }

    #[test]
    fn test_corrupt_snapshot_returns_none_and_renames() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.json");
        let ledger = make_ledger();
        let epoch = make_epoch();

        save_snapshot(&ledger, &HashSet::new(), &epoch, &path).unwrap();

        // Tamper with the file
        let mut data = std::fs::read_to_string(&path).unwrap();
        data = data.replace("1000000", "9999999");
        std::fs::write(&path, &data).unwrap();

        // Should return None due to checksum mismatch
        let result = load_snapshot(&path).unwrap();
        assert!(result.is_none(), "corrupt snapshot should return None");

        // Original file should be renamed to .corrupt
        assert!(!path.exists(), "corrupt file should be moved");
        let corrupt_path = dir.path().join("corrupt.json.corrupt");
        assert!(corrupt_path.exists(), "corrupt file should be renamed to .corrupt");

        // Second load should return None quickly (file gone)
        let result2 = load_snapshot(&path).unwrap();
        assert!(result2.is_none(), "missing file should return None");
    }

    #[test]
    fn test_legacy_snapshot_compat() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("legacy.json");

        // Write a ledger-only JSON (old format)
        let ledger = make_ledger();
        let json = serde_json::to_string(&ledger).unwrap();
        std::fs::write(&path, &json).unwrap();

        let loaded = load_snapshot(&path).unwrap().unwrap();
        assert_eq!(loaded.ledger.total_supply, 1_000_000);
        assert!(loaded.finalized.is_empty());
        assert!(loaded.epoch.is_none());
    }

    #[test]
    fn test_missing_snapshot() {
        let result = load_snapshot("/tmp/nonexistent-snapshot-12345.json").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_epoch_snapshot_roundtrip() {
        let epoch = make_epoch();
        let snap = epoch.to_snapshot();
        let restored = EpochState::from_snapshot(&snap);
        assert_eq!(restored.latest_epoch[&ZoneId::from_legacy(0)], 5);
        assert_eq!(restored.latest_seal_hash[&ZoneId::from_legacy(0)], [0xAA; 32]);
        assert_eq!(restored.next_epoch(&ZoneId::from_legacy(0)), 6);
    }

    // ── Governance state persistence ────────────────────────────────────

    fn make_ledger_with_governance() -> LedgerState {
        use crate::accounting::governance::{
            ProposalCategory, VoteDirection, DelegationEntry,
        };

        let mut ledger = LedgerState {
            total_supply: 5_000_000,
            records_processed: 100,
            ..Default::default()
        };

        // Create a proposal
        ledger.governance.create_proposal(
            "prop-001".into(),
            "alice-hash",
            ProposalCategory::Parameter,
            "Increase witness rewards".into(),
            "Raise from 1 beat to 2 beat per attestation".into(),
            2_000_000_000_000, // 2000 beat
            1741000000.0, None,
        ).unwrap();

        // Cast a vote
        ledger.governance.cast_vote(
            "prop-001",
            "bob-hash",
            VoteDirection::For,
            500_000_000_000, // 500 beat
            1741000100.0,
        ).unwrap();

        // Add a delegation
        ledger.governance.delegations.insert(
            "carol-hash".into(),
            DelegationEntry {
                delegator: "carol-hash".into(),
                delegate: "alice-hash".into(),
                created_at: 1741000050.0,
                active: true,
            },
        );

        ledger
    }

    #[test]
    fn test_governance_snapshot_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("gov-snapshot.json");
        let ledger = make_ledger_with_governance();
        let epoch = make_epoch();

        save_snapshot(&ledger, &HashSet::new(), &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        // Proposals survived
        assert_eq!(loaded.ledger.governance.proposals.len(), 1);
        let prop = &loaded.ledger.governance.proposals["prop-001"];
        assert_eq!(prop.title, "Increase witness rewards");
        assert_eq!(prop.proposer, "alice-hash");
        assert_eq!(prop.votes.len(), 1);
        assert_eq!(prop.votes[0].voter, "bob-hash");

        // Delegations survived
        assert_eq!(loaded.ledger.governance.delegations.len(), 1);
        let del = &loaded.ledger.governance.delegations["carol-hash"];
        assert_eq!(del.delegate, "alice-hash");
        assert!(del.active);
    }

    #[test]
    fn test_governance_vote_direction_serialization() {
        use crate::accounting::governance::VoteDirection;

        // VoteDirection should roundtrip through JSON
        let dir_for = serde_json::to_string(&VoteDirection::For).unwrap();
        let dir_against = serde_json::to_string(&VoteDirection::Against).unwrap();
        let dir_abstain = serde_json::to_string(&VoteDirection::Abstain).unwrap();

        assert_eq!(dir_for, "\"for\"");
        assert_eq!(dir_against, "\"against\"");
        assert_eq!(dir_abstain, "\"abstain\"");

        let restored: VoteDirection = serde_json::from_str(&dir_for).unwrap();
        assert_eq!(restored, VoteDirection::For);
    }

    #[test]
    fn test_governance_checksum_includes_governance() {
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("snap1.json");
        let path2 = dir.path().join("snap2.json");

        // Snapshot without governance
        let ledger1 = make_ledger();
        let epoch = make_epoch();
        save_snapshot(&ledger1, &HashSet::new(), &epoch, &path1).unwrap();

        // Snapshot with governance (same supply/accounts)
        let mut ledger2 = make_ledger();
        ledger2.governance.create_proposal(
            "prop-x".into(),
            "someone",
            crate::accounting::governance::ProposalCategory::Parameter,
            "Test".into(),
            "Test desc".into(),
            2_000_000_000_000,
            1741000000.0, None,
        ).unwrap();
        save_snapshot(&ledger2, &HashSet::new(), &epoch, &path2).unwrap();

        let snap1 = load_snapshot(&path1).unwrap().unwrap();
        let snap2 = load_snapshot(&path2).unwrap().unwrap();

        // Checksums must differ because governance state differs
        assert_ne!(
            snap1.checksum.unwrap(),
            snap2.checksum.unwrap(),
            "checksum should change when governance state differs"
        );
    }

    #[test]
    fn test_governance_snapshot_backward_compat() {
        // Simulate an old snapshot without governance (empty GovernanceState)
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old-format.json");
        let ledger = make_ledger();
        let epoch = EpochState::new();

        save_snapshot(&ledger, &HashSet::new(), &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        // Empty governance state should load fine
        assert!(loaded.ledger.governance.proposals.is_empty());
        assert!(loaded.ledger.governance.delegations.is_empty());
    }

    // ── Gap 7 slice 7.3: NodeSnapshot checksum covers latest_sealed_account ──

    #[test]
    fn gap7_slice73_checksum_changes_when_sealed_account_root_changes() {
        // Tampering the binding's root must invalidate the v5 checksum.
        // Without checksum coverage, a malicious /snapshot/latest server
        // could swap the (epoch, root) tuple under a still-valid signature
        // and steer light clients onto a dishonest seal commitment.
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("snap1.json");
        let path2 = dir.path().join("snap2.json");
        let ledger = make_ledger();
        let mut epoch1 = make_epoch();
        let mut epoch2 = make_epoch();
        let zone = ZoneId::from_legacy(0);
        epoch1.latest_sealed_account = Some((
            108,
            zone.clone(),
            "rec-bind-A".to_string(),
            [0xA1u8; 32],
            1234567890.0,
        ));
        epoch2.latest_sealed_account = Some((
            108,
            zone,
            "rec-bind-A".to_string(),
            [0xA2u8; 32], // root differs
            1234567890.0,
        ));
        save_snapshot(&ledger, &HashSet::new(), &epoch1, &path1).unwrap();
        save_snapshot(&ledger, &HashSet::new(), &epoch2, &path2).unwrap();
        let s1 = load_snapshot(&path1).unwrap().unwrap();
        let s2 = load_snapshot(&path2).unwrap().unwrap();
        assert_ne!(
            s1.checksum.unwrap(),
            s2.checksum.unwrap(),
            "checksum must change when sealed_account.root changes"
        );
    }

    #[test]
    fn gap7_slice73_checksum_changes_when_sealed_account_epoch_changes() {
        // Same chain-head defense from the epoch axis. Pins both halves of
        // the (epoch, root) tuple to the v5 checksum domain.
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("snap1.json");
        let path2 = dir.path().join("snap2.json");
        let ledger = make_ledger();
        let mut epoch1 = make_epoch();
        let mut epoch2 = make_epoch();
        let zone = ZoneId::from_legacy(0);
        epoch1.latest_sealed_account = Some((
            108,
            zone.clone(),
            "rec-bind".to_string(),
            [0xA1u8; 32],
            1234567890.0,
        ));
        epoch2.latest_sealed_account = Some((
            999, // epoch differs
            zone,
            "rec-bind".to_string(),
            [0xA1u8; 32],
            1234567890.0,
        ));
        save_snapshot(&ledger, &HashSet::new(), &epoch1, &path1).unwrap();
        save_snapshot(&ledger, &HashSet::new(), &epoch2, &path2).unwrap();
        let s1 = load_snapshot(&path1).unwrap().unwrap();
        let s2 = load_snapshot(&path2).unwrap().unwrap();
        assert_ne!(
            s1.checksum.unwrap(),
            s2.checksum.unwrap(),
            "checksum must change when sealed_account.epoch changes"
        );
    }

    #[test]
    fn gap7_slice73_checksum_stable_when_only_sealed_at_changes() {
        // The `sealed_at` f64 is excluded from the checksum (1-ulp risk
        // class — same reason zone_activity_rate was dropped in v4).
        // Two snapshots with identical bindings except for the timestamp
        // must hash to the same value, so a passive observer's clock skew
        // does not provoke spurious checksum mismatches.
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("snap1.json");
        let path2 = dir.path().join("snap2.json");
        let ledger = make_ledger();
        let mut epoch1 = make_epoch();
        let mut epoch2 = make_epoch();
        let zone = ZoneId::from_legacy(0);
        epoch1.latest_sealed_account = Some((
            108,
            zone.clone(),
            "rec-bind".to_string(),
            [0xA1u8; 32],
            1234567890.111111,
        ));
        epoch2.latest_sealed_account = Some((
            108,
            zone,
            "rec-bind".to_string(),
            [0xA1u8; 32],
            1234567890.999999, // only timestamp differs
        ));
        save_snapshot(&ledger, &HashSet::new(), &epoch1, &path1).unwrap();
        save_snapshot(&ledger, &HashSet::new(), &epoch2, &path2).unwrap();
        let s1 = load_snapshot(&path1).unwrap().unwrap();
        let s2 = load_snapshot(&path2).unwrap().unwrap();
        assert_eq!(
            s1.checksum.unwrap(),
            s2.checksum.unwrap(),
            "checksum must NOT change when only sealed_at differs"
        );
    }

    #[test]
    fn gap7_slice73_checksum_none_binding_round_trips() {
        // Pre-Gap-1 chains and fresh boots have None binding — must
        // produce a stable v5 checksum that survives save→load→verify.
        // Without this, every freshly-booted node would see a checksum
        // mismatch on its very first restart.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("snap-none.json");
        let ledger = make_ledger();
        let epoch = make_epoch(); // latest_sealed_account=None
        save_snapshot(&ledger, &HashSet::new(), &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();
        // load_snapshot internally re-runs compute_checksum and rejects
        // mismatches — successful Some(...) return = round-trip green.
        assert!(loaded.checksum.is_some());
        assert!(loaded
            .epoch
            .as_ref()
            .map(|e| e.latest_sealed_account.is_none())
            .unwrap_or(false));
    }

    #[test]
    fn test_governance_multiple_proposals_and_statuses() {
        use crate::accounting::governance::{ProposalCategory, VoteDirection};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multi-gov.json");
        let mut ledger = make_ledger();
        ledger.total_supply = 100_000_000_000; // 100K beat for participation check

        // Active proposal
        ledger.governance.create_proposal(
            "active-1".into(), "alice", ProposalCategory::Parameter,
            "Active".into(), "Still voting".into(), 2_000_000_000_000, 1741000000.0, None,
        ).unwrap();

        // Proposal that will be cancelled
        ledger.governance.create_proposal(
            "cancel-1".into(), "alice", ProposalCategory::Parameter,
            "Cancelled".into(), "Withdrawn".into(), 2_000_000_000_000, 1741000000.0, None,
        ).unwrap();
        ledger.governance.cancel_proposal("cancel-1", "alice").unwrap();

        // Proposal with multiple votes
        ledger.governance.create_proposal(
            "voted-1".into(), "bob", ProposalCategory::ZoneLocal,
            "Popular".into(), "Many votes".into(), 5_000_000_000_000, 1741000000.0, None,
        ).unwrap();
        ledger.governance.cast_vote("voted-1", "voter1", VoteDirection::For, 1_000_000_000, 1741000100.0).unwrap();
        ledger.governance.cast_vote("voted-1", "voter2", VoteDirection::Against, 500_000_000_000, 1741000200.0).unwrap();
        ledger.governance.cast_vote("voted-1", "voter3", VoteDirection::Abstain, 300_000_000, 1741000300.0).unwrap();

        let epoch = EpochState::new();
        save_snapshot(&ledger, &HashSet::new(), &epoch, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.ledger.governance.proposals.len(), 3);

        let active = &loaded.ledger.governance.proposals["active-1"];
        assert_eq!(active.status, crate::accounting::governance::ProposalStatus::Active);
        assert!(active.votes.is_empty());

        let cancelled = &loaded.ledger.governance.proposals["cancel-1"];
        assert_eq!(cancelled.status, crate::accounting::governance::ProposalStatus::Cancelled);

        let voted = &loaded.ledger.governance.proposals["voted-1"];
        assert_eq!(voted.votes.len(), 3);
        assert_eq!(voted.votes[0].direction, VoteDirection::For);
        assert_eq!(voted.votes[1].direction, VoteDirection::Against);
        assert_eq!(voted.votes[2].direction, VoteDirection::Abstain);
        assert_eq!(voted.category, ProposalCategory::ZoneLocal);
    }

    // ── Gap 7: epoch-indexed snapshot store ─────────────────────────────

    fn make_signed_snapshot(epoch_num: u64) -> NodeSnapshot {
        let mut ledger = make_ledger();
        ledger.total_supply = 1_000_000 + epoch_num;
        let mut epoch = EpochState::new();
        epoch.latest_epoch.insert(ZoneId::from_legacy(0), epoch_num);
        let mut snap = NodeSnapshot::new(ledger, HashSet::new(), epoch);
        snap.merkle_root = Some(hex::encode([epoch_num as u8; 32]));
        snap.record_count = Some(epoch_num * 10);
        snap.snapshot_timestamp = Some(1_700_000_000.0 + epoch_num as f64);
        snap.signer_identity = Some(format!("node-{:016}", epoch_num));
        snap.checksum = Some(compute_checksum(&snap));
        snap
    }

    #[test]
    fn mandate_carry_checksum_back_compat_content_bound_and_roundtrips() {
        use crate::mandate::{MandateRecord, MandateScope};

        let s_empty = NodeSnapshot::new(make_ledger(), HashSet::new(), EpochState::new());
        let checksum_empty = compute_checksum(&s_empty);

        // LEGACY SAFETY: a JSON literally MISSING the mandates/revocations fields
        // (an old snapshot) deserializes via serde(default) to empty maps and
        // computes the byte-identical checksum → it still verifies.
        let mut v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s_empty).unwrap()).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("mandates");
        obj.remove("revocations");
        assert!(!obj.contains_key("mandates"));
        let s_legacy: NodeSnapshot = serde_json::from_value(v).unwrap();
        assert!(s_legacy.mandates.is_empty() && s_legacy.revocations.is_empty());
        assert_eq!(
            compute_checksum(&s_legacy),
            checksum_empty,
            "legacy (no-field) snapshot must reproduce the identical checksum"
        );

        // CONTENT BOUND: adding a mandate changes the checksum (not count-only —
        // a different mandate of the same cardinality must also differ).
        let m = MandateRecord::new_root(
            "testnet", &"aa".repeat(32), &"bb".repeat(32), MandateScope::wildcard(), 0, 10, 0, "n0",
        );
        let mut s_one = s_empty.clone();
        s_one.mandates.insert(m.mandate_id(), m.clone());
        let checksum_one = compute_checksum(&s_one);
        assert_ne!(checksum_one, checksum_empty);

        let m2 = MandateRecord::new_root(
            "testnet", &"aa".repeat(32), &"cc".repeat(32), MandateScope::wildcard(), 0, 10, 0, "n0",
        );
        let mut s_other = s_empty.clone();
        s_other.mandates.insert(m2.mandate_id(), m2);
        assert_ne!(
            compute_checksum(&s_other),
            checksum_one,
            "same cardinality, different content → different checksum (swap-proof)"
        );

        // ROUND-TRIP: a carried mandate survives serialize→deserialize and the
        // checksum still matches.
        let json = serde_json::to_string(&s_one).unwrap();
        let loaded: NodeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.mandates.len(), 1);
        assert_eq!(compute_checksum(&loaded), checksum_one);
    }

    #[test]
    fn test_epoch_snapshot_filename_zero_padded() {
        assert_eq!(epoch_snapshot_filename(0), "epoch-000000000000.json");
        assert_eq!(epoch_snapshot_filename(100), "epoch-000000000100.json");
        assert_eq!(epoch_snapshot_filename(u64::MAX), format!("epoch-{:012}.json", u64::MAX));
    }

    #[test]
    fn test_parse_epoch_snapshot_filename() {
        assert_eq!(parse_epoch_snapshot_filename("epoch-000000000042.json"), Some(42));
        assert_eq!(parse_epoch_snapshot_filename("epoch-000000000000.json"), Some(0));
        assert_eq!(parse_epoch_snapshot_filename("snapshot.json"), None);
        assert_eq!(parse_epoch_snapshot_filename("epoch-abc.json"), None);
        assert_eq!(parse_epoch_snapshot_filename("epoch-42.txt"), None);
    }

    #[test]
    fn test_save_and_load_epoch_snapshot() {
        let dir = TempDir::new().unwrap();
        let snap = make_signed_snapshot(100);
        let path = save_epoch_snapshot(dir.path(), 100, &snap).unwrap();
        assert!(path.exists());

        let loaded = load_epoch_snapshot(dir.path(), 100).unwrap().unwrap();
        assert_eq!(loaded.ledger.total_supply, 1_000_100);
        assert_eq!(loaded.record_count, Some(1000));

        // Missing epoch returns None, not an error
        let missing = load_epoch_snapshot(dir.path(), 999).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_list_epoch_snapshots_sorted() {
        let dir = TempDir::new().unwrap();
        // Save out of order on purpose
        for n in [200u64, 50, 100, 150, 10] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        // Also drop an unrelated file — must be ignored
        std::fs::write(dir.path().join("unrelated.txt"), b"ignore me").unwrap();
        std::fs::write(dir.path().join("snapshot.json"), b"{}").unwrap();

        let epochs = list_epoch_snapshots(dir.path()).unwrap();
        assert_eq!(epochs, vec![10, 50, 100, 150, 200]);
    }

    #[test]
    fn test_list_epoch_snapshots_missing_dir_is_empty() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist");
        let epochs = list_epoch_snapshots(&missing).unwrap();
        assert!(epochs.is_empty());
    }

    #[test]
    fn test_latest_epoch_snapshot() {
        let dir = TempDir::new().unwrap();
        // Empty dir returns None
        assert!(latest_epoch_snapshot(dir.path()).unwrap().is_none());

        for n in [10u64, 20, 30] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        let (epoch, snap) = latest_epoch_snapshot(dir.path()).unwrap().unwrap();
        assert_eq!(epoch, 30);
        assert_eq!(snap.record_count, Some(300));
    }

    #[test]
    fn test_load_epoch_snapshot_at_or_before() {
        let dir = TempDir::new().unwrap();
        // Empty dir → None for any target.
        assert!(load_epoch_snapshot_at_or_before(dir.path(), 0).unwrap().is_none());
        assert!(load_epoch_snapshot_at_or_before(dir.path(), 999).unwrap().is_none());

        // Sparse cadence — every-10-epochs default.
        for n in [10u64, 20, 30] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }

        // Exact match at a stride epoch.
        let (epoch, _) = load_epoch_snapshot_at_or_before(dir.path(), 20).unwrap().unwrap();
        assert_eq!(epoch, 20);

        // Off-stride: client claims epoch 25 → falls back to 20.
        let (epoch, _) = load_epoch_snapshot_at_or_before(dir.path(), 25).unwrap().unwrap();
        assert_eq!(epoch, 20, "off-stride lookup must return the largest e ≤ target");

        // Beyond latest: client claims epoch 999 → returns 30.
        let (epoch, _) = load_epoch_snapshot_at_or_before(dir.path(), 999).unwrap().unwrap();
        assert_eq!(epoch, 30);

        // Below earliest: client claims epoch 5 → no baseline available.
        assert!(load_epoch_snapshot_at_or_before(dir.path(), 5).unwrap().is_none());

        // Exact match at the lowest stored epoch.
        let (epoch, _) = load_epoch_snapshot_at_or_before(dir.path(), 10).unwrap().unwrap();
        assert_eq!(epoch, 10);
    }

    #[test]
    fn test_prune_keeps_last_n() {
        let dir = TempDir::new().unwrap();
        for n in [10u64, 20, 30, 40, 50] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        let deleted = prune_old_epoch_snapshots(dir.path(), 3).unwrap();
        assert_eq!(deleted, 2);

        let remaining = list_epoch_snapshots(dir.path()).unwrap();
        assert_eq!(remaining, vec![30, 40, 50], "must keep the 3 most recent");
    }

    #[test]
    fn test_prune_with_fewer_than_keep() {
        let dir = TempDir::new().unwrap();
        for n in [10u64, 20] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        let deleted = prune_old_epoch_snapshots(dir.path(), 5).unwrap();
        assert_eq!(deleted, 0);

        let remaining = list_epoch_snapshots(dir.path()).unwrap();
        assert_eq!(remaining, vec![10, 20]);
    }

    #[test]
    fn test_prune_zero_is_noop() {
        let dir = TempDir::new().unwrap();
        for n in [10u64, 20, 30] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        let deleted = prune_old_epoch_snapshots(dir.path(), 0).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn test_epoch_snapshot_checksum_verified_on_load() {
        let dir = TempDir::new().unwrap();
        let snap = make_signed_snapshot(42);
        let path = save_epoch_snapshot(dir.path(), 42, &snap).unwrap();

        // Tamper: flip a byte
        let mut data = std::fs::read_to_string(&path).unwrap();
        data = data.replace("1000042", "9000042");
        std::fs::write(&path, &data).unwrap();

        // load_epoch_snapshot delegates to load_snapshot, so checksum mismatch
        // returns None and renames the corrupt file.
        let loaded = load_epoch_snapshot(dir.path(), 42).unwrap();
        assert!(loaded.is_none(), "corrupt epoch snapshot should return None");
    }

    #[test]
    fn test_checksum_stable_across_roundtrips() {
        // Verify that save→load→save→load produces identical checksums.
        // This catches the bug where `{:?}` Debug format produced different
        // output across process restarts (v2 checksum format).
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("round1.json");
        let path2 = dir.path().join("round2.json");

        let ledger = make_ledger_with_governance();
        let mut finalized = HashSet::new();
        for i in 0..100 {
            finalized.insert(format!("rec-{i:04}"));
        }
        let epoch = make_epoch();

        // Round 1: save and load
        save_snapshot(&ledger, &finalized, &epoch, &path1).unwrap();
        let loaded1 = load_snapshot(&path1).unwrap().unwrap();
        let checksum1 = loaded1.checksum.clone().unwrap();

        // Round 2: save the loaded data and load again
        save_snapshot(&loaded1.ledger, &loaded1.finalized, &loaded1.epoch_state(), &path2).unwrap();
        let loaded2 = load_snapshot(&path2).unwrap().unwrap();
        let checksum2 = loaded2.checksum.clone().unwrap();

        assert_eq!(checksum1, checksum2,
            "checksum must be identical after save→load→save→load roundtrip");
    }

    /// v4 regression test (2026-04-28): the v3 checksum included f64 fields
    /// (zone_activity_rate) via serde_json. ryu-formatted f64 strings do not
    /// always parse back to the same f64 bits in serde_json — see writer
    /// produces "0.11168954035834365" → reader's parse → ryu re-encoded as
    /// "0.11168954035834364". This produced "snapshot checksum mismatch" on
    /// 3 of 6 testnet nodes per restart batch. The fix is v4: drop the only
    /// f64-valued field from the hash. This test seeds zone_activity_rate
    /// with the exact value that triggered the bug in production and
    /// verifies the checksum is now stable across the JSON round-trip.
    #[test]
    fn test_checksum_stable_with_zone_activity_rate_f64_round_trip() {
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("v4_round1.json");
        let path2 = dir.path().join("v4_round2.json");

        let ledger = make_ledger_with_governance();
        let mut finalized = HashSet::new();
        for i in 0..50 {
            finalized.insert(format!("rec-{i:04}"));
        }
        let mut epoch = make_epoch();
        // The exact f64 from production snapshots that triggered
        // the v3 round-trip bug. Both values are in the "ulp drift" zone of
        // serde_json's f64 round-trip.
        epoch.zone_activity_rate.insert(ZoneId::from_legacy(0), 0.11168954035834365_f64);
        epoch.zone_activity_rate.insert(ZoneId::from_legacy(1), 0.10555818615216817_f64);

        save_snapshot(&ledger, &finalized, &epoch, &path1).unwrap();
        let loaded1 = load_snapshot(&path1).unwrap()
            .expect("v4 snapshot must verify checksum on first load");
        let checksum1 = loaded1.checksum.clone().unwrap();

        // Saving the loaded state must produce the same checksum after another round-trip.
        save_snapshot(&loaded1.ledger, &loaded1.finalized, &loaded1.epoch_state(), &path2).unwrap();
        let loaded2 = load_snapshot(&path2).unwrap()
            .expect("v4 snapshot must verify checksum after second round-trip");
        let checksum2 = loaded2.checksum.clone().unwrap();

        assert_eq!(checksum1, checksum2,
            "v4: checksum must be stable across JSON round-trip even with f64 values that don't ulp-roundtrip in serde_json");
    }

    // ── PQ-R2: verify_signed_snapshot must actually verify ──────────────

    fn sign_test_snapshot(profile: crate::identity::CryptoProfile) -> (NodeSnapshot, crate::identity::Identity) {
        use crate::identity::{EntityType, Identity};
        let identity = Identity::generate(EntityType::Device, profile).unwrap();
        let ledger = make_ledger();
        let finalized = HashSet::new();
        let epoch = make_epoch();
        let snap = create_signed_snapshot(SignedSnapshotInputs {
            ledger: &ledger,
            finalized: &finalized,
            epoch: &epoch,
            genesis_state: None,
            bootstrap_state: None,
            merkle_root: [0xBEu8; 32],
            record_count: 42,
            identity: &identity,
            account_state_root: None,
            mandates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            emergency: None,
        }).unwrap();
        (snap, identity)
    }

    #[test]
    fn test_g3_snapshot_roundtrip_preserves_bootstrap_claimed() {
        // G3 (internal design notes §2): a signed snapshot served to a
        // bootstrapping peer MUST carry genesis_state (incl. bootstrap_claimed),
        // or the 10K cap / per-identity dedup is unenforceable across a
        // snapshot-bootstrap. All three production serve/emit paths pass
        // Some(&genesis_state) and apply_bootstrap_snapshot_full installs it;
        // this pins that a non-empty claimed-set survives signing + the JSON wire
        // round-trip the serve route uses (`Json(snapshot)`).
        use crate::identity::{CryptoProfile, EntityType, Identity};

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let ledger = make_ledger();
        let finalized = HashSet::new();
        let epoch = make_epoch();

        let mut gs = crate::accounting::genesis::GenesisState::initialize(0.0);
        gs.claim_bootstrap("claimant_node_1").unwrap();
        gs.claim_bootstrap("claimant_node_2").unwrap();

        let snap = create_signed_snapshot(SignedSnapshotInputs {
            ledger: &ledger,
            finalized: &finalized,
            epoch: &epoch,
            genesis_state: Some(&gs),
            bootstrap_state: None,
            merkle_root: [0xBEu8; 32],
            record_count: 42,
            identity: &identity,
            account_state_root: None,
            mandates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            emergency: None,
        })
        .unwrap();

        // The serve route returns `Json(snapshot)`; a joiner deserializes + applies.
        // Round-trip through the same wire form.
        let wire = serde_json::to_vec(&snap).unwrap();
        let loaded: NodeSnapshot = serde_json::from_slice(&wire).unwrap();

        // genesis_state is checksum-bound, so the signature must still verify.
        verify_signed_snapshot(&loaded).expect("round-tripped snapshot must verify");

        let gs2 = loaded
            .genesis_state
            .expect("G3: genesis_state must survive the wire (not dropped to None)");
        assert_eq!(
            gs2.bootstrap_claimed.len(),
            2,
            "G3: bootstrap_claimed must survive snapshot serve -> wire"
        );
        assert!(gs2.bootstrap_claimed.contains("claimant_node_1"));
        assert!(gs2.bootstrap_claimed.contains("claimant_node_2"));
    }

    #[test]
    fn test_verify_signed_snapshot_golden_profile_b() {
        let (snap, identity) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        assert!(snap.signature.is_some(), "Dilithium3 sig must be populated");
        assert!(snap.signer_public_key.is_some(), "signer_public_key must be populated");
        assert!(snap.sphincs_signature.is_none(), "Profile B has no SPHINCS+ sig");
        assert!(snap.signer_sphincs_public_key.is_none(), "Profile B has no SPHINCS+ pk");
        let signer = verify_signed_snapshot(&snap).expect("Profile B snapshot must verify");
        assert_eq!(signer, identity.identity_hash);
    }

    #[test]
    fn test_verify_signed_snapshot_golden_profile_a_dual_sig() {
        let (snap, identity) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileA);
        assert!(snap.signature.is_some());
        assert!(snap.sphincs_signature.is_some(), "Profile A has SPHINCS+ sig");
        assert!(snap.signer_sphincs_public_key.is_some(), "Profile A has SPHINCS+ pk");
        let signer = verify_signed_snapshot(&snap).expect("Profile A snapshot must verify");
        assert_eq!(signer, identity.identity_hash);
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_forged_dilithium_sig() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        // Flip a byte in the middle of the signature hex — stays valid hex, invalid sig.
        let mut sig_hex = snap.signature.clone().unwrap();
        let mid = sig_hex.len() / 2;
        let byte = sig_hex.as_bytes()[mid];
        let replacement = if byte == b'0' { '1' } else { '0' };
        sig_hex.replace_range(mid..=mid, &replacement.to_string());
        snap.signature = Some(sig_hex);
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("Dilithium3"), "expected Dilithium3 error, got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_forged_sphincs_sig() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileA);
        let mut sig_hex = snap.sphincs_signature.clone().unwrap();
        let mid = sig_hex.len() / 2;
        let byte = sig_hex.as_bytes()[mid];
        let replacement = if byte == b'0' { '1' } else { '0' };
        sig_hex.replace_range(mid..=mid, &replacement.to_string());
        snap.sphincs_signature = Some(sig_hex);
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("SPHINCS"), "expected SPHINCS error, got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_checksum_tamper() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        // Mutate ledger without recomputing checksum — checksum will mismatch.
        snap.ledger.total_supply += 1;
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "expected checksum mismatch, got: {err}");
    }

    /// Gap 7: when the producer populates `account_state_root`, the field
    /// must be bound by the checksum/signature. A MITM that flips the hex
    /// value, or strips the field entirely, must break verify — otherwise the
    /// consumer-side post-apply check would be telemetry built on forgeable
    /// data.
    #[test]
    fn test_gap7_account_state_root_tamper_breaks_verify() {
        use crate::identity::{EntityType, Identity};
        // Build a signed snapshot WITH account_state_root populated.
        let identity = Identity::generate(EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        let ledger = make_ledger();
        let finalized = HashSet::new();
        let epoch = make_epoch();
        let producer_root: [u8; 32] = [0xA5u8; 32];
        let snap = create_signed_snapshot(SignedSnapshotInputs {
            ledger: &ledger,
            finalized: &finalized,
            epoch: &epoch,
            genesis_state: None,
            bootstrap_state: None,
            merkle_root: [0xBEu8; 32],
            record_count: 42,
            identity: &identity,
            account_state_root: Some(producer_root),
            mandates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            emergency: None,
        }).unwrap();
        assert_eq!(snap.account_state_root, Some(hex::encode(producer_root)));
        // Pristine snapshot verifies.
        verify_signed_snapshot(&snap).expect("pristine snapshot must verify");
        // Flip the hex → checksum recompute differs → verify fails.
        let mut flipped = snap.clone();
        flipped.account_state_root = Some(hex::encode([0xFFu8; 32]));
        let err = verify_signed_snapshot(&flipped).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "flipped root must fail checksum, got: {err}");
        // Strip the field → checksum recompute reverts to v5-only → verify fails.
        let mut stripped = snap.clone();
        stripped.account_state_root = None;
        let err = verify_signed_snapshot(&stripped).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "stripped root must fail checksum, got: {err}");
    }

    /// Back-compat: snapshots that never had `account_state_root` populated
    /// (None on the wire) verify exactly as v5 did — no checksum drift.
    #[test]
    fn test_gap7_legacy_snapshot_without_root_still_verifies() {
        let (snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        assert!(snap.account_state_root.is_none(), "test fixture must omit the field");
        verify_signed_snapshot(&snap).expect("legacy snapshot must verify under v5 checksum");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_identity_pubkey_mismatch() {
        use crate::identity::{EntityType, Identity};
        // Create snapshot signed by `real`, but substitute `other`'s pubkey.
        let (mut snap, _real) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        let other = Identity::generate(EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        snap.signer_public_key = Some(hex::encode(&other.public_key));
        // signer_identity still points at `real`'s hash → pk hash won't match.
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(
            err.contains("does not match hash of signer_public_key"),
            "expected identity/pubkey mismatch, got: {err}",
        );
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_substituted_signer() {
        use crate::identity::{EntityType, Identity};
        // Take a valid snapshot, swap BOTH pubkey + identity to another signer.
        // Signature was generated with real's key → fails verify under other's pk.
        let (mut snap, _real) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        let other = Identity::generate(EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        snap.signer_public_key = Some(hex::encode(&other.public_key));
        snap.signer_identity = Some(other.identity_hash.clone());
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("Dilithium3"), "expected Dilithium3 verify failure, got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_missing_pubkey() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.signer_public_key = None;
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("missing signer_public_key"), "got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_sphincs_sig_without_pubkey() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileA);
        // Strip pubkey but keep signature — should reject.
        snap.signer_sphincs_public_key = None;
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("missing signer_sphincs_public_key"), "got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_sphincs_pubkey_without_sig() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileA);
        // Strip sig but keep pubkey — should reject (prevents half-sig downgrade).
        snap.sphincs_signature = None;
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(err.contains("missing sphincs_signature"), "got: {err}");
    }

    // PQ-R2: trust-gate tests. verify_signed_snapshot only proves the bytes
    // were signed by *some* PQ key; the trust gate is what proves the signer
    // is one we accept. Without these checks, a node serving a forged
    // snapshot can hijack a bootstrapping peer's ledger.

    #[test]
    fn test_enforce_signer_trust_accepts_signer_in_set() {
        let signer = "abc123def456";
        let trust_set = ["other_signer", signer, "another"];
        enforce_snapshot_signer_trust(signer, &trust_set).unwrap();
    }

    #[test]
    fn test_enforce_signer_trust_rejects_signer_not_in_set() {
        let signer = "untrusted_signer_id";
        let trust_set = ["genesis_authority_hash", "operator_anchor_hash"];
        let err = enforce_snapshot_signer_trust(signer, &trust_set).unwrap_err().to_string();
        assert!(
            err.contains("not in the trusted-signer set"),
            "expected trust-set rejection, got: {err}"
        );
        assert!(err.contains("2 entries"), "expected entry-count in err, got: {err}");
    }

    #[test]
    fn test_enforce_signer_trust_rejects_empty_trust_set() {
        // Empty trust set MUST NOT default-allow — that would re-open the
        // hole this gate exists to close.
        let err = enforce_snapshot_signer_trust("any_signer", &[]).unwrap_err().to_string();
        assert!(
            err.contains("no trusted signers configured"),
            "expected empty-set rejection, got: {err}"
        );
    }

    #[test]
    fn test_enforce_signer_trust_short_signer_does_not_panic() {
        // Defensive: signer shorter than 16 chars is unusual but the helper
        // truncates to 16 in the error message. Ensure no slice panic.
        let signer = "short";
        let trust_set = ["genesis_hash"];
        let err = enforce_snapshot_signer_trust(signer, &trust_set).unwrap_err().to_string();
        assert!(err.contains("short..."), "got: {err}");
    }

    // ── Tier 1.3: Old Node Contamination — algorithm-size + version gates ──

    #[test]
    fn test_verify_signed_snapshot_rejects_wrong_dilithium_pk_size() {
        // Signer pubkey shorter than 1952 bytes — should trigger the
        // algorithm-size gate before the hash-binding check.
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.signer_public_key = Some(hex::encode(vec![0u8; 100]));
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(
            err.contains("wrong size for Dilithium3"),
            "expected algorithm-size rejection, got: {err}"
        );
        assert!(err.contains("expected 1952 bytes, got 100"), "got: {err}");
    }

    #[test]
    fn test_verify_signed_snapshot_rejects_wrong_sphincs_pk_size() {
        // Profile A snapshot with a SPHINCS+ pubkey of the wrong size —
        // should trigger the SLH-DSA size gate before signature verify.
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileA);
        snap.signer_sphincs_public_key = Some(hex::encode(vec![0u8; 32]));
        let err = verify_signed_snapshot(&snap).unwrap_err().to_string();
        assert!(
            err.contains("wrong size for SPHINCS+"),
            "expected SPHINCS+ size rejection, got: {err}"
        );
        assert!(err.contains("expected 48 bytes, got 32"), "got: {err}");
    }

    #[test]
    fn test_signed_snapshot_carries_protocol_version() {
        // Sanity: every freshly created snapshot must self-report the
        // current protocol version.
        let (snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        assert_eq!(
            snap.protocol_version,
            Some(crate::network::config::PROTOCOL_VERSION),
            "fresh snapshots must carry the current protocol version"
        );
    }

    #[test]
    fn test_enforce_protocol_version_min_zero_disables_gate() {
        // min_version == 0 short-circuits — even a None protocol_version
        // (legacy snapshot) passes when the operator hasn't set a floor.
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.protocol_version = None;
        enforce_snapshot_protocol_version(&snap, 0).unwrap();
        snap.protocol_version = Some(0);
        enforce_snapshot_protocol_version(&snap, 0).unwrap();
        snap.protocol_version = Some(7);
        enforce_snapshot_protocol_version(&snap, 0).unwrap();
    }

    #[test]
    fn test_enforce_protocol_version_accepts_equal_or_higher() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.protocol_version = Some(3);
        enforce_snapshot_protocol_version(&snap, 3).unwrap();
        enforce_snapshot_protocol_version(&snap, 1).unwrap();
    }

    #[test]
    fn test_enforce_protocol_version_rejects_old() {
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.protocol_version = Some(1);
        let err = enforce_snapshot_protocol_version(&snap, 5).unwrap_err().to_string();
        assert!(
            err.contains("protocol_version 1 < required minimum 5"),
            "expected old-version rejection, got: {err}"
        );
    }

    #[test]
    fn test_enforce_protocol_version_rejects_legacy_when_min_set() {
        // Legacy snapshots (None protocol_version) are treated as version 0,
        // so any non-zero min_version rejects them.
        let (mut snap, _id) = sign_test_snapshot(crate::identity::CryptoProfile::ProfileB);
        snap.protocol_version = None;
        let err = enforce_snapshot_protocol_version(&snap, 1).unwrap_err().to_string();
        assert!(
            err.contains("protocol_version 0 < required minimum 1"),
            "expected legacy-snapshot rejection, got: {err}"
        );
    }

    // ── StateDelta sign/verify + diff ────────────────────────

    fn make_account(available: u64, staked: u64) -> crate::accounting::ledger::AccountState {
        crate::accounting::ledger::AccountState {
            available,
            staked,
            ..Default::default()
        }
    }

    fn sign_test_state_delta(
        profile: crate::identity::CryptoProfile,
        changed: BTreeMap<String, crate::accounting::ledger::AccountState>,
        removed: Vec<String>,
    ) -> (StateDelta, crate::identity::Identity) {
        use crate::identity::{EntityType, Identity};
        let identity = Identity::generate(EntityType::Device, profile).unwrap();
        let total_accounts = changed.len() as u64;
        let delta = create_signed_state_delta(StateDeltaInputs {
            since_epoch: 100,
            current_epoch: 110,
            baseline_available: true,
            account_state_root: [0xC0u8; 32],
            merkle_root: [0xDEu8; 32],
            latest_super_seal_epoch: Some(64),
            latest_super_seal_record_hash: Some([0x55u8; 32]),
            latest_sealed_account_epoch: Some(108),
            latest_sealed_account_smt_root: Some([0xA1u8; 32]),
            changed_accounts: changed,
            removed_accounts: removed,
            total_accounts,
            total_supply: 1_000_000,
            total_staked: 200_000,
            identity: &identity,
        }).unwrap();
        (delta, identity)
    }

    #[test]
    fn test_state_delta_diff_basic() {
        let mut prior = std::collections::HashMap::new();
        prior.insert("acct-a".to_string(), make_account(100, 0));
        prior.insert("acct-b".to_string(), make_account(50, 25));
        prior.insert("acct-c-removed".to_string(), make_account(7, 0));

        let mut current = std::collections::HashMap::new();
        current.insert("acct-a".to_string(), make_account(100, 0)); // unchanged
        current.insert("acct-b".to_string(), make_account(60, 25)); // changed
        current.insert("acct-d-new".to_string(), make_account(1, 0)); // new
        // acct-c-removed is gone

        let (changed, removed) = diff_account_states(&prior, &current);
        assert_eq!(changed.len(), 2, "should contain b (changed) + d (new)");
        assert!(changed.contains_key("acct-b"));
        assert!(changed.contains_key("acct-d-new"));
        assert!(!changed.contains_key("acct-a"), "unchanged accounts must not be emitted");
        assert_eq!(removed, vec!["acct-c-removed".to_string()]);
    }

    #[test]
    fn test_state_delta_diff_empty_prior() {
        // baseline_available=false case: prior is empty → all current is "changed"
        let prior = std::collections::HashMap::new();
        let mut current = std::collections::HashMap::new();
        current.insert("a".to_string(), make_account(10, 0));
        current.insert("b".to_string(), make_account(20, 0));

        let (changed, removed) = diff_account_states(&prior, &current);
        assert_eq!(changed.len(), 2);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_state_delta_verify_profile_b() {
        let mut changed = BTreeMap::new();
        changed.insert("a".to_string(), make_account(50, 0));
        let (delta, identity) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            changed,
            vec![],
        );
        assert!(!delta.signature.is_empty(), "Dilithium3 sig must be populated");
        assert!(!delta.signer_public_key.is_empty());
        assert!(delta.sphincs_signature.is_none(), "Profile B has no SPHINCS+");
        let signer = verify_signed_state_delta(&delta)
            .expect("Profile B state-delta must verify");
        assert_eq!(signer, identity.identity_hash);
    }

    #[test]
    fn test_state_delta_verify_profile_a_dual_sig() {
        let mut changed = BTreeMap::new();
        changed.insert("a".to_string(), make_account(50, 0));
        let (delta, identity) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileA,
            changed,
            vec![],
        );
        assert!(delta.sphincs_signature.is_some(), "Profile A has SPHINCS+ sig");
        assert!(delta.signer_sphincs_public_key.is_some());
        let signer = verify_signed_state_delta(&delta)
            .expect("Profile A state-delta must verify");
        assert_eq!(signer, identity.identity_hash);
    }

    #[test]
    fn test_state_delta_rejects_checksum_tamper() {
        let mut changed = BTreeMap::new();
        changed.insert("a".to_string(), make_account(50, 0));
        let (mut delta, _id) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            changed,
            vec![],
        );
        // Mutate balance without recomputing checksum.
        if let Some(state) = delta.changed_accounts.get_mut("a") {
            state.available += 1;
        }
        let err = verify_signed_state_delta(&delta).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "expected checksum mismatch, got: {err}");
    }

    #[test]
    fn test_state_delta_rejects_forged_dilithium_sig() {
        let mut changed = BTreeMap::new();
        changed.insert("a".to_string(), make_account(50, 0));
        let (mut delta, _id) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            changed,
            vec![],
        );
        let mut sig_hex = delta.signature.clone();
        let mid = sig_hex.len() / 2;
        let byte = sig_hex.as_bytes()[mid];
        let replacement = if byte == b'0' { '1' } else { '0' };
        sig_hex.replace_range(mid..=mid, &replacement.to_string());
        delta.signature = sig_hex;
        let err = verify_signed_state_delta(&delta).unwrap_err().to_string();
        assert!(err.contains("Dilithium3"), "expected Dilithium3 error, got: {err}");
    }

    #[test]
    fn test_state_delta_rejects_pubkey_substitution() {
        use crate::identity::{EntityType, Identity};
        let mut changed = BTreeMap::new();
        changed.insert("a".to_string(), make_account(50, 0));
        let (mut delta, _real) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            changed,
            vec![],
        );
        let other = Identity::generate(EntityType::Device, crate::identity::CryptoProfile::ProfileB).unwrap();
        delta.signer_public_key = hex::encode(&other.public_key);
        let err = verify_signed_state_delta(&delta).unwrap_err().to_string();
        assert!(
            err.contains("does not match hash of signer_public_key"),
            "expected identity/pubkey mismatch, got: {err}",
        );
    }

    #[test]
    fn test_state_delta_round_trip_via_json() {
        // Simulates wire transport. sign locally → JSON → bytes → deserialize → verify.
        let mut changed = BTreeMap::new();
        changed.insert("acct-a".to_string(), make_account(123, 45));
        changed.insert("acct-b".to_string(), make_account(7, 0));
        let (delta, identity) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileA,
            changed,
            vec!["acct-c-gone".to_string()],
        );
        let json = serde_json::to_string(&delta).unwrap();
        let restored: StateDelta = serde_json::from_str(&json).unwrap();
        let signer = verify_signed_state_delta(&restored)
            .expect("round-tripped delta must verify");
        assert_eq!(signer, identity.identity_hash);
        assert_eq!(restored.changed_accounts.len(), 2);
        assert_eq!(restored.removed_accounts, vec!["acct-c-gone".to_string()]);
    }

    // ── Gap 7 slice 7.1: latest_sealed_account binding ─────────────────

    #[test]
    fn gap7_slice71_state_delta_carries_sealed_account_binding() {
        // The `sign_test_state_delta` helper now populates the binding
        // (epoch=108, root=[0xA1; 32]). Verify it survives serialize round-trip.
        let mut changed = BTreeMap::new();
        changed.insert("acct".to_string(), make_account(1, 0));
        let (delta, _identity) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            changed,
            vec![],
        );
        assert_eq!(delta.latest_sealed_account_epoch, Some(108));
        assert_eq!(
            delta.latest_sealed_account_smt_root.as_deref(),
            Some(hex::encode([0xA1u8; 32]).as_str())
        );
        let json = serde_json::to_string(&delta).unwrap();
        let restored: StateDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.latest_sealed_account_epoch, delta.latest_sealed_account_epoch);
        assert_eq!(restored.latest_sealed_account_smt_root, delta.latest_sealed_account_smt_root);
        verify_signed_state_delta(&restored)
            .expect("delta with sealed-account binding must verify");
    }

    #[test]
    fn gap7_slice71_state_delta_rejects_tampered_sealed_account_root() {
        // Mutate latest_sealed_account_smt_root post-sign — checksum recompute
        // must fail. Pins that the binding is covered by the v2 checksum.
        let (mut delta, _id) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            BTreeMap::new(),
            vec![],
        );
        // Original root was [0xA1; 32]. Flip one byte.
        delta.latest_sealed_account_smt_root = Some(hex::encode([0xA2u8; 32]));
        let err = verify_signed_state_delta(&delta).unwrap_err().to_string();
        assert!(
            err.contains("checksum mismatch"),
            "expected checksum-bound rejection on tampered sealed-account root, got: {err}"
        );
    }

    #[test]
    fn gap7_slice71_state_delta_rejects_tampered_sealed_account_epoch() {
        // Same chain-head defense from the epoch axis: a malicious server
        // that swaps a stale binding for a newer epoch (or vice versa) must
        // fail verify. Pins both halves of the (epoch, root) tuple.
        let (mut delta, _id) = sign_test_state_delta(
            crate::identity::CryptoProfile::ProfileB,
            BTreeMap::new(),
            vec![],
        );
        delta.latest_sealed_account_epoch = Some(999);
        let err = verify_signed_state_delta(&delta).unwrap_err().to_string();
        assert!(
            err.contains("checksum mismatch"),
            "expected checksum-bound rejection on tampered sealed-account epoch, got: {err}"
        );
    }

    #[test]
    fn gap7_slice71_state_delta_none_binding_legacy_node() {
        // Pre-Gap-1 / freshly-booted nodes have no `latest_sealed_account`
        // yet. Producer must still sign cleanly with both fields = None and
        // verifier must accept — operators on chains pre-instrumentation
        // can't be locked out of the delta endpoint.
        use crate::identity::{EntityType, Identity, CryptoProfile};
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let delta = create_signed_state_delta(StateDeltaInputs {
            since_epoch: 0,
            current_epoch: 5,
            baseline_available: false,
            account_state_root: [0u8; 32],
            merkle_root: [0u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: BTreeMap::new(),
            removed_accounts: vec![],
            total_accounts: 0,
            total_supply: 0,
            total_staked: 0,
            identity: &identity,
        }).unwrap();
        assert_eq!(delta.latest_sealed_account_epoch, None);
        assert_eq!(delta.latest_sealed_account_smt_root, None);
        verify_signed_state_delta(&delta)
            .expect("None-binding delta must verify on legacy chain heads");
    }

    #[test]
    fn prune_old_epoch_snapshots_pre_prune_pattern_caps_peak_at_keep_n() {
        // Pins the archive_snapshot_loop fix: with keep_n=3 and
        // 3 existing snapshots, the canonical order is
        //   pre-prune(keep_n-1=2) → save(new) → post-prune(keep_n=3).
        // Without pre-prune, the dir momentarily holds 4 snapshots before
        // post-prune trims back to 3 — the disk-doubling window that bit
        // the checkpoint_loop. With pre-prune, peak occupancy = 3,
        // matching keep_n exactly. Same regression class as
        // rotate_checkpoints_keep_zero_removes_all in bin/elara_node.rs.
        let dir = TempDir::new().unwrap();
        for n in [10u64, 20, 30] {
            let snap = make_signed_snapshot(n);
            save_epoch_snapshot(dir.path(), n, &snap).unwrap();
        }
        // Pre-prune: drops oldest (10), keeps last 2 (20, 30)
        let pre = prune_old_epoch_snapshots(dir.path(), 2).unwrap();
        assert_eq!(pre, 1, "pre-prune should delete exactly 1 (the oldest)");
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap(), vec![20, 30]);
        // Save new epoch 40 — dir now at keep_n=3 (matches the cap)
        let snap40 = make_signed_snapshot(40);
        save_epoch_snapshot(dir.path(), 40, &snap40).unwrap();
        let mid = list_epoch_snapshots(dir.path()).unwrap();
        assert_eq!(mid, vec![20, 30, 40],
            "peak occupancy must equal keep_n=3, NOT keep_n+1=4");
        // Post-prune: no-op since we're already at keep_n
        let post = prune_old_epoch_snapshots(dir.path(), 3).unwrap();
        assert_eq!(post, 0, "post-prune is a safety no-op after pre-prune");
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap(), vec![20, 30, 40]);
    }

    #[test]
    fn prune_old_epoch_snapshots_keep_one_documented_limitation() {
        // PINS the documented limitation of the archive_snapshot_loop
        // fix: when keep_n=1, saturating_sub(1)=0 and prune_old_epoch_snapshots
        // short-circuits as no-op, so peak occupancy stays at 2 (pre-existing
        // snapshot + new one) before post-prune trims to 1. Different from
        // the rotate_checkpoints(_, 0) which removes all entries.
        // This is acceptable because (a) the default `archive_snapshot_retention`
        // is 20, far above the limitation threshold; (b) the keep_n=1 case
        // still trims back to 1 immediately after save. Without this fix
        // keep_n>=2 cases peaked at N+1; with it they peak at N.
        let dir = TempDir::new().unwrap();
        let snap_a = make_signed_snapshot(100);
        save_epoch_snapshot(dir.path(), 100, &snap_a).unwrap();

        // Pre-prune to 0 (saturating_sub of keep_n=1) — short-circuit no-op
        let pre = prune_old_epoch_snapshots(dir.path(), 0).unwrap();
        assert_eq!(pre, 0);
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap(), vec![100],
            "pre-prune(0) is no-op — old snapshot survives in case save fails");

        // Save new epoch 200 — peak occupancy = 2 briefly
        let snap_b = make_signed_snapshot(200);
        save_epoch_snapshot(dir.path(), 200, &snap_b).unwrap();
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap(), vec![100, 200]);

        // Post-prune to 1 — drop the old
        let post = prune_old_epoch_snapshots(dir.path(), 1).unwrap();
        assert_eq!(post, 1);
        assert_eq!(list_epoch_snapshots(dir.path()).unwrap(), vec![200]);
    }

    // ─── fixture-free pure-helper coverage ──────────────

    #[test]
    fn batch_b_epoch_snapshot_filename_pins_12_digit_zero_padded_format_and_round_trips_parse() {
        // PIN: snapshot.rs:610 + :616 — filename convention is
        // `epoch-{N:012}.json`. The 12-digit zero-pad is load-bearing: it
        // guarantees lex-sorted directory listings match numeric epoch
        // order, which list_epoch_snapshots and prune_old_epoch_snapshots
        // depend on (they sort lexicographically before reading). A
        // regression that changed the pad width or extension would silently
        // break the lex-numeric correspondence and leave older snapshots
        // un-prunable.

        // (a) Format pins: exact zero-pad width.
        assert_eq!(epoch_snapshot_filename(0), "epoch-000000000000.json");
        assert_eq!(epoch_snapshot_filename(1), "epoch-000000000001.json");
        assert_eq!(epoch_snapshot_filename(100), "epoch-000000000100.json");
        assert_eq!(epoch_snapshot_filename(999_999_999_999), "epoch-999999999999.json");
        assert_eq!(epoch_snapshot_filename(u64::MAX), format!("epoch-{:012}.json", u64::MAX));

        // (b) Round-trip: parse(format(N)) == Some(N) for all N including 0.
        for n in [0u64, 1, 42, 100, 999_999_999_999, u64::MAX] {
            let name = epoch_snapshot_filename(n);
            assert_eq!(
                parse_epoch_snapshot_filename(&name),
                Some(n),
                "round-trip pin for epoch={}",
                n,
            );
        }

        // (c) Lexicographic-numeric correspondence — load-bearing for
        // list_epoch_snapshots + prune. 12-digit zero pad makes any two
        // epochs ≤ 999_999_999_999 sort correctly under string compare.
        let lo = epoch_snapshot_filename(2);
        let hi = epoch_snapshot_filename(10);
        assert!(lo < hi, "epoch-{{0..2}} MUST sort lex-before epoch-{{0..10}} (12-digit pad)");
        let lo2 = epoch_snapshot_filename(99);
        let hi2 = epoch_snapshot_filename(100);
        assert!(lo2 < hi2, "99 MUST sort lex-before 100 (12-digit pad)");

        // (d) parse_epoch_snapshot_filename rejection axes.
        assert_eq!(parse_epoch_snapshot_filename(""), None, "empty MUST be rejected");
        assert_eq!(parse_epoch_snapshot_filename("epoch-100"), None, "missing .json suffix MUST be rejected");
        assert_eq!(parse_epoch_snapshot_filename("100.json"), None, "missing epoch- prefix MUST be rejected");
        assert_eq!(parse_epoch_snapshot_filename("epoch-abc.json"), None, "non-numeric epoch MUST be rejected");
        assert_eq!(parse_epoch_snapshot_filename("epoch-.json"), None, "empty epoch MUST be rejected");
        assert_eq!(parse_epoch_snapshot_filename("epoch-100.tmp"), None, ".tmp scratch file MUST be rejected");
    }

    #[test]
    fn batch_b_enforce_snapshot_signer_trust_pins_three_branches_empty_match_reject() {
        // PIN: snapshot.rs:537 — three branches:
        //   (a) empty trust_set → Err with "no trusted signers" message
        //   (b) signer ∈ trust_set → Ok
        //   (c) signer ∉ trust_set → Err with preview-truncated identity
        // A regression that collapsed (a) into (c) would mean a node with
        // misconfigured genesis_authority+trust_set would emit a generic
        // "not in trust set" error instead of the actionable "trust set
        // is empty — fix your config" message.

        // (a) Empty trust set — explicit empty-trust error.
        let err = enforce_snapshot_signer_trust("anysigner", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no trusted signers configured"),
            "empty-trust error MUST mention 'no trusted signers configured', got: {msg}",
        );

        // (b) Signer in trust set — accept.
        let trust = ["alice", "bob"];
        assert!(
            enforce_snapshot_signer_trust("alice", &trust).is_ok(),
            "signer in trust set MUST be accepted",
        );
        assert!(
            enforce_snapshot_signer_trust("bob", &trust).is_ok(),
            "second signer in trust set MUST be accepted",
        );

        // (c) Signer NOT in trust set — reject with preview-truncated id.
        let long_sig = "deadbeefcafebabe0123456789abcdef01234567";
        let err = enforce_snapshot_signer_trust(long_sig, &trust).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not in the trusted-signer set"),
            "rejection MUST mention 'not in the trusted-signer set', got: {msg}",
        );
        // First 16 chars of the signer appear in the preview; the full
        // 40-char string MUST NOT (preview-truncation pin).
        assert!(
            msg.contains("deadbeefcafebabe"),
            "rejection MUST include first 16 chars of signer (preview), got: {msg}",
        );
        // Message MUST contain the trust set size for operator triage.
        assert!(
            msg.contains("2 entries"),
            "rejection MUST surface trust set cardinality, got: {msg}",
        );

        // Short signer (< 16 chars) MUST not panic — pin the .min(signer.len())
        // saturating slice.
        let err = enforce_snapshot_signer_trust("short", &trust).unwrap_err();
        assert!(
            err.to_string().contains("short"),
            "short-signer preview MUST not panic and MUST include the signer prefix",
        );
    }

    #[test]
    fn batch_b_enforce_snapshot_protocol_version_pins_disabled_legacy_and_old_node_branches() {
        // PIN: snapshot.rs:563 — three branches:
        //   (a) min_version == 0 → gate disabled, all snapshots accepted
        //   (b) snapshot.protocol_version == None → treat as 0 (legacy)
        //   (c) snapshot.protocol_version < min_version → reject
        //   (d) snapshot.protocol_version >= min_version → accept
        // The legacy=0 branch is load-bearing for backwards compat with
        // pre-Gap-7 snapshots in the wild.

        fn snap(v: Option<u32>) -> NodeSnapshot {
            // Construct a NodeSnapshot via the public constructor and then
            // override `protocol_version` to exercise the gate axes.
            let mut s = NodeSnapshot::new(
                LedgerState::new(),
                HashSet::new(),
                EpochState::new(),
            );
            s.protocol_version = v;
            s
        }

        // (a) min_version=0 disables the gate — any version (None / low / high) passes.
        assert!(enforce_snapshot_protocol_version(&snap(None), 0).is_ok(), "min=0 disables (None)");
        assert!(enforce_snapshot_protocol_version(&snap(Some(0)), 0).is_ok(), "min=0 disables (Some(0))");
        assert!(enforce_snapshot_protocol_version(&snap(Some(99)), 0).is_ok(), "min=0 disables (Some(99))");

        // (b) Legacy snapshot (None) is treated as version 0 → rejected when min>=1.
        let err = enforce_snapshot_protocol_version(&snap(None), 1).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("0 < required minimum 1"),
            "legacy(None)→0 rejection MUST surface in error, got: {msg}",
        );

        // (c) Below minimum — reject with explicit numerics.
        let err = enforce_snapshot_protocol_version(&snap(Some(3)), 5).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("3 < required minimum 5"),
            "below-min rejection MUST surface both numerics, got: {msg}",
        );

        // (d) At or above minimum — accept.
        assert!(enforce_snapshot_protocol_version(&snap(Some(5)), 5).is_ok(), "version==min MUST pass");
        assert!(enforce_snapshot_protocol_version(&snap(Some(6)), 5).is_ok(), "version>min MUST pass");
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_archive_snapshot_every_n_epochs_default_pins_to_documented_value_and_nonzero() {
        // PIN: snapshot.rs:32 — ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT
        // is referenced by `Config` defaults AND by the archival snapshot
        // loop early-exit in bin/elara_node.rs:3885. A regression that
        // changed the constant would (a) shift archival cadence across
        // the fleet on next deploy, (b) potentially zero out the loop
        // entirely if it became 0 (caught by the const_assert at line 39
        // but pinned here too for runtime visibility).
        //
        // The existing test `archive_snapshot_every_n_epochs_default_constant_pins_to_documented_value`
        // covers the literal value. This adds runtime invariants that
        // would otherwise stay implicit in the const_assert.
        assert_eq!(
            ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT, 10,
            "archive snapshot cadence MUST be 10 epochs (Gap 7 design budget)",
        );

        // Non-zero invariant (this is also a const_assert at compile time
        // but pin at runtime for explicit visibility).
        assert!(
            ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT > 0,
            "MUST be > 0 — 0 disables the archival loop entirely",
        );

        // Below-fleet-cadence sanity bound: a value of 1 (every epoch) at
        // 120s epochs = 30 snapshots/hour × 1M zones would blow the disk
        // budget. The pin protects against an accidental change to 1.
        assert!(
            ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT >= 5,
            "MUST be ≥ 5 — sub-5 cadence blows disk budget at mainnet scale",
        );

        // Upper bound: at >100 the snapshot lag is too high for cold-start
        // bootstrap UX.
        assert!(
            ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT <= 100,
            "MUST be ≤ 100 — beyond that, cold-start bootstrap UX degrades",
        );
    }

    #[test]
    fn batch_b_snapshot_metadata_returns_none_when_any_required_field_absent() {
        // PIN: snapshot.rs:578 — snapshot_metadata uses `?` to short-circuit
        // on any of (merkle_root / record_count / snapshot_timestamp /
        // signer_identity / checksum) being None. A regression that
        // replaced `?` with `.unwrap_or(default)` would emit synthetic
        // metadata pointing at a half-built snapshot, which is exactly
        // what /snapshot/latest MUST NOT do (light clients would trust
        // the synthetic).

        // (a) Build a minimal "fully populated" snapshot and confirm
        // Some-output.
        let mut full = NodeSnapshot::new(
            LedgerState::new(),
            HashSet::new(),
            EpochState::new(),
        );
        full.merkle_root = Some("dead".into());
        full.record_count = Some(42);
        full.snapshot_timestamp = Some(1000.0);
        full.signer_identity = Some("alice".into());
        full.checksum = Some("abc".into());
        let meta = snapshot_metadata(&full).expect("fully-populated snapshot MUST yield Some");
        assert_eq!(meta.merkle_root, "dead");
        assert_eq!(meta.record_count, 42);
        assert!((meta.snapshot_timestamp - 1000.0).abs() < f64::EPSILON);
        assert_eq!(meta.signer_identity, "alice");
        assert_eq!(meta.checksum, "abc");
        assert_eq!(meta.accounts, 0);
        assert_eq!(meta.total_supply, 0);
        assert_eq!(meta.total_staked, 0);

        // (b) Each of the 5 ?-fields, when None, MUST short-circuit to None.
        let original = full.clone();
        for axis in ["merkle_root", "record_count", "snapshot_timestamp", "signer_identity", "checksum"] {
            full = original.clone();
            match axis {
                "merkle_root" => full.merkle_root = None,
                "record_count" => full.record_count = None,
                "snapshot_timestamp" => full.snapshot_timestamp = None,
                "signer_identity" => full.signer_identity = None,
                "checksum" => full.checksum = None,
                _ => unreachable!(),
            }
            assert!(
                snapshot_metadata(&full).is_none(),
                "snapshot_metadata MUST return None when {axis} is None",
            );
        }
    }
}

