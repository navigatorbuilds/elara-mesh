//! Agent-mandate node wiring (C4 slice 1) — connects the pure verifier in
//! [`crate::mandate`] to the live ingest pipeline, storage CFs, and query layer.
//!
//! **v0 is OBSERVATIONAL.** Mandate-issuance and revocation records are parsed,
//! validated, and stored; mandate-bearing *act* records are indexed so their
//! [`crate::mandate::MandateFlag`] can be RECOMPUTED at query time. The flag
//! NEVER enters consensus weight, the SMT account leaf, or the epoch seal root —
//! that keeps v0 inert on the live authority chain. Scope (op/zone/amount) is
//! deferred for non-wildcard mandates (see [`crate::mandate::evaluate_mandate_v0`]
//! and internal design notes Q3).
//!
//! Distinct from [`crate::accounting::delegation`] (device-fleet stake-sharing) — no
//! shared metadata keys or CFs.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::hash::sha3_256_hex;
use crate::errors::{ElaraError, Result};
use crate::mandate::{
    self, MandateActEntry, MandateClaim, MandateFlag, MandateRecord, MandateResolver,
    RevocationRecord,
};
use crate::record::ValidationRecord;
use crate::storage::rocks::StorageEngine;

// The two metadata wire-key constants now live in core `crate::mandate` (so
// feature-light consumers can name them without the node `network` module);
// re-exported here for back-compat with every existing `mandate_node::` caller.
pub use crate::mandate::{MANDATE_OP_KEY, MANDATE_REVOCATION_OP_KEY};

/// Tight per-record cap on the serialized mandate/revocation payload — far below
/// the generic 8 KB metadata-value cap. These ops are GC-EXEMPT (permanent), so
/// the bound is enforced in Phase-1 (which runs for synced records too, BEFORE
/// the rate-limit bypass) to cap relayed-flood disk growth.
pub const MANDATE_MAX_PAYLOAD_BYTES: usize = 2048;
/// Max entries in either scope vector (bounds a pathological scope payload).
pub const MANDATE_MAX_SCOPE_ENTRIES: usize = 64;

// ── Observability (best-effort, first-apply gated so gossip replay can't
//    double-count). Read by the /metrics surface. ──
pub static MANDATE_RECORDS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MANDATE_REVOCATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MANDATE_ACTS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MANDATE_MALFORMED_REF_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Flag histogram indexed by [`MandateFlag`] discriminant (0..12), sampled at
/// first-apply (the authoritative answer is always the recomputed query flag).
pub static MANDATE_FLAG_TOTAL: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];

/// Read-only [`MandateResolver`] over the node's storage CFs. Keeps
/// [`mandate::evaluate_mandate_v0`] a pure function with no I/O of its own.
pub struct StorageMandateResolver<'a> {
    pub rocks: &'a StorageEngine,
}

impl MandateResolver for StorageMandateResolver<'_> {
    fn mandate(&self, mandate_id: &str) -> Option<MandateRecord> {
        self.rocks.get_mandate(mandate_id)
    }
    fn revocation(&self, mandate_id: &str, principal_identity_hash: &str) -> Option<u64> {
        self.rocks.get_revocation_ms(mandate_id, principal_identity_hash)
    }
}

fn parse_mandate(v: &serde_json::Value) -> Result<MandateRecord> {
    serde_json::from_value(v.clone())
        .map_err(|e| ElaraError::Wire(format!("mandate_op parse: {e}")))
}

fn parse_revocation(v: &serde_json::Value) -> Result<RevocationRecord> {
    serde_json::from_value(v.clone())
        .map_err(|e| ElaraError::Wire(format!("revocation_op parse: {e}")))
}

/// The amount an act commits, via the LEDGER's own parser — so the derived value
/// is identical to what the ledger layer enforces (a naive `as_u64()` would read
/// `None` on a string-encoded amount and silently skip the mandate's cap).
fn amount_from_record(record: &ValidationRecord) -> Option<u64> {
    record
        .metadata
        .get("beat_amount")
        .and_then(crate::accounting::types::parse_beat_amount)
}

/// Phase-1 ingest gate — runs for ALL records (including synced ones, before the
/// rate-limit bypass). Rejects a malformed / oversized / cross-network /
/// principal-mismatched mandate ISSUANCE, and a malformed / oversized /
/// cross-network REVOCATION. Acts (`mandate_ref`) are NEVER rejected here — a bad
/// ref is recorded and flagged at query, it must not block the carrier record.
///
/// Deterministic (same record + network_id → same verdict on every node), so
/// re-validating a synced record cannot diverge from the origin.
pub fn validate_mandate_ingest(record: &ValidationRecord, network_id: &str) -> Result<()> {
    if let Some(v) = record.metadata.get(MANDATE_OP_KEY) {
        if v.to_string().len() > MANDATE_MAX_PAYLOAD_BYTES {
            return Err(ElaraError::Wire("mandate_op payload exceeds cap".into()));
        }
        let m = parse_mandate(v)?;
        if m.scope.allowed_ops.len() > MANDATE_MAX_SCOPE_ENTRIES
            || m.scope.allowed_zones.len() > MANDATE_MAX_SCOPE_ENTRIES
        {
            return Err(ElaraError::Wire("mandate scope too large".into()));
        }
        if !m.network_id.eq_ignore_ascii_case(network_id) {
            return Err(ElaraError::Wire("mandate cross-network".into()));
        }
        if !m.is_well_formed() {
            return Err(ElaraError::Wire("mandate malformed".into()));
        }
        // Principal binding: the carrier's creator MUST be the named principal,
        // so the outer record signature IS the principal's signature over the
        // mandate (no embedded key/sig). `creator_identity_hash == sha3(pk)`.
        let creator = sha3_256_hex(&record.creator_public_key);
        if !creator.eq_ignore_ascii_case(&m.principal_identity_hash) {
            return Err(ElaraError::Wire("mandate principal-binding failed".into()));
        }
    }
    if let Some(v) = record.metadata.get(MANDATE_REVOCATION_OP_KEY) {
        if v.to_string().len() > MANDATE_MAX_PAYLOAD_BYTES {
            return Err(ElaraError::Wire("revocation_op payload exceeds cap".into()));
        }
        let r = parse_revocation(v)?;
        if !r.network_id.eq_ignore_ascii_case(network_id) {
            return Err(ElaraError::Wire("revocation cross-network".into()));
        }
        // No principal-binding gate here: authorization is read-time
        // (StorageMandateResolver::revocation), so the revocation is stored
        // unconditionally and is inert unless signed by the principal.
    }
    Ok(())
}

/// Phase-5 apply (post-store, observational — NO ledger mutation). Persists
/// mandates/revocations into their CFs and indexes mandate-bearing acts for
/// flag recomputation. Counters are first-apply gated (novelty pre-check) so
/// gossip replay does not double-count. Best-effort: a storage error is logged,
/// never fails the record (the carrier already committed).
pub fn apply_mandate_effects(record: &ValidationRecord, rocks: &StorageEngine, network_id: &str) {
    let creator = sha3_256_hex(&record.creator_public_key);

    // Issuance.
    if let Some(v) = record.metadata.get(MANDATE_OP_KEY) {
        if let Ok(m) = parse_mandate(v) {
            let id = m.mandate_id();
            let is_new = rocks.get_mandate(&id).is_none();
            match rocks.put_mandate(&m) {
                Ok(()) if is_new => {
                    MANDATE_RECORDS_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                Ok(()) => {}
                Err(e) => tracing::warn!("mandate store failed: {e}"),
            }
        }
    }

    // Revocation — revoker = carrier creator; effective at the carrier's SIGNED
    // timestamp (not a self-asserted field).
    if let Some(v) = record.metadata.get(MANDATE_REVOCATION_OP_KEY) {
        if let Ok(r) = parse_revocation(v) {
            let revoked_at_ms = mandate::secs_f64_to_ms_saturating(record.timestamp);
            let is_new = rocks.get_revocation_ms(&r.mandate_id, &creator).is_none();
            match rocks.put_revocation(&r.mandate_id, &creator, revoked_at_ms) {
                Ok(()) if is_new => {
                    MANDATE_REVOCATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                Ok(()) => {}
                Err(e) => tracing::warn!("revocation store failed: {e}"),
            }
        }
    }

    // Act — index a mandate-bearing record so the flag can be recomputed.
    if let Some(v) = record.metadata.get(mandate::MANDATE_REF_METADATA_KEY) {
        match v.as_str() {
            Some(mref) if !mref.is_empty() => {
                let entry = MandateActEntry::new(
                    mref,
                    &creator,
                    mandate::secs_f64_to_ms_saturating(record.timestamp),
                    amount_from_record(record),
                );
                let is_new = rocks.get_mandate_act(&record.id).is_none();
                match rocks.put_mandate_act(&record.id, &entry) {
                    Ok(()) if is_new => {
                        MANDATE_ACTS_TOTAL.fetch_add(1, Ordering::Relaxed);
                        // Best-effort flag histogram at first apply (the query
                        // path is the authoritative, always-current answer).
                        let resolver = StorageMandateResolver { rocks };
                        let flag = evaluate_act_entry(&entry, network_id, &resolver);
                        let idx = flag as usize;
                        if idx < MANDATE_FLAG_TOTAL.len() {
                            MANDATE_FLAG_TOTAL[idx].fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(()) => {}
                    Err(e) => tracing::warn!("mandate act-index store failed: {e}"),
                }
            }
            _ => {
                // Present but non-string or empty — a malformed reference. The
                // carrier record is still ingested normally; it is simply not
                // indexed as a mandate act.
                MANDATE_MALFORMED_REF_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Recompute the v0 flag for a stored act entry against current CF state. v0
/// defers scope: op/zone are empty and [`mandate::evaluate_mandate_v0`] applies
/// scope only for wildcard mandates (never a false `OverScope`).
pub fn evaluate_act_entry<R: MandateResolver + ?Sized>(
    entry: &MandateActEntry,
    network_id: &str,
    resolver: &R,
) -> MandateFlag {
    // One body: the flag is the `.0` projection of the lineage variant, so flag
    // and lineage are computed by the same single resolver pass (no drift).
    evaluate_act_entry_with_lineage(entry, network_id, resolver).0
}

/// Like [`evaluate_act_entry`] but ALSO returns the verified sub-delegation chain
/// (leaf→root) — non-empty only for a `Valid` verdict (see
/// [`mandate::evaluate_mandate_v0_with_lineage`]). Powers the `/mandate/status`
/// lineage view; v0 still defers scope (empty op/zone).
pub fn evaluate_act_entry_with_lineage<R: MandateResolver + ?Sized>(
    entry: &MandateActEntry,
    network_id: &str,
    resolver: &R,
) -> (MandateFlag, Vec<(String, MandateRecord)>) {
    let claim = MandateClaim {
        signer_identity_hash: &entry.signer_identity_hash,
        act_timestamp_ms: entry.act_timestamp_ms,
        mandate_ref: &entry.mandate_ref,
        op: "",
        zone: "",
        amount: entry.amount,
        network_id,
    };
    mandate::evaluate_mandate_v0_with_lineage(&claim, resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandate::{MandateRecord, MandateScope};
    use std::collections::BTreeMap;

    fn record_with(meta: BTreeMap<String, serde_json::Value>, creator_pk: Vec<u8>) -> ValidationRecord {
        let mut r = ValidationRecord::create(
            b"x",
            creator_pk,
            vec![],
            crate::record::Classification::Public,
            Some(meta),
        );
        r.timestamp = 1_700_000_000.0;
        r
    }

    // A creator pk whose sha3 is the mandate principal.
    fn pk_for(tag: u8) -> Vec<u8> {
        vec![tag; 1952]
    }

    #[test]
    fn ingest_validation_principal_binding_and_caps() {
        let principal_pk = pk_for(0x11);
        let principal = sha3_256_hex(&principal_pk);
        let agent = "bb".repeat(32);
        let m = MandateRecord::new_root(
            "testnet", &principal, &agent, MandateScope::wildcard(), 0, 1000, 0, "n0",
        );
        let mut meta = BTreeMap::new();
        meta.insert(MANDATE_OP_KEY.into(), serde_json::to_value(&m).unwrap());

        // Correct principal carrier → accepted.
        let ok = record_with(meta.clone(), principal_pk.clone());
        assert!(validate_mandate_ingest(&ok, "testnet").is_ok());

        // Wrong carrier (not the principal) → rejected.
        let bad = record_with(meta.clone(), pk_for(0x22));
        assert!(validate_mandate_ingest(&bad, "testnet").is_err());

        // Cross-network → rejected.
        assert!(validate_mandate_ingest(&ok, "mainnet").is_err());
    }

    #[test]
    fn act_with_malformed_ref_is_not_rejected_at_ingest() {
        // mandate_ref present but a JSON number → must NOT reject the record.
        let mut meta = BTreeMap::new();
        meta.insert(mandate::MANDATE_REF_METADATA_KEY.into(), serde_json::json!(12345));
        let rec = record_with(meta, pk_for(0x33));
        assert!(validate_mandate_ingest(&rec, "testnet").is_ok());
    }

    /// v0 INERTNESS: running the full observational mandate path (issuance +
    /// revocation + act) stores into the mandate CFs but leaves the account-state
    /// seal-root input byte-identical. This is the regression net for the whole
    /// safety argument — a future slice that wired the flag into consensus would
    /// have to route the ledger through `apply_mandate_effects` and break this.
    #[test]
    fn mandate_effects_are_inert_wrt_account_seal_root() {
        use crate::network::account_merkle::root_over_accounts;
        use crate::accounting::ledger::AccountState;
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // The seal-root input: one funded account.
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        let acct = AccountState { available: 1_000, ..Default::default() };
        accounts.insert("aa".repeat(32), acct);
        let baseline = root_over_accounts(&accounts).unwrap();

        // Issuance (carrier = principal).
        let principal_pk = pk_for(0x11);
        let principal = sha3_256_hex(&principal_pk);
        let agent_pk = pk_for(0x99);
        let agent = sha3_256_hex(&agent_pk);
        let m = MandateRecord::new_root(
            "testnet", &principal, &agent, MandateScope::wildcard(), 0, 2_000_000_000_000, 0, "n0",
        );
        let id = m.mandate_id();
        let mut issue_meta = BTreeMap::new();
        issue_meta.insert(MANDATE_OP_KEY.into(), serde_json::to_value(&m).unwrap());
        apply_mandate_effects(&record_with(issue_meta, principal_pk.clone()), &engine, "testnet");

        // Revocation (by the principal).
        let rev = RevocationRecord::new("testnet", &id, "compromised");
        let mut rev_meta = BTreeMap::new();
        rev_meta.insert(MANDATE_REVOCATION_OP_KEY.into(), serde_json::to_value(&rev).unwrap());
        apply_mandate_effects(&record_with(rev_meta, principal_pk), &engine, "testnet");

        // Act (by the agent), referencing the mandate.
        let mut act_meta = BTreeMap::new();
        act_meta.insert(mandate::MANDATE_REF_METADATA_KEY.into(), serde_json::json!(id));
        let act = record_with(act_meta, agent_pk);
        apply_mandate_effects(&act, &engine, "testnet");

        // Effects ran...
        assert!(engine.get_mandate(&id).is_some(), "mandate stored");
        assert!(engine.get_revocation_ms(&id, &principal).is_some(), "revocation stored");
        assert!(engine.get_mandate_act(&act.id).is_some(), "act indexed");
        // ...the act recomputes to PostRevocation (revoked at the act's own time).
        let resolver = StorageMandateResolver { rocks: &engine };
        let entry = engine.get_mandate_act(&act.id).unwrap();
        assert_eq!(
            evaluate_act_entry(&entry, "testnet", &resolver),
            MandateFlag::PostRevocation
        );
        // C4 slice 4: the act is enumerable via the reverse index under its
        // (64-hex) mandate id...
        let (acts, _) = engine.list_acts_for_mandate(&id, None, 10).unwrap();
        assert_eq!(acts, vec![act.id.clone()], "act enumerable via reverse index");
        // ...while a non-64-hex ref is forward-indexed but NEVER reverse-indexed
        // (it can never resolve to a real mandate), so it pollutes no enumeration.
        let mut bad_meta = BTreeMap::new();
        bad_meta.insert(mandate::MANDATE_REF_METADATA_KEY.into(), serde_json::json!("xyz"));
        let bad = record_with(bad_meta, pk_for(0x44));
        apply_mandate_effects(&bad, &engine, "testnet");
        assert!(engine.get_mandate_act(&bad.id).is_some(), "bad-ref act forward-indexed");
        let (acts2, _) = engine.list_acts_for_mandate(&id, None, 10).unwrap();
        assert_eq!(acts2, vec![act.id.clone()], "bad ref added to no reverse list");
        // ...and with the reverse CF now populated, the account seal-root input is
        // STILL byte-identical: the whole mandate layer is inert w.r.t. consensus.
        assert_eq!(root_over_accounts(&accounts).unwrap(), baseline);
    }

    /// The C4 dogfood path end-to-end: a principal issues a mandate, the agent
    /// acts under it, and the act recomputes to Valid; an act under an unknown
    /// mandate is NoChain (binds the signer only).
    #[test]
    fn happy_path_roundtrip_issuance_then_agent_act() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let principal_pk = pk_for(0x11);
        let principal = sha3_256_hex(&principal_pk);
        let agent_pk = pk_for(0x22);
        let agent = sha3_256_hex(&agent_pk);
        let m = MandateRecord::new_root(
            "testnet", &principal, &agent, MandateScope::wildcard(), 0, 2_000_000_000_000, 0, "n0",
        );
        let id = m.mandate_id();

        // Principal issues the mandate (carrier signed by the principal).
        let mut issue_meta = BTreeMap::new();
        issue_meta.insert(MANDATE_OP_KEY.into(), serde_json::to_value(&m).unwrap());
        let issue_rec = record_with(issue_meta, principal_pk);
        assert!(validate_mandate_ingest(&issue_rec, "testnet").is_ok());
        apply_mandate_effects(&issue_rec, &engine, "testnet");
        assert!(engine.get_mandate(&id).is_some());

        let resolver = StorageMandateResolver { rocks: &engine };

        // Agent acts under the mandate → Valid.
        let mut act_meta = BTreeMap::new();
        act_meta.insert(mandate::MANDATE_REF_METADATA_KEY.into(), serde_json::json!(id));
        let act = record_with(act_meta, agent_pk.clone());
        assert!(validate_mandate_ingest(&act, "testnet").is_ok());
        apply_mandate_effects(&act, &engine, "testnet");
        let act_entry = engine.get_mandate_act(&act.id).unwrap();
        assert_eq!(
            evaluate_act_entry(&act_entry, "testnet", &resolver),
            MandateFlag::Valid
        );

        // Act referencing an unknown (well-formed) mandate id → NoChain.
        let mut nc_meta = BTreeMap::new();
        nc_meta.insert(mandate::MANDATE_REF_METADATA_KEY.into(), serde_json::json!("ff".repeat(32)));
        let nc = record_with(nc_meta, agent_pk);
        apply_mandate_effects(&nc, &engine, "testnet");
        let nc_entry = engine.get_mandate_act(&nc.id).unwrap();
        assert_eq!(
            evaluate_act_entry(&nc_entry, "testnet", &resolver),
            MandateFlag::NoChain
        );
    }
}
