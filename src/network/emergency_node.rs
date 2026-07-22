//! Node-side ingest validation + apply for [`crate::emergency`] records.
//!
//! Mirrors `network::mandate_node`, with one deliberate difference: a halt *acts*
//! at ingest time (it gates new writes), so authority-binding (`sha3(creator_pk) ==
//! genesis_authority`) is enforced at VALIDATE time (the record is REJECTED, not
//! stored-inert like a mandate revocation). The apply path re-checks as
//! defense-in-depth and folds the verified op into the node-local atomics, persisting
//! the durable `CF_EMERGENCY` blob BEFORE publishing the atomics (crash-safety).

use std::sync::Arc;

use crate::crypto::hash::sha3_256_hex;
use crate::errors::{ElaraError, Result};
use crate::emergency::{
    parse_halt, parse_resume, EMERGENCY_HALT_OP_KEY, EMERGENCY_MAX_PAYLOAD_BYTES,
    EMERGENCY_RESUME_OP_KEY,
};
use crate::network::state::NodeState;
use crate::record::ValidationRecord;

/// Phase-1 ingest gate — runs for ALL records (including synced). Rejects a
/// malformed / oversized / cross-network / non-authority-signed Halt or Resume.
/// Deterministic (same record + config → same verdict on every node), so
/// re-validating a synced record cannot diverge from the origin.
pub fn validate_emergency_ingest(
    record: &ValidationRecord,
    network_id: &str,
    genesis_authority: &str,
) -> Result<()> {
    let creator = sha3_256_hex(&record.creator_public_key);
    if let Some(v) = record.metadata.get(EMERGENCY_HALT_OP_KEY) {
        if v.to_string().len() > EMERGENCY_MAX_PAYLOAD_BYTES {
            return Err(ElaraError::Wire("emergency_halt payload exceeds cap".into()));
        }
        let h = parse_halt(v)?;
        if !h.network_id.eq_ignore_ascii_case(network_id) {
            return Err(ElaraError::Wire("emergency_halt cross-network".into()));
        }
        if !h.is_well_formed() {
            return Err(ElaraError::Wire("emergency_halt malformed".into()));
        }
        // Authority-binding: the halt ACTS, so it must authorize at ingest. The
        // carrier signature (verified downstream) covers `metadata`, so a creator
        // == genesis_authority binding makes the outer record signature the
        // authority's signature over this halt.
        if !creator.eq_ignore_ascii_case(genesis_authority) {
            return Err(ElaraError::Wire("emergency_halt not authority-signed".into()));
        }
    }
    if let Some(v) = record.metadata.get(EMERGENCY_RESUME_OP_KEY) {
        if v.to_string().len() > EMERGENCY_MAX_PAYLOAD_BYTES {
            return Err(ElaraError::Wire("emergency_resume payload exceeds cap".into()));
        }
        let r = parse_resume(v)?;
        if !r.network_id.eq_ignore_ascii_case(network_id) {
            return Err(ElaraError::Wire("emergency_resume cross-network".into()));
        }
        if !r.is_well_formed() {
            return Err(ElaraError::Wire("emergency_resume malformed".into()));
        }
        if !creator.eq_ignore_ascii_case(genesis_authority) {
            return Err(ElaraError::Wire("emergency_resume not authority-signed".into()));
        }
    }
    Ok(())
}

/// Phase-5 apply (post-store, observational — NO ledger mutation). Folds a verified
/// Halt/Resume into the node-local atomics; the fold itself persists the durable
/// `CF_EMERGENCY` blob before publishing the atomics (atomic under the fold lock —
/// a crash/restart can never observe a stale un-halt). Best-effort: the carrier
/// already committed, so a non-winning or malformed op is simply a no-op.
pub fn apply_emergency_effects(state: &Arc<NodeState>, record: &ValidationRecord) {
    // Defense-in-depth re-check (validate_emergency_ingest already rejected a
    // non-authority op before it could be stored).
    let creator = sha3_256_hex(&record.creator_public_key);
    if !creator.eq_ignore_ascii_case(&state.config.genesis_authority) {
        return;
    }
    let network_id = &state.config.network_id;

    if let Some(v) = record.metadata.get(EMERGENCY_HALT_OP_KEY) {
        if let Ok(h) = parse_halt(v) {
            if h.is_well_formed()
                && h.network_id.eq_ignore_ascii_case(network_id)
                && state.emergency_fold_halt(&h)
            {
                tracing::warn!(
                    "EMERGENCY HALT active: nonce={} reason={:?} (network paused — new non-authority writes refused until resume/expiry)",
                    h.nonce,
                    h.reason
                );
            }
        }
    }

    if let Some(v) = record.metadata.get(EMERGENCY_RESUME_OP_KEY) {
        if let Ok(r) = parse_resume(v) {
            if r.is_well_formed()
                && r.network_id.eq_ignore_ascii_case(network_id)
                && state.emergency_fold_resume(&r)
            {
                tracing::info!("EMERGENCY RESUME applied: halt_nonce={} cleared", r.halt_nonce);
            }
        }
    }
}
