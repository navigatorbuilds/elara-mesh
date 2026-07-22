//! Anchor-proof records — REALMS P1.5(b). The codec (consts, field struct,
//! build + parse) moved into `elara-verify` in extraction Step 4b — the parse
//! leg is what `elara-verify --anchor-record` runs offline, and the whole
//! point of that binary is "no node stack". This shim keeps the node-side API
//! byte-identical: same paths, same `Result<_, ElaraError>` signatures (the
//! crate speaks `Result<_, String>` per its convention; `ElaraError::Wire`
//! carries the same message text, so error displays are unchanged).

use std::collections::BTreeMap;

use crate::errors::{ElaraError, Result};

pub use elara_verify::anchor_proof::{
    AnchorProofFields, ANCHOR_KIND_ELARA_SEAL, ANCHOR_KIND_EXTERNAL_ROOT, KIND_ANCHOR_PROOF,
    MAX_ANCHOR_ARTIFACT_RAW, MAX_ANCHOR_OTS_RAW,
};

/// Build the metadata map for an anchor-proof record. See
/// [`elara_verify::anchor_proof::anchor_proof_metadata`].
pub fn anchor_proof_metadata(
    anchor_kind: &str,
    anchor_digest_hex: &str,
    anchor_zone: &str,
    anchor_epoch: u64,
    artifact_bytes: &[u8],
    ots_bytes: &[u8],
) -> Result<BTreeMap<String, serde_json::Value>> {
    elara_verify::anchor_proof::anchor_proof_metadata(
        anchor_kind,
        anchor_digest_hex,
        anchor_zone,
        anchor_epoch,
        artifact_bytes,
        ots_bytes,
    )
    .map_err(ElaraError::Wire)
}

/// Parse + structurally validate anchor-proof metadata. See
/// [`elara_verify::anchor_proof::parse_anchor_proof_metadata`].
pub fn parse_anchor_proof_metadata(
    meta: &BTreeMap<String, serde_json::Value>,
) -> Result<AnchorProofFields> {
    elara_verify::anchor_proof::parse_anchor_proof_metadata(meta).map_err(ElaraError::Wire)
}
