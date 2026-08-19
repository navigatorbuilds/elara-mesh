//! Anchor-proof records — REALMS P1.5(b).
//!
//! Wraps a matured epoch-anchor artifact (the sidecar's `epoch-N-zone-Z.json`
//! plus its Bitcoin-upgraded OpenTimestamps proof) into a first-class mesh
//! record, so a light client can fetch the record and verify the full time
//! bracket OFFLINE with `elara-verify --anchor-record`:
//!
//!   drand not-before  (the artifact embeds a beacon pulse unknowable earlier)
//!   Bitcoin existed-by (the OTS proof commits the artifact into a BTC block)
//!
//! Trust model (mirrors the drand precedent — the node does NO OTS/BTC
//! crypto): ingest validates structure and bounds only; ALL cryptographic
//! verification lives in `elara-verify`, which MUST recompute the chain:
//!
//!   1. record signature over canonical bytes            (producer-signed)
//!   2. sha3_256(artifact bytes) == record.content_hash  (artifact ↔ record)
//!   3. sha256(artifact bytes)   == OTS committed digest (artifact ↔ Bitcoin)
//!   4. artifact.{seal_hash,epoch,zone} == anchor_* keys (metadata can't lie)
//!   5. --seal chaining via bind_chain                   (artifact ↔ real seal)
//!
//! Without (4)+(5) an anchor_proof record carrying a REAL OTS proof for
//! different bytes could claim to bracket a seal it never touched — the
//! binding tuple in metadata is self-asserted until the verifier recomputes it.
//!
//! The artifact rides VERBATIM (base64 of the exact bytes the sidecar wrote):
//! OTS commits to SHA-256 of the exact byte string, so any re-serialization
//! (key order, indentation) would break the digest and the proof with it.
//!
//! Size budget: per-metadata-value ingest cap is 8192 bytes measured on the
//! JSON-quoted form (`val.to_string()`), so usable base64 is 8190 bytes →
//! raw proof ≤ 6141. Observed upgraded `.ots` proofs are 1.6–5.4 KiB; the
//! builder enforces a 6000-byte raw cap so growth in calendar-aggregation
//! depth fails loudly at build time, never as a silent ingest rejection.
//!
//! Emission policy (SCALE RULE): anchor records are emitted by the sidecar at
//! most once per matured artifact and bounded per day (Tier-0 admission is 20
//! records/day) — never per-epoch, never per-zone-fan-out. A 1M-zone network
//! anchoring per-zone-per-epoch would be 1M records/hour; that policy is
//! explicitly out of scope and must not be introduced without a new design.
//!
//! Errors are `String` (the human reason a build/parse is rejected) per this
//! crate's convention; the node repo's `anchor_proof` shim maps them into its
//! `ElaraError::Wire` so node-side callers keep their typed error.

use base64::Engine as _;
use std::collections::BTreeMap;

/// `kind` discriminator value for anchor-proof records.
pub const KIND_ANCHOR_PROOF: &str = "anchor_proof";

/// `anchor_kind` for P1.5(b): the anchored digest is an Elara epoch-seal hash.
pub const ANCHOR_KIND_ELARA_SEAL: &str = "elara_seal";

/// `anchor_kind` reserved for the P3 anchor bridge (external networks
/// submitting state roots). Parsing accepts it; nothing emits it yet.
pub const ANCHOR_KIND_EXTERNAL_ROOT: &str = "external_root";

/// Raw-byte cap for the verbatim artifact (base64 ≤ 4000, TEXT_LIMITS 4096).
/// Observed sidecar artifacts are ~1.1 KiB.
pub const MAX_ANCHOR_ARTIFACT_RAW: usize = 3000;

/// Raw-byte cap for the OTS proof (base64 8000 ≤ the 8190 usable ingest
/// budget, TEXT_LIMITS 8192). Observed upgraded proofs max at 5338 bytes.
pub const MAX_ANCHOR_OTS_RAW: usize = 6000;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Build the metadata map for an anchor-proof record.
///
/// The record's CONTENT must be the same `artifact_bytes` passed here
/// (`ValidationRecord::create(artifact_bytes, ...)`), so `content_hash`
/// commits to the artifact the verifier decodes from `anchor_artifact_b64`.
///
/// Fails on oversize payloads — better a loud builder error in the CLI than
/// a silent per-value rejection at ingest.
pub fn anchor_proof_metadata(
    anchor_kind: &str,
    anchor_digest_hex: &str,
    anchor_zone: &str,
    anchor_epoch: u64,
    artifact_bytes: &[u8],
    ots_bytes: &[u8],
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    if artifact_bytes.len() > MAX_ANCHOR_ARTIFACT_RAW {
        return Err(format!(
            "anchor artifact too large: {} bytes (max {MAX_ANCHOR_ARTIFACT_RAW})",
            artifact_bytes.len()
        ));
    }
    if ots_bytes.len() > MAX_ANCHOR_OTS_RAW {
        return Err(format!(
            "OTS proof too large: {} bytes (max {MAX_ANCHOR_OTS_RAW})",
            ots_bytes.len()
        ));
    }
    if anchor_digest_hex.len() != 64 || hex::decode(anchor_digest_hex).is_err() {
        return Err(format!(
            "anchor_digest must be 64 hex chars, got {} chars",
            anchor_digest_hex.len()
        ));
    }
    let mut meta = BTreeMap::new();
    meta.insert("kind".into(), serde_json::Value::from(KIND_ANCHOR_PROOF));
    meta.insert("anchor_kind".into(), serde_json::Value::from(anchor_kind));
    meta.insert(
        "anchor_digest".into(),
        serde_json::Value::from(anchor_digest_hex.to_ascii_lowercase()),
    );
    meta.insert("anchor_zone".into(), serde_json::Value::from(anchor_zone));
    meta.insert("anchor_epoch".into(), serde_json::Value::from(anchor_epoch));
    meta.insert(
        "anchor_artifact_b64".into(),
        serde_json::Value::from(b64().encode(artifact_bytes)),
    );
    meta.insert(
        "anchor_ots_b64".into(),
        serde_json::Value::from(b64().encode(ots_bytes)),
    );
    Ok(meta)
}

/// Structurally-parsed anchor-proof fields, base64 already decoded.
/// Parsing proves NOTHING cryptographic — every field is producer-asserted
/// until `elara-verify --anchor-record` recomputes the binding chain.
pub struct AnchorProofFields {
    pub anchor_kind: String,
    pub anchor_digest: String,
    pub anchor_zone: String,
    pub anchor_epoch: u64,
    pub artifact_bytes: Vec<u8>,
    pub ots_bytes: Vec<u8>,
}

fn require_str<'m>(
    meta: &'m BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<&'m str, String> {
    meta.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("anchor_proof record missing '{key}'"))
}

/// Parse + structurally validate anchor-proof metadata.
pub fn parse_anchor_proof_metadata(
    meta: &BTreeMap<String, serde_json::Value>,
) -> Result<AnchorProofFields, String> {
    match meta.get("kind").and_then(|v| v.as_str()) {
        Some(KIND_ANCHOR_PROOF) => {}
        other => return Err(format!("not an anchor_proof record (kind={other:?})")),
    }
    let anchor_kind = require_str(meta, "anchor_kind")?.to_string();
    if anchor_kind != ANCHOR_KIND_ELARA_SEAL && anchor_kind != ANCHOR_KIND_EXTERNAL_ROOT {
        return Err(format!("unknown anchor_kind '{anchor_kind}'"));
    }
    let anchor_digest = require_str(meta, "anchor_digest")?.to_ascii_lowercase();
    if anchor_digest.len() != 64 || hex::decode(&anchor_digest).is_err() {
        return Err("anchor_digest is not 64 hex chars".to_string());
    }
    let anchor_zone = require_str(meta, "anchor_zone")?.to_string();
    let anchor_epoch = meta
        .get("anchor_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "anchor_epoch missing or not a u64".to_string())?;
    let artifact_bytes = b64()
        .decode(require_str(meta, "anchor_artifact_b64")?)
        .map_err(|e| format!("anchor_artifact_b64 invalid base64: {e}"))?;
    let ots_bytes = b64()
        .decode(require_str(meta, "anchor_ots_b64")?)
        .map_err(|e| format!("anchor_ots_b64 invalid base64: {e}"))?;
    if artifact_bytes.len() > MAX_ANCHOR_ARTIFACT_RAW {
        return Err("anchor artifact exceeds raw cap".to_string());
    }
    if ots_bytes.len() > MAX_ANCHOR_OTS_RAW {
        return Err("OTS proof exceeds raw cap".to_string());
    }
    Ok(AnchorProofFields {
        anchor_kind,
        anchor_digest,
        anchor_zone,
        anchor_epoch,
        artifact_bytes,
        ots_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122";

    fn sample_artifact() -> Vec<u8> {
        br#"{"v":1,"zone":"0","epoch":9980,"seal_hash":"abc","drand_round":123}"#.to_vec()
    }

    #[test]
    fn build_then_parse_round_trips() {
        let artifact = sample_artifact();
        let ots = vec![0x00u8, 0x4f, 0x70, 0x65, 0x6e]; // arbitrary binary
        let meta = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            9980,
            &artifact,
            &ots,
        )
        .expect("build");
        let parsed = parse_anchor_proof_metadata(&meta).expect("parse");
        assert_eq!(parsed.anchor_kind, ANCHOR_KIND_ELARA_SEAL);
        assert_eq!(parsed.anchor_digest, DIGEST);
        assert_eq!(parsed.anchor_zone, "0");
        assert_eq!(parsed.anchor_epoch, 9980);
        assert_eq!(parsed.artifact_bytes, artifact);
        assert_eq!(parsed.ots_bytes, ots);
    }

    #[test]
    fn oversize_ots_rejected_at_build() {
        let err = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            1,
            &sample_artifact(),
            &vec![0u8; MAX_ANCHOR_OTS_RAW + 1],
        )
        .unwrap_err();
        assert!(err.to_string().contains("OTS proof too large"));
    }

    #[test]
    fn oversize_artifact_rejected_at_build() {
        let err = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            1,
            &vec![b'x'; MAX_ANCHOR_ARTIFACT_RAW + 1],
            &[1, 2, 3],
        )
        .unwrap_err();
        assert!(err.to_string().contains("artifact too large"));
    }

    #[test]
    fn bad_digest_rejected() {
        assert!(anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            "zz11", // not hex, not 64 chars
            "0",
            1,
            &sample_artifact(),
            &[1],
        )
        .is_err());
    }

    #[test]
    fn parse_rejects_wrong_kind_and_bad_b64() {
        let mut meta = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            1,
            &sample_artifact(),
            &[1],
        )
        .unwrap();
        let mut wrong_kind = meta.clone();
        wrong_kind.insert("kind".into(), serde_json::Value::from("agent_audit"));
        assert!(parse_anchor_proof_metadata(&wrong_kind).is_err());

        meta.insert(
            "anchor_ots_b64".into(),
            serde_json::Value::from("!!! not base64 !!!"),
        );
        assert!(parse_anchor_proof_metadata(&meta).is_err());
    }

    #[test]
    fn parse_rejects_unknown_anchor_kind() {
        let mut meta = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            1,
            &sample_artifact(),
            &[1],
        )
        .unwrap();
        meta.insert("anchor_kind".into(), serde_json::Value::from("mystery"));
        assert!(parse_anchor_proof_metadata(&meta).is_err());
    }

    /// The wire-facing budget: a maximum-size proof, base64-encoded and
    /// JSON-quoted (what ingest actually measures via `val.to_string()`),
    /// must stay ≤ the 8192-byte per-metadata-value ingest cap.
    #[test]
    fn max_size_ots_fits_ingest_value_cap() {
        let meta = anchor_proof_metadata(
            ANCHOR_KIND_ELARA_SEAL,
            DIGEST,
            "0",
            1,
            &sample_artifact(),
            &vec![0xA5u8; MAX_ANCHOR_OTS_RAW],
        )
        .unwrap();
        let quoted = meta.get("anchor_ots_b64").unwrap().to_string();
        assert!(
            quoted.len() <= 8192,
            "quoted b64 OTS is {} bytes, exceeds the 8192 ingest cap",
            quoted.len()
        );
    }
}
