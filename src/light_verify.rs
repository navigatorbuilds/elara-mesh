//! Light-client proof verification — node-side seam over the standalone
//! [`elara_light_client`] crate.
//!
//! The storage-free, signature-free verification core — account-SMT inclusion
//! proofs, epoch-header root binding, and state-delta seal binding — lives in
//! the standalone `elara-light-client` crate (MIT/Apache, Lane 3) so it runs
//! unchanged in wasm32 browser builds and any other no-tokio environment. It is
//! re-exported here so every `crate::light_verify::*` path resolves unchanged.
//!
//! What stays node-side is [`verify_seal_record_against_anchor`]: it decodes a
//! [`crate::record::ValidationRecord`] and calls
//! [`crate::crypto::pqc::dilithium3_verify`], so it depends on the node's wire
//! type and lattice verifier rather than being pure. A wasm consumer that needs
//! the full anchor check pulls the node as a dependency; one that only needs to
//! fold proofs and bind roots depends on `elara-light-client` alone.
//!
//! A round-trip parity test (`compat_tests`, gated on `feature = "node"`) builds
//! a real proof against an `AccountStateSMT`, JSON-encodes it, decodes as the
//! crate's `LiteAccountStateProof`, and asserts the crate verifier agrees — so
//! the in-tree storage SMT and the extracted verifier cannot drift.
//!
//! Spec references:
//!   @spec Protocol §11.12 (account-state SMT)
//!   @spec Protocol §11.22 (light-client account proofs)
//!   @spec Protocol §11.3 (light client mode), §4.2 (Dilithium3)

// Re-export the pure, wasm-portable verification core. The extracted crate owns
// the wire types, the SMT fold, the header binding, and the state-delta seal
// binding; this shim keeps the `crate::light_verify::` paths stable for the
// node, the `elara_verify` CLI, and `network::light_sdk`.
pub use elara_light_client::{
    account_path, empty_hash, verify_account_proof_against_header, verify_proof,
    verify_state_delta_seal_binding, LiteAccountStateProof, LiteEpochHeader,
    LiteStateDeltaBinding, SealBindingError, MAX_DEPTH,
};

// ─── anchor-pinned seal-record verification (node-side: needs ValidationRecord) ──
//
// `network::light_sdk` previously documented that the module did not verify
// seal signatures against a known validator set — callers had to take "the
// server told us bound_to_seal=true" on faith. This helper closes that gap:
// the caller pins the anchor pubkey set out-of-band, and the verifier refuses
// any seal whose creator pubkey is not a member, even if the record's
// self-signature is valid.
//
// Trust chain:
//   1. The caller decides which Dilithium3 pubkeys to trust (e.g. shipped with
//      the account binary, or fetched from a signed governance record they pin).
//   2. They fetch a seal record body via `/records/fetch` (or any transport).
//   3. They obtain the expected `record_hash` from a header they trust
//      (chain-linked via `EpochHeader.seal_record_hash` from a checkpoint).
//   4. They call this function with `(wire_bytes, expected_hash, anchors)`.
//
// @spec Protocol §11.3 (light client mode), §4.2 (Dilithium3)

/// Errors returned by [`verify_seal_record_against_anchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRecordVerifyError {
    /// `wire_bytes` could not be decoded as a `ValidationRecord`.
    /// Light-client paths hit this when a seed returns truncated or
    /// corrupt bytes.
    WireDecode(String),
    /// `record.record_hash() != expected_record_hash`. Signals that the
    /// seeds substituted a record that doesn't match the checkpoint the
    /// caller trusts. Always refuse — never fall back.
    RecordHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Record carries no `signature` field. Unsigned seals MUST NOT be
    /// trusted; an unsigned record from a trusted seed is still a forgery
    /// vector if the seed itself is later compromised.
    MissingSignature,
    /// Record carries an empty `creator_public_key`. Same posture as
    /// `MissingSignature` — refuse.
    MissingCreatorPubkey,
    /// `creator_public_key` is not a member of `trusted_anchor_pubkeys`.
    /// Closes the explicit Gap 1 SDK caveat: the caller pins the validator
    /// set, and the SDK refuses to trust a seal signed by an unknown key
    /// even if the self-signature is valid.
    UntrustedAnchor,
    /// `dilithium3_verify` returned `Ok(false)`. Treat as a forgery
    /// attempt: the record claims to be signed by an anchor key whose
    /// signature does not validate.
    InvalidSignature,
    /// The verifier itself errored (corrupt sig/pubkey bytes). Distinct
    /// from `InvalidSignature` because the verifier could not run —
    /// caller may want to retry against a different seed before bumping
    /// a forgery counter.
    VerifyError(String),
}

impl core::fmt::Display for SealRecordVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WireDecode(msg) => write!(f, "seal record wire decode: {msg}"),
            Self::RecordHashMismatch { expected, actual } => write!(
                f,
                "seal record_hash mismatch: expected {} actual {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
            Self::MissingSignature => f.write_str("seal record has no Dilithium3 signature"),
            Self::MissingCreatorPubkey => f.write_str("seal record has empty creator_public_key"),
            Self::UntrustedAnchor => f.write_str(
                "seal creator_public_key is not in the caller-pinned anchor set"
            ),
            Self::InvalidSignature => f.write_str("seal Dilithium3 signature invalid"),
            Self::VerifyError(msg) => write!(f, "seal Dilithium3 verify error: {msg}"),
        }
    }
}

impl std::error::Error for SealRecordVerifyError {}

/// Verify a fetched epoch-seal record against a caller-pinned anchor pubkey
/// set. This is the trust-anchor closure for Gap 1.
///
/// Layered checks (any failure short-circuits with the most specific error):
///   1. Decode `wire_bytes` as a `ValidationRecord`.
///   2. Confirm `rec.record_hash() == expected_record_hash`.
///   3. Confirm `rec.signature` is `Some` and `rec.creator_public_key` is
///      non-empty.
///   4. Confirm `rec.creator_public_key` is a member of `trusted_anchor_pubkeys`.
///      Anchor membership is checked BEFORE the lattice verifier so a
///      non-anchor pubkey is rejected without spending CPU on Dilithium3.
///   5. Confirm `dilithium3_verify(signable_bytes, signature, creator_public_key)`
///      returns `Ok(true)`.
///
/// Caller fetches `wire_bytes` via any transport, supplies the expected
/// record hash from a header they trust, and supplies the anchor set
/// out-of-band.
///
/// An empty `trusted_anchor_pubkeys` slice always returns `UntrustedAnchor` —
/// there is no implicit trust mode. A caller that wants permissive behavior
/// must build its own wrapper.
///
/// @spec Protocol §11.3 (light client mode), §4.2 (Dilithium3)
pub fn verify_seal_record_against_anchor(
    wire_bytes: &[u8],
    expected_record_hash: [u8; 32],
    trusted_anchor_pubkeys: &[Vec<u8>],
) -> Result<(), SealRecordVerifyError> {
    let rec = crate::record::ValidationRecord::from_bytes(wire_bytes)
        .map_err(|e| SealRecordVerifyError::WireDecode(e.to_string()))?;

    let actual = rec.record_hash();
    if actual != expected_record_hash {
        return Err(SealRecordVerifyError::RecordHashMismatch {
            expected: expected_record_hash,
            actual,
        });
    }

    let sig = rec
        .signature
        .as_ref()
        .ok_or(SealRecordVerifyError::MissingSignature)?;
    if rec.creator_public_key.is_empty() {
        return Err(SealRecordVerifyError::MissingCreatorPubkey);
    }

    let creator_pk = rec.creator_public_key.as_slice();
    if !trusted_anchor_pubkeys
        .iter()
        .any(|pk| pk.as_slice() == creator_pk)
    {
        return Err(SealRecordVerifyError::UntrustedAnchor);
    }

    let signable = rec.signable_bytes();
    let ok = crate::crypto::pqc::dilithium3_verify(&signable, sig, creator_pk)
        .map_err(|e| SealRecordVerifyError::VerifyError(e.to_string()))?;
    if !ok {
        return Err(SealRecordVerifyError::InvalidSignature);
    }
    Ok(())
}

// ─── Round-trip parity test (gated — needs the storage-side SMT) ────────────

#[cfg(all(test, feature = "node"))]
mod compat_tests {
    use super::*;
    use crate::network::account_merkle::AccountStateSMT;
    use crate::storage::rocks::StorageEngine;
    use tempfile::TempDir;

    fn alphabet_id(c: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = c;
        id
    }

    #[test]
    fn lite_verify_accepts_storage_side_proof() {
        let tmp = TempDir::new().unwrap();
        let storage = StorageEngine::open(tmp.path()).unwrap();
        let mut smt = AccountStateSMT::new(&storage);
        for i in 0..32u8 {
            let id = alphabet_id(i);
            let mut h = [0u8; 32];
            h[31] = i;
            smt.update(&id, &h).unwrap();
        }
        smt.commit().unwrap();
        let target = alphabet_id(7);
        let proof = smt.proof(&target).unwrap().unwrap();

        // Round-trip via JSON to prove wire compatibility.
        let json = serde_json::to_string(&proof).unwrap();
        let lite: LiteAccountStateProof = serde_json::from_str(&json).unwrap();
        assert!(verify_proof(&lite), "lite verifier accepts storage-side proof");

        // Tamper detection: flip a bit, expect rejection.
        let mut bad = lite.clone();
        bad.state_hash[0] ^= 0x01;
        assert!(!verify_proof(&bad));
    }

    #[test]
    fn lite_verify_against_header_binds_root() {
        let tmp = TempDir::new().unwrap();
        let storage = StorageEngine::open(tmp.path()).unwrap();
        let mut smt = AccountStateSMT::new(&storage);
        let id = alphabet_id(3);
        smt.update(&id, &[7u8; 32]).unwrap();
        smt.commit().unwrap();
        let proof = smt.proof(&id).unwrap().unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let lite: LiteAccountStateProof = serde_json::from_str(&json).unwrap();

        let mut hdr = LiteEpochHeader {
            zone: "0".to_string(),
            epoch_number: 0,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            record_count: 1,
            start: 0.0,
            end: 60.0,
            account_smt_root: Some(lite.root),
            seal_record_hash: None,
        };
        assert!(verify_account_proof_against_header(&lite, &hdr));

        // Mismatched root: reject.
        hdr.account_smt_root = Some([0xffu8; 32]);
        assert!(!verify_account_proof_against_header(&lite, &hdr));

        // Pre-Gap-1 header (no SMT root): reject.
        hdr.account_smt_root = None;
        assert!(!verify_account_proof_against_header(&lite, &hdr));
    }
}

// ─── anchor-pinned seal-record verification tests (node-side: build real records) ──

#[cfg(test)]
mod tests {
    use super::*;

    // Build a real signed v5 ValidationRecord via the Identity helper, then
    // exercise each rejection path of `verify_seal_record_against_anchor`.
    fn signed_seal_record() -> (crate::record::ValidationRecord, Vec<u8>) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::record::{Classification, ValidationRecord};
        use crate::ZoneId;
        use std::collections::BTreeMap;

        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let mut rec = ValidationRecord::create(
            b"epoch-seal-body",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = 11;
        rec.zone = Some(ZoneId::from_legacy(0));
        id.sign_record_light(&mut rec).unwrap();
        let wire = rec.to_bytes();
        (rec, wire)
    }

    #[test]
    fn anchor_verify_accepts_valid_record_with_anchor_match() {
        let (rec, wire) = signed_seal_record();
        let anchors = vec![rec.creator_public_key.clone()];
        verify_seal_record_against_anchor(&wire, rec.record_hash(), &anchors)
            .expect("valid record with matching anchor must pass");
    }

    #[test]
    fn anchor_verify_rejects_unknown_anchor() {
        // Sign with one key; pin a DIFFERENT key as the trusted anchor set.
        let (rec, wire) = signed_seal_record();
        let other_pk = vec![0xAAu8; rec.creator_public_key.len()];
        let anchors = vec![other_pk];
        let err = verify_seal_record_against_anchor(&wire, rec.record_hash(), &anchors)
            .expect_err("unknown anchor must fail");
        assert_eq!(err, SealRecordVerifyError::UntrustedAnchor);
    }

    #[test]
    fn anchor_verify_rejects_empty_anchor_set() {
        // Empty anchor set has no implicit-trust fallback — closes the
        // "permissive default" attack where a misconfigured account
        // accepts every seal because it forgot to pin anchors.
        let (rec, wire) = signed_seal_record();
        let err = verify_seal_record_against_anchor(&wire, rec.record_hash(), &[])
            .expect_err("empty anchor set must fail");
        assert_eq!(err, SealRecordVerifyError::UntrustedAnchor);
    }

    #[test]
    fn anchor_verify_rejects_record_hash_mismatch() {
        let (rec, wire) = signed_seal_record();
        let anchors = vec![rec.creator_public_key.clone()];
        let wrong_hash = [0xCCu8; 32];
        let err = verify_seal_record_against_anchor(&wire, wrong_hash, &anchors)
            .expect_err("wrong hash must fail");
        match err {
            SealRecordVerifyError::RecordHashMismatch { expected, actual } => {
                assert_eq!(expected, wrong_hash);
                assert_eq!(actual, rec.record_hash());
            }
            other => panic!("expected RecordHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn anchor_verify_rejects_unsigned_record() {
        let (mut rec, _wire) = signed_seal_record();
        let hash = rec.record_hash();
        let anchors = vec![rec.creator_public_key.clone()];
        rec.signature = None;
        let wire = rec.to_bytes();
        let err = verify_seal_record_against_anchor(&wire, hash, &anchors)
            .expect_err("missing sig must fail");
        assert_eq!(err, SealRecordVerifyError::MissingSignature);
    }

    #[test]
    fn anchor_verify_rejects_forged_signature() {
        // Flip the last byte of the signature so the record_hash still
        // matches (sig is NOT part of signable_bytes), but the lattice
        // verifier rejects the bytes. Anchor IS in the trusted set —
        // proves anchor membership alone is not sufficient; sig must
        // also verify cryptographically.
        let (mut rec, _wire) = signed_seal_record();
        let hash = rec.record_hash();
        let anchors = vec![rec.creator_public_key.clone()];
        if let Some(sig) = rec.signature.as_mut() {
            let last = sig.len() - 1;
            sig[last] ^= 0x01;
        }
        let wire = rec.to_bytes();
        let err = verify_seal_record_against_anchor(&wire, hash, &anchors)
            .expect_err("forged sig must fail");
        assert!(
            matches!(
                err,
                SealRecordVerifyError::InvalidSignature
                    | SealRecordVerifyError::VerifyError(_)
            ),
            "expected sig-rejection variant, got {err:?}"
        );
    }

    #[test]
    fn anchor_verify_rejects_garbage_wire() {
        let anchors: Vec<Vec<u8>> = vec![];
        let err = verify_seal_record_against_anchor(b"not-a-record", [0u8; 32], &anchors)
            .expect_err("garbage wire must fail");
        assert!(
            matches!(err, SealRecordVerifyError::WireDecode(_)),
            "expected WireDecode variant, got {err:?}"
        );
    }

    #[test]
    fn anchor_verify_anchor_set_with_multiple_pubkeys_matches_one() {
        // Realistic shape: caller pins N anchors (foundation + community
        // attestors), record is signed by one of them. Membership check
        // must scan the slice and accept on first match.
        let (rec, wire) = signed_seal_record();
        let other_pk = vec![0xBBu8; rec.creator_public_key.len()];
        let anchors = vec![other_pk, rec.creator_public_key.clone()];
        verify_seal_record_against_anchor(&wire, rec.record_hash(), &anchors)
            .expect("record signed by second anchor must pass");
    }

    /// Pins the `MissingCreatorPubkey` rejection path: a record with a present
    /// signature but an EMPTY `creator_public_key`. The check sits AFTER the
    /// signature null-check and BEFORE the anchor-set membership scan, so it
    /// shields the `pk.as_slice() == creator_pk` loop from a degenerate
    /// empty-slice match that would silently accept any anchor.
    #[test]
    fn anchor_verify_rejects_empty_creator_pubkey_with_present_signature() {
        let (mut rec, _wire) = signed_seal_record();
        let anchors = vec![rec.creator_public_key.clone()];
        rec.creator_public_key = vec![]; // empty pubkey, signature still Some(..)
        let hash = rec.record_hash();
        let wire = rec.to_bytes();
        let err = verify_seal_record_against_anchor(&wire, hash, &anchors)
            .expect_err("empty creator_public_key with signature present must fail");
        assert_eq!(err, SealRecordVerifyError::MissingCreatorPubkey);
    }

    /// Pins the `Display` impl messages for `SealRecordVerifyError`. Operators
    /// read these strings in light-client logs and WASM account UIs; rewording a
    /// variant silently is a UX regression the `assert_eq!(..., variant)` tests
    /// don't catch. (The pure `SealBindingError` Display is pinned in the
    /// `elara-light-client` crate's own tests.)
    #[test]
    fn error_display_seal_record_verify_pins_distinguishing_keywords_per_variant() {
        let wd = SealRecordVerifyError::WireDecode("bad bytes".into()).to_string();
        assert!(wd.contains("wire decode"), "WireDecode keyword: {wd}");
        assert!(wd.contains("bad bytes"), "WireDecode shows inner msg: {wd}");

        let hm = SealRecordVerifyError::RecordHashMismatch {
            expected: [0xABu8; 32],
            actual: [0xCDu8; 32],
        }
        .to_string();
        assert!(hm.contains("mismatch"), "RecordHashMismatch keyword: {hm}");
        assert!(
            hm.contains(&hex::encode([0xABu8; 32])),
            "RecordHashMismatch shows expected hex"
        );
        assert!(
            hm.contains(&hex::encode([0xCDu8; 32])),
            "RecordHashMismatch shows actual hex"
        );

        assert!(
            SealRecordVerifyError::MissingSignature
                .to_string()
                .contains("no Dilithium3"),
            "MissingSignature keyword"
        );
        assert!(
            SealRecordVerifyError::MissingCreatorPubkey
                .to_string()
                .contains("empty creator_public_key"),
            "MissingCreatorPubkey keyword"
        );
        assert!(
            SealRecordVerifyError::UntrustedAnchor
                .to_string()
                .contains("anchor set"),
            "UntrustedAnchor keyword"
        );
        assert!(
            SealRecordVerifyError::InvalidSignature
                .to_string()
                .contains("invalid"),
            "InvalidSignature keyword"
        );

        let ve = SealRecordVerifyError::VerifyError("crypto bug".into()).to_string();
        assert!(ve.contains("verify error"), "VerifyError keyword: {ve}");
        assert!(ve.contains("crypto bug"), "VerifyError shows inner msg: {ve}");
    }
}
