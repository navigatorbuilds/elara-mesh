//! Anchor-pinned seal-record verification.
//!
//! `network::light_sdk` previously documented that the module did not verify
//! seal signatures against a known validator set — callers had to take "the
//! server told us bound_to_seal=true" on faith. This helper closes that gap:
//! the caller pins the anchor pubkey set out-of-band, and the verifier refuses
//! any seal whose creator pubkey is not a member, even if the record's
//! self-signature is valid.
//!
//! Trust chain:
//!   1. The caller decides which Dilithium3 pubkeys to trust (e.g. shipped with
//!      the account binary, or fetched from a signed governance record they pin).
//!   2. They fetch a seal record body via `/records/fetch` (or any transport).
//!   3. They obtain the expected `record_hash` from a header they trust
//!      (chain-linked via `EpochHeader.seal_record_hash` from a checkpoint).
//!   4. They call this function with `(wire_bytes, expected_hash, anchors)`.
//!
//! Node-side behavior tests (real `Identity` signing, which stays out of this
//! signing-incapable crate) live in the node's `light_verify` module.
//!
//! @spec Protocol §11.3 (light client mode), §4.2 (Dilithium3)

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
    let rec = elara_record::record::ValidationRecord::from_bytes(wire_bytes)
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
    // Keep the pre-extraction "Crypto error: …" prefix the node's ElaraError
    // Display added (error-string pinning tests hold it). `dilithium3_verify`
    // only ever constructs `RecordError::Crypto`, whose own Display is bare
    // `{0}`, so prefixing here reproduces the node text exactly.
    let ok = elara_record::pqc::dilithium3_verify(&signable, sig, creator_pk)
        .map_err(|e| SealRecordVerifyError::VerifyError(format!("Crypto error: {e}")))?;
    if !ok {
        return Err(SealRecordVerifyError::InvalidSignature);
    }
    Ok(())
}
