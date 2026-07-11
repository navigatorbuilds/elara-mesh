//! LivenessFailureProof — cryptographic evidence of rank-0 aggregator
//! failing to propose within `base_timeout`.
//!
//! Where [`super::conflict_proof::ConflictProof`] proves equivocation (two
//! different seals for one slot), `LivenessFailureProof` proves the dual:
//! *no* seal was produced by the responsible rank-0 aggregator within the
//! zone's observed `base_timeout`. The proof is a bundle of ≥1 attestations
//! from distinct zone stakers, each signing a canonical "rank-0 timeout
//! observed" message over `(offender, zone, epoch, base_timeout, epoch_start)`.
//!
//! To activate a slash, the proof must carry attestations representing
//! ≥2/3 of the zone's stake (checked by [`Self::verify_with_stakers`]).
//!
//! Slash percent: 1% (vs 25% for equivocation) — liveness failures are
//! weaker evidence than safety violations, so the penalty is graduated.
//!
//! Spec references:
//!   @spec Protocol §11.13 (planned v0.7.7)
//!   @spec MESH-BFT §4 (planned liveness theorem)

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::ZoneId;
use crate::crypto::hash::sha3_256_hex;
use crate::errors::{ElaraError, Result};
use crate::identity::Identity;

/// Domain separator for liveness-failure attestation signatures.
/// Prevents cross-protocol signature reuse (e.g., replay as a record sig).
pub const LIVENESS_DOMAIN_TAG: &[u8] = b"ELARA/LIVENESS_FAIL/v1";

/// Slash percentage applied on a verified liveness-failure proof.
/// Graduated: liveness failure is softer evidence than equivocation,
/// so this is 1% vs the 25% equivocation slash.
pub const LIVENESS_SLASH_PERCENT: f64 = 0.01;

/// A single staker's attestation that they observed rank-0 miss its deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessAttestation {
    /// Signer's Dilithium3 public key (used both to identify the signer
    /// via sha3_256 → identity_hash and to verify the signature).
    pub signer_public_key: Vec<u8>,
    /// Dilithium3 signature over `LivenessFailureProof::signable_bytes`.
    pub signature: Vec<u8>,
}

impl LivenessAttestation {
    /// Identity hash of the signer (used to look up stake).
    pub fn signer_identity_hash(&self) -> String {
        sha3_256_hex(&self.signer_public_key)
    }
}

/// Bundle of attestations proving rank-0 missed the `base_timeout` deadline
/// for a specific `(zone, epoch)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessFailureProof {
    /// Identity hash of the rank-0 aggregator who failed to propose.
    pub offender_identity_hash: String,
    /// The zone whose rank-0 failed.
    pub zone: ZoneId,
    /// The epoch number that rank-0 was responsible for sealing.
    pub epoch_number: u64,
    /// The zone's observed `base_timeout` in milliseconds. Signers agree
    /// on this value — a liar who inflates it cannot gather attestations.
    pub base_timeout_ms: u64,
    /// The zone's `epoch_start_ts` in milliseconds since unix epoch.
    /// Signers attest that `now_ms > epoch_start_ts_ms + base_timeout_ms`
    /// at sign-time.
    pub epoch_start_ts_ms: u64,
    /// Attestations from distinct zone stakers. Must be ≥1; 2/3 stake
    /// threshold checked by [`Self::verify_with_stakers`].
    pub attestations: Vec<LivenessAttestation>,
}

impl LivenessFailureProof {
    /// Build a proof. Does NOT verify — call [`verify`](Self::verify) or
    /// [`verify_with_stakers`](Self::verify_with_stakers) before acting.
    pub fn new(
        offender_identity_hash: String,
        zone: ZoneId,
        epoch_number: u64,
        base_timeout_ms: u64,
        epoch_start_ts_ms: u64,
        attestations: Vec<LivenessAttestation>,
    ) -> Self {
        Self {
            offender_identity_hash,
            zone,
            epoch_number,
            base_timeout_ms,
            epoch_start_ts_ms,
            attestations,
        }
    }

    /// Canonical bytes that every attestation signs. Layout:
    ///
    /// ```text
    /// LIVENESS_DOMAIN_TAG
    /// | offender_identity_hash (length-prefixed UTF-8)
    /// | zone path (length-prefixed UTF-8)
    /// | epoch_number (u64 BE)
    /// | base_timeout_ms (u64 BE)
    /// | epoch_start_ts_ms (u64 BE)
    /// ```
    ///
    /// Lengths are u32 BE so stringy fields cannot be ambiguously parsed
    /// (prevents length-extension-style attestation substitution).
    pub fn signable_bytes(
        offender_identity_hash: &str,
        zone: &ZoneId,
        epoch_number: u64,
        base_timeout_ms: u64,
        epoch_start_ts_ms: u64,
    ) -> Vec<u8> {
        let offender_bytes = offender_identity_hash.as_bytes();
        let zone_bytes = zone.path().as_bytes();
        let mut out = Vec::with_capacity(
            LIVENESS_DOMAIN_TAG.len()
                + 4 + offender_bytes.len()
                + 4 + zone_bytes.len()
                + 8 + 8 + 8,
        );
        out.extend_from_slice(LIVENESS_DOMAIN_TAG);
        out.extend_from_slice(&(offender_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(offender_bytes);
        out.extend_from_slice(&(zone_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(zone_bytes);
        out.extend_from_slice(&epoch_number.to_be_bytes());
        out.extend_from_slice(&base_timeout_ms.to_be_bytes());
        out.extend_from_slice(&epoch_start_ts_ms.to_be_bytes());
        out
    }

    /// Convenience: the signable message for *this* proof.
    pub fn message(&self) -> Vec<u8> {
        Self::signable_bytes(
            &self.offender_identity_hash,
            &self.zone,
            self.epoch_number,
            self.base_timeout_ms,
            self.epoch_start_ts_ms,
        )
    }

    /// Verify cryptographic well-formedness of the proof. Does NOT check
    /// the 2/3-stake threshold — use [`verify_with_stakers`](Self::verify_with_stakers)
    /// for the full slashing gate.
    ///
    /// Checks:
    /// 1. ≥1 attestation present.
    /// 2. `base_timeout_ms` is in the clamp range `[1000, 600_000]` used by
    ///    proposers (a liar cannot fabricate a timeout via zero/tiny base).
    /// 3. No attestation signer equals the offender (self-attestation is
    ///    degenerate and would let a rank-0 slash itself to dodge retry).
    /// 4. No two attestations share a `signer_public_key` (dup padding).
    /// 5. Every signature verifies under its `signer_public_key` against
    ///    [`message`](Self::message).
    pub fn verify(&self) -> Result<()> {
        // (1) at least one attestation
        if self.attestations.is_empty() {
            return Err(ElaraError::Wire(
                "LivenessFailureProof: no attestations".into(),
            ));
        }

        // (2) base_timeout in the proposer-clamp range
        if !(1_000..=600_000).contains(&self.base_timeout_ms) {
            return Err(ElaraError::Wire(format!(
                "LivenessFailureProof: base_timeout_ms {} outside [1000, 600000]",
                self.base_timeout_ms
            )));
        }

        // (3) offender not a signer
        for a in &self.attestations {
            if a.signer_identity_hash() == self.offender_identity_hash {
                return Err(ElaraError::Wire(
                    "LivenessFailureProof: offender cannot attest against self".into(),
                ));
            }
        }

        // (4) no duplicate signers
        let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(self.attestations.len());
        for a in &self.attestations {
            if !seen.insert(a.signer_public_key.clone()) {
                return Err(ElaraError::Wire(
                    "LivenessFailureProof: duplicate signer".into(),
                ));
            }
        }

        // (5) all signatures verify over the canonical message
        let msg = self.message();
        for (i, a) in self.attestations.iter().enumerate() {
            let ok = Identity::verify(&msg, &a.signature, &a.signer_public_key)?;
            if !ok {
                return Err(ElaraError::Crypto(format!(
                    "LivenessFailureProof: attestation #{i} signature invalid"
                )));
            }
        }

        Ok(())
    }

    /// Verify crypto well-formedness AND that signing stakers represent
    /// ≥2/3 of the zone's stake.
    ///
    /// `stakers_in_zone` is the full set of `(identity_hash, stake)` entries
    /// for the proof's zone (duplicate identities are collapsed by summing).
    ///
    /// Denominator is the total zone stake; numerator is the sum of stakes
    /// of signers who are known stakers in the zone (an attestation from a
    /// non-staker contributes 0 but does not poison the proof).
    pub fn verify_with_stakers(
        &self,
        stakers_in_zone: &[(String, u64)],
    ) -> Result<()> {
        self.verify()?;

        // Sum stakes per identity_hash (tolerate duplicate entries).
        let mut stake_by_id: std::collections::HashMap<&str, u128> =
            std::collections::HashMap::with_capacity(stakers_in_zone.len());
        let mut denominator: u128 = 0;
        for (id, stake) in stakers_in_zone {
            let s = *stake as u128;
            *stake_by_id.entry(id.as_str()).or_insert(0) += s;
            denominator += s;
        }

        if denominator == 0 {
            return Err(ElaraError::Wire(
                "LivenessFailureProof: zone has zero stake".into(),
            ));
        }

        // Numerator: unique signers' stakes.
        let mut numerator: u128 = 0;
        let mut counted: HashSet<String> = HashSet::with_capacity(self.attestations.len());
        for a in &self.attestations {
            let id = a.signer_identity_hash();
            if !counted.insert(id.clone()) {
                // verify() already rejected dup PKs, but guard dup hashes too
                continue;
            }
            if let Some(s) = stake_by_id.get(id.as_str()) {
                numerator += *s;
            }
        }

        // 2/3 threshold: 3·numerator ≥ 2·denominator (integer-safe).
        if numerator.saturating_mul(3) < denominator.saturating_mul(2) {
            return Err(ElaraError::Wire(format!(
                "LivenessFailureProof: {}/{} zone stake, need ≥2/3",
                numerator, denominator
            )));
        }

        Ok(())
    }

    /// Deterministic dedup key for a proof — one slash per `(offender, zone, epoch)`.
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.offender_identity_hash,
            self.zone.path(),
            self.epoch_number
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType};

    fn mk_identity() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    fn sign_attestation(
        signer: &Identity,
        offender: &str,
        zone: &ZoneId,
        epoch: u64,
        base_ms: u64,
        start_ms: u64,
    ) -> LivenessAttestation {
        let msg = LivenessFailureProof::signable_bytes(offender, zone, epoch, base_ms, start_ms);
        let sig = signer.sign(&msg).unwrap();
        LivenessAttestation {
            signer_public_key: signer.public_key.clone(),
            signature: sig,
        }
    }

    #[test]
    fn proof_builds_with_expected_fields() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signer_a = mk_identity();
        let att = sign_attestation(&signer_a, &offender_hash, &zone, 7, 5_000, 1_000_000);

        let proof = LivenessFailureProof::new(
            offender_hash.clone(),
            zone.clone(),
            7,
            5_000,
            1_000_000,
            vec![att],
        );

        assert_eq!(proof.offender_identity_hash, offender_hash);
        assert_eq!(proof.zone, zone);
        assert_eq!(proof.epoch_number, 7);
        assert_eq!(proof.base_timeout_ms, 5_000);
        assert_eq!(proof.epoch_start_ts_ms, 1_000_000);
        assert_eq!(proof.attestations.len(), 1);
        assert!(proof.dedup_key().contains(&offender_hash));
    }

    #[test]
    fn valid_proof_verifies_crypto() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signers: Vec<Identity> = (0..3).map(|_| mk_identity()).collect();
        let attestations = signers
            .iter()
            .map(|s| sign_attestation(s, &offender_hash, &zone, 42, 5_000, 1_000_000))
            .collect();

        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            42,
            5_000,
            1_000_000,
            attestations,
        );
        proof.verify().expect("valid proof must verify");
    }

    #[test]
    fn insufficient_stake_rejects() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        // Zone has 4 stakers × 100 each = 400 total. We'll get 1 to sign (25%).
        let stakers: Vec<Identity> = (0..4).map(|_| mk_identity()).collect();
        let staker_rows: Vec<(String, u64)> = stakers
            .iter()
            .map(|s| (sha3_256_hex(&s.public_key), 100u64))
            .collect();

        let att = sign_attestation(&stakers[0], &offender_hash, &zone, 1, 5_000, 1_000_000);
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            1,
            5_000,
            1_000_000,
            vec![att],
        );

        // Crypto check passes; stake threshold does not.
        proof.verify().unwrap();
        let err = proof.verify_with_stakers(&staker_rows).unwrap_err();
        assert!(format!("{err}").contains("need ≥2/3"), "got: {err}");
    }

    #[test]
    fn sufficient_stake_accepts() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let stakers: Vec<Identity> = (0..3).map(|_| mk_identity()).collect();
        let staker_rows: Vec<(String, u64)> = stakers
            .iter()
            .map(|s| (sha3_256_hex(&s.public_key), 100u64))
            .collect();

        // 2 of 3 sign → 200/300 → exactly 2/3.
        let attestations = stakers
            .iter()
            .take(2)
            .map(|s| sign_attestation(s, &offender_hash, &zone, 9, 5_000, 1_000_000))
            .collect();

        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            9,
            5_000,
            1_000_000,
            attestations,
        );
        proof.verify_with_stakers(&staker_rows).expect("2/3 exact must accept");
    }

    #[test]
    fn empty_attestations_rejected() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            1,
            5_000,
            1_000_000,
            vec![],
        );
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("no attestations"), "got: {err}");
    }

    #[test]
    fn offender_self_attestation_rejected() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        // Offender signs a proof against itself.
        let att = sign_attestation(&offender_id, &offender_hash, &zone, 3, 5_000, 1_000_000);
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            3,
            5_000,
            1_000_000,
            vec![att],
        );
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("offender cannot attest"), "got: {err}");
    }

    #[test]
    fn duplicate_signer_rejected() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signer = mk_identity();
        // Sign twice — identical signatures, but the dup-PK check trips first.
        let att1 = sign_attestation(&signer, &offender_hash, &zone, 2, 5_000, 1_000_000);
        let att2 = sign_attestation(&signer, &offender_hash, &zone, 2, 5_000, 1_000_000);
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            2,
            5_000,
            1_000_000,
            vec![att1, att2],
        );
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("duplicate signer"), "got: {err}");
    }

    #[test]
    fn tampered_signature_rejected() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signer = mk_identity();
        let mut att = sign_attestation(&signer, &offender_hash, &zone, 5, 5_000, 1_000_000);
        att.signature[0] ^= 0xFF;
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            5,
            5_000,
            1_000_000,
            vec![att],
        );
        let err = proof.verify().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("signature invalid") || msg.contains("Crypto"), "got: {err}");
    }

    #[test]
    fn mismatched_epoch_in_proof_rejects_sig() {
        // Attestation signed for epoch 5, but proof claims epoch 6 — the
        // recomputed canonical message differs, so the signature fails.
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signer = mk_identity();
        let att = sign_attestation(&signer, &offender_hash, &zone, 5, 5_000, 1_000_000);

        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            6, // ← different epoch
            5_000,
            1_000_000,
            vec![att],
        );
        let err = proof.verify().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("signature invalid") || msg.contains("Crypto"), "got: {err}");
    }

    #[test]
    fn degenerate_base_timeout_rejected() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        let signer = mk_identity();
        // base_timeout_ms = 500 is below the proposer clamp minimum (1000).
        let att = sign_attestation(&signer, &offender_hash, &zone, 1, 500, 1_000_000);
        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            1,
            500,
            1_000_000,
            vec![att],
        );
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("outside"), "got: {err}");
    }

    #[test]
    fn non_staker_attestations_do_not_count() {
        let offender_id = mk_identity();
        let offender_hash = sha3_256_hex(&offender_id.public_key);
        let zone = ZoneId::from_legacy(0);

        // Zone has 3 stakers × 100 each = 300 total. None sign.
        // 5 non-stakers sign instead — crypto passes, stake threshold fails.
        let stakers: Vec<Identity> = (0..3).map(|_| mk_identity()).collect();
        let staker_rows: Vec<(String, u64)> = stakers
            .iter()
            .map(|s| (sha3_256_hex(&s.public_key), 100u64))
            .collect();

        let randos: Vec<Identity> = (0..5).map(|_| mk_identity()).collect();
        let attestations = randos
            .iter()
            .map(|r| sign_attestation(r, &offender_hash, &zone, 1, 5_000, 1_000_000))
            .collect();

        let proof = LivenessFailureProof::new(
            offender_hash,
            zone,
            1,
            5_000,
            1_000_000,
            attestations,
        );
        let err = proof.verify_with_stakers(&staker_rows).unwrap_err();
        assert!(format!("{err}").contains("need ≥2/3"), "got: {err}");
    }

    // ─── additional axes ────────────────────────────────────────────────

    /// Pin `LIVENESS_DOMAIN_TAG` byte-exactly and structurally — domain
    /// separators are *the* anti-replay primitive. Any drift (rename,
    /// version bump, encoding change) makes every historical proof
    /// un-verifiable AND lets an attacker replay an old non-liveness
    /// signature as a liveness attestation. The `/v1` suffix is the
    /// upgrade primitive; if liveness proofs ever change shape, the bump
    /// becomes `/v2` and old/new are mutually unforgeable.
    #[test]
    fn batch_b_liveness_domain_tag_byte_exact_pin_with_versioning_and_namespace_invariants() {
        // Strict byte-string pin — must equal the documented constant verbatim.
        assert_eq!(LIVENESS_DOMAIN_TAG, b"ELARA/LIVENESS_FAIL/v1");
        // Byte-length pin (22 ASCII chars).
        assert_eq!(LIVENESS_DOMAIN_TAG.len(), 22);
        // ASCII-only invariant (cross-language tooling depends on this).
        for &b in LIVENESS_DOMAIN_TAG {
            assert!(
                b.is_ascii() && !b.is_ascii_control(),
                "domain tag byte {b:#x} must be printable ASCII"
            );
        }
        // Namespace prefix invariant: every Elara protocol tag begins with
        // "ELARA/" — a regression that dropped the prefix would collide
        // with any other crate using a bare "LIVENESS_FAIL" tag.
        assert!(
            LIVENESS_DOMAIN_TAG.starts_with(b"ELARA/"),
            "all Elara domain tags MUST share the ELARA/ namespace prefix"
        );
        // Version suffix invariant: `/v1` MUST be the last 3 bytes — the
        // upgrade primitive. A future v2 must bump the suffix to make old
        // and new proofs mutually unforgeable.
        assert!(
            LIVENESS_DOMAIN_TAG.ends_with(b"/v1"),
            "domain tag MUST carry the /v1 versioning suffix"
        );
        // Discriminator: the middle section (between ELARA/ and /v1) must
        // be exactly "LIVENESS_FAIL" — a typo to "LIVENES_FAIL" or
        // "LIVENESS_FAILED" would silently break verification.
        let body = &LIVENESS_DOMAIN_TAG[b"ELARA/".len()..LIVENESS_DOMAIN_TAG.len() - b"/v1".len()];
        assert_eq!(body, b"LIVENESS_FAIL");
    }

    /// Pin `LIVENESS_SLASH_PERCENT` and its ordering against the other
    /// slash percentages in the crate. The Protocol §11.13 graduation
    /// rule: liveness (soft evidence) < equivocation/geo-fraud (hard
    /// evidence) ≤ MAX. A tuner who lifted LIVENESS to 0.5 would silently
    /// equalize hard and soft evidence — breaking the graduated-penalty
    /// invariant.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_liveness_slash_percent_strict_pin_with_graduated_ordering_against_other_slash_constants() {
        // Strict literal pin — 1%.
        assert_eq!(LIVENESS_SLASH_PERCENT, 0.01_f64);
        // Finite, strictly positive, strictly below 1.0 (a 100%-or-more
        // slash for soft evidence would tank the staker without trial).
        assert!(LIVENESS_SLASH_PERCENT.is_finite());
        assert!(LIVENESS_SLASH_PERCENT > 0.0);
        assert!(LIVENESS_SLASH_PERCENT < 1.0);
        // Graduated-ordering invariant — soft < hard.
        assert!(
            LIVENESS_SLASH_PERCENT < crate::network::slashing::GEO_FRAUD_SLASH_PERCENT,
            "LIVENESS (soft) must be < GEO_FRAUD/equivocation (hard) — graduated penalty per §11.13"
        );
        // Soft < MAX_SLASH_PERCENTAGE (50% ceiling).
        assert!(
            LIVENESS_SLASH_PERCENT < crate::accounting::types::MAX_SLASH_PERCENTAGE,
            "LIVENESS (1%) must stay under MAX_SLASH_PERCENTAGE (50%) ceiling"
        );
        // 25× ratio invariant: GEO_FRAUD/LIVENESS == 25 — the documented
        // graduation gap. A tuner who narrowed this to 2× would soften the
        // "soft evidence" signaling. Use floating-point tolerance for the
        // ratio compare since IEEE-754 division can drift.
        let ratio = crate::network::slashing::GEO_FRAUD_SLASH_PERCENT / LIVENESS_SLASH_PERCENT;
        assert!(
            (ratio - 25.0).abs() < 1e-9,
            "GEO_FRAUD/LIVENESS ratio must be 25.0 (got {ratio}); the 1%↔25% graduation gap is load-bearing"
        );
    }

    /// Pin the exact wire layout produced by
    /// `LivenessFailureProof::signable_bytes`. The byte-layout is the
    /// signed-over message — a rename, a length-prefix size change, or a
    /// field reorder makes every historical attestation invalid. Verify:
    /// (1) starts with `LIVENESS_DOMAIN_TAG` verbatim, (2) length prefixes
    /// are u32 BE, (3) numeric fields are u64 BE in declaration order
    /// (epoch_number, base_timeout_ms, epoch_start_ts_ms), (4) total
    /// length matches the doc'd layout: `tag + 4 + offender + 4 + zone +
    /// 8 + 8 + 8`.
    #[test]
    fn batch_b_liveness_failure_proof_signable_bytes_exact_layout_pin() {
        let offender = "deadbeef".to_string();
        let zone = ZoneId::from_legacy(0);
        let epoch = 0x0102_0304_0506_0708_u64;
        let base_ms = 5_000_u64;
        let start_ms = 1_000_000_u64;

        let bytes = LivenessFailureProof::signable_bytes(&offender, &zone, epoch, base_ms, start_ms);

        // (1) Prefix MUST equal the domain tag verbatim.
        assert!(
            bytes.starts_with(LIVENESS_DOMAIN_TAG),
            "signable_bytes MUST start with LIVENESS_DOMAIN_TAG"
        );

        // (4) Total length pin: tag(22) + 4 + |offender|(8 hex) + 4 + |zone path| + 8*3
        let zone_path_len = zone.path().len();
        let expected_len = LIVENESS_DOMAIN_TAG.len()
            + 4 + offender.len()
            + 4 + zone_path_len
            + 8 + 8 + 8;
        assert_eq!(
            bytes.len(),
            expected_len,
            "signable_bytes length must match documented layout: tag + 4 + offender + 4 + zone + 24"
        );

        // (2)+(3) Walk the layout offset-by-offset.
        let mut cursor = LIVENESS_DOMAIN_TAG.len();
        // u32 BE length of offender_bytes
        let offender_len_be = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        assert_eq!(offender_len_be as usize, offender.len());
        cursor += 4;
        // Offender bytes
        assert_eq!(&bytes[cursor..cursor + offender.len()], offender.as_bytes());
        cursor += offender.len();
        // u32 BE length of zone_bytes
        let zone_len_be = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        assert_eq!(zone_len_be as usize, zone_path_len);
        cursor += 4;
        // Zone bytes
        assert_eq!(&bytes[cursor..cursor + zone_path_len], zone.path().as_bytes());
        cursor += zone_path_len;
        // u64 BE epoch
        let epoch_be = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        assert_eq!(epoch_be, epoch);
        cursor += 8;
        // u64 BE base_timeout_ms
        let base_be = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        assert_eq!(base_be, base_ms);
        cursor += 8;
        // u64 BE epoch_start_ts_ms
        let start_be = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        assert_eq!(start_be, start_ms);
        cursor += 8;
        assert_eq!(cursor, bytes.len(), "cursor must land exactly at end of layout");

        // Different inputs MUST produce different messages (sanity for the
        // domain-separation contract).
        let other = LivenessFailureProof::signable_bytes(
            &offender, &zone, epoch + 1, base_ms, start_ms,
        );
        assert_ne!(bytes, other);
    }

    /// Pin `LivenessFailureProof::dedup_key` exact format. The dedup
    /// contract: "at most one liveness slash per (offender, zone, epoch)".
    /// Format `{offender_hash}:{zone_path}:{epoch}` — a colon separator
    /// drift would silently re-emit historical slashes; a field reorder
    /// would change every key. Pre-batch test only checks `contains`,
    /// not the format.
    #[test]
    fn batch_b_liveness_failure_proof_dedup_key_exact_format_with_three_field_propagation() {
        let zone = ZoneId::from_legacy(0);
        let zone_path = zone.path();

        let signer = mk_identity();
        let att = sign_attestation(&signer, "offender_X", &zone, 100, 5_000, 1_000_000);

        let p = LivenessFailureProof::new(
            "offender_X".to_string(),
            zone.clone(),
            100,
            5_000,
            1_000_000,
            vec![att.clone()],
        );

        // Strict format pin: {offender}:{zone_path}:{epoch}
        assert_eq!(p.dedup_key(), format!("offender_X:{zone_path}:100"));
        // Offender propagates.
        let p_other_off = LivenessFailureProof::new(
            "offender_Y".to_string(),
            zone.clone(),
            100,
            5_000,
            1_000_000,
            vec![att.clone()],
        );
        assert_ne!(p.dedup_key(), p_other_off.dedup_key());
        // Epoch propagates.
        let p_other_epoch = LivenessFailureProof::new(
            "offender_X".to_string(),
            zone.clone(),
            101,
            5_000,
            1_000_000,
            vec![att.clone()],
        );
        assert_ne!(p.dedup_key(), p_other_epoch.dedup_key());
        // base_timeout_ms / epoch_start_ts_ms / attestations MUST NOT
        // participate in dedup_key (slash-per-tuple is on the canonical
        // (offender, zone, epoch) triple only).
        let p_diff_timing = LivenessFailureProof::new(
            "offender_X".to_string(),
            zone.clone(),
            100,
            9_999,
            42_000_000,
            vec![att.clone()],
        );
        assert_eq!(
            p.dedup_key(),
            p_diff_timing.dedup_key(),
            "timing fields MUST NOT participate in dedup_key — one slash per (offender, zone, epoch)"
        );
        // Two colons exactly (format has exactly 2 separator colons).
        assert_eq!(
            p.dedup_key().matches(':').count(),
            2,
            "dedup_key must have exactly 2 colon separators"
        );
    }

    /// Pin `LivenessAttestation::signer_identity_hash` determinism and
    /// SHA3-256 shape. Hash MUST be deterministic (same pk → same hash),
    /// distinct (different pk → different hash, with probability 1 in the
    /// 256-bit space), and exactly 64 hex chars (32-byte SHA3-256 hex-
    /// encoded). A regression that swapped SHA3 for SHA2 or stripped the
    /// hex-encoding would change every identity_hash in the cluster.
    #[test]
    fn batch_b_liveness_attestation_signer_identity_hash_sha3_256_hex_determinism_and_distinctness() {
        let id_a = mk_identity();
        let id_b = mk_identity();

        let att_a1 = LivenessAttestation {
            signer_public_key: id_a.public_key.clone(),
            signature: vec![0u8; 32],
        };
        let att_a2 = LivenessAttestation {
            signer_public_key: id_a.public_key.clone(),
            signature: vec![1u8; 32], // different sig, same key
        };
        let att_b = LivenessAttestation {
            signer_public_key: id_b.public_key.clone(),
            signature: vec![0u8; 32],
        };

        let h_a1 = att_a1.signer_identity_hash();
        let h_a2 = att_a2.signer_identity_hash();
        let h_b = att_b.signer_identity_hash();

        // Determinism: same pk → same hash (signature is NOT in the hash).
        assert_eq!(
            h_a1, h_a2,
            "signer_identity_hash must depend only on public_key, not signature"
        );
        // Distinctness: different pk → different hash.
        assert_ne!(h_a1, h_b, "distinct pks must yield distinct identity_hashes");
        // SHA3-256 hex shape: 64 lowercase hex chars.
        assert_eq!(h_a1.len(), 64, "SHA3-256 hex must be exactly 64 chars");
        assert!(
            h_a1.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())),
            "SHA3-256 hex must be lowercase hex"
        );
        // Verbatim cross-check: signer_identity_hash MUST equal the canonical
        // sha3_256_hex of the public_key bytes.
        assert_eq!(
            h_a1,
            sha3_256_hex(&id_a.public_key),
            "signer_identity_hash must equal sha3_256_hex(public_key)"
        );
    }
}
