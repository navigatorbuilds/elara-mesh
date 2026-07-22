//! ConflictProof — cryptographic evidence of slot equivocation.
//!
//! A `ConflictProof` bundles two `ValidationRecord`s that both claim the same
//! slot `(account, nonce)` but carry different content. Because the slot
//! tuple is covered by each record's Dilithium3 signature (wire v5+), a valid
//! pair of signatures from the same `creator_public_key` over two distinct
//! `content_hash` values is undeniable proof that the creator double-spent
//! the slot.
//!
//! This is the BFT equivocation primitive for MESH-BFT Phase 3 Stage 1D:
//! any node observing the conflict gossips the proof; the genesis authority
//! (and later, fisherman juries) consume the proof and emit a slash record.
//!
//! Spec references:
//!   @spec Protocol §11.12 (planned v0.7.1)
//!   @spec MESH-BFT Theorem 3.1 (planned v0.1.1)

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256_hex;
use crate::errors::{ElaraError, Result};
use crate::identity::Identity;
use crate::record::ValidationRecord;

/// Two `ValidationRecord`s proving the same creator signed two different
/// contents into the same slot. Minimum wire version for both records is 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictProof {
    /// First record observed for the slot.
    pub record_a: ValidationRecord,
    /// Second record observed for the slot (different content, same slot).
    pub record_b: ValidationRecord,
}

impl ConflictProof {
    /// Build a proof from two conflicting records. Does NOT verify — call
    /// [`verify`](Self::verify) before acting on it.
    pub fn new(record_a: ValidationRecord, record_b: ValidationRecord) -> Self {
        Self { record_a, record_b }
    }

    /// The slot key both records claim. Returns `None` if either record is
    /// pre-v5 (no nonce) or if the two records disagree on the slot — in
    /// either case there is no well-formed slot conflict to prove.
    pub fn slot_key(&self) -> Option<String> {
        let a = self.record_a.slot_key()?;
        let b = self.record_b.slot_key()?;
        if a == b { Some(a) } else { None }
    }

    /// Identity hash of the offending creator (sha3_256 of creator_public_key).
    pub fn offender_identity_hash(&self) -> String {
        sha3_256_hex(&self.record_a.creator_public_key)
    }

    /// Verify this proof is well-formed and cryptographically valid.
    ///
    /// A valid proof satisfies all of:
    /// 1. Both records are wire v5+ (carry a signed nonce).
    /// 2. Both records claim the same slot `(account, nonce)`.
    /// 3. Both records share the same `creator_public_key`.
    /// 4. The records have distinct `id`s AND distinct `record_hash()`es.
    ///    A pair is "duplicate, not conflict" ONLY when the signed bytes are
    ///    identical. The discriminator is deliberately `record_hash()`
    ///    (sha3 over signable_bytes — id, nonce, metadata, everything
    ///    signed), NOT `content_hash`: content_hash is a creator-supplied
    ///    field, so an equivocator could hand-set the same value on two
    ///    conflicting records and make the pair unprovable (audit
    ///    2026-07-06). Two distinct signed records claiming one slot ARE
    ///    equivocation, even if their declared content matches — a
    ///    well-behaved client re-submits the SAME record, it never re-signs
    ///    a new one for an occupied slot.
    /// 5. Both Dilithium3 signatures verify under the shared public key
    ///    against each record's `signable_bytes()`.
    pub fn verify(&self) -> Result<()> {
        // (1) wire v5+ gate
        if self.record_a.version < 5 || self.record_b.version < 5 {
            return Err(ElaraError::Wire(
                "ConflictProof requires wire v5+ on both records".into(),
            ));
        }

        // (2) same slot
        let slot_a = self.record_a.slot_key()
            .ok_or_else(|| ElaraError::Wire("record_a has no slot_key".into()))?;
        let slot_b = self.record_b.slot_key()
            .ok_or_else(|| ElaraError::Wire("record_b has no slot_key".into()))?;
        if slot_a != slot_b {
            return Err(ElaraError::Wire(format!(
                "ConflictProof slot mismatch: {} vs {}", slot_a, slot_b
            )));
        }

        // (3) same creator
        if self.record_a.creator_public_key != self.record_b.creator_public_key {
            return Err(ElaraError::Wire(
                "ConflictProof creator_public_key mismatch — not equivocation".into(),
            ));
        }

        // (4) distinct identity: different record IDs AND different content
        if self.record_a.id == self.record_b.id {
            return Err(ElaraError::Wire(
                "ConflictProof records share record_id — duplicate, not conflict".into(),
            ));
        }
        if self.record_a.record_hash() == self.record_b.record_hash() {
            return Err(ElaraError::Wire(
                "ConflictProof records share record_hash — duplicate, not conflict".into(),
            ));
        }

        // (5) both signatures verify
        for (label, rec) in [("record_a", &self.record_a), ("record_b", &self.record_b)] {
            let sig = rec.signature.as_deref().ok_or_else(|| {
                ElaraError::Wire(format!("ConflictProof {label} missing signature"))
            })?;
            let msg = rec.signable_bytes();
            let ok = Identity::verify(&msg, sig, &rec.creator_public_key)?;
            if !ok {
                return Err(ElaraError::Crypto(format!(
                    "ConflictProof {label} signature invalid"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType};
    use crate::record::{Classification, ValidationRecord};
    use std::collections::BTreeMap;

    /// Build a signed v5 record with the given nonce and content from `id`.
    fn signed_v5(
        identity: &Identity,
        nonce: u64,
        content: &[u8],
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = nonce;
        // Drive both records into the same zone by pinning explicit zone.
        rec.zone = Some(crate::ZoneId::from_legacy(0));
        identity.sign_record_light(&mut rec).unwrap();
        rec
    }

    /// Like `signed_v5` but pins the record timestamp before signing.
    /// Use this when the test serializes + deserializes the record via JSON
    /// and then re-verifies the signature — JSON's f64 round-trip is not
    /// bit-exact on the full f64 range, but small integer-valued f64s
    /// round-trip exactly.
    fn signed_v5_at(
        identity: &Identity,
        nonce: u64,
        content: &[u8],
        timestamp: f64,
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = nonce;
        rec.timestamp = timestamp;
        rec.zone = Some(crate::ZoneId::from_legacy(0));
        identity.sign_record_light(&mut rec).unwrap();
        rec
    }

    fn test_identity() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    #[test]
    fn valid_conflict_proof_verifies() {
        let id = test_identity();
        let a = signed_v5(&id, 42, b"content-alpha");
        let b = signed_v5(&id, 42, b"content-beta");
        let proof = ConflictProof::new(a, b);
        proof.verify().expect("valid conflict proof must verify");
        assert!(proof.slot_key().is_some());
    }

    #[test]
    fn different_nonces_not_a_conflict() {
        let id = test_identity();
        let a = signed_v5(&id, 1, b"content-alpha");
        let b = signed_v5(&id, 2, b"content-beta");
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("slot mismatch"), "got: {err}");
    }

    #[test]
    fn different_creators_reject_via_slot_mismatch() {
        // Two different creators cannot produce the same slot — slot_key
        // derives from creator_public_key, so distinct PKs always mean
        // distinct slots. The slot-mismatch check trips before the
        // (redundant, defense-in-depth) PK-equality check in verify().
        let id_a = test_identity();
        let id_b = test_identity();
        let a = signed_v5(&id_a, 7, b"content-alpha");
        let b = signed_v5(&id_b, 7, b"content-beta");
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("slot mismatch"), "got: {err}");
    }

    #[test]
    fn true_duplicate_identical_record_rejected() {
        let id = test_identity();
        // A relay duplicate is the SAME record twice — identical signed
        // bytes, identical id. The id-equality gate fires.
        let a = signed_v5(&id, 9, b"same-content");
        let b = a.clone();
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("record_id"), "got: {err}");
    }

    #[test]
    fn same_content_resigned_distinct_ids_is_equivocation() {
        let id = test_identity();
        // Semantics flip pinned (audit 2026-07-06): two DISTINCT signed
        // records claiming one slot are equivocation even when their
        // declared content matches. Under the old content_hash
        // discriminator this pair was unprovable ("duplicate, not
        // conflict") — which also let an attacker hand-set equal
        // content_hashes on two genuinely different transfers to dodge the
        // proof entirely.
        let mut a = signed_v5(&id, 9, b"same-content");
        let b = a.clone();
        a.id = "alpha".into();
        let mut b = b;
        b.id = "beta".into();
        // Re-sign both so signatures match the new ids.
        id.sign_record_light(&mut a).unwrap();
        id.sign_record_light(&mut b).unwrap();
        let proof = ConflictProof::new(a, b);
        proof
            .verify()
            .expect("distinct signed records on one slot must verify as conflict");
    }

    #[test]
    fn hand_set_equal_content_hash_still_provable() {
        let id = test_identity();
        // The attack the discriminator swap closes: same slot, genuinely
        // different operations (different content bytes), but the
        // equivocator hand-sets record_b's content_hash equal to
        // record_a's before signing. content_hash is signed but
        // creator-supplied — equality proves nothing. The proof must still
        // verify via record_hash inequality.
        let a = signed_v5(&id, 11, b"transfer-to-x");
        let mut b = signed_v5(&id, 11, b"transfer-to-y");
        b.content_hash = a.content_hash.clone();
        id.sign_record_light(&mut b).unwrap();
        let proof = ConflictProof::new(a, b);
        proof
            .verify()
            .expect("hand-set equal content_hash must not dodge the conflict proof");
    }

    #[test]
    fn v4_records_rejected() {
        let id = test_identity();
        let mut a = signed_v5(&id, 5, b"content-alpha");
        let mut b = signed_v5(&id, 5, b"content-beta");
        a.version = 4;
        b.version = 4;
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("v5+"), "got: {err}");
    }

    #[test]
    fn tampered_signature_rejected() {
        let id = test_identity();
        let a = signed_v5(&id, 11, b"content-alpha");
        let mut b = signed_v5(&id, 11, b"content-beta");
        // Flip a byte in b's signature
        if let Some(sig) = b.signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(
            format!("{err}").contains("signature invalid") || format!("{err}").contains("Crypto"),
            "got: {err}"
        );
    }

    #[test]
    fn same_record_id_rejected() {
        let id = test_identity();
        let mut a = signed_v5(&id, 3, b"content-alpha");
        let mut b = signed_v5(&id, 3, b"content-beta");
        b.id = a.id.clone();
        // Re-sign both with shared id so the shared-id check, not the sig check, trips.
        id.sign_record_light(&mut a).unwrap();
        id.sign_record_light(&mut b).unwrap();
        let proof = ConflictProof::new(a, b);
        let err = proof.verify().unwrap_err();
        assert!(format!("{err}").contains("record_id"), "got: {err}");
    }

    // 5 axes that ADD coverage orthogonal to the 7 existing
    // scenario tests (which `.contains(...)`-match the verify() string surface).
    // These pin (1) struct shape + Clone semantics + Serde round-trip,
    // (2) `new()` constructor field placement + no-verify side-effect,
    // (3) `slot_key()` public-API Some/None matrix,
    // (4) `offender_identity_hash()` formula + invariants + record_a dependence,
    // (5) `verify()` error VARIANT (Wire vs Crypto), which the existing tests
    // assert only via stringy `.contains(...)`.

    #[test]
    fn batch_b_struct_shape_two_field_destructure_clone_independence_serde_roundtrip() {
        // (1) PIN: ConflictProof is a 2-field struct {record_a, record_b}.
        // Exhaustive destructure WITHOUT `..rest` fails to compile if a
        // future PR adds a third field — operator log greps + Debug field-
        // name surface would silently shift.
        let id = test_identity();
        // Pin record timestamps to a JSON-bit-exact f64 value before signing.
        // signable_bytes() packs timestamp as raw to_be_bytes; serde_json's
        // f64 round-trip is not guaranteed bit-exact on the full f64 range
        // (ryu encodes the shortest decimal that the parser will round back
        // to the same f64, but some now_timestamp() values land one ULP off
        // after serde_json's parse path — manifesting as an intermittent
        // signature-verify failure on the deserialized record). A small
        // integer-valued f64 round-trips through JSON bit-identically.
        let a = signed_v5_at(&id, 100, b"alpha-content", 1_700_000_000.0);
        let b = signed_v5_at(&id, 100, b"beta-content", 1_700_000_000.0);
        let proof = ConflictProof::new(a.clone(), b.clone());

        // Exhaustive destructure shape pin (compile-time guard).
        let ConflictProof { record_a, record_b } = proof.clone();
        assert_eq!(record_a.id, a.id);
        assert_eq!(record_b.id, b.id);

        // Clone deep-copies — mutating clone leaves base untouched.
        let mut cloned = proof.clone();
        cloned.record_a.id = "tampered-id".into();
        assert_ne!(
            cloned.record_a.id, proof.record_a.id,
            "Clone must be a deep copy (Vec field independence)"
        );
        assert_eq!(
            proof.record_a.id, a.id,
            "mutation on clone must not leak into original"
        );

        // Debug surface renders both field names — operator-log greppability.
        let dbg = format!("{:?}", proof);
        assert!(dbg.contains("record_a"), "Debug must surface record_a field name");
        assert!(dbg.contains("record_b"), "Debug must surface record_b field name");

        // Serde round-trip preserves both records (JSON wire format).
        let json = serde_json::to_string(&proof)
            .expect("ConflictProof must serialize to JSON");
        let restored: ConflictProof = serde_json::from_str(&json)
            .expect("ConflictProof must deserialize from JSON");
        assert_eq!(restored.record_a.id, proof.record_a.id);
        assert_eq!(restored.record_b.id, proof.record_b.id);
        assert_eq!(restored.record_a.content_hash, proof.record_a.content_hash);
        assert_eq!(restored.record_b.content_hash, proof.record_b.content_hash);
        restored
            .verify()
            .expect("round-tripped valid proof must still verify");
    }

    #[test]
    fn batch_b_new_constructor_field_placement_and_no_verify_side_effect() {
        // (2) PIN: `new(a, b)` assigns the FIRST argument to `record_a` and
        // the SECOND to `record_b` (deterministic placement, not arbitrary).
        // A future refactor that swaps the constructor order would silently
        // break every caller that relies on `proof.record_a` being the
        // operator-named "first observed" record.
        let id = test_identity();
        let a = signed_v5(&id, 200, b"first-observed");
        let b = signed_v5(&id, 200, b"second-observed");

        let proof_ab = ConflictProof::new(a.clone(), b.clone());
        assert_eq!(
            proof_ab.record_a.id, a.id,
            "new(a, b).record_a MUST equal first argument"
        );
        assert_eq!(
            proof_ab.record_b.id, b.id,
            "new(a, b).record_b MUST equal second argument"
        );

        // Swap: new(b, a) puts b in record_a and a in record_b. Both forms
        // are still VALID proofs of the same conflict (equivocation is
        // symmetric in the two records) — but the field placement differs.
        let proof_ba = ConflictProof::new(b.clone(), a.clone());
        assert_eq!(proof_ba.record_a.id, b.id);
        assert_eq!(proof_ba.record_b.id, a.id);
        assert_ne!(
            proof_ab.record_a.id, proof_ba.record_a.id,
            "swap MUST place the swapped record in record_a slot"
        );

        // Equivocation is symmetric — both swaps verify.
        proof_ab.verify().expect("(a, b) must verify");
        proof_ba.verify().expect("(b, a) must verify — equivocation is symmetric");

        // new() MUST NOT call verify() under the hood — a tampered proof
        // must still construct (caller calls verify() explicitly per the
        // doc-comment contract on `new`).
        let mut tampered_a = a.clone();
        if let Some(sig) = tampered_a.signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let _proof_tampered = ConflictProof::new(tampered_a, b);
        // Constructing without panic confirms new() does not call verify()
        // (which would have returned Err on tampered sig).
    }

    #[test]
    fn batch_b_slot_key_public_api_some_none_matrix() {
        // (3) PIN: `ConflictProof::slot_key()` returns Some(key) only when
        // BOTH records are v5+ AND their slot_keys are equal; None in every
        // other case. The existing tests only exercise the verify() side of
        // slot mismatch — this pins the public slot_key() helper directly.
        let id = test_identity();

        // (a) v5 + same slot → Some(equal_key).
        let a_v5 = signed_v5(&id, 300, b"alpha");
        let b_v5 = signed_v5(&id, 300, b"beta");
        let proof_v5_same = ConflictProof::new(a_v5.clone(), b_v5.clone());
        let slot = proof_v5_same.slot_key();
        assert!(slot.is_some(), "v5 + same slot must yield Some(slot_key)");
        // Slot key format pinned in record.rs:678 — {account_hash:64hex}:{nonce:016x}
        let key = slot.unwrap();
        assert_eq!(
            key,
            a_v5.slot_key().unwrap(),
            "ConflictProof.slot_key() must equal record_a.slot_key() on agreement"
        );

        // (b) v5 + different nonces (so different slots) → None.
        let a_v5_n1 = signed_v5(&id, 301, b"alpha");
        let b_v5_n2 = signed_v5(&id, 302, b"beta");
        let proof_v5_diff = ConflictProof::new(a_v5_n1, b_v5_n2);
        assert!(
            proof_v5_diff.slot_key().is_none(),
            "v5 + different slots must yield None"
        );

        // (c) v4 on record_a (record_b v5) → None (v4.slot_key returns None,
        //     so the `?` operator short-circuits before the equality check).
        let mut a_v4 = signed_v5(&id, 303, b"alpha");
        a_v4.version = 4;
        let b_v5_c = signed_v5(&id, 303, b"beta");
        let proof_mixed_a = ConflictProof::new(a_v4, b_v5_c);
        assert!(
            proof_mixed_a.slot_key().is_none(),
            "v4 on record_a must short-circuit slot_key() to None"
        );

        // (d) v4 on record_b (record_a v5) → None.
        let a_v5_d = signed_v5(&id, 304, b"alpha");
        let mut b_v4 = signed_v5(&id, 304, b"beta");
        b_v4.version = 4;
        let proof_mixed_b = ConflictProof::new(a_v5_d, b_v4);
        assert!(
            proof_mixed_b.slot_key().is_none(),
            "v4 on record_b must short-circuit slot_key() to None"
        );

        // (e) v4 on both → None.
        let mut a_v4_both = signed_v5(&id, 305, b"alpha");
        let mut b_v4_both = signed_v5(&id, 305, b"beta");
        a_v4_both.version = 4;
        b_v4_both.version = 4;
        let proof_v4_both = ConflictProof::new(a_v4_both, b_v4_both);
        assert!(
            proof_v4_both.slot_key().is_none(),
            "v4 on both must yield None"
        );
    }

    #[test]
    fn batch_b_offender_identity_hash_formula_invariants_and_record_a_dependence() {
        // (4) PIN: `offender_identity_hash()` returns
        // `sha3_256_hex(&self.record_a.creator_public_key)` — formula pin.
        // Catches a future refactor that switches to record_b, to a different
        // hash function (Blake3/sha2/etc), or to a different input (e.g.
        // creator_id instead of public_key bytes).
        let id_a = test_identity();
        let id_b = test_identity();

        // Formula pin: equals sha3_256_hex of record_a's public key exactly.
        let a = signed_v5(&id_a, 400, b"content");
        let b = signed_v5(&id_a, 400, b"different");
        let proof = ConflictProof::new(a.clone(), b.clone());
        let computed = sha3_256_hex(&id_a.public_key);
        assert_eq!(
            proof.offender_identity_hash(),
            computed,
            "offender_identity_hash MUST equal sha3_256_hex(record_a.creator_public_key)"
        );

        // Deterministic across calls.
        assert_eq!(
            proof.offender_identity_hash(),
            proof.offender_identity_hash(),
            "offender_identity_hash MUST be deterministic"
        );

        // Output shape: 64-char lowercase hex (sha3_256 output).
        let h = proof.offender_identity_hash();
        assert_eq!(h.len(), 64, "sha3_256 hex must be exactly 64 chars");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())),
            "sha3_256 hex must be lowercase ASCII hex"
        );

        // Swap-invariant when creators match: new(b, a) produces the SAME
        // offender hash because both records share creator_public_key and
        // the function reads record_a in either layout.
        let proof_swap = ConflictProof::new(b.clone(), a.clone());
        assert_eq!(
            proof.offender_identity_hash(),
            proof_swap.offender_identity_hash(),
            "swap with same creator MUST preserve offender hash"
        );

        // Distinct creators → distinct offender hashes (regression guard:
        // if the function ever returned a constant, this would catch it).
        let a_other = signed_v5(&id_b, 400, b"content");
        let proof_other = ConflictProof::new(a_other, b.clone());
        assert_ne!(
            proof.offender_identity_hash(),
            proof_other.offender_identity_hash(),
            "distinct creators MUST yield distinct offender hashes"
        );

        // record_a dependence (regression guard): an artificial proof where
        // record_a's creator differs from record_b's STILL returns
        // record_a's hash — pins that the function reads ONLY record_a,
        // not record_b, not some hybrid. Constructing a malformed proof
        // here is fine — `new()` does not validate per axis 2 above.
        let malformed = ConflictProof::new(
            signed_v5(&id_a, 401, b"a-content"),
            signed_v5(&id_b, 401, b"b-content"),
        );
        let from_a = sha3_256_hex(&id_a.public_key);
        let from_b = sha3_256_hex(&id_b.public_key);
        assert_eq!(
            malformed.offender_identity_hash(),
            from_a,
            "function MUST read record_a's creator_public_key"
        );
        assert_ne!(
            malformed.offender_identity_hash(),
            from_b,
            "function MUST NOT read record_b's creator_public_key"
        );
    }

    #[test]
    fn batch_b_verify_error_variant_matrix_wire_vs_crypto_with_discriminant_distinct() {
        // (5) PIN: `verify()` returns ElaraError::Wire for the structural
        // gates (v5+, slot mismatch, record_id share, content_hash share,
        // missing signature) AND ElaraError::Crypto for the signature-
        // verify gate. Existing tests only `.contains(...)` against the
        // Display message; this pins the enum VARIANT, which catches a
        // refactor that collapses everything to a single error type.
        let id = test_identity();

        // Wire variant: v4 records.
        let mut a = signed_v5(&id, 500, b"alpha");
        let mut b = signed_v5(&id, 500, b"beta");
        a.version = 4;
        b.version = 4;
        let err_v4 = ConflictProof::new(a, b).verify().unwrap_err();
        assert!(
            matches!(err_v4, ElaraError::Wire(_)),
            "v4 rejection MUST be ElaraError::Wire, got {err_v4:?}"
        );

        // Wire variant: slot mismatch (different nonces).
        let a_n1 = signed_v5(&id, 510, b"alpha");
        let b_n2 = signed_v5(&id, 511, b"beta");
        let err_slot = ConflictProof::new(a_n1, b_n2).verify().unwrap_err();
        assert!(
            matches!(err_slot, ElaraError::Wire(_)),
            "slot mismatch MUST be ElaraError::Wire, got {err_slot:?}"
        );

        // Wire variant: same record_id.
        let mut a_id = signed_v5(&id, 520, b"alpha");
        let mut b_id = signed_v5(&id, 520, b"beta");
        b_id.id = a_id.id.clone();
        id.sign_record_light(&mut a_id).unwrap();
        id.sign_record_light(&mut b_id).unwrap();
        let err_id = ConflictProof::new(a_id, b_id).verify().unwrap_err();
        assert!(
            matches!(err_id, ElaraError::Wire(_)),
            "record_id share MUST be ElaraError::Wire, got {err_id:?}"
        );

        // Wire variant: duplicate record_hash. A record_hash share implies
        // identical signable bytes, which implies identical ids — so the
        // id-equality gate (pinned above) is the reachable form of the
        // duplicate rejection; the record_hash gate behind it is
        // defense-in-depth. The old content_hash-share leg was DELETED
        // (audit 2026-07-06): a same-content re-signed pair is now a
        // VERIFYING conflict by design (see
        // same_content_resigned_distinct_ids_is_equivocation), because the
        // content_hash discriminator let equivocators hand-set equal
        // hashes to dodge the proof.
        let base = signed_v5(&id, 530, b"same-content");
        let mut a_dup = base.clone();
        let mut b_dup = base.clone();
        a_dup.id = "alpha-id".into();
        b_dup.id = "beta-id".into();
        id.sign_record_light(&mut a_dup).unwrap();
        id.sign_record_light(&mut b_dup).unwrap();
        ConflictProof::new(a_dup, b_dup)
            .verify()
            .expect("re-signed same-content pair is a conflict post-audit");

        // Wire variant: missing signature on one record. The structural
        // gate fires BEFORE the cryptographic verify, so the error must be
        // Wire (not Crypto) — pinning this catches a refactor that elevates
        // missing-sig to a Crypto-level error and breaks operator triage
        // semantics ("Wire" = structural/wire-format, "Crypto" = sig-fail).
        let a_ms = signed_v5(&id, 540, b"alpha");
        let mut b_ms = signed_v5(&id, 540, b"beta");
        b_ms.signature = None;
        let err_missing = ConflictProof::new(a_ms, b_ms).verify().unwrap_err();
        assert!(
            matches!(err_missing, ElaraError::Wire(_)),
            "missing signature MUST be ElaraError::Wire (not Crypto), got {err_missing:?}"
        );

        // Crypto variant: tampered signature (passes structural gates,
        // fails Identity::verify).
        let a_tamper = signed_v5(&id, 550, b"alpha");
        let mut b_tamper = signed_v5(&id, 550, b"beta");
        if let Some(sig) = b_tamper.signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let err_crypto = ConflictProof::new(a_tamper, b_tamper).verify().unwrap_err();
        assert!(
            matches!(err_crypto, ElaraError::Crypto(_)),
            "tampered signature MUST be ElaraError::Crypto (not Wire), got {err_crypto:?}"
        );

        // Wire-vs-Crypto discriminant distinct: a future refactor that
        // collapses both gates to one variant would break here.
        let wire_disc = std::mem::discriminant(&err_v4);
        let crypto_disc = std::mem::discriminant(&err_crypto);
        assert_ne!(
            wire_disc, crypto_disc,
            "Wire and Crypto variants MUST be discriminant-distinct"
        );
    }
}
