//! Signing-dependent tests for `elara_verify`'s construction-disagreement probe
//! (parked node-side for the same reason as `mandate_bundle_tests`: elara-verify
//! is signing-incapable by design, and these fixtures need a live signature over
//! a preimage the verifier will NOT rebuild).
//!
//! What they pin: a record whose signature was made under an earlier preimage
//! construction than its own `version` field declares must report WHY it failed
//! (canonicalisation disagreement) instead of reading as a forgery, and must
//! still FAIL. A genuine forgery must keep the plain detail: the probe may never
//! manufacture an excuse for a signature nobody with the key produced.
//!
//! Raised by @meloliva14 in x402-foundation/wg-identity #21, 2026-09-13.

#[cfg(test)]
mod tests {
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::record::{Classification, ValidationRecord};
    use elara_verify::{verify_record, Status};

    fn unsigned_record(signer: &Identity) -> ValidationRecord {
        ValidationRecord::create(
            b"construction-probe",
            signer.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        )
    }

    fn signature_check_detail(rec: &ValidationRecord) -> (Status, String) {
        let mut checks = Vec::new();
        verify_record(rec, None, "", &mut checks);
        let c = checks
            .iter()
            .find(|c| c.name == "signature")
            .expect("signature check present");
        (c.status, c.detail.clone())
    }

    /// The equivalence that makes the probe sound: the preimage under the
    /// record's own construction is the one the verifier already builds.
    #[test]
    fn signable_bytes_is_signable_bytes_under_own_version() {
        let id = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap();
        let rec = unsigned_record(&id);
        assert_eq!(rec.signable_bytes(), rec.signable_bytes_under(rec.version));
    }

    /// A signature made under the v5 construction on a record that declares a
    /// v6+ version: FAILS, and says which construction the signer actually used.
    #[test]
    fn construction_disagreement_is_named_and_still_fails() {
        let id = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap();
        let mut rec = unsigned_record(&id);
        assert!(
            rec.version >= 6,
            "fixture assumes a v6+ default emission version, got {}",
            rec.version
        );
        // Sign the preimage an emitter running pre-v6 code would have built.
        let stale = rec.signable_bytes_under(5);
        rec.signature = Some(id.sign(&stale).expect("sign"));
        rec.sig_algorithm = crate::crypto::ALG_DILITHIUM3;

        let (status, detail) = signature_check_detail(&rec);
        assert_eq!(status, Status::Fail, "a disagreement must never pass");
        assert!(
            detail.contains("v5 preimage construction"),
            "detail must name the construction, got: {detail}"
        );
        assert!(
            detail.contains("not a forged signature"),
            "detail must withdraw the forgery reading, got: {detail}"
        );
    }

    /// A signature over unrelated bytes verifies under NO construction, so the
    /// detail stays plain: the probe never invents a disagreement.
    #[test]
    fn forged_signature_gets_no_excuse() {
        let id = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap();
        let mut rec = unsigned_record(&id);
        rec.signature = Some(id.sign(b"a different message entirely").expect("sign"));
        rec.sig_algorithm = crate::crypto::ALG_DILITHIUM3;

        let (status, detail) = signature_check_detail(&rec);
        assert_eq!(status, Status::Fail);
        assert!(
            !detail.contains("construction"),
            "a forgery must not be explained away, got: {detail}"
        );
    }
}
