//! NIST ACVP ML-DSA-44 signature-verification vectors (FIPS 204, external
//! interface, pure mode). Source: usnistgov/ACVP-Server, gen-val json-files,
//! ML-DSA-sigVer-FIPS204 (curated subset: 3 valid + 5 tampered — message / z /
//! hint / commitment classes, one of the tampers on an empty context) plus one
//! VALID empty-context case from ML-DSA-sigGen-FIPS204's deterministic
//! external/pure group (NIST-computed expected signature). Full provenance in
//! the vector file header.
//!
//! What passing proves: the `dilithium` backend implements FIPS 204 FINAL
//! ML-DSA-44 external/pure verification — the parameter set XRPL's `Quantum`
//! amendment standardizes (XLS draft "Post-Quantum Signatures (ML-DSA-44)",
//! XRPLF/XRPL-Standards discussion #295, empty-context convention). The two
//! empty-context cases additionally run through this crate's public
//! `mldsa44_verify` (ctx pinned `b""`, src/pqc.rs) and must land on BOTH
//! verdicts there — one VERIFIED, one REJECTED — so the XRPL-facing wrapper is
//! exercised in each direction, not just the reject path. Elara records
//! themselves remain ML-DSA-65; see tests/acvp_mldsa65.rs for that suite.

use dilithium::params::DilithiumMode;
use dilithium::safe_api::{DilithiumKeyPair, DilithiumSignature};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

#[test]
fn acvp_mldsa44_sigver_external_pure() {
    let data = include_str!("vectors/acvp_mldsa44_sigver.txt");
    let mut ran = 0usize;
    let mut wrapper_pass = 0usize;
    let mut wrapper_fail = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(7, '|').collect();
        assert_eq!(f.len(), 7, "malformed vector line");
        let (tc, expect) = (f[0], f[1] == "P");
        let (pk, msg, ctx, sig) = (unhex(f[3]), unhex(f[4]), unhex(f[5]), unhex(f[6]));
        assert_eq!(pk.len(), 1312, "ACVP tc{tc}: ML-DSA-44 pubkey must be 1312 B");
        assert_eq!(sig.len(), 2420, "ACVP tc{tc}: ML-DSA-44 signature must be 2420 B");

        let s = DilithiumSignature::from_slice(&sig);
        let got = DilithiumKeyPair::verify(&pk, &s, &msg, &ctx, DilithiumMode::Dilithium2);
        assert_eq!(got, expect, "ACVP tc{tc} ({}): got {got}", f[2]);

        if ctx.is_empty() {
            let wrapper = elara_record::pqc::mldsa44_verify(&msg, &sig, &pk)
                .expect("wrapper errored on well-formed ACVP input");
            assert_eq!(wrapper, expect, "public mldsa44_verify diverges on tc{tc}");
            if wrapper {
                wrapper_pass += 1;
            } else {
                wrapper_fail += 1;
            }
        }
        ran += 1;
    }
    assert_eq!(ran, 9, "vector file truncated: {ran}/9 cases ran");
    assert_eq!(wrapper_pass, 1, "valid empty-context wrapper case missing");
    assert_eq!(wrapper_fail, 1, "tampered empty-context wrapper case missing");
}
