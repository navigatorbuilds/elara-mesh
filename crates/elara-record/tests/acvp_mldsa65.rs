//! NIST ACVP ML-DSA-65 signature-verification vectors (FIPS 204, external
//! interface, pure mode). Source: usnistgov/ACVP-Server, gen-val json-files,
//! ML-DSA-sigVer-FIPS204 (NIST public test data), curated subset: 3 valid +
//! 5 tampered (z / hint / commitment / message classes) + empty-context tc39.
//!
//! What passing proves: the vendored `dilithium` backend implements FIPS 204
//! FINAL ML-DSA-65 external/pure verification — round-three Dilithium3
//! (tr = 32 bytes, no 0x00||len(ctx)||ctx message binding) fails every case
//! here. The empty-context case additionally runs through this crate's public
//! `dilithium3_verify`, which pins ctx = b"" (src/pqc.rs) — the exact variant
//! every Elara record and seal signature uses on the wire.

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
fn acvp_mldsa65_sigver_external_pure() {
    let data = include_str!("vectors/acvp_mldsa65_sigver.txt");
    let mut ran = 0usize;
    let mut wrapper_ran = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(7, '|').collect();
        assert_eq!(f.len(), 7, "malformed vector line");
        let (tc, expect) = (f[0], f[1] == "P");
        let (pk, msg, ctx, sig) = (unhex(f[3]), unhex(f[4]), unhex(f[5]), unhex(f[6]));

        let s = DilithiumSignature::from_slice(&sig);
        let got = DilithiumKeyPair::verify(&pk, &s, &msg, &ctx, DilithiumMode::Dilithium3);
        assert_eq!(got, expect, "ACVP tc{tc} ({}): got {got}", f[2]);

        if ctx.is_empty() {
            let wrapper = elara_record::pqc::dilithium3_verify(&msg, &sig, &pk)
                .expect("wrapper errored on well-formed ACVP input");
            assert_eq!(wrapper, expect, "public dilithium3_verify diverges on tc{tc}");
            wrapper_ran += 1;
        }
        ran += 1;
    }
    assert_eq!(ran, 9, "vector file truncated: {ran}/9 cases ran");
    assert_eq!(wrapper_ran, 1, "empty-context wrapper case missing");
}
