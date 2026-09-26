//! NIST ACVP SLH-DSA-SHAKE-192f verification vectors (FIPS 205, INTERNAL
//! interface), run against both copies of `lattice-slh-dsa` (see
//! acvp_slhdsa192f.rs). SHAKE H_msg is category-uniform (SHAKE256 for all
//! sets), so the legacy copy's SHA2 category-3 SHA-512 bug does not apply
//! here: both copies must match NIST.

use slh_dsa::params::SLH_DSA_SHAKE_192F;
use slh_dsa_legacy::params::SLH_DSA_SHAKE_192F as LEGACY_SHAKE_192F;
use slh_dsa_legacy::safe_api::SlhDsaSignature as LegacySignature;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

#[test]
fn acvp_slhdsa_shake_192f_sigver_internal() {
    let data = include_str!("vectors/acvp_slhdsa_shake192f_sigver.txt");
    let mut ran = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(6, '|').collect();
        assert_eq!(f.len(), 6, "malformed vector line");
        let (tc, expect) = (f[0], f[1] == "P");
        let (pk, msg, sig) = (unhex(f[3]), unhex(f[4]), unhex(f[5]));
        let legacy = LegacySignature::verify(&sig, &pk, &msg, LEGACY_SHAKE_192F);
        assert_eq!(legacy, expect, "legacy: ACVP tc{tc} ({}): got {legacy}", f[2]);
        let got = slh_dsa::verify_internal(&pk, &sig, &msg, SLH_DSA_SHAKE_192F);
        assert_eq!(got, expect, "FIPS 205: ACVP tc{tc} ({}): got {got}", f[2]);
        ran += 1;
    }
    assert_eq!(ran, 4, "vector file truncated: {ran}/4 cases ran");
}
