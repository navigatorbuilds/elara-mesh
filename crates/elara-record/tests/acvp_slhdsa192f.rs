//! NIST ACVP SLH-DSA-SHA2-192f verification vectors (FIPS 205, INTERNAL
//! interface) — used here to PIN A KNOWN DIVERGENCE, not to claim conformance.
//!
//! Finding (2026-08-26, pre-audit): `lattice-slh-dsa 0.3.3` computes H_msg with
//! SHA-256 / MGF1-SHA-256 for ALL SHA2 parameter sets (src/hash.rs
//! `hash_message`, no security-category branch). FIPS 205 §11.2.2 — and
//! SPHINCS+ r3.1 before it — require SHA-512 / MGF1-SHA-512 for categories 3
//! and 5. Our parameter set SLH-DSA-SHA2-192f is category 3, so the backend is
//! round-3.0-style there despite its FIPS 205 labeling:
//!   - valid FIPS 205 SHA2-192f signatures are REJECTED (tc183/tc185 below);
//!   - our own SPHINCS+ legs verify only within this stack, not under FIPS 205.
//!
//! Security note: this is a conformance/interop divergence, not a weakness —
//! the SPHINCS+ structure and margins are unaffected by which approved hash
//! feeds H_msg. The ML-DSA-65 leg (the primary signature) is FIPS 204 FINAL,
//! proven in acvp_mldsa65.rs.
//!
//! Why the valid-vector expectations below are `false`: changing H_msg is a
//! signing-domain change — hard-fork-class for every signed artifact on the
//! mesh — so it must ship as an audited, versioned suite transition, never as
//! a silent dependency fix. This test fails the moment the backend starts
//! accepting real FIPS 205 signatures (e.g. a crate bump), forcing that
//! decision into the open instead of letting the wire domain drift silently.
//! Tamper/length rejections are era-independent and asserted as rejections.

use elara_record::pqc::sphincs_verify;
use slh_dsa::params::SLH_DSA_SHA2_192F;
use slh_dsa::safe_api::SlhDsaSignature;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

#[test]
fn slh_dsa_sha2_192f_fips205_divergence_pinned() {
    let data = include_str!("vectors/acvp_slhdsa192f_sigver.txt");
    let mut valid_pinned = 0usize;
    let mut rejects = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(6, '|').collect();
        assert_eq!(f.len(), 6, "malformed vector line");
        let (tc, acvp_valid) = (f[0], f[1] == "P");
        let (pk, msg, sig) = (unhex(f[3]), unhex(f[4]), unhex(f[5]));

        let got = SlhDsaSignature::verify(&sig, &pk, &msg, SLH_DSA_SHA2_192F);
        let wrapper = sphincs_verify(&msg, &sig, &pk).unwrap_or(false);
        assert_eq!(got, wrapper, "crate vs public sphincs_verify diverge on tc{tc}");

        if acvp_valid {
            assert!(
                !got,
                "tc{tc}: backend ACCEPTED a valid FIPS 205 vector — the H_msg \
                 divergence is gone (crate fixed?). Wire-domain decision required: \
                 see file header; do NOT just flip this assertion."
            );
            valid_pinned += 1;
        } else {
            assert!(!got, "tc{tc}: tampered/oversized vector accepted ({})", f[2]);
            rejects += 1;
        }
    }
    assert_eq!(valid_pinned, 2, "expected 2 pinned valid-vector divergences");
    assert_eq!(rejects, 2, "expected 2 era-independent rejections");
}
