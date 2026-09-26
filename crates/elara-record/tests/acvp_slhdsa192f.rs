//! NIST ACVP SLH-DSA-SHA2-192f verification vectors (FIPS 205), run against
//! both copies of `lattice-slh-dsa` this crate carries.
//!
//! `slh_dsa_legacy` (=0.3.3) computes H_msg with SHA-256 / MGF1-SHA-256 for
//! ALL SHA2 parameter sets (src/hash.rs `hash_message`, no security-category
//! branch; found 2026-08-26). FIPS 205 §11.2.2 — and SPHINCS+ r3.1 before
//! it — require SHA-512 / MGF1-SHA-512 for categories 3 and 5. SLH-DSA-SHA2-192f
//! is category 3, so that copy is round-3.0-style there despite its FIPS 205
//! labeling: it REJECTS valid FIPS 205 SHA2-192f signatures (tc183/tc185 in
//! the internal file). It signed every existing 0x02 second leg and stays,
//! pinned, to verify them. That is why its valid-vector expectations below are
//! `false`: the day it accepts them, its H_msg has changed and every existing
//! leg stops verifying.
//!
//! `slh_dsa` (=0.4.0) is final FIPS 205 and must match NIST on both the
//! internal interface and the external pure one (M' = 0x00 || len(ctx) ||
//! ctx || M). It is the backend for the second-leg algorithm that will
//! replace 0x02.
//!
//! Security note: the divergence is a conformance/interop one, not a
//! weakness — the SPHINCS+ structure and margins are unaffected by which
//! approved hash feeds H_msg. The ML-DSA-65 leg (the primary signature) is
//! FIPS 204 FINAL, proven in acvp_mldsa65.rs.

use elara_record::pqc::sphincs_verify;
use slh_dsa::params::SLH_DSA_SHA2_192F;
use slh_dsa::safe_api::SlhDsaSignature;
use slh_dsa_legacy::params::SLH_DSA_SHA2_192F as LEGACY_SHA2_192F;
use slh_dsa_legacy::safe_api::SlhDsaSignature as LegacySignature;

const INTERNAL: &str = include_str!("vectors/acvp_slhdsa192f_sigver.txt");
const EXTERNAL: &str = include_str!("vectors/acvp_slhdsa192f_external_sigver.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

/// Runs `check(tcId, expect, reason, hex_fields)` on every case of a vector
/// file whose lines are `tcId|expect|reason|<hex_fields...>`; returns the
/// number of cases run.
fn each_case(
    data: &str,
    hex_fields: usize,
    mut check: impl FnMut(&str, bool, &str, &[Vec<u8>]),
) -> usize {
    let mut ran = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.splitn(3 + hex_fields, '|').collect();
        assert_eq!(f.len(), 3 + hex_fields, "malformed vector line");
        let hex: Vec<Vec<u8>> = f[3..].iter().copied().map(unhex).collect();
        check(f[0], f[1] == "P", f[2], &hex);
        ran += 1;
    }
    ran
}

#[test]
fn slh_dsa_sha2_192f_fips205_divergence_pinned() {
    let mut valid_pinned = 0usize;
    let mut rejects = 0usize;
    each_case(INTERNAL, 3, |tc, acvp_valid, reason, f| {
        let (pk, msg, sig) = (&f[0], &f[1], &f[2]);
        let got = LegacySignature::verify(sig, pk, msg, LEGACY_SHA2_192F);
        let wrapper = sphincs_verify(msg, sig, pk).unwrap_or(false);
        assert_eq!(got, wrapper, "legacy crate vs public sphincs_verify diverge on tc{tc}");

        if acvp_valid {
            assert!(
                !got,
                "tc{tc}: the legacy backend ACCEPTED a valid FIPS 205 vector, so \
                 its H_msg changed. It must stay =0.3.3, or every existing 0x02 \
                 leg stops verifying."
            );
            valid_pinned += 1;
        } else {
            assert!(!got, "tc{tc}: tampered/oversized vector accepted ({reason})");
            rejects += 1;
        }
    });
    assert_eq!(valid_pinned, 2, "expected 2 pinned valid-vector divergences");
    assert_eq!(rejects, 2, "expected 2 era-independent rejections");
}

#[test]
fn slh_dsa_sha2_192f_fips205_internal_sigver() {
    let ran = each_case(INTERNAL, 3, |tc, expect, reason, f| {
        let (pk, msg, sig) = (&f[0], &f[1], &f[2]);
        let got = slh_dsa::verify_internal(pk, sig, msg, SLH_DSA_SHA2_192F);
        assert_eq!(got, expect, "ACVP tc{tc} ({reason}): got {got}");
    });
    assert_eq!(ran, 4, "vector file truncated: {ran}/4 cases ran");
}

#[test]
fn slh_dsa_sha2_192f_fips205_external_sigver() {
    let ran = each_case(EXTERNAL, 4, |tc, expect, reason, f| {
        let (ctx, pk, msg, sig) = (&f[0], &f[1], &f[2], &f[3]);
        let got = slh_dsa::verify_ctx(pk, sig, msg, ctx, SLH_DSA_SHA2_192F);
        assert_eq!(got, expect, "ACVP tc{tc} ({reason}): got {got}");
        assert_eq!(
            SlhDsaSignature::verify_with_context(sig, pk, msg, ctx, SLH_DSA_SHA2_192F),
            expect,
            "safe_api diverges from verify_ctx on tc{tc}"
        );
        if ctx.is_empty() {
            assert_eq!(
                SlhDsaSignature::verify(sig, pk, msg, SLH_DSA_SHA2_192F),
                expect,
                "empty-context verify diverges on tc{tc}"
            );
        }
        if expect {
            // The M' wrapper is what these vectors exercise.
            assert!(
                !slh_dsa::verify_internal(pk, sig, msg, SLH_DSA_SHA2_192F),
                "tc{tc}: verifies without the external-interface wrapper"
            );
        }
    });
    assert_eq!(ran, 3, "vector file truncated: {ran}/3 cases ran");
}
