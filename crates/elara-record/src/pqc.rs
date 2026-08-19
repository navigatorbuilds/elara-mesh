//! Post-quantum signature **verification** primitives.
//!
//! Verify-only by design: this module carries `dilithium3_verify` (ML-DSA-65 / FIPS 204)
//! and `sphincs_verify` (SLH-DSA-SHA2-192f / FIPS 205) — both operate on **public data only**
//! (message, signature, public key). Key generation and signing stay in the node; a
//! third-party verifier embedding this crate is structurally incapable of producing a
//! signature. Pure-Rust wrappers over `dilithium-rs` / `lattice-slh-dsa`, wasm32-portable.

use crate::RecordError;
use dilithium::safe_api::{DilithiumKeyPair, DilithiumSignature};
use dilithium::params::DilithiumMode;
use slh_dsa::safe_api::SlhDsaSignature;
use slh_dsa::params::SLH_DSA_SHA2_192F;

const MODE: DilithiumMode = DilithiumMode::Dilithium3;

/// Algorithm ID for ML-DSA-65 (FIPS 204) — Dilithium3. Canonical definition —
/// the node's `crypto` module re-exports these; record wire bytes carry them.
pub const ALG_DILITHIUM3: u8 = 0x01;
/// Algorithm ID for SLH-DSA-SHA2-192f (FIPS 205) — SPHINCS+.
pub const ALG_SPHINCS_SHA2_192F: u8 = 0x02;

/// Verify a Dilithium3 / ML-DSA-65 (FIPS 204) signature over `message` with `public_key`.
///
/// FIPS 204 ML-DSA-65 only (3309-byte signatures). Legacy OQS 3293-byte signatures are
/// no longer supported — all identities were regenerated with FIPS 204.
pub fn dilithium3_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, RecordError> {
    if signature.len() != 3309 {
        return Err(RecordError::Crypto(format!(
            "invalid ML-DSA-65 signature length: {} (expected 3309)",
            signature.len()
        )));
    }
    let sig = DilithiumSignature::from_slice(signature);
    Ok(DilithiumKeyPair::verify(public_key, &sig, message, b"", MODE))
}

/// Verify a SPHINCS+ / SLH-DSA-SHA2-192f (FIPS 205) signature over `message` with `public_key`.
pub fn sphincs_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, RecordError> {
    Ok(SlhDsaSignature::verify(signature, public_key, message, SLH_DSA_SHA2_192F))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Committed verify KATs (public data only: message / public key / signature).
    /// Regenerate with `cargo test -p elara-record --lib -- --ignored gen_pqc_kat_vectors --nocapture`
    /// and paste the output over src/pqc_kat.hex — needed only if the fixture is
    /// ever lost; the vectors themselves must stay stable across dep upgrades
    /// (that stability is what the KAT tests pin).
    fn kat(key: &str) -> Vec<u8> {
        const KAT: &str = include_str!("pqc_kat.hex");
        let prefix = format!("{key}=");
        let line = KAT
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("pqc_kat.hex missing key {key}"));
        hex::decode(line[prefix.len()..].trim()).expect("pqc_kat.hex hex payload")
    }

    #[test]
    fn mldsa65_verify_rejects_wrong_signature_length_with_exact_error() {
        // The 3309-byte gate is a wire contract: the legacy OQS 3293-byte
        // signature class must surface the typed Crypto error, never reach the
        // verifier. Pin the exact message text (operators grep for it).
        for wrong in [0usize, 1, 3293, 3308, 3310] {
            let sig = vec![0u8; wrong];
            match dilithium3_verify(b"msg", &sig, b"pk") {
                Err(RecordError::Crypto(m)) => assert_eq!(
                    m,
                    format!("invalid ML-DSA-65 signature length: {wrong} (expected 3309)")
                ),
                other => panic!("len {wrong}: expected Err(Crypto), got {other:?}"),
            }
        }
    }

    #[test]
    fn mldsa65_kat_verifies_true_and_tampered_false() {
        let msg = kat("mldsa65.msg");
        let pk = kat("mldsa65.pk");
        let sig = kat("mldsa65.sig");
        assert_eq!(sig.len(), 3309, "KAT signature must be FIPS 204 ML-DSA-65 sized");
        assert!(
            dilithium3_verify(&msg, &sig, &pk).unwrap(),
            "committed ML-DSA-65 KAT must verify — a false here means the \
             verify path or the dilithium dep drifted"
        );
        // One flipped message byte must flip the verdict, not error.
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        assert!(!dilithium3_verify(&tampered, &sig, &pk).unwrap());
        // One flipped signature byte (length still valid) must flip the verdict.
        let mut bad_sig = sig.clone();
        bad_sig[100] ^= 0x01;
        assert!(!dilithium3_verify(&msg, &bad_sig, &pk).unwrap());
    }

    #[test]
    fn mldsa65_live_roundtrip_sign_verify() {
        // Live keygen→sign→verify through the same dep the node signs with —
        // catches a safe_api behavior change the fixed KAT can't (domain/ctx
        // handling), while the KAT catches drift the live loop can't.
        let kp = DilithiumKeyPair::generate(MODE).expect("keygen");
        let sig = kp.sign(b"elara-record pqc live roundtrip", b"").expect("sign");
        assert!(dilithium3_verify(
            b"elara-record pqc live roundtrip",
            sig.as_bytes(),
            kp.public_key()
        )
        .unwrap());
        assert!(!dilithium3_verify(b"different message", sig.as_bytes(), kp.public_key()).unwrap());
    }

    #[test]
    fn slhdsa192f_kat_verifies_true_and_tampered_false() {
        // SLH-DSA sign is seconds-slow in debug, so the positive case pins a
        // committed vector instead of signing live (verify is milliseconds).
        let msg = kat("slhdsa192f.msg");
        let pk = kat("slhdsa192f.pk");
        let sig = kat("slhdsa192f.sig");
        assert!(
            sphincs_verify(&msg, &sig, &pk).unwrap(),
            "committed SLH-DSA-SHA2-192f KAT must verify — a false here means \
             the verify path or the slh-dsa dep drifted"
        );
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        assert!(!sphincs_verify(&tampered, &sig, &pk).unwrap());
        let mut bad_sig = sig.clone();
        bad_sig[100] ^= 0x01;
        assert!(!sphincs_verify(&msg, &bad_sig, &pk).unwrap());
    }

    #[test]
    fn verify_fns_handle_garbage_inputs_without_panicking() {
        // Both verifiers sit on the node's untrusted ingest perimeter (dual-sign
        // check on attacker bytes) — malformed key/sig shapes must resolve to
        // Ok(false) or Err, never panic. (The dilithium length gate covers
        // wrong-size sigs; this sweeps the remaining shapes.)
        let sig3309 = vec![0u8; 3309];
        for pk in [&b""[..], &[0u8; 7][..], &[0xffu8; 4096][..]] {
            let r = dilithium3_verify(b"m", &sig3309, pk);
            assert!(matches!(r, Ok(false) | Err(_)), "garbage pk must not verify: {r:?}");
        }
        for (sig, pk) in [
            (&b""[..], &b""[..]),
            (&[0u8; 16][..], &[0u8; 16][..]),
            (&[0xffu8; 40000][..], &[0xffu8; 24][..]),
        ] {
            let r = sphincs_verify(b"m", sig, pk);
            assert!(matches!(r, Ok(false) | Err(_)), "garbage inputs must not verify: {r:?}");
        }
    }

    /// One-off fixture generator for src/pqc_kat.hex — run manually, never in CI:
    /// `cargo test -p elara-record --lib -- --ignored gen_pqc_kat_vectors --nocapture`
    #[test]
    #[ignore]
    fn gen_pqc_kat_vectors() {
        use slh_dsa::safe_api::SlhDsaKeyPair;
        let msg = b"elara-record pqc verify KAT v1 (public data only)";
        let dkp = DilithiumKeyPair::generate(MODE).expect("mldsa keygen");
        let dsig = dkp.sign(msg, b"").expect("mldsa sign");
        let skp = SlhDsaKeyPair::generate(SLH_DSA_SHA2_192F).expect("slhdsa keygen");
        let ssig = skp.sign(msg).expect("slhdsa sign");
        println!("# elara-record pqc verify KATs — PUBLIC data only (message/public-key/signature).");
        println!("# Generated once by gen_pqc_kat_vectors; stability across dep upgrades is the pin.");
        println!("mldsa65.msg={}", hex::encode(msg));
        println!("mldsa65.pk={}", hex::encode(dkp.public_key()));
        println!("mldsa65.sig={}", hex::encode(dsig.as_bytes()));
        println!("slhdsa192f.msg={}", hex::encode(msg));
        println!("slhdsa192f.pk={}", hex::encode(skp.public_key()));
        println!("slhdsa192f.sig={}", hex::encode(ssig.to_bytes()));
    }
}
