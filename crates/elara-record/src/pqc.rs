//! Post-quantum signature **verification** primitives.
//!
//! Verify-only by design: this module carries `dilithium3_verify` (ML-DSA-65 / FIPS 204),
//! `sphincs_verify` (SPHINCS+-SHA2-192f, not FIPS 205) and `slh_dsa_verify`
//! (SLH-DSA-SHA2-192f / FIPS 205) — all operate on **public data only**
//! (message, signature, public key). Key generation and signing stay in the node; a
//! third-party verifier embedding this crate is structurally incapable of producing a
//! signature. Pure-Rust wrappers over `dilithium-rs` / `lattice-slh-dsa`, wasm32-portable.

use crate::RecordError;
use dilithium::safe_api::{DilithiumKeyPair, DilithiumSignature};
use dilithium::params::DilithiumMode;
use slh_dsa_legacy::safe_api::SlhDsaSignature;
use slh_dsa_legacy::params::SLH_DSA_SHA2_192F;

const MODE: DilithiumMode = DilithiumMode::Dilithium3;

/// Algorithm ID for ML-DSA-65 (FIPS 204) — Dilithium3. Canonical definition —
/// the node's `crypto` module re-exports these; record wire bytes carry them.
pub const ALG_DILITHIUM3: u8 = 0x01;
/// Algorithm ID for SPHINCS+-SHA2-192f. The backend (`lattice-slh-dsa` =0.3.3, the
/// `slh_dsa_legacy` dependency) hashes with SHA-256 throughout, where FIPS 205 requires
/// SHA-512 at this category, so this is not FIPS 205 SLH-DSA-SHA2-192f
/// (`tests/acvp_slhdsa192f.rs` pins it). The record second leg up to WIRE_VERSION 7.
pub const ALG_SPHINCS_SHA2_192F: u8 = 0x02;
/// Algorithm ID for SLH-DSA-SHA2-192f (FIPS 205), the record second leg from
/// WIRE_VERSION 8: the pure external interface with an empty context, over the
/// `lattice-slh-dsa` 0.4.0 backend (the `slh_dsa` dependency), pinned to NIST's
/// ACVP vectors by `tests/acvp_slhdsa192f.rs`. 0x03 is taken (ML-KEM-768 in the node).
pub const ALG_SLH_DSA_SHA2_192F: u8 = 0x04;

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

/// Verify a SPHINCS+-SHA2-192f signature over `message` with `public_key`.
/// It rejects FIPS 205 SLH-DSA-SHA2-192f signatures: see [`ALG_SPHINCS_SHA2_192F`].
///
/// This is the legacy verifier itself, for bare messages, frozen artifacts and KATs.
/// A record's or snapshot's second signature goes through [`verify_second_leg`].
pub fn sphincs_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, RecordError> {
    Ok(SlhDsaSignature::verify(signature, public_key, message, SLH_DSA_SHA2_192F))
}

/// Verify an SLH-DSA-SHA2-192f (FIPS 205) signature over `message` with `public_key`,
/// through the pure external interface with an empty context (M' = 0x00 || 0x00 || M).
/// A key or signature of the wrong length verifies false.
///
/// This is the FIPS 205 verifier itself. A record's second signature goes through
/// [`verify_second_leg`].
pub fn slh_dsa_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, RecordError> {
    Ok(slh_dsa::verify(public_key, signature, message, slh_dsa::params::SLH_DSA_SHA2_192F))
}

/// The last record wire version whose second leg is SPHINCS+-SHA2-192f
/// ([`ALG_SPHINCS_SHA2_192F`], verified by [`sphincs_verify`]).
pub const LEGACY_SECOND_LEG_MAX_RECORD_VERSION: u16 = 7;

/// The last record wire version whose second leg is SLH-DSA-SHA2-192f
/// ([`ALG_SLH_DSA_SHA2_192F`], verified by [`slh_dsa_verify`]); that era starts right
/// after [`LEGACY_SECOND_LEG_MAX_RECORD_VERSION`]. A later version has no second leg
/// until it is given one here: raising `WIRE_VERSION` alone does not give it one.
pub const FIPS205_SECOND_LEG_MAX_RECORD_VERSION: u16 = 8;

/// The second-leg algorithm a record of wire `version` carries: [`ALG_SPHINCS_SHA2_192F`]
/// up to [`LEGACY_SECOND_LEG_MAX_RECORD_VERSION`], [`ALG_SLH_DSA_SHA2_192F`] up to
/// [`FIPS205_SECOND_LEG_MAX_RECORD_VERSION`], and `None` after that. The decoder, the
/// signer and [`verify_second_leg`] all read it from here.
pub const fn record_second_leg_algorithm(version: u16) -> Option<u8> {
    if version <= LEGACY_SECOND_LEG_MAX_RECORD_VERSION {
        Some(ALG_SPHINCS_SHA2_192F)
    } else if version <= FIPS205_SECOND_LEG_MAX_RECORD_VERSION {
        Some(ALG_SLH_DSA_SHA2_192F)
    } else {
        None
    }
}

/// The last snapshot and state-delta selector (`sig_domain`) whose second leg is
/// SPHINCS+-SHA2-192f. A snapshot without a selector (before T63) is legacy too.
pub const LEGACY_SECOND_LEG_MAX_SNAPSHOT_SELECTOR: u8 = 1;

/// The signed field a second-leg verifier is chosen from. A record's `version` is in its
/// signed bytes and a snapshot's selector picks its signed preimage, so neither can be
/// changed without breaking the first signature, unlike the algorithm byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedFormat {
    /// A record, by its wire `version`.
    Record(u16),
    /// A snapshot or state delta, by its `sig_domain` selector (`None` before T63).
    Snapshot(Option<u8>),
}

impl std::fmt::Display for SignedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedFormat::Record(v) => write!(f, "record version {v}"),
            SignedFormat::Snapshot(Some(s)) => write!(f, "snapshot selector {s}"),
            SignedFormat::Snapshot(None) => f.write_str("snapshot without a selector"),
        }
    }
}

/// The one chokepoint for second-leg verification: every record, snapshot and state-delta
/// second signature is checked here. The verifier is chosen from the signed `format`,
/// never from the unsigned algorithm byte `alg`, which may only agree with it.
///
/// A record's era is [`record_second_leg_algorithm`] of its version. Up to
/// [`LEGACY_SECOND_LEG_MAX_RECORD_VERSION`] it is [`sphincs_verify`] forever, and `alg`
/// may be `None` (a pre-agility record) or [`ALG_SPHINCS_SHA2_192F`]. From WIRE_VERSION 8
/// it is [`slh_dsa_verify`], and `alg` must be [`ALG_SLH_DSA_SHA2_192F`]: a v8 preimage
/// commits the byte, so a missing one is refused. Snapshots without a selector and up to
/// [`LEGACY_SECOND_LEG_MAX_SNAPSHOT_SELECTOR`] carry no byte and are legacy. A format with
/// no era has no verifier: it is an error, never a fallback.
///
/// `Ok(false)` means the signature does not verify; `Err` means it cannot be checked.
pub fn verify_second_leg(
    format: SignedFormat,
    alg: Option<u8>,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, RecordError> {
    let era = match format {
        SignedFormat::Record(v) => record_second_leg_algorithm(v),
        SignedFormat::Snapshot(None) => Some(ALG_SPHINCS_SHA2_192F),
        SignedFormat::Snapshot(Some(s)) => {
            (s <= LEGACY_SECOND_LEG_MAX_SNAPSHOT_SELECTOR).then_some(ALG_SPHINCS_SHA2_192F)
        }
    };
    let Some(era) = era else {
        return Err(RecordError::Crypto(format!("no second-leg verifier for {format}")));
    };
    match (era, alg) {
        (ALG_SPHINCS_SHA2_192F, None | Some(ALG_SPHINCS_SHA2_192F)) => {
            sphincs_verify(message, signature, public_key)
        }
        (ALG_SLH_DSA_SHA2_192F, Some(ALG_SLH_DSA_SHA2_192F)) => {
            slh_dsa_verify(message, signature, public_key)
        }
        (_, None) => Err(RecordError::Crypto(format!("no second-leg algorithm byte at {format}"))),
        (_, Some(other)) => Err(RecordError::Crypto(format!(
            "second-leg algorithm 0x{other:02x} is not valid at {format}"
        ))),
    }
}

/// Verify an ML-DSA-44 (FIPS 204 / Dilithium2) signature over `message` with `public_key`.
///
/// XRPL interop (XLS draft "Post-Quantum Signatures (ML-DSA-44)", XRPLF/XRPL-Standards
/// discussion #295): XRPL's `Quantum` amendment standardizes ML-DSA-44 with the FIPS 204
/// external interface and **empty context** — the exact variant pinned here (ctx = `b""`).
/// Elara records themselves remain ML-DSA-65 (`dilithium3_verify`); this helper targets
/// XRPL's wire, not ours. The public-key length gate doubles as XRPL's scheme dispatch
/// (a 1312-byte `SigningPubKey` selects the dilithium path post-amendment).
pub fn mldsa44_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, RecordError> {
    if public_key.len() != 1312 {
        return Err(RecordError::Crypto(format!(
            "invalid ML-DSA-44 public key length: {} (expected 1312)",
            public_key.len()
        )));
    }
    if signature.len() != 2420 {
        return Err(RecordError::Crypto(format!(
            "invalid ML-DSA-44 signature length: {} (expected 2420)",
            signature.len()
        )));
    }
    let sig = DilithiumSignature::from_slice(signature);
    Ok(DilithiumKeyPair::verify(public_key, &sig, message, b"", DilithiumMode::Dilithium2))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Committed verify KATs (public data only: message / public key / signature),
    /// generated 2026-07-10 with dilithium-rs 0.2.0 and lattice-slh-dsa 0.3.3 and
    /// frozen: they are never regenerated, since their stability across dep
    /// upgrades is what the KAT tests pin. The SLH-DSA vector is a legacy 0x02 leg.
    pub(crate) fn kat(key: &str) -> Vec<u8> {
        const KAT: &str = include_str!("pqc_kat.hex");
        let prefix = format!("{key}=");
        let line = KAT
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("pqc_kat.hex missing key {key}"));
        hex::decode(line[prefix.len()..].trim()).expect("pqc_kat.hex hex payload")
    }

    /// NIST's ACVP SLH-DSA-SHA2-192f sigGen tc25 (FIPS 205, deterministic, empty
    /// context), the form of a v8 second leg: `[sk, pk, message, signature]`.
    pub(crate) fn fips205_leg_vector() -> [Vec<u8>; 4] {
        const V8_LEG: &str = include_str!("../tests/vectors/acvp_slhdsa192f_v8_leg.txt");
        let line = V8_LEG
            .lines()
            .find(|l| l.starts_with("25|"))
            .expect("acvp_slhdsa192f_v8_leg.txt missing tc25");
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(f.len(), 7, "tc25 fields");
        [f[3], f[4], f[5], f[6]].map(|h| hex::decode(h).expect("tc25 hex payload"))
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
    fn mldsa44_verify_rejects_wrong_lengths_with_exact_errors() {
        // Both gates are wire contracts (XRPL dispatch is BY pubkey shape); pin
        // the exact messages like the ML-DSA-65 gate above. Correctness against
        // NIST truth lives in tests/acvp_mldsa44.rs.
        let sig2420 = vec![0u8; 2420];
        for wrong in [0usize, 1, 1311, 1313, 1952] {
            match mldsa44_verify(b"msg", &sig2420, &vec![0u8; wrong]) {
                Err(RecordError::Crypto(m)) => assert_eq!(
                    m,
                    format!("invalid ML-DSA-44 public key length: {wrong} (expected 1312)")
                ),
                other => panic!("pk len {wrong}: expected Err(Crypto), got {other:?}"),
            }
        }
        let pk1312 = vec![0u8; 1312];
        for wrong in [0usize, 1, 2419, 2421, 3309] {
            match mldsa44_verify(b"msg", &vec![0u8; wrong], &pk1312) {
                Err(RecordError::Crypto(m)) => assert_eq!(
                    m,
                    format!("invalid ML-DSA-44 signature length: {wrong} (expected 2420)")
                ),
                other => panic!("sig len {wrong}: expected Err(Crypto), got {other:?}"),
            }
        }
        // Well-formed lengths with garbage bytes must resolve false, never panic.
        assert!(!mldsa44_verify(b"msg", &sig2420, &pk1312).unwrap());
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
            "committed SPHINCS+-SHA2-192f KAT must verify — a false here means \
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
            let r = slh_dsa_verify(b"m", sig, pk);
            assert!(matches!(r, Ok(false) | Err(_)), "garbage inputs must not verify: {r:?}");
        }
    }

    #[test]
    fn slhdsa192f_kat_is_a_legacy_leg() {
        // The committed vector is a 0x02 leg: the legacy verifier accepts it, and
        // final FIPS 205 rejects it on both interfaces, since its H_msg differs.
        let msg = kat("slhdsa192f.msg");
        let pk = kat("slhdsa192f.pk");
        let sig = kat("slhdsa192f.sig");
        assert!(sphincs_verify(&msg, &sig, &pk).unwrap());
        let fips205 = slh_dsa::params::SLH_DSA_SHA2_192F;
        assert!(!slh_dsa::verify_internal(&pk, &sig, &msg, fips205));
        assert!(!slh_dsa::verify(&pk, &sig, &msg, fips205));
    }

    #[test]
    fn second_leg_chokepoint_verifies_legacy_formats_with_the_legacy_verifier() {
        let msg = kat("slhdsa192f.msg");
        let pk = kat("slhdsa192f.pk");
        let sig = kat("slhdsa192f.sig");
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        let legacy = (0..=LEGACY_SECOND_LEG_MAX_RECORD_VERSION)
            .map(SignedFormat::Record)
            .chain([SignedFormat::Snapshot(None), SignedFormat::Snapshot(Some(1))]);
        for format in legacy {
            for alg in [None, Some(ALG_SPHINCS_SHA2_192F)] {
                assert!(verify_second_leg(format, alg, &msg, &sig, &pk).unwrap(), "{format} {alg:?}");
                assert!(!verify_second_leg(format, alg, &tampered, &sig, &pk).unwrap(), "{format} {alg:?}");
            }
        }
    }

    #[test]
    fn second_leg_chokepoint_refuses_formats_and_algorithms_without_a_verifier() {
        let msg = kat("slhdsa192f.msg");
        let pk = kat("slhdsa192f.pk");
        let sig = kat("slhdsa192f.sig");
        // A format past the last era has no verifier, and no algorithm byte can select one.
        let past = SignedFormat::Record(FIPS205_SECOND_LEG_MAX_RECORD_VERSION + 1);
        for format in [past, SignedFormat::Record(u16::MAX), SignedFormat::Snapshot(Some(2))] {
            for alg in [None, Some(ALG_SPHINCS_SHA2_192F), Some(0x03), Some(ALG_SLH_DSA_SHA2_192F)] {
                let err = verify_second_leg(format, alg, &msg, &sig, &pk).unwrap_err();
                assert_eq!(err.to_string(), format!("no second-leg verifier for {format}"));
            }
        }
        // Inside an era, only that era's byte is valid.
        for (v, algs) in [
            (7, [0x00, ALG_DILITHIUM3, 0x03, ALG_SLH_DSA_SHA2_192F, 0xff]),
            (8, [0x00, ALG_DILITHIUM3, ALG_SPHINCS_SHA2_192F, 0x03, 0xff]),
        ] {
            for alg in algs {
                let err = verify_second_leg(SignedFormat::Record(v), Some(alg), &msg, &sig, &pk).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    format!("second-leg algorithm 0x{alg:02x} is not valid at record version {v}")
                );
            }
        }
        // A v8 preimage commits the byte, so its absence is not the legacy default.
        let err = verify_second_leg(SignedFormat::Record(8), None, &msg, &sig, &pk).unwrap_err();
        assert_eq!(err.to_string(), "no second-leg algorithm byte at record version 8");
        for alg in [0x03, ALG_SLH_DSA_SHA2_192F] {
            let err = verify_second_leg(SignedFormat::Snapshot(None), Some(alg), &msg, &sig, &pk).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("second-leg algorithm 0x{alg:02x} is not valid at snapshot without a selector")
            );
        }
    }

    #[test]
    fn second_leg_chokepoint_verifies_record_version_8_with_fips205() {
        let [_, pk, msg, sig] = fips205_leg_vector();
        let v8 = SignedFormat::Record(8);
        assert!(verify_second_leg(v8, Some(ALG_SLH_DSA_SHA2_192F), &msg, &sig, &pk).unwrap());
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        assert!(!verify_second_leg(v8, Some(ALG_SLH_DSA_SHA2_192F), &tampered, &sig, &pk).unwrap());
        // Each era verifies with its own algorithm only: the two hash messages differently.
        let v7 = SignedFormat::Record(7);
        assert!(!verify_second_leg(v7, Some(ALG_SPHINCS_SHA2_192F), &msg, &sig, &pk).unwrap());
        let (lmsg, lpk, lsig) = (kat("slhdsa192f.msg"), kat("slhdsa192f.pk"), kat("slhdsa192f.sig"));
        assert!(!verify_second_leg(v8, Some(ALG_SLH_DSA_SHA2_192F), &lmsg, &lsig, &lpk).unwrap());
    }

    #[test]
    fn record_second_leg_eras_are_contiguous_and_closed() {
        for v in 0..=LEGACY_SECOND_LEG_MAX_RECORD_VERSION {
            assert_eq!(record_second_leg_algorithm(v), Some(ALG_SPHINCS_SHA2_192F), "record version {v}");
        }
        for v in LEGACY_SECOND_LEG_MAX_RECORD_VERSION + 1..=FIPS205_SECOND_LEG_MAX_RECORD_VERSION {
            assert_eq!(record_second_leg_algorithm(v), Some(ALG_SLH_DSA_SHA2_192F), "record version {v}");
        }
        for v in [FIPS205_SECOND_LEG_MAX_RECORD_VERSION + 1, u16::MAX] {
            assert_eq!(record_second_leg_algorithm(v), None, "record version {v}");
        }
    }

    #[test]
    fn every_record_version_the_codec_accepts_has_a_second_leg_verifier() {
        // Raising WIRE_VERSION without giving the new version a second-leg verifier
        // would turn every Profile A record at that version into an unverifiable one.
        let legacy = [kat("slhdsa192f.msg"), kat("slhdsa192f.pk"), kat("slhdsa192f.sig")];
        let [_, pk, msg, sig] = fips205_leg_vector();
        let fips205 = [msg, pk, sig];
        for v in crate::wire::WIRE_VERSION_MIN..=crate::wire::WIRE_VERSION {
            let alg = record_second_leg_algorithm(v)
                .unwrap_or_else(|| panic!("record version {v} has no second-leg algorithm"));
            let [msg, pk, sig] = if alg == ALG_SLH_DSA_SHA2_192F { &fips205 } else { &legacy };
            let r = verify_second_leg(SignedFormat::Record(v), Some(alg), msg, sig, pk);
            assert!(matches!(r, Ok(true)), "record version {v}: {r:?}");
        }
    }
}
