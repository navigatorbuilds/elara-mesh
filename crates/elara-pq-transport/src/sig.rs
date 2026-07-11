//! Dilithium3 / ML-DSA-65 (FIPS 204) identity signatures — pure Rust.
//!
//! The handshake binds each session to a long-term identity: the responder
//! (and, in msg3, the initiator) signs the running transcript hash with its
//! Dilithium3 secret key. That signature is the MITM killer even if ML-KEM
//! is broken — an attacker cannot forge ML-DSA-65 over a transcript it did
//! not participate in.
//!
//! This is the transport crate's own thin wrapper over `dilithium-rs`, kept
//! deliberately independent of the node's `crypto::pqc` module so the crate
//! stands alone and stays pure Rust (it compiles for `wasm32`). Both wrap the
//! same pinned `dilithium-rs =0.2.0` with ML-DSA-65 params and an empty
//! context string, so the bytes are identical across the two call sites.
//!
//! Spec references:
//!   @spec Protocol §4.2

use dilithium::params::DilithiumMode;
use dilithium::safe_api::{DilithiumKeyPair, DilithiumSignature};

const MODE: DilithiumMode = DilithiumMode::Dilithium3;

/// FIPS 204 ML-DSA-65 signature length in bytes.
pub const DIL_SIG_LEN: usize = 3309;

/// Errors from Dilithium3 sign/verify.
#[derive(Debug, thiserror::Error)]
pub enum SigError {
    #[error("ML-DSA-65 keygen failed")]
    Keygen,
    #[error("invalid ML-DSA-65 keys")]
    InvalidKeys,
    #[error("ML-DSA-65 sign failed")]
    Sign,
    #[error("invalid ML-DSA-65 signature length: {got} (expected {expected})")]
    BadSignatureLength { got: usize, expected: usize },
}

/// Generate a fresh Dilithium3 keypair, returned as `(public_key, secret_key)`.
pub fn dilithium3_keygen() -> Result<(Vec<u8>, Vec<u8>), SigError> {
    let kp = DilithiumKeyPair::generate(MODE).map_err(|_| SigError::Keygen)?;
    Ok((kp.public_key().to_vec(), kp.private_key().to_vec()))
}

/// Sign `message` with both secret key and public key. The pure-Rust
/// ML-DSA-65 implementation needs both halves of the keypair to sign.
pub fn dilithium3_sign_with_pk(
    message: &[u8],
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, SigError> {
    let kp =
        DilithiumKeyPair::from_keys(secret_key, public_key, MODE).map_err(|_| SigError::InvalidKeys)?;
    let sig = kp.sign(message, b"").map_err(|_| SigError::Sign)?;
    Ok(sig.as_bytes().to_vec())
}

/// Verify a Dilithium3 signature over `message`. Returns `Ok(false)` for a
/// well-formed but invalid signature; `Err` only for a structurally wrong
/// (wrong-length) signature.
pub fn dilithium3_verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, SigError> {
    // FIPS 204 ML-DSA-65 only (3309 bytes). Legacy OQS 3293-byte signatures
    // are no longer supported — all identities use FIPS 204.
    if signature.len() != DIL_SIG_LEN {
        return Err(SigError::BadSignatureLength {
            got: signature.len(),
            expected: DIL_SIG_LEN,
        });
    }
    let sig = DilithiumSignature::from_slice(signature);
    Ok(DilithiumKeyPair::verify(public_key, &sig, message, b"", MODE))
}

/// SHA3-256 of `data` — used to derive the 32-byte identity hash of a
/// Dilithium3 public key during the handshake (`SHA3-256(pk_dil)`).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_fips204_sizes() {
        let (pk, sk) = dilithium3_keygen().unwrap();
        // ML-DSA-65 public key = 1952 bytes, secret key = 4032 bytes.
        assert_eq!(pk.len(), 1952);
        assert_eq!(sk.len(), 4032);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = dilithium3_keygen().unwrap();
        let msg = b"transcript hash bytes";
        let sig = dilithium3_sign_with_pk(msg, &sk, &pk).unwrap();
        assert_eq!(sig.len(), DIL_SIG_LEN);
        assert!(dilithium3_verify(msg, &sig, &pk).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (pk, sk) = dilithium3_keygen().unwrap();
        let sig = dilithium3_sign_with_pk(b"original", &sk, &pk).unwrap();
        // A different message under the same signature must not verify.
        assert!(!dilithium3_verify(b"tampered", &sig, &pk).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let (pk_a, sk_a) = dilithium3_keygen().unwrap();
        let (pk_b, _sk_b) = dilithium3_keygen().unwrap();
        let sig = dilithium3_sign_with_pk(b"msg", &sk_a, &pk_a).unwrap();
        // Verifying A's signature under B's public key must fail.
        assert!(!dilithium3_verify(b"msg", &sig, &pk_b).unwrap());
    }

    #[test]
    fn verify_wrong_length_is_err_not_panic() {
        let (pk, _sk) = dilithium3_keygen().unwrap();
        for n in [0usize, 1, 3308, 3310, 9000] {
            let bogus = vec![0u8; n];
            match dilithium3_verify(b"m", &bogus, &pk) {
                Err(SigError::BadSignatureLength { got, expected }) => {
                    assert_eq!(got, n);
                    assert_eq!(expected, DIL_SIG_LEN);
                }
                other => panic!("expected BadSignatureLength for len={n}, got {other:?}"),
            }
        }
    }

    #[test]
    fn sha3_256_known_answer() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let empty = sha3_256(b"");
        assert_eq!(
            hex::encode(empty),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        // SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
        let abc = sha3_256(b"abc");
        assert_eq!(
            hex::encode(abc),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}
