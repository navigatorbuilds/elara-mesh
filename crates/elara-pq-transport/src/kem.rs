//! ML-KEM-768 key encapsulation (FIPS 203), backed by liboqs via `oqs`.
//!
//! The post-quantum half of the hybrid key exchange: the initiator ships an
//! ML-KEM-768 public key, the responder encapsulates a shared secret under
//! it, and that secret is mixed (alongside the X25519 ECDH secret) into the
//! [`crate::crypto`] session key schedule. If ML-KEM is ever broken the
//! X25519 half still protects the session, and vice versa.
//!
//! Key sizes (ML-KEM-768):
//! - Public key: 1,184 bytes
//! - Secret key: 2,400 bytes
//! - Ciphertext: 1,088 bytes
//! - Shared secret: 32 bytes
//!
//! This module is gated behind the default-on `oqs` feature and is never
//! compiled for `wasm32` (liboqs is C). A future pure-Rust ML-KEM backend
//! can be slotted in behind the same feature without an API change.
//!
//! Spec references:
//!   @spec Protocol §4.2

use zeroize::Zeroize;

/// Errors from ML-KEM-768 key encapsulation.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    #[error("failed to initialize ML-KEM-768")]
    Init,
    #[error("ML-KEM-768 keypair generation failed")]
    Keygen,
    #[error("invalid ML-KEM-768 public key")]
    InvalidPublicKey,
    #[error("ML-KEM-768 encapsulation failed")]
    Encapsulate,
    #[error("invalid ML-KEM-768 secret key")]
    InvalidSecretKey,
    #[error("invalid ML-KEM-768 ciphertext")]
    InvalidCiphertext,
    #[error("ML-KEM-768 decapsulation failed")]
    Decapsulate,
}

type Result<T> = core::result::Result<T, KemError>;

/// ML-KEM-768 keypair.
///
/// `Debug` redacts `secret_key`, and the secret bytes are zeroized on drop — a
/// long-term secret must never reach a log line or linger in freed heap.
#[derive(Clone)]
pub struct KemKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl core::fmt::Debug for KemKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KemKeypair")
            .field("public_key", &format_args!("[{} bytes]", self.public_key.len()))
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl Drop for KemKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Encapsulation result: ciphertext + shared secret.
///
/// `Debug` redacts `shared_secret`, and it is zeroized on drop — it is the
/// direct input to the session key schedule and must not leak.
#[derive(Clone)]
pub struct KemEncapsulation {
    /// Ciphertext to send to the key holder.
    pub ciphertext: Vec<u8>,
    /// Shared secret (32 bytes) — known to both parties after decapsulation.
    pub shared_secret: Vec<u8>,
}

impl core::fmt::Debug for KemEncapsulation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KemEncapsulation")
            .field("ciphertext", &format_args!("[{} bytes]", self.ciphertext.len()))
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

impl Drop for KemEncapsulation {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Generate an ML-KEM-768 keypair.
pub fn mlkem768_keygen() -> Result<KemKeypair> {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).map_err(|_| KemError::Init)?;

    let (pk, sk) = kem.keypair().map_err(|_| KemError::Keygen)?;

    Ok(KemKeypair {
        public_key: pk.as_ref().to_vec(),
        secret_key: sk.as_ref().to_vec(),
    })
}

/// Encapsulate: generate a shared secret and ciphertext using the recipient's public key.
///
/// The sender calls this. They get:
/// - `ciphertext`: send to the recipient
/// - `shared_secret`: use as the symmetric key
pub fn mlkem768_encapsulate(public_key: &[u8]) -> Result<KemEncapsulation> {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).map_err(|_| KemError::Init)?;

    let pk = kem
        .public_key_from_bytes(public_key)
        .ok_or(KemError::InvalidPublicKey)?;

    let (ct, ss) = kem.encapsulate(pk).map_err(|_| KemError::Encapsulate)?;

    Ok(KemEncapsulation {
        ciphertext: ct.as_ref().to_vec(),
        shared_secret: ss.as_ref().to_vec(),
    })
}

/// Decapsulate: recover the shared secret from a ciphertext using the secret key.
///
/// The recipient calls this with their secret key and the sender's ciphertext.
/// Returns the same shared secret the sender derived.
pub fn mlkem768_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).map_err(|_| KemError::Init)?;

    let sk = kem
        .secret_key_from_bytes(secret_key)
        .ok_or(KemError::InvalidSecretKey)?;

    let ct = kem
        .ciphertext_from_bytes(ciphertext)
        .ok_or(KemError::InvalidCiphertext)?;

    let ss = kem.decapsulate(sk, ct).map_err(|_| KemError::Decapsulate)?;

    Ok(ss.as_ref().to_vec())
}

/// Get ML-KEM-768 key sizes for reference.
pub struct MlKem768Sizes;

impl MlKem768Sizes {
    pub const PUBLIC_KEY: usize = 1184;
    pub const SECRET_KEY: usize = 2400;
    pub const CIPHERTEXT: usize = 1088;
    pub const SHARED_SECRET: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let kp = mlkem768_keygen().unwrap();
        assert_eq!(kp.public_key.len(), MlKem768Sizes::PUBLIC_KEY);
        assert_eq!(kp.secret_key.len(), MlKem768Sizes::SECRET_KEY);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let kp = mlkem768_keygen().unwrap();
        let encap = mlkem768_encapsulate(&kp.public_key).unwrap();

        assert_eq!(encap.ciphertext.len(), MlKem768Sizes::CIPHERTEXT);
        assert_eq!(encap.shared_secret.len(), MlKem768Sizes::SHARED_SECRET);

        let ss = mlkem768_decapsulate(&kp.secret_key, &encap.ciphertext).unwrap();
        assert_eq!(ss, encap.shared_secret);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let kp1 = mlkem768_keygen().unwrap();
        let kp2 = mlkem768_keygen().unwrap();

        let encap1 = mlkem768_encapsulate(&kp1.public_key).unwrap();
        let encap2 = mlkem768_encapsulate(&kp2.public_key).unwrap();

        // Different keypairs produce different shared secrets
        assert_ne!(encap1.shared_secret, encap2.shared_secret);
    }

    #[test]
    fn test_wrong_secret_key_fails() {
        let kp1 = mlkem768_keygen().unwrap();
        let kp2 = mlkem768_keygen().unwrap();

        let encap = mlkem768_encapsulate(&kp1.public_key).unwrap();

        // Decapsulating with wrong secret key produces a different shared secret
        // (ML-KEM is IND-CCA2: wrong key decapsulates to random, not error)
        let wrong_ss = mlkem768_decapsulate(&kp2.secret_key, &encap.ciphertext).unwrap();
        assert_ne!(wrong_ss, encap.shared_secret);
    }

    #[test]
    fn test_invalid_public_key() {
        let result = mlkem768_encapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_secret_key() {
        let kp = mlkem768_keygen().unwrap();
        let encap = mlkem768_encapsulate(&kp.public_key).unwrap();

        let result = mlkem768_decapsulate(&[0u8; 100], &encap.ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let kp = mlkem768_keygen().unwrap();
        let result = mlkem768_decapsulate(&kp.secret_key, &[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encapsulations_same_key() {
        let kp = mlkem768_keygen().unwrap();

        let encap1 = mlkem768_encapsulate(&kp.public_key).unwrap();
        let encap2 = mlkem768_encapsulate(&kp.public_key).unwrap();

        // Each encapsulation produces different ciphertext and shared secret
        assert_ne!(encap1.ciphertext, encap2.ciphertext);
        assert_ne!(encap1.shared_secret, encap2.shared_secret);

        // Both can be decapsulated correctly
        let ss1 = mlkem768_decapsulate(&kp.secret_key, &encap1.ciphertext).unwrap();
        let ss2 = mlkem768_decapsulate(&kp.secret_key, &encap2.ciphertext).unwrap();
        assert_eq!(ss1, encap1.shared_secret);
        assert_eq!(ss2, encap2.shared_secret);
    }

    // ─── Density (fixture-free, pure helpers) ──────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn mlkem768_sizes_strict_pin_with_fips203_reference_and_cross_relations() {
        // FIPS 203 ML-KEM-768 reference byte budgets — these are the canonical
        // wire sizes. A regression here breaks every encrypted-session peer in
        // the fleet because all peers compute key/CT byte offsets from these.
        assert_eq!(MlKem768Sizes::PUBLIC_KEY, 1184);
        assert_eq!(MlKem768Sizes::SECRET_KEY, 2400);
        assert_eq!(MlKem768Sizes::CIPHERTEXT, 1088);
        assert_eq!(MlKem768Sizes::SHARED_SECRET, 32);

        // Cross-relations (load-bearing for memory/wire budgeting).
        // 1) SHARED_SECRET == 32 == SHA3-256 output size — shared secret is
        //    used directly as a symmetric key/seed for downstream KDFs that
        //    consume 32-byte inputs. Drift here breaks every downstream
        //    user of decapsulate().
        assert_eq!(MlKem768Sizes::SHARED_SECRET, 32);
        // 2) SECRET_KEY > PUBLIC_KEY > CIPHERTEXT > SHARED_SECRET strict
        //    ordering. CIPHERTEXT < PUBLIC_KEY catches an accidental swap
        //    that would still pass naive sanity-checks because both are
        //    ~1KB.
        assert!(MlKem768Sizes::SECRET_KEY > MlKem768Sizes::PUBLIC_KEY);
        assert!(MlKem768Sizes::PUBLIC_KEY > MlKem768Sizes::CIPHERTEXT);
        assert!(MlKem768Sizes::CIPHERTEXT > MlKem768Sizes::SHARED_SECRET);
        // 3) All sizes pairwise distinct.
        let sizes = [
            MlKem768Sizes::PUBLIC_KEY,
            MlKem768Sizes::SECRET_KEY,
            MlKem768Sizes::CIPHERTEXT,
            MlKem768Sizes::SHARED_SECRET,
        ];
        for i in 0..sizes.len() {
            for j in (i + 1)..sizes.len() {
                assert_ne!(sizes[i], sizes[j], "size collision at {i}/{j}");
            }
        }
        // 4) Memory budget: a single keypair + a single encapsulation fits
        //    in well under 8 KB total (mainnet phone-tier hardware floor).
        //    PUBLIC + SECRET + CIPHERTEXT + SHARED_SECRET = 4704 bytes.
        let total = MlKem768Sizes::PUBLIC_KEY
            + MlKem768Sizes::SECRET_KEY
            + MlKem768Sizes::CIPHERTEXT
            + MlKem768Sizes::SHARED_SECRET;
        assert_eq!(total, 4704);
        assert!(total < 8 * 1024);
        // 5) All sizes positive and fit in u16 (1184/2400/1088/32 all < 65536),
        //    so any wire format with u16 length prefix can carry them.
        for &s in &sizes {
            assert!(s > 0);
            assert!(s <= u16::MAX as usize);
        }

        // Round-trip with a live keypair confirms the constants match what
        // the underlying crypto library actually emits — guards against an
        // upgrade silently changing internal sizes.
        let kp = mlkem768_keygen().unwrap();
        assert_eq!(kp.public_key.len(), MlKem768Sizes::PUBLIC_KEY);
        assert_eq!(kp.secret_key.len(), MlKem768Sizes::SECRET_KEY);
        let encap = mlkem768_encapsulate(&kp.public_key).unwrap();
        assert_eq!(encap.ciphertext.len(), MlKem768Sizes::CIPHERTEXT);
        assert_eq!(encap.shared_secret.len(), MlKem768Sizes::SHARED_SECRET);
    }

    #[test]
    fn kem_keypair_and_encapsulation_struct_shape_pins() {
        let kp = mlkem768_keygen().unwrap();
        let encap = mlkem768_encapsulate(&kp.public_key).unwrap();

        // ─── KemKeypair shape ───
        // Field-name pin via destructuring — if a future PR renames either
        // field, this match fails to compile. Ref-destructure (not by-value)
        // because `KemKeypair` now implements `Drop` (zeroize), which forbids
        // moving fields out.
        let KemKeypair {
            public_key,
            secret_key,
        } = &kp;
        assert_eq!(public_key, &kp.public_key);
        assert_eq!(secret_key, &kp.secret_key);

        // Clone semantics: deep-copy of both Vec<u8> fields. Mutating the
        // clone's public_key must NOT affect the original. This catches an
        // accidental Arc/Cow refactor.
        let mut kp_clone = kp.clone();
        kp_clone.public_key[0] ^= 0xFF;
        assert_ne!(kp_clone.public_key, kp.public_key);
        assert_eq!(kp_clone.secret_key, kp.secret_key); // secret_key untouched

        // Debug format contains type + field names (used in error messages
        // and operator logs) but REDACTS the secret-key bytes — a `{:?}` of a
        // keypair must never dump the 2,400-byte secret to a log.
        let dbg = format!("{:?}", kp);
        assert!(dbg.contains("KemKeypair"));
        assert!(dbg.contains("public_key"));
        assert!(dbg.contains("secret_key")); // field name present
        assert!(dbg.contains("<redacted>"), "secret_key value must be redacted");

        // ─── KemEncapsulation shape ───
        let KemEncapsulation {
            ciphertext,
            shared_secret,
        } = &encap;
        assert_eq!(ciphertext, &encap.ciphertext);
        assert_eq!(shared_secret, &encap.shared_secret);

        // Clone independence: mutating clone's ciphertext leaves original
        // untouched.
        let mut encap_clone = encap.clone();
        encap_clone.ciphertext[0] ^= 0xFF;
        assert_ne!(encap_clone.ciphertext, encap.ciphertext);
        assert_eq!(encap_clone.shared_secret, encap.shared_secret);

        let dbg = format!("{:?}", encap);
        assert!(dbg.contains("KemEncapsulation"));
        assert!(dbg.contains("ciphertext"));
        assert!(dbg.contains("shared_secret")); // field name present
        assert!(dbg.contains("<redacted>"), "shared_secret value must be redacted");

        // The struct has EXACTLY 2 fields each — `KemKeypair { public_key,
        // secret_key }` and `KemEncapsulation { ciphertext, shared_secret }`.
        // The exhaustive match above with no `..` rest pattern enforces this
        // at compile time; if a third field is added the destructuring fails.
    }

    #[test]
    fn mlkem768_encapsulate_wrong_size_sweep_returns_err_not_panic() {
        // Every off-size or empty key MUST yield Err — never panic, never
        // silently encapsulate. ML-KEM is byte-exact: only a 1184-byte key
        // is structurally valid.
        let wrong_sizes = [
            0usize,                        // empty
            1,                             // far too small
            32,                            // SHARED_SECRET length (sneaky)
            1088,                          // CIPHERTEXT length (sneaky)
            MlKem768Sizes::PUBLIC_KEY - 1, // off-by-one short (1183)
            MlKem768Sizes::PUBLIC_KEY + 1, // off-by-one long (1185)
            MlKem768Sizes::SECRET_KEY,     // SECRET_KEY length (2400)
            5000,                          // far too large
        ];
        for n in wrong_sizes {
            let buf = vec![0xAAu8; n];
            let result = mlkem768_encapsulate(&buf);
            assert!(
                result.is_err(),
                "encapsulate with public_key len={n} must Err, got Ok",
            );
            // Pin the error variant: a wrong-size key is InvalidPublicKey.
            assert!(matches!(result.unwrap_err(), KemError::InvalidPublicKey));
        }

        // Boundary positive control: a buffer of CORRECT length but
        // all-zeros is accepted by the size-check (oqs may still decapsulate
        // garbage but the encapsulate call returns Ok or Err depending on
        // backend validation). The key invariant here is no panic.
        let buf = vec![0u8; MlKem768Sizes::PUBLIC_KEY];
        let _ = mlkem768_encapsulate(&buf); // either Ok or Err, never panic
    }

    #[test]
    fn mlkem768_decapsulate_wrong_size_sweep_returns_err_not_panic() {
        let kp = mlkem768_keygen().unwrap();
        let encap = mlkem768_encapsulate(&kp.public_key).unwrap();

        // ─── Wrong secret_key sizes ───
        let wrong_sk_sizes = [
            0usize,
            1,
            32,
            1088,
            1184,                          // PUBLIC_KEY length (sneaky)
            MlKem768Sizes::SECRET_KEY - 1, // off-by-one short (2399)
            MlKem768Sizes::SECRET_KEY + 1, // off-by-one long (2401)
            5000,
        ];
        for n in wrong_sk_sizes {
            let buf = vec![0xBBu8; n];
            let result = mlkem768_decapsulate(&buf, &encap.ciphertext);
            assert!(
                result.is_err(),
                "decapsulate with secret_key len={n} must Err, got Ok",
            );
            assert!(matches!(result.unwrap_err(), KemError::InvalidSecretKey));
        }

        // ─── Wrong ciphertext sizes ───
        let wrong_ct_sizes = [
            0usize,
            1,
            32,
            1184,                          // PUBLIC_KEY length (sneaky)
            MlKem768Sizes::CIPHERTEXT - 1, // off-by-one short (1087)
            MlKem768Sizes::CIPHERTEXT + 1, // off-by-one long (1089)
            MlKem768Sizes::SECRET_KEY,     // SECRET_KEY length (sneaky)
            5000,
        ];
        for n in wrong_ct_sizes {
            let buf = vec![0xCCu8; n];
            let result = mlkem768_decapsulate(&kp.secret_key, &buf);
            assert!(
                result.is_err(),
                "decapsulate with ciphertext len={n} must Err, got Ok",
            );
            assert!(matches!(result.unwrap_err(), KemError::InvalidCiphertext));
        }

        // Positive control: correct sizes round-trip cleanly.
        let ss = mlkem768_decapsulate(&kp.secret_key, &encap.ciphertext).unwrap();
        assert_eq!(ss, encap.shared_secret);
        assert_eq!(ss.len(), MlKem768Sizes::SHARED_SECRET);
    }

    #[test]
    fn kem_encapsulation_freshness_8_iter_no_collision_and_roundtrip() {
        // ML-KEM-768 encap MUST produce fresh randomness per call — both
        // ciphertext and shared_secret are sampled from the recipient's
        // public key + a random nonce. K=8 iterations gives a probabilistic
        // floor that catches any RNG seed/state leak: if encap reused
        // entropy, ciphertexts would collide within 8 samples at 256-bit
        // strength (negligible probability for honest RNG).
        let kp = mlkem768_keygen().unwrap();

        const K: usize = 8;
        let mut encaps = Vec::with_capacity(K);
        for _ in 0..K {
            encaps.push(mlkem768_encapsulate(&kp.public_key).unwrap());
        }

        // Pairwise distinctness on ciphertext: no two encaps share a CT.
        for i in 0..K {
            for j in (i + 1)..K {
                assert_ne!(
                    encaps[i].ciphertext, encaps[j].ciphertext,
                    "ciphertext collision at i={i} j={j} — RNG entropy reuse",
                );
            }
        }
        // Pairwise distinctness on shared_secret: no two encaps share an SS.
        for i in 0..K {
            for j in (i + 1)..K {
                assert_ne!(
                    encaps[i].shared_secret, encaps[j].shared_secret,
                    "shared_secret collision at i={i} j={j} — RNG entropy reuse",
                );
            }
        }

        // HashSet dedup confirms K distinct ciphertexts AND K distinct
        // shared secrets — redundant with the pairwise check but catches
        // bugs in the pairwise loop bounds.
        let cts: std::collections::HashSet<Vec<u8>> =
            encaps.iter().map(|e| e.ciphertext.clone()).collect();
        assert_eq!(cts.len(), K);
        let sss: std::collections::HashSet<Vec<u8>> =
            encaps.iter().map(|e| e.shared_secret.clone()).collect();
        assert_eq!(sss.len(), K);

        // Every ciphertext correctly decapsulates to its paired shared
        // secret — encapsulation freshness must not break the encap/decap
        // contract.
        for (i, encap) in encaps.iter().enumerate() {
            let decap = mlkem768_decapsulate(&kp.secret_key, &encap.ciphertext).unwrap();
            assert_eq!(decap, encap.shared_secret, "decap roundtrip failed at i={i}",);
            // Length invariant per iteration.
            assert_eq!(encap.ciphertext.len(), MlKem768Sizes::CIPHERTEXT);
            assert_eq!(encap.shared_secret.len(), MlKem768Sizes::SHARED_SECRET);
            assert_eq!(decap.len(), MlKem768Sizes::SHARED_SECRET);
        }
    }
}
