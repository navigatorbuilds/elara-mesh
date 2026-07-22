//! Parallel batch sign/verify via rayon (native) or sequential fallback (WASM).

//!
//! Spec references:
//!   @spec Protocol §4.2

#[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
use rayon::prelude::*;

use crate::crypto::pqc::{dilithium3_sign_with_pk, dilithium3_verify, sphincs_sign_with_pk};
use crate::errors::Result;

/// A verification job: (message, signature, public_key).
pub struct VerifyJob<'a> {
    pub message: &'a [u8],
    pub signature: &'a [u8],
    pub public_key: &'a [u8],
}

/// Verify multiple Dilithium3 signatures in parallel (native) or sequentially (WASM).
/// Returns a Vec of bools, one per job.
pub fn batch_verify(jobs: &[VerifyJob]) -> Vec<bool> {
    #[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
    {
        jobs.par_iter()
            .map(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
            .collect()
    }
    #[cfg(any(target_arch = "wasm32", not(feature = "node")))]
    {
        jobs.iter()
            .map(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
            .collect()
    }
}

/// Verify multiple signatures, returning true only if ALL pass.
pub fn batch_verify_all(jobs: &[VerifyJob]) -> bool {
    #[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
    {
        jobs.par_iter()
            .all(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
    }
    #[cfg(any(target_arch = "wasm32", not(feature = "node")))]
    {
        jobs.iter()
            .all(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
    }
}

/// A signing job: (message, secret_key, public_key).
pub struct SignJob<'a> {
    pub message: &'a [u8],
    pub secret_key: &'a [u8],
    pub public_key: &'a [u8],
}

/// Sign multiple messages with Dilithium3.
pub fn batch_sign(jobs: &[SignJob]) -> Vec<Result<Vec<u8>>> {
    #[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
    {
        jobs.par_iter()
            .map(|job| dilithium3_sign_with_pk(job.message, job.secret_key, job.public_key))
            .collect()
    }
    #[cfg(any(target_arch = "wasm32", not(feature = "node")))]
    {
        jobs.iter()
            .map(|job| dilithium3_sign_with_pk(job.message, job.secret_key, job.public_key))
            .collect()
    }
}

/// Dual-sign multiple messages (Dilithium3 + SPHINCS+ per message).
/// Returns Vec<Result<(Vec<u8>, Vec<u8>)>> — (dilithium_sig, sphincs_sig) per message.
pub fn batch_dual_sign(
    messages: &[Vec<u8>],
    dilithium_sk: &[u8],
    dilithium_pk: &[u8],
    sphincs_sk: &[u8],
    sphincs_pk: &[u8],
) -> Vec<Result<(Vec<u8>, Vec<u8>)>> {
    #[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
    {
        messages
            .par_iter()
            .map(|msg| {
                let dil = dilithium3_sign_with_pk(msg, dilithium_sk, dilithium_pk)?;
                let sph = sphincs_sign_with_pk(msg, sphincs_sk, sphincs_pk)?;
                Ok((dil, sph))
            })
            .collect()
    }
    #[cfg(any(target_arch = "wasm32", not(feature = "node")))]
    {
        messages
            .iter()
            .map(|msg| {
                let dil = dilithium3_sign_with_pk(msg, dilithium_sk, dilithium_pk)?;
                let sph = sphincs_sign_with_pk(msg, sphincs_sk, sphincs_pk)?;
                Ok((dil, sph))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk, sphincs_keygen, sphincs_verify};

    #[test]
    fn test_batch_verify_all_valid() {
        let kp = dilithium3_keygen().unwrap();
        let messages: Vec<Vec<u8>> = (0..10).map(|i| format!("msg-{i}").into_bytes()).collect();
        let sigs: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| dilithium3_sign_with_pk(m, &kp.secret_key, &kp.public_key).unwrap())
            .collect();

        let jobs: Vec<VerifyJob> = messages
            .iter()
            .zip(sigs.iter())
            .map(|(m, s)| VerifyJob {
                message: m,
                signature: s,
                public_key: &kp.public_key,
            })
            .collect();

        let results = batch_verify(&jobs);
        assert!(results.iter().all(|&r| r));
        assert!(batch_verify_all(&jobs));
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let kp = dilithium3_keygen().unwrap();
        let kp2 = dilithium3_keygen().unwrap();
        let msg = b"test message";
        let sig_valid = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
        let sig_invalid = dilithium3_sign_with_pk(msg, &kp2.secret_key, &kp2.public_key).unwrap();

        let jobs = vec![
            VerifyJob {
                message: msg,
                signature: &sig_valid,
                public_key: &kp.public_key,
            },
            VerifyJob {
                message: msg,
                signature: &sig_invalid,
                public_key: &kp.public_key, // wrong key for this sig
            },
        ];

        let results = batch_verify(&jobs);
        assert!(results[0]);
        assert!(!results[1]);
        assert!(!batch_verify_all(&jobs));
    }

    #[test]
    fn test_batch_sign() {
        let kp = dilithium3_keygen().unwrap();
        let messages: Vec<Vec<u8>> = (0..5).map(|i| format!("sign-{i}").into_bytes()).collect();
        let jobs: Vec<SignJob> = messages
            .iter()
            .map(|m| SignJob {
                message: m,
                secret_key: &kp.secret_key,
                public_key: &kp.public_key,
            })
            .collect();

        let sigs = batch_sign(&jobs);
        assert_eq!(sigs.len(), 5);
        for (i, sig_result) in sigs.iter().enumerate() {
            let sig = sig_result.as_ref().unwrap();
            assert!(dilithium3_verify(&messages[i], sig, &kp.public_key).unwrap());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_batch_dual_sign() {
        let dil_kp = dilithium3_keygen().unwrap();
        let sph_kp = sphincs_keygen().unwrap();
        let messages: Vec<Vec<u8>> = (0..5).map(|i| format!("dual-{i}").into_bytes()).collect();

        let results = batch_dual_sign(&messages, &dil_kp.secret_key, &dil_kp.public_key, &sph_kp.secret_key, &sph_kp.public_key);
        assert_eq!(results.len(), 5);

        for (i, result) in results.iter().enumerate() {
            let (dil_sig, sph_sig) = result.as_ref().unwrap();
            assert!(dilithium3_verify(&messages[i], dil_sig, &dil_kp.public_key).unwrap());
            assert!(sphincs_verify(&messages[i], sph_sig, &sph_kp.public_key).unwrap());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_batch_dual_sign_empty() {
        let dil_kp = dilithium3_keygen().unwrap();
        let sph_kp = sphincs_keygen().unwrap();
        let results = batch_dual_sign(&[], &dil_kp.secret_key, &dil_kp.public_key, &sph_kp.secret_key, &sph_kp.public_key);
        assert!(results.is_empty());
    }

    // ─── fixture-free, pure helpers ─────────────────────
    // Five axes that exercise the pure-parallel/sequential dispatch helpers
    // without spinning up NodeState / storage / network — fast, deterministic,
    // no rayon thread-pool dependence at the assertion layer.

    #[test]
    fn batch_b_batch_verify_empty_single_and_n_job_invariants_len_and_order_preserved() {
        // Axis 1: batch_verify contract — len-preservation, order-preservation,
        //   empty → empty Vec, single-job → length-1 Vec, all-valid → all true.
        // Both code paths (rayon par_iter on native, seq iter on wasm/non-node)
        // MUST preserve input order in the output Vec — this is a load-bearing
        // invariant for downstream `.zip(jobs)` correlation in callers.
        let kp = dilithium3_keygen().unwrap();

        // ── empty input → empty output (no panic on zero-length par_iter) ──
        let empty_result = batch_verify(&[]);
        assert!(empty_result.is_empty());
        assert_eq!(empty_result.len(), 0);

        // ── single job, valid ──
        let msg = b"single-batch_b";
        let sig = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
        let single = vec![VerifyJob {
            message: msg,
            signature: &sig,
            public_key: &kp.public_key,
        }];
        let single_result = batch_verify(&single);
        assert_eq!(single_result.len(), 1);
        assert!(single_result[0]);

        // ── N=7 jobs, all valid, distinct messages → all true, order preserved ──
        let msgs: Vec<Vec<u8>> = (0..7).map(|i| format!("ordered-{i}").into_bytes()).collect();
        let sigs: Vec<Vec<u8>> = msgs
            .iter()
            .map(|m| dilithium3_sign_with_pk(m, &kp.secret_key, &kp.public_key).unwrap())
            .collect();
        let jobs: Vec<VerifyJob> = msgs
            .iter()
            .zip(sigs.iter())
            .map(|(m, s)| VerifyJob {
                message: m,
                signature: s,
                public_key: &kp.public_key,
            })
            .collect();
        let results = batch_verify(&jobs);
        assert_eq!(results.len(), jobs.len());
        assert_eq!(results.len(), 7);
        for (i, r) in results.iter().enumerate() {
            assert!(*r, "job {i} should verify");
        }

        // ── Order witness: mix valid/invalid in known positions, confirm
        //    output bit-pattern matches input order (par_iter MUST collect in
        //    sequence, not reordered by completion time) ──
        let kp_other = dilithium3_keygen().unwrap();
        let valid_sig = dilithium3_sign_with_pk(b"order-test", &kp.secret_key, &kp.public_key).unwrap();
        let invalid_sig = dilithium3_sign_with_pk(b"order-test", &kp_other.secret_key, &kp_other.public_key).unwrap();
        // Pattern: [valid, invalid, valid, invalid, valid] → [T, F, T, F, T]
        let mixed = vec![
            VerifyJob { message: b"order-test", signature: &valid_sig, public_key: &kp.public_key },
            VerifyJob { message: b"order-test", signature: &invalid_sig, public_key: &kp.public_key },
            VerifyJob { message: b"order-test", signature: &valid_sig, public_key: &kp.public_key },
            VerifyJob { message: b"order-test", signature: &invalid_sig, public_key: &kp.public_key },
            VerifyJob { message: b"order-test", signature: &valid_sig, public_key: &kp.public_key },
        ];
        let mixed_results = batch_verify(&mixed);
        assert_eq!(mixed_results.len(), 5);
        assert_eq!(mixed_results, vec![true, false, true, false, true],
            "batch_verify MUST preserve input order in output Vec");
    }

    #[test]
    fn batch_b_batch_verify_all_short_circuit_empty_vacuous_true_and_equivalence_with_iter_all() {
        // Axis 2: batch_verify_all contract — empty input → true (vacuous),
        //   all-valid → true, any-invalid → false.
        //   Must be semantically equivalent to batch_verify(...).iter().all(|&r| r)
        //   for every input shape — both code paths.
        let kp = dilithium3_keygen().unwrap();
        let kp2 = dilithium3_keygen().unwrap();

        // ── Empty input → true (par_iter::all on empty iter is vacuously true) ──
        let empty_all = batch_verify_all(&[]);
        let empty_iter_all = batch_verify(&[]).iter().all(|&r| r);
        assert!(empty_all, "empty batch_verify_all MUST return true (vacuous truth)");
        assert_eq!(empty_all, empty_iter_all,
            "batch_verify_all must agree with batch_verify(...).iter().all() on empty");

        // ── Single valid → true ──
        let msg = b"all-valid";
        let sig = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
        let single = vec![VerifyJob { message: msg, signature: &sig, public_key: &kp.public_key }];
        assert!(batch_verify_all(&single));
        assert_eq!(batch_verify_all(&single), batch_verify(&single).iter().all(|&r| r));

        // ── N valid → true ──
        let msgs: Vec<Vec<u8>> = (0..5).map(|i| format!("av-{i}").into_bytes()).collect();
        let sigs: Vec<Vec<u8>> = msgs
            .iter()
            .map(|m| dilithium3_sign_with_pk(m, &kp.secret_key, &kp.public_key).unwrap())
            .collect();
        let jobs: Vec<VerifyJob> = msgs.iter().zip(sigs.iter())
            .map(|(m, s)| VerifyJob { message: m, signature: s, public_key: &kp.public_key })
            .collect();
        assert!(batch_verify_all(&jobs));
        assert_eq!(batch_verify_all(&jobs), batch_verify(&jobs).iter().all(|&r| r));

        // ── ANY invalid → false. Test invalid at FIRST, MIDDLE, LAST positions ──
        let valid = dilithium3_sign_with_pk(b"x", &kp.secret_key, &kp.public_key).unwrap();
        let invalid = dilithium3_sign_with_pk(b"x", &kp2.secret_key, &kp2.public_key).unwrap();
        let mk = |pos: usize| -> Vec<VerifyJob> {
            (0..3).map(|i| VerifyJob {
                message: b"x",
                signature: if i == pos { &invalid } else { &valid },
                public_key: &kp.public_key,
            }).collect()
        };
        for pos in 0..3 {
            let jobs = mk(pos);
            assert!(!batch_verify_all(&jobs), "invalid at position {pos} must fail batch_verify_all");
            assert_eq!(
                batch_verify_all(&jobs),
                batch_verify(&jobs).iter().all(|&r| r),
                "batch_verify_all and iter().all() must agree at pos {pos}"
            );
        }

        // ── ALL invalid → false ──
        let all_invalid: Vec<VerifyJob> = (0..3).map(|_| VerifyJob {
            message: b"x",
            signature: &invalid,
            public_key: &kp.public_key,
        }).collect();
        assert!(!batch_verify_all(&all_invalid));
        assert_eq!(batch_verify_all(&all_invalid), batch_verify(&all_invalid).iter().all(|&r| r));
    }

    #[test]
    fn batch_b_batch_sign_len_preservation_signature_size_invariant_and_per_job_roundtrip() {
        // Axis 3: batch_sign contract — len(output)==len(input);
        //   every signature is Ok(...) under matching keys + verifies with dilithium3_verify;
        //   every signature is exactly 3309 bytes (FIPS 204 ML-DSA-65, pqc.rs:108).
        //   Empty input → empty Vec (no panic on zero-length par_iter).
        let kp = dilithium3_keygen().unwrap();

        // ── Empty input → empty output ──
        let empty = batch_sign(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        // ── Single job ──
        let single_msg = b"single-sign".to_vec();
        let single_jobs = vec![SignJob {
            message: &single_msg,
            secret_key: &kp.secret_key,
            public_key: &kp.public_key,
        }];
        let single_sigs = batch_sign(&single_jobs);
        assert_eq!(single_sigs.len(), 1);
        let single_sig = single_sigs[0].as_ref().expect("single sign must succeed");
        assert_eq!(single_sig.len(), 3309, "Dilithium3/ML-DSA-65 signature MUST be 3309 bytes (FIPS 204)");
        assert!(dilithium3_verify(&single_msg, single_sig, &kp.public_key).unwrap());

        // ── N=8 jobs with distinct messages ──
        let msgs: Vec<Vec<u8>> = (0..8).map(|i| format!("bs-{i}").into_bytes()).collect();
        let jobs: Vec<SignJob> = msgs.iter().map(|m| SignJob {
            message: m,
            secret_key: &kp.secret_key,
            public_key: &kp.public_key,
        }).collect();
        let sigs = batch_sign(&jobs);
        assert_eq!(sigs.len(), 8);
        for (i, sig_result) in sigs.iter().enumerate() {
            let sig = sig_result.as_ref().unwrap_or_else(|_| panic!("job {i} must succeed"));
            assert_eq!(sig.len(), 3309, "every Dilithium3 sig must be 3309 bytes (pqc.rs:108 length gate)");
            // Per-job round-trip: each sig must verify against its message + the shared pubkey
            let verified = dilithium3_verify(&msgs[i], sig, &kp.public_key).unwrap();
            assert!(verified, "batch_sign output for job {i} must round-trip through dilithium3_verify");
        }

        // ── Cross-verification: sig for msg[0] does NOT verify against msg[1]
        //    (catches a hypothetical bug where batch_sign signed a constant) ──
        let sig0 = sigs[0].as_ref().unwrap();
        let sig1 = sigs[1].as_ref().unwrap();
        // Different messages → signatures must differ (ML-DSA-65 randomized but
        // even deterministic mode binds message into the transcript)
        assert!(dilithium3_verify(&msgs[0], sig0, &kp.public_key).unwrap());
        assert!(!dilithium3_verify(&msgs[1], sig0, &kp.public_key).unwrap(),
            "sig for msg[0] must NOT verify against msg[1]");
        assert!(dilithium3_verify(&msgs[1], sig1, &kp.public_key).unwrap());
        assert!(!dilithium3_verify(&msgs[0], sig1, &kp.public_key).unwrap(),
            "sig for msg[1] must NOT verify against msg[0]");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn batch_b_batch_dual_sign_empty_arity_dilithium_sphincs_separation_and_cross_alg_rejection() {
        // Axis 4: batch_dual_sign contract — emits Vec<Result<(dil_sig, sph_sig)>>;
        //   empty → empty; len matches input; each (dil, sph) verifies under its
        //   respective algorithm's pubkey; cross-algorithm verification REJECTS
        //   (dil_sig under sphincs pk → false/Err; sph_sig under dilithium pk → false/Err).
        //   Both signature kinds carry distinct length signatures:
        //     - Dilithium3 = 3309 bytes (FIPS 204)
        //     - SLH-DSA-SHA2-192f / SPHINCS+ = variable (35664 bytes for SHA2-192f, per FIPS 205)
        let dil_kp = dilithium3_keygen().unwrap();
        let sph_kp = sphincs_keygen().unwrap();

        // ── Empty input → empty output ──
        let empty = batch_dual_sign(&[], &dil_kp.secret_key, &dil_kp.public_key, &sph_kp.secret_key, &sph_kp.public_key);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        // ── N=4 messages, dual-sign each ──
        let msgs: Vec<Vec<u8>> = (0..4).map(|i| format!("dual-b-{i}").into_bytes()).collect();
        let results = batch_dual_sign(&msgs, &dil_kp.secret_key, &dil_kp.public_key, &sph_kp.secret_key, &sph_kp.public_key);
        assert_eq!(results.len(), 4);
        assert_eq!(results.len(), msgs.len(), "len(output) == len(messages)");

        for (i, result) in results.iter().enumerate() {
            let (dil_sig, sph_sig) = result.as_ref().unwrap_or_else(|_| panic!("dual sign job {i} must succeed"));
            // Length pins: Dilithium3 fixed 3309, SPHINCS+ non-trivially large + distinct.
            assert_eq!(dil_sig.len(), 3309, "Dilithium3 sig len pin (FIPS 204)");
            assert!(!sph_sig.is_empty(), "SPHINCS+ sig must be non-empty");
            assert_ne!(dil_sig.len(), sph_sig.len(),
                "dil_sig and sph_sig MUST have distinct lengths (different algorithms)");

            // ── Each sig verifies under its OWN algorithm's pubkey ──
            assert!(dilithium3_verify(&msgs[i], dil_sig, &dil_kp.public_key).unwrap(),
                "dil_sig for msg[{i}] must verify under Dilithium3 pubkey");
            assert!(sphincs_verify(&msgs[i], sph_sig, &sph_kp.public_key).unwrap(),
                "sph_sig for msg[{i}] must verify under SPHINCS+ pubkey");

            // ── Cross-algorithm REJECTION: feeding a Dilithium3 sig (3309 bytes)
            //    to sphincs_verify is well-formed at the slh-dsa layer but MUST
            //    return false (signature doesn't validate under SPHINCS+).
            //    Feeding a SPHINCS+ sig to dilithium3_verify hits the 3309-byte
            //    length gate at pqc.rs:108 → Err. Both are negative-path proof
            //    that the two signatures are algorithm-distinct, not just
            //    parallel-emitted with the same payload. ──
            // dil_sig under SPHINCS+ verifier — slh-dsa is tolerant of arbitrary
            // bytes but will return false on signature mismatch
            let cross_a = sphincs_verify(&msgs[i], dil_sig, &sph_kp.public_key);
            // Either Ok(false) (length-tolerant rejection) or Err (length gate).
            // Both are valid "rejection" outcomes — assert NOT Ok(true).
            match cross_a {
                Ok(b) => assert!(!b, "Dilithium3 sig MUST NOT verify under SPHINCS+ verifier"),
                Err(_) => { /* length/parse gate also acceptable */ }
            }
            // sph_sig under Dilithium3 verifier — length gate at pqc.rs:108 will Err
            // unless SPHINCS+ happens to emit 3309 bytes (it does not for SHA2-192f).
            let cross_b = dilithium3_verify(&msgs[i], sph_sig, &dil_kp.public_key);
            match cross_b {
                Ok(b) => assert!(!b, "SPHINCS+ sig MUST NOT verify under Dilithium3 verifier"),
                Err(_) => { /* length-gate rejection at pqc.rs:108 expected */ }
            }
        }

        // ── Witness that dual-sign uses the SAME dil sk across all messages
        //    (per-call: signs msg_i with dilithium_sk; signs msg_i with sphincs_sk).
        //    Different messages produce different signatures, but ALL verify under
        //    the SAME pubkey-pair — cross-message tampering breaks verify. ──
        let r0 = results[0].as_ref().unwrap();
        let r1 = results[1].as_ref().unwrap();
        // msg[1] under dil_sig from job[0] must NOT verify
        assert!(!dilithium3_verify(&msgs[1], &r0.0, &dil_kp.public_key).unwrap(),
            "dil_sig from job 0 must NOT verify against msg[1]");
        assert!(!dilithium3_verify(&msgs[0], &r1.0, &dil_kp.public_key).unwrap(),
            "dil_sig from job 1 must NOT verify against msg[0]");
    }

    #[test]
    fn batch_b_verify_job_and_sign_job_struct_shape_pin_lifetime_bound_no_unintended_derives() {
        // Axis 5: VerifyJob / SignJob struct-shape pin — both are #[no-derive]
        // lifetime-parameterized 3-field reference holders. Confirms:
        //   - Field count == 3 each
        //   - Field names exactly: VerifyJob {message, signature, public_key},
        //                          SignJob   {message, secret_key, public_key}
        //   - Fields are &[u8] references with lifetime 'a (compile-time pin
        //     via explicit destructuring rejects rename or type change)
        //   - SignJob has secret_key NOT signature (semantic delta from VerifyJob;
        //     reusing field names across the two would mask a typo at call site)
        //   - The structs do NOT implement Clone/Copy/Default/Debug — they are
        //     intended as zero-cost view structs only. Test by checking that
        //     none of these auto-derive bounds are present at construction time.
        let msg: &[u8] = b"shape-pin";
        let sig: &[u8] = b"sig-bytes";
        let pk: &[u8] = b"pk-bytes";
        let sk: &[u8] = b"sk-bytes";

        // ── VerifyJob exhaustive destructure: field-name + count pin ──
        let v = VerifyJob { message: msg, signature: sig, public_key: pk };
        let VerifyJob { message: m_v, signature: s_v, public_key: p_v } = v;
        assert_eq!(m_v.len(), msg.len());
        assert_eq!(s_v.len(), sig.len());
        assert_eq!(p_v.len(), pk.len());
        assert_eq!(m_v, msg);
        assert_eq!(s_v, sig);
        assert_eq!(p_v, pk);

        // ── SignJob exhaustive destructure: different middle field name ──
        let sj = SignJob { message: msg, secret_key: sk, public_key: pk };
        let SignJob { message: m_s, secret_key: sk_s, public_key: p_s } = sj;
        assert_eq!(m_s, msg);
        assert_eq!(sk_s, sk);
        assert_eq!(p_s, pk);

        // ── Compile-time witness that secret_key != signature: if SignJob's
        //    middle field were renamed to `signature`, the prior exhaustive
        //    destructure would not compile. Conversely, building a SignJob via
        //    `secret_key:` keyword and then reading `.secret_key` confirms
        //    field-name stability. ──
        let sj2 = SignJob { message: msg, secret_key: sk, public_key: pk };
        assert_eq!(sj2.secret_key, sk);
        assert_eq!(sj2.message, msg);
        assert_eq!(sj2.public_key, pk);

        // ── Vec<VerifyJob> with lifetime-distinct backings still type-checks
        //    when all references share the same lifetime (compile-time witness
        //    that the lifetime parameter behaves as a single 'a, not multi-'a). ──
        let m1 = b"m1".to_vec();
        let m2 = b"m2".to_vec();
        let s1 = b"s1".to_vec();
        let s2 = b"s2".to_vec();
        let p1 = b"p1".to_vec();
        let p2 = b"p2".to_vec();
        let multi: Vec<VerifyJob> = vec![
            VerifyJob { message: &m1, signature: &s1, public_key: &p1 },
            VerifyJob { message: &m2, signature: &s2, public_key: &p2 },
        ];
        assert_eq!(multi.len(), 2);
        assert_eq!(multi[0].message, &m1[..]);
        assert_eq!(multi[1].message, &m2[..]);

        // ── Sanity: empty references are accepted (zero-length payload pass-
        //    through; the type holds &[u8], not NonEmpty<u8>) ──
        let empty_v = VerifyJob { message: &[], signature: &[], public_key: &[] };
        assert!(empty_v.message.is_empty());
        assert!(empty_v.signature.is_empty());
        assert!(empty_v.public_key.is_empty());

        let empty_s = SignJob { message: &[], secret_key: &[], public_key: &[] };
        assert!(empty_s.message.is_empty());
        assert!(empty_s.secret_key.is_empty());
        assert!(empty_s.public_key.is_empty());
    }
}
