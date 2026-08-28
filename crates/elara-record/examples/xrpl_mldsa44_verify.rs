//! Offline XRPL ML-DSA-44 signature verifier.
//!
//! XRPL's `Quantum` amendment (XLS draft "Post-Quantum Signatures (ML-DSA-44)",
//! XRPLF/XRPL-Standards discussion #295) standardizes ML-DSA-44 / FIPS 204 with
//! the external interface and empty context; on the wire, a 1312-byte
//! `SigningPubKey` selects the dilithium path. This example verifies exactly
//! that primitive — raw (pubkey, message, signature) — fully offline, no
//! network, no key material beyond public data.
//!
//! Scope (v1, deliberate): the raw signature check ONLY. It does NOT derive
//! r-addresses, parse signed-transaction blobs, or reconstruct XRPL signing
//! payloads — the exact dilithium message construction must be read out of the
//! reference implementation before anything asserts it (see the build spec's
//! out-of-scope fences). Elara records themselves remain ML-DSA-65.
//!
//! Usage:
//!   cargo run -p elara-record --example xrpl_mldsa44_verify -- \
//!       <pubkey_hex:1312B> <message_hex> <signature_hex:2420B>
//!
//! Prints `VERIFIED` (exit 0) or `REJECTED`/`REJECTED (<reason>)` (exit 1).

use std::process::ExitCode;

fn unhex(label: &str, s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{label}: odd hex length {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("{label}: invalid hex at offset {i}"))
        })
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: xrpl_mldsa44_verify <pubkey_hex> <message_hex> <signature_hex>");
        return ExitCode::FAILURE;
    }
    let (pk, msg, sig) = match (
        unhex("pubkey", &args[1]),
        unhex("message", &args[2]),
        unhex("signature", &args[3]),
    ) {
        (Ok(pk), Ok(msg), Ok(sig)) => (pk, msg, sig),
        (pk, msg, sig) => {
            for r in [&pk, &msg, &sig] {
                if let Err(e) = r {
                    eprintln!("REJECTED ({e})");
                }
            }
            return ExitCode::FAILURE;
        }
    };
    match elara_record::pqc::mldsa44_verify(&msg, &sig, &pk) {
        Ok(true) => {
            println!("VERIFIED");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("REJECTED");
            ExitCode::FAILURE
        }
        Err(e) => {
            println!("REJECTED ({e})");
            ExitCode::FAILURE
        }
    }
}
