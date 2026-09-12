//! Cryptographic primitives: PQC signatures, hashing, batch operations.

pub mod batch;
pub use elara_record::hash;
#[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
pub mod kem;
pub mod pqc;
pub mod commitment;
pub mod vrf;
pub mod zk;

// ─── Algorithm Identifiers (Protocol §4.4 — Algorithm Agility) ─────────────
//
// Every signature carries an algorithm ID, so a future migration would not
// need a wire-format change. That is the whole of it today: the IDs are
// RESERVED, not dispatched on. The decoder hard-rejects any primary
// `sig_algorithm` other than `ALG_DILITHIUM3` (`elara-record`'s
// `record.rs`, "only 0x.. Dilithium3 is currently accepted"), and every
// verify path calls `dilithium3_verify` directly — there is no
// `match sig_algorithm` anywhere in non-test code.
//
// Corrected 2026-09-07 (audit R2/crypto-sig/CS-1): this comment used to say
// "old records remain valid under their original algorithms". That is NOT a
// property this code has — a record signed under a retired algorithm is
// rejected at decode, not grandfathered. Agility here is a wire affordance
// for a migration that has not been built.

/// Signature algorithm IDs — canonical in `elara_record::pqc` (record wire
/// bytes carry them): Dilithium3 / ML-DSA-65 (FIPS 204) primary,
/// SPHINCS+-SHA2-192f / SLH-DSA (FIPS 205) secondary hash-based.
pub use elara_record::pqc::{ALG_DILITHIUM3, ALG_SPHINCS_SHA2_192F};

/// CRYSTALS-Kyber768 / ML-KEM (FIPS 203) — key encapsulation.
pub const ALG_KYBER768: u8 = 0x03;

/// Look up algorithm name from ID.
pub fn algorithm_name(id: u8) -> &'static str {
    match id {
        ALG_DILITHIUM3 => "ML-DSA-65",
        ALG_SPHINCS_SHA2_192F => "SLH-DSA-SHA2-192f",
        ALG_KYBER768 => "ML-KEM-768",
        _ => "unknown",
    }
}
