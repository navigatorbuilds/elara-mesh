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
// need a wire-format change. For the PRIMARY signature that is the whole of
// it today: the ID is RESERVED, not dispatched on. The decoder hard-rejects
// any primary `sig_algorithm` other than `ALG_DILITHIUM3` (`elara-record`'s
// `record.rs`, "only 0x.. Dilithium3 is currently accepted"), and every
// verify path calls `dilithium3_verify` directly — there is no
// `match sig_algorithm` anywhere in non-test code.
//
// Corrected 2026-09-07 (audit R2/crypto-sig/CS-1): this comment used to say
// "old records remain valid under their original algorithms". That is NOT a
// property of the primary signature — a record signed under a retired
// primary algorithm is rejected at decode, not grandfathered.
//
// The SECOND leg is the one migration built (2026-09-26, FIPS 205): the
// record's wire version fixes its algorithm — `ALG_SPHINCS_SHA2_192F` up to
// v7, `ALG_SLH_DSA_SHA2_192F` from v8 (`elara_record::pqc::
// record_second_leg_algorithm`) — so old legs stay valid at their own
// version, and the decoder and `verify_second_leg` refuse a byte from the
// other era. The byte never picks a verifier on its own.

/// Signature algorithm IDs — canonical in `elara_record::pqc` (record wire
/// bytes carry them): Dilithium3 / ML-DSA-65 (FIPS 204) primary;
/// SPHINCS+-SHA2-192f secondary up to wire version 7 (SHA-256 throughout, so
/// not FIPS 205), SLH-DSA-SHA2-192f (FIPS 205) secondary from wire version 8.
pub use elara_record::pqc::{ALG_DILITHIUM3, ALG_SLH_DSA_SHA2_192F, ALG_SPHINCS_SHA2_192F};

/// CRYSTALS-Kyber768 / ML-KEM (FIPS 203) — key encapsulation.
pub const ALG_KYBER768: u8 = 0x03;

/// Look up algorithm name from ID.
pub fn algorithm_name(id: u8) -> &'static str {
    match id {
        ALG_DILITHIUM3 => "ML-DSA-65",
        ALG_SPHINCS_SHA2_192F => "SPHINCS+-SHA2-192f",
        ALG_SLH_DSA_SHA2_192F => "SLH-DSA-SHA2-192f",
        ALG_KYBER768 => "ML-KEM-768",
        _ => "unknown",
    }
}
