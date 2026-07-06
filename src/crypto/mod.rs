//! Cryptographic primitives: PQC signatures, hashing, batch operations.

pub mod batch;
pub mod hash;
#[cfg(all(not(target_arch = "wasm32"), feature = "node"))]
pub mod kem;
pub mod pqc;
pub mod commitment;
pub mod vrf;
pub mod zk;

// ─── Algorithm Identifiers (Protocol §4.4 — Algorithm Agility) ─────────────
//
// Every signature specifies its algorithm ID so the protocol can migrate
// to new algorithms without structural changes. Old records remain valid
// under their original algorithms; new records use updated ones.

/// CRYSTALS-Dilithium3 / ML-DSA-65 (FIPS 204) — primary signature algorithm.
pub const ALG_DILITHIUM3: u8 = 0x01;

/// SPHINCS+-SHA2-192f / SLH-DSA (FIPS 205) — secondary hash-based signature.
pub const ALG_SPHINCS_SHA2_192F: u8 = 0x02;

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
