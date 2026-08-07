//! ML-KEM Key Encapsulation (Protocol §11.26, FIPS 203).
//!
//! Post-quantum key exchange for encrypted peer-to-peer communication.
//! Uses ML-KEM-768 (Kyber) via liboqs for establishing shared secrets
//! between nodes for gossip, sync, and admin traffic encryption.
//!
//! The implementation lives in the standalone `elara-pq-transport` crate
//! (MIT/Apache, Lane 3), re-exported here so the `crate::crypto::kem` path
//! and the hybrid handshake resolve unchanged. Errors are the crate-local
//! [`KemError`] rather than `ElaraError` — the handshake maps them at its
//! own seam.
//!
//! Spec references:
//!   @spec Protocol §4.2

pub use elara_pq_transport::kem::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keygen, KemEncapsulation, KemError,
    KemKeypair, MlKem768Sizes,
};
