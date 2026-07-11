//! # elara-record
//!
//! The canonical Elara Protocol **data layer** — `ValidationRecord`, the byte-exact
//! post-quantum wire codec, receipt types, the hierarchical `ZoneId`, and the verify-side
//! crypto primitives — shared by the AGPL Elara node and the permissive `elara-verify`
//! receipt verifier so both speak **one** wire format with zero drift.
//!
//! Pure-Rust and `wasm32`-portable: no node/storage/network/tokio dependency. Extracted
//! from the Elara Protocol node — see internal design notes.
//!
//! Modules are migrated incrementally (crypto → wire → record → receipt); the node
//! re-exports each via `pub use elara_record::…` so its call sites are unchanged.

/// SHA3-256 hashing (`sha3_256`, `sha3_256_hex`) — the record/seal preimage hash.
pub mod hash;

/// UUIDv7 generation (`uuid7`) — time-ordered record identifiers.
pub mod uuid7;

/// Receipt leg types (`ReceiptLegs`) — the portable receipt schema.
pub mod receipt;

/// Post-quantum signature **verification** primitives (verify-only; no signing).
pub mod pqc;

/// Byte-exact record wire codec (`encode_*`/`decode_*`, `WIRE_VERSION`, `MAGIC`).
pub mod wire;
pub mod record;
pub mod zone_id;
pub use zone_id::ZoneId;

use thiserror::Error;

/// Errors from record / wire / crypto operations in this crate.
///
/// The node maps these into its wider `ElaraError` via `impl From<RecordError> for
/// ElaraError`, preserving the variant + message text so existing
/// `matches!(err, ElaraError::Wire(..))` sites keep matching after extraction.
#[derive(Debug, Error)]
pub enum RecordError {
    /// Wire encode/decode failure (malformed bytes, length overflow, bad version…).
    #[error("{0}")]
    Wire(String),
    /// Cryptographic failure (signature verify error, malformed key/sig bytes…).
    #[error("{0}")]
    Crypto(String),
    /// JSON (de)serialization failure in metadata handling.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// I/O failure (byte-buffer writer).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, RecordError>;
