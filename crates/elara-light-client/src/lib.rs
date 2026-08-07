//! Stateless, wasm-portable **light-client verification** for the Elara
//! Protocol.
//!
//! A light client never replays the chain. It pins a small amount of trusted
//! data out of band — a witness-signed epoch seal, or an anchor pubkey set —
//! and then checks individual proofs against it with pure functions that do no
//! I/O, allocate almost nothing, and run unchanged in a `wasm32` browser build
//! or any other no-tokio environment.
//!
//! This crate is the **deterministic core** of that flow:
//!
//! * [`verify_proof`] folds a compressed account-SMT inclusion proof back to a
//!   root. The leaf's position is the full `SHA3-256(account_id)` (256-bit), and
//!   the proof carries only the non-empty siblings (`≈ log₂(N)`) plus a 256-bit
//!   presence bitmap — collision-safe at billions of accounts and *smaller* on
//!   the wire than a fixed-depth proof.
//! * [`verify_exclusion_proof`] proves an account is **absent** (folds an empty
//!   leaf to the root) — a sound cryptographic non-membership proof, not a
//!   trust-the-server assertion.
//! * [`verify_account_proof_against_header`] /
//!   [`verify_account_non_membership_against_header`] bind those proofs to the
//!   `account_smt_root` a trusted epoch header signs — connecting "this is (not)
//!   the state" to "the network sealed this state".
//! * [`verify_state_delta_seal_binding`] checks that a fetched state-delta is
//!   bound to the exact seal (epoch + root) the caller already trusts, so a
//!   server cannot serve a delta from a different chain head.
//!
//! The wire types ([`LiteAccountStateProof`], [`LiteEpochHeader`],
//! [`LiteStateDeltaBinding`]) deserialize from either the REST JSON shape
//! (`[u8; 32]` as 64-char hex) or the in-process Rust→JSON shape (byte arrays),
//! so a caller can feed a raw endpoint payload straight in.
//!
//! # Scope
//!
//! Signature verification (Dilithium3 over a fetched seal record) stays in the
//! [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh) node, which
//! owns the `ValidationRecord` wire format. This crate covers the
//! storage-free, signature-free half of the trust chain — the part a phone or
//! browser must run locally. The hashing is pinned to SHA3-256 at the same
//! `sha3` minor the node resolves, so a proof the node produces folds
//! byte-identically here.
//!
//! ```
//! use elara_light_client::{LiteAccountStateProof, verify_proof};
//!
//! // A proof fetched from `/proof/account/{id}` deserializes straight from the
//! // endpoint's JSON; `verify_proof` folds it to a root with no store. The
//! // compressed proof carries a `present` bitmap (hex) + only non-empty
//! // `siblings` (hex), so a lone-account proof has an empty sibling list.
//! let json = r#"{ "identity": "ab", "state_hash": "cd", "root": "ef",
//!                 "present": "00", "siblings": [] }"#;
//! let parsed: Result<LiteAccountStateProof, _> = serde_json::from_str(json);
//! if let Ok(p) = parsed {
//!     let _ok: bool = verify_proof(&p);
//! }
//! ```

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// SHA3-256 of `data`. Inlined here (rather than depending on the node's
/// `crypto::hash`) so the crate carries no node dependency; pinned to the same
/// `sha3` minor as the node so folds stay byte-identical.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Wire-format helper: REST endpoints emit `[u8; 32]` fields as 64-char hex
/// strings (see the node's `compute_account_proof`). The in-tree storage side
/// serializes the same fields as JSON byte arrays. This module accepts EITHER
/// form on deserialize, and always emits hex on serialize — so the lite
/// verifier round-trips both the live wire shape and the in-process Rust→JSON
/// shape.
mod hex_or_bytes {
    use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("64-char hex string or 32-element byte array")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<[u8; 32], E> {
                let v = hex::decode(s).map_err(de::Error::custom)?;
                if v.len() != 32 {
                    return Err(de::Error::invalid_length(v.len(), &self));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                Ok(a)
            }
            fn visit_borrowed_str<E: de::Error>(self, s: &'de str) -> Result<[u8; 32], E> {
                self.visit_str(s)
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<[u8; 32], E> {
                self.visit_str(&s)
            }
            fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<[u8; 32], E> {
                if b.len() != 32 {
                    return Err(de::Error::invalid_length(b.len(), &self));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                Ok(a)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 32], A::Error> {
                let mut a = [0u8; 32];
                for slot in a.iter_mut() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(33, &self));
                }
                Ok(a)
            }
            fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<[u8; 32], A::Error> {
                Err(de::Error::custom("expected hex string or byte array, got map"))
            }
        }
        d.deserialize_any(V)
    }
}

mod hex_or_bytes_opt {
    use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::ser::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer>(b: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Option<[u8; 32]>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("null, 64-char hex string, or 32-element byte array")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                super::hex_or_bytes::deserialize(d).map(Some)
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let v = hex::decode(s).map_err(de::Error::custom)?;
                if v.len() != 32 {
                    return Err(de::Error::invalid_length(v.len(), &self));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                Ok(Some(a))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut a = [0u8; 32];
                for slot in a.iter_mut() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                }
                // Reject an over-length byte array (mirrors the non-optional
                // `hex_or_bytes` variant) — a 33+-element array is malformed,
                // not silently truncated to its first 32 bytes.
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(33, &self));
                }
                Ok(Some(a))
            }
            fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
                Err(de::Error::custom("expected null/hex/bytes, got map"))
            }
        }
        d.deserialize_option(V)
    }
}

/// Wire-format helper for `Vec<[u8; 32]>`: emits an array of 64-char hex
/// strings on serialize; accepts an array of either hex strings or 32-element
/// byte arrays on deserialize (reusing the single-hash [`hex_or_bytes`] logic
/// per element). Keeps compressed-proof sibling lists in the same hex convention
/// as every other 32-byte field.
mod hex_or_bytes_vec {
    use serde::de::{Deserializer, SeqAccess, Visitor};
    use serde::ser::{SerializeSeq, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for h in v {
            seq.serialize_element(&hex::encode(h))?;
        }
        seq.end()
    }

    struct Elem([u8; 32]);
    impl<'de> serde::Deserialize<'de> for Elem {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Elem(super::hex_or_bytes::deserialize(d)?))
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<[u8; 32]>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("array of 32-byte hashes (hex strings or byte arrays)")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                // Cap at MAX_DEPTH (256): a compressed proof carries at most one
                // sibling per tree level, so a longer list is malformed. Without
                // this a hostile blob would grow `out` unboundedly before the
                // fold's consistency check ever runs.
                let cap = seq.size_hint().unwrap_or(0).min(super::MAX_DEPTH as usize);
                let mut out = Vec::with_capacity(cap);
                while let Some(Elem(h)) = seq.next_element::<Elem>()? {
                    if out.len() >= super::MAX_DEPTH as usize {
                        return Err(serde::de::Error::custom(
                            "sibling list exceeds MAX_DEPTH",
                        ));
                    }
                    out.push(h);
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V)
    }
}

/// Maximum tree depth — must match the node's account-SMT `MAX_DEPTH`. The path
/// is the full 256-bit `SHA3-256(account_id)`, so the tree is 256 levels deep.
/// Proofs are compressed (a presence bitmap + only non-empty siblings), so the
/// sibling *count* is `≈ log₂(N)`, not `MAX_DEPTH`. `u16` because 256 > u8::MAX.
pub const MAX_DEPTH: u16 = 256;

/// Domain tag for leaf preimages: `leaf = SHA3-256([LEAF_TAG] ‖ key ‖ value)`.
/// Binds the account id into the leaf and separates leaves from interior nodes.
const LEAF_TAG: u8 = 0x00;
/// Domain tag for interior-node preimages: `node = SHA3-256([NODE_TAG] ‖ L ‖ R)`.
const NODE_TAG: u8 = 0x01;

/// Empty-subtree sentinel — SHA3-256 of the empty string.
const EMPTY_HASH: [u8; 32] = [
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
];

/// The empty-subtree sentinel hash (`SHA3-256("")`).
pub fn empty_hash() -> [u8; 32] { EMPTY_HASH }

/// Leaf hash — binds the key under [`LEAF_TAG`]. Identical to the node/crate
/// construction so a node-produced proof folds byte-for-byte here.
fn leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = LEAF_TAG;
    buf[1..33].copy_from_slice(key);
    buf[33..65].copy_from_slice(value);
    sha3_256(&buf)
}

/// Interior-node hash — combines children under [`NODE_TAG`].
fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha3_256(&buf)
}

/// The MSB-first bit at position `index` (`< 256`) of a 256-bit value — used for
/// both paths and presence bitmaps.
fn bit_get(bytes: &[u8; 32], index: u16) -> bool {
    let byte = (index / 8) as usize;
    let shift = 7 - (index % 8) as u8;
    (bytes[byte] >> shift) & 1 == 1
}

/// Fold a compressed sibling set from `leaf` at position `path` up to a root.
/// Mirrors `elara_smt::fold` exactly (incl. the both-empty → EMPTY_HASH collapse,
/// required for exclusion proofs). `None` if the present/siblings shape is
/// inconsistent.
fn fold(
    path: &[u8; 32],
    leaf: [u8; 32],
    present: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let mut current = leaf;
    let mut idx = 0usize;
    let mut parent_depth = MAX_DEPTH;
    while parent_depth > 0 {
        parent_depth -= 1;
        let sibling = if bit_get(present, parent_depth) {
            let s = *siblings.get(idx)?;
            idx += 1;
            s
        } else {
            EMPTY_HASH
        };
        let we_are_right = bit_get(path, parent_depth);
        let (left, right) = if we_are_right {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = if left == EMPTY_HASH && right == EMPTY_HASH {
            EMPTY_HASH
        } else {
            interior_hash(&left, &right)
        };
    }
    if idx != siblings.len() {
        return None;
    }
    Some(current)
}

/// Compressed inclusion proof — wire-compatible with the node's
/// `AccountStateProof`. `present` is a 256-bit MSB-first bitmap (by parent
/// depth): bit set = that level's sibling is non-empty and appears in
/// `siblings`; clear = empty (omitted). `siblings` lists only the non-empty
/// siblings, leaf-parent → root order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteAccountStateProof {
    /// Wire endpoint emits this as `"identity"`; storage-side serde uses
    /// `"account_id"`. Accept both — the caller verifies it matches the
    /// expected identity regardless.
    #[serde(with = "hex_or_bytes", alias = "identity")]
    pub account_id: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub state_hash: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub root: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub present: [u8; 32],
    #[serde(with = "hex_or_bytes_vec")]
    pub siblings: Vec<[u8; 32]>,
}

/// Compressed exclusion (non-membership) proof — wire-compatible with the node's
/// `SmtExclusionProof`. The leaf slot `SHA3-256(account_id)` is empty; folding
/// `EMPTY_HASH` up the siblings reproduces `root`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteExclusionProof {
    #[serde(with = "hex_or_bytes", alias = "identity")]
    pub account_id: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub root: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub present: [u8; 32],
    #[serde(with = "hex_or_bytes_vec")]
    pub siblings: Vec<[u8; 32]>,
}

/// Compact epoch header — wire-compatible with the node's `EpochHeader`.
/// Uses `String` for `zone` so it deserializes without pulling in the node's
/// `ZoneId` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteEpochHeader {
    pub zone: String,
    pub epoch_number: u64,
    #[serde(with = "hex_or_bytes")]
    pub merkle_root: [u8; 32],
    #[serde(with = "hex_or_bytes")]
    pub previous_seal_hash: [u8; 32],
    pub record_count: u64,
    pub start: f64,
    pub end: f64,
    #[serde(default, with = "hex_or_bytes_opt")]
    pub account_smt_root: Option<[u8; 32]>,
    #[serde(default, with = "hex_or_bytes_opt")]
    pub seal_record_hash: Option<[u8; 32]>,
}

/// The 256-bit tree path of an account: the full `SHA3-256(account_id)`. A
/// position collision now requires a true SHA3-256 collision (≈2¹²⁸), not a
/// 64-bit birthday collision (≈2³²).
pub fn account_path(account_id: &[u8; 32]) -> [u8; 32] {
    sha3_256(account_id)
}

/// Stateless inclusion verification. Returns true iff the compressed siblings
/// reconstruct `proof.root` from `leaf_hash(account_id, state_hash)` along the
/// path `SHA3-256(account_id)`.
pub fn verify_proof(proof: &LiteAccountStateProof) -> bool {
    let path = account_path(&proof.account_id);
    let leaf = leaf_hash(&proof.account_id, &proof.state_hash);
    match fold(&path, leaf, &proof.present, &proof.siblings) {
        Some(root) => root == proof.root,
        None => false,
    }
}

/// Stateless exclusion (non-membership) verification. Returns true iff the
/// compressed siblings reconstruct `proof.root` from an empty leaf at position
/// `SHA3-256(account_id)`.
pub fn verify_exclusion_proof(proof: &LiteExclusionProof) -> bool {
    let path = account_path(&proof.account_id);
    match fold(&path, EMPTY_HASH, &proof.present, &proof.siblings) {
        Some(root) => root == proof.root,
        None => false,
    }
}

/// Two-level binding: header signs `account_smt_root`; proof reconstructs it
/// from a leaf. If both pin the same root and the leaf path validates, the
/// caller can trust `proof.state_hash` as the account's state-as-of-seal.
///
/// # Security
/// This checks ONLY the Merkle-fold binding between the proof and
/// `header.account_smt_root`. It does **not** verify any signature. The caller
/// MUST independently verify the epoch header's Dilithium3 anchor signature
/// before trusting the result — otherwise an attacker supplies both a forged
/// header and a proof that folds to its root, and this returns `true`.
pub fn verify_account_proof_against_header(
    proof: &LiteAccountStateProof,
    header: &LiteEpochHeader,
) -> bool {
    let signed_root = match header.account_smt_root {
        Some(r) => r,
        None => return false, // pre-Gap-1 header — cannot bind
    };
    if proof.root != signed_root {
        return false;
    }
    verify_proof(proof)
}

/// Two-level binding for **non-membership**: the exclusion proof must fold to the
/// `account_smt_root` the trusted header signs. Replaces the old "trust the
/// server's claimed root" negative path — a Byzantine server can no longer
/// assert an account is absent without a fold that reaches the signed root.
///
/// # Security
/// As with [`verify_account_proof_against_header`], this checks only the
/// Merkle binding to `header.account_smt_root` — the caller MUST verify the
/// header's Dilithium3 anchor signature first; this function verifies no
/// signature.
pub fn verify_account_non_membership_against_header(
    proof: &LiteExclusionProof,
    header: &LiteEpochHeader,
) -> bool {
    let signed_root = match header.account_smt_root {
        Some(r) => r,
        None => return false,
    };
    if proof.root != signed_root {
        return false;
    }
    verify_exclusion_proof(proof)
}

// ─── State-delta seal-binding verifier ──────────────────────────────────────
//
// Light clients fetching `/snapshot/state-delta?since={epoch}` need to know
// the delta is bound to a chain head they already trust. The on-disk state
// delta carries `latest_sealed_account_epoch` + `latest_sealed_account_smt_root`
// (both inside the Dilithium3-signed checksum so a server cannot drop them).
// This crate exposes the binding-only sub-shape and a pure-logic verifier so
// wasm accounts can run the check without pulling the full runtime in.
//
// Trust chain end-to-end:
//   1. Client trusts a witness-signed seal (fetched out of band).
//      Knows: seal.epoch (T), seal.account_smt_root (R).
//   2. Client fetches state-delta. Deserializes binding fields into
//      `LiteStateDeltaBinding`.
//   3. Calls `verify_state_delta_seal_binding(&binding, T, &R)`.
//      - Epoch and root must both match. Mismatch on either axis means the
//        server is signing a different chain head than the one the client
//        trusts — refuse the delta.
//   4. (Out of scope here) Client verifies delta signature, applies it,
//      recomputes its local SMT root, compares to delta's `account_state_root`.
//
// `None` binding (legacy chain) returns a distinct `NoBinding` variant so the
// caller can decide policy: a strict account refuses, a permissive one falls
// through to signer-trust mode. The verifier itself does not pick that policy.

/// Wire-compatible sub-shape of the node's `StateDelta` carrying only the
/// fields needed for seal-binding verification. Deserializes from the same JSON
/// the server emits — extra fields are ignored, so accounts can pass the raw
/// delta payload without round-tripping through the full struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteStateDeltaBinding {
    /// Latest server-observed epoch carrying a sealed-account binding.
    /// `None` until the first binding-capable seal registers on this chain.
    #[serde(default)]
    pub latest_sealed_account_epoch: Option<u64>,
    /// Hex-encoded SMT root of that binding. Witness-signed in the seal
    /// record; the client compares this against the seal it independently
    /// trusts. `None` mirrors `latest_sealed_account_epoch`.
    #[serde(default)]
    pub latest_sealed_account_smt_root: Option<String>,
}

/// Errors returned by [`verify_state_delta_seal_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealBindingError {
    /// Delta carries no sealed-account binding — server is too old or no
    /// binding-capable seal has been emitted on this chain yet. Distinct
    /// variant so the caller can decide whether to fall back to signer-trust
    /// mode or refuse outright.
    NoBinding,
    /// Server populated exactly one of the two binding fields. Indicates a
    /// server bug — refused out of caution since the caller cannot
    /// distinguish "missing field" from "deliberately spoofed null".
    PartialBinding,
    /// Binding epoch differs from the seal the caller trusts. Caller inspects
    /// which side is larger to decide: smaller → stale-replay server (refuse
    /// delta); larger → fetch a newer seal first.
    EpochMismatch {
        delta_epoch: u64,
        trusted_epoch: u64,
    },
    /// Binding epoch matches but root does not — server is signing a different
    /// chain head than the one the caller trusts. Always refuse.
    RootMismatch {
        delta_root_hex: String,
        trusted_root_hex: String,
    },
    /// Binding root field is not valid 64-char hex.
    InvalidRootHex,
}

impl core::fmt::Display for SealBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoBinding => f.write_str("state-delta carries no Gap-1 sealed-account binding"),
            Self::PartialBinding => f.write_str(
                "state-delta binding has only one of (epoch, root) populated — server bug",
            ),
            Self::EpochMismatch { delta_epoch, trusted_epoch } => write!(
                f,
                "state-delta binding epoch {delta_epoch} != trusted seal epoch {trusted_epoch}"
            ),
            Self::RootMismatch { delta_root_hex, trusted_root_hex } => write!(
                f,
                "state-delta binding root {delta_root_hex} != trusted seal root {trusted_root_hex}"
            ),
            Self::InvalidRootHex => f.write_str("state-delta binding root is not valid hex"),
        }
    }
}

impl std::error::Error for SealBindingError {}

/// Pure-logic verifier: confirm a state-delta binds to the seal the caller
/// already trusts. Returns `Ok(())` only if BOTH epoch and root match.
///
/// Inputs:
///   - `binding`: extracted from the `/snapshot/state-delta` payload.
///   - `trusted_seal_epoch`: epoch number of the witness-signed seal the
///     caller pinned.
///   - `trusted_seal_root`: 32-byte SMT root from that same seal (raw, not
///     hex). Caller decoded it earlier from the seal record.
///
/// No I/O, no allocation beyond the error path, wasm-portable. Cryptographic
/// strength is the witness signature on the seal (caller's responsibility)
/// chained through the Dilithium3 signature on the delta (caller verifies
/// separately) — this function does the binding equality check that connects
/// the two.
pub fn verify_state_delta_seal_binding(
    binding: &LiteStateDeltaBinding,
    trusted_seal_epoch: u64,
    trusted_seal_root: &[u8; 32],
) -> Result<(), SealBindingError> {
    let (delta_epoch, delta_root_hex) = match (
        binding.latest_sealed_account_epoch,
        binding.latest_sealed_account_smt_root.as_deref(),
    ) {
        (None, None) => return Err(SealBindingError::NoBinding),
        (Some(_), None) | (None, Some(_)) => return Err(SealBindingError::PartialBinding),
        (Some(e), Some(r)) => (e, r),
    };

    if delta_epoch != trusted_seal_epoch {
        return Err(SealBindingError::EpochMismatch {
            delta_epoch,
            trusted_epoch: trusted_seal_epoch,
        });
    }

    let decoded = hex::decode(delta_root_hex).map_err(|_| SealBindingError::InvalidRootHex)?;
    if decoded.len() != 32 {
        return Err(SealBindingError::InvalidRootHex);
    }
    let mut delta_root = [0u8; 32];
    delta_root.copy_from_slice(&decoded);

    if delta_root != *trusted_seal_root {
        return Err(SealBindingError::RootMismatch {
            delta_root_hex: delta_root_hex.to_string(),
            trusted_root_hex: hex::encode(trusted_seal_root),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_matches_sha3_of_empty_string() {
        assert_eq!(EMPTY_HASH, sha3_256(&[]));
    }

    /// Absolute-value KAT: pins `account_path` to a fixed output so an
    /// accidental `sha3` swap or path-derivation change is caught here, not by
    /// a silent proof rejection at a account. Top 8 bytes (big-endian) of
    /// `SHA3-256` of thirty-two `0x2a` bytes.
    #[test]
    fn account_path_absolute_value_pin() {
        // Path is now the full SHA3-256(account_id); its first 8 bytes still
        // match the historical big-endian KAT prefix.
        let p = account_path(&[42u8; 32]);
        assert_eq!(p, sha3_256(&[42u8; 32]));
        assert_eq!(&p[..8], &[0xd1, 0x47, 0x84, 0xc1, 0x43, 0x0c, 0x8d, 0x44]);
    }

    #[test]
    fn account_path_is_deterministic() {
        let id = [42u8; 32];
        assert_eq!(account_path(&id), account_path(&id));
    }

    #[test]
    fn account_path_distinct_inputs_distinct_paths() {
        let zeros = account_path(&[0u8; 32]);
        let ones = account_path(&[0xffu8; 32]);
        let mixed = account_path(&[0x55u8; 32]);
        assert_ne!(zeros, ones);
        assert_ne!(zeros, mixed);
        assert_ne!(ones, mixed);
    }

    #[test]
    fn verify_proof_rejects_malformed_compressed_shape() {
        // present-bit set but no sibling provided → fold returns None → reject.
        let mut present = [0u8; 32];
        present[0] = 0x80; // bit 0 (parent_depth 0) set
        let p = LiteAccountStateProof {
            account_id: [0u8; 32],
            state_hash: [0u8; 32],
            root: [0u8; 32],
            present,
            siblings: vec![], // claims a sibling but provides none
        };
        assert!(!verify_proof(&p));
        // extra sibling with empty bitmap → leftover → reject.
        let q = LiteAccountStateProof {
            account_id: [0u8; 32],
            state_hash: [0u8; 32],
            root: [0u8; 32],
            present: [0u8; 32],
            siblings: vec![[7u8; 32]],
        };
        assert!(!verify_proof(&q));
    }

    /// Live wire-format check: REST `/epochs/headers` emits all `[u8; 32]`
    /// fields as 64-char hex strings, and `account_smt_root` as JSON `null`
    /// for pre-binding seals. Must deserialize without error.
    #[test]
    fn lite_header_parses_live_wire_hex() {
        let wire = r#"{
            "account_smt_root": null,
            "end": 1774978839.5091777,
            "epoch_number": 40,
            "merkle_root": "0000000000000000000000000000000000000000000000000000000000000000",
            "previous_seal_hash": "2e2dc23e03fb8d4cdc2804cfcde6b1b886f7cf9a18dbd7e531849743423ffeab",
            "record_count": 0,
            "seal_id": "019d44fb-b5f0-7b73-a31e-d7fbeb692de2",
            "seal_record_hash": "107d0796069ae1f689dc97b95aabd075bb578c7bc10fb22634b86a1308ca52cb",
            "start": 1774978539.5091777,
            "zone": "3"
        }"#;
        let h: LiteEpochHeader = serde_json::from_str(wire).unwrap();
        assert_eq!(h.zone, "3");
        assert_eq!(h.epoch_number, 40);
        assert_eq!(h.account_smt_root, None);
        assert!(h.seal_record_hash.is_some());
        assert_eq!(h.previous_seal_hash[0], 0x2e);
        assert_eq!(h.previous_seal_hash[1], 0x2d);
    }

    /// Live wire-format check: REST `/proof/account/{identity}` emits the
    /// account id as `"identity"` (not `"account_id"`), root/state_hash/
    /// sibling.hash as hex strings. Must deserialize cleanly via the
    /// `alias = "identity"` + `hex_or_bytes` handlers.
    #[test]
    fn lite_proof_parses_live_wire_hex() {
        // Compressed wire shape: `present` is a 64-char hex bitmap, `siblings` an
        // array of 64-char hex strings (only the non-empty ones).
        let mut s0 = [0u8; 32];
        s0[0] = 0xaa;
        let mut s1 = [0u8; 32];
        s1[0] = 0xbb;
        let mut present = [0u8; 32];
        present[0] = 0xC0; // bits 0 and 1 set → two siblings
        let wire = format!(
            r#"{{
                "identity": "abababababababababababababababababababababababababababababababab",
                "exists": true,
                "root": "1111111111111111111111111111111111111111111111111111111111111111",
                "state_hash": "2222222222222222222222222222222222222222222222222222222222222222",
                "present": "{}",
                "siblings": ["{}", "{}"],
                "bound_to_seal": false,
                "latest_sealed_account": null
            }}"#,
            hex::encode(present),
            hex::encode(s0),
            hex::encode(s1),
        );
        let p: LiteAccountStateProof = serde_json::from_str(&wire).unwrap();
        assert_eq!(p.account_id[0], 0xab);
        assert_eq!(p.account_id[31], 0xab);
        assert_eq!(p.root[0], 0x11);
        assert_eq!(p.state_hash[0], 0x22);
        assert_eq!(p.present[0], 0xC0);
        assert_eq!(p.siblings.len(), 2);
        assert_eq!(p.siblings[0][0], 0xaa);
        assert_eq!(p.siblings[1][0], 0xbb);
    }

    // ─── seal-binding verifier tests ────────────────────────────────────

    fn root_with_first_byte(b: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = b;
        r
    }

    #[test]
    fn seal_binding_accepts_matching_pair() {
        let trusted_root = root_with_first_byte(0xab);
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(100),
            latest_sealed_account_smt_root: Some(hex::encode(trusted_root)),
        };
        assert!(verify_state_delta_seal_binding(&binding, 100, &trusted_root).is_ok());
    }

    #[test]
    fn seal_binding_rejects_no_binding() {
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &[0u8; 32]),
            Err(SealBindingError::NoBinding)
        );
    }

    #[test]
    fn seal_binding_rejects_partial_epoch_only() {
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(100),
            latest_sealed_account_smt_root: None,
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &[0u8; 32]),
            Err(SealBindingError::PartialBinding)
        );
    }

    #[test]
    fn seal_binding_rejects_partial_root_only() {
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: Some(hex::encode([0u8; 32])),
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &[0u8; 32]),
            Err(SealBindingError::PartialBinding)
        );
    }

    #[test]
    fn seal_binding_rejects_stale_epoch() {
        let trusted_root = root_with_first_byte(0xab);
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(90),
            latest_sealed_account_smt_root: Some(hex::encode(trusted_root)),
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &trusted_root),
            Err(SealBindingError::EpochMismatch {
                delta_epoch: 90,
                trusted_epoch: 100,
            })
        );
    }

    #[test]
    fn seal_binding_rejects_newer_epoch() {
        let trusted_root = root_with_first_byte(0xab);
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(110),
            latest_sealed_account_smt_root: Some(hex::encode(trusted_root)),
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &trusted_root),
            Err(SealBindingError::EpochMismatch {
                delta_epoch: 110,
                trusted_epoch: 100,
            })
        );
    }

    #[test]
    fn seal_binding_rejects_root_mismatch() {
        let trusted_root = root_with_first_byte(0xab);
        let delta_root = root_with_first_byte(0xcd);
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(100),
            latest_sealed_account_smt_root: Some(hex::encode(delta_root)),
        };
        match verify_state_delta_seal_binding(&binding, 100, &trusted_root) {
            Err(SealBindingError::RootMismatch { .. }) => {}
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn seal_binding_rejects_invalid_hex() {
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(100),
            latest_sealed_account_smt_root: Some("not-hex-zzz".to_string()),
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &[0u8; 32]),
            Err(SealBindingError::InvalidRootHex)
        );
    }

    #[test]
    fn seal_binding_rejects_wrong_length_hex() {
        let binding = LiteStateDeltaBinding {
            latest_sealed_account_epoch: Some(100),
            latest_sealed_account_smt_root: Some(hex::encode([0u8; 16])), // 16 bytes, not 32
        };
        assert_eq!(
            verify_state_delta_seal_binding(&binding, 100, &[0u8; 32]),
            Err(SealBindingError::InvalidRootHex)
        );
    }

    #[test]
    fn seal_binding_deserializes_from_full_state_delta_json() {
        // The raw `/snapshot/state-delta` payload carries many more fields;
        // `LiteStateDeltaBinding` must pick out only the two it needs.
        let trusted_root = root_with_first_byte(0xee);
        let wire = format!(
            r#"{{
                "since_epoch": 12,
                "records": [],
                "latest_sealed_account_epoch": 42,
                "latest_sealed_account_smt_root": "{}",
                "account_state_root": "ff",
                "signature": "deadbeef"
            }}"#,
            hex::encode(trusted_root)
        );
        let binding: LiteStateDeltaBinding = serde_json::from_str(&wire).unwrap();
        assert!(verify_state_delta_seal_binding(&binding, 42, &trusted_root).is_ok());
    }

    #[test]
    fn batch_b_empty_hash_wrapper_matches_sha3_of_empty_input_and_not_zero_byte() {
        assert_eq!(empty_hash(), sha3_256(&[]));
        // A single zero byte hashes to something different — guards against an
        // accidental `sha3_256(&[0])` definition of "empty".
        assert_ne!(empty_hash(), sha3_256(&[0u8]));
    }

    /// KAT: independently fold a compressed proof (all-empty siblings, i.e. a
    /// lone-account tree) to a root and confirm `verify_proof` agrees. Catches
    /// drift in the fold order, the left/right combine, the both-empty collapse,
    /// the leaf-hash binding, or the path-bit derivation.
    #[test]
    fn batch_b_verify_proof_accepts_manually_folded_compressed_root() {
        let account_id = [7u8; 32];
        let state_hash = [9u8; 32];
        let path = account_path(&account_id);

        // Independent fold mirroring the verifier: lone account → every sibling
        // empty, so present is all-zero and siblings is empty. current starts at
        // the identity-bound leaf and is never empty, so no collapse fires.
        let mut current = leaf_hash(&account_id, &state_hash);
        let mut pd = MAX_DEPTH;
        while pd > 0 {
            pd -= 1;
            let we_are_right = bit_get(&path, pd);
            let (l, r) = if we_are_right {
                (EMPTY_HASH, current)
            } else {
                (current, EMPTY_HASH)
            };
            current = interior_hash(&l, &r);
        }

        let proof = LiteAccountStateProof {
            account_id,
            state_hash,
            root: current,
            present: [0u8; 32],
            siblings: vec![],
        };
        assert!(verify_proof(&proof));

        // Flip the root → must reject.
        let mut bad = proof.clone();
        bad.root[0] ^= 0x01;
        assert!(!verify_proof(&bad));

        // Swap the identity (keep state + siblings) → leaf rebinds, path shifts
        // → must reject. Pins the identity-binding property.
        let mut wrong_id = proof.clone();
        wrong_id.account_id = [8u8; 32];
        assert!(!verify_proof(&wrong_id));
    }

    /// Exclusion proof for a lone-account tree: an absent key's empty leaf folds
    /// to a different root than the present leaf, and `verify_exclusion_proof`
    /// agrees with an independent fold.
    #[test]
    fn batch_b_verify_exclusion_proof_folds_empty_leaf() {
        let absent = [5u8; 32];
        let path = account_path(&absent);
        // Independent fold from EMPTY with all-empty siblings → the empty-tree
        // root (a tree with no accounts). present all-zero, siblings empty.
        let mut current = EMPTY_HASH;
        let mut pd = MAX_DEPTH;
        while pd > 0 {
            pd -= 1;
            let we_are_right = bit_get(&path, pd);
            let (l, r) = if we_are_right {
                (EMPTY_HASH, current)
            } else {
                (current, EMPTY_HASH)
            };
            // both-empty collapse → stays EMPTY_HASH all the way up.
            current = if l == EMPTY_HASH && r == EMPTY_HASH {
                EMPTY_HASH
            } else {
                interior_hash(&l, &r)
            };
        }
        assert_eq!(current, EMPTY_HASH); // empty tree
        let xp = LiteExclusionProof {
            account_id: absent,
            root: current,
            present: [0u8; 32],
            siblings: vec![],
        };
        assert!(verify_exclusion_proof(&xp));
        let mut bad = xp.clone();
        bad.root[0] ^= 0x01;
        assert!(!verify_exclusion_proof(&bad));
    }

    #[test]
    fn error_display_seal_binding_pins_distinguishing_keywords_per_variant() {
        assert!(SealBindingError::NoBinding.to_string().contains("no Gap-1"));
        assert!(SealBindingError::PartialBinding
            .to_string()
            .contains("server bug"));
        let em = SealBindingError::EpochMismatch {
            delta_epoch: 5,
            trusted_epoch: 10,
        }
        .to_string();
        assert!(em.contains('5'), "EpochMismatch must show delta_epoch: {em}");
        assert!(em.contains("10"), "EpochMismatch must show trusted_epoch: {em}");
        assert!(em.contains("epoch"), "EpochMismatch keyword: {em}");
        let rm = SealBindingError::RootMismatch {
            delta_root_hex: "aa".repeat(32),
            trusted_root_hex: "bb".repeat(32),
        }
        .to_string();
        assert!(rm.contains(&"aa".repeat(32)), "RootMismatch shows delta hex");
        assert!(rm.contains(&"bb".repeat(32)), "RootMismatch shows trusted hex");
        assert!(SealBindingError::InvalidRootHex
            .to_string()
            .contains("not valid hex"));
    }

    #[test]
    fn siblings_list_over_max_depth_is_rejected() {
        // A compressed proof carries at most one sibling per tree level, so a
        // list longer than MAX_DEPTH (256) is malformed. The bounded visitor
        // must reject it rather than allocate unboundedly from the wire length.
        let h = "00".repeat(32);
        let id = "ab".repeat(32);
        let make = |n: usize| {
            let sibs = vec![format!("\"{h}\""); n].join(",");
            format!(
                r#"{{"identity":"{id}","exists":true,"root":"{h}","state_hash":"{h}","present":"{h}","siblings":[{sibs}],"bound_to_seal":false,"latest_sealed_account":null}}"#
            )
        };
        assert!(
            serde_json::from_str::<LiteAccountStateProof>(&make(MAX_DEPTH as usize + 1)).is_err(),
            "siblings list longer than MAX_DEPTH must be rejected"
        );
        assert!(
            serde_json::from_str::<LiteAccountStateProof>(&make(MAX_DEPTH as usize)).is_ok(),
            "siblings list exactly MAX_DEPTH long must still parse"
        );
    }
}
