//! ValidationRecord — the atomic unit of the Elara Protocol.
//!
//! Byte-identical serialization with the Python Layer 1 implementation.

//!
//! Spec references:
//!   @spec Protocol §3.3.4
//!   @spec Protocol §5.2 (Classification Levels: Public/Private/Restricted/Sovereign)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::uuid7::uuid7;
use crate::wire::*;

/// Max parents per record (wire-format cap). Canonical home: the record decoder
/// bounds `num_parents` against this before allocating, and the `node-core`-gated
/// `network::ingest` re-exports it so post-decode validation enforces the identical
/// ceiling. Lives in the core wire module so the decoder need not depend on the
/// node stack (a bare default-feature build still bounds the allocation).
pub const MAX_PARENTS: usize = 256;

/// Get current timestamp as seconds since UNIX epoch.
/// Uses `js_sys::Date::now()` on wasm32, `SystemTime` on native.
pub fn now_timestamp() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() / 1000.0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
}

/// Classification levels from Protocol Whitepaper, Section 5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Classification {
    Public = 0,
    Private = 1,
    Restricted = 2,
    Sovereign = 3,
}

/// Observer-dependent projection of a ValidationRecord (Protocol §3.3.3).
/// C: V × Observer → View — different clearance levels see different fields.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectedRecord {
    pub id: String,
    pub classification: Classification,
    pub timestamp: f64,
    /// Only visible at Public or higher clearance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Only visible at Public clearance (full metadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// Only visible at Public or Restricted clearance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_hash: Option<String>,
    /// Confirmation level if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_level: Option<String>,
}

impl ValidationRecord {
    /// Project this record based on the observer's clearance level.
    /// Protocol §3.3.3: C(v, observer) projects based on cryptographic clearance.
    pub fn project(&self, observer_clearance: Classification) -> ProjectedRecord {
        let creator_hash = crate::crypto::hash::sha3_256_hex(&self.creator_public_key);
        match observer_clearance {
            Classification::Public => ProjectedRecord {
                id: self.id.clone(),
                classification: self.classification,
                timestamp: self.timestamp,
                content_hash: Some(hex::encode(&self.content_hash)),
                metadata: Some(self.metadata.clone()),
                creator_hash: Some(creator_hash),
                confirmation_level: None,
            },
            Classification::Private => ProjectedRecord {
                id: self.id.clone(),
                classification: self.classification,
                timestamp: self.timestamp,
                content_hash: Some(hex::encode(&self.content_hash)),
                metadata: None, // redacted
                creator_hash: Some(creator_hash),
                confirmation_level: None,
            },
            Classification::Restricted => ProjectedRecord {
                id: self.id.clone(),
                classification: self.classification,
                timestamp: self.timestamp,
                content_hash: None, // redacted
                metadata: None,
                creator_hash: Some(creator_hash),
                confirmation_level: None,
            },
            Classification::Sovereign => ProjectedRecord {
                id: self.id.clone(),
                classification: self.classification,
                timestamp: self.timestamp,
                content_hash: None,
                metadata: None,
                creator_hash: None, // fully redacted
                confirmation_level: None,
            },
        }
    }
}

impl Classification {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Public),
            1 => Ok(Self::Private),
            2 => Ok(Self::Restricted),
            3 => Ok(Self::Sovereign),
            _ => Err(ElaraError::Wire(format!(
                "invalid classification: {val}"
            ))),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Private => "PRIVATE",
            Self::Restricted => "RESTRICTED",
            Self::Sovereign => "SOVEREIGN",
        }
    }
}

/// A single validation record on the DAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub id: String,
    pub version: u16,
    pub content_hash: Vec<u8>,
    pub creator_public_key: Vec<u8>,
    pub timestamp: f64,
    pub parents: Vec<String>,
    pub classification: Classification,
    /// BTreeMap ensures sorted keys, matching Python's `sort_keys=True`.
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub signature: Option<Vec<u8>>,
    pub sphincs_signature: Option<Vec<u8>>,
    pub zk_proof: Option<Vec<u8>>,
    /// ITC stamp for intra-zone causal ordering (Protocol §11.9).
    /// Serialized compact binary format. Added in wire version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub itc_stamp: Option<Vec<u8>>,
    /// Inter-zone causal references (Protocol §11.9).
    /// Each entry is 17 bytes: zone_id(1) + zone_sequence(8) + epoch(8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zone_refs: Vec<Vec<u8>>,
    /// SPHINCS+ public key of the creator (Profile A only, 48 bytes).
    /// Needed for verifiers to check the sphincs_signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_sphincs_pk: Option<Vec<u8>>,
    /// Algorithm ID for primary signature (Protocol §4.4).
    /// 0x01 = ML-DSA-65 (Dilithium3). Defaults to 0x01 if absent (backwards compat).
    #[serde(default = "default_sig_algorithm")]
    pub sig_algorithm: u8,
    /// Algorithm ID for secondary signature, if present.
    /// 0x02 = SLH-DSA-SHA2-192f (SPHINCS+). None for Profile B.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sphincs_algorithm: Option<u8>,
    /// Explicit zone assignment (wire format v3+).
    /// If None, zone is computed from `zone_for_record(id)` (legacy hash-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<crate::ZoneId>,
    /// Identity hash from wire v4 deserialization (32 bytes, SHA3-256 of PK).
    /// Used to resolve the full PK from CF_IDENTITIES when creator_public_key
    /// was omitted from the wire format. None for v1-v3 records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_hash_wire: Option<Vec<u8>>,
    /// Slot nonce for MESH-BFT mutual exclusion (wire v5+).
    /// Slot = (zone, account_hash, nonce). At most one record per slot finalizes.
    /// Creator-chosen uniqueness token, signed. v4 records default to 0 and are
    /// exempt from slot enforcement until migrated to v5.
    #[serde(default)]
    pub nonce: u64,
}

fn default_sig_algorithm() -> u8 {
    crate::crypto::ALG_DILITHIUM3
}

/// Reject a record/parent id decoded from the wire that is not ASCII.
///
/// Production ids are always `uuid7()` (36-char lowercase-hex + hyphens, ASCII —
/// pinned by the `uuid7` tests), so this rejects only malformed/hostile ids and
/// never a legitimate one (every sealed id is uuid7, so the guard is fork-safe on
/// historical-replay through `from_bytes`). Load-bearing reason: downstream code
/// slices `&id[..16]` for log/error display at many sinks; a multibyte (non-ASCII)
/// id makes that a non-char-boundary slice → panic. The worst sink runs in the
/// `state_core` singleton worker with no `catch_unwind`, so one unauthenticated
/// pre-signature-verify packet would permanently kill the ingest pipeline.
/// Guarding at the decode boundary closes the class: ASCII ⇒ every byte is its own
/// char boundary ⇒ `&id[..n]` (n ≤ len) can never split a char.
fn validate_wire_id(kind: &str, id: &str) -> Result<()> {
    if !id.is_ascii() {
        return Err(ElaraError::Wire(format!(
            "non-ASCII {kind} id rejected at decode ({} bytes)",
            id.len()
        )));
    }
    if id.len() > MAX_RECORD_ID_LEN {
        return Err(ElaraError::Wire(format!(
            "{kind} id too long at decode ({} bytes, max {MAX_RECORD_ID_LEN})",
            id.len()
        )));
    }
    Ok(())
}

/// Hard cap on a wire record/parent id, enforced at the decode boundary by
/// [`validate_wire_id`]. Production ids are 36-char UUIDv7 (`uuid7()`), so
/// 128 gives ~3.5× headroom while bounding every surface that carries an id
/// verbatim — CF_IDX_TIMESTAMP keys (`ts_be ++ id`), the delta-sync page
/// cursor (`hex(ts_be ++ id)` — an unbounded id would mint a cursor the
/// client cannot echo back under the cursor length cap, wedging paging at
/// that record), and log/error sinks. Anchored on the pre-existing informal
/// `record_id.len() > 128` admin checks (`routes/admin.rs`). Fail-closed:
/// a longer id is hostile/malformed, never legitimate (delta-sync cursor
/// audit 2026-07-05, C3).
pub const MAX_RECORD_ID_LEN: usize = 128;

/// Char-boundary-safe prefix of at most `n` bytes, for log/error display of an id.
/// Drop-in for the `&s[..n]` byte slices it replaces: byte-identical output for the
/// ASCII ids that are the only legitimate wire ids (enforced by [`validate_wire_id`]),
/// and for a non-wire / multibyte string it snaps DOWN to the nearest char boundary
/// `≤ n` instead of panicking the way `&s[..n]` does when byte `n` splits a char.
// Its only non-test caller is the `node-core`-gated `state_core` ingest worker, so
// gate the compile footprint to match — otherwise builds without the node stack
// (default / verify-cli) see it as dead code under `-D warnings`. Must track the
// caller's feature exactly: `node-core` (NOT `node`) so an HTTP-only build (e.g.
// the node-core examples) still has it where `state_core` calls it.
#[cfg(any(feature = "node-core", test))]
pub(crate) fn id_prefix(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl ValidationRecord {
    /// Create an unsigned record from content bytes.
    pub fn create(
        content: &[u8],
        creator_public_key: Vec<u8>,
        parents: Vec<String>,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Self {
        let content_hash = sha3_256(content).to_vec();
        Self {
            id: uuid7(),
            version: WIRE_VERSION,
            content_hash,
            creator_public_key,
            timestamp: now_timestamp(),
            parents,
            classification,
            metadata: metadata.unwrap_or_default(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: crate::crypto::ALG_DILITHIUM3,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    /// Create an unsigned record from a pre-computed hash.
    pub fn create_from_hash(
        content_hash: Vec<u8>,
        creator_public_key: Vec<u8>,
        parents: Vec<String>,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Result<Self> {
        if content_hash.len() != 32 {
            return Err(ElaraError::Wire(format!(
                "content hash must be 32 bytes, got {}",
                content_hash.len()
            )));
        }
        Ok(Self {
            id: uuid7(),
            version: WIRE_VERSION,
            content_hash,
            creator_public_key,
            timestamp: now_timestamp(),
            parents,
            classification,
            metadata: metadata.unwrap_or_default(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: crate::crypto::ALG_DILITHIUM3,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        })
    }

    /// Canonical byte representation for signing (everything except signatures).
    /// Must produce identical output to Python's `signable_bytes()`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // id as UTF-8
        buf.extend_from_slice(self.id.as_bytes());

        // version as u16 BE
        buf.extend_from_slice(&self.version.to_be_bytes());

        // v5+: slot nonce is signed. Placed right after version so v4 signatures
        // are byte-identical to before (v4 stops here and moves on to content_hash).
        if self.version >= 5 {
            buf.extend_from_slice(&self.nonce.to_be_bytes());
        }

        // content_hash (32 bytes)
        buf.extend_from_slice(&self.content_hash);

        // creator_public_key (raw bytes)
        buf.extend_from_slice(&self.creator_public_key);

        // timestamp as f64 BE (matches Python's struct.pack("!d", ...))
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // num_parents as u16 BE
        buf.extend_from_slice(&(self.parents.len() as u16).to_be_bytes());

        // Sorted parent IDs (Python sorts them for determinism)
        let mut sorted_parents = self.parents.clone();
        sorted_parents.sort();
        for pid in &sorted_parents {
            buf.extend_from_slice(pid.as_bytes());
        }

        // classification as u8
        buf.push(self.classification as u8);

        // Metadata: sorted compact JSON matching Python's
        // json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        // BTreeMap + serde_json::to_string produces this exact format.
        let meta_json = serde_json::to_string(&self.metadata)
            .unwrap_or_else(|_| "{}".to_string());
        let meta_bytes = meta_json.as_bytes();
        buf.extend_from_slice(&(meta_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(meta_bytes);

        // ZK proof
        match &self.zk_proof {
            Some(zk) => {
                buf.extend_from_slice(&(zk.len() as u32).to_be_bytes());
                buf.extend_from_slice(zk);
            }
            None => {
                buf.extend_from_slice(&0u32.to_be_bytes());
            }
        }

        // NOTE: ITC stamp and zone_refs are NOT included in signable_bytes.
        // They are added by nodes during insertion, not by the record creator,
        // so they must not affect signature verification.

        buf
    }

    /// Strip SPHINCS+ signature and public key from this record.
    /// Used in light mode: Profile A identity creates records but strips the
    /// 35KB SPHINCS+ signature + 48B public key, producing a Profile B record.
    /// Safe to call after signing — signable_bytes doesn't include SPHINCS+ data.
    pub fn strip_sphincs(&mut self) {
        self.sphincs_signature = None;
        self.creator_sphincs_pk = None;
        self.sphincs_algorithm = None;
    }

    /// Serialize to binary wire format (byte-identical to Python's to_bytes()).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4096);

        // Header: ELRA + version(2) + type(1) + reserved(1)
        // Use self.version, NOT WIRE_VERSION: a v4-signed record re-emitted
        // by to_bytes() must keep version=4 in the header so a peer's decoder
        // doesn't mistake it for v5 and recompute signable_bytes with a zero
        // nonce (signature mismatch — the ARCH-4 zombie pattern).
        encode_header(&mut buf, self.version);

        // Record ID (UUID v7, 36 chars UTF-8)
        encode_u8_prefixed(&mut buf, self.id.as_bytes());

        // Content hash (fixed 32 bytes, no length prefix)
        buf.extend_from_slice(&self.content_hash);

        // Creator public key (u16 length prefix).
        // PK dedup bandwidth savings come from announcement gossip (Tier 3.1) —
        // full records are only sent when the peer wants them. Wire format keeps
        // the full PK for storage and signature verification compatibility.
        encode_u16_prefixed(&mut buf, &self.creator_public_key);

        // Timestamp (f64 BE)
        encode_timestamp(&mut buf, self.timestamp);

        // Parents
        buf.extend_from_slice(&(self.parents.len() as u16).to_be_bytes());
        for pid in &self.parents {
            encode_u8_prefixed(&mut buf, pid.as_bytes());
        }

        // Classification
        buf.push(self.classification as u8);

        // Metadata — v4+: binary encoding, v3: JSON fallback.
        // The encoder returns Err only when a count/length field would
        // overflow its wire prefix — unreachable by construction (every
        // decode path caps at MAX_METADATA_ENTRIES=256, ingest per-value
        // size gates bind far lower; only a future local-builder bug can
        // land here). to_bytes() is infallible and feeds hot paths, so
        // degrade deterministically instead of propagating: rewind the
        // partial block and emit an empty map. The remaining wire fields
        // stay parseable (a wrapped count would desync them into the
        // signature bytes) and the record fails signature verification
        // loudly instead of corrupting the stream. (R3-8 slice 1)
        let meta_start = buf.len();
        if let Err(e) = crate::wire::encode_metadata_binary(&mut buf, &self.metadata) {
            tracing::error!(record_id = %self.id, "to_bytes: metadata encode overflow, emitting empty map: {e}");
            buf.truncate(meta_start);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        // ZK proof
        encode_optional_u32(&mut buf, self.zk_proof.as_deref());

        // Signature
        encode_optional_u16(&mut buf, self.signature.as_deref());

        // SPHINCS+ signature
        encode_optional_u16(&mut buf, self.sphincs_signature.as_deref());

        // v2 extension: ITC stamp + zone causal references
        if self.version >= 2 {
            encode_optional_u16(&mut buf, self.itc_stamp.as_deref());

            // Zone refs: count(u16) + N × 24 bytes each (ZoneId u64 + sequence u64 + epoch u64)
            buf.extend_from_slice(&(self.zone_refs.len() as u16).to_be_bytes());
            for zref in &self.zone_refs {
                buf.extend_from_slice(zref);
            }

            // SPHINCS+ public key (optional, 48 bytes for Profile A)
            encode_optional_u16(&mut buf, self.creator_sphincs_pk.as_deref());

            // Algorithm IDs (Protocol §4.4 — Algorithm Agility)
            buf.push(self.sig_algorithm);
            buf.push(self.sphincs_algorithm.unwrap_or(0));
        }

        // v3 extension: explicit zone assignment
        if self.version >= 3 {
            if let Some(ref zone) = self.zone {
                let zone_bytes = zone.to_wire_bytes();
                buf.push(1); // zone present flag
                buf.extend_from_slice(&zone_bytes);
            } else {
                buf.push(0); // no zone
            }
        }

        // v5 extension: slot nonce (MESH-BFT mutual exclusion)
        if self.version >= 5 {
            buf.extend_from_slice(&self.nonce.to_be_bytes());
        }

        buf
    }

    /// Deserialize from binary wire format (byte-compatible with Python's from_bytes()).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut reader = WireReader::new(data);

        // Header
        let (version, _rec_type) = reader.read_header()?;

        // Record ID
        let id_bytes = reader.read_u8_prefixed()?;
        let id = std::str::from_utf8(id_bytes)
            .map_err(|e| ElaraError::Wire(format!("invalid UTF-8 in record ID: {e}")))?
            .to_string();
        validate_wire_id("record", &id)?;

        // Content hash (32 bytes)
        let content_hash = reader.read_bytes(32)?.to_vec();

        // Creator public key (u16 length prefix)
        let creator_public_key = reader.read_u16_prefixed()?.to_vec();
        let identity_hash_wire: Option<Vec<u8>> = None;

        // Timestamp
        let timestamp = reader.read_f64()?;

        // Parents
        let num_parents = reader.read_u16()? as usize;
        // Bound the count before allocating. A peer encodes num_parents as a 2-byte
        // u16, so a tiny body can claim up to 65535 parents and drive a ~1.5 MB
        // Vec::with_capacity pre-allocation (memory amplification). Reject at the
        // decode boundary against the canonical per-record cap (MAX_PARENTS, defined
        // in this module) that network::ingest re-exports and enforces post-decode —
        // mirrors the num_refs guard below.
        if num_parents > MAX_PARENTS {
            return Err(ElaraError::Wire(format!(
                "too many parents: {} (max {})",
                num_parents,
                MAX_PARENTS
            )));
        }
        let mut parents = Vec::with_capacity(num_parents);
        for _ in 0..num_parents {
            let pid_bytes = reader.read_u8_prefixed()?;
            let pid = std::str::from_utf8(pid_bytes)
                .map_err(|e| ElaraError::Wire(format!("invalid UTF-8 in parent ID: {e}")))?
                .to_string();
            validate_wire_id("parent", &pid)?;
            parents.push(pid);
        }

        // Classification
        let class_val = reader.read_u8()?;
        let classification = Classification::from_u8(class_val)?;

        // Metadata — v4+: binary, v3-: JSON
        let metadata: BTreeMap<String, serde_json::Value> = if version >= 4 {
            crate::wire::decode_metadata_binary(&mut reader)?
        } else {
            // Legacy JSON path (v1-v3)
            const MAX_METADATA_BYTES: usize = 102_400;
            const MAX_METADATA_ENTRIES: usize = 256;
            let meta_len = {
                let l = reader.read_u32()? as usize;
                if l > MAX_METADATA_BYTES {
                    return Err(ElaraError::Wire(format!(
                        "metadata field too large: {} bytes (max {})", l, MAX_METADATA_BYTES
                    )));
                }
                l
            };
            let meta_bytes = reader.read_bytes(meta_len)?;
            if meta_bytes.is_empty() {
                BTreeMap::new()
            } else {
                let parsed: BTreeMap<String, serde_json::Value> = serde_json::from_slice(meta_bytes)?;
                if parsed.len() > MAX_METADATA_ENTRIES {
                    return Err(ElaraError::Wire(format!(
                        "too many metadata entries: {} (max {})", parsed.len(), MAX_METADATA_ENTRIES
                    )));
                }
                parsed
            }
        };

        // ZK proof
        let zk_proof = reader.read_optional_u32()?;

        // Signature
        let signature = reader.read_optional_u16()?;

        // SPHINCS+ signature (may be absent at end of data)
        let sphincs_signature = if reader.remaining() > 0 {
            reader.read_optional_u16()?
        } else {
            None
        };

        // v2 extension: ITC stamp + zone causal references
        let (itc_stamp, zone_refs) = if version >= 2 && reader.remaining() > 0 {
            let itc = reader.read_optional_u16()?;

            const MAX_ZONE_REFS: usize = 256;
            let num_refs = if reader.remaining() >= 2 {
                reader.read_u16()? as usize
            } else {
                0
            };
            if num_refs > MAX_ZONE_REFS {
                return Err(ElaraError::Wire(format!(
                    "too many zone_refs: {} (max {})", num_refs, MAX_ZONE_REFS
                )));
            }
            let mut refs = Vec::with_capacity(num_refs);
            for _ in 0..num_refs {
                let zref = reader.read_bytes(24)?.to_vec();
                refs.push(zref);
            }
            (itc, refs)
        } else {
            (None, Vec::new())
        };

        // SPHINCS+ public key (optional, added after v2 extension)
        let creator_sphincs_pk = if reader.remaining() > 0 {
            reader.read_optional_u16()?
        } else {
            None
        };

        // Algorithm IDs (Protocol §4.4).
        //
        // AUDIT-7: both bytes are validated against the currently-accepted set
        // {ALG_DILITHIUM3 primary, ALG_SPHINCS_SHA2_192F secondary}. Unknown IDs
        // are rejected at decode — the bytes are NOT in signable_bytes, so without
        // decode-side enforcement an attacker could rewrite them in transit
        // without invalidating the signature, silently bypassing any future
        // dispatch logic. Until a second primary algorithm ships, the dispatch
        // invariant *is* the wire-level equality check here.
        let (sig_algorithm, sphincs_algorithm) = if reader.remaining() >= 2 {
            let primary = reader.read_u8()?;
            let secondary = reader.read_u8()?;
            if primary != crate::crypto::ALG_DILITHIUM3 {
                return Err(ElaraError::Wire(format!(
                    "unsupported sig_algorithm byte: 0x{:02x} (only 0x{:02x} Dilithium3 is currently accepted)",
                    primary, crate::crypto::ALG_DILITHIUM3,
                )));
            }
            let sphincs_alg = if secondary == 0 {
                None
            } else if secondary == crate::crypto::ALG_SPHINCS_SHA2_192F {
                Some(secondary)
            } else {
                return Err(ElaraError::Wire(format!(
                    "unsupported sphincs_algorithm byte: 0x{:02x} (only 0x{:02x} SPHINCS+-SHA2-192f or 0x00 are accepted)",
                    secondary, crate::crypto::ALG_SPHINCS_SHA2_192F,
                )));
            };
            (primary, sphincs_alg)
        } else {
            // Backwards compat: pre-algorithm-agility records default to Dilithium3
            (crate::crypto::ALG_DILITHIUM3, None)
        };

        // v3 extension: explicit zone assignment
        let zone = if version >= 3 && reader.remaining() > 0 {
            let flag = reader.read_u8()?;
            if flag == 1 {
                let remaining_data = reader.remaining_bytes();
                crate::ZoneId::from_wire_bytes(remaining_data)
                    .map(|(z, consumed)| {
                        reader.advance(consumed);
                        z
                    })
            } else {
                None
            }
        } else {
            None
        };

        // v5 extension: slot nonce (MESH-BFT mutual exclusion)
        let nonce = if version >= 5 && reader.remaining() >= 8 {
            let b = reader.read_bytes(8)?;
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            0
        };

        // AUDIT-7: sphincs_algorithm and sphincs_signature must agree.
        // Same for sphincs_algorithm and creator_sphincs_pk. Declaring the
        // algorithm without the artifacts (or vice-versa) is a wire-format
        // inconsistency that verifiers would silently ignore.
        if sphincs_algorithm.is_some() && sphincs_signature.is_none() {
            return Err(ElaraError::Wire(
                "sphincs_algorithm declared but no SPHINCS+ signature attached".to_string()
            ));
        }
        if sphincs_signature.is_some() && sphincs_algorithm.is_none() {
            return Err(ElaraError::Wire(
                "SPHINCS+ signature attached but sphincs_algorithm byte is 0".to_string()
            ));
        }
        if sphincs_algorithm.is_some() && creator_sphincs_pk.is_none() {
            return Err(ElaraError::Wire(
                "sphincs_algorithm declared but no SPHINCS+ public key attached".to_string()
            ));
        }

        Ok(Self {
            id,
            version,
            content_hash,
            creator_public_key,
            timestamp,
            parents,
            classification,
            metadata,
            signature,
            sphincs_signature,
            zk_proof,
            itc_stamp,
            zone_refs,
            creator_sphincs_pk,
            sig_algorithm,
            sphincs_algorithm,
            zone,
            identity_hash_wire,
            nonce,
        })
    }

    /// SHA3-256 hash of the canonical signable bytes.
    ///
    /// Uses `signable_bytes()` — NOT `to_bytes()` — because `to_bytes()` includes
    /// node-local data (ITC stamps, zone_refs) that differ across nodes, which
    /// would make Merkle roots inconsistent even for identical records.
    pub fn record_hash(&self) -> [u8; 32] {
        sha3_256(&self.signable_bytes())
    }

    /// Get the zone this record belongs to.
    ///
    /// Uses the explicit `zone` field if set (v3), otherwise falls back to
    /// hash-based assignment (legacy: SHA3(record_id)[0] → 0..255).
    pub fn record_zone(&self) -> crate::ZoneId {
        self.zone.clone().unwrap_or_else(|| crate::ZoneId::for_record(&self.id))
    }

    /// Slot key for MESH-BFT mutual exclusion (Phase 3 Stage 1).
    ///
    /// Slot = (account_hash, nonce). At most one record per slot finalizes,
    /// and a second record by the same account with the same nonce (but
    /// different content) is equivocation and is slashed.
    ///
    /// Only meaningful for wire v5+ records; v4 records return None and are
    /// exempt from slot enforcement until migration backfills a nonce.
    ///
    /// # Why no zone in the key
    ///
    /// Earlier drafts prefixed the key with `zone.path()` derived from
    /// `self.record_zone()`. That was **unsound**: `record_zone()` falls back
    /// to `ZoneId::for_record(&self.id)` when `self.zone` is `None`, and the
    /// ingest pipeline never assigns `self.zone` before the slot check. Two
    /// equivocating records share the same (creator, nonce) but always have
    /// distinct `uuid7` ids, so their zone fell out differently → distinct
    /// slot keys → slot mutex never triggered. This was surfaced by the
    /// Stage 1H conflict-injection suite. Zone is a routing / consensus
    /// partition, not a component of slot identity — `(account, nonce)` is
    /// already canonical and unique, so zone is dropped from the key.
    pub fn slot_key(&self) -> Option<String> {
        if self.version < 5 {
            return None;
        }
        let account_hash = crate::crypto::hash::sha3_256_hex(&self.creator_public_key);
        Some(format!("{}:{:016x}", account_hash, self.nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk() -> Vec<u8> {
        vec![0xAA; 1952]
    }

    #[test]
    fn test_create_record() {
        let rec = ValidationRecord::create(
            b"test content",
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        );
        assert_eq!(rec.version, WIRE_VERSION);
        assert_eq!(rec.content_hash.len(), 32);
        assert_eq!(rec.classification, Classification::Public);
        assert!(rec.signature.is_none());
    }

    #[test]
    fn test_create_from_hash() {
        let hash = sha3_256(b"test");
        let rec = ValidationRecord::create_from_hash(
            hash.to_vec(),
            dummy_pk(),
            vec![],
            Classification::Private,
            None,
        )
        .unwrap();
        assert_eq!(rec.content_hash, hash);
    }

    #[test]
    fn test_create_from_hash_wrong_length() {
        assert!(ValidationRecord::create_from_hash(
            vec![0; 16],
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        )
        .is_err());
    }

    #[test]
    fn test_wire_roundtrip() {
        let mut metadata = BTreeMap::new();
        metadata.insert("key".into(), serde_json::Value::String("value".into()));

        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.123456,
            parents: vec!["019506e0-1234-7000-8000-000000000000".to_string()],
            classification: Classification::Public,
            metadata,
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let wire = rec.to_bytes();
        assert_eq!(&wire[0..4], b"ELRA");

        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.content_hash, rec.content_hash);
        assert_eq!(decoded.creator_public_key, rec.creator_public_key);
        assert_eq!(decoded.timestamp, rec.timestamp);
        assert_eq!(decoded.parents, rec.parents);
        assert_eq!(decoded.classification, rec.classification);
        assert_eq!(decoded.metadata, rec.metadata);
        assert_eq!(decoded.signature, rec.signature);
        assert_eq!(decoded.sphincs_signature, rec.sphincs_signature);
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![
                "019506e0-1234-7000-8000-000000000003".to_string(),
                "019506e0-1234-7000-8000-000000000002".to_string(),
            ],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };
        // signable_bytes() sorts parents, so calling twice should be identical
        assert_eq!(rec.signable_bytes(), rec.signable_bytes());
    }

    #[test]
    fn test_signable_bytes_parent_order_independent() {
        let base = || ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let mut rec1 = base();
        rec1.parents = vec!["aaa".to_string(), "bbb".to_string()];

        let mut rec2 = base();
        rec2.parents = vec!["bbb".to_string(), "aaa".to_string()];

        assert_eq!(rec1.signable_bytes(), rec2.signable_bytes());
    }

    #[test]
    fn signable_bytes_complex_metadata_is_stable() {
        // Pins that BTreeMap<String, Value> serialization is infallible and
        // deterministic across all standard JSON value types.
        let mut meta = BTreeMap::new();
        meta.insert("a".to_string(), serde_json::Value::String("v".to_string()));
        meta.insert("b".to_string(), serde_json::Value::Number(serde_json::Number::from(42)));
        meta.insert("c".to_string(), serde_json::Value::Bool(true));
        meta.insert("d".to_string(), serde_json::Value::Null);
        let rec = ValidationRecord::create(
            b"data",
            dummy_pk(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let b1 = rec.signable_bytes();
        let b2 = rec.signable_bytes();
        assert!(!b1.is_empty());
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_record_hash_changes() {
        let rec1 = ValidationRecord::create(b"content1", dummy_pk(), vec![], Classification::Public, None);
        let rec2 = ValidationRecord::create(b"content2", dummy_pk(), vec![], Classification::Public, None);
        assert_ne!(rec1.record_hash(), rec2.record_hash());
    }

    #[test]
    fn to_bytes_metadata_encode_overflow_degrades_to_empty_map_not_stream_corruption() {
        // R3-8 slice 1: a metadata value whose count overflows its u16 wire
        // prefix cannot be binary-encoded. to_bytes() must rewind the partial
        // block and emit an empty map so every later field (zk/sig/v2 ext)
        // stays at its expected offset — the old `as u16` wrap desynced the
        // decoder into the signature bytes. The record is invalid either way
        // (signable_bytes covers the real metadata, so verification fails
        // loudly); the invariant pinned here is that the WIRE STREAM stays
        // parseable and the degrade is the empty map, not garbage.
        let mut rec =
            ValidationRecord::create(b"overflow", dummy_pk(), vec![], Classification::Public, None);
        rec.metadata.insert(
            "giant".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::Null; u16::MAX as usize + 1]),
        );
        let bytes = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&bytes).expect("stream must stay parseable");
        assert!(decoded.metadata.is_empty(), "degrade emits an empty metadata map");
        assert_eq!(decoded.id, rec.id);
    }

    #[test]
    fn test_classification_roundtrip() {
        for val in 0..4u8 {
            let c = Classification::from_u8(val).unwrap();
            assert_eq!(c as u8, val);
        }
        assert!(Classification::from_u8(4).is_err());
    }

    // ── C1 regression: id-slice panic class (remote unauthenticated node-kill) ──
    // A wire-decoded record id was accepted as arbitrary UTF-8 then byte-sliced
    // `&id[..16]` at ~150 sinks; a multibyte char at byte 16 panicked the
    // catch_unwind-free state_core singleton worker — one pre-sig-verify packet
    // permanently killed ingest. Locked at the decode boundary (validate_wire_id)
    // plus a char-safe display helper (id_prefix).

    /// The exact attack id: 15 ASCII bytes + a 2-byte char so byte 16 is mid-char.
    fn c1_hostile_id() -> &'static str {
        "0123456789abcde\u{00e9}" // 15 + 2 = 17 bytes, valid UTF-8, non-ASCII
    }

    #[test]
    fn c1_helpers_fail_closed_on_multibyte_id() {
        let hostile = c1_hostile_id();
        assert_eq!(hostile.len(), 17);
        assert!(!hostile.is_ascii());
        assert!(
            !hostile.is_char_boundary(16),
            "byte 16 must split a char — that is the panic trigger"
        );
        // id_prefix must NOT panic and must stop on a char boundary before the split.
        let p = id_prefix(hostile, 16);
        assert_eq!(p, "0123456789abcde");
        assert!(hostile.is_char_boundary(p.len()));
        // validate_wire_id rejects the hostile id; a real uuid7 id passes.
        assert!(validate_wire_id("record", hostile).is_err());
        assert!(validate_wire_id("record", &crate::uuid7::uuid7()).is_ok());
    }

    #[test]
    fn c1_from_bytes_rejects_non_ascii_record_id() {
        // The sole attacker-reachable decoder must fail closed, so the hostile
        // record never reaches the state_core slice sink.
        let mut rec =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        rec.id = c1_hostile_id().to_string();
        assert!(
            ValidationRecord::from_bytes(&rec.to_bytes()).is_err(),
            "from_bytes must reject a non-ASCII record id"
        );
        // A genuine uuid7-id record still round-trips.
        let good =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        assert!(ValidationRecord::from_bytes(&good.to_bytes()).is_ok());
    }

    #[test]
    fn c1_from_bytes_rejects_non_ascii_parent_id() {
        let mut rec =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        rec.parents = vec![c1_hostile_id().to_string()];
        assert!(
            ValidationRecord::from_bytes(&rec.to_bytes()).is_err(),
            "from_bytes must reject a non-ASCII parent id"
        );
    }

    #[test]
    fn from_bytes_rejects_over_length_record_and_parent_ids() {
        // Delta-sync cursor audit 2026-07-05 C3: ids ride verbatim in
        // CF_IDX_TIMESTAMP keys and (hex-doubled) in the sync cursor — an
        // unbounded id would mint a cursor the client cannot echo back,
        // wedging paging at that record. MAX_RECORD_ID_LEN bounds the class
        // at the same decode boundary as the ASCII guard.
        let long_id = "a".repeat(MAX_RECORD_ID_LEN + 1);
        let mut rec =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        rec.id = long_id.clone();
        assert!(
            ValidationRecord::from_bytes(&rec.to_bytes()).is_err(),
            "from_bytes must reject a record id over MAX_RECORD_ID_LEN"
        );
        let mut rec2 =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        rec2.parents = vec![long_id];
        assert!(
            ValidationRecord::from_bytes(&rec2.to_bytes()).is_err(),
            "from_bytes must reject a parent id over MAX_RECORD_ID_LEN"
        );
        // Boundary: exactly MAX_RECORD_ID_LEN decodes fine (ASCII, at-cap).
        let mut rec3 =
            ValidationRecord::create(b"payload", dummy_pk(), vec![], Classification::Public, None);
        rec3.id = "b".repeat(MAX_RECORD_ID_LEN);
        assert!(
            ValidationRecord::from_bytes(&rec3.to_bytes()).is_ok(),
            "an exactly-at-cap ASCII id must still decode"
        );
    }

    #[test]
    fn test_wire_with_sphincs_sig() {
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xCC; 3293]),
            sphincs_signature: Some(vec![0xDD; 35664]),
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: Some(vec![0xEE; 48]),
            sig_algorithm: 0x01,
            sphincs_algorithm: Some(0x02),
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let wire = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.signature.as_ref().unwrap().len(), 3293);
        assert_eq!(decoded.sphincs_signature.as_ref().unwrap().len(), 35664);
        assert_eq!(decoded.creator_sphincs_pk.as_ref().unwrap().len(), 48);
        assert_eq!(decoded.sig_algorithm, 0x01);
        assert_eq!(decoded.sphincs_algorithm, Some(0x02));
    }

    #[test]
    fn test_wire_roundtrip_with_itc() {
        use crate::itc::{Stamp, ZoneCausalReference};
        use crate::ZoneId;

        let stamp = Stamp::seed().event().event();
        let zone_ref = ZoneCausalReference {
            zone_id: ZoneId::from_legacy(42),
            zone_sequence: 100,
            epoch: 5,
        };

        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: Some(stamp.to_bytes()),
            zone_refs: vec![zone_ref.to_bytes()],
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let wire = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.itc_stamp, rec.itc_stamp);
        assert_eq!(decoded.zone_refs, rec.zone_refs);
        assert_eq!(decoded.version, WIRE_VERSION);

        // Verify the ITC stamp deserializes correctly
        let decoded_stamp = Stamp::from_bytes(decoded.itc_stamp.as_ref().unwrap()).unwrap();
        assert_eq!(decoded_stamp, stamp);

        // Verify the zone ref deserializes correctly
        let decoded_ref = ZoneCausalReference::from_bytes(&decoded.zone_refs[0]).unwrap();
        assert_eq!(decoded_ref, zone_ref);
    }

    #[test]
    fn test_wire_v1_backward_compat() {
        // Build a v1 record (no ITC fields)
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: 1, // explicit v1
            content_hash: sha3_256(b"test").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        // Manually build v1 wire bytes (old format, no ITC extension)
        let mut buf = Vec::with_capacity(4096);
        buf.extend_from_slice(b"ELRA");
        buf.extend_from_slice(&1u16.to_be_bytes()); // version 1
        buf.push(0x01); // record_type
        buf.push(0x00); // reserved
        encode_u8_prefixed(&mut buf, rec.id.as_bytes());
        buf.extend_from_slice(&rec.content_hash);
        encode_u16_prefixed(&mut buf, &rec.creator_public_key);
        encode_timestamp(&mut buf, rec.timestamp);
        buf.extend_from_slice(&0u16.to_be_bytes()); // 0 parents
        buf.push(0); // PUBLIC
        encode_u32_prefixed(&mut buf, b"{}");
        encode_optional_u32(&mut buf, None); // zk_proof
        encode_optional_u16(&mut buf, rec.signature.as_deref());
        encode_optional_u16(&mut buf, None); // sphincs_sig
        // No ITC fields — this is v1

        let decoded = ValidationRecord::from_bytes(&buf).unwrap();
        assert_eq!(decoded.version, 1);
        assert!(decoded.itc_stamp.is_none());
        assert!(decoded.zone_refs.is_empty());
    }

    /// Spec-lock test for internal design notes — builds a minimal v5
    /// record with known-sized fields and asserts the exact byte layout
    /// the spec documents. If this test fails, either the emitter drifted
    /// or internal design notes needs to be updated. The two must stay
    /// bit-identical for cross-implementation clients to interoperate.
    #[test]
    fn test_wire_format_spec_locked() {
        let rec = ValidationRecord {
            id: "abc".to_string(),
            version: 5,
            // deterministic content hash (32 bytes of 0x11)
            content_hash: vec![0x11; 32],
            // 4-byte PK so the full layout is easy to eyeball
            creator_public_key: vec![0xAA, 0xBB, 0xCC, 0xDD],
            timestamp: 0.0_f64,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01, // ALG_DILITHIUM3
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let wire = rec.to_bytes();

        // Offsets documented in internal design notes §3, §4, §7.
        // Header (§3): 8 bytes
        assert_eq!(&wire[0..4], b"ELRA", "magic");
        assert_eq!(&wire[4..6], &5u16.to_be_bytes(), "version=5");
        assert_eq!(wire[6], 0x01, "rec_type = 0x01 (ValidationRecord frame)");
        assert_eq!(wire[7], 0, "reserved byte");

        // id (u8-prefix) at offset 8: len=3, "abc"
        assert_eq!(wire[8], 3);
        assert_eq!(&wire[9..12], b"abc");

        // content_hash (32 bytes raw) at offset 12
        assert_eq!(&wire[12..44], &[0x11; 32][..]);

        // creator_public_key (u16-prefix): len=4 at offset 44
        assert_eq!(&wire[44..46], &4u16.to_be_bytes());
        assert_eq!(&wire[46..50], &[0xAA, 0xBB, 0xCC, 0xDD]);

        // timestamp (f64 BE, 8 bytes) at offset 50
        assert_eq!(&wire[50..58], &0.0_f64.to_be_bytes());

        // num_parents u16 at offset 58: 0
        assert_eq!(&wire[58..60], &0u16.to_be_bytes());

        // classification u8 at offset 60: PUBLIC=0
        assert_eq!(wire[60], 0);

        // metadata (§5.1 v4+ binary): u16 count = 0 at offset 61
        assert_eq!(&wire[61..63], &0u16.to_be_bytes());

        // zk_proof optional u32 at offset 63: 0 = absent
        assert_eq!(&wire[63..67], &0u32.to_be_bytes());

        // signature optional u16 at offset 67: 0 = absent
        assert_eq!(&wire[67..69], &0u16.to_be_bytes());

        // sphincs_signature optional u16 at offset 69: 0 = absent
        assert_eq!(&wire[69..71], &0u16.to_be_bytes());

        // v2 extension (§7.1):
        //   itc_stamp optional u16 at offset 71: 0 = absent
        assert_eq!(&wire[71..73], &0u16.to_be_bytes());
        //   zone_refs_count u16 at offset 73: 0
        assert_eq!(&wire[73..75], &0u16.to_be_bytes());
        //   creator_sphincs_pk optional u16 at offset 75: 0 = absent
        assert_eq!(&wire[75..77], &0u16.to_be_bytes());
        //   sig_algorithm u8 at offset 77: 0x01 (Dilithium3)
        assert_eq!(wire[77], 0x01);
        //   sphincs_algorithm u8 at offset 78: 0 (none)
        assert_eq!(wire[78], 0);

        // v3 extension (§7.2): zone_flag u8 at offset 79: 0 = absent
        assert_eq!(wire[79], 0);

        // v5 extension (§7.4): nonce u64 at offset 80: 0
        assert_eq!(&wire[80..88], &0u64.to_be_bytes());

        // Total size: 88 bytes for this minimal v5 record.
        assert_eq!(wire.len(), 88, "minimal v5 record layout changed; update internal design notes");

        // Round-trip: decoder recovers identical record.
        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.version, 5);
        assert_eq!(decoded.nonce, 0);
        assert_eq!(decoded.classification, Classification::Public);
        assert_eq!(decoded.creator_public_key, rec.creator_public_key);
    }

    fn audit7_base_record() -> ValidationRecord {
        ValidationRecord {
            id: "019506e0-audit-7000-8000-00000000a007".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"audit7").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: crate::crypto::ALG_DILITHIUM3,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    /// AUDIT-7: decoder rejects an unknown primary sig_algorithm byte.
    /// The byte is not in signable_bytes, so without decode-side enforcement an
    /// attacker could flip it in transit without invalidating the signature.
    #[test]
    fn test_audit7_rejects_unknown_primary_sig_algorithm() {
        let mut rec = audit7_base_record();
        rec.sig_algorithm = 0xFE; // not ALG_DILITHIUM3
        let wire = rec.to_bytes();
        let err = ValidationRecord::from_bytes(&wire).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("unsupported sig_algorithm"),
                "unexpected wire error: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// AUDIT-7: decoder rejects an unknown sphincs_algorithm byte (non-zero, non-SPHINCS+).
    #[test]
    fn test_audit7_rejects_unknown_secondary_sphincs_algorithm() {
        let mut rec = audit7_base_record();
        rec.sphincs_signature = Some(vec![0xDD; 35664]);
        rec.creator_sphincs_pk = Some(vec![0xEE; 48]);
        rec.sphincs_algorithm = Some(0x7F); // not ALG_SPHINCS_SHA2_192F
        let wire = rec.to_bytes();
        let err = ValidationRecord::from_bytes(&wire).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("unsupported sphincs_algorithm"),
                "unexpected wire error: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// AUDIT-7: zero sphincs_algorithm with a SPHINCS+ signature attached is rejected.
    #[test]
    fn test_audit7_rejects_sphincs_sig_without_algorithm_byte() {
        let mut rec = audit7_base_record();
        rec.sphincs_signature = Some(vec![0xDD; 35664]);
        rec.creator_sphincs_pk = Some(vec![0xEE; 48]);
        rec.sphincs_algorithm = None; // encodes as 0x00 on wire
        let wire = rec.to_bytes();
        let err = ValidationRecord::from_bytes(&wire).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("SPHINCS+ signature attached but sphincs_algorithm byte is 0"),
                "unexpected wire error: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// AUDIT-7: sphincs_algorithm declared with no signature attached is rejected.
    #[test]
    fn test_audit7_rejects_sphincs_algorithm_without_signature() {
        let mut rec = audit7_base_record();
        rec.sphincs_signature = None;
        rec.creator_sphincs_pk = Some(vec![0xEE; 48]);
        rec.sphincs_algorithm = Some(crate::crypto::ALG_SPHINCS_SHA2_192F);
        let wire = rec.to_bytes();
        let err = ValidationRecord::from_bytes(&wire).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("sphincs_algorithm declared but no SPHINCS+ signature"),
                "unexpected wire error: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// AUDIT-7: sphincs_algorithm declared without creator_sphincs_pk is rejected.
    #[test]
    fn test_audit7_rejects_sphincs_algorithm_without_pk() {
        let mut rec = audit7_base_record();
        rec.sphincs_signature = Some(vec![0xDD; 35664]);
        rec.creator_sphincs_pk = None;
        rec.sphincs_algorithm = Some(crate::crypto::ALG_SPHINCS_SHA2_192F);
        let wire = rec.to_bytes();
        let err = ValidationRecord::from_bytes(&wire).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("sphincs_algorithm declared but no SPHINCS+ public key"),
                "unexpected wire error: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// AUDIT-7: canonical Profile A (Dilithium3 + SPHINCS+) record still round-trips.
    /// The validation paths above must not regress the valid case.
    #[test]
    fn test_audit7_profile_a_still_roundtrips() {
        let mut rec = audit7_base_record();
        rec.sphincs_signature = Some(vec![0xDD; 35664]);
        rec.creator_sphincs_pk = Some(vec![0xEE; 48]);
        rec.sphincs_algorithm = Some(crate::crypto::ALG_SPHINCS_SHA2_192F);
        let wire = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&wire).expect("profile A record must decode");
        assert_eq!(decoded.sig_algorithm, crate::crypto::ALG_DILITHIUM3);
        assert_eq!(decoded.sphincs_algorithm, Some(crate::crypto::ALG_SPHINCS_SHA2_192F));
    }

    /// Panic-hardening: the record decoder must bound `num_parents` at the wire
    /// boundary. The count is a 2-byte u16, so a peer can claim up to 65535
    /// parents in a tiny body and drive a ~1.5 MB `Vec::with_capacity`
    /// pre-allocation before the parent-read loop (or the downstream ingest cap)
    /// rejects it — a memory-amplification vector. The bound mirrors the existing
    /// `num_refs` (MAX_ZONE_REFS) and metadata guards in the same decoder, and is
    /// tied to the canonical per-record cap that ingest enforces post-decode.
    #[test]
    fn test_decoder_rejects_oversized_num_parents_alloc_amplification() {
        let over = crate::record::MAX_PARENTS + 1;

        // Hand-build a valid wire prefix through the num_parents field, then stop.
        // A bounded decoder must reject on the count BEFORE reading any parent
        // body, so the absence of parent bytes past num_parents must not matter.
        let mut buf = Vec::new();
        encode_header(&mut buf, WIRE_VERSION);
        encode_u8_prefixed(&mut buf, b"019506e0-pcap-7000-8000-00000000a009");
        buf.extend_from_slice(&sha3_256(b"pcap")[..]); // 32-byte content hash
        encode_u16_prefixed(&mut buf, &dummy_pk());
        encode_timestamp(&mut buf, 1739712345.0);
        buf.extend_from_slice(&(over as u16).to_be_bytes()); // num_parents = MAX_PARENTS + 1

        let err = ValidationRecord::from_bytes(&buf).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("too many parents"),
                "expected boundary rejection on num_parents, got: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// Panic-hardening twin of the num_parents alloc-amplification test, for the
    /// v2 `zone_refs` count. The decoder reads `num_refs` as a 2-byte u16 and
    /// must reject `> MAX_ZONE_REFS` BEFORE `Vec::with_capacity(num_refs)` — a
    /// peer claiming 65535 refs in a tiny body would otherwise drive a large
    /// pre-allocation (memory amplification). The num_parents test guards an
    /// earlier field and cannot exercise this branch; without this test a
    /// refactor that hoists the zone_refs `Vec::with_capacity` above its length
    /// gate would re-open the vector while every existing test stayed green.
    /// `MAX_ZONE_REFS` is a decoder-local const, so we claim u16::MAX — the true
    /// worst case a peer can encode — which exceeds any sane cap value.
    #[test]
    fn test_decoder_rejects_oversized_num_refs_alloc_amplification() {
        // Mirror to_bytes() through the v2 `num_refs` field using the real codec
        // helpers (robust by construction — no magic offsets), then stop. Use
        // version=4: binary metadata on both encode+decode, v2 extension decoded,
        // no v5 nonce required (the guard rejects before the nonce field).
        let mut buf = Vec::new();
        encode_header(&mut buf, 4);
        encode_u8_prefixed(&mut buf, b"019506e0-zref-7000-8000-00000000a00a");
        buf.extend_from_slice(&sha3_256(b"zref")[..]); // 32-byte content hash
        encode_u16_prefixed(&mut buf, &dummy_pk());
        encode_timestamp(&mut buf, 1739712345.0);
        buf.extend_from_slice(&0u16.to_be_bytes()); // num_parents = 0
        buf.push(Classification::Public as u8);
        crate::wire::encode_metadata_binary(&mut buf, &BTreeMap::new()).unwrap();
        encode_optional_u32(&mut buf, None); // zk_proof
        encode_optional_u16(&mut buf, None); // signature
        encode_optional_u16(&mut buf, None); // sphincs_signature
        // v2 extension:
        encode_optional_u16(&mut buf, None); // itc_stamp
        buf.extend_from_slice(&u16::MAX.to_be_bytes()); // num_refs = 65535, no ref bodies

        let err = ValidationRecord::from_bytes(&buf).unwrap_err();
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("too many zone_refs"),
                "expected boundary rejection on num_refs before alloc, got: {msg}"
            ),
            other => panic!("expected Wire error, got {other:?}"),
        }
    }

    /// ARCH-4 zombie-pattern regression: a v4-signed record re-emitted via
    /// `to_bytes()` MUST keep `version=4` on the wire. Earlier `encode_header`
    /// always stamped the current `WIRE_VERSION` (5) regardless of `self.version`.
    /// Combined with `to_bytes()` skipping the v5 nonce field for v4 records,
    /// that produced records whose header claimed v5 but whose signature was
    /// over the v4 signing input. The next decoder read version=5 and added a
    /// (zero) nonce to `signable_bytes()`, so the original signature failed to
    /// verify on the receiving node — the fleet-wide ARCH-4 storm.
    #[test]
    fn test_arch4_v4_record_roundtrip_preserves_version_and_signable_bytes() {
        let mut rec = ValidationRecord::create(
            b"arch4 zombie regression",
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        );
        rec.version = 4;
        rec.nonce = 0;
        let signable_pre = rec.signable_bytes();

        let wire = rec.to_bytes();

        let header_version = u16::from_be_bytes([wire[4], wire[5]]);
        assert_eq!(
            header_version, 4,
            "encode_header must stamp self.version, not WIRE_VERSION"
        );

        let decoded = ValidationRecord::from_bytes(&wire).expect("v4 wire must decode");
        assert_eq!(decoded.version, 4, "decoded version must match self.version");
        assert_eq!(decoded.nonce, 0, "v4 record must not carry a nonce");

        let signable_post = decoded.signable_bytes();
        assert_eq!(
            signable_pre, signable_post,
            "round-trip must preserve signable_bytes — that is the signature input"
        );
        assert_eq!(
            signable_pre.len(),
            signable_post.len(),
            "round-tripped signable_bytes must be byte-identical length"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fixture-free axis pins for record.rs.
    // Each test guards load-bearing semantics that existing tests don't
    // exercise (Classification names + error format, ProjectedRecord
    // redaction matrix, strip_sphincs full clear, record_zone branches,
    // slot_key v4/v5 format).
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_classification_name_and_from_u8_error_message_format() {
        // name() returns canonical uppercase strings consumed by
        // /classification logs and clearance-check UIs. Pin all 4 mappings.
        assert_eq!(Classification::Public.name(),     "PUBLIC");
        assert_eq!(Classification::Private.name(),    "PRIVATE");
        assert_eq!(Classification::Restricted.name(), "RESTRICTED");
        assert_eq!(Classification::Sovereign.name(),  "SOVEREIGN");

        // from_u8 with invalid byte must surface the offending value in the
        // Wire error message — grep-stable for debugging malformed records.
        let err = Classification::from_u8(99).unwrap_err();
        match err {
            ElaraError::Wire(msg) => {
                assert!(
                    msg.contains("invalid classification"),
                    "error must mention 'invalid classification', got: {msg}"
                );
                assert!(
                    msg.contains("99"),
                    "error must include offending byte 99, got: {msg}"
                );
            }
            other => panic!("expected Wire error for invalid classification, got {other:?}"),
        }
    }

    #[test]
    fn batch_b_project_clearance_level_redaction_matrix() {
        // ProjectedRecord.project() implements C(v, observer) per Protocol
        // §3.3.3. Pin the per-clearance redaction matrix — silent drift
        // would leak metadata across clearance boundaries:
        //   Public:     content_hash=visible, metadata=visible,  creator_hash=visible
        //   Private:    content_hash=visible, metadata=REDACTED, creator_hash=visible
        //   Restricted: content_hash=REDACTED, metadata=REDACTED, creator_hash=visible
        //   Sovereign:  content_hash=REDACTED, metadata=REDACTED, creator_hash=REDACTED
        let mut meta = BTreeMap::new();
        meta.insert("k".into(), serde_json::Value::String("v".into()));
        let rec = ValidationRecord {
            id: "test-id".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"x").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1.0,
            parents: vec![],
            classification: Classification::Sovereign,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let public = rec.project(Classification::Public);
        assert!(public.content_hash.is_some(), "Public sees content_hash");
        assert!(public.metadata.is_some(),     "Public sees metadata");
        assert!(public.creator_hash.is_some(), "Public sees creator_hash");

        let private = rec.project(Classification::Private);
        assert!(private.content_hash.is_some(), "Private still sees content_hash");
        assert!(private.metadata.is_none(),     "Private metadata REDACTED");
        assert!(private.creator_hash.is_some(), "Private sees creator_hash");

        let restricted = rec.project(Classification::Restricted);
        assert!(restricted.content_hash.is_none(),
            "Restricted content_hash REDACTED");
        assert!(restricted.metadata.is_none(),
            "Restricted metadata REDACTED");
        assert!(restricted.creator_hash.is_some(),
            "Restricted still sees creator_hash");

        let sovereign = rec.project(Classification::Sovereign);
        assert!(sovereign.content_hash.is_none(), "Sovereign content_hash REDACTED");
        assert!(sovereign.metadata.is_none(),     "Sovereign metadata REDACTED");
        assert!(sovereign.creator_hash.is_none(), "Sovereign creator_hash REDACTED");

        // id, classification, timestamp are always preserved across all
        // projection levels — they're the metadata OF the projection itself,
        // not subject to redaction.
        for view in [public, private, restricted, sovereign] {
            assert_eq!(view.id.as_str(), "test-id",
                "id preserved across projection levels");
            assert_eq!(view.classification, Classification::Sovereign,
                "record classification preserved (this is the record's own level)");
            assert_eq!(view.timestamp, 1.0,
                "timestamp preserved");
        }
    }

    #[test]
    fn batch_b_strip_sphincs_clears_all_three_sphincs_fields() {
        // strip_sphincs() drops the three SPHINCS+-related fields so a
        // Profile A signed record can be converted to a Profile B record
        // (~35KB SPHINCS+ signature + 48B PK saved). All three fields
        // must clear together — partial clearing would create a malformed
        // record that the decoder rejects via the audit7 invariants
        // (sphincs_algorithm declared without artifacts or vice-versa).
        let mut rec = ValidationRecord::create(
            b"strip test", dummy_pk(), vec![], Classification::Public, None,
        );
        rec.sphincs_signature = Some(vec![0xDD; 35664]);
        rec.creator_sphincs_pk = Some(vec![0xEE; 48]);
        rec.sphincs_algorithm = Some(0x02);

        rec.strip_sphincs();

        assert!(rec.sphincs_signature.is_none(),
            "strip_sphincs must clear sphincs_signature");
        assert!(rec.creator_sphincs_pk.is_none(),
            "strip_sphincs must clear creator_sphincs_pk");
        assert!(rec.sphincs_algorithm.is_none(),
            "strip_sphincs must clear sphincs_algorithm");

        // Primary signature and classification must be untouched —
        // strip_sphincs is a Profile-A→B transform, not a full reset.
        assert_eq!(rec.sig_algorithm, crate::crypto::ALG_DILITHIUM3,
            "strip_sphincs must leave primary algorithm intact");
        assert_eq!(rec.classification, Classification::Public,
            "strip_sphincs must not touch classification");
    }

    #[test]
    fn batch_b_record_zone_explicit_v3_vs_legacy_hash_fallback() {
        // record_zone() returns self.zone if set (v3+ explicit assignment),
        // otherwise falls back to ZoneId::for_record(self.id) (legacy v1/v2
        // hash-derived). Both branches are load-bearing — the fallback is
        // what lets v1/v2 records continue to route correctly post-v3 upgrade.

        // Branch 1: explicit self.zone takes precedence.
        let explicit_zone = crate::ZoneId::from_legacy(42);
        let mut rec_explicit = ValidationRecord::create(
            b"explicit", dummy_pk(), vec![], Classification::Public, None,
        );
        rec_explicit.zone = Some(explicit_zone.clone());
        let got_explicit = rec_explicit.record_zone();
        assert_eq!(got_explicit, explicit_zone,
            "explicit self.zone must be returned verbatim");

        // Branch 2: no explicit zone → hash-derived fallback.
        let mut rec_fallback = ValidationRecord::create(
            b"fallback", dummy_pk(), vec![], Classification::Public, None,
        );
        rec_fallback.zone = None;
        let got_fallback = rec_fallback.record_zone();
        let expected_fallback = crate::ZoneId::for_record(&rec_fallback.id);
        assert_eq!(got_fallback, expected_fallback,
            "no-zone fallback must match ZoneId::for_record(self.id)");
    }

    #[test]
    fn batch_b_slot_key_v4_none_and_v5_account_hash_nonce_format() {
        // slot_key() implements MESH-BFT mutual exclusion (Phase 3 Stage 1):
        //   - v4 records: returns None (exempt from slot enforcement until
        //     migration backfills a nonce)
        //   - v5+ records: returns Some("{account_hash}:{nonce:016x}") with
        //     16-hex zero-padded nonce. Format is the storage key for
        //     CF_SLOTS — silent drift would corrupt finality / equivocation
        //     detection.

        // v4 branch: None.
        let mut rec_v4 = ValidationRecord::create(
            b"v4", dummy_pk(), vec![], Classification::Public, None,
        );
        rec_v4.version = 4;
        rec_v4.nonce = 999;
        assert!(rec_v4.slot_key().is_none(),
            "v4 records must return None from slot_key (exempt until migration)");

        // v5 branch with non-trivial nonce: exact format.
        let mut rec_v5 = ValidationRecord::create(
            b"v5", dummy_pk(), vec![], Classification::Public, None,
        );
        rec_v5.version = 5;
        rec_v5.nonce = 0xDEAD_BEEF;
        let key = rec_v5.slot_key().expect("v5 slot_key must be Some");
        let expected_account_hash =
            crate::crypto::hash::sha3_256_hex(&rec_v5.creator_public_key);
        let expected_key =
            format!("{}:{:016x}", expected_account_hash, 0xDEAD_BEEFu64);
        assert_eq!(key, expected_key,
            "v5 slot_key format must be {{account_hash}}:{{nonce:016x}}");

        // Structural pins on the format:
        //   - single ':' separator
        //   - 64-hex-char account_hash (SHA3-256)
        //   - 16-hex-char nonce (u64 zero-padded)
        let parts: Vec<&str> = key.split(':').collect();
        assert_eq!(parts.len(), 2, "slot_key has single ':' separator");
        assert_eq!(parts[0].len(), 64,
            "account_hash part must be 64 hex chars (SHA3-256), got: {}", parts[0]);
        assert_eq!(parts[1].len(), 16,
            "nonce part must be exactly 16 hex characters (u64 zero-padded), got: {}",
            parts[1]);

        // Zero-nonce edge case: must pad to 16 zeros, not collapse to "0".
        rec_v5.nonce = 0;
        let key_zero = rec_v5.slot_key().unwrap();
        assert!(key_zero.ends_with(":0000000000000000"),
            "nonce=0 must zero-pad to 16 zeros, got: {key_zero}");
    }

    /// Companion to the v4 regression: a v5 record must still round-trip
    /// correctly with version=5 and the nonce included in signable_bytes.
    #[test]
    fn test_arch4_v5_record_roundtrip_preserves_version_and_nonce() {
        let mut rec = ValidationRecord::create(
            b"v5 baseline",
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        );
        rec.nonce = 42;
        let signable_pre = rec.signable_bytes();

        let wire = rec.to_bytes();
        let header_version = u16::from_be_bytes([wire[4], wire[5]]);
        assert_eq!(header_version, 5);

        let decoded = ValidationRecord::from_bytes(&wire).expect("v5 wire must decode");
        assert_eq!(decoded.version, 5);
        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.signable_bytes(), signable_pre);
    }

    #[test]
    fn signable_bytes_encodes_metadata_as_compact_sorted_json() {
        use std::collections::BTreeMap;
        let mut meta = BTreeMap::new();
        meta.insert("key".to_string(), serde_json::Value::String("val".to_string()));
        meta.insert("n".to_string(), serde_json::json!(42));
        let rec = ValidationRecord::create(
            b"content",
            dummy_pk(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let bytes = rec.signable_bytes();
        let bytes_str = String::from_utf8_lossy(&bytes);
        // BTreeMap serializes keys in sorted order; "key" < "n"
        assert!(
            bytes_str.contains(r#"{"key":"val","n":42}"#),
            "metadata must be compact-sorted JSON in signable bytes: {bytes_str:?}"
        );
    }

    #[test]
    fn signable_bytes_metadata_length_prefix_big_endian_u32() {
        // The 4 bytes immediately before the metadata JSON must be a BE u32
        // length that matches the JSON byte length exactly.  This is the
        // cross-language wire contract with Python's signable_bytes().
        let mut meta = BTreeMap::new();
        meta.insert("z".to_string(), serde_json::json!(1));
        let rec = ValidationRecord::create(
            b"x",
            dummy_pk(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let bytes = rec.signable_bytes();
        let expected_json = b"{\"z\":1}";
        let pos = bytes
            .windows(expected_json.len())
            .position(|w| w == expected_json)
            .expect("metadata JSON must appear verbatim in signable_bytes");
        assert!(pos >= 4, "metadata JSON must be preceded by a 4-byte length prefix");
        let encoded_len =
            u32::from_be_bytes(bytes[pos - 4..pos].try_into().expect("4 bytes"));
        assert_eq!(
            encoded_len,
            expected_json.len() as u32,
            "BE u32 length prefix must equal JSON byte length"
        );
    }

    #[test]
    fn signable_bytes_metadata_unwrap_or_else_is_normal_path_not_fallback() {
        // unwrap_or_else("{}") replaced the former .expect() so a Byzantine
        // peer's malformed record can't crash the node.  This test pins that
        // nested/unicode metadata takes the normal path (not the "{}" fallback).
        let mut meta = BTreeMap::new();
        meta.insert("nested".to_string(), serde_json::json!({"x": [1, null, true]}));
        meta.insert("z".to_string(), serde_json::Value::String("🌍".to_string()));
        let rec = ValidationRecord::create(
            b"d",
            vec![0xAA; 1952],
            vec![],
            Classification::Public,
            Some(meta),
        );
        let b = rec.signable_bytes();
        // The real metadata JSON appears verbatim — confirms normal path, not "{}".
        assert!(
            b.windows(10).any(|w| w == br#"{"nested":"#),
            "nested metadata must appear in signable_bytes output"
        );
    }

    #[test]
    fn now_timestamp_positive_and_pre_epoch_fallback() {
        // Production path: clock is after epoch → positive timestamp.
        let ts = now_timestamp();
        assert!(ts > 1_700_000_000.0, "now_timestamp must be after 2023: {ts}");

        // Fallback sentinel: duration_since returns Err for pre-epoch SystemTime.
        let pre_epoch = std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("test: sub 1s from epoch");
        let fallback: f64 = pre_epoch
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        assert_eq!(fallback, 0.0, "pre-epoch clock must yield sentinel 0.0, not panic");
    }

    /// Regression guard for the `serde_json` `float_roundtrip` feature (root
    /// Cargo.toml). Without it, ~12% of f64 timestamps lose 1 ULP when parsed
    /// back from JSON, flipping `timestamp.to_be_bytes()` in `signable_bytes()`
    /// so a VALID JSON record fails signature verification — and the verify CLI's
    /// primary `--record` input is JSON. These literals demonstrably did NOT
    /// round-trip with the feature off (captured from a live divergence probe),
    /// so they pin it ON deterministically — never a ~12% flake.
    #[test]
    fn f64_timestamp_round_trips_through_json_bit_exact() {
        let pinned = [1_781_560_154.611_071_3_f64, 1_781_560_154.735_918_5_f64];
        for t in pinned {
            let j = serde_json::to_string(&t).unwrap();
            let back: f64 = serde_json::from_str(&j).unwrap();
            assert_eq!(
                t.to_bits(),
                back.to_bits(),
                "f64 {t:?} must JSON round-trip bit-exact (serde_json float_roundtrip \
                 feature missing?) — got {back:?} via {j}"
            );
        }

        // Full record path: a fixed-timestamp record's signable_bytes must survive
        // a JSON round-trip unchanged — the signature-verification invariant the
        // verify CLI depends on when it parses a record from JSON.
        let mut rec = ValidationRecord::create(
            b"round-trip",
            vec![9, 9, 9],
            vec![],
            Classification::Public,
            None,
        );
        rec.timestamp = 1_781_560_154.611_071_3;
        let before = rec.signable_bytes();
        let j = serde_json::to_string(&rec).unwrap();
        let back: ValidationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(
            before,
            back.signable_bytes(),
            "record signable_bytes must be stable across a JSON round-trip"
        );
    }

    /// Companion to `f64_timestamp_round_trips_through_json_bit_exact`, but on the
    /// metadata dimension — the one seals actually use. Epoch seals carry f64
    /// `epoch_start`/`epoch_end` in `metadata` (see `network/epoch.rs`), and
    /// `signable_bytes()` re-serializes metadata to JSON. So every node that
    /// verifies a seal must reconstruct byte-identical `signable_bytes`, or the
    /// seal signature fails and the node rejects the authority's valid seal — a
    /// silent fork / follower-stall, exactly the path a first external follower hits.
    /// Pins that invariant across BOTH the production binary wire (seal gossip,
    /// where `encode_metadata_binary` must preserve the f64 bits *and* the
    /// float-vs-int type tag) and the JSON path (verify CLI / REST shapes, which
    /// lean on serde_json's `float_roundtrip` feature).
    #[test]
    fn f64_metadata_round_trips_with_stable_signable_bytes() {
        let mut meta = BTreeMap::new();
        // High-precision fractional floats — real `as_secs_f64()` seal timestamps,
        // the 1-ULP-sensitive case the JSON parse path depends on float_roundtrip for.
        meta.insert("epoch_start".to_string(), serde_json::json!(1_781_560_154.611_071_3_f64));
        meta.insert("epoch_end".to_string(), serde_json::json!(1_781_560_154.735_918_5_f64));
        // Integral-VALUED float: must stay a float so it serializes as "1741000000.0",
        // matching the creator. Guards a future codec change from collapsing the
        // float/int tag (which would silently change signable_bytes => signature break).
        meta.insert("epoch_integral".to_string(), serde_json::json!(1_741_000_000.0_f64));

        let mut rec = ValidationRecord::create(
            b"seal-metadata-float",
            dummy_pk(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        rec.timestamp = 1_781_560_154.611_071_3;
        let before = rec.signable_bytes();
        assert!(!before.is_empty());

        // Production seal-propagation path: binary wire round-trip.
        let wire = rec.to_bytes();
        let from_wire = ValidationRecord::from_bytes(&wire).expect("binary wire must decode");
        assert_eq!(
            before,
            from_wire.signable_bytes(),
            "f64 metadata must survive the binary wire with byte-identical signable_bytes \
             — that is the seal-signature input every node re-derives"
        );
        assert!(
            from_wire.metadata.get("epoch_integral").unwrap().is_f64(),
            "integral-valued metadata float must decode as a float (META_FLOAT), not META_INT"
        );

        // Verify-CLI / REST path: JSON round-trip (depends on serde_json float_roundtrip).
        let j = serde_json::to_string(&rec).unwrap();
        let from_json: ValidationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(
            before,
            from_json.signable_bytes(),
            "f64 metadata signable_bytes must be stable across a JSON round-trip \
             (serde_json float_roundtrip feature missing?)"
        );
    }
}
