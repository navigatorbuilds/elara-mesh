//! ELRA binary wire format — byte-identical to the Python Layer 1 implementation.
//!
//! Wire format layout:
//! ```text
//! [ELRA][version:2][type:1][reserved:1]  — 8-byte header
//! [id_len:1][id:N]                       — UUID v7
//! [content_hash:32]                      — SHA3-256
//! [pk_len:2][public_key:N]               — Dilithium3 public key
//! [timestamp:8]                          — IEEE 754 double, big-endian
//! [num_parents:2][parent_ids...]         — DAG edges (each: [len:1][id:N])
//! [classification:1]                     — 0=PUBLIC, 1=PRIVATE, 2=RESTRICTED, 3=SOVEREIGN
//! [meta_len:4][metadata:N]              — sorted compact JSON
//! [zk_len:4][zk_proof:N]               — ZK proof (future)
//! [sig_len:2][signature:N]              — Dilithium3 signature
//! [sphincs_len:2][sphincs_sig:N]        — SPHINCS+ signature
//! ```

//!
//! Spec references:
//!   @spec Protocol §3.3.4

use crate::{RecordError, Result};

pub const MAGIC: &[u8; 4] = b"ELRA";
/// Wire format version.
/// v5 (2026-04-16): added `nonce: u64` as a first-class signed field
/// for slot mutual exclusion (MESH-BFT Phase 3 Stage 1). Slot = (account, nonce)
/// (zone deliberately excluded — see `ValidationRecord::slot_key`);
/// at most one record per slot finalizes. v4 records are backward-readable but cannot
/// participate in slot-enforcement — nonce defaults to 0 and they're exempt from the
/// slot check until migrated.
pub const WIRE_VERSION: u16 = 5;
/// Minimum wire version we can read (backward compat).
pub const WIRE_VERSION_MIN: u16 = 1;
pub const HEADER_SIZE: usize = 8; // 4 (magic) + 2 (version) + 1 (type) + 1 (reserved)
/// Maximum metadata entries per record. Limits decode-time allocation.
pub const MAX_METADATA_ENTRIES: usize = 256;
/// Maximum nesting depth for metadata array/object values.
/// A Byzantine peer sending arbitrarily nested arrays can overflow the
/// call stack; cap recursion before it starts.
pub const MAX_METADATA_DEPTH: usize = 8;

/// Encode a record header with the caller-supplied wire version.
///
/// **Why version is a parameter, not the constant `WIRE_VERSION`:**
/// `to_bytes()` is also the round-trip / re-emit path for stored records.
/// A record whose `self.version == 4` (signed under the v4 signable_bytes
/// formula — no nonce) MUST keep its on-wire version field equal to 4 when
/// re-serialized. Stamping the current `WIRE_VERSION` (5) here while
/// `to_bytes()` still skips the v5 nonce extension — and `signable_bytes()`
/// still computes the v4 signing input — produced "zombie" records on
/// disk: header claims v5, signature is over v4 inputs, next decoder reads
/// version=5 and adds a (zero) nonce to the signing input, signature
/// verification fails. ARCH-4 surfaced this fleet-wide on 2026-04-28.
pub fn encode_header(buf: &mut Vec<u8>, version: u16) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&version.to_be_bytes());
    buf.push(0x01); // record_type
    buf.push(0x00); // reserved
}

/// Encode a length-prefixed byte field with u8 length prefix.
pub fn encode_u8_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

/// Encode a length-prefixed byte field with u16 (big-endian) length prefix.
/// Panics if data exceeds 65,535 bytes (prevents silent truncation).
pub fn encode_u16_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    assert!(
        data.len() <= u16::MAX as usize,
        "encode_u16_prefixed: data too large ({} bytes, max {})",
        data.len(),
        u16::MAX
    );
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode a length-prefixed byte field with u32 (big-endian) length prefix.
pub fn encode_u32_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode an f64 timestamp as big-endian IEEE 754.
pub fn encode_timestamp(buf: &mut Vec<u8>, ts: f64) {
    buf.extend_from_slice(&ts.to_be_bytes());
}

/// Encode optional bytes with u16 prefix (0 length if None).
pub fn encode_optional_u16(buf: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) => encode_u16_prefixed(buf, d),
        None => buf.extend_from_slice(&0u16.to_be_bytes()),
    }
}

/// Encode optional bytes with u32 prefix (0 length if None).
pub fn encode_optional_u32(buf: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) => encode_u32_prefixed(buf, d),
        None => buf.extend_from_slice(&0u32.to_be_bytes()),
    }
}

/// A cursor for reading wire-format bytes.
pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Get a slice of remaining unread bytes. Fail-closed: if the cursor was
    /// advanced past the end (see `advance`), return an empty slice rather
    /// than panicking on an out-of-range slice index.
    pub fn remaining_bytes(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Advance the cursor by n bytes (for externally-parsed data). `n` may be
    /// derived from attacker-controlled bytes (e.g. a `consumed` count from a
    /// sub-decoder), so saturate: the cursor can never wrap a 32-bit `usize`,
    /// and a read past the end fails closed via `read_bytes`/`remaining_bytes`.
    pub fn advance(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        // Overflow-safe bounds check. `n` may be an attacker-controlled length
        // prefix — up to ~4.3 GB from a u32 (`read_u32_prefixed`/`_optional_u32`,
        // e.g. a gossiped record's zk_proof field). On a 32-bit `usize` (in scope
        // under the phone-tier hardware floor) `self.pos + n` would wrap, pass a
        // naive `> data.len()` check, and panic the slice (start > end). checked_add
        // rejects at the boundary instead; a no-op on 64-bit, where pos+n over a
        // few-MB buffer cannot wrap.
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len());
        let Some(end) = end else {
            return Err(RecordError::Wire(format!(
                "unexpected EOF at offset {}, need {} bytes",
                self.pos, n
            )));
        };
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        let bytes = self.read_bytes(8)?;
        Ok(f64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a field with u8 length prefix.
    pub fn read_u8_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u8()? as usize;
        self.read_bytes(len)
    }

    /// Read a field with u16 length prefix.
    pub fn read_u16_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    /// Read a field with u32 length prefix.
    pub fn read_u32_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }

    /// Read optional bytes with u16 length prefix (returns None if length is 0).
    pub fn read_optional_u16(&mut self) -> Result<Option<Vec<u8>>> {
        let len = self.read_u16()? as usize;
        if len == 0 {
            Ok(None)
        } else {
            let data = self.read_bytes(len)?;
            Ok(Some(data.to_vec()))
        }
    }

    /// Read optional bytes with u32 length prefix.
    pub fn read_optional_u32(&mut self) -> Result<Option<Vec<u8>>> {
        let len = self.read_u32()? as usize;
        if len == 0 {
            Ok(None)
        } else {
            let data = self.read_bytes(len)?;
            Ok(Some(data.to_vec()))
        }
    }

    /// Validate the wire header, returning (version, record_type).
    pub fn read_header(&mut self) -> Result<(u16, u8)> {
        let magic = self.read_bytes(4)?;
        if magic != MAGIC {
            return Err(RecordError::Wire(format!("invalid magic: {:?}", magic)));
        }
        let version = self.read_u16()?;
        if !(WIRE_VERSION_MIN..=WIRE_VERSION).contains(&version) {
            return Err(RecordError::Wire(format!(
                "unsupported wire version: {version} (supported: {WIRE_VERSION_MIN}-{WIRE_VERSION})"
            )));
        }
        let rec_type = self.read_u8()?;
        let _reserved = self.read_u8()?;
        Ok((version, rec_type))
    }
}

// ── Binary metadata encoding (v4+) ──────────────────────────────────────
// Type tags for serde_json::Value variants:
const META_NULL: u8 = 0;
const META_BOOL: u8 = 1;
const META_INT: u8 = 2;   // i64 BE
const META_FLOAT: u8 = 3; // f64 BE
const META_STRING: u8 = 4; // u16-prefixed UTF-8
const META_ARRAY: u8 = 5;  // u16 count + values
const META_OBJECT: u8 = 6; // u16 count + key-value pairs

/// Encode a BTreeMap<String, serde_json::Value> as binary.
/// Format: u16 entry count, then for each: u8-prefixed key + type tag + value.
///
/// Returns a typed error when any length would overflow its wire prefix
/// (entry/array/object count or string byte-length > u16::MAX, key
/// byte-length > u8::MAX) instead of silently wrapping — a wrapped count
/// desynchronizes every field after the metadata block, so the decoder
/// misreads signature/zone_refs bytes as metadata (R3-8 slice 1).
/// Unreachable through current caps (every decode path caps at
/// `MAX_METADATA_ENTRIES` = 256 and ingest per-value size gates bind far
/// lower); defense-in-depth for future local builders. On `Err` the buffer
/// may hold a partial metadata block — callers must rewind to their
/// pre-call length before reusing it.
pub fn encode_metadata_binary(buf: &mut Vec<u8>, metadata: &std::collections::BTreeMap<String, serde_json::Value>) -> Result<()> {
    if metadata.len() > u16::MAX as usize {
        return Err(RecordError::Wire(format!(
            "metadata entry count {} overflows u16 length prefix (max {})",
            metadata.len(),
            u16::MAX
        )));
    }
    buf.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    for (key, val) in metadata {
        encode_metadata_key(buf, key)?;
        encode_json_value(buf, val)?;
    }
    Ok(())
}

/// Encode a metadata map key with its u8 length prefix. Typed error above
/// u8::MAX — `encode_u8_prefixed` would wrap the prefix (same corruption
/// class as the u16 count wrap).
fn encode_metadata_key(buf: &mut Vec<u8>, key: &str) -> Result<()> {
    if key.len() > u8::MAX as usize {
        return Err(RecordError::Wire(format!(
            "metadata key length {} overflows u8 length prefix (max {})",
            key.len(),
            u8::MAX
        )));
    }
    encode_u8_prefixed(buf, key.as_bytes());
    Ok(())
}

fn encode_json_value(buf: &mut Vec<u8>, val: &serde_json::Value) -> Result<()> {
    match val {
        serde_json::Value::Null => buf.push(META_NULL),
        serde_json::Value::Bool(b) => { buf.push(META_BOOL); buf.push(*b as u8); }
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.push(META_INT);
                buf.extend_from_slice(&i.to_be_bytes());
            } else if let Some(f) = n.as_f64() {
                buf.push(META_FLOAT);
                buf.extend_from_slice(&f.to_be_bytes());
            } else {
                buf.push(META_NULL); // fallback
            }
        }
        serde_json::Value::String(s) => {
            if s.len() > u16::MAX as usize {
                return Err(RecordError::Wire(format!(
                    "metadata string length {} overflows u16 length prefix (max {})",
                    s.len(),
                    u16::MAX
                )));
            }
            buf.push(META_STRING);
            encode_u16_prefixed(buf, s.as_bytes());
        }
        serde_json::Value::Array(arr) => {
            if arr.len() > u16::MAX as usize {
                return Err(RecordError::Wire(format!(
                    "metadata array count {} overflows u16 length prefix (max {})",
                    arr.len(),
                    u16::MAX
                )));
            }
            buf.push(META_ARRAY);
            buf.extend_from_slice(&(arr.len() as u16).to_be_bytes());
            for item in arr {
                encode_json_value(buf, item)?;
            }
        }
        serde_json::Value::Object(obj) => {
            if obj.len() > u16::MAX as usize {
                return Err(RecordError::Wire(format!(
                    "metadata object count {} overflows u16 length prefix (max {})",
                    obj.len(),
                    u16::MAX
                )));
            }
            buf.push(META_OBJECT);
            buf.extend_from_slice(&(obj.len() as u16).to_be_bytes());
            for (k, v) in obj {
                encode_metadata_key(buf, k)?;
                encode_json_value(buf, v)?;
            }
        }
    }
    Ok(())
}

/// Decode binary metadata. Returns BTreeMap<String, serde_json::Value>.
pub fn decode_metadata_binary(reader: &mut WireReader) -> Result<std::collections::BTreeMap<String, serde_json::Value>> {
    let count = reader.read_u16()? as usize;
    if count > MAX_METADATA_ENTRIES {
        return Err(RecordError::Wire(format!("too many metadata entries: {count} (max {MAX_METADATA_ENTRIES})")));
    }
    let mut map = std::collections::BTreeMap::new();
    for _ in 0..count {
        let key_bytes = reader.read_u8_prefixed()?;
        let key = std::str::from_utf8(key_bytes)
            .map_err(|e| RecordError::Wire(format!("invalid metadata key: {e}")))?
            .to_string();
        let val = decode_json_value(reader, 0)?;
        map.insert(key, val);
    }
    Ok(map)
}

fn decode_json_value(reader: &mut WireReader, depth: usize) -> Result<serde_json::Value> {
    if depth > MAX_METADATA_DEPTH {
        return Err(RecordError::Wire(format!(
            "metadata nesting depth {depth} exceeds limit {MAX_METADATA_DEPTH}"
        )));
    }
    let tag = reader.read_u8()?;
    match tag {
        META_NULL => Ok(serde_json::Value::Null),
        META_BOOL => Ok(serde_json::Value::Bool(reader.read_u8()? != 0)),
        META_INT => {
            let bytes = reader.read_bytes(8)?;
            let arr = <[u8; 8]>::try_from(bytes)
                .map_err(|_| RecordError::Wire("int tag: expected 8 bytes".to_string()))?;
            Ok(serde_json::json!(i64::from_be_bytes(arr)))
        }
        META_FLOAT => {
            let bytes = reader.read_bytes(8)?;
            let arr = <[u8; 8]>::try_from(bytes)
                .map_err(|_| RecordError::Wire("float tag: expected 8 bytes".to_string()))?;
            let f = f64::from_be_bytes(arr);
            if !f.is_finite() {
                return Err(RecordError::Wire(format!(
                    "metadata float is non-finite (NaN/Inf): {f:?}"
                )));
            }
            Ok(serde_json::json!(f))
        }
        META_STRING => {
            let s_bytes = reader.read_u16_prefixed()?;
            let s = std::str::from_utf8(s_bytes)
                .map_err(|e| RecordError::Wire(format!("invalid metadata string: {e}")))?
                .to_string();
            Ok(serde_json::Value::String(s))
        }
        META_ARRAY => {
            let count = reader.read_u16()? as usize;
            if count > MAX_METADATA_ENTRIES {
                return Err(RecordError::Wire(format!(
                    "metadata array too large: {count} (max {MAX_METADATA_ENTRIES})"
                )));
            }
            let mut arr = Vec::with_capacity(count);
            for _ in 0..count {
                arr.push(decode_json_value(reader, depth + 1)?);
            }
            Ok(serde_json::Value::Array(arr))
        }
        META_OBJECT => {
            let count = reader.read_u16()? as usize;
            if count > MAX_METADATA_ENTRIES {
                return Err(RecordError::Wire(format!(
                    "metadata object too large: {count} (max {MAX_METADATA_ENTRIES})"
                )));
            }
            let mut obj = serde_json::Map::new();
            for _ in 0..count {
                let k_bytes = reader.read_u8_prefixed()?;
                let k = std::str::from_utf8(k_bytes)
                    .map_err(|e| RecordError::Wire(format!("invalid metadata obj key: {e}")))?
                    .to_string();
                let v = decode_json_value(reader, depth + 1)?;
                obj.insert(k, v);
            }
            Ok(serde_json::Value::Object(obj))
        }
        _ => Err(RecordError::Wire(format!("unknown metadata type tag: {tag}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let mut buf = Vec::new();
        encode_header(&mut buf, WIRE_VERSION);
        assert_eq!(buf.len(), HEADER_SIZE);
        assert_eq!(&buf[0..4], MAGIC);

        let mut reader = WireReader::new(&buf);
        let (version, rec_type) = reader.read_header().unwrap();
        assert_eq!(version, WIRE_VERSION);
        assert_eq!(rec_type, 0x01);
    }

    #[test]
    fn advance_past_end_is_fail_closed_not_panic() {
        // `advance(n)` takes an externally-derived count (e.g. a sub-decoder's
        // `consumed`) that may be attacker-influenced. Over-advancing must not
        // wrap the cursor or panic a later slice: remaining_bytes() returns
        // empty and read_bytes() returns EOF instead of indexing out of range.
        let buf = [1u8, 2, 3, 4];
        let mut reader = WireReader::new(&buf);
        reader.advance(usize::MAX); // saturates; cursor now past end
        assert!(reader.remaining_bytes().is_empty(), "must not slice past end");
        assert_eq!(reader.remaining(), 0, "saturating_sub keeps this at 0");
        assert!(reader.read_bytes(1).is_err(), "read past end must be EOF, not panic");
    }

    /// Regression for the ARCH-4 zombie pattern: encode_header must honor the
    /// caller's version, NOT silently stamp the current WIRE_VERSION. A v4
    /// record re-emitted via to_bytes() must keep version=4 on the wire so the
    /// peer's decoder reproduces v4 signable_bytes (no nonce) and the original
    /// signature still verifies.
    #[test]
    fn test_header_encode_preserves_caller_version() {
        for v in WIRE_VERSION_MIN..=WIRE_VERSION {
            let mut buf = Vec::new();
            encode_header(&mut buf, v);
            let mut reader = WireReader::new(&buf);
            let (decoded, _ty) = reader.read_header().expect("decode");
            assert_eq!(decoded, v, "header version round-trip failed for v={v}");
        }
    }

    #[test]
    fn test_u8_prefixed() {
        let mut buf = Vec::new();
        encode_u8_prefixed(&mut buf, b"hello");
        assert_eq!(buf.len(), 6); // 1 + 5

        let mut reader = WireReader::new(&buf);
        let data = reader.read_u8_prefixed().unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_u16_prefixed() {
        let mut buf = Vec::new();
        let key = vec![0xAB; 1952]; // Dilithium3 pk size
        encode_u16_prefixed(&mut buf, &key);
        assert_eq!(buf.len(), 1954); // 2 + 1952

        let mut reader = WireReader::new(&buf);
        let data = reader.read_u16_prefixed().unwrap();
        assert_eq!(data.len(), 1952);
    }

    #[test]
    fn test_timestamp_encode_decode() {
        let mut buf = Vec::new();
        let ts = 1739712345.123456;
        encode_timestamp(&mut buf, ts);
        assert_eq!(buf.len(), 8);

        let mut reader = WireReader::new(&buf);
        let decoded = reader.read_f64().unwrap();
        assert_eq!(decoded, ts);
    }

    #[test]
    fn test_invalid_magic() {
        let buf = b"NOPE\x00\x01\x01\x00";
        let mut reader = WireReader::new(buf);
        assert!(reader.read_header().is_err());
    }

    // ── wire-format primitive axes ──────────────────────────────────────
    // Five fixture-free axes pinning the wire-format primitives that the
    // earlier 6-test surface covered only at happy-path / single-value
    // granularity:
    //   1. module constants (MAGIC bytes, WIRE_VERSION=5, WIRE_VERSION_MIN=1,
    //      HEADER_SIZE=8, MAX_METADATA_ENTRIES=256, META_* tags 0..=6)
    //   2. encode_u16_prefixed u16::MAX boundary (clean encode) + u16::MAX+1
    //      (assertion-panic, prevents silent truncation)
    //   3. encode_optional_u16/u32 wire-shape: None and Some(empty) are
    //      byte-identical; both decode to None (asymmetric semantics)
    //   4. read_header rejects versions outside [WIRE_VERSION_MIN, WIRE_VERSION]
    //      (existing test_invalid_magic only covers wrong magic)
    //   5. encode/decode_metadata_binary round-trip across all 7 META_*
    //      variants + decode-side guards on overcount + unknown tag

    #[test]
    fn batch_b_wire_module_constants_pinned_to_literal_values() {
        // MAGIC — load-bearing protocol identifier sent on every record header.
        // A coordinated edit (MAGIC + read_header check) would silently fork the
        // wire protocol; pinning the literal bytes blocks that.
        assert_eq!(MAGIC, b"ELRA");
        assert_eq!(MAGIC.len(), 4);

        // WIRE_VERSION literal — v5 (MESH-BFT Phase 3 Stage 1A, nonce field).
        // Bumping silently would re-write every fresh record's on-wire version
        // field while signable_bytes() still uses the prior formula, re-triggering
        // the ARCH-4 zombie pattern (header v5, sig over v4 inputs).
        assert_eq!(WIRE_VERSION, 5);

        // WIRE_VERSION_MIN — backward-compat floor for read_header.
        assert_eq!(WIRE_VERSION_MIN, 1);

        // HEADER_SIZE — 4 (MAGIC) + 2 (version) + 1 (type) + 1 (reserved).
        // Wire-shape load-bearing for fixed-offset readers.
        assert_eq!(HEADER_SIZE, 8);
        assert_eq!(HEADER_SIZE, MAGIC.len() + 2 + 1 + 1);

        // MAX_METADATA_ENTRIES — decode-side allocation cap (DoS guard).
        assert_eq!(MAX_METADATA_ENTRIES, 256);

        // META_* type tags 0..=6 (no gaps, sequence stable). The tag values
        // are wire-format-load-bearing; reordering would silently mis-decode
        // already-stored records.
        assert_eq!(META_NULL, 0);
        assert_eq!(META_BOOL, 1);
        assert_eq!(META_INT, 2);
        assert_eq!(META_FLOAT, 3);
        assert_eq!(META_STRING, 4);
        assert_eq!(META_ARRAY, 5);
        assert_eq!(META_OBJECT, 6);
    }

    #[test]
    fn batch_b_encode_u16_prefixed_at_u16_max_boundary_and_panic_above() {
        // u16::MAX-byte body is the boundary clean-encode case (no truncation).
        let max_data = vec![0xAA_u8; u16::MAX as usize];
        let mut buf = Vec::new();
        encode_u16_prefixed(&mut buf, &max_data);
        assert_eq!(buf.len(), u16::MAX as usize + 2);
        assert_eq!(&buf[0..2], &u16::MAX.to_be_bytes());

        // Round-trip via read_u16_prefixed reproduces exactly.
        let mut reader = WireReader::new(&buf);
        let decoded = reader.read_u16_prefixed().unwrap();
        assert_eq!(decoded.len(), u16::MAX as usize);
        assert_eq!(decoded[0], 0xAA);
        assert_eq!(decoded[u16::MAX as usize - 1], 0xAA);

        // u16::MAX + 1 bytes MUST panic — silent (data.len() as u16) truncation
        // would wrap the length prefix to 0 and leave the body unread, corrupting
        // every downstream field.
        let oversize = vec![0u8; u16::MAX as usize + 1];
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(move || {
            let mut buf = Vec::new();
            encode_u16_prefixed(&mut buf, &oversize);
        });
        std::panic::set_hook(prev_hook);
        assert!(result.is_err(), "encode_u16_prefixed must panic above u16::MAX");
    }

    #[test]
    fn batch_b_optional_u16_u32_none_and_empty_some_are_wire_indistinguishable() {
        // None encodes as 2 literal zero bytes (length prefix present, body
        // absent). NOT an omission — field position is fixed for downstream
        // offsets.
        let mut buf_none = Vec::new();
        encode_optional_u16(&mut buf_none, None);
        assert_eq!(buf_none, vec![0x00, 0x00]);

        // Some(&[]) ALSO emits 2 zero bytes — byte-identical to None. Decode
        // collapses both to None (empty Some is unrepresentable on the wire).
        // Pinned to prevent a refactor from differentiating them (which would
        // break the backward-compat read path).
        let mut buf_empty = Vec::new();
        encode_optional_u16(&mut buf_empty, Some(&[]));
        assert_eq!(buf_empty, buf_none);

        // Decode: both collapse to None.
        let mut r_none = WireReader::new(&buf_none);
        assert_eq!(r_none.read_optional_u16().unwrap(), None);
        let mut r_empty = WireReader::new(&buf_empty);
        assert_eq!(r_empty.read_optional_u16().unwrap(), None);

        // Non-empty Some round-trips: encode(Some(b"x")) → [0x00, 0x01, b'x'].
        let mut buf_some = Vec::new();
        encode_optional_u16(&mut buf_some, Some(b"x"));
        assert_eq!(buf_some, vec![0x00, 0x01, b'x']);
        let mut r_some = WireReader::new(&buf_some);
        assert_eq!(r_some.read_optional_u16().unwrap(), Some(b"x".to_vec()));

        // Same contract for u32: None / Some(empty) both emit 4 zero bytes.
        let mut buf_none_u32 = Vec::new();
        encode_optional_u32(&mut buf_none_u32, None);
        assert_eq!(buf_none_u32, vec![0x00, 0x00, 0x00, 0x00]);
        let mut buf_empty_u32 = Vec::new();
        encode_optional_u32(&mut buf_empty_u32, Some(&[]));
        assert_eq!(buf_empty_u32, buf_none_u32);
        let mut r = WireReader::new(&buf_empty_u32);
        assert_eq!(r.read_optional_u32().unwrap(), None);

        // Non-empty Some u32 round-trips.
        let mut buf_some_u32 = Vec::new();
        encode_optional_u32(&mut buf_some_u32, Some(b"yz"));
        assert_eq!(buf_some_u32, vec![0x00, 0x00, 0x00, 0x02, b'y', b'z']);
        let mut r = WireReader::new(&buf_some_u32);
        assert_eq!(r.read_optional_u32().unwrap(), Some(b"yz".to_vec()));
    }

    #[test]
    fn batch_b_read_header_rejects_versions_outside_supported_range() {
        // Forge a header buffer with an arbitrary version field (bypassing
        // encode_header's caller-version-stamping path).
        fn forge_header(version: u16) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(MAGIC);
            buf.extend_from_slice(&version.to_be_bytes());
            buf.push(0x01); // record_type
            buf.push(0x00); // reserved
            buf
        }

        // version=0 (below WIRE_VERSION_MIN=1) rejected — error mentions both
        // the literal version and the supported range.
        let buf = forge_header(0);
        let mut r = WireReader::new(&buf);
        let err = r.read_header().unwrap_err();
        let err_msg = format!("{err}");
        assert!(err_msg.contains("unsupported wire version"), "got: {err_msg}");
        assert!(err_msg.contains('0'), "version literal missing from: {err_msg}");

        // version=WIRE_VERSION+1 rejected (above current supported max).
        let buf = forge_header(WIRE_VERSION + 1);
        let mut r = WireReader::new(&buf);
        let err = r.read_header().unwrap_err();
        assert!(format!("{err}").contains("unsupported wire version"));

        // version=u16::MAX rejected (far-above sanity).
        let buf = forge_header(u16::MAX);
        let mut r = WireReader::new(&buf);
        assert!(r.read_header().is_err());

        // Boundary-pair sanity: WIRE_VERSION_MIN and WIRE_VERSION both accepted.
        // (test_header_encode_preserves_caller_version covers this for current
        // values; re-pinned here so a future MIN/MAX shift surfaces in BOTH
        // tests, not just the accept-path one.)
        let buf = forge_header(WIRE_VERSION_MIN);
        let mut r = WireReader::new(&buf);
        assert_eq!(r.read_header().unwrap(), (WIRE_VERSION_MIN, 0x01));
        let buf = forge_header(WIRE_VERSION);
        let mut r = WireReader::new(&buf);
        assert_eq!(r.read_header().unwrap(), (WIRE_VERSION, 0x01));
    }

    #[test]
    fn batch_b_metadata_roundtrip_seven_variants_plus_decode_guards() {
        use serde_json::{json, Value};
        use std::collections::BTreeMap;

        // Build a BTreeMap covering all 7 META_* tag variants (Null/Bool/Int/
        // Float/String/Array/Object). Round-trip via encode + decode and assert
        // bit-equality.
        let mut meta: BTreeMap<String, Value> = BTreeMap::new();
        meta.insert("a_null".to_string(), Value::Null);
        meta.insert("b_bool_t".to_string(), Value::Bool(true));
        meta.insert("b_bool_f".to_string(), Value::Bool(false));
        meta.insert("c_int_pos".to_string(), json!(42));
        meta.insert("c_int_neg".to_string(), json!(-1_234_567_890_i64));
        // 2.5 has exact binary repr; .as_i64() returns None → routes through
        // the META_FLOAT branch (NOT the INT branch).
        meta.insert("d_float".to_string(), json!(2.5_f64));
        meta.insert("e_string".to_string(), Value::String("hello-utf8-ñ".to_string()));
        meta.insert("f_array".to_string(), json!([1, "two", true, null]));
        meta.insert("g_object".to_string(), json!({"nested": "value", "n": 5}));

        let mut buf = Vec::new();
        encode_metadata_binary(&mut buf, &meta).unwrap();
        let mut reader = WireReader::new(&buf);
        let decoded = decode_metadata_binary(&mut reader).unwrap();
        assert_eq!(decoded, meta, "metadata round-trip failed across 7 variants");
        assert_eq!(reader.remaining(), 0, "metadata buffer not fully consumed");

        // Decode-side guard: count > MAX_METADATA_ENTRIES rejected (DoS cap).
        let mut bad_count = Vec::new();
        bad_count.extend_from_slice(&((MAX_METADATA_ENTRIES + 1) as u16).to_be_bytes());
        let mut reader = WireReader::new(&bad_count);
        let err = decode_metadata_binary(&mut reader).unwrap_err();
        assert!(format!("{err}").contains("too many metadata entries"));

        // Decode-side guard: unknown type tag rejected (forward-compat shield).
        // Valid tags are 0..=6; tag=99 must error.
        let mut bad_tag = Vec::new();
        bad_tag.extend_from_slice(&1u16.to_be_bytes()); // count=1
        bad_tag.push(1); // key_len=1
        bad_tag.push(b'k'); // key
        bad_tag.push(99); // unknown tag (valid range 0..=6)
        let mut reader = WireReader::new(&bad_tag);
        let err = decode_metadata_binary(&mut reader).unwrap_err();
        assert!(format!("{err}").contains("unknown metadata type tag"));
    }

    #[test]
    fn decode_json_value_truncated_int_and_float_return_error_not_panic() {
        // META_INT / META_FLOAT each expect exactly 8 bytes of payload.
        // Truncated payloads must return Err, not panic.
        fn make_buf(tag: u8, payload: &[u8]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // count=1
            v.push(1); v.push(b'k');                  // key="k"
            v.push(tag);
            v.extend_from_slice(payload);
            v
        }
        let buf = make_buf(META_INT, &[0u8; 4]);
        let mut reader = WireReader::new(&buf);
        assert!(decode_metadata_binary(&mut reader).is_err(), "truncated int must error");

        let buf = make_buf(META_FLOAT, &[0u8; 4]);
        let mut reader = WireReader::new(&buf);
        assert!(decode_metadata_binary(&mut reader).is_err(), "truncated float must error");

        let buf = make_buf(META_INT, &42i64.to_be_bytes());
        let mut reader = WireReader::new(&buf);
        assert!(decode_metadata_binary(&mut reader).is_ok(), "full int must parse");

        let buf = make_buf(META_FLOAT, &1.5f64.to_be_bytes());
        let mut reader = WireReader::new(&buf);
        assert!(decode_metadata_binary(&mut reader).is_ok(), "full float must parse");
    }

    #[test]
    fn decode_metadata_non_finite_float_returns_error_not_panic() {
        // A Byzantine peer can craft bytes that decode to NaN or Infinity.
        // serde_json::to_string panics on non-finite f64 values, so we must
        // reject them at wire-decode time before they reach signable_bytes().
        fn make_float_buf(f: f64) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // count=1
            v.push(1); v.push(b'k');                  // key="k"
            v.push(META_FLOAT);
            v.extend_from_slice(&f.to_be_bytes());
            v
        }
        let nan_buf = make_float_buf(f64::NAN);
        let mut r = WireReader::new(&nan_buf);
        let err = decode_metadata_binary(&mut r).unwrap_err();
        assert!(format!("{err}").contains("non-finite"), "NaN must produce non-finite error, got: {err}");

        let inf_buf = make_float_buf(f64::INFINITY);
        let mut r = WireReader::new(&inf_buf);
        assert!(decode_metadata_binary(&mut r).is_err(), "Infinity must error");

        let neg_inf_buf = make_float_buf(f64::NEG_INFINITY);
        let mut r = WireReader::new(&neg_inf_buf);
        assert!(decode_metadata_binary(&mut r).is_err(), "NegInfinity must error");

        // Finite floats still decode cleanly. (Arbitrary finite value — not π;
        // a 3.14 literal trips clippy::approx_constant for no reason here.)
        let ok_buf = make_float_buf(2.5_f64);
        let mut r = WireReader::new(&ok_buf);
        assert!(decode_metadata_binary(&mut r).is_ok(), "finite float must still decode");
    }

    #[test]
    fn decode_metadata_deeply_nested_array_returns_error_not_stack_overflow() {
        // A Byzantine peer can craft metadata with arbitrarily nested arrays.
        // Without a depth cap, this recurses until the stack overflows.
        // Verify that exactly MAX_METADATA_DEPTH levels is accepted and
        // MAX_METADATA_DEPTH+1 levels is rejected with a typed error.
        fn make_nested_array_buf(levels: usize) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // outer count=1
            v.push(1); v.push(b'k');                  // key="k"
            for _ in 0..levels {
                v.push(META_ARRAY);
                v.extend_from_slice(&1u16.to_be_bytes()); // array count=1
            }
            v.push(META_NULL); // innermost element
            v
        }

        // MAX_METADATA_DEPTH levels must succeed.
        let ok_buf = make_nested_array_buf(MAX_METADATA_DEPTH);
        let mut r = WireReader::new(&ok_buf);
        assert!(decode_metadata_binary(&mut r).is_ok(), "depth={MAX_METADATA_DEPTH} must be accepted");

        // MAX_METADATA_DEPTH+1 levels must error with a nesting-depth message.
        let bad_buf = make_nested_array_buf(MAX_METADATA_DEPTH + 1);
        let mut r = WireReader::new(&bad_buf);
        let err = decode_metadata_binary(&mut r).unwrap_err();
        assert!(
            format!("{err}").contains("nesting depth"),
            "expected nesting-depth error, got: {err}",
        );
    }

    #[test]
    fn decode_json_value_inner_array_and_object_over_limit_return_error() {
        // A Byzantine peer can claim inner array/object counts up to u16::MAX.
        // Both must be rejected with a typed error rather than allocating unboundedly.
        fn make_inner_array_buf(count: u16) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // outer count=1
            v.push(1); v.push(b'k');                  // key="k"
            v.push(META_ARRAY);
            v.extend_from_slice(&count.to_be_bytes());
            // no actual elements — the bounds check must fire before iteration
            v
        }
        fn make_inner_object_buf(count: u16) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes());
            v.push(1); v.push(b'k');
            v.push(META_OBJECT);
            v.extend_from_slice(&count.to_be_bytes());
            v
        }

        let over = (MAX_METADATA_ENTRIES + 1) as u16;

        let err = decode_metadata_binary(&mut WireReader::new(&make_inner_array_buf(over))).unwrap_err();
        assert!(format!("{err}").contains("array too large"), "got: {err}");

        let err = decode_metadata_binary(&mut WireReader::new(&make_inner_object_buf(over))).unwrap_err();
        assert!(format!("{err}").contains("object too large"), "got: {err}");

        // At-limit (count == MAX_METADATA_ENTRIES) must be accepted (no bytes to
        // parse, but the bounds check passes — the error will come from truncation).
        let at_limit = MAX_METADATA_ENTRIES as u16;
        let res = decode_metadata_binary(&mut WireReader::new(&make_inner_array_buf(at_limit)));
        assert!(res.is_err()); // truncated body, not a bounds error
        assert!(!format!("{}", res.unwrap_err()).contains("array too large"));
    }

    #[test]
    fn decode_metadata_invalid_utf8_bytes_return_error_not_panic() {
        // A Byzantine peer can send non-UTF-8 bytes in metadata keys or string
        // values.  All three rejection sites must return Err, never panic.
        let bad_utf8: &[u8] = &[0xFF, 0xFE, 0xFF];

        // Path 1: top-level map key is non-UTF-8.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // count=1
        buf.push(bad_utf8.len() as u8);             // key length prefix (u8)
        buf.extend_from_slice(bad_utf8);            // invalid key bytes
        buf.push(META_NULL);                        // value tag (irrelevant)
        let err = decode_metadata_binary(&mut WireReader::new(&buf)).unwrap_err();
        assert!(format!("{err}").contains("invalid metadata key"), "got: {err}");

        // Path 2: META_STRING value contains non-UTF-8 bytes.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // count=1
        buf.push(1); buf.push(b'k');                // valid key="k"
        buf.push(META_STRING);
        buf.extend_from_slice(&(bad_utf8.len() as u16).to_be_bytes());
        buf.extend_from_slice(bad_utf8);
        let err = decode_metadata_binary(&mut WireReader::new(&buf)).unwrap_err();
        assert!(format!("{err}").contains("invalid metadata string"), "got: {err}");

        // Path 3: key inside a META_OBJECT value is non-UTF-8.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // outer count=1
        buf.push(1); buf.push(b'k');                // outer key="k"
        buf.push(META_OBJECT);
        buf.extend_from_slice(&1u16.to_be_bytes()); // inner count=1
        buf.push(bad_utf8.len() as u8);             // inner key length prefix
        buf.extend_from_slice(bad_utf8);            // invalid inner key bytes
        buf.push(META_NULL);                        // inner value tag
        let err = decode_metadata_binary(&mut WireReader::new(&buf)).unwrap_err();
        assert!(format!("{err}").contains("invalid metadata obj key"), "got: {err}");
    }

    #[test]
    fn read_bytes_rejects_length_overflow_without_panic() {
        // A length prefix can carry a value that overflows `pos + n` on a 32-bit
        // usize, which would pass a naive bounds check and panic the slice
        // (start > end). read_bytes must return Err, never panic. Exercised at the
        // extreme (usize::MAX) so the overflow guard is pinned on every platform —
        // on 64-bit a realistic u32 length can't overflow, so only this extreme
        // distinguishes the checked_add fix from the old `pos + n`.
        let buf = [1u8, 2, 3, 4, 5];
        let mut r = WireReader::new(&buf);
        assert_eq!(r.read_u8().unwrap(), 1); // pos = 1
        assert!(r.read_bytes(usize::MAX).is_err());
        // Cursor unmoved on rejection; the reader is still usable afterward.
        assert_eq!(r.read_u8().unwrap(), 2); // pos = 2
    }

    #[test]
    fn encode_metadata_count_overflow_returns_typed_error_not_silent_wrap() {
        // R3-8 slice 1: every count/length that feeds a u16/u8 wire prefix
        // must produce a typed error above the prefix's range. The old
        // `as u16` silently wrapped (65536 → 0), desynchronizing every
        // field after the metadata block. Unreachable through decode caps
        // (MAX_METADATA_ENTRIES=256) — pinned so a future builder path
        // can't reintroduce the wrap.
        use serde_json::Value;
        use std::collections::BTreeMap;

        // Array count u16::MAX + 1 → typed Wire error naming the array.
        let mut meta = BTreeMap::new();
        meta.insert(
            "k".to_string(),
            Value::Array(vec![Value::Null; u16::MAX as usize + 1]),
        );
        let err = encode_metadata_binary(&mut Vec::new(), &meta).unwrap_err();
        assert!(format!("{err}").contains("array count"), "got: {err}");

        // Object count u16::MAX + 1 → typed error naming the object.
        let mut obj = serde_json::Map::new();
        for i in 0..=(u16::MAX as usize) {
            obj.insert(format!("k{i}"), Value::Null);
        }
        let mut meta = BTreeMap::new();
        meta.insert("k".to_string(), Value::Object(obj));
        let err = encode_metadata_binary(&mut Vec::new(), &meta).unwrap_err();
        assert!(format!("{err}").contains("object count"), "got: {err}");

        // Top-level entry count u16::MAX + 1 → typed error, checked BEFORE
        // any bytes are written (buf stays empty).
        let mut meta = BTreeMap::new();
        for i in 0..=(u16::MAX as usize) {
            meta.insert(format!("k{i}"), Value::Null);
        }
        let mut buf = Vec::new();
        let err = encode_metadata_binary(&mut buf, &meta).unwrap_err();
        assert!(format!("{err}").contains("entry count"), "got: {err}");
        assert!(buf.is_empty(), "top-level guard must fire before writing");

        // String byte-length u16::MAX + 1 → typed error (was an assert-panic
        // inside encode_u16_prefixed; now rejected before the panic site).
        let mut meta = BTreeMap::new();
        meta.insert("k".to_string(), Value::String("y".repeat(u16::MAX as usize + 1)));
        let err = encode_metadata_binary(&mut Vec::new(), &meta).unwrap_err();
        assert!(format!("{err}").contains("string length"), "got: {err}");

        // Key byte-length u8::MAX + 1 → typed error (u8 prefix wrap), both
        // as a top-level map key and inside a nested object.
        let mut meta = BTreeMap::new();
        meta.insert("x".repeat(u8::MAX as usize + 1), Value::Null);
        let err = encode_metadata_binary(&mut Vec::new(), &meta).unwrap_err();
        assert!(format!("{err}").contains("key length"), "got: {err}");

        let mut obj = serde_json::Map::new();
        obj.insert("x".repeat(u8::MAX as usize + 1), Value::Null);
        let mut meta = BTreeMap::new();
        meta.insert("k".to_string(), Value::Object(obj));
        let err = encode_metadata_binary(&mut Vec::new(), &meta).unwrap_err();
        assert!(format!("{err}").contains("key length"), "got: {err}");
    }

    #[test]
    fn encode_metadata_at_u16_boundary_still_encodes() {
        // Exactly u16::MAX array elements is the boundary accept case for the
        // ENCODER (the decoder's MAX_METADATA_ENTRIES=256 cap is a separate,
        // intentionally tighter gate — encode/decode asymmetry is pre-existing).
        use serde_json::Value;
        use std::collections::BTreeMap;
        let mut meta = BTreeMap::new();
        meta.insert(
            "k".to_string(),
            Value::Array(vec![Value::Null; u16::MAX as usize]),
        );
        let mut buf = Vec::new();
        encode_metadata_binary(&mut buf, &meta).unwrap();
        // count prefix for the array is the raw u16::MAX, not a wrap.
        // Layout: [entries:2][key_len:1]['k':1][META_ARRAY:1][count:2]...
        assert_eq!(&buf[5..7], &u16::MAX.to_be_bytes());

        // 255-byte key (u8::MAX boundary) still accepted.
        let mut meta = BTreeMap::new();
        meta.insert("x".repeat(u8::MAX as usize), Value::Null);
        encode_metadata_binary(&mut Vec::new(), &meta).unwrap();
    }

    #[test]
    fn read_optional_u32_rejects_oversized_length_without_panic() {
        // The real attacker path: a u32-prefixed optional field (e.g. a gossiped
        // record's zk_proof) declares ~4.3 GB in a tiny body. Must Err at the
        // decode boundary — no panic, no multi-GB allocation.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes()); // declares 4_294_967_295 bytes
        buf.extend_from_slice(b"tiny");
        let mut r = WireReader::new(&buf);
        assert!(r.read_optional_u32().is_err());
    }
}
