//! Delta sync + snapshot fast sync — Merkle tree + Bloom filter for efficient
//! state synchronization, with a snapshot fast path for nodes that have been
//! offline for extended periods.
//!
//! When delta sync would need >1000 records, the sync loop automatically
//! switches to snapshot fast sync: download records in 500-record chunks,
//! verify the Merkle root against the peer's latest epoch seal, and import
//! in bulk. Supports resume after connection drops via cursor.

//!
//! Spec references:
//!   @spec Protocol §11.4
//!   @spec Protocol §12.2

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};

// ─── Merkle Tree ────────────────────────────────────────────────────────────

/// Binary Merkle tree over sorted SHA3-256 hashes.
pub struct MerkleTree;

impl MerkleTree {
    /// Compute the Merkle root over a sorted slice of 32-byte hashes.
    pub fn root(hashes: &[[u8; 32]]) -> [u8; 32] {
        if hashes.is_empty() {
            return [0u8; 32];
        }
        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut layer: Vec<[u8; 32]> = hashes.to_vec();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            for pair in layer.chunks(2) {
                if pair.len() == 2 {
                    let mut combined = [0u8; 64];
                    combined[..32].copy_from_slice(&pair[0]);
                    combined[32..].copy_from_slice(&pair[1]);
                    next.push(sha3_256(&combined));
                } else {
                    // Odd element: promote unchanged
                    next.push(pair[0]);
                }
            }
            layer = next;
        }
        layer[0]
    }
}

// ─── Merkle Proof ───────────────────────────────────────────────────────────

/// Inclusion proof for a single leaf in a Merkle tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// The hash of the leaf being proven.
    pub leaf: [u8; 32],
    /// Sibling hashes along the path from leaf to root.
    pub siblings: Vec<MerkleProofNode>,
    /// The root this proof verifies against.
    pub root: [u8; 32],
}

/// A sibling node in a Merkle proof path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProofNode {
    pub hash: [u8; 32],
    /// True if this sibling is on the right side.
    pub is_right: bool,
}

impl MerkleTree {
    /// Generate an inclusion proof for a leaf hash within a sorted hash slice.
    ///
    /// Returns `None` if the leaf is not found in the set.
    pub fn proof(hashes: &[[u8; 32]], leaf: &[u8; 32]) -> Option<MerkleProof> {
        if hashes.is_empty() {
            return None;
        }
        let idx = hashes.iter().position(|h| h == leaf)?;
        let root = Self::root(hashes);

        let mut siblings = Vec::new();
        let mut layer: Vec<[u8; 32]> = hashes.to_vec();
        let mut pos = idx;

        while layer.len() > 1 {
            let mut next_layer = Vec::with_capacity(layer.len().div_ceil(2));
            let next_pos = pos / 2;

            for pair in layer.chunks(2) {
                if pair.len() == 2 {
                    let mut combined = [0u8; 64];
                    combined[..32].copy_from_slice(&pair[0]);
                    combined[32..].copy_from_slice(&pair[1]);
                    next_layer.push(sha3_256(&combined));
                } else {
                    next_layer.push(pair[0]);
                }
            }

            // Record sibling for this level
            if pos % 2 == 0 {
                // Our node is on the left — sibling is right (if it exists)
                if pos + 1 < layer.len() {
                    siblings.push(MerkleProofNode {
                        hash: layer[pos + 1],
                        is_right: true,
                    });
                }
                // If no right sibling (odd count), no sibling needed — node promoted as-is
            } else {
                // Our node is on the right — sibling is left
                siblings.push(MerkleProofNode {
                    hash: layer[pos - 1],
                    is_right: false,
                });
            }

            layer = next_layer;
            pos = next_pos;
        }

        Some(MerkleProof { leaf: *leaf, siblings, root })
    }

    /// Verify a Merkle inclusion proof against a known root.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;

        for node in &proof.siblings {
            let mut combined = [0u8; 64];
            if node.is_right {
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(&node.hash);
            } else {
                combined[..32].copy_from_slice(&node.hash);
                combined[32..].copy_from_slice(&current);
            }
            current = sha3_256(&combined);
        }

        current == proof.root
    }
}

// ─── Bloom Filter ───────────────────────────────────────────────────────────

/// Probabilistic set membership filter for delta sync.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
}

/// Upper bound on the record IDs a client folds into one `delta_sync` bloom.
/// Both honest senders — the sync loop below and `gossip.rs`'s `delta_pull` —
/// scan `record_ids_from(since, MAX_BLOOM_BUILD)`. The server only bloom-tests up
/// to `MAX_SCAN` (50_000) records per request, so this 200K superset guarantees
/// no false-negative in the "peer already has X" check. Module-scope (not a
/// function-local const) so [`MAX_DELTA_SYNC_BLOOM_BODY`] and its drift-guard test
/// bind to the SAME value the senders use.
pub const MAX_BLOOM_BUILD: usize = 200_000;

/// Wire body cap for a `delta_sync` request (a serialized [`BloomFilter`]),
/// enforced IDENTICALLY on both transports — HTTP via `delta_sync_body_cap()`
/// (`DefaultBodyLimit`) and PQ via `guard_command_body(..)` in `handle_delta_sync`.
/// `BloomFilter::new(MAX_BLOOM_BUILD, 0.01)` serializes to ~234 KiB (the largest
/// bloom any honest client produces), so 512 KiB leaves ~2.2× headroom: it 413s
/// zero legitimate blooms while replacing the loose 2 MiB (HTTP global) / ~16 MiB
/// (`MAX_PAYLOAD`, PQ global) ceilings that let an admitted peer force a multi-MiB
/// transient bloom alloc on a phone-tier node for a ≤234 KiB legitimate artifact.
/// The `delta_sync_body_cap_admits_max_bloom_build` test pins cap ≥ max-bloom-size
/// so a future `MAX_BLOOM_BUILD` bump can't silently start rejecting honest peers.
pub const MAX_DELTA_SYNC_BLOOM_BODY: usize = 512 * 1024;

/// Per-page byte budget for the hex-encoded JSON *response* of the bulk
/// record-sync verbs (`delta_sync` and `query_records`), enforced IDENTICALLY on
/// both transports (PQ `handle_delta_sync`/`handle_query_records`, HTTP twin
/// `routes::sync::delta_sync`). Twin of the request-body cap above.
///
/// TWO independent ceilings converge here; the SECOND is the binding one:
///
/// 1. **Frame overflow** (2026-07-01 driver): a PQ response is one Data frame
///    (`MAX_PAYLOAD` = 16 MiB−1). Count-only batching (500 × ~80 KiB-hex
///    dual-signed records ≈ 40 MB) overran it — the serve `send()` failed and
///    the connection dropped silently, so any node ≳1 day behind never caught up.
/// 2. **Slow-link transfer time** (2026-07-03 driver — BINDING): the per-page
///    RPC deadline is `pq_client::DEFAULT_CALL_TIMEOUT` = 30 s (it wraps ONE
///    `call()`, i.e. one page — the client already loops pages across
///    independent deadlines). A 6 MiB page needs ~100 s to move at the phone-tier
///    floor (0.5 Mbps = 62.5 KB/s) → it times out and retries forever. The
///    first external node (cellular hotspot) hit exactly this and converged only
///    because `timestamp_pull`'s smaller count-bound pages squeaked under the
///    deadline. 1 MiB moves in ~17 s at the floor, leaving ~13 s for connect +
///    PQ handshake + bloom upload + loss retransmit.
///
/// Shorter pages are wire-compatible: clients advance `offset`/cursor by
/// records-received and loop on `has_more` (they already tolerate truncation).
/// The cost is more round-trips on a large backlog — bounded by the client's
/// `MAX_TOTAL_RECORDS`/cycle and the 24 h `since` window, never a stall (today's
/// failure mode is a page that never arrives at all). One shared const because
/// the budget is a WIRE property (transfer time), not a per-verb one; the
/// delta_sync stateless-offset re-scan cost was a server-CPU concern whose
/// durable fix — the cross-page cursor, NOT a larger byte cap — SHIPPED
/// 2026-07-05 (`build_delta_page` cursor path; R3-8 side-find 7c closed,
/// audited in docs/AUDIT-REPORTS/delta-sync-cursor-an internal audit).
/// The offset path remains for legacy clients only. Pinned by
/// `sync_response_cap_fits_slow_link_deadline` (upper) and
/// `sync_response_cap_admits_one_max_record` (lower / progress guarantee).
pub const MAX_SYNC_RESPONSE_HEX_BYTES: usize = 1024 * 1024;

/// Server-side scan bound for the LEGACY (offset / page-1) delta-sync path —
/// the first shared scan const (previously duplicated per-handler in
/// `pq_transport/router.rs` + `routes/sync.rs`; delta-sync cursor audit
/// 2026-07-05 consolidated it here so the twins can't drift). Seek
/// CF_IDX_TIMESTAMP from `since`, hard-cap the scan; `scan_hit_cap` flips
/// when it binds.
pub const MAX_SCAN: usize = 50_000;

/// Per-page scan bound for the CURSOR delta-sync path (pages 2+): each page
/// walks at most this many NEW index entries strictly past the client's
/// cursor, so a full client cycle costs O(window + pages × PAGE_SCAN) server
/// CPU — not the offset path's O(pages × MAX_SCAN). Deliberately 1/5 of
/// [`MAX_SCAN`]: the same handler already tolerates a 50K scan per request
/// today, so 10K/page is strictly cheaper than shipped behavior.
pub const PAGE_SCAN: usize = 10_000;

/// Wire length cap for the `x-delta-cursor` header value:
/// `hex(f64_be(ts) ++ id_bytes)` = 16 hex chars + 2 per id byte, id bounded
/// by [`crate::record::MAX_RECORD_ID_LEN`]. Anything longer is malformed by
/// construction and 400s at [`parse_sync_cursor`].
pub const MAX_CURSOR_HEX_LEN: usize = 16 + 2 * crate::record::MAX_RECORD_ID_LEN;

/// Encode a raw CF_IDX_TIMESTAMP key as the opaque wire cursor — same
/// convention as the snapshot fast-sync cursor
/// (`StorageEngine::stream_records_chunk`): lowercase hex of the raw key.
/// Pure hex is header-safe by construction (record ids may legally contain
/// ASCII control bytes, which are illegal in HTTP header values — hex
/// closes that wedge; audit C3).
pub(crate) fn encode_sync_cursor(raw_key: &[u8]) -> String {
    hex::encode(raw_key)
}

/// Parse + validate an `x-delta-cursor` header value into the raw
/// CF_IDX_TIMESTAMP key it names. Fail-closed: every reject is a distinct
/// `ElaraError::Wire` (→ 400 on both transports) and NEVER falls back to
/// offset paging — a silent fallback would re-serve page 1 and mask client
/// bugs as duplicate floods.
///
/// The timestamp check is BIT-level (`is_finite() && !is_sign_negative()`),
/// the same rule as the ingest gate (`ingest.rs` "audit 16e"): IEEE
/// `-0.0 >= 0.0` is true, while `-0.0`'s be-bytes (`0x8000…`) sort above
/// every real key. Here it is defense-in-depth (the cursor is a read-only
/// seek key), but one rule everywhere keeps the invariant greppable.
pub(crate) fn parse_sync_cursor(hex_str: &str) -> crate::errors::Result<Vec<u8>> {
    use crate::errors::ElaraError;
    if hex_str.len() > MAX_CURSOR_HEX_LEN {
        return Err(ElaraError::Wire(format!(
            "sync cursor too long: {} hex chars (max {MAX_CURSOR_HEX_LEN})",
            hex_str.len()
        )));
    }
    // 16 hex = ts alone; a valid key carries ≥1 id byte after it.
    if hex_str.len() < 18 || !hex_str.len().is_multiple_of(2) {
        return Err(ElaraError::Wire(format!(
            "sync cursor malformed length: {} hex chars (need even, ≥18)",
            hex_str.len()
        )));
    }
    let raw = hex::decode(hex_str)
        .map_err(|e| ElaraError::Wire(format!("sync cursor bad hex: {e}")))?;
    let ts_bytes: [u8; 8] = raw[..8]
        .try_into()
        .map_err(|_| ElaraError::Wire("sync cursor short ts".into()))?;
    let ts = f64::from_be_bytes(ts_bytes);
    if !ts.is_finite() || ts.is_sign_negative() {
        return Err(ElaraError::Wire(format!(
            "sync cursor invalid timestamp: {ts}"
        )));
    }
    let id = std::str::from_utf8(&raw[8..])
        .map_err(|_| ElaraError::Wire("sync cursor id not utf8".into()))?;
    if !id.is_ascii() || id.is_empty() || id.len() > crate::record::MAX_RECORD_ID_LEN {
        return Err(ElaraError::Wire(format!(
            "sync cursor invalid id ({} bytes)",
            id.len()
        )));
    }
    Ok(raw)
}

/// One served delta-sync page — the transport-agnostic result of
/// [`build_delta_page`]. Both handlers (PQ `handle_delta_sync`, HTTP
/// `routes::sync::delta_sync`) serialize this into the same JSON shape, so
/// twin parity is by construction instead of hand-mirrored (I5).
pub(crate) struct DeltaPage {
    /// Wire bytes of the served records (handler hex-encodes).
    pub records_wire: Vec<Vec<u8>>,
    /// Legacy path only: bloom-miss count over the whole scanned window.
    /// `None` on the cursor path — cursor pages MUST omit `total_missing`
    /// so the client's window-level gauge overwrite stays inert (audit C5).
    pub total_missing: Option<usize>,
    /// Cursor path only: bloom-miss count within this page's walked range
    /// (informational; includes misses the caps left unserved).
    pub missing_in_slice: Option<usize>,
    pub has_more: bool,
    /// Legacy path only (the cap concept doesn't exist on the cursor path).
    pub scan_hit_cap: Option<bool>,
    /// Wire cursor for the client's next page (present on BOTH paths — the
    /// legacy/page-1 instance is what lets a cursor-capable client upgrade
    /// on page 2; audit C1). `None` when the scan yielded no frontier.
    pub next_cursor: Option<String>,
    /// Echo of the request cursor (cursor path; audit C6). `None` on legacy.
    pub cursor_echo: Option<String>,
}

/// The single response-shape assembler for BOTH delta_sync transports (I5:
/// twin parity by construction). Legacy pages keep today's field set plus
/// the additive `next_cursor`; cursor pages carry the cursor-path fields and
/// deliberately OMIT `total_missing`/`scan_hit_cap`/`offset` (C5: the
/// client's window-level gauge overwrite must stay inert on cursor pages).
pub(crate) fn delta_page_json(
    page: &DeltaPage,
    hex_records: Vec<String>,
    offset: usize,
) -> serde_json::Value {
    let batch_size = hex_records.len();
    if let Some(echo) = &page.cursor_echo {
        serde_json::json!({
            "records": hex_records,
            "missing_in_slice": page.missing_in_slice.unwrap_or(0),
            "batch_size": batch_size,
            "has_more": page.has_more,
            "next_cursor": page.next_cursor,
            "cursor_echo": echo,
        })
    } else {
        serde_json::json!({
            "records": hex_records,
            "total_missing": page.total_missing.unwrap_or(0),
            "offset": offset,
            "batch_size": batch_size,
            "has_more": page.has_more,
            "scan_hit_cap": page.scan_hit_cap.unwrap_or(false),
            "next_cursor": page.next_cursor,
        })
    }
}

/// Chunk size for the cursor path's incremental walk: small enough that the
/// walk stops near the byte/count cap (≤ CHUNK-1 over-scanned entries per
/// page — the property that makes a full client cycle O(window) instead of
/// O(pages × PAGE_SCAN)), large enough to amortize the storage call.
const CURSOR_WALK_CHUNK: usize = 512;

/// Build one delta-sync page. Runs inside the handlers' `spawn_blocking`
/// (RocksDB point-reads). `cursor_raw` is the pre-validated output of
/// [`parse_sync_cursor`] — parse (and 400) happens transport-side BEFORE
/// blocking. `batch_size` is already RAM-tier-clamped by the handler.
///
/// Legacy path (`cursor_raw = None`): exactly today's semantics — one
/// `MAX_SCAN`-bounded scan from `since`, bloom-test all, serve
/// `missing[offset..offset+batch]` under [`MAX_SYNC_RESPONSE_HEX_BYTES`] —
/// plus the additive cursor fields, and ONE deliberate change:
/// `has_more |= scan_truncated`, so a cursor-capable client keeps paging
/// past a fully-bloom-matched 50K head instead of false-healing (audit C1
/// corollary; old clients terminate via their empty-batch break in ≤1 extra
/// page).
///
/// Cursor path: chunked forward walk strictly after the cursor, bloom-test
/// inline, stop at byte/count cap or [`PAGE_SCAN`] iterated entries. The C2
/// frontier rule: caps bound with misses still unserved → `next_cursor` =
/// last INCLUDED key (unserved misses stay ahead of the frontier — no
/// skip); slice drained → last SCANNED key (strict progress through
/// bloom-dense ranges, 0-record pages included).
pub(crate) fn build_delta_page(
    rocks: &crate::storage::rocks::StorageEngine,
    their_bloom: &BloomFilter,
    since: f64,
    offset: usize,
    batch_size: usize,
    cursor_raw: Option<&[u8]>,
) -> crate::errors::Result<DeltaPage> {
    build_delta_page_budgeted(
        rocks,
        their_bloom,
        since,
        offset,
        batch_size,
        cursor_raw,
        MAX_SCAN,
        PAGE_SCAN,
        MAX_SYNC_RESPONSE_HEX_BYTES,
    )
}

/// [`build_delta_page`] with injectable scan/byte budgets so tests can pin
/// the budget-bound branches (page-scan truncation, `has_more |=
/// scan_hit_cap`, the C2 byte-cap frontier rule) without 50K-record
/// fixtures. Production reaches this ONLY through the wrapper above — the
/// budgets stay the compile-time consts there (values pinned by
/// `delta_page_budget_consts_pin`).
#[allow(clippy::too_many_arguments)]
fn build_delta_page_budgeted(
    rocks: &crate::storage::rocks::StorageEngine,
    their_bloom: &BloomFilter,
    since: f64,
    offset: usize,
    batch_size: usize,
    cursor_raw: Option<&[u8]>,
    max_scan: usize,
    page_scan: usize,
    byte_budget: usize,
) -> crate::errors::Result<DeltaPage> {
    use crate::storage::rocks::TsScanStart;

    // Byte-budget include helper: first record always ships (progress
    // guarantee), later ones only under the budget. Returns false when the
    // cap binds (caller stops).
    fn try_include(
        rocks: &crate::storage::rocks::StorageEngine,
        id: &str,
        batch: &mut Vec<Vec<u8>>,
        hex_cost: &mut usize,
        byte_budget: usize,
    ) -> Option<bool> {
        use crate::storage::Storage as _;
        let wire = rocks.get_wire_bytes(id).ok()?;
        let cost = wire.len() * 2 + 4; // hex chars + JSON quotes/comma
        if !batch.is_empty() && *hex_cost + cost > byte_budget {
            return Some(false);
        }
        *hex_cost += cost;
        batch.push(wire);
        Some(true)
    }

    if let Some(cursor) = cursor_raw {
        // ── Cursor path ────────────────────────────────────────────────
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut hex_cost = 0usize;
        let mut missing_in_slice = 0usize;
        let mut iterated_total = 0usize;
        let mut last_scanned: Option<Vec<u8>> = None;
        let mut last_included: Option<Vec<u8>> = None;
        let mut cap_bound_with_misses = false;
        let mut scan_truncated = false;
        let mut resume: Vec<u8> = cursor.to_vec();

        'walk: while iterated_total < page_scan {
            let chunk = CURSOR_WALK_CHUNK.min(page_scan - iterated_total);
            let page = rocks.record_entries_page(TsScanStart::AfterKey(&resume), chunk)?;
            let Some(chunk_last) = page.last_scanned_key.clone() else {
                break 'walk; // window exhausted
            };
            // entries carry (ts,id); reconstruct each raw key for frontier
            // bookkeeping as we consume them in order.
            for (ts, id) in &page.entries {
                if !their_bloom.contains(id.as_bytes()) {
                    missing_in_slice += 1;
                    if batch.len() < batch_size {
                        match try_include(rocks, id, &mut batch, &mut hex_cost, byte_budget) {
                            Some(true) => {
                                let mut k = ts.to_be_bytes().to_vec();
                                k.extend_from_slice(id.as_bytes());
                                last_included = Some(k);
                            }
                            Some(false) => {
                                cap_bound_with_misses = true;
                                break 'walk;
                            }
                            None => {} // index entry without body — skip
                        }
                    } else {
                        cap_bound_with_misses = true;
                        break 'walk;
                    }
                }
            }
            // Whole chunk consumed (no cap-bind inside it) — advance the
            // frontier, then decide continuation. `chunk` (the storage-side
            // iteration budget) is the honest PAGE_SCAN accounting unit:
            // malformed keys count toward it even though they never reach
            // `entries`.
            last_scanned = Some(chunk_last.clone());
            resume = chunk_last;
            if !page.scan_truncated {
                break 'walk; // window exhausted mid-chunk
            }
            iterated_total += chunk;
            if iterated_total >= page_scan {
                scan_truncated = true;
                break 'walk;
            }
        }

        let next_cursor = if cap_bound_with_misses {
            last_included.as_deref().map(encode_sync_cursor)
        } else {
            last_scanned.as_deref().map(encode_sync_cursor)
        };
        Ok(DeltaPage {
            records_wire: batch,
            total_missing: None,
            missing_in_slice: Some(missing_in_slice),
            has_more: scan_truncated || cap_bound_with_misses,
            scan_hit_cap: None,
            next_cursor,
            cursor_echo: Some(encode_sync_cursor(cursor)),
        })
    } else {
        // ── Legacy / page-1 path (today's semantics + additive cursor) ──
        let page = rocks.record_entries_page(TsScanStart::Since(since), max_scan)?;
        let scan_hit_cap = page.scan_truncated;
        let missing: Vec<&(f64, String)> = page
            .entries
            .iter()
            .filter(|(_, id)| !their_bloom.contains(id.as_bytes()))
            .collect();
        let total_missing = missing.len();

        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut hex_cost = 0usize;
        let mut last_included: Option<Vec<u8>> = None;
        for (ts, id) in missing.iter().skip(offset).take(batch_size) {
            match try_include(rocks, id, &mut batch, &mut hex_cost, byte_budget) {
                Some(true) => {
                    let mut k = ts.to_be_bytes().to_vec();
                    k.extend_from_slice(id.as_bytes());
                    last_included = Some(k);
                }
                Some(false) => break,
                None => {}
            }
        }

        let misses_remaining = offset.saturating_add(batch.len()) < total_missing;
        // C2 on the legacy page: unserved misses remain → frontier = last
        // included (page 2 re-covers them); fully delivered → frontier =
        // last scanned (page 2 continues into the deeper window).
        let next_cursor = if misses_remaining {
            last_included.as_deref().map(encode_sync_cursor)
        } else {
            page.last_scanned_key.as_deref().map(encode_sync_cursor)
        };
        Ok(DeltaPage {
            records_wire: batch,
            total_missing: Some(total_missing),
            missing_in_slice: None,
            has_more: misses_remaining || scan_hit_cap,
            scan_hit_cap: Some(scan_hit_cap),
            next_cursor,
            cursor_echo: None,
        })
    }
}

impl BloomFilter {
    /// Create a new Bloom filter optimized for the expected number of items.
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        let num_bits = optimal_num_bits(expected_items.max(1), fp_rate);
        let num_hashes = optimal_num_hashes(num_bits, expected_items.max(1));
        let words = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes,
        }
    }

    /// Insert an item into the filter.
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = double_hash(item);
        for i in 0..self.num_hashes {
            let idx = combined_hash(h1, h2, i, self.num_bits);
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// Check if an item is possibly in the set. False = definitely not present.
    pub fn contains(&self, item: &[u8]) -> bool {
        let (h1, h2) = double_hash(item);
        for i in 0..self.num_hashes {
            let idx = combined_hash(h1, h2, i, self.num_bits);
            if self.bits[idx / 64] & (1u64 << (idx % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// Serialize to bytes: [num_bits:u32][num_hashes:u32][bit_data...].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.bits.len() * 8);
        buf.extend_from_slice(&(self.num_bits as u32).to_be_bytes());
        buf.extend_from_slice(&self.num_hashes.to_be_bytes());
        for word in &self.bits {
            buf.extend_from_slice(&word.to_be_bytes());
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(ElaraError::Wire("bloom filter too short".into()));
        }
        let num_bits = u32::from_be_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| ElaraError::Wire("bloom: num_bits slice".into()))?,
        ) as usize;
        let num_hashes = u32::from_be_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| ElaraError::Wire("bloom: num_hashes slice".into()))?,
        );

        // Reject structurally-invalid headers that `new()` can never produce
        // (`optimal_num_bits` floors at 64, `optimal_num_hashes` clamps to
        // 1..=32). A peer-supplied `num_bits == 0` would make `combined_hash`
        // compute `% 0` on the first `insert`/`contains` — a guaranteed
        // remote panic (div-by-zero in debug AND release). The delta_sync
        // routes decode peer blooms straight off the wire, so this guard is
        // the boundary that keeps a crafted 8-byte body from crashing the node.
        //
        // SS-1 (2026-07-03 audit): also reject num_hashes ABOVE the legitimate
        // ceiling. `insert`/`contains` loop `0..num_hashes`, so a crafted
        // `num_hashes = u32::MAX` (4B iterations per item, from an 8-byte body)
        // is a remote CPU-exhaustion vector. `optimal_num_hashes` never exceeds
        // BLOOM_MAX_HASHES, so anything larger is malformed.
        if num_bits == 0 || num_hashes == 0 || num_hashes > BLOOM_MAX_HASHES {
            return Err(ElaraError::Wire(format!(
                "bloom: invalid header (num_bits={num_bits}, num_hashes={num_hashes})"
            )));
        }

        let expected_words = num_bits.div_ceil(64);
        let expected_len = 8 + expected_words * 8;
        if data.len() < expected_len {
            return Err(ElaraError::Wire(format!(
                "bloom filter data too short: need {expected_len}, got {}",
                data.len()
            )));
        }

        let mut bits = Vec::with_capacity(expected_words);
        for i in 0..expected_words {
            let offset = 8 + i * 8;
            let word = u64::from_be_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| ElaraError::Wire("bloom: word slice".into()))?,
            );
            bits.push(word);
        }

        Ok(Self {
            bits,
            num_bits,
            num_hashes,
        })
    }
}

/// Optimal number of bits for a Bloom filter.
fn optimal_num_bits(n: usize, p: f64) -> usize {
    let m = -(n as f64 * p.ln()) / (2.0f64.ln().powi(2));
    (m.ceil() as usize).max(64)
}

/// Optimal number of hash functions.
/// Upper bound on bloom hash functions. `optimal_num_hashes` never exceeds it,
/// and `from_bytes` rejects any wire header above it (SS-1 CPU-exhaustion guard).
const BLOOM_MAX_HASHES: u32 = 32;

fn optimal_num_hashes(m: usize, n: usize) -> u32 {
    let k = (m as f64 / n as f64) * 2.0f64.ln();
    (k.ceil() as u32).clamp(1, BLOOM_MAX_HASHES)
}

/// Double hashing: extract two 64-bit values from SHA3-256.
fn double_hash(item: &[u8]) -> (u64, u64) {
    let hash: [u8; 32] = sha3_256(item);
    let mut h1_bytes = [0u8; 8];
    let mut h2_bytes = [0u8; 8];
    h1_bytes.copy_from_slice(&hash[..8]);
    h2_bytes.copy_from_slice(&hash[8..16]);
    (u64::from_be_bytes(h1_bytes), u64::from_be_bytes(h2_bytes).max(1))
}

/// Combine two hashes: h1 + i * h2 (mod num_bits).
fn combined_hash(h1: u64, h2: u64, i: u32, num_bits: usize) -> usize {
    ((h1 as u128 + i as u128 * h2 as u128) % num_bits as u128) as usize
}

// ─── State Sync ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use super::state::NodeState;
use super::gossip;
use super::{LockRecover, RwLockRecover};
use crate::record::ValidationRecord;
use tracing::{info, debug, warn, error};

// ─── PQ-only helper wrappers ────────────────────────────────────────────────
//
// AUDIT-10 directive (2026-04-24): no HTTPS fallback. Each helper returns Err
// if PQ handshake fails or the peer URL doesn't yield a PQ address.

fn derive_pq_addr(state: &Arc<NodeState>, base_url: &str) -> Result<String> {
    gossip::http_to_pq_addr(base_url, state.config.pq_port_offset).ok_or_else(|| {
        crate::errors::ElaraError::Network(format!(
            "cannot derive PQ peer addr from {base_url:?}"
        ))
    })
}

async fn pq_get_merkle_root(state: &Arc<NodeState>, base_url: &str) -> Result<String> {
    let pq_addr = derive_pq_addr(state, base_url)?;
    state.pq_client.get_merkle_root(&pq_addr).await
}

/// Discriminated kind of a non-timeout (`_other`) delta_sync failure.
///
/// The `_other` aggregate hides whether a stale follower can't *reach* the peer
/// (`Addr`/`Dial`) vs reaches it but speaks an incompatible post-handshake
/// *wire* (`Rpc`) or gets a drifted *response shape* (`Decode`) — the exact
/// distinction an operator needs to tell a network blip from a silent
/// wire-break. See the per-counter docs on
/// `NodeState::delta_sync_failures_other_*_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeltaSyncOtherKind {
    /// `cannot derive PQ peer addr` — local URL/offset config; pull never sent.
    Addr,
    /// `pq_dial {peer}: …` — connect refused/unreachable or handshake rejected.
    Dial,
    /// `rpc {peer}: …` — post-handshake AEAD/transport break (silent wire-break).
    Rpc,
    /// `… returned status N` / `… parse:` / `unexpected … format` / `bad hex`.
    Decode,
    /// Anything else — counted in `_other_total` only.
    Uncategorized,
}

/// Classify a non-timeout delta_sync failure message into a discriminated
/// bucket. Matches on the stage-prefix the client error strings already carry
/// (`pq_dial` / `rpc `) plus the decode-error literals emitted by
/// `PqClient::{ensure_ok, json_body, delta_sync}` — the same substring approach
/// the existing `_timeout_{handshake,rpc}` split uses. The `Decode` literals are
/// checked before the stage prefixes because they are produced AFTER `rpc()`
/// returns (not wrapped in `rpc {peer}:`), so the orderings never collide.
/// Pinned by unit tests against the real error strings so a future error-text
/// change breaks the test, not the metric.
pub(crate) fn classify_delta_sync_other(msg: &str) -> DeltaSyncOtherKind {
    if msg.contains("cannot derive PQ peer addr") {
        DeltaSyncOtherKind::Addr
    } else if msg.contains("returned status")
        || msg.contains("unexpected delta_sync response format")
        || msg.contains("bad hex")
        || msg.contains(" parse:")
    {
        DeltaSyncOtherKind::Decode
    } else if msg.contains("pq_dial") {
        DeltaSyncOtherKind::Dial
    } else if msg.contains("rpc ") {
        DeltaSyncOtherKind::Rpc
    } else {
        DeltaSyncOtherKind::Uncategorized
    }
}

/// Increment the `_other_total` aggregate AND the discriminated sub-bucket for
/// `msg`. The single home for both `pq_delta_sync` call sites (sync.rs +
/// gossip.rs) so the classification can never drift between them. `_other_total`
/// is always bumped (backward-compatible with existing dashboards/alerts); the
/// sub-buckets refine it and sum to ≤ `_other_total` (uncategorized residue).
pub(crate) fn record_delta_sync_other_failure(state: &NodeState, msg: &str) {
    use std::sync::atomic::Ordering::Relaxed;
    state.delta_sync_failures_other_total.fetch_add(1, Relaxed);
    match classify_delta_sync_other(msg) {
        DeltaSyncOtherKind::Addr => {
            state
                .delta_sync_failures_other_addr_total
                .fetch_add(1, Relaxed);
        }
        DeltaSyncOtherKind::Dial => {
            state
                .delta_sync_failures_other_dial_total
                .fetch_add(1, Relaxed);
        }
        DeltaSyncOtherKind::Rpc => {
            state
                .delta_sync_failures_other_rpc_total
                .fetch_add(1, Relaxed);
        }
        DeltaSyncOtherKind::Decode => {
            state
                .delta_sync_failures_other_decode_total
                .fetch_add(1, Relaxed);
        }
        DeltaSyncOtherKind::Uncategorized => {}
    }
}

async fn pq_delta_sync(
    state: &Arc<NodeState>,
    base_url: &str,
    bloom_bytes: &[u8],
) -> Result<Vec<Vec<u8>>> {
    use std::sync::atomic::Ordering::Relaxed;
    state.delta_sync_attempts_total.fetch_add(1, Relaxed);
    let pq_addr = match derive_pq_addr(state, base_url) {
        Ok(addr) => addr,
        Err(e) => {
            record_delta_sync_other_failure(state, &e.to_string());
            return Err(e);
        }
    };
    let since = delta_sync_since_floor(state);
    let t0 = std::time::Instant::now();
    match state.pq_client.delta_sync(&pq_addr, bloom_bytes, since).await {
        Ok((v, peer_missing, guard_tripped, cycle_exhausted)) => {
            if guard_tripped {
                state
                    .delta_sync_cursor_guard_trips_total
                    .fetch_add(1, Relaxed);
            }
            if cycle_exhausted {
                state
                    .delta_sync_cursor_cycle_exhausted_total
                    .fetch_add(1, Relaxed);
            }
            let elapsed_ms = t0.elapsed().as_millis();
            if elapsed_ms < 2_000 {
                state.delta_sync_latency_lt_2s_total.fetch_add(1, Relaxed);
            } else if elapsed_ms < 10_000 {
                state.delta_sync_latency_lt_10s_total.fetch_add(1, Relaxed);
            } else {
                state.delta_sync_latency_lt_30s_total.fetch_add(1, Relaxed);
            }
            note_peer_reported_missing(state, peer_missing);
            Ok(v)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("timed out") {
                state.delta_sync_failures_timeout_total.fetch_add(1, Relaxed);
                if msg.contains("pq_dial") {
                    state
                        .delta_sync_failures_timeout_handshake_total
                        .fetch_add(1, Relaxed);
                } else if msg.contains("rpc") {
                    state
                        .delta_sync_failures_timeout_rpc_total
                        .fetch_add(1, Relaxed);
                }
            } else {
                record_delta_sync_other_failure(state, &msg);
            }
            Err(e)
        }
    }
}

/// Floor for `x-delta-since`. Returns `newest_record_ts - DELTA_SYNC_WINDOW_SECS`,
/// clamped to ≥ 0.0. If the local DB has no records yet, returns 0.0 (full sweep).
///
/// This bounds server-side scan work to records in the recent window — at 10M+ records,
/// `for_each_record_id` was burning 30s+ per dial (root cause of RPC timeouts).
/// The 24h window is generous enough that a node offline for less than a day doesn't
/// miss anything; longer outages catch up via state-snapshot sync (gap #7).
/// R2-6b honest-surface: persist the peer-reported remaining-missing count and
/// log the gap-state TRANSITIONS (0→N opens, N→0 heals) so a >24h gap is
/// impossible to miss in logs while never spamming steady-state pulls.
pub(crate) fn note_peer_reported_missing(state: &Arc<NodeState>, remaining: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    let prev = state.delta_peer_total_missing.swap(remaining, Relaxed);
    if prev == 0 && remaining > 0 {
        tracing::warn!(
            "dag-gap OPEN: peer reports {remaining} records missing locally beyond the \
             bounded delta window — automatic deep-heal is roadmap (R2-6b); manual \
             recovery: authenticated POST /admin/snapshot_rebootstrap_from (see \
             docs/KNOWN-LIMITATIONS.md)"
        );
    } else if prev > 0 && remaining == 0 {
        tracing::info!("dag-gap HEALED: peer-reported missing count returned to 0 (was {prev})");
    }
}

pub(crate) fn delta_sync_since_floor(state: &Arc<NodeState>) -> f64 {
    const DELTA_SYNC_WINDOW_SECS: f64 = 24.0 * 3600.0;
    state
        .rocks
        .last_key_timestamp_cf(crate::storage::rocks::CF_IDX_TIMESTAMP)
        .ok()
        .flatten()
        .map(|newest| (newest - DELTA_SYNC_WINDOW_SECS).max(0.0))
        .unwrap_or(0.0)
}

async fn pq_snapshot_metadata(
    state: &Arc<NodeState>,
    base_url: &str,
) -> Result<serde_json::Value> {
    let pq_addr = derive_pq_addr(state, base_url)?;
    state.pq_client.get_snapshot_metadata(&pq_addr).await
}

async fn pq_snapshot(
    state: &Arc<NodeState>,
    base_url: &str,
) -> Result<super::snapshot::NodeSnapshot> {
    let pq_addr = derive_pq_addr(state, base_url)?;
    state.pq_client.get_snapshot(&pq_addr).await
}

async fn pq_snapshot_fast_meta(
    state: &Arc<NodeState>,
    base_url: &str,
    since_epoch: Option<u64>,
) -> Result<SnapshotFastMeta> {
    let pq_addr = derive_pq_addr(state, base_url)?;
    state.pq_client.get_snapshot_fast_meta(&pq_addr, since_epoch).await
}

async fn pq_snapshot_fast_chunk(
    state: &Arc<NodeState>,
    base_url: &str,
    cursor: Option<&str>,
    since_epoch: Option<u64>,
) -> Result<SnapshotChunk> {
    let pq_addr = derive_pq_addr(state, base_url)?;
    state.pq_client.get_snapshot_fast_chunk(&pq_addr, cursor, since_epoch).await
}

/// Run initial sync — tries snapshot bootstrap first, falls back to delta sync.
///
/// Snapshot bootstrap (Phase 3-4): downloads a signed snapshot from a peer,
/// verifies its checksum and signature, loads ledger state directly.
/// Then delta syncs only records AFTER the snapshot timestamp.
/// Falls back to full delta sync if snapshot download fails.
/// Run initial sync. Returns the number of records ingested (0 if already in sync).
pub async fn initial_sync(state: &Arc<NodeState>) -> u32 {
    let peers = state.peers.read().await;
    let connected = peers.connected();
    if connected.is_empty() {
        info!("no peers for initial sync");
        return 0;
    }

    // Pick first connected peer for sync
    let peer = connected[0];
    let base_url = peer.base_url();
    drop(peers);

    initial_sync_from(state, &base_url).await
}

/// Run delta sync from a specific peer URL. Used by fork heal to target
/// the diverged peer directly instead of picking connected[0].
pub async fn initial_sync_from(state: &Arc<NodeState>, base_url: &str) -> u32 {

    // ── Snapshot bootstrap: try snapshot first if DAG is empty ──────────
    let dag_len = state.dag.read().await.len();
    if dag_len == 0 {
        info!("empty DAG — attempting snapshot bootstrap from {base_url}");
        match snapshot_bootstrap(state, base_url, false).await {
            Ok(true) => {
                info!("snapshot bootstrap complete — skipping full delta sync");
                return 0;
            }
            Ok(false) => {
                info!("snapshot bootstrap: peer has no snapshot, falling back to delta sync");
            }
            Err(e) => {
                if is_snapshot_config_error(&e) {
                    error!(
                        "snapshot bootstrap REJECTED by a config gate, not a transient fault: {e}. \
                         The delta-sync fallback rejects the seed's seals for the same reason, so the \
                         epoch will not advance until you fix this. Set genesis_authority (and \
                         min_protocol_version) to match the seed's /status, then restart — run \
                         scripts/check-my-join.sh to confirm."
                    );
                } else {
                    warn!("snapshot bootstrap failed: {e} — falling back to delta sync");
                }
            }
        }
    }

    info!("starting delta sync from {base_url}");

    // On ≤2GB nodes, skip Merkle root comparison and bloom filter entirely.
    // Both require full-DB scans (all_record_hashes iterates 60K+ records,
    // record_ids iterates all CF_RECORDS keys through 6GB+ of SST files).
    // The allocation churn causes 1.5GB of jemalloc fragmentation.
    // timestamp_pull is cursor-based — no full scan, bounded memory.
    //
    // Gap 7 Step 3 (2026-04-21): also take the cursor-based path when the
    // ledger was just loaded from a peer snapshot. The catch-up cursor is
    // seeded to snapshot_timestamp so we skip fetching the ~all records the
    // snapshot already captured; Merkle/bloom would force a full-DB delta
    // comparison that wastes the skip-ahead savings.
    let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
    let ledger_from_snap = state.ledger_loaded_from_snapshot
        .load(std::sync::atomic::Ordering::Relaxed);
    if ram_gb <= 2 || ledger_from_snap {
        let reason = if ledger_from_snap {
            "ledger loaded from snapshot — cursor-based delta"
        } else {
            "low-memory mode — no full scans"
        };
        info!("delta sync: {reason} ({}GB RAM)", ram_gb);
        let pulled = crate::network::gossip::timestamp_pull(state, base_url).await.unwrap_or(0);
        return pulled as u32;
    }

    // Step 1: Compare Merkle roots — O(zone_count) reads via SparseMerkleTree
    let our_root = crate::network::merkle::global_merkle_root(&state.rocks);

    match pq_get_merkle_root(state, base_url).await {
        Ok(their_root_hex) => {
            let our_root_hex = hex::encode(our_root);
            if our_root_hex == their_root_hex {
                info!("delta sync: already in sync (roots match)");
                return 0;
            }
            // their_root_hex is a peer-supplied String — not guaranteed >=16
            // bytes nor valid ASCII hex, so a naive &s[..16] panics on a short
            // string OR a multi-byte UTF-8 boundary. str::get(..16) is None on
            // both, never panics. (our_root_hex is local 64-char hex, guarded
            // the same way for symmetry.)
            debug!(
                "roots differ: ours={} theirs={}",
                our_root_hex.get(..16).unwrap_or(&our_root_hex),
                their_root_hex.get(..16).unwrap_or(&their_root_hex)
            );
        }
        Err(e) => {
            warn!("failed to get peer merkle root: {e}");
            return 0;
        }
    }

    // Step 2: Build our Bloom filter from records in the recent window.
    //
    // Bound the bloom build to `record_ids_from(since,
    // MAX_BLOOM_BUILD)`. Previously this used `for_each_record_id` (full
    // CF_RECORDS scan, 30s+ at 10M records, mirror of the server-side
    // bottleneck). Server caps its scan at MAX_SCAN=50_000; client
    // bloom covers a strict superset (200K) over the same `since` floor, so
    // every ID the server iterates is in the bloom — no false-negatives in
    // the "client doesn't have this" check, no over-fetch.
    let since = delta_sync_since_floor(state);
    let bloom_bytes = {
        let scanned_ids = state
            .rocks
            .record_ids_from(since, MAX_BLOOM_BUILD)
            .unwrap_or_else(|e| {
                warn!("delta sync: bloom build record_ids_from failed: {e}");
                Vec::new()
            });
        if scanned_ids.is_empty() {
            Vec::new()
        } else {
            let mut bloom = BloomFilter::new(scanned_ids.len().max(100), 0.01);
            for id in &scanned_ids {
                bloom.insert(id.as_bytes());
            }
            bloom.to_bytes()
        }
    };

    // Step 3: Get missing records from peer
    match pq_delta_sync(state, base_url, &bloom_bytes).await {
        Ok(missing_wire) => {
            // Parse all records first
            let mut records: Vec<ValidationRecord> = missing_wire
                .iter()
                .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
                .collect();

            // Sort by timestamp — genesis/mint records must be processed first
            records.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));

            let total = records.len();

            // Skip records already in the gossip_rejected cache — they failed
            // validation permanently (e.g., merkle mismatch, previous_seal mismatch)
            // and will never succeed. Without this, delta sync re-pulls and re-tries
            // the same ~20 permanently-stuck records every cycle, makes zero progress,
            // and effectively hangs the sync loop.
            let mut skipped_rejected = 0u32;
            let records: Vec<ValidationRecord> = records
                .into_iter()
                .filter(|rec| {
                    let rejected = state.gossip_rejected.lock_recover().contains(&rec.id);
                    if rejected {
                        skipped_rejected += 1;
                    }
                    !rejected
                })
                .collect();
            if skipped_rejected > 0 {
                info!("delta sync: skipped {skipped_rejected} previously-rejected records");
            }

            // Pre-filter stale epoch seals BEFORE sending to state_core.
            // When a node is catching up, peers serve hundreds of old epoch seals
            // whose epoch numbers are far behind local state. Each seal would go
            // through full processing (sig verify + dag.write() + epoch eval ~40ms)
            // only to be rejected. On Nuremberg this wasted ~45% of processing capacity.
            let mut skipped_stale_seals = 0u32;
            let records: Vec<ValidationRecord> = {
                let epoch_state = state.epoch.read_recover();
                records.into_iter().filter(|rec| {
                    let is_seal = rec.metadata.get("epoch_op")
                        .and_then(|v| v.as_str()) == Some("seal");
                    if !is_seal { return true; }

                    let seal_epoch = rec.metadata.get("epoch_number")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let zone_str = rec.metadata.get("epoch_zone")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    let zone_id = crate::ZoneId::new(zone_str);
                    let local_epoch = epoch_state.latest_epoch
                        .get(&zone_id)
                        .copied()
                        .unwrap_or(0);
                    // Max gap is 100 (same threshold as epoch.rs verification).
                    // Seals more than 100 epochs behind will always be rejected.
                    if local_epoch > 0 && seal_epoch + 100 < local_epoch {
                        skipped_stale_seals += 1;
                        // Contract §4.4: remember the intentional decline so
                        // the delta_pull bloom stops peers re-serving it every
                        // pass. NOT gossip_rejected — stale ≠ invalid.
                        state
                            .declined_seal_ids
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(rec.id.clone());
                        return false;
                    }
                    true
                }).collect()
            };
            if skipped_stale_seals > 0 {
                info!("delta sync: skipped {skipped_stale_seals} stale epoch seals (too far behind local epoch)");
            }

            // Multi-pass insertion: some records (witness_rewards) depend on
            // the conservation pool being funded, which requires genesis mints
            // to be processed first. We do up to 3 passes, rebuilding the
            // ledger between passes so later records can validate.
            let mut remaining = records;
            let mut total_inserted = 0u32;
            let mut final_failed: Vec<(ValidationRecord, String)> = Vec::new();

            for pass in 0..3 {
                if remaining.is_empty() {
                    break;
                }

                let mut failed = Vec::new();
                let mut pass_inserted = 0u32;

                for (i, record) in remaining.into_iter().enumerate() {
                    // Yield every 50 records to let HTTP server and gossip tasks run.
                    // Without this, delta sync floods state_core and starves all other
                    // tokio tasks on memory-constrained nodes (2 GB).
                    if i > 0 && i % 50 == 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    let already_seen = state.seen.lock_recover().contains(&record.id);
                    if !already_seen {
                        match gossip::insert_record_synced(state, record.clone()).await {
                            Ok(_) => {
                                state.seen.lock_recover().insert(record.id.clone());
                                pass_inserted += 1;
                            }
                            Err(e) => {
                                warn!(
                                    "delta sync: record {} failed: {} (ts={:.0})",
                                    &record.id[..record.id.len().min(16)],
                                    e,
                                    record.timestamp,
                                );
                                // Don't add to seen set — next pass can retry
                                failed.push((record, e.to_string()));
                            }
                        }
                    }
                }

                total_inserted += pass_inserted;
                info!("delta sync pass {}: {pass_inserted} inserted, {} failed", pass + 1, failed.len());

                if failed.is_empty() || pass_inserted == 0 {
                    final_failed = failed;
                    break; // No progress — stop retrying
                }

                // No ledger rebuild between passes — insert_record_synced already
                // applies each record to the live ledger via state_core. Rebuilding
                // from RocksDB here would double-count records that were just inserted
                // (applied live + replayed from storage), corrupting balances.
                // The retry pass works against the live ledger which already has
                // pass 1's records applied.

                remaining = failed.into_iter().map(|(rec, _)| rec).collect();
            }

            // Permanently-failed records go to gossip_rejected so they're
            // skipped on future delta syncs AND gossip push/pull cycles.
            // LEDGER-STATE-DEPENDENT failures are
            // ordering artifacts — the boot delta sync can race the local
            // genesis ledger build, so "insufficient balance" here may just
            // mean "mint not applied yet". Those park for targeted re-fetch
            // instead of poisoning the cache (rehearsal #4: the genesis pool
            // seed died exactly here, pool stuck 0 chain-wide).
            if !final_failed.is_empty() {
                let mut cached = 0usize;
                let mut parked = 0usize;
                for (rec, reason) in &final_failed {
                    // 8b invariant: seal-class never enters gossip_rejected —
                    // disposed centrally (decline if stale, bounded park else).
                    if gossip::dispose_seal_ingest_failure(state, rec, 0) {
                        parked += 1;
                    } else if gossip::is_retryable_ingest_rejection(reason) {
                        gossip::park_retryable(state, &rec.id);
                        parked += 1;
                    } else {
                        state.gossip_rejected.lock_recover().insert(rec.id.clone());
                        cached += 1;
                    }
                }
                info!(
                    "delta sync: {cached} permanently-failed records cached, \
                     {parked} retryable records parked for re-fetch"
                );
            }

            info!("delta sync complete: {total_inserted}/{total} records inserted");
            return total_inserted;
        }
        Err(e) => {
            warn!("delta sync failed: {e}");
        }
    }
    0
}

/// Gap 7: Bootstrap from a peer's *epoch-indexed* archive snapshot, if any.
///
/// Checks `/snapshot/epochs` on the peer. If present and non-empty, downloads
/// the latest epoch snapshot (same checksum across every archive node that
/// emitted at that epoch — cross-verifiable). Returns the loaded snapshot and
/// the epoch number on success. Returns Ok(None) if the peer is not an
/// archive, has no snapshots, or the returned snapshot fails signature verify.
///
/// Cross-peer checksum verification is performed best-effort: when other
/// connected peers also list the same epoch, we compare their snapshot
/// checksums against the primary one and reject if any peer disagrees. A
/// single-archive network is still accepted (signature verifies authenticity).
async fn epoch_indexed_snapshot_bootstrap(
    state: &Arc<NodeState>,
    base_url: &str,
) -> crate::errors::Result<Option<(u64, super::snapshot::NodeSnapshot)>> {
    // AUDIT-10 PQ-R5a: all epoch-snapshot traffic over PQ transport.
    let Some(pq_addr) = gossip::http_to_pq_addr(base_url, state.config.pq_port_offset) else {
        debug!("peer {base_url} has no derivable PQ address — skipping epoch-snapshot bootstrap");
        return Ok(None);
    };

    // Step 1: Ask the primary peer what epoch snapshots it has.
    let epochs_meta = match state.pq_client.list_epoch_snapshots(&pq_addr).await {
        Ok(v) => v,
        Err(e) => {
            debug!("peer {base_url} pq.list_epoch_snapshots failed: {e}");
            return Ok(None);
        }
    };
    // The peer's `epochs` array is unauthenticated metadata — the trust gate
    // below covers only the snapshot *signature*, not this list. A hostile seed
    // could pack a full MAX_PAYLOAD (~16 MiB) frame with minimal JSON ints which,
    // if collected, balloons into a ~64 MB `Vec<u64>` on a cold-starting joiner
    // (same remote memory-amplification class as the light.rs cold-start caps).
    // We only need the highest epoch, so stream the max — O(1) memory, zero
    // amplification. The honest server sorts ascending (`list_epoch_snapshots`)
    // so this equals the old `.last()`; a reordered hostile list can at worst
    // name a different epoch, which is signature/trust/cross-verified below.
    let epochs_arr = epochs_meta.get("epochs").and_then(|v| v.as_array());
    let available_epochs = epochs_arr.map(|a| a.len()).unwrap_or(0);
    let latest = match epochs_arr.and_then(|arr| arr.iter().filter_map(|e| e.as_u64()).max()) {
        Some(n) if n > 0 => n,
        _ => {
            debug!("peer {base_url} has no epoch-indexed archive snapshots");
            return Ok(None);
        }
    };

    // Step 2: Fetch the primary's epoch snapshot + verify checksum+signature.
    let primary = state.pq_client.get_epoch_snapshot(&pq_addr, latest).await?;
    let signer = super::snapshot::verify_signed_snapshot(&primary)
        .map_err(|e| crate::errors::ElaraError::Wire(format!(
            "epoch snapshot verify failed (peer={base_url} epoch={latest}): {e}"
        )))?;
    // PQ-R2: signer must be in the trust set, else any peer with a valid
    // identity can forge bootstrap state.
    let mut trust_set: Vec<&str> = Vec::with_capacity(state.config.trusted_snapshot_signers.len() + 1);
    if !state.config.genesis_authority.is_empty() {
        trust_set.push(state.config.genesis_authority.as_str());
    }
    trust_set.extend(state.config.trusted_snapshot_signers.iter().map(|s| s.as_str()));
    super::snapshot::enforce_snapshot_signer_trust(&signer, &trust_set)
        .map_err(|e| crate::errors::ElaraError::Wire(format!(
            "{EPOCH_SNAPSHOT_TRUST_GATE_LABEL} (peer={base_url} epoch={latest}): {e}"
        )))?;
    super::snapshot::enforce_snapshot_protocol_version(&primary, state.config.min_protocol_version)
        .map_err(|e| crate::errors::ElaraError::Wire(format!(
            "{EPOCH_SNAPSHOT_VERSION_GATE_LABEL} (peer={base_url} epoch={latest}): {e}"
        )))?;
    let primary_checksum = match primary.checksum.clone() {
        Some(c) => c,
        None => {
            return Err(crate::errors::ElaraError::Wire(format!(
                "epoch snapshot {latest} from {base_url} missing checksum"
            )));
        }
    };

    // Step 3: Cross-verify against up to 3 other connected peers that have the
    // same epoch on offer. Skip peers missing this epoch — they may just not
    // be archive nodes or may be behind. Only FAIL on an explicit checksum
    // mismatch, which indicates fork divergence.
    let cross_peer_urls: Vec<String> = {
        let peers = state.peers.read().await;
        peers.connected()
            .iter()
            .map(|p| p.base_url())
            .filter(|u| u != base_url)
            .take(3)
            .collect()
    };

    let mut cross_confirmed = 0usize;
    for other in &cross_peer_urls {
        let Some(other_pq) = gossip::http_to_pq_addr(other, state.config.pq_port_offset) else {
            debug!("cross-peer {other} has no derivable PQ address — skipping");
            continue;
        };
        // Same unauthenticated-metadata reasoning as the primary above: we only
        // test membership, so stream `.any()` instead of materializing the array.
        let has_latest = match state.pq_client.list_epoch_snapshots(&other_pq).await {
            Ok(v) => v
                .get("epochs")
                .and_then(|e| e.as_array())
                .map(|arr| arr.iter().filter_map(|e| e.as_u64()).any(|n| n == latest))
                .unwrap_or(false),
            Err(e) => {
                debug!("cross-peer {other} pq.list_epoch_snapshots failed: {e}");
                continue;
            }
        };
        if !has_latest {
            continue; // peer doesn't have this epoch — not a conflict
        }
        match state.pq_client.get_epoch_snapshot(&other_pq, latest).await {
            Ok(other_snap) => {
                if let Some(c) = &other_snap.checksum {
                    if *c != primary_checksum {
                        return Err(crate::errors::ElaraError::Wire(format!(
                            "epoch snapshot {latest} checksum mismatch: {base_url}={}... vs {other}={}...",
                            &primary_checksum[..16.min(primary_checksum.len())],
                            &c[..16.min(c.len())],
                        )));
                    }
                    cross_confirmed += 1;
                }
            }
            Err(e) => {
                debug!("cross-peer {other} pq.get_epoch_snapshot({latest}) failed: {e}");
            }
        }
    }

    info!(
        "epoch-indexed snapshot bootstrap: peer={} epoch={} signer={}... cross_confirmed={} available_epochs={}",
        base_url,
        latest,
        &signer[..16.min(signer.len())],
        cross_confirmed,
        available_epochs,
    );

    state.snapshot_bootstrap_epoch_indexed_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Ok(Some((latest, primary)))
}

/// Error-text labels for the `snapshot_bootstrap` CONFIG gates. Defined once and
/// used both in the `map_err` format strings below and in
/// [`is_snapshot_config_error`] so the classifier can never silently desync from
/// the message it keys on. The epoch-indexed path emits the `EPOCH_`-prefixed
/// variants; they are deliberate SUPERSTRINGS of the live labels, so a single
/// `contains` on the live label matches both paths. The `epoch_labels_are_*`
/// test pins that superstring invariant — break it with a rename and it fails.
const SNAPSHOT_TRUST_GATE_LABEL: &str = "snapshot trust gate";
const SNAPSHOT_VERSION_GATE_LABEL: &str = "snapshot version gate";
const EPOCH_SNAPSHOT_TRUST_GATE_LABEL: &str = "epoch snapshot trust gate";
const EPOCH_SNAPSHOT_VERSION_GATE_LABEL: &str = "epoch snapshot version gate";

/// True when a snapshot-bootstrap failure is an operator CONFIG mismatch — a
/// wrong `genesis_authority` (trust gate: the seed's snapshot is validly signed,
/// but by an authority this node does not trust) or a `min_protocol_version`
/// above what the seed serves (version gate) — rather than a transient/network
/// fault. Covers BOTH the epoch-indexed and live `/snapshot` paths: the `EPOCH_*`
/// labels are superstrings of the live labels, so the two `contains` checks match
/// either path. These are NOT recoverable by the delta-sync fallback (the same
/// gate rejects every seal the seed serves, so the epoch never advances) NOR by
/// retrying the live path after the epoch path fails (both build the same trust
/// set from the same config). They warrant a clear, actionable error instead of a
/// "falling back" warn that reads as self-healing recovery to a first-time operator.
pub fn is_snapshot_config_error(e: &crate::errors::ElaraError) -> bool {
    let s = e.to_string();
    s.contains(SNAPSHOT_TRUST_GATE_LABEL) || s.contains(SNAPSHOT_VERSION_GATE_LABEL)
}

/// Bootstrap from a peer's signed snapshot.
///
/// Gap 7: prefers the deterministic epoch-indexed archive snapshot
/// (`/snapshot/epochs` + `/snapshot/epoch/{N}`) when available — same checksum
/// across every archive node. Falls back to the live `/snapshot` path for
/// peers that haven't emitted an epoch-indexed snapshot yet.
///
/// Downloads the snapshot, verifies checksum, loads ledger state directly.
/// Then delta syncs only records created AFTER the snapshot timestamp.
/// Returns Ok(true) if bootstrap succeeded, Ok(false) if peer has no snapshot.
///
/// Made `pub` so the admin endpoint
/// `/admin/snapshot_rebootstrap_from` can force this path on a non-empty DAG.
/// `initial_sync_from` only triggers it when `dag_len == 0` — but a node
/// stuck severely behind on FinalizedIndex while holding a small hot DAG
/// (the bootstrap pathology) is the actual scenario that needs it. Operator
/// admin escape hatch when the pending buffers + always-fetch don't
/// unstick a node within reasonable cycle time.
pub async fn snapshot_bootstrap(
    state: &Arc<NodeState>,
    base_url: &str,
    allow_rollback: bool,
) -> crate::errors::Result<bool> {
    // ── Gap 7 preferred path: epoch-indexed archive snapshot ────────────
    match epoch_indexed_snapshot_bootstrap(state, base_url).await {
        Ok(Some((epoch_num, snapshot))) => {
            info!(
                "snapshot bootstrap (epoch-indexed): epoch={} accounts={} supply={} applied_ids={}",
                epoch_num,
                snapshot.ledger.accounts.len(),
                snapshot.ledger.total_supply,
                snapshot.ledger.applied_record_ids.len(),
            );
            // Gap 7 real closure: load ledger + CF_APPLIED from snapshot. Delta
            // sync still runs to fetch record bytes into RocksDB/DAG, but the
            // seeded CF_APPLIED means pre-snapshot records are ledger-deduped
            // (skip apply_single_record in ingest.rs). Post-snapshot records
            // apply fresh against the loaded ledger.
            apply_bootstrap_snapshot_full(state, &snapshot, allow_rollback).await?;
            info!("snapshot bootstrap: ledger loaded from snapshot, delta sync will run dedup-only for pre-snapshot records");
            // Fall through to delta sync — CF_APPLIED guards prevent double apply.
            return Ok(false);
        }
        Ok(None) => {
            debug!("snapshot bootstrap: no epoch-indexed snapshot available from {base_url}, trying live snapshot");
        }
        Err(e) => {
            if is_snapshot_config_error(&e) {
                // A wrong genesis_authority / min_protocol_version is NOT
                // transient. The live /snapshot fallback below builds the SAME
                // trust set from the SAME config and would reject the SAME
                // signer — only AFTER downloading a potentially multi-GB live
                // snapshot. Short-circuit so the caller logs the actionable fix
                // immediately and we skip the guaranteed-to-fail download.
                return Err(e);
            }
            warn!("snapshot bootstrap (epoch-indexed) failed: {e} — trying live snapshot");
        }
    }

    // ── Fallback: live /snapshot path ───────────────────────────────────
    // Step 1: Download snapshot metadata from multiple peers to compare
    let metadata = pq_snapshot_metadata(state, base_url).await?;
    let peer_record_count = metadata.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0);
    if peer_record_count == 0 {
        return Ok(false); // Peer has no records — nothing to bootstrap from
    }

    info!(
        "snapshot bootstrap: peer has {} records, downloading snapshot...",
        peer_record_count
    );

    // Step 2: Download the full signed snapshot
    let snapshot = pq_snapshot(state, base_url).await?;

    // Step 3: Verify checksum
    let signer = super::snapshot::verify_signed_snapshot(&snapshot)
        .map_err(|e| crate::errors::ElaraError::Wire(format!("snapshot verification failed: {e}")))?;

    // PQ-R2: signer must be in the trust set; verify_signed_snapshot only
    // proves the bytes were signed by *some* PQ key, not by an authority we
    // accept. Without this gate, any node with a Dilithium3 keypair can serve
    // a forged ledger snapshot.
    let mut trust_set: Vec<&str> = Vec::with_capacity(state.config.trusted_snapshot_signers.len() + 1);
    if !state.config.genesis_authority.is_empty() {
        trust_set.push(state.config.genesis_authority.as_str());
    }
    trust_set.extend(state.config.trusted_snapshot_signers.iter().map(|s| s.as_str()));
    super::snapshot::enforce_snapshot_signer_trust(&signer, &trust_set)
        .map_err(|e| crate::errors::ElaraError::Wire(format!(
            "{SNAPSHOT_TRUST_GATE_LABEL} (peer={base_url}): {e}"
        )))?;
    super::snapshot::enforce_snapshot_protocol_version(&snapshot, state.config.min_protocol_version)
        .map_err(|e| crate::errors::ElaraError::Wire(format!(
            "{SNAPSHOT_VERSION_GATE_LABEL} (peer={base_url}): {e}"
        )))?;

    info!(
        "snapshot verified: signer={}, {} accounts, supply={}",
        &signer[..16.min(signer.len())],
        snapshot.ledger.accounts.len(),
        snapshot.ledger.total_supply,
    );

    // Step 4: Load ledger + metadata + CF_APPLIED from the signed snapshot.
    // Gap 7 real closure: snapshot IS authoritative; pre-snapshot records
    // will be deduped by CF_APPLIED during the subsequent delta sync.
    apply_bootstrap_snapshot_full(state, &snapshot, allow_rollback).await?;
    state.snapshot_bootstrap_live_fallback_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    info!("snapshot bootstrap (live fallback): ledger loaded, delta sync will dedup pre-snapshot records");
    Ok(false)
}

/// Gap 7 real closure: apply a verified bootstrap snapshot as the authoritative
/// local state. Loads the ledger, seeds `CF_APPLIED` from the snapshot's
/// `applied_record_ids`, restores finalized/genesis/bootstrap metadata, and
/// sets `state.ledger_loaded_from_snapshot` so the next startup skips the
/// O(all_records) ledger rebuild.
///
/// Double-apply safety: `CF_APPLIED` is the fast-path dedup check used by
/// `state_core`/`ingest`. Once a record_id lives there, its ledger op will
/// never be replayed against the ledger — even if the record bytes are
/// fetched again during delta sync. That is what makes ledger-skip-ahead
/// safe.
async fn apply_bootstrap_snapshot_full(
    state: &Arc<NodeState>,
    snapshot: &super::snapshot::NodeSnapshot,
    allow_rollback: bool,
) -> crate::errors::Result<()> {
    // 0. Refuse-if-behind guard (admin-audit 2026-07-05). The ledger replace
    //    below is wholesale and CF_APPLIED seeding is additive-only: records
    //    already marked applied locally are never replayed. Loading a snapshot
    //    whose signed epoch tip is BEHIND our local tip therefore rolls ledger
    //    content back PERMANENTLY — delta sync re-fetches the newer records'
    //    bytes, but ingest dedups them against CF_APPLIED and their ledger
    //    effects are silently lost — while the monotone tip merge in step 4b
    //    keeps epoch height unchanged, so chain_divergence_monitor_loop
    //    (keyed on height alone) never notices. All boot-path callers are
    //    virgin-gated (dag_len==0 / local_tip=0) and pass trivially; only the
    //    operator escape hatch /admin/snapshot_rebootstrap_from can trip this,
    //    and it must send force=true to accept the rollback (e.g. local ledger
    //    known-corrupt). Note an AHEAD peer can still serve an epoch-indexed
    //    archive snapshot that lags its live tip below ours — that is the same
    //    hidden-rollback shape, so it refuses too; force covers the case where
    //    the operator has judged the rewind acceptable.
    let local_max_epoch = {
        let epoch = state.epoch.read_recover();
        epoch.latest_epoch.values().copied().max().unwrap_or(0)
    };
    let snap_max_epoch = snapshot
        .epoch
        .as_ref()
        .map(|ep| ep.latest_epoch.values().copied().max().unwrap_or(0))
        .unwrap_or(0);
    if !allow_rollback && local_max_epoch > 0 && snap_max_epoch < local_max_epoch {
        return Err(crate::errors::ElaraError::Wire(format!(
            "snapshot bootstrap refused: snapshot epoch tip ({snap_max_epoch}) is behind local \
             tip ({local_max_epoch}) — applying would roll ledger content back permanently \
             (CF_APPLIED dedup suppresses re-apply of the newer records). If the local ledger \
             is known-bad, retry with force=true"
        )));
    }

    // 1. Load ledger. Snapshot's ledger carries applied_record_ids now (Step 1).
    {
        let mut ledger = state.ledger.write().await;
        *ledger = snapshot.ledger.clone();
        // Re-derive incremental counters that aren't authoritative on the wire.
        // Old snapshots default `active_delegations_count` to 0 — recount fixes it before
        // any reader observes the loaded state.
        ledger.governance.recount_active_delegations();
        // Same reasoning for per-status proposal counters.
        ledger.governance.recount_proposal_statuses();
        // `staker_index` is `#[serde(skip)]`, so the deserialized snapshot
        // ledger lands with it EMPTY while `stakes` (serialized) is full.
        // `register_stakes_from_ledger` (step 5 below) builds `staker_stakes`
        // — the liveness-decay per-staker map — by iterating `staker_index`,
        // so without this rebuild it would come out empty post-bootstrap. The
        // other five restore paths already call this; this one was missed.
        ledger.rebuild_staker_index();
        // `cross_zone` is now serialized (`#[serde(default)]`), so `pending`
        // round-trips — but reconcile the per-status counters from the loaded
        // `pending` as belt-and-braces (idempotent on a populated snapshot;
        // zeroes them for a pre-fix snapshot that lands `pending` empty), keeping
        // the OPS-152 `locked+claimed+refunded+aborted == pending.len()` invariant.
        ledger.cross_zone.recount_status();
    }
    // The ledger was replaced wholesale — its `stake_mutation_seq` is
    // `#[serde(skip)]` and resets to 0 on the deserialized snapshot, so the
    // memoized staked-anchor view must be dropped explicitly or the next seal
    // tick could serve the pre-restore set. Rebuilds from authoritative state
    // on first read.
    state.invalidate_anchor_view();

    // 2. Seed CF_APPLIED from the snapshot's applied_record_ids so state_core's
    //    dedup check rejects any of these records if they arrive again via
    //    delta sync or gossip. This is the "no double apply" guarantee.
    if !snapshot.ledger.applied_record_ids.is_empty() {
        let n = snapshot.ledger.applied_record_ids.len();
        state.rocks.bulk_mark_applied(&snapshot.ledger.applied_record_ids);
        info!("snapshot bootstrap: seeded CF_APPLIED with {n} record ids from snapshot");
    } else {
        // Empty set on the wire now means one of two things (post-2026-06-24
        // producer fix): (1) a pre-fix / legacy peer that never populated the
        // set, or (2) a current peer whose CF_APPLIED exceeds
        // MAX_SNAPSHOT_APPLIED_RECORDS (1M) and intentionally shipped empty —
        // the bounded "applied watermark" follow-up (Phase 1) is what covers
        // that > 1M window. Either way we fall back to best-effort dedup: the
        // ledger is authoritative and the startup/forward rebuild re-seeds
        // CF_APPLIED from CF_RECORDS as it scans.
        warn!("snapshot bootstrap: applied_record_ids empty on wire (pre-fix peer or >1M-applied chain) — CF_APPLIED not pre-seeded, falling back to forward rebuild");
    }

    // 2b. Agent-mandate registries (C4 slice 1). A snapshot-bootstrapped
    //     follower does NOT replay pre-baseline records, so without this carry it
    //     would flag NoChain for a mandate issued before its baseline. Post-
    //     baseline issuance/revocation records sync as ordinary records and land
    //     in these CFs via the Phase-5 ingest hook. Empty on a legacy / pre-
    //     mandate snapshot (no-op).
    if !snapshot.mandates.is_empty() {
        if let Err(e) = state.rocks.apply_mandates(&snapshot.mandates) {
            warn!("snapshot bootstrap: apply_mandates failed: {e}");
        } else {
            info!("snapshot bootstrap: loaded {} mandates", snapshot.mandates.len());
        }
    }
    if !snapshot.revocations.is_empty() {
        if let Err(e) = state.rocks.apply_revocations(&snapshot.revocations) {
            warn!("snapshot bootstrap: apply_revocations failed: {e}");
        }
    }
    // EmergencyHalt state (B1) — without this carry a snapshot-bootstrapped node
    // comes up un-halted while the fleet is frozen (split-brain). Load into the live
    // atomics + persist the durable CF so a later warm restart keeps it.
    if let Some(es) = &snapshot.emergency {
        state.emergency_load_state(es);
        if let Err(e) = state.rocks.put_emergency_state(es) {
            warn!("snapshot bootstrap: persist emergency state failed: {e}");
        } else if es.halted_at(crate::network::ingest::now() as u64) {
            warn!(
                "snapshot bootstrap: chain is under an active EMERGENCY HALT (nonce={})",
                es.latest_halt_nonce
            );
        }
    }

    // 3. Finalized records
    {
        let mut finalized = state.finalized.write().await;
        finalized.restore_from_snapshot(&snapshot.finalized);
    }

    // 4. Genesis / bootstrap metadata
    if let Some(ref gs) = snapshot.genesis_state {
        let mut genesis = state.genesis_state.write_recover();
        *genesis = gs.clone();
    }
    if let Some(ref bs) = snapshot.bootstrap_state {
        let mut bootstrap = state.bootstrap_state.write_recover();
        *bootstrap = bs.clone();
    }

    // 4b. Epoch tip (B7 root-cause fix). The wire snapshot carries the chain
    //     tip — `latest_epoch` / `latest_seal_id` / `latest_seal_hash` /
    //     `latest_vrf_output` — and those maps are bound into the Dilithium3-
    //     signed `compute_checksum` (snapshot.rs), so they are authenticated by
    //     the same trusted-signer gate that admits the ledger. This path used to
    //     DISCARD them: it never wrote `state.epoch`, unlike the local-boot path
    //     (bin/elara_node.rs), which merges the persisted RocksDB epoch CF. A
    //     fresh wire-bootstrapped joiner therefore started at `our_latest = 0`,
    //     so every honest seal arrived on the UNBOUNDED fast-forward branch of
    //     `epoch::verify_epoch_seal_inner` instead of the sequential branch —
    //     which is exactly the branch a forged high-epoch seal abuses to wedge a
    //     joiner off the canonical chain (B7). Apply the signed tip here with the
    //     same monotone max-per-zone merge the local-boot path uses, so a joiner
    //     starts at the snapshot height and honest post-snapshot seals are
    //     sequential, not fast-forward. Strict `>` keeps it monotone and
    //     idempotent: a stale snapshot can never rewind a node already higher.
    if let Some(ref ep_snap) = snapshot.epoch {
        let snap_epoch = crate::network::epoch::EpochState::from_snapshot(ep_snap);
        let mut epoch = state.epoch.write_recover();
        let mut advanced = 0usize;
        for (zone, &snap_num) in &snap_epoch.latest_epoch {
            let local_num = epoch.latest_epoch.get(zone).copied().unwrap_or(0);
            if snap_num > local_num {
                epoch.latest_epoch.insert(zone.clone(), snap_num);
                if let Some(seal_id) = snap_epoch.latest_seal_id.get(zone) {
                    epoch.latest_seal_id.insert(zone.clone(), seal_id.clone());
                }
                if let Some(seal_hash) = snap_epoch.latest_seal_hash.get(zone) {
                    epoch.latest_seal_hash.insert(zone.clone(), *seal_hash);
                }
                if let Some(vrf) = snap_epoch.latest_vrf_output.get(zone) {
                    epoch.latest_vrf_output.insert(zone.clone(), *vrf);
                }
                advanced += 1;
            }
        }
        if advanced > 0 {
            info!(
                "snapshot bootstrap: epoch tip applied from signed snapshot — \
                 {advanced} zone(s) advanced to snapshot height (closes the B7 \
                 unverified fast-forward window)"
            );
        }
    }

    // 5. Consensus stake registration from the newly-loaded ledger
    {
        let ledger = state.ledger.read().await;
        state.consensus.lock_recover().register_stakes_from_ledger(&ledger);
    }

    // 6. Seed the timestamp_pull catch-up cursor to the snapshot's timestamp so
    //    subsequent delta sync starts AFTER the snapshot instead of from 0.0.
    //    This is the ledger-skip-ahead payoff: on a 10M-record chain we skip
    //    fetching the ~9.99M records that the snapshot already captured and
    //    only pull the delta since snapshot_timestamp. CF_APPLIED still guards
    //    against double-apply if a peer pushes an older record via gossip.
    //
    //    Profile gate (Gap 7 Step 3): Archive nodes MUST fetch the pre-snapshot
    //    records for DAG completeness (historical source of truth) — they
    //    skip the cursor seed and let delta sync backfill from 0. CF_APPLIED
    //    still deduplicates the ledger application, so backfill is safe and
    //    idempotent. Light / FullZone profiles skip the backfill entirely —
    //    ledger is authoritative, old records are not needed locally, and the
    //    GC retention window will prune them anyway.
    use super::node_profile::NodeProfile;
    let profile = NodeProfile::from_str(&state.config.node_profile);
    if matches!(profile, NodeProfile::Archive) {
        info!(
            "snapshot bootstrap: Archive profile — pull_catchup_cursor NOT seeded; \
             delta sync will backfill pre-snapshot records for DAG completeness \
             (CF_APPLIED dedup prevents double-apply)"
        );
    } else if let Some(ts) = snapshot.snapshot_timestamp {
        if ts > 0.0 {
            {
                let mut cursor = state.pull_catchup_cursor.lock()
                    .unwrap_or_else(|e| e.into_inner());
                if *cursor < ts {
                    *cursor = ts;
                    info!(
                        "snapshot bootstrap: pull_catchup_cursor seeded to \
                         snapshot_timestamp={ts:.3} (profile={}, skipping pre-snapshot fetch)",
                        profile.as_str()
                    );
                }
            }
            // 8b: also seed full_pull_cursor (never seeded here before) — a
            // snapshot-bootstrapped node's first full sweep otherwise starts
            // at 0.0 and re-fetches the entire pre-snapshot history once,
            // stale-declining every pruned-band seal in it. Archive skips
            // this branch entirely (full backfill is its job).
            {
                let mut fp = state
                    .full_pull_cursor
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if *fp < ts {
                    *fp = ts;
                    state.rocks.save_full_pull_cursor(ts);
                    info!(
                        "snapshot bootstrap: full_pull_cursor seeded to \
                         snapshot_timestamp={ts:.3}"
                    );
                }
            }
        }
    }

    // B5: durably advance the act-index coverage floor to the snapshot baseline.
    // A snapshot carries NO act entries, so acts before this timestamp are absent
    // on this node until delta sync re-ingests their carriers — and a
    // retention-window follower whose peers already pruned those carriers can
    // NEVER rebuild them. So absence below the baseline must read as
    // non-authoritative. Durable + monotone; this also fixes the live pre-existing
    // restart bug (ledger_loaded_from_snapshot is memory-only, so a restarted
    // snapshot follower would otherwise answer authoritative absence over its gap).
    if let Some(ts) = snapshot.snapshot_timestamp {
        if ts > 0.0 {
            // +1ms conservative bump: the snapshot ts is seconds-granular and the
            // delta-sync `since` cursor is an INCLUSIVE `>=` seek, so a record whose
            // sub-ms true time is a hair before the cursor (never re-fetched) can
            // truncate to this exact ms. Pushing the floor 1ms later makes that
            // boundary read "unknown" instead of a false RefutedForClaim in the
            // SDK's window check (B5 review LOW finding, 2026-07-19). Safe direction.
            let floor_ms = ((ts * 1000.0) as u64).saturating_add(1);
            if let Err(e) = state.rocks.advance_acts_coverage_floor(floor_ms) {
                tracing::warn!("snapshot bootstrap: failed to advance acts coverage floor: {e}");
            }
        }
    }

    // 7. Flag set: subsequent delta sync picks the cursor-based path.
    state.ledger_loaded_from_snapshot
        .store(true, std::sync::atomic::Ordering::Relaxed);
    state.snapshot_bootstrap_ledger_loaded_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // 8. Gap 7 post-apply SMT-root verify.
    //    Mirror of `apply_state_delta_for_repair`'s tail verify. After the
    //    ledger has been swapped in, rebuild the AccountStateSMT from the
    //    loaded accounts and cross-check against the producer's signed
    //    `account_state_root`. Catches local-apply bugs, version skew, and
    //    on-wire flips that didn't trip Dilithium3 verify. Counter-only
    //    signal — ledger is already committed; rollback is out of scope.
    //
    //    Skipped when the producer didn't populate the field (legacy or
    //    older producer that predates this binding). Logged + counted under `_root_absent_total` so
    //    operators can spot stale producers.
    use std::sync::atomic::Ordering;
    if let Some(ref expected_hex) = snapshot.account_state_root {
        // Mark every loaded account dirty so flush_dirty rebuilds the SMT
        // over the full set. O(accounts) — bootstrap is one-time work; the
        // SCALE RULE excludes one-shot bootstrap from "runtime hot paths".
        let pairs = {
            let mut ledger = state.ledger.write().await;
            for id in ledger.accounts.keys().cloned().collect::<Vec<_>>() {
                ledger.smt_dirty.insert(id);
            }
            super::account_merkle::snapshot_dirty(&mut ledger)
        };
        let rocks = std::sync::Arc::clone(&state.rocks);
        // CF_ACCOUNT_SMT writer gate (leaf lock — see NodeState field doc).
        // Ledger guard above is already released; held across the blocking
        // full-set apply (one-shot bootstrap work), dropped right after.
        let smt_gate = state.account_smt_write_gate.lock().await;
        let post_root = tokio::task::spawn_blocking(move || {
            super::account_merkle::apply_snapshot(&rocks, &pairs)
        })
        .await;
        drop(smt_gate);
        match post_root {
            Ok(Ok((_flushed, root))) => {
                let post_hex = hex::encode(root);
                let expected = expected_hex.trim().to_ascii_lowercase();
                if post_hex == expected {
                    state.snapshot_bootstrap_root_verified_total
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        "snapshot bootstrap (post-apply verify): SMT root match, root={}...",
                        &post_hex[..16.min(post_hex.len())]
                    );
                } else {
                    state.snapshot_bootstrap_root_mismatch_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "snapshot bootstrap (post-apply verify) ROOT MISMATCH: post_apply={} expected={} accounts={}",
                        post_hex,
                        expected,
                        snapshot.ledger.accounts.len(),
                    );
                }
            }
            Ok(Err(e)) => {
                warn!("snapshot bootstrap post-apply verify: SMT apply failed: {e}");
            }
            Err(e) => {
                warn!("snapshot bootstrap post-apply verify: spawn_blocking panicked: {e}");
            }
        }
    } else {
        state.snapshot_bootstrap_root_absent_total
            .fetch_add(1, Ordering::Relaxed);
        debug!("snapshot bootstrap: producer did not populate account_state_root — verify skipped");
    }
    Ok(())
}

// ─── Snapshot Fast Sync ─────────────────────────────────────────────────────

/// Threshold: if delta sync would need more than this many records,
/// switch to snapshot fast sync instead.
pub const SNAPSHOT_SYNC_THRESHOLD: usize = 1000;

/// Number of records per chunk in snapshot fast sync.
pub const SNAPSHOT_CHUNK_SIZE: usize = 500;

/// A single chunk of a snapshot fast sync response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotChunk {
    /// Hex-encoded wire bytes of each record in this chunk.
    pub records: Vec<String>,
    /// The cursor for the next chunk (hex-encoded hash of the last record).
    /// None if this is the final chunk.
    pub next_cursor: Option<String>,
    /// Total record count on the server (for progress tracking).
    pub total_records: u64,
    /// Number of records served so far (including this chunk).
    pub served_so_far: u64,
    /// Merkle root over ALL server records (hex). Client verifies at the end.
    pub merkle_root: String,
    /// Latest epoch number (zone 0) at the time of snapshot export.
    pub epoch_number: u64,
}

/// Metadata returned by the snapshot fast sync endpoint header.
/// Client uses this to decide whether to proceed with fast sync.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotFastMeta {
    /// Total records available on the peer.
    pub total_records: u64,
    /// Merkle root over all peer records (hex).
    pub merkle_root: String,
    /// Latest epoch number (zone 0).
    pub epoch_number: u64,
}

/// Server-side: build a snapshot chunk from storage.
///
/// Records are served in timestamp order via CF_IDX_TIMESTAMP (cursor-based pagination).
/// `cursor` is the hex-encoded CF_IDX_TIMESTAMP key from the previous chunk.
/// `since_ts` optionally filters to records after a given timestamp (from epoch seal).
///
/// Memory: O(chunk_size), not O(all_records). Merkle root via SparseMerkleTree (O(1)).
pub fn build_snapshot_chunk(
    state: &NodeState,
    cursor: Option<&str>,
    since_ts: Option<f64>,
    chunk_size: usize,
) -> Result<SnapshotChunk> {
    // Stream only chunk_size records from cursor position — O(chunk_size) memory
    let (chunk_records_raw, next_cursor) = state.rocks.stream_records_chunk(
        cursor,
        since_ts,
        chunk_size,
    )?;

    // Encode records as hex wire bytes
    let chunk_records: Vec<String> = chunk_records_raw
        .iter()
        .map(|r| hex::encode(r.to_bytes()))
        .collect();

    // Global merkle root — O(zone_count) RocksDB reads via SparseMerkleTree
    let merkle_root = hex::encode(crate::network::merkle::global_merkle_root(&state.rocks));

    // Total record count — O(1) from cached counter
    let total_records = state.record_count().unwrap_or(0) as u64;

    // Get current epoch number
    let epoch_number = state.epoch.read_recover()
        .latest_epoch.get(&crate::ZoneId::from_legacy(0)).copied().unwrap_or(0);

    // served_so_far: not precisely trackable without loading all records,
    // but the client only uses it for progress display. Approximate via
    // chunk position — if cursor is None and next_cursor is Some, we're at chunk 1.
    // For progress, total_records is the denominator and records.len() per chunk works.
    let served_so_far = chunk_records.len() as u64;

    Ok(SnapshotChunk {
        records: chunk_records,
        next_cursor,
        total_records,
        served_so_far,
        merkle_root,
        epoch_number,
    })
}

/// Client-side: perform snapshot fast sync from the best peer.
///
/// Downloads records in chunks of 500, tracks progress via cursor,
/// verifies the Merkle root at the end, and imports into local storage.
/// Falls back to delta sync if verification fails.
///
/// Returns Ok(records_imported) on success, Err on failure.
pub async fn snapshot_sync(
    state: &Arc<NodeState>,
    base_url: &str,
    since_epoch: Option<u64>,
) -> Result<u64> {
    info!("snapshot fast sync: starting from {base_url}");

    // Step 1: Get metadata to know what we're dealing with
    let meta = pq_snapshot_fast_meta(state, base_url, since_epoch).await?;
    info!(
        "snapshot fast sync: peer has {} records, merkle_root={}..., epoch={}",
        meta.total_records,
        &meta.merkle_root[..meta.merkle_root.len().min(16)],
        meta.epoch_number,
    );

    if meta.total_records == 0 {
        info!("snapshot fast sync: peer has no records");
        return Ok(0);
    }

    // Step 2: Download chunks, collecting all wire bytes
    let mut all_wire_bytes: Vec<Vec<u8>> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut chunks_downloaded = 0u32;
    let expected_merkle_root = meta.merkle_root.clone();

    loop {
        let chunk = pq_snapshot_fast_chunk(
            state,
            base_url,
            cursor.as_deref(),
            since_epoch,
        )
        .await?;

        chunks_downloaded += 1;

        // Decode records from hex
        for hex_str in &chunk.records {
            let wire = hex::decode(hex_str)
                .map_err(|e| ElaraError::Wire(format!("bad hex in snapshot chunk: {e}")))?;
            all_wire_bytes.push(wire);
        }

        debug!(
            "snapshot fast sync: chunk {} — {}/{} records",
            chunks_downloaded, chunk.served_so_far, chunk.total_records,
        );

        // Check if done
        match chunk.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    info!(
        "snapshot fast sync: downloaded {} records in {} chunks",
        all_wire_bytes.len(),
        chunks_downloaded,
    );

    // Step 3: Parse all records
    let mut records: Vec<ValidationRecord> = all_wire_bytes
        .iter()
        .filter_map(|wire| ValidationRecord::from_bytes(wire).ok())
        .collect();

    if records.len() != all_wire_bytes.len() {
        warn!(
            "snapshot fast sync: {} of {} records failed to parse",
            all_wire_bytes.len() - records.len(),
            all_wire_bytes.len(),
        );
    }

    // Step 4: Merkle verification happens AFTER import (post-import).
    // Each record imported via insert_record_synced triggers SparseMerkleTree::insert,
    // so after import our local tree will reflect the received records. We compare
    // our global_merkle_root() with the peer's reported root.
    // Pre-import verification would require O(all_records) memory — the old bug.
    // Individual records are already signature-verified during ingest.

    // Step 5: Sort by timestamp and import via multi-pass insertion
    records.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));

    let total = records.len();
    let mut remaining = records;
    let mut total_inserted = 0u64;

    for pass in 0..3 {
        if remaining.is_empty() {
            break;
        }

        let mut failed = Vec::new();
        let mut pass_inserted = 0u64;

        for record in remaining {
            let is_new = state.seen.lock_recover().insert(record.id.clone());
            if is_new {
                match gossip::insert_record_synced(state, record.clone()).await {
                    Ok(_) => {
                        pass_inserted += 1;
                    }
                    Err(e) => {
                        debug!(
                            "snapshot fast sync: record {} failed pass {}: {}",
                            &record.id[..record.id.len().min(16)],
                            pass + 1,
                            e,
                        );
                        state.seen.lock_recover().insert(record.id.clone());
                        failed.push(record);
                    }
                }
            }
        }

        total_inserted += pass_inserted;
        info!(
            "snapshot fast sync pass {}: {} inserted, {} failed",
            pass + 1,
            pass_inserted,
            failed.len(),
        );

        if failed.is_empty() || pass_inserted == 0 {
            break;
        }

        // No ledger rebuild between passes — insert_record_synced already
        // applies each record to the live ledger. Rebuilding from RocksDB
        // would double-count records (applied live + replayed from storage).

        remaining = failed;
    }

    info!(
        "snapshot fast sync complete: {total_inserted}/{total} records imported from {base_url}",
    );

    // Step 7: Post-import Merkle verification — O(zone_count) reads, not O(all_records)
    if since_epoch.is_none() && total_inserted > 0 {
        let our_root = hex::encode(crate::network::merkle::global_merkle_root(&state.rocks));
        if our_root != expected_merkle_root {
            warn!(
                "snapshot fast sync: post-import Merkle root mismatch! ours={}, expected={}",
                &our_root[..our_root.len().min(16)],
                &expected_merkle_root[..expected_merkle_root.len().min(16)],
            );
            // Don't error — records are individually verified. Mismatch may be due to
            // records we already had, timing differences, or zone count mismatch.
            // Log and continue — delta sync will reconcile remaining differences.
        } else {
            info!("snapshot fast sync: post-import Merkle root verified");
        }
    }

    Ok(total_inserted)
}

/// Decide whether to use snapshot fast sync based on the gap size.
///
/// Compares our record count to the peer's to estimate the gap.
/// If the gap exceeds SNAPSHOT_SYNC_THRESHOLD, returns true.
pub async fn should_use_fast_sync(
    state: &Arc<NodeState>,
    base_url: &str,
) -> bool {
    let our_count = state.record_count().unwrap_or(0) as u64;

    match pq_snapshot_metadata(state, base_url).await {
        Ok(meta) => {
            let peer_count = meta.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0);
            if peer_count > our_count {
                let gap = peer_count - our_count;
                if gap as usize > SNAPSHOT_SYNC_THRESHOLD {
                    info!(
                        "fast sync recommended: gap={} (ours={}, theirs={})",
                        gap, our_count, peer_count,
                    );
                    return true;
                }
            }
            false
        }
        Err(e) => {
            debug!("could not get peer metadata for fast sync decision: {e}");
            false
        }
    }
}

/// Enhanced initial sync — adds fast sync path between snapshot bootstrap and delta sync.
///
/// Decision flow:
///   1. Empty DAG → try full snapshot bootstrap (existing)
///   2. Large gap (>1000 records behind) → try snapshot fast sync
///   3. Small gap → delta sync (existing)
pub async fn initial_sync_with_fast_path(state: &Arc<NodeState>) {
    let peers = state.peers.read().await;
    let connected = peers.connected();
    if connected.is_empty() {
        info!("no peers for initial sync");
        return;
    }

    // Pick peer with highest record count for best sync source
    let mut best_peer_url = connected[0].base_url();
    let mut best_record_count = 0u64;

    for peer in &connected {
        let url = peer.base_url();
        if let Ok(meta) = pq_snapshot_metadata(state, &url).await {
            let count = meta.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0);
            if count > best_record_count {
                best_record_count = count;
                best_peer_url = url;
            }
        }
    }
    drop(peers);

    let dag_len = state.dag.read().await.len();

    // ── Phase 1: Empty DAG → full snapshot bootstrap ──────────────
    if dag_len == 0 {
        info!("empty DAG — attempting snapshot bootstrap from {best_peer_url}");
        match snapshot_bootstrap(state, &best_peer_url, false).await {
            Ok(true) => {
                info!("snapshot bootstrap complete");
                return;
            }
            Ok(false) => {
                info!("snapshot bootstrap: peer has no snapshot, trying fast sync...");
            }
            Err(e) => {
                if is_snapshot_config_error(&e) {
                    error!(
                        "snapshot bootstrap REJECTED by a config gate, not a transient fault: {e}. \
                         The delta-sync fallback rejects the seed's seals for the same reason, so the \
                         epoch will not advance until you fix this. Set genesis_authority (and \
                         min_protocol_version) to match the seed's /status, then restart — run \
                         scripts/check-my-join.sh to confirm."
                    );
                } else {
                    warn!("snapshot bootstrap failed: {e} — trying fast sync...");
                }
            }
        }
    }

    // ── Phase 2: Check if fast sync is warranted ──────────────────
    if should_use_fast_sync(state, &best_peer_url).await {
        info!("large gap detected — using snapshot fast sync from {best_peer_url}");
        match snapshot_sync(state, &best_peer_url, None).await {
            Ok(count) => {
                info!("snapshot fast sync imported {count} records");
                // After fast sync, do a quick delta sync to catch anything we missed
                info!("running delta sync to catch stragglers...");
                initial_sync(state).await;
                return;
            }
            Err(e) => {
                warn!("snapshot fast sync failed: {e} — falling back to delta sync");
            }
        }
    }

    // ── Phase 3: Fall back to delta sync ──────────────────────────
    initial_sync(state).await;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── delta-sync cross-page cursor: build_delta_page (I1/I2/C2 pins) ────

    fn cursor_test_engine() -> (crate::storage::rocks::StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = crate::storage::rocks::StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn cursor_test_record(id: &str, ts: f64) -> crate::record::ValidationRecord {
        let mut r = crate::record::ValidationRecord::create(
            b"cursor-test",
            vec![0xAA; 1952],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        r.id = id.to_string();
        r.timestamp = ts;
        r
    }

    fn raw_key(ts: f64, id: &str) -> Vec<u8> {
        let mut k = ts.to_be_bytes().to_vec();
        k.extend_from_slice(id.as_bytes());
        k
    }

    /// Legacy/page-1: full delivery → next_cursor = last-SCANNED key (the
    /// page-2 upgrade handle, audit C1), legacy fields intact, echo absent.
    #[test]
    fn build_delta_page_legacy_page1_mints_upgrade_cursor() {
        let (engine, _dir) = cursor_test_engine();
        for (i, id) in ["pg-a", "pg-b", "pg-c"].iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 10.0 + i as f64)).unwrap();
        }
        let bloom = BloomFilter::new(8, 0.01); // empty → everything missing
        let page = build_delta_page(&engine, &bloom, 0.0, 0, 10, None).unwrap();
        assert_eq!(page.records_wire.len(), 3);
        assert_eq!(page.total_missing, Some(3));
        assert_eq!(page.scan_hit_cap, Some(false));
        assert!(!page.has_more, "all misses delivered, window < MAX_SCAN");
        assert!(page.cursor_echo.is_none(), "legacy page must not echo");
        assert_eq!(
            page.next_cursor.as_deref(),
            Some(encode_sync_cursor(&raw_key(12.0, "pg-c")).as_str()),
            "full delivery → frontier = last scanned"
        );
    }

    /// C2 blocker pin: when the count cap truncates a slice with misses
    /// remaining, next_cursor = last-INCLUDED key (unserved misses stay
    /// AHEAD of the frontier — no skip), has_more=true; and chaining pages
    /// covers every record exactly once (I1 at the fn level).
    #[test]
    fn build_delta_page_cursor_cap_bound_frontier_is_last_included_no_skip() {
        let (engine, _dir) = cursor_test_engine();
        let ids = ["cc-a", "cc-b", "cc-c", "cc-d"];
        for (i, id) in ids.iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 20.0 + i as f64)).unwrap();
        }
        let bloom = BloomFilter::new(8, 0.01);
        // Page 1 (legacy, batch_size=1): serves cc-a; misses remain → C2 on
        // the legacy page: frontier = last INCLUDED (cc-a).
        let p1 = build_delta_page(&engine, &bloom, 0.0, 0, 1, None).unwrap();
        assert_eq!(p1.records_wire.len(), 1);
        assert!(p1.has_more);
        assert_eq!(
            p1.next_cursor.as_deref(),
            Some(encode_sync_cursor(&raw_key(20.0, "cc-a")).as_str()),
            "cap-bound legacy page → frontier = last included"
        );
        // Page 2 (cursor, batch_size=1): resumes AFTER cc-a → serves cc-b;
        // cc-c is a seen miss beyond the cap → cap_bound → frontier = cc-b.
        let c1 = parse_sync_cursor(p1.next_cursor.as_deref().unwrap()).unwrap();
        let p2 = build_delta_page(&engine, &bloom, 0.0, 0, 1, Some(&c1)).unwrap();
        assert_eq!(p2.records_wire.len(), 1);
        assert!(p2.has_more, "cap bound with misses remaining");
        assert_eq!(
            p2.cursor_echo.as_deref(),
            Some(encode_sync_cursor(&c1).as_str()),
            "cursor page must echo the request cursor"
        );
        assert_eq!(
            p2.next_cursor.as_deref(),
            Some(encode_sync_cursor(&raw_key(21.0, "cc-b")).as_str()),
            "C2: cap-bound cursor page → frontier = last included, NOT last scanned"
        );
        assert!(p2.missing_in_slice.unwrap_or(0) >= 2, "walked misses counted");
        // Chain to exhaustion: every record served exactly once.
        let mut served: Vec<usize> = vec![p1.records_wire.len(), p2.records_wire.len()];
        let mut cur = parse_sync_cursor(p2.next_cursor.as_deref().unwrap()).unwrap();
        for _ in 0..6 {
            let p = build_delta_page(&engine, &bloom, 0.0, 0, 1, Some(&cur)).unwrap();
            served.push(p.records_wire.len());
            if !p.has_more {
                assert!(p.next_cursor.is_some(), "drained page still names a frontier");
                break;
            }
            cur = parse_sync_cursor(p.next_cursor.as_deref().unwrap()).unwrap();
        }
        assert_eq!(served.iter().sum::<usize>(), ids.len(), "I1: exactly once, no skip/dup");
    }

    /// I2 pin: an all-match bloom (0 misses) still advances the frontier to
    /// the end of the walked window and terminates (has_more=false) — the
    /// 0-record page is progress, not a stall.
    #[test]
    fn build_delta_page_cursor_zero_record_page_advances_frontier() {
        let (engine, _dir) = cursor_test_engine();
        let mut bloom = BloomFilter::new(8, 0.001);
        for (i, id) in ["z-a", "z-b", "z-c"].iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 30.0 + i as f64)).unwrap();
            bloom.insert(id.as_bytes());
        }
        let start = parse_sync_cursor(&encode_sync_cursor(&raw_key(30.0, "z-a"))).unwrap();
        let p = build_delta_page(&engine, &bloom, 0.0, 0, 10, Some(&start)).unwrap();
        assert!(p.records_wire.is_empty());
        assert_eq!(p.missing_in_slice, Some(0));
        assert!(!p.has_more, "window drained");
        assert_eq!(
            p.next_cursor.as_deref(),
            Some(encode_sync_cursor(&raw_key(32.0, "z-c")).as_str()),
            "I2: empty page still advances the frontier to last scanned"
        );
    }

    // ── delta-sync cross-page cursor codec (I3 parse pins) ────────────────

    /// Roundtrip + every reject class of `parse_sync_cursor`, incl. the
    /// bit-level `-0.0` case (be-bytes `0x8000…` sort above every real key
    /// while IEEE `-0.0 >= 0.0` is true — "audit 16e" class). Each reject is
    /// `ElaraError::Wire` (→ 400 on both transports), never a fallback.
    #[test]
    fn parse_sync_cursor_roundtrip_and_fail_closed_rejects() {
        // Roundtrip: encode → parse yields the exact raw key.
        let mut raw = 1_700_000_000.0f64.to_be_bytes().to_vec();
        raw.extend_from_slice(b"019506e0-1234-7000-8000-000000000001");
        let hex_cursor = encode_sync_cursor(&raw);
        assert_eq!(
            parse_sync_cursor(&hex_cursor).expect("valid cursor must parse"),
            raw
        );
        // Boundary: exactly-at-cap id (MAX_RECORD_ID_LEN) parses.
        let mut at_cap = 100.0f64.to_be_bytes().to_vec();
        at_cap.extend_from_slice("b".repeat(crate::record::MAX_RECORD_ID_LEN).as_bytes());
        let at_cap_hex = encode_sync_cursor(&at_cap);
        assert_eq!(at_cap_hex.len(), MAX_CURSOR_HEX_LEN);
        assert!(parse_sync_cursor(&at_cap_hex).is_ok());

        let reject = |hex_str: &str, label: &str| {
            let err = parse_sync_cursor(hex_str)
                .expect_err(&format!("{label} must be rejected"));
            assert!(
                matches!(err, crate::errors::ElaraError::Wire(_)),
                "{label}: reject must be ElaraError::Wire (400), got {err:?}"
            );
        };

        // Timestamp bit-level rejects: -0.0, NaN, +inf, -1.0.
        for (ts_bytes, label) in [
            ((-0.0f64).to_be_bytes(), "-0.0 (sign-bit) cursor ts"),
            (f64::NAN.to_be_bytes(), "NaN cursor ts"),
            (f64::INFINITY.to_be_bytes(), "+inf cursor ts"),
            ((-1.0f64).to_be_bytes(), "negative cursor ts"),
        ] {
            let mut bad = ts_bytes.to_vec();
            bad.extend_from_slice(b"id");
            reject(&encode_sync_cursor(&bad), label);
        }
        // Length/shape rejects.
        reject("", "empty cursor");
        reject(&hex_cursor[..16], "ts-only cursor (no id byte)");
        reject(&hex_cursor[..17], "odd-length hex");
        reject(&format!("{}{}", at_cap_hex, "aa"), "over MAX_CURSOR_HEX_LEN");
        reject(&"zz".repeat(10), "non-hex chars");
        // Id rejects: non-utf8 / non-ascii byte in the id part.
        let mut non_ascii = 100.0f64.to_be_bytes().to_vec();
        non_ascii.extend_from_slice(&[0x80, 0x81]);
        reject(&encode_sync_cursor(&non_ascii), "non-utf8 id bytes");
    }

    /// Production budget consts pin: the budget-injected fn is test plumbing
    /// only — these are the values every production page is built with.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn delta_page_budget_consts_pin() {
        assert_eq!(MAX_SCAN, 50_000);
        assert_eq!(PAGE_SCAN, 10_000);
        assert_eq!(MAX_CURSOR_HEX_LEN, 272);
        assert!(
            PAGE_SCAN < MAX_SCAN,
            "cursor pages must be strictly cheaper than the legacy scan"
        );
    }

    /// I6 pin of the ONE deliberate legacy-semantics change:
    /// `has_more |= scan_hit_cap`. A page-1 scan that hits the cap with every
    /// scanned id already in the client's bloom (deep window, client holds
    /// the head) previously reported has_more=false — a cursor-capable
    /// client would stop at the 50K frontier and false-heal. Now it reports
    /// has_more=true + a frontier cursor to keep paging. Old clients see an
    /// empty batch and terminate via their existing `batch_len == 0` break
    /// (≤1 extra page).
    #[test]
    fn build_delta_page_legacy_scan_cap_forces_has_more_for_upgrade() {
        let (engine, _dir) = cursor_test_engine();
        let mut bloom = BloomFilter::new(8, 0.001);
        for (i, id) in ["sc-a", "sc-b", "sc-c", "sc-d", "sc-e"].iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 40.0 + i as f64)).unwrap();
            bloom.insert(id.as_bytes());
        }
        // max_scan=3 stands in for MAX_SCAN: scan truncates at sc-c with
        // zero bloom-misses found.
        let page = build_delta_page_budgeted(
            &engine, &bloom, 0.0, 0, 10, None, 3, PAGE_SCAN,
            MAX_SYNC_RESPONSE_HEX_BYTES,
        )
        .unwrap();
        assert!(page.records_wire.is_empty());
        assert_eq!(page.total_missing, Some(0));
        assert_eq!(page.scan_hit_cap, Some(true));
        assert!(
            page.has_more,
            "I6: has_more must be true when the scan cap binds, even with 0 misses"
        );
        assert_eq!(
            page.next_cursor.as_deref(),
            Some(encode_sync_cursor(&raw_key(42.0, "sc-c")).as_str()),
            "frontier = last scanned, the page-2 upgrade handle past the cap"
        );
    }

    /// I2 full pin: an all-match window deeper than the per-page scan budget
    /// terminates in exactly ceil(window/page_scan) cursor pages, every page
    /// 0-record with a strictly-advancing frontier and honest has_more.
    #[test]
    fn build_delta_page_cursor_page_scan_budget_terminates_in_ceil_pages() {
        let (engine, _dir) = cursor_test_engine();
        let mut bloom = BloomFilter::new(8, 0.001);
        let ids = ["ps-a", "ps-b", "ps-c", "ps-d", "ps-e"];
        for (i, id) in ids.iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 60.0 + i as f64)).unwrap();
            bloom.insert(id.as_bytes());
        }
        // Start strictly below the window (ts=0 sorts below every real key).
        let mut cursor = raw_key(0.0, "0");
        let mut pages = 0usize;
        let mut frontiers: Vec<Vec<u8>> = Vec::new();
        loop {
            // page_scan=2 stands in for PAGE_SCAN over the 5-record window.
            let p = build_delta_page_budgeted(
                &engine, &bloom, 0.0, 0, 10, Some(&cursor), MAX_SCAN, 2,
                MAX_SYNC_RESPONSE_HEX_BYTES,
            )
            .unwrap();
            pages += 1;
            assert!(p.records_wire.is_empty(), "all-match window serves 0 records");
            assert_eq!(p.missing_in_slice, Some(0));
            let nc = parse_sync_cursor(p.next_cursor.as_deref().expect("frontier"))
                .unwrap();
            assert!(
                nc.as_slice() > cursor.as_slice(),
                "I2: frontier must strictly advance on every 0-record page"
            );
            frontiers.push(nc.clone());
            if !p.has_more {
                break;
            }
            cursor = nc;
            assert!(pages < 10, "must terminate");
        }
        assert_eq!(pages, ids.len().div_ceil(2), "ceil(window/page_scan) pages");
        assert_eq!(
            frontiers.last().unwrap().as_slice(),
            raw_key(64.0, "ps-e").as_slice(),
            "final frontier = end of window"
        );
    }

    /// I1/I3 byte-cap pin (the C2 regression case with the BYTE cap, not the
    /// count cap, doing the truncating): a dense slice of records fatter than
    /// the page byte budget serves one record per page (first always ships —
    /// progress guarantee), frontier = last INCLUDED (never past an unserved
    /// miss), and chaining covers every record exactly once.
    #[test]
    fn build_delta_page_cursor_byte_cap_fat_records_no_skip() {
        let (engine, _dir) = cursor_test_engine();
        let bloom = BloomFilter::new(8, 0.01); // empty → everything missing
        let ids = ["fat-a", "fat-b", "fat-c"];
        for (i, id) in ids.iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 80.0 + i as f64)).unwrap();
        }
        // Records are ~2 KiB wire (Dilithium3-sized pk) → ~4 KiB hex cost;
        // a 3 KiB budget admits exactly one per page ("fat" is a ratio).
        let byte_budget = 3 * 1024;
        let mut cursor = raw_key(0.0, "0");
        let mut served = 0usize;
        for (i, id) in ids.iter().enumerate() {
            let p = build_delta_page_budgeted(
                &engine, &bloom, 0.0, 0, 10, Some(&cursor), MAX_SCAN, PAGE_SCAN,
                byte_budget,
            )
            .unwrap();
            served += p.records_wire.len();
            assert_eq!(
                p.records_wire.len(),
                1,
                "byte cap admits exactly the always-ships first record"
            );
            let nc = parse_sync_cursor(p.next_cursor.as_deref().expect("frontier")).unwrap();
            assert_eq!(
                nc.as_slice(),
                raw_key(80.0 + i as f64, id).as_slice(),
                "C2: cap-bound page frontier = last INCLUDED record, no skip"
            );
            if i < ids.len() - 1 {
                assert!(p.has_more, "misses remain past the byte cap");
            } else {
                assert!(!p.has_more, "window drained on the final page");
            }
            cursor = nc;
        }
        assert_eq!(served, ids.len(), "I1: exactly once");
    }

    /// I4 pin: a backdated insert BEHIND the cursor frontier is invisible to
    /// the rest of this cycle (deterministically — offset paging made this
    /// probabilistic) and is picked up by the next cycle's page-1 window
    /// re-scan. Same self-heal contract as the offset path.
    #[test]
    fn build_delta_page_backdated_insert_missed_then_caught_next_cycle() {
        let (engine, _dir) = cursor_test_engine();
        let bloom = BloomFilter::new(8, 0.01); // empty → everything missing
        for (i, id) in ["bd-a", "bd-b", "bd-c"].iter().enumerate() {
            engine.put_record(id, &cursor_test_record(id, 90.0 + i as f64)).unwrap();
        }
        // Page 1 delivers the full window; frontier = last scanned (bd-c).
        let p1 = build_delta_page(&engine, &bloom, 0.0, 0, 10, None).unwrap();
        assert_eq!(p1.records_wire.len(), 3);
        let frontier = parse_sync_cursor(p1.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(frontier.as_slice(), raw_key(92.0, "bd-c").as_slice());
        // Concurrent backdated ingest lands BEHIND the frontier.
        engine.put_record("bd-x", &cursor_test_record("bd-x", 91.5)).unwrap();
        // Rest of THIS cycle (cursor page past the frontier): not listed.
        let p2 = build_delta_page(&engine, &bloom, 0.0, 0, 10, Some(&frontier)).unwrap();
        assert!(
            p2.records_wire.is_empty(),
            "I4: backdated insert behind the frontier is missed this cycle"
        );
        assert!(!p2.has_more);
        // NEXT cycle's page 1 re-scans the window from `since`: listed.
        let p3 = build_delta_page(&engine, &bloom, 0.0, 0, 10, None).unwrap();
        assert_eq!(
            p3.records_wire.len(),
            4,
            "I4: next cycle's window re-scan picks the backdated record up"
        );
    }

    /// I5/C5 shape pin at the JSON layer both transports serialize through:
    /// cursor pages carry exactly the cursor-path field set (NO
    /// total_missing/scan_hit_cap/offset — the client's window-level gauge
    /// overwrite must stay inert), legacy pages carry exactly today's field
    /// set plus the additive next_cursor.
    #[test]
    fn delta_page_json_field_sets_pin_c5() {
        let keys = |v: &serde_json::Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        let cursor_page = DeltaPage {
            records_wire: vec![],
            total_missing: None,
            missing_in_slice: Some(2),
            has_more: true,
            scan_hit_cap: None,
            next_cursor: Some("aa".repeat(9)),
            cursor_echo: Some("bb".repeat(9)),
        };
        assert_eq!(
            keys(&delta_page_json(&cursor_page, vec![], 0)),
            ["batch_size", "cursor_echo", "has_more", "missing_in_slice", "next_cursor", "records"],
            "C5: cursor pages must omit total_missing/scan_hit_cap/offset"
        );
        let legacy_page = DeltaPage {
            records_wire: vec![],
            total_missing: Some(7),
            missing_in_slice: None,
            has_more: false,
            scan_hit_cap: Some(false),
            next_cursor: Some("cc".repeat(9)),
            cursor_echo: None,
        };
        assert_eq!(
            keys(&delta_page_json(&legacy_page, vec![], 0)),
            ["batch_size", "has_more", "next_cursor", "offset", "records", "scan_hit_cap", "total_missing"],
            "I6: legacy pages = today's fields + additive next_cursor only"
        );
    }

    // ── delta_sync _other failure classification ──────────────────────────
    //
    // Pins classify_delta_sync_other against the EXACT error strings produced
    // by PqClient (pq_client.rs) + derive_pq_addr. If any of those error texts
    // change, this test breaks — forcing the classifier (and the discriminated
    // _other_{addr,dial,rpc,decode} counters that depend on it) to be updated in
    // lockstep, instead of the metric silently misbucketing. This is the
    // silent-wire-break lesson applied to the detector itself: a string the
    // metric depends on must be guarded by a test.
    #[test]
    fn delta_sync_other_failure_buckets_match_real_error_strings() {
        use DeltaSyncOtherKind::*;
        // IP literals below are RFC 5737 TEST-NET-1 (192.0.2.0/24) documentation
        // placeholders — the classifier keys on the error-string SHAPE, not the
        // address. Never substitute a real fleet host IP here (publish-scrub gate).
        // derive_pq_addr (sync.rs:324) + gossip.rs addr site
        assert_eq!(
            classify_delta_sync_other("cannot derive PQ peer addr from \"http://seed:9474\""),
            Addr
        );
        // pq_client.rs:375 — dial+handshake stage, non-timeout (connect OR reject)
        assert_eq!(
            classify_delta_sync_other("pq_dial 192.0.2.1:9573: connection refused"),
            Dial
        );
        assert_eq!(
            classify_delta_sync_other("pq_dial 192.0.2.1:9573: identity pin mismatch"),
            Dial
        );
        // pq_client.rs:391 — post-handshake RPC transport, non-timeout (the
        // silent-wire-break signature: AEAD-on-data / peer-closed mid-call)
        assert_eq!(
            classify_delta_sync_other("rpc 192.0.2.1:9573: AEAD verification failed"),
            Rpc
        );
        assert_eq!(
            classify_delta_sync_other("rpc 192.0.2.1:9573: peer closed connection"),
            Rpc
        );
        // pq_client.rs:402 (ensure_ok), :412 (json_body), :988/:996 (delta_sync decode)
        assert_eq!(classify_delta_sync_other("delta_sync returned status 400"), Decode);
        assert_eq!(
            classify_delta_sync_other("delta_sync parse: invalid type at line 1 column 2"),
            Decode
        );
        assert_eq!(
            classify_delta_sync_other("unexpected delta_sync response format"),
            Decode
        );
        assert_eq!(classify_delta_sync_other("bad hex: odd number of digits"), Decode);
        // Unknown / pin-store-rejected stay uncategorized (in _other_total only)
        assert_eq!(
            classify_delta_sync_other("pin store rejected 1.2.3.4:9573: db error"),
            Uncategorized
        );
        assert_eq!(classify_delta_sync_other("something entirely new"), Uncategorized);
    }

    // ── snapshot_bootstrap config-error classification ────────────────────

    #[test]
    fn config_gate_errors_are_classified_not_transient() {
        use crate::errors::ElaraError;
        // The two CONFIG gates a misconfigured first-time joiner trips — wrong
        // genesis_authority (trust) / wrong min_protocol_version (version) — must
        // classify as config errors so the boot path logs the actionable fix
        // instead of a misleading "falling back" warn. Keyed on the same labels
        // the map_err sites emit, so a label rename can't silently desync.
        let trust = ElaraError::Wire(format!(
            "{SNAPSHOT_TRUST_GATE_LABEL} (peer=http://seed:9474): signer abcd not trusted"
        ));
        let version = ElaraError::Wire(format!(
            "{SNAPSHOT_VERSION_GATE_LABEL} (peer=http://seed:9474): snapshot v1 < min v2"
        ));
        assert!(is_snapshot_config_error(&trust), "trust gate must be a config error");
        assert!(is_snapshot_config_error(&version), "version gate must be a config error");

        // The epoch-indexed path emits the EPOCH_-prefixed labels. They must
        // classify too, so snapshot_bootstrap can short-circuit a config error
        // there instead of downloading the guaranteed-to-fail live snapshot.
        let epoch_trust = ElaraError::Wire(format!(
            "{EPOCH_SNAPSHOT_TRUST_GATE_LABEL} (peer=http://seed:9474 epoch=42): signer abcd not trusted"
        ));
        let epoch_version = ElaraError::Wire(format!(
            "{EPOCH_SNAPSHOT_VERSION_GATE_LABEL} (peer=http://seed:9474 epoch=42): snapshot v1 < min v2"
        ));
        assert!(is_snapshot_config_error(&epoch_trust), "epoch-indexed trust gate must be a config error");
        assert!(is_snapshot_config_error(&epoch_version), "epoch-indexed version gate must be a config error");

        // Transient/network faults must NOT be classified as config errors — they
        // keep the retry-friendly fallback path and its warn-level log.
        let transient = ElaraError::Wire("connection refused (peer=http://seed:9474)".into());
        assert!(!is_snapshot_config_error(&transient), "transient fault must not be a config error");
    }

    #[test]
    fn epoch_labels_are_superstrings_of_live_labels() {
        // is_snapshot_config_error keys on the two LIVE labels but must also
        // catch the epoch-indexed path's errors. That only holds because each
        // EPOCH_ label CONTAINS its live counterpart — a single `contains` on
        // the live label matches both. Pin the invariant so a rename that
        // breaks the substring relationship fails loudly here instead of
        // silently letting an epoch-path config error fall through unclassified.
        assert!(
            EPOCH_SNAPSHOT_TRUST_GATE_LABEL.contains(SNAPSHOT_TRUST_GATE_LABEL),
            "epoch trust label must remain a superstring of the live trust label"
        );
        assert!(
            EPOCH_SNAPSHOT_VERSION_GATE_LABEL.contains(SNAPSHOT_VERSION_GATE_LABEL),
            "epoch version label must remain a superstring of the live version label"
        );
    }

    // ── Merkle Tree tests ─────────────────────────────────────────────────

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(MerkleTree::root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = sha3_256(b"one");
        assert_eq!(MerkleTree::root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_two() {
        let h1 = sha3_256(b"left");
        let h2 = sha3_256(b"right");
        let root = MerkleTree::root(&[h1, h2]);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&h1);
        combined[32..].copy_from_slice(&h2);
        assert_eq!(root, sha3_256(&combined));
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes: Vec<[u8; 32]> = (0..10u8).map(|i| sha3_256(&[i])).collect();
        let root1 = MerkleTree::root(&hashes);
        let root2 = MerkleTree::root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let h1 = sha3_256(b"a");
        let h2 = sha3_256(b"b");
        let root_ab = MerkleTree::root(&[h1, h2]);
        let root_ba = MerkleTree::root(&[h2, h1]);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn test_merkle_proof_valid() {
        let mut hashes: Vec<[u8; 32]> = (0..8u8).map(|i| sha3_256(&[i])).collect();
        hashes.sort();
        let proof = MerkleTree::proof(&hashes, &hashes[3]).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_invalid_tamper() {
        let mut hashes: Vec<[u8; 32]> = (0..8u8).map(|i| sha3_256(&[i])).collect();
        hashes.sort();
        let mut proof = MerkleTree::proof(&hashes, &hashes[3]).unwrap();
        proof.leaf[0] ^= 0xFF;
        assert!(!MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_missing_leaf() {
        let hashes: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let missing = sha3_256(b"not_in_set");
        assert!(MerkleTree::proof(&hashes, &missing).is_none());
    }

    // ── Bloom Filter tests ────────────────────────────────────────────────

    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = BloomFilter::new(100, 0.01);
        bloom.insert(b"hello");
        bloom.insert(b"world");
        assert!(bloom.contains(b"hello"));
        assert!(bloom.contains(b"world"));
        assert!(!bloom.contains(b"missing"));
    }

    /// Drift-guard: the `delta_sync` body cap MUST admit the largest bloom an
    /// honest client ever sends — `BloomFilter::new(MAX_BLOOM_BUILD, 0.01)`. If a
    /// future `MAX_BLOOM_BUILD` bump pushes the serialized bloom past the cap, this
    /// fails CI (forcing a matching `MAX_DELTA_SYNC_BLOOM_BODY` bump) instead of
    /// silently 413ing real peers' delta_sync requests. The upper bound keeps the
    /// cap a meaningful bound, not a rubber stamp far above the real artifact.
    #[test]
    fn delta_sync_body_cap_admits_max_bloom_build() {
        let serialized = BloomFilter::new(MAX_BLOOM_BUILD, 0.01).to_bytes().len();
        assert!(
            serialized <= MAX_DELTA_SYNC_BLOOM_BODY,
            "delta_sync cap {MAX_DELTA_SYNC_BLOOM_BODY} < max honest bloom {serialized} \
             (MAX_BLOOM_BUILD={MAX_BLOOM_BUILD}) — bump MAX_DELTA_SYNC_BLOOM_BODY"
        );
        assert!(
            MAX_DELTA_SYNC_BLOOM_BODY <= serialized * 4,
            "delta_sync cap {MAX_DELTA_SYNC_BLOOM_BODY} > 4x max honest bloom {serialized} \
             — tighten toward the ~234 KiB artifact"
        );
    }

    /// Drift-guard (upper): the per-page response byte cap MUST transfer within
    /// one RPC deadline on the phone-tier link floor, else a fresh joiner's page
    /// times out every retry (root cause 2026-07-03, cellular hotspot). Budget =
    /// the per-page `DEFAULT_CALL_TIMEOUT` minus fixed overhead (TCP connect + PQ
    /// handshake + bloom upload + loss retransmit) at a 0.5 Mbps floor. A future
    /// bump toward the old 6 MiB — or even 1.5 MiB — trips this instead of
    /// silently re-breaking slow-link catch-up. The durable way to raise it is
    /// chunked streaming under a per-chunk idle timeout, NOT a bigger single page.
    #[test]
    fn sync_response_cap_fits_slow_link_deadline() {
        const FLOOR_BYTES_PER_SEC: f64 = 62_500.0; // 0.5 Mbps — phone-tier floor
        const OVERHEAD_SECS: f64 = 8.0; // connect + PQ handshake + bloom up + loss
        let transfer_secs = MAX_SYNC_RESPONSE_HEX_BYTES as f64 / FLOOR_BYTES_PER_SEC;
        let deadline = crate::network::pq_client::DEFAULT_CALL_TIMEOUT.as_secs_f64();
        assert!(
            transfer_secs + OVERHEAD_SECS < deadline,
            "response cap {MAX_SYNC_RESPONSE_HEX_BYTES}B needs {transfer_secs:.1}s + \
             {OVERHEAD_SECS:.0}s overhead > {deadline:.0}s RPC deadline at the \
             {FLOOR_BYTES_PER_SEC:.0} B/s floor — a page this large times out on the \
             slow-link floor; lower the cap or add chunked streaming"
        );
    }

    /// Drift-guard (lower / progress guarantee): the cap MUST admit at least one
    /// max-size record (hex-doubled, plus envelope) so the first-record-always-
    /// ships branch in `handle_delta_sync` can never stall a peer whose next
    /// needed record is a fat one. Guards a future over-aggressive shrink — below
    /// this a single fat record is an entire page (worst server re-scan amp).
    #[test]
    fn sync_response_cap_admits_one_max_record() {
        let one_record_hex = crate::network::ingest::MAX_RECORD_BYTES * 2 + 64;
        assert!(
            MAX_SYNC_RESPONSE_HEX_BYTES > one_record_hex,
            "response cap {MAX_SYNC_RESPONSE_HEX_BYTES}B < one max record hex \
             {one_record_hex}B — a single fat record would be a whole page; raise the cap"
        );
    }

    #[test]
    fn test_bloom_filter_roundtrip() {
        let mut bloom = BloomFilter::new(50, 0.01);
        bloom.insert(b"test_item");
        let bytes = bloom.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes).unwrap();
        assert!(restored.contains(b"test_item"));
        assert!(!restored.contains(b"other"));
    }

    #[test]
    fn test_bloom_filter_short_bytes() {
        assert!(BloomFilter::from_bytes(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_bloom_filter_truncated_word_data() {
        // Header claims num_bits=64 (1 word = 8 bytes needed) but only the
        // 8-byte header is present — from_bytes must return Err, not panic.
        let mut buf = Vec::new();
        buf.extend_from_slice(&64u32.to_be_bytes()); // num_bits = 64
        buf.extend_from_slice(&2u32.to_be_bytes());  // num_hashes = 2
        // expected_len = 8 + 1*8 = 16, but buf.len() = 8 → Err
        let err = BloomFilter::from_bytes(&buf);
        assert!(err.is_err(), "truncated word data must return Err");
    }

    #[test]
    fn test_bloom_filter_huge_num_bits_claim_rejected_without_overallocation() {
        // DoS guard: a peer-supplied header may claim num_bits up to u32::MAX
        // (~67M u64 words ≈ 536 MB) in an 8-byte body. The delta_sync paths
        // (routes/sync.rs + pq_transport/router.rs::handle_delta_sync) decode
        // peer blooms straight off the wire, so the ONLY thing between that
        // claim and a 536 MB `Vec::with_capacity` is the `data.len() <
        // expected_len` length gate that sits BEFORE the alloc in from_bytes.
        // test_bloom_filter_truncated_word_data uses num_bits=64 (1 word) and so
        // cannot distinguish guard-before-alloc from guard-after-alloc — both
        // orderings pass it. This pins the ordering invariant: claim the
        // maximum, supply only the 8-byte header, and require an immediate Err.
        // A refactor that hoists `Vec::with_capacity(expected_words)` above the
        // length gate re-opens the remote OOM vector and fails here (the alloc
        // runs, then the word loop slices data[8..16] out of an 8-byte body and
        // panics — either way this test does not see a clean Err).
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes()); // num_bits = 4_294_967_295
        buf.extend_from_slice(&8u32.to_be_bytes()); // num_hashes = 8 (valid)
        assert_eq!(buf.len(), 8, "only the header is supplied — no word data");
        let decoded = BloomFilter::from_bytes(&buf);
        assert!(
            decoded.is_err(),
            "huge num_bits claim with no word data must be rejected at the \
             length gate before allocating expected_words"
        );
    }

    #[test]
    fn test_bloom_filter_rejects_oversized_num_hashes_cpu_exhaustion_vector() {
        // SS-1 (2026-07-03 audit): insert/contains loop `0..num_hashes`, so a
        // peer-supplied num_hashes far above the legitimate ceiling (u32::MAX =
        // ~4B iterations per item) is a remote CPU-exhaustion vector from an
        // 8-byte header. `optimal_num_hashes` never exceeds BLOOM_MAX_HASHES=32,
        // so `from_bytes` must reject anything larger at the header gate.
        let mk = |nh: u32| {
            let mut b = Vec::new();
            b.extend_from_slice(&64u32.to_be_bytes()); // num_bits = 64 (valid)
            b.extend_from_slice(&nh.to_be_bytes());
            b.extend_from_slice(&[0u8; 8]); // 1 word of bit data (passes length gate)
            b
        };
        assert!(
            BloomFilter::from_bytes(&mk(u32::MAX)).is_err(),
            "num_hashes=u32::MAX must be rejected (SS-1 CPU-exhaustion guard)"
        );
        assert!(BloomFilter::from_bytes(&mk(33)).is_err(), "33 exceeds BLOOM_MAX_HASHES=32");
        assert!(BloomFilter::from_bytes(&mk(32)).is_ok(), "32 is the legitimate ceiling");
        assert!(BloomFilter::from_bytes(&mk(1)).is_ok(), "1 hash is valid");
    }

    #[test]
    fn test_bloom_filter_rejects_zero_num_bits_remote_panic_vector() {
        // A peer-supplied bloom with num_bits=0 used to decode into a filter
        // whose first `contains`/`insert` computed `% 0` in `combined_hash` —
        // a div-by-zero panic in BOTH debug and release. The delta_sync routes
        // (routes/sync.rs + pq_transport/router.rs) decode peer blooms straight
        // off the wire, so an 8-byte body would crash the node. from_bytes MUST
        // reject the header instead of producing a panic-on-use filter.
        let mut zero_bits = Vec::new();
        zero_bits.extend_from_slice(&0u32.to_be_bytes()); // num_bits = 0
        zero_bits.extend_from_slice(&7u32.to_be_bytes()); // num_hashes = 7
        // expected_words = 0, expected_len = 8 == data.len() → passed the length
        // gate before the fix and constructed a num_bits=0 filter.
        assert_eq!(zero_bits.len(), 8, "this is the minimal crash payload");
        let decoded = BloomFilter::from_bytes(&zero_bits);
        assert!(
            decoded.is_err(),
            "num_bits=0 must be rejected at decode, not panic on first contains()"
        );

        // num_hashes=0 is also structurally impossible from new() (optimal_num_hashes
        // clamps to 1..=32) and yields a filter that vacuously "contains" everything —
        // reject it at the boundary too.
        let mut zero_hashes = Vec::new();
        zero_hashes.extend_from_slice(&64u32.to_be_bytes()); // num_bits = 64
        zero_hashes.extend_from_slice(&0u32.to_be_bytes());  // num_hashes = 0
        zero_hashes.extend_from_slice(&0u64.to_be_bytes());  // 1 word of bits
        assert!(
            BloomFilter::from_bytes(&zero_hashes).is_err(),
            "num_hashes=0 must be rejected at decode"
        );

        // A well-formed filter still round-trips — the guard rejects only the
        // structurally-invalid headers, nothing new() can legitimately produce.
        let mut good = BloomFilter::new(50, 0.01);
        good.insert(b"x");
        assert!(BloomFilter::from_bytes(&good.to_bytes()).is_ok());
    }

    // ── Snapshot chunk serialization tests ─────────────────────────────────

    #[test]
    fn test_snapshot_chunk_serde() {
        let chunk = SnapshotChunk {
            records: vec!["deadbeef".into(), "cafebabe".into()],
            next_cursor: Some("abc123".into()),
            total_records: 5000,
            served_so_far: 500,
            merkle_root: "ff".repeat(32),
            epoch_number: 42,
        };

        let json = serde_json::to_string(&chunk).unwrap();
        let restored: SnapshotChunk = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.records.len(), 2);
        assert_eq!(restored.next_cursor, Some("abc123".into()));
        assert_eq!(restored.total_records, 5000);
        assert_eq!(restored.served_so_far, 500);
        assert_eq!(restored.epoch_number, 42);
    }

    #[test]
    fn test_snapshot_chunk_final() {
        let chunk = SnapshotChunk {
            records: vec!["last_batch".into()],
            next_cursor: None,
            total_records: 100,
            served_so_far: 100,
            merkle_root: "aa".repeat(32),
            epoch_number: 10,
        };

        let json = serde_json::to_string(&chunk).unwrap();
        let restored: SnapshotChunk = serde_json::from_str(&json).unwrap();
        assert!(restored.next_cursor.is_none(), "final chunk should have no cursor");
    }

    #[test]
    fn test_snapshot_fast_meta_serde() {
        let meta = SnapshotFastMeta {
            total_records: 10000,
            merkle_root: "bb".repeat(32),
            epoch_number: 99,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let restored: SnapshotFastMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_records, 10000);
        assert_eq!(restored.epoch_number, 99);
    }

    // ── Merkle verification of snapshot data ──────────────────────────────

    #[test]
    fn test_snapshot_merkle_verification_honest() {
        // Simulate: server has 50 records, client downloads all, verifies Merkle root
        let records: Vec<Vec<u8>> = (0..50u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();

        let hashes: Vec<[u8; 32]> = records.iter().map(|r| sha3_256(r)).collect();
        let mut sorted_hashes = hashes.clone();
        sorted_hashes.sort();
        let server_root = MerkleTree::root(&sorted_hashes);

        // Client recomputes from received data
        let client_hashes: Vec<[u8; 32]> = records.iter().map(|r| sha3_256(r)).collect();
        let mut client_sorted = client_hashes;
        client_sorted.sort();
        let client_root = MerkleTree::root(&client_sorted);

        assert_eq!(
            hex::encode(server_root),
            hex::encode(client_root),
            "honest snapshot should pass Merkle verification"
        );
    }

    #[test]
    fn test_snapshot_merkle_verification_tampered() {
        // Server computes root from 50 records
        let records: Vec<Vec<u8>> = (0..50u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();

        let hashes: Vec<[u8; 32]> = records.iter().map(|r| sha3_256(r)).collect();
        let mut sorted_hashes = hashes;
        sorted_hashes.sort();
        let server_root = MerkleTree::root(&sorted_hashes);

        // Client receives tampered data: one record replaced
        let mut tampered_records = records;
        tampered_records[25] = vec![0xFF; 10]; // replace record 25

        let client_hashes: Vec<[u8; 32]> = tampered_records.iter().map(|r| sha3_256(r)).collect();
        let mut client_sorted = client_hashes;
        client_sorted.sort();
        let client_root = MerkleTree::root(&client_sorted);

        assert_ne!(
            hex::encode(server_root),
            hex::encode(client_root),
            "tampered snapshot must fail Merkle verification"
        );
    }

    #[test]
    fn test_snapshot_merkle_verification_missing_record() {
        // Server has 50 records
        let records: Vec<Vec<u8>> = (0..50u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();

        let hashes: Vec<[u8; 32]> = records.iter().map(|r| sha3_256(r)).collect();
        let mut sorted_hashes = hashes;
        sorted_hashes.sort();
        let server_root = MerkleTree::root(&sorted_hashes);

        // Client only receives 49 records (one dropped)
        let partial_records: Vec<Vec<u8>> = (0..49u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();

        let client_hashes: Vec<[u8; 32]> = partial_records.iter().map(|r| sha3_256(r)).collect();
        let mut client_sorted = client_hashes;
        client_sorted.sort();
        let client_root = MerkleTree::root(&client_sorted);

        assert_ne!(
            hex::encode(server_root),
            hex::encode(client_root),
            "snapshot with missing record must fail Merkle verification"
        );
    }

    #[test]
    fn test_snapshot_merkle_verification_extra_record() {
        // Server has 50 records
        let records: Vec<Vec<u8>> = (0..50u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();

        let hashes: Vec<[u8; 32]> = records.iter().map(|r| sha3_256(r)).collect();
        let mut sorted_hashes = hashes;
        sorted_hashes.sort();
        let server_root = MerkleTree::root(&sorted_hashes);

        // Client receives 51 records (one injected)
        let mut extra_records: Vec<Vec<u8>> = (0..50u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();
        extra_records.push(vec![0xDE, 0xAD]); // injected record

        let client_hashes: Vec<[u8; 32]> = extra_records.iter().map(|r| sha3_256(r)).collect();
        let mut client_sorted = client_hashes;
        client_sorted.sort();
        let client_root = MerkleTree::root(&client_sorted);

        assert_ne!(
            hex::encode(server_root),
            hex::encode(client_root),
            "snapshot with injected record must fail Merkle verification"
        );
    }

    // ── Threshold / decision logic tests ──────────────────────────────────

    #[test]
    fn test_snapshot_sync_threshold_constant() {
        assert_eq!(SNAPSHOT_SYNC_THRESHOLD, 1000);
        assert_eq!(SNAPSHOT_CHUNK_SIZE, 500);
    }

    #[test]
    fn test_snapshot_chunk_pagination_simulation() {
        // Simulate chunked pagination with cursors
        let total = 1250;
        let chunk_size = 500;

        let records: Vec<String> = (0..total)
            .map(|i| format!("record_{i:04}"))
            .collect();

        // Chunk 1: records 0..500
        let chunk1_end = chunk_size.min(total);
        let chunk1 = &records[0..chunk1_end];
        assert_eq!(chunk1.len(), 500);
        let cursor1 = &records[chunk1_end - 1]; // "record_0499"

        // Chunk 2: records 500..1000
        let chunk2_start = chunk1_end;
        let chunk2_end = (chunk2_start + chunk_size).min(total);
        let chunk2 = &records[chunk2_start..chunk2_end];
        assert_eq!(chunk2.len(), 500);
        let cursor2 = &records[chunk2_end - 1]; // "record_0999"

        // Chunk 3: records 1000..1250 (final)
        let chunk3_start = chunk2_end;
        let chunk3 = &records[chunk3_start..total];
        assert_eq!(chunk3.len(), 250);

        // Total collected
        assert_eq!(chunk1.len() + chunk2.len() + chunk3.len(), total);
        assert_ne!(cursor1, cursor2);
    }

    // ── Resume simulation tests ───────────────────────────────────────────

    #[test]
    fn test_cursor_based_resume() {
        // Simulate: download 2 chunks, "disconnect", resume from cursor
        let all_data: Vec<[u8; 32]> = (0..20u32)
            .map(|i| sha3_256(&i.to_be_bytes()))
            .collect();

        // First download: get items 0..10
        let first_batch = &all_data[0..10];
        let resume_cursor = hex::encode(first_batch.last().unwrap());

        // Resume: find cursor position, continue from there
        let cursor_bytes = hex::decode(&resume_cursor).unwrap();
        let resume_pos = all_data.iter().position(|h| h[..] == cursor_bytes[..]).unwrap() + 1;
        let resumed_batch = &all_data[resume_pos..];

        assert_eq!(resumed_batch.len(), 10);
        assert_eq!(first_batch.len() + resumed_batch.len(), all_data.len());

        // Verify no overlap
        for item in first_batch {
            assert!(!resumed_batch.contains(item), "resumed batch should not overlap");
        }
    }

    /// Verify that delta sync's yield-every-50 pattern allows other tasks to run.
    /// This validates the anti-starvation mechanism: a concurrent task should
    /// complete within a reasonable time even while 500 items are being processed.
    #[tokio::test]
    async fn test_delta_sync_yield_allows_concurrent_tasks() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};

        let processed = Arc::new(AtomicU32::new(0));
        let concurrent_completed = Arc::new(AtomicU32::new(0));

        let processed2 = processed.clone();
        let concurrent2 = concurrent_completed.clone();

        // Simulate delta sync: process 500 items with yield every 50
        let sync_task = tokio::spawn(async move {
            for i in 0u32..500 {
                // Simulate work per record
                std::hint::black_box(i * 31 + 17);
                processed2.fetch_add(1, Ordering::Relaxed);

                // Same yield pattern as real delta sync
                if i > 0 && i % 50 == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });

        // Concurrent "health check" task — should complete quickly
        let health_task = tokio::spawn(async move {
            // Wait a bit for sync to start
            tokio::time::sleep(Duration::from_millis(5)).await;
            // This should run during a yield point
            concurrent2.fetch_add(1, Ordering::Relaxed);
        });

        // Both should complete within 2 seconds
        let result = timeout(Duration::from_secs(2), async {
            let _ = sync_task.await;
            let _ = health_task.await;
        }).await;

        assert!(result.is_ok(), "delta sync + health check should complete within 2s");
        assert_eq!(processed.load(Ordering::Relaxed), 500);
        assert_eq!(concurrent_completed.load(Ordering::Relaxed), 1,
            "concurrent health task should have completed during yield points");
    }

    // ── Gap 7 real closure (2026-04-21): bootstrap ledger skip-ahead ─────

    /// Build a NodeState backed by a tempdir, suitable for testing snapshot
    /// bootstrap side effects without spinning up the real network stack.
    fn test_state_for_bootstrap() -> Arc<NodeState> {
        test_state_for_bootstrap_with_profile("full_zone")
    }

    /// Variant that lets Gap 7 Step 3 tests pick a specific node profile —
    /// exercises the "Archive backfills / Light+FullZone skip" cursor-seed gate.
    fn test_state_for_bootstrap_with_profile(profile: &str) -> Arc<NodeState> {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap7-bootstrap-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            node_profile: profile.to_string(),
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp); // keep dir alive for the life of the test
        state
    }

    #[tokio::test]
    async fn test_apply_bootstrap_snapshot_full_loads_ledger_and_seeds_cf_applied() {
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();

        // Pre-condition: flag unset, CF_APPLIED empty.
        assert!(!state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(state.rocks.applied_count(), 0);
        assert_eq!(state.snapshot_bootstrap_ledger_loaded_total.load(std::sync::atomic::Ordering::Relaxed), 0);

        // Build a snapshot whose ledger carries 3 applied record ids. These are
        // the IDs a new bootstrapping node must learn about so it doesn't
        // double-apply them when delta sync fetches the record bytes.
        let mut ledger = LedgerState::new();
        ledger.total_supply = 42;
        let mut applied: HashSet<String> = HashSet::new();
        applied.insert("rec_1".to_string());
        applied.insert("rec_2".to_string());
        applied.insert("rec_3".to_string());
        ledger.applied_record_ids = applied.clone();

        let snapshot = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());

        // Act
        apply_bootstrap_snapshot_full(&state, &snapshot, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        // Post-condition: flag set, counter bumped, CF_APPLIED seeded, ledger loaded.
        assert!(
            state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed),
            "flag must be set after apply_bootstrap_snapshot_full"
        );
        assert_eq!(
            state.snapshot_bootstrap_ledger_loaded_total.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "counter should tick exactly once per apply"
        );
        assert_eq!(state.rocks.applied_count(), 3, "CF_APPLIED must contain all 3 ids from snapshot");
        for id in &applied {
            assert!(state.rocks.is_applied(id), "id {} must be marked applied", id);
        }
        assert_eq!(state.ledger.read().await.total_supply, 42, "ledger total_supply must match snapshot");
    }

    #[tokio::test]
    async fn b7_apply_bootstrap_snapshot_full_restores_epoch_tip() {
        // B7 root-cause fix: a wire-bootstrapped joiner must adopt the SIGNED
        // epoch tip from the snapshot (latest_epoch / latest_seal_hash), so its
        // our_latest starts at snapshot height and honest seals are sequential —
        // not fast-forward. Pre-fix this path discarded snapshot.epoch entirely,
        // leaving the joiner at epoch 0 (the condition that armed the B7 wedge).
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();
        let z0 = crate::ZoneId::from_legacy(0);
        // Pre-condition: fresh node has no epoch tip for the zone.
        assert!(!state.epoch.read().unwrap().latest_epoch.contains_key(&z0));

        let mut ep = EpochState::new();
        ep.latest_epoch.insert(z0.clone(), 5000);
        ep.latest_seal_hash.insert(z0.clone(), [0xAB; 32]);
        ep.latest_seal_id.insert(z0.clone(), "seal-5000".to_string());

        let snapshot = NodeSnapshot::new(LedgerState::new(), HashSet::new(), ep);
        apply_bootstrap_snapshot_full(&state, &snapshot, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        let restored = state.epoch.read().unwrap();
        assert_eq!(
            restored.latest_epoch.get(&z0).copied(), Some(5000),
            "bootstrap must adopt the signed snapshot epoch tip"
        );
        assert_eq!(
            restored.latest_seal_hash.get(&z0).copied(), Some([0xAB; 32]),
            "bootstrap must adopt the signed latest_seal_hash"
        );
    }

    #[tokio::test]
    async fn rebootstrap_refuses_behind_snapshot_without_force() {
        // Admin-audit 2026-07-05: applying a snapshot whose signed epoch tip is
        // BEHIND the local tip is a permanent ledger-content rollback (CF_APPLIED
        // dedup suppresses re-apply) that the height-keyed divergence monitor
        // can't see. The apply must REFUSE outright — not silently monotone-merge
        // — unless the caller explicitly forces.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();
        let z0 = crate::ZoneId::from_legacy(0);
        // Local node already at epoch 6000 with live ledger content.
        {
            let mut ep = state.epoch.write().unwrap();
            ep.latest_epoch.insert(z0.clone(), 6000);
            ep.latest_seal_hash.insert(z0.clone(), [0xCC; 32]);
        }
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = 777;
        }

        // Behind snapshot at epoch 5000 carrying different ledger content.
        let mut snap_ep = EpochState::new();
        snap_ep.latest_epoch.insert(z0.clone(), 5000);
        snap_ep.latest_seal_hash.insert(z0.clone(), [0xAB; 32]);
        let mut stale_ledger = LedgerState::new();
        stale_ledger.total_supply = 1;
        let snapshot = NodeSnapshot::new(stale_ledger, HashSet::new(), snap_ep);

        let res = apply_bootstrap_snapshot_full(&state, &snapshot, false).await;
        assert!(res.is_err(), "behind snapshot without force must be refused");

        // Nothing may have been touched: ledger content, epoch tip, and the
        // loaded-from-snapshot flag all keep their pre-call values.
        assert_eq!(state.ledger.read().await.total_supply, 777, "ledger must be untouched on refusal");
        let after = state.epoch.read().unwrap();
        assert_eq!(after.latest_epoch.get(&z0).copied(), Some(6000), "tip must be untouched on refusal");
        assert!(
            !state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed),
            "flag must not be set on refusal"
        );
    }

    #[tokio::test]
    async fn b7_bootstrap_epoch_merge_is_monotone_never_rewinds_even_forced() {
        // Safety: even when the operator FORCES a behind-snapshot apply
        // (accepting the ledger-content rewind), the epoch-tip merge stays
        // strict-greater per zone — the tip itself is never rewound, so
        // post-force seal verification remains sequential from the local tip.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();
        let z0 = crate::ZoneId::from_legacy(0);
        // Local node already at epoch 6000.
        {
            let mut ep = state.epoch.write().unwrap();
            ep.latest_epoch.insert(z0.clone(), 6000);
            ep.latest_seal_hash.insert(z0.clone(), [0xCC; 32]);
        }

        // Stale snapshot at epoch 5000, force-applied.
        let mut snap_ep = EpochState::new();
        snap_ep.latest_epoch.insert(z0.clone(), 5000);
        snap_ep.latest_seal_hash.insert(z0.clone(), [0xAB; 32]);
        let snapshot = NodeSnapshot::new(LedgerState::new(), HashSet::new(), snap_ep);
        apply_bootstrap_snapshot_full(&state, &snapshot, true)
            .await
            .expect("forced apply must proceed past the rollback guard");

        let after = state.epoch.read().unwrap();
        assert_eq!(after.latest_epoch.get(&z0).copied(), Some(6000), "stale snapshot must not rewind the tip");
        assert_eq!(after.latest_seal_hash.get(&z0).copied(), Some([0xCC; 32]), "seal_hash must not be rewound");
    }

    /// Audit 2026-06-15 item (f2): `staker_index` is `#[serde(skip)]`, so a
    /// snapshot's deserialized ledger arrives with it EMPTY while `stakes`
    /// (serialized) is full. `apply_bootstrap_snapshot_full` MUST
    /// `rebuild_staker_index()` from the carried stakes — otherwise the
    /// per-staker `staker_stakes` map (built by `register_stakes_from_ledger`
    /// iterating `staker_index` at step 5) comes out empty post-bootstrap,
    /// silently disabling liveness-decay for every staker on a freshly
    /// bootstrapped node. Five other restore paths already call this; this one
    /// was missed.
    #[tokio::test]
    async fn test_apply_bootstrap_snapshot_full_rebuilds_staker_index() {
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::{LedgerState, StakeEntry};
        use crate::accounting::types::StakePurpose;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();

        // A ledger in the post-deserialize shape: `stakes` populated, but
        // `staker_index` EMPTY (exactly what serde(skip) yields on the wire).
        let mut ledger = LedgerState::new();
        let staker = "anchor_staker_hash".to_string();
        ledger.accounts.entry(staker.clone()).or_default().staked = 500;
        ledger.total_staked = 500;
        ledger.stakes.insert(
            "stake_rec_1".to_string(),
            StakeEntry {
                record_id: "stake_rec_1".to_string(),
                amount: 500,
                purpose: StakePurpose::Witness,
                staker: staker.clone(),
                timestamp: 0.0,
                active: true,
            },
        );
        assert!(
            ledger.staker_index.is_empty(),
            "precondition: staker_index empty, as after deserialize"
        );

        let snapshot = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());
        apply_bootstrap_snapshot_full(&state, &snapshot, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        // The loaded ledger's staker_index must be rebuilt from carried stakes,
        // so the downstream register_stakes_from_ledger (same bootstrap) sees it.
        let l = state.ledger.read().await;
        assert!(
            l.staker_index.contains_key(&staker),
            "bootstrap must rebuild_staker_index from the carried stakes"
        );
        assert_eq!(l.staker_index.get(&staker).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn test_apply_bootstrap_snapshot_full_seeds_pull_catchup_cursor() {
        // Gap 7 Step 3: the catch-up cursor is the mechanism that lets
        // timestamp_pull skip ahead instead of re-pulling the ~all records the
        // snapshot already covers. Must advance to snapshot_timestamp and
        // MUST NOT regress if the local cursor is already further along.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();

        // Pre-condition: cursor starts at 0.0.
        assert_eq!(
            *state.pull_catchup_cursor.lock().unwrap(), 0.0,
            "pre: cursor must start at 0.0"
        );

        // Case 1: snapshot timestamp advances the cursor.
        let mut ledger = LedgerState::new();
        ledger.total_supply = 1;
        let mut snap = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());
        snap.snapshot_timestamp = Some(1_700_000_000.0);
        apply_bootstrap_snapshot_full(&state, &snap, false).await.expect("guard passes");
        assert_eq!(
            *state.pull_catchup_cursor.lock().unwrap(), 1_700_000_000.0,
            "cursor must seed to snapshot_timestamp on fresh bootstrap"
        );

        // Case 2: a snapshot with an EARLIER timestamp must NOT regress the cursor
        // (e.g., if gossip pulls have already advanced it past the snapshot).
        let mut ledger2 = LedgerState::new();
        ledger2.total_supply = 2;
        let mut snap2 = NodeSnapshot::new(ledger2, HashSet::new(), EpochState::default());
        snap2.snapshot_timestamp = Some(1_699_000_000.0); // earlier than case 1
        apply_bootstrap_snapshot_full(&state, &snap2, false).await.expect("guard passes");
        assert_eq!(
            *state.pull_catchup_cursor.lock().unwrap(), 1_700_000_000.0,
            "cursor must NOT regress on earlier-snapshot apply"
        );

        // Case 3: snapshot with no timestamp leaves cursor unchanged.
        let mut ledger3 = LedgerState::new();
        ledger3.total_supply = 3;
        let snap3 = NodeSnapshot::new(ledger3, HashSet::new(), EpochState::default());
        // snapshot_timestamp is None by default
        apply_bootstrap_snapshot_full(&state, &snap3, false).await.expect("guard passes");
        assert_eq!(
            *state.pull_catchup_cursor.lock().unwrap(), 1_700_000_000.0,
            "cursor must not change when snapshot has no timestamp"
        );
    }

    #[tokio::test]
    async fn test_archive_profile_does_not_seed_pull_catchup_cursor() {
        // Gap 7 Step 3 decision: Archive nodes are the historical source of
        // truth and MUST backfill pre-snapshot records for DAG completeness.
        // That requires pull_catchup_cursor to stay at 0.0 post-bootstrap so
        // timestamp_pull starts from genesis. Ledger state is still loaded
        // from the snapshot; CF_APPLIED still deduplicates ledger application
        // when delta sync redelivers those records. Archive just ALSO keeps
        // the record bytes and DAG edges.
        //
        // Light / FullZone take the opposite path: cursor seeded to
        // snapshot_timestamp so pre-snapshot fetches are skipped — the
        // "load ledger in seconds, never touch old records" behavior.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        // ── Archive profile: cursor MUST stay at 0.0 ──────────────────────
        let archive = test_state_for_bootstrap_with_profile("archive");
        assert_eq!(*archive.pull_catchup_cursor.lock().unwrap(), 0.0);

        let mut ledger = LedgerState::new();
        ledger.total_supply = 99;
        let mut snap = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());
        snap.snapshot_timestamp = Some(1_700_000_000.0);

        apply_bootstrap_snapshot_full(&archive, &snap, false).await.expect("guard passes");

        assert_eq!(
            *archive.pull_catchup_cursor.lock().unwrap(), 0.0,
            "Archive must not seed cursor — delta sync backfills pre-snapshot records"
        );
        assert!(
            archive.ledger_loaded_from_snapshot
                .load(std::sync::atomic::Ordering::Relaxed),
            "Archive still loads the ledger from snapshot (skip is only on the fetch-skip side)"
        );
        assert_eq!(archive.ledger.read().await.total_supply, 99);

        // ── Light profile: cursor MUST seed to snapshot_timestamp ─────────
        let light = test_state_for_bootstrap_with_profile("light");
        let mut ledger_l = LedgerState::new();
        ledger_l.total_supply = 99;
        let mut snap_l = NodeSnapshot::new(ledger_l, HashSet::new(), EpochState::default());
        snap_l.snapshot_timestamp = Some(1_700_000_000.0);

        apply_bootstrap_snapshot_full(&light, &snap_l, false).await.expect("guard passes");

        assert_eq!(
            *light.pull_catchup_cursor.lock().unwrap(), 1_700_000_000.0,
            "Light must seed cursor — skips pre-snapshot fetch entirely"
        );

        // ── FullZone (default): cursor MUST seed to snapshot_timestamp ────
        let full_zone = test_state_for_bootstrap_with_profile("full_zone");
        let mut ledger_f = LedgerState::new();
        ledger_f.total_supply = 99;
        let mut snap_f = NodeSnapshot::new(ledger_f, HashSet::new(), EpochState::default());
        snap_f.snapshot_timestamp = Some(1_700_000_000.0);

        apply_bootstrap_snapshot_full(&full_zone, &snap_f, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        assert_eq!(
            *full_zone.pull_catchup_cursor.lock().unwrap(), 1_700_000_000.0,
            "FullZone must seed cursor — skips pre-snapshot fetch entirely"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_does_not_double_apply() {
        // Gap 7 Step 4: the CF_APPLIED dedup seeded by apply_bootstrap_snapshot_full
        // is the brake on double-application when delta sync redelivers records
        // the snapshot already accounted for. Simulate the exact sequence:
        //   (1) snapshot ships with ledger state + applied_record_ids
        //   (2) loader seeds CF_APPLIED via bulk_mark_applied
        //   (3) delta sync redelivers a record whose id is in that set
        //   (4) ingest's is_applied gate (ingest.rs:1416) returns true → skipped
        // Without step (2), the ledger apply in ingest.rs would run a second time
        // and corrupt balances. This test asserts the gate mechanism fires.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();

        // (1) Snapshot: ledger has supply=1000, applied_record_ids covers 5 ops.
        let mut ledger = LedgerState::new();
        ledger.total_supply = 1000;
        let applied_ids: Vec<String> = (0..5).map(|i| format!("op_{i}")).collect();
        ledger.applied_record_ids = applied_ids.iter().cloned().collect::<HashSet<_>>();
        let snapshot = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());

        // (2) Loader seeds CF_APPLIED.
        apply_bootstrap_snapshot_full(&state, &snapshot, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        // (3)+(4) For every id the snapshot claims is applied, the is_applied gate
        // must return true — this is the same lookup ingest.rs:1416 uses to short-
        // circuit the ledger.write() + apply_single_record path.
        for id in &applied_ids {
            assert!(
                state.rocks.is_applied(id),
                "gate failure: is_applied({id}) must return true after bootstrap"
            );
        }

        // Also confirm a NEW id (post-snapshot delta) is NOT gated — it must still
        // flow through the normal apply path.
        assert!(
            !state.rocks.is_applied("op_new_after_snapshot"),
            "gate must only fire on ids the snapshot explicitly covered"
        );

        // And ledger supply must match snapshot — proving the bootstrap loaded
        // authoritative state without needing a replay of the 5 applied ops.
        assert_eq!(
            state.ledger.read().await.total_supply,
            1000,
            "ledger must reflect snapshot total_supply — no replay, no double-apply"
        );
    }

    #[tokio::test]
    async fn test_apply_bootstrap_snapshot_full_handles_empty_applied_set() {
        // Backward-compat: an older peer may ship a snapshot with an empty
        // applied_record_ids set. The loader must still set the ledger + flag
        // without panicking; it just can't pre-seed CF_APPLIED.
        use crate::network::epoch::EpochState;
        use crate::network::snapshot::NodeSnapshot;
        use crate::accounting::ledger::LedgerState;
        use std::collections::HashSet;

        let state = test_state_for_bootstrap();

        let mut ledger = LedgerState::new();
        ledger.total_supply = 7;
        let snapshot = NodeSnapshot::new(ledger, HashSet::new(), EpochState::default());

        apply_bootstrap_snapshot_full(&state, &snapshot, false)
            .await
            .expect("bootstrap apply must pass the rollback guard in this test");

        assert!(state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(state.rocks.applied_count(), 0, "empty set → CF_APPLIED stays empty");
        assert_eq!(state.ledger.read().await.total_supply, 7);
    }

    // ── delta_sync_since_floor ────────────────────────
    //
    // The floor is the watermark passed to peers as `x-delta-since`. Server-
    // side this gates the timestamp-index scan to records ≥ floor — at 10M+
    // records that's the difference between a 30s+ verb stall and a sub-second
    // bloom-test loop. Tests pin both the empty-DB path (returns 0.0 for
    // first-boot) and the populated-DB path (newest_ts - 24h).

    fn ops123_test_record(timestamp: f64, id_seed: &str) -> crate::record::ValidationRecord {
        crate::record::ValidationRecord {
            id: id_seed.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(id_seed.as_bytes()).to_vec(),
            creator_public_key: vec![0u8; 32],
            timestamp,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: std::collections::BTreeMap::new(),
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
        }
    }

    #[tokio::test]
    async fn test_ops123_delta_sync_since_floor_empty_db_returns_zero() {
        let state = test_state_for_bootstrap();
        let floor = delta_sync_since_floor(&state);
        assert_eq!(
            floor, 0.0,
            "empty DB must return 0.0 (full sweep on first boot — peers still cap at MAX_SCAN)"
        );
    }

    #[tokio::test]
    async fn test_ops123_delta_sync_since_floor_subtracts_24h_window() {
        let state = test_state_for_bootstrap();
        let newest_ts = 1_730_000_000.0;
        for (i, ts) in [newest_ts - 7200.0, newest_ts - 3600.0, newest_ts]
            .iter()
            .enumerate()
        {
            let id = format!("ops123-rec-{i}");
            let rec = ops123_test_record(*ts, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }
        let floor = delta_sync_since_floor(&state);
        let expected = newest_ts - 86400.0;
        assert!(
            (floor - expected).abs() < 1e-6,
            "since-floor should be newest_ts - 24h: got {floor}, expected {expected}"
        );
    }

    #[tokio::test]
    async fn test_ops123_delta_sync_since_floor_clamps_to_zero_for_old_records() {
        // If newest record is genesis-era (< 24h after epoch), floor would go
        // negative — must clamp to 0.0 so the timestamp-index seek doesn't
        // get a malformed seek key.
        let state = test_state_for_bootstrap();
        let rec = ops123_test_record(100.0, "ops123-old");
        state.rocks.put_record("ops123-old", &rec).expect("put_record");
        let floor = delta_sync_since_floor(&state);
        assert_eq!(floor, 0.0, "newest_ts < 24h must clamp floor to 0.0");
    }

    #[tokio::test]
    async fn test_ops123_record_ids_from_bounded_scan() {
        // The server-side primitive used by handle_delta_sync. With limit=2
        // we should only see the 2 oldest records ≥ since, never all 5.
        // This is the core SCALE invariant — bounded work per dial.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_000_000.0;
        for i in 0..5 {
            let id = format!("ops123-scan-{i}");
            let rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }
        let scanned = state
            .rocks
            .record_ids_from(base_ts, 2)
            .expect("record_ids_from");
        assert_eq!(scanned.len(), 2, "scan must respect limit=2 cap");

        let all = state
            .rocks
            .record_ids_from(base_ts, 100)
            .expect("record_ids_from");
        assert_eq!(all.len(), 5, "limit=100 returns all 5 records ≥ since");

        let later = state
            .rocks
            .record_ids_from(base_ts + 90.0, 100)
            .expect("record_ids_from");
        assert_eq!(later.len(), 3, "since past first 2 records returns only 3");
    }

    // ── Task 2419: snapshot fast-sync resume / partial-snapshot tests ──────
    //
    // Covers three snapshot fast-sync resume gaps:
    //   * partial-snapshot pagination (chunk → cursor → next chunk walk)
    //   * mid-fetch peer-drop (client saved cursor, resumes from it)
    //   * resume-from-saved-checkpoint with stale / combined filters
    //
    // All four hit the real `build_snapshot_chunk` against a tempdir-backed
    // NodeState — they pin the cursor-skip behaviour in stream_records_chunk
    // so a future change can't silently regress double-serve or skip-record.

    #[tokio::test]
    async fn test_build_snapshot_chunk_partial_paginates_with_cursor() {
        // 7 records, chunk_size=3 → three calls walk 3+3+1, last chunk has no
        // cursor. Pins the partial-snapshot invariant for clients that don't
        // get the full set in one round-trip.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_100_000.0;
        for i in 0..7u32 {
            let id = format!("snap-partial-{i:02}");
            let rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // Chunk 1: no cursor, expect 3 records + non-None cursor.
        let c1 = build_snapshot_chunk(&state, None, None, 3).expect("chunk1");
        assert_eq!(c1.records.len(), 3, "chunk_size=3 must cap chunk1 at 3");
        assert!(c1.next_cursor.is_some(), "more records remain → cursor must be set");
        let cursor1 = c1.next_cursor.clone().unwrap();

        // Chunk 2: feed cursor1 back, expect 3 more (no overlap with chunk 1).
        let c2 = build_snapshot_chunk(&state, Some(&cursor1), None, 3).expect("chunk2");
        assert_eq!(c2.records.len(), 3, "chunk_size=3 must cap chunk2 at 3");
        assert!(c2.next_cursor.is_some(), "1 record still remains");
        let cursor2 = c2.next_cursor.clone().unwrap();
        assert_ne!(cursor1, cursor2, "cursor must advance between chunks");
        for hex in &c2.records {
            assert!(!c1.records.contains(hex), "chunk2 must not overlap chunk1");
        }

        // Chunk 3: final tail. next_cursor must be None now.
        let c3 = build_snapshot_chunk(&state, Some(&cursor2), None, 3).expect("chunk3");
        assert_eq!(c3.records.len(), 1, "last chunk has 7 - 3 - 3 = 1 record");
        assert!(c3.next_cursor.is_none(), "final chunk must report no cursor");

        // All seven IDs reachable across the three chunks (no gaps, no dupes).
        let total: usize = c1.records.len() + c2.records.len() + c3.records.len();
        assert_eq!(total, 7, "partial walk must reach every record exactly once");
    }

    #[tokio::test]
    async fn test_build_snapshot_chunk_byte_budget_paginates_before_frame_cap() {
        // Fat records (35 KB sig ≈ 74 KB hex each) whose combined size crosses
        // the 1 MiB MAX_SYNC_RESPONSE_HEX_BYTES budget long before a 500-count
        // chunk. The chunk must cap by BYTES (staying under the 16 MiB PQ frame,
        // so the serve doesn't silently close) AND still report next_cursor=Some
        // so fast sync paginates — the pre-fix count-only next_cursor would have
        // reported a false final chunk and truncated the sync.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_200_000.0;
        const FAT: usize = 40; // ~40 × 74 KB hex ≈ 3 MB, ~14 fit one 1 MiB page
        for i in 0..FAT as u32 {
            let id = format!("snap-fat-{i:03}");
            let mut rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            rec.signature = Some(vec![0xBB; 35_000]);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // Request a huge chunk: chunk_size far exceeds what fits in the budget.
        let c1 = build_snapshot_chunk(&state, None, None, 500).expect("chunk1");
        assert!(
            c1.records.len() < FAT,
            "byte budget must cap the chunk below all {FAT} records (got {})",
            c1.records.len()
        );
        assert!(!c1.records.is_empty(), "progress guarantee: at least one record");
        let chunk_hex: usize = c1.records.iter().map(|r| r.len()).sum();
        assert!(
            chunk_hex <= MAX_SYNC_RESPONSE_HEX_BYTES + 200_000,
            "chunk hex {chunk_hex}B must stay within budget + one-record margin"
        );
        assert!(
            c1.next_cursor.is_some(),
            "byte-capped short page MUST still paginate (pre-fix: false final chunk)"
        );

        // Walk the remaining pages: every record reachable exactly once.
        let mut seen = std::collections::HashSet::new();
        for r in &c1.records {
            assert!(seen.insert(r.clone()), "no dupes within a chunk");
        }
        let mut cursor = c1.next_cursor.clone();
        let mut guard = 0;
        while let Some(cur) = cursor {
            guard += 1;
            assert!(guard < 100, "byte-paginated walk must terminate");
            let c = build_snapshot_chunk(&state, Some(&cur), None, 500).expect("chunkN");
            for r in &c.records {
                assert!(seen.insert(r.clone()), "no record served twice across pages");
            }
            cursor = c.next_cursor.clone();
        }
        assert_eq!(seen.len(), FAT, "byte-paginated walk must reach every record once");
    }

    #[tokio::test]
    async fn test_build_snapshot_chunk_resume_from_checkpoint_no_overlap() {
        // Mid-fetch peer-drop: download chunk 1, save cursor, simulate
        // disconnect, then resume from the cursor. The resumed chunk must NOT
        // re-serve the boundary record (cursor-skip invariant in
        // stream_records_chunk). This is the path a real client takes when
        // the HTTP connection drops mid-stream and it retries from the last
        // cursor it persisted.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_200_000.0;
        for i in 0..6u32 {
            let id = format!("snap-resume-{i:02}");
            let rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // First chunk: 2 records.
        let c1 = build_snapshot_chunk(&state, None, None, 2).expect("chunk1");
        assert_eq!(c1.records.len(), 2);
        let saved_cursor = c1.next_cursor.clone().expect("more records remain");

        // "Drop the connection" — open a fresh chunk request from saved cursor.
        // (No state change in between; mirrors a client retry.)
        let c2 = build_snapshot_chunk(&state, Some(&saved_cursor), None, 100)
            .expect("resume chunk");

        // Resumed chunk must contain exactly the remaining 4 records.
        assert_eq!(
            c2.records.len(), 4,
            "resume must return all remaining records (6 total - 2 served = 4)"
        );
        assert!(c2.next_cursor.is_none(), "resume drained the tail");

        // No overlap: the boundary record (last one in chunk1) must NOT appear
        // in chunk2. This is the cursor-skip invariant.
        for hex in &c1.records {
            assert!(
                !c2.records.contains(hex),
                "resumed chunk must not re-serve any record from chunk1 \
                 (cursor-skip invariant broken)"
            );
        }
    }

    #[tokio::test]
    async fn test_build_snapshot_chunk_stale_cursor_advances_safely() {
        // Edge case: client saved a cursor, then crashed, and by the time it
        // resumes the server may have compacted or otherwise lost the exact
        // CF_IDX_TIMESTAMP key the cursor points to. The seek lands on the
        // next-greater key (Forward direction); the skip-on-equal logic
        // simply falls through. Result: we still get records ≥ cursor, just
        // possibly including the original boundary record.
        //
        // The invariant we pin: a bogus / non-existent cursor never panics
        // and still produces a valid (record_count, next_cursor) pair.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_300_000.0;
        for i in 0..4u32 {
            let id = format!("snap-stale-{i:02}");
            let rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // Cursor that doesn't match any CF_IDX_TIMESTAMP key — 16 zero bytes.
        // Forward-seek lands on the first real key, no record is skipped.
        let bogus_cursor = hex::encode([0u8; 16]);
        let c = build_snapshot_chunk(&state, Some(&bogus_cursor), None, 100)
            .expect("stale cursor must not error");
        assert_eq!(
            c.records.len(), 4,
            "bogus cursor below all keys → forward-seek returns the full set"
        );
        assert!(c.next_cursor.is_none(), "fewer than chunk_size → no cursor");

        // Bad-hex cursor → server returns an error (caller decides to fall
        // back to delta sync or full snapshot).
        let bad_hex = "zzzznothex";
        let err = build_snapshot_chunk(&state, Some(bad_hex), None, 100);
        assert!(err.is_err(), "bad-hex cursor must surface a parse error");
    }

    #[tokio::test]
    async fn test_build_snapshot_chunk_since_ts_filter_combined_with_cursor() {
        // Resume-from-checkpoint with a since_ts filter active. The client
        // already has records ≤ since_ts; the server must serve only the
        // tail past `since_ts` AND past the cursor. Both bounds compose —
        // since_ts is the floor, cursor is the watermark within that floor.
        let state = test_state_for_bootstrap();
        let base_ts = 1_730_400_000.0;
        for i in 0..6u32 {
            let id = format!("snap-since-{i:02}");
            let rec = ops123_test_record(base_ts + i as f64 * 60.0, &id);
            state.rocks.put_record(&id, &rec).expect("put_record");
        }

        // since_ts: middle of the set (skip first 2 records).
        let since = base_ts + 120.0; // ≥ this timestamp → records 2..6
        let c1 = build_snapshot_chunk(&state, None, Some(since), 2).expect("c1");
        assert_eq!(c1.records.len(), 2, "first 2 of the 4 post-since records");
        let cursor1 = c1.next_cursor.clone().expect("2 more remain");

        // Resume: still apply since_ts, advance past cursor. Should return
        // the last 2 records (records 4..6 by index, ≥ since + already past
        // boundary).
        let c2 = build_snapshot_chunk(&state, Some(&cursor1), Some(since), 100)
            .expect("c2");
        assert_eq!(c2.records.len(), 2, "remaining 2 records past cursor");
        assert!(c2.next_cursor.is_none(), "drained tail");

        // No overlap: combined filters must not double-serve.
        for hex in &c1.records {
            assert!(
                !c2.records.contains(hex),
                "combined since_ts + cursor must not double-serve the boundary"
            );
        }

        // Total: only records ≥ since are reachable; the 2 below since stay
        // out of both chunks. Pins the floor invariant.
        let total = c1.records.len() + c2.records.len();
        assert_eq!(total, 4, "only the 4 records with ts ≥ since_ts get served");
    }

    // ── fixture-free pure-helper pins ─────────────────
    //
    // Five orthogonal axes targeting BloomFilter math + wire format that
    // the existing suite tests behaviorally (insert/contains/roundtrip)
    // but not at the formula level. A bug in optimal_num_bits / clamp /
    // overflow handling would manifest as a degraded false-positive rate
    // but not trip any current test — these close that gap.

    #[test]
    fn batch_b_optimal_num_bits_pins_formula_and_64_bit_lower_floor() {
        // m = -n * ln(p) / ln²(2), ceil, then .max(64).
        // Pin known cases derived from the closed-form formula so a
        // future refactor that drops the .ceil() or .max(64) trips.

        // Case 1: large enough that the floor is NOT engaged.
        // n=100, p=0.01 → m ≈ 958.51 → ceil = 959, floor inactive.
        let m_100_001 = optimal_num_bits(100, 0.01);
        assert_eq!(m_100_001, 959, "n=100, p=0.01 must give 959 (floor inactive)");

        // Case 2: tiny n forces the floor.
        // n=10, p=0.5 → m ≈ 14.43 → ceil = 15 → floored to 64.
        let m_10_5 = optimal_num_bits(10, 0.5);
        assert_eq!(m_10_5, 64, "small-n result must be floored to 64");

        // Case 3: even tinier — n=1, p=0.99 → m ≈ 0.021 → ceil = 1 → 64.
        let m_1_99 = optimal_num_bits(1, 0.99);
        assert_eq!(m_1_99, 64, "near-degenerate input must still floor at 64");

        // Case 4: large n keeps the formula dominant.
        // n=10_000, p=0.001 → m ≈ 143_775.88 → ceil = 143_776.
        let m_big = optimal_num_bits(10_000, 0.001);
        assert_eq!(m_big, 143_776, "large n must follow the formula, not the floor");

        // Monotonicity: lower fp_rate → more bits.
        let m_p01 = optimal_num_bits(1000, 0.01);
        let m_p001 = optimal_num_bits(1000, 0.001);
        assert!(m_p001 > m_p01, "lower fp_rate must demand strictly more bits");
    }

    #[test]
    fn batch_b_optimal_num_hashes_clamps_one_through_thirty_two_at_both_ends() {
        // k = (m/n) * ln(2), ceil, clamp(1, 32).
        // Floor (1) and ceiling (32) are load-bearing — without the
        // clamp, degenerate sizings would either zero out the filter
        // (all `insert` calls become no-ops) or burn 1000+ hash ops
        // per insert at 1M items.

        // Mid-range: m=959, n=100 → k = 9.59 × 0.6931 ≈ 6.647 → 7.
        let k_mid = optimal_num_hashes(959, 100);
        assert_eq!(k_mid, 7, "m=959,n=100 must produce 7 hashes");

        // Floor: m << n forces k toward 0 → clamped up to 1.
        // m=64, n=10_000 → k ≈ 0.00443 → ceil 1 → clamp 1.
        let k_lo = optimal_num_hashes(64, 10_000);
        assert_eq!(k_lo, 1, "tiny m vs huge n must clamp up to 1 (not 0)");

        // Ceiling: m >> n forces k toward many → clamped down to 32.
        // m=10_000_000, n=10 → k ≈ 693_147 → clamp 32.
        let k_hi = optimal_num_hashes(10_000_000, 10);
        assert_eq!(k_hi, 32, "huge m vs tiny n must clamp down to 32");

        // Boundary just above 32: m=200, n=4 → k = 50 × 0.6931 ≈ 34.66
        // → ceil 35 → clamp 32. Pins the strict-upper boundary.
        let k_boundary = optimal_num_hashes(200, 4);
        assert_eq!(k_boundary, 32, "ceil above 32 must clamp to exactly 32");
    }

    #[test]
    fn batch_b_double_hash_deterministic_and_h2_nonzero_max_one_invariant() {
        // double_hash returns (h1, h2.max(1)) — h2 MUST be ≥ 1 so that
        // combined_hash i × h2 advances the index per iteration. h2 = 0
        // would collapse all k hash functions to the same bucket, which
        // ruins the false-positive rate. Pin this invariant.

        // Determinism: same bytes → same (h1, h2).
        let item = b"elara-test-vector";
        let r1 = double_hash(item);
        let r2 = double_hash(item);
        assert_eq!(r1, r2, "double_hash must be deterministic");

        // h2 ≥ 1 always (max(1) contract). The all-zero-bytes-8..16
        // case is astronomically improbable for SHA3 on real input,
        // but we can still pin that the function's return type
        // satisfies the invariant for the empty input and a single
        // byte input.
        let (_h1_empty, h2_empty) = double_hash(&[]);
        assert!(h2_empty >= 1, "h2 must be ≥ 1 even on empty input");
        let (_h1_one, h2_one) = double_hash(&[0u8]);
        assert!(h2_one >= 1, "h2 must be ≥ 1 on single-zero-byte input");

        // Different inputs → almost certainly different hashes
        // (SHA3-256 collision resistance). At the (h1, h2) pair level
        // the probability of accidental match is 2^-128 — safe to
        // assert.
        let r_a = double_hash(b"alpha");
        let r_b = double_hash(b"beta");
        assert_ne!(r_a, r_b, "distinct inputs must produce distinct hash pairs");

        // h1 and h2 are extracted from non-overlapping SHA3 byte ranges
        // [0..8] and [8..16], so they are effectively independent. We
        // can't pin specific u64 values without hard-coding test
        // vectors, but we can pin that for "elara" specifically the
        // pair is non-equal (an extreme corner case where bytes 0..8 ==
        // bytes 8..16 is also 2^-64 improbable).
        let (h1_elara, h2_elara) = double_hash(b"elara");
        assert_ne!(h1_elara, h2_elara, "h1 == h2 for typical input would be a 2^-64 fluke");
    }

    #[test]
    fn batch_b_double_hash_matches_raw_sha3_bytes() {
        // Regression guard for the copy_from_slice rewrite: h1/h2 must equal
        // u64::from_be_bytes of the first/second 8 bytes of sha3_256 directly.
        use crate::crypto::hash::sha3_256;
        let inputs: &[&[u8]] = &[b"elara", b"", b"\x00", b"Byzantine peer"];
        for input in inputs {
            let hash: [u8; 32] = sha3_256(input);
            let expected_h1 = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            let expected_h2 = u64::from_be_bytes([
                hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
            ]).max(1);
            let (h1, h2) = double_hash(input);
            assert_eq!(h1, expected_h1, "h1 mismatch for {input:?}");
            assert_eq!(h2, expected_h2, "h2 mismatch for {input:?}");
        }
    }

    #[test]
    fn batch_b_combined_hash_u128_intermediate_avoids_u64_overflow_and_bounds_result() {
        // combined_hash uses u128 for `h1 + i * h2` to avoid u64
        // overflow at maximum-stretch inputs. Without u128 the
        // multiplication u64::MAX × u32::MAX would wrap and yield
        // non-uniform bucket selection.

        // Adversarial: every input at max. u128 absorbs the product.
        let result_max = combined_hash(u64::MAX, u64::MAX, u32::MAX, 1_000);
        assert!(result_max < 1_000, "result must be bounded by num_bits");

        // i = 0 → result = h1 % num_bits (the i*h2 term contributes 0).
        let r0 = combined_hash(0xDEAD_BEEF_CAFE_BABE, 999, 0, 100);
        assert_eq!(r0, (0xDEAD_BEEF_CAFE_BABE_u64 as u128 % 100) as usize,
            "i=0 must reduce to h1 mod num_bits");

        // i = 1 → result = (h1 + h2) % num_bits.
        let r1 = combined_hash(10, 20, 1, 7);
        assert_eq!(r1, 30 % 7, "i=1 must equal (h1+h2) mod num_bits");

        // i = 5 → result = (h1 + 5*h2) % num_bits.
        let r5 = combined_hash(0, 100, 5, 13);
        assert_eq!(r5, 500 % 13, "i=5 must equal (h1+5h2) mod num_bits");

        // Always < num_bits regardless of input.
        for i in 0u32..16 {
            let r = combined_hash(u64::MAX, u64::MAX, i, 256);
            assert!(r < 256, "result {r} must stay below num_bits=256 at i={i}");
        }
    }

    #[test]
    fn batch_b_bloom_filter_wire_format_header_byte_layout_pin_be_u32() {
        // to_bytes layout: [num_bits:u32 BE][num_hashes:u32 BE][bits...].
        // Pin the byte order + offsets so a future endianness change
        // (or accidental u16/u64 width) breaks immediately. The
        // existing roundtrip test uses opaque encode/decode and would
        // not catch a both-sides BE→LE swap.
        let mut bloom = BloomFilter::new(50, 0.01);
        bloom.insert(b"x");
        let bytes = bloom.to_bytes();
        assert!(bytes.len() >= 8, "header is at least 8 bytes (2× u32)");

        // First 4 bytes = num_bits as u32 BE.
        let header_num_bits = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        // Next 4 bytes = num_hashes as u32 BE.
        let header_num_hashes = u32::from_be_bytes(bytes[4..8].try_into().unwrap());

        // Decode side must agree with the header.
        let restored = BloomFilter::from_bytes(&bytes).expect("roundtrip ok");
        assert_eq!(restored.num_bits, header_num_bits as usize,
            "decoded num_bits must equal BE u32 at offset 0");
        assert_eq!(restored.num_hashes, header_num_hashes,
            "decoded num_hashes must equal BE u32 at offset 4");

        // Truncation past header but mid-body — must surface "too short".
        // expected_len = 8 + words*8. Strip the last word.
        // BloomFilter is not Debug, so destructure rather than unwrap_err().
        let mut truncated = bytes.clone();
        truncated.truncate(bytes.len() - 4);
        let msg = match BloomFilter::from_bytes(&truncated) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error on mid-body truncation"),
        };
        assert!(msg.contains("too short"),
            "mid-body truncation must report 'too short', got: {msg}");

        // Exactly-header is enough for from_bytes to know it expects more
        // (if num_bits > 0). Pin that the header alone isn't a valid
        // filter when num_bits > 0.
        let header_only = bytes[0..8].to_vec();
        let bytes_header_only_result = BloomFilter::from_bytes(&header_only);
        assert!(bytes_header_only_result.is_err(),
            "header-only must error when body is required");
    }
}
