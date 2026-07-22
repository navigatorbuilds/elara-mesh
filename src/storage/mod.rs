//! Storage backends: RocksDB production engine.

//!
//! Spec references:
//!   @spec Protocol §12.2

#[cfg(all(not(target_arch = "wasm32"), feature = "node-core"))]
pub mod rocks;

use crate::errors::Result;
use crate::record::{Classification, ValidationRecord};

/// Full-text search query parameters (Protocol §11.23).
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// Free-text query (FTS5 match expression).
    pub text: Option<String>,
    /// Filter by creator identity hash.
    pub creator_hash: Option<String>,
    /// Filter by metadata key existence.
    pub metadata_key: Option<String>,
    /// Filter by metadata key=value pair.
    pub metadata_value: Option<String>,
    /// Only records after this timestamp.
    pub since: Option<f64>,
    /// Only records before this timestamp.
    pub until: Option<f64>,
    /// Filter by classification.
    pub classification: Option<Classification>,
    /// Max results to return.
    pub limit: usize,
    /// Offset for pagination.
    pub offset: usize,
}

/// Storage trait — abstract backend for record persistence.
pub trait Storage {
    /// Insert a record into storage.
    fn insert(&mut self, record: &ValidationRecord) -> Result<String>;

    /// Retrieve a record by UUID.
    fn get(&self, record_id: &str) -> Result<ValidationRecord>;

    /// Retrieve a record by its SHA3-256 hash (hex).
    fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord>;

    /// Check if a record exists.
    fn exists(&self, record_id: &str) -> Result<bool>;

    /// KR-3 S2: the durable predecessor rotation-newkey index —
    /// `new_key_hash → (lineage_id, hop_index)` — or `None` when no finalized
    /// hop ever introduced `key_hash` (it is a lineage root `pk₀`). This is
    /// `derive_lineage_position`'s `introducing_hop` lookup, exposed on the
    /// trait so the seal-membership filters (`create_epoch_seal_with_balance` /
    /// `scan_window_record_hashes`), which hold only a `&dyn Storage`, can route
    /// a rotation hop under its lineage zone.
    ///
    /// The default returns `None`: a backend with no rotation index resolves
    /// every hop as a lineage root, which is exactly correct for the mock/test
    /// backends that never admit rotation chains. `StorageEngine` overrides it
    /// with the `CF_METADATA`-backed point read.
    fn get_rotation_newkey_index(&self, _key_hash: &str) -> Option<(String, u32)> {
        None
    }

    /// Return tip record IDs (no children).
    fn tips(&self) -> Result<Vec<String>>;

    /// Return root record IDs (no parents).
    fn roots(&self) -> Result<Vec<String>>;

    /// Return parent IDs of a record.
    fn parents(&self, record_id: &str) -> Result<Vec<String>>;

    /// Return child IDs of a record.
    fn children(&self, record_id: &str) -> Result<Vec<String>>;

    /// Total record count.
    fn count(&self) -> Result<usize>;

    /// Query with optional filters.
    fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>>;

    /// Query records belonging to a specific zone within a time window.
    ///
    /// Backends MUST override this with a zone-keyed secondary index lookup
    /// (e.g. `CF_RECORD_BY_ZONE` in `RocksEngine`) that is
    /// O(records_in_zone_in_window) independent of total fleet records —
    /// the load-bearing path for epoch sealing at 1M-zone scale where a
    /// `query()` + per-record filter would scan every zone's records in the
    /// window via the global timestamp index.
    ///
    /// `zone_count` controls `for_record_dynamic` semantics for verifiers
    /// checking historic seals against the seal's recorded zone count.
    ///
    /// Gated on `node`/`node-windows` because `ZoneId` lives in the
    /// feature-gated `network` module — wasm browser builds don't ship a
    /// Storage backend, so no method surface is lost on those targets.
    ///
    /// The default errors rather than silently falling back through
    /// `query(None, None, since, until, usize::MAX)`. The fallback hid
    /// SCALE-RULE violations from
    /// code review because `RocksEngine` always overrode it. Any new
    /// backend that omits an override now panics at the first call site
    /// instead of OOMing once the chain crosses ~10M records.
    #[cfg(feature = "node-core")]
    fn query_zone(
        &self,
        _zone: &crate::network::zone::ZoneId,
        _zone_count: u64,
        _since: Option<f64>,
        _until: Option<f64>,
        _limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        Err(crate::errors::ElaraError::Storage(
            "Storage::query_zone — backend must override with a zone-keyed secondary index (SCALE RULE, OPS-195)".into(),
        ))
    }

    /// Streaming variant of `query_zone` — returns record IDs only.
    ///
    /// Backends MUST override this with a zone-keyed secondary index that
    /// touches index keys only and never deserializes a full
    /// `ValidationRecord` body. Callers that only need IDs (or want to
    /// fetch records one at a time to keep peak memory bounded) use this
    /// on the seal/verify hot paths where materializing every record into
    /// a Vec is the OOM risk.
    ///
    /// Returned IDs MUST be in chronological (timestamp-ascending) order
    /// — same ordering as `query_zone`'s overrides.
    ///
    /// The default errors rather than falling back through `query()`;
    /// see `query_zone` for rationale.
    #[cfg(feature = "node-core")]
    fn query_zone_ids(
        &self,
        _zone: &crate::network::zone::ZoneId,
        _zone_count: u64,
        _since: Option<f64>,
        _until: Option<f64>,
        _limit: usize,
    ) -> Result<Vec<String>> {
        Err(crate::errors::ElaraError::Storage(
            "Storage::query_zone_ids — backend must override with a zone-keyed secondary index (SCALE RULE, OPS-195)".into(),
        ))
    }

    /// Delete a record by UUID. Also removes associated edges.
    fn delete(&mut self, record_id: &str) -> Result<()>;

    /// Retrieve raw wire bytes for a record (no deserialization round-trip).
    /// Used for attestation signature verification where byte-identity matters.
    fn get_wire_bytes(&self, record_id: &str) -> Result<Vec<u8>>;

    /// Full-text search over record metadata (Protocol §11.23).
    /// Default implementation returns empty — backends opt-in to FTS support.
    fn search(&self, _query: &SearchQuery) -> Result<Vec<ValidationRecord>> {
        Ok(vec![])
    }

    /// Layer B (Protocol §11.23) — creator-keyed lookup, O(records_for_creator).
    ///
    /// `creator_hash_hex` is `sha3_256_hex(creator_public_key)` (the same hash
    /// surfaced as `creator_hash` in `/records/search` responses). Backends
    /// with a creator-keyed secondary index override this for an
    /// O(records_for_creator_in_window) scan instead of the O(all_records)
    /// fallback through `query()`.
    fn query_by_creator_hash(
        &self,
        _creator_hash_hex: &str,
        _since: Option<f64>,
        _until: Option<f64>,
        _limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        Ok(vec![])
    }

    /// Mark a record as tombstoned (content safety §11.25).
    /// Tombstoned records are stored for audit but not gossiped or returned by API.
    fn mark_tombstoned(&mut self, _target_id: &str, _tombstone_id: &str, _reason: &str) -> Result<()> {
        Ok(())
    }

    /// Check if a record has been tombstoned.
    fn is_tombstoned(&self, _record_id: &str) -> Result<bool> {
        Ok(false)
    }

    /// List all tombstoned record IDs.
    fn tombstoned_records(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[cfg(test)]
#[cfg(feature = "node-core")]
mod tests {
    use super::*;
    use crate::errors::ElaraError;
    use crate::record::Classification;

    /// In-memory mock that implements the required methods plus explicit
    /// `query_zone`/`query_zone_ids` overrides that mirror the historic
    /// trait-default fallback (legacy hash-modulo zone mapping, filter +
    /// limit). The overrides exist because the previous fallback bodies
    /// were replaced with an error return to make new backends that forget
    /// the scale-safe override fail at
    /// runtime instead of OOMing at 10M+ records. Keeping the legacy
    /// behaviour wired up locally here lets the test below pin the
    /// filter/limit/ID-projection contract that production overrides must
    /// honour.
    ///
    /// The default impls of `search`, `query_by_creator_hash`, and the
    /// tombstone helpers are intentionally NOT overridden so the trait
    /// defaults are exercised end-to-end by `trait_defaults_for_unoverridden_methods_are_inert`.
    struct MockStorage {
        records: Vec<ValidationRecord>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self { records: Vec::new() }
        }

        fn push(&mut self, mut r: ValidationRecord, ts: f64) -> String {
            r.timestamp = ts;
            let id = r.id.clone();
            self.records.push(r);
            id
        }
    }

    impl Storage for MockStorage {
        fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
            self.records.push(record.clone());
            Ok(record.id.clone())
        }
        fn get(&self, record_id: &str) -> Result<ValidationRecord> {
            self.records
                .iter()
                .find(|r| r.id == record_id)
                .cloned()
                .ok_or_else(|| ElaraError::RecordNotFound(record_id.to_string()))
        }
        fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord> {
            Err(ElaraError::RecordNotFound(hash.to_string()))
        }
        fn exists(&self, record_id: &str) -> Result<bool> {
            Ok(self.records.iter().any(|r| r.id == record_id))
        }
        fn tips(&self) -> Result<Vec<String>> {
            Ok(vec![])
        }
        fn roots(&self) -> Result<Vec<String>> {
            Ok(vec![])
        }
        fn parents(&self, _record_id: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }
        fn children(&self, _record_id: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }
        fn count(&self) -> Result<usize> {
            Ok(self.records.len())
        }
        fn query(
            &self,
            classification: Option<Classification>,
            _creator_key: Option<&[u8]>,
            since: Option<f64>,
            until: Option<f64>,
            limit: usize,
        ) -> Result<Vec<ValidationRecord>> {
            let mut out: Vec<ValidationRecord> = self
                .records
                .iter()
                .filter(|r| classification.is_none_or(|c| r.classification == c))
                .filter(|r| since.is_none_or(|s| r.timestamp >= s))
                .filter(|r| until.is_none_or(|u| r.timestamp <= u))
                .cloned()
                .collect();
            out.sort_by(|a, b| {
                a.timestamp.total_cmp(&b.timestamp)
            });
            out.truncate(limit);
            Ok(out)
        }
        fn delete(&mut self, record_id: &str) -> Result<()> {
            self.records.retain(|r| r.id != record_id);
            Ok(())
        }
        fn get_wire_bytes(&self, _record_id: &str) -> Result<Vec<u8>> {
            Ok(vec![])
        }
        fn query_zone(
            &self,
            zone: &crate::network::zone::ZoneId,
            zone_count: u64,
            since: Option<f64>,
            until: Option<f64>,
            limit: usize,
        ) -> Result<Vec<ValidationRecord>> {
            let records = self.query(None, None, since, until, usize::MAX)?;
            let mut out = Vec::new();
            for rec in records {
                if crate::network::zone::ZoneId::for_record_dynamic(&rec.id, zone_count) != *zone {
                    continue;
                }
                out.push(rec);
                if out.len() >= limit {
                    break;
                }
            }
            Ok(out)
        }
        fn query_zone_ids(
            &self,
            zone: &crate::network::zone::ZoneId,
            zone_count: u64,
            since: Option<f64>,
            until: Option<f64>,
            limit: usize,
        ) -> Result<Vec<String>> {
            let records = self.query(None, None, since, until, usize::MAX)?;
            let mut out = Vec::new();
            for rec in records {
                if crate::network::zone::ZoneId::for_record_dynamic(&rec.id, zone_count) != *zone {
                    continue;
                }
                out.push(rec.id);
                if out.len() >= limit {
                    break;
                }
            }
            Ok(out)
        }
    }

    fn make_rec() -> ValidationRecord {
        ValidationRecord::create(
            b"content",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            None,
        )
    }

    #[test]
    fn search_query_default_has_no_filters() {
        let q = SearchQuery::default();
        assert!(q.text.is_none());
        assert!(q.creator_hash.is_none());
        assert!(q.metadata_key.is_none());
        assert!(q.metadata_value.is_none());
        assert!(q.since.is_none());
        assert!(q.until.is_none());
        assert!(q.classification.is_none());
        assert_eq!(q.limit, 0);
        assert_eq!(q.offset, 0);
    }

    #[test]
    fn trait_defaults_for_unoverridden_methods_are_inert() {
        let mut s = MockStorage::new();
        // Seed one record so we can prove the defaults ignore stored state.
        let r = make_rec();
        s.push(r, 1000.0);

        // search: default returns empty regardless of records or query.
        let q = SearchQuery::default();
        assert!(s.search(&q).unwrap().is_empty());

        // query_by_creator_hash: default returns empty until a backend overrides.
        assert!(s
            .query_by_creator_hash("any_hash", None, None, 100)
            .unwrap()
            .is_empty());

        // tombstone helpers: default mark is a no-op, nothing reads back as tombstoned.
        s.mark_tombstoned("rid", "tomb_id", "test").unwrap();
        assert!(!s.is_tombstoned("rid").unwrap());
        assert!(s.tombstoned_records().unwrap().is_empty());
    }

    #[test]
    fn mock_query_zone_override_filters_by_zone_window_and_limit() {
        use crate::network::zone::ZoneId;
        let mut s = MockStorage::new();
        let zone_target = ZoneId::from_legacy(0);
        let mut zone_a_ids: Vec<String> = Vec::new();
        let mut zone_a_count = 0usize;
        let mut zone_b_count = 0usize;

        // 30 records with monotonically increasing timestamps so since/until is observable.
        for i in 0..30 {
            let r = make_rec();
            let id = r.id.clone();
            s.push(r, 1000.0 + i as f64);
            if ZoneId::for_record_dynamic(&id, 2) == zone_target {
                zone_a_ids.push(id);
                zone_a_count += 1;
            } else {
                zone_b_count += 1;
            }
        }
        assert_eq!(zone_a_count + zone_b_count, 30);

        // Whole-window query for zone target returns exactly the zone-A records.
        let out = s.query_zone(&zone_target, 2, None, None, usize::MAX).unwrap();
        assert_eq!(out.len(), zone_a_count);
        for r in &out {
            assert_eq!(ZoneId::for_record_dynamic(&r.id, 2), zone_target);
        }

        // since-filter: drop records below ts=1015. No zone leakage from the other zone.
        let recent = s
            .query_zone(&zone_target, 2, Some(1015.0), None, usize::MAX)
            .unwrap();
        for r in &recent {
            assert!(r.timestamp >= 1015.0);
            assert_eq!(ZoneId::for_record_dynamic(&r.id, 2), zone_target);
        }

        // limit honored — cannot return more than `limit` records.
        let cap = (zone_a_count.saturating_sub(1)).max(1);
        let capped = s.query_zone(&zone_target, 2, None, None, cap).unwrap();
        assert!(capped.len() <= cap);

        // query_zone_ids returns the same set in chronological order, IDs only.
        let ids = s
            .query_zone_ids(&zone_target, 2, None, None, usize::MAX)
            .unwrap();
        assert_eq!(ids, zone_a_ids);
    }

    /// Any backend that omits `query_zone` must fail at the first
    /// call site rather than silently fall back to `query()` + per-record
    /// filter (the previous default, which masked SCALE-RULE violations).
    /// We verify the trait-level `unimplemented!` body by routing the call
    /// through an unoverridden minimal impl — distinct from `MockStorage`,
    /// which intentionally overrides both methods.
    #[test]
    fn query_zone_default_returns_storage_error_to_force_scale_safe_override() {
        use crate::network::zone::ZoneId;
        struct NoOverrideStorage;
        impl Storage for NoOverrideStorage {
            fn insert(&mut self, _r: &ValidationRecord) -> Result<String> { Ok(String::new()) }
            fn get(&self, id: &str) -> Result<ValidationRecord> {
                Err(ElaraError::RecordNotFound(id.into()))
            }
            fn get_by_hash(&self, h: &str) -> Result<ValidationRecord> {
                Err(ElaraError::RecordNotFound(h.into()))
            }
            fn exists(&self, _id: &str) -> Result<bool> { Ok(false) }
            fn tips(&self) -> Result<Vec<String>> { Ok(vec![]) }
            fn roots(&self) -> Result<Vec<String>> { Ok(vec![]) }
            fn parents(&self, _id: &str) -> Result<Vec<String>> { Ok(vec![]) }
            fn children(&self, _id: &str) -> Result<Vec<String>> { Ok(vec![]) }
            fn count(&self) -> Result<usize> { Ok(0) }
            fn query(
                &self,
                _c: Option<Classification>,
                _k: Option<&[u8]>,
                _s: Option<f64>,
                _u: Option<f64>,
                _l: usize,
            ) -> Result<Vec<ValidationRecord>> { Ok(vec![]) }
            fn delete(&mut self, _id: &str) -> Result<()> { Ok(()) }
            fn get_wire_bytes(&self, _id: &str) -> Result<Vec<u8>> { Ok(vec![]) }
        }
        let s = NoOverrideStorage;
        let zone = ZoneId::from_legacy(0);
        let err = s.query_zone(&zone, 2, None, None, 10).unwrap_err();
        assert!(matches!(err, ElaraError::Storage(_)), "expected Storage error, got {err:?}");
        assert!(err.to_string().contains("query_zone"), "error message must name the missing method");
    }

    #[test]
    fn query_zone_ids_default_returns_storage_error_to_force_scale_safe_override() {
        use crate::network::zone::ZoneId;
        struct NoOverrideStorage;
        impl Storage for NoOverrideStorage {
            fn insert(&mut self, _r: &ValidationRecord) -> Result<String> { Ok(String::new()) }
            fn get(&self, id: &str) -> Result<ValidationRecord> {
                Err(ElaraError::RecordNotFound(id.into()))
            }
            fn get_by_hash(&self, h: &str) -> Result<ValidationRecord> {
                Err(ElaraError::RecordNotFound(h.into()))
            }
            fn exists(&self, _id: &str) -> Result<bool> { Ok(false) }
            fn tips(&self) -> Result<Vec<String>> { Ok(vec![]) }
            fn roots(&self) -> Result<Vec<String>> { Ok(vec![]) }
            fn parents(&self, _id: &str) -> Result<Vec<String>> { Ok(vec![]) }
            fn children(&self, _id: &str) -> Result<Vec<String>> { Ok(vec![]) }
            fn count(&self) -> Result<usize> { Ok(0) }
            fn query(
                &self,
                _c: Option<Classification>,
                _k: Option<&[u8]>,
                _s: Option<f64>,
                _u: Option<f64>,
                _l: usize,
            ) -> Result<Vec<ValidationRecord>> { Ok(vec![]) }
            fn delete(&mut self, _id: &str) -> Result<()> { Ok(()) }
            fn get_wire_bytes(&self, _id: &str) -> Result<Vec<u8>> { Ok(vec![]) }
        }
        let s = NoOverrideStorage;
        let zone = ZoneId::from_legacy(0);
        let err = s.query_zone_ids(&zone, 2, None, None, 10).unwrap_err();
        assert!(matches!(err, ElaraError::Storage(_)), "expected Storage error, got {err:?}");
        assert!(err.to_string().contains("query_zone_ids"), "error message must name the missing method");
    }

    #[test]
    fn batch_b_search_query_clone_round_trip_preserves_all_nine_field_values_field_by_field() {
        // SearchQuery derives Clone — pin field-by-field round trip so a future edit
        // that drops a field from the derive (or replaces with a manual impl that
        // omits one) surfaces here. All 9 fields populated with distinct values.
        let q = SearchQuery {
            text: Some("hello world".into()),
            creator_hash: Some("abc123".into()),
            metadata_key: Some("zone".into()),
            metadata_value: Some("hil".into()),
            since: Some(1700000000.0),
            until: Some(1800000000.0),
            classification: Some(Classification::Public),
            limit: 250,
            offset: 1000,
        };
        let c = q.clone();
        assert_eq!(c.text.as_deref(), Some("hello world"));
        assert_eq!(c.creator_hash.as_deref(), Some("abc123"));
        assert_eq!(c.metadata_key.as_deref(), Some("zone"));
        assert_eq!(c.metadata_value.as_deref(), Some("hil"));
        assert_eq!(c.since, Some(1700000000.0));
        assert_eq!(c.until, Some(1800000000.0));
        assert_eq!(c.classification, Some(Classification::Public));
        assert_eq!(c.limit, 250);
        assert_eq!(c.offset, 1000);
        // Original still owned/intact post-clone (deep-copy semantics, not move).
        assert_eq!(q.limit, 250, "clone must not consume the source");
    }

    #[test]
    fn batch_b_search_query_debug_format_lists_all_nine_struct_field_names_for_log_grep_stability() {
        // The Debug derive expands to "SearchQuery { text: …, creator_hash: …, … }".
        // Pin all 9 field names so a rename surfaces here instead of silently
        // breaking operator log greps (e.g. `grep 'creator_hash:' search_query.log`).
        let q = SearchQuery::default();
        let dbg = format!("{q:?}");
        for field in &[
            "text", "creator_hash", "metadata_key", "metadata_value",
            "since", "until", "classification", "limit", "offset",
        ] {
            assert!(dbg.contains(field),
                "Debug output must include field name {:?}: got {:?}", field, dbg);
        }
        // The struct name itself must appear (not a fully-qualified path — Debug
        // derives just print the short name).
        assert!(dbg.starts_with("SearchQuery"),
            "Debug must lead with the struct name 'SearchQuery': got {:?}", dbg);
    }

    #[test]
    fn batch_b_storage_trait_default_search_returns_empty_regardless_of_query_filter_population() {
        // The existing `trait_defaults_for_unoverridden_methods_are_inert` test
        // covers the empty-query case. This pins the full-query case: even with
        // every filter populated, the trait DEFAULT body returns empty. A backend
        // that wants real search semantics MUST override search() — this guards
        // against a future edit replacing the default with a non-empty fallback.
        let mut s = MockStorage::new();
        let r = make_rec();
        s.push(r, 1234.0);

        // Populated query — every filter axis exercised.
        let q = SearchQuery {
            text: Some("anything".into()),
            creator_hash: Some("aabb".into()),
            metadata_key: Some("k".into()),
            metadata_value: Some("v".into()),
            since: Some(0.0),
            until: Some(99999999.0),
            classification: Some(Classification::Public),
            limit: 100,
            offset: 0,
        };
        assert!(s.search(&q).unwrap().is_empty(),
            "trait default search() must return empty even with populated query filters");
        // High-limit query: still empty (no clamp leakage past empty).
        let q_big = SearchQuery { limit: usize::MAX, ..Default::default() };
        assert!(s.search(&q_big).unwrap().is_empty(),
            "trait default search() must return empty even with usize::MAX limit");
    }

    #[test]
    fn batch_b_storage_trait_default_query_by_creator_hash_returns_empty_for_any_hash_window_or_limit() {
        let mut s = MockStorage::new();
        // Seed multiple records — prove default ignores stored state entirely.
        s.push(make_rec(), 100.0);
        s.push(make_rec(), 200.0);
        s.push(make_rec(), 300.0);

        // Empty hash.
        assert!(s.query_by_creator_hash("", None, None, 10).unwrap().is_empty(),
            "default query_by_creator_hash with empty hash must return empty");
        // Realistic hex.
        assert!(s.query_by_creator_hash(
            "deadbeef0123456789abcdef", Some(0.0), Some(99999.0), 10000
        ).unwrap().is_empty(),
            "default query_by_creator_hash with full window + high limit must return empty");
        // limit=0 edge case.
        assert!(s.query_by_creator_hash("any", None, None, 0).unwrap().is_empty(),
            "default query_by_creator_hash with limit=0 must still return Ok(empty), not panic");
    }

    #[test]
    fn batch_b_storage_trait_default_tombstone_pipeline_is_strictly_inert_with_arbitrary_string_inputs() {
        // The default impls of mark_tombstoned / is_tombstoned / tombstoned_records
        // are no-ops by design — backends MUST override to provide tombstoning.
        // Pin the no-op contract against multiple input shapes so a future edit
        // that lazily writes to in-memory state on mark_tombstoned() (and lets
        // is_tombstoned() read it back) regresses here.
        let mut s = MockStorage::new();

        // 1. Empty-string args (common defensive call from caller code).
        s.mark_tombstoned("", "", "").unwrap();
        assert!(!s.is_tombstoned("").unwrap(),
            "is_tombstoned must return false even for the same empty string just marked");

        // 2. Long-string args (UUIDs + reasons can be 100+ chars in production).
        let long_id = "a".repeat(256);
        let long_reason = "reason: ".to_string() + &"x".repeat(500);
        s.mark_tombstoned(&long_id, "tomb_xyz", &long_reason).unwrap();
        assert!(!s.is_tombstoned(&long_id).unwrap(),
            "is_tombstoned must still be false after long-string mark");

        // 3. Unicode + symbols (records can carry non-ASCII reasons).
        s.mark_tombstoned("rid-Ω", "tomb-✓", "reason: 漢字 + emoji 🛑").unwrap();
        assert!(!s.is_tombstoned("rid-Ω").unwrap(),
            "is_tombstoned must remain false for unicode rid post-mark");

        // 4. tombstoned_records: always empty regardless of all the marks above.
        assert!(s.tombstoned_records().unwrap().is_empty(),
            "tombstoned_records default must return empty Vec even after multiple mark_tombstoned calls");
    }
}
