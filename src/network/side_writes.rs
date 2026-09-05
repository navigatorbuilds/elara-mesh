//! Shared side-row builder for every path that stores a record — live ingest
//! Phase 2 (`network::ingest`), the genesis bootstrap pull
//! (`network::gossip::bootstrap_store_record`) and the one-time boot backfill
//! (`backfill_side_rows`, driven by `bin/elara_node`) — plus the delete path
//! (`storage::rocks::delete_record`), which re-derives the SAME keys to remove
//! them.
//!
//! F2 residual R2 (2026-09-02,
//! internal design notes): before
//! this module the writers carried hand-copied derivations and the bootstrap
//! writer had none, so a bootstrap-pulled seal owned no DISC-5 / equivocation
//! witness row (invisible to `seal_record_ids_at_zone_epoch`, the durable-tip
//! heal and the witness walk) and a bootstrap-pulled slash record no offense
//! marker (no restart-proof dedup). One builder ⇒ byte-identical rows on every
//! path, by construction, and one parser (`extract_epoch_seal`) deciding both
//! the write and the delete key — including the `ZoneId` normalisation of
//! `epoch_zone`.
//!
//! SCALE: this runs on every ingest and every delete. A non-seal, non-slash
//! record costs two metadata lookups — no hash, no parse.

use crate::record::ValidationRecord;
use crate::storage::rocks::{RecordSideWrites, StorageEngine};

/// The side rows one stored record owns, plus the seal coordinates the
/// live-ingest witness walk seeks after the put.
#[derive(Debug, Clone, Default)]
pub struct SideWriteSet {
    /// Rows that ride the record's own WriteBatch (`put_record_with_pk_zone`).
    pub side_writes: RecordSideWrites,
    /// `(epoch_number, zone_path)` of a seal record — the prefix of its witness
    /// row (`eqv:{epoch}:{zone}:{creator}:`). `None` for every non-seal record.
    pub seal_witness_coords: Option<(u64, String)>,
}

/// Derive every side row for `record`:
///   * seal record → the DISC-5 CF_EPOCHS existence key and the creator-keyed
///     equivocation witness row (value = the seal's `record_hash`);
///   * slash record carrying a canonical `beat_offense` digest → the durable
///     offense marker key.
///
/// Deterministic and metadata-only. A stored row exists iff this function
/// returns it, so `delete_record` derives the identical key. `epoch_zone` is
/// normalised through `extract_epoch_seal` (`ZoneId::new` for strings,
/// `ZoneId::from_legacy` for integers): "Medical/EU", "medical/eu/" and a
/// legacy `42` all land on one key. A record that claims `epoch_op == "seal"`
/// but fails the seal parser owns NO rows (ingest Phase 1 rejects it; the
/// bootstrap writer stores it row-less — residual R9 covers that channel).
pub fn record_side_writes(record: &ValidationRecord) -> SideWriteSet {
    let (disc5_epoch_key, equivocation_key, seal_witness_coords) =
        match super::epoch::extract_epoch_seal(record) {
            Ok(Some(seal)) => {
                let zone_path = seal.zone.path().to_string();
                let creator = crate::accounting::types::creator_identity_hash(record);
                (
                    Some(super::epoch::disc5_index_key(
                        seal.epoch_number,
                        &zone_path,
                        &record.id,
                    )),
                    Some((
                        StorageEngine::equivocation_index_key(
                            seal.epoch_number,
                            &zone_path,
                            &creator,
                            &record.id,
                        ),
                        record.record_hash(),
                    )),
                    Some((seal.epoch_number, zone_path)),
                )
            }
            _ => (None, None, None),
        };
    SideWriteSet {
        side_writes: RecordSideWrites {
            disc5_epoch_key,
            equivocation_key,
            slash_offense_key: super::slashing::slash_offense_side_key(record),
        },
        seal_witness_coords,
    }
}

/// Outcome of [`backfill_side_rows`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackfillOutcome {
    /// Seal records whose DISC-5 row was (re)written.
    pub disc5_rows: usize,
    /// Slash records whose durable offense marker was (re)written.
    pub offense_markers: usize,
    /// Records whose row batch failed to write (the caller logs; the next boot
    /// that still finds CF_EPOCHS empty retries).
    pub failed: usize,
}

/// One-time boot backfill body. `bin/elara_node.rs` owns the trigger
/// (`approximate_cf_size(CF_EPOCHS) == 0 && record_count > 0`) and the spawn;
/// this walks CF_RECORDS once and gives every already-stored seal its DISC-5
/// row and every stored slash record its offense marker — the rows an upgraded
/// node missed because its records predate incremental side-writes (or, before
/// R2, were bootstrap-pulled).
///
/// The equivocation witness row is deliberately NOT backfilled: a retroactive
/// `eqv:` row for a historical seal would arm the live witness walk against
/// seals the live path never adjudicated (pre-ceremony chains, foreign-ceremony
/// twins — a false self-slash class). That is the bounded, dated reconciliation
/// sweep of residuals R2b/R11, never a boot side effect.
///
/// Cost: one sequential CF_RECORDS scan; one idempotent WriteBatch per
/// row-bearing record; two metadata lookups per ordinary record. Races the
/// bootstrap pull benignly — both write the same fixed-value keys.
pub fn backfill_side_rows(engine: &StorageEngine) -> BackfillOutcome {
    let mut out = BackfillOutcome::default();
    let _ = engine.for_each_record(|rec| {
        let mut side = record_side_writes(rec).side_writes;
        side.equivocation_key = None;
        if side.is_empty() {
            return;
        }
        let disc5 = side.disc5_epoch_key.is_some();
        let marker = side.slash_offense_key.is_some();
        match engine.write_record_side_writes(&rec.id, &side) {
            Ok(()) => {
                if disc5 {
                    out.disc5_rows += 1;
                }
                if marker {
                    out.offense_markers += 1;
                }
            }
            Err(_) => out.failed += 1,
        }
    });
    out
}

/// Realistic record fixtures shared by the R2 tests in this module,
/// `network::gossip` and `storage::rocks`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::crypto::hash::sha3_256;
    use crate::record::Classification;
    use crate::ZoneId;

    /// A well-formed seal record (every field `extract_epoch_seal` requires)
    /// whose `epoch_zone` metadata carries `zone_literal` VERBATIM — pass
    /// "Medical/EU" to model a non-canonical producer; the builder normalises
    /// it through `ZoneId::new` exactly as ingest does. `salt` varies the
    /// content so two seals at one (zone, epoch) get different record hashes.
    pub(crate) fn seal_record(
        creator_public_key: Vec<u8>,
        zone_literal: &str,
        epoch: u64,
        salt: &[u8],
    ) -> ValidationRecord {
        let zone = ZoneId::new(zone_literal);
        let mut meta = super::super::epoch::seal_metadata(super::super::epoch::SealMetadataParams {
            zone: zone.clone(),
            epoch_number: epoch,
            start: 1_700_000_000.0 + epoch as f64,
            end: 1_700_000_000.0 + epoch as f64 + 60.0,
            record_count: 0,
            merkle_root: &sha3_256(b"merkle"),
            previous_seal_hash: &sha3_256(b"prev"),
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });
        meta.insert("epoch_zone".into(), serde_json::json!(zone_literal));
        let mut content = format!("seal-{zone_literal}-e{epoch}-").into_bytes();
        content.extend_from_slice(salt);
        let mut record = ValidationRecord::create(
            &content,
            creator_public_key,
            vec![],
            Classification::Public,
            Some(meta),
        );
        record.zone = Some(zone);
        record
    }

    /// A slash record carrying `beat_offense = digest` (what
    /// `slashing::create_slash_record` emits, minus the signature).
    pub(crate) fn slash_record(creator_public_key: Vec<u8>, digest: &str) -> ValidationRecord {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(
            crate::accounting::types::BEAT_OP_KEY.to_string(),
            serde_json::json!("slash"),
        );
        meta.insert(
            super::super::slashing::BEAT_OFFENSE_KEY.to_string(),
            serde_json::json!(digest),
        );
        ValidationRecord::create(
            b"slash",
            creator_public_key,
            vec![],
            Classification::Public,
            Some(meta),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{seal_record, slash_record};
    use super::*;
    use crate::crypto::hash::sha3_256_hex;
    use crate::storage::rocks::{CF_EPOCHS, CF_METADATA};
    use crate::storage::Storage;

    fn test_engine() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    /// T8: a seal's three coordinates agree with each other and with the key
    /// functions, and the raw `epoch_zone` literal is normalised — the exact
    /// keys ingest, bootstrap and the backfill all write.
    #[test]
    fn r2_builder_seal_rows_are_normalised_and_consistent() {
        let pk = vec![0xAA; 1952];
        let seal = seal_record(pk.clone(), "Medical/EU", 42, b"x");
        assert_eq!(
            seal.metadata.get("epoch_zone").and_then(|v| v.as_str()),
            Some("Medical/EU"),
            "fixture keeps the raw literal"
        );
        let set = record_side_writes(&seal);
        let creator = sha3_256_hex(&pk);
        assert_eq!(
            set.side_writes.disc5_epoch_key.as_deref(),
            Some(&super::super::epoch::disc5_index_key(42, "medical/eu", &seal.id)[..])
        );
        assert_eq!(
            set.side_writes.equivocation_key,
            Some((
                StorageEngine::equivocation_index_key(42, "medical/eu", &creator, &seal.id),
                seal.record_hash(),
            ))
        );
        assert_eq!(set.seal_witness_coords, Some((42, "medical/eu".to_string())));
        assert!(set.side_writes.slash_offense_key.is_none());
        assert!(!set.side_writes.is_empty());
        // Legacy integer zone → `from_legacy` normalisation, same path.
        let mut legacy = seal_record(pk, "7", 3, b"y");
        legacy.metadata.insert("epoch_zone".into(), serde_json::json!(7u64));
        let set = record_side_writes(&legacy);
        assert_eq!(
            set.seal_witness_coords,
            Some((3, crate::ZoneId::from_legacy(7).path().to_string()))
        );
    }

    #[test]
    fn r2_builder_ordinary_record_owns_no_rows() {
        let rec = ValidationRecord::create(
            b"plain",
            vec![0xAA; 1952],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        let set = record_side_writes(&rec);
        assert!(set.side_writes.is_empty());
        assert!(set.seal_witness_coords.is_none());
    }

    #[test]
    fn r2_builder_slash_record_owns_only_the_marker() {
        let digest = "ab".repeat(32);
        let slash = slash_record(vec![0xAA; 1952], &digest);
        let set = record_side_writes(&slash);
        assert_eq!(
            set.side_writes.slash_offense_key,
            Some(StorageEngine::slash_offense_key(&digest))
        );
        assert!(set.side_writes.disc5_epoch_key.is_none());
        assert!(set.side_writes.equivocation_key.is_none());
        assert!(set.seal_witness_coords.is_none());
        // Non-canonical digest → no marker (a second key for one offense).
        let upper = slash_record(vec![0xAA; 1952], &"AB".repeat(32));
        assert!(record_side_writes(&upper).side_writes.is_empty());
    }

    /// T7: the backfill gives a bare-stored seal its DISC-5 row and a
    /// bare-stored slash record its marker — and NEVER a witness row.
    /// Idempotent on re-run.
    #[test]
    fn r2_backfill_writes_disc5_and_marker_never_witness() {
        let (mut engine, _dir) = test_engine();
        let pk = vec![0xAA; 1952];
        let seal = seal_record(pk.clone(), "z/bf", 9, b"s");
        let digest = "cd".repeat(32);
        let slash = slash_record(pk.clone(), &digest);
        let plain = ValidationRecord::create(
            b"plain",
            pk.clone(),
            vec![],
            crate::record::Classification::Public,
            None,
        );
        for r in [&seal, &slash, &plain] {
            engine.insert(r).unwrap(); // bare `Storage::insert`: no rows
        }
        let disc5 = super::super::epoch::disc5_index_key(9, "z/bf", &seal.id);
        let eqv = StorageEngine::equivocation_index_key(9, "z/bf", &sha3_256_hex(&pk), &seal.id);
        assert!(engine.get_cf_raw(CF_EPOCHS, &disc5).unwrap().is_none());
        assert!(engine.slash_offense_record(&digest).is_none());

        let out = backfill_side_rows(&engine);
        assert_eq!(
            out,
            BackfillOutcome {
                disc5_rows: 1,
                offense_markers: 1,
                failed: 0
            }
        );
        assert!(engine.get_cf_raw(CF_EPOCHS, &disc5).unwrap().is_some());
        assert_eq!(engine.slash_offense_record(&digest), Some(slash.id.clone()));
        assert!(
            engine.get_cf_raw(CF_METADATA, &eqv).unwrap().is_none(),
            "backfill must never arm the witness walk retroactively (R2b/R11)"
        );
        assert_eq!(backfill_side_rows(&engine), out, "idempotent");
        assert_eq!(engine.seal_record_ids_at_zone_epoch(9, "z/bf"), vec![seal.id.clone()]);
    }
}
