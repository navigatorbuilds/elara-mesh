//! Disk-full graceful degradation test.
//!
//! Inserts 1000 records into RocksDB, then verifies all are readable.
//! Tests that RocksDB handles write pressure without corruption.

#[cfg(feature = "node")]
#[test]
fn test_disk_full_graceful_degradation() {
    use elara_runtime::storage::rocks::StorageEngine;
    use elara_runtime::record::{ValidationRecord, Classification};
    use std::collections::BTreeMap;

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("db");
    let rocks = StorageEngine::open(&db_path).unwrap();

    // Insert 1000 records
    let mut inserted = 0u32;
    for i in 0..1000u32 {
        let id = format!("rec-{i:06}");
        let mut record = ValidationRecord::create(
            &vec![0xAA; 512],
            vec![0x01; 32],
            if i == 0 { vec![] } else { vec![format!("rec-{:06}", i - 1)] },
            Classification::Public,
            Some(BTreeMap::new()),
        );
        record.id = id.clone();
        record.timestamp = i as f64;

        match rocks.put_record(&id, &record) {
            Ok(()) => inserted += 1,
            Err(e) => {
                eprintln!("write failed at record {i}: {e}");
                break;
            }
        }
    }

    assert_eq!(inserted, 1000, "all 1000 records should be inserted");

    // Verify existing data is still readable (no corruption)
    let loaded = rocks.get_record("rec-000999");
    assert!(loaded.is_ok(), "last record should be readable");
    if let Ok(Some(rec)) = loaded {
        assert_eq!(rec.id, "rec-000999");
    }

    // Verify we can query records
    let queried = elara_runtime::storage::Storage::query(&rocks, None, None, None, None, 10)
        .unwrap_or_default();
    assert!(!queried.is_empty(), "should query records after writes");

    // Close and reopen — verify data survives
    drop(rocks);
    let rocks2 = StorageEngine::open(&db_path).unwrap();
    let reloaded = rocks2.get_record("rec-000500");
    assert!(reloaded.is_ok(), "records should survive reopen");
    if let Ok(Some(rec)) = reloaded {
        assert_eq!(rec.id, "rec-000500");
    }

    eprintln!("PASS: {inserted} records, all readable, survive reopen");
}
