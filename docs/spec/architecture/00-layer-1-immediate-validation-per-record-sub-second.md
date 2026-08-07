### Layer 1: Immediate Validation (per-record, sub-second)

When a record arrives, local witnesses perform quick checks:
- Dilithium3 signature valid?
- Wire format correct?
- Balance sufficient? (for transfers)
- Not a duplicate?
- Entropy score acceptable? (anti-spam)

Record status → **Pending** (accepted into current epoch's candidate set).

This is lightweight. No HashMap accumulation. Records are written to RocksDB immediately. The hot_records LRU tracks only current-epoch pending records.

