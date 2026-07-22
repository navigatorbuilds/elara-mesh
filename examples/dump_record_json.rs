// Decode a canonical wire `ValidationRecord` and print it as JSON — the exact
// shape the browser verify-demo and `elara-verify <record.json>` both consume.
// This is the bridge from a node's binary wire record to a pasteable record for
// the offline verifier. Pass `--profile-b` to drop the SPHINCS+ leg for a
// smaller single-signature record (the Dilithium3 signature still verifies — it
// signs `signable_bytes()`, which excludes the SPHINCS+ fields).
//
// Run with: cargo run --example dump_record_json -- <record.wire> [--profile-b]
use std::fs;

fn main() {
    use elara_runtime::record::ValidationRecord;
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_record_json <record.wire> [--profile-b]");
    let profile_b = std::env::args().any(|a| a == "--profile-b");
    let bytes = fs::read(&path).expect("read wire file");
    let mut record = ValidationRecord::from_bytes(&bytes).expect("decode wire record");
    if profile_b {
        record.strip_sphincs();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&record).expect("serialize record to json")
    );
}
