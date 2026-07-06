// Generate the language-agnostic conformance test vectors from the authoritative
// code paths and write them to `examples/verify/conformance-vectors.json`.
//
// Every value is derived from the real implementation (SHA3-256, the account-SMT
// leaf/interior/empty hashing, identity derivation, and record-hash binding), so
// the file can never disagree with the code. Re-run after any change to a hashing
// recipe; the lib test
// `conformance::tests::committed_conformance_vectors_match_authoritative_derivation`
// fails until you do.
//
//   cargo run --example gen_conformance_vectors      # from the repo root
use std::fs;

fn main() {
    let wire = fs::read("examples/verify/sample-record.wire").expect(
        "run from the repo root: examples/verify/sample-record.wire not found",
    );
    let seal = fs::read("examples/verify/epoch-8219-zone-0.seal.wire").expect(
        "run from the repo root: examples/verify/epoch-8219-zone-0.seal.wire not found",
    );
    let anchor_hex = fs::read_to_string("examples/verify/zone-0-anchor-pubkey.hex")
        .expect("run from the repo root: examples/verify/zone-0-anchor-pubkey.hex not found");
    let anchor = hex::decode(anchor_hex.trim()).expect("zone-0-anchor-pubkey.hex is valid hex");
    let set = elara_runtime::conformance::generate_vector_set(&wire, &seal, &anchor)
        .expect("derive conformance vectors from the committed sample/seal/anchor inputs");
    let json = serde_json::to_string_pretty(&set).expect("serialize conformance vectors");
    let out = "examples/verify/conformance-vectors.json";
    fs::write(out, format!("{json}\n")).expect("write conformance-vectors.json");
    eprintln!("wrote {out} ({} vectors)", set.vectors.len());
}
