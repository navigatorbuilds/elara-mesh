//! Empirical fail-closed fuzz sweep over the attacker-reachable wire decoders.
//!
//! The panic-hardening lane (an internal audit §1059–§1063)
//! swept the hot-path decoders for implicit panics — out-of-bounds indexing,
//! arithmetic overflow, division-by-zero, recursion-depth abort — BY INSPECTION
//! plus hand-picked adversarial unit tests (see `wire.rs` truncated-int /
//! deep-nesting / invalid-utf8 cases). This module backs that with an EMPIRICAL
//! guarantee: every decoder that turns untrusted network bytes into a typed value
//! MUST fail closed (return `Err`/`None`) on ANY input — never panic, abort, hang,
//! or OOM. A panic here is per-connection, not a node crash (the node runs
//! `panic = "unwind"` with tokio task isolation), but a fail-closed decoder is the
//! contract we publish, and a fuzz-found panic is still a DoS amplifier worth
//! eliminating before the public flip.
//!
//! Approach: a zero-dependency, deterministically-seeded (splitmix64) sweep — no
//! `proptest`/`rand` dep added to a soon-public, crate-extracted tree, and a fixed
//! seed makes this a reproducible CI regression guard, not a flaky random one. Each
//! decoder takes ~30k structured-random inputs (lengths biased toward the
//! boundaries decoders branch on), and the length-prefixed types also get a
//! valid-then-mutated layer (the "almost-valid" class pure-random rarely reaches).
//! Any panic is caught and re-raised with the exact seed + hex input, so a failure
//! is replayable. Test-only — never compiled into a shipped binary.

/// splitmix64 — tiny, fast, deterministic. Seeded so failures are reproducible.
/// Every seed is XOR-masked by `ELARA_FUZZ_SEED_OFFSET` (hex, default 0), so an
/// extended campaign explores fresh deterministic input space per offset while
/// CI (offset absent) keeps the pinned seeds bit-identical. A failure is replayed
/// from the printed input hex — the offset only matters for re-running a sweep.
struct Rng(u64);

/// Iteration budget per sweep: CI default 30k (fast regression guard); soak
/// campaigns crank it via `ELARA_FUZZ_ITERS` without touching the pinned seeds.
static ITERS: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
    std::env::var("ELARA_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(30_000)
});

static SEED_OFFSET: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    std::env::var("ELARA_FUZZ_SEED_OFFSET")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
});

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ *SEED_OFFSET)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }
}

/// Lengths decoders branch on: header/fixed-field widths and 2^k − 1 / 0 / + 1.
const BOUNDARY_LENS: &[usize] = &[
    0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
];

/// One random input: length biased toward boundary sizes, content random, with a
/// 50% chance the leading bytes are small — plausible length prefixes that drive
/// length-prefixed decoders down their happy path, not just the early reject.
fn gen_input(rng: &mut Rng) -> Vec<u8> {
    let len = if rng.next_u64() % 5 < 3 {
        BOUNDARY_LENS[rng.below(BOUNDARY_LENS.len())]
    } else {
        rng.below(257)
    };
    let mut v = vec![0u8; len];
    for b in v.iter_mut() {
        *b = (rng.next_u64() & 0xff) as u8;
    }
    if rng.next_u64() & 1 == 0 {
        for b in v.iter_mut().take(4) {
            *b = (rng.next_u64() % 40) as u8;
        }
    }
    v
}

/// One structural mutation of a (valid) buffer — bit-flip / truncate / extend /
/// clobber-prefix. Targets the "almost-valid" class pure-random rarely reaches.
/// Used by the `zone::ZoneId` layer and the verifier-leg fixture sweeps below.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    match rng.below(4) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1u8 << rng.below(8);
        }
        1 if !v.is_empty() => v.truncate(rng.below(v.len())),
        2 => {
            for _ in 0..rng.below(8) {
                v.push((rng.next_u64() & 0xff) as u8);
            }
        }
        _ => {
            for b in v.iter_mut().take(2) {
                *b = (rng.next_u64() & 0xff) as u8;
            }
        }
    }
    v
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Run `decode` over `iters` seeded inputs; any panic is caught and re-raised as a
/// reproducible failure. The invariant: the call RETURNS (it does not panic/abort).
fn sweep(name: &str, seed: u64, iters: usize, decode: impl Fn(&[u8])) {
    let mut rng = Rng::new(seed);
    for i in 0..iters {
        let input = gen_input(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(&input)));
        assert!(
            r.is_ok(),
            "decoder `{name}` PANICKED — not fail-closed. seed={seed} iter={i} len={} input=0x{}",
            input.len(),
            to_hex(&input),
        );
    }
}

// ── Core decoders (always compiled — the light/mobile client decodes these too) ──

#[test]
fn fuzz_validation_record_from_bytes_is_fail_closed() {
    sweep("ValidationRecord::from_bytes", 0xE1A2_0001, *ITERS, |b| {
        let _ = crate::record::ValidationRecord::from_bytes(b);
    });
}

#[test]
fn fuzz_decode_metadata_binary_is_fail_closed() {
    sweep("decode_metadata_binary", 0xE1A2_0002, *ITERS, |b| {
        let mut r = crate::wire::WireReader::new(b);
        let _ = crate::wire::decode_metadata_binary(&mut r);
    });
}

#[test]
fn fuzz_zone_causal_reference_from_bytes_is_fail_closed() {
    sweep("ZoneCausalReference::from_bytes", 0xE1A2_0003, *ITERS, |b| {
        let _ = crate::itc::ZoneCausalReference::from_bytes(b);
    });
}

#[test]
fn fuzz_vrf_proof_from_bytes_is_fail_closed() {
    // VRF proofs ride inside attestation / committee-selection messages — a peer
    // (or a spoofed gossip relay) supplies the bytes. `crypto` is ungated, so the
    // light/mobile verifier decodes these too.
    sweep("VrfProof::from_bytes", 0xE1A2_000A, *ITERS, |b| {
        let _ = crate::crypto::vrf::VrfProof::from_bytes(b);
    });
}

#[test]
fn fuzz_commitment_proof_from_bytes_is_fail_closed() {
    // Commitment proofs are embedded in records/seals; the outer decode hands the
    // inner commitment blob straight to this length-prefixed parser.
    sweep("CommitmentProof::from_bytes", 0xE1A2_000B, *ITERS, |b| {
        let _ = crate::crypto::commitment::CommitmentProof::from_bytes(b);
    });
}

#[test]
fn fuzz_zk_verify_record_proof_is_fail_closed() {
    // The attacker entry point for ZK-proof bytes: a peer submits a *classified*
    // record carrying `zk_bytes`, and `network::ingest` hands them straight to
    // `verify_record_proof` (ingest.rs:1379). It version-routes on the first byte —
    // 0x03 → the commitment verifier (`verify_commitment_proof`, a hand-rolled
    // length-prefix decode), 0x02 → fail-closed, else → `deserialize_proof` below —
    // then indexes `public_inputs[..8]` (→ u64) or `from_utf8`s it. `crypto` is
    // ungated, so a light/mobile record verifier decodes these too. This sweep
    // covers the whole routed decode tree as the attacker reaches it: it was the one
    // attacker-reachable hand-rolled decoder family this module had missed.
    sweep("zk::verify_record_proof", 0xE1A2_000F, *ITERS, |b| {
        let _ = crate::crypto::zk::verify_record_proof(b);
    });
}

#[test]
fn fuzz_zk_deserialize_proof_is_fail_closed() {
    // The deep path of `verify_record_proof`: `[type:u8][commitment:32]
    // [proof_data_len:u16_be][proof_data][public_inputs_len:u16_be][public_inputs]`
    // — hand-rolled offset arithmetic with two length prefixes. Swept directly (not
    // just via the version-router, which forwards a subset) so the `proof_type` tag,
    // both length-prefix bounds, and the trailing-`public_inputs` extraction are all
    // exercised at the boundary lengths `gen_input` biases toward.
    sweep("zk::deserialize_proof", 0xE1A2_0010, *ITERS, |b| {
        let _ = crate::crypto::zk::deserialize_proof(b);
    });
}

// The light/mobile build (`not(node-core)`) substitutes the pure-Rust
// `ZoneId(u64)` stub (`src/lib.rs`) for the node `zone::ZoneId(String)`; its
// `from_wire_bytes` is a DISTINCT decoder the node-gated `zone::ZoneId` sweep
// below never reaches. Cover the stub in the config where it compiles — the
// resource-constrained client is exactly where a decoder panic stings most.
#[cfg(not(feature = "node-core"))]
#[test]
fn fuzz_core_zone_id_from_wire_bytes_is_fail_closed() {
    sweep("ZoneId(u64)::from_wire_bytes", 0xE1A2_000C, *ITERS, |b| {
        let _ = crate::ZoneId::from_wire_bytes(b);
    });
}

// ── Node-only decoders (network module, gated on `node-core` → enabled by `node`) ──

#[cfg(feature = "node-core")]
#[test]
fn fuzz_bloom_filter_from_bytes_is_fail_closed() {
    sweep("BloomFilter::from_bytes", 0xE1A2_0004, *ITERS, |b| {
        let _ = crate::network::sync::BloomFilter::from_bytes(b);
    });
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_parse_disc5_index_key_is_fail_closed() {
    sweep("parse_disc5_index_key", 0xE1A2_0005, *ITERS, |b| {
        let _ = crate::network::epoch::parse_disc5_index_key(b);
    });
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_zone_id_from_wire_bytes_is_fail_closed() {
    // (a) pure/structured-random sweep
    sweep("zone::ZoneId::from_wire_bytes", 0xE1A2_0006, *ITERS, |b| {
        let _ = crate::network::zone::ZoneId::from_wire_bytes(b);
    });
    // (b) valid-then-mutated layer — hand-built valid encodings `[len:u16_be][utf8]`
    // (the wire format `ZoneId::to_wire_bytes` produces), then one mutation each.
    let mut rng = Rng::new(0xE1A2_1006);
    let valids: &[&[u8]] = &[b"0", b"42", b"1/2/3", b"zone-7", b""];
    for _ in 0..*ITERS {
        let pick = valids[rng.below(valids.len())];
        let mut buf = (pick.len() as u16).to_be_bytes().to_vec();
        buf.extend_from_slice(pick);
        let m = mutate(&mut rng, &buf);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = crate::network::zone::ZoneId::from_wire_bytes(&m);
        }));
        assert!(
            r.is_ok(),
            "zone::ZoneId::from_wire_bytes PANICKED on mutated-valid input=0x{}",
            to_hex(&m),
        );
    }
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_pq_rpc_decoders_are_fail_closed() {
    // Post-frame RPC message decoders on the PQ-transport listener path.
    use crate::network::pq_transport::rpc::{PqRequest, PqResponse, PqStreamChunk};
    sweep("PqRequest::decode", 0xE1A2_0007, *ITERS, |b| {
        let _ = PqRequest::decode(b);
    });
    sweep("PqResponse::decode", 0xE1A2_0008, *ITERS, |b| {
        let _ = PqResponse::decode(b);
    });
    sweep("PqStreamChunk::decode", 0xE1A2_0009, *ITERS, |b| {
        let _ = PqStreamChunk::decode(b);
    });
}

// ── Hand-written JSON-Value wire parsers (account-proof light-client path) ──
//
// The sweeps above all take `&[u8]`. The account-proof parsers in
// `network::account_merkle` instead take a `serde_json::Value` (the HTTP route
// runs `serde_json::from_slice` first, then hands the parsed Value here). That
// makes them a DISTINCT decoder class: serde's derive-`Visitor` paths are
// bounds-checked by codegen and need no empirical sweep, but these parsers are
// hand-rolled field extraction — hex-decode + `copy_from_slice` into `[u8; 32]`
// and a peer-sized `siblings` array. A light client decodes these from a proof
// served by a possibly-malicious node, so a panic here is remotely reachable.
// They are fail-closed by inspection today (every `copy_from_slice` is guarded
// by a `len != 32` check, and `siblings.len()` is capped at `MAX_DEPTH`), but
// none of those guards is enforced by the prod-panic scan — `copy_from_slice`
// is neither an `unwrap` nor a `panic!`. This sweep is the regression guard
// that fails if a future edit drops one of them.

/// Random lowercase-hex string of `bytes` bytes (`2 * bytes` chars).
fn rand_hex(rng: &mut Rng, bytes: usize) -> String {
    let mut s = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        s.push_str(&format!("{:02x}", (rng.next_u64() & 0xff) as u8));
    }
    s
}

/// One JSON value for a hex-string field: valid (32-byte) / wrong-length /
/// non-hex / wrong-type — the four ways a field can be malformed on the wire.
fn gen_hex_field(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    match rng.below(6) {
        0 => Value::String(rand_hex(rng, 32)), // valid: exactly 32 bytes
        1 => {
            let n = rng.below(64); // wrong-length hex (0..63 bytes)
            Value::String(rand_hex(rng, n))
        }
        2 => Value::String("nothex_zz".into()),           // valid string, not hex
        3 => Value::Number(rng.next_u64().into()),        // not a string
        4 => Value::Bool(true),
        _ => Value::Null,
    }
}

/// A `siblings` array whose length is biased across the `MAX_DEPTH` cap so both
/// the accept and the reject-before-alloc branch are exercised.
#[cfg(feature = "node-core")]
fn gen_siblings(rng: &mut Rng) -> serde_json::Value {
    let n = match rng.below(4) {
        0 => rng.below(257),       // within the MAX_DEPTH=256 cap
        1 => 256 + rng.below(48),  // just over the cap → reject branch
        2 => 0,
        _ => rng.below(8),
    };
    let mut arr = Vec::with_capacity(n);
    for _ in 0..n {
        arr.push(gen_hex_field(rng));
    }
    serde_json::Value::Array(arr)
}

/// An account-proof request body: usually an object with an independently
/// present-or-absent, valid-or-malformed value per field (so the
/// `account_id`-then-`identity` fallback and every missing-field path are hit);
/// 1-in-8, a non-object shape the parsers must still reject without panicking.
#[cfg(feature = "node-core")]
fn gen_account_proof_body(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    if rng.below(8) == 0 {
        return match rng.below(4) {
            0 => Value::Null,
            1 => Value::Array(vec![gen_hex_field(rng)]),
            2 => Value::String(rand_hex(rng, 16)),
            _ => Value::Number(rng.next_u64().into()),
        };
    }
    let mut map = serde_json::Map::new();
    for key in ["account_id", "identity", "state_hash", "root", "present"] {
        if rng.next_u64() & 1 == 0 {
            map.insert(key.to_string(), gen_hex_field(rng));
        }
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("siblings".to_string(), gen_siblings(rng));
    }
    Value::Object(map)
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_account_proof_wire_parsers_are_fail_closed() {
    use crate::network::account_merkle::{parse_wire_exclusion, parse_wire_proof};
    let seed = 0xE1A2_000Du64;
    let mut rng = Rng::new(seed);
    for i in 0..*ITERS {
        let body = gen_account_proof_body(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_wire_proof(&body);
            let _ = parse_wire_exclusion(&body);
        }));
        assert!(
            r.is_ok(),
            "account-proof wire parser PANICKED — not fail-closed. seed={seed:#x} iter={i} body={body}",
        );
    }
}

// ── Checkpoint JSON-Value parsers (light-client cold-start path) ──
//
// `network::light::parse_checkpoint_json` is the SAME hand-rolled JSON-Value
// field-extraction class as the account-proof parsers above — and reached the
// same way: `light_sync_loop` pulls a `/checkpoints/from/{epoch}` body from a
// SEED PEER (`light.rs:489`), extracts the `checkpoints` array, and runs each
// element through `parse_checkpoint_json`. A hostile or compromised seed
// controls every byte of that JSON (see the threat-model comment at
// `light.rs:739`), so a panic here is remotely reachable on the resource-
// constrained client — exactly where it stings most. The parser is fail-closed
// by inspection today (every field is `?`-guarded, and the `[u8; 32]` hash
// fields go through `decode_hex32`, which checks `bytes.len() != 32` BEFORE
// `copy_from_slice`), but — like the account-proof guards — none of that is
// enforced by the prod-panic scan: a future edit that drops the length check or
// inlines a `copy_from_slice` would slip past it. This sweep is the regression
// guard. `pick_checkpoint_skip_epoch` (the `{"checkpoints":[…]}`-envelope max-
// picker the same response feeds) rides along in the same loop.

/// One JSON value for a u64 field: small / full-range / string-encoded /
/// wrong-type / absent-as-null — the ways an integer field arrives malformed.
#[cfg(feature = "node-core")]
fn gen_u64_field(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    match rng.below(5) {
        0 => Value::Number(rng.below(1024).into()),
        1 => Value::Number(rng.next_u64().into()), // full-range u64 (epoch overflow probe)
        2 => Value::String(format!("{}", rng.next_u64())), // string-encoded number
        3 => Value::Bool(false),                    // wrong type
        _ => Value::Null,
    }
}

/// One JSON value for a string field (`zone` / `record_id`): valid / wrong-type.
#[cfg(feature = "node-core")]
fn gen_str_field(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    match rng.below(4) {
        0 => Value::String("0".into()),
        1 => Value::String("1/2/3".into()), // hierarchical zone id
        2 => Value::Number(rng.next_u64().into()), // wrong type
        _ => Value::Null,
    }
}

/// A `/checkpoints/from` checkpoint object: each field independently
/// present-or-absent and valid-or-malformed (so every missing-field `?`
/// short-circuit, the inverted-epoch reject, and the `decode_hex32` guard are
/// hit); 1-in-8, a non-object shape the parser must still reject without
/// panicking. `record_hash`/`committee_hash` reuse `gen_hex_field` (valid-32 /
/// wrong-length / non-hex / wrong-type) — the inputs `decode_hex32` branches on.
#[cfg(feature = "node-core")]
fn gen_checkpoint_body(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    if rng.below(8) == 0 {
        return match rng.below(4) {
            0 => Value::Null,
            1 => Value::Array(vec![gen_hex_field(rng)]),
            2 => Value::String(rand_hex(rng, 16)),
            _ => Value::Bool(true),
        };
    }
    let mut map = serde_json::Map::new();
    if rng.next_u64() & 1 == 0 {
        map.insert("zone".to_string(), gen_str_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("start_epoch".to_string(), gen_u64_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("end_epoch".to_string(), gen_u64_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("seal_count".to_string(), gen_u64_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("record_id".to_string(), gen_str_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("record_hash".to_string(), gen_hex_field(rng));
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("committee_hash".to_string(), gen_hex_field(rng));
    }
    Value::Object(map)
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_checkpoint_json_parsers_are_fail_closed() {
    use crate::network::light::{parse_checkpoint_json, pick_checkpoint_skip_epoch};
    let seed = 0xE1A2_000Eu64;
    let mut rng = Rng::new(seed);
    for i in 0..*ITERS {
        let body = gen_checkpoint_body(&mut rng);
        // (a) the single-checkpoint object parser (per-array-element call)
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_checkpoint_json(&body);
        }));
        assert!(
            r.is_ok(),
            "parse_checkpoint_json PANICKED — not fail-closed. seed={seed:#x} iter={i} body={body}",
        );
        // (b) the `{"checkpoints":[…]}`-envelope skip-epoch max-picker the same
        // response body feeds. Move `body` in (the parser above only borrowed).
        let second = gen_checkpoint_body(&mut rng);
        let mut env = serde_json::Map::new();
        env.insert(
            "checkpoints".to_string(),
            serde_json::Value::Array(vec![body, second]),
        );
        let envelope = serde_json::Value::Object(env);
        let r2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = pick_checkpoint_skip_epoch(&envelope);
        }));
        assert!(
            r2.is_ok(),
            "pick_checkpoint_skip_epoch PANICKED — not fail-closed. seed={seed:#x} iter={i}",
        );
    }
}

// ── Light-client sync + SDK JSON parsers (untrusted-seed response bodies) ──
//
// Two more hand-rolled JSON-Value parsers in the same class as the checkpoint/
// account-proof sweeps above, each a DISTINCT implementation no other sweep
// reaches: `light::parse_header_json` decodes every element of the periodic
// `/headers/from/{epoch}` pull (`light.rs:934` / `:1146`) — running
// continuously on every light client, the broadest exposure in the class — and
// `light_sdk::ProofResponse::from_json` is the SDK-side re-implementation of
// the node's account-proof parser, fed the raw `/proof/account/{identity}`
// response from whatever seed the SDK consumer pointed it at (fuzzing the
// node-side `parse_wire_proof` does not touch it). Both are `?`/guard-correct
// by inspection today (hex fields go through a `len != 32`-checked
// `decode_hex32`, the SDK caps `siblings` at MAX_DEPTH before allocating);
// these sweeps pin that empirically so a future dropped guard fails in CI.

/// One JSON value for an f64 field (`start`/`end`/`sealed_at`): float / int /
/// string-encoded / wrong-type / null.
#[cfg(feature = "node-core")]
fn gen_f64_field(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    match rng.below(5) {
        0 => serde_json::Number::from_f64((rng.next_u64() >> 11) as f64 / 1e3)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        1 => Value::Number(rng.below(1 << 30).into()),
        2 => Value::String(format!("{}.5", rng.below(1024))),
        3 => Value::Bool(false),
        _ => Value::Null,
    }
}

/// An `/epochs/headers` element: each field independently present-or-absent
/// and valid-or-malformed; `zone` alternates the string leg / the legacy-u64
/// leg / wrong-type (all three arrive on the wire); 1-in-8 a non-object shape.
#[cfg(feature = "node-core")]
fn gen_header_body(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    if rng.below(8) == 0 {
        return match rng.below(4) {
            0 => Value::Null,
            1 => Value::Array(vec![gen_hex_field(rng)]),
            2 => Value::String(rand_hex(rng, 16)),
            _ => Value::Bool(true),
        };
    }
    let mut map = serde_json::Map::new();
    if rng.next_u64() & 1 == 0 {
        let zone = match rng.below(3) {
            0 => gen_str_field(rng),
            1 => Value::Number(rng.next_u64().into()),
            _ => Value::Bool(false),
        };
        map.insert("zone".to_string(), zone);
    }
    for key in ["epoch_number", "record_count"] {
        if rng.next_u64() & 1 == 0 {
            map.insert(key.to_string(), gen_u64_field(rng));
        }
    }
    for key in ["merkle_root", "previous_seal_hash", "account_smt_root", "seal_record_hash"] {
        if rng.next_u64() & 1 == 0 {
            map.insert(key.to_string(), gen_hex_field(rng));
        }
    }
    for key in ["start", "end"] {
        if rng.next_u64() & 1 == 0 {
            map.insert(key.to_string(), gen_f64_field(rng));
        }
    }
    Value::Object(map)
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_header_json_parser_is_fail_closed() {
    use crate::network::light::parse_header_json;
    let seed = 0xE1A2_0014u64;
    let mut rng = Rng::new(seed);
    for i in 0..*ITERS {
        let body = gen_header_body(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_header_json(&body);
        }));
        assert!(
            r.is_ok(),
            "parse_header_json PANICKED — not fail-closed. seed={seed:#x} iter={i} body={body}",
        );
    }
}

/// A `/proof/account/{identity}` response body for the SDK-side parser: hex
/// fields + `siblings` biased across the MAX_DEPTH cap (reusing
/// `gen_siblings`), the `latest_sealed_account` sub-object in valid / null /
/// wrong-type shapes, and an `account_state` whose serde reject path must
/// error, not panic.
#[cfg(feature = "node-core")]
fn gen_proof_response_body(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    if rng.below(8) == 0 {
        return match rng.below(4) {
            0 => Value::Null,
            1 => Value::Array(vec![gen_hex_field(rng)]),
            2 => Value::String(rand_hex(rng, 16)),
            _ => Value::Number(rng.next_u64().into()),
        };
    }
    let mut map = serde_json::Map::new();
    for key in ["identity", "root", "state_hash", "present"] {
        if rng.next_u64() & 1 == 0 {
            map.insert(key.to_string(), gen_hex_field(rng));
        }
    }
    if rng.next_u64() & 1 == 0 {
        map.insert("siblings".to_string(), gen_siblings(rng));
    }
    if rng.next_u64() & 1 == 0 {
        let b = match rng.below(3) {
            0 => Value::Bool(true),
            1 => Value::String("yes".into()),
            _ => Value::Null,
        };
        map.insert("bound_to_seal".to_string(), b);
    }
    if rng.next_u64() & 1 == 0 {
        let sub = match rng.below(4) {
            0 => Value::Null,
            1 => Value::String("not an object".into()),
            _ => {
                let mut m = serde_json::Map::new();
                if rng.next_u64() & 1 == 0 {
                    m.insert("account_smt_root".to_string(), gen_hex_field(rng));
                }
                if rng.next_u64() & 1 == 0 {
                    m.insert("epoch_number".to_string(), gen_u64_field(rng));
                }
                if rng.next_u64() & 1 == 0 {
                    m.insert("sealed_at".to_string(), gen_f64_field(rng));
                }
                Value::Object(m)
            }
        };
        map.insert("latest_sealed_account".to_string(), sub);
    }
    if rng.next_u64() & 1 == 0 {
        let st = match rng.below(3) {
            0 => Value::Null,
            1 => Value::Array(vec![gen_u64_field(rng)]),
            _ => {
                let mut m = serde_json::Map::new();
                m.insert("identity".to_string(), gen_hex_field(rng));
                m.insert("balance".to_string(), gen_u64_field(rng));
                Value::Object(m)
            }
        };
        map.insert("account_state".to_string(), st);
    }
    Value::Object(map)
}

#[cfg(feature = "node-core")]
#[test]
fn fuzz_sdk_proof_response_from_json_is_fail_closed() {
    use crate::network::light_sdk::ProofResponse;
    let seed = 0xE1A2_0015u64;
    let mut rng = Rng::new(seed);
    for i in 0..*ITERS {
        let body = gen_proof_response_body(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = ProofResponse::from_json(&body);
        }));
        assert!(
            r.is_ok(),
            "ProofResponse::from_json PANICKED — not fail-closed. seed={seed:#x} iter={i} body={body}",
        );
    }
}

// ── Offline-verifier legs (verify_core — the `elara-verify` attack surface) ──
//
// Gate C of the July plan (the internal roadmap): the files a user feeds
// `elara-verify` (record JSON/wire, seal wire, inclusion-proof JSON,
// account-inclusion JSON) are the most attacker-exposed bytes in the project —
// downloaded from an UNTRUSTED node, then verified on the user's own machine.
// The legs are fail-closed by inspection (2026-07-02 adversarial verify: zero
// input-reachable unwrap/expect in the production region); these sweeps are the
// empirical regression pin for the residual class inspection can miss — slice
// indexing, arithmetic overflow — same posture as the wire-decoder sweeps
// above. The valid-then-mutated layers mutate the REAL shipped fixtures under
// examples/verify/ so the deep paths (signature verify, Merkle fold, committed-
// roots extraction) are reached, not just the parse-reject front door. The
// binary-owned legs (OTS proof walk, archived-header parse, drand-BLS envelope)
// are swept in `src/bin/elara_verify.rs::tests` — they are invisible from here.

/// A shipped `examples/verify/` fixture — the same artifacts the public README
/// walks users through, so the mutation base is exactly what hostile copies of
/// those files would start from.
fn verify_fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/examples/verify/{name}",
        env!("CARGO_MANIFEST_DIR"),
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path} unreadable: {e}"))
}

#[test]
fn fuzz_verify_core_seal_leg_is_fail_closed() {
    use crate::verify_core::verify_seal;
    let seal = verify_fixture("epoch-8219-zone-0.seal.wire");
    // The fixture's real creator key drives mutated inputs into the anchor-
    // membership PASS branch (Dilithium3 verify + committed-roots extraction);
    // the other sets exercise the reject branches.
    let real_key_hex = crate::record::ValidationRecord::from_bytes(&seal)
        .map(|r| hex::encode(&r.creator_public_key))
        .expect("shipped seal fixture decodes");
    let anchor_sets: Vec<Vec<String>> = vec![
        vec![real_key_hex.clone()],
        vec!["ab".repeat(32)],       // valid hex, wrong key
        vec!["not-hex-zz".into()],   // bad hex
        vec![],                      // empty → early Err
    ];
    let seed = 0xE1A2_0010u64;
    let mut rng = Rng::new(seed);
    // (a) structured-random bytes across all argument shapes.
    for i in 0..*ITERS {
        let input = gen_input(&mut rng);
        let anchors = &anchor_sets[rng.below(anchor_sets.len())];
        let expected: Option<String> = match rng.below(3) {
            0 => None,
            1 => Some(rand_hex(&mut rng, 32)),
            _ => Some("zz-not-hex".into()),
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_seal(&input, anchors, expected.as_deref(), &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_seal PANICKED on random input. seed={seed:#x} iter={i} len={} input=0x{}",
            input.len(),
            to_hex(&input),
        );
    }
    // (b) valid-then-mutated real seal (48 KB, PQ-signed). Decode survivors run
    // the full signature path, so the iteration count is crypto-budgeted
    // (one Dilithium3 verify over ~48 KB per surviving decode, debug-mode).
    let mut rng = Rng::new(0xE1A2_1010);
    for i in 0..1024 {
        let m = mutate(&mut rng, &seal);
        let anchors = &anchor_sets[rng.below(anchor_sets.len())];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_seal(&m, anchors, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_seal PANICKED on mutated fixture seal. iter={i} len={}",
            m.len(),
        );
    }
}

/// One record-inclusion sibling entry — mostly the canonical
/// `{"hash": …, "is_right": …}` object, with the field-level malformations the
/// leg must reject (non-bool is_right, missing fields, non-object shapes).
fn gen_record_sibling(rng: &mut Rng) -> serde_json::Value {
    use serde_json::Value;
    if rng.below(8) == 0 {
        return gen_hex_field(rng); // non-object sibling
    }
    let mut map = serde_json::Map::new();
    if rng.below(8) != 0 {
        map.insert("hash".into(), gen_hex_field(rng));
    }
    match rng.below(5) {
        0 => {}
        1 => {
            map.insert("is_right".into(), Value::Bool(rng.next_u64() & 1 == 0));
        }
        2 => {
            map.insert("is_right".into(), Value::Number(1.into()));
        }
        3 => {
            map.insert("is_right".into(), Value::String("true".into()));
        }
        _ => {
            map.insert("is_right".into(), Value::Null);
        }
    }
    Value::Object(map)
}

#[test]
fn fuzz_verify_core_inclusion_leg_is_fail_closed() {
    use crate::verify_core::verify_inclusion;
    let seed = 0xE1A2_0011u64;
    let mut rng = Rng::new(seed);
    // (a) raw random bytes — the serde front door.
    for i in 0..*ITERS {
        let input = gen_input(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_inclusion(&input, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_inclusion PANICKED on random bytes. seed={seed:#x} iter={i} input=0x{}",
            to_hex(&input),
        );
    }
    // (b) structured proof JSON — sibling count biased across the 64-level cap
    // (accept branch, reject branch, and the 0-sibling tautology guard), every
    // field independently valid/malformed/absent.
    let mut rng = Rng::new(0xE1A2_1011);
    for i in 0..*ITERS {
        let mut map = serde_json::Map::new();
        if rng.below(8) != 0 {
            map.insert("leaf".into(), gen_hex_field(&mut rng));
        }
        if rng.below(8) != 0 {
            map.insert("root".into(), gen_hex_field(&mut rng));
        }
        if rng.below(8) != 0 {
            let n = match rng.below(4) {
                0 => rng.below(65),      // within the 64-level cap
                1 => 64 + rng.below(8),  // straddling / over the cap
                2 => 0,                  // tautology guard
                _ => 300,                // far over → reject before the walk
            };
            let sibs: Vec<_> = (0..n).map(|_| gen_record_sibling(&mut rng)).collect();
            map.insert("siblings".into(), serde_json::Value::Array(sibs));
        }
        let body = serde_json::to_vec(&serde_json::Value::Object(map)).unwrap();
        let expect_root: Option<String> = match rng.below(3) {
            0 => None,
            1 => Some(rand_hex(&mut rng, 32)),
            _ => Some("oddlen".into()),
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_inclusion(&body, expect_root.as_deref(), &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_inclusion PANICKED on structured proof. seed=0xE1A2_1011 iter={i} body={}",
            String::from_utf8_lossy(&body),
        );
    }
}

#[test]
fn fuzz_verify_core_account_inclusion_leg_is_fail_closed() {
    use crate::verify_core::verify_account_inclusion;
    let seed = 0xE1A2_0012u64;
    let mut rng = Rng::new(seed);
    // (a) raw random bytes.
    for i in 0..*ITERS {
        let input = gen_input(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_inclusion(&input, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_inclusion PANICKED on random bytes. seed={seed:#x} iter={i} input=0x{}",
            to_hex(&input),
        );
    }
    // (b) byte-mutated REAL /proof/account payload (examples/verify fixture) —
    // mutations that survive serde reach the compressed-SMT fold (present-bitmap
    // + identity-path arithmetic), the deepest arithmetic in the leg.
    let fixture = verify_fixture("account-proof.json");
    let mut rng = Rng::new(0xE1A2_1012);
    for i in 0..10_000 {
        let m = mutate(&mut rng, &fixture);
        let expect_identity: Option<String> = match rng.below(3) {
            0 => None,
            1 => Some(rand_hex(&mut rng, 32)),
            _ => Some("short".into()),
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_inclusion(&m, expect_identity.as_deref(), &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_inclusion PANICKED on mutated fixture. iter={i} body={}",
            String::from_utf8_lossy(&m),
        );
    }
    // (c) structured bodies: every field independently present/malformed, the
    // bare-hex sibling array biased across the 256-level cap, plus the
    // exists:false and record-proof-decoy ("leaf") routing branches.
    let mut rng = Rng::new(0xE1A2_2012);
    for i in 0..*ITERS {
        let mut map = serde_json::Map::new();
        for key in ["identity", "state_hash", "root", "present"] {
            if rng.below(8) != 0 {
                map.insert(key.into(), gen_hex_field(&mut rng));
            }
        }
        if rng.below(4) == 0 {
            map.insert("leaf".into(), gen_hex_field(&mut rng));
        }
        if rng.below(4) == 0 {
            map.insert(
                "exists".into(),
                serde_json::Value::Bool(rng.next_u64() & 1 == 0),
            );
        }
        if rng.below(8) != 0 {
            let n = match rng.below(4) {
                0 => rng.below(257),
                1 => 256 + rng.below(8),
                2 => 0,
                _ => 400,
            };
            let sibs: Vec<_> = (0..n).map(|_| gen_hex_field(&mut rng)).collect();
            map.insert("siblings".into(), serde_json::Value::Array(sibs));
        }
        let body = serde_json::to_vec(&serde_json::Value::Object(map)).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_inclusion(&body, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_inclusion PANICKED on structured body. seed=0xE1A2_2012 iter={i} body={}",
            String::from_utf8_lossy(&body),
        );
    }
}

#[test]
fn fuzz_verify_core_account_exclusion_leg_is_fail_closed() {
    use crate::verify_core::verify_account_exclusion;
    let seed = 0xE1A2_0014u64;
    let mut rng = Rng::new(seed);
    // (a) raw random bytes.
    for i in 0..*ITERS {
        let input = gen_input(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_exclusion(&input, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_exclusion PANICKED on random bytes. seed={seed:#x} iter={i} input=0x{}",
            to_hex(&input),
        );
    }
    // (b) byte-mutated REAL exclusion witness — synthesized from the same
    // network-agreed SMT engine the leg folds with, so mutations that survive
    // serde reach the present-bitmap + identity-path arithmetic (the deepest
    // arithmetic in the leg), exactly like the inclusion harness above.
    let fixture = {
        use elara_smt::{MemorySmtStore, SparseMerkleTree};
        let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
        for k in 1u8..=6 {
            tree.update(&[k; 32], &[k ^ 0xAA; 32]).expect("update");
        }
        tree.commit().expect("commit");
        let xp = tree
            .exclusion_proof(&[0x77; 32])
            .expect("proof ok")
            .expect("absent id");
        serde_json::to_vec(&serde_json::json!({
            "identity": hex::encode(xp.account_id),
            "account_id": hex::encode(xp.account_id),
            "root": hex::encode(xp.root),
            "present": hex::encode(xp.present),
            "siblings": xp.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "exists": false,
        }))
        .unwrap()
    };
    let mut rng = Rng::new(0xE1A2_1014);
    for i in 0..10_000 {
        let m = mutate(&mut rng, &fixture);
        let expect_identity: Option<String> = match rng.below(3) {
            0 => None,
            1 => Some(rand_hex(&mut rng, 32)),
            _ => Some("short".into()),
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_exclusion(&m, expect_identity.as_deref(), &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_exclusion PANICKED on mutated fixture. iter={i} body={}",
            String::from_utf8_lossy(&m),
        );
    }
    // (c) structured bodies: every field independently present/malformed, the
    // sibling array biased across the 256-level cap, plus the routing decoys
    // this leg rejects (state_hash → inclusion, leaf → record proof,
    // pending_first_seal / exists:true → presence claims) and the
    // identity/account_id agreement branch.
    let mut rng = Rng::new(0xE1A2_2014);
    for i in 0..*ITERS {
        let mut map = serde_json::Map::new();
        for key in ["identity", "account_id", "root", "present"] {
            if rng.below(8) != 0 {
                map.insert(key.into(), gen_hex_field(&mut rng));
            }
        }
        if rng.below(4) == 0 {
            map.insert("state_hash".into(), gen_hex_field(&mut rng));
        }
        if rng.below(4) == 0 {
            map.insert("leaf".into(), gen_hex_field(&mut rng));
        }
        if rng.below(4) == 0 {
            map.insert(
                "exists".into(),
                serde_json::Value::Bool(rng.next_u64() & 1 == 0),
            );
        }
        if rng.below(4) == 0 {
            map.insert(
                "pending_first_seal".into(),
                serde_json::Value::Bool(rng.next_u64() & 1 == 0),
            );
        }
        if rng.below(8) != 0 {
            let n = match rng.below(4) {
                0 => rng.below(257),
                1 => 256 + rng.below(8),
                2 => 0,
                _ => 400,
            };
            let sibs: Vec<_> = (0..n).map(|_| gen_hex_field(&mut rng)).collect();
            map.insert("siblings".into(), serde_json::Value::Array(sibs));
        }
        let body = serde_json::to_vec(&serde_json::Value::Object(map)).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut checks = Vec::new();
            let _ = verify_account_exclusion(&body, None, &mut checks);
        }));
        assert!(
            r.is_ok(),
            "verify_account_exclusion PANICKED on structured body. seed=0xE1A2_2014 iter={i} body={}",
            String::from_utf8_lossy(&body),
        );
    }
}

#[test]
fn fuzz_verify_core_record_leg_is_fail_closed() {
    use crate::verify_core::verify_record;
    // Invariant: any record that DECODES must also VERIFY panic-free — the
    // exact composition `elara-verify` runs on a hostile record file. Iteration
    // counts are crypto-budgeted: each decode survivor runs the full signature
    // stack (Dilithium3 + SPHINCS+ for Profile A) in debug mode.
    let wire = verify_fixture("sample-record.wire");
    let mut rng = Rng::new(0xE1A2_0013);
    for i in 0..192 {
        let m = mutate(&mut rng, &wire);
        let content: Option<Vec<u8>> = match rng.below(3) {
            0 => None,
            1 => Some(b"wrong artifact".to_vec()),
            _ => Some(gen_input(&mut rng)),
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(rec) = crate::record::ValidationRecord::from_bytes(&m) {
                let mut checks = Vec::new();
                verify_record(&rec, content.as_deref(), "artifact", &mut checks);
            }
        }));
        assert!(
            r.is_ok(),
            "verify_record PANICKED on decoded mutated wire record. iter={i}",
        );
    }
    // Same invariant through the JSON front door (the verifier's default input).
    let json = verify_fixture("sample-record.json");
    let mut rng = Rng::new(0xE1A2_1013);
    for i in 0..192 {
        let m = mutate(&mut rng, &json);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(rec) = serde_json::from_slice::<crate::record::ValidationRecord>(&m) {
                let mut checks = Vec::new();
                verify_record(&rec, None, "artifact", &mut checks);
            }
        }));
        assert!(
            r.is_ok(),
            "verify_record PANICKED on decoded mutated JSON record. iter={i}",
        );
    }
}

#[test]
fn fuzz_receipt_envelope_parse_is_fail_closed() {
    use crate::receipt::parse_receipt_input;
    // The `--receipt` envelope is a stranger-supplied file: the parse layer
    // (caps → JSON → version gate → per-leg hex/size bounds) must never panic
    // and never allocate unbounded. Random bytes first.
    let seed = 0xE1A2_0015u64;
    let mut rng = Rng::new(seed);
    for i in 0..*ITERS {
        let input = gen_input(&mut rng);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_receipt_input(&input);
        }));
        assert!(
            r.is_ok(),
            "parse_receipt_input PANICKED on random bytes. seed={seed:#x} iter={i} input=0x{}",
            to_hex(&input),
        );
    }
    // Byte-mutated REAL envelope — mutations that survive JSON reach the
    // version gate, the legs map walk, and the hex/size cap arithmetic.
    let fixture = serde_json::json!({
        "receipt_version": crate::receipt::RECEIPT_VERSION,
        "producer": { "node": "fuzz" },
        "legs": {
            "record": "ab".repeat(64),
            "seal": "cd".repeat(64),
            "anchor": { "epoch": 1, "seal_hash": "ee" },
            "account_exclusion": { "identity": "ff", "root": "00", "present": "00", "siblings": [] },
            "lineage": null,
        },
    })
    .to_string()
    .into_bytes();
    let mut rng = Rng::new(0xE1A2_1015);
    for i in 0..10_000 {
        let m = mutate(&mut rng, &fixture);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_receipt_input(&m);
        }));
        assert!(
            r.is_ok(),
            "parse_receipt_input PANICKED on mutated envelope. iter={i} len={}",
            m.len(),
        );
    }
}
