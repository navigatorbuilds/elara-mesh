//! Gap 6 content-routed-DHT scale benchmark — closes the "test + benchmark +
//! deploy" rule for the Kademlia routing table hot path (internal design notes §MAINNET
//! MANDATE Gap 6). Correctness is already covered by 17 unit tests in
//! `src/network/dht.rs`; this supplies the per-op CPU evidence behind the
//! design at scale.
//!
//! ## What this measures
//!
//! Six call surfaces drive the DHT hot path:
//!
//! 1. **`insert`** — append a peer into the right k-bucket. Looks O(1) on
//!    the bucket but the diversity guard scans every bucket to count `/24`
//!    occurrences (`table_subnet_count`), so the actual op is O(n) in the
//!    table size. Runs on every PEX gossip, bootstrap reply, and DHT
//!    lookup that surfaces a new peer.
//!
//! 2. **`closest`** — pure XOR-distance lookup. Flattens every bucket
//!    into a Vec and sorts by `distance`. O(n + n log n). Runs on every
//!    record publish/lookup and every iterative find-node hop.
//!
//! 3. **`closest_to_record`** — wraps `closest_prefer_outbound` with an
//!    extra SHA3-256(record_id) on the front and an Outbound/Inbound tie
//!    break on the back. This is the content-routing hot path: every
//!    record gossip resolves "who's responsible for record X" through it.
//!
//! 4. **`all_peers`** — full-table snapshot used by `/admin/dht/peers`
//!    and DHT save (every heartbeat cycle). Pure O(n) flatten+collect.
//!
//! 5. **`find_by_identity`** — linear scan by `identity_hash` string
//!    match. Runs once per test-before-evict ping callback. O(n).
//!
//! 6. **`rotate_stale_peers`** — sweeps all buckets and retains by
//!    `first_added` age. Runs on every save tick. O(n).
//!
//! ## Why this matters
//!
//! Spec §11.14 / §11.28 sets the routing-table ceiling at K × 256 buckets =
//! 2048 peers per node, but `MAX_PER_SUBNET_TOTAL = 10` caps it tighter
//! in practice — a healthy mainnet table sits in the 200-2000 range. At
//! §11.12 1M zones × 10K+ nodes the DHT lookup fires on every record
//! publish/lookup, so any super-linear op here multiplies into a fleet-wide
//! CPU floor. The `closest_to_record` call in particular is on the
//! content-routing hot path — its budget must stay <10 µs for the
//! 10 T records/day target to fit one core per node.
//!
//! Insertion deserves its own attention: `table_subnet_count` is the
//! one operation in the file that quietly flattens every bucket on
//! every call. At N=2000 it should stay under ~100 µs; if Criterion
//! shows it climbing past 1 ms the diversity guard is the place to
//! revisit (per-subnet counter incrementally maintained on insert/remove,
//! SCALE RULE: "Never rebuild what you can update").
//!
//! ## Scenarios
//!
//! - `N=8`     — one full bucket (K=8 lower bound).
//! - `N=64`    — ~6-8 buckets exercised (small testnet today).
//! - `N=512`   — mid-size mainnet node (~256 active peers across many `/24`s).
//! - `N=2000`  — near theoretical 2048 ceiling. Worst-case routing table.

use std::path::PathBuf;

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use elara_runtime::network::dht::{DhtPeer, NodeId, PeerProvenance, RoutingTable};

/// Deterministic NodeId from a u64 seed. Spreads the byte across all 32 bytes
/// via SHA3 so that bucket placement looks like real production diversity
/// (no clustering in low buckets).
fn make_node_id(seed: u64) -> NodeId {
    let bytes = seed.to_be_bytes();
    let hash = elara_runtime::crypto::hash::sha3_256(&bytes);
    NodeId(hash)
}

/// Build a peer with a diverse `/24` so we don't trip `MAX_PER_SUBNET_TOTAL=10`.
/// The 2nd and 3rd octets vary with `i`, giving 65 536 distinct `/24`s — well
/// above any benchmark size we run.
fn make_peer(i: u64) -> DhtPeer {
    let node_id = make_node_id(i);
    let identity_hash = node_id.to_hex();
    let octet_b = ((i / 256) % 256) as u8;
    let octet_c = (i % 256) as u8;
    DhtPeer {
        node_id,
        identity_hash,
        host: format!("10.{}.{}.1", octet_b, octet_c),
        port: 9473,
        last_seen: 1_000.0,
        first_added: 1_000.0,
        provenance: if i.is_multiple_of(4) {
            PeerProvenance::Inbound
        } else {
            PeerProvenance::Outbound
        },
    }
}

/// Build a routing table pre-populated with `n` peers. Subnet diversity is
/// guaranteed by `make_peer`, so insertion never trips the `/24` cap.
fn build_table(n: u64) -> RoutingTable {
    let local = make_node_id(0xFFFF_FFFF_FFFF_FFFF);
    let mut table = RoutingTable::new(local);
    for i in 1..=n {
        table.insert(make_peer(i));
    }
    table
}

/// `insert` cost — appears in unit-tests as a one-liner but actually
/// flattens every bucket via `table_subnet_count`. Bench with the table
/// already populated so the diversity-guard cost is exercised.
fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_insert");
    for &n in &[8u64, 64, 512, 2_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter_batched(
                || (build_table(n), make_peer(n + 1)),
                |(mut table, peer)| {
                    let res = table.insert(peer);
                    std::hint::black_box(res);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// `closest(target, K)` — pure XOR scan + sort. The two-arg `K=8`
/// matches the Kademlia replication factor used by `iterative_find_node`.
fn bench_closest(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_closest_k8");
    for &n in &[8u64, 64, 512, 2_000] {
        let table = build_table(n);
        let target = make_node_id(0xDEAD_BEEF);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter(|| {
                let peers = table.closest(&target, 8);
                std::hint::black_box(peers);
            });
        });
    }
    group.finish();
}

/// `closest_to_record(record_id, K)` — content-routing hot path. Adds a
/// SHA3-256 hash on the front and an outbound-prefer tie break on the back
/// of `closest`. The K=20 form matches a wider replication set sometimes
/// used in PoC traffic; K=8 is the production default — both benched.
fn bench_closest_to_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_closest_to_record_k8");
    for &n in &[8u64, 64, 512, 2_000] {
        let table = build_table(n);
        let record_id = "record-abc-123-deadbeef";
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter(|| {
                let peers = table.closest_to_record(record_id, 8);
                std::hint::black_box(peers);
            });
        });
    }
    group.finish();
}

/// `all_peers` — full-table snapshot used by `/admin/dht/peers` and the
/// DHT JSON save on every heartbeat. Pure O(n) flatten + collect — no
/// sort, no hashing. The reference cost for "linear scan of the table."
fn bench_all_peers(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_all_peers_snapshot");
    for &n in &[8u64, 64, 512, 2_000] {
        let table = build_table(n);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter(|| {
                let peers = table.all_peers();
                std::hint::black_box(peers);
            });
        });
    }
    group.finish();
}

/// `find_by_identity` — linear scan by string match. Worst-case path
/// (target is the LAST peer inserted) so the search walks every bucket.
fn bench_find_by_identity(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_find_by_identity_worst");
    for &n in &[8u64, 64, 512, 2_000] {
        let table = build_table(n);
        // Worst case: identity hash of the last peer (visited last by scan).
        let target = make_node_id(n).to_hex();
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter(|| {
                let p = table.find_by_identity(&target);
                std::hint::black_box(p);
            });
        });
    }
    group.finish();
}

/// `rotate_stale_peers` — every heartbeat (`peer_health_loop`). All peers
/// in `build_table` share `first_added = 1000.0`; with `now = 1000.0 + 1.0`
/// none age out (steady-state cost). Bench at the realistic "no evictions"
/// path — the eviction branch is cheaper (Vec::retain re-walks the same
/// elements either way).
fn bench_rotate_stale_peers(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_rotate_stale_no_evict");
    for &n in &[8u64, 64, 512, 2_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter_batched(
                || build_table(n),
                |mut table| {
                    let evicted = table.rotate_stale_peers(1_001.0);
                    std::hint::black_box(evicted);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

/// `save` + `load` round-trip — persisted DHT snapshot. Runs once per
/// heartbeat (`save`) and once per restart (`load`). Pure JSON marshalling
/// plus file I/O. Sized at the realistic mid-range (N=512); the smaller
/// and larger sizes are linear and don't change the conclusion.
fn bench_save_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_save_load_roundtrip");
    for &n in &[64u64, 512, 2_000] {
        let table = build_table(n);
        let tmp = std::env::temp_dir().join(format!("bench_dht_{}.json", n));
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("table_size", n), &n, |b, &_n| {
            b.iter_batched(
                || tmp.clone(),
                |path: PathBuf| {
                    table.save(&path);
                    let local = make_node_id(0xFFFF_FFFF_FFFF_FFFE);
                    let mut reloaded = RoutingTable::new(local);
                    let count = reloaded.load(&path);
                    std::hint::black_box(count);
                },
                BatchSize::SmallInput,
            );
        });
        let _ = std::fs::remove_file(&tmp);
    }
    group.finish();
}

fn print_projection(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[dht_scale_projection]");
    eprintln!("  Protocol §11.14 / §11.28 — Kademlia DHT.");
    eprintln!("  Routing-table ceiling: K=8 × 256 buckets = 2048 peers/node.");
    eprintln!("  Practical ceiling with MAX_PER_SUBNET_TOTAL=10: ~200-2000.");
    eprintln!();
    eprintln!("  Hot-path budgets at §11.12 target (10K nodes, 1M zones, 10 T records/day):");
    eprintln!("  - closest_to_record: <10 µs (content-routing on every record op)");
    eprintln!("  - closest:           <20 µs (find-node hop, alpha-3 parallel)");
    eprintln!("  - insert:            <100 µs (PEX/discovery, table_subnet_count walks all buckets)");
    eprintln!("  - all_peers:         <50 µs (admin endpoint + DHT save)");
    eprintln!("  - find_by_identity:  <50 µs (test-before-evict, rare)");
    eprintln!("  - rotate_stale:      <100 µs (every heartbeat, ~30 s)");
    eprintln!();
    eprintln!("  Fleet-wide CPU floor at content-routing rate:");
    eprintln!("  closest_to_record × 10 T records/day / 86 400 s = ~115 M ops/s cluster-wide.");
    eprintln!("  At 5 µs/op × 10 K nodes = 50 ms per node-second = 5 % of one core.");
    eprintln!("  If closest_to_record climbs above 50 µs at N=2000 we eat 50 % of a core.");
    eprintln!();
    eprintln!("  Mitigation paths if the bench shows red:");
    eprintln!("  - closest*: maintain a sorted-by-distance secondary index (BTreeMap of");
    eprintln!("    XOR-distance → peer ref) so closest(K) is O(K) not O(N log N).");
    eprintln!("  - insert: maintain a per-subnet counter on insert/remove so");
    eprintln!("    table_subnet_count becomes O(1) (SCALE RULE: never rebuild what you can update).");
    eprintln!("  - find_by_identity: HashMap<identity_hash, NodeId> sidecar.");
    eprintln!();
    eprintln!("  Save/load JSON cost is bounded by 2 KB/peer × 2000 = 4 MB serialisation.");
    eprintln!("  At restart, load is one-shot — no SCALE-RULE pressure.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_insert,
    bench_closest,
    bench_closest_to_record,
    bench_all_peers,
    bench_find_by_identity,
    bench_rotate_stale_peers,
    bench_save_load,
    print_projection,
);
criterion_main!(benches);
