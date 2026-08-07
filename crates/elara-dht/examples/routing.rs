// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! Kademlia XOR-distance routing in ~40 lines: build a routing table, insert a
//! handful of peers, and ask for the ones closest to a target key — the core
//! "who should hold record X?" primitive, with no global index.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-dht --example routing
//! ```
//!
//! This is peer discovery + content routing for the Elara mesh: nodes and
//! records share a 256-bit id space, and `closest` / `closest_to_record` pick
//! the peers whose ids XOR-nearest the target — the same metric answers both
//! "find a node" and "find the node responsible for a record."

use elara_dht::{DhtPeer, NodeId, PeerProvenance, RoutingTable};

fn id(byte: u8) -> NodeId {
    NodeId([byte; 32])
}

fn peer(byte: u8) -> DhtPeer {
    DhtPeer {
        node_id: id(byte),
        identity_hash: id(byte).to_hex(),
        // A hostname (not an IP): routing is by node_id, and this keeps the demo
        // clear of the per-subnet diversity limits real IPs would trigger.
        host: format!("node-{byte:02x}.test"),
        port: 9473,
        last_seen: 0.0,
        first_added: 0.0,
        provenance: PeerProvenance::Outbound,
    }
}

fn main() {
    // Local node at id 0x00..00; populate the table across the id space.
    let mut table = RoutingTable::new(id(0x00));
    for b in [0x01u8, 0x10, 0x40, 0x80, 0xC0, 0xFF] {
        let _ = table.insert(peer(b));
    }
    println!("routing table holds {} peers", table.len());

    // Who is XOR-closest to target 0x42..? Distance = target XOR peer_id.
    let target = id(0x42);
    let closest = table.closest(&target, 3);
    println!("3 closest peers to 0x42..:");
    for p in &closest {
        println!("  {} (id starts {:#04x})", p.identity_hash, p.node_id.0[0]);
    }

    // 0x42 ^ 0x40 = 0x02 (nearest); 0x42 ^ 0x01 = 0x43; 0x42 ^ 0x10 = 0x52.
    assert_eq!(closest[0].node_id.0[0], 0x40, "0x40 is XOR-nearest to 0x42");
    println!("  -> 0x40.. is nearest (0x42 XOR 0x40 = 0x02, the smallest distance)");

    // The same metric routes records: closest_to_record hashes the record id
    // into the node id space and returns the peers responsible for it.
    let holders = table.closest_to_record("record:abc123", 2);
    let names: Vec<&str> = holders.iter().map(|p| p.identity_hash.as_str()).collect();
    println!("\n2 peers responsible for \"record:abc123\": {}", names.join(", "));
}
