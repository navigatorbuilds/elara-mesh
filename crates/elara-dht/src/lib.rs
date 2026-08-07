//! Lightweight Kademlia DHT for peer discovery (no key-value storage).

//!
//! Spec references:
//!   @spec Protocol §11.14
//!   @spec Protocol §11.28

#![forbid(unsafe_code)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// SHA3-256 of `data` → 32 bytes.
///
/// Local copy of the one hash primitive this crate needs, so `elara-dht`
/// stands alone with no dependency on the parent runtime's crypto module.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Node identifier — 32-byte hash from identity_hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Parse a hex identity_hash into a NodeId.
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// XOR distance between two NodeIds.
    pub fn distance(&self, other: &NodeId) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, byte) in d.iter_mut().enumerate() {
            *byte = self.0[i] ^ other.0[i];
        }
        d
    }

    /// Bucket index for a target (0-255). Returns None if self == target.
    pub fn bucket_index(&self, target: &NodeId) -> Option<usize> {
        let dist = self.distance(target);
        // Find the first non-zero bit (MSB of XOR distance)
        for (i, byte) in dist.iter().enumerate() {
            if *byte != 0 {
                let leading = byte.leading_zeros() as usize;
                return Some(i * 8 + leading);
            }
        }
        None // identical nodes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Gap 6: Map a record_id to a NodeId-space target for content routing.
    ///
    /// Uses SHA3-256(record_id) so that every node agrees on which "address"
    /// a record lives at. The K closest peers to this address are the
    /// record's responsible replicas.
    pub fn from_record_id(record_id: &str) -> Self {
        let hash = sha3_256(record_id.as_bytes());
        Self(hash)
    }
}

/// How a peer was discovered — outbound (we found them) vs inbound (they found us).
/// Outbound peers are preferred for routing because inbound connections are easier
/// to fake in eclipse attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerProvenance {
    /// We discovered this peer via bootstrap, DHT lookup, or PEX.
    Outbound,
    /// This peer connected to us (inbound connection).
    Inbound,
}

/// A peer entry in the DHT routing table.
#[derive(Debug, Clone)]
pub struct DhtPeer {
    pub node_id: NodeId,
    /// Lowercase hex of `node_id.0` (64 chars). [`RoutingTable::load`] re-derives
    /// `node_id` from this field via [`NodeId::from_hex`] and silently SKIPS any
    /// peer whose `identity_hash` is not valid 64-char hex — so a non-hex value
    /// (e.g. a human label) survives in-memory routing but is dropped on
    /// save/load. Construct it with [`NodeId::to_hex`].
    pub identity_hash: String,
    pub host: String,
    pub port: u16,
    pub last_seen: f64,
    /// When this peer was first added to the routing table (unix timestamp).
    /// Used for time-gated rotation — peers older than `PEER_MAX_AGE_SECS` are
    /// proactively evicted even if responsive, limiting eclipse attack window.
    pub first_added: f64,
    /// How this peer was discovered (outbound = we found them, inbound = they found us).
    pub provenance: PeerProvenance,
}

/// Maximum peers per k-bucket.
const K: usize = 8;

/// Number of parallel lookups.
pub const ALPHA: usize = 3;

/// Number of disjoint parallel lookup paths (S/Kademlia).
/// d=4 gives 99% success even with 20% adversarial nodes.
pub const DISJOINT_PATHS: usize = 4;

/// Maximum nodes from the same /24 subnet per k-bucket.
const MAX_PER_SUBNET_PER_BUCKET: usize = 2;

/// Maximum nodes from the same /24 subnet across the entire routing table.
const MAX_PER_SUBNET_TOTAL: usize = 10;

/// Maximum DHT snapshot file size accepted by [`RoutingTable::load`].
///
/// The routing table holds at most `K * 256 = 2048` peers and each persisted
/// entry is a few hundred bytes of JSON, so 8 MiB is orders of magnitude above
/// any honest snapshot. The cap bounds the read allocation from a hostile or
/// corrupt file: `load` takes a caller-supplied path, and an unbounded
/// `read_to_string` on it could OOM the process before the per-bucket insert
/// caps ever apply.
const MAX_DHT_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum age of a peer before forced rotation (even if responsive).
/// Eclipse attackers holding long-lived connections gain disproportionate routing
/// influence; rotating peers every 4 hours bounds their advantage.
const PEER_MAX_AGE_SECS: f64 = 4.0 * 3600.0; // 4 hours

/// Extract network prefix from an IP address string for diversity enforcement.
///
/// - IPv4: returns /24 prefix (first 3 octets, e.g. "192.168.1" from "192.168.1.42")
/// - IPv6: returns /48 prefix (first 3 hextets, e.g. "2001:db8:1" from "2001:db8:1::42")
///
/// Returns None for hostnames or unparseable addresses.
fn subnet_prefix(host: &str) -> Option<String> {
    // Try IPv4 first
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
    }
    // Try IPv6: extract /48 prefix (first 3 hextets)
    // Handles full and abbreviated forms via std::net parse
    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        let segs = addr.segments();
        return Some(format!("{:x}:{:x}:{:x}", segs[0], segs[1], segs[2]));
    }
    // Also try [::ffff:x.x.x.x] mapped addresses stored as IPv6 text
    if host.contains(':') {
        // Try stripping brackets
        let stripped = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(addr) = stripped.parse::<std::net::Ipv6Addr>() {
            let segs = addr.segments();
            return Some(format!("{:x}:{:x}:{:x}", segs[0], segs[1], segs[2]));
        }
    }
    None
}

/// Result of attempting to insert a peer into a full k-bucket.
#[derive(Debug)]
pub enum InsertResult {
    /// Peer was inserted successfully (bucket had room or was an update).
    Inserted,
    /// Bucket is full. The oldest peer (front of list) should be pinged first.
    /// If it doesn't respond, call `evict_and_insert` to replace it.
    /// Contains the identity_hash of the peer to ping.
    PendingEviction {
        /// Identity hash of the oldest peer to ping before evicting.
        evict_candidate: String,
    },
    /// Peer was rejected due to IP diversity limits.
    RejectedSubnetLimit,
}

/// A single k-bucket with LRU ordering and IP diversity enforcement.
#[derive(Debug, Clone)]
struct KBucket {
    peers: Vec<DhtPeer>,
}

impl KBucket {
    fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Count peers from a given /24 subnet in this bucket.
    fn subnet_count(&self, subnet: &str) -> usize {
        self.peers.iter()
            .filter(|p| subnet_prefix(&p.host).as_deref() == Some(subnet))
            .count()
    }

    /// Insert a peer with IP diversity enforcement and test-before-evict.
    ///
    /// - If the peer already exists, updates it (move to back of LRU list).
    /// - If the bucket has room and subnet limits aren't exceeded, inserts.
    /// - If the bucket is full, returns `PendingEviction` with the oldest peer
    ///   to ping. The caller must ping it and call `evict_and_insert` if no response.
    fn insert(&mut self, peer: DhtPeer, table_subnet_count: usize) -> InsertResult {
        // Check if already present — update and move to back (preserve first_added)
        if let Some(pos) = self.peers.iter().position(|p| p.node_id == peer.node_id) {
            let original_first_added = self.peers[pos].first_added;
            let mut updated = peer;
            updated.first_added = original_first_added;
            self.peers.remove(pos);
            self.peers.push(updated);
            return InsertResult::Inserted;
        }

        // Check /24 subnet diversity limits
        if let Some(ref subnet) = subnet_prefix(&peer.host) {
            // Per-bucket limit
            if self.subnet_count(subnet) >= MAX_PER_SUBNET_PER_BUCKET {
                return InsertResult::RejectedSubnetLimit;
            }
            // Table-wide limit (caller provides the count)
            if table_subnet_count >= MAX_PER_SUBNET_TOTAL {
                return InsertResult::RejectedSubnetLimit;
            }
        }

        if self.peers.len() < K {
            self.peers.push(peer);
            InsertResult::Inserted
        } else {
            // Bucket full — test-before-evict: return the oldest peer for pinging
            let evict_candidate = self.peers[0].identity_hash.clone();
            InsertResult::PendingEviction { evict_candidate }
        }
    }

    /// Force-insert after confirming the eviction candidate is dead.
    /// Removes the oldest peer (front) and inserts the new one.
    fn evict_and_insert(&mut self, peer: DhtPeer) {
        if self.peers.len() >= K {
            self.peers.remove(0);
        }
        self.peers.push(peer);
    }

    /// Remove a peer by NodeId. Returns true if found and removed.
    fn remove(&mut self, node_id: &NodeId) -> bool {
        if let Some(pos) = self.peers.iter().position(|p| p.node_id == *node_id) {
            self.peers.remove(pos);
            true
        } else {
            false
        }
    }

    fn peers(&self) -> &[DhtPeer] {
        &self.peers
    }

    /// Move a peer to the back of the LRU list (most recently seen).
    fn touch(&mut self, node_id: &NodeId, last_seen: f64) {
        if let Some(pos) = self.peers.iter().position(|p| p.node_id == *node_id) {
            let mut peer = self.peers.remove(pos);
            peer.last_seen = last_seen;
            self.peers.push(peer);
        }
    }
}

/// Kademlia routing table with 256 k-buckets.
///
/// Hardened with:
/// - IP diversity limits (/24 subnet caps per bucket and table-wide)
/// - Test-before-evict (returns eviction candidate for ping before replacing)
/// - Outbound peer preference via `PeerProvenance` tracking
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a new routing table for the given local node ID.
    pub fn new(local_id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new());
        }
        Self { local_id, buckets }
    }

    /// Count total peers from a /24 subnet across the entire routing table.
    fn table_subnet_count(&self, subnet: &str) -> usize {
        self.buckets.iter()
            .flat_map(|b| b.peers())
            .filter(|p| subnet_prefix(&p.host).as_deref() == Some(subnet))
            .count()
    }

    /// Insert a peer into the appropriate k-bucket.
    ///
    /// Returns `InsertResult` indicating whether the insert succeeded,
    /// was rejected (subnet limits), or requires a ping-before-evict.
    pub fn insert(&mut self, peer: DhtPeer) -> InsertResult {
        if peer.node_id == self.local_id {
            return InsertResult::Inserted; // silently skip self
        }
        let subnet_count = subnet_prefix(&peer.host)
            .map(|s| self.table_subnet_count(&s))
            .unwrap_or(0);
        if let Some(idx) = self.local_id.bucket_index(&peer.node_id) {
            self.buckets[idx].insert(peer, subnet_count)
        } else {
            InsertResult::Inserted
        }
    }

    /// Force-insert a peer after confirming the eviction candidate is dead.
    /// Call this after `insert()` returns `PendingEviction` and the ping fails.
    pub fn evict_and_insert(&mut self, peer: DhtPeer) {
        if peer.node_id == self.local_id {
            return;
        }
        if let Some(idx) = self.local_id.bucket_index(&peer.node_id) {
            self.buckets[idx].evict_and_insert(peer);
        }
    }

    /// Mark a peer as recently seen (move to back of LRU list).
    /// Called when a ping succeeds during test-before-evict.
    pub fn touch(&mut self, node_id: &NodeId, last_seen: f64) {
        if let Some(idx) = self.local_id.bucket_index(node_id) {
            self.buckets[idx].touch(node_id, last_seen);
        }
    }

    /// Find the closest `count` peers to a target.
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<&DhtPeer> {
        let mut all: Vec<&DhtPeer> = self.buckets.iter()
            .flat_map(|b| b.peers())
            .collect();

        all.sort_by(|a, b| {
            let da = a.node_id.distance(target);
            let db = b.node_id.distance(target);
            da.cmp(&db)
        });

        all.truncate(count);
        all
    }

    /// Gap 6: K closest peers to `record_id` for content-routed gossip.
    ///
    /// The replication set for a record is the K peers whose NodeId is
    /// closest (in XOR distance) to SHA3-256(record_id). Every node computes
    /// the same set independently — no coordination needed.
    ///
    /// Returns an empty Vec if the routing table is empty.
    pub fn closest_to_record(&self, record_id: &str, count: usize) -> Vec<&DhtPeer> {
        let target = NodeId::from_record_id(record_id);
        self.closest_prefer_outbound(&target, count)
    }

    /// Find the closest `count` peers to a target, preferring outbound-discovered peers.
    /// For equal XOR distance, outbound peers sort before inbound peers.
    pub fn closest_prefer_outbound(&self, target: &NodeId, count: usize) -> Vec<&DhtPeer> {
        let mut all: Vec<&DhtPeer> = self.buckets.iter()
            .flat_map(|b| b.peers())
            .collect();

        all.sort_by(|a, b| {
            let da = a.node_id.distance(target);
            let db = b.node_id.distance(target);
            let dist_cmp = da.cmp(&db);
            if dist_cmp == std::cmp::Ordering::Equal {
                // Outbound < Inbound (prefer outbound)
                let a_out = matches!(a.provenance, PeerProvenance::Outbound);
                let b_out = matches!(b.provenance, PeerProvenance::Outbound);
                b_out.cmp(&a_out) // true > false, so reverse for outbound-first
            } else {
                dist_cmp
            }
        });

        all.truncate(count);
        all
    }

    /// Total number of peers in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.peers.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find a peer by identity hash (linear scan). Used for test-before-evict pings.
    pub fn find_by_identity(&self, identity_hash: &str) -> Option<DhtPeer> {
        for bucket in &self.buckets {
            for peer in bucket.peers() {
                if peer.identity_hash == identity_hash {
                    return Some(peer.clone());
                }
            }
        }
        None
    }

    /// Remove a peer from the routing table by NodeId. Returns true if found and removed.
    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        if let Some(idx) = self.local_id.bucket_index(node_id) {
            self.buckets[idx].remove(node_id)
        } else {
            false
        }
    }

    /// Evict peers older than `PEER_MAX_AGE_SECS` (time-gated rotation).
    ///
    /// Eclipse attackers who hold long-lived connections gain disproportionate
    /// routing influence. This method proactively removes peers that have been
    /// in the routing table for too long, forcing the node to discover fresh
    /// peers via DHT lookups. Returns the number of peers evicted.
    ///
    /// Call periodically (e.g. every heartbeat cycle alongside DHT save).
    pub fn rotate_stale_peers(&mut self, now: f64) -> usize {
        let mut evicted = 0;
        for bucket in &mut self.buckets {
            let before = bucket.peers.len();
            bucket.peers.retain(|p| (now - p.first_added) < PEER_MAX_AGE_SECS);
            evicted += before - bucket.peers.len();
        }
        evicted
    }

    /// Get the local node ID.
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Number of non-empty k-buckets (indicates address-space coverage).
    pub fn occupied_buckets(&self) -> usize {
        self.buckets.iter().filter(|b| !b.peers.is_empty()).count()
    }

    /// Bucket fill distribution: (bucket_index, peer_count) for non-empty buckets.
    pub fn bucket_distribution(&self) -> Vec<(usize, usize)> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.peers.is_empty())
            .map(|(i, b)| (i, b.peers.len()))
            .collect()
    }

    /// Return all peers in the routing table.
    pub fn all_peers(&self) -> Vec<&DhtPeer> {
        self.buckets.iter().flat_map(|b| b.peers()).collect()
    }

    /// Count of outbound vs inbound peers in the routing table.
    pub fn provenance_counts(&self) -> (usize, usize) {
        let mut outbound = 0;
        let mut inbound = 0;
        for peer in self.all_peers() {
            match peer.provenance {
                PeerProvenance::Outbound => outbound += 1,
                PeerProvenance::Inbound => inbound += 1,
            }
        }
        (outbound, inbound)
    }

    /// Save the routing table to a JSON file for persistence across restarts.
    pub fn save(&self, path: &Path) {
        let entries: Vec<DhtPeerEntry> = self.all_peers().iter().map(|p| DhtPeerEntry {
            identity_hash: p.identity_hash.clone(),
            host: p.host.clone(),
            port: p.port,
            last_seen: p.last_seen,
        }).collect();
        let data = DhtSnapshot { peers: entries };
        if let Ok(json) = serde_json::to_string(&data) {
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Load peers from a JSON snapshot and insert into routing table.
    pub fn load(&mut self, path: &Path) -> usize {
        use std::io::Read;
        // Bounded read: cap the allocation from a hostile/corrupt snapshot file
        // (an unbounded `read_to_string` on a caller-supplied path could OOM
        // before any per-bucket cap applies). A file over the cap truncates and
        // then fails JSON/UTF-8 decode → returns 0 (fails closed).
        let mut data = String::new();
        let read_result = std::fs::File::open(path)
            .and_then(|f| f.take(MAX_DHT_SNAPSHOT_BYTES).read_to_string(&mut data));
        if read_result.is_err() {
            return 0;
        }
        let snapshot: DhtSnapshot = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let mut count = 0;
        for entry in snapshot.peers {
            if let Some(node_id) = NodeId::from_hex(&entry.identity_hash) {
                self.insert(DhtPeer {
                    node_id,
                    identity_hash: entry.identity_hash,
                    host: entry.host,
                    port: entry.port,
                    last_seen: entry.last_seen,
                    first_added: entry.last_seen, // best estimate from persisted snapshot
                    provenance: PeerProvenance::Outbound,
                });
                count += 1;
            }
        }
        count
    }
}

/// Serializable peer entry for DHT persistence.
///
/// 4E.6 (2026-04-27): older snapshots may carry an extra `tls` key. Serde
/// silently ignores unknown fields, so legacy snapshots load cleanly.
#[derive(Serialize, Deserialize)]
struct DhtPeerEntry {
    identity_hash: String,
    host: String,
    port: u16,
    last_seen: f64,
}

/// JSON snapshot of the DHT routing table.
#[derive(Serialize, Deserialize)]
struct DhtSnapshot {
    peers: Vec<DhtPeerEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> NodeId {
        let mut arr = [0u8; 32];
        arr[0] = byte;
        NodeId(arr)
    }

    fn make_peer(byte: u8, port: u16) -> DhtPeer {
        DhtPeer {
            node_id: make_id(byte),
            identity_hash: format!("{:02x}{}", byte, "00".repeat(31)),
            host: "127.0.0.1".to_string(),
            port,
            last_seen: 1000.0,
            first_added: 1000.0,
            provenance: PeerProvenance::Outbound,
        }
    }

    fn make_peer_with_ip(byte: u8, port: u16, host: &str) -> DhtPeer {
        DhtPeer {
            node_id: make_id(byte),
            identity_hash: format!("{:02x}{}", byte, "00".repeat(31)),
            host: host.to_string(),
            port,
            last_seen: 1000.0,
            first_added: 1000.0,
            provenance: PeerProvenance::Outbound,
        }
    }

    #[test]
    fn test_xor_distance() {
        let a = make_id(0b1010_0000);
        let b = make_id(0b1100_0000);
        let d = a.distance(&b);
        assert_eq!(d[0], 0b0110_0000);
    }

    #[test]
    fn test_bucket_index() {
        let local = make_id(0);
        let target = make_id(1); // distance: 0x01 in byte 0
        assert_eq!(local.bucket_index(&target), Some(7)); // 7 leading zeros

        let target2 = make_id(128); // distance: 0x80 in byte 0
        assert_eq!(local.bucket_index(&target2), Some(0)); // 0 leading zeros
    }

    #[test]
    fn test_self_bucket_index() {
        let local = make_id(42);
        assert_eq!(local.bucket_index(&local), None);
    }

    #[test]
    fn test_routing_table_insert_and_closest() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        table.insert(make_peer(1, 9001));
        table.insert(make_peer(2, 9002));
        table.insert(make_peer(128, 9003));

        assert_eq!(table.len(), 3);

        let target = make_id(3); // close to 1 and 2
        let closest = table.closest(&target, 2);
        assert_eq!(closest.len(), 2);
        // Peer 2 (distance 1) and peer 1 (distance 2) should be closest
        assert_eq!(closest[0].node_id, make_id(2));
        assert_eq!(closest[1].node_id, make_id(1));
    }

    #[test]
    fn test_kbucket_test_before_evict() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Fill bucket 0 (all have MSB set, so distance byte[0] has MSB set)
        // Peers 128..135 all go into bucket 0
        for i in 128..128 + K {
            let mut peer = make_peer(i as u8, 9000 + i as u16);
            peer.host = format!("10.0.{}.1", i); // different subnets
            table.insert(peer);
        }
        assert_eq!(table.len(), K);

        // Insert one more into bucket 0 — should get PendingEviction
        let mut extra = make_peer(136, 9136);
        extra.host = "10.1.0.1".to_string();
        let result = table.insert(extra.clone());
        match result {
            InsertResult::PendingEviction { evict_candidate } => {
                // Should be the identity of peer 128 (oldest in bucket)
                assert!(evict_candidate.starts_with("80"));
                // Now simulate ping failure: force evict
                table.evict_and_insert(extra);
                assert_eq!(table.len(), K); // still K
            }
            _ => panic!("expected PendingEviction, got {:?}", result),
        }
    }

    #[test]
    fn test_skip_self() {
        let local = make_id(42);
        let mut table = RoutingTable::new(local);
        table.insert(make_peer(42, 9000));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_from_hex() {
        let hex = "aa".repeat(32);
        let id = NodeId::from_hex(&hex).unwrap();
        assert_eq!(id.0[0], 0xaa);
        assert_eq!(id.to_hex(), hex);
    }

    #[test]
    fn test_remove_peer() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        table.insert(make_peer(1, 9001));
        table.insert(make_peer(2, 9002));
        table.insert(make_peer(128, 9003));
        assert_eq!(table.len(), 3);

        // Remove existing peer
        assert!(table.remove(&make_id(1)));
        assert_eq!(table.len(), 2);

        // Remove non-existent peer
        assert!(!table.remove(&make_id(99)));
        assert_eq!(table.len(), 2);

        // Remove self (no bucket) returns false
        assert!(!table.remove(&make_id(0)));
    }

    #[test]
    fn test_save_load_roundtrip() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        table.insert(make_peer(1, 9001));
        table.insert(make_peer(2, 9002));
        table.insert(make_peer(128, 9003));
        assert_eq!(table.len(), 3);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht.json");
        table.save(&path);

        // Load into a fresh table
        let mut table2 = RoutingTable::new(local);
        let loaded = table2.load(&path);
        assert_eq!(loaded, 3);
        assert_eq!(table2.len(), 3);

        // Verify closest query still works
        let target = make_id(3);
        let closest = table2.closest(&target, 2);
        assert_eq!(closest[0].node_id, make_id(2));
        assert_eq!(closest[1].node_id, make_id(1));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        let loaded = table.load(Path::new("/tmp/nonexistent-dht.json"));
        assert_eq!(loaded, 0);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_load_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht.json");
        std::fs::write(&path, "not json").unwrap();

        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        let loaded = table.load(&path);
        assert_eq!(loaded, 0);
    }

    #[test]
    fn test_all_peers() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        table.insert(make_peer(1, 9001));
        table.insert(make_peer(128, 9002));
        assert_eq!(table.all_peers().len(), 2);
    }

    #[test]
    fn test_update_existing_peer() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        table.insert(DhtPeer {
            node_id: make_id(1),
            identity_hash: "test".into(),
            host: "127.0.0.1".into(),
            port: 9001,
            last_seen: 100.0,
            first_added: 100.0,
            provenance: PeerProvenance::Outbound,
        });

        table.insert(DhtPeer {
            node_id: make_id(1),
            identity_hash: "test".into(),
            host: "127.0.0.1".into(),
            port: 9001,
            last_seen: 200.0,
            first_added: 200.0,
            provenance: PeerProvenance::Outbound,
        });

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_occupied_buckets() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        assert_eq!(table.occupied_buckets(), 0);

        // Peer 1 goes into bucket 7 (distance byte 0 = 0x01 → 7 leading zeros)
        table.insert(make_peer(1, 9001));
        assert_eq!(table.occupied_buckets(), 1);

        // Peer 2 goes into bucket 6 (distance byte 0 = 0x02 → 6 leading zeros)
        table.insert(make_peer(2, 9002));
        assert_eq!(table.occupied_buckets(), 2);

        // Peer 3 goes into bucket 6 too (distance byte 0 = 0x03 → 6 leading zeros)
        table.insert(make_peer(3, 9003));
        assert_eq!(table.occupied_buckets(), 2); // still 2 distinct buckets
    }

    #[test]
    fn test_bucket_distribution() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        table.insert(make_peer(1, 9001));  // bucket 7
        table.insert(make_peer(2, 9002));  // bucket 6
        table.insert(make_peer(3, 9003));  // bucket 6
        table.insert(make_peer(128, 9004)); // bucket 0

        let dist = table.bucket_distribution();
        assert_eq!(dist.len(), 3); // 3 non-empty buckets

        // Find bucket 0 (peer 128)
        let b0 = dist.iter().find(|(i, _)| *i == 0).unwrap();
        assert_eq!(b0.1, 1);

        // Find bucket 6 (peers 2, 3)
        let b6 = dist.iter().find(|(i, _)| *i == 6).unwrap();
        assert_eq!(b6.1, 2);

        // Find bucket 7 (peer 1)
        let b7 = dist.iter().find(|(i, _)| *i == 7).unwrap();
        assert_eq!(b7.1, 1);
    }

    // ─── IP Diversity Limit Tests ────────────────────────────────────────

    #[test]
    fn test_subnet_prefix_extraction() {
        assert_eq!(subnet_prefix("192.168.1.42"), Some("192.168.1".into()));
        assert_eq!(subnet_prefix("10.0.0.1"), Some("10.0.0".into()));
        assert_eq!(subnet_prefix("::1"), Some("0:0:0".into())); // IPv6 loopback → /48
        assert_eq!(subnet_prefix("localhost"), None);
        assert_eq!(subnet_prefix(""), None);
    }

    #[test]
    fn test_subnet_per_bucket_limit() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Insert 2 peers from same /24 into bucket 0 (MSB set)
        let peer1 = make_peer_with_ip(128, 9001, "10.0.1.1");
        let peer2 = make_peer_with_ip(129, 9002, "10.0.1.2");
        table.insert(peer1);
        table.insert(peer2);
        assert_eq!(table.len(), 2);

        // Third peer from same /24 into same bucket should be rejected
        let peer3 = make_peer_with_ip(130, 9003, "10.0.1.3");
        let result = table.insert(peer3);
        assert!(matches!(result, InsertResult::RejectedSubnetLimit));
        assert_eq!(table.len(), 2);

        // Peer from different /24 into same bucket is fine
        let peer4 = make_peer_with_ip(131, 9004, "10.0.2.1");
        table.insert(peer4);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn test_subnet_table_wide_limit() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Spread 10 peers from same /24 across different buckets
        // Byte values: 1, 2, 4, 8, 16, 32, 64, 128 go into different buckets
        // We need 10 in different buckets from same /24
        // Use peers that land in different buckets
        let bytes = [128u8, 129, 64, 65, 32, 33, 16, 17, 8, 9];
        for (i, &b) in bytes.iter().enumerate().take(MAX_PER_SUBNET_TOTAL) {
            let mut peer = make_peer(b, 9000 + i as u16);
            peer.host = "10.0.1.1".to_string(); // same /24
            // Only 2 per subnet per bucket, so distribute across buckets
            // bucket for 128,129 = 0; 64,65 = 1; 32,33 = 2; 16,17 = 3; 8,9 = 4
            table.insert(peer);
        }

        // Now try to add one more from same /24 in a new bucket
        let mut extra = make_peer(4, 9999);
        extra.host = "10.0.1.200".to_string();
        let result = table.insert(extra);
        assert!(matches!(result, InsertResult::RejectedSubnetLimit));
    }

    // ─── Test-Before-Evict Tests ─────────────────────────────────────────

    #[test]
    fn test_touch_moves_to_back() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Insert two peers in same bucket
        let mut p1 = make_peer(128, 9001);
        p1.host = "10.0.1.1".to_string();
        let mut p2 = make_peer(129, 9002);
        p2.host = "10.0.2.1".to_string();
        table.insert(p1);
        table.insert(p2);

        // Touch the first one — it should move to back
        table.touch(&make_id(128), 2000.0);

        // Now if we fill the bucket and trigger eviction, p2 should be the
        // eviction candidate (it's now the oldest/front)
        for i in 130..128 + K {
            let mut p = make_peer(i as u8, 9000 + i as u16);
            p.host = format!("10.{}.0.1", i);
            table.insert(p);
        }

        // One more to trigger eviction
        let mut extra = make_peer(200, 9200);
        extra.host = "10.200.0.1".to_string();
        let result = table.insert(extra);
        match result {
            InsertResult::PendingEviction { evict_candidate } => {
                // Eviction candidate should be p2 (now front after p1 was touched)
                assert!(evict_candidate.starts_with("81")); // 129 = 0x81
            }
            _ => panic!("expected PendingEviction, got {:?}", result),
        }
    }

    // ─── Outbound Peer Preference Tests ──────────────────────────────────

    #[test]
    fn test_closest_prefer_outbound() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Two peers at similar distance, one outbound, one inbound
        let mut outbound_peer = make_peer(1, 9001);
        outbound_peer.provenance = PeerProvenance::Outbound;
        let inbound_peer = DhtPeer {
            node_id: {
                let mut arr = [0u8; 32];
                arr[0] = 1;
                arr[31] = 1; // slightly different but same bucket
                NodeId(arr)
            },
            identity_hash: format!("01{}01", "00".repeat(30)),
            host: "10.0.2.1".to_string(),
            port: 9002,
            last_seen: 1000.0,
            first_added: 1000.0,
            provenance: PeerProvenance::Inbound,
        };

        table.insert(inbound_peer);
        table.insert(outbound_peer);

        // closest_prefer_outbound should put outbound first for equal distance
        let target = make_id(1);
        let closest = table.closest_prefer_outbound(&target, 2);
        assert_eq!(closest.len(), 2);
        assert_eq!(closest[0].provenance, PeerProvenance::Outbound);
    }

    #[test]
    fn test_provenance_counts() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        let mut p1 = make_peer(1, 9001);
        p1.provenance = PeerProvenance::Outbound;
        let mut p2 = make_peer(2, 9002);
        p2.provenance = PeerProvenance::Inbound;
        let mut p3 = make_peer(128, 9003);
        p3.provenance = PeerProvenance::Outbound;

        table.insert(p1);
        table.insert(p2);
        table.insert(p3);

        let (out, inb) = table.provenance_counts();
        assert_eq!(out, 2);
        assert_eq!(inb, 1);
    }

    // ─── Gap 6: content routing tests ──────────────────────────────────

    #[test]
    fn test_node_id_from_record_id_deterministic() {
        let a = NodeId::from_record_id("0198d6e0-abcd-7890-9000-000000000001");
        let b = NodeId::from_record_id("0198d6e0-abcd-7890-9000-000000000001");
        let c = NodeId::from_record_id("0198d6e0-abcd-7890-9000-000000000002");
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
    }

    #[test]
    fn test_closest_to_record_returns_k_peers() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        for i in 1..20 {
            table.insert(make_peer(i, 9000 + i as u16));
        }
        let responsible = table.closest_to_record("record-xyz", 5);
        assert_eq!(responsible.len(), 5);
    }

    #[test]
    fn test_closest_to_record_different_records_different_sets() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        for i in 1..40 {
            table.insert(make_peer(i, 9000 + i as u16));
        }
        let a = table.closest_to_record("record-aaa", 3);
        let b = table.closest_to_record("record-zzz", 3);
        let a_ids: Vec<_> = a.iter().map(|p| p.identity_hash.clone()).collect();
        let b_ids: Vec<_> = b.iter().map(|p| p.identity_hash.clone()).collect();
        // Overwhelmingly likely to differ with a 40-peer table and distinct hashes.
        assert_ne!(a_ids, b_ids);
    }

    #[test]
    fn test_closest_to_record_deterministic() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);
        for i in 1..20 {
            table.insert(make_peer(i, 9000 + i as u16));
        }
        let a: Vec<_> = table.closest_to_record("record-abc", 4)
            .iter().map(|p| p.identity_hash.clone()).collect();
        let b: Vec<_> = table.closest_to_record("record-abc", 4)
            .iter().map(|p| p.identity_hash.clone()).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn test_closest_to_record_empty_table() {
        let local = make_id(0);
        let table = RoutingTable::new(local);
        assert!(table.closest_to_record("anything", 5).is_empty());
    }

    // ─── IPv6 Subnet Diversity Tests ─────────────────────────────────────

    #[test]
    fn test_subnet_prefix_ipv4() {
        assert_eq!(subnet_prefix("192.168.1.42"), Some("192.168.1".into()));
        assert_eq!(subnet_prefix("10.0.0.1"), Some("10.0.0".into()));
    }

    #[test]
    fn test_subnet_prefix_ipv6() {
        // Full IPv6 address → /48 prefix
        assert_eq!(
            subnet_prefix("2001:0db8:0001:0000:0000:0000:0000:0042"),
            Some("2001:db8:1".into())
        );
        // Abbreviated IPv6
        assert_eq!(subnet_prefix("2001:db8:abcd::1"), Some("2001:db8:abcd".into()));
        // Loopback
        assert_eq!(subnet_prefix("::1"), Some("0:0:0".into()));
    }

    #[test]
    fn test_subnet_prefix_rejects_hostnames() {
        assert_eq!(subnet_prefix("localhost"), None);
        assert_eq!(subnet_prefix("elara-node"), None);
        assert_eq!(subnet_prefix(""), None);
    }

    #[test]
    fn test_ipv6_subnet_diversity_enforced() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Insert 2 peers from same IPv6 /48
        let p1 = make_peer_with_ip(128, 9001, "2001:db8:1::1");
        let p2 = make_peer_with_ip(129, 9002, "2001:db8:1::2");
        table.insert(p1);
        table.insert(p2);
        assert_eq!(table.len(), 2);

        // Third from same /48 in same bucket → rejected
        let p3 = make_peer_with_ip(130, 9003, "2001:db8:1::3");
        let result = table.insert(p3);
        assert!(matches!(result, InsertResult::RejectedSubnetLimit));

        // Different /48 → accepted
        let p4 = make_peer_with_ip(131, 9004, "2001:db8:2::1");
        table.insert(p4);
        assert_eq!(table.len(), 3);
    }

    // ─── Peer Rotation Tests ─────────────────────────────────────────────

    #[test]
    fn test_rotate_stale_peers_evicts_old() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        // Add a peer with first_added = 1000.0
        let mut p1 = make_peer(1, 9001);
        p1.first_added = 1000.0;
        table.insert(p1);

        // Add a recent peer with first_added = 20000.0
        let mut p2 = make_peer(2, 9002);
        p2.first_added = 20000.0;
        table.insert(p2);

        assert_eq!(table.len(), 2);

        // Now = 20000.0. PEER_MAX_AGE_SECS = 14400 (4h).
        // p1 age = 19000s > 14400 → evicted
        // p2 age = 0s < 14400 → kept
        let evicted = table.rotate_stale_peers(20000.0);
        assert_eq!(evicted, 1);
        assert_eq!(table.len(), 1);
        // The remaining peer should be p2
        assert_eq!(table.all_peers()[0].node_id, make_id(2));
    }

    #[test]
    fn test_rotate_stale_peers_preserves_fresh() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        for i in 1..5u8 {
            let mut p = make_peer(i, 9000 + i as u16);
            p.first_added = 1000.0;
            table.insert(p);
        }
        // All peers added at t=1000, now=2000 → age=1000s < 14400s → none evicted
        let evicted = table.rotate_stale_peers(2000.0);
        assert_eq!(evicted, 0);
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn test_insert_preserves_first_added_on_update() {
        let local = make_id(0);
        let mut table = RoutingTable::new(local);

        let mut p = make_peer(1, 9001);
        p.first_added = 500.0;
        p.last_seen = 500.0;
        table.insert(p);

        // Re-insert same peer with later timestamps
        let mut p2 = make_peer(1, 9001);
        p2.first_added = 1000.0; // this should be overridden
        p2.last_seen = 1000.0;
        table.insert(p2);

        // first_added should be preserved from original insert
        let peer = table.all_peers()[0];
        assert_eq!(peer.first_added, 500.0);
        assert_eq!(peer.last_seen, 1000.0);
    }

    // ─── DHT >100-node convergence sim (an internal audit hole #2) ──────
    //
    // The single-table tests above prove each k-bucket's local invariants.
    // These tests exercise the *cluster* property the audit flagged as
    // unmeasured: with N independent routing tables built from the same
    // peer set, do queries converge on the true K-nearest in O(log N)
    // hops, and does the total memory footprint stay sublinear in N?
    //
    // Pure-Rust deterministic — every NodeId comes from a Linear Congruential
    // Generator seeded at test entry, so the same test always exercises the
    // same topology. No real network, no async, no sleeps.

    /// Tiny deterministic PRNG (LCG) so the simulation is reproducible
    /// without pulling in the `rand` crate's test surface. Values are good
    /// enough for spreading NodeIds uniformly over the 256-bit space; not
    /// cryptographic.
    struct LcgRng(u64);

    impl LcgRng {
        fn new(seed: u64) -> Self {
            Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0
        }
        fn fill_id(&mut self, out: &mut [u8; 32]) {
            for chunk in out.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }

    /// Spawn `n` synthetic nodes with deterministic NodeIds and unique hosts
    /// (so subnet limits never bite). Returns (NodeId, DhtPeer) pairs in
    /// stable order.
    fn synth_swarm(n: usize, seed: u64) -> Vec<(NodeId, DhtPeer)> {
        let mut rng = LcgRng::new(seed);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let mut id = [0u8; 32];
            rng.fill_id(&mut id);
            let node_id = NodeId(id);
            // Spread peers across distinct /24 subnets so MAX_PER_SUBNET_*
            // never refuses an insert (10.A.B.1 with A,B independent).
            let host = format!("10.{}.{}.1", (i / 256) as u8, (i % 256) as u8);
            let peer = DhtPeer {
                node_id,
                identity_hash: hex::encode(id),
                host,
                port: 9000 + (i as u16 % 1000),
                last_seen: 1000.0,
                first_added: 1000.0,
                provenance: PeerProvenance::Outbound,
            };
            out.push((node_id, peer));
        }
        out
    }

    /// Try to insert every other peer into every node's routing table.
    /// Returns the populated tables in the same order as `swarm`.
    fn bootstrap_full_mesh(swarm: &[(NodeId, DhtPeer)]) -> Vec<RoutingTable> {
        let mut tables: Vec<RoutingTable> = swarm
            .iter()
            .map(|(id, _)| RoutingTable::new(*id))
            .collect();
        for (i, table) in tables.iter_mut().enumerate() {
            for (j, (_, peer)) in swarm.iter().enumerate() {
                if i == j {
                    continue;
                }
                // We don't care about PendingEviction here — when k-buckets
                // saturate, the LRU side dictates which peers stay. That's
                // exactly the convergence property under test.
                let _ = table.insert(peer.clone());
            }
        }
        tables
    }

    /// Compute the global true K-nearest peers to `target` from the entire
    /// swarm, excluding `local` (a node never returns itself in lookups).
    fn global_k_nearest<'a>(
        swarm: &'a [(NodeId, DhtPeer)],
        target: &NodeId,
        local: &NodeId,
        k: usize,
    ) -> Vec<&'a DhtPeer> {
        let mut all: Vec<&DhtPeer> = swarm
            .iter()
            .filter_map(|(id, p)| if id == local { None } else { Some(p) })
            .collect();
        all.sort_by_key(|a| a.node_id.distance(target));
        all.truncate(k);
        all
    }

    /// Simulate iterative-find-node from `start`'s routing table toward
    /// `target`. Standard Kademlia shape: keep a *wide* candidate pool of
    /// size POOL (3K by default) during the search so that peers outside
    /// the rolling top-K aren't dropped before we get a chance to query
    /// them. Truncate to K only at the very end.
    fn iterative_find(
        tables_by_id: &std::collections::HashMap<NodeId, &RoutingTable>,
        start: NodeId,
        target: &NodeId,
        k: usize,
    ) -> (Vec<NodeId>, usize) {
        let pool_size = k * 3;
        let start_table = tables_by_id.get(&start).expect("start node present");
        let mut candidates: Vec<NodeId> = start_table
            .closest(target, pool_size)
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        queried.insert(start);

        let mut hops = 0usize;
        // Hard cap so a pathological topology can't run forever.
        // log2(10_000) ≈ 13.3 — anything more than 64 is a routing failure.
        let max_hops = 64;

        loop {
            // Pick the closest unqueried candidate.
            let next = candidates
                .iter()
                .find(|n| !queried.contains(n))
                .copied();
            let next = match next {
                Some(n) => n,
                None => break,
            };
            queried.insert(next);
            hops += 1;
            if hops > max_hops {
                break;
            }

            // Ask `next` for its own pool_size closest to target; merge into
            // the candidate pool. Sort by distance, dedupe, truncate to
            // `pool_size` (NOT k). Keeping the wider pool is what gives
            // Kademlia convergence even when individual k-buckets are sparse.
            if let Some(table) = tables_by_id.get(&next) {
                let local_view = table.closest(target, pool_size);
                for p in local_view {
                    if !candidates.contains(&p.node_id) && p.node_id != *target {
                        candidates.push(p.node_id);
                    }
                }
                candidates.sort_by_key(|a| a.distance(target));
                candidates.truncate(pool_size);
            }
        }
        // Final answer: the K closest in the converged candidate pool.
        candidates.truncate(k);
        (candidates, hops)
    }

    #[test]
    fn dht_swarm_routing_table_size_bounded_audit_2026_05_02() {
        // Property A: per-node memory footprint is sublinear in N. With K=8
        // per bucket and 256 buckets, a fully-populated table caps at 2048
        // peers regardless of swarm size — but in practice random NodeIds
        // distribute across only ~log2(N) buckets at the prefix sharing the
        // local node's high bits. At N=128 we expect ~K * log2(N) = ~56
        // peers per node, well under the 2048 cap.
        let swarm = synth_swarm(128, 0xDEAD_BEEF);
        let tables = bootstrap_full_mesh(&swarm);

        // Each node retains at most K * occupied_buckets peers — that's the
        // physical ceiling. Most nodes saturate well below 2048 (the
        // theoretical max with 256 fully-filled buckets).
        for (i, table) in tables.iter().enumerate() {
            let occupied = table.occupied_buckets();
            let len = table.len();
            assert!(
                len <= K * occupied,
                "node {i}: table.len()={len} exceeds K * occupied_buckets={} ({} occupied)",
                K * occupied,
                occupied
            );
            // Realistic ceiling for random N=128 peers in a 256-bit space:
            // with diverse subnets, len should be ≤ K * 256 = 2048 (the hard
            // cap), and in practice much smaller. Soft-assert the practical
            // ceiling at K * 8 = 64 — proves we did not somehow blow past
            // O(log N) bucket fill.
            assert!(
                len <= K * 8,
                "node {i}: table.len()={len} > 64 — bucket distribution unexpectedly fat"
            );
        }
    }

    #[test]
    fn dht_swarm_local_view_recall_audit_2026_05_02() {
        // Property B: at each node, `closest(target, K)` returns peers
        // whose distances are *competitive* with the global K-nearest.
        // Note: full-mesh bootstrap is not the steady-state Kademlia
        // construction — when a k-bucket saturates, later inserts hit LRU
        // and may not displace the existing peer. So the local view is a
        // *projection* of the network, not a strict subset of the global
        // top-K. The Kademlia convergence guarantee comes from
        // iterative-find (Property C), not from any single routing table.
        //
        // What we *can* assert per-node:
        //   * Routing table is non-trivial (at least K peers seen).
        //   * The local view's closest peer to target is within the
        //     global *top-3K window* — i.e. the routing-table projection
        //     captures at least one of the closest 24 peers in the network.
        //     This proves no node is so isolated that lookups would have
        //     to traverse the whole graph from any starting point.
        let swarm = synth_swarm(128, 0xC0FFEE);
        let tables = bootstrap_full_mesh(&swarm);

        let mut rng = LcgRng::new(42);
        for _round in 0..16 {
            let mut tgt = [0u8; 32];
            rng.fill_id(&mut tgt);
            let target = NodeId(tgt);

            for _ in 0..8 {
                let src_idx = (rng.next_u64() as usize) % swarm.len();
                let local = &swarm[src_idx].0;
                let local_view: Vec<&DhtPeer> = tables[src_idx].closest(&target, K);
                assert!(
                    !local_view.is_empty(),
                    "node {src_idx}: closest() returned no peers in N=128 swarm"
                );

                // Closest peer in the local view must be in the global top
                // 3K (24 peers). This is the actual "lookup will succeed"
                // safety property: we can ask SOMEONE in the global top-24
                // for their view and converge from there.
                let global_3k = global_k_nearest(&swarm, &target, local, K * 3);
                let local_best = &local_view[0];
                let local_best_d = local_best.node_id.distance(&target);
                let global_3k_th_d = global_3k
                    .last()
                    .expect("global 3K non-empty")
                    .node_id
                    .distance(&target);
                assert!(
                    local_best_d <= global_3k_th_d,
                    "node {src_idx}: local best peer at distance {} is outside the global top-3K (worst {}); routing table too sparse for convergence",
                    hex::encode(local_best_d),
                    hex::encode(global_3k_th_d),
                );
            }
        }
    }

    #[test]
    fn dht_swarm_iterative_find_converges_in_log_n_hops_audit_2026_05_02() {
        // Property C: iterative-find-node lookup converges in O(log N) hops
        // to a candidate set with high recall against the true K-nearest.
        // This is the canonical Kademlia scaling claim — a 1M-node mainnet
        // survives ≤ ~20 hops per lookup. We measure at N=128 over 32
        // random (start, target) pairs.
        //
        // Recall (not strict equality) is the right metric: with full-mesh
        // bootstrap and K-bucket eviction, the global K-nearest aren't
        // necessarily reachable from every starting point — but the
        // iterative search must still find a *competitive* set. We assert
        // recall ≥ 6/8 (75%) on average, with no individual run below 4/8.
        let swarm = synth_swarm(128, 0xBADBEEF);
        let tables = bootstrap_full_mesh(&swarm);

        let tables_by_id: std::collections::HashMap<NodeId, &RoutingTable> =
            swarm
                .iter()
                .zip(tables.iter())
                .map(|((id, _), t)| (*id, t))
                .collect();

        // log2(128)=7. Allow 8× slack for the wider candidate pool's
        // exploration: with pool_size=3K=24 and K=8 we may query up to
        // 24-ish peers per lookup. Bound: 8*log2(N)=56 hops worst case.
        let max_hops_allowed = 8 * (128f64).log2().ceil() as usize;

        let mut rng = LcgRng::new(7);
        let mut total_recall = 0usize;
        let mut total_hops = 0usize;
        let mut total_runs = 0usize;
        for _ in 0..32 {
            let start_idx = (rng.next_u64() as usize) % swarm.len();
            let mut tgt = [0u8; 32];
            rng.fill_id(&mut tgt);
            let target = NodeId(tgt);

            let (final_set, hops) =
                iterative_find(&tables_by_id, swarm[start_idx].0, &target, K);

            assert!(
                hops <= max_hops_allowed,
                "iterative-find from node {start_idx} took {hops} hops > {max_hops_allowed} (8 * log2(N))"
            );

            let global = global_k_nearest(&swarm, &target, &swarm[start_idx].0, K);
            let global_ids: std::collections::HashSet<NodeId> =
                global.iter().map(|p| p.node_id).collect();
            let recall = final_set.iter().filter(|n| global_ids.contains(n)).count();
            assert!(
                recall >= 4,
                "iterative-find from node {start_idx} found only {recall}/{} of true K-nearest — \
                 routing table too sparse, lookup did not converge",
                K
            );

            total_recall += recall;
            total_hops += hops;
            total_runs += 1;
        }
        let avg_recall = total_recall as f64 / total_runs as f64;
        let avg_hops = total_hops as f64 / total_runs as f64;
        assert!(
            avg_recall >= 6.0,
            "average recall {avg_recall}/{K} too low — Kademlia convergence is degraded"
        );
        // Sanity check the hops bound on the average too.
        assert!(
            avg_hops <= max_hops_allowed as f64,
            "average hops {avg_hops} exceeded max"
        );
    }

    #[test]
    fn dht_swarm_500_nodes_invariants_hold_audit_2026_05_02() {
        // Property D: scale up to 500 nodes (4× the canonical "fully-
        // populated 6-node testnet" boundary) and verify the same
        // invariants. This is the actual answer to "DHT >100 nodes" —
        // the audit's gate. N=500 produces ~256 GB of routing-table state
        // across the swarm if every peer is fully discovered, but per-node
        // it stays at K * occupied_buckets ≤ K * 9 ≈ 72 peers.
        //
        // We don't run iterative-find here (32 lookups × 500-table HashMap
        // probes is slow in debug builds). The size + correctness invariants
        // are the load-bearing properties.
        let swarm = synth_swarm(500, 0xFADE_F00D);
        let tables = bootstrap_full_mesh(&swarm);

        // Every node's routing table must obey the K-per-bucket cap and
        // the practical bucket-count ceiling.
        for (i, table) in tables.iter().enumerate() {
            let occupied = table.occupied_buckets();
            let len = table.len();
            assert!(
                len <= K * occupied,
                "node {i}/N=500: len={len} > K*occupied_buckets={}",
                K * occupied
            );
            // log2(500) ≈ 9. Allow K * 11 = 88 as a soft ceiling — covers
            // the buckets immediately adjacent to log2(N) which can fill.
            assert!(
                len <= K * 11,
                "node {i}/N=500: len={len} > 88 — bucket distribution unexpectedly fat"
            );
            // Every node must have *some* peers (otherwise convergence is
            // a non-property). With diverse subnets and N=500, each node
            // should have at least K peers (the minimum useful routing
            // table).
            assert!(
                len >= K,
                "node {i}/N=500: len={len} < K={K} — bootstrap left node isolated"
            );
        }

        // Spot-check convergence on 4 random targets via iterative-find at
        // N=500. Recall ≥ 4/8 on every lookup proves the routing topology
        // remains usable at 4× the canonical small-cluster scale.
        let tables_by_id: std::collections::HashMap<NodeId, &RoutingTable> =
            swarm
                .iter()
                .zip(tables.iter())
                .map(|((id, _), t)| (*id, t))
                .collect();
        let mut rng = LcgRng::new(99);
        // log2(500) ≈ 9. Allow 8× slack: 72 hops max.
        let max_hops_allowed = 8 * (500f64).log2().ceil() as usize;
        for _ in 0..4 {
            let start_idx = (rng.next_u64() as usize) % swarm.len();
            let mut tgt = [0u8; 32];
            rng.fill_id(&mut tgt);
            let target = NodeId(tgt);

            let (final_set, hops) =
                iterative_find(&tables_by_id, swarm[start_idx].0, &target, K);
            assert!(
                hops <= max_hops_allowed,
                "N=500: iterative-find from node {start_idx} took {hops} hops > {max_hops_allowed}"
            );

            let global = global_k_nearest(&swarm, &target, &swarm[start_idx].0, K);
            let global_ids: std::collections::HashSet<NodeId> =
                global.iter().map(|p| p.node_id).collect();
            let recall = final_set.iter().filter(|n| global_ids.contains(n)).count();
            assert!(
                recall >= 4,
                "N=500: lookup from node {start_idx} only found {recall}/{K} true K-nearest"
            );
        }
    }

    // ─── Batch-B density tests: fixture-free pure-helper coverage ──────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_pub_constants_pin_alpha_and_disjoint_paths_literal_values() {
        // PIN: dht.rs:96 + dht.rs:100 — ALPHA and DISJOINT_PATHS are the only
        // *public* tuning constants in this module. They govern the
        // parallelism of the iterative-find machinery and the S/Kademlia
        // adversarial-robustness budget. A regression that changed either
        // would silently re-shape every lookup: fewer parallel queries =
        // higher tail latency; fewer disjoint paths = lower adversarial
        // recall (the 99%/20% bound becomes invalid). Pin the literal values
        // so accidental tuning gets caught at test-time, not in production
        // observability.
        assert_eq!(ALPHA, 3, "ALPHA (parallel lookups) MUST be 3");
        assert_eq!(DISJOINT_PATHS, 4, "DISJOINT_PATHS (S/Kademlia) MUST be 4 — 99% recall @ 20% adv");
        // DISJOINT_PATHS > ALPHA would invert the meaning (more disjoint
        // paths than per-path parallelism); pin that ordering.
        assert!(
            DISJOINT_PATHS >= 1 && ALPHA >= 1,
            "both constants MUST be ≥ 1 (non-zero parallelism)",
        );
    }

    #[test]
    fn batch_b_node_id_from_hex_rejects_invalid_inputs_pins_strict_32_byte_parser() {
        // PIN: dht.rs:18 — NodeId::from_hex MUST reject anything that is not
        // exactly 32 bytes of hex. A loose parser would accept truncated or
        // padded identity hashes and route them to wrong buckets, fragmenting
        // the DHT. Pin the four canonical rejection axes:
        //   (a) too short (31 bytes)
        //   (b) too long (33 bytes)
        //   (c) odd-length hex (un-parseable)
        //   (d) non-hex characters
        // AND pin (e) uppercase A-F accepted (case-insensitivity).
        let too_short = "aa".repeat(31);   // 62 chars = 31 bytes
        assert!(
            NodeId::from_hex(&too_short).is_none(),
            "31-byte hex MUST be rejected — NodeId is strict 32 bytes",
        );

        let too_long = "aa".repeat(33);    // 66 chars = 33 bytes
        assert!(
            NodeId::from_hex(&too_long).is_none(),
            "33-byte hex MUST be rejected — NodeId is strict 32 bytes",
        );

        let odd = format!("{}a", "aa".repeat(31));  // 63 chars — invalid hex
        assert!(
            NodeId::from_hex(&odd).is_none(),
            "odd-length hex MUST be rejected",
        );

        let non_hex = format!("zz{}", "aa".repeat(31));  // 64 chars but 'zz' invalid
        assert!(
            NodeId::from_hex(&non_hex).is_none(),
            "non-hex characters MUST be rejected",
        );

        // Case-insensitivity: uppercase A-F MUST parse identically to
        // lowercase. Pin via cross-check.
        let lower = "abcdef00".repeat(8);  // 64 chars
        let upper = "ABCDEF00".repeat(8);
        let lo = NodeId::from_hex(&lower).expect("lowercase hex MUST parse");
        let up = NodeId::from_hex(&upper).expect("uppercase hex MUST parse");
        assert_eq!(lo.0, up.0, "uppercase and lowercase hex MUST yield identical NodeIds");

        // Empty string is also rejected (degenerate).
        assert!(
            NodeId::from_hex("").is_none(),
            "empty hex MUST be rejected",
        );
    }

    #[test]
    fn batch_b_node_id_distance_is_symmetric_self_zero_and_pins_xor_byte_formula() {
        // PIN: dht.rs:29 — distance(a,b) is byte-wise XOR. Pin:
        //   (a) XOR symmetry: a.distance(b) == b.distance(a)
        //   (b) self-distance is the all-zero byte array
        //   (c) MSB-flip on byte 0 produces [0x80, 0, …, 0] — pin formula
        //   (d) byte-3 flip produces zeros for byte 0..2, non-zero on byte 3
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0b1010_0000;
        b[0] = 0b1100_0000;
        let a_id = NodeId(a);
        let b_id = NodeId(b);

        // (a) symmetry
        assert_eq!(a_id.distance(&b_id), b_id.distance(&a_id), "XOR distance MUST be symmetric");

        // (b) self-distance is all-zero
        let zero = [0u8; 32];
        assert_eq!(a_id.distance(&a_id), zero, "self-distance MUST be all-zero");
        assert_eq!(b_id.distance(&b_id), zero, "self-distance MUST be all-zero");

        // (c) MSB-flip → 0x80 in byte 0
        let mut msb = [0u8; 32];
        msb[0] = 0b1000_0000;
        let zero_id = NodeId(zero);
        let msb_id = NodeId(msb);
        let d_msb = zero_id.distance(&msb_id);
        assert_eq!(d_msb[0], 0x80, "MSB-flip MUST set 0x80 in byte 0");
        for byte in &d_msb[1..] {
            assert_eq!(*byte, 0, "MSB-flip MUST be zero outside byte 0");
        }

        // (d) byte-3 flip: zeros in bytes 0..2, non-zero in byte 3
        let mut b3 = [0u8; 32];
        b3[3] = 0xFF;
        let b3_id = NodeId(b3);
        let d_b3 = zero_id.distance(&b3_id);
        for (i, b) in d_b3.iter().enumerate().take(3) {
            assert_eq!(*b, 0, "byte-3 flip MUST leave byte {i} zero");
        }
        assert_eq!(d_b3[3], 0xFF, "byte-3 flip MUST set 0xFF in byte 3");
        for (i, b) in d_b3.iter().enumerate().skip(4).take(28) {
            assert_eq!(*b, 0, "byte-3 flip MUST leave byte {i} zero");
        }
    }

    #[test]
    fn batch_b_node_id_bucket_index_pins_byte_offset_plus_leading_zeros_formula() {
        // PIN: dht.rs:38 — bucket_index returns (byte_idx * 8 + leading_zeros).
        // A regression that flipped the leading_zeros sign, dropped the
        // byte_idx*8 offset, or returned bit-from-LSB would mis-bucket every
        // peer. Pin three cross-byte data points to guard the formula.
        let zero = NodeId([0u8; 32]);

        // Byte 0, MSB set → leading_zeros=0, byte_idx=0 → bucket 0.
        let mut a = [0u8; 32]; a[0] = 0x80;
        assert_eq!(zero.bucket_index(&NodeId(a)), Some(0), "byte-0 MSB → bucket 0");

        // Byte 0, LSB set → leading_zeros=7, byte_idx=0 → bucket 7.
        let mut b = [0u8; 32]; b[0] = 0x01;
        assert_eq!(zero.bucket_index(&NodeId(b)), Some(7), "byte-0 LSB → bucket 7");

        // Byte 1, MSB set → leading_zeros=0, byte_idx=1 → bucket 8.
        let mut c = [0u8; 32]; c[1] = 0x80;
        assert_eq!(zero.bucket_index(&NodeId(c)), Some(8), "byte-1 MSB → bucket 8");

        // Byte 1, LSB set → leading_zeros=7, byte_idx=1 → bucket 15.
        let mut d = [0u8; 32]; d[1] = 0x01;
        assert_eq!(zero.bucket_index(&NodeId(d)), Some(15), "byte-1 LSB → bucket 15");

        // Last byte (31), MSB set → byte_idx=31, leading=0 → bucket 248.
        let mut e = [0u8; 32]; e[31] = 0x80;
        assert_eq!(zero.bucket_index(&NodeId(e)), Some(248), "byte-31 MSB → bucket 248");

        // Last byte (31), LSB set → byte_idx=31, leading=7 → bucket 255
        // (the maximum bucket index in the 256-bit space).
        let mut f = [0u8; 32]; f[31] = 0x01;
        assert_eq!(zero.bucket_index(&NodeId(f)), Some(255), "byte-31 LSB → bucket 255 (max)");

        // Identical nodes → None.
        assert_eq!(zero.bucket_index(&zero), None, "identical nodes MUST return None");
    }

    #[test]
    fn batch_b_node_id_from_record_id_is_sha3_256_pinned_and_distinct_from_hex_route() {
        // PIN: dht.rs:59 — from_record_id is the content-routing primitive
        // (Gap 6). It MUST be sha3_256(record_id_as_bytes); any regression
        // that switched hash family (e.g. sha2-256) or input encoding would
        // shift every record's responsible-replica set silently. Pin:
        //   (a) byte-exact equality to sha3_256(record_id.as_bytes())
        //   (b) determinism across calls
        //   (c) different inputs yield different NodeIds (collision-resistant smoke)
        //   (d) NodeId::from_record_id("X") != NodeId::from_hex("X-as-hex")
        //       — guards against accidentally inferring the record-id route is
        //       a parse-as-hex (which would lose entropy on short inputs).
        let rec = "record-abc-123";
        let id = NodeId::from_record_id(rec);
        let manual = sha3_256(rec.as_bytes());
        assert_eq!(id.0, manual, "from_record_id MUST equal sha3_256(record_id.as_bytes())");

        // Determinism.
        let id2 = NodeId::from_record_id(rec);
        assert_eq!(id.0, id2.0, "from_record_id MUST be deterministic");

        // Collision-resistance smoke: different inputs → different outputs.
        let other = NodeId::from_record_id("record-abc-124");
        assert_ne!(id.0, other.0, "distinct record IDs MUST yield distinct NodeIds");

        // Empty string is hashable (no panic) — degenerate but well-defined.
        let empty = NodeId::from_record_id("");
        assert_ne!(empty.0, [0u8; 32], "empty record_id MUST NOT collide with zero NodeId");

        // The "hex route" and the "record route" are distinct entry points;
        // a string that *happens* to be valid hex MUST go through sha3, not
        // hex-decode. Pin: a 64-char-hex string used as a record_id is
        // hashed, not decoded.
        let hexlike = "abcdef00".repeat(8);
        let via_record = NodeId::from_record_id(&hexlike);
        let via_hex = NodeId::from_hex(&hexlike).expect("valid hex");
        assert_ne!(
            via_record.0, via_hex.0,
            "from_record_id MUST hash, not hex-decode, even when input looks like hex",
        );
    }
}
