//! Peer types — identity, state, and peer table management.

//!
//! Spec references:
//!   @spec Protocol §11.14
//!   @spec Protocol §11.28

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::identity::Identity;

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// True for a well-formed peer identity hash: exactly 64 LOWERCASE hex chars.
///
/// The single trust-boundary guard for identities arriving from untrusted peers
/// — an mDNS `identity` TXT property or a remote `/status` `identity_hash` field,
/// both arbitrary attacker-controlled strings. Discovery code byte-slices these
/// for logs (`&identity_hash[..16]`); without this check a short value (e.g. the
/// `"unknown"` default) or a multi-byte-UTF-8 value panics the discovery loop and
/// lets garbage identities into the peer table + DHT. 64 ASCII bytes == 64 chars,
/// so any slice up to index 64 lands on a char boundary.
///
/// Lowercase-only is the canonicalization gate: every honest identity in the
/// system originates as `hex::encode(sha3(..))`, which emits lowercase. An
/// uppercase variant on the wire is adversarial-only, and admitting it would
/// alias one node under case-variant keys in the string-keyed peer table / DHT
/// (dedup, eviction, and ban lookups all treat "AB.." and "ab.." as distinct).
/// HTTP read-path boundaries (`routes/token.rs`, `routes/explorer`) stay
/// mixed-case-tolerant — a non-canonical lookup just misses; no state is keyed.
pub(crate) fn is_valid_peer_identity(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Per-peer ring-buffer capacity for recent bad-sig record IDs.
/// 16 is enough to spot-check several distinct records on other peers
/// during a forensic triage session, and at 64 bytes/UUID-string × 16
/// entries × 100 peers = ~100 KB worst case — bounded.
pub const BAD_SIG_SAMPLE_CAP: usize = 16;

/// Node type in the network (Protocol v0.6.2).
///
/// 6 roles defining what a node can and cannot do:
/// - **Leaf**: creates records, cannot relay/witness/seal
/// - **Relay**: forwards records between peers, cannot witness/seal
/// - **Witness**: attests records, can relay, cannot seal
/// - **Archive**: high-capacity storage node, can relay, stores full history
/// - **Anchor**: epoch seal authority, publishes trust headers, can witness
/// - **Gateway**: Profile C delegation proxy for constrained devices (IoT)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Create records only. Cannot relay, witness, or seal.
    Leaf,
    /// Forward records between peers. Cannot witness or seal.
    Relay,
    /// Attest records. Can relay. Cannot seal epochs.
    Witness,
    /// High-capacity storage. Can relay. Stores full DAG history.
    Archive,
    /// Epoch seal authority. Can witness. Publishes trust headers.
    Anchor,
    /// Profile C delegation proxy for constrained IoT devices.
    Gateway,
}

#[allow(clippy::should_implement_trait)]
impl NodeType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "relay" => Self::Relay,
            "witness" => Self::Witness,
            "archive" => Self::Archive,
            "anchor" => Self::Anchor,
            "gateway" => Self::Gateway,
            _ => Self::Leaf,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Relay => "relay",
            Self::Witness => "witness",
            Self::Archive => "archive",
            Self::Anchor => "anchor",
            Self::Gateway => "gateway",
        }
    }

    /// Can this node type relay (forward) records to peers?
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::Relay | Self::Witness | Self::Archive | Self::Anchor | Self::Gateway)
    }

    /// Can this node type witness (attest) records?
    pub fn can_witness(&self) -> bool {
        matches!(self, Self::Witness | Self::Anchor)
    }

    /// Can this node type seal epochs?
    pub fn can_seal_epochs(&self) -> bool {
        matches!(self, Self::Anchor)
    }

    /// Is this a storage-heavy node type?
    pub fn is_archival(&self) -> bool {
        matches!(self, Self::Archive | Self::Anchor)
    }

    /// Can this node type create delegation records for constrained devices?
    pub fn can_delegate(&self) -> bool {
        matches!(self, Self::Gateway | Self::Anchor)
    }

    /// All valid node type strings.
    pub fn all_names() -> &'static [&'static str] {
        &["leaf", "relay", "witness", "archive", "anchor", "gateway"]
    }
}

/// Connection state of a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum PeerState {
    #[default]
    Connected,
    Stale,
    /// Peer sent a signed going-offline notification — clean voluntary departure.
    /// Not counted as a failure; no backoff. Will be re-promoted to Connected on
    /// next successful heartbeat/gossip exchange.
    Offline,
}


/// How a peer was discovered — outbound (we found them) vs inbound (they found us).
/// Outbound peers are preferred for routing decisions because inbound connections
/// are easier for attackers to fake (eclipse attack vector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerProvenance {
    /// We discovered this peer via bootstrap, DHT lookup, or PEX.
    #[default]
    Outbound,
    /// This peer connected to us (inbound connection).
    Inbound,
}

/// Information about a known peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub identity_hash: String,
    pub host: String,
    pub port: u16,
    pub node_type: NodeType,
    pub last_seen: f64,
    #[serde(skip)]
    pub state: PeerState,
    #[serde(skip, default)]
    pub failures: u32,
    /// Successful gossip exchanges with this peer.
    #[serde(skip, default)]
    pub successes: u32,
    /// Records received from this peer that passed validation.
    #[serde(skip, default)]
    pub valid_records: u64,
    /// Records received from this peer that failed validation.
    #[serde(skip, default)]
    pub invalid_records: u64,
    /// Timestamp until which this peer is in exponential backoff (skip for gossip).
    /// Set after consecutive failures. Reset on success.
    #[serde(skip, default)]
    pub backoff_until: f64,
    /// PoW nonce for identity anti-Sybil verification.
    #[serde(default)]
    pub pow_nonce: u64,
    /// PoW difficulty (leading zero bits in SHA3-256(pk || nonce)).
    #[serde(default)]
    pub pow_difficulty: u8,
    /// Hex-encoded public key for PoW verification.
    /// Empty if not yet exchanged (pre-PoW peers).
    #[serde(default)]
    pub public_key_hex: String,
    /// How this peer was discovered (outbound = we found them, inbound = they found us).
    /// Outbound peers are preferred for routing to resist eclipse attacks.
    #[serde(default)]
    pub provenance: PeerProvenance,
    /// Zones this peer is subscribed to (for zone-scoped gossip filtering).
    /// Empty = accepts all zones (backward compat / testnet).
    #[serde(default)]
    pub subscribed_zones: Vec<String>,
    /// Per-peer attestation watermark: last timestamp successfully pulled.
    /// Pull uses `since=watermark` to avoid re-fetching known attestations.
    /// Persisted across restarts via peers.json.
    #[serde(default)]
    pub att_watermark: f64,
    /// Consecutive pull failures (connection timeout / unreachable).
    /// Separate from `failures` to avoid penalizing NAT'd peers' reputation.
    #[serde(skip, default)]
    pub pull_failures: u32,
    /// Timestamp until which pulls to this peer are skipped.
    /// Uses same exponential backoff tiers as `backoff_until`.
    #[serde(skip, default)]
    pub pull_backoff_until: f64,
    /// Whether this peer is directly reachable (not behind NAT).
    /// false = NAT'd — don't try to push to or pull from this peer.
    /// Set from peer's self-reported `x-elara-reachable` header, or
    /// auto-detected after consecutive pull failures.
    /// Skipped in serialization: stale unreachability from a previous instance's
    /// transient failures must not persist across restarts. The peer's header
    /// or fresh pull attempts will re-establish the correct state.
    #[serde(skip, default = "default_reachable")]
    pub reachable: bool,
    /// Protocol version reported by this peer (0 = unknown/pre-versioning).
    #[serde(default)]
    pub protocol_version: u32,
    /// Per-peer cumulative attestations rejected by the
    /// `attestation_pull_loop` because Dilithium3 sig-verify failed against
    /// THIS peer's batch. Complements global `attestation_pull_invalid_sig_total`.
    /// Lets operators identify the storm source: `top(rate())` over peers gives
    /// "which neighbour is sending us bad-sig attestations". Steady non-zero on
    /// a single peer = (a) we have stale records vs that peer, or (b) that peer
    /// is forging — cross-correlate with `peer_persistent_divergence_total`.
    /// Skipped in serialization: this is a per-process operational metric, not
    /// durable state; restart resets so rates are interpretable as "since up".
    #[serde(skip, default)]
    pub att_pull_invalid_sig: u64,
    /// Per-peer cumulative attestations rejected by the
    /// `attestation_pull_loop` because PoWaS proof-of-work failed against THIS
    /// peer's batch. Complements global `attestation_pull_invalid_powas_total`.
    /// Distinct from sig-fail: PoWaS-fail does NOT advance pull watermark, so a
    /// mis-issuing peer can stall progress on a record indefinitely. Sustained
    /// non-zero on one peer = peer running stale binary or witness key/stake
    /// mismatch — operator action is to ban/upgrade that peer specifically.
    #[serde(skip, default)]
    pub att_pull_invalid_powas: u64,
    /// Per-peer cumulative attestations PUSH-deferred by
    /// the Tier 4.6 low-stake gate (`MIN_WITNESS_STAKE = 100 beat`). Bumps in
    /// the PQ `receive_attestation` handler when the peer forwards an
    /// attestation whose witness's stake row hasn't synced to this node yet.
    /// Push-side counterpart to `att_pull_invalid_*` (which surface pull-side
    /// rejections). Operationally the most actionable bootstrap-pathology
    /// attribution: when one peer dominates this counter and the global
    /// `low_stake_drained_total` stays at 0, that peer is forwarding for a
    /// witness whose stake gossip is stuck on this node — pick a DIFFERENT
    /// peer for snapshot rebootstrap. HTTP path is
    /// account-originated, not peer-forwarded, so no HTTP attribution is
    /// recorded here. Skipped in serialization: per-process operational
    /// metric only, resets on restart for interpretable "since up" rates.
    #[serde(skip, default)]
    pub att_push_low_stake_deferred: u64,
    /// Bounded ring buffer of the most recent record
    /// IDs that triggered an `att_pull_invalid_sig` rejection from this
    /// peer. Capacity = `BAD_SIG_SAMPLE_CAP`. The counter alone tells you
    /// "a peer has 500 invalid sigs"; the sample tells you *which records*,
    /// so an operator can spot-check the same record IDs on other peers
    /// to triangulate whether that peer has actually-bad
    /// content (Byzantine forwarder, stale snapshot) or whether the
    /// rejecting node's verification is wrong (wire-format drift, missing
    /// PK row, content_hash mismatch). Skipped in serialization: forensic
    /// signal only, resets on restart.
    #[serde(skip, default)]
    pub recent_bad_sig_record_ids: std::collections::VecDeque<String>,
}

fn default_reachable() -> bool { true }

/// Backoff duration tiers based on consecutive failures.
/// 0-1: no backoff, 2: 30s, 3: 60s, 4: 300s, 5+: 1800s cap.
const BACKOFF_TIERS: &[(u32, f64)] = &[
    (2, 30.0),
    (3, 60.0),
    (4, 300.0),
    (5, 1800.0),
];

impl PeerInfo {
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// Check if this peer wants records for a given zone.
    /// Empty subscribed_zones = accepts all zones (backward compat).
    pub fn wants_zone(&self, zone: &str) -> bool {
        self.subscribed_zones.is_empty()
            || self.subscribed_zones.iter().any(|z| zone.starts_with(z.as_str()) || z.starts_with(zone))
    }

    /// Reputation score (0.0-1.0) based on success/failure ratio.
    /// Returns 1.0 if no interactions yet.
    pub fn reputation(&self) -> f64 {
        let total = self.successes as f64 + self.failures as f64;
        if total == 0.0 {
            return 1.0;
        }
        self.successes as f64 / total
    }

    /// Whether this peer is in exponential backoff at the given timestamp.
    pub fn in_backoff(&self, now: f64) -> bool {
        self.backoff_until > now
    }

    /// Compute backoff duration based on consecutive failure count.
    pub fn backoff_duration(&self) -> f64 {
        for &(threshold, duration) in BACKOFF_TIERS.iter().rev() {
            if self.failures >= threshold {
                return duration;
            }
        }
        0.0
    }

    /// Whether pulls to this peer should be skipped (unreachable, behind NAT).
    pub fn in_pull_backoff(&self, now: f64) -> bool {
        self.pull_backoff_until > now
    }

    /// Compute pull backoff duration from pull failure count.
    fn pull_backoff_duration(&self) -> f64 {
        for &(threshold, duration) in BACKOFF_TIERS.iter().rev() {
            if self.pull_failures >= threshold {
                return duration;
            }
        }
        0.0
    }
}

/// Maximum number of peers in the table. When exceeded, the peer with the
/// oldest `last_seen` timestamp is evicted to make room.
pub const MAX_PEERS: usize = 500;

/// Ban expiry time in seconds. Bans are temporary to prevent permanent
/// isolation from transient network failures.
const BAN_TTL_SECS: f64 = 600.0; // 10 minutes

/// In-memory peer table with ban list and PoW enforcement.
pub struct PeerTable {
    peers: HashMap<String, PeerInfo>,
    /// Banned peers: identity_hash → (ban_timestamp, ban_count). TTL escalates with count.
    banned: HashMap<String, (f64, u32)>,
    /// Historical ban counts — persists across ban/unban cycles so escalation works.
    ban_history: HashMap<String, u32>,
    /// Seed peer identity hashes — these are NEVER banned.
    seed_peers: std::collections::HashSet<String>,
    /// Minimum PoW difficulty required to join. 0 = no requirement.
    min_pow_difficulty: u8,
    /// Local node's identity hash — insert() silently rejects this to prevent
    /// NAT loopback self-gossip. Empty string = no filter (tests).
    local_identity_hash: String,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            banned: HashMap::new(),
            ban_history: HashMap::new(),
            seed_peers: std::collections::HashSet::new(),
            min_pow_difficulty: 0,
            local_identity_hash: String::new(),
        }
    }

    /// Create with a minimum PoW difficulty requirement.
    pub fn with_min_pow(min_difficulty: u8) -> Self {
        Self {
            peers: HashMap::new(),
            banned: HashMap::new(),
            ban_history: HashMap::new(),
            seed_peers: std::collections::HashSet::new(),
            min_pow_difficulty: min_difficulty,
            local_identity_hash: String::new(),
        }
    }

    /// Set the local node's identity hash. Insert() will silently reject peers
    /// matching this hash, preventing NAT loopback self-gossip at the table level.
    pub fn set_local_identity(&mut self, hash: &str) {
        self.local_identity_hash = hash.to_string();
    }

    /// Register a seed peer identity — seed peers are never banned.
    pub fn add_seed_peer(&mut self, identity_hash: &str) {
        self.seed_peers.insert(identity_hash.to_string());
        // Un-ban if already banned
        self.banned.remove(identity_hash);
    }

    /// Whether `identity_hash` is a configured seed peer (operator-trusted).
    /// Used by the gossip-push trust gate (B6): a seed's handshake-authenticated
    /// push is rate-exempt; a stranger's is not.
    pub fn is_seed_peer(&self, identity_hash: &str) -> bool {
        self.seed_peers.contains(identity_hash)
    }

    /// Insert a peer. Rejects banned peers (unless ban expired) and peers failing PoW verification.
    /// Seed peers are never rejected due to bans. Self is always rejected.
    /// Returns `true` if the peer was actually inserted or updated.
    pub fn insert(&mut self, peer: PeerInfo) -> bool {
        // Never insert self — prevents NAT loopback pull-from-self
        if !self.local_identity_hash.is_empty() && peer.identity_hash == self.local_identity_hash {
            return false;
        }
        // Seed peers bypass ban check entirely
        if !self.seed_peers.contains(&peer.identity_hash) {
            if let Some(&(ban_time, count)) = self.banned.get(&peer.identity_hash) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                if now - ban_time < Self::ban_ttl(count) {
                    return false; // ban still active
                }
                // Ban expired — remove active ban but preserve count in history
                self.ban_history.insert(peer.identity_hash.clone(), count);
                self.banned.remove(&peer.identity_hash);
                info!("ban expired for peer {} (ban count: {}), allowing reconnection",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)], count);
            }
        }

        // PoW enforcement: reject peers below the minimum difficulty.
        // Seed peers are operator-trusted and bypass PoW (matches the ban bypass above).
        if self.min_pow_difficulty > 0 && !self.seed_peers.contains(&peer.identity_hash) {
            if peer.pow_difficulty < self.min_pow_difficulty {
                warn!(
                    "rejecting peer {} — PoW difficulty {} < minimum {}",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                    peer.pow_difficulty,
                    self.min_pow_difficulty,
                );
                return false;
            }
            // B5/F1: an empty public_key_hex can no longer skip PoW verification.
            // The pre-B5 verify was guarded by `if !public_key_hex.is_empty()`, so a
            // peer self-reporting pow_difficulty>=min with NO key was admitted with
            // zero work (PoW is live: min_pow_difficulty=16 on the authority). Empty
            // key under live PoW is now a hard reject.
            if peer.public_key_hex.is_empty() {
                warn!(
                    "rejecting peer {} — empty public_key_hex under PoW",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                );
                return false;
            }
            let Ok(pk_bytes) = hex::decode(&peer.public_key_hex) else {
                warn!(
                    "rejecting peer {} — invalid public_key_hex",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                );
                return false;
            };
            // B5/F1: verify the peer did AT LEAST our required work — bind the check
            // to OUR minimum, not the peer's self-reported (untrusted) difficulty.
            if !Identity::verify_pow_static(&pk_bytes, peer.pow_nonce, self.min_pow_difficulty) {
                warn!(
                    "rejecting peer {} — invalid PoW proof",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                );
                return false;
            }
        }

        // B5/F2: bind the advertised identity_hash to the public key. UNCONDITIONAL
        // integrity invariant (independent of PoW): identity_hash IS
        // sha3_256_hex(dilithium_pk) by construction (identity.rs). Enforcing it stops
        // one PoW solution from minting unlimited identities AND blocks impersonation
        // (advertising a victim's hash with another key). Skipped only when no key is
        // present (PoW-off testnets with key-less peers) — nothing to bind.
        if !peer.public_key_hex.is_empty() {
            let Ok(pk_bytes) = hex::decode(&peer.public_key_hex) else {
                warn!(
                    "rejecting peer {} — undecodable public_key_hex",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                );
                return false;
            };
            if pk_bytes.len() != crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN {
                warn!(
                    "rejecting peer {} — pubkey length {} != Dilithium3 {}",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                    pk_bytes.len(),
                    crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN,
                );
                return false;
            }
            // sha3_256_hex is lowercase; the peer's identity_hash arrives over
            // untrusted JSON and may be mixed-case — compare case-insensitively so an
            // honest peer is never falsely rejected.
            let derived = crate::crypto::hash::sha3_256_hex(&pk_bytes);
            if !derived.eq_ignore_ascii_case(&peer.identity_hash) {
                warn!(
                    "rejecting peer {} — identity_hash does not match sha3(public_key)",
                    &peer.identity_hash[..peer.identity_hash.len().min(16)],
                );
                return false;
            }
        }

        // B5/F3a: tiered eviction at capacity. Never evict seeds. Prefer evicting
        // Offline, then Stale, then Connected. A Connected non-seed is displaced ONLY
        // by a strictly-fresher incoming peer — without that escape valve a full table
        // of Connected peers would permanently reject every newcomer (all peers enter
        // Stale, and Stale->Connected promotion requires already being in the table),
        // deadlocking discovery. Single O(N) pass over the table (N ≤ MAX_PEERS).
        //
        // SCOPE (B5 audit): this strictly-improves pre-B5 eviction (which evicted the
        // global oldest unconditionally, seeds included) by protecting seeds and
        // tiering by liveness. The "strictly-fresher" Connected guard resists floods
        // that REPLAY old last_seen values, but NOT a flood of freshly-discovered
        // peers: discovery stamps last_seen=now() locally (parse_peer_list), so a
        // newcomer always out-freshes an incumbent and CAN displace the oldest
        // Connected non-seed one slot at a time. Full Connected-incumbent
        // eclipse-resistance (don't let an unverified Stale newcomer displace a
        // verified Connected peer; global-rate + /24-ASN admission diversity) is
        // DEFERRED to before-untrusted-PEX, tracked with F3b's structural fix.
        // Dormant today: pex_interval_secs=0 (PEX off) + Tailscale seed topology.
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer.identity_hash) {
            let mut oldest_offline: Option<(&String, f64)> = None;
            let mut oldest_stale: Option<(&String, f64)> = None;
            let mut oldest_connected: Option<(&String, f64)> = None;
            for (k, v) in self.peers.iter() {
                if self.seed_peers.contains(k) {
                    continue; // seeds are never evicted
                }
                let slot = match v.state {
                    PeerState::Offline => &mut oldest_offline,
                    PeerState::Stale => &mut oldest_stale,
                    PeerState::Connected => &mut oldest_connected,
                };
                match slot {
                    Some((_, ls)) if v.last_seen >= *ls => {}
                    _ => *slot = Some((k, v.last_seen)),
                }
            }
            let victim: Option<String> = if let Some((k, _)) = oldest_offline {
                Some(k.clone())
            } else if let Some((k, _)) = oldest_stale {
                Some(k.clone())
            } else if let Some((k, vls)) = oldest_connected {
                // Only displace a Connected peer if the incoming is strictly fresher.
                if peer.last_seen > vls {
                    Some(k.clone())
                } else {
                    None
                }
            } else {
                None // table is all seeds — reject incoming rather than overflow
            };
            match victim {
                Some(vk) => {
                    warn!(
                        "peer table full ({MAX_PEERS}), evicting {} (tiered offline>stale>connected)",
                        &vk[..vk.len().min(16)],
                    );
                    self.peers.remove(&vk);
                }
                None => {
                    warn!(
                        "peer table full ({MAX_PEERS}), no evictable candidate — rejecting incoming {}",
                        &peer.identity_hash[..peer.identity_hash.len().min(16)],
                    );
                    return false;
                }
            }
        }

        self.peers.insert(peer.identity_hash.clone(), peer);
        true
    }

    /// Test-only: insert a peer directly into the table, bypassing ALL admission
    /// validation (PoW, B5/F2 identity-binding, B5/F3a eviction). Simulates a table
    /// entry that arrived via some path other than `insert()` — used to exercise
    /// downstream handlers' defense-in-depth guards against corrupt/legacy entries.
    /// This is NOT a production path: post-B5 `insert()` is the sole admission route
    /// and unconditionally rejects identity-unbound or undecodable-pk peers.
    #[cfg(test)]
    pub(crate) fn insert_unchecked(&mut self, peer: PeerInfo) {
        self.peers.insert(peer.identity_hash.clone(), peer);
    }

    /// Ban a peer temporarily. Removes from active table and prevents re-insertion
    /// for BAN_TTL_SECS. Seed peers are never banned — they get reset instead.
    pub fn ban(&mut self, identity_hash: &str) {
        if self.seed_peers.contains(identity_hash) {
            // Seed peers: just reset their failure count instead of banning
            if let Some(peer) = self.peers.get_mut(identity_hash) {
                peer.failures = 0;
                peer.state = PeerState::Stale;
            }
            warn!("refusing to ban seed peer {}, resetting failures instead",
                &identity_hash[..identity_hash.len().min(16)]);
            return;
        }
        self.peers.remove(identity_hash);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        // Escalating ban: 10min → 20min → 40min → 60min cap
        // Use ban_history to preserve count across ban/unban cycles
        let prev_count = self.banned.get(identity_hash).map(|&(_, c)| c)
            .or_else(|| self.ban_history.get(identity_hash).copied())
            .unwrap_or(0);
        let new_count = prev_count + 1;
        self.ban_history.insert(identity_hash.to_string(), new_count);
        self.banned.insert(identity_hash.to_string(), (now, new_count));
    }

    /// Compute adaptive ban TTL: 10min, 20min, 40min, 60min cap.
    fn ban_ttl(count: u32) -> f64 {
        (BAN_TTL_SECS * 2.0_f64.powi(count.saturating_sub(1).min(3) as i32)).min(3600.0)
    }

    /// Check if a peer is currently banned (within adaptive TTL).
    pub fn is_banned(&self, identity_hash: &str) -> bool {
        if let Some(&(ban_time, count)) = self.banned.get(identity_hash) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            now - ban_time < Self::ban_ttl(count)
        } else {
            false
        }
    }

    /// Number of currently active bans.
    pub fn banned_count(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        self.banned.iter().filter(|(_, &(t, c))| now - t < Self::ban_ttl(c)).count()
    }

    pub fn get(&self, identity_hash: &str) -> Option<&PeerInfo> {
        self.peers.get(identity_hash)
    }

    pub fn connected(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .collect()
    }

    pub fn all(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }

    /// Check if any peer has the given IP address.
    /// O(n) scan but no allocation — used by rate limiter on every request
    /// instead of `all().iter().any()` which allocates a Vec first.
    pub fn has_peer_ip(&self, ip: std::net::IpAddr) -> bool {
        self.peers.values().any(|p| p.host.parse::<std::net::IpAddr>().ok() == Some(ip))
    }

    pub fn mark_connected(&mut self, identity_hash: &str, ts: f64) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.state = PeerState::Connected;
            peer.last_seen = ts;
            peer.failures = 0;
            peer.backoff_until = 0.0;
        }
    }

    /// Update peer's reachability flag based on a self-report or proven dial.
    ///
    /// `reachable` semantics: can WE dial THEM (outbound from our side)? A peer
    /// behind a port-restricted NAT can push records to us (their outbound
    /// works) but we can't connect to them (no port forward). Such peers
    /// self-report `x-elara-reachable: 0` and the heartbeat dial loop in
    /// `discovery.rs` skips them — preventing failures-driven ban (Tier 1.1
    /// follow-up: "Don't register implicit peers from NAT'd connections").
    ///
    /// Update sources:
    /// - `false` from peer's `x-elara-reachable: 0` header on push: they
    ///   self-declare NAT. Trust immediately — we'd waste budget retrying.
    /// - `true` from peer's `x-elara-reachable: 1` header on push: they
    ///   *think* they're reachable. Trust speculatively; if they're wrong,
    ///   the next 5 pull failures will re-mark them unreachable
    ///   (`record_pull_failure` line 611).
    /// - `true` from a successful heartbeat dial (`discovery.rs`): proven
    ///   reachable. Cancels any prior `false` mark.
    ///
    /// No-op if the peer isn't in the table.
    pub fn update_reachability(&mut self, identity_hash: &str, reachable: bool) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.reachable = reachable;
        }
    }

    /// Mark a peer as voluntarily going offline (clean shutdown signal).
    /// Does NOT increment failures or set backoff — no reputation penalty.
    /// The peer will be re-promoted to Connected on the next successful exchange.
    pub fn mark_offline(&mut self, identity_hash: &str) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.state = PeerState::Offline;
        }
    }

    pub fn record_failure(&mut self, identity_hash: &str) {
        self.record_failure_at(identity_hash, now());
    }

    /// Record a failure with an explicit timestamp (for testing).
    pub fn record_failure_at(&mut self, identity_hash: &str, timestamp: f64) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.failures += 1;
            if peer.failures >= 3 {
                peer.state = PeerState::Stale;
            }
            let backoff = peer.backoff_duration();
            if backoff > 0.0 {
                peer.backoff_until = timestamp + backoff;
            }
        }
    }

    /// Count of peers currently in exponential backoff.
    pub fn in_backoff_count(&self) -> usize {
        let now = now();
        self.peers.values().filter(|p| p.in_backoff(now)).count()
    }

    /// Get connected peers excluding those in backoff.
    pub fn connected_active(&self) -> Vec<&PeerInfo> {
        let now = now();
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected && !p.in_backoff(now))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Remove a peer by identity hash. Returns the removed peer if present.
    pub fn remove(&mut self, identity_hash: &str) -> Option<PeerInfo> {
        self.peers.remove(identity_hash)
    }

    /// Return identity hashes of peers with `failures >= max_failures`.
    pub fn stale_above(&self, max_failures: u32) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, p)| p.failures >= max_failures)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Save connected peers to a JSON file for persistence across restarts.
    /// Excludes self (local_identity_hash) to prevent NAT loopback on reload.
    pub fn save(&self, path: &Path) {
        let peers_to_save: Vec<&PeerInfo> = self.peers.values()
            .filter(|p| self.local_identity_hash.is_empty() || p.identity_hash != self.local_identity_hash)
            .collect();
        match serde_json::to_string_pretty(&peers_to_save) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    warn!("failed to save peers: {e}");
                } else {
                    debug!("saved {} peers to {}", peers_to_save.len(), path.display());
                }
            }
            Err(e) => warn!("failed to serialize peers: {e}"),
        }
    }

    /// Record a successful gossip exchange with a peer.
    /// A successful exchange proves connectivity — reset failures and restore Connected state.
    pub fn record_success(&mut self, identity_hash: &str) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.successes = peer.successes.saturating_add(1);
            peer.state = PeerState::Connected;
            peer.failures = 0;
            peer.backoff_until = 0.0;
            peer.last_seen = now();
            // Any successful HTTP exchange proves reachability.
            if !peer.reachable {
                peer.reachable = true;
                peer.pull_failures = 0;
                peer.pull_backoff_until = 0.0;
                info!("peer {} reachable again after successful exchange",
                    &identity_hash[..identity_hash.len().min(16)]);
            }
        }
    }

    /// Record a pull failure (connection timeout / unreachable).
    /// Separate from `record_failure` — does NOT penalize peer reputation or
    /// change peer state. NAT'd peers are healthy but unreachable for pulls.
    pub fn record_pull_failure(&mut self, identity_hash: &str) {
        let ts = now();
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.pull_failures += 1;
            let dur = peer.pull_backoff_duration();
            if dur > 0.0 {
                peer.pull_backoff_until = ts + dur;
            }
            // Auto-detect NAT: after 5 consecutive pull failures, mark peer
            // as unreachable. A single success resets this (record_pull_success).
            if peer.pull_failures >= 5 && peer.reachable {
                peer.reachable = false;
                info!("peer {} auto-marked unreachable after {} consecutive pull failures",
                    &identity_hash[..identity_hash.len().min(16)], peer.pull_failures);
            }
        }
    }

    /// Record a successful pull (reset pull backoff).
    pub fn record_pull_success(&mut self, identity_hash: &str) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            // Restore reachability if it was auto-disabled by pull failures.
            if !peer.reachable && peer.pull_failures > 0 {
                peer.reachable = true;
                info!("peer {} reachable again after successful pull",
                    &identity_hash[..identity_hash.len().min(16)]);
            }
            peer.pull_failures = 0;
            peer.pull_backoff_until = 0.0;
        }
    }

    /// Record a valid record received from a peer.
    pub fn record_valid(&mut self, identity_hash: &str) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.valid_records = peer.valid_records.saturating_add(1);
        }
    }

    /// Record an invalid record received from a peer.
    pub fn record_invalid(&mut self, identity_hash: &str) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.invalid_records = peer.invalid_records.saturating_add(1);
        }
    }

    /// Compute reputation score for a peer (0.0 = bad, 1.0 = good).
    ///
    /// Score = (successes + valid_records) / (successes + valid_records + failures + invalid_records)
    /// Returns 0.5 (neutral) for unknown peers with no history.
    pub fn reputation(&self, identity_hash: &str) -> f64 {
        match self.peers.get(identity_hash) {
            Some(peer) => {
                let good = peer.successes as f64 + peer.valid_records as f64;
                let bad = peer.failures as f64 + peer.invalid_records as f64;
                let total = good + bad;
                if total == 0.0 {
                    0.5 // neutral
                } else {
                    good / total
                }
            }
            None => 0.5,
        }
    }

    /// Get a mutable reference to a peer by identity hash.
    pub fn get_mut(&mut self, identity_hash: &str) -> Option<&mut PeerInfo> {
        self.peers.get_mut(identity_hash)
    }

    /// Get attestation watermark for a peer (0.0 if unknown).
    pub fn att_watermark(&self, identity_hash: &str) -> f64 {
        self.peers.get(identity_hash).map_or(0.0, |p| p.att_watermark)
    }

    /// Advance attestation watermark for a peer. Only moves forward, never backward.
    pub fn advance_att_watermark(&mut self, identity_hash: &str, ts: f64) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            if ts > peer.att_watermark {
                peer.att_watermark = ts;
            }
        }
    }

    /// Bump per-peer pull-side invalid-sig counter by `n`.
    /// Called from `process_attestation_pull_batch` once at batch end (rather
    /// than per-attestation) to amortise the write-lock cost. No-op if the
    /// peer was evicted between batch start and end (a transient race that
    /// would only lose a single batch's count).
    pub fn bump_att_pull_invalid_sig(&mut self, identity_hash: &str, n: u64) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.att_pull_invalid_sig = peer.att_pull_invalid_sig.saturating_add(n);
        }
    }

    /// Bump per-peer pull-side invalid-PoWaS counter by `n`.
    /// Same amortisation pattern as `bump_att_pull_invalid_sig`.
    pub fn bump_att_pull_invalid_powas(&mut self, identity_hash: &str, n: u64) {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.att_pull_invalid_powas = peer.att_pull_invalid_powas.saturating_add(n);
        }
    }

    /// Bump per-peer push-side low-stake-deferred counter by `n`.
    /// Called from the PQ `receive_attestation` handler once per deferred
    /// attestation (push path is single-record, not batched, so no amortisation
    /// gain to defer the bump).
    ///
    /// Returns `true` if the peer was found and bumped, `false` otherwise.
    /// Callers use the `false` path to bump the global
    /// `att_push_unattributed_total` counter so attribution-gap signal is
    /// not silently dropped — a cold-restart race or a peer that
    /// PQ-handshakes but never gets into the table both look identical to
    /// the per-peer gauge ("zero growth"), which is misleading.
    pub fn bump_att_push_low_stake_deferred(&mut self, identity_hash: &str, n: u64) -> bool {
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            peer.att_push_low_stake_deferred =
                peer.att_push_low_stake_deferred.saturating_add(n);
            true
        } else {
            false
        }
    }

    /// Append record IDs that just got rejected for bad sig from
    /// `identity_hash` into the per-peer ring buffer, capping at
    /// `BAD_SIG_SAMPLE_CAP`. Oldest entries fall off when the buffer is
    /// full. Idempotent: passing an empty `ids` is a no-op. No-op if the
    /// peer was evicted between batch start and end (same race tolerance
    /// as the counter bumps).
    pub fn push_bad_sig_record_ids(&mut self, identity_hash: &str, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        if let Some(peer) = self.peers.get_mut(identity_hash) {
            for id in ids {
                if peer.recent_bad_sig_record_ids.len() >= BAD_SIG_SAMPLE_CAP {
                    peer.recent_bad_sig_record_ids.pop_front();
                }
                peer.recent_bad_sig_record_ids.push_back(id);
            }
        }
    }

    /// Load peers from a JSON file. All loaded peers start as Stale (re-verified on heartbeat).
    pub fn load(path: &Path) -> Self {
        let mut table = Self::new();
        if !path.exists() {
            return table;
        }
        match std::fs::read_to_string(path) {
            Ok(json) => {
                match serde_json::from_str::<Vec<PeerInfo>>(&json) {
                    Ok(peers) => {
                        let mut dropped = 0usize;
                        for mut peer in peers {
                            // The reload path bypasses the wire/mDNS ingest guards. Drop any
                            // persisted peer whose host is not LAN-dialable (a pre-guard
                            // hostname, or a mapped/NAT64 reserved literal) so the heartbeat
                            // verify-dial can't be turned into an SSRF.
                            if !crate::network::mdns::persisted_host_is_dialable_lan(&peer.host) {
                                dropped += 1;
                                continue;
                            }
                            peer.state = PeerState::Stale;
                            peer.failures = 0;
                            peer.pull_failures = 0;
                            peer.pull_backoff_until = 0.0;
                            table.peers.insert(peer.identity_hash.clone(), peer);
                        }
                        if dropped > 0 {
                            warn!("dropped {dropped} persisted peer(s) with undialable host from {}", path.display());
                        }
                        debug!("loaded {} peers from {}", table.len(), path.display());
                    }
                    Err(e) => warn!("failed to parse peers file: {e}"),
                }
            }
            Err(e) => warn!("failed to read peers file: {e}"),
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_peer_identity_accepts_canonical_64_hex() {
        assert!(is_valid_peer_identity(&"a".repeat(64)));
        assert!(is_valid_peer_identity(&"0123456789abcdef".repeat(4)));
        // Uppercase is REJECTED: hex::encode only ever emits lowercase, so an
        // uppercase identity on the wire is adversarial-only — admitting it
        // would alias one node under case-variant keys in the string-keyed
        // peer table / DHT (dedup, eviction, ban lookups).
        assert!(!is_valid_peer_identity(&"ABCDEF0123456789".repeat(4)));
        assert!(!is_valid_peer_identity(&format!("A{}", "a".repeat(63))));
    }

    #[test]
    fn valid_peer_identity_rejects_panic_triggering_inputs() {
        // Exactly the untrusted mDNS-TXT / remote-/status values that panicked
        // `&identity_hash[..16]` before the trust-boundary guard.
        assert!(!is_valid_peer_identity(""), "empty");
        assert!(!is_valid_peer_identity("unknown"), "the discovery .unwrap_or default (7 chars)");
        assert!(!is_valid_peer_identity("ab"), "shorter than the [..16] slice");
        assert!(!is_valid_peer_identity(&"a".repeat(15)), "just under 16 bytes");
        assert!(!is_valid_peer_identity(&"a".repeat(63)), "63 chars");
        assert!(!is_valid_peer_identity(&"a".repeat(65)), "65 chars");
        assert!(!is_valid_peer_identity(&"g".repeat(64)), "right length, non-hex");
        // 64 BYTES but a trailing multi-byte char → fewer than 64 chars and byte
        // index 16/63 can fall mid-codepoint; the `.len().min(16)` form does NOT
        // cover this, `is_ascii_hexdigit` does.
        let exactly_64_bytes_multibyte = format!("{}{}", "a".repeat(61), "日"); // 61 + 3 = 64 bytes
        assert_eq!(exactly_64_bytes_multibyte.len(), 64);
        assert!(
            !is_valid_peer_identity(&exactly_64_bytes_multibyte),
            "64 bytes but not 64 ascii-hex chars"
        );
    }

    fn make_peer(id: &str, failures: u32) -> PeerInfo {
        PeerInfo {
            identity_hash: id.to_string(),
            host: "127.0.0.1".to_string(),
            port: 9473,
            node_type: NodeType::Leaf,
            last_seen: 1000.0,
            state: PeerState::Connected,
            failures,
            successes: 0,
            valid_records: 0,
            invalid_records: 0,
            backoff_until: 0.0,
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: String::new(),
            provenance: PeerProvenance::Outbound,
            subscribed_zones: Vec::new(),
            att_watermark: 0.0,
            pull_failures: 0,
            pull_backoff_until: 0.0,
            reachable: true,
            protocol_version: 0,
            att_pull_invalid_sig: 0,
            att_pull_invalid_powas: 0,
            att_push_low_stake_deferred: 0,
            recent_bad_sig_record_ids: std::collections::VecDeque::new(),
        }
    }

    #[test]
    fn test_remove_peer() {
        let mut table = PeerTable::new();
        table.insert(make_peer("aaa", 0));
        table.insert(make_peer("bbb", 0));
        assert_eq!(table.len(), 2);

        let removed = table.remove("aaa");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().identity_hash, "aaa");
        assert_eq!(table.len(), 1);

        // Remove non-existent
        assert!(table.remove("zzz").is_none());
    }

    /// Tier 1.1 NAT detection: `update_reachability` is the recovery hook
    /// that routes/core.rs calls when a peer pushes records with their
    /// `x-elara-reachable` self-report header. Without this, NAT'd peers
    /// stay marked unreachable forever even when their NAT situation
    /// changes; alternatively, peers proven reachable by heartbeat dial
    /// success have no way back from `reachable=false`.
    #[test]
    fn update_reachability_toggles_flag() {
        let mut table = PeerTable::new();
        table.insert(make_peer("nat-peer", 0));
        assert!(table.get("nat-peer").unwrap().reachable, "default reachable=true");

        // Peer self-reports NAT.
        table.update_reachability("nat-peer", false);
        assert!(!table.get("nat-peer").unwrap().reachable);

        // Peer's NAT situation changes — they self-report reachable on next push.
        table.update_reachability("nat-peer", true);
        assert!(table.get("nat-peer").unwrap().reachable);
    }

    #[test]
    fn update_reachability_unknown_peer_is_no_op() {
        let mut table = PeerTable::new();
        // No insert; no panic, no-op.
        table.update_reachability("ghost", false);
        table.update_reachability("ghost", true);
        assert!(table.get("ghost").is_none());
    }

    #[test]
    fn is_seed_peer_reflects_add_seed_peer() {
        // B6: the gossip-push trust gate reads is_seed_peer to grant the
        // rate-exemption to operator-configured seeds.
        let mut table = PeerTable::new();
        assert!(!table.is_seed_peer("seed-a"), "unknown id is not a seed");
        table.add_seed_peer("seed-a");
        assert!(table.is_seed_peer("seed-a"), "configured seed must read back true");
        assert!(!table.is_seed_peer("seed-b"), "a different id is still not a seed");
    }

    #[test]
    fn test_stale_above() {
        let mut table = PeerTable::new();
        table.insert(make_peer("healthy", 2));
        table.insert(make_peer("borderline", 9));
        table.insert(make_peer("dead1", 10));
        table.insert(make_peer("dead2", 15));

        let stale = table.stale_above(10);
        assert_eq!(stale.len(), 2);
        assert!(stale.contains(&"dead1".to_string()));
        assert!(stale.contains(&"dead2".to_string()));

        // Threshold 0 returns all
        let all = table.stale_above(0);
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_reputation_neutral_for_new_peer() {
        let table = PeerTable::new();
        assert_eq!(table.reputation("unknown"), 0.5);
    }

    #[test]
    fn test_reputation_neutral_for_no_history() {
        let mut table = PeerTable::new();
        table.insert(make_peer("new-peer", 0));
        assert_eq!(table.reputation("new-peer"), 0.5);
    }

    #[test]
    fn test_reputation_good_peer() {
        let mut table = PeerTable::new();
        table.insert(make_peer("good", 0));

        table.record_success("good");
        table.record_success("good");
        table.record_valid("good");
        table.record_valid("good");
        table.record_valid("good");

        // 5 good, 0 bad → 1.0
        assert!((table.reputation("good") - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_reputation_mixed_peer() {
        let mut table = PeerTable::new();
        table.insert(make_peer("mixed", 1)); // starts with 1 failure

        table.record_success("mixed");
        // record_success resets failures → failures=0, successes=1
        table.record_success("mixed");
        // successes=2, failures=0
        table.record_valid("mixed");
        table.record_invalid("mixed");

        // good: 2 + 1 = 3, bad: 0 + 1 = 1, total = 4 → 0.75
        // Failures reset on success because a successful exchange proves connectivity
        assert!((table.reputation("mixed") - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_reputation_bad_peer() {
        let mut table = PeerTable::new();
        table.insert(make_peer("bad", 5));
        table.record_invalid("bad");
        table.record_invalid("bad");

        // good: 0, bad: 5 + 2 = 7 → 0.0
        assert!(table.reputation("bad") < 0.01);
    }

    #[test]
    fn test_ban_peer() {
        let mut table = PeerTable::new();
        table.insert(make_peer("aaa", 0));
        table.insert(make_peer("bbb", 0));
        assert_eq!(table.len(), 2);

        table.ban("aaa");
        assert_eq!(table.len(), 1);
        assert!(table.is_banned("aaa"));
        assert_eq!(table.banned_count(), 1);

        // Re-inserting a banned peer is silently rejected
        table.insert(make_peer("aaa", 0));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_seed_peer_never_banned() {
        let mut table = PeerTable::new();
        table.add_seed_peer("seed1");
        table.insert(make_peer("seed1", 0));
        assert_eq!(table.len(), 1);

        // Try to ban a seed peer
        table.ban("seed1");
        // Seed peer should NOT be banned
        assert!(!table.is_banned("seed1"));
        // Peer should still be in the table
        assert!(table.get("seed1").is_some());
    }

    #[test]
    fn test_ban_ttl_expires() {
        let mut table = PeerTable::new();
        table.insert(make_peer("temp", 0));
        table.ban("temp");
        assert!(table.is_banned("temp"));

        // Manually expire the ban by backdating it
        if let Some((ban_time, _count)) = table.banned.get_mut("temp") {
            *ban_time -= super::BAN_TTL_SECS + 1.0;
        }
        assert!(!table.is_banned("temp"));

        // Should be able to re-insert after ban expires
        table.insert(make_peer("temp", 0));
        assert!(table.get("temp").is_some());
    }

    // ─── PoW Enforcement Tests ──────────────────────────────────────────

    #[test]
    fn test_pow_disabled_accepts_all() {
        let mut table = PeerTable::with_min_pow(0);
        table.insert(make_peer("no-pow", 0)); // pow_difficulty=0
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_pow_rejects_insufficient_difficulty() {
        let mut table = PeerTable::with_min_pow(16);
        let mut peer = make_peer("weak", 0);
        peer.pow_difficulty = 8; // below 16
        table.insert(peer);
        assert_eq!(table.len(), 0); // rejected
    }

    #[test]
    fn test_pow_accepts_sufficient_difficulty() {
        let mut table = PeerTable::with_min_pow(8);
        // Generate a real identity with PoW for verification
        let id = Identity::generate_with_pow(
            crate::identity::EntityType::Human,
            crate::identity::CryptoProfile::ProfileB,
            8,
        )
        .unwrap();

        let mut peer = make_peer(&id.identity_hash, 0);
        peer.pow_nonce = id.pow_nonce;
        peer.pow_difficulty = id.pow_difficulty;
        peer.public_key_hex = hex::encode(&id.public_key);

        table.insert(peer);
        assert_eq!(table.len(), 1); // accepted
    }

    #[test]
    fn test_pow_rejects_invalid_proof() {
        let mut table = PeerTable::with_min_pow(8);
        let id = Identity::generate_with_pow(
            crate::identity::EntityType::Human,
            crate::identity::CryptoProfile::ProfileB,
            8,
        )
        .unwrap();

        let mut peer = make_peer(&id.identity_hash, 0);
        // Walk forward from a random offset until we land on a nonce that
        // is *confirmed* not to satisfy difficulty=8 for this public key.
        // wrapping_add(999) alone has a 1/256 chance of accidentally being
        // another valid PoW (the original flake); loop until verify_pow_static
        // returns false to make the test deterministic.
        let mut bad_nonce = id.pow_nonce.wrapping_add(999);
        while Identity::verify_pow_static(&id.public_key, bad_nonce, 8) {
            bad_nonce = bad_nonce.wrapping_add(1);
        }
        peer.pow_nonce = bad_nonce;
        peer.pow_difficulty = id.pow_difficulty;
        peer.public_key_hex = hex::encode(&id.public_key);

        table.insert(peer);
        assert_eq!(table.len(), 0); // rejected — invalid proof
    }

    #[test]
    fn test_pow_rejects_bad_hex() {
        let mut table = PeerTable::with_min_pow(8);
        let mut peer = make_peer("bad-hex", 0);
        peer.pow_difficulty = 8;
        peer.public_key_hex = "not_valid_hex!".to_string();

        table.insert(peer);
        assert_eq!(table.len(), 0); // rejected — bad hex
    }

    // ─── B5: empty-key PoW bypass, identity binding, tiered eviction ────

    /// A peer carrying a real PoW identity (external-joiner shape).
    fn b5_valid_peer(last_seen: f64) -> (PeerInfo, Identity) {
        let id = Identity::generate_with_pow(
            crate::identity::EntityType::Human,
            crate::identity::CryptoProfile::ProfileB,
            8,
        )
        .unwrap();
        let mut p = make_peer(&id.identity_hash, 0);
        p.pow_nonce = id.pow_nonce;
        p.pow_difficulty = id.pow_difficulty;
        p.public_key_hex = hex::encode(&id.public_key);
        p.last_seen = last_seen;
        (p, id)
    }

    fn peer_state_seen(id: &str, state: PeerState, last_seen: f64) -> PeerInfo {
        let mut p = make_peer(id, 0);
        p.state = state;
        p.last_seen = last_seen;
        p
    }

    #[test]
    fn b5_empty_pubkey_rejected_under_pow() {
        // V1: pre-B5, a peer self-reporting high difficulty with NO key skipped
        // verification and was admitted with zero work. Now a hard reject.
        let mut table = PeerTable::with_min_pow(8);
        let mut peer = make_peer("attacker-empty-key", 0);
        peer.pow_difficulty = 20; // self-reported, no proof attached
        peer.public_key_hex = String::new();
        assert!(!table.insert(peer));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn b5_valid_peer_admitted_under_pow() {
        // Guards against F1/F2 over-rejecting an honest PoW joiner.
        let mut table = PeerTable::with_min_pow(8);
        let (peer, _id) = b5_valid_peer(1000.0);
        assert!(table.insert(peer));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn b5_identity_pubkey_mismatch_rejected() {
        // V2: one valid PoW solution must not be reusable to mint a different
        // identity. Real key+proof, but a forged identity_hash → rejected.
        let mut table = PeerTable::with_min_pow(8);
        let (mut peer, _id) = b5_valid_peer(1000.0);
        peer.identity_hash = "0".repeat(64);
        assert!(!table.insert(peer));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn b5_identity_binding_case_insensitive_accept() {
        // F2 must NOT false-reject an honest peer that advertised an upper-cased
        // identity_hash. Isolated with PoW off.
        let mut table = PeerTable::with_min_pow(0);
        let id = Identity::generate(
            crate::identity::EntityType::Human,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let mut peer = make_peer(&id.identity_hash.to_uppercase(), 0);
        peer.public_key_hex = hex::encode(&id.public_key);
        assert!(table.insert(peer), "uppercase identity_hash must still bind");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn b5_identity_binding_wrong_pubkey_length_rejected() {
        // F2 length guard: a short blob whose sha3 matches the claimed hash is
        // still rejected — it is not a Dilithium3 public key.
        let mut table = PeerTable::with_min_pow(0);
        let short = vec![0u8; 100];
        let hash = crate::crypto::hash::sha3_256_hex(&short);
        let mut peer = make_peer(&hash, 0);
        peer.public_key_hex = hex::encode(&short);
        assert!(!table.insert(peer));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn b5_evict_offline_before_stale_before_connected() {
        // Tier dominates recency: a NEWEST Offline peer is evicted before any
        // Stale or Connected peer.
        let mut table = PeerTable::new();
        table.insert(peer_state_seen("offline-newest", PeerState::Offline, 9999.0));
        table.insert(peer_state_seen("stale-mid", PeerState::Stale, 5000.0));
        for i in 0..(MAX_PEERS - 2) {
            table.insert(peer_state_seen(&format!("conn-{i}"), PeerState::Connected, 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);
        table.insert(peer_state_seen("new", PeerState::Connected, 10000.0));
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.get("offline-newest").is_none(), "offline evicted first");
        assert!(table.get("stale-mid").is_some(), "stale tier not yet touched");
        assert!(table.get("new").is_some());
    }

    #[test]
    fn b5_stale_newcomer_displaces_only_if_fresher() {
        // Deadlock fix (accept side): a fresher Stale newcomer CAN displace the
        // oldest Connected peer so a healthy node never ossifies.
        let mut table = PeerTable::new();
        for i in 0..MAX_PEERS {
            table.insert(peer_state_seen(&format!("conn-{i}"), PeerState::Connected, 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.insert(peer_state_seen("fresh-stale", PeerState::Stale, 9000.0)));
        assert!(table.get("conn-0").is_none(), "oldest connected displaced by fresher newcomer");
        assert!(table.get("fresh-stale").is_some());
        assert_eq!(table.len(), MAX_PEERS);
    }

    #[test]
    fn b5_stale_newcomer_rejected_when_not_fresher() {
        // Deadlock fix (reject side): a newcomer whose last_seen REPLAYS an old
        // value cannot churn out established Connected peers. NOTE (B5 audit): this
        // only resists replayed-stale floods — a flood of freshly-discovered peers
        // arrives with last_seen=now() (stamped locally by parse_peer_list) and WILL
        // out-fresh incumbents, so this guard is not, by itself, production
        // eclipse-resistance. Full Connected-incumbent protection is deferred to the
        // before-untrusted-PEX admission-diversity work (see F3a scope comment).
        let mut table = PeerTable::new();
        for i in 0..MAX_PEERS {
            table.insert(peer_state_seen(&format!("conn-{i}"), PeerState::Connected, 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);
        assert!(!table.insert(peer_state_seen("old-stale", PeerState::Stale, 1.0)));
        assert!(table.get("old-stale").is_none());
        assert!(table.get("conn-0").is_some(), "established peer survives the flood");
        assert_eq!(table.len(), MAX_PEERS);
    }

    #[test]
    fn b5_seeds_never_evicted() {
        let mut table = PeerTable::new();
        for i in 0..MAX_PEERS {
            table.insert(peer_state_seen(&format!("conn-{i}"), PeerState::Connected, 1000.0 + i as f64));
        }
        table.add_seed_peer("conn-0"); // oldest, now protected
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.insert(peer_state_seen("new", PeerState::Connected, 9000.0)));
        assert!(table.get("conn-0").is_some(), "seed never evicted");
        assert!(table.get("conn-1").is_none(), "oldest non-seed evicted instead");
        assert!(table.get("new").is_some());
    }

    #[test]
    fn b5_all_seed_table_rejects_incoming() {
        let mut table = PeerTable::new();
        for i in 0..MAX_PEERS {
            let id = format!("seed-{i}");
            table.add_seed_peer(&id);
            table.insert(peer_state_seen(&id, PeerState::Connected, 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);
        // No non-seed eviction candidate → reject the incoming, never overflow.
        assert!(!table.insert(peer_state_seen("new", PeerState::Connected, 9000.0)));
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.get("new").is_none());
    }

    // ─── Exponential Backoff Tests ────────────────────────────────────

    #[test]
    fn test_backoff_duration_tiers() {
        let mut peer = make_peer("test", 0);

        // 0 failures: no backoff
        assert_eq!(peer.backoff_duration(), 0.0);

        // 1 failure: no backoff
        peer.failures = 1;
        assert_eq!(peer.backoff_duration(), 0.0);

        // 2 failures: 30s
        peer.failures = 2;
        assert_eq!(peer.backoff_duration(), 30.0);

        // 3 failures: 60s
        peer.failures = 3;
        assert_eq!(peer.backoff_duration(), 60.0);

        // 4 failures: 300s (5 min)
        peer.failures = 4;
        assert_eq!(peer.backoff_duration(), 300.0);

        // 5 failures: 1800s (30 min) cap
        peer.failures = 5;
        assert_eq!(peer.backoff_duration(), 1800.0);

        // 100 failures: still 1800s cap
        peer.failures = 100;
        assert_eq!(peer.backoff_duration(), 1800.0);
    }

    #[test]
    fn test_in_backoff() {
        let mut peer = make_peer("test", 0);
        let now = 10000.0;

        // No backoff set
        assert!(!peer.in_backoff(now));

        // Backoff in the future
        peer.backoff_until = now + 60.0;
        assert!(peer.in_backoff(now));

        // Backoff expired
        peer.backoff_until = now - 1.0;
        assert!(!peer.in_backoff(now));
    }

    #[test]
    fn test_record_failure_sets_backoff() {
        let mut table = PeerTable::new();
        table.insert(make_peer("peer-a", 0));
        let ts = 10000.0;

        // First failure: no backoff
        table.record_failure_at("peer-a", ts);
        assert_eq!(table.get("peer-a").unwrap().failures, 1);
        assert_eq!(table.get("peer-a").unwrap().backoff_until, 0.0);

        // Second failure: 30s backoff
        table.record_failure_at("peer-a", ts + 1.0);
        assert_eq!(table.get("peer-a").unwrap().failures, 2);
        assert!((table.get("peer-a").unwrap().backoff_until - (ts + 1.0 + 30.0)).abs() < 0.01);

        // Third failure: 60s backoff
        table.record_failure_at("peer-a", ts + 100.0);
        assert_eq!(table.get("peer-a").unwrap().failures, 3);
        assert!((table.get("peer-a").unwrap().backoff_until - (ts + 100.0 + 60.0)).abs() < 0.01);
    }

    #[test]
    fn test_mark_connected_resets_backoff() {
        let mut table = PeerTable::new();
        table.insert(make_peer("peer-b", 0));
        let ts = 10000.0;

        // Accumulate failures
        for i in 0..5 {
            table.record_failure_at("peer-b", ts + i as f64);
        }
        assert_eq!(table.get("peer-b").unwrap().failures, 5);
        assert!(table.get("peer-b").unwrap().backoff_until > 0.0);

        // Success resets everything
        table.mark_connected("peer-b", ts + 100.0);
        assert_eq!(table.get("peer-b").unwrap().failures, 0);
        assert_eq!(table.get("peer-b").unwrap().backoff_until, 0.0);
    }

    #[test]
    fn test_connected_active_excludes_backoff() {
        let mut table = PeerTable::new();
        table.insert(make_peer("active", 0));
        table.insert(make_peer("backoff", 0));

        // Put one peer in backoff (far future)
        if let Some(p) = table.get_mut("backoff") {
            p.backoff_until = now() + 9999.0;
        }

        let active = table.connected_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].identity_hash, "active");
    }

    #[test]
    fn test_in_backoff_count() {
        let mut table = PeerTable::new();
        table.insert(make_peer("a", 0));
        table.insert(make_peer("b", 0));
        table.insert(make_peer("c", 0));

        assert_eq!(table.in_backoff_count(), 0);

        // Put 2 in backoff
        let future = now() + 9999.0;
        table.get_mut("a").unwrap().backoff_until = future;
        table.get_mut("c").unwrap().backoff_until = future;

        assert_eq!(table.in_backoff_count(), 2);
    }

    // ─── NodeType Capability Tests (Protocol v0.6.2) ─────────────────

    #[test]
    fn test_node_type_from_str() {
        assert_eq!(NodeType::from_str("leaf"), NodeType::Leaf);
        assert_eq!(NodeType::from_str("relay"), NodeType::Relay);
        assert_eq!(NodeType::from_str("witness"), NodeType::Witness);
        assert_eq!(NodeType::from_str("archive"), NodeType::Archive);
        assert_eq!(NodeType::from_str("anchor"), NodeType::Anchor);
        assert_eq!(NodeType::from_str("gateway"), NodeType::Gateway);
        // Unknown defaults to Leaf
        assert_eq!(NodeType::from_str("potato"), NodeType::Leaf);
        assert_eq!(NodeType::from_str(""), NodeType::Leaf);
    }

    #[test]
    fn test_node_type_as_str_roundtrip() {
        for name in NodeType::all_names() {
            let nt = NodeType::from_str(name);
            assert_eq!(nt.as_str(), *name);
        }
    }

    #[test]
    fn test_leaf_capabilities() {
        let nt = NodeType::Leaf;
        assert!(!nt.can_relay());
        assert!(!nt.can_witness());
        assert!(!nt.can_seal_epochs());
        assert!(!nt.is_archival());
        assert!(!nt.can_delegate());
    }

    #[test]
    fn test_relay_capabilities() {
        let nt = NodeType::Relay;
        assert!(nt.can_relay());
        assert!(!nt.can_witness());
        assert!(!nt.can_seal_epochs());
        assert!(!nt.is_archival());
        assert!(!nt.can_delegate());
    }

    #[test]
    fn test_witness_capabilities() {
        let nt = NodeType::Witness;
        assert!(nt.can_relay());
        assert!(nt.can_witness());
        assert!(!nt.can_seal_epochs());
        assert!(!nt.is_archival());
        assert!(!nt.can_delegate());
    }

    #[test]
    fn test_archive_capabilities() {
        let nt = NodeType::Archive;
        assert!(nt.can_relay());
        assert!(!nt.can_witness());
        assert!(!nt.can_seal_epochs());
        assert!(nt.is_archival());
        assert!(!nt.can_delegate());
    }

    #[test]
    fn test_anchor_capabilities() {
        let nt = NodeType::Anchor;
        assert!(nt.can_relay());
        assert!(nt.can_witness());
        assert!(nt.can_seal_epochs());
        assert!(nt.is_archival());
        assert!(nt.can_delegate());
    }

    #[test]
    fn test_gateway_capabilities() {
        let nt = NodeType::Gateway;
        assert!(nt.can_relay());
        assert!(!nt.can_witness());
        assert!(!nt.can_seal_epochs());
        assert!(!nt.is_archival());
        assert!(nt.can_delegate());
    }

    #[test]
    fn test_all_names_complete() {
        let names = NodeType::all_names();
        assert_eq!(names.len(), 6);
        let expected = ["leaf", "relay", "witness", "archive", "anchor", "gateway"];
        assert_eq!(names, &expected);
        // Every name round-trips through from_str → as_str
        for name in names {
            assert_eq!(NodeType::from_str(name).as_str(), *name);
        }
    }

    #[test]
    fn test_node_type_serde() {
        let nt = NodeType::Anchor;
        let json = serde_json::to_string(&nt).unwrap();
        assert_eq!(json, "\"anchor\"");
        let back: NodeType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, NodeType::Anchor);
    }

    #[test]
    fn test_node_type_copy_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(NodeType::Leaf);
        set.insert(NodeType::Witness);
        set.insert(NodeType::Leaf); // duplicate
        assert_eq!(set.len(), 2);

        // Copy
        let a = NodeType::Anchor;
        let b = a; // copy, not move
        assert_eq!(a, b);
    }

    // ─── Peer Table Size Cap Tests ──────────────────────────────────────

    fn make_peer_with_last_seen(id: &str, last_seen: f64) -> PeerInfo {
        let mut p = make_peer(id, 0);
        p.last_seen = last_seen;
        p
    }

    #[test]
    fn test_evict_oldest_when_full() {
        let mut table = PeerTable::new();

        // Fill to MAX_PEERS
        for i in 0..MAX_PEERS {
            table.insert(make_peer_with_last_seen(&format!("peer-{i}"), 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);

        // Insert one more — should evict peer-0 (oldest last_seen=1000.0)
        table.insert(make_peer_with_last_seen("new-peer", 2000.0));
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.get("peer-0").is_none(), "oldest peer should be evicted");
        assert!(table.get("new-peer").is_some(), "new peer should be present");
    }

    #[test]
    fn test_no_eviction_when_updating_existing() {
        let mut table = PeerTable::new();

        for i in 0..MAX_PEERS {
            table.insert(make_peer_with_last_seen(&format!("peer-{i}"), 1000.0 + i as f64));
        }
        assert_eq!(table.len(), MAX_PEERS);

        // Re-inserting existing peer should NOT evict anyone
        table.insert(make_peer_with_last_seen("peer-0", 9999.0));
        assert_eq!(table.len(), MAX_PEERS);
        assert!(table.get("peer-0").is_some());
        assert_eq!(table.get("peer-0").unwrap().last_seen, 9999.0);
    }

    #[test]
    fn load_drops_persisted_peers_with_undialable_host() {
        // A peers.json written before the wire-host guards (or a tampered file)
        // can carry a hostname / reserved literal. load() must drop those — the
        // heartbeat would otherwise verify-dial them = SSRF — while keeping
        // legitimate public + RFC1918 LAN peers across a reboot. The filter lives
        // in load() (the reload boundary), NOT insert(), so trusted/mDNS-prefiltered
        // inserts of LAN literals are unaffected.
        use std::io::Write;
        let mut p_public = make_peer("1111111111111111", 0);
        p_public.host = "203.0.113.7".to_string();
        let mut p_lan = make_peer("2222222222222222", 0);
        p_lan.host = "192.168.1.20".to_string();
        let mut p_hostname = make_peer("3333333333333333", 0);
        p_hostname.host = "evil.example".to_string();
        let mut p_loopback = make_peer("4444444444444444", 0);
        p_loopback.host = "127.0.0.1".to_string();
        let mut p_mapped_meta = make_peer("5555555555555555", 0);
        p_mapped_meta.host = "::ffff:169.254.169.254".to_string();

        let peers = vec![p_public, p_lan, p_hostname, p_loopback, p_mapped_meta];
        let json = serde_json::to_string(&peers).unwrap();
        let path = std::env::temp_dir()
            .join(format!("elara_peer_load_ssrf_test_{}.json", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(json.as_bytes())
            .unwrap();

        let table = PeerTable::load(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(table.len(), 2, "only the public + RFC1918 LAN peers survive reload");
        assert!(table.get("1111111111111111").is_some(), "public peer kept");
        assert!(table.get("2222222222222222").is_some(), "RFC1918 LAN peer kept");
        assert!(table.get("3333333333333333").is_none(), "persisted hostname dropped");
        assert!(table.get("4444444444444444").is_none(), "persisted loopback dropped");
        assert!(
            table.get("5555555555555555").is_none(),
            "persisted IPv4-mapped metadata dropped (the residual a parse-only check would keep)"
        );
    }

    /// Per-peer pull-invalid-sig counter starts at 0 and accumulates
    /// across calls. Bumping a non-existent peer is a no-op (transient race
    /// where a peer is evicted between batch start and end).
    #[test]
    fn ops29_bump_att_pull_invalid_sig_accumulates() {
        let mut table = PeerTable::new();
        table.insert(make_peer("hil", 0));
        assert_eq!(table.get("hil").unwrap().att_pull_invalid_sig, 0);

        table.bump_att_pull_invalid_sig("hil", 8);
        assert_eq!(table.get("hil").unwrap().att_pull_invalid_sig, 8);

        // Subsequent batch adds, no reset between calls.
        table.bump_att_pull_invalid_sig("hil", 12);
        assert_eq!(table.get("hil").unwrap().att_pull_invalid_sig, 20);

        // Unknown peer: silently no-op, no panic, no insert.
        table.bump_att_pull_invalid_sig("ghost", 100);
        assert!(table.get("ghost").is_none());
    }

    /// PoWaS counter is independent from sig counter. The two
    /// reject-paths have different operator meanings (sig=permanent,
    /// PoWaS=peer may retry) so cross-bleed would erase the distinction.
    #[test]
    fn ops29_bump_att_pull_invalid_powas_independent_from_sig() {
        let mut table = PeerTable::new();
        table.insert(make_peer("nyc", 0));

        table.bump_att_pull_invalid_sig("nyc", 5);
        table.bump_att_pull_invalid_powas("nyc", 3);

        let p = table.get("nyc").unwrap();
        assert_eq!(p.att_pull_invalid_sig, 5);
        assert_eq!(p.att_pull_invalid_powas, 3);

        // Bump only PoWaS — sig counter must stay put.
        table.bump_att_pull_invalid_powas("nyc", 7);
        let p = table.get("nyc").unwrap();
        assert_eq!(p.att_pull_invalid_sig, 5, "sig must not move when only powas bumped");
        assert_eq!(p.att_pull_invalid_powas, 10);
    }

    /// Counters saturate rather than overflow. A pathological peer
    /// blasting bad-sigs for years should clamp at u64::MAX, not wrap.
    #[test]
    fn ops29_bump_att_pull_invalid_sig_saturates_on_overflow() {
        let mut table = PeerTable::new();
        let mut p = make_peer("evil", 0);
        p.att_pull_invalid_sig = u64::MAX - 5;
        table.insert(p);

        table.bump_att_pull_invalid_sig("evil", 100);
        assert_eq!(
            table.get("evil").unwrap().att_pull_invalid_sig,
            u64::MAX,
            "must saturate, not wrap"
        );
    }

    /// Per-peer push-side low-stake-deferred counter starts at 0,
    /// accumulates, and treats unknown peers as no-op. Same shape as the
    /// pull-side counters because the bump is on the same hot path semantics
    /// — server-side after authenticated handshake, with a transient race
    /// possible if the peer was evicted between handshake and dispatch.
    ///
    /// The bump returns `bool` so the caller (router.rs) can detect
    /// the unattributed case and bump the global gap counter — the test now
    /// asserts both the return shape and the no-op semantics on unknown
    /// peers.
    #[test]
    fn ops30_bump_att_push_low_stake_deferred_accumulates() {
        let mut table = PeerTable::new();
        table.insert(make_peer("hel", 0));
        assert_eq!(table.get("hel").unwrap().att_push_low_stake_deferred, 0);

        assert!(table.bump_att_push_low_stake_deferred("hel", 1));
        assert!(table.bump_att_push_low_stake_deferred("hel", 1));
        assert!(table.bump_att_push_low_stake_deferred("hel", 1));
        assert_eq!(table.get("hel").unwrap().att_push_low_stake_deferred, 3);

        // Unknown peer: silently no-op, no panic, no insert. Returns false
        // so callers can attribute the gap.
        assert!(!table.bump_att_push_low_stake_deferred("ghost", 50));
        assert!(table.get("ghost").is_none());
    }

    /// Push-side and pull-side counters are independent — they
    /// observe different code paths (PQ receive vs pull batch verify) and
    /// cross-bleed would erase the operator's ability to tell which path
    /// the storm is coming from.
    #[test]
    fn ops30_push_counter_independent_from_pull_counters() {
        let mut table = PeerTable::new();
        table.insert(make_peer("nyc", 0));

        table.bump_att_pull_invalid_sig("nyc", 7);
        table.bump_att_pull_invalid_powas("nyc", 4);
        table.bump_att_push_low_stake_deferred("nyc", 11);

        let p = table.get("nyc").unwrap();
        assert_eq!(p.att_pull_invalid_sig, 7);
        assert_eq!(p.att_pull_invalid_powas, 4);
        assert_eq!(p.att_push_low_stake_deferred, 11);
    }

    /// Push counter saturates at u64::MAX rather than wrapping.
    /// A peer permanently stuck forwarding a low-stake witness's atts in
    /// a long-running fleet should clamp, not wrap to a confusing low
    /// value that hides the storm.
    #[test]
    fn ops30_bump_att_push_low_stake_deferred_saturates_on_overflow() {
        let mut table = PeerTable::new();
        let mut p = make_peer("loud", 0);
        p.att_push_low_stake_deferred = u64::MAX - 3;
        table.insert(p);

        table.bump_att_push_low_stake_deferred("loud", 100);
        assert_eq!(
            table.get("loud").unwrap().att_push_low_stake_deferred,
            u64::MAX,
            "must saturate, not wrap"
        );
    }

    /// Ring buffer accumulates record IDs from a peer's bad-sig
    /// rejections, capped at BAD_SIG_SAMPLE_CAP. Two batches of distinct
    /// record IDs from the same peer must both be retained when total
    /// stays below cap.
    #[test]
    fn ops32_push_bad_sig_record_ids_accumulates_below_cap() {
        let mut table = PeerTable::new();
        table.insert(make_peer("hil", 0));

        table.push_bad_sig_record_ids(
            "hil",
            vec!["rec_a".to_string(), "rec_b".to_string()],
        );
        table.push_bad_sig_record_ids(
            "hil",
            vec!["rec_c".to_string()],
        );

        let p = table.get("hil").unwrap();
        assert_eq!(p.recent_bad_sig_record_ids.len(), 3);
        let collected: Vec<&String> = p.recent_bad_sig_record_ids.iter().collect();
        assert_eq!(collected, vec!["rec_a", "rec_b", "rec_c"]);
    }

    /// Oldest entries fall off when buffer is full. We never want
    /// to grow without bound — the cap is the upper memory contract.
    #[test]
    fn ops32_push_bad_sig_record_ids_evicts_oldest_when_full() {
        let mut table = PeerTable::new();
        table.insert(make_peer("hil", 0));

        // Fill exactly to cap.
        let initial: Vec<String> = (0..BAD_SIG_SAMPLE_CAP)
            .map(|i| format!("rec_{}", i))
            .collect();
        table.push_bad_sig_record_ids("hil", initial);

        // Push 3 more: oldest 3 must be evicted.
        table.push_bad_sig_record_ids(
            "hil",
            vec![
                "rec_new1".to_string(),
                "rec_new2".to_string(),
                "rec_new3".to_string(),
            ],
        );

        let p = table.get("hil").unwrap();
        assert_eq!(p.recent_bad_sig_record_ids.len(), BAD_SIG_SAMPLE_CAP);
        assert_eq!(
            p.recent_bad_sig_record_ids.front().unwrap(),
            "rec_3",
            "oldest 3 (rec_0/rec_1/rec_2) must have been evicted"
        );
        assert_eq!(
            p.recent_bad_sig_record_ids.back().unwrap(),
            "rec_new3",
            "newest must be at the tail"
        );
    }

    /// Empty input is a no-op — we don't acquire the slot or
    /// reset state on a benign batch with no rejections.
    #[test]
    fn ops32_push_bad_sig_record_ids_empty_is_noop() {
        let mut table = PeerTable::new();
        table.insert(make_peer("hil", 0));
        table.push_bad_sig_record_ids("hil", vec!["seed".to_string()]);

        table.push_bad_sig_record_ids("hil", Vec::new());

        let p = table.get("hil").unwrap();
        assert_eq!(p.recent_bad_sig_record_ids.len(), 1);
        assert_eq!(p.recent_bad_sig_record_ids.front().unwrap(), "seed");
    }

    /// Race tolerance — peer evicted between batch start and
    /// flush must not panic. Same race window as the counter bumps.
    #[test]
    fn ops32_push_bad_sig_record_ids_unknown_peer_is_noop() {
        let mut table = PeerTable::new();
        // No insert.
        table.push_bad_sig_record_ids("ghost", vec!["rec_x".to_string()]);
        assert!(table.get("ghost").is_none());
    }

    // ─── pure-helper pins ──────────────────────────────────────────────
    //
    // Fixture-free pins on pure helpers — orthogonal axes not covered
    // by the existing tests. No async, no I/O, no clock dependence.

    /// `wants_zone()` is bidirectional-prefix: subscriber accepts
    /// the zone iff its subscription list is empty OR ANY subscribed prefix
    /// matches the zone (either direction). Pins the 4-cell truth table.
    #[test]
    fn batch_b_wants_zone_bidirectional_prefix_truth_table() {
        let mut accepts_all = make_peer("a", 0);
        accepts_all.subscribed_zones = Vec::new();
        assert!(accepts_all.wants_zone("anything"), "empty subscribed_zones accepts all");
        assert!(accepts_all.wants_zone(""), "empty subscribed_zones accepts empty zone too");

        let mut narrow = make_peer("b", 0);
        narrow.subscribed_zones = vec!["zone-a".to_string()];
        assert!(narrow.wants_zone("zone-a"), "exact match must accept");
        assert!(
            narrow.wants_zone("zone-a:subzone"),
            "zone-name starts with subscription → accept"
        );
        assert!(
            narrow.wants_zone("zone"),
            "subscription starts with zone-name → accept (bidirectional prefix)"
        );
        assert!(!narrow.wants_zone("zone-b"), "non-overlapping prefix must reject");
        assert!(
            !narrow.wants_zone("other"),
            "completely unrelated name must reject"
        );
    }

    /// `PeerInfo::reputation()` is the SUCCESS/(SUCCESS+FAILURE)
    /// instance method (distinct from `PeerTable::reputation` which folds
    /// in valid/invalid records and returns 0.5 for unknowns). Pin: returns
    /// 1.0 on empty history (NOT 0.5), and successes/(successes+failures)
    /// for any non-empty history.
    #[test]
    fn batch_b_peer_info_reputation_one_on_empty_history() {
        let empty = make_peer("e", 0);
        assert_eq!(empty.successes, 0);
        assert_eq!(empty.failures, 0);
        assert!(
            (empty.reputation() - 1.0).abs() < 1e-12,
            "PeerInfo::reputation must return 1.0 on empty history (NOT 0.5 like PeerTable)"
        );

        let mut all_fail = make_peer("f", 5);
        all_fail.successes = 0;
        assert!(
            all_fail.reputation().abs() < 1e-12,
            "5 failures + 0 successes → 0.0"
        );

        let mut mixed = make_peer("m", 1);
        mixed.successes = 3;
        // 3 / (3+1) = 0.75
        assert!(
            (mixed.reputation() - 0.75).abs() < 1e-12,
            "3 successes + 1 failure → 0.75"
        );
    }

    /// `record_pull_failure` auto-NAT detection fires exactly at
    /// the 5th consecutive pull failure: reachable goes true→false at
    /// pull_failures=5, stays true at pull_failures<=4. Pins the threshold.
    #[test]
    fn batch_b_record_pull_failure_auto_nat_at_five() {
        let mut table = PeerTable::new();
        table.insert(make_peer("nat", 0));
        assert!(table.get("nat").unwrap().reachable, "default reachable=true");

        // 4 failures: still reachable (below threshold).
        for _ in 0..4 {
            table.record_pull_failure("nat");
        }
        assert_eq!(table.get("nat").unwrap().pull_failures, 4);
        assert!(
            table.get("nat").unwrap().reachable,
            "4 pull failures must keep reachable=true (below 5-threshold)"
        );

        // 5th failure: auto-NAT fires.
        table.record_pull_failure("nat");
        assert_eq!(table.get("nat").unwrap().pull_failures, 5);
        assert!(
            !table.get("nat").unwrap().reachable,
            "5 consecutive pull failures must auto-mark reachable=false"
        );
    }

    /// `insert()` rejects peers whose identity_hash matches the
    /// local node's identity (NAT loopback / self-gossip prevention). With
    /// empty local_identity_hash, no filter applies. Pins the 3-way truth.
    #[test]
    fn batch_b_insert_rejects_self_via_local_identity_hash() {
        // Empty filter: all peers accepted (default new()).
        let mut table = PeerTable::new();
        assert!(
            table.insert(make_peer("anyone", 0)),
            "empty local_identity_hash must accept any peer"
        );

        // Set local identity → matching insert rejected, non-matching accepted.
        let mut filtered = PeerTable::new();
        filtered.set_local_identity("self-hash");
        assert!(
            !filtered.insert(make_peer("self-hash", 0)),
            "insert with identity_hash == local_identity_hash must return false"
        );
        assert!(
            filtered.get("self-hash").is_none(),
            "rejected self-peer must NOT appear in the table"
        );
        assert!(
            filtered.insert(make_peer("other-hash", 0)),
            "non-self peer must still insert"
        );
        assert!(filtered.get("other-hash").is_some());
    }

    /// `ban_ttl(count)` doubles per repeat ban with a 60-minute
    /// cap: count=1→600s, 2→1200s, 3→2400s, 4→3600s (cap), 5+→3600s.
    /// Pins both the doubling curve and the saturation cap at count≥4.
    #[test]
    fn batch_b_ban_ttl_escalation_curve_doubles_then_caps_at_3600() {
        assert!(
            (PeerTable::ban_ttl(1) - 600.0).abs() < 1e-9,
            "ban_ttl(1) = BAN_TTL_SECS = 600s"
        );
        assert!(
            (PeerTable::ban_ttl(2) - 1200.0).abs() < 1e-9,
            "ban_ttl(2) = 600·2 = 1200s"
        );
        assert!(
            (PeerTable::ban_ttl(3) - 2400.0).abs() < 1e-9,
            "ban_ttl(3) = 600·4 = 2400s"
        );
        assert!(
            (PeerTable::ban_ttl(4) - 3600.0).abs() < 1e-9,
            "ban_ttl(4) = min(600·8, 3600) = 3600s (cap fires)"
        );
        assert!(
            (PeerTable::ban_ttl(5) - 3600.0).abs() < 1e-9,
            "ban_ttl(5) still 3600s (capped)"
        );
        assert!(
            (PeerTable::ban_ttl(100) - 3600.0).abs() < 1e-9,
            "ban_ttl(100) still 3600s (cap never breached)"
        );
        // Constants pin
        assert_eq!(super::BAN_TTL_SECS, 600.0, "BAN_TTL_SECS must remain 600s");
    }
}
