//! Peer discovery — seed bootstrap and heartbeat loop.

//!
//! Spec references:
//!   @spec Protocol §11.14
//!   @spec Protocol §11.4

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::dht::{DhtPeer, InsertResult, NodeId, PeerProvenance, ALPHA, DISJOINT_PATHS};
use super::peer::{NodeType, PeerInfo, PeerState};
use super::state::NodeState;
use super::LockRecover;

/// PQ-only `get_status` for seed bootstrap / reconnect. Authenticated via
/// Dilithium3 TOFU. Returns Err on any PQ failure — no HTTPS fallback
/// (AUDIT-10 directive, 2026-04-24; in-process TLS server removed in
/// 4E.6, 2026-04-27).
async fn pq_get_status(
    state: &Arc<NodeState>,
    base_url: &str,
) -> crate::errors::Result<serde_json::Value> {
    let pq_addr = super::gossip::http_to_pq_addr(base_url, state.config.pq_port_offset)
        .ok_or_else(|| {
            crate::errors::ElaraError::Network(format!(
                "cannot derive PQ peer addr from {base_url:?}"
            ))
        })?;
    state.pq_client.get_status(&pq_addr).await
}

/// PQ-only `list_peers` — PEX fetch authenticated via Dilithium3 TOFU.
/// Returns Err on any PQ failure (no HTTPS fallback, AUDIT-10 directive).
async fn pq_list_peers(
    state: &Arc<NodeState>,
    base_url: &str,
) -> crate::errors::Result<serde_json::Value> {
    let pq_addr = super::gossip::http_to_pq_addr(base_url, state.config.pq_port_offset)
        .ok_or_else(|| {
            crate::errors::ElaraError::Network(format!(
                "cannot derive PQ peer addr from {base_url:?}"
            ))
        })?;
    state.pq_client.list_peers(&pq_addr).await
}

/// AUDIT-9 Milestone B: after a successful PQ peer handshake (status, list_peers,
/// reconnect) we already have an authenticated session and an `identity_hash`,
/// so fetch the peer's `WitnessProfile` directly and register it in the local
/// consensus engine. No DAG-gossip round-trip required.
///
/// Best-effort: on any failure (peer on pre-Milestone-B binary, network hiccup,
/// profile intentionally unconfigured) we log at debug and move on. The DAG-
/// record path keeps working as a fallback, and correlation with an unknown
/// profile falls back to the conservative `ALPHA + BETA = 0.8` Sybil penalty.
/// Skip when the peer's profile is already registered so we don't re-hit the
/// verb every heartbeat.
async fn pq_exchange_profile_and_register(
    state: &Arc<NodeState>,
    base_url: &str,
    peer_identity_hash: &str,
) {
    if peer_identity_hash.is_empty() {
        return;
    }
    {
        let consensus = state.consensus.lock_recover();
        if consensus.has_profile(peer_identity_hash) {
            return;
        }
    }
    let Some(pq_addr) = super::gossip::http_to_pq_addr(base_url, state.config.pq_port_offset) else {
        return;
    };
    // B2: include our own profile so the server registers it symmetrically —
    // otherwise NAT'd nodes (public peers can't dial them back) would rely
    // on DAG-gossip propagation of our WitnessProfile record, losing the
    // latency win for half of every peer pair.
    let own_profile = state.config.effective_witness_profile();
    match state
        .pq_client
        .exchange_profile(&pq_addr, own_profile.as_ref())
        .await
    {
        Ok((reported_hash, Some(profile))) => {
            if reported_hash != peer_identity_hash {
                debug!(
                    "exchange_profile: peer {base_url} identity_hash mismatch — status said {peer_identity_hash}, PQ channel returned {reported_hash}; skipping"
                );
                return;
            }
            let mut consensus = state.consensus.lock_recover();
            consensus.register_profile(&reported_hash, profile);
            debug!(
                "exchange_profile: registered {base_url} ({})",
                &reported_hash[..reported_hash.len().min(16)]
            );
        }
        Ok((_, None)) => {
            debug!("exchange_profile: {base_url} has no witness profile configured");
        }
        Err(e) => {
            debug!("exchange_profile: {base_url} failed: {e}");
        }
    }
}

/// PQ-only liveness probe. Authenticated via Dilithium3 TOFU, no TLS trust.
/// Returns `false` on any PQ failure (unreachable peer, handshake rejection).
async fn pq_ping(state: &Arc<NodeState>, base_url: &str) -> bool {
    let Some(pq_addr) = super::gossip::http_to_pq_addr(base_url, state.config.pq_port_offset) else {
        return false;
    };
    state.pq_client.ping(&pq_addr).await
}

/// PQ-only Kademlia FIND_NODE. Authenticated via Dilithium3 TOFU.
async fn pq_find_node(
    state: &Arc<NodeState>,
    base_url: &str,
    target_hex: &str,
    count: usize,
) -> crate::errors::Result<Vec<serde_json::Value>> {
    let pq_addr = super::gossip::http_to_pq_addr(base_url, state.config.pq_port_offset)
        .ok_or_else(|| {
            crate::errors::ElaraError::Network(format!(
                "cannot derive PQ peer addr from {base_url:?}"
            ))
        })?;
    state.pq_client.find_node(&pq_addr, target_hex, count).await
}

/// Returns true if the IP address is private, loopback, link-local, or broadcast.
/// Peers advertising these addresses are rejected to prevent peer poisoning attacks
/// (internal network scanning, localhost access, broadcast amplification).
///
/// Covers BOTH IPv4 and IPv6 — an IPv6 literal previously fell through to "allow",
/// so a peer advertising `::1`, a ULA (`fc00::/7`), or a link-local (`fe80::/10`)
/// address bypassed the filter entirely (audit 16j). Hostnames and non-IP strings
/// still fall through to allow (they are resolved + re-filtered downstream).
pub(crate) fn is_private_or_reserved_ip(host: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};
    // Shared IPv4 reserved-range predicate, reused for a native IPv4 literal AND
    // for the IPv4 embedded in an IPv4-mapped (`::ffff:0:0/96`) or NAT64
    // (`64:ff9b::/96`) IPv6 literal. Without the embedded recheck, a peer can
    // smuggle a reserved IPv4 past this filter by wrapping it in an IPv6 literal —
    // e.g. `::ffff:169.254.169.254` (cloud metadata) parses as Ipv6Addr where
    // `is_loopback()`/the ULA+link-local prefix checks all miss it. The dial path
    // (`peer_base_url` → `TcpStream::connect`) never re-resolves a stored literal,
    // and an unbracketed `::ffff:…` literal DOES resolve via getaddrinfo, so the
    // doc's old "resolved + filtered downstream" claim was false for literals.
    fn v4_reserved(ip: Ipv4Addr) -> bool {
        ip.is_loopback()              // 127.0.0.0/8
            || ip.is_private()        // 10/8, 172.16/12, 192.168/16
            || ip.is_link_local()     // 169.254.0.0/16 (cloud metadata)
            || ip.is_broadcast()      // 255.255.255.255
            || ip.is_unspecified()    // 0.0.0.0
            || ip.octets()[0] == 0    // 0.0.0.0/8 "this network" (0.x → localhost on some stacks)
            || ip.is_multicast()      // 224.0.0.0/4 (dead TCP dial, but never a peer)
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return v4_reserved(ip);
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        // IPv4-mapped `::ffff:0:0/96` → apply the IPv4 rules to the embedded addr.
        // Use `to_ipv4_mapped()` (NOT `to_ipv4()`): the latter also folds the
        // deprecated IPv4-compatible `::/96` block and maps `::1` → `0.0.0.1`,
        // a false-negative on loopback. `to_ipv4_mapped()` matches ONLY `::ffff:/96`.
        if let Some(v4) = ip.to_ipv4_mapped() {
            return v4_reserved(v4);
        }
        // NAT64 well-known prefix `64:ff9b::/96` — embedded IPv4 in the low 32 bits.
        // `64:ff9b::169.254.169.254` would route through a NAT64 gateway to the
        // reserved IPv4; reject on the embedded address.
        let s = ip.segments();
        if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
            let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
            return v4_reserved(v4);
        }
        // Native IPv6 non-routable rejects. The stable std API lacks
        // is_unique_local()/is_unicast_link_local(), so match the prefixes on the
        // first 16-bit segment directly.
        let seg0 = s[0];
        return ip.is_loopback()                  // ::1
            || ip.is_unspecified()               // ::
            || (seg0 & 0xfe00) == 0xfc00         // fc00::/7  unique-local (ULA)
            || (seg0 & 0xffc0) == 0xfe80;        // fe80::/10 link-local
    }
    // Not an IP literal — hostname or garbage. Allow (resolved + filtered elsewhere).
    false
}

/// Stricter gate for an UNTRUSTED wire-advertised peer host — a `host` field from a
/// `/peers` PEX response, a FIND_NODE response, or the `x-elara-host` implicit-
/// discovery header. Returns true only when `host` is a routable IP **literal**.
///
/// Why literal-only, not just `!is_private_or_reserved_ip`: that filter passes any
/// hostname (it does no DNS), and the dial path never re-resolves+re-filters — it
/// interpolates the host raw (`peer_base_url` → `http://{host}:{port}`, and the PQ
/// `http_to_pq_addr` → `TcpStream::connect(&str)` which resolves via getaddrinfo at
/// connect time). So a peer advertising `host:"evil.example"` whose A-record points
/// at `169.254.169.254` (cloud metadata) / `127.0.0.1` / RFC1918 drives a blind SSRF
/// straight past the reserved-IP filter — the hostname sibling of the IPv4-mapped/
/// NAT64 literal bypass closed in 15dadd33. Requiring a literal removes the DNS step
/// entirely (so there is also no rebinding/TOCTOU window), and `is_private_or_reserved_ip`
/// then fully validates every literal form (v4, v6, `::ffff:` mapped, `64:ff9b::`
/// NAT64). Bracketed (`[::1]`) and zone-id (`fe80::1%eth0`) forms fail `parse` and are
/// rejected — the safe outcome on an untrusted path.
///
/// Operator-configured `seed_peers` are trusted and intentionally NOT gated by this
/// (they may be DNS names — resolved once at startup, then each resolved IP filtered
/// by the `lookup_host` seed path above). Tailscale CGNAT (`100.64/10`) is a literal
/// that `is_private_or_reserved_ip` deliberately permits, so it still passes here.
pub(crate) fn is_dialable_wire_host(host: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let is_ip_literal = host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok();
    is_ip_literal && !is_private_or_reserved_ip(host)
}

/// Parse a `/peers` JSON response into `PeerInfo` entries, skipping self.
/// Rejects peers with private/reserved IP addresses to prevent peer poisoning.
/// B5/F3b: max NEW peers admitted from a single source in one discovery round.
/// Blunts a malicious/compromised source from flooding the table in one response.
/// Not the structural defense (per-source caps are K-source-bypassable; real fix =
/// global rate + /24-ASN admission diversity, deferred) — a cheap latent bound for
/// when PEX (`pex_interval_secs`) is enabled. Generous so a legitimate seed handoff
/// during cold-start is not throttled at the current fleet scale.
const MAX_NEW_PEERS_PER_SOURCE: usize = 32;

/// B5/F3b: per-discovery-source admission decision for one offered peer.
/// Shared by the bootstrap PEX path and `pex_loop` so the cap invariant has a
/// single tested definition.
#[derive(Debug, PartialEq, Eq)]
enum NewPeerAction {
    /// Already in the table — refresh is the heartbeat's job; do NOT count it
    /// against the per-source NEW-peer budget (else a source returning ≥cap
    /// already-known peers starves discovery of genuinely-new ones).
    SkipKnown,
    /// Per-source NEW-peer budget exhausted this round — stop and record a clip.
    Clip,
    /// Genuinely new and under budget — admit and count.
    AdmitNew,
}

/// Classify an offered peer against the per-source NEW-peer cap. Pure +
/// unit-tested (the bootstrap path previously counted known-peer updates toward
/// the cap because `PeerTable::insert` returns true on overwrite — B5 audit
/// SEV-2). `known` MUST be the already-in-table check; `admitted_new` is the
/// count of genuinely-new peers admitted from this source so far this round.
fn classify_new_peer(known: bool, admitted_new: usize) -> NewPeerAction {
    if known {
        NewPeerAction::SkipKnown
    } else if admitted_new >= MAX_NEW_PEERS_PER_SOURCE {
        NewPeerAction::Clip
    } else {
        NewPeerAction::AdmitNew
    }
}

fn parse_peer_list(data: &serde_json::Value, self_hash: &str, min_protocol_version: u32) -> Vec<PeerInfo> {
    let Some(peer_list) = data["peers"].as_array() else {
        return Vec::new();
    };
    peer_list
        .iter()
        .filter_map(|p| {
            let ih = p["identity_hash"].as_str().unwrap_or("").to_string();
            // Reject malformed identities from the untrusted peer-list response:
            // any peer can return arbitrary entries, and `ih` is byte-sliced below
            // for logs (`&ih[..ih.len().min(16)]`, UTF-8-unsafe on a multi-byte
            // value) AND enters the peer table. The is_empty()/self checks alone
            // let a short or multi-byte identity through. (is_empty is subsumed.)
            if !super::peer::is_valid_peer_identity(&ih) || ih == self_hash {
                return None;
            }
            let h = p["host"].as_str().unwrap_or("").to_string();
            // Untrusted PEX host: require a routable IP literal. A hostname here would
            // bypass is_private_or_reserved_ip (no DNS) and be dialed raw → blind SSRF.
            if h.is_empty() || !is_dialable_wire_host(&h) {
                return None;
            }
            let pv = p["protocol_version"].as_u64().unwrap_or(0) as u32;
            if min_protocol_version > 0 && pv < min_protocol_version {
                debug!("peer {} protocol version {pv} < min {min_protocol_version}, skipping",
                    &ih[..ih.len().min(16)]);
                return None;
            }
            let pt = p["port"].as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(9473);
            let nt = p["node_type"]
                .as_str()
                .map(NodeType::from_str)
                .unwrap_or(NodeType::Leaf);

            let pow_nonce = p["pow_nonce"].as_u64().unwrap_or(0);
            let pow_difficulty = p["pow_difficulty"].as_u64().unwrap_or(0) as u8;
            let public_key_hex = p["public_key_hex"]
                .as_str()
                .unwrap_or("")
                .to_string();

            Some(PeerInfo {
                identity_hash: ih,
                host: h,
                port: pt,
                node_type: nt,
                last_seen: now(),
                state: PeerState::Stale,
                failures: 0,
                successes: 0,
                valid_records: 0,
                invalid_records: 0,
                backoff_until: 0.0,
                pow_nonce,
                pow_difficulty,
                public_key_hex,
                provenance: super::peer::PeerProvenance::Outbound,
                    subscribed_zones: Vec::new(),
                    att_watermark: 0.0,
                    pull_failures: 0,
                    pull_backoff_until: 0.0,
                    reachable: true,
                    protocol_version: pv,
                    att_pull_invalid_sig: 0,
                    att_pull_invalid_powas: 0,
                    att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
            })
        })
        .collect()
}

/// Resolve DNS seed hostnames to peer URLs.
///
/// Each hostname in `dns_seeds` is resolved via the system DNS resolver.
/// Resolved IPs are combined with `dns_seed_port` to form `http://IP:PORT` URLs.
/// Deduplicates against existing `seed_peers` to avoid double-bootstrapping.
/// DNS failures are logged and skipped — hardcoded seeds remain as fallback.
async fn resolve_dns_seeds(config: &super::config::NodeConfig) -> Vec<String> {
    use tokio::net::lookup_host;

    let mut resolved = Vec::new();
    let existing: std::collections::HashSet<String> = config.seed_peers.iter().cloned().collect();

    for hostname in &config.dns_seeds {
        // lookup_host needs host:port format
        let lookup_addr: String = if hostname.contains(':') {
            hostname.clone()
        } else {
            format!("{}:{}", hostname, config.dns_seed_port)
        };

        let addrs: std::result::Result<Vec<_>, _> = lookup_host(lookup_addr.as_str()).await.map(|a| a.collect());
        match addrs {
            Ok(addrs) => {
                let mut count = 0u32;
                for addr in addrs {
                    let ip = addr.ip();
                    // Skip private/loopback IPs from DNS (could be poisoned)
                    if is_private_or_reserved_ip(&ip.to_string()) {
                        debug!("DNS seed {hostname}: skipping private IP {ip}");
                        continue;
                    }
                    // PQ-R6: DNS seeds are classical-HTTP; real authentication
                    // happens on the PQ port. HTTPS dial-out still works if the
                    // peer is on a legacy binary (reqwest falls back), but we
                    // don't construct the URL with an https scheme.
                    let url = format!("http://{}:{}", ip, config.dns_seed_port);
                    if !existing.contains(&url) && !resolved.contains(&url) {
                        resolved.push(url);
                        count += 1;
                    }
                }
                if count > 0 {
                    info!("DNS seed {hostname}: resolved {count} new peer(s)");
                } else {
                    debug!("DNS seed {hostname}: resolved but all already known");
                }
            }
            Err(e) => {
                warn!("DNS seed {hostname}: resolution failed — {e} (using hardcoded seeds as fallback)");
            }
        }
    }

    resolved
}

/// Bootstrap: contact seed peers, populate peer table.
///
/// Seed addresses can include a scheme (`https://host:port`). When no scheme
/// is given, plain `http://` is used (4E.6: in-process TLS server removed).
pub async fn bootstrap(state: &Arc<NodeState>) {
    // Load persisted DHT state from previous session
    let dht_path = state.config.data_dir.join("dht.json");
    let restored = state.dht.lock_recover().load(&dht_path);
    if restored > 0 {
        // The reload path bypasses the wire/mDNS ingest guards: drop any persisted
        // DHT peer whose host is not LAN-dialable (a pre-guard hostname, or a
        // mapped/NAT64 reserved literal) so content-routing / heartbeat dials can't
        // be turned into an SSRF. Same floor as the live mDNS gate.
        let undialable: Vec<NodeId> = {
            let dht = state.dht.lock_recover();
            dht.all_peers()
                .into_iter()
                .filter(|p| !super::mdns::persisted_host_is_dialable_lan(&p.host))
                .filter_map(|p| NodeId::from_hex(&p.identity_hash))
                .collect()
        };
        if !undialable.is_empty() {
            let mut dht = state.dht.lock_recover();
            for id in &undialable {
                dht.remove(id);
            }
            warn!(
                "dropped {} persisted DHT peer(s) with undialable host",
                undialable.len()
            );
        }

        // Remove self from loaded DHT — prevents NAT loopback pull-from-self
        let self_hash = &state.identity.identity_hash;
        let removed = if let Some(self_node_id) = NodeId::from_hex(self_hash) {
            state.dht.lock_recover().remove(&self_node_id)
        } else {
            false
        };
        // restored counts the raw load; subtract the undialable peers dropped above
        // (and self, if present) so the line isn't inflated past the live table size.
        let kept = restored.saturating_sub(undialable.len() + usize::from(removed));
        if removed {
            info!("loaded {kept} peers from DHT snapshot (removed self)");
        } else {
            info!("loaded {kept} peers from DHT snapshot");
        }
    }

    // Resolve DNS seeds and merge with hardcoded seed peers
    let dns_resolved = resolve_dns_seeds(&state.config).await;
    let mut seeds = state.config.seed_peers.clone();
    seeds.extend(dns_resolved);

    if seeds.is_empty() {
        info!("no seed peers configured and DNS resolution returned nothing — running standalone");
        return;
    }

    info!("bootstrapping from {} seed peers", seeds.len());

    for seed_addr in &seeds {
        let base_url = seed_base_url(seed_addr);
        let (host, port) = parse_host_port_from_url(seed_addr);

        match pq_get_status(state, &base_url).await {
            Ok(status) => {
                let identity_hash = status["identity_hash"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();

                // Reject malformed identities from the remote /status response
                // (attacker-controlled). Downstream code byte-slices identity_hash
                // (`&identity_hash[..16]`) for logs, and the `"unknown"` default is
                // only 7 chars — without this guard a peer that omits identity_hash,
                // or reports a short / multi-byte value, panics the bootstrap loop.
                if !super::peer::is_valid_peer_identity(&identity_hash) {
                    debug!("discovery: seed peer at {base_url} reported malformed identity_hash, skipping");
                    continue;
                }

                // Skip self
                if identity_hash == state.identity.identity_hash {
                    continue;
                }

                // Protocol version check — reject incompatible peers early
                let peer_protocol_version = status["protocol_version"].as_u64().unwrap_or(0) as u32;
                let min_version = state.config.min_protocol_version;
                if min_version > 0 && peer_protocol_version < min_version {
                    warn!("seed {seed_addr} protocol version {peer_protocol_version} < min {min_version}, skipping");
                    continue;
                }

                // Network isolation — reject peers from different networks
                let peer_network = status["network_id"].as_str().unwrap_or("testnet");
                if peer_network != state.config.network_id {
                    warn!("seed {seed_addr} network {peer_network} != ours {}, skipping", state.config.network_id);
                    continue;
                }

                let node_type_str = status["node_type"].as_str().unwrap_or("leaf");
                let pow_nonce = status["pow_nonce"].as_u64().unwrap_or(0);
                let pow_difficulty = status["pow_difficulty"].as_u64().unwrap_or(0) as u8;
                let public_key_hex = status["public_key_hex"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let peer = PeerInfo {
                    identity_hash: identity_hash.clone(),
                    host: host.clone(),
                    port,
                    node_type: NodeType::from_str(node_type_str),
                    last_seen: now(),
                    state: PeerState::Connected,
                    failures: 0,
                    successes: 0,
                    valid_records: 0,
                    invalid_records: 0,
                    backoff_until: 0.0,
                    pow_nonce,
                    pow_difficulty,
                    public_key_hex,
                    provenance: super::peer::PeerProvenance::Outbound,
                    subscribed_zones: Vec::new(),
                    att_watermark: 0.0,
                    pull_failures: 0,
                    pull_backoff_until: 0.0,
                    reachable: true,
                    protocol_version: peer_protocol_version,
                    att_pull_invalid_sig: 0,
                    att_pull_invalid_powas: 0,
                    att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
                };

                {
                    let mut peers = state.peers.write().await;
                    // Register as seed peer — seed peers are never banned
                    peers.add_seed_peer(&identity_hash);
                    peers.insert(peer);
                }
                insert_into_dht_with_eviction(state, &identity_hash, &host, port).await;
                info!("discovered seed peer {}", &identity_hash[..16]);

                let peer_url = peer_base_url(&host, port);

                // AUDIT-9 Milestone B: eagerly fetch + register the peer's
                // WitnessProfile over the authenticated PQ channel so the
                // consensus engine doesn't have to wait for DAG gossip of
                // the registration record.
                pq_exchange_profile_and_register(state, &peer_url, &identity_hash).await;

                // Also ask this peer for ITS peer list (PQ-only)
                match pq_list_peers(state, &peer_url).await {
                    Ok(data) => {
                        let new_peers = parse_peer_list(&data, &state.identity.identity_hash, state.config.min_protocol_version);
                        // B5/F3b: bound how many genuinely-NEW peers one seed can
                        // inject per round. Known-peer refreshes do NOT count
                        // against the budget (audit SEV-2: insert() returns true on
                        // overwrite, so counting them would let a seed returning ≥cap
                        // already-known peers starve discovery of new ones).
                        let mut admitted = 0usize;
                        for p in new_peers {
                            let ih = p.identity_hash.clone();
                            let h = p.host.clone();
                            let pt = p.port;
                            let known = state.peers.read().await.get(&ih).is_some();
                            match classify_new_peer(known, admitted) {
                                NewPeerAction::SkipKnown => continue,
                                NewPeerAction::Clip => {
                                    state.peer_admission_source_cap_clipped_total
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    warn!("bootstrap PEX from {peer_url} hit per-source cap ({MAX_NEW_PEERS_PER_SOURCE}) — clipping");
                                    break;
                                }
                                NewPeerAction::AdmitNew => {
                                    // Insert as Stale — heartbeat will verify before trusting.
                                    // Inserting as Connected would let a compromised seed
                                    // eclipse the node at startup. The peers write lock is
                                    // released before the async DHT insert below.
                                    if state.peers.write().await.insert(p) {
                                        insert_into_dht_with_eviction(state, &ih, &h, pt).await;
                                        admitted += 1;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("bootstrap PEX from {peer_url} failed: {e}");
                    }
                }
            }
            Err(e) => {
                warn!("seed {seed_addr} unreachable: {e}");
            }
        }
    }

    let peers = state.peers.read().await;
    info!("bootstrap complete: {} peers discovered", peers.len());
    drop(peers);

    // Run iterative lookup on self to populate nearby k-buckets
    let self_id = NodeId::from_hex(&state.identity.identity_hash)
        .unwrap_or(NodeId([0u8; 32]));
    let self_discovered = iterative_find_node(state, &self_id).await;
    if self_discovered > 0 {
        info!("self-lookup discovered {self_discovered} additional peers");
    }
}

/// Heartbeat loop — ping all peers periodically, mark stale after 3 failures.
pub async fn heartbeat_loop(
    state: Arc<NodeState>,
    mut shutdown: mpsc::Receiver<()>,
) {
    let interval = Duration::from_secs(30);
    let mut first = true;
    let startup_time = std::time::Instant::now();
    // Grace period: don't ban peers within first 5 minutes of node uptime.
    // During fleet restarts, peers are briefly unreachable. Without grace,
    // failures accumulate and peers get banned before they finish restarting.
    let ban_grace_period = Duration::from_secs(300);

    loop {
        if !first {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.recv() => {
                    debug!("heartbeat loop shutting down");
                    return;
                }
            }
        }
        first = false;

        // Stage 6 cooperative scheduler (Protocol §11.10).
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        // Collect peer identity hashes + URLs.
        //
        // Tier 1.1 NAT detection: filter out peers marked `reachable=false`.
        // They self-reported NAT (or got auto-marked unreachable after 5
        // pull failures); dialing them just accumulates `failures` on the
        // peer record, eventually triggering the auto-ban path below. They
        // remain in the table — we still accept their pushes and track their
        // reputation — we just stop trying to dial them. Recovery: when they
        // push again with `x-elara-reachable: 1` (NAT situation changed),
        // routes/core.rs::core_submit calls update_reachability(true) so the
        // next heartbeat sweep includes them again.
        let peer_info: Vec<(String, String)> = {
            let peers = state.peers.read().await;
            peers
                .all()
                .iter()
                .filter(|p| p.reachable)
                .map(|p| (p.identity_hash.clone(), p.base_url()))
                .collect()
        };

        for (identity_hash, base_url) in peer_info {
            if identity_hash == state.identity.identity_hash {
                continue;
            }
            if pq_ping(&state, &base_url).await {
                state.peers.write().await.mark_connected(&identity_hash, now());
                // AUDIT-9 follow-up #2 (2026-04-26): opportunistic profile fetch.
                // Seed-discovery + reconnect cover the seed set, but PEX-discovered
                // peers (inserted as Stale at L408) never trigger eager profile
                // fetch — they wait for slow DAG-record propagation. Heartbeat is
                // the right hook because it visits every peer every 30s and we
                // already know the PQ channel just succeeded. The exchange itself
                // short-circuits via `has_profile()` so steady state = zero
                // round-trips; only genuine first-contact triggers traffic.
                pq_exchange_profile_and_register(&state, &base_url, &identity_hash).await;
            } else {
                state.peers.write().await.record_failure(&identity_hash);
                debug!("heartbeat failure for {}", &identity_hash[..identity_hash.len().min(16)]);
            }
        }

        // Prune dead peers (consecutive failures >= threshold) and auto-ban.
        // Skip banning during startup grace period — peers may still be restarting.
        let max_failures = state.config.max_peer_failures;
        if max_failures > 0 && startup_time.elapsed() >= ban_grace_period {
            let to_prune = state.peers.read().await.stale_above(max_failures);
            if !to_prune.is_empty() {
                let mut peers = state.peers.write().await;
                let mut dht = state.dht.lock_recover();
                for ih in &to_prune {
                    // Ban instead of just removing — prevents reconnection
                    peers.ban(ih);
                    if let Some(nid) = NodeId::from_hex(ih) {
                        dht.remove(&nid);
                    }
                }
                state.peer_auto_banned_total.fetch_add(to_prune.len() as u64, std::sync::atomic::Ordering::Relaxed);
                info!("banned {} dead peers (failures >= {max_failures})", to_prune.len());
            }
        }

        // DHT refresh: query random target for new peers
        dht_refresh(&state).await;

        // Save peers + DHT to disk at end of each heartbeat cycle
        let peers_path = state.config.data_dir.join("peers.json");
        let peers = state.peers.read().await;
        peers.save(&peers_path);

        let dht_path = state.config.data_dir.join("dht.json");
        {
            let mut dht = state.dht.lock_recover();
            // Rotate stale peers to limit eclipse attack window (§11.28)
            let evicted = dht.rotate_stale_peers(now());
            if evicted > 0 {
                info!(evicted, "DHT peer rotation: evicted stale peers");
            }
            dht.save(&dht_path);
        }
    }
}

/// PEX (Peer Exchange) loop — periodically query connected peers for their peer lists.
/// New peers are inserted as `Stale` and verified by the heartbeat loop.
pub async fn pex_loop(
    state: Arc<NodeState>,
    mut shutdown: mpsc::Receiver<()>,
) {
    let interval_secs = state.config.pex_interval_secs;
    if interval_secs == 0 {
        debug!("PEX disabled (interval = 0)");
        return;
    }

    let interval = Duration::from_secs(interval_secs);
    info!("PEX loop started (every {interval_secs}s)");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("PEX loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10).
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        // Collect current peer URLs
        let peer_urls: Vec<String> = {
            let peers = state.peers.read().await;
            peers
                .connected()
                .iter()
                .filter(|p| p.identity_hash != state.identity.identity_hash)
                .map(|p| p.base_url())
                .collect()
        };

        let self_hash = &state.identity.identity_hash;
        let mut discovered = 0u32;

        for base_url in &peer_urls {
            let data = match pq_list_peers(&state, base_url).await {
                Ok(d) => d,
                Err(e) => {
                    debug!("PEX: {base_url} list_peers failed: {e}");
                    continue;
                }
            };

            let new_peers = parse_peer_list(&data, self_hash, state.config.min_protocol_version);

            // Only insert peers we don't already know
            let mut peers_w = state.peers.write().await;
            // B5/F3b: bound genuinely-NEW peers admitted from this single source
            // per round. Known-peer refreshes don't count (shared invariant with
            // the bootstrap path via classify_new_peer).
            let mut admitted_this_source = 0usize;
            for p in new_peers {
                let known = peers_w.get(&p.identity_hash).is_some();
                match classify_new_peer(known, admitted_this_source) {
                    NewPeerAction::SkipKnown => continue,
                    NewPeerAction::Clip => {
                        state.peer_admission_source_cap_clipped_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        debug!("PEX from {base_url} hit per-source cap ({MAX_NEW_PEERS_PER_SOURCE}) — clipping");
                        break;
                    }
                    NewPeerAction::AdmitNew => {
                        let ih = p.identity_hash.clone();
                        let h = p.host.clone();
                        let pt = p.port;
                        if peers_w.insert(p) {
                            insert_into_dht(&state, &ih, &h, pt);
                            discovered += 1;
                            admitted_this_source += 1;
                        }
                    }
                }
            }
        }

        if discovered > 0 {
            debug!("PEX discovered {discovered} new peers");
        }
    }
}

/// Insert a peer into the DHT routing table with provenance tracking (sync, no eviction ping).
fn insert_into_dht(state: &NodeState, identity_hash: &str, host: &str, port: u16) {
    insert_into_dht_inner(state, identity_hash, host, port, PeerProvenance::Outbound);
}

/// Public wrapper for mDNS module to insert discovered LAN peers into DHT.
pub(super) fn insert_into_dht_pub(state: &NodeState, identity_hash: &str, host: &str, port: u16) {
    insert_into_dht_inner(state, identity_hash, host, port, PeerProvenance::Inbound);
}

/// Insert a peer into the DHT with test-before-evict (async — pings eviction candidate).
///
/// When the bucket is full, the oldest peer is pinged. If it responds,
/// the new peer is dropped. If it doesn't, the oldest is evicted and
/// the new peer takes its place. This is the Bitcoin 2015 eclipse defense.
async fn insert_into_dht_with_eviction(
    state: &Arc<NodeState>,
    identity_hash: &str,
    host: &str,
    port: u16,
) {
    if identity_hash == state.identity.identity_hash {
        return;
    }
    let Some(node_id) = NodeId::from_hex(identity_hash) else { return };
    let peer = DhtPeer {
        node_id,
        identity_hash: identity_hash.to_string(),
        host: host.to_string(),
        port,
        last_seen: now(),
        first_added: now(),
        provenance: PeerProvenance::Outbound,
    };
    let result = state.dht.lock_recover().insert(peer.clone());
    match result {
        InsertResult::PendingEviction { evict_candidate } => {
            // Test-before-evict: ping the eviction candidate
            let evict_url = {
                let dht = state.dht.lock_recover();
                dht.find_by_identity(&evict_candidate)
                    .map(|p| peer_base_url(&p.host, p.port))
            };
            if let Some(url) = evict_url {
                if pq_ping(state, &url).await {
                    // Candidate alive — keep it, drop the new peer
                    debug!(
                        "DHT eviction candidate {} alive — new peer {} dropped",
                        &evict_candidate[..evict_candidate.len().min(16)],
                        &identity_hash[..identity_hash.len().min(16)],
                    );
                } else {
                    // Candidate dead — evict it, insert new peer
                    debug!(
                        "DHT eviction candidate {} dead — replaced by {}",
                        &evict_candidate[..evict_candidate.len().min(16)],
                        &identity_hash[..identity_hash.len().min(16)],
                    );
                    state.dht.lock_recover().evict_and_insert(peer);
                }
            } else {
                // Can't find candidate URL — evict anyway
                state.dht.lock_recover().evict_and_insert(peer);
            }
        }
        InsertResult::RejectedSubnetLimit => {
            debug!(
                "DHT rejected peer {} — /24 subnet diversity limit reached",
                &identity_hash[..identity_hash.len().min(16)],
            );
        }
        InsertResult::Inserted => {}
    }
}

/// Insert a peer into the DHT with explicit provenance (sync, no eviction ping).
/// Skips inserting self (prevents NAT loopback pull-from-self bug).
fn insert_into_dht_inner(
    state: &NodeState,
    identity_hash: &str,
    host: &str,
    port: u16,
    provenance: PeerProvenance,
) {
    if identity_hash == state.identity.identity_hash {
        return;
    }
    if let Some(node_id) = NodeId::from_hex(identity_hash) {
        let peer = DhtPeer {
            node_id,
            identity_hash: identity_hash.to_string(),
            host: host.to_string(),
            port,
            last_seen: now(),
            first_added: now(),
            provenance,
        };
        let result = state.dht.lock_recover().insert(peer.clone());
        match result {
            InsertResult::PendingEviction { evict_candidate } => {
                // Sync path — can't ping. The heartbeat loop will prune dead peers
                // and the next insert attempt will succeed.
                debug!(
                    "DHT bucket full, eviction candidate {} (new peer {} deferred to heartbeat)",
                    &evict_candidate[..evict_candidate.len().min(16)],
                    &identity_hash[..identity_hash.len().min(16)],
                );
            }
            InsertResult::RejectedSubnetLimit => {
                debug!(
                    "DHT rejected peer {} — /24 subnet diversity limit reached",
                    &identity_hash[..identity_hash.len().min(16)],
                );
            }
            InsertResult::Inserted => {}
        }
    }
}

/// Refresh the DHT by running an iterative Kademlia lookup toward a random target.
pub async fn dht_refresh(state: &Arc<NodeState>) {
    // Generate a random target by hashing current time
    let target_bytes = crate::crypto::hash::sha3_256(
        format!("dht-refresh-{}", now()).as_bytes()
    );
    let target = NodeId(target_bytes);
    iterative_find_node(state, &target).await;
}

/// Disjoint parallel Kademlia FIND_NODE lookup (S/Kademlia).
///
/// Runs `d` independent lookup paths in parallel, each with its own shortlist
/// and queried set. This ensures 99% lookup success even with 20% adversarial
/// nodes, because an attacker must control nodes on ALL paths to block a lookup.
///
/// Each path:
/// 1. Seeds a shortlist with a portion of the K closest peers
/// 2. Queries ALPHA unqueried peers in parallel per round
/// 3. Merges responses into its own shortlist
/// 4. Repeats until no closer unqueried peers or MAX_ROUNDS reached
///
/// Results from all paths are merged and all discovered peers are inserted
/// into the local routing table.
///
/// Returns the number of new peers discovered.
pub async fn iterative_find_node(
    state: &Arc<NodeState>,
    target: &NodeId,
) -> usize {
    use std::collections::BTreeMap;

    const K: usize = 8;
    const MAX_ROUNDS: usize = 5;

    let target_hex = target.to_hex();
    let self_hash = &state.identity.identity_hash;

    // Get initial seed peers from routing table, preferring outbound-discovered
    let seed_peers: Vec<(String, u16, String, [u8; 32])> = {
        let dht = state.dht.lock_recover();
        dht.closest_prefer_outbound(target, K * DISJOINT_PATHS)
            .iter()
            .filter(|p| p.identity_hash != *self_hash)
            .map(|p| {
                let dist = p.node_id.distance(target);
                (p.host.clone(), p.port, p.identity_hash.clone(), dist)
            })
            .collect()
    };

    if seed_peers.is_empty() {
        return 0;
    }

    // Distribute seed peers across d disjoint paths (round-robin)
    let d = DISJOINT_PATHS.min(seed_peers.len().max(1));
    let mut path_shortlists: Vec<BTreeMap<[u8; 32], (String, u16, String)>> =
        (0..d).map(|_| BTreeMap::new()).collect();

    for (i, (host, port, ih, dist)) in seed_peers.into_iter().enumerate() {
        path_shortlists[i % d].insert(dist, (host, port, ih));
    }

    // Run all paths in parallel
    let mut handles = Vec::new();
    for shortlist in path_shortlists.iter().take(d) {
        let shortlist = shortlist.clone();
        let state = state.clone();
        let target = *target;
        let target_hex = target_hex.clone();
        let self_hash = self_hash.clone();

        handles.push(tokio::spawn(async move {
            single_path_lookup(
                &state, &target, &target_hex, &self_hash,
                shortlist, K, MAX_ROUNDS,
            ).await
        }));
    }

    // Collect results from all paths
    let mut total_discovered = 0usize;
    for handle in handles {
        if let Ok(discovered) = handle.await {
            total_discovered += discovered;
        }
    }

    if total_discovered > 0 {
        debug!(
            "disjoint lookup ({d} paths) discovered {total_discovered} new peers (target: {}...)",
            &target_hex[..16]
        );
    }

    total_discovered
}

/// Single-path iterative lookup (used by disjoint parallel lookup).
async fn single_path_lookup(
    state: &Arc<NodeState>,
    target: &NodeId,
    target_hex: &str,
    self_hash: &str,
    mut shortlist: std::collections::BTreeMap<[u8; 32], (String, u16, String)>,
    k: usize,
    max_rounds: usize,
) -> usize {
    use std::collections::HashSet;

    let mut queried: HashSet<String> = HashSet::new();
    let mut discovered = 0usize;

    for _round in 0..max_rounds {
        // Pick up to ALPHA unqueried peers closest to target
        let to_query: Vec<(String, u16, String)> = shortlist
            .values()
            .filter(|(_, _, ih)| !queried.contains(ih))
            .take(ALPHA)
            .cloned()
            .collect();

        if to_query.is_empty() {
            break;
        }

        // Track closest unqueried distance before this round
        let closest_before = shortlist
            .iter()
            .find(|(_, (_, _, ih))| !queried.contains(ih))
            .map(|(d, _)| *d);

        // Query peers in parallel (PQ-only)
        let mut handles = Vec::new();
        for (host, port, ih) in &to_query {
            queried.insert(ih.clone());
            let base_url = peer_base_url(host, *port);
            let state_c = state.clone();
            let target_hex = target_hex.to_string();
            handles.push(tokio::spawn(async move {
                pq_find_node(&state_c, &base_url, &target_hex, k).await
            }));
        }

        // Collect results
        let mut found_closer = false;
        for handle in handles {
            if let Ok(Ok(peers)) = handle.await {
                for p in peers {
                    let ih = p["identity_hash"].as_str().unwrap_or("");
                    let h = p["host"].as_str().unwrap_or("");
                    let pt = p["port"].as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(9473);

                    if ih.is_empty() || ih == self_hash {
                        continue;
                    }
                    // Identity canonicalization guard — parity with every other
                    // untrusted peer-ingest site (announce, PEX, mDNS). This is
                    // load-bearing beyond `NodeId::from_hex` below: from_hex
                    // accepts mixed-case hex, so without this gate an uppercase
                    // variant of a real identity would enter `insert_into_dht`
                    // as a distinct string key (case-alias of one node).
                    if !super::peer::is_valid_peer_identity(ih) {
                        continue;
                    }
                    // SSRF / peer-poisoning guard: a malicious FIND_NODE response
                    // can advertise any `host`, and the discovered entry is dialed
                    // directly (shortlist re-query + `insert_into_dht`) with no
                    // re-resolution. Require a routable IP literal here just like the
                    // PEX path (`parse_peer_list`): a bare hostname would slip past
                    // is_private_or_reserved_ip (no DNS) and be dialed raw → blind SSRF.
                    if h.is_empty() || !is_dialable_wire_host(h) {
                        continue;
                    }

                    if let Some(node_id) = NodeId::from_hex(ih) {
                        let dist = node_id.distance(target);

                        if let std::collections::btree_map::Entry::Vacant(entry) = shortlist.entry(dist) {
                            entry.insert((h.to_string(), pt, ih.to_string()));
                            insert_into_dht(state, ih, h, pt);
                            discovered += 1;

                            if let Some(ref prev) = closest_before {
                                if dist < *prev {
                                    found_closer = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Trim shortlist to K entries (keep closest)
        while shortlist.len() > k * 2 {
            shortlist.pop_last();
        }

        if !found_closer {
            break;
        }
    }

    discovered
}

/// Build a peer's base URL. 4E.6: the in-process TLS server was deleted in
/// PQ-R6, so peers always advertise plain HTTP. Operators wanting public
/// HTTPS front the listener with nginx/caddy.
fn peer_base_url(host: &str, port: u16) -> String {
    format!("http://{host}:{port}")
}

/// Build the initial URL for a seed address. Supports explicit scheme
/// (`https://host:port`) — when none is given, the URL is plain `http://`.
/// 4E.6: the in-process TLS server was deleted in PQ-R6, so the node never
/// terminates HTTPS itself. Operators wanting public HTTPS front the plain
/// listener with nginx/caddy and configure seed_peers with the explicit
/// `https://...` scheme.
pub(crate) fn seed_base_url(seed_addr: &str) -> String {
    if seed_addr.starts_with("http://") || seed_addr.starts_with("https://") {
        seed_addr.trim_end_matches('/').to_string()
    } else {
        format!("http://{seed_addr}")
    }
}

/// Parse host:port from a seed address, stripping any scheme prefix.
fn parse_host_port_from_url(addr: &str) -> (String, u16) {
    let stripped = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if let Some((host, port_str)) = stripped.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(9473);
        (host.to_string(), port)
    } else {
        (stripped.to_string(), 9473)
    }
}

/// Seed reconnection loop — periodically attempts to reconnect to configured
/// seed peers that are not in the active peer table (pruned or never reached).
///
/// Uses exponential backoff per seed: 1min → 2min → 4min → 8min → 15min (cap).
pub async fn seed_reconnect_loop(
    state: Arc<NodeState>,
    mut shutdown: mpsc::Receiver<()>,
) {
    use std::collections::HashMap;
    use std::sync::atomic::Ordering::Relaxed;

    let base_interval = Duration::from_secs(60);

    if state.config.seed_peers.is_empty() {
        debug!("no seed peers — reconnect loop disabled");
        return;
    }

    // Per-seed backoff state: seed_addr → (attempt_count, next_eligible_time)
    let mut backoff: HashMap<String, (u32, f64)> = HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(base_interval) => {}
            _ = shutdown.recv() => {
                debug!("seed reconnect loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host is saturated. Reconnect tries a TCP/PQ handshake per
        // seed — non-trivial when any seed is unreachable. Better to wait
        // a beat than to compete with hot-path seal signing.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        let current_time = now();

        for seed_addr in &state.config.seed_peers {
            let base_url = seed_base_url(seed_addr);
            let (host, port) = parse_host_port_from_url(seed_addr);

            // Check backoff
            let (attempts, eligible_time) = backoff.entry(seed_addr.clone()).or_insert((0, 0.0));
            if current_time < *eligible_time {
                continue; // Not eligible yet
            }

            // Check if any connected peer has this host:port
            let already_connected = {
                let peers = state.peers.read().await;
                peers.connected().iter().any(|p| p.host == host && p.port == port)
            };
            if already_connected {
                // Reset backoff on successful connection
                *attempts = 0;
                *eligible_time = 0.0;
                continue;
            }

            // Try to reconnect
            state.peer_reconnect_attempts_total.fetch_add(1, Relaxed);
            debug!("reconnecting to seed {seed_addr} (attempt {})", *attempts + 1);

            match pq_get_status(&state, &base_url).await {
                Ok(status) => {
                    let identity_hash = status["identity_hash"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    // Reject malformed identities from the seed's /status response
                    // (attacker-controlled). This reconnect path inserts into the
                    // peer table + DHT exactly like bootstrap; downstream code
                    // byte-slices identity_hash for logs, so a short / multi-byte
                    // value would admit garbage to the table and panic a `.min(16)`
                    // slice on a multi-byte boundary. Mirrors the bootstrap guard.
                    // (is_empty is subsumed; self is 64-hex so the self-check stays.)
                    if !super::peer::is_valid_peer_identity(&identity_hash)
                        || identity_hash == state.identity.identity_hash
                    {
                        continue;
                    }

                    // Protocol version + network check
                    let peer_protocol_version = status["protocol_version"].as_u64().unwrap_or(0) as u32;
                    let min_version = state.config.min_protocol_version;
                    if min_version > 0 && peer_protocol_version < min_version {
                        warn!("seed {seed_addr} protocol version {peer_protocol_version} < min {min_version}, skipping");
                        continue;
                    }
                    let peer_network = status["network_id"].as_str().unwrap_or("testnet");
                    if peer_network != state.config.network_id {
                        warn!("seed {seed_addr} network {peer_network} != ours {}, skipping", state.config.network_id);
                        continue;
                    }

                    let node_type_str = status["node_type"].as_str().unwrap_or("leaf");
                    let pow_nonce = status["pow_nonce"].as_u64().unwrap_or(0);
                    let pow_difficulty = status["pow_difficulty"].as_u64().unwrap_or(0) as u8;
                    let public_key_hex = status["public_key_hex"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    let peer = PeerInfo {
                        identity_hash: identity_hash.clone(),
                        host: host.clone(),
                        port,
                        node_type: NodeType::from_str(node_type_str),
                        last_seen: now(),
                        state: PeerState::Connected,
                        failures: 0,
                        successes: 0,
                        valid_records: 0,
                        invalid_records: 0,
                        backoff_until: 0.0,
                        pow_nonce,
                        pow_difficulty,
                        public_key_hex,
                        provenance: super::peer::PeerProvenance::Outbound,
                    subscribed_zones: Vec::new(),
                    att_watermark: 0.0,
                    pull_failures: 0,
                    pull_backoff_until: 0.0,
                    reachable: true,
                    protocol_version: peer_protocol_version,
                    att_pull_invalid_sig: 0,
                    att_pull_invalid_powas: 0,
                    att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
                    };

                    {
                        let mut peers = state.peers.write().await;
                        peers.add_seed_peer(&identity_hash);
                        peers.insert(peer);
                    }
                    insert_into_dht(&state, &identity_hash, &host, port);
                    state.peer_reconnect_success_total.fetch_add(1, Relaxed);
                    info!("reconnected to seed {} ({})", &identity_hash[..identity_hash.len().min(16)], seed_addr);

                    // AUDIT-9 Milestone B: re-exchange on reconnect too.
                    // `has_profile` gates the PQ call so repeat reconnects are
                    // cheap once registered.
                    let peer_url_for_profile = peer_base_url(&host, port);
                    pq_exchange_profile_and_register(&state, &peer_url_for_profile, &identity_hash).await;

                    // Reset backoff
                    *attempts = 0;
                    *eligible_time = 0.0;
                }
                Err(_) => {
                    // Exponential backoff: 60s * 2^attempts, capped at 15 minutes
                    *attempts = (*attempts + 1).min(8);
                    let delay = (60.0 * 2.0_f64.powi(*attempts as i32)).min(900.0);
                    *eligible_time = current_time + delay;
                    debug!("seed {seed_addr} still unreachable, next retry in {delay:.0}s");
                }
            }
        }
    }
}

pub(super) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: deterministically expand a short, readable tag into a valid
    /// 64-hex peer identity (one that passes `super::peer::is_valid_peer_identity`).
    /// Distinct tags yield distinct identities. Fixtures predating the
    /// trust-boundary guard used short strings ("aa", "peer-01") the guard now
    /// rejects; this keeps them readable without hand-writing 64-char hex.
    fn hex64(tag: &str) -> String {
        let hex: String = tag.bytes().map(|b| format!("{b:02x}")).collect();
        let out: String = hex.chars().cycle().take(64).collect();
        debug_assert!(
            crate::network::peer::is_valid_peer_identity(&out),
            "hex64({tag:?}) must produce a valid identity"
        );
        out
    }

    #[test]
    fn b5_f3b_known_peers_never_consume_the_per_source_cap() {
        // Audit SEV-2 regression: the bootstrap path counted known-peer updates
        // toward the per-source NEW-peer cap (insert() returns true on overwrite),
        // so a source returning ≥cap already-known peers would starve discovery of
        // genuinely-new ones. Known peers MUST classify as SkipKnown regardless of
        // how many new peers have already been admitted.
        assert_eq!(classify_new_peer(true, 0), NewPeerAction::SkipKnown);
        assert_eq!(
            classify_new_peer(true, MAX_NEW_PEERS_PER_SOURCE),
            NewPeerAction::SkipKnown,
            "a known peer at/over the cap is still a no-cost refresh, never a clip",
        );
        assert_eq!(
            classify_new_peer(true, MAX_NEW_PEERS_PER_SOURCE * 100),
            NewPeerAction::SkipKnown,
        );
    }

    #[test]
    fn b5_f3b_new_peers_admitted_under_cap_then_clipped() {
        // Genuinely-new peers are admitted until the budget is exhausted, then the
        // source is clipped. The boundary is exclusive at the cap value.
        assert_eq!(classify_new_peer(false, 0), NewPeerAction::AdmitNew);
        assert_eq!(
            classify_new_peer(false, MAX_NEW_PEERS_PER_SOURCE - 1),
            NewPeerAction::AdmitNew,
            "the cap-th new peer is still admitted",
        );
        assert_eq!(
            classify_new_peer(false, MAX_NEW_PEERS_PER_SOURCE),
            NewPeerAction::Clip,
            "the (cap+1)-th new peer is clipped",
        );
    }

    #[tokio::test]
    async fn test_dns_resolve_localhost() {
        // localhost should resolve but IPs should be filtered as private
        let config = super::super::config::NodeConfig {
            dns_seeds: vec!["localhost".to_string()],
            dns_seed_port: 9473,
            ..Default::default()
        };
        let resolved = resolve_dns_seeds(&config).await;
        // All localhost IPs are private/loopback → should be filtered out
        assert!(resolved.is_empty(), "localhost IPs should be filtered: {resolved:?}");
    }

    #[tokio::test]
    async fn test_dns_resolve_nonexistent() {
        // Non-existent domain should fail gracefully
        let config = super::super::config::NodeConfig {
            dns_seeds: vec!["this-domain-does-not-exist-elara-test.invalid".to_string()],
            dns_seed_port: 9473,
            ..Default::default()
        };
        let resolved = resolve_dns_seeds(&config).await;
        assert!(resolved.is_empty(), "nonexistent domain should return empty");
    }

    #[tokio::test]
    async fn test_dns_resolve_empty_seeds() {
        let config = super::super::config::NodeConfig {
            dns_seeds: vec![],
            dns_seed_port: 9473,
            ..Default::default()
        };
        let resolved = resolve_dns_seeds(&config).await;
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_dns_resolve_deduplicates_existing() {
        // If DNS resolves an IP that's already in seed_peers, it shouldn't be added
        let config = super::super::config::NodeConfig {
            dns_seeds: vec!["localhost".to_string()],
            dns_seed_port: 9473,
            seed_peers: vec!["http://127.0.0.1:9473".to_string()],
            ..Default::default()
        };
        let resolved = resolve_dns_seeds(&config).await;
        // Even if localhost resolved, it's either private-filtered or deduped
        assert!(resolved.is_empty());
    }

    // Lock in the three sync pure-fn helpers that
    // gate the peer-discovery path. `is_private_or_reserved_ip` is the load-
    // bearing anti-peer-poisoning filter (a regression here lets a hostile
    // /peers response inject 192.168.0.0/16 entries into the DHT and partition
    // the cluster); `parse_peer_list` is the composite skip-gate that calls
    // it; `peer_base_url` + `parse_host_port_from_url` round-trip together
    // and feed the seed_reconnect_loop's exponential-backoff lookup table.

    #[test]
    fn batch_aa_is_private_or_reserved_ip_blocks_all_five_reserved_classes_allows_public_and_hostname() {
        // Pins the 6-way classifier at discovery.rs:140. Each reserved class
        // is the anti-poisoning rejection a hostile /peers response would
        // otherwise slip past: loopback bypasses the host's PQ identity
        // pinning, RFC1918 private space partitions clusters along NAT
        // boundaries, link-local is autoconf garbage, broadcast/unspecified
        // hijack peering. Public IPs (v4 and v6) and hostnames MUST fall
        // through to `false` so legitimate seeds work; non-routable IPv6
        // (loopback/ULA/link-local/unspecified) now rejects too (audit 16j).
        // Loopback 127.0.0.0/8
        assert!(is_private_or_reserved_ip("127.0.0.1"), "127.0.0.1 must reject");
        assert!(is_private_or_reserved_ip("127.255.255.254"), "127.255.255.254 must reject");
        // RFC1918 private (all three blocks)
        assert!(is_private_or_reserved_ip("10.0.0.1"), "10/8 must reject");
        assert!(is_private_or_reserved_ip("172.16.0.1"), "172.16/12 must reject");
        assert!(is_private_or_reserved_ip("192.168.1.1"), "192.168/16 must reject");
        // Link-local 169.254/16
        assert!(is_private_or_reserved_ip("169.254.1.1"), "169.254/16 must reject");
        // Broadcast + unspecified
        assert!(is_private_or_reserved_ip("255.255.255.255"), "broadcast must reject");
        assert!(is_private_or_reserved_ip("0.0.0.0"), "unspecified must reject");
        // 0.0.0.0/8 "this network" beyond the bare 0.0.0.0 — a non-zero 0.x can map
        // to localhost on some stacks, so the whole /8 rejects (not just is_unspecified).
        assert!(is_private_or_reserved_ip("0.1.2.3"), "0.0.0.0/8 this-network must reject");
        assert!(is_private_or_reserved_ip("0.255.255.255"), "0.0.0.0/8 upper bound must reject");
        // IPv4 multicast 224.0.0.0/4 — never a unicast peer (dead TCP dial), reject.
        assert!(is_private_or_reserved_ip("224.0.0.251"), "multicast must reject");
        assert!(is_private_or_reserved_ip("239.255.255.250"), "multicast upper must reject");
        // Public IPv4 — must NOT reject
        assert!(!is_private_or_reserved_ip("8.8.8.8"), "8.8.8.8 must pass");
        assert!(!is_private_or_reserved_ip("203.0.113.7"), "public IP must pass");
        // Non-IPv4 input falls through to false (hostname / IPv6 / garbage).
        // This base filter deliberately still ALLOWS hostnames; the "reject
        // hostnames too" contract the old note anticipated is now realized by
        // `is_dialable_wire_host` (literal-only) at the untrusted call sites —
        // see `ssrf_is_dialable_wire_host_requires_routable_ip_literal`.
        assert!(!is_private_or_reserved_ip("seed.elara.example"), "hostname falls through to allow");
        assert!(!is_private_or_reserved_ip(""), "empty string falls through to allow");
        assert!(!is_private_or_reserved_ip("not-an-ip"), "garbage falls through to allow");
        // IPv6 non-routable classes MUST reject (audit 16j — previously these
        // fell through to allow, letting an IPv6 peer bypass the filter).
        assert!(is_private_or_reserved_ip("::1"), "IPv6 loopback must reject");
        assert!(is_private_or_reserved_ip("::"), "IPv6 unspecified must reject");
        assert!(is_private_or_reserved_ip("fc00::1"), "IPv6 ULA fc00::/7 must reject");
        assert!(is_private_or_reserved_ip("fd12:3456::1"), "IPv6 ULA fd00 must reject");
        assert!(is_private_or_reserved_ip("fe80::1"), "IPv6 link-local fe80::/10 must reject");
        assert!(is_private_or_reserved_ip("febf::1"), "IPv6 link-local upper bound must reject");
        // Public/global IPv6 MUST pass (legitimate seeds).
        assert!(!is_private_or_reserved_ip("2606:4700:4700::1111"), "public IPv6 must pass");
        assert!(!is_private_or_reserved_ip("2001:db8::1"), "global-unicast IPv6 must pass");
    }

    #[test]
    fn ssrf_is_dialable_wire_host_requires_routable_ip_literal() {
        // Closes the hostname sibling of the 15dadd33 IPv4-mapped/NAT64 literal
        // SSRF: an UNTRUSTED wire host (PEX `parse_peer_list`, FIND_NODE
        // `single_path_lookup`, or the `x-elara-host` header) is dialed raw with
        // no resolve-then-recheck, so a hostname resolving to a reserved IP would
        // be a blind SSRF. The gate admits ONLY a routable IP literal.

        // Hostnames / non-literals → reject. These all PASS the base
        // is_private_or_reserved_ip filter, so this is the new line of defense.
        assert!(!is_dialable_wire_host("evil.example"), "hostname must reject");
        assert!(!is_dialable_wire_host("metadata.google.internal"), "metadata hostname must reject");
        assert!(!is_dialable_wire_host("seed.elara.example"), "any hostname must reject on the wire path");
        assert!(!is_dialable_wire_host(""), "empty must reject");
        assert!(!is_dialable_wire_host("not-an-ip"), "garbage must reject");
        assert!(!is_dialable_wire_host("1.2.3.4:9000"), "host-with-port is not a bare literal → reject");
        assert!(!is_dialable_wire_host("[::1]"), "bracketed IPv6 fails parse → reject (safe outcome)");
        assert!(!is_dialable_wire_host("fe80::1%eth0"), "zone-id IPv6 fails parse → reject (safe outcome)");

        // Reserved literals still reject (folds in is_private_or_reserved_ip,
        // incl. the IPv4-mapped / NAT64 forms closed in 15dadd33).
        assert!(!is_dialable_wire_host("127.0.0.1"), "loopback must reject");
        assert!(!is_dialable_wire_host("10.0.0.1"), "RFC1918 must reject");
        assert!(!is_dialable_wire_host("192.168.1.1"), "RFC1918 must reject");
        assert!(!is_dialable_wire_host("169.254.169.254"), "cloud-metadata must reject");
        assert!(!is_dialable_wire_host("::1"), "IPv6 loopback must reject");
        assert!(!is_dialable_wire_host("::ffff:169.254.169.254"), "IPv4-mapped metadata must reject");
        assert!(!is_dialable_wire_host("64:ff9b::169.254.169.254"), "NAT64 metadata must reject");

        // Routable public literals → allow (must NOT partition legitimate peers).
        assert!(is_dialable_wire_host("8.8.8.8"), "public IPv4 must pass");
        assert!(is_dialable_wire_host("203.0.113.7"), "public IPv4 must pass");
        assert!(is_dialable_wire_host("2606:4700:4700::1111"), "public IPv6 must pass");
        // Tailscale CGNAT 100.64/10 — the live fleet dials peers in this range; MUST pass.
        // Bracket the whole /10 with synthetic edge literals (no real fleet host here —
        // a real Tailscale IP in shipped source leaks into the public mirror).
        assert!(is_dialable_wire_host("100.64.0.1"), "Tailscale CGNAT lower edge must pass");
        assert!(is_dialable_wire_host("100.127.255.254"), "Tailscale CGNAT upper edge must pass");
    }

    #[test]
    fn ssrf_parse_peer_list_drops_hostname_and_reserved_keeps_public_literal() {
        // Path-level proof the is_dialable_wire_host gate is wired into the PEX
        // parser (not merely unit-tested in isolation): a hostname peer AND a
        // cloud-metadata literal in a hostile /peers response — both of which
        // would otherwise resolve+dial raw → SSRF — are dropped, while the
        // public IP-literal peer alongside them survives. Guards against a
        // refactor silently reverting the call site to the base filter.
        let data = serde_json::json!({
            "peers": [
                { "identity_hash": hex64("aaaa1111"), "host": "evil.example",
                  "port": 9473, "protocol_version": 5 },
                { "identity_hash": hex64("bbbb2222"), "host": "169.254.169.254",
                  "port": 9473, "protocol_version": 5 },
                { "identity_hash": hex64("cccc3333"), "host": "8.8.8.8",
                  "port": 9473, "protocol_version": 5 },
            ]
        });
        let kept = parse_peer_list(&data, &hex64("self-hash-xyz"), 5);
        assert_eq!(kept.len(), 1, "only the public IP literal survives the wire gate");
        assert_eq!(kept[0].host, "8.8.8.8");
    }

    #[test]
    fn ipv4_mapped_and_nat64_ipv6_forms_of_reserved_ranges_must_reject() {
        // SSRF / peer-poisoning hardening: a reserved IPv4 wrapped in an IPv6
        // literal (IPv4-mapped `::ffff:0:0/96` or NAT64 `64:ff9b::/96`) previously
        // bypassed the filter — `is_loopback()`/the ULA+link-local prefix checks
        // all miss it because seg0 is 0x0000. The dial path resolves the unbracketed
        // literal via getaddrinfo and connects, so this was a reachable bypass.
        // IPv4-mapped reserved forms — MUST reject.
        assert!(is_private_or_reserved_ip("::ffff:127.0.0.1"), "mapped loopback must reject");
        assert!(is_private_or_reserved_ip("::ffff:169.254.169.254"), "mapped cloud-metadata must reject");
        assert!(is_private_or_reserved_ip("::ffff:10.0.0.5"), "mapped 10/8 must reject");
        assert!(is_private_or_reserved_ip("::ffff:172.16.0.1"), "mapped 172.16/12 must reject");
        assert!(is_private_or_reserved_ip("::ffff:192.168.1.1"), "mapped 192.168/16 must reject");
        assert!(is_private_or_reserved_ip("::ffff:255.255.255.255"), "mapped broadcast must reject");
        assert!(is_private_or_reserved_ip("::ffff:0.0.0.0"), "mapped unspecified must reject");
        // NAT64 64:ff9b::/96 wrapping a reserved IPv4 — MUST reject.
        assert!(is_private_or_reserved_ip("64:ff9b::169.254.169.254"), "NAT64 cloud-metadata must reject");
        assert!(is_private_or_reserved_ip("64:ff9b::127.0.0.1"), "NAT64 loopback must reject");
        // IPv4-mapped PUBLIC addr maps to a public IPv4 — MUST pass (no false reject).
        assert!(!is_private_or_reserved_ip("::ffff:8.8.8.8"), "mapped public must pass");
        // Native ::1 must still reject and must NOT be mis-handled by to_ipv4_mapped
        // (which returns None for ::1, so the native is_loopback() branch catches it).
        assert!(is_private_or_reserved_ip("::1"), "native ::1 still rejects");
    }

    #[test]
    fn batch_aa_parse_peer_list_skips_self_empty_host_private_ip_and_low_protocol_version() {
        // Pins the 4-way skip-gate at discovery.rs:155. The composite filter
        // is the peer-poisoning defense: identity_hash=self prevents loops,
        // empty fields drop malformed entries, is_private_or_reserved_ip
        // rejects RFC1918 injections, protocol_version<min drops stale-version
        // peers that would corrupt newer wire formats. A regression that
        // dropped any one of these gates would leak that class into the DHT.
        let data = serde_json::json!({
            "peers": [
                // 0. Valid public peer — must be kept
                {
                    "identity_hash": hex64("aaaa1111"), "host": "8.8.8.8",
                    "port": 9473, "protocol_version": 5,
                    "node_type": "leaf", "pow_nonce": 0, "pow_difficulty": 0,
                    "public_key_hex": "deadbeef"
                },
                // 1. Self_hash — must be skipped (valid identity, so the
                //    self-equality gate is what drops it, not the format guard)
                { "identity_hash": hex64("self-hash-xyz"), "host": "203.0.113.7",
                  "port": 9473, "protocol_version": 5 },
                // 2. Empty identity_hash — must be skipped (format guard)
                { "identity_hash": "", "host": "203.0.113.7",
                  "port": 9473, "protocol_version": 5 },
                // 3. Empty host — must be skipped (valid identity isolates the
                //    empty-host gate as the reason)
                { "identity_hash": hex64("bbbb2222"), "host": "",
                  "port": 9473, "protocol_version": 5 },
                // 4. Private/RFC1918 host — must be skipped
                { "identity_hash": hex64("cccc3333"), "host": "192.168.1.10",
                  "port": 9473, "protocol_version": 5 },
                // 5. Protocol version below min — must be skipped
                { "identity_hash": hex64("dddd4444"), "host": "1.1.1.1",
                  "port": 9473, "protocol_version": 3 },
                // 6. Another valid public peer — must be kept (sanity: gate
                //    doesn't accidentally short-circuit after first reject)
                { "identity_hash": hex64("eeee5555"), "host": "9.9.9.9",
                  "port": 8080, "protocol_version": 5 },
            ]
        });
        let kept = parse_peer_list(&data, &hex64("self-hash-xyz"), 5);
        assert_eq!(kept.len(), 2, "exactly the two public peers ≥min_proto must survive");
        assert_eq!(kept[0].identity_hash, hex64("aaaa1111"));
        assert_eq!(kept[0].host, "8.8.8.8");
        assert_eq!(kept[0].port, 9473);
        assert_eq!(kept[0].protocol_version, 5);
        assert_eq!(kept[1].identity_hash, hex64("eeee5555"));
        assert_eq!(kept[1].host, "9.9.9.9");
        assert_eq!(kept[1].port, 8080);

        // No "peers" array at all → empty Vec (not a panic). Defensive guard
        // against a misshapen /peers JSON body that doesn't carry the key.
        let no_peers = serde_json::json!({});
        assert!(parse_peer_list(&no_peers, &hex64("self-hash-xyz"), 5).is_empty());

        // min_protocol_version=0 disables the version gate — keeps the
        // pre-protocol-version peers on the wire (the `if min > 0` guard
        // at L171 is what enables backwards-compat with pre-5 nodes).
        let pre_v5_only = serde_json::json!({
            "peers": [
                { "identity_hash": hex64("old1"), "host": "1.1.1.1",
                  "port": 9473, "protocol_version": 0 },
                { "identity_hash": hex64("old2"), "host": "2.2.2.2",
                  "port": 9473 },  // protocol_version absent entirely → 0
            ]
        });
        assert_eq!(
            parse_peer_list(&pre_v5_only, &hex64("self-hash-xyz"), 0).len(),
            2,
            "min_protocol_version=0 must disable the version gate"
        );
    }

    #[test]
    fn batch_aa_peer_base_url_and_parse_host_port_round_trip_with_and_without_scheme_prefix() {
        // Pins the two URL helpers that bracket the seed-reconnect loop at
        // discovery.rs:966+. `peer_base_url` is the canonical writer used
        // by every outbound connect; `parse_host_port_from_url` is the
        // canonical reader used by the seed-reconnect lookup table. The
        // round-trip is the load-bearing invariant — if either side drifts,
        // the seed-reconnect loop's per-seed exponential-backoff map keys
        // diverge from the active peer-table keys and the same seed gets
        // re-attempted at the cap-15-min cadence forever.

        // Writer: always emits `http://host:port` form.
        assert_eq!(peer_base_url("8.8.8.8", 9473), "http://8.8.8.8:9473");
        assert_eq!(peer_base_url("seed.elara.example", 8080), "http://seed.elara.example:8080");
        // Even with the loopback host, the writer doesn't second-guess —
        // the caller is expected to have already passed is_private_or_reserved_ip
        // (caller-side gate, not writer-side).
        assert_eq!(peer_base_url("127.0.0.1", 9474), "http://127.0.0.1:9474");

        // Reader: strips scheme prefix + trailing slash, splits at the LAST
        // colon (rsplit_once) so IPv6-literal-with-port shapes parse the
        // port off the right edge.
        assert_eq!(
            parse_host_port_from_url("8.8.8.8:9473"),
            ("8.8.8.8".to_string(), 9473),
            "bare host:port must parse"
        );
        assert_eq!(
            parse_host_port_from_url("http://8.8.8.8:9473"),
            ("8.8.8.8".to_string(), 9473),
            "http:// scheme must be stripped"
        );
        assert_eq!(
            parse_host_port_from_url("https://seed.elara.example:8080/"),
            ("seed.elara.example".to_string(), 8080),
            "https:// scheme + trailing slash must both be stripped"
        );
        // Missing port → 9473 default (the protocol default port). Catches
        // a regression where the helper started returning 0 or 80 from a
        // schemeless input — both would silently misroute every seed.
        assert_eq!(
            parse_host_port_from_url("8.8.8.8"),
            ("8.8.8.8".to_string(), 9473),
            "missing port must default to 9473 (protocol default)"
        );
        // Malformed port → also defaults to 9473 (the `.parse().ok()` →
        // `.unwrap_or(9473)` path at L955). A regression that switched to
        // `.expect()` would panic the seed_reconnect_loop on first bad URL.
        assert_eq!(
            parse_host_port_from_url("8.8.8.8:NOTAPORT"),
            ("8.8.8.8".to_string(), 9473),
            "malformed port must default to 9473, not panic"
        );

        // Round-trip: writer → reader recovers the original (host, port).
        for (host, port) in [
            ("8.8.8.8", 9473u16),
            ("203.0.113.7", 9473),
            ("seed.elara.example", 8080),
            ("1.1.1.1", 80),
        ] {
            let url = peer_base_url(host, port);
            let (h2, p2) = parse_host_port_from_url(&url);
            assert_eq!(h2, host, "host must round-trip through peer_base_url / parse_host_port_from_url");
            assert_eq!(p2, port, "port must round-trip through peer_base_url / parse_host_port_from_url");
        }
    }

    // ─── additional seam pins ─────────────────────────────────────────────
    //
    // The four core helpers (is_private_or_reserved_ip, parse_peer_list
    // skip-gates, peer_base_url + parse_host_port_from_url round-trip) are
    // covered above. These pin three uncovered seams: seed_base_url
    // scheme handling, parse_peer_list PeerInfo-construction defaults,
    // and node_type field-mapping fallthrough.

    /// `seed_base_url` is the canonical seed-URL normalizer used by
    /// bootstrap + seed_reconnect_loop. The TLS-deletion comment at L934-939
    /// is wire-shape critical: bare `host:port` MUST emit `http://` (plain
    /// listener), explicit `https://` MUST survive (for operator-fronted
    /// caddy/nginx HTTPS), trailing slashes MUST be stripped so two seed
    /// entries that differ only by a final `/` collapse to one map key in
    /// the seed-reconnect exponential-backoff table.
    #[test]
    fn batch_ab_seed_base_url_pins_all_scheme_paths_and_trailing_slash_strip() {
        // 1. Bare host:port → http:// is prepended.
        assert_eq!(
            seed_base_url("8.8.8.8:9473"),
            "http://8.8.8.8:9473",
            "schemeless seed must default to http://"
        );
        assert_eq!(
            seed_base_url("seed.elara.example:8080"),
            "http://seed.elara.example:8080",
            "schemeless hostname seed must default to http://"
        );

        // 2. Explicit http:// is preserved verbatim.
        assert_eq!(
            seed_base_url("http://8.8.8.8:9473"),
            "http://8.8.8.8:9473",
            "explicit http:// must round-trip"
        );

        // 3. Explicit https:// is preserved — operator fronts with TLS proxy.
        assert_eq!(
            seed_base_url("https://seed.elara.example:443"),
            "https://seed.elara.example:443",
            "explicit https:// must survive (caddy/nginx-fronted operator path)"
        );

        // 4. Trailing slash stripped from both schemes — collapses near-dupes
        //    in the seed-reconnect backoff map.
        assert_eq!(
            seed_base_url("http://8.8.8.8:9473/"),
            "http://8.8.8.8:9473",
            "trailing slash must be stripped from http:// form"
        );
        assert_eq!(
            seed_base_url("https://seed.elara.example:443/"),
            "https://seed.elara.example:443",
            "trailing slash must be stripped from https:// form"
        );
    }

    /// `parse_peer_list` happy-path PeerInfo construction. The skip-gates
    /// and a subset of fields (identity_hash/host/port/
    /// protocol_version). This pins the rest of the construction: the
    /// initial-state defaults (`PeerState::Stale`, zero counters), the
    /// peer-provenance label (`Outbound` — sets the right inbound/outbound
    /// quota for the rate limiter), and JSON-field propagation for the
    /// trust-bookkeeping fields (`pow_nonce`, `pow_difficulty`, `public_key_hex`).
    #[test]
    fn batch_ab_parse_peer_list_happy_path_pins_peerinfo_construction_defaults() {
        let data = serde_json::json!({
            "peers": [{
                "identity_hash": hex64("a1b2c3d4"),
                "host": "203.0.113.7",
                "port": 9473,
                "protocol_version": 5,
                "node_type": "witness",
                "pow_nonce": 12_345u64,
                "pow_difficulty": 18u64,
                "public_key_hex": "AABBCCDD"
            }]
        });
        let kept = parse_peer_list(&data, "self-hash-xyz", 5);
        assert_eq!(kept.len(), 1, "single valid peer must survive");
        let p = &kept[0];

        // Initial-state defaults — load-bearing: a peer that came in with
        // failures>0 or successes>0 would skip the freshness handshake and
        // immediately be promoted to Connected on stale evidence.
        assert!(matches!(p.state, crate::network::peer::PeerState::Stale),
            "newly parsed peer must enter at PeerState::Stale");
        assert_eq!(p.failures, 0);
        assert_eq!(p.successes, 0);
        assert_eq!(p.valid_records, 0);
        assert_eq!(p.invalid_records, 0);
        assert!((p.backoff_until - 0.0).abs() < 1e-9);
        assert!(p.last_seen > 0.0, "last_seen must be initialized to current time, not 0");

        // Provenance label — Outbound means "we learned this peer from a
        // /peers response, not from an inbound connection". The rate limiter
        // uses this to bucket the per-direction concurrent-connect cap.
        assert!(matches!(p.provenance, crate::network::peer::PeerProvenance::Outbound),
            "peers parsed from a /peers response are Outbound provenance");

        // Trust-bookkeeping field propagation — these are the PoW-attestation
        // credentials the witness gate checks. A regression that zeroed any
        // of them would mass-evict every existing witness on the next refresh.
        assert_eq!(p.pow_nonce, 12_345);
        assert_eq!(p.pow_difficulty, 18);
        assert_eq!(p.public_key_hex, "AABBCCDD");
    }

    /// `node_type` JSON-field mapping inside `parse_peer_list`. The unwrap_or
    /// at L177-180 maps an absent or unknown `node_type` string to
    /// `NodeType::Leaf` — that's the safe default (no relay, no witness,
    /// no seal authority). Pins that "witness" maps to Witness and that
    /// unknown / absent strings fall through to Leaf rather than panic.
    #[test]
    fn batch_ab_parse_peer_list_node_type_unknown_or_absent_falls_through_to_leaf() {
        use crate::network::peer::NodeType;
        let data = serde_json::json!({
            "peers": [
                // Known type — witness.
                { "identity_hash": hex64("aa"), "host": "8.8.8.8", "port": 9473,
                  "protocol_version": 5, "node_type": "witness" },
                // Unknown type — must default to Leaf, NOT panic.
                { "identity_hash": hex64("bb"), "host": "8.8.4.4", "port": 9473,
                  "protocol_version": 5, "node_type": "frobnicator" },
                // node_type absent entirely — also default to Leaf.
                { "identity_hash": hex64("cc"), "host": "1.1.1.1", "port": 9473,
                  "protocol_version": 5 },
                // Known type — anchor (epoch seal authority).
                { "identity_hash": hex64("dd"), "host": "9.9.9.9", "port": 9473,
                  "protocol_version": 5, "node_type": "anchor" },
            ]
        });
        let kept = parse_peer_list(&data, "self", 5);
        assert_eq!(kept.len(), 4, "all four valid peers must survive (node_type is not a skip-gate)");
        assert!(matches!(kept[0].node_type, NodeType::Witness),
            "explicit 'witness' must map to NodeType::Witness");
        assert!(matches!(kept[1].node_type, NodeType::Leaf),
            "unknown node_type must fall through to NodeType::Leaf (safe default)");
        assert!(matches!(kept[2].node_type, NodeType::Leaf),
            "absent node_type must default to NodeType::Leaf");
        assert!(matches!(kept[3].node_type, NodeType::Anchor),
            "explicit 'anchor' must map to NodeType::Anchor");
    }

    // Pin the sync DHT-insert helper that previously had ZERO direct test
    // coverage despite being the canonical
    // entry point for every non-eviction insert path. `insert_into_dht`
    // (Outbound) is called from the `/peers` PEX merge at L607 and the
    // seed-handshake at L1090; `insert_into_dht_pub` (Inbound) is called
    // from the mDNS LAN-peer discoverer. A regression in either bypass
    // (self-skip or hex-validation) would let a hostile /peers response
    // poison the DHT — either with a pull-from-self loopback or with
    // garbage NodeIds that the closest_to_record routing then fans out to.
    fn build_test_state_for_dht_insert() -> (std::sync::Arc<NodeState>, tempfile::TempDir) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "batch-ac-dht-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    #[test]
    fn batch_ac_insert_into_dht_inner_skips_self_identity_hash() {
        // Pins the L702 string-equality early-return guard. NAT-loopback
        // defense: a /peers response that lists `self` MUST NOT add self
        // to the local DHT, or the next gossip cycle pulls from self.
        let (state, _tmp) = build_test_state_for_dht_insert();
        assert_eq!(state.dht.lock_recover().len(), 0, "fresh DHT must be empty");

        let self_hash = state.identity.identity_hash.clone();
        super::insert_into_dht(&state, &self_hash, "8.8.8.8", 9473);

        assert_eq!(
            state.dht.lock_recover().len(),
            0,
            "DHT must remain empty after attempting to insert self_hash"
        );
        assert!(
            state.dht.lock_recover().find_by_identity(&self_hash).is_none(),
            "find_by_identity must NOT return self after self-insert attempt"
        );

        // Same contract via the Inbound wrapper — both paths share the
        // pre-construction string check.
        super::insert_into_dht_pub(&state, &self_hash, "10.0.0.1", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            0,
            "insert_into_dht_pub must also skip self_hash"
        );
    }

    #[test]
    fn batch_ac_insert_into_dht_inner_rejects_invalid_hex() {
        // Pins the L705 `NodeId::from_hex` None-branch silent-skip. A
        // malformed identity_hash (corrupted JSON field, hostile garbage,
        // wrong byte length) MUST NOT panic and MUST NOT insert a degenerate
        // peer. Three rejection shapes: non-hex chars, short hex (16 chars
        // = 8 bytes ≠ 32), long hex (130 chars = 65 bytes ≠ 32). The DHT's
        // closest_to_record routing relies on NodeId being exactly 32 bytes
        // for the XOR-distance comparator to be well-defined.
        let (state, _tmp) = build_test_state_for_dht_insert();
        assert_eq!(state.dht.lock_recover().len(), 0);

        // Non-hex characters — `hex::decode` returns Err.
        super::insert_into_dht(&state, "not-a-hex-string", "8.8.8.8", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            0,
            "non-hex identity_hash must silently skip"
        );

        // Hex too short — `hex::decode` succeeds but byte len != 32.
        super::insert_into_dht(&state, "aabbccdd", "8.8.8.8", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            0,
            "short hex identity_hash must silently skip (len != 32 bytes)"
        );

        // Hex too long — 130 chars = 65 bytes != 32.
        let long_hex = "ab".repeat(65);
        super::insert_into_dht(&state, &long_hex, "8.8.8.8", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            0,
            "long hex identity_hash must silently skip (len != 32 bytes)"
        );
    }

    #[test]
    fn batch_ac_insert_into_dht_outbound_wrapper_pins_provenance_label() {
        // Pins the L619-621 wrapper contract: `insert_into_dht` MUST stamp
        // `PeerProvenance::Outbound` on every peer it inserts. Outbound
        // provenance is the rate-limit bucket for "we initiated the contact
        // via a /peers fetch", and the closest_prefer_outbound routing
        // selector at L345 ties content-routing preference to this label.
        // A regression that flipped the default to Inbound would re-bucket
        // every PEX peer into the inbound-quota half of the rate limiter
        // and starve the seed-reconnect path.
        let (state, _tmp) = build_test_state_for_dht_insert();
        let peer_hex = "11".repeat(32); // 64 hex chars = 32 bytes, valid

        super::insert_into_dht(&state, &peer_hex, "203.0.113.7", 9473);

        let dht = state.dht.lock_recover();
        assert_eq!(dht.len(), 1, "valid peer must land in DHT");
        let found = dht
            .find_by_identity(&peer_hex)
            .expect("peer must be findable by identity_hash");
        assert_eq!(found.identity_hash, peer_hex);
        assert_eq!(found.host, "203.0.113.7");
        assert_eq!(found.port, 9473);
        assert!(
            matches!(found.provenance, super::PeerProvenance::Outbound),
            "insert_into_dht must stamp Outbound provenance"
        );
    }

    #[test]
    fn batch_ac_insert_into_dht_pub_inbound_wrapper_pins_provenance_label() {
        // Pins the L624-626 `insert_into_dht_pub` wrapper contract — mDNS
        // and LAN-discovered peers MUST carry `PeerProvenance::Inbound` so
        // they bucket into the inbound-quota rate limiter and DO NOT win
        // ties against PEX peers in the closest_prefer_outbound selector.
        // (Inbound is the conservative bucket — a LAN peer that announced
        // itself via mDNS hasn't been validated through the PEX handshake
        // gauntlet.)
        let (state, _tmp) = build_test_state_for_dht_insert();
        let peer_hex = "22".repeat(32);

        super::insert_into_dht_pub(&state, &peer_hex, "203.0.113.8", 9473);

        let dht = state.dht.lock_recover();
        assert_eq!(dht.len(), 1, "valid LAN peer must land in DHT");
        let found = dht
            .find_by_identity(&peer_hex)
            .expect("peer must be findable by identity_hash");
        assert!(
            matches!(found.provenance, super::PeerProvenance::Inbound),
            "insert_into_dht_pub must stamp Inbound provenance"
        );
        assert_eq!(found.host, "203.0.113.8");
        assert_eq!(found.port, 9473);
    }

    #[test]
    fn batch_ac_insert_into_dht_inner_dedupes_repeat_inserts_by_node_id() {
        // Pins the bucket-level dedupe at dht.rs:185 — re-inserting the
        // same identity_hash MUST keep `dht.len() == 1` (NodeId-keyed
        // dedupe with first_added preservation). Two distinct identity
        // hashes MUST both land. This is the contract the seed-reconnect
        // loop relies on: a seed peer that we re-discover via /peers
        // doesn't double-count or evict its own LRU entry.
        let (state, _tmp) = build_test_state_for_dht_insert();
        let hex_a = "33".repeat(32);
        let hex_b = "44".repeat(32);

        super::insert_into_dht(&state, &hex_a, "203.0.113.7", 9473);
        assert_eq!(state.dht.lock_recover().len(), 1, "first insert: 1 peer");

        // Re-insert same identity_hash — should dedupe by NodeId.
        super::insert_into_dht(&state, &hex_a, "203.0.113.7", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            1,
            "repeat insert of same identity_hash must NOT double-count"
        );

        // Distinct identity_hash — should add as second entry.
        super::insert_into_dht(&state, &hex_b, "8.8.8.8", 9473);
        assert_eq!(
            state.dht.lock_recover().len(),
            2,
            "distinct identity_hash must land as a separate entry"
        );

        // Both findable.
        let dht = state.dht.lock_recover();
        assert!(dht.find_by_identity(&hex_a).is_some(), "peer A retrievable");
        assert!(dht.find_by_identity(&hex_b).is_some(), "peer B retrievable");
    }

    // ─── adjacency / boundary / defect-capture pins ───────────────────────
    //
    // The tests above cover the happy paths of each helper; these 5 pin
    // **adjacency / boundary / defect-capture** axes that no prior test
    // reaches — exactly the surface a sloppy refactor would silently break.
    //
    //   1. is_private_or_reserved_ip — adjacency precision at every reserved-
    //      class edge (9.255.255.255 vs 10.0.0.0, 11.0.0.0 vs 10.255.255.255,
    //      etc.). Pins the std::net Ipv4Addr classifier ranges so a future
    //      stdlib drift or hand-rolled replacement reproduces the exact cut.
    //   2. parse_peer_list — port boundary contract: u16::try_from on u64.
    //      port=0 / 65535 kept; port=65536 rejected → default 9473.
    //   3. parse_host_port_from_url — IPv6-literal current behavior is
    //      buggy (rsplit_once on ':' eats the literal). Captures the defect
    //      so a future IPv6 fix arrives as a test diff, not a silent change.
    //   4. seed_base_url — scheme match is case-sensitive `starts_with`.
    //      `Http://`/`HTTPS://` fall to the no-scheme branch and get a
    //      second `http://` prepended → defect-pin so a future case-insens.
    //      fix surfaces as a test diff.
    //   5. parse_peer_list — `peers` field non-array (string/number/object)
    //      or missing entirely returns empty Vec, never panics. Pins the
    //      `as_array()`-returns-None silent-skip across all non-array shapes.

    #[test]
    fn batch_ad_is_private_or_reserved_ip_boundary_precision_at_reserved_class_edges() {
        // 10/8 boundary: 9.255.255.255 is PUBLIC, 10.0.0.0 is PRIVATE,
        // 10.255.255.255 is PRIVATE, 11.0.0.0 is PUBLIC. A future hand-rolled
        // classifier that used `<= 10` (vs the stdlib `0x0A000000..=0x0AFFFFFF`)
        // would silently misclassify 10.0.0.0 itself or leak 11.0.0.0.
        assert!(!is_private_or_reserved_ip("9.255.255.255"), "9.255.255.255 just below 10/8 = public");
        assert!(is_private_or_reserved_ip("10.0.0.0"), "10.0.0.0 lower edge of 10/8 = private");
        assert!(is_private_or_reserved_ip("10.255.255.255"), "10.255.255.255 upper edge of 10/8 = private");
        assert!(!is_private_or_reserved_ip("11.0.0.0"), "11.0.0.0 just above 10/8 = public");

        // 172.16/12 boundary: spans 172.16.0.0 through 172.31.255.255.
        assert!(!is_private_or_reserved_ip("172.15.255.255"), "172.15.255.255 just below 172.16/12 = public");
        assert!(is_private_or_reserved_ip("172.16.0.0"), "172.16.0.0 lower edge = private");
        assert!(is_private_or_reserved_ip("172.31.255.255"), "172.31.255.255 upper edge = private");
        assert!(!is_private_or_reserved_ip("172.32.0.0"), "172.32.0.0 just above 172.16/12 = public");

        // 192.168/16 boundary.
        assert!(!is_private_or_reserved_ip("192.167.255.255"), "192.167.255.255 below 192.168/16 = public");
        assert!(is_private_or_reserved_ip("192.168.0.0"), "192.168.0.0 lower edge = private");
        assert!(is_private_or_reserved_ip("192.168.255.255"), "192.168.255.255 upper edge = private");
        assert!(!is_private_or_reserved_ip("192.169.0.0"), "192.169.0.0 above 192.168/16 = public");

        // 169.254/16 link-local boundary.
        assert!(!is_private_or_reserved_ip("169.253.255.255"), "169.253.255.255 below link-local = public");
        assert!(is_private_or_reserved_ip("169.254.0.0"), "169.254.0.0 lower edge link-local = reject");
        assert!(is_private_or_reserved_ip("169.254.255.255"), "169.254.255.255 upper edge link-local = reject");
        assert!(!is_private_or_reserved_ip("169.255.0.0"), "169.255.0.0 above link-local = public");

        // 127/8 loopback — only first byte matters. 128.0.0.0 is the lower
        // edge of the historical "class B" public space and MUST pass.
        assert!(is_private_or_reserved_ip("127.255.255.255"), "127.255.255.255 upper edge loopback = reject");
        assert!(!is_private_or_reserved_ip("128.0.0.0"), "128.0.0.0 just above 127/8 = public");
    }

    #[test]
    fn batch_ad_parse_peer_list_port_boundary_values_pin_u16_range_contract() {
        // Port extraction uses u16::try_from — values >65535 are rejected and
        // fall back to the default 9473. port=0 and port=65535 are kept as-is.
        // Each row is one peer for clarity.
        let cases: Vec<(serde_json::Value, u16, &str)> = vec![
            // port=0 — currently kept; some OS rejects bind to port 0 but the
            // parser is permissive. Pins "accept 0, let connect() fail later".
            (serde_json::json!(0), 0, "port=0 must round-trip verbatim"),
            // port=1 — minimum non-zero.
            (serde_json::json!(1), 1, "port=1 must round-trip"),
            // port=65535 — max valid u16.
            (serde_json::json!(65535), 65535, "port=65535 (max u16) must round-trip"),
            // port=65536 — overflows u16; rejected by try_from, falls back to default 9473.
            (serde_json::json!(65536), 9473, "port=65536 out-of-range falls to default 9473"),
            // port="9473" (string) — `as_u64()` returns None → 9473 default.
            (serde_json::json!("9473"), 9473, "string port falls to default 9473"),
            // port absent — also defaults to 9473.
            (serde_json::Value::Null, 9473, "null port falls to default 9473"),
        ];
        for (i, (port_val, expected, label)) in cases.iter().enumerate() {
            let mut peer = serde_json::json!({
                "identity_hash": hex64(&format!("peer-{i:02}")),
                "host": "8.8.8.8",
                "protocol_version": 5,
            });
            if !matches!(port_val, serde_json::Value::Null) {
                peer["port"] = port_val.clone();
            }
            let data = serde_json::json!({ "peers": [peer] });
            let kept = parse_peer_list(&data, "self-hash", 5);
            assert_eq!(kept.len(), 1, "{label}: peer must survive (port is not a skip-gate)");
            assert_eq!(kept[0].port, *expected, "{label}: expected port {expected}, got {}", kept[0].port);
        }
    }

    #[test]
    fn batch_ad_parse_host_port_from_url_ipv6_literal_current_behavior_pin() {
        // CURRENT behavior — IPv6 literals are NOT correctly parsed by the
        // helper. `rsplit_once(':')` eats the literal's last colon as the
        // port separator. Pin so a future IPv6 fix (or a switch to the `url`
        // crate) arrives as a test diff, not a silent semantic change that
        // breaks every seed-reconnect entry whose admin pasted an IPv6 URL.

        // 1. `[::1]:9473` — host retains the brackets; port parses cleanly.
        //    A correct IPv6 parser would return ("::1", 9473) without brackets.
        let (host, port) = parse_host_port_from_url("[::1]:9473");
        assert_eq!(host, "[::1]", "current behavior: brackets retained in host (defect)");
        assert_eq!(port, 9473, "port still parses off the right edge");

        // 2. Bare `::1` (loopback IPv6, no port). `rsplit_once(':')` finds
        //    the RIGHTMOST ':' (between the second ':' and '1') and splits
        //    there → host=":", port=1. Both wrong — a correct parser would
        //    return ("::1", 9473 default).
        let (host, port) = parse_host_port_from_url("::1");
        assert_eq!(host, ":", "current behavior: bare IPv6 splits at last colon (defect)");
        assert_eq!(port, 1, "current behavior: trailing IPv6 segment parsed as port (defect)");

        // 3. `http://[::1]:9473` — scheme stripped, then bracket-retained.
        let (host, port) = parse_host_port_from_url("http://[::1]:9473");
        assert_eq!(host, "[::1]", "scheme stripped, brackets retained (defect)");
        assert_eq!(port, 9473, "port still parses off the right edge");
    }

    #[test]
    fn batch_ad_seed_base_url_scheme_match_is_lowercase_only_uppercase_falls_through() {
        // CURRENT behavior — `starts_with("http://")` is case-sensitive, so
        // `Http://`, `HTTP://`, `hTTp://`, `HTTPS://` all fall to the "no
        // scheme" branch and get a SECOND `http://` prepended. Pin so a
        // future case-insensitive fix arrives as a test diff.

        // Uppercase HTTP — gets http:// prepended → garbage URL.
        assert_eq!(
            seed_base_url("HTTP://8.8.8.8:9473"),
            "http://HTTP://8.8.8.8:9473",
            "uppercase HTTP:// falls through scheme detection and double-schemes (defect)"
        );

        // Mixed-case — same fallthrough.
        assert_eq!(
            seed_base_url("Http://seed.example:9473"),
            "http://Http://seed.example:9473",
            "Http:// (capital H) falls through (defect)"
        );

        // Uppercase HTTPS — same fallthrough.
        assert_eq!(
            seed_base_url("HTTPS://seed.example:443"),
            "http://HTTPS://seed.example:443",
            "uppercase HTTPS:// falls through (defect)"
        );

        // Lowercase still works — sanity that the case-sensitive match is
        // the only reason uppercase fails (not some other parse bug).
        assert_eq!(
            seed_base_url("http://8.8.8.8:9473"),
            "http://8.8.8.8:9473",
            "lowercase http:// works as expected (control)"
        );
    }

    #[test]
    fn batch_ad_parse_peer_list_peers_field_non_array_or_missing_returns_empty_no_panic() {
        // `data["peers"].as_array()` returns None for every non-array shape:
        // missing key, string value, number value, object value, null. In all
        // cases parse_peer_list must return an empty Vec — never panic, never
        // misinterpret. Pin so a future "be flexible — accept single peer as
        // a non-array" refactor surfaces as a test diff.

        let self_hash = "self";
        let min_ver = 5;

        // Missing key entirely.
        let missing = serde_json::json!({});
        assert!(parse_peer_list(&missing, self_hash, min_ver).is_empty(),
            "missing 'peers' key must return empty");

        // `peers` is a string.
        let str_peers = serde_json::json!({ "peers": "not-an-array" });
        assert!(parse_peer_list(&str_peers, self_hash, min_ver).is_empty(),
            "string 'peers' must return empty (not parse the string as JSON)");

        // `peers` is a number.
        let num_peers = serde_json::json!({ "peers": 42 });
        assert!(parse_peer_list(&num_peers, self_hash, min_ver).is_empty(),
            "numeric 'peers' must return empty");

        // `peers` is an object (single peer not wrapped in array — a common
        // mistake). Defect-pin: a future "be permissive" refactor would
        // accept this and add a single peer. Today: empty.
        let obj_peers = serde_json::json!({
            "peers": { "identity_hash": "aa", "host": "8.8.8.8", "port": 9473, "protocol_version": 5 }
        });
        assert!(parse_peer_list(&obj_peers, self_hash, min_ver).is_empty(),
            "object 'peers' (non-array) must return empty");

        // `peers` is null.
        let null_peers = serde_json::json!({ "peers": null });
        assert!(parse_peer_list(&null_peers, self_hash, min_ver).is_empty(),
            "null 'peers' must return empty");

        // `peers` is empty array — also empty, but for a different reason
        // (array branch taken, filter_map yields nothing). Control case.
        let empty_arr = serde_json::json!({ "peers": [] });
        assert!(parse_peer_list(&empty_arr, self_hash, min_ver).is_empty(),
            "empty 'peers' array must return empty (control)");
    }
}
