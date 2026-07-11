//! mDNS LAN discovery — Protocol §11.14 Layer C.
//!
//! Announces this node on the local network via `_elara._tcp.local.`
//! and discovers peers automatically. Discovered peers are inserted
//! into the peer table as `Stale` — the heartbeat loop verifies them
//! before trusting.
//!
//! No central authority. Nodes on the same LAN find each other via
//! multicast DNS without needing seed_peers configuration.
//!
//! Spec references:
//!   @spec Protocol §11.14 (Layer C: Local Discovery)

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::peer::{NodeType, PeerInfo, PeerState};
use super::state::NodeState;

/// Service type for mDNS announcements.
const SERVICE_TYPE: &str = "_elara._tcp.local.";

/// Run the mDNS discovery loop.
///
/// 1. Announces this node's identity, port, and node type on the LAN.
/// 2. Listens for other Elara nodes and inserts them as Stale peers.
/// 3. Runs until shutdown signal received.
pub async fn mdns_loop(
    state: Arc<NodeState>,
    mut shutdown: mpsc::Receiver<()>,
) {
    let daemon = match mdns_sd::ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!("mDNS: failed to start daemon: {e}");
            return;
        }
    };

    // ─── Announce this node ─────────────────────────────────────────────

    let identity_hash = &state.identity.identity_hash;
    let port = state.config.listen_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9473);
    let node_type = &state.config.node_type;

    // Instance name: first 16 chars of identity hash (unique per node)
    let instance_name = &identity_hash[..identity_hash.len().min(16)];

    let properties = [
        ("identity", identity_hash.as_str()),
        ("node_type", node_type),
        ("version", env!("CARGO_PKG_VERSION")),
    ];

    // Use identity hash prefix as hostname — unique per node, no extra deps
    let hostname = format!("{}.local.", instance_name);

    match mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &hostname,
        "",  // empty = auto-detect IP
        port,
        &properties[..],
    ) {
        Ok(service_info) => {
            if let Err(e) = daemon.register(service_info) {
                warn!("mDNS: failed to register service: {e}");
            } else {
                info!("mDNS: announcing {instance_name} on port {port} ({node_type})");
            }
        }
        Err(e) => {
            warn!("mDNS: failed to create service info: {e}");
        }
    }

    // ─── Discover other nodes ───────────────────────────────────────────

    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(e) => {
            warn!("mDNS: failed to browse: {e}");
            return;
        }
    };

    info!("mDNS: browsing for peers on LAN");

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                debug!("mDNS: shutting down");
                let _ = daemon.shutdown();
                return;
            }
            event = tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(std::time::Duration::from_secs(2))
            }) => {
                match event {
                    Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) => {
                        handle_discovered_peer(&state, &info).await;
                    }
                    Ok(Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, fullname))) => {
                        debug!("mDNS: peer left LAN: {fullname}");
                    }
                    Ok(Ok(_)) => {} // other events (searching, found, etc.)
                    Ok(Err(_)) => {} // timeout — normal, loop again
                    Err(e) => {
                        warn!("mDNS: recv task failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }
}

/// True for link-local addresses an mDNS responder must not be allowed to
/// advertise as a dial target: IPv4 169.254.0.0/16 (cloud metadata) and IPv6
/// fe80::/10. `Ipv6Addr::is_unicast_link_local` is unstable, so match fe80::/10
/// on the first segment directly.
fn is_mdns_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Canonicalize an mDNS-advertised address to the IPv4 it will actually reach,
/// so the SSRF-class filter below sees the real target. A malicious responder
/// can wrap a reserved IPv4 in an IPv6 literal — `::ffff:127.0.0.1`
/// (IPv4-mapped `::ffff:/96`) or `64:ff9b::169.254.169.254` (NAT64
/// `64:ff9b::/96`) — where `is_loopback()` and the `fe80::/10` check both miss
/// it because the leading segment is `0x0000`. Unwrap both `/96` forms to the
/// embedded IPv4 first; a mapped RFC1918 peer (`::ffff:192.168.1.10`) then
/// stays dialable because the unwrapped 192.168/16 still passes the LAN-allow
/// filter. Mirrors `discovery::is_private_or_reserved_ip`'s embedded-IPv4
/// recheck (commit 15dadd33) — the SSRF-sibling that path closed for remote
/// peers, here for the LAN heartbeat verify-dial.
fn canonical_mdns_dial_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv4Addr};
    if let IpAddr::V6(v6) = ip {
        // `to_ipv4_mapped()` matches ONLY `::ffff:/96` — NOT the deprecated
        // IPv4-compatible `::/96`, which would fold `::1` → `0.0.0.1` and
        // false-negative loopback.
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
        let s = v6.segments();
        if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
            return IpAddr::V4(Ipv4Addr::new(
                (s[6] >> 8) as u8,
                s[6] as u8,
                (s[7] >> 8) as u8,
                s[7] as u8,
            ));
        }
    }
    ip
}

/// True if `ip` is a LAN-dialable target after mapped/NAT64 canonicalization:
/// rejects loopback / unspecified / multicast / link-local (incl. 169.254 cloud
/// metadata, fe80::/10), but ALLOWS RFC1918 / ULA — mDNS LAN discovery and the
/// persisted-peer reload paths share this single floor so a reserved literal
/// can never become a verify-dial SSRF.
pub(crate) fn canonical_ip_is_dialable_lan(ip: std::net::IpAddr) -> bool {
    let c = canonical_mdns_dial_ip(ip);
    // 0.0.0.0/8 ("this network" — a non-zero 0.x can resolve to localhost on some
    // stacks) and the v4 limited-broadcast are rejected here too, so the LAN floor
    // matches the wire floor's reserved set. RFC1918/ULA stay allowed — that LAN
    // carve-out is the whole point of the predicate (see is_private_or_reserved_ip).
    let v4_extra =
        matches!(c, std::net::IpAddr::V4(v4) if v4.octets()[0] == 0 || v4.is_broadcast());
    !(c.is_loopback() || c.is_unspecified() || c.is_multicast() || is_mdns_link_local(&c) || v4_extra)
}

/// String entry point for the persisted-peer reload paths (peers.json /
/// dht.json). A non-literal host (hostname) is dropped: the wire/mDNS ingest
/// guards reject hostnames, but the reload path bypasses them, and dialing a
/// persisted hostname raw resolves it via DNS = blind SSRF (the deferred sibling
/// of the 75e4c8b9 / 15dadd33 wire-host fixes).
pub(crate) fn persisted_host_is_dialable_lan(host: &str) -> bool {
    host.parse::<std::net::IpAddr>()
        .map(canonical_ip_is_dialable_lan)
        .unwrap_or(false)
}

/// Handle a discovered mDNS peer — insert into peer table as Stale.
async fn handle_discovered_peer(
    state: &Arc<NodeState>,
    info: &mdns_sd::ServiceInfo,
) {
    // Extract identity hash from TXT record
    let Some(identity_hash) = info.get_property_val_str("identity") else {
        debug!("mDNS: discovered peer without identity TXT record, skipping");
        return;
    };

    // Reject malformed identities at the trust boundary: the TXT value is
    // arbitrary attacker-controlled LAN input, and downstream slices it
    // (`&identity_hash[..16]`). Without this, a peer advertising a short or
    // multi-byte-UTF-8 `identity` twice panics the discovery loop (first packet
    // inserts it; second hits the known-peer log slice).
    if !super::peer::is_valid_peer_identity(identity_hash) {
        debug!("mDNS: discovered peer with malformed identity TXT record, skipping");
        return;
    }

    // Skip self
    if identity_hash == state.identity.identity_hash.as_str() {
        return;
    }

    let port = info.get_port();
    let node_type_str = info.get_property_val_str("node_type").unwrap_or("leaf");

    // Pick the first advertised address that is safe to dial. mDNS is a LAN
    // mechanism, so RFC1918 / ULA peers are legitimate and MUST pass — but a
    // malicious responder can advertise loopback (127.0.0.1 / ::1), link-local
    // (169.254/16 cloud metadata, fe80::/10), unspecified, or multicast to turn
    // the heartbeat's verify-dial into an SSRF. Reject only those classes — and
    // run the check on the canonical (mapped/NAT64-unwrapped) address so an
    // `::ffff:127.0.0.1` / `64:ff9b::169.254.169.254` literal can't smuggle a
    // reserved IPv4 past it. Vet and dial the SAME canonical address.
    let dialable = info.get_addresses().iter().find_map(|addr| {
        let ip = canonical_mdns_dial_ip(*addr);
        canonical_ip_is_dialable_lan(ip).then_some(ip)
    });
    let Some(host) = dialable.map(|ip| ip.to_string()) else {
        debug!("mDNS: peer {identity_hash} has no dialable address");
        return;
    };

    // Check if we already know this peer
    {
        let peers = state.peers.read().await;
        if peers.get(identity_hash).is_some() {
            debug!("mDNS: already know peer {}", &identity_hash[..16]);
            return;
        }
    }

    // Insert as Stale — heartbeat will verify before trusting
    let peer = PeerInfo {
        identity_hash: identity_hash.to_string(),
        host: host.clone(),
        port,
        node_type: NodeType::from_str(node_type_str),
        last_seen: super::discovery::now(),
        state: PeerState::Stale,
        failures: 0,
        successes: 0,
        valid_records: 0,
        invalid_records: 0,
        backoff_until: 0.0,
        pow_nonce: 0,
        pow_difficulty: 0,
        public_key_hex: String::new(),
        provenance: super::peer::PeerProvenance::Inbound,
        subscribed_zones: Vec::new(),
        att_watermark: 0.0,
        pull_failures: 0,
        pull_backoff_until: 0.0,
        reachable: true,
        protocol_version: 0, // unknown until heartbeat verifies
        att_pull_invalid_sig: 0,
        att_pull_invalid_powas: 0,
        att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
    };

    state.peers.write().await.insert(peer);
    super::discovery::insert_into_dht_pub(state, identity_hash, &host, port);

    info!(
        "mDNS: discovered LAN peer {} at {}:{}",
        &identity_hash[..identity_hash.len().min(16)],
        host,
        port,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type() {
        assert!(SERVICE_TYPE.ends_with(".local."));
        assert!(SERVICE_TYPE.starts_with("_elara."));
    }

    #[test]
    fn mdns_dial_filter_rejects_ssrf_classes_but_allows_lan() {
        use std::net::IpAddr;
        // Mirror of the production filter in handle_discovered_peer: an
        // mDNS-advertised address is dialable iff it is NOT loopback /
        // unspecified / multicast / link-local. RFC1918 + ULA (legitimate LAN
        // peers) MUST stay dialable — rejecting them would disable mDNS, which
        // is the whole point of the mechanism.
        // Pins the extracted production predicate (now shared with the
        // persisted-peer reload paths) — not a hand-mirrored copy.
        let dialable = |s: &str| -> bool { canonical_ip_is_dialable_lan(s.parse::<IpAddr>().unwrap()) };
        // Rejected SSRF classes a malicious responder could advertise:
        assert!(!dialable("127.0.0.1"), "loopback v4 must be rejected");
        assert!(!dialable("::1"), "loopback v6 must be rejected");
        assert!(!dialable("169.254.169.254"), "link-local v4 (cloud metadata) rejected");
        assert!(!dialable("fe80::1"), "link-local v6 must be rejected");
        assert!(!dialable("0.0.0.0"), "unspecified must be rejected");
        assert!(!dialable("224.0.0.251"), "multicast (mDNS group) must be rejected");
        // 0.0.0.0/8 "this network" (non-zero) + v4 broadcast — match the wire floor's
        // reserved set so the two predicates can't drift apart:
        assert!(!dialable("0.1.2.3"), "0.0.0.0/8 this-network must be rejected");
        assert!(!dialable("255.255.255.255"), "v4 broadcast must be rejected");
        // IPv4-mapped / NAT64 forms of the SSRF classes — a malicious responder
        // wraps a reserved IPv4 in an IPv6 literal so is_loopback()/fe80 miss it
        // (seg0 == 0x0000). The canonical-unwrap must catch these:
        assert!(!dialable("::ffff:127.0.0.1"), "IPv4-mapped loopback must be rejected");
        assert!(!dialable("::ffff:169.254.169.254"), "IPv4-mapped cloud metadata must be rejected");
        assert!(!dialable("::ffff:0.0.0.0"), "IPv4-mapped unspecified must be rejected");
        assert!(!dialable("64:ff9b::169.254.169.254"), "NAT64 cloud metadata must be rejected");
        assert!(!dialable("64:ff9b::127.0.0.1"), "NAT64 loopback must be rejected");
        // Legitimate LAN peers — MUST remain dialable:
        assert!(dialable("192.168.1.10"), "RFC1918 192.168/16 is a legit LAN peer");
        assert!(dialable("10.1.2.3"), "RFC1918 10/8 is a legit LAN peer");
        assert!(dialable("172.16.5.5"), "RFC1918 172.16/12 is a legit LAN peer");
        assert!(dialable("fd00::1"), "ULA fd00::/8 is a legit LAN peer");
        // Unwrap must NOT over-reject a mapped RFC1918 LAN peer:
        assert!(dialable("::ffff:192.168.1.10"), "IPv4-mapped RFC1918 stays a legit LAN peer");
        // A mapped PUBLIC address must stay dialable (no false reject):
        assert!(dialable("::ffff:8.8.8.8"), "IPv4-mapped public addr must stay dialable");
    }

    #[test]
    fn persisted_host_is_dialable_lan_drops_hostnames_and_reserved_keeps_lan() {
        // The persisted-peer reload path (peers.json / dht.json) feeds host
        // STRINGS straight past the wire/mDNS ingest guards. The string predicate
        // must drop any non-literal host (a hostname dialed raw resolves via DNS =
        // blind SSRF) and any reserved literal, while keeping legitimate LAN/public
        // literals so a normal reboot doesn't lose its peer table.
        let keep = persisted_host_is_dialable_lan;
        // Hostnames — the documented pre-guard residual — MUST drop:
        assert!(!keep("evil.example"), "hostname must drop (raw dial = DNS SSRF)");
        assert!(!keep("metadata.google.internal"), "cloud-metadata hostname must drop");
        assert!(!keep(""), "empty host must drop");
        assert!(!keep("not-an-ip"), "garbage must drop");
        assert!(!keep("1.2.3.4:9000"), "host:port is not a bare literal → drop");
        // Reserved literals (incl. the mapped/NAT64 residual the narrow
        // parse-only check would have kept) MUST drop:
        assert!(!keep("127.0.0.1"), "loopback must drop");
        assert!(!keep("169.254.169.254"), "cloud-metadata link-local must drop");
        assert!(!keep("::1"), "v6 loopback must drop");
        assert!(!keep("::ffff:169.254.169.254"), "IPv4-mapped metadata must drop (residual)");
        assert!(!keep("64:ff9b::127.0.0.1"), "NAT64 loopback must drop");
        assert!(!keep("0.1.2.3"), "0.0.0.0/8 this-network must drop");
        assert!(!keep("255.255.255.255"), "v4 broadcast must drop");
        // Legitimate persisted peers MUST survive a reboot:
        assert!(keep("192.168.1.10"), "RFC1918 LAN peer kept");
        assert!(keep("10.1.2.3"), "RFC1918 LAN peer kept");
        assert!(keep("fd00::1"), "ULA LAN peer kept");
        assert!(keep("1.2.3.4"), "public peer kept");
        assert!(keep("::ffff:192.168.1.10"), "mapped RFC1918 LAN peer kept");
    }

    // ─── mDNS service-type DNS/RFC compliance ──────

    /// Exact-string pin on the mDNS service type. The existing test only
    /// pins the prefix and suffix — a regression like "_elara_v2._tcp.local."
    /// would still pass both. Pin the literal bytes so any drift in the
    /// service-type identifier breaks here (and forces a deliberate
    /// `assert_eq` update + cross-node deploy coordination, since changing
    /// the type breaks discovery between old and new nodes).
    #[test]
    fn batch_b_mdns_service_type_exact_byte_string_pinned() {
        assert_eq!(
            SERVICE_TYPE, "_elara._tcp.local.",
            "mDNS SERVICE_TYPE drifted — cross-version discovery will break silently",
        );
    }

    /// RFC 6763 §7 service type structure: `<service>.<protocol>.<domain>.`
    /// Splitting on `.` MUST yield exactly 4 elements (trailing dot creates
    /// the empty 4th label) — i.e. the path "_elara" / "_tcp" / "local" / ""
    /// is canonical. Pin so a future "let's nest under a subdomain"
    /// regression (5 labels) or "let's drop the trailing dot" (3 labels)
    /// breaks here, not in the mdns_sd daemon at runtime.
    #[test]
    fn batch_b_mdns_service_type_has_exactly_four_dot_separated_labels() {
        let labels: Vec<&str> = SERVICE_TYPE.split('.').collect();
        assert_eq!(
            labels.len(),
            4,
            "SERVICE_TYPE {SERVICE_TYPE} split into {} labels (expected 4: service/proto/domain/empty)",
            labels.len(),
        );
        assert_eq!(labels[0], "_elara", "label 0 (service) must be '_elara'");
        assert_eq!(labels[1], "_tcp", "label 1 (protocol) must be '_tcp'");
        assert_eq!(labels[2], "local", "label 2 (domain) must be 'local'");
        assert_eq!(labels[3], "", "label 3 must be empty (trailing dot for FQDN)");
    }

    /// RFC 6335 §5.1: service-name labels (positions 0 and 1) start with
    /// underscore. The third label "local" is the mDNS pseudo-TLD and does
    /// NOT carry the underscore. Pin the first-char structure of all four
    /// labels independently so a regression that drops or adds an
    /// underscore at the wrong position fails here.
    #[test]
    fn batch_b_mdns_service_type_label_underscores_match_rfc6335_marker() {
        let labels: Vec<&str> = SERVICE_TYPE.split('.').collect();
        assert!(labels[0].starts_with('_'), "service label must begin with underscore per RFC 6335");
        assert!(labels[1].starts_with('_'), "protocol label must begin with underscore per RFC 6335");
        assert!(!labels[2].starts_with('_'), "domain label 'local' must NOT begin with underscore");
        // labels[3] is empty — no first char to check
        assert!(labels[3].is_empty(), "trailing label is the FQDN dot, must be empty");
    }

    /// RFC 1035 §2.3.4: each non-empty DNS label must be ≤ 63 octets.
    /// Pin so a future verbose-naming regression (e.g. `_elara_protocol_mesh_node`)
    /// can't push a label past the DNS limit and silently break wire
    /// serialization. Also pin total length ≤ 255 octets (RFC 1035 FQDN
    /// limit) so the full constant stays within DNS-wire bounds.
    #[test]
    fn batch_b_mdns_service_type_labels_within_rfc1035_octet_limits() {
        assert!(
            SERVICE_TYPE.len() <= 255,
            "SERVICE_TYPE total {} octets exceeds RFC 1035 FQDN limit of 255",
            SERVICE_TYPE.len(),
        );
        for label in SERVICE_TYPE.split('.') {
            if label.is_empty() {
                continue; // trailing dot label
            }
            assert!(
                label.len() <= 63,
                "label {label:?} is {} octets — exceeds RFC 1035 §2.3.4 label limit of 63",
                label.len(),
            );
        }
    }

    /// RFC 6763 service-name character set: `_elara` must be valid per the
    /// RFC 1035 §2.3.1 "letter-digit-hyphen" rule (minus the leading
    /// underscore, which is the RFC 6335 marker). Pin that every char of
    /// the service label after the underscore is ASCII alphanumeric — so a
    /// future regression that switches to `_élara` (Unicode) or `_elara!`
    /// (punctuation) breaks here. DNS doesn't natively allow either; the
    /// fix would force a Punycode transform that we don't have.
    #[test]
    fn batch_b_mdns_service_type_service_label_chars_are_ascii_alphanumeric() {
        let labels: Vec<&str> = SERVICE_TYPE.split('.').collect();
        // labels[0] = "_elara" — first char is underscore (RFC 6335 marker),
        // every subsequent char must be ASCII alphanumeric.
        let service = labels[0];
        let mut iter = service.chars();
        assert_eq!(iter.next(), Some('_'), "service label must start with '_'");
        for (i, c) in iter.enumerate() {
            assert!(
                c.is_ascii_alphanumeric(),
                "non-ASCII-alphanumeric char {c:?} at position {} in service label {service:?}",
                i + 1,
            );
        }
        // labels[1] = "_tcp" — same rule
        let proto = labels[1];
        let mut iter = proto.chars();
        assert_eq!(iter.next(), Some('_'), "protocol label must start with '_'");
        for (i, c) in iter.enumerate() {
            assert!(
                c.is_ascii_alphanumeric(),
                "non-ASCII-alphanumeric char {c:?} at position {} in protocol label {proto:?}",
                i + 1,
            );
        }
    }
}
