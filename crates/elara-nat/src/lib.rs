//! NAT traversal — automatic detection and port mapping.
//!
//! Three strategies, tried in order:
//! 1. **STUN** — discover external IP + port via public STUN servers (RFC 5389).
//!    Detects NAT type (full cone, restricted, port-restricted, symmetric).
//! 2. **UPnP/IGD** — request router to forward our listen port via Internet Gateway Device.
//! 3. **Fallback** — if both fail, mark self as behind_nat=true and pull 2x faster.
//!
//! Spec references:
//!   @spec Protocol §11.14

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, info, warn};

/// Cap on a single HTTP/SOAP response read from a UPnP gateway. A valid device
/// description or SOAP body is well under 64 KB; a hostile or buggy gateway on
/// the LAN could otherwise stream an unbounded body and exhaust caller memory —
/// the 3 s read timeout bounds time, not bytes.
const MAX_HTTP_RESPONSE_BYTES: u64 = 64 * 1024;

// ─── STUN (RFC 5389) ─────────────────────────────────────────────────────────

/// Public STUN servers for external address discovery.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.stunprotocol.org:3478",
];

/// STUN message types.
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN attribute: XOR-MAPPED-ADDRESS.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN attribute: MAPPED-ADDRESS (fallback for classic STUN).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Result of STUN external address discovery.
#[derive(Debug, Clone)]
pub struct StunResult {
    /// Our external IP as seen by the STUN server.
    pub external_ip: IpAddr,
    /// Our external port as seen by the STUN server.
    pub external_port: u16,
    /// Which STUN server responded.
    pub server: String,
}

/// NAT type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — external IP matches local IP.
    None,
    /// Full cone NAT — any external host can reach the mapped port.
    FullCone,
    /// Restricted cone — only hosts we've sent to can reach us.
    RestrictedCone,
    /// Port-restricted cone — only host:port pairs we've sent to can reach us.
    PortRestricted,
    /// Symmetric NAT — different mapping for each destination. UPnP required.
    Symmetric,
    /// Could not determine NAT type.
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::None => write!(f, "none"),
            NatType::FullCone => write!(f, "full-cone"),
            NatType::RestrictedCone => write!(f, "restricted-cone"),
            NatType::PortRestricted => write!(f, "port-restricted"),
            NatType::Symmetric => write!(f, "symmetric"),
            NatType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Build a STUN Binding Request (RFC 5389, Section 6).
///
/// Header: 20 bytes
/// - Type (2 bytes): 0x0001 (Binding Request)
/// - Length (2 bytes): 0x0000 (no attributes)
/// - Magic Cookie (4 bytes): 0x2112A442
/// - Transaction ID (12 bytes): random
fn build_stun_request() -> ([u8; 20], [u8; 12]) {
    let mut buf = [0u8; 20];
    let msg_type = STUN_BINDING_REQUEST.to_be_bytes();
    buf[0] = msg_type[0];
    buf[1] = msg_type[1];
    // Length = 0 (no attributes in request)
    buf[2] = 0;
    buf[3] = 0;
    // Magic cookie
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    buf[4..8].copy_from_slice(&cookie);
    // Transaction ID (12 random bytes)
    let mut txn_id = [0u8; 12];
    getrandom::getrandom(&mut txn_id).unwrap_or_default();
    buf[8..20].copy_from_slice(&txn_id);
    (buf, txn_id)
}

/// Parse a STUN Binding Response and extract the external address.
///
/// Looks for XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS (fallback).
fn parse_stun_response(data: &[u8], txn_id: &[u8; 12]) -> Option<(IpAddr, u16)> {
    if data.len() < 20 {
        return None;
    }

    // Check message type = Binding Response
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return None;
    }

    // Verify magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    // Verify transaction ID
    if &data[8..20] != txn_id {
        return None;
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return None;
    }

    // Parse attributes
    let mut offset = 20;
    let end = 20 + msg_len;
    let mut xor_result: Option<(IpAddr, u16)> = None;
    let mut mapped_result: Option<(IpAddr, u16)> = None;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let attr_start = offset + 4;

        if attr_start + attr_len > end {
            break;
        }

        let attr_data = &data[attr_start..attr_start + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_result = parse_xor_mapped_address(attr_data);
            }
            ATTR_MAPPED_ADDRESS => {
                mapped_result = parse_mapped_address(attr_data);
            }
            _ => {} // Skip unknown attributes
        }

        // Attributes are padded to 4-byte boundary
        offset = attr_start + ((attr_len + 3) & !3);
    }

    // Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
    xor_result.or(mapped_result)
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389, Section 15.2).
fn parse_xor_mapped_address(data: &[u8]) -> Option<(IpAddr, u16)> {
    if data.len() < 8 {
        return None;
    }
    // data[0] = reserved, data[1] = family (0x01 = IPv4, 0x02 = IPv6)
    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 if data.len() >= 8 => {
            // IPv4: XOR with magic cookie
            let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                data[4] ^ cookie_bytes[0],
                data[5] ^ cookie_bytes[1],
                data[6] ^ cookie_bytes[2],
                data[7] ^ cookie_bytes[3],
            );
            Some((IpAddr::V4(ip), xport))
        }
        // IPv6 support can be added later
        _ => None,
    }
}

/// Parse MAPPED-ADDRESS attribute (classic STUN, RFC 3489).
fn parse_mapped_address(data: &[u8]) -> Option<(IpAddr, u16)> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 if data.len() >= 8 => {
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some((IpAddr::V4(ip), port))
        }
        _ => None,
    }
}

/// Discover our external address via STUN.
///
/// Tries multiple STUN servers, returns the first successful result.
/// Timeout: 3s per server, tries up to 3 servers.
pub fn stun_discover_external() -> Option<StunResult> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("NAT: failed to bind UDP socket for STUN: {e}");
            return None;
        }
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    for &server in STUN_SERVERS {
        let (request, txn_id) = build_stun_request();

        // Resolve and send
        let addrs: Vec<SocketAddr> = match std::net::ToSocketAddrs::to_socket_addrs(&server) {
            Ok(a) => a.collect(),
            Err(_) => continue,
        };

        for addr in addrs {
            if sock.send_to(&request, addr).is_err() {
                continue;
            }

            let mut buf = [0u8; 512];
            match sock.recv_from(&mut buf) {
                Ok((len, _)) => {
                    if let Some((ip, port)) = parse_stun_response(&buf[..len], &txn_id) {
                        return Some(StunResult {
                            external_ip: ip,
                            external_port: port,
                            server: server.to_string(),
                        });
                    }
                }
                Err(_) => continue, // timeout, try next
            }
        }
    }

    None
}

/// Detect NAT type by comparing STUN results from two different servers.
///
/// If both return the same external IP:port → full cone or restricted.
/// If different ports → symmetric NAT (worst case, UPnP needed).
pub fn detect_nat_type(local_ip: IpAddr) -> (NatType, Option<StunResult>) {
    let result1 = stun_discover_external();
    let Some(ref r1) = result1 else {
        return (NatType::Unknown, None);
    };

    // If external IP matches local IP → no NAT
    if r1.external_ip == local_ip {
        return (NatType::None, result1);
    }

    // Try a second STUN server from the same socket to detect symmetric NAT
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return (NatType::Unknown, result1),
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

    // Find a different server than r1
    let second_server = STUN_SERVERS.iter()
        .find(|&&s| s != r1.server)
        .unwrap_or(&STUN_SERVERS[0]);

    let (request, txn_id) = build_stun_request();
    let addrs: Vec<SocketAddr> = match std::net::ToSocketAddrs::to_socket_addrs(second_server) {
        Ok(a) => a.collect(),
        Err(_) => return (NatType::Unknown, result1),
    };

    for addr in addrs {
        if sock.send_to(&request, addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 512];
        if let Ok((len, _)) = sock.recv_from(&mut buf) {
            if let Some((ip2, port2)) = parse_stun_response(&buf[..len], &txn_id) {
                if ip2 != r1.external_ip || port2 != r1.external_port {
                    // Different mapping per destination → symmetric NAT
                    return (NatType::Symmetric, result1);
                }
                // Same mapping → cone NAT (full, restricted, or port-restricted)
                // Can't distinguish without STUN CHANGE-REQUEST which most servers don't support
                return (NatType::FullCone, result1);
            }
        }
    }

    (NatType::Unknown, result1)
}

// ─── URL parsing (no external dep) ──────────────────────────────────────────

/// Parse an HTTP(S) URL into (host, port, path). No external crate needed.
fn parse_http_url(url: &str) -> Option<(&str, u16, &str)> {
    let after_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let default_port: u16 = if url.starts_with("https") { 443 } else { 80 };

    let (authority, path) = match after_scheme.find('/') {
        Some(i) => (&after_scheme[..i], &after_scheme[i..]),
        None => (after_scheme, "/"),
    };

    match authority.rfind(':') {
        Some(colon) => {
            let host = &authority[..colon];
            let port: u16 = authority[colon + 1..].parse().ok()?;
            Some((host, port, path))
        }
        None => Some((authority, default_port, path)),
    }
}

// ─── UPnP/IGD Port Mapping ──────────────────────────────────────────────────

/// Attempt to map a port via UPnP/IGD.
///
/// Sends SSDP M-SEARCH to discover the Internet Gateway Device,
/// then requests a port mapping via SOAP.
///
/// Returns the external IP if successful.
pub async fn upnp_map_port(internal_port: u16, description: &str) -> Option<IpAddr> {
    // SSDP discovery
    let gateway = match discover_igd_gateway().await {
        Some(g) => g,
        None => {
            debug!("NAT: no UPnP/IGD gateway found");
            return None;
        }
    };

    info!("NAT: found UPnP gateway at {}", gateway.control_url);

    // Get external IP
    let external_ip = match get_external_ip(&gateway).await {
        Some(ip) => ip,
        None => {
            debug!("NAT: failed to get external IP from gateway");
            return None;
        }
    };

    // Request port mapping
    let local_ip = get_local_ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
    match add_port_mapping(&gateway, internal_port, local_ip, description).await {
        true => {
            info!(
                "NAT: UPnP port mapping created: {}:{} → {}:{}",
                external_ip, internal_port, local_ip, internal_port
            );
            Some(IpAddr::V4(external_ip))
        }
        false => {
            debug!("NAT: UPnP port mapping request failed");
            None
        }
    }
}

/// UPnP gateway info.
struct IgdGateway {
    control_url: String,
    service_type: String,
}

/// Discover IGD gateway via SSDP M-SEARCH (multicast).
async fn discover_igd_gateway() -> Option<IgdGateway> {
    let ssdp_request = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 3\r\n\
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
        \r\n";

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    sock.set_nonblocking(false).ok()?;

    let multicast_addr: SocketAddr = "239.255.255.250:1900".parse().ok()?;
    sock.send_to(ssdp_request.as_bytes(), multicast_addr).ok()?;

    let mut buf = [0u8; 2048];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    let response = std::str::from_utf8(&buf[..len]).ok()?;

    // Extract LOCATION header
    let location = response.lines()
        .find(|line| line.to_lowercase().starts_with("location:"))
        .and_then(|line| line.split_once(':').map(|x| x.1))
        .map(|s| s.trim().to_string())?;

    // Fetch the device description XML
    let desc_xml = fetch_url_blocking(&location)?;

    // Parse control URL and service type from XML
    parse_igd_control_url(&desc_xml, &location)
}

/// Fetch a URL synchronously (blocking — used for UPnP discovery only).
fn fetch_url_blocking(url: &str) -> Option<String> {
    let (host, port, path) = parse_http_url(url)?;

    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = addr_str.parse().ok()?;
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr,
        Duration::from_secs(3),
    ).ok()?;

    use std::io::{Read, Write};
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    stream.take(MAX_HTTP_RESPONSE_BYTES).read_to_string(&mut response).ok()?;

    // Strip HTTP headers
    response.split_once("\r\n\r\n").map(|(_, body)| body.to_string())
}

/// Parse the IGD control URL from device description XML.
fn parse_igd_control_url(xml: &str, base_url: &str) -> Option<IgdGateway> {
    let service_types = [
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];

    for st in &service_types {
        if xml.contains(st) {
            let after_service = xml.split_once(st)?.1;
            let control_start = after_service.find("<controlURL>")?;
            let control_end = after_service[control_start..].find("</controlURL>")?;
            let control_path = &after_service[control_start + 12..control_start + control_end];

            let control_url = if control_path.starts_with("http") {
                control_path.to_string()
            } else {
                let (host, port, _) = parse_http_url(base_url)?;
                let scheme = if base_url.starts_with("https") { "https" } else { "http" };
                if port == 80 || port == 443 {
                    format!("{scheme}://{host}{control_path}")
                } else {
                    format!("{scheme}://{host}:{port}{control_path}")
                }
            };

            return Some(IgdGateway {
                control_url,
                service_type: st.to_string(),
            });
        }
    }

    None
}

/// Get external IP from IGD gateway via SOAP.
async fn get_external_ip(gateway: &IgdGateway) -> Option<Ipv4Addr> {
    let soap_body = format!(
        "<?xml version=\"1.0\"?>\
        <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
        s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
        <s:Body><u:GetExternalIPAddress xmlns:u=\"{}\"/></s:Body>\
        </s:Envelope>",
        gateway.service_type
    );

    let soap_action = format!("\"{}#GetExternalIPAddress\"", gateway.service_type);
    let response = soap_request(&gateway.control_url, &soap_action, &soap_body)?;

    // Extract IP from XML response
    let start = response.find("<NewExternalIPAddress>")?;
    let end = response[start..].find("</NewExternalIPAddress>")?;
    let ip_str = &response[start + 22..start + end];
    ip_str.parse().ok()
}

/// Add a port mapping via IGD SOAP.
async fn add_port_mapping(
    gateway: &IgdGateway,
    port: u16,
    local_ip: Ipv4Addr,
    description: &str,
) -> bool {
    let soap_body = format!(
        "<?xml version=\"1.0\"?>\
        <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
        s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
        <s:Body><u:AddPortMapping xmlns:u=\"{}\">\
        <NewRemoteHost></NewRemoteHost>\
        <NewExternalPort>{port}</NewExternalPort>\
        <NewProtocol>TCP</NewProtocol>\
        <NewInternalPort>{port}</NewInternalPort>\
        <NewInternalClient>{local_ip}</NewInternalClient>\
        <NewEnabled>1</NewEnabled>\
        <NewPortMappingDescription>{description}</NewPortMappingDescription>\
        <NewLeaseDuration>3600</NewLeaseDuration>\
        </u:AddPortMapping></s:Body></s:Envelope>",
        gateway.service_type
    );

    let soap_action = format!("\"{}#AddPortMapping\"", gateway.service_type);
    soap_request(&gateway.control_url, &soap_action, &soap_body).is_some()
}

/// Make a SOAP request to an IGD control URL.
fn soap_request(url: &str, soap_action: &str, body: &str) -> Option<String> {
    let (host, port, path) = parse_http_url(url)?;

    let addr_str = format!("{host}:{port}");
    let addr: SocketAddr = addr_str.parse().ok()?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;

    use std::io::{Read, Write};
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
        Host: {host}\r\n\
        Content-Type: text/xml; charset=\"utf-8\"\r\n\
        SOAPAction: {soap_action}\r\n\
        Content-Length: {}\r\n\
        Connection: close\r\n\
        \r\n\
        {body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    stream.take(MAX_HTTP_RESPONSE_BYTES).read_to_string(&mut response).ok()?;
    response.split_once("\r\n\r\n").map(|(_, body)| body.to_string())
}

/// Get the local (LAN) IP address.
fn get_local_ip() -> Option<Ipv4Addr> {
    // Connect to a public address to determine which interface routes to internet
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

// ─── Public API: Auto-detect and configure ───────────────────────────────────

/// NAT detection result.
#[derive(Debug, Clone)]
pub struct NatDetection {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// External IP (from STUN or UPnP).
    pub external_ip: Option<IpAddr>,
    /// External port (from STUN).
    pub external_port: Option<u16>,
    /// Whether UPnP port mapping was created.
    pub upnp_mapped: bool,
    /// Whether the node should flag itself as behind NAT.
    pub behind_nat: bool,
    /// Suggested advertise_addr.
    pub advertise_addr: Option<String>,
}

/// True if `ip` is a publicly routable unicast address — NOT private (RFC1918),
/// loopback, link-local, CGNAT (RFC 6598 100.64/10), broadcast, documentation,
/// unspecified, or otherwise reserved.
///
/// Load-bearing for NAT detection under **double-NAT**, where a UPnP/IGD gateway
/// reports a *private* "external" IP (an inner router whose WAN faces another
/// LAN, e.g. `192.168.1.108`). Advertising such an address to the mesh is
/// useless — no internet peer can reach it — and pollutes peer tables at scale.
fn is_public_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_unspecified()
                && o[0] != 0                                  // 0.0.0.0/8
                && o[0] < 240                                 // 240/4 reserved + 255 broadcast
                && !(o[0] == 100 && (o[1] & 0xc0) == 0x40)    // 100.64.0.0/10 CGNAT (RFC 6598)
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && (v6.segments()[0] & 0xfe00) != 0xfc00      // fc00::/7 ULA
                && (v6.segments()[0] & 0xffc0) != 0xfe80      // fe80::/10 link-local
        }
    }
}

/// Pure reachability decision — the testable core of `auto_detect_nat` Step 3
/// (no network I/O). Returns `(behind_nat, advertise_addr)`.
///
/// A node is only *publicly reachable for arbitrary inbound* when it has a
/// mapping to a genuinely PUBLIC address. Two real-world traps this guards:
///   1. **Double-NAT** — UPnP "succeeds" but maps onto an intermediate private
///      LAN (private external IP). Never internet-reachable.
///   2. **Symmetric NAT** — remaps the external port per-destination, so a STUN
///      address is useless for a *new* peer; only an explicit UPnP/manual
///      port-forward to a public IP survives it.
fn decide_advertise(
    nat_type: NatType,
    upnp_ip: Option<IpAddr>,
    stun_ip: Option<IpAddr>,
    stun_port: Option<u16>,
    listen_port: u16,
) -> (bool, Option<String>) {
    let upnp_public = upnp_ip.filter(is_public_routable);
    let stun_public = stun_ip.filter(is_public_routable);

    let reachable = match nat_type {
        NatType::None => true,                               // directly on a public IP
        _ if upnp_public.is_some() => true,                  // explicit static forward to a public IP
        NatType::FullCone if stun_public.is_some() => true,  // stable mapping, any host can reach
        _ => false, // restricted / port-restricted / symmetric / unknown → pull-only
    };

    let advertise_addr = if let Some(ip) = upnp_public {
        // UPnP maps external listen_port → internal listen_port (1:1).
        Some(format!("{ip}:{listen_port}"))
    } else if reachable {
        // Full-cone via STUN: advertise the NAT-observed external port.
        match (stun_public, stun_port) {
            (Some(ip), Some(p)) => Some(format!("{ip}:{p}")),
            (Some(ip), None) => Some(format!("{ip}:{listen_port}")),
            _ => None,
        }
    } else {
        None
    };

    (!reachable, advertise_addr)
}

/// Run full NAT detection and attempt port mapping.
///
/// Call this at startup before gossip begins. Updates config if auto-detection
/// is enabled (advertise_addr empty and behind_nat not explicitly set).
pub async fn auto_detect_nat(listen_port: u16) -> NatDetection {
    info!("NAT: starting auto-detection...");

    // Step 1: STUN discovery
    let (nat_type, stun_result) = tokio::task::spawn_blocking(|| {
        let local_ip = get_local_ip()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        detect_nat_type(local_ip)
    })
    .await
    .unwrap_or((NatType::Unknown, None));

    let external_ip = stun_result.as_ref().map(|r| r.external_ip);
    let external_port = stun_result.as_ref().map(|r| r.external_port);

    info!("NAT: type={nat_type}, external={:?}:{:?}",
        external_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "?".into()),
        external_port
    );

    // Step 2: If behind NAT, try UPnP port mapping
    let mut upnp_mapped = false;
    let mut upnp_ip = None;

    if nat_type != NatType::None {
        upnp_ip = upnp_map_port(listen_port, "elara-node").await;
        upnp_mapped = upnp_ip.is_some();
        if upnp_mapped {
            info!("NAT: UPnP port mapping succeeded");
        } else {
            debug!("NAT: UPnP port mapping failed — node will rely on outbound connections");
        }
    }

    // Step 3: Determine final state. Reachability is decided honestly against
    // *publicly routable* addresses only — a UPnP mapping onto a private inner
    // LAN (double-NAT) or a STUN address under symmetric NAT does NOT make us an
    // inbound seed. See `decide_advertise`.
    let (behind_nat, advertise_addr) =
        decide_advertise(nat_type, upnp_ip, external_ip, external_port, listen_port);

    let result = NatDetection {
        nat_type,
        external_ip: upnp_ip.filter(is_public_routable).or(external_ip),
        external_port,
        upnp_mapped,
        behind_nat,
        advertise_addr,
    };

    match &result.advertise_addr {
        Some(addr) => info!("NAT: node is publicly reachable at {addr}"),
        None => warn!(
            "NAT: behind NAT (type={nat_type}) with no public mapping — pull-only \
             (gossip outbound; cannot serve as an inbound seed). To act as a public \
             seed, port-forward {listen_port} to a public IP and set \
             ELARA_ADVERTISE_ADDR=<public-ip>:<port>, or join over an overlay \
             (e.g. Tailscale) and advertise that address.",
        ),
    }

    result
}

// ─── UPnP lease renewal ─────────────────────────────────────────────────────

/// Periodically renew the UPnP port mapping (lease is 3600s, renew every 2700s).
pub async fn upnp_renewal_loop(listen_port: u16) {
    let mut interval = tokio::time::interval(Duration::from_secs(2700));
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;
        debug!("NAT: renewing UPnP port mapping");
        if upnp_map_port(listen_port, "elara-node").await.is_none() {
            warn!("NAT: UPnP renewal failed — port mapping may have expired");
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn public_routable_rejects_private_cgnat_and_reserved() {
        let pr = |s: &str| is_public_routable(&ip(s));
        // Private / reserved / link-local → NOT routable
        assert!(!pr("192.168.1.108"), "an RFC1918 gateway address is not publicly routable");
        assert!(!pr("192.168.0.103"), "an RFC1918 LAN address is not publicly routable");
        assert!(!pr("10.0.0.1"));
        assert!(!pr("172.16.5.5"));
        assert!(!pr("172.31.255.255"));
        assert!(!pr("127.0.0.1"));
        assert!(!pr("169.254.1.1"));      // link-local
        assert!(!pr("100.64.0.1"));       // CGNAT lower edge
        assert!(!pr("100.127.255.255"));  // CGNAT upper edge
        assert!(!pr("0.0.0.0"));
        assert!(!pr("255.255.255.255"));
        assert!(!pr("203.0.113.9"));      // documentation
        assert!(!pr("240.0.0.1"));        // reserved 240/4
        // Genuinely public → routable
        assert!(pr("9.9.9.9"), "a public STUN-discovered external");
        assert!(pr("8.8.8.8"));
        assert!(pr("1.1.1.1"));
        // Just outside CGNAT 100.64/10 is public
        assert!(pr("100.63.255.255"));
        assert!(pr("100.128.0.0"));
    }

    #[test]
    fn double_nat_private_upnp_is_pull_only() {
        // The EXACT live case (2026-06-13 elara-node logs): symmetric NAT,
        // UPnP "succeeds" but returns a PRIVATE external IP (inner gateway WAN).
        let (behind, addr) = decide_advertise(
            NatType::Symmetric,
            Some(ip("192.168.1.108")), // inner gateway WAN — private
            Some(ip("9.9.9.9")), // STUN public, but symmetric → per-dest port
            Some(48504),
            9474,
        );
        assert!(behind, "double-NAT private UPnP must be behind_nat=true");
        assert_eq!(addr, None, "must NOT advertise a private LAN address to the mesh");
    }

    #[test]
    fn upnp_public_mapping_is_reachable_even_under_symmetric() {
        // An explicit static forward to a PUBLIC ip survives symmetric NAT.
        let (behind, addr) = decide_advertise(
            NatType::Symmetric,
            Some(ip("9.9.9.9")),
            None,
            None,
            9474,
        );
        assert!(!behind);
        assert_eq!(addr.as_deref(), Some("9.9.9.9:9474"));
    }

    #[test]
    fn full_cone_advertises_stun_external_port() {
        let (behind, addr) = decide_advertise(
            NatType::FullCone,
            None,
            Some(ip("9.9.9.9")),
            Some(48504),
            9474,
        );
        assert!(!behind);
        assert_eq!(addr.as_deref(), Some("9.9.9.9:48504"));
    }

    #[test]
    fn symmetric_and_restricted_without_upnp_are_pull_only() {
        for ty in [NatType::Symmetric, NatType::RestrictedCone, NatType::PortRestricted, NatType::Unknown] {
            let (behind, addr) = decide_advertise(
                ty, None, Some(ip("9.9.9.9")), Some(48504), 9474,
            );
            assert!(behind, "{ty} without a public UPnP mapping must be pull-only");
            assert_eq!(addr, None, "{ty} must not advertise (port unstable for new peers)");
        }
    }

    #[test]
    fn no_nat_is_directly_reachable() {
        let (behind, addr) = decide_advertise(
            NatType::None, None, Some(ip("9.9.9.9")), Some(9474), 9474,
        );
        assert!(!behind);
        assert_eq!(addr.as_deref(), Some("9.9.9.9:9474"));
    }

    #[test]
    fn test_build_stun_request() {
        let (buf, txn_id) = build_stun_request();
        // Type = Binding Request
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), STUN_BINDING_REQUEST);
        // Length = 0
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 0);
        // Magic cookie
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), STUN_MAGIC_COOKIE);
        // Transaction ID matches
        assert_eq!(&buf[8..20], &txn_id);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        // XOR-MAPPED-ADDRESS for 198.51.100.1:32853
        // Family = 0x01 (IPv4)
        // X-Port = 32853 XOR (0x2112A442 >> 16) = 32853 XOR 0x2112 = ...
        let port: u16 = 32853;
        let xport = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip = Ipv4Addr::new(198, 51, 100, 1);
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let xip = [
            ip.octets()[0] ^ cookie[0],
            ip.octets()[1] ^ cookie[1],
            ip.octets()[2] ^ cookie[2],
            ip.octets()[3] ^ cookie[3],
        ];

        let data = [
            0x00, 0x01, // reserved + family (IPv4)
            (xport >> 8) as u8, (xport & 0xFF) as u8,
            xip[0], xip[1], xip[2], xip[3],
        ];

        let result = parse_xor_mapped_address(&data);
        assert!(result.is_some());
        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V4(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_mapped_address() {
        let data = [
            0x00, 0x01, // reserved + family (IPv4)
            0x00, 0x50, // port 80
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
        ];
        let result = parse_mapped_address(&data);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_stun_response_valid() {
        let (_, txn_id) = build_stun_request();

        // Build a valid Binding Response with XOR-MAPPED-ADDRESS
        let mut resp = vec![0u8; 32];
        // Type = Binding Response
        let msg_type = STUN_BINDING_RESPONSE.to_be_bytes();
        resp[0] = msg_type[0];
        resp[1] = msg_type[1];
        // Length = 12 (one attribute: type(2) + len(2) + data(8))
        resp[2] = 0;
        resp[3] = 12;
        // Magic cookie
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        resp[4..8].copy_from_slice(&cookie);
        // Transaction ID
        resp[8..20].copy_from_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute
        let attr_type = ATTR_XOR_MAPPED_ADDRESS.to_be_bytes();
        resp[20] = attr_type[0];
        resp[21] = attr_type[1];
        resp[22] = 0; // attr length high
        resp[23] = 8; // attr length low

        // XOR-encoded 1.2.3.4:5678
        let port: u16 = 5678;
        let xport = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let xip = [
            ip.octets()[0] ^ cookie[0],
            ip.octets()[1] ^ cookie[1],
            ip.octets()[2] ^ cookie[2],
            ip.octets()[3] ^ cookie[3],
        ];
        resp[24] = 0x00; // reserved
        resp[25] = 0x01; // family IPv4
        resp[26] = (xport >> 8) as u8;
        resp[27] = (xport & 0xFF) as u8;
        resp[28] = xip[0];
        resp[29] = xip[1];
        resp[30] = xip[2];
        resp[31] = xip[3];

        let result = parse_stun_response(&resp, &txn_id);
        assert!(result.is_some());
        let (parsed_ip, parsed_port) = result.unwrap();
        assert_eq!(parsed_ip, IpAddr::V4(ip));
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_parse_stun_response_wrong_txn_id() {
        let (_, txn_id) = build_stun_request();
        let mut wrong_id = txn_id;
        wrong_id[0] ^= 0xFF;

        let mut resp = vec![0u8; 20];
        let msg_type = STUN_BINDING_RESPONSE.to_be_bytes();
        resp[0] = msg_type[0];
        resp[1] = msg_type[1];
        resp[2] = 0;
        resp[3] = 0;
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        resp[4..8].copy_from_slice(&cookie);
        resp[8..20].copy_from_slice(&wrong_id);

        assert!(parse_stun_response(&resp, &txn_id).is_none());
    }

    #[test]
    fn test_nat_type_display() {
        assert_eq!(NatType::None.to_string(), "none");
        assert_eq!(NatType::Symmetric.to_string(), "symmetric");
        assert_eq!(NatType::FullCone.to_string(), "full-cone");
    }

    #[test]
    fn test_get_local_ip() {
        let ip = get_local_ip();
        if let Some(addr) = ip {
            assert!(!addr.is_loopback());
            assert!(!addr.is_unspecified());
        }
    }

    #[test]
    fn test_parse_http_url() {
        let (h, p, path) = parse_http_url("http://192.168.1.1:8080/control").unwrap();
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, 8080);
        assert_eq!(path, "/control");

        let (h, p, path) = parse_http_url("http://example.com/foo/bar").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/foo/bar");

        let (h, p, path) = parse_http_url("https://secure.io").unwrap();
        assert_eq!(h, "secure.io");
        assert_eq!(p, 443);
        assert_eq!(path, "/");

        assert!(parse_http_url("ftp://nope").is_none());
    }

    /// Batch B (2026-05-21 §482): pins the happy-path branch of
    /// `parse_igd_control_url` for `WANIPConnection:1` with an ABSOLUTE
    /// control URL (the simpler resolution path — control_url returned
    /// verbatim, no base_url manipulation). The `IgdGateway.service_type`
    /// MUST match the matched UPnP service URN string for the SOAP-envelope
    /// `xmlns:u=…` formatting downstream at `nat.rs:486-492`.
    #[test]
    fn batch_b_parse_igd_control_url_absolute_http_control_path_returned_verbatim() {
        let xml = r#"<root>
            <device><serviceList><service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>http://10.0.0.1:1900/ctl/IPConn</controlURL>
            </service></serviceList></device>
        </root>"#;
        let g = parse_igd_control_url(xml, "http://192.168.1.1:80/igd.xml")
            .expect("WANIPConnection:1 with abs URL must parse");
        assert_eq!(
            g.control_url, "http://10.0.0.1:1900/ctl/IPConn",
            "absolute http://… control URL must be returned verbatim (no base_url join)"
        );
        assert_eq!(
            g.service_type, "urn:schemas-upnp-org:service:WANIPConnection:1",
            "service_type must echo the matched URN for downstream SOAP xmlns:u"
        );
    }

    /// Batch B (2026-05-21 §482): pins the RELATIVE-path branch — control
    /// URL starts with `/`, must be joined to base_url's host+port with the
    /// matching scheme. Three sub-axes:
    ///   (a) port 80 collapse — `http://host:80` → `http://host` (no `:80`)
    ///   (b) port 443 collapse for https — `https://host:443` → `https://host`
    ///   (c) non-default port preserved verbatim
    /// All three exercised in one test to keep the batch shape consistent.
    /// A regression that drops the port-collapse logic would surface UPnP
    /// gateways requiring strict canonical URL form for their control endpoint.
    #[test]
    fn batch_b_parse_igd_control_url_relative_path_port_collapse_and_https_scheme() {
        let xml = r#"<root>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/ctl/IPConn</controlURL>
        </root>"#;

        // (a) port 80 → collapsed
        let g = parse_igd_control_url(xml, "http://10.0.0.1:80/igd.xml").expect("port-80 case");
        assert_eq!(
            g.control_url, "http://10.0.0.1/ctl/IPConn",
            "http://host:80 must collapse to http://host (no :80) when joining relative path"
        );

        // (b) port 443 with https scheme → collapsed
        let g = parse_igd_control_url(xml, "https://gw.lan:443/igd.xml").expect("https-443 case");
        assert_eq!(
            g.control_url, "https://gw.lan/ctl/IPConn",
            "https://host:443 must collapse to https://host AND keep the https scheme"
        );

        // (c) non-default port → preserved
        let g = parse_igd_control_url(xml, "http://10.0.0.1:1900/igd.xml").expect("port-1900 case");
        assert_eq!(
            g.control_url, "http://10.0.0.1:1900/ctl/IPConn",
            "non-default port (1900) must be preserved in the joined URL"
        );
    }

    /// Batch B (2026-05-21 §482): pins the `WANPPPConnection:1` FALLBACK
    /// branch when `WANIPConnection:1` is absent. The service-type loop at
    /// `nat.rs:455` iterates IP first, then PPP — a PPP-only gateway must
    /// still produce a working IgdGateway. Regression that dropped PPP
    /// support would break the subset of routers that ship PPPoE-only
    /// (typical for some DSL ISP-supplied gateways).
    #[test]
    fn batch_b_parse_igd_control_url_falls_back_to_wanpppconnection_when_wanipconnection_absent() {
        let xml = r#"<root>
            <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
            <controlURL>http://10.0.0.1:1900/ppp-ctl</controlURL>
        </root>"#;
        let g = parse_igd_control_url(xml, "http://10.0.0.1:1900/igd.xml")
            .expect("PPP-only XML must still parse via fallback service-type");
        assert_eq!(
            g.service_type, "urn:schemas-upnp-org:service:WANPPPConnection:1",
            "service_type must reflect the PPP URN (not the IP URN)"
        );
        assert_eq!(g.control_url, "http://10.0.0.1:1900/ppp-ctl");
    }

    /// Batch B (2026-05-21 §482): pins the SERVICE-TYPE PRECEDENCE — when
    /// BOTH `WANIPConnection:1` AND `WANPPPConnection:1` appear in the XML
    /// (e.g. a gateway exposing both), the IP service wins because it's
    /// FIRST in the `service_types` array at `nat.rs:450-453`. A reorder
    /// that put PPP first would silently flip the SOAP endpoint to PPP for
    /// every dual-mode gateway in the fleet — a subtle regression that
    /// would never surface in single-service test fixtures.
    #[test]
    fn batch_b_parse_igd_control_url_wanipconnection_wins_precedence_over_wanpppconnection() {
        let xml = r#"<root>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>http://10.0.0.1/ip-ctl</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <controlURL>http://10.0.0.1/ppp-ctl</controlURL>
              </service>
            </serviceList>
        </root>"#;
        let g = parse_igd_control_url(xml, "http://10.0.0.1:80/igd.xml")
            .expect("dual-service XML must parse — IP branch wins");
        assert_eq!(
            g.service_type, "urn:schemas-upnp-org:service:WANIPConnection:1",
            "WANIPConnection:1 must win when both services present (first in service_types array)"
        );
        assert_eq!(
            g.control_url, "http://10.0.0.1/ip-ctl",
            "control URL must be from the IP service block, not the PPP block"
        );
    }

    /// Batch B (2026-05-21 §482): pins ALL THREE None-branches of
    /// `parse_igd_control_url`:
    ///   (a) no recognized service type → None
    ///   (b) service type present but `<controlURL>` open-tag missing → None
    ///   (c) service type + open tag present but closing `</controlURL>` missing → None
    /// Together these pin every `?` early-return at `nat.rs:457-459`. A
    /// regression that allowed malformed XML to leak through could produce
    /// an IgdGateway with empty/garbage control_url, then call
    /// `add_port_mapping` against an unreachable endpoint — silent NAT-
    /// traversal failure rather than the explicit None operators rely on.
    #[test]
    fn batch_b_parse_igd_control_url_none_on_missing_service_type_or_missing_control_tag() {
        let base = "http://10.0.0.1:80/igd.xml";

        // (a) no recognized service type — neither IP nor PPP URN matches.
        let no_service = r#"<root>
            <serviceType>urn:schemas-upnp-org:service:Unrecognized:1</serviceType>
            <controlURL>/ctl</controlURL>
        </root>"#;
        assert!(
            parse_igd_control_url(no_service, base).is_none(),
            "unrecognized service URN must return None — no IgdGateway constructed"
        );

        // (b) service type present, but `<controlURL>` open-tag absent.
        let no_open_tag = r#"<root>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <other>nope</other>
        </root>"#;
        assert!(
            parse_igd_control_url(no_open_tag, base).is_none(),
            "missing <controlURL> open-tag must return None"
        );

        // (c) open-tag present but no closing `</controlURL>` — `.find()` fails on the slice.
        let no_close_tag = r#"<root>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/ctl  </root>"#;
        assert!(
            parse_igd_control_url(no_close_tag, base).is_none(),
            "missing </controlURL> close-tag must return None — no garbage control_url leaks through"
        );
    }
}

/// Fail-closed fuzz sweep over the STUN response parsers.
///
/// `parse_stun_response` / `parse_xor_mapped_address` / `parse_mapped_address`
/// turn a raw, unauthenticated UDP datagram into an `IpAddr`/port — any host can
/// spoof one at our ephemeral source port, so these MUST return (`None`) on ANY
/// input, never panic. The hand-picked unit tests above check specific valid and
/// near-valid encodings; this module backs the UNIVERSAL property with ~30k
/// structured-random inputs per decoder, plus a header-valid-then-corrupted layer
/// that drives `parse_stun_response` past its early rejects into the attribute
/// loop (`while offset + 4 <= end`), where the slice indexing actually lives.
///
/// Zero-dependency, deterministically seeded (splitmix64) — no proptest/rand in a
/// published crate, and a fixed seed makes a failure replayable, not flaky. Mirrors
/// the node crate's `decoder_fuzz` approach. Test-only.
#[cfg(test)]
mod fuzz {
    use super::*;

    /// splitmix64 — tiny, deterministic, seeded for reproducible failures.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed)
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

    /// Lengths the STUN decoders branch on: < 20 (truncated header), 20 (empty
    /// body), the 4-byte attribute-header edge, and 4-byte padding boundaries.
    const BOUNDARY_LENS: &[usize] = &[0, 1, 7, 8, 19, 20, 21, 23, 24, 27, 28, 31, 32, 36, 64, 128, 256];
    const ITERS: usize = 30_000;
    /// `STUN_MAGIC_COOKIE` is private to the parent module; re-state it here.
    const MAGIC: u32 = 0x2112_A442;

    fn rand_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        for b in v.iter_mut() {
            *b = (rng.next_u64() & 0xff) as u8;
        }
        v
    }

    fn gen_input(rng: &mut Rng) -> Vec<u8> {
        let len = if rng.next_u64() % 5 < 3 {
            BOUNDARY_LENS[rng.below(BOUNDARY_LENS.len())]
        } else {
            rng.below(257)
        };
        rand_bytes(rng, len)
    }

    /// A header-valid datagram (Binding-Response type + magic cookie + matching
    /// txn id) with a random attribute body, then a 50% chance the declared
    /// message length is clobbered — so `20 + msg_len` and the attribute walk both
    /// get over/under-run inputs that the pure-random path almost never reaches.
    fn gen_valid_prefixed(rng: &mut Rng, txn_id: &[u8; 12]) -> Vec<u8> {
        let body_len = rng.below(64);
        let body = rand_bytes(rng, body_len);
        let mut v = Vec::with_capacity(20 + body.len());
        v.extend_from_slice(&0x0101u16.to_be_bytes()); // STUN_BINDING_RESPONSE
        v.extend_from_slice(&(body.len() as u16).to_be_bytes()); // message length
        v.extend_from_slice(&MAGIC.to_be_bytes()); // magic cookie
        v.extend_from_slice(txn_id); // matching transaction id
        v.extend_from_slice(&body);
        if rng.next_u64() & 1 == 0 {
            let bad = (rng.next_u64() & 0xffff) as u16;
            v[2..4].copy_from_slice(&bad.to_be_bytes());
        }
        v
    }

    /// Run `decode` over `ITERS` seeded inputs; any panic is caught and re-raised
    /// as a reproducible failure. The invariant: the call RETURNS.
    fn sweep(name: &str, seed: u64, decode: impl Fn(&[u8])) {
        let mut rng = Rng::new(seed);
        for i in 0..ITERS {
            let input = gen_input(&mut rng);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(&input)));
            assert!(
                r.is_ok(),
                "STUN decoder `{name}` PANICKED — not fail-closed. seed={seed:#x} iter={i} len={} input={:02x?}",
                input.len(),
                input,
            );
        }
    }

    #[test]
    fn fuzz_parse_stun_response_is_fail_closed() {
        let txn_id = [0x42u8; 12];
        // (a) pure / boundary random — exercises the early-reject guards.
        sweep("parse_stun_response", 0x57A0_0001, |b| {
            let _ = parse_stun_response(b, &txn_id);
        });
        // (b) header-valid-then-corrupted — reaches the attribute-parsing loop.
        let mut rng = Rng::new(0x57A0_1001);
        for _ in 0..ITERS {
            let m = gen_valid_prefixed(&mut rng, &txn_id);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_stun_response(&m, &txn_id);
            }));
            assert!(
                r.is_ok(),
                "parse_stun_response PANICKED on header-valid input len={} input={:02x?}",
                m.len(),
                m,
            );
        }
    }

    #[test]
    fn fuzz_attribute_address_decoders_are_fail_closed() {
        sweep("parse_xor_mapped_address", 0x57A0_0002, |b| {
            let _ = parse_xor_mapped_address(b);
        });
        sweep("parse_mapped_address", 0x57A0_0003, |b| {
            let _ = parse_mapped_address(b);
        });
    }
}
