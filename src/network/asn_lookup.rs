//! Bundled ASN lookup for the major VPS / cloud providers.
//!
//! Covers the ~80% of sybil-farm surface — an attacker spinning up 100 VPS
//! instances in one provider will share an ASN even if individual /16
//! subnets differ. Granular enough to notice that correlation without
//! shipping the 5 MB MaxMind GeoLite2-ASN database in the binary.
//!
//! This is a **hint**, not ground truth. Returns `0` ("unknown") for IPs
//! outside the bundled ranges. The geographic-fraud detector treats
//! `asn = 0` as "no signal" (neither same nor different).
//!
//! Ranges transcribed from ARIN / RIPE WHOIS as of 2026-04. Coverage:
//! Hetzner, DigitalOcean, Linode/Akamai, OVH, Vultr, AWS (US-EAST-1 +
//! EU-CENTRAL-1 core), Google Cloud (primary blocks), Azure (primary blocks),
//! Oracle Cloud, Cloudflare, Tailscale CGNAT.
//!
//! # Scale
//! Linear scan of ~60 CIDR blocks per lookup — ~50 ns in release build.
//! Not hot-path (called at profile registration, once per witness).
//!
//! # Spec
//! @spec Protocol §11.12 (geographic diversity correlation)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Unknown-ASN sentinel. Geo-fraud detector treats this as "no signal".
pub const UNKNOWN_ASN: u32 = 0;

/// IPv4 CIDR block: (network, prefix_len, asn).
const IPV4_TABLE: &[(u32, u8, u32)] = &[
    // Hetzner (AS24940)
    (v4(5, 9, 0, 0), 16, 24940),
    (v4(5, 75, 0, 0), 16, 24940),
    (v4(5, 78, 0, 0), 16, 24940),
    (v4(46, 4, 0, 0), 16, 24940),
    (v4(78, 46, 0, 0), 16, 24940),
    (v4(88, 99, 0, 0), 16, 24940),
    (v4(94, 130, 0, 0), 15, 24940),
    (v4(116, 202, 0, 0), 16, 24940),
    (v4(136, 243, 0, 0), 16, 24940),
    (v4(138, 201, 0, 0), 16, 24940),
    (v4(144, 76, 0, 0), 16, 24940),
    (v4(148, 251, 0, 0), 16, 24940),
    (v4(159, 69, 0, 0), 16, 24940),
    (v4(168, 119, 0, 0), 16, 24940),
    (v4(176, 9, 0, 0), 16, 24940),
    (v4(178, 63, 0, 0), 16, 24940),
    (v4(188, 40, 0, 0), 14, 24940),
    (v4(195, 201, 0, 0), 16, 24940),
    (v4(213, 133, 96, 0), 19, 24940),

    // DigitalOcean (AS14061)
    (v4(45, 55, 0, 0), 16, 14061),
    (v4(104, 131, 0, 0), 16, 14061),
    (v4(104, 236, 0, 0), 16, 14061),
    (v4(138, 68, 0, 0), 16, 14061),
    (v4(142, 93, 0, 0), 16, 14061),
    (v4(143, 110, 0, 0), 16, 14061),
    (v4(157, 245, 0, 0), 16, 14061),
    (v4(159, 65, 0, 0), 16, 14061),
    (v4(159, 89, 0, 0), 16, 14061),
    (v4(159, 203, 0, 0), 16, 14061),
    (v4(165, 22, 0, 0), 16, 14061),
    (v4(165, 227, 0, 0), 16, 14061),
    (v4(167, 71, 0, 0), 16, 14061),
    (v4(167, 99, 0, 0), 16, 14061),
    (v4(178, 62, 0, 0), 16, 14061),

    // Linode / Akamai Connected Cloud
    (v4(45, 33, 0, 0), 16, 63949),
    (v4(45, 56, 0, 0), 16, 63949),
    (v4(45, 79, 0, 0), 16, 63949),
    (v4(50, 116, 0, 0), 16, 63949),
    (v4(66, 228, 0, 0), 16, 63949),
    (v4(96, 126, 96, 0), 19, 63949),
    (v4(139, 144, 0, 0), 16, 63949),
    (v4(172, 104, 0, 0), 16, 63949),
    (v4(192, 46, 208, 0), 20, 63949),
    (v4(198, 58, 96, 0), 19, 63949),

    // OVH (AS16276)
    (v4(5, 135, 0, 0), 16, 16276),
    (v4(37, 59, 0, 0), 16, 16276),
    (v4(51, 38, 0, 0), 15, 16276),
    (v4(51, 68, 0, 0), 14, 16276),
    (v4(51, 75, 0, 0), 16, 16276),
    (v4(51, 89, 0, 0), 16, 16276),
    (v4(51, 254, 0, 0), 16, 16276),
    (v4(91, 121, 0, 0), 16, 16276),
    (v4(92, 222, 0, 0), 16, 16276),
    (v4(137, 74, 0, 0), 16, 16276),
    (v4(141, 94, 0, 0), 15, 16276),
    (v4(146, 59, 0, 0), 16, 16276),
    (v4(147, 135, 0, 0), 16, 16276),
    (v4(149, 202, 0, 0), 16, 16276),
    (v4(164, 132, 0, 0), 16, 16276),
    (v4(167, 114, 0, 0), 16, 16276),
    (v4(176, 31, 0, 0), 16, 16276),
    (v4(178, 32, 0, 0), 15, 16276),
    (v4(188, 165, 0, 0), 16, 16276),
    (v4(193, 70, 0, 0), 16, 16276),
    (v4(198, 27, 64, 0), 20, 16276),

    // Vultr / Choopa
    (v4(45, 32, 0, 0), 16, 20473),
    (v4(45, 76, 0, 0), 16, 20473),
    (v4(45, 77, 0, 0), 16, 20473),
    (v4(66, 42, 64, 0), 18, 20473),
    (v4(104, 156, 224, 0), 19, 20473),
    (v4(108, 61, 0, 0), 16, 20473),
    (v4(140, 82, 0, 0), 16, 20473),
    (v4(149, 28, 0, 0), 16, 20473),
    (v4(155, 138, 128, 0), 17, 20473),
    (v4(207, 148, 0, 0), 16, 20473),

    // AWS (primary EC2 blocks — not exhaustive)
    (v4(3, 5, 0, 0), 16, 16509),
    (v4(3, 80, 0, 0), 15, 16509),
    (v4(13, 56, 0, 0), 14, 16509),
    (v4(15, 236, 0, 0), 16, 16509),
    (v4(18, 32, 0, 0), 14, 16509),
    (v4(18, 192, 0, 0), 14, 16509),
    (v4(34, 192, 0, 0), 12, 16509),
    (v4(35, 80, 0, 0), 13, 16509),
    (v4(44, 192, 0, 0), 10, 16509),
    (v4(52, 0, 0, 0), 11, 16509),
    (v4(52, 208, 0, 0), 13, 16509),
    (v4(54, 64, 0, 0), 11, 16509),
    (v4(54, 144, 0, 0), 13, 16509),
    (v4(54, 224, 0, 0), 12, 16509),

    // Google Cloud (AS396_982)
    (v4(34, 64, 0, 0), 10, 396_982),
    (v4(35, 184, 0, 0), 13, 396_982),
    (v4(35, 192, 0, 0), 12, 396_982),
    (v4(35, 224, 0, 0), 12, 396_982),
    (v4(104, 196, 0, 0), 14, 396_982),

    // Azure (Microsoft AS8075 — primary Azure compute blocks)
    (v4(13, 64, 0, 0), 11, 8075),
    (v4(13, 104, 0, 0), 14, 8075),
    (v4(20, 0, 0, 0), 11, 8075),
    (v4(20, 128, 0, 0), 16, 8075),
    (v4(23, 96, 0, 0), 13, 8075),
    (v4(40, 64, 0, 0), 10, 8075),
    (v4(51, 4, 0, 0), 15, 8075),
    (v4(52, 96, 0, 0), 12, 8075),
    (v4(52, 160, 0, 0), 11, 8075),
    (v4(104, 208, 0, 0), 13, 8075),

    // Oracle Cloud
    (v4(129, 146, 0, 0), 16, 31898),
    (v4(130, 35, 0, 0), 16, 31898),
    (v4(132, 145, 0, 0), 16, 31898),
    (v4(138, 1, 0, 0), 16, 31898),
    (v4(140, 91, 0, 0), 16, 31898),
    (v4(141, 148, 0, 0), 16, 31898),
    (v4(152, 67, 0, 0), 16, 31898),
    (v4(158, 101, 0, 0), 16, 31898),
    (v4(168, 138, 0, 0), 16, 31898),
    (v4(192, 9, 128, 0), 17, 31898),
    (v4(193, 122, 128, 0), 17, 31898),

    // Cloudflare (for L4/L7 front tunneling)
    (v4(104, 16, 0, 0), 12, 13335),
    (v4(172, 64, 0, 0), 13, 13335),
    (v4(162, 158, 0, 0), 15, 13335),

    // Tailscale CGNAT (100.64.0.0/10) — overlay-network nodes.
    // ASN is the "Tailscale overlay" — nodes on this range share logical
    // locality even if physically diverse, so we mark them as one group.
    (v4(100, 64, 0, 0), 10, 46489),
];

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

/// IPv6 /32 prefix → ASN. Sparse table (only a few providers).
const IPV6_TABLE: &[(u128, u8, u32)] = &[
    // Hetzner
    (v6_prefix(0x2a01, 0x4f8), 32, 24940),
    (v6_prefix(0x2a01, 0x4f9), 32, 24940),
    // DigitalOcean
    (v6_prefix(0x2604, 0xa880), 32, 14061),
    (v6_prefix(0x2a03, 0xb0c0), 32, 14061),
    // Linode
    (v6_prefix(0x2600, 0x3c00), 32, 63949),
    (v6_prefix(0x2a01, 0x7e00), 32, 63949),
    // OVH
    (v6_prefix(0x2001, 0x41d0), 32, 16276),
    // Vultr
    (v6_prefix(0x2001, 0x19f0), 32, 20473),
    // AWS
    (v6_prefix(0x2600, 0x1f00), 32, 16509),
    (v6_prefix(0x2a05, 0xd000), 32, 16509),
    // Google Cloud
    (v6_prefix(0x2600, 0x1900), 32, 396_982),
    // Azure
    (v6_prefix(0x2603, 0x1000), 32, 8075),
];

const fn v6_prefix(hi: u16, lo: u16) -> u128 {
    ((hi as u128) << 112) | ((lo as u128) << 96)
}

/// Lookup ASN for an IP address. Returns [`UNKNOWN_ASN`] (0) if not in the
/// bundled table. Callers treat 0 as "no signal" in correlation math.
pub fn ip_to_asn(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => ipv4_to_asn(v4),
        IpAddr::V6(v6) => ipv6_to_asn(v6),
    }
}

fn ipv4_to_asn(ip: Ipv4Addr) -> u32 {
    let addr = u32::from_be_bytes(ip.octets());
    for &(net, prefix, asn) in IPV4_TABLE {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        if (addr & mask) == (net & mask) {
            return asn;
        }
    }
    UNKNOWN_ASN
}

fn ipv6_to_asn(ip: Ipv6Addr) -> u32 {
    let addr = u128::from_be_bytes(ip.octets());
    for &(net, prefix, asn) in IPV6_TABLE {
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        if (addr & mask) == (net & mask) {
            return asn;
        }
    }
    UNKNOWN_ASN
}

/// Extract the /16 IPv4 prefix as `[high_byte, low_byte]`, or the upper-16
/// of the IPv6 address. Small, fixed-size, comparable — used as the
/// "subnet bucket" in correlation() without storing the whole IP.
pub fn ip_prefix16(ip: IpAddr) -> [u8; 2] {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            [a, b]
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // Take the top 16 bits of the address (first segment).
            segs[0].to_be_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn hetzner_88_99_prefix_resolves() {
        // An address in Hetzner's 88.99.0.0/16 prefix → AS24940.
        assert_eq!(ip_to_asn(ip4(88, 99, 10, 20)), 24940);
    }

    #[test]
    fn hetzner_159_69_prefix_resolves() {
        // An address in Hetzner's 159.69.0.0/16 prefix → AS24940.
        assert_eq!(ip_to_asn(ip4(159, 69, 10, 20)), 24940);
    }

    #[test]
    fn hetzner_5_78_prefix_resolves() {
        // An address in Hetzner's 5.78.0.0/16 prefix → AS24940.
        assert_eq!(ip_to_asn(ip4(5, 78, 10, 20)), 24940);
    }

    #[test]
    fn digitalocean_165_227_prefix_resolves() {
        // An address in DigitalOcean's 165.227.0.0/16 prefix → AS14061.
        assert_eq!(ip_to_asn(ip4(165, 227, 10, 20)), 14061);
    }

    #[test]
    fn tailscale_cgnat_resolves_to_tailscale() {
        // A Tailscale CGNAT (100.64.0.0/10) address resolves to the overlay ASN.
        assert_eq!(ip_to_asn(ip4(100, 64, 0, 1)), 46489);
    }

    #[test]
    fn unknown_ip_returns_zero() {
        // Private-space residential IP — not in table.
        assert_eq!(ip_to_asn(ip4(192, 168, 1, 1)), UNKNOWN_ASN);
        // Loopback.
        assert_eq!(ip_to_asn(ip4(127, 0, 0, 1)), UNKNOWN_ASN);
    }

    #[test]
    fn prefix16_ipv4_extracts_top_two_bytes() {
        assert_eq!(ip_prefix16(ip4(88, 99, 142, 148)), [88, 99]);
        assert_eq!(ip_prefix16(ip4(10, 0, 0, 1)), [10, 0]);
    }

    #[test]
    fn prefix16_ipv6_uses_first_segment() {
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ip_prefix16(ipv6), [0x2a, 0x01]);
    }

    #[test]
    fn aws_ip_resolves_to_amazon_asn() {
        // 52.5.x.x falls in 52.0.0.0/11 → AWS (covers 52.0–52.31).
        assert_eq!(ip_to_asn(ip4(52, 5, 12, 34)), 16509);
        // 3.80.x.x in 3.80.0.0/15 → AWS.
        assert_eq!(ip_to_asn(ip4(3, 80, 100, 1)), 16509);
    }

    #[test]
    fn digitalocean_ipv4_block_canonical() {
        // 142.93.0.0/16 → DigitalOcean.
        assert_eq!(ip_to_asn(ip4(142, 93, 50, 100)), 14061);
    }

    #[test]
    fn ipv6_hetzner_block() {
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0xc0, 0xabcd, 0, 0, 0, 1));
        assert_eq!(ip_to_asn(ipv6), 24940);
    }

    #[test]
    fn ipv6_unknown_returns_zero() {
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(ip_to_asn(ipv6), UNKNOWN_ASN);
    }

    #[test]
    fn prefix_bucket_same_within_org() {
        // Two Hetzner IPs in the same /16 → same prefix.
        assert_eq!(
            ip_prefix16(ip4(88, 99, 1, 1)),
            ip_prefix16(ip4(88, 99, 200, 50))
        );
    }

    #[test]
    fn prefix_bucket_differs_across_orgs() {
        // Hetzner vs DO → different prefix, different ASN.
        assert_ne!(
            ip_prefix16(ip4(88, 99, 142, 148)),
            ip_prefix16(ip4(165, 227, 10, 20))
        );
        assert_ne!(
            ip_to_asn(ip4(88, 99, 142, 148)),
            ip_to_asn(ip4(165, 227, 10, 20))
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Coverage tests on uncovered invariants.
    // Existing 14 tests pin specific testnet-node lookups and a handful of
    // /16 spot-checks. They do NOT pin UNKNOWN_ASN's sentinel uniqueness
    // across both tables, the v4/v6_prefix const-fn byte-order layout, the
    // CIDR prefix-mask first/last/off-by-one boundary, the ip_prefix16
    // cross-version collision (IPv4 100.64.x.x and IPv6 starting 0x6440
    // share prefix bytes by design — that is a real gotcha for correlation
    // math), or ip_to_asn's dispatch determinism. These tests close those.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_unknown_asn_sentinel_uniqueness_across_tables_and_size_sanity() {
        // UNKNOWN_ASN must equal 0. The geo-fraud detector hardcodes 0 as
        // "no signal" — bumping this to e.g. u32::MAX would silently let
        // correlation math treat "unknown" as a real ASN and over-cluster
        // honest peers. Pin the literal.
        assert_eq!(UNKNOWN_ASN, 0u32);
        // Type: u32 (not u16, not i32 — pin via size_of).
        assert_eq!(std::mem::size_of_val(&UNKNOWN_ASN), 4);

        // No entry in IPV4_TABLE may carry asn == 0; that would collide
        // with the UNKNOWN sentinel and ambiguate the lookup. Sweep both
        // tables to guarantee the sentinel is exclusive.
        for &(net, prefix, asn) in IPV4_TABLE {
            assert_ne!(
                asn, UNKNOWN_ASN,
                "IPV4_TABLE entry (net=0x{net:08x}, prefix={prefix}) has asn=0; collides with UNKNOWN_ASN"
            );
            // Prefix length must be a valid IPv4 CIDR: 0..=32.
            assert!(
                prefix <= 32,
                "invalid IPv4 prefix {prefix} (>32) for net 0x{net:08x}"
            );
        }
        for &(net, prefix, asn) in IPV6_TABLE {
            assert_ne!(
                asn, UNKNOWN_ASN,
                "IPV6_TABLE entry (net=0x{net:032x}, prefix={prefix}) has asn=0; collides with UNKNOWN_ASN"
            );
            // Prefix length must be a valid IPv6 CIDR: 0..=128.
            assert!(
                prefix <= 128,
                "invalid IPv6 prefix {prefix} (>128) for net 0x{net:032x}"
            );
        }

        // Sanity floor: covering "~80% of sybil-farm surface" requires at
        // least the 10 major providers × a few blocks each. Pin a floor
        // — silent deletion of half the table would slip past code review
        // without this guard.
        assert!(
            IPV4_TABLE.len() >= 50,
            "IPV4_TABLE shrunk to {} entries — major-provider coverage at risk",
            IPV4_TABLE.len()
        );
        assert!(
            IPV6_TABLE.len() >= 8,
            "IPV6_TABLE shrunk to {} entries — primary IPv6 coverage at risk",
            IPV6_TABLE.len()
        );
    }

    #[test]
    fn batch_b_v4_and_v6_prefix_const_fn_byte_order_layout_matrix() {
        // v4(a,b,c,d) is documented as `u32::from_be_bytes([a,b,c,d])`.
        // Pin the byte order — a switch to LE would silently break every
        // table entry. Use both edge values and a known testnet IP.
        assert_eq!(v4(0, 0, 0, 0), 0u32);
        assert_eq!(v4(255, 255, 255, 255), u32::MAX);
        // 127.0.0.1 → 0x7F00_0001 BE.
        assert_eq!(v4(127, 0, 0, 1), 0x7F00_0001u32);
        // 203.0.113.7 (RFC-5737 doc address) → 0xCB00_7107 BE.
        assert_eq!(v4(203, 0, 113, 7), 0xCB00_7107u32);
        // Incrementing the last octet adds 1 (BE: lowest-significance byte).
        assert_eq!(v4(0, 0, 0, 1).wrapping_sub(v4(0, 0, 0, 0)), 1);
        // Incrementing the FIRST octet adds 0x0100_0000 (BE: highest byte).
        assert_eq!(v4(1, 0, 0, 0).wrapping_sub(v4(0, 0, 0, 0)), 0x0100_0000);

        // v6_prefix(hi, lo) = ((hi as u128) << 112) | ((lo as u128) << 96).
        // The low 96 bits are always zero by construction (this is a /32
        // prefix builder — anything below the /32 is unspecified).
        assert_eq!(v6_prefix(0, 0), 0u128);
        // Hetzner 2a01:4f8::/32: hi=0x2a01, lo=0x04f8.
        let expected =
            (0x2a01u128 << 112) | (0x04f8u128 << 96);
        assert_eq!(v6_prefix(0x2a01, 0x04f8), expected);
        // Negative pin: bits below the /32 boundary must be zero.
        let any = v6_prefix(0x2001, 0x0db8);
        assert_eq!(any & ((1u128 << 96) - 1), 0,
            "v6_prefix must leave the low 96 bits zero");
        // Maximum (hi=0xFFFF, lo=0xFFFF): top 32 bits set, rest zero.
        let max32 = v6_prefix(0xFFFF, 0xFFFF);
        assert_eq!(max32 >> 96, 0xFFFF_FFFFu128,
            "top 32 bits of (0xFFFF, 0xFFFF) prefix must equal 0xFFFFFFFF");
        assert_eq!(max32 & ((1u128 << 96) - 1), 0);
    }

    #[test]
    fn batch_b_cidr_prefix_mask_first_last_and_off_by_one_boundary_matrix() {
        // Pin the prefix-mask arithmetic that drives every lookup. For
        // each provider class (small /19, mid /16, large /11) verify:
        //   • Network address itself: hits the ASN.
        //   • Last address in the block: still hits the ASN.
        //   • One byte past the block on each side: does NOT hit the ASN.

        // Hetzner /19 block (213.133.96.0/19) - real public WHOIS allocation.
        const HETZ: u32 = 24940;
        assert_eq!(ip_to_asn(ip4(213, 133, 96, 0)), HETZ, "network addr of /19 must match");
        assert_eq!(ip_to_asn(ip4(213, 133, 127, 255)), HETZ, "last addr of /19 must match");
        assert_eq!(ip_to_asn(ip4(213, 133, 100, 50)), HETZ, "mid /19 must match");
        // Just outside the /19: addresses below .96.0 and above .127.255 resolve
        // to UNKNOWN (no adjacent 213.133.* block in the table).
        assert_eq!(ip_to_asn(ip4(213, 133, 128, 0)), UNKNOWN_ASN,
            "/19 must NOT extend past its upper bound");
        assert_eq!(ip_to_asn(ip4(213, 133, 95, 255)), UNKNOWN_ASN,
            "/19 must NOT extend below its lower bound");

        // DigitalOcean /16 — 165.227.0.0/16 covers .0.0 → .255.255.
        const DO: u32 = 14061;
        assert_eq!(ip_to_asn(ip4(165, 227, 0, 0)), DO, "network addr of /16 must match");
        assert_eq!(ip_to_asn(ip4(165, 227, 255, 255)), DO, "last addr of /16 must match");
        assert_eq!(ip_to_asn(ip4(165, 227, 128, 1)), DO, "mid /16 must match");
        // Just outside: 165.228.0.0 / 165.226.255.255.
        // 165.226 may be in another DO block — check it's not 14061 if so. The
        // table only has 165.227.0.0/16 for that range, so .228 and .226 are
        // UNKNOWN.
        assert_eq!(ip_to_asn(ip4(165, 228, 0, 0)), UNKNOWN_ASN);
        assert_eq!(ip_to_asn(ip4(165, 226, 255, 255)), UNKNOWN_ASN);

        // AWS /11 — 52.0.0.0/11 covers 52.0.0.0 → 52.31.255.255.
        const AWS: u32 = 16509;
        assert_eq!(ip_to_asn(ip4(52, 0, 0, 0)), AWS, "network addr of /11 must match");
        assert_eq!(ip_to_asn(ip4(52, 31, 255, 255)), AWS, "last addr of /11 must match");
        assert_eq!(ip_to_asn(ip4(52, 16, 0, 1)), AWS, "mid /11 must match");
        // Just outside (high side): 52.32.0.0 is in 52.32-52.63 → not in /11.
        // The table has no 52.32 block, so UNKNOWN.
        assert_eq!(ip_to_asn(ip4(52, 32, 0, 0)), UNKNOWN_ASN,
            "/11 must NOT extend into 52.32.*.* range");

        // Tailscale CGNAT /10 — 100.64.0.0/10 covers 100.64.0.0 → 100.127.255.255.
        const TS: u32 = 46489;
        assert_eq!(ip_to_asn(ip4(100, 64, 0, 0)), TS);
        assert_eq!(ip_to_asn(ip4(100, 127, 255, 255)), TS);
        // 100.128.x.x is past the /10.
        assert_eq!(ip_to_asn(ip4(100, 128, 0, 0)), UNKNOWN_ASN);
        // 100.63.255.255 is just before the /10.
        assert_eq!(ip_to_asn(ip4(100, 63, 255, 255)), UNKNOWN_ASN);
    }

    #[test]
    fn batch_b_ip_prefix16_cross_version_invariants_and_known_collision() {
        // ip_prefix16 takes the top 2 bytes — the /16 bucket. Pin the
        // contract across IPv4 / IPv6 and confirm the cross-version
        // collision that the doc implies but the existing tests don't pin:
        // a Tailscale IPv4 in 100.64.0.0/10 and an IPv6 starting 0x6440
        // SHARE prefix16 == [100, 64], even though they're different
        // address families. Correlation math has to handle that.

        // IPv4: prefix16 == octets[0..2].
        assert_eq!(ip_prefix16(ip4(88, 99, 142, 148)), [88, 99]);
        assert_eq!(ip_prefix16(ip4(0, 0, 0, 0)), [0, 0]);
        assert_eq!(ip_prefix16(ip4(255, 255, 255, 255)), [255, 255]);
        // Type: [u8; 2] exactly.
        let pfx: [u8; 2] = ip_prefix16(ip4(1, 2, 3, 4));
        assert_eq!(pfx, [1, 2]);
        assert_eq!(pfx.len(), 2);

        // IPv6: first segment's BE bytes.
        let v6_ts = IpAddr::V6(Ipv6Addr::new(0x1234, 0x5678, 0, 0, 0, 0, 0, 0));
        assert_eq!(ip_prefix16(v6_ts), [0x12, 0x34]);
        let v6_zero = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(ip_prefix16(v6_zero), [0, 0]);
        let v6_max = IpAddr::V6(Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        ));
        assert_eq!(ip_prefix16(v6_max), [0xFF, 0xFF]);

        // Cross-version COLLISION pin: IPv4 100.64.0.0 (Tailscale) has
        // prefix16 [100, 64]; IPv6 with first segment 0x6440 (= 25664
        // decimal = [0x64, 0x40] = [100, 64]) shares the same prefix.
        // This is a real correlation-math gotcha — pin it so a future
        // maintainer who refactors prefix16 to be address-family-tagged
        // has to update the correlation contract too.
        let v4_ts_cgnat = ip4(100, 64, 12, 34);
        let v6_collide = IpAddr::V6(Ipv6Addr::new(0x6440, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ip_prefix16(v4_ts_cgnat), [100, 64]);
        assert_eq!(ip_prefix16(v6_collide), [100, 64]);
        assert_eq!(ip_prefix16(v4_ts_cgnat), ip_prefix16(v6_collide),
            "by design, prefix16 is family-agnostic — pin the collision so correlation callers are aware");

        // Same-/16 grouping: any pair of IPs in the same /16 → same bucket.
        for c in 0u8..255 {
            for d in [0u8, 128, 255] {
                assert_eq!(ip_prefix16(ip4(88, 99, c, d)), [88, 99],
                    "any IP in 88.99.x.x has prefix16 [88, 99]");
            }
        }
        // Cross-/16 distinct.
        assert_ne!(ip_prefix16(ip4(88, 99, 1, 1)), ip_prefix16(ip4(89, 99, 1, 1)));
        assert_ne!(ip_prefix16(ip4(88, 99, 1, 1)), ip_prefix16(ip4(88, 100, 1, 1)));
    }

    #[test]
    fn batch_b_ip_to_asn_dispatch_purity_determinism_and_ipv4_mapped_ipv6_quirk() {
        // ip_to_asn is a pure function over a static table — called many
        // times with the same arg must return the same value bit-for-bit.
        // This defends against a future "memoization" or "cache" addition
        // that introduces hidden state.
        let hetzner_ip = ip4(88, 99, 142, 10);
        let first = ip_to_asn(hetzner_ip);
        for _ in 0..100 {
            assert_eq!(ip_to_asn(hetzner_ip), first,
                "ip_to_asn must be a pure function — same input → same output");
        }
        assert_eq!(first, 24940u32);

        // Dispatch: IpAddr::V4 → ipv4 lookup; IpAddr::V6 → ipv6 lookup.
        // The two are independent — feeding an IPv4-in-IPv6-mapped address
        // (::ffff:88.99.142.10) does NOT find Hetzner via the IPv4 table.
        // It goes through the IPv6 table, where 0x0000…ffff… is unknown.
        // Pin this gotcha so a refactor that "unifies" the dispatch must
        // deliberately update this test.
        let v4_mapped = IpAddr::V6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0xFF, 0xFF,
            88, 99, 142, 10,
        ]));
        let v4_direct = ip4(88, 99, 142, 10);
        assert_eq!(ip_to_asn(v4_direct), 24940);
        assert_eq!(ip_to_asn(v4_mapped), UNKNOWN_ASN,
            "IPv4-mapped IPv6 (::ffff:a.b.c.d) does NOT fall through to IPv4 table");

        // Cover each major provider's ASN at least once — defends against a
        // future table rewrite that drops one of the bundled providers.
        let providers: &[(u32, IpAddr, &str)] = &[
            (24940, ip4(5, 9, 100, 200), "Hetzner /16 5.9"),
            (14061, ip4(45, 55, 1, 1), "DigitalOcean /16 45.55"),
            (63949, ip4(45, 33, 100, 200), "Linode /16 45.33"),
            (16276, ip4(51, 38, 0, 1), "OVH /15 51.38"),
            (20473, ip4(45, 32, 1, 1), "Vultr /16 45.32"),
            (16509, ip4(3, 80, 1, 1), "AWS /15 3.80"),
            (396_982, ip4(34, 64, 1, 1), "Google /10 34.64"),
            (8075, ip4(13, 64, 1, 1), "Azure /11 13.64"),
            (31898, ip4(129, 146, 1, 1), "Oracle /16 129.146"),
            (13335, ip4(104, 16, 1, 1), "Cloudflare /12 104.16"),
            (46489, ip4(100, 64, 1, 1), "Tailscale CGNAT /10"),
        ];
        for (expected_asn, ip, label) in providers {
            assert_eq!(
                ip_to_asn(*ip), *expected_asn,
                "{label}: expected ASN {expected_asn}, got {}",
                ip_to_asn(*ip)
            );
        }
    }
}
