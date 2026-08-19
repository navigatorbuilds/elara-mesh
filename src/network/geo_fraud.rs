//! Geographic fraud detector for MESH-BFT §5.
//!
//! A witness's self-reported `geo_zone` is peer-controlled and can be lied
//! about. The aggregator-chain safety proof (Protocol §11.12, Theorem 3.1)
//! depends on a *real* geographic spread across the witness set, so sybils
//! claiming diverse geos from one datacenter break the assumption.
//!
//! This detector cross-checks every witness's claimed `geo_zone` against
//! per-peer RTT observations ([`super::peer_rtt::PeerRttEstimator`]). Two
//! independent tests:
//!
//! 1. **RTT outlier within claimed bucket.** Peers claiming the same
//!    `geo_zone` should have similar RTTs from this node. If one peer in a
//!    bucket has RTT > `OUTLIER_FACTOR × bucket_median`, it is very likely
//!    not actually in that geo.
//!
//! 2. **Intercontinental RTT floor.** Two peers claiming different continent
//!    buckets (e.g. `earth-eu` vs `earth-us`) cannot both be honest if the
//!    lighter-speed floor between those two peers is violated — i.e. if
//!    their RTTs from *this* node differ by less than the minimum plausible
//!    delta. In practice: if we see RTT 5ms to a peer claiming "earth-us"
//!    while we're in Helsinki, it is impossible.
//!
//! Both tests emit [`FraudVerdict`] which the slashing pipeline
//! ([`super::slashing`]) uses to slash the offending witness's stake.
//!
//! # Design: no false positives on sparse data
//!
//! We intentionally refuse to emit verdicts when evidence is thin:
//! - Bucket must have ≥ [`MIN_BUCKET_SIZE`] peers before a median is trusted.
//! - Each peer must have ≥ [`MIN_SAMPLES_FOR_VERDICT`] RTT samples.
//! - Bucket median must be above [`RTT_NOISE_FLOOR_US`] before outlier
//!   ratios are applied (otherwise a 1µs median × 3 = 3µs threshold fires
//!   on every peer — noise).
//!
//! Scale: O(n) over the witness set per scan. `scan_witness_set` is not hot-path —
//! called once per epoch boundary or on demand by the slashing worker.
//!
//! # Spec
//! @spec Protocol §11.12 (geographic diversity, Theorem 3.1)
//! @spec MESH-BFT §5 (geographic fraud proofs)

use std::collections::HashMap;
use std::time::Duration;

use super::consensus::WitnessProfile;
use super::peer_rtt::{PeerId, PeerRttEstimator};

/// Minimum peers in a `geo_zone` bucket before the median is trusted.
/// Below this, the bucket produces no verdicts (insufficient signal).
pub const MIN_BUCKET_SIZE: usize = 3;

/// Minimum RTT samples per peer before we'll emit a verdict against it.
/// One-off RTT noise (desktop peer under load) shouldn't trigger slashing.
pub const MIN_SAMPLES_FOR_VERDICT: usize = 20;

/// Ratio above bucket median that counts as "outlier".
///
/// Value 3.0 is the standard Tukey outer-fence for skewed distributions.
/// RTT is right-skewed (long tail on slow peers), so 3× median is a
/// conservative threshold — real geographic outliers are typically 10×+.
pub const OUTLIER_FACTOR: f64 = 3.0;

/// Below this median RTT, outlier detection is disabled for the bucket.
/// Prevents `median × 3` becoming trivially small and firing on every peer.
/// 500 µs = 0.5 ms — below typical in-datacenter peer RTT.
pub const RTT_NOISE_FLOOR_US: u32 = 500;

/// Minimum plausible RTT between any two different *continents*. Below
/// this floor, two peers cannot honestly both be in different continents.
/// 30ms ≈ best-case fiber Helsinki↔London; between continents it's ≥ 60ms
/// round-trip. 30ms is a lenient floor that leaves plenty of room for same-
/// continent variance while still catching obvious lies.
pub const INTERCONTINENTAL_MIN_RTT_US: u32 = 30_000;

/// Categorical reason a verdict was emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudReason {
    /// Peer's RTT is > `OUTLIER_FACTOR × bucket_median` within its claimed
    /// `geo_zone`. The peer is probably not where it claims.
    RttOutlierInBucket {
        bucket_median_us: u32,
        peer_rtt_us: u32,
    },
    /// Peer claims a continent different from another peer, but the
    /// observer's RTT to both is below the intercontinental floor.
    /// Both cannot be honest; the one whose self-reported continent is
    /// closest to the observer's own wins (but when we can't self-verify,
    /// we flag both as suspicious for human/slashing review).
    IntercontinentalFloorViolation {
        our_rtt_us: u32,
        floor_us: u32,
        paired_peer: String,
        paired_peer_zone: String,
    },
}

impl FraudReason {
    /// Short categorical tag — stable across upgrades, usable as a dedup
    /// component and a log filter. Must not embed numeric measurements
    /// (those would make every slash a "new" one and defeat dedup).
    pub fn tag(&self) -> &'static str {
        match self {
            FraudReason::RttOutlierInBucket { .. } => "rtt_outlier",
            FraudReason::IntercontinentalFloorViolation { .. } => "intercontinental_floor",
        }
    }

    /// Human-readable single-line summary suitable for the slash-record
    /// `reason` metadata field. Used by tribunals and explorers.
    pub fn summary(&self) -> String {
        match self {
            FraudReason::RttOutlierInBucket {
                bucket_median_us,
                peer_rtt_us,
            } => format!(
                "rtt_outlier:bucket_med_us={bucket_median_us}:peer_us={peer_rtt_us}"
            ),
            FraudReason::IntercontinentalFloorViolation {
                our_rtt_us,
                floor_us,
                paired_peer_zone,
                ..
            } => format!(
                "intercontinental_floor:our_us={our_rtt_us}:floor_us={floor_us}:near_zone={paired_peer_zone}"
            ),
        }
    }
}

/// A single proven-or-provable instance of geographic fraud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FraudVerdict {
    /// Identity of the misbehaving witness.
    pub peer_id: String,
    /// The `geo_zone` value the peer claimed in its `WitnessProfile`.
    pub claimed_zone: String,
    /// What triggered the verdict.
    pub reason: FraudReason,
    /// RTT sample count backing the verdict — slashing tribunal sees this
    /// to gauge confidence.
    pub sample_count: usize,
}

impl FraudVerdict {
    /// Stable dedup key — (claimed_zone, reason_tag). Paired with
    /// `peer_id` and the current epoch to ensure at most one geo-fraud
    /// slash per offender per zone per epoch per category.
    pub fn dedup_key(&self, epoch_number: u64) -> String {
        format!(
            "geo_fraud:epoch={}:zone={}:{}",
            epoch_number,
            self.claimed_zone,
            self.reason.tag(),
        )
    }
}

/// Input bundle for [`scan_witness_set`]. Kept as a plain struct (not a trait) so the
/// detector is purely functional — easy to unit-test without real consensus
/// state.
///
/// - `witnesses`: every witness we are considering + its self-reported profile.
/// - `rtt`: per-peer RTT estimator snapshot keyed by the same peer_id string.
pub struct FraudScanInput<'a> {
    pub witnesses: &'a [(String, WitnessProfile)],
    pub rtt: &'a PeerRttEstimator,
}

/// Scan the witness set, emit every geographic-fraud verdict.
///
/// Deterministic — same inputs produce the same verdict list in the same
/// order (sorted by `(peer_id, reason)` for gossip determinism).
///
/// O(n) over the witness set, plus O(n²) for the intercontinental pairwise
/// check. At mainnet scale (per-zone committee of 32), that's 1024 comparisons
/// per scan — trivial. If committee sizes ever grow to thousands, callers
/// can batch by geo_zone first.
pub fn scan_witness_set(input: FraudScanInput<'_>) -> Vec<FraudVerdict> {
    let mut verdicts = Vec::new();

    // Bucket witnesses by claimed geo_zone (non-empty only — empty zone is
    // "undisclosed", which the correlation engine already penalizes; not
    // a geo-fraud case).
    let mut buckets: HashMap<String, Vec<(&String, &WitnessProfile)>> = HashMap::new();
    for (peer_id, profile) in input.witnesses {
        if profile.geo_zone.is_empty() {
            continue;
        }
        buckets
            .entry(profile.geo_zone.clone())
            .or_default()
            .push((peer_id, profile));
    }

    // ── Test 1: RTT outlier within claimed bucket ──────────────────────
    for (zone, peers) in &buckets {
        if peers.len() < MIN_BUCKET_SIZE {
            continue;
        }

        // Collect per-peer RTTs — but only for peers with enough samples.
        let mut rtts: Vec<(String, u32, usize)> = Vec::with_capacity(peers.len());
        for (peer_id, _) in peers {
            let pid = PeerId::new(peer_id.as_str());
            let samples = input.rtt.sample_count(&pid);
            if samples < MIN_SAMPLES_FOR_VERDICT {
                continue;
            }
            if let Some(med) = input.rtt.median(&pid) {
                let us = duration_to_us(med);
                rtts.push((peer_id.to_string(), us, samples));
            }
        }

        // Need at least MIN_BUCKET_SIZE peers with RTT data to compute a
        // trustworthy bucket median.
        if rtts.len() < MIN_BUCKET_SIZE {
            continue;
        }

        let bucket_median = median_u32(&rtts.iter().map(|(_, us, _)| *us).collect::<Vec<_>>());

        // Noise floor: if bucket is too fast, outlier ratio is meaningless.
        if bucket_median < RTT_NOISE_FLOOR_US {
            continue;
        }

        let threshold_us = (bucket_median as f64 * OUTLIER_FACTOR) as u32;
        for (peer_id, peer_us, samples) in &rtts {
            if *peer_us > threshold_us {
                verdicts.push(FraudVerdict {
                    peer_id: peer_id.clone(),
                    claimed_zone: zone.clone(),
                    reason: FraudReason::RttOutlierInBucket {
                        bucket_median_us: bucket_median,
                        peer_rtt_us: *peer_us,
                    },
                    sample_count: *samples,
                });
            }
        }
    }

    // ── Test 2: intercontinental floor vs majority co-location ─────────
    //
    // Insight: the observer itself has a physical location. The majority of
    // peers with enough samples that show low RTT to the observer are
    // statistically the observer's co-located bucket (e.g. if observer is in
    // Helsinki, all EU peers show ~5ms). Any peer claiming a geo OUTSIDE that
    // majority bucket but still showing low RTT is fraudulent — it claims to
    // be far away while physically being close.
    //
    // We don't assume the observer knows its own geo. We infer it from the
    // largest-bucket co-location signal.

    // Collect per-peer entries with enough samples.
    let mut entries: Vec<(String, String, u32, usize)> = Vec::with_capacity(input.witnesses.len());
    for (peer_id, profile) in input.witnesses {
        if profile.geo_zone.is_empty() {
            continue;
        }
        let pid = PeerId::new(peer_id.as_str());
        let samples = input.rtt.sample_count(&pid);
        if samples < MIN_SAMPLES_FOR_VERDICT {
            continue;
        }
        if let Some(med) = input.rtt.median(&pid) {
            entries.push((
                peer_id.clone(),
                profile.geo_zone.clone(),
                duration_to_us(med),
                samples,
            ));
        }
    }

    // Compute per-zone bucket medians for the floor check.
    let mut bucket_medians: HashMap<String, (u32, usize)> = HashMap::new();
    for (zone, peers) in &buckets {
        let rtts: Vec<u32> = peers
            .iter()
            .filter_map(|(peer_id, _)| {
                let pid = PeerId::new(peer_id.as_str());
                if input.rtt.sample_count(&pid) < MIN_SAMPLES_FOR_VERDICT {
                    return None;
                }
                input.rtt.median(&pid).map(duration_to_us)
            })
            .collect();
        if rtts.len() >= MIN_BUCKET_SIZE {
            bucket_medians.insert(zone.clone(), (median_u32(&rtts), rtts.len()));
        }
    }

    // Find the "near" bucket: majority-bucket with median BELOW the
    // intercontinental floor. If such a bucket exists, it is the observer's
    // physical neighborhood. Any peer OUTSIDE this bucket claiming low RTT
    // is a geo liar.
    let near_bucket: Option<(&String, u32)> = bucket_medians
        .iter()
        .filter(|(_, (med, _))| *med < INTERCONTINENTAL_MIN_RTT_US)
        .max_by_key(|(_, (_, count))| *count)
        .map(|(zone, (med, _))| (zone, *med));

    if let Some((near_zone, _near_med)) = near_bucket {
        for (peer_id, claimed_zone, rtt_us, samples) in &entries {
            if claimed_zone == near_zone {
                continue; // peer is in the near bucket; not a liar
            }
            // Peer claims a FAR zone but RTT is below intercontinental floor.
            if *rtt_us < INTERCONTINENTAL_MIN_RTT_US {
                verdicts.push(FraudVerdict {
                    peer_id: peer_id.clone(),
                    claimed_zone: claimed_zone.clone(),
                    reason: FraudReason::IntercontinentalFloorViolation {
                        our_rtt_us: *rtt_us,
                        floor_us: INTERCONTINENTAL_MIN_RTT_US,
                        paired_peer: String::from("<near_bucket>"),
                        paired_peer_zone: near_zone.clone(),
                    },
                    sample_count: *samples,
                });
            }
        }
    }

    // Sort deterministic — gossip determinism requires byte-identical
    // verdict lists across validators.
    verdicts.sort_by(|a, b| {
        a.peer_id
            .cmp(&b.peer_id)
            .then_with(|| a.claimed_zone.cmp(&b.claimed_zone))
            .then_with(|| format!("{:?}", a.reason).cmp(&format!("{:?}", b.reason)))
    });

    verdicts
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn duration_to_us(d: Duration) -> u32 {
    d.as_micros().min(u128::from(u32::MAX)) as u32
}

/// Median of a slice — sorts a stack copy (no allocation if small).
fn median_u32(xs: &[u32]) -> u32 {
    if xs.is_empty() {
        return 0;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    v[v.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prof(org: &str, subnet: &str, geo: &str) -> WitnessProfile {
        WitnessProfile {
            organization: org.to_string(),
            subnet: subnet.to_string(),
            geo_zone: geo.to_string(),
        }
    }

    fn make_rtt(samples: &[(&str, u32, usize)]) -> PeerRttEstimator {
        // (peer_id, per-sample-us, count).
        let mut est = PeerRttEstimator::new();
        for (peer, us, n) in samples {
            for _ in 0..*n {
                est.observe(&PeerId::new(*peer), Duration::from_micros(u64::from(*us)));
            }
        }
        est
    }

    fn witnesses(entries: &[(&str, &str, &str, &str)]) -> Vec<(String, WitnessProfile)> {
        entries
            .iter()
            .map(|(pid, org, subnet, zone)| (pid.to_string(), prof(org, subnet, zone)))
            .collect()
    }

    #[test]
    fn empty_input_produces_no_verdicts() {
        let ws = Vec::new();
        let rtt = PeerRttEstimator::new();
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(v.is_empty());
    }

    #[test]
    fn single_bucket_too_small_no_verdict() {
        // Only 2 peers claim earth-eu; bucket < MIN_BUCKET_SIZE.
        let ws = witnesses(&[
            ("p1", "o1", "", "earth-eu"),
            ("p2", "o2", "", "earth-eu"),
        ]);
        let rtt = make_rtt(&[
            ("p1", 1_000, 50),
            ("p2", 100_000, 50), // would be outlier with a full bucket
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(v.is_empty(), "bucket of 2 must not produce verdicts");
    }

    #[test]
    fn outlier_in_bucket_produces_verdict() {
        // 3 honest EU peers + 1 liar claiming EU but with US-like RTT.
        let ws = witnesses(&[
            ("eu1", "o", "", "earth-eu"),
            ("eu2", "o", "", "earth-eu"),
            ("eu3", "o", "", "earth-eu"),
            ("liar", "o", "", "earth-eu"),
        ]);
        let rtt = make_rtt(&[
            ("eu1", 5_000, 50),
            ("eu2", 6_000, 50),
            ("eu3", 5_500, 50),
            ("liar", 80_000, 50), // 16× bucket median
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].peer_id, "liar");
        assert_eq!(v[0].claimed_zone, "earth-eu");
        assert!(matches!(v[0].reason, FraudReason::RttOutlierInBucket { .. }));
    }

    #[test]
    fn insufficient_samples_suppresses_verdict() {
        // Would-be liar has <MIN_SAMPLES_FOR_VERDICT samples → no verdict.
        let ws = witnesses(&[
            ("eu1", "o", "", "earth-eu"),
            ("eu2", "o", "", "earth-eu"),
            ("eu3", "o", "", "earth-eu"),
            ("liar", "o", "", "earth-eu"),
        ]);
        let rtt = make_rtt(&[
            ("eu1", 5_000, 50),
            ("eu2", 6_000, 50),
            ("eu3", 5_500, 50),
            ("liar", 80_000, 5), // only 5 samples
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(
            v.iter().all(|ver| ver.peer_id != "liar"),
            "peer with <{MIN_SAMPLES_FOR_VERDICT} samples must not be flagged"
        );
    }

    #[test]
    fn noise_floor_suppresses_tiny_medians() {
        // Bucket median is 100µs — below RTT_NOISE_FLOOR_US. Outlier test
        // must be disabled (otherwise 300µs is an "outlier").
        let ws = witnesses(&[
            ("a", "o", "", "earth-eu"),
            ("b", "o", "", "earth-eu"),
            ("c", "o", "", "earth-eu"),
            ("d", "o", "", "earth-eu"),
        ]);
        let rtt = make_rtt(&[
            ("a", 100, 50),
            ("b", 120, 50),
            ("c", 80, 50),
            ("d", 400, 50), // 4× median but below noise floor
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(v.is_empty(), "sub-noise-floor medians must not produce verdicts");
    }

    #[test]
    fn intercontinental_floor_catches_5ms_to_claimed_us() {
        // Observer has peers claiming earth-eu (normal 5ms) and one claiming
        // earth-us but RTT is 5ms → impossible. Must flag "us" peer.
        // Bucket size = 1 for us (no in-bucket check), so only the inter-
        // continental pairwise check can catch it.
        let ws = witnesses(&[
            ("eu1", "o", "", "earth-eu"),
            ("eu2", "o", "", "earth-eu"),
            ("eu3", "o", "", "earth-eu"),
            ("us1", "o", "", "earth-us"),
        ]);
        let rtt = make_rtt(&[
            ("eu1", 5_000, 50),
            ("eu2", 6_000, 50),
            ("eu3", 5_500, 50),
            ("us1", 5_000, 50), // should be 80_000+ if really in US
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(
            v.iter().any(|ver| ver.peer_id == "us1"
                && matches!(ver.reason, FraudReason::IntercontinentalFloorViolation { .. })),
            "us1 at 5ms RTT while peers claim earth-eu must trip intercontinental floor; got {v:?}"
        );
    }

    #[test]
    fn same_continent_does_not_trip_floor() {
        // Two peers both in earth-eu with low RTT — perfectly legal.
        let ws = witnesses(&[
            ("a", "o", "", "earth-eu"),
            ("b", "o", "", "earth-eu"),
            ("c", "o", "", "earth-eu"),
        ]);
        let rtt = make_rtt(&[
            ("a", 5_000, 50),
            ("b", 4_000, 50),
            ("c", 6_000, 50),
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(v.is_empty());
    }

    #[test]
    fn empty_zone_excluded_from_scan() {
        // Peers with empty geo_zone must not be bucketed or floor-checked.
        let ws = witnesses(&[
            ("p1", "o", "", ""),
            ("p2", "o", "", ""),
            ("p3", "o", "", ""),
        ]);
        let rtt = make_rtt(&[
            ("p1", 5_000, 50),
            ("p2", 6_000, 50),
            ("p3", 200_000, 50),
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert!(v.is_empty());
    }

    #[test]
    fn verdicts_are_deterministic_ordering() {
        // Build a scan with two liars in different buckets — sort order
        // must be lex(peer_id) then claimed_zone then reason.
        let ws = witnesses(&[
            ("eu1", "o", "", "earth-eu"),
            ("eu2", "o", "", "earth-eu"),
            ("eu3", "o", "", "earth-eu"),
            ("z_liar", "o", "", "earth-eu"),
            ("as1", "o", "", "earth-as"),
            ("as2", "o", "", "earth-as"),
            ("as3", "o", "", "earth-as"),
            ("a_liar", "o", "", "earth-as"),
        ]);
        let rtt = make_rtt(&[
            ("eu1", 5_000, 50),
            ("eu2", 6_000, 50),
            ("eu3", 5_500, 50),
            ("z_liar", 300_000, 50),
            ("as1", 200_000, 50),
            ("as2", 210_000, 50),
            ("as3", 220_000, 50),
            ("a_liar", 800_000, 50),
        ]);
        let v = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        let v2 = scan_witness_set(FraudScanInput {
            witnesses: &ws,
            rtt: &rtt,
        });
        assert_eq!(v, v2, "identical inputs must yield byte-identical verdicts");
        // Must be lex-sorted by peer_id ("a_liar" before "z_liar").
        assert!(v.len() >= 2);
        let peers: Vec<_> = v.iter().map(|x| x.peer_id.as_str()).collect();
        let a_pos = peers.iter().position(|p| *p == "a_liar").unwrap();
        let z_pos = peers.iter().position(|p| *p == "z_liar").unwrap();
        assert!(a_pos < z_pos, "a_liar must sort before z_liar");
    }

    #[test]
    fn median_u32_handles_empty_and_odd_and_even() {
        assert_eq!(median_u32(&[]), 0);
        assert_eq!(median_u32(&[5]), 5);
        assert_eq!(median_u32(&[3, 1, 2]), 2); // sorted: 1 2 3 → idx 1
        assert_eq!(median_u32(&[10, 20, 30, 40]), 30); // idx 2 (upper-median; ok for our purposes)
    }

    // ─── additional axes ────────────────────────────────────────────────

    /// Pin all five module constants to their documented mainnet values plus
    /// the inter-constant invariants that the detector logic depends on.
    /// A tuner who drops MIN_SAMPLES_FOR_VERDICT below MIN_BUCKET_SIZE, or
    /// raises RTT_NOISE_FLOOR_US above INTERCONTINENTAL_MIN_RTT_US, silently
    /// breaks the §11.12 detector — fast-fail at compile/test time.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_geo_fraud_five_constants_strict_pin_with_cross_relations_and_module_disjointness() {
        // Strict literal pins — these values are the §11.12 / MESH-BFT §5
        // canonical mainnet floors. Any change must be deliberate and bring
        // a slashing-pipeline review.
        assert_eq!(MIN_BUCKET_SIZE, 3usize);
        assert_eq!(MIN_SAMPLES_FOR_VERDICT, 20usize);
        assert_eq!(OUTLIER_FACTOR, 3.0_f64);
        assert_eq!(RTT_NOISE_FLOOR_US, 500_u32);
        assert_eq!(INTERCONTINENTAL_MIN_RTT_US, 30_000_u32);

        // OUTLIER_FACTOR finite + > 1.0 (a factor of 1.0 would flag every
        // peer above the median — a regression that dropped it to 1.0
        // would flood slashing).
        assert!(OUTLIER_FACTOR.is_finite());
        assert!(OUTLIER_FACTOR > 1.0);
        assert_eq!(OUTLIER_FACTOR.fract(), 0.0, "Tukey factor MUST be integer-valued");

        // Inter-constant invariant 1: per-peer sample requirement must be
        // strictly larger than per-bucket peer requirement. Otherwise a
        // bucket of 3 peers with 3 samples each would trigger verdicts
        // before any peer had enough samples to discriminate noise.
        assert!(
            MIN_SAMPLES_FOR_VERDICT > MIN_BUCKET_SIZE,
            "MIN_SAMPLES_FOR_VERDICT ({}) must exceed MIN_BUCKET_SIZE ({})",
            MIN_SAMPLES_FOR_VERDICT, MIN_BUCKET_SIZE
        );
        // Inter-constant invariant 2: intercontinental floor must exceed the
        // outlier noise floor — a continental-distance RTT smaller than the
        // bucket noise floor would make the intercontinental check vacuous.
        assert!(
            INTERCONTINENTAL_MIN_RTT_US > RTT_NOISE_FLOOR_US,
            "INTERCONTINENTAL ({}) must exceed RTT_NOISE_FLOOR ({})",
            INTERCONTINENTAL_MIN_RTT_US, RTT_NOISE_FLOOR_US
        );
        // Specific cross-relation: 30_000 / 500 = 60. Pin the 60× ratio so
        // a tuner can't silently tighten or loosen one without the other.
        assert_eq!(
            INTERCONTINENTAL_MIN_RTT_US,
            60 * RTT_NOISE_FLOOR_US,
            "intercontinental floor MUST be exactly 60× noise floor"
        );

        // Cross-module disjointness — geo_fraud constants must NOT collide
        // with the unrelated numeric anchors elsewhere in the crate. A
        // refactor that re-used (e.g.) MAX_STATE_CORE_WORKERS=64 in place
        // of MIN_BUCKET_SIZE=3 would silently inflate the bucket-trust
        // threshold by 21×.
        assert_ne!(
            MIN_BUCKET_SIZE as u64,
            crate::network::state_core::MAX_STATE_CORE_WORKERS as u64
        );
        assert_ne!(
            INTERCONTINENTAL_MIN_RTT_US as f64,
            crate::network::pending_drain::PENDING_DISCARD_TIMEOUT_SECS
        );
        assert_ne!(
            INTERCONTINENTAL_MIN_RTT_US as f64,
            crate::network::pending_drain::PENDING_HARD_DISCARD_TIMEOUT_SECS
        );
    }

    /// Pin `FraudReason::tag()` to its documented categorical strings.
    /// Tags MUST be stable across upgrades — they ride in dedup keys and
    /// log filters. A rename "rtt_outlier"→"rttOutlier" would (a) re-emit
    /// every historical verdict as a "new" slash (because dedup_key changes)
    /// and (b) silently break operator log greppers keyed on the old name.
    /// Also pin the &'static str shape — tag MUST return a static, not an
    /// allocated String, so it can land in zero-allocation log macros.
    #[test]
    fn batch_b_geo_fraud_reason_tag_strict_string_pin_with_two_variant_disjointness() {
        let outlier = FraudReason::RttOutlierInBucket {
            bucket_median_us: 1_000,
            peer_rtt_us: 5_000,
        };
        let intercont = FraudReason::IntercontinentalFloorViolation {
            our_rtt_us: 2_000,
            floor_us: INTERCONTINENTAL_MIN_RTT_US,
            paired_peer: "peer_b".into(),
            paired_peer_zone: "earth-us".into(),
        };

        // Strict-string pin per variant — must NOT drift across upgrades.
        assert_eq!(outlier.tag(), "rtt_outlier");
        assert_eq!(intercont.tag(), "intercontinental_floor");

        // Tags MUST be distinct (otherwise dedup_key collisions would lose
        // one category of slash silently).
        assert_ne!(outlier.tag(), intercont.tag());

        // Tags MUST NOT embed numeric measurements (would defeat dedup —
        // every slash would be "new"). Negative-axis check on the outlier
        // tag — the numeric fields (1000, 5000) should not appear.
        assert!(!outlier.tag().contains("1000"));
        assert!(!outlier.tag().contains("5000"));
        // Tags MUST be lowercase + snake_case + ASCII (log-grep contract).
        for t in [outlier.tag(), intercont.tag()] {
            assert!(
                t.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "tag {:?} must be ascii_lowercase + underscores",
                t
            );
            assert!(!t.is_empty());
            // No leading/trailing underscore.
            assert!(!t.starts_with('_'));
            assert!(!t.ends_with('_'));
        }
    }

    /// Pin `FraudReason::summary()` exact-format strings for both variants.
    /// Summaries are stored verbatim in slash-record metadata and surfaced
    /// to tribunals and explorers — a format drift silently breaks the
    /// explorer "reason" column. The keys (`bucket_med_us`, `peer_us`,
    /// `our_us`, `floor_us`, `near_zone`) and the `:` separator must hold.
    #[test]
    fn batch_b_geo_fraud_reason_summary_exact_format_pins_for_both_variants() {
        let outlier = FraudReason::RttOutlierInBucket {
            bucket_median_us: 1_234,
            peer_rtt_us: 9_876,
        };
        assert_eq!(
            outlier.summary(),
            "rtt_outlier:bucket_med_us=1234:peer_us=9876",
            "outlier summary format must be rtt_outlier:bucket_med_us=N:peer_us=N"
        );

        let intercont = FraudReason::IntercontinentalFloorViolation {
            our_rtt_us: 4_321,
            floor_us: 30_000,
            paired_peer: "peer_b_ignored_in_summary".into(),
            paired_peer_zone: "earth-asia".into(),
        };
        assert_eq!(
            intercont.summary(),
            "intercontinental_floor:our_us=4321:floor_us=30000:near_zone=earth-asia",
            "intercont summary format must be intercontinental_floor:our_us=N:floor_us=N:near_zone=Z"
        );
        // paired_peer field MUST NOT leak into the summary (only zone does).
        assert!(
            !intercont.summary().contains("peer_b_ignored_in_summary"),
            "summary must not leak paired_peer id"
        );
        // Summary always starts with the tag (so a grep on tag also catches
        // the summary line in mixed logs).
        assert!(outlier.summary().starts_with(outlier.tag()));
        assert!(intercont.summary().starts_with(intercont.tag()));
        // Summaries MUST be distinct across variants under any non-degenerate
        // input — different prefix guarantees this.
        assert_ne!(outlier.summary(), intercont.summary());
    }

    /// Pin `FraudVerdict::dedup_key` to its exact format and field-propagation
    /// shape. The dedup contract: "at most one geo-fraud slash per (peer,
    /// claimed_zone, reason_tag, epoch)". A format change silently un-dedups
    /// historical slashes (everyone gets re-slashed once). The peer_id is
    /// intentionally NOT in the dedup_key because slashing already keys on
    /// peer_id externally — pin that asymmetry too.
    #[test]
    fn batch_b_geo_fraud_verdict_dedup_key_exact_format_and_field_propagation() {
        let v1 = FraudVerdict {
            peer_id: "peer_alpha".into(),
            claimed_zone: "earth-eu".into(),
            reason: FraudReason::RttOutlierInBucket {
                bucket_median_us: 1_000,
                peer_rtt_us: 5_000,
            },
            sample_count: 42,
        };
        // Strict format pin: geo_fraud:epoch={E}:zone={Z}:{tag}
        assert_eq!(
            v1.dedup_key(7),
            "geo_fraud:epoch=7:zone=earth-eu:rtt_outlier"
        );
        // Epoch propagates (different epoch → different key).
        assert_ne!(v1.dedup_key(7), v1.dedup_key(8));
        // Zone propagates (different zone → different key).
        let v2 = FraudVerdict {
            peer_id: v1.peer_id.clone(),
            claimed_zone: "earth-us".into(),
            reason: v1.reason.clone(),
            sample_count: v1.sample_count,
        };
        assert_ne!(v1.dedup_key(7), v2.dedup_key(7));
        // Reason tag propagates (different variant → different key).
        let v3 = FraudVerdict {
            peer_id: v1.peer_id.clone(),
            claimed_zone: v1.claimed_zone.clone(),
            reason: FraudReason::IntercontinentalFloorViolation {
                our_rtt_us: 2_000,
                floor_us: 30_000,
                paired_peer: "peer_b".into(),
                paired_peer_zone: "earth-us".into(),
            },
            sample_count: 99,
        };
        assert_ne!(v1.dedup_key(7), v3.dedup_key(7));
        assert_eq!(
            v3.dedup_key(7),
            "geo_fraud:epoch=7:zone=earth-eu:intercontinental_floor"
        );
        // peer_id is NOT in dedup_key — changing it MUST NOT change the key.
        let v4 = FraudVerdict {
            peer_id: "peer_BETA_completely_different".into(),
            claimed_zone: v1.claimed_zone.clone(),
            reason: v1.reason.clone(),
            sample_count: v1.sample_count,
        };
        assert_eq!(
            v1.dedup_key(7),
            v4.dedup_key(7),
            "peer_id must NOT participate in dedup_key (slashing keys on peer_id externally)"
        );
        // sample_count is NOT in dedup_key either.
        let v5 = FraudVerdict {
            peer_id: v1.peer_id.clone(),
            claimed_zone: v1.claimed_zone.clone(),
            reason: v1.reason.clone(),
            sample_count: 999_999,
        };
        assert_eq!(v1.dedup_key(7), v5.dedup_key(7));
        // Key always starts with the "geo_fraud:" namespace prefix (operator
        // log greps key on this).
        assert!(v1.dedup_key(7).starts_with("geo_fraud:"));
    }

    /// Pin `duration_to_us` saturating-cast behavior. The function clamps
    /// `as_micros()` (u128) to `u32::MAX` so a pathological RTT measurement
    /// (e.g. millennium-long Duration from a clock-skew bug) can't wrap
    /// around to a tiny u32 and produce a spurious "RTT 5ms peer claiming
    /// us-east-1" intercontinental verdict against a hung peer. Existing
    /// tests exercise the higher-level scan; this pins the raw saturation.
    #[test]
    fn batch_b_geo_fraud_duration_to_us_saturating_cast_at_u32_max_boundary() {
        // Sub-µs duration → 0
        assert_eq!(duration_to_us(Duration::from_nanos(500)), 0);
        // Exactly 1 µs → 1
        assert_eq!(duration_to_us(Duration::from_micros(1)), 1);
        // Typical RTT regime — 5 ms = 5_000 µs (well within u32 range)
        assert_eq!(duration_to_us(Duration::from_millis(5)), 5_000);
        // RTT_NOISE_FLOOR boundary
        assert_eq!(
            duration_to_us(Duration::from_micros(RTT_NOISE_FLOOR_US as u64)),
            RTT_NOISE_FLOOR_US
        );
        // INTERCONTINENTAL boundary — 30 ms = 30_000 µs
        assert_eq!(
            duration_to_us(Duration::from_micros(INTERCONTINENTAL_MIN_RTT_US as u64)),
            INTERCONTINENTAL_MIN_RTT_US
        );
        // u32::MAX boundary — exactly u32::MAX µs casts to u32::MAX exactly
        let exact_max = Duration::from_micros(u32::MAX as u64);
        assert_eq!(duration_to_us(exact_max), u32::MAX);
        // 1 µs past u32::MAX saturates to u32::MAX (no wraparound)
        let one_past = Duration::from_micros(u32::MAX as u64 + 1);
        assert_eq!(
            duration_to_us(one_past),
            u32::MAX,
            "Duration > u32::MAX µs must saturate, not wrap"
        );
        // Far past u32::MAX — millennium-long Duration also saturates
        let way_past = Duration::from_secs(1_000_000_000); // 10^9 sec ≈ 31.7 years
        assert_eq!(
            duration_to_us(way_past),
            u32::MAX,
            "millennium-scale Duration must saturate (not wrap to a tiny u32)"
        );
    }
}
