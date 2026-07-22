//! KR-3 S2 — finalized-causal ordering for rotation-class records: foundational
//! primitives (Step-1, unwired slice).
//!
//! Governing design: internal design notes
//! (round-3 GATE-PASS 2026-07-11). This module ships ONLY the parts §1/§2/§6.1/§9
//! specify exactly and that carry **zero runtime effect on their own**:
//!
//!   * [`FinalityCoord`] — the coordinate assigned by the finalizing seal (§2).
//!   * the S2 constants (§9 "Constants" bullet).
//!   * [`lineage_id`] — the rotation-chain routing/CF key, `sha3(pk₀)` (§6.1, R-8).
//!
//! Everything that changes consensus behaviour is DELIBERATELY NOT here and is
//! sequenced for dedicated wiring sessions (each fork-risk-bearing, each with the
//! §9 test plan): the W1 drain hook + W2 marker sweep (§3-3), the rotation CF
//! writes + registration + snapshot/checksum carriage (§4/B7), the `resolve_record_zone`
//! routing pin + override map + proof-path branches (§6.1), the H1–H5 / R1–R4 gates
//! (§5/§4), and the resolver / `revocation_authorized_v2` (§6.3/§6.3a). Nothing in
//! this file is referenced by a consensus path yet, so the S1 flag is trivially
//! OFF-equivalent (byte-identical behaviour) until the wiring lands.
//!
//! The one subtle invariant encoded here is §2's **cross-chain incomparability**:
//! drand rounds from different beacon chains are not comparable, so [`FinalityCoord`]
//! implements [`PartialOrd`] (returning `None` on a chain-hash mismatch) but
//! deliberately does NOT implement [`Ord`] — a total order would silently permit the
//! meaningless cross-chain comparison the design forbids. Use
//! [`FinalityCoord::cmp_within_chain`] for an explicit, checked comparison.

use std::cmp::Ordering;

/// RocksDB column-family name for the rotation-chain finality state, keyed by
/// [`lineage_id`] (§4, house naming `key_rotation_chain`).
///
/// Declared here alongside the primitives; the CF is **registered in the DB open
/// descriptor and written** only by the §3-3/§4 wiring slice (W1/W2). Until then it
/// is an unused name constant — no CF is opened, so there is no on-disk schema change.
pub const CF_KEY_ROTATION_CHAIN: &str = "key_rotation_chain";

// ── Constants (§9) ──────────────────────────────────────────────────────────

/// Fixed admission bound: a rotation-class record whose author timestamp is more
/// than this far in the past is admitted-but-alarmed, never an ordering input
/// (§5-H1, R-4 — a *fixed* constant, never a per-node adaptive value, to keep the
/// witness coverage gate fork-free).
pub const ROTATION_CLASS_MAX_PAST_SECS: u64 = 3_600;

/// Retention-derived parent-freshness bound for the H3 predecessor check (§5-H3,
/// B2). Matches the 24 h in-memory attestation retention, NOT the storage-GC
/// horizon.
pub const ROTATION_PARENT_MAX_AGE_SECS: u64 = 86_400;

/// Maximum accepted wall-clock skew when ingesting an admin-supplied drand pulse
/// on mainnet (§4b, B3).
pub const PULSE_INGEST_MAX_SKEW_SECS: u64 = 900;

/// Depth cap on a single rotation lineage's chain-walk (§1.4) — bounds cascade,
/// resolver, and proof work.
pub const ROTATION_MAX_CHAIN_DEPTH: u32 = 16;

/// W2 durable-evidence fallback: a seal buried at least this many canonical-chain
/// successors deep is treated as final without re-reading the 24 h-evicted
/// attestation trackers (§3-3, R-1).
pub const ROTATION_SEAL_BURY_DEPTH: u64 = 2;

/// Late-revoke freeze-reach horizon, as **wall-clock seconds** (7 days). The design
/// expresses this "in rounds" because the effect clock is the drand round; the
/// fixed magnitude is wall-clock, so it is stored in seconds here and converted to
/// a round delta at the consumer via [`secs_to_rounds`] against the live pulse
/// period (§6.3, R-3/R-5). A hop dormant longer than this cannot freeze a fresh
/// chain; admission never rejects on age.
pub const ROTATION_LATE_REVOKE_HORIZON_SECS: u64 = 7 * 86_400;

/// A lineage left Frozen longer than this (wall-clock seconds, 7 days) escalates to
/// health-CRITICAL (§6.3, R-5). Same seconds↔rounds treatment as
/// [`ROTATION_LATE_REVOKE_HORIZON_SECS`].
pub const ROTATION_FREEZE_ESCALATION_SECS: u64 = 7 * 86_400;

/// Dispute window, epoch component: `max(3 epochs, 24 h floor)` (§6.4, B9). This is
/// the epoch count; the wall-clock floor is [`ROTATION_DISPUTE_WINDOW_FLOOR_SECS`].
pub const ROTATION_DISPUTE_WINDOW_EPOCHS: u64 = 3;

/// Dispute window wall-clock floor (24 h) — guards against sub-second epochs racing
/// the window shut (§6.4, B9).
pub const ROTATION_DISPUTE_WINDOW_FLOOR_SECS: u64 = 86_400;

/// Floor for the per-zone pulse-freshness slack (§4-R2/B10). The effective slack is
/// [`pulse_freshness_slack_secs`].
pub const PULSE_FRESHNESS_SLACK_FLOOR_SECS: u64 = 900;

/// Per-zone pulse-freshness slack: `max(2 × zone epoch duration, 900 s)` (§4-R2,
/// B10). Safe to stay zone-derived — R2/R4 are voluntary live-attestation gates,
/// not historical hard-verify gates.
#[inline]
pub fn pulse_freshness_slack_secs(zone_epoch_duration_secs: u64) -> u64 {
    zone_epoch_duration_secs
        .saturating_mul(2)
        .max(PULSE_FRESHNESS_SLACK_FLOOR_SECS)
}

/// Convert a wall-clock second-count into a drand round delta for the given beacon
/// period, rounding up so a horizon is never under-counted. The League-of-Entropy
/// mainnet period is 30 s (`drand_fetch::LOE_PERIOD_SECS`); the live period is read
/// from the pulse at the call site. A `period_secs` of 0 is treated as 1 to avoid a
/// divide-by-zero (a malformed period never yields a zero-length horizon).
#[inline]
pub fn secs_to_rounds(secs: u64, period_secs: u64) -> u64 {
    let period = period_secs.max(1);
    secs.div_ceil(period)
}

// ── Lineage id (§6.1, R-8) ──────────────────────────────────────────────────

/// The rotation-chain lineage identifier: `sha3-256(pk₀)` as lowercase hex, where
/// `pk₀` is the **origin** public key of the lineage (the anchor the whole chain
/// descends from). This is rotation-stable — unlike `identity_hash`, it does not
/// move when a key rotates — so it is the routing-pin and CF key for the lineage
/// (§6.1). Callers pass the raw origin public-key bytes.
#[inline]
pub fn lineage_id(origin_public_key: &[u8]) -> String {
    crate::crypto::hash::sha3_256_hex(origin_public_key)
}

// ── The coordinate (§2) ─────────────────────────────────────────────────────

/// Error returned when two [`FinalityCoord`]s are compared across different drand
/// beacon chains — a meaningless comparison the design forbids (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DifferentChain;

impl std::fmt::Display for DifferentChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalityCoord comparison across different drand beacon chains is undefined")
    }
}

impl std::error::Error for DifferentChain {}

/// The finalized-causal coordinate of a rotation-class record (§2).
///
/// Assigned by the consensus event that finalizes the record — inclusion in a
/// covering **final** epoch seal — never by any author-chosen field. Its purpose is
/// honest-ordering infrastructure (ordering uncontested history, expiring windows,
/// cross-anchor tie-break); it is deliberately NOT the compromise-cascade
/// eligibility test (that is causal chain-reachability, §6.2).
///
/// ```text
/// FinalityCoord = (chain_hash, round, zone_path, epoch, record_id)   // lexicographic
/// ```
///
/// **Comparison is defined only within one beacon chain.** [`PartialOrd::partial_cmp`]
/// returns `None` on a `chain_hash` mismatch, and this type does not implement
/// [`Ord`]. For explicit handling use [`cmp_within_chain`](Self::cmp_within_chain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FinalityCoord {
    /// drand beacon chain hash of the covering final seal's embedded pulse. A seal
    /// with no pulse cannot finalize a rotation-class record (§4 fail-closed), so a
    /// coordinate only ever exists with a concrete `chain_hash` — see
    /// [`from_seal_pulse`](Self::from_seal_pulse).
    pub chain_hash: String,
    /// drand round of the covering seal's pulse — a single global clock (fixed
    /// genesis + period) that makes coordinates comparable across zones with
    /// independent epoch counters.
    pub round: u64,
    /// Zone path (`ZoneId::path`) of the covering seal — disambiguates multiple
    /// zones sealing within one round period.
    pub zone_path: String,
    /// Per-zone epoch of the covering seal, monotonic under the seal chain-link.
    pub epoch: u64,
    /// Record id — total-order completeness only; grinding a low id buys nothing
    /// because same-seal rivals route to dispute resolution (§6).
    pub record_id: String,
}

impl FinalityCoord {
    /// Build a coordinate from a covering seal's pulse components. Returns `None`
    /// when `chain_hash` is absent — a pulse-less seal yields no coordinate, which
    /// is exactly §4's fail-closed "non-effective" outcome for rotation-class.
    pub fn from_seal_pulse(
        chain_hash: Option<String>,
        round: u64,
        zone_path: String,
        epoch: u64,
        record_id: String,
    ) -> Option<Self> {
        Some(Self {
            chain_hash: chain_hash?,
            round,
            zone_path,
            epoch,
            record_id,
        })
    }

    /// Checked comparison. Returns `Err(DifferentChain)` when the two coordinates
    /// come from different beacon chains; otherwise the lexicographic order over
    /// `(round, zone_path, epoch, record_id)` within the shared chain (§2).
    pub fn cmp_within_chain(&self, other: &Self) -> Result<Ordering, DifferentChain> {
        if self.chain_hash != other.chain_hash {
            return Err(DifferentChain);
        }
        Ok((self.round, self.zone_path.as_str(), self.epoch, self.record_id.as_str()).cmp(&(
            other.round,
            other.zone_path.as_str(),
            other.epoch,
            other.record_id.as_str(),
        )))
    }
}

impl PartialOrd for FinalityCoord {
    /// `None` on a `chain_hash` mismatch (cross-chain rounds are incomparable, §2).
    /// Deliberately partial: this type has no [`Ord`] impl.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.cmp_within_chain(other).ok()
    }
}

// ── Rotation-chain CF entry (§4 schema) ──────────────────────────────────────
//
// The persisted record of one finalized rotation hop. It lives in the rotation
// CF (`CF_KEY_ROTATION_CHAIN`) keyed by `(lineage_id, hop_index)`, and — per
// §3-3 — the *existence* of an entry with `state ≥ Final` IS the durable
// finalization predicate for rotation-class records (never `FinalizedIndex` /
// the pruned attestation map). These are the shared types the §3-3 W1/W2
// writers, the §4 snapshot carriage, the §6 walks, and the proof paths all
// consume; the primitives land here so that wiring inherits verified types.
// No consensus path references them yet (the store helpers in `storage::rocks`
// have no live caller until W1/W2), so this remains zero-runtime-effect.

/// The kind of rotation-class operation a hop represents (§4 schema `kind`).
/// Explicit discriminants: the byte value feeds [`rotation_chain_root`]'s
/// canonical encoding, so it must never silently shift under a reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RotationKind {
    Rotation = 0,
    SphincsRotation = 1,
    Revocation = 2,
    Succession = 3,
}

impl RotationKind {
    /// Single-char namespace tag folded into a hop's ROOT `lineage_id`
    /// ([`derive_lineage_position`]). Two rotation chains that share the same
    /// root key *hash* but differ in key TYPE (e.g. an identity's Dilithium
    /// primary chain and its SPHINCS+ secondary chain) must never collide on the
    /// same `(lineage_id, hop_index)` CF slot or zone-routing key — the KR-3
    /// origin-key audit's C6 cross-kind collision. The tag makes the two
    /// lineages disjoint by construction, independent of any key-material
    /// argument. A deep hop INHERITS its predecessor's already-tagged lineage
    /// (the `Some` arm copies it verbatim), so the tag is applied exactly once,
    /// at the root.
    pub fn lineage_tag(self) -> &'static str {
        match self {
            RotationKind::Rotation => "d",        // Dilithium3 primary
            RotationKind::SphincsRotation => "s", // SPHINCS+ secondary
            RotationKind::Revocation => "r",
            RotationKind::Succession => "x",
        }
    }
}

/// Lifecycle state of a rotation hop (§4 schema `state`). An entry only exists
/// once its covering seal finalizes (§3-3), so the W1/W2 writers write `Final`;
/// `Pending` is reserved for snapshot-inherited-but-locally-unconfirmed entries
/// (§4 provisional inheritance), and the later states are the resolver's (§6.3).
/// Explicit discriminants for the same canonical-encoding reason as above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RotationState {
    Pending = 0,
    Final = 1,
    Effective = 2,
    Frozen = 3,
    Disputed = 4,
    Cascaded = 5,
}

/// Which durable-evidence leg established the covering seal's finality for this
/// entry (§3-3 W2). `Quorum` = Leg-A stored-attestation recount (also what W1
/// writes, since it runs on the finalize tick with fresh in-memory seal state);
/// `Burial` = Leg-B canonical-chain burial, provisional — re-derived if
/// `canonicalize_latest_seals` later disagrees, firing
/// `elara_rotation_cf_canonicality_mismatch_total`. Kept out of §4's abbreviated
/// schema list but required by §3-3's "records `evidence: Burial`" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FinalityEvidence {
    Quorum = 0,
    Burial = 1,
}

/// One hop of a rotation lineage — the §4 CF entry, keyed by
/// `(lineage_id, hop_index)`. The durable home of the hop's [`FinalityCoord`]
/// and of the pulse bytes needed for offline re-verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotationChainEntry {
    /// Rotation-stable anchor key (§6.1) — `lineage_id`, NOT `identity_hash`.
    pub lineage_id: String,
    /// Position in the lineage chain-walk, 0 = the origin hop. Bounded by
    /// [`ROTATION_MAX_CHAIN_DEPTH`].
    pub hop_index: u32,
    pub record_id: String,
    pub record_hash: String,
    pub prev_key_hash: String,
    pub new_key_hash: String,
    pub kind: RotationKind,
    /// The coordinate assigned by the covering final seal (§2/§3-3).
    pub coord: FinalityCoord,
    /// The covering seal's record id (offline re-verification / dispute audit).
    pub seal_record_id: String,
    /// The covering seal's embedded pulse, retained verbatim so an offline
    /// verifier can re-derive the coordinate and check the beacon (§4).
    pub pulse: crate::network::time_bracket::DrandPulse,
    pub state: RotationState,
    /// The evidence leg behind the finality claim (§3-3 W2).
    pub evidence: FinalityEvidence,
    /// Set only once a dispute resolves (§6.4); `None` for uncontested hops.
    /// Placeholder `String` until the §6.3 resolver defines the outcome type —
    /// safe to refine later since `None` is wire-identical across inner types
    /// and the CF holds no persisted entries until the W1/W2 slice lands.
    pub dispute_outcome: Option<String>,
}

/// Append `s` to `buf` length-prefixed, so field boundaries are unambiguous —
/// the encoding must be injective for [`rotation_chain_root`] to be
/// tamper-evident. `usize as u64` is lossless on every supported platform.
#[inline]
fn absorb_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u64).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Length-prefixed with a leading presence byte, so `None` and `Some("")` are
/// distinguishable (injective).
#[inline]
fn absorb_opt_str(buf: &mut Vec<u8>, s: &Option<String>) {
    match s {
        None => buf.push(0),
        Some(v) => {
            buf.push(1);
            absorb_str(buf, v);
        }
    }
}

/// Absorb one entry into the canonical byte stream in a fixed field order —
/// explicit, never serde map/field ordering, so the commitment is bit-identical
/// across nodes and serde versions (a fork-suspect detail, handled here).
fn absorb_entry(buf: &mut Vec<u8>, e: &RotationChainEntry) {
    absorb_str(buf, &e.lineage_id);
    buf.extend_from_slice(&e.hop_index.to_be_bytes());
    absorb_str(buf, &e.record_id);
    absorb_str(buf, &e.record_hash);
    absorb_str(buf, &e.prev_key_hash);
    absorb_str(buf, &e.new_key_hash);
    buf.push(e.kind as u8);
    absorb_str(buf, &e.coord.chain_hash);
    buf.extend_from_slice(&e.coord.round.to_be_bytes());
    absorb_str(buf, &e.coord.zone_path);
    buf.extend_from_slice(&e.coord.epoch.to_be_bytes());
    absorb_str(buf, &e.coord.record_id);
    absorb_str(buf, &e.seal_record_id);
    buf.extend_from_slice(&e.pulse.round.to_be_bytes());
    absorb_str(buf, &e.pulse.randomness);
    buf.extend_from_slice(&e.pulse.genesis_unix.to_be_bytes());
    buf.extend_from_slice(&e.pulse.period_secs.to_be_bytes());
    absorb_opt_str(buf, &e.pulse.chain_hash);
    absorb_opt_str(buf, &e.pulse.signature);
    absorb_opt_str(buf, &e.pulse.previous_signature);
    buf.push(e.state as u8);
    buf.push(e.evidence as u8);
    absorb_opt_str(buf, &e.dispute_outcome);
}

/// Deterministic SHA3-256 (hex) commitment over a set of rotation-chain entries,
/// in canonical per-anchor chain order (§4/B7). Input order does not matter —
/// entries are sorted by `(lineage_id, hop_index)` first — so a full-CF root is
/// reproducible on every node regardless of iteration order.
///
/// This is the pure primitive; the B7 wiring that threads it into snapshot
/// `compute_checksum` (closing the SNAP-1 swap-under-valid-signature footgun)
/// lands with the snapshot-carriage slice. Scale note: a full-CF root is a
/// snapshot-time operation, never a hot path; the incremental-vs-full-recompute
/// choice at 1M-anchor scale belongs to that slice — this fn just hashes the
/// slice it is given.
pub fn rotation_chain_root(entries: &[RotationChainEntry]) -> String {
    let mut ordered: Vec<&RotationChainEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| {
        a.lineage_id
            .cmp(&b.lineage_id)
            .then_with(|| a.hop_index.cmp(&b.hop_index))
    });
    let mut buf: Vec<u8> = Vec::with_capacity(ordered.len() * 256);
    for e in ordered {
        absorb_entry(&mut buf, e);
    }
    crate::crypto::hash::sha3_256_hex(&buf)
}

// ── Hop-field derivation (§3-3 entry construction, §6.1 lineage rule) ─────────
//
// The two §3-3 writers — W1 (finalize-drain hook) and W2 (durable-marker sweep)
// — both build a [`RotationChainEntry`] for a finalized rotation-class member.
// An entry has three provenances: its [`FinalityCoord`] comes from the covering
// seal (§2), its lineage position (`lineage_id` + `hop_index`) comes from
// finalized history (§6.1's derivation rule), and everything else is a pure
// function of the record. These two helpers cover the pure legs so that BOTH
// writers, the sealer membership filter, and the witness re-check inherit ONE
// derivation and cannot drift — the §6.1 / R-2 / R-8 pin-determinism invariant
// (every node computes the same lineage for the same record regardless of WHEN).
// No consensus path calls them yet (W1/W2 are the next slice), so this stays
// zero-runtime-effect.

/// The record-derived structural fields of a rotation *hop* — every
/// [`RotationChainEntry`] field that is a pure function of the record, i.e. all
/// of them EXCEPT the [`FinalityCoord`] (assigned by the covering seal, §2) and
/// the lineage position (`lineage_id` + `hop_index`, resolved from finalized
/// history by [`derive_lineage_position`], §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationHopFields {
    pub kind: RotationKind,
    pub record_id: String,
    /// Lowercase-hex SHA3-256 of the record's signable bytes (`record_hash()`).
    pub record_hash: String,
    /// `sha3(old signing key)` — the key this hop rotates AWAY from. A rotation
    /// record is signed by the OLD key (`key_rotation.rs` banner ll. 24-26), so
    /// that key IS the record's `creator_public_key`; hence this equals the
    /// record's `creator_identity_hash`. For a *first* hop it is by definition
    /// `sha3_256_hex(pk₀)` — precisely the lineage root key hash (§6.1).
    pub prev_key_hash: String,
    /// `sha3(new key)` — the key this hop rotates INTO. A later hop's
    /// `prev_key_hash` matches against this value to chain-link the lineage
    /// (§6.1: hop N+1's `prev_key` is hop N's introduced `new_key`).
    pub new_key_hash: String,
}

/// Extract the pure structural fields of a rotation *hop* from a record, or
/// `None` when the record is not a hop-shaped rotation-class op.
///
/// **Scope fence:** this covers the two clean prev→new hops — `key_rotation`
/// (Dilithium) and `sphincs_key_rotation`. `key_revocation` (a tombstone/freeze,
/// not a prev→new hop) and the Step-2 `authority_transfer` / [`RotationKind::Succession`]
/// kind are deliberately NOT constructed here: their CF-entry shape is defined
/// by the §6.3 resolver slice, so returning `None` keeps this slice from baking
/// in a revocation-entry layout the resolver has not yet fixed.
pub fn rotation_hop_fields(
    record: &crate::record::ValidationRecord,
) -> Option<RotationHopFields> {
    let (kind, new_key, prev_key_hash) =
        if let Some(r) = crate::network::key_rotation::extract_key_rotation(record) {
            // Dilithium: a rotation record is signed by the OLD signing key, so
            // `creator_identity_hash(record) == sha3_256_hex(creator_public_key)`
            // == sha3 of the OLD key == the prev_key this hop rotates away from.
            (
                RotationKind::Rotation,
                r.new_public_key,
                crate::accounting::types::creator_identity_hash(record),
            )
        } else if let Some(r) = crate::network::key_rotation::extract_sphincs_rotation(record) {
            // SPHINCS+ is a Profile-A *secondary* key: the rotation record is
            // signed by the Dilithium PRIMARY, so `creator_identity_hash` is the
            // Dilithium identity hash — NOT the previous SPHINCS key. Using it
            // (the pre-slice-1 behavior) gave EVERY SPHINCS hop of one identity
            // the same `prev_key_hash = sha3(Dilithium)`, so they all collapsed to
            // the same root slot and no SPHINCS lineage could chain past hop 0
            // (KR-3 origin-key audit F4 / v3-H3). The fix: chain on the REAL
            // previous SPHINCS key the record carries in `prev_sphincs_public_key`
            // — `sha3(prev)` equals the predecessor SPHINCS hop's `new_key_hash`,
            // so the introducing-hop lookup links the chain. A legacy record
            // predating the field falls back to the old Dilithium-hash behavior
            // (byte-identical; such a hop simply cannot chain, exactly as before).
            let prev = sphincs_prev_key_hash(record)
                .unwrap_or_else(|| crate::accounting::types::creator_identity_hash(record));
            (RotationKind::SphincsRotation, r.new_sphincs_pk, prev)
        } else {
            return None;
        };
    Some(RotationHopFields {
        kind,
        record_id: record.id.clone(),
        record_hash: hex::encode(record.record_hash()),
        prev_key_hash,
        new_key_hash: crate::crypto::hash::sha3_256_hex(&new_key),
    })
}

/// The hash of a SPHINCS+ hop's PREVIOUS key, read from the record's
/// `prev_sphincs_public_key` metadata (the slice-1 chaining field written by
/// [`crate::network::key_rotation::sphincs_rotation_metadata`]). `sha3(prev)`
/// matches the predecessor SPHINCS hop's `new_key_hash`, which is what the
/// introducing-hop lookup keys on to link the lineage. `None` when the field is
/// absent or not valid hex (a legacy record predating the field) — the caller
/// then falls back to the pre-slice-1 Dilithium-hash behavior.
fn sphincs_prev_key_hash(record: &crate::record::ValidationRecord) -> Option<String> {
    let hex_str = record
        .metadata
        .get("prev_sphincs_public_key")
        .and_then(|v| v.as_str())?;
    let bytes = hex::decode(hex_str).ok()?;
    Some(crate::crypto::hash::sha3_256_hex(&bytes))
}

/// Resolve a hop's `(lineage_id, hop_index)` by §6.1's deterministic derivation
/// rule. `introducing_hop(prev_key_hash)` looks up the finalized hop that
/// rotated INTO this hop's `prev_key` — the entry whose `new_key_hash` equals
/// `prev_key_hash` — returning that predecessor's `(lineage_id, hop_index)`, or
/// `None` when `prev_key` has no introducing hop (it is the lineage root `pk₀`).
///
/// The lookup MECHANISM — a durable predecessor index, present-and-Final by the
/// §5-H3b admission gate — is the §6.1 / H3b wiring slice's to build; this is
/// the pure RULE over whatever that lookup returns, so W1, W2, the sealer
/// filter, and the witness re-check all compute an identical position from
/// identical predecessor state (the R-2 / R-8 pin-determinism invariant). The
/// equivalent CF-behind fallback (§6.1: walk stored predecessor *records* when
/// the CF is momentarily behind) is just a different `introducing_hop` impl over
/// the same rule.
///
/// - Root hop (`introducing_hop` → `None`) → `("{kind_tag}:{prev_key_hash}", 0)`:
///   the record's `prev_key_hash` IS `sha3_256_hex(pk₀)`, and the
///   [`RotationKind::lineage_tag`] prefix keeps a Dilithium chain and a SPHINCS+
///   chain that root at the same key hash disjoint (KR-3 audit C6). The tag lives
///   ONLY in the `lineage_id` component — `prev_key_hash`/`new_key_hash` stay raw
///   key hashes, so the introducing-hop chain-link match is unaffected.
/// - Deeper hop → `(predecessor.lineage_id, predecessor.hop_index + 1)`: the
///   predecessor's `lineage_id` is already tagged, so the tag propagates down the
///   chain and is applied exactly once, at the root.
///
/// [`ROTATION_MAX_CHAIN_DEPTH`] is an admission-time (H3b) policy, not a
/// derivation concern, so this stays faithful — a caller enforces
/// `hop_index < ROTATION_MAX_CHAIN_DEPTH`, never this function silently. The
/// `saturating_add` guards only the arithmetic edge (a `u32::MAX` predecessor
/// index cannot exist under the depth cap; saturating is the panic-free floor).
pub fn derive_lineage_position(
    kind: RotationKind,
    prev_key_hash: &str,
    introducing_hop: impl FnOnce(&str) -> Option<(String, u32)>,
) -> (String, u32) {
    match introducing_hop(prev_key_hash) {
        Some((lineage_id, pred_hop)) => (lineage_id, pred_hop.saturating_add(1)),
        None => (format!("{}:{}", kind.lineage_tag(), prev_key_hash), 0),
    }
}

/// KR-3 S2 wiring-(c) c3-ii: the record's rotation-lineage ROUTING id, or `None`
/// when the record is not a rotation-class hop. This is the ONE content-derived
/// routing key shared by admission (`ingest::rotation_hop_pin` → the durable pin
/// write + the c3-i in-memory publish) AND the consensus seal-membership filters
/// (`epoch::create_epoch_seal_with_balance` + `epoch::scan_window_record_hashes`),
/// so every node computes an identical lineage from identical predecessor
/// state — the R-2/R-8 pin-determinism / anti-fork invariant. Routing both the
/// admission pin and the sealer/witness membership through this single function
/// (rather than each calling `rotation_hop_fields` + `derive_lineage_position`
/// independently) is what keeps them from drifting.
///
/// **Derives from record CONTENT, never a local pin row** (§6.1 item 3): the
/// seal producer and a witness on a node that never admitted this hop still
/// agree bit-for-bit, because the derivation reads only the record's own
/// `prev_key_hash` plus the durable predecessor `newkey_lookup` (a deep hop
/// resolves THROUGH its introducing predecessor to the root lineage; a root
/// hop's `prev_key_hash` IS `sha3(pk₀)` = the lineage id and needs no lookup).
///
/// **Scale fence (CRITICAL — the sealer/witness loop over ≤`MAX_SEAL_RECORDS`
/// (1M) records):** `rotation_hop_fields` is a pure in-memory struct parse of the
/// already-loaded record and returns `None` for every non-rotation op, so a
/// non-rotation record short-circuits BEFORE `newkey_lookup` is ever consulted —
/// zero CF reads on the overwhelmingly-common (no rotation) record.
pub fn rotation_routing_id(
    record: &crate::record::ValidationRecord,
    newkey_lookup: impl FnOnce(&str) -> Option<(String, u32)>,
) -> Option<String> {
    let hop = rotation_hop_fields(record)?;
    let (lineage_id, _hop_index) =
        derive_lineage_position(hop.kind, &hop.prev_key_hash, newkey_lookup);
    Some(lineage_id)
}

// ── Entry construction (§3-3 shared writer core) ─────────────────────────────

/// Compose a complete [`RotationChainEntry`] for a finalized rotation *hop* from
/// its record, the covering seal's coordinate inputs, and the lineage
/// predecessor lookup. This is the ONE entry-construction path shared by both
/// §3-3 writers — W1 (finalize-drain hook) and W2 (durable-marker sweep) — so
/// the two can never drift (the R-2/R-8 pin-determinism invariant: every node
/// builds an identical entry for the same record + covering seal). It is pure —
/// the seal inputs and the `introducing_hop` lookup are the caller's to supply —
/// so it carries no runtime effect on its own; the wiring that feeds it real
/// consensus state is the W1/W2 slice.
///
/// Returns `None` (writes nothing — fail-closed) in exactly the two cases §3/§4
/// specify a rotation record does NOT finalize:
/// - the record is not a clean prev→new rotation hop
///   ([`rotation_hop_fields`] → `None`: revocations — whose CF-entry shape the
///   §6.3 resolver slice owns — and every non-rotation op); or
/// - the covering seal carries no drand `chain_hash`
///   ([`FinalityCoord::from_seal_pulse`] → `None`): a pulse-less seal yields no
///   coordinate, so the rotation stays non-effective (§4).
///
/// `evidence` records which durable leg established the covering seal's finality
/// (§3-3 W2): W1 always passes [`FinalityEvidence::Quorum`] (it runs on the
/// finalize tick with fresh in-memory seal state); W2 passes `Quorum` or
/// [`FinalityEvidence::Burial`] per the leg it used. The entry is written
/// `state = Final` — an entry only ever exists once its covering seal finalized.
#[allow(clippy::too_many_arguments)]
pub fn build_rotation_entry(
    record: &crate::record::ValidationRecord,
    seal_chain_hash: Option<String>,
    seal_round: u64,
    seal_zone_path: String,
    seal_epoch: u64,
    seal_record_id: String,
    pulse: crate::network::time_bracket::DrandPulse,
    evidence: FinalityEvidence,
    introducing_hop: impl FnOnce(&str) -> Option<(String, u32)>,
) -> Option<RotationChainEntry> {
    let hop = rotation_hop_fields(record)?;
    let coord = FinalityCoord::from_seal_pulse(
        seal_chain_hash,
        seal_round,
        seal_zone_path,
        seal_epoch,
        record.id.clone(),
    )?;
    let (lineage_id, hop_index) =
        derive_lineage_position(hop.kind, &hop.prev_key_hash, introducing_hop);
    Some(RotationChainEntry {
        lineage_id,
        hop_index,
        record_id: hop.record_id,
        record_hash: hop.record_hash,
        prev_key_hash: hop.prev_key_hash,
        new_key_hash: hop.new_key_hash,
        kind: hop.kind,
        coord,
        seal_record_id,
        pulse,
        state: RotationState::Final,
        evidence,
        dispute_outcome: None,
    })
}

// ── W2 durable-evidence legs (§3-3 sweep) ────────────────────────────────────
//
// The W2 durable-marker sweep re-derives any rotation-CF entry that W1's
// finalize-drain hook missed (queue-overflow drop-newest, or a crash between
// the fast-track transition and the drain). It MUST establish the covering
// seal's finality from **durable evidence only — never the 24 h-evicted
// attestation trackers** (the round-2 R-1 lesson). The brief (§3-3) names two
// durable legs; these are the PURE deciders over whatever durable state the
// sweep tick (W2-B2) hands them — no DB access, no consensus lock, so this slice
// stays zero-runtime-effect until the sweep wires them. Keeping them pure and
// here (beside `build_rotation_entry`) means W2-B2 inherits verified deciders
// and cannot drift from the threshold the live settlement path uses.

/// The raw 2/3 settlement threshold, integer form — **bit-identical to
/// [`ConsensusEngine::is_settled`](crate::network::consensus) (`consensus.rs:2611`)**:
/// `attesting·3 ≥ eligible·2`, with `saturating_mul` because the release build
/// carries no overflow checks and a raw `*` wraps silently once stake nears
/// `MAX_SUPPLY`, flipping the verdict. `eligible_stake` is the zone settlement
/// denominator already net of the excluded creator stake; a zero denominator
/// never settles (matches `is_settled`'s early return).
///
/// The sweep uses the **raw** recount (not the diverse-weighted
/// `is_seal_settled`) deliberately (§3-3): the durable scheme-(i) `att:` rows
/// carry no stake field and no diversity profile, and Leg A is only ever
/// *decisive* for a seal that is ALSO the zone's canonical chain member (Leg B),
/// where a genuine 2/3 quorum is BFT-unique per slot.
#[inline]
pub fn two_thirds_stake_met(attesting_stake: u64, eligible_stake: u64) -> bool {
    if eligible_stake == 0 {
        return false;
    }
    attesting_stake.saturating_mul(3) >= eligible_stake.saturating_mul(2)
}

/// **Leg A — durable recount.** Re-derives the covering seal's 2/3 quorum from
/// the durable scheme-(i) attestation rows (`att:{seal_rid}:{witness_hash}` →
/// [`AttestationData`](crate::network::witness), *no stake field*), re-deriving
/// each attester's stake through `staked` — the shipped boot-rebuild technique
/// (`elara_node.rs:1640-1682`: `get_latest_attestations` → `ledger.staked(w)`).
///
/// - `attesting_witnesses`: the witness-hash of every durable `att:` row on the
///   seal record. Deduplicated here (a witness counts once) even though the
///   `att:{rid}:{witness}` key is already unique per pair — defensive, and makes
///   the recount independent of how the caller enumerated the rows.
/// - `eligible_stake`: the zone settlement denominator **already net of the
///   excluded seal-creator stake** (the sweep computes it the same way
///   `is_seal_settled` does, `consensus.rs:4323-4328`); a seal creator cannot
///   self-attest, so their stake must not inflate the denominator.
/// - `staked`: the **staked-anchor view** (`ledger.staked` over the
///   settlement-eligible anchor set — see the shared-view invariant, memory
///   `project_staked_anchor_view_cache`). Passing a different view than the one
///   behind `eligible_stake` would compare mismatched numerator/denominator.
///
/// Pure: the caller owns every durable read, so this carries no runtime effect.
pub fn leg_a_quorum_recount<S: AsRef<str>>(
    attesting_witnesses: impl IntoIterator<Item = S>,
    eligible_stake: u64,
    staked: impl Fn(&str) -> u64,
) -> bool {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut attesting_stake: u64 = 0;
    for w in attesting_witnesses {
        let w = w.as_ref();
        if seen.insert(w.to_string()) {
            attesting_stake = attesting_stake.saturating_add(staked(w));
        }
    }
    two_thirds_stake_met(attesting_stake, eligible_stake)
}

/// Verdict of the [`leg_b_canonical_burial`] walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealBurial {
    /// The target sits on the canonical chain with at least
    /// [`ROTATION_SEAL_BURY_DEPTH`] canonical successors above it — durable
    /// finality evidence (Leg B).
    Buried,
    /// The target is on the canonical prefix but with fewer successors than the
    /// bury depth — not yet buried; the marker stays for the next sweep tick.
    Shallow { successors: u64 },
    /// The target was NOT reached walking the canonical chain tip-backward within
    /// the bounded walk — it is either on a non-canonical rival branch (DISC-5
    /// keeps rivals on disk, so "any 2 successors" is NOT burial) or it lies
    /// deeper than `max_walk` (the caller's SCALE bound). No burial evidence;
    /// treated conservatively as not-yet-final.
    NotOnCanonicalPrefix,
}

impl SealBurial {
    /// True only for [`SealBurial::Buried`].
    #[inline]
    pub fn is_buried(&self) -> bool {
        matches!(self, SealBurial::Buried)
    }
}

/// **Leg B — canonical burial.** A seal is buried once at least
/// [`ROTATION_SEAL_BURY_DEPTH`] successors sit above it **on the zone's canonical
/// chain-link history** — each successor's `previous_seal_hash` verified at its
/// own ingest (the C2-authoritative link). This is emphatically NOT "any 2
/// stored successors": DISC-5 preserves rival branches on disk, and a
/// partition-minority could durably chain 2 self-successors onto a losing
/// branch, so burial counts only along the chain the zone's verified history
/// extends (§3-3, round-3 finding).
///
/// `canonical_tip_backward` yields seal hashes from the canonical tip
/// (position 0) backward via `previous_seal_hash` — the caller's walk, exactly
/// as [`derive_lineage_position`] takes its predecessor lookup. The position at
/// which `target_seal_hash` appears IS its canonical successor count (tip = 0
/// successors, tip's parent = 1, …), because on the linked chain every seal
/// walked before the target is a strict successor of it.
///
/// `max_walk` bounds the search so a lazy/unbounded caller walk always
/// terminates (SCALE): if the target is not reached within `max_walk` steps the
/// result is [`SealBurial::NotOnCanonicalPrefix`]. The sweep sizes `max_walk`
/// from `tip_epoch − target_epoch + slack`; for the common recent-marker case
/// the target sits within a step or two of the tip.
pub fn leg_b_canonical_burial(
    target_seal_hash: &[u8; 32],
    canonical_tip_backward: impl IntoIterator<Item = [u8; 32]>,
    max_walk: u64,
) -> SealBurial {
    for (pos, seal_hash) in canonical_tip_backward.into_iter().enumerate() {
        if pos as u64 >= max_walk {
            break;
        }
        if &seal_hash == target_seal_hash {
            let successors = pos as u64;
            return if successors >= ROTATION_SEAL_BURY_DEPTH {
                SealBurial::Buried
            } else {
                SealBurial::Shallow { successors }
            };
        }
    }
    SealBurial::NotOnCanonicalPrefix
}

/// Combine the two durable legs into a §3-3 finality verdict, encoding the
/// brief's **rival discipline**: prefer Leg A (a live 2/3 quorum) — recording
/// [`FinalityEvidence::Quorum`]; else accept Leg-B burial — recording the
/// provisional [`FinalityEvidence::Burial`] (the sweep re-derives it, firing
/// `elara_rotation_cf_canonicality_mismatch_total`, if `canonicalize_latest_seals`
/// later disagrees); else `None` — the seal is not yet final, so the marker
/// stays for the next tick and nothing is written (fail-closed).
///
/// Safety margin (§3, stated in the brief): even a transiently-wrong `Burial`
/// verdict never flips an *effect*, because §3 step 4 gates every effect flip
/// behind the 24 h `ROTATION_DISPUTE_WINDOW` measured from the frozen coordinate
/// — by which time seal cadence (seconds-to-minutes) has long converged burial
/// and canonicality.
#[inline]
pub fn seal_finality_evidence(leg_a_quorum: bool, leg_b: SealBurial) -> Option<FinalityEvidence> {
    if leg_a_quorum {
        Some(FinalityEvidence::Quorum)
    } else if leg_b.is_buried() {
        Some(FinalityEvidence::Burial)
    } else {
        None
    }
}

// ── W2 per-slot sweep planner (§3-3 rival discipline) ────────────────────────
//
// DISC-5 deliberately preserves rival seals at one `(zone, epoch)` slot on
// disk, so the durable-marker sweep (W2-B2) must, per marker slot, decide
// **which** seal's rotation members finalize before it writes anything. This is
// the PURE decision core: the IO layer (W2-B2b) gathers the durable inputs for
// a slot — the candidate seals, their coordinate inputs, their scheme-(i)
// attestation witnesses, the zone's bounded canonical tip-backward walk, the
// eligible settlement stake, and the durable predecessor lookup — hands them
// here, and this returns the exact rotation-CF entries to persist plus whether
// to delete the marker. No DB, no consensus lock, no clock ⇒ zero runtime
// effect until W2-B2b wires it, and exhaustively unit-testable (including the
// §9 races) without a live node.

/// One rival seal at a marker's `(zone, epoch)` DISC-5 slot, with the durable
/// inputs the sweep's IO layer gathered for it (`plan_marker_slot_sweep`).
#[derive(Debug, Clone)]
pub struct SlotSealCandidate {
    /// The seal record's id (offline re-verification / dispute audit; also the
    /// [`RotationChainEntry::seal_record_id`] written for its members).
    pub seal_record_id: String,
    /// The seal record's hash — its canonical-chain identity and the Leg-B
    /// burial target. Only the canonical seal's hash appears on the caller's
    /// canonical walk, so a non-canonical rival is `NotOnCanonicalPrefix` and
    /// can never win by burial (the "NOT any-2-successors" guard, enforced
    /// upstream by the walk itself — see [`leg_b_canonical_burial`]).
    pub seal_hash: [u8; 32],
    /// Coordinate inputs from the parsed seal's drand pulse (§2). `chain_hash`
    /// `None` ⇒ a pulse-less seal ⇒ its members yield no coordinate and cannot
    /// finalize (§4 fail-closed); the marker is then kept, never discharged.
    pub seal_chain_hash: Option<String>,
    pub seal_round: u64,
    pub seal_zone_path: String,
    pub seal_epoch: u64,
    pub pulse: crate::network::time_bracket::DrandPulse,
    /// Witness hashes of every durable scheme-(i) `att:{seal_rid}:{witness}` row
    /// on the SEAL record — the Leg-A recount input (deduped in the recount).
    pub attesting_witnesses: Vec<String>,
    /// The seal's member records, already filtered to rotation *hops* by the IO
    /// layer (`rotation_hop_fields` Some — revocations and non-rotation records
    /// excluded, their entry shape being the §6.3 resolver's).
    pub member_hops: Vec<crate::record::ValidationRecord>,
}

/// The pure outcome of planning one marker slot (`plan_marker_slot_sweep`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerSlotPlan {
    /// Rotation-CF entries to persist (`put_rotation_entry`), one per finalized
    /// member hop of the slot's winning seal. Empty ⇒ nothing to write this tick.
    pub entries: Vec<RotationChainEntry>,
    /// Delete the durable marker iff the slot's rotation-hop obligations are
    /// fully discharged — a final seal was chosen AND every member hop was
    /// written this tick (or the seal had no hop members). Otherwise the marker
    /// stays for the next tick (§3-3: "Not yet final → marker stays"), which
    /// also covers the pulse-less-seal and same-slot-lineage-defer cases below.
    pub delete_marker: bool,
    /// The evidence leg behind the entries written, for the `writer=sweep`
    /// metric split; `None` when nothing was written this tick.
    pub evidence: Option<FinalityEvidence>,
}

/// §3-3 rival discipline: pick THE seal at a DISC-5 slot whose members finalize.
/// A Leg-A quorum wins outright — a genuine 2/3 is BFT-unique per slot, so at
/// most one candidate can hold it (a lowest-index tie-break is purely defensive
/// against a malformed input). Failing that, the canonical seal wins if it is
/// Leg-B buried; canonicality is enforced upstream — only the canonical seal's
/// hash is on the caller's walk, so `is_buried()` implies canonical, and there
/// is at most one buried candidate. Returns the winning index + its evidence.
fn resolve_slot_finality(per_candidate: &[(bool, SealBurial)]) -> Option<(usize, FinalityEvidence)> {
    if let Some(i) = per_candidate.iter().position(|(quorum, _)| *quorum) {
        return Some((i, FinalityEvidence::Quorum));
    }
    if let Some(i) = per_candidate.iter().position(|(_, burial)| burial.is_buried()) {
        return Some((i, FinalityEvidence::Burial));
    }
    None
}

/// Plan the rotation-CF writes for one durable-marker slot (§3-3 W2 sweep, pure
/// core). Evaluates each rival candidate's two durable evidence legs, applies
/// the [`resolve_slot_finality`] rival discipline, then builds a
/// [`RotationChainEntry`] for each member hop of the winning seal.
///
/// - `eligible_stake`: the slot's zone settlement denominator already net of the
///   excluded seal-creator stake (all candidates share the slot's `(zone, epoch)`).
/// - `staked`: the staked-anchor view (`ledger.staked`) — must match the view
///   behind `eligible_stake` (see [`leg_a_quorum_recount`]).
/// - `canonical_prefix`: the zone's canonical chain seal hashes, tip first,
///   bounded by the caller (SCALE); `max_walk` re-bounds it defensively.
/// - `introducing_hop`: the durable `new_key_hash → (lineage_id, hop_index)`
///   predecessor lookup (`get_rotation_newkey_index`) for lineage derivation.
///
/// **Same-slot lineage defer (self-healing):** if two member hops of the SAME
/// lineage land in one seal, the second's predecessor is the first — which is
/// NOT yet in the durable index this tick. Writing it now would mis-derive it as
/// a spurious root. Instead such a member is *deferred* (skipped, marker kept);
/// once the first hop's entry is persisted, the next sweep tick finds the
/// predecessor in the durable index and writes the second correctly. No wrong
/// entry is ever persisted; a rare multi-hop-same-lineage-in-one-epoch slot just
/// converges over a few 60 s ticks — well within the 24 h effect-gate window.
pub fn plan_marker_slot_sweep(
    candidates: &[SlotSealCandidate],
    eligible_stake: u64,
    staked: impl Fn(&str) -> u64,
    canonical_prefix: &[[u8; 32]],
    max_walk: u64,
    introducing_hop: impl Fn(&str) -> Option<(String, u32)>,
) -> MarkerSlotPlan {
    let empty = || MarkerSlotPlan {
        entries: Vec::new(),
        delete_marker: false,
        evidence: None,
    };

    // Per-candidate durable evidence: Leg-A recount + Leg-B canonical burial.
    let per: Vec<(bool, SealBurial)> = candidates
        .iter()
        .map(|c| {
            let leg_a = leg_a_quorum_recount(
                c.attesting_witnesses.iter().map(|s| s.as_str()),
                eligible_stake,
                &staked,
            );
            let leg_b =
                leg_b_canonical_burial(&c.seal_hash, canonical_prefix.iter().copied(), max_walk);
            (leg_a, leg_b)
        })
        .collect();

    let Some((idx, evidence)) = resolve_slot_finality(&per) else {
        return empty(); // no seal final yet → keep the marker
    };
    let winner = &candidates[idx];

    // The new_key hashes introduced by THIS slot's members — a member whose
    // predecessor is one of these is deferred (see the doc-comment above).
    let slot_new_keys: std::collections::HashSet<String> = winner
        .member_hops
        .iter()
        .filter_map(|m| rotation_hop_fields(m).map(|h| h.new_key_hash))
        .collect();

    let mut entries = Vec::with_capacity(winner.member_hops.len());
    let mut deferred = false;
    let mut build_failed = false;
    for member in &winner.member_hops {
        let Some(hop) = rotation_hop_fields(member) else {
            continue; // defensively skip a non-hop (IO layer pre-filters these out)
        };
        let durable = introducing_hop(&hop.prev_key_hash);
        if durable.is_none() && slot_new_keys.contains(&hop.prev_key_hash) {
            // Predecessor is a same-slot member not yet in the durable index →
            // defer to a later tick so we never persist a spurious-root entry.
            deferred = true;
            continue;
        }
        // Feed the already-resolved durable position straight into the builder
        // (avoids a second index lookup; the builder only queries with this
        // member's own prev_key_hash).
        match build_rotation_entry(
            member,
            winner.seal_chain_hash.clone(),
            winner.seal_round,
            winner.seal_zone_path.clone(),
            winner.seal_epoch,
            winner.seal_record_id.clone(),
            winner.pulse.clone(),
            evidence,
            move |_prev| durable,
        ) {
            Some(entry) => entries.push(entry),
            None => build_failed = true, // pulse-less seal → None for every member
        }
    }

    // Discharge the marker only when every hop obligation is written this tick:
    // nothing deferred (same-slot lineage) and nothing failed (pulse-less seal).
    // An all-non-hop seal (member_hops empty) discharges trivially — no hop to
    // record, revocations are the §6.3 resolver's.
    let delete_marker = !deferred && !build_failed;
    let evidence = if entries.is_empty() { None } else { Some(evidence) };
    MarkerSlotPlan {
        entries,
        delete_marker,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coord(chain: &str, round: u64, zone: &str, epoch: u64, id: &str) -> FinalityCoord {
        FinalityCoord {
            chain_hash: chain.to_string(),
            round,
            zone_path: zone.to_string(),
            epoch,
            record_id: id.to_string(),
        }
    }

    #[test]
    fn orders_lexicographically_within_a_chain() {
        let base = coord("cA", 100, "default", 5, "id1");
        // round dominates
        assert_eq!(base.cmp_within_chain(&coord("cA", 101, "default", 5, "id1")), Ok(Ordering::Less));
        // then zone_path
        assert_eq!(base.cmp_within_chain(&coord("cA", 100, "medical/eu", 5, "id1")), Ok(Ordering::Less));
        // then epoch
        assert_eq!(base.cmp_within_chain(&coord("cA", 100, "default", 6, "id1")), Ok(Ordering::Less));
        // then record_id
        assert_eq!(base.cmp_within_chain(&coord("cA", 100, "default", 5, "id2")), Ok(Ordering::Less));
        // equal
        assert_eq!(base.cmp_within_chain(&coord("cA", 100, "default", 5, "id1")), Ok(Ordering::Equal));
        // round beats a later-sorting zone (proves ordering priority, not field concat)
        assert_eq!(
            coord("cA", 100, "zzz", 0, "a").cmp_within_chain(&coord("cA", 101, "aaa", 0, "a")),
            Ok(Ordering::Less)
        );
    }

    #[test]
    fn cross_chain_comparison_is_undefined() {
        let a = coord("chainA", 100, "default", 5, "id1");
        let b = coord("chainB", 5, "default", 1, "id1"); // "smaller" numbers, different chain
        assert_eq!(a.cmp_within_chain(&b), Err(DifferentChain));
        assert_eq!(a.partial_cmp(&b), None);
        // ... even though a naive field-lex order would have said Greater.
        assert_ne!(a, b);
    }

    #[test]
    fn partial_ord_agrees_within_chain() {
        let lo = coord("c", 1, "z", 0, "a");
        let hi = coord("c", 2, "z", 0, "a");
        let lo_again = coord("c", 1, "z", 0, "a");
        assert!(lo < hi);
        assert!(hi > lo);
        assert!(lo <= lo_again);
        assert!(lo >= lo_again);
    }

    #[test]
    fn from_seal_pulse_fails_closed_without_chain_hash() {
        assert!(FinalityCoord::from_seal_pulse(None, 10, "default".into(), 3, "id".into()).is_none());
        let c = FinalityCoord::from_seal_pulse(Some("cA".into()), 10, "default".into(), 3, "id".into());
        assert_eq!(c, Some(coord("cA", 10, "default", 3, "id")));
    }

    #[test]
    fn coord_serde_roundtrips() {
        let c = coord("cA", 42, "medical/eu", 7, "rec-abc");
        let json = serde_json::to_string(&c).expect("serialize");
        let back: FinalityCoord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, back);
    }

    #[test]
    fn lineage_id_is_deterministic_and_key_distinct() {
        let pk0 = b"origin-public-key-bytes";
        let pk1 = b"a-different-key";
        assert_eq!(lineage_id(pk0), lineage_id(pk0), "deterministic");
        assert_ne!(lineage_id(pk0), lineage_id(pk1), "distinct keys → distinct lineage");
        // sha3-256 hex is 64 chars
        assert_eq!(lineage_id(pk0).len(), 64);
        // matches the codebase's existing key-hash convention (sha3_256_hex of raw pk)
        assert_eq!(lineage_id(pk0), crate::crypto::hash::sha3_256_hex(pk0));
    }

    #[test]
    fn pulse_freshness_slack_honours_floor_and_doubling() {
        assert_eq!(pulse_freshness_slack_secs(0), PULSE_FRESHNESS_SLACK_FLOOR_SECS);
        assert_eq!(pulse_freshness_slack_secs(100), 900); // 200 < floor → floor
        assert_eq!(pulse_freshness_slack_secs(600), 1_200); // 2×600 > floor
        assert_eq!(pulse_freshness_slack_secs(u64::MAX), u64::MAX); // saturating, no overflow
    }

    #[test]
    fn secs_to_rounds_rounds_up_and_guards_zero_period() {
        assert_eq!(secs_to_rounds(0, 30), 0);
        assert_eq!(secs_to_rounds(30, 30), 1);
        assert_eq!(secs_to_rounds(31, 30), 2); // rounds up — never under-count a horizon
        assert_eq!(secs_to_rounds(604_800, 30), 20_160); // 7 d at LoE 30 s period
        assert_eq!(secs_to_rounds(100, 0), 100); // zero period treated as 1
    }

    // ── Rotation-chain entry + chain-root (§4 / B7) ──────────────────────────

    use crate::network::time_bracket::DrandPulse;

    fn sample_pulse() -> DrandPulse {
        DrandPulse {
            round: 6_276_496,
            randomness: "deadbeef".into(),
            genesis_unix: 1_692_803_367,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: Some("abcd".into()),
            previous_signature: None,
        }
    }

    fn sample_entry(lineage: &str, hop: u32) -> RotationChainEntry {
        RotationChainEntry {
            lineage_id: lineage.into(),
            hop_index: hop,
            record_id: format!("rec-{hop}"),
            record_hash: "rh".into(),
            prev_key_hash: "pk".into(),
            new_key_hash: "nk".into(),
            kind: RotationKind::Rotation,
            coord: coord("cA", 100 + hop as u64, "default", 5, &format!("rec-{hop}")),
            seal_record_id: "seal-1".into(),
            pulse: sample_pulse(),
            state: RotationState::Final,
            evidence: FinalityEvidence::Quorum,
            dispute_outcome: None,
        }
    }

    #[test]
    fn rotation_entry_serde_roundtrips() {
        let e = sample_entry("aa", 3);
        let json = serde_json::to_string(&e).expect("serialize");
        let back: RotationChainEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(e, back);
    }

    #[test]
    fn chain_root_is_order_independent_and_deterministic() {
        let a = sample_entry("aa", 0);
        let b = sample_entry("aa", 1);
        let c = sample_entry("bb", 0);
        // Canonical order = sort by (lineage_id, hop_index); any input order → same root.
        let r1 = rotation_chain_root(&[a.clone(), b.clone(), c.clone()]);
        let r2 = rotation_chain_root(&[c.clone(), a.clone(), b.clone()]);
        let r3 = rotation_chain_root(&[b, c, a]);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
        assert_eq!(r1.len(), 64, "sha3-256 hex");
    }

    #[test]
    fn chain_root_empty_is_stable() {
        assert_eq!(rotation_chain_root(&[]), rotation_chain_root(&[]));
        // empty set is distinct from any non-empty set
        assert_ne!(rotation_chain_root(&[]), rotation_chain_root(&[sample_entry("aa", 0)]));
    }

    #[test]
    fn chain_root_is_tamper_evident_on_every_field() {
        let base = sample_entry("aa", 2);
        let root = rotation_chain_root(std::slice::from_ref(&base));
        // Mutating ANY field must flip the root — the encoding is injective.
        let mut m;
        macro_rules! flips {
            ($mutate:expr) => {{
                m = base.clone();
                $mutate(&mut m);
                assert_ne!(
                    rotation_chain_root(std::slice::from_ref(&m)),
                    root,
                    "mutation did not change the root"
                );
            }};
        }
        flips!(|e: &mut RotationChainEntry| e.lineage_id = "ab".into());
        flips!(|e: &mut RotationChainEntry| e.hop_index = 3);
        flips!(|e: &mut RotationChainEntry| e.record_id = "x".into());
        flips!(|e: &mut RotationChainEntry| e.record_hash = "x".into());
        flips!(|e: &mut RotationChainEntry| e.prev_key_hash = "x".into());
        flips!(|e: &mut RotationChainEntry| e.new_key_hash = "x".into());
        flips!(|e: &mut RotationChainEntry| e.kind = RotationKind::Revocation);
        flips!(|e: &mut RotationChainEntry| e.coord.chain_hash = "cB".into());
        flips!(|e: &mut RotationChainEntry| e.coord.round = 999);
        flips!(|e: &mut RotationChainEntry| e.coord.zone_path = "medical/eu".into());
        flips!(|e: &mut RotationChainEntry| e.coord.epoch = 99);
        flips!(|e: &mut RotationChainEntry| e.coord.record_id = "x".into());
        flips!(|e: &mut RotationChainEntry| e.seal_record_id = "seal-2".into());
        flips!(|e: &mut RotationChainEntry| e.pulse.round = 1);
        flips!(|e: &mut RotationChainEntry| e.pulse.randomness = "cafe".into());
        flips!(|e: &mut RotationChainEntry| e.pulse.genesis_unix = 1);
        flips!(|e: &mut RotationChainEntry| e.pulse.period_secs = 3);
        flips!(|e: &mut RotationChainEntry| e.pulse.chain_hash = None);
        flips!(|e: &mut RotationChainEntry| e.pulse.signature = None);
        flips!(|e: &mut RotationChainEntry| e.pulse.previous_signature = Some("z".into()));
        flips!(|e: &mut RotationChainEntry| e.state = RotationState::Effective);
        flips!(|e: &mut RotationChainEntry| e.evidence = FinalityEvidence::Burial);
        flips!(|e: &mut RotationChainEntry| e.dispute_outcome = Some("resolved".into()));
    }

    #[test]
    fn chain_root_none_vs_empty_string_distinct() {
        // The presence byte in absorb_opt_str keeps Some("") ≠ None.
        let mut none_case = sample_entry("aa", 0);
        none_case.dispute_outcome = None;
        let mut empty_case = sample_entry("aa", 0);
        empty_case.dispute_outcome = Some(String::new());
        assert_ne!(
            rotation_chain_root(std::slice::from_ref(&none_case)),
            rotation_chain_root(std::slice::from_ref(&empty_case)),
        );
    }

    // ── Hop-field derivation (§3-3 entry construction / §6.1 rule) ────────────

    use crate::record::{Classification, ValidationRecord};

    /// A Dilithium rotation record: signed by `old_key` (the OLD key), rotating
    /// into `new_key`. Mirrors the "signed by the OLD key, carries the NEW key"
    /// invariant the derivation relies on (`key_rotation.rs` banner).
    fn rotation_record(old_key: &[u8], new_key: &[u8]) -> ValidationRecord {
        ValidationRecord::create(
            b"content",
            old_key.to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(new_key, "periodic")),
        )
    }

    fn sphincs_rotation_record(
        old_key: &[u8],
        prev_sphincs: &[u8],
        new_sphincs: &[u8],
    ) -> ValidationRecord {
        ValidationRecord::create(
            b"content",
            old_key.to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::sphincs_rotation_metadata(
                new_sphincs,
                prev_sphincs,
                "upgrade",
            )),
        )
    }

    /// §9 (c3-ii-2a) SCALE fence: a non-rotation record returns `None` WITHOUT
    /// ever consulting the newkey lookup — the property that keeps the
    /// ≤`MAX_SEAL_RECORDS` (1M) seal-window loop free of per-record CF reads on
    /// the overwhelmingly-common (no rotation) record.
    #[test]
    fn rotation_routing_id_non_rotation_short_circuits_without_lookup() {
        let rec = ValidationRecord::create(
            b"x",
            b"k".to_vec(),
            vec![],
            Classification::Public,
            None,
        );
        let mut consulted = false;
        let out = rotation_routing_id(&rec, |_| {
            consulted = true;
            None
        });
        assert_eq!(out, None, "a non-rotation record has no routing lineage");
        assert!(
            !consulted,
            "rotation_hop_fields must short-circuit BEFORE the newkey lookup"
        );
    }

    /// §9 (c3-ii-2a): a root hop routes by its own `prev_key_hash` == `sha3(pk₀)`
    /// == the lineage id (empty predecessor index ⇒ lineage root).
    #[test]
    fn rotation_routing_id_root_hop_is_prev_key_lineage() {
        let rec = rotation_record(b"pk0", b"pk1");
        // Root hop → lineage is the kind-tagged prev_key_hash ("d:" for Dilithium).
        let prev = crate::accounting::types::creator_identity_hash(&rec);
        let out = rotation_routing_id(&rec, |_| None);
        assert_eq!(out, Some(format!("d:{prev}")));
    }

    /// §9 (c3-ii-2a): a deep hop routes by the PREDECESSOR's lineage id from the
    /// durable index — never its own `prev_key` — co-zoning the whole chain
    /// (R-2/R-8). The hop index is irrelevant to routing.
    #[test]
    fn rotation_routing_id_deep_hop_resolves_through_predecessor() {
        let rec = rotation_record(b"pk1", b"pk2");
        let root_lineage = crate::crypto::hash::sha3_256_hex(b"the-root-pk0");
        let own_prev = crate::accounting::types::creator_identity_hash(&rec);
        assert_ne!(root_lineage, own_prev, "test is meaningful: root != own prev");
        let out = rotation_routing_id(&rec, |_| Some((root_lineage.clone(), 4)));
        assert_eq!(out, Some(root_lineage));
    }

    #[test]
    fn rotation_hop_fields_extracts_dilithium_hop() {
        let old = b"old-signing-key-bytes";
        let new = b"new-rotated-in-key-bytes";
        let rec = rotation_record(old, new);
        let f = rotation_hop_fields(&rec).expect("a dilithium rotation is a hop");
        assert_eq!(f.kind, RotationKind::Rotation);
        assert_eq!(f.record_id, rec.id);
        // prev_key_hash = sha3(OLD signing key) = the record's creator_identity_hash.
        assert_eq!(f.prev_key_hash, crate::crypto::hash::sha3_256_hex(old));
        assert_eq!(
            f.prev_key_hash,
            crate::accounting::types::creator_identity_hash(&rec)
        );
        assert_eq!(f.new_key_hash, crate::crypto::hash::sha3_256_hex(new));
        // record_hash is the hex of record_hash() (sha3-256 → 64 hex chars).
        assert_eq!(f.record_hash, hex::encode(rec.record_hash()));
        assert_eq!(f.record_hash.len(), 64);
    }

    #[test]
    fn rotation_hop_fields_extracts_sphincs_hop() {
        let old = b"old-primary-key";
        let prev_sphincs = b"prev-sphincs-secondary-key";
        let new_sphincs = b"new-sphincs-secondary-key";
        let rec = sphincs_rotation_record(old, prev_sphincs, new_sphincs);
        let f = rotation_hop_fields(&rec).expect("a sphincs rotation is a hop");
        assert_eq!(f.kind, RotationKind::SphincsRotation);
        // prev_key_hash chains on the REAL previous SPHINCS key (slice-1 F4 fix),
        // NOT the Dilithium signer (creator_identity_hash).
        assert_eq!(
            f.prev_key_hash,
            crate::crypto::hash::sha3_256_hex(prev_sphincs)
        );
        assert_ne!(
            f.prev_key_hash,
            crate::accounting::types::creator_identity_hash(&rec),
            "the SPHINCS prev-key must not fall back to the Dilithium signer"
        );
        assert_eq!(f.new_key_hash, crate::crypto::hash::sha3_256_hex(new_sphincs));
    }

    #[test]
    fn rotation_hop_fields_none_for_non_hop() {
        // A plain record is not rotation-class at all.
        let plain =
            ValidationRecord::create(b"x", b"k".to_vec(), vec![], Classification::Public, None);
        assert!(rotation_hop_fields(&plain).is_none());
        // A revocation IS rotation-class but is deliberately out of scope for this
        // slice — its CF-entry shape belongs to the §6.3 resolver — so the hop
        // extractor returns None rather than baking in a tombstone layout.
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(
            crate::network::key_rotation::REVOCATION_OP_KEY.into(),
            serde_json::json!(true),
        );
        meta.insert(
            "revoked_public_key".into(),
            serde_json::json!(hex::encode(b"victim-key")),
        );
        meta.insert("revocation_reason".into(), serde_json::json!("compromise"));
        let revoc =
            ValidationRecord::create(b"x", b"k".to_vec(), vec![], Classification::Public, Some(meta));
        assert!(
            rotation_hop_fields(&revoc).is_none(),
            "revocation entry-construction is deferred to §6.3"
        );
    }

    #[test]
    fn consecutive_hops_chain_link_via_key_hashes() {
        // Rotation 1: pk0 → pk1, signed by pk0. Rotation 2: pk1 → pk2, signed by pk1.
        let (pk0, pk1, pk2) = (b"pk0".as_slice(), b"pk1".as_slice(), b"pk2".as_slice());
        let hop1 = rotation_hop_fields(&rotation_record(pk0, pk1)).unwrap();
        let hop2 = rotation_hop_fields(&rotation_record(pk1, pk2)).unwrap();
        // The chain-link the introducing-hop lookup keys on: hop2's prev_key
        // (its signer, pk1) is exactly hop1's introduced new_key.
        assert_eq!(hop1.new_key_hash, hop2.prev_key_hash);
        // hop1's prev (pk0) is the lineage root; the lineage id is "d:" + sha3(pk0).
        assert_eq!(hop1.prev_key_hash, crate::crypto::hash::sha3_256_hex(pk0));
    }

    /// KR-3 slice-1 (F4 / v3-H3): two consecutive SPHINCS+ hops CHAIN. The second
    /// hop's `prev_key_hash` — sha3 of the previous SPHINCS key the record now
    /// carries — equals the first hop's introduced `new_key_hash`, which is what
    /// the introducing-hop lookup keys on, so hop 2 resolves THROUGH hop 1 to the
    /// same lineage at index 1. Before slice-1 every SPHINCS hop's prev_key_hash
    /// fell back to the Dilithium signer, so no SPHINCS lineage could chain past
    /// hop 0 (they all collapsed onto one root slot).
    #[test]
    fn sphincs_hops_chain_via_carried_prev_key() {
        // One Dilithium primary signs both; the SPHINCS chain is s0 → s1 → s2.
        let primary = b"dilithium-primary";
        let (s0, s1, s2) = (
            b"sphincs0".as_slice(),
            b"sphincs1".as_slice(),
            b"sphincs2".as_slice(),
        );
        let hop1 = rotation_hop_fields(&sphincs_rotation_record(primary, s0, s1)).unwrap();
        let hop2 = rotation_hop_fields(&sphincs_rotation_record(primary, s1, s2)).unwrap();
        assert_eq!(hop1.kind, RotationKind::SphincsRotation);
        assert_eq!(hop1.new_key_hash, hop2.prev_key_hash, "s1 links hop1→hop2");
        // Both are keyed on SPHINCS material, never the shared Dilithium signer.
        let dilithium = crate::crypto::hash::sha3_256_hex(primary);
        assert_ne!(hop1.prev_key_hash, dilithium);
        assert_ne!(hop2.prev_key_hash, dilithium);

        // Drive position derivation the way W1/W2 will: hop1 roots (tagged "s:"),
        // hop2 resolves through hop1's introduced key to the SAME lineage, index 1.
        let root = derive_lineage_position(hop1.kind, &hop1.prev_key_hash, |_| None);
        assert_eq!(root, (format!("s:{}", hop1.prev_key_hash), 0));
        let mut index = std::collections::HashMap::new();
        index.insert(hop1.new_key_hash.clone(), root.clone());
        let deep =
            derive_lineage_position(hop2.kind, &hop2.prev_key_hash, |k| index.get(k).cloned());
        assert_eq!(deep, (root.0, 1), "hop2 co-lineages with hop1 at index 1");
    }

    /// KR-3 slice-1 (C6): a Dilithium primary rotation and a SPHINCS+ secondary
    /// rotation of the SAME identity derive DISJOINT lineage roots, so the two
    /// chains can never overwrite each other's `(lineage_id, hop_index)` CF slot
    /// or share a zone-routing key.
    #[test]
    fn sphincs_and_dilithium_roots_distinct_for_same_identity() {
        let primary = b"same-dilithium-primary";
        let dil = rotation_hop_fields(&rotation_record(primary, b"new-dilithium")).unwrap();
        let sph = rotation_hop_fields(&sphincs_rotation_record(
            primary,
            b"sphincs-prev",
            b"sphincs-new",
        ))
        .unwrap();
        let dil_lineage = derive_lineage_position(dil.kind, &dil.prev_key_hash, |_| None).0;
        let sph_lineage = derive_lineage_position(sph.kind, &sph.prev_key_hash, |_| None).0;
        assert_ne!(dil_lineage, sph_lineage, "cross-kind lineages must be disjoint");
        assert!(dil_lineage.starts_with("d:"));
        assert!(sph_lineage.starts_with("s:"));
    }

    /// KR-3 slice-1: a SPHINCS record lacking `prev_sphincs_public_key` (a legacy
    /// record predating the field) falls back to the pre-slice-1 behavior —
    /// prev_key_hash == the Dilithium signer's `creator_identity_hash` — so old
    /// records parse byte-identically.
    #[test]
    fn sphincs_missing_prev_key_falls_back_to_signer() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(
            crate::network::key_rotation::SPHINCS_ROTATION_KEY.into(),
            serde_json::json!(true),
        );
        meta.insert(
            "new_sphincs_public_key".into(),
            serde_json::json!(hex::encode(b"new-sphincs")),
        );
        let rec = ValidationRecord::create(
            b"content",
            b"primary".to_vec(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let f = rotation_hop_fields(&rec).expect("still a sphincs hop");
        assert_eq!(
            f.prev_key_hash,
            crate::accounting::types::creator_identity_hash(&rec),
            "absent prev field ⇒ legacy Dilithium-signer fallback"
        );
    }

    #[test]
    fn derive_lineage_position_root_hop() {
        // No introducing hop → prev_key IS pk₀; lineage_id = "{tag}:{prev_key_hash}", hop 0.
        let pk0_hash = crate::crypto::hash::sha3_256_hex(b"pk0");
        let (lineage, hop) = derive_lineage_position(RotationKind::Rotation, &pk0_hash, |_| None);
        assert_eq!(lineage, format!("d:{pk0_hash}"));
        assert_eq!(hop, 0);
    }

    /// The kind tag makes a Dilithium root and a SPHINCS+ root that share the
    /// SAME `prev_key_hash` land on DISTINCT lineages (KR-3 audit C6): the
    /// cross-kind CF-slot / zone-routing collision cannot occur.
    #[test]
    fn derive_lineage_position_root_namespaced_by_kind() {
        let shared = crate::crypto::hash::sha3_256_hex(b"same-root-hash");
        let (d_lineage, _) =
            derive_lineage_position(RotationKind::Rotation, &shared, |_| None);
        let (s_lineage, _) =
            derive_lineage_position(RotationKind::SphincsRotation, &shared, |_| None);
        assert_eq!(d_lineage, format!("d:{shared}"));
        assert_eq!(s_lineage, format!("s:{shared}"));
        assert_ne!(d_lineage, s_lineage, "cross-kind roots must not collide");
    }

    #[test]
    fn derive_lineage_position_deep_hop_copies_lineage_and_increments() {
        let lineage = crate::crypto::hash::sha3_256_hex(b"pk0");
        let lineage_c = lineage.clone();
        // Predecessor is hop 4 of that lineage → this hop is 5, same lineage id.
        let (l, hop) = derive_lineage_position(RotationKind::Rotation, "prev-hash", move |k| {
            assert_eq!(k, "prev-hash"); // the rule queries by prev_key_hash
            Some((lineage_c, 4))
        });
        assert_eq!(l, lineage);
        assert_eq!(hop, 5);
    }

    #[test]
    fn pin_determinism_full_depth_chain_is_stable_across_nodes() {
        // Simulate a lineage pk0 → pk1 → … as ROTATION_MAX_CHAIN_DEPTH hops. The
        // "introducing-hop index" maps new_key_hash → (lineage_id, hop_index) —
        // exactly what the §6.1/H3b durable index (or the record-walk fallback)
        // will provide. We build the chain by deriving each hop's position and
        // inserting its new_key_hash, mirroring what W1/W2 do at finalize time,
        // then assert every hop lands on the SAME lineage_id (= sha3(pk0)) with a
        // strictly increasing hop_index — and that a second node rebuilding the
        // same chain gets byte-identical positions (no per-node state, R-2/R-8).
        use std::collections::HashMap;
        let keys: Vec<Vec<u8>> = (0..=ROTATION_MAX_CHAIN_DEPTH)
            .map(|i| format!("pk{i}").into_bytes())
            .collect();
        let expected_lineage = format!("d:{}", crate::crypto::hash::sha3_256_hex(&keys[0]));

        let build = || {
            let mut index: HashMap<String, (String, u32)> = HashMap::new();
            let mut positions = Vec::new();
            for i in 0..(keys.len() - 1) {
                let prev_hash = crate::crypto::hash::sha3_256_hex(&keys[i]);
                let new_hash = crate::crypto::hash::sha3_256_hex(&keys[i + 1]);
                let (lineage, hop) = derive_lineage_position(
                    RotationKind::Rotation,
                    &prev_hash,
                    |k| index.get(k).cloned(),
                );
                index.insert(new_hash, (lineage.clone(), hop));
                positions.push((lineage, hop));
            }
            positions
        };

        let positions_a = build();
        // Every hop is the same lineage; hop_index runs 0..ROTATION_MAX_CHAIN_DEPTH.
        assert_eq!(positions_a.len(), ROTATION_MAX_CHAIN_DEPTH as usize);
        for (i, (lineage, hop)) in positions_a.iter().enumerate() {
            assert_eq!(*lineage, expected_lineage, "hop {i} lineage");
            assert_eq!(*hop, i as u32, "hop {i} index");
        }
        assert_eq!(positions_a.last().unwrap().1, ROTATION_MAX_CHAIN_DEPTH - 1);

        // Independent second node, same order → byte-identical positions.
        let positions_b = build();
        assert_eq!(positions_a, positions_b, "two nodes derive identical positions");
    }

    // ── Entry construction (build_rotation_entry — §3-3 shared writer core) ────

    #[test]
    fn build_rotation_entry_composes_root_hop() {
        let (old, new) = (b"pk0".as_slice(), b"pk1".as_slice());
        let rec = rotation_record(old, new);
        let e = build_rotation_entry(
            &rec,
            Some("cA".into()),
            100,
            "default".into(),
            5,
            "seal-1".into(),
            sample_pulse(),
            FinalityEvidence::Quorum,
            |_| None, // no introducing hop → root
        )
        .expect("a rotation hop over a pulse-bearing seal builds an entry");
        // Root hop: lineage_id = "d:" + sha3(pk0), hop_index 0.
        assert_eq!(e.lineage_id, format!("d:{}", crate::crypto::hash::sha3_256_hex(old)));
        assert_eq!(e.hop_index, 0);
        assert_eq!(e.kind, RotationKind::Rotation);
        assert_eq!(e.record_id, rec.id);
        assert_eq!(e.prev_key_hash, crate::crypto::hash::sha3_256_hex(old));
        assert_eq!(e.new_key_hash, crate::crypto::hash::sha3_256_hex(new));
        // Coordinate is assigned entirely by the covering seal, never the record.
        assert_eq!(e.coord.chain_hash, "cA");
        assert_eq!(e.coord.round, 100);
        assert_eq!(e.coord.zone_path, "default");
        assert_eq!(e.coord.epoch, 5);
        assert_eq!(e.coord.record_id, rec.id);
        assert_eq!(e.seal_record_id, "seal-1");
        // An entry only exists once its seal finalized → always Final at write.
        assert_eq!(e.state, RotationState::Final);
        assert_eq!(e.evidence, FinalityEvidence::Quorum);
        assert_eq!(e.dispute_outcome, None);
    }

    #[test]
    fn build_rotation_entry_deep_hop_uses_predecessor() {
        let (k1, k2) = (b"pk1".as_slice(), b"pk2".as_slice());
        let rec = rotation_record(k1, k2); // signed by pk1, rotates into pk2
        let lineage = crate::crypto::hash::sha3_256_hex(b"pk0");
        let lineage_c = lineage.clone();
        let e = build_rotation_entry(
            &rec,
            Some("cA".into()),
            200,
            "default".into(),
            7,
            "seal-2".into(),
            sample_pulse(),
            FinalityEvidence::Quorum,
            // introducing hop for prev_key (pk1) is hop 3 of the lineage.
            move |k| {
                assert_eq!(k, crate::crypto::hash::sha3_256_hex(k1));
                Some((lineage_c, 3))
            },
        )
        .expect("deep hop builds");
        assert_eq!(e.lineage_id, lineage, "lineage copied forward from predecessor");
        assert_eq!(e.hop_index, 4, "predecessor hop 3 → this hop 4");
    }

    #[test]
    fn build_rotation_entry_sphincs_hop() {
        let rec = sphincs_rotation_record(b"pk0", b"prev-sphincs", b"new-sphincs");
        let e = build_rotation_entry(
            &rec,
            Some("cA".into()),
            1,
            "z".into(),
            1,
            "s".into(),
            sample_pulse(),
            FinalityEvidence::Quorum,
            |_| None,
        )
        .expect("sphincs rotation is a hop");
        assert_eq!(e.kind, RotationKind::SphincsRotation);
    }

    #[test]
    fn build_rotation_entry_none_for_non_hop() {
        // Plain (non-rotation) record → not a hop → None (writes nothing).
        let plain =
            ValidationRecord::create(b"x", b"k".to_vec(), vec![], Classification::Public, None);
        assert!(
            build_rotation_entry(
                &plain,
                Some("cA".into()),
                1,
                "z".into(),
                1,
                "s".into(),
                sample_pulse(),
                FinalityEvidence::Quorum,
                |_| None,
            )
            .is_none()
        );
    }

    #[test]
    fn build_rotation_entry_none_for_pulseless_seal() {
        // A pulse-less covering seal (no drand chain_hash) yields no coordinate,
        // so the rotation stays non-effective — §4 fail-closed, writes nothing.
        let rec = rotation_record(b"pk0", b"pk1");
        assert!(
            build_rotation_entry(
                &rec,
                None, // no chain_hash → from_seal_pulse → None
                100,
                "default".into(),
                5,
                "seal-1".into(),
                sample_pulse(),
                FinalityEvidence::Quorum,
                |_| None,
            )
            .is_none(),
            "pulse-less seal must not finalize a rotation-class record"
        );
    }

    #[test]
    fn build_rotation_entry_full_chain_links_and_shares_lineage() {
        // Drive a full lineage through build_rotation_entry the way W1/W2 will:
        // each entry's new_key_hash → its position feeds the next hop's lookup.
        use std::collections::HashMap;
        let mut index: HashMap<String, (String, u32)> = HashMap::new();
        let keys: Vec<Vec<u8>> = (0..=4).map(|i| format!("pk{i}").into_bytes()).collect();
        let expected_lineage = format!("d:{}", crate::crypto::hash::sha3_256_hex(&keys[0]));
        let mut entries = Vec::new();
        for i in 0..(keys.len() - 1) {
            let rec = rotation_record(&keys[i], &keys[i + 1]);
            let e = build_rotation_entry(
                &rec,
                Some("cA".into()),
                100 + i as u64,
                "default".into(),
                i as u64,
                format!("seal-{i}"),
                sample_pulse(),
                FinalityEvidence::Quorum,
                |k| index.get(k).cloned(),
            )
            .expect("hop builds");
            index.insert(e.new_key_hash.clone(), (e.lineage_id.clone(), e.hop_index));
            entries.push(e);
        }
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.lineage_id, expected_lineage, "hop {i} shares lineage");
            assert_eq!(e.hop_index, i as u32, "hop {i} index");
        }
        // Chain-link holds: hop N's new_key == hop N+1's prev_key.
        for w in entries.windows(2) {
            assert_eq!(w[0].new_key_hash, w[1].prev_key_hash);
        }
    }

    // ── W2 durable-evidence legs (Leg A recount / Leg B burial / combiner) ────

    #[test]
    fn two_thirds_threshold_matches_is_settled_arithmetic() {
        // Inclusive boundary: attesting·3 ≥ eligible·2.
        // eligible=3 → threshold stake = 2 (2·3=6 ≥ 3·2=6).
        assert!(two_thirds_stake_met(2, 3));
        assert!(!two_thirds_stake_met(1, 3)); // 1·3=3 < 3·2=6
        // eligible=9 → need 6 (6·3=18 ≥ 9·2=18); 5 falls short (15 < 18).
        assert!(two_thirds_stake_met(6, 9));
        assert!(!two_thirds_stake_met(5, 9));
        // Full stake always meets it.
        assert!(two_thirds_stake_met(100, 100));
        // Zero eligible never settles (mirrors is_settled early return).
        assert!(!two_thirds_stake_met(0, 0));
        assert!(!two_thirds_stake_met(1_000, 0));
        // Zero attesting against positive eligible fails.
        assert!(!two_thirds_stake_met(0, 1));
    }

    #[test]
    fn two_thirds_threshold_saturates_instead_of_wrapping() {
        // A raw `attesting * 3` would wrap in a release build near u64::MAX and
        // could flip the verdict; saturating_mul pins it to u64::MAX so a huge
        // attesting stake still meets a huge (but ≤) eligible.
        assert!(two_thirds_stake_met(u64::MAX, u64::MAX));
        // Huge eligible, tiny attesting → correctly fails (no wrap-to-true).
        assert!(!two_thirds_stake_met(1, u64::MAX));
    }

    #[test]
    fn leg_a_recount_sums_distinct_witness_stake() {
        // Stake view: three staked witnesses, one unstaked.
        let staked = |w: &str| -> u64 {
            match w {
                "wa" => 10,
                "wb" => 10,
                "wc" => 10,
                _ => 0,
            }
        };
        // eligible = 30 → threshold = 20 (attesting·3 ≥ 30·2=60 ⇒ attesting ≥ 20).
        // wa+wb = 20 → meets exactly.
        assert!(leg_a_quorum_recount(
            vec!["wa".to_string(), "wb".to_string()],
            30,
            staked
        ));
        // wa alone = 10 → short.
        assert!(!leg_a_quorum_recount(vec!["wa".to_string()], 30, staked));
        // An unstaked witness adds nothing.
        assert!(!leg_a_quorum_recount(
            vec!["wa".to_string(), "unknown".to_string()],
            30,
            staked
        ));
    }

    #[test]
    fn leg_a_recount_dedups_repeated_witness() {
        let staked = |w: &str| -> u64 { if w == "wa" { 100 } else { 0 } };
        // The same witness listed 3× must count its stake ONCE — a duplicated
        // att row cannot manufacture a quorum. 100 counted once, eligible 200 →
        // 100·3=300 < 200·2=400 → not met.
        assert!(!leg_a_quorum_recount(
            vec!["wa".to_string(), "wa".to_string(), "wa".to_string()],
            200,
            staked
        ));
        // Counted once against a smaller denominator it does meet: eligible 150 →
        // 100·3=300 ≥ 150·2=300.
        assert!(leg_a_quorum_recount(
            vec!["wa".to_string(), "wa".to_string()],
            150,
            staked
        ));
    }

    #[test]
    fn leg_a_recount_accepts_str_slices() {
        // AsRef<str> bound accepts &str borrows straight from AttestationData.
        let staked = |_: &str| -> u64 { 5 };
        let witnesses = ["w1", "w2", "w3"];
        // 3 distinct × 5 = 15; eligible 21 → 15·3=45 ≥ 21·2=42 → met.
        assert!(leg_a_quorum_recount(witnesses.iter().copied(), 21, staked));
    }

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn leg_b_burial_counts_canonical_successors_as_walk_position() {
        // Canonical chain tip-backward: tip=S4, S3, S2, S1, S0(genesis).
        let chain = vec![h(4), h(3), h(2), h(1), h(0)];
        // Target = tip → 0 successors → Shallow{0}.
        assert_eq!(
            leg_b_canonical_burial(&h(4), chain.clone(), 100),
            SealBurial::Shallow { successors: 0 }
        );
        // Target = tip's parent → 1 successor → Shallow{1} (< bury depth 2).
        assert_eq!(
            leg_b_canonical_burial(&h(3), chain.clone(), 100),
            SealBurial::Shallow { successors: 1 }
        );
        // Target buried exactly at the depth threshold (2 successors) → Buried.
        assert_eq!(
            leg_b_canonical_burial(&h(2), chain.clone(), 100),
            SealBurial::Buried
        );
        assert!(leg_b_canonical_burial(&h(2), chain.clone(), 100).is_buried());
        // Deeper still → Buried.
        assert_eq!(
            leg_b_canonical_burial(&h(1), chain.clone(), 100),
            SealBurial::Buried
        );
        assert_eq!(
            leg_b_canonical_burial(&h(0), chain, 100),
            SealBurial::Buried
        );
    }

    #[test]
    fn leg_b_burial_rejects_seal_absent_from_canonical_prefix() {
        // A rival-branch seal (h(9)) never appears on the canonical tip-backward
        // walk — even though on disk it may have its own 2 self-successors, it is
        // NOT buried on the canonical chain. This is the "NOT any-2-successors"
        // guard: burial counts only along canonical history.
        let canonical = vec![h(4), h(3), h(2), h(1), h(0)];
        assert_eq!(
            leg_b_canonical_burial(&h(9), canonical, 100),
            SealBurial::NotOnCanonicalPrefix
        );
        assert!(!leg_b_canonical_burial(&h(9), vec![h(4), h(3), h(2)], 100).is_buried());
    }

    #[test]
    fn leg_b_burial_respects_max_walk_bound() {
        // Target is genuinely canonical but sits at depth 5; a max_walk of 3 only
        // examines positions 0,1,2 → target unseen → NotOnCanonicalPrefix
        // (conservative false — the marker is retried next tick). SCALE guard:
        // an unbounded lazy walk always terminates.
        let deep_chain = vec![h(5), h(4), h(3), h(2), h(1), h(0)];
        assert_eq!(
            leg_b_canonical_burial(&h(1), deep_chain.clone(), 3),
            SealBurial::NotOnCanonicalPrefix
        );
        // With a bound that reaches it, the same target is Buried (depth 4 ≥ 2).
        assert_eq!(
            leg_b_canonical_burial(&h(1), deep_chain, 100),
            SealBurial::Buried
        );
    }

    #[test]
    fn leg_b_burial_stops_walking_once_target_found() {
        // The walk must short-circuit at the target so a lazy caller iterator is
        // not consumed past it. We prove it by making the iterator panic if asked
        // for an element beyond the target's position.
        let target = h(2); // at position 2 in 4,3,2,...
        let seq = [h(4), h(3), h(2), h(1), h(0)];
        let guarded = seq.into_iter().enumerate().map(|(i, v)| {
            assert!(i <= 2, "walk consumed past the found target at position {i}");
            v
        });
        assert_eq!(
            leg_b_canonical_burial(&target, guarded, 100),
            SealBurial::Buried
        );
    }

    #[test]
    fn seal_finality_evidence_prefers_quorum_then_burial_then_none() {
        // Leg A wins even when Leg B would also fire (prefer the live quorum).
        assert_eq!(
            seal_finality_evidence(true, SealBurial::Buried),
            Some(FinalityEvidence::Quorum)
        );
        assert_eq!(
            seal_finality_evidence(true, SealBurial::NotOnCanonicalPrefix),
            Some(FinalityEvidence::Quorum)
        );
        // No quorum but buried → provisional Burial evidence.
        assert_eq!(
            seal_finality_evidence(false, SealBurial::Buried),
            Some(FinalityEvidence::Burial)
        );
        // No quorum, not buried (shallow or off-chain) → not yet final → None.
        assert_eq!(
            seal_finality_evidence(false, SealBurial::Shallow { successors: 1 }),
            None
        );
        assert_eq!(
            seal_finality_evidence(false, SealBurial::NotOnCanonicalPrefix),
            None
        );
    }

    #[test]
    fn seal_bury_depth_constant_is_two() {
        // Pin the depth the burial legs count against — a silent change here would
        // alter the finality predicate.
        assert_eq!(ROTATION_SEAL_BURY_DEPTH, 2);
    }

    // ── W2 per-slot sweep planner (rival discipline + member entry planning) ──

    /// Even split so `w1`+`w2` reach the 2/3 bar against `eligible = 3`
    /// (attesting 2 → 2·3 ≥ 3·2). Any other witness is unstaked.
    fn even_staked(w: &str) -> u64 {
        if w == "w1" || w == "w2" {
            1
        } else {
            0
        }
    }

    fn slot_candidate(
        seal_id: &str,
        seal_hash: [u8; 32],
        witnesses: &[&str],
        members: Vec<ValidationRecord>,
    ) -> SlotSealCandidate {
        SlotSealCandidate {
            seal_record_id: seal_id.into(),
            seal_hash,
            seal_chain_hash: Some("cA".into()),
            seal_round: 100,
            seal_zone_path: "default".into(),
            seal_epoch: 5,
            pulse: sample_pulse(),
            attesting_witnesses: witnesses.iter().map(|s| s.to_string()).collect(),
            member_hops: members,
        }
    }

    #[test]
    fn resolve_slot_finality_prefers_quorum_then_burial_then_none() {
        use SealBurial::*;
        // Quorum at index 1 wins even though index 0 is buried.
        assert_eq!(
            resolve_slot_finality(&[(false, Buried), (true, NotOnCanonicalPrefix)]),
            Some((1, FinalityEvidence::Quorum))
        );
        // No quorum → the buried (canonical) candidate wins.
        assert_eq!(
            resolve_slot_finality(&[(false, Shallow { successors: 1 }), (false, Buried)]),
            Some((1, FinalityEvidence::Burial))
        );
        // Nothing final yet.
        assert_eq!(
            resolve_slot_finality(&[(false, Shallow { successors: 0 }), (false, NotOnCanonicalPrefix)]),
            None
        );
        assert_eq!(resolve_slot_finality(&[]), None);
    }

    #[test]
    fn plan_slot_quorum_winner_writes_and_discharges() {
        let m = rotation_record(b"pk0", b"pk1");
        let cand = slot_candidate("seal-1", h(4), &["w1", "w2"], vec![m.clone()]);
        let plan = plan_marker_slot_sweep(&[cand], 3, even_staked, &[h(9), h(8), h(4)], 100, |_| None);
        assert_eq!(plan.entries.len(), 1);
        assert!(plan.delete_marker);
        assert_eq!(plan.evidence, Some(FinalityEvidence::Quorum));
        let e = &plan.entries[0];
        assert_eq!(e.lineage_id, format!("d:{}", crate::crypto::hash::sha3_256_hex(b"pk0")));
        assert_eq!(e.hop_index, 0);
        assert_eq!(e.evidence, FinalityEvidence::Quorum);
        assert_eq!(e.seal_record_id, "seal-1");
        assert_eq!(e.record_id, m.id);
    }

    #[test]
    fn plan_slot_burial_winner_when_no_quorum() {
        // No attesters → no Leg-A; canonical walk buries h(2) at position 2.
        let cand = slot_candidate("seal-b", h(2), &[], vec![rotation_record(b"pk0", b"pk1")]);
        let plan = plan_marker_slot_sweep(&[cand], 100, |_| 0, &[h(4), h(3), h(2), h(1)], 100, |_| None);
        assert_eq!(plan.entries.len(), 1);
        assert!(plan.delete_marker);
        assert_eq!(plan.evidence, Some(FinalityEvidence::Burial));
        assert_eq!(plan.entries[0].evidence, FinalityEvidence::Burial);
    }

    #[test]
    fn plan_slot_not_final_keeps_marker() {
        // h(3) sits at position 1 → Shallow; no quorum → NotYet → keep the marker.
        let cand = slot_candidate("seal-s", h(3), &[], vec![rotation_record(b"pk0", b"pk1")]);
        let plan = plan_marker_slot_sweep(&[cand], 100, |_| 0, &[h(4), h(3), h(2)], 100, |_| None);
        assert!(plan.entries.is_empty());
        assert!(!plan.delete_marker);
        assert_eq!(plan.evidence, None);
    }

    #[test]
    fn plan_slot_quorum_preferred_over_burial_rival() {
        // A: quorum, hash NOT on canonical walk. B: canonical + buried, no quorum.
        let cand_a = slot_candidate("seal-a", h(7), &["w1", "w2"], vec![rotation_record(b"a0", b"a1")]);
        let cand_b = slot_candidate("seal-b", h(2), &[], vec![rotation_record(b"b0", b"b1")]);
        let plan =
            plan_marker_slot_sweep(&[cand_a, cand_b], 3, even_staked, &[h(4), h(3), h(2)], 100, |_| None);
        assert_eq!(plan.evidence, Some(FinalityEvidence::Quorum));
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].seal_record_id, "seal-a");
        assert_eq!(plan.entries[0].lineage_id, format!("d:{}", crate::crypto::hash::sha3_256_hex(b"a0")));
        assert!(plan.delete_marker);
    }

    #[test]
    fn plan_slot_noncanonical_rival_never_buried() {
        // Rival hash h(9) is absent from the canonical walk and has no quorum →
        // the "NOT any-2-successors" guard: no evidence, marker stays.
        let cand = slot_candidate("seal-r", h(9), &[], vec![rotation_record(b"pk0", b"pk1")]);
        let plan = plan_marker_slot_sweep(&[cand], 100, |_| 0, &[h(4), h(3), h(2), h(1)], 100, |_| None);
        assert!(plan.entries.is_empty());
        assert!(!plan.delete_marker);
    }

    #[test]
    fn plan_slot_pulseless_winner_keeps_marker() {
        // Quorum met, but the winning seal carries no chain_hash → no coordinate
        // → build yields None for every member → fail-closed, marker kept.
        let mut cand = slot_candidate("seal-p", h(4), &["w1", "w2"], vec![rotation_record(b"pk0", b"pk1")]);
        cand.seal_chain_hash = None;
        let plan = plan_marker_slot_sweep(&[cand], 3, even_staked, &[h(4)], 100, |_| None);
        assert!(plan.entries.is_empty());
        assert!(!plan.delete_marker, "pulse-less seal must not discharge the marker");
        assert_eq!(plan.evidence, None);
    }

    #[test]
    fn plan_slot_same_lineage_defers_dependent_hop() {
        // Two hops of ONE lineage in one seal: pk0→pk1 and pk1→pk2. With an empty
        // durable index, hop2's predecessor (pk1) is a SAME-SLOT member, so hop2
        // is deferred (writing it now would mis-root it); hop1 (root) is written,
        // and the marker is kept so the next tick completes hop2.
        let hop1 = rotation_record(b"pk0", b"pk1");
        let hop2 = rotation_record(b"pk1", b"pk2");
        let cand = slot_candidate("seal-x", h(4), &["w1", "w2"], vec![hop1, hop2]);
        let plan = plan_marker_slot_sweep(&[cand], 3, even_staked, &[h(4)], 100, |_| None);
        assert_eq!(plan.entries.len(), 1, "only the root hop is written this tick");
        assert_eq!(plan.entries[0].new_key_hash, crate::crypto::hash::sha3_256_hex(b"pk1"));
        assert_eq!(plan.entries[0].hop_index, 0);
        assert!(!plan.delete_marker, "dependent hop deferred → marker kept");
        assert_eq!(plan.evidence, Some(FinalityEvidence::Quorum));
    }

    #[test]
    fn plan_slot_durable_predecessor_chains_hop_index() {
        // The member's predecessor (pk1) is already in the durable index at hop 3
        // → this hop chains to index 4 on the same lineage, and discharges.
        let cand = slot_candidate("seal-d", h(4), &["w1", "w2"], vec![rotation_record(b"pk1", b"pk2")]);
        let lineage = crate::crypto::hash::sha3_256_hex(b"pk0");
        let lineage_c = lineage.clone();
        let plan = plan_marker_slot_sweep(&[cand], 3, even_staked, &[h(4)], 100, move |k| {
            if k == crate::crypto::hash::sha3_256_hex(b"pk1") {
                Some((lineage_c.clone(), 3))
            } else {
                None
            }
        });
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].lineage_id, lineage);
        assert_eq!(plan.entries[0].hop_index, 4);
        assert!(plan.delete_marker);
    }

    #[test]
    fn plan_slot_independent_members_all_written() {
        let cand = slot_candidate(
            "seal-m",
            h(4),
            &["w1", "w2"],
            vec![rotation_record(b"a0", b"a1"), rotation_record(b"b0", b"b1")],
        );
        let plan = plan_marker_slot_sweep(&[cand], 3, even_staked, &[h(4)], 100, |_| None);
        assert_eq!(plan.entries.len(), 2);
        assert!(plan.delete_marker);
        let got: std::collections::HashSet<String> =
            plan.entries.iter().map(|e| e.lineage_id.clone()).collect();
        assert!(got.contains(&format!("d:{}", crate::crypto::hash::sha3_256_hex(b"a0"))));
        assert!(got.contains(&format!("d:{}", crate::crypto::hash::sha3_256_hex(b"b0"))));
    }

    #[test]
    fn plan_slot_no_hop_members_discharges_without_writing() {
        // A final (canonical-buried) seal whose rotation members were all
        // revocations → the IO layer passes member_hops empty. No hop to record,
        // but the hop obligation IS discharged (revocations are the §6.3
        // resolver's), so the marker is deleted and nothing is written.
        let cand = slot_candidate("seal-e", h(2), &[], vec![]);
        let plan = plan_marker_slot_sweep(&[cand], 100, |_| 0, &[h(4), h(3), h(2)], 100, |_| None);
        assert!(plan.entries.is_empty());
        assert!(plan.delete_marker);
        assert_eq!(plan.evidence, None);
    }

    #[test]
    fn plan_slot_empty_candidates_is_noop() {
        let plan = plan_marker_slot_sweep(&[], 100, |_| 0, &[], 100, |_| None);
        assert!(plan.entries.is_empty());
        assert!(!plan.delete_marker);
        assert_eq!(plan.evidence, None);
    }
}
