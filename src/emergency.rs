//! EmergencyHalt / EmergencyResume — a signed, auditable, gossip-propagating
//! consensus circuit-breaker.
//!
//! The problem this closes: on the live chain the only way to stop a misbehaving
//! network is to ssh in and kill the process — unauditable, non-propagating, and
//! indistinguishable to a follower from a crash. This module is the signed-record
//! alternative: the genesis authority (pre-S3) signs an [`EmergencyHalt`]; every
//! node that verifies it stops admitting NEW external writes (an *ingest* gate, not
//! a seal gate — see below); a signed [`EmergencyResume`] lifts it.
//!
//! ## Design (fusion-audited 2026-06-28, internal design notes)
//! - **Node-local, never consensus-folded.** The halt state is exactly the
//!   fork-character of the disk-pressure ingest gate (`network::ingest`): an
//!   observed-local condition that suppresses local writes and is NEVER mixed into
//!   the account-SMT root, an epoch seal, a snapshot checksum, or a light-client
//!   proof. A halted node simply emits/admits less; "stop" cannot fork.
//! - **Ingest-gate ONLY.** Seal production is deliberately NOT gated: with the
//!   bootstrap carve-out (`staked.len() < 3`) the genesis authority is the sole
//!   proposer, so gating seals would freeze the chain fleet-wide with no in-protocol
//!   recovery, and a seal rule keyed on a gossiped flag would re-introduce the
//!   proposer↔verifier split-brain fork class. "Halt" therefore means **stop
//!   admitting new external writes**, NOT "freeze the tip" — records already in the
//!   DAG, governance ops, and sync/replay still finalize.
//! - **Max-fold, order-independent, replay-immune.** `halted ⟺ latest_halt_nonce >
//!   latest_resume_nonce`. Both are max-folds over the *authority-signed* records, so
//!   a re-gossiped stale `Halt@5` after `Resume@5` leaves `5 > 5` false. This is the
//!   monotonic-revocation precedent (`crate::mandate`), but — unlike revocation,
//!   which is stored unconditionally and authorized at read time — the halt *acts*
//!   at ingest time, so authority-binding (`sha3(creator_pk) == genesis_authority`)
//!   is enforced at FOLD time by the node layer.
//! - **Wall-clock auto-expiry (continuity backstop).** If the authority halts then
//!   loses its key, the chain would brick forever. Each halt carries
//!   `max_duration_secs`; the gate self-clears at `issued_ts + min(max_duration_secs,
//!   MAX_HALT_DURATION_SECS)`. Wall-clock (not epoch-number) is deliberate: an
//!   epoch-number expiry never fires on an authority-gone follower (its sealed tip is
//!   frozen), while wall-clock self-heals regardless. Safe precisely because the halt
//!   is node-local — cross-node clock skew only shifts the admit/reject boundary by
//!   seconds (the same benign "delayed-write" character as disk-pressure
//!   self-clearing at different `statvfs` moments per node), never a consensus fork.
//!
//! ## Frozen wire surface (one-way-door)
//! Domain tags, `canonical_bytes` field order + length-prefixing, the `nonce`
//! semantics, and the `>`-not-`>=` fold direction are FROZEN on first commit; any
//! layout change mints a `_V2` tag. All integers are big-endian; **never f64** (this
//! codebase has a documented f64-fork class). Authenticity rides on the carrier
//! [`crate::record::ValidationRecord`] signature (which covers `metadata`), so the
//! payload embeds no key/signature of its own — mirroring [`crate::mandate`].

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256_hex;
use crate::errors::{ElaraError, Result};

/// Domain tag for [`EmergencyHalt::canonical_bytes`] (frozen — a layout change
/// mints `ELARA_EMERGENCY_HALT_V2`).
pub const EMERGENCY_HALT_DOMAIN_TAG: &[u8] = b"ELARA_EMERGENCY_HALT_V1";
/// Domain tag for [`EmergencyResume::canonical_bytes`] (frozen). Distinct from the
/// halt tag so a halt and a resume can never collide on content-address.
pub const EMERGENCY_RESUME_DOMAIN_TAG: &[u8] = b"ELARA_EMERGENCY_RESUME_V1";

/// Metadata key carrying a serialized [`EmergencyHalt`]. Must be in the
/// `content_safety::ALLOWED_KEYS` allowlist (else the carrier hard-rejects at
/// ingest) and in the `is_global_op` zone-filter exemption (else a zone-scoped node
/// drops the record before store/gossip).
pub const EMERGENCY_HALT_OP_KEY: &str = "emergency_halt_op";
/// Metadata key carrying a serialized [`EmergencyResume`].
pub const EMERGENCY_RESUME_OP_KEY: &str = "emergency_resume_op";

/// In-payload format version.
pub const EMERGENCY_FORMAT_VERSION: u8 = 1;

/// Reject an op whose serialized JSON exceeds this (bounds metadata floods into the
/// halt path; the carrier already enforces record-size caps, this is belt-and-braces).
pub const EMERGENCY_MAX_PAYLOAD_BYTES: usize = 4096;
/// Max `reason` length in bytes.
pub const EMERGENCY_MAX_REASON_BYTES: usize = 1024;
/// Default halt window the CLI stamps when the operator omits `--max-duration-secs`.
pub const DEFAULT_HALT_DURATION_SECS: u64 = 72 * 3600;
/// Hard node-side ceiling on a halt window — the continuity backstop. Even a halt
/// issued with a larger `max_duration_secs` auto-expires within this bound, capping
/// the brick window after authority-key loss. The authority extends a legitimate
/// long halt by re-issuing a fresh (higher-nonce) halt. This is NODE POLICY, applied
/// at expiry computation — NOT a wire field — so it can evolve without a `_V2`.
pub const MAX_HALT_DURATION_SECS: u64 = 30 * 24 * 3600;

/// Bound an issuer-anchored halt expiry to the node-observed continuity backstop:
/// `min(expiry_unix, observed_now + MAX_HALT_DURATION_SECS)`.
///
/// [`EmergencyHalt::effective_expiry_unix`] clamps only the *duration*, so a halt with
/// a far-future `issued_ts` would otherwise expire far beyond `now + 30d`, defeating the
/// backstop that caps the brick window after authority-key loss (a single signed halt
/// with `issued_ts = now + 10y` would freeze ingest for a decade). Anchoring the ceiling
/// to the NODE's observation time — NOT the issuer-supplied `issued_ts` — closes that:
/// a future-dated halt is bounded to ~30d of wall-clock from when this node first
/// folds/loads it. For a legitimate halt (`issued_ts <= observed_now` by propagation
/// latency, `dur <= MAX`) the `min` is a strict no-op, so there is zero behaviour change.
/// `saturating_add` keeps a crafted huge `observed_now` safe. The node layer applies this
/// at fold + load time; the pure [`EmergencyState`] model and `effective_expiry_unix`
/// stay unbounded nonce-algebra (see their docs).
pub fn bound_expiry(expiry_unix: u64, observed_now: u64) -> u64 {
    expiry_unix.min(observed_now.saturating_add(MAX_HALT_DURATION_SECS))
}

/// A signed command to pause new-write admission across the network.
///
/// Rides inside a [`crate::record::ValidationRecord`] whose `creator_public_key` is
/// the genesis authority; the outer record signature (which covers `metadata`) *is*
/// the authority's signature over this payload. The node layer folds it only after
/// checking `sha3(creator_public_key) == genesis_authority`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyHalt {
    /// In-payload format version ([`EMERGENCY_FORMAT_VERSION`]).
    pub version: u8,
    /// Network this halt is bound to. Bound into [`Self::canonical_bytes`] so a halt
    /// signed on one network cannot be replayed onto another.
    pub network_id: String,
    /// Strictly-increasing authority-issued counter. The max-fold ordering/dedup
    /// key — NOT a content uniquifier. Must be persisted durably by the issuer
    /// (a reset counter would let an old `Resume` cancel a future `Halt`).
    pub nonce: u64,
    /// Unix SECONDS (integer, never f64) the authority issued this halt. The expiry
    /// anchor; also informational/forensic.
    pub issued_ts: u64,
    /// Issuer-intended halt window in seconds. The node clamps it to
    /// [`MAX_HALT_DURATION_SECS`] when computing [`Self::effective_expiry_unix`].
    pub max_duration_secs: u64,
    /// Human-readable cause (audit trail). Not load-bearing for security.
    pub reason: String,
}

impl EmergencyHalt {
    /// Domain-tagged canonical encoding — the content-address preimage and the
    /// durable-CF blob. Field order is FROZEN.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(EMERGENCY_HALT_DOMAIN_TAG);
        out.push(self.version);
        push_lp(&mut out, self.network_id.as_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.issued_ts.to_be_bytes());
        out.extend_from_slice(&self.max_duration_secs.to_be_bytes());
        push_lp(&mut out, self.reason.as_bytes());
        out
    }

    /// Content-address: `sha3` over [`Self::canonical_bytes`].
    pub fn id(&self) -> String {
        sha3_256_hex(&self.canonical_bytes())
    }

    /// Structural self-consistency. `max_duration_secs == 0` (a halt that expires
    /// instantly) is malformed; an over-long `reason` is malformed.
    pub fn is_well_formed(&self) -> bool {
        self.version == EMERGENCY_FORMAT_VERSION
            && self.max_duration_secs > 0
            && self.reason.len() <= EMERGENCY_MAX_REASON_BYTES
    }

    /// Node-side effective expiry (unix secs): `issued_ts + min(max_duration_secs,
    /// MAX_HALT_DURATION_SECS)`, saturating to avoid overflow on a crafted huge
    /// `issued_ts`/duration (a saturated `u64::MAX` keeps the gate closed, which is
    /// the safe direction for a *malformed* halt — and `is_well_formed` plus the
    /// authority signature gate the path long before this).
    ///
    /// NOTE: this is the *unbounded*, issuer-anchored expiry — it clamps duration but
    /// NOT against the node clock, so a future-dated `issued_ts` produces a far-future
    /// value. The node layer stores [`Self::effective_expiry_bounded`] instead (which
    /// wraps this in [`bound_expiry`]) so the `now + MAX_HALT_DURATION_SECS` continuity
    /// backstop cannot be bypassed. This bare form is for the content-address preimage
    /// and the pure reference model only.
    pub fn effective_expiry_unix(&self) -> u64 {
        self.issued_ts
            .saturating_add(self.max_duration_secs.min(MAX_HALT_DURATION_SECS))
    }

    /// [`Self::effective_expiry_unix`] bounded to the node-observed continuity backstop
    /// `observed_now + MAX_HALT_DURATION_SECS` (see [`bound_expiry`]). This is the value
    /// the node layer stores into `active_expiry_unix`; it is what actually gates ingest.
    pub fn effective_expiry_bounded(&self, observed_now: u64) -> u64 {
        bound_expiry(self.effective_expiry_unix(), observed_now)
    }
}

/// A signed command lifting the halt identified by [`Self::halt_nonce`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyResume {
    /// In-payload format version.
    pub version: u8,
    /// Network binding (replay-domain separation, as [`EmergencyHalt::network_id`]).
    pub network_id: String,
    /// The [`EmergencyHalt::nonce`] this resume clears. The max-fold over resume
    /// nonces is compared against the max-fold over halt nonces.
    pub halt_nonce: u64,
    /// Unix seconds the authority issued this resume (forensic).
    pub issued_ts: u64,
}

impl EmergencyResume {
    /// Domain-tagged canonical encoding. Field order is FROZEN.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(EMERGENCY_RESUME_DOMAIN_TAG);
        out.push(self.version);
        push_lp(&mut out, self.network_id.as_bytes());
        out.extend_from_slice(&self.halt_nonce.to_be_bytes());
        out.extend_from_slice(&self.issued_ts.to_be_bytes());
        out
    }

    /// Content-address: `sha3` over [`Self::canonical_bytes`].
    pub fn id(&self) -> String {
        sha3_256_hex(&self.canonical_bytes())
    }

    /// Structural self-consistency.
    pub fn is_well_formed(&self) -> bool {
        self.version == EMERGENCY_FORMAT_VERSION
    }
}

/// The node-local fold state — the pure reference model the `NodeState` atomics
/// implement, and the form carried in the bootstrap snapshot (B1) + persisted to
/// `CF_EMERGENCY` (B2). `#[serde(default)]` on its container keeps a pre-feature
/// snapshot legacy-safe (absent → `Default` → un-halted).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyState {
    /// Max nonce over observed authority-signed halts.
    pub latest_halt_nonce: u64,
    /// Max `halt_nonce` over observed authority-signed resumes.
    pub latest_resume_nonce: u64,
    /// Effective expiry (unix secs) of the max-nonce halt. `0` = none.
    pub active_expiry_unix: u64,
    /// Reason of the max-nonce halt (observability only).
    pub active_reason: String,
}

impl EmergencyState {
    /// The gate predicate: halted iff a halt out-ranks every resume AND the wall
    /// clock has not passed the active window. `>` (not `>=`) → a tie un-halts.
    pub fn halted_at(&self, now_secs: u64) -> bool {
        self.latest_halt_nonce > self.latest_resume_nonce && now_secs < self.active_expiry_unix
    }

    /// Max-fold a verified halt (caller has already checked authority-binding +
    /// `is_well_formed`). Updates the active window iff this halt wins the nonce
    /// race. Idempotent and order-independent.
    ///
    /// NOTE: this pure reference model stores the *unbounded* `effective_expiry_unix`
    /// (nonce-algebra only). The production node layer ([`crate::network::state::NodeState`]
    /// `::emergency_fold_halt`) instead stores [`EmergencyHalt::effective_expiry_bounded`]
    /// so a future-dated `issued_ts` cannot bypass the `now + MAX_HALT_DURATION_SECS`
    /// backstop. Keep this model wall-clock-free so it stays order-independent.
    pub fn fold_halt(&mut self, h: &EmergencyHalt) {
        if h.nonce > self.latest_halt_nonce {
            self.latest_halt_nonce = h.nonce;
            self.active_expiry_unix = h.effective_expiry_unix();
            self.active_reason = h.reason.clone();
        }
    }

    /// Max-fold a verified resume. Idempotent and order-independent.
    pub fn fold_resume(&mut self, r: &EmergencyResume) {
        if r.halt_nonce > self.latest_resume_nonce {
            self.latest_resume_nonce = r.halt_nonce;
        }
    }
}

/// Parse a serialized [`EmergencyHalt`] from a record-metadata value.
pub fn parse_halt(v: &serde_json::Value) -> Result<EmergencyHalt> {
    serde_json::from_value(v.clone())
        .map_err(|e| ElaraError::Wire(format!("emergency_halt parse: {e}")))
}

/// Parse a serialized [`EmergencyResume`] from a record-metadata value.
pub fn parse_resume(v: &serde_json::Value) -> Result<EmergencyResume> {
    serde_json::from_value(v.clone())
        .map_err(|e| ElaraError::Wire(format!("emergency_resume parse: {e}")))
}

/// `out += u32-BE(len) ‖ bytes` — the canonical length-prefix idiom shared with
/// `crate::mandate::push_lp`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halt(nonce: u64, issued: u64, dur: u64) -> EmergencyHalt {
        EmergencyHalt {
            version: EMERGENCY_FORMAT_VERSION,
            network_id: "testnet".into(),
            nonce,
            issued_ts: issued,
            max_duration_secs: dur,
            reason: "dilithium3 break suspected".into(),
        }
    }
    fn resume(halt_nonce: u64, issued: u64) -> EmergencyResume {
        EmergencyResume {
            version: EMERGENCY_FORMAT_VERSION,
            network_id: "testnet".into(),
            halt_nonce,
            issued_ts: issued,
        }
    }

    #[test]
    fn halt_canonical_bytes_are_byte_pinned() {
        // FROZEN WIRE SURFACE — this hand-rolled oracle must match `canonical_bytes`
        // exactly. A diff here is a wire-break that demands a `_V2` tag, never a
        // silent edit to the encoder.
        let h = halt(5, 1_700_000_000, 3600);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ELARA_EMERGENCY_HALT_V1");
        expected.push(1u8); // version
        expected.extend_from_slice(&7u32.to_be_bytes()); // "testnet" len
        expected.extend_from_slice(b"testnet");
        expected.extend_from_slice(&5u64.to_be_bytes()); // nonce
        expected.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // issued_ts
        expected.extend_from_slice(&3600u64.to_be_bytes()); // max_duration_secs
        expected.extend_from_slice(&(b"dilithium3 break suspected".len() as u32).to_be_bytes());
        expected.extend_from_slice(b"dilithium3 break suspected");
        assert_eq!(h.canonical_bytes(), expected);
        assert_eq!(h.id(), sha3_256_hex(&expected));
    }

    #[test]
    fn resume_canonical_bytes_are_byte_pinned() {
        let r = resume(5, 1_700_000_500);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ELARA_EMERGENCY_RESUME_V1");
        expected.push(1u8);
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(b"testnet");
        expected.extend_from_slice(&5u64.to_be_bytes()); // halt_nonce
        expected.extend_from_slice(&1_700_000_500u64.to_be_bytes());
        assert_eq!(r.canonical_bytes(), expected);
        assert_eq!(r.id(), sha3_256_hex(&expected));
    }

    #[test]
    fn halt_and_resume_domain_tags_are_distinct() {
        // Same scalar fields must not collide on content-address across the two ops.
        assert_ne!(EMERGENCY_HALT_DOMAIN_TAG, EMERGENCY_RESUME_DOMAIN_TAG);
    }

    #[test]
    fn fold_is_halted_then_resumed() {
        let mut s = EmergencyState::default();
        assert!(!s.halted_at(1_700_000_100));
        s.fold_halt(&halt(1, 1_700_000_000, 3600));
        assert!(s.halted_at(1_700_000_100)); // within window
        s.fold_resume(&resume(1, 1_700_000_200));
        assert!(!s.halted_at(1_700_000_300)); // 1 > 1 is false
    }

    #[test]
    fn stale_halt_replay_after_resume_stays_unhalted() {
        // The replay-immunity invariant: re-observing Halt@5 after Resume@5 is inert.
        let mut s = EmergencyState::default();
        s.fold_halt(&halt(5, 1_700_000_000, 3600));
        s.fold_resume(&resume(5, 1_700_000_100));
        assert!(!s.halted_at(1_700_000_200));
        // stale re-gossip of the SAME halt
        s.fold_halt(&halt(5, 1_700_000_000, 3600));
        assert!(!s.halted_at(1_700_000_200), "5 > 5 must stay false after replay");
    }

    #[test]
    fn fold_is_order_independent() {
        // Apply {Halt@3, Halt@5, Resume@4} in two different orders → same verdict.
        let recs_a = || {
            let mut s = EmergencyState::default();
            s.fold_halt(&halt(3, 1_700_000_000, 3600));
            s.fold_halt(&halt(5, 1_700_000_010, 3600));
            s.fold_resume(&resume(4, 1_700_000_020));
            s
        };
        let recs_b = || {
            let mut s = EmergencyState::default();
            s.fold_resume(&resume(4, 1_700_000_020));
            s.fold_halt(&halt(5, 1_700_000_010, 3600));
            s.fold_halt(&halt(3, 1_700_000_000, 3600));
            s
        };
        let a = recs_a();
        let b = recs_b();
        assert_eq!(a, b);
        // 5 > 4 → halted (within the Halt@5 window).
        assert!(a.halted_at(1_700_000_100));
        // active window/reason tracks the MAX-nonce halt (Halt@5), order-independent.
        assert_eq!(a.active_expiry_unix, halt(5, 1_700_000_010, 3600).effective_expiry_unix());
    }

    #[test]
    fn out_of_order_low_halt_does_not_clobber_active_window() {
        let mut s = EmergencyState::default();
        s.fold_halt(&halt(7, 1_700_000_700, 3600));
        let win7 = s.active_expiry_unix;
        s.fold_halt(&halt(5, 1_700_000_500, 9999)); // arrives late, lower nonce
        assert_eq!(s.active_expiry_unix, win7, "low-nonce halt must not clobber the window");
        assert_eq!(s.latest_halt_nonce, 7);
    }

    #[test]
    fn auto_expiry_self_clears_without_resume() {
        // The continuity backstop: no Resume ever arrives, yet the gate self-clears.
        let mut s = EmergencyState::default();
        s.fold_halt(&halt(1, 1_700_000_000, 3600)); // 1h window
        assert!(s.halted_at(1_700_001_000)); // +1000s: inside
        assert!(s.halted_at(1_700_003_599)); // +3599s: inside
        assert!(!s.halted_at(1_700_003_600)); // +3600s: expired (now < expiry is false)
        assert!(!s.halted_at(1_700_010_000)); // well past
    }

    #[test]
    fn effective_expiry_clamps_to_ceiling() {
        let h = halt(1, 1_000, u64::MAX); // absurd issuer duration
        // Clamped to the 30-day ceiling, saturating-add safe.
        assert_eq!(h.effective_expiry_unix(), 1_000u64.saturating_add(MAX_HALT_DURATION_SECS));
    }

    #[test]
    fn future_dated_issued_ts_is_bounded_to_node_backstop() {
        // Regression: a halt with a far-future `issued_ts` must NOT keep the gate closed
        // beyond observed_now + MAX_HALT_DURATION_SECS. `effective_expiry_unix` (issuer-
        // anchored) is ~10y out — the bug; `effective_expiry_bounded` caps it. Without
        // this bound a single signed halt bricks ingest for a decade after key loss.
        let observed_now = 1_700_000_000u64;
        let ten_years = 10 * 365 * 24 * 3600u64;
        let h = halt(1, observed_now + ten_years, 3600); // issued 10y in the future
        assert!(
            h.effective_expiry_unix() > observed_now + ten_years,
            "unbounded form is far-future (this is the defeated path)"
        );
        assert_eq!(
            h.effective_expiry_bounded(observed_now),
            observed_now + MAX_HALT_DURATION_SECS,
            "future-dated halt must be bounded to the node continuity backstop"
        );
        // A state holding the BOUNDED expiry self-clears at the backstop, not in 10y.
        let s = EmergencyState {
            latest_halt_nonce: 1,
            active_expiry_unix: h.effective_expiry_bounded(observed_now),
            ..Default::default()
        };
        assert!(s.halted_at(observed_now), "halted right now");
        assert!(
            !s.halted_at(observed_now + MAX_HALT_DURATION_SECS),
            "must expire at the 30d backstop, not 10y out"
        );
    }

    #[test]
    fn bound_expiry_is_noop_for_legitimate_halt() {
        // A normal halt (issued ~now, dur <= MAX) is unaffected: bounded == unbounded,
        // so the backstop introduces zero behaviour change on the legitimate path.
        let observed_now = 1_700_000_000u64;
        let h = halt(1, observed_now, DEFAULT_HALT_DURATION_SECS); // issued now, 72h
        assert_eq!(
            h.effective_expiry_bounded(observed_now),
            h.effective_expiry_unix(),
            "legitimate halt must not be shortened by the bound (strict no-op)"
        );
        // Issued slightly in the past (realistic: a node observes it after propagation).
        let h2 = halt(2, observed_now - 60, 3600);
        assert_eq!(h2.effective_expiry_bounded(observed_now), h2.effective_expiry_unix());
    }

    #[test]
    fn malformed_halts_rejected_by_well_formed() {
        let mut h = halt(1, 1_000, 0); // zero duration
        assert!(!h.is_well_formed());
        h.max_duration_secs = 3600;
        assert!(h.is_well_formed());
        h.version = 2; // unknown version
        assert!(!h.is_well_formed());
        h.version = EMERGENCY_FORMAT_VERSION;
        h.reason = "x".repeat(EMERGENCY_MAX_REASON_BYTES + 1);
        assert!(!h.is_well_formed());
    }

    #[test]
    fn parse_round_trips_through_metadata_value() {
        let h = halt(9, 1_700_000_000, 7200);
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(parse_halt(&v).unwrap(), h);
        let r = resume(9, 1_700_000_100);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(parse_resume(&v).unwrap(), r);
    }
}
