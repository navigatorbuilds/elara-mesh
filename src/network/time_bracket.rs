//! In-protocol time bracket — REALMS P1.5(a): the drand-pulse NOT-BEFORE.
//!
//! A record (or an epoch seal) that embeds a drand beacon pulse can carry a
//! *not-before* reference: the beacon's randomness for round `N` does not exist
//! until the League-of-Entropy network emits it, at `genesis_time + (N - 1) *
//! period`. So "this seal references drand round N" is evidence the seal was
//! produced at or after that wall-clock instant — a lower time bound
//! independent of any node's self-reported timestamp.
//!
//! IMPORTANT — this is a *reference* bound, not (yet) a trustless one. The
//! guarantee above holds only once the embedded pulse is shown to be a genuine
//! beacon emission, i.e. once its BLS12-381 threshold signature is verified
//! (see "Not yet verified here" below). Until then a `DrandPulse` is
//! attacker-constructible — nothing here detects a fabricated round/randomness
//! — so the not-before is a cross-check, NOT a backdating proof. The trustless
//! leg of the bracket is the OTS→Bitcoin existed-by anchor.
//!
//! Round→time relationship (drand round 1 is emitted at genesis_time):
//!   `time(round) = genesis_time + (round - 1) * period`
//! The round→time FORMULA is verified against the drand protocol specification
//! and the Sui / Filecoin drand integrations (2026-06-13), not assumed; the
//! beacon SIGNATURE over the pulse is a separate check, deferred (below).
//!
//! ## Scope of THIS slice (a)
//! Standalone type + not-before math + metadata (de)serialization helpers.
//! Originally landed type-first (mirroring Gap-7's `account_state_root` and
//! REALMS (b)'s transport certs); slices (a2)/(a3) later wired it into seal
//! production: the opt-in beacon fetcher (`src/network/drand_fetch.rs`,
//! `drand_pulse_enabled`, default off) constructs a `DrandPulse` and the seal
//! path embeds it (`epoch.rs`), so fetcher-enabled producers emit seals
//! carrying these keys. With the flag off — the shipped default — this module
//! is inert at runtime.
//!
//! ## Not yet verified here (honest scope)
//! This slice stores and time-brackets a pulse; it does **not** verify the
//! beacon's BLS12-381 threshold signature here (that would add a BLS dependency
//! to the node graph — kept out by design). The BLS verification DOES ship, in
//! the standalone offline verifier: `src/bin/elara_verify.rs::verify_drand_bls`
//! checks the signature against the pinned League-of-Entropy key (`drand-verify`,
//! gated behind the `verify-cli` feature only). So a pulse-bearing seal's or
//! anchor artifact's not-before is trustless when checked by `elara-verify`;
//! in-protocol (consensus) the pulse stays reference-only — nodes never
//! BLS-verify it (the G2 gate in MESH-BFT-MERGE-SEMANTICS remains unshipped
//! by design, keeping BLS out of the node dep graph). The OTS/TSA anchor
//! braid (P1.5(b)) independently carries the existed-by leg.
//!
//! Spec references:
//!   @spec Protocol §11.12

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Metadata keys a `DrandPulse` occupies on a record / seal. Namespaced
/// `drand_*` so they never collide with the `epoch_*` seal keys. All absent
/// ⇒ legacy record, `from_metadata` returns `None` (no behavior change).
pub const KEY_ROUND: &str = "drand_round";
pub const KEY_RANDOMNESS: &str = "drand_randomness";
pub const KEY_GENESIS: &str = "drand_genesis_unix";
pub const KEY_PERIOD: &str = "drand_period_secs";
/// Optional: identifies WHICH drand chain (beacon) the pulse came from, so a
/// verifier can re-fetch its `/info` and (future slice) check the BLS sig.
pub const KEY_CHAIN: &str = "drand_chain_hash";
/// Optional: the beacon's BLS signature for this round (hex). Carrying it in
/// the seal is what upgrades the offline drand leg from a reference bound to
/// a trustless one — `elara-verify` checks it against the PINNED LoE key, so
/// a forged value fails verification rather than forging time.
pub const KEY_SIGNATURE: &str = "drand_signature";
/// Optional: the PREVIOUS round's BLS signature (hex). The chained-beacon
/// signed message is `H(previous_signature || round)`, so offline BLS
/// verification is impossible without it.
pub const KEY_PREV_SIGNATURE: &str = "drand_previous_signature";

/// A single drand beacon pulse, carried as a cryptographic not-before.
///
/// `genesis_unix` + `period_secs` are stored WITH the pulse (the beacon's own
/// published chain parameters) rather than hardcoded, so the not-before is
/// computed from carried data — correct for any drand beacon (mainnet,
/// quicknet, or a realm-private one) and never dependent on a magic constant
/// baked into this binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrandPulse {
    /// Beacon round number (round 1 is emitted at `genesis_unix`).
    pub round: u64,
    /// Beacon randomness for this round, lowercase hex.
    pub randomness: String,
    /// The beacon chain's genesis time (unix seconds).
    pub genesis_unix: u64,
    /// The beacon chain's period (seconds between rounds).
    pub period_secs: u64,
    /// Optional beacon chain identifier (hex chain hash).
    pub chain_hash: Option<String>,
    /// Optional BLS signature for this round (hex). Present ⇒ the offline
    /// verifier can reach a trustless PASS; absent ⇒ reference bound only
    /// (legacy pulses and producers without the fetcher).
    pub signature: Option<String>,
    /// Optional previous-round BLS signature (hex); required alongside
    /// `signature` for offline verification of the chained beacon.
    pub previous_signature: Option<String>,
}

impl DrandPulse {
    /// The cryptographic not-before: the wall-clock instant (unix seconds) at
    /// which this round's randomness first became producible.
    /// `genesis_unix + (round - 1) * period_secs`; round 0 is treated as
    /// round 1 (clamped) since drand rounds are 1-indexed.
    pub fn not_before_unix(&self) -> u64 {
        let rounds_after_genesis = self.round.saturating_sub(1);
        self.genesis_unix
            .saturating_add(rounds_after_genesis.saturating_mul(self.period_secs))
    }

    /// True if `self` is internally coherent enough to time-bracket with.
    /// A zero period can't map rounds to time; empty randomness is not a
    /// pulse. (Signature authenticity is a separate, later check.)
    pub fn is_well_formed(&self) -> bool {
        let sig_hex_ok = |s: &Option<String>| {
            s.as_ref()
                .is_none_or(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_hexdigit()))
        };
        self.period_secs > 0
            && !self.randomness.is_empty()
            && self.randomness.chars().all(|c| c.is_ascii_hexdigit())
            && sig_hex_ok(&self.signature)
            && sig_hex_ok(&self.previous_signature)
    }

    /// Write this pulse's keys into a record/seal metadata map. Inverse of
    /// [`from_metadata`]. Only called on the producer side (future slice);
    /// kept here so producer and parser share one key contract.
    pub fn write_metadata(&self, map: &mut BTreeMap<String, Value>) {
        map.insert(KEY_ROUND.into(), Value::from(self.round));
        map.insert(KEY_RANDOMNESS.into(), Value::from(self.randomness.clone()));
        map.insert(KEY_GENESIS.into(), Value::from(self.genesis_unix));
        map.insert(KEY_PERIOD.into(), Value::from(self.period_secs));
        if let Some(ch) = &self.chain_hash {
            map.insert(KEY_CHAIN.into(), Value::from(ch.clone()));
        }
        if let Some(sig) = &self.signature {
            map.insert(KEY_SIGNATURE.into(), Value::from(sig.clone()));
        }
        if let Some(prev) = &self.previous_signature {
            map.insert(KEY_PREV_SIGNATURE.into(), Value::from(prev.clone()));
        }
    }

    /// Parse a pulse back out of record/seal metadata. Returns `None` when
    /// the required keys are absent (legacy record — the legacy-safe path) or
    /// malformed. `chain_hash` is optional and absent ⇒ `None` for that field
    /// only.
    pub fn from_metadata(map: &BTreeMap<String, Value>) -> Option<Self> {
        let round = map.get(KEY_ROUND)?.as_u64()?;
        let randomness = map.get(KEY_RANDOMNESS)?.as_str()?.to_string();
        let genesis_unix = map.get(KEY_GENESIS)?.as_u64()?;
        let period_secs = map.get(KEY_PERIOD)?.as_u64()?;
        let chain_hash = map
            .get(KEY_CHAIN)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let signature = map
            .get(KEY_SIGNATURE)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let previous_signature = map
            .get(KEY_PREV_SIGNATURE)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let pulse = DrandPulse {
            round,
            randomness,
            genesis_unix,
            period_secs,
            chain_hash,
            signature,
            previous_signature,
        };
        pulse.is_well_formed().then_some(pulse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real drand mainnet ("League of Entropy") chain parameters, used here
    /// only as arithmetic test vectors — the type itself hardcodes nothing.
    const MAINNET_GENESIS: u64 = 1_595_431_050;
    const MAINNET_PERIOD: u64 = 30;

    fn mainnet_pulse(round: u64) -> DrandPulse {
        DrandPulse {
            round,
            randomness: "deadbeef".into(),
            genesis_unix: MAINNET_GENESIS,
            period_secs: MAINNET_PERIOD,
            chain_hash: Some("8990e7a9aaed2ffed73dbd7092123d6f".into()),
            signature: None,
            previous_signature: None,
        }
    }

    #[test]
    fn not_before_round_one_is_genesis() {
        // Verified formula: round 1 is emitted exactly at genesis.
        assert_eq!(mainnet_pulse(1).not_before_unix(), MAINNET_GENESIS);
    }

    #[test]
    fn not_before_advances_one_period_per_round() {
        assert_eq!(
            mainnet_pulse(2).not_before_unix(),
            MAINNET_GENESIS + MAINNET_PERIOD
        );
        assert_eq!(
            mainnet_pulse(1001).not_before_unix(),
            MAINNET_GENESIS + 1000 * MAINNET_PERIOD
        );
        // Round 0 clamps to round 1's time (drand rounds are 1-indexed).
        assert_eq!(mainnet_pulse(0).not_before_unix(), MAINNET_GENESIS);
    }

    #[test]
    fn metadata_round_trip_is_lossless() {
        let p = mainnet_pulse(42);
        let mut map = BTreeMap::new();
        p.write_metadata(&mut map);
        assert_eq!(DrandPulse::from_metadata(&map), Some(p));
    }

    #[test]
    fn metadata_round_trip_with_signatures_is_lossless() {
        let mut p = mainnet_pulse(42);
        p.signature = Some("ab01".repeat(48)); // 192 hex chars, G2-sized
        p.previous_signature = Some("cd02".repeat(48));
        let mut map = BTreeMap::new();
        p.write_metadata(&mut map);
        assert!(map.contains_key(KEY_SIGNATURE));
        assert!(map.contains_key(KEY_PREV_SIGNATURE));
        assert_eq!(DrandPulse::from_metadata(&map), Some(p));
    }

    #[test]
    fn legacy_five_key_metadata_still_parses() {
        // A pulse written by a pre-signature binary carries only the original
        // five keys; the parser must return it with both signature fields None.
        let p = mainnet_pulse(42);
        let mut map = BTreeMap::new();
        p.write_metadata(&mut map);
        assert!(!map.contains_key(KEY_SIGNATURE));
        assert!(!map.contains_key(KEY_PREV_SIGNATURE));
        let parsed = DrandPulse::from_metadata(&map).expect("legacy pulse parses");
        assert_eq!(parsed.signature, None);
        assert_eq!(parsed.previous_signature, None);
        assert_eq!(parsed, p);
    }

    #[test]
    fn non_hex_signature_is_rejected_as_malformed() {
        let mut p = mainnet_pulse(42);
        p.signature = Some("not-hex!".into());
        assert!(!p.is_well_formed());
        let mut map = BTreeMap::new();
        p.write_metadata(&mut map);
        assert_eq!(DrandPulse::from_metadata(&map), None);
    }

    #[test]
    fn metadata_round_trip_without_chain_hash() {
        let mut p = mainnet_pulse(42);
        p.chain_hash = None;
        let mut map = BTreeMap::new();
        p.write_metadata(&mut map);
        assert!(!map.contains_key(KEY_CHAIN));
        assert_eq!(DrandPulse::from_metadata(&map), Some(p));
    }

    #[test]
    fn legacy_metadata_parses_to_none() {
        // Empty metadata (every record before this feature) → None, the
        // legacy-safe path: no drand keys means no bracket, never an error.
        let empty: BTreeMap<String, Value> = BTreeMap::new();
        assert_eq!(DrandPulse::from_metadata(&empty), None);
        // A foreign key set (e.g. an epoch seal's own keys) is also None.
        let mut other = BTreeMap::new();
        other.insert("epoch_number".into(), Value::from(7u64));
        assert_eq!(DrandPulse::from_metadata(&other), None);
    }

    #[test]
    fn partial_metadata_parses_to_none() {
        // Missing randomness → None (not a half-built pulse).
        let mut map = BTreeMap::new();
        map.insert(KEY_ROUND.into(), Value::from(5u64));
        map.insert(KEY_GENESIS.into(), Value::from(MAINNET_GENESIS));
        map.insert(KEY_PERIOD.into(), Value::from(MAINNET_PERIOD));
        assert_eq!(DrandPulse::from_metadata(&map), None);
    }

    #[test]
    fn malformed_pulse_rejected() {
        // Zero period can't map rounds to time.
        let mut zero_period = mainnet_pulse(3);
        zero_period.period_secs = 0;
        assert!(!zero_period.is_well_formed());
        let mut map = BTreeMap::new();
        zero_period.write_metadata(&mut map);
        assert_eq!(DrandPulse::from_metadata(&map), None);

        // Non-hex randomness is not a beacon output.
        let mut bad_rand = mainnet_pulse(3);
        bad_rand.randomness = "nothex!!".into();
        assert!(!bad_rand.is_well_formed());
    }
}
