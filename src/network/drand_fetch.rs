//! Live drand pulse fetcher — REALMS P1.5 slice a3, the producer side of the
//! `time_bracket.rs` pulse contract.
//!
//! A background task polls ≥2 independent League-of-Entropy relays; when two
//! distinct relays return byte-identical BLS material for the same round, the
//! pulse (WITH its signature pair) is cached, and the seal-emit loop embeds it
//! into seal metadata. Design rules, locked by the 2026-07-02 fusion audit:
//!
//! - **The node does NO BLS.** Trustless verification is `elara-verify`'s job
//!   against its PINNED LoE key (`drand-verify` stays out of the node graph by
//!   design — Cargo.toml). Cross-relay byte-equality only protects an honest
//!   producer from a single lying relay; a colluding relay set can at worst
//!   degrade ONE seal's offline drand leg to FAIL — no consensus rule reads
//!   the pulse at all.
//! - **Sealing never blocks.** Every failure mode here ends in "the cache
//!   doesn't advance"; the seal path does a non-blocking cache read and embeds
//!   `None` when nothing fresh is available.
//! - **`randomness` is DERIVED, never trusted:** drand randomness is
//!   `sha256(signature)` by definition, so we compute it from the signature we
//!   are about to embed (some relays omit or reorder the field anyway).
//! - **`genesis_unix`/`period_secs` are pinned constants, never fetched:** the
//!   beacon BLS signature does not cover them, and `elara-verify` fail-closes
//!   on a pinned-chain artifact whose parameters differ from the pins
//!   (`loe_param_conflict`). Fetching them from a relay would reintroduce the
//!   exact substitution attack that gate exists to stop.
//! - **Monotone cache:** the cached round only advances, so a relay replaying
//!   an old round can never walk an embedded not-before backwards.
//! - **A "future" round is a local-clock signal, not a relay fault:** a
//!   BLS-valid round cannot actually predate its own emission, so a pulse
//!   whose `not_before` is ahead of local now means OUR clock is behind —
//!   counted and logged, still embedded. Only an absurdly-ahead round
//!   (> +1 day) is treated as relay garbage and dropped.
//!
//! Deployment posture (fusion final-verify Hole 1/2): the fetch loop spawns
//! only under `drand_pulse_enabled && allow_public_https` — testnet/dev
//! profiles; a mainnet node (which must boot with `allow_public_https=false`)
//! keeps its zero-classical-TLS wire and uses the out-of-process anchor
//! sidecar (`scripts/elara-epoch-anchor.sh`) for drand bracketing instead.
//! `drand_pulse_enabled` defaults FALSE so a producer can never emit the new
//! metadata keys before its whole fleet runs an allowlist-aware binary.
//!
//! Spec references:
//!   @spec Protocol §11.12 (time-bracketing)

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::{info, warn};

use super::state::NodeState;
use super::time_bracket::DrandPulse;

/// The League-of-Entropy default (`pedersen-bls-chained`) beacon chain hash.
/// MUST stay byte-identical to `LOE_DEFAULT_CHAIN_HASH` in
/// `crates/elara-verify/src/anchor.rs` (the verifier extraction moved it out of
/// `src/bin/elara_verify.rs`) — the two live in disjoint feature graphs
/// (`node-core` vs `verify-anchor`), so a shared const is impossible. The
/// `loe_trust_root_matches_node_fetcher` test in the verify-cli bin graph pins
/// equality of all three constants (2026-07-12 sweep A8).
pub const LOE_CHAIN_HASH: &str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";
/// LoE default-chain genesis (unix seconds) — pinned, never fetched.
pub const LOE_GENESIS_UNIX: u64 = 1_595_431_050;
/// LoE default-chain round period (seconds) — pinned, never fetched.
pub const LOE_PERIOD_SECS: u64 = 30;

/// Default relay set: independent operators (Protocol Labs / Cloudflare /
/// two LoE mirrors). The agreement rule needs any TWO distinct entries alive.
pub const DEFAULT_RELAYS: [&str; 4] = [
    "https://api.drand.sh",
    "https://drand.cloudflare.com",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
];

/// Per-request timeout. Relay outages cost at most this per relay per tick,
/// on the background task only — never on the seal path.
pub const FETCH_TIMEOUT_SECS: u64 = 5;
/// Fetch cadence: period/2, so the cache is at most ~1 round behind.
pub const FETCH_INTERVAL_SECS: u64 = 15;
/// Cache freshness cap for EMBEDDING (10 rounds). An older pulse is still a
/// TRUE not-before (conservative), but past this age `None` is more honest
/// and surfaces a stuck fetcher / halted beacon instead of masking it.
pub const STALENESS_CAP_SECS: u64 = 300;
/// A pulse whose not-before is further than this ahead of local now is relay
/// garbage (vs mild ahead-of-clock = local NTP skew, which still embeds).
pub const FUTURE_INSANITY_CAP_SECS: u64 = 86_400;
/// Relay response body cap — a well-formed `/public/<round>` payload is
/// ~600 bytes; anything past this is not a drand pulse.
pub const MAX_RESPONSE_BYTES: usize = 4_096;

/// The relay-supplied BLS material for one round, before cross-relay
/// agreement. `randomness` is deliberately NOT carried — it is derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPulse {
    pub round: u64,
    /// 192 hex chars (G2, 96 bytes) — pedersen-bls-chained signature.
    pub signature: String,
    /// 192 hex chars — the chained previous-round signature.
    pub previous_signature: String,
}

/// Parse one relay JSON response into a `RawPulse`. Pure; rejects round 0,
/// non-hex or wrong-length signature material, and anything non-JSON.
pub fn parse_relay_response(body: &str) -> Option<RawPulse> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let round = v.get("round")?.as_u64()?;
    if round == 0 {
        return None;
    }
    let hex_192 = |s: &str| s.len() == 192 && s.chars().all(|c| c.is_ascii_hexdigit());
    let signature = v.get("signature")?.as_str()?.to_ascii_lowercase();
    let previous_signature = v.get("previous_signature")?.as_str()?.to_ascii_lowercase();
    if !hex_192(&signature) || !hex_192(&previous_signature) {
        return None;
    }
    Some(RawPulse {
        round,
        signature,
        previous_signature,
    })
}

/// Build the embeddable `DrandPulse` from cross-relay-agreed material.
/// Randomness is derived (`sha256(signature)`), chain parameters are the
/// pins. Returns `None` for insanely-future rounds (relay garbage).
pub fn pulse_from_agreed(raw: &RawPulse, now_unix: u64) -> Option<DrandPulse> {
    use sha2::{Digest, Sha256};
    let sig_bytes = hex::decode(&raw.signature).ok()?;
    let randomness = hex::encode(Sha256::digest(&sig_bytes));
    let pulse = DrandPulse {
        round: raw.round,
        randomness,
        genesis_unix: LOE_GENESIS_UNIX,
        period_secs: LOE_PERIOD_SECS,
        chain_hash: Some(LOE_CHAIN_HASH.to_string()),
        signature: Some(raw.signature.clone()),
        previous_signature: Some(raw.previous_signature.clone()),
    };
    if pulse.not_before_unix() > now_unix.saturating_add(FUTURE_INSANITY_CAP_SECS) {
        return None;
    }
    pulse.is_well_formed().then_some(pulse)
}

/// A cached pulse plus the local instant it was agreed, for staleness math.
#[derive(Debug, Clone)]
pub struct CachedPulse {
    pub pulse: DrandPulse,
    pub fetched_at_unix: u64,
}

/// The seal-loop-facing cache. Writer = the fetch loop; readers = the seal
/// preamble (non-blocking) and `/metrics`. Poisoning recovers to the inner
/// value — a panicked writer mid-store leaves at worst a stale-but-valid
/// pulse, which the staleness cap already handles.
#[derive(Default)]
pub struct DrandPulseCache {
    inner: std::sync::RwLock<Option<CachedPulse>>,
}

impl DrandPulseCache {
    /// Monotone store: accepts only a strictly-newer round. Returns whether
    /// the cache advanced (false ⇒ round regression, caller counts it).
    pub fn store_if_newer(&self, pulse: DrandPulse, now_unix: u64) -> bool {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let newer = guard
            .as_ref()
            .is_none_or(|cached| pulse.round > cached.pulse.round);
        if newer {
            *guard = Some(CachedPulse {
                pulse,
                fetched_at_unix: now_unix,
            });
        }
        newer
    }

    /// Non-blocking freshness-capped read for the seal path. `None` when the
    /// cache is empty OR older than [`STALENESS_CAP_SECS`].
    pub fn get_fresh(&self, now_unix: u64) -> Option<DrandPulse> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().and_then(|c| {
            (now_unix.saturating_sub(c.fetched_at_unix) <= STALENESS_CAP_SECS)
                .then(|| c.pulse.clone())
        })
    }

    /// Seconds since the cached pulse was agreed; `None` = never fetched.
    /// Metrics-only.
    pub fn age_secs(&self, now_unix: u64) -> Option<u64> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|c| now_unix.saturating_sub(c.fetched_at_unix))
    }
}

/// One cross-relay fetch attempt's outcome (caller maps these to counters).
#[derive(Debug, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Two distinct relays agreed byte-for-byte on this round's material.
    Agreed(RawPulse),
    /// A second relay answered for the same round with DIFFERENT bytes.
    Disagree,
    /// Fewer than two relays produced a usable answer — no quorum.
    NoQuorum,
}

/// Decide agreement between the candidate and a confirming relay's response
/// for the SAME round. Pure — unit-tested without any network.
pub fn judge_confirmation(candidate: &RawPulse, confirm_body: &str) -> Option<bool> {
    let confirm = parse_relay_response(confirm_body)?;
    Some(
        confirm.round == candidate.round
            && confirm.signature == candidate.signature
            && confirm.previous_signature == candidate.previous_signature,
    )
}

/// Validate an operator-supplied relay URL. `https://` with a hostname for
/// real deployments; plain-`http` loopback is allowed so hermetic tests can
/// point the fetcher at an in-process mock relay.
pub fn relay_url_is_acceptable(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or("");
        return !host.is_empty() && !host.contains('@');
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or("");
        let host_no_port = host.split(':').next().unwrap_or("");
        return matches!(host_no_port, "127.0.0.1" | "localhost");
    }
    false
}

/// GET one relay URL with the body cap. `None` on any transport/HTTP error.
async fn fetch_body(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// The cross-relay protocol: take `/public/latest` from the first relay that
/// answers usably (the candidate), then confirm the SAME ROUND by number from
/// a DIFFERENT relay (`/public/{round}` — round-scoped, so a relay that has
/// already advanced to round N+1 cannot cause a false disagreement).
pub async fn fetch_agreed_pulse(client: &reqwest::Client, relays: &[String]) -> FetchOutcome {
    let mut candidate: Option<(usize, RawPulse)> = None;
    for (i, base) in relays.iter().enumerate() {
        let url = format!("{base}/{LOE_CHAIN_HASH}/public/latest");
        if let Some(body) = fetch_body(client, &url).await {
            if let Some(raw) = parse_relay_response(&body) {
                candidate = Some((i, raw));
                break;
            }
        }
    }
    let Some((cand_idx, raw)) = candidate else {
        return FetchOutcome::NoQuorum;
    };
    for (i, base) in relays.iter().enumerate() {
        if i == cand_idx {
            continue;
        }
        let url = format!("{base}/{}/public/{}", LOE_CHAIN_HASH, raw.round);
        if let Some(body) = fetch_body(client, &url).await {
            match judge_confirmation(&raw, &body) {
                Some(true) => return FetchOutcome::Agreed(raw),
                Some(false) => return FetchOutcome::Disagree,
                // Unparseable confirmation body = that relay is unusable for
                // quorum; keep trying the remaining relays.
                None => continue,
            }
        }
    }
    FetchOutcome::NoQuorum
}

/// The background fetch loop. Spawned from the node binary only when
/// `drand_pulse_enabled && allow_public_https`; runs for the node's lifetime.
pub async fn drand_fetch_loop(state: Arc<NodeState>, hb: Arc<super::supervision::LoopStatus>) {
    let relays: Vec<String> = state
        .config
        .drand_relays
        .iter()
        .filter(|u| {
            let ok = relay_url_is_acceptable(u);
            if !ok {
                warn!(relay = %u, "drand relay rejected by URL policy (need https://host or http://127.0.0.1 for tests) — skipped");
            }
            ok
        })
        .cloned()
        .collect();
    if relays.len() < 2 {
        warn!(
            usable = relays.len(),
            "drand fetch loop NOT started: cross-relay agreement needs ≥2 usable relays"
        );
        return;
    }
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("drand fetch loop NOT started: http client build failed: {e}");
            return;
        }
    };
    info!(
        relays = relays.len(),
        interval_secs = FETCH_INTERVAL_SECS,
        "drand pulse fetcher started (chain {})",
        &LOE_CHAIN_HASH[..16]
    );
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(FETCH_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut first_store_logged = false;
    loop {
        tick.tick().await;
        hb.heartbeat();
        let now = super::admin_pq_auth::now_unix_secs();
        match fetch_agreed_pulse(&client, &relays).await {
            FetchOutcome::Agreed(raw) => match pulse_from_agreed(&raw, now) {
                Some(pulse) => {
                    if pulse.not_before_unix() > now {
                        // A genuine round can't be future — our clock is behind.
                        state
                            .drand_pulse_ahead_of_clock_total
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            round = pulse.round,
                            not_before = pulse.not_before_unix(),
                            local_now = now,
                            "drand pulse is ahead of local clock — local NTP likely behind (pulse still embedded)"
                        );
                    }
                    if state.drand_pulse_cache.store_if_newer(pulse, now) {
                        state.drand_fetch_ok_total.fetch_add(1, Ordering::Relaxed);
                        if !first_store_logged {
                            first_store_logged = true;
                            info!("drand pulse cache populated — seals will start carrying not-before pulses");
                        }
                    } else {
                        state
                            .drand_round_regression_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                None => {
                    state.drand_fetch_fail_total.fetch_add(1, Ordering::Relaxed);
                }
            },
            FetchOutcome::Disagree => {
                state
                    .drand_relay_disagree_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!("drand relays disagreed on same-round BLS material — pulse skipped this tick");
            }
            FetchOutcome::NoQuorum => {
                state.drand_fetch_fail_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real LoE mainnet material for round 6251924, captured 2026-07-02 from
    /// api.drand.sh AND drand.cloudflare.com (byte-identical on both). Used
    /// here purely as parser/agreement vectors — no network in these tests.
    const V_ROUND: u64 = 6_251_924;
    const V_SIG: &str = "b42d6efe6dd2987ebcbc24ace710a8fcd8b5c90a37e6d6a7be9542a421f7a0af410fa17799cde329e72de6e502c17a881736d68b8131c37cda18e8726f5432e5497080d0da540accc8b284b83aa335731c554b250bf09d62b6c57bc4ade2c60a";

    fn body(round: u64, sig: &str, prev: &str) -> String {
        format!(
            "{{\"round\":{round},\"randomness\":\"ignored-by-parser\",\"signature\":\"{sig}\",\"previous_signature\":\"{prev}\"}}"
        )
    }

    fn prev_sig() -> String {
        "9".repeat(192)
    }

    #[test]
    fn parse_accepts_real_shape_and_lowercases() {
        let raw = parse_relay_response(&body(V_ROUND, &V_SIG.to_ascii_uppercase(), &prev_sig()))
            .expect("real-shaped body parses");
        assert_eq!(raw.round, V_ROUND);
        assert_eq!(raw.signature, V_SIG); // lowercased on parse
    }

    #[test]
    fn parse_rejects_round_zero_bad_hex_and_wrong_length() {
        assert!(parse_relay_response(&body(0, V_SIG, &prev_sig())).is_none());
        let bad_hex = "zz".repeat(96);
        assert!(parse_relay_response(&body(1, &bad_hex, &prev_sig())).is_none());
        let short = "ab".repeat(48); // 96 hex chars — G1-sized, wrong for this chain
        assert!(parse_relay_response(&body(1, &short, &prev_sig())).is_none());
        assert!(parse_relay_response("not json").is_none());
        assert!(parse_relay_response("{}").is_none());
    }

    #[test]
    fn derived_randomness_is_sha256_of_signature() {
        use sha2::{Digest, Sha256};
        let raw = RawPulse {
            round: V_ROUND,
            signature: V_SIG.into(),
            previous_signature: prev_sig(),
        };
        let p = pulse_from_agreed(&raw, u64::MAX / 2).expect("builds");
        let expect = hex::encode(Sha256::digest(hex::decode(V_SIG).unwrap()));
        assert_eq!(p.randomness, expect);
        assert_eq!(p.genesis_unix, LOE_GENESIS_UNIX);
        assert_eq!(p.period_secs, LOE_PERIOD_SECS);
        assert_eq!(p.chain_hash.as_deref(), Some(LOE_CHAIN_HASH));
        assert_eq!(p.signature.as_deref(), Some(V_SIG));
        assert!(p.is_well_formed());
    }

    #[test]
    fn insanely_future_round_is_dropped_mild_future_is_kept() {
        let raw = RawPulse {
            round: V_ROUND,
            signature: V_SIG.into(),
            previous_signature: prev_sig(),
        };
        let real_nb = LOE_GENESIS_UNIX + (V_ROUND - 1) * LOE_PERIOD_SECS;
        // Local clock 2 minutes behind the round's instant: keep (NTP skew).
        assert!(pulse_from_agreed(&raw, real_nb - 120).is_some());
        // Local clock more than a day behind: relay garbage, drop.
        assert!(pulse_from_agreed(&raw, real_nb - FUTURE_INSANITY_CAP_SECS - 61).is_none());
    }

    #[test]
    fn judge_confirmation_agrees_only_on_byte_identical_material() {
        let cand = RawPulse {
            round: V_ROUND,
            signature: V_SIG.into(),
            previous_signature: prev_sig(),
        };
        assert_eq!(
            judge_confirmation(&cand, &body(V_ROUND, V_SIG, &prev_sig())),
            Some(true)
        );
        // Same round, different signature byte ⇒ disagreement.
        let mut tampered = V_SIG.to_string();
        tampered.replace_range(0..1, "a");
        assert_eq!(
            judge_confirmation(&cand, &body(V_ROUND, &tampered, &prev_sig())),
            Some(false)
        );
        // Unparseable confirmation ⇒ None (relay unusable, not a disagreement).
        assert_eq!(judge_confirmation(&cand, "garbage"), None);
    }

    #[test]
    fn cache_is_monotone_and_staleness_capped() {
        let cache = DrandPulseCache::default();
        let now = 1_782_000_000u64;
        assert_eq!(cache.get_fresh(now), None);
        let mk = |round: u64| {
            pulse_from_agreed(
                &RawPulse {
                    round,
                    signature: V_SIG.into(),
                    previous_signature: prev_sig(),
                },
                u64::MAX / 2,
            )
            .unwrap()
        };
        assert!(cache.store_if_newer(mk(100), now));
        assert_eq!(cache.get_fresh(now).unwrap().round, 100);
        // Regression: rejected, cache unchanged.
        assert!(!cache.store_if_newer(mk(99), now + 10));
        assert!(!cache.store_if_newer(mk(100), now + 10));
        assert_eq!(cache.get_fresh(now + 10).unwrap().round, 100);
        // Advance: accepted.
        assert!(cache.store_if_newer(mk(101), now + 20));
        // Within the cap: fresh; past it: None (and age still reports).
        assert!(cache.get_fresh(now + 20 + STALENESS_CAP_SECS).is_some());
        assert_eq!(cache.get_fresh(now + 21 + STALENESS_CAP_SECS), None);
        assert_eq!(
            cache.age_secs(now + 21 + STALENESS_CAP_SECS),
            Some(STALENESS_CAP_SECS + 1)
        );
    }

    #[test]
    fn relay_url_policy() {
        for u in DEFAULT_RELAYS {
            assert!(relay_url_is_acceptable(u), "default relay {u} must pass");
        }
        assert!(relay_url_is_acceptable("http://127.0.0.1:9999")); // test mock
        assert!(relay_url_is_acceptable("http://localhost:9999"));
        assert!(!relay_url_is_acceptable("http://10.0.0.1")); // plain http non-loopback
        assert!(!relay_url_is_acceptable("ftp://api.drand.sh"));
        assert!(!relay_url_is_acceptable("https://user@evil.example"));
        assert!(!relay_url_is_acceptable("https://"));
    }
}
