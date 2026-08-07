//! Post-quantum admin authentication (Stage 4E.4).
//!
//! Replaces the shared-secret bearer-token model (`admin_token`) with a
//! Dilithium3 (FIPS 204 ML-DSA-65) signed challenge model for every admin
//! request. Wired into every admin handler via `server.rs::verify_admin_auth_pq`
//! — PQ-first, bearer-fallback. The legacy bearer-only entry
//! (`verify_admin_auth`) is retained only as a refusal path that rejects
//! `X-PQ-Admin` on any handler not using the PQ-bound variant (anti-downgrade).
//!
//! ## Wire format
//!
//! Client sends one HTTP header on every admin request:
//!
//! ```text
//! X-PQ-Admin: <pubkey_hex>:<unix_ts_secs>:<nonce_hex_16B>:<sig_hex>
//! ```
//!
//! - `pubkey_hex` — Dilithium3 public key (1952 bytes → 3904 hex chars). Must
//!   be present in the server's allowlist (`ELARA_ADMIN_PUBKEYS`).
//! - `unix_ts_secs` — request timestamp in seconds since UNIX epoch. Server
//!   rejects if abs(now - ts) > [`MAX_CLOCK_SKEW_SECS`].
//! - `nonce_hex_16B` — 16 random bytes (32 hex chars). Server rejects if seen
//!   within [`NONCE_WINDOW_SECS`] (replay protection).
//! - `sig_hex` — Dilithium3 signature (3309 bytes → 6618 hex chars) over
//!   the canonical message (see [`canonical_message`]).
//!
//! ## Canonical message
//!
//! ```text
//! "ELARA_ADMIN_V2\n" || method || "\n" || request_target || "\n" || ts || "\n" || nonce_hex
//! ```
//!
//! `request_target` is the RFC 7230 §5.3.1 origin form: `path`, plus `"?" +
//! query` when the request carries a non-empty query string (bare `path`
//! otherwise — no trailing `?`). Binding the query — not just the path —
//! stops an on-path attacker from racing a captured header with a substituted
//! `?query` (the nonce burn only blocks straight replay, not a substitution
//! race). Literal wire bytes: no percent-decode, no reorder, no case-fold —
//! the client MUST sign exactly the bytes it puts on the wire.
//!
//! Domain-separated by the `ELARA_ADMIN_V2` tag so admin signatures cannot
//! be replayed against any other Elara protocol message that happens to use
//! Dilithium3 (records, seals, attestations, etc.).
//!
//! ## Why not the existing record/seal Dilithium pipeline?
//!
//! Admin auth is a different trust domain — operator key, not validator key.
//! Sharing the verify path would let a leaked operator key sign a seal, or
//! a leaked validator key sign an admin request. Domain separation prevents
//! this. The crypto primitive is reused (`crypto::pqc::dilithium3_verify`)
//! but the message construction is exclusive to this module.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::pqc::dilithium3_verify;
use crate::network::LockRecover;

/// Maximum clock skew between client and server, in seconds. Requests outside
/// this window are rejected to limit the replay attack surface even if the
/// nonce cache wraps.
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Nonce-cache retention. A nonce seen within this window is rejected as a
/// replay. Must be ≥ 2 × MAX_CLOCK_SKEW_SECS so a request right at the skew
/// edge can't be replayed by waiting for cache eviction. (60s ≥ 2 × 30s.)
pub const NONCE_WINDOW_SECS: u64 = 60;

/// Domain-separation tag baked into the signed message. Bumping the version
/// lets us evolve the signed-bytes format without ambiguity.
///
/// V2 (2026-07-05): the signed bytes bind the full origin-form **request
/// target** (path + `?` + query) instead of the bare path. This closes the
/// query-substitution gap where an on-path attacker raced a valid header with a
/// different `?query` (e.g. `zone_transition?new_count=2`→`50`) while the V1
/// signature still verified. HARD CUT — there is no V1 fallback (a V1-accepting
/// server would keep the query unbound = a downgrade surface). The only signers
/// are our own `elara-cli`, which ships in lockstep; a version mismatch
/// fail-closes to 403. See [`request_target_from_parts`].
pub const DOMAIN_TAG: &str = "ELARA_ADMIN_V2";

/// HTTP header name. Lowercase form (axum normalizes).
pub const HEADER_NAME: &str = "x-pq-admin";

/// Reasons an admin auth check can fail. `Display` impl is safe to return to
/// clients — no sensitive material in any variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Header missing or empty.
    Missing,
    /// Header could not be parsed into the expected 4 colon-separated parts.
    Malformed(&'static str),
    /// Hex decode failed for one of the fields.
    BadHex(&'static str),
    /// Timestamp outside the allowed clock-skew window.
    StaleTimestamp { skew_secs: i64 },
    /// Nonce was seen recently — replay.
    ReplayedNonce,
    /// Pubkey not in the server's allowlist.
    UnknownPubkey,
    /// Cryptographic verification failed.
    BadSignature,
    /// Pubkey or signature length wrong.
    WrongLength { field: &'static str, got: usize, expected: usize },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing X-PQ-Admin header"),
            Self::Malformed(why) => write!(f, "malformed X-PQ-Admin header: {why}"),
            Self::BadHex(field) => write!(f, "X-PQ-Admin: invalid hex in {field}"),
            Self::StaleTimestamp { skew_secs } => {
                write!(f, "X-PQ-Admin: timestamp skew {skew_secs}s exceeds ±{MAX_CLOCK_SKEW_SECS}s")
            }
            Self::ReplayedNonce => write!(f, "X-PQ-Admin: nonce replayed within {NONCE_WINDOW_SECS}s window"),
            Self::UnknownPubkey => write!(f, "X-PQ-Admin: pubkey not in admin allowlist"),
            Self::BadSignature => write!(f, "X-PQ-Admin: Dilithium3 signature verification failed"),
            Self::WrongLength { field, got, expected } => {
                write!(f, "X-PQ-Admin: {field} length {got} ≠ expected {expected}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Build the origin-form request target (RFC 7230 §5.3.1) that V2 binds:
/// `path`, plus `"?" + query` when `query` is `Some(non-empty)` — bare `path`
/// otherwise (no trailing `?`, so `None` and `Some("")` are treated
/// identically). This is the ONE source of truth for the format; both the
/// server (`verify_admin_auth_inner`, from `uri.path()`/`uri.query()`) and the
/// client (`elara-cli`, from the exact wire query bytes) route through it so
/// the signed bytes and the transmitted bytes cannot diverge.
///
/// Literal bytes only — no percent-decode/encode, no reorder. Any difference
/// in the query bytes yields a different target and a different signature,
/// which is exactly the substitution resistance V2 exists to provide. The
/// caller is responsible for passing the query bytes as they appear on the
/// wire (the CLI pre-encodes with `urlencode_zone`, whose output the `url`
/// crate does not re-encode).
pub fn request_target_from_parts(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    }
}

/// Build the canonical message bytes that the client signs and the server
/// verifies. Same function on both sides — this IS the wire spec. `request_target`
/// is [`request_target_from_parts`]'s output (path + optional `?query`), NOT the
/// bare path (V2, 2026-07-05).
pub fn canonical_message(method: &str, request_target: &str, ts_secs: u64, nonce_hex: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        DOMAIN_TAG.len() + method.len() + request_target.len() + nonce_hex.len() + 24,
    );
    buf.extend_from_slice(DOMAIN_TAG.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(method.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(request_target.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(ts_secs.to_string().as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(nonce_hex.as_bytes());
    buf
}

/// Parsed `X-PQ-Admin` header. Field order matches the wire format.
#[derive(Debug, Clone)]
pub struct AdminCredential {
    pub pubkey: Vec<u8>,
    pub ts_secs: u64,
    pub nonce_hex: String,
    pub signature: Vec<u8>,
}

impl AdminCredential {
    /// Parse the header value. Does NOT verify the signature — call
    /// [`verify_admin_request`] for the full check.
    pub fn parse(header_value: &str) -> Result<Self, AuthError> {
        let value = header_value.trim();
        if value.is_empty() {
            return Err(AuthError::Missing);
        }
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 4 {
            return Err(AuthError::Malformed("expected 4 colon-separated fields"));
        }
        let pubkey = hex::decode(parts[0]).map_err(|_| AuthError::BadHex("pubkey"))?;
        // Dilithium3 (ML-DSA-65) public key is exactly 1952 bytes.
        if pubkey.len() != 1952 {
            return Err(AuthError::WrongLength {
                field: "pubkey",
                got: pubkey.len(),
                expected: 1952,
            });
        }
        let ts_secs: u64 = parts[1]
            .parse()
            .map_err(|_| AuthError::Malformed("timestamp not u64"))?;
        let nonce_hex = parts[2].to_string();
        // 16-byte nonce → 32 hex chars. Tighter than just any-length to defeat
        // truncated-nonce replay attacks.
        if nonce_hex.len() != 32 {
            return Err(AuthError::Malformed("nonce must be 32 hex chars (16 bytes)"));
        }
        if hex::decode(&nonce_hex).is_err() {
            return Err(AuthError::BadHex("nonce"));
        }
        let signature = hex::decode(parts[3]).map_err(|_| AuthError::BadHex("signature"))?;
        if signature.len() != 3309 {
            return Err(AuthError::WrongLength {
                field: "signature",
                got: signature.len(),
                expected: 3309,
            });
        }
        Ok(Self { pubkey, ts_secs, nonce_hex, signature })
    }
}

/// Bounded LRU-like nonce cache: stores `(nonce_hex → first_seen_unix_secs)`
/// and evicts entries older than [`NONCE_WINDOW_SECS`] on every check.
///
/// Memory bound: at sane admin request rates (≤ 10 req/s) the steady-state
/// size is O(NONCE_WINDOW_SECS × rate) = O(600 entries × ~50 bytes) ≈ 30 KB.
/// A genuinely-busy admin endpoint would still fit in single-digit MB.
pub struct NonceCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self { seen: Mutex::new(HashMap::new()) }
    }

    /// Returns `true` if this is the first time we've seen `nonce_hex` in
    /// the last [`NONCE_WINDOW_SECS`]. Returns `false` (= replay rejected)
    /// otherwise. Always evicts expired entries.
    pub fn check_and_insert(&self, nonce_hex: &str, now_secs: u64) -> bool {
        let mut seen = self.seen.lock_recover();
        // Evict expired entries. O(n) per call but n is bounded as analyzed
        // in the doc above. If this ever becomes hot, swap for a min-heap.
        seen.retain(|_, &mut ts| now_secs.saturating_sub(ts) <= NONCE_WINDOW_SECS);
        if seen.contains_key(nonce_hex) {
            return false;
        }
        seen.insert(nonce_hex.to_string(), now_secs);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.lock_recover().len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.lock_recover().is_empty()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Full verification: parse, allowlist check, timestamp check, replay check,
/// signature verify. Returns `Ok(pubkey_hex)` on success so the caller can
/// log which operator key was used.
///
/// `now_secs` is injected (rather than read from `SystemTime`) so tests are
/// deterministic. Production callers pass [`now_unix_secs`].
pub fn verify_admin_request(
    header_value: &str,
    method: &str,
    request_target: &str,
    allowlist: &[Vec<u8>],
    nonce_cache: &NonceCache,
    now_secs: u64,
) -> Result<String, AuthError> {
    let cred = AdminCredential::parse(header_value)?;

    // Allowlist check FIRST — cheap, and we don't want to even verify a
    // signature from an unknown key (avoids leaking timing info about which
    // Dilithium3 verifies are slow).
    if !allowlist.iter().any(|pk| pk.as_slice() == cred.pubkey.as_slice()) {
        return Err(AuthError::UnknownPubkey);
    }

    // Timestamp window check.
    let skew = (now_secs as i64) - (cred.ts_secs as i64);
    if skew.unsigned_abs() > MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::StaleTimestamp { skew_secs: skew });
    }

    // Replay check. Must come BEFORE signature verify so a flood of
    // duplicate-nonce requests can't burn CPU on Dilithium3 verifies.
    if !nonce_cache.check_and_insert(&cred.nonce_hex, now_secs) {
        return Err(AuthError::ReplayedNonce);
    }

    // Signature check.
    let msg = canonical_message(method, request_target, cred.ts_secs, &cred.nonce_hex);
    let ok = dilithium3_verify(&msg, &cred.signature, &cred.pubkey)
        .map_err(|_| AuthError::BadSignature)?;
    if !ok {
        return Err(AuthError::BadSignature);
    }

    Ok(hex::encode(&cred.pubkey))
}

/// Helper: parse the env var `ELARA_ADMIN_PUBKEYS` (comma-separated hex
/// pubkeys) into a vector of decoded pubkey bytes. Returns empty vec if env
/// var is unset or empty.
pub fn load_allowlist_from_env() -> Vec<Vec<u8>> {
    let raw = std::env::var("ELARA_ADMIN_PUBKEYS").unwrap_or_default();
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| hex::decode(s).ok())
        .filter(|pk| pk.len() == 1952)
        .collect()
}

/// Production timestamp source.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Operator-side helper: build a signed `X-PQ-Admin` header value bound to
/// `(method, request_target)` using the supplied Dilithium3 keypair. The nonce
/// is sampled from OS randomness; the timestamp is [`now_unix_secs`].
///
/// `request_target` MUST be the exact origin-form target that will appear on
/// the wire — `path` for a no-query request, or `path?query` built via
/// [`request_target_from_parts`] with the SAME pre-encoded query bytes the
/// request URL carries (V2). Signing the bare path while sending a `?query`
/// (the pre-V2 bug) makes the query attacker-malleable.
///
/// This is the symmetric counterpart to [`verify_admin_request`]. Returns the
/// formatted header string `pubkey_hex:ts:nonce_hex:sig_hex`.
pub fn build_admin_header(
    secret_key: &[u8],
    public_key: &[u8],
    method: &str,
    request_target: &str,
) -> Result<String, String> {
    let ts = now_unix_secs();
    let mut nonce_bytes = [0u8; 16];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("nonce getrandom: {e}"))?;
    let nonce_hex = hex::encode(nonce_bytes);
    let msg = canonical_message(method, request_target, ts, &nonce_hex);
    let sig = crate::crypto::pqc::dilithium3_sign_with_pk(&msg, secret_key, public_key)
        .map_err(|e| format!("dilithium3 sign: {e}"))?;
    Ok(format!(
        "{}:{}:{}:{}",
        hex::encode(public_key),
        ts,
        nonce_hex,
        hex::encode(sig),
    ))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk};

    /// Build a valid header for the given keypair, method, path, ts, nonce.
    fn make_header(
        sk: &[u8], pk: &[u8],
        method: &str, path: &str, ts: u64, nonce_hex: &str,
    ) -> String {
        let msg = canonical_message(method, path, ts, nonce_hex);
        let sig = dilithium3_sign_with_pk(&msg, sk, pk).expect("sign");
        format!("{}:{}:{}:{}", hex::encode(pk), ts, nonce_hex, hex::encode(sig))
    }

    fn fixed_nonce(byte: u8) -> String {
        hex::encode([byte; 16])
    }

    #[test]
    fn canonical_message_is_deterministic() {
        let a = canonical_message("POST", "/admin/snapshot", 1234567890, "deadbeef");
        let b = canonical_message("POST", "/admin/snapshot", 1234567890, "deadbeef");
        assert_eq!(a, b);
        // Domain tag MUST be at the very start — defeats cross-protocol replay.
        assert!(a.starts_with(b"ELARA_ADMIN_V2\n"));
    }

    #[test]
    fn parse_rejects_obvious_garbage() {
        assert_eq!(AdminCredential::parse("").unwrap_err(), AuthError::Missing);
        assert!(matches!(
            AdminCredential::parse("only:two:fields").unwrap_err(),
            AuthError::Malformed(_)
        ));
        // 4 fields but pubkey isn't hex.
        assert!(matches!(
            AdminCredential::parse("zz:1:abcd:ef").unwrap_err(),
            AuthError::BadHex("pubkey")
        ));
    }

    #[test]
    fn nonce_cache_blocks_replay_within_window() {
        let cache = NonceCache::new();
        assert!(cache.check_and_insert("nonce-A", 1000));
        // Same nonce within window → replay.
        assert!(!cache.check_and_insert("nonce-A", 1010));
        // Different nonce → fine.
        assert!(cache.check_and_insert("nonce-B", 1010));
    }

    #[test]
    fn nonce_cache_evicts_after_window() {
        let cache = NonceCache::new();
        assert!(cache.check_and_insert("nonce-A", 1000));
        // Move past the window — entry must be evicted, replay accepted.
        assert!(cache.check_and_insert("nonce-A", 1000 + NONCE_WINDOW_SECS + 1));
    }

    #[test]
    fn verify_happy_path() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "GET", "/admin/tasks", 5_000, &fixed_nonce(0xAA),
        );
        let result = verify_admin_request(
            &header,
            "GET", "/admin/tasks",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000,
        );
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        assert_eq!(result.unwrap(), hex::encode(&kp.public_key));
    }

    #[test]
    fn verify_rejects_pubkey_not_in_allowlist() {
        let kp_attacker = dilithium3_keygen().expect("kg attacker");
        let kp_legit    = dilithium3_keygen().expect("kg legit");
        let cache = NonceCache::new();
        let header = make_header(
            &kp_attacker.secret_key, &kp_attacker.public_key,
            "POST", "/admin/snapshot", 5_000, &fixed_nonce(0x01),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/snapshot",
            std::slice::from_ref(&kp_legit.public_key),
            &cache,
            5_000,
        ).unwrap_err();
        assert_eq!(err, AuthError::UnknownPubkey);
    }

    #[test]
    fn verify_rejects_stale_timestamp() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        // Sign a request "now=5000", verify at "now=5000 + skew + 1".
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "POST", "/admin/gc", 5_000, &fixed_nonce(0x02),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/gc",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000 + MAX_CLOCK_SKEW_SECS + 1,
        ).unwrap_err();
        assert!(matches!(err, AuthError::StaleTimestamp { .. }), "got {err:?}");
    }

    #[test]
    fn verify_rejects_future_timestamp() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "POST", "/admin/gc", 5_000 + MAX_CLOCK_SKEW_SECS + 5, &fixed_nonce(0x03),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/gc",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000,
        ).unwrap_err();
        assert!(matches!(err, AuthError::StaleTimestamp { .. }));
    }

    #[test]
    fn verify_rejects_replayed_nonce() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "GET", "/admin/bans", 5_000, &fixed_nonce(0x04),
        );
        // First call: ok.
        verify_admin_request(
            &header, "GET", "/admin/bans",
            std::slice::from_ref(&kp.public_key), &cache, 5_000,
        ).expect("first ok");
        // Second call (same nonce): replay.
        let err = verify_admin_request(
            &header, "GET", "/admin/bans",
            std::slice::from_ref(&kp.public_key), &cache, 5_001,
        ).unwrap_err();
        assert_eq!(err, AuthError::ReplayedNonce);
    }

    #[test]
    fn verify_rejects_tampered_path() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        // Sign for /admin/snapshot but submit against /admin/purge_peer.
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "POST", "/admin/snapshot", 5_000, &fixed_nonce(0x05),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/purge_peer",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000,
        ).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn request_target_from_parts_v2_format() {
        // No query / empty query → bare path (no trailing '?').
        assert_eq!(request_target_from_parts("/admin/x", None), "/admin/x");
        assert_eq!(request_target_from_parts("/admin/x", Some("")), "/admin/x");
        // Non-empty query → path?query.
        assert_eq!(
            request_target_from_parts("/admin/x", Some("a=1&b=2")),
            "/admin/x?a=1&b=2"
        );
        // Literal bytes: a percent-encoded slash is preserved verbatim, NOT
        // decoded — the signed target must equal the wire bytes exactly.
        assert_eq!(
            request_target_from_parts("/admin/zones/subscribe", Some("zone=medical%2Feu")),
            "/admin/zones/subscribe?zone=medical%2Feu"
        );
    }

    #[test]
    fn verify_binds_query_string_v2() {
        // V2 core property: the query is part of the signed request target, so a
        // header signed for one query MUST NOT verify against a substituted one.
        // This is the zone_transition new_count=2→50 substitution attack.
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "POST", "/admin/zone_transition?target_epoch=30&new_count=2",
            5_000, &fixed_nonce(0x20),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/zone_transition?target_epoch=30&new_count=50",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000,
        ).unwrap_err();
        assert_eq!(err, AuthError::BadSignature, "substituted query must fail closed");
    }

    #[test]
    fn verify_accepts_exact_query_target_v2() {
        // The matching full target (with a %2F-bearing zone) round-trips OK —
        // proves query binding doesn't break legitimate query-bearing requests.
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let target = "/admin/zones/subscribe?zone=medical%2Feu";
        let header = make_header(
            &kp.secret_key, &kp.public_key, "POST", target, 5_000, &fixed_nonce(0x21),
        );
        let ok = verify_admin_request(
            &header, "POST", target,
            std::slice::from_ref(&kp.public_key), &cache, 5_000,
        );
        assert!(ok.is_ok(), "exact query target must verify, got {ok:?}");
    }

    #[test]
    fn verify_empty_query_equals_bare_path_v2() {
        // A header signed for the bare path verifies against the same bare path;
        // request_target_from_parts maps None and Some("") identically, so a
        // client that signs the bare path and a server that sees no query agree.
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = make_header(
            &kp.secret_key, &kp.public_key, "GET", "/admin/memory", 5_000, &fixed_nonce(0x22),
        );
        let ok = verify_admin_request(
            &header, "GET", &request_target_from_parts("/admin/memory", None),
            std::slice::from_ref(&kp.public_key), &cache, 5_000,
        );
        assert!(ok.is_ok(), "bare-path target must verify, got {ok:?}");
    }

    #[test]
    fn verify_rejects_rebootstrap_force_and_peer_substitution_v2() {
        // The one real body-substitution residual the V2 relocation closes:
        // `/admin/snapshot_rebootstrap_from` now carries `peer_addr` + `force`
        // in the SIGNED query (they were an unsigned JSON body). A captured
        // header signed for force=false must fail against force=true (the
        // permanent-rollback lever that defeats the refuse-if-behind guard)
        // and against a redirected peer_addr.
        let kp = dilithium3_keygen().expect("keygen");
        let signed = "/admin/snapshot_rebootstrap_from?peer_addr=http://seed:9473&force=false";
        let header = make_header(
            &kp.secret_key, &kp.public_key, "POST", signed, 5_000, &fixed_nonce(0x23),
        );
        for tampered in [
            "/admin/snapshot_rebootstrap_from?peer_addr=http://seed:9473&force=true",
            "/admin/snapshot_rebootstrap_from?peer_addr=http://evil:9473&force=false",
        ] {
            let cache = NonceCache::new();
            let err = verify_admin_request(
                &header, "POST", tampered,
                std::slice::from_ref(&kp.public_key), &cache, 5_000,
            )
            .unwrap_err();
            assert_eq!(
                err,
                AuthError::BadSignature,
                "substituted target {tampered} must fail closed"
            );
        }
        // Control: the exact signed target still verifies.
        let cache = NonceCache::new();
        let ok = verify_admin_request(
            &header, "POST", signed,
            std::slice::from_ref(&kp.public_key), &cache, 5_000,
        );
        assert!(ok.is_ok(), "exact signed target must verify, got {ok:?}");
    }

    #[test]
    fn verify_rejects_tampered_method() {
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        // Sign GET, present as POST.
        let header = make_header(
            &kp.secret_key, &kp.public_key,
            "GET", "/admin/tasks", 5_000, &fixed_nonce(0x06),
        );
        let err = verify_admin_request(
            &header,
            "POST", "/admin/tasks",
            std::slice::from_ref(&kp.public_key),
            &cache,
            5_000,
        ).unwrap_err();
        assert_eq!(err, AuthError::BadSignature);
    }

    #[test]
    fn verify_rejects_wrong_pubkey_length() {
        // 1951 bytes instead of 1952.
        let bogus_pk = hex::encode(vec![0u8; 1951]);
        let bogus_sig = hex::encode(vec![0u8; 3309]);
        let header = format!("{bogus_pk}:5000:{}:{bogus_sig}", fixed_nonce(0x07));
        let err = AdminCredential::parse(&header).unwrap_err();
        assert!(matches!(err, AuthError::WrongLength { field: "pubkey", .. }));
    }

    #[test]
    fn allowlist_check_runs_before_signature_verify() {
        // Use a junk signature (3309 bytes of 0x00) — verify_admin_request must
        // reject on UnknownPubkey before calling dilithium3_verify (which would
        // either return Ok(false) or Err). UnknownPubkey is the proof.
        let pk = vec![0xAB; 1952];
        let sig = vec![0x00; 3309];
        let nonce = fixed_nonce(0x08);
        let header = format!("{}:5000:{}:{}", hex::encode(&pk), nonce, hex::encode(&sig));
        let cache = NonceCache::new();
        let err = verify_admin_request(
            &header,
            "GET", "/admin/tasks",
            &[], // empty allowlist
            &cache,
            5_000,
        ).unwrap_err();
        assert_eq!(err, AuthError::UnknownPubkey);
    }

    #[test]
    fn build_admin_header_round_trips_against_verify() {
        // PQ-R7 regression: the client-side helper must produce a header that
        // the server-side verifier accepts on the exact same (method, path).
        let kp = dilithium3_keygen().expect("keygen");
        let cache = NonceCache::new();
        let header = build_admin_header(
            &kp.secret_key, &kp.public_key,
            "POST", "/admin/rebuild",
        ).expect("build_admin_header");
        let now = now_unix_secs();
        let result = verify_admin_request(
            &header,
            "POST", "/admin/rebuild",
            std::slice::from_ref(&kp.public_key),
            &cache,
            now,
        );
        assert!(result.is_ok(), "round-trip verify must succeed, got {:?}", result);
    }

    #[test]
    fn build_admin_header_nonces_differ_across_calls() {
        // PQ-R7 regression: each call samples a fresh nonce so two headers
        // built in rapid succession are not identical (would be a replay bug).
        let kp = dilithium3_keygen().expect("keygen");
        let a = build_admin_header(&kp.secret_key, &kp.public_key, "GET", "/admin/x").unwrap();
        let b = build_admin_header(&kp.secret_key, &kp.public_key, "GET", "/admin/x").unwrap();
        assert_ne!(a, b, "nonce randomness must differ between successive headers");
    }

    #[test]
    fn load_allowlist_from_env_filters_garbage() {
        // Use a process-unique env var name so parallel tests don't race.
        std::env::set_var("ELARA_ADMIN_PUBKEYS", "");
        assert!(load_allowlist_from_env().is_empty());

        // Wrong-length entries dropped, valid entry kept.
        let valid = hex::encode(vec![0x42u8; 1952]);
        let too_short = hex::encode(vec![0x99u8; 100]);
        std::env::set_var(
            "ELARA_ADMIN_PUBKEYS",
            format!("{valid},{too_short},not-hex,,{valid}"),
        );
        let loaded = load_allowlist_from_env();
        assert_eq!(loaded.len(), 2, "two valid entries should survive");
        assert!(loaded.iter().all(|pk| pk.len() == 1952));
        std::env::remove_var("ELARA_ADMIN_PUBKEYS");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pure-helper coverage tests.
    // 5 axes targeting distinct invariants:
    //   1. 4 module constants strict-pin + cross-relation (NONCE_WINDOW ≥ 2 ×
    //      MAX_CLOCK_SKEW) + DOMAIN_TAG and HEADER_NAME byte-exact values.
    //   2. AuthError 8-variant Debug + Display + Clone + PartialEq + Eq;
    //      Display messages embed key tokens; per-variant pairwise distinct.
    //   3. canonical_message wire format byte-exact layout pin: 4 '\n'
    //      separators, DOMAIN_TAG at byte 0, no trailing '\n', determinism,
    //      capacity hint accepts empty fields with no panic.
    //   4. AdminCredential::parse negative-path coverage matrix: empty,
    //      whitespace-trimmed-empty, ≠4 fields, non-hex pubkey, wrong-length
    //      pubkey, non-u64 ts, nonce wrong length, non-hex nonce, non-hex sig,
    //      wrong-length sig — each maps to its specific AuthError variant.
    //   5. NonceCache::{new,default} initial-state + first-insert-true +
    //      replay-false within window + post-window eviction + cross-nonce
    //      independence + len/is_empty consistency + clock-skew (now < ts)
    //      saturating_sub safety (no panic on backward clock).
    // ─────────────────────────────────────────────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_admin_pq_constants_strict_pin_and_window_cross_relation() {
        // Axis 1: 4 module constants strict-pin.

        // MAX_CLOCK_SKEW_SECS exact value + u64 type-pin.
        assert_eq!(MAX_CLOCK_SKEW_SECS, 30);
        let _: u64 = MAX_CLOCK_SKEW_SECS;
        assert!(MAX_CLOCK_SKEW_SECS > 0);

        // NONCE_WINDOW_SECS exact value + u64 type-pin.
        assert_eq!(NONCE_WINDOW_SECS, 60);
        let _: u64 = NONCE_WINDOW_SECS;

        // Cross-relation invariant: NONCE_WINDOW ≥ 2 × MAX_CLOCK_SKEW.
        // Doc comment claims this — load-bearing so a request right at the
        // skew edge cannot be replayed by waiting for cache eviction.
        assert!(NONCE_WINDOW_SECS >= 2 * MAX_CLOCK_SKEW_SECS,
            "NONCE_WINDOW_SECS ({}) must be >= 2 × MAX_CLOCK_SKEW_SECS ({})",
            NONCE_WINDOW_SECS, 2 * MAX_CLOCK_SKEW_SECS);

        // DOMAIN_TAG exact byte value + length + ASCII uppercase + version
        // suffix. Bumping the version IS the breaking-change knob — must
        // not silently change.
        assert_eq!(DOMAIN_TAG, "ELARA_ADMIN_V2");
        assert_eq!(DOMAIN_TAG.len(), 14);
        assert!(DOMAIN_TAG.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
            "domain tag should be ASCII uppercase + '_' + digits");
        assert!(DOMAIN_TAG.ends_with("_V2"));
        // Domain-separation from any plausible non-admin Dilithium3 tag:
        // record/seal/attestation namespaces don't start with ELARA_ADMIN.
        assert!(DOMAIN_TAG.starts_with("ELARA_ADMIN"));

        // HEADER_NAME exact value + ASCII lowercase (axum normalizes — must
        // match the lowercase form to avoid case-sensitivity bugs).
        assert_eq!(HEADER_NAME, "x-pq-admin");
        assert_eq!(HEADER_NAME.len(), 10);
        assert!(HEADER_NAME.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        // No underscore in header name (HTTP header convention is '-').
        assert!(!HEADER_NAME.contains('_'));
        assert!(HEADER_NAME.contains('-'));
        // Header name and domain tag are distinct identifiers — no overlap.
        assert_ne!(HEADER_NAME, DOMAIN_TAG.to_lowercase());
    }

    #[test]
    fn batch_b_admin_pq_auth_error_8_variant_display_debug_clone_partial_eq() {
        // Axis 2: AuthError 8-variant Debug + Display + Clone + PartialEq.

        let variants = vec![
            AuthError::Missing,
            AuthError::Malformed("test-why"),
            AuthError::BadHex("pubkey"),
            AuthError::StaleTimestamp { skew_secs: 42 },
            AuthError::ReplayedNonce,
            AuthError::UnknownPubkey,
            AuthError::BadSignature,
            AuthError::WrongLength { field: "sig", got: 100, expected: 3309 },
        ];
        assert_eq!(variants.len(), 8);

        // PartialEq + Eq: each variant equals itself.
        for v in &variants {
            assert_eq!(v, v);
            // Clone yields equivalent value.
            let c = v.clone();
            assert_eq!(&c, v);
        }

        // Pairwise distinct (8×8 matrix minus diagonal — 56 off-diagonal).
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants at {} and {} must differ", i, j);
                }
            }
        }

        // Display messages: each contains an identifying token.
        let display: Vec<String> = variants.iter().map(|e| format!("{e}")).collect();
        assert!(display[0].contains("missing"));
        assert!(display[1].contains("malformed") && display[1].contains("test-why"));
        assert!(display[2].contains("hex") && display[2].contains("pubkey"));
        assert!(display[3].contains("skew") && display[3].contains("42"));
        assert!(display[4].contains("replay") || display[4].contains("nonce"));
        // UnknownPubkey Display — must be non-empty and reference pubkey.
        assert!(!display[5].is_empty());
        assert!(display[6].contains("verification") || display[6].contains("signature"));
        assert!(display[7].contains("100") && display[7].contains("3309"));

        // Debug shape includes variant name for all.
        let debug: Vec<String> = variants.iter().map(|e| format!("{e:?}")).collect();
        assert!(debug[0].contains("Missing"));
        assert!(debug[1].contains("Malformed"));
        assert!(debug[2].contains("BadHex"));
        assert!(debug[3].contains("StaleTimestamp"));
        assert!(debug[4].contains("ReplayedNonce"));
        assert!(debug[5].contains("UnknownPubkey"));
        assert!(debug[6].contains("BadSignature"));
        assert!(debug[7].contains("WrongLength"));

        // Variants with payload distinguish by payload value.
        assert_ne!(
            AuthError::Malformed("a"),
            AuthError::Malformed("b"),
        );
        assert_ne!(
            AuthError::StaleTimestamp { skew_secs: 1 },
            AuthError::StaleTimestamp { skew_secs: 2 },
        );
        assert_ne!(
            AuthError::WrongLength { field: "a", got: 1, expected: 2 },
            AuthError::WrongLength { field: "a", got: 1, expected: 3 },
        );
    }

    #[test]
    fn batch_b_admin_pq_canonical_message_byte_exact_layout_and_determinism() {
        // Axis 3: canonical_message wire format byte-exact pin.

        let msg = canonical_message("POST", "/admin/snapshot", 1_234_567_890, "deadbeef");

        // Domain tag at byte 0 with newline separator — defeats
        // cross-protocol replay against any other Dilithium3 verifier.
        assert!(msg.starts_with(b"ELARA_ADMIN_V2\n"));

        // Count of '\n' separators: exactly 4 (5 fields separated by 4 '\n').
        let nl_count = msg.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(nl_count, 4, "expected 4 newlines, got {} in {:?}",
            nl_count, std::str::from_utf8(&msg));

        // No trailing newline.
        assert_ne!(msg.last(), Some(&b'\n'));

        // Reconstruct the exact byte layout.
        let expected = b"ELARA_ADMIN_V2\nPOST\n/admin/snapshot\n1234567890\ndeadbeef";
        assert_eq!(msg.as_slice(), expected.as_slice());

        // Determinism: same inputs => same output.
        let msg2 = canonical_message("POST", "/admin/snapshot", 1_234_567_890, "deadbeef");
        assert_eq!(msg, msg2);

        // Different in any single field → different output.
        let alt_method = canonical_message("GET", "/admin/snapshot", 1_234_567_890, "deadbeef");
        assert_ne!(msg, alt_method);
        let alt_path = canonical_message("POST", "/admin/rebuild", 1_234_567_890, "deadbeef");
        assert_ne!(msg, alt_path);
        let alt_ts = canonical_message("POST", "/admin/snapshot", 1_234_567_891, "deadbeef");
        assert_ne!(msg, alt_ts);
        let alt_nonce = canonical_message("POST", "/admin/snapshot", 1_234_567_890, "cafebabe");
        assert_ne!(msg, alt_nonce);

        // Empty fields accepted (format-level, not policy-level — policy lives
        // in AdminCredential::parse). The fn must not panic on empty input.
        let empty_msg = canonical_message("", "", 0, "");
        assert_eq!(empty_msg.as_slice(), b"ELARA_ADMIN_V2\n\n\n0\n");
        let nl_empty = empty_msg.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(nl_empty, 4);

        // Timestamp written as decimal u64 (.to_string()), not as 8 bytes BE.
        let ts_msg = canonical_message("X", "Y", 100, "Z");
        assert!(ts_msg.windows(3).any(|w| w == b"100"),
            "ts must be decimal-encoded: {:?}", std::str::from_utf8(&ts_msg));

        // u64::MAX as ts works (decimal width up to 20 chars).
        let big = canonical_message("M", "/p", u64::MAX, "n");
        assert!(big.windows(20).any(|w| w == b"18446744073709551615"));
    }

    #[test]
    fn batch_b_admin_pq_credential_parse_negative_path_matrix() {
        // Axis 4: AdminCredential::parse exhaustive negative-path coverage.

        // Empty + whitespace-trimmed-empty → Missing.
        assert_eq!(AdminCredential::parse("").unwrap_err(), AuthError::Missing);
        assert_eq!(AdminCredential::parse("   ").unwrap_err(), AuthError::Missing);
        assert_eq!(AdminCredential::parse("\t\n  ").unwrap_err(), AuthError::Missing);

        // ≠4 fields → Malformed.
        let err_1 = AdminCredential::parse("just-one").unwrap_err();
        assert!(matches!(err_1, AuthError::Malformed(_)), "got {err_1:?}");
        let err_2 = AdminCredential::parse("a:b").unwrap_err();
        assert!(matches!(err_2, AuthError::Malformed(_)));
        let err_3 = AdminCredential::parse("a:b:c").unwrap_err();
        assert!(matches!(err_3, AuthError::Malformed(_)));
        let err_5 = AdminCredential::parse("a:b:c:d:e").unwrap_err();
        assert!(matches!(err_5, AuthError::Malformed(_)));

        // 4 fields but non-hex pubkey → BadHex("pubkey").
        let err_hex_pk = AdminCredential::parse("zz:1:abcd:ef").unwrap_err();
        assert_eq!(err_hex_pk, AuthError::BadHex("pubkey"));

        // 4 fields, valid hex pubkey but wrong length → WrongLength{pubkey,..,1952}.
        let short_pk = hex::encode(vec![0xAA; 100]);
        let header = format!("{short_pk}:1234567890:{}:ab", "0".repeat(32));
        let err_wl_pk = AdminCredential::parse(&header).unwrap_err();
        assert!(matches!(err_wl_pk, AuthError::WrongLength {
            field: "pubkey", got: 100, expected: 1952,
        }), "got {err_wl_pk:?}");

        // Pubkey correct length but ts not u64 → Malformed("...not u64").
        let good_pk = hex::encode(vec![0x42; 1952]);
        let header_bad_ts = format!("{good_pk}:not-a-number:{}:ab", "0".repeat(32));
        let err_ts = AdminCredential::parse(&header_bad_ts).unwrap_err();
        assert!(matches!(err_ts, AuthError::Malformed(_)), "got {err_ts:?}");

        // Pubkey + ts OK but nonce ≠ 32 hex chars → Malformed.
        let header_short_nonce = format!("{good_pk}:1234567890:short:ab");
        let err_nonce_len = AdminCredential::parse(&header_short_nonce).unwrap_err();
        assert!(matches!(err_nonce_len, AuthError::Malformed(_)));

        // Pubkey + ts + nonce 32 chars but non-hex nonce → BadHex("nonce").
        let header_bad_nonce_hex = format!("{good_pk}:1234567890:{}:ab", "z".repeat(32));
        let err_nonce_hex = AdminCredential::parse(&header_bad_nonce_hex).unwrap_err();
        assert_eq!(err_nonce_hex, AuthError::BadHex("nonce"));

        // Sig non-hex → BadHex("signature"). Use a valid-hex nonce so we get
        // past the nonce gate.
        let valid_nonce = "0".repeat(32);
        let header_bad_sig_hex = format!("{good_pk}:1234567890:{valid_nonce}:zz");
        let err_sig_hex = AdminCredential::parse(&header_bad_sig_hex).unwrap_err();
        assert_eq!(err_sig_hex, AuthError::BadHex("signature"));

        // Sig wrong length → WrongLength{signature,..,3309}.
        let short_sig = hex::encode(vec![0x55; 100]);
        let header_short_sig = format!("{good_pk}:1234567890:{valid_nonce}:{short_sig}");
        let err_sig_len = AdminCredential::parse(&header_short_sig).unwrap_err();
        assert!(matches!(err_sig_len, AuthError::WrongLength {
            field: "signature", got: 100, expected: 3309,
        }), "got {err_sig_len:?}");
    }

    #[test]
    fn batch_b_admin_pq_nonce_cache_lifecycle_eviction_and_clock_skew_safety() {
        // Axis 5: NonceCache lifecycle invariants.

        // new() and default() both yield an empty cache.
        let c1 = NonceCache::new();
        let c2 = NonceCache::default();
        assert_eq!(c1.len(), 0);
        assert_eq!(c2.len(), 0);
        assert!(c1.is_empty());
        assert!(c2.is_empty());

        // First insert at t=1000 returns true.
        assert!(c1.check_and_insert("n-A", 1000));
        assert_eq!(c1.len(), 1);
        assert!(!c1.is_empty());

        // Same nonce within window → false (replay).
        assert!(!c1.check_and_insert("n-A", 1010));
        assert!(!c1.check_and_insert("n-A", 1000 + NONCE_WINDOW_SECS));
        assert_eq!(c1.len(), 1, "rejected insert must not grow the cache");

        // Different nonce within window → true (independent).
        assert!(c1.check_and_insert("n-B", 1010));
        assert_eq!(c1.len(), 2);

        // Past the window: insert at t = 1000 + 2 × WINDOW evicts BOTH n-A
        // (inserted at 1000, elapsed = 2 × WINDOW > WINDOW) and n-B (inserted
        // at 1010, elapsed = 2 × WINDOW − 10 > WINDOW for WINDOW ≥ 11s, holds
        // for the actual 60s value).
        let t_evict = 1000 + 2 * NONCE_WINDOW_SECS;
        assert!(c1.check_and_insert("n-A", t_evict),
            "n-A should be re-acceptable once its window has passed");
        // After eviction + re-insert, cache holds ONLY the freshly inserted
        // n-A at t_evict. n-B was inserted at 1010 and its elapsed
        // (2×WINDOW − 10 = 110) > WINDOW (60), so n-B is evicted.
        assert_eq!(c1.len(), 1, "old entries should have been evicted");

        // Replay-protection still holds for the freshly inserted n-A.
        assert!(!c1.check_and_insert("n-A", t_evict));

        // Clock-skew safety: now_secs < entry's stored ts must not panic
        // (uses saturating_sub). Insert n-C at high ts, then probe with
        // lower ts — eviction logic returns 0 elapsed, retains entry.
        let c3 = NonceCache::new();
        assert!(c3.check_and_insert("n-C", 10_000));
        // Backward clock: now=5000 < ts=10000. saturating_sub(5000-10000)=0
        // ≤ NONCE_WINDOW_SECS, so n-C is retained, and we treat it as replay.
        assert!(!c3.check_and_insert("n-C", 5_000),
            "backward-clock replay must still be rejected (entry retained)");
        // len still 1.
        assert_eq!(c3.len(), 1);

        // Boundary: exactly at NONCE_WINDOW_SECS the entry is still considered
        // active (.retain(|_,&mut ts| now.saturating_sub(ts) <= WINDOW)).
        let c4 = NonceCache::new();
        assert!(c4.check_and_insert("n-D", 2000));
        // now - ts = NONCE_WINDOW_SECS exactly => retained.
        assert!(!c4.check_and_insert("n-D", 2000 + NONCE_WINDOW_SECS));
        // now - ts = NONCE_WINDOW_SECS + 1 => evicted, fresh insert OK.
        assert!(c4.check_and_insert("n-D", 2000 + NONCE_WINDOW_SECS + 1));
    }
}
