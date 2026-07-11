//! Peer identity pinning store — TOFU then pinned.
//!
//! Maps `peer_addr` (socket-addr string like "203.0.113.5:9473") to the
//! SHA3-256 hash of that peer's long-term Dilithium3 public key. On first
//! contact the observed hash is recorded (Trust On First Use); on every
//! subsequent contact the observed hash must match the pinned value or the
//! connection is rejected.
//!
//! This is the SSH-style trust model described in Phase 4 of the task list:
//! no PKI, no CAs, no certificate revocation lists. The pin list is the
//! authoritative source of "who I think this peer is."
//!
//! # Threading
//!
//! The store uses a single `RwLock<HashMap>` internally. Reads (the common
//! case — every outbound connection calls `expectation_for`) are lock-free
//! for concurrent readers. Writes (TOFU pin on first contact) are rare.
//!
//! # Persistence
//!
//! When opened from a path, every successful `pin_or_verify` that mutates
//! the map triggers a whole-file rewrite via a temp-file + rename. The file
//! is JSON for human inspection; at testnet scale (≤10K pinned peers) this
//! is ~2 MiB which rewrites in a few ms. At mainnet scale this will want
//! a bounded append-only log with periodic compaction — out of scope here.
//!
//! # Hard rule
//!
//! A pinned peer that presents a different hash is an identity change.
//! The store NEVER silently overwrites — the caller must explicitly
//! `forget(addr)` and then `pin_or_verify` again. This is deliberate:
//! silent pin rotation defeats the whole point.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::handshake::PeerExpectation;

#[derive(Debug, thiserror::Error)]
pub enum PeerStoreError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("serde_json: {0}")]
    Serde(#[from] serde_json::Error),
    #[error(
        "identity pin mismatch for {addr}: expected {expected}, observed {observed}"
    )]
    PinMismatch {
        addr: String,
        expected: String,
        observed: String,
    },
    #[error("hex decode for addr {addr}: {source}")]
    Hex {
        addr: String,
        #[source]
        source: hex::FromHexError,
    },
    #[error("invalid pinned hash length for {addr}: expected 32 bytes, got {len}")]
    BadHashLen { addr: String, len: usize },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PinRecord {
    /// Lowercase hex of SHA3-256(Dilithium3 pubkey).
    identity_hash_hex: String,
    /// Unix seconds when first pinned.
    first_seen_unix: u64,
    /// Unix seconds of most recent verification.
    last_seen_unix: u64,
}

/// TOFU-then-pinned peer identity store.
pub struct PeerIdentityStore {
    path: Option<PathBuf>,
    inner: RwLock<HashMap<String, PinRecord>>,
}

impl std::fmt::Debug for PeerIdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerIdentityStore")
            .field("path", &self.path)
            .field("pinned_peers", &self.len())
            .finish()
    }
}

impl PeerIdentityStore {
    /// Create an in-memory store (no disk persistence — useful for tests
    /// and for nodes that only care about live-session pinning).
    pub fn in_memory() -> Self {
        Self {
            path: None,
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Open (or create) a persistent store at `path`. If the file does not
    /// exist, an empty store is returned and will be created on first write.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PeerStoreError> {
        let path: PathBuf = path.into();
        let map = if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.is_empty() {
                HashMap::new()
            } else {
                serde_json::from_slice::<HashMap<String, PinRecord>>(&bytes)?
            }
        } else {
            HashMap::new()
        };

        // Validate every loaded record's hash shape once, up front, so we
        // never surface a malformed pin at connection time.
        for (addr, rec) in &map {
            let bytes = hex::decode(&rec.identity_hash_hex).map_err(|e| PeerStoreError::Hex {
                addr: addr.clone(),
                source: e,
            })?;
            if bytes.len() != 32 {
                return Err(PeerStoreError::BadHashLen {
                    addr: addr.clone(),
                    len: bytes.len(),
                });
            }
        }

        Ok(Self {
            path: Some(path),
            inner: RwLock::new(map),
        })
    }

    /// Return the `PeerExpectation` to pass into `pq_dial` for this address.
    /// `Pinned(hash)` if we've seen this peer before, `Tofu` on first contact.
    pub fn expectation_for(&self, addr: &str) -> PeerExpectation {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match guard.get(addr) {
            Some(rec) => {
                // We already validated hex + length on load / pin, so this
                // decode is infallible in practice; fall back to TOFU if
                // something went wrong rather than panicking a live node.
                match hex::decode(&rec.identity_hash_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&b);
                        PeerExpectation::Pinned(out)
                    }
                    _ => PeerExpectation::Tofu,
                }
            }
            None => PeerExpectation::Tofu,
        }
    }

    /// REALMS P1 slice (c2): identity-based membership for the sovereign
    /// inbound deny-unknown gate. Inbound source addresses are ephemeral
    /// (random source port), so the lookup is by IDENTITY across all pinned
    /// records, never by addr. O(pins) — a sovereign realm pins a small
    /// operator-curated set.
    pub fn contains_identity(&self, identity: &[u8; 32]) -> bool {
        let hex = hex::encode(identity);
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.values().any(|rec| rec.identity_hash_hex == hex)
    }

    /// After a successful handshake, call this with the peer's observed
    /// identity hash. If no pin exists the hash is recorded (TOFU); if a
    /// pin exists and matches, `last_seen_unix` is refreshed; if a pin
    /// exists and does NOT match, this returns `PinMismatch` — callers
    /// must treat this as an authentication failure.
    pub fn pin_or_verify(
        &self,
        addr: &str,
        observed: [u8; 32],
    ) -> Result<(), PeerStoreError> {
        let observed_hex = hex::encode(observed);
        let now = now_unix();

        let needs_persist = {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            match guard.get_mut(addr) {
                Some(rec) => {
                    if rec.identity_hash_hex != observed_hex {
                        return Err(PeerStoreError::PinMismatch {
                            addr: addr.to_string(),
                            expected: rec.identity_hash_hex.clone(),
                            observed: observed_hex,
                        });
                    }
                    rec.last_seen_unix = now;
                    // Touch-only updates get persisted too — otherwise a
                    // crash loses the freshness signal. Cheap: single rewrite.
                    true
                }
                None => {
                    guard.insert(
                        addr.to_string(),
                        PinRecord {
                            identity_hash_hex: observed_hex,
                            first_seen_unix: now,
                            last_seen_unix: now,
                        },
                    );
                    true
                }
            }
        };

        if needs_persist {
            self.persist()?;
        }
        Ok(())
    }

    /// Drop a pin. Next contact with this address is TOFU again. Use this
    /// for intentional peer-identity rotation (e.g. a node rekeyed its
    /// long-term Dilithium3 identity).
    pub fn forget(&self, addr: &str) -> Result<(), PeerStoreError> {
        let removed = {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            guard.remove(addr).is_some()
        };
        if removed {
            self.persist()?;
        }
        Ok(())
    }

    /// Return a snapshot of `(addr, hex_hash)` pairs for admin / debug use.
    pub fn list(&self) -> Vec<(String, String)> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<_> = guard
            .iter()
            .map(|(k, v)| (k.clone(), v.identity_hash_hex.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Number of pinned peers.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn persist(&self) -> Result<(), PeerStoreError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };

        // Serialize under read lock — writers are already serialized by
        // the caller holding the write lock in `pin_or_verify` /
        // `forget`, so no TOCTOU on the map contents.
        let bytes = {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            serde_json::to_vec_pretty(&*guard)?
        };

        // Atomic swap via tmp + rename. If the node crashes mid-write
        // the old file is still intact.
        let tmp = tmp_sibling(path);
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn tofu_on_first_contact() {
        let store = PeerIdentityStore::in_memory();
        assert!(matches!(
            store.expectation_for("1.2.3.4:9473"),
            PeerExpectation::Tofu
        ));
    }

    #[test]
    fn pin_then_expect_pinned() {
        let store = PeerIdentityStore::in_memory();
        store.pin_or_verify("1.2.3.4:9473", hash(0xab)).unwrap();
        match store.expectation_for("1.2.3.4:9473") {
            PeerExpectation::Pinned(h) => assert_eq!(h, hash(0xab)),
            _ => panic!("expected Pinned"),
        }
    }

    #[test]
    fn verify_matching_is_ok() {
        let store = PeerIdentityStore::in_memory();
        store.pin_or_verify("peer:1", hash(0x11)).unwrap();
        // same hash again — must not error, must refresh last_seen
        store.pin_or_verify("peer:1", hash(0x11)).unwrap();
    }

    #[test]
    fn verify_mismatch_is_rejected() {
        let store = PeerIdentityStore::in_memory();
        store.pin_or_verify("peer:1", hash(0x11)).unwrap();
        let err = store.pin_or_verify("peer:1", hash(0x22)).unwrap_err();
        assert!(matches!(err, PeerStoreError::PinMismatch { .. }));
    }

    #[test]
    fn forget_clears_the_pin() {
        let store = PeerIdentityStore::in_memory();
        store.pin_or_verify("peer:1", hash(0x11)).unwrap();
        store.forget("peer:1").unwrap();
        assert!(matches!(
            store.expectation_for("peer:1"),
            PeerExpectation::Tofu
        ));
        // And now a new hash is accepted TOFU-style.
        store.pin_or_verify("peer:1", hash(0x99)).unwrap();
    }

    #[test]
    fn list_is_sorted_by_addr() {
        let store = PeerIdentityStore::in_memory();
        store.pin_or_verify("b:1", hash(0x02)).unwrap();
        store.pin_or_verify("a:1", hash(0x01)).unwrap();
        store.pin_or_verify("c:1", hash(0x03)).unwrap();
        let list = store.list();
        assert_eq!(list[0].0, "a:1");
        assert_eq!(list[1].0, "b:1");
        assert_eq!(list[2].0, "c:1");
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pins.json");

        {
            let store = PeerIdentityStore::open(&path).unwrap();
            store.pin_or_verify("peer:1", hash(0xaa)).unwrap();
            store.pin_or_verify("peer:2", hash(0xbb)).unwrap();
            assert_eq!(store.len(), 2);
        }

        // Reopen — pins must survive.
        let store = PeerIdentityStore::open(&path).unwrap();
        assert_eq!(store.len(), 2);
        match store.expectation_for("peer:1") {
            PeerExpectation::Pinned(h) => assert_eq!(h, hash(0xaa)),
            _ => panic!("lost peer:1 pin"),
        }
        match store.expectation_for("peer:2") {
            PeerExpectation::Pinned(h) => assert_eq!(h, hash(0xbb)),
            _ => panic!("lost peer:2 pin"),
        }
    }

    #[test]
    fn open_nonexistent_path_is_empty_ok() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = PeerIdentityStore::open(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn open_rejects_bad_hex() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(
            &path,
            r#"{"peer:1":{"identity_hash_hex":"zzzz","first_seen_unix":0,"last_seen_unix":0}}"#,
        )
        .unwrap();
        let err = PeerIdentityStore::open(&path).unwrap_err();
        assert!(matches!(err, PeerStoreError::Hex { .. }));
    }

    #[test]
    fn open_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.json");
        fs::write(
            &path,
            r#"{"peer:1":{"identity_hash_hex":"aabb","first_seen_unix":0,"last_seen_unix":0}}"#,
        )
        .unwrap();
        let err = PeerIdentityStore::open(&path).unwrap_err();
        assert!(matches!(err, PeerStoreError::BadHashLen { .. }));
    }

    #[test]
    fn persisted_mismatch_is_still_rejected_after_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pins.json");

        {
            let store = PeerIdentityStore::open(&path).unwrap();
            store.pin_or_verify("peer:1", hash(0x11)).unwrap();
        }

        let store = PeerIdentityStore::open(&path).unwrap();
        let err = store
            .pin_or_verify("peer:1", hash(0x22))
            .unwrap_err();
        assert!(matches!(err, PeerStoreError::PinMismatch { .. }));
    }

    // ────────────────────────────────────────────────────────────────────
    // Coverage tests on uncovered invariants.
    // Existing 11 tests cover state-machine paths (TOFU, pin, verify,
    // forget, persist round-trip, bad-hex, bad-len). They do NOT pin
    // EXACT Display prose (log-scraper grep), the #[from]/{#[source]}/flat
    // source-chain asymmetry across the 5 variants, Send+Sync auto-traits
    // required for async network use, hash-byte round-trip across all 256
    // values, lifecycle idempotency (forget-of-missing is no-op), or the
    // tmp_sibling/now_unix free helpers' invariants.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_peer_store_error_5_variant_exact_display_prose_pin() {
        // Each variant's Display prose is what an operator sees in logs.
        // A silent rewording breaks log scrapers; pin EXACT strings.
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "boom");
        let io_msg = io_err.to_string();
        assert_eq!(
            PeerStoreError::Io(io_err).to_string(),
            format!("io: {io_msg}"),
            "Io wrapper format must be 'io: <inner>'"
        );

        let serde_err = serde_json::from_str::<HashMap<String, PinRecord>>("not json").unwrap_err();
        let serde_msg = serde_err.to_string();
        assert_eq!(
            PeerStoreError::Serde(serde_err).to_string(),
            format!("serde_json: {serde_msg}"),
            "Serde wrapper format must be 'serde_json: <inner>'"
        );

        assert_eq!(
            PeerStoreError::PinMismatch {
                addr: "1.2.3.4:9473".into(),
                expected: "deadbeef".into(),
                observed: "cafebabe".into(),
            }
            .to_string(),
            "identity pin mismatch for 1.2.3.4:9473: expected deadbeef, observed cafebabe",
            "PinMismatch field rendering must be exact (addr, expected, observed)"
        );

        let hex_err = hex::decode("zzzz").unwrap_err();
        let hex_msg = hex_err.to_string();
        assert_eq!(
            PeerStoreError::Hex {
                addr: "peer:1".into(),
                source: hex_err,
            }
            .to_string(),
            format!("hex decode for addr peer:1: {hex_msg}"),
            "Hex format must surface addr + inner via #[source] field"
        );

        assert_eq!(
            PeerStoreError::BadHashLen {
                addr: "peer:2".into(),
                len: 8,
            }
            .to_string(),
            "invalid pinned hash length for peer:2: expected 32 bytes, got 8",
            "BadHashLen format must include addr + observed len"
        );
    }

    #[test]
    fn batch_b_peer_store_error_source_chain_from_source_flat_asymmetry() {
        // Io and Serde use #[from], Hex uses a named #[source] field, and
        // PinMismatch / BadHashLen are flat (no inner). Each has a
        // distinct source-chain contract that scrapers walking
        // std::error::Error::source() depend on. Pin all three classes.
        use std::error::Error;

        // #[from] class: source returns the inner error type.
        let io_err = PeerStoreError::Io(io::Error::other("inner-io"));
        let src = io_err.source().expect("Io must have source via #[from]");
        assert!(
            src.downcast_ref::<io::Error>().is_some(),
            "Io::source must downcast to io::Error"
        );

        let serde_err = serde_json::from_str::<HashMap<String, PinRecord>>("{").unwrap_err();
        let outer_serde = PeerStoreError::Serde(serde_err);
        let src = outer_serde.source().expect("Serde must have source via #[from]");
        assert!(
            src.downcast_ref::<serde_json::Error>().is_some(),
            "Serde::source must downcast to serde_json::Error"
        );

        // #[source] field class: source returns the named field's inner.
        let hex_err = hex::decode("nothex").unwrap_err();
        let outer_hex = PeerStoreError::Hex {
            addr: "peer".into(),
            source: hex_err,
        };
        let src = outer_hex.source().expect("Hex must have source via #[source]");
        assert!(
            src.downcast_ref::<hex::FromHexError>().is_some(),
            "Hex::source must downcast to hex::FromHexError (via #[source] attr)"
        );

        // Flat class: no inner error, source returns None.
        let pm = PeerStoreError::PinMismatch {
            addr: "x".into(),
            expected: "a".into(),
            observed: "b".into(),
        };
        assert!(
            pm.source().is_none(),
            "PinMismatch is flat — must NOT chain to a source"
        );
        let bl = PeerStoreError::BadHashLen {
            addr: "x".into(),
            len: 4,
        };
        assert!(
            bl.source().is_none(),
            "BadHashLen is flat — must NOT chain to a source"
        );
    }

    #[test]
    fn batch_b_peer_store_send_sync_static_and_debug_format_pin() {
        // PeerIdentityStore is reached from async network code (every
        // outbound dial calls expectation_for, every successful handshake
        // calls pin_or_verify). The Result<T, PeerStoreError> from those
        // calls crosses .await points — Send + Sync + 'static are required.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_static<T: 'static>() {}
        fn assert_error<T: std::error::Error>() {}

        assert_send::<PeerStoreError>();
        assert_sync::<PeerStoreError>();
        assert_static::<PeerStoreError>();
        assert_error::<PeerStoreError>();

        assert_send::<PeerIdentityStore>();
        assert_sync::<PeerIdentityStore>();
        assert_static::<PeerIdentityStore>();

        // Debug format for PeerIdentityStore is hand-rolled (line 86) so
        // it surfaces pinned_peers count instead of the raw HashMap. Pin
        // it: a future drop of the manual Debug impl back to #[derive]
        // would silently dump up to 10K records into logs.
        let store = PeerIdentityStore::in_memory();
        let dbg_empty = format!("{store:?}");
        assert!(
            dbg_empty.contains("PeerIdentityStore"),
            "Debug must start with type name; got {dbg_empty}"
        );
        assert!(
            dbg_empty.contains("path: None"),
            "in_memory store must show path: None; got {dbg_empty}"
        );
        assert!(
            dbg_empty.contains("pinned_peers: 0"),
            "empty store must show pinned_peers: 0; got {dbg_empty}"
        );
        // Negative: the hand-rolled Debug MUST NOT leak HashMap internals.
        assert!(
            !dbg_empty.contains("identity_hash_hex"),
            "Debug must NOT dump PinRecord fields (privacy + log-volume); got {dbg_empty}"
        );

        store.pin_or_verify("peer:1", hash(0x01)).unwrap();
        let dbg_one = format!("{store:?}");
        assert!(
            dbg_one.contains("pinned_peers: 1"),
            "after one pin, debug must show pinned_peers: 1; got {dbg_one}"
        );
    }

    #[test]
    fn batch_b_pin_lifecycle_hash_byte_roundtrip_and_idempotency_matrix() {
        // The existing tests pin individual states (TOFU, pin, mismatch).
        // This axis pins the full lifecycle as a state-machine matrix:
        //   Tofu → pin(h) → Pinned(h) → pin(h again) → Pinned(h)
        //                              → pin(h') → PinMismatch
        //                              → forget → Tofu → pin(h'') → Pinned(h'')
        // AND that every byte value 0..=255 round-trips through the hash
        // field exactly (no truncation, sign extension, hex case drift).
        let store = PeerIdentityStore::in_memory();

        // Forget on missing key is a no-op (returns Ok, len unchanged).
        // Existing tests never pin this — defends against a future change
        // that returns Err for missing keys, which would break callers
        // that defensively call forget() before pinning a new identity.
        assert_eq!(store.len(), 0);
        store.forget("never-pinned").unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());

        // Byte-exact round-trip across the full 0..=255 range. Each byte
        // value gets its own peer addr so collisions don't mask drops.
        for byte in 0u8..=255 {
            let addr = format!("peer:{byte:03}");
            let h = hash(byte);
            store.pin_or_verify(&addr, h).unwrap();
            match store.expectation_for(&addr) {
                PeerExpectation::Pinned(got) => {
                    assert_eq!(got, h,
                        "byte 0x{byte:02x} must round-trip through hex encode/decode losslessly");
                }
                PeerExpectation::Tofu => panic!("addr {addr} unexpectedly TOFU after pin"),
            }
        }
        assert_eq!(store.len(), 256, "256 distinct peers must be retained");
        assert!(!store.is_empty());

        // Idempotency: re-pin same addr with same hash must succeed and
        // NOT inflate count. This is the "touch updates last_seen" path.
        let before_len = store.len();
        store.pin_or_verify("peer:042", hash(0x2a)).unwrap();
        assert_eq!(store.len(), before_len, "idempotent pin must not grow store");

        // Mismatch on existing pin returns PinMismatch with EXACT field
        // values (addr verbatim, expected = stored hex, observed = new hex).
        let err = store.pin_or_verify("peer:042", hash(0xff)).unwrap_err();
        match err {
            PeerStoreError::PinMismatch { addr, expected, observed } => {
                assert_eq!(addr, "peer:042");
                assert_eq!(expected, hex::encode(hash(0x2a)));
                assert_eq!(observed, hex::encode(hash(0xff)));
                assert_eq!(expected.len(), 64, "32-byte hash must serialize as 64 hex chars");
                assert!(
                    expected.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())),
                    "hex must be lowercase"
                );
            }
            other => panic!("expected PinMismatch, got {other:?}"),
        }

        // Forget brings the addr back to TOFU, and a different hash is now accepted.
        store.forget("peer:042").unwrap();
        assert!(matches!(store.expectation_for("peer:042"), PeerExpectation::Tofu));
        store.pin_or_verify("peer:042", hash(0xff)).unwrap();
        match store.expectation_for("peer:042") {
            PeerExpectation::Pinned(got) => assert_eq!(got, hash(0xff)),
            _ => panic!("expected new Pinned after forget+pin"),
        }
    }

    #[test]
    fn batch_b_tmp_sibling_now_unix_helpers_and_in_memory_persist_noop() {
        // Internal helpers that no test currently exercises directly.
        // A regression in tmp_sibling would corrupt the atomic-swap
        // invariant (rename of .tmp must land in the same dir as the
        // original to be an atomic rename on POSIX). A regression in
        // now_unix would silently make every fresh pin look stale.

        // tmp_sibling appends ".tmp" — preserves directory + adds suffix.
        let p = PathBuf::from("/var/lib/elara/peers.json");
        let t = tmp_sibling(&p);
        assert_eq!(t, PathBuf::from("/var/lib/elara/peers.json.tmp"));
        // Same parent directory (atomic-rename invariant on same FS).
        assert_eq!(t.parent(), p.parent());

        let relative = PathBuf::from("pins.json");
        let t_rel = tmp_sibling(&relative);
        assert_eq!(t_rel, PathBuf::from("pins.json.tmp"));

        // Bare filename without extension still gets ".tmp" appended.
        let bare = PathBuf::from("/tmp/peers");
        let t_bare = tmp_sibling(&bare);
        assert_eq!(t_bare, PathBuf::from("/tmp/peers.tmp"));

        // Multi-extension: ".tmp" is APPENDED, not REPLACED.
        let multi = PathBuf::from("/tmp/peers.json.bak");
        let t_multi = tmp_sibling(&multi);
        assert_eq!(t_multi, PathBuf::from("/tmp/peers.json.bak.tmp"));

        // now_unix returns the current Unix-epoch seconds. Bound it: the
        // 2026 codebase floor (≥ 2024-01-01 = 1_704_067_200) and a far
        // upper cap (< year 2100 = 4_102_444_800) so a clock that returned
        // 0 (the unwrap_or fallback) or u64::MAX would trip this test.
        let now = now_unix();
        assert!(now >= 1_704_067_200,
            "now_unix returned {now}; clock must be past 2024-01-01");
        assert!(now < 4_102_444_800,
            "now_unix returned {now}; sanity ceiling is year 2100");

        // in_memory store's persist() is a true no-op even after mutation.
        // The path field is None, so the early-return in persist() (line
        // 246) skips all I/O. A regression that removed the early-return
        // would crash on every pin against an in_memory store, since
        // fs::write to a None path would have to panic or pick a default.
        let store = PeerIdentityStore::in_memory();
        // Many writes, no I/O — verified by absence of panic.
        for i in 0..50u8 {
            let addr = format!("ephemeral:{i}");
            store.pin_or_verify(&addr, hash(i)).unwrap();
        }
        assert_eq!(store.len(), 50);
        // forget also goes through persist() — must also be a no-op.
        for i in 0..50u8 {
            store.forget(&format!("ephemeral:{i}")).unwrap();
        }
        assert!(store.is_empty());

        // PinRecord serde shape pin: JSON field names are snake_case as
        // written (no rename attr → derive default uses the Rust field
        // identifier). A future #[serde(rename_all="camelCase")] would
        // silently break all persisted pin files.
        let rec = PinRecord {
            identity_hash_hex: "aa".repeat(32),
            first_seen_unix: 1_700_000_000,
            last_seen_unix: 1_700_000_001,
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"identity_hash_hex\""),
            "PinRecord JSON must use snake_case 'identity_hash_hex'; got {json}");
        assert!(json.contains("\"first_seen_unix\""),
            "PinRecord JSON must use snake_case 'first_seen_unix'; got {json}");
        assert!(json.contains("\"last_seen_unix\""),
            "PinRecord JSON must use snake_case 'last_seen_unix'; got {json}");
        // Round-trip
        let back: PinRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.identity_hash_hex, rec.identity_hash_hex);
        assert_eq!(back.first_seen_unix, 1_700_000_000);
        assert_eq!(back.last_seen_unix, 1_700_000_001);
    }

    #[test]
    fn poisoned_rwlock_recovers_without_cascading_panic() {
        use std::sync::Arc;
        let store = Arc::new(PeerIdentityStore::in_memory());
        let clone = Arc::clone(&store);
        // Poison the write lock by panicking while holding it.
        let _ = std::thread::spawn(move || {
            let _guard = clone.inner.write().unwrap();
            panic!("intentional poison");
        })
        .join();
        // All public methods must survive a poisoned lock.
        assert!(matches!(store.expectation_for("1.2.3.4:9473"), PeerExpectation::Tofu));
        assert_eq!(store.len(), 0);
        assert!(store.list().is_empty());
        store.pin_or_verify("1.2.3.4:9473", [0u8; 32]).unwrap();
        assert_eq!(store.len(), 1);
        store.forget("1.2.3.4:9473").unwrap();
        assert_eq!(store.len(), 0);
    }
}
