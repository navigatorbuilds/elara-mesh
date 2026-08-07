//! [`AccountClient`] — narrow PQ surface for accounts and external clients.

use std::sync::Arc;

use serde_json::Value;

use crate::errors::Result;
use crate::network::pq_client::PqNodeClient;
use crate::network::pq_transport::PeerIdentityStore;

/// Account-facing PQ client. Wraps a [`PqNodeClient`] with a deliberately
/// small surface area: the four verbs Protocol §11.18/§11.22/§11.23
/// enumerate as light-client/account endpoints, plus `submit_record` for
/// posting transactions.
///
/// Cheap to clone — keypair and pin store are held behind `Arc`s in the
/// underlying [`PqNodeClient`]. One [`AccountClient`] can fan out across
/// multiple peers concurrently; the connection pool inside
/// [`PqNodeClient`] handshakes once per peer and reuses the encrypted
/// stream for subsequent calls.
#[derive(Clone)]
pub struct AccountClient {
    inner: PqNodeClient,
}

impl AccountClient {
    /// Create a account client with caller-supplied identity. Use this when
    /// the account persists a Dilithium3 keypair across launches.
    pub fn with_keypair(
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
        pins: Arc<PeerIdentityStore>,
    ) -> Self {
        Self {
            inner: PqNodeClient::new(public_key, secret_key, pins),
        }
    }

    /// Create a account client with a freshly minted ephemeral keypair and
    /// an empty in-memory pin store. Suitable for short-lived account
    /// sessions where every peer is TOFU-pinned at first contact and the
    /// pin store is discarded on exit.
    pub fn ephemeral() -> Result<Self> {
        let kp = crate::crypto::pqc::dilithium3_keygen()?;
        let (pk, sk) = kp.into_parts();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        Ok(Self::with_keypair(pk, sk, pins))
    }

    /// Attach the network id (realm) stamped on record submissions. Required
    /// when the target node runs a non-default `network_id`, else writes are
    /// rejected with `network_mismatch`. Chains after a constructor:
    /// `AccountClient::ephemeral()?.with_network_id("my-realm")`.
    pub fn with_network_id(mut self, network_id: impl Into<String>) -> Self {
        self.inner = self.inner.with_network_id(network_id);
        self
    }

    /// Borrow the pin store. Wallets that want to inspect or persist the
    /// TOFU pins (e.g. show the user "you have talked to N peers") read
    /// them through this handle.
    pub fn pins(&self) -> &PeerIdentityStore {
        self.inner.pins()
    }

    /// Submit a wire-encoded record to a peer. `wire_bytes` is the
    /// result of [`crate::wire::encode_record`] (or whatever the account's
    /// record builder produces). Returns the JSON receipt the peer
    /// returns: `{"accepted": true, "record_id": "..."}` on success or
    /// `{"accepted": false, "reason": "..."}` on rejection.
    ///
    /// Network-level errors (peer unreachable, handshake failed, pin
    /// mismatch) propagate as [`crate::errors::ElaraError::Network`].
    pub async fn submit_record(
        &self,
        peer_addr: &str,
        wire_bytes: &[u8],
    ) -> Result<Value> {
        self.inner.submit_record(peer_addr, wire_bytes).await
    }

    /// Fetch a Merkle proof of an account's current balance + nonce.
    /// `identity_hex` is the 64-character hex SHA3-256 hash of the
    /// account's Dilithium3 public key (the same identity the account
    /// uses to sign records). Returned JSON includes `balance`, `nonce`,
    /// `merkle_root`, and the proof path — enough for the account to
    /// verify locally without trusting the peer.
    pub async fn account_proof(
        &self,
        peer_addr: &str,
        identity_hex: &str,
    ) -> Result<Value> {
        self.inner.account_proof(peer_addr, identity_hex).await
    }

    /// Poll seal progress for a previously submitted record. The peer
    /// returns: `{"sealed": bool, "epoch": u64, "attestations": u32,
    /// "quorum": u32}`. Wallets surface this as the "tx confirmation
    /// counter" UI.
    pub async fn seal_progress(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<Value> {
        self.inner.seal_progress(peer_addr, record_id).await
    }

    /// Fetch the activity summary for an identity. Protocol §11.23 — a
    /// rolling list of recent records that touched this identity (in,
    /// out, sealed/pending). Wallets render this as the transaction
    /// history feed.
    pub async fn activity(
        &self,
        peer_addr: &str,
        identity_hex: &str,
    ) -> Result<Value> {
        self.inner.get_activity(peer_addr, identity_hex).await
    }

    /// Fetch a cross-zone settlement proof bundle and verify it locally
    /// before returning. Convenience wrapper over the raw `xzone_bundle`
    /// PQ verb: deserialize, run [`XZoneTransferBundle::verify`], and
    /// only return `Ok` if the source-zone Merkle inclusion + 2/3
    /// finality quorum both check out.
    ///
    /// On success the account knows the lock is sealed and finalized in
    /// the source zone — i.e., the funds are atomically debited and the
    /// caller can safely treat the cross-zone transfer as committed
    /// from zone A's side. The destination-side claim (zone B credit)
    /// is NOT verified here; that's the account's separate concern.
    ///
    /// Errors propagate as [`crate::errors::ElaraError::Wire`] for
    /// proof failures and [`crate::errors::ElaraError::Network`] for
    /// peer-reach issues.
    pub async fn xzone_bundle_and_verify(
        &self,
        peer_addr: &str,
        transfer_id: &str,
    ) -> Result<crate::accounting::cross_zone::XZoneTransferBundle> {
        let raw = self.inner.xzone_bundle(peer_addr, transfer_id).await?;
        let bundle: crate::accounting::cross_zone::XZoneTransferBundle =
            serde_json::from_value(raw).map_err(|e| {
                crate::errors::ElaraError::Wire(format!(
                    "xzone bundle {transfer_id}: deserialize failed: {e}"
                ))
            })?;
        bundle.verify()?;
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::pq_transport::{status, PqListener, PqRequest, PqResponse, PqStream};

    /// Mint a fresh Dilithium3 identity for tests: returns
    /// `(pk, sk, identity_hash_hex)`.
    fn mint_identity() -> (Vec<u8>, Vec<u8>, String) {
        use sha3::{Digest, Sha3_256};
        let kp = crate::crypto::pqc::dilithium3_keygen().expect("keygen");
        let (pk, sk) = kp.into_parts();
        let mut hasher = Sha3_256::new();
        hasher.update(&pk);
        let id_hex = hex::encode(hasher.finalize());
        (pk, sk, id_hex)
    }

    /// Tiny mock server that answers exactly the four account verbs. Each
    /// reply embeds a method-specific marker so tests can prove the verb
    /// dispatched correctly.
    async fn wallet_verb_handler(mut stream: PqStream) {
        for _ in 0..8 {
            let req: PqRequest = match stream.recv_request().await {
                Ok(r) => r,
                Err(_) => return,
            };
            let resp = match req.method.as_str() {
                "submit_record" => PqResponse::ok(
                    serde_json::to_vec(&serde_json::json!({
                        "accepted": true,
                        "record_id": "abc123",
                        "echo_bytes": req.body.len(),
                    }))
                    .unwrap(),
                ),
                "account_proof" => {
                    let id = req
                        .headers
                        .get("identity")
                        .cloned()
                        .unwrap_or_default();
                    PqResponse::ok(
                        serde_json::to_vec(&serde_json::json!({
                            "verb": "account_proof",
                            "identity": id,
                            "balance": "1000",
                            "nonce": 7,
                            "merkle_root": "deadbeef",
                        }))
                        .unwrap(),
                    )
                }
                "seal_progress" => {
                    let rid = req
                        .headers
                        .get("record_id")
                        .cloned()
                        .unwrap_or_default();
                    PqResponse::ok(
                        serde_json::to_vec(&serde_json::json!({
                            "verb": "seal_progress",
                            "record_id": rid,
                            "sealed": false,
                            "attestations": 3,
                            "quorum": 7,
                        }))
                        .unwrap(),
                    )
                }
                "activity" => {
                    let id = req
                        .headers
                        .get("identity")
                        .cloned()
                        .unwrap_or_default();
                    PqResponse::ok(
                        serde_json::to_vec(&serde_json::json!({
                            "verb": "activity",
                            "identity": id,
                            "events": [],
                        }))
                        .unwrap(),
                    )
                }
                "xzone_bundle" => {
                    // Returns a syntactically valid bundle whose verify()
                    // will fail because the signer list is empty (a real
                    // committee needs ≥2/3 verified witnesses). This proves
                    // the SDK calls verify() and surfaces the error rather
                    // than blindly trusting the peer.
                    use crate::network::zone::ZoneId;
                    use crate::accounting::cross_zone::XZoneTransferBundle;
                    let tid = req
                        .headers
                        .get("transfer_id")
                        .cloned()
                        .unwrap_or_default();
                    let bundle = XZoneTransferBundle {
                        transfer_id: tid,
                        sender: "alice".into(),
                        recipient: "bob".into(),
                        amount: 100,
                        source_zone: ZoneId::new("a"),
                        dest_zone: ZoneId::new("b"),
                        lock_record_hash: [0u8; 32],
                        merkle_proof: Vec::new(),
                        source_merkle_root: [0u8; 32],
                        source_seal_epoch: 7,
                        source_committee_hash: [0u8; 32],
                        source_committee_size: 5,
                        source_seal_signers: Vec::new(),
                    };
                    PqResponse::ok(serde_json::to_vec(&bundle).unwrap())
                }
                _ => PqResponse::new(
                    status::NOT_FOUND,
                    format!("unknown verb {}", req.method).into_bytes(),
                ),
            };
            if stream.send_response(&resp).await.is_err() {
                return;
            }
        }
    }

    async fn start_wallet_server(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .expect("bind PqListener");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            for _ in 0..16 {
                let (stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(wallet_verb_handler(stream));
            }
        });
        addr
    }

    #[tokio::test]
    async fn ephemeral_constructor_mints_keypair_and_empty_pins() {
        let account = AccountClient::ephemeral().expect("ephemeral");
        assert!(account.pins().list().is_empty());
    }

    #[tokio::test]
    async fn submit_record_round_trip() {
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let receipt = account
            .submit_record(&addr.to_string(), b"hello-pq-account")
            .await
            .expect("submit_record");

        assert_eq!(receipt["accepted"], serde_json::json!(true));
        assert_eq!(receipt["record_id"], serde_json::json!("abc123"));
        assert_eq!(receipt["echo_bytes"], serde_json::json!(b"hello-pq-account".len()));
    }

    #[tokio::test]
    async fn account_proof_round_trip_passes_identity_header() {
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let proof = account
            .account_proof(&addr.to_string(), "deadbeefcafebabe")
            .await
            .expect("account_proof");

        assert_eq!(proof["verb"], serde_json::json!("account_proof"));
        assert_eq!(proof["identity"], serde_json::json!("deadbeefcafebabe"));
        assert_eq!(proof["balance"], serde_json::json!("1000"));
    }

    #[tokio::test]
    async fn seal_progress_round_trip_passes_record_id_header() {
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let progress = account
            .seal_progress(&addr.to_string(), "rec-xyz-1")
            .await
            .expect("seal_progress");

        assert_eq!(progress["verb"], serde_json::json!("seal_progress"));
        assert_eq!(progress["record_id"], serde_json::json!("rec-xyz-1"));
        assert_eq!(progress["sealed"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn activity_round_trip_passes_identity_header() {
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let activity = account
            .activity(&addr.to_string(), "abcd1234")
            .await
            .expect("activity");

        assert_eq!(activity["verb"], serde_json::json!("activity"));
        assert_eq!(activity["identity"], serde_json::json!("abcd1234"));
    }

    #[tokio::test]
    async fn first_call_pins_peer_via_tofu() {
        let (spk, ssk, server_id_hex) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let _ = account
            .activity(&addr.to_string(), "abcd1234")
            .await
            .expect("activity");

        let pins = account.pins().list();
        assert_eq!(pins.len(), 1, "exactly one peer pinned after first call");
        assert_eq!(pins[0].0, addr.to_string());
        assert_eq!(pins[0].1, server_id_hex, "pin matches server identity hash");
    }

    #[tokio::test]
    async fn shared_pin_store_visible_across_clones() {
        // AUDIT-10 Milestone C: accounts that fan out across services
        // should be able to clone the AccountClient and still observe a
        // single TOFU pin set.
        let (spk, ssk, server_id_hex) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let wallet_a = AccountClient::ephemeral().expect("ephemeral");
        let wallet_b = wallet_a.clone();

        let _ = wallet_a
            .activity(&addr.to_string(), "id-a")
            .await
            .expect("activity a");

        let pins_b = wallet_b.pins().list();
        assert_eq!(pins_b.len(), 1, "clone sees the pin established by sibling");
        assert_eq!(pins_b[0].1, server_id_hex);
    }

    #[tokio::test]
    async fn xzone_bundle_and_verify_surfaces_proof_failure() {
        // Mock server returns a syntactically valid bundle whose signer
        // list is empty — verify() must fail (quorum unmet) and the SDK
        // helper must propagate that failure rather than silently return
        // an unverified bundle.
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let account = AccountClient::ephemeral().expect("ephemeral");
        let err = account
            .xzone_bundle_and_verify(&addr.to_string(), "tx-stub")
            .await
            .expect_err("empty signers must fail verify");

        let msg = err.to_string();
        assert!(
            msg.contains("finality quorum failed") || msg.contains("merkle inclusion proof invalid"),
            "expected verify-side error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn with_keypair_uses_caller_supplied_identity() {
        // Persistence path: the account brings its own Dilithium3 keys.
        let (cpk, csk, _id) = mint_identity();
        let (spk, ssk, _server_id_hex) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let account = AccountClient::with_keypair(cpk, csk, pins.clone());

        let receipt = account
            .submit_record(&addr.to_string(), b"persistent-id")
            .await
            .expect("submit_record");
        assert_eq!(receipt["accepted"], serde_json::json!(true));
        // Pin store handed in is the same one the client uses.
        assert_eq!(pins.list().len(), 1);
    }

    // ─── account SDK wire-contract tests ───────────────────────────────────
    //
    // Five orthogonal axes pinning AUDIT-10 Milestone C contract surface
    // for the account-facing PQ SDK. Existing tests round-trip each verb
    // once; these tests pin:
    //   1. submit_record wire-framing length-passthrough across 0..4096 B,
    //   2. xzone_bundle_and_verify error prose contains transfer_id
    //      verbatim (log-scraper grep contract),
    //   3. xzone_bundle_and_verify dispatches "xzone_bundle" wire verb
    //      (NOT "xzone_bundle_and_verify") — helper name diverges from
    //      wire verb by design (local verify-after-fetch),
    //   4. TOFU pin store dedup invariant under repeated calls to the
    //      same peer (no unbounded growth),
    //   5. xzone_bundle_and_verify wraps serde shape-mismatch as
    //      ElaraError::Wire (NOT ::Json) per the explicit map_err at
    //      account.rs:133-137 — surfaces transfer_id + "deserialize failed:".
    //
    // The account SDK is the user-visible PQ surface; format strings and
    // verb names are an external contract that integrators grep against.

    /// Mock server that records the `req.method` of every received PqRequest
    /// into a shared Vec — lets a test prove the SDK dispatched a specific
    /// wire verb without trusting the response shape.
    async fn start_verb_recording_server(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
        observed: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> std::net::SocketAddr {
        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .expect("bind PqListener");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            for _ in 0..8 {
                let (mut stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let observed_inner = observed.clone();
                tokio::spawn(async move {
                    for _ in 0..4 {
                        let req: PqRequest = match stream.recv_request().await {
                            Ok(r) => r,
                            Err(_) => return,
                        };
                        observed_inner.lock().unwrap().push(req.method.clone());
                        // Echo back the empty-signer bundle so the SDK
                        // helper's verify() fails post-deserialize — the
                        // verb already landed, that's what the test reads.
                        use crate::network::zone::ZoneId;
                        use crate::accounting::cross_zone::XZoneTransferBundle;
                        let tid = req
                            .headers
                            .get("transfer_id")
                            .cloned()
                            .unwrap_or_default();
                        let bundle = XZoneTransferBundle {
                            transfer_id: tid,
                            sender: "alice".into(),
                            recipient: "bob".into(),
                            amount: 0,
                            source_zone: ZoneId::new("a"),
                            dest_zone: ZoneId::new("b"),
                            lock_record_hash: [0u8; 32],
                            merkle_proof: Vec::new(),
                            source_merkle_root: [0u8; 32],
                            source_seal_epoch: 0,
                            source_committee_hash: [0u8; 32],
                            source_committee_size: 1,
                            source_seal_signers: Vec::new(),
                        };
                        let resp = PqResponse::ok(serde_json::to_vec(&bundle).unwrap());
                        if stream.send_response(&resp).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Mock server that returns syntactically valid JSON that does NOT
    /// shape-match XZoneTransferBundle on every "xzone_bundle" request —
    /// used to exercise the helper's serde -> ElaraError::Wire wrapping.
    async fn start_malformed_bundle_server(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
    ) -> std::net::SocketAddr {
        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .expect("bind PqListener");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            for _ in 0..8 {
                let (mut stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    for _ in 0..4 {
                        let _req: PqRequest = match stream.recv_request().await {
                            Ok(r) => r,
                            Err(_) => return,
                        };
                        let resp = PqResponse::ok(
                            serde_json::to_vec(&serde_json::json!({
                                "unrelated": "field",
                                "not_a_bundle": true,
                            }))
                            .unwrap(),
                        );
                        if stream.send_response(&resp).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn batch_b_submit_record_byte_count_passthrough_size_sweep() {
        // Wire framing must preserve payload length byte-for-byte across a
        // size sweep. A regression that truncated, padded, or chunked
        // bytes would surface here as a mismatched `echo_bytes`.
        //
        // Sizes chosen to cross typical buffer boundaries: 0 (empty), 1
        // (single-byte edge), 128 (sub-KB), 1024 (1 KB), 4096 (page-aligned).
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;
        let account = AccountClient::ephemeral().expect("ephemeral");

        for size in [0usize, 1, 128, 1024, 4096] {
            let payload = vec![0xABu8; size];
            let receipt = account
                .submit_record(&addr.to_string(), &payload)
                .await
                .unwrap_or_else(|e| panic!("submit_record size={size}: {e}"));
            assert_eq!(
                receipt["echo_bytes"],
                serde_json::json!(size),
                "echo_bytes must equal payload.len() for size={size}"
            );
            assert_eq!(receipt["accepted"], serde_json::json!(true));
        }
    }

    #[tokio::test]
    async fn batch_b_xzone_bundle_and_verify_error_prefix_contains_transfer_id_verbatim() {
        // Error prose at account.rs map_err + cross_zone.rs verify() must
        // include the transfer_id literal verbatim AND the "xzone bundle"
        // prefix — log scrapers grep on the combined phrase to surface
        // failed bundles. A future format-string refactor that dropped
        // or escaped the transfer_id would break that pipeline silently.
        let (spk, ssk, _id) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;
        let account = AccountClient::ephemeral().expect("ephemeral");

        let sentinel_tid = "tid-sentinel-batch-b-42";
        let err = account
            .xzone_bundle_and_verify(&addr.to_string(), sentinel_tid)
            .await
            .expect_err("empty signers must fail verify");
        let msg = err.to_string();

        assert!(
            msg.contains(sentinel_tid),
            "error must contain transfer_id verbatim, got: {msg}"
        );
        assert!(
            msg.contains("xzone bundle"),
            "error must contain 'xzone bundle' prefix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn batch_b_xzone_bundle_and_verify_dispatches_xzone_bundle_wire_verb() {
        // Helper name diverges from wire verb by design — SDK call is
        // `xzone_bundle_and_verify` (local verify-after-fetch), wire verb
        // dispatched is "xzone_bundle". A refactor that aliased the wire
        // verb to the helper name would break existing PQ servers.
        let (spk, ssk, _id) = mint_identity();
        let observed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let addr = start_verb_recording_server(spk, ssk, observed.clone()).await;
        let account = AccountClient::ephemeral().expect("ephemeral");

        // Verify is expected to fail (empty signers); we only care that
        // the verb dispatched lands at the server.
        let _ = account
            .xzone_bundle_and_verify(&addr.to_string(), "tx-verb-check")
            .await;

        let v = observed.lock().unwrap();
        assert_eq!(v.len(), 1, "exactly one verb observed, got {v:?}");
        assert_eq!(
            v[0], "xzone_bundle",
            "wire verb must be 'xzone_bundle' (NOT 'xzone_bundle_and_verify')"
        );
    }

    #[tokio::test]
    async fn batch_b_tofu_pin_store_idempotent_under_repeat_calls() {
        // PeerIdentityStore must dedup repeated TOFU pin attempts against
        // the same peer. A regression that appended instead of upserted
        // would grow the store unbounded over a long-running account
        // session (memory leak + linear pin-lookup degradation).
        let (spk, ssk, server_id_hex) = mint_identity();
        let addr = start_wallet_server(spk, ssk).await;
        let account = AccountClient::ephemeral().expect("ephemeral");

        for _ in 0..5 {
            let _ = account
                .activity(&addr.to_string(), "idempotent-pin")
                .await
                .expect("activity");
        }

        let pins = account.pins().list();
        assert_eq!(
            pins.len(),
            1,
            "five activity() calls to same peer must yield exactly ONE pin entry, got {} entries: {pins:?}",
            pins.len()
        );
        assert_eq!(pins[0].1, server_id_hex, "pin matches server identity");
    }

    #[tokio::test]
    async fn batch_b_xzone_bundle_and_verify_wraps_serde_shape_mismatch_as_wire() {
        // Server returns syntactically valid JSON that does NOT shape-match
        // XZoneTransferBundle. The helper's explicit map_err at
        // account.rs:133-137 must wrap the serde error as ElaraError::Wire
        // (NOT ::Json), and the prose must include the literal transfer_id
        // + "deserialize failed:" substring — defends the log-triage
        // pipeline against operators having to grep two different error
        // surfaces for the same root cause.
        let (spk, ssk, _id) = mint_identity();
        let addr = start_malformed_bundle_server(spk, ssk).await;
        let account = AccountClient::ephemeral().expect("ephemeral");

        let sentinel_tid = "tid-malformed-22";
        let err = account
            .xzone_bundle_and_verify(&addr.to_string(), sentinel_tid)
            .await
            .expect_err("malformed bundle must fail deserialize");

        assert!(
            matches!(err, crate::errors::ElaraError::Wire(_)),
            "must surface ElaraError::Wire (NOT ::Json), got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains(sentinel_tid),
            "error must contain transfer_id verbatim, got: {msg}"
        );
        assert!(
            msg.contains("deserialize failed:"),
            "error must contain 'deserialize failed:' substring, got: {msg}"
        );
    }
}
