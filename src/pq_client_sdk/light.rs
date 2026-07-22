//! [`LightClient`] — read-only PQ surface for light clients verifying
//! account state without holding the chain.
//!
//! Companion to [`super::AccountClient`]. Where `AccountClient` is the
//! transaction-author surface (submit + poll), `LightClient` is the
//! verifier surface (fetch headers + proofs + verify locally).
//!
//! The headline API is [`LightClient::verify_account`]: one async call
//! that (1) fetches the latest epoch header for the target zone, (2)
//! fetches the account-state Merkle proof, (3) runs
//! [`crate::network::light::verify_account_proof_against_header`] to
//! confirm the proof root matches the header's signed
//! `account_smt_root`, and (4) returns the verified leaf state.
//!
//! Two-peer mode (header from peer A, proof from peer B) gives
//! cross-witness verification at the SDK layer — a single peer cannot
//! lie about both the header *and* a matching proof unless they're
//! colluding. For maximum simplicity the same peer can also serve both
//! sides; the choice is the integrator's.

use std::sync::Arc;

use serde_json::Value;

use crate::errors::{ElaraError, Result};
use crate::network::account_merkle::{
    parse_wire_exclusion, verify_exclusion_proof, AccountStateProof, MAX_DEPTH,
};
use crate::network::light::{verify_account_proof_against_header, EpochHeader};
use crate::network::pq_client::PqNodeClient;
use crate::network::pq_transport::PeerIdentityStore;

/// Verified account-state result returned by
/// [`LightClient::verify_account`]. Fields mirror the cryptographically
/// witnessed slice of `/proof/account/{id}` *after* binding to a signed
/// epoch header — every field below was confirmed against the header's
/// `account_smt_root`.
#[derive(Debug, Clone)]
pub struct VerifiedAccount {
    /// Hex identity hash queried.
    pub identity: String,
    /// True if the account exists in the SMT. False = verified
    /// non-existence (the empty-leaf path reconstructs the signed
    /// `account_smt_root`).
    pub exists: bool,
    /// Leaf hash — `SHA3-256(serialized AccountState)` from the proof.
    /// `None` when `exists == false`.
    pub state_hash: Option<[u8; 32]>,
    /// Header used as the trust anchor for verification.
    pub header: EpochHeader,
}

/// Light-client SDK handle. Cheap to clone (keypair + pin store live
/// behind `Arc`s in the underlying [`PqNodeClient`]).
#[derive(Clone)]
pub struct LightClient {
    inner: PqNodeClient,
}

impl LightClient {
    /// Build a light client with caller-supplied identity. Use this when
    /// the SDK consumer persists a Dilithium3 keypair across sessions
    /// (e.g. a long-running service).
    pub fn with_keypair(
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
        pins: Arc<PeerIdentityStore>,
    ) -> Self {
        Self {
            inner: PqNodeClient::new(public_key, secret_key, pins),
        }
    }

    /// Build a light client with a freshly minted ephemeral keypair and
    /// an empty in-memory pin store. Suitable for short-lived
    /// verification scripts and one-shot CLI lookups.
    pub fn ephemeral() -> Result<Self> {
        let kp = crate::crypto::pqc::dilithium3_keygen()?;
        let (pk, sk) = kp.into_parts();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        Ok(Self::with_keypair(pk, sk, pins))
    }

    /// Borrow the TOFU pin store. Persistent SDK consumers can snapshot
    /// the pin set on shutdown and restore it on startup so subsequent
    /// runs reject identity rotation.
    pub fn pins(&self) -> &PeerIdentityStore {
        self.inner.pins()
    }

    /// Pass-through to [`PqNodeClient::headers_from`]. Returns the raw
    /// `{total, headers: [...]}` JSON the peer serves.
    pub async fn headers_from(
        &self,
        peer_addr: &str,
        since: u64,
        zone: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Value> {
        self.inner.headers_from(peer_addr, since, zone, limit).await
    }

    /// Pass-through to [`PqNodeClient::account_proof`].
    pub async fn account_proof(
        &self,
        peer_addr: &str,
        identity_hex: &str,
    ) -> Result<Value> {
        self.inner.account_proof(peer_addr, identity_hex).await
    }

    /// Fetch the most recent verifiable header for `zone` from `peer`.
    /// Issues `headers_from(since=0, zone, limit=N)` and returns the
    /// header with the highest `epoch_number` whose
    /// `account_smt_root` is present. Pre-Gap-1 headers (no
    /// `account_smt_root`) are filtered out — they cannot anchor an
    /// account proof. Returns `Err` if the peer has no Gap-1+ headers
    /// for the zone.
    ///
    /// `limit` defaults to 16 — enough to skip a few legacy headers at
    /// the tail without paying the bandwidth of a full pull.
    pub async fn latest_header(
        &self,
        peer_addr: &str,
        zone: &str,
        limit: Option<usize>,
    ) -> Result<EpochHeader> {
        let body = self
            .inner
            .headers_from(peer_addr, 0, Some(zone), Some(limit.unwrap_or(16)))
            .await?;
        let arr = body
            .get("headers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ElaraError::Network(format!(
                    "headers_from: peer {peer_addr} returned no `headers` array"
                ))
            })?;
        let mut best: Option<EpochHeader> = None;
        for entry in arr {
            let Some(h) = parse_header_json(entry) else {
                continue;
            };
            if h.account_smt_root.is_none() {
                continue;
            }
            match &best {
                Some(prev) if prev.epoch_number >= h.epoch_number => {}
                _ => best = Some(h),
            }
        }
        best.ok_or_else(|| {
            ElaraError::Network(format!(
                "headers_from: peer {peer_addr} returned no Gap-1 headers \
                 (with account_smt_root) for zone {zone}"
            ))
        })
    }

    /// One-call verified balance lookup. Fetches the latest signed
    /// header for `zone` from `header_peer`, fetches the account proof
    /// from `proof_peer`, and verifies the proof root binds to the
    /// header's `account_smt_root` via
    /// [`verify_account_proof_against_header`].
    ///
    /// Pass the same string for both peers to verify against a single
    /// peer; pass two different peers for cross-witness verification.
    ///
    /// Returns [`VerifiedAccount`] on success. Returns
    /// [`ElaraError::Network`] when the peer's response is malformed,
    /// the proof doesn't verify against the header, or the header lacks
    /// an `account_smt_root` (pre-Gap-1).
    pub async fn verify_account(
        &self,
        header_peer: &str,
        proof_peer: &str,
        zone: &str,
        identity_hex: &str,
    ) -> Result<VerifiedAccount> {
        // Fetch proof first — it carries the seal binding (epoch_number +
        // zone + account_smt_root) that tells us which header anchors this
        // proof. The global account SMT has one root that advances at every
        // seal regardless of zone, so the caller-supplied `zone` only
        // selects which peer's header subset we query as a hint; the
        // authoritative anchor is the seal in the proof body. Pre-2026-04-29
        // this routine fetched the latest header for the caller's zone and
        // demanded its root match the proof — but the latest header in
        // zone X may pre-date the most recent zone-Y seal (zone-Y's flush
        // advanced the SMT past zone-X's last header), so the comparison
        // failed for any account whose home zone wasn't the one that just
        // sealed. Following the proof's own binding eliminates that race.
        let proof_body = self.account_proof(proof_peer, identity_hex).await?;

        let exists = proof_body
            .get("exists")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                ElaraError::Network(
                    "account_proof: missing or non-bool `exists` field".into(),
                )
            })?;

        // Pull the seal binding out of the proof. `latest_sealed_account`
        // tells us the (epoch, zone) of the seal whose `account_smt_root`
        // equals the on-disk SMT root the proof is anchored at.
        let header = self
            .fetch_header_for_proof_binding(header_peer, zone, &proof_body)
            .await?;

        if !exists {
            // Sound cryptographic non-membership. The server returns a
            // compressed exclusion proof; we (1) require it to be for THIS
            // identity, (2) require its root to equal the header's signed root,
            // and (3) fold it to confirm the empty leaf reaches that root. A
            // Byzantine server can no longer assert absence by echoing the
            // signed root — it must produce a fold, which is impossible for an
            // account that actually exists. (Pre-2026-06-16 this trusted the
            // bare root; see internal design notes.)
            let signed_root = header.account_smt_root.ok_or_else(|| {
                ElaraError::Network(
                    "header lacks account_smt_root — pre-Gap-1, cannot verify"
                        .into(),
                )
            })?;
            let expected_id = decode_hex32(identity_hex).ok_or_else(|| {
                ElaraError::Network(format!("invalid identity hex: {identity_hex}"))
            })?;
            let xproof = parse_wire_exclusion(&proof_body).map_err(|e| {
                ElaraError::Network(format!("account_proof: malformed exclusion proof: {e}"))
            })?;
            if xproof.account_id != expected_id {
                return Err(ElaraError::Network(
                    "account_proof: exclusion proof is for a different identity".into(),
                ));
            }
            if xproof.root != signed_root {
                return Err(ElaraError::Network(format!(
                    "account_proof: non-existence root {} ≠ header.account_smt_root {}",
                    hex::encode(xproof.root),
                    hex::encode(signed_root),
                )));
            }
            if !verify_exclusion_proof(&xproof) {
                return Err(ElaraError::Network(
                    "account_proof: exclusion proof did not fold to its root".into(),
                ));
            }
            return Ok(VerifiedAccount {
                identity: identity_hex.to_string(),
                exists: false,
                state_hash: None,
                header,
            });
        }

        // Inclusion proof: parse → verify against header.
        let proof = parse_account_proof(&proof_body, identity_hex)?;
        if !verify_account_proof_against_header(&proof, &header) {
            return Err(ElaraError::Network(format!(
                "account_proof for {identity_hex} did not verify \
                 against signed header (zone={zone}, epoch={})",
                header.epoch_number
            )));
        }
        Ok(VerifiedAccount {
            identity: identity_hex.to_string(),
            exists: true,
            state_hash: Some(proof.state_hash),
            header,
        })
    }

    /// Fetch the header that anchors a `compute_account_proof` response.
    ///
    /// Reads the `latest_sealed_account` field from `proof_body` to learn
    /// the exact `(zone, epoch)` of the seal whose `account_smt_root`
    /// matches the proof. Issues `headers_from(since=epoch, zone, limit=4)`
    /// against `header_peer` and returns the one whose `account_smt_root`
    /// matches the seal binding.
    ///
    /// Falls back to `latest_header(header_peer, zone, ...)` (pre-2026-04-29
    /// behavior) when the proof body doesn't carry a `latest_sealed_account`
    /// — e.g., responses from older nodes that haven't picked up the
    /// at-last-seal binding fix.
    async fn fetch_header_for_proof_binding(
        &self,
        header_peer: &str,
        fallback_zone: &str,
        proof_body: &Value,
    ) -> Result<EpochHeader> {
        let binding = proof_body
            .get("latest_sealed_account")
            .filter(|v| !v.is_null());
        let Some(binding) = binding else {
            return self.latest_header(header_peer, fallback_zone, None).await;
        };
        let epoch = binding
            .get("epoch_number")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                ElaraError::Network(
                    "latest_sealed_account.epoch_number missing or non-u64".into(),
                )
            })?;
        let bind_zone = binding
            .get("zone")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ElaraError::Network(
                    "latest_sealed_account.zone missing or non-string".into(),
                )
            })?;
        let want_root = binding
            .get("account_smt_root")
            .and_then(|v| v.as_str())
            .and_then(decode_hex32)
            .ok_or_else(|| {
                ElaraError::Network(
                    "latest_sealed_account.account_smt_root missing or malformed".into(),
                )
            })?;
        let body = self
            .inner
            .headers_from(header_peer, epoch, Some(bind_zone), Some(4))
            .await?;
        let arr = body
            .get("headers")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ElaraError::Network(format!(
                    "headers_from: peer {header_peer} returned no `headers` array"
                ))
            })?;
        for entry in arr {
            let Some(h) = parse_header_json(entry) else {
                continue;
            };
            if h.epoch_number != epoch {
                continue;
            }
            if h.account_smt_root != Some(want_root) {
                continue;
            }
            return Ok(h);
        }
        Err(ElaraError::Network(format!(
            "headers_from: peer {header_peer} has no header matching seal binding \
             (zone={bind_zone}, epoch={epoch}, root={})",
            hex::encode(want_root)
        )))
    }
}

// ─── JSON parsers ───────────────────────────────────────────────────────────

fn parse_header_json(v: &Value) -> Option<EpochHeader> {
    use crate::ZoneId;
    let zone_val = v.get("zone")?;
    let zone: ZoneId = if let Some(s) = zone_val.as_str() {
        ZoneId::new(s)
    } else if let Some(n) = zone_val.as_u64() {
        ZoneId::from_legacy(n)
    } else {
        return None;
    };
    let epoch_number = v.get("epoch_number")?.as_u64()?;
    let merkle_root = decode_hex32(v.get("merkle_root")?.as_str()?)?;
    let previous_seal_hash = decode_hex32(v.get("previous_seal_hash")?.as_str()?)?;
    let record_count = v.get("record_count")?.as_u64()?;
    let start = v.get("start")?.as_f64()?;
    let end = v.get("end")?.as_f64()?;
    let account_smt_root = v
        .get("account_smt_root")
        .and_then(|a| a.as_str())
        .and_then(decode_hex32);
    let seal_record_hash = v
        .get("seal_record_hash")
        .and_then(|a| a.as_str())
        .and_then(decode_hex32);
    Some(EpochHeader {
        zone,
        epoch_number,
        merkle_root,
        previous_seal_hash,
        record_count,
        start,
        end,
        account_smt_root,
        seal_record_hash,
    })
}

fn parse_account_proof(v: &Value, identity_hex: &str) -> Result<AccountStateProof> {
    let id_bytes = hex::decode(identity_hex).map_err(|_| {
        ElaraError::Network(format!("identity is not hex: {identity_hex}"))
    })?;
    if id_bytes.len() != 32 {
        return Err(ElaraError::Network(format!(
            "identity hex must decode to 32 bytes, got {}",
            id_bytes.len()
        )));
    }
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&id_bytes);

    let root = decode_hex32_field(v, "root")?;
    let state_hash = decode_hex32_field(v, "state_hash")?;
    let present = decode_hex32_field(v, "present")?;
    let siblings_arr = v
        .get("siblings")
        .and_then(|s| s.as_array())
        .ok_or_else(|| {
            ElaraError::Network("account_proof: missing siblings array".into())
        })?;
    // Compressed proof: each sibling is a 64-char hex hash (non-empty siblings
    // only; orientation/empties are recovered from `present` + the path).
    // siblings.len() <= MAX_DEPTH (256, one per `present` bit) for any valid
    // proof. Cap the peer-supplied length before allocating — else a malicious
    // node could amplify a few KB of wire into megabytes of client-side
    // pre-allocation (remote memory-amplification DoS).
    if siblings_arr.len() > MAX_DEPTH as usize {
        return Err(ElaraError::Network(format!(
            "account_proof: {} siblings exceeds SMT depth {MAX_DEPTH}",
            siblings_arr.len()
        )));
    }
    let mut siblings = Vec::with_capacity(siblings_arr.len());
    for entry in siblings_arr {
        let hash_hex = entry.as_str().ok_or_else(|| {
            ElaraError::Network("account_proof: sibling is not a hex string".into())
        })?;
        let hash = decode_hex32(hash_hex).ok_or_else(|| {
            ElaraError::Network(format!("account_proof: bad sibling hex {hash_hex}"))
        })?;
        siblings.push(hash);
    }
    Ok(AccountStateProof {
        account_id,
        state_hash,
        root,
        present,
        siblings,
    })
}

fn decode_hex32_field(v: &Value, field: &str) -> Result<[u8; 32]> {
    let s = v
        .get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            ElaraError::Network(format!("account_proof: missing field `{field}`"))
        })?;
    decode_hex32(s).ok_or_else(|| {
        ElaraError::Network(format!("account_proof: `{field}` is not 32-byte hex"))
    })
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_account_proof_rejects_oversized_siblings() {
        // Memory-amplification guard: a proof from a malicious node with more
        // siblings than the SMT depth (256) is rejected before pre-allocation.
        let h = "00".repeat(32);
        let id = "11".repeat(32);
        let body = serde_json::json!({
            "root": h, "state_hash": h, "present": h,
            "siblings": vec![serde_json::Value::Null; MAX_DEPTH as usize + 1],
        });
        let err = parse_account_proof(&body, &id).unwrap_err();
        assert!(
            format!("{err}").contains("exceeds SMT depth"),
            "expected depth-cap rejection, got: {err}"
        );
    }
    use crate::crypto::hash::sha3_256;
    use crate::network::account_merkle::{AccountStateSMT, hash_account_state};
    use crate::network::pq_transport::{
        status, PqListener, PqRequest, PqResponse, PqStream,
    };
    use crate::storage::rocks::StorageEngine;
    use crate::accounting::ledger::AccountState;
    use crate::ZoneId;
    use tempfile::TempDir;

    fn mint_identity() -> (Vec<u8>, Vec<u8>) {
        let kp = crate::crypto::pqc::dilithium3_keygen().expect("keygen");
        kp.into_parts()
    }

    /// Build a real SMT with one funded account so the proof we hand out
    /// is cryptographically genuine — the test verifies the SDK against
    /// the same logic that runs in production, not a hand-rolled stub.
    fn build_proof_for(
        identity_hex: &str,
        balance: u64,
    ) -> (AccountStateProof, [u8; 32], TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageEngine::open(dir.path()).expect("rocksdb");
        let id_bytes = hex::decode(identity_hex).expect("hex");
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&id_bytes);

        let account = AccountState {
            available: balance,
            ..Default::default()
        };
        let leaf = hash_account_state(&account);

        let mut smt = AccountStateSMT::new(&storage);
        smt.update(&account_id, &leaf).expect("update");
        smt.commit().expect("commit");

        let smt2 = AccountStateSMT::new(&storage);
        let root = smt2.root().expect("root");
        let proof = smt2
            .proof(&account_id)
            .expect("proof")
            .expect("proof some");
        (proof, root, dir)
    }

    fn header_with_root(
        zone: &str,
        epoch: u64,
        account_smt_root: [u8; 32],
    ) -> EpochHeader {
        let zone = ZoneId::new(zone);
        let seal_record_hash = sha3_256(format!("seal_{zone}_{epoch}").as_bytes());
        EpochHeader {
            zone,
            epoch_number: epoch,
            merkle_root: sha3_256(format!("mr_{epoch}").as_bytes()),
            previous_seal_hash: [0u8; 32],
            record_count: 1,
            start: epoch as f64 * 100.0,
            end: (epoch + 1) as f64 * 100.0,
            account_smt_root: Some(account_smt_root),
            seal_record_hash: Some(seal_record_hash),
        }
    }

    fn header_to_json(h: &EpochHeader) -> serde_json::Value {
        serde_json::json!({
            "zone": h.zone.to_string(),
            "epoch_number": h.epoch_number,
            "merkle_root": hex::encode(h.merkle_root),
            "previous_seal_hash": hex::encode(h.previous_seal_hash),
            "record_count": h.record_count,
            "start": h.start,
            "end": h.end,
            "account_smt_root": h.account_smt_root.map(hex::encode),
            "seal_record_hash": h.seal_record_hash.map(hex::encode),
        })
    }

    fn proof_to_json(
        proof: &AccountStateProof,
        identity: &str,
    ) -> serde_json::Value {
        let mut body = crate::network::account_merkle::proof_to_wire(proof);
        if let Some(o) = body.as_object_mut() {
            o.insert("identity".into(), serde_json::json!(identity));
            o.insert("exists".into(), serde_json::json!(true));
            o.insert("bound_to_seal".into(), serde_json::json!(true));
            o.insert("latest_sealed_account".into(), serde_json::Value::Null);
        }
        body
    }

    /// Test fixture: serves whatever JSON we hand it under whichever
    /// verb the request asks for.
    async fn fixture_handler(
        mut stream: PqStream,
        headers_body: serde_json::Value,
        proof_body: serde_json::Value,
    ) {
        for _ in 0..8 {
            let req: PqRequest = match stream.recv_request().await {
                Ok(r) => r,
                Err(_) => return,
            };
            let resp = match req.method.as_str() {
                "headers_from" => PqResponse::ok(
                    serde_json::to_vec(&headers_body).unwrap(),
                ),
                "account_proof" => PqResponse::ok(
                    serde_json::to_vec(&proof_body).unwrap(),
                ),
                other => PqResponse::new(
                    status::NOT_FOUND,
                    format!("unknown verb {other}").into_bytes(),
                ),
            };
            if stream.send_response(&resp).await.is_err() {
                return;
            }
        }
    }

    async fn start_fixture(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
        headers_body: serde_json::Value,
        proof_body: serde_json::Value,
    ) -> std::net::SocketAddr {
        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            for _ in 0..16 {
                let (stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let h = headers_body.clone();
                let p = proof_body.clone();
                tokio::spawn(fixture_handler(stream, h, p));
            }
        });
        addr
    }

    #[tokio::test]
    async fn ephemeral_constructor_mints_keypair_and_empty_pins() {
        let lc = LightClient::ephemeral().expect("ephemeral");
        assert!(lc.pins().list().is_empty());
    }

    #[tokio::test]
    async fn verify_account_happy_path_against_real_smt() {
        // Real SMT, real proof, real verify. Header carries the same
        // root the SMT produced; SDK must report `exists=true` and
        // surface the proof's state_hash unchanged.
        let identity = "11".repeat(32);
        let (proof, smt_root, _dir) = build_proof_for(&identity, 1_000_000);
        let header = header_with_root("0", 42, smt_root);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 1,
                "headers": [header_to_json(&header)],
            }),
            proof_to_json(&proof, &identity),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let v = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect("verify_account");

        assert!(v.exists);
        assert_eq!(v.identity, identity);
        assert_eq!(v.state_hash, Some(proof.state_hash));
        assert_eq!(v.header.epoch_number, 42);
        assert_eq!(v.header.account_smt_root, Some(smt_root));
    }

    #[tokio::test]
    async fn verify_account_rejects_root_mismatch() {
        // Proof binds to one root; header asserts a different root.
        // Even if both shapes parse cleanly, the cryptographic chain
        // must break and the SDK must surface a Network error.
        let identity = "22".repeat(32);
        let (proof, _real_root, _dir) = build_proof_for(&identity, 5_000);
        let mut tampered = [0u8; 32];
        tampered[0] = 0xFF;
        let header = header_with_root("0", 9, tampered);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 1,
                "headers": [header_to_json(&header)],
            }),
            proof_to_json(&proof, &identity),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let err = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect_err("must reject tampered root");
        match err {
            ElaraError::Network(msg) => assert!(
                msg.contains("did not verify"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_account_rejects_pre_gap1_header() {
        // Header without account_smt_root is pre-Gap-1 — latest_header
        // filters it out, so the SDK must report no usable headers
        // rather than silently downgrading to an unverifiable result.
        let identity = "33".repeat(32);
        let (proof, _root, _dir) = build_proof_for(&identity, 99);
        let mut header = header_with_root("0", 1, [0u8; 32]);
        header.account_smt_root = None;

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 1,
                "headers": [header_to_json(&header)],
            }),
            proof_to_json(&proof, &identity),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let err = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect_err("must reject pre-Gap-1");
        match err {
            ElaraError::Network(msg) => {
                assert!(msg.contains("Gap-1"), "unexpected error: {msg}");
            }
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_account_picks_highest_epoch_header() {
        // Peer returns three headers; SDK must pick the highest epoch
        // with an account_smt_root set.
        let identity = "44".repeat(32);
        let (proof, smt_root, _dir) = build_proof_for(&identity, 1);
        let h_old = header_with_root("0", 5, [0xAAu8; 32]);
        let h_new = header_with_root("0", 99, smt_root);
        let h_mid = header_with_root("0", 50, [0xBBu8; 32]);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 3,
                "headers": [
                    header_to_json(&h_old),
                    header_to_json(&h_new),
                    header_to_json(&h_mid),
                ],
            }),
            proof_to_json(&proof, &identity),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let v = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect("verify");
        assert_eq!(v.header.epoch_number, 99);
    }

    /// Build a proof_body JSON with a non-null `latest_sealed_account`
    /// binding. Tests for `fetch_header_for_proof_binding` use this to
    /// drive the SDK down the binding-aware path instead of the
    /// fallback `latest_header` path used by `proof_to_json`.
    fn proof_to_json_with_binding(
        proof: &AccountStateProof,
        identity: &str,
        bind_zone: &str,
        bind_epoch: u64,
        bind_root: [u8; 32],
    ) -> serde_json::Value {
        let mut body = crate::network::account_merkle::proof_to_wire(proof);
        if let Some(o) = body.as_object_mut() {
            o.insert("identity".into(), serde_json::json!(identity));
            o.insert("exists".into(), serde_json::json!(true));
            o.insert("bound_to_seal".into(), serde_json::json!(true));
            o.insert("live_state_matches_sealed".into(), serde_json::json!(true));
            o.insert(
                "latest_sealed_account".into(),
                serde_json::json!({
                    "epoch_number": bind_epoch,
                    "zone": bind_zone,
                    "seal_id": "test-seal",
                    "account_smt_root": hex::encode(bind_root),
                    "sealed_at": 12345,
                    "matches_proof_root": true,
                }),
            );
        }
        body
    }

    #[tokio::test]
    async fn verify_account_uses_proof_binding_to_pick_matching_header() {
        // Peer returns 3 candidate headers — only one has the
        // (epoch, account_smt_root) pair the proof's binding points
        // at. The SDK MUST pick that one even though another header
        // has a higher epoch number.
        //
        // Real-world scenario this guards against: the global SMT
        // root advances at every seal across any zone, so the latest
        // header in the caller-supplied zone may pre-date the most
        // recent (other-zone) seal that the proof anchors at. Pre-fix
        // SDK called `latest_header(zone)` and always picked the
        // highest-epoch header in that zone — which had a STALE
        // `account_smt_root` relative to the proof, breaking
        // verification.
        let identity = "55".repeat(32);
        let (proof, smt_root, _dir) = build_proof_for(&identity, 7_777);
        // Header 1 — wrong root, lower epoch.
        let h_old = header_with_root("0", 5, [0xAAu8; 32]);
        // Header 2 — correct (epoch, root), middle position.
        let h_match = header_with_root("0", 42, smt_root);
        // Header 3 — wrong root, HIGHER epoch (would be picked by
        // latest_header).
        let h_new = header_with_root("0", 99, [0xBBu8; 32]);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 3,
                "headers": [
                    header_to_json(&h_old),
                    header_to_json(&h_match),
                    header_to_json(&h_new),
                ],
            }),
            proof_to_json_with_binding(&proof, &identity, "0", 42, smt_root),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let v = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect("verify_account");

        assert!(v.exists);
        assert_eq!(
            v.header.epoch_number, 42,
            "SDK must pick header by proof binding, not latest epoch",
        );
        assert_eq!(v.header.account_smt_root, Some(smt_root));
    }

    #[tokio::test]
    async fn verify_account_errors_when_binding_has_no_matching_header() {
        // Proof binding declares (epoch=77, root=R), but the peer's
        // header set has neither. SDK must surface a descriptive
        // error rather than silently picking a wrong header.
        let identity = "66".repeat(32);
        let (proof, smt_root, _dir) = build_proof_for(&identity, 1);
        let h_wrong_epoch = header_with_root("0", 1, smt_root);
        let h_wrong_root = header_with_root("0", 77, [0xDDu8; 32]);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 2,
                "headers": [
                    header_to_json(&h_wrong_epoch),
                    header_to_json(&h_wrong_root),
                ],
            }),
            proof_to_json_with_binding(&proof, &identity, "0", 77, smt_root),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let peer = addr.to_string();
        let err = lc
            .verify_account(&peer, &peer, "0", &identity)
            .await
            .expect_err("must error: no header matches binding");
        match err {
            ElaraError::Network(msg) => assert!(
                msg.contains("seal binding") || msg.contains("matching"),
                "expected binding-mismatch error, got: {msg}"
            ),
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_account_falls_back_to_latest_header_when_binding_absent() {
        // proof_to_json sets `latest_sealed_account: null` — this is
        // what older nodes (pre-2026-04-29) return. SDK must fall
        // back to the legacy latest_header(zone) path so a network
        // mid-rollout still verifies. This reuses the
        // `verify_account_happy_path_against_real_smt` setup but
        // pins the fallback explicitly.
        let identity = "77".repeat(32);
        let (proof, smt_root, _dir) = build_proof_for(&identity, 333);
        let header = header_with_root("0", 1, smt_root);

        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 1,
                "headers": [header_to_json(&header)],
            }),
            proof_to_json(&proof, &identity), // null binding
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let v = lc
            .verify_account(&addr.to_string(), &addr.to_string(), "0", &identity)
            .await
            .expect("verify_account");
        assert!(v.exists);
        assert_eq!(v.header.epoch_number, 1);
    }

    #[tokio::test]
    async fn latest_header_errors_when_no_gap1_headers_present() {
        // All headers are pre-Gap-1. latest_header must return an error
        // so callers don't accidentally try to verify against a header
        // that can't anchor an account proof.
        let mut h = header_with_root("0", 1, [0u8; 32]);
        h.account_smt_root = None;
        let (spk, ssk) = mint_identity();
        let addr = start_fixture(
            spk,
            ssk,
            serde_json::json!({
                "total": 1,
                "headers": [header_to_json(&h)],
            }),
            serde_json::json!({}),
        )
        .await;

        let lc = LightClient::ephemeral().expect("ephemeral");
        let err = lc
            .latest_header(&addr.to_string(), "0", None)
            .await
            .expect_err("must error");
        match err {
            ElaraError::Network(msg) => assert!(
                msg.contains("no Gap-1 headers"),
                "unexpected error: {msg}"
            ),
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    #[test]
    fn batch_b_decode_hex32_accepts_64_hex_chars_and_returns_none_for_off_length_or_invalid_chars() {
        // Happy path: 64 hex chars (32 bytes) → Some.
        let zeros = decode_hex32(&"00".repeat(32)).expect("all-zeros decodes");
        assert_eq!(zeros, [0u8; 32]);
        let ffs = decode_hex32(&"ff".repeat(32)).expect("all-ffs decodes");
        assert_eq!(ffs, [0xffu8; 32]);
        // Mixed-case hex must work (Rust hex crate accepts both).
        assert!(decode_hex32(&"aB".repeat(32)).is_some(),
            "mixed-case hex must decode");

        // Wrong length: 31 bytes (62 chars) → None.
        assert!(decode_hex32(&"00".repeat(31)).is_none(),
            "31-byte hex must reject (decode_hex32 demands exactly 32)");
        // Wrong length: 33 bytes (66 chars) → None.
        assert!(decode_hex32(&"00".repeat(33)).is_none(),
            "33-byte hex must reject");
        // Empty string → None.
        assert!(decode_hex32("").is_none(),
            "empty string must reject");
        // Non-hex character → None.
        assert!(decode_hex32(&"zz".repeat(32)).is_none(),
            "non-hex chars must reject (hex::decode fails)");
        // Odd-length hex → hex::decode fails → None.
        assert!(decode_hex32("abc").is_none(),
            "odd-length hex must reject");
    }

    #[test]
    fn batch_b_decode_hex32_field_propagates_field_name_in_error_message_for_missing_or_malformed_field() {
        // Missing field → error message contains the field name verbatim.
        let v = serde_json::json!({"present": "00".repeat(32)});
        let err = decode_hex32_field(&v, "absent").expect_err("missing field must error");
        match &err {
            ElaraError::Network(msg) => {
                assert!(msg.contains("absent"),
                    "error must surface the field name 'absent': got {:?}", msg);
                assert!(msg.contains("missing"),
                    "error must say 'missing': got {:?}", msg);
            }
            other => panic!("expected Network error, got {other:?}"),
        }

        // Field present but is a number (not a string) → also "missing" branch
        // (as_str returns None for non-string JSON nodes).
        let v_num = serde_json::json!({"f": 12345});
        let err_num = decode_hex32_field(&v_num, "f").expect_err("non-string field must error");
        assert!(matches!(err_num, ElaraError::Network(_)));

        // Field present, is a string, but not 32-byte hex → distinct error path.
        let v_bad = serde_json::json!({"f": "deadbeef"});  // 4 bytes, not 32
        let err_bad = decode_hex32_field(&v_bad, "f").expect_err("short hex must error");
        match &err_bad {
            ElaraError::Network(msg) => {
                assert!(msg.contains("f"),
                    "error must surface the field name 'f': got {:?}", msg);
                assert!(msg.contains("32-byte hex"),
                    "error must call out the 32-byte hex requirement: got {:?}", msg);
            }
            other => panic!("expected Network error, got {other:?}"),
        }
    }

    #[test]
    fn batch_b_parse_header_json_returns_some_for_complete_header_and_none_when_required_field_missing() {
        // Build a complete header JSON and round-trip through parse_header_json.
        let h = header_with_root("hil", 42, [0xaa; 32]);
        let v = header_to_json(&h);
        let parsed = parse_header_json(&v).expect("complete header must parse");
        assert_eq!(parsed.epoch_number, 42);
        assert_eq!(parsed.record_count, 1);
        assert_eq!(parsed.account_smt_root, Some([0xaa; 32]));
        assert!(parsed.seal_record_hash.is_some(),
            "seal_record_hash present in test fixture must round-trip");

        // Zone alternative: u64 path (legacy numeric zone id).
        let mut v_numeric = v.clone();
        v_numeric["zone"] = serde_json::json!(7u64);
        assert!(parse_header_json(&v_numeric).is_some(),
            "numeric zone id must parse via ZoneId::from_legacy fallback");

        // Optional fields absent: account_smt_root + seal_record_hash both None.
        let mut v_no_opts = v.clone();
        v_no_opts.as_object_mut().unwrap().remove("account_smt_root");
        v_no_opts.as_object_mut().unwrap().remove("seal_record_hash");
        let parsed_no_opts = parse_header_json(&v_no_opts)
            .expect("missing optional fields must still parse");
        assert_eq!(parsed_no_opts.account_smt_root, None);
        assert_eq!(parsed_no_opts.seal_record_hash, None);

        // Required field removal → None. Pin each separately.
        for required in &[
            "zone", "epoch_number", "merkle_root", "previous_seal_hash",
            "record_count", "start", "end",
        ] {
            let mut bad = v.clone();
            bad.as_object_mut().unwrap().remove(*required);
            assert!(parse_header_json(&bad).is_none(),
                "removing required field {:?} must yield None", required);
        }
    }

    #[test]
    fn batch_b_parse_account_proof_preserves_compressed_siblings_order() {
        // Compressed proof: siblings are hex hashes (no is_right) + a `present`
        // bitmap. parse_account_proof must preserve insertion order verbatim —
        // order is load-bearing for the fold.
        let identity = "11".repeat(32);
        let siblings_json = serde_json::json!([
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
        ]);
        let mut present = [0u8; 32];
        present[0] = 0xE0; // bits 0,1,2 set → 3 siblings
        let v = serde_json::json!({
            "identity": identity,
            "exists": true,
            "root": "dd".repeat(32),
            "state_hash": "ee".repeat(32),
            "present": hex::encode(present),
            "siblings": siblings_json,
            "bound_to_seal": true,
        });
        let proof = parse_account_proof(&v, &identity).expect("complete proof must parse");
        assert_eq!(proof.root, [0xddu8; 32]);
        assert_eq!(proof.state_hash, [0xeeu8; 32]);
        assert_eq!(proof.account_id, [0x11u8; 32]);
        assert_eq!(proof.present[0], 0xE0);
        assert_eq!(proof.siblings.len(), 3);
        // Order-preserving: index 0 = aa, 1 = bb, 2 = cc.
        assert_eq!(proof.siblings[0], [0xaau8; 32]);
        assert_eq!(proof.siblings[1], [0xbbu8; 32]);
        assert_eq!(proof.siblings[2], [0xccu8; 32]);
    }

    #[test]
    fn batch_b_parse_account_proof_rejects_non_hex_identity_wrong_length_id_and_missing_siblings_array() {
        let good_id = "22".repeat(32);
        let base = serde_json::json!({
            "root": "00".repeat(32),
            "state_hash": "00".repeat(32),
            "present": "00".repeat(32),
            "siblings": [],
        });

        // (1) Identity is not hex → "not hex" error.
        let err_not_hex = parse_account_proof(&base, "ZZ".repeat(32).as_str())
            .expect_err("non-hex identity must error");
        match &err_not_hex {
            ElaraError::Network(msg) => assert!(msg.contains("not hex"),
                "expected 'not hex' in: {:?}", msg),
            other => panic!("expected Network, got {other:?}"),
        }

        // (2) Identity is hex but wrong length (16 bytes instead of 32) → length error.
        let short_id = "33".repeat(16);
        let err_short = parse_account_proof(&base, &short_id)
            .expect_err("short identity must error");
        match &err_short {
            ElaraError::Network(msg) => {
                assert!(msg.contains("32 bytes"),
                    "expected '32 bytes' in: {:?}", msg);
                assert!(msg.contains("16"),
                    "expected actual byte count 16 in: {:?}", msg);
            }
            other => panic!("expected Network, got {other:?}"),
        }

        // (3) Valid identity but `siblings` array missing entirely.
        let mut no_siblings = base.clone();
        no_siblings.as_object_mut().unwrap().remove("siblings");
        let err_no_sibs = parse_account_proof(&no_siblings, &good_id)
            .expect_err("missing siblings must error");
        match &err_no_sibs {
            ElaraError::Network(msg) => assert!(msg.contains("siblings array"),
                "expected 'siblings array' phrase in: {:?}", msg),
            other => panic!("expected Network, got {other:?}"),
        }

        // (4) Sibling entry is not a hex string (compressed format: siblings are
        //     bare hex hashes, not {hash,is_right} objects).
        let bad_sib = serde_json::json!({
            "root": "00".repeat(32),
            "state_hash": "00".repeat(32),
            "present": "00".repeat(32),
            "siblings": [{"hash": "ff".repeat(32)}],  // object, not a hex string
        });
        let err_bad_sib = parse_account_proof(&bad_sib, &good_id)
            .expect_err("non-string sibling must error");
        match &err_bad_sib {
            ElaraError::Network(msg) => assert!(msg.contains("hex string"),
                "expected 'hex string' in: {:?}", msg),
            other => panic!("expected Network, got {other:?}"),
        }

        // (5) Missing `present` bitmap → error.
        let mut no_present = base.clone();
        no_present.as_object_mut().unwrap().remove("present");
        let err_no_present = parse_account_proof(&no_present, &good_id)
            .expect_err("missing present must error");
        match &err_no_present {
            ElaraError::Network(msg) => assert!(msg.contains("present"),
                "expected 'present' in: {:?}", msg),
            other => panic!("expected Network, got {other:?}"),
        }
    }

    // ── Empirical fail-closed fuzz sweep over the SDK light-client JSON-Value
    // parsers. `parse_header_json` / `parse_account_proof` are the EXTERNAL-
    // facing analogues of the node-side `account_merkle` / `light` checkpoint
    // parsers swept in `src/decoder_fuzz.rs`: a third-party light client built
    // on this SDK feeds them header / proof JSON served by a possibly-malicious
    // node, so a panic is a remotely-triggered DoS on the integrator's client.
    // Both are fail-closed by inspection (every field `?`/`ok_or`-guarded; the
    // `[u8;32]` fields route through `decode_hex32`, which checks `len != 32`
    // before `copy_from_slice`; `siblings` is `MAX_DEPTH`-capped before
    // `Vec::with_capacity`) — but none of that is enforced by the prod-panic
    // scan, so a future edit could silently drop a guard. This deterministic
    // (splitmix64-seeded, replayable) sweep is the regression guard. Self-
    // contained — no `proptest`/`rand` dep on a soon-public tree, mirroring the
    // `decoder_fuzz` approach.

    struct SweepRng(u64);
    impl SweepRng {
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

    fn sweep_rand_hex(rng: &mut SweepRng, bytes: usize) -> String {
        let mut s = String::with_capacity(bytes * 2);
        for _ in 0..bytes {
            s.push_str(&format!("{:02x}", (rng.next_u64() & 0xff) as u8));
        }
        s
    }

    /// A hex-string field: valid-32 / wrong-length-hex / non-hex / wrong-type —
    /// the inputs `decode_hex32` / `decode_hex32_field` branch on.
    fn sweep_hex_field(rng: &mut SweepRng) -> serde_json::Value {
        use serde_json::Value;
        match rng.below(6) {
            0 => Value::String(sweep_rand_hex(rng, 32)),
            1 => {
                let n = rng.below(64);
                Value::String(sweep_rand_hex(rng, n))
            }
            2 => Value::String("nothex_zz".into()),
            3 => Value::Number(rng.next_u64().into()),
            4 => Value::Bool(true),
            _ => Value::Null,
        }
    }

    /// A numeric field (`epoch_number` / `record_count` / `start` / `end`):
    /// valid number / string-encoded / wrong-type.
    fn sweep_num_field(rng: &mut SweepRng) -> serde_json::Value {
        use serde_json::Value;
        match rng.below(5) {
            0 => Value::Number(rng.below(4096).into()),
            1 => Value::Number(rng.next_u64().into()),
            2 => Value::String("123".into()),
            3 => Value::Bool(false),
            _ => Value::Null,
        }
    }

    /// A `zone` field hitting all three branches of `parse_header_json`'s zone
    /// decode: string / legacy-u64 / wrong-type.
    fn sweep_zone_field(rng: &mut SweepRng) -> serde_json::Value {
        use serde_json::Value;
        match rng.below(4) {
            0 => Value::String("1/2/3".into()),
            1 => Value::Number(rng.next_u64().into()),
            2 => Value::Bool(true),
            _ => Value::Null,
        }
    }

    /// A `siblings` array whose length straddles the `MAX_DEPTH` cap so both the
    /// accept and the reject-before-alloc branch are exercised.
    fn sweep_siblings(rng: &mut SweepRng) -> serde_json::Value {
        let n = match rng.below(4) {
            0 => rng.below(MAX_DEPTH as usize + 1),    // within cap
            1 => MAX_DEPTH as usize + 1 + rng.below(32), // just over → reject
            2 => 0,
            _ => rng.below(8),
        };
        let mut arr = Vec::with_capacity(n);
        for _ in 0..n {
            arr.push(sweep_hex_field(rng));
        }
        serde_json::Value::Array(arr)
    }

    fn sweep_header_body(rng: &mut SweepRng) -> serde_json::Value {
        use serde_json::Value;
        if rng.below(8) == 0 {
            return match rng.below(3) {
                0 => Value::Null,
                1 => Value::Array(vec![sweep_hex_field(rng)]),
                _ => Value::String(sweep_rand_hex(rng, 8)),
            };
        }
        let mut m = serde_json::Map::new();
        for (key, mk) in [
            ("zone", 0u8),
            ("epoch_number", 1),
            ("merkle_root", 2),
            ("previous_seal_hash", 2),
            ("record_count", 1),
            ("start", 1),
            ("end", 1),
            ("account_smt_root", 2),
            ("seal_record_hash", 2),
        ] {
            if rng.next_u64() & 1 == 0 {
                let v = match mk {
                    0 => sweep_zone_field(rng),
                    1 => sweep_num_field(rng),
                    _ => sweep_hex_field(rng),
                };
                m.insert(key.to_string(), v);
            }
        }
        Value::Object(m)
    }

    fn sweep_proof_body(rng: &mut SweepRng) -> serde_json::Value {
        use serde_json::Value;
        if rng.below(8) == 0 {
            return match rng.below(3) {
                0 => Value::Null,
                1 => Value::Array(vec![sweep_hex_field(rng)]),
                _ => Value::Bool(true),
            };
        }
        let mut m = serde_json::Map::new();
        for key in ["root", "state_hash", "present"] {
            if rng.next_u64() & 1 == 0 {
                m.insert(key.to_string(), sweep_hex_field(rng));
            }
        }
        if rng.next_u64() & 1 == 0 {
            m.insert("siblings".to_string(), sweep_siblings(rng));
        }
        Value::Object(m)
    }

    /// The separate `identity_hex: &str` arg `parse_account_proof` decodes
    /// (`hex::decode` + `len != 32` + `copy_from_slice`): valid-32 / wrong-
    /// length / non-hex / empty.
    fn sweep_identity_hex(rng: &mut SweepRng) -> String {
        match rng.below(4) {
            0 => sweep_rand_hex(rng, 32),
            1 => {
                let n = rng.below(40);
                sweep_rand_hex(rng, n)
            }
            2 => "zz".repeat(16),
            _ => String::new(),
        }
    }

    #[test]
    fn fuzz_sdk_light_json_parsers_are_fail_closed() {
        const SWEEP_ITERS: usize = 20_000;
        let seed = 0xE1A2_5D01u64;
        let mut rng = SweepRng(seed);
        for i in 0..SWEEP_ITERS {
            let hdr = sweep_header_body(&mut rng);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_header_json(&hdr);
            }));
            assert!(
                r.is_ok(),
                "parse_header_json PANICKED — not fail-closed. seed={seed:#x} iter={i} body={hdr}",
            );

            let body = sweep_proof_body(&mut rng);
            let id = sweep_identity_hex(&mut rng);
            let r2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_account_proof(&body, &id);
            }));
            assert!(
                r2.is_ok(),
                "parse_account_proof PANICKED — not fail-closed. seed={seed:#x} iter={i} id={id} body={body}",
            );
        }
    }
}
