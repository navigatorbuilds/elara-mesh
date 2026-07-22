//! elara-verify — offline Elara record + anchor verifier (READ-SIDE-STRATEGY
//! §1, thin slice).
//!
//! Single file in, plain-language verdict out. No node, no network, no
//! trust in us.
//!
//! **Record mode** (`<record>`) verifies, in order:
//!   1. **structure** — parses as a `ValidationRecord` (JSON, or wire with `--wire`)
//!   2. **binding** — the creator public key hashes (SHA3-256) to the claimed identity
//!   3. **signature** — Dilithium3 (ML-DSA-65), plus SPHINCS+ (SLH-DSA) for Profile A
//!   4. **content** — with `--content <file>`, SHA3-256 of your artifact == content hash
//!
//! **Anchor mode** (`--anchor <epoch-anchor.json>`) verifies the Bitcoin-anchored
//! time bracket around the seal, both legs, fully offline (each leg is trustless
//! only when it is cryptographically anchored — see below; otherwise a reference):
//!   - **NOT-BEFORE** — the artifact references a drand round whose publication
//!     time is fixed by the beacon's `genesis + period`, indicating the seal was
//!     created no earlier (lower bound). When the artifact carries the beacon's
//!     BLS signature it is verified against the PINNED League-of-Entropy key and
//!     the bound is trustless; signature-less (legacy) artifacts stay a reference.
//!   - **EXISTED-BY** — the `.ots` proof is a SHA-256 path from the artifact's
//!     hash into a Bitcoin block's merkle root; we walk it and confirm it lands
//!     on the merkle root of a block header archived next to the artifact. That
//!     header is the upper bound's trust root, so it must itself be authenticated:
//!     when its double-SHA256 matches a block hash PINNED in this verifier the
//!     bound is trustless; otherwise (no pin for that height) it is a REFERENCE
//!     bound whose strength rests on the operator-supplied header's authenticity —
//!     this offline tool cannot validate an arbitrary Bitcoin header (no PoW chain
//!     to a checkpoint), so it says so rather than implying a bound it cannot show.
//!     A still-pending or un-archived proof likewise says exactly that.
//!
//! **Seal mode** (`--seal <wire> --trusted-anchor <pubkey-hex>`) verifies a
//! fetched epoch-seal record is authentically signed by a caller-pinned anchor
//! key (the audited `light_verify::verify_seal_record_against_anchor` closure):
//! anchor membership + Dilithium3, plus an optional `--expected-hash` to pin
//! the seal's identity to a header you already trust.
//!
//! **Inclusion mode** (`--inclusion <proof.json>`) verifies a record-inclusion
//! proof (the `/zone/{zone}/proof/{record_hash}` payload): the record's hash is
//! a leaf under a zone's sparse-Merkle root, walked offline with sha3-256. With
//! `--expect-root <hex>` the proven root is bound to a sealed root you trust —
//! chaining record → seal → (via --seal + --anchor) a Bitcoin-anchored window.
//!
//! At least one of `<record>` / `--anchor` / `--seal` / `--inclusion` is
//! required; any may be combined.
//!
//! Exit codes: 0 = VERIFIED, 1 = verification FAILED, 2 = cannot read or
//! parse an input at all.
//!
//! Spec references:
//!   @spec docs/READ-SIDE-STRATEGY.md §1
//!   The drand round→time formula mirrors `src/network/time_bracket.rs`
//!   (§1045, `DrandPulse::not_before_unix`); it is reproduced here so the
//!   verifier stays standalone — the `network` module is `node-core`-gated and
//!   the whole point of this binary is "no node stack."

use std::process::ExitCode;

// The CLI driver, every helper, and all checks live in `elara_verify::cli` /
// the `elara-verify` crate root since extraction Step 4b — `main` is a thin
// delegate, byte-identical in behavior to the crate's own `elara-verify` bin
// (`cargo build --release --features verify-cli --bin elara-verify` keeps
// producing it from this repo unchanged, which release.yml and the docs rely
// on). Everything imported below exists for the `#[cfg(test)]` mods (which do
// `use super::*`): the fixtures sign live records/seals with node-side
// `Identity`, so they stay in this repo — the crate remains signing-incapable.
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use clap::Parser;
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use sha2::{Digest, Sha256};

#[allow(unused_imports)]
use elara_runtime::crypto::hash::sha3_256;
#[allow(unused_imports)]
use elara_runtime::crypto::pqc::dilithium3_verify;
#[allow(unused_imports)]
use elara_runtime::receipt;
#[allow(unused_imports)]
use elara_runtime::record::ValidationRecord;
#[allow(unused_imports)]
use elara_runtime::verify_core::{
    self, account_absence_time_bracketed, account_chain_time_bracketed, bind_account_chain,
    bind_chain, chain_is_account_absence_bound, chain_is_account_bound, chain_is_bound,
    hash32_from_hex, hash32_from_json, seal_committed_roots, st, AccountExclusionFacts,
    AccountInclusionFacts, AnchorSummary, Check, InclusionFacts, RecordSummary, Status, Verdict,
};
#[allow(unused_imports)]
use elara_runtime::verify_core::anchor::{
    drand_derive_randomness as derive_randomness, drand_not_before, drand_not_before_leg,
    existed_by_leg_from_bytes, flexible_u64, format_utc, ots_bitcoin_attestations,
    pinned_btc_hash, read_varbytes, read_varint, seal_drand_leg, verify_anchor_obj,
    verify_drand_bls, DrandBls, DrandLegOutcome, HeaderLoad, PulseSubject, LOE_DEFAULT_CHAIN_HASH,
    LOE_DEFAULT_GENESIS_UNIX, LOE_DEFAULT_PERIOD_SECS, LOE_DEFAULT_PUBKEY_HEX, OTS_BITCOIN_TAG,
    OTS_MAX_OPS,
};
#[allow(unused_imports)]
use elara_runtime::verify_core::grade::{
    bind_outcomes, grade_receipt_v1, record_leg, ContentArtifact, LegOutcomes, ReceiptDisplay,
    TrustPins,
};
// The driver + helpers (verify_seal, verify_inclusion, load_btc_header,
// emit_json/emit_prose, verdict_exit, …) — glob so `use super::*` in the test
// mods resolves them exactly as it did when they were file-level items here.
#[allow(unused_imports)]
use elara_verify::cli::*;

fn main() -> ExitCode {
    elara_verify::cli::run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use elara_runtime::crypto::pqc::dilithium3_sign_with_pk;
    use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
    use elara_runtime::record::Classification;

    pub(crate) fn signed_record(content: &[u8]) -> (ValidationRecord, Identity) {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let mut rec = ValidationRecord::create(
            content,
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        rec.signature = Some(
            dilithium3_sign_with_pk(&rec.signable_bytes(), &id.secret_key_bytes(), &id.public_key)
                .expect("sign"),
        );
        (rec, id)
    }

    /// A signed seal-shaped record committing `account_root` as its typed
    /// `epoch_account_smt_root` (metadata is inside `signable_bytes`, so the
    /// signature vouches for it). Returns (wire bytes, anchor pubkey hex,
    /// record hash hex) — the receipt/seal test fixtures pin all three.
    pub(crate) fn seal_committing(account_root: [u8; 32]) -> (Vec<u8>, String, String) {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let mut seal = ValidationRecord::create(
            b"epoch seal",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        seal.metadata.insert(
            "epoch_account_smt_root".into(),
            serde_json::json!(hex::encode(account_root)),
        );
        seal.signature = Some(
            dilithium3_sign_with_pk(&seal.signable_bytes(), &id.secret_key_bytes(), &id.public_key)
                .expect("sign"),
        );
        let hash_hex = hex::encode(seal.record_hash());
        (seal.to_bytes(), hex::encode(&id.public_key), hash_hex)
    }

    #[test]
    fn verifier_core_checks_pass_and_fail_correctly() {
        let (rec, _id) = signed_record(b"the artifact");

        // Valid signature verifies over canonical bytes.
        let signable = rec.signable_bytes();
        assert!(dilithium3_verify(
            &signable,
            rec.signature.as_ref().unwrap(),
            &rec.creator_public_key,
        )
        .unwrap());

        // A single flipped metadata bit must break verification — the
        // signable bytes are canonical over content.
        let mut tampered = rec.clone();
        tampered
            .metadata
            .insert("injected".into(), serde_json::json!(true));
        assert!(!dilithium3_verify(
            &tampered.signable_bytes(),
            tampered.signature.as_ref().unwrap(),
            &tampered.creator_public_key,
        )
        .unwrap());

        // Content binding: right artifact matches, wrong artifact doesn't.
        assert_eq!(sha3_256(b"the artifact").to_vec(), rec.content_hash);
        assert_ne!(sha3_256(b"a forgery").to_vec(), rec.content_hash);

        // JSON round-trip preserves verifiability (the verifier's default
        // input format).
        let json = serde_json::to_string(&rec).unwrap();
        let back: ValidationRecord = serde_json::from_str(&json).unwrap();
        assert!(dilithium3_verify(
            &back.signable_bytes(),
            back.signature.as_ref().unwrap(),
            &back.creator_public_key,
        )
        .unwrap());
    }

    #[test]
    fn format_utc_renders_known_instants() {
        assert_eq!(format_utc(0.0), "1970-01-01 00:00:00");
        // 2026-06-13 00:00:00 UTC == 1781308800.
        assert_eq!(format_utc(1_781_308_800.0), "2026-06-13 00:00:00");
        assert!(format_utc(-5.0).contains("unparseable"));
    }

    #[test]
    fn drand_not_before_matches_verified_formula() {
        // Round 1 is emitted exactly at genesis.
        assert_eq!(
            drand_not_before(1, LOE_DEFAULT_GENESIS_UNIX, LOE_DEFAULT_PERIOD_SECS),
            LOE_DEFAULT_GENESIS_UNIX
        );
        // Each round adds one period; round 0 clamps to round 1's time.
        assert_eq!(
            drand_not_before(2, LOE_DEFAULT_GENESIS_UNIX, LOE_DEFAULT_PERIOD_SECS),
            LOE_DEFAULT_GENESIS_UNIX + LOE_DEFAULT_PERIOD_SECS
        );
        assert_eq!(
            drand_not_before(0, LOE_DEFAULT_GENESIS_UNIX, LOE_DEFAULT_PERIOD_SECS),
            LOE_DEFAULT_GENESIS_UNIX
        );
    }

    #[test]
    fn live_anchor_round_maps_to_its_stamped_time() {
        // The real sidecar artifact epoch-14 cites drand round 6192366 and was
        // stamped 2026-06-11T18:20:03 UTC. The not-before must land at that
        // round's deterministic publication minute (18:20:00) — proving the
        // round genuinely brackets the stamp from below.
        let nb = drand_not_before(6_192_366, LOE_DEFAULT_GENESIS_UNIX, LOE_DEFAULT_PERIOD_SECS);
        assert_eq!(format_utc(nb as f64), "2026-06-11 18:20:00");
    }

    #[test]
    fn anchor_verify_self_describing_and_legacy() {
        // Self-describing artifact (carries its own genesis/period) — not a fallback.
        let self_desc = serde_json::json!({
            "epoch": 14,
            "seal_hash": "2ac41d55c0c1e344665e98e085703e2cd8dc6128144b1dec1e0a877520f902ef",
            "drand_round": 6_192_366u64,
            "drand_genesis_unix": LOE_DEFAULT_GENESIS_UNIX,
            "drand_period_secs": LOE_DEFAULT_PERIOD_SECS,
            "drand_chain_hash": LOE_DEFAULT_CHAIN_HASH,
        });
        let p = std::env::temp_dir().join("elara_verify_test_self.json");
        std::fs::write(&p, serde_json::to_vec(&self_desc).unwrap()).unwrap();
        let mut checks = Vec::new();
        let s = verify_anchor(&p, &mut checks).expect("anchor parses");
        assert!(!s.assumed_default_beacon, "self-describing must not fall back");
        assert_eq!(s.not_before_unix, Some(1_781_202_000));
        // No drand_signature on this self-describing artifact → reference-only,
        // now PARTIAL (not a green Pass): the round→time arithmetic holds but the
        // beacon BLS signature was never verified, so it is not a trustless bound.
        assert!(checks
            .iter()
            .any(|c| c.name == "drand not-before" && c.status == Status::Partial));
        let _ = std::fs::remove_file(&p);

        // Legacy artifact (round-only, string-encoded) — must fall back + flag it.
        let legacy = serde_json::json!({
            "epoch": 14,
            "seal_hash": "2ac41d55c0c1e344665e98e085703e2cd8dc6128144b1dec1e0a877520f902ef",
            "drand_round": "6192366",
        });
        let p2 = std::env::temp_dir().join("elara_verify_test_legacy.json");
        std::fs::write(&p2, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let mut checks2 = Vec::new();
        let s2 = verify_anchor(&p2, &mut checks2).expect("legacy anchor parses");
        assert!(s2.assumed_default_beacon, "legacy must fall back to LoE default");
        assert_eq!(s2.not_before_unix, Some(1_781_202_000));
        let _ = std::fs::remove_file(&p2);

        // Not an anchor artifact at all → exit 2.
        let p3 = std::env::temp_dir().join("elara_verify_test_notanchor.json");
        std::fs::write(&p3, b"{\"hello\":\"world\"}").unwrap();
        let mut checks3 = Vec::new();
        assert!(verify_anchor(&p3, &mut checks3).is_err());
        let _ = std::fs::remove_file(&p3);
    }

    // ── OpenTimestamps EXISTED-BY leg ───────────────────────────────────

    /// Minimal OTS base-128 varint encoder (prod only decodes).
    fn enc_varint(mut v: u64) -> Vec<u8> {
        let mut out = vec![];
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        out
    }

    fn ots_header(file_sha256: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"\x00OpenTimestamps\x00\x00Proof\x00");
        p.extend_from_slice(&[0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
        p.push(0x01); // version varint
        p.push(0x08); // file op: sha256
        p.extend_from_slice(file_sha256);
        p
    }

    fn bitcoin_attestation(height: u64) -> Vec<u8> {
        let mut a = vec![0x00];
        a.extend_from_slice(&OTS_BITCOIN_TAG);
        let h = enc_varint(height);
        a.extend_from_slice(&enc_varint(h.len() as u64)); // varbytes length
        a.extend_from_slice(&h);
        a
    }

    #[test]
    fn ots_varint_roundtrips_including_multibyte() {
        for v in [0u64, 1, 127, 128, 16_384, 953_350, u32::MAX as u64] {
            let bytes = enc_varint(v);
            let mut pos = 0;
            assert_eq!(read_varint(&bytes, &mut pos), Some(v), "decode {v}");
            assert_eq!(pos, bytes.len(), "consumed all bytes for {v}");
        }
    }

    #[test]
    fn ots_walk_reaches_bitcoin_root_and_rejects_wrong_file() {
        let file = b"hello anchor";
        let d0 = Sha256::digest(file);
        let operand = [0xAAu8, 0xBB, 0xCC];
        // expected committed root = sha256(d0 || operand)
        let mut pre = d0.to_vec();
        pre.extend_from_slice(&operand);
        let expected_root = Sha256::digest(&pre);
        let height = 953_350u64;

        let mut proof = ots_header(&d0);
        proof.push(0xf0); // append
        proof.extend_from_slice(&enc_varint(operand.len() as u64));
        proof.extend_from_slice(&operand);
        proof.push(0x08); // sha256
        proof.extend_from_slice(&bitcoin_attestation(height));

        let mut d0arr = [0u8; 32];
        d0arr.copy_from_slice(&d0);
        let atts = ots_bitcoin_attestations(&proof, &d0arr).expect("parses");
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].height, height);
        assert_eq!(&atts[0].merkle_root[..], &expected_root[..]);

        // A proof whose file digest != the artifact's must be rejected.
        let mut wrong = [0u8; 32];
        wrong.copy_from_slice(&Sha256::digest(b"a different file"));
        assert!(ots_bitcoin_attestations(&proof, &wrong).is_err());

        // Garbage magic → Err.
        assert!(ots_bitcoin_attestations(b"not a proof", &d0arr).is_err());
    }

    #[test]
    fn ots_fork_branch_is_walked() {
        // At the file digest, fork: branch A = a pending attestation (ignored),
        // last branch = sha256 -> Bitcoin attestation. The 0xff path must still
        // reach the Bitcoin leaf.
        let d0 = Sha256::digest(b"forked");
        let expected_root = Sha256::digest(&d0);

        let mut proof = ots_header(&d0);
        proof.push(0xff); // fork: another branch follows
        // branch A: pending attestation (tag + a 1-byte uri payload)
        proof.push(0x00);
        proof.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        proof.extend_from_slice(&enc_varint(1));
        proof.push(b'x');
        // last branch: sha256 -> Bitcoin
        proof.push(0x08);
        proof.extend_from_slice(&bitcoin_attestation(700_000));

        let mut d0arr = [0u8; 32];
        d0arr.copy_from_slice(&d0);
        let atts = ots_bitcoin_attestations(&proof, &d0arr).expect("parses fork");
        assert_eq!(atts.len(), 1, "pending branch ignored, bitcoin branch found");
        assert_eq!(atts[0].height, 700_000);
        assert_eq!(&atts[0].merkle_root[..], &expected_root[..]);
    }

    #[test]
    fn btc_header_reads_raw_merkle_and_blocktime() {
        // Build an 80-byte header: merkle field (bytes 36..68) + time (68..72).
        // The OTS walk arrives at the merkle root in the header's STORED order,
        // so load_btc_header must return bytes 36..68 raw (no reversal).
        let mut raw = vec![0u8; 80];
        let merkle: Vec<u8> = (0u8..32).collect();
        raw[36..68].copy_from_slice(&merkle);
        raw[68..72].copy_from_slice(&1_781_259_049u32.to_le_bytes());
        let hexhdr = hex::encode(&raw);

        let dir = std::env::temp_dir();
        let p = dir.join("btc-header-999001.txt");
        std::fs::write(&p, format!("height: 999001\nblockstream_header: {hexhdr}\n")).unwrap();

        let (root, ts) = match load_btc_header(&dir, 999_001) {
            HeaderLoad::Found(root, ts, _) => (root, ts),
            HeaderLoad::Absent => panic!("header should be present"),
            HeaderLoad::Broken(why) => panic!("header should parse, got broken: {why}"),
        };
        assert_eq!(&root[..], &merkle[..], "merkle root returned in raw stored order");
        assert_eq!(ts, 1_781_259_049);
        let _ = std::fs::remove_file(&p);

        // Tri-state: a genuinely missing file is ABSENT (→ PARTIAL); a present-
        // but-unparseable one is BROKEN (→ FAIL). They must never collapse —
        // that conflation was the existed-by fail-open.
        assert!(matches!(load_btc_header(&dir, 999_002), HeaderLoad::Absent));
        let bad = dir.join("btc-header-999003.txt");
        std::fs::write(&bad, "blockstream_header: ZZZZ_not_hex\n").unwrap();
        assert!(matches!(load_btc_header(&dir, 999_003), HeaderLoad::Broken(_)));
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn btc_header_pin_authenticates_genuine_953657_and_rejects_tamper() {
        // SECURITY REGRESSION (honest-claims): the verifier pins block 953657 (the
        // examples/verify/ demo anchor). A genuine header double-SHA256s to the pin
        // → existed-by stays a TRUSTLESS Pass; a substituted header for that height
        // does NOT match the pin → the Fail path. An unpinned height has no pin →
        // reference-only (Partial), never a trustless Pass on an unauthenticated
        // operator-supplied header.
        let genuine = "00000028d6dd81d8e4e158338a1de94ed18b5b4c62c1acbda4eb01000000000000000000109b5d57e387613c229a0f629f3bda594ad75e0099d347c9759988d49ab94dba2dda2e6ac34002175a507ddc";
        let pin = pinned_btc_hash(953_657).expect("953657 must be pinned");

        let dir = std::env::temp_dir().join("elara_verify_pin_test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("btc-header-953657.txt");

        std::fs::write(&p, format!("height: 953657\nblockstream_header: {genuine}\n")).unwrap();
        if let HeaderLoad::Found(_, _, block_hash) = load_btc_header(&dir, 953_657) {
            assert_eq!(block_hash, pin, "genuine header must double-SHA256 to the pin");
        } else {
            panic!("genuine header should load as Found");
        }

        // Flip the nonce's last byte → a different 80-byte header whose double-
        // SHA256 must NOT equal the pin (the operator-substitution the pin catches).
        let mut raw = hex::decode(genuine).unwrap();
        raw[79] ^= 0x01;
        std::fs::write(&p, format!("height: 953657\nblockstream_header: {}\n", hex::encode(&raw)))
            .unwrap();
        if let HeaderLoad::Found(_, _, block_hash) = load_btc_header(&dir, 953_657) {
            assert_ne!(block_hash, pin, "tampered header must NOT match the pin");
        } else {
            panic!("tampered header should still load as Found");
        }
        let _ = std::fs::remove_file(&p);

        assert!(pinned_btc_hash(999_999).is_none(), "unpinned height has no pin");
    }

    #[test]
    fn seal_anchor_accepts_pinned_rejects_unknown_and_wrong_hash() {
        // A seal record signed by an anchor key. --seal must accept it when that
        // key is pinned, and reject an unpinned anchor or a wrong expected-hash.
        let (rec, anchor) = signed_record(b"epoch seal payload");
        let wire = rec.to_bytes();
        let dir = std::env::temp_dir();
        let p = dir.join("elara_verify_test_seal.wire");
        std::fs::write(&p, &wire).unwrap();
        let anchor_hex = hex::encode(&anchor.public_key);

        // Pinned anchor + correct --expected-hash → Pass (identity bound).
        let mut checks_pin = Vec::new();
        let good_hash = hex::encode(rec.record_hash());
        verify_seal(&p, &[anchor_hex.clone()], Some(&good_hash), &mut checks_pin).expect("runs");
        assert!(
            checks_pin.iter().any(|c| c.name == "seal anchor" && c.status == Status::Pass),
            "pinned anchor + matching expected-hash accepted"
        );

        // Pinned anchor but NO --expected-hash → PARTIAL, not Pass: the seal is
        // signed by a trusted anchor, but its identity is bound to nothing (the
        // record_hash check was a tautology). A green ✓ here was the fail-open.
        let mut checks = Vec::new();
        verify_seal(&p, &[anchor_hex.clone()], None, &mut checks).expect("runs");
        assert!(
            checks.iter().any(|c| c.name == "seal anchor" && c.status == Status::Partial),
            "unpinned (no --expected-hash) seal is PARTIAL, never a green Pass"
        );
        assert!(
            !checks.iter().any(|c| c.name == "seal anchor" && c.status == Status::Pass),
            "unpinned seal must NOT report Pass"
        );

        // A different (unpinned) key → fail (UntrustedAnchor).
        let (_other_rec, other) = signed_record(b"unrelated");
        let mut checks2 = Vec::new();
        verify_seal(&p, &[hex::encode(&other.public_key)], None, &mut checks2).expect("runs");
        assert!(
            checks2.iter().any(|c| c.name == "seal anchor" && c.status == Status::Fail),
            "unpinned anchor rejected"
        );

        // Wrong --expected-hash → fail (RecordHashMismatch).
        let mut checks3 = Vec::new();
        let wrong_hash = hex::encode([0u8; 32]);
        verify_seal(&p, &[anchor_hex], Some(&wrong_hash), &mut checks3).expect("runs");
        assert!(
            checks3.iter().any(|c| c.name == "seal anchor" && c.status == Status::Fail),
            "wrong expected-hash rejected"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn inclusion_walk_matches_merkle_verify_proof() {
        // Build a 2-level proof with the SAME combine logic as
        // network::merkle::verify_proof (is_right ⇒ current‖sib, else sib‖current),
        // compute the root forward, and confirm verify_inclusion reproduces it.
        let leaf = sha3_256(b"a record");
        let sib0 = sha3_256(b"sibling 0"); // is_right = true → combined = leaf‖sib0
        let mut c = [0u8; 64];
        c[..32].copy_from_slice(&leaf);
        c[32..].copy_from_slice(&sib0);
        let lvl1 = sha3_256(&c);
        let sib1 = sha3_256(b"sibling 1"); // is_right = false → combined = sib1‖lvl1
        let mut c2 = [0u8; 64];
        c2[..32].copy_from_slice(&sib1);
        c2[32..].copy_from_slice(&lvl1);
        let root = sha3_256(&c2);

        let proof = serde_json::json!({
            "zone": 0,
            "leaf": hex::encode(leaf),
            "root": hex::encode(root),
            "siblings": [
                {"hash": hex::encode(sib0), "is_right": true},
                {"hash": hex::encode(sib1), "is_right": false},
            ],
        });
        let p = std::env::temp_dir().join("elara_verify_test_incl.json");
        std::fs::write(&p, serde_json::to_vec(&proof).unwrap()).unwrap();

        // Correct proof + matching --expect-root → both checks pass.
        let mut checks = Vec::new();
        verify_inclusion(&p, Some(&hex::encode(root)), &mut checks).expect("runs");
        assert!(checks.iter().any(|c| c.name == "record inclusion" && c.status == Status::Pass));
        assert!(checks.iter().any(|c| c.name == "sealed-root bind" && c.status == Status::Pass));

        // Tampered root → inclusion fails.
        let bad = serde_json::json!({
            "zone": 0,
            "leaf": hex::encode(leaf),
            "root": hex::encode([0u8; 32]),
            "siblings": [
                {"hash": hex::encode(sib0), "is_right": true},
                {"hash": hex::encode(sib1), "is_right": false},
            ],
        });
        let p2 = std::env::temp_dir().join("elara_verify_test_incl_bad.json");
        std::fs::write(&p2, serde_json::to_vec(&bad).unwrap()).unwrap();
        let mut checks2 = Vec::new();
        verify_inclusion(&p2, None, &mut checks2).expect("runs");
        assert!(checks2.iter().any(|c| c.name == "record inclusion" && c.status == Status::Fail));

        // Right proof but wrong --expect-root → bind fails.
        let mut checks3 = Vec::new();
        verify_inclusion(&p, Some(&hex::encode([1u8; 32])), &mut checks3).expect("runs");
        assert!(checks3.iter().any(|c| c.name == "sealed-root bind" && c.status == Status::Fail));

        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn inclusion_without_expect_root_is_partial_not_pass() {
        // CRITICAL fail-open fix: with no --expect-root the proof's root is
        // self-declared (attacker-chosen). The path walk may be internally
        // consistent, but the sealed-root bind MUST be Partial so the verdict is
        // PARTIAL, never a green VERIFIED.
        let leaf = sha3_256(b"some record");
        let sib = sha3_256(b"sib");
        let mut c = [0u8; 64];
        c[..32].copy_from_slice(&leaf);
        c[32..].copy_from_slice(&sib);
        let root = sha3_256(&c);
        let proof = serde_json::json!({
            "leaf": hex::encode(leaf),
            "root": hex::encode(root),
            "siblings": [{"hash": hex::encode(sib), "is_right": true}],
        });
        let p = std::env::temp_dir().join("elara_verify_incl_noexpect.json");
        std::fs::write(&p, serde_json::to_vec(&proof).unwrap()).unwrap();
        let mut checks = Vec::new();
        verify_inclusion(&p, None, &mut checks).expect("runs");
        assert!(
            checks.iter().any(|c| c.name == "sealed-root bind" && c.status == Status::Partial),
            "unbound inclusion root must be Partial, not omitted/Pass"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Partial, "no --expect-root ⇒ not VERIFIED");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn inclusion_empty_siblings_leaf_eq_root_is_rejected() {
        // The leaf==root, zero-siblings tautology must NOT pass: a record can
        // never equal a sealed zone root, and a zero-length path proves nothing.
        let leaf = sha3_256(b"x");
        let proof = serde_json::json!({
            "leaf": hex::encode(leaf),
            "root": hex::encode(leaf), // attacker sets root == leaf
            "siblings": [],
        });
        let p = std::env::temp_dir().join("elara_verify_incl_empty.json");
        std::fs::write(&p, serde_json::to_vec(&proof).unwrap()).unwrap();
        let mut checks = Vec::new();
        verify_inclusion(&p, None, &mut checks).expect("runs");
        assert!(
            checks.iter().any(|c| c.name == "record inclusion" && c.status == Status::Fail),
            "zero-sibling leaf==root tautology must Fail"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn inclusion_non_bool_is_right_is_rejected() {
        // is_right selects the combine order; a non-bool (integer 1) must be a
        // hard input error, not a silent default-to-false that flips the path.
        let leaf = sha3_256(b"r");
        let sib = sha3_256(b"s");
        let proof = serde_json::json!({
            "leaf": hex::encode(leaf),
            "root": hex::encode(leaf),
            "siblings": [{"hash": hex::encode(sib), "is_right": 1}],
        });
        let p = std::env::temp_dir().join("elara_verify_incl_isright.json");
        std::fs::write(&p, serde_json::to_vec(&proof).unwrap()).unwrap();
        let mut checks = Vec::new();
        assert!(
            verify_inclusion(&p, None, &mut checks).is_err(),
            "non-bool is_right must be an input error (exit 2)"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn inclusion_over_depth_sibling_flood_is_rejected() {
        // The zone-Merkle tree is network::merkle::MAX_DEPTH = 64, so a real path
        // carries at most 64 siblings. A proof JSON with > 64 is a structural
        // non-proof AND a DoS lever: an offline verifier handed millions of
        // siblings would do unbounded SHA3-256 work. It must be a hard input
        // error BEFORE the walk, mirroring the 256-cap on the account path.
        let leaf = sha3_256(b"r");
        let mk_sibs = |n: u32| -> Vec<serde_json::Value> {
            (0..n)
                .map(|i| {
                    serde_json::json!({
                        "hash": hex::encode(sha3_256(&i.to_le_bytes())),
                        "is_right": i % 2 == 0,
                    })
                })
                .collect()
        };

        // 65 siblings (> 64) → hard reject (exit 2), never walked.
        let flood = serde_json::json!({
            "leaf": hex::encode(leaf),
            "root": hex::encode([0u8; 32]),
            "siblings": mk_sibs(65),
        });
        let p = std::env::temp_dir().join("elara_verify_incl_flood.json");
        std::fs::write(&p, serde_json::to_vec(&flood).unwrap()).unwrap();
        let mut checks = Vec::new();
        assert!(
            verify_inclusion(&p, None, &mut checks).is_err(),
            "a >64-sibling record proof must be a hard input error, not an unbounded walk"
        );

        // Boundary: exactly 64 siblings is a valid INPUT shape — it Fails the
        // walk against the bogus root, but must NOT be rejected as malformed.
        let at_cap = serde_json::json!({
            "leaf": hex::encode(leaf),
            "root": hex::encode([0u8; 32]),
            "siblings": mk_sibs(64),
        });
        let p64 = std::env::temp_dir().join("elara_verify_incl_64.json");
        std::fs::write(&p64, serde_json::to_vec(&at_cap).unwrap()).unwrap();
        let mut checks64 = Vec::new();
        verify_inclusion(&p64, None, &mut checks64)
            .expect("exactly 64 siblings is a valid input shape (Fails walk, not malformed)");

        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&p64);
    }

    #[test]
    fn identity_binding_malformed_wire_is_fail() {
        // A present-but-wrong-length identity_hash_wire is a malformed claim and
        // must Fail — it previously fell through to a green Pass. The field is
        // outside signable_bytes, so it can be grafted onto a validly-signed
        // record (the signature still verifies).
        let (mut rec, _id) = signed_record(b"payload");
        rec.identity_hash_wire = Some(vec![0x01, 0x02, 0x03]); // 3 bytes, not 32
        let mut checks = Vec::new();
        verify_core::verify_record(&rec, None, "", &mut checks);
        assert!(
            checks.iter().any(|c| c.name == "signature" && c.status == Status::Pass),
            "signature still valid (identity_hash_wire is outside the signature)"
        );
        assert!(
            checks.iter().any(|c| c.name == "identity binding" && c.status == Status::Fail),
            "malformed identity_hash_wire must Fail, not silently Pass"
        );
    }

    #[test]
    fn verdict_of_empty_is_not_verified() {
        // Defensive fail-closed: a verifier that checked nothing is never green.
        assert_eq!(Verdict::of(&[]), Verdict::Failed);
    }

    #[test]
    fn cross_leg_binding_catches_mismatched_record_and_proof() {
        // record↔proof: a valid record + a valid proof for a DIFFERENT record
        // must Fail the binding; a matching leaf must Pass.
        let (rec, _id) = signed_record(b"the real record");
        let rh = rec.record_hash();
        let incl_other = InclusionFacts { leaf: sha3_256(b"a different record"), root: [9u8; 32] };
        let mut checks = Vec::new();
        bind_chain(&mut checks, Some(rh), Some(&incl_other), None, &[], None);
        assert!(
            checks.iter().any(|c| c.name == "record↔proof" && c.status == Status::Fail),
            "proof for a different record must Fail the binding"
        );
        let incl_ok = InclusionFacts { leaf: rh, root: [9u8; 32] };
        let mut checks2 = Vec::new();
        bind_chain(&mut checks2, Some(rh), Some(&incl_ok), None, &[], None);
        assert!(
            checks2.iter().any(|c| c.name == "record↔proof" && c.status == Status::Pass),
            "proof whose leaf is THIS record's hash binds"
        );
    }

    #[test]
    fn cross_leg_binding_catches_mismatched_seal_and_anchor() {
        // seal↔anchor: a seal whose hash ≠ the anchor's committed seal_hash Fails.
        let seal_h = sha3_256(b"the seal record");
        let anchor = AnchorSummary {
            epoch: 1,
            seal_hash: hex::encode(sha3_256(b"a DIFFERENT seal")),
            not_before_unix: None,
            not_before_trustless: false,
            beacon_label: String::new(),
            assumed_default_beacon: false,
            has_ots_sidecar: false,
            existed_by_unix: None,
            existed_by_height: None,
            existed_by_trustless: false,
        };
        let mut checks = Vec::new();
        bind_chain(&mut checks, None, None, Some(seal_h), &[], Some(&anchor));
        assert!(
            checks.iter().any(|c| c.name == "seal↔anchor" && c.status == Status::Fail),
            "anchor committing to a different seal must Fail the binding"
        );
    }

    // Shared AnchorSummary builder for the chain-binding tests below — a
    // fully-confirmed anchor committing to `seal_h`, so the only variable under
    // test is the inclusion↔seal link.
    fn confirmed_anchor(seal_h: [u8; 32]) -> AnchorSummary {
        AnchorSummary {
            epoch: 7,
            seal_hash: hex::encode(seal_h),
            not_before_unix: Some(1_700_000_000),
            not_before_trustless: true,
            beacon_label: "test-chain".into(),
            assumed_default_beacon: false,
            has_ots_sidecar: true,
            existed_by_unix: Some(1_700_000_600),
            existed_by_height: Some(953_657),
            existed_by_trustless: true,
        }
    }

    #[test]
    fn inclusion_seal_link_fails_for_unrelated_seal_and_blocks_chain_bound() {
        // THE false-chain regression: a valid record + a valid proof for it
        // (climbing to ROOT_P) + an individually-valid but UNRELATED seal that
        // committed to a DIFFERENT root must NOT read as one chain. The
        // inclusion↔seal link Fails, and chain_is_bound stays false so the prose
        // can never say "this record's seal".
        let (rec, _id) = signed_record(b"the real record");
        let rh = rec.record_hash();
        let root_p = sha3_256(b"root the proof climbs to");
        let root_s = sha3_256(b"a DIFFERENT root the seal signed");
        let incl = InclusionFacts { leaf: rh, root: root_p };
        let seal_h = sha3_256(b"the unrelated seal record");
        let anchor = confirmed_anchor(seal_h);
        let mut checks = Vec::new();
        bind_chain(&mut checks, Some(rh), Some(&incl), Some(seal_h), &[root_s], Some(&anchor));
        assert!(
            checks.iter().any(|c| c.name == "record↔proof" && c.status == Status::Pass),
            "record↔proof passes (leaf is this record)"
        );
        assert!(
            checks.iter().any(|c| c.name == "seal↔anchor" && c.status == Status::Pass),
            "seal↔anchor passes (anchor commits to this seal)"
        );
        assert!(
            checks.iter().any(|c| c.name == "inclusion↔seal" && c.status == Status::Fail),
            "inclusion↔seal must FAIL — proof root is not a root this seal signed"
        );
        // The two end-links pass, but the missing middle link means the chain is
        // NOT bound: the old code (record↔proof && seal↔anchor) returned true here.
        assert!(
            !chain_is_bound(&checks),
            "unrelated proof+seal must NOT be chain_bound"
        );
        // And the hard Fail propagates to the overall verdict.
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
    }

    #[test]
    fn inclusion_seal_link_passes_when_proof_root_is_a_sealed_root() {
        // The legitimate full chain: the proof climbs to a root the seal
        // actually committed to. All four links pass → chain_is_bound true →
        // the prose may honestly say "this record's seal".
        let (rec, _id) = signed_record(b"the real record");
        let rh = rec.record_hash();
        let sealed_root = sha3_256(b"the root the seal committed to");
        let incl = InclusionFacts { leaf: rh, root: sealed_root };
        let seal_h = sha3_256(b"the matching seal record");
        let anchor = confirmed_anchor(seal_h);
        let mut checks = Vec::new();
        // Seal committed to several roots; the proof's root is one of them.
        let seal_roots = [sha3_256(b"some other tree root"), sealed_root];
        bind_chain(&mut checks, Some(rh), Some(&incl), Some(seal_h), &seal_roots, Some(&anchor));
        assert!(
            checks.iter().any(|c| c.name == "inclusion↔seal" && c.status == Status::Pass),
            "inclusion↔seal passes when proof root is among the seal's committed roots"
        );
        // record inclusion is produced by verify_inclusion, not bind_chain, so
        // assemble the full check set chain_is_bound expects.
        checks.push(Check { name: "record inclusion", status: Status::Pass, detail: String::new() });
        assert!(chain_is_bound(&checks), "all four links present and Pass ⇒ chain bound");
    }

    #[test]
    fn seal_committed_roots_keeps_valid_drops_malformed_never_admits_garbage() {
        // seal_committed_roots feeds the inclusion↔seal bind. A valid 32-byte hex
        // root in signed seal metadata is admitted; a present-but-malformed root is
        // dropped (→ that bind stays UNPROVEN), never coerced into the accepted set.
        // The audit's LOW residual was that the malformed drop was SILENT (now it
        // warns); the security-relevant invariant pinned here is the harder one —
        // garbage is never admitted as a root, whatever its shape.
        let (mut rec, _id) = signed_record(b"a seal");
        let good = sha3_256(b"a real committed root");
        rec.metadata
            .insert("epoch_merkle_root".into(), serde_json::json!(hex::encode(good)));
        // Present but not 32-byte hex → dropped, not parsed into a root.
        rec.metadata
            .insert("epoch_sparse_merkle_root".into(), serde_json::json!("not-hex-zzz"));
        // Present but a non-string JSON value → dropped.
        rec.metadata
            .insert("epoch_account_smt_root".into(), serde_json::json!(12345));
        // (epoch_zone_registry_root absent → legacy seal, silently skipped.)

        let roots = seal_committed_roots(&rec);
        assert!(roots.contains(&good), "the one valid hex root is admitted");
        assert_eq!(
            roots.len(),
            1,
            "only the valid root survives — malformed/non-string dropped, never garbage admitted"
        );
    }

    #[test]
    fn legacy_seal_without_root_metadata_leaves_chain_unproven() {
        // A pre-Gap-1 seal carries no committed roots. The inclusion↔seal link
        // is then simply absent (not invented), so the chain stays unproven and
        // the prose falls back to "the anchored seal" + the NOTE — never a false
        // claim, never a false Fail.
        let (rec, _id) = signed_record(b"the real record");
        let rh = rec.record_hash();
        let incl = InclusionFacts { leaf: rh, root: sha3_256(b"some root") };
        let seal_h = sha3_256(b"a legacy seal");
        let anchor = confirmed_anchor(seal_h);
        let mut checks = Vec::new();
        bind_chain(&mut checks, Some(rh), Some(&incl), Some(seal_h), &[], Some(&anchor));
        assert!(
            !checks.iter().any(|c| c.name == "inclusion↔seal"),
            "no inclusion↔seal link is emitted when the seal carries no committed roots"
        );
        assert!(!chain_is_bound(&checks), "legacy seal cannot bind the chain");
        // No hard Fail introduced — the absent link is honest, not an error.
        assert_ne!(Verdict::of(&checks), Verdict::Failed);
    }

    // ── drand BLS verification (the not-before reference→trustless upgrade) ──
    // Real League-of-Entropy default-chain vector, round 6195966 — the exact
    // round the shipped examples/verify sample cites. Harvested once from
    // https://api.drand.sh/public/6195966 + /info; the verification is offline.
    const V_ROUND: u64 = 6_195_966;
    const V_SIG: &str = "916f0de9b0e0c988fe0cd0c6b3da9298ef5a764fafe93d8a00087bb65b31145cd4c34c823f0400330e2e0db365f642d804ff7956ca2cac9f1a48dfb46e315e920d3f97a073553da98f94e39736dfd8a7bdd8d6dfcb079fceddacec5a094dd7b1";
    const V_PREV: &str = "a233afb7e73e355e1f7ebf4d0b4c5e46893787e3743638ea83fca548f27a1ecda8a970a73e184172cd4757c11a9392401661c14beecfbb65e74409b9afc4b89de5a4e3e463417db0899851b106b6a885e368a748e772de062b32d1d3e64bcd37";
    const V_RANDOMNESS: &str = "64bee73a49f4ccb408d98bd2de5a6b8b33c9132f7b7d31533d6172aff3ae17d9";

    fn vector_artifact() -> Value {
        serde_json::json!({
            "drand_round": V_ROUND,
            "drand_randomness": V_RANDOMNESS,
            "drand_signature": V_SIG,
            "drand_previous_signature": V_PREV,
            "drand_public_key": LOE_DEFAULT_PUBKEY_HEX,
            "drand_chain_hash": LOE_DEFAULT_CHAIN_HASH,
        })
    }

    /// The exact JSON shape the --seal path projects from a produced seal's
    /// metadata: the seven `drand_*` keys `time_bracket::write_metadata`
    /// emits when the a3 producer embeds a signature-bearing pulse. Numbers
    /// are JSON numbers (seal metadata stores them via `Value::from(u64)`),
    /// genesis/period are the pinned LoE constants the fetcher hardcodes.
    fn seal_projected_obj() -> Value {
        serde_json::json!({
            "drand_round": V_ROUND,
            "drand_randomness": V_RANDOMNESS,
            "drand_genesis_unix": 1_595_431_050u64,
            "drand_period_secs": 30u64,
            "drand_chain_hash": LOE_DEFAULT_CHAIN_HASH,
            "drand_signature": V_SIG,
            "drand_previous_signature": V_PREV,
        })
    }

    #[test]
    fn seal_projected_drand_leg_grades_trustless_pass() {
        // DONE-WHEN leg contract, hermetic: a seal produced with the a3
        // fetcher's pulse projects to this obj, and the shared leg grades it
        // a trustless PASS (BLS against the PINNED key, real LoE vector).
        let mut checks = Vec::new();
        let leg = drand_not_before_leg(&seal_projected_obj(), PulseSubject::Seal, &mut checks);
        assert!(leg.not_before_trustless, "real vector must upgrade to trustless");
        assert_eq!(
            leg.not_before_unix,
            Some(1_595_431_050 + (V_ROUND - 1) * 30),
            "not-before must be the round's real emission instant"
        );
        let c = checks.iter().find(|c| c.name == "drand not-before").unwrap();
        assert_eq!(c.status, Status::Pass, "detail: {}", c.detail);
    }

    #[test]
    fn seal_projected_tampered_signature_grades_fail() {
        let mut obj = seal_projected_obj();
        let mut sig = V_SIG.to_string();
        sig.replace_range(0..1, "a"); // flip a nibble — forged material
        obj["drand_signature"] = Value::from(sig);
        let mut checks = Vec::new();
        let leg = drand_not_before_leg(&obj, PulseSubject::Seal, &mut checks);
        assert!(!leg.not_before_trustless);
        let c = checks.iter().find(|c| c.name == "drand not-before").unwrap();
        assert_eq!(c.status, Status::Fail, "forged sig must FAIL, not degrade");
    }

    #[test]
    fn seal_projected_signature_less_pulse_grades_partial() {
        // A legacy 5-key pulse (pre-a3 producer, or a fetcher that stored no
        // signature) is a reference bound: honest PARTIAL, never Pass.
        let mut obj = seal_projected_obj();
        obj.as_object_mut().unwrap().remove("drand_signature");
        obj.as_object_mut().unwrap().remove("drand_previous_signature");
        let mut checks = Vec::new();
        let leg = drand_not_before_leg(&obj, PulseSubject::Seal, &mut checks);
        assert!(!leg.not_before_trustless);
        assert!(leg.not_before_unix.is_some(), "reference bound still computed");
        let c = checks.iter().find(|c| c.name == "drand not-before").unwrap();
        assert_eq!(c.status, Status::Partial);
    }

    #[test]
    fn seal_projected_forged_genesis_grades_fail_closed() {
        // Pinned-chain claim + non-pinned genesis: the BLS signature cannot
        // vouch for chain parameters, so the leg must fail closed
        // (loe_param_conflict) — a real round must not be remappable to an
        // attacker-chosen instant under the trustless badge.
        let mut obj = seal_projected_obj();
        obj["drand_genesis_unix"] = Value::from(1_595_431_050u64 + 3_600);
        let mut checks = Vec::new();
        let leg = drand_not_before_leg(&obj, PulseSubject::Seal, &mut checks);
        assert!(!leg.not_before_trustless);
        let c = checks.iter().find(|c| c.name == "drand not-before").unwrap();
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn drand_bls_verifies_real_loe_vector() {
        // The real signature verifies against the PINNED key → trustless.
        let obj = vector_artifact();
        assert_eq!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Verified
        );
        // Sanity: the pinned key matches the round's real signer, and the
        // randomness binding (randomness == sha256(signature)) holds.
        let sig = hex::decode(V_SIG).unwrap();
        assert_eq!(hex::encode(derive_randomness(&sig)), V_RANDOMNESS);
    }

    #[test]
    fn anchor_forged_loe_genesis_period_is_fail_not_trustless() {
        // HIGH-severity fail-open guard (fusion audit 2026-06-15). The beacon BLS
        // signature binds only (round, previous_signature) — NOT genesis/period.
        // A forger replays a REAL, validly-signed LoE beacon (round 6195966) but
        // supplies bogus genesis/period to map that round to an attacker-chosen
        // instant, while keeping the real chain hash so the signature still
        // verifies against the pinned key. Pre-fix this read Status::Pass +
        // not_before_trustless=true (a trustless badge on an attacker-controlled
        // time). It must now FAIL the drand leg.
        let sh = "2ac41d55c0c1e344665e98e085703e2cd8dc6128144b1dec1e0a877520f902ef";
        let mut forged = vector_artifact(); // real round-6195966 beacon, verifies
        forged["epoch"] = serde_json::json!(14u64);
        forged["seal_hash"] = Value::String(sh.into());
        forged["drand_genesis_unix"] = serde_json::json!(1u64); // 25y early
        forged["drand_period_secs"] = serde_json::json!(1u64);
        let pf = std::env::temp_dir().join("elara_verify_forged_loe_params.json");
        std::fs::write(&pf, serde_json::to_vec(&forged).unwrap()).unwrap();
        let mut cf = Vec::new();
        let sf = verify_anchor(&pf, &mut cf).expect("anchor parses");
        let _ = std::fs::remove_file(&pf);
        assert!(
            !sf.not_before_trustless,
            "forged LoE genesis/period must NOT yield a trustless not-before"
        );
        assert!(
            cf.iter()
                .any(|c| c.name == "drand not-before" && c.status == Status::Fail),
            "forged LoE timing must FAIL the drand not-before leg, got: {:?}",
            cf.iter()
                .find(|c| c.name == "drand not-before")
                .map(|c| c.status)
        );

        // Control: the SAME real beacon with the CORRECT pinned constants stays
        // trustless — proves the guard isolates the parameter forgery, not the
        // signature, and does not over-reject genuine self-describing artifacts.
        let mut genuine = vector_artifact();
        genuine["epoch"] = serde_json::json!(14u64);
        genuine["seal_hash"] = Value::String(sh.into());
        genuine["drand_genesis_unix"] = serde_json::json!(LOE_DEFAULT_GENESIS_UNIX);
        genuine["drand_period_secs"] = serde_json::json!(LOE_DEFAULT_PERIOD_SECS);
        let pg = std::env::temp_dir().join("elara_verify_genuine_loe_params.json");
        std::fs::write(&pg, serde_json::to_vec(&genuine).unwrap()).unwrap();
        let mut cg = Vec::new();
        let sg = verify_anchor(&pg, &mut cg).expect("anchor parses");
        let _ = std::fs::remove_file(&pg);
        assert!(
            sg.not_before_trustless,
            "genuine LoE beacon with correct constants must stay trustless (control)"
        );
        assert!(
            cg.iter()
                .any(|c| c.name == "drand not-before" && c.status == Status::Pass),
            "genuine LoE beacon must PASS the drand not-before leg (control)"
        );
    }

    #[test]
    fn drand_bls_rejects_tampered_signature() {
        // Flip the last nibble of the signature: must NOT verify.
        let mut bad = V_SIG.to_string();
        bad.pop();
        bad.push('2'); // original ends in '1'
        let mut obj = vector_artifact();
        obj["drand_signature"] = Value::String(bad);
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Failed(_)
        ));
    }

    #[test]
    fn drand_bls_rejects_substituted_pubkey() {
        // A forger swaps in their own beacon key — rejected before pairing,
        // because we only ever trust the PINNED key.
        let mut obj = vector_artifact();
        let mut forged = LOE_DEFAULT_PUBKEY_HEX.to_string();
        forged.replace_range(0..2, "00");
        obj["drand_public_key"] = Value::String(forged);
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Failed(_)
        ));
    }

    #[test]
    fn drand_bls_rejects_randomness_mismatch() {
        let mut obj = vector_artifact();
        obj["drand_randomness"] = Value::String("00".repeat(32));
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Failed(_)
        ));
    }

    #[test]
    fn drand_bls_reference_when_no_signature() {
        // Legacy artifact: only round + randomness. Stays a reference bound.
        let obj = serde_json::json!({
            "drand_round": V_ROUND,
            "drand_randomness": V_RANDOMNESS,
        });
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Reference(_)
        ));
    }

    #[test]
    fn drand_bls_reference_for_unknown_chain() {
        // Signature present, but the chain is not the pinned LoE default and we
        // are not assuming the default → no pinned key → reference, not failure.
        let mut obj = vector_artifact();
        obj["drand_chain_hash"] = Value::String("ab".repeat(32));
        obj["drand_public_key"] = Value::String(String::new()); // don't trip the pin cross-check
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(&"ab".repeat(32)), false),
            DrandBls::Reference(_)
        ));
    }

    #[test]
    fn drand_bls_reference_when_previous_signature_absent() {
        // Chained beacon needs previous_signature to rebuild the message.
        let mut obj = vector_artifact();
        obj["drand_previous_signature"] = Value::String(String::new());
        assert!(matches!(
            verify_drand_bls(&obj, V_ROUND, Some(LOE_DEFAULT_CHAIN_HASH), false),
            DrandBls::Reference(_)
        ));
    }

    // ── Anchor verdict semantics ─────────────────────────────────────────────
    // The bracket legs must FAIL CLOSED on forged/tampered/broken evidence yet
    // report a legitimately-unproven bound as PARTIAL — never a silent VERIFIED.
    // These drive the REAL shipped sample (a fully-confirmed anchor) with
    // controlled corruption, automating the manual adversarial battery.

    fn sample_copy() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/verify");
        let dir = std::env::temp_dir().join(format!(
            "elara-verify-anchor-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for f in [
            "epoch-41340-zone-0.json",
            "epoch-41340-zone-0.json.ots",
            "btc-header-957487.txt",
        ] {
            std::fs::copy(src.join(f), dir.join(f)).expect("sample file present");
        }
        dir
    }

    fn anchor_checks(dir: &std::path::Path) -> Vec<Check> {
        let mut checks = Vec::new();
        let _ = verify_anchor(&dir.join("epoch-41340-zone-0.json"), &mut checks);
        checks
    }

    fn existed_by(checks: &[Check]) -> Status {
        checks
            .iter()
            .find(|c| c.name == "existed-by")
            .expect("existed-by leg must ALWAYS be pushed, never silently dropped")
            .status
    }

    #[test]
    fn anchor_full_sample_is_verified() {
        let dir = sample_copy();
        let checks = anchor_checks(&dir);
        assert_eq!(existed_by(&checks), Status::Pass, "confirmed sample upper bound");
        assert!(checks
            .iter()
            .any(|c| c.name == "drand not-before" && c.status == Status::Pass));
        assert_eq!(Verdict::of(&checks), Verdict::Verified);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Build a wire anchor-proof RECORD from the shipped sample (real
    /// artifact + real Bitcoin-attested .ots), signed by a fresh identity,
    /// and drive it through `--anchor-record`. Every leg must grade exactly
    /// like the file path (TRUSTLESS existed-by against pinned block 957487)
    /// plus the record-only legs (signature, content bind, anchor binding).
    #[test]
    fn anchor_record_full_sample_is_verified() {
        let dir = sample_copy();
        let artifact_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json")).unwrap();
        let ots_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json.ots")).unwrap();
        let obj: Value = serde_json::from_slice(&artifact_bytes).unwrap();
        let meta = elara_runtime::anchor_proof::anchor_proof_metadata(
            elara_runtime::anchor_proof::ANCHOR_KIND_ELARA_SEAL,
            obj.get("seal_hash").unwrap().as_str().unwrap(),
            obj.get("zone").unwrap().as_str().unwrap(),
            obj.get("epoch").unwrap().as_u64().unwrap(),
            &artifact_bytes,
            &ots_bytes,
        )
        .expect("sample payloads fit the builder caps");
        let id = elara_runtime::identity::Identity::generate(
            elara_runtime::identity::EntityType::Device,
            elara_runtime::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let mut record = ValidationRecord::create(
            &artifact_bytes,
            id.public_key.clone(),
            vec![],
            elara_runtime::record::Classification::Public,
            Some(meta),
        );
        record.nonce = 7;
        id.sign_record(&mut record).unwrap();
        let rec_path = dir.join("anchor-record.wire");
        std::fs::write(&rec_path, record.to_bytes()).unwrap();

        let mut checks = Vec::new();
        let summary =
            verify_anchor_record(&rec_path, &mut checks).expect("record path verifies");
        assert!(
            summary.existed_by_trustless,
            "pinned header alongside the record → trustless existed-by"
        );
        for leg in ["signature", "content", "anchor binding"] {
            assert!(
                checks.iter().any(|c| c.name == leg && c.status == Status::Pass),
                "leg '{leg}' must Pass on the honest sample"
            );
        }
        assert_eq!(Verdict::of(&checks), Verdict::Verified);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A record whose metadata tuple LIES about what it anchors — valid
    /// signature, REAL OTS proof, but a different anchor_digest — must FAIL
    /// the anchor-binding check. This is the audit-theater vector: without
    /// the cross-check, any record carrying any genuine proof could claim
    /// to bracket any seal.
    #[test]
    fn anchor_record_lying_tuple_fails_binding() {
        let dir = sample_copy();
        let artifact_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json")).unwrap();
        let ots_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json.ots")).unwrap();
        let obj: Value = serde_json::from_slice(&artifact_bytes).unwrap();
        // Lie: claim a DIFFERENT seal digest than the artifact carries.
        let lie = "deadbeef".repeat(8);
        assert_ne!(lie, obj.get("seal_hash").unwrap().as_str().unwrap());
        let meta = elara_runtime::anchor_proof::anchor_proof_metadata(
            elara_runtime::anchor_proof::ANCHOR_KIND_ELARA_SEAL,
            &lie,
            obj.get("zone").unwrap().as_str().unwrap(),
            obj.get("epoch").unwrap().as_u64().unwrap(),
            &artifact_bytes,
            &ots_bytes,
        )
        .unwrap();
        let id = elara_runtime::identity::Identity::generate(
            elara_runtime::identity::EntityType::Device,
            elara_runtime::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let mut record = ValidationRecord::create(
            &artifact_bytes,
            id.public_key.clone(),
            vec![],
            elara_runtime::record::Classification::Public,
            Some(meta),
        );
        record.nonce = 8;
        id.sign_record(&mut record).unwrap();
        let rec_path = dir.join("anchor-record-lying.wire");
        std::fs::write(&rec_path, record.to_bytes()).unwrap();

        let mut checks = Vec::new();
        let _ = verify_anchor_record(&rec_path, &mut checks).expect("parses + runs");
        assert!(
            checks
                .iter()
                .any(|c| c.name == "anchor binding" && c.status == Status::Fail),
            "a lying tuple must FAIL the binding check"
        );
        assert!(
            checks.iter().any(|c| c.name == "signature" && c.status == Status::Pass),
            "the signature is genuinely valid — the LIE is in the tuple, and \
             only the binding check catches it"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tampering with the OTS payload inside the record (bit-flip in
    /// anchor_ots_b64) must fail the existed-by leg — the proof no longer
    /// walks to a consistent Bitcoin attestation for these artifact bytes.
    #[test]
    fn anchor_record_tampered_ots_fails() {
        let dir = sample_copy();
        let artifact_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json")).unwrap();
        let mut ots_bytes = std::fs::read(dir.join("epoch-41340-zone-0.json.ots")).unwrap();
        let mid = ots_bytes.len() / 2;
        ots_bytes[mid] ^= 0xFF;
        let obj: Value = serde_json::from_slice(&artifact_bytes).unwrap();
        let meta = elara_runtime::anchor_proof::anchor_proof_metadata(
            elara_runtime::anchor_proof::ANCHOR_KIND_ELARA_SEAL,
            obj.get("seal_hash").unwrap().as_str().unwrap(),
            obj.get("zone").unwrap().as_str().unwrap(),
            obj.get("epoch").unwrap().as_u64().unwrap(),
            &artifact_bytes,
            &ots_bytes,
        )
        .unwrap();
        let id = elara_runtime::identity::Identity::generate(
            elara_runtime::identity::EntityType::Device,
            elara_runtime::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let mut record = ValidationRecord::create(
            &artifact_bytes,
            id.public_key.clone(),
            vec![],
            elara_runtime::record::Classification::Public,
            Some(meta),
        );
        record.nonce = 9;
        id.sign_record(&mut record).unwrap();
        let rec_path = dir.join("anchor-record-tampered.wire");
        std::fs::write(&rec_path, record.to_bytes()).unwrap();

        let mut checks = Vec::new();
        let summary = verify_anchor_record(&rec_path, &mut checks).expect("parses + runs");
        assert!(!summary.existed_by_trustless);
        assert_ne!(
            Verdict::of(&checks),
            Verdict::Verified,
            "a corrupted OTS payload must never grade VERIFIED"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_absent_ots_is_partial_never_verified() {
        let dir = sample_copy();
        std::fs::remove_file(dir.join("epoch-41340-zone-0.json.ots")).unwrap();
        let checks = anchor_checks(&dir);
        assert_eq!(
            existed_by(&checks),
            Status::Partial,
            "no .ots → unproven upper bound, but the leg must still be present"
        );
        assert_eq!(
            Verdict::of(&checks),
            Verdict::Partial,
            "stripping the .ots must NOT yield VERIFIED (the original fail-open)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_unarchived_header_is_partial() {
        let dir = sample_copy();
        std::fs::remove_file(dir.join("btc-header-957487.txt")).unwrap();
        let checks = anchor_checks(&dir);
        assert_eq!(
            existed_by(&checks),
            Status::Partial,
            "OTS present, confirming header absent → Partial"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Partial);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_broken_header_is_fail_not_partial() {
        let dir = sample_copy();
        // Present but structurally invalid — tamper class, distinct from absent.
        std::fs::write(
            dir.join("btc-header-957487.txt"),
            "blockstream_header: ZZZZ_not_hex\n",
        )
        .unwrap();
        let checks = anchor_checks(&dir);
        assert_eq!(
            existed_by(&checks),
            Status::Fail,
            "present-but-broken header must FAIL, not silently pass as unarchived"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_wrong_block_header_root_mismatch_is_fail() {
        let dir = sample_copy();
        // Valid 80-byte hex header, but for the wrong block → merkle root disagrees.
        let bogus = "00".repeat(80);
        std::fs::write(
            dir.join("btc-header-957487.txt"),
            format!("blockstream_header: {bogus}\n"),
        )
        .unwrap();
        let checks = anchor_checks(&dir);
        assert_eq!(existed_by(&checks), Status::Fail, "root mismatch → Fail");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn anchor_reference_drand_is_partial_not_verified() {
        // Strip the drand signature → reference-only lower bound (Partial). Also
        // drop the .ots so the (now content-changed) file's upper bound is Partial
        // (absent), not Fail — isolating the lower-bound downgrade.
        let dir = sample_copy();
        std::fs::remove_file(dir.join("epoch-41340-zone-0.json.ots")).unwrap();
        let raw = std::fs::read_to_string(dir.join("epoch-41340-zone-0.json")).unwrap();
        let mut v: Value = serde_json::from_str(&raw).unwrap();
        let o = v.as_object_mut().unwrap();
        o.remove("drand_signature");
        o.remove("drand_previous_signature");
        std::fs::write(
            dir.join("epoch-41340-zone-0.json"),
            serde_json::to_vec(&v).unwrap(),
        )
        .unwrap();
        let checks = anchor_checks(&dir);
        assert!(
            checks
                .iter()
                .any(|c| c.name == "drand not-before" && c.status == Status::Partial),
            "reference-only drand (BLS not verified) must be Partial, not a green Pass"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Partial);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verdict_precedence_fail_dominates_partial_dominates_pass() {
        let mk = |s: Status| Check {
            name: "x",
            status: s,
            detail: String::new(),
        };
        // Fail dominates everything (the strip-the-.ots downgrade defense): a
        // tampered bound is never softened by a proven one.
        assert_eq!(
            Verdict::of(&[mk(Status::Pass), mk(Status::Partial), mk(Status::Fail)]),
            Verdict::Failed
        );
        assert_eq!(
            Verdict::of(&[mk(Status::Pass), mk(Status::Partial)]),
            Verdict::Partial
        );
        assert_eq!(
            Verdict::of(&[mk(Status::Pass), mk(Status::Pass)]),
            Verdict::Verified
        );
    }

    // ─── Account-inclusion proof verification ───────────────────────────────

    /// Build a real `/proof/account/{identity}`-shaped JSON for `identity`
    /// holding sealed leaf `state_hash`, using the network-agreed account SMT.
    /// Returns the JSON and the tree root (== the proof's root).
    fn account_proof_json(
        identity: [u8; 32],
        state_hash: [u8; 32],
    ) -> (serde_json::Value, [u8; 32]) {
        use elara_smt::{MemorySmtStore, SparseMerkleTree};
        let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
        tree.update(&identity, &state_hash).expect("update");
        tree.commit().expect("commit");
        let root = tree.root().expect("root");
        let proof = tree.proof(&identity).expect("proof ok").expect("proof present");
        let siblings: Vec<_> = proof.siblings.iter().map(hex::encode).collect();
        let json = serde_json::json!({
            "identity": hex::encode(identity),
            "state_hash": hex::encode(proof.state_hash),
            "root": hex::encode(proof.root),
            "present": hex::encode(proof.present),
            "siblings": siblings,
            "exists": true,
        });
        (json, root)
    }

    fn write_tmp(name: &str, v: &serde_json::Value) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, serde_json::to_vec(v).unwrap()).unwrap();
        p
    }

    #[test]
    fn account_inclusion_real_proof_walks_then_binds_three_ways() {
        let identity = sha3_256(b"genesis-authority-pk");
        let state_hash = sha3_256(b"sealed account state @ epoch N");
        let (json, root) = account_proof_json(identity, state_hash);
        let p = write_tmp("elara_verify_acct_pos.json", &json);

        // Walk passes on a real proof.
        let mut checks = Vec::new();
        let facts = verify_account_inclusion(&p, None, &mut checks).unwrap().unwrap();
        assert_eq!(facts.root, root);
        assert_eq!(facts.identity, identity);
        assert!(checks.iter().any(|c| c.name == "account inclusion" && c.status == Status::Pass));

        // Bind via a --seal that committed this root → Pass.
        let mut c1 = Vec::new();
        bind_account_chain(&mut c1, Some(&facts), None, Some(root)).unwrap();
        assert!(c1.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Pass));

        // Bind via a --seal that committed a DIFFERENT root → Fail (the guard).
        let mut c2 = Vec::new();
        bind_account_chain(&mut c2, Some(&facts), None, Some([7u8; 32])).unwrap();
        assert!(c2.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Fail));

        // Bind via a matching --expect-root → Pass.
        let mut c3 = Vec::new();
        bind_account_chain(&mut c3, Some(&facts), Some(&hex::encode(root)), None).unwrap();
        assert!(c3.iter().any(|c| c.name == "sealed account-root bind" && c.status == Status::Pass));

        // No seal, no expect-root → honest PARTIAL (self-declared root).
        let mut c4 = Vec::new();
        bind_account_chain(&mut c4, Some(&facts), None, None).unwrap();
        assert!(c4.iter().any(|c| c.name == "sealed account-root bind" && c.status == Status::Partial));
    }

    #[test]
    fn account_inclusion_tampered_root_fails_walk() {
        let identity = sha3_256(b"id-A");
        let (mut json, _root) = account_proof_json(identity, sha3_256(b"state-A"));
        // Swap the declared root for an unrelated one: the leaf no longer climbs
        // to it, so the SMT walk must Fail (not silently pass).
        json["root"] = serde_json::Value::from(hex::encode([9u8; 32]));
        let p = write_tmp("elara_verify_acct_tamper.json", &json);
        let mut checks = Vec::new();
        let out = verify_account_inclusion(&p, None, &mut checks).unwrap();
        assert!(out.is_some());
        assert!(checks.iter().any(|c| c.name == "account inclusion" && c.status == Status::Fail));
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
    }

    #[test]
    fn account_inclusion_rejects_record_proof_shape() {
        // A record-inclusion proof has `leaf` and no `state_hash`; it must be
        // routed to --inclusion, never silently walked as an account proof.
        let json = serde_json::json!({
            "leaf": hex::encode([1u8; 32]),
            "root": hex::encode([2u8; 32]),
            "siblings": [],
        });
        let p = write_tmp("elara_verify_acct_recordshape.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_inclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_inclusion_exists_false_is_input_error() {
        let json = serde_json::json!({
            "identity": hex::encode([3u8; 32]),
            "exists": false,
            "root": hex::encode([0u8; 32]),
        });
        let p = write_tmp("elara_verify_acct_absent.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_inclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_inclusion_pending_first_seal_is_partial_not_error() {
        // Account exists but not yet committed to a seal: no proof body. Honest
        // PARTIAL, never a false green and never a hard error.
        let json = serde_json::json!({
            "identity": hex::encode([4u8; 32]),
            "exists": true,
            "bound_to_seal": false,
            "account_state": { "available": 0 },
        });
        let p = write_tmp("elara_verify_acct_pending.json", &json);
        let mut checks = Vec::new();
        let out = verify_account_inclusion(&p, None, &mut checks).unwrap();
        assert!(out.is_none());
        assert!(checks.iter().any(|c| c.name == "account inclusion" && c.status == Status::Partial));
    }

    #[test]
    fn account_inclusion_missing_present_errors() {
        let identity = sha3_256(b"id-short");
        let (mut json, _root) = account_proof_json(identity, sha3_256(b"state"));
        // A compressed account proof MUST carry the `present` bitmap; dropping it
        // is a structural input error (exit 2), not a silent walk.
        json.as_object_mut().unwrap().remove("present");
        let p = write_tmp("elara_verify_acct_nopresent.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_inclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_inclusion_expect_identity_mismatch_fails() {
        let identity = sha3_256(b"real-id");
        let (json, _root) = account_proof_json(identity, sha3_256(b"state"));
        let p = write_tmp("elara_verify_acct_idpin.json", &json);
        let mut checks = Vec::new();
        // Ask about a DIFFERENT identity than the proof is for.
        let other = hex::encode(sha3_256(b"some-other-id"));
        let _ = verify_account_inclusion(&p, Some(&other), &mut checks).unwrap();
        assert!(checks.iter().any(|c| c.name == "account identity" && c.status == Status::Fail));
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
    }

    #[test]
    fn account_chain_bound_predicate_requires_all_three_legs() {
        let pass = |name: &'static str| Check { name, status: Status::Pass, detail: String::new() };
        let full = vec![pass("account inclusion"), pass("account-root↔seal"), pass("seal↔anchor")];
        assert!(chain_is_account_bound(&full));
        // Missing the anchor link → not bound to Bitcoin.
        let no_anchor = vec![pass("account inclusion"), pass("account-root↔seal")];
        assert!(!chain_is_account_bound(&no_anchor));
        // A record-named leg must NEVER satisfy the account predicate.
        let record_legs = vec![pass("record inclusion"), pass("inclusion↔seal"), pass("seal↔anchor")];
        assert!(!chain_is_account_bound(&record_legs));
    }

    fn anchor_summary(
        not_before_trustless: bool,
        existed_by_unix: Option<u64>,
        existed_by_trustless: bool,
    ) -> AnchorSummary {
        AnchorSummary {
            epoch: 1,
            seal_hash: "ab".repeat(32),
            not_before_unix: Some(1_781_553_600),
            not_before_trustless,
            beacon_label: "test".into(),
            assumed_default_beacon: false,
            has_ots_sidecar: existed_by_unix.is_some(),
            existed_by_unix,
            existed_by_height: existed_by_unix.map(|_| 953_657),
            existed_by_trustless,
        }
    }

    #[test]
    fn account_time_bracket_requires_a_PROVEN_anchor_bound_not_just_chain_linkage() {
        let pass = |name: &'static str| Check { name, status: Status::Pass, detail: String::new() };
        // Fully chain-linked (account inclusion + account-root↔seal + seal↔anchor).
        let linked = vec![pass("account inclusion"), pass("account-root↔seal"), pass("seal↔anchor")];
        assert!(chain_is_account_bound(&linked));

        // seal↔anchor passing only means the anchor NAMES this seal. With NO anchor
        // time bound proven, claiming a Bitcoin/trustless bracket is an overclaim.
        assert!(!account_chain_time_bracketed(&linked, None));
        // An anchor present but with neither a trustless drand bound nor a Bitcoin
        // existed-by is STILL not a bracket.
        let unproven = anchor_summary(false, None, false);
        assert!(!account_chain_time_bracketed(&linked, Some(&unproven)));
        // crown-F1: a trustless drand not-before is the ANCHOR's freshness, which
        // places NO trustless bound on the seal (the seal predates the anchor) →
        // NOT bracketed. Only a trustless Bitcoin existed-by qualifies.
        let drand_ok = anchor_summary(true, None, false);
        assert!(!account_chain_time_bracketed(&linked, Some(&drand_ok)));
        // A REFERENCE Bitcoin existed-by (archived header NOT pin-authenticated) is
        // NOT a trustless bracket — the honest-downgrade fix: an unauthenticated
        // operator-supplied header cannot earn the trustless badge.
        let btc_ref = anchor_summary(false, Some(1_781_553_805), false);
        assert!(!account_chain_time_bracketed(&linked, Some(&btc_ref)));
        // A PIN-AUTHENTICATED (trustless) Bitcoin existed-by → bracketed.
        let btc_ok = anchor_summary(false, Some(1_781_553_805), true);
        assert!(account_chain_time_bracketed(&linked, Some(&btc_ok)));
        // Not chain-linked → never bracketed, regardless of the anchor.
        let unlinked = vec![pass("account inclusion")];
        assert!(!account_chain_time_bracketed(&unlinked, Some(&drand_ok)));
    }

    #[test]
    fn account_inclusion_half_proof_body_is_malformed_not_pending() {
        // state_hash present but siblings absent → malformed input (exit 2), NOT
        // the reassuring "exists but not yet sealed" PARTIAL.
        let json = serde_json::json!({
            "identity": hex::encode([5u8; 32]),
            "exists": true,
            "state_hash": hex::encode([6u8; 32]),
            // no "siblings"
        });
        let p = write_tmp("elara_verify_acct_halfbody.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_inclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    // ─── Account-exclusion (absence) witness verification ────────────────────

    /// Build a real `/proof/account/{identity}`-shaped NON-EXISTENCE response
    /// for `absent_id` against a tree populated with `present_ids`, using the
    /// same network-agreed account SMT the server folds with. Returns the wire
    /// JSON and the tree root.
    pub(crate) fn account_exclusion_json(
        absent_id: [u8; 32],
        present_ids: &[[u8; 32]],
    ) -> (serde_json::Value, [u8; 32]) {
        use elara_smt::{MemorySmtStore, SparseMerkleTree};
        let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
        for id in present_ids {
            tree.update(id, &sha3_256(id)).expect("update");
        }
        tree.commit().expect("commit");
        let root = tree.root().expect("root");
        let xp = tree
            .exclusion_proof(&absent_id)
            .expect("proof ok")
            .expect("id genuinely absent");
        let json = serde_json::json!({
            "account_id": hex::encode(xp.account_id),
            "identity": hex::encode(xp.account_id),
            "root": hex::encode(xp.root),
            "present": hex::encode(xp.present),
            "siblings": xp.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "exists": false,
        });
        (json, root)
    }

    #[test]
    fn account_exclusion_real_witness_verifies_and_binds_three_ways() {
        let absent = sha3_256(b"never-provisioned-identity");
        let others = [sha3_256(b"id-1"), sha3_256(b"id-2"), sha3_256(b"id-3")];
        let (json, root) = account_exclusion_json(absent, &others);
        let p = write_tmp("elara_verify_axcl_pos.json", &json);

        // The fold passes on a real witness.
        let mut checks = Vec::new();
        let facts = verify_account_exclusion(&p, None, &mut checks).unwrap();
        assert_eq!(facts.root, root);
        assert_eq!(facts.identity, absent);
        assert!(checks.iter().any(|c| c.name == "account exclusion" && c.status == Status::Pass));

        // Bind via a --seal that committed this root → Pass.
        let mut c1 = Vec::new();
        verify_core::bind_sealed_account_root(&mut c1, facts.root, None, Some(root)).unwrap();
        assert!(c1.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Pass));

        // Bind via a --seal that committed a DIFFERENT root → Fail (the guard).
        let mut c2 = Vec::new();
        verify_core::bind_sealed_account_root(&mut c2, facts.root, None, Some([7u8; 32])).unwrap();
        assert!(c2.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Fail));

        // Bind via matching --expect-root → Pass; no binding at all → PARTIAL
        // (an unbound absence claim must never read as a green).
        let mut c3 = Vec::new();
        verify_core::bind_sealed_account_root(&mut c3, facts.root, Some(&hex::encode(root)), None).unwrap();
        assert!(c3.iter().any(|c| c.name == "sealed account-root bind" && c.status == Status::Pass));
        let mut c4 = Vec::new();
        verify_core::bind_sealed_account_root(&mut c4, facts.root, None, None).unwrap();
        assert!(c4.iter().any(|c| c.name == "sealed account-root bind" && c.status == Status::Partial));
        assert_eq!(Verdict::of(&c4), Verdict::Partial);
    }

    #[test]
    fn account_exclusion_for_present_identity_fails_fold() {
        // An "absence witness" for an identity that IS in the tree: take the
        // present identity's real sibling set (from its inclusion proof) and
        // recast it as an exclusion payload. The empty leaf cannot reconstruct
        // the root where a real leaf exists → the fold must Fail, never pass.
        let identity = sha3_256(b"existing-id");
        let (incl, root) = account_proof_json(identity, sha3_256(b"state"));
        let json = serde_json::json!({
            "identity": incl["identity"],
            "root": incl["root"],
            "present": incl["present"],
            "siblings": incl["siblings"],
            "exists": false,
        });
        let p = write_tmp("elara_verify_axcl_present.json", &json);
        let mut checks = Vec::new();
        let facts = verify_account_exclusion(&p, None, &mut checks).unwrap();
        assert_eq!(facts.root, root);
        assert!(checks.iter().any(|c| c.name == "account exclusion" && c.status == Status::Fail));
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
    }

    #[test]
    fn account_exclusion_routes_inclusion_payload_to_the_right_flag() {
        // A payload with `state_hash` is an inclusion response — the server
        // asserts presence. Grading it as absence is a category error → exit 2.
        let identity = sha3_256(b"present-id");
        let (json, _root) = account_proof_json(identity, sha3_256(b"state"));
        let p = write_tmp("elara_verify_axcl_inclshape.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_exclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
        assert!(checks.is_empty(), "routing errors must not push gradeable checks");
    }

    #[test]
    fn account_exclusion_rejects_record_proof_shape() {
        let json = serde_json::json!({
            "leaf": hex::encode([1u8; 32]),
            "root": hex::encode([2u8; 32]),
            "siblings": [],
        });
        let p = write_tmp("elara_verify_axcl_recordshape.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_exclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_exclusion_exists_true_and_pending_are_input_errors() {
        // exists:true (presence claim) and pending_first_seal (neither claim is
        // provable against a sealed root yet) both route out with exit 2.
        let exists_true = serde_json::json!({
            "identity": hex::encode([3u8; 32]),
            "exists": true,
            "root": hex::encode([0u8; 32]),
        });
        let p1 = write_tmp("elara_verify_axcl_exists.json", &exists_true);
        let mut c1 = Vec::new();
        let err = verify_account_exclusion(&p1, None, &mut c1).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));

        let pending = serde_json::json!({
            "identity": hex::encode([4u8; 32]),
            "exists": true,
            "pending_first_seal": true,
            "bound_to_seal": false,
            "root": hex::encode([9u8; 32]),
        });
        let p2 = write_tmp("elara_verify_axcl_pending.json", &pending);
        let mut c2 = Vec::new();
        let err = verify_account_exclusion(&p2, None, &mut c2).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_exclusion_bare_root_legacy_response_is_input_error() {
        // Pre-witness servers answered absence with a bare root — a
        // trust-the-server claim with NO cryptographic witness. Grading it
        // would be exactly the fail-open this leg exists to kill.
        let json = serde_json::json!({
            "identity": hex::encode([5u8; 32]),
            "exists": false,
            "root": hex::encode([8u8; 32]),
        });
        let p = write_tmp("elara_verify_axcl_bareroot.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_exclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
        assert!(checks.is_empty());
    }

    #[test]
    fn account_exclusion_expect_identity_mismatch_fails() {
        let absent = sha3_256(b"absent-id");
        let (json, _root) = account_exclusion_json(absent, &[sha3_256(b"other")]);
        let p = write_tmp("elara_verify_axcl_idpin.json", &json);
        let mut checks = Vec::new();
        // Ask about a DIFFERENT identity than the witness proves absent — the
        // inversion trap: "some other id is absent" must never read as "yours is".
        let want = hex::encode(sha3_256(b"the-id-i-actually-queried"));
        let _ = verify_account_exclusion(&p, Some(&want), &mut checks).unwrap();
        assert!(checks.iter().any(|c| c.name == "account identity" && c.status == Status::Fail));
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
    }

    #[test]
    fn account_exclusion_conflicting_identity_fields_error() {
        // `identity` and `account_id` naming DIFFERENT ids is self-inconsistent:
        // silently picking one would let a server display one identity while
        // proving absence of another.
        let (mut json, _root) = account_exclusion_json(sha3_256(b"absent"), &[sha3_256(b"x")]);
        json["account_id"] = serde_json::Value::from(hex::encode(sha3_256(b"different")));
        let p = write_tmp("elara_verify_axcl_conflict.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_exclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_exclusion_sibling_overflow_and_half_witness_error() {
        // >256 siblings → rejected before the fold (alloc-amplification guard).
        let (mut json, _root) = account_exclusion_json(sha3_256(b"absent"), &[sha3_256(b"y")]);
        let flood: Vec<_> = (0..257).map(|_| hex::encode([1u8; 32])).collect();
        json["siblings"] = serde_json::Value::from(flood);
        let p = write_tmp("elara_verify_axcl_flood.json", &json);
        let mut checks = Vec::new();
        let err = verify_account_exclusion(&p, None, &mut checks).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));

        // present without siblings (half a witness) → malformed, exit 2.
        let half = serde_json::json!({
            "identity": hex::encode([6u8; 32]),
            "exists": false,
            "root": hex::encode([7u8; 32]),
            "present": hex::encode([0u8; 32]),
        });
        let p2 = write_tmp("elara_verify_axcl_half.json", &half);
        let mut c2 = Vec::new();
        let err = verify_account_exclusion(&p2, None, &mut c2).unwrap_err();
        assert_eq!(format!("{err:?}"), format!("{:?}", ExitCode::from(2)));
    }

    #[test]
    fn account_exclusion_empty_tree_folds_but_stays_partial_unbound() {
        // The trivial trick: an EMPTY tree "proves" any identity absent (all-zero
        // present, no siblings, root = the empty hash). The fold legitimately
        // passes — and the root binding is what keeps it meaningless: an empty
        // root can never equal a real sealed root, and with no binding the run
        // is capped at PARTIAL. Pins the posture the prose CAUTION documents.
        let (json, root) = account_exclusion_json(sha3_256(b"anything"), &[]);
        assert_eq!(root, elara_smt::EMPTY_HASH);
        let p = write_tmp("elara_verify_axcl_empty.json", &json);
        let mut checks = Vec::new();
        let facts = verify_account_exclusion(&p, None, &mut checks).unwrap();
        assert!(checks.iter().any(|c| c.name == "account exclusion" && c.status == Status::Pass));
        // Unbound → PARTIAL overall; bound against a REAL sealed root → Fail.
        verify_core::bind_sealed_account_root(&mut checks, facts.root, None, None).unwrap();
        assert_eq!(Verdict::of(&checks), Verdict::Partial);
        let mut c2 = Vec::new();
        verify_core::bind_sealed_account_root(&mut c2, facts.root, None, Some(sha3_256(b"real sealed root"))).unwrap();
        assert!(c2.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Fail));
    }

    #[test]
    fn account_exclusion_empty_witness_cannot_bind_a_nonempty_account_seal() {
        // REGRESSION (fusion audit 2026-07-06, CRITICAL fail-open): an
        // empty-account-tree exclusion witness folds to EMPTY_HASH. A real
        // anchor-signed seal for an empty RECORD zone commits
        // epoch_sparse_merkle_root == EMPTY_HASH — so the OLD untyped union
        // bind (seal_roots.contains(root)) let that witness bind, certifying a
        // fabricated absence for ANY identity (incl. present ones) as VERIFIED.
        // The typed bind compares ONLY against the seal's account root, so an
        // empty witness can never bind a seal whose account tree is non-empty.
        let (empty_witness, empty_root) = account_exclusion_json(sha3_256(b"victim-present-id"), &[]);
        assert_eq!(empty_root, elara_smt::EMPTY_HASH, "empty tree must fold to EMPTY_HASH");
        let p = write_tmp("elara_verify_axcl_regression.json", &empty_witness);
        let mut checks = Vec::new();
        let facts = verify_account_exclusion(&p, None, &mut checks).unwrap();
        // The fold itself passes (it IS a valid empty-tree witness)…
        assert!(checks.iter().any(|c| c.name == "account exclusion" && c.status == Status::Pass));
        // …but binding it against a seal whose ACCOUNT root is NON-empty must
        // FAIL — even though that same seal's record/zone roots (the old union)
        // could contain EMPTY_HASH. The typed API only accepts the account root,
        // so the cross-type match is now structurally impossible.
        let nonempty_account_root = sha3_256(b"seal committed a populated account tree");
        verify_core::bind_sealed_account_root(&mut checks, facts.root, None, Some(nonempty_account_root)).unwrap();
        assert!(
            checks.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Fail),
            "empty EMPTY_HASH witness must NOT bind a non-empty account seal"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
        // And an empty witness against a genuinely-EMPTY account seal binds and
        // is TRUE (universal absence held at that seal) — the benign case the
        // fix must preserve, not over-reject.
        let mut c2 = Vec::new();
        let facts2 = verify_account_exclusion(&p, None, &mut c2).unwrap();
        verify_core::bind_sealed_account_root(&mut c2, facts2.root, None, Some(elara_smt::EMPTY_HASH)).unwrap();
        assert!(c2.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Pass));
    }

    #[test]
    fn absence_chain_predicates_never_cross_with_presence_legs() {
        let pass = |name: &'static str| Check { name, status: Status::Pass, detail: String::new() };
        // Full absence chain → absence predicate true, presence predicate false.
        let absence = vec![pass("account exclusion"), pass("account-root↔seal"), pass("seal↔anchor")];
        assert!(chain_is_account_absence_bound(&absence));
        assert!(!chain_is_account_bound(&absence));
        // Full presence chain → the mirror.
        let presence = vec![pass("account inclusion"), pass("account-root↔seal"), pass("seal↔anchor")];
        assert!(chain_is_account_bound(&presence));
        assert!(!chain_is_account_absence_bound(&presence));
        // Missing the anchor link → not bracketable either way.
        let no_anchor = vec![pass("account exclusion"), pass("account-root↔seal")];
        assert!(!chain_is_account_absence_bound(&no_anchor));
        // Time bracket additionally requires a PROVEN anchor bound.
        assert!(!account_absence_time_bracketed(&absence, None));
        // crown-F1: drand-only is the ANCHOR's freshness, NOT a trustless seal
        // bound (the seal predates the anchor) → NOT bracketed.
        let drand_ok = anchor_summary(true, None, false);
        assert!(!account_absence_time_bracketed(&absence, Some(&drand_ok)));
        let unproven = anchor_summary(false, None, false);
        assert!(!account_absence_time_bracketed(&absence, Some(&unproven)));
        // A PIN-authenticated (trustless) Bitcoin existed-by → bracketed.
        let btc_ok = anchor_summary(false, Some(1_781_553_805), true);
        assert!(account_absence_time_bracketed(&absence, Some(&btc_ok)));
    }
}

/// Gate C of the 2026-07 launch plan: deterministic hostile-input battery for
/// the stranger-facing verifier. The unwrap/expect surface was verified ZERO
/// (fusion Opus pass, 2026-07-02); this corpus pins the residual class that
/// grep can't see — slice indexing and arithmetic on attacker-controlled
/// bytes. Every case asserts "returns, never panics"; exact Err text is
/// deliberately not asserted so error-message wording can evolve.
#[cfg(test)]
mod hostile_input_tests {
    use super::*;

    #[test]
    fn varint_hostile_battery() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x80],
            vec![0x80; 20],
            vec![0xff; 10],
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ];
        for c in &cases {
            let mut pos = 0usize;
            let _ = read_varint(c, &mut pos); // must return, never panic
            let mut pos = c.len(); // pos already at/near end
            let _ = read_varint(c, &mut pos);
        }
    }

    #[test]
    fn varbytes_length_lies() {
        // Declared length far beyond the buffer, max-varint lengths, zero.
        let mut lying: Vec<u8> = vec![0xff, 0xff, 0xff, 0x7f]; // huge declared len
        lying.extend_from_slice(b"short");
        for buf in [&lying[..], &[0x05][..], &[0x00][..], &[][..]] {
            let mut pos = 0usize;
            let _ = read_varbytes(buf, &mut pos);
        }
    }

    #[test]
    fn ots_garbage_battery() {
        const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00";
        let digest = [0u8; 32];
        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            b"garbage".to_vec(),
            MAGIC.to_vec(), // magic then truncated
        ];
        // magic + version + adversarial tag soups (deterministic patterns)
        for filler in [0x00u8, 0x08, 0xf0, 0xff, 0x51] {
            let mut v = MAGIC.to_vec();
            v.push(0x01); // version varint
            v.extend(std::iter::repeat(filler).take(64));
            cases.push(v);
        }
        // deep fork nesting to exercise the recursion budget
        let mut deep = MAGIC.to_vec();
        deep.push(0x01);
        deep.extend(std::iter::repeat(0xff).take(4096));
        cases.push(deep);
        for c in &cases {
            let _ = ots_bitcoin_attestations(c, &digest); // must return, never panic
        }
    }

    #[test]
    fn anchor_file_hostile_battery() {
        let dir = std::env::temp_dir().join(format!("elara-hostile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases: &[(&str, &[u8])] = &[
            ("empty.json", b""),
            ("nonutf8.json", &[0xff, 0xfe, 0x00, 0x9f, 0x92, 0x96]),
            ("truncated.json", b"{\"seal\": {\"epoch\":"),
            ("wrong-shape.json", b"[]"),
            ("wrong-types.json", b"{\"seal\": 7, \"zone\": [true], \"epoch\": \"x\"}"),
            (
                "huge-numbers.json",
                b"{\"epoch\": 18446744073709551615, \"round\": 99999999999999999999}",
            ),
        ];
        for (name, bytes) in cases {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            let mut checks = Vec::new();
            let _ = verify_anchor(&p, &mut checks); // Err(exit) is fine; panic is the bug
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drand_not_before_extremes_pinned_saturating() {
        assert_eq!(drand_not_before(u64::MAX, u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(drand_not_before(0, 0, 0), 0);
        assert_eq!(drand_not_before(1, 5, 100), 5);
        let _ = drand_not_before(u64::MAX, 0, 2);
    }

    #[test]
    fn flexible_u64_hostile() {
        for v in [
            serde_json::json!("not-a-number"),
            serde_json::json!(-1),
            serde_json::json!(1.5e300),
            serde_json::json!({"n": 1}),
            serde_json::json!(null),
            serde_json::json!("18446744073709551616"),
        ] {
            let _ = flexible_u64(Some(&v));
        }
        let _ = flexible_u64(None);
    }
    // ── Gate C seeded fuzz sweeps (July plan, the internal roadmap) ──
    //
    // The fixed-vector hostile batteries above pin known adversarial shapes;
    // these sweeps add the EMPIRICAL layer: deterministically-seeded
    // structured-random + valid-then-mutated inputs at scale, mirroring
    // `src/decoder_fuzz.rs` (that module is cfg(test) inside the lib and
    // invisible to a bin target, so the tiny splitmix64 harness is local).
    // Targets: the binary-owned legs a hostile "anchor bundle" fully controls —
    // the OTS proof walk, the archived-header parse, and the drand-BLS
    // envelope. Any panic is caught and re-raised with seed + iteration so a
    // failure replays exactly.

    struct FuzzRng(u64);

    impl FuzzRng {
        fn new(seed: u64) -> Self {
            FuzzRng(seed)
        }
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

    /// One structural mutation — bit-flip / truncate / extend / clobber-prefix
    /// (the decoder_fuzz `mutate` verbatim).
    fn fz_mutate(rng: &mut FuzzRng, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match rng.below(4) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1u8 << rng.below(8);
            }
            1 if !v.is_empty() => v.truncate(rng.below(v.len())),
            2 => {
                for _ in 0..rng.below(8) {
                    v.push((rng.next_u64() & 0xff) as u8);
                }
            }
            _ => {
                for b in v.iter_mut().take(2) {
                    *b = (rng.next_u64() & 0xff) as u8;
                }
            }
        }
        v
    }

    fn fz_fixture(name: &str) -> Vec<u8> {
        let p = format!("{}/examples/verify/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {p} unreadable: {e}"))
    }

    /// Catch-unwind wrapper: the invariant is the call RETURNS — Ok or Err both
    /// fine, a panic (or abort) is the bug.
    fn fz_assert_returns(name: &str, seed: u64, i: usize, f: impl FnOnce()) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        assert!(
            r.is_ok(),
            "{name} PANICKED — not fail-closed. seed={seed:#x} iter={i}",
        );
    }

    /// A structurally-valid OTS prologue for `digest`: magic + version magic +
    /// version varint + sha256 file-op + the 32-byte digest. Everything after
    /// this prefix reaches `ots_walk` — the recursive region the fixed
    /// batteries above never enter (their deep case dies at the file-op check).
    fn ots_prologue(digest: &[u8; 32]) -> Vec<u8> {
        let mut v = b"\x00OpenTimestamps\x00\x00Proof\x00".to_vec();
        v.extend_from_slice(&[0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
        v.push(0x01); // version varint
        v.push(0x08); // file op = sha256
        v.extend_from_slice(digest);
        v
    }

    #[test]
    fn fuzz_ots_walk_random_tails_are_fail_closed() {
        // Random bytes AFTER a valid prologue — every iteration enters the
        // recursive walk itself, not the early header rejects.
        let digest = [0x5au8; 32];
        let prologue = ots_prologue(&digest);
        let seed = 0xE1A2_0020u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..30_000 {
            let mut buf = prologue.clone();
            let n = rng.below(257);
            for _ in 0..n {
                // Bias toward the bytes the walk branches on (tags + varints).
                buf.push(match rng.below(8) {
                    0 => 0x00,
                    1 => 0x08,
                    2 => 0xf0,
                    3 => 0xf1,
                    4 => 0xff,
                    _ => (rng.next_u64() & 0xff) as u8,
                });
            }
            fz_assert_returns("ots_bitcoin_attestations(random-tail)", seed, i, || {
                let _ = ots_bitcoin_attestations(&buf, &digest);
            });
        }
    }

    #[test]
    fn fuzz_ots_mutated_real_proof_is_fail_closed() {
        // The shipped 2 KB Bitcoin-calendar proof, one mutation per iteration —
        // the almost-valid class that walks deepest.
        let ots = fz_fixture("epoch-41340-zone-0.json.ots");
        let real_digest: [u8; 32] = Sha256::digest(fz_fixture("epoch-41340-zone-0.json")).into();
        let seed = 0xE1A2_0021u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..20_000 {
            let m = fz_mutate(&mut rng, &ots);
            // Rotate the expected digest: the real one keeps the walk reachable,
            // a random one exercises the mismatch arm.
            let d = if rng.below(4) == 0 {
                let mut x = [0u8; 32];
                for b in x.iter_mut() {
                    *b = (rng.next_u64() & 0xff) as u8;
                }
                x
            } else {
                real_digest
            };
            fz_assert_returns("ots_bitcoin_attestations(mutated-fixture)", seed, i, || {
                let _ = ots_bitcoin_attestations(&m, &d);
            });
        }
    }

    #[test]
    fn ots_recursion_depth_probe_returns_err_not_stack_overflow() {
        // FOUND-BUG RECEIPT (2026-07-02): the original mutually-recursive walk
        // (ots_walk ⇄ ots_do_tag, one call-stack level per chained op) DIED
        // HERE — a ~4 KB proof of OTS_MAX_OPS chained sha256 ops (0x08)
        // overflowed the 2 MiB test-thread stack (SIGABRT). The walk is now
        // iterative (explicit heap stack); this probe pins that property
        // EMPIRICALLY, since a stack overflow aborts and cannot be caught.
        // If this test ever dies with SIGSEGV/abort again, the walk has
        // regressed to unbounded call-stack depth — do not delete the probe.
        let digest = [0x11u8; 32];
        let mut deep = ots_prologue(&digest);
        deep.extend(std::iter::repeat(0x08).take(OTS_MAX_OPS + 64));
        let r = ots_bitcoin_attestations(&deep, &digest);
        assert!(r.is_err(), "budget-exhausted proof must Err (walk returned Ok)");

        // Branch-flood variant: 0xff branch markers each recursing via a
        // chained-op branch — the while-loop nesting path.
        let mut fanout = ots_prologue(&digest);
        for _ in 0..OTS_MAX_OPS {
            fanout.push(0xff);
            fanout.push(0x08);
        }
        let r2 = ots_bitcoin_attestations(&fanout, &digest);
        assert!(r2.is_err(), "branch-flood proof must Err (walk returned Ok)");
    }

    #[test]
    fn fuzz_ots_varint_varbytes_random_sweep() {
        // Direct primitive sweep at scale (the batteries above pin ~10 shapes).
        let seed = 0xE1A2_0022u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..30_000 {
            let n = rng.below(64);
            let buf: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 0xff) as u8).collect();
            let start = if buf.is_empty() { 0 } else { rng.below(buf.len() + 1) };
            fz_assert_returns("read_varint/read_varbytes", seed, i, || {
                let mut pos = start;
                let _ = read_varint(&buf, &mut pos);
                let mut pos = start;
                let _ = read_varbytes(&buf, &mut pos);
            });
        }
    }

    #[test]
    fn fuzz_load_btc_header_mutated_archive_is_fail_closed() {
        // The archived-header file is operator-supplied (a hostile bundle
        // controls it byte-for-byte). Mutate the REAL shipped header archive —
        // hex lines, key:value framing, the 80-byte header slice arithmetic.
        let real = fz_fixture("btc-header-957487.txt");
        let dir =
            std::env::temp_dir().join(format!("elara-fuzz-hdr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("btc-header-957487.txt");
        let seed = 0xE1A2_0023u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..2_048 {
            let m = fz_mutate(&mut rng, &real);
            std::fs::write(&path, &m).unwrap();
            fz_assert_returns("load_btc_header(mutated-archive)", seed, i, || {
                let _ = load_btc_header(&dir, 953_657);
            });
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fuzz_verify_drand_bls_structured_envelopes_are_fail_closed() {
        // Structured random drand envelopes: signature / previous_signature /
        // randomness hex rotated across the lengths the G2/BLS layer branches
        // on (real chained sigs are 96 bytes), rounds at the arithmetic
        // extremes. Iteration count is pairing-budgeted (a well-formed 96-byte
        // point that parses costs a debug-mode pairing attempt).
        let seed = 0xE1A2_0024u64;
        let mut rng = FuzzRng::new(seed);
        let hex_of = |rng: &mut FuzzRng, kind: usize| -> serde_json::Value {
            let n = match kind {
                0 => 96,              // real G2 signature size
                1 => 48,              // G1-sized (wrong group)
                2 => rng.below(200),  // arbitrary
                _ => 95,              // off-by-one
            };
            let s: String = (0..n).map(|_| format!("{:02x}", rng.next_u64() & 0xff)).collect();
            serde_json::Value::String(s)
        };
        for i in 0..768 {
            let mut obj = serde_json::Map::new();
            if rng.below(8) != 0 {
                let k = rng.below(4);
                obj.insert("drand_signature".into(), hex_of(&mut rng, k));
            }
            if rng.below(8) != 0 {
                let k = rng.below(4);
                obj.insert("previous_signature".into(), hex_of(&mut rng, k));
            }
            if rng.below(4) != 0 {
                let k = rng.below(4);
                obj.insert("drand_randomness".into(), hex_of(&mut rng, k));
            }
            if rng.below(4) == 0 {
                obj.insert("drand_signature".into(), serde_json::json!(12345));
            }
            let obj = serde_json::Value::Object(obj);
            let round = match rng.below(4) {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                _ => rng.next_u64(),
            };
            let chain: Option<String> = match rng.below(3) {
                0 => None,
                1 => Some(LOE_DEFAULT_CHAIN_HASH.into()),
                _ => Some("deadbeef".into()),
            };
            let assumed = rng.next_u64() & 1 == 0;
            fz_assert_returns("verify_drand_bls(structured)", seed, i, || {
                let _ = verify_drand_bls(&obj, round, chain.as_deref(), assumed);
            });
        }
    }

    #[test]
    fn fuzz_verify_anchor_mutated_real_artifact_is_fail_closed() {
        // The top-level hostile-file entry point, on mutations of the REAL
        // shipped anchor artifact with its REAL .ots sitting beside it — the
        // full leg: JSON field walk, flexible_u64 coercions, drand round
        // arithmetic, OTS side-file resolution, header lookup. Iteration count
        // is budgeted for the BLS pairing that runs when the signature fields
        // survive mutation.
        let anchor = fz_fixture("epoch-41340-zone-0.json");
        let ots = fz_fixture("epoch-41340-zone-0.json.ots");
        let dir =
            std::env::temp_dir().join(format!("elara-fuzz-anchor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let apath = dir.join("epoch-41340-zone-0.json");
        std::fs::write(dir.join("epoch-41340-zone-0.json.ots"), &ots).unwrap();
        let seed = 0xE1A2_0025u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..384 {
            let m = fz_mutate(&mut rng, &anchor);
            std::fs::write(&apath, &m).unwrap();
            // Every 8th iteration also corrupts the sidecar proof.
            if rng.below(8) == 0 {
                std::fs::write(dir.join("epoch-41340-zone-0.json.ots"), fz_mutate(&mut rng, &ots))
                    .unwrap();
            } else {
                std::fs::write(dir.join("epoch-41340-zone-0.json.ots"), &ots).unwrap();
            }
            fz_assert_returns("verify_anchor(mutated-fixture)", seed, i, || {
                let mut checks = Vec::new();
                let _ = verify_anchor(&apath, &mut checks);
            });
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── `.elara-receipt` v1 — fail-closed fuzz over the parse→grade glue ───

    #[test]
    fn fuzz_receipt_pipeline_is_fail_closed() {
        use super::tests::{account_exclusion_json, seal_committing, signed_record};
        let no_pins = TrustPins {
            trusted_anchor: &[],
            expected_hash: None,
            expect_root: None,
            expect_identity: None,
            content: None,
        };
        // (a) Random bytes through the full parse→grade pipeline: never panic.
        let seed = 0xE1A2_0030u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..2_000 {
            let len = rng.below(2048);
            let input: Vec<u8> = (0..len).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
            fz_assert_returns("receipt(random)", seed, i, || {
                let mut checks = Vec::new();
                if let Ok(elara_runtime::receipt::ReceiptInput::V1(legs)) =
                    elara_runtime::receipt::parse_receipt_input(&input)
                {
                    let _ = grade_receipt_v1(&legs, &no_pins, &mut checks);
                }
            });
        }
        // (b) Byte-mutated REAL envelope — mutations that survive the envelope
        // parse reach the leg verifiers' arithmetic, exactly like the other
        // mutated-fixture harnesses above.
        let (rec, _) = signed_record(b"fuzz fixture");
        let (xjson, root) = account_exclusion_json([0x77; 32], &[[1; 32], [2; 32]]);
        let (seal_wire, _, _) = seal_committing(root);
        let fixture = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "legs": {
                "record": hex::encode(rec.to_bytes()),
                "seal": hex::encode(&seal_wire),
                "account_exclusion": xjson,
            },
        })
        .to_string()
        .into_bytes();
        let seed = 0xE1A2_1030u64;
        let mut rng = FuzzRng::new(seed);
        for i in 0..2_000 {
            let m = fz_mutate(&mut rng, &fixture);
            fz_assert_returns("receipt(mutated-fixture)", seed, i, || {
                let mut checks = Vec::new();
                if let Ok(elara_runtime::receipt::ReceiptInput::V1(legs)) =
                    elara_runtime::receipt::parse_receipt_input(&m)
                {
                    let _ = grade_receipt_v1(&legs, &no_pins, &mut checks);
                }
            });
        }
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::tests::{account_exclusion_json, seal_committing, signed_record};
    use super::*;

    /// No pins — the "just verify this receipt" invocation.
    fn no_pins() -> TrustPins<'static> {
        TrustPins {
            trusted_anchor: &[],
            expected_hash: None,
            expect_root: None,
            expect_identity: None,
            content: None,
        }
    }

    #[test]
    fn receipt_v1_full_chain_grades_like_flags() {
        // Envelope carrying a signed record + a seal committing the account
        // root + the absence witness for an id NOT in the tree — the whole
        // absence chain in one file, graded with CLI-side pins only.
        let (rec, _) = signed_record(b"receipt evidence");
        let (xjson, root) = account_exclusion_json([0x77; 32], &[[1; 32], [2; 32], [3; 32]]);
        let (seal_wire, anchor_hex, seal_hash_hex) = seal_committing(root);
        let envelope = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "producer": { "node": "test-fixture" },
            "legs": {
                "record": hex::encode(rec.to_bytes()),
                "seal": hex::encode(&seal_wire),
                "account_exclusion": xjson,
            },
        })
        .to_string();
        let elara_runtime::receipt::ReceiptInput::V1(legs) =
            elara_runtime::receipt::parse_receipt_input(envelope.as_bytes()).expect("parses")
        else {
            panic!("expected V1 envelope");
        };
        let anchors = vec![anchor_hex];
        let pins = TrustPins {
            trusted_anchor: &anchors,
            expected_hash: Some(&seal_hash_hex),
            expect_root: None,
            expect_identity: None,
            content: None,
        };
        let mut checks = Vec::new();
        let out = grade_receipt_v1(&legs, &pins, &mut checks).expect("grades");
        // Fact threading: the seal's TYPED account root reached the outcome.
        assert_eq!(out.seal_account_root, Some(root));
        assert!(out.record_hash.is_some() && out.seal_hash.is_some());
        let x = out.absence_facts.as_ref().expect("absence facts");
        // The same binding pass main runs — the witness root binds to THIS seal.
        verify_core::bind_sealed_account_root(&mut checks, x.root, None, out.seal_account_root)
            .expect("bind runs");
        assert!(
            checks.iter().any(|c| c.name == "account-root↔seal" && c.status == Status::Pass),
            "witness root must bind to the receipt's seal"
        );
        assert_eq!(Verdict::of(&checks), Verdict::Verified, "full chain, pinned → VERIFIED");
    }

    #[test]
    fn receipt_v1_unknown_leg_caps_at_partial() {
        let (rec, _) = signed_record(b"receipt evidence");
        let envelope = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "legs": {
                "record": hex::encode(rec.to_bytes()),
                "lineage": { "hops": [] },
            },
        })
        .to_string();
        let elara_runtime::receipt::ReceiptInput::V1(legs) =
            elara_runtime::receipt::parse_receipt_input(envelope.as_bytes()).expect("parses")
        else {
            panic!("expected V1 envelope");
        };
        let mut checks = Vec::new();
        let _ = grade_receipt_v1(&legs, &no_pins(), &mut checks).expect("grades");
        assert!(
            checks.iter().any(|c| c.name == "receipt coverage" && c.status == Status::Partial),
            "unrecognized leg must be disclosed"
        );
        assert_eq!(
            Verdict::of(&checks),
            Verdict::Partial,
            "a green record + an unevaluated leg is PARTIAL, never VERIFIED-with-skips"
        );
    }

    #[test]
    fn receipt_v1_seal_without_trusted_anchor_is_partial_not_error() {
        let (xjson, root) = account_exclusion_json([0x55; 32], &[[9; 32]]);
        let (seal_wire, _anchor_hex, _) = seal_committing(root);
        let legs = elara_runtime::receipt::ReceiptLegs {
            seal_wire: Some(seal_wire),
            account_exclusion: Some(xjson),
            ..Default::default()
        };
        let mut checks = Vec::new();
        let out = grade_receipt_v1(&legs, &no_pins(), &mut checks).expect("grades, not exit-2");
        assert!(
            checks.iter().any(|c| c.name == "seal anchor" && c.status == Status::Partial),
            "ungraded seal must push an honest PARTIAL"
        );
        // No trust root → the seal's roots must NOT thread through.
        assert_eq!(out.seal_account_root, None);
        assert!(out.seal_hash.is_none());
        assert_ne!(Verdict::of(&checks), Verdict::Verified);
    }

    #[test]
    fn receipt_v1_claim_conflicts_and_bad_legs_are_input_errors() {
        // Both account claims in one envelope.
        let (xjson, _) = account_exclusion_json([0x55; 32], &[[9; 32]]);
        let legs = elara_runtime::receipt::ReceiptLegs {
            account_inclusion: Some(serde_json::json!({"state_hash": "00"})),
            account_exclusion: Some(xjson),
            ..Default::default()
        };
        let mut checks = Vec::new();
        let Err(e) = grade_receipt_v1(&legs, &no_pins(), &mut checks) else {
            panic!("both account claims must be an input error");
        };
        assert!(e.contains("one account claim per receipt"), "{e}");
        // Malformed record wire.
        let legs = elara_runtime::receipt::ReceiptLegs {
            record_wire: Some(b"ELRA-not-a-record".to_vec()),
            ..Default::default()
        };
        let mut checks = Vec::new();
        let Err(e) = grade_receipt_v1(&legs, &no_pins(), &mut checks) else {
            panic!("malformed record wire must be an input error");
        };
        assert!(e.contains("not a valid Elara wire record"), "{e}");
    }
}

#[cfg(test)]
mod loe_trust_root_drift_guard {
    /// The pinned League-of-Entropy constants exist in two disjoint feature
    /// graphs — the node fetcher (`node-core`) and the offline verifier crate
    /// (`verify-anchor`) — so they cannot share a `const`. This bin builds with
    /// BOTH graphs (`--features "node verify-cli" --bins`, run by ci.yml and
    /// the deploy gate), making it the one place equality can be pinned
    /// (2026-07-12 sweep A8): verifier and node must never disagree on which
    /// beacon chain "drand" means.
    #[test]
    fn loe_trust_root_matches_node_fetcher() {
        assert_eq!(
            elara_verify::anchor::LOE_DEFAULT_CHAIN_HASH,
            elara_runtime::network::drand_fetch::LOE_CHAIN_HASH,
            "verifier crate and node fetcher pin different LoE chain hashes"
        );
        assert_eq!(
            elara_verify::anchor::LOE_DEFAULT_GENESIS_UNIX,
            elara_runtime::network::drand_fetch::LOE_GENESIS_UNIX,
            "verifier crate and node fetcher pin different LoE genesis times"
        );
        assert_eq!(
            elara_verify::anchor::LOE_DEFAULT_PERIOD_SECS,
            elara_runtime::network::drand_fetch::LOE_PERIOD_SECS,
            "verifier crate and node fetcher pin different LoE round periods"
        );
    }
}
