//! Language-agnostic conformance test vectors for independent implementations.
//!
//! Every value produced here is **derived from the authoritative code paths**
//! (`crypto::hash`, `elara_smt`, `record::ValidationRecord`) — never hand-written
//! — so the published vectors cannot silently disagree with the implementation.
//! `examples/gen_conformance_vectors.rs` writes them to
//! `examples/verify/conformance-vectors.json`; the unit test below pins that
//! committed file against a fresh derivation, so any future change to a hashing
//! recipe fails the test until the vectors are regenerated and reviewed.
//!
//! The intent is the `docs/PROTOCOL-SPEC.md` promise — *implement Elara in any
//! language* — made mechanical: an implementation in Go/Python/JS/… can iterate
//! this one file and self-check the deterministic primitives (SHA3-256, the
//! account-SMT empty/leaf/interior hashing, the full 256-level inclusion-proof
//! fold, identity derivation, record-hash binding, and the *second*,
//! domain-tag-free zone record-membership Merkle proof — `merkle-inclusion`,
//! the cross-zone evidence fold `elara-verify verify-inclusion` checks) with no
//! Rust, no node, and no network. The set also carries an ML-DSA-65 (FIPS 204) signature
//! verification KAT (`mldsa65-sig` + its must-reject twin) — the one vector that
//! needs a post-quantum verifier rather than just a hash, certifying that an
//! independent implementation accepts a valid anchor signature and rejects a
//! forged one. Finally it pins the light-client *binding* keystone
//! (`account-binding` + its must-reject twin): a folded account-proof root is
//! only trustworthy once bound to the `account_smt_root` the anchor-signed
//! header commits to — the must-reject twin is a perfectly VALID proof against
//! the WRONG signed root, the fail-open class the per-tree `*-reject` vectors
//! cannot catch. Finally it pins the trust ROOT the whole chain stands on
//! (`seal-anchor-sig` + its must-reject twin): a real anchor-signed epoch seal,
//! decoded and verified against a caller-pinned anchor key via
//! `light_verify::verify_seal_record_against_anchor` — the ML-DSA-65 signature
//! over the seal's OWN §4.4 preimage (not an arbitrary string), so the PQ
//! primitive is bound to the actual bundled epoch seal whose `account_smt_root` the
//! `account-binding` vector consumes; the must-reject twin pins the same valid
//! seal against the WRONG pinned anchor (untrusted-anchor rejection). See
//! Appendix A of the spec.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;
use crate::record::ValidationRecord;

/// One conformance vector: a named primitive, the spec section it pins, a fully
/// specified input, and the expected output (hex unless the note says otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    /// Stable identifier, e.g. `sha3-256/abc`.
    pub name: String,
    /// Primitive under test: `sha3-256` | `smt-empty` | `smt-leaf` |
    /// `smt-interior` | `smt-proof` | `smt-proof-reject` | `identity-derivation`
    /// | `record-hash` | `merkle-inclusion` | `merkle-inclusion-reject` |
    /// `mldsa65-sig` | `mldsa65-sig-reject` | `account-binding` |
    /// `account-binding-reject` | `seal-anchor-sig` | `seal-anchor-sig-reject`.
    /// A `*-reject` primitive is a MUST-NOT-verify case. For a hash fold,
    /// `expected` is the root the (tampered) input falsely claims and a sound
    /// reproduction must NOT equal it. For `mldsa65-sig*`, `account-binding*` and
    /// `seal-anchor-sig*` the operation is VERIFICATION and `expected` is the
    /// boolean verify result ("true"/"false"), not a hash — so its `*-reject`
    /// twin is direct-compared (`expected = "false"`), never root-inverted.
    pub primitive: String,
    /// `docs/PROTOCOL-SPEC.md` reference, e.g. `§4.4` / `Appendix A.5`.
    pub spec_ref: String,
    /// What an implementation must do to reproduce `expected`.
    pub note: String,
    /// Fully specified input (hex bytes / ascii / structured), keyed by role.
    pub input: serde_json::Value,
    /// Expected output — lowercase hex unless `note` states otherwise.
    pub expected: String,
}

/// The full conformance vector set, as serialized to
/// `examples/verify/conformance-vectors.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVectorSet {
    /// Self-describing preamble for a human opening the file.
    pub about: String,
    /// Pointer to the normative spec.
    pub spec: String,
    /// The vectors, in a stable order.
    pub vectors: Vec<ConformanceVector>,
}

/// One fold step of the **zone record-membership** Merkle tree
/// (`network::merkle`), byte-identical to `network::merkle::verify_proof`:
/// `is_right ⇒ current‖sibling`, else `sibling‖current`, then SHA3-256 of the
/// 64-byte concatenation. Crucially this carries **no domain tag** — unlike the
/// account-SMT's `0x00`/`0x01`-tagged leaf/interior hashing (`elara_smt`). Kept
/// SHA3-only (no `network::` reference) so the generator stays buildable in the
/// default, non-`node` build that feeds the example binary and the public mirror.
fn merkle_inclusion_step(is_right: bool, current: &[u8; 32], sib: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    if is_right {
        combined[..32].copy_from_slice(current);
        combined[32..].copy_from_slice(sib);
    } else {
        combined[..32].copy_from_slice(sib);
        combined[32..].copy_from_slice(current);
    }
    sha3_256(&combined)
}

/// Build the conformance vector set from the authoritative code paths.
///
/// `sample_record_wire` is the canonical wire bytes of
/// `examples/verify/sample-record.wire`; the record-derived vectors
/// (identity + record-hash) are computed from it via `ValidationRecord`.
/// `seal_wire` is the bundled `examples/verify/epoch-<N>-zone-0.seal.wire` (a real
/// anchor-signed epoch seal) and `trusted_anchor_pubkey` is the raw bytes of
/// `examples/verify/zone-0-anchor-pubkey.hex` (the zone-0 validator key that
/// signed it); the `seal-anchor-sig` vectors are derived from them via the
/// authoritative `light_verify::verify_seal_record_against_anchor`.
///
/// Returns `Err` if the record or seal bytes do not decode as a
/// `ValidationRecord`, or the anchor key cannot be derived (the only fallible
/// steps) — keeping this module free of production panics (Lane 2).
pub fn generate_vector_set(
    sample_record_wire: &[u8],
    seal_wire: &[u8],
    trusted_anchor_pubkey: &[u8],
) -> Result<ConformanceVectorSet, String> {
    use elara_smt::{interior_hash, leaf_hash, MemorySmtStore, SparseMerkleTree, EMPTY_HASH};

    let mut vectors: Vec<ConformanceVector> = Vec::new();

    // ── SHA3-256 known-answer tests (FIPS-202) ──────────────────────────────
    for (name, msg) in [
        ("sha3-256/empty", ""),
        ("sha3-256/abc", "abc"),
        ("sha3-256/hello", "hello"),
    ] {
        vectors.push(ConformanceVector {
            name: name.into(),
            primitive: "sha3-256".into(),
            spec_ref: "§2.1 / Appendix A.1".into(),
            note: "SHA3-256 (FIPS-202) of the ASCII input bytes.".into(),
            input: serde_json::json!({ "ascii": msg }),
            expected: hex::encode(sha3_256(msg.as_bytes())),
        });
    }

    // ── Account-SMT empty-subtree sentinel (§6.2) ───────────────────────────
    vectors.push(ConformanceVector {
        name: "smt-empty".into(),
        primitive: "smt-empty".into(),
        spec_ref: "§6.2 / Appendix A".into(),
        note: "Empty-subtree sentinel: EMPTY_HASH = SHA3-256(\"\"). Every \
               unpopulated subtree hashes to this at every level."
            .into(),
        input: serde_json::json!({}),
        expected: hex::encode(EMPTY_HASH),
    });

    // ── Account-SMT leaf hash: SHA3-256(0x00 || key || value) ────────────────
    let leaf_key = [0x11u8; 32];
    let leaf_value = [0x22u8; 32];
    let leaf = leaf_hash(&leaf_key, &leaf_value);
    vectors.push(ConformanceVector {
        name: "smt-leaf".into(),
        primitive: "smt-leaf".into(),
        spec_ref: "§6.2".into(),
        note: "Leaf hash binds key+value under tag 0x00: \
               SHA3-256(0x00 || key || value). Distinct keys never collide even \
               at equal value."
            .into(),
        input: serde_json::json!({
            "tag": "0x00",
            "key": hex::encode(leaf_key),
            "value": hex::encode(leaf_value),
        }),
        expected: hex::encode(leaf),
    });

    // ── Account-SMT interior hash: SHA3-256(0x01 || left || right) ───────────
    // One fold step of a sparse proof: empty sibling on the left, the leaf above
    // on the right.
    vectors.push(ConformanceVector {
        name: "smt-interior/empty-left".into(),
        primitive: "smt-interior".into(),
        spec_ref: "§6.2".into(),
        note: "Interior node combines two children under tag 0x01: \
               SHA3-256(0x01 || left || right). Here left = EMPTY_HASH, \
               right = the `smt-leaf` vector's output — one fold step."
            .into(),
        input: serde_json::json!({
            "tag": "0x01",
            "left": hex::encode(EMPTY_HASH),
            "right": hex::encode(leaf),
        }),
        expected: hex::encode(interior_hash(&EMPTY_HASH, &leaf)),
    });
    let int_left = [0x33u8; 32];
    let int_right = [0x44u8; 32];
    vectors.push(ConformanceVector {
        name: "smt-interior/fixed".into(),
        primitive: "smt-interior".into(),
        spec_ref: "§6.2".into(),
        note: "Interior node with two fixed children — \
               SHA3-256(0x01 || left || right)."
            .into(),
        input: serde_json::json!({
            "tag": "0x01",
            "left": hex::encode(int_left),
            "right": hex::encode(int_right),
        }),
        expected: hex::encode(interior_hash(&int_left, &int_right)),
    });

    // ── Account-SMT inclusion-proof fold (§6.2 / Appendix A) ─────────────────
    // The whole light-client trust model in one vector: fold a *compressed*
    // inclusion proof back to the sealed account-SMT root. The leaf/interior
    // vectors above are the pieces; THIS pins the 256-level traversal an
    // implementer must get exactly right — path = SHA3-256(account_id) (the key
    // is hashed to get the path), MSB-first bit order, fold parent_depth 255→0
    // consuming the non-empty siblings named by `present`, EMPTY_HASH for the
    // omitted ones, and `we_are_right = bit(path, depth)` choosing
    // (sibling, current) vs (current, sibling). Derived from a fixed
    // alice/bob/carol tree so bob's proof carries a *real* non-empty sibling —
    // a single-account proof folds trivially and never pins the sibling order.
    // The expected root is independently pinned to the published `PIN_ABC`
    // constant in the unit test below (the derive-vs-derive tautology break).
    let mut smt = SparseMerkleTree::new(MemorySmtStore::new());
    let acc_alice = sha3_256(b"alice");
    let acc_bob = sha3_256(b"bob");
    let acc_carol = sha3_256(b"carol");
    smt.update(&acc_alice, &sha3_256(b"balance=100"))
        .map_err(|e| format!("conformance smt update(alice) failed: {e}"))?;
    smt.update(&acc_bob, &sha3_256(b"balance=200"))
        .map_err(|e| format!("conformance smt update(bob) failed: {e}"))?;
    smt.update(&acc_carol, &sha3_256(b"balance=300"))
        .map_err(|e| format!("conformance smt update(carol) failed: {e}"))?;
    smt.commit()
        .map_err(|e| format!("conformance smt commit failed: {e}"))?;
    let bob_proof = smt
        .proof(&acc_bob)
        .map_err(|e| format!("conformance smt proof(bob) failed: {e}"))?
        .ok_or_else(|| "conformance: bob absent from tree".to_string())?;
    vectors.push(ConformanceVector {
        name: "smt-proof/bob-in-abc".into(),
        primitive: "smt-proof".into(),
        spec_ref: "§6.2 / Appendix A".into(),
        note: "Fold a compressed account-SMT inclusion proof to its root — the \
               light-client account-proof check, end to end. Steps: \
               leaf = SHA3-256(0x00 || account_id || state_hash); \
               path = SHA3-256(account_id); then fold parent_depth from 255 down \
               to 0: sibling = the next unconsumed `siblings` entry when \
               present-bit[depth] is set, else EMPTY_HASH (= SHA3-256(\"\")); \
               (left, right) = (sibling, current) if bit(path, depth) else \
               (current, sibling); parent = SHA3-256(0x01 || left || right) \
               unless BOTH children are EMPTY_HASH (then parent = EMPTY_HASH). \
               All bits are MSB-first (bit 0 = MSB of byte 0). After the fold, \
               every sibling must be consumed and the result must equal \
               `expected`. From a fixed alice/bob/carol tree, so bob's proof \
               carries a real non-empty sibling that pins the consumption order."
            .into(),
        input: serde_json::json!({
            "account_id": hex::encode(bob_proof.account_id),
            "state_hash": hex::encode(bob_proof.state_hash),
            "present": hex::encode(bob_proof.present),
            "siblings": bob_proof
                .siblings
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
        }),
        expected: hex::encode(bob_proof.root),
    });

    // ── Account-SMT inclusion-proof REJECTION (§6.2 / Appendix A) ────────────
    // The fail-CLOSED twin of smt-proof/bob-in-abc: the SAME proof with one
    // sibling byte flipped. A sound verifier folds it, finds it does NOT
    // reconstruct the sealed root, and REJECTS — the positive vector alone can
    // never catch a fail-OPEN implementation (one that accepts a forged
    // account-state proof, the catastrophic light-client soundness break). This
    // is what lets the language-agnostic set certify "we never fake a green" in
    // a second language, not just the happy path. `expected` is the sealed root
    // the tampered proof falsely claims (PIN_ABC); a conforming fold MUST NOT
    // equal it (the Python harness inverts the comparison for `*-reject`). Pinned
    // in the unit test: the reconstructed proof fails `elara_smt::verify_proof`.
    let mut tampered = bob_proof.siblings.clone();
    // Flip the lowest bit of the first (non-empty) sibling — a single-bit change
    // cascades up the SHA3 fold to a wholly different root. Guarded so this stays
    // panic-free (Lane 2): bob co-resident with alice/carol always has a sibling.
    let first_sibling = tampered
        .first_mut()
        .ok_or_else(|| "conformance: bob proof has no sibling to tamper".to_string())?;
    first_sibling[0] ^= 0x01;
    vectors.push(ConformanceVector {
        name: "smt-proof-reject/bob-tampered-sibling".into(),
        primitive: "smt-proof-reject".into(),
        spec_ref: "§6.2 / Appendix A".into(),
        note: "MUST-REJECT vector — the fail-closed twin of smt-proof/bob-in-abc. \
               Identical inputs EXCEPT the first sibling has its lowest bit \
               flipped. Fold it exactly as `smt-proof`: a correct fold does NOT \
               reconstruct `expected` (the sealed root this tampered proof falsely \
               claims), so a verifier comparing the fold to the trusted sealed \
               root REJECTS it. The check passes iff your fold does NOT equal \
               `expected`. An implementation that still folds to `expected` — or \
               otherwise accepts this proof — is fail-OPEN: it would admit a \
               forged account-state proof, the catastrophic light-client \
               soundness break the positive vector alone cannot detect."
            .into(),
        input: serde_json::json!({
            "account_id": hex::encode(bob_proof.account_id),
            "state_hash": hex::encode(bob_proof.state_hash),
            "present": hex::encode(bob_proof.present),
            "siblings": tampered.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
        expected: hex::encode(bob_proof.root),
    });

    // ── Record-derived vectors (from the real sample record) ─────────────────
    let record = ValidationRecord::from_bytes(sample_record_wire)
        .map_err(|e| format!("examples/verify/sample-record.wire failed to decode: {e:?}"))?;

    vectors.push(ConformanceVector {
        name: "identity-derivation".into(),
        primitive: "identity-derivation".into(),
        spec_ref: "§3.1 / Appendix A.5".into(),
        note: "identity_hash = SHA3-256(creator_public_key). Input is the sample \
               record's public key; the output is its on-chain identity."
            .into(),
        input: serde_json::json!({
            "creator_public_key": hex::encode(&record.creator_public_key),
        }),
        expected: hex::encode(sha3_256(&record.creator_public_key)),
    });

    vectors.push(ConformanceVector {
        name: "record-hash".into(),
        primitive: "record-hash".into(),
        spec_ref: "§4.4 / Appendix A.3".into(),
        note: "Parse the referenced wire record per §4, build signable_bytes per \
               §4.4, then record_hash = SHA3-256(signable_bytes). Reproducing this \
               hash proves your decode + canonicalization are byte-correct."
            .into(),
        input: serde_json::json!({
            "wire_file": "examples/verify/sample-record.wire",
            "wire_sha3_256": hex::encode(sha3_256(sample_record_wire)),
            "record_id": record.id,
        }),
        expected: hex::encode(record.record_hash()),
    });

    // ── Record-inclusion Merkle proof (zone record-membership tree, §11.22.1) ─
    // A SECOND, deliberately DIFFERENT Merkle structure from the account-SMT
    // above — and the single divergence most likely to trip an external
    // implementer who reuses the SMT recipe. The account-SMT (`smt-*`) is
    // domain-separated: leaf = SHA3(0x00‖key‖value), interior = SHA3(0x01‖left‖
    // right). The zone record-membership tree (`network::merkle`) uses NO tags:
    // the leaf is the record hash verbatim and an interior node is
    // SHA3(left‖right). This is the cross-zone settlement-evidence path
    // (`verify_cross_zone_proof`) and exactly the proof `elara-verify
    // verify-inclusion` checks against a sealed root.
    //
    // The leaf is THIS set's own `record-hash` output (the sample record), so the
    // vector chains end-to-end: that record, proven into a sealed zone root. Two
    // levels, sibling-on-the-right at level 0 and sibling-on-the-left at level 1,
    // so BOTH `is_right` branches of the fold are pinned (sibling order is
    // explicit per node here, not derived from a key path as in the SMT). The
    // reconstructed proof is accepted by the authoritative
    // `network::merkle::verify_proof` in the unit test below.
    let incl_leaf = record.record_hash();
    let incl_sib0 = sha3_256(b"elara-merkle-inclusion-sibling-0"); // level 0, is_right = true
    let incl_sib1 = sha3_256(b"elara-merkle-inclusion-sibling-1"); // level 1, is_right = false
    let incl_lvl1 = merkle_inclusion_step(true, &incl_leaf, &incl_sib0); // SHA3(leaf ‖ sib0)
    let incl_root = merkle_inclusion_step(false, &incl_lvl1, &incl_sib1); // SHA3(sib1 ‖ lvl1)
    vectors.push(ConformanceVector {
        name: "merkle-inclusion/sample-record-in-zone".into(),
        primitive: "merkle-inclusion".into(),
        spec_ref: "§11.22.1 / Appendix A.4.1".into(),
        note: "Fold a record-inclusion proof in the zone record-membership tree \
               (network::merkle) to its sealed root — the cross-zone settlement \
               evidence path, and the proof `elara-verify verify-inclusion` checks. \
               UNLIKE the account-SMT (smt-*), this tree carries NO domain tags: the \
               leaf is the record hash verbatim (here the `record-hash` vector's \
               output) and each step combines 64 raw bytes — current||sibling when \
               the sibling is on the right (is_right=true), else sibling||current — \
               then SHA3-256. Fold bottom-up over `siblings` in order; the result \
               MUST equal `expected`. Reusing the account-SMT's 0x00/0x01 tags here \
               is the most likely cross-language mistake."
            .into(),
        input: serde_json::json!({
            "tree": "zone record-membership (network::merkle) — no domain tags",
            "leaf": hex::encode(incl_leaf),
            "record_id": record.id,
            "siblings": [
                { "hash": hex::encode(incl_sib0), "is_right": true },
                { "hash": hex::encode(incl_sib1), "is_right": false },
            ],
        }),
        expected: hex::encode(incl_root),
    });

    // MUST-REJECT twin: flip the lowest bit of the first sibling. A correct fold
    // no longer reaches the sealed root, so a verifier binding the fold to the
    // trusted root REJECTS — the fail-closed property for cross-zone inclusion
    // evidence, the analogue of `smt-proof-reject` for this second tree.
    let mut incl_sib0_tampered = incl_sib0;
    incl_sib0_tampered[0] ^= 0x01;
    vectors.push(ConformanceVector {
        name: "merkle-inclusion-reject/tampered-sibling".into(),
        primitive: "merkle-inclusion-reject".into(),
        spec_ref: "§11.22.1 / Appendix A.4.1".into(),
        note: "MUST-REJECT twin of merkle-inclusion — identical inputs EXCEPT the \
               first sibling has its lowest bit flipped. Fold it exactly as \
               `merkle-inclusion`: a correct fold does NOT reach `expected` (the \
               sealed root this tampered proof falsely claims), so a verifier \
               binding the fold to the trusted sealed root REJECTS it. The check \
               passes iff your fold does NOT equal `expected`. An implementation \
               that still reaches it is fail-OPEN — it would admit forged \
               cross-zone inclusion evidence."
            .into(),
        input: serde_json::json!({
            "tree": "zone record-membership (network::merkle) — no domain tags",
            "leaf": hex::encode(incl_leaf),
            "record_id": record.id,
            "siblings": [
                { "hash": hex::encode(incl_sib0_tampered), "is_right": true },
                { "hash": hex::encode(incl_sib1), "is_right": false },
            ],
        }),
        expected: hex::encode(incl_root),
    });

    // ── Account-proof → signed-header BINDING (§11.22) ───────────────────────
    // The light-client keystone the primitive vectors above leave un-pinned.
    // `smt-proof` certifies a proof folds to ITS OWN claimed root — but a sound
    // light client must ALSO bind that folded root to the `account_smt_root` the
    // trusted, anchor-signed epoch header commits to. Skip the bind and a
    // Byzantine server ships a proof that folds perfectly to a root of ITS
    // choosing — one no anchor ever signed — and a client trusting `proof.root`
    // blindly is fooled into believing a forged balance. This is the fail-OPEN
    // class `smt-proof-reject` structurally CANNOT catch: there the fold is
    // broken; here the fold is VALID and only the context (which header signs the
    // root) is wrong. Reuses bob's real abc-tree proof (folds to PIN_ABC) and is
    // derived from the authoritative
    // `elara_light_client::verify_account_proof_against_header` — the exact
    // verifier real SDK clients call — so the boolean can never drift from it.
    {
        use elara_light_client::{
            verify_account_proof_against_header, LiteAccountStateProof, LiteEpochHeader,
        };
        // bob's inclusion proof, re-expressed in the light-client wire shape
        // (same five fields as `elara_smt::SmtProof`).
        let lite_proof = LiteAccountStateProof {
            account_id: bob_proof.account_id,
            state_hash: bob_proof.state_hash,
            root: bob_proof.root,
            present: bob_proof.present,
            siblings: bob_proof.siblings.clone(),
        };
        // A header committing to the SAME root bob's proof folds to → binds.
        // Only `account_smt_root` is consulted by the binding check; the other
        // header fields are representative placeholders.
        let header_match = LiteEpochHeader {
            zone: "0".into(),
            epoch_number: 8219,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            record_count: 0,
            start: 0.0,
            end: 0.0,
            account_smt_root: Some(bob_proof.root),
            seal_record_hash: None,
        };
        // A header committing to a DIFFERENT root (one bit flipped) → bind fails,
        // even though the proof itself remains perfectly valid.
        let mut wrong_root = bob_proof.root;
        wrong_root[0] ^= 0x01;
        let header_mismatch = LiteEpochHeader {
            account_smt_root: Some(wrong_root),
            ..header_match.clone()
        };
        let accept = verify_account_proof_against_header(&lite_proof, &header_match);
        let reject = verify_account_proof_against_header(&lite_proof, &header_mismatch);

        vectors.push(ConformanceVector {
            name: "account-binding/bob-matches-signed-root".into(),
            primitive: "account-binding".into(),
            spec_ref: "§11.22 / Appendix A.7".into(),
            note: "Two-level light-client account check: fold the inclusion proof \
                   to a root (exactly as `smt-proof`), THEN bind that root to the \
                   `header_account_smt_root` the trusted anchor-signed epoch header \
                   commits to. Accept (`expected = \"true\"`) iff BOTH hold: the \
                   fold reconstructs `proof_root`, AND `proof_root == \
                   header_account_smt_root`. Here the header signs the very root \
                   bob's proof folds to, so the bind holds. `expected` is the \
                   boolean verify result, not a hash."
                .into(),
            input: serde_json::json!({
                "account_id": hex::encode(bob_proof.account_id),
                "state_hash": hex::encode(bob_proof.state_hash),
                "present": hex::encode(bob_proof.present),
                "siblings": bob_proof
                    .siblings
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                "proof_root": hex::encode(bob_proof.root),
                "header_account_smt_root": hex::encode(bob_proof.root),
            }),
            expected: accept.to_string(),
        });

        vectors.push(ConformanceVector {
            name: "account-binding-reject/wrong-signed-root".into(),
            primitive: "account-binding-reject".into(),
            spec_ref: "§11.22 / Appendix A.7".into(),
            note: "MUST-REJECT twin of `account-binding` — the same VALID proof \
                   (it still folds cleanly to `proof_root`), but bound to a header \
                   whose `header_account_smt_root` is a DIFFERENT root (one bit \
                   flipped). Bind it exactly as `account-binding`: the fold succeeds \
                   yet `proof_root != header_account_smt_root`, so a sound verifier \
                   REJECTS (`expected = \"false\"`). Unlike `smt-proof-reject` (a \
                   broken fold), the proof here is internally sound — only the \
                   header context is wrong. An implementation that returns true \
                   anyway is fail-OPEN: it trusts a proof's self-claimed root \
                   without binding it to the anchor-signed root, admitting a forged \
                   account balance. `expected` is the boolean verify result."
                .into(),
            input: serde_json::json!({
                "account_id": hex::encode(bob_proof.account_id),
                "state_hash": hex::encode(bob_proof.state_hash),
                "present": hex::encode(bob_proof.present),
                "siblings": bob_proof
                    .siblings
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                "proof_root": hex::encode(bob_proof.root),
                "header_account_smt_root": hex::encode(wrong_root),
            }),
            expected: reject.to_string(),
        });
    }

    // ── ML-DSA-65 (FIPS 204) signature verification vectors ──────────────────
    // The post-quantum anchor-signature primitive. Unlike the hash vectors this
    // is a VERIFICATION known-answer test: ML-DSA-65 signing is randomized (FIPS
    // 204 hedged), so `signature` is one frozen valid signature — a conformant
    // signer produces a different but equally-valid one. The conformance surface
    // is therefore verification, not signature reproduction. The keypair is
    // derived deterministically from the pinned 32-byte seed (0x00..0x1f), so
    // `public_key` is reproducible; `expected` is the boolean verify result.
    {
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
        let msg = "Elara Protocol ML-DSA-65 (FIPS 204) conformance vector";
        // One frozen, committed valid ML-DSA-65 signature over `msg` under the
        // seed-derived key (signing is randomized, so it is pinned here rather
        // than re-derived). Its validity is asserted by the unit test
        // `mldsa65_signature_vector_verifies_and_reject_is_rejected`.
        let sig_hex = "cd5a495952320e885556d31ef393facb7d434836517a7094ad8b0086a7226fe0aea221fbb3def3936d1530f12967b9d017bc3ea5085212b7b6f3fa36046f39fa0ac4665976736752fb20c21acdaccd93ec1fe10edd5d306f98bbc8357525d585f56cff345d5ecf5bb77aa9bf535772cabfda5295451b83f456856a10cb3bd27b8835371974f72bdb7340b261ace17060d41cb0f6bb22bb5d318ef7c105ff1c87ae354ad64d972ef51c0178b612f29f48682b9f478e4188cd4e3bbdba62fb1b36fc5da036db369691e43533bdd1f9f2c9d9a621c518965dc134a5b1deaef3544164230924877dc2f384e9f7b30d90b908dba4028ec78f68cb8db6fb8651c2057fa57d22e7123594e605865101365ac40b77bbe5d17dd3c85fe85043623ae5650aaac6e9fd61f556d7fbfea42b549f5b4b4f0b99f71e08eae8dec175441e54b45f15faacbb1970e5703ec04566ee0964f6d7b9f548b0d3f4a89260914d1a3610b7293658db4c456eb47f358d5ec1682eb87bd853acf981952b4d978bb8756d591cab57687ae53ff0dadfc728dceab6a8737059bfc5266da6d2514ef17b6a0609ad0bfe27bbd9a180c663c4ff311eab1bff1aba8dd9ab3999b628a16e89c984b0f30ddb17f37be77708ef7f8e3e92df14948a66a07583241e1a066aea47c2eba0079354b21f991793cf45ce6b0efbd79ddbabaaf0d6e0a733ca83a4fa6dabcd8fd4b7ec6768c3c74f783ef14161d5dde9d8f814a4f9335cd50a2ea0fe7741e9a067ee08f6b3c296ad1c40ad7fffacef29c21c6dc1668f963dfa92098dac9060cd4e169950fc386c6ecf4f5980e387117c0694d9e382fc845b031391a49c1b29a02ca225d71cf7481a5a8a8bebe0985bfc3ad25ae0ae45b064d02487f38cb038673a2005f627fd205b587212146daa1060dd863feea0e02fdf5db2a692b552b4954c5ce7c86f3081f728bbdbae4ef0df9f898bfc38726c207ffe5da4044ecd69557d1b8d18526caa46b1aeead6fc895cf0f08b8a3292e084d22125079f717af8bf83559d5c7647ad8061cfab10a12838b2e4368c95afce1574b6b116d8e167aa4063e938f8ad73e694e203f8d4f9350606fe455c577ee11b5f3fdaba76b50802178aff945f36c4321b9fe74153328d85325e6a6e6eb509186a64f1820552aae15c585b9727e31a04e5d3a2e6c2ad0b2196d51c2645a4d67f66ca00fd520d8f885873d97cd0feeec6518de3a20603d9afcc817f43d3d22f91e65b6d29a9a8b24d7871d0f813126f0901370132bff749093692711b557f5a7aa23f6117248273824943017da2fcf1ffd9e348d07b4e4d769f00b685726d2c90d139cb103a519f85bc3b22da779bf1e5f49c9ee5ce557affc886f4aea8cffbb8d9c915c707a81e67a73a61e483871f4f83d474e8c87bb54f826b78bdc648352b140f884845075ee66b4ca214624fbb41964b25b54dc627e9a3c89b1bed4182ecf91e2356e603cdfc403cad3afb7b8e7b6178e52b1ffd18a8f20a594059088c397945822ee30e5c0e2a24ce8558059fc48124874a687548b7e218f25fa6e992e73451169bce0e019806c64eea3a3583cac23c9f5eb5e6bf04fe97894fbb435dbe05bf07bb184aa3a9bab6a9c276a493ed12e7f0bc83839289ddc656f35483826891c211d1c0505a64acb40a0c5a035c4239ab9de0a43a11a7a5091a2ea4d7f997677e8d906f2aece3d9ff0f94c380d3e8b87e62232a26201434ee6f27e1c28ce8e5341be7373e7b6e4c3ff14fe8c693b9d484224de5ee3bc1506210c495531de14070a9939101742ca500cd2639ef30fb46444f54a82b1974b1a3b9edfa37191cd7703d9176b91083487537aad06d83618fd770809c5f188dad66fd9459a83fbd026c516290002e373a11fb928b0b5b8b825d0b766c5f76160f9626c57049c3d4745469531caf0a508000460959bc57dd083eb6453040063d2a8a68dde21919e7af41ac53fb6688b0090eecad3b9496f6068d1c88674501dddc9009f451327984bdb280e3f2fda883c3ef94063d053246bc8ee9fefbc110a81368d095d510aed7e0810c95f6dcb3b49d09150c331fd49d586f58d180149d1c2fc0d479f220edaa7a44c330ee85972754ad7a13ea3d0d12a93d5cc9d613a33dd46f03a2b39ceaf2805df1dd739f16aa4299f24dc8738b1ef247256075b1e9bd7e0c6b031c0e51ef0d6daae9f86d237de6d0838aec7f8c7635b0634ef82587ceddebf8f01cc19ca7b3b746330236b32cfd4eb978d488bfb4874c399049ee13ce07ba8cbb673c1817445104dcde0e8d412445b712f6521026e29a40b03355915a85fba0b1039bd65885fd051ade5f08891f29f7da7fd3a9bc70cd1d02938c0971399c62d44cd7f9d15e454db839b9116e6e4d0eb5a7d68a48c8d984895409dd73ede4822e605714eeaec53cc13718c62d710e43e1db5e6898d8cc7154509b06d9bab8c5855691087a5febf114cacd5c2be30c7fa8736deaaec34caa757eeaa402ad3b244e406486cad6b83b1bbe1c83866e6af95ce8a529b0f533630a6b49ed76d6e57fd4631e6088247418273516eea8786fec0465defb752578eb592bc79e43dfd10ce2a1664d76d7224dc530ed98730adbecb7d4d545bb1ff9bfc6b43ef3a94ec280c42c8858e45aaacf068618c49ed1c6d7a1c21d5908a4434b3c9634060551268c89cac72c1c852a6041c40bef55ef39eb1e45a7f1e839571bb325be4cf990e8b2d3353495c7463d747e20141ffda7e934acb6197b1eab871c1a78320c3d70ebae800cde58dd6c97a268747de766c917d5b90cc6a5f293bb16e2e08b854883618d6a65139e4ff9e6bdf12ceec7bd6c1e23a9e69c2f8566c0e3ccdb6abaecc0f34bc16303ce657314e9d75c9e008693ff71c4961de4fd1c762336f8f110481515bc5f2811f4f04281bbca92b9c0a063e4c944e5858097c72268480003fc041a65da538489ef45aa018a1c1fbfd925de16107141e39d951fde7ba5d9454ff75cb19679df82f45d6f24a8ffa3c327a64284e12cbe9a511875f01fe6de25260a137404d351586e92ded2e3ee8487e6344e839ddb0fe41c646c2dd01510033650245613d60dea0c16b81c71e8b2c17ee93e7b495b5ef7c547d80e88850cea8f87beeb8d2db8d3e58ece979bae81df04316959adaf13a53ba19687ef19b1610258a9f351dcc66db3bd485594c8687f1b051af601cfff19d5ac23e1929d0e0eb0751c2fcc3ef8cb11a31bd87e211f01b8127041ab2214829da59f094878b8f50288afa444101c76d1a3c3e4715592ee50b012b9013b8791a42d43ed1995f81595f2289fae63c85030ceb2bc509bdb1e2cfff79e0ed37a173a303ac04c05274194857bbeabcefacefdd34e69b31dcfee4c0608cc8e3c0e18241969d08b3005dc3fb24a24f9cc083581a8c5064429f0ecb59dbf30c0d23bdceeed1e00046f7ce06c820463945935dd21fdc4e9d4ac804539e7d99657013d13256fa0012d3b930ea05fe624b720e7ae95b864709d5bb61e8a93b852765e0d95fc3100546d09ee016d7cf3e04c21958d4d3e61c7454eaa58c6ecbf9a8b95e3078ed232047ab6f390289df9f5e2251819587f6d1d0a751fc861b50b26a5c568ce764e63b638e3070495f4910b59e8232717f19518b229a4c053e2ca0299b480e9ca8989820c6b5f85bae55c6afe6deba6a561e0040cfc96ca309f3bef24e21f9511abc658a0acf9fb8982507391b8c2546b7a6df8c3d1e5e56db054379e294e16b832c7524feecae1ad59f5fefd937ce588567015120c76c584961241773ef8682f9d333c280ce526fa7704e89387d8a37cd5b019ac30130a573e38cbe4dc6a1f6e7edd579ad1230445085da8036f83395229c5f299999deab528ec842d39e9dfc2ca1855645724b3e14f9518d986c9e6898bd6ee72662fb3a2f6a772fdbdb5dd42320f1160db9f6dc28c2f2f4bd0309aff1554a81f0eb1ba829a327a96b581fca91e08267a3e2f37f0c3907f164c0916c7f74aa9edb39f7c586dcfb3debcecc3f116a8cb208e6db36480e854372e7b9215889460b3f2c985e0801670b91342b21bed38542f532ab91676802d35b7cd1cc09ecef002bd99f2eeeae1b1936ac55fbe35794ef777cda2097c3ef989f4c554a52e894b8aa96497a70c37e86e69afd15675116327d40a7e314faa9f53215cc27cdfb9edde26d0e5004dba75efa44f035358f9c2bf718fedc777813edc0ead4ca6bfa7164a8818a725348a76c0d8f4f503089d6f0cdde19ccf630c8abc93c2411436efbcd39c21d09be00b0646df0976e2ff9813c063a29831732becd320a2fae4426dd2271cc1364d0585bd572050ee1ca2172f282a4d736acb41a5798e1752121fc4e9d86626892aaf473f559b1457ab08881db36f55b3778fc599dee15f8193940fa55fbf9300632a6432745eb6d45f6555c375fb2ee390ab5fa79aaff9e49906deb3171fae4a59a2b800789d256802db44edda1c29749216addbb37b9c6e23c6b4625094f1df39e393a382f5879eaa4228778f54579be30570ac7aef39d4179308f2a570b05940bc86ccfe1d932dae91a751c82abd26c09eaa79141a44495183d10811131e21569da0fd32556a8b99a5d8f2275a6c7eb6bfc9d9f2bae2ebf22d515263d4e100000000000000000000000007101821252b";
        let (mldsa65_pk, _sk) = crate::crypto::pqc::dilithium3_keypair_from_seed(&seed)
            .map_err(|e| format!("ML-DSA-65 keypair-from-seed failed: {e:?}"))?;

        vectors.push(ConformanceVector {
            name: "mldsa65-sig".into(),
            primitive: "mldsa65-sig".into(),
            spec_ref: "§4.4 / Appendix A.6".into(),
            note: "ML-DSA-65 (FIPS 204) signature verification KAT. Derive the \
                   keypair deterministically from `seed` (or use `public_key` \
                   directly), then run your FIPS 204 ML-DSA-65 Verify over \
                   `message_ascii` (ASCII bytes) with an EMPTY context string: it \
                   MUST accept. Signing is randomized, so do NOT expect to \
                   reproduce `signature` byte-for-byte — verification is the \
                   conformance surface. `expected` is the boolean verify result."
                .into(),
            input: serde_json::json!({
                "algorithm": "ML-DSA-65 (FIPS 204), context=empty",
                "seed": hex::encode(seed),
                "public_key": hex::encode(&mldsa65_pk),
                "message_ascii": msg,
                "signature": sig_hex,
            }),
            expected: "true".into(),
        });

        // MUST-REJECT twin: identical key + message, one signature byte flipped.
        let mut tampered = hex::decode(sig_hex)
            .map_err(|e| format!("frozen ML-DSA-65 signature is not valid hex: {e:?}"))?;
        if tampered.is_empty() {
            return Err("frozen ML-DSA-65 signature decoded to empty".into());
        }
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        vectors.push(ConformanceVector {
            name: "mldsa65-sig-reject".into(),
            primitive: "mldsa65-sig-reject".into(),
            spec_ref: "§4.4 / Appendix A.6".into(),
            note: "MUST-REJECT twin of `mldsa65-sig`: identical key and message, \
                   one signature byte flipped. Your FIPS 204 ML-DSA-65 Verify \
                   MUST reject it (return false). Accepting this forged signature \
                   is fail-OPEN — it would admit a forged anchor signature. \
                   `expected` is the boolean verify result."
                .into(),
            input: serde_json::json!({
                "algorithm": "ML-DSA-65 (FIPS 204), context=empty",
                "seed": hex::encode(seed),
                "public_key": hex::encode(&mldsa65_pk),
                "message_ascii": msg,
                "signature": hex::encode(&tampered),
            }),
            expected: "false".into(),
        });
    }

    // ── Epoch-seal anchor-signature verification (§11.3 / §4.2) ──────────────
    // The TRUST ROOT every account/record vector above stands on. `smt-proof` and
    // `account-binding` certify a proof folds to the `account_smt_root` a header
    // commits to — but WHY trust that header's root? Because an anchor signed the
    // epoch seal that carries it. This vector pins exactly that closure: decode a
    // real anchor-signed seal record, rebuild its §4.4 signable bytes, and verify
    // the anchor's ML-DSA-65 signature over them — binding the post-quantum
    // signature primitive (A.6, which signs an ARBITRARY string) to the ACTUAL
    // bundled epoch seal whose `account_smt_root` the `account-binding` vector
    // consumes. Unlike `mldsa65-sig` the signed message is not arbitrary: it is the
    // seal record's own canonical preimage, so reproducing this proves an
    // implementer's record decode AND PQ verify AND anchor-pinning all compose into
    // one trust-anchor check. Derived from the authoritative
    // `light_verify::verify_seal_record_against_anchor` — the exact Gap-1
    // light-client trust closure real SDK clients call — so the boolean can never
    // drift from it.
    let seal_rec = ValidationRecord::from_bytes(seal_wire).map_err(|e| {
        format!("the bundled examples/verify epoch seal wire failed to decode: {e:?}")
    })?;
    let seal_record_hash = seal_rec.record_hash();
    let accept_seal = crate::light_verify::verify_seal_record_against_anchor(
        seal_wire,
        seal_record_hash,
        &[trusted_anchor_pubkey.to_vec()],
    )
    .is_ok();
    vectors.push(ConformanceVector {
        name: "seal-anchor-sig/zone-0".into(),
        primitive: "seal-anchor-sig".into(),
        spec_ref: "§11.3 / §4.2 / Appendix A.8".into(),
        note: "Epoch-seal anchor-signature verification — the light-client trust \
               ROOT. Steps an implementer must reproduce: (1) decode `seal_wire_file` \
               per §4 into a ValidationRecord; (2) recompute record_hash per §4.4 and \
               require it equals `seal_record_hash` (binds the seal to the header you \
               trust); (3) require the record's `creator_public_key` equals \
               `trusted_anchor_public_key` (refuse a seal signed by any unpinned \
               key, even if its self-signature is valid); (4) build signable_bytes \
               per §4.4 and run FIPS 204 ML-DSA-65 Verify(signable_bytes, \
               record.signature, creator_public_key) with an EMPTY context string. \
               Accept (`expected = \"true\"`) iff ALL hold. Unlike `mldsa65-sig` the \
               message is the seal's OWN §4.4 preimage, not an arbitrary string — so \
               this is the one vector binding the PQ signature primitive to the real \
               bundled epoch seal whose `account_smt_root` the `account-binding` vector \
               consumes. Signing is randomized; verification is the conformance \
               surface. `expected` is the boolean verify result, not a hash."
            .into(),
        input: serde_json::json!({
            "operation": "decode seal wire per §4 → ValidationRecord; \
                          require record_hash == seal_record_hash; \
                          require creator_public_key == trusted_anchor_public_key; \
                          build signable_bytes per §4.4; \
                          ML-DSA-65 Verify(signable_bytes, signature, creator_public_key), ctx=empty",
            "seal_wire_file": "examples/verify/epoch-41340-zone-0.seal.wire",
            "seal_wire_sha3_256": hex::encode(sha3_256(seal_wire)),
            "seal_record_hash": hex::encode(seal_record_hash),
            "trusted_anchor_public_key": hex::encode(trusted_anchor_pubkey),
            "epoch": 41340,
            "zone": "0",
        }),
        expected: accept_seal.to_string(),
    });

    // MUST-REJECT twin: the SAME valid, anchor-signed seal, but pinned to a
    // DIFFERENT trusted anchor (the deterministic seed-0x00..0x1f key the
    // `mldsa65-sig` vector uses — structurally valid, definitely NOT the zone-0
    // anchor). The seal's self-signature is perfectly valid; it is rejected because
    // `creator_public_key` is not the pinned anchor — the fail-OPEN class where a
    // light client trusts a seal signed by some key it never pinned (mirrors
    // `account-binding-reject`: a valid object in the wrong trusted context). The
    // authoritative verifier checks anchor membership BEFORE the lattice verify, so
    // this rejects without even running ML-DSA. `expected` is the boolean result.
    let wrong_anchor_seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let (wrong_anchor_pk, _sk) = crate::crypto::pqc::dilithium3_keypair_from_seed(&wrong_anchor_seed)
        .map_err(|e| format!("ML-DSA-65 wrong-anchor keypair-from-seed failed: {e:?}"))?;
    let reject_seal = crate::light_verify::verify_seal_record_against_anchor(
        seal_wire,
        seal_record_hash,
        std::slice::from_ref(&wrong_anchor_pk),
    )
    .is_ok();
    vectors.push(ConformanceVector {
        name: "seal-anchor-sig-reject/wrong-anchor".into(),
        primitive: "seal-anchor-sig-reject".into(),
        spec_ref: "§11.3 / §4.2 / Appendix A.8".into(),
        note: "MUST-REJECT twin of `seal-anchor-sig`: the SAME valid, anchor-signed \
               seal, but with `trusted_anchor_public_key` set to a DIFFERENT key \
               (the seed-0x00..0x1f ML-DSA-65 key — not the zone-0 anchor). Verify it \
               exactly as `seal-anchor-sig`: the seal's `creator_public_key` is NOT \
               the pinned anchor, so a sound verifier REJECTS (`expected = \"false\"`) \
               at the anchor-membership check, before spending CPU on the lattice \
               verify. Unlike `mldsa65-sig-reject` (a tampered signature), the \
               signature here is perfectly valid — only the pinned trust context is \
               wrong. An implementation that accepts it is fail-OPEN: it would trust \
               a seal signed by a key the operator never pinned, the catastrophic \
               trust-root break. `expected` is the boolean verify result."
            .into(),
        input: serde_json::json!({
            "operation": "same as seal-anchor-sig, but creator_public_key != \
                          trusted_anchor_public_key → REJECT at the anchor-membership check",
            "seal_wire_file": "examples/verify/epoch-41340-zone-0.seal.wire",
            "seal_wire_sha3_256": hex::encode(sha3_256(seal_wire)),
            "seal_record_hash": hex::encode(seal_record_hash),
            "trusted_anchor_public_key": hex::encode(&wrong_anchor_pk),
            "epoch": 41340,
            "zone": "0",
        }),
        expected: reject_seal.to_string(),
    });

    Ok(ConformanceVectorSet {
        about:
            "Language-agnostic conformance vectors for the Elara Protocol. Every \
             `expected` is derived from the reference implementation (see \
             docs/PROTOCOL-SPEC.md Appendix B), not hand-written — an independent \
             implementation that reproduces all of them is byte-compatible on \
             these deterministic primitives. No node, no network required. \
             Regenerate with `cargo run --example gen_conformance_vectors`."
                .into(),
        spec: "docs/PROTOCOL-SPEC.md".into(),
        vectors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_wire() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/verify/sample-record.wire"
        );
        std::fs::read(path).expect("read examples/verify/sample-record.wire")
    }

    fn seal_wire() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/verify/epoch-41340-zone-0.seal.wire"
        );
        std::fs::read(path).expect("read examples/verify/epoch-41340-zone-0.seal.wire")
    }

    fn anchor_pubkey() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/verify/zone-0-anchor-pubkey.hex"
        );
        let h = std::fs::read_to_string(path).expect("read examples/verify/zone-0-anchor-pubkey.hex");
        hex::decode(h.trim()).expect("zone-0-anchor-pubkey.hex is valid hex")
    }

    /// The single derivation entry point every test shares: feeds all three
    /// committed inputs (sample record wire, bundled epoch seal wire, zone-0 anchor
    /// pubkey) to the authoritative generator.
    fn derive() -> ConformanceVectorSet {
        generate_vector_set(&sample_wire(), &seal_wire(), &anchor_pubkey())
            .expect("derive conformance vectors")
    }

    /// The drift guard: the committed JSON MUST equal a fresh derivation from
    /// code. If a hashing recipe changes, this fails until the file is
    /// regenerated (`cargo run --example gen_conformance_vectors`) and reviewed.
    #[test]
    fn committed_conformance_vectors_match_authoritative_derivation() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/verify/conformance-vectors.json"
        );
        let bytes = std::fs::read(path)
            .expect("read examples/verify/conformance-vectors.json (regenerate if missing)");
        let committed: ConformanceVectorSet =
            serde_json::from_slice(&bytes).expect("parse committed conformance vectors");
        let fresh = derive();
        assert_eq!(
            committed, fresh,
            "examples/verify/conformance-vectors.json is stale — regenerate with \
             `cargo run --example gen_conformance_vectors`"
        );
    }

    /// Independent cross-check of the headline SMT invariant, so the vector set
    /// can't quietly ship a wrong empty-sentinel.
    #[test]
    fn smt_empty_sentinel_is_sha3_of_empty_string() {
        assert_eq!(elara_smt::EMPTY_HASH, sha3_256(b""));
    }

    /// Pin the published SHA3-256("abc") KAT against the FIPS-202 constant.
    #[test]
    fn sha3_abc_matches_fips202_constant() {
        assert_eq!(
            hex::encode(sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    /// Pin the protocol-SPECIFIC SMT domain-separation to fixed published
    /// constants, recomputed from the documented `tag || …` byte layout (§6.2)
    /// via the raw SHA3 primitive — NOT `elara_smt`'s helpers. The drift guard
    /// above only checks JSON == fresh derivation (both sides call the same
    /// `leaf_hash`/`interior_hash`), so a wrong tag byte or concat order would
    /// pass it silently — yet that is exactly the first thing an external
    /// implementer gets wrong reproducing these vectors. This breaks the
    /// derive-vs-derive tautology: published hex == documented-layout recompute
    /// == library output, all three pinned in one place. The same constants are
    /// independently reproduced in a second language — pure-`hashlib`, no Rust —
    /// by `examples/verify/verify_conformance.py` (run as leg 0 of `verify.sh`),
    /// which is the genuinely non-tautological cross-check.
    #[test]
    fn smt_domain_separation_matches_published_constants_and_library() {
        // smt-leaf: SHA3-256(0x00 || key || value)
        let key = [0x11u8; 32];
        let value = [0x22u8; 32];
        let mut leaf_in = Vec::with_capacity(1 + 64);
        leaf_in.push(0x00);
        leaf_in.extend_from_slice(&key);
        leaf_in.extend_from_slice(&value);
        let leaf_raw = sha3_256(&leaf_in);
        assert_eq!(
            hex::encode(leaf_raw),
            "452d9b157b3dda4e3c5a34e4bd81ada68345af58d9cdcb1f03c0b4c27c595ad4",
            "smt-leaf published constant drifted from the documented 0x00||key||value layout"
        );
        assert_eq!(
            leaf_raw,
            elara_smt::leaf_hash(&key, &value),
            "elara_smt::leaf_hash disagrees with the documented 0x00||key||value layout"
        );

        // smt-interior/empty-left: SHA3-256(0x01 || EMPTY_HASH || leaf) — one fold step.
        let mut int_in = Vec::with_capacity(1 + 64);
        int_in.push(0x01);
        int_in.extend_from_slice(&elara_smt::EMPTY_HASH);
        int_in.extend_from_slice(&leaf_raw);
        let int_raw = sha3_256(&int_in);
        assert_eq!(
            hex::encode(int_raw),
            "fdbb40c3e727c0bd28b10f8c8023429dfa18339960d93ff14f952347b7b2fb45",
            "smt-interior/empty-left published constant drifted from 0x01||left||right"
        );
        assert_eq!(
            int_raw,
            elara_smt::interior_hash(&elara_smt::EMPTY_HASH, &leaf_raw),
            "elara_smt::interior_hash disagrees with the documented 0x01||left||right layout"
        );

        // smt-interior/fixed: SHA3-256(0x01 || 0x33×32 || 0x44×32)
        let l = [0x33u8; 32];
        let r = [0x44u8; 32];
        let mut fixed_in = Vec::with_capacity(1 + 64);
        fixed_in.push(0x01);
        fixed_in.extend_from_slice(&l);
        fixed_in.extend_from_slice(&r);
        let fixed_raw = sha3_256(&fixed_in);
        assert_eq!(
            hex::encode(fixed_raw),
            "180ee6edabe094e03ce3b2ea5c04820c4649ff5a60b2a921bec135e9f989a6b8",
            "smt-interior/fixed published constant drifted from 0x01||left||right"
        );
        assert_eq!(
            fixed_raw,
            elara_smt::interior_hash(&l, &r),
            "elara_smt::interior_hash disagrees on fixed children"
        );
    }

    /// Pin the account-SMT inclusion-proof fold against the published
    /// three-account root constant (`PIN_ABC`, frozen in elara-smt's
    /// `root_hex_pins_match_node`), and confirm the reconstructed proof actually
    /// verifies under the authoritative verifier. `PIN_ABC` is a hardcoded hex
    /// literal — NOT a fresh derivation — so this breaks the same
    /// derive-vs-derive tautology as `smt_domain_separation_*`: the published
    /// `smt-proof` root must equal a constant frozen from a real tree, and the
    /// independent Python fold in `verify_conformance.py` must reproduce it too.
    /// Without this an `smt-proof` vector could ship a self-consistent but wrong
    /// traversal (e.g. LSB-first, or flipped sibling side) and the drift guard
    /// would pass it silently — exactly the fold mistake an external implementer
    /// is most likely to make.
    #[test]
    fn smt_proof_vector_folds_to_published_abc_root_and_verifies() {
        use elara_smt::{verify_proof, SmtProof};
        // The alice/bob/carol root, frozen byte-for-byte in elara-smt.
        const PIN_ABC: &str =
            "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba";
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "smt-proof")
            .expect("smt-proof vector present in the set");
        assert_eq!(
            v.expected, PIN_ABC,
            "smt-proof root drifted from the published alice/bob/carol PIN_ABC \
             constant — the fold or the tree construction changed"
        );

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        let siblings: Vec<[u8; 32]> = v.input["siblings"]
            .as_array()
            .expect("siblings is an array")
            .iter()
            .map(|s| unhex32(s.as_str().expect("sibling is a hex string")))
            .collect();
        // Must carry a real non-empty sibling — otherwise the vector is a
        // degenerate single-account fold that never pins the consumption order.
        assert!(
            !siblings.is_empty(),
            "smt-proof vector has no non-empty sibling — degenerate, does not pin fold order"
        );

        // Reconstruct the proof from the published vector and confirm the
        // authoritative verifier accepts it: the vector IS a valid proof, not
        // just a matching hash.
        let proof = SmtProof {
            account_id: unhex32(v.input["account_id"].as_str().unwrap()),
            state_hash: unhex32(v.input["state_hash"].as_str().unwrap()),
            root: unhex32(&v.expected),
            present: unhex32(v.input["present"].as_str().unwrap()),
            siblings,
        };
        assert!(
            verify_proof(&proof),
            "reconstructed smt-proof vector must verify under elara_smt::verify_proof"
        );
    }

    /// The MUST-REJECT twin: a tampered inclusion proof MUST fail the
    /// authoritative verifier and MUST NOT fold to the sealed root — the
    /// fail-CLOSED property the positive `smt-proof` vector cannot pin. An
    /// implementation that accepts this forged proof is the catastrophic
    /// light-client soundness break (admitting a forged account-state proof).
    /// This is what makes the language-agnostic set able to certify fail-closed
    /// behaviour, not just the happy path.
    #[test]
    fn smt_proof_reject_vector_is_rejected_by_authoritative_verifier() {
        use elara_smt::{verify_proof, SmtProof};
        const PIN_ABC: &str =
            "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba";
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "smt-proof-reject")
            .expect("smt-proof-reject vector present in the set");
        // `expected` is the sealed root the tampered proof falsely claims.
        assert_eq!(
            v.expected, PIN_ABC,
            "reject vector must claim the published sealed PIN_ABC root"
        );

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        let siblings: Vec<[u8; 32]> = v.input["siblings"]
            .as_array()
            .expect("siblings is an array")
            .iter()
            .map(|s| unhex32(s.as_str().expect("sibling is a hex string")))
            .collect();
        // The forged proof CLAIMS the sealed root; the authoritative verifier
        // MUST reject it, because the tampered siblings do not fold to that root.
        let forged = SmtProof {
            account_id: unhex32(v.input["account_id"].as_str().unwrap()),
            state_hash: unhex32(v.input["state_hash"].as_str().unwrap()),
            root: unhex32(&v.expected),
            present: unhex32(v.input["present"].as_str().unwrap()),
            siblings,
        };
        assert!(
            !verify_proof(&forged),
            "tampered proof claiming the sealed root MUST be rejected — fail-open regression"
        );

        // It must differ from the positive vector by exactly the tamper: confirm
        // the positive vector still folds to PIN_ABC, so the pair is a real
        // accept/reject contrast, not two coincidentally-failing proofs.
        let pos = set
            .vectors
            .iter()
            .find(|x| x.primitive == "smt-proof")
            .expect("positive smt-proof vector present");
        assert_eq!(
            pos.expected, PIN_ABC,
            "positive vector must still reach the sealed root (accept/reject contrast)"
        );
        // Exactly one sibling byte differs between accept and reject inputs.
        let pos_sibs = pos.input["siblings"].as_array().unwrap();
        let rej_sibs = v.input["siblings"].as_array().unwrap();
        assert_eq!(pos_sibs.len(), rej_sibs.len(), "tamper must not change sibling count");
        let differing: usize = pos_sibs
            .iter()
            .zip(rej_sibs)
            .filter(|(a, b)| a.as_str() != b.as_str())
            .count();
        assert_eq!(
            differing, 1,
            "reject vector must differ from the accept vector in exactly one sibling"
        );
    }

    /// ML-DSA-65 (FIPS 204) signature KAT: the published `mldsa65-sig` vector
    /// MUST verify under the authoritative verifier, and its must-reject twin
    /// (one signature byte flipped) MUST be rejected — the fail-CLOSED property
    /// for the post-quantum anchor signature, the analogue of the smt-proof pair.
    /// Signing is randomized, so the vector pins one frozen valid signature and
    /// certifies *verification*, not signature reproduction. This also pins the
    /// FIPS 204 byte sizes (public key 1952, signature 3309) and that the public
    /// key re-derives from the published seed (deterministic keygen).
    #[test]
    fn mldsa65_signature_vector_verifies_and_reject_is_rejected() {
        use crate::crypto::pqc::{
            dilithium3_keypair_from_seed, dilithium3_verify, DILITHIUM3_PUBLIC_KEY_LEN,
        };
        let set = derive();

        let unhex = |s: &str| hex::decode(s).expect("vector field is valid hex");
        let unseed = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("seed is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };

        // ── positive: the published signature MUST verify ────────────────────
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "mldsa65-sig")
            .expect("mldsa65-sig vector present in the set");
        assert_eq!(v.expected, "true", "positive sig vector expects verify=true");
        let pk = unhex(v.input["public_key"].as_str().unwrap());
        let msg = v.input["message_ascii"].as_str().unwrap().as_bytes();
        let sig = unhex(v.input["signature"].as_str().unwrap());

        // FIPS 204 structural pins an external implementer must match.
        assert_eq!(
            pk.len(),
            DILITHIUM3_PUBLIC_KEY_LEN,
            "ML-DSA-65 public key must be 1952 bytes"
        );
        assert_eq!(sig.len(), 3309, "ML-DSA-65 signature must be 3309 bytes (FIPS 204)");

        // public_key must re-derive from the published seed (deterministic keygen).
        let seed = unseed(v.input["seed"].as_str().unwrap());
        let (derived_pk, _sk) = dilithium3_keypair_from_seed(&seed).expect("keypair from seed");
        assert_eq!(derived_pk, pk, "public_key must re-derive from the pinned seed");

        assert!(
            dilithium3_verify(msg, &sig, &pk).expect("verify must not error"),
            "published mldsa65-sig vector MUST verify under the authoritative ML-DSA-65 verifier"
        );

        // ── reject: the forged twin MUST NOT verify ──────────────────────────
        let r = set
            .vectors
            .iter()
            .find(|v| v.primitive == "mldsa65-sig-reject")
            .expect("mldsa65-sig-reject vector present in the set");
        assert_eq!(r.expected, "false", "reject sig vector expects verify=false");
        let rpk = unhex(r.input["public_key"].as_str().unwrap());
        let rmsg = r.input["message_ascii"].as_str().unwrap().as_bytes();
        let rsig = unhex(r.input["signature"].as_str().unwrap());
        assert!(
            !dilithium3_verify(rmsg, &rsig, &rpk).expect("verify must not error"),
            "tampered mldsa65-sig-reject vector MUST be rejected — fail-open regression"
        );

        // A real accept/reject contrast: same key + message, signatures differ by
        // exactly one byte (the single-byte tamper), not two unrelated inputs.
        assert_eq!(rpk, pk, "reject twin must use the same public key");
        assert_eq!(rmsg, msg, "reject twin must use the same message");
        assert_eq!(sig.len(), rsig.len(), "tamper must not change signature length");
        let differing = sig.iter().zip(&rsig).filter(|(a, b)| a != b).count();
        assert_eq!(
            differing, 1,
            "reject twin must differ from the accept vector by exactly one byte"
        );
    }

    /// The zone record-membership Merkle proof (`network::merkle`, distinct from
    /// the account-SMT): the published `merkle-inclusion` vector MUST fold to the
    /// pinned sealed root AND be accepted by the authoritative
    /// `network::merkle::verify_proof`. The frozen `PIN_INCL_ROOT` literal breaks
    /// the derive-vs-derive tautology (a change to the sample record, the sibling
    /// derivation, or the no-domain-tag fold flips it), and the pure-`hashlib`
    /// `verify_conformance.py` leg reproduces it independently in a second
    /// language. Gated to `node-core` because `network::merkle` only exists in the
    /// node build (the canonical `cargo test --features node --lib` gate); the
    /// generator itself is SHA3-only and builds without `node`.
    #[cfg(feature = "node-core")]
    #[test]
    fn merkle_inclusion_vector_folds_to_pinned_root_and_verifies() {
        use crate::network::merkle::{verify_proof, SparseMerkleProof, SparseMerkleProofNode};
        // The sealed root the sample record's 2-level inclusion proof folds to,
        // frozen byte-for-byte. Reproduced independently (pure hashlib) by
        // verify_conformance.py.
        const PIN_INCL_ROOT: &str =
            "438b93f583a4936c68633fe0e127dd8270bd09776aadf7f195c35ab40265acdc";
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "merkle-inclusion")
            .expect("merkle-inclusion vector present in the set");
        assert_eq!(
            v.expected, PIN_INCL_ROOT,
            "merkle-inclusion root drifted from the pinned sealed root — the sample \
             record, the sibling derivation, or the no-domain-tag fold changed"
        );

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        // The leaf MUST be the sample record's record_hash (the `record-hash`
        // vector's output) — this is what chains the two vectors end-to-end.
        let rh = set
            .vectors
            .iter()
            .find(|x| x.primitive == "record-hash")
            .expect("record-hash vector present");
        assert_eq!(
            v.input["leaf"].as_str().unwrap(),
            rh.expected,
            "merkle-inclusion leaf must equal the record-hash vector's output"
        );

        let siblings: Vec<SparseMerkleProofNode> = v.input["siblings"]
            .as_array()
            .expect("siblings is an array")
            .iter()
            .map(|n| SparseMerkleProofNode {
                hash: unhex32(n["hash"].as_str().expect("sibling hash is hex")),
                is_right: n["is_right"].as_bool().expect("is_right is bool"),
            })
            .collect();
        // Must pin BOTH fold branches: one right-sibling, one left-sibling.
        assert_eq!(siblings.len(), 2, "vector must carry a 2-level proof");
        assert!(
            siblings[0].is_right && !siblings[1].is_right,
            "must exercise both is_right branches"
        );

        // The authoritative verifier MUST accept the reconstructed proof: the
        // vector IS a valid `network::merkle` inclusion proof, not just a matching
        // hash. (`zone` is unused by verify_proof — fold only.)
        let proof = SparseMerkleProof {
            leaf: unhex32(v.input["leaf"].as_str().unwrap()),
            root: unhex32(&v.expected),
            siblings,
            zone: crate::ZoneId::from_legacy(0),
        };
        assert!(
            verify_proof(&proof),
            "reconstructed merkle-inclusion vector must verify under network::merkle::verify_proof"
        );
    }

    /// The MUST-REJECT twin: the tampered `merkle-inclusion-reject` proof MUST be
    /// rejected by `network::merkle::verify_proof` and MUST NOT fold to the sealed
    /// root — the fail-CLOSED property for cross-zone inclusion evidence that the
    /// positive vector alone cannot pin. Accepting it is the catastrophic
    /// fail-open break (admitting forged cross-zone inclusion evidence).
    #[cfg(feature = "node-core")]
    #[test]
    fn merkle_inclusion_reject_vector_is_rejected_by_authoritative_verifier() {
        use crate::network::merkle::{verify_proof, SparseMerkleProof, SparseMerkleProofNode};
        const PIN_INCL_ROOT: &str =
            "438b93f583a4936c68633fe0e127dd8270bd09776aadf7f195c35ab40265acdc";
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "merkle-inclusion-reject")
            .expect("merkle-inclusion-reject vector present in the set");
        // `expected` is the sealed root the tampered proof falsely claims.
        assert_eq!(v.expected, PIN_INCL_ROOT, "reject vector must claim the pinned sealed root");

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        let to_sibs = |val: &serde_json::Value| -> Vec<SparseMerkleProofNode> {
            val.as_array()
                .expect("siblings is an array")
                .iter()
                .map(|n| SparseMerkleProofNode {
                    hash: unhex32(n["hash"].as_str().expect("sibling hash is hex")),
                    is_right: n["is_right"].as_bool().expect("is_right is bool"),
                })
                .collect()
        };

        // The forged proof CLAIMS the sealed root; the authoritative verifier MUST
        // reject it, because the tampered sibling does not fold to that root.
        let forged = SparseMerkleProof {
            leaf: unhex32(v.input["leaf"].as_str().unwrap()),
            root: unhex32(&v.expected),
            siblings: to_sibs(&v.input["siblings"]),
            zone: crate::ZoneId::from_legacy(0),
        };
        assert!(
            !verify_proof(&forged),
            "tampered merkle-inclusion proof claiming the sealed root MUST be rejected — fail-open regression"
        );

        // A real accept/reject contrast: the positive vector still folds to the
        // sealed root, and the two differ in exactly one sibling hash.
        let pos = set
            .vectors
            .iter()
            .find(|x| x.primitive == "merkle-inclusion")
            .expect("positive merkle-inclusion vector present");
        let valid = SparseMerkleProof {
            leaf: unhex32(pos.input["leaf"].as_str().unwrap()),
            root: unhex32(&pos.expected),
            siblings: to_sibs(&pos.input["siblings"]),
            zone: crate::ZoneId::from_legacy(0),
        };
        assert!(verify_proof(&valid), "positive vector must still verify (accept/reject contrast)");

        let pos_sibs = pos.input["siblings"].as_array().unwrap();
        let rej_sibs = v.input["siblings"].as_array().unwrap();
        assert_eq!(pos_sibs.len(), rej_sibs.len(), "tamper must not change sibling count");
        let differing = pos_sibs
            .iter()
            .zip(rej_sibs)
            .filter(|(a, b)| a["hash"].as_str() != b["hash"].as_str())
            .count();
        assert_eq!(differing, 1, "reject vector must differ from accept in exactly one sibling");
    }

    /// Every vector's `expected` is non-empty lowercase hex and every primitive
    /// is one of the documented set — guards a malformed hand-edit.
    /// The account-proof → signed-header BINDING holds when the proof's root
    /// matches the header's `account_smt_root`. Non-tautological cross-check: the
    /// vector's `expected` is re-derived here through the authoritative
    /// `verify_account_proof_against_header`, and the input's `proof_root` is
    /// asserted equal to its `header_account_smt_root` (the bind condition).
    #[test]
    fn account_binding_vector_binds_under_authoritative_verifier() {
        use elara_light_client::{
            verify_account_proof_against_header, LiteAccountStateProof, LiteEpochHeader,
        };
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "account-binding")
            .expect("account-binding vector present");
        assert_eq!(v.expected, "true", "positive binding vector must accept");

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        let proof_root = unhex32(v.input["proof_root"].as_str().unwrap());
        let header_root = unhex32(v.input["header_account_smt_root"].as_str().unwrap());
        assert_eq!(
            proof_root, header_root,
            "positive vector must bind the proof root to the SAME signed header root"
        );
        let siblings: Vec<[u8; 32]> = v.input["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| unhex32(s.as_str().unwrap()))
            .collect();
        let proof = LiteAccountStateProof {
            account_id: unhex32(v.input["account_id"].as_str().unwrap()),
            state_hash: unhex32(v.input["state_hash"].as_str().unwrap()),
            root: proof_root,
            present: unhex32(v.input["present"].as_str().unwrap()),
            siblings,
        };
        let header = LiteEpochHeader {
            zone: "0".into(),
            epoch_number: 8219,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            record_count: 0,
            start: 0.0,
            end: 0.0,
            account_smt_root: Some(header_root),
            seal_record_hash: None,
        };
        assert!(
            verify_account_proof_against_header(&proof, &header),
            "reconstructed account-binding vector must bind under the authoritative verifier"
        );
    }

    /// MUST-REJECT twin: a VALID proof bound to the WRONG signed root is
    /// rejected — the fail-open class `smt-proof-reject` cannot catch. The key
    /// non-tautological assertions: (1) the proof folds cleanly to its OWN root
    /// (so the reject is NOT a broken fold), yet (2) the authoritative binding
    /// verifier returns false because `proof_root != header_account_smt_root`.
    #[test]
    fn account_binding_reject_vector_rejects_valid_proof_against_wrong_root() {
        use elara_light_client::{
            verify_account_proof_against_header, verify_proof, LiteAccountStateProof,
            LiteEpochHeader,
        };
        let set = derive();
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "account-binding-reject")
            .expect("account-binding-reject vector present");
        assert_eq!(v.expected, "false", "reject vector must NOT accept");

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };
        let proof_root = unhex32(v.input["proof_root"].as_str().unwrap());
        let header_root = unhex32(v.input["header_account_smt_root"].as_str().unwrap());
        assert_ne!(
            proof_root, header_root,
            "reject vector must bind to a DIFFERENT signed root than the proof folds to"
        );
        let siblings: Vec<[u8; 32]> = v.input["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| unhex32(s.as_str().unwrap()))
            .collect();
        let proof = LiteAccountStateProof {
            account_id: unhex32(v.input["account_id"].as_str().unwrap()),
            state_hash: unhex32(v.input["state_hash"].as_str().unwrap()),
            root: proof_root,
            present: unhex32(v.input["present"].as_str().unwrap()),
            siblings,
        };
        // (1) The proof itself is VALID — it folds cleanly to its own root. This
        // is what makes the reject a BINDING failure, not a broken-fold failure.
        assert!(
            verify_proof(&proof),
            "the proof in the reject vector must itself be internally valid (folds to its root)"
        );
        // (2) But bound to a header signing a different root, the verifier rejects.
        let header = LiteEpochHeader {
            zone: "0".into(),
            epoch_number: 8219,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            record_count: 0,
            start: 0.0,
            end: 0.0,
            account_smt_root: Some(header_root),
            seal_record_hash: None,
        };
        assert!(
            !verify_account_proof_against_header(&proof, &header),
            "a valid proof against the WRONG signed root must be REJECTED (fail-open guard)"
        );
    }

    /// Epoch-seal anchor-signature KAT — the light-client trust ROOT. The
    /// published `seal-anchor-sig` vector MUST verify under the authoritative
    /// `verify_seal_record_against_anchor` (the real seal decoded, its §4.4
    /// preimage rebuilt, the anchor's ML-DSA-65 signature checked against the
    /// PINNED zone-0 key), and its must-reject twin — the SAME valid seal pinned to
    /// a DIFFERENT anchor — MUST be rejected as `UntrustedAnchor`. Pins the
    /// published seal record hash (`SEAL_HASH`, the value `verify.sh` leg 5 feeds
    /// as `--expected-hash`) and the FIPS 204 anchor key size, breaking the
    /// derive-vs-derive tautology: the seal the vector points at must hash to a
    /// constant frozen outside the generator, and the real verifier must accept it.
    #[test]
    fn seal_anchor_sig_vector_verifies_and_reject_is_rejected() {
        use crate::light_verify::{verify_seal_record_against_anchor, SealRecordVerifyError};
        // The seal's record hash, frozen byte-for-byte in examples/verify/verify.sh
        // (SEAL_HASH, leg 5's --expected-hash) — independent of this generator.
        const SEAL_HASH: &str =
            "826306639200879beac7fc073166d18b968ad73756bbeefe836bdd60b557d3b7";
        let set = derive();
        let seal = seal_wire();
        let anchor = anchor_pubkey();

        let unhex32 = |s: &str| -> [u8; 32] {
            let b = hex::decode(s).expect("vector field is valid hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        };

        // ── positive: the published seal MUST verify against the pinned anchor ──
        let v = set
            .vectors
            .iter()
            .find(|v| v.primitive == "seal-anchor-sig")
            .expect("seal-anchor-sig vector present in the set");
        assert_eq!(v.expected, "true", "positive seal vector expects verify=true");

        // FIPS 204 anchor key size + the frozen seal record hash, pinned.
        assert_eq!(anchor.len(), 1952, "zone-0 anchor key must be 1952 bytes (ML-DSA-65)");
        assert_eq!(
            v.input["seal_record_hash"].as_str().unwrap(),
            SEAL_HASH,
            "seal-anchor-sig record hash drifted from verify.sh's pinned SEAL_HASH"
        );
        assert_eq!(
            v.input["trusted_anchor_public_key"].as_str().unwrap(),
            hex::encode(&anchor),
            "vector anchor key must equal the committed zone-0-anchor-pubkey.hex"
        );
        assert_eq!(
            v.input["seal_wire_sha3_256"].as_str().unwrap(),
            hex::encode(sha3_256(&seal)),
            "vector seal-wire hash must equal SHA3-256 of the committed seal wire"
        );

        let seal_hash = unhex32(SEAL_HASH);
        // The seal decodes and its record_hash matches the pinned value — proves
        // the expected-hash bind the verifier enforces in step 2.
        let rec = ValidationRecord::from_bytes(&seal).expect("seal wire decodes");
        assert_eq!(rec.record_hash(), seal_hash, "decoded seal must hash to SEAL_HASH");

        assert!(
            verify_seal_record_against_anchor(&seal, seal_hash, std::slice::from_ref(&anchor)).is_ok(),
            "published seal-anchor-sig vector MUST verify against the pinned zone-0 anchor"
        );

        // ── reject: the SAME valid seal against a DIFFERENT pinned anchor ───────
        let r = set
            .vectors
            .iter()
            .find(|v| v.primitive == "seal-anchor-sig-reject")
            .expect("seal-anchor-sig-reject vector present in the set");
        assert_eq!(r.expected, "false", "reject seal vector expects verify=false");
        let wrong = hex::decode(r.input["trusted_anchor_public_key"].as_str().unwrap())
            .expect("wrong-anchor key is valid hex");
        assert_ne!(wrong, anchor, "reject twin must pin a DIFFERENT anchor than the real one");
        assert_eq!(
            wrong.len(),
            1952,
            "wrong anchor key must still be a structurally valid ML-DSA-65 key"
        );

        // It rejects specifically at the anchor-membership gate — NOT a broken
        // signature (the seal's self-signature is perfectly valid). This is what
        // makes the reject a TRUST-CONTEXT failure, not a forged-signature failure.
        let err = verify_seal_record_against_anchor(&seal, seal_hash, &[wrong])
            .expect_err("a seal pinned to the wrong anchor MUST be rejected");
        assert_eq!(
            err,
            SealRecordVerifyError::UntrustedAnchor,
            "wrong-anchor seal must reject as UntrustedAnchor (valid sig, unpinned key), got {err:?}"
        );

        // A real accept/reject contrast: the SAME seal still verifies against the
        // RIGHT anchor — the only difference is which key the caller pinned.
        assert!(
            verify_seal_record_against_anchor(&seal, seal_hash, &[anchor]).is_ok(),
            "the same seal must still verify against the correct anchor (accept/reject contrast)"
        );
    }

    #[test]
    fn all_vectors_are_well_formed() {
        let set = derive();
        let primitives = [
            "sha3-256",
            "smt-empty",
            "smt-leaf",
            "smt-interior",
            "smt-proof",
            "smt-proof-reject",
            "identity-derivation",
            "record-hash",
            "merkle-inclusion",
            "merkle-inclusion-reject",
            "mldsa65-sig",
            "mldsa65-sig-reject",
            "account-binding",
            "account-binding-reject",
            "seal-anchor-sig",
            "seal-anchor-sig-reject",
        ];
        assert!(!set.vectors.is_empty());
        for v in &set.vectors {
            assert!(
                primitives.contains(&v.primitive.as_str()),
                "unknown primitive {:?}",
                v.primitive
            );
            assert!(!v.expected.is_empty(), "empty expected for {}", v.name);
            let is_boolean_verify = matches!(
                v.primitive.as_str(),
                "mldsa65-sig"
                    | "mldsa65-sig-reject"
                    | "account-binding"
                    | "account-binding-reject"
                    | "seal-anchor-sig"
                    | "seal-anchor-sig-reject"
            );
            if is_boolean_verify {
                // Verification vectors (PQ signature, account-proof binding) carry
                // a boolean verify result, not a hash.
                assert!(
                    v.expected == "true" || v.expected == "false",
                    "verify-result expected must be a boolean for {}: {}",
                    v.name,
                    v.expected
                );
            } else {
                assert!(
                    v.expected.bytes().all(|b| b.is_ascii_hexdigit()
                        && (!b.is_ascii_alphabetic() || b.is_ascii_lowercase())),
                    "expected not lowercase hex for {}: {}",
                    v.name,
                    v.expected
                );
            }
        }
    }
}
