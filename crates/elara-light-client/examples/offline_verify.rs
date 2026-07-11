// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! A light client that holds *only* a trusted epoch header verifies an account's
//! state — and a non-existent account's *absence* — with no node, no network, no
//! history replay. The header's `account_smt_root` is signed by the epoch anchor
//! (that signature check is the node's job); given the verified header, every
//! check below is local, stateless math.
//!
//! The producer side uses the sibling `elara-smt` engine to build a *real*
//! account-state tree and proof — so this also demonstrates that the proof the
//! node emits folds byte-identically under the light client's verifier.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-light-client --example offline_verify
//! ```

use elara_light_client::{
    verify_account_non_membership_against_header, verify_account_proof_against_header,
    LiteAccountStateProof, LiteEpochHeader, LiteExclusionProof,
};
use elara_smt::{MemorySmtStore, SparseMerkleTree};

/// Demo key from a label (real keys are 256-bit identity hashes).
fn key32(label: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    let b = label.as_bytes();
    let n = b.len().min(32);
    k[..n].copy_from_slice(&b[..n]);
    k
}

fn main() {
    // ── Producer (the node) ──────────────────────────────────────────────────
    // Build the account-state tree, commit, and snapshot the root the anchor
    // will sign into the epoch header.
    let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
    tree.update(&key32("alice"), &key32("balance=100")).unwrap();
    tree.update(&key32("bob"), &key32("balance=42")).unwrap();
    tree.commit().unwrap();
    let account_smt_root = tree.root().unwrap();

    // The ONLY thing the light client trusts: a header whose `account_smt_root`
    // is anchor-signed. (Signature verification is the node's job; here we hold
    // the already-verified header.)
    let header = LiteEpochHeader {
        zone: "0".to_string(),
        epoch_number: 7965,
        merkle_root: [0u8; 32], // record-tree root — not used by the account binding
        previous_seal_hash: [0u8; 32],
        record_count: 2,
        start: 0.0,
        end: 0.0,
        account_smt_root: Some(account_smt_root),
        seal_record_hash: None,
    };

    // ── Light client ─────────────────────────────────────────────────────────
    // The server sends alice's inclusion proof; map the node's SMT proof onto the
    // wire type (field-for-field — they are wire-compatible by construction).
    let smt_proof = tree.proof(&key32("alice")).unwrap().expect("alice present");
    let proof = LiteAccountStateProof {
        account_id: smt_proof.account_id,
        state_hash: smt_proof.state_hash,
        root: smt_proof.root,
        present: smt_proof.present,
        siblings: smt_proof.siblings,
    };

    // 1. The account verifies against the trusted header — offline.
    assert!(
        verify_account_proof_against_header(&proof, &header),
        "honest proof binds to the header's signed root"
    );
    println!("✓ inclusion — alice's state verified against the trusted epoch header (offline)");

    // 2. A header advertising a DIFFERENT root won't accept this proof — the
    //    two-level binding fails, so a server can't swap in a forged root.
    let mut wrong_header = header.clone();
    wrong_header.account_smt_root = Some(key32("not-the-real-root"));
    assert!(
        !verify_account_proof_against_header(&proof, &wrong_header),
        "a proof that doesn't fold to the header's root is rejected"
    );
    println!("✓ binding — a proof that doesn't match the header's signed root is rejected");

    // 3. A pre-Gap-1 header with no signed account root cannot bind anything —
    //    refused, never trusted-by-default.
    let mut legacy_header = header.clone();
    legacy_header.account_smt_root = None;
    assert!(
        !verify_account_proof_against_header(&proof, &legacy_header),
        "a header without a signed account root cannot bind"
    );
    println!("✓ no blind trust — a header lacking a signed account root is refused");

    // 4. Provable ABSENCE — a non-membership proof for an account that was never
    //    inserted, bound to the same signed root. Not "the server says it's gone".
    let smt_excl = tree
        .exclusion_proof(&key32("mallory"))
        .unwrap()
        .expect("mallory absent");
    let exclusion = LiteExclusionProof {
        account_id: smt_excl.account_id,
        root: smt_excl.root,
        present: smt_excl.present,
        siblings: smt_excl.siblings,
    };
    assert!(
        verify_account_non_membership_against_header(&exclusion, &header),
        "honest exclusion proof binds to the signed root"
    );
    println!("✓ exclusion — mallory's absence is provable against the trusted root");

    println!("\nall checks passed — a light client verified state AND absence from a header alone.");
}
