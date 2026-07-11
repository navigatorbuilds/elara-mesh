// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! Verifiable provenance in ~40 lines: build a sparse Merkle tree of account
//! states, then prove membership, tamper-rejection, and *provable absence* —
//! each check stateless, from the proof bytes plus the 32-byte root alone. No
//! tree, no network, no trusted server.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-smt --example proof_verify
//! ```
//!
//! This is the offline-verifier core of the Elara Protocol: a light client
//! that holds only a trusted root can check any account's state — or its
//! absence — without replaying history or trusting the responder.

use elara_smt::{
    verify_exclusion_proof, verify_proof, MemorySmtStore, SmtProof, SparseMerkleTree,
};

/// Derive a 32-byte key from a label (demo helper — real keys are identity
/// hashes). The full 256-bit path is why an absent key's slot is *genuinely*
/// empty, which is what makes the exclusion proof sound rather than a
/// trust-the-server assertion.
fn key32(label: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    let b = label.as_bytes();
    let n = b.len().min(32);
    k[..n].copy_from_slice(&b[..n]);
    k
}

fn main() {
    // 1. Build a tree of three account states, then commit once (build → commit
    //    → serve proofs is the real lifecycle: updates buffer, commit flushes).
    let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
    tree.update(&key32("alice"), &key32("balance=100")).unwrap();
    tree.update(&key32("bob"), &key32("balance=42")).unwrap();
    tree.update(&key32("carol"), &key32("balance=7")).unwrap();
    tree.commit().unwrap();

    let root = tree.root().unwrap();
    println!("committed root: {}", hex32(&root));

    // 2. INCLUSION — prove alice's state is in the tree, then verify against the
    //    root alone. `verify_proof` never sees the tree: proof bytes + root only.
    let proof: SmtProof = tree
        .proof(&key32("alice"))
        .unwrap()
        .expect("alice is present");
    assert!(verify_proof(&proof), "honest inclusion proof must verify");
    assert_eq!(proof.root, root, "proof folds to the committed root");
    println!("✓ inclusion — alice's state verified from {} sibling(s)", proof.siblings.len());

    // 3. TAMPER — flip one byte of the claimed value. The leaf re-hashes
    //    differently, the fold no longer reaches the root, and verification
    //    fails. A forged balance cannot survive against a trusted root.
    let mut forged = proof.clone();
    forged.state_hash[0] ^= 0x01;
    assert!(!verify_proof(&forged), "tampered proof must be rejected");
    println!("✓ tamper-rejection — a one-bit forgery of alice's value is rejected");

    // 4. EXCLUSION — prove a key that was never inserted is *absent*. Because
    //    the path is the full 256-bit hash, mallory's slot is provably empty.
    let excl = tree
        .exclusion_proof(&key32("mallory"))
        .unwrap()
        .expect("mallory is absent");
    assert!(verify_exclusion_proof(&excl), "honest exclusion proof must verify");
    assert_eq!(excl.root, root, "exclusion proof folds to the same root");
    println!("✓ exclusion — mallory's absence is cryptographically provable");

    // 5. An exclusion proof for a key that IS present is refused — the right
    //    artifact there is an inclusion proof.
    assert!(
        tree.exclusion_proof(&key32("alice")).unwrap().is_none(),
        "no exclusion proof for a present key"
    );
    println!("✓ exclusion is refused for a present key (alice)");

    println!("\nall checks passed — provenance verified offline, from the root alone.");
}

/// Short hex for the 32-byte root (first 8 bytes, demo-readable).
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(19);
    for byte in &b[..8] {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}
