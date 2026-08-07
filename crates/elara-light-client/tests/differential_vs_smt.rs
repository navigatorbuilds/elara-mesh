//! Differential fuzz: the light client's compressed `fold` MUST stay
//! byte-identical to the canonical `elara_smt::fold`.
//!
//! The lite crate re-implements the 256-level compressed fold to stay
//! wasm-minimal — it does NOT depend on `elara-smt` at runtime (only as a
//! dev-dependency, here). Its doc-comment claims it "Mirrors `elara_smt::fold`
//! exactly"; this test is the mechanical enforcement of that claim. If a future
//! edit drifts one fold from the other — especially in the direction that makes
//! the lite verifier ACCEPT a proof the canonical tree would REJECT (a
//! light-client forgery) — this test fails.
//!
//! Strategy (sharp differential, no fold internals exposed):
//!
//! 1. VALID proofs from the real `SparseMerkleTree` generator → BOTH verifiers
//!    must accept. Catches any combine/hash/sibling-order divergence: the lite
//!    fold has to reproduce the canonical root the tree computed.
//! 2. MUTATED valid proofs, RETAINING the canonical root R → the two verifiers
//!    must AGREE. Keeping R makes the bool comparison sharp — a divergence that
//!    flips lite to ACCEPT (fold == R) what smt REJECTS shows up as
//!    `smt != lite`, not as two coincidental falses.
//!
//! The same two checks run for exclusion (non-membership) proofs.
//!
//! Deterministic SplitMix64 PRNG (fixed seeds) → reproducible failures, no
//! `rand` dependency.

use elara_light_client::{
    verify_exclusion_proof as lite_verify_excl, verify_proof as lite_verify, LiteAccountStateProof,
    LiteExclusionProof,
};
use elara_smt::{
    verify_exclusion_proof as smt_verify_excl, verify_proof as smt_verify, MemorySmtStore,
    SmtExclusionProof, SmtProof, SparseMerkleTree,
};

/// SplitMix64 — a tiny deterministic PRNG so a failing case is reproducible.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next_u64().to_le_bytes()[..c.len()]);
        }
        b
    }
    /// Uniform in `0..n` (0 when `n == 0`).
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Re-key a canonical inclusion proof into the lite crate's struct — same bytes,
/// independent fold.
fn lite_incl(p: &SmtProof) -> LiteAccountStateProof {
    LiteAccountStateProof {
        account_id: p.account_id,
        state_hash: p.state_hash,
        root: p.root,
        present: p.present,
        siblings: p.siblings.clone(),
    }
}

fn lite_excl(p: &SmtExclusionProof) -> LiteExclusionProof {
    LiteExclusionProof {
        account_id: p.account_id,
        root: p.root,
        present: p.present,
        siblings: p.siblings.clone(),
    }
}

/// A tree of `n` distinct random accounts (committed); returns it plus the keys.
fn build_tree(rng: &mut Rng, n: usize) -> (SparseMerkleTree<MemorySmtStore>, Vec<[u8; 32]>) {
    let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let k = rng.fill32();
        let v = rng.fill32();
        tree.update(&k, &v).unwrap();
        keys.push(k);
    }
    tree.commit().unwrap();
    (tree, keys)
}

#[test]
fn valid_inclusion_proofs_accepted_by_both_folds() {
    // Across many tree sizes the lite fold must reproduce the canonical root for
    // every real proof. A combine/order/hash drift surfaces here immediately.
    for seed in 0..24u64 {
        let mut rng = Rng::new(0xE1A0_0000 ^ seed);
        let n = 1 + rng.below(32); // 1..=32 accounts (enough for multi-sibling paths)
        let (tree, keys) = build_tree(&mut rng, n);
        for k in &keys {
            let p = tree.proof(k).unwrap().expect("a present key has an inclusion proof");
            assert!(smt_verify(&p), "elara-smt rejected its OWN valid proof (seed {seed})");
            assert!(
                lite_verify(&lite_incl(&p)),
                "lite REJECTED a valid proof the canonical tree produced (seed {seed}, n={n}) — \
                 fold drift: the lite fold no longer reproduces the canonical root"
            );
        }
    }
}

#[test]
fn valid_exclusion_proofs_accepted_by_both_folds() {
    for seed in 0..24u64 {
        let mut rng = Rng::new(0xEC10_0000 ^ seed);
        let n = rng.below(32); // includes the empty-tree case
        let (tree, keys) = build_tree(&mut rng, n);
        for _ in 0..8 {
            let k = rng.fill32(); // absent w.h.p. in a 256-bit space
            if keys.contains(&k) {
                continue;
            }
            let p = tree
                .exclusion_proof(&k)
                .unwrap()
                .expect("an absent key has an exclusion proof");
            assert!(smt_verify_excl(&p), "elara-smt rejected its OWN valid exclusion proof (seed {seed})");
            assert!(
                lite_verify_excl(&lite_excl(&p)),
                "lite REJECTED a valid exclusion proof (seed {seed}, n={n}) — exclusion fold drift"
            );
        }
    }
}

#[test]
fn mutated_inclusion_proofs_agree_across_folds() {
    // Each mutation keeps the canonical root R, so `verify == (fold == R)` is a
    // sharp test: any divergence that flips acceptance is caught as smt != lite.
    for seed in 0..80u64 {
        let mut rng = Rng::new(0x4D17_0000 ^ seed.wrapping_mul(2_654_435_761));
        let n = 2 + rng.below(30);
        let (tree, keys) = build_tree(&mut rng, n);
        let k = keys[rng.below(keys.len())];
        let base = tree.proof(&k).unwrap().expect("present key");

        let mut variants: Vec<SmtProof> = Vec::new();
        // (a) flip one present bit (MSB-first), sibling list unchanged
        {
            let mut m = base.clone();
            let bit = rng.below(256);
            m.present[bit / 8] ^= 0x80u8 >> (bit % 8);
            variants.push(m);
        }
        // (b) drop a sibling → too few for the bitmap's popcount
        if !base.siblings.is_empty() {
            let mut m = base.clone();
            let i = rng.below(m.siblings.len());
            m.siblings.remove(i);
            variants.push(m);
        }
        // (c) append an extra sibling → leftover after the fold
        {
            let mut m = base.clone();
            m.siblings.push(rng.fill32());
            variants.push(m);
        }
        // (d) tamper one sibling hash
        if !base.siblings.is_empty() {
            let mut m = base.clone();
            let i = rng.below(m.siblings.len());
            m.siblings[i] = rng.fill32();
            variants.push(m);
        }
        // (e) duplicate a sibling → shifts the consume alignment vs the bitmap
        if !base.siblings.is_empty() {
            let mut m = base.clone();
            let i = rng.below(m.siblings.len());
            let s = m.siblings[i];
            m.siblings.insert(i, s);
            variants.push(m);
        }
        // (f) flip a byte of account_id → changes BOTH the path and the leaf
        {
            let mut m = base.clone();
            m.account_id[rng.below(32)] ^= 1u8 << rng.below(8);
            variants.push(m);
        }
        // (g) flip a byte of state_hash → changes the leaf only
        {
            let mut m = base.clone();
            m.state_hash[rng.below(32)] ^= 1u8 << rng.below(8);
            variants.push(m);
        }
        // (h) clear the bitmap but keep siblings → gross popcount/len mismatch
        {
            let mut m = base.clone();
            m.present = [0u8; 32];
            variants.push(m);
        }
        // (i) all-ones bitmap → claims 256 non-empty siblings
        {
            let mut m = base.clone();
            m.present = [0xFFu8; 32];
            variants.push(m);
        }

        for (j, m) in variants.iter().enumerate() {
            let s = smt_verify(m);
            let l = lite_verify(&lite_incl(m));
            assert_eq!(
                s, l,
                "FOLD DIVERGENCE on inclusion mutation #{j} (seed {seed}): smt={s} lite={l} — \
                 the two compressed folds disagree on a crafted proof"
            );
        }
    }
}

#[test]
fn mutated_exclusion_proofs_agree_across_folds() {
    for seed in 0..80u64 {
        let mut rng = Rng::new(0xE7C0_0000 ^ seed.wrapping_mul(40_503));
        let n = 1 + rng.below(30);
        let (tree, keys) = build_tree(&mut rng, n);
        // Find an absent key to prove non-membership for.
        let mut k = rng.fill32();
        let mut guard = 0;
        while keys.contains(&k) && guard < 8 {
            k = rng.fill32();
            guard += 1;
        }
        let base = tree.exclusion_proof(&k).unwrap().expect("absent key");

        let mut variants: Vec<SmtExclusionProof> = Vec::new();
        {
            let mut m = base.clone();
            let bit = rng.below(256);
            m.present[bit / 8] ^= 0x80u8 >> (bit % 8);
            variants.push(m);
        }
        if !base.siblings.is_empty() {
            let mut m = base.clone();
            let i = rng.below(m.siblings.len());
            m.siblings.remove(i);
            variants.push(m);
        }
        {
            let mut m = base.clone();
            m.siblings.push(rng.fill32());
            variants.push(m);
        }
        if !base.siblings.is_empty() {
            let mut m = base.clone();
            let i = rng.below(m.siblings.len());
            m.siblings[i] = rng.fill32();
            variants.push(m);
        }
        {
            // Flip a byte of account_id → different absent slot, same siblings.
            let mut m = base.clone();
            m.account_id[rng.below(32)] ^= 1u8 << rng.below(8);
            variants.push(m);
        }
        {
            let mut m = base.clone();
            m.present = [0xFFu8; 32];
            variants.push(m);
        }

        for (j, m) in variants.iter().enumerate() {
            let s = smt_verify_excl(m);
            let l = lite_verify_excl(&lite_excl(m));
            assert_eq!(
                s, l,
                "FOLD DIVERGENCE on exclusion mutation #{j} (seed {seed}): smt={s} lite={l}"
            );
        }
    }
}
