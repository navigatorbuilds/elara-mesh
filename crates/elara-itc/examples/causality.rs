// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! Causality tracking without coordination, in ~40 lines: one Interval Tree
//! Clock forks into two independent replicas, each records a local event, and
//! `leq` / `concurrent` / `before` recover the exact happens-before relation —
//! then a `join` merges the histories back together. No central sequencer, no
//! wall clock, no per-peer slot.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-itc --example causality
//! ```
//!
//! This is how the Elara mesh orders events across replicas: an ITC forks when
//! a peer splits off and joins when state merges, so the stamp space grows and
//! shrinks with the membership instead of leaking a slot per peer forever (the
//! vector-clock failure mode at mesh scale).

use elara_itc::Stamp;

fn main() {
    // One causal origin, forked so two replicas can act independently.
    let (mut a, b) = Stamp::seed().fork();
    println!("forked the seed stamp into replica A and replica B");

    // Each replica records a local event. Neither has observed the other's.
    a = a.event();
    let b = b.event();
    println!("A and B each recorded one independent event");

    // They are genuinely concurrent — neither happened-before the other, and
    // ITC refuses to invent an ordering that the causal history doesn't justify.
    assert!(a.concurrent(&b));
    assert!(!a.leq(&b) && !b.leq(&a));
    println!("  -> A || B   (concurrent: no false ordering invented)");

    // A learns of B by joining B's stamp in, then records a fresh event on top.
    a = a.join(b.clone()).event();
    println!("A joined B's history, then recorded another event");

    // Now B's pre-merge state strictly precedes A's post-merge state...
    assert!(b.before(&a));
    assert!(b.leq(&a));
    println!("  -> B -> A   (B now strictly happens-before A)");

    // ...but A does not precede B. Causality is directional, not symmetric.
    assert!(!a.leq(&b));
    println!("  -> A does NOT precede B   (the relation stays directional)");

    println!("\nITC recovered the exact happens-before relation with zero coordination.");
}
