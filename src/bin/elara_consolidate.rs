// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! elara-consolidate — one-shot exact-duplicate collapse for the semantic store
//! (queue F2 slice 1; design + runbook:
//! internal design notes).
//!
//! MUST run with `elara-cognition` STOPPED (`systemctl --user stop`, never
//! `kill` — Restart=always respawns in 10s and the daemon's flush would clobber
//! the edit). Persists via `semantic_memory::save`, which regenerates the
//! SHA3-256 integrity sidecar — the reason this is a Rust tool and not a
//! jq/python edit (a wrong sidecar means the daemon loads an EMPTY store and
//! overwrites everything on its next flush).
//!
//! Usage:
//!   elara-consolidate             # dry-run (default): print the cluster plan, write nothing
//!   elara-consolidate --apply     # collapse + save (refuses if the daemon is running)

use elara_runtime::cognition::semantic_memory;

fn daemon_running() -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "elara-cognition"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn main() {
    let apply = std::env::args().any(|a| a == "--apply");
    println!(
        "[elara-consolidate] mode: {}",
        if apply { "APPLY" } else { "dry-run (pass --apply to mutate)" }
    );

    if apply && daemon_running() {
        eprintln!(
            "[elara-consolidate] REFUSING --apply: elara-cognition is ACTIVE. \
             The daemon holds the store in memory and its next flush would clobber \
             this edit. Run `systemctl --user stop elara-cognition` first."
        );
        std::process::exit(2);
    }

    let mut mem = semantic_memory::load(None);
    let before = mem.entries().len();
    println!("[elara-consolidate] loaded {before} entries");
    if before == 0 {
        // A healthy store is never empty; an empty load here almost certainly
        // means a sidecar/integrity failure upstream. Never "collapse" that.
        eprintln!("[elara-consolidate] ABORT: store loaded EMPTY — refusing to touch it");
        std::process::exit(3);
    }

    let mut probe = mem.clone();
    let report = probe.collapse_exact_duplicates();

    println!(
        "[elara-consolidate] clusters: {} seen, {} collapsible, {} skipped",
        report.clusters_seen,
        report.clusters_collapsed,
        report.clusters_skipped.len()
    );
    for (id, size, reason) in &report.clusters_skipped {
        println!("  SKIP cluster(rep id {id}, size {size}): {reason}");
    }
    println!(
        "[elara-consolidate] plan: remove {} entries, keep {} survivors",
        report.entries_removed,
        report.survivor_ids.len()
    );
    println!("  survivors: {:?}", report.survivor_ids);
    println!("  removed:   {:?}", report.removed_ids);

    if !apply {
        println!("[elara-consolidate] dry-run complete — nothing written");
        return;
    }

    let applied = mem.collapse_exact_duplicates();
    assert_eq!(
        applied.removed_ids, report.removed_ids,
        "apply pass must match the just-printed plan"
    );
    match semantic_memory::save(&mem, None) {
        Ok(()) => println!(
            "[elara-consolidate] APPLIED: {} → {} entries ({} removed); sidecar regenerated",
            before,
            mem.entries().len(),
            applied.entries_removed
        ),
        Err(e) => {
            eprintln!("[elara-consolidate] SAVE FAILED: {e} — store file NOT modified (atomic write)");
            std::process::exit(4);
        }
    }
}
