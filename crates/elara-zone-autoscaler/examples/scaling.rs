// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! Adaptive sharding decisions in ~40 lines: feed a per-zone throughput
//! snapshot to the pure `recommend_zone_count`, then watch the stateful
//! `AutoScaler` swallow a transient spike and fire a Split only once the load
//! stays hot for `hysteresis_ticks` in a row. Dependency-free, generic over the
//! zone-id type.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-zone-autoscaler --example scaling
//! ```
//!
//! This is the decision engine behind Elara's zone auto-scaling: it says *what*
//! the zone count should be; the node owns the signed transition that makes it
//! so. Hysteresis is what stops a bursty workload from flapping splits/merges.

use elara_zone_autoscaler::{recommend_zone_count, AutoScaler, ScalingDecision, MAX_ZONE_COUNT};
use std::collections::HashMap;

fn main() {
    // A snapshot of per-zone record rates (records/sec). Two zones, both hot —
    // averaging well above the split threshold (TARGET_ZONE_RATE 20 x 2 = 40).
    let mut hot: HashMap<u64, f64> = HashMap::new();
    hot.insert(0, 55.0);
    hot.insert(1, 60.0);

    // Pure, stateless recommendation: avg 57.5 rec/s >> 40 -> Split.
    match recommend_zone_count(&hot, 2, MAX_ZONE_COUNT) {
        ScalingDecision::Split { new_count, avg_rate } => {
            println!("pure: avg {avg_rate:.1} rec/s over 2 zones -> SPLIT to {new_count} zones");
        }
        other => println!("pure: {other:?}"),
    }

    // But one hot tick must not reshard the network. The AutoScaler requires
    // `hysteresis_ticks` consecutive hot observations before it commits.
    let mut scaler = AutoScaler::new(4, MAX_ZONE_COUNT); // fire only after 4 in a row
    println!("\nAutoScaler (hysteresis = 4): driving health ticks...");
    for tick in 1..=4 {
        let fired = scaler.observe(&hot, 2);
        let (hot_streak, _) = scaler.counters();
        match fired {
            Some(ScalingDecision::Split { new_count, .. }) => {
                println!("  tick {tick}: FIRED -> split to {new_count} zones");
            }
            _ => println!("  tick {tick}: holding (hot streak = {hot_streak}/4)"),
        }
    }

    println!("\nA single transient spike never reshards; only sustained load does.");
}
