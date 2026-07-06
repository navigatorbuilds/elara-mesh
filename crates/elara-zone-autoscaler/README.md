# elara-zone-autoscaler

A small, dependency-free decision engine for **adaptive sharding**: given a
snapshot of per-zone activity, decide whether to split hot zones, merge cold
zones, or hold — with hysteresis so transient spikes don't flap the network.

Extracted from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
node, where it drives zone split/merge transitions, but it has no protocol
dependencies and works for any sharded system that can report a per-shard rate.

## What it does

- **`recommend_zone_count`** — pure function: per-zone activity (rec/s) →
  `ScalingDecision` (`Split` / `Merge` / `NoChange`). Decisions are coarse
  (double / halve) by design — a few transitions per hour, not continuous churn.
- **`AutoScaler`** — wraps the recommender with hysteresis: a direction must
  hold for `HYSTERESIS_TICKS` (default 4) consecutive observations before it
  fires, and the counters reset after firing.
- **`pick_transition_target`** — narrows a global decision to the concrete
  zone(s) to act on, with a deterministic tie-break (smallest zone id under
  `Ord`) so independent peers observing the same snapshot pick the *same*
  target — essential when a transition needs M-of-N agreement.

## Generic over the zone id

Everything is generic over the zone-identifier type `Z`. The recommender and
the autoscaler place no bound on `Z`; `pick_transition_target` needs only
`Z: Ord + Clone`. Use `String`, a newtype, or your own path type.

```rust
use std::collections::HashMap;
use elara_zone_autoscaler::{AutoScaler, ScalingDecision, pick_transition_target};

let mut scaler = AutoScaler::new(4, 1_000_000); // hysteresis ticks, max zones
let mut activity: HashMap<String, f64> = HashMap::new();
activity.insert("zone-0".into(), 55.0); // rec/s, well above the split band

// Feed one observation per health tick. Returns Some(..) only once the
// direction has held for `hysteresis_ticks` consecutive ticks.
if let Some(decision @ ScalingDecision::Split { .. }) = scaler.observe(&activity, 2) {
    if let Some(target) = pick_transition_target(&decision, &activity) {
        // act on `target` — e.g. emit a signed split announcement
        let _ = target;
    }
}
```

## Tuning knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `TARGET_ZONE_RATE` | `20.0` | Per-zone saturation rate (rec/s) |
| `SPLIT_RATE_MULTIPLIER` | `2.0` | Split when avg > 2× target |
| `MERGE_RATE_MULTIPLIER` | `0.1` | Merge when avg < 0.1× target |
| `HYSTERESIS_TICKS` | `4` | Consecutive ticks before acting |
| `MIN_ZONE_COUNT` / `MAX_ZONE_COUNT` | `1` / `1_000_000` | Hard bounds |

`TARGET_ZONE_RATE` is baked so the crate stays dependency-free; in the Elara
node it equals `target_records_per_epoch / min_epoch_secs`, with a test that
fails the build if those constants ever drift from this value.

## License

MIT OR Apache-2.0.
