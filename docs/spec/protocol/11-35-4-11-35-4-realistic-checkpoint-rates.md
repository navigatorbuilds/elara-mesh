#### 11.35.4 Realistic Checkpoint Rates

The theoretical maximum checkpoint rate (one every 5 minutes = 288/day) is never reached in practice. Checkpoints are triggered by cognitive events, not timers:

| Trigger | Typical Frequency | Size |
|---------|-------------------|------|
| Boot | 1/day | ~3.5 KB (dual-signed) |
| Shutdown | 1/day | ~3.5 KB |
| Milestone | 5-10/day | ~3.5 KB |
| Drift (session) | 2-5/day | ~3.5 KB |
| Manual | 0-2/day | ~3.5 KB |
| Periodic (rate-limited) | 5-10/day | ~3.5 KB |

**Realistic rate: 15-30 checkpoints/day per Tier 2+ node.**

**Storage budget:**

```
30 checkpoints/day × 3,500 bytes = 105,000 bytes/day ≈ 100 KB/day
100 KB/day × 365 days = 36.5 MB/year per node
```

At 10,000 Tier 2+ nodes: 365 GB/year of cognitive checkpoint data. Negligible compared to the 7 PB/year estimated for full IoT-scale validation records (Section 11.32).

