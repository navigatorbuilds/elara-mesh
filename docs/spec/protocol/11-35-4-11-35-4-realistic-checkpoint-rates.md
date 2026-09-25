#### 11.35.4 Realistic Checkpoint Rates

The theoretical maximum checkpoint rate (one every 5 minutes = 288/day) is never reached in practice. Checkpoints are triggered by cognitive events, not timers:

| Trigger | Typical Frequency | Size |
|---------|-------------------|------|
| Boot | 1/day | ~42 KB (dual-signed) |
| Shutdown | 1/day | ~42 KB |
| Milestone | 5-10/day | ~42 KB |
| Drift (session) | 2-5/day | ~42 KB |
| Manual | 0-2/day | ~42 KB |
| Periodic (rate-limited) | 5-10/day | ~42 KB |

Sizes are for a record carrying both signatures of Section 11.35.1 (ML-DSA-65 and the 35,664-byte SPHINCS+ signature); with ML-DSA-65 alone a checkpoint is about 6 KB.

**Realistic rate: 15-30 checkpoints/day per Tier 2+ node.**

**Storage budget:**

```
30 checkpoints/day × ~42,000 bytes ≈ 1.26 MB/day
1.26 MB/day × 365 days ≈ 460 MB/year per node
```

At 10,000 Tier 2+ nodes: about 4.6 TB/year of cognitive checkpoint data. Negligible compared to the 7 PB/year estimated for full IoT-scale validation records (Section 11.32).

