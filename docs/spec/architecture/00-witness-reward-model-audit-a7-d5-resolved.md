## Witness Reward Model

The witness reward formula, adapted for layered consensus:

```
epoch_reward = BASE_EPOCH_REWARD
             * record_count_factor         // more records = more work = more reward
             * trust_multiplier            // witness's trust score (existing)
             * diversity_bonus             // cross-zone witnessing bonus (existing, per-day)
             * entity_diminishing_returns  // prevents entity concentration (existing)
```

**record_count_factor:** `min(record_count / EXPECTED_RECORDS_PER_EPOCH, 2.0)`. A zone with 10M records/epoch pays more than one with 100 records/epoch. Capped at 2x to prevent gaming via self-generated records.

**diversity_bonus:** Still works — a witness attesting to 3 different zones' epoch seals in one day gets the diversity bonus. The bonus incentivizes witnessing across zones, not just one high-value zone.

---

