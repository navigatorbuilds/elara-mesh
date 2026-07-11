### Cross-Zone Transfer: Two-Phase Lock/Claim

**Phase 1 — Lock (sender zone):**
1. Sender creates a `transfer-lock` record in their zone
2. Sender's account is debited. Amount moves to `pending_xzone` state
3. Record includes: recipient identity, recipient zone, amount, timeout epoch
4. Record is sealed in sender zone's epoch. Gets a Merkle proof.

**Phase 2 — Claim (recipient zone):**
1. Anyone presents the `transfer-lock` record + Merkle proof from sender zone's epoch seal to recipient zone
2. Recipient zone verifies: Merkle proof valid? Epoch seal signed by legitimate witnesses? Genesis chain intact?
3. Recipient zone creates `transfer-claim` record. Beats recipient's account.
4. Claim record references the lock record's hash (prevents double-claim).

**Conservation at every moment:**
```
Before lock:  beats in sender's balance
After lock:   beats in pending_xzone (sender zone tracks)
After claim:  beats in recipient's balance
Always:       sum(all_balances) + sum(pending_xzone) + pool == GENESIS_SUPPLY
```

**Timeout:** If claim isn't made within N epochs (e.g., 100 epochs = ~8 hours), lock expires. Funds return to sender automatically. Prevents permanent loss from zone unavailability.

**Where records live:**
- Lock record → sender's zone (it's the sender's action)
- Claim record → recipient's zone (it's the recipient's beat)
- Both zones update their ledger independently
- The Merkle proof is the bridge — no direct trust between zones needed

