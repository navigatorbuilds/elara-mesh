### 11.20 Nothing-at-Stake and Witness Incentive Alignment

**The problem:** In proof-of-stake systems, validators can sign conflicting blocks at no cost because there is "nothing at stake" — they don't burn energy like proof-of-work miners. Does the Elara Protocol's witness accumulation have the same problem? Can a witness attest to conflicting records (two creators claiming the same work) without penalty?

**Analysis:**

In blockchain PoS, nothing-at-stake matters because fork choice affects which chain becomes canonical. Attesting to both forks is profitable because you earn rewards on whichever one wins.

In the Elara Protocol, this dynamic does not apply because **both branches of a conflict are preserved.** There is no fork choice. Both records exist. Neither is "canonical." The trust score mechanism (Section 11.12) handles precedence through temporal and causal analysis, not by choosing a winner.

However, a related problem exists: **indiscriminate witnessing.** A witness could attest to everything — every record from every identity — to maximize rewards without performing any quality check. This degrades the trust signal.

**Solution: Witness Reputation Scoring**

Witnesses earn not just beats but **reputation** based on the quality of their attestations:

```
reputation_delta = f(record_outcome)

Record never disputed:          +1 reputation
Record disputed, witness sided with winner: +2 reputation
Record disputed, witness sided with loser:  -5 reputation
Record flagged as spam/anomaly:             -10 reputation
```

A witness that attests to everything — including spam and disputed records — rapidly loses reputation. Reputation loss reduces the weight of future attestations (Section 11.12), reducing earned rewards. Indiscriminate witnessing is therefore economically irrational.

A witness that carefully evaluates records before attesting — checking for rate limit compliance, duplicate content, identity trust, and causal consistency — maintains high reputation and earns more. Selective, honest witnessing is the Nash equilibrium. The complete witness incentive model and reward mechanics are specified separately.

The related problem of **reputation escape** — where an entity destroys a damaged identity to start fresh — is addressed in Section 11.33, which introduces identity continuity scoring and organizational binding as countermeasures.

