### 11.10 Free Tier and Economic Accessibility

> **Scope note:** The beat economics described in this section apply exclusively to the public permissionless network. Private network deployments (Section 10.6) — enterprise, government, defense — have no beat involvement. Layer 1 validation is always free, always offline, always sovereign. No network, no beats, no fees.

**The question:** Section 3.5 shows that any device can validate locally for free. Section 9 describes beat staking for public network witnessing. For participants on the public network without beats, who pays for their records to be witnessed?

**Solution: Tiered Economic Model**

**Layer 1: Always free. No exceptions.**

Local validation — generating a keypair, hashing content, signing with a private key, storing on local DAG — costs zero beats. This is a cryptographic operation that runs on the device's own hardware. It is free because it consumes no network resources. Private network deployments operate entirely at this level with organizational witnessing — no beat layer exists.

This is the foundational principle of the protocol. Layer 1 never has a cost, on any deployment model.

**Layer 2: Free propagation, paid priority.**

When a node syncs to the network, its validation records propagate through the gossip protocol. Basic propagation is free — relay nodes forward records as part of their normal operation (they benefit from a well-connected DAM, so relaying is incentive-compatible).

What costs beats is **priority**: requesting faster propagation, higher witness counts, or guaranteed inclusion in the next epoch summary. Free-tier records propagate and accumulate witnesses organically. Paid-tier records get expedited service.

```
Free tier:
- Local validation: always free
- Network propagation: free (best-effort gossip)
- Witness accumulation: organic (witnesses choose what to attest)
- Epoch inclusion: guaranteed (but not prioritized)
- Storage: included in epoch summaries

Paid tier (beats):
- Priority propagation: faster global reach
- Requested witnessing: specific anchor nodes attest on request
- Priority sync: records synced first during bandwidth-limited windows
- Layer 3 AI: pattern analysis, similarity search, anomaly detection
```

**Community witnessing pool:**

A percentage of the Community/Governance beat allocation (20% of genesis supply) funds a **public witnessing service** — anchor nodes that attest to free-tier records. This creates a baseline level of network attestation for all participants, regardless of economic status.

Free-tier records propagate for free, get witnessed by community-funded anchors, and accumulate organic witnesses over time. Any user has the same Layer 1 cryptographic proof as a Fortune 500 company. Their Layer 2 trust score grows slower than paid-tier — but it grows.

**Earn-by-participation:**

Nodes that contribute resources (relay bandwidth, storage, compute) earn beats. The teenager's phone, by relaying other users' records, earns enough beats to request priority witnessing if she ever needs it. The protocol pays its participants. The complete tiered economic model, storage delegation markets, and earn-by-participation mechanics are specified separately.

