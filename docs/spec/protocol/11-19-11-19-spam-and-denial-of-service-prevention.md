### 11.19 Spam and Denial-of-Service Prevention

**The attack:** Layer 1 validation is free. An attacker generates millions of garbage validation records — random hashes, signed by valid keys — flooding the network. Each record is individually valid (correctly signed, properly formatted). The DAM fills with noise, relay and witness nodes waste bandwidth and storage, and legitimate records are drowned out.

This is the cost of "Layer 1 is always free." Free creation means free spam.

**Defense 1: Propagation Rate Limiting**

Layer 1 (local validation) is unrestricted — an attacker can fill their own local DAG with garbage. But Layer 2 (network propagation) applies rate limits:

- Each identity is allowed **N records per hour** via the gossip protocol (default: 100)
- Records exceeding the rate limit are queued, not rejected — they propagate eventually, but slowly
- Witness nodes prioritize attestation of records from identities within their rate limit
- Rate limits scale with identity trust score — a trusted, long-standing identity gets higher limits

An attacker generating 1 million records per hour from a fresh identity would see 100 propagate immediately and 999,900 enter a slow queue. By the time they propagate, the identity's anomalous behavior is flagged.

**Cross-zone enforcement of global rate limits.** Rate limits are per-identity GLOBALLY (10/50/200 records/day by trust tier), but with zone-scoped gossip a node in zone A only sees zone A traffic. An identity creating 200 records/day spread across 10 zones is within the per-zone window everywhere yet exceeds the global limit. Global enforcement is reconciled at epoch boundaries: each zone's epoch seal includes per-identity record counts for that epoch. A monitoring process (or fisherman) detects identities exceeding global limits by summing their per-identity counts across zone epoch seals and submits a challenge. Global enforcement therefore rides on the existing seal stream — no synchronous cross-zone coordination is required, and the check is eventually-consistent over a one-epoch window.

**Defense 2: Proof-of-Work for Burst Propagation**

If a node needs to propagate more than its rate limit (legitimate use case: IoT gateway syncing a batch of sensor readings), it can solve a lightweight proof-of-work puzzle for each excess record. The puzzle difficulty is calibrated so that:

- Normal usage (under rate limit): zero computational cost
- Moderate burst (2–10x limit): seconds of compute
- Spam-scale burst (1000x+ limit): hours/days of compute — economically infeasible

This is the same approach used by Hashcash [24] (email anti-spam, 2002) and later adopted by blockchain networks. It adds no cost to honest users and makes spam expensive.

**Defense 3: Content-Independent Duplicate Detection**

Bloom filters at the zone level detect records with identical content hashes. If the same hash is submitted by different identities simultaneously (a classic spam pattern — resubmitting the same garbage with different keys), only the first propagation proceeds. Subsequent duplicates are annotated as conflicts but not relayed further.

**Defense 4: Economic Filtering at Layer 2**

Witness nodes choose what to attest. They are rational economic actors — attesting costs computational resources (PoWaS). No witness will spend resources attesting to records from identities with zero trust, anomalous patterns, or rate-limit violations. Spam records exist on the DAM but accumulate zero witnesses and zero trust. They are dead weight — present but invisible to anyone querying the DAM with a minimum trust threshold.

