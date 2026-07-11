### 11.17 Beat Supply Model

> **Scope: Public permissionless network only.** This section applies to the public permissionless network. Private deployments have no beat supply.

> **Full specification:** The complete beat supply model — including supply mechanics and conservation economics — is specified separately. This section addresses only the adversarial implications.

The public network's beat supply model is designed as a **conservation system** — beats circulate between producers (witnesses) and consumers (record submitters) rather than being continuously minted. This design choice has specific security implications:

- **No inflationary dilution attack** — because supply is fixed, an attacker cannot devalue existing stakes by inflating the supply
- **MEV prevention** — witness attestation order does not affect outcome (trust scores are order-independent — the same witnesses produce the same trust score regardless of when they attest). This eliminates Maximal Extractable Value by design. There is nothing to extract from reordering.
- **No gas fee exploitation** — because the protocol does not charge per-transaction gas fees, there is no fee market to manipulate

The complete supply model, distribution schedule, and economic equilibrium analysis are specified separately.

