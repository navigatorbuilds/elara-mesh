### 11.17 Beat Supply Model

> **Scope: Public permissionless network only.** This section applies to the public permissionless network. Private deployments have no beat supply.

> **Scope.** This section describes the public network's beat supply model — a fixed-supply conservation system — and its security implications. See Section 9 for the protocol-level economic summary.

The public network's beat supply model is designed as a **conservation system** — beats circulate between producers (witnesses) and consumers (record submitters) rather than being continuously minted. This design choice has specific security implications:

- **No inflationary dilution attack** — because supply is fixed, an attacker cannot devalue existing stakes by inflating the supply
- **MEV prevention** — witness attestation order does not affect outcome (trust scores are order-independent — given the same attestations and ledger state, the same witnesses produce the same trust score whatever order they attest in). This eliminates Maximal Extractable Value by design. There is nothing to extract from reordering.
- **No gas fee exploitation** — because the protocol does not charge per-transaction gas fees, there is no fee market to manipulate

**Genesis allocation.** The fixed supply (10 billion beats) is partitioned at genesis into six internal accounting pools. Only the bootstrap pool has an active distribution path (the participation faucet, Section 9.5 of the whitepaper); the others are reserved genesis balances. Consistent with Section 9.2, **no pool is sold, listed, auctioned, or made tradeable** — this is internal accounting, not a token distribution.

| Pool | Share | Distribution path |
|------|------:|-------------------|
| Bootstrap | 30% | **Active** — earned by participating nodes via the faucet (whitepaper §9.5) |
| Development | 20% | Reserved genesis balance; a 3-of-5 multisig for protocol development is planned, not implemented; no market |
| Community | 20% | Reserved genesis balance; control by conviction voting (§10.3–10.4) is planned, not wired to this pool; no market |
| Team | 15% | Reserved genesis balance — **no active distribution path** |
| Contributors | 10% | Reserved genesis balance — **no active distribution path** |
| Reserve | 5% (+ rounding remainder) | Reserved genesis balance; a 4-of-5 multisig emergency reserve is planned, not implemented; no market |

The split is computed with exact integer arithmetic and a conservation check (the six pools sum to the total supply — no minting beyond genesis). Because beats are never tradeable, these shares confer no monetary claim; they bound how much internal staking/accounting weight each pool may hold, not a financial position.

