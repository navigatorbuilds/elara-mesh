#### 5.3.4 Trusted Setup

> **Implementation status — DESIGN-STAGE.** No CRS exists in the runtime. The
> Phase-1 SHA3-256 commitment scheme requires **no trusted setup**; the setup
> below applies only to the design-stage Groth16 construction.

The Groth16 construction would require a CRS (Common Reference String). For a future testnet of that construction, the CRS would be generated deterministically from a seed:

```
seed = SHA3-256("elara-protocol-groth16-crs-v2")
```

For mainnet, a multi-party computation (MPC) ceremony would produce the CRS. Security requires ≥1 honest participant who destroys their randomness. See Section 11.11 for the ceremony process and migration path to transparent proof systems (STARKs).

