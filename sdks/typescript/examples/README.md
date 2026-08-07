# `@elara/sdk` examples

Three runnable scripts — each verbatim against a node you operate (no public testnet endpoints yet).

| File                  | What it shows                                                   |
|-----------------------|-----------------------------------------------------------------|
| `quickstart.ts`       | The three-line spec — `Agent.create` → `balance` → `prove`.     |
| `light_verify.ts`     | Fetch a fresh proof and compare its root to the latest seal.    |
| `submit_record.ts`    | Sign-and-submit pattern with a stub signer (wire your wallet).  |

## Running

```bash
npm install
ELARA_NODE_URL=http://127.0.0.1:9473 \
ELARA_IDENTITY=<your-64-hex-char-identity> \
npm run example:quickstart
```

The examples call the same in-process SDK code the unit tests exercise, so
typechecking them is part of `npm run typecheck:examples`.
