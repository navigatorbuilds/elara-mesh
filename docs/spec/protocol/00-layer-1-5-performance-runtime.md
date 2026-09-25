#### Layer 1.5: Performance Runtime

Layer 1 defines the protocol semantics — what a valid record is, how it is signed, how it references parents. Its reference implementation is the Rust runtime in the public source repository, and the record encoding is specified normatively in that repository's `docs/PROTOCOL-SPEC.md`, with test vectors. Because the encoding is fixed, every conformant implementation produces byte-identical records. An early Python prototype of Layer 1 (February 2026) was never published and is no longer maintained. Layer 1.5 names the performance features of the same Rust runtime.

The Elara Runtime (Layer 1.5) implements:

- A **DAM Virtual Machine** with all 9 primitive operations: `DAM_INSERT`, `DAM_QUERY`, `DAM_WITNESS`, `DAM_HASH`, `DAM_SIGN`, `DAM_VERIFY`, `DAM_MERGE`, `DAM_CLASSIFY`, `DAM_ANALYZE`. The VM defines and tests the semantics of each operation; the node's own write path calls the storage layer directly rather than going through the VM.
- **5-tuple dimensional addressing** `(T, C, Z, K, A)` — the same addressing model that native hardware will implement physically
- **Tiled storage** with in-memory DAG index for sub-millisecond record lookup
- **Parallel batch verification** via Rayon — verifying multiple signatures concurrently on multi-core hardware
- **PyO3 bindings** — key generation, signing and verification for both signature algorithms (including batch verification), SHA3-256, record encoding and decoding, and account and light-client helpers, callable from Python; the DAM VM operations are not exposed to Python

Layer 1.5 is optional. A constrained device needs only the Layer 1 semantics — hash, sign, append to its local DAG — which are small enough to implement in any language. The Layer 1.5 features target capable hardware (laptops, servers, capable phones). No cross-language performance comparison has been measured, so this paper claims no speed-up factor. The progression is: Layer 1 semantics (language-agnostic; Rust reference implementation available now) → Layer 1.5 runtime features (Rust, available now) → native hardware (FPGA prototyping 2027, ASIC 2029+).

**No layer depends on the layers above it.** Layer 1 is universal. Layer 1.5 is an acceleration of Layer 1. Layer 2 requires connectivity. Layer 3 is optional.

