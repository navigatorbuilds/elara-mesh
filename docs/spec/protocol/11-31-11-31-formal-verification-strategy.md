### 11.31 Formal Verification Strategy

**The obligation:** A protocol handling trust for all digital creation across planetary distances must be provably correct. Informal reasoning and test suites are necessary but insufficient. Formal methods check that the protocol's stated properties hold in bounded models of it; they complement the tests below and do not replace them.

**Approach: Layered Verification**

**Layer 1: TLA+ Specification of Consensus**

The Adaptive Witness Consensus mechanism (Section 11.12) is specified in TLA+ (Temporal Logic of Actions) — the same framework used to verify distributed databases, cache coherence protocols, and globally distributed data services at major technology companies — and its safety and liveness cores are bounded-model-checked with TLC (the runnable models and configs ship in `spec/tla/`).

The TLA+ models, as shipped, check:
- **Safety (agreement):** two conflicting records claiming the same slot never both reach settlement while Byzantine stake stays below one third (`NoConflictingFinalization`), and diversity weighting can only lower a record's effective stake, never raise it (`DiversitySoundness`)
- **Cross-zone conservation:** a sealed transfer is never both claimed and aborted (`NoAbortAndClaim`, `SealGateSound`), and the four-bucket supply sum is invariant (`SupplyInvariant`), including the partition-merge seal-demotion tail
- **Liveness:** a sealed cross-zone transfer eventually settles under a live honest committee after GST (`LiveFast`), and in-zone epoch sealing recurs (`Liveness.tla`, `LivenessRecurrence.tla`). These are bounded models with uniform stake, with the record creator's stake set to zero, and with Byzantine proposers that only withhold. They count a raw two-thirds as meeting the diversity-weighted threshold, so they miss that seal settlement is not live (Section 11.12). The cross-epoch model assumes an unsteerable beacon; its failing twin shows the fast path is lost when the beacon can be steered, as the shipped one can
- **Not modelled:** record-preserving zone split and merge. The earlier claim that zone merging is verified to preserve all records without duplication or loss is withdrawn; that path is covered by tests, not by the TLA+ models

**Layer 2: Cryptographic Protocol Verification (ProVerif)**

The post-quantum transport handshake, the post-handshake record layer, and realm admission are modelled in ProVerif (`spec/proverif/`: handshake, record, admission and composed cores, assembled per scenario by `run-proverif.sh` and run in continuous integration). Under a Dolev-Yao attacker the models establish:

- Session-key secrecy and injective mutual authentication over the transcript for peers whose keys are already known (the transcript-bound ML-DSA-65 signature is the man-in-the-middle defence). On first contact a node trusts the key a peer presents (trust on first use); the models do not cover that case
- Hybrid secrecy: the session key stays secret when ML-KEM is fully broken, and when X25519 is fully broken — and, as an intentional failing scenario, not when both are
- Forward secrecy, key-compromise-impersonation resistance, and freedom from identity misbinding, each paired with an intentional-violation scenario that shows the query is not vacuous
- Not modelled: device authorization and revocation propagation, and the ZKP circuit. Tamarin has not been used

**Layer 3: Reference Implementation Testing**

Alongside the formal models, the reference implementation carries:

- **Decoder fuzzing:** the `decoder_fuzz` sweep feeds random inputs to the attacker-reachable wire decoders and runs in continuous integration; coverage-guided fuzzing (AFL, libFuzzer) is not yet set up
- **Fault-injection tests:** disk-full, memory-ceiling, slot-conflict and relay scenarios
- **Property-based testing:** planned
- **Simulation testing** (adversarial behavior, partitions, clock skew): planned, not yet run
- **Chaos engineering:** planned; done by hand on small testnets so far

**Timeline:**

- Phase 1: TLA+ specification and TLC model checking of the settlement, cross-zone, conservation and liveness cores — shipped (`spec/tla/`, `run-tlc.sh`)
- Phase 2: ProVerif models of the transport handshake, record layer and realm admission — shipped (`spec/proverif/`); machine-checked proofs at unbounded scale — ongoing
- Phase 3 (ongoing): the decoder fuzz sweep runs in continuous integration; coverage-guided fuzzing and simulation testing are planned

**Publication:** The specifications ship with the runtime source (github.com/navigatorbuilds/elara-mesh, `spec/`), so they can be re-run rather than trusted; the consensus proofs (three theorems and a liveness sketch) are in the companion paper (Vasic, 2026).

