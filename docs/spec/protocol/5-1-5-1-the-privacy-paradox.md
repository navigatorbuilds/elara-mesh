### 5.1 The Privacy Paradox

Validation and privacy are traditionally in tension. To prove you created something, you must reveal what you created. This is acceptable for open-source code or public art, but unacceptable for:

- Trade secrets under development
- Medical data from IoT health devices
- Military or intelligence sensor readings
- Unreleased creative work
- Corporate R&D
- Personal journals or private communications

The Elara Protocol specifies zero-knowledge proofs (ZKPs) as the target privacy layer: cryptographic constructions that prove a statement is true without revealing the underlying data. Phase 1 ships SHA3-256 hash commitments as a stand-in (not genuine zero-knowledge — see §5.3); the zk-SNARK constructions described below are design-stage.

