### 4.1 The Quantum Timeline

Quantum computing capable of breaking current cryptographic standards (RSA-2048, ECDSA, EdDSA) is widely believed to arrive within 10–20 years, though the exact timeline remains highly uncertain and subject to ongoing debate. NIST finalized its first post-quantum standards in August 2024, signaling that the migration is no longer theoretical.

The threat model is "harvest now, decrypt later": adversaries can collect encrypted data and signed records today, then break the cryptography retroactively when quantum computers become available. For a protocol designed to produce proofs that outlive the protocol itself, this is not a future concern — it is a present design requirement.

