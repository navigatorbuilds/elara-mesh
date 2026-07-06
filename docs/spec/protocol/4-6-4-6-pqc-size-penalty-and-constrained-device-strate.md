### 4.6 PQC Size Penalty and Constrained Device Strategy

Post-quantum cryptography provides stronger security at a measurable cost in size:

| Algorithm           | Key Size    | Signature Size | Classical Equivalent   |
|---------------------|-------------|----------------|------------------------|
| CRYSTALS-Dilithium3 | 1,952 bytes | 3,293 bytes†   | ECDSA: 33 + 72 bytes   |
| SPHINCS+-SHA2-192f  | 48 bytes    | 35,664 bytes   | Ed25519: 32 + 64 bytes |
| CRYSTALS-Kyber768   | 1,184 bytes | 1,088 bytes    | X25519: 32 bytes       |

†liboqs Round 3 implementation value; FIPS 204 final specifies 3,309 bytes for ML-DSA-65 (see Section 4.2 for migration plan).

Dilithium signatures are **~46x larger** than ECDSA signatures (3,293 vs ~72 bytes). For a datacenter or laptop, this is negligible. For an ESP32 sending thousands of signed readings over LoRa (max payload ~242 bytes), it is prohibitive.

**Solution: Tiered Cryptographic Profiles**

The protocol defines three cryptographic profiles that devices select based on their capabilities:

**Profile A: Full PQC (default)**
- Dilithium3 signatures, Kyber768 key exchange, SPHINCS+ for anchoring
- For: servers, laptops, phones, gateways
- Signature overhead: ~3.3 KB per record

**Profile B: Compact PQC**
- Dilithium3 (same parameter set as Profile A: 3,293 byte signatures, NIST Level 3)
- No dual signatures (Dilithium only, no SPHINCS+)
- For: Raspberry Pi, industrial controllers, modern IoT gateways
- Signature overhead: ~3.3 KB per record (identical to Profile A primary signature)

**Profile C: Gateway-Delegated Signing**
- Constrained device (ESP32) sends unsigned readings to a trusted gateway via secure local channel (BLE, CAN, wired)
- Gateway batches readings and signs the batch with Profile A or B
- Device authenticates to gateway using lightweight symmetric key (pre-shared, established at provisioning)
- For: $4 microcontrollers, ultra-low-power sensors
- Per-reading overhead on device: ~32 bytes (HMAC)
- Per-batch overhead on network: ~3.3 KB (one Dilithium signature per batch of hundreds/thousands of readings)

**Profile C** is a pragmatic compromise: the constrained device cannot run PQC itself, but its readings are still validated on the DAM through a trusted gateway. The trust boundary shifts from the device to the gateway — acceptable for IoT deployments where the gateway is physically secured alongside the sensors.

All three profiles produce validation records that are interoperable on the DAM. The profile is specified in the record metadata, so verifiers know which security level applies.

**Profile B Security Boundary (v0.7.1 clarification).** Profile B is Profile A minus SPHINCS+ — it uses the same ML-DSA-65 (Dilithium3, NIST Level 3) primary signature but omits the SLH-DSA secondary signature. Under the quantum adversary model of §11.12 / §12.1, Profile B records become forgeable if ML-DSA-65 is broken by a quantum adversary — unlike Profile A records which remain secure via the independent SPHINCS+ signature. Consequently, Profile B identities are treated as lower-trust for consensus purposes. The protocol recommends: (a) transfer limits for Profile B identities (e.g., max 1,000 beats per transaction), (b) settlement requires a minimum fraction of Profile A attestations (e.g., ≥50% of attesting stake from Profile A witnesses), and (c) high-value operations (staking >10K beats, governance votes) require Profile A identity.

**Future PQC Size Reduction: NIST Additional Signatures Project**

The PQC size penalty described above reflects the first generation of NIST-standardized post-quantum signatures. This is not the final generation. In November 2024, NIST announced the **Post-Quantum Cryptography: Additional Digital Signature Schemes** project, accepting ~50 submissions for evaluation. Several candidates offer dramatically smaller signatures than Dilithium:

| Candidate | Signature Size | vs. Dilithium3 (3,293 B) | Basis |
|-----------|---------------|--------------------------|-------|
| **SQIsign** | ~204 bytes | **16x smaller** | Supersingular isogenies |
| **HAWK** | ~555 bytes | **6x smaller** | Lattice (NTRU) |
| **UOV** (variants) | ~96–128 bytes | **25-34x smaller** | Multivariate |

These are candidates, not standards — NIST evaluation will take years, with standardization likely in 2027-2028 at the earliest. Signing performance varies (SQIsign is significantly slower than Dilithium), and security assumptions for some candidates are less studied.

The Elara Protocol's **algorithm agility** (Section 4.4) means that adoption of compact PQC signatures is a configuration change, not a protocol redesign. When NIST standardizes a compact alternative:

1. New algorithm identifier added to the protocol via governance vote
2. Transition period: both Dilithium and the new algorithm accepted
3. New records use the compact algorithm; old records remain valid under Dilithium
4. Profile B and C devices benefit most — a 200-byte signature eliminates the size penalty that drove the Profile C delegation model

The current 46x size penalty over classical signatures is a first-generation cost, not a permanent constraint. The protocol is designed to absorb future improvements without structural change.

---

