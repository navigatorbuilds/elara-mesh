### 4.6 PQC Size Penalty and Constrained Device Strategy

Post-quantum cryptography provides stronger security at a measurable cost in size:

| Algorithm           | Key Size    | Signature Size | Classical Equivalent   |
|---------------------|-------------|----------------|------------------------|
| ML-DSA-65           | 1,952 bytes | 3,309 bytes†   | ECDSA: 33 + 72 bytes   |
| SPHINCS+-SHA2-192f  | 48 bytes    | 35,664 bytes   | Ed25519: 32 + 64 bytes |
| ML-KEM-768          | 1,184 bytes | 1,088 bytes    | X25519: 32 bytes       |

†FIPS 204 ML-DSA-65 standard value (3,309 bytes). Earlier liboqs Round 3 implementations used 3,293 bytes.

ML-DSA-65 signatures are **~46x larger** than ECDSA signatures (3,309 vs ~72 bytes). For a datacenter or laptop, this is negligible. For an ESP32 sending thousands of signed readings over LoRa (max payload ~242 bytes), it is prohibitive.

**Solution: Tiered Cryptographic Profiles**

The protocol defines three cryptographic profiles that devices select based on their capabilities:

**Profile A: Full PQC (default)**
- ML-DSA-65 signatures, ML-KEM-768 key exchange, optional SPHINCS+ second signature
- For: servers, laptops, phones, gateways
- Signature overhead: ~3.3 KB per record

**Profile B: Compact PQC**
- ML-DSA-65 (same parameter set as Profile A: 3,309 byte signatures, NIST Level 3)
- No dual signatures (ML-DSA only, no SPHINCS+)
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

**Profile B Security Boundary (v0.7.1 clarification; corrected in v0.7.38).** Profile B is Profile A minus SPHINCS+: it uses the same ML-DSA-65 primary signature and omits the secondary SPHINCS+ signature. If ML-DSA-65 is broken, Profile B records become forgeable. The design intends Profile A records to stay secure in that case through the independent SPHINCS+ signature; as shipped they do not, because the SPHINCS+ key is not yet bound to the signer's identity (Section 4.3). Profile B identities should therefore be treated as lower-trust. The runtime caps a transfer or stake without a SPHINCS+ signature at 1,000 beats, but any SPHINCS+ signature lifts the cap, including one made with a freshly generated key. Two further measures are recommendations the runtime does not enforce: requiring a minimum fraction of Profile A attestations for settlement (witness attestations carry a single ML-DSA signature in any case) and requiring a Profile A identity for governance votes.

**Future PQC Size Reduction: NIST Additional Signatures Project**

The PQC size penalty described above reflects the first generation of NIST-standardized post-quantum signatures. This is not the final generation. In November 2024, NIST announced the **Post-Quantum Cryptography: Additional Digital Signature Schemes** project, accepting ~50 submissions for evaluation. Several candidates offer dramatically smaller signatures than Dilithium:

| Candidate | Signature Size | vs. Dilithium3 (3,309 B) | Basis |
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

