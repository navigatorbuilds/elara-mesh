### 4.3 Dual-Signature Strategy

A record can carry a second, SPHINCS+ signature alongside its ML-DSA signature (Profile A):

1. **Primary:** ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium) (fast, compact)
2. **Secondary:** SPHINCS+ (conservative, hash-based)

The design goal is defense-in-depth against cryptographic breakthroughs: ML-DSA (lattice-based) and SPHINCS+ (hash-based) rely on different mathematical assumptions, so a dual-signed record should stay unforgeable unless both are broken. **The current implementation does not yet meet that goal.** A record's SPHINCS+ public key is taken from the record itself and is not bound to the signer's identity, so an attacker who can forge ML-DSA signatures can also attach a fresh SPHINCS+ key and signature of their own; and because the SPHINCS+ fields are not part of the record identifier, any relay can strip or replace them without changing it. Until the key is bound (a planned wire change), a dual-signed record is as strong as ML-DSA alone. Witness attestations and epoch seals carry a single ML-DSA signature in any case, so dual signing protects record authorship at most, never consensus.

