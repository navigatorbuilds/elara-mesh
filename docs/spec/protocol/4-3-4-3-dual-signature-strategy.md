### 4.3 Dual-Signature Strategy

Critical validation records (anchor attestations, identity registrations, governance votes) carry dual signatures:

1. **Primary:** CRYSTALS-Dilithium (fast, compact)
2. **Secondary:** SPHINCS+ (conservative, hash-based)

This provides defense-in-depth against cryptographic breakthroughs. Dilithium (lattice-based) and SPHINCS+ (hash-based) rely on fundamentally different mathematical assumptions — lattice problems and hash function preimage resistance, respectively. Breaking one does not weaken the other. If lattice-based cryptography falls to an unforeseen advance, the hash-based signature remains valid; if hash functions are weakened, the lattice signature still holds. Both must be broken simultaneously to forge a dual-signed record. The protocol's trust model degrades gracefully rather than failing catastrophically.

