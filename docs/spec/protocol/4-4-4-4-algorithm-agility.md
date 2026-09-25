### 4.4 Algorithm Agility

The Elara Protocol does not hardcode cryptographic algorithms. Every signature and key exchange specifies its algorithm identifier:

```
signature {
    algorithm: "dilithium3"
    value: <bytes>
}
```

When new algorithms are standardized or existing ones are deprecated, the protocol can migrate without structural changes. The design intent is that old records remain verifiable under their original algorithms while new records use updated ones. The shipped verifier does not yet honor this: it rejects the signature length of Round-3 Dilithium3, the pre-standard predecessor of ML-DSA-65 (FIPS 204), and no longer decodes wire versions 1–3, so records in those formats cannot be verified by the current code. Keeping retired formats verifiable is open work. The DAG preserves the full cryptographic history.

This agility is a core survival mechanism. A protocol that hardcodes today's best cryptography is guaranteed to become insecure. A protocol that specifies algorithms by identifier can evolve with the field.

