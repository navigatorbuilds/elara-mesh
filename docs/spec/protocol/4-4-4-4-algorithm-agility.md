### 4.4 Algorithm Agility

The Elara Protocol does not hardcode cryptographic algorithms. Every signature and key exchange specifies its algorithm identifier:

```
signature {
    algorithm: "dilithium3"
    value: <bytes>
}
```

When new algorithms are standardized or existing ones are deprecated, the protocol can migrate without structural changes. Old records remain valid under their original algorithms; new records use updated algorithms. The DAG preserves the full cryptographic history.

This agility is a core survival mechanism. A protocol that hardcodes today's best cryptography is guaranteed to become insecure. A protocol that specifies algorithms by identifier can evolve with the field.

