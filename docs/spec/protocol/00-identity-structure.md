#### Identity Structure

```
ElaraIdentity {
    public_key:     CRYSTALS-Dilithium public key
    identity_hash:  SHA3-256(public_key)  // short identifier
    created:        timestamp
    entity_type:    HUMAN | AI | DEVICE | ORGANIZATION | COMPOSITE
    metadata:       optional, creator-defined, signed
    succession:     optional, designated heir public keys
    revocation:     self-revocation mechanism (signed revocation record)
}
```

The identity hash serves as a short, human-communicable identifier (similar to a fingerprint in PGP). The full public key is used for cryptographic operations.

