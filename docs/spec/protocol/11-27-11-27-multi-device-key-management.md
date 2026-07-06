### 11.27 Multi-Device Key Management

**The problem:** A user has a phone, a laptop, and a tablet. They generate a keypair on their phone. How do they validate work from their laptop? If the phone breaks, how do they access their validated history from a new device?

This is the most common UX failure in cryptographic systems. PGP failed mass adoption largely because of key management complexity. The Elara Protocol must not repeat this.

**Solution: Identity Constellation Model**

Instead of one keypair per person, the protocol supports an **identity constellation** — a set of device keys linked to a root identity:

```
RootIdentity (generated once, stored securely)
├── DeviceKey: phone_key (signed by root)
├── DeviceKey: laptop_key (signed by root)
├── DeviceKey: tablet_key (signed by root)
└── RecoveryKey: paper_key (stored offline, Section 11.2)
```

**How it works:**

1. **Root key generation:** User generates a root keypair. This is the canonical identity. The root private key is immediately exported to a secure backup (paper, USB, password manager) and optionally deleted from the generating device.

2. **Device key enrollment:** Each device generates its own keypair and submits an enrollment request. The root key signs a **DeviceAuthorization** record:

```
DeviceAuthorization {
    root_identity:  root public key
    device_key:     device public key
    device_name:    "Alice's phone" (optional, user-facing)
    permissions:    [VALIDATE, WITNESS, REVOKE_DEVICE]
    expires:        optional expiration date
    signature:      root key signature
}
```

3. **Validation from any device:** When the user validates work from their laptop, the validation record is signed by laptop_key. Any verifier can follow the DeviceAuthorization chain: laptop_key → authorized by root_identity → valid.

4. **Device loss/theft:** The user revokes the lost device's key using any other enrolled device or the recovery key. A DeviceRevocation record propagates across the network. The lost device's future signatures are rejected.

5. **All devices lost:** The recovery key (paper, USB) can revoke all device keys and enroll new devices. This is the catastrophic recovery path — inconvenient but functional.

**Key sync between devices:**

Device keys are independent — they do not share private key material. There is no "syncing" of private keys between devices (which would be a security risk). Instead, each device has its own key, and the root identity links them.

The user's validated work history is accessible from any device by querying the DAM for records associated with the root identity or any of its authorized device keys.

**UX simplification:**

Reference implementations abstract this complexity:

- First launch: "Create your Elara identity" (generates root key + first device key)
- "Back up your recovery phrase" (12-word mnemonic encoding the root key, BIP-39 [25] compatible)
- Adding a device: scan QR code on existing device → DeviceAuthorization created automatically
- Losing a device: "Remove device" from any other enrolled device

The user never sees keypairs, hashes, or DAG structures. They see devices and a recovery phrase.

For organizational deployments (IoT fleets, enterprise environments), the Identity Constellation model extends to **organizational identity chains** with fleet-level binding — see Section 11.33 for the full specification.

