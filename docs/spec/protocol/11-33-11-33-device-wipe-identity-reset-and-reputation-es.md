### 11.33 Device Wipe, Identity Reset, and Reputation Escape

**The attack:** An adversary — or a negligent operator — physically wipes a device and reboots it. The device generates a fresh cryptographic keypair at first boot (Section 6.2). The old identity, along with its accumulated trust weight, reputation history, and behavioral profile, is severed. The device now presents as a brand-new entity with zero history.

This is not a theoretical concern. It is trivially executable: flash a new OS, pull the battery, factory reset. Any device that generates identity from local entropy can be reset to a blank slate. The protocol cannot prevent a physical wipe — no software can survive a formatted disk.

**Why this matters — three attack scenarios:**

**Scenario 1: Reputation Escape**

A malicious IoT gateway operator deploys sensors that submit fabricated readings — false environmental data, manipulated supply chain records, fraudulent energy generation claims. The network's anomaly detection (Section 8.6) flags the devices. Their trust scores collapse. Rather than face accountability, the operator wipes every device, reboots, and re-enrolls them with fresh identities. The toxic history stays on the DAM under the old identities, but the new identities carry zero penalty. The operator is back in business.

**Scenario 2: Accountability Destruction**

A research lab validates experimental results on the protocol. Later, the results are found to be fabricated. The lab wipes the devices that signed the original records, destroying the private keys. The fraudulent records still exist on the DAM, but without the private key, no revocation or correction can be issued by the original identity. The lab creates new identities and distances itself from the old ones. There is no cryptographic link between old and new.

**Scenario 3: Sybil Amplification via Recycling**

An attacker with 100 physical devices generates identities, uses them until their trust scores are meaningful, then wipes and regenerates — creating an endless supply of fresh identities from the same hardware. Unlike pure Sybil attacks (Section 11.1), which require acquiring new devices or computational resources, identity recycling exploits the same physical devices repeatedly.

**Defense 1: Hardware-Bound Identity (Where Available)**

Some devices support hardware-rooted identity that survives wipes:

- **TPM (Trusted Platform Module)** — stores keys in tamper-resistant hardware. A factory reset clears the OS but not the TPM. The device's identity persists across wipes. Available on most modern x86 hardware and some ARM devices.
- **ARM TrustZone / Secure Enclave** — hardware-isolated key storage on mobile and embedded devices. A device key generated in TrustZone survives an OS reinstall.
- **eFuse-based identity** — one-time programmable fuses on some microcontrollers (ESP32-S3, certain NXP chips). The identity is literally burned into silicon at first boot. It cannot be reset without replacing the chip.
- **PUF (Physical Unclonable Function)** — semiconductor fingerprints derived from manufacturing variations. The identity is inherent to the physical silicon — it cannot be cloned, cannot be reset, and does not depend on stored key material.

The protocol assigns a **hardware attestation level** to each identity:

```
HardwareAttestation {
    level:  NONE | SOFTWARE | SECURE_BOOT | HARDWARE_KEY | PUF
    evidence: firmware hash, TPM endorsement key, PUF challenge-response
}
```

Identities with hardware-bound attestation that suddenly disappear and are replaced by a new identity from the same hardware class, same network location, and same behavioral pattern trigger an **identity discontinuity alert** at the zone level. The new identity is not rejected — rejection would violate the self-sovereign principle — but it is flagged, and its trust accumulation is throttled until the discontinuity is explained (e.g., legitimate hardware replacement, authorized device decommission).

**Defense 2: Identity Continuity Scoring**

The protocol introduces a **continuity score** as a component of trust weight. Continuity measures how long an identity has maintained an unbroken presence on the network:

```
continuity_score = f(identity_age, gap_history, attestation_consistency)

New identity (< 24 hours):         continuity = 0.0
Young identity (1-30 days):        continuity = 0.1 – 0.4
Established identity (30-365 days): continuity = 0.4 – 0.8
Veteran identity (1+ years):       continuity = 0.8 – 1.0
```

A wiped-and-reset device starts at continuity 0.0 — the same cold start as any new entity. This means:

- Its validation records carry minimal trust weight (Section 11.1)
- Its propagation rate is limited (Section 11.19, Defense 1)
- Its witness attestations are worth less to others
- It cannot earn elevated trust without sustained, consistent behavior over time

**There is no shortcut.** Trust is earned through time, and time cannot be manufactured. An operator who wipes 100 devices faces 100 cold starts — weeks or months before those devices carry meaningful weight again. The economic cost of lost trust is the deterrent.

**Defense 3: Organizational Identity Binding**

For IoT deployments, the protocol supports **organizational identity chains** — device identities linked to an organizational root identity (similar to the personal Identity Constellation in Section 11.27):

```
OrganizationIdentity (root)
├── DeviceFleet: "Weather Station Network" (signed by org root)
│   ├── Device_001 (signed by fleet key)
│   ├── Device_002 (signed by fleet key)
│   └── Device_NNN (signed by fleet key)
└── OperatorKey: "Field Technician A" (signed by org root)
```

When a device within a fleet is wiped, the organizational identity persists. The organization cannot escape accountability by resetting individual devices — the fleet's history, the organization's reputation, and the operator's actions are all linked to the root identity. Wiping a device only orphans that specific device key; the organizational chain of custody remains on the DAM.

An organization that attempts to escape accountability by wiping its root identity faces the same cold-start penalty described above — but at the organizational level, where the economic consequences are far more severe. Contracts, partnerships, and institutional trust built over months or years are lost.

**Defense 4: Network-Level Behavioral Fingerprinting**

Even without hardware attestation, devices exhibit behavioral fingerprints that are difficult to forge:

- **Network location** — IP range, gateway, geographic zone
- **Timing patterns** — boot times, reading intervals, sync frequencies
- **Data characteristics** — sensor noise profiles, value distributions, reading precision
- **Communication patterns** — which peers it connects to, sync timing, gossip participation

The AI layer (Layer 3) maintains behavioral profiles for active identities. When a new identity appears from the same network location, with similar timing patterns and data characteristics as a recently disappeared identity, the system calculates a **reincarnation probability**:

```
reincarnation_prob = similarity(new_identity_behavior, old_identity_behavior)

If reincarnation_prob > 0.85:
    Flag as probable identity reset
    Inherit old identity's trust penalties (not trust benefits)
    Require organizational attestation to clear the flag
```

This is explicitly a heuristic, not a proof. False positives are possible — a legitimate replacement device at the same location will exhibit similar behavior. The protocol does not punish automatically; it flags and throttles, leaving final adjudication to zone operators and the dispute resolution mechanism (Section 11.13).

**Defense 5: Decommissioning Protocol**

The protocol defines a legitimate device retirement process:

```
DeviceDecommission {
    device_key:     public key of the retiring device
    reason:         REPLACEMENT | END_OF_LIFE | COMPROMISE | TRANSFER
    successor:      optional, public key of the replacement device
    signed_by:      device key (if available) AND organizational key (if enrolled)
    timestamp:      network-witnessed
}
```

A properly decommissioned device creates a clear record: "Device_042 was retired on this date, replaced by Device_043, authorized by Organization_X." The successor device inherits the predecessor's behavioral context (not its private keys or trust score, but the network's understanding that this is a known replacement, not a suspicious new entity).

Devices that disappear without a decommission record are flagged as **abandoned identities.** If a new device appears that behaviorally matches an abandoned identity, the reincarnation detection (Defense 4) applies.

**What the protocol cannot prevent — honest acknowledgment:**

1. **A determined individual wiping a personal phone** and creating a new identity. If there is no hardware-bound key, no organizational chain, and the user connects from a different network — the old and new identities are cryptographically unlinkable. The protocol treats this as a new person. This is by design: self-sovereign identity means the protocol cannot force identity persistence. The tradeoff is deliberate — the alternative (mandatory identity linking) would require a central authority, which violates the protocol's foundational principle.

2. **Constrained devices (Profile C) without hardware attestation.** A $4 ESP32 with a pre-shared symmetric key has no TPM, no PUF, no hardware identity. Wiping it and reprogramming it creates a genuinely new device from the protocol's perspective. The mitigation is organizational binding (Defense 3) and gateway-level anomaly detection (Section 8.6), not device-level identity persistence.

3. **Perfect behavioral mimicry.** If an attacker studies a device's behavioral fingerprint and reproduces it exactly on a fresh identity, the reincarnation detection will not trigger. This requires significant effort and ongoing maintenance — the attacker must continuously match the original device's patterns. The cost is prohibitive for most scenarios but not impossible for state-level adversaries.

**The fundamental tradeoff:**

Self-sovereign identity and identity reset resistance are in tension. A system that truly allows anyone to create an identity without permission must also accept that anyone can create a *new* identity without permission. The Elara Protocol resolves this tension not by preventing identity creation, but by making **trust expensive to build and cheap to lose.** A fresh identity is free. A trusted identity takes months. Destroying trust takes seconds. Rebuilding it takes months again.

This asymmetry — combined with hardware binding where available, organizational chains for IoT, behavioral fingerprinting, and decommissioning protocols — makes identity reset a viable but costly strategy. The protocol does not claim to make it impossible. It claims to make it unprofitable.

