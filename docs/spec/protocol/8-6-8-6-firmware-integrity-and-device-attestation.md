### 8.6 Firmware Integrity and Device Attestation

Physical access to IoT deployments is a realistic attack vector. An adversary who captures a Profile C device can clone its firmware, implant a backdoor, and inject false readings through the gateway. The protocol mitigates this through:

**Secure boot attestation** — devices that support it produce a firmware hash at boot time. The security level varies by hardware: ARM TrustZone provides hardware-isolated key storage; ESP32-S3 secure boot uses eFuse-based verification of a signed bootloader in flash (not a full hardware-fused signing key). The gateway verifies the firmware hash before accepting readings. Devices with unexpected firmware hashes are quarantined. The attestation strength is reflected in the device's trust weight — hardware-isolated attestation carries more weight than flash-based verification.

**Heartbeat anomaly detection** — gateways monitor timing patterns, reading distributions, and communication behavior of leaf devices. A cloned device with modified firmware will exhibit measurable behavioral differences (response latency, reading noise profile, boot timing). The AI layer (Layer 3) can flag statistical anomalies for operator investigation.

**Key rotation** — pre-shared symmetric keys between leaf devices and gateways are rotated periodically (configurable, default: 30 days). A captured device with an extracted key has a limited exploitation window.

**Physical tamper detection** — for high-security deployments (medical, military, critical infrastructure), devices can include tamper-evident enclosures that zeroize key material upon case opening. This is not required by the protocol but is recommended for Profile C deployments with physical access risk.

For the broader threat of device wipes, identity resets, and reputation escape through hardware recycling — including hardware-bound identity persistence, organizational binding, behavioral fingerprinting, and decommissioning protocols — see Section 11.33.

---

