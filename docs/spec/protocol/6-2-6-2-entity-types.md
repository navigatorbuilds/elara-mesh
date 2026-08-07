### 6.2 Entity Types

The protocol recognizes five entity types, each with the same cryptographic standing:

**HUMAN** — Individual creators. One or more keypairs per person (separation of personal and professional identity is supported).

**AI** — Artificial intelligence systems. Each AI model instance generates its own keypair. This solves the AI attribution problem: when an AI generates content, its validation record includes the AI's identity, the model version, and (optionally) the prompt that triggered the generation.

**DEVICE** — IoT sensors, robots, vehicles, satellites. Capable devices (Raspberry Pi and above) generate a keypair at first boot and sign readings directly (Profile A/B). Constrained devices ($4 ESP32) authenticate to a local gateway via pre-shared symmetric key; the gateway signs batches on their behalf (Profile C, Section 4.6). Device identity persistence across physical resets — including hardware-bound keys, organizational binding, and behavioral fingerprinting — is addressed in Section 11.33.

**ORGANIZATION** — Companies, research labs, governments. Organizational identities can designate authorized signers (multi-signature schemes).

**COMPOSITE** — Human-AI collaborations. A composite identity explicitly records the relationship: who prompted, who generated, who edited, who approved. This creates an unambiguous attribution chain that courts, patent offices, and licensing systems can interpret.

