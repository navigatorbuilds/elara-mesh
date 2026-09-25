### 11.2 Key Compromise and Revocation

**The scenario:** A teenager's phone is stolen. The thief has her private key. Without intervention, the thief can sign new work as her and validate fraudulent claims under her identity.

**Revocation mechanism:**

Every Elara identity supports a **revocation record** — a special validation record that:

1. Is signed with the compromised key (proving ownership)
2. Contains a revocation timestamp (all signatures after this time are invalid)
3. Optionally designates a successor key (migration, not just termination)
4. Is flagged as REVOCATION type and propagates with highest priority across the network

Once published, the revocation record is immutable on the DAM. All future signatures from the compromised key are rejected by any node that has received the revocation.

**But what if the thief revokes first?**

This is the harder problem. The protocol handles it through **pre-committed recovery keys:**

At identity creation, the user can (and is strongly encouraged to) generate a **recovery keypair** stored separately — written on paper, saved on a USB drive, held by a trusted person. The design embeds a commitment to the recovery key in the original identity record. (Status: the runtime defines the succession data model and record formats, but no node path processes them yet; recovery is specified, not operational.)

Only the recovery key can:
- Override a fraudulent revocation
- Designate the legitimate successor key
- Prove identity in a dispute where both parties hold valid keys

If no recovery key was pre-committed, the dispute becomes a social/legal matter — but the DAM preserves the full timeline of both parties' claims, providing evidence for resolution.

**Dual compromise (both primary and recovery keys lost):** If an adversary obtains both keys, the identity is irrecoverably compromised. The user must create a new identity and rely on out-of-band evidence (legal records, prior witnesses, incremental creation chains) to re-establish attribution of their work. This is the catastrophic failure mode — analogous to losing both a password and all recovery options. The protocol cannot solve this cryptographically; it can only preserve the evidentiary record for dispute resolution. Users who require higher assurance should use multi-party recovery schemes (e.g., Shamir secret sharing across trusted contacts) to protect their recovery key.

**Key rotation:**

The protocol **specifies** scheduled key rotation without identity loss: a rotation record — signed by both the old and new keys — would maintain continuity, keeping all past work attributed to the identity while future work uses the new key, limiting the damage window of a compromise. **This mechanism is specified but not yet operational** (an identity is currently addressed by the hash of its active key, so a rotated key resolves to a different account — see §14 and KNOWN-LIMITATIONS). Today, key **revocation** (the compromised-key tombstone) is the live compromise-recovery path; rotation lands with a versioned identity→active-key index.

Note: deliberate key destruction through device wipes — where the goal is to sever accountability rather than steal identity — is a distinct attack vector addressed in Section 11.33.

