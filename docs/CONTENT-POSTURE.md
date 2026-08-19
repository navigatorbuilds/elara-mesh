# Content Posture — commitments, not content

**Doctrine: integrity is protocol law; availability is operator choice.** The
mesh's value is that attested history cannot be
silently rewritten. It must never become the world's involuntary hard drive.
These two survive together only if the protocol is precise about what it
carries and what it promises.

## What the mesh carries

Records are **commitments**: content hashes, post-quantum signatures, causal
links, bounded metadata (`MAX_METADATA_ENTRIES = 64`,
`MAX_METADATA_VALUE_LEN = 8192` — enforced at ingest). Payloads live
**off-mesh** with their owners. The mesh proves *that* something existed, in
what form, authored by whom, when — it does not host the something.

## Erasure (GDPR / right-to-be-forgotten)

Erase the off-mesh payload and what remains on-mesh is an opaque hash plus
attestation context. The record continues to prove existence-at-time without
preserving the data — provable history and erasable content, by construction.
(Honest caveat: metadata fields can carry personal data if users put it
there; see abuse handling. NETWORK_PUBLISH additionally carries
`redaction_policy` for realm-to-public transitions.)

## Metadata abuse (the OP_RETURN problem)

Up to ~64KB/record of arbitrary bytes is a real smuggling channel (the 64 KiB
whole-record cap `MAX_RECORD_BYTES` binds before the nominal 64-entry × 8 KB
metadata budget). Layered answer:

1. **Cost:** OPEN-realm ingestion is stake/rate-gated — bulk smuggling pays
   bulk prices (earn-in economy keeps free-floor records small and slow).
2. **Retention classes + pinning** (see AGENT-DELEGATION): nodes are not
   obligated to store unpinned non-protocol payload-bearing records forever.
   Unpinned junk ages out of nodes that choose to drop it; pinned evidence
   persists with its pinner's stake behind it.
3. **Operator sovereignty:** each node already chooses storage scope (zone
   subscriptions); each operator applies their jurisdiction's law to what
   they STORE. The protocol guarantees what was ATTESTED cannot be silently
   rewritten — it never guarantees universal availability of every byte.
   Censorship-resistance of history without forced hosting of content.
4. **Uniform metadata budget (not per-kind caps).** The metadata budget is a
   single ceiling for every record kind — 64 entries × 8 KB values, bounded
   above by the 64 KiB whole-record cap (`MAX_RECORD_BYTES`), which binds
   first, so the practical channel is <64 KiB/record. Protocol records (epoch
   seals with Dilithium3-signed sortition proofs — SHA3-based, not a full
   RFC-9381 VRF — ~3.3 KB each) need the headroom; differential per-kind caps
   were considered and rejected — they add a wire-validation surface
   (kind-claim gaming; two ceilings to keep consistent with the Dilithium3-VRF
   proof-size assert at ingest) while, with the record cap binding first, they
   would not shrink the practical channel at all. Layers 1–3 above (ingestion cost, retention decay of the
   unpinned, operator storage sovereignty) are the actual defense and are
   kind-agnostic; the lever for observed junk volume is retention classes,
   not tighter caps.

## Abuse handling (early-network posture)

- Abuse contact published in SECURITY.md (+ site).
- SOP for reports: (1) payloads are never hosted — point reporters at the
  off-mesh host; (2) metadata abuse: unpin + local-retention drop on
  operator-run nodes + flag; (3) document every action taken (the response
  itself is recorded — this is a provenance project); (4) legal escalation to
  the maintainers.
- Operator liability: disclaimers at launch; the legal-entity question is
  revisited when funding makes counsel practical.

## What we never do

No protocol-level content deletion, no authority who can rewrite attested
history, no silent removals — the answer to bad content is cost, decay of
the unpinned, and operator storage choice; never a delete button on truth.
