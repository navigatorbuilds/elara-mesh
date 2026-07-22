## Context

Decentralized peer discovery is a security-critical problem for any permissionless
mesh: a joining node must locate honest peers and verify it has reached the real
network — not an attacker's simulation — with no trusted coordinator to ask. A naive
setup that depends on hardcoded or hand-updated peer addresses does not survive
address churn or adversarial conditions in production. This document captures the
research behind Elara's approach to peer discovery for a multi-zone post-quantum
mesh: how existing networks bootstrap, the known attack classes, and the design
choices that follow.

---

