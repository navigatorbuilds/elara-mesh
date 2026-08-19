# Decision records

Structured decision records (`YYYY-MM-DD/<topic>.json`) capturing ratified
strategy/product calls and their reasoning.

> **⚠ THIS DIRECTORY SHIPS PUBLIC.** The release staging tooling includes
> `docs/decisions/` as a directory-level allowlist entry, so every file added
> here — any extension — lands in the public mirror by default. The mirror's
> voice/secret scans cover `*.md` **and** `*.json` (sweep 2026-07-12), but the
> scan is a regex net, not a judgment call: do not put session logs, ops
> details, IPs/hosts, credentials, or open ("pending / awaits go") internal
> deliberations in a decision record. Write every record as if a stranger
> reads it the day it lands — because after the flip, one will.
