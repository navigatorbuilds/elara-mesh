# Upstream conformance vectors (verbatim copies)

Source: `robertolocatelli81-dev/ap2-evidence-pack`, commit `ed57e24c1c5088ddadb8346b05b5725629d5456a`
(spec v1.0, 2026-09-05), licence Apache-2.0 (copyright Roberto Locatelli). Copied byte-for-byte on
2026-09-06 so this reader's tests are self-contained; nothing here was edited.

| file | sha256 |
|---|---|
| `SPEC_AP2_EVIDENCE.md` | a091d16ee7992986… |
| `valid_signed.json` (= `anchor_missing.json`) | 89a63ec3b581a0cc… |
| `digest_mismatch.json` | 9f5ff840810d7c59… |
| `unpinned_producer.json` | 52b55ae8db3d3ed3… |
| `stripped_signature.json` | 5d0766eca02ac186… |
| `anchor_invalid.json` | 4a9139c9e4b7bfe0… |

Run `sha256sum vectors/*` to check the full digests. The `.expected.json` files are the upstream
`normative` verdict blocks the reader must reproduce (spec §7).
