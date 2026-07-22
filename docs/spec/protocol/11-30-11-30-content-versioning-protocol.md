### 11.30 Content Versioning Protocol

**The gap:** A document goes through 20 drafts. A software project has thousands of commits. An AI model has hundreds of training iterations. The paper describes validating individual artifacts but not the relationship between versions of the same work.

**Solution: DAM-Native Version Chains**

The protocol supports explicit version linking through a **VersionRecord**:

```
VersionRecord {
    content_hash:     hash of current version
    previous_version: record_id of the prior version (or null for v1)
    version_number:   sequential counter
    change_summary:   optional metadata describing what changed
    creator:          must match previous version's creator (or authorized collaborator)
    signature:        creator's signature
}
```

**Properties:**

- **Chain integrity:** Each version references the previous version's record ID. The full history is traversable from any version back to v1. Tampering with any version breaks the chain.

- **Fork tracking:** If two people create different v3s from the same v2 (a fork), both are preserved on the DAM as branches — exactly like a git repository, but cryptographically signed and globally attested.

- **Diff validation:** For text-based content, the protocol supports optional **diff records** — validated diffs that prove the exact changes between versions. A verifier can reconstruct any version from v1 + the chain of diffs, confirming nothing was altered retroactively.

- **Semantic versioning:** The metadata field supports semver (1.0.0, 1.1.0, 2.0.0) for software, draft numbering for documents, or any user-defined scheme.

**Integration with incremental validation (Section 11.7):**

Version chains ARE the incremental validation recommended for originality protection. A poet who validates each draft creates a version chain automatically. The chain proves creative process — something a plagiarist cannot replicate.

