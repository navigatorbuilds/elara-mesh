### 6.3 AI Attribution in Detail

The rise of AI-generated content has created an attribution crisis. Current systems cannot distinguish between:
- Fully human-created work
- AI-assisted work (human-directed, AI-generated)
- Fully AI-generated work
- AI-to-AI generated work (one model's output fed to another)

The Elara Protocol makes this explicit:

```
CollaborationRecord {
    work_hash:       content hash of the final output
    participants:    [
        { identity: human_key,  role: "prompter",  contribution: "direction, editing" },
        { identity: ai_key,    role: "generator",  contribution: "initial draft",
          model: "claude-opus-4-8", version: "2026-06" }
    ]
    chain:           optional, references to intermediate outputs
    signed_by:       all participants
}
```

This record is immutable on the DAG. When a dispute arises about who created what, the cryptographic evidence is already in place.

