# Give YOUR agent a receipted mandate — the issuer quickstart

Fifteen minutes, one machine, no permission from anyone. At the end you have:
**your own chain**, **your own agent identity**, a **signed, scoped, revocable
mandate** from you to it, **receipted acts** under that mandate, a working
**kill switch**, and offline verification of all of it — with post-quantum
signatures throughout. Nothing here talks to Elara's own network: your chain
is yours.

Every command and output below was executed as written on 2026-08-19
(single Linux box; the flow needs ~2 GB RAM and one free set of ports).

## 0. Build once

```bash
git clone https://github.com/navigatorbuilds/elara-mesh
cd elara-mesh
cargo build --release --features node   # ~30-60s warm, a few minutes cold
```

Binaries used below: `target/release/elara-keygen`, `elara-node`, `elara-cli`.

## 1. Two identities — yours and the agent's

Separate keys are the whole point: the agent can act, only you can authorize.

```bash
W=$HOME/my-agent-chain && mkdir -p $W
OP=$(target/release/elara-keygen gen --output $W/operator.json --profile B --entity human --quiet)
AG=$(target/release/elara-keygen gen --output $W/agent.json    --profile B --entity ai    --quiet)
echo "you:   $OP"
echo "agent: $AG"
```

(`--entity ai` is a first-class identity type. `--profile A` adds SPHINCS+
dual-signing if you want both PQ families; B is ML-DSA-65 (FIPS 204, "Dilithium3")-only and faster.)
Both files are written mode 0600 and contain secret keys — back them up.

## 2. Boot your chain

One process. You are the genesis authority of this chain; it self-funds and
starts sealing epochs on its own.

```bash
ELARA_DATA_DIR=$W/node-data \
ELARA_IDENTITY=$W/operator.json \
ELARA_IDENTITY_PASSPHRASE='pick-a-real-passphrase' \
ELARA_LISTEN=127.0.0.1:19474 \
ELARA_PQ_LISTEN=127.0.0.1:19574 \
ELARA_ADMIN_LISTEN=127.0.0.1:19475 \
ELARA_DATA_PLANE_LISTEN=127.0.0.1:19472 \
ELARA_GENESIS=$OP \
ELARA_GENESIS_VALIDATORS=$OP:1000000000000000 \
ELARA_NODE_TYPE=genesis \
ELARA_NETWORK_ID=my-agent-chain \
ELARA_ALLOW_PUBLIC_HTTPS=false \
target/release/elara-node --config /dev/null --data-dir $W/node-data \
  > $W/node.log 2>&1 &

sleep 15 && curl -s http://127.0.0.1:19474/status | head -c 200
```

Traps we hit so you don't (each of these produced a real failure first):
- **All four listeners** must be set — miss `ELARA_DATA_PLANE_LISTEN` and the
  node dies at boot with `Address already in use` if anything else runs on
  the default ports.
- `ELARA_GENESIS_VALIDATORS` is `<identity_hash>:<stake_micros>` — a bare
  hash is dropped as malformed (the log tells you, but only the log).
- Pick your `ELARA_NETWORK_ID` now. It is baked into every record your chain
  emits (wire v6 binds it into the signed preimage) and the chain **rejects
  records bound to any other network** — see the trap in step 3.

## 3. Issue the mandate

You (the principal) grant the agent's key bounded authority: 24 hours,
wildcard ops, revocable.

```bash
export ELARA_NETWORK_ID=my-agent-chain   # ← for every elara-cli call below
MID=$(target/release/elara-cli --node http://127.0.0.1:19474 mandate-issue \
  --identity $W/operator.json --agent $AG --hours 24 --ops '*' \
  | grep -oP 'mandate_id=\K[0-9a-f]+')
echo "mandate: $MID"
```

Real output shape:
```
accepted: 01a01ae7-8cc5-7441-b19e-022c3ad507a2
mandate-issue: mandate_id=cbead771… principal=f46a0cc9… agent=5344a7be… network=my-agent-chain window_hours=24
```

**The trap:** forget the `ELARA_NETWORK_ID` export and the CLI stamps its
default network into the record — your chain answers `network_mismatch` and
refuses it. That refusal is a feature (it is what keeps two chains' records
from ever mixing), but the error message is all you get.

## 4. The agent acts — every act a receipt

Signed with the **agent's** key, carrying the mandate reference:

```bash
H=$(printf 'my agent did a thing' | python3 -c 'import sys,hashlib;print(hashlib.sha3_256(sys.stdin.buffer.read()).hexdigest())')
RID=$(target/release/elara-cli --node http://127.0.0.1:19474 agent-emit \
  --identity $W/agent.json --tool demo-tool --action demo-action \
  --args-hash $H --agent-id my-first-agent --mandate-ref $MID \
  | grep -oP '^accepted: \K[0-9a-f-]+')
echo "act: $RID"
```

## 5. Anyone asks: "was that authorized?"

```bash
curl -s http://127.0.0.1:19474/mandate/status/$RID | python3 -m json.tool
```

Real answer (excerpt):
```json
{
  "authorized": true,
  "flag": "valid",
  "chain_depth": 1,
  "lineage": [{ "hop_index": 0,
                "agent_identity_hash":     "5344a7be…",
                "principal_identity_hash": "f46a0cc9…",
                "mandate_id":              "cbead771…" }]
}
```

The lineage is the verified delegation chain — who authorized whom, leaf to
root, recomputed from signatures, not from an access-control table.

## 6. The kill switch

```bash
target/release/elara-cli --node http://127.0.0.1:19474 mandate-revoke \
  --identity $W/operator.json --mandate-id $MID
```

Only the original principal's revocation counts, and it is terminal (re-
authorization is a new mandate, never an un-revoke). Now let the agent try
again with the dead mandate (repeat step 4 with a new digest) and ask again:

```
post-revocation act:  { "authorized": false, "flag": "post_revocation" }
the act from step 4:  { "authorized": true,  "flag": "valid" }
```

That second line is the accountability property in one glance: **revocation
kills the future, never the past.** What the agent was authorized to do
remains provably authorized forever; what it does after stands flagged
forever.

## 7. Verify offline — trust no node, including yours

```bash
curl -s http://127.0.0.1:19474/record/$RID/wire -o $W/act.wire
python3 examples/verify/decode_record.py $W/act.wire
```

Real output (excerpt):
```
version:    6   network_id: 'my-agent-chain'
identity:   5344a7be…   ← the AGENT's key hash, recomputed from raw bytes
record_hash: df75ca51…
```

The pure-stdlib Python reimplements the wire format and the signing preimage
from the spec — no Rust, no node. For full signature verification and the
graded verdicts (VERIFIED / PARTIAL / FAILED with the honest UNPROVEN
states), use the published crate: `cargo install elara-verify` — or read
`examples/verify/verify.sh` for the complete offline evidence walk.

Three committed mandate-bundle vectors — harvested from exactly this flow on
a real chain — live at `examples/verify/mandate-bundle-{valid,post-revocation,
agent-mismatch}.json`: feed any of them to
`elara_verify::mandate_bundle::evaluate_mandate_bundle` (crate) and you get
the three canonical verdicts offline, including the anti-libel agent-mismatch
case where the principal is exonerated because someone ELSE's key claimed
their mandate.

## What you now have

A sovereign audit trail for your agent: post-quantum signed, third-party
checkable, with authority that is granted, bounded, queryable over time, and
revocable in one command. Multi-machine setups, witness committees, and
cross-zone scaling are the same records on more nodes — see
`docs/AGENT-DELEGATION.md` and `docs/PROTOCOL-SPEC.md` when you outgrow one
box.

*This quickstart is executed end-to-end before every revision; if a step's
output does not match what you see, that is a bug — file it.*
