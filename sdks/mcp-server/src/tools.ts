// Five MCP tool definitions:
//   elara_balance, elara_prove, elara_record, elara_witness, elara_sign.
//
// Read tools (balance, prove) hit the public REST API directly.
// Write tools (record, witness) follow a build-and-submit pattern: the
// caller supplies a Dilithium3 signature produced from the canonical
// to-be-signed payload this server returns. This keeps key material out
// of the MCP server process — which is the right default for "AI agent
// has cryptographic identity" since the signing wallet is owned by the
// human or the agent's secure keystore, not the tool runner.
//
// The `elara_sign` tool returns the canonical to-be-signed bytes for a
// given intent (transfer/stake/witness) so the wallet can sign them
// without needing to know the protocol's serialization rules.

import { NodeClient } from "./node-client.js";

export interface ToolContext {
  client: NodeClient;
  /** Default identity hex used when the caller omits it. Read from MCP config. */
  defaultIdentity?: string;
}

export const TOOL_DEFS = [
  {
    name: "elara_balance",
    description:
      "Get the proof-backed balance for an identity on the Elara network. Returns " +
      "the account state (available, staked, total_received, total_sent, tx_count, " +
      "last_active, …) overlaid with verification flags (exists, bound_to_seal), " +
      "read from the public GET /proof/account/{identity} endpoint. Read-only — no " +
      "signature required.",
    inputSchema: {
      type: "object",
      properties: {
        identity: {
          type: "string",
          description:
            "32-byte SHA3-256 identity hash, hex-encoded (64 hex chars). " +
            "Optional if a default_identity is configured in the MCP server.",
        },
      },
    },
  },
  {
    name: "elara_prove",
    description:
      "Get a Merkle proof of an identity's account state, verifiable against the " +
      "latest signed epoch seal. Returns root + siblings + state_hash + " +
      "bound_to_seal flag. Light clients use this to verify balances without " +
      "downloading the full ledger. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        identity: {
          type: "string",
          description: "32-byte SHA3-256 identity hash, hex-encoded.",
        },
      },
      required: ["identity"],
    },
  },
  {
    name: "elara_record",
    description:
      "Submit a signed record to the Elara network. The record JSON must already " +
      "carry a valid Dilithium3 signature in its `signature` field — produced by " +
      "the agent's wallet from the canonical bytes returned by elara_sign. The " +
      "server validates and gossips it to the rest of the mesh.",
    inputSchema: {
      type: "object",
      properties: {
        record: {
          type: "object",
          description:
            "Fully-formed record JSON (id, identity, payload, timestamp, " +
            "signature, public_key). See protocol §3.2 / docs/openapi.json.",
        },
      },
      required: ["record"],
    },
  },
  {
    name: "elara_witness",
    description:
      "Cast a witness attestation on a record. Returns the canonical to-be-signed " +
      "bytes if no signature is supplied (build mode), or submits a signed " +
      "witness attestation to POST /witness if `signature` and `public_key` are " +
      "provided (submit mode). This two-phase shape lets the agent's wallet sign " +
      "without exposing keys to the MCP server.",
    inputSchema: {
      type: "object",
      properties: {
        record_id: {
          type: "string",
          description: "Hex-encoded record id to witness.",
        },
        signature: {
          type: "string",
          description: "Optional Dilithium3 signature hex. Omit to build only.",
        },
        public_key: {
          type: "string",
          description: "Witness public key hex. Required when signature is set.",
        },
      },
      required: ["record_id"],
    },
  },
  {
    name: "elara_sign",
    description:
      "Build the canonical to-be-signed bytes for a protocol intent (transfer / " +
      "stake / unstake / burn / witness) without performing the signature. The " +
      "agent's wallet signs the returned hex bytes with its Dilithium3 key, then " +
      "calls elara_record / elara_witness with the resulting signature. Keeps " +
      "private key material out of this process.",
    inputSchema: {
      type: "object",
      properties: {
        intent: {
          type: "string",
          enum: ["transfer", "stake", "unstake", "burn", "witness"],
          description: "Which protocol op the agent wants to authorize.",
        },
        from: { type: "string", description: "Source identity hex." },
        to: { type: "string", description: "Recipient identity hex (transfer only)." },
        amount: {
          type: "number",
          description: "Amount in beat base units (1 beat = 1_000_000_000 units).",
        },
        record_id: {
          type: "string",
          description: "Target record id (witness / unstake only).",
        },
        memo: { type: "string", description: "Optional UTF-8 memo." },
      },
      required: ["intent"],
    },
  },
] as const;

// ─── Handlers ────────────────────────────────────────────────────────────────

export async function handleBalance(
  ctx: ToolContext,
  args: { identity?: string },
): Promise<unknown> {
  const id = args.identity ?? ctx.defaultIdentity;
  if (!id) throw new Error("identity is required (or set default_identity in config)");
  return ctx.client.accountDetail(id);
}

export async function handleProve(
  ctx: ToolContext,
  args: { identity: string },
): Promise<unknown> {
  if (!args.identity) throw new Error("identity is required");
  return ctx.client.accountProof(args.identity);
}

export async function handleRecord(
  ctx: ToolContext,
  args: { record: unknown },
): Promise<unknown> {
  if (!args.record) throw new Error("record is required");
  return ctx.client.submitRecord(args.record);
}

export async function handleWitness(
  ctx: ToolContext,
  args: { record_id: string; signature?: string; public_key?: string },
): Promise<unknown> {
  if (!args.record_id) throw new Error("record_id is required");
  if (!args.signature) {
    return {
      mode: "build",
      to_sign_hex: canonicalWitnessBytes(args.record_id),
      hint: "Sign the to_sign_hex bytes with your Dilithium3 key, then call " +
        "elara_witness again with `signature` and `public_key` set.",
    };
  }
  if (!args.public_key) throw new Error("public_key is required when signature is set");
  return ctx.client.submitWitness({
    record_id: args.record_id,
    signature: args.signature,
    public_key: args.public_key,
  });
}

export async function handleSign(
  ctx: ToolContext,
  args: {
    intent: "transfer" | "stake" | "unstake" | "burn" | "witness";
    from?: string;
    to?: string;
    amount?: number;
    record_id?: string;
    memo?: string;
  },
): Promise<unknown> {
  void ctx;
  const from = args.from;
  const memo = args.memo ?? "";
  switch (args.intent) {
    case "transfer": {
      need(args.to, "to");
      need(args.amount, "amount");
      need(from, "from");
      return {
        intent: "transfer",
        canonical: { from, to: args.to, amount: args.amount, memo },
        to_sign_hex: canonicalIntentBytes("transfer", { from, to: args.to, amount: args.amount, memo }),
      };
    }
    case "stake":
    case "burn": {
      need(args.amount, "amount");
      need(from, "from");
      return {
        intent: args.intent,
        canonical: { from, amount: args.amount, memo },
        to_sign_hex: canonicalIntentBytes(args.intent, { from, amount: args.amount, memo }),
      };
    }
    case "unstake": {
      need(args.record_id, "record_id");
      need(from, "from");
      return {
        intent: "unstake",
        canonical: { from, record_id: args.record_id },
        to_sign_hex: canonicalIntentBytes("unstake", { from, record_id: args.record_id }),
      };
    }
    case "witness": {
      need(args.record_id, "record_id");
      return {
        intent: "witness",
        canonical: { record_id: args.record_id },
        to_sign_hex: canonicalWitnessBytes(args.record_id),
      };
    }
    default:
      throw new Error(`unknown intent: ${args.intent}`);
  }
}

function need<T>(v: T | undefined | null, name: string): asserts v is T {
  if (v === undefined || v === null || v === "") {
    throw new Error(`${name} is required for this intent`);
  }
}

// Canonical pre-image: a stable JSON encoding of the intent. The wallet
// hashes this with SHA3-256 and signs the digest with Dilithium3, matching
// the witness/record signing rule in src/accounting/validate.rs and
// src/witness/manager.rs. We hand back the raw JSON-as-hex so the wallet
// (which already knows the hash-then-sign convention) does the rest.
function canonicalIntentBytes(intent: string, body: Record<string, unknown>): string {
  const json = stableStringify({ intent, ...body });
  return Buffer.from(json, "utf8").toString("hex");
}

function canonicalWitnessBytes(recordId: string): string {
  return Buffer.from(`witness:${recordId}`, "utf8").toString("hex");
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const keys = Object.keys(v as Record<string, unknown>).sort();
  const parts = keys.map(
    (k) => JSON.stringify(k) + ":" + stableStringify((v as Record<string, unknown>)[k]),
  );
  return "{" + parts.join(",") + "}";
}
