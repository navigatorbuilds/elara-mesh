// High-level Agent API. Three-line integration:
//
//   const agent = await Agent.create({ nodeUrl, identity });
//   const balance = await agent.balance();
//   const proof = await agent.prove();
//
// This SDK is read-and-submit only: signing happens in the caller's wallet
// (browser, hardware, elara-cli, or `@elara/mcp-server`'s elara_sign tool).
// Records arrive at `agent.record()` already carrying a Dilithium3 signature,
// matching the boundary the public REST API enforces.

import { NodeClient, type NodeClientConfig } from "./client.js";
import type {
  AccountDetail,
  AccountProof,
  SignedRecord,
  SubmitResult,
} from "./types.js";

export interface AgentConfig extends NodeClientConfig {
  /**
   * 32-byte SHA3-256 identity hash, hex-encoded (64 chars).
   * Optional — pass per-call instead if you don't have a default.
   */
  identity?: string;
}

export class Agent {
  /** The node this agent talks to. */
  readonly client: NodeClient;
  /** Default identity used when methods are called without an override. */
  readonly identity?: string;

  private constructor(client: NodeClient, identity?: string) {
    this.client = client;
    this.identity = identity;
  }

  /**
   * Construct an Agent and verify the configured node is reachable.
   * Throws `ElaraHttpError` if the node returns non-2xx for `/status`.
   */
  static async create(cfg: AgentConfig): Promise<Agent> {
    // Validate config (identity hex shape) before any I/O so a bad config
    // fails fast rather than spending an HTTP timeout on an unreachable node.
    const id = normalizeIdentity(cfg.identity);
    const client = new NodeClient(cfg);
    // Liveness check — fails fast on misconfigured node URL.
    await client.status();
    return new Agent(client, id);
  }

  /**
   * Construct an Agent without performing the liveness check.
   * Useful in tests or when you want lazy connection.
   */
  static unchecked(cfg: AgentConfig): Agent {
    return new Agent(new NodeClient(cfg), normalizeIdentity(cfg.identity));
  }

  /**
   * Proof-backed balance for `id` (or this agent's default identity): the
   * account state fields (`available`, `staked`, …) overlaid with `exists`
   * and `bound_to_seal`, so the balance is self-describing as verified
   * against the latest signed seal. `exists` is false for an unknown
   * identity. Use `prove()` for the full Merkle proof.
   */
  async balance(id?: string): Promise<AccountDetail> {
    return this.client.accountDetail(this.requireId(id));
  }

  /** Merkle proof of `id`'s account state against the latest signed seal. */
  async prove(id?: string): Promise<AccountProof> {
    return this.client.accountProof(this.requireId(id));
  }

  /**
   * Submit a fully-signed record. The `signature` and `public_key` fields
   * must already be set — this SDK does not hold key material.
   */
  async record(record: SignedRecord): Promise<SubmitResult> {
    if (!record.signature || !record.public_key) {
      throw new Error(
        "record must carry `signature` and `public_key` — sign with your " +
          "wallet (or @elara/mcp-server's elara_sign tool) before calling " +
          "agent.record().",
      );
    }
    return this.client.submitRecord(record);
  }

  private requireId(id?: string): string {
    const out = id ?? this.identity;
    if (!out) {
      throw new Error(
        "identity is required — pass one to the method, or supply " +
          "`identity` to Agent.create().",
      );
    }
    return out;
  }
}

function normalizeIdentity(id: string | undefined): string | undefined {
  if (id === undefined) return undefined;
  const trimmed = id.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error(
      `identity must be 64 hex chars (32-byte SHA3-256), got ${id.length} chars`,
    );
  }
  return trimmed;
}
