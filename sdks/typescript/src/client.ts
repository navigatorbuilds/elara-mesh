// Low-level HTTP client. Most callers want the higher-level `Agent` API in
// `agent.ts` — this is exposed for advanced users who need raw access.

import type {
  AccountDetail,
  AccountProof,
  AccountState,
  SignedRecord,
  SubmitResult,
} from "./types.js";

export interface NodeClientConfig {
  /** Public REST endpoint, e.g. `http://127.0.0.1:9473`. */
  nodeUrl: string;
  /** Per-request timeout. Default 8000ms. */
  timeoutMs?: number;
}

export class NodeClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(cfg: NodeClientConfig) {
    if (!cfg.nodeUrl) throw new Error("nodeUrl is required");
    this.baseUrl = cfg.nodeUrl.replace(/\/+$/, "");
    this.timeoutMs = cfg.timeoutMs ?? 8000;
  }

  get url(): string {
    return this.baseUrl;
  }

  /**
   * Proof-backed balance — the account state fields plus the verification
   * flags. Reads the public `/proof/account/{id}` endpoint and projects its
   * `account_state`. (The raw `/account/{id}` route is loopback/data-plane
   * only and 404s off-host, so the SDK never calls it.)
   */
  async accountDetail(identity: string): Promise<AccountDetail> {
    const proof = await this.accountProof(identity);
    return projectBalance(proof, identity);
  }

  accountProof(identity: string): Promise<AccountProof> {
    return this.getJson<AccountProof>(
      `/proof/account/${encodeURIComponent(identity)}`,
    );
  }

  submitRecord(record: SignedRecord): Promise<SubmitResult> {
    return this.postJson<SubmitResult>("/records", record);
  }

  status(): Promise<Record<string, unknown>> {
    return this.getJson<Record<string, unknown>>("/status");
  }

  private async getJson<T>(path: string): Promise<T> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.baseUrl + path, { signal: ctl.signal });
      if (!res.ok) {
        throw new ElaraHttpError(`GET ${path}`, res.status, await safeText(res));
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(t);
    }
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.baseUrl + path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      const txt = await safeText(res);
      if (!res.ok) throw new ElaraHttpError(`POST ${path}`, res.status, txt);
      try {
        return JSON.parse(txt) as T;
      } catch {
        return txt as unknown as T;
      }
    } finally {
      clearTimeout(t);
    }
  }
}

export class ElaraHttpError extends Error {
  constructor(
    public readonly request: string,
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`${request} → HTTP ${status}: ${body}`);
    this.name = "ElaraHttpError";
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

/**
 * Project a `/proof/account` envelope into the ergonomic `AccountDetail`
 * balance view: the `account_state` fields overlaid with the verification
 * flags. Handles all three server response shapes — normal, `exists:false`
 * (no `account_state`), and `pending_first_seal` (state present, not yet
 * sealed). Never throws on a sparse envelope.
 */
function projectBalance(proof: AccountProof, identity: string): AccountDetail {
  const state = (proof.account_state ?? {}) as Partial<AccountState>;
  const out: AccountDetail = {
    ...state,
    identity: proof.identity ?? identity,
    exists: proof.exists ?? false,
    bound_to_seal: proof.bound_to_seal ?? false,
  };
  if (proof.live_state_matches_sealed !== undefined) {
    out.live_state_matches_sealed = proof.live_state_matches_sealed;
  }
  if (proof.pending_first_seal) out.pending_first_seal = true;
  return out;
}
