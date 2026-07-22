// Thin HTTP wrapper around an Elara node's public REST API.
// Read-only — no signing. The five tools in `tools.ts` compose this with
// the user's wallet identity for write paths.

export interface NodeClientConfig {
  /** e.g. "http://127.0.0.1:9473" */
  baseUrl: string;
  /** Per-request timeout. Public RPC nodes are usually <500ms; default 8s. */
  timeoutMs?: number;
}

export class NodeClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(cfg: NodeClientConfig) {
    this.baseUrl = cfg.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = cfg.timeoutMs ?? 8000;
  }

  // Proof-backed balance — the account state fields plus verification flags.
  // Reads the public `/proof/account/{id}` endpoint and projects its
  // `account_state`. (The raw `/account/{id}` route is loopback/data-plane
  // only and 404s off-host, so this server never calls it.)
  async accountDetail(identity: string): Promise<AccountDetail> {
    const proof = await this.accountProof(identity);
    return projectBalance(proof, identity);
  }

  async accountProof(identity: string): Promise<AccountProof> {
    return this.getJson<AccountProof>(`/proof/account/${encodeURIComponent(identity)}`);
  }

  async recordDetail(recordId: string): Promise<RecordDetail> {
    return this.getJson<RecordDetail>(`/record/${encodeURIComponent(recordId)}`);
  }

  async submitRecord(record: unknown): Promise<unknown> {
    return this.postJson("/records", record);
  }

  async submitWitness(witness: unknown): Promise<unknown> {
    return this.postJson("/witness", witness);
  }

  async status(): Promise<NodeStatus> {
    return this.getJson<NodeStatus>("/status");
  }

  private async getJson<T>(path: string): Promise<T> {
    const url = this.baseUrl + path;
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, { signal: ctl.signal });
      if (!res.ok) {
        throw new Error(`GET ${path} → HTTP ${res.status}: ${await safeText(res)}`);
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(t);
    }
  }

  private async postJson(path: string, body: unknown): Promise<unknown> {
    const url = this.baseUrl + path;
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      const txt = await safeText(res);
      if (!res.ok) throw new Error(`POST ${path} → HTTP ${res.status}: ${txt}`);
      try { return JSON.parse(txt); } catch { return txt; }
    } finally {
      clearTimeout(t);
    }
  }
}

async function safeText(res: Response): Promise<string> {
  try { return await res.text(); } catch { return ""; }
}

// Project a `/proof/account` envelope into the ergonomic balance view: the
// `account_state` fields overlaid with the verification flags. Handles all
// three server shapes — normal, `exists:false` (no account_state), and
// `pending_first_seal` (state present, not yet sealed). Never throws.
function projectBalance(proof: AccountProof, identity: string): AccountDetail {
  const state = proof.account_state ?? {};
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

// ─── Wire-format types (matches src/network/routes/explorer.rs JSON) ────────

// Account state fields, as carried in `/proof/account`'s `account_state`.
export interface AccountState {
  available: number;
  staked: number;
  total_received: number;
  total_sent: number;
  tx_count: number;
  last_active: number | null;
  inactive_days?: number;
  uptime_secs?: number;
  vested_locked?: number;
  witness_bonded?: number;
}

// Proof-backed balance: account state fields overlaid with verification
// flags. Sourced from the public `/proof/account` endpoint. For an unknown
// identity, `exists` is false and the state fields are absent.
export interface AccountDetail extends Partial<AccountState> {
  identity: string;
  exists: boolean;
  bound_to_seal: boolean;
  live_state_matches_sealed?: boolean;
  pending_first_seal?: boolean;
}

export interface AccountProof {
  identity: string;
  exists: boolean;
  root: string;
  state_hash?: string;
  account_state?: AccountState;
  siblings?: Array<{ hash: string; is_right: boolean }>;
  depth?: number;
  bound_to_seal?: boolean;
  live_state_matches_sealed?: boolean;
  pending_first_seal?: boolean;
  latest_sealed_account?: {
    epoch_number: number;
    zone: string;
    seal_id: string;
    account_smt_root: string;
    sealed_at: number;
    matches_proof_root: boolean;
  } | null;
}

export interface RecordDetail {
  // Shape varies — see compute_record_detail in src/network/routes/explorer.rs.
  // We surface the whole JSON to the caller verbatim.
  [k: string]: unknown;
}

export interface NodeStatus {
  ledger_supply?: number;
  zone?: string;
  [k: string]: unknown;
}
