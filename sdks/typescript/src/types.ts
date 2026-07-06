// Wire-format types — mirror the JSON shapes returned by the public REST
// API (see src/network/routes/explorer.rs and docs/openapi.json).

/** Account state fields, as carried in `/proof/account`'s `account_state`. */
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

/**
 * Proof-backed balance: the account state fields overlaid with verification
 * flags. Returned by `agent.balance()`. Sourced from the public
 * `/proof/account` endpoint (the raw `/account` route is loopback-only and
 * 404s off-host). For an unknown identity, `exists` is false and the state
 * fields are absent.
 */
export interface AccountDetail extends Partial<AccountState> {
  identity: string;
  exists: boolean;
  /** `true` when the balance is bound to the latest signed epoch seal. */
  bound_to_seal: boolean;
  /** `true` when live ledger state matches the sealed state (else the proof lags one+ epochs). */
  live_state_matches_sealed?: boolean;
  /** `true` for a funded account whose first leaf has not been sealed yet. */
  pending_first_seal?: boolean;
}

export interface AccountProof {
  identity: string;
  exists: boolean;
  root: string;
  state_hash?: string;
  /** Live account state (display only — not signed; verify via root/siblings). */
  account_state?: AccountState;
  siblings?: ProofSibling[];
  depth?: number;
  /**
   * `true` when the proof root matches the account-SMT root signed in the
   * latest epoch seal. `false` means the proof reflects post-seal state — a
   * light client should wait for the next seal for verifiable finality.
   */
  bound_to_seal?: boolean;
  live_state_matches_sealed?: boolean;
  pending_first_seal?: boolean;
  latest_sealed_account?: SealedAccountBinding | null;
}

export interface ProofSibling {
  hash: string;
  is_right: boolean;
}

export interface SealedAccountBinding {
  epoch_number: number;
  zone: string;
  seal_id: string;
  account_smt_root: string;
  sealed_at: number;
  matches_proof_root: boolean;
}

/** Minimal record shape — full schema in src/record/mod.rs / openapi.json. */
export interface SignedRecord {
  id: string;
  identity: string;
  signature: string;
  public_key: string;
  payload: unknown;
  timestamp: number;
  [k: string]: unknown;
}

export interface SubmitResult {
  accepted?: boolean;
  id?: string;
  [k: string]: unknown;
}
