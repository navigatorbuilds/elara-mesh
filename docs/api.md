# Elara Node API Reference

Base URL: `http://<node-host>:9473`

All responses are JSON unless otherwise noted. CORS is enabled for all origins.

> **Two listeners.** By default a node serves only a read-only **public surface** on
> the `--listen` port — liveness/meta (`/ping` `/status` `/health` `/alive` `/metrics`
> `/version`), the light-client / account reads (`/proof/account/{id}`,
> `/headers/from/{epoch}`, `/snapshot/state-delta`, `/seal/progress/{id}`,
> `/records/by-hash/{hash}`, `/mandate`, `/governance/upgrade_outcomes`), and the
> read-only block explorer (`/explorer` plus `/epochs` `/consensus/status` `/dag/stats`
> `/dag/tips` `/transactions/recent` `/record/{id}` `/account/{identity}`), plus the
> `/pq-ws` post-quantum WebSocket (see [WebSocket](#websocket-pq-ws) below). Every
> other endpoint in this reference is on the **data plane**, bound to
> `127.0.0.1:9472` (loopback) by default. Run with `ELARA_DATA_PLANE_LISTEN=`
> (empty) to serve everything on the single `:9473` port, or front the data-plane
> port with a reverse proxy. See the README ("Two listeners") for the full model.

---

## Health & Status

### `GET /ping`

Simple liveness check.

```bash
curl http://localhost:9473/ping
```

```json
{"pong": true}
```

### `GET /health`

Node health status. Use this for monitoring and load balancer health checks.

```bash
curl http://localhost:9473/health
```

```json
{
  "status": "healthy",
  "synced": true,
  "peers_connected": 2,
  "dag_size": 1547,
  "uptime_secs": 3600,
  "version": "0.2.0"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"healthy"` (peers connected) or `"degraded"` (no peers) |
| `synced` | bool | Whether node has data (peers > 0 or DAG non-empty) |
| `peers_connected` | int | Active peer connections |
| `dag_size` | int | Total records in the DAG |
| `uptime_secs` | int | Node uptime in seconds |
| `version` | string | Software version |

### `GET /status`

Full node status with DAG, ledger, and consensus details.

```bash
curl http://localhost:9473/status
```

```json
{
  "identity_hash": "a1b2c3d4...",
  "node_type": "authority",
  "listen_addr": "0.0.0.0:9473",
  "dag_size": 1547,
  "dag_tips": 3,
  "dag_roots": 1,
  "dag_edges": 2891,
  "ledger_supply": 10000000000000000000,
  "ledger_staked": 250000000000,
  "ledger_accounts": 42,
  "peers_connected": 2,
  "peers_total": 5,
  "finalized_count": 1200,
  "consensus_attestations": 4500,
  "consensus_settled": 1200,
  "uptime_secs": 3600,
  "version": "0.2.0"
}
```

### `GET /metrics`

Prometheus-compatible metrics endpoint.

```bash
curl http://localhost:9473/metrics
```

Returns `text/plain; version=0.0.4` with standard Prometheus gauge/counter format.

---

## Network

### `GET /network`

Chain metadata and network statistics. Use this for explorer dashboards.

> **Units:** raw amount fields are in base units — 1 beat = 1,000,000,000
> (10⁹) base units. The matching `*_beat` fields carry the same value in whole
> beats. Maximum supply is 10,000,000,000 beats (`max: 10000000000000000000`).

```bash
curl http://localhost:9473/network
```

```json
{
  "ticker": "BEAT",
  "protocol": "Elara DAM",
  "consensus_algorithm": "AWC",
  "crypto": "Dilithium3",
  "version": "0.2.0",
  "uptime_seconds": 46800.0,
  "supply": {
    "max": 10000000000000000000,
    "max_beat": 10000000000.0,
    "total": 10000000000000000000,
    "total_beat": 10000000000.0,
    "circulating": 8997000000000000000,
    "circulating_beat": 8997000000.0,
    "staked": 3000000000000000,
    "staked_beat": 3000000.0,
    "conservation_pool": 1000000000000,
    "accounts": 42,
    "active_stakes": 8
  },
  "dag": {
    "size": 1547,
    "tips": 15,
    "edges": 4821,
    "records_processed": 1547
  },
  "topology": {
    "peers_connected": 2,
    "peers_total": 5,
    "peers_by_type": { "witness": 3, "light": 2 },
    "avg_peer_reputation": 0.9812,
    "dht_size": 5,
    "dht_occupied_buckets": 4,
    "dht_total_buckets": 256,
    "dht_bucket_coverage_pct": 1.5625,
    "dht_bucket_distribution": [ { "bucket": 0, "peers": 2 } ]
  },
  "consensus": {
    "attestations": 877,
    "settled": 0,
    "unsettled": 877,
    "finalized": 14570,
    "witness_profiles": 2,
    "total_zone_stake": 3000000000000000,
    "total_zone_stake_beat": "3000000.0",
    "effective_hops": 2
  },
  "gossip": { "push_total": 1278, "pull_total": 34 },
  "epochs": [
    { "epoch_number": 2946, "zone": "0" },
    { "epoch_number": 1260, "zone": "1" }
  ]
}
```

### `GET /peers`

List all known peers.

```bash
curl http://localhost:9473/peers
```

```json
{
  "peers": [
    {
      "identity_hash": "a1b2c3d4...",
      "host": "10.0.0.2",
      "port": 9473,
      "node_type": "witness",
      "tls": true,
      "last_seen": 1710000000.0
    }
  ]
}
```

### `GET /dht/find_node`

Find closest peers to a target in the DHT.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | self | Target identity hash (hex) |
| `count` | int | 8 | Max peers to return (max 20) |

```bash
curl "http://localhost:9473/dht/find_node?target=a1b2c3d4&count=5"
```

---

## Accounts

### `GET /validate_address/{address}`

Validate an address format and check existence.

```bash
curl http://localhost:9473/validate_address/a1b2c3d4e5f6...
```

```json
{
  "address": "a1b2c3d4e5f6...",
  "valid_format": true,
  "exists": true,
  "format": "sha3-256-hex"
}
```

Address format: 64 lowercase hexadecimal characters (SHA3-256 hash of public key).

---

## Internal beat accounting

Balances, stakes, transfers, and transaction history are **protocol plumbing,
not a documented public API.** Beats move internally for staking, witness
rewards, and resource accounting — the node exposes these primitives in source,
but they are not a payment or trading surface. Elara is a post-quantum
validation mesh, not a cryptocurrency: there is no token sale, no listing, and
no transfer product.

---

## Records

### `POST /records`

Submit a signed record (wire-encoded binary).

```bash
curl -X POST http://localhost:9473/records \
  -H "Content-Type: application/octet-stream" \
  --data-binary @signed_record.bin
```

```json
{"accepted": true, "id": "01234567-..."}
```

The record must be signed with Dilithium3. The node verifies the signature before accepting.

### `GET /records`

Query records by timestamp.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | float | 0.0 | Unix timestamp to query from |
| `limit` | int | 100 | Max records (max 1000) |

Returns hex-encoded wire bytes.

### `GET /record/{id}`

Full record detail with metadata, attestations, and finalization status.

```bash
curl http://localhost:9473/record/01234567-89ab-cdef-...
```

```json
{
  "id": "01234567-89ab-cdef-...",
  "timestamp": 1710000000.0,
  "creator": "a1b2c3d4...",
  "parents": ["parent-id-1"],
  "classification": "Public",
  "has_signature": true,
  "has_sphincs_signature": false,
  "metadata_keys": ["beat_op", "beat_amount", "beat_to"],
  "beat_op": {
    "op": "transfer",
    "amount": 5000000,
    "to": "d4e5f6a7...",
    "memo": "payment"
  },
  "attestations": [
    {
      "witness_hash": "w1t2n3e4...",
      "timestamp": 1710000001.0,
      "has_pubkey": true
    }
  ],
  "attestation_count": 3,
  "finalized": true
}
```

---

## Attestations

### `GET /attestations`

Query attestations for a record or since a timestamp.

| Parameter | Type | Description |
|-----------|------|-------------|
| `record_id` | string | Attestations for a specific record |
| `since` | float | All attestations since timestamp |
| `limit` | int | Max results (max 1000, default 100) |

```bash
# For a specific record
curl "http://localhost:9473/attestations?record_id=01234567-..."

# Since a timestamp (for gossip pull)
curl "http://localhost:9473/attestations?since=1710000000.0&limit=100"
```

### `POST /attestations`

Submit a witness attestation.

```bash
curl -X POST http://localhost:9473/attestations \
  -H "Content-Type: application/json" \
  -d '{
    "record_id": "01234567-...",
    "witness_hash": "w1t2n3e4...",
    "signature": "deadbeef...",
    "timestamp": 1710000001.0,
    "witness_public_key": "abcdef01..."
  }'
```

```json
{"accepted": true, "finalized": false}
```

If `witness_public_key` is provided, the node verifies:
1. `SHA3-256(public_key) == witness_hash`
2. `Dilithium3_verify(record_wire_bytes, signature, public_key)`

### `POST /witness`

Request the node to counter-sign (witness) a record. Send the record as wire-encoded binary.

```bash
curl -X POST http://localhost:9473/witness \
  -H "Content-Type: application/octet-stream" \
  --data-binary @record.bin
```

Returns: `witness_identity_hash (64 bytes) + dilithium3_signature`

---

## Sync

### `GET /merkle_root`

Merkle root of all record hashes. Used for sync comparison.

```bash
curl http://localhost:9473/merkle_root
```

```json
{"root": "abcdef01..."}
```

### `POST /delta_sync`

Send a Bloom filter, receive records the peer is missing.

```bash
curl -X POST http://localhost:9473/delta_sync \
  -H "Content-Type: application/octet-stream" \
  --data-binary @bloom.bin
```

Returns JSON array of hex-encoded wire bytes.

---

## Rate Limits

| Type | Default | Description |
|------|---------|-------------|
| Write (POST) | 120/min | Per IP, 60-second window |
| Read (GET) | 600/min | Per IP, 60-second window |

Exceeded limits return `429 Too Many Requests`.

---

## Error Responses

| Status | Meaning |
|--------|---------|
| 400 | Bad request (invalid wire format, bad signature) |
| 404 | Record not found |
| 409 | Duplicate record |
| 422 | Operation validation failed |
| 429 | Rate limited |
| 500 | Internal server error |

Error body is plain text describing the issue.

---

## Record Processing

### `POST /validate`

Validate a record without inserting it into the DAG. Useful for pre-flight checks.

```bash
curl -X POST http://localhost:9473/validate \
  -H "Content-Type: application/octet-stream" \
  --data-binary @signed_record.bin
```

```json
{
  "valid": true,
  "record_id": "01234567-...",
  "creator_hash": "a1b2c3d4...",
  "classification": "Public",
  "timestamp": 1710000000.0,
  "checks": [
    {"check": "wire_format", "passed": true},
    {"check": "bounds", "passed": true, "metadata_entries": 4, "parents": 1},
    {"check": "timestamp", "passed": true, "record_ts": 1710000000.0, "drift_secs": 0.5},
    {"check": "signature", "passed": true},
    {"check": "token_op", "passed": true, "op": {"type": "transfer", "amount": 5000000}},
    {"check": "parents", "passed": true, "total": 1, "found_locally": 1},
    {"check": "duplicate", "passed": true, "is_duplicate": false}
  ]
}
```

### `GET /records/search`

Search records by various criteria.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | | Full-text search |
| `creator` | string | | Creator identity hash |
| `key` | string | | Metadata key |
| `value` | string | | Metadata value |
| `from` | float | | Since timestamp |
| `to` | float | | Until timestamp |
| `class` | int | | Classification (0=public, 1=private, 2=restricted, 3=sovereign) |
| `limit` | int | 100 | Max results (max 1000) |
| `offset` | int | 0 | Pagination offset |

```bash
curl "http://localhost:9473/records/search?creator=a1b2c3d4...&limit=10"
```

### `GET /records/stream`

Server-Sent Events (SSE) stream of real-time record events.

```bash
curl -N http://localhost:9473/records/stream
```

Events: `record_inserted`, `record_finalized`. Data format matches the WebSocket event format.

---

## Epochs

### `GET /epochs`

Current epoch sealing status per zone.

```bash
curl http://localhost:9473/epochs
```

```json
{
  "epochs": [
    {"zone": 0, "epoch_number": 42, "latest_seal_id": "seal-...", "latest_seal_hash": "abcdef..."}
  ]
}
```

---

## Governance

### `GET /governance/proposals`

List governance proposals with optional filtering.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | | Filter: active, passed, rejected, expired, executed, cancelled, vetoed |
| `limit` | int | 50 | Max results (max 200) |
| `offset` | int | 0 | Pagination offset |

```bash
curl "http://localhost:9473/governance/proposals?status=active&limit=10"
```

```json
{
  "proposals": [
    {
      "id": "prop-001",
      "proposer": "a1b2c3d4...",
      "category": "parameter",
      "title": "Increase witness reward",
      "status": "active",
      "created_at": 1710000000.0,
      "voting_deadline": 1710604800.0,
      "vote_count": 5,
      "tally": {"for": 3.5, "against": 1.0, "abstain": 0.5, "voters": 5, "raw_participating_stake": 500000000}
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

### `GET /governance/proposal/{id}`

Detailed view of a single proposal including all votes.

```bash
curl http://localhost:9473/governance/proposal/prop-001
```

```json
{
  "id": "prop-001",
  "proposer": "a1b2c3d4...",
  "category": "parameter",
  "title": "Increase witness reward",
  "description": "Raise the witness reward from 0.1 to 0.2 beat per attestation.",
  "status": "active",
  "created_at": 1710000000.0,
  "voting_deadline": 1710604800.0,
  "passed_at": null,
  "can_execute": false,
  "votes": [
    {"voter": "d4e5f6...", "direction": "for", "stake": 200000000, "voted_at": 1710001000.0, "conviction": 1.0, "dampened_power": 200000000}
  ],
  "tally": {
    "for_conviction": 3.5, "against_conviction": 1.0, "abstain_conviction": 0.5,
    "voters": 5, "raw_participating_stake": 500000000,
    "for_fraction": 0.7, "supermajority_met": true
  },
  "total_governance_staked": 800000000
}
```

### `GET /governance/summary`

High-level governance statistics.

```bash
curl http://localhost:9473/governance/summary
```

```json
{
  "total_proposals": 5,
  "active": 1, "passed": 2, "rejected": 1, "expired": 0,
  "executed": 1, "cancelled": 0, "vetoed": 0,
  "active_delegations": 3,
  "total_governance_staked": 3000000000000,
  "min_proposal_stake": 1000000000000,
  "max_active_proposals_per_identity": 3,
  "voting_period_secs": 604800,
  "execution_delay_secs": 86400,
  "supermajority_threshold": 0.6667,
  "min_participation_fraction": 0.1
}
```

### `GET /governance/delegations/{identity}`

Delegation information for an identity (incoming and outgoing).

```bash
curl http://localhost:9473/governance/delegations/a1b2c3d4...
```

```json
{
  "identity": "a1b2c3d4...",
  "own_governance_stake": 200000000,
  "delegated_to_me": [{"delegator": "d4e5f6...", "stake": 100000000, "created_at": 1710000000.0}],
  "delegated_from_me": null,
  "total_effective_stake": 300000000
}
```

### `GET /governance/params`

Current governable parameter values.

```bash
curl http://localhost:9473/governance/params
```

```json
{
  "propagation_rate_limit_per_hour": 10000,
  "epoch_seal_interval_secs": 120,
  "witness_reward_micros": 100000,
  "record_retention_secs": 2592000,
  "total_changes": 2
}
```

### `GET /governance/params/history`

Parameter change history.

| Parameter | Type | Description |
|-----------|------|-------------|
| `param` | string | (optional) Filter by parameter name |

```bash
curl "http://localhost:9473/governance/params/history?param=witness_reward_micros"
```

```json
{
  "count": 1,
  "changes": [
    {"name": "witness_reward_micros", "old_value": 50000, "new_value": 100000, "proposal_id": "prop-001", "applied_at": 1710000000.0}
  ]
}
```

---

## Protocol Limits

### `GET /limits`

Hard protocol limits.

```bash
curl http://localhost:9473/limits
```

Returns complete limits structure including max supply, rate limits, staking minimums, and all protocol-enforced bounds.

---

## Consensus

### `GET /consensus/status`

Consensus tracking with unsettled records.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 20 | Max unsettled records (max 100) |

```bash
curl http://localhost:9473/consensus/status
```

```json
{
  "total_attestations": 4500,
  "settled": 1200,
  "finalized": 1200,
  "confirmation_levels": {"unconfirmed": 10, "attested": 5, "confirmed": 3, "anchored": 1200},
  "waiting": [
    {"record_id": "01234567-...", "attestations": 2, "trust_score": 0.45}
  ]
}
```

### `GET /consensus/record/{id}`

Detailed consensus state for a specific record.

```bash
curl http://localhost:9473/consensus/record/01234567-...
```

```json
{
  "record_id": "01234567-...",
  "zone": 0,
  "is_settled": true,
  "is_finalized": true,
  "confirmation_level": "anchored",
  "distinct_clusters": 3,
  "trust_score": 0.95,
  "total_zone_stake": 500000000,
  "attesting_stake": 400000000,
  "threshold_pct": 80.0,
  "settlement_threshold": "66.67%",
  "attestation_count": 3,
  "attestations": [
    {"witness_hash": "w1t2n3e4...", "stake": 200000000, "independence": 1.0, "timestamp": 1710000001.0}
  ]
}
```

---

## Witness Management

### `POST /witness/profile`

Register a witness profile for sybil resistance scoring.

```bash
curl -X POST http://localhost:9473/witness/profile \
  -H "Content-Type: application/json" \
  -d '{"witness_hash": "w1t2n3e4...", "organization": "org-a", "subnet": "10.0.0.0/8", "geo_zone": "eu-west"}'
```

```json
{"registered": true, "witness_hash": "w1t2n3e4...", "organization": "org-a", "subnet": "10.0.0.0/8", "geo_zone": "eu-west"}
```

### `GET /witness/profiles`

List all registered witness profiles.

```bash
curl http://localhost:9473/witness/profiles
```

### `GET /witness/correlation`

Compute sybil correlation between two witnesses.

| Parameter | Type | Description |
|-----------|------|-------------|
| `witness_a` | string | *required* — First witness hash |
| `witness_b` | string | *required* — Second witness hash |

```bash
curl "http://localhost:9473/witness/correlation?witness_a=w1t2n3e4...&witness_b=x5y6z7a8..."
```

```json
{
  "witness_a": "w1t2n3e4...", "witness_b": "x5y6z7a8...",
  "correlation": 0.15,
  "profile_a": {"organization": "org-a", "subnet": "10.0.0.0/8", "geo_zone": "eu-west"},
  "profile_b": {"organization": "org-b", "subnet": "172.16.0.0/12", "geo_zone": "us-east"}
}
```

### `GET /witness/reputation`

Witness reputation scores and trust multipliers.

| Parameter | Type | Description |
|-----------|------|-------------|
| `witness` | string | (optional) Specific witness hash |

```bash
curl "http://localhost:9473/witness/reputation?witness=w1t2n3e4..."
```

```json
{"witness_hash": "w1t2n3e4...", "score": 0.85, "trust_multiplier": 1.2, "positive_events": 150, "negative_events": 2, "last_event": 1710000000.0}
```

---

## Peer Reputation

### `GET /peers/reputation`

Reputation scores for all known peers.

```bash
curl http://localhost:9473/peers/reputation
```

```json
{
  "peers": [
    {"identity_hash": "a1b2c3d4...", "host": "10.0.0.2", "node_type": "witness", "reputation": 0.95, "successes": 500, "failures": 2, "valid_records": 1200, "invalid_records": 0, "state": "connected"}
  ],
  "count": 2
}
```

---

## Disputes

### `GET /disputes`

List disputes (Protocol §11.13).

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | (optional) Filter by status |

```bash
curl http://localhost:9473/disputes
```

### `GET /disputes/{id}`

Single dispute detail.

```bash
curl http://localhost:9473/disputes/dispute-001
```

---

## Fisherman Challenges

### `GET /challenges`

List fisherman challenges.

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | (optional) Filter by status |

```bash
curl http://localhost:9473/challenges
```

```json
{
  "total": 3,
  "filed_total": 5,
  "challenges": [
    {"id": "chal-001", "challenger": "a1b2c3d4...", "accused": "d4e5f6a7...", "challenge_type": "double_attestation", "status": "voting", "filed_at": 1710000000.0, "jury_size": 5, "votes_cast": 3}
  ]
}
```

### `GET /challenges/{id}`

Single challenge detail with jury votes.

```bash
curl http://localhost:9473/challenges/chal-001
```

```json
{
  "id": "chal-001",
  "challenger": "a1b2c3d4...",
  "accused": "d4e5f6a7...",
  "challenge_type": "double_attestation",
  "status": "resolved",
  "filed_at": 1710000000.0,
  "evidence": {},
  "jury": ["j1...", "j2...", "j3..."],
  "votes": [{"juror": "j1...", "guilty": true, "timestamp": 1710001000.0}],
  "verdict": true,
  "verdict_at": 1710002000.0,
  "is_appeal": false,
  "slash_amount": 50000000
}
```

---

## Light Client

### `GET /proofs/{record_id}`

Merkle inclusion proof for a record (Protocol §11.3).

```bash
curl http://localhost:9473/proofs/01234567-...
```

```json
{
  "record_id": "01234567-...",
  "zone": 0,
  "leaf": "abcdef01...",
  "root": "fedcba98...",
  "siblings": [{"hash": "112233...", "is_right": true}],
  "verified": true
}
```

### `GET /epochs/headers`

Epoch headers for light client sync.

| Parameter | Type | Description |
|-----------|------|-------------|
| `zone` | int | (optional) Filter by zone |
| `since` | int | (optional) Epoch number to start from |

```bash
curl "http://localhost:9473/epochs/headers?zone=0&since=40"
```

```json
{
  "total": 3,
  "headers": [
    {"zone": 0, "epoch_number": 42, "merkle_root": "abcdef...", "previous_seal_hash": "fedcba...", "record_count": 50, "start": 1709900000.0, "end": 1710000000.0}
  ]
}
```

---

## Zone Health

### `GET /zones`

Zone health and witness coverage (Protocol §7.5).

```bash
curl http://localhost:9473/zones
```

```json
{
  "zones": [{"zone": 0, "total_stake": 500000000, "active_records": 100, "settled_records": 95, "unique_witnesses": 3}],
  "total_zones": 1,
  "coverage": [{"zone": 0, "record_count": 100, "unique_witnesses": 3, "has_coverage": true}],
  "under_witnessed_zones": 0,
  "min_witnesses_required": 2
}
```

---

## ITC Causal Clocks

### `GET /itc`

Interval Tree Clock status (Protocol §11.9).

```bash
curl http://localhost:9473/itc
```

```json
{"itc": {}, "events_total": 1500, "joins_total": 300}
```

---

## Rewards

### `GET /rewards`

Witness reward statistics.

```bash
curl http://localhost:9473/rewards
```

```json
{
  "auto_rewards_total": 500,
  "auto_rewards_amount_micros": 50000000000,
  "auto_rewards_amount_beat": 50.0,
  "reward_per_attestation_micros": 100000000,
  "reward_per_attestation_beat": 0.1,
  "conservation_pool_micros": 50000000000000,
  "conservation_pool_beat": 50000.0,
  "conservation_pool_cap_micros": 1000000000000000000,
  "conservation_pool_headroom_micros": 999950000000000000,
  "is_genesis_authority": true
}
```

---

## Gossip Protocol

### `GET /gossip`

Gossip protocol health metrics.

```bash
curl http://localhost:9473/gossip
```

```json
{
  "push_total": 5000,
  "relay_total": 3000,
  "pull_total": 1000,
  "push_skipped_total": 50,
  "seen_dedup_total": 200,
  "push_failed_total": 10,
  "retry_total": 15,
  "retry_success_total": 12,
  "attestation_dedup_total": 30,
  "push_rate_per_min": 8.3,
  "pull_rate_per_min": 1.7,
  "effective_hops": 3,
  "config_max_hops": 5,
  "pull_interval_secs": 60,
  "seen_set_size": 5000,
  "attestation_seen_set_size": 5000,
  "attestation_bad_sig_cache_size": 10,
  "uptime_seconds": 3600
}
```

---

## Genesis & Bootstrap

### `GET /genesis/allocation`

Genesis pool allocation and distribution status.

```bash
curl http://localhost:9473/genesis/allocation
```

```json
{
  "pools": [
    {"pool": "conservation", "remaining": 9500000000000000, "distributed": 0},
    {"pool": "witness_rewards", "remaining": 250000000000000, "distributed": 50000000}
  ],
  "total_remaining": 9750000000000000,
  "total_distributed": 50000000,
  "bootstrap_nodes_claimed": 3,
  "bootstrap_target_nodes": 100,
  "team_available_to_unlock": 0,
  "contributor_available_to_unlock": 0
}
```

### `GET /bootstrap/status`

Bootstrap phase detection.

```bash
curl http://localhost:9473/bootstrap/status
```

```json
{
  "phase": "genesis",
  "node_count": 3,
  "multiplier": 3.0,
  "transitions": 0,
  "testnet": true,
  "phase_boundaries": {"genesis": "<10 nodes", "early_growth": "10-50", "decentralization": "50-200", "critical_mass": "200+"}
}
```

---

## DAG

### `GET /dag/lifecycle`

Record lifecycle counts (pending → attested → finalized).

```bash
curl http://localhost:9473/dag/lifecycle
```

```json
{
  "total_records": 1547,
  "pending": 10,
  "attested": 5,
  "finalized": 1200,
  "dag_tips": 3,
  "dag_edges": 2891,
  "avg_parents": 1.87
}
```

### `GET /dag/tips`

Current DAG tips and roots.

```bash
curl http://localhost:9473/dag/tips
```

```json
{
  "tips": ["tip-id-1", "tip-id-2"],
  "tips_count": 2,
  "roots": ["root-id-1"],
  "roots_count": 1
}
```

### `GET /dag/record/{id}/graph`

Graph traversal around a record.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `depth` | int | 5 | Max traversal depth (max 20) |
| `direction` | string | both | `both`, `ancestors`, or `descendants` |

```bash
curl "http://localhost:9473/dag/record/01234567-.../graph?depth=3&direction=ancestors"
```

### `GET /dag/search`

Search DAG records by multiple criteria.

| Parameter | Type | Description |
|-----------|------|-------------|
| `op` | string | Token op: mint, transfer, stake, unstake, witness_reward, slash, burn, dormancy_reclaim |
| `creator` | string | Creator identity hash |
| `to` | string | Recipient (beat_to) |
| `from` | string | Sender (beat_from) |
| `since` | float | Unix timestamp lower bound |
| `until` | float | Unix timestamp upper bound |
| `classification` | string | public, private, restricted, sovereign |
| `has_key` | string | Filter by metadata key existence |
| `limit` | int | Max results (default 50, max 500) |

```bash
curl "http://localhost:9473/dag/search?op=transfer&since=1710000000&limit=20"
```

### `GET /dag/stats`

Comprehensive DAG statistics.

```bash
curl http://localhost:9473/dag/stats
```

```json
{
  "total_records": 1547,
  "unique_creators": 42,
  "time_range": {"earliest": 1709900000.0, "latest": 1710000000.0},
  "by_classification": {"public": 1500, "private": 20, "restricted": 25, "sovereign": 2},
  "by_operation": {"mint": 1, "transfer": 500, "stake": 10, "unstake": 2, "burn": 0, "slash": 1, "witness_reward": 500, "dormancy_reclaim": 0, "pool_fund": 3, "epoch_seal": 42, "non_token": 488}
}
```

---

## Node Diagnostics

### `GET /node/identity`

Node identity information.

```bash
curl http://localhost:9473/node/identity
```

```json
{
  "identity_hash": "a1b2c3d4...",
  "entity_type": "node",
  "crypto_profile": "dilithium3",
  "algorithm": "dilithium3",
  "has_pow": true,
  "pow_difficulty": 16,
  "node_type": "authority",
  "is_genesis_authority": true,
  "version": "0.2.0"
}
```

### `GET /node/config`

Operational node configuration (no secrets exposed).

```bash
curl http://localhost:9473/node/config
```

```json
{
  "listen_addr": "0.0.0.0:9473",
  "node_type": "authority",
  "genesis_authority": "a1b2c3d4... (truncated)",
  "seed_peers_count": 2,
  "gossip_pull_interval_secs": 60,
  "gossip_max_hops": 5,
  "auto_witness": true,
  "auto_witness_interval_secs": 30,
  "auto_witness_batch_size": 10,
  "epoch_seal_interval_secs": 120,
  "snapshot_interval_secs": 600,
  "max_peer_failures": 5,
  "pex_interval_secs": 120,
  "rate_limit_read": 600,
  "rate_limit_write": 120,
  "witness_reward_micros": 100000
}
```

---

## Admin Endpoints

Admin endpoints are served only on the node's on-box admin listener (the
loopback data-plane address, `127.0.0.1:9472` under the default split data
plane) — never on the public API port. Each mutating call is authorized by a
post-quantum **signed header** (`X-PQ-Admin`), not a bearer token: bearer auth
was removed in the PQ-R7 transport revision. Authorize an operator key once via
the `ELARA_ADMIN_PUBKEYS` environment variable, then sign each request's
method + full request target (path INCLUDING any `?query` — V2) with
`elara-cli`. Requests without a valid signed header receive HTTP 422.

```bash
# One-time: generate an operator keypair, then authorize its public key on the
# node (e.g. a systemd drop-in setting ELARA_ADMIN_PUBKEYS).
elara-cli pq-admin-keygen                       # writes a Dilithium3 keypair JSON

# Per call: sign the exact method + request target (path INCLUDING any
# `?query`, byte-identical to the URL you curl — V2), then send the header.
HDR=$(elara-cli admin-sign --key ~/.elara/admin/admin.dilithium3.json \
      --method POST --path /admin/snapshot)
curl -X POST http://127.0.0.1:9472/admin/snapshot -H "X-PQ-Admin: $HDR"
```

Every `/admin/*` endpoint requires the header — including the read-only diagnostics (`/admin/gc` GET, `/admin/dag_check`, `/admin/fork_check`, `/admin/revocations`, `/admin/key_rotations`, `/admin/witness_liveness`, `/admin/sunset`); unauthenticated calls fail and count toward the auth lockout.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/snapshot` | Trigger ledger state snapshot |
| `GET` | `/admin/tasks` | List background tasks (auto-witness, gossip, etc.) |
| `GET` | `/admin/export` | Export full node state as JSON |
| `POST` | `/admin/purge_peer` | Remove peer from routing table |
| `POST` | `/admin/force_sync` | Force delta sync with specific peer |
| `POST` | `/admin/reindex_dag` | Rebuild DAG indexes from storage |
| `POST` | `/admin/ban_ip` | Ban IP address |
| `POST` | `/admin/unban_ip` | Unban IP address |
| `GET` | `/admin/bans` | List banned IPs |
| `GET` | `/admin/gc` | Garbage collection status |
| `POST` | `/admin/gc` | Trigger garbage collection |
| `GET` | `/admin/dag_check` | DAG integrity check |
| `GET` | `/admin/fork_check` | Detect forks across peers |
| `POST` | `/admin/fork_heal` | Heal detected forks |
| `GET` | `/admin/revocations` | List key revocations |
| `GET` | `/admin/key_rotations` | List key rotations |
| `GET` | `/admin/witness_liveness` | Witness liveness tracking |
| `GET` | `/admin/sunset` | Algorithm sunset state (Protocol v0.6.1 §11.29) |
| `POST` | `/admin/ban_identity` | Ban identity hash (all records rejected) |
| `POST` | `/admin/unban_identity` | Unban identity hash |
| `GET` | `/admin/banned_identities` | List banned identities |
| `POST` | `/admin/blocklist/add` | Add content blocklist term |
| `POST` | `/admin/blocklist/remove` | Remove content blocklist term |
| `GET` | `/admin/blocklist` | List content blocklist terms |

---

## WebSocket (`/pq-ws`)

### `GET /pq-ws`

The node's single real-time transport is an **ELPQ-tunneled WebSocket**. The
connection first completes the post-quantum ElaraPQ handshake (ML-KEM-768 +
X25519 key exchange, Dilithium3 authentication — see whitepaper §4.7), then
carries WebSocket frames inside that authenticated tunnel. It is **not** a plain
`ws://` upgrade — a standard WebSocket client cannot connect without the ELPQ
layer. The legacy unauthenticated `/ws` route has been retired. `/pq-ws` is on
the public surface (reachable off-host); the light-client SDK
(`src/network/light_sdk.rs`) performs the handshake for you.

**Connection:** ElaraPQ handshake (10 s timeout) → WebSocket. Concurrent
connections are globally capped (`ws_max_connections`) and per-message size is
bounded; the PQ identity established during the handshake authorizes write verbs.

**Messages:** request/response JSON inside the tunnel, envelope
`{"type": "<verb>", "id": <number>, ...params}` — the node echoes the same `id`
on its reply. The verb set is broad (light-client reads, chain sync, submit,
event streams); the authoritative, always-current list is the dispatch table in
[`src/network/pq_transport/router.rs`](../src/network/pq_transport/router.rs).
Common verbs (non-exhaustive):

| Verb | Auth | Purpose |
|------|------|---------|
| `ping` | No | Heartbeat |
| `status` | No | Node status / chain tip |
| `query_records` | No | Query records (bounded limit) |
| `account_proof` | No | Account state + Merkle proof bound to a seal |
| `headers_from` | No | Epoch headers from a given epoch (light-client sync) |
| `delta_sync` | No | Incremental record sync since a baseline |
| `submit_record` | Yes | Submit a signed record |
| `node_events_stream` | No | Stream real-time `record_inserted` / `record_finalized` events |

*Auth = requires the authenticated PQ identity established in the handshake.*

**Server → Client events** (delivered on the `node_events_stream` verb):

```json
{"type": "record_inserted", "data": {"record_id": "...", "creator_hash": "...", "timestamp": 1710000000.0}}
{"type": "record_finalized", "data": {"record_id": "..."}}
```
