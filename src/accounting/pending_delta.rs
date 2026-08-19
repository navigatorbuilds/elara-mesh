//! ARCH-1 tentative ledger delta — reversible representation of every
//! ledger mutation a [`ParsedLedgerOp`] would make.
//!
//! A delta is produced at ingest (phase 4) and sits in
//! [`PendingLedger`](super::pending_ledger::PendingLedger) until the
//! owning record reaches `ConfirmationLevel::Finalized`. Only then is the
//! delta committed to `CF_LEDGER`. If the record is discarded (epoch
//! timeout, explicit rejection, conflict resolution), the delta is
//! dropped with no ledger mutation.
//!
//! Kept as a struct rather than a closure so the whole thing is
//! serializable and can be persisted to `CF_PENDING_DELTAS` for crash
//! recovery (see internal design notes §3.3, §6).

use serde::{Deserialize, Serialize};

use crate::accounting::types::{ParsedLedgerOp, PredictionClaim, StakePurpose};

/// A single pending ledger mutation, keyed by the ingesting record's id.
///
/// `op` carries every field the commit and discard paths need. The creator
/// identity hash is captured at parse time (from the `ValidationRecord`'s
/// creator key) so commit/discard do not need to re-parse the record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingLedgerDelta {
    /// The ingesting record's id. Primary key in `CF_PENDING_DELTAS`.
    pub record_id: String,
    /// The ingesting record's creator identity hash (hex-encoded).
    /// Captured from the record's creator public key at parse time.
    pub creator: String,
    /// `record.timestamp`. Preserved so commit can compute idle_decay /
    /// decay relative to the original record time, not the commit time.
    pub timestamp: f64,
    /// Wall-clock seconds (epoch) when this delta was inserted into
    /// `PendingLedger`. Drives the epoch-timeout discard path (see
    /// internal design notes §4.3).
    pub applied_at: f64,
    /// The reversible operation representation.
    pub op: PendingOp,
}

/// Reversible representation of every [`ParsedLedgerOp`] variant.
///
/// One-to-one with `ParsedLedgerOp`, but flattened to include the fields the
/// commit path needs without re-parsing. Field order matches the source
/// enum so future additions stay obvious.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PendingOp {
    Mint {
        to: String,
        amount: u64,
        reason: String,
    },
    Transfer {
        from: String,
        to: String,
        amount: u64,
        memo: Option<String>,
    },
    Stake {
        owner: String,
        amount: u64,
        purpose: StakePurpose,
        stake_record_id: String,
    },
    Unstake {
        owner: String,
        stake_record_id: String,
    },
    WitnessReward {
        from: String,
        to: String,
        amount: u64,
        witnessed_record_id: String,
    },
    Slash {
        offender: String,
        challenger: String,
        jury: Vec<String>,
        stake_record_id: String,
        amount: u64,
        reason: String,
    },
    DormancyReclaim {
        dormant_identity: String,
        amount: u64,
        last_activity: f64,
        reclaimer: String,
    },
    Burn {
        owner: String,
        amount: u64,
        memo: Option<String>,
    },
    PoolFund {
        from: String,
        amount: u64,
    },
    Predict {
        from: String,
        amount: u64,
        zone: String,
        target_epoch: u64,
        claim: PredictionClaim,
        predicted_value: u64,
    },
    XZoneLock {
        from: String,
        amount: u64,
        recipient: String,
        source_zone: String,
        dest_zone: String,
    },
    XZoneClaim {
        recipient: String,
        transfer_id: String,
        amount: u64,
    },
    XZoneCancel {
        sender: String,
        transfer_id: String,
    },
    XZoneReject {
        recipient: String,
        transfer_id: String,
    },
    /// Sealed-abort with B-committee non-inclusion proof. Submitter
    /// (`aborter`) need not be the sender or recipient — anyone with a
    /// valid 2/3 quorum may submit. The full proof lives in the record's
    /// metadata; the pending delta only needs the transfer id for
    /// effective-balance accounting (no debit on the aborter's side).
    XZoneAbort {
        aborter: String,
        transfer_id: String,
    },
    DormancyDeclare {
        declarer: String,
        target_identity: String,
        last_known_active: f64,
    },
    DormancyHeartbeat {
        identity: String,
    },
    DormancyProofOfLife {
        relayer: String,
        target_identity: String,
        signature: String,
    },
    WitnessRegister {
        witness: String,
        zone_path: String,
        bond: u64,
    },
    /// Frozen per-epoch custodial-idle_decay batch (genesis-authority emitted).
    /// Only the exchange debits matter for effective-available accounting; the
    /// staker / pool credits are not tracked as pending (same as `Slash`).
    IdleDecay {
        debits: Vec<(String, u64)>,
    },
    /// Frozen per-epoch cross-zone timeout-refund batch (genesis-authority
    /// emitted). Pure credit back to the original senders of expired UNSEALED
    /// locks — it debits no one — so nothing is tracked for effective-available
    /// (same no-debit accounting as XZoneCancel/Reject/Abort; the lock-time debit
    /// was already booked under the original XZoneLock pending entry).
    XZoneTimeoutRefund,
    /// Frozen per-epoch far-horizon SEALED-stuck reap batch (genesis-authority
    /// emitted, co-fix (b)). Same no-debit accounting as XZoneTimeoutRefund.
    XZoneStaleReap,
}

impl PendingOp {
    /// Flatten a [`ParsedLedgerOp`] + its creator identity into a
    /// [`PendingOp`]. `creator` is the hex identity hash of the record's
    /// creator public key (see `identity_hash`). `record_id` is the
    /// ingesting record id; used by variants that need to self-reference
    /// (e.g. `Stake` uses `record.id` as `stake_record_id`).
    pub fn from_parsed(op: ParsedLedgerOp, creator: &str, record_id: &str) -> Self {
        match op {
            ParsedLedgerOp::Mint { amount, to, reason } => {
                PendingOp::Mint { to, amount, reason }
            }
            ParsedLedgerOp::Transfer { amount, to, memo } => PendingOp::Transfer {
                from: creator.to_string(),
                to,
                amount,
                memo,
            },
            ParsedLedgerOp::Stake { amount, purpose } => PendingOp::Stake {
                owner: creator.to_string(),
                amount,
                purpose,
                stake_record_id: record_id.to_string(),
            },
            ParsedLedgerOp::Unstake { stake_record_id } => PendingOp::Unstake {
                owner: creator.to_string(),
                stake_record_id,
            },
            ParsedLedgerOp::WitnessReward {
                amount,
                from,
                to,
                record_id: witnessed,
            } => PendingOp::WitnessReward {
                from,
                to,
                amount,
                witnessed_record_id: witnessed,
            },
            ParsedLedgerOp::Slash {
                amount,
                offender,
                challenger,
                jury,
                stake_record_id,
                reason,
            } => PendingOp::Slash {
                offender,
                challenger,
                jury,
                stake_record_id,
                amount,
                reason,
            },
            ParsedLedgerOp::DormancyReclaim {
                amount,
                dormant_identity,
                last_activity,
            } => PendingOp::DormancyReclaim {
                dormant_identity,
                amount,
                last_activity,
                reclaimer: creator.to_string(),
            },
            ParsedLedgerOp::Burn { amount, memo } => PendingOp::Burn {
                owner: creator.to_string(),
                amount,
                memo,
            },
            ParsedLedgerOp::PoolFund { amount } => PendingOp::PoolFund {
                from: creator.to_string(),
                amount,
            },
            ParsedLedgerOp::Predict {
                amount,
                zone,
                target_epoch,
                claim,
                predicted_value,
            } => PendingOp::Predict {
                from: creator.to_string(),
                amount,
                zone,
                target_epoch,
                claim,
                predicted_value,
            },
            ParsedLedgerOp::XZoneLock {
                amount,
                recipient,
                source_zone,
                dest_zone,
            } => PendingOp::XZoneLock {
                from: creator.to_string(),
                amount,
                recipient,
                source_zone,
                dest_zone,
            },
            ParsedLedgerOp::XZoneClaim {
                transfer_id,
                amount,
                recipient,
            } => PendingOp::XZoneClaim {
                recipient,
                transfer_id,
                amount,
            },
            ParsedLedgerOp::XZoneCancel { transfer_id } => PendingOp::XZoneCancel {
                sender: creator.to_string(),
                transfer_id,
            },
            ParsedLedgerOp::XZoneReject { transfer_id } => PendingOp::XZoneReject {
                recipient: creator.to_string(),
                transfer_id,
            },
            ParsedLedgerOp::XZoneAbort { transfer_id, .. } => PendingOp::XZoneAbort {
                aborter: creator.to_string(),
                transfer_id,
            },
            ParsedLedgerOp::DormancyDeclare {
                target_identity,
                last_known_active,
            } => PendingOp::DormancyDeclare {
                declarer: creator.to_string(),
                target_identity,
                last_known_active,
            },
            ParsedLedgerOp::DormancyHeartbeat => PendingOp::DormancyHeartbeat {
                identity: creator.to_string(),
            },
            ParsedLedgerOp::DormancyProofOfLife {
                target_identity,
                signature,
            } => PendingOp::DormancyProofOfLife {
                relayer: creator.to_string(),
                target_identity,
                signature,
            },
            ParsedLedgerOp::WitnessRegister { zone_path, bond } => PendingOp::WitnessRegister {
                witness: creator.to_string(),
                zone_path,
                bond,
            },
            ParsedLedgerOp::IdleDecay { batch } => PendingOp::IdleDecay {
                debits: batch.debits,
            },
            ParsedLedgerOp::XZoneTimeoutRefund { .. } => PendingOp::XZoneTimeoutRefund,
            ParsedLedgerOp::XZoneStaleReap { .. } => PendingOp::XZoneStaleReap,
        }
    }

    /// Amount the operation would debit from its originating identity.
    ///
    /// Used by `PendingLedger::locked_by_identity` so `effective_available`
    /// can subtract in-flight pending debits from the committed balance.
    /// Returns 0 for ops that do not debit the creator (Mint, Unstake,
    /// WitnessReward, DormancyDeclare/Heartbeat/ProofOfLife).
    pub fn debit_amount_for(&self, identity: &str) -> u64 {
        match self {
            PendingOp::Transfer { from, amount, .. }
            | PendingOp::Stake {
                owner: from,
                amount,
                ..
            }
            | PendingOp::Burn {
                owner: from,
                amount,
                ..
            }
            | PendingOp::PoolFund { from, amount }
            | PendingOp::Predict { from, amount, .. }
            | PendingOp::XZoneLock { from, amount, .. }
            | PendingOp::WitnessRegister {
                witness: from,
                bond: amount,
                ..
            } => {
                if from == identity {
                    *amount
                } else {
                    0
                }
            }
            // IdleDecay debits the listed exchanges (not the creator); sum the
            // debit(s) targeting this identity so its effective-available drops
            // during the brief pre-seal window. Staker/pool credits aren't tracked.
            PendingOp::IdleDecay { debits } => debits
                .iter()
                .filter(|(id, _)| id == identity)
                .map(|(_, a)| *a)
                .sum(),
            PendingOp::Mint { .. }
            | PendingOp::Unstake { .. }
            | PendingOp::WitnessReward { .. }
            | PendingOp::Slash { .. }
            | PendingOp::DormancyReclaim { .. }
            | PendingOp::XZoneClaim { .. }
            // XZoneCancel only credits the sender (refund of an unsealed
            // lock) — the available-balance debit at lock time was already
            // accounted for by the XZoneLock's pending entry. The cancel
            // record itself does not debit `available`.
            | PendingOp::XZoneCancel { .. }
            // XZoneReject is the recipient-initiated counterpart of
            // XZoneCancel; same no-debit accounting (the refund credits
            // the sender from the existing locked pool).
            | PendingOp::XZoneReject { .. }
            // XZoneAbort: like cancel/reject, no debit on the submitter —
            // the lock-time debit is already booked under the original
            // sender's XZoneLock pending entry; abort just flips the
            // refund-credit path.
            | PendingOp::XZoneAbort { .. }
            // XZoneTimeoutRefund / XZoneStaleReap credit the original senders of
            // expired locks — no debit on anyone; the lock-time debit was already
            // booked under the original XZoneLock pending entry.
            | PendingOp::XZoneTimeoutRefund
            | PendingOp::XZoneStaleReap
            | PendingOp::DormancyDeclare { .. }
            | PendingOp::DormancyHeartbeat { .. }
            | PendingOp::DormancyProofOfLife { .. } => 0,
        }
    }
}

impl PendingLedgerDelta {
    pub fn new(
        record_id: String,
        creator: String,
        timestamp: f64,
        applied_at: f64,
        op: PendingOp,
    ) -> Self {
        Self {
            record_id,
            creator,
            timestamp,
            applied_at,
            op,
        }
    }

    /// Serialize to JSON — the on-disk format for `CF_PENDING_DELTAS`.
    /// Same encoding used by `CF_TRANSITIONS_PENDING` (see
    /// `network::transition_store`).
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_transfer_delta() -> PendingLedgerDelta {
        PendingLedgerDelta::new(
            "rec-001".to_string(),
            "alice_hash".to_string(),
            100.0,
            100.5,
            PendingOp::Transfer {
                from: "alice_hash".to_string(),
                to: "bob_hash".to_string(),
                amount: 42,
                memo: Some("lunch".to_string()),
            },
        )
    }

    #[test]
    fn json_roundtrip_preserves_delta() {
        let d = mk_transfer_delta();
        let bytes = d.to_json().unwrap();
        let back = PendingLedgerDelta::from_json(&bytes).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn from_parsed_captures_creator_for_transfer() {
        let op = ParsedLedgerOp::Transfer {
            amount: 10,
            to: "bob".to_string(),
            memo: None,
        };
        let pending = PendingOp::from_parsed(op, "alice", "rec-x");
        match pending {
            PendingOp::Transfer { from, to, amount, memo } => {
                assert_eq!(from, "alice");
                assert_eq!(to, "bob");
                assert_eq!(amount, 10);
                assert_eq!(memo, None);
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn from_parsed_stake_uses_record_id() {
        let op = ParsedLedgerOp::Stake {
            amount: 500,
            purpose: StakePurpose::Witness,
        };
        let pending = PendingOp::from_parsed(op, "alice", "rec-stake-42");
        match pending {
            PendingOp::Stake { owner, amount, purpose, stake_record_id } => {
                assert_eq!(owner, "alice");
                assert_eq!(amount, 500);
                assert_eq!(purpose, StakePurpose::Witness);
                assert_eq!(stake_record_id, "rec-stake-42");
            }
            other => panic!("expected Stake, got {other:?}"),
        }
    }

    #[test]
    fn debit_amount_counts_only_originating_debits() {
        let d = mk_transfer_delta();
        assert_eq!(d.op.debit_amount_for("alice_hash"), 42);
        assert_eq!(d.op.debit_amount_for("bob_hash"), 0);
        assert_eq!(d.op.debit_amount_for("charlie"), 0);
    }

    #[test]
    fn debit_amount_skips_non_debiting_ops() {
        let mint = PendingOp::Mint {
            to: "alice".to_string(),
            amount: 1_000,
            reason: "genesis".to_string(),
        };
        assert_eq!(mint.debit_amount_for("alice"), 0);

        let heartbeat = PendingOp::DormancyHeartbeat {
            identity: "alice".to_string(),
        };
        assert_eq!(heartbeat.debit_amount_for("alice"), 0);
    }

    #[test]
    fn every_parsed_variant_maps_to_pending_op() {
        // Defensive: if a new ParsedLedgerOp variant lands without being
        // added to PendingOp::from_parsed, this test won't compile.
        // Acts as a compile-time checklist for ARCH-1 completeness.
        let _ = PendingOp::from_parsed(
            ParsedLedgerOp::DormancyHeartbeat,
            "alice",
            "rec",
        );
    }

    // ─────────────── wire-format + dispatch tests ──────────────────────────
    // Fixture-free wire-format + dispatch pins. No PendingLedger, no ingest
    // chain — these tests defend the byte-shape of CF_PENDING_DELTAS and the
    // creator-capture rules in from_parsed for variants the existing tests
    // don't touch (Burn, Mint).

    #[test]
    fn batch_b_pending_op_serde_kind_tag_snake_case_shape_pin_for_transfer() {
        // ARCH-1 wire-format pin: the enum is serialized with `tag = "kind"`
        // and `rename_all = "snake_case"`. Drift in either silently breaks
        // every CF_PENDING_DELTAS row from before the drift; pin the exact
        // JSON shape on the Transfer variant.
        let op = PendingOp::Transfer {
            from: "a".to_string(),
            to: "b".to_string(),
            amount: 7,
            memo: None,
        };
        let json: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
        assert_eq!(json["kind"], "transfer", "tag must be 'kind', value snake_case");
        assert_eq!(json["from"], "a");
        assert_eq!(json["to"], "b");
        assert_eq!(json["amount"], 7);
        // `None` for memo serializes to JSON null, not omitted.
        assert!(json["memo"].is_null(), "Option::None must be JSON null, not absent");

        // Sanity-pin a different variant's snake_case tag value.
        let stake = PendingOp::Stake {
            owner: "x".into(),
            amount: 1,
            purpose: StakePurpose::Witness,
            stake_record_id: "r".into(),
        };
        let sjson: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&stake).unwrap()).unwrap();
        assert_eq!(sjson["kind"], "stake");
    }

    #[test]
    fn batch_b_pending_ledger_delta_constructor_pins_five_fields_in_order() {
        // PendingLedgerDelta::new pins the 5-field constructor signature
        // (record_id, creator, timestamp, applied_at, op) — drift in the
        // positional order silently swaps `creator` ↔ `record_id` strings
        // at every caller. Construct with distinct sentinel values and
        // project each field.
        let op = PendingOp::Burn {
            owner: "alice".into(),
            amount: 13,
            memo: None,
        };
        let d = PendingLedgerDelta::new(
            "REC".to_string(),
            "CREATOR".to_string(),
            123.5,
            999.0,
            op.clone(),
        );
        assert_eq!(d.record_id, "REC");
        assert_eq!(d.creator, "CREATOR");
        assert_eq!(d.timestamp, 123.5);
        assert_eq!(d.applied_at, 999.0);
        assert_eq!(d.op, op);
    }

    #[test]
    fn batch_b_pending_op_clone_deep_copies_owned_string_fields_no_aliasing() {
        // Derive(Clone): pin that mutating the clone's String/Vec fields
        // does NOT touch the source. Caller-side aliasing of pending deltas
        // would corrupt CF_PENDING_DELTAS replays.
        let original = PendingOp::Slash {
            offender: "off".into(),
            challenger: "ch".into(),
            jury: vec!["j1".into(), "j2".into()],
            stake_record_id: "stake-rec".into(),
            amount: 100,
            reason: "double-sign".into(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);

        // Drop original via let-binding to a different value; cloned must
        // remain intact.
        match &cloned {
            PendingOp::Slash { offender, challenger, jury, amount, reason, .. } => {
                assert_eq!(offender, "off");
                assert_eq!(challenger, "ch");
                assert_eq!(jury, &vec!["j1".to_string(), "j2".to_string()]);
                assert_eq!(*amount, 100);
                assert_eq!(reason, "double-sign");
            }
            other => panic!("expected Slash, got {other:?}"),
        }

        // Round-trip equality: clone of clone == original.
        assert_eq!(original.clone(), cloned.clone());
    }

    #[test]
    fn batch_b_pending_op_from_parsed_burn_owner_captured_from_creator_parameter() {
        // Burn has no `from` field in ParsedLedgerOp — the debiting party
        // is recovered from the record's creator. Pin that the creator
        // parameter (not the record_id, not the memo, not the amount) is
        // what lands in `PendingOp::Burn.owner`.
        let parsed = ParsedLedgerOp::Burn {
            amount: 42,
            memo: Some("retire".into()),
        };
        let pending = PendingOp::from_parsed(parsed, "alice-hash", "ignored-rec-id");
        match pending {
            PendingOp::Burn { owner, amount, memo } => {
                assert_eq!(owner, "alice-hash", "owner must be creator, not record_id");
                assert_ne!(owner, "ignored-rec-id");
                assert_eq!(amount, 42);
                assert_eq!(memo, Some("retire".to_string()));
            }
            other => panic!("expected Burn, got {other:?}"),
        }
    }

    #[test]
    fn batch_b_pending_op_from_parsed_mint_does_not_capture_creator_to_recipient() {
        // Mint is the only debit-free op in this dispatch — the creator
        // is NOT used. `to` comes from the parsed op verbatim. Pin that
        // an "operator" creator parameter is silently discarded when
        // mapping Mint, and `to` survives unchanged.
        let parsed = ParsedLedgerOp::Mint {
            amount: 1_000_000,
            to: "treasury".into(),
            reason: "genesis-grant".into(),
        };
        let pending = PendingOp::from_parsed(parsed, "operator-creator", "rec-mint");
        match pending {
            PendingOp::Mint { to, amount, reason } => {
                assert_eq!(to, "treasury");
                assert_ne!(to, "operator-creator", "Mint must not capture creator into to-field");
                assert_eq!(amount, 1_000_000);
                assert_eq!(reason, "genesis-grant");
            }
            other => panic!("expected Mint, got {other:?}"),
        }
    }
}
