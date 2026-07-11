//! Emitter authorization for privileged protocol mutations.
//!
//! Privileged mutations (mint / witness_reward / slash / dormancy_reclaim / burn /
//! idle_decay) move money or change stake and are consensus-replicated: every node — and
//! every follower replaying the chain — must reach the SAME accept/reject for the same
//! record, or two honest nodes silently fork. Today exactly one identity, the
//! `genesis_authority`, may emit them.
//!
//! This module is the single seam through which the apply/validate path (`ledger.rs`,
//! `validate.rs`) makes that decision, so the rule lives in ONE place when it is later
//! generalized to an M-of-N validator quorum (the "S3" multi-validator stage). See
//! `docs/MULTI-VALIDATOR-EMITTER-AUTH.md` for the full design and the deferred M-of-N plan.
//!
//! DETERMINISM INVARIANT (do not violate when generalizing): authorization is a pure
//! function of (the actor identity, the genesis-pinned authority). It reads no balance,
//! no live stake, no finality state, no wall-clock, no per-node `#[serde(skip)]` tracker.
//! The authority is byte-identical on every node and immutable-since-genesis. Any future
//! mutable/rotating authority set MUST be epoch-scoped (look up the set sealed at the
//! record's apply epoch, never the current tip) or replay forks the instant it changes.

/// Returns `true` iff `actor` is authorized to emit a privileged protocol mutation.
///
/// Current model: a single authority. The body is exactly `actor == genesis_authority`,
/// so routing every gate through this function is behaviorally identical to the prior
/// inline string comparison — the seam is a no-op today (proven by the property test
/// below and by fresh-clone replay converging to the same account-state SMT root).
#[inline]
pub fn is_privileged_emitter(actor: &str, genesis_authority: &str) -> bool {
    actor == genesis_authority
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam is bit-identical to the old inline comparison: for ANY actor string,
    /// `is_privileged_emitter(actor, ga)` must equal `actor == ga`. This is the property
    /// that lets the ~23 gate substitutions be a provable no-op.
    #[test]
    fn is_privileged_emitter_is_exactly_string_equality() {
        let ga = "genesis_authority_hash_abc123";
        for actor in [
            ga,                              // the authority itself
            "genesis_authority_hash_abc124", // off by one
            "",                              // empty
            "some_other_node",               // unrelated
            "GENESIS_AUTHORITY_HASH_ABC123", // case differs
            "genesis_authority_hash_abc123 ",// trailing space
        ] {
            assert_eq!(
                is_privileged_emitter(actor, ga),
                actor == ga,
                "seam must equal raw string equality for actor={actor:?}"
            );
        }
    }

    #[test]
    fn authority_authorizes_itself_and_rejects_others() {
        assert!(is_privileged_emitter("auth", "auth"));
        assert!(!is_privileged_emitter("attacker", "auth"));
        assert!(!is_privileged_emitter("", "auth"));
    }
}
