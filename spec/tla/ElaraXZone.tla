----------------------------- MODULE ElaraXZone -----------------------------
(***************************************************************************)
(* TLA+ model of the Elara cross-zone settlement CONSERVATION core         *)
(* (Phase C — spec/tla/README.md, §4.3 NoAbortAndClaim row).                *)
(*                                                                         *)
(* The protocol's atomic-cross-zone-rollback claim: a sealed transfer is   *)
(* EITHER claimed in the destination zone OR aborted via a B-committee      *)
(* non-inclusion quorum — never both. Both outcomes would credit value     *)
(* twice (recipient credited in zone B AND sender refunded in zone A), so   *)
(* mutual exclusion is the load-bearing conservation property for the      *)
(* sealed-abort path (src/accounting/cross_zone.rs process_expired doc :751-756).*)
(*                                                                         *)
(* THE KEY INSIGHT (why this is a faithful specialization of Phase B):     *)
(* Both a global CLAIM and a global ABORT require a 2/3 quorum of zone B's  *)
(* committee.                                                              *)
(*   - "Claimed" globally = zone B's consensus sealed the recipient's      *)
(*     claim record; that sealing IS a 2/3 zone-B quorum (Phase B applied   *)
(*     to the claim record).                                              *)
(*   - "Aborted" globally = >=2/3 of zone B's committee signed an          *)
(*     XZoneAbort non-inclusion attestation ("we never claimed").          *)
(* An HONEST zone-B committee member that saw/sealed the claim will NOT     *)
(* sign the non-inclusion abort, and vice-versa — so an honest witness     *)
(* contributes to AT MOST ONE side. This is structurally identical to      *)
(* Phase B's "honest witness signs at most one of two conflicting records" *)
(* (ElaraConsensus.HonestFree), reframed as claim-side vs abort-side over   *)
(* zone B's committee.                                                     *)
(*                                                                         *)
(* REFINEMENT MAP (TLA+ <-> Rust, src/accounting/cross_zone.rs):                *)
(*   Quorum(S)        <-> the count-based 2/3 gate `n*3 >= size*2` shared by *)
(*                        verify_finality_quorum :1404 AND                  *)
(*                        verify_abort_quorum     :1523 (BOTH plain count,  *)
(*                        NOT diversity-weighted — so uniform "one witness  *)
(*                        = one vote" is EXACT here, unlike Phase B).       *)
(*   Claimed          <-> claim_transfer succeeds :464 (status -> Claimed)  *)
(*   Aborted          <-> abort_transfer succeeds :657 (status -> Aborted), *)
(*                        gated by verify_abort_quorum over the B2-anchored  *)
(*                        dest committee (XZONE-ABORT-FORGERY-FIX-2026-06-22)*)
(*   unsealedRefund   <-> cancel_transfer :590 / reject_transfer :699 /     *)
(*                        process_expired passive-24h — all UNSEALED-only.  *)
(*   SignClaim/Abort  <-> a zone-B committee member adding its attestation  *)
(*                        to the claim seal / the abort proof.             *)
(*                                                                         *)
(* ABSTRACTIONS (deliberate, documented — audited 2026-06-28):             *)
(*   - The honest "signs at most one side" rule is a BEHAVIORAL TRUST       *)
(*     ASSUMPTION, not a code-enforced check — exactly the epistemic        *)
(*     status of Phase B's HonestFree. The code relies on claim-record      *)
(*     propagation so an honest zone-B member that sealed a claim observes   *)
(*     the transfer is Claimed before the abort-signing loop selects it     *)
(*     (epoch.rs abort emitter filters status==Locked). Modeling it as an   *)
(*     honest invariant is the standard BFT idealization.                  *)
(*   - The zone-A seal-finality proof (verify_finality_quorum, a SEPARATE   *)
(*     zone-A committee) is folded into the `Sealed` precondition: it makes  *)
(*     the lock real and claimable but is not the claim-vs-abort CONFLICT,   *)
(*     which lives entirely on zone B's committee. claimAtt models zone B's  *)
(*     committee VIEW, not the zone-A finality signers.                     *)
(*   - `Sealed` is a non-reverting CONSTANT. The partition-merge seal-      *)
(*     DEMOTION conservation tail (docs/PARTITION-MERGE.md Gap D / the      *)
(*     unimplemented XZoneRevert, and the 30-day XZoneStaleReap path        *)
(*     cross_zone.rs:936) is a SUPPLY-conservation break (a non-canonical   *)
(*     debit), expressible only with `amount`/`total_locked` — that is      *)
(*     Phase D (§4.4 SupplyInvariant), NOT this claim/abort mutual-         *)
(*     exclusion model. See README "Not yet modelled".                     *)
(*   - A SINGLE transfer is modeled; transfer_id keys are independent, so   *)
(*     per-transfer mutual exclusion composes (the cross-transfer aggregate *)
(*     supply invariant is Phase D).                                       *)
(*   - Legacy/pre-B2 locks (dest_finality_committee = None) CANNOT be       *)
(*     aborted (verify_abort_quorum :1479 fail-closed) — strictly safer     *)
(*     (one fewer terminal). Modeling the anchored case (abort POSSIBLE) is  *)
(*     the conservative worst case for proving mutual exclusion.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Witnesses,    \* zone B's finality committee (the conflict-relevant committee)
    Byzantine,    \* SUBSET Witnesses : may sign BOTH claim-side and abort-side
    Sealed        \* BOOLEAN : is the lock sealed+final in zone A? (scenario param)

Honest == Witnesses \ Byzantine

(***************************************************************************)
(* State.                                                                  *)
(*   claimAtt       : zone-B witnesses contributing to the claim seal       *)
(*   abortAtt       : zone-B witnesses contributing to the abort proof       *)
(*   unsealedRefund : an UNSEALED-path refund fired (cancel/reject/passive) *)
(***************************************************************************)
VARIABLES claimAtt, abortAtt, unsealedRefund
vars == << claimAtt, abortAtt, unsealedRefund >>

TypeOK ==
    /\ claimAtt \in SUBSET Witnesses
    /\ abortAtt \in SUBSET Witnesses
    /\ unsealedRefund \in BOOLEAN

(***************************************************************************)
(* Count-based 2/3 quorum — mirrors BOTH verify_finality_quorum :1404 and  *)
(* verify_abort_quorum :1523:  `n.saturating_mul(3) < denom.saturating_mul *)
(* (2)` rejects, i.e. accept iff  3*|S| >= 2*|committee|.                   *)
(***************************************************************************)
Quorum(S) == Cardinality(S) * 3 >= Cardinality(Witnesses) * 2

\* A claim/abort is GLOBALLY effective only when the lock is sealed AND the
\* zone-B committee reached 2/3 on that side.
Claimed == Sealed /\ Quorum(claimAtt)
Aborted == Sealed /\ Quorum(abortAtt)

(***************************************************************************)
(* State machine.                                                          *)
(***************************************************************************)
Init ==
    /\ claimAtt = {}
    /\ abortAtt = {}
    /\ unsealedRefund = FALSE

\* A zone-B witness contributes to the claim seal. Enabled only on a sealed
\* transfer (claim requires seal — M7 gate, claim_transfer :428). An HONEST
\* witness will not also be on the abort side (the at-most-one-side trust
\* assumption); a Byzantine witness has no such constraint.
SignClaim(w) ==
    /\ Sealed
    /\ w \notin claimAtt
    /\ (w \in Honest => w \notin abortAtt)
    /\ claimAtt' = claimAtt \cup {w}
    /\ UNCHANGED << abortAtt, unsealedRefund >>

\* Symmetric: a zone-B witness signs the non-inclusion abort attestation.
\* Sealed-only (abort_transfer :650). Honest witnesses do not also seal the claim.
SignAbort(w) ==
    /\ Sealed
    /\ w \notin abortAtt
    /\ (w \in Honest => w \notin claimAtt)
    /\ abortAtt' = abortAtt \cup {w}
    /\ UNCHANGED << claimAtt, unsealedRefund >>

\* The UNSEALED refund paths (cancel/reject/passive-24h) collapse to one
\* action — all three require `merkle_proof.is_empty()` (cancel :581,
\* reject :690, process_expired skips sealed). Disabled once a lock is sealed.
Refund ==
    /\ ~Sealed
    /\ ~unsealedRefund
    /\ unsealedRefund' = TRUE
    /\ UNCHANGED << claimAtt, abortAtt >>

Next ==
    \/ \E w \in Witnesses : SignClaim(w) \/ SignAbort(w)
    \/ Refund

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

\* 4.3 NoAbortAndClaim (the headline cross-zone conservation property):
\* a transfer is never both claimed in zone B and aborted in zone A. Holds
\* iff Byzantine zone-B stake stays below 1/3 (n = 3f+1). The quorum-
\* intersection argument: two 2/3-quorums of an n-member committee share
\* >= 2*ceil(2n/3) - n members; for f < n/3 at least one is honest, and an
\* honest witness signs at most one side — contradiction.
NoAbortAndClaim == ~(Claimed /\ Aborted)

\* Structural seal-gate soundness (Byzantine-INDEPENDENT, like Phase B's
\* DiversitySoundness): claim/abort require a sealed lock; the unsealed-refund
\* paths require an UNSEALED lock. This is the code-path partition that makes
\* the "passive refund races a claim" double-credit impossible WITHOUT any BFT
\* assumption. Holds in EVERY config, including the broken one.
SealGateSound ==
    /\ (Claimed => Sealed)
    /\ (Aborted => Sealed)
    /\ (unsealedRefund => ~Sealed)
=============================================================================
