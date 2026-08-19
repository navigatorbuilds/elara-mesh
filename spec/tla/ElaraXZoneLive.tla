--------------------------- MODULE ElaraXZoneLive ---------------------------
(***************************************************************************)
(* TLA+ LIVENESS model of the Elara cross-zone settlement core             *)
(* (Phase E — spec/tla/README.md — the temporal DUAL of the                 *)
(* Phase C safety property NoAbortAndClaim).                               *)
(*                                                                         *)
(* Phase C proved a sealed transfer is NEVER BOTH claimed and aborted.     *)
(* Phase E proves the complementary LIVENESS fact: a sealed transfer is    *)
(* never STUCK in-flight forever — it eventually reaches a terminal state. *)
(* This is the formal companion to the OPS-56 gauge                         *)
(* `elara_xzone_sealed_locked_past_expiry_count` (cross_zone.rs:973), which *)
(* exists precisely to detect stuck-sealed transfers.                      *)
(*                                                                         *)
(* TWO DISCRIMINATING THEOREMS (the design's teeth):                       *)
(*                                                                         *)
(*   LiveFast == Sealed ~> (Claimed \/ Aborted)                            *)
(*     The FAST path. Holds ONLY with a live >= 2/3-honest zone-B          *)
(*     committee AND partial synchrony (GST). It FAILS (and TLC produces a  *)
(*     real lasso) when synchrony never arrives (MCXZoneLiveNoGST) or when  *)
(*     Byzantine stake reaches 1/3 so the honest remainder cannot form a    *)
(*     2/3 quorum (MCXZoneLiveByzStall). This is the liveness DUAL of the   *)
(*     Phase C safety bound: safety needs f < 1/3 so Byzantine cannot forge *)
(*     TWO quorums; liveness needs f < 1/3 so the honest CAN form ONE.      *)
(*                                                                         *)
(*   LiveBackstop == Sealed ~> Terminal     (Terminal includes Refunded)   *)
(*     The UNCONDITIONAL guarantee. Holds in EVERY scenario — even with no  *)
(*     GST and even at f = 2 — because the quorum-FREE 30-day stale-reap    *)
(*     (REAP_HORIZON_SECS, compute_stale_reap_batch / apply_reap_batch      *)
(*     cross_zone.rs:903/936) eventually refunds the lock. The code is      *)
(*     explicit that without a quorum a sealed transfer "stays Locked       *)
(*     indefinitely" (epoch.rs:5805, cross_zone.rs:768) — so the real       *)
(*     never-stuck-FOREVER guarantee is the reaper, bounding the stuck      *)
(*     window at ~30 days, NOT the abort quorum. Omitting the reaper would  *)
(*     model a path the code treats as best-effort while ignoring the path  *)
(*     the code actually relies on; LiveBackstop closes that gap.           *)
(*                                                                         *)
(*   The discrimination is the point: every break model breaks LiveFast for *)
(*   a DIFFERENT reason while LiveBackstop survives in all of them —        *)
(*   "Byzantine/asynchrony can deny the fast path but cannot deny eventual  *)
(*   reap."                                                                 *)
(*                                                                         *)
(* PARTIAL SYNCHRONY / FLP. Under full asynchrony deterministic BFT         *)
(* liveness is impossible (FLP). So LiveFast is conditioned on a Global     *)
(* Stabilization Time: `gst` is a monotone latch set by `ReachGST`, and     *)
(* honest convergence actions are gst-gated. MCXZoneLiveNoGST sets          *)
(* GstReachable = FALSE (gst never latches), and LiveFast then genuinely    *)
(* fails — the FLP-respecting break.                                        *)
(*                                                                         *)
(* CONVERGENCE IS EARNED, NOT ASSUMED. There is NO global "everyone agrees  *)
(* which side" oracle. Each honest witness has its OWN local view           *)
(* `view[w] \in {Unseen, SawClaim, PastTimeout}`, resolved only AFTER gst   *)
(* by the per-witness actions `DeliverClaim(w)` / `Timeout(w)` (each        *)
(* carrying weak fairness — they MODEL claim-gossip delivery as a           *)
(* discharged WF obligation, not an axiom). An honest witness signs the     *)
(* side ITS view dictates. Pre-gst no view resolves, so honest cannot       *)
(* converge — exactly the partial-synchrony premise.                       *)
(*                                                                         *)
(* REFINEMENT MAP (TLA+ <-> Rust, src/accounting/cross_zone.rs + epoch.rs):     *)
(*   Quorum(S)        <-> count-based 2/3 gate shared by verify_finality_   *)
(*                        quorum:1404 and verify_abort_quorum:1523.         *)
(*   Claimed/Aborted  <-> claim_transfer:464 / abort_transfer:657.         *)
(*   view + Deliver/  <-> a zone-B committee member's LOCAL ledger status   *)
(*     Timeout            for the transfer (Claimed once claim gossip       *)
(*                        applies; abort-eligible once `now > expires_at`,  *)
(*                        pending_abort_candidates:740 / emitter            *)
(*                        epoch.rs:5828). gst abstracts gossip delivery.    *)
(*   SignClaim/Abort  <-> a committee member adding its attestation.        *)
(*   ExpireWindow     <-> wall clock passing expires_at (CLAIM_TIMEOUT_SECS,*)
(*                        cross_zone.rs:29). NOT gst-gated (time elapses     *)
(*                        regardless of synchrony).                         *)
(*   ReapWindow/Reap  <-> the 30-day stale-reap, quorum-free, gated on      *)
(*                        expires_at + REAP_HORIZON_SECS (cross_zone.rs:40).*)
(*                        NOT gst-gated — this is why LiveBackstop holds     *)
(*                        even with no GST.                                  *)
(*   refunded/Refunded<-> apply_reap_batch:943 status -> Refunded (the      *)
(*                        SEALED 30-day reap terminal; the unsealed         *)
(*                        passive-24h refund path is out of scope here).    *)
(*                                                                         *)
(* FIDELITY of the fairness (honest-claims, audited 2026-06-28): honest WF  *)
(* abstracts the BEST-EFFORT retry-on-next-tick emitter (epoch.rs:5808 uses *)
(* try_read/try_lock and "re-attempts on the next tick"), which under a     *)
(* fair scheduler eventually wins its locks — NOT a "deterministic per-tick *)
(* emission". Non-seal-eligible committee members rely on gossip relay      *)
(* rather than self-emission; the model abstracts both as the per-honest    *)
(* WF obligation. The Reap `~Claimed /\ ~Aborted` guard abstracts the code's*)
(* TIME separation (claim impossible past expires_at; reap only past        *)
(* expires_at + 30d) plus the apply_reap_batch:940 Locked-status re-check — *)
(* it is the same reap/claim-exclusion device as Conservation.tla.         *)
(*                                                                         *)
(* EXPLICITLY OUT OF SCOPE (deferred; NOT covered by either theorem):      *)
(*   - In-zone proposer/leader liveness (the precondition that the source   *)
(*     zone SEALS the lock at all). These specs have no leader/view/round;  *)
(*     that is a DIFFERENT model — Phase E.2 — not an increment here.       *)
(*   - Message-level delivery bounds (GST is abstracted to a flag).        *)
(*   - The unsealed (pre-seal) refund path liveness.                       *)
(*                                                                         *)
(* DAG / STUTTER NOTE. The Phase C-style state machine is monotone-growth   *)
(* (sets only grow, booleans only latch) so it TERMINATES; a `~>`/`<>`      *)
(* check needs an infinite behaviour to be non-vacuous. `Stutter ==         *)
(* UNCHANGED vars` is an explicit unconditional self-loop guaranteeing      *)
(* every state has a successor, so TLC evaluates the temporal property over *)
(* genuinely infinite behaviours regardless of the -deadlock flag, while    *)
(* per-action WF still forces real progress on every fair behaviour (the    *)
(* stutter-forever behaviours are unfair and excluded).                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Witnesses,     \* zone B's finality committee (the conflict-relevant committee)
    Byzantine,     \* SUBSET Witnesses : may equivocate; never fair
    GstReachable,  \* BOOLEAN : does GST ever arrive? (FALSE in MCXZoneLiveNoGST)
    ByzMaySign,    \* BOOLEAN : may Byzantine witnesses attest? (FALSE in ByzStall)
    ModelReap      \* BOOLEAN : is the 30-day reap backstop in scope? (TRUE for LiveBackstop)

Honest == Witnesses \ Byzantine

\* All live models concern an ALREADY-sealed transfer (post-seal lifecycle);
\* in-zone seal liveness is Phase E.2, out of scope. Sealed is therefore TRUE.
Sealed == TRUE

(***************************************************************************)
(* State.                                                                  *)
(*   claimAtt/abortAtt : zone-B witnesses on each side (monotone, Phase C)  *)
(*   view              : each honest witness's LOCAL observation            *)
(*   claimGossiped     : scenario branch (chosen in Init): did a claim      *)
(*                       propagate? TRUE -> honest converge claim; FALSE -> *)
(*                       converge abort after expiry. Constant per behaviour.*)
(*   refunded          : the quorum-free reap terminal fired                *)
(*   gst,pastExpiry,pastReap : monotone synchrony/time latches              *)
(***************************************************************************)
VARIABLES claimAtt, abortAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap
vars == << claimAtt, abortAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap >>

ViewVals == { "Unseen", "SawClaim", "PastTimeout" }

TypeOK ==
    /\ claimAtt \in SUBSET Witnesses
    /\ abortAtt \in SUBSET Witnesses
    /\ view \in [Honest -> ViewVals]
    /\ claimGossiped \in BOOLEAN
    /\ refunded \in BOOLEAN
    /\ gst \in BOOLEAN
    /\ pastExpiry \in BOOLEAN
    /\ pastReap \in BOOLEAN

\* Count-based 2/3 quorum — identical to Phase C / verify_*_quorum.
Quorum(S) == Cardinality(S) * 3 >= Cardinality(Witnesses) * 2

Claimed  == Sealed /\ Quorum(claimAtt)
Aborted  == Sealed /\ Quorum(abortAtt)
Refunded == refunded
Terminal == Claimed \/ Aborted \/ Refunded

(***************************************************************************)
(* Initial state.                                                          *)
(***************************************************************************)
Init ==
    /\ claimAtt = {}
    /\ abortAtt = {}
    /\ view = [w \in Honest |-> "Unseen"]
    /\ claimGossiped \in BOOLEAN          \* nondeterministic branch; constant after
    /\ refunded = FALSE
    /\ gst = FALSE
    /\ pastExpiry = FALSE
    /\ pastReap = FALSE

(***************************************************************************)
(* Synchrony / time latches (monotone). gst is gated on GstReachable so    *)
(* MCXZoneLiveNoGST keeps it FALSE forever. ExpireWindow/ReapWindow/Reap    *)
(* are NOT gst-gated — wall-clock time and the reaper proceed regardless of *)
(* synchrony, which is why LiveBackstop survives no-GST.                    *)
(***************************************************************************)
ReachGST ==
    /\ GstReachable /\ ~gst
    /\ gst' = TRUE
    /\ UNCHANGED << claimAtt, abortAtt, view, claimGossiped, refunded, pastExpiry, pastReap >>

ExpireWindow ==
    /\ ~pastExpiry
    /\ pastExpiry' = TRUE
    /\ UNCHANGED << claimAtt, abortAtt, view, claimGossiped, refunded, gst, pastReap >>

ReapWindow ==
    /\ ModelReap /\ pastExpiry /\ ~pastReap
    /\ pastReap' = TRUE
    /\ UNCHANGED << claimAtt, abortAtt, view, claimGossiped, refunded, gst, pastExpiry >>

(***************************************************************************)
(* Per-honest-witness convergence — gossip delivery as a WF obligation.    *)
(* Resolves only AFTER gst (partial synchrony). The claim branch needs      *)
(* claimGossiped; the timeout branch needs ~claimGossiped AND pastExpiry    *)
(* (abort is post-expiry-gated, pending_abort_candidates:740).             *)
(***************************************************************************)
DeliverClaim(w) ==
    /\ w \in Honest /\ gst /\ claimGossiped /\ view[w] = "Unseen"
    /\ view' = [view EXCEPT ![w] = "SawClaim"]
    /\ UNCHANGED << claimAtt, abortAtt, claimGossiped, refunded, gst, pastExpiry, pastReap >>

Timeout(w) ==
    /\ w \in Honest /\ gst /\ pastExpiry /\ ~claimGossiped /\ view[w] = "Unseen"
    /\ view' = [view EXCEPT ![w] = "PastTimeout"]
    /\ UNCHANGED << claimAtt, abortAtt, claimGossiped, refunded, gst, pastExpiry, pastReap >>

\* Honest signs the side ITS OWN view dictates (at-most-one-side guard kept
\* from Phase C, here belt-and-suspenders since a view resolves to one side).
\* The `~refunded` guard mirrors the code: a reaped transfer has left `Locked`
\* (status -> Refunded), so claim/abort signing can no longer progress it. This
\* makes reap/claim exclusion BIDIRECTIONAL (Reap requires ~Claimed/~Aborted;
\* signing requires ~refunded), so ConserveExcl holds even under the reap race.
SignClaim(w) ==
    /\ w \in Honest /\ view[w] = "SawClaim" /\ ~refunded
    /\ w \notin claimAtt /\ w \notin abortAtt
    /\ claimAtt' = claimAtt \cup {w}
    /\ UNCHANGED << abortAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap >>

SignAbort(w) ==
    /\ w \in Honest /\ view[w] = "PastTimeout" /\ ~refunded
    /\ w \notin abortAtt /\ w \notin claimAtt
    /\ abortAtt' = abortAtt \cup {w}
    /\ UNCHANGED << claimAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap >>

(***************************************************************************)
(* Byzantine attestation — may equivocate (both sides), NEVER fair.        *)
(* Removed entirely in MCXZoneLiveByzStall (ByzMaySign = FALSE) so the      *)
(* break unambiguously proves the honest remainder ALONE cannot reach a     *)
(* 2/3 quorum — Byzantine cooperation is not relied upon.                  *)
(***************************************************************************)
\* `~refunded` gates Byzantine signing too: the ledger's status==Locked apply
\* check (apply_reap_batch:940) rejects ANY claim/abort record once the lock is
\* reaped, regardless of who submits it — so a Byzantine post-reap signature
\* cannot push a side to quorum. This makes reap/claim exclusion hold against
\* the adversary, not just honest racers.
ByzSignClaim(w) ==
    /\ ByzMaySign /\ w \in Byzantine /\ ~refunded /\ w \notin claimAtt
    /\ claimAtt' = claimAtt \cup {w}
    /\ UNCHANGED << abortAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap >>

ByzSignAbort(w) ==
    /\ ByzMaySign /\ w \in Byzantine /\ ~refunded /\ w \notin abortAtt
    /\ abortAtt' = abortAtt \cup {w}
    /\ UNCHANGED << claimAtt, view, claimGossiped, refunded, gst, pastExpiry, pastReap >>

(***************************************************************************)
(* The 30-day stale-reap backstop — quorum-FREE. Guarded ~Claimed/~Aborted *)
(* (reap/claim exclusion, abstracting the code's time-separation +         *)
(* Locked-status re-check). Only in scope when ModelReap.                   *)
(***************************************************************************)
Reap ==
    /\ ModelReap /\ pastReap /\ ~Claimed /\ ~Aborted /\ ~refunded
    /\ refunded' = TRUE
    /\ UNCHANGED << claimAtt, abortAtt, view, claimGossiped, gst, pastExpiry, pastReap >>

\* Explicit unconditional self-loop — see DAG/STUTTER NOTE in the header.
Stutter == UNCHANGED vars

Next ==
    \/ ReachGST \/ ExpireWindow \/ ReapWindow \/ Reap
    \/ \E w \in Honest    : DeliverClaim(w) \/ Timeout(w) \/ SignClaim(w) \/ SignAbort(w)
    \/ \E w \in Byzantine : ByzSignClaim(w) \/ ByzSignAbort(w)
    \/ Stutter

(***************************************************************************)
(* Fairness. Per-action WF on every PROGRESS action (never WF_vars(Next),   *)
(* which the Stutter disjunct would satisfy vacuously). NO fairness on the  *)
(* Byzantine actions (the adversary may withhold) and NONE on Stutter.      *)
(***************************************************************************)
Fairness ==
    /\ WF_vars(ReachGST)
    /\ WF_vars(ExpireWindow)
    /\ WF_vars(ReapWindow)
    /\ WF_vars(Reap)
    /\ \A w \in Honest :
          /\ WF_vars(DeliverClaim(w))
          /\ WF_vars(Timeout(w))
          /\ WF_vars(SignClaim(w))
          /\ WF_vars(SignAbort(w))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Liveness properties (checked one per model invocation — TLC stops at the *)
(* first temporal violation, so LiveFast and LiveBackstop are run           *)
(* separately so the expected outcome is per-property unambiguous).         *)
(***************************************************************************)
\* The transfer is sealed-and-locked from Init (Sealed == TRUE), and Claimed /
\* Aborted / Refunded are all STABLE (sets only grow, refunded latches), so `<>P`
\* ("eventually a terminal") is the faithful form of "a sealed transfer reaches P".
\*
\* FastTerminal = the COMMITTEE fast path: Claimed or Aborted, reached WITHOUT
\* falling back to the reap backstop (`~refunded`). LiveFast is only checked with
\* reap OFF (ModelReap = FALSE), where refunded == FALSE identically, so the
\* `~refunded` conjunct is inert there and FastTerminal == Claimed \/ Aborted.
\* It is retained because it (a) names the precise notion of "fast" (settled by
\* the committee, not the 30-day reaper) and (b) gives the temporal predicate a
\* directly-referenced variable: TLC's liveness checker mis-levels a `<>`/`~>`
\* predicate built ONLY from parameterized operator-applications
\* (`Quorum(claimAtt) \/ Quorum(abortAtt)`) — it raises "claimAtt undefined" —
\* whereas the same predicate with a bare-variable leaf evaluates cleanly (this
\* is also why LiveBackstop's `<>Terminal`, which carries the bare `refunded`
\* disjunct, never tripped it).
FastTerminal == (Claimed \/ Aborted) /\ ~refunded
LiveFast     == <>FastTerminal
LiveBackstop == <>Terminal

\* Carried Phase C / Phase D sanity invariants (cheap, must always hold):
SafetyStillHolds == ~(Claimed /\ Aborted)
ConserveExcl     == ~(refunded /\ (Claimed \/ Aborted))
ReapAfterExpiry  == pastReap => pastExpiry
=============================================================================
