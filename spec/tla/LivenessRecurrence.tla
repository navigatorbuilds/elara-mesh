------------------------ MODULE LivenessRecurrence ------------------------
(***************************************************************************)
(* TLA+ CROSS-EPOCH LIVENESS model — "Phase E.3" of                         *)
(* spec/tla/README.md. The complement to Phase E.2                          *)
(* (Liveness.tla), which proves a SINGLE epoch eventually PRODUCES its seal. *)
(* This proves the CHAIN keeps producing seals FOREVER ([]<>sealed) and that *)
(* it stays on its FAST local path forever ([]<>local-sealed) — the          *)
(* documented future extension the Liveness.tla header (lines 74-84) defers. *)
(*                                                                         *)
(* THE MECHANISM UNDER TEST: the CHAINED VRF BEACON                         *)
(* chained_beacon(prev_seal_hash, epoch, zone) (aggregator.rs:310). The      *)
(* proposer rank ladder is re-derived every epoch off the PREVIOUS epoch's   *)
(* seal hash. Because that hash is not known until the previous epoch seals  *)
(* (and is honest-influenced), the adversary cannot PREDICT or STEER which   *)
(* identities land in eligible ranks next epoch — so it cannot GRIND or      *)
(* SUSTAIN a worst-case rank assignment across epochs. Liveness.tla bounds    *)
(* the worst SINGLE epoch; this model proves the worst case cannot RECUR     *)
(* indefinitely under a re-randomizing beacon, and FAILS (non-vacuously)     *)
(* under a grindable / adversary-pinned beacon.                             *)
(*                                                                         *)
(* FAITHFUL ABSTRACTION OF THE BEACON. Per epoch, the only liveness-relevant *)
(* fact about the rank assignment is whether the LOCAL committee path is      *)
(* VIABLE: does some honest identity land in an eligible rank with >= 2/3     *)
(* honest attesting stake (Liveness.tla's LiveLocal precondition)?  We model  *)
(* that single bit as `LocalViable == epoch \in ViableEpochs`, with `epoch`   *)
(* a counter that WRAPS mod BeaconPeriod — so ViableEpochs is the beacon's    *)
(* COVERAGE pattern over one rotation period, and it is a CONSTANT the        *)
(* adversary does NOT choose (it is the hash output, not an adversary move).  *)
(*   - A re-randomizing beacon => ViableEpochs is large and recurs           *)
(*     (MCRecurSafe: every slot; MCRecurLadder: 2 of every 3 — the adversary  *)
(*     captures rank-0 periodically but the rotation always cycles an honest  *)
(*     identity back into an eligible rank).                                 *)
(*   - A grindable / pinned beacon => ViableEpochs = {} (the adversary fixes  *)
(*     the worst-case assignment every epoch: MCRecurGrind / MCRecurGrindStall*)
(* A deterministic wrapping counter is the canonical adversary-INDEPENDENT    *)
(* witness of "coverage that recurs"; modelling the choice as a fair          *)
(* non-deterministic action would be WRONG (TLA+ weak fairness does NOT force *)
(* a fair resolution of a non-deterministic existential, so worst-case-       *)
(* forever would be an admitted behaviour — the very thing the beacon rules   *)
(* out). The grindable twin (ViableEpochs={}) IS that worst-case-forever, and *)
(* its property violation is what proves the re-randomization is load-bearing.*)
(*                                                                         *)
(* COMPOSITION, NOT RE-DERIVATION. Phase E.2 already machine-checked the      *)
(* PER-EPOCH sealing conditions (local GST necessity, honest >= 2/3, the      *)
(* escalation reduction, the bootstrap freeze trap). Phase E.3 TAKES those    *)
(* as established and isolates the CROSS-EPOCH beacon dimension: `LocalViable` *)
(* folds in "local GST + honest 2/3 + an eligible honest rank"; the           *)
(* escalation backstop folds "global GST + global f < 1/3" into the boolean   *)
(* `EscalationAvailable`. We do NOT re-expand the witness-by-witness          *)
(* attestation here — that is Liveness.tla's job, and re-deriving it would    *)
(* only multiply the state space without adding a NEW guarantee.             *)
(*                                                                         *)
(* THE TWO PROPERTIES (mirroring Phase E.2's LiveLocal / LiveWithEscalation): *)
(*   RecurSealed      == []<>sealed         — the chain PERPETUALLY seals.    *)
(*       Holds whenever every epoch seals by SOME path (local when viable,    *)
(*       escalation otherwise). FAILS only if a worst-case epoch recurs with  *)
(*       NO escalation floor (MCRecurGrindStall) — the cross-epoch statement  *)
(*       of Phase E.2's no-quorum-free-floor asymmetry.                       *)
(*   RecurLocalSealed == []<>(sealed local) — the FAST local path RECURS.     *)
(*       Holds iff LocalViable recurs (a re-randomizing beacon). FAILS under  *)
(*       a grindable beacon (MCRecurGrind): the chain still seals, but ONLY   *)
(*       via escalation forever — a permanent liveness DEGRADATION. This is   *)
(*       the headline contribution: it machine-checks that the chained VRF    *)
(*       beacon is what keeps the protocol on its fast path.                  *)
(*                                                                         *)
(* ESCALATION GATING (faithful timing). EscalSeal is gated on ~LocalViable:   *)
(* escalation fires only when the local committee CANNOT seal this epoch.     *)
(* This is faithful to is_zone_stuck (aggregator.rs:224): escalation unlocks  *)
(* only after the WHOLE ladder times out (elapsed > (2^7-1)*base), whereas an *)
(* eligible honest rank seals at a far earlier elapsed — so in a viable epoch *)
(* the local seal always beats escalation. Gating on ~LocalViable models that *)
(* ordering exactly and avoids a spurious cross-epoch race in which a viable  *)
(* epoch could be "stolen" by escalation.                                    *)
(*                                                                         *)
(* DAG / STUTTER NOTE (identical to Phase E.2). The per-epoch sub-machine is  *)
(* monotone (phase climbs, seal latches) but the epoch counter WRAPS, so the  *)
(* whole behaviour is genuinely cyclic — exactly what a []<> recurrence check *)
(* needs. `Stutter == UNCHANGED vars` (unfair) guarantees every state has a    *)
(* successor; per-action WF forces real progress, and NextEpoch (WF) is the   *)
(* recurrence engine that re-randomizes the beacon and resets the epoch. No   *)
(* fairness on Stutter, so a grindable-stall behaviour that can only stutter  *)
(* (MCRecurGrindStall) is an admitted fair lasso that violates RecurSealed.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    BeaconPeriod,        \* Nat >= 1 : the beacon's rotation period (epoch wraps mod this)
    ViableEpochs,        \* SUBSET 0..BeaconPeriod-1 : epoch-slots where the LOCAL committee
                         \*   path is viable (an honest identity in an eligible rank, honest
                         \*   attesting stake >= 2/3). The beacon's coverage pattern; the
                         \*   adversary does NOT choose it. {} = a grindable / pinned beacon.
    EscalationAvailable  \* BOOLEAN : is the cross-zone escalation backstop in scope AND
                         \*   globally healthy (global GST + global f < 1/3)?  FALSE = no floor.

Epochs == 0..(BeaconPeriod - 1)

VARIABLES
    epoch,        \* the beacon clock, 0..BeaconPeriod-1, WRAPS — re-randomizes the ranks
    phase,        \* within-epoch ladder latch 0..2 (0=fast window, 1=climbing, 2=exhausted)
    epochSealed,  \* the CURRENT epoch produced its seal
    escalated     \* the current epoch's seal came via cross-zone escalation (not the committee)

vars == << epoch, phase, epochSealed, escalated >>

\* The beacon's verdict for THIS epoch: is the local committee path viable?
LocalViable == epoch \in ViableEpochs

\* A locally-sealed state — the fast committee path, not escalation.
LocalSealedNow == epochSealed /\ ~escalated

TypeOK ==
    /\ epoch \in Epochs
    /\ phase \in 0..2
    /\ epochSealed \in BOOLEAN
    /\ escalated \in BOOLEAN

Init ==
    /\ epoch = 0
    /\ phase = 0
    /\ epochSealed = FALSE
    /\ escalated = FALSE

(***************************************************************************)
(* Within-epoch: the rank ladder climbs by elapsed time until exhausted     *)
(* (phase 2). Faithful order-preserving collapse of the (2^k-1)*base ladder. *)
(***************************************************************************)
Climb ==
    /\ phase < 2
    /\ ~epochSealed
    /\ phase' = phase + 1
    /\ UNCHANGED << epoch, epochSealed, escalated >>

(***************************************************************************)
(* Local committee seal — enabled iff the beacon made the local path viable  *)
(* this epoch. Folds Phase E.2's proven LiveLocal precondition into one bit.  *)
(***************************************************************************)
LocalSeal ==
    /\ ~epochSealed
    /\ LocalViable
    /\ epochSealed' = TRUE
    /\ escalated' = FALSE
    /\ UNCHANGED << epoch, phase >>

(***************************************************************************)
(* Cross-zone escalation seal — the fallback for a NON-viable epoch, after    *)
(* the local ladder is exhausted, iff the backstop is in scope + healthy.     *)
(* Gated on ~LocalViable (faithful timing: a viable epoch seals locally far   *)
(* earlier than the whole ladder times out — see ESCALATION GATING note).     *)
(***************************************************************************)
EscalSeal ==
    /\ ~epochSealed
    /\ EscalationAvailable
    /\ ~LocalViable
    /\ phase = 2
    /\ epochSealed' = TRUE
    /\ escalated' = TRUE
    /\ UNCHANGED << epoch, phase >>

(***************************************************************************)
(* The chained VRF beacon advances. Once the epoch sealed, the chain moves to *)
(* the next epoch; `epoch` WRAPS, so a different ViableEpochs slot governs —   *)
(* the re-randomization. This per-epoch reset is the recurrence engine.       *)
(***************************************************************************)
NextEpoch ==
    /\ epochSealed
    /\ epoch' = (epoch + 1) % BeaconPeriod
    /\ phase' = 0
    /\ epochSealed' = FALSE
    /\ escalated' = FALSE

\* Unconditional self-loop — see DAG/STUTTER NOTE in the header.
Stutter == UNCHANGED vars

Next ==
    \/ Climb \/ LocalSeal \/ EscalSeal \/ NextEpoch \/ Stutter

(***************************************************************************)
(* Fairness. Per-action WF on every progress action (never WF_vars(Next),     *)
(* which Stutter satisfies vacuously). NO fairness on Stutter — so a worst-    *)
(* case epoch with no escalation floor may stutter forever (the stall lasso).  *)
(***************************************************************************)
Fairness ==
    /\ WF_vars(Climb)
    /\ WF_vars(LocalSeal)
    /\ WF_vars(EscalSeal)
    /\ WF_vars(NextEpoch)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Cross-epoch liveness properties (bare-variable leaves per the Phase E.2    *)
(* TLC note). Checked one per model invocation.                              *)
(***************************************************************************)
RecurSealed      == []<>epochSealed       \* the chain perpetually seals (never permanent stall)
RecurLocalSealed == []<>LocalSealedNow    \* the fast local path recurs (no permanent escalation-degradation)

(* Cheap sanity invariants (must always hold). *)
EscalImpliesSealed == escalated => epochSealed
LadderBeforeEscal  == escalated => (phase >= 2)
=============================================================================
