-------------------------- MODULE MCRecurLadder --------------------------
(* Cross-epoch liveness, LADDER scenario — the direct machine-check of        *)
(* "the adversary cannot SUSTAIN a worst-case rank assignment." The beacon    *)
(* rotates a PERIODIC worst-case epoch: slot 0 is non-viable (the adversary's *)
(* corrupted identity captured every eligible rank that epoch), slots 1 and 2 *)
(* viable. The re-randomization always cycles an honest identity back into an *)
(* eligible rank, so the worst case cannot persist. Escalation covers the     *)
(* lone non-viable epoch; the fast local path still recurs 2 of every 3.      *)
(* BeaconPeriod 3, escalation available. RecurSealed HOLDS, RecurLocalSealed  *)
(* HOLDS.                                                                     *)
EXTENDS LivenessRecurrence, TLC

MCViable == {1, 2}
=============================================================================
