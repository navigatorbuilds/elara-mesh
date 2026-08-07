--------------------------- MODULE MCRecurSafe ---------------------------
(* Cross-epoch liveness, SAFE baseline. A fully re-randomizing beacon: EVERY  *)
(* epoch-slot is locally viable (ViableEpochs = 0..2). The chain seals on its *)
(* fast committee path every epoch, forever. BeaconPeriod 3, escalation       *)
(* available (present but never needed — the local path always wins).         *)
(* RecurSealed HOLDS and RecurLocalSealed HOLDS.                              *)
EXTENDS LivenessRecurrence, TLC

MCViable == {0, 1, 2}
=============================================================================
