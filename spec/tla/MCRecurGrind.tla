--------------------------- MODULE MCRecurGrind ---------------------------
(* Cross-epoch liveness, GRINDABLE-BEACON break (the headline non-vacuity).   *)
(* The beacon does NOT re-randomize: the adversary pins the worst-case rank   *)
(* assignment EVERY epoch (ViableEpochs = {} — no epoch is locally viable).   *)
(* Escalation is available, so the chain STILL seals every epoch — but ONLY   *)
(* via cross-zone escalation, a permanent liveness DEGRADATION. RecurSealed   *)
(* HOLDS (escalation keeps the chain alive); RecurLocalSealed is VIOLATED     *)
(* (the fast local path never recurs). The violation proves the chained VRF   *)
(* beacon's re-randomization is load-bearing for staying on the fast path.    *)
(* BeaconPeriod 3, escalation available.                                      *)
EXTENDS LivenessRecurrence, TLC

MCViable == {}
=============================================================================
