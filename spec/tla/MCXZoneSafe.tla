----------------------------- MODULE MCXZoneSafe -----------------------------
(* Cross-zone sealed-abort safety. n = 5, f = 1 (Byzantine < 1/3), sealed   *)
(* transfer. Both NoAbortAndClaim and SealGateSound HOLD: the zone-B         *)
(* committee cannot reach a 2/3 quorum on BOTH the claim seal and the abort  *)
(* proof while honest witnesses each sign at most one side.                  *)
EXTENDS ElaraXZone, TLC

MCWit    == {"w1", "w2", "w3", "w4", "w5"}
MCByz    == {"w5"}
MCSealed == TRUE
=============================================================================
