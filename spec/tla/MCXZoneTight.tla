----------------------------- MODULE MCXZoneTight -----------------------------
(* Byzantine-bound TIGHTNESS, safe side. n = 4, f = 1 = floor((n-1)/3), the  *)
(* exact n = 3f+1 boundary, sealed transfer. NoAbortAndClaim STILL HOLDS at   *)
(* the bound: reaching a 2/3 quorum (>= 3 of 4) on both sides needs >= 2      *)
(* honest on each side, but only 3 honest exist and each signs at most one    *)
(* side (2 + 2 > 3) — impossible. Pairs with MCXZoneBreak (f = 2) to pin the  *)
(* threshold from both sides.                                                *)
EXTENDS ElaraXZone, TLC

MCWit    == {"w1", "w2", "w3", "w4"}
MCByz    == {"w4"}
MCSealed == TRUE
=============================================================================
