------------------------ MODULE MCInZoneLiveByzWit ------------------------
(* In-zone liveness, INSUFFICIENT HONEST ATTESTING STAKE. rank-0 honest and  *)
(* GST reachable, but ByzWit = {w3,w4}: only 2 of 4 witnesses are honest, so  *)
(* the honest attesting set can never reach 2/3 (3 of 4). The proposal       *)
(* exists and is delivered, yet Settle never enables. LiveLocal VIOLATED —   *)
(* the dual of the Phase E ByzStall break (honest >= 2/3 is necessary).      *)
(* LiveWithEscalation HOLDS via the healthy cross-zone quorum.               *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w3", "w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
