------------------------- MODULE MCInZoneLiveSafe -------------------------
(* In-zone liveness, SAFE baseline. 3 ranks (rank-0 HONEST), 4 witnesses     *)
(* (f=1, honest 3/4 >= 2/3), 3 external anchors (f=1, honest 2/3). GST       *)
(* reachable both locally and globally. The FAST path: rank-0 proposes       *)
(* immediately, honest witnesses converge post-GST, 2/3 attest, Settle.      *)
(* LiveLocal HOLDS (committee seals) and LiveWithEscalation HOLDS.           *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
