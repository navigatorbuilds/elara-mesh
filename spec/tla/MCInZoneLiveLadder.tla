------------------------ MODULE MCInZoneLiveLadder ------------------------
(* In-zone liveness, LADDER scenario. rank-0 is BYZANTINE (withholds), ranks *)
(* 1 and 2 honest. The fast path (rank-0) is denied, but the rank ladder     *)
(* unlocks rank-1 by elapsed and an honest proposer eventually emits the     *)
(* seal. LiveLocal still HOLDS — this is what distinguishes the ladder       *)
(* guarantee from the rank-0 fast path (MCInZoneLiveSafe). 4 witnesses       *)
(* (honest 3/4), 3 external anchors (honest 2/3), GST reachable.             *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {0}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
