------------------------ MODULE MCInZoneLiveAllByz ------------------------
(* In-zone liveness, ALL LOCAL PROPOSERS BYZANTINE. Every rank withholds,    *)
(* so no canonical seal candidate ever appears locally and the committee     *)
(* path is dead. LiveLocal VIOLATED. LiveWithEscalation HOLDS: with the      *)
(* ladder exhausted and a healthy cross-zone quorum (honest 2/3 external,    *)
(* global GST) the escalation seal fires. This is the scenario that the      *)
(* escalation backstop exists for.                                          *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {0, 1, 2}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
