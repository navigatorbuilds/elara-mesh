------------------------ MODULE MCInZoneLiveEscByz ------------------------
(* In-zone liveness, ESCALATION QUORUM TOO BYZANTINE. All local proposers    *)
(* Byzantine AND ByzExt = {z2,z3}: only 1 of 3 external anchors is honest,   *)
(* so even with global GST the escalation seal can never reach its 2/3       *)
(* cross-zone quorum. LiveWithEscalation VIOLATED — distinct from            *)
(* MCInZoneLiveNoEscGST (there the break is no synchrony; here it is global  *)
(* f >= 1/3). Together they prove BOTH escalation preconditions necessary.   *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {0, 1, 2}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z2", "z3"}
=============================================================================
