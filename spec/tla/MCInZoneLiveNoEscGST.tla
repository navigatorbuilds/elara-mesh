----------------------- MODULE MCInZoneLiveNoEscGST -----------------------
(* In-zone liveness, NO GLOBAL GST. All local proposers Byzantine AND        *)
(* ExtGstReachable = FALSE: the local committee is dead and the cross-zone   *)
(* escalation never gathers (its external anchors can never deliver without  *)
(* global GST). LiveWithEscalation is VIOLATED. This is the headline         *)
(* asymmetry vs Phase E: there is NO quorum-free in-zone floor, so global    *)
(* asynchrony + all-Byzantine local proposers leaves the zone stuck          *)
(* indefinitely (FLP at the cross-zone layer).                              *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {0, 1, 2}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
