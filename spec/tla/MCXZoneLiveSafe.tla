--------------------------- MODULE MCXZoneLiveSafe ---------------------------
(* Cross-zone liveness, SAFE scenario. n = 4, f = 1 (Byzantine < 1/3), GST   *)
(* reachable, Byzantine may attest. Honest = 3 = a 2/3 quorum, so the fast   *)
(* path completes after GST. Used for LiveFast (reap off) and LiveBackstop   *)
(* (reap on) — both HOLD.                                                    *)
EXTENDS ElaraXZoneLive, TLC

MCWit     == {"w1", "w2", "w3", "w4"}
MCByz     == {"w4"}
MCGst     == TRUE
MCByzSign == TRUE
=============================================================================
