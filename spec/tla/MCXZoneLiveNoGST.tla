--------------------------- MODULE MCXZoneLiveNoGST ---------------------------
(* Cross-zone liveness, NO-GST scenario. n = 4, f = 1, but GstReachable =     *)
(* FALSE: synchrony never arrives, so no honest view ever resolves and the    *)
(* fast path cannot complete (FLP-respecting). LiveFast (reap off) is         *)
(* VIOLATED — TLC produces a real lasso. LiveBackstop (reap on) still HOLDS:   *)
(* the quorum-free reaper is not gst-gated.                                   *)
EXTENDS ElaraXZoneLive, TLC

MCWit     == {"w1", "w2", "w3", "w4"}
MCByz     == {"w4"}
MCGst     == FALSE
MCByzSign == TRUE
=============================================================================
