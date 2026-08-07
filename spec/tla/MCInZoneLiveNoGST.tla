------------------------- MODULE MCInZoneLiveNoGST -------------------------
(* In-zone liveness, NO LOCAL GST. rank-0 honest, but GstReachable = FALSE:  *)
(* local attestations never converge (FLP-respecting). LiveLocal is          *)
(* VIOLATED (TLC produces a real lasso — honest witnesses can never deliver  *)
(* attestations). LiveWithEscalation HOLDS: cross-zone GST (ExtGstReachable  *)
(* = TRUE in the _Esc cfg) lets the escalation seal the locally-async zone   *)
(* once the ladder is exhausted — escalation does not need LOCAL synchrony.  *)
EXTENDS Liveness, TLC

MCRanks    == {0, 1, 2}
MCByzRanks == {}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
