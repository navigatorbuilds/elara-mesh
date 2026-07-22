-------------------------- MODULE MCXZoneLiveByzStall --------------------------
(* Cross-zone liveness, BYZANTINE-STALL scenario. n = 4, f = 2 (Byzantine =   *)
(* 1/3, past the bound), GST reachable, but ByzMaySign = FALSE so Byzantine    *)
(* witnesses are REMOVED from attestation: the break unambiguously proves the  *)
(* honest remainder (2 < 3) ALONE cannot form a 2/3 quorum. LiveFast (reap     *)
(* off) is VIOLATED. LiveBackstop (reap on) still HOLDS via the reaper — the   *)
(* discriminating result: f >= 1/3 denies the fast path but not eventual reap. *)
EXTENDS ElaraXZoneLive, TLC

MCWit     == {"w1", "w2", "w3", "w4"}
MCByz     == {"w3", "w4"}
MCGst     == TRUE
MCByzSign == FALSE
=============================================================================
