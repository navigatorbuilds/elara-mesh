----------------------------- MODULE MCXZoneBreak -----------------------------
(* Byzantine-bound TIGHTNESS, broken side. n = 4 but f = 2 (Byzantine        *)
(* > 1/3), sealed transfer. NoAbortAndClaim is EXPECTED TO FAIL: the two      *)
(* equivocators sign BOTH sides, and one honest joins each side, manufacturing*)
(* a 3-of-4 quorum for the claim seal AND a 3-of-4 quorum for the abort proof *)
(* at once — the cross-zone double-credit. Reachable witness assignment:      *)
(*   claimAtt = {w3, w4, w1}   (|.|=3 >= 3 -> quorum)                          *)
(*   abortAtt = {w3, w4, w2}   (|.|=3 >= 3 -> quorum)                          *)
(* with w3,w4 Byzantine (both sides) and w1,w2 honest (one side each, so the  *)
(* at-most-one-side rule is respected). TLC prints this counterexample,       *)
(* proving the 1/3 bound is NECESSARY for cross-zone conservation, not merely *)
(* sufficient (acceptance gate 3).                                            *)
(* SealGateSound STILL HOLDS even here — it is a structural code-path truth,  *)
(* independent of the Byzantine fraction.                                     *)
EXTENDS ElaraXZone, TLC

MCWit    == {"w1", "w2", "w3", "w4"}
MCByz    == {"w3", "w4"}
MCSealed == TRUE
=============================================================================
