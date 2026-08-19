---------------------------- MODULE MCTightBreak ----------------------------
(* Byzantine-bound TIGHTNESS, broken side. n = 4 but f = 2 (Byzantine       *)
(* stake > 1/3), all witnesses fully independent, uniform stake. Here        *)
(* NoConflictingFinalization is EXPECTED TO FAIL: two equivocators plus one   *)
(* honest each form a 3-of-4 quorum for two conflicting records, so TLC must  *)
(* print a counterexample. This proves the 1/3 bound is necessary - the spec  *)
(* is tight, not merely sufficient (acceptance gate 3).                       *)
(* DiversitySoundness still HOLDS even here (it is a universal arithmetic     *)
(* truth, independent of the Byzantine fraction).                            *)
EXTENDS ElaraConsensus, TLC

MCWit    == {"w1", "w2", "w3", "w4"}
MCByz    == {"w3", "w4"}
MCRec    == {"r1", "r2"}
MCStake  == [w \in MCWit |-> 1]
MCOrg    == ("w1" :> "A" @@ "w2" :> "B" @@ "w3" :> "C" @@ "w4" :> "D")
MCSubnet == ("w1" :> "s1" @@ "w2" :> "s2" @@ "w3" :> "s3" @@ "w4" :> "s4")
MCZone   == ("w1" :> "z1" @@ "w2" :> "z2" @@ "w3" :> "z3" @@ "w4" :> "z4")
=============================================================================
