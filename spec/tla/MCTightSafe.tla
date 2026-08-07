----------------------------- MODULE MCTightSafe ----------------------------
(* Byzantine-bound TIGHTNESS, safe side. n = 4, f = 1 (n = 3f+1), all       *)
(* witnesses fully independent (corr = 0 => effective = raw), uniform stake. *)
(* With Byzantine = 1 (= floor(n/3)), NoConflictingFinalization HOLDS:       *)
(* settlement needs >= 3 of 4 attesters, and a single equivocator cannot     *)
(* manufacture two such quorums. Paired with MCTightBreak this shows the     *)
(* 1/3 threshold is necessary AND sufficient (acceptance gate 3).            *)
EXTENDS ElaraConsensus, TLC

MCWit    == {"w1", "w2", "w3", "w4"}
MCByz    == {"w4"}
MCRec    == {"r1", "r2"}
MCStake  == [w \in MCWit |-> 1]
MCOrg    == ("w1" :> "A" @@ "w2" :> "B" @@ "w3" :> "C" @@ "w4" :> "D")
MCSubnet == ("w1" :> "s1" @@ "w2" :> "s2" @@ "w3" :> "s3" @@ "w4" :> "s4")
MCZone   == ("w1" :> "z1" @@ "w2" :> "z2" @@ "w3" :> "z3" @@ "w4" :> "z4")
=============================================================================
