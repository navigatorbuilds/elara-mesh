------------------------------- MODULE MCSafe -------------------------------
(* Safety + diversity model: 5 witnesses, 1 Byzantine (< 1/3), uniform     *)
(* stake. Profiles: w1..w4 mutually distinct (fully independent); w5 is a   *)
(* full clone of w1 (org+subnet+zone all equal) -> a maximally-correlated   *)
(* pair (corr = Q, independence halves). This exercises BOTH diversity      *)
(* boundaries (corr = 0 and corr = Q) demanded by acceptance gate 2.        *)
(* Concrete constants are wired to ElaraConsensus via `<-` in MCSafe.cfg.   *)
(* Expected: TypeOK, DiversitySoundness, NoConflictingFinalization all hold.*)
EXTENDS ElaraConsensus, TLC

MCWit    == {"w1", "w2", "w3", "w4", "w5"}
MCByz    == {"w5"}
MCRec    == {"r1", "r2"}
MCStake  == [w \in MCWit |-> 1]
MCOrg    == ("w1" :> "A" @@ "w2" :> "B" @@ "w3" :> "C" @@ "w4" :> "D" @@ "w5" :> "A")
MCSubnet == ("w1" :> "s1" @@ "w2" :> "s2" @@ "w3" :> "s3" @@ "w4" :> "s4" @@ "w5" :> "s1")
MCZone   == ("w1" :> "z1" @@ "w2" :> "z2" @@ "w3" :> "z3" @@ "w4" :> "z4" @@ "w5" :> "z1")
=============================================================================
