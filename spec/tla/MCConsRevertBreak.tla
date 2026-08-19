-------------------------- MODULE MCConsRevertBreak --------------------------
(* TAIL 1 — partition-merge seal demotion, XZoneRevert ABSENT.                 *)
(* RevertEnabled = FALSE (the unimplemented fix is missing); ReapClaimExclusive*)
(* = TRUE (so the ONLY violation is the demotion one — a clean counterexample).*)
(* SupplyInvariant is EXPECTED TO FAIL. Reachable trace (ZERO Byzantine):     *)
(*   Lock -> Seal -> Claim -> SealDemote -> ResolveSealDemotion               *)
(* After Claim the recipient holds +Amt and in-flight is 0; the merge reverts *)
(* the now non-canonical lock debit, restoring bal[Sender] +Amt, but with no  *)
(* XZoneRevert nothing claws back the recipient => supply = TotalSupply + Amt.*)
(* This proves the XZoneRevert guard is NECESSARY for conservation under a    *)
(* partition merge — a guard-necessity proof, NOT a Byzantine-threshold one.  *)
EXTENDS Conservation, TLC

MCAccounts == {"s", "r", "t"}
MCInitBal  == ("s" :> 2 @@ "r" :> 0 @@ "t" :> 1)
=============================================================================
