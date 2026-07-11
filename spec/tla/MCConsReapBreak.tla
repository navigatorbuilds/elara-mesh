--------------------------- MODULE MCConsReapBreak ---------------------------
(* TAIL 2 — 30-day stale-reap races a claim under a >30-day partition.         *)
(* ReapClaimExclusive = FALSE (the >30d partition defeats the 24h claim-expiry *)
(* gate, so reap and claim are no longer mutually exclusive); RevertEnabled =  *)
(* TRUE (so the ONLY violation is the reap/claim one — a clean counterexample).*)
(* SupplyInvariant is EXPECTED TO FAIL. Reachable trace (ZERO Byzantine):     *)
(*   Lock -> Seal -> SetStale -> Claim -> Reap                                *)
(* The claim credits the recipient (+Amt) and drains in-flight to 0; the reap *)
(* then credits the sender (+Amt) while its saturating decrement of the       *)
(* already-zero in-flight masks the missing backing => supply = TotalSupply   *)
(* + Amt. One lock, two credits. This proves the reap/claim exclusion guard   *)
(* is NECESSARY for conservation under extended partition — guard-necessity,  *)
(* not a Byzantine-threshold proof.                                           *)
EXTENDS Conservation, TLC

MCAccounts == {"s", "r", "t"}
MCInitBal  == ("s" :> 2 @@ "r" :> 0 @@ "t" :> 1)
=============================================================================
