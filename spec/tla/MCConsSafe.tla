----------------------------- MODULE MCConsSafe -----------------------------
(* Supply-conservation SAFE model. Both protocol guards ON                    *)
(* (RevertEnabled = TRUE, ReapClaimExclusive = TRUE). SupplyInvariant is      *)
(* EXPECTED TO HOLD: every reachable path — lock/seal/claim, sealed-abort,    *)
(* unsealed-refund, 30-day reap, partition-merge demotion handled by          *)
(* XZoneRevert, plus the ambient stake/burn/mint moves — conserves the        *)
(* four-bucket sum. Zero Byzantine nodes: conservation here is a structural    *)
(* property of symmetric debit/credit, not a quorum argument.                 *)
EXTENDS Conservation, TLC

MCAccounts == {"s", "r", "t"}
MCInitBal  == ("s" :> 2 @@ "r" :> 0 @@ "t" :> 1)
=============================================================================
