----------------------- MODULE MCInZoneLiveBootstrap -----------------------
(* In-zone liveness, BOOTSTRAP FREEZE TRAP (staked.len() < 3). The carve-out *)
(* at aggregator.rs:755 collapses the ladder to a single genesis-only rank,  *)
(* and escalation has no bootstrap path (escalation_decision :346). Modelled *)
(* as a single rank {0} that is BYZANTINE (genesis offline/equivocating ->   *)
(* HonestRanks = {}) and EscalationAvailable = FALSE in BOTH cfgs. Nothing   *)
(* can seal: LiveWithEscalation is VIOLATED with NO safety net — neither the *)
(* ladder, the committee, nor escalation rescues it. This is the formal      *)
(* statement of the operational invariant "never sit at 2 stakers; re-       *)
(* genesis 1 -> 3 atomically." GST is reachable to prove the freeze is       *)
(* structural, not a synchrony artifact.                                    *)
EXTENDS Liveness, TLC

MCRanks    == {0}
MCByzRanks == {0}
MCWit      == {"w1", "w2", "w3", "w4"}
MCByzWit   == {"w4"}
MCExt      == {"z1", "z2", "z3"}
MCByzExt   == {"z3"}
=============================================================================
