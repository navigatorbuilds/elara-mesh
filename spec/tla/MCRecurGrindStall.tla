------------------------ MODULE MCRecurGrindStall ------------------------
(* Cross-epoch liveness, GRINDABLE-BEACON + NO-FLOOR break. The adversary     *)
(* pins the worst-case assignment every epoch (ViableEpochs = {}) AND the     *)
(* cross-zone escalation backstop is out of scope (EscalationAvailable =      *)
(* FALSE). With no honest eligible rank and no escalation floor, the chain    *)
(* PERMANENTLY STALLS — RecurSealed is VIOLATED. This is the cross-epoch      *)
(* statement of Phase E.2's headline asymmetry: an in-zone seal IS a 2/3      *)
(* quorum certificate, so there is no quorum-free floor; a sustained          *)
(* worst-case with no escalation has nothing to rescue it.                    *)
(* BeaconPeriod 3, escalation UNAVAILABLE.                                     *)
EXTENDS LivenessRecurrence, TLC

MCViable == {}
=============================================================================
