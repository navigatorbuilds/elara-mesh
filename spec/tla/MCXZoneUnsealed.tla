--------------------------- MODULE MCXZoneUnsealed ---------------------------
(* Seal-gate STRUCTURAL exclusion (no BFT needed). Sealed = FALSE: the lock   *)
(* has not been committed to a zone-A epoch seal. Here Claimed and Aborted    *)
(* are UNREACHABLE (both require Sealed — the M7 claim gate :428 and the      *)
(* abort seal gate :650); the only enabled terminal is the unsealed Refund    *)
(* path (cancel/reject/passive-24h). This exercises the code-path partition   *)
(* that makes the "passive refund races a claim" double-credit impossible     *)
(* WITHOUT any Byzantine-fraction assumption. n=4, f=1, but f is irrelevant   *)
(* here — no quorum action is ever enabled. Expected: no errors.              *)
EXTENDS ElaraXZone, TLC

MCWit    == {"w1", "w2", "w3", "w4"}
MCByz    == {"w4"}
MCSealed == FALSE
=============================================================================
