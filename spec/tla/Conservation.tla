---------------------------- MODULE Conservation ----------------------------
(***************************************************************************)
(* TLA+ model of the Elara beat SUPPLY-CONSERVATION core                     *)
(* (Phase D — spec/tla/README.md, §4.4 SupplyInvariant row).                *)
(*                                                                         *)
(* THE INVARIANT (verbatim from src/accounting/ledger.rs:206):                  *)
(*   sum(available) + total_staked + pending_xzone_locked + conservation_  *)
(*   pool = total_supply                                                   *)
(* i.e. value is never created or destroyed: every beat is in exactly one *)
(* of four buckets, and the four-bucket sum is a constant. This is the     *)
(* STRONGEST safety property because it must hold across EVERY action —    *)
(* including ones a designer doesn't think about (sealed-abort rollback,   *)
(* partition-merge seal demotion, 30-day stale-reap). It catches any path  *)
(* that forgot to debit/credit symmetrically.                             *)
(*                                                                         *)
(* BUCKET <-> CODE MAP (the four terms of ledger.rs:206):                  *)
(*   bal[a]   <-> AccountState.available  (per-account spendable balance)  *)
(*   staked   <-> LedgerState.total_staked                                 *)
(*   inflight <-> LedgerState.pending_xzone_locked  (NOT cross_zone.       *)
(*                total_locked — that is a SEPARATE in-module tracker; the  *)
(*                conservation invariant at ledger.rs:206 is keyed on      *)
(*                pending_xzone_locked, mutated at ledger.rs:1985 (+=) and  *)
(*                :2039/:2071/:2156/:2194/:1707/:1734 (saturating_sub)).    *)
(*   pool     <-> LedgerState.conservation_pool                            *)
(*                                                                         *)
(* TRANSITION <-> CODE MAP (cross-zone lifecycle, the conservation-risky   *)
(* path — single transfer, sender s -> recipient r):                       *)
(*   Lock   <-> XZoneLock apply: available -= amt (ledger.rs:1978);        *)
(*              pending_xzone_locked += amt (:1985). [bal[s]->inflight]     *)
(*   Seal   <-> source-zone epoch seal commits the lock (set_proof +        *)
(*              verify_finality_quorum). No bucket move.                    *)
(*   Claim  <-> XZoneClaim apply: pending_xzone_locked -= amt (:2039,sat);  *)
(*              recipient available += amt (:2032). [inflight->bal[r]]      *)
(*   Abort  <-> XZoneAbort apply: pending_xzone_locked -= amt (sat);        *)
(*              sender available += amt. Sealed-only (cross_zone.rs:650).   *)
(*              [inflight->bal[s]]                                          *)
(*   Refund <-> cancel/reject/passive-24h: pending -= amt (sat); sender     *)
(*              += amt. UNSEALED-only (merkle_proof.is_empty()). [->bal[s]] *)
(*   Reap   <-> apply_reap_batch (cross_zone.rs:936): pending -= amt (sat); *)
(*              sender += amt. Sealed lock past expires_at+30d.[->bal[s]]    *)
(*                                                                         *)
(* DECREMENTS ARE SATURATING. Every pending_xzone_locked decrement in the  *)
(* code is `saturating_sub`. This is LOAD-BEARING: a double-release        *)
(* SATURATES the bucket to 0 instead of panicking, so a double-CREDIT      *)
(* manifests as SUPPLY INFLATION (the invariant catches it) rather than a  *)
(* crash. SatSub(x,k) below mirrors this exactly.                          *)
(*                                                                         *)
(* THE TWO CONSERVATION TAILS (documented design-only — README "Not yet    *)
(* modelled", docs/PARTITION-MERGE.md Gap D). Phase C's NoAbortAndClaim is  *)
(* per-transfer mutual exclusion; it is NECESSARY BUT NOT SUFFICIENT for    *)
(* the aggregate supply invariant. The two tails are SUPPLY breaks, not    *)
(* claim/abort breaks, so they live here where `amount` is carried:        *)
(*                                                                         *)
(*  TAIL 1 — partition-merge seal DEMOTION (the unimplemented XZoneRevert). *)
(*   After a claim in zone B (bal[r]+=amt), a partition-merge demotes the   *)
(*   source-zone seal. On the canonical chain the lock record is a NON-     *)
(*   canonical debit (Gap D) — zone A's state reverts the lock, restoring   *)
(*   bal[s]. The recipient keeps the credit => supply +amt. The fix is the  *)
(*   `XZoneRevert` record, which claws back bal[r]. It is DESIGN-ONLY /      *)
(*   UNIMPLEMENTED today. Modeled by `ResolveSealDemotion` gated on the      *)
(*   RevertEnabled switch.                                                  *)
(*                                                                         *)
(*  TAIL 2 — 30-day stale-reap vs claim under a >30-day partition.          *)
(*   A sealed lock past expires_at+30d is reaped (bal[s]+=amt). Under a     *)
(*   >30-day partition zone B cannot see the reap and a pre-expiry claim    *)
(*   record applies anyway (bal[r]+=amt). One lock backs two credits =>     *)
(*   supply +amt. In normal synchrony the 24h claim-expiry gate            *)
(*   (cross_zone.rs:420) keeps reap and claim disjoint; the >30d partition  *)
(*   defeats that gate. Modeled by the ReapClaimExclusive switch.           *)
(*                                                                         *)
(* WHY THE BREAK MODELS ARE GUARD-NECESSITY, NOT BYZANTINE-TIGHTNESS:       *)
(*   Unlike Phase A/B/C (where the counterexample needs f > 1/3 Byzantine   *)
(*   witnesses), BOTH Phase-D break traces contain ZERO Byzantine nodes.    *)
(*   They are reachability proofs under a network PARTITION with a named    *)
(*   protocol guard removed — they prove each fix (XZoneRevert / reap-claim *)
(*   exclusion) is INDIVIDUALLY NECESSARY for conservation. This is a       *)
(*   DIFFERENT proof shape from the threshold-pinning triples; the README   *)
(*   and run-tlc.sh keep the two banners separate.                          *)
(*                                                                         *)
(* DELIBERATE ABSTRACTIONS (documented — audited 2026-06-28):              *)
(*   - witness_bonded is NOT a conservation bucket. AccountState.total()    *)
(*     (ledger.rs:97) and the conservation equation (ledger.rs:206) both    *)
(*     EXCLUDE it, matching design-doc §4.4's four-term sum. So witness     *)
(*     registration/bonding is out of scope here BY THE INVARIANT'S OWN     *)
(*     definition — modeling it would be the error.                        *)
(*   - Idle decay (demurrage-era name) is omitted: its debit SPLITS between conservation_pool and *)
(*     active stakers (ledger.rs:740) — an economic distribution, not a     *)
(*     consensus-safety move (design doc §9). The conservation property it  *)
(*     would exercise is identical to the Burn/Mint pair modeled below.     *)
(*   - Stake/Mint/Burn are modeled as minimal CONSERVING bucket moves on a  *)
(*     dedicated Treasury account, present so SupplyInvariant is a genuine  *)
(*     FOUR-bucket check (staked + pool are exercised), not a 2-bucket one. *)
(*     They are deliberately kept off the s/r transfer accounts so the      *)
(*     XZoneRevert clawback always sees bal[r] >= Amt (exact, not saturated)*)
(*   - The 30-day staleness is enforced PROPOSER-side                       *)
(*     (compute_stale_reap_batch); apply_reap_batch trusts the genesis-     *)
(*     signed batch. `stale` here represents that proposer gate.            *)
(*   - ResolveSealDemotion is ATOMIC (revert-lock-debit + clawback in one   *)
(*     step). The real cross-zone window between the two is a LIVENESS/      *)
(*     timing concern (Phase E), not a settled-state supply-safety concern; *)
(*     SupplyInvariant is checked on settled states.                        *)
(*   - A SINGLE transfer is modeled; transfer_ids are independent so per-   *)
(*     transfer conservation composes. The cross-transfer saturating-sub    *)
(*     masking aggregate is a multi-transfer extension, noted in README.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Accounts,            \* set of account ids (>= {Sender, Recipient, Treasury})
    Sender,              \* the cross-zone transfer's sender (debited at Lock)
    Recipient,           \* the recipient (credited at Claim)
    Treasury,            \* a 3rd account carrying the ambient stake/pool moves
    Amt,                 \* the transfer amount (Nat > 0)
    Unit,                \* ambient stake/burn/mint move size (Nat > 0)
    InitBal,             \* [Accounts -> Nat] initial balances
    InitStaked,          \* Nat initial total_staked
    InitPool,            \* Nat initial conservation_pool
    RevertEnabled,       \* BOOLEAN: is XZoneRevert wired? (Tail-1 guard)
    ReapClaimExclusive   \* BOOLEAN: is reap/claim mutual exclusion enforced? (Tail-2 guard)

VARIABLES
    bal,                 \* [Accounts -> Nat]  (available)
    inflight,            \* Nat  (pending_xzone_locked)
    staked,              \* Nat  (total_staked)
    pool,                \* Nat  (conservation_pool)
    \* transfer-lifecycle flags (all BOOLEAN):
    locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved

vars == << bal, inflight, staked, pool,
           locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* Saturating subtraction — mirrors Rust u64::saturating_sub (clamps at 0).
SatSub(x, k) == IF x >= k THEN x - k ELSE 0

\* Sum of a Nat-valued function over a finite set (TLC-evaluable fold).
RECURSIVE SumOver(_, _)
SumOver(f, S) ==
    IF S = {} THEN 0
    ELSE LET a == CHOOSE x \in S : TRUE
         IN f[a] + SumOver(f, S \ {a})

SumBal     == SumOver(bal, Accounts)
TotalSupply == SumOver(InitBal, Accounts) + InitStaked + InitPool

TypeOK ==
    /\ bal \in [Accounts -> Nat]
    /\ inflight \in Nat
    /\ staked   \in Nat
    /\ pool     \in Nat
    /\ locked   \in BOOLEAN
    /\ sealed   \in BOOLEAN
    /\ claimed  \in BOOLEAN
    /\ aborted  \in BOOLEAN
    /\ refunded \in BOOLEAN
    /\ stale    \in BOOLEAN
    /\ reaped   \in BOOLEAN
    /\ sealDemoted \in BOOLEAN
    /\ resolved \in BOOLEAN

(***************************************************************************)
(* Initial state: all value sits in its starting bucket; nothing in flight.*)
(***************************************************************************)
Init ==
    /\ bal = InitBal
    /\ inflight = 0
    /\ staked = InitStaked
    /\ pool = InitPool
    /\ locked = FALSE
    /\ sealed = FALSE
    /\ claimed = FALSE
    /\ aborted = FALSE
    /\ refunded = FALSE
    /\ stale = FALSE
    /\ reaped = FALSE
    /\ sealDemoted = FALSE
    /\ resolved = FALSE

(***************************************************************************)
(* Cross-zone transfer lifecycle.                                          *)
(***************************************************************************)

\* XZoneLock: sender -> in-flight.
Lock ==
    /\ ~locked
    /\ bal[Sender] >= Amt
    /\ bal' = [bal EXCEPT ![Sender] = bal[Sender] - Amt]
    /\ inflight' = inflight + Amt
    /\ locked' = TRUE
    /\ UNCHANGED << staked, pool, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* Source-zone epoch seal commits the lock (no bucket move).
Seal ==
    /\ locked /\ ~sealed
    /\ ~claimed /\ ~aborted /\ ~refunded
    /\ sealed' = TRUE
    /\ UNCHANGED << bal, inflight, staked, pool, locked, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* XZoneClaim: in-flight -> recipient. Sealed-only (M7). With ReapClaimExclusive
\* a claim is blocked once reaped; with it off (>30d partition) it may still fire.
Claim ==
    /\ locked /\ sealed
    /\ ~aborted /\ ~refunded /\ ~claimed
    /\ (~reaped \/ ~ReapClaimExclusive)
    /\ inflight' = SatSub(inflight, Amt)
    /\ bal' = [bal EXCEPT ![Recipient] = bal[Recipient] + Amt]
    /\ claimed' = TRUE
    /\ UNCHANGED << staked, pool, locked, sealed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* XZoneAbort (B-committee non-inclusion quorum): in-flight -> sender. Sealed-only.
Abort ==
    /\ locked /\ sealed
    /\ ~claimed /\ ~refunded /\ ~reaped /\ ~aborted
    /\ inflight' = SatSub(inflight, Amt)
    /\ bal' = [bal EXCEPT ![Sender] = bal[Sender] + Amt]
    /\ aborted' = TRUE
    /\ UNCHANGED << staked, pool, locked, sealed, claimed, refunded, stale, reaped, sealDemoted, resolved >>

\* Unsealed refund (cancel/reject/passive-24h): in-flight -> sender. UNSEALED-only.
Refund ==
    /\ locked /\ ~sealed
    /\ ~claimed /\ ~aborted /\ ~refunded
    /\ inflight' = SatSub(inflight, Amt)
    /\ bal' = [bal EXCEPT ![Sender] = bal[Sender] + Amt]
    /\ refunded' = TRUE
    /\ UNCHANGED << staked, pool, locked, sealed, claimed, aborted, stale, reaped, sealDemoted, resolved >>

\* Time elapses past expires_at + 30d — the proposer-side stale gate opens.
SetStale ==
    /\ locked /\ sealed
    /\ ~stale
    /\ stale' = TRUE
    /\ UNCHANGED << bal, inflight, staked, pool, locked, sealed, claimed, aborted, refunded, reaped, sealDemoted, resolved >>

\* 30-day stale-reap: in-flight -> sender. Sealed + stale. With ReapClaimExclusive
\* a reap is blocked once claimed; with it off (>30d partition) it may still fire.
Reap ==
    /\ locked /\ sealed /\ stale
    /\ ~aborted /\ ~refunded /\ ~reaped
    /\ (~claimed \/ ~ReapClaimExclusive)
    /\ inflight' = SatSub(inflight, Amt)
    /\ bal' = [bal EXCEPT ![Sender] = bal[Sender] + Amt]
    /\ reaped' = TRUE
    /\ UNCHANGED << staked, pool, locked, sealed, claimed, aborted, refunded, stale, sealDemoted, resolved >>

(***************************************************************************)
(* TAIL 1 — partition-merge seal demotion.                                 *)
(***************************************************************************)

\* The partition-merge demotes the source-zone seal AFTER a claim.
SealDemote ==
    /\ sealed /\ claimed /\ ~sealDemoted
    /\ sealDemoted' = TRUE
    /\ UNCHANGED << bal, inflight, staked, pool, locked, sealed, claimed, aborted, refunded, stale, reaped, resolved >>

\* The canonical chain reverts the (now non-canonical) lock debit, restoring
\* bal[Sender]. XZoneRevert — IF wired (RevertEnabled) — atomically claws back
\* the recipient credit, conserving supply. WITHOUT it, supply inflates by Amt.
ResolveSealDemotion ==
    /\ sealDemoted /\ ~resolved
    /\ resolved' = TRUE
    /\ IF RevertEnabled
         THEN bal' = [bal EXCEPT ![Sender] = bal[Sender] + Amt,
                                 ![Recipient] = SatSub(bal[Recipient], Amt)]
         ELSE bal' = [bal EXCEPT ![Sender] = bal[Sender] + Amt]
    /\ UNCHANGED << inflight, staked, pool, locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted >>

(***************************************************************************)
(* Ambient CONSERVING moves on the Treasury account — present so the four- *)
(* bucket SupplyInvariant is genuinely exercised on staked + pool.         *)
(***************************************************************************)

\* Stake bond: available -> total_staked.
Stake ==
    /\ bal[Treasury] >= Unit
    /\ bal' = [bal EXCEPT ![Treasury] = bal[Treasury] - Unit]
    /\ staked' = staked + Unit
    /\ UNCHANGED << inflight, pool, locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* Unbond: total_staked -> available.
Unstake ==
    /\ staked >= Unit
    /\ staked' = staked - Unit
    /\ bal' = [bal EXCEPT ![Treasury] = bal[Treasury] + Unit]
    /\ UNCHANGED << inflight, pool, locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* Burn / PoolFund: available -> conservation_pool (ledger.rs:1761).
Burn ==
    /\ bal[Treasury] >= Unit
    /\ bal' = [bal EXCEPT ![Treasury] = bal[Treasury] - Unit]
    /\ pool' = pool + Unit
    /\ UNCHANGED << inflight, staked, locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

\* Reward emission / mint from pool: conservation_pool -> available (ledger.rs:1515).
Mint ==
    /\ pool >= Unit
    /\ pool' = pool - Unit
    /\ bal' = [bal EXCEPT ![Treasury] = bal[Treasury] + Unit]
    /\ UNCHANGED << inflight, staked, locked, sealed, claimed, aborted, refunded, stale, reaped, sealDemoted, resolved >>

Next ==
    \/ Lock \/ Seal \/ Claim \/ Abort \/ Refund
    \/ SetStale \/ Reap
    \/ SealDemote \/ ResolveSealDemotion
    \/ Stake \/ Unstake \/ Burn \/ Mint

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* §4.4 — the supply invariant. The four buckets always sum to the         *)
(* constant TotalSupply. TLC checks it in every reachable state.           *)
(***************************************************************************)
SupplyInvariant == SumBal + inflight + staked + pool = TotalSupply
=============================================================================
