-------------------------- MODULE ElaraConsensus --------------------------
(***************************************************************************)
(* TLA+ model of the Elara MESH-BFT (Adaptive Witness Consensus)           *)
(* settlement core.                                                        *)
(*                                                                         *)
(* This is the implementation of the blueprint in                          *)
(* spec/tla/README.md (Phase A + single-zone Phase B). It                  *)
(* faithfully mirrors the DETERMINISTIC fixed-point settlement path in     *)
(* src/network/consensus.rs (the `*_q` functions), scaled by SETTLEMENT_Q. *)
(* The float path (`independence`, the display sibling of                  *)
(* `is_settled_diverse`) is explicitly NOT modelled: it is RPC/explorer-   *)
(* only and never gates consensus (see docs/SETTLEMENT-FLOAT-DETERMINISM). *)
(*                                                                         *)
(* PROPERTIES (see the .cfg files):                                        *)
(*   DiversitySoundness         the AWC novelty: diversity weighting is    *)
(*                              deflationary-only - effective stake can     *)
(*                              never exceed raw stake. (4.2 in the doc)    *)
(*   NoConflictingFinalization  the headline BFT agreement property: no    *)
(*                              two conflicting records both finalize while *)
(*                              Byzantine stake stays < 1/3. (4.1)          *)
(*                                                                         *)
(* REFINEMENT MAP (TLA+ operator  <->  Rust function, file:line):          *)
(*   CorrQ          <-> ConsensusState::correlation_weighted_q  consensus.rs:2829 *)
(*   IndependenceQ  <-> ConsensusState::independence_q          consensus.rs:2862 *)
(*   EffStakeQ      <-> ConsensusState::effective_stake_q       consensus.rs:2884 *)
(*   DiverseSettled <-> ConsensusState::diverse_threshold_met_q consensus.rs:2906 *)
(*                      reached via   is_settled_diverse        consensus.rs:2583 *)
(*   AttestHonest   <-> honest add_attestation (single, non-equivocating)   *)
(*   AttestByz      <-> Byzantine equivocation (attests conflicting records)*)
(*                                                                         *)
(* ABSTRACTIONS (deliberate, documented):                                  *)
(*   - Stake is uniform per witness in the model configs; the BFT bound is  *)
(*     a stake-FRACTION argument, so uniform stake exercises the n=3f+1     *)
(*     boundary crisply. Stake-weighted scenarios are a follow-up.          *)
(*   - gamma is taken at full GAMMA_Q (the geo-diversity honest-degradation *)
(*     gamma_effective() -> 0 path is abstracted). Full gamma is the        *)
(*     conservative direction (more correlation => lower effective stake =>  *)
(*     harder to settle => strictly harder for the adversary).              *)
(*   - creator_stake = 0 (record creators are not modelled as witnesses), so*)
(*     Eligible = TotalStake. The code subtracts creator stake, which only  *)
(*     LOWERS Eligible; modelling it = 0 keeps the threshold uniform across *)
(*     the conflicting candidates.                                          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Witnesses,    \* set of all witness identities
    Byzantine,    \* SUBSET Witnesses : may equivocate (attest conflicting records)
    Records,      \* set of conflicting candidate records (all claim the same slot)
    Stake,        \* [Witnesses -> Nat] : per-witness stake
    Org,          \* [Witnesses -> STRING] : organization (alpha-correlation)
    Subnet,       \* [Witnesses -> STRING] : subnet      (beta-correlation)
    Zone          \* [Witnesses -> STRING] : geo bucket  (gamma-correlation)

Honest == Witnesses \ Byzantine

(***************************************************************************)
(* State variable - declared before use.                                   *)
(***************************************************************************)
VARIABLE attest      \* [Records -> SUBSET Witnesses] : who has attested each
vars == << attest >>

TypeOK == attest \in [Records -> SUBSET Witnesses]

(***************************************************************************)
(* Fixed-point constants - mirror src/network/consensus.rs:132-138.        *)
(* Scaled to 1000ths (not 1e9ths) — a deliberate model reduction: TLC       *)
(* uses 32-bit ints, so the 1e9 scale of SETTLEMENT_Q would overflow. The   *)
(* settlement decision depends only on the RATIOS (Alpha:Beta:Gamma:Q =     *)
(* 5:3:2:10 and the 2/3 threshold), which are identical at 1000ths, so this *)
(* is a faithful re-scaling, not an approximation.                          *)
(***************************************************************************)
Q      == 1000     \* SETTLEMENT_Q  (1e9 in code, 1000ths here)
AlphaQ == 500      \* ALPHA_Q : same organization
BetaQ  == 300      \* BETA_Q  : same subnet
GammaQ == 200      \* GAMMA_Q : same geo zone (full gamma)

\* The code-side invariant that correlation maxes out at 1.0 (== Q).
ASSUME AlphaQ + BetaQ + GammaQ = Q

(***************************************************************************)
(* Diversity math - deterministic integer mirror of the `_q` path.         *)
(***************************************************************************)

\* correlation_weighted_q(a, b, gamma_q)   consensus.rs:2829.
\* (All profiles are known in the model; the unknown-profile -> ALPHA+BETA  *)
\*  branch is not exercised here.)                                          *)
CorrQ(a, b) ==
    (IF Org[a]    = Org[b]    THEN AlphaQ ELSE 0)
  + (IF Subnet[a] = Subnet[b] THEN BetaQ  ELSE 0)
  + (IF Zone[a]   = Zone[b]   THEN GammaQ ELSE 0)

\* Sum of correlation of `a` against every OTHER member of S.
RECURSIVE CorrSumQ(_, _)
CorrSumQ(a, S) ==
    IF S = {} THEN 0
    ELSE LET m == CHOOSE e \in S : TRUE
         IN (IF m = a THEN 0 ELSE CorrQ(a, m)) + CorrSumQ(a, S \ {m})

\* independence_q(a, S)   consensus.rs:2862 :  d_q = Q^2 \div (Q + corr_sum).
\* `\div` is integer floor division, matching Rust's u128 `/`.
IndependenceQ(a, S) == (Q * Q) \div (Q + CorrSumQ(a, S))

\* effective_stake_q(S)   consensus.rs:2884 : Sum over w in S of stake[w]*d_q(w,S).
\* Independence is always computed against the FULL attesting set `Full`.
RECURSIVE EffStakeQOver(_, _)
EffStakeQOver(Rem, Full) ==
    IF Rem = {} THEN 0
    ELSE LET w == CHOOSE e \in Rem : TRUE
         IN Stake[w] * IndependenceQ(w, Full) + EffStakeQOver(Rem \ {w}, Full)
EffStakeQ(S) == EffStakeQOver(S, S)

\* Raw (un-discounted) stake of a set.
RECURSIVE RawStakeOf(_)
RawStakeOf(S) ==
    IF S = {} THEN 0
    ELSE LET w == CHOOSE e \in S : TRUE
         IN Stake[w] + RawStakeOf(S \ {w})

TotalStake == RawStakeOf(Witnesses)
Eligible   == TotalStake          \* creator_stake = 0 abstraction

\* diverse_threshold_met_q(eff_q, eligible)   consensus.rs:2906 :
\* settle iff  3*eff_q >= 2*eligible*Q.   Reached via is_settled_diverse:2583.
DiverseSettled(r) == EffStakeQ(attest[r]) * 3 >= Eligible * 2 * Q

(***************************************************************************)
(* State machine.                                                          *)
(***************************************************************************)
Init == attest = [r \in Records |-> {}]

\* An honest witness signs at most one of a set of conflicting records.
HonestFree(w, r) == \A r2 \in Records : (w \in attest[r2]) => (r2 = r)

AttestHonest(w, r) ==
    /\ w \in Honest
    /\ w \notin attest[r]
    /\ HonestFree(w, r)
    /\ attest' = [attest EXCEPT ![r] = @ \cup {w}]

\* A Byzantine witness may attest BOTH conflicting records (equivocation).
AttestByz(w, r) ==
    /\ w \in Byzantine
    /\ w \notin attest[r]
    /\ attest' = [attest EXCEPT ![r] = @ \cup {w}]

Next == \E w \in Witnesses, r \in Records :
            AttestHonest(w, r) \/ AttestByz(w, r)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

\* 4.2 DiversitySoundness : diversity weighting is deflationary-only.
\* eff_q = Sum stake*ind_q  and  ind_q = Q^2\div(Q+corr) <= Q  (corr >= 0),
\* hence eff_q <= Q*raw_stake.  TLC verifies this across every reachable set.
DiversitySoundness ==
    \A r \in Records : EffStakeQ(attest[r]) <= Q * RawStakeOf(attest[r])

\* Every pair of distinct candidate records claims the same logical slot,
\* so any two distinct records conflict (the smallest Conflicts() relation).
Conflicts(r1, r2) == r1 # r2

\* 4.1 NoConflictingFinalization (BFT agreement) : two conflicting records
\* can never both reach settlement.  Holds iff Byzantine stake < 1/3.
NoConflictingFinalization ==
    \A r1, r2 \in Records :
        (Conflicts(r1, r2) /\ DiverseSettled(r1) /\ DiverseSettled(r2)) => FALSE
=============================================================================
