----------------------------- MODULE Liveness -----------------------------
(***************************************************************************)
(* TLA+ LIVENESS model of Elara's IN-ZONE epoch-seal production            *)
(* ("Phase E.2" — spec/tla/README.md, EventualFinalization row).           *)
(* The complement to Phase E (ElaraXZoneLive.tla): Phase E proves a        *)
(* CROSS-ZONE sealed transfer eventually reaches a terminal state; this     *)
(* proves a single zone eventually PRODUCES the epoch seal in the first     *)
(* place (the precondition Phase E folds into `Sealed == TRUE`).            *)
(*                                                                         *)
(* THE IN-ZONE MECHANISM IS A HYBRID (src/network/aggregator.rs +           *)
(* consensus.rs), faithfully NOT textbook leader+view-change:               *)
(*                                                                         *)
(*   1. PROPOSAL — a VRF-stake RANK LADDER. proposer_rank (aggregator.rs:   *)
(*      290) ranks staked identities by hash(vrf||zone||id)/isqrt(stake);   *)
(*      rank-k becomes ELIGIBLE only once elapsed >= (2^k - 1)*base_timeout  *)
(*      (current_allowed_rank), up to MAX_VIEW_DEPTH = 7 ranks. Lower rank   *)
(*      = earlier eligibility.                                              *)
(*   2. SETTLEMENT — a LEADERLESS 2/3 attestation snapshot. is_settled      *)
(*      (consensus.rs:2515) / is_global_seal_settled (:4134): a seal        *)
(*      finalizes when attestations reach 2/3 of eligible (non-creator)     *)
(*      stake. ANY honest witness may attest; the proposer's identity is    *)
(*      irrelevant to settlement.                                          *)
(*   3. STALL RECOVERY — NOT view-change messages. The ladder unlocks       *)
(*      higher ranks purely by elapsed time. If ALL ranks time out          *)
(*      (elapsed > (2^7 - 1)*base, is_zone_stuck aggregator.rs:224) a        *)
(*      CROSS-ZONE GLOBAL ESCALATION fires (escalation_decision :350):       *)
(*      honest anchors in OTHER zones emit a global quorum seal that         *)
(*      unsticks the zone. That escalation is itself a 2/3 quorum of         *)
(*      non-stuck zones, so it needs cross-zone gossip (global GST) and      *)
(*      global f < 1/3.                                                     *)
(*                                                                         *)
(* THREE GUARANTEES, captured as two checked properties across discrimina-  *)
(* ting scenarios (mirroring Phase E's LiveFast/LiveBackstop split):        *)
(*                                                                         *)
(*   LiveLocal == <>LocalSealed   (escalation OUT of scope)                 *)
(*     The committee path. Holds iff SOME honest rank is eligible AND the    *)
(*     honest attesting stake can reach 2/3 AND local GST arrives. Covers    *)
(*     both the FAST sub-case (rank-0 honest: MCInZoneLiveSafe) and the      *)
(*     LADDER sub-case (rank-0 Byzantine, a later rank honest:               *)
(*     MCInZoneLiveLadder still HOLDS — the ladder reaches the honest rank   *)
(*     by elapsed-unlock). FAILS with no GST (FLP), all ranks Byzantine, or  *)
(*     honest attesting stake < 2/3.                                        *)
(*                                                                         *)
(*   LiveWithEscalation == <>sealed   (escalation IN scope)                 *)
(*     Adds the cross-zone escalation backstop: even with ALL local         *)
(*     proposers Byzantine, the zone still seals IF global GST holds and a   *)
(*     2/3-honest cross-zone quorum exists. Models the escalation as an      *)
(*     EXPLICIT external-anchor committee (ExternalAnchors / ByzExt /        *)
(*     extGst / QuorumExt) — NOT a `globalQuorumHealthy` flag, which would   *)
(*     make the property a two-state tautology that assumes the very        *)
(*     cross-zone liveness it should depend on.                            *)
(*                                                                         *)
(* THE KEY ASYMMETRY vs Phase E (the headline honest finding). Phase E's     *)
(* LiveBackstop is UNCONDITIONAL — the quorum-FREE 30-day reaper REFUNDS a   *)
(* stuck transfer with no quorum at all. IN-ZONE LIVENESS HAS NO SUCH        *)
(* FLOOR: an epoch seal IS a 2/3 quorum certificate, so it cannot be         *)
(* produced without a quorum. The weakest sufficient condition for          *)
(* <>sealed is therefore global GST + global f < 1/3 (the escalation path,   *)
(* MCInZoneLiveNoEscGST / MCInZoneLiveEscByz both VIOLATE it). If those      *)
(* fail AND every local proposer is Byzantine, the zone is stuck            *)
(* indefinitely. In-zone liveness is fundamentally quorum-dependent;        *)
(* "Byzantine/asynchrony can deny the fast path but cannot deny the reap"    *)
(* (Phase E) has NO in-zone analogue.                                      *)
(*                                                                         *)
(* THE BOOTSTRAP FREEZE TRAP (the one scenario NOTHING rescues). When        *)
(* staked.len() < 3, the carve-out at aggregator.rs:755 collapses the        *)
(* ladder: ONLY the genesis authority may propose, and escalation has no     *)
(* bootstrap path (escalation_decision :346). MCInZoneLiveBootstrap models   *)
(* this as HonestRanks = {} (Byzantine genesis) + EscalationAvailable =      *)
(* FALSE: LiveWithEscalation is VIOLATED with no safety net. This is the     *)
(* formal statement of the operational invariant "never sit at 2 stakers;    *)
(* re-genesis 1 -> 3 atomically" (memory: proposer freeze-trap carve-out).   *)
(*                                                                         *)
(* CROSS-EPOCH NOTE (single-epoch model -> chain recurrence). This spec      *)
(* checks ONE epoch's seal. A single epoch can be adversarially stuck (all   *)
(* low ranks Byzantine), needing escalation. CHAIN progress — every epoch    *)
(* eventually seals, []<>sealed — rests on the CHAINED VRF BEACON            *)
(* chained_beacon(prev_seal_hash, epoch, zone) (aggregator.rs:310): the      *)
(* proposer ranks RE-RANDOMIZE every epoch off the previous seal hash, so    *)
(* an adversary cannot GRIND or SUSTAIN a worst-case rank assignment across  *)
(* epochs. The worst-case single epoch modelled here is therefore an upper   *)
(* bound on per-epoch stall; cross-epoch []<>sealed (every epoch seals, AND  *)
(* the FAST local path recurs because the beacon re-randomizes ranks so a    *)
(* worst-case assignment cannot be sustained) is now machine-checked in      *)
(* LivenessRecurrence.tla (Phase E.3) — see that module + the README.        *)
(*                                                                         *)
(* DELIBERATE ABSTRACTIONS (documented, same epistemic status as Phase E):   *)
(*   - WITHHOLDING. Byzantine proposers have NO action (they withhold).      *)
(*     A Byzantine proposal that honest witnesses verify and attest is       *)
(*     indistinguishable from an honest seal and settles the epoch anyway    *)
(*     (a liveness SUCCESS), so the only liveness-relevant Byzantine         *)
(*     proposer strategy is silence. Honest witnesses attest only the        *)
(*     canonical honest candidate (`proposedByHonest`).                     *)
(*   - SINGLE CANONICAL CANDIDATE. Real ranks can each emit a competing      *)
(*     seal; the weight-reconciliation (register_seal_with_reconcile /       *)
(*     promote_orphan_to_canonical, the same device Conservation.tla         *)
(*     models) collapses them to one canonical seal post-GST. We model that  *)
(*     single canonical candidate; the pre-GST multi-candidate attestation-  *)
(*     split is the documented deferred extension (the in-zone analogue of   *)
(*     Phase E's `claimGossiped` branch).                                   *)
(*   - creator_stake = 0 (witnesses are not record creators), uniform stake  *)
(*     so raw 2/3 count == diversity-weighted effective stake (the           *)
(*     DiversitySoundness conservative direction: real weighting makes       *)
(*     settlement strictly HARDER, so uniform-stake liveness is a lower      *)
(*     bound) — same conventions as ElaraConsensus.tla.                     *)
(*   - The (2^k - 1)*base elapsed thresholds collapse to a UNIT ladder       *)
(*     (`phase`): only the ORDER of rank unlock matters for liveness, as     *)
(*     Phase E collapses wall-clock to monotone latches.                    *)
(*                                                                         *)
(* DAG / STUTTER NOTE (identical to Phase E). The state machine is monotone- *)
(* growth (phase climbs, sets only grow, booleans only latch) so it          *)
(* TERMINATES; a `<>` check needs an infinite behaviour to be non-vacuous.   *)
(* `Stutter == UNCHANGED vars` is an unconditional self-loop guaranteeing    *)
(* every state has a successor, while per-action WF still forces real        *)
(* progress on every fair behaviour (the stutter-forever behaviours are      *)
(* unfair and excluded). Non-vacuity of each break is the TLC lasso it       *)
(* produces — and DeliverAttest / EscalDeliver are GST-gated precisely so    *)
(* the no-GST breaks produce a genuine never-converging cycle rather than a  *)
(* trivial flag-is-false counterexample.                                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ranks,               \* set of proposer ranks (naturals 0..R-1), VRF-stake ordered
    ByzRanks,            \* SUBSET Ranks : Byzantine proposers (withhold; never fair)
    Witnesses,           \* the local finality committee (attesters)
    ByzWit,              \* SUBSET Witnesses : Byzantine local attesters (withhold)
    GstReachable,        \* BOOLEAN : does LOCAL GST ever arrive?
    ExternalAnchors,     \* the cross-zone escalation committee (other zones' anchors)
    ByzExt,              \* SUBSET ExternalAnchors : Byzantine escalation anchors (withhold)
    ExtGstReachable,     \* BOOLEAN : does GLOBAL / cross-zone GST ever arrive?
    EscalationAvailable  \* BOOLEAN : is the cross-zone escalation path in scope?
                         \*   FALSE = escalation out of scope (LiveLocal) OR the
                         \*   staked<3 bootstrap carve-out (no escalation path).

HonestRanks == Ranks \ ByzRanks
HonestWit   == Witnesses \ ByzWit
HonestExt   == ExternalAnchors \ ByzExt
NumRanks    == Cardinality(Ranks)

VARIABLES
    phase,            \* monotone time latch 0..NumRanks (rank-unlock ladder + escalation)
    proposedByHonest, \* an honest eligible rank emitted THE canonical seal candidate
    attest,           \* local honest witnesses that attested the canonical seal
    gst,              \* local GST latch
    extGst,           \* cross-zone GST latch
    extAttest,        \* honest external anchors that attested the escalation seal
    escalated,        \* the escalation seal (not the local committee) produced the terminal
    sealed            \* TERMINAL: the epoch seal is finalized

vars == << phase, proposedByHonest, attest, gst, extGst, extAttest, escalated, sealed >>

\* Rank k is eligible once the ladder has climbed to it. Faithful order-preserving
\* abstraction of elapsed >= (2^k - 1)*base_timeout: only the ORDER matters.
RankEligible(k) == phase >= k
\* Escalation is eligible only AFTER the whole local ladder is exhausted
\* (is_zone_stuck: elapsed > (2^MAX_VIEW_DEPTH - 1)*base, aggregator.rs:224).
EscalEligible   == phase >= NumRanks

\* Count-based 2/3 quorums. Local == is_settled (uniform stake, creator_stake=0).
\* External == the cross-zone non-stuck-zone quorum behind the escalation seal.
Quorum(S)    == Cardinality(S) * 3 >= Cardinality(Witnesses) * 2
QuorumExt(S) == Cardinality(S) * 3 >= Cardinality(ExternalAnchors) * 2

LocalSealed == sealed /\ ~escalated   \* sealed by the local committee, not escalation

TypeOK ==
    /\ phase \in 0..NumRanks
    /\ proposedByHonest \in BOOLEAN
    /\ attest \in SUBSET Witnesses
    /\ gst \in BOOLEAN
    /\ extGst \in BOOLEAN
    /\ extAttest \in SUBSET ExternalAnchors
    /\ escalated \in BOOLEAN
    /\ sealed \in BOOLEAN

Init ==
    /\ phase = 0
    /\ proposedByHonest = FALSE
    /\ attest = {}
    /\ gst = FALSE
    /\ extGst = FALSE
    /\ extAttest = {}
    /\ escalated = FALSE
    /\ sealed = FALSE

(***************************************************************************)
(* Time + synchrony latches (monotone). Tick climbs the rank ladder; the    *)
(* two GST latches are gated on their reachability flag so the no-GST        *)
(* scenarios keep them FALSE forever.                                       *)
(***************************************************************************)
Tick ==
    /\ phase < NumRanks
    /\ ~sealed
    /\ phase' = phase + 1
    /\ UNCHANGED << proposedByHonest, attest, gst, extGst, extAttest, escalated, sealed >>

ReachGST ==
    /\ GstReachable /\ ~gst
    /\ gst' = TRUE
    /\ UNCHANGED << phase, proposedByHonest, attest, extGst, extAttest, escalated, sealed >>

ReachExtGST ==
    /\ ExtGstReachable /\ ~extGst
    /\ extGst' = TRUE
    /\ UNCHANGED << phase, proposedByHonest, attest, gst, extAttest, escalated, sealed >>

(***************************************************************************)
(* Local committee path. Honest eligible rank emits the canonical seal;     *)
(* Byzantine ranks have NO action (withholding abstraction). Attestation is  *)
(* GST-gated gossip delivery as a WF obligation (cf. Phase E DeliverClaim).  *)
(***************************************************************************)
HonestPropose(k) ==
    /\ k \in HonestRanks
    /\ RankEligible(k)
    /\ ~proposedByHonest
    /\ ~sealed
    /\ proposedByHonest' = TRUE
    /\ UNCHANGED << phase, attest, gst, extGst, extAttest, escalated, sealed >>

DeliverAttest(w) ==
    /\ w \in HonestWit
    /\ gst
    /\ proposedByHonest
    /\ w \notin attest
    /\ ~sealed
    /\ attest' = attest \cup {w}
    /\ UNCHANGED << phase, proposedByHonest, gst, extGst, extAttest, escalated, sealed >>

Settle ==
    /\ proposedByHonest
    /\ Quorum(attest)
    /\ ~sealed
    /\ sealed' = TRUE
    /\ escalated' = FALSE
    /\ UNCHANGED << phase, proposedByHonest, attest, gst, extGst, extAttest >>

(***************************************************************************)
(* Cross-zone escalation backstop — an EXPLICIT external committee, not a    *)
(* flag. Eligible only after the local ladder is exhausted (EscalEligible)   *)
(* AND cross-zone GST. This makes LiveWithEscalation a genuine REDUCTION to  *)
(* a 2/3 cross-zone quorum (the Phase E shape, one layer up), not an         *)
(* assumed conclusion. There is deliberately NO quorum-free disjunct: an     *)
(* in-zone seal cannot exist without a quorum (the no-floor asymmetry).      *)
(***************************************************************************)
EscalDeliver(a) ==
    /\ EscalationAvailable
    /\ a \in HonestExt
    /\ extGst
    /\ EscalEligible
    /\ a \notin extAttest
    /\ ~sealed
    /\ extAttest' = extAttest \cup {a}
    /\ UNCHANGED << phase, proposedByHonest, attest, gst, extGst, escalated, sealed >>

EscalateSettle ==
    /\ EscalationAvailable
    /\ EscalEligible
    /\ QuorumExt(extAttest)
    /\ ~sealed
    /\ sealed' = TRUE
    /\ escalated' = TRUE
    /\ UNCHANGED << phase, proposedByHonest, attest, gst, extGst, extAttest >>

\* Unconditional self-loop — see DAG/STUTTER NOTE in the header.
Stutter == UNCHANGED vars

Next ==
    \/ Tick \/ ReachGST \/ ReachExtGST \/ Settle \/ EscalateSettle
    \/ \E k \in Ranks           : HonestPropose(k)
    \/ \E w \in Witnesses       : DeliverAttest(w)
    \/ \E a \in ExternalAnchors : EscalDeliver(a)
    \/ Stutter

(***************************************************************************)
(* Fairness. Per-action WF on every PROGRESS action (never WF_vars(Next),    *)
(* which Stutter would satisfy vacuously). WF (not SF) suffices because the   *)
(* state is monotone: once an action's guard holds it stays enabled until    *)
(* the action fires (phase only climbs, sets only grow, latches only set),   *)
(* so weak fairness is enough to discharge it. NO fairness on Byzantine       *)
(* proposers/attesters (they may withhold) and NONE on Stutter.              *)
(***************************************************************************)
Fairness ==
    /\ WF_vars(Tick)
    /\ WF_vars(ReachGST)
    /\ WF_vars(ReachExtGST)
    /\ WF_vars(Settle)
    /\ WF_vars(EscalateSettle)
    /\ \A k \in Ranks           : WF_vars(HonestPropose(k))
    /\ \A w \in Witnesses       : WF_vars(DeliverAttest(w))
    /\ \A a \in ExternalAnchors : WF_vars(EscalDeliver(a))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Liveness properties (bare-variable leaves per the Phase E TLC note: a     *)
(* `<>` predicate built only from parameterized operator-applications        *)
(* mis-levels in TLC's liveness checker, so each leaf is a bare variable).   *)
(* Checked one per model invocation.                                        *)
(***************************************************************************)
LiveLocal          == <>LocalSealed   \* checked with EscalationAvailable = FALSE
LiveWithEscalation == <>sealed         \* checked with EscalationAvailable = TRUE

(* Cheap sanity invariants (must always hold): escalation only ever fires    *)
(* together with the terminal, and only after the local ladder is exhausted. *)
EscalImpliesSealed == escalated => sealed
LadderBeforeEscal  == escalated => (phase >= NumRanks)
=============================================================================
