#!/usr/bin/env bash
# Machine-check the Elara PQ handshake's symbolic security properties (ProVerif).
#
# Mirrors spec/tla/run-tlc.sh: each scenario has an EXPECTED outcome and the
# gate passes iff every scenario produces its expected outcome. One scenario
# (both_broken) is an INTENTIONAL violation — it proves the hybrid claim is
# non-vacuous, exactly like spec/tla/MCTightBreak proves the BFT bound is tight.
# A naive "proverif exit 0" check would be WRONG, so we assert the specific
# RESULT line per scenario.
#
#   baseline       : session-key secrecy + mutual injective authentication   -> all "is true"
#   mlkem_broken   : ML-KEM broken, secrecy still holds (X25519 carries it)  -> probe "is true"
#   x25519_broken  : X25519 broken, secrecy still holds (ML-KEM carries it)  -> probe "is true"
#   both_broken    : BOTH broken, secrecy MUST FAIL (non-vacuity sanity gate)-> probe "is false"
#   forward_secrecy: long-term keys leak AFTER the sessions, secrecy holds   -> probe "is true" (phase 1)
#   forward_secrecy_broken : same sessions but skR known DURING -> MITM       -> probe "is false"
#   kci            : initiator's OWN key skI leaked DURING; secrecy + the     -> probe + InitAcceptResp "true",
#                    I->R injective auth still hold (KCI resistance), while       RespAcceptInit "false"
#                    impersonating the compromised party itself fails
#   kci_broken     : kci world but the PINNED-PEER key skR ALSO leaked -> MITM -> probe "is false"
#   uks            : UKS / identity-misbinding. TWO honest initiators I, I2 both -> both RespAcceptInit "true",
#                    pinning R: the accept-any responder never cross-attributes      probe "is true"
#                    one initiator's session to the other honest identity
#   uks_broken     : same world, I2's key skI2 leaked -> I's attribution holds  -> RespAcceptInit(skI) "true",
#                    (cross-key separation), I2's is falsifiable (non-vacuity)      RespAcceptInit(skI2) "false"
#   uks_broken_sym : mirror, skI leaked -> witnesses RespAcceptInit(skI)        -> RespAcceptInit(skI) "false",
#                    reachable; I2's attribution holds                              RespAcceptInit(skI2) "true"
#
# Post-handshake RECORD/STREAM protocol (core = elara_record_core.pvi):
#   record_baseline          : payload secrecy + injective agreement (anti-replay -> both "is true"
#                              /reorder/integrity) for the strictly-sequential receiver
#   record_nonce_reuse       : reuse the counter -> replay reappears               -> inj-agreement "is false"
#   record_direction         : two-key direction separation, both directions agree -> both "is true"
#   record_direction_confusion : k_send=k_recv -> reflection accepted              -> both "is false"
#   record_no_aead           : plaintext, no AEAD -> forgery + disclosure          -> inj "false" + secrecy "false"
#   record_type_binding      : frame TYPE bound into AD -> Data->Admission relabel -> misroute "is true" (unreachable)
#                              cannot misroute an authenticated payload
#   record_type_binding_broken : empty AD (pre-fix) -> relabel misroutes           -> misroute "is false" (reachable)
#   record_close_unauth      : unauthenticated Close -> forged teardown (the       -> CloseRecv<=CloseSent "is false"
#                              truncation boundary; injective agreement is safety,     (INTENTIONAL, documents the gap)
#                              not delivery — see README scope note)
#
# FULL COMPOSITION (core = elara_composed_core.pvi): the record key is the GENUINE
# handshake output kdf_send/kdf_recv(dh_ss,kem_ss,t2), not a fresh name.
#   composed_baseline        : record secrecy + record anti-replay (R->I, the      -> all four "is true"
#                              attributable direction) + BOTH handshake-auth
#                              directions, all under the genuine derived key
#   composed_broken          : leak both ephemeral secrets -> attacker forges a     -> RtoI agreement
#                              Record B the initiator accepts -> composed record         "is false"
#                              anti-replay FAILS (record integrity is bound to the      (non-vacuity;
#                              breakable handshake key, non-vacuity)                      see README)
#
# REALM ADMISSION (core = elara_admission_core.pvi): post-handshake membership-cert
# exchange. The cert binds the HANDSHAKE-authenticated peer identity to the
# federation root; integrity = Admitted(mid) ==> RootIssued(mid). Cert presented in
# CLEARTEXT (strongest attacker; validates realm.rs "needn't ride in the transcript").
#   admission_baseline       : root-sig + realm match + identity binding intact   -> Admitted=>RootIssued
#                              -> every admitted id was issued by the root             "is true"
#   admission_forge_broken   : realm ROOT SECRET KEY leaks -> attacker forges a    -> "is false"
#                              cert for its own id (unforgeability load-bearing)       (non-vacuity)
#   admission_bind_broken    : identity binding DROPPED -> stolen valid cert        -> "is false"
#                              admits the wrong (handshake) id (binding load-bearing)  (non-vacuity)
#   admission_cross_realm    : attacker fully OWNS a foreign federation root, yet   -> "is true"
#                              a realm-B cert never verifies against our root            (realm isolation)
#
# The handshake body has a single source of truth (elara_handshake_core.pvi);
# each scenario header in scenarios/*.pvh adds only its queries + top process.
# The record scenarios deliberately VARY their body (nonce reuse, no-AEAD,
# empty-AD) to make each non-vacuity twin, so elara_record_core.pvi shares only
# the AEAD primitives + cleartext frame-type tags; each record_*.pvh carries its
# own sender/receiver processes.
# Model<->code correspondence: README.md (this directory).
#
# Usage: ./run-proverif.sh
# Env:   PROVERIF_BIN=/path/to/proverif   to use a specific binary.
# Verified against ProVerif 2.05.
set -uo pipefail

cd "$(dirname "$0")"
CORE="elara_handshake_core.pvi"
RECORD_CORE="elara_record_core.pvi"
COMPOSED_CORE="elara_composed_core.pvi"
ADMISSION_CORE="elara_admission_core.pvi"

# --- locate proverif -------------------------------------------------------
PV="${PROVERIF_BIN:-$(command -v proverif 2>/dev/null || true)}"
if [ -z "$PV" ] && [ -x "$HOME/.opam/elarapv/bin/proverif" ]; then
  PV="$HOME/.opam/elarapv/bin/proverif"
fi
if [ -z "$PV" ]; then
  echo "FAIL: proverif not found."
  echo "  Install: apt-get install -y opam && opam init --bare -y --disable-sandboxing \\"
  echo "           && opam switch create elarapv ocaml-system && opam install -y proverif"
  echo "  Or set PROVERIF_BIN=/path/to/proverif. See README.md."
  exit 2
fi
echo "Using proverif: $PV"
"$PV" -help 2>&1 | head -1 | sed 's/^/  /'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# run_scenario <name> <mode>
#   mode = all_true     : >=3 RESULTs, none "is false"
#          secret_true  : the probe-secrecy RESULT is "is true"
#          secret_false : the probe-secrecy RESULT is "is false" (intentional)
#          fs_true      : the phase-1 probe-secrecy RESULT (attacker_p1, the
#                         post-session long-term-key attacker) is "is true" —
#                         forward secrecy holds
#          kci          : KCI battery — probe secrecy "is true" AND the
#                         InitAcceptResp injective auth "is true" AND the
#                         RespAcceptInit injective auth "is false" (an attacker
#                         holding skI can impersonate ONLY the compromised party).
#                         Matched by EVENT NAME, not a bare "is false" grep, so a
#                         regressed-true auth query cannot satisfy the false check.
run_scenario() {
  local name="$1" mode="$2" core="${3:-$CORE}"
  cat "$core" "scenarios/$name.pvh" > "$TMP/$name.pv"
  local out; out="$("$PV" -in pitype "$TMP/$name.pv" 2>&1)"
  local results; results="$(printf '%s\n' "$out" | grep '^RESULT' || true)"
  echo "--- $name ---"
  printf '%s\n' "$results" | sed 's/^/  /'

  if printf '%s\n' "$out" | grep -qiE 'Error|Internal error'; then
    echo "  FAIL($name): proverif reported an error"; fails=$((fails+1)); return
  fi
  if [ -z "$results" ]; then
    echo "  FAIL($name): no RESULT lines"; fails=$((fails+1)); return
  fi

  case "$mode" in
    all_true)
      if printf '%s\n' "$results" | grep -q 'is false'; then
        echo "  FAIL($name): expected every property to hold, got a false"; fails=$((fails+1)); return
      fi
      if [ "$(printf '%s\n' "$results" | grep -c 'is true')" -lt 3 ]; then
        echo "  FAIL($name): expected >=3 properties true"; fails=$((fails+1)); return
      fi ;;
    secret_true)
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected session-key secrecy to HOLD"; fails=$((fails+1)); return
      fi ;;
    secret_false)
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is false'; then
        echo "  FAIL($name): expected session-key secrecy to FAIL (non-vacuity gate)"; fails=$((fails+1)); return
      fi ;;
    fs_true)
      if ! printf '%s\n' "$results" | grep -q 'not attacker_p1(probe\[\]) is true'; then
        echo "  FAIL($name): expected forward secrecy to HOLD (phase-1 attacker cannot derive probe)"; fails=$((fails+1)); return
      fi ;;
    kci)
      # (1) session-key secrecy HOLDS despite the initiator's own key being public
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected KCI session-key secrecy to HOLD under skI compromise"; fails=$((fails+1)); return
      fi
      # (2) initiator still injectively authenticates the honest pinned responder.
      #     Match the InitAcceptResp query line specifically (its LHS event name is
      #     unique to this query) and require it true.
      if ! printf '%s\n' "$results" | grep 'inj-event(InitAcceptResp' | grep -q 'is true'; then
        echo "  FAIL($name): expected initiator->responder injective auth to HOLD under skI compromise"; fails=$((fails+1)); return
      fi
      # (3) the attacker holding skI CAN impersonate the compromised party itself to
      #     the accept-any responder — key-disclosure impersonation, NOT a KCI
      #     violation — so this query MUST fail. Match the inj-event(RespAcceptInit
      #     line (distinct from the parenthetical non-injective note) and require false.
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit' | grep -q 'is false'; then
        echo "  FAIL($name): expected responder->initiator auth to FAIL (compromised-party impersonation)"; fails=$((fails+1)); return
      fi ;;
    uks)
      # Multi-principal UKS-freedom: R never cross-attributes a session between the
      # two honest initiators. Match each identity's RespAcceptInit line by its
      # BRACKETED name (spk(skI[]) vs spk(skI2[]) + trailing comma) so the two lines
      # cannot be confused, and require both true. Session-key secrecy also holds.
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI\[\]),' | grep -q 'is true'; then
        echo "  FAIL($name): expected UKS-freedom for I (no misbinding) to HOLD"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI2\[\]),' | grep -q 'is true'; then
        echo "  FAIL($name): expected UKS-freedom for I2 (no misbinding) to HOLD"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected multi-principal session-key secrecy to HOLD"; fails=$((fails+1)); return
      fi ;;
    uks_broken)
      # Same world as uks, skI2 leaked. I's attribution unaffected (cross-key
      # signature separation), I2's attribution falsifiable (non-vacuity witness for
      # RespAcceptInit(skI2)), secrecy intact. Matched by event NAME like the kci mode.
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI\[\]),' | grep -q 'is true'; then
        echo "  FAIL($name): expected I's attribution to HOLD despite skI2 leak"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI2\[\]),' | grep -q 'is false'; then
        echo "  FAIL($name): expected I2's attribution to FAIL (skI2 leaked — non-vacuity gate)"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected session-key secrecy to HOLD (responder side emits no probe)"; fails=$((fails+1)); return
      fi ;;
    uks_broken_sym)
      # Mirror of uks_broken: skI leaked. I's attribution falsifiable (witnesses
      # RespAcceptInit(skI) reachable -> Q_I non-vacuous in uks), I2's attribution holds.
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI\[\]),' | grep -q 'is false'; then
        echo "  FAIL($name): expected I's attribution to FAIL (skI leaked — reachability witness)"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RespAcceptInit(spk(skI2\[\]),' | grep -q 'is true'; then
        echo "  FAIL($name): expected I2's attribution to HOLD despite skI leak"; fails=$((fails+1)); return
      fi ;;
    # ---- post-handshake record-layer scenarios (core = elara_record_core.pvi) ----
    rec_baseline)
      # Anti-replay/reorder (injective Recv<=Send) AND payload secrecy both HOLD.
      if ! printf '%s\n' "$results" | grep 'inj-event(Recv(' | grep -q 'is true'; then
        echo "  FAIL($name): expected record injective agreement (anti-replay) to HOLD"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected record payload secrecy to HOLD"; fails=$((fails+1)); return
      fi ;;
    rec_inj_false)
      # Non-vacuity twin (nonce reuse): the injective Recv<=Send query FAILS.
      # Match the inj-event line specifically — the parenthetical non-injective
      # note prints "event(Recv(", not "inj-event(Recv(", so it can't be confused.
      if ! printf '%s\n' "$results" | grep 'inj-event(Recv(' | grep -q 'is false'; then
        echo "  FAIL($name): expected injective agreement to FAIL under nonce reuse (non-vacuity gate)"; fails=$((fails+1)); return
      fi ;;
    rec_dir_true)
      # Direction separation: BOTH directions injectively agree.
      if ! printf '%s\n' "$results" | grep 'inj-event(RecvIR(' | grep -q 'is true'; then
        echo "  FAIL($name): expected I->R direction agreement to HOLD"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RecvRI(' | grep -q 'is true'; then
        echo "  FAIL($name): expected R->I direction agreement to HOLD"; fails=$((fails+1)); return
      fi ;;
    rec_dir_false)
      # Non-vacuity twin (k_send=k_recv): reflection breaks BOTH directions.
      if ! printf '%s\n' "$results" | grep 'inj-event(RecvIR(' | grep -q 'is false'; then
        echo "  FAIL($name): expected I->R agreement to FAIL when direction keys collapse"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RecvRI(' | grep -q 'is false'; then
        echo "  FAIL($name): expected R->I agreement to FAIL when direction keys collapse"; fails=$((fails+1)); return
      fi ;;
    rec_noaead)
      # Non-vacuity twin (plaintext, no AEAD): forgery AND payload disclosure.
      if ! printf '%s\n' "$results" | grep 'inj-event(Recv(' | grep -q 'is false'; then
        echo "  FAIL($name): expected agreement to FAIL without AEAD (forgery)"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is false'; then
        echo "  FAIL($name): expected payload secrecy to FAIL without AEAD (non-vacuity gate)"; fails=$((fails+1)); return
      fi ;;
    rec_type_true)
      # Type-dispatch integrity (the fix): the misroute event is UNREACHABLE.
      if ! printf '%s\n' "$results" | grep 'event(AdmissionDispatched(' | grep -q 'is true'; then
        echo "  FAIL($name): expected type-dispatch integrity to HOLD (misroute unreachable)"; fails=$((fails+1)); return
      fi ;;
    rec_type_false)
      # Non-vacuity twin (empty AD, pre-fix): the misroute event FIRES.
      if ! printf '%s\n' "$results" | grep 'event(AdmissionDispatched(' | grep -q 'is false'; then
        echo "  FAIL($name): expected misroute to be REACHABLE without type binding (non-vacuity gate)"; fails=$((fails+1)); return
      fi ;;
    rec_close_false)
      # Intended failure: unauthenticated Close => forged teardown accepted.
      if ! printf '%s\n' "$results" | grep 'inj-event(CloseRecv(' | grep -q 'is false'; then
        echo "  FAIL($name): expected forged Close to be accepted (documents truncation gap)"; fails=$((fails+1)); return
      fi ;;
    composed_all_true)
      # Full composition (core = elara_composed_core.pvi): record secrecy +
      # record anti-replay (R->I, attributable) + BOTH handshake-auth directions,
      # all under the GENUINE handshake-derived record key. As all_true but the
      # auth lines are explicitly matched so a regressed false cannot hide.
      if printf '%s\n' "$results" | grep -q 'is false'; then
        echo "  FAIL($name): composed property regressed to false"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep -q 'not attacker(probe\[\]) is true'; then
        echo "  FAIL($name): expected composed record secrecy to HOLD under the genuine key"; fails=$((fails+1)); return
      fi
      if ! printf '%s\n' "$results" | grep 'inj-event(RtoI_Recv(' | grep -q 'is true'; then
        echo "  FAIL($name): expected composed record anti-replay to HOLD under the genuine key"; fails=$((fails+1)); return
      fi
      if [ "$(printf '%s\n' "$results" | grep -c 'is true')" -lt 4 ]; then
        echo "  FAIL($name): expected all four composed properties true"; fails=$((fails+1)); return
      fi ;;
    composed_nonvacuity)
      # Non-vacuity twin: leaking BOTH ephemeral secrets lets the attacker
      # reconstruct the record key and FORGE a Record B the initiator accepts, so
      # the composed record-layer injective agreement FAILS — proving record
      # integrity is bound to the breakable handshake key, not a fresh name.
      # Matched by the inj-event(RtoI_Recv line (the parenthetical non-injective
      # note prints "event(RtoI_Recv(", so it cannot be confused) and required
      # false. (The companion secrecy goal is also reachable but ProVerif's
      # generic-KEM term yields a non-deterministic "cannot be proved" there; the
      # clean reconstructed secrecy-false lives in handshake both_broken.)
      if ! printf '%s\n' "$results" | grep 'inj-event(RtoI_Recv(' | grep -q 'is false'; then
        echo "  FAIL($name): expected record anti-replay to FAIL once ephemeral secrets leak (composition non-vacuity)"; fails=$((fails+1)); return
      fi ;;
    # ---- realm-admission scenarios (core = elara_admission_core.pvi) -------------
    adm_holds)
      # Admission integrity HOLDS: every admitted (handshake-authenticated)
      # identity was genuinely issued a membership cert by the federation root.
      # Match the correspondence query line by its LHS event name and require true.
      if ! printf '%s\n' "$results" | grep 'event(Admitted(' | grep -q 'is true'; then
        echo "  FAIL($name): expected admission integrity (Admitted ==> RootIssued) to HOLD"; fails=$((fails+1)); return
      fi ;;
    adm_fails)
      # Non-vacuity twin: the correspondence FAILS — the attacker is admitted as
      # an identity the root never issued (forged cert, or stolen cert with the
      # binding dropped). Also witnesses Admitted reachable ⇒ adm_holds is
      # non-vacuous.
      if ! printf '%s\n' "$results" | grep 'event(Admitted(' | grep -q 'is false'; then
        echo "  FAIL($name): expected admission integrity to FAIL (non-vacuity gate)"; fails=$((fails+1)); return
      fi ;;
  esac
  echo "  OK($name)"
}

run_scenario baseline             all_true
run_scenario mlkem_broken         secret_true
run_scenario x25519_broken        secret_true
run_scenario both_broken          secret_false
run_scenario forward_secrecy      fs_true
run_scenario forward_secrecy_broken secret_false
run_scenario kci                  kci
run_scenario kci_broken           secret_false
run_scenario uks                  uks
run_scenario uks_broken           uks_broken
run_scenario uks_broken_sym       uks_broken_sym

# Post-handshake record/stream protocol (core = elara_record_core.pvi).
run_scenario record_baseline             rec_baseline   "$RECORD_CORE"
run_scenario record_nonce_reuse          rec_inj_false  "$RECORD_CORE"
run_scenario record_direction            rec_dir_true   "$RECORD_CORE"
run_scenario record_direction_confusion  rec_dir_false  "$RECORD_CORE"
run_scenario record_no_aead              rec_noaead     "$RECORD_CORE"
run_scenario record_type_binding         rec_type_true  "$RECORD_CORE"
run_scenario record_type_binding_broken  rec_type_false "$RECORD_CORE"
run_scenario record_close_unauth         rec_close_false "$RECORD_CORE"

# Full composition: handshake ∘ record layer, record key = genuine handshake
# output (core = elara_composed_core.pvi).
run_scenario composed_baseline           composed_all_true   "$COMPOSED_CORE"
run_scenario composed_broken             composed_nonvacuity "$COMPOSED_CORE"

# Realm admission: post-handshake membership-cert exchange. The cert binds the
# handshake-authenticated peer identity to the federation root (core =
# elara_admission_core.pvi). Admitted ==> RootIssued.
run_scenario admission_baseline          adm_holds  "$ADMISSION_CORE"
run_scenario admission_forge_broken      adm_fails  "$ADMISSION_CORE"
run_scenario admission_bind_broken       adm_fails  "$ADMISSION_CORE"
run_scenario admission_cross_realm       adm_holds  "$ADMISSION_CORE"

echo
if [ "$fails" -eq 0 ]; then
  echo "PASS: all 25 ProVerif scenarios produced their expected outcomes."
  exit 0
else
  echo "FAILED: $fails scenario(s) did not match expected outcomes."
  exit 1
fi
