#!/usr/bin/env bash
# Model-check the Elara MESH-BFT (AWC) consensus settlement core.
#
# Implements the BFT acceptance gate (defined by the TLA+ models in this directory):
#   - MCSafe       : safety + diversity hold (n=5, f=1, correlated pair)   -> NO error
#   - MCTightSafe  : safety holds at the BFT bound (n=4, f=1)              -> NO error
#   - MCTightBreak : agreement BREAKS past the bound (n=4, f=2 > 1/3)      -> EXPECTED violation
#
# The gate passes iff every model produces its EXPECTED outcome. MCTightBreak
# is an intentional violation (it proves the 1/3 threshold is necessary), so a
# naive "tlc exit 0" check would be wrong - we assert the specific outcome.
#
# Usage: ./run-tlc.sh            (downloads tla2tools.jar to a cache if absent)
# Env:   TLA_TOOLS_JAR=/path/to/tla2tools.jar  to use a pre-fetched jar.
set -uo pipefail

cd "$(dirname "$0")"
JAR="${TLA_TOOLS_JAR:-$HOME/.local/share/tlaplus/tla2tools.jar}"
TLA_URL="https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"

if [ ! -s "$JAR" ]; then
  echo "tla2tools.jar not found at $JAR - downloading..."
  mkdir -p "$(dirname "$JAR")"
  curl -fsSL -o "$JAR" "$TLA_URL" || { echo "FAIL: could not download tla2tools.jar"; exit 2; }
fi

META="$(mktemp -d)"
trap 'rm -rf "$META"' EXIT

run() {  # run <module> ; echoes TLC output to stdout, returns nothing
  local m="$1"
  java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
       -deadlock -metadir "$META/$m" -config "$m.cfg" "$m.tla" 2>&1
}

# Liveness models bind a separate .cfg per property (LiveFast / LiveBackstop)
# on top of one scenario .tla. The unconditional `Stutter` disjunct guarantees
# every state has a successor, so -deadlock is moot and TLC evaluates the
# temporal property over genuinely infinite behaviours.
run_cfg() {  # run_cfg <tla-module> <cfg-basename>
  local tla="$1" cfg="$2"
  java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
       -deadlock -metadir "$META/$cfg" -config "$cfg.cfg" "$tla.tla" 2>&1
}

expect_clean() {  # <module>
  local m="$1" out
  out="$(run "$m")"
  if echo "$out" | grep -q "No error has been found"; then
    echo "PASS  $m  (safety holds, $(echo "$out" | grep -oE '[0-9]+ distinct states' | head -1))"
  else
    echo "FAIL  $m  (expected clean run, got:)"; echo "$out" | tail -20; return 1
  fi
}

expect_violation() {  # <module> <invariant>
  local m="$1" inv="$2" out
  out="$(run "$m")"
  if echo "$out" | grep -q "Invariant $inv is violated"; then
    echo "PASS  $m  (expected violation of $inv reproduced - 1/3 bound is tight)"
  else
    echo "FAIL  $m  (expected $inv to be violated, got:)"; echo "$out" | tail -20; return 1
  fi
}

# Phase D breaks are GUARD-NECESSITY (zero Byzantine, partition-reachable), NOT
# Byzantine-threshold tightness — so the PASS message must NOT say "1/3 bound".
expect_guard_violation() {  # <module> <invariant> <guard-name>
  local m="$1" inv="$2" guard="$3" out
  out="$(run "$m")"
  if echo "$out" | grep -q "Invariant $inv is violated"; then
    echo "PASS  $m  (expected violation of $inv reproduced - $guard guard is necessary)"
  else
    echo "FAIL  $m  (expected $inv to be violated, got:)"; echo "$out" | tail -20; return 1
  fi
}

# Phase E liveness: a clean run prints "No error has been found"; a temporal
# break prints "Temporal properties were violated" (NOT the invariant banner the
# Phase A-D helpers match), so liveness needs its own classifiers.
expect_live_clean() {  # <tla> <cfg> <property>
  local tla="$1" cfg="$2" prop="$3" out
  out="$(run_cfg "$tla" "$cfg")"
  if echo "$out" | grep -q "No error has been found"; then
    echo "PASS  $cfg  ($prop holds, $(echo "$out" | grep -oE '[0-9]+ distinct states found' | tail -1))"
  else
    echo "FAIL  $cfg  (expected $prop to hold, got:)"; echo "$out" | tail -20; return 1
  fi
}

expect_live_violation() {  # <tla> <cfg> <property> <reason>
  local tla="$1" cfg="$2" prop="$3" reason="$4" out
  out="$(run_cfg "$tla" "$cfg")"
  if echo "$out" | grep -q "Temporal properties were violated"; then
    echo "PASS  $cfg  (expected violation of $prop reproduced - $reason)"
  else
    echo "FAIL  $cfg  (expected $prop to be violated, got:)"; echo "$out" | tail -20; return 1
  fi
}

echo "=== Elara consensus TLA+ model check (TLC) ==="
rc=0
echo "--- Phase A/B: in-zone settlement core ---"
expect_clean     MCSafe                                    || rc=1
expect_clean     MCTightSafe                               || rc=1
expect_violation MCTightBreak NoConflictingFinalization    || rc=1
echo "--- Phase C: cross-zone sealed-abort / claim mutual exclusion ---"
expect_clean     MCXZoneSafe                               || rc=1
expect_clean     MCXZoneTight                              || rc=1
expect_violation MCXZoneBreak NoAbortAndClaim              || rc=1
expect_clean     MCXZoneUnsealed                           || rc=1
echo "--- Phase D: supply conservation / guard-necessity (zero-Byzantine, partition-reachable) ---"
expect_clean           MCConsSafe                                          || rc=1
expect_guard_violation MCConsRevertBreak SupplyInvariant XZoneRevert       || rc=1
expect_guard_violation MCConsReapBreak   SupplyInvariant reap/claim-exclusion || rc=1
echo "--- Phase E: cross-zone settlement liveness (partial synchrony + GST, 30d reap backstop) ---"
expect_live_clean     MCXZoneLiveSafe      MCXZoneLiveSafe_Fast      LiveFast                                     || rc=1
expect_live_clean     MCXZoneLiveSafe      MCXZoneLiveSafe_Back      LiveBackstop                                 || rc=1
expect_live_violation MCXZoneLiveNoGST     MCXZoneLiveNoGST_Fast     LiveFast     "GST is necessary for the fast path" || rc=1
expect_live_clean     MCXZoneLiveNoGST     MCXZoneLiveNoGST_Back     LiveBackstop                                 || rc=1
expect_live_violation MCXZoneLiveByzStall  MCXZoneLiveByzStall_Fast  LiveFast     "honest >= 2/3 is necessary for the fast path" || rc=1
expect_live_clean     MCXZoneLiveByzStall  MCXZoneLiveByzStall_Back  LiveBackstop                                 || rc=1
echo "--- Phase E.2: IN-ZONE epoch-seal liveness (VRF rank ladder + cross-zone escalation; NO quorum-free floor) ---"
expect_live_clean     MCInZoneLiveSafe      MCInZoneLiveSafe_Local      LiveLocal                                  || rc=1
expect_live_clean     MCInZoneLiveSafe      MCInZoneLiveSafe_Esc        LiveWithEscalation                         || rc=1
expect_live_clean     MCInZoneLiveLadder    MCInZoneLiveLadder_Local    LiveLocal                                  || rc=1
expect_live_clean     MCInZoneLiveLadder    MCInZoneLiveLadder_Esc      LiveWithEscalation                         || rc=1
expect_live_violation MCInZoneLiveNoGST     MCInZoneLiveNoGST_Local     LiveLocal          "local GST is necessary for the committee path" || rc=1
expect_live_clean     MCInZoneLiveNoGST     MCInZoneLiveNoGST_Esc       LiveWithEscalation                         || rc=1
expect_live_violation MCInZoneLiveAllByz    MCInZoneLiveAllByz_Local    LiveLocal          "an honest proposer is necessary for the committee path" || rc=1
expect_live_clean     MCInZoneLiveAllByz    MCInZoneLiveAllByz_Esc      LiveWithEscalation                         || rc=1
expect_live_violation MCInZoneLiveByzWit    MCInZoneLiveByzWit_Local    LiveLocal          "honest >= 2/3 attesting stake is necessary" || rc=1
expect_live_clean     MCInZoneLiveByzWit    MCInZoneLiveByzWit_Esc      LiveWithEscalation                         || rc=1
expect_live_violation MCInZoneLiveNoEscGST  MCInZoneLiveNoEscGST_Esc    LiveWithEscalation "no quorum-free floor: global GST is necessary" || rc=1
expect_live_violation MCInZoneLiveEscByz    MCInZoneLiveEscByz_Esc      LiveWithEscalation "escalation needs a 2/3 cross-zone quorum (global f < 1/3)" || rc=1
expect_live_violation MCInZoneLiveBootstrap MCInZoneLiveBootstrap_Esc   LiveWithEscalation "staked<3 freeze trap has no safety net" || rc=1
echo "--- Phase E.3: CROSS-EPOCH seal recurrence ([]<>sealed) — the chained VRF beacon re-randomizes ranks ---"
expect_live_clean     MCRecurSafe       MCRecurSafe_Any         RecurSealed                                  || rc=1
expect_live_clean     MCRecurSafe       MCRecurSafe_Local       RecurLocalSealed                             || rc=1
expect_live_clean     MCRecurLadder     MCRecurLadder_Any       RecurSealed                                  || rc=1
expect_live_clean     MCRecurLadder     MCRecurLadder_Local     RecurLocalSealed                             || rc=1
expect_live_clean     MCRecurGrind      MCRecurGrind_Any        RecurSealed                                  || rc=1
expect_live_violation MCRecurGrind      MCRecurGrind_Local      RecurLocalSealed   "a re-randomizing beacon is necessary for the fast path to recur" || rc=1
expect_live_violation MCRecurGrindStall MCRecurGrindStall_Any   RecurSealed        "no quorum-free floor: a pinned worst-case with no escalation stalls forever" || rc=1
echo "==============================================="
if [ "$rc" -eq 0 ]; then echo "ALL MODELS BEHAVED AS EXPECTED"; else echo "GATE FAILED"; fi
exit "$rc"
