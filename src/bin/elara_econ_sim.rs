// Copyright (c) 2026 Elara Protocol contributors
// Licensed under AGPL-3.0-only
//
// elara-econ-sim — Analytical economic simulator for beat at mainnet scale.
//
// Pure numeric model (no node, no DB, no tokio). Pulls live constants from
// `elara_runtime::accounting::types` and `elara_runtime::accounting::genesis` so the
// projections stay in sync with the protocol code; if a constant changes,
// re-running this binary surfaces the new equilibrium.
//
// Subcommands:
//   bootstrap        — distribution timeline of the 30% bootstrap pool
//                      across the first 10K nodes (one-shot per-node share).
//   witness-runway   — Conservation-Pool drain at various network sizes
//                      (zones × witnesses × epochs/day × reward/attestation)
//                      compared to the 10%-of-supply pool cap.
//   stake-yield      — staking yield envelope: prediction reward + slashing
//                      sink, expressed as APR for various staked-fraction
//                      assumptions.
//   equilibrium      — solve for the witness_reward_micros that makes daily
//                      pool drain equal to a given replenishment budget at
//                      a given scale (the Option D base-rate question from
//                      internal design notes §4).
//   report           — runs all four (default if no subcommand given).
//
// References:
//   - economics §5.1 (genesis allocation), §9.4 (stake-gated throughput).
//   - internal design notes §3 (scale-collapse math).
//   - internal design notes (pool inflows from dormancy reclaim).

use std::process::ExitCode;

use elara_runtime::accounting::genesis::{
    GenesisAllocation, BOOTSTRAP_FRACTION, BOOTSTRAP_TARGET_NODES, COMMUNITY_FRACTION,
    CONTRIBUTORS_FRACTION, DEVELOPMENT_FRACTION, RESERVE_FRACTION, TEAM_FRACTION,
};
use elara_runtime::accounting::types::{
    CONSERVATION_POOL_MAX_FRACTION, DEFAULT_WITNESS_REWARD, MAX_SUPPLY, MAX_WITNESS_REWARD,
    BASE_UNITS_PER_BEAT, MIN_PREDICTION_STAKE, MIN_STAKE, PREDICTION_REWARD_RATE,
};

const USAGE: &str = "\
elara-econ-sim — beat economic projections at mainnet scale

USAGE:
    elara-econ-sim [report]
    elara-econ-sim bootstrap [--nodes N] [--per-day N]
    elara-econ-sim witness-runway [--reward-beat F] [--epoch-secs F] [--witnesses N]
    elara-econ-sim stake-yield [--staked-fraction F] [--pool-beat F]
    elara-econ-sim equilibrium [--budget-beat F] [--zones N] [--witnesses N]
                               [--epoch-secs F]

OPTIONS:
    --reward-beat F        Witness reward per attestation, in beat
                           (default: protocol DEFAULT_WITNESS_REWARD = 1.0)
    --epoch-secs F         Seal cadence, in seconds (default: 30)
    --witnesses N          Witnesses per zone per epoch (default: 5)
    --zones N              Active zones (default: 1_000_000 — Protocol §11.12)
    --nodes N              Active nodes for bootstrap claims (default: 10000)
    --per-day N            Nodes claiming bootstrap per day (default: 1000)
    --staked-fraction F    Fraction of circulating beat that is staked
                           (default: 0.30)
    --pool-beat F          Conservation Pool size in beat for yield model
                           (default: 1e9 — pool cap)
    --budget-beat F        Daily replenishment budget for equilibrium solve
                           (default: 1e6 — 0.01% of pool/day)
    -h | --help            Show this message.

All scale defaults match internal design notes §3 mainnet target:
1M zones × 5 witnesses × 30s epochs.";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = argv.iter().peekable();
    let cmd = match iter.peek().map(|s| s.as_str()) {
        Some("-h") | Some("--help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("bootstrap") | Some("witness-runway") | Some("stake-yield")
        | Some("equilibrium") | Some("report") => {
            // peek() confirmed Some; next() cannot return None for a Peekable.
            // unwrap_or_else avoids a panic if the invariant ever breaks.
            iter.next().cloned().unwrap_or_else(|| "report".to_string())
        }
        _ => "report".to_string(),
    };

    let opts = match parse_opts(iter.cloned().collect()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    dispatch(&cmd, &opts)
}

fn dispatch(cmd: &str, opts: &Opts) -> ExitCode {
    match cmd {
        "bootstrap" => print_bootstrap(opts),
        "witness-runway" => print_witness_runway(opts),
        "stake-yield" => print_stake_yield(opts),
        "equilibrium" => print_equilibrium(opts),
        "report" => {
            print_header();
            print_bootstrap(opts);
            println!();
            print_witness_runway(opts);
            println!();
            print_stake_yield(opts);
            println!();
            print_equilibrium(opts);
        }
        _ => return ExitCode::from(2),
    }
    ExitCode::SUCCESS
}

// ─── Options ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Opts {
    reward_beat: f64,
    epoch_secs: f64,
    witnesses_per_zone: u64,
    zones: u64,
    bootstrap_nodes: u64,
    bootstrap_per_day: u64,
    staked_fraction: f64,
    pool_beat: f64,
    budget_beat: f64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            reward_beat: DEFAULT_WITNESS_REWARD as f64 / BASE_UNITS_PER_BEAT as f64,
            epoch_secs: 30.0,
            witnesses_per_zone: 5,
            zones: 1_000_000,
            bootstrap_nodes: BOOTSTRAP_TARGET_NODES,
            bootstrap_per_day: 1_000,
            staked_fraction: 0.30,
            pool_beat: pool_cap_beat(),
            budget_beat: 1_000_000.0,
        }
    }
}

fn parse_opts(args: Vec<String>) -> Result<Opts, String> {
    let mut opts = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("flag {key} expects a value"))?;
        match key {
            "--reward-beat" => opts.reward_beat = val.parse().map_err(|_| bad(key, val))?,
            "--epoch-secs" => opts.epoch_secs = val.parse().map_err(|_| bad(key, val))?,
            "--witnesses" => {
                opts.witnesses_per_zone = val.parse().map_err(|_| bad(key, val))?;
            }
            "--zones" => opts.zones = val.parse().map_err(|_| bad(key, val))?,
            "--nodes" => opts.bootstrap_nodes = val.parse().map_err(|_| bad(key, val))?,
            "--per-day" => opts.bootstrap_per_day = val.parse().map_err(|_| bad(key, val))?,
            "--staked-fraction" => {
                opts.staked_fraction = val.parse().map_err(|_| bad(key, val))?;
            }
            "--pool-beat" => opts.pool_beat = val.parse().map_err(|_| bad(key, val))?,
            "--budget-beat" => opts.budget_beat = val.parse().map_err(|_| bad(key, val))?,
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    if opts.epoch_secs <= 0.0 {
        return Err("--epoch-secs must be > 0".into());
    }
    if opts.bootstrap_per_day == 0 {
        return Err("--per-day must be > 0".into());
    }
    if opts.zones == 0 || opts.witnesses_per_zone == 0 {
        return Err("--zones and --witnesses must be > 0".into());
    }
    if !(0.0..=1.0).contains(&opts.staked_fraction) {
        return Err("--staked-fraction must be in [0, 1]".into());
    }
    Ok(opts)
}

fn bad(key: &str, val: &str) -> String {
    format!("invalid value for {key}: {val}")
}

// ─── Sections ─────────────────────────────────────────────────────────────

fn print_header() {
    let alloc = GenesisAllocation::compute();
    println!("Elara beat economic projection — generated against live protocol constants");
    println!("============================================================================");
    println!(
        "MAX_SUPPLY                  = {:>20} beat  ({:.0} micros)",
        format_int(MAX_SUPPLY / BASE_UNITS_PER_BEAT),
        MAX_SUPPLY as f64
    );
    println!(
        "Conservation Pool cap       = {:>20} beat  ({:.0}% of MAX_SUPPLY)",
        format_int((MAX_SUPPLY / BASE_UNITS_PER_BEAT) / 10),
        CONSERVATION_POOL_MAX_FRACTION * 100.0
    );
    println!(
        "DEFAULT_WITNESS_REWARD      = {:>20} beat / attestation",
        DEFAULT_WITNESS_REWARD as f64 / BASE_UNITS_PER_BEAT as f64,
    );
    println!(
        "MAX_WITNESS_REWARD          = {:>20} beat / attestation (governance ceiling)",
        MAX_WITNESS_REWARD as f64 / BASE_UNITS_PER_BEAT as f64,
    );
    println!(
        "MIN_STAKE                   = {:>20} beat",
        MIN_STAKE as f64 / BASE_UNITS_PER_BEAT as f64,
    );
    println!(
        "MIN_PREDICTION_STAKE        = {:>20} beat",
        MIN_PREDICTION_STAKE as f64 / BASE_UNITS_PER_BEAT as f64,
    );
    println!(
        "PREDICTION_REWARD_RATE      = {:>20} (10% of stake on correct claim)",
        PREDICTION_REWARD_RATE
    );
    let frac_sum = BOOTSTRAP_FRACTION + DEVELOPMENT_FRACTION + COMMUNITY_FRACTION
        + TEAM_FRACTION + CONTRIBUTORS_FRACTION + RESERVE_FRACTION;
    println!(
        "Allocation check: {:.0}%+{:.0}%+{:.0}%+{:.0}%+{:.0}%+{:.0}% = {:.0}%  (verify={})",
        BOOTSTRAP_FRACTION * 100.0,
        DEVELOPMENT_FRACTION * 100.0,
        COMMUNITY_FRACTION * 100.0,
        TEAM_FRACTION * 100.0,
        CONTRIBUTORS_FRACTION * 100.0,
        RESERVE_FRACTION * 100.0,
        frac_sum * 100.0,
        alloc.verify(),
    );
    println!();
}

fn print_bootstrap(opts: &Opts) {
    let alloc = GenesisAllocation::compute();
    let per_node_micros = alloc.bootstrap / BOOTSTRAP_TARGET_NODES;
    let per_node_beat = per_node_micros as f64 / BASE_UNITS_PER_BEAT as f64;

    println!("[bootstrap distribution — economics §5.1, src/accounting/genesis.rs]");
    println!(
        "  Bootstrap pool          = {:>14} beat  ({}% of MAX_SUPPLY)",
        format_int(alloc.bootstrap / BASE_UNITS_PER_BEAT),
        (BOOTSTRAP_FRACTION * 100.0) as u64
    );
    println!(
        "  Per-node share (1/{:>5}) = {:>14} beat  ({} micros)",
        BOOTSTRAP_TARGET_NODES,
        format_int(per_node_micros / BASE_UNITS_PER_BEAT),
        format_int(per_node_micros)
    );
    println!(
        "  Per-node share (USD-ish) ~ ${:.2}M at $10/beat, ${:.0}K at $1/beat",
        per_node_beat * 10.0 / 1_000_000.0,
        per_node_beat / 1_000.0,
    );
    println!();
    println!("  Distribution timeline at {} nodes/day:", opts.bootstrap_per_day);
    let mut claimed = 0u64;
    let mut day = 0u64;
    let target = opts.bootstrap_nodes.min(BOOTSTRAP_TARGET_NODES);
    let mut printed_milestones = std::collections::BTreeSet::new();
    let milestones = [1, 7, 30, 90, 180, 365];
    while claimed < target {
        claimed = (claimed + opts.bootstrap_per_day).min(target);
        day += 1;
        for &m in &milestones {
            if day == m && !printed_milestones.contains(&m) {
                printed_milestones.insert(m);
                println!(
                    "    day {:>4} — {:>5} nodes claimed ({:>5.1}% of pool, {:>14} beat distributed)",
                    day,
                    format_int(claimed),
                    100.0 * claimed as f64 / target as f64,
                    format_int(claimed * per_node_micros / BASE_UNITS_PER_BEAT),
                );
            }
        }
    }
    println!(
        "    day {:>4} — pool fully distributed ({} nodes claimed)",
        day, format_int(target)
    );
    println!();
    println!("  Note: bootstrap is one-shot per node, no decay function. After the");
    println!("  first 10K nodes claim, additional participants earn through normal");
    println!("  witness rewards + prediction yields only.");
}

fn print_witness_runway(opts: &Opts) {
    println!("[witness-reward pool runway — internal design notes §3.1]");
    println!(
        "  Configured: zones={}, witnesses/zone={}, epoch={:.1}s, reward={} beat/attestation",
        format_int(opts.zones),
        opts.witnesses_per_zone,
        opts.epoch_secs,
        opts.reward_beat,
    );
    println!();
    println!("  Daily witness payout = zones × witnesses × (86400 / epoch_secs) × reward");
    println!();
    println!(
        "    {:<14} {:<12} {:<14} {:<14} {:<18}",
        "scale", "epochs/day", "attestations", "beat/day", "pool runway"
    );
    println!(
        "    {:-<14} {:-<12} {:-<14} {:-<14} {:-<18}",
        "", "", "", "", ""
    );
    let pool_micros = (MAX_SUPPLY as f64 * CONSERVATION_POOL_MAX_FRACTION) as u64;
    let pool_beat = pool_micros as f64 / BASE_UNITS_PER_BEAT as f64;
    let scenarios = [
        ("100 zones", 100u64),
        ("1K zones", 1_000),
        ("10K zones", 10_000),
        ("100K zones", 100_000),
        ("1M zones", 1_000_000),
    ];
    for (label, zones) in scenarios {
        let epochs_per_day = 86_400.0 / opts.epoch_secs;
        let attestations = zones as f64 * opts.witnesses_per_zone as f64 * epochs_per_day;
        let beat_per_day = attestations * opts.reward_beat;
        let runway_days = pool_beat / beat_per_day;
        let runway = if runway_days >= 365.25 {
            format!("{:.1} years", runway_days / 365.25)
        } else if runway_days >= 1.0 {
            format!("{:.1} days", runway_days)
        } else if runway_days >= 1.0 / 24.0 {
            format!("{:.1} hours", runway_days * 24.0)
        } else {
            format!("{:.1} minutes", runway_days * 24.0 * 60.0)
        };
        println!(
            "    {:<14} {:<12} {:<14} {:<14} {:<18}",
            label,
            format_int(epochs_per_day as u64),
            format_int(attestations as u64),
            format_int(beat_per_day as u64),
            runway
        );
    }
    println!();
    println!(
        "  Pool cap = {} beat (10% of MAX_SUPPLY). Pool inflow comes from",
        format_int(pool_beat as u64)
    );
    println!("  slashing + dormancy reclaim — both are infrequent at steady state.");
    println!();
    println!("  Reward sweep at 1M zones (mainnet target):");
    println!(
        "    {:<18} {:<14} {:<18}",
        "reward / attestation", "beat/day", "pool runway"
    );
    println!("    {:-<18} {:-<14} {:-<18}", "", "", "");
    let sweep = [
        ("1.0 beat (current)", 1.0_f64),
        ("0.1 beat", 0.1),
        ("0.01 beat", 0.01),
        ("0.001 beat (Option D)", 0.001),
        ("0.0001 beat", 0.0001),
    ];
    for (label, reward) in sweep {
        let epochs_per_day = 86_400.0 / opts.epoch_secs;
        let attestations =
            opts.zones as f64 * opts.witnesses_per_zone as f64 * epochs_per_day;
        let beat_per_day = attestations * reward;
        let runway_days = pool_beat / beat_per_day;
        let runway = if runway_days >= 365.25 {
            format!("{:.1} years", runway_days / 365.25)
        } else if runway_days >= 1.0 {
            format!("{:.1} days", runway_days)
        } else {
            format!("{:.2} days", runway_days)
        };
        println!(
            "    {:<18} {:<14} {:<18}",
            label,
            format_int(beat_per_day as u64),
            runway
        );
    }
    println!();
    println!(
        "  Conclusion (FEE-MARKET §3.1): at 1.0 beat/attestation, pool drains in"
    );
    println!("  hours at 1M zones. Even 0.001 beat only gives ~70 days; reaching");
    println!("  multi-year runway purely from the pool requires ≤0.0001 beat, OR");
    println!("  steady fee/slashing inflow to replenish the pool. Option D in");
    println!("  FEE-MARKET §4 picks the latter — base rate stays at 0.001 beat,");
    println!("  priority fees become the dominant witness compensation at scale.");
}

fn print_stake_yield(opts: &Opts) {
    println!("[staking yield envelope — economics §6, src/accounting/types.rs]");
    let alloc = GenesisAllocation::compute();
    let circulating_micros = alloc.bootstrap + alloc.community + alloc.contributors
        + alloc.development + alloc.team + alloc.reserve;
    let circulating_beat = circulating_micros as f64 / BASE_UNITS_PER_BEAT as f64;
    let staked_beat = circulating_beat * opts.staked_fraction;
    println!(
        "  Circulating supply (max)    = {} beat",
        format_int(circulating_beat as u64)
    );
    println!(
        "  Staked fraction assumption  = {:.0}%  ({} beat staked)",
        opts.staked_fraction * 100.0,
        format_int(staked_beat as u64)
    );
    println!(
        "  Pool size (yield source)    = {} beat",
        format_int(opts.pool_beat as u64)
    );
    println!();
    println!("  Yield streams a staker can earn (economics §6, ledger.rs):");
    println!("    • Witness reward       — 1 beat per attestation (pool-funded today)");
    println!(
        "    • Prediction yield     — {:.0}% of stake on correct claim (pool-funded)",
        PREDICTION_REWARD_RATE * 100.0
    );
    println!("    • Slashing share       — 30% to challenger, 20% to jury, 50% to pool");
    println!();
    println!("  Reverse-solving: how much can the pool sustainably distribute as yield?");
    println!(
        "    Pool capital           = {} beat",
        format_int(opts.pool_beat as u64)
    );
    let sustainable_inflows = [
        ("0.1% / year (slow drain)", 0.001),
        ("1% / year (steady)", 0.01),
        ("5% / year (aggressive)", 0.05),
    ];
    for (label, frac) in sustainable_inflows {
        let yield_per_year = opts.pool_beat * frac;
        let apr_on_stake = if staked_beat > 0.0 {
            yield_per_year / staked_beat
        } else {
            0.0
        };
        println!(
            "    {:<24}  → {:>14} beat/yr → {:.3}% APR on staked",
            label,
            format_int(yield_per_year as u64),
            apr_on_stake * 100.0
        );
    }
    println!();
    println!("  Implication: at 30% staking ratio, even draining the pool 5%/yr only");
    println!("  yields ~0.5% APR on stake. Realistic staker compensation must come");
    println!("  from priority fees (FEE-MARKET §4 Option D), not pool drain alone.");
}

fn print_equilibrium(opts: &Opts) {
    println!("[reward equilibrium solver — fee-market Option D base-rate]");
    println!(
        "  Question: what reward/attestation makes daily payout = ${} beat budget?",
        format_int(opts.budget_beat as u64)
    );
    println!(
        "  At zones={}, witnesses={}, epoch={:.1}s",
        format_int(opts.zones),
        opts.witnesses_per_zone,
        opts.epoch_secs
    );
    let epochs_per_day = 86_400.0 / opts.epoch_secs;
    let attestations =
        opts.zones as f64 * opts.witnesses_per_zone as f64 * epochs_per_day;
    let reward_beat = opts.budget_beat / attestations;
    let reward_micros = reward_beat * BASE_UNITS_PER_BEAT as f64;
    println!(
        "  Daily attestations         = {}",
        format_int(attestations as u64)
    );
    println!(
        "  Solved reward/attestation  = {:.9} beat  ({:.3} micros)",
        reward_beat, reward_micros
    );
    println!();
    println!("  Cross-check at common budget targets:");
    println!(
        "    {:<22} {:<22}",
        "daily budget (beat)", "implied reward / attestation"
    );
    println!("    {:-<22} {:-<22}", "", "");
    let budgets = [
        ("100 beat/day", 100.0_f64),
        ("1K beat/day", 1_000.0),
        ("10K beat/day", 10_000.0),
        ("100K beat/day", 100_000.0),
        ("1M beat/day", 1_000_000.0),
    ];
    for (label, budget) in budgets {
        let reward = budget / attestations;
        println!("    {:<22} {:<22}", label, format!("{:.9} beat", reward));
    }
    println!();
    println!("  Implication: the headline `priority_fee` design works because the");
    println!("  attestation count at mainnet scale is ~1.4×10^10/day; even paying");
    println!("  1M beat/day across all witnesses is ~7×10^-5 beat each. So the");
    println!("  base-rate floor in Option D (drop reward to 0.001 beat) leaves");
    println!("  headroom for fees to dominate without breaking the pool.");
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn pool_cap_beat() -> f64 {
    let cap_micros = (MAX_SUPPLY as f64 * CONSERVATION_POOL_MAX_FRACTION) as u64;
    cap_micros as f64 / BASE_UNITS_PER_BEAT as f64
}

fn format_int(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dispatch_unknown_command_returns_error_not_panic() {
        let opts = parse_opts(vec![]).unwrap();
        assert_eq!(dispatch("INVALID", &opts), ExitCode::from(2));
        assert_eq!(dispatch("", &opts), ExitCode::from(2));
    }

    #[test]
    fn dispatch_known_commands_return_success() {
        // Covers the unwrap_or_else("report") fallback: all recognised commands
        // must route through dispatch() without panicking and return SUCCESS.
        let opts = parse_opts(vec![]).unwrap();
        for cmd in &["bootstrap", "witness-runway", "stake-yield", "equilibrium", "report"] {
            assert_eq!(
                dispatch(cmd, &opts),
                ExitCode::SUCCESS,
                "command '{cmd}' must dispatch without error"
            );
        }
    }

    // ─── format_int (thousands separator) ─────────────────────────────────

    #[test]
    fn format_int_zero_through_999_unchanged() {
        assert_eq!(format_int(0), "0");
        assert_eq!(format_int(9), "9");
        assert_eq!(format_int(42), "42");
        assert_eq!(format_int(999), "999");
    }

    #[test]
    fn format_int_inserts_comma_at_thousand() {
        assert_eq!(format_int(1_000), "1,000");
        assert_eq!(format_int(12_345), "12,345");
        assert_eq!(format_int(999_999), "999,999");
    }

    #[test]
    fn format_int_handles_millions() {
        assert_eq!(format_int(1_000_000), "1,000,000");
        assert_eq!(format_int(12_345_678), "12,345,678");
        assert_eq!(format_int(123_456_789), "123,456,789");
    }

    #[test]
    fn format_int_handles_billions_and_max_supply_scale() {
        assert_eq!(format_int(1_000_000_000), "1,000,000,000");
        // MAX_SUPPLY (10B beat = 10^16 micros) — exercise the upper end
        assert_eq!(format_int(10_000_000_000_000_000), "10,000,000,000,000,000");
    }

    #[test]
    fn format_int_u64_max_does_not_panic() {
        let s = format_int(u64::MAX);
        // u64::MAX = 18,446,744,073,709,551,615 → 20 digits → 6 commas
        assert_eq!(s.matches(',').count(), 6);
        assert!(s.starts_with("18,"));
    }

    // ─── pool_cap_beat ────────────────────────────────────────────────────

    #[test]
    fn pool_cap_beat_matches_protocol_constants() {
        let cap = pool_cap_beat();
        let expected =
            (MAX_SUPPLY as f64 * CONSERVATION_POOL_MAX_FRACTION) / BASE_UNITS_PER_BEAT as f64;
        assert!((cap - expected).abs() < 1e-6, "cap={cap}, expected={expected}");
        assert!(cap > 0.0, "pool cap must be positive");
    }

    // ─── Opts::default ─────────────────────────────────────────────────────

    #[test]
    fn opts_default_matches_protocol_defaults() {
        let d = Opts::default();
        assert_eq!(d.epoch_secs, 30.0);
        assert_eq!(d.witnesses_per_zone, 5);
        assert_eq!(d.zones, 1_000_000);
        assert_eq!(d.bootstrap_per_day, 1_000);
        assert_eq!(d.staked_fraction, 0.30);
        assert_eq!(d.bootstrap_nodes, BOOTSTRAP_TARGET_NODES);
        assert!((d.reward_beat
            - DEFAULT_WITNESS_REWARD as f64 / BASE_UNITS_PER_BEAT as f64)
            .abs()
            < 1e-9);
        assert!((d.pool_beat - pool_cap_beat()).abs() < 1e-6);
    }

    // ─── parse_opts: happy paths ──────────────────────────────────────────

    #[test]
    fn parse_opts_empty_returns_defaults() {
        let opts = parse_opts(vec![]).unwrap();
        let d = Opts::default();
        assert_eq!(opts.zones, d.zones);
        assert_eq!(opts.witnesses_per_zone, d.witnesses_per_zone);
        assert_eq!(opts.epoch_secs, d.epoch_secs);
    }

    #[test]
    fn parse_opts_each_flag_overrides_default() {
        let opts = parse_opts(argv(&[
            "--reward-beat", "2.5",
            "--epoch-secs", "15.0",
            "--witnesses", "11",
            "--zones", "500",
            "--nodes", "20000",
            "--per-day", "250",
            "--staked-fraction", "0.4",
            "--pool-beat", "1234567.89",
            "--budget-beat", "9999.0",
        ])).unwrap();
        assert_eq!(opts.reward_beat, 2.5);
        assert_eq!(opts.epoch_secs, 15.0);
        assert_eq!(opts.witnesses_per_zone, 11);
        assert_eq!(opts.zones, 500);
        assert_eq!(opts.bootstrap_nodes, 20_000);
        assert_eq!(opts.bootstrap_per_day, 250);
        assert_eq!(opts.staked_fraction, 0.4);
        assert!((opts.pool_beat - 1_234_567.89).abs() < 1e-6);
        assert_eq!(opts.budget_beat, 9999.0);
    }

    // ─── parse_opts: error paths ──────────────────────────────────────────

    #[test]
    fn parse_opts_unknown_flag_rejected() {
        let err = parse_opts(argv(&["--bogus", "value"])).unwrap_err();
        assert!(err.contains("unknown flag"), "{err}");
    }

    #[test]
    fn parse_opts_flag_without_value_rejected() {
        let err = parse_opts(argv(&["--zones"])).unwrap_err();
        assert!(err.contains("expects a value"), "{err}");
    }

    #[test]
    fn parse_opts_invalid_numeric_value_rejected() {
        let err = parse_opts(argv(&["--zones", "twelve"])).unwrap_err();
        assert!(err.contains("invalid value"), "{err}");
    }

    #[test]
    fn parse_opts_invalid_float_rejected() {
        let err = parse_opts(argv(&["--epoch-secs", "not_a_number"])).unwrap_err();
        assert!(err.contains("invalid value"), "{err}");
    }

    // ─── parse_opts: validation rules ─────────────────────────────────────

    #[test]
    fn parse_opts_zero_epoch_rejected() {
        let err = parse_opts(argv(&["--epoch-secs", "0"])).unwrap_err();
        assert!(err.contains("--epoch-secs must be > 0"), "{err}");
    }

    #[test]
    fn parse_opts_negative_epoch_rejected() {
        let err = parse_opts(argv(&["--epoch-secs", "-1"])).unwrap_err();
        assert!(err.contains("--epoch-secs must be > 0"), "{err}");
    }

    #[test]
    fn parse_opts_zero_per_day_rejected() {
        let err = parse_opts(argv(&["--per-day", "0"])).unwrap_err();
        assert!(err.contains("--per-day must be > 0"), "{err}");
    }

    #[test]
    fn parse_opts_zero_zones_rejected() {
        let err = parse_opts(argv(&["--zones", "0"])).unwrap_err();
        assert!(err.contains("--zones and --witnesses must be > 0"), "{err}");
    }

    #[test]
    fn parse_opts_zero_witnesses_rejected() {
        let err = parse_opts(argv(&["--witnesses", "0"])).unwrap_err();
        assert!(err.contains("--zones and --witnesses must be > 0"), "{err}");
    }

    #[test]
    fn parse_opts_staked_fraction_above_one_rejected() {
        let err = parse_opts(argv(&["--staked-fraction", "1.5"])).unwrap_err();
        assert!(err.contains("--staked-fraction must be in [0, 1]"), "{err}");
    }

    #[test]
    fn parse_opts_staked_fraction_negative_rejected() {
        let err = parse_opts(argv(&["--staked-fraction", "-0.01"])).unwrap_err();
        assert!(err.contains("--staked-fraction must be in [0, 1]"), "{err}");
    }

    #[test]
    fn parse_opts_staked_fraction_boundaries_accepted() {
        // Closed interval: 0.0 and 1.0 are both valid.
        let opts0 = parse_opts(argv(&["--staked-fraction", "0.0"])).unwrap();
        assert_eq!(opts0.staked_fraction, 0.0);
        let opts1 = parse_opts(argv(&["--staked-fraction", "1.0"])).unwrap();
        assert_eq!(opts1.staked_fraction, 1.0);
    }

    // ─── bad() helper ─────────────────────────────────────────────────────

    #[test]
    fn bad_helper_formats_key_and_value() {
        let s = bad("--zones", "abc");
        assert!(s.contains("--zones"));
        assert!(s.contains("abc"));
        assert!(s.contains("invalid value"));
    }

    // ─── format_int round-trip tests ─────────────────────────────────────

    #[test]
    fn batch_b_format_int_round_trips_digits_only_strip_recovers_decimal_repr() {
        // For any n: stripping commas from format_int(n) must yield n.to_string()
        let cases = [
            0u64, 1, 9, 10, 99, 100, 999, 1_000, 9_999, 10_000, 99_999, 100_000,
            999_999, 1_000_000, 12_345_678, 1_000_000_000_000, u32::MAX as u64,
            u64::MAX / 2, u64::MAX - 1, u64::MAX,
        ];
        for n in cases {
            let s = format_int(n);
            let digits_only: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            assert_eq!(digits_only, n.to_string(), "n={n}, format={s}, digits={digits_only}");
            // Output contains only commas and ASCII digits
            for c in s.chars() {
                assert!(c.is_ascii_digit() || c == ',', "n={n}, unexpected char {c:?} in {s:?}");
            }
        }
    }

    #[test]
    fn batch_b_format_int_three_digit_group_invariant_from_right() {
        // Each comma-separated group from the right must be exactly 3 digits,
        // except the leftmost group which is 1-3 digits.
        let cases = [
            (0u64, "0"),
            (1, "1"),
            (999, "999"),
            (1_000, "1,000"),
            (10_000, "10,000"),
            (100_000, "100,000"),
            (1_000_000, "1,000,000"),
            (1_000_000_000, "1,000,000,000"),
            (12_345_678_901, "12,345,678,901"),
        ];
        for (n, want) in cases {
            assert_eq!(format_int(n), want, "n={n}");
        }
        // Cross-check for arbitrary larger values: group-3 from right
        let s = format_int(12_345_678_901_234_567_u64);
        let groups: Vec<&str> = s.split(',').collect();
        // Last n-1 groups must be exactly 3 chars; first group is 1-3 chars
        assert!(!groups[0].is_empty() && groups[0].len() <= 3, "leftmost group len out of [1,3]: {:?}", groups[0]);
        for g in &groups[1..] {
            assert_eq!(g.len(), 3, "non-leftmost group must have 3 digits, got {:?}", g);
        }
    }

    #[test]
    fn batch_b_format_int_u64_max_exact_value_pin() {
        // u64::MAX = 18_446_744_073_709_551_615 — 20 digits, 6 commas.
        // Pin the exact rendered form so an off-by-one in the comma-insertion
        // step gets caught.
        assert_eq!(format_int(u64::MAX), "18,446,744,073,709,551,615");
        assert_eq!(format_int(u64::MAX - 1), "18,446,744,073,709,551,614");
        // u64::MAX has exactly 20 digits → 6 commas → total length 26
        let s = format_int(u64::MAX);
        assert_eq!(s.len(), 26);
        assert_eq!(s.matches(',').count(), 6);
    }

    #[test]
    fn batch_b_opts_default_uncovered_field_pins_reward_bootstrap_nodes_pool_budget() {
        // `opts_default_matches_protocol_defaults` already pins epoch_secs,
        // witnesses_per_zone, zones, bootstrap_per_day, staked_fraction.
        // Pin the remaining 4 fields so the full surface is locked.
        let d = Opts::default();
        assert!(d.reward_beat.is_finite() && d.reward_beat > 0.0,
            "reward_beat must be finite positive, got {}", d.reward_beat);
        assert_eq!(d.bootstrap_nodes, BOOTSTRAP_TARGET_NODES,
            "bootstrap_nodes must equal protocol BOOTSTRAP_TARGET_NODES");
        // pool_beat = pool_cap_beat() — must match the helper
        assert!((d.pool_beat - pool_cap_beat()).abs() < 1e-6,
            "pool_beat must equal pool_cap_beat(): got {}, expected {}", d.pool_beat, pool_cap_beat());
        assert_eq!(d.budget_beat, 1_000_000.0,
            "budget_beat must default to 1,000,000 beat");
        // Sanity: all numeric fields finite
        assert!(d.pool_beat.is_finite());
        assert!(d.budget_beat.is_finite());
        assert!(d.epoch_secs.is_finite());
        assert!(d.staked_fraction.is_finite());
    }

    #[test]
    fn batch_b_parse_opts_multi_flag_composition_and_last_wins_on_duplicate() {
        // Multiple distinct flags in one call all apply.
        let opts = parse_opts(argv(&[
            "--epoch-secs", "60",
            "--witnesses", "7",
            "--zones", "500",
            "--per-day", "5000",
            "--staked-fraction", "0.5",
            "--reward-beat", "100.0",
            "--budget-beat", "2000000.0",
        ])).expect("multi-flag should parse");
        assert_eq!(opts.epoch_secs, 60.0);
        assert_eq!(opts.witnesses_per_zone, 7);
        assert_eq!(opts.zones, 500);
        assert_eq!(opts.bootstrap_per_day, 5000);
        assert_eq!(opts.staked_fraction, 0.5);
        assert_eq!(opts.reward_beat, 100.0);
        assert_eq!(opts.budget_beat, 2_000_000.0);
        // Last-wins on duplicate: parsing iterates positionally, so the later
        // value overwrites the earlier one.
        let opts2 = parse_opts(argv(&[
            "--zones", "100",
            "--zones", "200",
            "--zones", "300",
        ])).expect("duplicate flag should parse");
        assert_eq!(opts2.zones, 300, "last --zones value must win");
        // Compose with override: a defaulted field stays default if no flag
        let opts3 = parse_opts(argv(&["--zones", "42"])).expect("single flag");
        assert_eq!(opts3.zones, 42);
        assert_eq!(opts3.epoch_secs, 30.0, "non-overridden field stays at default");
        assert_eq!(opts3.witnesses_per_zone, 5);
    }
}
