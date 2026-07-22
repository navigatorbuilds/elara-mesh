//! elara-mandate-audit — point it at an act record and learn whether it was
//! *authorized* by a mandate: the question OpenTimestamps + bare PQ-signatures
//! structurally cannot answer ("existed by T" / "key K signed" — never "agent A
//! was mandated by principal P to do X, valid at signing, later revoked").
//!
//! This is the operator/auditor-facing face of the project's reason-to-exist
//! (mandate/accountability layer). The consensus, the evaluator
//! (`evaluate_mandate_v0`), and the read API (`GET /mandate/status/{record_id}`)
//! already existed — what was missing was a tool a human can run to get a plain
//! verdict instead of reading JSON. This closes that gap.
//!
//! Build: `cargo build --release --features mandate-cli --bin elara-mandate-audit`
//! Usage: `elara-mandate-audit <RECORD_ID> [--node URL] [--json]`
//!        `elara-mandate-audit --agent <AGENT_HASH> [--node URL] [--json]`
//!
//! Exit codes (so it scripts cleanly): 0 = authorized · 1 = a definitive
//! NOT-authorized verdict · 2 = usage/network/parse error · 3 = AUTHORITATIVE
//! not-a-mandate-act (proven absent within this node's coverage) or an unverified
//! sub-delegation chain · 4 = UNKNOWN-outside-coverage (B5: the record is absent
//! but this node's act-index coverage is incomplete for it — a pruned / out-of-
//! window / zone-scoped / storage-fault miss; a script gating on 3 must NOT treat
//! this as proven-absent).
//!
//! v0 uses the `curl` binary for HTTP, matching this project's ops convention
//! (every monitor/drill script shells curl); a pure-Rust client is a follow-up.

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "elara-mandate-audit",
    about = "Was this act authorized? Verify a record against the mandate it claimed.",
    long_about = "Queries a running Elara node's public /mandate/status/{record_id} and \
prints a plain-language verdict: was the act authorized, by whom, under what \
mandate, and — if not — exactly why (no chain / lapsed / revoked / out-of-scope / \
agent-mismatch). This is the authority-to-act question that OTS and bare \
signatures cannot express."
)]
struct Args {
    /// Act record id (hex) to audit.
    record_id: Option<String>,

    /// Instead of one record, list every act by this agent identity (hex).
    /// Uses /agent/{hash}/acts, served on the node's DATAPLANE port (default
    /// 9472) from the node's own host — pass `--node http://127.0.0.1:9472`.
    #[arg(long, value_name = "AGENT_HASH")]
    agent: Option<String>,

    /// Base URL of the Elara node to query.
    #[arg(long, default_value = "http://127.0.0.1:9474")]
    node: String,

    /// Print the raw JSON the node returned instead of the formatted verdict.
    #[arg(long)]
    json: bool,
}

/// Plain-language meaning for each wire-stable `MandateFlag` label
/// (mirrors `crate::mandate::MandateFlag::as_str` — those discriminants are
/// frozen, so this map never drifts).
fn flag_meaning(flag: &str) -> &'static str {
    match flag {
        "valid" => "by the mandated agent, in-window, not revoked, in scope",
        "no_chain" => "no mandate resolves — this binds the SIGNER only; the named principal is cryptographically uninvolved",
        "lapsed" => "a mandate existed but had expired (act after not_after)",
        "post_revocation" => "the mandate was revoked at or before the act's signed time",
        "over_scope" => "valid, in-window mandate, but the act is outside its op/zone/amount scope",
        "agent_mismatch" => "the signer is NOT the mandate's agent — the named principal authorized a different key and is exonerated",
        "malformed" => "the mandate reference is malformed / structurally invalid",
        "not_yet_valid" => "a well-formed mandate, but the act precedes its not_before",
        "unverified_chain" => "a sub-delegation chain that could not be verified on this node (missing / malformed / cross-network ancestor, or a broken genealogy link) — an honest 'not verified', neither valid nor forged",
        "depth_exceeded" => "a sub-delegation chain exceeded a depth cap (the global maximum, or an ancestor's own sub-delegation limit)",
        "scope_broadened" => "a hop broadened its parent's scope or validity window — a forged privilege escalation, rejected",
        "unauthorized_revocation" => "(reserved v1: a revocation signed by a party not authorized to revoke)",
        _ => "unrecognized flag (newer node than this tool?)",
    }
}

/// GET `url` via the system `curl`. Returns the body on success.
fn http_get(url: &str) -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args(["-s", "--show-error", "--max-time", "10", url])
        .output()
        .map_err(|e| format!("could not run curl ({e}); is curl installed?"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl failed for {url}: {}", err.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_json(body: &str, node: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(body).map_err(|_| {
        format!("{node} did not return JSON — is it an Elara node? body was:\n{body}")
    })
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

/// Render one `/mandate/status/{id}` response. Returns the process exit code.
fn print_status(v: &serde_json::Value) -> i32 {
    let rid = s(v, "record_id").unwrap_or("?");
    println!("record:    {rid}");

    if v.get("is_mandate_act").and_then(|x| x.as_bool()) != Some(true) {
        let authoritative =
            v.get("authoritative_complete").and_then(|x| x.as_bool()) == Some(true);
        let basis = s(v, "absence_basis").unwrap_or("");
        if authoritative {
            // Authoritative negative — proven NOT a mandate act within this node's
            // coverage. Exit 3 = proven-absent (a script may treat it as definitive).
            match basis {
                "removed_by_operator" => println!(
                    "verdict:   — NOT A MANDATE ACT (an operator forensically un-indexed this act)"
                ),
                "record_checked" => println!(
                    "verdict:   — NOT A MANDATE ACT (the signed record itself references no mandate)"
                ),
                _ => println!(
                    "verdict:   — NOT A MANDATE ACT (authoritative — within this node's coverage window)"
                ),
            }
            return 3;
        }
        // Non-authoritative absence → genuinely UNKNOWN outside the coverage
        // window. Exit 4 (NEVER 3): a script gating on 3 must not treat a pruned /
        // out-of-window / zone-scoped / storage-fault miss as proven-absent (B5).
        println!(
            "verdict:   ? UNKNOWN — this record is absent, but this node's act-index coverage is INCOMPLETE for it"
        );
        if let Some(cov) = v.get("acts_coverage") {
            if let Some(floor) = cov.get("complete_from_ms").and_then(|x| x.as_u64()) {
                println!(
                    "coverage:  absence is authoritative only for acts at/after {floor} (epoch ms); below that it is unknown on this node"
                );
            }
            if let Some(tags) = cov.get("basis").and_then(|x| x.as_array()) {
                let tags: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
                if !tags.is_empty() {
                    println!("basis:     {}", tags.join(", "));
                }
            }
        }
        println!(
            "note:      query a full-history/archive node, or re-check with the receipt's own claimed \
             timestamp — a claim INSIDE the coverage window is authoritatively refuted"
        );
        return 4;
    }

    if let Some(a) = s(v, "agent_identity_hash") {
        println!("agent:     {a}");
    }
    if let Some(p) = s(v, "principal_identity_hash") {
        println!("principal: {p}");
    }
    if let Some(m) = s(v, "mandate_ref") {
        println!("mandate:   {m}");
    }
    if let Some(ts) = v.get("act_timestamp_ms").and_then(|x| x.as_u64()) {
        println!("acted_at:  {ts} (epoch ms)");
    }
    println!();

    let flag = s(v, "flag").unwrap_or("?");
    let authorized = v.get("authorized").and_then(|x| x.as_bool()).unwrap_or(false);
    if authorized {
        println!("VERDICT:   ✓ AUTHORIZED");
    } else {
        println!("VERDICT:   ✗ NOT AUTHORIZED");
    }
    println!("reason:    {flag} — {}", flag_meaning(flag));

    if v.get("scope_deferred").and_then(|x| x.as_bool()) == Some(true) {
        println!(
            "caveat:    this mandate carries op/zone/amount scope, but v0 does NOT enforce scope — \
             only who / when / revocation were checked"
        );
    }
    if let Some(note) = s(v, "principal_note") {
        println!("note:      {note}");
    }
    if flag == "valid" {
        if let Some(hops) = v.get("lineage").and_then(|x| x.as_array()) {
            if !hops.is_empty() {
                println!("lineage:   {} verified hop(s) leaf→root", hops.len());
            }
        }
    }

    match flag {
        "valid" => 0,
        "unverified_chain" => 3,
        _ => 1,
    }
}

/// Render an `/agent/{hash}/acts` response defensively (its exact shape may grow;
/// summarize the common `acts` array, else pretty-print whatever came back).
fn print_agent_acts(v: &serde_json::Value, agent: &str) -> i32 {
    println!("agent:     {agent}");
    let acts = v.get("acts").and_then(|x| x.as_array());
    match acts {
        Some(list) if !list.is_empty() => {
            println!("acts:      {}", list.len());
            println!();
            for (i, act) in list.iter().enumerate() {
                let rid = s(act, "record_id").unwrap_or("?");
                let flag = s(act, "flag").unwrap_or("?");
                let mark = if flag == "valid" { "✓" } else { "✗" };
                println!("  {:>3}. {mark} {flag:<16} {rid}", i + 1);
            }
            0
        }
        Some(_) => {
            // B5: an empty list is authoritative "never acted" only when the page
            // says so; otherwise it is unknown outside coverage (exit 4, never 3).
            if v.get("authoritative_complete").and_then(|x| x.as_bool()) == Some(true) {
                println!("acts:      0 (no acts for this agent — authoritative on this node)");
                3
            } else {
                println!(
                    "acts:      0 indexed here, but this node's act-index coverage is INCOMPLETE — query a full-history/archive node"
                );
                if let Some(cov) = v.get("acts_coverage") {
                    if let Some(floor) = cov.get("complete_from_ms").and_then(|x| x.as_u64()) {
                        println!("coverage:  complete only for acts at/after {floor} (epoch ms)");
                    }
                }
                4
            }
        }
        None => {
            // Unknown shape — don't guess; show it.
            println!(
                "{}",
                serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
            );
            0
        }
    }
}

fn main() {
    let args = Args::parse();
    let base = args.node.trim_end_matches('/');

    // --agent mode: list an agent's acts.
    if let Some(agent) = args.agent.as_deref() {
        let url = format!("{base}/agent/{agent}/acts");
        let body = match http_get(&url) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        };
        if args.json {
            println!("{body}");
            std::process::exit(0);
        }
        if body.trim().is_empty() {
            eprintln!(
                "error: empty response from {url} — /agent/{{hash}}/acts is served on the node's \
                 DATAPLANE port (default 9472), NOT the public read port (9474). Retry with \
                 `--node http://127.0.0.1:9472`, from the node's own host, with a full 64-hex agent hash."
            );
            std::process::exit(2);
        }
        let v = match parse_json(&body, base) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        };
        std::process::exit(print_agent_acts(&v, agent));
    }

    // record-id mode: audit one act.
    let Some(rid) = args.record_id.as_deref() else {
        eprintln!("error: give a RECORD_ID to audit, or --agent <hash>. See --help.");
        std::process::exit(2);
    };
    let url = format!("{base}/mandate/status/{rid}");
    let body = match http_get(&url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    if args.json {
        println!("{}", body.trim());
        std::process::exit(0);
    }
    let v = match parse_json(&body, base) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    std::process::exit(print_status(&v));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mandate_audit_exit_code_4_for_unknown_outside_coverage() {
        // B5: a NON-authoritative absent answer exits 4, NEVER 3 — a script gating
        // on 3 must not treat a pruned / out-of-window miss as proven-absent.
        let v = json!({
            "record_id": "r",
            "is_mandate_act": false,
            "authoritative_complete": false,
            "absence_basis": "outside_coverage",
            "acts_coverage": {"complete_from_ms": 5000, "basis": ["pruned_or_upgrade_baseline"]}
        });
        assert_eq!(print_status(&v), 4);

        // Authoritative not-a-mandate-act stays 3 (proven absent within coverage).
        let v_auth = json!({
            "record_id": "r",
            "is_mandate_act": false,
            "authoritative_complete": true,
            "absence_basis": "full_coverage"
        });
        assert_eq!(print_status(&v_auth), 3);

        // removed_by_operator is authoritative → 3, not 4.
        let v_removed = json!({
            "record_id": "r",
            "is_mandate_act": false,
            "authoritative_complete": true,
            "absence_basis": "removed_by_operator"
        });
        assert_eq!(print_status(&v_removed), 3);
    }
}
