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
//! NOT-authorized verdict · 2 = usage/network/parse error · 3 = indeterminate
//! (not a mandate act, or an unverified sub-delegation chain).
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
        "unverified_chain" => "a sub-delegation; v0 does not verify chains — an honest 'not verified', neither valid nor forged",
        "depth_exceeded" | "scope_broadened" | "unauthorized_revocation" => "(reserved v1 sub-delegation verdict)",
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
        println!("verdict:   — NOT A MANDATE ACT (this record claimed no mandate)");
        if v.get("authoritative_complete").and_then(|x| x.as_bool()) == Some(false) {
            println!(
                "note:      this node bootstrapped past the record's epoch (the act index is \
                 live-ingest-only, not snapshot-carried); query a full-history/archive node to be certain"
            );
        }
        return 3;
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
            println!("acts:      0 (no acts found for this agent on this node)");
            3
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
