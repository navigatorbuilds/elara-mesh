//! Live-node mandate query tutorial — the READ-side companion to the in-memory
//! [`mandate_demo`](./mandate_demo.rs) and the offline browser verifier.
//!
//! Where `mandate_demo` runs the verdict core against a `HashMap` (no node, no
//! network), this points the typed, footgun-fenced
//! [`elara_runtime::mandate_sdk::MandateQueryClient`] at a **running node** and
//! turns its `/mandate/*` responses into misread-proof verdicts — closing the
//! "no runnable mandate tutorial beyond in-memory demos" gap.
//!
//! It is **read-only**: the SDK holds no key material and cannot issue or revoke.
//! That is the CLI's job (`elara-cli mandate-issue` / `mandate-revoke`), because
//! writing needs a Dilithium3 secret key — the read client has zero key custody.
//!
//! ## 1. Seed a mandate (the write side, via the CLI / dogfood script)
//!
//! ```text
//! NODE=http://127.0.0.1:9474 NETWORK=testnet scripts/mandate-dogfood.sh
//! ```
//!
//! That issues a mandate, emits two acts (one before, one after a revocation),
//! and prints a `mandate_id` plus two act record ids.
//!
//! ## 2. Query it (the read side, via this SDK)
//!
//! ```text
//! cargo run --features node-core --example mandate_query_live -- \
//!     http://127.0.0.1:9474 <mandate_id> [<act_id> ...]
//! ```
//!
//! With only a node URL + `mandate_id`, the example auto-discovers the mandate's
//! acts from `/mandate/{id}/acts` and drills into each. Pass explicit act ids to
//! query `/mandate/status/{record_id}` directly (the per-act path also surfaces
//! the verified leaf→root delegation lineage).
//!
//! ## What this teaches
//!
//! The SDK never exposes a bare `authorized: bool`. Every answer is a
//! [`MandateActVerdict`] whose only unqualified-authorization variant
//! (`Authorized`) is reachable solely when the node is authoritative AND scope was
//! enforced AND the flag is `Valid`. Any caveat (a snapshot-follower's incomplete
//! view, or v0's recorded-but-unenforced scope) downgrades it to
//! `AuthorizedWithCaveats`, where the caveat fields cannot be ignored. An
//! unrecognized flag from a newer node maps to `UnknownFlag`, never silently to
//! "not authorized". This example prints those distinctions verbatim.

use std::process::ExitCode;

use elara_runtime::mandate_sdk::{
    Coverage, MandateActVerdict, MandateDetail, MandateQueryClient, MandateSdkError,
};

const DEFAULT_NODE: &str = "http://127.0.0.1:9474";

fn coverage_note(c: Coverage) -> &'static str {
    match c {
        Coverage::Authoritative => "authoritative (full-history node — answer is complete)",
        Coverage::IncompleteSnapshotFollower => {
            "⚠ snapshot follower — a negative may be a false negative; query a full-history node"
        }
    }
}

/// Pretty-print one act verdict the honest way — the whole point of the SDK is
/// that a caller is forced to confront the caveats, so we surface them all.
fn print_verdict(label: &str, v: &MandateActVerdict) {
    println!("  ── {label}");
    // The single security-gating predicate: true ONLY for the unqualified state.
    println!("     is_authorized_strict() = {}", v.is_authorized_strict());
    match v {
        MandateActVerdict::Authorized {
            agent,
            principal,
            mandate_ref,
            act_timestamp_ms,
            lineage,
        } => {
            println!("     ✓ AUTHORIZED (unqualified — authoritative node, scope enforced, Valid)");
            println!("       agent       : {agent}");
            println!("       principal   : {}", principal.as_deref().unwrap_or("(none)"));
            println!("       mandate_ref : {mandate_ref}");
            println!("       act_ts_ms   : {act_timestamp_ms}");
            if !lineage.is_empty() {
                println!("       lineage (leaf→root, {} hop(s)):", lineage.len());
                for h in lineage {
                    println!(
                        "         #{} mandate={} principal={} agent={}",
                        h.hop_index, h.mandate_id, h.principal_identity_hash, h.agent_identity_hash
                    );
                }
            }
        }
        MandateActVerdict::AuthorizedWithCaveats {
            agent,
            principal,
            mandate_ref,
            coverage,
            scope_deferred,
            ..
        } => {
            println!("     ✓ authorized BUT caveated — do NOT use is_valid_on_this_node() as a gate:");
            if !coverage.is_authoritative() {
                println!("       • coverage: {}", coverage_note(*coverage));
            }
            if *scope_deferred {
                println!("       • scope_deferred: op/zone/amount were RECORDED but NOT enforced (v0)");
            }
            println!("       agent={agent} principal={} mandate_ref={mandate_ref}",
                principal.as_deref().unwrap_or("(none)"));
        }
        MandateActVerdict::NotAuthorized {
            flag,
            agent,
            principal,
            coverage,
            ..
        } => {
            println!("     ✗ NOT AUTHORIZED — flag = {}", flag.as_str());
            println!("       agent     : {}", agent.as_deref().unwrap_or("(none)"));
            // Anti-libel: a principal is named ONLY when the flag attributes to it.
            match principal {
                Some(p) => println!("       principal : {p} (this flag attributes the act to them)"),
                None => println!("       principal : (not named — this flag does not attribute to a principal)"),
            }
            if !coverage.is_authoritative() {
                println!("       • {}", coverage_note(*coverage));
            }
        }
        MandateActVerdict::NotAMandateAct { coverage } => {
            println!("     · not a mandate act on this node");
            println!("       • {}", coverage_note(*coverage));
        }
        MandateActVerdict::UnknownFlag { raw, coverage } => {
            println!("     ? node returned flag '{raw}' this client does not recognize (newer node)");
            println!("       — NOT treated as 'not authorized'. {}", coverage_note(*coverage));
        }
    }
    println!();
}

fn print_detail(d: &MandateDetail) {
    println!("  mandate_id  : {}", d.mandate_id);
    println!("  network_id  : {}", d.network_id);
    println!("  principal   : {}", d.principal_identity_hash);
    println!("  agent       : {}", d.agent_identity_hash);
    println!(
        "  scope       : ops={:?} zones={:?} max_amount={:?}",
        d.scope.allowed_ops, d.scope.allowed_zones, d.scope.max_amount
    );
    println!(
        "  scope_enforced_v0 : {}  (false ⇒ op/zone/amount recorded but NOT enforced in v0)",
        d.scope_enforced_v0
    );
    println!("  window_ms   : [{} .. {}]", d.not_before_ms, d.not_after_ms);
    match (d.revoked, d.revoked_at_ms) {
        (true, Some(ms)) => println!("  revoked     : YES at {ms} ms (principal-authorized)"),
        (true, None) => println!("  revoked     : YES"),
        (false, _) => println!("  revoked     : no"),
    }
    if let Some(parent) = &d.parent_mandate_id {
        println!("  parent      : {parent} (sub-delegation; max_depth={})", d.sub_delegation_max_depth);
    }
    println!();
}

async fn run(node_url: &str, mandate_id: &str, act_ids: &[String]) -> Result<(), MandateSdkError> {
    // Read-only client: a fixed node URL + redirects-disabled reqwest (SSRF guard).
    // It holds no key material — it can only query.
    let client = MandateQueryClient::new(node_url)?;
    println!("\n================ Elara live mandate query (read-only SDK) ================");
    println!("node: {}\n", client.node_url());

    // ── 1. The mandate itself: GET /mandate/{mandate_id} ────────────────────────
    println!("1. Mandate detail  (GET /mandate/{{id}})");
    match client.mandate_detail(mandate_id).await? {
        Some(detail) => print_detail(&detail),
        None => {
            println!("  (no such mandate on this node: {mandate_id})\n");
            return Ok(());
        }
    }

    // ── 2. The accountability enumeration: GET /mandate/{id}/acts ───────────────
    // "What did agents do under this authority?" — the query the layer exists for.
    println!("2. Acts under this mandate  (GET /mandate/{{id}}/acts)");
    let page = client.mandate_acts(mandate_id, None, 50).await?;
    let coverage = page.coverage();
    println!(
        "  mandate_found={} count={} page-coverage: {}",
        page.mandate_found,
        page.count,
        coverage_note(coverage)
    );
    if page.next_from.is_some() {
        println!("  (more pages available — pass next_from back as `from` to continue)");
    }
    println!();
    // Each compact row is classified with the PAGE-level coverage.
    let mut discovered: Vec<String> = Vec::new();
    for act in &page.acts {
        discovered.push(act.record_id.clone());
        print_verdict(
            &format!("act {} (from acts list)", act.record_id),
            &act.classify(coverage),
        );
    }

    // ── 3. Per-act drill-down: GET /mandate/status/{record_id} ──────────────────
    // The status path adds the verified leaf→root lineage the lean list omits.
    // Use the caller's explicit ids if given, else the ones we just discovered.
    let drill: &[String] = if act_ids.is_empty() { &discovered } else { act_ids };
    if !drill.is_empty() {
        println!("3. Per-act status drill-down  (GET /mandate/status/{{record_id}})");
        for id in drill {
            let status = client.act_status(id).await?;
            // Never branch on the raw fields — classify() folds in coverage +
            // scope-deferral + unknown-flag handling into one misread-proof verdict.
            print_verdict(&format!("status of {id}"), &status.classify());
        }
    }

    println!("=========================================================================");
    println!("Read-only: this SDK cannot issue or revoke. The verdict is only as");
    println!("complete as the queried node's view — coverage caveats say when to ask");
    println!("a full-history node. For a server-trust-free check, verify an offline");
    println!("bundle with mandate_sdk::verify_bundle (see examples/dump_mandate_bundle.rs).");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // args[1] = node url (optional, defaults to the local dev node)
    // args[2] = mandate_id (required)
    // args[3..] = optional explicit act record ids to drill into
    let (node_url, mandate_id, act_ids): (String, String, Vec<String>) = match args.len() {
        0 | 1 => {
            eprintln!(
                "usage: mandate_query_live [NODE_URL] <mandate_id> [act_id ...]\n\
                 \n\
                 Seed one first:\n\
                 \x20 NODE={DEFAULT_NODE} NETWORK=testnet scripts/mandate-dogfood.sh\n\
                 then pass the printed mandate_id (and optionally act ids) here.\n\
                 \n\
                 NODE_URL defaults to {DEFAULT_NODE} if the first arg looks like a 64-hex mandate_id."
            );
            return ExitCode::from(2);
        }
        // One arg: treat it as the mandate_id, default the node URL.
        2 => (DEFAULT_NODE.to_string(), args[1].clone(), Vec::new()),
        // Two+ args: if arg1 looks like a URL, it's the node; else it's the mandate_id.
        _ => {
            if args[1].starts_with("http://") || args[1].starts_with("https://") {
                (args[1].clone(), args[2].clone(), args[3..].to_vec())
            } else {
                (DEFAULT_NODE.to_string(), args[1].clone(), args[2..].to_vec())
            }
        }
    };

    // Explicit current-thread runtime — no #[tokio::main] macro dependency.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(&node_url, &mandate_id, &act_ids)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nquery failed: {e}");
            ExitCode::FAILURE
        }
    }
}
