//! Live-node light-client tutorial — verify an account **without trusting the
//! node's word for it**.
//!
//! This is the runnable companion to the light-client SDK docs
//! (internal design notes) and the in-browser record verifier: where those
//! explain the design, this points the typed, SSRF-fenced
//! [`elara_runtime::network::light_sdk::LightClient`] at a **running node** and
//! cryptographically verifies a server-claimed balance against its Merkle proof
//! — closing the "no runnable light-client tutorial beyond in-memory demos" gap.
//!
//! It is **read-only**: the SDK holds no key material and only ever talks to its
//! one fixed seed (no redirects — a hostile seed cannot bounce it at an internal
//! address).
//!
//! ## Run it
//!
//! ```text
//! cargo run --features node-core --example light_client_live
//! cargo run --features node-core --example light_client_live -- http://127.0.0.1:9474 [<identity-hex>]
//! ```
//!
//! With no identity argument it auto-discovers the node's genesis authority from
//! `/status` (an account that always exists), so it runs zero-config against any
//! node, including the local dev node.
//!
//! ## What this teaches — "trust the math, not the server"
//!
//! 1. [`LightClient::verify_balance`] fetches `/proof/account/{id}` and proves the
//!    server-claimed [`AccountState`] is consistent with the proof: it re-hashes
//!    the leaf and folds the 256-level sparse-Merkle path back up to the root. A
//!    node that lies about your balance is caught by arithmetic, not by reputation.
//! 2. The two tamper beats make that concrete with the pure
//!    [`verify_account_against_proof`] kernel (no I/O, no clock): inflate the
//!    claimed balance → `LeafHashMismatch`; corrupt one Merkle sibling →
//!    `ProofInvalid`. This is the light-client analogue of the browser verifier's
//!    "flip one byte → ✗ FAILED".
//! 3. [`LightClient::verify_balance_against_trusted_seal`] is the fully trustless
//!    tier: pin a seal root you obtained out-of-band (a checkpoint, an anchor) and
//!    the SDK refuses any proof whose binding does not match it exactly — and
//!    *fails closed* when the node gives it no seal epoch to pin against.
//!
//! ## What this does NOT prove
//!
//! `verify_balance` alone confirms the state is consistent with the proof's root
//! and relays the *server-asserted* `bound_to_seal` flag. To remove trust in the
//! server's "this root is sealed" claim you must pin the seal yourself — that is
//! tier 3. For a record's signature/identity with zero server trust at all, see
//! `examples/verify/` and the offline browser verifier.

use std::process::ExitCode;
use std::time::Duration;

use elara_runtime::network::light_sdk::{
    verify_account_against_proof, LightClient, LightClientError, VerifiedAccount, VerifyOpts,
};
use elara_runtime::accounting::ledger::AccountState;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

const DEFAULT_NODE: &str = "http://127.0.0.1:9474";

/// Ask the node who its genesis authority is — an account guaranteed to exist on
/// any chain — so the tutorial needs no hand-picked identity. Uses the same
/// no-redirect policy the SDK itself does.
async fn discover_genesis_authority(node_url: &str) -> Result<String, BoxErr> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let body: serde_json::Value = http
        .get(format!("{node_url}/status"))
        .send()
        .await?
        .json()
        .await?;
    body.get("genesis_authority")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| "node /status did not return a genesis_authority field".into())
}

fn print_verified(v: &VerifiedAccount) {
    println!("   ✓ VERIFIED — the server-claimed state folds to the proof root.");
    println!("     identity      : {}", v.identity);
    // Raw smallest-unit integers: the lesson is the verification, not the
    // denomination. (The public unit is the beat; these are its base units.)
    println!("     available     : {} base units", v.state.available);
    println!("     staked        : {} base units", v.state.staked);
    println!("     tx_count      : {}", v.state.tx_count);
    println!("     proof root    : {}", hex::encode(v.root));
    println!(
        "     bound_to_seal : {}  (server-asserted — pin it yourself in tier 3 to remove that trust)",
        v.bound_to_seal
    );
    match v.epoch_number {
        Some(e) => println!("     seal epoch    : {e}"),
        None => println!("     seal epoch    : (node did not surface one in this proof)"),
    }
    println!();
}

async fn run(node_url: &str, identity_arg: Option<&str>) -> Result<(), BoxErr> {
    println!("\n=========== Elara live light-client verify (read-only SDK) ===========");
    println!("node: {node_url}");

    let identity = match identity_arg {
        Some(id) => id.to_string(),
        None => {
            let g = discover_genesis_authority(node_url).await?;
            println!("identity: {g}  (auto-discovered genesis authority)\n");
            g
        }
    };
    if identity_arg.is_some() {
        println!("identity: {identity}\n");
    }

    let client = LightClient::new(node_url)?;

    // ── 1. Fetch the proof bundle: GET /proof/account/{id} ──────────────────────
    println!("1. Fetch proof bundle  (GET /proof/account/{{id}})");
    let proof_resp = match client.fetch_proof(&identity).await? {
        Some(r) => r,
        None => {
            println!("   (no such account on this node: {identity})\n");
            return Ok(());
        }
    };
    println!(
        "   root={} bound_to_seal={} siblings={} (compressed; ≤256)",
        hex::encode(proof_resp.proof.root),
        proof_resp.bound_to_seal,
        proof_resp.proof.siblings.len()
    );
    println!();

    // ── 2. Cryptographically verify the balance: trust the math ─────────────────
    println!("2. Verify balance  (re-hash leaf + fold 256-level SMT path → root)");
    let verified = client.verify_balance(&identity, VerifyOpts::default()).await?;
    print_verified(&verified);

    // The fetched bundle carries the inline state the verify just confirmed; we
    // reuse it to drive the tamper beats through the pure (no-I/O) kernel.
    let claimed: AccountState = proof_resp
        .account_state
        .clone()
        .ok_or("server omitted account_state from the /proof response")?;
    let proof = proof_resp.proof.clone();

    // ── 3. Tamper beats — why a lying or compromised node is caught ─────────────
    println!("3. Tamper detection  (pure verify_account_against_proof kernel — no I/O)");

    // 3a. Baseline: the real, untouched state verifies.
    match verify_account_against_proof(&claimed, &proof) {
        Ok(()) => println!("   3a. untouched state                         → ✓ verifies (baseline)"),
        Err(e) => return Err(format!("baseline verify unexpectedly failed: {e}").into()),
    }

    // 3b. The node lies about the balance: inflate `available`. The leaf re-hash
    //     no longer matches the proof's committed `state_hash`.
    let mut lied = claimed.clone();
    lied.available = lied.available.saturating_add(1_000_000_000);
    match verify_account_against_proof(&lied, &proof) {
        Err(LightClientError::LeafHashMismatch { .. }) => {
            println!("   3b. claim +1e9 to the balance               → ✗ LeafHashMismatch (rejected)");
        }
        other => return Err(format!("expected LeafHashMismatch on inflated balance, got {other:?}").into()),
    }

    // 3c. The node forges the proof path: flip one byte of a Merkle sibling (or
    //     the root if the tree is degenerate). The siblings no longer reconstruct
    //     the committed root.
    let mut forged = proof.clone();
    let what = if let Some(first) = forged.siblings.first_mut() {
        first[0] ^= 0x01;
        "one Merkle sibling byte"
    } else {
        forged.root[0] ^= 0x01;
        "the proof root byte"
    };
    match verify_account_against_proof(&claimed, &forged) {
        Err(LightClientError::ProofInvalid) => {
            println!("   3c. flip {what:<24} → ✗ ProofInvalid (rejected)");
        }
        other => return Err(format!("expected ProofInvalid on corrupted proof, got {other:?}").into()),
    }
    println!();

    // ── 4. Trustless tier: bind to a seal you pinned yourself ───────────────────
    println!("4. Trusted-seal binding  (verify_balance_against_trusted_seal)");
    match verified.epoch_number {
        Some(epoch) => {
            // Honest path: pin the (epoch, root) the SDK just verified — in real
            // use you'd obtain these out-of-band from a checkpoint/anchor, not from
            // the same response — then prove a one-byte-different root is refused.
            client
                .verify_balance_against_trusted_seal(
                    &identity,
                    epoch,
                    &verified.root,
                    VerifyOpts::default(),
                )
                .await?;
            println!("   4a. pin (epoch {epoch}, the verified root) → ✓ binding matches");

            let mut wrong_root = verified.root;
            wrong_root[0] ^= 0x01;
            match client
                .verify_balance_against_trusted_seal(&identity, epoch, &wrong_root, VerifyOpts::default())
                .await
            {
                Err(LightClientError::TrustedSealRootMismatch { .. }) => {
                    println!("   4b. pin a one-byte-different root        → ✗ TrustedSealRootMismatch (rejected)");
                }
                other => return Err(format!("expected TrustedSealRootMismatch, got {other:?}").into()),
            }
        }
        None => {
            // Fail-closed: no seal epoch to pin against ⇒ the SDK refuses to claim
            // a trusted-seal binding rather than inventing one. That refusal IS the
            // correct behaviour, and the example asserts it.
            match client
                .verify_balance_against_trusted_seal(&identity, 0, &verified.root, VerifyOpts::default())
                .await
            {
                Err(LightClientError::TrustedSealEpochUnknown) => {
                    println!("   this node surfaced no seal epoch in the proof, so the trustless");
                    println!("   pin cannot be demonstrated here — and the SDK correctly FAILS");
                    println!("   CLOSED (TrustedSealEpochUnknown) instead of asserting a binding.");
                }
                other => return Err(format!("expected fail-closed TrustedSealEpochUnknown, got {other:?}").into()),
            }
        }
    }
    println!();

    println!("=====================================================================");
    println!("Read-only: the SDK holds no key and cannot move funds. tier-2 verify");
    println!("proves the state matches the proof root; tier-3 (pin your own seal)");
    println!("removes trust in the server's 'this root is sealed' claim entirely.");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // [NODE_URL] [identity-hex]. If the first arg looks like a URL it's the node;
    // otherwise it's the identity and the node defaults to the local dev node.
    let (node_url, identity): (String, Option<String>) = match args.get(1).map(String::as_str) {
        None => (DEFAULT_NODE.to_string(), None),
        Some(a1) if a1.starts_with("http://") || a1.starts_with("https://") => {
            (a1.to_string(), args.get(2).cloned())
        }
        Some(a1) => (DEFAULT_NODE.to_string(), Some(a1.to_string())),
    };

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

    match rt.block_on(run(&node_url, identity.as_deref())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nlight-client verify failed: {e}");
            ExitCode::FAILURE
        }
    }
}
