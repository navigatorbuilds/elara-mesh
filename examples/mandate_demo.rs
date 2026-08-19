//! Agent-mandate demo — the accountability property OpenTimestamps and a bare
//! post-quantum signature **structurally cannot express**.
//!
//! Run it (no node, no network, no features — verdict logic is core):
//!
//! ```text
//! cargo run --example mandate_demo
//! ```
//!
//! ## What every other primitive can and cannot answer
//!
//! - **OpenTimestamps** answers *"these exact bytes existed by time T."* It says
//!   nothing about who produced them or whether they were allowed to.
//! - **A PQ signature** (Dilithium3 / ML-DSA) answers *"key K signed these
//!   bytes."* It says nothing about whether K was *authorized* to act — by whom,
//!   for what, or whether that authority was still valid when K signed.
//! - **An Elara mandate** answers the question the other two cannot:
//!   *"agent A was authorized by principal P, with scope S, valid at the act's
//!   signing time — or was it expired / revoked / not A's to use?"* — and it is
//!   queryable, time-aware, and revocable, forever.
//!
//! This matters most for AI agents: when an autonomous agent acts, the audit
//! question is never "did some key sign this?" — it is "was this agent *mandated*
//! to do this, and by whom?". That is the question this demo answers live.
//!
//! Every verdict below is produced by [`mandate::evaluate_mandate_v0`] — the
//! exact pure function the live node's `GET /mandate/status/{record_id}` endpoint
//! calls. The only thing swapped for this self-contained demo is the storage
//! backend: a `HashMap` standing in for the node's RocksDB column families (the
//! [`mandate::MandateResolver`] trait exists precisely so the verdict core is
//! I/O-free and re-runnable anywhere). Identities are real Dilithium3 keypairs;
//! every record is really signed and its carrier signature really verified.
//!
//! v0 scope note (honest-claims rule): what is enforced today is **agent-identity
//! binding + validity window + revocation** — the *who* and the *when*. A
//! mandate's op/zone scope is *recorded* but its enforcement is deferred to the
//! v1 taxonomy slice (see `docs/AGENT-DELEGATION.md`); this demo never claims an
//! op/zone scope check it does not perform.

use std::collections::{BTreeMap, HashMap};

use elara_runtime::crypto::hash::sha3_256_hex;
use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::mandate::{
    self, evaluate_mandate_v0, MandateClaim, MandateFlag, MandateRecord, MandateResolver,
    MandateScope, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
    MANDATE_REVOCATION_OP_KEY,
};
use elara_runtime::record::{Classification, ValidationRecord};

const NETWORK: &str = "testnet";

// Fixed timestamps (unix seconds) so the run is fully deterministic — no
// wall-clock anywhere. The mandate is valid across this whole window; the
// revocation lands in the middle of it.
const WINDOW_OPEN_MS: u64 = 1_700_000_000_000; // mandate not_before
const WINDOW_CLOSE_MS: u64 = 1_700_100_000_000; // mandate not_after (~27.7h later)
const T_ACT_AUTHORIZED: f64 = 1_700_000_500.0; // agent acts, early in the window
const T_ACT_IMPOSTOR: f64 = 1_700_001_000.0; // impostor acts, still in the window
const T_ACT_NOCHAIN: f64 = 1_700_001_500.0; // act under a non-existent mandate
const T_REVOKE: f64 = 1_700_050_000.0; // principal revokes (mid-window)
const T_ACT_AFTER_REVOKE: f64 = 1_700_060_000.0; // agent acts after revocation

/// In-memory stand-in for the node's `CF_MANDATE` / `CF_REVOCATION` column
/// families. Revocations are keyed by `(mandate_id, revoker)` — exactly as the
/// node stores them — so a revocation only counts when looked up under the
/// *principal's* identity (a spoofed revocation by anyone else lands under a
/// different key and is never consulted).
#[derive(Default)]
struct MemResolver {
    mandates: HashMap<String, MandateRecord>,
    revocations: HashMap<(String, String), u64>,
}

impl MandateResolver for MemResolver {
    fn mandate(&self, mandate_id: &str) -> Option<MandateRecord> {
        self.mandates.get(mandate_id).cloned()
    }
    fn revocation(&self, mandate_id: &str, principal_identity_hash: &str) -> Option<u64> {
        self.revocations
            .get(&(mandate_id.to_string(), principal_identity_hash.to_string()))
            .copied()
    }
}

/// Build a *real* signed carrier record. `set_ts_secs` is applied BEFORE signing
/// (the timestamp is inside `signable_bytes()`), so the carrier signature covers
/// it — then we verify the signature, mirroring the node's ingest path.
fn signed_record(
    signer: &Identity,
    meta: BTreeMap<String, serde_json::Value>,
    ts_secs: f64,
) -> ValidationRecord {
    let mut rec = ValidationRecord::create(
        b"agent-mandate-demo",
        signer.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    rec.timestamp = ts_secs;
    signer
        .sign_record(&mut rec)
        .expect("sign carrier record");
    // The carrier signature is the only thing binding the payload to the signer
    // — verify it the same way the node (and the browser verifier) does.
    let sig = rec.signature.as_ref().expect("record is signed");
    let ok = Identity::verify(&rec.signable_bytes(), sig, &rec.creator_public_key)
        .expect("verify call");
    assert!(ok, "carrier signature must verify over canonical bytes");
    rec
}

/// Recompute a verdict the way the node's query endpoint does: derive the signer
/// from the act's embedded key, take the act's own signed timestamp, and run the
/// pure v0 verdict against current mandate/revocation state.
fn verdict(act: &ValidationRecord, resolver: &MemResolver) -> MandateFlag {
    let signer = sha3_256_hex(&act.creator_public_key);
    let mandate_ref = act
        .metadata
        .get(MANDATE_REF_METADATA_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let claim = MandateClaim {
        signer_identity_hash: &signer,
        act_timestamp_ms: mandate::secs_f64_to_ms_saturating(act.timestamp),
        mandate_ref,
        op: "",   // v0 defers op/zone scope (see module note)
        zone: "", // — only who + when are enforced today
        amount: None,
        network_id: NETWORK,
    };
    evaluate_mandate_v0(&claim, resolver)
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// One line per scenario: the verdict, plus what OTS / a bare sig would (not) see.
fn report(title: &str, act: &ValidationRecord, flag: MandateFlag) {
    println!("  ── {title}");
    println!("     act record id : {}", short(&act.id));
    println!(
        "     signer        : {}",
        short(&sha3_256_hex(&act.creator_public_key))
    );
    println!(
        "     VERDICT        : {}   (authorized: {} · names principal: {})",
        flag.as_str().to_uppercase(),
        if flag.is_authorized() { "yes" } else { "NO" },
        if flag.attributes_to_principal() { "yes" } else { "no" },
    );
    println!("     OpenTimestamps would say : \"these bytes existed by T\"");
    println!("     a bare PQ signature says : \"this key signed these bytes\"");
    println!("     the mandate layer says   : \"{}\"", explain(flag));
    println!();
}

fn explain(flag: MandateFlag) -> &'static str {
    match flag {
        MandateFlag::Valid => "this agent WAS authorized by the principal, at this signing time",
        MandateFlag::AgentMismatch => {
            "the signer is NOT the mandated agent — the named principal is EXONERATED"
        }
        MandateFlag::NoChain => "no such mandate exists — the act is unauthorized (binds the signer only)",
        MandateFlag::PostRevocation => "the principal had REVOKED this mandate before this act was signed",
        MandateFlag::Lapsed => "the mandate's validity window had closed before this act",
        MandateFlag::NotYetValid => "the mandate's validity window had not yet opened",
        _ => "see MandateFlag",
    }
}

fn main() {
    println!("\n================ Elara agent-mandate demo ================");
    println!("What can be proven about an act, beyond \"it existed\" and \"a key signed it\"?\n");

    // ── Cast: three real Dilithium3 identities ──────────────────────────────
    let principal = Identity::generate(EntityType::Human, CryptoProfile::ProfileB)
        .expect("keygen principal");
    let agent = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).expect("keygen agent");
    let impostor =
        Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).expect("keygen impostor");
    println!("Principal (issuer) : {}", short(&principal.identity_hash));
    println!("Agent  (mandated)  : {}", short(&agent.identity_hash));
    println!("Impostor (rogue AI): {}\n", short(&impostor.identity_hash));

    let mut resolver = MemResolver::default();

    // ── 1. The principal issues a scoped mandate to the agent ───────────────
    // Scope: the agent may emit "agent_audit" provenance records (the kind
    // Elara's own build-agent emits via hook). v0 records the op/zone scope but
    // enforces only identity + window + revocation; the carrier signature IS the
    // principal's signature over the mandate (no embedded key — the ledger
    // mandate is ~2 KB, not ~6 KB).
    let scope = MandateScope {
        allowed_ops: vec!["agent_audit".to_string()],
        allowed_zones: vec!["*".to_string()],
        max_amount: None,
    };
    let m = MandateRecord::new_root(
        NETWORK,
        &principal.identity_hash,
        &agent.identity_hash,
        scope,
        WINDOW_OPEN_MS,
        WINDOW_CLOSE_MS,
        0,           // sub_delegation_max_depth
        "demo-0001", // nonce — re-authorizing is always a NEW mandate, never an un-revoke
    );
    let mandate_id = m.mandate_id();

    // Wrap the mandate in a carrier record signed by the PRINCIPAL.
    let mut issue_meta = BTreeMap::new();
    issue_meta.insert(MANDATE_OP_KEY.to_string(), serde_json::to_value(&m).unwrap());
    let issue_rec = signed_record(&principal, issue_meta, 1_700_000_000.0);

    // The ingest binding the node enforces: sha3(carrier creator pk) == principal.
    let carrier_principal = sha3_256_hex(&issue_rec.creator_public_key);
    assert_eq!(
        carrier_principal, principal.identity_hash,
        "principal-binding: the carrier signature IS the principal's signature"
    );
    resolver.mandates.insert(mandate_id.clone(), m);

    println!("1. Principal issues a mandate (carrier signed + verified, principal-bound):");
    println!("   mandate_id : {}", short(&mandate_id));
    println!("   grant      : agent may emit `agent_audit` records, window [open..close]");
    println!("   (op/zone scope recorded; v0 enforces identity + window + revocation)\n");

    // ── 2. The four verdicts a key + a timestamp can never give you ─────────
    println!("2. Now judge five acts. Same chain. Same crypto. Different ANSWERS:\n");

    // (A) The mandated agent acts within the window, before any revocation.
    let mut a_meta = BTreeMap::new();
    a_meta.insert(
        MANDATE_REF_METADATA_KEY.to_string(),
        serde_json::Value::String(mandate_id.clone()),
    );
    let act_authorized = signed_record(&agent, a_meta, T_ACT_AUTHORIZED);
    report(
        "(A) the mandated agent acts, within the window",
        &act_authorized,
        verdict(&act_authorized, &resolver),
    );

    // (B) The impostor presents the agent's mandate. Crypto is perfect — the
    //     impostor really signed the act. But it is not THEIR mandate.
    let mut b_meta = BTreeMap::new();
    b_meta.insert(
        MANDATE_REF_METADATA_KEY.to_string(),
        serde_json::Value::String(mandate_id.clone()),
    );
    let act_impostor = signed_record(&impostor, b_meta, T_ACT_IMPOSTOR);
    report(
        "(B) a DIFFERENT AI uses the agent's mandate (perfectly signed)",
        &act_impostor,
        verdict(&act_impostor, &resolver),
    );

    // (C) The agent references a mandate that was never issued.
    let mut c_meta = BTreeMap::new();
    c_meta.insert(
        MANDATE_REF_METADATA_KEY.to_string(),
        serde_json::Value::String("ff".repeat(32)),
    );
    let act_nochain = signed_record(&agent, c_meta, T_ACT_NOCHAIN);
    report(
        "(C) the agent claims a mandate that does not exist",
        &act_nochain,
        verdict(&act_nochain, &resolver),
    );

    // ── 3. The principal revokes — keyed by (mandate_id, principal) ─────────
    let rev = RevocationRecord::new(NETWORK, mandate_id.clone(), "agent key suspected compromised");
    let mut rev_meta = BTreeMap::new();
    rev_meta.insert(
        MANDATE_REVOCATION_OP_KEY.to_string(),
        serde_json::to_value(&rev).unwrap(),
    );
    let rev_rec = signed_record(&principal, rev_meta, T_REVOKE);
    // Effective at the carrier's SIGNED time, under the revoker's key.
    let revoker = sha3_256_hex(&rev_rec.creator_public_key);
    resolver.revocations.insert(
        (mandate_id.clone(), revoker),
        mandate::secs_f64_to_ms_saturating(T_REVOKE),
    );
    println!("3. Principal REVOKES the mandate at T_revoke (signed, principal-keyed).\n");

    // (D) The agent acts AFTER the revocation.
    let mut d_meta = BTreeMap::new();
    d_meta.insert(
        MANDATE_REF_METADATA_KEY.to_string(),
        serde_json::Value::String(mandate_id.clone()),
    );
    let act_after = signed_record(&agent, d_meta, T_ACT_AFTER_REVOKE);
    report(
        "(D) the agent acts AFTER the principal revoked",
        &act_after,
        verdict(&act_after, &resolver),
    );

    // (E) The killer property: re-judge act (A) — signed BEFORE the revocation —
    //     now that the revocation exists. It is STILL Valid. Revocation is not
    //     retroactive: an act authorized when signed stays authorized forever.
    //     No timestamp-or-signature scheme can make this distinction, because
    //     neither carries the notion of "authority valid at signing time".
    let flag_a_again = verdict(&act_authorized, &resolver);
    report(
        "(E) re-judge act (A) AFTER revocation — authority is not retroactive",
        &act_authorized,
        flag_a_again,
    );

    // ── Summary ─────────────────────────────────────────────────────────────
    println!("================ summary ================");
    println!("  (A) mandated agent, in window      -> {}", verdict(&act_authorized, &resolver).as_str());
    println!("  (B) impostor with agent's mandate  -> {}", verdict(&act_impostor, &resolver).as_str());
    println!("  (C) mandate that never existed     -> {}", verdict(&act_nochain, &resolver).as_str());
    println!("  (D) agent acting post-revocation   -> {}", verdict(&act_after, &resolver).as_str());
    println!("  (E) pre-revocation act, re-judged  -> {}  (unchanged: not retroactive)", flag_a_again.as_str());
    println!();
    println!("OpenTimestamps + a PQ signature can prove (A)-(E) all EXISTED and were");
    println!("SIGNED. Only a mandate layer can tell you which were AUTHORIZED — by whom,");
    println!("for what, and whether that authority still held the moment the agent acted.");
    println!("=========================================\n");

    // Fail loudly if the verdict logic ever drifts from the documented story.
    assert_eq!(verdict(&act_authorized, &resolver), MandateFlag::Valid);
    assert_eq!(verdict(&act_impostor, &resolver), MandateFlag::AgentMismatch);
    assert_eq!(verdict(&act_nochain, &resolver), MandateFlag::NoChain);
    assert_eq!(verdict(&act_after, &resolver), MandateFlag::PostRevocation);
    assert_eq!(flag_a_again, MandateFlag::Valid);
}
