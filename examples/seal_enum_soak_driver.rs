// R3-8 seal-enumeration soak driver (internal design notes).
//
// Floods one zone-epoch with unique signed validation records so the next
// seal's window exceeds SEAL_INLINE_ENUM_MAX (96) and the producer omits the
// inline `epoch_record_hashes` — forcing every consumer onto the
// derive-when-absent path at real testnet rates, no emission-knob override
// needed. Watch `elara_seal_enum_derived_total` /
// `elara_seal_enum_derive_miss_total` on every node that holds the window.
//
// Run with:
//   cargo run --release --features node-core --example seal_enum_soak_driver \
//     -- [target] [count] [identities] [pace_ms]
// Defaults: http://127.0.0.1:9472, 150 records, 15 identities, 50 ms/record.
//
// Identity count matters: fresh identities are continuity-tier0 and throttled
// at 10 records/day each, so count must be <= 10 * identities or the tail of
// the burst is rejected ("daily record limit exceeded"). 15 idents x 10 recs
// clears SEAL_INLINE_ENUM_MAX (96) with ~54 margin in one window.
//
// Pace matters too: an unpaced loopback burst (~158 rec/s) trips the ingress
// request limiter with HTTP 429s around ~110 requests. 50 ms/record = 20
// rec/s — TARGET_ZONE_RATE, the honest hot-zone shape — finishes 150 records
// in ~7.5 s, still inside any adaptive window (floor 5 s only pins under
// sustained load).
//
// The submit leg is the plain HTTP wire-bytes POST /records (loopback data
// plane) — the same admission path gossip re-ingest uses, so the soak
// exercises the exact gate that used to self-wedge at ~123 inline hashes.

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::record::{Classification, ValidationRecord};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "http://127.0.0.1:9472".into());
    let count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(150);
    let n_idents: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(15);
    let pace_ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(50);

    println!("[soak-driver] target={target} count={count} identities={n_idents} pace_ms={pace_ms}");

    let mut identities = Vec::with_capacity(n_idents);
    for i in 0..n_idents {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity generation");
        println!("[soak-driver] identity {i}: {}", &id.identity_hash[..16]);
        identities.push(id);
    }

    let run_tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client");

    let url = format!("{}/records", target.trim_end_matches('/'));
    let started = std::time::Instant::now();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut errors = 0usize;

    for i in 0..count {
        if pace_ms > 0 && i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(pace_ms)).await;
        }
        let identity = &identities[i % n_idents];
        let content = format!("seal-enum-soak run={run_tag} seq={i}");
        let mut record = ValidationRecord::create(
            content.as_bytes(),
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        // Slot-nonce anti-spam gate: each identity claims one record per slot,
        // and create() defaults nonce=0 — a second slot-0 record from the same
        // identity is rejected at ingest ("slot conflict"). Fresh identities
        // start at slot 0; claim densely upward per identity.
        record.nonce = (i / n_idents) as u64;
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).expect("sign record"));
        let wire = record.to_bytes();

        match http
            .post(&url)
            .header("x-elara-protocol-version", "1")
            .header("x-elara-network-id", "testnet")
            .header("Content-Type", "application/octet-stream")
            .body(wire)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let ok = body.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok {
                    accepted += 1;
                } else {
                    rejected += 1;
                    if rejected <= 5 {
                        println!("[soak-driver] seq={i} REJECTED http={status} body={body}");
                    }
                }
            }
            Err(e) => {
                errors += 1;
                if errors <= 5 {
                    println!("[soak-driver] seq={i} ERROR {e}");
                }
            }
        }
    }

    let elapsed = started.elapsed();
    println!(
        "[soak-driver] done: accepted={accepted} rejected={rejected} errors={errors} in {:.1}s ({:.0} rec/s)",
        elapsed.as_secs_f64(),
        accepted as f64 / elapsed.as_secs_f64().max(0.001),
    );
    // The whole burst must land inside ONE seal window to push it past the
    // inline cap — at adaptive-idle intervals (>=60 s) any sub-20 s burst
    // qualifies. Non-zero exit on any shortfall so scripted soaks fail loud.
    if accepted < count {
        std::process::exit(1);
    }
}
