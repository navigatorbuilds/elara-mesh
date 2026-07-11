// Stand-alone PQ handshake probe. Run with `cargo run --example pq_probe -- 127.0.0.1:9574`
// Just: dial, ping, status, print outcome.
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).expect("usage: pq_probe <addr:port>");
    use elara_runtime::crypto::pqc::dilithium3_keygen;
    use elara_runtime::network::pq_client::PqNodeClient;
    use elara_runtime::network::pq_transport::PeerIdentityStore;

    let kp = dilithium3_keygen()?;
    let (pk, sk) = kp.into_parts();
    let pins = Arc::new(PeerIdentityStore::in_memory());
    let client = PqNodeClient::new(pk, sk, pins.clone());

    let t0 = std::time::Instant::now();
    let ping_ok = client.ping(&target).await;
    let ping_ms = t0.elapsed().as_millis();

    let status = client.get_status(&target).await;
    let peer_hash = pins.list().into_iter().next().map(|(_, h)| h).unwrap_or_default();

    println!("target:          {target}");
    println!("ping:            {}  ({} ms)", if ping_ok {"OK"} else {"FAIL"}, ping_ms);
    match &status {
        Ok(v) => println!("status.version:  {}", v.get("version").and_then(|x| x.as_str()).unwrap_or("?")),
        Err(e) => println!("status:          ERR {e}"),
    }
    println!("pinned identity: {peer_hash}");
    Ok(())
}
