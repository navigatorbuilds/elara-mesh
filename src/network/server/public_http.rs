//! Hardened accept loop for the PUBLIC classical-HTTP listener.
//!
//! Replaces `axum::serve` at the one internet-exposed bind site
//! (design + 4-seat fusion audit + Opus final-verify:
//! internal design notes). `axum::serve` cannot arm
//! hyper's `header_read_timeout` — it hardcodes a timer-less builder — so a
//! slow-header (slowloris) client held a socket + task open forever. This loop
//! adds, in accept order:
//!
//! 1. transient-`accept()`-error tolerance (axum `Listener` parity: retry
//!    connection-level kinds at once, sleep 1s on resource errors like EMFILE
//!    so fd pressure cannot spin or kill the listener);
//! 2. loopback-exempt admission — a global connection cap
//!    (`http_conn_cap`, try-acquire-or-DROP + `http_conn_shed_total`) and a
//!    per-remote-IP sub-cap (`http_conn_per_ip_cap` +
//!    `http_conn_per_ip_shed_total`) so one address cannot hold every slot;
//! 3. a PURE `hyper::server::conn::http1` builder with a real
//!    `TokioTimer` + `header_read_timeout` — pure-h1 on purpose: the
//!    hyper-util `auto` builder's protocol sniff (`ReadVersion`) reads with NO
//!    deadline, so a zero-byte client would park untouchable before the
//!    timeout ever armed. Nothing on this listener speaks h2c (browsers never
//!    do h2c on plain http; `/pq-ws` is RFC 6455 HTTP/1.1 Upgrade), so
//!    dropping auto-detection closes that hole by construction;
//! 4. graceful shutdown with a BOUNDED drain: hyper-util's `GracefulShutdown`
//!    does not implement `GracefulConnection` for http1's
//!    `UpgradeableConnection` (final-verify C4), so each conn task `select!`s
//!    the connection against a shutdown watch and calls the connection's
//!    inherent `graceful_shutdown()` itself; the top level then waits for the
//!    axum-style close-channel drain under `drain_timeout`. Bounded on
//!    purpose — durability completes inside the caller's shutdown future
//!    BEFORE the drain starts, and an unbounded drain (axum's behavior) hangs
//!    on any never-ending response body.
//!
//! ConnectInfo fidelity: the per-conn service comes from
//! `into_make_service_with_connect_info::<SocketAddr>()` called with the real
//! peer address (`impl Connected<SocketAddr> for SocketAddr`), plus axum's own
//! `Request<Incoming> -> Request<Body>` adaptation, so handlers see exactly
//! what `axum::serve` gives them (per-IP SSE cap, `public_route_gate`, and
//! the rate limiter all read it).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tower::{Service, ServiceExt};
use tracing::{debug, trace, warn};

/// Knobs for one hardened listener instance. Split out of `NodeConfig` so the
/// loop is testable without a full `NodeState` (tests arm a 1s header deadline
/// and a tiny cap; production wires `NodeConfig` + `NodeState` counters).
pub struct PublicHttpOpts {
    /// Global concurrent-connection ceiling (`http_conn_cap`), min 1.
    pub conn_cap: usize,
    /// Per-remote-IP ceiling within the global cap (`http_conn_per_ip_cap`).
    pub per_ip_cap: u64,
    /// hyper http1 `header_read_timeout` (`http_header_read_timeout_secs`).
    pub header_read_timeout: Duration,
    /// Upper bound on the post-shutdown connection drain.
    pub drain_timeout: Duration,
    /// Production = true. Tests set false so loopback sockets exercise the
    /// caps (the caps are otherwise unreachable from a unit test, which can
    /// only connect from 127.0.0.1). The header deadline applies to ALL
    /// connections regardless — it is not part of the exemption.
    pub exempt_loopback: bool,
    /// `NodeState.http_conn_shed_total` (global-cap sheds).
    pub shed_total: Arc<AtomicU64>,
    /// `NodeState.http_conn_per_ip_shed_total` (per-IP-cap sheds).
    pub per_ip_shed_total: Arc<AtomicU64>,
}

/// Live per-IP connection counts. Entries are removed at zero so the map is
/// O(distinct active remote IPs), never O(history).
struct PerIpSlots {
    map: Mutex<HashMap<IpAddr, u64>>,
}

impl PerIpSlots {
    /// Poison-recovering lock: an unwound conn task must not wedge admission
    /// (mirrors the crate's `LockRecover` posture; counts are advisory
    /// admission state, safe to read after a panic elsewhere).
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, u64>> {
        match self.map.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Claim one slot for `ip` if under `cap`. Returns false = shed.
    fn try_claim(&self, ip: IpAddr, cap: u64) -> bool {
        let mut m = self.lock();
        let n = m.entry(ip).or_insert(0);
        if *n >= cap {
            false
        } else {
            *n += 1;
            true
        }
    }
}

/// RAII per-IP slot: releases the count when the connection task ends
/// (same shape as the SSE `SsePerIpSlot`, one layer lower).
struct PerIpSlot {
    slots: Arc<PerIpSlots>,
    ip: IpAddr,
}

impl Drop for PerIpSlot {
    fn drop(&mut self) {
        let mut m = self.slots.lock();
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// axum `Listener` parity for accept errors: these three kinds are per-peer
/// noise — retry immediately. Everything else (EMFILE/ENFILE fd pressure,
/// ENOBUFS, …) sleeps 1s so the loop neither spins hot nor dies.
fn accept_error_is_connection_noise(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Serve `app` on `listener` until `shutdown` completes, then drain (bounded).
///
/// The caller's `shutdown` future is the same one previously handed to
/// `axum::serve(...).with_graceful_shutdown(...)` — all durability work
/// (RocksDB snapshot saves) happens inside it, so it has fully completed
/// before the drain here begins; the process force-exits after this returns.
pub async fn serve_public_http(
    listener: tokio::net::TcpListener,
    app: Router,
    opts: PublicHttpOpts,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(opts.conn_cap.max(1)));
    let per_ip = Arc::new(PerIpSlots { map: Mutex::new(HashMap::new()) });

    // Shutdown fan-out: each conn task watches for the signal and calls the
    // connection's inherent graceful_shutdown(). Close-channel drain tracking
    // is axum's shape: every task holds a close_rx clone dropped at task end;
    // close_tx.closed() resolves when the last one is gone.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let (close_tx, close_rx) = tokio::sync::watch::channel(());

    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, remote) = tokio::select! {
            _ = shutdown.as_mut() => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    if accept_error_is_connection_noise(&e) {
                        continue;
                    }
                    warn!("public-http accept error (backing off 1s): {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };

        let ip = remote.ip();
        let exempt = opts.exempt_loopback && super::ip_is_loopback_canonical(ip);
        let (permit, ip_slot) = if exempt {
            (None, None)
        } else {
            // Global cap first: try-acquire-or-DROP (accept-path semantics —
            // a bounded wait would hold the very fd the cap protects).
            let permit = match conn_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    opts.shed_total.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
            };
            if !per_ip.try_claim(ip, opts.per_ip_cap.max(1)) {
                opts.per_ip_shed_total.fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }
            (
                Some(permit),
                Some(PerIpSlot { slots: per_ip.clone(), ip }),
            )
        };

        // axum-serve fidelity: ready() + call(remote) injects
        // ConnectInfo<SocketAddr>; map_request adapts hyper's Incoming body.
        // (`<_ as ServiceExt<SocketAddr>>` pins the request type — the make-
        // service also implements Service<IncomingStream>, so bare `.ready()`
        // is ambiguous.)
        <_ as ServiceExt<SocketAddr>>::ready(&mut make_service)
            .await
            .unwrap_or_else(|err| match err {});
        let tower_service = match Service::<SocketAddr>::call(&mut make_service, remote).await {
            Ok(svc) => svc,
            Err(err) => match err {},
        };
        let tower_service = tower_service
            .map_request(|req: hyper::Request<hyper::body::Incoming>| req.map(axum::body::Body::new));
        let hyper_service = TowerToHyperService::new(tower_service);

        let mut sig = shutdown_rx.clone();
        let close_guard = close_rx.clone();
        let header_read_timeout = opts.header_read_timeout;
        let conn_drain = opts.drain_timeout;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            // Held for the task's whole life: admission permits + drain guard.
            let _permit = permit;
            let _ip_slot = ip_slot;
            let _close_guard = close_guard;

            let mut builder = hyper::server::conn::http1::Builder::new();
            // Timer + timeout are pinned TOGETHER on the same builder: a
            // Configured timeout with no timer is a per-connection panic
            // inside hyper (time.rs "timeout set, but no timer set") — under
            // panic=unwind that reads as a silent full outage of external
            // traffic. The header-deadline tests below exist to keep this
            // invariant load-bearing.
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);
            let conn = builder
                .serve_connection(io, hyper_service)
                .with_upgrades();
            let mut conn = std::pin::pin!(conn);

            tokio::select! {
                res = conn.as_mut() => {
                    if let Err(e) = res {
                        trace!("public-http connection ended: {e}");
                    }
                }
                _ = sig.changed() => {
                    // Finish the in-flight exchange, refuse keep-alive reuse,
                    // then force-close at the drain bound (a never-ending
                    // response body must not outlive shutdown).
                    conn.as_mut().graceful_shutdown();
                    if tokio::time::timeout(conn_drain, conn.as_mut()).await.is_err() {
                        debug!("public-http conn exceeded drain bound; dropping");
                    }
                }
            }
        });
    }

    // Shutdown: stop accepting, fan the graceful signal out, drain bounded.
    drop(listener);
    let _ = shutdown_tx.send(());
    drop(close_rx);
    if tokio::time::timeout(opts.drain_timeout, close_tx.closed())
        .await
        .is_err()
    {
        warn!(
            "public-http drain bound ({}s) reached with connections still open — proceeding to exit",
            opts.drain_timeout.as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_opts(cap: usize, per_ip: u64, header_secs_ms: u64, exempt_loopback: bool) -> PublicHttpOpts {
        PublicHttpOpts {
            conn_cap: cap,
            per_ip_cap: per_ip,
            header_read_timeout: Duration::from_millis(header_secs_ms),
            drain_timeout: Duration::from_millis(500),
            exempt_loopback,
            shed_total: Arc::new(AtomicU64::new(0)),
            per_ip_shed_total: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn spawn_server(
        app: Router,
        opts: PublicHttpOpts,
    ) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(serve_public_http(listener, app, opts, async move {
            let _ = rx.await;
        }));
        (addr, tx)
    }

    fn tiny_router() -> Router {
        use axum::routing::get;
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    /// The deploy-gating invariant: the header deadline actually FIRES — for
    /// a stalled partial header AND for a zero-byte connection (the pure-h1
    /// builder has no untimed sniff phase). Firing also proves the Timer is
    /// armed (a mis-wired builder panics per-connection instead).
    #[tokio::test]
    async fn header_read_timeout_fires_for_stalled_and_zero_byte_clients() {
        let (addr, _shutdown) = spawn_server(tiny_router(), test_opts(8, 8, 700, true)).await;

        for send_partial in [true, false] {
            let started = std::time::Instant::now();
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            if send_partial {
                // Request line + one header, never terminated.
                s.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n").await.unwrap();
            }
            // Server must close us at ~700ms; generous 8s guard for CI noise.
            let mut buf = [0u8; 512];
            let n = tokio::time::timeout(Duration::from_secs(8), async {
                // Drain until EOF (a 408 body may arrive first on the partial case).
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break 0usize,
                        Ok(_) => continue,
                    }
                }
            })
            .await
            .expect("header deadline never fired: connection stayed open past 8s");
            assert_eq!(n, 0);
            let elapsed = started.elapsed();
            assert!(
                elapsed >= Duration::from_millis(500),
                "closed suspiciously early ({elapsed:?}) — deadline should be ~700ms (partial={send_partial})"
            );
        }
    }

    /// Global cap: with cap=1 (exemption off), a second concurrent connection
    /// is dropped at accept and the shed counter increments.
    #[tokio::test]
    async fn global_conn_cap_sheds_and_counts() {
        let opts = test_opts(1, 8, 30_000, false);
        let shed = opts.shed_total.clone();
        let (addr, _shutdown) = spawn_server(tiny_router(), opts).await;

        let _held = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Give the accept loop time to admit the first conn.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("shed connection was not closed")
            .unwrap_or(0);
        assert_eq!(n, 0, "over-cap connection must be dropped, not served");
        assert_eq!(shed.load(Ordering::Relaxed), 1, "global shed counter must increment");
    }

    /// Per-IP cap: with per_ip=1 but global room, the same source's second
    /// connection sheds on the per-IP counter (not the global one).
    #[tokio::test]
    async fn per_ip_cap_sheds_on_the_per_ip_counter() {
        let opts = test_opts(8, 1, 30_000, false);
        let (global, per_ip) = (opts.shed_total.clone(), opts.per_ip_shed_total.clone());
        let (addr, _shutdown) = spawn_server(tiny_router(), opts).await;

        let _held = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
            .await
            .expect("per-IP shed connection was not closed")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(per_ip.load(Ordering::Relaxed), 1, "per-IP shed counter must increment");
        assert_eq!(global.load(Ordering::Relaxed), 0, "global counter must stay 0 (permit released on per-IP shed)");
    }

    /// Slot release: a shed source is admitted again once its first
    /// connection closes (RAII decrement — no leak that bricks an IP).
    #[tokio::test]
    async fn per_ip_slot_releases_on_disconnect() {
        let opts = test_opts(8, 1, 30_000, false);
        let (addr, _shutdown) = spawn_server(tiny_router(), opts).await;

        {
            let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            // Complete a real request so the conn task ends cleanly after close.
            first
                .write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = first.read_to_end(&mut buf).await;
            assert!(String::from_utf8_lossy(&buf).contains("200"), "first request must succeed");
        } // dropped → slot released

        // Poll until the slot frees (task Drop runs asynchronously).
        let mut admitted = false;
        for _ in 0..40 {
            let mut again = tokio::net::TcpStream::connect(addr).await.unwrap();
            again
                .write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), again.read_to_end(&mut buf)).await;
            if String::from_utf8_lossy(&buf).contains("200") {
                admitted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(admitted, "slot must be released after the first connection closed");
    }

    /// ConnectInfo fidelity through the manual loop: a handler extracting
    /// ConnectInfo sees the real peer address.
    #[tokio::test]
    async fn connect_info_reaches_handlers() {
        use axum::extract::ConnectInfo;
        use axum::routing::get;
        let app = Router::new().route(
            "/ip",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        );
        let (addr, _shutdown) = spawn_server(app, test_opts(8, 8, 30_000, true)).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /ip HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("200"), "expected 200, got: {resp}");
        assert!(resp.contains("127.0.0.1"), "handler must see the real peer IP, got: {resp}");
    }

    /// HTTP/1.1 Upgrade survives the manual loop (`with_upgrades` +
    /// axum WebSocketUpgrade — the /pq-ws path): handshake returns 101.
    #[tokio::test]
    async fn websocket_upgrade_gets_101_through_the_loop() {
        use axum::extract::ws::WebSocketUpgrade;
        use axum::routing::get;
        let app = Router::new().route(
            "/ws",
            get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(|_socket| async {}) }),
        );
        let (addr, _shutdown) = spawn_server(app, test_opts(8, 8, 30_000, true)).await;

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("no upgrade response")
            .unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "expected 101 Switching Protocols, got: {head}"
        );
    }

    /// The drain is BOUNDED: with a never-ending SSE response in flight,
    /// shutdown still returns within the drain budget instead of hanging
    /// (axum's own drain would wait forever).
    #[tokio::test]
    async fn shutdown_drain_is_bounded_with_infinite_stream_in_flight() {
        use axum::response::sse::{Event, Sse};
        use axum::routing::get;
        use futures_util::stream;
        let app = Router::new().route(
            "/sse",
            get(|| async {
                Sse::new(stream::pending::<Result<Event, std::convert::Infallible>>())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(serve_public_http(
            listener,
            app,
            test_opts(8, 8, 30_000, true),
            async move {
                let _ = rx.await;
            },
        ));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /sse HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        // Read the response head so the infinite body is genuinely in flight.
        let mut buf = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("no SSE response head")
            .unwrap();

        let started = std::time::Instant::now();
        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("serve future must return within the drain bound despite an infinite body")
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "drain took {:?} — bound not enforced",
            started.elapsed()
        );
    }
}
