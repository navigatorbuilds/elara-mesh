//! Async transport wrapper for the PQ handshake.
//!
//! Runs the [`PqHandshake`] state machine over a [`tokio::net::TcpStream`],
//! then exposes a frame-oriented encrypted channel for application payloads.
//!
//! # Scope (Stage 4B.1)
//!
//! This is the plumbing layer. It does NOT yet replace rustls in
//! `client.rs` / `server.rs` / `gossip.rs` — that's Stage 4B.2. Here we
//! only provide:
//!
//! - [`handshake_initiator`] / [`handshake_responder`]: drive the 3-message
//!   handshake to completion over real TCP.
//! - [`PqStream`]: post-handshake bidirectional encrypted channel with
//!   `send` / `recv` / `close`.
//!
//! # Data-frame nonce scheme
//!
//! The handshake consumes counter 0 in each direction. Post-handshake,
//! both peers' `k_send` counters sit at 1. Each `send` call increments
//! the sender's counter by one. The receiver tracks the expected counter
//! independently (TCP preserves order, so any mismatch is tampering or a
//! bug — either way, abort).
//!
//! # What is intentionally NOT here
//!
//! - AsyncRead / AsyncWrite implementations. Those require a poll-based
//!   state machine for partial reads/writes; gossip.rs and sync.rs send
//!   discrete JSON blobs, so frame-oriented `send` / `recv` is enough.
//!   Add AsyncRead/Write later if hyper needs it.
//! - Rekey. `FrameType::Rekey` is detected on recv and errored out;
//!   wiring the actual key rotation is a later stage once the key-schedule
//!   label scheme is extended with rotation epochs.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::network::config::NetworkRealm;
use crate::network::realm::{
    AdmissionMsg, RealmAdmissionError, RealmMembershipCert, ADMISSION_PROTOCOL_V,
};
use super::frame::{Frame, FrameError, FrameType, HEADER_LEN, MAX_PAYLOAD};
use super::handshake::{
    CompletedHandshake, HandshakeError, PeerExpectation, PqHandshake,
};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("unexpected frame type: {0:?}")]
    UnexpectedFrame(FrameType),
    #[error("peer closed connection")]
    PeerClosed,
    #[error("AEAD verification failed (transit corruption or tampering)")]
    AeadFailed,
    #[error("send counter exhausted — rekey required")]
    SendCounterExhausted,
    #[error("recv counter exhausted — rekey required")]
    RecvCounterExhausted,
    #[error("rekey not supported yet (Stage 4B.1)")]
    RekeyUnsupported,
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD})")]
    PayloadTooLarge(usize),
    #[error("system clock before unix epoch")]
    ClockBeforeEpoch,
    #[error("handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),
    /// REALMS P1 slice (c2): a sovereign listener dropped an inbound
    /// connection whose authenticated identity is not in the pin store.
    /// Per-connection and recoverable — the server accept loop continues.
    #[error("sovereign realm: inbound identity {0} is not pinned")]
    SovereignDenied(String),
    /// REALMS P1 slice (b): the realm admission gate rejected this
    /// connection. Carries the stable wire reason
    /// ([`crate::network::realm::RealmAdmissionError::wire_reason`]).
    #[error("realm admission rejected: {0}")]
    AdmissionRejected(String),
    /// REALMS P1 slice (b): the admission exchange itself was violated —
    /// malformed message, wrong sequencing, or missing local context.
    #[error("realm admission protocol violation: {0}")]
    AdmissionProtocol(String),
}

/// Default ceiling on how long a single handshake may take from TCP
/// accept / dial to `Done`. Without this, a peer that opens a connection
/// and stops talking holds an accept slot forever. 10 s is generous for
/// Dilithium3 signing + verification on slow hardware but tight enough
/// to shed slow-read attacks.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pre-allocation ceiling for any frame read BEFORE the data phase — i.e.
/// the handshake messages (Hello/Challenge/Auth) and the realm-admission
/// exchange. The largest legitimate such frame is msg2 (Challenge) at
/// 6397 bytes; 16 KiB leaves comfortable headroom. `read_frame` allocates
/// `HEADER_LEN + payload_len` BEFORE reading the body, so a pre-auth peer
/// must not be able to declare the full 16 MiB [`MAX_PAYLOAD`] on the
/// handshake path: at `pq_handshake_concurrency` (256) that is 4 GiB of
/// attacker-controlled heap from a few bytes per connection — an
/// unauthenticated OOM on phone-tier nodes. Bounding the handshake path to
/// this ceiling caps that to ~4 MiB node-wide. Only [`Self::recv_typed`]
/// (post-handshake Data/StreamChunk) reads against the full `MAX_PAYLOAD`.
const MAX_HANDSHAKE_FRAME: usize = 16 * 1024;

fn now_unix_secs() -> Result<u64, TransportError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TransportError::ClockBeforeEpoch)
}

/// REALMS P1 slice (b): how many application frames the responder will
/// buffer while waiting for the initiator's admission response. The
/// initiator legitimately races its first request ahead of seeing our
/// challenge (full-duplex TCP); more than a few frames before answering
/// means the peer is not speaking the admission protocol at all.
pub const ADMISSION_MAX_EARLY_FRAMES: usize = 4;

/// Initiator-side realm context: what we present when a responder
/// challenges us for admission. Built from `NodeConfig` by the dial path
/// (`network_id` + the member cert loaded at boot, if any).
#[derive(Debug, Clone)]
pub struct AdmissionContext {
    pub network_id: String,
    pub cert: Option<RealmMembershipCert>,
}

/// Responder-side admission gate, armed via [`PqListener::with_realm_gate`].
#[derive(Debug, Clone)]
pub struct RealmGate {
    pub network_id: String,
    pub realm: NetworkRealm,
}

impl RealmGate {
    /// Pure verdict over an admission response. Typed reasons map 1:1
    /// onto the wire verdict + (future) rejection metrics.
    fn check(
        &self,
        peer_network_id: &str,
        cert: &Option<RealmMembershipCert>,
        peer_identity_hash: [u8; 32],
        now_unix: u64,
    ) -> std::result::Result<(), RealmAdmissionError> {
        if peer_network_id != self.network_id {
            return Err(RealmAdmissionError::NetworkMismatch {
                peer: peer_network_id.to_string(),
                ours: self.network_id.clone(),
            });
        }
        if let Some(root_pk) = self.realm.federated_root_pk() {
            let cert = cert.as_ref().ok_or(RealmAdmissionError::CertMissing)?;
            cert.verify(root_pk, &hex::encode(peer_identity_hash), now_unix)?;
        }
        Ok(())
    }
}

fn admission_json(msg: &AdmissionMsg) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(msg)
        .map_err(|e| TransportError::AdmissionProtocol(format!("encode admission message: {e}")))
}

/// Responder side of the admission exchange. Runs inside the accept
/// timeout, immediately after the handshake, only when a realm gate is
/// armed. Early application frames are decrypted in counter order and
/// parked on the stream's pending queue so nothing is lost or reordered.
async fn run_responder_admission(
    stream: &mut PqStream,
    gate: &RealmGate,
) -> Result<(), TransportError> {
    let challenge = AdmissionMsg::Challenge {
        v: ADMISSION_PROTOCOL_V,
        network_id: gate.network_id.clone(),
        realm: gate.realm.label().to_string(),
        cert_required: gate.realm.federated_root_pk().is_some(),
    };
    stream
        .send_typed(FrameType::Admission, &admission_json(&challenge)?)
        .await?;

    let (peer_network_id, cert) = loop {
        let frame = read_frame(&mut stream.tcp, MAX_HANDSHAKE_FRAME).await?;
        match frame.frame_type {
            FrameType::Admission => {
                let pt = stream.decrypt_frame(frame.frame_type, &frame.payload)?;
                let msg: AdmissionMsg = serde_json::from_slice(&pt).map_err(|e| {
                    TransportError::AdmissionProtocol(format!("malformed admission message: {e}"))
                })?;
                match msg {
                    AdmissionMsg::Response { network_id, cert, .. } => break (network_id, cert),
                    other => {
                        return Err(TransportError::AdmissionProtocol(format!(
                            "expected admission response, got {other:?}"
                        )))
                    }
                }
            }
            // The initiator's first request racing ahead of our challenge
            // is legal — park it (bounded) and keep waiting.
            FrameType::Data | FrameType::StreamChunk => {
                if stream.pending.len() >= ADMISSION_MAX_EARLY_FRAMES {
                    return Err(TransportError::AdmissionProtocol(
                        "too many application frames before admission response".into(),
                    ));
                }
                let pt = stream.decrypt_frame(frame.frame_type, &frame.payload)?;
                stream.pending.push_back((frame.frame_type, pt));
            }
            FrameType::Close => return Err(TransportError::PeerClosed),
            other => return Err(TransportError::UnexpectedFrame(other)),
        }
    };

    match gate.check(&peer_network_id, &cert, stream.peer_identity_hash(), now_unix_secs()?) {
        Ok(()) => {
            let verdict = AdmissionMsg::Verdict {
                v: ADMISSION_PROTOCOL_V,
                admitted: true,
                reason: String::new(),
            };
            stream
                .send_typed(FrameType::Admission, &admission_json(&verdict)?)
                .await?;
            Ok(())
        }
        Err(e) => {
            let reason = e.wire_reason().to_string();
            let verdict = AdmissionMsg::Verdict {
                v: ADMISSION_PROTOCOL_V,
                admitted: false,
                reason: reason.clone(),
            };
            // Best-effort verdict + close so the peer gets a diagnosable
            // reason instead of an opaque drop; the connection is dead
            // either way.
            let _ = stream
                .send_typed(FrameType::Admission, &admission_json(&verdict)?)
                .await;
            let _ = write_frame(&mut stream.tcp, &Frame::new(FrameType::Close, Vec::new())?).await;
            Err(TransportError::AdmissionRejected(reason))
        }
    }
}

/// Read exactly one framed message off the wire.
///
/// Reads the 9-byte header first (to learn payload length), then reads
/// the full payload, then parses. A length field that exceeds `max_payload`
/// is rejected BEFORE allocating. Callers pass [`MAX_HANDSHAKE_FRAME`] on the
/// pre-data (handshake/admission) path and [`MAX_PAYLOAD`] only for
/// post-handshake Data/StreamChunk reads — so a pre-auth peer cannot declare
/// a 16 MiB length and force the node to commit that heap per connection.
async fn read_frame(tcp: &mut TcpStream, max_payload: usize) -> Result<Frame, TransportError> {
    let mut header = [0u8; HEADER_LEN];
    tcp.read_exact(&mut header).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::PeerClosed
        } else {
            TransportError::Io(e)
        }
    })?;

    // Sanity-check magic/version/type/length from the header before allocating.
    // Frame::decode will re-validate; this is the pre-alloc gate.
    let payload_len =
        ((header[6] as u32) << 16) | ((header[7] as u32) << 8) | (header[8] as u32);
    let payload_len = payload_len as usize;
    if payload_len > max_payload {
        return Err(TransportError::PayloadTooLarge(payload_len));
    }

    let mut buf = vec![0u8; HEADER_LEN + payload_len];
    buf[..HEADER_LEN].copy_from_slice(&header);
    if payload_len > 0 {
        tcp.read_exact(&mut buf[HEADER_LEN..]).await?;
    }
    let (frame, used) = Frame::decode(&buf)?;
    debug_assert_eq!(used, buf.len(), "frame decode should consume exactly what was read");
    Ok(frame)
}

async fn write_frame(tcp: &mut TcpStream, frame: &Frame) -> Result<(), TransportError> {
    let bytes = frame.encode();
    tcp.write_all(&bytes).await?;
    Ok(())
}

/// Drive the initiator side of the handshake over `tcp`.
///
/// On success, returns a live [`PqStream`] ready for `send` / `recv`.
/// On any error, the TCP stream is dropped without further I/O — the
/// caller is responsible for not reusing it.
pub async fn handshake_initiator(
    mut tcp: TcpStream,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    peer_expectation: PeerExpectation,
) -> Result<PqStream, TransportError> {
    let now = now_unix_secs()?;
    let (mut hs, msg1) =
        PqHandshake::new_initiator(my_dil_pk, my_dil_sk, peer_expectation, now)?;
    write_frame(&mut tcp, &Frame::new(FrameType::Hello, msg1)?).await?;

    let msg2_frame = read_frame(&mut tcp, MAX_HANDSHAKE_FRAME).await?;
    if msg2_frame.frame_type != FrameType::Challenge {
        return Err(TransportError::UnexpectedFrame(msg2_frame.frame_type));
    }
    let msg3 = hs.initiator_process_msg2(&msg2_frame.payload)?;
    write_frame(&mut tcp, &Frame::new(FrameType::Auth, msg3)?).await?;

    let completed = hs.into_completed()?;
    Ok(PqStream::new(tcp, completed))
}

/// Drive the responder side of the handshake over `tcp`.
pub async fn handshake_responder(
    mut tcp: TcpStream,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
) -> Result<PqStream, TransportError> {
    let now = now_unix_secs()?;
    let mut hs = PqHandshake::new_responder(my_dil_pk, my_dil_sk, now)?;

    let msg1_frame = read_frame(&mut tcp, MAX_HANDSHAKE_FRAME).await?;
    if msg1_frame.frame_type != FrameType::Hello {
        return Err(TransportError::UnexpectedFrame(msg1_frame.frame_type));
    }
    let msg2 = hs.responder_process_msg1(&msg1_frame.payload)?;
    write_frame(&mut tcp, &Frame::new(FrameType::Challenge, msg2)?).await?;

    let msg3_frame = read_frame(&mut tcp, MAX_HANDSHAKE_FRAME).await?;
    if msg3_frame.frame_type != FrameType::Auth {
        return Err(TransportError::UnexpectedFrame(msg3_frame.frame_type));
    }
    hs.responder_process_msg3(&msg3_frame.payload)?;

    let completed = hs.into_completed()?;
    Ok(PqStream::new(tcp, completed))
}

/// Accepting side of the PQ transport: wraps a `TcpListener` and runs
/// the responder handshake (with timeout) on every accepted connection.
///
/// Single-identity: a node binds one listener, and every inbound peer
/// handshakes against the same long-term Dilithium3 identity. Per-peer
/// identity would mean per-peer certificates, which we explicitly don't do.
///
/// Handshake failures (malformed messages, timeouts, signature-invalid)
/// are returned as errors from [`accept`](Self::accept). The caller's
/// accept loop typically logs and continues — a failed handshake on one
/// connection never affects others.
pub struct PqListener {
    inner: TcpListener,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    handshake_timeout: Duration,
    /// REALMS P1 slice (b): when armed, every accepted connection must
    /// pass the admission exchange after the handshake. `None` (default)
    /// = Open behavior, bit-identical to pre-realm builds.
    realm_gate: Option<RealmGate>,
    /// REALMS P1 slice (c2): sovereign inbound deny-unknown. When armed,
    /// any inbound handshake whose authenticated initiator identity is not
    /// in the pin store is dropped post-handshake (the handshake itself is
    /// what authenticates — no extra round trip, no admission frames).
    sovereign_pins: Option<std::sync::Arc<super::peer_store::PeerIdentityStore>>,
}

/// B8: the per-connection inputs a responder handshake needs, cloned out of a
/// [`PqListener`] so the handshake can run in a detached task without borrowing
/// the listener (which must stay in the serial TCP-accept loop). Returned by
/// [`PqListener::handshake_params`] and consumed by
/// [`PqListener::finish_handshake_accepted`]. Taken BY VALUE there so the
/// owned Dilithium keys move straight into [`handshake_responder`] with no
/// extra clone. Fields are private; construct it only via `handshake_params`.
pub struct HandshakeParams {
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    realm_gate: Option<RealmGate>,
    sovereign_pins: Option<std::sync::Arc<super::peer_store::PeerIdentityStore>>,
    handshake_timeout: Duration,
}

impl PqListener {
    /// Bind a TCP listener at `addr` and prepare to accept PQ handshakes
    /// under the given long-term identity.
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Self {
            inner,
            my_dil_pk,
            my_dil_sk,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            realm_gate: None,
            sovereign_pins: None,
        })
    }

    /// Wrap an already-bound `TcpListener`. Used by the simulator harness,
    /// which reserves 50+ ports atomically (HTTP and PQ paired) up front to
    /// avoid TIME_WAIT collisions on back-to-back ephemeral binds. Production
    /// callers prefer [`bind`] which derives the address from config.
    pub fn from_tcp_listener(
        inner: TcpListener,
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            my_dil_pk,
            my_dil_sk,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            realm_gate: None,
            sovereign_pins: None,
        }
    }

    /// Override the default handshake timeout. Useful for tests; callers
    /// should rarely change it in production.
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// REALMS P1 slice (b): arm the realm admission gate. Only `Federated`
    /// realms run the post-handshake admission exchange in this slice —
    /// `Open` is the public mesh (no gate, today's behavior) and
    /// `Sovereign`'s inbound deny-unknown lands with the slice-(c)
    /// discovery-off wiring. Passing a non-federated realm is a no-op, so
    /// callers can thread `config.network_realm` through unconditionally.
    pub fn with_realm_gate(mut self, network_id: String, realm: NetworkRealm) -> Self {
        self.realm_gate = match &realm {
            NetworkRealm::Federated { .. } => Some(RealmGate { network_id, realm }),
            NetworkRealm::Open | NetworkRealm::Sovereign => None,
        };
        self
    }

    /// REALMS P1 slice (c2): arm the sovereign inbound deny-unknown gate.
    /// Open/Federated listeners never arm this; callers gate on
    /// `NetworkRealm::Sovereign`. Denied accepts surface as
    /// [`TransportError::SovereignDenied`], which the server accept loop
    /// treats as per-connection (recoverable) like every other
    /// hostile-peer error.
    pub fn with_sovereign_pins(
        mut self,
        pins: std::sync::Arc<super::peer_store::PeerIdentityStore>,
    ) -> Self {
        self.sovereign_pins = Some(pins);
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// B8: accept ONE raw TCP connection (serial, cheap) and set TCP_NODELAY.
    /// Runs NO handshake — the caller drives [`finish_handshake_accepted`],
    /// typically inside a spawned task, so a slow/half-open peer can never
    /// stall this loop. Errors here are LISTENER-level (fd exhaustion,
    /// `ECONNABORTED`), not per-connection handshake failures.
    pub async fn accept_tcp(&self) -> Result<(TcpStream, SocketAddr), TransportError> {
        let (tcp, addr) = self.inner.accept().await?;
        // TCP_NODELAY: gossip/sync traffic is request/response with small
        // frames — Nagle's batching adds ~40ms per round without this.
        // The encrypted-frame layer already controls how much we write per
        // call, so we want writes to hit the wire immediately.
        tcp.set_nodelay(true)?;
        Ok((tcp, addr))
    }

    /// B8: snapshot the per-connection handshake inputs so a spawned task can
    /// run the responder handshake without borrowing `&self` (the listener
    /// stays in the accept loop). These are the exact clones the old inline
    /// `accept()` body made per connection — no new allocation vs. status quo.
    pub fn handshake_params(&self) -> HandshakeParams {
        HandshakeParams {
            my_dil_pk: self.my_dil_pk.clone(),
            my_dil_sk: self.my_dil_sk.clone(),
            realm_gate: self.realm_gate.clone(),
            sovereign_pins: self.sovereign_pins.clone(),
            handshake_timeout: self.handshake_timeout,
        }
    }

    /// B8: run the responder handshake, then the sovereign deny-unknown check,
    /// then — when a realm gate is armed — the admission exchange, all under
    /// one `handshake_timeout`. This is the exact body that used to be inlined
    /// in [`accept`](Self::accept); lifted to a free-standing assoc fn over an
    /// already-accepted TCP + owned [`HandshakeParams`] so it can run detached.
    ///
    /// On timeout the TCP socket is dropped. Any IdentityPin/SignatureInvalid/
    /// AEAD/admission failure surfaces as a `TransportError`; the caller
    /// decides whether to blocklist the peer.
    /// [`TransportError::AdmissionRejected`] carries the stable reason.
    pub async fn finish_handshake_accepted(
        tcp: TcpStream,
        p: HandshakeParams,
    ) -> Result<PqStream, TransportError> {
        // `handshake_timeout` is read in the outer map_err, so copy it out
        // before `p` is moved into the async block below.
        let handshake_timeout = p.handshake_timeout;
        let stream = tokio::time::timeout(handshake_timeout, async move {
            // Owned keys move straight into handshake_responder — no clone.
            let mut stream = handshake_responder(tcp, p.my_dil_pk, p.my_dil_sk).await?;
            // REALMS P1 slice (c2): sovereign deny-unknown — the handshake
            // has authenticated the initiator; unknown identities go no
            // further. Checked before any admission exchange.
            if let Some(pins) = &p.sovereign_pins {
                let peer = stream.peer_identity_hash();
                if !pins.contains_identity(&peer) {
                    let peer_hex = hex::encode(peer);
                    tracing::warn!(
                        peer = %&peer_hex[..16.min(peer_hex.len())],
                        "sovereign realm: denied unpinned inbound identity",
                    );
                    return Err(TransportError::SovereignDenied(peer_hex));
                }
            }
            if let Some(gate) = &p.realm_gate {
                run_responder_admission(&mut stream, gate).await?;
            }
            Ok::<PqStream, TransportError>(stream)
        })
        .await
        .map_err(|_| TransportError::HandshakeTimeout(handshake_timeout))??;
        Ok(stream)
    }

    /// Accept one connection and complete its handshake + admission, serially.
    ///
    /// Backward-compatible composition of [`accept_tcp`](Self::accept_tcp) +
    /// [`finish_handshake_accepted`](Self::finish_handshake_accepted) — the
    /// contract (returns a fully-handshook [`PqStream`]) is byte-identical to
    /// pre-B8, so SDK/client/test callers are unaffected. The production server
    /// (`PqServer::run`) does NOT use this; it drives the two halves directly
    /// so the handshake runs in a detached, semaphore-bounded task.
    pub async fn accept(&self) -> Result<(PqStream, SocketAddr), TransportError> {
        let (tcp, addr) = self.accept_tcp().await?;
        let stream = Self::finish_handshake_accepted(tcp, self.handshake_params()).await?;
        Ok((stream, addr))
    }
}

/// Dial `addr`, run the initiator handshake, return a live [`PqStream`].
///
/// The composed (TCP connect + handshake) operation is bounded by
/// [`DEFAULT_HANDSHAKE_TIMEOUT`]. The TCP connect stage alone respects
/// the OS-level connect timeout; the handshake stage respects the
/// explicit tokio timer.
pub async fn pq_dial<A: ToSocketAddrs>(
    addr: A,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    peer_expectation: PeerExpectation,
) -> Result<PqStream, TransportError> {
    pq_dial_with_admission(addr, my_dil_pk, my_dil_sk, peer_expectation, None).await
}

/// [`pq_dial`] plus an initiator-side realm admission context. When the
/// responder challenges (its realm is not `Open`), the stream answers
/// transparently inside `recv` using `admission`; with `None`, a
/// challenge surfaces as [`TransportError::AdmissionProtocol`] — a node
/// with no realm context cannot join a gated realm.
pub async fn pq_dial_with_admission<A: ToSocketAddrs>(
    addr: A,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    peer_expectation: PeerExpectation,
    admission: Option<AdmissionContext>,
) -> Result<PqStream, TransportError> {
    let tcp = TcpStream::connect(addr).await?;
    // See PqListener::accept for rationale — Nagle+delayed-ACK turns a
    // req/resp workload into a 40ms-per-round-trip disaster without this.
    tcp.set_nodelay(true)?;
    let mut stream = tokio::time::timeout(
        DEFAULT_HANDSHAKE_TIMEOUT,
        handshake_initiator(tcp, my_dil_pk, my_dil_sk, peer_expectation),
    )
    .await
    .map_err(|_| TransportError::HandshakeTimeout(DEFAULT_HANDSHAKE_TIMEOUT))??;
    stream.admission = admission;
    Ok(stream)
}

/// A post-handshake encrypted channel over TCP.
///
/// Frame-oriented: each [`send`](Self::send) maps to one [`FrameType::Data`]
/// frame; each [`recv`](Self::recv) returns one frame's decrypted payload.
pub struct PqStream {
    tcp: TcpStream,
    completed: CompletedHandshake,
    /// Next expected receive counter. Starts at 1 (handshake used 0).
    /// The AeadKey does NOT auto-track this on the recv side — we must.
    next_recv_counter: u64,
    /// REALMS P1 slice (b): initiator-side admission context. `None` on
    /// responder-side streams and on initiators with no realm config —
    /// an inbound admission challenge then fails the connection.
    admission: Option<AdmissionContext>,
    /// Decrypted application frames parked during the responder-side
    /// admission exchange (the initiator may race requests ahead of its
    /// admission response). Drained FIFO by `recv_typed` before any new
    /// wire reads — counter order is preserved end to end.
    pending: VecDeque<(FrameType, Vec<u8>)>,
}

// Manual Debug: never leak session-key bytes. Only peer identity + counter.
impl std::fmt::Debug for PqStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqStream")
            .field("peer_identity_hash", &hex::encode(self.completed.peer_identity_hash))
            .field("next_recv_counter", &self.next_recv_counter)
            .finish()
    }
}

impl PqStream {
    fn new(tcp: TcpStream, completed: CompletedHandshake) -> Self {
        Self {
            tcp,
            completed,
            next_recv_counter: 1,
            admission: None,
            pending: VecDeque::new(),
        }
    }

    /// REALMS P1 slice (b): attach the initiator-side admission context
    /// post-construction. Prefer [`pq_dial_with_admission`]; this exists
    /// for callers that build streams from raw handshakes (tests, sim).
    pub fn with_admission_context(mut self, ctx: AdmissionContext) -> Self {
        self.admission = Some(ctx);
        self
    }

    /// Decrypt one AEAD frame payload under the recv counter and advance
    /// it. Single choke point — every inbound encrypted frame (Data,
    /// StreamChunk, Admission) MUST come through here so the counter
    /// sequence matches the sender's exactly.
    ///
    /// `frame_type` is the type byte read from the (cleartext) wire header
    /// and is bound into the AEAD associated data, so it must equal the
    /// type the sender encrypted under. The header type sits OUTSIDE the
    /// ciphertext and is therefore malleable in transit; binding it here
    /// means a flipped type byte (e.g. Data→Admission to misroute an
    /// authenticated payload into `handle_inbound_admission`) fails the
    /// Poly1305 tag and aborts, instead of decrypting and dispatching down
    /// the wrong branch. Machine-checked in `spec/proverif/` (record model).
    fn decrypt_frame(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let pt = self
            .completed
            .session
            .k_recv
            .decrypt(self.next_recv_counter, &[frame_type as u8], payload)
            .map_err(|_| TransportError::AeadFailed)?;
        self.next_recv_counter = self
            .next_recv_counter
            .checked_add(1)
            .ok_or(TransportError::RecvCounterExhausted)?;
        Ok(pt)
    }

    /// Test-only: emit one Data frame whose Poly1305 tag is corrupted, so the
    /// peer's next `recv`/`recv_request` fails with
    /// [`TransportError::AeadFailed`] — the post-handshake silent-wire-break
    /// path. Encapsulates the tamper technique used by
    /// `data_frame_tamper_is_detected` so a cross-module test (e.g.
    /// `pq_server`'s serve-decrypt counter) can drive a REAL AEAD failure
    /// without reaching into private session state. The frame is encrypted
    /// under the live `k_send` (advancing the counter exactly as a real send
    /// would) and is well-formed on the wire; only the AEAD tag is flipped, so
    /// it fails verification at the receiver's decrypt choke point.
    #[cfg(test)]
    pub(crate) async fn send_tampered_data_frame(
        &mut self,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        let ct = self
            .completed
            .session
            .k_send
            .encrypt(&[FrameType::Data as u8], plaintext)
            .expect("k_send encrypt must not fail in tests");
        let mut frame_bytes = Frame::new(FrameType::Data, ct)
            .expect("frame encode must not fail in tests")
            .encode();
        let last = frame_bytes.len() - 1;
        frame_bytes[last] ^= 0x01; // Flip one bit in the Poly1305 tag.
        self.tcp.write_all(&frame_bytes).await
    }

    /// Initiator-side reaction to an inbound admission message. Challenges
    /// are answered from `self.admission`; verdicts either pass (admitted)
    /// or fail the connection with the responder's stable reason.
    async fn handle_inbound_admission(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        let msg: AdmissionMsg = serde_json::from_slice(plaintext).map_err(|e| {
            TransportError::AdmissionProtocol(format!("malformed admission message: {e}"))
        })?;
        match msg {
            AdmissionMsg::Challenge { network_id, .. } => {
                let ctx = self.admission.as_ref().ok_or_else(|| {
                    TransportError::AdmissionProtocol(
                        "peer requires realm admission but no admission context is configured"
                            .into(),
                    )
                })?;
                // Never present our cert to a different network — fail
                // locally with the same stable reason the responder would
                // use, before any membership material leaves this node.
                if network_id != ctx.network_id {
                    return Err(TransportError::AdmissionRejected(format!(
                        "network_mismatch: peer '{network_id}', ours '{}'",
                        ctx.network_id
                    )));
                }
                let response = AdmissionMsg::Response {
                    v: ADMISSION_PROTOCOL_V,
                    network_id: ctx.network_id.clone(),
                    cert: ctx.cert.clone(),
                };
                let bytes = admission_json(&response)?;
                self.send_typed(FrameType::Admission, &bytes).await
            }
            AdmissionMsg::Verdict { admitted, reason, .. } => {
                if admitted {
                    Ok(())
                } else {
                    Err(TransportError::AdmissionRejected(if reason.is_empty() {
                        "unspecified".into()
                    } else {
                        reason
                    }))
                }
            }
            AdmissionMsg::Response { .. } => Err(TransportError::AdmissionProtocol(
                "unexpected admission response on initiator side".into(),
            )),
        }
    }

    /// SHA3-256 of the peer's Dilithium3 public key. Stable cross-session
    /// identity for TOFU / pin storage.
    pub fn peer_identity_hash(&self) -> [u8; 32] {
        self.completed.peer_identity_hash
    }

    /// Peer's Dilithium3 public key bytes.
    pub fn peer_dilithium_pk(&self) -> &[u8] {
        &self.completed.peer_dilithium_pk
    }

    /// Send one application payload as a single [`FrameType::Data`] frame.
    ///
    /// Encrypts with `k_send` under the current send counter. Counter
    /// auto-advances inside the AeadKey.
    ///
    /// `data` must fit within one frame's payload limit minus the AEAD
    /// tag. With [`MAX_PAYLOAD`] = 16 MiB - 1, the app-visible ceiling
    /// is 16 MiB - 1 - 16 (Poly1305 tag). Callers that want to send
    /// more must chunk.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.send_typed(FrameType::Data, data).await
    }

    /// Send an encrypted payload under an arbitrary post-handshake frame
    /// type. Used by streaming responses (`FrameType::StreamChunk`, 4E.3)
    /// and by `send()` for the default `Data` case. AEAD key + counter are
    /// shared with `send()` — interleaving Data and StreamChunk frames on
    /// the same stream is safe: the AEAD nonce is per-send, not per-type.
    ///
    /// Rejects handshake frame types (Hello / Challenge / Auth) and the
    /// framing-level Close / Rekey types: those belong to the transport
    /// machine, not the application.
    pub async fn send_typed(
        &mut self,
        frame_type: FrameType,
        data: &[u8],
    ) -> Result<(), TransportError> {
        match frame_type {
            FrameType::Data | FrameType::StreamChunk | FrameType::Admission => {}
            other => return Err(TransportError::UnexpectedFrame(other)),
        }
        const TAG_LEN: usize = 16;
        if data.len() + TAG_LEN > MAX_PAYLOAD {
            return Err(TransportError::PayloadTooLarge(data.len()));
        }
        // AD = the 1-byte frame type. The counter-nonce already binds
        // record uniqueness/order; binding the type closes the one
        // remaining malleable field — the type byte lives in the cleartext
        // header, outside the ciphertext, so without this an on-path
        // attacker could relabel an authenticated Data frame as Admission
        // (or StreamChunk) and have the receiver dispatch a genuine payload
        // down the wrong branch. The receiver re-binds the type it observes
        // on the wire, so any flip flips the Poly1305 tag → AeadFailed.
        let ct = self
            .completed
            .session
            .k_send
            .encrypt(&[frame_type as u8], data)
            .map_err(|_| TransportError::SendCounterExhausted)?;
        let frame = Frame::new(frame_type, ct)?;
        write_frame(&mut self.tcp, &frame).await?;
        Ok(())
    }

    /// Receive the next application payload.
    ///
    /// Silently ignores no frame types — anything other than [`FrameType::Data`]
    /// on the wire post-handshake is either a protocol violation, an
    /// unsupported-in-this-stage Rekey, or a peer-initiated Close.
    pub async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let (ft, pt) = self.recv_typed().await?;
        match ft {
            FrameType::Data => Ok(pt),
            // recv() is the strict Data-only path. A peer that sends
            // a StreamChunk where the caller expected a singleton Data
            // response is as wrong as sending handshake frames post-init.
            other => Err(TransportError::UnexpectedFrame(other)),
        }
    }

    /// Receive one application frame and return it alongside its frame
    /// type. Used by streaming consumers (`FrameType::StreamChunk`) and
    /// by `recv()` internally. Close and Rekey still surface as errors.
    ///
    /// REALMS P1 slice (b): admission frames are handled transparently —
    /// a responder's challenge is answered from the stream's admission
    /// context and the loop continues to the next application frame; a
    /// rejecting verdict surfaces as [`TransportError::AdmissionRejected`].
    /// Frames parked during a responder-side admission exchange are
    /// drained first, preserving arrival order.
    pub async fn recv_typed(&mut self) -> Result<(FrameType, Vec<u8>), TransportError> {
        if let Some(parked) = self.pending.pop_front() {
            return Ok(parked);
        }
        // A peer that streams `Admission` frames without ever sending the
        // application frame the caller awaits would otherwise spin this loop
        // forever, wedging the recv task (and its TCP socket) at zero cost to
        // the attacker. A legitimate mid-stream admission exchange is a single
        // challenge or verdict; cap well above that and fail closed.
        const MAX_ADMISSION_FRAMES_PER_RECV: u32 = 4;
        let mut admission_frames: u32 = 0;
        loop {
            let frame = read_frame(&mut self.tcp, MAX_PAYLOAD).await?;
            match frame.frame_type {
                FrameType::Data | FrameType::StreamChunk => {
                    let pt = self.decrypt_frame(frame.frame_type, &frame.payload)?;
                    return Ok((frame.frame_type, pt));
                }
                FrameType::Admission => {
                    admission_frames += 1;
                    if admission_frames > MAX_ADMISSION_FRAMES_PER_RECV {
                        return Err(TransportError::AdmissionProtocol(format!(
                            "peer sent >{MAX_ADMISSION_FRAMES_PER_RECV} admission frames \
                             without an application frame"
                        )));
                    }
                    let pt = self.decrypt_frame(frame.frame_type, &frame.payload)?;
                    self.handle_inbound_admission(&pt).await?;
                    // Challenge answered or admitted verdict absorbed —
                    // keep reading for the caller's application frame.
                }
                FrameType::Close => return Err(TransportError::PeerClosed),
                FrameType::Rekey => return Err(TransportError::RekeyUnsupported),
                // Hello / Challenge / Auth are all handshake frames — seeing
                // any of them post-handshake means the peer is confused or
                // malicious. Drop.
                other => return Err(TransportError::UnexpectedFrame(other)),
            }
        }
    }

    /// Send a Close frame and shut the write half of the TCP socket.
    /// The caller drops the stream afterwards; any further I/O is UB.
    pub async fn close(mut self) -> Result<(), TransportError> {
        let frame = Frame::new(FrameType::Close, Vec::new())?;
        write_frame(&mut self.tcp, &frame).await?;
        self.tcp.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::WIRE_VERSION;
    use crate::crypto::hash::sha3_256;
    use crate::crypto::pqc::dilithium3_keygen;
    use tokio::net::TcpListener;

    struct TestPeer {
        pk: Vec<u8>,
        sk: Vec<u8>,
        identity_hash: [u8; 32],
    }

    fn gen_peer() -> TestPeer {
        let kp = dilithium3_keygen().unwrap();
        let (pk, sk) = kp.into_parts();
        let identity_hash = sha3_256(&pk);
        TestPeer { pk, sk, identity_hash }
    }

    /// Stand up a tokio TCP listener on an OS-picked port and return
    /// (listener, bind_addr). Used by all async tests below.
    async fn bind_local() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn end_to_end_handshake_and_data_roundtrip() {
        let init = gen_peer();
        let resp = gen_peer();
        let resp_pin = resp.identity_hash;

        let (listener, addr) = bind_local().await;

        // Responder task: accept one connection, handshake, echo 3 messages, close.
        let resp_pk = resp.pk.clone();
        let resp_sk = resp.sk.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = handshake_responder(tcp, resp_pk, resp_sk).await.unwrap();
            for _ in 0..3 {
                let msg = stream.recv().await.unwrap();
                stream.send(&msg).await.unwrap(); // Echo.
            }
            stream.close().await.unwrap();
        });

        // Initiator.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut client = handshake_initiator(
            tcp,
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp_pin),
        )
        .await
        .unwrap();

        // Identity reported matches the pin we supplied.
        assert_eq!(client.peer_identity_hash(), resp_pin);
        assert_eq!(client.peer_dilithium_pk().len(), 1952);

        for payload in [&b"hello"[..], &b"post-quantum over TCP"[..], &b""[..]] {
            client.send(payload).await.unwrap();
            let echoed = client.recv().await.unwrap();
            assert_eq!(echoed, payload);
        }

        // Server should have closed; next recv returns PeerClosed.
        match client.recv().await {
            Err(TransportError::PeerClosed) => {}
            other => panic!("expected PeerClosed, got {other:?}"),
        }

        server.await.unwrap();
    }

    // Pre-auth memory-amplification guard. A stranger sends only a 9-byte
    // header declaring a huge payload on the handshake read path; `read_frame`
    // must reject it via MAX_HANDSHAKE_FRAME BEFORE allocating the buffer and
    // WITHOUT blocking on a body that never arrives — otherwise a few bytes
    // per connection commit up to 16 MiB of attacker heap (× the handshake
    // concurrency = node OOM on phone-tier hardware).
    #[tokio::test]
    async fn handshake_read_bounds_payload_to_handshake_ceiling() {
        let (listener, addr) = bind_local().await;
        let server = tokio::spawn(async move {
            let (mut a, _) = listener.accept().await.unwrap();
            let r1 = read_frame(&mut a, MAX_HANDSHAKE_FRAME).await;
            let (mut b, _) = listener.accept().await.unwrap();
            let r2 = read_frame(&mut b, MAX_HANDSHAKE_FRAME).await;
            (r1, r2)
        });

        // Probe 1: declare the full 16 MiB data-path ceiling on a handshake
        // read. The tighter handshake cap must still reject it.
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        c1.write_all(&[b'E', b'L', b'P', b'Q', WIRE_VERSION, FrameType::Hello as u8, 0xFF, 0xFF, 0xFF])
            .await
            .unwrap();

        // Probe 2: declare exactly one byte over the handshake cap.
        let over = (MAX_HANDSHAKE_FRAME + 1) as u32;
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        c2.write_all(&[
            b'E', b'L', b'P', b'Q', WIRE_VERSION, FrameType::Hello as u8,
            (over >> 16) as u8, (over >> 8) as u8, over as u8,
        ])
        .await
        .unwrap();

        let (r1, r2) = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("read_frame must reject oversized handshake frames without blocking on an unsent body")
            .unwrap();
        assert!(
            matches!(r1, Err(TransportError::PayloadTooLarge(n)) if n == MAX_PAYLOAD),
            "16 MiB payload on the handshake path must be rejected, got {r1:?}"
        );
        assert!(
            matches!(r2, Err(TransportError::PayloadTooLarge(n)) if n == MAX_HANDSHAKE_FRAME + 1),
            "one-byte-over-cap handshake frame must be rejected, got {r2:?}"
        );
    }

    #[tokio::test]
    async fn tofu_handshake_accepts_unknown_responder() {
        let init = gen_peer();
        let resp = gen_peer();
        let expected_hash = resp.identity_hash;

        let (listener, addr) = bind_local().await;

        let resp_pk = resp.pk.clone();
        let resp_sk = resp.sk.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _stream = handshake_responder(tcp, resp_pk, resp_sk).await.unwrap();
            // Keep the connection alive long enough for the client to finish.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let client = handshake_initiator(
            tcp,
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // TOFU captures the identity — now the caller can pin for later.
        assert_eq!(client.peer_identity_hash(), expected_hash);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_mismatch_aborts_initiator() {
        let init = gen_peer();
        let actual_resp = gen_peer();
        let imposter = gen_peer();

        let (listener, addr) = bind_local().await;
        let resp_pk = actual_resp.pk.clone();
        let resp_sk = actual_resp.sk.clone();
        let _server = tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                // The responder will complete its side; the initiator aborts
                // on identity mismatch after decrypting msg2.
                let _ = handshake_responder(tcp, resp_pk, resp_sk).await;
            }
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let err = handshake_initiator(
            tcp,
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(imposter.identity_hash),
        )
        .await
        .unwrap_err();

        match err {
            TransportError::Handshake(HandshakeError::IdentityPinMismatch) => {}
            other => panic!("expected IdentityPinMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn garbage_on_wire_gets_dropped() {
        // Peer sends raw bytes that are neither ELPQ-framed nor a TLS
        // probe — we must not try to parse them, just drop.
        let resp = gen_peer();
        let (listener, addr) = bind_local().await;

        let resp_pk = resp.pk.clone();
        let resp_sk = resp.sk.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // Responder tries to handshake; expects ELPQ Hello, gets garbage.
            handshake_responder(tcp, resp_pk, resp_sk).await
        });

        // Garbage starting with TLS ClientHello bytes.
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&[0x16, 0x03, 0x03, 0x00, 0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
            .await
            .unwrap();
        drop(tcp);

        let result = server.await.unwrap();
        // Must fail. The garbage's bytes 6..9 read as a 0xADBEEF (~11 MiB)
        // length field, which now exceeds the handshake-path MAX_HANDSHAKE_FRAME
        // cap and is rejected at the pre-alloc gate (PayloadTooLarge) before any
        // body read — cheaper than the prior BadMagic-after-read drop. Garbage
        // with a small length field still falls through to BadMagic. Either
        // way it is dropped, never parsed or trusted.
        match result {
            Err(TransportError::PayloadTooLarge(_)) => {}
            Err(TransportError::Frame(FrameError::BadMagic)) => {}
            Err(TransportError::PeerClosed) => {}
            Err(TransportError::Io(_)) => {}
            other => panic!("expected frame rejection, got {other:?}"),
        }
    }

    /// Raw stream echo perf, no RPC envelope.
    ///
    /// Single-stream QPS on localhost is scheduler-bound (one context
    /// switch per await on each side), NOT crypto-bound. On a real
    /// network (multi-ms RTT) the wire latency swamps scheduler
    /// overhead, so this number is a lower bound on real-world usage.
    /// What matters at protocol scale is aggregate across many streams,
    /// not per-stream ceiling — see `perf_concurrent_streams_scale`.
    ///
    /// `#[ignore]` — diagnostic, not a correctness check. Run via
    /// `cargo test --features node --lib perf_raw -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn perf_raw_stream_echo() {
        use std::time::Instant;

        let server_id = gen_peer();
        let client_id = gen_peer();
        let server_pin = server_id.identity_hash;

        let listener = PqListener::bind("127.0.0.1:0", server_id.pk, server_id.sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        const ROUNDS: usize = 2_000;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..ROUNDS {
                let msg = match stream.recv().await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                stream.send(&msg).await.unwrap();
            }
        });

        let mut client = pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            PeerExpectation::Pinned(server_pin),
        )
        .await
        .unwrap();

        let payload = vec![0x42u8; 2048];
        let t0 = Instant::now();
        for _ in 0..ROUNDS {
            client.send(&payload).await.unwrap();
            let echo = client.recv().await.unwrap();
            assert_eq!(echo.len(), 2048);
        }
        let secs = t0.elapsed().as_secs_f64();
        let qps = ROUNDS as f64 / secs;
        println!(
            "RAW stream perf (single): 2KiB round-trip = {qps:.0} QPS ({ROUNDS} in {secs:.2}s)"
        );

        drop(client);
        let _ = server.await;
    }

    /// Aggregate throughput with N concurrent streams. Proves that
    /// single-stream QPS is a scheduler artefact, not a crypto/CPU
    /// limit — adding more streams should scale throughput until the
    /// CPU actually saturates.
    ///
    /// `#[ignore]` — diagnostic, not a correctness check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn perf_concurrent_streams_scale() {
        use std::time::Instant;

        let server_id = gen_peer();
        let server_pin = server_id.identity_hash;

        let listener = PqListener::bind("127.0.0.1:0", server_id.pk, server_id.sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        const STREAMS: usize = 8;
        const ROUNDS_PER_STREAM: usize = 500;
        const TOTAL_ROUNDS: usize = STREAMS * ROUNDS_PER_STREAM;

        // Server: accept STREAMS connections, echo on each.
        let server = tokio::spawn(async move {
            for _ in 0..STREAMS {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    for _ in 0..ROUNDS_PER_STREAM {
                        let msg = match stream.recv().await {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        if stream.send(&msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let payload = vec![0xAAu8; 2048];
        let t0 = Instant::now();

        let mut handles = Vec::with_capacity(STREAMS);
        for _ in 0..STREAMS {
            let client_id = gen_peer();
            let payload = payload.clone();
            let h = tokio::spawn(async move {
                let mut client = pq_dial(
                    addr,
                    client_id.pk,
                    client_id.sk,
                    PeerExpectation::Pinned(server_pin),
                )
                .await
                .unwrap();
                for _ in 0..ROUNDS_PER_STREAM {
                    client.send(&payload).await.unwrap();
                    let _ = client.recv().await.unwrap();
                }
            });
            handles.push(h);
        }
        for h in handles {
            h.await.unwrap();
        }
        let secs = t0.elapsed().as_secs_f64();
        let aggregate_qps = TOTAL_ROUNDS as f64 / secs;
        let per_stream_qps = aggregate_qps / STREAMS as f64;
        println!(
            "RAW stream perf ({STREAMS}x concurrent): aggregate = {aggregate_qps:.0} QPS, \
             per-stream = {per_stream_qps:.0} QPS ({TOTAL_ROUNDS} round-trips in {secs:.2}s)"
        );

        let _ = server.await;

        // Aggregate should clearly exceed single-stream ceiling, proving
        // per-stream QPS was scheduler-bound rather than a crypto/CPU
        // ceiling. Loose floor: `cargo test` runs tests in parallel, so
        // this test's worker threads contend with others. 500 QPS passes
        // on any machine that isn't genuinely broken. Run isolated via
        // `-- --test-threads=1 --nocapture` to see the real ceiling.
        assert!(
            aggregate_qps > 500.0,
            "aggregate too low: {aggregate_qps:.0} — investigate"
        );
    }

    #[tokio::test]
    async fn listener_and_dial_roundtrip() {
        let server_id = gen_peer();
        let client_id = gen_peer();
        let server_pin = server_id.identity_hash;

        let listener = PqListener::bind("127.0.0.1:0", server_id.pk, server_id.sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _peer_addr) = listener.accept().await.unwrap();
            let msg = stream.recv().await.unwrap();
            stream.send(&msg).await.unwrap();
            stream.close().await.unwrap();
        });

        let mut client = pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            PeerExpectation::Pinned(server_pin),
        )
        .await
        .unwrap();
        assert_eq!(client.peer_identity_hash(), server_pin);

        client.send(b"ping over PqListener").await.unwrap();
        let echo = client.recv().await.unwrap();
        assert_eq!(echo, b"ping over PqListener");

        // Server sent Close; next recv should surface that.
        match client.recv().await {
            Err(TransportError::PeerClosed) => {}
            other => panic!("expected PeerClosed, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listener_times_out_silent_peer() {
        let server_id = gen_peer();
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk, server_id.sk)
            .await
            .unwrap()
            .with_handshake_timeout(Duration::from_millis(150));
        let addr = listener.local_addr().unwrap();

        // Attacker: open TCP and sit silent. Listener must abort the
        // accept slot on timeout, not hang forever.
        let _silent = tokio::spawn(async move {
            let _tcp = TcpStream::connect(addr).await.unwrap();
            // Hold the connection open well past the timeout, then drop.
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        let start = std::time::Instant::now();
        let result = listener.accept().await;
        let elapsed = start.elapsed();

        match result {
            Err(TransportError::HandshakeTimeout(d)) => {
                assert_eq!(d, Duration::from_millis(150));
            }
            other => panic!("expected HandshakeTimeout, got {other:?}"),
        }
        // Sanity: we actually waited for the timeout, not instant-failed.
        assert!(elapsed >= Duration::from_millis(150), "returned too fast: {elapsed:?}");
        // And not dramatically longer (allow plenty of slack for CI).
        assert!(elapsed < Duration::from_millis(2000), "returned too slow: {elapsed:?}");
    }

    #[tokio::test]
    async fn data_frame_tamper_is_detected() {
        // Stand up a real handshake, then MITM a data frame mid-flight by
        // splicing a raw TcpStream in between. Simpler approach: after
        // handshake, craft a Data frame with a flipped byte and inject it
        // directly, then ensure the receiver rejects it.
        //
        // We do this by driving both sides in the same task and touching
        // the wire bytes via a proxy.

        // Approach: direct test on the PqStream by tampering the ciphertext
        // before send. We bypass encrypt path: manually build a Data frame
        // with a corrupted tag and write to the TCP socket, observing that
        // the receiver's `recv` fails with AeadFailed.

        let init = gen_peer();
        let resp = gen_peer();
        let resp_pin = resp.identity_hash;

        let (listener, addr) = bind_local().await;
        let resp_pk = resp.pk.clone();
        let resp_sk = resp.sk.clone();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = handshake_responder(tcp, resp_pk, resp_sk).await.unwrap();
            // First recv must fail with AeadFailed.
            let result = stream.recv().await;
            matches!(result, Err(TransportError::AeadFailed))
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut client = handshake_initiator(
            tcp,
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp_pin),
        )
        .await
        .unwrap();

        // Produce a legitimate Data frame, then flip a byte in its payload
        // before writing. We reach inside PqStream for this by calling
        // encrypt + write manually. The AD MUST match the choke point's
        // binding ([frame_type]) so this test isolates ciphertext/tag
        // tamper detection — not the type-binding (covered separately).
        let ct = client
            .completed
            .session
            .k_send
            .encrypt(&[FrameType::Data as u8], b"will be tampered")
            .unwrap();
        let mut frame_bytes = Frame::new(FrameType::Data, ct).unwrap().encode();
        let last = frame_bytes.len() - 1;
        frame_bytes[last] ^= 0x01; // Flip one bit in the Poly1305 tag.
        client.tcp.write_all(&frame_bytes).await.unwrap();

        let detected = server.await.unwrap();
        assert!(detected, "receiver should have flagged AEAD tamper");
    }

    #[tokio::test]
    async fn data_frame_type_byte_flip_is_rejected() {
        // Regression for the header type-byte binding: the frame type lives
        // in the CLEARTEXT wire header (offset 5), outside the ciphertext.
        // An on-path attacker can flip Data→Admission without touching the
        // payload; without binding the type into the AEAD AD the receiver
        // would decrypt successfully and dispatch a genuine, authenticated
        // payload down `handle_inbound_admission`. Binding the type means
        // the flip flips the Poly1305 tag → AeadFailed. This pins that.
        let init = gen_peer();
        let resp = gen_peer();
        let resp_pin = resp.identity_hash;

        let (listener, addr) = bind_local().await;
        let resp_pk = resp.pk.clone();
        let resp_sk = resp.sk.clone();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = handshake_responder(tcp, resp_pk, resp_sk).await.unwrap();
            // recv_typed because recv() rejects non-Data types before decrypt;
            // we need the decrypt itself to be the thing that fails.
            stream.recv_typed().await
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut client = handshake_initiator(
            tcp,
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp_pin),
        )
        .await
        .unwrap();

        // Encrypt a legitimate Data frame (AD = Data type, as send_typed does),
        // then relabel the header type byte to Admission on the wire.
        let ct = client
            .completed
            .session
            .k_send
            .encrypt(&[FrameType::Data as u8], b"genuine application payload")
            .unwrap();
        let mut frame_bytes = Frame::new(FrameType::Data, ct).unwrap().encode();
        assert_eq!(frame_bytes[5], FrameType::Data as u8); // sanity: type at offset 5
        frame_bytes[5] = FrameType::Admission as u8; // flip Data → Admission
        client.tcp.write_all(&frame_bytes).await.unwrap();

        // The receiver observes Admission, binds Admission as AD, and the
        // tag fails because the sender bound Data. AeadFailed, not a
        // successful misroute into the admission handler.
        let got = server.await.unwrap();
        assert!(
            matches!(got, Err(TransportError::AeadFailed)),
            "type-byte flip must be rejected at AEAD verify, got {got:?}"
        );
    }

    #[test]
    fn batch_b_default_handshake_timeout_pins_ten_second_literal_value_at_module_level() {
        // The handshake timeout caps how long a slow-loris-style accept can hold
        // an accept slot. 10 s is the documented value at stream.rs:80 — bumping
        // this is a security-relevant decision (longer = more slot-holding budget
        // for a malicious peer). This pin forces a deliberate edit.
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(10),
            "DEFAULT_HANDSHAKE_TIMEOUT must equal Duration::from_secs(10) literally");
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT.as_secs(), 10,
            "as_secs() must round-trip to 10");
        assert!(DEFAULT_HANDSHAKE_TIMEOUT > Duration::ZERO,
            "timeout must be strictly positive (zero would make handshake_initiator return immediately)");
        assert!(DEFAULT_HANDSHAKE_TIMEOUT < Duration::from_secs(60),
            "timeout must stay well under a minute — longer holds Dilithium3 verify slots open under DOS");
    }

    #[test]
    fn batch_b_transport_error_handshake_timeout_display_renders_duration_with_secs_unit() {
        let err = TransportError::HandshakeTimeout(Duration::from_secs(10));
        let s = err.to_string();
        assert!(s.contains("handshake timed out after"),
            "Display must lead with the documented prefix: got {:?}", s);
        // Rust Duration's Debug formatter writes "10s" (no space, no quotes) for
        // a whole-second value. Operators reading logs depend on the unit being
        // present to distinguish a 10 s window from a hypothetical 60 s tuning
        // regression.
        assert!(s.contains("10s"),
            "Display must embed the Duration with second-unit suffix: got {:?}", s);
    }

    #[test]
    fn batch_b_transport_error_payload_too_large_display_pins_byte_count_and_max_payload_in_message() {
        let big = MAX_PAYLOAD + 1;
        let err = TransportError::PayloadTooLarge(big);
        let s = err.to_string();
        assert!(s.contains("payload too large"),
            "Display must start with the documented marker: got {:?}", s);
        assert!(s.contains(&big.to_string()),
            "Display must include the actual offending byte count {}: got {:?}", big, s);
        assert!(s.contains("bytes"),
            "Display must include the 'bytes' unit so the number isn't ambiguous: got {:?}", s);
        // The const MAX_PAYLOAD must be embedded — operators reading the log
        // know the threshold without cross-referencing src.
        assert!(s.contains(&MAX_PAYLOAD.to_string()),
            "Display must surface the MAX_PAYLOAD limit {}: got {:?}", MAX_PAYLOAD, s);
    }

    #[test]
    fn batch_b_transport_error_handshake_source_chain_walks_to_inner_handshake_error_via_thiserror_from() {
        // The #[from] HandshakeError on TransportError::Handshake gives us
        // (a) implicit conversion via .into() and (b) a working source() chain
        // for log-scrapers that walk to root-cause. e.to_string() alone collapses
        // to "handshake: …" and discards the variant — source() preserves it.
        let inner = HandshakeError::SignatureInvalid;
        let err: TransportError = inner.into();
        match &err {
            TransportError::Handshake(_) => {}
            other => panic!("From<HandshakeError> must construct Handshake variant, got {:?}", other),
        }
        let source = std::error::Error::source(&err);
        assert!(source.is_some(),
            "TransportError::Handshake must expose a source() to walk into the inner error");
        let inner_ref = source.unwrap().downcast_ref::<HandshakeError>();
        assert!(inner_ref.is_some(),
            "source() must downcast back to HandshakeError — log scrapers depend on this");
        assert!(matches!(inner_ref.unwrap(), HandshakeError::SignatureInvalid),
            "downcast must preserve the original variant identity");
        // The top-level Display still carries the wrapping prefix:
        assert!(err.to_string().contains("handshake:"),
            "outer Display must keep the 'handshake:' prefix that thiserror generates from #[error(\"handshake: {{0}}\")]");
    }

    #[test]
    fn batch_b_transport_error_display_pins_static_unit_variant_messages_exhaustively() {
        // Unit-variant Display strings are part of the operator-visible log
        // surface. Pin them so a thiserror attribute edit (e.g. casing change)
        // surfaces here instead of silently breaking log greps.
        assert_eq!(TransportError::PeerClosed.to_string(),
            "peer closed connection",
            "PeerClosed Display is the exact phrase grep'd by health checks");
        assert_eq!(TransportError::ClockBeforeEpoch.to_string(),
            "system clock before unix epoch",
            "ClockBeforeEpoch Display is the exact phrase");
        assert_eq!(TransportError::SendCounterExhausted.to_string(),
            "send counter exhausted — rekey required",
            "SendCounterExhausted points operators at rekey path");
        assert_eq!(TransportError::RecvCounterExhausted.to_string(),
            "recv counter exhausted — rekey required",
            "RecvCounterExhausted points operators at rekey path");
        assert_eq!(TransportError::RekeyUnsupported.to_string(),
            "rekey not supported yet (Stage 4B.1)",
            "RekeyUnsupported tags the unimplemented stage so operators don't open spurious bugs");
        // AeadFailed phrasing differs subtly from the HandshakeError::AeadFailed
        // variant (which mentions "transcript mismatch"). The transport-level one
        // explicitly cites "transit corruption or tampering" — pin so the two
        // remain distinguishable in logs.
        let aead = TransportError::AeadFailed.to_string();
        assert!(aead.contains("AEAD verification failed"),
            "AeadFailed Display starts with the standard marker: got {:?}", aead);
        assert!(aead.contains("transit corruption or tampering"),
            "AeadFailed Display must distinguish transit-level vs handshake-level AEAD failure: got {:?}", aead);
    }

    // ---- REALMS P1 slice (b): post-handshake admission exchange ----

    use crate::network::config::NetworkRealm;
    use crate::network::realm::RealmMembershipCert;

    /// Federation fixtures: root keypair, a member peer, and a valid cert
    /// binding the member's transport identity to the federation root.
    fn federation() -> (crate::crypto::pqc::DilithiumKeypair, TestPeer, RealmMembershipCert) {
        let root = dilithium3_keygen().unwrap();
        let member = gen_peer();
        let now = now_unix_secs().unwrap();
        let cert = RealmMembershipCert::issue(
            &hex::encode(member.identity_hash),
            &root.public_key,
            &root.secret_key,
            now.saturating_sub(60),
            now + 3600,
        )
        .unwrap();
        (root, member, cert)
    }

    fn federated_realm(root_pk: &[u8]) -> NetworkRealm {
        NetworkRealm::Federated { root_pk: hex::encode(root_pk) }
    }

    async fn federated_listener(realm: NetworkRealm) -> (PqListener, std::net::SocketAddr, TestPeer) {
        let server_id = gen_peer();
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk.clone(), server_id.sk.clone())
            .await
            .unwrap()
            .with_realm_gate("testnet".into(), realm);
        let addr = listener.local_addr().unwrap();
        (listener, addr, server_id)
    }

    #[tokio::test]
    async fn federated_admission_happy_path_with_early_request() {
        let (root, member, cert) = federation();
        let (listener, addr, server_id) = federated_listener(federated_realm(&root.public_key)).await;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("valid member must be admitted");
            // The client's request raced ahead of its admission response —
            // it must surface from the pending queue intact and in order.
            let msg = stream.recv().await.unwrap();
            assert_eq!(msg, b"ping");
            stream.send(b"pong").await.unwrap();
        });

        let mut client = pq_dial_with_admission(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
            Some(AdmissionContext { network_id: "testnet".into(), cert: Some(cert) }),
        )
        .await
        .unwrap();
        // Send BEFORE the first recv — exercises responder-side early-frame
        // parking while the admission exchange is still in flight.
        client.send(b"ping").await.unwrap();
        // recv absorbs challenge + admitted-verdict transparently.
        let resp = client.recv().await.unwrap();
        assert_eq!(resp, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn federated_rejects_missing_cert_with_stable_reason() {
        let (root, member, _cert) = federation();
        let (listener, addr, server_id) = federated_listener(federated_realm(&root.public_key)).await;

        let server = tokio::spawn(async move {
            let err = listener.accept().await.expect_err("certless peer must be rejected");
            match err {
                TransportError::AdmissionRejected(reason) => assert_eq!(reason, "cert_missing"),
                other => panic!("expected AdmissionRejected(cert_missing), got {other:?}"),
            }
        });

        let mut client = pq_dial_with_admission(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
            Some(AdmissionContext { network_id: "testnet".into(), cert: None }),
        )
        .await
        .unwrap();
        let err = client.recv().await.expect_err("verdict must reject");
        match err {
            TransportError::AdmissionRejected(reason) => assert_eq!(reason, "cert_missing"),
            other => panic!("expected AdmissionRejected(cert_missing), got {other:?}"),
        }
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn federated_rejects_stolen_cert_as_member_mismatch() {
        let (root, _member, cert) = federation();
        let (listener, addr, server_id) = federated_listener(federated_realm(&root.public_key)).await;

        let server = tokio::spawn(async move {
            let err = listener.accept().await.expect_err("stolen cert must be rejected");
            match err {
                TransportError::AdmissionRejected(reason) => assert_eq!(reason, "member_mismatch"),
                other => panic!("expected AdmissionRejected(member_mismatch), got {other:?}"),
            }
        });

        // The thief presents a real member's cert but handshakes with its
        // own keys — the handshake-proven identity cannot match the cert.
        let thief = gen_peer();
        let mut client = pq_dial_with_admission(
            addr,
            thief.pk.clone(),
            thief.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
            Some(AdmissionContext { network_id: "testnet".into(), cert: Some(cert) }),
        )
        .await
        .unwrap();
        let err = client.recv().await.expect_err("verdict must reject");
        match err {
            TransportError::AdmissionRejected(reason) => assert_eq!(reason, "member_mismatch"),
            other => panic!("expected AdmissionRejected(member_mismatch), got {other:?}"),
        }
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn initiator_refuses_to_present_cert_across_networks() {
        let (root, member, cert) = federation();
        let (listener, addr, server_id) = federated_listener(federated_realm(&root.public_key)).await;

        let server = tokio::spawn(async move {
            // Client bails locally without answering the challenge — the
            // responder sees the connection die, not a response.
            let _ = listener.accept().await.expect_err("client hangs up during admission");
        });

        let mut client = pq_dial_with_admission(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
            Some(AdmissionContext { network_id: "othernet".into(), cert: Some(cert) }),
        )
        .await
        .unwrap();
        let err = client.recv().await.expect_err("local network guard must fire");
        match err {
            TransportError::AdmissionRejected(reason) => {
                assert!(reason.starts_with("network_mismatch"), "got: {reason}");
            }
            other => panic!("expected AdmissionRejected(network_mismatch...), got {other:?}"),
        }
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn contextless_dialer_cannot_join_federated_realm() {
        let (root, member, _cert) = federation();
        let (listener, addr, server_id) = federated_listener(federated_realm(&root.public_key)).await;

        let server = tokio::spawn(async move {
            let _ = listener.accept().await.expect_err("contextless peer never completes admission");
        });

        // Plain pq_dial — no admission context (the in-repo equivalent of a
        // peer that has no realm configuration at all).
        let mut client = pq_dial(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
        )
        .await
        .unwrap();
        let err = client.recv().await.expect_err("challenge without context must fail");
        assert!(
            matches!(err, TransportError::AdmissionProtocol(_)),
            "expected AdmissionProtocol, got {err:?}"
        );
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn open_realm_gate_is_a_no_op_zero_delta() {
        // Threading config.network_realm unconditionally must not change
        // Open-realm behavior: no challenge, plain dial works, and an
        // armed admission context on the client is simply never used.
        let server_id = gen_peer();
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk.clone(), server_id.sk.clone())
            .await
            .unwrap()
            .with_realm_gate("testnet".into(), NetworkRealm::Open);
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg = stream.recv().await.unwrap();
            stream.send(&msg).await.unwrap();
        });

        let member = gen_peer();
        let mut client = pq_dial_with_admission(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
            Some(AdmissionContext { network_id: "testnet".into(), cert: None }),
        )
        .await
        .unwrap();
        client.send(b"open-mesh").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"open-mesh");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sovereign_listener_denies_unknown_and_accepts_pinned() {
        // REALMS P1 (c2): a sovereign listener drops post-handshake any
        // initiator whose identity is not in the pin store; pinned
        // identities sail through. No admission frames are involved — the
        // handshake itself authenticates the initiator.
        let server_id = gen_peer();
        let pins = std::sync::Arc::new(super::super::peer_store::PeerIdentityStore::in_memory());
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk.clone(), server_id.sk.clone())
            .await
            .unwrap()
            .with_realm_gate("sov-net".into(), NetworkRealm::Sovereign)
            .with_sovereign_pins(pins.clone());
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // First accept: unknown initiator → SovereignDenied (recoverable).
            let denied = listener.accept().await;
            assert!(
                matches!(denied, Err(TransportError::SovereignDenied(_))),
                "unknown inbound identity must be denied, got: {denied:?}",
            );
            // Second accept: pinned initiator → echo works.
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg = stream.recv().await.unwrap();
            stream.send(&msg).await.unwrap();
        });

        // Stranger: the PQ handshake completes (authentication is what
        // identifies them), then the server drops the stream. The client
        // may see the dial succeed — denial is server-side — but the
        // stream is dead on first use.
        let stranger = gen_peer();
        let stranger_conn = pq_dial(
            addr,
            stranger.pk.clone(),
            stranger.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
        )
        .await;
        if let Ok(mut s) = stranger_conn {
            let _ = s.send(b"hello?").await;
            assert!(s.recv().await.is_err(), "stranger stream must be dead");
        }

        // Pinned member: pinned under its DIAL addr (the store is
        // addr-keyed); the sovereign gate matches by identity, proving
        // ephemeral inbound source ports don't matter.
        let member = gen_peer();
        pins.pin_or_verify("member-dial-addr:9573", member.identity_hash)
            .unwrap();
        let mut client = pq_dial(
            addr,
            member.pk.clone(),
            member.sk.clone(),
            PeerExpectation::Pinned(server_id.identity_hash),
        )
        .await
        .unwrap();
        client.send(b"sovereign-member").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"sovereign-member");
        server.await.unwrap();
    }

    #[test]
    fn realm_gate_check_rejects_network_mismatch_from_byzantine_response() {
        // The honest client path never reaches the server-side network
        // check (it bails locally on the challenge) — a byzantine client
        // hand-rolling a response is exactly who this arm exists for.
        let (root, member, cert) = federation();
        let gate = RealmGate {
            network_id: "testnet".into(),
            realm: federated_realm(&root.public_key),
        };
        let now = now_unix_secs().unwrap();
        let err = gate
            .check("othernet", &Some(cert.clone()), member.identity_hash, now)
            .expect_err("network mismatch must reject");
        assert_eq!(err.wire_reason(), "network_mismatch");
        // Same response on the right network passes.
        assert!(gate.check("testnet", &Some(cert), member.identity_hash, now).is_ok());
    }
}
