//! ADR-0074 slice 4 — SOCKS5 intent tests (auth, loopback bind, port deny).
//!
//! Session tests speak SOCKS on a real `TcpListener` / `TcpStream` pair and
//! call [`handle_tcp_client`]. The connector is a [`SocksConnector`]; these
//! tests do not open a duplex or call a stream-session helper.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use super::config::{SocksConfig, SocksConfigError};
use super::proto::{
    resolve_x0x_host, ProtoError, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USER_PASS,
    REP_NOT_ALLOWED, REP_SUCCEEDED, VER,
};
use super::service::{
    handle_tcp_client, SocksConnectError, SocksConnector, SocksService, SocksTunnel,
    MAX_SOCKS_SESSIONS,
};
use crate::exec::acl::parse_agent_id;
use crate::identity::AgentId;

const TOKEN: &str = "test-api-token-for-socks-auth";

fn peer_host() -> (AgentId, String) {
    let id = parse_agent_id(&"ab".repeat(32)).unwrap();
    let host = format!("{}.x0x", hex::encode(id.as_bytes()));
    (id, host)
}

/// Client-side: greet with the given methods list.
async fn client_greet(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    methods: &[u8],
) -> u8 {
    let mut msg = vec![VER, methods.len() as u8];
    msg.extend_from_slice(methods);
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], VER);
    resp[1]
}

async fn client_userpass(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    user: &str,
    pass: &str,
) -> u8 {
    let mut msg = vec![0x01, user.len() as u8];
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x01);
    resp[1]
}

async fn client_connect_domain(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    host: &str,
    port: u16,
) -> u8 {
    let host_b = host.as_bytes();
    let mut msg = vec![VER, 0x01, 0x00, 0x03, host_b.len() as u8];
    msg.extend_from_slice(host_b);
    msg.extend_from_slice(&port.to_be_bytes());
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], VER);
    resp[1]
}

async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

struct SessionFlags {
    prepares: Arc<AtomicU64>,
    attempted: Arc<AtomicBool>,
    denied: Arc<AtomicU64>,
}

fn session_flags() -> SessionFlags {
    SessionFlags {
        prepares: Arc::new(AtomicU64::new(0)),
        attempted: Arc::new(AtomicBool::new(false)),
        denied: Arc::new(AtomicU64::new(0)),
    }
}

/// Counts `prepare` calls. Used to prove auth refusal never reaches the connector.
struct CountingConnector {
    prepares: Arc<AtomicU64>,
}

#[async_trait]
impl SocksConnector for CountingConnector {
    async fn prepare(
        &self,
        _peer: AgentId,
        _port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Err(SocksConnectError::NotAllowed)
    }
}

struct RecordedPrepare {
    prepares: AtomicU64,
    port: AtomicU64,
    peer: Mutex<Option<AgentId>>,
    bridged: Arc<AtomicBool>,
}

struct FlagTunnel {
    bridged: Arc<AtomicBool>,
}

#[async_trait]
impl SocksTunnel for FlagTunnel {
    async fn bridge(self: Box<Self>, _client: TcpStream) {
        self.bridged.store(true, Ordering::SeqCst);
    }
}

/// Allow path: record the peer and port, then a tunnel whose `bridge` returns immediately.
struct AllowConnector {
    recorded: Arc<RecordedPrepare>,
}

#[async_trait]
impl SocksConnector for AllowConnector {
    async fn prepare(
        &self,
        peer: AgentId,
        port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        self.recorded.prepares.fetch_add(1, Ordering::SeqCst);
        self.recorded.port.store(u64::from(port), Ordering::SeqCst);
        *self.recorded.peer.lock().unwrap() = Some(peer);
        Ok(Box::new(FlagTunnel {
            bridged: Arc::clone(&self.recorded.bridged),
        }))
    }
}

/// Protocol-mapping deny: `prepare` ran, the SOCKS layer must answer `0x02`.
/// `target_bytes` is never incremented here — it is not a stand-in for a real target.
struct DenyConnector {
    prepares: AtomicU64,
    port: AtomicU64,
    /// Left at zero on [`SocksConnectError::NotAllowed`]. Not a byte counter on a socket.
    target_bytes: AtomicU64,
}

#[async_trait]
impl SocksConnector for DenyConnector {
    async fn prepare(
        &self,
        _peer: AgentId,
        port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        self.port.store(u64::from(port), Ordering::SeqCst);
        Err(SocksConnectError::NotAllowed)
    }
}

struct IdleConnector;

#[async_trait]
impl SocksConnector for IdleConnector {
    async fn prepare(
        &self,
        _peer: AgentId,
        _port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        Err(SocksConnectError::Unreachable)
    }
}

fn spawn_handler(
    server: TcpStream,
    api_token: &'static str,
    connector: Arc<dyn SocksConnector>,
    flags: &SessionFlags,
) -> tokio::task::JoinHandle<Result<(), ProtoError>> {
    let attempted = Arc::clone(&flags.attempted);
    let denied = Arc::clone(&flags.denied);
    let cancel = CancellationToken::new();
    tokio::spawn(async move {
        handle_tcp_client(
            server,
            api_token,
            connector.as_ref(),
            denied.as_ref(),
            Some(attempted.as_ref()),
            &cancel,
        )
        .await
    })
}

async fn finish(task: tokio::task::JoinHandle<Result<(), ProtoError>>) {
    task.await.expect("handler task").expect("handler finished");
}

#[test]
fn socks_config_refuses_non_loopback_listen() {
    let cfg = SocksConfig {
        listen: Some("192.168.1.10:1080".parse().unwrap()),
    };
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, SocksConfigError::NonLoopback { .. }), "{err}");
}

#[test]
fn socks_config_accepts_loopback_and_off() {
    assert!(SocksConfig::default().validate().is_ok());
    assert!(!SocksConfig::default().enabled());
    let cfg = SocksConfig {
        listen: Some("127.0.0.1:1080".parse().unwrap()),
    };
    assert!(cfg.validate().is_ok());
    assert!(cfg.enabled());
    let cfg6 = SocksConfig {
        listen: Some("[::1]:1080".parse().unwrap()),
    };
    assert!(cfg6.validate().is_ok());
}

#[test]
fn resolve_hex_agent_x0x_host() {
    let id = parse_agent_id(&"cd".repeat(32)).unwrap();
    let host = format!("{}.x0x", hex::encode(id.as_bytes()));
    assert_eq!(resolve_x0x_host(&host).unwrap(), id);
    assert!(resolve_x0x_host("example.com").is_err());
    assert!(resolve_x0x_host("192.168.1.1").is_err());
}

#[tokio::test]
async fn no_auth_refused_before_any_connect() {
    let flags = session_flags();
    let connector = Arc::new(CountingConnector {
        prepares: Arc::clone(&flags.prepares),
    });
    let (mut client, server) = connected_pair().await;
    let task = spawn_handler(server, TOKEN, connector, &flags);

    let method = client_greet(&mut client, &[METHOD_NO_AUTH]).await;
    assert_eq!(method, METHOD_NO_ACCEPTABLE);
    finish(task).await;
    assert_eq!(flags.prepares.load(Ordering::SeqCst), 0);
    assert!(!flags.attempted.load(Ordering::SeqCst));
}

#[tokio::test]
async fn wrong_token_refused_before_any_connect() {
    let flags = session_flags();
    let connector = Arc::new(CountingConnector {
        prepares: Arc::clone(&flags.prepares),
    });
    let (mut client, server) = connected_pair().await;
    let task = spawn_handler(server, TOKEN, connector, &flags);

    assert_eq!(
        client_greet(&mut client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(
        client_userpass(&mut client, "x0x", "wrong-token").await,
        0x01
    );
    finish(task).await;
    assert_eq!(flags.prepares.load(Ordering::SeqCst), 0);
    assert!(!flags.attempted.load(Ordering::SeqCst));
}

#[tokio::test]
async fn empty_daemon_token_refused_before_any_connect() {
    let flags = session_flags();
    // An absent daemon token must not compare equal to an empty password.
    for password in ["", "any-password"] {
        let connector = Arc::new(CountingConnector {
            prepares: Arc::clone(&flags.prepares),
        });
        let (mut client, server) = connected_pair().await;
        let task = spawn_handler(server, "", connector, &flags);
        assert_eq!(
            client_greet(&mut client, &[METHOD_USER_PASS]).await,
            METHOD_USER_PASS
        );
        assert_eq!(client_userpass(&mut client, "x0x", password).await, 0x01);
        finish(task).await;
        assert!(
            !flags.attempted.load(Ordering::SeqCst),
            "empty daemon token must not open a tunnel for password {password:?}"
        );
    }
    assert_eq!(flags.prepares.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn empty_password_against_real_token_refused() {
    let flags = session_flags();
    let connector = Arc::new(CountingConnector {
        prepares: Arc::clone(&flags.prepares),
    });
    let (mut client, server) = connected_pair().await;
    let task = spawn_handler(server, TOKEN, connector, &flags);

    assert_eq!(
        client_greet(&mut client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(&mut client, "x0x", "").await, 0x01);
    finish(task).await;
    assert_eq!(flags.prepares.load(Ordering::SeqCst), 0);
    assert!(!flags.attempted.load(Ordering::SeqCst));
}

#[tokio::test]
async fn allowed_connect_reaches_connector() {
    let (expected_peer, host) = peer_host();
    let recorded = Arc::new(RecordedPrepare {
        prepares: AtomicU64::new(0),
        port: AtomicU64::new(0),
        peer: Mutex::new(None),
        bridged: Arc::new(AtomicBool::new(false)),
    });
    let connector = Arc::new(AllowConnector {
        recorded: Arc::clone(&recorded),
    });
    let flags = session_flags();
    let (mut client, server) = connected_pair().await;
    let task = spawn_handler(server, TOKEN, connector, &flags);

    assert_eq!(
        client_greet(&mut client, &[METHOD_NO_AUTH, METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(&mut client, "x0x", TOKEN).await, 0x00);
    let rep = client_connect_domain(&mut client, &host, 8080).await;
    assert_eq!(rep, REP_SUCCEEDED);
    finish(task).await;

    assert_eq!(recorded.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(recorded.port.load(Ordering::SeqCst), 8080);
    assert_eq!(*recorded.peer.lock().unwrap(), Some(expected_peer));
    assert!(recorded.bridged.load(Ordering::SeqCst));
    assert!(flags.attempted.load(Ordering::SeqCst));
}

#[tokio::test]
async fn disallowed_port_returns_0x02_and_denied_count() {
    let (_peer, host) = peer_host();
    let connector = Arc::new(DenyConnector {
        prepares: AtomicU64::new(0),
        port: AtomicU64::new(0),
        target_bytes: AtomicU64::new(0),
    });
    let flags = session_flags();
    let (mut client, server) = connected_pair().await;
    let task = spawn_handler(
        server,
        TOKEN,
        Arc::clone(&connector) as Arc<dyn SocksConnector>,
        &flags,
    );

    assert_eq!(
        client_greet(&mut client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(&mut client, "x0x", TOKEN).await, 0x00);
    let rep = client_connect_domain(&mut client, &host, 9999).await;
    assert_eq!(rep, REP_NOT_ALLOWED);
    finish(task).await;

    assert_eq!(connector.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(connector.port.load(Ordering::SeqCst), 9999);
    assert_eq!(
        flags.denied.load(Ordering::SeqCst),
        1,
        "NotAllowed must increment the SOCKS denied counter"
    );
    // The connector does not touch this counter on NotAllowed. A real target's
    // accept/byte counts are asserted in tests/socks_peer_gate.rs.
    assert_eq!(connector.target_bytes.load(Ordering::SeqCst), 0);
}

async fn try_spawn(listen: &str) -> std::io::Result<SocksService> {
    let cfg = SocksConfig {
        listen: Some(listen.parse().unwrap()),
    };
    let connector: Arc<dyn SocksConnector> = Arc::new(IdleConnector);
    SocksService::spawn(
        &cfg,
        Arc::new(TOKEN.to_string()),
        connector,
        CancellationToken::new(),
    )
    .await
}

fn assert_invalid_input(result: std::io::Result<SocksService>) {
    match result {
        Err(err) => assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "non-loopback spawn must fail before bind: {err}"
        ),
        Ok(_) => panic!("non-loopback spawn must fail before bind"),
    }
}

#[tokio::test]
async fn spawn_refuses_non_loopback_without_binding() {
    // Well-known non-loopback literals. InvalidInput is the validate-before-bind
    // failure; an in-use port 1080 would be AddrInUse if spawn had bound.
    assert_invalid_input(try_spawn("0.0.0.0:1080").await);
    assert_invalid_input(try_spawn("8.8.8.8:1").await);

    // Ephemeral proof: if spawn had bound 0.0.0.0:port, 127.0.0.1:port would fail.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let unspecified = format!("0.0.0.0:{port}");
    assert_invalid_input(try_spawn(&unspecified).await);
    let rebound = TcpListener::bind(("127.0.0.1", port)).await;
    assert!(
        rebound.is_ok(),
        "spawn must not be listening on 0.0.0.0:{port}: {rebound:?}"
    );
    drop(rebound);

    let loopback = format!("127.0.0.1:{port}");
    let service = try_spawn(&loopback).await.expect("loopback spawn");
    service.shutdown_and_wait().await;
    TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("shutdown_and_wait released the loopback port");

    let ephemeral = try_spawn("127.0.0.1:0").await.expect("127.0.0.1:0 spawn");
    ephemeral.shutdown_and_wait().await;
}

/// Half-open sessions occupy the cap. One more connection is closed and does
/// not sit in the handshake. An unlimited accept loop would keep it open.
#[tokio::test]
async fn session_cap_closes_the_next_connection() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let service = try_spawn(&format!("127.0.0.1:{port}"))
        .await
        .expect("loopback spawn");

    let mut held = Vec::new();
    for _ in 0..MAX_SOCKS_SESSIONS {
        held.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut extra = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_millis(500), extra.read(&mut buf))
        .await
        .expect("over-cap connection must be closed, not held open");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "over-cap session must not stay open: {closed:?}"
    );

    let still_open = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        held[0].read(&mut buf),
    )
    .await;
    assert!(
        still_open.is_err(),
        "an admitted session must stay open until it sends bytes or the deadline"
    );

    service.shutdown_and_wait().await;
}

/// A handshake blocked on the first client byte must end when the listener
/// shuts down, not when the step deadline expires.
#[tokio::test]
async fn shutdown_cancels_idle_handshake() {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let service = try_spawn(&format!("127.0.0.1:{port}"))
        .await
        .expect("loopback spawn");
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.shutdown_and_wait(),
    )
    .await
    .expect("shutdown must not wait out the handshake deadline");

    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("cancelled handshake must drop the socket");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
}

/// An idle method read ends at the step deadline and never calls prepare.
#[tokio::test]
async fn idle_handshake_hits_the_step_deadline() {
    let flags = session_flags();
    let connector = Arc::new(CountingConnector {
        prepares: Arc::clone(&flags.prepares),
    });
    let (_client, server) = connected_pair().await;
    let cancel = CancellationToken::new();
    let denied = AtomicU64::new(0);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        handle_tcp_client(
            server,
            TOKEN,
            connector.as_ref(),
            &denied,
            Some(flags.attempted.as_ref()),
            &cancel,
        ),
    )
    .await
    .expect("handshake deadline must end the session before 12s");
    let err = outcome.expect_err("idle handshake is a timeout, not success");
    match err {
        ProtoError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::TimedOut, "{io}"),
        other => panic!("expected a timed-out handshake, got {other}"),
    }
    assert_eq!(flags.prepares.load(Ordering::SeqCst), 0);
    assert!(!flags.attempted.load(Ordering::SeqCst));
}

/// `prepare` never returns. Dropping the future counts as stream cleanup.
struct StallConnector {
    started: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

struct StallGuard(Arc<AtomicU64>);

impl Drop for StallGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl SocksConnector for StallConnector {
    async fn prepare(
        &self,
        _peer: AgentId,
        _port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        let _guard = StallGuard(Arc::clone(&self.dropped));
        std::future::pending::<Result<Box<dyn SocksTunnel>, SocksConnectError>>().await
    }
}

async fn write_connect_domain(client: &mut TcpStream, host: &str, port: u16) {
    let host_b = host.as_bytes();
    let mut msg = vec![VER, 0x01, 0x00, 0x03, host_b.len() as u8];
    msg.extend_from_slice(host_b);
    msg.extend_from_slice(&port.to_be_bytes());
    client.write_all(&msg).await.unwrap();
    client.flush().await.unwrap();
}

async fn login(client: &mut TcpStream) {
    assert_eq!(
        client_greet(client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(client, "x0x", TOKEN).await, 0x00);
}

fn stall_connector() -> Arc<StallConnector> {
    Arc::new(StallConnector {
        started: Arc::new(AtomicU64::new(0)),
        dropped: Arc::new(AtomicU64::new(0)),
    })
}

async fn spawn_stall(connector: Arc<StallConnector>) -> (SocksService, u16) {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let cfg = SocksConfig {
        listen: Some(format!("127.0.0.1:{port}").parse().unwrap()),
    };
    let service = SocksService::spawn(
        &cfg,
        Arc::new(TOKEN.to_string()),
        connector,
        CancellationToken::new(),
    )
    .await
    .expect("loopback spawn");
    (service, port)
}

async fn wait_until(flag: &AtomicU64, want: u64) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while flag.load(Ordering::SeqCst) < want {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("counter must reach the target within 2s");
}

/// WHY (Codex P2 / #1505): 32 prepares that never return fill the session
/// cap. Disconnecting those clients must drop each prepare future and free
/// the permits before the handshake deadline.
#[tokio::test]
async fn stalled_prepare_client_disconnect_releases_session_cap() {
    let (_peer, host) = peer_host();
    let stall = stall_connector();
    let (service, port) = spawn_stall(Arc::clone(&stall)).await;
    let mut held = Vec::new();
    for _ in 0..MAX_SOCKS_SESSIONS {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        login(&mut client).await;
        write_connect_domain(&mut client, &host, 9).await;
        held.push(client);
    }
    wait_until(&stall.started, MAX_SOCKS_SESSIONS as u64).await;

    let mut extra = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_millis(500), extra.read(&mut buf))
        .await
        .expect("the 33rd session must be refused while prepares are stalled");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "over-cap session must not stay open: {closed:?}"
    );

    drop(held);
    wait_until(&stall.dropped, MAX_SOCKS_SESSIONS as u64).await;

    let admitted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            if client
                .write_all(&[VER, 0x01, METHOD_USER_PASS])
                .await
                .is_err()
            {
                continue;
            }
            let mut method = [0u8; 2];
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client.read_exact(&mut method),
            )
            .await
            {
                Ok(Ok(_)) => {
                    assert_eq!(method[0], VER);
                    break;
                }
                _ => tokio::task::yield_now().await,
            }
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "disconnect during prepare must free a session permit within 2s"
    );
    service.shutdown_and_wait().await;
}

/// Listener cancel during a withheld prepare must drop that future. The
/// client socket closes without waiting for the 10 second deadline.
#[tokio::test]
async fn shutdown_cancels_stalled_prepare() {
    let (_peer, host) = peer_host();
    let stall = stall_connector();
    let (service, port) = spawn_stall(Arc::clone(&stall)).await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    login(&mut client).await;
    write_connect_domain(&mut client, &host, 9).await;
    wait_until(&stall.started, 1).await;

    let mut buf = [0u8; 1];
    let finished = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(service.shutdown_and_wait(), client.read(&mut buf))
    })
    .await
    .expect("cancel during prepare must end the session within 2s");
    assert!(
        matches!(finished.1, Ok(0) | Err(_)),
        "cancelled prepare must drop the client socket: {:?}",
        finished.1
    );
    assert_eq!(stall.dropped.load(Ordering::SeqCst), 1);
}
