//! ADR-0074 §5 / #1390: `Connect { ports }` admits one listener through a
//! forward and through SOCKS, denies the other listener listed on the same
//! `principal = "grant"` entry, and after `revoke_share_grant` tears both
//! live tunnels down. The peer gate is `authorize_attested_opener`.
//!
//! The test is `#[ignore]`. The CI tailnet job runs it with
//! `X0X_REQUIRE_NETWORK_TESTS=1`. A refused UDP bind fails the test. The
//! test passes only after both tunnels carry a byte and then end in EOF or
//! reset. It does not return success when setup does not run. The
//! five-second teardown bound starts when the revocation is inserted, not
//! when `revoke_share_grant` returns from its gossip publish. A sighting
//! after that return does not move the deadline, including a sighting taken
//! before the observer consumes the join handle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "common/network_gate.rs"]
mod network_gate;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use x0x::connect::{ConnectAcl, ConnectDiagnostics, ConnectOwnerEntry, ConnectPolicy, OwnerTarget};
use x0x::forward::ForwardService;
use x0x::identity::UserKeypair;
use x0x::network::NetworkConfig;
use x0x::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
use x0x::socks::{handle_tcp_client, ForwardSocksConnector};
use x0x::DiscoveredAgent;

const TOKEN: &str = "share-grant-connect-token";

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

async fn build_agent(dir: &TempDir, name: &str, user: Option<UserKeypair>) -> x0x::Agent {
    network_gate::init_stream_tracing();
    let mut builder = x0x::Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config());
    if let Some(user) = user {
        builder = builder.with_user_key(user);
    }
    match builder.build().await {
        Ok(agent) => agent,
        // `skip_on_refused_network` panics when the CI tailnet job sets
        // `X0X_REQUIRE_NETWORK_TESTS=1`. A refused bind without that variable
        // still fails: this test must not report success for a skipped setup.
        Err(e) if network_gate::skip_on_refused_network(&e) => {
            panic!(
                "network setup refused; share_grant_connect observes the connect path and does not skip: {e}"
            );
        }
        Err(e) => panic!("agent build failed: {e}"),
    }
}

fn normalize_loopback(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

fn beacon(agent: &x0x::Agent, addr: SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: agent.user_id(),
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

async fn link_pair(alice: &x0x::Agent, bob: &x0x::Agent) {
    alice.join_network().await.unwrap();
    bob.join_network().await.unwrap();
    let alice_network = alice.network().unwrap().clone();
    let bob_network = bob.network().unwrap().clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.unwrap());
    alice_network.connect_addr(bob_addr).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    while std::time::Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network
                .is_connected(&ant_quic::PeerId(alice.machine_id().0))
                .await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(alice_network.is_connected(&bob_peer).await, "alice->bob");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.unwrap());
    alice
        .insert_discovered_agent_for_testing(beacon(bob, bob_addr, now))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(beacon(alice, alice_addr, now))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;
    bob.record_authenticated_machine_binding_for_testing(alice.agent_id(), alice.machine_id())
        .await;
}

fn grant_policy(allowed: SocketAddr, denied: SocketAddr) -> Arc<ConnectPolicy> {
    Arc::new(ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: "test".into(),
        loaded_at_unix_ms: 0,
        allow: Vec::new(),
        owner_allow: Vec::new(),
        grant_allow: vec![ConnectOwnerEntry {
            description: None,
            targets: vec![OwnerTarget::Exact(allowed), OwnerTarget::Exact(denied)],
        }],
    }))
}

fn forwarder(agent: &Arc<x0x::Agent>, policy: Arc<ConnectPolicy>) -> Arc<ForwardService> {
    let diag = Arc::new(ConnectDiagnostics::new(policy.summary()));
    let service = Arc::new(
        ForwardService::new(Arc::clone(agent), policy, diag, true).expect("ForwardService::new"),
    );
    service.spawn_inbound();
    service
}

struct Probe {
    port: u16,
    accepts: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    cancel: CancellationToken,
}

async fn spawn_probe() -> Probe {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let accepts_task = Arc::clone(&accepts);
    let bytes_task = Arc::clone(&bytes);
    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = cancel_task.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut sock, _)) = accepted else { break };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let bytes_task = Arc::clone(&bytes_task);
            tokio::spawn(async move {
                // Echo every byte and stay up until the peer closes. One echo
                // and then a discarded read lets the handler exit, so a later
                // liveness probe would observe a close that revoke did not cause.
                let mut buf = [0u8; 8];
                let mut counted = false;
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if !counted {
                        bytes_task.fetch_add(1, Ordering::SeqCst);
                        counted = true;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Probe {
        port,
        accepts,
        bytes,
        cancel,
    }
}

async fn forward_exchange(local: SocketAddr) -> Result<u8, String> {
    let mut client = TcpStream::connect(local)
        .await
        .map_err(|e| format!("connect {local}: {e}"))?;
    client
        .write_all(&[0x42])
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut got = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(15), client.read_exact(&mut got)).await {
        Ok(Ok(_)) => Ok(got[0]),
        Ok(Err(e)) => Err(format!("read: {e}")),
        Err(_) => Err("forward exchange timed out".into()),
    }
}

async fn socks_reply(
    connector: &dyn x0x::socks::SocksConnector,
    host: &str,
    port: u16,
    exchange: bool,
) -> u8 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_res, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut client = client_res.unwrap();
    let (server, _) = accepted.unwrap();
    let cancel = CancellationToken::new();
    let denied = AtomicU64::new(0);
    let host = host.to_string();
    // Drop the client before the handler future ends. `bridge` returns only
    // on client EOF, so joining while `client` is still held deadlocks.
    let (handler, rep) = tokio::join!(
        handle_tcp_client(server, TOKEN, connector, &denied, None, &cancel),
        async move {
            let rep = socks_roundtrip(&mut client, &host, port, exchange).await;
            drop(client);
            rep
        },
    );
    handler.expect("socks session");
    rep
}

async fn socks_roundtrip(client: &mut TcpStream, host: &str, port: u16, exchange: bool) -> u8 {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);
    let user = b"x0x";
    let pass = TOKEN.as_bytes();
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    client.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [0x01, 0x00]);
    let host_b = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
    req.extend_from_slice(host_b);
    req.extend_from_slice(&port.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    if exchange && resp[1] == 0x00 {
        client.write_all(&[0x42]).await.unwrap();
        let mut got = [0u8; 1];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x42, "SOCKS tunnel must echo the granted port");
    }
    resp[1]
}

/// EOF or a reset-class error. A data byte is not teardown.
fn closed_by_teardown(result: &std::io::Result<usize>) -> bool {
    match result {
        Ok(0) => true,
        Ok(_) => false,
        Err(err) => matches!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
    }
}

#[test]
fn closed_by_teardown_rejects_payload_and_accepts_eof_or_reset() {
    let eof: std::io::Result<usize> = Ok(0);
    let payload: std::io::Result<usize> = Ok(1);
    assert!(closed_by_teardown(&eof));
    assert!(
        !closed_by_teardown(&payload),
        "a data byte before or after revoke is not teardown"
    );
    assert!(closed_by_teardown(&Err(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ))));
    assert!(!closed_by_teardown(&Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out",
    ))));
}

/// ADR-0074 §4: `closed` is within `bound` of the revocation taking effect.
///
/// `effect` is the first moment `is_share_grant_revoked` is true. That is
/// inside `revoke_share_grant`, before that call publishes.
fn closed_within_revocation_bound(
    effect: std::time::Instant,
    closed: std::time::Instant,
    bound: Duration,
) -> bool {
    closed
        .checked_duration_since(effect)
        .is_some_and(|elapsed| elapsed <= bound)
}

/// Deadline for the teardown read.
///
/// A revoked bit seen while `revoke_share_grant` is still running starts
/// the bound at that instant. A bit seen only after the call returns does
/// not: the deadline stays at `armed + bound`, which was set before the call.
///
/// `effect_during_revoke` is [`bound_starts_at_sample`]. An unconsumed join
/// handle is not "still running".
fn revocation_teardown_deadline(
    armed: std::time::Instant,
    effect: Option<std::time::Instant>,
    effect_during_revoke: bool,
    bound: Duration,
) -> std::time::Instant {
    match effect {
        Some(effect) if effect_during_revoke => effect + bound,
        _ => armed + bound,
    }
}

/// What the observer knows when it first sees the revoked bit.
#[derive(Clone, Copy)]
struct RevokeSighting {
    /// `revoke_share_grant` has returned. This is `JoinHandle::is_finished`,
    /// not whether `select` has consumed the handle.
    task_finished: bool,
    /// The observer has consumed the join handle.
    join_consumed: bool,
}

/// The sighting starts the five-second bound only while revoke is running.
///
/// `join_consumed` stays false until `select` takes the join branch. A
/// biased `select` takes the socket reads first, so the next sighting can
/// run with an unconsumed join after the task has already returned. That
/// sighting must not move the deadline.
fn bound_starts_at_sample(sighting: RevokeSighting) -> bool {
    match sighting {
        RevokeSighting {
            task_finished: true,
            join_consumed: _,
        } => false,
        RevokeSighting {
            task_finished: false,
            join_consumed: _,
        } => true,
    }
}

/// WHY (Codex P2): `revoke_share_grant` inserts the revocation and then
/// awaits gossip. A clock that starts when the call returns accepts a
/// teardown that already took longer than five seconds. The bound is the
/// insert.
#[test]
fn slow_teardown_past_the_revocation_bound_fails() {
    let effect = std::time::Instant::now();
    let bound = Duration::from_secs(5);
    // Publish returns six seconds after the insert. The sockets close with
    // that return. The old clock starts here and sees an immediate EOF.
    let revoke_returned = effect + Duration::from_secs(6);
    let closed = revoke_returned;
    assert!(
        closed.saturating_duration_since(revoke_returned) <= bound,
        "a clock started at revoke's return hides this teardown"
    );
    assert!(
        !closed_within_revocation_bound(effect, closed, bound),
        "teardown 6s after the revocation took effect must fail"
    );
    assert!(closed_within_revocation_bound(
        effect,
        effect + bound,
        bound
    ));
    // The revoked bit is sampled only when revoke returns, six seconds
    // later. That sample must not move the deadline.
    let armed = effect;
    let late_sample = effect + Duration::from_secs(6);
    let deadline = revocation_teardown_deadline(armed, Some(late_sample), false, bound);
    assert_eq!(deadline, armed + bound);
    assert!(
        late_sample > deadline,
        "a close that lands when revoke returns is past the armed deadline"
    );
    let during =
        revocation_teardown_deadline(armed, Some(effect + Duration::from_millis(10)), true, bound);
    assert_eq!(during, effect + Duration::from_millis(10) + bound);
}

/// WHY (Codex P2): both the socket reads and `revoke_share_grant` can finish
/// before the observer resumes. Biased `select` takes the reads and leaves
/// the join handle unconsumed. The next sighting is six seconds late. The
/// join flag would start the bound at that sighting and accept the teardown.
#[test]
fn late_sample_after_finished_revoke_before_join_keeps_armed_deadline() {
    let armed = std::time::Instant::now();
    let bound = Duration::from_secs(5);
    let late_sample = armed + Duration::from_secs(6);
    let sighting = RevokeSighting {
        task_finished: true,
        join_consumed: false,
    };
    let starts = bound_starts_at_sample(sighting);
    let deadline = revocation_teardown_deadline(armed, Some(late_sample), starts, bound);
    let join_flag_deadline =
        revocation_teardown_deadline(armed, Some(late_sample), !sighting.join_consumed, bound);
    assert!(
        late_sample <= join_flag_deadline,
        "the unconsumed join flag would accept this six-second teardown"
    );
    assert_eq!(deadline, armed + bound);
    assert!(
        late_sample > deadline,
        "teardown at {late_sample:?} must miss {deadline:?}"
    );
}

/// A sighting taken while `revoke_share_grant` is still inside publish
/// starts the bound at that sighting. The armed instant is before the insert.
#[test]
fn running_revoke_sighting_starts_the_teardown_bound() {
    let armed = std::time::Instant::now();
    let bound = Duration::from_secs(5);
    let effect = armed + Duration::from_millis(10);
    let starts = bound_starts_at_sample(RevokeSighting {
        task_finished: false,
        join_consumed: false,
    });
    assert!(starts);
    assert_eq!(
        revocation_teardown_deadline(armed, Some(effect), starts, bound),
        effect + bound
    );
}

/// Revoke `grant_id` and wait until both sockets close.
///
/// The five-second bound starts when the grant first shows as revoked,
/// which is the insert inside `revoke_share_grant`. Gossip after that
/// insert is inside the bound. A sample taken only when the call returns
/// cannot move the deadline later than the instant revoke was armed.
/// Whether the join handle has been consumed is not that return.
async fn await_revocation_teardown(
    bob: &Arc<x0x::Agent>,
    grant_id: [u8; 32],
    owner: x0x::identity::UserId,
    held_forward: &mut TcpStream,
    held_socks: &mut TcpStream,
) -> (std::io::Result<usize>, std::io::Result<usize>) {
    let bound = Duration::from_secs(5);
    let armed = std::time::Instant::now();
    let revocation_set = bob.revocation_set();
    let bob_for_revoke = Arc::clone(bob);
    let revoke_task = tokio::spawn(async move {
        bob_for_revoke
            .revoke_share_grant(grant_id, None)
            .await
            .expect("revoke grant")
    });
    tokio::pin!(revoke_task);

    let mut forward_buf = [0u8; 1];
    let mut socks_buf = [0u8; 1];
    let close_reads = async {
        let pair = tokio::join!(
            held_forward.read(&mut forward_buf),
            held_socks.read(&mut socks_buf),
        );
        (std::time::Instant::now(), pair)
    };
    tokio::pin!(close_reads);

    let mut effect_at = None;
    // Set only when the revoked bit is seen before `revoke_share_grant`
    // returns. `revoke_done` is the join handle, which biased `select`
    // can leave unconsumed after the task has finished.
    let mut effect_during_revoke = false;
    let mut closed = None;
    let mut revoke_done = false;

    loop {
        if effect_at.is_none()
            && revocation_set
                .read()
                .await
                .is_share_grant_revoked(&grant_id, &owner)
        {
            let seen = std::time::Instant::now();
            effect_at = Some(seen);
            effect_during_revoke = bound_starts_at_sample(RevokeSighting {
                task_finished: revoke_task.is_finished(),
                join_consumed: revoke_done,
            });
        }
        let deadline = revocation_teardown_deadline(armed, effect_at, effect_during_revoke, bound);
        if revoke_done && effect_at.is_none() {
            panic!("revoke_share_grant finished without the revocation taking effect");
        }
        if closed.is_some() && revoke_done && effect_at.is_some() {
            break;
        }
        if closed.is_none() && std::time::Instant::now() >= deadline {
            if effect_during_revoke {
                let effect = effect_at.expect("effect");
                panic!(
                    "forward and SOCKS still open {:?} after the revocation took effect",
                    effect.elapsed()
                );
            }
            panic!(
                "forward and SOCKS still open {:?} after revoke was armed",
                armed.elapsed()
            );
        }

        let wait = deadline.saturating_duration_since(std::time::Instant::now());
        let effect_unknown = effect_at.is_none();
        tokio::select! {
            biased;
            sample = &mut close_reads, if closed.is_none() => {
                closed = Some(sample);
            }
            joined = &mut revoke_task, if !revoke_done => {
                joined.expect("revoke task panicked");
                revoke_done = true;
            }
            // Poll the revoked bit while revoke is still inside publish.
            _ = tokio::time::sleep(Duration::from_millis(5)), if effect_unknown => {}
            _ = tokio::time::sleep(wait), if !effect_unknown && closed.is_none() => {}
        }
    }

    let effect = effect_at.expect("revocation effect");
    let (closed_at, (forward_closed, socks_closed)) = closed.expect("socket close");
    let deadline = revocation_teardown_deadline(armed, Some(effect), effect_during_revoke, bound);
    let started = if effect_during_revoke { effect } else { armed };
    assert!(
        closed_at <= deadline,
        "teardown {:?} after the bound started missed deadline {deadline:?}",
        closed_at.saturating_duration_since(started)
    );
    (forward_closed, socks_closed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback ShareGrant connect; binds UDP. Integration tailnet job."]
async fn share_grant_connect_reaches_forward_and_socks() {
    let dir = TempDir::new().unwrap();
    let alice = Arc::new(build_agent(&dir, "alice", None).await);
    let bob = Arc::new(build_agent(&dir, "bob", Some(UserKeypair::generate().unwrap())).await);
    link_pair(&alice, &bob).await;

    let allowed = spawn_probe().await;
    let denied = spawn_probe().await;
    assert_ne!(allowed.port, denied.port);
    // The grant lists only the allowed listener. Both ports are on the
    // grant ACL entry, so the other port is refused by the grant. These
    // ports stand in for :22 and :80; the test cannot bind privileged ports.
    let allowed_addr: SocketAddr = format!("127.0.0.1:{}", allowed.port).parse().unwrap();
    let denied_addr: SocketAddr = format!("127.0.0.1:{}", denied.port).parse().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner = bob.identity().user_keypair().expect("bob owner key");
    let grant = ShareGrant::sign(
        owner,
        [0x52; 32],
        Grantee::Agent(alice.agent_id()),
        vec![bob.agent_id()],
        vec![ShareCap::Connect {
            ports: vec![allowed.port],
        }],
        now.saturating_sub(60),
        now + 3_600,
    )
    .expect("sign grant");
    let store = Arc::new(ShareGrantStore::in_memory(bob.agent_id(), bob.user_id()));
    store.accept(grant.clone(), now).await.expect("store grant");
    bob.install_share_grant_store(store);
    let access = bob
        .share_grant_access(&alice.agent_id(), &alice.machine_id())
        .await;
    assert!(
        access.allows_connect_port(allowed.port),
        "issued grant must cover the allowed port: {access:?}"
    );
    assert!(
        !access.allows_connect_port(denied.port),
        "issued grant must not cover the other port: {access:?}"
    );

    let bob_fwd = forwarder(&bob, grant_policy(allowed_addr, denied_addr));
    let alice_fwd = forwarder(
        &alice,
        Arc::new(ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
        })),
    );
    let local_ok = alice_fwd
        .add_forward(x0x::forward::ForwardSpec {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_agent: bob.agent_id(),
            target_host: "127.0.0.1".into(),
            target_port: allowed.port,
        })
        .await
        .expect("forward to granted port");
    let echoed = forward_exchange(local_ok).await;
    let local_no = alice_fwd
        .add_forward(x0x::forward::ForwardSpec {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_agent: bob.agent_id(),
            target_host: "127.0.0.1".into(),
            target_port: denied.port,
        })
        .await
        .expect("forward to unganted port");
    let denied_forward = forward_exchange(local_no).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let connector = Arc::new(ForwardSocksConnector::new(Arc::clone(&alice_fwd)));
    let host = format!("{}.x0x", hex::encode(bob.agent_id().as_bytes()));
    let socks_no = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, denied.port, false),
    )
    .await;
    let socks_ok = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, allowed.port, true),
    )
    .await;

    // Live forward + SOCKS, then revoke. Slice 3 tears the open streams down.
    let mut held_forward = TcpStream::connect(local_ok).await.unwrap();
    held_forward.write_all(&[0x11]).await.unwrap();
    let mut fwd_ack = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(15),
        held_forward.read_exact(&mut fwd_ack),
    )
    .await
    .expect("held forward echo")
    .unwrap();
    assert_eq!(fwd_ack[0], 0x11, "held forward must echo before revoke");
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let (socks_client_res, socks_accepted) =
        tokio::join!(TcpStream::connect(socks_addr), socks_listener.accept());
    let mut held_socks = socks_client_res.unwrap();
    let (socks_server, _) = socks_accepted.unwrap();
    let socks_cancel = CancellationToken::new();
    let socks_denied = AtomicU64::new(0);
    let socks_handler = tokio::spawn({
        let connector = Arc::clone(&connector);
        async move {
            handle_tcp_client(
                socks_server,
                TOKEN,
                connector.as_ref(),
                &socks_denied,
                None,
                &socks_cancel,
            )
            .await
        }
    });
    let held_rep = socks_roundtrip(&mut held_socks, &host, allowed.port, true).await;
    assert_eq!(held_rep, 0x00, "held SOCKS tunnel must be up before revoke");
    // Both sockets must still carry a byte at this moment. A close or a
    // payload that arrived earlier must not satisfy the post-revoke read.
    held_forward
        .write_all(&[0x21])
        .await
        .expect("forward liveness write");
    held_socks
        .write_all(&[0x21])
        .await
        .expect("SOCKS liveness write");
    let mut forward_live = [0u8; 1];
    let mut socks_live = [0u8; 1];
    let (forward_live_read, socks_live_read) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                held_forward.read_exact(&mut forward_live),
                held_socks.read_exact(&mut socks_live),
            )
        })
        .await
        .expect("both tunnels must echo before revoke");
    forward_live_read.expect("forward closed before revoke");
    socks_live_read.expect("SOCKS closed before revoke");
    assert_eq!(forward_live[0], 0x21, "forward must echo before revoke");
    assert_eq!(socks_live[0], 0x21, "SOCKS must echo before revoke");
    let (forward_closed, socks_closed) = await_revocation_teardown(
        &bob,
        grant.grant_id,
        grant.owner,
        &mut held_forward,
        &mut held_socks,
    )
    .await;
    assert!(
        closed_by_teardown(&forward_closed),
        "forward after revoke must EOF or reset, got {forward_closed:?}"
    );
    assert!(
        closed_by_teardown(&socks_closed),
        "SOCKS after revoke must EOF or reset, got {socks_closed:?}"
    );
    let after_forward = forward_exchange(local_ok).await;
    let after_socks = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, allowed.port, false),
    )
    .await;
    drop(held_forward);
    drop(held_socks);
    let _ = socks_handler.await;

    let sink_accepts = denied.accepts.load(Ordering::SeqCst);
    let sink_bytes = denied.bytes.load(Ordering::SeqCst);
    let echo_bytes = allowed.bytes.load(Ordering::SeqCst);

    allowed.cancel.cancel();
    denied.cancel.cancel();
    bob_fwd.shutdown();
    alice_fwd.shutdown();
    alice.shutdown().await;
    bob.shutdown().await;

    assert_eq!(
        echoed.expect("granted forward must echo"),
        0x42,
        "forward to the granted port must carry a byte"
    );
    assert!(
        denied_forward.is_err(),
        "forward to the unganted port must not echo: {denied_forward:?}"
    );
    assert_eq!(
        socks_no.expect("socks deny finished"),
        0x02,
        "SOCKS to the unganted port must be REP_NOT_ALLOWED"
    );
    assert_eq!(
        socks_ok.expect("socks allow finished"),
        0x00,
        "SOCKS to the granted port must succeed"
    );
    assert_eq!(sink_accepts, 0, "unganted target accepted a connection");
    assert_eq!(sink_bytes, 0, "unganted target received bytes");
    assert!(
        echo_bytes >= 2,
        "forward and SOCKS must both have delivered a byte, got {echo_bytes}"
    );
    assert!(
        after_forward.is_err(),
        "forward after revoke must be denied: {after_forward:?}"
    );
    // Revoke empties `connect_ports`, so the stream gate drops the grantee
    // before the forwarder can write a connect-denied byte. SOCKS maps that
    // failed open to `0x04`. A forwarder denial while the grant is live is
    // `0x02`. Either reply is a denial; success is not.
    let after_rep = after_socks.expect("socks after revoke finished");
    assert!(
        after_rep == 0x02 || after_rep == 0x04,
        "SOCKS after revoke must be denied, got {after_rep:#x}"
    );
}
