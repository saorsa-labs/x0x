//! Isolated loopback regression for port-0 forwards listed and removed by their
//! bound address. Lives in an integration test target so `Integration (core)`
//! does not have to cold-compile the entire `--lib` unit-test binary (#2232).

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use x0x::connect::{ConnectDiagnostics, ConnectPolicy};
use x0x::forward::{ForwardService, ForwardSpec};
use x0x::identity::AgentId;

async fn wait_until_bindable(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpListener::bind(addr).await.is_ok() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("listener {addr} did not close within bounded wait");
}

#[tokio::test]
#[ignore = "binds loopback TCP listeners; run only in the isolated integration tier"]
async fn port_zero_forwards_are_listed_and_removed_by_bound_address() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let agent = Arc::new(
        x0x::Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_user_key_path(dir.path().join("user.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .build()
            .await
            .expect("offline agent build"),
    );
    let policy = Arc::new(ConnectPolicy::default());
    let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
    let service = ForwardService::new(agent.clone(), policy, diagnostics, true)
        .expect("forward acceptor registration");
    let peer = AgentId([7; 32]);
    let spec = |peer_agent| ForwardSpec {
        local_addr: "127.0.0.1:0".parse().expect("loopback address"),
        peer_agent,
        target_host: "127.0.0.1".to_string(),
        target_port: 9,
    };

    let first = service.add_forward(spec(peer)).await.expect("first bind");
    let second = service.add_forward(spec(peer)).await.expect("second bind");
    assert_ne!(first, second);
    assert!(first.port() != 0 && second.port() != 0);
    let listed = service.list_forwards();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|entry| entry.local_addr == first));
    assert!(listed.iter().any(|entry| entry.local_addr == second));

    assert!(service.remove_forward(first));
    assert!(!service.remove_forward(first));
    wait_until_bindable(first).await;
    assert_eq!(service.list_forwards().len(), 1);
    assert!(service.remove_forward(second));
    wait_until_bindable(second).await;
    assert!(service.list_forwards().is_empty());
    service.shutdown();
    agent.shutdown().await;
}
