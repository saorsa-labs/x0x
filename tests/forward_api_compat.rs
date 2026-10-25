//! The published `x0x::forward` Rust API stays source-compatible.
//!
//! An existing `ForwardSpec` literal must compile, `list_forwards` must
//! still return `Vec<ForwardSpec>`, and `resolve_name_for_forward` must
//! stay callable. `names::require_agent_target` and the five-argument
//! `cli::commands::forward::add` stay callable too. Name, machine pin,
//! and persistence live on `ForwardBinding` / `ForwardStatus`.

use std::sync::Arc;

use x0x::connect::{ConnectDiagnostics, ConnectPolicy};
use x0x::forward::{ForwardService, ForwardSpec};
use x0x::identity::AgentId;

#[tokio::test]
async fn old_forward_spec_literal_and_fns_still_compile() {
    let spec = ForwardSpec {
        local_addr: "127.0.0.1:0".parse().expect("loopback"),
        peer_agent: AgentId([1; 32]),
        target_host: "127.0.0.1".to_string(),
        target_port: 7,
    };

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
            .expect("offline agent"),
    );
    let policy = Arc::new(ConnectPolicy::default());
    let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
    let service =
        ForwardService::new(Arc::clone(&agent), policy, diagnostics, true).expect("forwarder");

    let before: Vec<ForwardSpec> = service.list_forwards();
    assert!(before.is_empty());

    let bound = service
        .add_forward(spec.clone())
        .await
        .expect("old add_forward");
    let listed: Vec<ForwardSpec> = service.list_forwards();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].local_addr, bound);
    assert_eq!(listed[0].peer_agent, spec.peer_agent);
    assert_eq!(listed[0].target_host, spec.target_host);
    assert_eq!(listed[0].target_port, spec.target_port);

    let status = service.list_forward_status();
    assert_eq!(status.len(), 1);
    assert!(status[0].error.is_none());
    assert!(!status[0].binding.persistent);
    assert!(status[0].binding.pinned_machine.is_none());

    let names = x0x::names::NameStore::in_memory();
    let name = x0x::names::NameRef::parse("agent:compat.me").expect("name");
    #[allow(deprecated)]
    let resolved = agent.resolve_name_for_forward(&names, None, &name).await;
    assert!(resolved.is_err(), "the old helper still runs: {resolved:?}");

    let agent_resolved = x0x::names::Resolved {
        name: "agent:compat.me".to_string(),
        kind: x0x::names::NameKind::Agent,
        owner: x0x::identity::UserId([4; 32]),
        agent_id: Some(AgentId([1; 32])),
        machine_id: None,
        newly_pinned: false,
    };
    #[allow(deprecated)]
    let kept = x0x::names::require_agent_target(&agent_resolved, &name).expect("old agent target");
    assert_eq!(kept, AgentId([1; 32]));
    let machine_name = x0x::names::NameRef::parse("machine:compat.me").expect("machine name");
    let machine_resolved = x0x::names::Resolved {
        name: "machine:compat.me".to_string(),
        kind: x0x::names::NameKind::Machine,
        owner: x0x::identity::UserId([4; 32]),
        agent_id: Some(AgentId([1; 32])),
        machine_id: Some(x0x::identity::MachineId([5; 32])),
        newly_pinned: false,
    };
    #[allow(deprecated)]
    let refused = x0x::names::require_agent_target(&machine_resolved, &machine_name)
        .expect_err("old helper still refuses a machine");
    assert_eq!(refused.code(), "machine_target_unsupported");

    let client = x0x::cli::DaemonClient::new(
        Some("forward-api-compat"),
        Some("http://127.0.0.1:9"),
        x0x::cli::OutputFormat::Json,
    )
    .expect("client")
    .dump_requests(true);
    x0x::cli::commands::forward::add(&client, "127.0.0.1:9", "ab", "127.0.0.1", 7)
        .await
        .expect("old five-argument add");

    service.shutdown();
    agent.shutdown().await;
}
