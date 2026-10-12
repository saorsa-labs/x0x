//! #1241 / D197: real streams, production admission/dispatch/Hello verification.
//! Execute only in the Linux network-isolation harness. No gossip is started.

use super::*;
use crate::{
    contacts::TrustLevel,
    peer_evidence::{PeerEvidenceStore, RuntimePolicy},
    streams::{StreamAccept, StreamAcceptor},
    Agent,
};
use futures::FutureExt;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    BeforePrefixRefused,
    ProtocolRefused,
    ApplicationDelivered,
    HelloVerified,
    HelloRefused,
}

struct Fixture {
    _dir: tempfile::TempDir,
    _fabric: Option<Arc<crate::network::sim::SimFabric>>,
    initiator: Agent,
    responder: Agent,
    context: Arc<Context>,
    policy: Arc<RuntimePolicy>,
    incoming: Arc<StreamAccept>,
    evidence_acceptor: StreamAcceptor,
    app_acceptor: StreamAcceptor,
}

impl Fixture {
    async fn new(related: bool, discovered: bool) -> Self {
        Self::new_with_load(related, discovered, true).await
    }

    async fn new_with_load(related: bool, discovered: bool, loaded: bool) -> Self {
        Self::new_with_transport(related, discovered, loaded, false).await
    }

    async fn new_with_transport(
        related: bool,
        discovered: bool,
        loaded: bool,
        simulated: bool,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        // A plane id allows only [A-Za-z0-9._-]; use the tempdir's own name.
        let plane = format!(
            "s1-{}",
            dir.path()
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
                .trim_start_matches('.')
        );
        let fabric = simulated.then(|| {
            let fabric = crate::network::sim::SimFabric::new(1207);
            crate::network::sim::register(&plane, &fabric);
            fabric
        });
        let mut agents = Vec::new();
        for name in ["initiator", "responder"] {
            let path = dir.path().join(name);
            std::fs::create_dir_all(&path).unwrap();
            agents.push(
                Agent::builder()
                    .with_identity_dir(&path)
                    .with_machine_key(path.join("machine.key"))
                    .with_agent_key_path(path.join("agent.key"))
                    .with_user_key_path(path.join("user.key"))
                    .with_agent_cert_path(path.join("agent.cert"))
                    .with_contact_store_path(path.join("contacts.json"))
                    .with_peer_cache_disabled()
                    .with_network_config(crate::network::NetworkConfig {
                        bind_addr: Some(
                            if simulated {
                                if name == "initiator" {
                                    "198.18.0.1:5483"
                                } else {
                                    "198.18.0.2:5483"
                                }
                            } else {
                                "127.0.0.1:0"
                            }
                            .parse()
                            .unwrap(),
                        ),
                        network_id: simulated.then(|| plane.clone()),
                        bootstrap_nodes: Vec::new(),
                        mdns_enabled: false,
                        port_mapping_enabled: false,
                        ..Default::default()
                    })
                    .build()
                    .await
                    .unwrap(),
            );
        }
        let responder = agents.pop().unwrap();
        let initiator = agents.pop().unwrap();
        let peer = initiator.agent_id();
        let local = responder.agent_id();
        if discovered {
            let announced_at = dm_capability::now_unix_ms() / 1000;
            // ADR 0115 §2: a discovered peer's class A announcement records
            // its announced binding (never the authenticated store).
            responder
                .announced_machine_bindings
                .write()
                .await
                .record_announcement(peer, initiator.machine_id(), announced_at, None, None);
            let mut entry = crate::discovered_agent_fixture(1, announced_at, &[], None);
            entry.agent_id = peer;
            entry.machine_id = initiator.machine_id();
            entry.agent_public_key = initiator
                .identity
                .agent_keypair()
                .public_key()
                .as_bytes()
                .to_vec();
            entry.machine_public_key = initiator
                .identity
                .machine_keypair()
                .public_key()
                .as_bytes()
                .to_vec();
            responder
                .identity_discovery_cache
                .write()
                .await
                .insert(peer, entry);
        }
        let policy = Arc::new(RuntimePolicy::new(
            local,
            responder.owner_trust.clone(),
            Arc::clone(&responder.revocation_set),
        ));
        // Same policy adapter as named groups: both agents occupy one active
        // roster. Neither agent gets a contact, owner certificate, or grant.
        let roster = if related {
            vec![local, peer]
        } else {
            vec![local]
        };
        policy.set_groups(Arc::new(move |agent| {
            Some(roster.contains(&local) && roster.contains(&agent))
        }));
        let runtime = Arc::clone(responder.peer_evidence());
        responder.owner_trust.install_evidence(&runtime);
        if loaded {
            runtime.start(
                dir.path().join("evidence"),
                Default::default(),
                policy.clone(),
                Arc::clone(&responder.capability_store.evidence_wire),
            );
            assert!(runtime.wait(0).await, "evidence store must finish loading");
            assert_eq!(
                runtime.store().unwrap().related(
                    peer,
                    initiator.machine_id(),
                    None,
                    dm_capability::now_unix_ms(),
                ),
                related,
            );
        }
        assert!(responder.contact_store.read().await.get(&peer).is_none());
        assert_eq!(
            responder.contact_store.read().await.trust_level(&peer),
            TrustLevel::Unknown,
        );
        assert_eq!(
            responder
                .owner_trust
                .evaluate_pair(
                    &responder.contact_store,
                    &responder.identity_discovery_cache,
                    &responder.revocation_set,
                    &peer,
                    &initiator.machine_id(),
                )
                .await
                .decision,
            crate::trust::TrustDecision::Unknown,
            "the roster must not silently promote ordinary stream trust",
        );
        let context = Arc::new(Context {
            bindings: Arc::clone(&responder.authenticated_machine_bindings),
            runtime,
            capture: Arc::clone(&responder.capability_store.evidence_wire),
            network: Arc::clone(responder.network().unwrap()),
            identity: Arc::clone(&responder.identity),
            template: responder.build_announcement(false, false).unwrap(),
            own_cert: Arc::clone(&responder.own_cert_pair),
            capabilities: Arc::clone(&responder.dm_capabilities_tx),
            caps: Arc::clone(&responder.capability_store),
            discovery: Arc::clone(&responder.identity_discovery_cache),
            machines: Arc::clone(&responder.machine_discovery_cache),
            owner: responder.owner_trust.clone(),
            revoked: Arc::clone(&responder.revocation_set),
        });
        let incoming = Arc::new(StreamAccept::new(8));
        let evidence_acceptor = incoming.register(StreamProtocol::EvidenceV1).unwrap();
        let app_acceptor = incoming.register(StreamProtocol::SocksV1).unwrap();
        let address = responder.network().unwrap().bound_addr().await.unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(10),
            initiator.network().unwrap().connect_addr(address),
        )
        .await
        .expect("loopback connection timeout")
        .expect("loopback connection");
        assert_eq!(connected.0, responder.machine_id().0);
        Self {
            _dir: dir,
            _fabric: fabric,
            initiator,
            responder,
            context,
            policy,
            incoming,
            evidence_acceptor,
            app_acceptor,
        }
    }

    fn store(&self) -> Arc<PeerEvidenceStore> {
        self.context.runtime.store().unwrap()
    }

    fn hello(&self) -> Hello {
        mint_hello(
            &self.initiator.identity,
            self.initiator.build_announcement(false, false).unwrap(),
            &self.initiator.own_cert_pair,
            crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]),
            None,
            false,
        )
        .unwrap()
    }

    async fn exchange(&mut self, protocol: StreamProtocol, hello: &Hello) -> Outcome {
        self.exchange_after_admission(protocol, hello, None).await
    }

    async fn exchange_after_admission(
        &mut self,
        protocol: StreamProtocol,
        hello: &Hello,
        denial: Option<Denial>,
    ) -> Outcome {
        let body = codec().serialize(hello).unwrap();
        let (mut send, mut reply) = tokio::time::timeout(
            Duration::from_secs(10),
            self.initiator
                .network()
                .unwrap()
                .open_bi(&ant_quic::PeerId(self.responder.machine_id().0)),
        )
        .await
        .expect("open timeout")
        .expect("open stream");
        // Raw transport is deliberate: EvidenceV1 does not use the public
        // application opener's outbound trust gate (see Context::exchange).
        send.write_u8(protocol.as_u8()).await.unwrap();
        write_message(
            &mut send,
            &Limits::default(),
            self.responder.machine_id(),
            HELLO,
            &body,
        )
        .await
        .unwrap();
        let (peer, send, recv) = tokio::time::timeout(
            Duration::from_secs(10),
            self.responder.network().unwrap().accept_bi(),
        )
        .await
        .expect("transport must deliver stream before trust is evaluated")
        .expect("accept stream");
        assert_eq!(peer.0, self.initiator.machine_id().0);
        let r = &self.responder;
        let Some(admission) = Agent::admit_stream_before_prefix(
            &r.identity_discovery_cache,
            &r.contact_store,
            &r.revocation_set,
            &r.move_state,
            &r.connect_policy,
            &r.owner_trust,
            &self.initiator.machine_id(),
            &self.context.runtime.wire_limits,
        )
        .await
        else {
            return Outcome::BeforePrefixRefused;
        };
        if let Some(denial) = denial {
            self.deny(denial).await;
        }
        Agent::dispatch_admitted_stream(
            Arc::clone(&self.incoming),
            Arc::clone(&r.identity_discovery_cache),
            Arc::clone(&r.contact_store),
            Arc::clone(&r.revocation_set),
            Arc::clone(&r.move_state),
            Arc::clone(&r.connect_policy),
            r.owner_trust.clone(),
            Arc::clone(&self.context.runtime),
            admission,
            self.initiator.machine_id(),
            send,
            recv,
        )
        .await;
        assert!(
            self.incoming.receiver().lock().await.try_recv().is_err(),
            "neither selected protocol may leak into the default channel",
        );
        if self.app_acceptor.next().now_or_never().flatten().is_some() {
            return Outcome::ApplicationDelivered;
        }
        let Some(stream) = self.evidence_acceptor.next().now_or_never().flatten() else {
            return Outcome::ProtocolRefused;
        };
        assert!(stream.evidence_lease.is_some(), "bounded admission lease");
        Arc::clone(&self.context).accept(stream).await;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            read_message(&mut reply, &Limits::default()),
        )
        .await
        .expect("Hello must be answered or reset, not left pending");
        match response {
            Ok((ACK | HELLO, _)) => Outcome::HelloVerified,
            Err(_) => Outcome::HelloRefused,
            other => panic!("unexpected Hello response: {other:?}"),
        }
    }

    async fn shutdown(&self) {
        self.initiator.network().unwrap().shutdown().await;
        self.responder.network().unwrap().shutdown().await;
    }
}

#[tokio::test]
async fn issue1241_unknown_group_peer_evidence_hello_is_verified_and_stored() {
    let mut f = Fixture::new(true, true).await;
    let hello = f.hello();
    let now = dm_capability::now_unix_ms();
    assert!(f
        .store()
        .usable(f.initiator.agent_id(), f.initiator.machine_id(), now)
        .is_none());
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
    f.shutdown().await;
    assert_eq!(
        outcome,
        Outcome::HelloVerified,
        "D197: discovery must not prevent an Unknown group peer's EvidenceV1 Hello"
    );
    let view = f
        .store()
        .usable(
            f.initiator.agent_id(),
            f.initiator.machine_id(),
            dm_capability::now_unix_ms(),
        )
        .expect("verified relationship evidence stored");
    assert_eq!(view.announcement.agent_id, f.initiator.agent_id());
    assert_eq!(view.announcement.machine_id, f.initiator.machine_id());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        1
    );
    assert!(f
        .responder
        .contact_store
        .read()
        .await
        .get(&f.initiator.agent_id())
        .is_none());
}

#[tokio::test]
async fn issue1241_blocked_group_peer_evidence_is_refused() {
    let mut f = Fixture::new(true, true).await;
    f.responder
        .contact_store
        .write()
        .await
        .set_trust(&f.initiator.agent_id(), TrustLevel::Blocked);
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &f.hello()).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::BeforePrefixRefused);
    assert!(f
        .store()
        .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
        .is_none());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        0
    );
}

#[tokio::test]
async fn issue1241_stranger_evidence_keeps_current_admission_and_ttl_only_storage() {
    for discovered in [false, true] {
        let mut f = Fixture::new(false, discovered).await;
        let hello = f.hello();
        let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
        f.shutdown().await;
        assert_eq!(
            outcome,
            if discovered {
                Outcome::BeforePrefixRefused
            } else {
                Outcome::HelloVerified
            }
        );
        let now = dm_capability::now_unix_ms();
        assert!(
            f.store()
                .usable_agent(f.initiator.agent_id(), now)
                .is_none(),
            "strangers never gain persisted authority"
        );
        assert_eq!(
            f.context.capture.get(f.initiator.agent_id(), true, now),
            (!discovered).then_some(hello.announcement)
        );
        assert_eq!(
            f.context.capture.get(f.initiator.agent_id(), false, now),
            (!discovered).then_some(hello.advert)
        );
    }
}

#[tokio::test]
async fn issue1241_unknown_group_peer_non_evidence_stream_stays_gated() {
    for protocol in [
        StreamProtocol::ForwardV1,
        StreamProtocol::SocksV1,
        StreamProtocol::ForwardV2,
        StreamProtocol::WebRtcV1,
        StreamProtocol::SyncV1,
    ] {
        let mut f = Fixture::new(true, true).await;
        if protocol != StreamProtocol::SocksV1 {
            drop(f.app_acceptor);
            f.app_acceptor = f.incoming.register(protocol).unwrap();
        }
        let outcome = f.exchange(protocol, &f.hello()).await;
        f.responder
            .contact_store
            .write()
            .await
            .set_trust(&f.initiator.agent_id(), TrustLevel::Trusted);
        let trusted = f.exchange(protocol, &f.hello()).await;
        f.shutdown().await;
        assert!(
            matches!(
                outcome,
                Outcome::BeforePrefixRefused | Outcome::ProtocolRefused
            ),
            "Unknown group peer must not reach an application acceptor: {outcome:?}"
        );
        assert_eq!(
            f.context.runtime.diagnostics()["evidence_hello_received"],
            0
        );
        assert_eq!(
            trusted,
            Outcome::ApplicationDelivered,
            "live application acceptor control"
        );
    }
}

#[tokio::test]
async fn issue1241_admitted_group_peer_forged_hello_is_not_ingested() {
    let mut f = Fixture::new(true, true).await;
    // Trusted here so this independent verification control reaches the body
    // on both the old and fixed code; the Unknown admission test is separate.
    f.responder
        .contact_store
        .write()
        .await
        .set_trust(&f.initiator.agent_id(), TrustLevel::Trusted);
    let mut hello = f.hello();
    let mut announcement = announce_v3::deserialize_v3(&hello.announcement).unwrap();
    announcement.announced_at -= 1; // well-formed and fresh, invalid signature
    hello.announcement = announce_v3::serialize_v3(&announcement).unwrap();
    assert!(decode::parts(&hello.announcement, &hello.advert, None).is_ok());
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &hello).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::HelloRefused);
    assert!(f
        .store()
        .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
        .is_none());
    assert!(f
        .context
        .capture
        .get(f.initiator.agent_id(), true, dm_capability::now_unix_ms())
        .is_none());
    assert_eq!(
        f.context.runtime.diagnostics()["evidence_hello_received"],
        0
    );
    assert_eq!(f.context.runtime.diagnostics()["evidence_hello_refused"], 1);
}

#[derive(Clone, Copy, Debug)]
enum Denial {
    Blocked,
    Known,
    MachinePin,
    AgentRevoked,
    MachineRevoked,
    BindingRevoked,
    PlacementMoved,
    Expired,
    Acl,
    CoResidentBlocked,
    RelationshipRemoved,
    DiscoveryRemoved,
}

impl Fixture {
    async fn deny(&self, denial: Denial) {
        use crate::revocation::{RevocationRecord, RevokedSubject};
        let r = &self.responder;
        let agent = self.initiator.agent_id();
        let machine = self.initiator.machine_id();
        match denial {
            Denial::Blocked | Denial::Known | Denial::MachinePin => {
                let mut contacts = r.contact_store.write().await;
                contacts.set_trust(
                    &agent,
                    match denial {
                        Denial::Blocked => TrustLevel::Blocked,
                        Denial::Known => TrustLevel::Known,
                        _ => TrustLevel::Unknown,
                    },
                );
                if matches!(denial, Denial::MachinePin) {
                    contacts.set_identity_type(&agent, crate::contacts::IdentityType::Pinned);
                }
            }
            Denial::AgentRevoked | Denial::MachineRevoked => {
                let (subject, public, secret) = if matches!(denial, Denial::AgentRevoked) {
                    (
                        RevokedSubject::Agent(agent),
                        self.initiator.identity.agent_keypair().public_key(),
                        self.initiator.identity.agent_keypair().secret_key(),
                    )
                } else {
                    (
                        RevokedSubject::Machine(machine),
                        self.initiator.identity.machine_keypair().public_key(),
                        self.initiator.identity.machine_keypair().secret_key(),
                    )
                };
                let record = RevocationRecord::sign(
                    subject,
                    public,
                    secret,
                    dm_capability::now_unix_ms() / 1000,
                    None,
                )
                .unwrap();
                r.revocation_set
                    .write()
                    .await
                    .verify_and_insert(record, None)
                    .unwrap();
            }
            Denial::BindingRevoked => {
                r.revocation_set.write().await.union_bundle_retired(&[
                    crate::revocation::AgentMachineBinding {
                        agent,
                        machine,
                        move_epoch: 1,
                    },
                ]);
            }
            Denial::PlacementMoved => {
                let owner = crate::identity::UserKeypair::generate().unwrap();
                let record = crate::key_move::PlacementRecord::sign(
                    agent,
                    owner.public_key().as_bytes(),
                    crate::key_move::Placement::Pinned(MachineId([99; 32])),
                    1,
                    dm_capability::now_unix_ms() / 1000,
                    owner.secret_key(),
                )
                .unwrap();
                r.move_state
                    .write()
                    .await
                    .cache_placement(
                        record,
                        crate::key_move::PlacementAuthority::local_owner(&owner),
                    )
                    .unwrap();
            }
            Denial::Expired => {
                r.identity_discovery_cache
                    .write()
                    .await
                    .get_mut(&agent)
                    .unwrap()
                    .cert_not_after = Some(1);
            }
            Denial::Acl => {
                r.set_connect_policy(Arc::new(crate::connect::ConnectPolicy::Enabled(
                    crate::connect::ConnectAcl {
                        loaded_from: "/test".into(),
                        loaded_at_unix_ms: 0,
                        allow: Vec::new(),
                        owner_allow: Vec::new(),
                        grant_allow: Vec::new(),
                    },
                )));
            }
            Denial::CoResidentBlocked => {
                let other = AgentId([255; 32]);
                let mut entry = r.identity_discovery_cache.read().await[&agent].clone();
                entry.agent_id = other;
                r.identity_discovery_cache
                    .write()
                    .await
                    .insert(other, entry);
                r.contact_store
                    .write()
                    .await
                    .set_trust(&other, TrustLevel::Blocked);
            }
            Denial::RelationshipRemoved => self.policy.set_groups(Arc::new(|_| Some(false))),
            Denial::DiscoveryRemoved => {
                r.identity_discovery_cache.write().await.clear();
            }
        }
    }
}

#[tokio::test]
async fn issue1241_evidence_exception_preserves_and_rechecks_denials() {
    for denial in [
        Denial::Blocked,
        Denial::Known,
        Denial::MachinePin,
        Denial::AgentRevoked,
        Denial::MachineRevoked,
        Denial::BindingRevoked,
        Denial::PlacementMoved,
        Denial::Expired,
        Denial::Acl,
        Denial::CoResidentBlocked,
        Denial::RelationshipRemoved,
        Denial::DiscoveryRemoved,
    ] {
        for after_prefix_admission in [false, true] {
            // No discovery has its existing stranger path; test its removal
            // only AFTER admission as a known Unknown relationship peer.
            if !after_prefix_admission && matches!(denial, Denial::DiscoveryRemoved) {
                continue;
            }
            let mut f = Fixture::new(true, true).await;
            if !after_prefix_admission {
                f.deny(denial).await;
            }
            let outcome = f
                .exchange_after_admission(
                    StreamProtocol::EvidenceV1,
                    &f.hello(),
                    after_prefix_admission.then_some(denial),
                )
                .await;
            f.shutdown().await;
            assert_eq!(
                outcome,
                if after_prefix_admission {
                    Outcome::ProtocolRefused
                } else {
                    Outcome::BeforePrefixRefused
                },
                "{denial:?}, after admission: {after_prefix_admission}"
            );
            assert_eq!(
                f.context.runtime.diagnostics()["evidence_hello_received"],
                0
            );
            assert!(f
                .store()
                .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
                .is_none());
        }
    }
}

#[tokio::test]
async fn issue1241_unknown_relationship_prefix_slots_are_bounded_and_released() {
    let f = Fixture::new(true, true).await;
    let r = &f.responder;
    let machine = f.initiator.machine_id();
    let admit = || {
        Agent::admit_stream_before_prefix(
            &r.identity_discovery_cache,
            &r.contact_store,
            &r.revocation_set,
            &r.move_state,
            &r.connect_policy,
            &r.owner_trust,
            &machine,
            &f.context.runtime.wire_limits,
        )
    };
    let first = admit().await.expect("first prefix slot");
    assert!(first.agents.is_none() && first.prefix.is_some() && first.evidence_only);
    let second = admit().await.expect("second prefix slot");
    assert!(
        admit().await.is_none(),
        "third same-machine prefix must reset"
    );
    drop(first);
    let replacement = admit().await.expect("dropped slot is reusable");
    let others: Vec<_> = (0..30)
        .map(|id| {
            f.context
                .runtime
                .wire_limits
                .admit_prefix(MachineId([id; 32]))
                .unwrap()
        })
        .collect();
    assert!(f
        .context
        .runtime
        .wire_limits
        .admit_prefix(MachineId([31; 32]))
        .is_none());
    drop(others);
    drop(second);
    drop(replacement);
    assert!(admit().await.is_some());
    f.shutdown().await;
}

#[tokio::test]
async fn issue1241_roster_alone_does_not_trigger_outbound_hello() {
    let mut f = Fixture::new(true, true).await;
    let machine = f.initiator.machine_id();
    assert!(
        f.context.related(machine).await,
        "fresh discovery resolves the roster peer"
    );
    f.responder.identity_discovery_cache.write().await.clear();
    assert!(f.store().related(
        f.initiator.agent_id(),
        machine,
        None,
        dm_capability::now_unix_ms()
    ));
    assert!(
        !f.context.related(machine).await,
        "a roster agent without a machine mapping cannot trigger Hello"
    );
    let outcome = f.exchange(StreamProtocol::EvidenceV1, &f.hello()).await;
    f.shutdown().await;
    assert_eq!(outcome, Outcome::HelloVerified);
    assert!(
        f.context.related(machine).await,
        "an inbound verified Hello supplies the missing evidence"
    );
    assert!(
        f.responder
            .authenticated_machine_bindings
            .read()
            .await
            .peek(&f.initiator.agent_id())
            .is_none(),
        "Hello supplies evidence, not a live binding-cache insertion"
    );
    assert!(f
        .store()
        .usable(
            f.initiator.agent_id(),
            machine,
            dm_capability::now_unix_ms()
        )
        .is_some());
}

// Capture the same per-runtime opt-in as daemon startup. This neither mutates
// process environment nor changes another test's agent.
fn start_ready_wire(agent: &Agent, enabled: bool) {
    agent
        .peer_evidence()
        .wire_limits
        .ready_hello
        .store(enabled, std::sync::atomic::Ordering::Release);
    agent.start_evidence_wire();
}

impl Fixture {
    async fn ready_wire(&self, enabled: bool, existing: bool, publishable: bool) {
        let peer = self.responder.agent_id();
        let runtime = self.initiator.peer_evidence();
        self.initiator.owner_trust.install_evidence(runtime);
        let policy = Arc::new(RuntimePolicy::new(
            self.initiator.agent_id(),
            self.initiator.owner_trust.clone(),
            Arc::clone(&self.initiator.revocation_set),
        ));
        policy.set_groups(Arc::new(move |agent| Some(agent == peer)));
        runtime.start(
            self._dir.path().join("initiator-evidence"),
            Default::default(),
            policy,
            Arc::clone(&self.initiator.capability_store.evidence_wire),
        );
        assert!(runtime.wait(0).await);
        self.initiator
            .dm_capabilities_tx
            .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]));
        if publishable {
            self.publish_ready();
        }
        // Only the responder runs the scheduler under test. The initiator
        // receives and replies using the production ingress and Hello paths.
        start_ready_wire(&self.initiator, false);
        self.initiator.start_stream_accept_loop();
        self.responder.start_stream_accept_loop();
        if !existing {
            self.initiator
                .network()
                .unwrap()
                .disconnect(&ant_quic::PeerId(self.responder.machine_id().0))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        start_ready_wire(&self.responder, enabled);
        if !existing {
            let address = self
                .responder
                .network()
                .unwrap()
                .bound_addr()
                .await
                .unwrap();
            self.initiator
                .network()
                .unwrap()
                .connect_addr(address)
                .await
                .unwrap();
        }
        // Let the original connect job finish, including its five-second
        // advert timeout. No reconnect or identity publication follows this.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(self.sent(), 0, "setup must not send an early Hello");
    }

    fn publish_ready(&self) {
        self.responder
            .dm_capabilities_tx
            .send_replace(crate::dm::DmCapabilities::v1_gossip_ready(vec![43; 1184]));
    }

    fn roster_ready(&self) {
        let peer = self.initiator.agent_id();
        self.policy
            .set_groups(Arc::new(move |agent| Some(agent == peer)));
    }

    fn sent(&self) -> u64 {
        self.context
            .runtime
            .wire_limits
            .counters
            .evidence_hello_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn one_exchange(&self) {
        let peer = self.initiator.agent_id();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if self
                    .context
                    .runtime
                    .usable_agent(peer, dm_capability::now_unix_ms())
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("late readiness must produce usable verified evidence without reconnect");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(self.sent(), 1, "one real outbound Hello");
        assert_eq!(
            self.initiator.peer_evidence().diagnostics()["evidence_hello_received"],
            1
        );
        assert_eq!(
            self.initiator.peer_evidence().diagnostics()["evidence_hello_sent"],
            1
        );
        assert!(self
            .initiator
            .peer_evidence()
            .usable_agent(self.responder.agent_id(), dm_capability::now_unix_ms(),)
            .is_some());
        assert!(
            self.responder
                .authenticated_machine_bindings
                .read()
                .await
                .peek(&peer)
                .is_none(),
            "evidence must not invent an authenticated binding"
        );
        self.initiator.shutdown_token.cancel();
        self.responder.shutdown_token.cancel();
        self.shutdown().await;
    }
}

async fn ready_order(mapping_first: bool, enabled: bool) {
    let f = Fixture::new(false, true).await;
    let entry = f
        .responder
        .identity_discovery_cache
        .write()
        .await
        .remove(&f.initiator.agent_id())
        .unwrap();
    f.ready_wire(enabled, false, true).await;
    if mapping_first {
        f.responder
            .identity_discovery_cache
            .write()
            .await
            .insert(entry.agent_id, entry.clone());
    } else {
        f.roster_ready();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(f.sent(), 0, "one prerequisite alone cannot authorize");
    if mapping_first {
        f.roster_ready();
    } else {
        f.responder
            .identity_discovery_cache
            .write()
            .await
            .insert(entry.agent_id, entry);
    }
    if enabled {
        f.one_exchange().await;
    } else {
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            f.sent(),
            0,
            "default off preserves the lost-trigger behavior"
        );
        f.initiator.shutdown_token.cancel();
        f.responder.shutdown_token.cancel();
        f.shutdown().await;
    }
}

#[tokio::test]
async fn issue1207_mapping_then_roster_sends_one_hello() {
    ready_order(true, true).await;
}

#[tokio::test]
async fn issue1207_roster_then_mapping_sends_one_hello() {
    ready_order(false, true).await;
}

#[tokio::test]
async fn issue1207_default_off_keeps_connect_only_behavior() {
    ready_order(true, false).await;
}

#[tokio::test]
async fn issue1207_connection_before_subscription_is_reconciled() {
    let f = Fixture::new(false, true).await;
    f.ready_wire(true, true, true).await;
    f.roster_ready();
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_local_capability_ready_after_connect_timeout() {
    let f = Fixture::new(false, true).await;
    f.ready_wire(true, false, false).await;
    f.roster_ready();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(f.sent(), 0);
    f.publish_ready();
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_busy_roster_and_change_flood_coalesce() {
    let f = Fixture::new(false, true).await;
    let roster = Arc::new(tokio::sync::RwLock::new(false));
    let live = Arc::clone(&roster);
    f.policy
        .set_groups(Arc::new(move |_| live.try_read().ok().map(|r| *r)));
    let mut guard = roster.write().await;
    f.ready_wire(true, false, true).await;
    *guard = true;
    drop(guard);
    for _ in 0..10_000 {
        *roster.write().await = true;
        f.publish_ready();
    }
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_sim_transport_late_readiness_exchanges_real_hello() {
    let f = Fixture::new_with_transport(false, true, true, true).await;
    assert!(
        f.responder
            .network()
            .unwrap()
            .peer_link_conn(&ant_quic::PeerId(f.initiator.machine_id().0))
            .await
            .is_err(),
        "this control must use Sim, with no QUIC handle"
    );
    f.ready_wire(true, true, true).await;
    f.roster_ready();
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_late_readiness_preserves_denials() {
    for denial in [
        Denial::Blocked,
        Denial::CoResidentBlocked,
        Denial::AgentRevoked,
        Denial::MachineRevoked,
        Denial::BindingRevoked,
        Denial::PlacementMoved,
        Denial::Expired,
        Denial::RelationshipRemoved,
    ] {
        let f = Fixture::new(false, true).await;
        f.ready_wire(true, false, true).await;
        if matches!(denial, Denial::RelationshipRemoved) {
            f.roster_ready();
            f.deny(denial).await;
        } else {
            f.deny(denial).await;
            f.roster_ready();
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(f.sent(), 0, "denial must prevent emission: {denial:?}");
        assert!(f
            .context
            .runtime
            .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
            .is_none());
        f.initiator.shutdown_token.cancel();
        f.responder.shutdown_token.cancel();
        f.shutdown().await;
    }
}

#[tokio::test]
async fn issue1207_unrelated_machine_never_sends() {
    let f = Fixture::new(false, true).await;
    f.publish_ready();
    let machine = f.initiator.machine_id();
    Arc::clone(&f.context).connect(machine, None, None).await;
    assert!(!f
        .context
        .runtime
        .wire_limits
        .state
        .lock()
        .unwrap()
        .machines
        .contains_key(&machine));
    f.ready_wire(true, true, true).await;
    for _ in 0..1000 {
        f.publish_ready();
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(f.sent(), 0);
    assert!(!f
        .context
        .runtime
        .wire_limits
        .state
        .lock()
        .unwrap()
        .machines
        .contains_key(&machine));
    f.initiator.shutdown_token.cancel();
    f.responder.shutdown_token.cancel();
    f.shutdown().await;
}

#[tokio::test]
async fn issue1207_evidence_load_ready_after_connect_timeout() {
    let f = Fixture::new_with_load(false, true, false).await;
    f.ready_wire(true, false, true).await;
    f.roster_ready();
    f.context.runtime.start(
        f._dir.path().join("late-evidence"),
        Default::default(),
        f.policy.clone(),
        Arc::clone(&f.responder.capability_store.evidence_wire),
    );
    assert!(f.context.runtime.wait(0).await);
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_peer_capability_becomes_ready_later() {
    let f = Fixture::new(false, true).await;
    let mut caps = crate::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry.bits = 0;
    assert!(f.responder.capability_store.insert(
        f.initiator.agent_id(),
        f.initiator.machine_id(),
        caps.clone(),
        dm_capability::now_unix_ms()
    ));
    f.ready_wire(true, false, true).await;
    f.roster_ready();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(f.sent(), 0);
    caps.application_registry = crate::dm::CapabilityRegistry::current();
    assert!(f.responder.capability_store.insert(
        f.initiator.agent_id(),
        f.initiator.machine_id(),
        caps,
        dm_capability::now_unix_ms()
    ));
    f.one_exchange().await;
}

#[tokio::test]
async fn issue1207_reset_and_ready_flood_never_repeat_attempt() {
    let f = Fixture::new(true, true).await;
    let network = Arc::clone(f.initiator.network().unwrap());
    let reset_peer = tokio::spawn(async move {
        let (_, send, mut recv) = network.accept_bi().await.unwrap();
        assert_eq!(
            recv.read_u8().await.unwrap(),
            StreamProtocol::EvidenceV1.as_u8()
        );
        let (kind, body) = read_message(&mut recv, &Limits::default()).await.unwrap();
        assert_eq!(kind, HELLO);
        decode::hello(&body)
            .unwrap()
            .into_record()
            .verify(dm_capability::now_unix_ms(), W_MS)
            .unwrap();
        // Refuse the actual exchange by resetting its reply stream.
        drop((send, recv));
    });
    f.initiator
        .network()
        .unwrap()
        .disconnect(&ant_quic::PeerId(f.responder.machine_id().0))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    f.publish_ready();
    start_ready_wire(&f.responder, true);
    let address = f.responder.network().unwrap().bound_addr().await.unwrap();
    f.initiator
        .network()
        .unwrap()
        .connect_addr(address)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(8), reset_peer)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..10_000 {
        f.publish_ready();
        f.roster_ready();
    }
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(
        f.sent(),
        1,
        "reset and floods never clear the actual attempt"
    );
    assert!(!f
        .context
        .runtime
        .wire_limits
        .begin_hello(f.initiator.machine_id(), true));
    assert!(f
        .context
        .runtime
        .usable_agent(f.initiator.agent_id(), dm_capability::now_unix_ms())
        .is_none());
    f.responder.shutdown_token.cancel();
    f.shutdown().await;
}

// BEGIN #1207 S1b RED tests and controls. Commit this block before the fix.
// The peer uses the real Sim transport and production EvidenceV1 bytes. It
// never runs an outgoing Hello scheduler, including after its cold restart.
#[derive(Clone, Copy)]
enum S1bReply {
    Ack,
    Reset,
    Refuse,
}

impl Fixture {
    fn s1b_generation(&self) -> u64 {
        self.responder
            .network()
            .unwrap()
            .try_connection_generation(&ant_quic::PeerId(self.initiator.machine_id().0))
            .unwrap()
            .unwrap()
    }

    fn s1b_expire_rate_gate(&self) {
        // Advance only the rate timestamp, never the attempted marker. This
        // avoids a minute of wall time without pausing durable-store workers.
        self.context
            .runtime
            .wire_limits
            .state
            .lock()
            .unwrap()
            .machines
            .get_mut(&self.initiator.machine_id())
            .unwrap()
            .hello_out = Some(Instant::now() - HELLO_INTERVAL);
    }

    async fn s1b_read_hello(&self, reply: S1bReply) {
        let (peer, mut send, mut recv) = tokio::time::timeout(
            Duration::from_secs(8),
            self.initiator.network().unwrap().accept_bi(),
        )
        .await
        .expect("new connection must receive a Hello")
        .unwrap();
        assert_eq!(peer.0, self.responder.machine_id().0);
        assert_eq!(
            recv.read_u8().await.unwrap(),
            StreamProtocol::EvidenceV1.as_u8()
        );
        let limits = Limits::default();
        let (kind, body) = read_message(&mut recv, &limits).await.unwrap();
        assert_eq!(kind, HELLO);
        let record = decode::hello(&body).unwrap().into_record();
        let verified = record.verify(dm_capability::now_unix_ms(), W_MS).unwrap();
        assert_eq!(verified.announcement.agent_id, self.responder.agent_id());
        assert_eq!(
            verified.announcement.machine_id,
            self.responder.machine_id()
        );
        match reply {
            S1bReply::Reset => {} // Drop the real reply stream.
            S1bReply::Ack | S1bReply::Refuse => {
                let (kind, body) = match reply {
                    S1bReply::Ack => (ACK, codec().serialize(&Option::<[u8; 32]>::None).unwrap()),
                    _ => (NOT_FOUND, Vec::new()),
                };
                write_message(&mut send, &limits, self.responder.machine_id(), kind, &body)
                    .await
                    .unwrap();
            }
        }
    }

    async fn s1b_first_attempt(&self, reply: S1bReply) {
        self.publish_ready();
        assert!(!self
            .context
            .runtime
            .wire_limits
            .ready_hello
            .load(std::sync::atomic::Ordering::Acquire));
        let ((), ()) = tokio::join!(
            Arc::clone(&self.context).connect(self.initiator.machine_id(), None, None),
            self.s1b_read_hello(reply),
        );
        assert_eq!(self.sent(), 1);
    }

    async fn s1b_restart_remote(&mut self) {
        let machine = self.initiator.machine_id();
        let agent = self.initiator.agent_id();
        let old_generation = self.s1b_generation();
        let network = self.initiator.network().unwrap();
        let config = network.config().clone();
        let mut events = self.responder.network().unwrap().subscribe();
        // Only B stops. A never calls disconnect and must not depend on a
        // synthetic PeerDisconnected event to release its old attempt.
        network.shutdown().await;
        assert_eq!(
            self.responder
                .network()
                .unwrap()
                .try_connection_generation(&ant_quic::PeerId(machine.0)),
            Ok(None)
        );
        let path = self._dir.path().join("initiator");
        self.initiator = Agent::builder()
            .with_identity_dir(&path)
            .with_machine_key(path.join("machine.key"))
            .with_agent_key_path(path.join("agent.key"))
            .with_user_key_path(path.join("user.key"))
            .with_agent_cert_path(path.join("agent.cert"))
            .with_contact_store_path(path.join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(config)
            .build()
            .await
            .unwrap();
        assert_eq!(self.initiator.machine_id(), machine);
        assert_eq!(self.initiator.agent_id(), agent);
        self.initiator
            .network()
            .unwrap()
            .connect_addr(
                self.responder
                    .network()
                    .unwrap()
                    .bound_addr()
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(self.s1b_generation() > old_generation);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.recv().await.unwrap() {
                    crate::network::NetworkEvent::PeerDisconnected { peer_id, .. }
                        if peer_id == machine.0 =>
                    {
                        panic!("remote restart must not emit A's local disconnect event");
                    }
                    crate::network::NetworkEvent::PeerConnected { peer_id, .. }
                        if peer_id == machine.0 =>
                    {
                        break
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
    }

    async fn s1b_no_more_hellos(&self) {
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                self.initiator.network().unwrap().accept_bi(),
            )
            .await
            .is_err(),
            "same connection must not send another Hello"
        );
    }
}

async fn s1b_restart_sends_once(enabled: bool) {
    let mut f = Fixture::new_with_transport(true, true, true, true).await;
    f.s1b_first_attempt(S1bReply::Ack).await;
    f.s1b_expire_rate_gate();
    start_ready_wire(&f.responder, enabled);
    if enabled {
        // Let S1 track the old generation before the remote replacement.
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
    f.s1b_restart_remote().await;
    f.s1b_read_hello(S1bReply::Ack).await;
    assert_eq!(f.sent(), 2);
    // Remove the cooldown as a possible explanation of the no-retry result.
    f.s1b_expire_rate_gate();
    for _ in 0..3 {
        Arc::clone(&f.context)
            .connect(f.initiator.machine_id(), None, None)
            .await;
    }
    f.s1b_no_more_hellos().await;
    assert_eq!(f.sent(), 2);
    f.responder.shutdown_token.cancel();
    f.shutdown().await;
}

#[tokio::test]
async fn issue1207_s1b_red_default_off_remote_restart_sends_one_new_hello() {
    s1b_restart_sends_once(false).await;
}

#[tokio::test]
async fn issue1207_s1b_ready_enabled_remote_restart_sends_one_new_hello() {
    s1b_restart_sends_once(true).await;
}

#[tokio::test]
async fn issue1207_s1b_default_off_reset_or_refusal_never_retries_same_connection() {
    for reply in [S1bReply::Reset, S1bReply::Refuse] {
        let f = Fixture::new_with_transport(true, true, true, true).await;
        let generation = f.s1b_generation();
        f.s1b_first_attempt(reply).await;
        f.s1b_expire_rate_gate();
        for _ in 0..3 {
            Arc::clone(&f.context)
                .connect(f.initiator.machine_id(), None, None)
                .await;
        }
        f.s1b_no_more_hellos().await;
        assert_eq!(f.s1b_generation(), generation);
        assert_eq!(f.sent(), 1);
        f.shutdown().await;
    }
}

#[tokio::test]
async fn issue1207_s1b_default_off_reconnect_keeps_machine_rate_gate_and_shares_replies() {
    let mut f = Fixture::new_with_transport(true, true, true, true).await;
    f.s1b_first_attempt(S1bReply::Ack).await;
    start_ready_wire(&f.responder, false);
    f.s1b_restart_remote().await;
    f.s1b_no_more_hellos().await;
    assert_eq!(
        f.sent(),
        1,
        "two connections inside 60 s share one Hello budget"
    );
    let hello = f.hello();
    assert_eq!(
        f.exchange(StreamProtocol::EvidenceV1, &hello).await,
        Outcome::HelloVerified
    );
    assert_eq!(
        f.sent(),
        1,
        "reply must be ACK inside the same machine rate window"
    );
    f.s1b_expire_rate_gate();
    // No flag-off timer may turn the unsent connect into a deferred attempt.
    f.s1b_no_more_hellos().await;
    assert_eq!(f.sent(), 1);
    f.responder.shutdown_token.cancel();
    f.shutdown().await;
}
#[tokio::test]
async fn issue1207_s1b_red_default_off_reply_after_remote_restart_carries_hello() {
    let mut f = Fixture::new_with_transport(true, true, true, true).await;
    f.s1b_first_attempt(S1bReply::Ack).await;
    f.s1b_expire_rate_gate();
    // Model S1 observing the old connection, then receiving a new-generation
    // reply before its next readiness pass.
    let mut connections = ReadyConnections::new(1);
    let jobs = WireJobs::default();
    let machine = f.initiator.machine_id();
    assert!(connections.insert(machine));
    connections.generation(
        machine,
        f.s1b_generation(),
        &jobs,
        &f.context.runtime.wire_limits,
    );
    // No scheduler: exercise the reply arriving before any connect job.
    f.s1b_restart_remote().await;
    let hello = f.hello();
    assert_eq!(
        f.exchange(StreamProtocol::EvidenceV1, &hello).await,
        Outcome::HelloVerified
    );
    assert_eq!(
        f.sent(),
        2,
        "new-generation reply must carry our Hello, not only ACK"
    );
    connections.generation(
        machine,
        f.s1b_generation(),
        &jobs,
        &f.context.runtime.wire_limits,
    );
    f.s1b_expire_rate_gate();
    Arc::clone(&f.context)
        .connect(f.initiator.machine_id(), None, None)
        .await;
    f.s1b_no_more_hellos().await;
    assert_eq!(
        f.sent(),
        2,
        "reply and connect share the connection attempt"
    );
    f.shutdown().await;
}
// END #1207 S1b RED tests and controls.

// Review round 1: control the real outgoing job at the stream-open boundary.
#[tokio::test]
async fn issue1207_s1b_default_off_replacement_around_open_does_not_spend_unsent_attempt() {
    for after_open in [false, true] {
        let mut f = Fixture::new_with_transport(true, true, true, true).await;
        f.publish_ready();
        let machine = f.initiator.machine_id();
        let old = f.s1b_generation();
        let pause = Arc::new(HelloOpenPause {
            after_open,
            ..Default::default()
        });
        *f.context
            .runtime
            .wire_limits
            .hello_open_pause
            .lock()
            .unwrap() = Some(Arc::clone(&pause));
        let job = tokio::spawn(Arc::clone(&f.context).connect(machine, None, None));
        tokio::time::timeout(DEADLINE, pause.reached.notified())
            .await
            .expect("g1 job must reach the real open boundary");
        assert_eq!(f.sent(), 0);
        assert_eq!(f.s1b_generation(), old);
        // In the reviewed fix the g1 job had already consumed here. No bytes
        // were sent, so superseding it must leave g2's attempt and rate free.
        f.s1b_restart_remote().await;
        *f.context
            .runtime
            .wire_limits
            .hello_open_pause
            .lock()
            .unwrap() = None;
        pause.resume.notify_one();
        tokio::time::timeout(DEADLINE, job).await.unwrap().unwrap();
        {
            let state = f.context.runtime.wire_limits.state.lock().unwrap();
            let budget = &state.machines[&machine];
            assert!(!budget.attempted, "unsent g1 must not consume an attempt");
            assert!(
                budget.hello_out.is_none(),
                "unsent g1 must not start 60 s gate"
            );
        }
        assert_eq!(f.sent(), 0);
        // No clock advance, marker edit, scheduler or retry can rescue g2.
        let ((), ()) = tokio::join!(
            Arc::clone(&f.context).connect(machine, None, None),
            f.s1b_read_hello(S1bReply::Ack),
        );
        assert_eq!(f.sent(), 1, "g2 receives exactly one verified Hello");
        f.s1b_expire_rate_gate();
        Arc::clone(&f.context).connect(machine, None, None).await;
        f.s1b_no_more_hellos().await;
        assert_eq!(f.sent(), 1);
        f.shutdown().await;
    }
}

#[tokio::test]
async fn issue1207_s1b_delayed_disconnect_cannot_rearm_live_generation() {
    let f = Fixture::new_with_transport(true, true, true, true).await;
    f.s1b_first_attempt(S1bReply::Ack).await;
    let machine = f.initiator.machine_id();
    let generation = f.s1b_generation();
    let limits = &f.context.runtime.wire_limits;
    limits.need_certificate(machine, f.initiator.agent_id(), [9; 32]);
    limits.disconnect(machine); // A delayed local event has no generation.
    assert!(limits.state.lock().unwrap().machines[&machine]
        .certificate
        .is_none());
    f.s1b_expire_rate_gate();
    Arc::clone(&f.context).connect(machine, None, None).await;
    f.s1b_no_more_hellos().await;
    assert_eq!(f.s1b_generation(), generation);
    assert_eq!(f.sent(), 1);
    f.shutdown().await;
}

#[test]
fn issue1207_s1b_older_promoted_generation_fails_closed_without_spending_budget() {
    let limits = Limits::default();
    let machine = MachineId([19; 32]);
    assert!(limits.begin_hello_on_connection(machine, true, Some(2)));
    let aged = Instant::now() - HELLO_INTERVAL;
    limits
        .state
        .lock()
        .unwrap()
        .machines
        .get_mut(&machine)
        .unwrap()
        .hello_out = Some(aged);
    limits.hello_connection(machine, 1);
    assert!(!limits.hello_candidate(machine, 1));
    assert!(!limits.begin_hello_on_connection(machine, true, Some(1)));
    {
        let state = limits.state.lock().unwrap();
        let budget = &state.machines[&machine];
        assert_eq!(budget.hello_generation, Some(2));
        assert!(budget.attempted);
        assert_eq!(budget.hello_out, Some(aged));
    }
    assert!(limits.begin_hello_on_connection(machine, true, Some(3)));
}

#[test]
fn issue1207_s1b_stale_attempts_allow_new_machine_without_evicting_active_budgets() {
    let limits = Arc::new(Limits::default());
    let machine = |id: usize| {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(id as u64).to_le_bytes());
        MachineId(bytes)
    };
    for id in 0..MACHINE_CAP {
        assert!(limits.begin_hello_on_connection(machine(id), true, Some(100)));
    }
    let lease = limits.admit(machine(0), true).unwrap();
    let job = limits.pin_machine(machine(1)).unwrap();
    let prefix = limits.admit_prefix(machine(2)).unwrap();
    assert!(limits.request(machine(4), true));
    {
        let now = Instant::now();
        let stale = now - HELLO_INTERVAL - Duration::from_secs(1);
        let mut state = limits.state.lock().unwrap();
        for budget in state.machines.values_mut() {
            budget.hello_out = Some(stale);
            budget.touched = Some(stale);
        }
        // Independent controls: outbound cooldown, inbound cooldown, and
        // recent non-Hello traffic must each survive table pressure.
        state.machines.get_mut(&machine(3)).unwrap().hello_out = Some(now);
        state.machines.get_mut(&machine(5)).unwrap().touched = Some(now);
        assert_eq!(state.machines.len(), MACHINE_CAP);
    }
    // The readiness pass observes the same live generation without evidence traffic.
    limits.hello_connection(machine(6), 100);
    // This untracked machine's connection is gone; its idle marker may be evicted.
    limits.disconnect(machine(7));
    let newcomer = machine(MACHINE_CAP);
    let new_lease = limits
        .admit(newcomer, true)
        .expect("stale attempts evicted");
    assert!(limits.begin_hello_on_connection(newcomer, true, Some(1)));
    {
        let state = limits.state.lock().unwrap();
        assert_eq!(state.machines.len(), 8);
        for id in 0..7 {
            let budget = &state.machines[&machine(id)];
            assert!(budget.attempted);
            assert_eq!(budget.hello_generation, Some(100));
        }
        assert!(!state.machines.contains_key(&machine(7)));
    }
    assert!(!limits.hello_pending(machine(6)));
    assert!(!limits.begin_hello_on_connection(machine(6), true, Some(100)));
    assert!(!limits.request(machine(4), true), "inbound gate retained");
    assert!(!limits.begin_hello_on_connection(machine(3), true, Some(101)));
    // Eviction forgets the old high-water marker. One new attempt is allowed,
    // but the shared 60-second gate still blocks even a newer generation.
    assert!(limits.begin_hello_on_connection(machine(7), true, Some(1)));
    assert!(!limits.begin_hello_on_connection(machine(7), true, Some(2)));
    drop((lease, job, prefix, new_lease));
    let state = limits.state.lock().unwrap();
    assert_eq!(state.machines[&machine(0)].open, 0);
    assert_eq!(state.machines[&machine(1)].jobs, 0);
    assert_eq!(state.machines[&machine(2)].jobs, 0);
}
