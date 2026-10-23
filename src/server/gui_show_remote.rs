//! Receive path for remote GUI show typed DMs (ADR 0083 slice 3).
//!
//! Owner trust runs before any body decode. Result and activity replies
//! are one attempt, with no retry. The handler starts each reply send and
//! returns, so one slow send does not hold the next message. A sender that
//! is not owner-trusted gets at most one refusal per minute.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::dm::DmSendConfig;
use crate::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion};
use crate::gui::remote::{
    activity_reply, classify_prefix, decode_show_result, ingress_activity, ingress_show,
    receive_action, ActivityIngress, DmClass, GuiActivityBody, GuiShowDmResult, ReceiveAction,
    ShowIngress,
};
use crate::identity::{AgentId, MachineId};

use super::state::AppState;

/// Handle one durable gui-show typed DM.
///
/// The completion sender is always answered on a path this function handles.
pub(crate) async fn handle_gui_show_typed(state: &Arc<AppState>, typed: DmTypedPayload) {
    match classify_prefix(&typed.payload) {
        Some(DmClass::ShowRequest) => handle_show_request(state, typed).await,
        Some(DmClass::ShowResult) => handle_show_result(state, typed).await,
        Some(DmClass::Activity) => handle_activity(state, typed).await,
        None => finish(typed, DmTypedPayloadCompletion::Inserted),
    }
}

async fn handle_show_request(state: &Arc<AppState>, typed: DmTypedPayload) {
    // Envelope authentication is the ADR 0050 signature. An unverified
    // frame is not a sender, so it gets no result and no body decode.
    if !typed.verified {
        finish(typed, DmTypedPayloadCompletion::Inserted);
        return;
    }
    let trusted = owner_trusted(state, &typed).await;
    let now = unix_now_secs();
    let sender = *typed.sender.as_bytes();
    let ingress = state
        .gui_show
        .with_replay_cache(|cache| ingress_show(trusted, &typed.payload, &sender, now, cache));
    let Some(ingress) = ingress else {
        finish(typed, DmTypedPayloadCompletion::Inserted);
        return;
    };

    let remote_enabled = state.gui_show.config().remote_enabled;
    let control = show_control(state, &typed.sender, &ingress);
    let via_rider = matches!(
        &ingress,
        ShowIngress::Trusted(show) if show.request.via_rider
    );
    // The envelope signer is blocked even when `via_rider` names another
    // subject. A rider pair block does not add that subject.
    let blocked = match &control {
        Some(agent) => {
            state.gui_show.is_blocked(&typed.sender)
                || state.gui_show.is_blocked(agent)
                || (via_rider && state.gui_show.rider_pair_blocked(&typed.sender, agent))
                || subject_barred(state, agent).await
        }
        None => state.gui_show.is_blocked(&typed.sender),
    };
    let mut preview = receive_action(&ingress, remote_enabled, blocked, false);
    // A rider subject that names this daemon, or is empty, must not display.
    // Replay and stale_request keep their own results.
    if control.is_none() && matches!(preview, ReceiveAction::Display { .. }) {
        preview = ReceiveAction::Reply(crate::gui::GuiShowOutcome::Refused);
    }
    let rate_limited = if let (Some(agent), ReceiveAction::Display { .. }) = (&control, &preview) {
        let mut agents = vec![typed.sender];
        if agent != &typed.sender {
            agents.push(*agent);
        }
        !state
            .gui_show
            .try_rate_limit_agents(&agents, Instant::now())
    } else {
        false
    };
    let action = if rate_limited {
        receive_action(&ingress, remote_enabled, blocked, true)
    } else {
        preview
    };

    match action {
        ReceiveAction::Drop => finish(typed, DmTypedPayloadCompletion::Duplicate),
        ReceiveAction::Reply(outcome) => {
            let Some(request_id) = request_id_of(&ingress) else {
                finish(typed, DmTypedPayloadCompletion::Inserted);
                return;
            };
            let result = GuiShowDmResult {
                request_id,
                outcome,
            };
            let untrusted = matches!(ingress, ShowIngress::Untrusted { .. });
            if untrusted && !state.gui_show.allow_untrusted_refusal(Instant::now()) {
                finish(typed, DmTypedPayloadCompletion::Inserted);
                return;
            }
            detach_reply(
                state,
                ReplyJob::Result {
                    to: typed.sender,
                    result,
                },
            );
            finish(typed, DmTypedPayloadCompletion::Inserted);
        }
        ReceiveAction::Display { route, via_rider } => {
            let Some(request_id) = request_id_of(&ingress) else {
                finish(typed, DmTypedPayloadCompletion::Inserted);
                return;
            };
            let Some(sender) = control else {
                finish(typed, DmTypedPayloadCompletion::Inserted);
                return;
            };
            let request_id_hex = hex::encode(request_id);
            let outcome = deliver_remote_show(
                state,
                sender,
                typed.sender,
                typed.machine_id,
                &route,
                via_rider,
                &request_id_hex,
            )
            .await;
            let result = GuiShowDmResult {
                request_id,
                outcome,
            };
            detach_reply(
                state,
                ReplyJob::Result {
                    to: typed.sender,
                    result,
                },
            );
            finish(typed, DmTypedPayloadCompletion::Inserted);
        }
    }
}

async fn handle_show_result(state: &Arc<AppState>, typed: DmTypedPayload) {
    if !typed.verified {
        finish(typed, DmTypedPayloadCompletion::Inserted);
        return;
    }
    let trusted = owner_trusted(state, &typed).await;
    if !trusted {
        finish(typed, DmTypedPayloadCompletion::Inserted);
        return;
    }
    if let Some(result) = decode_show_result(&typed.payload) {
        state
            .gui_show
            .remote_hub()
            .complete_show(&typed.sender, &typed.machine_id, result);
    }
    finish(typed, DmTypedPayloadCompletion::Inserted);
}

async fn handle_activity(state: &Arc<AppState>, typed: DmTypedPayload) {
    if !typed.verified {
        finish(typed, DmTypedPayloadCompletion::Inserted);
        return;
    }
    let trusted = owner_trusted(state, &typed).await;
    match ingress_activity(trusted, &typed.payload) {
        ActivityIngress::Ignore => finish(typed, DmTypedPayloadCompletion::Inserted),
        ActivityIngress::Query { request_id } => {
            let remote_enabled = state.gui_show.config().remote_enabled;
            let visible = crate::server::routes::gui_show::fresh_gui_visible_at(state).await;
            let body = activity_reply(request_id, remote_enabled, visible);
            detach_reply(
                state,
                ReplyJob::Activity {
                    to: typed.sender,
                    body,
                },
            );
            finish(typed, DmTypedPayloadCompletion::Inserted);
        }
        ActivityIngress::Reply(body) => {
            state
                .gui_show
                .remote_hub()
                .complete_activity(&typed.sender, &typed.machine_id, body);
            finish(typed, DmTypedPayloadCompletion::Inserted);
        }
    }
}

/// impl-api owns this function in `src/server/routes/gui_show.rs`.
async fn deliver_remote_show(
    state: &Arc<AppState>,
    subject: AgentId,
    envelope: AgentId,
    sender_machine: MachineId,
    route: &str,
    via_rider: bool,
    request_id_hex: &str,
) -> crate::gui::GuiShowOutcome {
    crate::server::routes::gui_show::deliver_remote_show(
        state.as_ref(),
        subject,
        envelope,
        sender_machine,
        route,
        via_rider,
        request_id_hex,
    )
    .await
}

/// Agent id the target blocks, rate-limits and names on the banner.
///
/// `None` for an untrusted ingress, or a rider subject this daemon must
/// refuse. The envelope signer stays the daemon that holds the rider token.
fn show_control(state: &AppState, envelope: &AgentId, ingress: &ShowIngress) -> Option<AgentId> {
    let ShowIngress::Trusted(show) = ingress else {
        return None;
    };
    let bytes = crate::gui::remote::show_subject(
        envelope.as_bytes(),
        &show.request,
        state.agent.agent_id().as_bytes(),
    )?;
    Some(AgentId(bytes))
}

/// Contact block and revocation for the agent the target attributes.
///
/// The envelope signer is already owner-trusted. A rider subject is a
/// different agent. A Blocked contact or a revoked agent does not display.
async fn subject_barred(state: &AppState, agent: &AgentId) -> bool {
    if state.agent.contacts().read().await.is_blocked(agent) {
        return true;
    }
    state
        .agent
        .revocation_set()
        .read()
        .await
        .is_agent_revoked(agent)
}

fn request_id_of(ingress: &ShowIngress) -> Option<[u8; 16]> {
    match ingress {
        ShowIngress::Trusted(show) => Some(show.request.request_id),
        ShowIngress::Untrusted { request_id } => *request_id,
    }
}

/// Owner authority for one authenticated sender, before any body decode.
///
/// `evaluate_pair` runs `OwnerTrust::is_owner_trusted` and forces
/// `owner_trusted` false for a `Blocked` contact (ADR 0083 §2).
async fn owner_trusted(state: &AppState, typed: &DmTypedPayload) -> bool {
    if state.gui_show.trust_hook_allows(&typed.sender) {
        return true;
    }
    let cache = state.agent.identity_discovery_cache();
    let revoked = state.agent.revocation_set();
    state
        .agent
        .owner_trust()
        .evaluate_pair(
            state.agent.contacts().as_ref(),
            cache.as_ref(),
            revoked.as_ref(),
            &typed.sender,
            &typed.machine_id,
        )
        .await
        .owner_trusted
}

enum ReplyJob {
    Result {
        to: AgentId,
        result: GuiShowDmResult,
    },
    Activity {
        to: AgentId,
        body: GuiActivityBody,
    },
}

/// Start one reply send and return.
///
/// The receive loop can take the next message while this send waits.
/// A full permit set skips the send. The caller does not wait for a slot.
fn detach_reply(state: &Arc<AppState>, job: ReplyJob) {
    let Some(permit) = state.gui_show.try_reply_permit() else {
        tracing::debug!("gui show reply skipped: send slots are full");
        return;
    };
    let task_state = Arc::clone(state);
    // The shutdown drain owns this task. A bare spawn would keep `AppState`
    // alive after the supervisor returns.
    if !state.spawn_detached(async move {
        let _permit = permit;
        match job {
            ReplyJob::Result { to, result } => send_show_result(&task_state, to, result).await,
            ReplyJob::Activity { to, body } => send_activity(&task_state, to, body).await,
        }
    }) {
        tracing::debug!("gui show reply skipped: shutdown closed task admission");
    }
}

async fn send_show_result(state: &AppState, to: AgentId, result: GuiShowDmResult) {
    if delayed_test_reply(state).await {
        return;
    }
    let Some(payload) = result.to_dm_payload() else {
        return;
    };
    let config = DmSendConfig {
        require_durable_app_ack: false,
        max_retries: 0,
        logical_request_id: Some(result.request_id),
        ..DmSendConfig::default()
    };
    if let Err(err) = state
        .agent
        .send_direct_with_config(&to, payload, config)
        .await
    {
        tracing::debug!("gui show result was not sent: {err}");
    }
}

async fn send_activity(state: &AppState, to: AgentId, body: GuiActivityBody) {
    if delayed_test_reply(state).await {
        return;
    }
    let request_id = match &body {
        GuiActivityBody::Query { request_id } | GuiActivityBody::Reply { request_id, .. } => {
            *request_id
        }
    };
    let Some(payload) = body.to_dm_payload() else {
        return;
    };
    let config = DmSendConfig {
        require_durable_app_ack: false,
        max_retries: 0,
        logical_request_id: Some(request_id),
        ..DmSendConfig::default()
    };
    if let Err(err) = state
        .agent
        .send_direct_with_config(&to, payload, config)
        .await
    {
        tracing::debug!("gui show activity reply was not sent: {err}");
    }
}

fn finish(mut typed: DmTypedPayload, completion: DmTypedPayloadCompletion) {
    if let Some(done) = typed.completion.take() {
        let _ = done.send(Ok(completion));
    }
}

/// Test replies wait here and skip the network.
///
/// A zero delay keeps the real send. The receive handler starts this
/// wait on a detached task.
async fn delayed_test_reply(state: &AppState) -> bool {
    #[cfg(test)]
    {
        let delay_ms = state.gui_show.reply_delay_ms_for_test();
        if delay_ms > 0 {
            state.gui_show.count_reply_send_for_test();
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            return true;
        }
    }
    #[cfg(not(test))]
    {
        let _ = state;
    }
    false
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod adr_remote {
    use super::*;
    use crate::contacts::{ContactStore, TrustLevel};
    use crate::dm_inbox::AuthenticatedMachineBindings;
    use crate::gui::remote::{ingress_show, receive_action, GuiShowDmRequest, ReceiveAction};
    use crate::gui::{CapturingOpener, GuiShowOutcome};
    use crate::identity::{
        AgentCertificate, AgentId, AgentKeypair, MachineId, MachineKeypair, UserKeypair,
    };
    use crate::owner_sync::OwnerEnrollment;
    use crate::owner_trust::OwnerTrust;
    use crate::revocation::{RevocationRecord, RevocationSet, RevokedSubject};
    use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
    use crate::DiscoveredAgent;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{oneshot, RwLock};

    struct Peer {
        _dir: tempfile::TempDir,
        owner: UserKeypair,
        trust: OwnerTrust,
        cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>,
        revoked: Arc<RwLock<RevocationSet>>,
        contacts: Arc<RwLock<ContactStore>>,
        agent_kp: AgentKeypair,
        agent_id: AgentId,
        machine_id: MachineId,
    }

    async fn peer(enroll: bool, cert_from_local: bool) -> Peer {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = UserKeypair::generate().expect("owner");
        let other = UserKeypair::generate().expect("other owner");
        let agent_kp = AgentKeypair::generate().expect("agent");
        let machine_kp = MachineKeypair::generate().expect("machine");
        let agent_id = agent_kp.agent_id();
        let machine_id = machine_kp.machine_id();
        let signer = if cert_from_local { &owner } else { &other };
        let cert = AgentCertificate::issue(signer, &agent_kp).expect("cert");
        let devices = load_device_store(dir.path()).await;
        if enroll {
            let now_ms = unix_now_secs().saturating_mul(1000);
            let record =
                OwnerEnrollment::sign(machine_id, &owner, now_ms, None).expect("enroll sign");
            devices.enroll(record).await.expect("enroll");
        }
        let devices = Arc::new(devices);
        let bindings = AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(
            &bindings,
            agent_id,
            machine_id,
            unix_now_secs(),
        )
        .await;
        let trust = OwnerTrust::new(Some(owner.user_id()), bindings);
        trust.install_device_store(Arc::clone(&devices));
        let mut found = HashMap::new();
        found.insert(
            agent_id,
            DiscoveredAgent {
                agent_id,
                machine_id,
                user_id: cert.user_id().ok(),
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: AgentCertificate::not_after(&cert),
                agent_certificate: Some(cert),
                cert_digest: None,
                agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
                self_name: None,
            },
        );
        let contacts = Arc::new(RwLock::new(ContactStore::new(
            dir.path().join("contacts.json"),
        )));
        let _keep = (machine_kp, other);
        Peer {
            _dir: dir,
            owner,
            trust,
            cache: Arc::new(RwLock::new(found)),
            revoked: Arc::new(RwLock::new(RevocationSet::new())),
            contacts,
            agent_kp,
            agent_id,
            machine_id,
        }
    }

    async fn load_device_store(path: &std::path::Path) -> crate::owner_sync::OwnerSyncStore {
        crate::owner_sync::OwnerSyncStore::load(path)
            .await
            .expect("device store")
    }

    async fn trusted(peer: &Peer) -> bool {
        peer.trust
            .evaluate_pair(
                &peer.contacts,
                &peer.cache,
                &peer.revoked,
                &peer.agent_id,
                &peer.machine_id,
            )
            .await
            .owner_trusted
    }

    fn action_for(trusted_sender: bool) -> ReceiveAction {
        let now = unix_now_secs();
        let payload = GuiShowDmRequest {
            request_id: [9; 16],
            view: "people".into(),
            issued_at: now,
            via_rider: false,
            subject: [0; 32],
        }
        .to_dm_payload()
        .expect("encode");
        let mut cache = crate::gui::remote::ReplayCache::new();
        let ingress =
            ingress_show(trusted_sender, &payload, &[4; 32], now, &mut cache).expect("ingress");
        receive_action(&ingress, true, false, false)
    }

    #[tokio::test]
    async fn same_owner_enrolled_sender_may_display() {
        let peer = peer(true, true).await;
        assert!(
            trusted(&peer).await,
            "enrolled same-owner sender is trusted"
        );
        assert!(matches!(
            action_for(true),
            ReceiveAction::Display { route, .. } if route == "people"
        ));
    }

    #[tokio::test]
    async fn different_owner_is_refused() {
        let peer = peer(true, false).await;
        assert!(!trusted(&peer).await);
        assert_eq!(
            action_for(false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[tokio::test]
    async fn unenrolled_same_owner_is_refused() {
        let peer = peer(false, true).await;
        assert!(!trusted(&peer).await);
        assert_eq!(
            action_for(false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[tokio::test]
    async fn revoked_sender_is_refused() {
        let peer = peer(true, true).await;
        assert!(trusted(&peer).await, "precondition");
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(peer.agent_id),
            peer.agent_kp.public_key(),
            peer.agent_kp.secret_key(),
            unix_now_secs(),
            None,
        )
        .expect("sign revocation");
        peer.revoked
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("insert revocation");
        assert!(!trusted(&peer).await, "revoked sender is not owner-trusted");
        assert_eq!(
            action_for(false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[tokio::test]
    async fn blocked_contact_is_refused_even_when_enrolled() {
        let peer = peer(true, true).await;
        assert!(
            peer.trust
                .is_owner_trusted(&peer.cache, &peer.revoked, &peer.agent_id, &peer.machine_id)
                .await,
            "is_owner_trusted does not read contacts; Blocked is evaluate_pair"
        );
        peer.contacts
            .write()
            .await
            .set_trust(&peer.agent_id, TrustLevel::Blocked);
        assert!(!trusted(&peer).await, "Blocked contact refuses the show");
        assert_eq!(
            action_for(false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[tokio::test]
    async fn sharee_with_every_cap_is_refused() {
        let peer = peer(false, false).await;
        let local = AgentId([3; 32]);
        let grants = Arc::new(ShareGrantStore::in_memory(
            local,
            Some(peer.owner.user_id()),
        ));
        let grant = ShareGrant::sign(
            &peer.owner,
            [0x5A; 32],
            Grantee::Agent(peer.agent_id),
            vec![local],
            vec![
                ShareCap::Dm,
                ShareCap::Exec,
                ShareCap::Connect { ports: vec![9] },
                ShareCap::GroupInvite,
                ShareCap::Call,
            ],
            unix_now_secs().saturating_sub(30),
            unix_now_secs().saturating_add(3_600),
        )
        .expect("sign grant");
        grants
            .accept(grant, unix_now_secs())
            .await
            .expect("store grant");
        peer.trust.install_share_grant_store(grants);
        assert!(!trusted(&peer).await, "a share grant is not owner trust");
        assert_eq!(
            action_for(false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[tokio::test]
    async fn untrusted_handler_does_not_open_a_window() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        let local = state.agent.agent_id();
        let owner = UserKeypair::generate().expect("owner");
        let grants = Arc::new(ShareGrantStore::in_memory(local, Some(owner.user_id())));
        let sender = AgentId([0x44; 32]);
        let grant = ShareGrant::sign(
            &owner,
            [0x11; 32],
            Grantee::Agent(sender),
            vec![local],
            vec![
                ShareCap::Dm,
                ShareCap::Exec,
                ShareCap::Connect { ports: vec![443] },
                ShareCap::GroupInvite,
                ShareCap::Call,
            ],
            unix_now_secs().saturating_sub(30),
            unix_now_secs().saturating_add(3_600),
        )
        .expect("grant");
        grants.accept(grant, unix_now_secs()).await.expect("accept");
        state.agent.install_share_grant_store(grants);
        let now = unix_now_secs();
        let payload = GuiShowDmRequest {
            request_id: [7; 16],
            view: "people".into(),
            issued_at: now,
            via_rider: false,
            subject: [0; 32],
        }
        .to_dm_payload()
        .expect("encode");
        let (tx, rx) = oneshot::channel();
        let typed = DmTypedPayload {
            sender,
            machine_id: MachineId([0x55; 32]),
            payload,
            verified: true,
            trust_decision: None,
            received_at_unix_ms: now.saturating_mul(1000),
            request_id: [7; 16],
            completion: Some(tx),
        };
        handle_gui_show_typed(&state, typed).await;
        assert!(cap.urls.lock().expect("urls").is_empty());
        let done = rx.await.expect("completion");
        assert!(done.is_ok());
    }

    #[tokio::test]
    async fn stop_on_one_remote_rider_does_not_block_the_other_or_the_daemon() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let daemon = AgentId([0x11; 32]);
        let rider_a = AgentId([0x22; 32]);
        let rider_b = AgentId([0x33; 32]);
        state.gui_show.block_agent(&rider_a);
        let now = unix_now_secs();
        let ingress = |subject: AgentId, via_rider: bool| {
            let payload = GuiShowDmRequest {
                request_id: [4; 16],
                view: "people".into(),
                issued_at: now,
                via_rider,
                subject: *subject.as_bytes(),
            }
            .to_dm_payload()
            .expect("encode");
            let mut cache = crate::gui::remote::ReplayCache::new();
            ingress_show(true, &payload, daemon.as_bytes(), now, &mut cache).expect("ingress")
        };
        let rider_a_ingress = ingress(rider_a, true);
        let rider_b_ingress = ingress(rider_b, true);
        let owner_ingress = ingress(daemon, false);
        let rider_a_control =
            super::show_control(&state, &daemon, &rider_a_ingress).expect("rider a");
        let rider_b_control =
            super::show_control(&state, &daemon, &rider_b_ingress).expect("rider b");
        assert!(state.gui_show.is_blocked(&rider_a_control));
        assert!(!state.gui_show.is_blocked(&rider_b_control));
        assert_ne!(rider_a_control, rider_b_control);
        let owner = super::show_control(&state, &daemon, &owner_ingress).expect("owner");
        assert_eq!(owner, daemon);
        assert!(!state.gui_show.is_blocked(&owner));
        assert!(!state.gui_show.is_blocked(&state.agent.agent_id()));
        assert_ne!(rider_a_control, state.agent.agent_id());
    }

    fn show_typed(
        sender: AgentId,
        machine: MachineId,
        request_id: [u8; 16],
        subject: AgentId,
        via_rider: bool,
    ) -> DmTypedPayload {
        let now = unix_now_secs();
        let payload = GuiShowDmRequest {
            request_id,
            view: "people".into(),
            issued_at: now,
            via_rider,
            subject: *subject.as_bytes(),
        }
        .to_dm_payload()
        .expect("encode");
        DmTypedPayload {
            sender,
            machine_id: machine,
            payload,
            verified: true,
            trust_decision: None,
            received_at_unix_ms: now.saturating_mul(1000),
            request_id,
            completion: None,
        }
    }

    /// A flood of signed strangers must not hold the owner's result.
    ///
    /// Each refusal is a full attempt when the handler awaits the send.
    /// Twelve delays of 250 ms pass one second. The owner result has to
    /// land inside that second, and at most one refusal may be sent.
    #[tokio::test]
    async fn untrusted_flood_then_owner_result_completes() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let owner = AgentId([0xA1; 32]);
        let owner_machine = MachineId([0xB2; 32]);
        state.gui_show.trust_sender_for_test(&owner);
        let request_id = [0xC3; 16];
        let wait = state
            .gui_show
            .remote_hub()
            .begin_show(request_id, owner, owner_machine)
            .expect("waiter");
        state.gui_show.arm_reply_delay_for_test(250);
        let started = std::time::Instant::now();
        for n in 0..12u8 {
            let stranger = AgentId([n.saturating_add(1); 32]);
            let mut id = [0xD0; 16];
            id[0] = n;
            handle_gui_show_typed(
                &state,
                show_typed(stranger, MachineId([0xE0; 32]), id, stranger, false),
            )
            .await;
        }
        let payload = crate::gui::remote::GuiShowDmResult {
            request_id,
            outcome: GuiShowOutcome::Opened,
        }
        .to_dm_payload()
        .expect("result");
        let now = unix_now_secs();
        handle_gui_show_typed(
            &state,
            DmTypedPayload {
                sender: owner,
                machine_id: owner_machine,
                payload,
                verified: true,
                trust_decision: None,
                received_at_unix_ms: now.saturating_mul(1000),
                request_id,
                completion: None,
            },
        )
        .await;
        let elapsed = started.elapsed();
        let result = wait.recv().await.expect("owner result");
        assert_eq!(result.outcome, GuiShowOutcome::Opened);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "owner result waited behind untrusted refusals: {elapsed:?}"
        );
        tokio::task::yield_now().await;
        let sends = state.gui_show.reply_sends_for_test();
        assert!(
            sends <= 1,
            "a stranger flood sent {sends} refusals; the cap is one per minute"
        );
        state.gui_show.arm_reply_delay_for_test(0);
    }

    /// Shutdown takes the reply task out of the registry and aborts it.
    /// A bare `tokio::spawn` leaves the sleep outside that registry.
    #[tokio::test]
    async fn shutdown_drains_a_delayed_reply() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        state.gui_show.arm_reply_delay_for_test(60_000);
        let stranger = AgentId([0x71; 32]);
        handle_gui_show_typed(
            &state,
            show_typed(stranger, MachineId([0x72; 32]), [0x73; 16], stranger, false),
        )
        .await;
        let tasks = state
            .detached_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("admission open");
        assert_eq!(
            tasks.len(),
            1,
            "a delayed reply must sit in the shutdown task registry"
        );
        for task in &tasks {
            task.abort();
        }
        let started = std::time::Instant::now();
        for task in tasks {
            let _ = task.await;
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "shutdown did not drain the delayed reply: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn blocked_or_revoked_rider_does_not_display() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        let daemon = AgentId([0x11; 32]);
        let machine = MachineId([0x44; 32]);
        state.gui_show.trust_sender_for_test(&daemon);
        let blocked = AgentId([0x22; 32]);
        let allowed = AgentId([0x55; 32]);
        state
            .agent
            .contacts()
            .write()
            .await
            .set_trust(&blocked, crate::contacts::TrustLevel::Blocked);
        let rider_kp = crate::identity::AgentKeypair::generate().expect("rider key");
        let revoked = rider_kp.agent_id();
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(revoked),
            rider_kp.public_key(),
            rider_kp.secret_key(),
            unix_now_secs(),
            None,
        )
        .expect("sign revocation");
        state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("insert revocation");

        handle_gui_show_typed(&state, show_typed(daemon, machine, [1; 16], blocked, true)).await;
        handle_gui_show_typed(&state, show_typed(daemon, machine, [2; 16], revoked, true)).await;
        assert!(
            cap.urls.lock().expect("urls").is_empty(),
            "a blocked or revoked rider must not open a window"
        );
        handle_gui_show_typed(&state, show_typed(daemon, machine, [3; 16], allowed, true)).await;
        assert!(
            !cap.urls.lock().expect("urls").is_empty(),
            "another rider on the same daemon still displays"
        );
    }

    /// A signer already on `gui_show_blocked` cannot display by setting `via_rider`.
    #[tokio::test]
    async fn stopped_signer_with_via_rider_is_refused() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        let signer = AgentId([0x11; 32]);
        let subject = AgentId([0x22; 32]);
        state.gui_show.trust_sender_for_test(&signer);
        state.gui_show.block_agent(&signer);
        handle_gui_show_typed(
            &state,
            show_typed(signer, MachineId([0x44; 32]), [9; 16], subject, true),
        )
        .await;
        assert!(
            cap.urls.lock().expect("urls").is_empty(),
            "a blocked envelope signer must not open a rider show"
        );
    }

    /// A new subject does not refill the envelope signer's burst.
    #[tokio::test]
    async fn rotating_subjects_hit_the_per_signer_limit() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        let signer = AgentId([0x11; 32]);
        state.gui_show.trust_sender_for_test(&signer);
        let machine = MachineId([0x44; 32]);
        for n in 0..3u8 {
            let mut subject = [0xA0; 32];
            subject[0] = n.saturating_add(1);
            let mut request_id = [0xB0; 16];
            request_id[0] = n;
            handle_gui_show_typed(
                &state,
                show_typed(signer, machine, request_id, AgentId(subject), true),
            )
            .await;
        }
        assert_eq!(
            cap.urls.lock().expect("urls").len(),
            3,
            "the signer burst is three shows"
        );
        handle_gui_show_typed(
            &state,
            show_typed(signer, machine, [0xB4; 16], AgentId([0xA4; 32]), true),
        )
        .await;
        assert_eq!(
            cap.urls.lock().expect("urls").len(),
            3,
            "a fourth subject must not bypass the signer burst"
        );
    }

    /// Stop on a rider banner blocks the envelope signer, not the named subject.
    #[tokio::test]
    async fn stop_on_a_forged_subject_does_not_block_that_agents_direct_shows() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        let signer = AgentId([0x11; 32]);
        let victim = AgentId([0x22; 32]);
        let machine = MachineId([0x44; 32]);
        state.gui_show.trust_sender_for_test(&signer);
        state.gui_show.trust_sender_for_test(&victim);
        handle_gui_show_typed(&state, show_typed(signer, machine, [1; 16], victim, true)).await;
        let token = {
            let urls = cap.urls.lock().expect("urls");
            assert_eq!(urls.len(), 1, "the forged rider show displayed");
            urls[0]
                .split("token=")
                .nth(1)
                .unwrap_or("")
                .split(['&', '#'])
                .next()
                .unwrap_or("")
                .to_string()
        };
        let pending = state
            .gui_show
            .take_pending_for_session(&token, std::time::Instant::now())
            .expect("rider banner");
        assert_eq!(pending.agent_id, hex::encode(signer.as_bytes()));
        assert_ne!(pending.agent_id, hex::encode(victim.as_bytes()));
        let bytes = hex::decode(&pending.agent_id).expect("agent hex");
        let mut stopped = [0u8; 32];
        stopped.copy_from_slice(&bytes);
        crate::server::routes::gui_show::apply_gui_block(&state, AgentId(stopped)).expect("stop");
        assert!(
            state.gui_show.is_blocked(&signer),
            "Stop writes the envelope signer"
        );
        assert!(
            !state.gui_show.is_blocked(&victim),
            "Stop does not write the forged subject"
        );
        assert!(
            state.gui_show.rider_pair_blocked(&signer, &victim),
            "Stop records the (signer, subject) pair"
        );
        handle_gui_show_typed(&state, show_typed(victim, machine, [2; 16], victim, false)).await;
        assert_eq!(
            cap.urls.lock().expect("urls").len(),
            2,
            "the forged subject's own direct show still displays"
        );
        handle_gui_show_typed(
            &state,
            show_typed(signer, machine, [3; 16], AgentId([0x55; 32]), true),
        )
        .await;
        assert_eq!(
            cap.urls.lock().expect("urls").len(),
            2,
            "that signer's later rider shows stay refused"
        );
    }
}
