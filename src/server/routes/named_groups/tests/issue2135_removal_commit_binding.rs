#![cfg(test)]
//! #2135 (David's ruling, 22 Nov 2026: bind the commit identity into the
//! state hash). Two admins A and D remove the same member T from the same
//! parent. Their TreeKEM commits differ, so their epoch keys differ. Before
//! this change both sealed `treekem:epoch=<n>`, both roster commits had one
//! state hash, and A took D's commit for a duplicate of its own: a silent
//! fork (W3-H 1581e). With every member's advert carrying
//! `removal_commit_binding_v1`, the signed binding names the TreeKEM commit
//! (`treekem:epoch=<n>:commit=<blake3>`), so D's commit is fork evidence on
//! A and a replay of one commit is still a duplicate.

use super::*;
use x0x::identity::AgentKeypair;
use x0x::mls::TreeKemMlsGroup;

const GROUP: &str = "e2135e2135e2135e2135e2135e2135e2";

fn seed_advert(state: &AppState, agent: &AgentId, bits: u64) {
    let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
    assert!(state.agent.capability_store().insert(
        *agent,
        x0x::identity::MachineId([4; 32]),
        caps,
        x0x::dm::now_unix_ms(),
    ));
}

fn all_bits() -> u64 {
    x0x::dm::CapabilityRegistry::current().bits
}

fn without_binding_bit() -> u64 {
    all_bits() & !x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1
}

async fn body_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn owner() -> axum::extract::Extension<crate::server::rider_auth::ActorContext> {
    axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
}

async fn remove_via_route(
    state: &Arc<AppState>,
    target_hex: &str,
) -> (StatusCode, serde_json::Value) {
    let response = remove_named_group_member(
        State(Arc::clone(state)),
        owner(),
        Path((GROUP.to_string(), target_hex.to_string())),
    )
    .await
    .into_response();
    body_of(response).await
}

async fn ban_via_route(state: &Arc<AppState>, target_hex: &str) -> (StatusCode, serde_json::Value) {
    let response = ban_group_member(
        State(Arc::clone(state)),
        owner(),
        Path((GROUP.to_string(), target_hex.to_string())),
    )
    .await
    .into_response();
    body_of(response).await
}

/// Admin A (this daemon), a second admin D, a member L (its own daemon)
/// and the target T, all seated in one TreeKEM tree at `epoch`. A, D and L
/// each hold that tree; `parent` is the committed roster they share.
struct Fixture {
    a: Arc<AppState>,
    _a_dir: tempfile::TempDir,
    l: Arc<AppState>,
    _l_dir: tempfile::TempDir,
    d_kp: AgentKeypair,
    d_tree: TreeKemMlsGroup,
    parent: x0x::groups::GroupInfo,
    target: AgentId,
    target_kp: Vec<u8>,
    epoch: u64,
}

impl Fixture {
    fn hex(id: &AgentId) -> String {
        hex::encode(id.as_bytes())
    }

    fn d_hex(&self) -> String {
        Self::hex(&self.d_kp.agent_id())
    }

    fn target_hex(&self) -> String {
        Self::hex(&self.target)
    }

    async fn head(&self, state: &AppState) -> x0x::groups::GroupInfo {
        state.named_groups.read().await[GROUP].clone()
    }

    /// D's removal or ban of T from `parent`, with its own TreeKEM commit
    /// and the binding `binding` gives for those bytes.
    fn d_event(
        &mut self,
        ban: bool,
        binding: impl Fn(&x0x::groups::GroupInfo, &[u8]) -> String,
    ) -> Result<NamedGroupMetadataEvent> {
        let commit_bytes = self
            .d_tree
            .remove_member_verified(self.target, &self.target_kp)?;
        let d_hex = self.d_hex();
        let target_hex = self.target_hex();
        let mut next = self.parent.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        let revision = next.roster_revision;
        if ban {
            next.ban_member(&target_hex, Some(d_hex.clone()));
        } else {
            next.remove_member(&target_hex, Some(d_hex.clone()));
        }
        next.secret_epoch = self.epoch + 1;
        next.security_binding = Some(binding(&next, &commit_bytes));
        let commit = next.seal_commit(&self.d_kp, now_millis_u64())?;
        let treekem_commit_b64 = Some(BASE64.encode(&commit_bytes));
        Ok(if ban {
            NamedGroupMetadataEvent::MemberBanned {
                group_id: GROUP.to_string(),
                revision,
                actor: d_hex,
                agent_id: target_hex,
                secret_epoch: None,
                treekem_commit_b64,
                treekem_epoch: Some(self.epoch + 1),
                commit: Some(commit),
                target_key_package_b64: None,
            }
        } else {
            NamedGroupMetadataEvent::MemberRemoved {
                group_id: GROUP.to_string(),
                revision,
                actor: d_hex,
                agent_id: target_hex,
                treekem_commit_b64,
                treekem_epoch: Some(self.epoch + 1),
                secret_epoch: None,
                commit: Some(commit),
            }
        })
    }
}

/// `l_bits` is the registry of L's advert as A holds it. A also holds D's
/// and its own advert with every bit.
async fn fixture(l_bits: u64) -> Result<Fixture> {
    let (a, a_dir) = secure_endpoint_test_state().await?;
    let (l, l_dir) = secure_endpoint_test_state().await?;
    let a_id = a.agent.agent_id();
    let l_id = l.agent.agent_id();
    let d_kp = AgentKeypair::generate()?;
    let d_id = d_kp.agent_id();
    let target = AgentKeypair::generate()?.agent_id();
    let group_id_bytes = hex::decode(GROUP)?;

    let a_seed = super::super::agent_treekem_seed(a.agent.as_ref(), &group_id_bytes);
    let l_seed = super::super::agent_treekem_seed(l.agent.as_ref(), &group_id_bytes);
    let mut a_tree = TreeKemMlsGroup::create(group_id_bytes, a_id, &a_seed)?;
    let d_prepared = TreeKemMlsGroup::prepare_member(d_id, &[5u8; 32])?;
    let d_kp_bytes = d_prepared.key_package_bytes().to_vec();
    let l_prepared = TreeKemMlsGroup::prepare_member(l_id, &l_seed)?;
    let l_kp_bytes = l_prepared.key_package_bytes().to_vec();
    let target_kp = TreeKemMlsGroup::prepare_member(target, &[8u8; 32])?
        .key_package_bytes()
        .to_vec();
    let added_d = a_tree.add_member(d_id, &d_kp_bytes)?;
    let mut d_tree = TreeKemMlsGroup::join_from_welcome(d_prepared, &added_d.welcome)?;
    let added_l = a_tree.add_member(l_id, &l_kp_bytes)?;
    d_tree.process_commit(&added_l.commit)?;
    let mut l_tree = TreeKemMlsGroup::join_from_welcome(l_prepared, &added_l.welcome)?;
    let added_t = a_tree.add_member(target, &target_kp)?;
    d_tree.process_commit(&added_t.commit)?;
    l_tree.process_commit(&added_t.commit)?;
    let epoch = a_tree.epoch();
    assert_eq!(d_tree.epoch(), epoch);
    assert_eq!(l_tree.epoch(), epoch);

    let a_hex = Fixture::hex(&a_id);
    let mut parent =
        x0x::groups::GroupInfo::new("fork-2135".to_string(), String::new(), a_id, GROUP.into());
    parent.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    for (id, role, kp) in [
        (d_id, x0x::groups::GroupRole::Admin, &d_kp_bytes),
        (l_id, x0x::groups::GroupRole::Member, &l_kp_bytes),
        (target, x0x::groups::GroupRole::Member, &target_kp),
    ] {
        let id_hex = Fixture::hex(&id);
        parent.add_member(id_hex.clone(), role, Some(a_hex.clone()), None);
        parent.set_member_treekem_key_package(&id_hex, BASE64.encode(kp));
    }
    parent.secret_epoch = epoch;
    parent.security_binding = Some(format!("treekem:epoch={epoch}"));
    parent.roster_revision = parent.roster_revision.saturating_add(1);
    parent.seal_commit(a.agent.identity().agent_keypair(), now_millis_u64())?;

    for (state, tree) in [(&a, a_tree), (&l, l_tree)] {
        state
            .named_groups
            .write()
            .await
            .insert(GROUP.to_string(), parent.clone());
        state
            .treekem_groups
            .write()
            .await
            .insert(GROUP.to_string(), Arc::new(tokio::sync::Mutex::new(tree)));
    }
    seed_advert(&a, &a_id, all_bits());
    seed_advert(&a, &d_id, all_bits());
    seed_advert(&a, &l_id, l_bits);
    Ok(Fixture {
        a,
        _a_dir: a_dir,
        l,
        _l_dir: l_dir,
        d_kp,
        d_tree,
        parent,
        target,
        target_kp,
        epoch,
    })
}

fn commit_bound(binding: Option<&str>, epoch: u64) -> bool {
    binding.is_some_and(|binding| binding.starts_with(&format!("treekem:epoch={epoch}:commit=")))
}

/// The 1581e shape, red on main. A removes T through the route; D removes
/// T from the same parent with its own TreeKEM commit, its binding given by
/// the same production rule. The two state hashes differ, D's commit is
/// fork evidence on A (a persisted marker naming D), L applies D's commit,
/// and a replay of D's commit on L is a duplicate, not evidence.
#[tokio::test]
async fn a_second_admins_removal_of_the_same_member_is_fork_evidence() -> Result<()> {
    let mut f = fixture(all_bits()).await?;
    let (status, body) = remove_via_route(&f.a, &f.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let a_head = f.head(&f.a).await;
    assert!(
        commit_bound(a_head.security_binding.as_deref(), f.epoch + 1),
        "A's removal names its TreeKEM commit: {:?}",
        a_head.security_binding
    );

    let a_state = Arc::clone(&f.a);
    let d_hex = f.d_hex();
    let target_hex = f.target_hex();
    let epoch = f.epoch + 1;
    let d_event = f.d_event(false, |next, bytes| {
        treekem_removal_security_binding(&a_state, next, &d_hex, &target_hex, epoch, bytes)
    })?;
    let d_hash = match &d_event {
        NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(commit),
            ..
        } => commit.state_hash.clone(),
        _ => unreachable!("a removal"),
    };
    assert_ne!(
        d_hash, a_head.state_hash,
        "two admins' removals of one member are distinct states"
    );

    let d_id = f.d_kp.agent_id();
    let on_l = apply_named_group_metadata_event(&f.l, d_event.clone(), d_id, true, None).await;
    assert!(on_l.accepted, "L applies D's removal: {on_l:?}");
    let l_head = f.head(&f.l).await;
    assert_eq!(l_head.state_hash, d_hash);
    assert_eq!(l_head.secret_epoch, f.epoch + 1);
    let replay = apply_named_group_metadata_event(&f.l, d_event.clone(), d_id, true, None).await;
    assert!(!replay.accepted, "a replay applies nothing new");
    let l_after = f.head(&f.l).await;
    assert_eq!(l_after.state_hash, d_hash);
    assert!(
        l_after.fork_quarantine.is_none(),
        "a replay of one commit is a duplicate, not fork evidence"
    );

    let on_a = apply_named_group_metadata_event(&f.a, d_event, d_id, true, None).await;
    assert!(!on_a.accepted, "A keeps its own commit: {on_a:?}");
    let a_after = f.head(&f.a).await;
    assert_eq!(a_after.state_hash, a_head.state_hash);
    let marker = a_after
        .fork_quarantine
        .clone()
        .expect("D's competing removal is fork evidence on A");
    assert_eq!(marker.state_hash, d_hash);
    assert_eq!(marker.committed_by, f.d_hex());
    assert_eq!(
        marker.snapshot.terminal_commit.state_hash,
        a_head.state_hash
    );
    // The marker is part of the stored group record, so it survives a
    // restart.
    let stored: x0x::groups::GroupInfo = serde_json::from_str(&serde_json::to_string(&a_after)?)?;
    assert_eq!(stored.fork_quarantine, Some(marker));
    Ok(())
}

/// The mixed-version rule: while one member's advert lacks
/// `removal_commit_binding_v1`, the route seals the legacy binding, which
/// every released receiver applies. The state hash form is unchanged.
#[tokio::test]
async fn a_member_without_the_bit_keeps_the_legacy_binding() -> Result<()> {
    let f = fixture(without_binding_bit()).await?;
    let (status, body) = remove_via_route(&f.a, &f.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = f.head(&f.a).await;
    let legacy = format!("treekem:epoch={}", f.epoch + 1);
    assert_eq!(head.security_binding.as_deref(), Some(legacy.as_str()));
    let mut expected = head.clone();
    expected.recompute_state_hash();
    assert_eq!(expected.state_hash, head.state_hash);
    Ok(())
}

/// The ban route follows the same rule as the removal route.
#[tokio::test]
async fn the_ban_route_binds_the_treekem_commit_once_every_member_is_ready() -> Result<()> {
    let ready = fixture(all_bits()).await?;
    let (status, body) = ban_via_route(&ready.a, &ready.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = ready.head(&ready.a).await;
    assert!(head.is_banned(&ready.target_hex()));
    assert!(
        commit_bound(head.security_binding.as_deref(), ready.epoch + 1),
        "{:?}",
        head.security_binding
    );

    let mixed = fixture(without_binding_bit()).await?;
    let (status, body) = ban_via_route(&mixed.a, &mixed.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = mixed.head(&mixed.a).await;
    let legacy = format!("treekem:epoch={}", mixed.epoch + 1);
    assert_eq!(head.security_binding.as_deref(), Some(legacy.as_str()));
    Ok(())
}

/// A receiver applies a commit-bound ban and keeps its signed binding, so
/// it reaches the sender's state hash; a ban whose binding names other
/// bytes is refused. Red on main: the receiver rebuilt the legacy binding,
/// so the commit-bound ban failed its state-hash check.
#[tokio::test]
async fn a_member_applies_a_commit_bound_ban_and_refuses_other_bytes() -> Result<()> {
    let mut f = fixture(all_bits()).await?;
    let epoch = f.epoch + 1;
    let forged = f.d_event(true, |_, _| treekem_commit_binding(epoch, b"other bytes"))?;
    // `d_event` advanced D's tree; rebuild it for the genuine event.
    let mut g = fixture(all_bits()).await?;
    let d_id = f.d_kp.agent_id();
    let refused = apply_named_group_metadata_event(&f.l, forged, d_id, true, None).await;
    assert!(!refused.accepted, "a binding over other bytes: {refused:?}");
    assert_eq!(f.head(&f.l).await.state_hash, f.parent.state_hash);

    let genuine = g.d_event(true, |_, bytes| treekem_commit_binding(epoch, bytes))?;
    let signed = match &genuine {
        NamedGroupMetadataEvent::MemberBanned {
            commit: Some(commit),
            ..
        } => commit.clone(),
        _ => unreachable!("a ban"),
    };
    let applied =
        apply_named_group_metadata_event(&g.l, genuine, g.d_kp.agent_id(), true, None).await;
    assert!(
        applied.accepted,
        "the commit-bound ban applies: {applied:?}"
    );
    let head = g.head(&g.l).await;
    assert!(head.is_banned(&g.target_hex()));
    assert_eq!(head.state_hash, signed.state_hash);
    assert_eq!(head.security_binding, signed.security_binding);
    Ok(())
}

/// The readiness rule: every other Active or Pending member must hold a
/// verified advert with the bit; the actor, the target and removed seats do
/// not count, and an unknown advert is not support.
#[test]
fn readiness_needs_every_other_live_members_advert() {
    let ids: Vec<AgentId> = (1u8..=5).map(|n| AgentId([n; 32])).collect();
    let hex_of = |id: &AgentId| hex::encode(id.as_bytes());
    let mut info =
        x0x::groups::GroupInfo::new("g".to_string(), String::new(), ids[0], GROUP.into());
    for id in &ids[1..] {
        info.add_member(hex_of(id), x0x::groups::GroupRole::Member, None, None);
    }
    info.remove_member(&hex_of(&ids[4]), None);
    let (actor, target) = (hex_of(&ids[0]), hex_of(&ids[1]));
    let supported = |set: Vec<AgentId>| {
        move |agent: &AgentId| {
            if set.contains(agent) {
                Some(true)
            } else {
                None
            }
        }
    };
    assert!(removal_commit_binding_peers_ready(
        &info,
        &actor,
        &target,
        supported(vec![ids[2], ids[3]])
    ));
    assert!(!removal_commit_binding_peers_ready(
        &info,
        &actor,
        &target,
        supported(vec![ids[2]])
    ));
    assert!(!removal_commit_binding_peers_ready(
        &info,
        &actor,
        &target,
        |agent: &AgentId| (*agent == ids[2]).then_some(true).or(Some(false))
    ));
}

#[test]
fn the_removal_commit_binding_bit_is_twenty_two_and_current() {
    assert_eq!(
        x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1,
        1 << 22
    );
    assert!(x0x::dm::CapabilityRegistry::current()
        .supports(x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1));
}
