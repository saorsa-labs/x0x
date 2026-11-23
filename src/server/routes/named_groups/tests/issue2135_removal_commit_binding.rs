#![cfg(test)]
//! #2135 (David's ruling, 22 Nov 2026: bind the commit identity into the
//! state hash). Two admins A and D remove the same member T from the same
//! parent. Their TreeKEM commits differ, so their epoch keys differ. Before
//! this change both sealed `treekem:epoch=<n>`, both roster commits had one
//! state hash, and A took D's commit for a duplicate of its own: a silent
//! fork (W3-H 1581e). Once every member, the target included, is ready for
//! `removal_commit_binding_v1` (a current verified advert with the bit, or
//! with no current advert a sticky record that one showed it), the signed
//! binding names the TreeKEM commit (`treekem:epoch=<n>:commit=<blake3>`),
//! so D's commit is fork evidence on A and a replay of one commit is still a
//! duplicate.

use super::*;
use x0x::identity::AgentKeypair;
use x0x::mls::TreeKemMlsGroup;

const GROUP: &str = "e2135e2135e2135e2135e2135e2135e2";

/// What A's capability store knows about one member.
#[derive(Clone, Copy)]
enum Advert {
    /// No verified advert was ever seen.
    Never,
    /// A current verified advert with these registry bits.
    Current(u64),
    /// No current advert (expired, offline, withheld), but a verified
    /// advert once showed the bit: only the sticky record remains.
    StickyOnly,
}

fn all_bits() -> u64 {
    x0x::dm::CapabilityRegistry::current().bits
}

fn without_binding_bit() -> u64 {
    all_bits() & !x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1
}

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

fn seed_sticky(state: &AppState, agent: &AgentId) {
    state.agent.capability_store().seed_sticky([(
        *agent,
        x0x::dm_capability::StickySeen {
            bits: x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1,
            advert_created_at_unix_ms: 1,
        },
    )]);
}

fn apply_advert(state: &AppState, agent: &AgentId, advert: Advert) {
    match advert {
        Advert::Never => {}
        Advert::Current(bits) => seed_advert(state, agent, bits),
        Advert::StickyOnly => seed_sticky(state, agent),
    }
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

/// Admin A (this daemon), a second admin D, a member L and the target T
/// (each of L and T its own daemon), all seated in one TreeKEM tree at
/// `epoch`. A, D, L and T each hold that tree; `parent` is the committed
/// roster they share.
struct Fixture {
    a: Arc<AppState>,
    _a_dir: tempfile::TempDir,
    l: Arc<AppState>,
    _l_dir: tempfile::TempDir,
    t: Arc<AppState>,
    _t_dir: tempfile::TempDir,
    d_kp: AgentKeypair,
    d_tree: TreeKemMlsGroup,
    parent: x0x::groups::GroupInfo,
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

    fn target(&self) -> AgentId {
        self.t.agent.agent_id()
    }

    fn target_hex(&self) -> String {
        Self::hex(&self.target())
    }

    async fn head(&self, state: &AppState) -> x0x::groups::GroupInfo {
        state.named_groups.read().await[GROUP].clone()
    }

    async fn epoch_of(&self, state: &AppState) -> u64 {
        let tree = state.treekem_groups.read().await[GROUP].clone();
        let epoch = tree.lock().await.epoch();
        epoch
    }

    /// D's removal or ban of T from `parent`, with its own TreeKEM commit
    /// and the binding `binding` gives for those bytes.
    fn d_event(
        &mut self,
        ban: bool,
        binding: impl Fn(&x0x::groups::GroupInfo, &[u8]) -> String,
    ) -> Result<NamedGroupMetadataEvent> {
        let target = self.target();
        let commit_bytes = self
            .d_tree
            .remove_member_verified(target, &self.target_kp)?;
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
                target_key_package_b64: None,
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

    /// D's removal or ban, its binding chosen by the production rule from
    /// A's capability store.
    fn d_event_by_rule(&mut self, ban: bool) -> Result<NamedGroupMetadataEvent> {
        let a_state = Arc::clone(&self.a);
        let d_hex = self.d_hex();
        let target_hex = self.target_hex();
        let epoch = self.epoch + 1;
        self.d_event(ban, |next, bytes| {
            treekem_removal_security_binding(&a_state, next, &d_hex, &target_hex, epoch, bytes)
        })
    }
}

fn signed_commit(event: &NamedGroupMetadataEvent) -> x0x::groups::GroupStateCommit {
    match event {
        NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(commit),
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            commit: Some(commit),
            ..
        } => commit.clone(),
        _ => unreachable!("a removal or ban"),
    }
}

/// `l` and `target` are what A's store knows about L and T. A also holds
/// its own and D's advert with every bit.
async fn fixture(l: Advert, target: Advert) -> Result<Fixture> {
    let (a, a_dir) = secure_endpoint_test_state().await?;
    let (l_state, l_dir) = secure_endpoint_test_state().await?;
    let (t, t_dir) = secure_endpoint_test_state().await?;
    let a_id = a.agent.agent_id();
    let l_id = l_state.agent.agent_id();
    let t_id = t.agent.agent_id();
    let d_kp = AgentKeypair::generate()?;
    let d_id = d_kp.agent_id();
    let group_id_bytes = hex::decode(GROUP)?;

    let seed_of =
        |state: &AppState| super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut a_tree = TreeKemMlsGroup::create(group_id_bytes.clone(), a_id, &seed_of(&a))?;
    let d_prepared = TreeKemMlsGroup::prepare_member(d_id, &[5u8; 32])?;
    let d_kp_bytes = d_prepared.key_package_bytes().to_vec();
    let l_prepared = TreeKemMlsGroup::prepare_member(l_id, &seed_of(&l_state))?;
    let l_kp_bytes = l_prepared.key_package_bytes().to_vec();
    let t_prepared = TreeKemMlsGroup::prepare_member(t_id, &seed_of(&t))?;
    let target_kp = t_prepared.key_package_bytes().to_vec();
    let added_d = a_tree.add_member(d_id, &d_kp_bytes)?;
    let mut d_tree = TreeKemMlsGroup::join_from_welcome(d_prepared, &added_d.welcome)?;
    let added_l = a_tree.add_member(l_id, &l_kp_bytes)?;
    d_tree.process_commit(&added_l.commit)?;
    let mut l_tree = TreeKemMlsGroup::join_from_welcome(l_prepared, &added_l.welcome)?;
    let added_t = a_tree.add_member(t_id, &target_kp)?;
    d_tree.process_commit(&added_t.commit)?;
    l_tree.process_commit(&added_t.commit)?;
    let t_tree = TreeKemMlsGroup::join_from_welcome(t_prepared, &added_t.welcome)?;
    let epoch = a_tree.epoch();
    assert_eq!(d_tree.epoch(), epoch);
    assert_eq!(l_tree.epoch(), epoch);
    assert_eq!(t_tree.epoch(), epoch);

    let a_hex = Fixture::hex(&a_id);
    let mut parent =
        x0x::groups::GroupInfo::new("fork-2135".to_string(), String::new(), a_id, GROUP.into());
    parent.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    for (id, role, kp) in [
        (d_id, x0x::groups::GroupRole::Admin, &d_kp_bytes),
        (l_id, x0x::groups::GroupRole::Member, &l_kp_bytes),
        (t_id, x0x::groups::GroupRole::Member, &target_kp),
    ] {
        let id_hex = Fixture::hex(&id);
        parent.add_member(id_hex.clone(), role, Some(a_hex.clone()), None);
        parent.set_member_treekem_key_package(&id_hex, BASE64.encode(kp));
    }
    parent.secret_epoch = epoch;
    parent.security_binding = Some(format!("treekem:epoch={epoch}"));
    parent.roster_revision = parent.roster_revision.saturating_add(1);
    parent.seal_commit(a.agent.identity().agent_keypair(), now_millis_u64())?;

    for (state, tree) in [(&a, a_tree), (&l_state, l_tree), (&t, t_tree)] {
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
    // The scope the daemon's writer sets: the members of A's groups.
    a.agent
        .capability_store()
        .set_sticky_scope([a_id, d_id, l_id, t_id]);
    seed_advert(&a, &a_id, all_bits());
    seed_advert(&a, &d_id, all_bits());
    apply_advert(&a, &l_id, l);
    apply_advert(&a, &t_id, target);
    Ok(Fixture {
        a,
        _a_dir: a_dir,
        l: l_state,
        _l_dir: l_dir,
        t,
        _t_dir: t_dir,
        d_kp,
        d_tree,
        parent,
        target_kp,
        epoch,
    })
}

fn ready() -> Advert {
    Advert::Current(all_bits())
}

fn commit_bound(binding: Option<&str>, epoch: u64) -> bool {
    binding.is_some_and(|binding| binding.starts_with(&format!("treekem:epoch={epoch}:commit=")))
}

/// Drives the 1581e shape on `f`: A removes T through the route; D removes
/// T from the same parent with its own TreeKEM commit, its binding by the
/// same rule. Returns A's head and D's event.
async fn race(f: &mut Fixture) -> Result<(x0x::groups::GroupInfo, NamedGroupMetadataEvent)> {
    let (status, body) = remove_via_route(&f.a, &f.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let a_head = f.head(&f.a).await;
    let d_event = f.d_event_by_rule(false)?;
    Ok((a_head, d_event))
}

/// The 1581e shape, red on main. The two state hashes differ, D's commit
/// is fork evidence on A (a marker naming D, in the stored roster file),
/// L applies D's commit, a replay of D's commit on L is a duplicate, and
/// the manual clear removes the marker in memory and on disk.
#[tokio::test]
async fn a_second_admins_removal_of_the_same_member_is_fork_evidence() -> Result<()> {
    let mut f = fixture(ready(), ready()).await?;
    let (a_head, d_event) = race(&mut f).await?;
    assert!(
        commit_bound(a_head.security_binding.as_deref(), f.epoch + 1),
        "A's removal names its TreeKEM commit: {:?}",
        a_head.security_binding
    );
    let d_hash = signed_commit(&d_event).state_hash;
    assert_ne!(
        d_hash, a_head.state_hash,
        "two admins' removals of one member are distinct states"
    );

    let d_id = f.d_kp.agent_id();
    let on_l = apply_named_group_metadata_event(&f.l, d_event.clone(), d_id, true, None).await;
    assert!(on_l.accepted, "L applies D's removal: {on_l:?}");
    assert_eq!(f.head(&f.l).await.state_hash, d_hash);
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
    // The evidence is in the stored roster file, so it survives a restart.
    let stored = load_named_groups(&f.a.named_groups_path).await?;
    assert_eq!(stored[GROUP].fork_quarantine.as_ref(), Some(&marker));

    // The manual exit (ADR 0066) clears it in memory and on disk.
    let response = clear_group_quarantine(
        State(Arc::clone(&f.a)),
        owner(),
        Path(GROUP.to_string()),
        Json(ClearQuarantineRequest {
            force: true,
            reason: "#2135 fork resolved by hand".to_string(),
        }),
    )
    .await
    .into_response();
    let (status, body) = body_of(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(f.head(&f.a).await.fork_quarantine.is_none());
    let stored = load_named_groups(&f.a.named_groups_path).await?;
    assert!(stored[GROUP].fork_quarantine.is_none());
    Ok(())
}

/// Blocker of the #2173 review: two admins partitioned for longer than the
/// 900 s advert TTL hold no current advert of the others. Each member once
/// showed the bit, so the sticky record keeps the commit-bound form and the
/// fork is found. Red on the previous head: it needed a current advert, so
/// both admins sealed the legacy form, the hashes matched and A took D's
/// commit for a duplicate.
#[tokio::test]
async fn admins_partitioned_past_the_advert_ttl_still_find_the_fork() -> Result<()> {
    let mut f = fixture(Advert::StickyOnly, Advert::StickyOnly).await?;
    let (a_head, d_event) = race(&mut f).await?;
    assert!(
        commit_bound(a_head.security_binding.as_deref(), f.epoch + 1),
        "{:?}",
        a_head.security_binding
    );
    let d_id = f.d_kp.agent_id();
    let on_a = apply_named_group_metadata_event(&f.a, d_event, d_id, true, None).await;
    assert!(!on_a.accepted);
    assert!(
        f.head(&f.a).await.fork_quarantine.is_some(),
        "D's competing removal is fork evidence on A"
    );
    Ok(())
}

/// A verified advert with the bit that then expires leaves the member
/// ready through the sticky record.
#[tokio::test]
async fn an_expired_advert_keeps_the_commit_bound_form() -> Result<()> {
    let f = fixture(Advert::Never, ready()).await?;
    let l_id = f.l.agent.agent_id();
    let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry = x0x::dm::CapabilityRegistry {
        version: 1,
        bits: all_bits(),
    };
    let ttl_ms = x0x::dm_capability::ADVERT_CACHE_TTL_SECS * 1000;
    let store = f.a.agent.capability_store();
    assert!(store.insert(
        l_id,
        x0x::identity::MachineId([4; 32]),
        caps,
        x0x::dm::now_unix_ms() - ttl_ms + 2_000,
    ));
    tokio::time::sleep(std::time::Duration::from_millis(3_500)).await;
    let bit = x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1;
    assert_eq!(
        store.verified_registry_supports(&l_id, bit),
        None,
        "expired"
    );
    let (status, body) = remove_via_route(&f.a, &f.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = f.head(&f.a).await;
    assert!(
        commit_bound(head.security_binding.as_deref(), f.epoch + 1),
        "{:?}",
        head.security_binding
    );
    Ok(())
}

/// A member never seen with the bit, and a member whose current advert
/// dropped it (a downgrade), keep the legacy binding, which every released
/// receiver applies. The state hash form is unchanged.
#[tokio::test]
async fn a_member_never_seen_with_the_bit_keeps_the_legacy_binding() -> Result<()> {
    for downgraded in [false, true] {
        let f = fixture(Advert::Never, ready()).await?;
        if downgraded {
            // It once showed the bit; the later advert without it wins.
            seed_sticky(&f.a, &f.l.agent.agent_id());
            seed_advert(&f.a, &f.l.agent.agent_id(), without_binding_bit());
        }
        let (status, body) = remove_via_route(&f.a, &f.target_hex()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let head = f.head(&f.a).await;
        let legacy = format!("treekem:epoch={}", f.epoch + 1);
        assert_eq!(head.security_binding.as_deref(), Some(legacy.as_str()));
        let mut expected = head.clone();
        expected.recompute_state_hash();
        assert_eq!(expected.state_hash, head.state_hash);
    }
    Ok(())
}

/// Blocker of the #2173 review: the target receives its own removal or ban
/// and must apply it, so it counts in the gate. A target never seen with
/// the bit gets the legacy form, and it applies its own legacy ban and tears
/// its group down. Red on the previous head: the target was left out of the
/// gate, so a released target got a commit-bound ban it refuses.
#[tokio::test]
async fn a_target_never_seen_with_the_bit_gets_the_legacy_form_and_tears_down() -> Result<()> {
    let f = fixture(ready(), Advert::Never).await?;
    let (status, body) = ban_via_route(&f.a, &f.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let legacy = format!("treekem:epoch={}", f.epoch + 1);
    assert_eq!(
        f.head(&f.a).await.security_binding.as_deref(),
        Some(legacy.as_str())
    );

    let mut g = fixture(ready(), Advert::Never).await?;
    let ban = g.d_event_by_rule(true)?;
    assert_eq!(
        signed_commit(&ban).security_binding.as_deref(),
        Some(format!("treekem:epoch={}", g.epoch + 1).as_str())
    );
    let applied = apply_named_group_metadata_event(&g.t, ban, g.d_kp.agent_id(), true, None).await;
    assert!(
        applied.accepted,
        "the target applies its own ban: {applied:?}"
    );
    assert!(
        !g.t.treekem_groups.read().await.contains_key(GROUP),
        "the banned target drops its tree"
    );
    Ok(())
}

/// The ban route follows the same rule as the removal route.
#[tokio::test]
async fn the_ban_route_binds_the_treekem_commit_once_every_member_is_ready() -> Result<()> {
    let ready_fixture = fixture(ready(), ready()).await?;
    let (status, body) = ban_via_route(&ready_fixture.a, &ready_fixture.target_hex()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = ready_fixture.head(&ready_fixture.a).await;
    assert!(head.is_banned(&ready_fixture.target_hex()));
    assert!(
        commit_bound(head.security_binding.as_deref(), ready_fixture.epoch + 1),
        "{:?}",
        head.security_binding
    );

    let mixed = fixture(Advert::Current(without_binding_bit()), ready()).await?;
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
    let mut f = fixture(ready(), ready()).await?;
    let epoch = f.epoch + 1;
    let forged = f.d_event(true, |_, _| treekem_commit_binding(epoch, b"other bytes"))?;
    let refused =
        apply_named_group_metadata_event(&f.l, forged, f.d_kp.agent_id(), true, None).await;
    assert!(!refused.accepted, "a binding over other bytes: {refused:?}");
    assert_eq!(f.head(&f.l).await.state_hash, f.parent.state_hash);

    // `d_event` advanced D's tree; a fresh fixture gives the genuine ban.
    let mut g = fixture(ready(), ready()).await?;
    let genuine = g.d_event(true, |_, bytes| treekem_commit_binding(epoch, bytes))?;
    let signed = signed_commit(&genuine);
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

/// The removal and ban routes make the TreeKEM commit before the seal. A
/// seal that fails rolls the tree back, so the roster and the tree stay at
/// the parent and the next attempt succeeds.
#[tokio::test]
async fn a_failed_seal_rolls_the_tree_back() -> Result<()> {
    for ban in [false, true] {
        let f = fixture(ready(), ready()).await?;
        arm_removal_seal_fault_for_test(&f.a);
        let (status, body) = if ban {
            ban_via_route(&f.a, &f.target_hex()).await
        } else {
            remove_via_route(&f.a, &f.target_hex()).await
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(f.epoch_of(&f.a).await, f.epoch, "the tree is rolled back");
        let head = f.head(&f.a).await;
        assert_eq!(
            head.state_hash, f.parent.state_hash,
            "the roster is unchanged"
        );
        let (status, body) = if ban {
            ban_via_route(&f.a, &f.target_hex()).await
        } else {
            remove_via_route(&f.a, &f.target_hex()).await
        };
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(f.epoch_of(&f.a).await, f.epoch + 1);
    }
    Ok(())
}

/// #2173 review (item 3): the persistence through the daemon's startup
/// path and the real file. A record for L (no advert at all) written before
/// startup makes L ready after it; the writer then writes the scoped record
/// (D and T, whose adverts were cached); when L leaves the group, the next
/// write drops L and keeps the others.
#[tokio::test]
async fn the_sticky_record_survives_a_restart_through_startup() -> Result<()> {
    let f = fixture(Advert::Never, ready()).await?;
    let l_id = f.l.agent.agent_id();
    let bit = x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1;
    let path = crate::server::sticky_capabilities::path_in(&f.a.data_dir);
    crate::server::sticky_capabilities::write(
        &f.a.data_dir,
        &[(
            l_id,
            x0x::dm_capability::StickySeen {
                bits: bit,
                advert_created_at_unix_ms: 1,
            },
        )],
    )
    .await?;
    let store = f.a.agent.capability_store();
    store.set_sticky_scope([]);
    assert!(!store.registry_bit_ready(&l_id, bit));

    let writer = crate::server::sticky_capabilities::start_with_interval(
        &f.a,
        std::time::Duration::from_millis(50),
    )
    .await;
    assert!(
        store.registry_bit_ready(&l_id, bit),
        "the startup load seeds L"
    );
    let on_disk = |want: Vec<AgentId>, gone: Vec<AgentId>| {
        let path = path.clone();
        async move {
            for _ in 0..200 {
                if let Ok(bytes) = tokio::fs::read(&path).await {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    let has = |id: &AgentId| text.contains(&hex::encode(id.as_bytes()));
                    if want.iter().all(has) && !gone.iter().any(has) {
                        return true;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            false
        }
    };
    let d_id = f.d_kp.agent_id();
    let t_id = f.target();
    assert!(
        on_disk(vec![l_id, d_id, t_id], vec![]).await,
        "the writer writes the scoped record"
    );
    {
        let mut groups = f.a.named_groups.write().await;
        if let Some(info) = groups.get_mut(GROUP) {
            info.remove_member(&Fixture::hex(&l_id), None);
        }
    }
    assert!(
        on_disk(vec![d_id, t_id], vec![l_id]).await,
        "L left the group: its record is dropped, the others stay"
    );
    writer.abort();
    Ok(())
}

/// #2173 review round 4: a roster candidate that a failed persist rolls
/// back is never read as the scope. The refresh waits for the persistence
/// lock, so L, whose removal candidate was shown and then restored, keeps
/// its record. Red on e327afc2: the refresh read the candidate and dropped
/// L's record for good.
#[tokio::test]
async fn a_rolled_back_candidate_never_narrows_the_sticky_scope() -> Result<()> {
    let f = fixture(Advert::StickyOnly, ready()).await?;
    let l_id = f.l.agent.agent_id();
    let bit = x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1;
    let store = f.a.agent.capability_store();
    assert!(store.registry_bit_ready(&l_id, bit));
    let committed = f.head(&f.a).await;
    let persisting = f.a.named_groups_persistence_lock.lock().await;
    {
        let mut candidate = committed.clone();
        candidate.remove_member(&Fixture::hex(&l_id), None);
        f.a.named_groups
            .write()
            .await
            .insert(GROUP.to_string(), candidate);
    }
    let refresh = {
        let state = Arc::clone(&f.a);
        tokio::spawn(async move { crate::server::sticky_capabilities::refresh_scope(&state).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    f.a.named_groups
        .write()
        .await
        .insert(GROUP.to_string(), committed);
    drop(persisting);
    refresh.await?;
    assert!(
        store.registry_bit_ready(&l_id, bit),
        "the rolled-back candidate did not drop L's record"
    );
    Ok(())
}

/// #2173 review round 4: the production entry point `start` (what the
/// daemon's startup calls) loads the file into the store.
#[tokio::test]
async fn the_daemon_startup_entry_loads_the_record() -> Result<()> {
    let f = fixture(Advert::Never, ready()).await?;
    let l_id = f.l.agent.agent_id();
    let bit = x0x::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1;
    crate::server::sticky_capabilities::write(
        &f.a.data_dir,
        &[(
            l_id,
            x0x::dm_capability::StickySeen {
                bits: bit,
                advert_created_at_unix_ms: 1,
            },
        )],
    )
    .await?;
    assert!(!f.a.agent.capability_store().registry_bit_ready(&l_id, bit));
    let writer = crate::server::sticky_capabilities::start(&f.a).await;
    assert!(f.a.agent.capability_store().registry_bit_ready(&l_id, bit));
    writer.abort();
    Ok(())
}

/// #2173 review (item 5): the seal fails and the restore fails too. The
/// route answers `treekem_rollback_failed` and the tree is already unloaded
/// when the reply arrives, so no request can use the advanced tree.
#[tokio::test]
async fn a_failed_restore_answers_treekem_rollback_failed_and_unloads_the_tree() -> Result<()> {
    for ban in [false, true] {
        let f = fixture(ready(), ready()).await?;
        arm_removal_seal_fault_for_test(&f.a);
        arm_rollback_restore_fault_for_test(&f.a);
        let (status, body) = if ban {
            ban_via_route(&f.a, &f.target_hex()).await
        } else {
            remove_via_route(&f.a, &f.target_hex()).await
        };
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["error"], TREEKEM_ROLLBACK_FAILED);
        assert!(
            !f.a.treekem_groups.read().await.contains_key(GROUP),
            "the tree is unloaded before the reply"
        );
        assert_eq!(f.head(&f.a).await.state_hash, f.parent.state_hash);
    }
    Ok(())
}

/// The readiness rule: every Active or Pending member other than the actor,
/// and the target, must be ready; removed seats do not count.
#[test]
fn readiness_needs_every_other_live_member_and_the_target() {
    let ids: Vec<AgentId> = (1u8..=5).map(|n| AgentId([n; 32])).collect();
    let hex_of = |id: &AgentId| hex::encode(id.as_bytes());
    let mut info =
        x0x::groups::GroupInfo::new("g".to_string(), String::new(), ids[0], GROUP.into());
    for id in &ids[1..] {
        info.add_member(hex_of(id), x0x::groups::GroupRole::Member, None, None);
    }
    info.remove_member(&hex_of(&ids[1]), None);
    info.remove_member(&hex_of(&ids[4]), None);
    let actor = hex_of(&ids[0]);
    let target = Some(&ids[1]);
    let ready_set = |set: Vec<AgentId>| move |agent: &AgentId| set.contains(agent);
    assert!(removal_commit_binding_peers_ready(
        &info,
        &actor,
        target,
        ready_set(vec![ids[1], ids[2], ids[3]])
    ));
    assert!(!removal_commit_binding_peers_ready(
        &info,
        &actor,
        target,
        ready_set(vec![ids[2], ids[3]])
    ));
    assert!(!removal_commit_binding_peers_ready(
        &info,
        &actor,
        target,
        ready_set(vec![ids[1], ids[2]])
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
