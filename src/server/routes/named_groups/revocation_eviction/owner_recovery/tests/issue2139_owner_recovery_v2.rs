#![cfg(test)]
//! #2139 stage 2: `OwnerRecoveryV2`. One TreeKEM commit, made by saorsa-mls
//! `remove_members`, removes every leafed revoked admin and the held
//! expired creator together, so no removed leaf gets that commit's path
//! secrets.
//!
//! - Real TreeKEM trees: two revoked seats removed in one commit get no new
//!   epoch; the V1 baseline (one commit per seat) gives the second seat the
//!   first commit's epoch; an excluded creator cannot follow later commits.
//! - The receiver's set rule on a real tree ([`v2_removal_proof`]).
//! - Daemon level: the author holds (`waiting_for_receiver_upgrade`, no
//!   frame) while a survivor is not ready, sends V2 to a sticky-ready
//!   survivor that has no current advert, keeps the hold across a restart,
//!   and a second daemon applies the V2 frame.

use super::*;
use x0x::mls::treekem::commit_removals;
use x0x::mls::TreeKemMlsGroup;

fn agent(id: u8) -> AgentId {
    AgentId([id; 32])
}

/// One member's in-step tree and KeyPackage.
struct Seat {
    id: AgentId,
    tree: TreeKemMlsGroup,
    kp: Vec<u8>,
}

/// The committer's tree and each member's tree, added in order; every
/// member follows every later add, so all are in step.
fn in_step(
    group: &[u8],
    committer: AgentId,
    members: &[(AgentId, u8)],
) -> (TreeKemMlsGroup, Vec<Seat>) {
    let mut committer = TreeKemMlsGroup::create(group.to_vec(), committer, &[0xA0; 32]).unwrap();
    let mut seats: Vec<Seat> = Vec::new();
    for (id, seed) in members {
        let prepared = TreeKemMlsGroup::prepare_member(*id, &[*seed; 32]).unwrap();
        let kp = prepared.key_package_bytes().to_vec();
        let added = committer.add_member(*id, &kp).unwrap();
        for seat in &mut seats {
            seat.tree.process_commit(&added.commit).unwrap();
        }
        let tree = TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome).unwrap();
        seats.push(Seat { id: *id, tree, kp });
    }
    for seat in &seats {
        assert_eq!(
            seat.tree.epoch(),
            committer.epoch(),
            "precondition: in step"
        );
    }
    (committer, seats)
}

/// Two revoked seats removed in ONE commit: neither can read the new
/// epoch with its full prior state, while a survivor does.
#[test]
fn two_revoked_seats_removed_in_one_commit_get_no_new_epoch() {
    let (r1, r2, s) = (agent(0x51), agent(0x52), agent(0x5E));
    let (mut committer, mut seats) = in_step(
        b"2139-v2-two",
        agent(0xA0),
        &[(r1, 0x51), (r2, 0x52), (s, 0x5E)],
    );
    let start = committer.epoch();
    let (kp1, kp2) = (seats[0].kp.clone(), seats[1].kp.clone());
    let commit = committer
        .remove_members_verified(&[(r1, &kp1), (r2, &kp2)])
        .unwrap();
    assert_eq!(committer.epoch(), start + 1, "one commit, one epoch");
    assert_eq!(commit_removals(&commit).unwrap().removed_leaves.len(), 2);
    seats[2].tree.process_commit(&commit).unwrap();
    let ciphertext = committer.encrypt_message(b"after the recovery").unwrap();
    assert_eq!(
        seats[2].tree.decrypt_message(&ciphertext).unwrap(),
        b"after the recovery"
    );
    for seat in &mut seats[..2] {
        let applied = seat.tree.process_commit(&commit);
        assert!(
            seat.tree.decrypt_message(&ciphertext).is_err(),
            "{:?} reads nothing of the new epoch (its own apply: {applied:?})",
            seat.id
        );
    }
}

/// The baseline, which is why V1 is not enough: V1 makes one commit per
/// revoked seat, and each commit's path secrets reach every leaf still in
/// the tree, so the second revoked seat gets the first commit's epoch.
#[test]
fn baseline_two_single_removals_give_the_second_seat_an_epoch() {
    let (r1, r2, s) = (agent(0x51), agent(0x52), agent(0x5E));
    let (mut committer, mut seats) = in_step(
        b"2139-v1-two",
        agent(0xA0),
        &[(r1, 0x51), (r2, 0x52), (s, 0x5E)],
    );
    let kp1 = seats[0].kp.clone();
    let first = committer.remove_member_verified(r1, &kp1).unwrap();
    seats[1]
        .tree
        .process_commit(&first)
        .expect("the second revoked seat applies the first removal");
    seats[2].tree.process_commit(&first).unwrap();
    let ciphertext = seats[2].tree.encrypt_message(b"epoch + 1").unwrap();
    assert_eq!(
        seats[1].tree.decrypt_message(&ciphertext).unwrap(),
        b"epoch + 1",
        "the second revoked seat reads the intermediate epoch"
    );
}

/// Limits (i) and (ii) of #2133: the revoked admin holds no leaf, and the
/// held creator is in step. The V2 commit removes the creator's leaf
/// alone. Even holding the commit (a leaked frame), the creator reads
/// nothing of the new epoch and cannot apply the next public commit.
#[test]
fn an_excluded_creator_cannot_follow_the_recovery_or_the_next_commit() {
    let (creator, tolerated) = (agent(0xC1), agent(0x71));
    let (mut committer, mut seats) = in_step(
        b"2139-v2-creator",
        agent(0xA0),
        &[(creator, 0xC1), (tolerated, 0x71)],
    );
    let kp = seats[0].kp.clone();
    let recovery = committer
        .remove_members_verified(&[(creator, &kp)])
        .unwrap();
    seats[1].tree.process_commit(&recovery).unwrap();
    let ciphertext = committer.encrypt_message(b"recovery epoch").unwrap();
    let _ = seats[0].tree.process_commit(&recovery);
    assert!(
        seats[0].tree.decrypt_message(&ciphertext).is_err(),
        "limit (i) closed: the commit holds no path secret for the creator"
    );
    let eviction = committer.remove_member(tolerated).unwrap();
    assert!(
        seats[0].tree.process_commit(&eviction).is_err(),
        "limit (ii) closed: the creator cannot apply the next public commit"
    );
    let later = committer.encrypt_message(b"after the eviction").unwrap();
    assert!(seats[0].tree.decrypt_message(&later).is_err());
}

// ─── The receiver's set rule on a real tree ───────────────────────────────

/// A roster with a committed KeyPackage for each seat.
fn roster_with(seats: &[(AgentId, &[u8])]) -> GroupInfo {
    use base64::Engine as _;
    let mut info = GroupInfo::new(
        "2139-v2".to_string(),
        String::new(),
        agent(0xA0),
        "e2".repeat(16),
    );
    for (id, kp) in seats {
        let id_hex = hex::encode(id.as_bytes());
        info.members_v2.insert(
            id_hex.clone(),
            x0x::groups::GroupMember::new_member(id_hex.clone(), None, None, 1),
        );
        info.set_member_treekem_key_package(
            &id_hex,
            base64::engine::general_purpose::STANDARD.encode(kp),
        );
    }
    info
}

/// A V2 body naming `removed` (leafed) and `excluded`, carrying `commits`.
/// The proof reads only these fields.
fn proof_body(
    info: &GroupInfo,
    removed: &[AgentId],
    excluded: &[AgentId],
    commits: Vec<Vec<u8>>,
) -> orc::OwnerRecoveryBodyV2 {
    let leaf = |id: &AgentId| {
        info.members_v2[&hex::encode(id.as_bytes())]
            .treekem_key_package_hash
            .clone()
    };
    orc::OwnerRecoveryBodyV2 {
        core: orc::OwnerRecoveryBodyV1 {
            stable_group_id: info.stable_group_id().to_string(),
            actor: [0xA0; 32],
            prior_head: String::new(),
            prior_revision: 0,
            next_revision: 1,
            roster_revision: 1,
            mandate: orc::SignedOwnerRecoveryMandateV1 {
                body: orc::OwnerRecoveryMandateBodyV1 {
                    stable_group_id: String::new(),
                    parent_head: String::new(),
                    parent_revision: 0,
                    revoked_admins: Vec::new(),
                    promoted: [0xA0; 32],
                    promoted_certificate_digest: String::new(),
                    owner_public_key: Vec::new(),
                    issued_at_ms: 0,
                },
                signature: Vec::new(),
            },
            promoted_certificate: Vec::new(),
            removed: removed
                .iter()
                .map(|id| orc::RemovedSeatV1 {
                    agent: *id.as_bytes(),
                    leaf_key_package_hash: leaf(id),
                })
                .collect(),
            crypto: orc::OwnerRecoveryCryptoV1::TreeKem {
                commits,
                next_epoch: 0,
            },
            commit: x0x::groups::crypto_exclusion::CommitHeaderV1::from(
                &x0x::groups::GroupStateCommit {
                    group_id: String::new(),
                    revision: 0,
                    prev_state_hash: None,
                    roster_root: String::new(),
                    policy_hash: String::new(),
                    public_meta_hash: String::new(),
                    security_binding: None,
                    state_hash: String::new(),
                    withdrawn: false,
                    committed_by: String::new(),
                    committed_at: 0,
                    signer_public_key: String::new(),
                    signature: String::new(),
                },
            ),
        },
        excluded: excluded
            .iter()
            .map(|id| orc::ExcludedSeatV2 {
                agent: *id.as_bytes(),
                leaf_key_package_hash: leaf(id).unwrap_or_default(),
            })
            .collect(),
        exclusion_anchor_unix: 0,
    }
}

fn forged(commit: &[u8], edit: impl FnOnce(&mut Vec<u32>, u32)) -> Vec<u8> {
    let mut decoded: saorsa_mls::treekem_group::TreeKemCommit =
        postcard::from_bytes(commit).unwrap();
    let committer = decoded.committer_leaf;
    edit(&mut decoded.removed_leaves, committer);
    postcard::to_stdvec(&decoded).unwrap()
}

/// The receiver decides on its own tree, before the commit applies, that
/// a V2 commit removes exactly the targets' leaves, compared as a set.
/// Every other shape is a typed refusal, and a target whose KeyPackage is
/// not held here keeps the frame for a retry.
#[test]
fn a_v2_commit_must_remove_exactly_the_target_leaves() {
    let (r1, r2, x, s) = (agent(0x51), agent(0x52), agent(0x58), agent(0x5E));
    let members = [(r1, 0x51), (r2, 0x52), (x, 0x58), (s, 0x5E)];
    // A fresh group per case: the committer's tree moves with each commit,
    // the receiver's (S) does not.
    let case = |make: &dyn Fn(&mut TreeKemMlsGroup, &[Seat]) -> Vec<u8>,
                removed: &[AgentId],
                excluded: &[AgentId],
                extra_commit: bool| {
        let (mut committer, seats) = in_step(b"2139-v2-proof", agent(0xA0), &members);
        let info = roster_with(
            &seats
                .iter()
                .map(|seat| (seat.id, seat.kp.as_slice()))
                .collect::<Vec<_>>(),
        );
        let commit = make(&mut committer, &seats);
        let mut commits = vec![commit.clone()];
        if extra_commit {
            commits.push(commit);
        }
        let body = proof_body(&info, removed, excluded, commits);
        v2_removal_proof(&seats[3].tree, &info, &body)
    };
    let remove = |ids: &'static [usize]| {
        move |committer: &mut TreeKemMlsGroup, seats: &[Seat]| {
            let pairs: Vec<(AgentId, &[u8])> = ids
                .iter()
                .map(|i| (seats[*i].id, seats[*i].kp.as_slice()))
                .collect();
            committer.remove_members_verified(&pairs).unwrap()
        }
    };
    let refused = |proof: V2RemovalProof| matches!(proof, V2RemovalProof::Refused(_));
    let targets = |ids: &[AgentId]| {
        V2RemovalProof::Exact(ids.iter().map(|id| hex::encode(id.as_bytes())).collect())
    };

    assert_eq!(
        case(&remove(&[0, 1]), &[r1, r2], &[], false),
        targets(&[r1, r2]),
        "the honest commit"
    );
    assert_eq!(
        case(&remove(&[0, 1, 2]), &[r1, r2], &[x], false),
        targets(&[r1, r2, x]),
        "a removed seat and an excluded seat"
    );
    assert!(
        refused(case(&remove(&[0, 1, 2]), &[r1, r2], &[], false)),
        "a commit that also removes a seat the body does not name"
    );
    assert!(
        refused(case(&remove(&[0, 1]), &[r1, r2], &[x], false)),
        "a commit that keeps an excluded seat's leaf"
    );
    assert!(
        refused(case(&remove(&[0, 1]), &[r1, r2], &[], true)),
        "an extra commit"
    );
    let honest = remove(&[0, 1]);
    let reversed = move |committer: &mut TreeKemMlsGroup, seats: &[Seat]| {
        forged(&honest(committer, seats), |leaves, _| leaves.reverse())
    };
    assert_eq!(
        case(&reversed, &[r1, r2], &[], false),
        targets(&[r1, r2]),
        "the signed order is not checked: the list is a set"
    );
    for (name, edit) in [
        (
            "a duplicate leaf",
            Box::new(|leaves: &mut Vec<u32>, _| leaves[1] = leaves[0])
                as Box<dyn Fn(&mut Vec<u32>, u32)>,
        ),
        (
            "an out-of-range leaf",
            Box::new(|leaves, _| leaves[1] = 999),
        ),
        (
            "the committer's own leaf",
            Box::new(|leaves, committer| leaves[1] = committer),
        ),
    ] {
        let honest = remove(&[0, 1]);
        let make = move |committer: &mut TreeKemMlsGroup, seats: &[Seat]| {
            forged(&honest(committer, seats), |leaves, own| edit(leaves, own))
        };
        match case(&make, &[r1, r2], &[], false) {
            V2RemovalProof::Refused(reason) => {
                assert!(reason.starts_with("removal_list"), "{name}: {reason}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    let add = |committer: &mut TreeKemMlsGroup, _: &[Seat]| {
        let prepared = TreeKemMlsGroup::prepare_member(agent(0x77), &[0x77; 32]).unwrap();
        committer
            .add_member(agent(0x77), prepared.key_package_bytes())
            .unwrap()
            .commit
    };
    assert_eq!(
        case(&add, &[r1], &[], false),
        V2RemovalProof::Refused("commit_adds_a_leaf".to_string())
    );

    // A target whose committed KeyPackage is not held here.
    let (mut committer, seats) = in_step(b"2139-v2-proof", agent(0xA0), &members);
    let mut info = roster_with(
        &seats
            .iter()
            .map(|seat| (seat.id, seat.kp.as_slice()))
            .collect::<Vec<_>>(),
    );
    let commit = remove(&[0, 1])(&mut committer, &seats);
    let body = proof_body(&info, &[r1, r2], &[], vec![commit]);
    let r2_hex = hex::encode(r2.as_bytes());
    info.members_v2
        .get_mut(&r2_hex)
        .unwrap()
        .treekem_key_package_b64 = None;
    assert_eq!(
        v2_removal_proof(&seats[3].tree, &info, &body),
        V2RemovalProof::Unproven(vec![r2_hex])
    );
}

// ─── Daemon level ──────────────────────────────────────────────────────────

/// The #2133 mixed case on TreeKEM (the stage-1 test
/// `known_limit_2139_a_leafless_recovery_leaves_the_expired_creator_in_step`):
/// the revoked admin holds no leaf, the creator C is a Member held on its
/// own expired certificate with a leaf, and a revoked Member T with a leaf
/// is tolerated. Returns the promoted member's state, the parent, the
/// tree, C's in-step tree, and C's and T's IDs.
struct V2Fixture {
    _dir: tempfile::TempDir,
    state: Arc<AppState>,
    info: GroupInfo,
    stable: String,
    tree: Arc<tokio::sync::Mutex<TreeKemMlsGroup>>,
    creator_tree: TreeKemMlsGroup,
    creator: AgentId,
    tolerated: AgentId,
    tolerated_tree: TreeKemMlsGroup,
    survivors: Vec<(AgentId, TreeKemMlsGroup)>,
}

fn member_seat(
    owner: &x0x::identity::UserKeypair,
    agent: &x0x::identity::AgentKeypair,
    not_after: Option<u64>,
) -> x0x::groups::GroupMember {
    let cert = x0x::identity::AgentCertificate::issue_with_expiry(owner, agent, not_after).unwrap();
    let mut member = x0x::groups::GroupMember::new_member(
        hex::encode(agent.agent_id().as_bytes()),
        None,
        None,
        1,
    );
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    member
}

/// `survivors`: extra non-revoked Members with a leaf, added last.
async fn v2_fixture(survivors: &[&x0x::identity::AgentKeypair]) -> V2Fixture {
    use base64::Engine as _;
    let (dir, state, mut info, admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local = state.agent.agent_id();
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let tolerated = x0x::identity::AgentKeypair::generate().unwrap();
    let group_id_bytes = hex::decode(&info.mls_group_id).unwrap();
    let mut tree = TreeKemMlsGroup::create(group_id_bytes, local, &[0x5A; 32]).unwrap();
    let mut trees: Vec<TreeKemMlsGroup> = Vec::new();
    // The promoted member's own committed KeyPackage (the same seed names
    // the same leaf), so a receiver accounts for every leaf of the tree.
    let own_kp = TreeKemMlsGroup::prepare_member(local, &[0x5A; 32])
        .unwrap()
        .key_package_bytes()
        .to_vec();
    assert!(tree.has_key_package_leaf(&own_kp));
    let mut packages: Vec<(String, Vec<u8>)> = vec![(hex::encode(local.as_bytes()), own_kp)];
    let joiners: Vec<&x0x::identity::AgentKeypair> = [&creator, &tolerated]
        .into_iter()
        .chain(survivors.iter().copied())
        .collect();
    for (n, joiner) in joiners.iter().enumerate() {
        let id = joiner.agent_id();
        let prepared = TreeKemMlsGroup::prepare_member(id, &[0xC0 + n as u8; 32]).unwrap();
        let kp = prepared.key_package_bytes().to_vec();
        let added = tree.add_member(id, &kp).unwrap();
        for member in &mut trees {
            member.process_commit(&added.commit).unwrap();
        }
        trees.push(TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome).unwrap());
        packages.push((hex::encode(id.as_bytes()), kp));
    }
    let epoch = tree.epoch();
    let now = x0x::groups::owner_cert::restore_clock_now();
    info.members_v2.insert(
        hex::encode(creator.agent_id().as_bytes()),
        member_seat(owner, &creator, Some(now.saturating_sub(2 * 3_600))),
    );
    for keypair in std::iter::once(&tolerated).chain(survivors.iter().copied()) {
        info.members_v2.insert(
            hex::encode(keypair.agent_id().as_bytes()),
            member_seat(owner, keypair, None),
        );
    }
    for (id_hex, kp) in &packages {
        info.set_member_treekem_key_package(
            id_hex,
            base64::engine::general_purpose::STANDARD.encode(kp),
        );
    }
    assert!(info.members_v2[&admin_hex]
        .treekem_key_package_hash
        .is_none());
    info.creator = creator.agent_id();
    info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    info.recompute_state_hash();
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    assert!(info.creator_expired_certificate_hold(&creator_hex, now));
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(tolerated.agent_id()),
        tolerated.public_key(),
        tolerated.secret_key(),
        1,
        None,
    )
    .unwrap();
    assert!(state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)
        .unwrap());
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());
    let tree = Arc::new(tokio::sync::Mutex::new(tree));
    state
        .treekem_groups
        .write()
        .await
        .insert(stable.clone(), Arc::clone(&tree));
    let mut trees = trees.into_iter();
    let creator_tree = trees.next().unwrap();
    let tolerated_tree = trees.next().unwrap();
    V2Fixture {
        _dir: dir,
        state,
        info,
        stable,
        tree,
        creator_tree,
        creator: creator.agent_id(),
        tolerated: tolerated.agent_id(),
        tolerated_tree,
        survivors: survivors
            .iter()
            .map(|keypair| keypair.agent_id())
            .zip(trees)
            .collect(),
    }
}

/// The sticky record holds `owner_recovery_v2` for `agent` (a member of
/// this node's groups) with no current advert.
async fn sticky_v2(state: &AppState, agent: &AgentId) {
    crate::server::sticky_capabilities::refresh_scope(state).await;
    state.agent.capability_store().seed_sticky([(
        *agent,
        x0x::dm_capability::StickySeen {
            bits: x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V2,
            advert_created_at_unix_ms: 1,
        },
    )]);
}

async fn attempt(f: &V2Fixture) {
    let owner = f.state.agent.identity().user_keypair().unwrap();
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    let (status, Json(body)) = sign_recovery_mandate(&f.state, owner, &f.stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(&f.state, &f.info).await;
    try_commit(&f.state, &f.stable).await;
}

/// What left this node for the recovery: its delivery and its catch-up
/// log. A held recovery has neither.
async fn outbox(state: &AppState, stable: &str) -> (Option<Vec<u8>>, usize) {
    let inner = state.revocation_evictions.inner.lock().await;
    (
        inner
            .orc
            .deliveries
            .get(stable)
            .map(|delivery| delivery.bytes.to_vec()),
        inner
            .orc
            .log
            .catchup_frames(std::slice::from_ref(&stable.to_string()), 0)
            .len(),
    )
}

/// The V2 hold: T, a survivor never seen with `owner_recovery_v2`, holds
/// the recovery. Nothing is committed and no frame (V1 or V2) is written;
/// the held mandate shows `waiting_for_receiver_upgrade` naming T, with
/// the capability. The creator keeps its leaf, so nothing reached it.
#[tokio::test]
async fn a_survivor_not_ready_for_v2_holds_the_recovery_with_no_frame() {
    let f = v2_fixture(&[]).await;
    attempt(&f).await;
    let head = f.state.named_groups.read().await[&f.stable].clone();
    assert_eq!(head.state_hash, f.info.state_hash, "nothing committed");
    assert_eq!(outbox(&f.state, &f.stable).await, (None, 0), "no frame");
    assert!(f.tree.lock().await.tracks_member(&f.creator));
    let status = status_json(&f.state, &f.stable).await;
    assert_eq!(
        status["promoted_member"]["state"], "waiting_for_receiver_upgrade",
        "{status}"
    );
    assert_eq!(status["promoted_member"]["capability"], "owner_recovery_v2");
    assert_eq!(
        status["promoted_member"]["named"],
        serde_json::json!([hex::encode(f.tolerated.as_bytes())])
    );
    // A current advert that lacks bit 23 holds it too.
    advertise(
        &f.state,
        f.tolerated,
        x0x::dm::CapabilityRegistry::current().bits
            & !x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V2,
        x0x::dm::now_unix_ms(),
    );
    try_commit(&f.state, &f.stable).await;
    assert_eq!(outbox(&f.state, &f.stable).await, (None, 0));
}

/// A restart in the middle of the hold: the held mandate is durable, so
/// the next attempt after the restart holds again and still writes no
/// frame; once T is ready, the same mandate commits V2.
#[tokio::test]
async fn a_restart_mid_hold_resumes_the_hold() {
    let f = v2_fixture(&[]).await;
    attempt(&f).await;
    assert_eq!(outbox(&f.state, &f.stable).await, (None, 0));
    {
        // The restart: memory is gone, the pending-mandate file stays.
        let mut inner = f.state.revocation_evictions.inner.lock().await;
        inner.orc.pending.clear();
        inner.orc.mandates_restored = false;
    }
    restore_mandates(&f.state).await;
    try_commit(&f.state, &f.stable).await;
    assert_eq!(
        status_json(&f.state, &f.stable).await["promoted_member"]["state"],
        "waiting_for_receiver_upgrade",
        "the restored mandate holds again"
    );
    assert_eq!(outbox(&f.state, &f.stable).await, (None, 0));
    sticky_v2(&f.state, &f.tolerated).await;
    try_commit(&f.state, &f.stable).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    assert!(frame.is_some_and(|bytes| bytes.starts_with(orc::OWNER_RECOVERY_V2_PREFIX)));
}

/// T has no current advert (offline) but the sticky record holds
/// `owner_recovery_v2` for it: the author commits V2 at once. The frame is
/// `X0XORC2`, its one commit removes the creator's leaf, the creator stays
/// seated and is no recipient, and the creator's in-step tree can neither
/// read the recovery epoch nor apply the next public commit (closing
/// limits (i) and (ii) of #2133).
#[tokio::test]
async fn a_sticky_ready_offline_survivor_gets_v2_and_the_creator_gets_no_keys() {
    let mut f = v2_fixture(&[]).await;
    sticky_v2(&f.state, &f.tolerated).await;
    attempt(&f).await;
    let committed = f.state.named_groups.read().await[&f.stable].clone();
    assert_eq!(committed.state_revision, f.info.state_revision + 1);
    let creator_hex = hex::encode(f.creator.as_bytes());
    assert_eq!(
        committed.members_v2[&creator_hex].state,
        x0x::groups::GroupMemberState::Active,
        "the creator stays seated"
    );
    let (frame, logged) = outbox(&f.state, &f.stable).await;
    let bytes = frame.expect("a delivery");
    assert_eq!(logged, 1);
    let Ok(orc::OwnerRecoveryFrameV1::CommitV2(signed)) = orc::decode_frame(&bytes) else {
        panic!("an X0XORC2 commit frame");
    };
    assert_eq!(
        signed
            .body
            .excluded
            .iter()
            .map(|seat| seat.agent)
            .collect::<Vec<_>>(),
        vec![*f.creator.as_bytes()]
    );
    let orc::OwnerRecoveryCryptoV1::TreeKem {
        commits,
        next_epoch,
    } = &signed.body.core.crypto
    else {
        panic!("TreeKEM");
    };
    assert_eq!(commits.len(), 1);
    assert_eq!(*next_epoch, f.info.secret_epoch + 1, "the epoch moves");
    assert_eq!(
        committed.security_binding.as_deref(),
        Some(orc::treekem_binding_v2(*next_epoch, &commits[0]).as_str())
    );
    {
        let inner = f.state.revocation_evictions.inner.lock().await;
        let delivery = &inner.orc.deliveries[&f.stable];
        assert!(!delivery.recipients.contains_key(f.creator.as_bytes()));
        assert!(delivery.recipients.contains_key(f.tolerated.as_bytes()));
    }
    let mut tree = f.tree.lock().await;
    assert!(!tree.tracks_member(&f.creator));
    f.tolerated_tree.process_commit(&commits[0]).unwrap();
    let ciphertext = tree.encrypt_message(b"recovery epoch").unwrap();
    assert_eq!(
        f.tolerated_tree.decrypt_message(&ciphertext).unwrap(),
        b"recovery epoch"
    );
    let _ = f.creator_tree.process_commit(&commits[0]);
    assert!(f.creator_tree.decrypt_message(&ciphertext).is_err());
    let eviction = tree.remove_member(f.tolerated).unwrap();
    assert!(f.creator_tree.process_commit(&eviction).is_err());
}

/// End to end: a second daemon (survivor R, sticky-ready) receives the V2
/// frame the author wrote and applies it: its head and its TreeKEM epoch
/// move, and its tree no longer holds the creator's leaf.
#[tokio::test]
async fn a_survivor_daemon_applies_the_v2_frame() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let r_id = r_keypair.agent_id();
    let mut f = v2_fixture(&[r_keypair]).await;
    for agent in [f.tolerated, r_id] {
        sticky_v2(&f.state, &agent).await;
    }
    // The receiver holds the same parent and the author's revocations.
    let records = f.state.agent.revocation_set().read().await.all_records();
    for record in records {
        let _ = receiver
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None);
    }
    receiver
        .named_groups
        .write()
        .await
        .insert(f.stable.clone(), f.info.clone());
    let (_, r_tree) = f.survivors.pop().unwrap();
    let r_tree = Arc::new(tokio::sync::Mutex::new(r_tree));
    receiver
        .treekem_groups
        .write()
        .await
        .insert(f.stable.clone(), Arc::clone(&r_tree));

    attempt(&f).await;
    let author_head = f.state.named_groups.read().await[&f.stable].clone();
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.expect("the author committed V2");
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    let outcome = receive_commit(&receiver, f.state.agent.agent_id(), commit, &bytes).await;
    assert_eq!(outcome, ReceiveOutcome::Applied);
    let head = receiver.named_groups.read().await[&f.stable].clone();
    assert_eq!(head.state_hash, author_head.state_hash);
    let tree = r_tree.lock().await;
    assert_eq!(tree.epoch(), author_head.secret_epoch);
    let creator_kp = {
        use base64::Engine as _;
        let b64 = f.info.members_v2[&hex::encode(f.creator.as_bytes())]
            .treekem_key_package_b64
            .clone()
            .unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    };
    assert!(!tree.has_key_package_leaf(&creator_kp));
}
