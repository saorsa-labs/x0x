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

/// The #2133 mixed case on TreeKEM: the promoted member P (this daemon),
/// a revoked admin (a leaf only with `admin_leaf`), the creator C (a Member
/// held on its own expired certificate, with a leaf unless
/// `creator_leafless`, which models the state after an earlier V2), a
/// revoked Member T with a leaf (tolerated), and `survivors` (unrevoked
/// Members with a leaf). Every member's tree is in step.
struct V2Fixture {
    _dir: tempfile::TempDir,
    state: Arc<AppState>,
    info: GroupInfo,
    stable: String,
    tree: Arc<tokio::sync::Mutex<TreeKemMlsGroup>>,
    creator_keys: Option<x0x::identity::AgentKeypair>,
    creator: AgentId,
    creator_tree: TreeKemMlsGroup,
    tolerated: AgentId,
    tolerated_tree: Option<TreeKemMlsGroup>,
    survivors: Vec<(AgentId, TreeKemMlsGroup)>,
}

#[derive(Default)]
struct Shape<'a> {
    survivors: &'a [&'a x0x::identity::AgentKeypair],
    creator: Option<&'a x0x::identity::AgentKeypair>,
    admin_leaf: bool,
    creator_leafless: bool,
    /// T commits a KeyPackage but was never added to the tree, so its own
    /// eviction is roster-only and keeps the epoch.
    tolerated_leafless: bool,
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

async fn v2_fixture(shape: Shape<'_>) -> V2Fixture {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let (dir, state, mut info, admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local = state.agent.agent_id();
    let own_keys = match shape.creator {
        Some(_) => None,
        None => Some(x0x::identity::AgentKeypair::generate().unwrap()),
    };
    let creator: &x0x::identity::AgentKeypair = match (shape.creator, own_keys.as_ref()) {
        (Some(keys), _) | (None, Some(keys)) => keys,
        (None, None) => unreachable!(),
    };
    let tolerated = x0x::identity::AgentKeypair::generate().unwrap();
    let group_id_bytes = hex::decode(&info.mls_group_id).unwrap();
    let mut tree = TreeKemMlsGroup::create(group_id_bytes, local, &[0x5A; 32]).unwrap();
    // The promoted member's own committed KeyPackage (the same seed names
    // the same leaf), so a receiver accounts for every leaf of the tree.
    let own_kp = TreeKemMlsGroup::prepare_member(local, &[0x5A; 32])
        .unwrap()
        .key_package_bytes()
        .to_vec();
    let mut packages: Vec<(String, Vec<u8>)> = vec![(hex::encode(local.as_bytes()), own_kp)];
    let mut trees: Vec<TreeKemMlsGroup> = Vec::new();
    if shape.admin_leaf {
        let admin_id = AgentId(<[u8; 32]>::try_from(hex::decode(&admin_hex).unwrap()).unwrap());
        let prepared = TreeKemMlsGroup::prepare_member(admin_id, &[0xAD; 32]).unwrap();
        let kp = prepared.key_package_bytes().to_vec();
        tree.add_member(admin_id, &kp).unwrap();
        packages.push((admin_hex.clone(), kp));
    }
    let joiners: Vec<&x0x::identity::AgentKeypair> = [creator]
        .into_iter()
        .chain((!shape.tolerated_leafless).then_some(&tolerated))
        .chain(shape.survivors.iter().copied())
        .collect();
    if shape.tolerated_leafless {
        let kp = TreeKemMlsGroup::prepare_member(tolerated.agent_id(), &[0x7F; 32])
            .unwrap()
            .key_package_bytes()
            .to_vec();
        packages.push((hex::encode(tolerated.agent_id().as_bytes()), kp));
    }
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
    if shape.creator_leafless {
        let creator_kp = packages
            .iter()
            .find(|(id, _)| *id == hex::encode(creator.agent_id().as_bytes()))
            .unwrap()
            .1
            .clone();
        let earlier = tree
            .remove_members_verified(&[(creator.agent_id(), creator_kp.as_slice())])
            .unwrap();
        for member in trees.iter_mut().skip(1) {
            member.process_commit(&earlier).unwrap();
        }
    }
    let epoch = tree.epoch();
    let now = x0x::groups::owner_cert::restore_clock_now();
    info.members_v2.insert(
        hex::encode(creator.agent_id().as_bytes()),
        member_seat(owner, creator, Some(now.saturating_sub(2 * 3_600))),
    );
    for keypair in std::iter::once(&tolerated).chain(shape.survivors.iter().copied()) {
        info.members_v2.insert(
            hex::encode(keypair.agent_id().as_bytes()),
            member_seat(owner, keypair, None),
        );
    }
    for (id_hex, kp) in &packages {
        info.set_member_treekem_key_package(id_hex, b64.encode(kp));
    }
    info.creator = creator.agent_id();
    info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    info.recompute_state_hash();
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    assert!(info.creator_expired_certificate_hold(&creator_hex, now));
    revoke_agent(&state, &tolerated).await;
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
    let tolerated_tree = (!shape.tolerated_leafless).then(|| trees.next().unwrap());
    V2Fixture {
        _dir: dir,
        state,
        info,
        stable,
        tree,
        creator: creator.agent_id(),
        creator_keys: own_keys,
        creator_tree,
        tolerated: tolerated.agent_id(),
        tolerated_tree,
        survivors: shape
            .survivors
            .iter()
            .map(|keypair| keypair.agent_id())
            .zip(trees)
            .collect(),
    }
}

async fn revoke_agent(state: &AppState, agent: &x0x::identity::AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(agent.agent_id()),
        agent.public_key(),
        agent.secret_key(),
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
}

fn bits_without_v2() -> u64 {
    x0x::dm::CapabilityRegistry::current().bits & !x0x::dm::CapabilityRegistry::OWNER_RECOVERY_V2
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

/// The holder set is the delivery's write set. T is revoked, so the
/// recovery frame is never written to it, and its advert that lacks bit 23
/// does not hold the recovery: V2 commits. Red on 2f80bf60, where T held it.
#[tokio::test]
async fn a_survivor_the_frame_is_not_written_to_never_holds_it() {
    let f = v2_fixture(Shape::default()).await;
    advertise(
        &f.state,
        f.tolerated,
        bits_without_v2(),
        x0x::dm::now_unix_ms(),
    );
    attempt(&f).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    assert!(frame.is_some_and(|bytes| bytes.starts_with(orc::OWNER_RECOVERY_V2_PREFIX)));
}

/// D76 (ADR 0110 §4b(1)): an unrevoked survivor R whose current verified
/// advert lacks bit 23 holds the V2 recovery. Nothing is committed, no
/// frame is written (no V1 either), and the status names R and the
/// capability.
#[tokio::test]
async fn a_known_lacking_survivor_holds_v2_and_no_v1_is_sent() {
    let r = x0x::identity::AgentKeypair::generate().unwrap();
    let f = v2_fixture(Shape {
        survivors: &[&r],
        ..Shape::default()
    })
    .await;
    advertise(
        &f.state,
        r.agent_id(),
        bits_without_v2(),
        x0x::dm::now_unix_ms(),
    );
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
        serde_json::json!([hex::encode(r.agent_id().as_bytes())])
    );
}

/// A restart in the middle of the hold: the held mandate is durable, so
/// the next attempt holds again and writes no frame; once R's advert sets
/// bit 23, the same mandate commits V2.
#[tokio::test]
async fn a_restart_mid_hold_resumes_the_hold() {
    let r = x0x::identity::AgentKeypair::generate().unwrap();
    let f = v2_fixture(Shape {
        survivors: &[&r],
        ..Shape::default()
    })
    .await;
    let at = x0x::dm::now_unix_ms();
    advertise(&f.state, r.agent_id(), bits_without_v2(), at);
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
    advertise(
        &f.state,
        r.agent_id(),
        x0x::dm::CapabilityRegistry::current().bits,
        at + 1,
    );
    try_commit(&f.state, &f.stable).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    assert!(frame.is_some_and(|bytes| bytes.starts_with(orc::OWNER_RECOVERY_V2_PREFIX)));
}

/// V2 commits with T unknown (no advert). The frame is `X0XORC2`, its one
/// commit removes the creator's leaf, the creator stays seated and is no
/// recipient, and the creator's in-step tree can neither read the recovery
/// epoch nor apply the next public commit (limits (i) and (ii) of #2133).
#[tokio::test]
async fn v2_commits_and_the_creator_gets_no_keys() {
    let mut f = v2_fixture(Shape::default()).await;
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
    let tolerated_tree = f.tolerated_tree.as_mut().unwrap();
    tolerated_tree.process_commit(&commits[0]).unwrap();
    let ciphertext = tree.encrypt_message(b"recovery epoch").unwrap();
    assert_eq!(
        tolerated_tree.decrypt_message(&ciphertext).unwrap(),
        b"recovery epoch"
    );
    let _ = f.creator_tree.process_commit(&commits[0]);
    assert!(f.creator_tree.decrypt_message(&ciphertext).is_err());
    let eviction = tree.remove_member(f.tolerated).unwrap();
    assert!(f.creator_tree.process_commit(&eviction).is_err());
}

/// A second owner recovery when an earlier V2 already left the creator
/// without a leaf: the creator is not excluded again (its KeyPackage names
/// no live leaf), so the recovery commits V1 for the one leafed revoked
/// admin. Red on 2f80bf60: the creator was named again, `remove_members`
/// failed on its blank leaf on every attempt, and the status stayed the
/// bare `mandate_received`.
#[tokio::test]
async fn a_second_recovery_with_a_leafless_creator_commits() {
    let f = v2_fixture(Shape {
        admin_leaf: true,
        creator_leafless: true,
        ..Shape::default()
    })
    .await;
    attempt(&f).await;
    let committed = f.state.named_groups.read().await[&f.stable].clone();
    assert_eq!(
        committed.state_revision,
        f.info.state_revision + 1,
        "it commits"
    );
    let (frame, _) = outbox(&f.state, &f.stable).await;
    assert!(frame.is_some_and(|bytes| bytes.starts_with(orc::OWNER_RECOVERY_PREFIX)));
}

/// A commit attempt that fails after its checks shows a typed wait, not the
/// bare `mandate_received`.
#[tokio::test]
async fn a_failed_commit_attempt_shows_a_typed_wait() {
    let f = v2_fixture(Shape::default()).await;
    f.state.treekem_groups.write().await.remove(&f.stable);
    attempt(&f).await;
    assert_eq!(
        status_json(&f.state, &f.stable).await["promoted_member"]["state"],
        RECOVERY_COMMIT_FAILED
    );
}

/// The receiving side: a second daemon R. Returns R's state and its tree.
async fn receiver_for(
    f: &mut V2Fixture,
    receiver: &Arc<AppState>,
) -> Arc<tokio::sync::Mutex<TreeKemMlsGroup>> {
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
    r_tree
}

/// R has no advert when the author commits, so it is stranded: the frame is
/// not written to it, and the status names it with the capability. Once R
/// advertises bit 23, the gated carrier admits the frame (a bit-7-only
/// advert is refused), and R applies the frame that the author's catch-up
/// log serves: its head and epoch reach the V2 head and its tree no longer
/// holds the creator's leaf.
#[tokio::test]
async fn an_unknown_survivor_is_stranded_and_catches_up_after_it_upgrades() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let r_id = r_keypair.agent_id();
    let mut f = v2_fixture(Shape {
        survivors: &[r_keypair],
        ..Shape::default()
    })
    .await;
    let r_tree = receiver_for(&mut f, &receiver).await;
    attempt(&f).await;
    let author_head = f.state.named_groups.read().await[&f.stable].clone();
    assert_eq!(author_head.state_revision, f.info.state_revision + 1);
    drive_deliveries(&f.state).await;
    let status = status_json(&f.state, &f.stable).await;
    let stranded = status["receiver_upgrade_members"].as_array().unwrap();
    let r_row = stranded
        .iter()
        .find(|row| row["agent_id"] == hex::encode(r_id.as_bytes()))
        .unwrap_or_else(|| panic!("R is named: {status}"));
    assert_eq!(r_row["advert"], "unknown");
    assert_eq!(r_row["capability"], "owner_recovery_v2");

    let frames = f
        .state
        .revocation_evictions
        .inner
        .lock()
        .await
        .orc
        .log
        .catchup_frames(std::slice::from_ref(&f.stable), f.info.state_revision);
    let (_, head, bytes) = frames
        .into_iter()
        .next()
        .expect("the catch-up log serves the frame");
    // The carrier admission that `send_guarded` and the catch-up serve
    // use, gated on the frame's own bit (23 for `X0XORC2`).
    let admitted = || async {
        guarded_admission_for(
            &f.state,
            &f.stable,
            &r_id,
            HeadRule::OnChain(head.clone()),
            frame_capability(&bytes).0,
        )()
        .await
        .is_some_and(|seam| seam())
    };
    let at = x0x::dm::now_unix_ms();
    advertise(&f.state, r_id, bits_without_v2(), at.saturating_sub(1_000));
    assert!(
        !admitted().await,
        "a bit-7-only receiver is not written the frame"
    );
    advertise(
        &f.state,
        r_id,
        x0x::dm::CapabilityRegistry::current().bits,
        at,
    );
    assert!(
        admitted().await,
        "an upgraded receiver is written the frame"
    );
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

/// A receiver that lacks the excluded creator's certificate bytes keeps the
/// V2 frame for a retry (`recovery_exclusion_unproven`); it does not refuse
/// it.
#[tokio::test]
async fn a_receiver_without_the_certificate_bytes_keeps_the_frame() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let mut f = v2_fixture(Shape {
        survivors: &[r_keypair],
        ..Shape::default()
    })
    .await;
    let _r_tree = receiver_for(&mut f, &receiver).await;
    attempt(&f).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.unwrap();
    {
        let mut groups = receiver.named_groups.write().await;
        let info = groups.get_mut(&f.stable).unwrap();
        info.members_v2
            .get_mut(&hex::encode(f.creator.as_bytes()))
            .unwrap()
            .certificate = None;
    }
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    let outcome = receive_commit(&receiver, f.state.agent.agent_id(), commit, &bytes).await;
    assert!(
        matches!(outcome, ReceiveOutcome::Retained { .. }),
        "kept for a retry: {outcome:?}"
    );
}

/// The excluded creator's own node: the V2 frame verifies, cannot apply
/// (it removes this node's leaf), and the node shows the typed state
/// `excluded_by_owner_recovery` with its remedy. Its head stays.
#[tokio::test]
async fn the_excluded_creator_shows_a_typed_state() {
    let (_cdir, creator_node, _, _) = recovery_fixture().await;
    let creator_keys = creator_node.agent.identity().agent_keypair();
    let f = v2_fixture(Shape {
        creator: Some(creator_keys),
        ..Shape::default()
    })
    .await;
    assert!(f.creator_keys.is_none());
    let records = f.state.agent.revocation_set().read().await.all_records();
    for record in records {
        let _ = creator_node
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None);
    }
    creator_node
        .named_groups
        .write()
        .await
        .insert(f.stable.clone(), f.info.clone());
    creator_node.treekem_groups.write().await.insert(
        f.stable.clone(),
        Arc::new(tokio::sync::Mutex::new(f.creator_tree)),
    );
    attempt_on(&f.state, &f.stable, &f.info).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.unwrap();
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    let outcome = receive_commit(&creator_node, f.state.agent.agent_id(), commit, &bytes).await;
    assert_eq!(outcome, ReceiveOutcome::NotApplicable);
    let status = status_json(&creator_node, &f.stable).await;
    assert_eq!(
        status["local_seat"]["state"], EXCLUDED_BY_OWNER_RECOVERY,
        "{status}"
    );
    assert_eq!(
        status["local_seat"]["remedy"],
        "admin_removes_then_local_leave_and_new_invite"
    );
    assert_eq!(
        creator_node.named_groups.read().await[&f.stable].state_hash,
        f.info.state_hash
    );
}

async fn attempt_on(state: &Arc<AppState>, stable: &str, info: &GroupInfo) {
    let owner = state.agent.identity().user_keypair().unwrap();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (status, Json(body)) = sign_recovery_mandate(state, owner, stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(state, info).await;
    try_commit(state, stable).await;
}

// ─── #2197: the exit for a leafless seat ──────────────────────────────────

/// The roster-only `MemberRemoved` the author's route just committed for
/// `target`, rebuilt from its retained head commit.
async fn last_roster_only_removal(
    f: &V2Fixture,
    target: &str,
) -> crate::server::NamedGroupMetadataEvent {
    let info = f.state.named_groups.read().await[&f.stable].clone();
    let commit = info.commit_log.last().unwrap().commit.clone();
    assert_eq!(commit.state_hash, info.state_hash);
    crate::server::NamedGroupMetadataEvent::MemberRemoved {
        target_key_package_b64: None,
        group_id: f.stable.clone(),
        revision: info.roster_revision,
        actor: hex::encode(f.state.agent.agent_id().as_bytes()),
        agent_id: target.to_string(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    }
}

/// After a V2 recovery the creator is Active with no leaf. An admin's
/// removal of it is roster-only: no TreeKEM commit, no epoch or binding
/// change. A receiver applies it by its own proof (the creator's
/// KeyPackage names no leaf in its tree) and reaches the same head. An
/// ordinary TreeKEM removal then works again, and a roster-only removal
/// of a seat that still holds a leaf is refused by the receiver.
#[tokio::test]
async fn an_admin_removes_the_leafless_creator_roster_only() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let r_id = r_keypair.agent_id();
    let s_keypair = x0x::identity::AgentKeypair::generate().unwrap();
    let mut f = v2_fixture(Shape {
        survivors: &[&s_keypair, r_keypair],
        tolerated_leafless: true,
        ..Shape::default()
    })
    .await;
    let _r_tree = receiver_for(&mut f, &receiver).await;
    attempt(&f).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.unwrap();
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    let author = f.state.agent.agent_id();
    assert_eq!(
        receive_commit(&receiver, author, commit, &bytes).await,
        ReceiveOutcome::Applied
    );
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(author.as_bytes());
    // T is revoked: an owner-certified group seals nothing else until T is
    // evicted (ADR-0038), so the S4 eviction runs first; it spares the held
    // creator. The receiver takes the resulting roster (its tree already
    // shows the creator without a leaf).
    let evicted = crate::server::routes::named_groups::owner_certified_seal_with_eviction(
        &f.state, &f.stable, &local_hex,
    )
    .await
    .expect("an owner-certified group");
    assert!(
        evicted.is_ok()
            || !f.state.named_groups.read().await[&f.stable]
                .has_active_member(&hex::encode(f.tolerated.as_bytes()))
    );
    let before = f.state.named_groups.read().await[&f.stable].clone();
    assert!(
        before.has_active_member(&creator_hex),
        "the creator is spared"
    );
    receiver
        .named_groups
        .write()
        .await
        .insert(f.stable.clone(), before.clone());
    assert!(
        crate::server::routes::named_groups::treekem_seat_is_provably_leafless(
            &f.state,
            &f.stable,
            &before,
            &creator_hex
        )
        .await
    );
    // Gate: a member whose current advert lacks bit 23 holds it.
    let at = x0x::dm::now_unix_ms();
    advertise(&f.state, r_id, bits_without_v2(), at);
    let (status, Json(body)) =
        crate::server::routes::named_groups::remove_treekem_named_group_member(
            Arc::clone(&f.state),
            f.stable.clone(),
            creator_hex.clone(),
            local_hex.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["capability"], "owner_recovery_v2");
    advertise(
        &f.state,
        r_id,
        x0x::dm::CapabilityRegistry::current().bits,
        at + 1,
    );
    let (status, Json(body)) =
        crate::server::routes::named_groups::remove_treekem_named_group_member(
            Arc::clone(&f.state),
            f.stable.clone(),
            creator_hex.clone(),
            local_hex.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["roster_only"], true);
    let after = f.state.named_groups.read().await[&f.stable].clone();
    assert!(!after.has_active_member(&creator_hex));
    assert_eq!(after.secret_epoch, before.secret_epoch, "no epoch change");
    assert_eq!(after.security_binding, before.security_binding);

    let event = last_roster_only_removal(&f, &creator_hex).await;
    let applied = crate::server::routes::named_groups::apply_named_group_metadata_event(
        &receiver, event, author, true, None,
    )
    .await;
    assert!(applied.accepted, "{applied:?}");
    assert_eq!(
        receiver.named_groups.read().await[&f.stable].state_hash,
        after.state_hash
    );

    // A roster-only removal of S, which holds a leaf, is refused.
    let mut forged = after.clone();
    let tolerated_hex = hex::encode(s_keypair.agent_id().as_bytes());
    forged.roster_revision += 1;
    forged.remove_member(&tolerated_hex, Some(local_hex.clone()));
    let forged_commit = forged
        .seal_commit_evicting(f.state.agent.identity().agent_keypair(), 9_000)
        .unwrap();
    let forged_event = crate::server::NamedGroupMetadataEvent::MemberRemoved {
        target_key_package_b64: None,
        group_id: f.stable.clone(),
        revision: forged.roster_revision,
        actor: local_hex.clone(),
        agent_id: tolerated_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(forged_commit),
    };
    let refused = crate::server::routes::named_groups::apply_named_group_metadata_event(
        &receiver,
        forged_event,
        author,
        true,
        None,
    )
    .await;
    assert!(
        !refused.accepted,
        "a seat with a leaf needs its TreeKEM removal"
    );

    // An ordinary TreeKEM removal works again on the author.
    let (status, Json(body)) =
        crate::server::routes::named_groups::remove_treekem_named_group_member(
            Arc::clone(&f.state),
            f.stable.clone(),
            tolerated_hex,
            local_hex,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["epoch"], before.secret_epoch + 1);
}

/// The ban of the leafless creator is roster-only too.
#[tokio::test]
async fn an_admin_bans_the_leafless_creator_roster_only() {
    let f = v2_fixture(Shape::default()).await;
    attempt(&f).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    // T (revoked) is evicted first, as an owner-certified seal requires.
    let _ = crate::server::routes::named_groups::owner_certified_seal_with_eviction(
        &f.state, &f.stable, &local_hex,
    )
    .await;
    let before = f.state.named_groups.read().await[&f.stable].clone();
    let (status, Json(body)) = crate::server::routes::named_groups::ban_treekem_group_member(
        Arc::clone(&f.state),
        f.stable.clone(),
        creator_hex.clone(),
        local_hex,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["roster_only"], true);
    let after = f.state.named_groups.read().await[&f.stable].clone();
    assert!(after.is_banned(&creator_hex));
    assert_eq!(after.secret_epoch, before.secret_epoch);
}

/// The revocation eviction of the leafless creator (its verdict is Failed
/// once it is revoked) is roster-only. T, revoked with a leaf, is evicted in
/// the same operation with its own TreeKEM commit.
#[tokio::test]
async fn a_revoked_leafless_creator_is_evicted_roster_only() {
    let f = v2_fixture(Shape::default()).await;
    attempt(&f).await;
    revoke_agent(&f.state, f.creator_keys.as_ref().unwrap()).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    let before = f.state.named_groups.read().await[&f.stable].clone();
    let outcome = crate::server::routes::named_groups::owner_certified_seal_with_eviction(
        &f.state, &f.stable, &local_hex,
    )
    .await
    .expect("an owner-certified group");
    let after = f.state.named_groups.read().await[&f.stable].clone();
    assert!(
        !after.has_active_member(&creator_hex),
        "the creator is evicted: {:?}",
        outcome
            .as_ref()
            .err()
            .map(|(status, Json(body))| (*status, body.clone()))
    );
    // T (revoked, with a leaf) is evicted in the same operation with its
    // own TreeKEM commit; the creator's eviction adds none.
    assert!(!after.has_active_member(&hex::encode(f.tolerated.as_bytes())));
    assert_eq!(after.secret_epoch, before.secret_epoch + 1);
}

/// A self-leaver's leaf is not hidden by an Active seat with no leaf.
#[test]
fn a_leafless_seat_does_not_hide_a_removed_members_leaf() {
    use base64::Engine as _;
    let (creator, leaver) = (agent(0xC1), agent(0x7E));
    let (mut committer, seats) = in_step(
        b"2139-hidden",
        agent(0xA0),
        &[(creator, 0xC1), (leaver, 0x7E)],
    );
    committer
        .remove_members_verified(&[(creator, seats[0].kp.as_slice())])
        .unwrap();
    let mut info = roster_with(&[(creator, &seats[0].kp), (leaver, &seats[1].kp)]);
    let admin_hex = hex::encode(agent(0xA0).as_bytes());
    info.members_v2.insert(
        admin_hex.clone(),
        x0x::groups::GroupMember::new_member(admin_hex.clone(), None, None, 1),
    );
    let own = TreeKemMlsGroup::prepare_member(agent(0xA0), &[0xA0; 32])
        .unwrap()
        .key_package_bytes()
        .to_vec();
    info.set_member_treekem_key_package(
        &admin_hex,
        base64::engine::general_purpose::STANDARD.encode(own),
    );
    info.remove_member(&hex::encode(leaver.as_bytes()), None);
    assert_eq!(committer.member_count(), 2, "the committer and the leaver");
    assert!(
        crate::server::routes::named_groups::tree_has_leaf_outside_active_roster(&info, &committer)
    );
}

// ─── #2197 round 2: hash-only receivers, fail-closed proof, the gates, ─────
// ─── and the excluded creator's own way back ──────────────────────────────

use crate::server::routes::named_groups as ng;
use axum::extract::{Path, State};
use axum::response::IntoResponse;

/// A V2-committed author and a receiver R that applied the frame, after the
/// S4 eviction of T. Returns the fixture, R's state, R's tree and the roster
/// both hold.
async fn excluded_pair(
    survivors: &[&x0x::identity::AgentKeypair],
    receiver: &Arc<AppState>,
) -> (
    V2Fixture,
    Arc<tokio::sync::Mutex<TreeKemMlsGroup>>,
    GroupInfo,
) {
    let mut f = v2_fixture(Shape {
        survivors,
        tolerated_leafless: true,
        ..Shape::default()
    })
    .await;
    let r_tree = receiver_for(&mut f, receiver).await;
    attempt(&f).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.unwrap();
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    let author = f.state.agent.agent_id();
    assert_eq!(
        receive_commit(receiver, author, commit, &bytes).await,
        ReceiveOutcome::Applied
    );
    let local_hex = hex::encode(author.as_bytes());
    // The S4 eviction of T; the held creator stays pending, so the seal
    // answers a retryable conflict after committing T's eviction.
    let _ = ng::owner_certified_seal_with_eviction(&f.state, &f.stable, &local_hex).await;
    assert!(!f.state.named_groups.read().await[&f.stable]
        .has_active_member(&hex::encode(f.tolerated.as_bytes())));
    let roster = f.state.named_groups.read().await[&f.stable].clone();
    receiver
        .named_groups
        .write()
        .await
        .insert(f.stable.clone(), roster.clone());
    (f, r_tree, roster)
}

/// R holds only the creator's KeyPackage hash (as a member that joined after
/// the exclusion does: Welcome and invite rosters carry hashes only).
async fn strip_bytes(state: &AppState, stable: &str, seat: &AgentId) {
    let mut groups = state.named_groups.write().await;
    let info = groups.get_mut(stable).unwrap();
    let member = info
        .members_v2
        .get_mut(&hex::encode(seat.as_bytes()))
        .unwrap();
    assert!(member.treekem_key_package_hash.is_some());
    member.treekem_key_package_b64 = None;
}

/// A hash-only receiver applies the creator's roster-only removal by the
/// KeyPackage the event carries, hash-checked against its row, and reaches
/// the author's head. The same event without the KeyPackage is refused:
/// missing bytes are never read as no leaf. Red on dffc8f3f (the removal
/// carried no KeyPackage and the receiver refused it for good).
#[tokio::test]
async fn a_hash_only_receiver_applies_the_creators_roster_only_removal() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let (f, _r_tree, _) = excluded_pair(&[r_keypair], &receiver).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    strip_bytes(&receiver, &f.stable, &f.creator).await;
    let (status, Json(body)) = ng::remove_treekem_named_group_member(
        Arc::clone(&f.state),
        f.stable.clone(),
        creator_hex.clone(),
        local_hex,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let author_head = f.state.named_groups.read().await[&f.stable].clone();
    let mut event = last_roster_only_removal(&f, &creator_hex).await;
    let carried = author_head.members_v2[&creator_hex]
        .treekem_key_package_b64
        .clone();
    assert!(
        carried.is_some(),
        "the author keeps the removed row's KeyPackage"
    );
    let bare = event.clone();
    let refused =
        ng::apply_named_group_metadata_event(&receiver, bare, f.state.agent.agent_id(), true, None)
            .await;
    assert!(
        !refused.accepted,
        "no KeyPackage bytes: refused, fail closed"
    );
    if let crate::server::NamedGroupMetadataEvent::MemberRemoved {
        target_key_package_b64,
        ..
    } = &mut event
    {
        *target_key_package_b64 = carried;
    }
    let applied = ng::apply_named_group_metadata_event(
        &receiver,
        event,
        f.state.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "{applied:?}");
    assert_eq!(
        receiver.named_groups.read().await[&f.stable].state_hash,
        author_head.state_hash
    );
}

/// The same for the ban: a hash-only receiver applies the roster-only ban
/// of the leafless creator by the KeyPackage the ban carries. Red on
/// dffc8f3f (the seated-leafless arm read only the row's bytes).
#[tokio::test]
async fn a_hash_only_receiver_applies_the_creators_roster_only_ban() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let (f, _r_tree, before) = excluded_pair(&[r_keypair], &receiver).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    strip_bytes(&receiver, &f.stable, &f.creator).await;
    let (status, Json(body)) = ng::ban_treekem_group_member(
        Arc::clone(&f.state),
        f.stable.clone(),
        creator_hex.clone(),
        local_hex.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = f.state.named_groups.read().await[&f.stable].clone();
    let commit = after.commit_log.last().unwrap().commit.clone();
    let event = crate::server::NamedGroupMetadataEvent::MemberBanned {
        group_id: f.stable.clone(),
        revision: after.roster_revision,
        actor: local_hex,
        agent_id: creator_hex.clone(),
        secret_epoch: None,
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
        target_key_package_b64: ng::roster_only_ban_key_package(&before, &creator_hex),
    };
    let applied = ng::apply_named_group_metadata_event(
        &receiver,
        event,
        f.state.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "{applied:?}");
    assert_eq!(
        receiver.named_groups.read().await[&f.stable].state_hash,
        after.state_hash
    );
}

/// The proof is fail-closed. A seat whose KeyPackage bytes are missing is
/// `MissingBytes`, never leafless, even when its leaf is gone; a seat that
/// holds a leaf is never leafless; no loaded tree, or a tree at another
/// epoch than the roster, proves nothing.
#[tokio::test]
async fn the_leafless_proof_fails_closed() {
    let (_rdir, receiver, _, _) = recovery_fixture().await;
    let r_keypair = receiver.agent.identity().agent_keypair();
    let s_keypair = x0x::identity::AgentKeypair::generate().unwrap();
    let (f, _r_tree, roster) = excluded_pair(&[&s_keypair, r_keypair], &receiver).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let s_hex = hex::encode(s_keypair.agent_id().as_bytes());
    let leaf = |info: GroupInfo, seat: String, carried: Option<String>| {
        let receiver = Arc::clone(&receiver);
        let stable = f.stable.clone();
        async move { ng::treekem_seat_leaf(&receiver, &stable, &info, &seat, carried.as_deref()).await }
    };
    assert_eq!(
        leaf(roster.clone(), creator_hex.clone(), None).await,
        ng::SeatLeaf::Absent
    );
    assert_eq!(
        leaf(roster.clone(), s_hex.clone(), None).await,
        ng::SeatLeaf::NotAbsent,
        "a seat with a leaf"
    );
    let mut stripped = roster.clone();
    for seat in [&creator_hex, &s_hex] {
        stripped
            .members_v2
            .get_mut(seat)
            .unwrap()
            .treekem_key_package_b64 = None;
    }
    assert_eq!(
        leaf(stripped.clone(), creator_hex.clone(), None).await,
        ng::SeatLeaf::MissingBytes,
        "missing bytes are never no leaf"
    );
    assert_eq!(
        leaf(stripped.clone(), s_hex.clone(), None).await,
        ng::SeatLeaf::MissingBytes,
        "a stripped seat that still holds a leaf is never leafless"
    );
    assert_eq!(
        leaf(
            stripped,
            creator_hex.clone(),
            Some("bm90LXRoZS1wYWNrYWdl".into())
        )
        .await,
        ng::SeatLeaf::MissingBytes,
        "carried bytes that do not hash to the row are ignored"
    );
    let mut later = roster.clone();
    later.secret_epoch += 1;
    assert_eq!(
        leaf(later, creator_hex.clone(), None).await,
        ng::SeatLeaf::NotAbsent,
        "a tree at another epoch than the roster"
    );
    receiver.treekem_groups.write().await.remove(&f.stable);
    assert_eq!(
        leaf(roster, creator_hex, None).await,
        ng::SeatLeaf::NotAbsent,
        "no loaded tree"
    );
}

/// The bit-23 gate (D76) also holds the roster-only ban and eviction of the
/// leafless creator while a member's current advert lacks the bit.
#[tokio::test]
async fn the_bit_23_gate_holds_the_ban_and_the_eviction() {
    let r = x0x::identity::AgentKeypair::generate().unwrap();
    let f = v2_fixture(Shape {
        survivors: &[&r],
        ..Shape::default()
    })
    .await;
    attempt(&f).await;
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    let _ = ng::owner_certified_seal_with_eviction(&f.state, &f.stable, &local_hex).await;
    advertise(
        &f.state,
        r.agent_id(),
        bits_without_v2(),
        x0x::dm::now_unix_ms(),
    );
    let (status, Json(body)) = ng::ban_treekem_group_member(
        Arc::clone(&f.state),
        f.stable.clone(),
        creator_hex.clone(),
        local_hex.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["capability"], "owner_recovery_v2");
    revoke_agent(&f.state, f.creator_keys.as_ref().unwrap()).await;
    let outcome = ng::owner_certified_seal_with_eviction(&f.state, &f.stable, &local_hex)
        .await
        .expect("an owner-certified group");
    let Err((status, Json(body))) = outcome else {
        panic!("the eviction is held");
    };
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["capability"], "owner_recovery_v2");
    assert!(f.state.named_groups.read().await[&f.stable].has_active_member(&creator_hex));
}

/// The excluded creator's own way back, end to end on two daemons. The
/// creator's node verifies the V2 frame and shows `excluded_by_owner_recovery`.
/// An admin removes its seat (roster-only). The creator's node leaves
/// locally (`DELETE /groups/:id`): only its local copy is dropped, no
/// commit is sealed (before this, the self-leave seal answered 500). A
/// fresh invite then
/// starts an ordinary join (no "already seated" answer). Its re-admission
/// adds a fresh leaf: the creator reads traffic after it, and not the
/// traffic sent while it was out.
#[tokio::test]
async fn the_excluded_creator_leaves_locally_and_rejoins_by_invite() {
    let (_cdir, creator_node, _, _) = recovery_fixture().await;
    let creator_keys = creator_node.agent.identity().agent_keypair();
    let f = v2_fixture(Shape {
        creator: Some(creator_keys),
        tolerated_leafless: true,
        ..Shape::default()
    })
    .await;
    let records = f.state.agent.revocation_set().read().await.all_records();
    for record in records {
        let _ = creator_node
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None);
    }
    creator_node
        .named_groups
        .write()
        .await
        .insert(f.stable.clone(), f.info.clone());
    creator_node.treekem_groups.write().await.insert(
        f.stable.clone(),
        Arc::new(tokio::sync::Mutex::new(f.creator_tree)),
    );
    attempt_on(&f.state, &f.stable, &f.info).await;
    let (frame, _) = outbox(&f.state, &f.stable).await;
    let bytes = frame.unwrap();
    let commit = orc::decode_frame(&bytes)
        .ok()
        .and_then(orc::OwnerRecoveryFrameV1::into_commit)
        .unwrap();
    assert_eq!(
        receive_commit(&creator_node, f.state.agent.agent_id(), commit, &bytes).await,
        ReceiveOutcome::NotApplicable
    );
    // Traffic while the creator is out.
    let while_out = f.tree.lock().await.encrypt_message(b"while out").unwrap();

    // The admin removes the creator's seat (T is evicted first).
    let creator_hex = hex::encode(f.creator.as_bytes());
    let local_hex = hex::encode(f.state.agent.agent_id().as_bytes());
    // The S4 eviction of T; the held creator stays pending, so the seal
    // answers a retryable conflict after committing T's eviction.
    let _ = ng::owner_certified_seal_with_eviction(&f.state, &f.stable, &local_hex).await;
    assert!(!f.state.named_groups.read().await[&f.stable]
        .has_active_member(&hex::encode(f.tolerated.as_bytes())));
    let (status, Json(body)) = ng::remove_treekem_named_group_member(
        Arc::clone(&f.state),
        f.stable.clone(),
        creator_hex.clone(),
        local_hex,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let response = ng::leave_group(
        State(Arc::clone(&creator_node)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(f.stable.clone()),
    )
    .await
    .into_response();
    let status = response.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["local_only"], true);
    assert_eq!(body["excluded_by_owner_recovery"], true);
    assert!(!creator_node
        .named_groups
        .read()
        .await
        .contains_key(&f.stable));

    // A fresh invite starts an ordinary join on the creator's node.
    let (_invite, link) = ng::mint_invite_transaction(
        &f.state,
        &f.stable,
        3_600,
        Some(f.creator),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .unwrap_or_else(|e| panic!("mint invite: {e:?}"));
    let response = ng::join_group_via_invite(
        State(Arc::clone(&creator_node)),
        Json(ng::JoinGroupRequest {
            invite: link,
            display_name: None,
            // An owner-certified group is joined in Home mode, pinned to its
            // owner.
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(hex::encode(
                f.state
                    .agent
                    .identity()
                    .user_keypair()
                    .unwrap()
                    .user_id()
                    .as_bytes(),
            )),
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap_or(serde_json::Value::Null);
    assert!(
        status.is_success() && body["join_state"] != "active",
        "an ordinary join starts, not an already-seated answer: {status} {body}"
    );

    // The re-admission's TreeKEM add gives the creator a fresh leaf.
    let prepared = TreeKemMlsGroup::prepare_member(f.creator, &[0xE1; 32]).unwrap();
    let added = f
        .tree
        .lock()
        .await
        .add_member(f.creator, prepared.key_package_bytes())
        .unwrap();
    let mut rejoined = TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome).unwrap();
    let after = f
        .tree
        .lock()
        .await
        .encrypt_message(b"after rejoin")
        .unwrap();
    assert_eq!(rejoined.decrypt_message(&after).unwrap(), b"after rejoin");
    assert!(
        rejoined.decrypt_message(&while_out).is_err(),
        "nothing sent while it was out"
    );
}
