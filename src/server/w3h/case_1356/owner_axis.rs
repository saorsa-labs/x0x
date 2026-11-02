//! OwnerCertified harness support (#1666) and the ADR 0109 §10 rows
//! H-S3-c, H-S3-c2, H-S3-c3 and H-S3-d8 (#871, D78, D79, D121, D156, #1572). O is the only
//! install with the owner's USER key; A, X and J hold owner-issued agent
//! certificates only (test builds load `agent.cert` without a user key).
//!
//! Control, expected GREEN on `main`: A joins O's OwnerCertified group, O
//! promotes it, and A's own seal reaches O.
//!
//! H-S3-c/c2 follow the ADR setup on a non-Home OwnerCertified group: J
//! redeems invite I (minted at r) after O removes X (r+1), so O's seal of
//! J (r+2) carries the owner's v2 terminal attestation and arms J's gap
//! gate; the case checks the gate before the window. X's rename (r+1′)
//! then reaches J only. Each red arm keeps its `_red_` name and expects
//! GREEN (the ADR 0109 behaviour). A failure is RED only when J shows the
//! row's main observation, or leaves containment before the keyed swap
//! (`CAUSE_C`); a missing prerequisite or any other failure is INFRA.

use super::*;

const LABELS: &[&str] = &["O", "A"];
const FINAL: &str = "certificate_only_admin_seals_an_owner_certified_group";

/// Start `label` with an owner-issued agent certificate; with `user_key`
/// the install also holds the owner's USER key.
async fn start_certified(
    sim: &mut Sim,
    label: &str,
    owner: &crate::identity::UserKeypair,
    user_key: bool,
) -> Result<()> {
    let (machine, agent) = sim.take_keys(label)?;
    let cert = crate::identity::AgentCertificate::issue(owner, &agent)?;
    let user_key = if user_key {
        Some(crate::storage::serialize_user_keypair(owner)?)
    } else {
        None
    };
    sim.start_node_with(
        label,
        Provision {
            machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
            agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
            user_key,
            agent_cert: Some(cert.to_storage_bytes()?),
        },
    )
    .await
}

/// Each of `labels` announces its identity with its certificate.
async fn announce_all(sim: &Sim, labels: &[&str]) -> Result<()> {
    for label in labels {
        let body = json!({"include_user_identity": true, "human_consent": true});
        let (code, answer) = sim
            .api(label, Method::POST, "/announce", Some(body))
            .await?;
        ensure!(code.is_success(), "{label} announce: {code} {answer}");
    }
    Ok(())
}

/// `admin` seals a rename. A seal checks every member's certificate and the
/// first try may start the fetches it needs; the creator's seat carries no
/// certificate, so each retry refreshes O's certificate announce.
async fn seal_rename(sim: &Sim, admin: &str, group: &str, name: &str) -> Result<()> {
    let path = format!("/groups/{group}");
    let mut last = String::new();
    sim.until(
        &format!("{admin} seals a rename"),
        SETUP,
        async |s: &Sim| {
            let body = Some(json!({"name": name}));
            match s.request(admin, Method::PATCH, &path, body).await {
                Ok((code, _)) if code.is_success() => true,
                answer => {
                    last = format!("{answer:?}");
                    let body = json!({"include_user_identity": true, "human_consent": true});
                    let _ = s.request("O", Method::POST, "/announce", Some(body)).await;
                    false
                }
            }
        },
    )
    .await
    .with_context(|| format!("{admin}'s last seal answer: {last}"))
}

/// An OwnerCertified TreeKEM group that is not the Home policy: admin-only
/// writes keep it off ADR 0109 §4's Home gate (`home_gate_closed`) and out
/// of Home adoption (#1687). Hidden + MlsEncrypted keeps the TreeKEM plane.
async fn create_group(sim: &Sim, owner: &crate::identity::UserKeypair) -> Result<String> {
    let policy = crate::groups::GroupPolicy {
        admission: crate::groups::GroupAdmission::OwnerCertified(owner.user_id()),
        write_access: crate::groups::GroupWriteAccess::AdminOnly,
        ..crate::groups::GroupPolicyPreset::PrivateSecure.to_policy()
    };
    ensure!(
        policy != crate::groups::GroupPolicy::home(&owner.user_id()),
        "the fixture policy must not be the Home policy"
    );
    let body = json!({"name": "w3h owner axis", "display_name": "O", "policy": policy});
    let (code, created) = sim.api("O", Method::POST, "/groups", Some(body)).await?;
    ensure!(code.is_success(), "create: {code} {created}");
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// `member` redeems `link` in the owner-pinned join mode.
async fn redeem(
    sim: &Sim,
    member: &str,
    link: &str,
    owner: &crate::identity::UserKeypair,
) -> Result<(StatusCode, Value)> {
    let body = json!({
        "invite": link,
        "display_name": member,
        "mode": "home",
        "expected_owner_user_id": hex::encode(owner.user_id().as_bytes()),
    });
    sim.api(member, Method::POST, "/groups/join", Some(body))
        .await
}

/// `member` redeems a fresh invite from O and is seated.
async fn join_owner(
    sim: &Sim,
    member: &str,
    group: &str,
    owner: &crate::identity::UserKeypair,
) -> Result<()> {
    let link = invite(sim, "O", group).await?;
    let (code, joined) = redeem(sim, member, &link, owner).await?;
    ensure!(code.is_success(), "{member} join: {code} {joined}");
    let hex = sim.agent_hex(member)?;
    sim.until(&format!("{member} is seated"), SETUP, async |s: &Sim| {
        let listed = members(s, "O", group)
            .await
            .is_ok_and(|listed| listed.contains(&hex));
        let membership = status_now(s, member, group).await.ok().flatten();
        listed && membership.and_then(|st| st.membership).as_deref() == Some("active")
    })
    .await
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
    start_certified(sim, "O", &owner, true).await?;
    start_certified(sim, "A", &owner, false).await?;
    mesh(sim, LABELS).await?;
    announce_all(sim, LABELS).await?;
    let group = create_group(sim, &owner).await?;
    join_owner(sim, "A", &group, &owner).await?;
    let a_hex = sim.agent_hex("A")?;
    let path = format!("/groups/{group}/members/{a_hex}/role");
    let body = json!({"role": "admin"});
    let (code, promoted) = sim.api("O", Method::PATCH, &path, Some(body)).await?;
    ensure!(code.is_success(), "O promotes A: {code} {promoted}");
    sim.until("A holds its promotion", SETUP, async |s: &Sim| {
        let (Ok(o), Ok(a)) = (
            view_now(s, "O", &group).await,
            view_now(s, "A", &group).await,
        ) else {
            return false;
        };
        o.state_hash == a.state_hash
    })
    .await?;
    let a_state = sim.state("A")?;
    let a_identity = a_state.agent.identity();
    receipt.setup_done(at(sim));
    let has_user_key = a_identity.user_keypair().is_some();
    let has_cert = a_identity.agent_certificate().is_some();
    let disclosed = a_identity.disclosed_user_id();
    receipt.evidence(
        "a_is_certificate_only",
        !has_user_key && has_cert && disclosed == Some(owner.user_id()),
        format!("A user key {has_user_key}; A certificate {has_cert}; disclosed {disclosed:?}"),
        at(sim),
    );
    let since = sim.fabric().mark_indexed("case: A renames");
    seal_rename(sim, "A", &group, "w3h owner axis A").await?;
    let head = view(sim, "A", &group).await?;
    let applied = sim
        .until("O applies A's seal", SETUP, async |s: &Sim| {
            view_now(s, "O", &group)
                .await
                .is_ok_and(|v| v.state_hash == head.state_hash)
        })
        .await
        .is_ok();
    let to_o = delivered_after(sim, "A", "O", since)?;
    receipt.request_delivered(
        "a_reached_o",
        to_o > 0,
        format!("frames A->O: {to_o}"),
        at(sim),
    );
    receipt.note(format!("A {}", head.describe()));
    receipt.finish(FINAL, applied, at(sim));
    Ok(())
}

// ─── H-S3-c and H-S3-c2 ───────────────────────────────────────────────────

const C_LABELS: &[&str] = &["O", "A", "X", "J"];
const FINAL_C: &str = "j_reseat_required_then_promoted_admin_reseats_it_with_the_owner_offline";
const CAUSE_C: &str = "the row's main observation: after the advance J stays on X's fork r+1′ \
                       with its gap gate armed and no typed re-seat state (H-S3-c: no marker); \
                       or J leaves containment before the keyed swap (ADR 0109 §3); \
                       `observed` lists each failing candidate step";
/// H-S3-c: "Advance 30 min".
const GATE_WINDOW: Duration = Duration::from_secs(30 * 60);
/// X publishes its r+1′ bytes again after this long with no frame to J.
/// J's join poll ends about 120 s after the join, so retries fit inside it.
const FORK_REPUBLISH: Duration = Duration::from_secs(10);

type Key = crate::network::sim::Key;
type Policy = Box<dyn Fn(Key, Key, Option<[u8; 32]>) -> bool + Send + Sync>;

/// Drops a write when the policy returns true for its origin (the first
/// sender of its pubsub message ID, or its sender), its receiver and its
/// pubsub message ID. Relays of a held publish are held too.
fn install_hold(sim: &Sim) -> Arc<Mutex<Policy>> {
    use crate::network::sim::{Fault, LaneClass};
    let policy: Arc<Mutex<Policy>> = Arc::new(Mutex::new(Box::new(|_, _, _| false)));
    let origins: Mutex<std::collections::HashMap<[u8; 32], Key>> = Mutex::default();
    let rule = Arc::clone(&policy);
    sim.fabric().add_rule(move |write| {
        let msg = (write.lane.class == LaneClass::PubSub)
            .then(|| pubsub_header(&write.bytes))
            .flatten()
            .map(|(_, id)| id);
        let origin = match (msg, origins.lock()) {
            (Some(id), Ok(mut map)) => *map.entry(id).or_insert(write.lane.src),
            (Some(_), Err(_)) => return Fault::Drop,
            (None, _) => write.lane.src,
        };
        match rule.lock().map_or(true, |p| p(origin, write.lane.dst, msg)) {
            true => Fault::Drop,
            false => Fault::Pass,
        }
    });
    policy
}

fn set_hold(
    sim: &Sim,
    hold: &Mutex<Policy>,
    what: &str,
    policy: impl Fn(Key, Key, Option<[u8; 32]>) -> bool + Send + Sync + 'static,
) {
    if let Ok(mut slot) = hold.lock() {
        *slot = Box::new(policy);
    }
    sim.fabric().mark(format!("fault: hold now {what}"));
}

/// Wait up to `budget` for `label`'s view to reach `hash`.
async fn reaches(sim: &Sim, label: &str, group: &str, hash: &str, budget: Duration) -> bool {
    let what = format!("{label} applies {}", short(hash));
    sim.until(&what, budget, async |s: &Sim| {
        view_now(s, label, group)
            .await
            .is_ok_and(|v| v.state_hash == hash)
    })
    .await
    .is_ok()
}

async fn all_reach(sim: &Sim, labels: &[&str], group: &str, hash: &str) -> Result<()> {
    for label in labels {
        if !reaches(sim, label, group, hash, SETUP).await {
            let seen = try_view_now(sim, label, group).await?;
            let seen = seen
                .as_ref()
                .map_or("no record".to_string(), View::describe);
            bail!("{label} did not apply {}: {label} {seen}", short(hash));
        }
    }
    Ok(())
}

/// Whether `label`'s gossip plane holds `other`. A pubsub topic's peers
/// come from this plane (refreshed each second), not from a subscribe frame.
async fn on_plane(sim: &Sim, label: &str, other: &str) -> bool {
    let (Ok(state), Ok(other)) = (sim.state(label), sim.peer(other)) else {
        return false;
    };
    match state.agent.network() {
        Some(network) => network.gossip_plane_peers().await.contains(&other),
        None => false,
    }
}

/// Pubsub writes from `src` to `dst` delivered after write `cut` that
/// carry `needle` (group metadata events are plaintext JSON in the frame).
fn pubsub_delivered(sim: &Sim, src: &str, dst: &str, cut: usize, needle: &[u8]) -> Result<usize> {
    use crate::network::sim::LaneClass;
    let writes = sim
        .fabric()
        .delivered_writes_after(&sim.peer(src)?, &sim.peer(dst)?, cut);
    Ok(writes
        .iter()
        .filter(|(w, _)| w.lane.class == LaneClass::PubSub)
        .filter(|(w, _)| w.bytes.windows(needle.len()).any(|x| x == needle))
        .count())
}

/// The `MemberAdded(member)` events `src` wrote since write `cut`: how
/// many, and whether any carried a `reseat_mandate` or an `owner_mandate`.
fn member_added_mandates(
    sim: &Sim,
    cut: usize,
    src: &str,
    member: &str,
) -> Result<(usize, bool, bool)> {
    let has = |b: &[u8], n: &[u8]| b.windows(n.len()).any(|w| w == n);
    let (src, member) = (sim.peer(src)?.0, sim.agent_hex(member)?);
    let mut found = (0, false, false);
    for write in sim.fabric().writes().iter().skip(cut) {
        let b = &write.bytes;
        if write.lane.src == src && has(b, b"\"member_added\"") && has(b, member.as_bytes()) {
            found.0 += 1;
            found.1 |= has(b, b"\"reseat_mandate\"");
            found.2 |= has(b, b"\"owner_mandate\"");
        }
    }
    Ok(found)
}

/// What the shared H-S3-c prefix leaves for a row: J on X's fork r+1′ with
/// its gap gate armed, and the fabric hold still in place.
struct Prefix {
    group: String,
    j_hex: String,
    /// O's head when invite I was minted (r).
    minted: View,
    /// The owner's (O's) ML-DSA-65 USER public key bytes.
    owner_key: Vec<u8>,
    /// X's r+1′ head, which J holds.
    fork: View,
    /// The fabric write index when J redeemed invite I.
    joined_at: usize,
    /// While set, every write that O originates is held from J (H-S3-c).
    o_to_j_held: Arc<std::sync::atomic::AtomicBool>,
    /// While set, every write that J originates is held from A and O
    /// (H-S3-d8). Unset after the prefix.
    j_out_held: Arc<std::sync::atomic::AtomicBool>,
    /// O's held r+1 gossip writes to J after r+1′.
    held_to_j: Arc<std::sync::atomic::AtomicUsize>,
    /// H-S3-c2: re-published canonical r+1 frames delivered to J.
    canonical: usize,
}

/// The H-S3-c setup up to J on X's fork r+1′ (ADR 0109 §10), shared by the
/// owner-axis rows; with `both`, H-S3-c2's canonical r+1 also reaches J.
/// `None` when a prerequisite is missing: the receipt is then finished
/// under the row's final step `last`.
async fn fork_prefix(
    sim: &mut Sim,
    receipt: &mut Receipt,
    both: bool,
    last: &str,
) -> Result<Option<Prefix>> {
    let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
    start_certified(sim, "O", &owner, true).await?;
    for label in ["A", "X", "J"] {
        start_certified(sim, label, &owner, false).await?;
    }
    mesh(sim, C_LABELS).await?;
    // O is an owned install: let its deferred Home provisioning finish
    // before the announces, so it runs outside the row.
    sim.until("O provisions its Home", SETUP, async |s: &Sim| {
        let home = s.request("O", Method::GET, "/home", None).await;
        home.is_ok_and(|(code, body)| code.is_success() && body["state"] != "provisioning_pending")
    })
    .await?;
    announce_all(sim, C_LABELS).await?;
    // A pinned send with no binding runs a blocking Lookup that stalls
    // paused virtual time (see `case_1357`).
    sim.until("every node pins every peer", SETUP, async |s: &Sim| {
        for (from, to) in C_LABELS
            .iter()
            .flat_map(|f| C_LABELS.iter().map(move |t| (f, t)))
        {
            let (Ok(state), Ok((id, _))) = (s.state(from), s.ids(to)) else {
                return false;
            };
            if from != to && state.agent.pinned_binding_now(&id).await.is_none() {
                return false;
            }
        }
        true
    })
    .await?;
    let group = create_group(sim, &owner).await?;
    for member in ["A", "X"] {
        join_owner(sim, member, &group, &owner).await?;
    }
    for admin in ["A", "X"] {
        let hex = sim.agent_hex(admin)?;
        let path = format!("/groups/{group}/members/{hex}/role");
        let (code, body) = sim
            .api("O", Method::PATCH, &path, Some(json!({"role": "admin"})))
            .await?;
        ensure!(code.is_success(), "O promotes {admin}: {code} {body}");
    }
    // Each admin seals once before the partition: a seal starts the
    // certificate fetches it needs.
    for admin in ["A", "X"] {
        seal_rename(sim, admin, &group, &format!("w3h c {admin} warm")).await?;
        let head = view(sim, admin, &group).await?;
        all_reach(sim, &["O", "A", "X"], &group, &head.state_hash).await?;
    }
    // S0 skew (as `case_818`): four state-only policy changes before the
    // mint (r is taken after them) put J's stub roster clock, seeded from
    // r, above O's r+2 MemberAdded, so the frontier gate does not queue
    // J's seal and the refused chain reaches the owner-anchored gap check
    // (ADR 0109, #818 part 2). A rename bumps the roster clock too, so it cannot skew.
    // `read_access` keeps the policy non-Home throughout.
    for read_access in ["public", "members_only", "public", "members_only"] {
        let path = format!("/groups/{group}/policy");
        let body = Some(json!({"read_access": read_access}));
        let (code, answer) = sim.api("O", Method::PATCH, &path, body).await?;
        ensure!(code.is_success(), "policy {read_access}: {code} {answer}");
    }
    let head = view(sim, "O", &group).await?;
    all_reach(sim, &["A", "X"], &group, &head.state_hash).await?;
    // Invite I at r; J redeems it only after O removes X.
    let minted = view(sim, "O", &group).await?;
    let link = invite(sim, "O", &group).await?;
    let (o, x, j) = (sim.peer("O")?.0, sim.peer("X")?.0, sim.peer("J")?.0);
    let a = sim.peer("A")?.0;

    // X is cut from O and A; O's r+1 publish (and its relays) is captured
    // and held from J.
    let held: Arc<Mutex<std::collections::HashSet<[u8; 32]>>> = Arc::default();
    let is_held = |held: &Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
                   msg: Option<[u8; 32]>| {
        msg.is_some_and(|id| held.lock().map_or(true, |h| h.contains(&id)))
    };
    let capture = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let seal_ids: Arc<Mutex<std::collections::HashSet<[u8; 32]>>> = Arc::default();
    let seal_capture = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let held_to_j = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // X reaches J only, from the partition on: the X~J link and gossip
    // plane stay up, so X's later r+1′ publish has a path to J. Origins are
    // tracked per message, so J relays nothing between X and O or A, and
    // J (not yet a member) authors no group event. The X~O and X~A links
    // are also closed (below): a write the hold drops still reports a
    // send, so with those links open O and A keep X's two roster-preferred
    // eager slots for the topic, and J (not on X's roster) stays lazy and
    // gets no r+1′ frame in some runs (#1689 trace).
    let cut_x = move |origin: Key, dst: Key| (origin == x && dst != j) || (dst == x && origin != j);
    let hold = install_hold(sim);
    {
        let (held, capture) = (Arc::clone(&held), Arc::clone(&capture));
        let (seal_ids, seal_capture) = (Arc::clone(&seal_ids), Arc::clone(&seal_capture));
        set_hold(
            sim,
            &hold,
            "X reaches J only; O's r+1 captured",
            move |origin, dst, msg| {
                if let (Some(id), true, Ok(mut set)) = (msg, origin == o, held.lock()) {
                    if capture.load(std::sync::atomic::Ordering::SeqCst) {
                        set.insert(id);
                    }
                }
                if let (Some(id), true, Ok(mut set)) = (msg, origin == o, seal_ids.lock()) {
                    if seal_capture.load(std::sync::atomic::Ordering::SeqCst) {
                        set.insert(id);
                    }
                }
                cut_x(origin, dst) || (dst == j && is_held(&held, msg))
            },
        );
    }
    for other in ["O", "A"] {
        sim.fabric()
            .set_partitioned(&sim.peer("X")?, &sim.peer(other)?, true);
    }
    sim.fabric().mark("fault: X~O and X~A partitioned");
    let x_hex = sim.agent_hex("X")?;
    let recorded_from = sim
        .state("O")?
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .map_or(0, |p| p.len());
    let path = format!("/groups/{group}/members/{x_hex}");
    let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "O removes X: {code} {body}");
    // O's r+1 event bytes, as published. J is not yet a member, so no r+1
    // frame to J exists to buffer; H-S3-c2 re-publishes these bytes.
    let removal_event = {
        let state = sim.state("O")?;
        let published = state
            .named_group_test_recorders
            .publish_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let has = |b: &[u8], n: &[u8]| b.windows(n.len()).any(|w| w == n);
        published
            .iter()
            .skip(recorded_from)
            .find(|(_, b)| has(b, b"\"member_removed\"") && has(b, x_hex.as_bytes()))
            .cloned()
    };
    let (removal_topic, removal_bytes) =
        removal_event.context("O's r+1 removal event was not recorded")?;
    let removal = view(sim, "O", &group).await?;
    all_reach(sim, &["A"], &group, &removal.state_hash).await?;
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    capture.store(false, std::sync::atomic::Ordering::SeqCst);
    // H-S3-c: O's r+2 (J's seal) gossip IDs are recorded, not held, during
    // the join (J's gate arms from it); they are held from J after r+1′.
    seal_capture.store(!both, std::sync::atomic::Ordering::SeqCst);

    // J redeems I; O seals J (r+2) and its join result carries the owner's
    // v2 terminal attestation, which arms J's gap gate.
    let joined_at = sim.fabric().mark_indexed("case: J redeems invite I");
    let join_t = sim.fabric().now();
    let (join_code, join_answer) = redeem(sim, "J", &link, &owner).await?;
    let j_hex = sim.agent_hex("J")?;
    let armed = sim
        .until("O seals J and J's gap gate arms", SETUP, async |s: &Sim| {
            let o_lists = view_now(s, "O", &group)
                .await
                .is_ok_and(|v| v.lists(&j_hex));
            let gate = try_view_now(s, "J", &group).await.ok().flatten();
            o_lists && gate.is_some_and(|v| v.gap_refusal.is_some())
        })
        .await
        .is_ok();
    let sealed = view(sim, "O", &group).await?;
    seal_capture.store(false, std::sync::atomic::Ordering::SeqCst);
    let gate = try_view_now(sim, "J", &group).await?;
    let gate_text = gate
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);

    // J hears only X (so its catch-up with O and A waits too, as the ADR
    // orders it) until r+1′ lands. Then X is fully cut (its catch-up loop
    // with J is #1685). H-S3-c keeps O's r+1 gossip held from J; H-S3-c2
    // re-publishes it to J by gossip.
    set_hold(
        sim,
        &hold,
        "X reaches J only; J hears only X",
        move |origin, dst, _| cut_x(origin, dst) || (dst == j && origin != x),
    );
    // J is not on X's roster, so X's gossip publish is the only path for
    // r+1′ to J. Each must hold the other on its gossip plane, then two
    // topic refreshes pass, before X publishes.
    let plane = sim
        .until(
            "X and J hold each other on the gossip plane",
            SETUP,
            async |s: &Sim| on_plane(s, "X", "J").await && on_plane(s, "J", "X").await,
        )
        .await
        .is_ok();
    sim.within("X's topic peers refresh", secs(4), async {
        tokio::time::sleep(secs(2)).await;
    })
    .await?;
    let x_recorded_from = sim
        .state("X")?
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .map_or(0, |p| p.len());
    let forked_at = sim.fabric().mark_indexed("case: X publishes r+1′");
    rename(sim, "X", &group, "w3h c X fork").await?;
    let fork = view(sim, "X", &group).await?;
    // X's r+1′ event bytes, as published. A publish can have no eager
    // peer for the topic yet ("zero successful ordinary EAGER fan-out"),
    // and J drops its stub when its join poll ends, so X publishes the
    // same bytes again (a new message ID) until a frame reaches J.
    let fork_event = {
        let state = sim.state("X")?;
        let published = state
            .named_group_test_recorders
            .publish_bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        published
            .iter()
            .skip(x_recorded_from)
            .find(|(_, b)| b.windows(12).any(|w| w == b"w3h c X fork"))
            .cloned()
    };
    let (fork_topic, fork_bytes) = fork_event.context("X's r+1′ rename event was not recorded")?;
    let mut fork_publishes = 1;
    let mut last_publish = sim.fabric().now();
    let on_fork = sim
        .until("J applies X's r+1′", SETUP, async |s: &Sim| {
            let delivered = pubsub_delivered(s, "X", "J", forked_at, b"w3h c X fork").unwrap_or(0);
            if delivered == 0 && s.fabric().now() >= last_publish + FORK_REPUBLISH {
                if let Ok(state) = s.state("X") {
                    if state
                        .agent
                        .publish(&fork_topic, fork_bytes.clone())
                        .await
                        .is_ok()
                    {
                        fork_publishes += 1;
                    }
                }
                last_publish = s.fabric().now();
            }
            view_now(s, "J", &group)
                .await
                .is_ok_and(|v| v.state_hash == fork.state_hash)
        })
        .await
        .is_ok();
    let fork_frames = pubsub_delivered(sim, "X", "J", forked_at, b"w3h c X fork")?;
    let o_to_j_held = Arc::new(std::sync::atomic::AtomicBool::new(!both));
    let j_out_held = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (held, held_to_j) = (Arc::clone(&held), Arc::clone(&held_to_j));
        let (seal_ids, o_held) = (Arc::clone(&seal_ids), Arc::clone(&o_to_j_held));
        let j_held = Arc::clone(&j_out_held);
        let what = match both {
            true => "X cut; O's r+1 gossip passes to J",
            false => {
                "X cut; O's r+1 gossip and every O->J write held from J until the advance ends"
            }
        };
        set_hold(sim, &hold, what, move |origin, dst, msg| {
            let to_j = dst == j && is_held(&held, msg);
            if to_j {
                held_to_j.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            // H-S3-c: no canonical commit reaches J after r+1′. O's r+2
            // reaches J more ways than r+1's gossip: r+2's own gossip (its
            // recorded IDs, from any relay) and O's direct sends. Those are
            // J's join poll, and O's control blob of r+2 (#1689 trace), whose
            // dropped chunks O re-sends as encrypted gossip DMs (origin O).
            // So every write that O originates is held from J until J's read
            // after the advance. r+2 conflicts with r+1′ and installs a
            // marker (ADR 0109 l.96, correct, but not this row's premise).
            let from_o =
                origin == o && dst == j && o_held.load(std::sync::atomic::Ordering::SeqCst);
            let seal_to_j = dst == j && is_held(&seal_ids, msg);
            let from_j = origin == j
                && (dst == a || dst == o)
                && j_held.load(std::sync::atomic::Ordering::SeqCst);
            origin == x || dst == x || from_j || (!both && (to_j || from_o || seal_to_j))
        });
    }
    // H-S3-c2: O publishes its recorded r+1 bytes again (a new message ID,
    // so the hold above does not match it); the case waits until a frame
    // that carries them is delivered to J and J records the marker.
    let mut canonical = 0;
    if both && on_fork {
        let released_at = sim
            .fabric()
            .mark_indexed("case: O re-publishes canonical r+1");
        sim.state("O")?
            .agent
            .publish(&removal_topic, removal_bytes.clone())
            .await?;
        let _ = sim
            .until(
                "canonical r+1 reaches J and J records the marker",
                SETUP,
                async |s: &Sim| {
                    canonical =
                        pubsub_delivered(s, "O", "J", released_at, &removal_bytes).unwrap_or(0);
                    canonical > 0
                        && try_view_now(s, "J", &group)
                            .await
                            .is_ok_and(|v| v.is_some_and(|v| v.marker.is_some()))
                },
            )
            .await;
    }
    let j0 = try_view_now(sim, "J", &group).await?;
    let j0_text = j0
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    receipt.setup_done(at(sim));
    // Prerequisites: a missing one is INFRA, never RED.
    let gate_reason = gate.as_ref().and_then(|v| v.gap_refusal.as_deref());
    let armed = armed && gate_reason == Some("owner_attested_stale_base_gap");
    let on_fork = on_fork && j0.as_ref().is_some_and(|v| v.gap_refusal.is_some());
    receipt.evidence(
        "j_gap_gate_armed_by_o_v2_seal_before_the_window",
        armed
            && sealed.owner_axis
            && removal.state_revision == minted.state_revision + 1
            && !removal.lists(&x_hex)
            && sealed.state_revision == minted.state_revision + 2,
        format!(
            "join {join_code} {join_answer}; O at the mint {}; O after removal {}; O after J's \
             seal {}; J then {gate_text}",
            minted.describe(),
            removal.describe(),
            sealed.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "j_on_x_fork_at_r_plus_1_prime_with_its_gate",
        plane && fork_frames > 0 && on_fork && fork.state_revision == minted.state_revision + 1,
        format!(
            "X~J gossip plane {plane}; r+1′ frames X->J {fork_frames} (X publishes \
             {fork_publishes}); X {}; J {j0_text}",
            fork.describe()
        ),
        at(sim),
    );
    if !(armed && on_fork) {
        // INFRA: name the daemons' WARN logs since J's join.
        let logs: Vec<String> = sim
            .logs_containing(&[])
            .into_iter()
            .filter(|log| log.at >= join_t)
            .take(40)
            .map(|log| log.text.chars().take(300).collect())
            .collect();
        receipt.note(format!("WARN logs since J's join: {}", logs.join(" | ")));
        receipt.note("J's gate did not arm before the window: the row's prerequisite is missing");
        receipt.finish(last, false, at(sim));
        return Ok(None);
    }
    Ok(Some(Prefix {
        group,
        j_hex,
        minted,
        owner_key: owner.public_key().as_bytes().to_vec(),
        fork,
        joined_at,
        o_to_j_held,
        j_out_held,
        held_to_j,
        canonical,
    }))
}

/// J's recovery over H-S3-c's gate window, and the row's main observation.
struct Advanced {
    j_status: Option<Status>,
    /// J's record after the window.
    j1: View,
    states: Vec<String>,
    typed: bool,
    refs_ok: bool,
    unchanged: bool,
    kind: Option<String>,
    baseline: bool,
    /// Every answer J recorded from a peer it asked, over the advance.
    answers: std::collections::BTreeSet<String>,
    /// The `reseat_required` cause the row expects.
    cause: &'static str,
}

/// H-S3-c's "Advance 30 min" on `p` (or H-S3-d8's shorter `window`): J
/// must show `reseat_required {cause, ..}`, unchanged to the end. `None`
/// when H-S3-c2's prerequisite is missing: the receipt is then finished
/// under `last`.
async fn advance(
    sim: &mut Sim,
    receipt: &mut Receipt,
    p: &Prefix,
    both: bool,
    (window, cause): (Duration, &'static str),
    last: &str,
) -> Result<Option<Advanced>> {
    let Prefix {
        fork, held_to_j, ..
    } = p;
    let (group, joined_at, canonical) = (p.group.clone(), p.joined_at, p.canonical);

    // The advance: J's recovery states, sampled each poll. A failed read
    // stops the window and the row is INFRA.
    let mut states: Vec<String> = Vec::new();
    let mut answers = std::collections::BTreeSet::new();
    let mut seen = Observations::default();
    let waited = sim
        .until("the gate window", window, async |s: &Sim| {
            let Some(j_status) = seen.observe(status_now(s, "J", &group)).await else {
                return true;
            };
            if let Some(st) = j_status {
                let text = format!("{:?}{{{:?}}}", st.recovery_state(), st.recovery_cause());
                if states.last() != Some(&text) {
                    states.push(text);
                }
                let asked = st.recovery["asked"].as_array().into_iter().flatten();
                answers.extend(asked.filter_map(|a| a["answer"].as_str().map(str::to_string)));
            }
            false
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    seen.verify("the gate window")?;
    let j_status = status(sim, "J", &group).await?;
    let j1 = view(sim, "J", &group).await?;
    if both {
        // H-S3-c2 prerequisite: canonical r+1 reached J, so J holds both
        // the marker and the gap record before the re-seat. A missing one
        // is INFRA, never RED.
        let held = j1.marker.is_some() && j1.gap_refusal.is_some();
        receipt.evidence(
            "j_holds_marker_and_gap_before_the_reseat",
            held,
            format!(
                "J {}; re-published canonical r+1 frames O->J: {canonical}",
                j1.describe()
            ),
            at(sim),
        );
        if !held {
            receipt.note("J lacks the marker or the gap record: the row's prerequisite is missing");
            receipt.finish(last, false, at(sim));
            return Ok(None);
        }
    }
    let typed = j_status.as_ref().is_some_and(|st| {
        st.recovery_state() == Some("reseat_required") && st.recovery_cause() == Some(cause)
    });
    let kind = j_status
        .as_ref()
        .and_then(|st| st.recovery["ref"]["kind"].as_str().map(str::to_string));
    let refs_ok = match both {
        true => j1.marker.is_some() && j1.gap_refusal.is_some() && kind.is_some(),
        false => kind.as_deref() == Some("gap"),
    };
    let first_typed = states.iter().position(|s| s.contains("reseat_required"));
    let unchanged = first_typed.is_some_and(|i| states[i..].iter().all(|s| *s == states[i]));
    let home_gated = states.iter().any(|s| s.contains("home_gate_closed"));
    receipt.evidence(
        "j_recovery_not_home_gated",
        !home_gated,
        format!("J's recovery states over the advance {states:?}"),
        at(sim),
    );
    // The row's `main` observation (ADR 0109 §10): J stays on X's fork
    // with its gate armed and no typed state in any sample.
    let baseline = j1.state_hash == fork.state_hash
        && j1.gap_refusal.is_some()
        && !states.is_empty()
        && states.iter().all(|s| s == "None{None}")
        && (both || j1.marker.is_none());
    let to_j = delivered_after(sim, "O", "J", joined_at)?;
    receipt.request_delivered(
        "o_reached_j",
        to_j > 0,
        format!("frames O->J: {to_j}"),
        at(sim),
    );
    let j_text = j_status
        .as_ref()
        .map_or_else(|| "404".to_string(), Status::describe);
    receipt.note(format!(
        "after the advance: J {j_text}; J {}; states {states:?}; O's r+1 gossip frames to J \
         after r+1′ (held in c): {}; re-published to J (c2): {canonical}; answers J \
         recorded {answers:?}",
        j1.describe(),
        held_to_j.load(std::sync::atomic::Ordering::SeqCst)
    ));
    Ok(Some(Advanced {
        j_status,
        j1,
        states,
        typed,
        refs_ok,
        unchanged,
        kind,
        baseline,
        answers,
        cause,
    }))
}

/// A's or O's re-seat of J and what followed it.
struct Swap {
    code: StatusCode,
    /// The first sample in which J left containment before the swap.
    early_active: Option<String>,
    /// The issuer's head after the re-seat.
    head: View,
    j2: Option<View>,
    membership: Option<String>,
    /// `MemberAdded(J)` writes from the issuer, and whether any carried a
    /// `reseat_mandate` or an `owner_mandate`.
    adds: usize,
    reseat_mandate: bool,
    owner_mandate: bool,
    /// The re-seat invite the issuer stored, read right after the call
    /// (the issuer prunes it once J is seated). H-S3-c3 only.
    invite: Option<crate::groups::invite::SignedInvite>,
}

/// `issuer` calls the re-seat route for J with basis `Removal(j_removal)`;
/// J's live record is sampled until the keyed swap (ADR 0109 §3), each
/// sample checked against J's record after the advance. With `read_invite`
/// (H-S3-c3 only), the issuer's stored re-seat invite is read right after
/// the call; rows C and C2 do not read it.
async fn reseat_and_swap(
    sim: &Sim,
    receipt: &mut Receipt,
    p: &Prefix,
    adv: &Advanced,
    (issuer, read_invite): (&str, bool),
    j_removal: &View,
) -> Result<Swap> {
    let (group, j_hex) = (p.group.clone(), p.j_hex.clone());
    let (j1, j_status) = (&adv.j1, &adv.j_status);
    let cut = sim.fabric().writes().len();
    let path = format!("/groups/{group}/members/{j_hex}/reseat");
    let (reseat_code, answer) = sim
        .api(issuer, Method::POST, &path, Some(reseat_body(j_removal)))
        .await?;
    let invite = match read_invite {
        true => issued_invite(sim, issuer, &j_hex)?,
        false => None,
    };
    // Contained until the keyed swap (ADR 0109 §3): every sample is checked.
    let base_membership = j_status.as_ref().and_then(|st| st.membership.clone());
    let mut early_active = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("J is re-seated", RESEAT_BOUND, async |s: &Sim| {
            let Some(jv) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            // No call on J's API until the swap (the row's "with no call on
            // J's API"): see [`membership_now`].
            let Some(membership) = seen.observe(membership_now(s, "J", &group)).await else {
                return true;
            };
            let Some(again) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            // The issuer is read after J, so a swapped J never meets an older head.
            let Some(a) = seen.observe(view_now(s, issuer, &group)).await else {
                return true;
            };
            if !same_record(jv.as_ref(), again.as_ref()) {
                return false; // J moved between its reads: no consistent sample.
            }
            let membership = membership.as_deref();
            let sample = (jv.as_ref(), membership);
            let base = (j1, base_membership.as_deref());
            match staging(sample, &a, base, j_removal.state_revision) {
                Staging::Swapped => true,
                Staging::Contained => false,
                Staging::Breach => {
                    early_active.get_or_insert_with(|| {
                        let j = jv
                            .as_ref()
                            .map_or_else(|| "no record".into(), View::describe);
                        format!("J {j} membership {membership:?}; {issuer} {}", a.describe())
                    });
                    false
                }
            }
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    seen.verify("J is re-seated")?;
    let head = view(sim, issuer, &group).await?;
    let j2 = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    // The probe, not `GET /groups/:id`: with no swap J is still in staging,
    // and the GET does not return in one virtual instant there.
    let membership = sim
        .at_instant("read J's membership", membership_now(sim, "J", &group))
        .await??;
    let (adds, reseat_mandate, owner_mandate) = member_added_mandates(sim, cut, issuer, "J")?;
    let j2_text = j2
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    receipt.note(format!(
        "reseat by {issuer} {reseat_code} {answer}; J removed at {}; {issuer} {}; J {j2_text}; J \
         membership {membership:?}; {issuer}'s MemberAdded(J) writes {adds} reseat_mandate \
         {reseat_mandate} owner_mandate {owner_mandate}; J membership after the advance \
         {base_membership:?}; early_active={early_active:?}",
        j_removal.state_revision,
        head.describe()
    ));
    Ok(Swap {
        code: reseat_code,
        early_active,
        head,
        j2,
        membership,
        adds,
        reseat_mandate,
        owner_mandate,
        invite,
    })
}

/// H-S3-c, or with `both` H-S3-c2 (ADR 0109 §10). Each candidate step is a
/// named sub-check; a red run lists the ones that fail.
async fn owner_reseat(sim: &mut Sim, receipt: &mut Receipt, both: bool) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, both, FINAL_C).await? else {
        return Ok(());
    };
    let Some(adv) = advance(
        sim,
        receipt,
        &p,
        both,
        (GATE_WINDOW, "not_on_chain"),
        FINAL_C,
    )
    .await?
    else {
        return Ok(());
    };
    let (group, j_hex, o_to_j_held) = (p.group.clone(), p.j_hex.clone(), &p.o_to_j_held);
    // The capability floor: A holds O's current mandate advert, then O stops.
    let o_agent = sim.ids("O")?.0;
    let bit = crate::dm::CapabilityRegistry::GROUP_RESEAT_MANDATE_V1;
    let floor = sim
        .until("A holds O's mandate advert", SETUP, async |s: &Sim| {
            let Ok(st) = s.state("A") else {
                return false;
            };
            if st
                .agent
                .capability_store()
                .verified_registry_supports(&o_agent, bit)
                == Some(true)
            {
                return true;
            }
            st.agent.refresh_application_capability(o_agent, bit).await;
            false
        })
        .await
        .is_ok();
    sim.stop("O", RestartMode::Graceful).await?;
    // #1689 review: the O->J hold ends only once O is stopped, so a late
    // O re-send of r+2 cannot reach J between the advance and the stop.
    o_to_j_held.store(false, std::sync::atomic::Ordering::SeqCst);
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes J: {code} {body}");
    sim.until("A no longer lists J", SETUP, async |s: &Sim| {
        view_now(s, "A", &group)
            .await
            .is_ok_and(|v| !v.lists(&j_hex))
    })
    .await?;
    let j_removal = view(sim, "A", &group).await?;
    let swap = reseat_and_swap(sim, receipt, &p, &adv, ("A", false), &j_removal).await?;
    let mut checks = advance_checks(&p, &adv, both);
    checks.extend([
        ("a_holds_o_mandate_advert_before_o_stops", floor),
        (
            "reseat_route_accepts_with_owner_offline",
            swap.code.is_success(),
        ),
        ("member_added_carries_reseat_mandate", swap.reseat_mandate),
        (
            "member_added_carries_no_owner_mandate",
            swap.adds > 0 && !swap.owner_mandate,
        ),
    ]);
    checks.extend(swap_checks(&p, &swap));
    // Restart O after the swap; O applies it and O's next rename applies.
    sim.start_again("O").await?;
    let head = &swap.head;
    let o_applies = reaches(sim, "O", &group, &head.state_hash, SETUP).await;
    checks.push(("restarted_o_applies_the_reseat", o_applies));
    let mut rename_applies = false;
    if o_applies {
        rename(sim, "O", &group, "w3h c O after").await?;
        let o_head = view(sim, "O", &group).await?;
        rename_applies = reaches(sim, "A", &group, &o_head.state_hash, SETUP).await
            && reaches(sim, "J", &group, &o_head.state_hash, SETUP).await;
    }
    checks.push(("a_and_j_apply_o_next_rename", rename_applies));
    let red = adv.baseline || swap.early_active.is_some();
    settle(sim, receipt, (FINAL_C, CAUSE_C), &adv, &swap, &checks, red);
    Ok(())
}

/// The advance's sub-checks, shared by the owner-axis rows.
fn advance_checks(p: &Prefix, adv: &Advanced, both: bool) -> Vec<(&'static str, bool)> {
    let refs = match both {
        true => "j_holds_marker_and_gap_ref_named",
        false => "ref_kind_gap",
    };
    vec![
        (
            "j_gate_still_armed_after_the_advance",
            adv.j1.gap_refusal.is_some(),
        ),
        (
            match adv.cause {
                "not_a_member" => "j_typed_reseat_required_not_a_member",
                _ => "j_typed_reseat_required_not_on_chain",
            },
            adv.typed,
        ),
        (refs, adv.refs_ok),
        (
            "typed_state_unchanged_to_the_end_of_the_advance",
            adv.unchanged,
        ),
        (
            "j_contained_on_x_fork_after_the_advance",
            adv.j1.state_hash == p.fork.state_hash,
        ),
    ]
}

/// The keyed swap's sub-checks: J stays contained until the swap, then is
/// Active with keys at the issuer's r+4 head, with its records retired.
fn swap_checks(p: &Prefix, swap: &Swap) -> Vec<(&'static str, bool)> {
    vec![
        (
            "reseat_head_at_r_plus_4",
            swap.head.state_revision == p.minted.state_revision + 4,
        ),
        (
            "j_contained_until_the_keyed_swap",
            swap.early_active.is_none(),
        ),
        (
            "j_active_with_keys_at_the_issuer_head_and_epoch",
            caught_up(swap.j2.as_ref(), &swap.head, swap.membership.as_deref()),
        ),
        (
            "j_marker_and_gap_record_retired",
            swap.j2
                .as_ref()
                .is_some_and(|v| v.marker.is_none() && v.gap_refusal.is_none()),
        ),
    ]
}

/// Notes the row's sub-checks and concludes it under `(last, cause)`.
fn settle(
    sim: &Sim,
    receipt: &mut Receipt,
    (last, cause): (&str, &str),
    adv: &Advanced,
    swap: &Swap,
    checks: &[(&str, bool)],
    red: bool,
) {
    let failing: Vec<&str> = checks
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(n, _)| *n)
        .collect();
    receipt.note(format!("sub-checks {checks:?}; ref_kind={:?}", adv.kind));
    let j2_text = swap
        .j2
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    let observed = format!(
        "failing {failing:?}; J after the advance {}; states {:?}; reseat {}; issuer {}; J \
         {j2_text}",
        adv.j1.describe(),
        adv.states,
        swap.code,
        swap.head.describe()
    );
    conclude_row(receipt, (last, cause), &failing, observed, red, at(sim));
}

// ─── H-S3-c3 ──────────────────────────────────────────────────────────────

const FINAL_C3: &str = "owner_reseats_j_with_a_countersigned_invite_and_its_owner_mandate";
const CAUSE_C3: &str = "the row's main observation: O's re-seat route returns 404 (no S3 \
                        re-seat); or J leaves containment before the keyed swap (ADR 0109 \
                        §3); `observed` lists each failing step";

/// H-S3-c3 (owner path): H-S3-c with O online throughout. O removes J
/// (r+3) and calls reseat with basis `Removal(r+3)`.
async fn owner_path_reseat(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let Some(p) = fork_prefix(sim, receipt, false, FINAL_C3).await? else {
        return Ok(());
    };
    let Some(adv) = advance(
        sim,
        receipt,
        &p,
        false,
        (GATE_WINDOW, "not_on_chain"),
        FINAL_C3,
    )
    .await?
    else {
        return Ok(());
    };
    let (group, j_hex) = (&p.group, &p.j_hex);
    // O stays online, so its direct writes to J pass from here (the re-seat
    // needs them). O's held r+1 and r+2 gossip IDs stay held from J.
    p.o_to_j_held
        .store(false, std::sync::atomic::Ordering::SeqCst);
    sim.fabric().mark("fault: O's direct writes pass to J");
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "O removes J: {code} {body}");
    sim.until("O no longer lists J", SETUP, async |s: &Sim| {
        view_now(s, "O", group).await.is_ok_and(|v| !v.lists(j_hex))
    })
    .await?;
    let j_removal = view(sim, "O", group).await?;
    let swap = reseat_and_swap(sim, receipt, &p, &adv, ("O", true), &j_removal).await?;
    let invite = swap.invite.as_ref();
    let countersignature = invite.map(|i| owner_countersignature(i, &p.owner_key));
    let countersigned = invite
        .is_some_and(|i| i.version == crate::groups::invite::INVITE_VERSION_V4)
        && countersignature == Some(Ok(()));
    receipt.note(format!(
        "O's issued re-seat invite: version {:?}, owner countersignature verified under O's \
         USER key {countersigned} ({countersignature:?})",
        invite.map(|i| i.version)
    ));
    let mut checks = advance_checks(&p, &adv, false);
    checks.extend([
        (
            "reseat_route_accepts_on_the_owner_path",
            swap.code.is_success(),
        ),
        ("o_mints_an_owner_countersigned_invite_v4", countersigned),
        (
            "member_added_carries_owner_mandate",
            swap.adds > 0 && swap.owner_mandate,
        ),
        (
            "member_added_carries_no_reseat_mandate",
            !swap.reseat_mandate,
        ),
    ]);
    checks.extend(swap_checks(&p, &swap));
    let red = swap.code == StatusCode::NOT_FOUND || swap.early_active.is_some();
    settle(
        sim,
        receipt,
        (FINAL_C3, CAUSE_C3),
        &adv,
        &swap,
        &checks,
        red,
    );
    Ok(())
}

// ─── H-S3-d8 ──────────────────────────────────────────────────────────────

const FINAL_D8: &str = "j_reseat_required_not_a_member_then_a_removal_basis_reseats_it";
const CAUSE_D8: &str = "the row's main observation: after the advance J stays on X's fork r+1′ \
                        with its gap gate armed and no typed re-seat state (as H-S3-c); or O's \
                        route returns 404; or J leaves containment before the keyed swap \
                        (ADR 0109 §3); `observed` lists each failing step";
/// One request interval (§11: the first retry after 60 s, plus margin).
const REQUEST_INTERVAL: Duration = Duration::from_secs(70);

/// H-S3-d8 (`Removal` basis): H-S3-c up to r+1′ on J. With J's writes to
/// A and O held, A removes J (r+3); after `GATE_STALL` and one request
/// interval J shows `reseat_required {not_a_member, Gap(..)}`, and O's
/// re-seat with basis `Removal(r+3)` swaps J in at r+4.
async fn removal_basis_reseat(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    use std::sync::atomic::Ordering;
    let Some(p) = fork_prefix(sim, receipt, false, FINAL_D8).await? else {
        return Ok(());
    };
    let (group, j_hex) = (&p.group, &p.j_hex);
    p.j_out_held.store(true, Ordering::SeqCst);
    sim.fabric()
        .mark("fault: every write from J to A and O held");
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = sim.api("A", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "A removes J: {code} {body}");
    let j_removal = view(sim, "A", group).await?;
    all_reach(sim, &["O"], group, &j_removal.state_hash).await?;
    p.j_out_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: J's writes to A and O released");
    // O's direct writes stay held from J for the advance, as in H-S3-c, so
    // J's answers come from A; they pass from the re-seat on (H-S3-c3).
    let window = (
        crate::groups::recovery::GATE_STALL + REQUEST_INTERVAL,
        "not_a_member",
    );
    let Some(adv) = advance(sim, receipt, &p, false, window, FINAL_D8).await? else {
        return Ok(());
    };
    p.o_to_j_held.store(false, Ordering::SeqCst);
    sim.fabric().mark("fault: O's direct writes pass to J");
    let swap = reseat_and_swap(sim, receipt, &p, &adv, ("O", false), &j_removal).await?;
    // O's answers stay held from J over the advance, so O shows `pending`.
    let answered: Vec<&String> = adv.answers.iter().filter(|a| *a != "pending").collect();
    let only_not_a_member = !answered.is_empty() && answered.iter().all(|a| *a == "not_a_member");
    let mut checks = advance_checks(&p, &adv, false);
    checks.extend([
        (
            "a_removal_at_r_plus_3",
            j_removal.state_revision == p.minted.state_revision + 3 && !j_removal.lists(j_hex),
        ),
        ("j_requests_answered_only_not_a_member", only_not_a_member),
        (
            "reseat_route_accepts_the_removal_basis",
            swap.code.is_success(),
        ),
        (
            "member_added_carries_owner_mandate",
            swap.adds > 0 && swap.owner_mandate,
        ),
    ]);
    checks.extend(swap_checks(&p, &swap));
    let red = adv.baseline || swap.code == StatusCode::NOT_FOUND || swap.early_active.is_some();
    settle(
        sim,
        receipt,
        (FINAL_D8, CAUSE_D8),
        &adv,
        &swap,
        &checks,
        red,
    );
    Ok(())
}

/// The owner countersignature on `invite`, checked as production checks it
/// (`SignedInvite::verify_v4_owner_countersignature`: the canonical v4
/// bytes under the inline owner key, bound to the policy's owner id). The
/// inline key must also be `owner_key` (O's), and the countersignature
/// must be present: the production check is a no-op without an owner axis.
fn owner_countersignature(
    invite: &crate::groups::invite::SignedInvite,
    owner_key: &[u8],
) -> Result<(), String> {
    use base64::Engine as _;
    let inline = invite
        .owner_public_key_b64
        .as_deref()
        .and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok());
    if inline.as_deref() != Some(owner_key) {
        return Err("the inline owner key is not O's USER key".to_string());
    }
    if invite.owner_countersignature_b64.is_none() {
        return Err("no owner countersignature".to_string());
    }
    invite
        .verify_v4_owner_countersignature()
        .map_err(|refusal| format!("{refusal:?}"))
}

/// The newest re-seat invite `issuer` issued for `subject`, read from the
/// S3 sidecar files under its data directory. The read is passive, so it
/// runs while `issuer` is up (`Sim::data_dir` is for stopped nodes).
fn issued_invite(
    sim: &Sim,
    issuer: &str,
    subject: &str,
) -> Result<Option<crate::groups::invite::SignedInvite>> {
    use crate::groups::recovery::{decode_sidecar, GROUP_RECOVERY_EXTENSION};
    let mut dirs = vec![sim.root.path().join(issuer).join("data")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path
                .extension()
                .is_none_or(|e| e != GROUP_RECOVERY_EXTENSION)
            {
                continue;
            }
            let Ok(body) = decode_sidecar(&std::fs::read(&path)?) else {
                continue;
            };
            let issued = body
                .issued_reseats
                .iter()
                .rev()
                .find(|i| i.authorisation.fields.subject.eq_ignore_ascii_case(subject));
            if let Some(issued) = issued {
                return crate::groups::invite::SignedInvite::from_link(&issued.invite)
                    .map(Some)
                    .map_err(|e| anyhow!("{issuer}'s re-seat invite: {e}"));
            }
        }
    }
    Ok(None)
}

/// `label`'s `membership_state` for `group` (the label `GET /groups/:id`
/// reports), read from the daemon's state; `None` with no record of it.
///
/// The staging samples must not call J's API: H-S3-c says "with no call on
/// J's API, J stays contained until the swap". `GET /groups/:id` is not a
/// pure read. It swaps a seated staging record in (`recovery_json`) and
/// applies retained owner-cert joins (`retry_pending_owner_cert_joins`), so
/// it can change J and it can block. In CI run 40730491973, three of four
/// row runs were INFRA with "a read was still running when the wait ended
/// (10 started, 9 completed)". A sample makes four reads, so read 10 was the
/// GET of the third sample. This probe reads the same label from J's state
/// with no side effects. It admits nothing, so the #1166
/// `disallowed_methods` rule is allowed here.
#[allow(clippy::disallowed_methods)]
async fn membership_now(sim: &Sim, label: &str, group: &str) -> Result<Option<String>> {
    let state = sim.state(label)?;
    let info = {
        let groups = state.named_groups.read().await;
        match crate::server::resolve_group_entry_locked(&groups, group) {
            Some((_, info)) => info.clone(),
            None => return Ok(None),
        }
    };
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let membership =
        crate::server::routes::named_groups::local_join_membership_state(&state, &info, &local)
            .await;
    Ok(Some(membership.to_string()))
}

/// One staging sample of J's live record, from the issuer's re-seat call on.
#[derive(Debug, PartialEq)]
enum Staging {
    Contained,
    Swapped,
    Breach,
}

/// ADR 0109 §3: until the keyed swap, J's live record stays as it was
/// after the advance (`base`: same hash, gate armed, same marker presence,
/// same membership label). The swap is J Active with keys at the issuer's
/// head (`a`) past its removal of J (`removal`), with the gate retired. Any
/// other sample is a breach: for example J Active while the issuer is still
/// at the removal revision, or Active at its new hash before J has keys.
fn staging(
    (j, membership): (Option<&View>, Option<&str>),
    a: &View,
    (base, base_membership): (&View, Option<&str>),
    removal: u64,
) -> Staging {
    let retired = j.is_some_and(|v| v.gap_refusal.is_none());
    if a.state_revision > removal && caught_up(j, a, membership) && retired {
        return Staging::Swapped;
    }
    let contained = j.is_some_and(|v| {
        v.state_hash == base.state_hash
            && v.gap_refusal.is_some()
            && v.marker.is_some() == base.marker.is_some()
    }) && membership == base_membership;
    match contained {
        true => Staging::Contained,
        false => Staging::Breach,
    }
}

/// Two reads of one node's record agree on the fields [`staging`] reads.
fn same_record(one: Option<&View>, two: Option<&View>) -> bool {
    match (one, two) {
        (Some(x), Some(y)) => {
            x.state_hash == y.state_hash
                && x.epoch == y.epoch
                && x.gap_refusal == y.gap_refusal
                && x.marker.is_some() == y.marker.is_some()
        }
        (None, None) => true,
        _ => false,
    }
}

/// RED only with the row's main observation or a staging breach (`red`);
/// any other failure is INFRA.
fn conclude(receipt: &mut Receipt, failing: &[&str], observed: String, red: bool, at_us: u128) {
    conclude_row(receipt, (FINAL_C, CAUSE_C), failing, observed, red, at_us);
}

/// [`conclude`] for a row with its own final step and RED cause.
fn conclude_row(
    receipt: &mut Receipt,
    (last, cause): (&str, &str),
    failing: &[&str],
    observed: String,
    red: bool,
    at_us: u128,
) {
    if !failing.is_empty() {
        receipt.cause(cause, Some(observed), red, at_us);
    }
    receipt.finish(last, failing.is_empty(), at_us);
}

#[derive(Clone, Copy)]
enum Row {
    Control,
    C,
    C2,
    C3,
    D8,
}

async fn run(case: &str, seed: u64, row: Row) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    let (labels, last) = match row {
        Row::Control => (LABELS, FINAL),
        Row::C | Row::C2 => (C_LABELS, FINAL_C),
        Row::C3 => (C_LABELS, FINAL_C3),
        Row::D8 => (C_LABELS, FINAL_D8),
    };
    receipt.note(match row {
        Row::Control => "OwnerCertified harness support (#1666): A has no USER key".to_string(),
        Row::C => "ADR 0109 S3 (#1356, #1572) H-S3-c; O alone holds the USER key".to_string(),
        Row::C2 => "ADR 0109 S3 (#1356, #1572) H-S3-c2; O alone holds the USER key".to_string(),
        Row::C3 => "ADR 0109 S3 (#1356, #1572) H-S3-c3; O online throughout".to_string(),
        Row::D8 => "ADR 0109 S3 (#1356, #1572) H-S3-d8; A removes J, O re-seats".to_string(),
    });
    match Sim::empty(case, seed, labels) {
        Ok(mut sim) => {
            let ran = match row {
                Row::Control => scenario(&mut sim, &mut receipt).await,
                Row::C => owner_reseat(&mut sim, &mut receipt, false).await,
                Row::C2 => owner_reseat(&mut sim, &mut receipt, true).await,
                Row::C3 => owner_path_reseat(&mut sim, &mut receipt).await,
                Row::D8 => removal_basis_reseat(&mut sim, &mut receipt).await,
            };
            if let Err(error) = ran {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(last);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, row: Row) -> Result<()> {
    let receipt = run(case, seed, row).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// Control: a certificate-only admin seals an OwnerCertified group.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1666_control_certificate_only_admin_seals() -> Result<()> {
    let case = "w3h_1666_control_certificate_only_admin_seals";
    super::super::block_on_paused(expect(case, 0x1666_0001, Row::Control))
}

/// H-S3-c (#871, D78, D79, D121, D156): RED on `main`; GREEN with ADR 0109
/// S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node() -> Result<()> {
    let case = "w3h_1356_red_s3_c_promoted_admin_reseats_owner_axis_node";
    super::super::block_on_paused(expect(case, 0x1356_0106, Row::C))
}

/// H-S3-c2 (both records): RED on `main`; GREEN with ADR 0109 S3.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_red_s3_c2_reseat_retires_marker_and_gap() -> Result<()> {
    let case = "w3h_1356_red_s3_c2_reseat_retires_marker_and_gap";
    super::super::block_on_paused(expect(case, 0x1356_0107, Row::C2))
}

/// H-S3-c3 (owner path): a control; on `main` before S3 the route returned
/// 404.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_c3_owner_reseats_owner_axis_node() -> Result<()> {
    let case = "w3h_1356_control_s3_c3_owner_reseats_owner_axis_node";
    super::super::block_on_paused(expect(case, 0x1356_0109, Row::C3))
}

/// H-S3-d8 (`Removal` basis): a control; on `main` before S3, J stayed at
/// r+1′ with no typed state, as in H-S3-c.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1356_control_s3_d8_removal_basis_reseats_owner_axis_node() -> Result<()> {
    let case = "w3h_1356_control_s3_d8_removal_basis_reseats_owner_axis_node";
    super::super::block_on_paused(expect(case, 0x1356_0110, Row::D8))
}

/// A record for the staging tests: J's fork is r+1′ (11), A removes J at
/// r+3 (13) and re-seats it at r+4 (14).
fn rec(state_revision: u64, hash: &str, gate: bool, epoch: Option<u64>) -> View {
    View {
        state_revision,
        roster_revision: state_revision,
        state_hash: hash.to_string(),
        owner_axis: true,
        active: Vec::new(),
        marker: None,
        fork_evidence: false,
        gap_refusal: gate.then(|| "owner_attested_stale_base_gap".to_string()),
        base_revision: None,
        epoch,
    }
}

/// A receipt whose prerequisites all hold.
fn prepared() -> Receipt {
    let mut receipt = Receipt::new("w3h_staging", 1);
    receipt.setup_done(1);
    receipt.evidence("j_gap_gate_armed", true, "", 2);
    receipt.request_delivered("o_reached_j", true, "", 3);
    receipt
}

/// The row's verdict over staging samples `(J, J's membership, A)`, with
/// every other check passing, as the row's loop and [`conclude`] run.
fn staged_verdict(samples: &[(View, &str, View)]) -> Option<Verdict> {
    let base = rec(11, "fork", true, Some(1));
    let breach = samples
        .iter()
        .map(|(j, m, a)| staging((Some(j), Some(m)), a, (&base, Some("pending")), 13))
        .take_while(|sample| *sample != Staging::Swapped)
        .any(|sample| sample == Staging::Breach);
    let failing: &[&str] = if breach {
        &["j_contained_until_the_keyed_swap"]
    } else {
        &[]
    };
    let mut receipt = prepared();
    conclude(&mut receipt, failing, String::new(), breach, 4);
    receipt.verdict()
}

/// Mutation proof for the staging check (ADR 0109 §3): the real order
/// (contained, then the keyed swap at A's r+4 head) is GREEN; activation
/// forced early at any point in staging is RED.
#[test]
fn w3h_1356_staging_containment_mutation_proof() {
    let fork = |m| {
        (
            rec(11, "fork", true, Some(1)),
            m,
            rec(13, "removal", false, Some(4)),
        )
    };
    let at_head = |m| {
        (
            rec(11, "fork", true, Some(1)),
            m,
            rec(14, "head", false, Some(5)),
        )
    };
    let swap = (
        rec(14, "head", false, Some(5)),
        "active",
        rec(14, "head", false, Some(5)),
    );
    let real = [fork("pending"), at_head("pending"), swap.clone()];
    assert_eq!(staged_verdict(&real), Some(Verdict::Green));
    let removal = rec(13, "removal", false, Some(4));
    // J's base record with one field of the containment check mutated.
    let marked = View {
        marker: Some(Marker {
            revision: 11,
            no_anchor: false,
            classification: None,
            committed_by: "o".to_string(),
        }),
        ..rec(11, "fork", true, Some(1))
    };
    let early = [
        fork("active"),
        (removal.clone(), "active", removal),
        (
            rec(14, "head", false, None),
            "active",
            rec(14, "head", false, Some(5)),
        ),
        at_head("active"),
        // The swap shape with the gate still armed is not the swap.
        (
            rec(14, "head", true, Some(5)),
            "active",
            rec(14, "head", false, Some(5)),
        ),
        // The gate retired in staging.
        (
            rec(11, "fork", false, Some(1)),
            "pending",
            rec(14, "head", false, Some(5)),
        ),
        // The marker presence flipped in staging.
        (marked, "pending", rec(14, "head", false, Some(5))),
        // J moved off its base hash in staging.
        (
            rec(12, "other", true, Some(1)),
            "pending",
            rec(14, "head", false, Some(5)),
        ),
    ];
    for sample in early {
        let verdict = staged_verdict(&[sample.clone(), swap.clone()]);
        assert_eq!(verdict, Some(Verdict::Red), "{sample:?}");
    }
    // After the swap, staging is over.
    assert_eq!(
        staged_verdict(&[swap, fork("active")]),
        Some(Verdict::Green)
    );
    // Any other failure without the main observation stays INFRA.
    let mut receipt = prepared();
    conclude(
        &mut receipt,
        &["reseat_head_at_r_plus_4"],
        String::new(),
        false,
        4,
    );
    assert_eq!(receipt.verdict(), Some(Verdict::Infra));
}
