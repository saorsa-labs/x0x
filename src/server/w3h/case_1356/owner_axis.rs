//! OwnerCertified harness support (#1666) and the ADR 0109 §10 rows
//! H-S3-c and H-S3-c2 (#871, D78, D79, D121, D156, #1572). O is the only
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
//! row's main observation (`CAUSE_C`); a missing prerequisite or any other
//! failure is INFRA.

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

/// An OwnerCertified TreeKEM group that is not the Home policy: admin-only
/// writes keep it off ADR 0109 §4's Home gate (`home_gate_closed`) and out
/// of Home adoption (#1687). Hidden + MlsEncrypted keeps the TreeKEM plane.
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
                       `observed` lists each failing candidate step";
/// H-S3-c: "Advance 30 min".
const GATE_WINDOW: Duration = Duration::from_secs(30 * 60);

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

/// H-S3-c, or with `both` H-S3-c2 (ADR 0109 §10). Each candidate step is a
/// named sub-check; a red run lists the ones that fail.
async fn owner_reseat(sim: &mut Sim, receipt: &mut Receipt, both: bool) -> Result<()> {
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

    // X is cut; O's r+1 publish (and its relays) is captured and held
    // from J.
    let held: Arc<Mutex<std::collections::HashSet<[u8; 32]>>> = Arc::default();
    let is_held = |held: &Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
                   msg: Option<[u8; 32]>| {
        msg.is_some_and(|id| held.lock().map_or(true, |h| h.contains(&id)))
    };
    let capture = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let held_to_j = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hold = install_hold(sim);
    {
        let (held, capture) = (Arc::clone(&held), Arc::clone(&capture));
        set_hold(
            sim,
            &hold,
            "X cut; O's r+1 captured",
            move |origin, dst, msg| {
                if let (Some(id), true, Ok(mut set)) = (msg, origin == o, held.lock()) {
                    if capture.load(std::sync::atomic::Ordering::SeqCst) {
                        set.insert(id);
                    }
                }
                origin == x || dst == x || (dst == j && is_held(&held, msg))
            },
        );
    }
    let x_hex = sim.agent_hex("X")?;
    let path = format!("/groups/{group}/members/{x_hex}");
    let (code, body) = sim.api("O", Method::DELETE, &path, None).await?;
    ensure!(code.is_success(), "O removes X: {code} {body}");
    let removal = view(sim, "O", &group).await?;
    all_reach(sim, &["A"], &group, &removal.state_hash).await?;
    sim.within("the removal resends end", RESENDS_DONE + secs(2), async {
        tokio::time::sleep(RESENDS_DONE).await;
    })
    .await?;
    capture.store(false, std::sync::atomic::Ordering::SeqCst);

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
    let gate = try_view_now(sim, "J", &group).await?;
    let gate_text = gate
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);

    // X reaches J only, and J hears only X (so its catch-up with O and A
    // waits too, as the ADR orders it), until r+1′ lands. Then X is
    // fully cut (its catch-up loop with J is #1685). H-S3-c keeps O's r+1
    // gossip held from J; H-S3-c2 releases it.
    let cut_x = move |origin: Key, dst: Key| (origin == x && dst != j) || (dst == x && origin != j);
    set_hold(
        sim,
        &hold,
        "X reaches J only; J hears only X",
        move |origin, dst, _| cut_x(origin, dst) || (dst == j && origin != x),
    );
    rename(sim, "X", &group, "w3h c X").await?;
    let fork = view(sim, "X", &group).await?;
    let on_fork = reaches(sim, "J", &group, &fork.state_hash, SETUP).await;
    {
        let (held, held_to_j) = (Arc::clone(&held), Arc::clone(&held_to_j));
        let what = match both {
            true => "X cut; canonical r+1 released to J",
            false => "X cut; O's r+1 gossip held from J",
        };
        set_hold(sim, &hold, what, move |origin, dst, msg| {
            let to_j = dst == j && is_held(&held, msg);
            if to_j {
                held_to_j.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            origin == x || dst == x || (!both && to_j)
        });
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
        on_fork && fork.state_revision == minted.state_revision + 1,
        format!("X {}; J {j0_text}", fork.describe()),
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
        receipt.finish(FINAL_C, false, at(sim));
        return Ok(());
    }

    // The advance: J's recovery states, sampled each poll.
    let mut states: Vec<String> = Vec::new();
    let waited = sim
        .until("the gate window", GATE_WINDOW, async |s: &Sim| {
            if let Ok(Some(st)) = status_now(s, "J", &group).await {
                let text = format!("{:?}{{{:?}}}", st.recovery_state(), st.recovery_cause());
                if states.last() != Some(&text) {
                    states.push(text);
                }
            }
            false
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
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
                "J {}; O's r+1 gossip frames to J after r+1′: {}",
                j1.describe(),
                held_to_j.load(std::sync::atomic::Ordering::SeqCst)
            ),
            at(sim),
        );
        if !held {
            receipt.note("J lacks the marker or the gap record: the row's prerequisite is missing");
            receipt.finish(FINAL_C, false, at(sim));
            return Ok(());
        }
    }
    let typed = j_status.as_ref().is_some_and(|st| {
        st.recovery_state() == Some("reseat_required")
            && st.recovery_cause() == Some("not_on_chain")
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
         after r+1′ (held in c, released in c2): {}",
        j1.describe(),
        held_to_j.load(std::sync::atomic::Ordering::SeqCst)
    ));

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
    let cut = sim.fabric().writes().len();
    let path = format!("/groups/{group}/members/{j_hex}/reseat");
    let (reseat_code, answer) = sim
        .api("A", Method::POST, &path, Some(reseat_body(&j_removal)))
        .await?;
    // Contained until the swap: J is never Active below A's re-seat head.
    let mut early_active = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("J is re-seated", RESEAT_BOUND, async |s: &Sim| {
            let Some(a) = seen.observe(view_now(s, "A", &group)).await else {
                return true;
            };
            let Some(jv) = seen.observe(try_view_now(s, "J", &group)).await else {
                return true;
            };
            let Some(st) = seen.observe(status_now(s, "J", &group)).await else {
                return true;
            };
            let membership = st.as_ref().and_then(|st| st.membership.as_deref());
            if membership == Some("active") && a.state_revision > j_removal.state_revision {
                if let Some(v) = jv.as_ref().filter(|v| v.state_hash != a.state_hash) {
                    early_active.get_or_insert_with(|| v.describe());
                }
            }
            caught_up(jv.as_ref(), &a, membership)
                && jv.as_ref().is_some_and(|v| v.gap_refusal.is_none())
        })
        .await;
    if let Err(error) = waited {
        ensure!(expired(&error), error);
    }
    seen.verify("J is re-seated")?;
    let head = view(sim, "A", &group).await?;
    let j2 = sim
        .at_instant("read J's group", try_view_now(sim, "J", &group))
        .await??;
    let membership = status(sim, "J", &group).await?.and_then(|st| st.membership);
    let (adds, reseat_mandate, owner_mandate) = member_added_mandates(sim, cut, "A", "J")?;
    let j2_text = j2
        .as_ref()
        .map_or_else(|| "no record".to_string(), View::describe);
    receipt.note(format!(
        "reseat {reseat_code} {answer}; A removed J at {}; A {}; J {j2_text}; J membership \
         {membership:?}; A's MemberAdded(J) writes {adds} reseat_mandate {reseat_mandate} \
         owner_mandate {owner_mandate}",
        j_removal.state_revision,
        head.describe()
    ));
    let mut checks: Vec<(&str, bool)> = vec![
        (
            "j_gate_still_armed_after_the_advance",
            j1.gap_refusal.is_some(),
        ),
        ("j_typed_reseat_required_not_on_chain", typed),
        (
            if both {
                "j_holds_marker_and_gap_ref_named"
            } else {
                "ref_kind_gap"
            },
            refs_ok,
        ),
        ("typed_state_unchanged_to_the_end_of_the_advance", unchanged),
        (
            "j_contained_on_x_fork_after_the_advance",
            j1.state_hash == fork.state_hash,
        ),
        ("a_holds_o_mandate_advert_before_o_stops", floor),
        (
            "reseat_route_accepts_with_owner_offline",
            reseat_code.is_success(),
        ),
        (
            "a_reseat_head_at_r_plus_4",
            head.state_revision == minted.state_revision + 4,
        ),
        ("member_added_carries_reseat_mandate", reseat_mandate),
        (
            "member_added_carries_no_owner_mandate",
            adds > 0 && !owner_mandate,
        ),
        ("j_not_active_before_the_swap", early_active.is_none()),
        (
            "j_active_with_keys_at_a_head_and_epoch",
            caught_up(j2.as_ref(), &head, membership.as_deref()),
        ),
        (
            "j_marker_and_gap_record_retired",
            j2.as_ref()
                .is_some_and(|v| v.marker.is_none() && v.gap_refusal.is_none()),
        ),
    ];
    // Restart O after the swap; O applies it and O's next rename applies.
    sim.start_again("O").await?;
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
    let failing: Vec<&str> = checks
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(n, _)| *n)
        .collect();
    receipt.note(format!(
        "sub-checks {checks:?}; ref_kind={kind:?}; early_active={early_active:?}"
    ));
    if !failing.is_empty() {
        let observed = format!(
            "failing {failing:?}; J after the advance {}; states {states:?}; reseat {reseat_code}; \
             A {}; J {j2_text}",
            j1.describe(),
            head.describe()
        );
        // RED only with the row's own baseline; any other failure is INFRA.
        receipt.cause(CAUSE_C, Some(observed), baseline, at(sim));
    }
    receipt.finish(FINAL_C, failing.is_empty(), at(sim));
    Ok(())
}

#[derive(Clone, Copy)]
enum Row {
    Control,
    C,
    C2,
}

async fn run(case: &str, seed: u64, row: Row) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    let (labels, last) = match row {
        Row::Control => (LABELS, FINAL),
        Row::C | Row::C2 => (C_LABELS, FINAL_C),
    };
    receipt.note(match row {
        Row::Control => "OwnerCertified harness support (#1666): A has no USER key".to_string(),
        Row::C => "ADR 0109 S3 (#1356, #1572) H-S3-c; O alone holds the USER key".to_string(),
        Row::C2 => "ADR 0109 S3 (#1356, #1572) H-S3-c2; O alone holds the USER key".to_string(),
    });
    match Sim::empty(case, seed, labels) {
        Ok(mut sim) => {
            let ran = match row {
                Row::Control => scenario(&mut sim, &mut receipt).await,
                Row::C => owner_reseat(&mut sim, &mut receipt, false).await,
                Row::C2 => owner_reseat(&mut sim, &mut receipt, true).await,
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
