//! W3-H case for #1023 (#1364): a restarted promoted admin cannot admit a
//! new joiner while the creator and every eligible holder are offline.
//!
//! Nodes: O (owner device and group creator), X1–X3 (members), A (the
//! promoted admin) and J (the joiner). All are same-owner devices,
//! certified through the public API as the live Home fixture does
//! (`home.rs`).
//!
//! - t0: O creates an owner-certified group G on the GSS plane, as the
//!   in-process #1023 test does (`r19_cert_carry.rs`), and seats X1–X3.
//!   A starts after the X devices announced, so A never caches their
//!   announces. O seats A and promotes A. A's seat event carries
//!   certificates inline only up to the DM budget
//!   (`attach_roster_certificates_to_member_added`), so A keeps some X
//!   seats digest-only. A asks the group for the omitted certificates
//!   (#946). The digest-only state is HARNESS-MADE (ADR 0111 H3: the
//!   harness makes the admin's seat digest-only). On `main` A otherwise
//!   gets every certificate: a Home seat event carries all of them inline
//!   (its TreeKEM fields put the event over the DM budget, so the sidecar
//!   is not trimmed below 32 certificates), and in a GSS group each X's
//!   `MemberJoined` and `MemberAdded` are replayed to A on G's metadata
//!   topic. So, during setup only, the harness drops every frame toward A
//!   that carries an X certificate (other than A's own seat event) and
//!   every #946 answer. It lifts the drop at a named trace mark before
//!   the holders go offline. Evidence (read from A's state, not from the
//!   drop count): the exact list of A's digest-only seats.
//! - t1: the drop is lifted, then O and every X device go offline. A
//!   restarts on its own directories. Evidence: after the restart A is
//!   still an admin, its digest-only seats are the same, its durable
//!   announce cache has no certificate for them, and every eligible holder
//!   (an active member that holds the bytes) is offline.
//! - t2: A mints J's invite and J redeems it. Desired (ADR 0111 S5,
//!   fetch by hash from any holder): A seals and J becomes Active. On
//!   `main`, A's seal refuses with `OwnerCertMemberPending` naming exactly
//!   the digest-only seats. A's seal-time fetch has no online holder to
//!   answer it, so the refusal repeats until the 10-minute deadline.
//!
//! Two tests share the scenario:
//! - `w3h_1023_red_baseline_restart_all_holders_offline_join_stays_pending`:
//!   every eligible holder is offline. RED on `main`.
//! - `w3h_1023_restart_one_holder_online_admits`: the control. One X
//!   device that holds every missing certificate stays online after A's
//!   restart. A's seal-time fetch gets an answer and J is admitted. GREEN.
//!   The restart and the digest-only seats are the same in both tests, so
//!   only the offline holders make the red case red.

#![cfg(test)]

use super::control::invite;
use super::home::{membership_state, roster, HomeIds};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::{AgentId, UserKeypair};
use crate::network::sim::{Fault, Write};
use anyhow::ensure;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const LABELS: &[&str] = &["O", "X1", "X2", "X3", "A", "J"];
const HOLDERS: &[&str] = &["O", "X1", "X2", "X3"];
const MEMBERS: &[&str] = &["X1", "X2", "X3"];
const JOIN_BUDGET: Duration = Duration::from_secs(180);
const SETTLE: Duration = Duration::from_secs(10);
const SEAL_REFUSAL: &str = "failed to seal authoritative add";
const PENDING_CAUSE: &str = "pending certificate resolution";
const FINAL: &str = "j_active_within_180s_after_a_restart";
/// The #946 answer domain (`seat_cert_fetch::GROUP_CERT_FETCH_RESPONSE_DOMAIN`).
/// It leads the pubsub payload in clear.
const FETCH_RESPONSE_DOMAIN: &[u8] = b"x0x/group-cert-fetch-response-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// O and every X device are offline after A's restart.
    AllHoldersOffline,
    /// One X device that holds every missing certificate stays online.
    OneHolderOnline,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// While held, drops every frame toward `target` that carries an X
/// device's certificate, except `target`'s own seat event, and every #946
/// answer. Each X certificate is matched in the two forms that frames
/// carry in clear: base64 of its bincode (`certificate_b64`, sidecars,
/// replayed `MemberJoined`) and the raw bincode (identity announces).
/// Byte streams are never touched. Run 39366636451 showed why the drop
/// must be this wide: after A joined, each X's `MemberJoined` and
/// `MemberAdded` were replayed to A on G's metadata topic and gave A
/// every certificate that its own seat event had trimmed.
struct AnswerDrop {
    held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

/// A distinctive slice of each form of `cert`.
fn cert_needles(cert: &crate::identity::AgentCertificate) -> Result<Vec<Vec<u8>>> {
    use base64::Engine as _;
    let raw = bincode::serialize(cert)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    // Offset 2100 is inside the agent public key in both forms, so the
    // owner's user key (the same in every certificate) is not matched.
    Ok(vec![
        raw.get(2100..2200).context("short certificate")?.to_vec(),
        b64.as_bytes()
            .get(2900..3000)
            .context("short certificate")?
            .to_vec(),
    ])
}

impl AnswerDrop {
    fn install(sim: &Sim, target: &str, holders: &[&str]) -> Result<Self> {
        let machine = sim.ids(target)?.1 .0;
        let own_seat = format!("\"agent_id\":\"{}\"", hex::encode(sim.ids(target)?.0 .0));
        let mut needles = Vec::new();
        for label in holders {
            let cert = sim
                .state(label)?
                .agent
                .identity()
                .agent_certificate()
                .cloned()
                .with_context(|| format!("{label} has no agent certificate"))?;
            needles.extend(cert_needles(&cert)?);
        }
        let held = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write: &Write| {
            let carries_cert = || {
                !matches!(write.lane.class, crate::network::sim::LaneClass::Stream(_))
                    && !contains(&write.bytes, own_seat.as_bytes())
                    && needles.iter().any(|needle| contains(&write.bytes, needle))
            };
            if rule_held.load(Ordering::SeqCst)
                && write.lane.dst == machine
                && (contains(&write.bytes, FETCH_RESPONSE_DOMAIN) || carries_cert())
            {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held, dropped })
    }

    fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// A node's view of G: its own role, and its active seats that
/// carry a committed digest but no certificate bytes (agent hex → digest).
struct SeatView {
    admin: bool,
    digest_only: BTreeMap<String, String>,
}

async fn seat_view(sim: &Sim, label: &str, gid: &str) -> Result<SeatView> {
    let state = sim.state(label)?;
    let local = sim.agent_hex(label)?;
    let gid = gid.to_string();
    let label = label.to_string();
    sim.at_instant(&format!("read {label}'s seats in G"), async move {
        let groups = state.named_groups.read().await;
        let (_, info) = crate::server::resolve_group_entry_locked(&groups, &gid)
            .with_context(|| format!("{label} has no entry for G"))?;
        let admin = info
            .members_v2
            .get(&local)
            .is_some_and(|seat| seat.is_active() && seat.role == crate::groups::GroupRole::Admin);
        let digest_only = info
            .active_members()
            .filter(|seat| seat.certificate.is_none())
            .filter_map(|seat| {
                seat.certificate_digest
                    .clone()
                    .map(|digest| (seat.agent_id.clone(), digest))
            })
            .collect();
        Ok(SeatView { admin, digest_only })
    })
    .await?
}

/// Whether `label` is an eligible holder of each digest: an active member
/// of G that holds bytes for it, on the matching seat or in its
/// durable announce cache. The result lists the digests it holds.
async fn held_digests(
    sim: &Sim,
    label: &str,
    gid: &str,
    digests: &[String],
) -> Result<(bool, Vec<String>)> {
    let state = sim.state(label)?;
    let local = sim.agent_hex(label)?;
    let gid = gid.to_string();
    let digests = digests.to_vec();
    sim.at_instant(&format!("read {label}'s certificate bytes"), async move {
        let (active, on_seats) = {
            let groups = state.named_groups.read().await;
            match crate::server::resolve_group_entry_locked(&groups, &gid) {
                Some((_, info)) => (
                    info.has_active_member(&local),
                    info.members_v2
                        .values()
                        .filter_map(|seat| {
                            let cert = seat.certificate.as_ref()?;
                            let digest = seat.certificate_digest.as_ref()?;
                            crate::groups::owner_cert::certificate_digest_hex(cert)
                                .eq_ignore_ascii_case(digest)
                                .then(|| digest.to_ascii_lowercase())
                        })
                        .collect::<Vec<_>>(),
                ),
                None => (false, Vec::new()),
            }
        };
        let mut held = Vec::new();
        for digest in digests {
            let cached = match parse_digest(&digest) {
                Some(bytes) => state
                    .agent
                    .announce_blob_cache
                    .find_by_cert_digest(&bytes)
                    .await
                    .is_some(),
                None => false,
            };
            if cached || on_seats.contains(&digest.to_ascii_lowercase()) {
                held.push(digest);
            }
        }
        (active, held)
    })
    .await
}

fn parse_digest(digest: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(digest).ok()?).ok()
}

/// Whether `label` is on the fabric now.
fn online(sim: &Sim, label: &str) -> Result<bool> {
    Ok(sim.fabric().is_online(&sim.peer(label)?).unwrap_or(false))
}

/// One join `fetch_request` from J that A's DM layer handed to its
/// consumers (A's join listener among them).
struct RequestSeen {
    position: usize,
    at: Duration,
    verified: bool,
    /// `member_joined` or `fetch_request`.
    kind: &'static str,
}

/// Aborts the watcher when the scenario ends, however it ends.
struct Watcher(tokio::task::JoinHandle<()>);

impl Drop for Watcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The kind of a DM payload that is J's join message for `gid`: its
/// `MemberJoined` or its JoinResult `fetch_request`, each naming J as the
/// member. `None` for any other payload.
fn join_message_kind(payload: &[u8], gid: &str, joiner: &AgentId) -> Option<&'static str> {
    let body = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
    if body["group_id"] != gid || body["member_agent_id"] != hex::encode(joiner.as_bytes()) {
        return None;
    }
    if body["event"] == "member_joined" {
        Some("member_joined")
    } else if body["type"] == "fetch_request" {
        Some("fetch_request")
    } else {
        None
    }
}

/// Create O's owner-certified group on the GSS plane: `MlsEncrypted`
/// and `ListedToContacts` keep it off the TreeKEM plane (only Hidden
/// encrypted groups are TreeKEM). This is the plane of the in-process
/// #1023 test (`r19_cert_carry.rs`). A Home event cannot be used: its
/// TreeKEM fields make the bare `MemberAdded` larger than one DM, so its
/// certificate sidecar takes the 8 MiB budget and is not trimmed below 32
/// certificates.
async fn create_owner_certified(sim: &Sim, label: &str, owner_user_id: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            label,
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 1023",
                "display_name": label,
                "policy": {
                    "discoverability": "listed_to_contacts",
                    "admission": {"owner_certified": owner_user_id},
                    "confidentiality": "mls_encrypted",
                    "read_access": "members_only",
                    "write_access": "members_only",
                },
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create owner-certified group: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

/// `joiner` redeems `link`. An owner-certified invite needs the pinned
/// owner mode (`mode: home`) for any group, not only the Home.
async fn join(sim: &Sim, joiner: &str, group: &HomeIds, link: &str) -> Result<()> {
    let (status, joined) = sim
        .api(
            joiner,
            Method::POST,
            "/groups/join",
            Some(json!({
                "invite": link,
                "display_name": joiner,
                "mode": "home",
                "expected_owner_user_id": group.owner_user_id,
            })),
        )
        .await?;
    ensure!(
        status.is_success() && joined["ok"] != false,
        "{joiner} join: {status} {joined}"
    );
    Ok(())
}

/// Whether, within `budget`, `authority` lists `member` in `gid` and
/// `member` reports itself `active`. "Not admitted" is a verdict only when
/// every read completed and succeeded; a failed or hanging read is INFRA.
async fn admitted(
    sim: &Sim,
    authority: &str,
    member: &str,
    gid: &str,
    budget: Duration,
) -> Result<bool> {
    let member_hex = sim.agent_hex(member)?;
    let what = format!("{member} seated on {authority} and locally");
    let mut seen = Observations::default();
    let ready = sim
        .until(&what, budget, async |s: &Sim| {
            let Some(rows) = seen.observe(roster(s, authority, gid)).await else {
                return true;
            };
            if !rows.iter().any(|(id, _)| *id == member_hex) {
                return false;
            }
            let Some(state) = seen.observe(membership_state(s, member, gid)).await else {
                return true;
            };
            state.as_deref() == Some("active")
        })
        .await;
    match ready {
        Ok(()) if !seen.failed() => Ok(true),
        Ok(()) => seen.verify(&what).map(|()| false),
        Err(error) if expired(&error) => seen.verify(&what).map(|()| false),
        Err(error) => Err(error),
    }
}

/// Whether `observer` verifies `subject`'s AgentId->MachineId binding now
/// (the `verified` flag of a direct message from `subject`).
async fn binding_verified(sim: &Sim, observer: &str, subject: &str) -> Result<bool> {
    let state = sim.state(observer)?;
    let (agent, machine) = sim.ids(subject)?;
    sim.at_instant(
        &format!("read whether {observer} verifies {subject}'s binding"),
        async move {
            state
                .agent
                .is_agent_machine_verified(&agent, &machine)
                .await
        },
    )
    .await
}

/// `subject` re-announces (`POST /announce`); whether `observer` then
/// verifies `subject`'s machine binding within 30 s.
async fn announce_and_wait_verified(sim: &Sim, subject: &str, observer: &str) -> Result<bool> {
    let (status, body) = sim
        .api(subject, Method::POST, "/announce", Some(json!({})))
        .await?;
    ensure!(status.is_success(), "{subject} announce: {status} {body}");
    let what = format!("{observer} verifies {subject}'s binding");
    match sim
        .until(&what, secs(30), async |s: &Sim| {
            binding_verified(s, observer, subject)
                .await
                .unwrap_or(false)
        })
        .await
    {
        Ok(()) => Ok(true),
        Err(error) if expired(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Watch A's DM layer for J's join `fetch_request` for `gid`, from now on.
/// The watcher is one more subscriber of A's `DirectMessaging` fan-out
/// (either DM transport), so it sees what A's join listener sees.
fn watch_join_requests(
    sim: &Sim,
    gid: &str,
) -> Result<(Watcher, Arc<std::sync::Mutex<Vec<RequestSeen>>>)> {
    let joiner = sim.state("J")?.agent.agent_id();
    let mut inbox = sim.state("A")?.agent.subscribe_direct();
    let fabric = Arc::clone(sim.fabric());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let gid = gid.to_string();
    let task = tokio::spawn(async move {
        while let Some(msg) = inbox.recv().await {
            if msg.sender != joiner {
                continue;
            }
            let Some(kind) = join_message_kind(&msg.payload, &gid, &joiner) else {
                continue;
            };
            let position = fabric.mark_indexed(format!(
                "A's DM layer received J's join {kind} (verified={})",
                msg.verified
            ));
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(RequestSeen {
                    position,
                    at: fabric.now(),
                    verified: msg.verified,
                    kind,
                });
        }
    });
    Ok((Watcher(task), seen))
}

// DIAG #1364 (do not merge): A's MemberJoined-path counters for G, and
// whether A resolves the gid that J's events name (the watcher matched
// only events whose `group_id` is `gid`) by the inner apply's rule: map
// key or stable id (`named_groups.rs:12693`), not the MLS id.
async fn diag_a_member_joined_path(sim: &Sim, gid: &str) {
    let resolves = match sim.state("A") {
        Ok(state) => {
            let gid = gid.to_string();
            sim.at_instant("DIAG: A resolves G", async move {
                let groups = state.named_groups.read().await;
                let by_key = groups.contains_key(&gid);
                let by_stable = groups.values().any(|info| info.stable_group_id() == gid);
                let keys: Vec<String> = groups.keys().cloned().collect();
                format!("by_key={by_key} by_stable_id={by_stable} a_keys={keys:?}")
            })
            .await
            .unwrap_or_else(|error| format!("read failed: {error:#}"))
        }
        Err(error) => format!("no state: {error:#}"),
    };
    eprintln!("W3H-DIAG A resolves J's event gid {gid}: {resolves}"); // DIAG #1364
    let rows = match sim.api("A", Method::GET, "/diagnostics/groups", None).await {
        Ok((_, body)) => body["groups"].as_array().cloned().unwrap_or_default(),
        Err(error) => {
            eprintln!("W3H-DIAG A GET /diagnostics/groups failed: {error:#}"); // DIAG #1364
            Vec::new()
        }
    };
    for row in rows {
        eprintln!(
            "W3H-DIAG A counters group_id={} member_joined_events_applied={} \
             rejected_non_member_role(#14)={} rejected_owner_cert_pending(#17)={} \
             rejected_invite_secret_unknown(#19)={} invites_refused_reasons(#14/#19)={} \
             subscribed_metadata={}",
            row["group_id"],
            row["member_joined_events_applied"],
            row["member_joined_events_rejected_non_member_role"],
            row["member_joined_events_rejected_owner_cert_pending"],
            row["member_joined_events_rejected_invite_secret_unknown"],
            row["invites_refused_reasons"],
            row["subscribed_metadata"],
        ); // DIAG #1364
    }
}

/// The member list of a `pending certificate resolution` refusal, as hex.
fn refused_members(text: &str) -> Option<Vec<String>> {
    let start = text.find(PENDING_CAUSE)? + PENDING_CAUSE.len();
    let rest = text.get(start..)?.strip_prefix(": ")?;
    let end = rest.find(']')? + 1;
    let mut members: Vec<String> = serde_json::from_str(rest.get(..end)?).ok()?;
    members.sort();
    Some(members)
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    // t0: O's owner-certified group G with X1–X3. A and J start after the
    // X devices announced. The answer drop toward A is active from before
    // A starts.
    let owner = UserKeypair::generate()?;
    let owner_home = sim.start_owner_device("O", &owner).await?;
    for member in MEMBERS {
        sim.certify_owner_device("O", member, &owner, &owner_home)
            .await?;
    }
    let group = HomeIds {
        gid: create_owner_certified(sim, "O", &owner_home.owner_user_id).await?,
        owner_user_id: owner_home.owner_user_id.clone(),
    };
    for member in MEMBERS {
        let link = invite(sim, "O", &group.gid).await?;
        join(sim, member, &group, &link).await?;
        ensure!(
            admitted(sim, "O", member, &group.gid, JOIN_BUDGET).await?,
            "setup: O could not seat {member}"
        );
    }
    let answers = AnswerDrop::install(sim, "A", MEMBERS)?;
    for device in ["A", "J"] {
        sim.certify_owner_device("O", device, &owner, &owner_home)
            .await?;
    }
    let link = invite(sim, "O", &group.gid).await?;
    join(sim, "A", &group, &link).await?;
    ensure!(
        admitted(sim, "O", "A", &group.gid, JOIN_BUDGET).await?,
        "setup: O could not seat A"
    );
    let mut observers = vec!["A"];
    observers.extend_from_slice(MEMBERS);
    sim.promote_admin("O", "A", &group, &observers).await?;
    let home = group;
    sim.within(
        "A's seat settles",
        SETTLE + secs(1),
        tokio::time::sleep(SETTLE),
    )
    .await?;
    let before = seat_view(sim, "A", &home.gid).await?;
    let missing: Vec<String> = before.digest_only.values().cloned().collect();
    let owner_hex = sim.agent_hex("O")?;
    receipt.evidence(
        "a_holds_digest_only_seats_after_its_seat_event",
        !missing.is_empty() && !before.digest_only.contains_key(&owner_hex),
        format!(
            "digest-only seats at A: {:?}; O's seat has bytes: {}; #946 answers \
             dropped toward A: {}",
            before.digest_only.keys().collect::<Vec<_>>(),
            !before.digest_only.contains_key(&owner_hex),
            answers.dropped()
        ),
        at(sim),
    );
    ensure!(
        !missing.is_empty(),
        "INFRA: A holds every certificate after its seat event (answers dropped: {})",
        answers.dropped()
    );

    // Who holds the missing bytes, while every node is still online.
    let mut holders = BTreeMap::new();
    for label in HOLDERS {
        let (active, held) = held_digests(sim, label, &home.gid, &missing).await?;
        holders.insert(*label, (active, held));
    }
    let full_holder = MEMBERS.iter().copied().find(|label| {
        holders
            .get(label)
            .is_some_and(|(active, held)| *active && held.len() == missing.len())
    });
    let stays_online = match arm {
        Arm::AllHoldersOffline => None,
        Arm::OneHolderOnline => Some(
            full_holder.context("INFRA: no X device holds every certificate that A is missing")?,
        ),
    };

    // t1: the setup drop ends, then the holders go offline (no await in
    // between, so no frame moves), and A restarts.
    answers.release();
    sim.fabric().mark(format!(
        "setup fault lifted: X-certificate and #946 drop toward A ({} frames dropped)",
        answers.dropped()
    ));
    for label in HOLDERS {
        if Some(*label) != stays_online {
            sim.set_online(label, false)?;
        }
    }
    let a_peer = sim.peer("A")?;
    let incarnation = sim
        .fabric()
        .incarnation_of(&a_peer)
        .context("A is not on the fabric")?;
    sim.restart("A", RestartMode::Graceful).await?;
    let restarted = sim
        .fabric()
        .incarnation_of(&a_peer)
        .context("A is not on the fabric after its restart")?;
    // A's bootstrap peer is O, which is offline: A dials J (and the online
    // holder) itself.
    let network = sim
        .state("A")?
        .agent
        .network()
        .cloned()
        .context("A has no network")?;
    let mut dial = vec!["J"];
    dial.extend(stays_online);
    for label in dial {
        let addr = super::sim_addr(sim.node_index(label)?)?;
        sim.within(
            &format!("A dials {label}"),
            secs(10),
            network.connect_addr(addr),
        )
        .await?
        .map_err(|error| anyhow!("A could not dial {label}: {error}"))?;
    }
    // A's discovery cache is in memory, so after its restart A cannot
    // verify J's AgentId->MachineId binding until J announces again. An
    // unverified MemberJoined or fetch_request is dropped before the
    // MemberJoined arm, at DEBUG only
    // (`apply_named_group_metadata_event_inner`, reason "unverified"), so
    // A never reaches its seal (run 39371831602: 123 join messages, all
    // verified=false, in both arms). J re-announces, as a joiner that
    // comes online after A's restart does at its start, and the case
    // waits until A verifies J's binding (`case_1207.rs` does the same).
    let j_verified = announce_and_wait_verified(sim, "J", "A").await?;
    receipt.evidence(
        "a_verifies_j_binding_after_its_restart",
        j_verified,
        format!("after J's re-announce, A verifies J's machine binding: {j_verified}"),
        at(sim),
    );
    ensure!(
        j_verified,
        "INFRA: A never verified J's machine binding after A's restart"
    );
    receipt.setup_done(at(sim));

    let after = seat_view(sim, "A", &home.gid).await?;
    receipt.evidence(
        "a_restarted_as_promoted_admin_with_the_same_digest_only_seats",
        restarted == incarnation + 1 && after.admin && after.digest_only == before.digest_only,
        format!(
            "A incarnation {incarnation}->{restarted}; admin={}; digest-only seats after \
             the restart: {:?}",
            after.admin,
            after.digest_only.keys().collect::<Vec<_>>()
        ),
        at(sim),
    );
    let (_, a_held) = held_digests(sim, "A", &home.gid, &missing).await?;
    receipt.evidence(
        "a_has_no_bytes_for_the_missing_certificates",
        a_held.is_empty(),
        format!(
            "A holds {} of {} missing digests",
            a_held.len(),
            missing.len()
        ),
        at(sim),
    );
    let mut rows = Vec::new();
    let mut online_holders = Vec::new();
    let mut offline_holders = 0usize;
    for label in HOLDERS {
        let (active, held) = holders.get(label).cloned().unwrap_or_default();
        let up = online(sim, label)?;
        if active && !held.is_empty() {
            if up {
                online_holders.push(*label);
            } else {
                offline_holders += 1;
            }
        }
        rows.push(format!(
            "{label}: active={active} holds {}/{} online={up}",
            held.len(),
            missing.len()
        ));
    }
    let o_offline = !online(sim, "O")?;
    let holders_ok = match arm {
        Arm::AllHoldersOffline => o_offline && online_holders.is_empty() && offline_holders > 0,
        Arm::OneHolderOnline => {
            o_offline && online_holders == stays_online.into_iter().collect::<Vec<_>>()
        }
    };
    receipt.evidence(
        match arm {
            Arm::AllHoldersOffline => "creator_and_every_eligible_holder_offline",
            Arm::OneHolderOnline => "creator_offline_and_exactly_one_eligible_holder_online",
        },
        holders_ok,
        rows.join("; "),
        at(sim),
    );

    // t2: A mints J's invite and J redeems it.
    let link = invite(sim, "A", &home.gid).await?;
    let join_position = sim
        .fabric()
        .mark_indexed("t2: J redeems A's invite after A's restart");
    let (watcher, received) = watch_join_requests(sim, &home.gid)?;
    join(sim, "J", &home, &link).await?;
    let j_admitted = admitted(sim, "A", "J", &home.gid, JOIN_BUDGET).await?;
    drop(watcher);
    let received = std::mem::take(
        &mut *received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    // Only a verified message reaches A's MemberJoined arm and its seal.
    let first = received
        .iter()
        .find(|seen| seen.verified && seen.position > join_position);
    let count = |kind: &str, verified: bool| {
        received
            .iter()
            .filter(|seen| seen.kind == kind && seen.verified == verified)
            .count()
    };
    let by_kind = ["member_joined", "fetch_request"]
        .iter()
        .map(|kind| {
            format!(
                "{kind}: {} verified, {} unverified",
                count(kind, true),
                count(kind, false)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let first_request = first.map(|seen| seen.at);
    let direct_frames = sim
        .fabric()
        .delivered_writes_after(&sim.peer("J")?, &a_peer, join_position)
        .len();
    receipt.request_delivered(
        "j_join_request_reached_a",
        first.is_some(),
        format!(
            "{} join messages from J for this group reached A's DM layer after the \
             join call (trace #{join_position}) ({by_kind}); {direct_frames} frames \
             J->A delivered; first verified at trace #{} ({})",
            received.len(),
            first.map_or("none".to_string(), |seen| seen.position.to_string()),
            first.map_or("none", |seen| seen.kind),
        ),
        at(sim),
    );
    if !j_admitted {
        // The cause: A's seal refusal for THIS group and THIS joiner, after
        // J's request reached A, naming exactly A's digest-only seats.
        let j_hex = sim.agent_hex("J")?;
        let j_tokens = [
            crate::logging::LogHexId::agent(j_hex.as_str()).to_string(),
            crate::logging::LogHexId::agent(j_hex.to_uppercase().as_str()).to_string(),
        ];
        let mut want: Vec<String> = before.digest_only.keys().cloned().collect();
        want.sort();
        let refusal = sim
            .logs_containing(&[SEAL_REFUSAL, PENDING_CAUSE, &format!("group {}", home.gid)])
            .into_iter()
            .filter(|log| {
                j_tokens
                    .iter()
                    .any(|token| log.text.contains(&format!("member={token}")))
            })
            .filter(|log| first_request.is_some_and(|first| log.at >= first))
            .find(|log| refused_members(&log.text).as_ref() == Some(&want));
        receipt.cause(
            "OwnerCertMemberPending{members=A's digest-only seats} from A's seal of J's add",
            refusal.as_ref().map(|log| log.text.clone()),
            refusal.is_some(),
            at(sim),
        );
        // DIAG #1364 (do not merge): every captured log after t2.
        let t2_at = received.first().map(|seen| seen.at).unwrap_or_default();
        for log in sim.logs_containing(&[]) {
            if log.at >= t2_at.saturating_sub(secs(5)) {
                eprintln!("W3H-DIAG @{}us {}", log.at.as_micros(), log.text);
            }
        }
        diag_a_member_joined_path(sim, &home.gid).await; // DIAG #1364
        let a_rows = roster(sim, "A", &home.gid).await.unwrap_or_default();
        let j_state = membership_state(sim, "J", &home.gid).await.ok().flatten();
        sim.fabric().mark(format!(
            "observed: A lists {} members, J membership_state={j_state:?}",
            a_rows.len()
        ));
    }
    receipt.note(format!(
        "arm={arm:?}; #946 answers dropped toward A during setup: {}; digest-only seats \
         at A: {}",
        answers.dropped(),
        missing.len()
    ));
    receipt.finish(FINAL, j_admitted, at(sim));
    Ok(())
}

/// Run the scenario once and return its emitted receipt. Any error before
/// the final assertion is recorded as INFRA.
async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "setup fault: every frame toward A that carries an X certificate (except A's own \
         seat event) and every #946 answer is dropped from A's start until the holders go \
         offline, so A keeps the seats its seat event omitted \
         digest-only (ADR 0111 H3: the harness makes the admin's seat digest-only)",
    );
    receipt.note(
        "sim byte streams (EvidenceV1 hello, SyncV1 owner sync) are in-memory \
         pipes with zero latency and no QUIC flow control (W3-H S4)",
    );
    match Sim::empty(case, seed, LABELS) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, arm, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

async fn expect(case: &str, seed: u64, arm: Arm, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1023_red_baseline_restart_all_holders_offline_join_stays_pending() -> Result<()> {
    expect(
        "w3h_1023_red_baseline_restart_all_holders_offline_join_stays_pending",
        0x1023_0001,
        Arm::AllHoldersOffline,
        Verdict::Red,
    )
    .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1023_restart_one_holder_online_admits() -> Result<()> {
    expect(
        "w3h_1023_restart_one_holder_online_admits",
        0x1023_0002,
        Arm::OneHolderOnline,
        Verdict::Green,
    )
    .await
}

#[test]
fn w3h_1023_refused_members_parses_the_seal_refusal() {
    let text = "MemberJoined: failed to seal authoritative add: owner-certified group g has \
                members pending certificate resolution: [\"bb\", \"aa\"] (retry after fetch \
                convergence) group_id=g member=agent:cc";
    assert_eq!(
        refused_members(text),
        Some(vec!["aa".to_string(), "bb".to_string()])
    );
    assert_eq!(refused_members("no refusal here"), None);
}
