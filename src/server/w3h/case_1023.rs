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
//!   and J that carries an X certificate (other than the target's own
//!   seat event) and every #946 answer. The drop covers J because J must
//!   not hold the missing bytes. In run 39379002253 J cached X1's
//!   certificate, and with every holder offline A resolved X1's seat from
//!   J. It lifts the drop at a named trace mark before the holders go
//!   offline. Evidence (read from A's and J's state, not from the drop
//!   count): the exact list of A's digest-only seats, and J holds none of
//!   their certificates.
//! - t0, after A's promotion: O announces with consent. This is the
//!   documented #1143 workaround, which the `case_1143.rs` positive
//!   control also uses. A REST-created owner-certified group that is not
//!   the Home does not certify the creator's seat, so A has no certificate
//!   for O. O's default announce is anonymous. O repeats the consented
//!   announce until A verifies it, as a heartbeat would. Without the
//!   consented announce, A holds O `InGrace` and every seal of J's add refuses
//!   naming O, in both tests. That is a different defect from #1364 and
//!   is out of scope. Evidence: A's verdict for O is `Clean`, before and
//!   again after A's restart (A's discovery cache is in memory, so A must
//!   learn O's announce again from an online node).
//! - t1: the drop is lifted, then O and every X device go offline (in the
//!   one-holder control, one X device stays online). A restarts on its own
//!   directories and dials J. J announces again, and the case waits until
//!   A verifies J's machine binding: A drops an unverified join message
//!   before its seal (run 39371831602). Evidence: after the restart A is
//!   still an admin and every eligible holder (an active member that
//!   holds the bytes) is offline. In the two offline tests A's
//!   digest-only seats are the same and A holds no bytes for them. In the
//!   control the online
//!   holder can answer A before t2 (run 39380658640: A held 1 of 1
//!   missing digests). That is the behaviour that the control proves. So
//!   the control requires only that A's digest-only seats are a subset of
//!   the seats before the restart, and that A's bytes are for digests that
//!   the online holder holds.
//! - t2: A mints J's invite and J redeems it. In the control, the case
//!   waits up to 180 s for J to become Active. With every holder offline,
//!   ADR 0088 (§1 L3, §2 item 8) says the fetch waits until one holder is
//!   online. The wait is not terminal. It stays retryable, and its state is
//!   typed, visible and names what it waits for. ADR 0111 §8 gives the
//!   states: the authority reports `evidence_pending` for each missing
//!   digest, and a capable joiner shows `awaiting_evidence` with the same
//!   digests. The joiner's attempt does not end at its 120 s poll deadline
//!   (D64). So the case polls every 5 s for 150 s (`HOLDER_GAP`). It scans
//!   `/groups/{gid}` at A for the typed wait, and `/groups/{gid}` and
//!   `/groups/{gid}/join-status` at J. It reads A's roster from
//!   `/groups/{gid}/members` but does not scan it, because it lists seat
//!   digests. One body shows a typed wait when it contains the state name
//!   and names every missing digest (as hex or base64). An S5
//!   implementation must expose the typed states on one of the scanned
//!   routes. Evidence (red test only): J is not admitted during the gap,
//!   and A holds none of the missing bytes at its end. On `main`, A's seal refuses
//!   with `OwnerCertMemberPending` naming exactly A's digest-only seats,
//!   A and J show no typed state, and J's attempt ends `timed_out` at
//!   120 s.
//! - After the gap (red test only, ADR 0111 H3): the X device that holds
//!   every missing certificate comes back and A dials it. If J's attempt
//!   is still pending, the attempt must resume by itself. Otherwise J
//!   redeems the same invite again. A must hold every missing certificate
//!   within 60 s, and J must become Active within 120 s.
//!
//! Three tests share the scenario:
//! - `w3h_1023_red_baseline_all_holders_offline_wait_is_typed_then_resumes`:
//!   every eligible holder is offline, then one returns. FINAL
//!   `typed_retryable_wait_then_j_active_after_holder_returns` needs A's
//!   typed `evidence_pending`, J's typed `awaiting_evidence`, no end of J's
//!   attempt during the gap, A's bytes within 60 s of the return and J
//!   Active after it. RED on `main`. The cause is the
//!   `OwnerCertMemberPending` refusal above, with no typed wait at A or J.
//! - `w3h_1023_restart_one_holder_online_admits`: the control. One X
//!   device that holds every missing certificate stays online after A's
//!   restart. A gets the bytes from it and J is admitted. GREEN. The
//!   restart and the setup are the same in all tests, so only the offline
//!   holders make the red case red.
//! - `w3h_1023_control_holders_never_return_fail_closed`: every holder
//!   stays offline for 330 s (`NEVER_WINDOW`, the span of the red test).
//!   FINAL `fail_closed_never_admitted_never_silently_dropped`: J is never
//!   admitted and A never holds any of the missing bytes (both fail FINAL,
//!   not INFRA, in this test), and at every poll J's
//!   join-status shows a pending attempt or a typed outcome (`timed_out`,
//!   or a refusal). ADR 0088 L4 keeps the wait fail-closed. GREEN on
//!   `main` (pending, then `timed_out` at 120 s) and GREEN under a correct
//!   S5 (pending throughout).

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
/// How often the case reads the wait states of A and J.
const POLL: Duration = secs(5);
/// How long every holder stays offline after J's join: past J's 120 s
/// join-result poll deadline (ADR 0111 §8, D64).
const HOLDER_GAP: Duration = secs(150);
/// ADR 0111 H3: A holds the certificates within 60 s of the holder's start.
const RETURN_FETCH: Duration = secs(60);
/// How long J has to become Active after A holds the certificates.
const RETURN_ADMIT: Duration = secs(120);
/// The never-return control covers the same span as the red test.
const NEVER_WINDOW: Duration = HOLDER_GAP
    .saturating_add(RETURN_FETCH)
    .saturating_add(RETURN_ADMIT);
/// J's `join_state` while its attempt waits for the authority.
const JOIN_PENDING: &str = "pending_authority_commit";
/// The #946 answer domain (`seat_cert_fetch::GROUP_CERT_FETCH_RESPONSE_DOMAIN`).
/// It leads the pubsub payload in clear.
const FETCH_RESPONSE_DOMAIN: &[u8] = b"x0x/group-cert-fetch-response-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// O and every X device are offline after A's restart. After
    /// `HOLDER_GAP` the X device that holds every missing certificate
    /// comes back.
    HolderReturns,
    /// One X device that holds every missing certificate stays online.
    OneHolderOnline,
    /// O and every X device are offline after A's restart and stay
    /// offline.
    HoldersNeverReturn,
}

impl Arm {
    /// The name of this arm's desired-behaviour assertion.
    fn final_name(self) -> &'static str {
        match self {
            Arm::HolderReturns => "typed_retryable_wait_then_j_active_after_holder_returns",
            Arm::OneHolderOnline => "j_active_within_180s_after_a_restart",
            Arm::HoldersNeverReturn => "fail_closed_never_admitted_never_silently_dropped",
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// While held, drops every frame toward each target that carries an X
/// device's certificate, except that target's own seat event, and every
/// #946 answer. The own-seat exception applies only to frames toward the
/// target that it names. Each X certificate is matched in the two forms that frames
/// carry in clear: base64 of its bincode (`certificate_b64`, sidecars,
/// replayed `MemberJoined`) and the raw bincode (identity announces).
/// Byte streams are never touched. Run 39366636451 showed why the drop
/// must be this wide: after A joined, each X's `MemberJoined` and
/// `MemberAdded` were replayed to A on G's metadata topic and gave A
/// every certificate that its own seat event had trimmed. Run 39379002253
/// showed why J is a target too: J cached X1's certificate, and with every
/// holder offline A resolved X1's seat from J.
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
    fn install(sim: &Sim, targets: &[&str], holders: &[&str]) -> Result<Self> {
        // Each target's machine, with that target's own-seat marker.
        let mut destinations = Vec::new();
        for target in targets {
            let (agent, machine) = sim.ids(target)?;
            let own_seat = format!("\"agent_id\":\"{}\"", hex::encode(agent.0));
            destinations.push((machine.0, own_seat));
        }
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
            let Some((_, own_seat)) = destinations
                .iter()
                .find(|(machine, _)| write.lane.dst == *machine)
            else {
                return Fault::Pass;
            };
            let carries_cert = || {
                !matches!(write.lane.class, crate::network::sim::LaneClass::Stream(_))
                    && !contains(&write.bytes, own_seat.as_bytes())
                    && needles.iter().any(|needle| contains(&write.bytes, needle))
            };
            if rule_held.load(Ordering::SeqCst)
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

/// A clone of A's `GroupInfo` for `gid`.
async fn a_group_info(a: &AppState, gid: &str) -> Result<crate::groups::GroupInfo> {
    let groups = a.named_groups.read().await;
    let (_, info) =
        crate::server::resolve_group_entry_locked(&groups, gid).context("A has no entry for G")?;
    Ok(info.clone())
}

/// A's owner-cert verdict per active member of G, as a seal computes it
/// (`owner_cert_seal_evidence`): every active member and the local agent,
/// each with its seat digest. `case_1143.rs` (`admin_view_of_owner`) reads
/// the verdict the same way.
async fn a_verdicts(
    a: &AppState,
    info: &crate::groups::GroupInfo,
) -> std::collections::HashMap<String, crate::groups::owner_cert::MemberCertStatus> {
    let local_hex = hex::encode(a.agent.agent_id().as_bytes());
    let mut agents: Vec<String> = info.active_members().map(|m| m.agent_id.clone()).collect();
    if !agents.iter().any(|x| x.eq_ignore_ascii_case(&local_hex)) {
        agents.push(local_hex);
    }
    let with_digests: Vec<(String, Option<String>)> = agents
        .into_iter()
        .map(|agent| {
            let digest = info
                .members_v2
                .get(&agent)
                .and_then(|seat| seat.certificate_digest.clone());
            (agent, digest)
        })
        .collect();
    let evidence =
        crate::server::routes::named_groups::owner_cert_evidence_for_with_digests(a, &with_digests)
            .await;
    info.clone().owner_cert_verdict(&evidence).per_member
}

/// A's owner-cert verdict for `label`'s seat in G now. `None` when A has
/// no verdict for that member (not an active member at A).
async fn a_status_of(
    sim: &Sim,
    gid: &str,
    label: &str,
) -> Result<Option<crate::groups::owner_cert::MemberCertStatus>> {
    let a = sim.state("A")?;
    let hex = sim.agent_hex(label)?;
    let gid = gid.to_string();
    sim.at_instant(&format!("read A's verdict for {label}"), async move {
        let info = a_group_info(&a, &gid).await?;
        Ok(a_verdicts(&a, &info).await.get(&hex).cloned())
    })
    .await?
}

/// Whether, within `budget`, A's verdict for `label` becomes `Clean`.
/// The result also gives A's last verdict for `label`.
async fn until_a_clean(
    sim: &Sim,
    gid: &str,
    label: &str,
    budget: Duration,
) -> Result<(bool, Option<crate::groups::owner_cert::MemberCertStatus>)> {
    use crate::groups::owner_cert::MemberCertStatus;
    let mut last = None;
    let mut failure = None;
    let waited = sim
        .until(
            &format!("A verifies {label}'s certificate"),
            budget,
            async |s: &Sim| match a_status_of(s, gid, label).await {
                Ok(status) => {
                    let clean = status == Some(MemberCertStatus::Clean);
                    last = status;
                    clean
                }
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
        )
        .await;
    if let Some(error) = failure {
        return Err(error.context(format!("INFRA: reading A's verdict for {label}")));
    }
    match waited {
        Ok(()) => Ok((last == Some(MemberCertStatus::Clean), last)),
        Err(error) if expired(&error) => Ok((false, last)),
        Err(error) => Err(error),
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

/// The forms in which a read route can name `digest`. The S5 encoding is
/// not fixed, so lowercase hex, uppercase hex and each base64 alphabet of
/// the 32 bytes count.
fn digest_forms(digest: &str) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let mut forms = vec![digest.to_ascii_lowercase(), digest.to_ascii_uppercase()];
    if let Some(bytes) = parse_digest(digest) {
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            forms.push(engine.encode(bytes));
        }
    }
    forms
}

/// Whether `body` shows the typed state `marker` and names every digest.
fn names_every(body: &serde_json::Value, marker: &str, digests: &[String]) -> bool {
    let text = body.to_string();
    text.contains(marker)
        && digests
            .iter()
            .all(|digest| digest_forms(digest).iter().any(|form| text.contains(form)))
}

/// One read of the wait states of A and J during the holder gap.
struct Snapshot {
    /// A shows `evidence_pending` naming every missing digest.
    a_typed: bool,
    /// J shows `awaiting_evidence` naming every missing digest.
    j_typed: bool,
    a_lists_j: bool,
    j_active: bool,
    /// J's `join_state`; `None` when the join-status body has none.
    join_state: Option<String>,
    /// J's join-status answered 404: the local stub is gone.
    stub_gone: bool,
    /// J's `last_join_outcome`, with its reason when it has one.
    outcome: Option<String>,
}

/// Read the group routes at A and J once. A 404 counts as "nothing
/// shown"; a failed request is an error.
async fn snapshot(sim: &Sim, gid: &str, digests: &[String]) -> Result<Snapshot> {
    let j_hex = sim.agent_hex("J")?;
    // A's typed wait is read from `/groups/{gid}` only: the members body
    // lists seat digests, so a marker elsewhere in it would match falsely.
    let (_, group) = sim
        .request("A", Method::GET, &format!("/groups/{gid}"), None)
        .await?;
    let a_typed = names_every(&group, "evidence_pending", digests);
    let (status, members) = sim
        .request("A", Method::GET, &format!("/groups/{gid}/members"), None)
        .await?;
    ensure!(
        status.is_success(),
        "A GET /groups/{gid}/members: {status} {members}"
    );
    let a_lists_j = members["members"]
        .as_array()
        .with_context(|| format!("A GET /groups/{gid}/members: no members array: {members}"))?
        .iter()
        .any(|row| {
            row["agent_id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(&j_hex))
        });
    let (status, group) = sim
        .request("J", Method::GET, &format!("/groups/{gid}"), None)
        .await?;
    let j_active = status.is_success() && group["membership_state"] == "active";
    let (status, join) = sim
        .request(
            "J",
            Method::GET,
            &format!("/groups/{gid}/join-status"),
            None,
        )
        .await?;
    let last = &join["last_join_outcome"];
    let outcome = last["outcome"]
        .as_str()
        .map(|outcome| match last["reason"].as_str() {
            Some(reason) => format!("{outcome} ({reason})"),
            None => outcome.to_string(),
        });
    Ok(Snapshot {
        a_typed,
        j_typed: names_every(&group, "awaiting_evidence", digests)
            || names_every(&join, "awaiting_evidence", digests),
        a_lists_j,
        j_active,
        join_state: join["join_state"].as_str().map(str::to_string),
        stub_gone: status == StatusCode::NOT_FOUND,
        outcome,
    })
}

/// What the polls saw, as times since J's join call.
#[derive(Default)]
struct WaitWindow {
    polls: usize,
    a_typed_at: Option<Duration>,
    j_typed_at: Option<Duration>,
    /// The first poll at which J's attempt had ended, and how.
    j_ended: Option<(Duration, String)>,
    /// The first poll at which A listed J or J was active.
    admitted: Option<(Duration, String)>,
    /// The first poll at which J showed neither a pending attempt nor a
    /// typed outcome.
    silent_drop: Option<(Duration, String)>,
    /// The first poll at which A held any missing digest, and how many.
    a_held: Option<(Duration, usize)>,
    /// At the last poll, J's attempt was pending with no outcome.
    j_pending_now: bool,
    /// J's state at each change.
    timeline: Vec<(Duration, String)>,
}

impl WaitWindow {
    fn record(&mut self, since: Duration, snap: &Snapshot) {
        self.polls += 1;
        if snap.a_typed {
            self.a_typed_at.get_or_insert(since);
        }
        if snap.j_typed {
            self.j_typed_at.get_or_insert(since);
        }
        if (snap.a_lists_j || snap.j_active) && self.admitted.is_none() {
            self.admitted = Some((
                since,
                format!("A lists J: {}; J active: {}", snap.a_lists_j, snap.j_active),
            ));
        }
        // A correct S5 joiner may report its typed wait as the join state
        // itself (ADR 0111 §8), so that state also counts as pending.
        let pending = snap.j_typed
            || snap
                .join_state
                .as_deref()
                .is_some_and(|state| state == JOIN_PENDING || state.contains("awaiting_evidence"));
        self.j_pending_now = pending && snap.outcome.is_none();
        let state = format!(
            "join_state={} outcome={}{}",
            match (&snap.join_state, snap.stub_gone) {
                (Some(state), _) => state.as_str(),
                (None, true) => "stub gone (404)",
                (None, false) => "none",
            },
            snap.outcome.as_deref().unwrap_or("none"),
            if snap.j_active { " active" } else { "" }
        );
        if !snap.j_active {
            if self.j_ended.is_none() && (snap.outcome.is_some() || !pending) {
                self.j_ended = Some((since, state.clone()));
            }
            if self.silent_drop.is_none() && !pending && snap.outcome.is_none() {
                self.silent_drop = Some((since, state.clone()));
            }
        }
        if self.timeline.last().map(|(_, last)| last) != Some(&state) {
            self.timeline.push((since, state));
        }
    }

    /// Poll every `POLL` until `until` has passed since `joined_at`.
    async fn poll_until(
        &mut self,
        sim: &Sim,
        gid: &str,
        digests: &[String],
        joined_at: Duration,
        until: Duration,
    ) -> Result<()> {
        loop {
            let since = sim.fabric().now().saturating_sub(joined_at);
            let snap = sim
                .within(
                    &format!("read the wait states at t2+{}s", since.as_secs()),
                    secs(10),
                    snapshot(sim, gid, digests),
                )
                .await??;
            self.record(since, &snap);
            let (_, held) = held_digests(sim, "A", gid, digests).await?;
            if !held.is_empty() && self.a_held.is_none() {
                self.a_held = Some((since, held.len()));
            }
            if since >= until {
                return Ok(());
            }
            sim.within(
                "wait for the next poll",
                POLL + secs(1),
                tokio::time::sleep(POLL),
            )
            .await?;
        }
    }

    fn timeline(&self) -> String {
        self.timeline
            .iter()
            .map(|(since, state)| format!("t2+{}s {state}", since.as_secs()))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn at_text(at: Option<Duration>) -> String {
    at.map_or("never".to_string(), |at| format!("t2+{}s", at.as_secs()))
}

/// A dials `label` directly. A's bootstrap peer is O, which is offline.
async fn a_dials(sim: &Sim, label: &str) -> Result<()> {
    let network = sim
        .state("A")?
        .agent
        .network()
        .cloned()
        .context("A has no network")?;
    let addr = super::sim_addr(sim.node_index(label)?)?;
    sim.within(
        &format!("A dials {label}"),
        secs(10),
        network.connect_addr(addr),
    )
    .await?
    .map_err(|error| anyhow!("A could not dial {label}: {error}"))?;
    Ok(())
}

/// A's seal refusal for THIS group and THIS joiner, at or after J's first
/// verified request, naming exactly `want` (A's digest-only seats).
fn seal_refusal(
    sim: &Sim,
    gid: &str,
    want: &[String],
    first_request: Option<Duration>,
) -> Result<Option<String>> {
    let j_hex = sim.agent_hex("J")?;
    let j_tokens = [
        crate::logging::LogHexId::agent(j_hex.as_str()).to_string(),
        crate::logging::LogHexId::agent(j_hex.to_uppercase().as_str()).to_string(),
    ];
    Ok(sim
        .logs_containing(&[SEAL_REFUSAL, PENDING_CAUSE, &format!("group {gid}")])
        .into_iter()
        .filter(|log| {
            j_tokens
                .iter()
                .any(|token| log.text.contains(&format!("member={token}")))
        })
        .filter(|log| first_request.is_some_and(|first| log.at >= first))
        .find(|log| refused_members(&log.text).as_deref() == Some(want))
        .map(|log| log.text))
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
    let answers = AnswerDrop::install(sim, &["A", "J"], MEMBERS)?;
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
    // O announces with consent (the #1143 workaround): A's seat for O has
    // no certificate, so only O's consented announce gives A O's
    // certificate. Without it, every seal of J's add refuses naming O.
    // A fetches the certificate blob once per announce, and only the
    // next announce retries a failed fetch. The drop toward A can lose
    // that blob, so O repeats the announce every 10 s, as a heartbeat
    // would (run 39384499206).
    let mut announces = 0_u32;
    let mut waited = Duration::ZERO;
    let (o_clean, o_status) = loop {
        let (status, body) = sim
            .api(
                "O",
                Method::POST,
                "/announce",
                Some(json!({"include_user_identity": true, "human_consent": true})),
            )
            .await?;
        ensure!(status.is_success(), "O announce: {status} {body}");
        announces += 1;
        let (clean, last) = until_a_clean(sim, &home.gid, "O", secs(10)).await?;
        waited += secs(10);
        if clean || waited >= secs(60) {
            break (clean, last);
        }
    };
    receipt.evidence(
        "a_verifies_creator_certificate_from_its_consented_announce",
        o_clean,
        format!("after {announces} consented announces from O, A's verdict for O: {o_status:?}"),
        at(sim),
    );
    ensure!(
        o_clean,
        "INFRA: A did not verify O's certificate after O's consented announce \
         (verdict {o_status:?})"
    );
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
    // J must hold none of the missing bytes, or A resolves the seats from J
    // with every X device offline.
    let j_holds = {
        let j = sim.state("J")?;
        let digests = missing.clone();
        sim.at_instant("read J's announce cache", async move {
            let mut held = 0usize;
            for digest in &digests {
                if let Some(bytes) = parse_digest(digest) {
                    if j.agent
                        .announce_blob_cache
                        .find_by_cert_digest(&bytes)
                        .await
                        .is_some()
                    {
                        held += 1;
                    }
                }
            }
            held
        })
        .await?
    };
    receipt.evidence(
        "j_holds_none_of_the_missing_certificates",
        j_holds == 0,
        format!("J holds {j_holds} of {}", missing.len()),
        at(sim),
    );
    ensure!(
        j_holds == 0,
        "INFRA: J holds {j_holds} of {} certificates that A is missing",
        missing.len()
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
    // The control keeps this holder online; the red test brings it back
    // after the gap.
    let full_holder = match arm {
        Arm::OneHolderOnline | Arm::HolderReturns => Some(
            full_holder.context("INFRA: no X device holds every certificate that A is missing")?,
        ),
        Arm::HoldersNeverReturn => None,
    };
    let stays_online = match arm {
        Arm::OneHolderOnline => full_holder,
        Arm::HolderReturns | Arm::HoldersNeverReturn => None,
    };

    // t1: the setup drop ends, then the holders go offline (no await in
    // between, so no frame moves), and A restarts.
    answers.release();
    sim.fabric().mark(format!(
        "setup fault lifted: X-certificate and #946 drop toward A and J ({} frames dropped)",
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
    let mut dial = vec!["J"];
    dial.extend(stays_online);
    for label in dial {
        a_dials(sim, label).await?;
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
    // A's discovery cache is in memory, so A lost O's consented announce in
    // the restart. A must learn it again from an online node, or every
    // seal of J's add refuses naming O.
    let o_wait_from = sim.fabric().now();
    let (o_clean, o_status) = until_a_clean(sim, &home.gid, "O", secs(60)).await?;
    let o_took = sim.fabric().now().saturating_sub(o_wait_from);
    receipt.evidence(
        "a_verifies_creator_certificate_after_its_restart",
        o_clean,
        format!("A's verdict for O after its restart: {o_status:?} (after {o_took:?})"),
        at(sim),
    );
    ensure!(
        o_clean,
        "INFRA: A did not verify O's certificate after A's restart (verdict {o_status:?})"
    );
    receipt.setup_done(at(sim));

    // In the control the online holder can answer A before t2 (run
    // 39380658640: A held 1 of 1 missing digests after the 26 s wait for
    // O). Then a seat can hydrate before this read. The red arm keeps the
    // exact seats; the control requires a subset of them.
    let after = seat_view(sim, "A", &home.gid).await?;
    let same_seats = match arm {
        Arm::HolderReturns | Arm::HoldersNeverReturn => after.digest_only == before.digest_only,
        Arm::OneHolderOnline => after
            .digest_only
            .iter()
            .all(|(agent, digest)| before.digest_only.get(agent) == Some(digest)),
    };
    receipt.evidence(
        "a_restarted_as_promoted_admin_with_the_same_digest_only_seats",
        restarted == incarnation + 1 && after.admin && same_seats,
        format!(
            "A incarnation {incarnation}->{restarted}; admin={}; digest-only seats after \
             the restart: {:?} ({} before; {})",
            after.admin,
            after.digest_only.keys().collect::<Vec<_>>(),
            before.digest_only.len(),
            match arm {
                Arm::HolderReturns | Arm::HoldersNeverReturn => "must be equal",
                Arm::OneHolderOnline => "must be a subset",
            }
        ),
        at(sim),
    );
    let (_, a_held) = held_digests(sim, "A", &home.gid, &missing).await?;
    match stays_online {
        None => receipt.evidence(
            "a_has_no_bytes_for_the_missing_certificates",
            a_held.is_empty(),
            format!(
                "A holds {} of {} missing digests",
                a_held.len(),
                missing.len()
            ),
            at(sim),
        ),
        Some(label) => {
            let (_, online_held) = holders.get(label).cloned().unwrap_or_default();
            receipt.evidence(
                "a_bytes_after_its_restart_come_only_from_the_online_holder",
                a_held.iter().all(|digest| online_held.contains(digest)),
                format!(
                    "A holds {} of {} missing digests; online holder {label} holds {}",
                    a_held.len(),
                    missing.len(),
                    online_held.len()
                ),
                at(sim),
            );
        }
    }
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
        Arm::HolderReturns | Arm::HoldersNeverReturn => {
            o_offline && online_holders.is_empty() && offline_holders > 0
        }
        Arm::OneHolderOnline => {
            o_offline && online_holders == stays_online.into_iter().collect::<Vec<_>>()
        }
    };
    receipt.evidence(
        match arm {
            Arm::HolderReturns | Arm::HoldersNeverReturn => {
                "creator_and_every_eligible_holder_offline"
            }
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
    let joined_at = sim.fabric().now();
    let mut window = WaitWindow::default();
    let j_admitted = match arm {
        Arm::OneHolderOnline => admitted(sim, "A", "J", &home.gid, JOIN_BUDGET).await?,
        Arm::HolderReturns | Arm::HoldersNeverReturn => {
            // Every holder is offline: the wait must be typed and must not
            // end at J's 120 s poll deadline (ADR 0111 §8, D64).
            window
                .poll_until(sim, &home.gid, &missing, joined_at, HOLDER_GAP)
                .await?;
            false
        }
    };
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
    let mut want: Vec<String> = before.digest_only.keys().cloned().collect();
    want.sort();
    receipt.note(format!(
        "arm={arm:?}; #946 answers dropped toward A during setup: {}; digest-only seats \
         at A: {}",
        answers.dropped(),
        missing.len()
    ));
    let passed = match arm {
        Arm::OneHolderOnline => {
            if !j_admitted {
                // The cause: A's seal refusal for THIS group and THIS joiner,
                // after J's request reached A, naming exactly A's digest-only
                // seats.
                let refusal = seal_refusal(sim, &home.gid, &want, first_request)?;
                receipt.cause(
                    "OwnerCertMemberPending{members=A's digest-only seats} from A's seal of J's add",
                    refusal.clone(),
                    refusal.is_some(),
                    at(sim),
                );
                let a_rows = roster(sim, "A", &home.gid).await.unwrap_or_default();
                let j_state = membership_state(sim, "J", &home.gid).await.ok().flatten();
                sim.fabric().mark(format!(
                    "observed: A lists {} members, J membership_state={j_state:?}",
                    a_rows.len()
                ));
            }
            j_admitted
        }
        Arm::HolderReturns => {
            // Preconditions of the red arm: with every holder offline,
            // nothing can admit J or give A the bytes. Otherwise the
            // scenario broke.
            let gap_admitted = window.admitted.clone();
            receipt.evidence(
                "j_not_admitted_while_every_holder_offline",
                gap_admitted.is_none(),
                match &gap_admitted {
                    Some((since, how)) => format!("at t2+{}s: {how}", since.as_secs()),
                    None => format!(
                        "{} polls over {}s: A never lists J and J is never active",
                        window.polls,
                        HOLDER_GAP.as_secs()
                    ),
                },
                at(sim),
            );
            let (_, gap_held) = held_digests(sim, "A", &home.gid, &missing).await?;
            receipt.evidence(
                "a_holds_none_of_the_missing_bytes_while_every_holder_offline",
                gap_held.is_empty(),
                format!(
                    "after the gap A holds {} of {} missing digests",
                    gap_held.len(),
                    missing.len()
                ),
                at(sim),
            );
            ensure!(
                gap_admitted.is_none() && gap_held.is_empty(),
                "INFRA: with every holder offline, J was admitted ({gap_admitted:?}) or A \
                 holds {} missing digests",
                gap_held.len()
            );
            let refusal = seal_refusal(sim, &home.gid, &want, first_request)?;
            let holder = full_holder
                .context("INFRA: no X device holds every certificate that A is missing")?;
            holder_returns(
                sim,
                receipt,
                Returning {
                    gid: &home.gid,
                    home: &home,
                    link: &link,
                    holder,
                    missing: &missing,
                    joined_at,
                    refusal,
                },
                &window,
            )
            .await?
        }
        // In the fail-closed control an admission or bytes at A are the
        // defect, so they fail FINAL; they are not INFRA.
        Arm::HoldersNeverReturn => {
            never_return(sim, receipt, &home.gid, &missing, joined_at, &mut window).await?
        }
    };
    receipt.finish(arm.final_name(), passed, at(sim));
    Ok(())
}

/// What the red arm needs after the gap.
struct Returning<'a> {
    gid: &'a str,
    home: &'a HomeIds,
    link: &'a str,
    /// The X device that holds every missing certificate.
    holder: &'static str,
    missing: &'a [String],
    joined_at: Duration,
    /// A's seal refusal naming exactly its digest-only seats, if logged.
    refusal: Option<String>,
}

/// ADR 0111 H3 after the gap: the holder comes back, J retries, A must
/// hold the bytes within 60 s and J must become Active. Returns FINAL.
async fn holder_returns(
    sim: &Sim,
    receipt: &mut Receipt,
    ret: Returning<'_>,
    window: &WaitWindow,
) -> Result<bool> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let since_join = |sim: &Sim| sim.fabric().now().saturating_sub(ret.joined_at).as_secs();
    sim.set_online(ret.holder, true)?;
    sim.fabric()
        .mark(format!("holder {} returns after the gap", ret.holder));
    let returned_at = sim.fabric().now();
    a_dials(sim, ret.holder).await?;
    // H3 step 3: J retries. A pending attempt must resume by itself, so
    // the case re-POSTs only when J's attempt has ended. A failed re-POST
    // is product behaviour, not INFRA.
    if window.j_pending_now {
        receipt.note("J's attempt is still pending after the gap: no new join call");
    } else {
        let (status, body) = sim
            .api(
                "J",
                Method::POST,
                "/groups/join",
                Some(json!({
                    "invite": ret.link,
                    "display_name": "J",
                    "mode": "home",
                    "expected_owner_user_id": ret.home.owner_user_id,
                })),
            )
            .await?;
        receipt.note(format!(
            "J's attempt had ended; J redeems the same invite again at t2+{}s: {status} {body}",
            since_join(sim)
        ));
    }
    // ADR 0111 H3: within 60 s of the holder's start, A holds the bytes.
    let deadline = returned_at.saturating_add(RETURN_FETCH);
    let a_holds = loop {
        let (_, held) = held_digests(sim, "A", ret.gid, ret.missing).await?;
        if held.len() == ret.missing.len() {
            break Some(sim.fabric().now().saturating_sub(returned_at));
        }
        if sim.fabric().now() >= deadline {
            break None;
        }
        sim.within(
            "wait for A to fetch the certificates",
            secs(2),
            tokio::time::sleep(secs(1)),
        )
        .await?;
    };
    let j_active = admitted(sim, "A", "J", ret.gid, RETURN_ADMIT).await?;
    let ended_in_gap = window.j_ended.clone();
    let parts = [
        (
            "a_typed_evidence_pending_seen",
            window.a_typed_at.is_some(),
            format!("first at {}", at_text(window.a_typed_at)),
        ),
        (
            "j_typed_awaiting_evidence_seen",
            window.j_typed_at.is_some(),
            format!("first at {}", at_text(window.j_typed_at)),
        ),
        (
            "j_attempt_did_not_end_during_the_gap",
            ended_in_gap.is_none(),
            match &ended_in_gap {
                Some((since, how)) => format!("ended at t2+{}s: {how}", since.as_secs()),
                None => "pending throughout".to_string(),
            },
        ),
        (
            "a_holds_within_60s",
            a_holds.is_some(),
            a_holds.map_or(
                "A did not hold every missing digest within 60 s".to_string(),
                |took| {
                    format!(
                        "A held every missing digest {}s after the return",
                        took.as_secs()
                    )
                },
            ),
        ),
        (
            "j_admitted_after_return",
            j_active,
            format!(
                "J Active and listed by A within {}s: {j_active}",
                RETURN_ADMIT.as_secs()
            ),
        ),
    ];
    for (name, ok, detail) in &parts {
        receipt.note(format!("final component {name}: {ok} ({detail})"));
    }
    receipt.note(format!("J's states during the gap: {}", window.timeline()));
    let passed = parts.iter().all(|(_, ok, _)| *ok);
    if !passed {
        let typed_absent = window.a_typed_at.is_none() && window.j_typed_at.is_none();
        let summary = format!(
            "J's attempt end: {}; A held the bytes after the return: {}; J active after \
             the return: {j_active}",
            match &ended_in_gap {
                Some((since, how)) => format!("t2+{}s ({how})", since.as_secs()),
                None => "none during the gap".to_string(),
            },
            a_holds.map_or("no".to_string(), |took| format!(
                "yes, after {}s",
                took.as_secs()
            )),
        );
        receipt.cause(
            "every holder offline: A's seal waits on OwnerCertMemberPending{A's digest-only \
             seats}, but A shows no typed evidence_pending and J's attempt shows no \
             awaiting_evidence naming them",
            Some(format!(
                "{}; {summary}",
                ret.refusal
                    .as_deref()
                    .unwrap_or("no matching seal refusal logged")
            )),
            ret.refusal.is_some() && typed_absent,
            at(sim),
        );
    }
    Ok(passed)
}

/// The fail-closed control: every holder stays offline for
/// `NEVER_WINDOW`. Returns FINAL.
async fn never_return(
    sim: &Sim,
    receipt: &mut Receipt,
    gid: &str,
    missing: &[String],
    joined_at: Duration,
    window: &mut WaitWindow,
) -> Result<bool> {
    window
        .poll_until(sim, gid, missing, joined_at, NEVER_WINDOW)
        .await?;
    let (_, held) = held_digests(sim, "A", gid, missing).await?;
    receipt.note(format!(
        "{} polls over {}s; J admitted: {:?}; J silently dropped: {:?}; A first held \
         bytes: {:?}; A holds {} of {} missing digests at the end; A typed wait first at \
         {}; J typed wait first at {}",
        window.polls,
        NEVER_WINDOW.as_secs(),
        window.admitted,
        window.silent_drop,
        window.a_held,
        held.len(),
        missing.len(),
        at_text(window.a_typed_at),
        at_text(window.j_typed_at)
    ));
    receipt.note(format!("J's states: {}", window.timeline()));
    Ok(window.admitted.is_none()
        && window.a_held.is_none()
        && held.is_empty()
        && window.silent_drop.is_none())
}

/// Run the scenario once and return its emitted receipt. Any error before
/// the final assertion is recorded as INFRA.
async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "setup fault: every frame toward A or J that carries an X certificate (except the \
         target's own seat event) and every #946 answer is dropped from A's start until \
         the holders go offline, so A keeps the seats its seat event omitted \
         digest-only (ADR 0111 H3: the harness makes the admin's seat digest-only)",
    );
    receipt.note(format!(
        "arm {arm:?}, FINAL {}: with every holder offline the case polls A \
         (/groups/{{gid}}) and J (/groups/{{gid}}, /join-status) every {}s \
         for {}s; a typed wait is evidence_pending at A and awaiting_evidence at J, \
         each naming every missing digest (ADR 0088 §1 L3, §2 item 8; ADR 0111 §8, \
         H3). The holder returns after the gap in the red test only",
        arm.final_name(),
        POLL.as_secs(),
        HOLDER_GAP.as_secs()
    ));
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
        receipt.reclassify(arm.final_name());
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
async fn w3h_1023_red_baseline_all_holders_offline_wait_is_typed_then_resumes() -> Result<()> {
    expect(
        "w3h_1023_red_baseline_all_holders_offline_wait_is_typed_then_resumes",
        0x1023_0001,
        Arm::HolderReturns,
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

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1023_control_holders_never_return_fail_closed() -> Result<()> {
    expect(
        "w3h_1023_control_holders_never_return_fail_closed",
        0x1023_0003,
        Arm::HoldersNeverReturn,
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
