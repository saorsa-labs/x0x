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
//!   (D64). ADR 0111 H3 brings the holder back at minute 12, after the
//!   10-minute #946 terminal refusal (`CERT_EVIDENCE_DEADLINE_MS`), and
//!   requires no terminal refusal before then. So the case polls every 5 s
//!   for 720 s (`HOLDER_GAP`) after J's join call. It reads `/groups/{gid}`
//!   at A for the typed wait, and `/groups/{gid}` and
//!   `/groups/{gid}/join-status` at J. It reads A's roster from
//!   `/groups/{gid}/members`. Every read must answer with the expected
//!   HTTP status and body shape; any other answer is INFRA, never a
//!   verdict. Each value that a verdict reads is a closed set (ADR 0025):
//!   `join_state` is `pending_authority_commit`, `idle` or
//!   `awaiting_evidence`; `last_join_outcome` is null, or an object whose
//!   `outcome` is `refused`, `timed_out` or `seated` and whose
//!   `finished_at_ms` is a non-negative integer; `membership_state` is
//!   `active`, `pending`, `pending_authority_commit` or `not_member`. Any
//!   other value is INFRA. A `seated` outcome ends J's attempt and counts
//!   as an admission. A typed wait is a parsed JSON object, not a
//!   substring: an object whose tag field (`state`, `status`, `cause`,
//!   `type`, `join_state` or `wait`) is exactly the state name, or an
//!   object keyed by the state name, with its own `digest` or `digests`
//!   field. Each digest must decode to 32 bytes (hex or base64). Subtrees
//!   under `error` and `message` are not read. A shows `evidence_pending` when
//!   the digests of its typed objects are exactly the missing set. J shows
//!   `awaiting_evidence` when one typed object names exactly the missing
//!   set. An S5 implementation must expose the typed states on one of
//!   these routes. Each typed wait must stay visible; seen once is not
//!   enough. A's wait begins at A's first verified join message from J.
//!   A must show `evidence_pending` at every poll after that, through the
//!   last gap poll. J must show `awaiting_evidence` at every poll after
//!   the first poll at which A showed its typed wait, through the last gap
//!   poll. Each rule needs at least one such poll. The receipt names the
//!   first poll at which a typed wait was absent. Evidence (red test
//!   only): J is not admitted during the gap, and A holds none of the
//!   missing bytes at its end. On `main`, A's
//!   seal refuses with `OwnerCertMemberPending` naming exactly A's
//!   digest-only seats, and A and J show no typed state.
//! - After the gap (red test only, ADR 0111 H3): the X device that holds
//!   every missing certificate comes back and A dials it. If J's attempt
//!   is still pending, the attempt must resume by itself. Otherwise J
//!   redeems the same invite again. A must hold every missing certificate
//!   within 60 s, and J must become Active within 120 s. No terminal
//!   refusal may come before the return: J shows no `refused` outcome, and
//!   A records no `certificate_evidence_unavailable` refusal for G.
//!
//! Strict reads. Every HTTP answer that the case reads goes through
//! one pure parse function per route, which unit tests call:
//! `parse_created`, `parse_invite`, `parse_join_answer` (each join call,
//! the re-join after the return included), `parse_announce`,
//! `parse_roster`, `parse_membership` and `parse_join_status`. The case
//! does not use the lenient helpers of `home.rs` (`membership_state`,
//! `roster`) for any read that feeds a verdict. The parse needs the
//! status and body that the handler really sends. It also needs the
//! group id of the path. A 404 must be the handler's exact not-found
//! body (no other keys). A missing field, a wrong type, a wrong group id
//! or a value outside the closed set is an error, so the run is INFRA.
//! Such an answer is never "not active", "not admitted" or "nothing
//! shown", and it cannot keep the expected RED. A typed-state object
//! (tagged or keyed with the state name) must name at least one
//! well-formed digest, or it is an error too. In-process reads (seats,
//! bytes, verdicts, bindings, refusal counters) return an error when G
//! or a node is missing, never "none".
//!
//! Timing at observation. Every "within" bound uses one helper
//! (`timed_wait`): the setup seats (180 s), O's announces (60 s), J's
//! binding (30 s), A's restart verdict for O (60 s), J Active in the
//! control (180 s), A's bytes after the return (60 s) and J Active
//! after the return (120 s). The observation time is the time at which
//! the satisfying read FINISHED, from the wait's start (`observed_at`).
//! This is the conservative end: a read that started inside the bound
//! but finished after it is `Late`. `classify` gives `Met` only at or
//! under the bound, and `component_passes` passes only `Met`. So no
//! component takes evidence first and checks its deadline later. No
//! read starts after the bound (`may_read`), so a wait overruns its
//! bound by one read at most. `LATE_SLACK` is only a hard cap for a read
//! that hangs (INFRA). Each poll of the gap records when it started and
//! when it finished. The lower bounds (minute 12, the 900 s window and
//! `SETTLE`) use the conservative end too: a span reaches its bound only
//! when its last poll STARTED at or after the bound (`span_reached`). The
//! rules that count polls "after" an instant also use the poll start.
//!
//! Three tests share the scenario:
//! - `w3h_1023_red_baseline_all_holders_offline_wait_is_typed_then_resumes`:
//!   every eligible holder is offline, then one returns. FINAL
//!   `typed_retryable_wait_then_j_active_after_holder_returns` needs A's
//!   typed `evidence_pending` and J's typed `awaiting_evidence`, each at
//!   every poll of its span, no end of J's
//!   attempt and no terminal refusal during the gap, A's bytes within 60 s
//!   of the return and J Active after it. RED on `main`. The cause is the
//!   `OwnerCertMemberPending` refusal above, with no typed wait at A or J.
//! - `w3h_1023_restart_one_holder_online_admits`: the control. One X
//!   device that holds every missing certificate stays online after A's
//!   restart. A gets the bytes from it and J is admitted. GREEN. The
//!   restart and the setup are the same in all tests, so only the offline
//!   holders make the red case red.
//! - `w3h_1023_control_holders_never_return_fail_closed`: every holder
//!   stays offline for 900 s (`NEVER_WINDOW`, the span of the red test),
//!   past the same minute-12 boundary. FINAL
//!   `fail_closed_never_admitted_never_silently_dropped`: J is never
//!   admitted and A never holds any of the missing bytes (both fail FINAL,
//!   not INFRA, in this test), and at every poll J's join-status shows a
//!   pending attempt or a typed outcome (`timed_out`, or a refusal such as
//!   the 10-minute `certificate_evidence_unavailable`). ADR 0088 L4 keeps
//!   the wait fail-closed. GREEN on `main` and GREEN under a correct S5
//!   (pending throughout). The receipt names the first terminal refusal.

#![cfg(test)]

use super::home::HomeIds;
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::identity::{AgentId, UserKeypair};
use crate::network::sim::{Fault, Write};
use anyhow::ensure;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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
/// When `main` stages the #946 terminal refusal after continuous seal
/// refusals (`CERT_EVIDENCE_DEADLINE_MS`, `seat_cert_fetch.rs`).
const TERMINAL_REFUSAL: Duration = secs(600);
/// The reason of that terminal refusal.
const TERMINAL_REASON: &str = "certificate_evidence_unavailable";
/// How long every holder stays offline after J's join: ADR 0111 H3's
/// minute 12. This is past J's 120 s join-result poll deadline (ADR 0111
/// §8, D64) and past `TERMINAL_REFUSAL`.
const HOLDER_GAP: Duration = secs(720);
const _: () = assert!(HOLDER_GAP.as_secs() > TERMINAL_REFUSAL.as_secs());
/// ADR 0111 H3: A holds the certificates within 60 s of the holder's start.
const RETURN_FETCH: Duration = secs(60);
/// How long J has to become Active after A holds the certificates.
const RETURN_ADMIT: Duration = secs(120);
/// The never-return control covers the same span as the red test (900 s).
const NEVER_WINDOW: Duration = HOLDER_GAP
    .saturating_add(RETURN_FETCH)
    .saturating_add(RETURN_ADMIT);
const _: () = assert!(NEVER_WINDOW.as_secs() > HOLDER_GAP.as_secs());
/// J's `join_state` while its attempt waits for the authority.
const JOIN_PENDING: &str = "pending_authority_commit";
/// The authority's typed wait for a missing digest (ADR 0111 §8).
const EVIDENCE_PENDING: &str = "evidence_pending";
/// A capable joiner's typed wait (ADR 0111 §8).
const AWAITING_EVIDENCE: &str = "awaiting_evidence";
/// The #946 answer domain (`seat_cert_fetch::GROUP_CERT_FETCH_RESPONSE_DOMAIN`).
/// It leads the pubsub payload in clear.
const FETCH_RESPONSE_DOMAIN: &[u8] = b"x0x/group-cert-fetch-response-v1\0";
/// The hard cap of a bounded wait past its bound. No read starts after
/// the bound (`may_read`); the cap only lets a read that started inside
/// the bound finish, so that it is reported as `Late`, and it stops a
/// read that hangs (INFRA).
const LATE_SLACK: Duration = secs(10);
/// How long O's consented announces have, in total, until A verifies O.
const O_ANNOUNCE_BOUND: Duration = secs(60);
/// How often O repeats its consented announce, as a heartbeat would.
const O_ANNOUNCE_EVERY: Duration = secs(10);
/// How long A has to verify an announced machine binding.
const VERIFY_BOUND: Duration = secs(30);
/// How long A has to verify O again after A's restart.
const RESTART_CLEAN_BOUND: Duration = secs(60);

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

/// Post-condition of the shared certify helpers (`home.rs`): `label`
/// runs with a valid agent certificate for its own agent, signed by
/// `owner`.
fn certified_by(sim: &Sim, label: &str, owner: &UserKeypair) -> Result<()> {
    let state = sim.state(label)?;
    let cert = state
        .agent
        .identity()
        .agent_certificate()
        .cloned()
        .with_context(|| format!("INFRA: {label} has no agent certificate"))?;
    cert.verify()
        .with_context(|| format!("INFRA: {label}'s agent certificate does not verify"))?;
    ensure!(
        cert.user_id()? == owner.user_id() && cert.agent_id()? == state.agent.agent_id(),
        "INFRA: {label}'s agent certificate is not the owner's certificate for its agent"
    );
    Ok(())
}

/// Post-condition of `promote_admin` (`home.rs`): the strict roster of
/// each observer lists `member` as an active admin.
async fn admin_everywhere(sim: &Sim, gid: &str, member: &str, observers: &[&str]) -> Result<()> {
    let member_hex = sim.agent_hex(member)?;
    let path = format!("/groups/{gid}/members");
    for observer in observers {
        let (status, body) = sim
            .within(
                &format!("read {observer}'s roster"),
                secs(10),
                get_object(sim, observer, &path),
            )
            .await??;
        let rows =
            parse_roster(gid, status, &body).with_context(|| format!("{observer} GET {path}"))?;
        ensure!(
            rows.iter().any(|row| row.agent_id == member_hex
                && row.role == crate::groups::GroupRole::Admin
                && row.state == crate::groups::GroupMemberState::Active),
            "INFRA: {observer} does not list {member} as an active admin: {rows:?}"
        );
    }
    Ok(())
}

/// Whether `label` is an eligible holder of each digest: an active member
/// of G that holds bytes for it, on the matching seat or in its
/// durable announce cache. The result lists the digests it holds. A node
/// with no entry for G is an error: every node that the case reads this
/// way joined G during the setup.
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
    let what = format!("read {label}'s certificate bytes");
    let label = label.to_string();
    sim.at_instant(&what, async move {
        let (active, on_seats) = {
            let groups = state.named_groups.read().await;
            let (_, info) = crate::server::resolve_group_entry_locked(&groups, &gid)
                .with_context(|| format!("{label} has no entry for G"))?;
            (
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
            )
        };
        let mut held = Vec::new();
        for digest in digests {
            // The case read every digest from A's own seats: one that does
            // not decode is an error, not "not held".
            let bytes =
                parse_digest(&digest).with_context(|| format!("bad seat digest {digest}"))?;
            let cached = state
                .agent
                .announce_blob_cache
                .find_by_cert_digest(&bytes)
                .await
                .is_some();
            if cached || on_seats.contains(&digest.to_ascii_lowercase()) {
                held.push(digest);
            }
        }
        Ok((active, held))
    })
    .await?
}

fn parse_digest(digest: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(digest).ok()?).ok()
}

/// Whether `label` is on the fabric now. A node that the fabric does not
/// know is an error.
fn online(sim: &Sim, label: &str) -> Result<bool> {
    sim.fabric()
        .is_online(&sim.peer(label)?)
        .with_context(|| format!("{label} is not on the fabric"))
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
    let body = json!({
        "name": "w3h 1023",
        "display_name": label,
        "policy": {
            "discoverability": "listed_to_contacts",
            "admission": {"owner_certified": owner_user_id},
            "confidentiality": "mls_encrypted",
            "read_access": "members_only",
            "write_access": "members_only",
        },
    });
    let (status, created) = post_object(sim, label, "/groups", body).await?;
    parse_created(status, &created).context("create owner-certified group")
}

/// `inviter` mints an unaddressed invite to `gid`.
async fn invite(sim: &Sim, inviter: &str, gid: &str) -> Result<String> {
    let path = format!("/groups/{gid}/invite");
    let (status, body) = post_object(sim, inviter, &path, json!({})).await?;
    parse_invite(gid, status, &body).with_context(|| format!("{inviter} POST {path}"))
}

/// The body of `POST /groups/join` for `joiner`. An owner-certified
/// invite needs the pinned owner mode (`mode: home`) for any group, not
/// only the Home.
fn join_body(joiner: &str, group: &HomeIds, link: &str) -> serde_json::Value {
    json!({
        "invite": link,
        "display_name": joiner,
        "mode": "home",
        "expected_owner_user_id": group.owner_user_id,
    })
}

/// `joiner` redeems `link` during the setup or at t2. Only the handler's
/// success shape, with a fresh-join `join_state`, is accepted. A refusal
/// or any other answer is an error.
async fn join(sim: &Sim, joiner: &str, group: &HomeIds, link: &str) -> Result<()> {
    let (status, body) =
        post_object(sim, joiner, "/groups/join", join_body(joiner, group, link)).await?;
    let answer = parse_join_answer(&group.gid, status, &body)
        .with_context(|| format!("{joiner} POST /groups/join"))?;
    ensure!(
        matches!(
            answer,
            JoinAnswer::Accepted {
                join_state: Membership::PendingAuthorityCommit | Membership::Active,
                ..
            }
        ),
        "{joiner} join: {}",
        answer.text()
    );
    Ok(())
}

/// `label` announces (`POST /announce`) and the handler answers with its
/// exact success body.
async fn announce(sim: &Sim, label: &str, include_user_identity: bool) -> Result<()> {
    let body = if include_user_identity {
        json!({"include_user_identity": true, "human_consent": true})
    } else {
        json!({})
    };
    let (status, answer) = post_object(sim, label, "/announce", body).await?;
    parse_announce(status, &answer, include_user_identity)
        .with_context(|| format!("{label} POST /announce"))
}

/// Whether a strict roster read lists `member_hex`.
fn lists(gid: &str, member_hex: &str, status: StatusCode, body: &Object) -> Result<bool> {
    Ok(parse_roster(gid, status, body)?
        .iter()
        .any(|row| row.agent_id.eq_ignore_ascii_case(member_hex)))
}

/// Whether a strict `/groups/{gid}` read says `active`. The handler's
/// exact 404 means "no group here", so not active. Any other answer is an
/// error.
fn is_active(gid: &str, status: StatusCode, body: &Object) -> Result<bool> {
    Ok(parse_membership(gid, status, body)? == Some(Membership::Active))
}

/// One strict read of whether `authority` lists `member` and `member`
/// says it is `active`.
async fn read_admitted(
    sim: &Sim,
    authority: &str,
    member: &str,
    gid: &str,
    member_hex: &str,
) -> Result<bool> {
    let path = format!("/groups/{gid}/members");
    let (status, body) = get_object(sim, authority, &path).await?;
    if !lists(gid, member_hex, status, &body).with_context(|| format!("{authority} GET {path}"))? {
        return Ok(false);
    }
    let path = format!("/groups/{gid}");
    let (status, body) = get_object(sim, member, &path).await?;
    is_active(gid, status, &body).with_context(|| format!("{member} GET {path}"))
}

/// When, after `start`, `authority` lists `member` in `gid` and `member`
/// reports itself `active`, against `bound`. "Not admitted" is a verdict
/// only when every read completed and succeeded; a failed, malformed or
/// hanging read is INFRA.
async fn admitted(
    sim: &Sim,
    authority: &str,
    member: &str,
    gid: &str,
    start: Duration,
    bound: Duration,
) -> Result<Deadline> {
    let member_hex = sim.agent_hex(member)?;
    let what = format!("{member} seated on {authority} and locally");
    let timed = timed_wait(sim, &what, start, bound, None, async |s: &Sim| {
        read_admitted(s, authority, member, gid, &member_hex)
            .await
            .map(|done| (done, ()))
    })
    .await?;
    Ok(timed.deadline)
}

/// When an awaited observation was made, against its bound. Each time is
/// read on the fabric clock right after the read that made the
/// observation, and is measured from the wait's start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Deadline {
    /// Seen `at` after the start, within the bound.
    Met { at: Duration },
    /// Seen `at` after the start, past the bound.
    Late { at: Duration },
    /// Not seen in the `waited` time after the start.
    Never { waited: Duration },
}

/// Classify one observation time. `Met` if and only if `at <= bound`.
fn classify(at: Option<Duration>, waited: Duration, bound: Duration) -> Deadline {
    match at {
        Some(at) if at <= bound => Deadline::Met { at },
        Some(at) => Deadline::Late { at },
        None => Deadline::Never { waited },
    }
}

/// The decision of each bounded component: it passes only on `Met`
/// within `bound`. A late or missing observation fails.
fn component_passes(deadline: Deadline, bound: Duration) -> bool {
    matches!(deadline, Deadline::Met { at } if at <= bound)
}

/// A duration as seconds with millisecond precision.
fn ms_text(time: Duration) -> String {
    format!("{:.3}s", time.as_secs_f64())
}

impl Deadline {
    fn text(self, bound: Duration) -> String {
        match self {
            Self::Met { at } => format!("met at {} (bound {}s)", ms_text(at), bound.as_secs()),
            Self::Late { at } => format!("LATE at {} (bound {}s)", ms_text(at), bound.as_secs()),
            Self::Never { waited } => {
                format!("never in {} (bound {}s)", ms_text(waited), bound.as_secs())
            }
        }
    }
}

/// The result of one timed wait.
struct Timed<T> {
    deadline: Deadline,
    /// The value of the last read that completed.
    last: Option<T>,
}

/// Whether a timed wait may start one more read: the first read always
/// starts, and no read starts after the bound. So a wait overruns its
/// bound by at most one read, and the schedule does not grow.
fn may_read(reads: usize, elapsed: Duration, bound: Duration) -> bool {
    reads == 0 || elapsed <= bound
}

/// The observation time of a read that satisfied its condition: the time
/// the read FINISHED, measured from the wait's start. For a "within"
/// bound this is the conservative end: a read that started before the
/// bound and finished after it is `Late`, so its evidence fails.
fn observed_at(start: Duration, read_finished: Duration) -> Duration {
    read_finished.saturating_sub(start)
}

/// How a timed wait ended: INFRA unless every read completed and
/// succeeded, else the classified observation time. A wait that stopped
/// with no observation must have passed its bound (`Never`).
fn settle(
    ended: Result<()>,
    seen: &Observations,
    what: &str,
    at: Option<Duration>,
    waited: Duration,
    bound: Duration,
) -> Result<Deadline> {
    match ended {
        Ok(()) if !seen.failed() => {
            ensure!(
                at.is_some() || waited > bound,
                "INFRA: {what}: the wait ended with no observation at {}, inside its {}s bound",
                ms_text(waited),
                bound.as_secs()
            );
        }
        // A failed read stopped the wait: `verify` names it.
        Ok(()) => seen.verify(what)?,
        Err(error) if expired(&error) => seen.verify(what)?,
        Err(error) => return Err(error),
    }
    Ok(classify(at, waited, bound))
}

/// The one timed wait of the case. It polls `read` (strict reads only)
/// until it reports the condition or the bound passes (`may_read`), or
/// for at most `cadence` in this call. The observation time is the time
/// the satisfying read finished (`observed_at`), measured from `start`,
/// and `classify` decides `Met` or `Late` from it. So evidence seen after
/// its bound fails. `bound + LATE_SLACK` is only a hard cap for a read
/// that hangs. A failed read, or a read still running at the cap, is
/// INFRA (`Observations`). At least one read is made.
async fn timed_wait<T>(
    sim: &Sim,
    what: &str,
    start: Duration,
    bound: Duration,
    cadence: Option<Duration>,
    mut read: impl AsyncFnMut(&Sim) -> Result<(bool, T)>,
) -> Result<Timed<T>> {
    let end = start.saturating_add(bound).saturating_add(LATE_SLACK);
    let mut budget = end.saturating_sub(sim.fabric().now());
    if let Some(cadence) = cadence {
        budget = budget.min(cadence);
    }
    let budget = budget.max(secs(1));
    let mut seen = Observations::default();
    let mut at = None;
    let mut last = None;
    let mut reads = 0usize;
    let ended = sim
        .until(what, budget, async |s: &Sim| {
            if !may_read(reads, s.fabric().now().saturating_sub(start), bound) {
                return true;
            }
            reads += 1;
            let Some((done, value)) = seen.observe(read(s)).await else {
                return true;
            };
            last = Some(value);
            if done {
                at = Some(observed_at(start, s.fabric().now()));
            }
            done
        })
        .await;
    let waited = sim.fabric().now().saturating_sub(start);
    let deadline = settle(ended, &seen, what, at, waited, bound)?;
    Ok(Timed { deadline, last })
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

/// `subject` re-announces (`POST /announce`); when `observer` then
/// verifies `subject`'s machine binding, measured from the end of the
/// announce call against `VERIFY_BOUND`. A failed read is INFRA, not "not
/// verified".
async fn announce_and_wait_verified(sim: &Sim, subject: &str, observer: &str) -> Result<Deadline> {
    announce(sim, subject, false).await?;
    let what = format!("{observer} verifies {subject}'s binding");
    let start = sim.fabric().now();
    let timed = timed_wait(sim, &what, start, VERIFY_BOUND, None, async |s: &Sim| {
        binding_verified(s, observer, subject)
            .await
            .map(|now| (now, ()))
    })
    .await?;
    Ok(timed.deadline)
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

/// When, after `start`, A's verdict for `label` becomes `Clean`, against
/// `bound`; this call polls for at most `cadence` (if set). The result
/// also gives A's last verdict for `label`. A failed read is INFRA.
async fn until_a_clean(
    sim: &Sim,
    gid: &str,
    label: &str,
    start: Duration,
    bound: Duration,
    cadence: Option<Duration>,
) -> Result<(
    Deadline,
    Option<crate::groups::owner_cert::MemberCertStatus>,
)> {
    use crate::groups::owner_cert::MemberCertStatus;
    let what = format!("A verifies {label}'s certificate");
    let timed = timed_wait(sim, &what, start, bound, cadence, async |s: &Sim| {
        let status = a_status_of(s, gid, label).await?;
        Ok((status == Some(MemberCertStatus::Clean), status))
    })
    .await?;
    Ok((timed.deadline, timed.last.flatten()))
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

/// The fields whose string value names a typed state of the object that
/// holds them.
const TAG_KEYS: &[&str] = &["state", "status", "cause", "type", "join_state", "wait"];
/// Subtrees that the typed-state parse does not read: error text is not
/// a typed state.
const SKIPPED_KEYS: &[&str] = &["error", "message"];

/// One digest decoded to its 32 bytes: 64 hex digits, or base64 (standard
/// or URL-safe, padded or not). `None` for any other text.
fn decode_digest(text: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    if text.len() == 64 {
        if let Some(bytes) = parse_digest(text) {
            return Some(bytes);
        }
    }
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| <[u8; 32]>::try_from(engine.decode(text).ok()?).ok())
}

/// The digests that one typed object names in its own `digest` and
/// `digests` fields. A typed object must name at least one digest, each
/// field must have its type (a string, an array of strings) and each
/// digest must decode. Any other typed object is an error, never "not
/// typed": a malformed typed state is INFRA, so it cannot count as
/// absence and keep the expected RED.
fn own_digests(object: &Object) -> Result<BTreeSet<[u8; 32]>> {
    let decode = |value: &serde_json::Value| -> Result<[u8; 32]> {
        let text = value
            .as_str()
            .with_context(|| format!("typed digest is not a string: {value}"))?;
        decode_digest(text).with_context(|| format!("typed digest does not decode: {text:?}"))
    };
    let mut digests = BTreeSet::new();
    if let Some(one) = object.get("digest") {
        digests.insert(decode(one)?);
    }
    if let Some(many) = object.get("digests") {
        let many = many
            .as_array()
            .with_context(|| format!("typed digests is not an array: {many}"))?;
        for digest in many {
            digests.insert(decode(digest)?);
        }
    }
    ensure!(
        !digests.is_empty(),
        "typed object names no digest: {object:?}"
    );
    Ok(digests)
}

/// The digest set of each typed `state` object in `body`. A typed object
/// has a tag field (`TAG_KEYS`) whose value is exactly `state`, or it is
/// the object value of a `state` key (externally tagged). Its digests are
/// its own `digest`/`digests` fields. Subtrees under `SKIPPED_KEYS` are
/// not read. A typed object with malformed digests is an error; a `state`
/// key whose value is not an object is an error too.
fn typed_digest_sets(body: &serde_json::Value, state: &str) -> Result<Vec<BTreeSet<[u8; 32]>>> {
    let mut found = Vec::new();
    let mut stack = vec![body];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Object(object) => {
                let tagged = TAG_KEYS
                    .iter()
                    .any(|key| object.get(*key).and_then(|tag| tag.as_str()) == Some(state));
                if tagged {
                    found.push(own_digests(object)?);
                }
                match object.get(state) {
                    None => {}
                    Some(serde_json::Value::Object(inner)) => found.push(own_digests(inner)?),
                    Some(other) => bail!("typed key {state} is not an object: {other}"),
                }
                stack.extend(
                    object
                        .iter()
                        .filter(|(key, _)| !SKIPPED_KEYS.contains(&key.as_str()))
                        .map(|(_, child)| child),
                );
            }
            serde_json::Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    Ok(found)
}

/// The missing digests as bytes. A digest that does not decode is an
/// error: the case read every digest from A's own seats.
fn digest_set(digests: &[String]) -> Result<BTreeSet<[u8; 32]>> {
    digests
        .iter()
        .map(|digest| parse_digest(digest).with_context(|| format!("bad seat digest {digest}")))
        .collect()
}

/// Whether the typed `state` objects in `body` together name exactly
/// `want` (the authority reports one object per missing digest). A
/// malformed typed object is an error.
fn shows_all(body: &serde_json::Value, state: &str, want: &BTreeSet<[u8; 32]>) -> Result<bool> {
    let sets = typed_digest_sets(body, state)?;
    Ok(!sets.is_empty() && sets.into_iter().flatten().collect::<BTreeSet<_>>() == *want)
}

/// Whether one typed `state` object in `body` names exactly `want` (the
/// joiner reports one wait naming every digest). A malformed typed object
/// is an error.
fn shows_one(body: &serde_json::Value, state: &str, want: &BTreeSet<[u8; 32]>) -> Result<bool> {
    Ok(typed_digest_sets(body, state)?
        .iter()
        .any(|set| set == want))
}

/// J's `join_state` on a 200 join-status body. The set is closed: any
/// other value is an error, never a verdict (ADR 0025).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JoinState {
    /// `main`: J's attempt waits for the authority.
    PendingAuthorityCommit,
    /// `main`: J has no pending attempt.
    Idle,
    /// S5: J's typed wait reported as the join state (ADR 0111 §8).
    AwaitingEvidence,
}

impl JoinState {
    fn parse(text: &str) -> Result<Self> {
        match text {
            JOIN_PENDING => Ok(Self::PendingAuthorityCommit),
            "idle" => Ok(Self::Idle),
            AWAITING_EVIDENCE => Ok(Self::AwaitingEvidence),
            other => bail!("unsupported join_state {other:?}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PendingAuthorityCommit => JOIN_PENDING,
            Self::Idle => "idle",
            Self::AwaitingEvidence => AWAITING_EVIDENCE,
        }
    }
}

/// The `outcome` of J's `last_join_outcome`. The set is closed: any other
/// value is an error. `main` records `refused` and `timed_out` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeKind {
    Refused,
    TimedOut,
    /// Not recorded on `main`. It ends the attempt and claims admission.
    Seated,
}

impl OutcomeKind {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "refused" => Ok(Self::Refused),
            "timed_out" => Ok(Self::TimedOut),
            "seated" => Ok(Self::Seated),
            other => bail!("unsupported last_join_outcome.outcome {other:?}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Seated => "seated",
        }
    }
}

/// J's `membership_state` on a 200 `/groups/{gid}` body
/// (`local_join_membership_state`). The set is closed: any other value
/// is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Membership {
    Active,
    Pending,
    PendingAuthorityCommit,
    NotMember,
}

impl Membership {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "active" => Ok(Self::Active),
            "pending" => Ok(Self::Pending),
            JOIN_PENDING => Ok(Self::PendingAuthorityCommit),
            "not_member" => Ok(Self::NotMember),
            other => bail!("unsupported membership_state {other:?}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::PendingAuthorityCommit => JOIN_PENDING,
            Self::NotMember => "not_member",
        }
    }
}

/// J's `last_join_outcome`.
#[derive(Debug)]
struct JoinOutcome {
    kind: OutcomeKind,
    /// Display only.
    reason: Option<String>,
}

impl JoinOutcome {
    fn text(&self) -> String {
        match &self.reason {
            Some(reason) => format!("{} ({reason})", self.kind.name()),
            None => self.kind.name().to_string(),
        }
    }
}

/// One parsed J join-status read.
#[derive(Debug)]
struct JoinStatus {
    /// `None` when join-status answered 404 (the local stub is gone).
    join_state: Option<JoinState>,
    outcome: Option<JoinOutcome>,
}

/// One read of the wait states of A and J during the holder gap.
struct Snapshot {
    /// A shows `evidence_pending` naming exactly the missing digests.
    a_typed: bool,
    /// J shows `awaiting_evidence` naming exactly the missing digests.
    j_typed: bool,
    a_lists_j: bool,
    j_active: bool,
    /// J's `join_state`; `None` when join-status answered 404.
    join_state: Option<JoinState>,
    /// J's join-status answered 404: the local stub is gone.
    stub_gone: bool,
    /// J's `last_join_outcome`.
    outcome: Option<JoinOutcome>,
    /// How many #946 terminal refusals A recorded for G.
    a_terminal: u64,
}

/// A JSON object body.
type Object = serde_json::Map<String, serde_json::Value>;

/// GET `path` at `label`: the status and the body, which must be a JSON
/// object. No barrier: callers run it inside one.
async fn get_object(sim: &Sim, label: &str, path: &str) -> Result<(StatusCode, Object)> {
    let (status, body) = sim.request(label, Method::GET, path, None).await?;
    match body {
        serde_json::Value::Object(object) => Ok((status, object)),
        other => bail!("{label} GET {path}: {status}: body is not an object: {other}"),
    }
}

/// POST `body` to `path` at `label`, in its own barrier (`Sim::api`): the
/// status and the answer, which must be a JSON object. A body that is not
/// JSON (`Sim::api` gives `Null`) is an error too.
async fn post_object(
    sim: &Sim,
    label: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, Object)> {
    let (status, answer) = sim.api(label, Method::POST, path, Some(body)).await?;
    match answer {
        serde_json::Value::Object(object) => Ok((status, object)),
        other => bail!("{label} POST {path}: {status}: body is not an object: {other}"),
    }
}

fn str_field<'a>(object: &'a Object, key: &str) -> Option<&'a str> {
    object.get(key).and_then(serde_json::Value::as_str)
}

/// Whether `body` has exactly the keys `keys`, and no other key.
fn has_exact_keys(body: &Object, keys: &[&str]) -> bool {
    body.len() == keys.len() && keys.iter().all(|key| body.contains_key(*key))
}

/// Whether `ok` is exactly the boolean `want`.
fn ok_is(body: &Object, want: bool) -> bool {
    body.get("ok") == Some(&serde_json::Value::Bool(want))
}

/// Whether `text` is 64 hex digits (a 32-byte id).
fn is_id_hex(text: &str) -> bool {
    text.len() == 64 && parse_digest(text).is_some()
}

/// The handler's 404 for an unknown group: `not_found("group not found")`
/// (`server/mod.rs:3600`, through `api_error` at `server/mod.rs:3572`),
/// that is, exactly `{"ok": false, "error": "group not found"}`.
/// `get_named_group` (`routes/named_groups.rs:16649`) and
/// `get_named_group_members` (`routes/named_groups.rs:16993`) send it.
fn is_group_not_found(body: &Object) -> bool {
    has_exact_keys(body, &["ok", "error"])
        && ok_is(body, false)
        && str_field(body, "error") == Some("group not found")
}

/// One row of `GET /groups/{gid}/members` (`named_group_member_values`,
/// `routes/named_groups.rs:2393`).
#[derive(Debug, PartialEq, Eq)]
struct RosterRow {
    /// Lowercase hex of the 32-byte agent id.
    agent_id: String,
    /// `GroupRole`, serde `snake_case`: a closed set.
    role: crate::groups::GroupRole,
    /// `GroupMemberState`, serde `snake_case`: a closed set.
    state: crate::groups::GroupMemberState,
}

/// One roster row: an object with a 64-hex `agent_id` and a `role` and
/// `state` from their closed serde sets. Extra keys are allowed (the
/// handler also sends `display_name`, `joined_at` and `added_by`).
fn parse_roster_row(row: &serde_json::Value) -> Result<RosterRow> {
    let row = row
        .as_object()
        .with_context(|| format!("roster row is not an object: {row}"))?;
    let agent_id =
        str_field(row, "agent_id").with_context(|| format!("row has no agent_id: {row:?}"))?;
    ensure!(
        is_id_hex(agent_id),
        "agent_id is not 64 hex digits: {agent_id:?}"
    );
    let closed = |key: &str| {
        row.get(key)
            .cloned()
            .with_context(|| format!("row has no {key}: {row:?}"))
    };
    let role = serde_json::from_value(closed("role")?)
        .with_context(|| format!("unsupported role: {row:?}"))?;
    let state = serde_json::from_value(closed("state")?)
        .with_context(|| format!("unsupported member state: {row:?}"))?;
    Ok(RosterRow {
        agent_id: agent_id.to_ascii_lowercase(),
        role,
        state,
    })
}

/// Parse `GET /groups/{gid}/members` (`get_named_group_members`,
/// `routes/named_groups.rs:16985`): only 200 with `ok: true`, the path's
/// `group_id`, a `members` array of valid rows and a `member_count` equal
/// to its length. Any other status (the 404 included: the case reads the
/// roster only where G exists), shape or value is an error.
fn parse_roster(gid: &str, status: StatusCode, body: &Object) -> Result<Vec<RosterRow>> {
    ensure!(
        status == StatusCode::OK && ok_is(body, true) && str_field(body, "group_id") == Some(gid),
        "{status} {body:?}"
    );
    let members = body
        .get("members")
        .and_then(serde_json::Value::as_array)
        .with_context(|| format!("no members array: {body:?}"))?;
    ensure!(
        body.get("member_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            == Some(members.len()),
        "member_count does not match the members array: {body:?}"
    );
    members.iter().map(parse_roster_row).collect()
}

/// Parse `POST /groups` (`create_named_group`,
/// `routes/named_groups.rs:16501`): 201 with `ok: true`, a 64-hex
/// `group_id` and the effective `policy` echoed as an object (the
/// ADR-0038 downgrade check). Extra keys are allowed (`name`,
/// `chat_topic`). The result is the group id.
fn parse_created(status: StatusCode, body: &Object) -> Result<String> {
    ensure!(
        status == StatusCode::CREATED && ok_is(body, true),
        "{status} {body:?}"
    );
    let gid = str_field(body, "group_id").with_context(|| format!("no group_id: {body:?}"))?;
    ensure!(is_id_hex(gid), "group_id is not 64 hex digits: {gid:?}");
    ensure!(
        body.get("policy").is_some_and(serde_json::Value::is_object),
        "no policy echo: {body:?}"
    );
    Ok(gid.to_string())
}

/// Parse `POST /groups/{gid}/invite` (`create_group_invite`,
/// `routes/named_groups.rs:19553`): 200 with `ok: true`, the `group_id`
/// and a non-empty `invite_link` string. Extra keys are allowed
/// (`group_name`, `expires_at`). The result is the link.
fn parse_invite(gid: &str, status: StatusCode, body: &Object) -> Result<String> {
    ensure!(
        status == StatusCode::OK && ok_is(body, true) && str_field(body, "group_id") == Some(gid),
        "{status} {body:?}"
    );
    let link = str_field(body, "invite_link")
        .filter(|link| !link.is_empty())
        .with_context(|| format!("no invite_link: {body:?}"))?;
    Ok(link.to_string())
}

/// Parse `POST /announce` (`announce_identity`,
/// `routes/identity.rs:306`): 200 with exactly `{"ok": true,
/// "include_user_identity": <the requested flag>}`. The object is small
/// and fixed, so no other key is allowed.
fn parse_announce(status: StatusCode, body: &Object, include_user_identity: bool) -> Result<()> {
    ensure!(
        status == StatusCode::OK
            && has_exact_keys(body, &["ok", "include_user_identity"])
            && ok_is(body, true)
            && body.get("include_user_identity")
                == Some(&serde_json::Value::Bool(include_user_identity)),
        "{status} {body:?}"
    );
    Ok(())
}

/// The statuses at which `join_group_via_invite` refuses with its
/// `api_error` body: 400 (`bad_request`), 403 (`forbidden`), 409
/// (`refuse_invite`, `join_already_pending`, a withdrawn group,
/// `JoinFailed`, fork-quarantined with a `reason`), 500 and 503.
const JOIN_REFUSAL_STATUSES: &[StatusCode] = &[
    StatusCode::BAD_REQUEST,
    StatusCode::FORBIDDEN,
    StatusCode::CONFLICT,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::SERVICE_UNAVAILABLE,
];

/// The answer of `POST /groups/join` (`join_group_via_invite`,
/// `routes/named_groups.rs:20381`). The set is closed: any other answer
/// is an error.
#[derive(Debug, PartialEq, Eq)]
enum JoinAnswer {
    /// 200 with `ok: true`, the `group_id` and a `join_state` from the
    /// closed membership set: a fresh join (`routes/named_groups.rs:21597`,
    /// no `already_joined`), a duplicate (`:20864`) or a re-arm
    /// (`:20368`), both with a boolean `already_joined`. Extra keys are
    /// allowed (`group_name`, `chat_topic`).
    Accepted {
        join_state: Membership,
        already_joined: Option<bool>,
    },
    /// At a status in `JOIN_REFUSAL_STATUSES`, exactly `{"ok": false,
    /// "error": <text>}` (`api_error`), or with a `reason` string as well
    /// (`api_error_with_reason`).
    Refused {
        status: StatusCode,
        error: String,
        reason: Option<String>,
    },
}

impl JoinAnswer {
    fn text(&self) -> String {
        match self {
            Self::Accepted {
                join_state,
                already_joined,
            } => format!(
                "accepted (join_state={}, already_joined={already_joined:?})",
                join_state.name()
            ),
            Self::Refused {
                status,
                error,
                reason,
            } => format!("refused ({status}: {error:?}, reason={reason:?})"),
        }
    }
}

/// Parse a `POST /groups/join` answer for `gid` into its closed set.
fn parse_join_answer(gid: &str, status: StatusCode, body: &Object) -> Result<JoinAnswer> {
    if status == StatusCode::OK {
        ensure!(
            ok_is(body, true) && str_field(body, "group_id") == Some(gid),
            "{status} {body:?}"
        );
        let join_state = Membership::parse(
            str_field(body, "join_state").with_context(|| format!("no join_state: {body:?}"))?,
        )?;
        let already_joined = match body.get("already_joined") {
            None => None,
            Some(serde_json::Value::Bool(joined)) => Some(*joined),
            Some(other) => bail!("already_joined is not a bool: {other}"),
        };
        return Ok(JoinAnswer::Accepted {
            join_state,
            already_joined,
        });
    }
    ensure!(JOIN_REFUSAL_STATUSES.contains(&status), "{status} {body:?}");
    let reason = match body.get("reason") {
        None => None,
        Some(serde_json::Value::String(reason)) => Some(reason.clone()),
        Some(other) => bail!("reason is not a string: {other}"),
    };
    let keys: &[&str] = if reason.is_some() {
        &["ok", "error", "reason"]
    } else {
        &["ok", "error"]
    };
    ensure!(
        has_exact_keys(body, keys) && ok_is(body, false),
        "{status} {body:?}"
    );
    let error = str_field(body, "error").with_context(|| format!("no error text: {body:?}"))?;
    Ok(JoinAnswer::Refused {
        status,
        error: error.to_string(),
        reason,
    })
}

/// The `last_join_outcome` of a join-status body: null, or an object
/// with a known `outcome`, a `reason` that is null or a string, and a
/// `finished_at_ms` that is a non-negative integer. The handler always
/// sends the key and the three fields (`join_status_body`,
/// `routes/named_groups.rs:16617`). A missing key or field, or any other
/// shape or value, is an error.
fn join_outcome(body: &Object) -> Result<Option<JoinOutcome>> {
    let last = match body.get("last_join_outcome") {
        Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Object(last)) => last,
        None => bail!("no last_join_outcome: {body:?}"),
        Some(other) => bail!("last_join_outcome is not an object: {other}"),
    };
    let outcome = str_field(last, "outcome")
        .with_context(|| format!("last_join_outcome has no outcome: {last:?}"))?;
    let kind = OutcomeKind::parse(outcome)?;
    let reason = match last.get("reason") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(reason)) => Some(reason.clone()),
        None => bail!("last_join_outcome has no reason: {last:?}"),
        Some(other) => bail!("reason is not a string: {other}"),
    };
    ensure!(
        last.get("finished_at_ms")
            .is_some_and(serde_json::Value::is_u64),
        "finished_at_ms is not a non-negative integer: {last:?}"
    );
    Ok(Some(JoinOutcome { kind, reason }))
}

/// Parse J's `/groups/{gid}/join-status` answer (`join_status_body`,
/// `routes/named_groups.rs:16566`). 200 needs a known `join_state`; extra
/// keys are allowed there, because S5 may add its typed wait. 404 needs
/// the handler's body with exactly the keys `error` (`group_not_found`)
/// and `last_join_outcome`. Both need a valid `last_join_outcome`. Any
/// other status, shape or value is an error.
fn parse_join_status(status: StatusCode, body: &Object) -> Result<JoinStatus> {
    let join_state = if status == StatusCode::OK {
        let text =
            str_field(body, "join_state").with_context(|| format!("no join_state: {body:?}"))?;
        Some(JoinState::parse(text)?)
    } else {
        ensure!(
            status == StatusCode::NOT_FOUND
                && has_exact_keys(body, &["error", "last_join_outcome"])
                && str_field(body, "error") == Some("group_not_found"),
            "{status} {body:?}"
        );
        None
    };
    Ok(JoinStatus {
        join_state,
        outcome: join_outcome(body)?,
    })
}

/// Parse a `/groups/{gid}` answer (`get_named_group`,
/// `routes/named_groups.rs:16638`): 200 with `ok: true`, `group_id` equal
/// to `gid` and a known `membership_state` (extra keys are allowed: the
/// full body has many, and S5 may add typed fields), or the handler's
/// exact 404 body (`is_group_not_found`, `None`). Any other status
/// (a 403 included), shape or value is an error, never "not active".
fn parse_membership(gid: &str, status: StatusCode, body: &Object) -> Result<Option<Membership>> {
    if status == StatusCode::OK {
        ensure!(
            ok_is(body, true) && str_field(body, "group_id") == Some(gid),
            "wrong group or no ok: {body:?}"
        );
        let text = str_field(body, "membership_state")
            .with_context(|| format!("no membership_state: {body:?}"))?;
        return Membership::parse(text).map(Some);
    }
    ensure!(
        status == StatusCode::NOT_FOUND && is_group_not_found(body),
        "{status} {body:?}"
    );
    Ok(None)
}

/// How many #946 terminal refusals (`TERMINAL_REASON`) A recorded for G,
/// from A's groups diagnostics (`record_invite_refusal`).
async fn a_terminal_refusals(sim: &Sim, gid: &str) -> Result<u64> {
    let a = sim.state("A")?;
    let gid = gid.to_string();
    sim.at_instant("read A's #946 terminal refusals for G", async move {
        let groups = a.named_groups.read().await;
        let (key, info) = crate::server::resolve_group_entry_locked(&groups, &gid)
            .context("A has no entry for G")?;
        let names = [
            key.to_string(),
            gid.clone(),
            info.stable_group_id().to_string(),
        ];
        let snapshot = a.groups_diagnostics.snapshot(
            &groups,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &std::collections::HashMap::new(),
            a.groups_config.mandate_grace_days,
        );
        let rows: Vec<_> = snapshot
            .groups
            .iter()
            .filter(|row| names.contains(&row.group_id))
            .collect();
        // The snapshot has one row per group: no row for G is an error,
        // not "no refusal".
        ensure!(!rows.is_empty(), "A's diagnostics have no row for G");
        // A reason with no count yet is zero refusals.
        Ok(rows
            .iter()
            .map(|row| {
                row.counters
                    .invites_refused_reasons
                    .get(TERMINAL_REASON)
                    .copied()
                    .unwrap_or(0)
            })
            .sum())
    })
    .await?
}

/// Read the group routes at A and J once. Each read must answer with its
/// route's status and body shape. J's two routes may answer 404 with the
/// handler's not-found body (J's stub is gone). Any other answer is an
/// error, so a broken read is INFRA, never "nothing shown".
async fn snapshot(sim: &Sim, gid: &str, want: &BTreeSet<[u8; 32]>) -> Result<Snapshot> {
    let j_hex = sim.agent_hex("J")?;
    let group_path = format!("/groups/{gid}");
    let status_path = format!("/groups/{gid}/join-status");
    let members_path = format!("/groups/{gid}/members");
    // A is the authority: its group read must be a 200 for G.
    let (status, a_group) = get_object(sim, "A", &group_path).await?;
    ensure!(
        status == StatusCode::OK
            && parse_membership(gid, status, &a_group)
                .with_context(|| format!("A GET {group_path}"))?
                .is_some(),
        "A GET {group_path}: {status} {a_group:?}"
    );
    let a_typed = shows_all(&serde_json::Value::Object(a_group), EVIDENCE_PENDING, want)
        .with_context(|| format!("A GET {group_path}: typed {EVIDENCE_PENDING}"))?;
    let (status, a_roster) = get_object(sim, "A", &members_path).await?;
    let a_lists_j =
        lists(gid, &j_hex, status, &a_roster).with_context(|| format!("A GET {members_path}"))?;
    let (status, j_group) = get_object(sim, "J", &group_path).await?;
    let j_membership =
        parse_membership(gid, status, &j_group).with_context(|| format!("J GET {group_path}"))?;
    let (status, join) = get_object(sim, "J", &status_path).await?;
    let JoinStatus {
        join_state,
        outcome,
    } = parse_join_status(status, &join).with_context(|| format!("J GET {status_path}"))?;
    let j_group = serde_json::Value::Object(j_group);
    let join = serde_json::Value::Object(join);
    // Both bodies are parsed, so a malformed typed object in either one is
    // INFRA.
    let j_group_typed = shows_one(&j_group, AWAITING_EVIDENCE, want)
        .with_context(|| format!("J GET {group_path}: typed {AWAITING_EVIDENCE}"))?;
    let j_status_typed = shows_one(&join, AWAITING_EVIDENCE, want)
        .with_context(|| format!("J GET {status_path}: typed {AWAITING_EVIDENCE}"))?;
    let j_typed = j_group_typed || j_status_typed;
    Ok(Snapshot {
        a_typed,
        j_typed,
        a_lists_j,
        j_active: j_membership == Some(Membership::Active),
        join_state,
        stub_gone: status == StatusCode::NOT_FOUND,
        outcome,
        a_terminal: a_terminal_refusals(sim, gid).await?,
    })
}

/// The typed wait states that one poll saw.
#[derive(Clone, Copy, Debug)]
struct PollRecord {
    /// When the poll's first read started, as time since J's join call.
    /// Every "after" rule and every lower bound uses this time.
    started: Duration,
    /// When the poll's last read finished, as time since J's join call.
    /// The reads may advance virtual time inside the poll's barrier.
    finished: Duration,
    /// A showed typed `evidence_pending` naming exactly the missing set.
    a_typed: bool,
    /// J showed typed `awaiting_evidence` naming exactly the missing set.
    j_typed: bool,
}

/// Whether a typed wait stayed visible.
#[derive(Debug, PartialEq, Eq)]
enum Visibility {
    /// Visible at each of `polls` polls, the first at `from`.
    Every { polls: usize, from: Duration },
    /// The wait never began, for this reason.
    NoStart(&'static str),
    /// No poll came after the start at `after`.
    NoPolls { after: Duration },
    /// Absent at the poll at `at`, after `seen` polls that showed it.
    AbsentAt { at: Duration, seen: usize },
}

impl Visibility {
    fn ok(&self) -> bool {
        matches!(self, Self::Every { .. })
    }

    fn text(&self) -> String {
        match self {
            Self::Every { polls, from } => format!(
                "visible at {polls} of {polls} polls from t2+{}s",
                from.as_secs()
            ),
            Self::NoStart(why) => why.to_string(),
            Self::NoPolls { after } => format!("no poll after t2+{}s", after.as_secs()),
            Self::AbsentAt { at, seen } => format!(
                "absent at t2+{}s, after {seen} polls that showed it",
                at.as_secs()
            ),
        }
    }
}

/// Whether `pick` holds at EVERY poll that STARTED strictly after
/// `after`. A poll that started before `after` does not count, even if it
/// finished after it. There must be at least one such poll.
fn continuous_from(
    polls: &[PollRecord],
    after: Duration,
    pick: impl Fn(&PollRecord) -> bool,
) -> Visibility {
    let checked: Vec<&PollRecord> = polls.iter().filter(|poll| poll.started > after).collect();
    let Some(first) = checked.first() else {
        return Visibility::NoPolls { after };
    };
    match checked.iter().enumerate().find(|(_, poll)| !pick(poll)) {
        Some((seen, poll)) => Visibility::AbsentAt {
            at: poll.started,
            seen,
        },
        None => Visibility::Every {
            polls: checked.len(),
            from: first.started,
        },
    }
}

/// ADR 0111 H3 for A: A shows typed `evidence_pending` at every poll after
/// its wait began (`a_wait_began`, A's first verified join message from
/// J, as time since J's join call) through the last gap poll.
fn a_typed_visibility(polls: &[PollRecord], a_wait_began: Option<Duration>) -> Visibility {
    match a_wait_began {
        None => Visibility::NoStart("A never received J's request"),
        Some(began) => continuous_from(polls, began, |poll| poll.a_typed),
    }
}

/// ADR 0111 H3 for J: J shows typed `awaiting_evidence` at every poll
/// after the first poll at which A showed its typed wait, through the
/// last gap poll.
fn j_typed_visibility(polls: &[PollRecord]) -> Visibility {
    match polls.iter().find(|poll| poll.a_typed) {
        None => Visibility::NoStart("A never showed its typed wait"),
        Some(first) => continuous_from(polls, first.started, |poll| poll.j_typed),
    }
}

/// Whether a span of polls reached `bound`: its last poll STARTED at or
/// after `bound` (a poll that started before it does not count, even if
/// it finished after it), and `now` (time since J's join call) is at or
/// after `bound` too. The minute-12 return and the never-return window
/// both use it.
fn span_reached(last_started: Option<Duration>, now: Duration, bound: Duration) -> bool {
    last_started.is_some_and(|last| last >= bound) && now >= bound
}

/// What the polls saw, as times since J's join call.
#[derive(Default)]
struct WaitWindow {
    /// Every poll, in order.
    records: Vec<PollRecord>,
    /// The first poll at which J's attempt had ended, and how.
    j_ended: Option<(Duration, String)>,
    /// The first poll at which A listed J, J was active, or J's outcome
    /// was `seated`.
    admitted: Option<(Duration, String)>,
    /// The first poll at which J showed neither a pending attempt nor a
    /// typed outcome.
    silent_drop: Option<(Duration, String)>,
    /// The first read at which A held any missing digest, and how many.
    /// The time is that read's own instant, since J's join call.
    a_held: Option<(Duration, usize)>,
    /// The first poll at which J showed a `refused` outcome or A had
    /// recorded the #946 terminal refusal for G, and what it showed.
    terminal_refusal: Option<(Duration, String)>,
    /// At the last poll, J's attempt was pending with no outcome.
    j_pending_now: bool,
    /// J's state at each change.
    timeline: Vec<(Duration, String)>,
}

impl WaitWindow {
    fn polls(&self) -> usize {
        self.records.len()
    }

    /// When the last poll started.
    fn last_poll(&self) -> Option<Duration> {
        self.records.last().map(|poll| poll.started)
    }

    /// The start of the first poll at which `pick` held.
    fn first(&self, pick: impl Fn(&PollRecord) -> bool) -> Option<Duration> {
        self.records
            .iter()
            .find(|poll| pick(poll))
            .map(|poll| poll.started)
    }

    /// Record one poll. The events below are named by the poll's start.
    fn record(&mut self, started: Duration, finished: Duration, snap: &Snapshot) {
        self.records.push(PollRecord {
            started,
            finished,
            a_typed: snap.a_typed,
            j_typed: snap.j_typed,
        });
        let since = started;
        let j_refused = snap
            .outcome
            .as_ref()
            .filter(|outcome| outcome.kind == OutcomeKind::Refused);
        if self.terminal_refusal.is_none() && (j_refused.is_some() || snap.a_terminal > 0) {
            self.terminal_refusal = Some((
                since,
                format!(
                    "J outcome: {}; A {TERMINAL_REASON} refusals for G: {}",
                    j_refused.map_or("none".to_string(), JoinOutcome::text),
                    snap.a_terminal
                ),
            ));
        }
        // A `seated` outcome claims admission, as an Active J does.
        let j_seated = snap
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.kind == OutcomeKind::Seated);
        if (snap.a_lists_j || snap.j_active || j_seated) && self.admitted.is_none() {
            self.admitted = Some((
                since,
                format!(
                    "A lists J: {}; J active: {}; J outcome seated: {j_seated}",
                    snap.a_lists_j, snap.j_active
                ),
            ));
        }
        // A correct S5 joiner may report its typed wait as the join state
        // itself (ADR 0111 §8), so that state also counts as pending.
        let pending = snap.j_typed
            || matches!(
                snap.join_state,
                Some(JoinState::PendingAuthorityCommit | JoinState::AwaitingEvidence)
            );
        self.j_pending_now = pending && snap.outcome.is_none();
        let outcome = snap.outcome.as_ref().map(JoinOutcome::text);
        let state = format!(
            "join_state={} outcome={}{}",
            match (snap.join_state, snap.stub_gone) {
                (Some(state), _) => state.name(),
                (None, true) => "stub gone (404)",
                (None, false) => "none",
            },
            outcome.as_deref().unwrap_or("none"),
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
        let want = digest_set(digests)?;
        let since = |sim: &Sim| sim.fabric().now().saturating_sub(joined_at);
        loop {
            let started = since(sim);
            let snap = sim
                .within(
                    &format!("read the wait states at t2+{}s", started.as_secs()),
                    secs(10),
                    snapshot(sim, gid, &want),
                )
                .await?
                .with_context(|| {
                    format!(
                        "INFRA: reading the wait states at t2+{}s",
                        started.as_secs()
                    )
                })?;
            let finished = since(sim);
            self.record(started, finished, &snap);
            let (_, held) = held_digests(sim, "A", gid, digests).await?;
            let held_at = since(sim);
            if !held.is_empty() && self.a_held.is_none() {
                self.a_held = Some((held_at, held.len()));
            }
            // The span ends with the first poll that STARTED at `until`.
            if started >= until {
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

    /// The last poll's span, for the receipt.
    fn last_span(&self) -> String {
        self.records.last().map_or("no poll".to_string(), |poll| {
            format!(
                "last poll t2+{}..{}",
                ms_text(poll.started),
                ms_text(poll.finished)
            )
        })
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
    // Post-conditions of the shared helpers, from in-process state.
    ensure!(
        owner_home
            .owner_user_id
            .eq_ignore_ascii_case(&hex::encode(owner.user_id().0)),
        "INFRA: O's Home owner {} is not the owner key",
        owner_home.owner_user_id
    );
    certified_by(sim, "O", &owner)?;
    for member in MEMBERS {
        sim.certify_owner_device("O", member, &owner, &owner_home)
            .await?;
        certified_by(sim, member, &owner)?;
    }
    let group = HomeIds {
        gid: create_owner_certified(sim, "O", &owner_home.owner_user_id).await?,
        owner_user_id: owner_home.owner_user_id.clone(),
    };
    for member in MEMBERS {
        let link = invite(sim, "O", &group.gid).await?;
        join(sim, member, &group, &link).await?;
        let start = sim.fabric().now();
        let seated = admitted(sim, "O", member, &group.gid, start, JOIN_BUDGET).await?;
        ensure!(
            component_passes(seated, JOIN_BUDGET),
            "setup: O could not seat {member}: {}",
            seated.text(JOIN_BUDGET)
        );
    }
    let answers = AnswerDrop::install(sim, &["A", "J"], MEMBERS)?;
    for device in ["A", "J"] {
        sim.certify_owner_device("O", device, &owner, &owner_home)
            .await?;
        certified_by(sim, device, &owner)?;
    }
    let link = invite(sim, "O", &group.gid).await?;
    join(sim, "A", &group, &link).await?;
    let start = sim.fabric().now();
    let seated = admitted(sim, "O", "A", &group.gid, start, JOIN_BUDGET).await?;
    ensure!(
        component_passes(seated, JOIN_BUDGET),
        "setup: O could not seat A: {}",
        seated.text(JOIN_BUDGET)
    );
    let mut observers = vec!["A"];
    observers.extend_from_slice(MEMBERS);
    sim.promote_admin("O", "A", &group, &observers).await?;
    // Post-condition of `promote_admin`: every observer's strict roster
    // lists A as an active admin.
    admin_everywhere(sim, &group.gid, "A", &observers).await?;
    let home = group;
    // SETTLE is a lower bound: the measured sleep must reach it.
    let settle_from = sim.fabric().now();
    sim.within(
        "A's seat settles",
        SETTLE + secs(1),
        tokio::time::sleep(SETTLE),
    )
    .await?;
    let settled = sim.fabric().now().saturating_sub(settle_from);
    ensure!(
        settled >= SETTLE,
        "INFRA: A's seat settled for {}, under {}s",
        ms_text(settled),
        SETTLE.as_secs()
    );
    // O announces with consent (the #1143 workaround): A's seat for O has
    // no certificate, so only O's consented announce gives A O's
    // certificate. Without it, every seal of J's add refuses naming O.
    // A fetches the certificate blob once per announce, and only the
    // next announce retries a failed fetch. The drop toward A can lose
    // that blob, so O repeats the announce every 10 s, as a heartbeat
    // would (run 39384499206). The 60 s total is measured on the fabric
    // clock from before the first announce.
    let mut announces = 0_u32;
    let o_start = sim.fabric().now();
    let (o_wait, o_status) = loop {
        announce(sim, "O", true).await?;
        announces += 1;
        let (deadline, last) = until_a_clean(
            sim,
            &home.gid,
            "O",
            o_start,
            O_ANNOUNCE_BOUND,
            Some(O_ANNOUNCE_EVERY),
        )
        .await?;
        // `Met` or `Late` ends the loop. So does the bound: no announce
        // or read starts after it (`may_read`).
        let elapsed = sim.fabric().now().saturating_sub(o_start);
        if !matches!(deadline, Deadline::Never { .. }) || elapsed > O_ANNOUNCE_BOUND {
            break (deadline, last);
        }
    };
    let o_clean = component_passes(o_wait, O_ANNOUNCE_BOUND);
    receipt.evidence(
        "a_verifies_creator_certificate_from_its_consented_announce",
        o_clean,
        format!(
            "after {announces} consented announces from O, A's verdict for O: {o_status:?} \
             ({})",
            o_wait.text(O_ANNOUNCE_BOUND)
        ),
        at(sim),
    );
    ensure!(
        o_clean,
        "INFRA: A did not verify O's certificate after O's consented announce \
         (verdict {o_status:?}, {})",
        o_wait.text(O_ANNOUNCE_BOUND)
    );
    let before = seat_view(sim, "A", &home.gid).await?;
    ensure!(
        before.admin,
        "INFRA: A is not an active admin of G after its promotion"
    );
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
                // A digest that does not decode is an error, not "not held".
                let bytes =
                    parse_digest(digest).with_context(|| format!("bad seat digest {digest}"))?;
                if j.agent
                    .announce_blob_cache
                    .find_by_cert_digest(&bytes)
                    .await
                    .is_some()
                {
                    held += 1;
                }
            }
            Ok::<_, anyhow::Error>(held)
        })
        .await??
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
    let j_binding = announce_and_wait_verified(sim, "J", "A").await?;
    let j_verified = component_passes(j_binding, VERIFY_BOUND);
    receipt.evidence(
        "a_verifies_j_binding_after_its_restart",
        j_verified,
        format!(
            "after J's re-announce, A verifies J's machine binding: {}",
            j_binding.text(VERIFY_BOUND)
        ),
        at(sim),
    );
    ensure!(
        j_verified,
        "INFRA: A did not verify J's machine binding after A's restart ({})",
        j_binding.text(VERIFY_BOUND)
    );
    // A's discovery cache is in memory, so A lost O's consented announce in
    // the restart. A must learn it again from an online node, or every
    // seal of J's add refuses naming O.
    let o_wait_from = sim.fabric().now();
    let (o_wait, o_status) =
        until_a_clean(sim, &home.gid, "O", o_wait_from, RESTART_CLEAN_BOUND, None).await?;
    let o_clean = component_passes(o_wait, RESTART_CLEAN_BOUND);
    receipt.evidence(
        "a_verifies_creator_certificate_after_its_restart",
        o_clean,
        format!(
            "A's verdict for O after its restart: {o_status:?} ({})",
            o_wait.text(RESTART_CLEAN_BOUND)
        ),
        at(sim),
    );
    ensure!(
        o_clean,
        "INFRA: A did not verify O's certificate after A's restart (verdict {o_status:?}, {})",
        o_wait.text(RESTART_CLEAN_BOUND)
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
            let (_, online_held) = holders
                .get(label)
                .cloned()
                .with_context(|| format!("no holder read for {label}"))?;
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
        let (active, held) = holders
            .get(label)
            .cloned()
            .with_context(|| format!("no holder read for {label}"))?;
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
    // The control's JOIN_BUDGET is measured from the end of J's join call.
    let j_admission = match arm {
        Arm::OneHolderOnline => {
            Some(admitted(sim, "A", "J", &home.gid, joined_at, JOIN_BUDGET).await?)
        }
        Arm::HolderReturns | Arm::HoldersNeverReturn => {
            // Every holder is offline: the wait must be typed and must not
            // end at J's 120 s poll deadline (ADR 0111 §8, D64).
            window
                .poll_until(sim, &home.gid, &missing, joined_at, HOLDER_GAP)
                .await?;
            None
        }
    };
    let j_admitted = j_admission.is_some_and(|deadline| component_passes(deadline, JOIN_BUDGET));
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
            if let Some(deadline) = j_admission {
                receipt.note(format!(
                    "J Active and listed by A after J's join call: {}",
                    deadline.text(JOIN_BUDGET)
                ));
            }
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
                // Strict diagnostic reads: a malformed answer is INFRA.
                let members_path = format!("/groups/{}/members", home.gid);
                let group_path = format!("/groups/{}", home.gid);
                let (status, body) = sim
                    .within(
                        "read A's roster",
                        secs(10),
                        get_object(sim, "A", &members_path),
                    )
                    .await??;
                let a_rows = parse_roster(&home.gid, status, &body)
                    .with_context(|| format!("A GET {members_path}"))?;
                let (status, body) = sim
                    .within(
                        "read J's membership",
                        secs(10),
                        get_object(sim, "J", &group_path),
                    )
                    .await??;
                let j_state = parse_membership(&home.gid, status, &body)
                    .with_context(|| format!("J GET {group_path}"))?;
                sim.fabric().mark(format!(
                    "observed: A lists {} members, J membership_state={}",
                    a_rows.len(),
                    j_state.map_or("none (404)", Membership::name)
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
                        window.polls(),
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
                    a_wait_began: first_request.map(|at| at.saturating_sub(joined_at)),
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
    /// When A's wait began: its first verified join message from J, as
    /// time since J's join call. `None` when A received none.
    a_wait_began: Option<Duration>,
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
    // ADR 0111 H3: the holder returns at minute 12, after the 10-minute
    // terminal refusal, and never before.
    // The last poll must have STARTED at or after the gap.
    let gap = sim.fabric().now().saturating_sub(ret.joined_at);
    ensure!(
        span_reached(window.last_poll(), gap, HOLDER_GAP),
        "INFRA: the holder would return at t2+{} (last poll started {}; {}), before the {}s gap",
        ms_text(gap),
        at_text(window.last_poll()),
        window.last_span(),
        HOLDER_GAP.as_secs()
    );
    // The last read before the return: A's #946 terminal refusals for G.
    let terminal_before_return = a_terminal_refusals(sim, ret.gid).await?;
    sim.set_online(ret.holder, true)?;
    sim.fabric()
        .mark(format!("holder {} returns after the gap", ret.holder));
    let returned_at = sim.fabric().now();
    a_dials(sim, ret.holder).await?;
    // H3 step 3: J retries. A pending attempt must resume by itself, so
    // the case re-POSTs only when J's attempt has ended. A typed refusal
    // of the re-POST is product behaviour, not INFRA; any answer outside
    // the closed set is INFRA (`parse_join_answer`).
    if window.j_pending_now {
        receipt.note("J's attempt is still pending after the gap: no new join call");
    } else {
        let (status, body) =
            post_object(sim, "J", "/groups/join", join_body("J", ret.home, ret.link)).await?;
        let answer = parse_join_answer(ret.gid, status, &body)
            .context("J POST /groups/join after the return")?;
        receipt.note(format!(
            "J's attempt had ended; J redeems the same invite again at t2+{}s: {}",
            since_join(sim),
            answer.text()
        ));
    }
    // ADR 0111 H3: within 60 s of the holder's start, A holds the bytes.
    // The time is that of the read that saw every byte (`timed_wait`), so
    // bytes seen after the bound fail the component.
    let a_holds = timed_wait(
        sim,
        "A holds every missing certificate",
        returned_at,
        RETURN_FETCH,
        None,
        async |s: &Sim| {
            let (_, held) = held_digests(s, "A", ret.gid, ret.missing).await?;
            Ok((held.len() == ret.missing.len(), held.len()))
        },
    )
    .await?;
    let a_holds_ok = component_passes(a_holds.deadline, RETURN_FETCH);
    // J has RETURN_ADMIT from the end of A's fetch wait.
    let admit_from = sim.fabric().now();
    let j_active = admitted(sim, "A", "J", ret.gid, admit_from, RETURN_ADMIT).await?;
    let j_active_ok = component_passes(j_active, RETURN_ADMIT);
    let ended_in_gap = window.j_ended.clone();
    // ADR 0111 H3: each typed wait stays visible at every poll, through
    // the last gap poll. Seen once is not enough.
    let a_visible = a_typed_visibility(&window.records, ret.a_wait_began);
    let j_visible = j_typed_visibility(&window.records);
    let parts = [
        (
            "a_typed_evidence_pending_every_poll",
            a_visible.ok(),
            a_visible.text(),
        ),
        (
            "j_typed_awaiting_evidence_every_poll",
            j_visible.ok(),
            j_visible.text(),
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
            "no_terminal_refusal_before_return",
            window.terminal_refusal.is_none() && terminal_before_return == 0,
            match &window.terminal_refusal {
                Some((since, how)) => format!("first at t2+{}s: {how}", since.as_secs()),
                None => format!(
                    "none in {} polls over {}s; A {TERMINAL_REASON} refusals for G at the \
                     return: {terminal_before_return}",
                    window.polls(),
                    HOLDER_GAP.as_secs()
                ),
            },
        ),
        (
            "a_holds_within_60s",
            a_holds_ok,
            format!(
                "A holds every missing digest after the holder's start: {} (last read: {} of {})",
                a_holds.deadline.text(RETURN_FETCH),
                a_holds
                    .last
                    .map_or("none".to_string(), |held| held.to_string()),
                ret.missing.len()
            ),
        ),
        (
            "j_admitted_after_return",
            j_active_ok,
            format!(
                "J Active and listed by A after A's fetch wait: {}",
                j_active.text(RETURN_ADMIT)
            ),
        ),
    ];
    for (name, ok, detail) in &parts {
        receipt.note(format!("final component {name}: {ok} ({detail})"));
    }
    receipt.note(format!("J's states during the gap: {}", window.timeline()));
    let passed = parts.iter().all(|(_, ok, _)| *ok);
    if !passed {
        // The cause on `main`: no poll showed either typed wait.
        let typed_absent = window.first(|poll| poll.a_typed || poll.j_typed).is_none();
        let summary = format!(
            "J's attempt end: {}; terminal refusal: {}; A held the bytes after the return: \
             {}; J active after the return: {}",
            match &ended_in_gap {
                Some((since, how)) => format!("t2+{}s ({how})", since.as_secs()),
                None => "none during the gap".to_string(),
            },
            match &window.terminal_refusal {
                Some((since, how)) => format!("t2+{}s ({how})", since.as_secs()),
                None => "none before the return".to_string(),
            },
            a_holds.deadline.text(RETURN_FETCH),
            j_active.text(RETURN_ADMIT),
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
    // The window is a lower bound: the last poll must have STARTED at or
    // after it (`span_reached`), as for the minute-12 return.
    let now = sim.fabric().now().saturating_sub(joined_at);
    ensure!(
        span_reached(window.last_poll(), now, NEVER_WINDOW),
        "INFRA: the never-return polls ended at {} ({}), before {}s",
        at_text(window.last_poll()),
        window.last_span(),
        NEVER_WINDOW.as_secs()
    );
    let (_, held) = held_digests(sim, "A", gid, missing).await?;
    receipt.note(format!(
        "{} polls over {}s; J admitted: {:?}; J silently dropped: {:?}; A first held \
         bytes: {:?}; A holds {} of {} missing digests at the end; A typed wait first at \
         {}; J typed wait first at {}; first terminal refusal (fail-closed, allowed): {:?}",
        window.polls(),
        NEVER_WINDOW.as_secs(),
        window.admitted,
        window.silent_drop,
        window.a_held,
        held.len(),
        missing.len(),
        at_text(window.first(|poll| poll.a_typed)),
        at_text(window.first(|poll| poll.j_typed)),
        window.terminal_refusal
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
         (/groups/{{gid}}, /members, #946 refusal counter) and J (/groups/{{gid}}, \
         /join-status) every {}s for {}s (the red test, ADR 0111 H3 minute 12, past \
         the {}s terminal refusal) or {}s (the never-return control). Every read must \
         answer with its route's status and body shape, and join_state, \
         last_join_outcome and membership_state must be known values, or the run is \
         INFRA. A typed wait is a parsed object tagged evidence_pending at A or \
         awaiting_evidence at J whose own digest/digests fields name exactly the \
         missing digests (ADR 0088 §1 L3, §2 item 8; ADR 0111 §8, H3). A's typed wait \
         must show at every poll after A's first verified join message from J, and \
         J's at every poll after A's first typed poll, through the last gap poll. The \
         holder returns after the gap in the red test only",
        arm.final_name(),
        POLL.as_secs(),
        HOLDER_GAP.as_secs(),
        TERMINAL_REFUSAL.as_secs(),
        NEVER_WINDOW.as_secs()
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

#[cfg(test)]
fn typed_fixture() -> (String, String, BTreeSet<[u8; 32]>) {
    let (one, two) = ([0x11_u8; 32], [0x22_u8; 32]);
    (
        hex::encode(one),
        hex::encode(two),
        BTreeSet::from([one, two]),
    )
}

#[test]
fn w3h_1023_typed_state_name_in_error_text_does_not_match() {
    let (one, two, want) = typed_fixture();
    let body = json!({
        "ok": false,
        "error": format!("evidence_pending for {one} and {two}"),
        "message": {"state": "evidence_pending", "digests": [one, two]},
    });
    assert!(!shows_all(&body, EVIDENCE_PENDING, &want).unwrap());
    assert!(!shows_one(&body, EVIDENCE_PENDING, &want).unwrap());
}

#[test]
fn w3h_1023_typed_digest_in_unrelated_field_does_not_match() {
    let (one, two, want) = typed_fixture();
    // No tagged object: the digests sit in roster rows. Not typed.
    let untagged = json!({
        "members": [{"agent_id": "aa", "certificate_digest": one, "digest_of": two}],
    });
    assert!(!shows_all(&untagged, EVIDENCE_PENDING, &want).unwrap());
    assert!(!shows_one(&untagged, AWAITING_EVIDENCE, &want).unwrap());
    // A tagged object whose own digest fields are malformed or absent is
    // INFRA, never "not typed": the digests elsewhere do not count.
    let body = json!({
        "status": "evidence_pending",
        "members": [{"agent_id": "aa", "certificate_digest": one, "digest_of": two}],
        "wait": {"state": "awaiting_evidence"},
        "digests": "not an array",
    });
    assert!(shows_all(&body, EVIDENCE_PENDING, &want).is_err());
    assert!(shows_one(&body, AWAITING_EVIDENCE, &want).is_err());
}

#[test]
fn w3h_1023_typed_tagged_node_with_exact_digests_matches() {
    use base64::Engine as _;
    let (one, two, want) = typed_fixture();
    let b64 = |hex_digest: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(parse_digest(hex_digest).unwrap_or_default())
    };
    // The authority: one object per digest, hex and base64.
    let authority = json!({
        "group_id": "g",
        "evidence": [
            {"state": "evidence_pending", "kind": "certificate", "digest": one},
            {"state": "evidence_pending", "kind": "certificate", "digest": b64(&two)},
        ],
    });
    assert!(shows_all(&authority, EVIDENCE_PENDING, &want).unwrap());
    // The joiner: one wait that names every digest.
    let joiner =
        json!({"join_state": "awaiting_evidence", "digests": [b64(&one), two], "since": 1});
    assert!(shows_one(&joiner, AWAITING_EVIDENCE, &want).unwrap());
}

#[test]
fn w3h_1023_typed_wrong_or_partial_digest_set_does_not_match() {
    let (one, two, want) = typed_fixture();
    let other = hex::encode([0x33_u8; 32]);
    let partial = json!({"state": "evidence_pending", "digest": one});
    assert!(!shows_all(&partial, EVIDENCE_PENDING, &want).unwrap());
    let extra = json!([
        {"state": "evidence_pending", "digest": one},
        {"state": "evidence_pending", "digest": two},
        {"state": "evidence_pending", "digest": other},
    ]);
    assert!(!shows_all(&extra, EVIDENCE_PENDING, &want).unwrap());
    let split = json!([
        {"join_state": "awaiting_evidence", "digests": [one]},
        {"join_state": "awaiting_evidence", "digests": [two]},
    ]);
    assert!(!shows_one(&split, AWAITING_EVIDENCE, &want).unwrap());
    let undecodable = json!({"state": "awaiting_evidence", "digests": [one, two, "zz"]});
    // An undecodable digest in a typed object is INFRA.
    assert!(shows_one(&undecodable, AWAITING_EVIDENCE, &want).is_err());
    let wrong_state = json!({"state": "evidence_pendingx", "digests": [one, two]});
    assert!(!shows_one(&wrong_state, EVIDENCE_PENDING, &want).unwrap());
}

#[test]
fn w3h_1023_typed_externally_tagged_form_matches() {
    let (one, two, want) = typed_fixture();
    let body = json!({
        "last_join_outcome": null,
        "attempt": {"awaiting_evidence": {"digests": [one, two], "since": 7}},
    });
    assert!(shows_one(&body, AWAITING_EVIDENCE, &want).unwrap());
    let authority = json!({"evidence_pending": {"digest": one}, "more": [{"evidence_pending": {"digest": two}}]});
    assert!(shows_all(&authority, EVIDENCE_PENDING, &want).unwrap());
}

/// Poll records every 5 s from t2+5s: `a` and `j` give the typed flags of
/// each poll.
#[cfg(test)]
fn polls(a: &[bool], j: &[bool]) -> Vec<PollRecord> {
    a.iter()
        .zip(j)
        .enumerate()
        .map(|(index, (&a_typed, &j_typed))| PollRecord {
            started: secs(5 * (index as u64 + 1)),
            finished: secs(5 * (index as u64 + 1)) + Duration::from_millis(300),
            a_typed,
            j_typed,
        })
        .collect()
}

#[test]
fn w3h_1023_cont_typed_at_every_poll_passes() {
    // A's wait begins at t2+2s; A shows its typed wait from the first poll
    // after that, J from the poll after A's first.
    let records = polls(&[true; 6], &[false, true, true, true, true, true]);
    assert_eq!(
        a_typed_visibility(&records, Some(secs(2))),
        Visibility::Every {
            polls: 6,
            from: secs(5)
        }
    );
    assert_eq!(
        j_typed_visibility(&records),
        Visibility::Every {
            polls: 5,
            from: secs(10)
        }
    );
}

#[test]
fn w3h_1023_disappearance_of_a_for_one_poll_fails() {
    let records = polls(
        &[true, true, false, true, true],
        &[false, true, true, true, true],
    );
    assert_eq!(
        a_typed_visibility(&records, Some(secs(2))),
        Visibility::AbsentAt {
            at: secs(15),
            seen: 2
        }
    );
    assert!(j_typed_visibility(&records).ok());
}

#[test]
fn w3h_1023_disappearance_of_j_for_one_poll_fails() {
    // J's join_state stays pending_authority_commit throughout; that does
    // not stand in for J's typed wait.
    let records = polls(&[true; 5], &[false, true, true, false, true]);
    assert!(a_typed_visibility(&records, Some(secs(2))).ok());
    assert_eq!(
        j_typed_visibility(&records),
        Visibility::AbsentAt {
            at: secs(20),
            seen: 2
        }
    );
}

#[test]
fn w3h_1023_reviewer_seen_once_then_gone_fails_both() {
    let records = polls(&[false, true, false, false], &[false, true, false, false]);
    assert_eq!(
        a_typed_visibility(&records, Some(secs(2))),
        Visibility::AbsentAt {
            at: secs(5),
            seen: 0
        }
    );
    // A first showed its wait at t2+10s; J is absent at the next poll.
    assert_eq!(
        j_typed_visibility(&records),
        Visibility::AbsentAt {
            at: secs(15),
            seen: 0
        }
    );
}

#[test]
fn w3h_1023_late_start_of_a_fails() {
    // A's wait began at t2+2s, but A shows it only from t2+15s.
    let records = polls(
        &[false, false, true, true, true],
        &[false, false, false, true, true],
    );
    assert_eq!(
        a_typed_visibility(&records, Some(secs(2))),
        Visibility::AbsentAt {
            at: secs(5),
            seen: 0
        }
    );
}

#[test]
fn w3h_1023_cont_no_start_or_no_polls_fails() {
    let records = polls(&[true; 3], &[true; 3]);
    assert!(matches!(
        a_typed_visibility(&records, None),
        Visibility::NoStart(_)
    ));
    assert_eq!(
        a_typed_visibility(&records, Some(secs(15))),
        Visibility::NoPolls { after: secs(15) }
    );
    // A never typed: J fails as well.
    let records = polls(&[false; 3], &[true; 3]);
    assert!(matches!(
        j_typed_visibility(&records),
        Visibility::NoStart(_)
    ));
    // A typed only at the last poll: no J poll is after it.
    let records = polls(&[false, false, true], &[true; 3]);
    assert_eq!(
        j_typed_visibility(&records),
        Visibility::NoPolls { after: secs(15) }
    );
}

#[cfg(test)]
fn object(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    match value {
        serde_json::Value::Object(object) => object,
        other => panic!("not an object: {other}"),
    }
}

#[test]
fn w3h_1023_closed_join_status_rejects_unknown_outcome() {
    let body = object(json!({
        "join_state": "idle",
        "last_join_outcome": {"outcome": "garbage", "reason": null, "finished_at_ms": 1},
    }));
    assert!(parse_join_status(StatusCode::OK, &body).is_err());
    let gone = object(json!({
        "error": "group_not_found",
        "last_join_outcome": {"outcome": "garbage", "reason": null, "finished_at_ms": 1},
    }));
    assert!(parse_join_status(StatusCode::NOT_FOUND, &gone).is_err());
}

#[test]
fn w3h_1023_closed_join_status_rejects_unknown_join_state() {
    let body = object(json!({"join_state": "weird", "last_join_outcome": null}));
    assert!(parse_join_status(StatusCode::OK, &body).is_err());
    let missing = object(json!({"last_join_outcome": null}));
    assert!(parse_join_status(StatusCode::OK, &missing).is_err());
}

#[test]
fn w3h_1023_closed_join_status_rejects_bad_finished_at_ms() {
    for finished in [json!("1"), json!(-1), json!(1.5), json!(null)] {
        let body = object(json!({
            "join_state": "idle",
            "last_join_outcome": {"outcome": "refused", "reason": null, "finished_at_ms": finished},
        }));
        assert!(
            parse_join_status(StatusCode::OK, &body).is_err(),
            "{body:?}"
        );
    }
    let missing = object(json!({
        "join_state": "idle",
        "last_join_outcome": {"outcome": "refused", "reason": null},
    }));
    assert!(parse_join_status(StatusCode::OK, &missing).is_err());
}

#[test]
fn w3h_1023_closed_join_status_parses_known_values() {
    for (text, state) in [
        (
            "pending_authority_commit",
            JoinState::PendingAuthorityCommit,
        ),
        ("idle", JoinState::Idle),
        ("awaiting_evidence", JoinState::AwaitingEvidence),
    ] {
        let body = object(json!({"join_state": text, "last_join_outcome": null}));
        let parsed = parse_join_status(StatusCode::OK, &body).unwrap();
        assert_eq!(parsed.join_state, Some(state));
        assert!(parsed.outcome.is_none());
    }
    for (text, kind) in [
        ("refused", OutcomeKind::Refused),
        ("timed_out", OutcomeKind::TimedOut),
        ("seated", OutcomeKind::Seated),
    ] {
        let body = object(json!({
            "error": "group_not_found",
            "last_join_outcome": {"outcome": text, "reason": TERMINAL_REASON, "finished_at_ms": 7},
        }));
        let parsed = parse_join_status(StatusCode::NOT_FOUND, &body).unwrap();
        assert_eq!(parsed.join_state, None);
        assert_eq!(parsed.outcome.map(|outcome| outcome.kind), Some(kind));
    }
    let teapot = object(json!({"join_state": "idle"}));
    assert!(parse_join_status(StatusCode::IM_A_TEAPOT, &teapot).is_err());
}

#[test]
fn w3h_1023_closed_membership_state() {
    for (text, state) in [
        ("active", Membership::Active),
        ("pending", Membership::Pending),
        (
            "pending_authority_commit",
            Membership::PendingAuthorityCommit,
        ),
        ("not_member", Membership::NotMember),
    ] {
        let body = object(json!({"ok": true, "group_id": "g", "membership_state": text}));
        assert_eq!(
            parse_membership("g", StatusCode::OK, &body).unwrap(),
            Some(state)
        );
    }
    let weird = object(json!({"ok": true, "group_id": "g", "membership_state": "weird"}));
    assert!(parse_membership("g", StatusCode::OK, &weird).is_err());
    let wrong = object(json!({"ok": true, "group_id": "h", "membership_state": "active"}));
    assert!(parse_membership("g", StatusCode::OK, &wrong).is_err());
    let gone = object(json!({"ok": false, "error": "group not found"}));
    assert_eq!(
        parse_membership("g", StatusCode::NOT_FOUND, &gone).unwrap(),
        None
    );
}

#[cfg(test)]
fn snap(join_state: Option<JoinState>, outcome: Option<OutcomeKind>) -> Snapshot {
    Snapshot {
        a_typed: false,
        j_typed: false,
        a_lists_j: false,
        j_active: false,
        join_state,
        stub_gone: join_state.is_none(),
        outcome: outcome.map(|kind| JoinOutcome { kind, reason: None }),
        a_terminal: 0,
    }
}

#[test]
fn w3h_1023_silent_drop_idle_with_no_outcome_fails_closed() {
    let mut window = WaitWindow::default();
    window.record(
        secs(5),
        secs(6),
        &snap(Some(JoinState::PendingAuthorityCommit), None),
    );
    assert!(window.silent_drop.is_none() && window.j_pending_now);
    window.record(secs(10), secs(11), &snap(Some(JoinState::Idle), None));
    assert_eq!(
        window.silent_drop.as_ref().map(|(at, _)| *at),
        Some(secs(10))
    );
    assert!(!window.j_pending_now);
    // A typed outcome is not a silent drop; a seated one is an admission.
    let mut window = WaitWindow::default();
    window.record(secs(5), secs(6), &snap(None, Some(OutcomeKind::TimedOut)));
    assert!(window.silent_drop.is_none() && window.admitted.is_none());
    window.record(secs(10), secs(11), &snap(None, Some(OutcomeKind::Seated)));
    assert_eq!(window.admitted.as_ref().map(|(at, _)| *at), Some(secs(10)));
    assert_eq!(window.polls(), 2);
}

/// The late-arrival controls of one "within" bound, through the same pure
/// functions that `timed_wait` and every bounded component use.
#[cfg(test)]
fn assert_within_bound(bound: Duration) {
    let ms = Duration::from_millis;
    let start = secs(1000);
    let decide = |read_finished: Duration| {
        let at = observed_at(start, read_finished);
        component_passes(classify(Some(at), at, bound), bound)
    };
    // Exactly at and just under the bound: PASS.
    assert!(decide(start + bound), "{bound:?}: at the bound");
    assert!(decide(start + bound - ms(1)), "{bound:?}: just under");
    // Just past the bound: FAIL.
    assert!(!decide(start + bound + ms(1)), "{bound:?}: just past");
    assert!(!decide(start + bound + LATE_SLACK), "{bound:?}: at the cap");
    // A read that started inside the bound but finished after it: the
    // finish time counts, so the evidence is late and FAILS.
    let read_started = start + bound - ms(500);
    assert!(may_read(1, read_started - start, bound));
    assert!(
        !decide(start + bound + ms(500)),
        "{bound:?}: straddling read"
    );
    assert_eq!(
        classify(
            Some(observed_at(start, start + bound + ms(500))),
            bound,
            bound
        ),
        Deadline::Late {
            at: bound + ms(500)
        }
    );
    // No read starts after the bound; the first read always starts.
    assert!(may_read(3, bound, bound));
    assert!(!may_read(3, bound + ms(1), bound));
    assert!(may_read(0, bound + secs(100), bound));
    // Not seen: FAIL. A `Met` past the bound never passes either.
    assert!(!component_passes(
        classify(None, bound + ms(1), bound),
        bound
    ));
    assert!(!component_passes(
        Deadline::Met { at: bound + ms(1) },
        bound
    ));
}

#[test]
fn w3h_1023_deadline_a_holds_within_60s_late_arrival_fails() {
    assert_eq!(RETURN_FETCH, secs(60));
    assert_within_bound(RETURN_FETCH);
}

#[test]
fn w3h_1023_deadline_j_active_late_arrival_fails() {
    // After the return (RETURN_ADMIT) and in the control (JOIN_BUDGET).
    assert_within_bound(RETURN_ADMIT);
    assert_within_bound(JOIN_BUDGET);
}

#[test]
fn w3h_1023_deadline_setup_bounds_late_arrival_fails() {
    for bound in [O_ANNOUNCE_BOUND, VERIFY_BOUND, RESTART_CLEAN_BOUND] {
        assert_within_bound(bound);
    }
}

#[test]
fn w3h_1023_settle_needs_an_observation_or_a_passed_bound() {
    let seen = Observations::default();
    let bound = RETURN_FETCH;
    // The wait stopped inside its bound with no observation: INFRA.
    assert!(settle(Ok(()), &seen, "w", None, bound, bound).is_err());
    // It stopped because the bound passed: `Never`, a failed component.
    let never = settle(Ok(()), &seen, "w", None, bound + secs(1), bound).unwrap();
    assert_eq!(
        never,
        Deadline::Never {
            waited: bound + secs(1)
        }
    );
    assert!(!component_passes(never, bound));
    // A late observation settles as `Late` and fails.
    let late = settle(
        Ok(()),
        &seen,
        "w",
        Some(bound + secs(1)),
        bound + secs(1),
        bound,
    )
    .unwrap();
    assert!(!component_passes(late, bound));
    // Any error that is not the budget is passed on.
    assert!(settle(
        Err(anyhow!("boom")),
        &seen,
        "w",
        Some(secs(1)),
        secs(1),
        bound
    )
    .is_err());
}

#[test]
fn w3h_1023_span_lower_bounds_use_the_poll_start() {
    let ms = Duration::from_millis;
    for bound in [HOLDER_GAP, NEVER_WINDOW] {
        // The last poll started before the bound and finished after it:
        // not reached.
        assert!(!span_reached(Some(bound - ms(1)), bound + secs(5), bound));
        assert!(span_reached(Some(bound), bound, bound));
        assert!(span_reached(Some(bound + ms(1)), bound + secs(1), bound));
        assert!(!span_reached(Some(bound), bound - ms(1), bound));
        assert!(!span_reached(None, bound + secs(1), bound));
    }
    // A poll fixture: the poll that straddles 720 s does not reach it.
    let mut window = WaitWindow::default();
    let pending = snap(Some(JoinState::PendingAuthorityCommit), None);
    window.record(HOLDER_GAP - ms(200), HOLDER_GAP + secs(2), &pending);
    assert!(!span_reached(
        window.last_poll(),
        HOLDER_GAP + secs(3),
        HOLDER_GAP
    ));
    window.record(HOLDER_GAP + secs(5), HOLDER_GAP + secs(6), &pending);
    assert!(span_reached(
        window.last_poll(),
        HOLDER_GAP + secs(6),
        HOLDER_GAP
    ));
}

#[test]
fn w3h_1023_admitted_membership_parse_rejects_malformed() {
    let gid = "g";
    // The well-formed answers.
    let active = object(json!({"ok": true, "group_id": gid, "membership_state": "active"}));
    assert!(is_active(gid, StatusCode::OK, &active).unwrap());
    let pending = object(json!({"ok": true, "group_id": gid, "membership_state": "pending"}));
    assert!(!is_active(gid, StatusCode::OK, &pending).unwrap());
    // The handler's exact 404 is "no group here", so not a member.
    let not_found = object(json!({"ok": false, "error": "group not found"}));
    assert!(!is_active(gid, StatusCode::NOT_FOUND, &not_found).unwrap());
    assert_eq!(
        parse_membership(gid, StatusCode::NOT_FOUND, &not_found).unwrap(),
        None
    );
    // Every malformed answer is an error (INFRA), never `Ok(false)`.
    let malformed: Vec<(&str, StatusCode, serde_json::Value)> = vec![
        (
            "missing membership_state",
            StatusCode::OK,
            json!({"ok": true, "group_id": gid}),
        ),
        (
            "non-string membership_state",
            StatusCode::OK,
            json!({"ok": true, "group_id": gid, "membership_state": 1}),
        ),
        (
            "null membership_state",
            StatusCode::OK,
            json!({"ok": true, "group_id": gid, "membership_state": null}),
        ),
        (
            "unknown membership_state",
            StatusCode::OK,
            json!({"ok": true, "group_id": gid, "membership_state": "activated"}),
        ),
        (
            "wrong group_id",
            StatusCode::OK,
            json!({"ok": true, "group_id": "h", "membership_state": "active"}),
        ),
        (
            "no group_id",
            StatusCode::OK,
            json!({"ok": true, "membership_state": "active"}),
        ),
        (
            "ok false on 200",
            StatusCode::OK,
            json!({"ok": false, "group_id": gid, "membership_state": "active"}),
        ),
        (
            "404 with an arbitrary body",
            StatusCode::NOT_FOUND,
            json!({"error": "not here"}),
        ),
        (
            "404 with an extra key",
            StatusCode::NOT_FOUND,
            json!({"ok": false, "error": "group not found", "hint": "x"}),
        ),
        (
            "404 with other error text",
            StatusCode::NOT_FOUND,
            json!({"ok": false, "error": "route not found"}),
        ),
        (
            "500",
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok": false, "error": "group not found"}),
        ),
        (
            "403",
            StatusCode::FORBIDDEN,
            json!({"ok": false, "error": "forbidden"}),
        ),
    ];
    for (name, status, body) in malformed {
        let body = object(body);
        assert!(is_active(gid, status, &body).is_err(), "{name}");
        assert!(parse_membership(gid, status, &body).is_err(), "{name}");
    }
    // The roster half of `read_admitted`: a 404 or a wrong group is an
    // error, never "not listed".
    let member = hex::encode([0xaa_u8; 32]);
    let roster = |status, body| lists(gid, &member, status, &object(body));
    let row = json!({"agent_id": member, "role": "member", "state": "active"});
    assert!(roster(
        StatusCode::OK,
        json!({"ok": true, "group_id": gid, "members": [row], "member_count": 1})
    )
    .unwrap());
    assert!(!roster(
        StatusCode::OK,
        json!({"ok": true, "group_id": gid, "members": [], "member_count": 0})
    )
    .unwrap());
    assert!(roster(
        StatusCode::NOT_FOUND,
        json!({"ok": false, "error": "group not found"})
    )
    .is_err());
    assert!(roster(
        StatusCode::OK,
        json!({"ok": true, "group_id": "h", "members": [], "member_count": 0})
    )
    .is_err());
    assert!(roster(
        StatusCode::OK,
        json!({"ok": true, "group_id": gid, "members": [{"agent_id": member, "role": "boss", "state": "active"}], "member_count": 1})
    )
    .is_err());
    assert!(roster(
        StatusCode::OK,
        json!({"ok": true, "group_id": gid, "members": [], "member_count": 2})
    )
    .is_err());
}

#[test]
fn w3h_1023_join_answer_closed_set() {
    let gid = "g";
    let accepted =
        object(json!({"ok": true, "group_id": gid, "join_state": "pending_authority_commit"}));
    assert_eq!(
        parse_join_answer(gid, StatusCode::OK, &accepted).unwrap(),
        JoinAnswer::Accepted {
            join_state: Membership::PendingAuthorityCommit,
            already_joined: None
        }
    );
    let refused = object(json!({"ok": false, "error": "no"}));
    assert!(matches!(
        parse_join_answer(gid, StatusCode::CONFLICT, &refused).unwrap(),
        JoinAnswer::Refused { .. }
    ));
    for (status, body) in [
        (
            StatusCode::OK,
            json!({"ok": true, "group_id": "h", "join_state": "active"}),
        ),
        (
            StatusCode::OK,
            json!({"ok": true, "group_id": gid, "join_state": "weird"}),
        ),
        (StatusCode::OK, json!({"ok": true, "group_id": gid})),
        (StatusCode::NOT_FOUND, json!({"ok": false, "error": "no"})),
        (
            StatusCode::CONFLICT,
            json!({"ok": false, "error": "no", "extra": 1}),
        ),
        (StatusCode::CONFLICT, json!({"ok": false, "error": 7})),
    ] {
        let body = object(body);
        assert!(
            parse_join_answer(gid, status, &body).is_err(),
            "{status} {body:?}"
        );
    }
}
