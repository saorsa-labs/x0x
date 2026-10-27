//! W3-H cases for #1357, ADR 0110 §4a (`CertificateRebindV1`) and §4b(1)
//! (`OwnerRecoveryV1`): the Validation rows `s4_certificate_rebind` and
//! `s4_owner_recovery`. These cases came after the S4 code merged, so no
//! run on `main` was recorded. Each arm expects GREEN (the ADR
//! behaviour); a failure whose observation matches the ADR's "red on
//! main" line is RED, any other failure is INFRA.
//!
//! Every arm uses a Home (`OwnerCertified`, TreeKEM) that A provisions
//! with a fresh owner key U, as in the parent case. In a W3-H Home every
//! device holds U (the live fixture's same-owner devices), so any device
//! can sign as the owner. Everything is driven through the public HTTP
//! API: `POST /owner/agents/issue` (with `not_after`) for the first
//! certificate and for each renewal,
//! `POST /groups/:id/members/:agent_id/certificate/rebind`,
//! `POST /identity/revoke`, `POST /owner/groups/:id/recovery-mandate`,
//! `GET /groups/:id` (S4 status) and the secure encrypt/decrypt routes.
//! Roster, epoch and commit-log reads use the daemon state, as the parent
//! case does.
//!
//! `s4_certificate_rebind` (nodes A, B, C; A is the Home owner and only
//! admin; B is the seat whose certificate expires):
//!
//! - `w3h_1357_s4_certificate_rebind_pre_cutoff`, runs (1) and (4). B's
//!   first certificate has `not_after` = issue time + [`LONG_NOT_AFTER`].
//!   At t = 0, U issues B's renewal and B self-rebinds through the route.
//!   Desired (1): every node keeps B's seat, role, leaf and TreeKEM epoch,
//!   only B's committed digest changes (to the renewal's), the head commit
//!   is B's own, no S4 row for B stays open, and B and C still decrypt A's
//!   new traffic. Then (4): B tries to rebind a certificate that expires
//!   before the one now committed; the route refuses with
//!   `rebind_not_later` and nothing changes. This arm does not depend on
//!   the wall clock moving, so it also runs without the shim.
//! - `w3h_1357_s4_certificate_rebind_post_cutoff`, run (6) with A
//!   reachable. B's first certificate has `not_after` N = issue time +
//!   [`LATE_NOT_AFTER`]. At B's clock N − τ/2 (after the cutoff N − τ),
//!   U issues the renewal and B calls the route. Desired: the route
//!   refuses with `rebind_window_closed`, hands the renewal to A and
//!   shows `waiting_for_admin_rebind` naming A; A holds the verified
//!   renewal; no node changes B's digest before raw N; then the designated
//!   admin A commits the rebind (not `MemberRemoved`) at its expiry commit
//!   point, after raw N, within the completion bound from A's own trigger
//!   N + τ; B keeps its seat, role, leaf and epoch; B's wait ends; no S4
//!   row for B stays open (an expiry-only row ends `terminated` with
//!   `certificate_valid`, and retention drops terminated rows in the same
//!   pass, so the public status shows no row; any row seen is recorded);
//!   B and C still decrypt. The cutoff and the expiry follow the daemons'
//!   wall clock, so this arm needs the shim (wall clock = base + virtual
//!   time). It runs about 800 virtual seconds (τ = 300 s fixes the span
//!   from the cutoff to A's trigger). It is `#[ignore]`d outside the shim,
//!   and the 20-rerun W3-H gate runs it (`--run-ignored all`) and requires
//!   GREEN in every rerun, as for the other `s4_` arms.
//!
//! Not in this case yet (ADR rows (2), (3), (5), (7)–(10) and the
//! D-fallback form of (6)): (2) needs B offline with the renewal reaching
//! A only by announce; (3) needs a released 0.46.1 member whose advert
//! lacks `certificate_rebind_v1` (W3-H runs one build); (5) needs a second
//! user key's certificate over a Home device; (7) is close to the parent
//! case's revocation arms, but it needs the revoked agent's own route
//! after its revocation is held; (8) and (9) need every admin certificate
//! to expire, so the owner device needs an expiring certificate, and
//! [`Sim::start_owner_device`] issues a non-expiring one; (10) needs a
//! fault rule that holds one commit frame for 600 s + W; (6) with A
//! offline until N + W needs a second admin D and about 2 × 600 virtual
//! seconds.
//!
//! `s4_owner_recovery` (Home; A is the owner device and the only admin):
//!
//! - `w3h_1357_s4_owner_recovery` (nodes A, B, C). Before t = 0, C (an
//!   owner device) asks for a mandate while A is an eligible admin; the
//!   route refuses with `recovery_not_needed`. At t = 0 A revokes its own
//!   agent (`POST /identity/revoke`); B and C must hold the record.
//!   Desired: B and C show `admin_availability` =
//!   `waiting_for_eligible_admin_revocation` with exit `owner_recovery`,
//!   naming A, and their secure encrypt (send) is refused with it; then
//!   C signs a mandate naming B (`202 waiting_for_recovery_member`); B
//!   commits `OwnerRecoveryV1`: on B and C, A is `Removed` with its leaf
//!   excluded (one epoch step, `n − 1` leaves), B is an Admin and the head
//!   commit is B's; `admin_availability` clears; B's new ciphertext opens
//!   on C and not on A.
//!
//! Not in this case yet: the ADR's form of `recovery_not_needed` (A
//! revoked while a second admin D stays eligible; the arm above checks the
//! refusal with A itself eligible, before t = 0); the `SignedPublic` and non-Home `OwnerCertified`
//! variants (the harness has no non-Home owner-certified group setup);
//! a mandate naming a revoked or expired member, an older head, a
//! non-owner signer or a replay (each needs a mandate built outside the
//! route, which always signs the current head with the local U); B
//! offline until t = 10 s; a 0.46.1 member L; O silent for 24 virtual
//! hours; and the joiner J's `JoinPendingNotice`.

use super::*;
use crate::groups::cert_rebind as cr;
use crate::groups::eviction::EXPIRY_TOLERANCE_SECS as TAU;
use crate::identity::{AgentCertificate, AgentId};

/// Run (1)/(4): B's first certificate expires this long after issue, so
/// the self-rebind window stays open for the whole arm.
const LONG_NOT_AFTER: u64 = 3600;
/// Run (6): B's first certificate expires this long after issue. Its
/// cutoff `N − τ` is 300 s after issue, so setup ends with the window
/// still open; the case then waits to `N − τ/2` (450 s after issue).
const LATE_NOT_AFTER: u64 = 600;
/// A renewal expires this much later than B's first certificate.
const RENEWAL_EXTRA: u64 = 3600;
/// After a refused rebind, the case waits this long and checks that
/// nothing changed.
const QUIET: Duration = Duration::from_secs(5);
/// Budget for the promoted member's recovery commit to reach the
/// survivors after the mandate.
const RECOVERY: Duration = Duration::from_secs(120);

/// Public typed states the case matches on.
const RECEIVER_UPGRADE: &str = "waiting_for_receiver_upgrade";
const ADMIN_REBIND: &str = "waiting_for_admin_rebind";
const ELIGIBLE_ADMIN_REVOCATION: &str = "waiting_for_eligible_admin_revocation";

const FINAL_REBIND_PRE: &str =
    "pre_cutoff_self_rebind_changes_only_the_digest_and_an_older_certificate_is_refused";
const FINAL_REBIND_POST: &str =
    "post_cutoff_rebind_is_handed_to_the_designated_admin_who_rebinds_after_raw_not_after";
const FINAL_RECOVERY: &str = "owner_mandate_promotes_b_and_b_excludes_the_revoked_admin_once";

const CAUSE_NO_REBIND: &str = "no rebinding commit: every node still binds B's first certificate \
                               digest (the ADR's red-on-main observation)";
const CAUSE_REBIND_EVICTED: &str = "B's seat was removed at expiry instead of rebound: a survivor \
                                    lists B as not Active";
const CAUSE_NO_RECOVERY: &str = "no owner-recovery exit: A stays seated at e0 on B and C and B is \
                                 not an Admin (the ADR's red-on-main observation)";

/// Which `s4_certificate_rebind` runs an arm does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebindRun {
    /// Runs (1) and (4).
    PreCutoff,
    /// Run (6), designated admin reachable.
    PostCutoff,
}

impl RebindRun {
    fn not_after_offset(self) -> u64 {
        match self {
            Self::PreCutoff => LONG_NOT_AFTER,
            Self::PostCutoff => LATE_NOT_AFTER,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::PreCutoff => FINAL_REBIND_PRE,
            Self::PostCutoff => FINAL_REBIND_POST,
        }
    }
}

/// Which `s4_owner_recovery` form an arm runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryArm {
    /// A is the only admin; A is revoked; the mandate promotes B.
    SoleAdminRevoked,
}

impl RecoveryArm {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::SoleAdminRevoked => THREE,
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::SoleAdminRevoked => FINAL_RECOVERY,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Arm2 {
    Rebind(RebindRun),
    Recovery(RecoveryArm),
}

impl Arm2 {
    fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Rebind(_) => THREE,
            Self::Recovery(arm) => arm.labels(),
        }
    }

    fn final_name(self) -> &'static str {
        match self {
            Self::Rebind(run) => run.final_name(),
            Self::Recovery(arm) => arm.final_name(),
        }
    }
}

// ─── Reads ──────────────────────────────────────────────────────────────────

/// One node's view of a seat: the parent case's [`View`] (with `lists_b`,
/// `b_state` and `tracks_b` about `target`), plus the seat's role and
/// committed certificate, and the head commit's time.
#[derive(Clone, Debug)]
struct Seat {
    view: View,
    role: Option<String>,
    digest: Option<String>,
    not_after: Option<u64>,
    /// `committed_at` of the commit at `state_revision`, in Unix ms.
    head_committed_at_ms: Option<u64>,
}

impl Seat {
    fn describe(&self) -> String {
        format!(
            "{} role={:?} digest={:?} not_after={:?} head_committed_at_ms={:?}",
            self.view.describe(),
            self.role,
            self.digest,
            self.not_after,
            self.head_committed_at_ms
        )
    }

    fn active(&self) -> bool {
        self.view.b_state.as_deref() == Some("Active")
    }
}

type Seats = Vec<(&'static str, Option<Seat>)>;

async fn try_seat_now(
    sim: &Sim,
    label: &str,
    group: &str,
    target: &AgentId,
) -> Result<Option<Seat>> {
    let Some(view) = try_view_now(sim, label, group, target).await? else {
        return Ok(None);
    };
    let target_hex = hex::encode(target.as_bytes());
    let state = sim.state(label)?;
    let groups = state.named_groups.read().await;
    let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, group) else {
        return Ok(None);
    };
    let member = info
        .members_v2
        .values()
        .find(|member| member.agent_id.eq_ignore_ascii_case(&target_hex));
    Ok(Some(Seat {
        view,
        role: member.map(|member| format!("{:?}", member.role)),
        digest: member.and_then(cr::committed_digest),
        not_after: member
            .and_then(cr::committed_certificate)
            .and_then(AgentCertificate::not_after),
        head_committed_at_ms: info
            .commit_log
            .iter()
            .rev()
            .find(|retained| retained.commit.revision == info.state_revision)
            .map(|retained| retained.commit.committed_at),
    }))
}

async fn seats_now(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    target: &AgentId,
) -> Result<Seats> {
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        out.push((*label, try_seat_now(sim, label, group, target).await?));
    }
    Ok(out)
}

async fn seats(sim: &Sim, labels: &[&'static str], group: &str, target: &AgentId) -> Result<Seats> {
    sim.at_instant("read the seats", seats_now(sim, labels, group, target))
        .await?
}

fn describe_seats(seats: &Seats) -> String {
    seats
        .iter()
        .map(|(label, seat)| {
            format!(
                "{label}: {}",
                seat.as_ref()
                    .map_or_else(|| "no record".to_string(), Seat::describe)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Every node binds `digest` to the seat.
fn all_bind(seats: &Seats, digest: &str) -> bool {
    !seats.is_empty()
        && seats.iter().all(|(_, seat)| {
            seat.as_ref()
                .is_some_and(|seat| seat.digest.as_deref() == Some(digest))
        })
}

/// Run (1)'s and (6)'s structural outcome: on every node the seat is still
/// Active with its base role and leaf tracking, the epoch and leaf count
/// are unchanged, no fork quarantine, and the committed digest is
/// `digest`.
fn rebound_in_place(after: &Seats, base: &Seats, digest: &str, e0: u64, leaves0: u32) -> bool {
    after.len() == base.len()
        && after
            .iter()
            .zip(base)
            .all(|((label, now), (base_label, was))| {
                let (Some(now), Some(was)) = (now, was) else {
                    return false;
                };
                label == base_label
                    && now.active()
                    && now.view.lists_b
                    && now.role == was.role
                    && now.digest.as_deref() == Some(digest)
                    && now.view.epoch == Some(e0)
                    && now.view.leaves == Some(leaves0)
                    && now.view.tracks_b == was.view.tracks_b
                    && !now.view.quarantined
            })
}

/// Every node's head commit is signed by `signer_hex`.
fn head_signed_by(seats: &Seats, signer_hex: &str) -> bool {
    !seats.is_empty()
        && seats.iter().all(|(_, seat)| {
            seat.as_ref()
                .is_some_and(|seat| seat.view.head_committed_by.as_deref() == Some(signer_hex))
        })
}

/// `GET /groups/:id` on `label`, without a barrier (for `until`
/// predicates and `at_instant` reads).
async fn group_body(sim: &Sim, label: &str, group: &str) -> Result<serde_json::Value> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /groups/{group}: {status} {body}"
    );
    Ok(body)
}

/// The S4 rows `label` lists for `target_hex` in `group`.
fn rows_for(body: &serde_json::Value, target_hex: &str) -> Vec<serde_json::Value> {
    body["revocation_evictions"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|row| row["target"].as_str() == Some(target_hex))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// No open S4 row for `target_hex` on any of `labels`: each listed row is
/// `terminated` with `certificate_valid`. Returns the verdict and what was
/// seen.
async fn no_open_row(
    sim: &Sim,
    labels: &[&'static str],
    group: &str,
    target_hex: &str,
) -> Result<(bool, String)> {
    let mut ok = true;
    let mut seen = Vec::with_capacity(labels.len());
    for label in labels {
        let body = sim
            .at_instant("read a node's S4 rows", group_body(sim, label, group))
            .await??;
        let rows = rows_for(&body, target_hex);
        ok &= rows.iter().all(|row| {
            row["phase"] == "terminated" && row["termination_cause"] == "certificate_valid"
        });
        seen.push(format!("{label}: {rows:?}"));
    }
    Ok((ok, seen.join("; ")))
}

/// `observer`'s verified view of whether `subject` supports `bit`.
fn supports(sim: &Sim, observer: &str, subject: &str, bit: u64) -> Result<Option<bool>> {
    let (subject_id, _) = sim.ids(subject)?;
    Ok(sim
        .state(observer)?
        .agent
        .capability_store()
        .verified_registry_supports(&subject_id, bit))
}

/// Wait `duration` of virtual time in a named barrier.
async fn pause(sim: &Sim, what: &str, duration: Duration) -> Result<()> {
    sim.within(what, duration + secs(2), async {
        tokio::time::sleep(duration).await;
    })
    .await
}

/// Wait until the daemons' wall clock reaches `target_ms` (Unix ms). With
/// the shim the wall clock is a fixed base plus virtual time, so this is
/// exact.
async fn pause_until_wall(sim: &Sim, what: &str, target_ms: u64) -> Result<()> {
    let left = Duration::from_millis(target_ms.saturating_sub(wall_ms()));
    pause(sim, what, left).await
}

// ─── Setup ──────────────────────────────────────────────────────────────────

/// A 2xx reply whose body does not say `ok: false`.
async fn ok_call(
    sim: &Sim,
    label: &str,
    method: Method,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value> {
    let (status, response) = sim.api(label, method, path, Some(body)).await?;
    ensure!(
        (status == StatusCode::OK || status == StatusCode::CREATED) && response["ok"] != false,
        "{label} {path}: {status} {response}"
    );
    Ok(response)
}

/// `issuer` (a U holder) certifies `subject`'s running agent key with
/// `not_after` through `POST /owner/agents/issue`. Returns the
/// certificate's storage encoding (base64) and its digest.
async fn issue_for(
    sim: &Sim,
    issuer: &str,
    subject: &str,
    not_after: u64,
) -> Result<(String, String, AgentCertificate)> {
    let public_key = hex::encode(
        sim.state(subject)?
            .agent
            .identity()
            .agent_keypair()
            .public_key()
            .as_bytes(),
    );
    let issued = ok_call(
        sim,
        issuer,
        Method::POST,
        "/owner/agents/issue",
        json!({
            "agent_public_key": public_key,
            "mode": "acp",
            "label": format!("w3h-{subject}-renewal"),
            "not_after": not_after,
        }),
    )
    .await?;
    let encoded = issued["certificate"]["storage_b64"]
        .as_str()
        .context("certificate.storage_b64")?
        .to_string();
    let certificate = AgentCertificate::from_storage_bytes(&BASE64.decode(&encoded)?)?;
    ensure!(
        certificate.not_after() == Some(not_after),
        "{issuer} issued {subject} a certificate with not_after {:?}, not {not_after}",
        certificate.not_after()
    );
    let digest = crate::groups::owner_cert::certificate_digest_hex(&certificate);
    Ok((encoded, digest, certificate))
}

/// [`Sim::certify_owner_device`] with a certificate `not_after`: the
/// owner device certifies `label` (`POST /owner/agents/issue`), both
/// sides trust and enroll each other, and `label` starts with U and that
/// certificate, yields to the canonical Home and announces.
async fn certify_expiring_device(
    sim: &mut Sim,
    owner_label: &str,
    label: &str,
    owner: &UserKeypair,
    home: &super::super::home::HomeIds,
    not_after: u64,
) -> Result<()> {
    let (machine, agent) = sim.take_keys(label)?;
    let agent_hex = hex::encode(agent.agent_id().as_bytes());
    let machine_hex = hex::encode(machine.machine_id().0);
    let issued = ok_call(
        sim,
        owner_label,
        Method::POST,
        "/owner/agents/issue",
        json!({
            "agent_public_key": hex::encode(agent.public_key().as_bytes()),
            "mode": "acp",
            "label": format!("w3h-{label}"),
            "not_after": not_after,
        }),
    )
    .await?;
    let cert = BASE64.decode(
        issued["certificate"]["storage_b64"]
            .as_str()
            .context("certificate.storage_b64")?,
    )?;
    ok_call(
        sim,
        owner_label,
        Method::POST,
        "/contacts/trust",
        json!({"agent_id": agent_hex, "level": "trusted"}),
    )
    .await?;
    ok_call(
        sim,
        owner_label,
        Method::POST,
        "/sync/devices/enroll",
        json!({"machine_id": machine_hex}),
    )
    .await?;
    sim.start_node_with(
        label,
        Provision {
            machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
            agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
            user_key: Some(crate::storage::serialize_user_keypair(owner)?),
            agent_cert: Some(cert),
        },
    )
    .await?;
    let owner_agent = sim.agent_hex(owner_label)?;
    let owner_machine = sim.machine_hex(owner_label)?;
    ok_call(
        sim,
        label,
        Method::POST,
        "/contacts/trust",
        json!({"agent_id": owner_agent, "level": "trusted"}),
    )
    .await?;
    ok_call(
        sim,
        label,
        Method::POST,
        "/sync/devices/enroll",
        json!({"machine_id": owner_machine}),
    )
    .await?;
    ok_call(sim, label, Method::POST, "/sync/devices/enroll", json!({})).await?;
    let gid = home.gid.clone();
    let mut last = serde_json::Value::Null;
    sim.until(
        &format!("{label} yields to the canonical Home"),
        SETUP,
        async |s: &Sim| {
            last = s
                .request(label, Method::GET, "/home", None)
                .await
                .map_or(serde_json::Value::Null, |(_, body)| body);
            last["state"] == "elsewhere" && last["canonical_group_id"] == gid.as_str()
        },
    )
    .await
    .with_context(|| format!("{label} last GET /home: {last}"))?;
    ok_call(
        sim,
        label,
        Method::POST,
        "/announce",
        json!({"include_user_identity": true, "human_consent": true}),
    )
    .await?;
    Ok(())
}

/// A provisions its Home with a fresh owner key; every other label is a
/// certified same-owner device with a seat. `expiring` names a device and
/// its certificate's `not_after` offset from now; the rest get
/// non-expiring certificates. `admins` are promoted by A. Returns the
/// Home's ids and the expiring device's `not_after` (Unix s).
async fn home_with(
    sim: &mut Sim,
    labels: &[&'static str],
    expiring: Option<(&str, u64)>,
    admins: &[&str],
) -> Result<(super::super::home::HomeIds, Option<u64>)> {
    let owner = UserKeypair::generate()?;
    let home = sim.start_owner_device("A", &owner).await?;
    let mut not_after = None;
    for device in labels.iter().filter(|label| **label != "A") {
        match expiring {
            Some((label, offset)) if label == *device => {
                let at = wall_ms() / 1000 + offset;
                certify_expiring_device(sim, "A", device, &owner, &home, at).await?;
                not_after = Some(at);
            }
            _ => sim.certify_owner_device("A", device, &owner, &home).await?,
        }
    }
    for member in labels.iter().filter(|label| **label != "A") {
        let invite = sim.home_seat("A", member, &home).await?;
        ensure!(
            sim.join_home("A", member, &home, &invite, SETUP).await?,
            "setup: A could not seat {member} in its Home"
        );
    }
    let observers: Vec<&str> = labels.iter().copied().filter(|l| *l != "A").collect();
    for admin in admins {
        sim.promote_admin("A", admin, &home, &observers).await?;
    }
    Ok((home, not_after))
}

/// The parent case's pre-t0 wait: every node is past its restart sync
/// wait from process start (ADR 0110 §2, D73).
async fn past_sync_wait(sim: &Sim, receipt: &mut Receipt) -> Result<()> {
    let setup_end = sim.fabric().now();
    let sync_wait = timing().restart_sync_wait;
    pause(sim, "every node's restart sync wait", sync_wait).await?;
    let t0 = sim.fabric().now();
    receipt.evidence(
        "every_node_past_its_restart_sync_wait_at_t0",
        t0.saturating_sub(setup_end) >= sync_wait,
        format!(
            "setup ended at {} us; restart sync wait {sync_wait:?}; t0 at {} us",
            setup_end.as_micros(),
            t0.as_micros()
        ),
        t0.as_micros(),
    );
    Ok(())
}

/// The ordered pairs of `labels` whose sender holds no pinned binding (the
/// verified machine a pinned send would use) for the recipient.
async fn missing_bindings(
    sim: &Sim,
    labels: &[&'static str],
) -> Result<Vec<(&'static str, &'static str)>> {
    let mut missing = Vec::new();
    for from in labels {
        let state = sim.state(from)?;
        for to in labels.iter().filter(|to| *to != from) {
            let (id, _) = sim.ids(to)?;
            if state.agent.pinned_binding_now(&id).await.is_none() {
                missing.push((*from, *to));
            }
        }
    }
    Ok(missing)
}

/// Before t = 0, every node holds a pinned binding for every other node.
///
/// A pinned send (rebind delivery, catch-up and the capability refresh)
/// to an agent with no binding runs a peer-evidence Lookup. That Lookup
/// runs on a blocking worker that `block_on`s a virtual-time deadline
/// (#1239). Under paused tokio a blocking task inhibits auto-advance, so
/// the deadline never fires and the case stalls in real time (it reached
/// nextest's terminate bound in CI, with and without the shim). In this
/// Home each device announces once, as it joins, so a node that started
/// later may hold no binding for an earlier one. Every node announces
/// again once all are up; a pair that still has no binding is an INFRA
/// failure, never a hang.
async fn pinned_bindings_ready(
    sim: &Sim,
    labels: &[&'static str],
    receipt: &mut Receipt,
) -> Result<()> {
    let mut announced = Vec::with_capacity(labels.len());
    for label in labels {
        let (status, body) = sim
            .api(
                label,
                Method::POST,
                "/announce",
                Some(json!({"include_user_identity": true, "human_consent": true})),
            )
            .await?;
        announced.push(format!("{label}: {status} {body}"));
    }
    let mut last = Vec::new();
    let waited = sim
        .until(
            "every node holds a pinned binding for every peer",
            SETUP,
            async |s: &Sim| match missing_bindings(s, labels).await {
                Ok(missing) => {
                    let done = missing.is_empty();
                    last = missing;
                    done
                }
                Err(_) => false,
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    let ready = last.is_empty();
    receipt.evidence(
        "every_node_holds_a_pinned_binding_for_every_peer_before_t0",
        ready,
        format!("missing (sender, recipient) {last:?}; announces {announced:?}"),
        sim.fabric().now().as_micros(),
    );
    ensure!(
        ready,
        "setup: no pinned binding for (sender, recipient) {last:?}; a pinned send would run a \
         blocking peer-evidence Lookup that stalls paused virtual time"
    );
    Ok(())
}

/// The rebind request; a typed `409 waiting_for_receiver_upgrade` whose
/// named members have unknown support (`None`, the route asked for an
/// advert refresh) is retried with a doubling wait until `budget`.
async fn rebind_request(
    sim: &Sim,
    label: &str,
    group: &str,
    certificate_b64: &str,
    budget: Duration,
) -> Result<(StatusCode, serde_json::Value, Vec<String>)> {
    let path = format!(
        "/groups/{group}/members/{}/certificate/rebind",
        sim.agent_hex(label)?
    );
    let deadline = sim.fabric().now().saturating_add(budget);
    let mut retries = Vec::new();
    let mut wait = RETRY_FIRST;
    loop {
        let (status, body) = sim
            .api(
                label,
                Method::POST,
                &path,
                Some(json!({"certificate": certificate_b64})),
            )
            .await?;
        let now = sim.fabric().now();
        let upgrade = status == StatusCode::CONFLICT && body["error"] == RECEIVER_UPGRADE;
        if !upgrade || now.saturating_add(wait) >= deadline {
            return Ok((status, body, retries));
        }
        retries.push(format!("{} us: {status} {body}", now.as_micros()));
        pause(sim, "the receiver-upgrade retry wait", wait).await?;
        wait = wait.saturating_mul(2).min(RETRY_CAP);
    }
}

/// A encrypts the probe; B and C (or `readers`) try to open it.
async fn data_plane(
    sim: &Sim,
    group: &str,
    encryptor: &str,
    readers: &[&str],
) -> Result<Vec<(String, bool, String)>> {
    let mut out = Vec::with_capacity(readers.len());
    match encrypt(sim, encryptor, group).await? {
        Ok(ciphertext) => {
            for reader in readers {
                let (ok, detail) = decrypts(sim, reader, group, &ciphertext).await?;
                out.push(((*reader).to_string(), ok, detail));
            }
        }
        Err(error) => {
            for reader in readers {
                out.push(((*reader).to_string(), false, error.clone()));
            }
        }
    }
    Ok(out)
}

// ─── s4_certificate_rebind ──────────────────────────────────────────────────

async fn rebind_scenario(sim: &mut Sim, run: RebindRun, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    if run == RebindRun::PostCutoff && sim.shim.is_none() {
        bail!(
            "run (6) needs the W3-H shim: the cutoff and the expiry follow the daemons' wall \
             clock, which without the shim does not move with virtual time"
        );
    }
    let (home, not_after0) =
        home_with(sim, THREE, Some(("B", run.not_after_offset())), &[]).await?;
    let not_after0 = not_after0.context("B's not_after")?;
    let group = home.gid.clone();
    let (b, _) = sim.ids("B")?;
    let b_hex = sim.agent_hex("B")?;
    let a_hex = sim.agent_hex("A")?;
    settled(sim, THREE, &group, &b).await?;
    let base = seats(sim, THREE, &group, &b).await?;
    let a_base = base
        .first()
        .and_then(|(_, seat)| seat.clone())
        .context("A has no record of its Home")?;
    let e0 = a_base.view.epoch.context("A has no live TreeKEM group")?;
    let leaves0 = a_base.view.leaves.context("A has no live TreeKEM group")?;
    let d0 = a_base
        .digest
        .clone()
        .context("A holds no committed certificate digest for B")?;
    let before = data_plane(sim, &group, "A", &["B", "C"]).await?;
    receipt.setup_done(at(sim));
    let (same, detail) = runtime_timing(sim, THREE)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));
    receipt.evidence(
        "home_treekem_group_settled_with_b_seated_on_its_first_certificate",
        all_bind(&base, &d0)
            && base.iter().all(|(_, seat)| {
                seat.as_ref()
                    .is_some_and(|seat| seat.active() && seat.not_after == Some(not_after0))
            })
            && a_base.view.tracks_b == Some(true)
            && leaves0 == 3,
        format!(
            "e0={e0} leaves0={leaves0} d0={d0} not_after0={not_after0}; {}",
            describe_seats(&base)
        ),
        at(sim),
    );
    receipt.evidence(
        "b_and_c_decrypt_before_the_trigger",
        before.iter().all(|(_, ok, _)| *ok),
        format!("{before:?}"),
        at(sim),
    );
    pinned_bindings_ready(sim, THREE, receipt).await?;
    past_sync_wait(sim, receipt).await?;
    match run {
        RebindRun::PreCutoff => {
            pre_cutoff(
                sim, receipt, &group, &b, &b_hex, &base, e0, leaves0, &d0, not_after0,
            )
            .await
        }
        RebindRun::PostCutoff => {
            post_cutoff(
                sim, receipt, &group, &b, &b_hex, &a_hex, &base, e0, leaves0, &d0, not_after0,
            )
            .await
        }
    }
}

/// Runs (1) and (4).
#[allow(clippy::too_many_arguments)]
async fn pre_cutoff(
    sim: &Sim,
    receipt: &mut Receipt,
    group: &str,
    b: &AgentId,
    b_hex: &str,
    base: &Seats,
    e0: u64,
    leaves0: u32,
    d0: &str,
    not_after0: u64,
) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let now_s = wall_ms() / 1000;
    receipt.evidence(
        "b_self_rebind_window_open_at_t0",
        cr::self_rebind_window_open(Some(not_after0), now_s),
        format!(
            "wall {now_s} s; B's not_after {not_after0}; cutoff {}",
            cr::rebind_cutoff(not_after0)
        ),
        at(sim),
    );

    // Run (1): U issues the renewal; B self-rebinds before its cutoff.
    let (renewal, d1, _) = issue_for(sim, "A", "B", not_after0 + RENEWAL_EXTRA).await?;
    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 B self-rebinds its renewal (run 1)");
    let started = sim.fabric().now();
    let (status, body, retries) = rebind_request(sim, "B", group, &renewal, EVIDENCE).await?;
    receipt.note(format!(
        "run (1) B's self-rebind: {status} {body}; typed receiver-upgrade retries {retries:?}"
    ));
    // §2 (#1508 Codex P1 F3): a replica whose head is not synced yet
    // holds the self-rebind (`409 waiting_for_head_sync`) and its worker
    // commits it once the head is synced; the binding check below
    // observes the commit either way.
    let accepted = (status == StatusCode::OK && body["certificate_digest"] == d1.as_str())
        || (status == StatusCode::CONFLICT && body["error"] == "waiting_for_head_sync");
    let mut reached: Option<Duration> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("every node binds B's renewal", EVIDENCE, async |s: &Sim| {
            let Some(now) = seen.observe(seats_now(s, THREE, group, b)).await else {
                return true;
            };
            let done = all_bind(&now, &d1);
            if done {
                reached.get_or_insert(s.fabric().now().saturating_sub(started));
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("every node binds B's renewal")?;
    if reached.is_some() {
        pause(sim, "the rebind settles", SETTLE).await?;
    }
    let after = seats(sim, THREE, group, b).await?;
    let in_place = rebound_in_place(&after, base, &d1, e0, leaves0);
    let by_b = head_signed_by(&after, b_hex);
    let (rows_clear, rows) = no_open_row(sim, THREE, group, b_hex).await?;
    let plane = data_plane(sim, group, "A", &["B", "C"]).await?;
    let plane_ok = plane.iter().all(|(_, ok, _)| *ok);
    let run1 = accepted && in_place && by_b && rows_clear && plane_ok;
    receipt.note(format!(
        "run (1): accepted {accepted}; every node bound d1={d1} at {reached:?} after t=0; in \
         place {in_place}; head signed by B {by_b}; no open S4 row for B {rows_clear} ({rows}); \
         data plane {plane:?}; after: {}",
        describe_seats(&after)
    ));

    // Run (4): a certificate that expires before the committed one.
    let (older, older_digest, _) = issue_for(sim, "A", "B", not_after0 + RENEWAL_EXTRA / 2).await?;
    let path = format!("/groups/{group}/members/{b_hex}/certificate/rebind");
    let (status4, body4) = sim
        .api(
            "B",
            Method::POST,
            &path,
            Some(json!({"certificate": older})),
        )
        .await?;
    pause(sim, "after the refused rebind", QUIET).await?;
    let after4 = seats(sim, THREE, group, b).await?;
    let refused =
        status4 == StatusCode::UNPROCESSABLE_ENTITY && body4["error"] == "rebind_not_later";
    let unchanged = all_bind(&after4, &d1)
        && after4
            .iter()
            .zip(&after)
            .all(|((_, now), (_, was))| match (now, was) {
                (Some(now), Some(was)) => now.view.state_revision == was.view.state_revision,
                _ => false,
            });
    let run4 = refused && unchanged;
    receipt.note(format!(
        "run (4) older certificate (digest {older_digest}, not_after {}): {status4} {body4}; \
         refused rebind_not_later {refused}; nothing changed {unchanged}; {}",
        not_after0 + RENEWAL_EXTRA / 2,
        describe_seats(&after4)
    ));

    let to_a = sim
        .fabric()
        .delivered_writes_after(&sim.peer("B")?, &sim.peer("A")?, trigger)
        .len();
    let to_c = sim
        .fabric()
        .delivered_writes_after(&sim.peer("B")?, &sim.peer("C")?, trigger)
        .len();
    receipt.request_delivered(
        "b_answered_the_rebind_and_reached_a_and_c",
        status != StatusCode::NOT_FOUND
            && status != StatusCode::METHOD_NOT_ALLOWED
            && to_a > 0
            && to_c > 0,
        format!("B's reply {status}; frames since t=0: B->A={to_a} B->C={to_c}"),
        at(sim),
    );
    let passed = run1 && run4;
    if !passed {
        receipt.cause(
            CAUSE_NO_REBIND,
            Some(describe_seats(&after)),
            all_bind(&after, d0),
            at(sim),
        );
    }
    receipt.finish(FINAL_REBIND_PRE, passed, at(sim));
    Ok(())
}

/// Run (6), with the designated admin A reachable.
#[allow(clippy::too_many_arguments)]
async fn post_cutoff(
    sim: &Sim,
    receipt: &mut Receipt,
    group: &str,
    b: &AgentId,
    b_hex: &str,
    a_hex: &str,
    base: &Seats,
    e0: u64,
    leaves0: u32,
    d0: &str,
    not_after0: u64,
) -> Result<()> {
    use crate::dm::CapabilityRegistry as Reg;
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let timing = timing();
    let cutoff = cr::rebind_cutoff(not_after0);
    let handoff_at = not_after0.saturating_sub(TAU / 2);
    receipt.evidence(
        "setup_ended_before_not_after_minus_half_tau",
        wall_ms() / 1000 < handoff_at,
        format!(
            "wall {} s; B's not_after {not_after0}; cutoff {cutoff}; hand-off point {handoff_at}",
            wall_ms() / 1000
        ),
        at(sim),
    );

    // Precondition: the adverts the hand-off and the admin rebind need are
    // current (`None` would skip the hand-off, or make A evict, D129).
    let mut adverts = String::new();
    let mut adverts_ok = false;
    let waited = sim
        .until(
            "the hand-off and rebind adverts are current",
            SETUP,
            async |s: &Sim| {
                let views = (
                    supports(s, "B", "A", Reg::EVICTION_HANDOFF_V1),
                    supports(s, "A", "B", Reg::CERTIFICATE_REBIND_V1),
                    supports(s, "A", "C", Reg::CERTIFICATE_REBIND_V1),
                );
                adverts = format!("{views:?}");
                adverts_ok = matches!(views, (Ok(Some(true)), Ok(Some(true)), Ok(Some(true))));
                adverts_ok
            },
        )
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    receipt.evidence(
        "b_knows_a_takes_handoffs_and_a_knows_b_and_c_take_rebinds",
        adverts_ok,
        format!(
            "(B sees A eviction_handoff_v1, A sees B certificate_rebind_v1, A sees C \
             certificate_rebind_v1) = {adverts}"
        ),
        at(sim),
    );

    pause_until_wall(sim, "wait to B's not_after − τ/2", handoff_at * 1000).await?;
    let now_s = wall_ms() / 1000;
    receipt.evidence(
        "b_is_past_its_cutoff_and_before_raw_not_after",
        !cr::self_rebind_window_open(Some(not_after0), now_s) && now_s < not_after0,
        format!("wall {now_s} s; cutoff {cutoff}; not_after {not_after0}"),
        at(sim),
    );

    // t = 0: U's renewal reaches B after the cutoff; B calls the route.
    let (renewal, d1, _) = issue_for(sim, "A", "B", not_after0 + RENEWAL_EXTRA).await?;
    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 B self-rebinds after its cutoff (run 6)");
    let path = format!("/groups/{group}/members/{b_hex}/certificate/rebind");
    let (status, body) = sim
        .api(
            "B",
            Method::POST,
            &path,
            Some(json!({"certificate": renewal})),
        )
        .await?;
    let handed_to_a = body["handed_to"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(a_hex)));
    let closed = status == StatusCode::CONFLICT
        && body["error"] == "rebind_window_closed"
        && body["state"] == ADMIN_REBIND
        && body["designated_admin"].as_str() == Some(a_hex)
        && handed_to_a;
    receipt.note(format!(
        "run (6) B's self-rebind after the cutoff: {status} {body}"
    ));
    let b_status = sim
        .at_instant("read B's rebind wait", group_body(sim, "B", group))
        .await??;
    let b_waits = b_status["certificate_rebind"]["waiting_for_admin_rebind"]
        .as_array()
        .is_some_and(|waits| {
            waits.iter().any(|wait| {
                wait["cause"] == ADMIN_REBIND
                    && wait["agent_id"].as_str() == Some(b_hex)
                    && wait["designated_admin"].as_str() == Some(a_hex)
                    && wait["renewal_digest"].as_str() == Some(d1.as_str())
            })
        });
    receipt.note(format!(
        "B's certificate_rebind status after the call: {}",
        b_status["certificate_rebind"]
    ));
    let mut a_holds = false;
    let waited = sim
        .until("A holds B's verified renewal", EVIDENCE, async |s: &Sim| {
            a_holds = group_body(s, "A", group).await.is_ok_and(|body| {
                body["certificate_rebind"]["held_renewals"]
                    .as_array()
                    .is_some_and(|held| held.iter().any(|id| id.as_str() == Some(b_hex)))
            });
            a_holds
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }

    // Just before raw not_after: no node has rebound or removed B.
    pause_until_wall(
        sim,
        "wait to just before raw not_after",
        (not_after0 - 1) * 1000,
    )
    .await?;
    let early = seats(sim, THREE, group, b).await?;
    let early_unmoved = all_bind(&early, d0)
        && early
            .iter()
            .all(|(_, seat)| seat.as_ref().is_some_and(Seat::active));
    receipt.note(format!(
        "just before raw not_after ({} s): {}",
        not_after0 - 1,
        describe_seats(&early)
    ));
    receipt.note(format!(
        "adverts before the expiry: B sees A eviction_handoff_v1 {:?}; A sees B, C \
         certificate_rebind_v1 {:?}, {:?}",
        supports(sim, "B", "A", Reg::EVICTION_HANDOFF_V1)?,
        supports(sim, "A", "B", Reg::CERTIFICATE_REBIND_V1)?,
        supports(sim, "A", "C", Reg::CERTIFICATE_REBIND_V1)?
    ));

    // H: A's own expiry trigger is N + τ; it must rebind within the
    // completion bound from there.
    let deadline_ms = (not_after0 + TAU) * 1000
        + u64::try_from(timing.completion_bound.as_millis()).unwrap_or(u64::MAX)
        + 1000;
    let budget = Duration::from_millis(deadline_ms.saturating_sub(wall_ms()));
    let mut reached_ms: Option<u64> = None;
    let mut removed_seen: Option<String> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("the designated admin rebinds B", budget, async |s: &Sim| {
            let Some(now) = seen.observe(seats_now(s, THREE, group, b)).await else {
                return true;
            };
            if removed_seen.is_none()
                && now.iter().any(|(_, seat)| {
                    seat.as_ref()
                        .is_some_and(|seat| !seat.active() || !seat.view.lists_b)
                })
            {
                removed_seen = Some(format!(
                    "at wall {} ms: {}",
                    wall_ms(),
                    describe_seats(&now)
                ));
            }
            let done = all_bind(&now, &d1);
            if done {
                reached_ms.get_or_insert(wall_ms());
            }
            done || removed_seen.is_some()
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("the designated admin rebinds B")?;
    receipt.note(format!(
        "after the rebind wait (wall {} ms): A's rebind deliveries: {}; A sees B, C \
         certificate_rebind_v1 {:?}, {:?}",
        wall_ms(),
        crate::server::routes::named_groups::w3h_rebind_delivery_report(&sim.state("A")?).await,
        supports(sim, "A", "B", Reg::CERTIFICATE_REBIND_V1)?,
        supports(sim, "A", "C", Reg::CERTIFICATE_REBIND_V1)?
    ));
    let (b_id, _) = sim.ids("B")?;
    let b_seen = sim
        .state("A")?
        .agent
        .discovered_agent(b_id)
        .await
        .ok()
        .flatten();
    receipt.note(format!(
        "A's discovery entry for B: cert_not_after {:?}, announced cert digest {:?} (B's \
         pinned binding carries this expiry; an expired live binding resolves nothing)",
        b_seen.as_ref().and_then(|entry| entry.cert_not_after),
        b_seen
            .as_ref()
            .and_then(|entry| entry.agent_certificate.as_ref())
            .map(crate::groups::owner_cert::certificate_digest_hex)
    ));
    if reached_ms.is_some() {
        pause(sim, "the rebind settles", SETTLE).await?;
    }
    let end = seats(sim, THREE, group, b).await?;
    let in_place = rebound_in_place(&end, base, &d1, e0, leaves0);
    let by_a = head_signed_by(&end, a_hex);
    let after_raw = end.iter().all(|(_, seat)| {
        seat.as_ref()
            .and_then(|seat| seat.head_committed_at_ms)
            .is_some_and(|ms| ms > not_after0 * 1000)
    });
    let b_end = sim
        .at_instant(
            "read B's rebind wait at the end",
            group_body(sim, "B", group),
        )
        .await??;
    let wait_ended = b_end["certificate_rebind"]["waiting_for_admin_rebind"]
        .as_array()
        .is_some_and(|waits| {
            !waits
                .iter()
                .any(|wait| wait["agent_id"].as_str() == Some(b_hex))
        });
    let (rows_clear, rows) = no_open_row(sim, THREE, group, b_hex).await?;
    let plane = data_plane(sim, group, "A", &["B", "C"]).await?;
    let plane_ok = plane.iter().all(|(_, ok, _)| *ok);
    let in_bound = reached_ms.is_some_and(|ms| ms <= deadline_ms);
    let passed = closed
        && b_waits
        && a_holds
        && early_unmoved
        && removed_seen.is_none()
        && in_place
        && by_a
        && after_raw
        && in_bound
        && wait_ended
        && rows_clear
        && plane_ok;
    receipt.note(format!(
        "run (6): window closed + handed to A {closed}; B waits naming A {b_waits}; A holds the \
         renewal {a_holds}; unmoved before raw not_after {early_unmoved}; removal seen \
         {removed_seen:?}; every node bound d1={d1} at wall {reached_ms:?} ms (deadline \
         {deadline_ms} = (N + τ) + completion bound + 1 s: {in_bound}); in place {in_place}; head \
         signed by A {by_a}; head committed after raw not_after {after_raw}; B's wait ended \
         {wait_ended}; no open S4 row for B {rows_clear} ({rows}); data plane {plane:?}; end: {}",
        describe_seats(&end)
    ));
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, THREE, group).await?
    ));

    let to_a = sim
        .fabric()
        .delivered_writes_after(&sim.peer("B")?, &sim.peer("A")?, trigger)
        .len();
    receipt.request_delivered(
        "b_answered_the_rebind_and_reached_a",
        status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED && to_a > 0,
        format!("B's reply {status}; frames since t=0: B->A={to_a}"),
        at(sim),
    );
    if !passed {
        if let Some(removed) = &removed_seen {
            receipt.cause(CAUSE_REBIND_EVICTED, Some(removed.clone()), true, at(sim));
        } else {
            receipt.cause(
                CAUSE_NO_REBIND,
                Some(describe_seats(&end)),
                all_bind(&end, d0),
                at(sim),
            );
        }
    }
    receipt.finish(FINAL_REBIND_POST, passed, at(sim));
    Ok(())
}

// ─── s4_owner_recovery ──────────────────────────────────────────────────────

/// The mandate request on the owner device `signer`, naming `promoted`.
async fn mandate(
    sim: &Sim,
    signer: &str,
    group: &str,
    promoted_hex: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    sim.api(
        signer,
        Method::POST,
        &format!("/owner/groups/{group}/recovery-mandate"),
        Some(json!({"promoted_agent_id": promoted_hex})),
    )
    .await
}

/// `admin_availability` names the typed wait with exit `owner_recovery`
/// and A among the revoked admins.
fn waits_for_owner_recovery(body: &serde_json::Value, a_hex: &str) -> bool {
    let availability = &body["admin_availability"];
    availability["state"] == ELIGIBLE_ADMIN_REVOCATION
        && availability["exit"] == "owner_recovery"
        && availability["revoked_admins"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(a_hex)))
}

async fn recovery_scenario(sim: &mut Sim, arm: RecoveryArm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    let labels = arm.labels();
    let (home, _) = home_with(sim, labels, None, &[]).await?;
    let group = home.gid.clone();
    let (a, _) = sim.ids("A")?;
    let a_hex = sim.agent_hex("A")?;
    let b_hex = sim.agent_hex("B")?;
    let survivors: &[&'static str] = &["B", "C"];
    settled(sim, labels, &group, &a).await?;
    let base = views(sim, survivors, &group, &a).await?;
    let a_view = view(sim, "A", &group, &a).await?;
    let e0 = a_view.epoch.context("A has no live TreeKEM group")?;
    let leaves0 = a_view.leaves.context("A has no live TreeKEM group")?;
    let before = data_plane(sim, &group, "B", &["A", "C"]).await?;
    receipt.setup_done(at(sim));
    let (same, detail) = runtime_timing(sim, labels)?;
    receipt.evidence("every_node_runs_s4timing_default", same, detail, at(sim));
    let b_admin_before = sees_admin(sim, "C", &group, "B").await?;
    receipt.evidence(
        "home_treekem_group_settled_with_a_as_admin_and_b_a_member",
        base.iter().all(|(_, seen)| {
            seen.as_ref()
                .is_some_and(|seen| seen.lists_b && seen.epoch == Some(e0) && !seen.quarantined)
        }) && a_view.tracks_b.is_some()
            && u32::try_from(labels.len()).ok() == Some(leaves0)
            && !b_admin_before,
        format!(
            "e0={e0} leaves0={leaves0}; A {}; survivors (about A) {}; B admin on C \
             {b_admin_before}",
            a_view.describe(),
            describe_all(&base)
        ),
        at(sim),
    );
    receipt.evidence(
        "a_and_c_decrypt_b_traffic_before_the_trigger",
        before.iter().all(|(_, ok, _)| *ok),
        format!("{before:?}"),
        at(sim),
    );

    // Before t = 0 A is an eligible admin: a mandate is not needed.
    let (early_status, early_body) = mandate(sim, "C", &group, &b_hex).await?;
    let early_refused =
        early_status == StatusCode::CONFLICT && early_body["error"] == "recovery_not_needed";
    receipt.note(format!(
        "C's mandate while A is an eligible admin: {early_status} {early_body}"
    ));
    past_sync_wait(sim, receipt).await?;

    // t = 0: A revokes its own agent.
    let trigger = sim
        .fabric()
        .mark_indexed("case: t=0 A revokes its own agent");
    let (status, body) = sim
        .api(
            "A",
            Method::POST,
            "/identity/revoke",
            Some(json!({"agent_id": a_hex, "reason": "w3h-1357 owner recovery"})),
        )
        .await?;
    ensure!(status.is_success(), "A self-revokes: {status} {body}");
    await_holders(sim, survivors, &a_hex).await?;
    let held = held_by(sim, survivors, &a_hex).await?;

    // B and C wait for the owner-recovery exit, and their sends are
    // refused with it.
    let mut waiting = String::new();
    let waited = sim
        .until(
            "B and C show waiting_for_eligible_admin_revocation",
            EVIDENCE,
            async |s: &Sim| {
                let mut all = true;
                let mut seen = Vec::new();
                for label in ["B", "C"] {
                    let body = group_body(s, label, &group).await;
                    all &= body
                        .as_ref()
                        .is_ok_and(|body| waits_for_owner_recovery(body, &a_hex));
                    seen.push(format!(
                        "{label}: {}",
                        body.map_or_else(
                            |e| format!("{e:#}"),
                            |b| b["admin_availability"].to_string()
                        )
                    ));
                }
                waiting = seen.join("; ");
                all
            },
        )
        .await;
    let waits_typed = match waited {
        Ok(()) => true,
        Err(error) if expired(&error) => false,
        Err(error) => return Err(error),
    };
    let mut sends = Vec::new();
    for label in ["B", "C"] {
        let (status, body) = sim
            .api(
                label,
                Method::POST,
                &format!("/groups/{group}/secure/encrypt"),
                Some(json!({"payload_b64": BASE64.encode(PROBE)})),
            )
            .await?;
        sends.push((
            label,
            status == StatusCode::CONFLICT && body["error"] == ELIGIBLE_ADMIN_REVOCATION,
            format!("{status} {body}"),
        ));
    }
    let sends_refused = sends.iter().all(|(_, refused, _)| *refused);
    receipt.note(format!(
        "before the mandate: admin_availability {waiting}; sends {sends:?}"
    ));

    // The owner device C signs a mandate naming B.
    let (status, body) = mandate(sim, "C", &group, &b_hex).await?;
    let started = sim.fabric().now();
    let signed = status == StatusCode::ACCEPTED
        && body["state"] == "waiting_for_recovery_member"
        && body["promoted_member"].as_str() == Some(b_hex.as_str())
        && body["revoked_admins"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(a_hex.as_str())));
    receipt.note(format!("C's mandate naming B: {status} {body}"));

    // H: B is an Admin and A is excluded, on B and C.
    let mut reached: Option<Duration> = None;
    let mut seen = Observations::default();
    let waited = sim
        .until("B commits the owner recovery", RECOVERY, async |s: &Sim| {
            let Some(now) = seen.observe(views_now(s, survivors, &group, &a)).await else {
                return true;
            };
            let promoted = sees_admin(s, "B", &group, "B").await.unwrap_or(false)
                && sees_admin(s, "C", &group, "B").await.unwrap_or(false);
            let done = promoted && excluded(&now, e0, leaves0);
            if done {
                reached.get_or_insert(s.fabric().now().saturating_sub(started));
            }
            done
        })
        .await;
    if let Err(error) = waited {
        if !expired(&error) {
            return Err(error);
        }
    }
    seen.verify("B commits the owner recovery")?;
    if reached.is_some() {
        pause(sim, "the recovery settles", SETTLE).await?;
    }
    let end = views(sim, survivors, &group, &a).await?;
    let h = excluded(&end, e0, leaves0) && all_at(&end, e0 + 1);
    let a_removed = end.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.b_state.as_deref() == Some("Removed"))
    });
    let b_admin =
        sees_admin(sim, "B", &group, "B").await? && sees_admin(sim, "C", &group, "B").await?;
    let by_b = end.iter().all(|(_, seen)| {
        seen.as_ref()
            .is_some_and(|seen| seen.head_committed_by.as_deref() == Some(b_hex.as_str()))
    });
    let mut cleared = Vec::new();
    for label in ["B", "C"] {
        let body = sim
            .at_instant("read admin availability", group_body(sim, label, &group))
            .await??;
        cleared.push((
            label,
            body["admin_availability"].is_null(),
            body["admin_availability"].to_string(),
        ));
    }
    let availability_cleared = cleared.iter().all(|(_, null, _)| *null);
    let (c_after, a_after) = match encrypt(sim, "B", &group).await? {
        Ok(ciphertext) => (
            decrypts(sim, "C", &group, &ciphertext).await?,
            decrypts(sim, "A", &group, &ciphertext).await?,
        ),
        Err(error) => ((false, error.clone()), (false, error)),
    };
    let plane_ok = c_after.0 && !a_after.0;
    let passed = early_refused
        && waits_typed
        && sends_refused
        && signed
        && h
        && a_removed
        && b_admin
        && by_b
        && availability_cleared
        && plane_ok;
    receipt.note(format!(
        "pre-t0 mandate refused recovery_not_needed {early_refused}; typed wait {waits_typed}; \
         sends refused {sends_refused}; mandate signed {signed}; H at {reached:?} after the \
         mandate: {h}; A Removed {a_removed}; B admin {b_admin}; head signed by B {by_b}; \
         admin_availability cleared {availability_cleared} {cleared:?}; after: {}; {}; end: {}",
        c_after.1,
        a_after.1,
        describe_all(&end)
    ));
    receipt.note(format!(
        "S4 status at the end: {}",
        statuses(sim, labels, &group).await?
    ));
    receipt.request_delivered(
        "survivors_hold_a_revocation_and_c_answered_the_mandate",
        held.iter().all(|(_, has)| *has)
            && status != StatusCode::NOT_FOUND
            && status != StatusCode::METHOD_NOT_ALLOWED
            && !sim
                .fabric()
                .delivered_writes_after(&sim.peer("A")?, &sim.peer("C")?, trigger)
                .is_empty(),
        format!("revocation held {held:?}; mandate reply {status}"),
        at(sim),
    );
    if !passed {
        receipt.cause(
            CAUSE_NO_RECOVERY,
            Some(describe_all(&end)),
            still_seated(&end, e0, leaves0) && !b_admin,
            at(sim),
        );
    }
    receipt.finish(FINAL_RECOVERY, passed, at(sim));
    Ok(())
}

// ─── Runner and tests ───────────────────────────────────────────────────────

async fn run2(case: &str, seed: u64, arm: Arm2) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!(
        "#1357 / ADR 0110 S4 §4a/§4b(1). Timing from S4Timing::default() (D69, D73): {:?}; \
         τ = {TAU} s; arm {arm:?}.",
        timing()
    ));
    match Sim::empty(case, seed, arm.labels()) {
        Ok(mut sim) => {
            let fabric = Arc::clone(sim.fabric());
            let watchdog = real_time_watchdog(case, fabric);
            let outcome = match arm {
                Arm2::Rebind(run) => rebind_scenario(&mut sim, run, &mut receipt).await,
                Arm2::Recovery(form) => recovery_scenario(&mut sim, form, &mut receipt).await,
            };
            watchdog.disarm();
            if let Err(error) = outcome {
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

/// A case that has not finished after this much real time has stalled.
const REAL_TIME_STALL: Duration = Duration::from_secs(200);

/// A real-time watchdog for one scenario. A stall in a barrier (virtual
/// time stops while the runtime waits on a blocking task) otherwise shows
/// only as nextest's terminate, with no trace. On a stall it prints the
/// tail of the fabric's trace, so the open barrier is named, and exits the
/// test process.
struct Watchdog {
    disarmed: Arc<std::sync::atomic::AtomicBool>,
}

impl Watchdog {
    fn disarm(&self) {
        self.disarmed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn real_time_watchdog(case: &str, fabric: Arc<SimFabric>) -> Watchdog {
    let disarmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&disarmed);
    let case = case.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(REAL_TIME_STALL);
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let trace = fabric.canonical_trace();
        let tail: Vec<&str> = trace.lines().rev().take(60).collect();
        println!(
            "W3H-STALL {case}: no progress after {REAL_TIME_STALL:?} real time; last trace lines \
             (newest first):"
        );
        for line in tail {
            println!("W3H-STALL {line}");
        }
        std::process::exit(101);
    });
    Watchdog { disarmed }
}

async fn expect2(case: &str, seed: u64, arm: Arm2, want: Verdict) -> Result<()> {
    let receipt = run2(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// ADR 0110 `s4_certificate_rebind` runs (1) and (4): GREEN with S4.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1357_s4_certificate_rebind_pre_cutoff() -> Result<()> {
    super::super::block_on_paused(async move {
        expect2(
            "w3h_1357_s4_certificate_rebind_pre_cutoff",
            0x1357_000b,
            Arm2::Rebind(RebindRun::PreCutoff),
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_certificate_rebind` run (6), designated admin reachable:
/// GREEN with S4. Needs the shim (wall clock = base + virtual time), so
/// it runs in the W3-H gate only.
#[test]
#[ignore = "needs the W3-H LD_PRELOAD shim: the W3-H gate runs it with --run-ignored all"]
fn w3h_1357_s4_certificate_rebind_post_cutoff() -> Result<()> {
    super::super::block_on_paused(async move {
        expect2(
            "w3h_1357_s4_certificate_rebind_post_cutoff",
            0x1357_000c,
            Arm2::Rebind(RebindRun::PostCutoff),
            Verdict::Green,
        )
        .await
    })
}

/// ADR 0110 `s4_owner_recovery`, Home with its sole admin revoked: GREEN
/// with S4.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1357_s4_owner_recovery() -> Result<()> {
    super::super::block_on_paused(async move {
        expect2(
            "w3h_1357_s4_owner_recovery",
            0x1357_000d,
            Arm2::Recovery(RecoveryArm::SoleAdminRevoked),
            Verdict::Green,
        )
        .await
    })
}
