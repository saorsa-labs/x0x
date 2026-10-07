//! Home setup through the public API, mirroring the live Home fixture
//! (`tests/e2e_home_fixture.py`, `tests/e2e_vps_private_kv.py`
//! `Scenario.run_home`):
//!
//! - the owner device starts with the owner key and provisions the Home;
//! - every other Home device is a same-owner device: the owner certifies
//!   its agent key (`POST /owner/agents/issue`), both sides trust and enroll
//!   each other for owner sync, the device starts with the owner key and
//!   its certificate, yields to the canonical Home (`state = elsewhere`) and
//!   publishes its own consented announce;
//! - seats are minted with `POST /home/seat` and redeemed with
//!   `POST /groups/join {mode: home}`, then awaited on both the authority's
//!   roster and the joiner's own `membership_state`;
//! - promotion is `PATCH /groups/:id/members/:agent/role {role: admin}`.
//!
//! The one deliberate difference from the live fixture: a device's keys
//! and certificate are written before its first start instead of through a
//! stop/restart, so S2 needs no restart support. Owner sync (Tier-1,
//! `SyncV1`) and the peer-evidence hello (`EvidenceV1`) run over the
//! simulator's byte streams (W3-H S4), dialled by the daemons themselves.
//!
//! Nothing here injects discovered certificate bytes (ADR 0108 Validation).

#![cfg(test)]

use super::*;
use crate::identity::{AgentCertificate, UserKeypair};
use anyhow::ensure;
use base64::Engine as _;
use serde_json::{json, Value};

/// `GET /home` while provisioning waits for owner sync (#824).
const HOME_PROVISIONING_PENDING: &str = "provisioning_pending";
/// Virtual-time budget for each setup readiness wait.
const SETUP_BUDGET: Duration = Duration::from_secs(180);

/// The canonical Home's identifiers.
#[derive(Clone, Debug)]
pub(crate) struct HomeIds {
    pub(crate) gid: String,
    pub(crate) owner_user_id: String,
}

fn ok_status(status: StatusCode) -> bool {
    status == StatusCode::OK || status == StatusCode::CREATED
}

async fn home_state(sim: &Sim, label: &str) -> Option<Value> {
    let (status, body) = sim.request(label, Method::GET, "/home", None).await.ok()?;
    ok_status(status).then_some(body)
}

/// `members` rows of `gid` as seen by `label`, as (agent id, role). A
/// failed request, a non-2xx status or a malformed body is an error, never
/// an empty roster.
pub(crate) async fn roster(sim: &Sim, label: &str, gid: &str) -> Result<Vec<(String, String)>> {
    let path = format!("/groups/{gid}/members");
    let (status, body) = sim.request(label, Method::GET, &path, None).await?;
    ensure!(ok_status(status), "{label} GET {path}: {status} {body}");
    body["members"]
        .as_array()
        .with_context(|| format!("{label} GET {path}: no members array: {body}"))?
        .iter()
        .map(|row| {
            Ok((
                row["agent_id"]
                    .as_str()
                    .with_context(|| format!("{label} GET {path}: row without agent_id: {row}"))?
                    .to_string(),
                row["role"].as_str().unwrap_or_default().to_string(),
            ))
        })
        .collect()
}

/// `membership_state` of `gid` on `label` (`active`,
/// `pending_authority_commit`, …); `None` when `label` has no such group
/// (404). Any other failure is an error.
pub(crate) async fn membership_state(sim: &Sim, label: &str, gid: &str) -> Result<Option<String>> {
    let path = format!("/groups/{gid}");
    let (status, body) = sim.request(label, Method::GET, &path, None).await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(ok_status(status), "{label} GET {path}: {status} {body}");
    ensure!(
        body["group_id"].as_str() == Some(gid),
        "{label} GET {path}: wrong group: {body}"
    );
    Ok(body["membership_state"].as_str().map(str::to_string))
}

impl Sim {
    /// The node's machine id, hex.
    pub(crate) fn machine_hex(&self, label: &str) -> Result<String> {
        Ok(hex::encode(
            self.state(label)?.agent.identity().machine_id().0,
        ))
    }

    async fn ok_api(&self, label: &str, method: Method, path: &str, body: Value) -> Result<Value> {
        let (status, response) = self.api(label, method, path, Some(body)).await?;
        ensure!(
            ok_status(status) && response["ok"] != false,
            "{label} {path}: {status} {response}"
        );
        Ok(response)
    }

    /// Start the owner device with the owner key and wait for it to
    /// provision the Home (`state = local`).
    pub(crate) async fn start_owner_device(
        &mut self,
        label: &str,
        owner: &UserKeypair,
    ) -> Result<HomeIds> {
        let (machine, agent) = self.take_keys(label)?;
        let cert = AgentCertificate::issue(owner, &agent)?;
        self.start_node_with(
            label,
            Provision {
                machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
                agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
                user_key: Some(crate::storage::serialize_user_keypair(owner)?),
                agent_cert: Some(cert.to_storage_bytes()?),
            },
        )
        .await?;
        let mut home = None;
        self.until(
            &format!("{label} provisions the Home"),
            SETUP_BUDGET,
            async |s: &Sim| {
                home = home_state(s, label)
                    .await
                    .filter(|body| body["state"].as_str() != Some(HOME_PROVISIONING_PENDING));
                home.is_some()
            },
        )
        .await?;
        let home = home.context("Home state")?;
        ensure!(home["state"] == "local", "{label} Home: {home}");
        let ids = HomeIds {
            gid: home["group_id"].as_str().context("group_id")?.to_string(),
            owner_user_id: home["owner_user_id"]
                .as_str()
                .context("owner_user_id")?
                .to_string(),
        };
        self.ok_api(label, Method::POST, "/sync/devices/enroll", json!({}))
            .await?;
        Ok(ids)
    }

    /// Certify, start and settle one more same-owner device.
    pub(crate) async fn certify_owner_device(
        &mut self,
        owner_label: &str,
        label: &str,
        owner: &UserKeypair,
        home: &HomeIds,
    ) -> Result<()> {
        let (machine, agent) = self.take_keys(label)?;
        let agent_hex = hex::encode(agent.agent_id().as_bytes());
        let machine_hex = hex::encode(machine.machine_id().0);
        let issued = self
            .ok_api(
                owner_label,
                Method::POST,
                "/owner/agents/issue",
                json!({
                    "agent_public_key": hex::encode(agent.public_key().as_bytes()),
                    "mode": "acp",
                    "label": format!("w3h-{label}"),
                }),
            )
            .await?;
        let cert = BASE64_STANDARD.decode(
            issued["certificate"]["storage_b64"]
                .as_str()
                .context("certificate.storage_b64")?,
        )?;
        self.ok_api(
            owner_label,
            Method::POST,
            "/contacts/trust",
            json!({"agent_id": agent_hex, "level": "trusted"}),
        )
        .await?;
        self.ok_api(
            owner_label,
            Method::POST,
            "/sync/devices/enroll",
            json!({"machine_id": machine_hex}),
        )
        .await?;
        self.start_node_with(
            label,
            Provision {
                machine_key: Some(crate::storage::serialize_machine_keypair(&machine)?),
                agent_key: Some(crate::storage::serialize_agent_keypair(&agent)?),
                user_key: Some(crate::storage::serialize_user_keypair(owner)?),
                agent_cert: Some(cert),
            },
        )
        .await?;
        let owner_agent = self.agent_hex(owner_label)?;
        let owner_machine = self.machine_hex(owner_label)?;
        self.ok_api(
            label,
            Method::POST,
            "/contacts/trust",
            json!({"agent_id": owner_agent, "level": "trusted"}),
        )
        .await?;
        self.ok_api(
            label,
            Method::POST,
            "/sync/devices/enroll",
            json!({"machine_id": owner_machine}),
        )
        .await?;
        self.ok_api(label, Method::POST, "/sync/devices/enroll", json!({}))
            .await?;
        let gid = home.gid.clone();
        let mut last = Value::Null;
        self.until(
            &format!("{label} yields to the canonical Home"),
            SETUP_BUDGET,
            async |s: &Sim| {
                last = home_state(s, label).await.unwrap_or(Value::Null);
                last["state"] == "elsewhere" && last["canonical_group_id"] == gid.as_str()
            },
        )
        .await
        // The receipt names what the device actually reported.
        .with_context(|| format!("{label} last GET /home: {last}"))?;
        self.ok_api(
            label,
            Method::POST,
            "/announce",
            json!({"include_user_identity": true, "human_consent": true}),
        )
        .await?;
        Ok(())
    }

    /// `inviter` mints an addressed Home seat invite for `member`.
    pub(crate) async fn home_seat(
        &self,
        inviter: &str,
        member: &str,
        home: &HomeIds,
    ) -> Result<String> {
        let gid = home.gid.clone();
        self.until(
            &format!("{inviter} serves the canonical Home"),
            SETUP_BUDGET,
            async |s: &Sim| {
                home_state(s, inviter).await.is_some_and(|body| {
                    body["state"] == "local" && body["group_id"] == gid.as_str()
                })
            },
        )
        .await?;
        let member_hex = self.agent_hex(member)?;
        let seat = self
            .ok_api(
                inviter,
                Method::POST,
                "/home/seat",
                json!({"agent_id": member_hex}),
            )
            .await?;
        ensure!(
            seat["group_id"] == home.gid.as_str() && seat["intended_joiner"] == member_hex.as_str(),
            "seat for {member}: {seat}"
        );
        let invite = seat["invite"].as_str().context("invite")?.to_string();
        ensure!(
            invite.starts_with("x0x://invite/"),
            "invite shape: {invite}"
        );
        Ok(invite)
    }

    /// `member` redeems `invite` (`mode: home`). Returns whether, within
    /// `budget`, `authority` lists the member and the member reports itself
    /// `active` — the live fixture's owner + local readiness.
    pub(crate) async fn join_home(
        &self,
        authority: &str,
        member: &str,
        home: &HomeIds,
        invite: &str,
        budget: Duration,
    ) -> Result<bool> {
        self.ok_api(
            member,
            Method::POST,
            "/groups/join",
            json!({
                "invite": invite,
                "mode": "home",
                "expected_owner_user_id": home.owner_user_id,
            }),
        )
        .await?;
        let member_hex = self.agent_hex(member)?;
        let gid = home.gid.clone();
        let what = format!("{member} Home seat ready on {authority} and locally");
        // "Not admitted" is a verdict only when every roster and state read
        // completed and succeeded; a failed or hanging read is INFRA.
        let mut seen = Observations::default();
        let ready = self
            .until(&what, budget, async |s: &Sim| {
                let Some(rows) = seen.observe(roster(s, authority, &gid)).await else {
                    return true;
                };
                if !rows.iter().any(|(id, _)| *id == member_hex) {
                    return false;
                }
                let Some(state) = seen.observe(membership_state(s, member, &gid)).await else {
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

    /// The owner promotes `member` to admin; every observer sees the role.
    pub(crate) async fn promote_admin(
        &self,
        owner: &str,
        member: &str,
        home: &HomeIds,
        observers: &[&str],
    ) -> Result<()> {
        let member_hex = self.agent_hex(member)?;
        let promoted = self
            .ok_api(
                owner,
                Method::PATCH,
                &format!("/groups/{}/members/{member_hex}/role", home.gid),
                json!({"role": "admin"}),
            )
            .await?;
        ensure!(promoted["role"] == "admin", "promotion: {promoted}");
        let gid = home.gid.clone();
        for observer in observers {
            self.until(
                &format!("{observer} sees {member} as admin"),
                SETUP_BUDGET,
                async |s: &Sim| {
                    roster(s, observer, &gid).await.is_ok_and(|rows| {
                        rows.iter()
                            .any(|(id, role)| *id == member_hex && role == "admin")
                    })
                },
            )
            .await?;
        }
        Ok(())
    }
}

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
