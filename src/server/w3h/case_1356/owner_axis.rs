//! OwnerCertified harness support (#1666, for the ADR 0109 §10 rows H-S3-c
//! and H-S3-c2, #1572). O is the only install with the owner's USER key;
//! A holds an owner-issued agent certificate only (test builds load
//! `agent.cert` without a user key). Control, expected GREEN on `main`:
//! A joins O's OwnerCertified group, O promotes it, and A's own seal
//! reaches O.

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

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let owner = crate::identity::UserKeypair::from_seed(&[0x13; 32])?;
    start_certified(sim, "O", &owner, true).await?;
    start_certified(sim, "A", &owner, false).await?;
    mesh(sim, LABELS).await?;
    announce_all(sim, LABELS).await?;
    let policy = crate::groups::GroupPolicy {
        admission: crate::groups::GroupAdmission::OwnerCertified(owner.user_id()),
        ..crate::groups::GroupPolicyPreset::PrivateSecure.to_policy()
    };
    let body = json!({"name": "w3h owner axis", "display_name": "O", "policy": policy});
    let (code, created) = sim.api("O", Method::POST, "/groups", Some(body)).await?;
    ensure!(code.is_success(), "create: {code} {created}");
    let group = created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string();
    let link = invite(sim, "O", &group).await?;
    let body = json!({
        "invite": link,
        "display_name": "A",
        "mode": "home",
        "expected_owner_user_id": hex::encode(owner.user_id().as_bytes()),
    });
    let (code, joined) = sim
        .api("A", Method::POST, "/groups/join", Some(body))
        .await?;
    ensure!(code.is_success(), "A join: {code} {joined}");
    let a_hex = sim.agent_hex("A")?;
    sim.until("A is seated", SETUP, async |s: &Sim| {
        let listed = members(s, "O", &group)
            .await
            .is_ok_and(|listed| listed.contains(&a_hex));
        let membership = status_now(s, "A", &group).await.ok().flatten();
        listed && membership.and_then(|st| st.membership).as_deref() == Some("active")
    })
    .await?;
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
    // A seal checks every member's certificate; the first try may start
    // the fetches it needs.
    let path = format!("/groups/{group}");
    sim.until("A seals a rename", SETUP, async |s: &Sim| {
        let body = Some(json!({"name": "w3h owner axis A"}));
        let sealed = s.request("A", Method::PATCH, &path, body).await;
        sealed.is_ok_and(|(code, _)| code.is_success())
    })
    .await?;
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

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note("OwnerCertified harness support (#1666): A has no USER key".to_string());
    match Sim::empty(case, seed, LABELS) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt).await {
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

/// Control: a certificate-only admin seals an OwnerCertified group.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1666_control_certificate_only_admin_seals() -> Result<()> {
    super::super::block_on_paused(async move {
        let case = "w3h_1666_control_certificate_only_admin_seals";
        let receipt = run(case, 0x1666_0001).await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{case}: expected Green, got {:?}",
            receipt.verdict()
        );
        Ok(())
    })
}
