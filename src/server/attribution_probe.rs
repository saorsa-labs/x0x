//! #1659 attribution probe installed by `x0xd`.
//!
//! A library embedder that does not run this probe gets contact-only
//! protection. OpenJoin membership does not protect a peer.

use std::collections::HashMap;

use crate::groups::policy::GroupAdmission;
use crate::groups::GroupInfo;
use crate::identity::{AgentCertificate, AgentId};
use crate::peer_evidence::EvidenceRuntime;
use crate::revocation::RevocationSet;
use crate::share_grant::ShareGrantStore;

/// Inputs for one probe answer. Locks are already taken by the caller.
pub(crate) struct AttributionProbeInput<'a> {
    /// `None` when the group map could not be read.
    pub groups: Option<&'a HashMap<String, GroupInfo>>,
    pub local: AgentId,
    pub peer: AgentId,
    pub grants: Option<&'a ShareGrantStore>,
    /// `None` when the revocation set could not be read.
    pub revoked: Option<&'a RevocationSet>,
    /// `None` when the discovery cache could not be read.
    /// `Some(None)` when it was readable and held no certificate.
    pub discovery_cert: Option<Option<&'a AgentCertificate>>,
    pub evidence: Option<&'a EvidenceRuntime>,
    pub now_secs: u64,
}

/// `Some(true)` protects the peer from the stranger share.
/// `Some(false)` does not. `None` means a lock was busy; keep the stored standing.
pub(crate) fn answer(input: AttributionProbeInput<'_>) -> Option<bool> {
    let group_related = input.groups.map(|groups| {
        let local = hex::encode(input.local.as_bytes());
        let peer = hex::encode(input.peer.as_bytes());
        groups
            .values()
            .any(|group| membership_protects(group, &local, &peer))
    });
    if group_related == Some(true) {
        return Some(true);
    }
    let Some(grants) = input.grants else {
        return group_related;
    };
    let revoked = input.revoked?;
    let cert = certificate_for_grant(
        input.discovery_cert,
        input.evidence,
        input.peer,
        input.now_secs,
    )?;
    match grants.try_evidence_related(input.peer, cert.as_ref(), revoked, input.now_secs) {
        Some(true) => Some(true),
        Some(false) => group_related,
        None => None,
    }
}

/// Admission that needs an invite or an approval. OpenJoin does not.
fn admission_protects(admission: GroupAdmission) -> bool {
    matches!(
        admission,
        GroupAdmission::InviteOnly
            | GroupAdmission::RequestAccess
            | GroupAdmission::OwnerCertified(_)
    )
}

fn membership_protects(group: &GroupInfo, local_hex: &str, peer_hex: &str) -> bool {
    !group.withdrawn
        && admission_protects(group.policy.admission)
        && group
            .members_v2
            .get(local_hex)
            .is_some_and(|member| member.is_active())
        && group
            .members_v2
            .get(peer_hex)
            .is_some_and(|member| member.is_active())
}

/// `None` when a needed lock was busy and no certificate was found.
/// `Some` is the certificate to pass to grant matching, which may itself be absent.
fn certificate_for_grant(
    discovery_cert: Option<Option<&AgentCertificate>>,
    evidence: Option<&EvidenceRuntime>,
    peer: AgentId,
    now_secs: u64,
) -> Option<Option<AgentCertificate>> {
    if let Some(Some(cert)) = discovery_cert {
        return Some(Some(cert.clone()));
    }
    let persisted = match evidence {
        // A store that has started and has not finished loading is uncertain.
        // An empty answer here would drop a user grant before the certificate
        // is readable. A store that never started has no persisted certificate.
        Some(runtime) if !runtime.ready_now() => None,
        Some(runtime) => match runtime.try_usable_agent(peer, now_secs.saturating_mul(1000)) {
            Ok(Some(view)) => Some(view.certificate.clone()),
            Ok(None) => Some(None),
            Err(()) => None,
        },
        None => Some(None),
    };
    match (discovery_cert, persisted) {
        (_, None) => None,
        (None, Some(Some(cert))) => Some(Some(cert)),
        (None, Some(None)) => None,
        (Some(None), Some(cert)) => Some(cert),
        // `discovery_cert` is `Copy`, so this arm stays for exhaustiveness.
        // The early return above already handled `Some(Some(_))`.
        (Some(Some(_)), _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::GroupPolicy;
    use crate::groups::GroupMember;
    use crate::identity::{AgentKeypair, UserKeypair};
    use crate::share_grant::{Grantee, ShareCap, ShareGrant};

    fn group_with(local: AgentId, peer: AgentId, admission: GroupAdmission) -> GroupInfo {
        let policy = GroupPolicy {
            admission,
            ..GroupPolicy::default()
        };
        let mut group = GroupInfo::with_policy(
            "probe".to_string(),
            String::new(),
            local,
            "probe-mls".to_string(),
            policy,
        );
        let peer_hex = hex::encode(peer.as_bytes());
        group.members_v2.insert(
            peer_hex.clone(),
            GroupMember::new_member(peer_hex, None, None, 1),
        );
        group
    }

    fn map_of(group: GroupInfo) -> HashMap<String, GroupInfo> {
        let mut groups = HashMap::new();
        groups.insert("probe".to_string(), group);
        groups
    }

    #[test]
    fn open_join_does_not_protect_and_invite_or_approval_does() {
        let local = AgentKeypair::generate().expect("local").agent_id();
        let peer = AgentKeypair::generate().expect("peer").agent_id();
        let revoked = RevocationSet::new();
        let cases = [
            (GroupAdmission::OpenJoin, Some(false)),
            (GroupAdmission::InviteOnly, Some(true)),
            (GroupAdmission::RequestAccess, Some(true)),
            (
                GroupAdmission::OwnerCertified(UserKeypair::generate().expect("user").user_id()),
                Some(true),
            ),
            (GroupAdmission::Unknown, Some(false)),
        ];
        for (admission, expected) in cases {
            let groups = map_of(group_with(local, peer, admission));
            let got = answer(AttributionProbeInput {
                groups: Some(&groups),
                local,
                peer,
                grants: None,
                revoked: Some(&revoked),
                discovery_cert: Some(None),
                evidence: None,
                now_secs: 1_700_000_000,
            });
            assert_eq!(got, expected, "{admission:?}");
        }
    }

    #[tokio::test]
    async fn user_grant_uses_a_certificate_and_an_agent_grant_does_not() {
        let owner = UserKeypair::generate().expect("owner");
        let local = AgentKeypair::generate().expect("local");
        let peer_owner = UserKeypair::generate().expect("peer owner");
        let peer_kp = AgentKeypair::generate().expect("peer");
        let peer = peer_kp.agent_id();
        let cert = AgentCertificate::issue(&peer_owner, &peer_kp).expect("cert");
        let now = 1_700_000_000_u64;
        let grants = ShareGrantStore::in_memory(local.agent_id(), Some(owner.user_id()));
        let revoked = RevocationSet::new();
        let empty = HashMap::new();
        grants
            .accept(
                ShareGrant::sign(
                    &owner,
                    [7; 32],
                    Grantee::User(peer_owner.user_id()),
                    vec![local.agent_id()],
                    vec![ShareCap::Dm],
                    now - 1,
                    now + 60,
                )
                .expect("user grant"),
                now,
            )
            .await
            .expect("store user grant");
        let without_cert = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer,
            grants: Some(&grants),
            revoked: Some(&revoked),
            discovery_cert: Some(None),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(
            without_cert,
            Some(false),
            "a user grant with no certificate is not protection"
        );
        let with_cert = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer,
            grants: Some(&grants),
            revoked: Some(&revoked),
            discovery_cert: Some(Some(&cert)),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(with_cert, Some(true));

        let agent_grants = ShareGrantStore::in_memory(local.agent_id(), Some(owner.user_id()));
        agent_grants
            .accept(
                ShareGrant::sign(
                    &owner,
                    [8; 32],
                    Grantee::Agent(peer),
                    vec![local.agent_id()],
                    vec![ShareCap::Dm],
                    now - 1,
                    now + 60,
                )
                .expect("agent grant"),
                now,
            )
            .await
            .expect("store agent grant");
        let agent_only = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer,
            grants: Some(&agent_grants),
            revoked: Some(&revoked),
            discovery_cert: Some(None),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(agent_only, Some(true));
    }

    async fn flood_strangers(state: &crate::server::state::AppState, first: u8) {
        let bindings = state.agent.authenticated_machine_bindings();
        for offset in 0..2u8 {
            let byte = first.wrapping_add(offset);
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                AgentId([byte; 32]),
                crate::identity::MachineId([byte; 32]),
                u64::from(offset) + 10,
            )
            .await;
        }
    }

    /// Contact delete and downgrade go through the same resolve path as a record.
    #[tokio::test]
    async fn contact_change_keeps_probe_protection_through_a_stranger_flood() {
        use crate::contacts::TrustLevel;
        use crate::dm_inbox::AttributionRelationshipProbe;
        use crate::server::routes::contacts::{
            delete_contact, update_contact, UpdateContactRequest,
        };
        use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
        use axum::extract::{Path, State};
        use axum::Json;

        let (state, _dir) = secure_endpoint_test_state().await.expect("state");
        let member = AgentId([0x81; 32]);
        let machine = crate::identity::MachineId([0x82; 32]);
        state
            .contacts
            .write()
            .await
            .set_trust(&member, TrustLevel::Trusted);
        let bindings = state.agent.authenticated_machine_bindings();
        {
            let mut cache = bindings.write().await;
            cache.set_stranger_pair_limit_for_test(1);
            cache.install_relationship_probe(AttributionRelationshipProbe::from_fn(move |agent| {
                agent == member
            }));
        }
        crate::dm_inbox::record_authenticated_machine_binding(&bindings, member, machine, 1).await;
        let req: UpdateContactRequest =
            serde_json::from_value(serde_json::json!({"trust_level": "unknown"}))
                .expect("downgrade body");
        let _ = update_contact(
            State(std::sync::Arc::clone(&state)),
            Path(hex::encode(member.0)),
            Json(req),
        )
        .await;
        flood_strangers(&state, 0x83).await;
        assert!(
            state
                .agent
                .authenticated_machine_bindings()
                .read()
                .await
                .machines_accepted_for(&member)
                .contains(&machine),
            "a downgrade must keep probe protection"
        );
        let _ = delete_contact(
            State(std::sync::Arc::clone(&state)),
            Path(hex::encode(member.0)),
        )
        .await;
        flood_strangers(&state, 0x85).await;
        assert!(
            state
                .agent
                .authenticated_machine_bindings()
                .read()
                .await
                .machines_accepted_for(&member)
                .contains(&machine),
            "deleting the contact must keep probe protection"
        );
    }

    /// Card import applies the stored trust, not the requested trust.
    /// A blocked contact that imports a "trusted" card stays evictable.
    #[tokio::test]
    async fn card_import_uses_stored_trust_for_attribution() {
        use crate::contacts::TrustLevel;
        use crate::server::routes::identity::{import_agent_card, ImportCardRequest};
        use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
        use axum::extract::State;
        use axum::Json;

        let (state, _dir) = secure_endpoint_test_state().await.expect("state");
        let target = AgentKeypair::generate().expect("target").agent_id();
        let machine = crate::identity::MachineId([0x11; 32]);
        state
            .contacts
            .write()
            .await
            .set_trust(&target, TrustLevel::Blocked);
        let bindings = state.agent.authenticated_machine_bindings();
        {
            let mut cache = bindings.write().await;
            cache.set_stranger_pair_limit_for_test(1);
            cache.set_relationship_peer(target, true);
        }
        crate::dm_inbox::record_authenticated_machine_binding(
            &state.agent.authenticated_machine_bindings(),
            target,
            machine,
            1,
        )
        .await;
        let card = crate::groups::card::AgentCard::new(
            "Ada".to_string(),
            &target,
            &hex::encode([0x11u8; 32]),
        );
        let req: ImportCardRequest = serde_json::from_value(serde_json::json!({
            "card": card.to_link(),
            "trust_level": "trusted"
        }))
        .expect("import body");
        let _ = import_agent_card(State(std::sync::Arc::clone(&state)), None, Json(req)).await;
        assert_eq!(
            state.contacts.read().await.trust_level(&target),
            TrustLevel::Blocked
        );
        flood_strangers(&state, 0x21).await;
        assert!(
            state
                .agent
                .authenticated_machine_bindings()
                .read()
                .await
                .machines_accepted_for(&target)
                .is_empty(),
            "stored Blocked trust must not keep contact protection"
        );
    }

    #[tokio::test]
    async fn received_grant_protects_grantor_and_grantee_only() {
        let local_owner = UserKeypair::generate().expect("local owner");
        let local = AgentKeypair::generate().expect("local");
        let grantor = UserKeypair::generate().expect("grantor");
        let grantor_agent = AgentKeypair::generate().expect("grantor agent");
        let listed = AgentKeypair::generate().expect("listed");
        let grantor_cert = AgentCertificate::issue(&grantor, &grantor_agent).expect("grantor cert");
        let listed_cert = AgentCertificate::issue(&local_owner, &listed).expect("listed cert");
        let now = 1_700_000_000_u64;
        let grants = ShareGrantStore::in_memory(local.agent_id(), Some(local_owner.user_id()));
        let revoked = RevocationSet::new();
        let empty = HashMap::new();
        grants
            .accept(
                ShareGrant::sign(
                    &grantor,
                    [9; 32],
                    Grantee::Agent(local.agent_id()),
                    vec![listed.agent_id()],
                    vec![ShareCap::Dm],
                    now - 1,
                    now + 60,
                )
                .expect("received grant"),
                now,
            )
            .await
            .expect("store received grant");

        let listed_only = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer: listed.agent_id(),
            grants: Some(&grants),
            revoked: Some(&revoked),
            discovery_cert: Some(None),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(
            listed_only,
            Some(false),
            "an agent listed in a received grant is not protected"
        );
        let listed_with_other_cert = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer: listed.agent_id(),
            grants: Some(&grants),
            revoked: Some(&revoked),
            discovery_cert: Some(Some(&listed_cert)),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(listed_with_other_cert, Some(false));
        let grantor_party = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer: grantor_agent.agent_id(),
            grants: Some(&grants),
            revoked: Some(&revoked),
            discovery_cert: Some(Some(&grantor_cert)),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(
            grantor_party,
            Some(true),
            "the verified grantor is protected"
        );
        let busy_revocation = answer(AttributionProbeInput {
            groups: Some(&empty),
            local: local.agent_id(),
            peer: grantor_agent.agent_id(),
            grants: Some(&grants),
            revoked: None,
            discovery_cert: Some(Some(&grantor_cert)),
            evidence: None,
            now_secs: now,
        });
        assert_eq!(
            busy_revocation, None,
            "a busy revocation lock keeps the stored standing"
        );
    }

    #[tokio::test]
    async fn invalid_identity_type_does_not_apply_trust() {
        use crate::contacts::TrustLevel;
        use crate::server::routes::contacts::{update_contact, UpdateContactRequest};
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::Json;

        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("state");
        let member = AgentId([0x91; 32]);
        state
            .contacts
            .write()
            .await
            .set_trust(&member, TrustLevel::Known);
        let req: UpdateContactRequest = serde_json::from_value(serde_json::json!({
            "trust_level": "trusted",
            "identity_type": "not-a-type"
        }))
        .expect("update body");
        let response = update_contact(
            State(std::sync::Arc::clone(&state)),
            Path(hex::encode(member.0)),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state.contacts.read().await.trust_level(&member),
            TrustLevel::Known,
            "an invalid identity type must not change trust"
        );
    }
}
