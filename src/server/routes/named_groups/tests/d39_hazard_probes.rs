use super::*;

// D39 hazard (B) probe — DO NOT MERGE. Asserts the SAFE behaviour: CI red
// means the hazard reproduces. A repeat explicit `POST /groups/:id/state/seal`
// on an owner-certified Home must never evict the OWNER device's seat.

async fn seal(state: &Arc<AppState>, gid: &str) -> (StatusCode, String) {
    let response = seal_group_state(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(gid.to_string()),
    )
    .await
    .into_response();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    (status, body)
}

async fn owner_seat_active(state: &Arc<AppState>, gid: &str) -> bool {
    let local = hex::encode(state.agent.agent_id().as_bytes());
    state
        .named_groups
        .read()
        .await
        .get(gid)
        .is_some_and(|info| info.has_active_member(&local))
}

/// Every missing-evidence stamp moved >= 300 s into the past — the repeat
/// seal's view after the ADR-0038 grace window elapsed.
async fn age_missing_evidence_stamps(state: &Arc<AppState>, gid: &str) -> usize {
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(gid) else {
        return 0;
    };
    let past = now_millis_u64().saturating_sub(
        (x0x::groups::owner_cert::OWNER_CERT_MISSING_EVIDENCE_GRACE_SECS + 1) * 1_000,
    );
    let mut aged = 0;
    for seat in info.members_v2.values_mut() {
        if seat.certificate_missing_since_ms.is_some() {
            seat.certificate_missing_since_ms = Some(past);
            aged += 1;
        }
    }
    aged
}

async fn owned_home(seed: [u8; 32]) -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    let state = super::super::super::home::tests::owned_state(dir.path(), seed).await?;
    super::super::super::home::provision_home(&state).await;
    let owner = state.agent.identity().user_keypair().expect("owned");
    let (_, home) = super::super::super::home::find_home(&state, &owner.user_id())
        .await
        .expect("provisioned Home");
    Ok((state, dir, home.mls_group_id.clone()))
}

/// D39 (B) SAFE BEHAVIOUR, the reported shape: first explicit seal, then a
/// second one after the 300 s grace window — the owner seat survives both.
#[tokio::test]
async fn d39_b_owner_seat_survives_second_explicit_seal_after_grace() -> Result<()> {
    let (state, _dir, gid) = owned_home([0xD3; 32]).await?;
    let (s1, b1) = seal(&state, &gid).await;
    let after_first = owner_seat_active(&state, &gid).await;
    let aged = age_missing_evidence_stamps(&state, &gid).await;
    let (s2, b2) = seal(&state, &gid).await;
    let after_second = owner_seat_active(&state, &gid).await;
    assert!(
        after_first && after_second,
        "D39 hazard (B) REPRODUCED: owner seat evicted (after_first={after_first} \
         after_second={after_second} aged_stamps={aged}; seal1={s1} {b1}; seal2={s2} {b2})"
    );
    Ok(())
}

/// D39 (B) SAFE BEHAVIOUR, the live owner-device condition (#1143): the
/// owner device announces ANONYMOUSLY, so its own discovery entry carries
/// the anonymous digest. Repeat explicit seals (one after the grace window)
/// must still not evict the owner's seat.
#[tokio::test]
async fn d39_b_owner_seat_survives_explicit_seals_with_anonymous_owner_announce() -> Result<()> {
    let (state, _dir, gid) = owned_home([0xD4; 32]).await?;
    let me = state.agent.agent_id();
    let anonymous = x0x::announce_v3::cert_digest(&None, &None);
    state.agent.identity_discovery_cache().write().await.insert(
        me,
        x0x::DiscoveredAgent {
            self_name: None,
            agent_id: me,
            machine_id: state.agent.machine_id(),
            user_id: None,
            addresses: Vec::new(),
            announced_at: 0,
            last_seen: 0,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: Some(anonymous),
        },
    );
    let (s1, b1) = seal(&state, &gid).await;
    let after_first = owner_seat_active(&state, &gid).await;
    let aged = age_missing_evidence_stamps(&state, &gid).await;
    let (s2, b2) = seal(&state, &gid).await;
    let after_second = owner_seat_active(&state, &gid).await;
    assert!(
        after_first && after_second,
        "D39 hazard (B) REPRODUCED (anonymous owner announce): owner seat evicted \
         (after_first={after_first} after_second={after_second} aged_stamps={aged}; \
         seal1={s1} {b1}; seal2={s2} {b2})"
    );
    Ok(())
}
