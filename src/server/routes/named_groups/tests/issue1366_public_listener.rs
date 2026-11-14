#![cfg(test)]
//! #1366 (cut scope): the public-message listener follows the group's
//! confidentiality, and a concurrent install leaves one running task.
//!
//! A local topic drives the real subscriber. Inert apart from the
//! loopback-only test network of `networked_test_state`.

use super::*;

/// Live public-listener tasks by group id. Group ids are unique per test,
/// so concurrent tests do not see each other's counts.
static LIVE: std::sync::Mutex<Vec<(String, usize)>> = std::sync::Mutex::new(Vec::new());

/// Counts one running public-listener task until it ends or is aborted.
pub(in crate::server) struct LiveListener {
    group_id: String,
}

impl LiveListener {
    pub(in crate::server) fn start(group_id: &str) -> Self {
        let mut live = LIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match live.iter_mut().find(|(id, _)| id == group_id) {
            Some((_, count)) => *count += 1,
            None => live.push((group_id.to_string(), 1)),
        }
        Self {
            group_id: group_id.to_string(),
        }
    }
}

impl Drop for LiveListener {
    fn drop(&mut self) {
        let mut live = LIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, count)) = live.iter_mut().find(|(id, _)| *id == self.group_id) {
            *count = count.saturating_sub(1);
        }
    }
}

fn live(group_id: &str) -> usize {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(id, _)| id == group_id)
        .map_or(0, |(_, count)| *count)
}

/// Lets aborted tasks drop and new tasks reach their first poll.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn fixture(
    group_id: &str,
    confidentiality: x0x::groups::GroupConfidentiality,
) -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let (state, dir) = networked_test_state("1366-public-listener").await?;
    let (mut info, _, _) = metadata_terminality_test_group(&state, group_id);
    info.policy.confidentiality = confidentiality;
    info.metadata_topic = format!("local:1366-metadata-{group_id}");
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    Ok((state, dir, stable))
}

async fn registered(state: &AppState, stable: &str) -> bool {
    state.public_message_tasks.read().await.contains_key(stable)
}

async fn set_confidentiality(
    state: &Arc<AppState>,
    group_id: &str,
    confidentiality: x0x::groups::GroupConfidentiality,
) -> StatusCode {
    update_group_policy(
        State(Arc::clone(state)),
        Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.to_string()),
        Json(UpdateGroupPolicyRequest {
            preset: None,
            discoverability: None,
            admission: None,
            confidentiality: Some(confidentiality),
            read_access: None,
            write_access: None,
        }),
    )
    .await
    .into_response()
    .status()
}

#[tokio::test]
async fn issue1366_concurrent_installs_leave_one_running_public_listener() -> Result<()> {
    let group_id = "1366-concurrent-local-key";
    let (state, _dir, stable) =
        fixture(group_id, x0x::groups::GroupConfidentiality::SignedPublic).await?;
    futures::future::join_all(
        (0..8).map(|_| spawn_public_message_listener(Arc::clone(&state), stable.clone())),
    )
    .await;
    settle().await;
    assert!(
        registered(&state, &stable).await,
        "one listener is registered"
    );
    assert_eq!(
        live(&stable),
        1,
        "#1366: concurrent installs must leave exactly one running listener task, \
         not overwritten handles that keep running"
    );
    Ok(())
}

#[tokio::test]
async fn issue1366_policy_flip_starts_and_stops_the_public_listener() -> Result<()> {
    let group_id = "1366-flip-local-key";
    let (state, _dir, stable) =
        fixture(group_id, x0x::groups::GroupConfidentiality::MlsEncrypted).await?;
    ensure_named_group_listeners(Arc::clone(&state), group_id).await;
    settle().await;
    assert!(
        !registered(&state, &stable).await,
        "an MlsEncrypted group runs no public listener"
    );

    let status = set_confidentiality(
        &state,
        group_id,
        x0x::groups::GroupConfidentiality::SignedPublic,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the flip to SignedPublic applies");
    settle().await;
    assert!(
        registered(&state, &stable).await && live(&stable) == 1,
        "#1366: a flip to SignedPublic starts the public listener without a restart"
    );

    let status = set_confidentiality(
        &state,
        group_id,
        x0x::groups::GroupConfidentiality::MlsEncrypted,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the flip back to MlsEncrypted applies"
    );
    settle().await;
    assert!(
        !registered(&state, &stable).await,
        "#1366: a flip to MlsEncrypted removes the public listener"
    );
    assert_eq!(live(&stable), 0, "#1366: and stops its task");
    Ok(())
}

/// A restart runs `ensure_named_group_listeners` for each stored group: it
/// keeps exactly the public listeners the stored state needs.
#[tokio::test]
async fn issue1366_restart_keeps_only_the_public_listeners_the_state_needs() -> Result<()> {
    let public_id = "1366-restart-public-key";
    let (state, _dir, public_stable) =
        fixture(public_id, x0x::groups::GroupConfidentiality::SignedPublic).await?;
    let secure_id = "1366-restart-secure-key";
    let (mut secure, _, _) = metadata_terminality_test_group(&state, secure_id);
    secure.policy.confidentiality = x0x::groups::GroupConfidentiality::MlsEncrypted;
    secure.metadata_topic = "local:1366-metadata-secure".to_string();
    secure.recompute_state_hash();
    let secure_stable = secure.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(secure_id.to_string(), secure);
    for group_id in [public_id, secure_id] {
        ensure_named_group_listeners(Arc::clone(&state), group_id).await;
    }
    settle().await;
    assert!(registered(&state, &public_stable).await);
    assert!(!registered(&state, &secure_stable).await);
    assert_eq!(live(&public_stable), 1);
    assert_eq!(live(&secure_stable), 0);
    Ok(())
}
