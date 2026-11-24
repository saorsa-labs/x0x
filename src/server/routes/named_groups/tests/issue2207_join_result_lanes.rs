#![cfg(test)]
//! #2207: on a joiner, the join-result listener awaited each apply inline.
//! A `Result` apply can wait in a Welcome fetch for up to 115 s, so every
//! other join-result frame, for every group, waited behind it. The frames
//! of one group must still apply in arrival order (#1275).
//!
//! In-process only: the agent has no network config. The frames are put on
//! the agent's direct-message bus; no socket is used. A held apply stands
//! for the slow Welcome fetch (`join_result_apply_test_gate`).

use super::super::{join_result_apply_test_gate, run_join_result_listener};
use super::*;

const GROUP_A: &str = "2207-group-a-slow-apply";
const GROUP_B: &str = "2207-group-b-other-group";
/// How long group B's frame may wait while group A's apply is held.
const BOUND: Duration = Duration::from_secs(5);

async fn install_group(state: &Arc<AppState>, group_id: &str) {
    let (info, _, _) = metadata_terminality_test_group(state, group_id);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
}

/// An unsigned `Pending` for `group_id`. The apply drops it at once; only
/// the order and timing of the applies matter here.
fn pending(group_id: &str, nonce: &str) -> JoinResultMessage {
    JoinResultMessage::Pending {
        notice: Box::new(JoinPendingNotice {
            group_id: group_id.to_string(),
            member_agent_id: "11".repeat(32),
            signer_agent_id: "22".repeat(32),
            attempt_id: "33".repeat(32),
            cause: "no_eligible_admin".to_string(),
            detail: JoinPendingNoticeDetail {
                count: None,
                revision: None,
                digests: Vec::new(),
            },
            issued_at_ms: now_millis_u64(),
            nonce: nonce.to_string(),
            signature_b64: String::new(),
            signer_public_key_b64: None,
        }),
    }
}

async fn inject(state: &AppState, msg: &JoinResultMessage) -> Result<()> {
    let delivered = state
        .agent
        .direct_messaging()
        .handle_incoming(
            state.agent.machine_id(),
            AgentId([0x72; 32]),
            serde_json::to_vec(msg)?,
            false,
            None,
            None,
        )
        .await;
    anyhow::ensure!(delivered >= 1, "the listener is subscribed");
    Ok(())
}

async fn applied_within(group_id: &str, count: u32, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if join_result_apply_test_gate::applied(group_id) >= count {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// WHY: a slow apply for one group (a Welcome fetch inside a `Result`) must
/// not delay the join-result frames of another group, and a later frame of
/// the slow group must still wait for it. Red before the fix: the listener
/// awaits group A's held apply, so group B's frame is never applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_result_apply_does_not_delay_another_groups_result() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    install_group(&state, GROUP_A).await;
    install_group(&state, GROUP_B).await;
    let release_a = join_result_apply_test_gate::hold(GROUP_A);
    let listener = tokio::spawn(run_join_result_listener(
        Arc::clone(&state),
        state.agent.subscribe_direct(),
    ));

    inject(&state, &pending(GROUP_A, "a1")).await?;
    inject(&state, &pending(GROUP_A, "a2")).await?;
    inject(&state, &pending(GROUP_B, "b1")).await?;

    let b_applied = applied_within(GROUP_B, 1, BOUND).await;
    let a_while_held = join_result_apply_test_gate::applied(GROUP_A);
    release_a.add_permits(16);
    let a_applied = applied_within(GROUP_A, 2, BOUND).await;
    state.shutdown_started.cancel();
    listener.abort();

    assert!(
        b_applied,
        "group B's frame waited behind group A's held apply"
    );
    assert_eq!(
        a_while_held, 0,
        "group A's second frame applied before its first apply finished"
    );
    assert!(a_applied, "group A's frames applied once released");
    Ok(())
}
