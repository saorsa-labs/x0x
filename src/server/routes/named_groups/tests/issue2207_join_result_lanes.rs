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

/// How long a test waits for a step that must happen.
const WAIT: Duration = Duration::from_secs(10);
/// How long a test watches for a step that must not happen.
const QUIET: Duration = Duration::from_millis(300);

/// Poll until `check` holds, or `within` ends.
async fn until(within: Duration, check: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if check() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// WHY: a slow apply for one group (a Welcome fetch inside a `Result`) must
/// not delay the join-result frames of another group, and the frames of
/// the slow group must still apply one at a time, in arrival order (#1275).
/// Red before the fix: the listener awaits group A's held apply, so group
/// B's frame is never applied. Red with same-group applies run at the same
/// time: A's second frame enters while the first is held.
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
    let entered_a = || join_result_apply_test_gate::entered(GROUP_A);
    let applied_a = || join_result_apply_test_gate::applied(GROUP_A);

    inject(&state, &pending(GROUP_A, "a1")).await?;
    inject(&state, &pending(GROUP_A, "a2")).await?;
    inject(&state, &pending(GROUP_A, "a3")).await?;
    inject(&state, &pending(GROUP_B, "b1")).await?;

    let first_a_held = until(WAIT, || entered_a() >= 1).await;
    let b_applied = until(BOUND, || {
        join_result_apply_test_gate::applied(GROUP_B) == ["b1"]
    })
    .await;
    // Only the first frame of A may be in its apply while it is held.
    let second_a_entered_while_held = until(QUIET, || entered_a() > 1).await;
    let mut steps = Vec::new();
    for expected in [vec!["a1"], vec!["a1", "a2"], vec!["a1", "a2", "a3"]] {
        release_a.add_permits(1);
        let reached = until(WAIT, || applied_a() == expected).await;
        // The next frame enters only after this one finished.
        steps.push((reached, applied_a(), entered_a()));
    }
    state.shutdown_started.cancel();
    listener.abort();

    assert!(first_a_held, "group A's first frame entered its apply");
    assert!(
        b_applied,
        "group B's frame waited behind group A's held apply"
    );
    assert!(
        !second_a_entered_while_held,
        "a second frame of group A entered its apply while the first was held"
    );
    for (n, (reached, applied, entered)) in steps.into_iter().enumerate() {
        assert!(
            reached,
            "group A's frames finished out of arrival order: {applied:?}"
        );
        assert!(
            entered as usize <= n + 2,
            "group A had {entered} applies started after {} finished",
            n + 1
        );
    }
    Ok(())
}
