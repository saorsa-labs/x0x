#![cfg(test)]
//! #1366 (first slice for the metadata listener): a restart installs the
//! metadata listener only for the stored records that need it
//! ([`metadata_listener_wanted`]).
//!
//! A local topic drives the real subscriber. Inert apart from the
//! loopback-only test network of `networked_test_state`.

use super::*;
use x0x::groups::member::GroupMemberState;

/// The local agent's seat in a stored record, by class.
#[derive(Clone, Copy, Debug)]
enum LocalSeat {
    Active,
    Pending,
    Removed,
    Banned,
    /// No local row: a card-import or join stub.
    None,
}

/// A stored record whose local seat is `seat`, `withdrawn` or not.
fn record(
    state: &Arc<AppState>,
    group_id: &str,
    seat: LocalSeat,
    withdrawn: bool,
) -> x0x::groups::GroupInfo {
    let (mut info, local_hex, _) = metadata_terminality_test_group(state, group_id);
    match seat {
        LocalSeat::Active => {}
        LocalSeat::None => {
            info.members_v2.remove(&local_hex);
        }
        LocalSeat::Pending | LocalSeat::Removed | LocalSeat::Banned => {
            if let Some(member) = info.members_v2.get_mut(&local_hex) {
                member.state = match seat {
                    LocalSeat::Pending => GroupMemberState::Pending,
                    LocalSeat::Removed => GroupMemberState::Removed,
                    _ => GroupMemberState::Banned,
                };
            }
        }
    }
    info.withdrawn = withdrawn;
    info.metadata_topic = format!("local:1366-metadata-{group_id}");
    info.recompute_state_hash();
    info
}

/// Each class of stored record and whether it needs the metadata listener.
const CLASSES: [(&str, LocalSeat, bool, bool); 6] = [
    ("1366-meta-active", LocalSeat::Active, false, true),
    ("1366-meta-pending", LocalSeat::Pending, false, true),
    ("1366-meta-stub", LocalSeat::None, false, true),
    ("1366-meta-removed", LocalSeat::Removed, false, false),
    ("1366-meta-banned", LocalSeat::Banned, false, false),
    ("1366-meta-withdrawn", LocalSeat::Active, true, false),
];

/// The rule, class by class.
#[tokio::test]
async fn issue1366_metadata_listener_wanted_by_class() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-metadata-rule").await?;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    for (group_id, seat, withdrawn, wanted) in CLASSES {
        let info = record(&state, group_id, seat, withdrawn);
        assert_eq!(
            metadata_listener_wanted(&info, &local),
            wanted,
            "#1366: {group_id} ({seat:?}, withdrawn {withdrawn})"
        );
    }
    Ok(())
}

/// A restart installs exactly the metadata listeners the stored state
/// needs. Before #1366 it installed one for every stored record, also for
/// a group this agent was removed from or banned in.
#[tokio::test]
async fn issue1366_restart_keeps_only_the_metadata_listeners_the_state_needs() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-metadata-restart").await?;
    {
        let mut groups = state.named_groups.write().await;
        for (group_id, seat, withdrawn, _) in CLASSES {
            groups.insert(
                group_id.to_string(),
                record(&state, group_id, seat, withdrawn),
            );
        }
    }
    restore_named_group_listeners(Arc::clone(&state)).await;
    let tasks = state.group_metadata_tasks.read().await;
    for (group_id, seat, withdrawn, wanted) in CLASSES {
        assert_eq!(
            tasks.contains_key(group_id),
            wanted,
            "#1366: restart listener for {group_id} ({seat:?}, withdrawn {withdrawn})"
        );
    }
    assert_eq!(
        tasks.len(),
        CLASSES.iter().filter(|class| class.3).count(),
        "#1366: no other metadata listener runs"
    );
    Ok(())
}
