#![cfg(test)]
//! #1366 (first slice for the metadata listener): a restart installs the
//! metadata listener only for the stored records that need it
//! ([`metadata_listener_wanted`]), and the public-message listener by the
//! group's confidentiality.
//!
//! The rule test checks the predicate alone. The restart tests run
//! [`restore_named_group_listeners`] on stored records whose metadata topic
//! is a `local:` topic, so the real subscriber starts without wire traffic.
//! Inert apart from the loopback-only test network of
//! `networked_test_state`.

use super::*;
use x0x::groups::member::GroupMemberState;
use x0x::groups::GroupConfidentiality::{MlsEncrypted, SignedPublic};

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

/// One class of stored record and the listeners a restart gives it.
#[derive(Clone, Copy, Debug)]
struct Class {
    group_id: &'static str,
    seat: LocalSeat,
    withdrawn: bool,
    confidentiality: x0x::groups::GroupConfidentiality,
    /// Whether the record needs the metadata listener.
    metadata: bool,
    /// Whether the record gets the public-message listener.
    public: bool,
}

const fn class(
    group_id: &'static str,
    seat: LocalSeat,
    withdrawn: bool,
    confidentiality: x0x::groups::GroupConfidentiality,
    metadata: bool,
    public: bool,
) -> Class {
    Class {
        group_id,
        seat,
        withdrawn,
        confidentiality,
        metadata,
        public,
    }
}

/// Each class of stored record. Only a withdrawn group loses the metadata
/// listener; a Banned seat keeps it, because an admin's `MemberUnbanned`
/// reaches the agent only on this topic. The public-message listener runs
/// only for a SignedPublic group that is not withdrawn.
const CLASSES: [Class; 9] = [
    class(
        "1366-meta-active",
        LocalSeat::Active,
        false,
        MlsEncrypted,
        true,
        false,
    ),
    class(
        "1366-meta-pending",
        LocalSeat::Pending,
        false,
        MlsEncrypted,
        true,
        false,
    ),
    class(
        "1366-meta-stub",
        LocalSeat::None,
        false,
        MlsEncrypted,
        true,
        false,
    ),
    class(
        "1366-meta-removed",
        LocalSeat::Removed,
        false,
        MlsEncrypted,
        true,
        false,
    ),
    class(
        "1366-meta-banned",
        LocalSeat::Banned,
        false,
        MlsEncrypted,
        true,
        false,
    ),
    class(
        "1366-meta-withdrawn",
        LocalSeat::Active,
        true,
        MlsEncrypted,
        false,
        false,
    ),
    class(
        "1366-meta-active-public",
        LocalSeat::Active,
        false,
        SignedPublic,
        true,
        true,
    ),
    class(
        "1366-meta-banned-public",
        LocalSeat::Banned,
        false,
        SignedPublic,
        true,
        true,
    ),
    class(
        "1366-meta-withdrawn-public",
        LocalSeat::Active,
        true,
        SignedPublic,
        false,
        false,
    ),
];

/// A stored record of `class`.
fn record(state: &Arc<AppState>, class: Class) -> Result<x0x::groups::GroupInfo> {
    let (mut info, local_hex, _) = metadata_terminality_test_group(state, class.group_id);
    let seat_state = match class.seat {
        LocalSeat::Active => None,
        LocalSeat::None => {
            info.members_v2.remove(&local_hex);
            None
        }
        LocalSeat::Pending => Some(GroupMemberState::Pending),
        LocalSeat::Removed => Some(GroupMemberState::Removed),
        LocalSeat::Banned => Some(GroupMemberState::Banned),
    };
    if let Some(seat_state) = seat_state {
        let member = info
            .members_v2
            .get_mut(&local_hex)
            .ok_or_else(|| anyhow::anyhow!("fixture has no local seat for {}", class.group_id))?;
        member.state = seat_state;
    }
    info.withdrawn = class.withdrawn;
    info.policy.confidentiality = class.confidentiality;
    info.metadata_topic = format!("local:1366-metadata-{}", class.group_id);
    info.recompute_state_hash();
    Ok(info)
}

/// Stores every class in `classes` and runs the restart restore.
async fn restore(state: &Arc<AppState>, classes: &[Class]) -> Result<()> {
    {
        let mut groups = state.named_groups.write().await;
        for class in classes {
            groups.insert(class.group_id.to_string(), record(state, *class)?);
        }
    }
    restore_named_group_listeners(Arc::clone(state)).await;
    Ok(())
}

/// The rule, class by class.
#[tokio::test]
async fn issue1366_metadata_listener_wanted_by_class() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-metadata-rule").await?;
    for class in CLASSES {
        let info = record(&state, class)?;
        assert_eq!(
            metadata_listener_wanted(&info),
            class.metadata,
            "#1366: {class:?}"
        );
    }
    Ok(())
}

/// A restart installs exactly the listeners the stored state needs: the
/// metadata listener by [`metadata_listener_wanted`] and the
/// public-message listener by confidentiality.
#[tokio::test]
async fn issue1366_restart_keeps_only_the_metadata_listeners_the_state_needs() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-metadata-restart").await?;
    restore(&state, &CLASSES).await?;
    let metadata = state.group_metadata_tasks.read().await;
    let public = state.public_message_tasks.read().await;
    for class in CLASSES {
        assert_eq!(
            metadata.contains_key(class.group_id),
            class.metadata,
            "#1366: restart metadata listener for {class:?}"
        );
        let stable = record(&state, class)?.stable_group_id().to_string();
        assert_eq!(
            public.contains_key(&stable),
            class.public,
            "#1366: restart public-message listener for {class:?}"
        );
    }
    assert_eq!(
        metadata.len(),
        CLASSES.iter().filter(|class| class.metadata).count(),
        "#1366: no other metadata listener runs"
    );
    assert_eq!(
        public.len(),
        CLASSES.iter().filter(|class| class.public).count(),
        "#1366: no other public-message listener runs"
    );
    Ok(())
}

/// A Banned seat keeps its metadata listener after a restart. An admin
/// lifts a ban with a `MemberUnbanned` event published only on the group's
/// metadata topic (`unban_group_member`), so without this listener a
/// restarted banned agent never learns of the unban and its
/// request-access stays refused as `banned`. Base (before #1366) started
/// this listener for every stored record; this keeps that.
#[tokio::test]
async fn issue1366_restart_keeps_the_metadata_listener_for_a_banned_seat() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-metadata-banned").await?;
    let banned = class(
        "1366-banned-restart",
        LocalSeat::Banned,
        false,
        MlsEncrypted,
        true,
        false,
    );
    restore(&state, &[banned]).await?;
    // The listener task must run, not only be registered.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let metadata = state.group_metadata_tasks.read().await;
    let registration = metadata.get(banned.group_id);
    assert!(
        registration.is_some(),
        "#1366: a restart must start the metadata listener for a Banned seat"
    );
    assert!(
        registration.is_some_and(|registration| !registration.handle.is_finished()),
        "#1366: the Banned seat's metadata listener is still running"
    );
    Ok(())
}
