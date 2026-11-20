//! #1366: the named-group listeners follow the desired state of the stored
//! group record, not only the events that start them.
//!
//! Two listeners belong to a stored group:
//! - the metadata listener, keyed by the local map key. It runs while the
//!   record is stored and not withdrawn ([`metadata_listener_wanted`]).
//! - the public-message listener, keyed by the stable id. It runs while any
//!   stored record with that stable id is not withdrawn and not
//!   `MlsEncrypted` ([`public_message_listener_wanted`]).
//!
//! Before #1366 the start paths followed this rule, but some exit paths did
//! not. A self-leave (both planes), a local-only drop, a remote self-removal
//! and a refused join stub took the record away and left the public-message
//! listener running; the TreeKEM self-leave left the metadata listener too.
//! A refreshed card that changed a stub to `MlsEncrypted`, and a withdrawn
//! card, left it running as well. The functions here stop a listener when
//! no stored record needs it.
//!
//! Lock order: a registry lock (`group_metadata_tasks` or
//! `public_message_tasks`), then `named_groups`, as in the install paths.
//! The callers hold no group lock.

use super::*;

/// Stop the public-message listener of `group_id` when no stored record
/// needs it. `group_id` is a local map key or a stable id. The desired
/// state is read under the registry write lock, so a concurrent install
/// for a record that needs the listener is kept.
pub(super) async fn retire_unwanted_public_message_listener(state: &AppState, group_id: &str) {
    // Cheap check first: most callers run after an apply that changed no
    // listener input, so the registry write lock is not needed.
    if public_message_listener_wanted(&*state.named_groups.read().await, group_id)
        .is_some_and(|(_, wanted)| wanted)
    {
        return;
    }
    let mut tasks = state.public_message_tasks.write().await;
    let key = match public_message_listener_wanted(&*state.named_groups.read().await, group_id) {
        Some((_, true)) => return,
        Some((stable_id, false)) => stable_id,
        None => group_id.to_string(),
    };
    if let Some(handle) = tasks.remove(&key) {
        handle.abort();
    }
}

/// Stop the metadata listener under `group_key` when the record under that
/// key is gone or withdrawn. The check and the removal run under the
/// registry write lock, so an install for a record stored again since is
/// kept.
///
/// Unlike its public twin this needs no stable-id fallback: the metadata
/// registry is keyed by the local map key only.
/// [`ensure_named_group_metadata_listener`] installs under the key it is
/// given and only for a record stored under exactly that key, so the
/// wanted rule is per key.
async fn retire_unwanted_metadata_listener(state: &AppState, group_key: &str) {
    let mut tasks = state.group_metadata_tasks.write().await;
    let wanted = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .is_some_and(metadata_listener_wanted);
    if wanted {
        return;
    }
    if let Some(reg) = tasks.remove(group_key) {
        reg.handle.abort();
    }
}

/// Make both listeners of a group match its stored record: start each
/// listener the record needs and stop each one it does not need. `group_key`
/// is the local map key. `stable_id` is the stable id of the record, which
/// the caller reads before a removal: after the removal the key alone cannot
/// name the public-message listener.
pub(super) async fn reconcile_named_group_listeners(
    state: &Arc<AppState>,
    group_key: &str,
    stable_id: Option<&str>,
) {
    retire_unwanted_metadata_listener(state, group_key).await;
    ensure_named_group_metadata_listener(Arc::clone(state), group_key).await;
    reconcile_public_message_listener(state, group_key).await;
    if let Some(stable_id) = stable_id.filter(|stable_id| *stable_id != group_key) {
        reconcile_public_message_listener(state, stable_id).await;
    }
}
