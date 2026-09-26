//! Task-list REST handlers (`category: "tasks"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::crdt_subscriptions;
use super::super::state::AppState;
use super::super::{api_error, bad_request, forbidden, not_found};

// ---------------------------------------------------------------------------
// Group-membership enforcement (#153)
// ---------------------------------------------------------------------------
//
// Task-list REST endpoints are local daemon control-plane endpoints
// authenticated by the daemon's bearer API token (`src/server/auth.rs`
// `auth_middleware`). That token authenticates the daemon, NOT a remote
// requester agent — there is no per-request agent identity in this path.
//
// So group isolation is enforced against the daemon's *local* agent: if a
// task-list id is group-scoped, the daemon's local agent must be an ACTIVE
// member of that named group, otherwise the handler returns 403. This gives
// hard cross-daemon isolation (a daemon whose local agent is not in group G
// cannot read/write G's task lists via its own REST API) and is what the
// x0x-symphony XSY-0021 two-daemon isolation test proves. Non-group-scoped
// ids are unchanged.
//
// Fail-closed: a malformed scoped id, a missing group, or a
// non-active/non-member local agent all deny. See `ensure_task_list_access`.

/// Symphony's group-scoped task-list id convention:
/// `x0x.group.<group_id>.symphony.<list_id>`.
///
/// Returns the parsed `<group_id>` when `id` is group-scoped, or `None` for a
/// plain (non-scoped) task-list id. A string that *looks* scoped but is
/// malformed (wrong segment count, empty group id, …) is NOT treated as
/// plain: callers must deny it via [`ensure_task_list_access`].
pub(in crate::server) fn parse_group_scoped_task_list_id(id: &str) -> Option<GroupScopedId> {
    // Split on '.' but keep it simple and strict: exactly 5 non-empty segments
    // `x0x . group . <group_id> . symphony . <list_id>`.
    let parts: Vec<&str> = id.split('.').collect();
    if parts.len() != 5 {
        return None;
    }
    if parts[0] != "x0x" || parts[1] != "group" || parts[3] != "symphony" {
        return None;
    }
    let group_id = parts[2];
    let list_id = parts[4];
    if group_id.is_empty() || list_id.is_empty() {
        // Malformed scoped id — signal "looked scoped but invalid" distinctly
        // from a plain id by returning Some with an empty group id, which the
        // guard treats as deny. We use a dedicated sentinel for clarity.
        return Some(GroupScopedId::malformed());
    }
    Some(GroupScopedId {
        group_id: group_id.to_string(),
        list_id: list_id.to_string(),
    })
}

/// A parsed group-scoped task-list id, or a malformed sentinel.
///
/// `list_id` is retained for diagnostics/future use but is not consulted by
/// the membership guard (only `group_id` is needed to check access).
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) struct GroupScopedId {
    pub(in crate::server) group_id: String,
    #[allow(dead_code)]
    pub(in crate::server) list_id: String,
}

impl GroupScopedId {
    /// Sentinel for an id that looked scoped (`x0x.group.…`) but was malformed.
    /// `group_id` is empty so the guard cannot find a matching group ⇒ deny.
    pub(in crate::server) fn malformed() -> Self {
        Self {
            group_id: String::new(),
            list_id: String::new(),
        }
    }

    pub(in crate::server) fn is_malformed(&self) -> bool {
        self.group_id.is_empty()
    }
}

/// Enforcement guard for group-scoped task lists (#153).
///
/// - Non-scoped id  ⇒ allow (returns `Ok(())`).
/// - Group-scoped id ⇒ allow only if the daemon's local agent is an ACTIVE
///   member of the named group in `state.named_groups`.
/// - Malformed scoped id, missing group, or non-member ⇒ `Err(403)`.
///
/// `Ok(())` means the caller may proceed; the `Err` is an `impl IntoResponse`
/// 403 ready to return.
pub(in crate::server) async fn ensure_task_list_access(
    state: &Arc<AppState>,
    id: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        // Plain (non-group-scoped) task-list id — unchanged behavior.
        return Ok(());
    };
    if scoped.is_malformed() {
        return Err(forbidden("malformed group-scoped task-list id"));
    }
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&scoped.group_id) else {
        // Unknown group ⇒ fail closed. We do NOT reveal whether the group
        // exists to a non-member, but the id namespace is public-by-convention
        // so a plain 403 is the safe, non-leaky response.
        return Err(forbidden("not a member of task-list group"));
    };
    let member = info.members_v2.get(&local_agent_hex);
    let allowed = member.is_some_and(|m| matches!(m.state, x0x::groups::GroupMemberState::Active));
    if allowed {
        Ok(())
    } else {
        Err(forbidden("not a member of task-list group"))
    }
}

/// ADR-0066 §3c row 20: the fork-quarantine marker of the named group this
/// task list is bound to, or `None` for a list that is not group-scoped.
///
/// WHY the lookup goes through [`crate::server::delegations::fork_quarantine_marker`]
/// rather than a bare `named_groups.get(id)`: the roster map is keyed by
/// whichever alias this daemon learned the group under, which is not
/// necessarily the group's stable id — and a task-list id carries whichever
/// spelling the creating client used. A single-spelling read would serve
/// mutations on a contested roster whenever the two differ, which is the
/// containment hole review found in slices 3, 4 and 6. That resolver is the
/// one place both spellings are tried, so this row reuses it rather than
/// adding a fourth copy of the fallback.
///
/// A malformed scoped id resolves to `None` deliberately: it is already
/// denied with a 403 by [`ensure_task_list_access`], which every caller of
/// this function runs first, so there is no group to be contested.
pub(in crate::server) async fn task_list_fork_quarantine(
    state: &Arc<AppState>,
    id: &str,
) -> Option<(String, x0x::groups::ForkQuarantine)> {
    let scoped = parse_group_scoped_task_list_id(id)?;
    if scoped.is_malformed() {
        return None;
    }
    let marker =
        crate::server::delegations::fork_quarantine_marker(state, &scoped.group_id).await?;
    Some((scoped.group_id, marker))
}

/// ADR-0066 §3c row 20 (mutation half): refuse a task-list mutation whose
/// group is fork-quarantined on this node.
///
/// R5 made this immediate and unconditional — there is no warn-only window
/// and no request budget, so the FIRST mutation after the marker installs is
/// refused. Callers must invoke this before touching `state.task_lists`, so
/// the refusal happens before any CRDT mutation, any snapshot write and any
/// delta publish: a mutation accepted on a contested roster is an act taken
/// under disputed membership even when the CRDT data itself is recoverable
/// (the ADR's own answer to the warn-only argument it rejected).
///
/// The refusal goes through the shared marker gate and bumps
/// `fork_quarantine_refusals` once. Sessions without an active local seat
/// receive only a membership error; durable operators retain the §5 body.
///
/// WHY it runs BEFORE [`ensure_task_list_access`] rather than after: #153's
/// guard resolves the group with a single-spelling `named_groups.get(id)`, so
/// for a group filed under a local alias it answers 403 "not a member" to a
/// request naming the stable id. Ordering the quarantine check after it would
/// make the alias case fail closed for the wrong, undiagnosable reason — the
/// exact "right outcome, wrong reason" defect slice 3 found on row 18 — and
/// R5's condition for removing the warn-only window was that an authorized
/// operator learns WHY. A session without a local seat must not inspect the
/// marker, even though quarantine containment remains unconditional. Slice 3
/// set the same precedence on
/// `delegate_group_authority`, where the quarantine refusal precedes the
/// ban/role checks.
async fn reject_quarantined_task_mutation(
    state: &Arc<AppState>,
    id: &str,
    actor: &crate::server::rider_auth::ActorContext,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let scoped = parse_group_scoped_task_list_id(id)?;
    if scoped.is_malformed() {
        return None;
    }
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, &scoped.group_id)?;
    crate::server::routes::named_groups::reject_fork_quarantined_for_actor(
        state,
        &scoped.group_id,
        info,
        actor,
    )
}

/// Apply group authorization to a task list handle at the CRDT layer.
///
/// If the list `id` is group-scoped (`x0x.group.<gid>.symphony.<lid>`), look
/// up the group's active members and call `set_authorized_agents` so remote
/// CRDT admission rejects claims/completions from non-members. For plain
/// (non-scoped) lists this is a no-op.
///
/// This closes the gap where group membership was enforced at REST but not at
/// replication admission: a remote peer who subscribes to the topic but is not
/// a group member cannot inject operations even with a valid signature.
pub(in crate::server) async fn apply_group_authorization(
    state: &Arc<AppState>,
    id: &str,
    handle: &x0x::TaskListHandle,
) {
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        return; // plain list — no group authorization
    };
    if scoped.is_malformed() {
        return;
    }
    if let Some(agents) = active_group_members(state, &scoped.group_id).await {
        handle.set_authorized_agents(agents).await;
    }
    // The gate goes on even for a group this node cannot resolve yet: it
    // resolves the marker LIVE on every delta, so installing it costs nothing
    // while there is no record and covers the case where the record (and its
    // marker) arrives afterwards. The previous early return on an unresolvable
    // group left such a list permanently ungated, which ADR-0068's alias-keyed
    // row forbids.
    install_task_ingest_gate(state, &scoped.group_id, handle);
}

/// The group's ACTIVE members as CRDT writer identities, or `None` when this
/// node holds no resolvable record for `group_id` (admission is left open, as
/// it has always been for an unknown group).
///
/// Resolved through [`crate::server::resolve_group_entry_locked`], not a bare
/// `named_groups.get()`: the roster map is keyed by whichever alias this node
/// learned the group under, while a task-list id carries the spelling its
/// creator used. The single-spelling read this replaced left an alias-keyed
/// group's list with open admission AND no ingest gate.
async fn active_group_members(
    state: &Arc<AppState>,
    group_id: &str,
) -> Option<std::collections::HashSet<x0x::identity::AgentId>> {
    let groups = state.named_groups.read().await;
    let (_, info) = crate::server::resolve_group_entry_locked(&groups, group_id)?;
    Some(active_members_of(info))
}

/// The active members of one already-resolved record, as CRDT writer
/// identities. Split out so the roster read and the ADR-0067 token read in
/// [`TaskQuarantineIngestGate::with_pinned_roster`] happen under ONE guard
/// (#756 review P1).
fn active_members_of(
    info: &x0x::groups::GroupInfo,
) -> std::collections::HashSet<x0x::identity::AgentId> {
    let mut agents = std::collections::HashSet::new();
    for (agent_hex, member) in &info.members_v2 {
        if matches!(member.state, x0x::groups::GroupMemberState::Active) {
            if let Ok(bytes) = hex::decode(agent_hex) {
                if bytes.len() == x0x::identity::PEER_ID_LENGTH {
                    let mut arr = [0u8; x0x::identity::PEER_ID_LENGTH];
                    arr.copy_from_slice(&bytes);
                    agents.insert(x0x::identity::AgentId(arr));
                }
            }
        }
    }
    agents
}

/// Everything the CRDT layer needs to know about this list's named group,
/// gathered BEFORE the list's replication starts.
///
/// #732 finding 3: [`apply_group_authorization`] can only run on a handle that
/// already exists, and the constructor starts the delta listener before it
/// returns one — so on a restart with a quarantined group a peer delta could
/// merge and persist into a list the marker says is frozen. Pass this to
/// `Agent::{create,join}_task_list_persistent_bound` instead and the gate is in
/// place before the listener is. Returns an empty binding for a list with no
/// group scoping, which therefore behaves exactly as it did before ADR-0068.
pub(in crate::server) async fn group_task_list_binding(
    state: &Arc<AppState>,
    id: &str,
) -> x0x::TaskListBinding {
    let mut binding = x0x::TaskListBinding::default();
    if legacy_space_board_prefix(id).is_some() {
        // #895 (omp finding 1): a legacy plaintext board answers state
        // requests only from members of its group, and not at all once
        // this node has migrated it.
        binding.state_serve_gate = Some(legacy_board_serve_gate(state, id));
        return binding;
    }
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        return binding;
    };
    if scoped.is_malformed() {
        return binding;
    }
    binding.authorized_agents = active_group_members(state, &scoped.group_id).await;
    // #895: installed for EVERY group-scoped id, including one whose group
    // this node cannot resolve yet — the protector resolves live and fails
    // closed (no publish, no merge) until the group is known.
    binding.delta_protector = Some(std::sync::Arc::new(GroupTaskDeltaProtector {
        state: Arc::downgrade(state),
        group_id: scoped.group_id.clone(),
        topic: id.to_string(),
    }));
    binding.ingest_gate = Some(std::sync::Arc::new(TaskQuarantineIngestGate {
        state: Arc::downgrade(state),
        group_id: scoped.group_id,
    }));
    binding
}

/// #895: seals a group-scoped task list's wire payloads with its group's
/// CURRENT key, using exactly the mechanism the group's KV stores use:
///
/// - `MlsEncrypted` on the GSS plane: [`x0x::crdt::sealed::seal_gss_task_payload`]
///   (current shared-secret epoch; AAD binds group, record id and epoch).
/// - `MlsEncrypted` on the TreeKEM plane: the live TreeKEM store protector
///   ([`super::stores::treekem_task_list_protector`]).
/// - `SignedPublic`: plaintext, as before (the group's content is public).
/// - Unresolvable group: fail closed — nothing is sealed, opened or admitted.
///
/// Resolved on EVERY call, through the one both-spellings resolver, so a GSS
/// rotation or TreeKEM commit (e.g. on member removal) applies to the very
/// next delta.
struct GroupTaskDeltaProtector {
    state: std::sync::Weak<AppState>,
    /// The group as spelled in the list id.
    group_id: String,
    /// The list id, which is also its gossip topic.
    topic: String,
}

/// The group a task list is bound to, as this node holds it right now.
enum TaskListPlane {
    Public,
    Gss(Box<x0x::groups::GroupInfo>),
    TreeKem(x0x::kv::SharedTreeKemKvProtector, String),
}

impl GroupTaskDeltaProtector {
    async fn plane(&self) -> x0x::crdt::Result<(Arc<AppState>, TaskListPlane)> {
        let unavailable =
            |why: &str| x0x::crdt::CrdtError::Gossip(format!("group task list sealing: {why}"));
        let state = self
            .state
            .upgrade()
            .ok_or_else(|| unavailable("daemon is shutting down"))?;
        let (group_key, info) = {
            let groups = state.named_groups.read().await;
            let (key, info) = crate::server::resolve_group_entry_locked(&groups, &self.group_id)
                .ok_or_else(|| unavailable("group is not known on this node"))?;
            (key.to_string(), info.clone())
        };
        if info.withdrawn {
            return Err(unavailable("group is withdrawn"));
        }
        let plane = match info.policy.confidentiality {
            x0x::groups::GroupConfidentiality::SignedPublic => TaskListPlane::Public,
            x0x::groups::GroupConfidentiality::MlsEncrypted => match info.secure_plane {
                x0x::mls::SecureGroupPlane::Gss => TaskListPlane::Gss(Box::new(info)),
                x0x::mls::SecureGroupPlane::TreeKem => {
                    let stable = info.stable_group_id().to_string();
                    let protector =
                        super::stores::treekem_task_list_protector(&state, &group_key, &info)
                            .ok_or_else(|| unavailable("TreeKEM group is not eligible"))?;
                    TaskListPlane::TreeKem(protector, stable)
                }
            },
        };
        Ok((state, plane))
    }
}

impl x0x::crdt::TaskDeltaProtector for GroupTaskDeltaProtector {
    fn seal<'a>(
        &'a self,
        kind: x0x::kv::KvMutationKind,
        payload: &'a [u8],
    ) -> x0x::crdt::sealed::TaskSealFuture<'a, Option<x0x::crdt::sealed::SealedTaskRecordBody>>
    {
        Box::pin(async move {
            let (state, plane) = self.plane().await?;
            let signing =
                x0x::kv::AuthorSigning::from_keypair(state.agent.identity().agent_keypair())
                    .map_err(|e| {
                        x0x::crdt::CrdtError::Gossip(format!("task author signing: {e}"))
                    })?;
            match plane {
                TaskListPlane::Public => Ok(None),
                TaskListPlane::Gss(info) => x0x::crdt::sealed::seal_gss_task_payload(
                    &info,
                    &signing,
                    kind,
                    &self.topic,
                    payload,
                )
                .map(Some),
                TaskListPlane::TreeKem(protector, stable) => {
                    let record_id =
                        x0x::crdt::sealed::group_task_list_record_id(&stable, &self.topic);
                    protector
                        .seal_record(&signing, kind, &record_id, payload, false)
                        .await
                        .map(|record| {
                            Some(x0x::crdt::sealed::SealedTaskRecordBody::TreeKem(record))
                        })
                        .map_err(|e| {
                            x0x::crdt::CrdtError::Gossip(format!("TreeKEM task seal: {e}"))
                        })
                }
            }
        })
    }

    fn open<'a>(
        &'a self,
        body: &'a x0x::crdt::sealed::SealedTaskRecordBody,
    ) -> x0x::crdt::sealed::TaskSealFuture<'a, x0x::crdt::sealed::OpenedTaskPayload> {
        Box::pin(async move {
            let (_, plane) = self.plane().await?;
            match (plane, body) {
                (
                    TaskListPlane::Gss(info),
                    x0x::crdt::sealed::SealedTaskRecordBody::Gss(record),
                ) => x0x::crdt::sealed::open_gss_task_record(&info, &self.topic, record),
                (
                    TaskListPlane::TreeKem(protector, stable),
                    x0x::crdt::sealed::SealedTaskRecordBody::TreeKem(record),
                ) => {
                    let record_id =
                        x0x::crdt::sealed::group_task_list_record_id(&stable, &self.topic);
                    let opened = protector
                        .open_record(&record_id, record)
                        .await
                        .map_err(|e| {
                            x0x::crdt::CrdtError::Gossip(format!("TreeKEM task open: {e}"))
                        })?;
                    // `open_record` already required a current WRITER for a
                    // non-read-only record; a read-only one is never content.
                    x0x::crdt::sealed::accept_opened(
                        opened.mutation.kind,
                        !opened.reader_only,
                        opened.mutation.author_id,
                        opened.mutation.payload,
                    )
                }
                _ => Err(x0x::crdt::CrdtError::Gossip(
                    "sealed task record does not match the group's current plane".to_string(),
                )),
            }
        })
    }

    fn admits_plaintext(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move { matches!(self.plane().await, Ok((_, TaskListPlane::Public))) })
    }

    fn on_rejected(&self, reason: x0x::crdt::TaskSealRejection) {
        if let Some(state) = self.state.upgrade() {
            state
                .groups_diagnostics
                .record_task_delta_seal_rejected(&self.group_id);
            tracing::debug!(group_id = %self.group_id, ?reason, "[tasks] task delta refused (#895)");
        }
    }

    fn local_agent(&self) -> Option<x0x::identity::AgentId> {
        self.state.upgrade().map(|state| state.agent.agent_id())
    }

    /// #975: a sealed record is published only while the epoch it was
    /// sealed under is still current, and the epoch is held fixed through the
    /// publish call.
    ///
    /// - GSS: the daemon's GSS publication gate (#973). Every authoritative
    ///   roster commit holds it exclusively from installing the rotated
    ///   secret through durable save or rollback, so under a read permit the
    ///   live `secret_epoch` cannot move.
    /// - TreeKEM: the group's membership lock, then its live ratchet mutex —
    ///   the same order `seal_record` takes them. Every ratchet epoch change
    ///   needs the ratchet mutex.
    ///
    /// Called with no lock held (after `seal` has returned), and takes each
    /// lock once: nothing here re-enters a lock the caller or `seal` holds.
    fn confirm_publication<'a>(
        &'a self,
        body: &'a x0x::crdt::sealed::SealedTaskRecordBody,
    ) -> x0x::crdt::sealed::TaskSealFuture<'a, x0x::crdt::TaskPublication> {
        Box::pin(async move {
            let unavailable = |why: &str| {
                x0x::crdt::CrdtError::Gossip(format!("group task list publication: {why}"))
            };
            let state = self
                .state
                .upgrade()
                .ok_or_else(|| unavailable("daemon is shutting down"))?;
            match body {
                x0x::crdt::sealed::SealedTaskRecordBody::Gss(record) => {
                    let permit = Arc::clone(&state.gss_publication_gate).read_owned().await;
                    let current = {
                        let groups = state.named_groups.read().await;
                        crate::server::resolve_group_entry_locked(&groups, &self.group_id).map(
                            |(_, info)| {
                                (
                                    info.secret_epoch,
                                    info.secure_plane == x0x::mls::SecureGroupPlane::Gss,
                                )
                            },
                        )
                    };
                    let (current_epoch, still_gss) =
                        current.ok_or_else(|| unavailable("group is not known"))?;
                    Ok(if still_gss && current_epoch == record.epoch {
                        x0x::crdt::TaskPublication::Current(
                            x0x::crdt::TaskPublicationPermit::holding(permit),
                        )
                    } else {
                        x0x::crdt::TaskPublication::Stale
                    })
                }
                x0x::crdt::sealed::SealedTaskRecordBody::TreeKem(record) => {
                    let group_key = {
                        let groups = state.named_groups.read().await;
                        crate::server::resolve_group_entry_locked(&groups, &self.group_id)
                            .map(|(key, _)| key.to_string())
                    };
                    let group_key = group_key.ok_or_else(|| unavailable("group is not known"))?;
                    let membership =
                        super::named_groups::group_membership_lock(&state, &group_key).await;
                    let membership_guard = membership.lock_owned().await;
                    let live = state
                        .treekem_groups
                        .read()
                        .await
                        .get(&group_key)
                        .cloned()
                        .ok_or_else(|| unavailable("live TreeKEM ratchet is unavailable"))?;
                    let ratchet = live.lock_owned().await;
                    Ok(if ratchet.epoch() == record.epoch {
                        x0x::crdt::TaskPublication::Current(
                            x0x::crdt::TaskPublicationPermit::holding((membership_guard, ratchet)),
                        )
                    } else {
                        x0x::crdt::TaskPublication::Stale
                    })
                }
            }
        })
    }
}

/// ADR-0068 D2: the inbound-delta admission gate for a group-scoped task list.
///
/// WHY a `Weak<AppState>`: the gate is installed on a `TaskListHandle` the
/// `AppState` owns (`state.task_lists`), so an `Arc` here would be a cycle and
/// would keep the daemon's state alive for the life of the CRDT sync. An
/// expired `Weak` means the daemon is gone, and a gate with no state suspends
/// nothing — the sync loops are being torn down in the same breath.
///
/// WHY it resolves through
/// [`crate::server::delegations::fork_quarantine_marker`]: the `named_groups`
/// map is keyed by whichever alias this node learned the group under, while a
/// task-list id carries the spelling its creator used. That wrapper is the one
/// resolver, so an alias-keyed group is gated rather than silently ungated —
/// the same defect review found three times in slices 3, 4 and 6.
struct TaskQuarantineIngestGate {
    state: std::sync::Weak<AppState>,
    /// The group this list is bound to, as spelled in the list id. The
    /// resolver accepts either spelling.
    group_id: String,
}

impl x0x::crdt::TaskIngestGate for TaskQuarantineIngestGate {
    fn suspended(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let Some(state) = self.state.upgrade() else {
                return false; // daemon gone — nothing left to contain
            };
            crate::server::delegations::fork_quarantine_marker(&state, &self.group_id)
                .await
                .is_some()
        })
    }

    /// ADR-0067's token for the bound group, resolved under both spellings by
    /// the one resolver (`lifecycle_epoch_token_locked` is the thin wrapper over
    /// it). `None` when this node holds no record for the id — which the CRDT
    /// side must treat as a mismatch, never as "unchanged".
    fn epoch_token(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<x0x::groups::LifecycleEpochToken>> + Send + '_>,
    > {
        Box::pin(async move {
            let state = self.state.upgrade()?;
            let groups = state.named_groups.read().await;
            crate::server::lifecycle_epoch_token_locked(&groups, &self.group_id)
        })
    }

    /// Pin the roster and hand the drain the live active-member set with the
    /// lifecycle token derived from that same pinned read (#732 finding 4,
    /// hardened by #756 review r2).
    ///
    /// One `named_groups` **read** guard is taken and held across the caller's
    /// synchronous closure, so the whole re-authorize-then-merge step sees one
    /// roster state and a roster WRITER cannot commit in the middle of it. The
    /// caller already holds the task-list write guard, so this is the documented
    /// `TaskList` → `named_groups` order — acquiring the roster second is that
    /// order, not its inverse. The closure does no I/O and no `await`, and the
    /// batch it runs is bounded by the ADR-0068 buffer bounds.
    ///
    /// `apply(None)` is still called when the record cannot be resolved (both
    /// spellings tried) or the daemon has gone, so the drain can abandon rather
    /// than merge on a stale set.
    fn with_pinned_roster<'a>(
        &'a self,
        apply: &'a mut (dyn FnMut(Option<&x0x::crdt::AuthorizedRoster>) + Send),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(state) = self.state.upgrade() else {
                apply(None);
                return;
            };
            let groups = state.named_groups.read().await;
            let pinned = crate::server::resolve_group_entry_locked(&groups, &self.group_id)
                .and_then(|(_, info)| {
                    let token =
                        crate::server::lifecycle_epoch_token_locked(&groups, &self.group_id)?;
                    Some(x0x::crdt::AuthorizedRoster {
                        agents: active_members_of(info),
                        token,
                    })
                });
            // Synchronous, under the guard: nothing can write the roster until
            // `apply` returns.
            apply(pinned.as_ref());
        })
    }

    fn on_buffered(&self, depth: usize, bytes: usize) {
        if let Some(state) = self.state.upgrade() {
            state
                .groups_diagnostics
                .record_task_delta_quarantine_buffered(&self.group_id);
            tracing::debug!(
                group_id = %self.group_id,
                depth,
                bytes,
                "[tasks] inbound task delta held under fork quarantine (ADR-0068 D2)"
            );
        }
    }

    fn on_dropped(&self, count: u64) {
        if let Some(state) = self.state.upgrade() {
            state
                .groups_diagnostics
                .record_task_deltas_quarantine_dropped(&self.group_id, count);
        }
    }

    fn on_applied(&self, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(state) = self.state.upgrade() {
            state
                .groups_diagnostics
                .record_task_deltas_quarantine_applied(&self.group_id, count);
        }
    }
}

/// Install the ADR-0068 D2 gate on a group-scoped task list, if it has none.
///
/// Called from [`apply_group_authorization`] — the one choke point every path
/// that produces a live handle already runs (create, join, and subscription
/// rehydration), which is what keeps the gate from being missed on one of them.
/// A list with no group binding never reaches here and is unaffected.
pub(in crate::server) fn install_task_ingest_gate(
    state: &Arc<AppState>,
    group_id: &str,
    handle: &x0x::TaskListHandle,
) {
    handle.install_ingest_gate(std::sync::Arc::new(TaskQuarantineIngestGate {
        state: Arc::downgrade(state),
        group_id: group_id.to_string(),
    }));
}

/// #759: every spelling of `group_id` a group-scoped task-list id could carry
/// for the group the id resolves to — the id itself, the resolved map key,
/// the stable id, and every map key that shares that stable id (an
/// alias-keyed store holds sibling spellings). A task-list id embeds the
/// spelling its creator used (`TaskQuarantineIngestGate`'s docs), so an
/// exact-string match against any ONE spelling — the manual route's stable
/// id, the apply path's map key — can silently miss a list that is bound to
/// the very group whose marker just cleared. Resolved through the one
/// resolver's rule (exact key, then stable id); unresolvable ids keep only
/// themselves, preserving the pre-#759 exact-match behavior for a record
/// this node no longer holds.
pub(in crate::server) fn group_task_resume_spellings(
    groups: &std::collections::HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> std::collections::BTreeSet<String> {
    let mut spellings = std::collections::BTreeSet::new();
    spellings.insert(group_id.to_string());
    let Some((map_key, info)) = crate::server::resolve_group_entry_locked(groups, group_id) else {
        return spellings;
    };
    let stable = info.stable_group_id().to_string();
    spellings.insert(map_key.to_string());
    spellings.insert(stable.clone());
    for (key, sibling) in groups {
        if sibling.stable_group_id() == stable {
            spellings.insert(key.clone());
        }
    }
    spellings
}

/// ADR-0068 D2: apply the deltas held for `group_id`'s task lists now that its
/// marker is gone. Returns how many deltas were applied across all its lists.
///
/// The listener's own poll would get there within
/// `TASK_QUARANTINE_DRAIN_POLL_SECS`; calling this from the clear route makes an
/// operator's manual clear take effect at once instead, which is the difference
/// between "the list caught up while I watched" and "the list looked stuck for
/// another five seconds". Since #759 the same accelerator runs after the
/// OWNER-ANCHORED clears that fire inside the metadata-apply machinery and the
/// explicit owner seal route — via a durable-clear notification propagated to
/// callers that have released every membership/roster/persistence guard —
/// because the poll only arms while the buffer is NON-empty: with an empty
/// buffer a clear left the listener's captured authorized-agent set stale
/// indefinitely (until rehydrate), and the drain's empty-buffer arm is what
/// refreshes it. The poll remains the guarantee for every other clear writer.
///
/// `group_id` may be any spelling: matching runs over
/// [`group_task_resume_spellings`], so an alias-keyed list is not lost to
/// exact-string filtering. Residual: a list whose scoped id carries a spelling
/// that is no longer resolvable in the map (a pruned alias) matches only that
/// spelling — its gate already resolves nothing either, so such a list is
/// outside containment bookkeeping entirely.
///
/// **Must be called with NO `named_groups` guard held.** It awaits each list's
/// CRDT write lock, and the ingest gate takes `named_groups.read()` inside that
/// lock; the lock order is `TaskList` → `named_groups` (see `admit_or_buffer`),
/// so holding the roster lock here would invert it. The drain itself is a
/// #759 lifecycle section per list (see `resume_quarantined_ingest`), so it is
/// also serialized against a draining retire of the same list.
pub(in crate::server) async fn resume_group_task_ingest(
    state: &Arc<AppState>,
    group_id: &str,
) -> usize {
    // Resolve the spellings under one brief read, then release: the drain
    // below must not hold the roster guard (lock order above).
    let spellings = {
        let groups = state.named_groups.read().await;
        group_task_resume_spellings(&groups, group_id)
    };
    // Snapshot the matching handles, then release the registry lock: the drain
    // itself takes per-list CRDT locks and must not hold the map meanwhile.
    let handles: Vec<x0x::TaskListHandle> = {
        let lists = state.task_lists.read().await;
        lists
            .iter()
            .filter(|(id, _)| {
                parse_group_scoped_task_list_id(id).is_some_and(|scoped| {
                    !scoped.is_malformed() && spellings.contains(&scoped.group_id)
                })
            })
            .map(|(_, handle)| handle.clone())
            .collect()
    };
    let mut applied = 0usize;
    for handle in handles {
        applied += handle.resume_quarantined_ingest().await;
    }
    if applied > 0 {
        tracing::info!(
            group_id = %group_id,
            applied,
            "[tasks] applied task deltas held under fork quarantine after the clear (ADR-0068 D2)"
        );
    }
    applied
}

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

/// POST /task-lists request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateTaskListRequest {
    pub(in crate::server) name: String,
    pub(in crate::server) topic: String,
}

/// POST /task-lists/:id/tasks request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AddTaskRequest {
    pub(in crate::server) title: String,
    #[serde(default)]
    pub(in crate::server) description: Option<String>,
}

/// PATCH /task-lists/:id/tasks/:tid request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct UpdateTaskRequest {
    pub(in crate::server) action: String, // "claim" or "complete"
    /// Optional **local-replica** fencing precondition (opaque token). Echo
    /// the `fence_token` from a prior GET/mutation verbatim. If it does not
    /// match THIS daemon's current `(epoch, revision)`, the mutation is
    /// rejected with 409 and nothing changes. This is NOT a distributed
    /// compare-and-swap: two daemons at the same token both accept. A token
    /// captured before a daemon restart never matches post-restart (the epoch
    /// differs), closing the restart-ABA window.
    #[serde(default)]
    pub(in crate::server) fence_token: Option<String>,
    /// Hex delegation digest (ADR-0040): authorization evidence for a
    /// `task_execute` claim/complete performed under a delegation. Validated
    /// against the group's durably-committed delegation set before the
    /// mutation runs; invalid ⇒ 403 and nothing changes.
    #[serde(default)]
    pub(in crate::server) delegation: Option<String>,
}

/// Task list entry.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskListEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) topic: String,
    /// ADR-0066 §3c row 20 (read half): present and `true` only while the
    /// bound group carries a fork-quarantine marker. Absent — so the
    /// response is byte-identical to the pre-ADR shape — otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::server) fork_quarantined: Option<bool>,
    /// The marker itself, in the same shape the refusal body carries under
    /// `fork_quarantine`, so a client parses one shape whether the
    /// operation was served-with-a-warning or refused outright.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::server) fork_quarantine: Option<serde_json::Value>,
}

/// Task snapshot for API response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) title: String,
    pub(in crate::server) description: String,
    /// Legacy Display string ("empty" | "claimed:<hex>" | "done:<hex>").
    /// Kept for backward compatibility — prefer the structured fields below.
    pub(in crate::server) state: String,
    pub(in crate::server) assignee: Option<String>,
    pub(in crate::server) priority: u8,
    /// Hex AgentId of the deterministic claim winner; null if never claimed.
    pub(in crate::server) claimed_by: Option<String>,
    /// Unix-ms timestamp of the winning claim; null if never claimed.
    pub(in crate::server) claimed_at: Option<u64>,
    /// Hex AgentId of the deterministic completion winner; null unless done.
    pub(in crate::server) completed_by: Option<String>,
    /// Unix-ms timestamp of the winning completion; null unless done.
    pub(in crate::server) completed_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /task-lists
pub(in crate::server) async fn list_task_lists(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Snapshot the keys, then release the lock before the per-id membership
    // check (which takes `named_groups.read()`). Holding both read locks at
    // once is safe for an RwLock, but collecting first keeps the critical
    // section short and avoids re-entrancy surprises.
    let ids: Vec<String> = state.task_lists.read().await.keys().cloned().collect();
    // #153: filter the collection through the same membership guard as the
    // per-id read/write handlers, so this endpoint does not leak the existence
    // or exact topics of group-scoped task lists the local agent is not an
    // active member of. (The per-id handlers already 403 those; this prevents
    // the collection from enumerating them.) Red-team review of #166 found
    // this collection endpoint was the sole unguarded path.
    let mut entries = Vec::with_capacity(ids.len());
    for id in ids {
        if ensure_task_list_access(&state, &id).await.is_ok() {
            // ADR-0066 §3c row 20 (read half): the collection SERVES,
            // annotated. An operator listing lists during an incident must
            // be able to see which of them are bound to a contested roster
            // — that is what tells them why a mutation on one of these is
            // being refused, without a second round trip per list.
            let quarantine = task_list_fork_quarantine(&state, &id).await;
            entries.push(TaskListEntry {
                id: id.clone(),
                topic: id, // topic is used as ID
                fork_quarantined: quarantine.as_ref().map(|_| true),
                fork_quarantine: quarantine.as_ref().map(|(_, marker)| {
                    crate::server::routes::named_groups::fork_quarantine_annotation(marker)
                }),
            });
        }
    }
    Json(serde_json::json!({ "ok": true, "task_lists": entries }))
}

/// POST /task-lists
pub(in crate::server) async fn create_task_list(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<CreateTaskListRequest>,
) -> impl IntoResponse {
    // ADR-0066 §3c row 20: binding a NEW task list to a contested roster is
    // a mutation, not a read — it derives the CRDT's authorized-agent set
    // from the disputed membership (`apply_group_authorization` below),
    // writes a durable subscription registration and starts a sync listener
    // that publishes deltas on the group's topic. Refusing here means none
    // of that happens: no handle, no manifest row, no listener.
    if let Some(refused) = reject_quarantined_task_mutation(&state, &req.topic, &actor).await {
        return refused;
    }
    // #153: creating a group-scoped task list requires membership of that group.
    if let Err(denied) = ensure_task_list_access(&state, &req.topic).await {
        return denied;
    }
    let id = req.topic.clone();
    // #895: a legacy board this node migrated stays retired — an old GUI tab
    // must not bring its plaintext sync back.
    if legacy_space_board_retired(&state, &id).await {
        return api_error(
            StatusCode::GONE,
            "this space board moved to the group's encrypted list (#895)",
        );
    }
    // Reserve the entire handle+manifest transaction for this (kind,id) so
    // a concurrent create/rehydrate for the same id cannot interleave handle
    // insertion with failure rollback, or spawn a duplicate listener.
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_TASK_LIST, &id)
            .await;
    let _guard = reservation.lock().await;
    // Under the reservation: if a handle already exists (created by a prior
    // successful request or rehydration), return conflict rather than
    // overwriting it and leaking the existing sync listener.
    if state.task_lists.read().await.contains_key(&id) {
        return api_error(StatusCode::CONFLICT, "task list already exists");
    }
    // #557: the persistent variant arms per-list content snapshots under the
    // instance data dir (`task-lists/<id>.bin`) so restarts restore content,
    // not just the registration; it fails closed on a corrupt snapshot.
    // #732 finding 3: the group binding (authorized writers + the ADR-0068 D2
    // gate) is gathered here and installed by the constructor BEFORE it starts
    // the delta listener, so no inbound delta can merge ungated.
    let binding = group_task_list_binding(&state, &id).await;
    match state
        .agent
        .create_task_list_persistent_bound(
            &req.name,
            &req.topic,
            &state.task_list_state_dir,
            binding,
        )
        .await
    {
        Ok(handle) => {
            let version = handle.version().await;
            // Re-apply group authorization now the listener is running: it
            // refreshes the roster read taken for the binding above (the gate
            // install is set-once and keeps the one already in place).
            apply_group_authorization(&state, &id, &handle).await;
            state.task_lists.write().await.insert(id.clone(), handle);
            // Persist the registration so it survives a daemon restart
            // (rehydrated after join_network — see crdt_subscriptions). This
            // is a durable transaction: if the manifest write fails we roll
            // back the just-inserted live handle and surface the error, so the
            // registration is never acknowledged as durable when it is not.
            let entry = crdt_subscriptions::CrdtSubscriptionEntry {
                kind: crdt_subscriptions::KIND_TASK_LIST.to_string(),
                id: id.clone(),
                name: req.name.clone(),
                topic: req.topic.clone(),
                role: crdt_subscriptions::ROLE_CREATED.to_string(),
                extra: serde_json::Map::new(),
            };
            if let Err(e) = crdt_subscriptions::record(&state, entry).await {
                tracing::error!(
                    topic = %req.topic,
                    "failed to persist task-list subscription registration: {e}"
                );
                // Roll back AND stop the discarded handle's sync — its
                // bootstrap requester is infinite while unconverged
                // (issue #238) and would otherwise chatter until shutdown.
                // #759: the draining retire, so "rolled back" also means
                // "no in-flight merge or snapshot write lands afterwards".
                // The registry guard is dropped BEFORE awaiting the drain:
                // a receive section takes no registry lock, so this is
                // safety, not correctness — but holding the map across the
                // drain would stall every other task-list route for the
                // length of one merge section. The section's lock order is
                // `lifecycle` -> `TaskList` write -> `named_groups` read
                // (-> persist gate -> `TaskList` read); none of those is
                // held here.
                let discarded = state.task_lists.write().await.remove(&id);
                if let Some(h) = discarded {
                    h.cancel_sync_and_drain().await;
                }
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist subscription registration",
                );
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "id": id,
                    "version": version.revision,
                    "fence_token": version.to_wire(),
                    "committed": "local",
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// #895: the list segment of a GUI space Board's group-scoped id,
/// `x0x.group.<gid>.symphony.board`.
const SPACE_BOARD_LIST: &str = "board";

/// #895: for a space Board id, the legacy PLAINTEXT board id the GUI used
/// before the Board moved to the group-scoped (sealed) list:
/// `x0x-board-<first 16 chars of the group id>`. `None` for any other list.
pub(in crate::server) fn legacy_space_board_id(id: &str) -> Option<String> {
    let scoped = parse_group_scoped_task_list_id(id)?;
    if scoped.is_malformed() || scoped.list_id != SPACE_BOARD_LIST {
        return None;
    }
    let prefix = scoped.group_id.get(..16).unwrap_or(&scoped.group_id);
    Some(format!("x0x-board-{prefix}"))
}

/// #895: the durable "this node has migrated this board" marker, keyed by
/// the LEGACY board id so both the migration and the legacy list's
/// retirement (serve gate, rehydration, re-creation) can find it.
fn space_board_migration_marker(state: &AppState, legacy_id: &str) -> std::path::PathBuf {
    state.task_list_state_dir.join(format!(
        "board-migration-{}.done",
        blake3::hash(legacy_id.as_bytes()).to_hex()
    ))
}

/// #895: the group-id prefix of a legacy plaintext space board id
/// (`x0x-board-<first 16 chars of the group id>`), or `None`.
fn legacy_space_board_prefix(id: &str) -> Option<&str> {
    id.strip_prefix("x0x-board-")
        .filter(|prefix| !prefix.is_empty())
}

/// #895: whether this node has migrated — and so retired — the legacy
/// plaintext board `id`. `false` for any other list.
pub(in crate::server) async fn legacy_space_board_retired(state: &AppState, id: &str) -> bool {
    legacy_space_board_prefix(id).is_some()
        && tokio::fs::try_exists(space_board_migration_marker(state, id))
            .await
            .unwrap_or(false)
}

/// #895: whether `sender` is an ACTIVE member of the group a legacy board id
/// abbreviates (a group whose map key or stable id starts with the prefix).
/// An unsigned request, an unknown group or a non-member answers `false`.
pub(in crate::server) fn legacy_board_requester_is_member(
    groups: &std::collections::HashMap<String, x0x::groups::GroupInfo>,
    legacy_id: &str,
    sender: Option<&x0x::identity::AgentId>,
) -> bool {
    let (Some(prefix), Some(sender)) = (legacy_space_board_prefix(legacy_id), sender) else {
        return false;
    };
    let sender_hex = hex::encode(sender.as_bytes());
    groups.iter().any(|(key, info)| {
        (key.starts_with(prefix) || info.stable_group_id().starts_with(prefix))
            && info.has_active_member(&sender_hex)
    })
}

/// #895: the state-serve gate for a legacy plaintext board. It answers a
/// `StateRequest` only from an active member of the board's group, and
/// never once this node has migrated (retired) the board — so a non-member
/// that derives the topic cannot make a holder broadcast the list.
fn legacy_board_serve_gate(state: &Arc<AppState>, legacy_id: &str) -> x0x::crdt::StateServeGate {
    let weak = Arc::downgrade(state);
    let legacy_id = legacy_id.to_string();
    Arc::new(move |sender: Option<x0x::identity::AgentId>| {
        let weak = weak.clone();
        let legacy_id = legacy_id.clone();
        Box::pin(async move {
            let Some(state) = weak.upgrade() else {
                return false;
            };
            if legacy_space_board_retired(&state, &legacy_id).await {
                return false;
            }
            let groups = state.named_groups.read().await;
            legacy_board_requester_is_member(&groups, &legacy_id, sender.as_ref())
        })
    })
}

/// #895 (David, 2026-09-25): whether `agent` may write under the group's
/// write policy — the same rule the group's encrypted stores and the task
/// protector apply (active member; `AdminOnly` ⇒ admin or above;
/// `ModeratedPublic` ⇒ nobody).
fn may_write_group(info: &x0x::groups::GroupInfo, agent: &x0x::identity::AgentId) -> bool {
    let Some(member) = info.members_v2.get(&hex::encode(agent.as_bytes())) else {
        return false;
    };
    if !member.is_active() {
        return false;
    }
    match info.policy.write_access {
        x0x::groups::GroupWriteAccess::MembersOnly => true,
        x0x::groups::GroupWriteAccess::AdminOnly => {
            member.role.at_least(x0x::groups::GroupRole::Admin)
        }
        x0x::groups::GroupWriteAccess::ModeratedPublic => false,
    }
}

/// #895: copy the legacy plaintext space Board into its group-scoped
/// (sealed) list exactly once, then RETIRE the legacy list on this node.
/// Returns `true` when the board needs no migration on this node (not a
/// board, already migrated, or migrated now).
///
/// - Only a member with write permission migrates; anyone else gets `false`
///   and the caller reports `board_migration_pending`.
/// - Idempotent: the durable marker short-circuits re-runs, and the copy
///   keeps each task's id, so a crash before the marker, or two members
///   migrating concurrently, converge instead of duplicating.
/// - A node that does not hold the legacy list has nothing to copy and
///   records the marker.
/// - Retirement (omp review finding 1): once the marker is durable, the
///   legacy sync is cancelled (no more state serves, publishes or listening;
///   its subscriptions drop with its loops) and its handle deregistered. The
///   marker also keeps it from being rehydrated at boot or re-created via
///   REST. Its local snapshot and manifest row stay on disk.
pub(in crate::server) async fn migrate_space_board_once(state: &Arc<AppState>, id: &str) -> bool {
    let Some(legacy) = legacy_space_board_id(id) else {
        return true;
    };
    let marker = space_board_migration_marker(state, &legacy);
    if tokio::fs::try_exists(&marker).await.unwrap_or(false) {
        retire_legacy_space_board(state, &legacy).await;
        return true;
    }
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        return true;
    };
    let may_write = {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &scoped.group_id)
            .is_some_and(|(_, info)| may_write_group(info, &state.agent.agent_id()))
    };
    if !may_write {
        return false;
    }
    let (target, source) = {
        let lists = state.task_lists.read().await;
        (lists.get(id).cloned(), lists.get(&legacy).cloned())
    };
    let Some(target) = target else {
        return false;
    };
    if let Some(source) = source {
        match target.import_tasks_from(&source).await {
            Ok(copied) => tracing::info!(
                board = %id,
                legacy = %legacy,
                copied,
                "[tasks] migrated the legacy plaintext space board (#895)"
            ),
            Err(e) => {
                tracing::warn!(board = %id, "space board migration failed (#895): {e}");
                return false;
            }
        }
    }
    if let Err(e) = tokio::fs::write(&marker, b"").await {
        tracing::warn!(board = %id, "space board migration marker write failed: {e}");
        return false;
    }
    retire_legacy_space_board(state, &legacy).await;
    true
}

/// #895: stop the legacy plaintext board's sync on this node and deregister
/// its live handle. The snapshot and manifest row are kept (local data is
/// not deleted in this slice). Idempotent.
async fn retire_legacy_space_board(state: &AppState, legacy: &str) {
    // Read first: this runs on every board poll once migrated.
    if !state.task_lists.read().await.contains_key(legacy) {
        return;
    }
    let retired = state.task_lists.write().await.remove(legacy);
    if let Some(handle) = retired {
        handle.cancel_sync_and_drain().await;
        tracing::info!(legacy = %legacy, "[tasks] retired the legacy plaintext space board (#895)");
    }
}

/// GET /task-lists/:id/tasks
pub(in crate::server) async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // #153: group-scoped task lists require local-agent membership.
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    // ADR-0066 §3c row 20 (read half): resolved before the task-list lock is
    // taken, so the roster read never nests inside it.
    let quarantine = task_list_fork_quarantine(&state, &id).await;
    // #895: a space Board's first access copies the legacy plaintext board in
    // once (a mutation, so never while the roster is contested).
    let board_migrated = quarantine.is_some() || migrate_space_board_once(&state, &id).await;
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle.list_tasks_with_version().await {
        Ok((tasks, fence)) => {
            let entries: Vec<TaskEntry> = tasks
                .into_iter()
                .map(|t| TaskEntry {
                    id: format!("{}", t.id),
                    title: t.title,
                    description: t.description,
                    state: format!("{}", t.state),
                    assignee: t.assignee.map(|a| hex::encode(a.as_bytes())),
                    priority: t.priority,
                    claimed_by: t.claimed_by.map(|a| hex::encode(a.as_bytes())),
                    claimed_at: t.claimed_at,
                    completed_by: t.completed_by.map(|a| hex::encode(a.as_bytes())),
                    completed_at: t.completed_at,
                })
                .collect();
            let entries_empty = entries.is_empty();
            let mut body = serde_json::json!({
                "ok": true,
                "version": fence.revision,
                "fence_token": fence.to_wire(),
                "tasks": entries,
            });
            // #895: a reader (or a writer that could not migrate yet) sees an
            // explicit pending state instead of an unexplained empty board.
            // Absent for every other list.
            if !board_migrated && entries_empty {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "board_migration_pending".to_string(),
                        serde_json::Value::Bool(true),
                    );
                }
            }
            // ADR-0066 §3c row 20 (read half): reads are NEVER refused —
            // containment must not blind the operator who is reading the
            // list to work out what the contested roster has been doing —
            // but the same response says plainly that the roster this list
            // is bound to is disputed and that mutations are being refused.
            // Absent (byte-identical response) when there is no marker.
            if let Some((_, marker)) = &quarantine {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "fork_quarantined".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    obj.insert(
                        "fork_quarantine".to_string(),
                        crate::server::routes::named_groups::fork_quarantine_annotation(marker),
                    );
                }
            }
            (StatusCode::OK, Json(body))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /task-lists/:id/tasks
pub(in crate::server) async fn add_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    // ADR-0066 §3c row 20: refuse BEFORE the handle is resolved, so nothing
    // downstream can mutate the CRDT, write the `task-lists/<id>.bin`
    // snapshot or publish a delta. The ordering is observable: on a
    // quarantined group this returns 409 even for a list this daemon does
    // not hold, where the ungated path returns 404.
    if let Some(refused) = reject_quarantined_task_mutation(&state, &id, &actor).await {
        return refused;
    }
    // #153: group-scoped task lists require local-agent membership (write too).
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle
        .add_task_versioned(req.title, req.description.unwrap_or_default())
        .await
    {
        Ok((task_id, version)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "task_id": format!("{task_id}"),
                "version": version,
                "committed": "local",
            })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PATCH /task-lists/:id/tasks/:tid
pub(in crate::server) async fn update_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    // ADR-0066 §3c row 20: claim/complete is a mutation, refused before any
    // of this handler's work — before the handle is resolved, before the
    // fence token is parsed and before the delegation branch below. That
    // ordering subsumes slice 3's row-17 gate (`:~560`), which only guards
    // the delegation-CITING branch: a plain claim on a contested roster is
    // this row's business and used to be admitted. Composition is
    // deliberate, not accidental duplication — because this gate returns
    // first, a quarantined group produces exactly ONE refusal and one
    // `fork_quarantine_refusals` increment, and row 17's check stays wired
    // for the case where a future change narrows row 20's scope.
    if let Some(refused) = reject_quarantined_task_mutation(&state, &id, &actor).await {
        return refused;
    }
    // #153: group-scoped task lists require local-agent membership (write too).
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid task ID (expected 64 hex chars)");
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    // Parse the opaque fence token.
    //
    // Distinguish **absent** (None ⇒ unconditional advisory commit) from
    // **present but malformed** (parse error ⇒ 400 BAD_REQUEST, non-mutating).
    // Collapsing the two would let a corrupt/legacy/attacker token silently
    // downgrade a fenced request to an unfenced mutation.
    let expected = match req.fence_token.as_deref() {
        None => None,
        Some(s) => match x0x::FenceToken::from_wire(s) {
            Ok(token) => Some(token),
            Err(_) => {
                // Machine-readable error code — the API contract (and
                // daemon_api_claim_malformed_fence_token_is_rejected_non_mutating)
                // matches on this exact string.
                return bad_request("malformed_fence_token");
            }
        },
    };

    // ADR-0040 task-execute authorization (review r2): when the caller
    // cites a delegation on claim/complete, it must be durably committed
    // in the GROUP's history, grant this verb, target THIS task, name the
    // local agent as delegate, and be unexpired with its whole chain still
    // membered. The mutation itself is still self-signed by the local
    // agent (blocker 25); the delegation is the authorization evidence,
    // surfaced as `authorized_via` in the response.
    let mut authorized_via: Option<String> = None;
    if req.delegation.is_some() {
        let digest = req.delegation.clone().unwrap_or_default();
        let Some(scoped) = parse_group_scoped_task_list_id(&id) else {
            return bad_request(
                "delegation requires a group-scoped task list (x0x.group.<id>.symphony.<list>)",
            );
        };
        let verb = if req.action == "claim" {
            x0x::delegation::DelegationVerb::Claim
        } else {
            x0x::delegation::DelegationVerb::Complete
        };
        // ADR-0066 §3b row 17: this branch HONOURS a delegation, so it is
        // an authority act on the group's roster and fails closed before
        // the claim/complete mutation below. Scoped strictly to the
        // delegation-cited branch — gating group task mutations generally
        // is row 20 (§3c, slice 5) and is not this slice's business.
        //
        // Row 17 uses the shared helper. The marker and local seat are read
        // together, so a nonmember session cannot inspect contested details.
        let groups = state.named_groups.read().await;
        if let Some((_, info)) =
            crate::server::resolve_group_entry_locked(&groups, &scoped.group_id)
        {
            if let Some(refused) =
                crate::server::routes::named_groups::reject_fork_quarantined_for_actor(
                    &state,
                    &scoped.group_id,
                    info,
                    &actor,
                )
            {
                return refused;
            }
        }
        drop(groups);
        let committed =
            crate::server::delegations::committed_delegations(&state, &scoped.group_id).await;
        let sd = committed
            .iter()
            .find(|sd| hex::encode(x0x::delegation::signed_delegation_digest(sd)) == digest);
        let Some(sd) = sd else {
            return forbidden("delegation is not durably committed in this group's history");
        };
        if sd.delegation.task_ref.as_ref() != Some(task_id.as_bytes()) {
            return forbidden("delegation does not target this task");
        }
        if let Err(why) = crate::server::delegations::authorize(
            sd,
            &state.agent.agent_id(),
            verb,
            &scoped.group_id,
            crate::server::now_millis_u64(),
            &committed,
            // Proven `None` by the refusal above; passed rather than
            // hard-coded so the predicate's gate stays wired here.
            None,
        ) {
            return forbidden(format!("delegation does not authorize this action: {why}"));
        }
        let active = crate::server::delegations::active_members_of(&state, &scoped.group_id).await;
        if let Err(why) =
            crate::server::delegations::chain_members_active(sd, &committed, &active, None)
        {
            return forbidden(format!("delegation chain no longer active: {why}"));
        }
        authorized_via = Some(hex::encode(sd.delegation.from_agent.as_bytes()));
    }

    let result = match req.action.as_str() {
        "claim" => handle.claim_task_versioned(task_id, expected).await,
        "complete" => handle.complete_task_versioned(task_id, expected).await,
        _ => {
            return bad_request("action must be 'claim' or 'complete'");
        }
    };

    match result {
        // `committed:"local"` makes explicit that success = local CRDT
        // commit + best-effort delta publish — NOT replicated observation and
        // NOT exclusive ownership. The `resolution` block reports the local
        // OR-Set snapshot at commit time; the deterministic winner may change
        // when concurrent operations from other replicas merge in. `cas.scope`
        // localizes the version guard; `execution.authorization:"advisory"`
        // and `exclusive:false` make the non-exclusive status unambiguous, so
        Ok(x0x::TaskMutationOutcome::Committed { fence, advisory }) => {
            let current_winner = advisory.current_winner.map(|(agent, ts)| {
                serde_json::json!({
                    "agent_id": hex::encode(agent.as_bytes()),
                    "timestamp_ms": ts,
                })
            });
            (
                StatusCode::OK,
                Json({
                    // ADR-0040: authorization evidence when the caller
                    // cited a task-execute delegation (absent otherwise).
                    let mut body = serde_json::json!({
                        "ok": true,
                        "version": fence.revision,
                        "fence_token": fence.to_wire(),
                        "committed": "local",
                        "resolution": {
                            "agent_id": hex::encode(advisory.agent.as_bytes()),
                            "locally_winning": advisory.locally_winning,
                            "current_winner": current_winner,
                            "pending_convergence": true,
                        },
                        "cas": { "scope": "local_replica" },
                        "execution": { "authorization": "advisory" },
                        "exclusive": false,
                    });
                    if let Some(delegator) = &authorized_via {
                        body["authorized_via"] = serde_json::json!({
                            "delegator_agent_id": delegator,
                        });
                    }
                    body
                }),
            )
        }
        Ok(x0x::TaskMutationOutcome::StaleLocalVersion { current }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "stale_local_version",
                "current_version": current.revision,
                "fence_token": current.to_wire(),
                "cas": { "scope": "local_replica" },
            })),
        ),
        // Issue #643: a task a caller just read can be transiently absent
        // from this replica while convergence settles (a stale bootstrap
        // full-serve pruned it before its re-delivery merged), or it was
        // deleted elsewhere, or it never existed. That is a structured,
        // retryable 404 — NOT a 500-class storage failure: the caller
        // re-reads the list (the echoed fence token is the current one) and
        // retries or gives up. Non-mutating by construction.
        Ok(x0x::TaskMutationOutcome::TaskMissing { current }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "task_not_found",
                "retryable": true,
                "current_version": current.revision,
                "fence_token": current.to_wire(),
                "cas": { "scope": "local_replica" },
            })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_group_scoped_task_list_id: the security crown jewel ──────────
    //
    // The parser's contract is the foundation of #153's fail-closed
    // property. It must partition every input into exactly one of:
    //   - None              ⇒ plain id, ALLOW (unchanged behavior)
    //   - Some(valid)       ⇒ group-scoped, defer to membership check
    //   - Some(malformed)   ⇒ looked scoped but invalid, DENY
    // A misspelled prefix (`x0x.grop.…`) MUST NOT silently fall through to the
    // plain-id allow path, and a malformed scoped id MUST NOT be treated as a
    // valid group lookup.

    #[test]
    fn parser_recognizes_well_formed_scoped_id() {
        let parsed = parse_group_scoped_task_list_id("x0x.group.acme-corp.symphony.inbox");
        let scoped = parsed.expect("well-formed scoped id parses");
        assert!(!scoped.is_malformed());
        assert_eq!(scoped.group_id, "acme-corp");
    }

    #[test]
    fn parser_treats_plain_id_as_none() {
        // A non-scoped topic is unchanged behavior — must return None so the
        // guard allows it without any group lookup.
        assert_eq!(parse_group_scoped_task_list_id("plain-topic"), None);
        assert_eq!(parse_group_scoped_task_list_id("inbox"), None);
        assert_eq!(parse_group_scoped_task_list_id(""), None);
        // A 4-segment id is NOT the scoped shape (needs exactly 5).
        assert_eq!(parse_group_scoped_task_list_id("x0x.group.acme"), None);
        // 6 segments is also not the shape.
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.group.acme.symphony.inbox.extra"),
            None
        );
    }

    #[test]
    fn parser_rejects_wrong_prefix_as_plain() {
        // A scoped shape with a misspelled prefix is NOT treated as scoped —
        // it falls through to plain (None). This is safe because such an id
        // is genuinely not the symphony convention; treating it as scoped
        // would be over-eager denial of legitimate plain ids.
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.grop.acme.symphony.inbox"),
            None
        );
        assert_eq!(
            parse_group_scoped_task_list_id("foo.group.acme.symphony.inbox"),
            None
        );
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.group.acme.secure.inbox"),
            None // wrong 4th segment (not "symphony")
        );
    }

    #[test]
    fn parser_flags_empty_group_or_list_as_malformed() {
        // A scoped *shape* with an empty group_id or list_id is malformed and
        // MUST be denied (Some(malformed)), never allowed as plain.
        let empty_group = parse_group_scoped_task_list_id("x0x.group..symphony.inbox");
        let scoped = empty_group.expect("scoped shape with empty group is Some");
        assert!(scoped.is_malformed(), "empty group_id ⇒ malformed ⇒ deny");

        let empty_list = parse_group_scoped_task_list_id("x0x.group.acme.symphony.");
        let scoped = empty_list.expect("scoped shape with empty list is Some");
        assert!(scoped.is_malformed(), "empty list_id ⇒ malformed ⇒ deny");
    }

    // ── UpdateTaskRequest strict parsing: no silent fence downgrade ────────
    //
    // The PATCH claim/complete body must reject unknown fields. The pre-fence
    // API used `expected_version`; a client still sending it MUST get a 4xx
    // (serde reject → axum Json extractor), NOT a silent ignore that drops the
    // field and downgrades the request to fence_token=None (unfenced) — which
    // would let a stale claim commit 200. `deny_unknown_fields` enforces this.

    #[test]
    fn update_task_request_rejects_obsolete_expected_version_field() {
        // The obsolete pre-fence field is now unknown → rejected, not ignored.
        let obsolete =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","expected_version":3}"#);
        assert!(
            obsolete.is_err(),
            "obsolete expected_version must be rejected (4xx), not silently \
             downgraded to an unfenced claim"
        );
    }

    #[test]
    fn update_task_request_accepts_current_contract_and_rejects_typos() {
        // fence_token provided (fenced) parses.
        let fenced =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","fence_token":"1:2"}"#);
        assert!(fenced.is_ok(), "fenced request parses");
        // fence_token omitted (unfenced) is still a valid shape — strictness is
        // about UNKNOWN fields, not requiring a fence.
        let unfenced = serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim"}"#);
        assert!(unfenced.is_ok(), "unfenced request parses");
        // A typo'd field name is also rejected (defense in depth).
        let typo =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","fence_tokn":"1:2"}"#);
        assert!(typo.is_err(), "typo'd field name must be rejected");
    }

    // ── group_task_resume_spellings (#759): an alias-keyed task list must
    // not be lost to exact-string filtering when the resume is keyed by a
    // different spelling of the same group.

    /// Two map spellings of ONE group: the map key `alias-key` and the
    /// stable id `stable-id` (an alias-keyed store holds siblings). The
    /// MLS group id IS the stable id (`GroupInfo::new` pins genesis to it),
    /// so `mls_group_id = "stable-id"` for both entries.
    fn spellings_map() -> std::collections::HashMap<String, x0x::groups::GroupInfo> {
        let creator = x0x::identity::AgentId([7; 32]);
        let mut map = std::collections::HashMap::new();
        let alias = x0x::groups::GroupInfo::new(
            "alias".to_string(),
            "alias-keyed spelling".to_string(),
            creator,
            "stable-id".to_string(),
        );
        let canonical = x0x::groups::GroupInfo::new(
            "canonical".to_string(),
            "stable-id spelling".to_string(),
            creator,
            "stable-id".to_string(),
        );
        map.insert("alias-key".to_string(), alias);
        map.insert("stable-id".to_string(), canonical);
        map
    }

    #[test]
    fn spellings_from_the_stable_id_reach_the_alias_key() {
        let map = spellings_map();
        let spellings = group_task_resume_spellings(&map, "stable-id");
        assert_eq!(
            spellings,
            std::collections::BTreeSet::from(["alias-key".to_string(), "stable-id".to_string()]),
            "a resume keyed by the stable id must also match a list whose scoped \
             id carries the alias spelling"
        );
    }

    #[test]
    fn spellings_from_an_alias_key_reach_the_stable_id() {
        let map = spellings_map();
        let spellings = group_task_resume_spellings(&map, "alias-key");
        assert_eq!(
            spellings,
            std::collections::BTreeSet::from(["alias-key".to_string(), "stable-id".to_string()]),
            "a resume keyed by the apply path's map-key spelling must also match \
             a list whose scoped id carries the stable id"
        );
    }

    #[test]
    fn spellings_for_an_unknown_group_keep_only_the_id_itself() {
        let map = spellings_map();
        let spellings = group_task_resume_spellings(&map, "pruned-alias");
        assert_eq!(
            spellings,
            std::collections::BTreeSet::from(["pruned-alias".to_string()]),
            "an unresolvable spelling keeps the pre-#759 exact-match behavior"
        );
    }

    /// #975: a task delta sealed under a group epoch must never be published
    /// after a member removal has moved the group past that epoch — the
    /// removed member still holds the old key and would read it.
    ///
    /// The interleaving is forced, not slept into: [`PauseAfterSeal`] wraps
    /// the PRODUCTION protector and parks the publisher right after its seal
    /// returns, the test commits the removal, then releases the publisher.
    mod publication_epoch_975 {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use x0x::crdt::sealed::{decode_sealed_task_record, SealedTaskRecordBody};
        use x0x::identity::AgentId;

        const BOUND: Duration = Duration::from_secs(20);

        type Hook = (
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        );

        /// Delegates everything to the production protector; the first
        /// `seal` after [`arm`](Self::arm) signals and then waits to be
        /// released before returning its (already sealed) record.
        struct PauseAfterSeal {
            inner: Arc<dyn x0x::crdt::TaskDeltaProtector>,
            hook: std::sync::Mutex<Option<Hook>>,
            seals: AtomicUsize,
        }

        impl PauseAfterSeal {
            fn arm(
                &self,
            ) -> (
                tokio::sync::oneshot::Receiver<()>,
                tokio::sync::oneshot::Sender<()>,
            ) {
                let (sealed_tx, sealed_rx) = tokio::sync::oneshot::channel();
                let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
                *self.hook.lock().expect("hook") = Some((sealed_tx, resume_rx));
                (sealed_rx, resume_tx)
            }

            fn seals(&self) -> usize {
                self.seals.load(Ordering::SeqCst)
            }
        }

        impl x0x::crdt::TaskDeltaProtector for PauseAfterSeal {
            fn seal<'a>(
                &'a self,
                kind: x0x::kv::KvMutationKind,
                payload: &'a [u8],
            ) -> x0x::crdt::sealed::TaskSealFuture<'a, Option<SealedTaskRecordBody>> {
                Box::pin(async move {
                    let sealed = self.inner.seal(kind, payload).await;
                    self.seals.fetch_add(1, Ordering::SeqCst);
                    let hook = self.hook.lock().expect("hook").take();
                    if let Some((sealed_tx, resume_rx)) = hook {
                        let _ = sealed_tx.send(());
                        let _ = resume_rx.await;
                    }
                    sealed
                })
            }

            fn open<'a>(
                &'a self,
                body: &'a SealedTaskRecordBody,
            ) -> x0x::crdt::sealed::TaskSealFuture<'a, x0x::crdt::sealed::OpenedTaskPayload>
            {
                self.inner.open(body)
            }

            fn admits_plaintext(
                &self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>
            {
                self.inner.admits_plaintext()
            }

            fn on_rejected(&self, reason: x0x::crdt::TaskSealRejection) {
                self.inner.on_rejected(reason);
            }

            fn local_agent(&self) -> Option<AgentId> {
                self.inner.local_agent()
            }

            fn confirm_publication<'a>(
                &'a self,
                body: &'a SealedTaskRecordBody,
            ) -> x0x::crdt::sealed::TaskSealFuture<'a, x0x::crdt::TaskPublication> {
                self.inner.confirm_publication(body)
            }
        }

        fn test_network_config() -> x0x::network::NetworkConfig {
            x0x::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..x0x::network::NetworkConfig::default()
            }
        }

        async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
            let dir = tempfile::tempdir().expect("tempdir");
            let data_dir = dir.path().to_path_buf();
            let agent = Arc::new(
                x0x::Agent::builder()
                    .with_identity_dir(&data_dir)
                    .with_machine_key(data_dir.join("machine.key"))
                    .with_agent_key(x0x::identity::AgentKeypair::generate().expect("agent key"))
                    .with_agent_cert_path(data_dir.join("agent.cert"))
                    .with_peer_cache_disabled()
                    .with_contact_store_path(data_dir.join("contacts.json"))
                    .with_network_config(test_network_config())
                    .build()
                    .await
                    .expect("agent"),
            );
            let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                &data_dir, agent,
            )
            .await
            .expect("state");
            (state, dir)
        }

        /// A sync for `topic` carrying the production protector wrapped in
        /// [`PauseAfterSeal`], and a pubsub the test can subscribe to.
        async fn sealed_sync(
            state: &Arc<AppState>,
            topic: &str,
        ) -> (
            Arc<x0x::crdt::TaskListSync>,
            Arc<x0x::gossip::PubSubManager>,
            Arc<PauseAfterSeal>,
        ) {
            let node = Arc::new(
                x0x::network::NetworkNode::new(test_network_config(), None, None)
                    .await
                    .expect("node"),
            );
            let pubsub = Arc::new(x0x::gossip::PubSubManager::new(node, None).expect("pubsub"));
            let peer = saorsa_gossip_types::PeerId::new([1; 32]);
            let list = x0x::crdt::TaskList::new(
                x0x::crdt::TaskListId::new([9; 32]),
                "Board".to_string(),
                peer,
            );
            let sync =
                x0x::crdt::TaskListSync::new(list, Arc::clone(&pubsub), topic.to_string(), peer)
                    .expect("sync");
            let inner = group_task_list_binding(state, topic)
                .await
                .delta_protector
                .expect("a group-scoped list gets a protector");
            let protector = Arc::new(PauseAfterSeal {
                inner,
                hook: std::sync::Mutex::new(None),
                seals: AtomicUsize::new(0),
            });
            assert!(sync.install_protector(Arc::clone(&protector) as _));
            (Arc::new(sync), pubsub, protector)
        }

        fn spawn_publish(
            sync: &Arc<x0x::crdt::TaskListSync>,
        ) -> tokio::task::JoinHandle<x0x::crdt::Result<()>> {
            let sync = Arc::clone(sync);
            tokio::spawn(async move {
                sync.publish_delta(
                    saorsa_gossip_types::PeerId::new([1; 32]),
                    x0x::crdt::TaskListDelta::new(1),
                )
                .await
            })
        }

        /// A GSS group owned by this node with `removed` seated; returns the
        /// group as it stands BEFORE the removal (what `removed` holds).
        async fn seed_gss_group(
            state: &AppState,
            group_key: &str,
            removed: AgentId,
        ) -> x0x::groups::GroupInfo {
            let owner = state.agent.agent_id();
            let mut info = x0x::groups::GroupInfo::new(
                "board".to_string(),
                String::new(),
                owner,
                group_key.to_string(),
            );
            info.migrate_from_v1();
            let _ = info.rotate_shared_secret();
            info.add_member(
                hex::encode(removed.as_bytes()),
                x0x::groups::GroupRole::Member,
                Some(hex::encode(owner.as_bytes())),
                None,
            );
            state
                .named_groups
                .write()
                .await
                .insert(group_key.to_string(), info.clone());
            info
        }

        /// `previous` with `removed` removed and the secret rotated, exactly
        /// as a removal commit produces it.
        fn removal_of(
            previous: &x0x::groups::GroupInfo,
            owner: AgentId,
            removed: AgentId,
        ) -> x0x::groups::GroupInfo {
            let mut next = previous.clone();
            next.roster_revision += 1;
            next.remove_member(
                &hex::encode(removed.as_bytes()),
                Some(hex::encode(owner.as_bytes())),
            );
            let _ = next.rotate_shared_secret();
            next
        }

        async fn published_record(sub: &mut x0x::gossip::Subscription) -> SealedTaskRecordBody {
            let msg = tokio::time::timeout(BOUND, sub.recv())
                .await
                .expect("a sealed delta was published")
                .expect("subscription open");
            decode_sealed_task_record(&msg.payload)
                .expect("an encrypted group's delta is a sealed record")
                .1
        }

        /// THE #975 race, GSS plane. Seal at epoch E, then the production
        /// roster writer commits a removal (E+1), then the publish continues.
        ///
        /// On the unfixed code `publish_delta` published the bytes its one
        /// seal produced, so the record on the wire was the paused epoch-E
        /// record: `record.epoch == E` and the removed member's pre-removal
        /// group opens it — both assertions below fail. Fixed, the publisher
        /// sees the epoch moved, discards that seal and re-seals under E+1.
        #[tokio::test]
        async fn gss_delta_sealed_before_removal_is_resealed_after_it() {
            let (state, _dir) = test_state().await;
            let owner = state.agent.agent_id();
            let removed = AgentId([7; 32]);
            let group_key = "97".repeat(16);
            let pre_removal = seed_gss_group(&state, &group_key, removed).await;
            let topic = format!("x0x.group.{group_key}.symphony.board");
            let (sync, pubsub, protector) = sealed_sync(&state, &topic).await;
            let mut sub = pubsub.subscribe(topic.clone()).await;

            let (sealed, resume) = protector.arm();
            let publisher = spawn_publish(&sync);
            tokio::time::timeout(BOUND, sealed)
                .await
                .expect("publisher reached its seal")
                .expect("hook");

            let next = removal_of(&pre_removal, owner, removed);
            assert_eq!(next.secret_epoch, pre_removal.secret_epoch + 1);
            let committed = tokio::time::timeout(
                BOUND,
                crate::server::routes::named_groups::persist_named_group_info(
                    &state, &group_key, next,
                ),
            )
            .await
            .expect("a paused seal holds no lock the roster writer needs")
            .expect("persist removal");
            assert!(matches!(
                committed,
                crate::server::routes::named_groups::AtomicWriteOutcome::Durable
            ));

            let _ = resume.send(());
            tokio::time::timeout(BOUND, publisher)
                .await
                .expect("publish completes")
                .expect("join")
                .expect("publish");

            let SealedTaskRecordBody::Gss(record) = published_record(&mut sub).await else {
                panic!("GSS group publishes a GSS record");
            };
            assert_eq!(
                record.epoch,
                pre_removal.secret_epoch + 1,
                "the delta must be sealed under the post-removal epoch"
            );
            assert!(
                x0x::crdt::sealed::open_gss_task_record(&pre_removal, &topic, &record).is_err(),
                "the removed member's pre-removal key must not open the published delta"
            );
            let current = state.named_groups.read().await[&group_key].clone();
            x0x::crdt::sealed::open_gss_task_record(&current, &topic, &record)
                .expect("a current member opens it");
            assert_eq!(
                protector.seals(),
                2,
                "the stale seal was discarded, not published"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(200), sub.recv())
                    .await
                    .is_err(),
                "exactly one record reached the wire"
            );
        }

        /// No roster change: one seal, one publish, under the current epoch —
        /// the gate adds no re-seal and does not refuse.
        #[tokio::test]
        async fn gss_delta_without_a_removal_publishes_once_under_the_current_epoch() {
            let (state, _dir) = test_state().await;
            let group_key = "98".repeat(16);
            let info = seed_gss_group(&state, &group_key, AgentId([8; 32])).await;
            let topic = format!("x0x.group.{group_key}.symphony.board");
            let (sync, pubsub, protector) = sealed_sync(&state, &topic).await;
            let mut sub = pubsub.subscribe(topic.clone()).await;

            tokio::time::timeout(BOUND, spawn_publish(&sync))
                .await
                .expect("publish completes")
                .expect("join")
                .expect("publish");

            let SealedTaskRecordBody::Gss(record) = published_record(&mut sub).await else {
                panic!("GSS group publishes a GSS record");
            };
            assert_eq!(record.epoch, info.secret_epoch);
            x0x::crdt::sealed::open_gss_task_record(&info, &topic, &record)
                .expect("every current member opens it");
            assert_eq!(protector.seals(), 1);
        }

        /// No deadlock, and the gate really orders publication after a
        /// commit: while a roster writer holds the GSS publication gate the
        /// sealed publish cannot go out; once the writer finishes, it
        /// completes within the bound under the writer's epoch. Then publishes
        /// and real roster commits race freely and all finish in bound.
        #[tokio::test]
        async fn gss_publish_during_a_roster_commit_completes_without_deadlock() {
            let (state, _dir) = test_state().await;
            let owner = state.agent.agent_id();
            let removed = AgentId([6; 32]);
            let group_key = "99".repeat(16);
            let pre_removal = seed_gss_group(&state, &group_key, removed).await;
            let topic = format!("x0x.group.{group_key}.symphony.board");
            let (sync, pubsub, protector) = sealed_sync(&state, &topic).await;
            let mut sub = pubsub.subscribe(topic.clone()).await;

            // A commit in flight: the writer permit is held and the live map
            // moves to the rotated epoch under it, as the writer does.
            let writer = state.gss_publication_gate.write().await;
            let publisher = spawn_publish(&sync);
            tokio::time::timeout(BOUND, async {
                while protector.seals() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("sealing does not need the gate");
            state
                .named_groups
                .write()
                .await
                .insert(group_key.clone(), removal_of(&pre_removal, owner, removed));
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            assert!(
                !publisher.is_finished(),
                "a sealed record must not publish while a roster commit holds the gate"
            );
            drop(writer);
            tokio::time::timeout(BOUND, publisher)
                .await
                .expect("publish completes once the commit releases the gate")
                .expect("join")
                .expect("publish");
            let SealedTaskRecordBody::Gss(record) = published_record(&mut sub).await else {
                panic!("GSS group publishes a GSS record");
            };
            assert_eq!(record.epoch, pre_removal.secret_epoch + 1);

            // Real commits (production writer) racing real publishes.
            tokio::time::timeout(BOUND, async {
                for round in 0..5u8 {
                    let previous = state.named_groups.read().await[&group_key].clone();
                    let mut next = previous.clone();
                    next.roster_revision += 1;
                    let _ = next.rotate_shared_secret();
                    let publish = spawn_publish(&sync);
                    let commit = crate::server::routes::named_groups::persist_named_group_info(
                        &state, &group_key, next,
                    );
                    let (published, committed) = tokio::join!(publish, commit);
                    published
                        .expect("join")
                        .unwrap_or_else(|e| panic!("round {round} publish: {e}"));
                    committed.unwrap_or_else(|e| panic!("round {round} commit: {e}"));
                }
            })
            .await
            .expect("publishes and roster commits never deadlock");
        }

        /// THE #975 race, TreeKEM plane: seal at ratchet epoch E, then a
        /// removal commit advances the live ratchet, then the publish
        /// continues. Unfixed, the paused epoch-E record was published — one
        /// the removed member's epoch-E ratchet can decrypt — so the epoch
        /// assertion below fails. Fixed, it is re-sealed at the new epoch.
        #[tokio::test]
        async fn treekem_delta_sealed_before_removal_is_resealed_after_it() {
            let (state, _dir) = test_state().await;
            let owner = AgentId([78; 32]);
            let writer = state.agent.agent_id();
            let removed = AgentId([79; 32]);
            let group_key = "4a".repeat(16);
            let group_id = hex::decode(&group_key).expect("group id");
            let writer_seed = crate::server::routes::named_groups::agent_treekem_seed(
                state.agent.as_ref(),
                &group_id,
            );
            let mut owner_group =
                x0x::mls::TreeKemMlsGroup::create(group_id.clone(), owner, &[78; 32])
                    .expect("owner group");
            let writer_prepared =
                x0x::mls::TreeKemMlsGroup::prepare_member(writer, &writer_seed).expect("writer kp");
            let writer_add = owner_group
                .add_member(writer, writer_prepared.key_package_bytes())
                .expect("add writer");
            let mut writer_group =
                x0x::mls::TreeKemMlsGroup::join_from_welcome(writer_prepared, &writer_add.welcome)
                    .expect("writer join");
            let removed_prepared =
                x0x::mls::TreeKemMlsGroup::prepare_member(removed, &[79; 32]).expect("removed kp");
            let removed_add = owner_group
                .add_member(removed, removed_prepared.key_package_bytes())
                .expect("add removed");
            writer_group
                .process_commit(&removed_add.commit)
                .expect("writer seats the soon-removed member");
            let pre_removal_epoch = writer_group.epoch();

            let mut info = x0x::groups::GroupInfo::new(
                "tasks".to_string(),
                String::new(),
                owner,
                group_key.clone(),
            );
            info.migrate_from_v1();
            info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
            info.shared_secret = None;
            for member in [writer, removed] {
                info.add_member(
                    hex::encode(member.as_bytes()),
                    x0x::groups::GroupRole::Member,
                    Some(hex::encode(owner.as_bytes())),
                    None,
                );
            }
            info.secret_epoch = pre_removal_epoch;
            info.security_binding = Some(format!("treekem:epoch={pre_removal_epoch}"));
            info.recompute_state_hash();
            state
                .named_groups
                .write()
                .await
                .insert(group_key.clone(), info);
            state.treekem_groups.write().await.insert(
                group_key.clone(),
                Arc::new(tokio::sync::Mutex::new(writer_group)),
            );

            let topic = format!("x0x.group.{group_key}.symphony.board");
            let (sync, pubsub, protector) = sealed_sync(&state, &topic).await;
            let mut sub = pubsub.subscribe(topic.clone()).await;

            let (sealed, resume) = protector.arm();
            let publisher = spawn_publish(&sync);
            tokio::time::timeout(BOUND, sealed)
                .await
                .expect("publisher reached its seal")
                .expect("hook");

            let removal = owner_group.remove_member(removed).expect("remove");
            let post_removal_epoch = {
                let live = state.treekem_groups.read().await[&group_key].clone();
                let mut ratchet = tokio::time::timeout(BOUND, live.lock())
                    .await
                    .expect("a paused seal holds no ratchet lock");
                ratchet
                    .process_commit(&removal)
                    .expect("writer applies removal");
                ratchet.epoch()
            };
            assert!(post_removal_epoch > pre_removal_epoch);

            let _ = resume.send(());
            tokio::time::timeout(BOUND, publisher)
                .await
                .expect("publish completes")
                .expect("join")
                .expect("publish");

            let SealedTaskRecordBody::TreeKem(record) = published_record(&mut sub).await else {
                panic!("TreeKEM group publishes a TreeKEM record");
            };
            assert_eq!(
                record.epoch, post_removal_epoch,
                "the delta must be sealed at the post-removal ratchet epoch, which the \
                 removed member cannot derive"
            );
            assert_eq!(
                protector.seals(),
                2,
                "the stale seal was discarded, not published"
            );
        }
    }
}
