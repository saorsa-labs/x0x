//! W3-H red case for #1256: a member's metadata listener for a named group
//! exits after it applies a `MemberAdded` that arrived by gossip, and
//! nothing re-arms it until the daemon restarts. A later metadata event
//! that reaches the member only by gossip is then never applied.
//!
//! # Why it is RED on main (0abd524)
//!
//! - `ensure_named_group_metadata_listener` (named_groups.rs:14499) loops
//!   on the group's metadata topic and does `if apply_result.should_exit
//!   { break; }` (:14577), then `remove_listener_if_token` (:14581, :34512)
//!   drops its registration. Dropping its `Subscription` unsubscribes the
//!   topic (gossip/pubsub.rs:681).
//! - `ApplyMetadataResult::ACCEPTED_EXIT` sets `should_exit`
//!   (named_groups.rs:1090-1096), and the `MemberAdded` arm returns it for
//!   every accepted add (:12314).
//! - Only daemon start (server/mod.rs:1458-1468), create, join-via-invite,
//!   card import, the sealed-join re-arm and the bootstrap outbox call
//!   `ensure_named_group_listeners`. None runs after the exit.
//! - The committer sends each metadata event on two channels: a publish on
//!   the metadata topic and a DM to every active member
//!   (`spawn_named_group_event_delivery_to_active_members`,
//!   named_groups.rs:3433; for `MemberAdded` :14413-14420; for the rename
//!   below `update_named_group`, :24316-24317). DMs are applied by the
//!   daemon's direct-channel listener (server/mod.rs:2051-2086), which
//!   never exits. So a DM copy hides the dead topic listener, and only an
//!   event whose DM copies are lost shows it.
//!
//! # Scenario
//!
//! Nodes O (owner; node 0, every node's bootstrap peer), M (the member) and
//! J (a later joiner). G is a `private_secure` group of O's.
//!
//! 1. M joins G. Its own seat may already stop its listener (that is this
//!    defect too), so M then restarts on its own directories: daemon start
//!    re-arms the listener, and the case requires it live. The receipt
//!    notes M's listener before that restart.
//! 2. A fault rule drops every DM-class frame to M: raw direct DMs,
//!    relayed DMs, and pubsub frames on the DM topics (`x0x/dm/v1/`, the
//!    gossip inbox and bus). Nothing else to M is touched.
//! 3. First event: J redeems O's invite and O commits J's seat. M gets the
//!    `MemberAdded` only on G's metadata topic, applies it, and (on main)
//!    its listener exits.
//! 4. Between the events, per arm:
//!    - gossip only (the red case): nothing;
//!    - also by DM (control): the DM rule is lifted;
//!    - restarted member (control): M restarts on its own directories.
//! 5. Second event: O renames G (`PATCH /groups/:id`, a signed
//!    `GroupMetadataUpdated`). M must apply it (its name and state hash
//!    match O's) within 30 s.
//!
//! On main the gossip-only arm is RED: the listener is gone after the
//! first event and still gone at the final. Both controls are GREEN: a DM
//! copy is applied by the direct-channel listener, and a restart re-arms
//! the topic listener.
//!
//! # Receipts
//!
//! Every precondition is an `evidence` stage (INFRA when false):
//! - M's listener live before the first event (both legs below);
//! - O seats J;
//! - M applies J's seat with its state equal to O's;
//! - no DM-class frame reaches M while that happens, and frames on G's
//!   metadata topic do;
//! - M's state equals O's before the second event;
//! - per arm:
//!   - gossip-only and restarted arms: no DM copy of the rename reaches M
//!     (no DM-class frame is delivered to M, and M's DM layer hands on no
//!     copy of the rename);
//!   - DM arm: a DM copy of the rename itself reaches M (M's DM layer
//!     hands on a verified payload from O that is byte-equal to O's
//!     rename event), not merely any DM;
//!   - restarted arm: M restarted between the events with its listener
//!     live.
//!
//! The request is O's rename, published: PATCH 200, O's record renamed,
//! and an O-authored frame on G's metadata topic that carries the rename
//! event's exact bytes, written after the second event's mark. O's publish
//! logs and swallows a failure or a timeout (named_groups.rs:3225) and the
//! PATCH still answers 200, so a run without that frame is INFRA. Its
//! delivery to M is not required: on main, M's unsubscribe can stop it.
//!
//! M's listener is read two independent ways: the server's listener
//! registry (`group_metadata_tasks`), and the pubsub layer's subscriber
//! count for G's metadata topic. `GET /diagnostics/groups` is recorded
//! too, but its `subscribed_metadata` reads that same registry
//! (routes/network.rs:1181), so it is not a third leg. The red arm's
//! causes are both legs gone after the first event and still gone at the
//! final. Orderings are trace positions (`SimFabric::mark_indexed`,
//! `SimFabric::writes_from_between`). Receipts carry ids, hashes, kinds
//! and counts, never secrets or payloads.

#![cfg(test)]

use super::control::{create_group, invite, join, local_membership, members, mesh};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use crate::server::routes::named_groups::{
    named_group_metadata_event_kind, NamedGroupMetadataEvent,
};
use anyhow::ensure;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::PoisonError;

/// O first: node 0 is every node's bootstrap peer.
const LABELS: &[&str] = &["O", "M", "J"];
/// Budget for every setup readiness wait.
const SETUP: Duration = Duration::from_secs(180);
/// Bound for O's commit of J's seat and M's apply of it.
const FIRST_BOUND: Duration = Duration::from_secs(60);
/// Lets M's apply of the first event, and (on main) its listener's exit and
/// unsubscribe, settle before the listener is read. It does not drain the
/// first event's DM sends to M: each attempt waits up to 8 s for its ACK
/// (routes/direct.rs:33), and a failed attempt backs off before it retries
/// (dm_send.rs:416), so copies of the first event can still reach M after
/// the DM arm lifts the rule. The DM arm's evidence is therefore a copy of
/// the rename itself, never just any DM.
const SETTLE: Duration = Duration::from_secs(10);
/// The bound for M's apply of the second event.
const SECOND_BOUND: Duration = Duration::from_secs(30);
/// G's name after the second event.
const RENAMED: &str = "w3h 1256 renamed";
/// Topic prefix of the gossip DM inbox and bus (`x0x/dm/v1/inbox/..`,
/// `x0x/dm/v1/bus`); a signed pubsub frame carries its topic.
const DM_TOPIC_MARKER: &[u8] = b"x0x/dm/v1/";
const FINAL: &str = "m_applies_the_gossip_second_event_within_the_bound";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// The second event reaches M only by gossip (the red case).
    GossipOnly,
    /// The DM rule is lifted before the second event.
    AlsoByDm,
    /// M restarts between the events; the second event is gossip only.
    RestartedMember,
}

impl Arm {
    fn gossip_only(self) -> bool {
        !matches!(self, Self::AlsoByDm)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether a frame is a DM on any transport: a raw direct DM, a relayed
/// DM, or a pubsub frame on a DM topic.
fn is_dm(write: &Write) -> bool {
    match write.lane.class {
        LaneClass::Direct | LaneClass::RelayedDm => true,
        LaneClass::PubSub => contains(&write.bytes, DM_TOPIC_MARKER),
        _ => false,
    }
}

/// Whether a frame is a pubsub frame on `topic` (a signed pubsub frame
/// carries its topic) that is not a DM.
fn on_topic(write: &Write, topic: &str) -> bool {
    write.lane.class == LaneClass::PubSub
        && !is_dm(write)
        && contains(&write.bytes, topic.as_bytes())
}

/// A fault rule that drops every DM-class frame to `target` while held,
/// and counts what it dropped.
struct DmBlock {
    held: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl DmBlock {
    fn install(sim: &Sim, target: &str) -> Result<Self> {
        let machine = sim.peer(target)?.0;
        let held = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (rule_held, rule_dropped) = (Arc::clone(&held), Arc::clone(&dropped));
        sim.fabric().add_rule(move |write| {
            if rule_held.load(Ordering::SeqCst) && write.lane.dst == machine && is_dm(write) {
                rule_dropped.fetch_add(1, Ordering::SeqCst);
                Fault::Drop
            } else {
                Fault::Pass
            }
        });
        Ok(Self { held, dropped })
    }

    fn set(&self, held: bool) {
        self.held.store(held, Ordering::SeqCst);
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// Frames delivered to `target` from any other node whose delivery lies
/// after trace position `after` and before `before`, that match `keep`.
fn delivered_to(
    sim: &Sim,
    target: &str,
    after: usize,
    before: usize,
    keep: impl Fn(&Write) -> bool,
) -> Result<usize> {
    let dst = sim.peer(target)?;
    let mut count = 0;
    for label in LABELS.iter().filter(|label| **label != target) {
        let src = sim.peer(label)?;
        count += sim
            .fabric()
            .delivered_writes_after(&src, &dst, after)
            .into_iter()
            .filter(|(write, position)| *position < before && keep(write))
            .count();
    }
    Ok(count)
}

/// The parts of a group's local record the case compares.
struct GroupView {
    name: String,
    state_revision: u64,
    state_hash: String,
    active: Vec<String>,
    metadata_topic: String,
}

impl GroupView {
    fn json(&self) -> Value {
        json!({
            "name": self.name,
            "state_revision": self.state_revision,
            "state_hash": self.state_hash.get(..16).unwrap_or(&self.state_hash),
            "active_members": self.active.len(),
        })
    }
}

async fn group_view(sim: &Sim, label: &str, gid: &str) -> Result<Option<GroupView>> {
    let state = sim.state(label)?;
    let gid = gid.to_string();
    sim.at_instant(&format!("read {label}'s record of {gid}"), async move {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &gid).map(|(_, info)| GroupView {
            name: info.name.clone(),
            state_revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            active: info
                .members_v2
                .values()
                .filter(|m| m.is_active())
                .map(|m| m.agent_id.clone())
                .collect(),
            metadata_topic: info.metadata_topic.clone(),
        })
    })
    .await
}

/// `label`'s metadata listener for `gid` (resolved to its local key as the
/// server does), read two independent ways at one instant, as
/// `(registry, subscribed)`:
/// - the server's listener registry (`group_metadata_tasks`), which the
///   listener installs into and removes itself from
///   (named_groups.rs:14499-14590);
/// - the pubsub layer's own subscriber count for the group's metadata
///   topic (`PubSubManager::is_topic_subscribed`): the ref count that the
///   listener's `Subscription` takes and its drop releases
///   (gossip/pubsub.rs:681). Only that listener subscribes the topic
///   (named_groups.rs:14522).
async fn listener_legs(sim: &Sim, label: &str, gid: &str) -> Result<(bool, bool)> {
    let state = sim.state(label)?;
    let gid = gid.to_string();
    sim.at_instant(
        &format!("read {label}'s metadata listener for {gid}"),
        async move {
            let record = {
                let groups = state.named_groups.read().await;
                crate::server::resolve_group_entry_locked(&groups, &gid)
                    .map(|(key, info)| (key.to_string(), info.metadata_topic.clone()))
            };
            let Some((key, topic)) = record else {
                return (false, false);
            };
            let registry = state.group_metadata_tasks.read().await.contains_key(&key);
            let subscribed = match state.agent.pubsub() {
                Some(pubsub) => pubsub.is_topic_subscribed(&topic).await,
                None => false,
            };
            (registry, subscribed)
        },
    )
    .await
}

/// A metadata listener's state (see [`listener_legs`]).
struct Listener {
    registry: bool,
    subscribed: bool,
    detail: Value,
}

impl Listener {
    /// Both legs show the listener.
    fn live(&self) -> bool {
        self.registry && self.subscribed
    }

    /// Neither leg shows it.
    fn gone(&self) -> bool {
        !self.registry && !self.subscribed
    }
}

/// `label`'s listener for `gid`: both legs, and its `GET /diagnostics/groups`
/// row reduced to the listener flags, the roster size and the non-zero
/// counters (all counts). That row's `subscribed_metadata` reads the same
/// registry (routes/network.rs:1181), so it is recorded, not counted as a
/// leg.
async fn listener_state(sim: &Sim, label: &str, gid: &str) -> Result<Listener> {
    let (registry, subscribed) = listener_legs(sim, label, gid).await?;
    let (status, body) = sim
        .api(label, Method::GET, "/diagnostics/groups", None)
        .await?;
    ensure!(
        status.is_success(),
        "{label} GET /diagnostics/groups: {status}"
    );
    let key = {
        let state = sim.state(label)?;
        let gid = gid.to_string();
        sim.at_instant(&format!("resolve {label}'s key for {gid}"), async move {
            let groups = state.named_groups.read().await;
            crate::server::resolve_group_entry_locked(&groups, &gid)
                .map_or(gid.clone(), |(key, _)| key.to_string())
        })
        .await?
    };
    let row = body["groups"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["group_id"] == key.as_str()));
    let mut reduced = serde_json::Map::new();
    if let Some(fields) = row.and_then(Value::as_object) {
        for (field, value) in fields {
            let keep = matches!(
                field.as_str(),
                "subscribed_metadata" | "subscribed_public" | "members_v2_size"
            ) || value.as_u64().is_some_and(|count| count > 0);
            if keep {
                reduced.insert(field.clone(), value.clone());
            }
        }
    }
    Ok(Listener {
        registry,
        subscribed,
        detail: json!({
            "registry": registry,
            "pubsub_topic_subscribed": subscribed,
            "diagnostics_reads_the_registry": Value::Object(reduced),
        }),
    })
}

/// Aborts the watcher when the scenario ends, however it ends.
struct Watcher(tokio::task::JoinHandle<()>);

impl Drop for Watcher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One named-group metadata event that a node's DM layer handed to its
/// consumers (the direct-channel metadata listener among them).
struct DmSeen {
    /// Trace position of the mark recorded on receipt.
    position: usize,
    kind: &'static str,
    from_owner: bool,
    verified: bool,
    payload: Vec<u8>,
}

type DmLog = Arc<std::sync::Mutex<Vec<DmSeen>>>;

/// Watch `label`'s DM layer for named-group metadata events, from now on.
///
/// The x0x DM layer carries a DM on either transport: a raw direct frame,
/// or the recipient's gossip DM inbox, end-to-end encrypted. Both end in
/// the recipient's `DirectMessaging` fan-out, which its direct-channel
/// metadata listener reads (server/mod.rs:2059-2086). This watcher is one
/// more subscriber there, with its own queue: it sees what that listener
/// sees, takes nothing from it, and decodes each payload as that listener
/// does. Each receipt is marked in the trace, so its position orders it.
fn watch_metadata_dms(sim: &Sim, label: &str, owner: &str) -> Result<(Watcher, DmLog)> {
    let owner = sim.state(owner)?.agent.agent_id();
    let mut inbox = sim.state(label)?.agent.subscribe_direct();
    let fabric = Arc::clone(sim.fabric());
    let seen: DmLog = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let label = label.to_string();
    let task = tokio::spawn(async move {
        while let Some(msg) = inbox.recv().await {
            let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else {
                continue;
            };
            let kind = named_group_metadata_event_kind(&event);
            let position = fabric.mark_indexed(format!(
                "{label}'s DM layer received a named-group {kind} (verified={})",
                msg.verified
            ));
            sink.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(DmSeen {
                    position,
                    kind,
                    from_owner: msg.sender == owner,
                    verified: msg.verified,
                    payload: msg.payload,
                });
        }
    });
    Ok((Watcher(task), seen))
}

/// How many publishes `label`'s publish recorder holds so far.
fn published_count(sim: &Sim, label: &str) -> Result<usize> {
    Ok(sim
        .state(label)?
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len())
}

/// Whether `bytes` decode to `actor`'s `GroupMetadataUpdated` naming
/// [`RENAMED`] at roster revision `revision`.
fn is_rename(bytes: &[u8], actor: &str, revision: u64) -> bool {
    match serde_json::from_slice::<NamedGroupMetadataEvent>(bytes) {
        Ok(NamedGroupMetadataEvent::GroupMetadataUpdated {
            revision: got,
            actor: by,
            name: Some(name),
            ..
        }) => got == revision && by.eq_ignore_ascii_case(actor) && name == RENAMED,
        _ => false,
    }
}

/// The exact serialized bytes of `label`'s rename event on `topic`, from
/// its publish recorder entries at or after `from` (named_groups.rs:3223).
/// The same bytes are each DM copy's payload (named_groups.rs:3344): both
/// serialize the one event. The recorder logs the attempt, so this is the
/// event's content, not proof of its publication.
fn rename_event_bytes(
    sim: &Sim,
    label: &str,
    from: usize,
    topic: &str,
    revision: u64,
) -> Result<Option<Vec<u8>>> {
    let actor = sim.agent_hex(label)?;
    let state = sim.state(label)?;
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(published
        .iter()
        .skip(from)
        .find(|(on, bytes)| on == topic && is_rename(bytes, &actor, revision))
        .map(|(_, bytes)| bytes.clone()))
}

/// The label of the node with transport key `key`.
fn label_of(sim: &Sim, key: &[u8; 32]) -> &'static str {
    LABELS
        .iter()
        .copied()
        .find(|label| sim.peer(label).is_ok_and(|peer| peer.0 == *key))
        .unwrap_or("?")
}

async fn wait_for(
    sim: &Sim,
    what: &str,
    budget: Duration,
    check: impl AsyncFnMut(&Sim) -> bool,
) -> Result<bool> {
    match sim.until(what, budget, check).await {
        Ok(()) => Ok(true),
        Err(error) if expired(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// After `label` restarts, make sure it is linked to `peer`: its own
/// bootstrap redial gets 10 s, then `label` dials.
async fn relink(sim: &Sim, label: &str, peer: &str) -> Result<()> {
    let peer_id = sim.peer(peer)?;
    let linked = wait_for(
        sim,
        &format!("{label}~{peer} linked after {label}'s restart"),
        secs(10),
        async |s: &Sim| {
            let Some(network) = s.state(label).ok().and_then(|n| n.agent.network().cloned()) else {
                return false;
            };
            network.is_connected(&peer_id).await
        },
    )
    .await?;
    if !linked {
        let network = sim
            .state(label)?
            .agent
            .network()
            .cloned()
            .with_context(|| format!("{label} has no network"))?;
        let addr = super::sim_addr(sim.node_index(peer)?)?;
        sim.within(
            &format!("{label} dials {peer}"),
            secs(10),
            network.connect_addr(addr),
        )
        .await?
        .with_context(|| format!("{label} dials {peer}"))?;
    }
    Ok(())
}

/// Restart `label` on its own directories, relink it to O, and wait until
/// its listener for `gid` is live (both legs). Returns the stop's trace
/// position.
async fn restart_member(sim: &mut Sim, label: &str, gid: &str) -> Result<(usize, bool)> {
    let position = sim.fabric().mark_indexed(format!("case: restart {label}"));
    sim.restart(label, RestartMode::Graceful).await?;
    relink(sim, label, "O").await?;
    let live = wait_for(
        sim,
        &format!("{label}'s listener for G live after its restart"),
        SETUP,
        async |s: &Sim| {
            listener_legs(s, label, gid)
                .await
                .is_ok_and(|(registry, subscribed)| registry && subscribed)
        },
    )
    .await?;
    Ok((position, live))
}

async fn scenario(sim: &mut Sim, arm: Arm, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    for label in LABELS {
        sim.start_node_with(label, Provision::default()).await?;
    }
    mesh(sim, LABELS).await?;
    let block = DmBlock::install(sim, "M")?;

    // G, with M seated.
    let g = create_group(sim, "O").await?;
    let m_hex = sim.agent_hex("M")?;
    let j_hex = sim.agent_hex("J")?;
    let link = invite(sim, "O", &g).await?;
    join(sim, "M", &link).await?;
    sim.until("M seated in G", SETUP, async |s: &Sim| {
        members(s, "O", &g).await.is_ok_and(|m| m.contains(&m_hex))
            && local_membership(s, "M", &g).await.as_deref() == Some("active")
    })
    .await?;
    let after_own_join = listener_state(sim, "M", &g).await?;
    receipt.note(format!(
        "setup: M's G metadata listener after its own join, before its setup restart: \
         live={} {}",
        after_own_join.live(),
        after_own_join.detail
    ));
    let (_, live_after_setup_restart) = restart_member(sim, "M", &g).await?;
    ensure!(
        live_after_setup_restart,
        "setup: M's restart did not re-arm its G metadata listener"
    );
    let start = listener_state(sim, "M", &g).await?;
    let metadata_topic = group_view(sim, "O", &g)
        .await?
        .context("O has no record of G")?
        .metadata_topic;
    receipt.setup_done(at(sim));

    // First event: J's seat. M gets O's MemberAdded only by gossip.
    block.set(true);
    let first = sim
        .fabric()
        .mark_indexed("case: first event, J redeems O's invite (DMs to M dropped)");
    let dropped_before_first = block.dropped();
    let link = invite(sim, "O", &g).await?;
    join(sim, "J", &link).await?;
    let o_seats_j = wait_for(sim, "O seats J", FIRST_BOUND, async |s: &Sim| {
        members(s, "O", &g).await.is_ok_and(|m| m.contains(&j_hex))
    })
    .await?;
    let m_applied_first = wait_for(sim, "M lists J", FIRST_BOUND, async |s: &Sim| {
        group_view(s, "M", &g)
            .await
            .ok()
            .flatten()
            .is_some_and(|v| v.active.contains(&j_hex))
    })
    .await?;
    let first_applied = sim.fabric().mark_indexed("case: M lists J");
    let o_first = group_view(sim, "O", &g).await?.context("O lost G")?;
    let m_first = group_view(sim, "M", &g).await?.context("M lost G")?;
    sim.within(
        "first-event settle",
        SETTLE + secs(1),
        tokio::time::sleep(SETTLE),
    )
    .await?;
    let after_first = listener_state(sim, "M", &g).await?;
    let dropped_first = block.dropped().saturating_sub(dropped_before_first);
    let dm_first = delivered_to(sim, "M", first, first_applied, is_dm)?;
    let topic_first = delivered_to(sim, "M", first, first_applied, |w| {
        on_topic(w, &metadata_topic)
    })?;

    // Between the events.
    let mut restart = None;
    let mut released = None;
    match arm {
        Arm::GossipOnly => {}
        Arm::AlsoByDm => {
            block.set(false);
            released = Some(sim.fabric().mark_indexed("case: DM rule lifted"));
        }
        Arm::RestartedMember => {
            restart = Some(restart_member(sim, "M", &g).await?);
        }
    }
    let o_before = group_view(sim, "O", &g).await?.context("O lost G")?;
    let m_before = group_view(sim, "M", &g).await?.context("M lost G")?;
    let o_m_linked = match sim.state("O")?.agent.network().cloned() {
        Some(network) => network.is_connected(&sim.peer("M")?).await,
        None => false,
    };

    // Second event: O renames G. M's DM layer is watched from here on (its
    // current incarnation, after any restart above).
    let (dm_watch, dm_log) = watch_metadata_dms(sim, "M", "O")?;
    let published_before = published_count(sim, "O")?;
    let second = sim.fabric().mark_indexed("case: second event, O renames G");
    let dropped_before_second = block.dropped();
    let (status, body) = sim
        .api(
            "O",
            Method::PATCH,
            &format!("/groups/{g}"),
            Some(json!({"name": RENAMED})),
        )
        .await?;
    let o_after = group_view(sim, "O", &g).await?.context("O lost G")?;
    let revision = body["revision"].as_u64();
    let rename = match revision {
        Some(revision) => {
            rename_event_bytes(sim, "O", published_before, &metadata_topic, revision)?
        }
        None => None,
    };
    let target_hash = o_after.state_hash.clone();
    let applied = wait_for(
        sim,
        "M applies O's rename",
        SECOND_BOUND,
        async |s: &Sim| {
            group_view(s, "M", &g)
                .await
                .ok()
                .flatten()
                .is_some_and(|v| v.name == RENAMED && v.state_hash == target_hash)
        },
    )
    .await?;
    let applied_at = applied.then(|| sim.fabric().mark_indexed("case: M applied the rename"));
    let final_position = sim.fabric().mark_indexed("case: final");
    drop(dm_watch);
    let dropped_second = block.dropped().saturating_sub(dropped_before_second);
    let dm_second = delivered_to(sim, "M", second, final_position, is_dm)?;
    let topic_second = delivered_to(sim, "M", second, final_position, |w| {
        on_topic(w, &metadata_topic)
    })?;
    // O's publication of the rename: an O-authored frame on G's metadata
    // topic that carries the event's exact bytes, written (to any peer)
    // after the second event's mark. Its delivery is not required.
    let rename_frames: Vec<Write> = match &rename {
        Some(bytes) => sim
            .fabric()
            .writes_from_between(&sim.peer("O")?, second..final_position)
            .into_iter()
            .filter(|w| on_topic(w, &metadata_topic) && contains(&w.bytes, bytes))
            .collect(),
        None => Vec::new(),
    };
    let rename_frames_to: Vec<&str> = rename_frames
        .iter()
        .map(|w| label_of(sim, &w.lane.dst))
        .collect();
    let published = status.is_success()
        && o_after.name == RENAMED
        && o_after.state_revision > o_before.state_revision
        && rename.is_some()
        && !rename_frames.is_empty();
    // The rename's copies delivered to M, by its exact bytes where they are
    // plaintext on the wire: the signed topic publish, and a raw direct DM.
    // Gossip DMs are encrypted on the wire; M's DM layer (below) sees them.
    let (rename_on_topic, rename_by_direct_dm) = match &rename {
        Some(bytes) => (
            delivered_to(sim, "M", second, final_position, |w| {
                on_topic(w, &metadata_topic) && contains(&w.bytes, bytes)
            })?,
            delivered_to(sim, "M", second, final_position, |w| {
                w.lane.class == LaneClass::Direct && contains(&w.bytes, bytes)
            })?,
        ),
        None => (0, 0),
    };
    // What M's DM layer handed on in the window: copies of the rename
    // itself (byte-equal to O's event), as (position, from O, verified),
    // and other named-group events by kind (such as a late retry of the
    // first event's MemberAdded, which can arrive after the rule lifts).
    let (rename_dms, other_dms) = {
        let log = dm_log.lock().unwrap_or_else(PoisonError::into_inner);
        let mut rename_dms = Vec::new();
        let mut other_dms: BTreeMap<&'static str, usize> = BTreeMap::new();
        for seen in log
            .iter()
            .filter(|seen| second < seen.position && seen.position < final_position)
        {
            if rename.as_deref() == Some(seen.payload.as_slice()) {
                rename_dms.push((seen.position, seen.from_owner, seen.verified));
            } else {
                *other_dms.entry(seen.kind).or_default() += 1;
            }
        }
        (rename_dms, other_dms)
    };
    let rename_dm_from_o = rename_dms
        .iter()
        .any(|(_, from_owner, verified)| *from_owner && *verified);
    let rename_dms_json: Vec<Value> = rename_dms
        .iter()
        .map(|(position, from_owner, verified)| {
            json!({"position": position, "from_o": from_owner, "verified": verified})
        })
        .collect();
    let final_listener = listener_state(sim, "M", &g).await?;
    let m_final = group_view(sim, "M", &g).await?.context("M lost G")?;

    // ---- receipt ----
    receipt.evidence(
        "m_listener_live_before_the_first_event",
        start.live(),
        start.detail.to_string(),
        at(sim),
    );
    receipt.evidence(
        "o_seats_j",
        o_seats_j,
        format!("O lists J in G: {o_seats_j}"),
        at(sim),
    );
    receipt.evidence(
        "m_applied_the_first_event",
        m_applied_first && m_first.state_hash == o_first.state_hash,
        json!({"m": m_first.json(), "o": o_first.json(), "position": first_applied}).to_string(),
        at(sim),
    );
    receipt.evidence(
        "first_event_reached_m_by_gossip_only",
        dm_first == 0 && topic_first > 0,
        json!({
            "window": [first, first_applied],
            "dm_frames_delivered_to_m": dm_first,
            "g_metadata_topic_frames_delivered_to_m": topic_first,
            "dm_frames_to_m_dropped_by_the_rule": dropped_first,
        })
        .to_string(),
        at(sim),
    );
    receipt.evidence(
        "m_state_matches_o_before_the_second_event",
        m_before.state_hash == o_before.state_hash,
        json!({"m": m_before.json(), "o": o_before.json()}).to_string(),
        at(sim),
    );
    match arm {
        Arm::AlsoByDm => {
            receipt.evidence(
                "dm_copy_of_the_rename_reached_m",
                released.is_some_and(|position| position < second) && rename_dm_from_o,
                json!({
                    "rule_lifted": released,
                    "window": [second, final_position],
                    "rename_copies_m_dm_layer_handed_on": rename_dms_json,
                    "other_named_group_dms_m_dm_layer_handed_on": other_dms,
                    "dm_frames_delivered_to_m": dm_second,
                    "rename_by_direct_dm_delivered_to_m": rename_by_direct_dm,
                })
                .to_string(),
                at(sim),
            );
        }
        Arm::GossipOnly | Arm::RestartedMember => {
            receipt.evidence(
                "no_dm_copy_of_the_rename_reached_m",
                dm_second == 0 && rename_dms.is_empty(),
                json!({
                    "window": [second, final_position],
                    "dm_frames_delivered_to_m": dm_second,
                    "dm_frames_to_m_dropped_by_the_rule": dropped_second,
                    "rename_copies_m_dm_layer_handed_on": rename_dms_json,
                    "other_named_group_dms_m_dm_layer_handed_on": other_dms,
                })
                .to_string(),
                at(sim),
            );
        }
    }
    if let Some((position, live)) = restart {
        receipt.evidence(
            "m_restarted_between_the_events_with_its_listener_live",
            first_applied < position && position < second && live,
            json!({"first_applied": first_applied, "restart": position, "second": second,
                "listener_live_after": live})
            .to_string(),
            at(sim),
        );
    }
    receipt.evidence(
        "o_and_m_linked_at_the_second_event",
        o_m_linked,
        format!("O~M connected: {o_m_linked}"),
        at(sim),
    );
    receipt.request_delivered(
        "o_published_the_rename_on_g_metadata_topic",
        published,
        json!({
            "status": status.as_u16(),
            "ok": body["ok"],
            "revision": revision,
            "o": o_after.json(),
            "o_revision_before": o_before.state_revision,
            "rename_event_recorded": rename.is_some(),
            "rename_event_len": rename.as_ref().map(Vec::len),
            "window": [second, final_position],
            "rename_frames_written_by_o": rename_frames.len(),
            "rename_frames_to": rename_frames_to,
        })
        .to_string(),
        at(sim),
    );
    receipt.note(format!(
        "listener: after the first event live={} gone={} {}; at the final live={} gone={} {}",
        after_first.live(),
        after_first.gone(),
        after_first.detail,
        final_listener.live(),
        final_listener.gone(),
        final_listener.detail
    ));
    receipt.note(format!(
        "second event: g_metadata_topic_frames_delivered_to_m={topic_second} \
         rename_on_the_topic_delivered_to_m={rename_on_topic} \
         rename_by_direct_dm_delivered_to_m={rename_by_direct_dm} \
         dm_frames_delivered_to_m={dm_second} dm_dropped={dropped_second} m_final={}",
        m_final.json()
    ));
    // Cause stages explain a RED; a GREEN receipt must carry no false cause
    // (the W3-H gate rejects that), so record them only when not applied.
    if arm == Arm::GossipOnly && !applied {
        receipt.cause(
            "M's G metadata listener is gone (registry and pubsub subscription) after it \
             applied the gossip MemberAdded",
            Some(after_first.detail.to_string()),
            after_first.gone(),
            at(sim),
        );
        receipt.cause(
            "nothing re-armed M's G metadata listener (registry or pubsub subscription) \
             before the final",
            Some(final_listener.detail.to_string()),
            final_listener.gone(),
            at(sim),
        );
    }
    receipt.note(format!(
        "final: applied={applied} at={applied_at:?} bound_s={} gossip_only={}",
        SECOND_BOUND.as_secs(),
        arm.gossip_only()
    ));
    receipt.finish(FINAL, applied, at(sim));
    Ok(())
}

/// Run one arm and return its emitted receipt. Any error before the final
/// assertion is recorded as INFRA.
async fn run(case: &str, seed: u64, arm: Arm) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(format!("arm {arm:?}"));
    receipt.note(
        "DM loss is a harness fault rule: every DM-class frame to M (raw direct, relayed, \
         and pubsub on x0x/dm/v1/ topics) is dropped while the rule is held",
    );
    match Sim::empty(case, seed, LABELS) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, arm, &mut receipt).await {
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

async fn expect(case: &str, seed: u64, arm: Arm, want: Verdict) -> Result<()> {
    let receipt = run(case, seed, arm).await;
    ensure!(
        receipt.verdict() == Some(want),
        "{case}: expected {want:?}, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// The red case: after a gossip-applied `MemberAdded`, a metadata event
/// sent to M only by gossip is never applied. RED on main.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_red_1256_gossip_only_event_after_a_gossip_member_added() -> Result<()> {
    expect(
        "w3h_red_1256_gossip_only_event_after_a_gossip_member_added",
        0x1256_0001,
        Arm::GossipOnly,
        // #1256 fixed: RED on main (CI 20/20 on 8244ce7), GREEN with the fix.
        Verdict::Green,
    )
    .await
}

/// Control: the second event also reaches M by DM, which the never-exiting
/// direct-channel listener applies. GREEN on main.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1256_control_second_event_also_by_dm() -> Result<()> {
    expect(
        "w3h_1256_control_second_event_also_by_dm",
        0x1256_0002,
        Arm::AlsoByDm,
        Verdict::Green,
    )
    .await
}

/// Control: M restarts after the first event, which re-arms its topic
/// listener, so the gossip-only second event is applied. GREEN on main.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_1256_control_member_restarted_after_the_first_event() -> Result<()> {
    expect(
        "w3h_1256_control_member_restarted_after_the_first_event",
        0x1256_0003,
        Arm::RestartedMember,
        Verdict::Green,
    )
    .await
}
