//! W3-H red case for #1776: a fresh joiner that starts ~90 s after the
//! group was created receives its `MemberAdded` over the gossip mesh but
//! cannot fetch the TreeKEM Welcome, and the join times out.
//!
//! # Why it is RED on main (8596bb83d)
//!
//! - The staging authority puts a content-addressed `welcome_ref` in the
//!   `MemberAdded` event and keeps the Welcome bytes locally
//!   (`stage_treekem_welcome`, named_groups.rs). The joiner's only
//!   transport for those bytes is a direct-DM `FetchRequest` to
//!   `welcome_ref.source` — the authority itself.
//! - A direct DM needs a capability binding (a gossip-inbox KEM advert) or
//!   a machine it can dial for raw QUIC. In the reported deployment the
//!   joiner held neither: it joined the mesh ~90 s after the authority's
//!   last advert and identity-announcement beats (both ride a 600 s
//!   cadence plus a ~80 s startup burst, and are not replayed onto meshes
//!   joined later), and nothing from the authority reached it in the other
//!   direction either — so no store the DM path resolves through ever
//!   learned the authority. Group membership events seed none of them, so
//!   the verified `MemberAdded` taught the joiner nothing it could address.
//! - Every `FetchRequest` therefore failed `AgentNotFound` →
//!   `RecipientUndiscovered`, each fetch burned its full budget while the
//!   apply held the group membership lock, and the attempt finalised
//!   `timed_out` with no local group — while the authority still listed
//!   the joiner as an active member.
//!
//! # Scenario
//!
//! Nodes O (node 0, every node's bootstrap peer — the issue's relay R) and
//! A (the owner). B, the fresh joiner, starts only after the delay. The
//! fabric carries the deployment's blind window as two fault rules:
//!
//! - Nothing but the group's own metadata topic and the targeted
//!   capability control topics reaches B over pubsub: the identity
//!   announcements, adverts and shards the mesh would otherwise sync to a
//!   new subscriber never arrive, exactly the deployment where the relay
//!   reconciled no state for the late joiner. The `MemberAdded` still
//!   arrives (the issue's reporter observed that), and a fresh on-demand
//!   capability exchange still converges.
//! - No DM-class frame reaches B while B holds no capability binding for
//!   A: the blind window's other half (in the report, nothing from the
//!   authority ever reached the joiner). The rule releases the moment B
//!   can address A — which on main never happens, and with the fix is
//!   exactly what the targeted refresh brings about.
//!
//! 1. A creates a `private_secure` group and invites B.
//! 2. 90 s of virtual idleness pass — past A's advert startup burst, well
//!    before its next steady beat (the issue's reproduction delay).
//! 3. B starts, bootstraps only to O, and redeems the invitation once.
//! 4. A seats B over the topic mesh. On main, B's local membership never
//!    turns `active`: its group install waits for a Welcome it cannot
//!    request. With the fix, the failed fetch triggers a targeted
//!    capability refresh, the retry goes out on the gossip-inbox leg, and
//!    B installs the group — proven further by B opening the group store,
//!    which needs the group key the Welcome carries.

use super::control::{
    create_group, invite, join, local_membership, members, mesh, open_store, try_open_store,
};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::network::sim::{Fault, LaneClass, Write};
use anyhow::{ensure, Context as _};

const CASE: &str = "w3h_1776_delayed_fresh_joiner_fetches_the_welcome";
const SEED: u64 = 0x1776_0001;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

const DM_TOPIC_MARKER: &[u8] = b"x0x/dm/v1/";
const TARGETED_MARKER: &[u8] = b"targeted";

fn is_dm(write: &Write) -> bool {
    match write.lane.class {
        LaneClass::Direct | LaneClass::RelayedDm => true,
        LaneClass::PubSub => contains(&write.bytes, DM_TOPIC_MARKER),
        _ => false,
    }
}

#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
fn w3h_1776_delayed_fresh_joiner_fetches_the_welcome() -> Result<()> {
    super::block_on_paused(async move {
        let receipt = run().await;
        ensure!(
            receipt.verdict() == Some(Verdict::Green),
            "{CASE} verdict {:?}, expected GREEN",
            receipt.verdict()
        );
        Ok(())
    })
}

async fn run() -> Receipt {
    let mut receipt = Receipt::new(CASE, SEED);
    receipt.note(
        "The fabric drops every pubsub frame to B except the group's own \
         metadata topic and the targeted capability control topics, and every \
         DM to B while B holds no capability binding for A: the deployment's \
         blind window. Welcome delivery is observed as B's own active \
         membership plus B opening the group store, which needs the group \
         key the Welcome carries.",
    );
    match Sim::empty(CASE, SEED, &["O", "A", "B"]) {
        Ok(mut sim) => {
            if let Err(error) = scenario(&mut sim, &mut receipt).await {
                receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
            }
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
        }
        Err(error) => receipt.infra(format!("sim: {error:#}"), 0),
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(CASE);
    }
    receipt.emit();
    receipt
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<()> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    sim.start_node_with("O", Provision::default()).await?;
    sim.start_node_with("A", Provision::default()).await?;
    mesh(sim, &["O", "A"]).await?;
    let group = create_group(sim, "A").await?;
    let link = invite(sim, "A", &group).await?;
    let metadata_topic = {
        let state = sim.state("A")?;
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &group)
            .map(|(_, info)| info.metadata_topic.clone())
            .context("A has no record of the group")?
    };

    // The reproduction delay: 90 s after creation, A's advert startup
    // burst is over and the next steady beat is 600 s away. B joins the
    // mesh after every advert A has already published.
    sim.within(
        "90 s idle after the invite",
        secs(92),
        tokio::time::sleep(secs(90)),
    )
    .await?;

    let b_machine = sim.ids("B")?.1 .0;
    let topic_bytes = metadata_topic.clone().into_bytes();
    // Fault 1: the mesh reconciles no state for the late joiner. Of the
    // pubsub traffic delivered to B, only the group's own metadata topic
    // (the `MemberAdded` leg) and the targeted capability request/response
    // control topics pass; the identity, advert and shard topics that
    // would teach B about A never arrive.
    sim.fabric().add_rule(move |write| {
        if write.lane.dst == b_machine
            && write.lane.class == LaneClass::PubSub
            && !is_dm(write)
            && !contains(&write.bytes, &topic_bytes)
            && !contains(&write.bytes, TARGETED_MARKER)
        {
            Fault::Drop
        } else {
            Fault::Pass
        }
    });

    sim.start_node_with("B", Provision::default()).await?;
    mesh(sim, &["O", "B"]).await?;
    // Fault 2: no DM-class frame reaches B while B holds no capability
    // binding for A. Installed after B's daemon exists, before the join:
    // A has nothing to send B before the join volley. The rule holds only
    // a Weak handle, so it cannot keep B's daemon state alive past
    // shutdown.
    let b_state = Arc::downgrade(&sim.state("B")?);
    let a_agent = sim.ids("A")?.0;
    sim.fabric().add_rule(move |write| {
        if write.lane.dst == b_machine
            && is_dm(write)
            && b_state.upgrade().is_some_and(|state| {
                state
                    .agent
                    .capability_store
                    .lookup_binding(&a_agent)
                    .is_none()
            })
        {
            Fault::Drop
        } else {
            Fault::Pass
        }
    });
    receipt.setup_done(at(sim));

    join(sim, "B", &link).await?;

    let b = sim.agent_hex("B")?;
    sim.until("A seats B", secs(180), async |s: &Sim| {
        members(s, "A", &group)
            .await
            .is_ok_and(|listed| listed.contains(&b))
    })
    .await?;
    receipt.evidence("a_seats_b_over_the_topic_mesh", true, b.clone(), at(sim));
    sim.fabric().mark("checkpoint: A seated B");

    // The step that never completes on main: B's own seat installs only
    // with the Welcome, and B's group lookup 404s until then. The budget
    // covers the blind window's full grind: the first FetchRequest send
    // only surfaces its recipient_undiscovered after the DM ladder's
    // internal retries (~100 s here), then the targeted refresh lands the
    // binding and the next retry delivers.
    sim.until("B reports active membership", secs(180), async |s: &Sim| {
        local_membership(s, "B", &group).await.as_deref() == Some("active")
    })
    .await?;
    receipt.evidence(
        "b_fetches_the_welcome_and_activates",
        true,
        "membership_state=active",
        at(sim),
    );
    receipt.request_delivered(
        "b_fetches_the_welcome_over_the_gossip_mesh",
        true,
        "B's group install completed with the Welcome, so the FetchRequest \
         reached the staging authority and the chunks returned",
        at(sim),
    );
    sim.fabric()
        .mark("checkpoint: B fetched and applied the Welcome");

    // The Welcome's keying material, not just its metadata: opening the
    // group store needs the group key the Welcome carries.
    let store = open_store(sim, "A", &group).await?;
    let mut opened = None;
    let mut last = String::new();
    sim.until(
        "B opens the group store",
        secs(60),
        async |s: &Sim| match try_open_store(s, "B", &group).await {
            Ok(id) => {
                opened = Some(id);
                true
            }
            Err(error) => {
                last = format!("{error:#}");
                false
            }
        },
    )
    .await
    .with_context(|| format!("B last store-open error: {last}"))?;
    ensure!(
        opened.as_deref() == Some(store.as_str()),
        "B opened a different store id: {opened:?}"
    );
    receipt.evidence(
        "b_opens_the_group_store_with_the_welcome_key",
        true,
        store,
        at(sim),
    );
    sim.fabric().mark("checkpoint: B holds the group key");
    receipt.finish(CASE, true, at(sim));
    Ok(())
}
