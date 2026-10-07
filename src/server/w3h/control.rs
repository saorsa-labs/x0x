//! W3-H S1 controls: the harness itself, before any failure case.
//!
//! - `w3h_clock_gate_*`: virtual time does not move outside a barrier.
//! - `w3h_s1_control_*`: three real daemons, public API only, over the
//!   fabric. The positive control must converge AND deliver group data; the
//!   negative control (joiner offline) must fail for exactly the intended
//!   reason, with every authority read succeeding.
//!
//! The group shape is the live fixture's `private_secure` path
//! (`tests/e2e_vps_private_kv.py` `run_private`): create with the preset,
//! join by invite, open the same `wiki` store on every member, write on
//! the owner, read on the joiners.
//!
//! Daemon controls run only in the Linux isolated namespace (CI `w3h`
//! profile); they are compile-checked elsewhere.

#![cfg(test)]

use super::*;
use anyhow::ensure;
use base64::Engine as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Percent-encode one path segment (every byte outside RFC 3986's
/// unreserved set), as the live fixture's `urllib.parse.quote(v, safe="")`
/// does. A group store id is its topic, `x0x/group/<gid>/kv/<name>`, so
/// its slashes must not split the `/stores/:id/:key` route.
fn path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The members `label` lists for `group`; `Err` when the read itself fails
/// (non-2xx, or no `members` array).
pub(super) async fn members(sim: &Sim, label: &str, group: &str) -> Result<Vec<String>> {
    let (status, info) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await?;
    ensure!(status.is_success(), "{label} GET /groups/{group}: {status}");
    Ok(info["members"]
        .as_array()
        .context("no members array")?
        .iter()
        .filter_map(|member| member["agent_id"].as_str().map(str::to_string))
        .collect())
}

pub(super) async fn mesh(sim: &Sim, labels: &[&str]) -> Result<()> {
    sim.until("mesh up", secs(60), async |s: &Sim| {
        for label in labels {
            if s.connected_peer_count(label).await == 0 {
                return false;
            }
        }
        true
    })
    .await
}

pub(super) async fn create_group(sim: &Sim, owner: &str) -> Result<String> {
    let (status, created) = sim
        .api(
            owner,
            Method::POST,
            "/groups",
            Some(json!({"name": "w3h control", "display_name": owner, "preset": "private_secure"})),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    Ok(created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string())
}

pub(super) async fn invite(sim: &Sim, inviter: &str, group: &str) -> Result<String> {
    let (status, invite) = sim
        .api(
            inviter,
            Method::POST,
            &format!("/groups/{group}/invite"),
            Some(json!({})),
        )
        .await?;
    ensure!(status.is_success(), "invite: {status} {invite}");
    Ok(invite["invite_link"]
        .as_str()
        .context("invite response has no invite_link")?
        .to_string())
}

pub(super) async fn join(sim: &Sim, joiner: &str, link: &str) -> Result<()> {
    let (status, joined) = sim
        .api(
            joiner,
            Method::POST,
            "/groups/join",
            Some(json!({"invite": link, "display_name": joiner})),
        )
        .await?;
    ensure!(
        status.is_success() && joined["ok"] != false,
        "{joiner} join: {status} {joined}"
    );
    Ok(())
}

pub(super) async fn open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .api(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

/// `membership_state` of `group` as `label` reports it.
pub(super) async fn local_membership(sim: &Sim, label: &str, group: &str) -> Option<String> {
    let (status, body) = sim
        .request(label, Method::GET, &format!("/groups/{group}"), None)
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    body["membership_state"].as_str().map(str::to_string)
}

/// `POST /groups/:id/stores` without a barrier (for use inside one).
pub(super) async fn try_open_store(sim: &Sim, label: &str, group: &str) -> Result<String> {
    let (status, store) = sim
        .request(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "wiki"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} open store: {status} {store}");
    Ok(store["id"].as_str().context("store id")?.to_string())
}

pub(super) async fn read_value(sim: &Sim, label: &str, store: &str, key: &str) -> Option<String> {
    let (status, body) = sim
        .request(
            label,
            Method::GET,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            None,
        )
        .await
        .ok()?;
    if !status.is_success() {
        return None;
    }
    let bytes = BASE64.decode(body["value"].as_str()?).ok()?;
    String::from_utf8(bytes).ok()
}

/// `label` writes `value` under `key` in the group store `store`, inside
/// its own barrier (the S1 control's write, as a helper).
pub(super) async fn put_value(
    sim: &Sim,
    label: &str,
    store: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let (status, put) = sim
        .api(
            label,
            Method::PUT,
            &format!("/stores/{}/{}", path_segment(store), path_segment(key)),
            Some(json!({"value": BASE64.encode(value), "content_type": "text/plain"})),
        )
        .await?;
    ensure!(status.is_success(), "{label} put {key}: {status} {put}");
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w3h_clock_gate_holds_virtual_time_outside_barriers() -> Result<()> {
    let start = tokio::time::Instant::now();
    let gate = ClockGate::close();
    let sleeper = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(10)).await });
    // Stay idle for 300 ms of real time with a 10 s virtual timer pending.
    // Without the gate, paused tokio would auto-advance straight to it.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _ = tx.send(());
    });
    rx.await?;
    ensure!(
        tokio::time::Instant::now() == start,
        "virtual time moved while the gate was closed"
    );
    ensure!(!sleeper.is_finished(), "a 10 s timer fired while gated");
    gate.open().await;
    sleeper.await?;
    ensure!(tokio::time::Instant::now() >= start + Duration::from_secs(10));
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s1_control_group_invite_join_over_public_api() -> Result<()> {
    let sim = Sim::start(
        "w3h_s1_control_group_invite_join_over_public_api",
        0x5100_0001,
        &["A", "B", "C"],
    )
    .await?;
    mesh(&sim, &["A", "B", "C"]).await?;
    let group = create_group(&sim, "A").await?;
    for joiner in ["B", "C"] {
        let link = invite(&sim, "A", &group).await?;
        join(&sim, joiner, &link).await?;
    }
    let want = [
        sim.agent_hex("A")?,
        sim.agent_hex("B")?,
        sim.agent_hex("C")?,
    ];
    sim.until("A lists A, B and C", secs(180), async |s: &Sim| {
        members(s, "A", &group)
            .await
            .is_ok_and(|listed| want.iter().all(|id| listed.contains(id)))
    })
    .await?;
    sim.fabric().mark("checkpoint: membership converged on A");

    // Data-plane delivery: one write on A reaches B and C through the
    // group store (the same store id on every member). Each joiner must
    // first be seated locally (`membership_state == active`, the live
    // fixture's local readiness) and able to open the store, which needs
    // the group key; both are awaited inside named barriers.
    for member in ["B", "C"] {
        sim.until(
            &format!("{member} reports active membership"),
            secs(120),
            async |s: &Sim| local_membership(s, member, &group).await.as_deref() == Some("active"),
        )
        .await?;
    }
    let store = open_store(&sim, "A", &group).await?;
    for member in ["B", "C"] {
        let mut opened = None;
        let mut last = String::new();
        sim.until(
            &format!("{member} opens the group store"),
            secs(60),
            async |s: &Sim| match try_open_store(s, member, &group).await {
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
        .with_context(|| format!("{member} last store-open error: {last}"))?;
        ensure!(
            opened.as_deref() == Some(store.as_str()),
            "{member} opened a different store id: {opened:?}"
        );
    }
    let (status, put) = sim
        .api(
            "A",
            Method::PUT,
            &format!("/stores/{}/w3h-control", path_segment(&store)),
            Some(json!({"value": BASE64.encode("delivered"), "content_type": "text/plain"})),
        )
        .await?;
    ensure!(status.is_success(), "A put: {status} {put}");
    sim.until("B and C read A's write", secs(120), async |s: &Sim| {
        read_value(s, "B", &store, "w3h-control").await.as_deref() == Some("delivered")
            && read_value(s, "C", &store, "w3h-control").await.as_deref() == Some("delivered")
    })
    .await?;
    sim.fabric()
        .mark("checkpoint: group data delivered to B and C");
    sim.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s1_negative_control_offline_joiner_is_not_admitted() -> Result<()> {
    let sim = Sim::start(
        "w3h_s1_negative_control_offline_joiner_is_not_admitted",
        0x5100_0002,
        &["A", "B", "C"],
    )
    .await?;
    mesh(&sim, &["A", "B", "C"]).await?;
    let group = create_group(&sim, "A").await?;
    let link = invite(&sim, "A", &group).await?;
    let c_peer = sim.peer("C")?;
    let offline_at = sim.fabric().now();
    sim.set_online("C", false)?;
    // The join is a valid local attempt: C accepts it and queues the
    // request (the handler's only refusals are local durability/signing).
    join(&sim, "C", &link).await?;
    let c = sim.agent_hex("C")?;
    let what = "A lists C (must not happen)";
    // Only an expired budget with every read completed and successful is
    // "not admitted"; a failed or cut-off read is INFRA.
    let mut seen = Observations::default();
    let waited = sim
        .until(what, secs(60), async |s: &Sim| {
            match seen.observe(members(s, "A", &group)).await {
                Some(listed) => listed.contains(&c),
                None => true,
            }
        })
        .await;
    seen.verify(what)?;
    match waited {
        Ok(()) => bail!("an offline joiner was admitted"),
        Err(error) if expired(&error) => {}
        Err(error) => return Err(error),
    }
    // A's view at the frozen instant after the barrier closed.
    let listed = sim
        .at_instant("A members after the barrier", members(&sim, "A", &group))
        .await??;
    ensure!(!listed.contains(&c), "C is listed: {listed:?}");
    // The intended refusal: the transport refused C's attempts (dials or
    // sends) and nothing C wrote after going offline was delivered.
    let refused = sim.fabric().refused_since(&c_peer, offline_at);
    let delivered = sim.fabric().delivered_from_since(&c_peer, offline_at);
    ensure!(
        !refused.is_empty(),
        "C's join produced no transport refusal; the window did not exercise the fault"
    );
    ensure!(
        delivered.is_empty(),
        "{} frames from C were delivered while it was offline",
        delivered.len()
    );
    sim.fabric().mark(format!(
        "checkpoint: C refused {} times, 0 frames delivered",
        refused.len()
    ));
    sim.finish().await?;
    Ok(())
}

/// Streams (by pair and ordinal) whose opener wrote `prefix` first and
/// whose acceptor wrote a reply: (opener, acceptor) peer ids.
fn answered_streams(
    sim: &Sim,
    prefix: u8,
) -> Vec<(crate::network::sim::Key, crate::network::sim::Key)> {
    use crate::network::sim::LaneClass;
    let writes = sim.fabric().writes();
    writes
        .iter()
        .filter(|w| {
            matches!(w.lane.class, LaneClass::Stream(_))
                && w.seq == 0
                && w.bytes.first() == Some(&prefix)
        })
        .filter(|opener| {
            writes.iter().any(|reply| {
                reply.lane.class == opener.lane.class
                    && reply.lane.src == opener.lane.dst
                    && reply.lane.dst == opener.lane.src
                    && !reply.bytes.is_empty()
            })
        })
        .map(|w| (w.lane.src, w.lane.dst))
        .collect()
}

/// Whether `observer` holds `subject`'s network-verified evidence: the
/// pairing capture (unrelated peers) or the relationship store. Both are
/// written only after the evidence verified (`evidence_wire::ingest_hello`).
fn holds_verified_evidence(sim: &Sim, observer: &str, subject: &str) -> Result<bool> {
    let state = sim.state(observer)?;
    let agent = sim.state(subject)?.agent.agent_id();
    let now = crate::dm_capability::now_unix_ms();
    let captured = state
        .agent
        .capability_store
        .evidence_wire
        .get(agent, true, now)
        .is_some();
    let stored = state
        .agent
        .peer_evidence()
        .store()
        .is_some_and(|store| store.usable_agent(agent, now).is_some());
    Ok(captured || stored)
}

/// One EvidenceV1 stream as the fabric recorded it: who opened it, the
/// request and reply frames (each `kind`, u32 length, body), and when the
/// opener read the reply to its FIN.
struct EvidenceStream {
    opener: crate::network::sim::Key,
    acceptor: crate::network::sim::Key,
    opened_at: Duration,
    request: Option<(u8, Vec<u8>)>,
    reply: Option<(u8, Vec<u8>)>,
    reply_fin_read: Option<Duration>,
}

/// Exactly one whole frame (`kind`, u32 length, body), or `None`.
fn one_frame(bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
    let (&kind, rest) = bytes.split_first()?;
    let (len, body) = rest.split_first_chunk::<4>()?;
    (usize::try_from(u32::from_be_bytes(*len)).ok() == Some(body.len()))
        .then(|| (kind, body.to_vec()))
}

/// Every EvidenceV1 stream opened at or after `since`.
fn evidence_streams(sim: &Sim, since: Duration) -> Vec<EvidenceStream> {
    use crate::network::sim::{LaneClass, LaneKey};
    const EVIDENCE_V1: u8 = 0x06;
    let writes = sim.fabric().writes();
    let lane_bytes = |lane: LaneKey| {
        let mut on_lane: Vec<_> = writes.iter().filter(|w| w.lane == lane).collect();
        on_lane.sort_by_key(|w| w.seq);
        on_lane
            .iter()
            .flat_map(|w| w.bytes.iter().copied())
            .collect::<Vec<u8>>()
    };
    writes
        .iter()
        .filter(|w| {
            matches!(w.lane.class, LaneClass::Stream(_))
                && w.seq == 0
                && w.at >= since
                && w.bytes.first() == Some(&EVIDENCE_V1)
        })
        .map(|open| {
            let reverse = LaneKey {
                src: open.lane.dst,
                dst: open.lane.src,
                class: open.lane.class,
            };
            let request = lane_bytes(open.lane);
            EvidenceStream {
                opener: open.lane.src,
                acceptor: open.lane.dst,
                opened_at: open.at,
                request: request.get(1..).and_then(one_frame),
                reply: one_frame(&lane_bytes(reverse)),
                reply_fin_read: sim.fabric().fin_read_at(&reverse),
            }
        })
        .collect()
}

/// The announce digest of `label`'s own certificate pair, if it has a
/// certificate: what an ACK's `have_certificate` must equal for the node to
/// skip its CERTIFICATE follow-up (`mint_hello`).
fn own_certificate_digest(sim: &Sim, label: &str) -> Result<Option<[u8; 32]>> {
    let state = sim.state(label)?;
    let pair = state
        .agent
        .own_cert_pair
        .read()
        .map_err(|_| anyhow!("{label}: certificate pair lock poisoned"))?;
    Ok(pair
        .1
        .is_some()
        .then(|| crate::announce_v3::cert_digest(&pair.0, &pair.1)))
}

/// EvidenceV1 exchanges opened at or after `since` that the INITIATOR
/// completed, as `opener->acceptor …`. Every counted reply is one whole
/// frame that the opener read to its FIN, and the opener's resulting state
/// shows it accepted the reply:
/// - HELLO request, HELLO reply: the opener holds the acceptor's verified
///   evidence, and the acceptor opened no EvidenceV1 stream of its own to
///   the opener (so only the reply can have provided it);
/// - HELLO request, ACK reply whose `have_certificate` (bincode
///   `Option<[u8; 32]>`) differs from the opener's own certificate digest:
///   the opener acted on the decoded ACK by opening a CERTIFICATE exchange
///   to the acceptor afterwards, and that exchange completed too (an empty
///   ACK, read to FIN), which is the opener's only success outcome
///   (`send_certificate_if_missing`).
///
/// An ACK that leaves the opener nothing to send changes no opener state,
/// so it proves nothing about the opener and is not counted.
fn completed_evidence_exchanges(
    sim: &Sim,
    labels: &[&str],
    since: Duration,
) -> Result<Vec<String>> {
    // `evidence_wire.rs` message kinds.
    const HELLO: u8 = 1;
    const CERTIFICATE: u8 = 3;
    const ACK: u8 = 5;
    let mut peers = Vec::new();
    for label in labels {
        peers.push((sim.peer(label)?.0, *label));
    }
    let label_of = |key| peers.iter().find(|(peer, _)| *peer == key).map(|(_, l)| *l);
    let streams = evidence_streams(sim, since);
    let mut done = Vec::new();
    for stream in &streams {
        let (Some(opener), Some(acceptor)) = (label_of(stream.opener), label_of(stream.acceptor))
        else {
            continue;
        };
        let (Some((HELLO, _)), Some((reply_kind, reply)), Some(read_at)) =
            (&stream.request, &stream.reply, stream.reply_fin_read)
        else {
            continue;
        };
        match *reply_kind {
            HELLO => {
                let reverse_stream = streams.iter().any(|other| {
                    other.opener == stream.acceptor && other.acceptor == stream.opener
                });
                if !reverse_stream && holds_verified_evidence(sim, opener, acceptor)? {
                    done.push(format!("{opener}->{acceptor} HELLO/HELLO"));
                }
            }
            ACK => {
                let have = match reply.as_slice() {
                    [0] => None,
                    [1, digest @ ..] => match <[u8; 32]>::try_from(digest) {
                        Ok(digest) => Some(digest),
                        Err(_) => continue,
                    },
                    _ => continue,
                };
                let Some(own) = own_certificate_digest(sim, opener)? else {
                    continue;
                };
                if have == Some(own) {
                    continue;
                }
                let followed = streams.iter().any(|follow| {
                    follow.opener == stream.opener
                        && follow.acceptor == stream.acceptor
                        && follow.opened_at >= read_at
                        && matches!(&follow.request, Some((CERTIFICATE, _)))
                        && matches!(&follow.reply, Some((ACK, body)) if body.is_empty())
                        && follow.reply_fin_read.is_some()
                });
                if followed {
                    done.push(format!(
                        "{opener}->{acceptor} HELLO/ACK then CERTIFICATE/ACK"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(done)
}

/// S4 control: the peer-evidence hello (`EvidenceV1`) runs over simulated
/// byte streams between relationship peers, and the initiator completes it
/// (see [`completed_evidence_exchanges`]).
///
/// The topology matters (be1a8db CI: two strangers never exchanged any).
/// A Hello is sent only to a relationship peer: an enrolled machine, a
/// stored record or a live relationship (ADR 0089 §6; `begin_hello` refuses
/// when `!related`, `evidence_wire.rs:318`). Here X is O's same-owner
/// device: O enrolls X's machine before X starts, so O sends X a Hello on
/// connect.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s4_control_evidence_hello_over_sim_streams() -> Result<()> {
    let mut sim = Sim::empty(
        "w3h_s4_control_evidence_hello_over_sim_streams",
        0x5400_0001,
        &["O", "X"],
    )?;
    let outcome = evidence_hello_scenario(&mut sim).await;
    sim.conclude(outcome).await
}

async fn evidence_hello_scenario(sim: &mut Sim) -> Result<()> {
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = crate::identity::UserKeypair::generate()?;
    let home = sim.start_owner_device("O", &owner).await?;
    sim.certify_owner_device("O", "X", &owner, &home).await?;
    let mut done = Vec::new();
    let mut failure = None;
    sim.until(
        "an EvidenceV1 exchange between O and X completes",
        secs(60),
        async |s: &Sim| match completed_evidence_exchanges(s, &["O", "X"], Duration::ZERO) {
            Ok(found) => {
                done = found;
                !done.is_empty()
            }
            Err(error) => {
                failure = Some(error);
                true
            }
        },
    )
    .await?;
    if let Some(error) = failure {
        return Err(error.context("INFRA: reading evidence state"));
    }
    sim.fabric().mark(format!(
        "checkpoint: EvidenceV1 completed over sim streams: {}",
        done.join(", ")
    ));
    Ok(())
}

/// S4 control: owner sync (Tier-1, `SyncV1`) runs over simulated byte
/// streams, dialled by the daemons themselves, and delivers the canonical
/// Home pointer: a second same-owner device yields to the owner's Home.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon controls run in the Linux isolated namespace only"
)]
async fn w3h_s4_control_owner_sync_over_sim_streams() -> Result<()> {
    let mut sim = Sim::empty(
        "w3h_s4_control_owner_sync_over_sim_streams",
        0x5400_0002,
        &["O", "X"],
    )?;
    let outcome = owner_sync_scenario(&mut sim).await;
    sim.conclude(outcome).await
}

async fn owner_sync_scenario(sim: &mut Sim) -> Result<()> {
    const SYNC_V1: u8 = 0x05;
    // Before any daemon starts, like the node keys (`Sim::empty`).
    let owner = crate::identity::UserKeypair::generate()?;
    let home = sim.start_owner_device("O", &owner).await?;
    // Waits for X to report `elsewhere` with O's canonical Home id, which
    // only owner sync can deliver.
    sim.certify_owner_device("O", "X", &owner, &home).await?;
    let synced = answered_streams(sim, SYNC_V1);
    let (o, x) = (sim.peer("O")?.0, sim.peer("X")?.0);
    ensure!(
        synced.iter().any(|pair| *pair == (x, o) || *pair == (o, x)),
        "no answered SyncV1 stream between X and O"
    );
    sim.fabric()
        .mark("checkpoint: X yielded to O's Home via SyncV1 over sim streams");
    Ok(())
}
