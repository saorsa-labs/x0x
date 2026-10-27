//! W3-H case for #969 (leave, rekey, restart: a frame sealed under an old
//! epoch), the last missing #1164 case. Nodes: A (owner), B (member,
//! restarted), C (member, A removes it).
//!
//! The scenario mirrors the in-process oracle
//! `encrypted_kv_leave_rekey_restart_has_only_sealed_transport_payloads`
//! (`tests/encrypted_kv_transport.rs`):
//!
//! 1. A creates a `public_request_secure` group (the GSS plane — a
//!    `private_secure` group is TreeKEM and seals no GSS records); B and C
//!    join by card import and invite;
//! 2. A opens the encrypted store at epoch e0, B and C open the same store,
//!    A writes the pre key and B reads it;
//! 3. A removes C (the leave). The removal rekeys the store to e1 > e0
//!    (evidence, read from A's group state, never assumed);
//! 4. A writes the post key and B reads it — sealed at e1;
//! 5. B restarts gracefully, re-seats, re-opens the store at e1, reads the
//!    post key from its local replica and writes the restart key, which A
//!    reads — the restart-triggered control request and every other frame
//!    flow again;
//! 6. Oracle: every frame A, B or C sent on the store topic or its
//!    `/state-sync` side topic AFTER the rekey was observed complete is
//!    decoded from the fabric's recorded writes (pubsub lane → signed
//!    gossip inner → `(PeerId, EncryptedKvStoreRecordV1)`) and must be
//!    sealed under the CURRENT epoch e1 and open under the current secret.
//!    An e0 frame is tolerated only as an authenticated pre-rekey replay
//!    that carries no post-rekey key — the exact rule of the in-process
//!    oracle. #969's defect (a post-rekey frame sealed under the old
//!    epoch) is RED, named per frame.
//!
//! The window opens only after the rekey is observed (frames between the
//! removal request and the completed rekey are legitimately e0-sealed), and
//! the oracle proves itself first: before the removal it opens A's pre-key
//! frame under the saved e0 secret.
//!
//! A second cut at B's restart opens the restart recovery window: GREEN
//! also requires B's sealed `StateRequest` on the `/state-sync` side topic
//! and A's sealed recovery answer on the main topic, both after that
//! cut — the exchange the restart actually triggers, never a Control frame
//! B sent before it went down. (A's answer is its retained image when the
//! responder cooldown allows one, else its sealed re-propagation of B's
//! restarted-incarnation write; the case spans about 6 virtual seconds,
//! so the 15-second cooldown usually holds from the bootstrap serve.)

#![cfg(test)]

use super::control::{invite, join, local_membership, members, mesh, put_value, read_value};
use super::receipt::{Receipt, Verdict};
use super::*;
use crate::groups::{GroupInfo, GssKvSecureContext};
use crate::kv::encrypted::{open_mutation, EncryptedKvStoreRecordV1};
use crate::kv::{KvMutationKind, KvSecureContext, KvStoreDelta, KvStoreId};
use crate::mls::SecureGroupPlane;
use crate::network::sim::{LaneClass, Write};
use anyhow::ensure;
use base64::Engine as _;
use bincode::Options as _;
use serde_json::json;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const SEED: u64 = 0x0969_0001;
const CASE: &str = "w3h_969_leave_rekey_restart_seals_under_the_current_epoch";
const FINAL: &str = "every_relevant_frame_after_the_rekey_is_sealed_under_the_current_epoch";
const PRE_KEY: &str = "w3h-969-pre";
const PRE_VALUE: &str = "pre-value-969";
const POST_KEY: &str = "w3h-969-post";
const POST_VALUE: &str = "post-value-969";
const RESTART_KEY: &str = "w3h-969-restart";
const RESTART_VALUE: &str = "restart-value-969";
const SEAT_BUDGET: Duration = Duration::from_secs(180);
const STORE_BUDGET: Duration = Duration::from_secs(90);
const READ_BUDGET: Duration = Duration::from_secs(120);

/// A decoded sealed-record frame from the fabric's writes.
struct SealedFrame {
    from: String,
    to: String,
    topic: String,
    sender_hex: String,
    verified: bool,
    envelope: Vec<u8>,
    record: EncryptedKvStoreRecordV1,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The three nodes' labels and fabric keys.
fn peers_of(sim: &Sim) -> Result<Vec<(&'static str, [u8; 32])>> {
    let mut peers = Vec::new();
    for label in ["A", "B", "C"] {
        peers.push((label, sim.peer(label)?.0));
    }
    Ok(peers)
}

/// A fabric key's label (A, B or C), or its first bytes as hex.
fn label_in(peers: &[(&'static str, [u8; 32])], key: [u8; 32]) -> String {
    peers
        .iter()
        .find(|(_, peer)| *peer == key)
        .map(|(label, _)| label.to_string())
        .unwrap_or_else(|| hex::encode(&key[..4]))
}

/// One pubsub-lane write as a sealed store record, when it is one: the frame
/// must be an Eager gossip message whose signed inner envelope names one of
/// `topics` and whose payload is the `(PeerId, record)` envelope. `Err` is a
/// frame that names a store topic but is none of those things (RED, not a
/// skip); `Ok(None)` is every other frame.
/// The saorsa-gossip key-cache v3 wire marker (`key_cache::WIRE_MARKER`,
/// `pub(crate)` there): frames on the pubsub stream start with it, then a
/// postcard `WireMessage { header, payload, signature, key }`.
const SG_V3_MARKER: &[u8] = b"\xffSGKC\x03";

/// Mirror of saorsa-gossip-pubsub's private `WireMessage` (the postcard
/// field order and variant order are the wire contract; both crates use
/// plain serde derives).
#[derive(serde::Serialize, serde::Deserialize)]
struct WireV3 {
    header: saorsa_gossip_types::MessageHeader,
    payload: Option<bytes::Bytes>,
    signature: Vec<u8>,
    key: WireKey,
}

/// Mirror of `KeyMaterial`: variant 0 carries the full key, 1 a reference.
#[derive(serde::Serialize, serde::Deserialize)]
enum WireKey {
    Full {
        key_id: saorsa_gossip_types::PeerId,
        public_key: Vec<u8>,
    },
    Ref {
        key_id: saorsa_gossip_types::PeerId,
    },
}

/// Mirror of kv::sync's private `KvSyncMessage`, first variant only: the
/// bincode discriminant and field order are the sealed Control payload
/// contract (`wire_compat::decode_bincode`, fixint). A payload that decodes
/// to this mirror is a `StateRequest` naming its requester; every other
/// variant fails the discriminant check and is not one.
#[derive(serde::Deserialize)]
enum SyncControlPrefix {
    StateRequest {
        requester: saorsa_gossip_types::PeerId,
    },
}

fn decode_sealed(
    write: &Write,
    topics: &[String],
    label_of: &dyn Fn([u8; 32]) -> String,
) -> Result<Option<SealedFrame>> {
    if write.lane.class != LaneClass::PubSub {
        return Ok(None);
    }
    // Byte 0 is the gossip stream-type prefix; the rest is the frame.
    let Some(body) = write.bytes.get(1..) else {
        return Ok(None);
    };
    if !topics.iter().any(|topic| contains(body, topic.as_bytes())) {
        return Ok(None);
    }
    // Both framings carry the header first and the inner payload in
    // `payload`: the key-cache v3 marker plus its WireMessage, or a plain
    // legacy GossipMessage.
    let (kind, inner) = if let Some(v3_body) = body.strip_prefix(SG_V3_MARKER) {
        let wire: WireV3 = postcard::from_bytes(v3_body)
            .context("a store-topic frame is not a key-cache v3 WireMessage")?;
        (wire.header.kind, wire.payload)
    } else {
        let frame: saorsa_gossip_pubsub::GossipMessage = postcard::from_bytes(body)
            .context("a store-topic frame is not a gossip GossipMessage")?;
        (frame.header.kind, frame.payload)
    };
    ensure!(
        kind == saorsa_gossip_types::MessageKind::Eager,
        "a store-topic frame is not an Eager gossip message"
    );
    let inner = inner.context("a store-topic Eager frame has no payload")?;
    let message = crate::gossip::pubsub::decode_v2(&inner)
        .map_err(|error| anyhow!("store-topic frame is not a signed v2 envelope: {error}"))?;
    ensure!(
        topics.contains(&message.topic),
        "a frame carrying the topic bytes decodes to another topic {}",
        message.topic
    );
    let (_, record) = bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(16 * 1024 * 1024)
        .deserialize::<(saorsa_gossip_types::PeerId, EncryptedKvStoreRecordV1)>(&message.payload)
        .context("a store-topic payload is not an encrypted KV record envelope")?;
    Ok(Some(SealedFrame {
        from: label_of(write.lane.src),
        to: label_of(write.lane.dst),
        topic: message.topic,
        sender_hex: message
            .sender
            .map(|agent| hex::encode(agent.as_bytes()))
            .unwrap_or_default(),
        verified: message.verified,
        envelope: message.payload.to_vec(),
        record,
    }))
}

/// Whether a decrypted mutation's payload names `key` (the in-process
/// oracle's `mutation_contains_key`).
fn mutation_mentions(kind: KvMutationKind, payload: &[u8], key: &str) -> Result<bool> {
    match kind {
        KvMutationKind::Delta | KvMutationKind::FullState => {
            let delta: KvStoreDelta =
                bincode::deserialize(payload).context("decrypted KV delta does not decode")?;
            Ok(delta.added.contains_key(key)
                || delta.updated.contains_key(key)
                || delta.removed.contains_key(key))
        }
        KvMutationKind::RetainedState | KvMutationKind::Control => {
            Ok(contains(payload, key.as_bytes()))
        }
    }
}

/// The verdict on one post-rekey frame.
enum FrameCheck {
    /// Sealed under the current epoch and opened under the current secret.
    Current {
        mentions_post: bool,
        mentions_restart: bool,
    },
    /// An authenticated pre-rekey replay carrying no post-rekey key.
    ToleratedReplay,
    Defect(String),
}

#[allow(clippy::too_many_arguments)]
fn check_frame(
    frame: &SealedFrame,
    store: &KvStoreId,
    group_bytes: &[u8],
    previous: &GssKvSecureContext,
    current: &GssKvSecureContext,
    post_epoch: u64,
) -> FrameCheck {
    let where_ = format!("{}->{} on {}", frame.from, frame.to, frame.topic);
    if !frame.verified {
        return FrameCheck::Defect(format!("{where_}: inner signature did not verify"));
    }
    if frame.record.group_id != group_bytes {
        return FrameCheck::Defect(format!(
            "{where_}: wrong group binding {}",
            hex::encode(&frame.record.group_id)
        ));
    }
    if frame.record.store_id != *store.as_bytes() {
        return FrameCheck::Defect(format!(
            "{where_}: wrong store binding {}",
            hex::encode(frame.record.store_id)
        ));
    }
    // Plaintext that must never appear in a transport payload: every key
    // name and value the scenario wrote, in clear text and in base64 (the
    // API's wire form), as the in-process oracle scans for.
    for (what, bytes) in [
        (PRE_KEY, PRE_KEY.as_bytes()),
        (PRE_VALUE, PRE_VALUE.as_bytes()),
        (POST_KEY, POST_KEY.as_bytes()),
        (POST_VALUE, POST_VALUE.as_bytes()),
        (RESTART_KEY, RESTART_KEY.as_bytes()),
        (RESTART_VALUE, RESTART_VALUE.as_bytes()),
        ("b64 pre value", BASE64.encode(PRE_VALUE).as_bytes()),
        ("b64 post value", BASE64.encode(POST_VALUE).as_bytes()),
        ("b64 restart value", BASE64.encode(RESTART_VALUE).as_bytes()),
    ] {
        if contains(&frame.envelope, bytes) {
            return FrameCheck::Defect(format!("{where_}: recognizable plaintext ({what})"));
        }
    }
    if frame.record.epoch == post_epoch {
        return match open_mutation(current, store, &frame.record) {
            Ok(mutation) => FrameCheck::Current {
                mentions_post: mutation_mentions(mutation.kind, &mutation.payload, POST_KEY)
                    .unwrap_or(false),
                mentions_restart: mutation_mentions(mutation.kind, &mutation.payload, RESTART_KEY)
                    .unwrap_or(false),
            },
            Err(error) => FrameCheck::Defect(format!(
                "{where_}: current-epoch frame failed authenticated open: {error}"
            )),
        };
    }
    if frame.record.epoch > post_epoch {
        return FrameCheck::Defect(format!(
            "{where_}: epoch {} is ahead of the group's {}",
            frame.record.epoch, post_epoch
        ));
    }
    // A pre-rekey epoch after the rekey: only an authenticated replay of
    // pre-rekey content is tolerable (#969 sealed post-rekey content under
    // old epoch; the in-process oracle's rule).
    match open_mutation(previous, store, &frame.record) {
        Ok(mutation) => {
            for key in [POST_KEY, RESTART_KEY] {
                match mutation_mentions(mutation.kind, &mutation.payload, key) {
                    Ok(true) => {
                        return FrameCheck::Defect(format!(
                            "{where_}: post-rekey key {key} sealed under the pre-rekey epoch {}",
                            frame.record.epoch
                        ))
                    }
                    Ok(false) => {}
                    Err(error) => {
                        return FrameCheck::Defect(format!(
                            "{where_}: pre-rekey-epoch payload invalid: {error}"
                        ))
                    }
                }
            }
            FrameCheck::ToleratedReplay
        }
        Err(error) => FrameCheck::Defect(format!(
            "{where_}: pre-rekey-epoch frame failed authenticated open under the saved secret: \
             {error}"
        )),
    }
}

/// The post-rekey oracle over every frame A, B and C sent from `cut` on.
struct Oracle {
    relevant: usize,
    current: usize,
    tolerated: usize,
    defects: Vec<String>,
    a_post_write: bool,
    b_restart_write: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_oracle(
    sim: &Sim,
    cut: usize,
    topics: &[String],
    store: &KvStoreId,
    group_bytes: &[u8],
    previous: &GssKvSecureContext,
    current: &GssKvSecureContext,
    post_epoch: u64,
    side_topic: &str,
) -> Result<Oracle> {
    let peers = peers_of(sim)?;
    let label_of = |key: [u8; 32]| label_in(&peers, key);
    let mut out = Oracle {
        relevant: 0,
        current: 0,
        tolerated: 0,
        defects: Vec::new(),
        a_post_write: false,
        b_restart_write: false,
    };
    for (_label, peer) in &peers {
        for write in sim
            .fabric()
            .writes_from_between(&ant_quic::PeerId(*peer), cut..usize::MAX)
        {
            let Some(frame) = decode_sealed(&write, topics, &label_of)? else {
                continue;
            };
            out.relevant += 1;
            match check_frame(&frame, store, group_bytes, previous, current, post_epoch) {
                FrameCheck::Current {
                    mentions_post,
                    mentions_restart,
                } => {
                    out.current += 1;
                    // Coverage, not a wire contract: a member's write may be
                    // served to its reader as a delta or as a full/retained
                    // state image (the serve shape depends on PlumTree peer
                    // state at publish time — the unshimmed coverage job
                    // took the retained shape), so any current-epoch frame
                    // from the writer naming the key proves the traffic.
                    let main_topic = frame.topic != side_topic;
                    match (
                        frame.from.as_str(),
                        main_topic,
                        mentions_post,
                        mentions_restart,
                    ) {
                        ("A", true, true, _) => out.a_post_write = true,
                        ("B", true, _, true) => out.b_restart_write = true,
                        _ => {}
                    }
                }
                FrameCheck::ToleratedReplay => out.tolerated += 1,
                FrameCheck::Defect(why) => out.defects.push(why),
            }
        }
    }
    Ok(out)
}

/// The restart recovery exchange after `restart_cut`: when B's sealed
/// `StateRequest` on the side topic and A's sealed recovery answer were
/// sent (fabric virtual time), so a GREEN proves the exchange happened,
/// not merely that both nodes stayed quiet-sealed.
#[derive(Default)]
struct RestartExchange {
    b_request_at: Option<Duration>,
    a_answer_at: Option<Duration>,
}

impl RestartExchange {
    fn happened(&self) -> bool {
        self.b_request_at.is_some() && self.a_answer_at.is_some()
    }

    fn describe(&self) -> String {
        let show = |at: Option<Duration>| {
            at.map(|at| format!("{}us", at.as_micros()))
                .unwrap_or_else(|| "never".to_string())
        };
        format!(
            "b_state_request_at={} a_recovery_answer_at={}",
            show(self.b_request_at),
            show(self.a_answer_at)
        )
    }
}

/// The restart recovery oracle: over B's and A's writes from `restart_cut`
/// (taken after B's new incarnation is up), find B's `StateRequest` — a
/// Control-kind frame on the side topic whose payload decodes to the
/// mirror's first variant naming B's own peer and whose sealed author is
/// B's agent — and A's recovery answer: a current-epoch frame of A's on
/// the main topic that is a retained image (`RetainedState`, the answer
/// shape when the responder's cooldown allows one) or names the restart
/// key (A's sealed re-propagation of B's restarted-incarnation write —
/// in this harness A's full-state answer to the post-restart request is
/// suppressed by the responder's `STATE_RESPONSE_COOLDOWN_SECS` window:
/// A's last full serve was the bootstrap about 2.6 virtual seconds
/// earlier, and the whole case spans about 6 virtual seconds). Either
/// shape proves A carried B's restarted-incarnation traffic; the trace
/// artifact records which. Every frame in this window is also judged by
/// [`run_oracle`], so a frame that fails its authenticated open fails the
/// case there; here an open failure only means the frame is not one of
/// the two exchange shapes being classified.
fn run_restart_exchange(
    sim: &Sim,
    restart_cut: usize,
    topics: &[String],
    side_topic: &str,
    store: &KvStoreId,
    current: &GssKvSecureContext,
    post_epoch: u64,
) -> Result<RestartExchange> {
    let b_peer = sim.peer("B")?.0;
    let b_agent = sim.agent_hex("B")?;
    let mut out = RestartExchange::default();
    for label in ["B", "A"] {
        let peer_key = sim.peer(label)?.0;
        let peers = [(label, peer_key)];
        for write in sim
            .fabric()
            .writes_from_between(&ant_quic::PeerId(peer_key), restart_cut..usize::MAX)
        {
            let label_of = |key: [u8; 32]| label_in(&peers, key);
            let Some(frame) = decode_sealed(&write, topics, &label_of)? else {
                continue;
            };
            let Ok(mutation) = open_mutation(current, store, &frame.record) else {
                continue;
            };
            if !frame.verified || mutation.epoch != post_epoch {
                continue;
            }
            if label == "B"
                && frame.topic == side_topic
                && mutation.kind == KvMutationKind::Control
                && hex::encode(mutation.author_id.as_bytes()) == b_agent
            {
                let request = bincode::options()
                    .with_fixint_encoding()
                    .allow_trailing_bytes()
                    .deserialize::<SyncControlPrefix>(&mutation.payload)
                    .ok();
                if matches!(request, Some(SyncControlPrefix::StateRequest { requester }) if requester.as_bytes() == &b_peer)
                {
                    out.b_request_at = Some(out.b_request_at.unwrap_or(write.at));
                }
            }
            if label == "A"
                && frame.topic != side_topic
                && (mutation.kind == KvMutationKind::RetainedState
                    || mutation_mentions(mutation.kind, &mutation.payload, RESTART_KEY)
                        .unwrap_or(false))
            {
                out.a_answer_at = Some(out.a_answer_at.unwrap_or(write.at));
            }
        }
    }
    Ok(out)
}

/// `POST /groups/:id/stores` without a barrier (for use inside one): the
/// store's full metadata, including its current `epoch`.
async fn try_open_meta(sim: &Sim, label: &str, group: &str) -> Result<serde_json::Value> {
    let (status, store) = sim
        .request(
            label,
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "transport"})),
        )
        .await?;
    ensure!(
        status.is_success() && store["policy"] == "encrypted",
        "{label} open store: {status} {store}"
    );
    Ok(store)
}

/// A's persisted view of `group`, at a frozen instant.
async fn group_info(sim: &Sim, group: &str) -> Result<GroupInfo> {
    let state = sim.state("A")?;
    sim.within("read A's group state", secs(5), async {
        state
            .named_groups
            .read()
            .await
            .get(group)
            .cloned()
            .context("A has no such group")
    })
    .await?
}

/// Wait until `member` is listed by `owner` and reports itself active.
async fn wait_seated(sim: &Sim, owner: &str, member: &str, group: &str, what: &str) -> Result<()> {
    let id = sim.agent_hex(member)?;
    let mut seen = Observations::default();
    sim.until(what, SEAT_BUDGET, async |s: &Sim| {
        let Some(listed) = seen.observe(members(s, owner, group)).await else {
            return true;
        };
        listed.contains(&id)
            && local_membership(s, member, group).await.as_deref() == Some("active")
    })
    .await?;
    seen.verify(what)?;
    Ok(())
}

async fn scenario(sim: &mut Sim, receipt: &mut Receipt) -> Result<bool> {
    let at = |sim: &Sim| sim.fabric().now().as_micros();
    mesh(sim, &["A", "B", "C"]).await?;
    let (status, created) = sim
        .api(
            "A",
            Method::POST,
            "/groups",
            Some(json!({
                "name": "w3h 969 leave rekey restart",
                "display_name": "A",
                "preset": "public_request_secure"
            })),
        )
        .await?;
    ensure!(
        status.is_success() && created["ok"] == true,
        "create: {status} {created}"
    );
    let group = created["group_id"]
        .as_str()
        .context("create response has no group_id")?
        .to_string();

    let (card_status, card) = sim
        .api("A", Method::GET, &format!("/groups/cards/{group}"), None)
        .await?;
    ensure!(card_status.is_success(), "GET card: {card_status} {card}");
    for joiner in ["B", "C"] {
        let (import_status, imported) = sim
            .api(
                joiner,
                Method::POST,
                "/groups/cards/import",
                Some(card.clone()),
            )
            .await?;
        ensure!(
            import_status.is_success() && imported["ok"] != false,
            "{joiner} card import: {import_status} {imported}"
        );
        let link = invite(sim, "A", &group).await?;
        join(sim, joiner, &link).await?;
        wait_seated(
            sim,
            "A",
            joiner,
            &group,
            &format!("{joiner} seated in A's group"),
        )
        .await?;
    }

    let (open_status, opened) = sim
        .api(
            "A",
            Method::POST,
            &format!("/groups/{group}/stores"),
            Some(json!({"name": "transport"})),
        )
        .await?;
    ensure!(
        open_status.is_success() && opened["policy"] == "encrypted",
        "A open store: {open_status} {opened}"
    );
    let topic = opened["topic"].as_str().context("store topic")?.to_string();
    let side_topic = format!("{topic}/state-sync");
    let store_hex = opened["store_id"].as_str().context("store id")?.to_string();
    let store_bytes = hex::decode(&store_hex).context("store id hex")?;
    let store = KvStoreId::new(
        store_bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| anyhow!("store id is {} bytes, not 32", bytes.len()))?,
    );
    let group_bytes = opened["group_id"]
        .as_str()
        .context("stable group id")?
        .as_bytes()
        .to_vec();
    let e0 = opened["epoch"].as_u64().context("store epoch")?;
    for joiner in ["B", "C"] {
        let what = format!("{joiner} opens the same store at epoch {e0}");
        let mut last = String::new();
        sim.until(&what, STORE_BUDGET, async |s: &Sim| {
            match try_open_meta(s, joiner, &group).await {
                Ok(meta) => meta["topic"] == topic.as_str() && meta["epoch"].as_u64() == Some(e0),
                Err(error) => {
                    last = format!("{error:#}");
                    false
                }
            }
        })
        .await
        .with_context(|| format!("{joiner} last store-open error: {last}"))?;
    }
    put_value(sim, "A", &topic, PRE_KEY, PRE_VALUE).await?;
    sim.until("B reads the pre-rekey key", READ_BUDGET, async |s: &Sim| {
        read_value(s, "B", &topic, PRE_KEY).await.as_deref() == Some(PRE_VALUE)
    })
    .await?;
    receipt.setup_done(at(sim));

    // The group must run the GSS plane: a TreeKEM group seals no
    // EncryptedKvStoreRecordV1 at all, so the case would prove nothing.
    let previous_info = group_info(sim, &group).await?;
    let gss = previous_info.secure_plane == SecureGroupPlane::Gss
        && previous_info.shared_secret.is_some();
    receipt.evidence(
        "group runs the GSS plane with a shared secret",
        gss,
        format!(
            "secure_plane={:?} epoch={}",
            previous_info.secure_plane, previous_info.secret_epoch
        ),
        at(sim),
    );
    ensure!(
        gss,
        "the group is not on the GSS plane; the case proves nothing"
    );
    let previous = GssKvSecureContext::from_group(&previous_info)
        .context("no GSS context before the removal")?;
    ensure!(
        previous.current_epoch() == e0,
        "A's group epoch {} is not the store epoch {e0}",
        previous.current_epoch()
    );

    // Oracle self-proof on a known-good frame: A's pre-key write, sealed at
    // e0, opens under the saved secret and names the pre key.
    let topics = [topic.clone(), side_topic.clone()];
    let peers = peers_of(sim)?;
    let label_of = |key: [u8; 32]| label_in(&peers, key);
    let mut self_proof = None;
    for write in sim.fabric().writes() {
        if write.lane.src != sim.peer("A")?.0 {
            continue;
        }
        // A decode error on a store-topic frame is a harness-visible fault
        // here too, never a silent skip.
        let Some(frame) = decode_sealed(&write, &topics, &label_of)? else {
            continue;
        };
        if frame.topic != topic || frame.record.epoch != e0 {
            continue;
        }
        match open_mutation(&previous, &store, &frame.record) {
            Ok(mutation)
                if mutation.kind == KvMutationKind::Delta
                    && mutation_mentions(mutation.kind, &mutation.payload, PRE_KEY)? =>
            {
                self_proof = Some(format!(
                    "sender={} kind={:?} epoch={}",
                    frame.sender_hex, mutation.kind, frame.record.epoch
                ));
                break;
            }
            _ => {}
        }
    }
    receipt.evidence(
        "the oracle opens A's pre-key seal under the saved epoch-e0 secret",
        self_proof.is_some(),
        self_proof
            .as_deref()
            .unwrap_or("no e0 main-topic frame decoded"),
        at(sim),
    );
    ensure!(
        self_proof.is_some(),
        "the oracle saw no pre-rekey seal to prove itself on"
    );

    // Leave: A removes C. The removal must rekey the store.
    let c_hex = sim.agent_hex("C")?;
    let (removed_status, removed) = sim
        .api(
            "A",
            Method::DELETE,
            &format!("/groups/{group}/members/{c_hex}"),
            None,
        )
        .await?;
    ensure!(
        removed_status.is_success(),
        "remove C: {removed_status} {removed}"
    );
    let what = "A's store re-open reports an epoch above e0 after C's removal";
    let mut last = String::new();
    let mut post_epoch = None;
    sim.until(what, READ_BUDGET, async |s: &Sim| {
        match try_open_meta(s, "A", &group).await {
            Ok(meta) => match meta["epoch"].as_u64() {
                Some(epoch) if epoch > e0 => {
                    post_epoch = Some(epoch);
                    true
                }
                _ => false,
            },
            Err(error) => {
                last = format!("{error:#}");
                false
            }
        }
    })
    .await
    .with_context(|| format!("A's re-open never showed a rekey; last error: {last}"))?;
    let post_epoch = post_epoch.context("no post-removal epoch was read")?;
    let current_info = group_info(sim, &group).await?;
    let rekeyed = current_info.secret_epoch == post_epoch && post_epoch > e0;
    receipt.evidence(
        "C's removal rekeyed the store",
        rekeyed,
        format!(
            "e0={e0} post_epoch={post_epoch} secret_epoch={}",
            current_info.secret_epoch
        ),
        at(sim),
    );
    ensure!(rekeyed, "the removal did not rekey the store");
    let listed = sim
        .at_instant("A's roster after C's removal", members(sim, "A", &group))
        .await??;
    receipt.evidence(
        "A no longer lists C",
        !listed.contains(&c_hex),
        format!("members={listed:?}"),
        at(sim),
    );
    ensure!(
        !listed.contains(&c_hex),
        "A still lists C after its removal"
    );
    let current =
        GssKvSecureContext::from_group(&current_info).context("no GSS context after the rekey")?;
    ensure!(
        current.current_epoch() == post_epoch,
        "the current context epoch {} is not {post_epoch}",
        current.current_epoch()
    );
    let cut = sim
        .fabric()
        .cut("case 969: rekey observed, the post-rekey frame window opens");

    put_value(sim, "A", &topic, POST_KEY, POST_VALUE).await?;
    sim.until(
        "B reads the post-rekey key",
        READ_BUDGET,
        async |s: &Sim| read_value(s, "B", &topic, POST_KEY).await.as_deref() == Some(POST_VALUE),
    )
    .await?;

    // Restart: B stops gracefully and comes back on the same dirs.
    let before = sim
        .fabric()
        .incarnation_of(&sim.peer("B")?)
        .context("B is not on the fabric")?;
    sim.restart("B", RestartMode::Graceful).await?;
    let after = sim
        .fabric()
        .incarnation_of(&sim.peer("B")?)
        .context("B is not on the fabric after its restart")?;
    ensure!(
        after == before + 1,
        "B restarted as incarnation {after}, expected {before}+1"
    );
    // The restart recovery window: the fabric refuses writes from B's
    // stopped incarnation, so a `StateRequest` found from this cut on is
    // the restarted node's own, never one B sent before it went down.
    let restart_cut = sim
        .fabric()
        .cut("case 969: B is back, the restart recovery window opens");
    wait_seated(sim, "A", "B", &group, "B seated again after its restart").await?;
    let what = "B re-opens the store at the current epoch after its restart";
    let mut last = String::new();
    let mut b_epoch = None;
    sim.until(what, STORE_BUDGET, async |s: &Sim| {
        match try_open_meta(s, "B", &group).await {
            Ok(meta) if meta["topic"] == topic.as_str() => {
                b_epoch = meta["epoch"].as_u64();
                b_epoch.is_some_and(|epoch| epoch >= post_epoch)
            }
            Ok(_) => false,
            Err(error) => {
                last = format!("{error:#}");
                false
            }
        }
    })
    .await
    .with_context(|| format!("B's re-open never settled; last error: {last}"))?;
    let b_epoch = b_epoch.unwrap_or(0);
    receipt.evidence(
        "B re-opened the store at the current epoch after its restart",
        b_epoch >= post_epoch,
        format!("b_epoch={b_epoch} post_epoch={post_epoch}"),
        at(sim),
    );
    ensure!(
        b_epoch >= post_epoch,
        "B re-opened at epoch {b_epoch} < {post_epoch}"
    );
    sim.until(
        "B still reads the post-rekey key after its restart",
        READ_BUDGET,
        async |s: &Sim| read_value(s, "B", &topic, POST_KEY).await.as_deref() == Some(POST_VALUE),
    )
    .await?;
    put_value(sim, "B", &topic, RESTART_KEY, RESTART_VALUE).await?;
    sim.until(
        "A reads B's post-restart key",
        READ_BUDGET,
        async |s: &Sim| {
            read_value(s, "A", &topic, RESTART_KEY).await.as_deref() == Some(RESTART_VALUE)
        },
    )
    .await?;
    sim.fabric()
        .mark("checkpoint: leave, rekey and restart all carried store traffic");

    let oracle = run_oracle(
        sim,
        cut,
        &topics,
        &store,
        &group_bytes,
        &previous,
        &current,
        post_epoch,
        &side_topic,
    )?;
    let exchange = run_restart_exchange(
        sim,
        restart_cut,
        &topics,
        &side_topic,
        &store,
        &current,
        post_epoch,
    )?;
    receipt.request_delivered(
        "B's restarted incarnation sent a sealed StateRequest on the side topic",
        exchange.b_request_at.is_some(),
        format!(
            "restart_window_from_cut={restart_cut} {}",
            exchange.describe()
        ),
        at(sim),
    );
    receipt.evidence(
        "A carried B's restarted-incarnation traffic: a sealed retained image or its sealed \
         re-propagation of B's restart write, after the cut",
        exchange.a_answer_at.is_some(),
        exchange.describe(),
        at(sim),
    );
    let coverage = oracle.a_post_write && oracle.b_restart_write && exchange.happened();
    receipt.evidence(
        "the oracle saw post-rekey sealed traffic from both members and the restart recovery \
         exchange",
        coverage,
        format!(
            "a_post_write={} b_restart_write={} {}",
            oracle.a_post_write,
            oracle.b_restart_write,
            exchange.describe()
        ),
        at(sim),
    );
    let clean = oracle.defects.is_empty();
    if !clean {
        receipt.cause(
            "a relevant frame after the rekey was sealed under the pre-rekey epoch or failed \
             its authenticated open",
            Some(oracle.defects.join("; ")),
            true,
            at(sim),
        );
    }
    Ok(clean)
}

async fn run(case: &str, seed: u64) -> Receipt {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(
        "The frame oracle reads the fabric's recorded pubsub-lane writes (send-side, per \
         peer). Lazy IHAVE/IWANT digest frames carry no record; sealed records ride Eager \
         frames. A pre-rekey-epoch frame after the rekey is tolerated only when it opens \
         under the saved pre-rekey secret and names no post-rekey key — the in-process \
         oracle's rule (tests/encrypted_kv_transport.rs).",
    );
    let clean = match Sim::start(case, seed, &["A", "B", "C"]).await {
        Ok(mut sim) => {
            let outcome = scenario(&mut sim, &mut receipt).await;
            let clean = match outcome {
                Ok(clean) => clean,
                Err(error) => {
                    receipt.infra(format!("{error:#}"), sim.fabric().now().as_micros());
                    false
                }
            };
            if let Err(error) = sim.finish().await {
                receipt.infra(format!("finish: {error:#}"), 0);
            }
            clean
        }
        Err(error) => {
            receipt.infra(format!("sim: {error:#}"), 0);
            false
        }
    };
    if receipt.verdict().is_none() {
        receipt.finish(FINAL, clean && !receipt.has_infra(), 0);
    }
    if receipt.has_infra() {
        receipt.reclassify(FINAL);
    }
    receipt.emit();
    receipt
}

/// The #969 case: after leave, rekey and restart, every relevant frame is
/// sealed under the current epoch (expected GREEN on main; the in-process
/// oracle passes).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "W3-H daemon cases run in the Linux isolated namespace only"
)]
async fn w3h_969_leave_rekey_restart_seals_under_the_current_epoch() -> Result<()> {
    let receipt = run(CASE, SEED).await;
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{CASE}: expected GREEN, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// The frame oracle's decode chain, proved on a locally built frame (it runs
/// everywhere; the daemon case itself needs the Linux namespace). The frame
/// is exactly what the transport sends: stream-type byte, then the Eager
/// gossip `GossipMessage`, whose payload is the signed v2 inner envelope
/// carrying `(PeerId, EncryptedKvStoreRecordV1)`.
#[test]
fn w3h_969_frame_oracle_decodes_a_sealed_transport_frame() -> Result<()> {
    use crate::gossip::pubsub::test_support;
    use bytes::Bytes;

    let topic = "x0x/group/w3h-969/kv/transport";
    let record = EncryptedKvStoreRecordV1 {
        group_id: b"w3h-969-group".to_vec(),
        store_id: [7; 32],
        epoch: 9,
        nonce: [3; 24],
        ciphertext: vec![0xA5; 64],
    };
    let payload = bincode::options()
        .with_fixint_encoding()
        .serialize(&(saorsa_gossip_types::PeerId::new([1; 32]), record))?;
    let author = test_support::signing_context();
    let inner = test_support::signed_inner_v2(&author, topic, &Bytes::from(payload));
    let frame = test_support::outer_v2_frame(
        saorsa_gossip_types::TopicId::from_entity(topic.as_bytes()),
        inner.clone(),
        [9; 32],
    );
    let lane = |class: LaneClass| crate::network::sim::LaneKey {
        src: [1; 32],
        dst: [2; 32],
        class,
    };
    // A fabric write: the lane class always agrees with the stream-type
    // prefix byte (`LaneClass::of`), as the recording transport tags it.
    let write = |class: LaneClass, prefix: u8, body: &[u8]| Write {
        lane: lane(class),
        seq: 0,
        pair_ordinal: 0,
        at: Duration::ZERO,
        bytes: [&[prefix][..], body].concat().into(),
    };
    let pubsub_byte = saorsa_gossip_transport::GossipStreamType::PubSub.to_byte();
    let membership_byte = saorsa_gossip_transport::GossipStreamType::Membership.to_byte();
    let pubsub_write = write(LaneClass::PubSub, pubsub_byte, &frame);
    let label_of = |key: [u8; 32]| hex::encode(&key[..4]);

    let decoded = decode_sealed(&pubsub_write, &[topic.to_string()], &label_of)?
        .context("a valid sealed frame did not decode")?;
    ensure!(decoded.verified, "the inner signature did not verify");
    ensure!(decoded.topic == topic, "wrong topic {}", decoded.topic);
    ensure!(
        decoded.record.store_id == [7; 32]
            && decoded.record.epoch == 9
            && decoded.record.group_id == b"w3h-969-group".to_vec(),
        "wrong record binding: {:?}",
        decoded.record
    );

    // The key-cache v3 framing the fabric actually recorded in CI: the
    // marker plus the WireMessage mirror, serialized back through the same
    // serde derives, must decode through the same path.
    let mut header = saorsa_gossip_types::MessageHeader {
        version: 1,
        payload_hash: None,
        topic: saorsa_gossip_types::TopicId::from_entity(topic.as_bytes()),
        msg_id: [9; 32],
        kind: saorsa_gossip_types::MessageKind::Eager,
        hop: 0,
        ttl: 10,
    };
    header.seal_payload_hash(Some(&inner));
    let wire = WireV3 {
        header,
        payload: Some(inner.clone()),
        signature: vec![0xAB; 3309],
        key: WireKey::Full {
            key_id: saorsa_gossip_types::PeerId::new([3; 32]),
            public_key: vec![0xCD; 1952],
        },
    };
    let v3_body = [SG_V3_MARKER, &postcard::to_stdvec(&wire)?].concat();
    let v3_write = write(LaneClass::PubSub, pubsub_byte, &v3_body);
    let decoded_v3 = decode_sealed(&v3_write, &[topic.to_string()], &label_of)?
        .context("a valid v3-framed seal did not decode")?;
    ensure!(
        decoded_v3.verified && decoded_v3.topic == topic && decoded_v3.record.epoch == 9,
        "the v3-framed seal decoded wrong: {:?}",
        decoded_v3.record
    );

    // An unrelated topic never enters the oracle.
    let other = write(LaneClass::PubSub, pubsub_byte, &frame);
    ensure!(
        decode_sealed(&other, &["x0x/group/other/kv/x".to_string()], &label_of)?.is_none(),
        "a frame on another topic was treated as relevant"
    );
    // The membership stream is not the sealed-record path.
    let membership = write(LaneClass::Membership, membership_byte, &frame);
    ensure!(
        decode_sealed(&membership, &[topic.to_string()], &label_of)?.is_none(),
        "a membership-stream frame entered the oracle"
    );
    // Bytes naming the topic but not forming a gossip frame are an error,
    // never a silent skip.
    let junk = write(
        LaneClass::PubSub,
        pubsub_byte,
        &[topic.as_bytes(), &[0xFF; 8][..]].concat(),
    );
    ensure!(
        decode_sealed(&junk, &[topic.to_string()], &label_of).is_err(),
        "malformed store-topic bytes decoded or were skipped"
    );
    Ok(())
}
