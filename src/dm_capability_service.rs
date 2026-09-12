//! Runtime service that publishes this agent's DM capability advert to the
//! mesh-wide `x0x/caps/v1` topic and consumes peers' adverts into a
//! shared [`crate::dm_capability::CapabilityStore`].

use crate::dm::DmCapabilities;
use crate::dm_capability::{
    now_unix_ms, CapabilityAdvert, CapabilityStore, ADVERT_PUBLISH_INTERVAL_SECS,
    DM_CAPABILITY_TARGETED_REQUEST_TOPIC, DM_CAPABILITY_TARGETED_RESPONSE_TOPIC,
    DM_CAPABILITY_TOPIC,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, PubSubMessage, SigningContext};
use crate::identity::{AgentId, MachineId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const ADVERT_PROTOCOL_VERSION: u16 = 1;

const TARGETED_REQUEST_PROTOCOL_VERSION: u16 = 2;

/// Domain prefix that lets a targeted request ride the steady advert topic
/// without a pre-0030 subscriber mistaking it for an advert.
const WARM_TARGETED_REQUEST_DOMAIN: &[u8] = b"x0x/caps/v1/targeted-request-v2\0";

const FIRST_PUBLISH_DELAY_MS: u64 = 250;

/// A verified requester can make one peer republish public data, but must not
/// be able to amplify traffic without bound. Exactly one daemon answers a
/// targeted request, so a short global coalescing window suffices to keep a
/// burst of concurrent strict sends from producing an advert storm.
const MIN_TARGETED_RESPONSE_INTERVAL_SECS: u64 = 1;

/// Startup-burst schedule so late-joining peers catch our advert quickly.
const STARTUP_BURST_INTERVALS_MS: &[u64] = &[5_000, 10_000, 20_000, 45_000];

#[derive(Debug, Serialize, Deserialize)]
struct TargetedCapabilityAdvertRequest {
    protocol_version: u16,
    requested_agent_id: [u8; 32],
}

// There is deliberately no request nonce. PubSub authenticates the requester,
// and the responder answers with its independently signed current-state
// advert rather than a challenge response. A nonce that is neither echoed nor
// bound into the accepted advert would add bytes and security claims without
// providing replay protection.

/// Decode a targeted capability request according to its exact topic-owned
/// wire contract.
///
/// On the dedicated request topic the payload is a bare postcard record. On
/// the steady advert topic it must carry the domain prefix and be consumed
/// exactly, so a pre-0030 subscriber sees an undecodable advert rather than
/// mistaking the request for one.
pub(crate) fn decode_targeted_capability_request(topic: &str, payload: &[u8]) -> Option<AgentId> {
    let request: TargetedCapabilityAdvertRequest = match topic {
        DM_CAPABILITY_TARGETED_REQUEST_TOPIC => postcard::from_bytes(payload).ok()?,
        DM_CAPABILITY_TOPIC => {
            let encoded = payload.strip_prefix(WARM_TARGETED_REQUEST_DOMAIN)?;
            let (request, trailing) =
                postcard::take_from_bytes::<TargetedCapabilityAdvertRequest>(encoded).ok()?;
            if !trailing.is_empty() {
                return None;
            }
            request
        }
        _ => return None,
    };
    (request.protocol_version == TARGETED_REQUEST_PROTOCOL_VERSION)
        .then_some(AgentId(request.requested_agent_id))
}

fn encode_targeted_capability_request(requested_agent_id: AgentId) -> NetworkResult<Vec<u8>> {
    let request = TargetedCapabilityAdvertRequest {
        protocol_version: TARGETED_REQUEST_PROTOCOL_VERSION,
        requested_agent_id: *requested_agent_id.as_bytes(),
    };
    postcard::to_stdvec(&request).map_err(|error| {
        NetworkError::SerializationError(format!(
            "targeted capability advert request encode: {error}"
        ))
    })
}

/// Publish an authenticated request asking exactly `requested_agent_id` to
/// republish its signed capability advert (ADR 0030 §3).
///
/// It goes out on two carriers: the dedicated Critical request topic, and the
/// steady advert topic behind a domain prefix. The second is not redundancy
/// theatre — a freshly created Critical topic may have no gossip mesh peers
/// yet, while the steady advert topic's mesh is already established, and a
/// strict send only has a three-second window to converge. Failure on one
/// carrier is logged; only a failure on both is an error.
pub(crate) async fn publish_targeted_capability_request(
    pubsub: &PubSubManager,
    requested_agent_id: AgentId,
) -> NetworkResult<()> {
    let targeted = encode_targeted_capability_request(requested_agent_id)?;
    let warm = {
        let mut warm = Vec::with_capacity(WARM_TARGETED_REQUEST_DOMAIN.len() + targeted.len());
        warm.extend_from_slice(WARM_TARGETED_REQUEST_DOMAIN);
        warm.extend_from_slice(&targeted);
        warm
    };
    let (targeted_result, warm_result) = tokio::join!(
        pubsub.publish(
            DM_CAPABILITY_TARGETED_REQUEST_TOPIC.to_string(),
            Bytes::from(targeted),
        ),
        pubsub.publish(DM_CAPABILITY_TOPIC.to_string(), Bytes::from(warm)),
    );
    match (targeted_result, warm_result) {
        (Ok(()), Ok(())) => {}
        (Ok(()), Err(error)) => tracing::warn!(
            target: "dm.trace",
            recipient = %hex::encode(requested_agent_id.as_bytes()),
            %error,
            "warm capability refresh request carrier publish failed"
        ),
        (Err(error), Ok(())) => tracing::warn!(
            target: "dm.trace",
            recipient = %hex::encode(requested_agent_id.as_bytes()),
            %error,
            "critical capability refresh request carrier publish failed"
        ),
        (Err(targeted_error), Err(warm_error)) => {
            return Err(NetworkError::ConnectionFailed(format!(
                "both targeted capability request carriers failed: \
                 critical={targeted_error}; warm={warm_error}"
            )));
        }
    }
    tracing::debug!(
        target: "dm.trace",
        stage = "capability_refresh_request_published",
        recipient = %hex::encode(requested_agent_id.as_bytes()),
    );
    Ok(())
}

/// Verify and ingest one capability advert using the same checks as the live
/// subscriber. Kept as one function so both subscriber tasks — and tests —
/// exercise the identical authenticated-sender → advert-signature → exact
/// AgentId/MachineId acceptance boundary.
pub(crate) fn ingest_verified_capability_advert(
    store: &CapabilityStore,
    self_agent_id: AgentId,
    message: &PubSubMessage,
) -> bool {
    let (pubsub_sender, sender_pubkey) =
        match (message.sender, message.sender_public_key.as_deref()) {
            (Some(sender), Some(public_key)) if message.verified => (sender, public_key),
            _ => return false,
        };
    if pubsub_sender == self_agent_id {
        return false;
    }
    let advert = match CapabilityAdvert::from_postcard(&message.payload) {
        Ok(advert) => advert,
        Err(_) => return false,
    };
    if advert.protocol_version != ADVERT_PROTOCOL_VERSION
        || advert.agent_id != *pubsub_sender.as_bytes()
    {
        return false;
    }
    // #674: a stale or replayed advert cannot change store state — insert's
    // last-write-wins rule would reject it — so it must not cost the
    // ML-DSA-65 verify. `advert.agent_id` is constrained to the
    // transport-authenticated sender above, so the pre-check key cannot be
    // forged to suppress a genuine newer advert: the store only holds
    // verified entries and only a strictly newer timestamp passes.
    if !store.would_accept_advert(&AgentId(advert.agent_id), advert.created_at_unix_ms) {
        store.record_prefiltered_stale_advert();
        return false;
    }
    if !verify_advert_signature(&advert, sender_pubkey) {
        return false;
    }
    store.insert(
        AgentId(advert.agent_id),
        MachineId(advert.machine_id),
        advert.capabilities,
        advert.created_at_unix_ms,
    )
}

/// Verify and ingest one digest extension using the same authenticated
/// sender boundary as [`ingest_verified_capability_advert`]: the pubsub
/// envelope must be verified, carry the sender and their public key, name
/// themselves as the extension's agent, and sign the extension with the
/// matching ML-DSA-65 key.
pub(crate) fn ingest_verified_digest_extension(
    store: &CapabilityStore,
    self_agent_id: AgentId,
    message: &PubSubMessage,
) -> bool {
    let (pubsub_sender, sender_pubkey) =
        match (message.sender, message.sender_public_key.as_deref()) {
            (Some(sender), Some(public_key)) if message.verified => (sender, public_key),
            _ => return false,
        };
    if pubsub_sender == self_agent_id {
        return false;
    }
    let Ok(extension) =
        crate::dm_capability::DigestSupportExtension::from_postcard(&message.payload)
    else {
        return false;
    };
    if extension.protocol_version != crate::dm_capability::DIGEST_EXTENSION_PROTOCOL_VERSION
        || extension.agent_id != *pubsub_sender.as_bytes()
    {
        return false;
    }
    // #674: same freshness pre-check as the advert path — see
    // [`ingest_verified_capability_advert`].
    if !store
        .would_accept_digest_extension(&AgentId(extension.agent_id), extension.created_at_unix_ms)
    {
        store.record_prefiltered_stale_advert();
        return false;
    }
    if !verify_digest_extension_signature(&extension, sender_pubkey) {
        return false;
    }
    store.apply_digest_extension(
        AgentId(extension.agent_id),
        MachineId(extension.machine_id),
        extension.digest_support,
        extension.created_at_unix_ms,
    )
}

/// Owns the optional blob responder even while an asynchronous stop is cancelled.
/// Ordinary stop joins this task; Drop can only request its cancellation.
#[derive(Default)]
pub(crate) struct BlobResponderTask {
    handle: Option<JoinHandle<()>>,
}

impl BlobResponderTask {
    fn install(&mut self, handle: JoinHandle<()>) -> Result<(), Self> {
        let incoming = Self {
            handle: Some(handle),
        };
        if self.handle.is_some() {
            // Refuse replacement without losing custody of either task. The
            // caller can join the rejected task; dropping it still aborts it.
            incoming.abort();
            return Err(incoming);
        }
        *self = incoming;
        Ok(())
    }

    fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }

    fn abort_if_cancelled(&self, token: &tokio_util::sync::CancellationToken) -> bool {
        if token.is_cancelled() {
            self.abort();
            true
        } else {
            false
        }
    }

    pub(crate) async fn stop(&mut self) {
        self.abort();
        if let Some(handle) = self.handle.as_mut() {
            // Keep the handle in its Drop-aborting owner across this await.
            // Taking it first would detach it if the stop future were dropped.
            match handle.await {
                Ok(()) => tracing::debug!("Announce blob responder stopped"),
                Err(error) if error.is_cancelled() => {
                    tracing::debug!("Announce blob responder aborted");
                }
                Err(error) => {
                    tracing::warn!(%error, "Announce blob responder failed during stop");
                }
            }
            self.handle = None;
        }
    }
}

impl Drop for BlobResponderTask {
    fn drop(&mut self) {
        self.abort();
    }
}

pub struct CapabilityAdvertService {
    publisher: JoinHandle<()>,
    subscriber: JoinHandle<()>,
    digest_subscriber: JoinHandle<()>,
    targeted_response_subscriber: JoinHandle<()>,
    targeted_request_responder: JoinHandle<()>,
    blob_responder: BlobResponderTask,
}

impl CapabilityAdvertService {
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        caps_rx: tokio::sync::watch::Receiver<DmCapabilities>,
        store: Arc<CapabilityStore>,
        publish_interval: Duration,
        periodic: bool,
    ) -> NetworkResult<Self> {
        Self::spawn_observed(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            caps_rx,
            store,
            publish_interval,
            periodic,
            #[cfg(test)]
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn_observed(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        caps_rx: tokio::sync::watch::Receiver<DmCapabilities>,
        store: Arc<CapabilityStore>,
        publish_interval: Duration,
        periodic: bool,
        #[cfg(test)] observation: Option<Arc<ConvergenceServiceObserver>>,
    ) -> NetworkResult<Self> {
        let mut subscription = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        // #448: new peers additionally consume the signed digest
        // extension; v0.40.4 peers never subscribe to this topic.
        let mut digest_subscription = pubsub
            .subscribe(crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string())
            .await;
        let mut targeted_response_subscription = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let mut targeted_request_subscription = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_REQUEST_TOPIC.to_string())
            .await;
        let store_sub = Arc::clone(&store);
        let targeted_store_sub = Arc::clone(&store);
        let self_agent_for_sub = self_agent_id;
        // Depth 16 absorbs a burst; the publisher coalesces every queued
        // request into a single signed advert under the rate limit below.
        let (reannounce_tx, mut reannounce_rx) = tokio::sync::mpsc::channel::<()>(16);
        let warm_reannounce_tx = reannounce_tx.clone();

        #[cfg(test)]
        let warm_observation = observation.clone();
        let subscriber = tokio::spawn(async move {
            while let Some(message) = subscription.recv().await {
                let sender = message.sender;
                // The steady advert topic doubles as the warm carrier for
                // targeted requests, so classify before trying to ingest.
                if message.verified
                    && message.sender.is_some()
                    && message.sender_public_key.is_some()
                    && decode_targeted_capability_request(&message.topic, &message.payload)
                        == Some(self_agent_for_sub)
                {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "capability_refresh_request_received",
                        carrier = "warm",
                        requester = sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                    );
                    let _result = warm_reannounce_tx.try_send(());
                    #[cfg(test)]
                    if let Some(observer) = &warm_observation {
                        observer.enqueue(&message, "warm", _result.is_ok());
                    }
                    continue;
                }
                if ingest_verified_capability_advert(&store_sub, self_agent_for_sub, &message) {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "capability_advert_ingested",
                        sender = sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                    );
                }
            }
            tracing::debug!("capability advert subscriber exited");
        });

        let digest_store_sub = Arc::clone(&store);
        let digest_subscriber = tokio::spawn(async move {
            while let Some(message) = digest_subscription.recv().await {
                if ingest_verified_digest_extension(&digest_store_sub, self_agent_for_sub, &message)
                {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "capability_digest_extension_ingested",
                        sender = message
                            .sender
                            .map(|agent_id| hex::encode(agent_id.as_bytes())),
                    );
                }
            }
            tracing::debug!("capability digest extension subscriber exited");
        });

        let targeted_response_subscriber = tokio::spawn(async move {
            while let Some(message) = targeted_response_subscription.recv().await {
                let sender = message.sender;
                if ingest_verified_capability_advert(
                    &targeted_store_sub,
                    self_agent_for_sub,
                    &message,
                ) {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "capability_advert_ingested",
                        carrier = "targeted",
                        sender = sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                    );
                }
            }
            tracing::debug!("targeted capability advert response subscriber exited");
        });

        #[cfg(test)]
        let critical_observation = observation.clone();
        let targeted_request_responder = tokio::spawn(async move {
            while let Some(message) = targeted_request_subscription.recv().await {
                if !message.verified
                    || message.sender.is_none()
                    || message.sender_public_key.is_none()
                {
                    continue;
                }
                if decode_targeted_capability_request(&message.topic, &message.payload)
                    != Some(self_agent_id)
                {
                    continue;
                }
                tracing::debug!(
                    target: "dm.trace",
                    stage = "capability_refresh_request_received",
                    carrier = "critical",
                    requester = message.sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                );
                let _result = reannounce_tx.try_send(());
                #[cfg(test)]
                if let Some(observer) = &critical_observation {
                    observer.enqueue(&message, "critical", _result.is_ok());
                }
            }
            tracing::debug!("targeted capability advert request responder exited");
        });

        let publisher_pubsub = Arc::clone(&pubsub);
        let publisher_signing = Arc::clone(&signing);
        let mut publisher_caps_rx = caps_rx;
        let publisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(FIRST_PUBLISH_DELAY_MS)).await;
            // L3 retirement: in on-demand mode (periodic == false) there is
            // no startup burst, and the publisher answers requesters on the
            // Critical response topic (#656: the steady topic carries at
            // most ONE advert per advert window — see the warm fallback
            // below — instead of one per request cycle). It still keeps a
            // freshness timer: the idle wake is bounded by the advert window
            // so the steady advert is refreshed inside every consumer's
            // `ADVERT_CACHE_TTL_SECS` cache window even with zero request
            // traffic (#664 regression — see `next_delay` below).
            let mut burst_idx: usize = if periodic {
                0
            } else {
                STARTUP_BURST_INTERVALS_MS.len()
            };
            let mut last_targeted_response_at: Option<tokio::time::Instant> = None;
            let mut targeted_response_pending = false;
            let mut requests_open = true;
            // #656: whether the CURRENT publish cycle is a steady one (the
            // startup beat, a timer beat, or a capability upgrade) rather
            // than a cycle woken purely to answer a targeted request.
            // Request-triggered cycles answer on the Critical response
            // topic; the steady topic sees them only through the
            // rate-limited warm fallback below.
            let mut steady_cycle = true;
            // #656 warm fallback: even a request-triggered cycle may emit a
            // steady advert, but at most ONE per advert window, so a fresh
            // Critical topic with no mesh peers yet (or a warm-carrier
            // listener) still gets a copy without the per-request storm.
            let mut last_steady_publish_at: Option<tokio::time::Instant> = None;
            loop {
                while reannounce_rx.try_recv().is_ok() {
                    #[cfg(test)]
                    if let Some(observer) = &observation {
                        observer.record(ServiceEvent::Consumed);
                    }
                    targeted_response_pending = true;
                }
                let caps_snapshot = publisher_caps_rx.borrow().clone();
                // Never broadcast a not-yet-usable (pending) advert: absence
                // already tells senders to use the raw fallback, while a
                // pending advert on the wire can race ahead of (or arrive
                // after) the upgraded one and poison receiver caches. The
                // `changed()` arm below restarts the burst as soon as the
                // caps watch upgrades, so readiness still propagates fast.
                if !advert_is_publishable(&caps_snapshot) {
                    #[cfg(test)]
                    if let Some(observer) = &observation {
                        observer.record(ServiceEvent::PendingSkip);
                    }
                    tracing::debug!("capability advert pending (no inbox/KEM yet); not publishing");
                    tokio::select! {
                        _ = tokio::time::sleep(publish_interval) => {}
                        res = publisher_caps_rx.changed() => {
                            if res.is_ok() {
                                burst_idx = 0;
                                // The pending→ready transition is the
                                // readiness announce: the first publishable
                                // cycle after it is steady-worthy (#656),
                                // even if an earlier request cycle cleared
                                // the flag.
                                steady_cycle = true;
                            }
                        }
                        request = reannounce_rx.recv(), if requests_open => {
                            // Pending capabilities cannot produce a usable
                            // advert. A later watch upgrade publishes
                            // immediately, so there is nothing to answer with
                            // yet — just remember that someone asked.
                            match request {
                                Some(()) => {
                                    #[cfg(test)]
                                    if let Some(observer) = &observation { observer.record(ServiceEvent::Consumed); }
                                    targeted_response_pending = true;
                                },
                                None => requests_open = false,
                            }
                        }
                    }
                    continue;
                }
                match build_signed_advert(
                    &publisher_signing,
                    self_agent_id,
                    self_machine_id,
                    caps_snapshot.clone(),
                ) {
                    Ok(bytes) => {
                        // #448: publish the digest extension alongside
                        // every advert cycle, on its own topic. A publish
                        // failure is logged, not fatal — the base advert
                        // alone already keeps old and pre-#448 peers
                        // fully served for v1 semantics; new peers simply
                        // fall back to v1 relay frames until the next
                        // extension window.
                        //
                        // #656: this stays on EVERY cycle, including
                        // request-triggered ones. A targeted refresh is
                        // the only reliable delivery path for the digest
                        // bit in on-demand mode (the default): a lone
                        // node's initial-cycle extension publishes before
                        // it has any gossip links, so the requester would
                        // otherwise never learn the bit. Verified against
                        // `asymmetric_signed_capability_convergence_over_relay`.
                        if let Ok(Some(ext)) = build_signed_digest_extension(
                            &publisher_signing,
                            self_agent_id,
                            self_machine_id,
                            &caps_snapshot,
                        ) {
                            if let Err(e) = publisher_pubsub
                                .publish(
                                    crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string(),
                                    Bytes::from(ext),
                                )
                                .await
                            {
                                tracing::warn!("digest extension publish failed: {e}");
                            }
                        }
                        let bytes = Bytes::from(bytes);
                        // Answer the strict requester on the Critical topic
                        // first: its convergence window is seconds long and
                        // must not be spent waiting behind Bulk cooling on
                        // the steady advert topic.
                        if targeted_response_pending {
                            match publisher_pubsub
                                .publish(
                                    DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string(),
                                    bytes.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    last_targeted_response_at = Some(tokio::time::Instant::now());
                                    targeted_response_pending = false;
                                    tracing::debug!(
                                        target: "dm.trace",
                                        stage = "capability_advert_response_published",
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    "capability advert publish failed on targeted response topic: {e}"
                                ),
                            }
                        }
                        // #656: the steady advert rides its own cadence —
                        // the startup burst, the timer beat, or a capability
                        // upgrade (`steady_cycle`). A targeted requester
                        // already received its answer on the Critical
                        // response topic above; republishing the fleet-wide
                        // advert per request turned the 600 s documented
                        // cadence into the request rate (27 nodes × 1
                        // response-cycle/s ≈ the observed 77 caps msgs/s).
                        // The warm-fallback arm below keeps one bounded
                        // exception: a request-triggered cycle may still
                        // emit a steady copy, at most ONE per advert window,
                        // so a fresh Critical topic with no mesh peers yet
                        // keeps a working carrier.
                        let steady_fallback_due = last_steady_publish_at
                            .is_none_or(|last| last.elapsed() >= publish_interval);
                        if (periodic && steady_cycle) || steady_fallback_due {
                            match publisher_pubsub
                                .publish(DM_CAPABILITY_TOPIC.to_string(), bytes)
                                .await
                            {
                                Ok(()) => {
                                    last_steady_publish_at = Some(tokio::time::Instant::now());
                                    tracing::debug!("capability advert published");
                                }
                                Err(e) => {
                                    tracing::warn!("capability advert publish failed: {e}")
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!("capability advert build failed: {e}"),
                }
                let next_delay = if burst_idx < STARTUP_BURST_INTERVALS_MS.len() {
                    let d = Duration::from_millis(STARTUP_BURST_INTERVALS_MS[burst_idx]);
                    burst_idx += 1;
                    d
                } else if periodic {
                    publish_interval
                } else {
                    // On-demand mode has no fleet-wide steady BEAT, but the
                    // publisher must still wake in time to keep its own
                    // steady advert inside every consumer's
                    // `ADVERT_CACHE_TTL_SECS` window (#664 regression): with
                    // an hour-long idle sleep the only thing that refreshed
                    // the advert was inbound request traffic, so a peer
                    // nobody happened to ask about went stale after one TTL
                    // and strict senders got `AckSemanticsUnavailable`.
                    //
                    // Wake when the warm fallback next comes due — measured
                    // from the last SUCCESSFUL steady publish, not from this
                    // cycle — so a request-triggered cycle inside the window
                    // cannot defer the steady publish by a whole extra
                    // window. The floor keeps a persistently failing publish
                    // (which leaves the fallback permanently due) from
                    // spinning the loop; it costs at most one tenth of an
                    // advert window of extra staleness.
                    let remaining = last_steady_publish_at.map_or(publish_interval, |last| {
                        publish_interval.saturating_sub(last.elapsed())
                    });
                    remaining.max(publish_interval / 10)
                };
                let publish_delay = tokio::time::sleep(next_delay);
                tokio::pin!(publish_delay);
                loop {
                    tokio::select! {
                        _ = &mut publish_delay => {
                            steady_cycle = true;
                            break;
                        }
                        res = publisher_caps_rx.changed() => {
                            if res.is_ok() {
                                tracing::debug!("capability advert upgraded; republishing");
                                burst_idx = 0;
                            }
                            // A capability upgrade is steady-worthy: the
                            // fleet should see the new state immediately,
                            // not at the next timer beat.
                            steady_cycle = true;
                            break;
                        }
                        request = reannounce_rx.recv(), if requests_open => {
                            match request {
                                None => requests_open = false,
                                Some(()) => {
                                    #[cfg(test)]
                                    if let Some(observer) = &observation { observer.record(ServiceEvent::Consumed); }
                                    targeted_response_pending = true;
                                    let now = tokio::time::Instant::now();
                                    let earliest = last_targeted_response_at.map_or(now, |last| {
                                        last + Duration::from_secs(
                                            MIN_TARGETED_RESPONSE_INTERVAL_SECS,
                                        )
                                    });
                                    if earliest <= now {
                                        tracing::debug!(
                                            "verified capability request received; republishing"
                                        );
                                        // #656: this cycle answers on the
                                        // targeted response topic only.
                                        steady_cycle = false;
                                        break;
                                    }
                                    // Bring the wake-up forward to the first
                                    // eligible moment instead of publishing
                                    // now — the request is answered, just rate
                                    // limited.
                                    if earliest < publish_delay.deadline() {
                                        publish_delay.as_mut().reset(earliest);
                                    }
                                    tracing::debug!(
                                        "verified capability request coalesced until next eligible publish"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            digest_subscriber,
            publisher,
            subscriber,
            targeted_response_subscriber,
            targeted_request_responder,
            blob_responder: BlobResponderTask::default(),
        })
    }

    pub async fn spawn_default(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        caps_rx: tokio::sync::watch::Receiver<DmCapabilities>,
        store: Arc<CapabilityStore>,
    ) -> NetworkResult<Self> {
        Self::spawn(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            caps_rx,
            store,
            Duration::from_secs(ADVERT_PUBLISH_INTERVAL_SECS),
            true,
        )
        .await
    }

    /// Attach without an await after the responder factory returns its handle.
    pub(crate) fn attach_blob_responder(
        &mut self,
        handle: JoinHandle<()>,
    ) -> Result<(), BlobResponderTask> {
        self.blob_responder.install(handle)
    }

    pub(crate) fn abort_blob_responder_if_cancelled(
        &self,
        token: &tokio_util::sync::CancellationToken,
    ) -> bool {
        self.blob_responder.abort_if_cancelled(token)
    }

    /// Join only the blob responder. The other five tasks remain abort-only.
    pub(crate) async fn stop_blob_responder(&mut self) {
        self.blob_responder.stop().await;
    }

    pub fn abort(&self) {
        self.blob_responder.abort();
        self.publisher.abort();
        self.subscriber.abort();
        self.digest_subscriber.abort();
        self.targeted_response_subscriber.abort();
        self.targeted_request_responder.abort();
    }
}

impl Drop for CapabilityAdvertService {
    fn drop(&mut self) {
        self.abort();
    }
}

/// True when the capabilities are worth broadcasting: the gossip inbox is
/// live and the KEM key is present. Anything less is indistinguishable from
/// "no advert" to senders, so publishing it only risks clobbering a usable
/// cached advert at receivers.
#[must_use]
pub fn advert_is_publishable(caps: &DmCapabilities) -> bool {
    caps.gossip_inbox && !caps.kem_public_key.is_empty()
}

/// Build the steady-topic advert in its FROZEN v1 wire shape (#448).
///
/// `capabilities` is projected onto
/// [`crate::dm::DmCapabilitiesV1Wire`] before
/// v0.40.4 verifier recomputes — carry exactly the five pre-#437 caps
/// fields. A true `digest_support` bit must instead travel via
/// [`build_signed_digest_extension`] on
/// [`DM_CAPABILITY_DIGEST_TOPIC`](crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC).
/// Mixed-window note: a pre-#448 build's v2-shaped advert (true bit
/// inline) is still DECODED and verified by new peers via
/// [`CapabilityAdvert::from_postcard`]; this function merely never
/// produces that shape.
pub fn build_signed_advert(
    signing: &SigningContext,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    capabilities: DmCapabilities,
) -> NetworkResult<Vec<u8>> {
    // #448: freeze to the v1 wire shape. `digest_support: false` is
    // omitted from both the postcard body (skip_serializing_if) and the
    // recomputed signed bytes, making the advert byte-identical to what
    // an old peer's own encoder produces.
    let mut capabilities = capabilities;
    capabilities.digest_support = false;
    let mut advert = CapabilityAdvert {
        protocol_version: ADVERT_PROTOCOL_VERSION,
        agent_id: *self_agent_id.as_bytes(),
        machine_id: *self_machine_id.as_bytes(),
        created_at_unix_ms: now_unix_ms(),
        capabilities,
        signature: Vec::new(),
    };
    let signed_bytes = advert
        .signed_bytes()
        .map_err(|e| NetworkError::SerializationError(format!("advert sign-bytes: {e}")))?;
    advert.signature = signing.sign(&signed_bytes)?;
    postcard::to_stdvec(&advert)
        .map_err(|e| NetworkError::SerializationError(format!("advert encode: {e}")))
}

/// Build the signed `digest_support` extension record for the same
/// live capability snapshot (#448). Returns `None` when the bit is
/// false — the frozen v1 advert already encodes false, so an extension
/// would be pure noise.
pub fn build_signed_digest_extension(
    signing: &SigningContext,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    capabilities: &DmCapabilities,
) -> NetworkResult<Option<Vec<u8>>> {
    if !capabilities.digest_support {
        return Ok(None);
    }
    let mut extension = crate::dm_capability::DigestSupportExtension {
        protocol_version: crate::dm_capability::DIGEST_EXTENSION_PROTOCOL_VERSION,
        agent_id: *self_agent_id.as_bytes(),
        machine_id: *self_machine_id.as_bytes(),
        created_at_unix_ms: now_unix_ms(),
        digest_support: true,
        signature: Vec::new(),
    };
    let signed_bytes = extension
        .signed_bytes()
        .map_err(|e| NetworkError::SerializationError(format!("digest ext sign-bytes: {e}")))?;
    extension.signature = signing.sign(&signed_bytes)?;
    postcard::to_stdvec(&extension)
        .map_err(|e| NetworkError::SerializationError(format!("digest ext encode: {e}")))
        .map(Some)
}

/// Verify an extension record against the sender's ML-DSA-65 public key,
/// mirroring [`verify_advert_signature`]'s derived-id binding.
pub fn verify_digest_extension_signature(
    extension: &crate::dm_capability::DigestSupportExtension,
    public_key_bytes: &[u8],
) -> bool {
    let Ok(signed_bytes) = extension.signed_bytes() else {
        return false;
    };
    let Ok(public_key) = ant_quic::MlDsaPublicKey::from_bytes(public_key_bytes) else {
        return false;
    };
    let derived = crate::identity::AgentId::from_public_key(&public_key);
    if derived.0 != extension.agent_id {
        return false;
    }
    let Ok(signature) =
        ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&extension.signature)
    else {
        return false;
    };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        &signed_bytes,
        &signature,
    )
    .is_ok()
}

pub fn verify_advert_signature(advert: &CapabilityAdvert, public_key_bytes: &[u8]) -> bool {
    let signed_bytes = match advert.signed_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let public_key = match ant_quic::MlDsaPublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let derived = crate::identity::AgentId::from_public_key(&public_key);
    if derived.0 != advert.agent_id {
        return false;
    }
    let signature =
        match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&advert.signature)
        {
            Ok(s) => s,
            Err(_) => return false,
        };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        &signed_bytes,
        &signature,
    )
    .is_ok()
}

#[cfg(test)]
mod blob_responder_lifecycle_tests {
    use super::{BlobResponderTask, CapabilityAdvertService};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    struct Dropped(Option<oneshot::Sender<()>>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    // No service factory or transport: the real owner's methods receive only
    // inert Tokio tasks. Construct the sentinel before spawn so even an unpolled
    // task must release its captured state when cancellation completes.
    fn pending_task() -> (JoinHandle<()>, oneshot::Receiver<()>, oneshot::Receiver<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let sentinel = Dropped(Some(dropped_tx));
        let task = tokio::spawn(async move {
            let _sentinel = sentinel;
            let _ = entered_tx.send(());
            std::future::pending::<()>().await;
        });
        (task, entered_rx, dropped_rx)
    }

    fn inert_service() -> CapabilityAdvertService {
        CapabilityAdvertService {
            publisher: tokio::spawn(async {}),
            subscriber: tokio::spawn(async {}),
            digest_subscriber: tokio::spawn(async {}),
            targeted_response_subscriber: tokio::spawn(async {}),
            targeted_request_responder: tokio::spawn(async {}),
            blob_responder: BlobResponderTask::default(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn service_abort_and_stop_join_pending_responder() {
        let mut service = inert_service();
        let (handle, entered, dropped) = pending_task();
        assert!(service.attach_blob_responder(handle).is_ok());
        entered.await.unwrap();
        service.abort();
        service.stop_blob_responder().await;
        dropped.await.unwrap();
        assert!(service.blob_responder.handle.is_none());
        service.stop_blob_responder().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stopped_slot_can_be_reused_without_retaining_prior_tasks() {
        let mut service = inert_service();
        for _ in 0..3 {
            let (handle, entered, dropped) = pending_task();
            assert!(service.attach_blob_responder(handle).is_ok());
            entered.await.unwrap();
            service.stop_blob_responder().await;
            dropped.await.unwrap();
            assert!(service.blob_responder.handle.is_none());
        }
        service.stop_blob_responder().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_attachment_retains_old_and_returns_aborted_new_owner() {
        let mut service = inert_service();
        let (old, old_entered, mut old_dropped) = pending_task();
        assert!(service.attach_blob_responder(old).is_ok());
        old_entered.await.unwrap();
        let (new, new_entered, new_dropped) = pending_task();
        new_entered.await.unwrap();
        let mut refused = match service.attach_blob_responder(new) {
            Err(owner) => owner,
            Ok(()) => panic!("occupied responder slot accepted a replacement"),
        };
        // The refused task is already cancelled, not merely left for the caller.
        new_dropped.await.unwrap();
        assert!(matches!(
            old_dropped.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        refused.stop().await;
        assert!(refused.handle.is_none());
        service.stop_blob_responder().await;
        old_dropped.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn service_drop_aborts_responder_without_explicit_shutdown() {
        let mut service = inert_service();
        let (handle, entered, dropped) = pending_task();
        assert!(service.attach_blob_responder(handle).is_ok());
        entered.await.unwrap();
        drop(service);
        dropped.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_attach_cancel_check_aborts_when_already_cancelled() {
        let mut service = inert_service();
        let token = CancellationToken::new();
        token.cancel();
        let (handle, _entered, dropped) = pending_task();
        assert!(service.attach_blob_responder(handle).is_ok());
        assert!(service.abort_blob_responder_if_cancelled(&token));
        service.stop_blob_responder().await;
        dropped.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_attach_cancel_check_preserves_live_task_until_cancelled() {
        let mut service = inert_service();
        let token = CancellationToken::new();
        let (handle, entered, mut dropped) = pending_task();
        assert!(service.attach_blob_responder(handle).is_ok());
        entered.await.unwrap();
        assert!(!service.abort_blob_responder_if_cancelled(&token));
        tokio::task::yield_now().await;
        assert!(matches!(
            dropped.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        token.cancel();
        assert!(service.abort_blob_responder_if_cancelled(&token));
        service.stop_blob_responder().await;
        dropped.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_stop_keeps_handle_owned_until_drop() {
        let mut service = inert_service();
        let (handle, entered, dropped) = pending_task();
        assert!(service.attach_blob_responder(handle).is_ok());
        entered.await.unwrap();
        let mut stop = Box::pin(service.stop_blob_responder());
        let mut context = Context::from_waker(Waker::noop());
        // No scheduler turn between abort and this first join poll. Dropping
        // the pending stop simulates cancellation without signalling a process.
        assert!(matches!(stop.as_mut().poll(&mut context), Poll::Pending));
        drop(stop);
        assert!(service.blob_responder.handle.is_some());
        drop(service);
        dropped.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_task_is_joined_and_slot_cleared() {
        let mut service = inert_service();
        let (finished_tx, finished_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = finished_tx.send(());
        });
        finished_rx.await.unwrap();
        assert!(handle.is_finished());
        assert!(service.attach_blob_responder(handle).is_ok());
        service.stop_blob_responder().await;
        assert!(service.blob_responder.handle.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn already_aborted_task_is_joined_and_slot_cleared() {
        let mut service = inert_service();
        let (handle, entered, dropped) = pending_task();
        entered.await.unwrap();
        handle.abort();
        dropped.await.unwrap();
        assert!(service.attach_blob_responder(handle).is_ok());
        service.stop_blob_responder().await;
        assert!(service.blob_responder.handle.is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;
    use crate::network::{NetworkConfig, NetworkNode};

    /// Explicit test-only network config (#417/#337): loopback bind, no
    /// seeds, discovery/port-mapping off. Still a real socket constructor.
    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..NetworkConfig::default()
        }
    }

    /// Isolated network node (mirrors the helper in `src/gossip/pubsub.rs`
    /// tests). `PubSubManager` is fully constructable in tests, so the advert
    /// service is testable end-to-end without a live mesh.
    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("network node"),
        )
    }

    /// Build a valid signed advert for `signing`'s own agent and decode it
    /// back, ready for negative-test mutation.
    fn fresh_advert(signing: &SigningContext) -> CapabilityAdvert {
        let encoded = build_signed_advert(
            signing,
            signing.agent_id,
            MachineId([1u8; 32]),
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
        )
        .expect("build signed advert");
        CapabilityAdvert::from_postcard(&encoded).expect("decode advert")
    }

    #[test]
    fn build_and_verify_advert_roundtrip() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = SigningContext::from_keypair(&kp);
        let agent_id = kp.agent_id();
        let machine_id = MachineId([9u8; 32]);
        let encoded = build_signed_advert(
            &signing,
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
        )
        .expect("build");
        let advert: CapabilityAdvert = CapabilityAdvert::from_postcard(&encoded).expect("decode");
        assert!(verify_advert_signature(&advert, &signing.public_key_bytes));
    }

    /// A pending advert must never reach the wire — receivers cache adverts
    /// last-writer-wins per timestamp, so broadcasting "I can't receive"
    /// degrades DM routing for every sender that hears it.
    #[test]
    fn pending_capabilities_are_not_publishable() {
        assert!(!advert_is_publishable(&DmCapabilities::pending()));
        assert!(advert_is_publishable(&DmCapabilities::v1_gossip_ready(
            vec![0u8; 1184]
        )));
    }

    #[test]
    fn verify_advert_rejects_tampered_signature() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = SigningContext::from_keypair(&kp);
        let encoded = build_signed_advert(
            &signing,
            kp.agent_id(),
            MachineId([0u8; 32]),
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
        )
        .expect("build");
        let mut advert: CapabilityAdvert =
            CapabilityAdvert::from_postcard(&encoded).expect("decode");
        advert.signature[0] ^= 0x01;
        assert!(!verify_advert_signature(&advert, &signing.public_key_bytes));
    }

    // ------------------------------------------------------------------
    // advert_is_publishable(): every branch of the predicate
    // ------------------------------------------------------------------

    #[test]
    fn advert_is_publishable_branch_coverage() {
        // gossip_inbox == false must reject EVEN with a KEM present. This
        // isolates the first operand of the `&&`: `pending()` alone is both
        // gossip_inbox=false AND empty-KEM, so it would not catch a broken
        // impl that only checked KEM presence.
        let mut gossip_off_kem_present = DmCapabilities::pending();
        gossip_off_kem_present.kem_public_key = vec![0u8; 1184];
        assert!(
            !advert_is_publishable(&gossip_off_kem_present),
            "gossip_inbox=false must reject even with a KEM present"
        );
        // gossip_inbox == true but KEM absent -> false (second operand).
        assert!(!advert_is_publishable(&DmCapabilities::v1_gossip_ready(
            Vec::new()
        )));
        // gossip_inbox == true AND KEM present -> true.
        assert!(advert_is_publishable(&DmCapabilities::v1_gossip_ready(
            vec![0u8; 1184]
        )));
    }

    // ------------------------------------------------------------------
    // verify_advert_signature(): negative cases (a verifier must fail closed)
    // ------------------------------------------------------------------

    #[test]
    fn verify_advert_rejects_foreign_public_key() {
        let kp_a = AgentKeypair::generate().expect("keygen a");
        let signing_a = SigningContext::from_keypair(&kp_a);
        let signing_b = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen b"));

        let advert = fresh_advert(&signing_a);
        // A valid advert signed by A must NOT verify against B's foreign key.
        assert!(
            !verify_advert_signature(&advert, &signing_b.public_key_bytes),
            "advert signed by A must not verify against B's public key"
        );
        // Sanity: it DOES verify against the correct key.
        assert!(verify_advert_signature(
            &advert,
            &signing_a.public_key_bytes
        ));
    }

    #[test]
    fn verify_advert_rejects_agent_id_mismatch() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        let mut advert = fresh_advert(&signing);
        // Swap the advertised agent_id; the derived key id no longer matches.
        advert.agent_id = [0xFF; 32];
        assert!(
            !verify_advert_signature(&advert, &signing.public_key_bytes),
            "mismatched agent_id must fail verification"
        );
    }

    #[test]
    fn verify_advert_rejects_malformed_public_key_bytes() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        let advert = fresh_advert(&signing);
        // Garbage public key -> MlDsaPublicKey::from_bytes fails -> false.
        assert!(!verify_advert_signature(
            &advert,
            b"not-a-valid-ml-dsa-public-key"
        ));
    }

    #[test]
    fn verify_advert_rejects_malformed_signature_bytes() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        let mut advert = fresh_advert(&signing);
        // Replace the signature with unparseable garbage -> signature
        // from_bytes fails -> false (distinct from a bit-flipped but
        // format-valid signature, which is covered by the test above).
        advert.signature = vec![0xFFu8; 8];
        assert!(
            !verify_advert_signature(&advert, &signing.public_key_bytes),
            "unparseable signature must fail verification"
        );
    }

    #[test]
    fn verify_advert_rejects_tampered_payload() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().expect("keygen"));
        let mut advert = fresh_advert(&signing);
        // Mutate a SIGNED field (machine_id) but keep the signature: the
        // recomputed signed_bytes no longer match -> crypto verify fails.
        advert.machine_id[0] ^= 0x01;
        assert!(
            !verify_advert_signature(&advert, &signing.public_key_bytes),
            "tampered payload must fail signature verification"
        );
    }

    // ------------------------------------------------------------------
    // CapabilityAdvertService: publisher delivers a verifiable advert
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn service_publishes_verifiable_advert_on_loopback() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let agent_id = kp.agent_id();
        let machine_id = MachineId([9u8; 32]);

        let pubsub = Arc::new(PubSubManager::new(make_node().await, None).expect("pubsub"));
        // Subscribe BEFORE spawning so we observe the advert the publisher
        // actually places on the wire.
        let mut sub = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;

        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v1_gossip_ready(vec![0u8; 1184]));

        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            agent_id,
            machine_id,
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        // The publisher sleeps FIRST_PUBLISH_DELAY_MS (250 ms) before its
        // first publish; wait for it with a generous timeout.
        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("timed out waiting for published advert")
            .expect("subscriber stream closed");

        let advert: CapabilityAdvert =
            CapabilityAdvert::from_postcard(&msg.payload).expect("decode advert");
        assert_eq!(advert.protocol_version, ADVERT_PROTOCOL_VERSION);
        assert_eq!(advert.agent_id, *agent_id.as_bytes());
        assert_eq!(advert.machine_id, *machine_id.as_bytes());
        assert!(
            verify_advert_signature(&advert, &signing.public_key_bytes),
            "published advert must verify against the signer's public key"
        );
        assert_eq!(msg.topic, DM_CAPABILITY_TOPIC);

        service.abort();
    }

    // ------------------------------------------------------------------
    // CapabilityAdvertService: subscriber ingests a peer's verified advert
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn service_subscriber_ingests_verified_peer_advert() {
        // The pubsub signs with the "peer" keypair P; the service's
        // self_agent_id is a DIFFERENT agent Q, so the subscriber does not
        // skip P's advert as self. The advert is built+signed for P, so its
        // agent_id matches the transport-verified sender P.
        let kp_p = AgentKeypair::generate().expect("keygen");
        let signing_p = Arc::new(SigningContext::from_keypair(&kp_p));
        let agent_p = kp_p.agent_id();

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing_p))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());

        let self_agent = AgentId([99u8; 32]);
        // pending caps -> the service's own publisher stays quiet, so the
        // only advert on the topic is the peer one we publish below.
        let (_caps_tx, caps_rx) = tokio::sync::watch::channel(DmCapabilities::pending());

        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing_p),
            self_agent,
            MachineId([7u8; 32]),
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        // Let the subscriber's subscription register before we publish.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let peer_caps = DmCapabilities::v1_gossip_ready(vec![0xAA; 1184]);
        let peer_machine = MachineId([42u8; 32]);
        let encoded = build_signed_advert(&signing_p, agent_p, peer_machine, peer_caps.clone())
            .expect("build peer advert");
        pubsub
            .publish(DM_CAPABILITY_TOPIC.to_string(), Bytes::from(encoded))
            .await
            .expect("publish");

        // Ingest is asynchronous; poll the store until the peer advert lands.
        let ingested = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.lookup(&agent_p).is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(
            ingested.is_ok(),
            "peer advert was not ingested into the store"
        );

        let cached = store.lookup(&agent_p).expect("cached after ingest");
        assert_eq!(cached.max_protocol_version, peer_caps.max_protocol_version);
        assert!(cached.gossip_inbox && !cached.kem_public_key.is_empty());

        service.abort();
    }

    /// The request wire format is owned by its topic. Accepting a targeted
    /// request off the wrong topic — or accepting trailing bytes on the warm
    /// carrier — would let a request be confused with an advert on the shared
    /// steady topic.
    #[test]
    fn targeted_request_decoding_is_scoped_to_its_topic() {
        let requested = AgentId([0x33; 32]);
        let bare = encode_targeted_capability_request(requested).expect("encode");
        let warm = {
            let mut warm = WARM_TARGETED_REQUEST_DOMAIN.to_vec();
            warm.extend_from_slice(&bare);
            warm
        };

        assert_eq!(
            decode_targeted_capability_request(DM_CAPABILITY_TARGETED_REQUEST_TOPIC, &bare),
            Some(requested)
        );
        assert_eq!(
            decode_targeted_capability_request(DM_CAPABILITY_TOPIC, &warm),
            Some(requested)
        );

        // The bare form is not accepted on the shared steady topic: without
        // the domain prefix it is just an undecodable advert.
        assert_eq!(
            decode_targeted_capability_request(DM_CAPABILITY_TOPIC, &bare),
            None
        );
        // Nor is the domain-prefixed form accepted anywhere else.
        assert_eq!(
            decode_targeted_capability_request(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC, &warm),
            None
        );
        // Trailing bytes after the record are rejected rather than ignored.
        let mut padded = warm.clone();
        padded.push(0);
        assert_eq!(
            decode_targeted_capability_request(DM_CAPABILITY_TOPIC, &padded),
            None
        );
        // A future request version is not silently treated as v2.
        let wrong_version = postcard::to_stdvec(&TargetedCapabilityAdvertRequest {
            protocol_version: TARGETED_REQUEST_PROTOCOL_VERSION + 1,
            requested_agent_id: *requested.as_bytes(),
        })
        .expect("encode");
        assert_eq!(
            decode_targeted_capability_request(
                DM_CAPABILITY_TARGETED_REQUEST_TOPIC,
                &wrong_version
            ),
            None
        );
        // And a request never decodes as an advert, so a pre-0030 subscriber
        // sharing the steady topic drops it instead of caching garbage.
        assert!(postcard::from_bytes::<CapabilityAdvert>(&warm).is_err());
    }

    /// ADR 0030 §3 end-to-end: a targeted request for this daemon's agent id
    /// produces a freshly signed advert on the Critical response topic,
    /// carrying the v2 capability the requester's strict gate needs.
    #[tokio::test]
    async fn targeted_request_triggers_a_signed_response_on_the_critical_topic() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let self_agent = kp.agent_id();
        let self_machine = MachineId([0x44; 32]);

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0xCC; 1184]));

        let mut responses = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            self_agent,
            self_machine,
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        // Let the responder's subscription register before requesting.
        tokio::time::sleep(Duration::from_millis(300)).await;
        publish_targeted_capability_request(&pubsub, self_agent)
            .await
            .expect("publish targeted request");

        let response = tokio::time::timeout(Duration::from_secs(5), responses.recv())
            .await
            .expect("targeted response within the strict convergence window")
            .expect("subscription live");
        let advert: CapabilityAdvert =
            CapabilityAdvert::from_postcard(&response.payload).expect("decode signed response");

        assert_eq!(advert.agent_id, *self_agent.as_bytes());
        assert_eq!(advert.machine_id, *self_machine.as_bytes());
        assert!(advert.capabilities.supports_durable_app_ack());
        assert!(
            verify_advert_signature(&advert, kp.public_key().as_bytes()),
            "the response must be a freshly signed advert, not a replayed blob"
        );

        service.abort();
    }

    /// A request naming a different agent must not make this daemon republish
    /// — otherwise any peer could use one broadcast to fan out the whole fleet.
    #[tokio::test]
    async fn targeted_request_for_another_agent_is_ignored() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let self_agent = kp.agent_id();

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0xCD; 1184]));

        let mut responses = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            self_agent,
            MachineId([0x45; 32]),
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        tokio::time::sleep(Duration::from_millis(300)).await;
        publish_targeted_capability_request(&pubsub, AgentId([0x46; 32]))
            .await
            .expect("publish targeted request");

        assert!(
            tokio::time::timeout(Duration::from_secs(2), responses.recv())
                .await
                .is_err(),
            "a request for another agent must not draw a response"
        );

        service.abort();
    }

    /// #656: a targeted capability refresh is point-to-point — the requester
    /// is answered on the Critical response topic — and must NOT cost a
    /// fleet-wide steady advert. Under `respond_on_steady`, N requests
    /// inside one 600 s advert window put N extra signed adverts on
    /// `x0x/caps/v1` (27 nodes × 1 response-cycle/s ≈ the observed 77 caps
    /// msgs/s), a 600× amplification of the documented cadence.
    #[tokio::test]
    async fn targeted_requests_do_not_republish_the_steady_advert() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let self_agent = kp.agent_id();

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0xCE; 1184]));

        // Advert-shaped counters on the steady topic and the targeted
        // response topic. The steady topic also carries this test's
        // warm-carrier REQUESTS (domain-prefixed); those fail the
        // advert decode and are filtered, so the steady count is exactly
        // A's own advert publications.
        let mut steady = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let mut responses = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let steady_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let response_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let steady_counter = Arc::clone(&steady_seen);
        tokio::spawn(async move {
            while let Some(message) = steady.recv().await {
                if CapabilityAdvert::from_postcard(&message.payload).is_ok() {
                    steady_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        let response_counter = Arc::clone(&response_seen);
        tokio::spawn(async move {
            while let Some(message) = responses.recv().await {
                if CapabilityAdvert::from_postcard(&message.payload).is_ok() {
                    response_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });

        // A runs the real publisher (periodic mode, the production
        // interval); B is modeled by the raw request publishes below.
        let service = CapabilityAdvertService::spawn(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            self_agent,
            MachineId([0x47; 32]),
            caps_rx,
            Arc::clone(&store),
            Duration::from_secs(ADVERT_PUBLISH_INTERVAL_SECS),
            true,
        )
        .await
        .expect("spawn periodic service");

        // Wait for the one periodic beat of this advert window (the
        // FIRST_PUBLISH_DELAY_MS initial publish).
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while steady_seen.load(std::sync::atomic::Ordering::Relaxed) < 1
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // B sends three targeted requests inside the same advert window,
        // spaced past the responder's 1 s coalescing window so each draws
        // its own response.
        for expected in 1..=3 {
            publish_targeted_capability_request(&pubsub, self_agent)
                .await
                .expect("publish targeted request");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while response_seen.load(std::sync::atomic::Ordering::Relaxed) < expected
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_millis(1_150)).await;
        }

        // Quiet period, then the exact-count assertions.
        assert_eq!(
            response_seen.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "each request must draw exactly one targeted response"
        );
        assert_eq!(
            steady_seen.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a point-to-point refresh must not cost a fleet-wide steady advert"
        );

        service.abort();
    }

    /// #656 round 2 — the PRODUCTION default: on-demand mode
    /// (`periodic == false`, `legacy_announce` defaults to false). There is
    /// no startup burst and no steady beat; the initial publishable cycle
    /// (~250 ms after spawn) emits exactly ONE steady advert via the warm
    /// fallback, and after that at most one per 600 s advert window
    /// regardless of request volume. Under `respond_on_steady` (origin/main)
    /// every request-triggered cycle re-broadcast the steady advert, so
    /// this fixture counted THREE extra fleet-wide adverts.
    #[tokio::test]
    async fn on_demand_mode_answers_requests_without_steady_republishes() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let self_agent = kp.agent_id();

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0xCF; 1184]));

        let mut steady = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let mut responses = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let steady_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let response_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let steady_counter = Arc::clone(&steady_seen);
        tokio::spawn(async move {
            while let Some(message) = steady.recv().await {
                if CapabilityAdvert::from_postcard(&message.payload).is_ok() {
                    steady_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        let response_counter = Arc::clone(&response_seen);
        tokio::spawn(async move {
            while let Some(message) = responses.recv().await {
                if CapabilityAdvert::from_postcard(&message.payload).is_ok() {
                    response_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });

        let service = CapabilityAdvertService::spawn(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            self_agent,
            MachineId([0x48; 32]),
            caps_rx,
            Arc::clone(&store),
            Duration::from_secs(ADVERT_PUBLISH_INTERVAL_SECS),
            false,
        )
        .await
        .expect("spawn on-demand service");

        // Startup: exactly one warm-fallback steady advert from the initial
        // publishable cycle. On origin/main an on-demand service publishes
        // ZERO at startup (no burst, no beat, no pending request).
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while steady_seen.load(std::sync::atomic::Ordering::Relaxed) < 1
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            steady_seen.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "startup is the ONE warm-fallback advert that opens the window"
        );

        // N targeted requests inside the same advert window: N responses on
        // the Critical topic, and no further steady advert (the fallback is
        // not due again inside the 600 s window).
        for expected in 1..=3 {
            publish_targeted_capability_request(&pubsub, self_agent)
                .await
                .expect("publish targeted request");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while response_seen.load(std::sync::atomic::Ordering::Relaxed) < expected
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_millis(1_150)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            response_seen.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "each request must still draw exactly one targeted response"
        );
        assert_eq!(
            steady_seen.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "at most one steady advert per advert window regardless of request volume"
        );

        service.abort();
    }

    /// #664 regression: on-demand mode must keep its own steady advert
    /// fresh on a TIMER, not on inbound request traffic.
    ///
    /// WHY this matters: a consumer drops a cached advert after
    /// `ADVERT_CACHE_TTL_SECS` (900 s) and a strict ADR-0030 send then
    /// refuses with `AckSemanticsUnavailable` ("recipient has no current v2
    /// durable-ACK capability advert"). #664 removed the per-request steady
    /// republish — correctly, it was a storm — but left the on-demand idle
    /// wake at 3600 s, four times the consumer TTL. Freshness therefore
    /// depended entirely on somebody targeting the node: on the 6-node
    /// testnet the peers that saw request traffic stayed fresh while SFO,
    /// which nobody asked about, went stale after one TTL and every
    /// NYC -> SFO durable DM returned HTTP 409 for hours.
    ///
    /// The fixture is the consumer's half of that: agent A publishes in
    /// on-demand mode with a shortened advert window, NOBODY sends A a
    /// targeted request, and B ingests the mesh-wide topics into a store
    /// whose TTL is shortened in the same proportion. B's record of A must
    /// stay current — and keep passing the exact production strict-send
    /// gate — across several TTL windows. On origin/main B's record expires
    /// one TTL after A's single startup advert and never returns.
    #[tokio::test]
    async fn on_demand_publisher_refreshes_steady_advert_without_any_requests() {
        // Shortened but proportional to production: the advert window is
        // shorter than the cache TTL (600 s < 900 s there), so one
        // on-time republish per window keeps every consumer current.
        const ADVERT_WINDOW: Duration = Duration::from_millis(400);
        const CACHE_TTL: Duration = Duration::from_millis(700);
        // > 3 cache TTLs of observation after the first ingest.
        const OBSERVE: Duration = Duration::from_millis(2_500);

        let kp_a = AgentKeypair::generate().expect("keygen");
        let signing_a = Arc::new(SigningContext::from_keypair(&kp_a));
        let agent_a = kp_a.agent_id();
        let machine_a = MachineId([0x4A; 32]);

        // The pubsub signs as A, so loopback messages reach B's ingest path
        // with a verified sender of A — the same authenticated boundary the
        // real subscriber enforces.
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing_a))).expect("pubsub"),
        );

        // B: a second agent's view of A, with the proportionally shortened
        // cache TTL.
        let agent_b = AgentId([0x4B; 32]);
        let store_b = Arc::new(CapabilityStore::with_ttl(CACHE_TTL));
        let mut adverts_b = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let mut digests_b = pubsub
            .subscribe(crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string())
            .await;
        let advert_store = Arc::clone(&store_b);
        let advert_ingest = tokio::spawn(async move {
            while let Some(message) = adverts_b.recv().await {
                ingest_verified_capability_advert(&advert_store, agent_b, &message);
            }
        });
        let digest_store = Arc::clone(&store_b);
        let digest_ingest = tokio::spawn(async move {
            while let Some(message) = digests_b.recv().await {
                ingest_verified_digest_extension(&digest_store, agent_b, &message);
            }
        });

        // A publishes in on-demand mode — the production default
        // (`legacy_announce == false`).
        let store_a = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0xCA; 1184]));
        let service = CapabilityAdvertService::spawn(
            Arc::clone(&pubsub),
            Arc::clone(&signing_a),
            agent_a,
            machine_a,
            caps_rx,
            Arc::clone(&store_a),
            ADVERT_WINDOW,
            false,
        )
        .await
        .expect("spawn on-demand service");

        // Wait for B's first sight of A (the initial publishable cycle).
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while store_b.lookup_binding(&agent_a).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "B never ingested A's initial advert"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // No targeted request is ever sent to A. Poll continuously: a single
        // observation of an expired record is the regression.
        let until = std::time::Instant::now() + OBSERVE;
        let mut samples: u32 = 0;
        while std::time::Instant::now() < until {
            let binding = store_b.lookup_binding(&agent_a);
            assert!(
                crate::capability_binding_supports_durable_ack(binding.as_ref()),
                "B's record of A went stale with no request traffic after {} sample(s): \
                 a strict send would refuse with AckSemanticsUnavailable",
                samples
            );
            samples += 1;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(samples > 0, "observation loop never sampled");

        // The `caps/v2/digest` extension rides the same publish cycle and
        // carries the same TTL, so a set bit this far past startup proves
        // the extension was republished too — not just the base advert.
        // Asserted once at the end rather than per sample: within a single
        // cycle the two topics are ingested by independent tasks, so the
        // bit can lag the base advert by a scheduling hop.
        assert!(
            store_b
                .lookup_binding(&agent_a)
                .is_some_and(|b| b.capabilities.digest_support),
            "the caps/v2/digest extension must be refreshed on the same timer"
        );

        service.abort();
        advert_ingest.abort();
        digest_ingest.abort();
    }

    // ------------------------------------------------------------------
    // CapabilityAdvertService::abort(): terminates both background loops
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn service_abort_terminates_background_tasks() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(PubSubManager::new(make_node().await, None).expect("pubsub"));
        let store = Arc::new(CapabilityStore::new());
        let (_tx, caps_rx) = tokio::sync::watch::channel(DmCapabilities::pending());

        let service = CapabilityAdvertService::spawn_default(
            pubsub,
            signing,
            AgentId([5u8; 32]),
            MachineId([6u8; 32]),
            caps_rx,
            store,
        )
        .await
        .expect("spawn_default");

        // Before abort, both loops are alive (they run forever by design).
        assert!(!service.publisher.is_finished());
        assert!(!service.subscriber.is_finished());

        service.abort();

        // abort() cancels both JoinHandles; they must report finished promptly.
        let finished = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service.publisher.is_finished() && service.subscriber.is_finished() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(finished.is_ok(), "abort() did not terminate both tasks");
    }

    // ------------------------------------------------------------------
    // #448: digest extension end-to-end on loopback pubsub
    // ------------------------------------------------------------------

    /// The publisher must emit a signed digest extension alongside every
    /// advert cycle whenever the live caps carry the bit.
    #[tokio::test]
    async fn service_publishes_signed_digest_extension_on_loopback() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let agent_id = kp.agent_id();
        let machine_id = MachineId([0x61; 32]);

        let pubsub = Arc::new(PubSubManager::new(make_node().await, None).expect("pubsub"));
        let mut ext_sub = pubsub
            .subscribe(crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string())
            .await;

        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v2_durable_gossip_ready(vec![0x62; 1184]));

        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            agent_id,
            machine_id,
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        let msg = tokio::time::timeout(Duration::from_secs(3), ext_sub.recv())
            .await
            .expect("timed out waiting for published digest extension")
            .expect("subscriber stream closed");

        let ext = crate::dm_capability::DigestSupportExtension::from_postcard(&msg.payload)
            .expect("decode extension");
        assert_eq!(ext.agent_id, *agent_id.as_bytes());
        assert_eq!(ext.machine_id, *machine_id.as_bytes());
        assert!(ext.digest_support);
        assert!(
            verify_digest_extension_signature(&ext, &signing.public_key_bytes),
            "published extension must verify against the signer's public key"
        );

        service.abort();
    }

    /// A digest=false publisher must NOT emit extensions (the frozen
    /// advert already encodes false; an extension would be noise).
    #[tokio::test]
    async fn service_emits_no_digest_extension_when_bit_is_false() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let mut caps = DmCapabilities::v2_durable_gossip_ready(vec![0x63; 1184]);
        caps.digest_support = false;

        let pubsub = Arc::new(PubSubManager::new(make_node().await, None).expect("pubsub"));
        let mut ext_sub = pubsub
            .subscribe(crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string())
            .await;

        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) = tokio::sync::watch::channel(caps);

        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            signing,
            kp.agent_id(),
            MachineId([0x64; 32]),
            caps_rx,
            store,
        )
        .await
        .expect("spawn_default");

        assert!(
            tokio::time::timeout(Duration::from_secs(2), ext_sub.recv())
                .await
                .is_err(),
            "a false bit must not produce extension traffic"
        );

        service.abort();
    }

    /// Full #448 mixed-fleet convergence on one loopback mesh: the peer's
    /// v1-shaped base advert lands (old-verifiable, no digest knowledge)
    /// and its signed extension merges the bit into the cached binding.
    #[tokio::test]
    async fn peer_advert_plus_extension_converge_in_the_store() {
        let kp_p = AgentKeypair::generate().expect("keygen");
        let signing_p = Arc::new(SigningContext::from_keypair(&kp_p));
        let agent_p = kp_p.agent_id();
        let peer_machine = MachineId([0x71; 32]);

        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing_p))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let self_agent = AgentId([99u8; 32]);
        let (_caps_tx, caps_rx) = tokio::sync::watch::channel(DmCapabilities::pending());

        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&signing_p),
            self_agent,
            MachineId([7u8; 32]),
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn_default");

        tokio::time::sleep(Duration::from_millis(150)).await;

        let peer_caps = DmCapabilities::v2_durable_gossip_ready(vec![0x72; 1184]);
        let advert = build_signed_advert(&signing_p, agent_p, peer_machine, peer_caps.clone())
            .expect("build peer advert");
        pubsub
            .publish(DM_CAPABILITY_TOPIC.to_string(), Bytes::from(advert))
            .await
            .expect("publish advert");
        let extension =
            build_signed_digest_extension(&signing_p, agent_p, peer_machine, &peer_caps)
                .expect("build peer extension")
                .expect("digest bit is true");
        pubsub
            .publish(
                crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.to_string(),
                Bytes::from(extension),
            )
            .await
            .expect("publish extension");

        let converged = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store
                    .lookup(&agent_p)
                    .is_some_and(|caps| caps.digest_support)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(
            converged.is_ok(),
            "base advert + extension must converge to a full-knowledge binding"
        );
        let caps = store.lookup(&agent_p).expect("binding");
        assert!(caps.supports_durable_app_ack());

        service.abort();
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServiceEvent {
    Enqueue {
        requester: [u8; 32],
        carrier: &'static str,
        payload_hash: [u8; 32],
        accepted: bool,
    },
    Consumed,
    PendingSkip,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct ConvergenceServiceObserver(std::sync::Mutex<(Vec<ServiceEvent>, bool)>);

#[cfg(test)]
impl ConvergenceServiceObserver {
    fn record(&self, event: ServiceEvent) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if state.0.len() == 16 {
            state.1 = true;
        } else {
            state.0.push(event);
        }
    }
    fn enqueue(&self, message: &PubSubMessage, carrier: &'static str, accepted: bool) {
        use sha2::{Digest, Sha256};
        if let Some(requester) = message.sender {
            self.record(ServiceEvent::Enqueue {
                requester: requester.0,
                carrier,
                payload_hash: Sha256::digest(&message.payload).into(),
                accepted,
            });
        }
    }
    pub(crate) fn snapshot(&self) -> Result<Vec<ServiceEvent>, &'static str> {
        let state = self.0.lock().map_err(|_| "service observer poisoned")?;
        if state.1 {
            return Err("service observer overflow");
        }
        Ok(state.0.clone())
    }
}

#[cfg(test)]
pub(crate) fn convergence_request_bytes(agent: AgentId) -> Vec<u8> {
    encode_targeted_capability_request(agent).expect("encode fixed-size fixture request")
}

#[cfg(test)]
mod asymmetric_ingress_tests {
    use super::*;
    use crate::{
        dm,
        identity::{AgentKeypair, MachineKeypair},
        peer_relay::{PeerRelay, RelayDisposition, RelayPolicy, RelayRefusal},
    };

    fn message(signing: &SigningContext, extension: bool) -> PubSubMessage {
        let caps = DmCapabilities::v1_gossip_ready(vec![1; 1184]);
        let payload = if extension {
            build_signed_digest_extension(signing, signing.agent_id, MachineId([4; 32]), &caps)
                .unwrap()
                .unwrap()
        } else {
            build_signed_advert(signing, signing.agent_id, MachineId([4; 32]), caps).unwrap()
        };
        // Unit boundary only: these are controlled verified outer metadata,
        // not evidence that a live PubSub transport authenticated the message.
        PubSubMessage {
            topic: if extension {
                crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC
            } else {
                DM_CAPABILITY_TOPIC
            }
            .into(),
            payload: payload.into(),
            sender: Some(signing.agent_id),
            sender_public_key: Some(signing.public_key_bytes.clone()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        }
    }

    fn frame(signing: &SigningContext, bound: bool) -> crate::peer_relay::RelayedDm {
        let machine = MachineKeypair::generate().unwrap();
        let kem = crate::groups::kem_envelope::AgentKemKeypair::generate().unwrap();
        let now = dm::now_unix_ms();
        let inner = dm::EnvelopeBuilder::build_payload_envelope(
            [7; 16],
            &signing.agent_id,
            &machine.machine_id(),
            &machine,
            &AgentId([9; 32]),
            &kem.public_bytes,
            now,
            now + 60_000,
            b"unit payload".to_vec(),
            |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
        )
        .unwrap();
        PeerRelay::new()
            .build_relayed_dm(
                &AgentId([9; 32]),
                &signing.agent_id,
                signing.public_key_bytes.clone(),
                now,
                inner,
                bound,
                |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
            )
            .unwrap()
    }

    #[test]
    fn asymmetric_signed_ingress_preserves_legacy_until_observed_v2() {
        let s = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let r = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let at_r = CapabilityStore::new();
        let at_s = CapabilityStore::new();
        assert!(ingest_verified_capability_advert(
            &at_r,
            r.agent_id,
            &message(&s, false)
        ));
        assert!(ingest_verified_digest_extension(
            &at_r,
            r.agent_id,
            &message(&s, true)
        ));
        assert!(ingest_verified_capability_advert(
            &at_s,
            s.agent_id,
            &message(&r, false)
        ));
        assert!(at_r.lookup(&s.agent_id).unwrap().digest_support);
        assert!(!crate::peer_relay::peer_advertises_inner_digest(
            at_s.lookup(&r.agent_id).as_ref()
        ));
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        assert_eq!(
            relay.disposition_for(
                &frame(&s, false),
                &r.agent_id,
                dm::now_unix_ms(),
                true,
                false
            ),
            RelayDisposition::Forward {
                dst_agent_id: [9; 32]
            }
        );
        assert!(relay
            .digest_diagnostic_snapshot(std::time::Instant::now(), None)
            .rows
            .is_empty());
        assert_eq!(
            relay.disposition_for(
                &frame(&s, true),
                &r.agent_id,
                dm::now_unix_ms(),
                true,
                false
            ),
            RelayDisposition::Forward {
                dst_agent_id: [9; 32]
            }
        );
        assert_eq!(
            relay.disposition_for(
                &frame(&s, false),
                &r.agent_id,
                dm::now_unix_ms(),
                true,
                false
            ),
            RelayDisposition::Refuse(RelayRefusal::MissingInnerDigest)
        );
    }

    #[test]
    fn asymmetric_signed_ingress_extension_order_and_rejection() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let local = AgentId([3; 32]);
        let store = CapabilityStore::new();
        let base = message(&signing, false);
        let extension = message(&signing, true);
        assert!(ingest_verified_digest_extension(&store, local, &extension));
        assert!(store.lookup(&signing.agent_id).is_none());
        assert!(ingest_verified_capability_advert(&store, local, &base));
        assert!(store.lookup(&signing.agent_id).unwrap().digest_support);
        let mut unverified = extension.clone();
        unverified.verified = false;
        assert!(!ingest_verified_digest_extension(
            &CapabilityStore::new(),
            local,
            &unverified
        ));
        let mut forged =
            crate::dm_capability::DigestSupportExtension::from_postcard(&extension.payload)
                .unwrap();
        forged.signature[0] ^= 1;
        let mut forged_message = extension;
        forged_message.payload = postcard::to_stdvec(&forged).unwrap().into();
        assert!(!ingest_verified_digest_extension(
            &CapabilityStore::new(),
            local,
            &forged_message
        ));
        let foreign = AgentKeypair::generate().unwrap();
        let mut wrong_sender = base.clone();
        wrong_sender.sender = Some(foreign.agent_id());
        assert!(!ingest_verified_capability_advert(
            &CapabilityStore::new(),
            local,
            &wrong_sender
        ));
    }

    #[test]
    fn asymmetric_signed_ingress_observation_does_not_refresh() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let store = CapabilityStore::new();
        let local = AgentId([3; 32]);
        assert!(ingest_verified_capability_advert(
            &store,
            local,
            &message(&signing, false)
        ));
        assert!(ingest_verified_digest_extension(
            &store,
            local,
            &message(&signing, true)
        ));
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let v2 = frame(&signing, true);
        assert_eq!(
            relay.disposition_for(&v2, &local, dm::now_unix_ms(), true, false),
            RelayDisposition::Forward {
                dst_agent_id: [9; 32]
            }
        );
        let at = std::time::Instant::now();
        let before = crate::dm_digest_diagnostics::join_snapshots(
            store.digest_diagnostic_snapshot(at, None),
            relay.digest_diagnostic_snapshot(at, None),
            None,
        );
        let after = crate::dm_digest_diagnostics::join_snapshots(
            store.digest_diagnostic_snapshot(at, None),
            relay.digest_diagnostic_snapshot(at, None),
            None,
        );
        assert_eq!(before, after);
        assert_eq!(
            relay.disposition_for(
                &frame(&signing, false),
                &local,
                dm::now_unix_ms(),
                true,
                false
            ),
            RelayDisposition::Refuse(RelayRefusal::MissingInnerDigest)
        );
    }

    #[test]
    fn service_observer_bounds_poison_and_pending_predicate() {
        let observer = ConvergenceServiceObserver::default();
        assert!(!advert_is_publishable(&DmCapabilities::pending()));
        assert!(advert_is_publishable(&DmCapabilities::v1_gossip_ready(
            vec![1; 1184]
        )));
        for _ in 0..16 {
            observer.record(ServiceEvent::PendingSkip);
        }
        assert_eq!(observer.snapshot().unwrap().len(), 16);
        observer.record(ServiceEvent::Consumed);
        assert_eq!(
            observer.snapshot().unwrap_err(),
            "service observer overflow"
        );
        let observer = ConvergenceServiceObserver::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = observer.0.lock().unwrap();
            panic!("inert service poison");
        });
        observer.record(ServiceEvent::Consumed);
        assert_eq!(
            observer.snapshot().unwrap_err(),
            "service observer poisoned"
        );
    }
}

/// #674 freshness pre-check: an advert the store would reject as stale must
/// not cost a signature verification. Each test pins one leg of the safety
/// argument — stale skip, newer acceptance, forged-newer rejection.
#[cfg(test)]
mod caps_prefilter_tests {
    use super::*;
    use crate::identity::AgentKeypair;

    /// Signed advert from `signing`, bound to `machine`, stamped
    /// `created_at_unix_ms`.
    fn advert_message(
        signing: &SigningContext,
        machine: MachineId,
        created_at_unix_ms: u64,
    ) -> PubSubMessage {
        let mut advert = CapabilityAdvert {
            protocol_version: ADVERT_PROTOCOL_VERSION,
            agent_id: *signing.agent_id.as_bytes(),
            machine_id: *machine.as_bytes(),
            created_at_unix_ms,
            capabilities: DmCapabilities::v1_gossip_ready(vec![1; 1184]),
            signature: Vec::new(),
        };
        advert.signature = signing
            .sign(&advert.signed_bytes().unwrap())
            .expect("re-sign fixture advert");
        PubSubMessage {
            topic: DM_CAPABILITY_TOPIC.into(),
            payload: postcard::to_stdvec(&advert).unwrap().into(),
            sender: Some(signing.agent_id),
            sender_public_key: Some(signing.public_key_bytes.clone()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        }
    }

    /// Signed digest extension from `signing`, stamped
    /// `created_at_unix_ms`.
    fn extension_message(
        signing: &SigningContext,
        machine: MachineId,
        created_at_unix_ms: u64,
    ) -> PubSubMessage {
        let mut extension = crate::dm_capability::DigestSupportExtension {
            protocol_version: crate::dm_capability::DIGEST_EXTENSION_PROTOCOL_VERSION,
            agent_id: *signing.agent_id.as_bytes(),
            machine_id: *machine.as_bytes(),
            created_at_unix_ms,
            digest_support: true,
            signature: Vec::new(),
        };
        extension.signature = signing
            .sign(&extension.signed_bytes().unwrap())
            .expect("re-sign fixture extension");
        PubSubMessage {
            topic: crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC.into(),
            payload: postcard::to_stdvec(&extension).unwrap().into(),
            sender: Some(signing.agent_id),
            sender_public_key: Some(signing.public_key_bytes.clone()),
            verified: true,
            trust_level: None,
            raw_envelope: None,
        }
    }

    #[test]
    fn stale_advert_replays_skip_the_signature_verify() {
        // Why (#674): on a 27-peer mesh nearly every inbound advert is one
        // the store already holds at the same or newer timestamp; each one
        // previously paid a full ML-DSA-65 verify before insert's
        // last-write-wins rule discarded it.
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let local = AgentId([3; 32]);
        let store = CapabilityStore::new();
        let now = now_unix_ms();
        let first = advert_message(&signing, MachineId([1; 32]), now);
        assert!(ingest_verified_capability_advert(&store, local, &first));
        assert_eq!(store.prefiltered_stale_adverts(), 0);

        // Same-timestamp replay: rejected without verify (counter is the
        // counting hook for the skipped verify) and the TTL-bearing record
        // is untouched — machine binding still the first advert's.
        let replay = advert_message(&signing, MachineId([2; 32]), now);
        assert!(!ingest_verified_capability_advert(&store, local, &replay));
        let older = advert_message(&signing, MachineId([2; 32]), now - 1);
        assert!(!ingest_verified_capability_advert(&store, local, &older));
        assert_eq!(store.prefiltered_stale_adverts(), 2);
        assert_eq!(
            store.lookup_binding(&signing.agent_id).unwrap().machine_id,
            MachineId([1; 32]),
            "a stale or replayed advert must not replace the stored record"
        );
    }

    #[test]
    fn newer_advert_still_verifies_and_replaces_the_record() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let local = AgentId([3; 32]);
        let store = CapabilityStore::new();
        let now = now_unix_ms();
        assert!(ingest_verified_capability_advert(
            &store,
            local,
            &advert_message(&signing, MachineId([1; 32]), now)
        ));
        assert!(ingest_verified_capability_advert(
            &store,
            local,
            &advert_message(&signing, MachineId([2; 32]), now + 5_000)
        ));
        assert_eq!(
            store.prefiltered_stale_adverts(),
            0,
            "a genuinely newer advert must reach the verify, never the skip"
        );
        assert_eq!(
            store.lookup_binding(&signing.agent_id).unwrap().machine_id,
            MachineId([2; 32]),
            "the newer advert must replace the stored record"
        );
    }

    #[test]
    fn forged_newer_advert_is_rejected_by_the_verify() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let local = AgentId([3; 32]);
        let store = CapabilityStore::new();
        let now = now_unix_ms();
        assert!(ingest_verified_capability_advert(
            &store,
            local,
            &advert_message(&signing, MachineId([1; 32]), now)
        ));
        let mut forged = advert_message(&signing, MachineId([2; 32]), now + 5_000);
        let mut advert = CapabilityAdvert::from_postcard(&forged.payload).unwrap();
        advert.signature[0] ^= 1;
        forged.payload = postcard::to_stdvec(&advert).unwrap().into();
        assert!(!ingest_verified_capability_advert(&store, local, &forged));
        assert_eq!(
            store.prefiltered_stale_adverts(),
            0,
            "a forged newer timestamp must be rejected by the verify, not by the pre-check"
        );
        assert_eq!(
            store.lookup_binding(&signing.agent_id).unwrap().machine_id,
            MachineId([1; 32]),
            "a forged advert must not replace the stored record"
        );
    }

    #[test]
    fn digest_extension_stale_replays_skip_but_newer_extensions_apply() {
        let signing = SigningContext::from_keypair(&AgentKeypair::generate().unwrap());
        let local = AgentId([3; 32]);
        let store = CapabilityStore::new();
        let now = now_unix_ms();
        assert!(ingest_verified_digest_extension(
            &store,
            local,
            &extension_message(&signing, MachineId([1; 32]), now)
        ));
        assert!(!ingest_verified_digest_extension(
            &store,
            local,
            &extension_message(&signing, MachineId([1; 32]), now - 1)
        ));
        assert_eq!(store.prefiltered_stale_adverts(), 1);
        assert!(ingest_verified_digest_extension(
            &store,
            local,
            &extension_message(&signing, MachineId([1; 32]), now + 5_000)
        ));
        assert_eq!(store.prefiltered_stale_adverts(), 1);
    }
}
