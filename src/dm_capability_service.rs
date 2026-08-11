//! Runtime service that publishes this agent's DM capability advert to the
//! mesh-wide `x0x/caps/v1` topic and consumes peers' adverts into a
//! shared [`crate::dm_capability::CapabilityStore`].

use crate::dm::DmCapabilities;
use crate::dm_capability::{
    now_unix_ms, CapabilityAdvert, CapabilityStore, ADVERT_PUBLISH_INTERVAL_SECS,
    DM_CAPABILITY_REQUEST_TOPIC, DM_CAPABILITY_TARGETED_REQUEST_TOPIC, DM_CAPABILITY_TOPIC,
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
const FLEET_REQUEST_PROTOCOL_VERSION: u16 = 1;
const TARGETED_REQUEST_PROTOCOL_VERSION: u16 = 2;

/// Dedicated response topic for an exact-recipient strict refresh.
///
/// Steady capability adverts remain Bulk anti-entropy traffic. A strict send
/// has only a short convergence window, so its authenticated targeted request
/// and signed response use their own Critical control topics instead of being
/// cooled behind the fleet-wide advert stream.
pub(crate) const DM_CAPABILITY_TARGETED_RESPONSE_TOPIC: &str = "x0x/caps/v1/response/targeted-v2";

const FIRST_PUBLISH_DELAY_MS: u64 = 250;

/// A verified requester can make the fleet republish public data, but it must
/// not be able to amplify traffic without bound. Long-running responders
/// therefore publish at most once per window in response to requests. A peer
/// that has not answered a fleet request recently still responds immediately.
const MIN_REQUEST_RESPONSE_INTERVAL_SECS: u64 = 30;

/// A targeted refresh is emitted only by a strict send whose recipient cache
/// entry is missing. Unlike the fleet-wide startup hint, exactly one daemon
/// responds, so a short global coalescing window is sufficient to prevent a
/// burst of concurrent sends from producing unbounded advert traffic.
const MIN_TARGETED_RESPONSE_INTERVAL_SECS: u64 = 1;

/// Startup-burst schedule so late-joining peers catch our advert quickly.
const STARTUP_BURST_INTERVALS_MS: &[u64] = &[5_000, 10_000, 20_000, 45_000];

#[derive(Debug, Serialize, Deserialize)]
struct FleetCapabilityAdvertRequest {
    protocol_version: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetedCapabilityAdvertRequest {
    protocol_version: u16,
    requested_agent_id: [u8; 32],
}

// There is deliberately no request nonce here. PubSub authenticates the
// requester, while the responder emits its independently signed current-state
// advert on `DM_CAPABILITY_TOPIC`; that advert is not a challenge response.
// A nonce that is neither echoed nor bound into the accepted advert would add
// bytes and security claims without providing replay protection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodedCapabilityAdvertRequest {
    Fleet,
    Targeted { requested_agent_id: AgentId },
}

/// Decode a request according to its exact topic-owned wire contract.
///
/// The fleet topic remains the original one-field postcard layout. Targeted
/// requests are never decoded on that topic, preventing an older responder
/// (whose v1 decoder accepts trailing postcard bytes) from amplifying them as
/// fleet requests.
pub(crate) fn decode_capability_advert_request(
    topic: &str,
    payload: &[u8],
) -> Option<DecodedCapabilityAdvertRequest> {
    match topic {
        DM_CAPABILITY_REQUEST_TOPIC => {
            let request: FleetCapabilityAdvertRequest = postcard::from_bytes(payload).ok()?;
            (request.protocol_version == FLEET_REQUEST_PROTOCOL_VERSION)
                .then_some(DecodedCapabilityAdvertRequest::Fleet)
        }
        DM_CAPABILITY_TARGETED_REQUEST_TOPIC => {
            let request: TargetedCapabilityAdvertRequest = postcard::from_bytes(payload).ok()?;
            (request.protocol_version == TARGETED_REQUEST_PROTOCOL_VERSION).then_some(
                DecodedCapabilityAdvertRequest::Targeted {
                    requested_agent_id: AgentId(request.requested_agent_id),
                },
            )
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum ReannounceRequest {
    Fleet,
    Targeted,
}

#[derive(Debug, Default)]
struct PendingResponses {
    fleet: bool,
    targeted: bool,
}

impl PendingResponses {
    fn record(&mut self, request: ReannounceRequest) {
        match request {
            ReannounceRequest::Fleet => self.fleet = true,
            ReannounceRequest::Targeted => self.targeted = true,
        }
    }
}

/// Publish an authenticated request for fresh capability state.
///
/// `requested_agent_id = None` is reserved for the bounded startup burst.
/// Strict sends pass their exact recipient so only that daemon responds.
pub(crate) async fn publish_capability_advert_request(
    pubsub: &PubSubManager,
    requested_agent_id: Option<AgentId>,
) -> NetworkResult<()> {
    let (topic, request_bytes) = match requested_agent_id {
        Some(requested_agent_id) => {
            let request = TargetedCapabilityAdvertRequest {
                protocol_version: TARGETED_REQUEST_PROTOCOL_VERSION,
                requested_agent_id: *requested_agent_id.as_bytes(),
            };
            let bytes = postcard::to_stdvec(&request).map_err(|error| {
                NetworkError::SerializationError(format!(
                    "targeted capability advert request encode: {error}"
                ))
            })?;
            (DM_CAPABILITY_TARGETED_REQUEST_TOPIC, bytes)
        }
        None => {
            let request = FleetCapabilityAdvertRequest {
                protocol_version: FLEET_REQUEST_PROTOCOL_VERSION,
            };
            let bytes = postcard::to_stdvec(&request).map_err(|error| {
                NetworkError::SerializationError(format!(
                    "fleet capability advert request encode: {error}"
                ))
            })?;
            (DM_CAPABILITY_REQUEST_TOPIC, bytes)
        }
    };
    pubsub
        .publish(topic.to_string(), Bytes::from(request_bytes))
        .await?;
    tracing::debug!(
        target: "dm.trace",
        stage = "capability_refresh_request_published",
        kind = if requested_agent_id.is_some() { "targeted_v2" } else { "fleet_v1" },
        recipient = requested_agent_id.map(|agent_id| hex::encode(agent_id.as_bytes())),
    );
    Ok(())
}

/// Verify and ingest one capability advert using the same checks as the live
/// subscriber. Kept as one function so tests can exercise the complete
/// authenticated sender -> advert signature -> exact AgentId/MachineId store
/// boundary without duplicating acceptance logic.
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
    let advert: CapabilityAdvert = match postcard::from_bytes(&message.payload) {
        Ok(advert) => advert,
        Err(_) => return false,
    };
    if advert.protocol_version != ADVERT_PROTOCOL_VERSION
        || advert.agent_id != *pubsub_sender.as_bytes()
        || !verify_advert_signature(&advert, sender_pubkey)
    {
        return false;
    }
    store.insert(
        AgentId(advert.agent_id),
        MachineId(advert.machine_id),
        advert.capabilities,
        advert.created_at_unix_ms,
    )
}

pub struct CapabilityAdvertService {
    publisher: JoinHandle<()>,
    subscriber: JoinHandle<()>,
    targeted_response_subscriber: JoinHandle<()>,
    request_responder: JoinHandle<()>,
    targeted_request_responder: JoinHandle<()>,
    requester: JoinHandle<()>,
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
    ) -> NetworkResult<Self> {
        Self::spawn_with_timing(
            pubsub,
            signing,
            self_agent_id,
            self_machine_id,
            caps_rx,
            store,
            publish_interval,
            Duration::from_secs(MIN_REQUEST_RESPONSE_INTERVAL_SECS),
            STARTUP_BURST_INTERVALS_MS,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_with_timing(
        pubsub: Arc<PubSubManager>,
        signing: Arc<SigningContext>,
        self_agent_id: AgentId,
        self_machine_id: MachineId,
        caps_rx: tokio::sync::watch::Receiver<DmCapabilities>,
        store: Arc<CapabilityStore>,
        publish_interval: Duration,
        request_response_min_interval: Duration,
        startup_burst_intervals_ms: &'static [u64],
        request_startup_burst: bool,
    ) -> NetworkResult<Self> {
        let mut subscription = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let mut targeted_response_subscription = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let mut request_subscription = pubsub
            .subscribe(DM_CAPABILITY_REQUEST_TOPIC.to_string())
            .await;
        let mut targeted_request_subscription = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_REQUEST_TOPIC.to_string())
            .await;
        let store_sub = Arc::clone(&store);
        let targeted_store_sub = Arc::clone(&store);
        let self_agent_for_sub = self_agent_id;
        let self_agent_for_targeted_sub = self_agent_id;
        let (reannounce_tx, mut reannounce_rx) =
            tokio::sync::mpsc::channel::<ReannounceRequest>(16);
        let targeted_reannounce_tx = reannounce_tx.clone();

        let subscriber = tokio::spawn(async move {
            while let Some(message) = subscription.recv().await {
                let sender = message.sender;
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

        let targeted_response_subscriber = tokio::spawn(async move {
            while let Some(message) = targeted_response_subscription.recv().await {
                let sender = message.sender;
                if ingest_verified_capability_advert(
                    &targeted_store_sub,
                    self_agent_for_targeted_sub,
                    &message,
                ) {
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "capability_advert_ingested",
                        kind = "targeted_v2",
                        sender = sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                    );
                }
            }
            tracing::debug!("targeted capability advert response subscriber exited");
        });

        let request_responder = tokio::spawn(async move {
            while let Some(message) = request_subscription.recv().await {
                if !message.verified
                    || message.sender.is_none()
                    || message.sender_public_key.is_none()
                {
                    continue;
                }
                if !matches!(
                    decode_capability_advert_request(&message.topic, &message.payload),
                    Some(DecodedCapabilityAdvertRequest::Fleet)
                ) {
                    continue;
                }
                // The bounded channel absorbs a mixed fleet/targeted burst;
                // the publisher coalesces every queued request into one
                // signed advert and applies the per-kind rate limits.
                let _ = reannounce_tx.try_send(ReannounceRequest::Fleet);
            }
            tracing::debug!("fleet capability advert request responder exited");
        });

        let targeted_request_responder = tokio::spawn(async move {
            while let Some(message) = targeted_request_subscription.recv().await {
                if !message.verified
                    || message.sender.is_none()
                    || message.sender_public_key.is_none()
                {
                    continue;
                }
                let Some(DecodedCapabilityAdvertRequest::Targeted { requested_agent_id }) =
                    decode_capability_advert_request(&message.topic, &message.payload)
                else {
                    continue;
                };
                if requested_agent_id != self_agent_id {
                    continue;
                }
                tracing::debug!(
                    target: "dm.trace",
                    stage = "capability_refresh_request_received",
                    kind = "targeted_v2",
                    requester = message.sender.map(|agent_id| hex::encode(agent_id.as_bytes())),
                );
                let _ = targeted_reannounce_tx.try_send(ReannounceRequest::Targeted);
            }
            tracing::debug!("targeted capability advert request responder exited");
        });

        let requester_pubsub = Arc::clone(&pubsub);
        let requester = tokio::spawn(async move {
            if !request_startup_burst {
                std::future::pending::<()>().await;
                return;
            }

            tokio::time::sleep(Duration::from_millis(FIRST_PUBLISH_DELAY_MS)).await;
            // Repeat across the same mesh-formation envelope as the advert
            // startup burst. A request missed before peer discovery is retried
            // without changing the five-minute steady-state advert cadence.
            for delay_after_request_ms in startup_burst_intervals_ms
                .iter()
                .copied()
                .map(Some)
                .chain(std::iter::once(None))
            {
                if let Err(error) = publish_capability_advert_request(&requester_pubsub, None).await
                {
                    tracing::warn!("capability advert request publish failed: {error}");
                }
                let Some(delay_ms) = delay_after_request_ms else {
                    break;
                };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        });

        let publisher_pubsub = Arc::clone(&pubsub);
        let publisher_signing = Arc::clone(&signing);
        let mut publisher_caps_rx = caps_rx;
        let publisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(FIRST_PUBLISH_DELAY_MS)).await;
            let mut burst_idx: usize = 0;
            let mut last_fleet_response_at: Option<tokio::time::Instant> = None;
            let mut last_targeted_response_at: Option<tokio::time::Instant> = None;
            let mut pending_responses = PendingResponses::default();
            let mut requests_open = true;
            loop {
                while let Ok(request) = reannounce_rx.try_recv() {
                    pending_responses.record(request);
                }
                let caps_snapshot = publisher_caps_rx.borrow().clone();
                // Never broadcast a not-yet-usable (pending) advert: absence
                // already tells senders to use the raw fallback, while a
                // pending advert on the wire can race ahead of (or arrive
                // after) the upgraded one and poison receiver caches. The
                // `changed()` arm below restarts the burst as soon as the
                // caps watch upgrades, so readiness still propagates fast.
                if !advert_is_publishable(&caps_snapshot) {
                    tracing::debug!("capability advert pending (no inbox/KEM yet); not publishing");
                    tokio::select! {
                        _ = tokio::time::sleep(publish_interval) => {}
                        res = publisher_caps_rx.changed() => {
                            if res.is_ok() {
                                burst_idx = 0;
                            }
                        }
                        request = reannounce_rx.recv(), if requests_open => {
                            // Pending capabilities cannot produce a usable
                            // advert. A later watch upgrade publishes
                            // immediately; do not manufacture startup bursts
                            // in response to requests while still pending.
                            match request {
                                Some(request) => pending_responses.record(request),
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
                    caps_snapshot,
                ) {
                    Ok(bytes) => {
                        let bytes = Bytes::from(bytes);
                        let publish_targeted = pending_responses.targeted;
                        let mut published_any = false;

                        if publish_targeted {
                            match publisher_pubsub
                                .publish(
                                    DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string(),
                                    bytes.clone(),
                                )
                                .await
                            {
                                Ok(()) => {
                                    published_any = true;
                                    last_targeted_response_at = Some(tokio::time::Instant::now());
                                    pending_responses.targeted = false;
                                    tracing::debug!(
                                        target: "dm.trace",
                                        stage = "capability_advert_response_published",
                                        kind = "targeted_v2",
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        "capability advert publish failed on targeted response topic: {error}"
                                    );
                                }
                            }
                        }

                        // Preserve the original advert topic for mixed-patch
                        // interoperability, but only after the strict Critical
                        // response has been emitted. Bulk cooling must never
                        // consume the targeted convergence window.
                        match publisher_pubsub
                            .publish(DM_CAPABILITY_TOPIC.to_string(), bytes)
                            .await
                        {
                            Ok(()) => {
                                published_any = true;
                                if pending_responses.fleet {
                                    last_fleet_response_at = Some(tokio::time::Instant::now());
                                    pending_responses.fleet = false;
                                }
                            }
                            Err(error) => {
                                tracing::warn!(
                                    "capability advert publish failed on steady topic: {error}"
                                );
                            }
                        }

                        if published_any {
                            tracing::debug!("capability advert published");
                        }
                    }
                    Err(e) => tracing::warn!("capability advert build failed: {e}"),
                }
                let next_delay = if burst_idx < startup_burst_intervals_ms.len() {
                    let d = Duration::from_millis(startup_burst_intervals_ms[burst_idx]);
                    burst_idx += 1;
                    d
                } else {
                    publish_interval
                };
                let publish_delay = tokio::time::sleep(next_delay);
                tokio::pin!(publish_delay);
                loop {
                    tokio::select! {
                        _ = &mut publish_delay => break,
                        res = publisher_caps_rx.changed() => {
                            if res.is_ok() {
                                tracing::debug!("capability advert upgraded; republishing");
                                burst_idx = 0;
                            }
                            break;
                        }
                        request = reannounce_rx.recv(), if requests_open => {
                            match request {
                                None => requests_open = false,
                                Some(kind) => {
                                    pending_responses.record(kind);
                                    let (last_response, min_interval) = match kind {
                                        ReannounceRequest::Fleet => (
                                            last_fleet_response_at,
                                            request_response_min_interval,
                                        ),
                                        ReannounceRequest::Targeted => (
                                            last_targeted_response_at,
                                            Duration::from_secs(MIN_TARGETED_RESPONSE_INTERVAL_SECS),
                                        ),
                                    };
                                    let now = tokio::time::Instant::now();
                                    let earliest = last_response
                                        .map_or(now, |last| last + min_interval);
                                    if earliest <= now {
                                        tracing::debug!(?kind, "verified capability request received; republishing");
                                        break;
                                    }
                                    if earliest < publish_delay.deadline() {
                                        publish_delay.as_mut().reset(earliest);
                                    }
                                    tracing::debug!(
                                        ?kind,
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
            publisher,
            subscriber,
            targeted_response_subscriber,
            request_responder,
            targeted_request_responder,
            requester,
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
        )
        .await
    }

    pub fn abort(&self) {
        self.publisher.abort();
        self.subscriber.abort();
        self.targeted_response_subscriber.abort();
        self.request_responder.abort();
        self.targeted_request_responder.abort();
        self.requester.abort();
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

pub fn build_signed_advert(
    signing: &SigningContext,
    self_agent_id: AgentId,
    self_machine_id: MachineId,
    capabilities: DmCapabilities,
) -> NetworkResult<Vec<u8>> {
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
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;
    use crate::network::{NetworkConfig, NetworkNode};

    /// Isolated network node (mirrors the helper in `src/gossip/pubsub.rs`
    /// tests). `PubSubManager` is fully constructable in tests, so the advert
    /// service is testable end-to-end without a live mesh.
    async fn make_node() -> Arc<NetworkNode> {
        Arc::new(
            NetworkNode::new(NetworkConfig::default(), None, None)
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
        postcard::from_bytes(&encoded).expect("decode advert")
    }

    #[test]
    fn request_wire_keeps_legacy_fleet_bytes_and_separates_targeted_v2() {
        let fleet = FleetCapabilityAdvertRequest {
            protocol_version: FLEET_REQUEST_PROTOCOL_VERSION,
        };
        let fleet_bytes = postcard::to_stdvec(&fleet).expect("encode fleet request");
        assert_eq!(
            fleet_bytes,
            vec![1],
            "legacy startup request must remain byte-for-byte compatible"
        );
        assert_eq!(
            decode_capability_advert_request(DM_CAPABILITY_REQUEST_TOPIC, &fleet_bytes),
            Some(DecodedCapabilityAdvertRequest::Fleet)
        );

        let target = AgentId([0xA7; 32]);
        let targeted = TargetedCapabilityAdvertRequest {
            protocol_version: TARGETED_REQUEST_PROTOCOL_VERSION,
            requested_agent_id: *target.as_bytes(),
        };
        let targeted_bytes = postcard::to_stdvec(&targeted).expect("encode targeted request");
        let mut expected_targeted_bytes = vec![2];
        expected_targeted_bytes.extend_from_slice(target.as_bytes());
        assert_eq!(
            targeted_bytes, expected_targeted_bytes,
            "targeted v2 carries only its wire version and exact recipient"
        );
        // Postcard's old one-field decoder accepts trailing bytes. Topic
        // separation, not wishful decoder strictness, is therefore the wire
        // safety boundary that keeps old responders from amplifying this.
        assert!(postcard::from_bytes::<FleetCapabilityAdvertRequest>(&targeted_bytes).is_ok());
        assert_ne!(
            DM_CAPABILITY_REQUEST_TOPIC,
            DM_CAPABILITY_TARGETED_REQUEST_TOPIC
        );
        assert_eq!(
            decode_capability_advert_request(DM_CAPABILITY_TARGETED_REQUEST_TOPIC, &targeted_bytes,),
            Some(DecodedCapabilityAdvertRequest::Targeted {
                requested_agent_id: target,
            })
        );
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
        let advert: CapabilityAdvert = postcard::from_bytes(&encoded).expect("decode");
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
        let mut advert: CapabilityAdvert = postcard::from_bytes(&encoded).expect("decode");
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

        let advert: CapabilityAdvert = postcard::from_bytes(&msg.payload).expect("decode advert");
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

    #[tokio::test]
    async fn service_ingests_verified_peer_advert_from_targeted_response_topic() {
        let peer_keypair = AgentKeypair::generate().expect("peer keygen");
        let peer_signing = Arc::new(SigningContext::from_keypair(&peer_keypair));
        let peer_agent = peer_keypair.agent_id();
        let peer_machine = MachineId([0x43; 32]);
        let peer_caps = DmCapabilities::v2_durable_gossip_ready(vec![0x44; 1184]);
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&peer_signing))).expect("pubsub"),
        );
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) = tokio::sync::watch::channel(DmCapabilities::pending());
        let service = CapabilityAdvertService::spawn_default(
            Arc::clone(&pubsub),
            Arc::clone(&peer_signing),
            AgentId([0x45; 32]),
            MachineId([0x46; 32]),
            caps_rx,
            Arc::clone(&store),
        )
        .await
        .expect("spawn service");

        let encoded =
            build_signed_advert(&peer_signing, peer_agent, peer_machine, peer_caps.clone())
                .expect("build targeted peer advert");
        let mut stale: CapabilityAdvert =
            postcard::from_bytes(&encoded).expect("decode stale advert template");
        stale.created_at_unix_ms =
            now_unix_ms().saturating_sub(crate::dm_capability::ADVERT_CACHE_TTL_SECS * 1_000 + 1);
        stale.signature = peer_signing
            .sign(&stale.signed_bytes().expect("stale signed bytes"))
            .expect("sign stale advert");
        pubsub
            .publish(
                DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string(),
                Bytes::from(postcard::to_stdvec(&stale).expect("encode stale advert")),
            )
            .await
            .expect("publish stale targeted advert");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            store.lookup_binding(&peer_agent).is_none(),
            "stale signed targeted response must not satisfy strict refresh"
        );
        pubsub
            .publish(
                DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string(),
                Bytes::from(encoded),
            )
            .await
            .expect("publish targeted peer advert");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.lookup_binding(&peer_agent).is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("targeted response subscriber did not ingest peer advert");
        let binding = store
            .lookup_binding(&peer_agent)
            .expect("targeted strict binding");
        assert_eq!(binding.machine_id, peer_machine);
        assert_eq!(binding.capabilities, peer_caps);

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

    // ------------------------------------------------------------------
    // CapabilityAdvertService: a late subscriber requests fresh state
    // ------------------------------------------------------------------

    /// Regression: pub/sub does not retain capability adverts indefinitely.
    /// A subscriber that appears after another daemon's configured startup
    /// burst must be able to solicit a fresh, independently signed advert
    /// instead of waiting for the five-minute steady-state publication.
    #[tokio::test]
    async fn late_subscriber_request_triggers_signed_reannounce_after_startup_burst() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let agent_id = kp.agent_id();
        let machine_id = MachineId([31u8; 32]);
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );

        let mut preexisting_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let store = Arc::new(CapabilityStore::new());
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v1_gossip_ready(vec![0x5A; 1184]));

        // An empty startup schedule makes the first publish the whole burst;
        // the next timer is deliberately an hour away. The request burst is
        // disabled so only the explicit late-subscriber request below can
        // cause the second advert.
        let service = CapabilityAdvertService::spawn_with_timing(
            Arc::clone(&pubsub),
            Arc::clone(&signing),
            agent_id,
            machine_id,
            caps_rx,
            store,
            Duration::from_secs(3_600),
            Duration::from_millis(25),
            &[],
            false,
        )
        .await
        .expect("spawn service");

        let initial_message =
            tokio::time::timeout(Duration::from_secs(3), preexisting_subscriber.recv())
                .await
                .expect("initial advert timeout")
                .expect("initial subscriber closed");
        let initial_advert: CapabilityAdvert =
            postcard::from_bytes(&initial_message.payload).expect("decode initial advert");

        // This subscriber starts only after the complete configured startup
        // burst. It cannot have observed the initial advert live.
        let mut late_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let request = FleetCapabilityAdvertRequest {
            protocol_version: FLEET_REQUEST_PROTOCOL_VERSION,
        };
        let request_bytes = postcard::to_stdvec(&request).expect("encode request");
        pubsub
            .publish(
                DM_CAPABILITY_REQUEST_TOPIC.to_string(),
                Bytes::from(request_bytes),
            )
            .await
            .expect("publish request");

        let reannounced_message =
            tokio::time::timeout(Duration::from_secs(2), late_subscriber.recv())
                .await
                .expect("late subscriber did not receive requested reannounce")
                .expect("late subscriber closed");
        let reannounced: CapabilityAdvert =
            postcard::from_bytes(&reannounced_message.payload).expect("decode reannounce");

        assert_eq!(reannounced.agent_id, *agent_id.as_bytes());
        assert_eq!(reannounced.machine_id, *machine_id.as_bytes());
        assert!(
            reannounced.created_at_unix_ms > initial_advert.created_at_unix_ms,
            "requested response must be a freshly built advert, not replayed startup state"
        );
        assert!(
            verify_advert_signature(&reannounced, &signing.public_key_bytes),
            "requested advert must retain the exact signed AgentId + MachineId binding"
        );

        service.abort();
    }

    /// A rate-limited fleet request must not park the publisher and suppress
    /// an already-scheduled startup advert. The live installed-binary failure
    /// showed this matters: each daemon also receives its own startup request,
    /// so sleeping inside the request branch can serialize the complete burst
    /// behind the 30-second response window.
    #[tokio::test]
    async fn rate_limited_request_does_not_block_scheduled_startup_publish() {
        const SHORT_BURST: &[u64] = &[100, 100];

        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let mut subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v1_gossip_ready(vec![0x5C; 1184]));
        let service = CapabilityAdvertService::spawn_with_timing(
            Arc::clone(&pubsub),
            signing,
            kp.agent_id(),
            MachineId([0x5D; 32]),
            caps_rx,
            Arc::new(CapabilityStore::new()),
            Duration::from_secs(3_600),
            Duration::from_secs(2),
            SHORT_BURST,
            false,
        )
        .await
        .expect("spawn service");

        tokio::time::timeout(Duration::from_secs(3), subscriber.recv())
            .await
            .expect("initial advert timeout")
            .expect("subscriber closed");

        publish_capability_advert_request(&pubsub, None)
            .await
            .expect("first fleet request");
        tokio::time::timeout(Duration::from_millis(500), subscriber.recv())
            .await
            .expect("first request response timeout")
            .expect("subscriber closed");

        publish_capability_advert_request(&pubsub, None)
            .await
            .expect("second fleet request");
        tokio::time::timeout(Duration::from_millis(500), subscriber.recv())
            .await
            .expect("scheduled startup advert was blocked by response rate limit")
            .expect("subscriber closed");

        service.abort();
    }

    /// On-demand strict-send refreshes are addressed. Non-target daemons must
    /// stay silent; the exact target may respond immediately without making
    /// every mesh member amplify one UI send.
    #[tokio::test]
    async fn targeted_request_only_reannounces_from_exact_agent() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let self_agent = kp.agent_id();
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let mut steady_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let mut targeted_subscriber = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v1_gossip_ready(vec![0x6A; 1184]));
        let service = CapabilityAdvertService::spawn_with_timing(
            Arc::clone(&pubsub),
            signing,
            self_agent,
            MachineId([0x6B; 32]),
            caps_rx,
            Arc::new(CapabilityStore::new()),
            Duration::from_secs(3_600),
            Duration::from_millis(25),
            &[],
            false,
        )
        .await
        .expect("spawn service");

        tokio::time::timeout(Duration::from_secs(3), steady_subscriber.recv())
            .await
            .expect("initial advert timeout")
            .expect("subscriber closed");

        publish_capability_advert_request(&pubsub, Some(AgentId([0xEE; 32])))
            .await
            .expect("foreign targeted request");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), targeted_subscriber.recv())
                .await
                .is_err(),
            "a non-target daemon must not reannounce"
        );

        publish_capability_advert_request(&pubsub, Some(self_agent))
            .await
            .expect("self targeted request");
        let response = tokio::time::timeout(Duration::from_secs(2), targeted_subscriber.recv())
            .await
            .expect("exact target did not reannounce")
            .expect("subscriber closed");
        assert_eq!(response.topic, DM_CAPABILITY_TARGETED_RESPONSE_TOPIC);
        let advert: CapabilityAdvert =
            postcard::from_bytes(&response.payload).expect("decode targeted response advert");
        assert_eq!(advert.agent_id, *self_agent.as_bytes());
        assert!(verify_advert_signature(
            &advert,
            &response.sender_public_key.expect("response public key"),
        ));
        let compatibility_response =
            tokio::time::timeout(Duration::from_secs(2), steady_subscriber.recv())
                .await
                .expect("legacy advert-topic compatibility response timeout")
                .expect("steady subscriber closed");
        assert_eq!(compatibility_response.payload, response.payload);

        service.abort();
    }

    #[tokio::test]
    async fn pending_targeted_request_survives_upgrade_and_critical_response_leads_bulk() {
        let keypair = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&keypair));
        let self_agent = keypair.agent_id();
        let pubsub = Arc::new(
            PubSubManager::new(make_node().await, Some(Arc::clone(&signing))).expect("pubsub"),
        );
        let mut targeted_subscriber = pubsub
            .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
            .await;
        let mut bulk_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let (caps_tx, caps_rx) = tokio::sync::watch::channel(DmCapabilities::pending());
        let service = CapabilityAdvertService::spawn_with_timing(
            Arc::clone(&pubsub),
            signing,
            self_agent,
            MachineId([0xB1; 32]),
            caps_rx,
            Arc::new(CapabilityStore::new()),
            Duration::from_secs(3_600),
            Duration::from_millis(25),
            &[],
            false,
        )
        .await
        .expect("spawn service");

        publish_capability_advert_request(&pubsub, Some(self_agent))
            .await
            .expect("targeted request while pending");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), targeted_subscriber.recv())
                .await
                .is_err(),
            "pending inbox must not claim strict capability"
        );

        caps_tx.send_replace(DmCapabilities::v3_threaded_durable_gossip_ready(vec![
            0xB2;
            1184
        ]));
        let targeted = tokio::time::timeout(Duration::from_secs(2), targeted_subscriber.recv())
            .await
            .expect("retained targeted request did not respond after upgrade")
            .expect("targeted subscriber closed");
        assert_eq!(targeted.topic, DM_CAPABILITY_TARGETED_RESPONSE_TOPIC);
        let bulk = tokio::time::timeout(Duration::from_secs(2), bulk_subscriber.recv())
            .await
            .expect("compatibility advert missing")
            .expect("bulk subscriber closed");
        assert_eq!(targeted.payload, bulk.payload);

        // Model stop_dm_inbox's watch transition while retaining the service
        // so the negative assertion exercises the publisher itself. A
        // targeted request observed after stop must remain unanswered until a
        // restarted inbox advertises a new live KEM binding.
        caps_tx.send_replace(DmCapabilities::pending());
        tokio::time::sleep(Duration::from_millis(50)).await;
        publish_capability_advert_request(&pubsub, Some(self_agent))
            .await
            .expect("targeted request after stop");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), targeted_subscriber.recv())
                .await
                .is_err(),
            "stopped inbox must not publish a strict targeted response"
        );

        caps_tx.send_replace(DmCapabilities::v3_threaded_durable_gossip_ready(vec![
            0xB3;
            1184
        ]));
        let restarted = tokio::time::timeout(Duration::from_secs(2), targeted_subscriber.recv())
            .await
            .expect("retained post-stop request did not respond after restart")
            .expect("targeted subscriber closed after restart");
        let restarted_advert: CapabilityAdvert =
            postcard::from_bytes(&restarted.payload).expect("decode restarted advert");
        assert!(restarted_advert.capabilities.supports_thread_metadata());
        assert_eq!(
            restarted_advert.capabilities.kem_public_key,
            vec![0xB3; 1184]
        );

        service.abort();
    }

    /// The request side channel is only a convergence hint, but accepting an
    /// unsigned hint would let anonymous gossip traffic amplify into a
    /// fleet-wide advert burst. Keep the responder fail-closed.
    #[tokio::test]
    async fn unsigned_late_subscriber_request_does_not_trigger_reannounce() {
        let kp = AgentKeypair::generate().expect("keygen");
        let signing = Arc::new(SigningContext::from_keypair(&kp));
        let agent_id = kp.agent_id();
        let pubsub = Arc::new(PubSubManager::new(make_node().await, None).expect("pubsub"));

        let mut preexisting_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
        let (_caps_tx, caps_rx) =
            tokio::sync::watch::channel(DmCapabilities::v1_gossip_ready(vec![0x7B; 1184]));
        let service = CapabilityAdvertService::spawn_with_timing(
            Arc::clone(&pubsub),
            signing,
            agent_id,
            MachineId([41u8; 32]),
            caps_rx,
            Arc::new(CapabilityStore::new()),
            Duration::from_secs(3_600),
            Duration::from_millis(10),
            &[],
            false,
        )
        .await
        .expect("spawn service");

        tokio::time::timeout(Duration::from_secs(3), preexisting_subscriber.recv())
            .await
            .expect("initial advert timeout")
            .expect("initial subscriber closed");
        let mut late_subscriber = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;

        let request = FleetCapabilityAdvertRequest {
            protocol_version: FLEET_REQUEST_PROTOCOL_VERSION,
        };
        pubsub
            .publish(
                DM_CAPABILITY_REQUEST_TOPIC.to_string(),
                Bytes::from(postcard::to_stdvec(&request).expect("encode request")),
            )
            .await
            .expect("publish unsigned request");

        assert!(
            tokio::time::timeout(Duration::from_millis(300), late_subscriber.recv())
                .await
                .is_err(),
            "an unsigned request must not trigger a capability reannounce"
        );

        service.abort();
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

        // Before abort, the long-lived loops are alive. The finite requester
        // is also still inside its startup schedule at this point.
        assert!(!service.publisher.is_finished());
        assert!(!service.subscriber.is_finished());
        assert!(!service.targeted_response_subscriber.is_finished());
        assert!(!service.request_responder.is_finished());
        assert!(!service.targeted_request_responder.is_finished());
        assert!(!service.requester.is_finished());

        service.abort();

        // abort() cancels every JoinHandle; they must report finished promptly.
        let finished = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service.publisher.is_finished()
                    && service.subscriber.is_finished()
                    && service.targeted_response_subscriber.is_finished()
                    && service.request_responder.is_finished()
                    && service.targeted_request_responder.is_finished()
                    && service.requester.is_finished()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(finished.is_ok(), "abort() did not terminate all tasks");
    }
}
