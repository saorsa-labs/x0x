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
    targeted_request_responder: JoinHandle<()>,
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
        let mut subscription = pubsub.subscribe(DM_CAPABILITY_TOPIC.to_string()).await;
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
                    let _ = warm_reannounce_tx.try_send(());
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
                let _ = reannounce_tx.try_send(());
            }
            tracing::debug!("targeted capability advert request responder exited");
        });

        let publisher_pubsub = Arc::clone(&pubsub);
        let publisher_signing = Arc::clone(&signing);
        let mut publisher_caps_rx = caps_rx;
        let publisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(FIRST_PUBLISH_DELAY_MS)).await;
            // L3 retirement: in on-demand mode (periodic == false) there is no
            // startup burst and no steady beat — the publisher wakes only for
            // targeted/warm requests and capability upgrades, and publishes to
            // the steady topic only on request-triggered cycles (warm-carrier
            // requesters listen there).
            let mut burst_idx: usize = if periodic {
                0
            } else {
                STARTUP_BURST_INTERVALS_MS.len()
            };
            let mut last_targeted_response_at: Option<tokio::time::Instant> = None;
            let mut targeted_response_pending = false;
            let mut requests_open = true;
            loop {
                while reannounce_rx.try_recv().is_ok() {
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
                            // immediately, so there is nothing to answer with
                            // yet — just remember that someone asked.
                            match request {
                                Some(()) => targeted_response_pending = true,
                                None => requests_open = false,
                            }
                        }
                    }
                    continue;
                }
                let respond_on_steady = targeted_response_pending;
                match build_signed_advert(
                    &publisher_signing,
                    self_agent_id,
                    self_machine_id,
                    caps_snapshot,
                ) {
                    Ok(bytes) => {
                        let bytes = Bytes::from(bytes);
                        // Answer the strict requester on the Critical topic
                        // first: its convergence window is seconds long and
                        // must not be spent waiting behind Bulk cooling on the
                        // steady advert topic.
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
                        if periodic || respond_on_steady {
                            if let Err(e) = publisher_pubsub
                                .publish(DM_CAPABILITY_TOPIC.to_string(), bytes)
                                .await
                            {
                                tracing::warn!("capability advert publish failed: {e}");
                            } else {
                                tracing::debug!("capability advert published");
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
                    // On-demand mode: no steady beat. The select below still
                    // wakes on requests and capability upgrades.
                    Duration::from_secs(3600)
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
                                Some(()) => {
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
            publisher,
            subscriber,
            targeted_response_subscriber,
            targeted_request_responder,
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

    pub fn abort(&self) {
        self.publisher.abort();
        self.subscriber.abort();
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
            postcard::from_bytes(&response.payload).expect("decode signed response");

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
}
