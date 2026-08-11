//! Runtime service that publishes this agent's DM capability advert to the
//! mesh-wide `x0x/caps/v1` topic and consumes peers' adverts into a
//! shared [`crate::dm_capability::CapabilityStore`].

use crate::dm::DmCapabilities;
use crate::dm_capability::{
    now_unix_ms, CapabilityAdvert, CapabilityStore, ADVERT_PUBLISH_INTERVAL_SECS,
    DM_CAPABILITY_REQUEST_TOPIC, DM_CAPABILITY_TOPIC,
};
use crate::error::{NetworkError, NetworkResult};
use crate::gossip::{PubSubManager, SigningContext};
use crate::identity::{AgentId, MachineId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub const ADVERT_PROTOCOL_VERSION: u16 = 1;

const FIRST_PUBLISH_DELAY_MS: u64 = 250;

/// A verified requester can make the fleet republish public data, but it must
/// not be able to amplify traffic without bound. Long-running responders
/// therefore publish at most once per window in response to requests. A peer
/// that has not published recently still responds immediately.
const MIN_REQUEST_RESPONSE_INTERVAL_SECS: u64 = 30;

/// Startup-burst schedule so late-joining peers catch our advert quickly.
const STARTUP_BURST_INTERVALS_MS: &[u64] = &[5_000, 10_000, 20_000, 45_000];

#[derive(Debug, Serialize, Deserialize)]
struct CapabilityAdvertRequest {
    protocol_version: u16,
}

pub struct CapabilityAdvertService {
    publisher: JoinHandle<()>,
    subscriber: JoinHandle<()>,
    request_responder: JoinHandle<()>,
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
        let mut request_subscription = pubsub
            .subscribe(DM_CAPABILITY_REQUEST_TOPIC.to_string())
            .await;
        let store_sub = Arc::clone(&store);
        let self_agent_for_sub = self_agent_id;
        let (reannounce_tx, mut reannounce_rx) = tokio::sync::mpsc::channel::<()>(1);

        let subscriber = tokio::spawn(async move {
            while let Some(message) = subscription.recv().await {
                let (pubsub_sender, sender_pubkey) =
                    match (message.sender, message.sender_public_key.as_deref()) {
                        (Some(s), Some(pk)) if message.verified => (s, pk.to_vec()),
                        _ => continue,
                    };
                if pubsub_sender == self_agent_for_sub {
                    continue;
                }
                let advert: CapabilityAdvert = match postcard::from_bytes(&message.payload) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                if advert.protocol_version != ADVERT_PROTOCOL_VERSION {
                    continue;
                }
                if advert.agent_id != *pubsub_sender.as_bytes() {
                    continue;
                }
                if !verify_advert_signature(&advert, &sender_pubkey) {
                    continue;
                }
                store_sub.insert(
                    AgentId(advert.agent_id),
                    MachineId(advert.machine_id),
                    advert.capabilities,
                    advert.created_at_unix_ms,
                );
                tracing::debug!(
                    "cached capability advert from {}",
                    hex::encode(advert.agent_id)
                );
            }
            tracing::debug!("capability advert subscriber exited");
        });

        let request_responder = tokio::spawn(async move {
            while let Some(message) = request_subscription.recv().await {
                if !message.verified
                    || message.sender.is_none()
                    || message.sender_public_key.is_none()
                {
                    continue;
                }
                let request: CapabilityAdvertRequest = match postcard::from_bytes(&message.payload)
                {
                    Ok(request) => request,
                    Err(_) => continue,
                };
                if request.protocol_version != ADVERT_PROTOCOL_VERSION {
                    continue;
                }
                // Capacity one deliberately coalesces concurrent requests.
                // The publisher applies an additional global rate limit.
                let _ = reannounce_tx.try_send(());
            }
            tracing::debug!("capability advert request responder exited");
        });

        let requester_pubsub = Arc::clone(&pubsub);
        let requester = tokio::spawn(async move {
            if !request_startup_burst {
                std::future::pending::<()>().await;
                return;
            }

            tokio::time::sleep(Duration::from_millis(FIRST_PUBLISH_DELAY_MS)).await;
            let request = CapabilityAdvertRequest {
                protocol_version: ADVERT_PROTOCOL_VERSION,
            };
            let request_bytes = match postcard::to_stdvec(&request) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!("capability advert request encode failed: {error}");
                    return;
                }
            };

            // Repeat across the same mesh-formation envelope as the advert
            // startup burst. A request missed before peer discovery is retried
            // without changing the five-minute steady-state advert cadence.
            for delay_after_request_ms in startup_burst_intervals_ms
                .iter()
                .copied()
                .map(Some)
                .chain(std::iter::once(None))
            {
                if let Err(error) = requester_pubsub
                    .publish(
                        DM_CAPABILITY_REQUEST_TOPIC.to_string(),
                        Bytes::copy_from_slice(&request_bytes),
                    )
                    .await
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
            let mut last_publish_at: Option<tokio::time::Instant> = None;
            let mut requests_open = true;
            loop {
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
                            if request.is_none() {
                                requests_open = false;
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
                        if let Err(e) = publisher_pubsub
                            .publish(DM_CAPABILITY_TOPIC.to_string(), Bytes::from(bytes))
                            .await
                        {
                            tracing::warn!("capability advert publish failed: {e}");
                        } else {
                            last_publish_at = Some(tokio::time::Instant::now());
                            // This advert also satisfies requests that queued
                            // while signing/publishing it.
                            while reannounce_rx.try_recv().is_ok() {}
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
                tokio::select! {
                    _ = tokio::time::sleep(next_delay) => {}
                    res = publisher_caps_rx.changed() => {
                        if res.is_ok() {
                            tracing::debug!("capability advert upgraded; republishing");
                            burst_idx = 0;
                        }
                    }
                    request = reannounce_rx.recv(), if requests_open => {
                        if request.is_none() {
                            requests_open = false;
                        } else {
                            if let Some(last_publish) = last_publish_at {
                                let earliest = last_publish + request_response_min_interval;
                                tokio::time::sleep_until(earliest).await;
                            }
                            // One response satisfies all requests observed in
                            // the rate-limit window.
                            while reannounce_rx.try_recv().is_ok() {}
                            tracing::debug!("verified capability request received; republishing");
                        }
                    }
                }
            }
        });

        Ok(Self {
            publisher,
            subscriber,
            request_responder,
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
        self.request_responder.abort();
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

        let request = CapabilityAdvertRequest {
            protocol_version: ADVERT_PROTOCOL_VERSION,
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

        let request = CapabilityAdvertRequest {
            protocol_version: ADVERT_PROTOCOL_VERSION,
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
        assert!(!service.request_responder.is_finished());
        assert!(!service.requester.is_finished());

        service.abort();

        // abort() cancels every JoinHandle; they must report finished promptly.
        let finished = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if service.publisher.is_finished()
                    && service.subscriber.is_finished()
                    && service.request_responder.is_finished()
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
