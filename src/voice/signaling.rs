//! [`SignalingTransport`] over x0x direct messages (saorsa-webrtc V1.1).
//!
//! QUIC-native call setup needs three messages
//! (`CapabilityExchange → ConnectionConfirm → ConnectionReady`), each a
//! small serde enum. They ride the existing DM path — ML-KEM-768 sealed,
//! ML-DSA-65 signed, trust- and revocation-gated — prefixed with
//! [`VOICE_SIGNALING_DM_PREFIX`] so the ADR-0023 taxonomy classifies them
//! Ephemeral (signaling is control traffic, not conversation history).

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use saorsa_webrtc_core::signaling::{SignalingMessage, SignalingTransport};
use tokio::sync::{mpsc, Mutex};

use crate::error::VoiceError;
use crate::identity::AgentId;
use crate::Agent;

use super::VOICE_SIGNALING_DM_PREFIX;

/// Depth of the inbound signaling queue. Signaling is three messages per
/// call setup plus teardown; 256 absorbs any realistic burst, and overflow
/// drops (counted via `tracing::warn!`) rather than blocking the DM
/// subscriber fan-out.
const SIGNALING_QUEUE_DEPTH: usize = 256;

/// Voice peer identity: an [`AgentId`] with a **round-trippable** textual
/// form (full 64-char lowercase hex).
///
/// `AgentId`'s own `Display` is a truncated debug form; the
/// [`SignalingTransport`] contract wants `Display`/`FromStr` to round-trip,
/// so this newtype provides the parseable encoding without touching core
/// identity types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoicePeerId(pub AgentId);

impl std::fmt::Display for VoicePeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0 .0))
    }
}

impl FromStr for VoicePeerId {
    type Err = VoiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| VoiceError::InvalidPeerId(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VoiceError::InvalidPeerId(format!("expected 32 bytes, got {s:?}")))?;
        Ok(Self(AgentId(arr)))
    }
}

/// [`SignalingTransport`] implementation over x0x DMs.
///
/// A background task drains the agent's direct-message subscription,
/// filters for the voice prefix, and feeds parsed messages into a bounded
/// queue that [`SignalingTransport::receive_message`] drains. Non-voice
/// DMs are ignored (other subscribers receive their own clones — the DM
/// fan-out is per-subscriber).
pub struct X0xSignaling {
    agent: Arc<Agent>,
    inbound: Mutex<mpsc::Receiver<(VoicePeerId, SignalingMessage)>>,
    reader: tokio::task::JoinHandle<()>,
}

impl X0xSignaling {
    /// Attach a signaling transport to a running agent.
    #[must_use]
    pub fn new(agent: Arc<Agent>) -> Self {
        let (tx, rx) = mpsc::channel(SIGNALING_QUEUE_DEPTH);
        let mut direct = agent.subscribe_direct();
        let reader = tokio::spawn(async move {
            while let Some(msg) = direct.recv().await {
                let Some(body) = msg.payload.strip_prefix(VOICE_SIGNALING_DM_PREFIX) else {
                    continue;
                };
                // x0x transport-extension frames (`"type": "x0x_*"`, e.g.
                // the ADR-0042 datagram-capability advert) ride the same
                // prefix but are consumed by `X0xLinkTransport`'s own
                // subscriber — skip them silently here instead of logging
                // a decode warning per frame.
                if is_x0x_extension_frame(body) {
                    continue;
                }
                match serde_json::from_slice::<SignalingMessage>(body) {
                    Ok(parsed) => {
                        if tx.try_send((VoicePeerId(msg.sender), parsed)).is_err() {
                            tracing::warn!(
                                target: "voice",
                                "signaling queue full or closed; dropping inbound frame"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "voice",
                            error = %e,
                            "undecodable voice signaling frame dropped"
                        );
                    }
                }
            }
        });
        Self {
            agent,
            inbound: Mutex::new(rx),
            reader,
        }
    }

    /// The local agent identity in voice-peer form.
    #[must_use]
    pub fn local_peer_id(&self) -> VoicePeerId {
        VoicePeerId(self.agent.agent_id())
    }
}

impl Drop for X0xSignaling {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[async_trait]
impl SignalingTransport for X0xSignaling {
    type PeerId = VoicePeerId;
    type Error = VoiceError;

    async fn send_message(
        &self,
        peer: &Self::PeerId,
        message: SignalingMessage,
    ) -> Result<(), Self::Error> {
        let body = serde_json::to_vec(&message)?;
        let mut payload = Vec::with_capacity(VOICE_SIGNALING_DM_PREFIX.len() + body.len());
        payload.extend_from_slice(VOICE_SIGNALING_DM_PREFIX);
        payload.extend_from_slice(&body);
        self.agent
            .send_direct(&peer.0, payload)
            .await
            .map_err(|e| VoiceError::SignalingSend(e.to_string()))?;
        Ok(())
    }

    async fn receive_message(&self) -> Result<(Self::PeerId, SignalingMessage), Self::Error> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(VoiceError::ChannelClosed)
    }

    async fn discover_peer_endpoint(
        &self,
        _peer: &Self::PeerId,
    ) -> Result<Option<std::net::SocketAddr>, Self::Error> {
        // QUIC-native flow: ant-quic owns NAT traversal and addressing; no
        // endpoint discovery is required at the signaling layer.
        Ok(None)
    }
}

/// Whether a voice-signaling DM body is an x0x transport-extension frame
/// (`"type"` starting with `x0x_`) rather than an upstream
/// [`SignalingMessage`].
///
/// The `x0x_` namespace is disjoint from upstream's snake_case tags, so
/// this never swallows a real signaling message. Extension frames have
/// their own consumers (e.g. the ADR-0042 datagram-capability advert is
/// consumed by `X0xLinkTransport`'s DM subscriber); this predicate lets
/// the signaling reader skip them silently instead of logging a decode
/// warning per frame. Undecodable bodies are NOT extensions (only a
/// decodable JSON object with a matching tag is).
fn is_x0x_extension_frame(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
        value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|tag| tag.starts_with("x0x_"))
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_peer_id_round_trips() {
        let id = VoicePeerId(AgentId([0xAB; 32]));
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        let parsed: VoicePeerId = text.parse().expect("round trip");
        assert_eq!(parsed, id);
    }

    #[test]
    fn voice_peer_id_rejects_bad_input() {
        assert!(VoicePeerId::from_str("zz").is_err());
        assert!(VoicePeerId::from_str(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn x0x_extension_frames_are_recognized_and_upstream_tags_are_not() {
        // The ADR-0042 datagram advert is an extension frame.
        assert!(is_x0x_extension_frame(
            br#"{"type":"x0x_datagram_cap","datagram":true}"#
        ));
        // Future x0x_ extensions too.
        assert!(is_x0x_extension_frame(br#"{"type":"x0x_anything"}"#));
        // Upstream SignalingMessage tags never match the namespace…
        assert!(!is_x0x_extension_frame(
            br#"{"type":"capability_exchange","session_id":"s"}"#
        ));
        // …and neither do undecodable bodies (they keep the decode-warn
        // path — an extension frame must be valid JSON by definition).
        assert!(!is_x0x_extension_frame(b"not json"));
    }

    #[test]
    fn prefix_literal_is_pinned() {
        // The wire prefix is protocol surface — changing it breaks live
        // calls between versions. Bump deliberately, never accidentally.
        assert_eq!(VOICE_SIGNALING_DM_PREFIX, b"x0x-voice-sig-v1\n");
    }
}
