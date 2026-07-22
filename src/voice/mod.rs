//! Voice adapters for `saorsa-webrtc` (feature `voice`).
//!
//! Implements the two seams the saorsa-webrtc revival design (V1.1/V1.2)
//! assigns to x0x:
//!
//! * [`X0xSignaling`] — [`saorsa_webrtc_core::signaling::SignalingTransport`]
//!   over x0x direct messages. Signaling frames ride the DM path with the
//!   [`crate::history::classify::VOICE_SIGNALING_DM_PREFIX`] typed prefix and
//!   are classified **Ephemeral** (never recorded to history).
//! * [`X0xLinkTransport`] — [`saorsa_webrtc_core::link_transport::LinkTransport`]
//!   over ADR-0022 byte streams using
//!   [`crate::streams::StreamProtocol::WebRtcV1`] (`0x04`). The byte after
//!   the x0x protocol prefix is the saorsa-webrtc
//!   [`saorsa_webrtc_core::link_transport::StreamType`] (0x20–0x24), so
//!   audio/video/control lanes nest inside one gated x0x stream protocol.
//!
//! Both adapters sit **behind** the existing identity gate, trust
//! evaluation, revocation checks, and the connect-ACL pair gate — voice
//! traffic gets no special path through any of them.

mod link_transport;
mod signaling;

pub use link_transport::X0xLinkTransport;
pub use signaling::{VoicePeerId, X0xSignaling};

/// Typed DM prefix for voice signaling frames.
///
/// Re-exported from the history taxonomy module, which owns the constant so
/// classification (and its deny-test) hold even when the `voice` feature is
/// disabled.
pub use crate::history::classify::VOICE_SIGNALING_DM_PREFIX;
