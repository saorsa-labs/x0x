//! Voice adapters for `saorsa-webrtc` (feature `voice`).
//!
//! Implements the two seams the saorsa-webrtc revival design (V1.1/V1.2)
//! assigns to x0x, plus the ADR-0042 (c) unreliable datagram lane:
//!
//! * [`X0xSignaling`](crate::voice::X0xSignaling) — [`saorsa_webrtc_core::signaling::SignalingTransport`]
//!   over x0x direct messages. Signaling frames ride the DM path with the
//!   [`crate::history::classify::VOICE_SIGNALING_DM_PREFIX`] typed prefix and
//!   are classified **Ephemeral** (never recorded to history). The ADR-0042
//!   datagram-capability advert rides the same channel as an additive
//!   `x0x_*`-tagged extension frame.
//! * [`X0xLinkTransport`](crate::voice::X0xLinkTransport) — [`saorsa_webrtc_core::link_transport::LinkTransport`]
//!   over ADR-0022 byte streams using
//!   [`crate::streams::StreamProtocol::WebRtcV1`] (`0x04`). The byte after
//!   the x0x protocol prefix is the saorsa-webrtc
//!   [`saorsa_webrtc_core::link_transport::StreamType`] (0x20–0x24), so
//!   audio/video/control lanes nest inside one gated x0x stream protocol.
//!   With [`AudioLaneMode::Datagram`] pinned, encoded audio additionally
//!   rides unreliable QUIC datagrams on the same peer connection once both
//!   ends advertise the lane — falling back to the reliable stream
//!   otherwise (ADR-0042 decision (c)); the jitter buffer stays mandatory
//!   on the receive side.
//!
//! Both adapters sit **behind** the existing identity gate, trust
//! evaluation, revocation checks, and the connect-ACL pair gate — voice
//! traffic gets no special path through any of them. The datagram lane
//! opens through [`crate::Agent::open_peer_datagram_lane`], which enforces
//! the gates in both directions.

mod link_transport;
mod signaling;

pub use link_transport::{VoiceLaneError, X0xLinkTransport};
pub use signaling::{VoicePeerId, X0xSignaling};

/// Which lane carries encoded audio (ADR-0042 c): the ordered reliable
/// stream (default) or unreliable QUIC datagrams with automatic reliable
/// fallback. Re-exported so applications pin exactly one voice dependency
/// (`x0x` with the `voice` feature).
pub use saorsa_webrtc_core::datagram_lane::AudioLaneMode;

/// The codec crate matching this transport (real Opus; video codecs stay
/// feature-gated upstream). Re-exported so applications pin exactly one
/// voice dependency: `x0x` with the `voice` feature.
pub use saorsa_webrtc_codecs as codecs;

/// Typed DM prefix for voice signaling frames.
///
/// Re-exported from the history taxonomy module, which owns the constant so
/// classification (and its deny-test) hold even when the `voice` feature is
/// disabled.
pub use crate::history::classify::VOICE_SIGNALING_DM_PREFIX;
