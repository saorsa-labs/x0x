//! The transport backend under [`super::NetworkNode`] (W3-H, #1164).
//!
//! Production builds have exactly one backend: the ant-quic [`QuicNode`].
//! Test builds add a second, in-memory backend ([`super::sim::SimLink`]) so
//! the W3-H deterministic simulation harness can run the whole x0x stack —
//! the receive pump, plane gate, authenticated sessions, gossip runtime,
//! direct messages and every daemon listener — over a seeded, virtual-time
//! fabric with fault injection, without binding a socket.
//!
//! Every method here delegates one-to-one to the ant-quic method of the same
//! name, so the production behaviour of `NetworkNode` is unchanged. Methods
//! that only make sense for a real QUIC endpoint (diagnostics, the inner
//! endpoint, raw byte streams) are reached through [`LinkNode::quic`] and
//! report "not initialized" for the simulated backend.

use std::net::SocketAddr;
use std::time::Duration;

use ant_quic::{
    bootstrap_cache::PeerCapabilities, ConnectionHealth, EndpointError, Node as QuicNode,
    NodeError, PeerConnection, PeerId, PeerLifecycleEvent,
};
use tokio::sync::broadcast;

/// The transport backend a [`super::NetworkNode`] runs on.
#[derive(Clone)]
pub(crate) enum LinkNode {
    /// The real ant-quic endpoint (the only production backend).
    Quic(QuicNode),
    /// The W3-H in-memory simulation link (test builds only).
    #[cfg(test)]
    Sim(std::sync::Arc<super::sim::SimLink>),
}

impl std::fmt::Debug for LinkNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic(node) => f.debug_tuple("Quic").field(node).finish(),
            #[cfg(test)]
            Self::Sim(link) => f.debug_tuple("Sim").field(&link.peer_id()).finish(),
        }
    }
}

impl LinkNode {
    /// The real QUIC endpoint, when this backend is one.
    pub(crate) fn quic(&self) -> Option<&QuicNode> {
        match self {
            Self::Quic(node) => Some(node),
            #[cfg(test)]
            Self::Sim(_) => None,
        }
    }

    pub(crate) fn peer_id(&self) -> PeerId {
        match self {
            Self::Quic(node) => node.peer_id(),
            #[cfg(test)]
            Self::Sim(link) => link.peer_id(),
        }
    }

    pub(crate) fn external_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Quic(node) => node.external_addr(),
            #[cfg(test)]
            Self::Sim(_) => None,
        }
    }

    pub(crate) async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        match self {
            Self::Quic(node) => node.connect_addr(addr).await,
            #[cfg(test)]
            Self::Sim(link) => link.connect_addr(addr).await,
        }
    }

    pub(crate) async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        match self {
            Self::Quic(node) => node.connect_peer(peer_id).await,
            #[cfg(test)]
            Self::Sim(link) => link.connect_peer(peer_id).await,
        }
    }

    pub(crate) async fn connect_peer_with_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, NodeError> {
        match self {
            Self::Quic(node) => node.connect_peer_with_addrs(peer_id, addrs).await,
            #[cfg(test)]
            Self::Sim(link) => link.connect_peer_with_addrs(peer_id, addrs).await,
        }
    }

    pub(crate) async fn upsert_peer_hints(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
        capabilities: Option<PeerCapabilities>,
    ) {
        match self {
            Self::Quic(node) => node.upsert_peer_hints(peer_id, addrs, capabilities).await,
            #[cfg(test)]
            Self::Sim(link) => link.upsert_peer_hints(peer_id, addrs),
        }
    }

    pub(crate) async fn accept(&self) -> Option<PeerConnection> {
        match self {
            Self::Quic(node) => node.accept().await,
            #[cfg(test)]
            Self::Sim(link) => link.accept().await,
        }
    }

    pub(crate) async fn disconnect(&self, peer_id: &PeerId) -> Result<(), NodeError> {
        match self {
            Self::Quic(node) => node.disconnect(peer_id).await,
            #[cfg(test)]
            Self::Sim(link) => link.disconnect(peer_id),
        }
    }

    pub(crate) async fn connected_peers(&self) -> Vec<PeerConnection> {
        match self {
            Self::Quic(node) => node.connected_peers().await,
            #[cfg(test)]
            Self::Sim(link) => link.connected_peers(),
        }
    }

    pub(crate) async fn is_connected(&self, peer_id: &PeerId) -> bool {
        match self {
            Self::Quic(node) => node.is_connected(peer_id).await,
            #[cfg(test)]
            Self::Sim(link) => link.is_connected(peer_id),
        }
    }

    pub(crate) async fn connection_health(&self, peer_id: &PeerId) -> ConnectionHealth {
        match self {
            Self::Quic(node) => node.connection_health(peer_id).await,
            #[cfg(test)]
            Self::Sim(link) => link.connection_health(peer_id),
        }
    }

    /// Live connections: ant-quic's `NodeStatus::connected_peers`.
    pub(crate) async fn connection_count(&self) -> usize {
        match self {
            Self::Quic(node) => node.status().await.connected_peers,
            #[cfg(test)]
            Self::Sim(link) => link.connected_peers().len(),
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        match self {
            Self::Quic(node) => node.is_running(),
            #[cfg(test)]
            Self::Sim(link) => link.is_running(),
        }
    }

    pub(crate) fn subscribe_all_peer_events(
        &self,
    ) -> broadcast::Receiver<(PeerId, PeerLifecycleEvent)> {
        match self {
            Self::Quic(node) => node.subscribe_all_peer_events(),
            #[cfg(test)]
            Self::Sim(link) => link.subscribe_all_peer_events(),
        }
    }

    pub(crate) async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), NodeError> {
        match self {
            Self::Quic(node) => node.send(peer_id, data).await,
            #[cfg(test)]
            Self::Sim(link) => link.send(peer_id, data),
        }
    }

    pub(crate) async fn send_on_generation_with_admission<B, F>(
        &self,
        peer_id: &PeerId,
        generation: u64,
        admit: F,
    ) -> Result<(), NodeError>
    where
        B: AsRef<[u8]> + Send,
        F: FnOnce(u64) -> Result<B, EndpointError> + Send,
    {
        match self {
            Self::Quic(node) => {
                node.send_on_generation_with_admission(peer_id, generation, admit)
                    .await
            }
            #[cfg(test)]
            Self::Sim(link) => link.send_on_generation_with_admission(peer_id, generation, admit),
        }
    }

    pub(crate) async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), NodeError> {
        match self {
            Self::Quic(node) => node.send_with_receive_ack(peer_id, data, timeout).await,
            #[cfg(test)]
            Self::Sim(link) => link.send_with_receive_ack(peer_id, data, timeout).await,
        }
    }

    pub(crate) async fn probe_peer(
        &self,
        peer_id: &PeerId,
        timeout: Duration,
    ) -> Result<Duration, NodeError> {
        match self {
            Self::Quic(node) => node.probe_peer(peer_id, timeout).await,
            #[cfg(test)]
            Self::Sim(link) => link.probe_peer(peer_id),
        }
    }

    pub(crate) async fn recv_with_generation(&self) -> Result<(PeerId, u64, Vec<u8>), NodeError> {
        match self {
            Self::Quic(node) => node.recv_with_generation().await,
            #[cfg(test)]
            Self::Sim(link) => link.recv_with_generation().await,
        }
    }

    /// The live backend connection behind `peer`'s current generation, for
    /// the authenticated-session registry.
    pub(super) fn session_connection(&self, peer: &PeerId) -> Option<super::SessionConnection> {
        match self {
            Self::Quic(node) => node
                .inner_endpoint()
                .get_quic_connection(peer)
                .ok()
                .flatten()
                .map(super::SessionConnection::Quic),
            #[cfg(test)]
            Self::Sim(link) => link
                .session_connection(peer)
                .map(super::SessionConnection::Sim),
        }
    }

    pub(crate) async fn open_bi(
        &self,
        peer_id: &PeerId,
    ) -> Result<(super::StreamSend, super::StreamRecv), NodeError> {
        match self {
            Self::Quic(node) => {
                let (send, recv) = node.open_bi(peer_id).await?;
                Ok(super::stream::from_quic(send, recv))
            }
            #[cfg(test)]
            Self::Sim(link) => {
                let (send, recv) = link.open_bi(peer_id)?;
                Ok((super::StreamSend::Sim(send), super::StreamRecv::Sim(recv)))
            }
        }
    }

    pub(crate) async fn accept_bi(
        &self,
    ) -> Result<(PeerId, super::StreamSend, super::StreamRecv), NodeError> {
        match self {
            Self::Quic(node) => {
                let (peer, send, recv) = node.accept_bi().await?;
                let (send, recv) = super::stream::from_quic(send, recv);
                Ok((peer, send, recv))
            }
            #[cfg(test)]
            Self::Sim(link) => {
                let (peer, send, recv) = link.accept_bi().await?;
                Ok((
                    peer,
                    super::StreamSend::Sim(send),
                    super::StreamRecv::Sim(recv),
                ))
            }
        }
    }

    pub(crate) fn current_connection_generation(&self, peer: &PeerId) -> Option<u64> {
        match self {
            Self::Quic(node) => node.current_connection_generation(peer),
            #[cfg(test)]
            Self::Sim(link) => link.current_connection_generation(peer),
        }
    }

    pub(crate) async fn try_shutdown(self) -> Result<(), EndpointError> {
        match self {
            Self::Quic(node) => node.try_shutdown().await,
            #[cfg(test)]
            Self::Sim(link) => {
                link.shutdown();
                Ok(())
            }
        }
    }
}
