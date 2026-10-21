//! Production [`SocksConnector`] over [`crate::forward::ForwardService`].

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::forward::{ForwardService, PrepareSocksError, PreparedSocksTunnel};
use crate::identity::AgentId;

use super::service::{SocksConnectError, SocksConnector, SocksTunnel};

/// Bridges SOCKS CONNECTs through the daemon's [`ForwardService`].
pub struct ForwardSocksConnector {
    forward: Arc<ForwardService>,
}

impl ForwardSocksConnector {
    #[must_use]
    pub fn new(forward: Arc<ForwardService>) -> Self {
        Self { forward }
    }
}

struct Tunnel(PreparedSocksTunnel);

#[async_trait]
impl SocksTunnel for Tunnel {
    async fn bridge(self: Box<Self>, client: TcpStream) {
        self.0.bridge(client).await;
    }
}

#[async_trait]
impl SocksConnector for ForwardSocksConnector {
    async fn prepare(
        &self,
        peer: AgentId,
        target_port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError> {
        match self.forward.prepare_socks_tunnel(&peer, target_port).await {
            Ok(prepared) => Ok(Box::new(Tunnel(prepared))),
            Err(PrepareSocksError::Denied) => Err(SocksConnectError::NotAllowed),
            Err(PrepareSocksError::Failed) => Err(SocksConnectError::Unreachable),
        }
    }
}
