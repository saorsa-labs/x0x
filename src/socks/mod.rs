//! SOCKS5 front-end for tailnet forwards (ADR-0074 §3 / #1389).
//!
//! Optional loopback-only listener (`[socks] listen = "127.0.0.1:1080"`).
//! Off until configured. Clients must use RFC 1929 username/password with
//! the daemon API token as the password; `NO AUTH` is refused (`0xFF`).
//!
//! `CONNECT` to `<name>.x0x:P` opens a `ForwardV2` stream to `127.0.0.1:P`
//! on the resolved peer. A connect-gate denial maps to SOCKS reply `0x02`
//! with zero bytes sent to the target. This slice accepts hex `AgentId`
//! hostnames (`<64-hex>.x0x`); named labels land with #1386.

mod auth;
mod config;
mod forward_bridge;
mod proto;
mod service;

pub use config::{SocksConfig, SocksConfigError};
pub use forward_bridge::ForwardSocksConnector;
pub use service::{
    handle_stream_session, handle_tcp_client, SocksConnectError, SocksConnector, SocksService,
    SocksTunnel,
};

#[cfg(test)]
mod tests;
