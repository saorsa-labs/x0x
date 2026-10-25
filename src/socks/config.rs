//! `[socks]` daemon config — loopback-only listen address (ADR-0074 §3 Q6).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::connect::is_loopback;

/// Optional SOCKS5 listener configuration (TOML `[socks]`).
///
/// Absent or `listen` unset ⇒ listener off. A non-loopback `listen` is a
/// hard load error (the loader refuses to start).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksConfig {
    /// Bind address for the SOCKS5 listener. Must be loopback when set.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

/// Why a `[socks]` section was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SocksConfigError {
    /// `listen` was not a loopback address.
    #[error(
        "socks listen address {addr} is not loopback; bind only 127.0.0.0/8 or ::1 \
         (ADR-0074 §3)"
    )]
    NonLoopback { addr: SocketAddr },
}

impl SocksConfig {
    /// Validate the listen address. `None` is always valid (listener off).
    ///
    /// # Errors
    /// [`SocksConfigError::NonLoopback`] when `listen` is set and not loopback.
    pub fn validate(&self) -> Result<(), SocksConfigError> {
        if let Some(addr) = self.listen {
            if !is_loopback(addr.ip()) {
                return Err(SocksConfigError::NonLoopback { addr });
            }
        }
        Ok(())
    }

    /// Whether the SOCKS listener should start.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.listen.is_some()
    }
}
