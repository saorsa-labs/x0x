//! SOCKS5 listener and per-connection handler (ADR-0074 §3).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::identity::AgentId;

use super::auth::token_eq;
use super::config::SocksConfig;
use super::proto::{
    authenticate_userpass, negotiate_method, read_connect_request, resolve_x0x_host, write_reply,
    ProtoError, REP_HOST_UNREACHABLE, REP_NOT_ALLOWED, REP_SUCCEEDED,
};

/// Why a SOCKS CONNECT could not open a peer tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksConnectError {
    /// Peer connect gate denied the target — map to SOCKS `0x02`.
    /// Zero bytes must have reached the target.
    NotAllowed,
    /// Peer unreachable / stream open failed — map to `0x04`.
    Unreachable,
}

/// A prepared peer tunnel ready to bridge after the SOCKS success reply.
#[async_trait]
pub trait SocksTunnel: Send {
    /// Bridge `client` to the peer stream until either side closes.
    async fn bridge(self: Box<Self>, client: TcpStream);
}

/// Opens a ForwardV2 tunnel for an authenticated SOCKS CONNECT.
///
/// [`SocksConnector::prepare`] must not deliver any bytes to the remote
/// loopback target until the peer's connect gate allows. A
/// [`SocksConnectError::NotAllowed`] means the target received zero bytes.
#[async_trait]
pub trait SocksConnector: Send + Sync {
    async fn prepare(
        &self,
        peer: AgentId,
        target_port: u16,
    ) -> Result<Box<dyn SocksTunnel>, SocksConnectError>;
}

/// Running SOCKS5 listener handle.
pub struct SocksService {
    cancel: CancellationToken,
    /// CONNECTs refused by ruleset (`0x02`).
    denied: Arc<AtomicU64>,
}

impl SocksService {
    /// Bind and spawn the accept loop. `config.listen` must already be validated.
    ///
    /// # Errors
    /// Bind failure.
    pub async fn spawn(
        config: &SocksConfig,
        api_token: Arc<String>,
        connector: Arc<dyn SocksConnector>,
        parent_cancel: CancellationToken,
    ) -> std::io::Result<Self> {
        let listen = config
            .listen
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "socks off"))?;
        let listener = TcpListener::bind(listen).await?;
        let cancel = parent_cancel.child_token();
        let denied = Arc::new(AtomicU64::new(0));
        let denied_task = Arc::clone(&denied);
        let cancel_task = cancel.clone();
        tokio::spawn(async move {
            accept_loop(listener, api_token, connector, cancel_task, denied_task).await;
        });
        Ok(Self { cancel, denied })
    }

    /// Count of CONNECT denials (`0x02`) observed since start.
    #[must_use]
    pub fn denied_count(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// Stop accepting.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

async fn accept_loop(
    listener: TcpListener,
    api_token: Arc<String>,
    connector: Arc<dyn SocksConnector>,
    cancel: CancellationToken,
    denied: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let token = Arc::clone(&api_token);
                        let conn = Arc::clone(&connector);
                        let denied = Arc::clone(&denied);
                        let child = cancel.child_token();
                        tokio::spawn(async move {
                            let _ = handle_tcp_client(stream, &token, conn.as_ref(), &denied, None).await;
                            drop(child);
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "x0x::socks", error = %e, "socks accept failed");
                        break;
                    }
                }
            }
        }
    }
}

/// Full SOCKS5 session on a real `TcpStream` (production + integration tests).
pub async fn handle_tcp_client(
    mut client: TcpStream,
    api_token: &str,
    connector: &dyn SocksConnector,
    denied: &AtomicU64,
    connect_attempted: Option<&AtomicBool>,
) -> Result<(), ProtoError> {
    if !negotiate_method(&mut client).await? {
        return Ok(());
    }
    let authed =
        authenticate_userpass(&mut client, |password| token_eq(password, api_token)).await?;
    if !authed {
        return Ok(());
    }

    let request = match read_connect_request(&mut client).await? {
        Ok(req) => req,
        Err(rep) => {
            write_reply(&mut client, rep).await?;
            return Ok(());
        }
    };

    let peer = match resolve_x0x_host(&request.host) {
        Ok(id) => id,
        Err(rep) => {
            write_reply(&mut client, rep).await?;
            return Ok(());
        }
    };

    if let Some(flag) = connect_attempted {
        flag.store(true, Ordering::SeqCst);
    }

    match connector.prepare(peer, request.port).await {
        Ok(tunnel) => {
            write_reply(&mut client, REP_SUCCEEDED).await?;
            tunnel.bridge(client).await;
            Ok(())
        }
        Err(SocksConnectError::NotAllowed) => {
            denied.fetch_add(1, Ordering::Relaxed);
            write_reply(&mut client, REP_NOT_ALLOWED).await?;
            Ok(())
        }
        Err(SocksConnectError::Unreachable) => {
            write_reply(&mut client, REP_HOST_UNREACHABLE).await?;
            Ok(())
        }
    }
}

/// Protocol-only session for unit tests (any `AsyncRead + AsyncWrite`).
///
/// `prepare` is invoked only after successful auth + `.x0x` resolve. Returning
/// `NotAllowed` writes `0x02` and must mean zero target bytes.
pub async fn handle_stream_session<S, F, Fut>(
    stream: &mut S,
    api_token: &str,
    prepare: F,
    connect_attempted: Option<&AtomicBool>,
) -> Result<u8, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(AgentId, u16) -> Fut,
    Fut: std::future::Future<Output = Result<(), SocksConnectError>>,
{
    if !negotiate_method(stream).await? {
        return Ok(0xFF);
    }
    let authed = authenticate_userpass(stream, |password| token_eq(password, api_token)).await?;
    if !authed {
        return Ok(0x01); // auth failure status already written
    }

    let request = match read_connect_request(stream).await? {
        Ok(req) => req,
        Err(rep) => {
            write_reply(stream, rep).await?;
            return Ok(rep);
        }
    };

    let peer = match resolve_x0x_host(&request.host) {
        Ok(id) => id,
        Err(rep) => {
            write_reply(stream, rep).await?;
            return Ok(rep);
        }
    };

    if let Some(flag) = connect_attempted {
        flag.store(true, Ordering::SeqCst);
    }

    match prepare(peer, request.port).await {
        Ok(()) => {
            write_reply(stream, REP_SUCCEEDED).await?;
            Ok(REP_SUCCEEDED)
        }
        Err(SocksConnectError::NotAllowed) => {
            write_reply(stream, REP_NOT_ALLOWED).await?;
            Ok(REP_NOT_ALLOWED)
        }
        Err(SocksConnectError::Unreachable) => {
            write_reply(stream, REP_HOST_UNREACHABLE).await?;
            Ok(REP_HOST_UNREACHABLE)
        }
    }
}
