//! SOCKS5 listener and per-connection handler (ADR-0074 §3).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::identity::AgentId;

use super::auth::token_eq;
use super::config::SocksConfig;
use super::proto::{
    authenticate_userpass, negotiate_method, read_connect_request, resolve_x0x_host, write_reply,
    ProtoError, REP_HOST_UNREACHABLE, REP_NOT_ALLOWED, REP_SUCCEEDED,
};

/// Concurrent SOCKS sessions (handshake and bridge) admitted by one listener.
pub(crate) const MAX_SOCKS_SESSIONS: usize = 32;

/// Per-step cap for method negotiation, user/pass auth, and the CONNECT read.
/// Matches forward `HEADER_READ_TIMEOUT`.
const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(10);

const ACCEPT_LOOP_STOP_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Accept-loop task. Taken by [`SocksService::shutdown_and_wait`].
    accept_loop: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SocksService {
    /// Bind and spawn the accept loop.
    ///
    /// [`SocksConfig::validate`] runs before [`TcpListener::bind`]. A
    /// non-loopback `listen` returns [`std::io::ErrorKind::InvalidInput`] and
    /// does not bind. `listen == None` returns `InvalidInput` ("socks off").
    ///
    /// # Errors
    /// [`std::io::ErrorKind::InvalidInput`] when listen is unset or not
    /// loopback. Bind failure otherwise.
    pub async fn spawn(
        config: &SocksConfig,
        api_token: Arc<String>,
        connector: Arc<dyn SocksConnector>,
        parent_cancel: CancellationToken,
    ) -> std::io::Result<Self> {
        if let Err(err) = config.validate() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                err.to_string(),
            ));
        }
        let listen = config
            .listen
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "socks off"))?;
        let listener = TcpListener::bind(listen).await?;
        let cancel = parent_cancel.child_token();
        let denied = Arc::new(AtomicU64::new(0));
        let denied_task = Arc::clone(&denied);
        let cancel_task = cancel.clone();
        let sessions = Arc::new(tokio::sync::Semaphore::new(MAX_SOCKS_SESSIONS));
        let accept_loop = tokio::spawn(async move {
            accept_loop(
                listener,
                api_token,
                connector,
                cancel_task,
                denied_task,
                sessions,
            )
            .await;
        });
        Ok(Self {
            cancel,
            denied,
            accept_loop: Mutex::new(Some(accept_loop)),
        })
    }

    /// Count of CONNECT denials (`0x02`) observed since start.
    #[must_use]
    pub fn denied_count(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// Stop accepting. Idempotent. In-flight sessions observe the same token.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Cancel the listener, then wait for the accept loop to finish.
    ///
    /// After 2 seconds the accept-loop task is aborted and joined so the
    /// bound socket is released. Idempotent with [`Self::shutdown`].
    pub async fn shutdown_and_wait(&self) {
        self.shutdown();
        let handle = self
            .accept_loop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut handle) = handle else {
            return;
        };
        tokio::select! {
            _ = &mut handle => {}
            _ = tokio::time::sleep(ACCEPT_LOOP_STOP_TIMEOUT) => {
                handle.abort();
                let _ = handle.await;
            }
        }
    }
}

impl Drop for SocksService {
    fn drop(&mut self) {
        // Cancel only. Drop must not wait on the accept loop.
        self.shutdown();
    }
}

async fn accept_loop(
    listener: TcpListener,
    api_token: Arc<String>,
    connector: Arc<dyn SocksConnector>,
    cancel: CancellationToken,
    denied: Arc<AtomicU64>,
    sessions: Arc<tokio::sync::Semaphore>,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let Some(permit) = sessions.clone().try_acquire_owned().ok() else {
                            drop(stream);
                            continue;
                        };
                        let token = Arc::clone(&api_token);
                        let conn = Arc::clone(&connector);
                        let denied = Arc::clone(&denied);
                        let child = cancel.child_token();
                        tokio::spawn(async move {
                            let permit = permit;
                            let _ = handle_tcp_client(
                                stream,
                                &token,
                                conn.as_ref(),
                                &denied,
                                None,
                                &child,
                            )
                            .await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "x0x::socks", error = %e, "socks accept failed");
                        // Stay up after a transient accept error. Back off so a
                        // persistent error (for example EMFILE) does not spin.
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Full SOCKS5 session on a real `TcpStream` (production + integration tests).
///
/// Method negotiation, username/password auth, and the CONNECT read each race
/// `cancel` and a 10 second limit. Cancel or timeout returns an I/O error and
/// does not call [`SocksConnector::prepare`].
pub async fn handle_tcp_client(
    mut client: TcpStream,
    api_token: &str,
    connector: &dyn SocksConnector,
    denied: &AtomicU64,
    connect_attempted: Option<&AtomicBool>,
    cancel: &CancellationToken,
) -> Result<(), ProtoError> {
    let negotiated = handshake_step(cancel, negotiate_method(&mut client)).await?;
    if !negotiated {
        return Ok(());
    }
    let authed = handshake_step(
        cancel,
        authenticate_userpass(&mut client, |password| token_eq(password, api_token)),
    )
    .await?;
    if !authed {
        return Ok(());
    }

    let request = match handshake_step(cancel, read_connect_request(&mut client)).await? {
        Ok(req) => req,
        Err(rep) => {
            ensure_running(cancel)?;
            write_reply(&mut client, rep).await?;
            return Ok(());
        }
    };

    let peer = match resolve_x0x_host(&request.host) {
        Ok(id) => id,
        Err(rep) => {
            ensure_running(cancel)?;
            write_reply(&mut client, rep).await?;
            return Ok(());
        }
    };

    // Cancel before prepare and before every reply. `SocksTunnel::bridge` is
    // not cancel-safe to abort: the forward copy loop resets QUIC and TCP
    // only when it returns or its own guard fires. The bridge therefore runs
    // until the tunnel ends. Handshake reads above still end when `cancel` fires.
    ensure_running(cancel)?;
    if let Some(flag) = connect_attempted {
        flag.store(true, Ordering::SeqCst);
    }

    match connector.prepare(peer, request.port).await {
        Ok(tunnel) => {
            ensure_running(cancel)?;
            write_reply(&mut client, REP_SUCCEEDED).await?;
            tunnel.bridge(client).await;
            Ok(())
        }
        Err(SocksConnectError::NotAllowed) => {
            denied.fetch_add(1, Ordering::Relaxed);
            ensure_running(cancel)?;
            write_reply(&mut client, REP_NOT_ALLOWED).await?;
            Ok(())
        }
        Err(SocksConnectError::Unreachable) => {
            ensure_running(cancel)?;
            write_reply(&mut client, REP_HOST_UNREACHABLE).await?;
            Ok(())
        }
    }
}

async fn handshake_step<T>(
    cancel: &CancellationToken,
    step: impl std::future::Future<Output = Result<T, ProtoError>>,
) -> Result<T, ProtoError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancelled_err()),
        result = step => result,
        _ = tokio::time::sleep(HANDSHAKE_STEP_TIMEOUT) => Err(timed_out_err()),
    }
}

fn ensure_running(cancel: &CancellationToken) -> Result<(), ProtoError> {
    if cancel.is_cancelled() {
        Err(cancelled_err())
    } else {
        Ok(())
    }
}

fn cancelled_err() -> ProtoError {
    ProtoError::Io(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "socks handshake cancelled",
    ))
}

fn timed_out_err() -> ProtoError {
    ProtoError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "socks handshake timed out",
    ))
}
