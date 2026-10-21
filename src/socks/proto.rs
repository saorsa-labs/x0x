//! RFC 1928 / 1929 wire helpers (CONNECT-only SOCKS5).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 version byte.
pub const VER: u8 = 0x05;
/// RFC 1929 username/password sub-negotiation version.
pub const AUTH_VER: u8 = 0x01;
/// No authentication required (refused by x0x).
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Username/password (RFC 1929).
pub const METHOD_USER_PASS: u8 = 0x02;
/// No acceptable methods.
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// CONNECT command.
pub const CMD_CONNECT: u8 = 0x01;
/// BIND (unsupported).
pub const CMD_BIND: u8 = 0x02;
/// UDP ASSOCIATE (unsupported).
pub const CMD_UDP: u8 = 0x03;

/// IPv4 address type.
pub const ATYP_IPV4: u8 = 0x01;
/// Domain name address type.
pub const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 address type.
pub const ATYP_IPV6: u8 = 0x04;

/// Succeeded.
pub const REP_SUCCEEDED: u8 = 0x00;
/// Connection not allowed by ruleset (connect-gate denial).
pub const REP_NOT_ALLOWED: u8 = 0x02;
/// Host unreachable (unresolvable `.x0x` name).
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
/// Command not supported.
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
/// Address type not supported (raw IP — x0x is not an exit node).
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Parsed CONNECT destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

/// Errors while speaking SOCKS on the wire.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("socks io: {0}")]
    Io(#[from] std::io::Error),
    #[error("socks protocol: {0}")]
    Protocol(&'static str),
}

/// Negotiate methods: require USERNAME/PASSWORD; refuse NO AUTH with `0xFF`.
pub async fn negotiate_method<S>(stream: &mut S) -> Result<bool, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != VER {
        return Err(ProtoError::Protocol("bad socks version"));
    }
    let nmethods = hdr[1] as usize;
    if nmethods == 0 {
        return Err(ProtoError::Protocol("zero methods"));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Prefer USERNAME/PASSWORD. Any offer that does not include it,
    // including NO AUTH only, is refused with 0xFF before any CONNECT
    // (ADR-0074 Q7).
    if methods.contains(&METHOD_USER_PASS) {
        stream.write_all(&[VER, METHOD_USER_PASS]).await?;
        stream.flush().await?;
        Ok(true)
    } else {
        if methods.iter().all(|&method| method == METHOD_NO_AUTH) {
            tracing::debug!(target: "x0x::socks", "refusing NO AUTH");
        }
        stream.write_all(&[VER, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        Ok(false)
    }
}

/// RFC 1929 sub-negotiation. Returns `true` when the password matches.
pub async fn authenticate_userpass<S, F>(
    stream: &mut S,
    check_password: F,
) -> Result<bool, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    if ver[0] != AUTH_VER {
        return Err(ProtoError::Protocol("bad auth version"));
    }
    let mut ulen = [0u8; 1];
    stream.read_exact(&mut ulen).await?;
    // Username is ignored; the password is the API token.
    let username_len = usize::from(ulen[0]);
    if username_len > 0 {
        let mut username = vec![0u8; username_len];
        stream.read_exact(&mut username).await?;
    }
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut password = vec![0u8; plen[0] as usize];
    if !password.is_empty() {
        stream.read_exact(&mut password).await?;
    }
    let password =
        String::from_utf8(password).map_err(|_| ProtoError::Protocol("password not utf-8"))?;
    let ok = check_password(&password);
    let status = if ok { 0x00 } else { 0x01 };
    stream.write_all(&[AUTH_VER, status]).await?;
    stream.flush().await?;
    Ok(ok)
}

/// Read a CONNECT request. Returns the request or a reply code to send.
pub async fn read_connect_request<S>(
    stream: &mut S,
) -> Result<Result<ConnectRequest, u8>, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != VER {
        return Err(ProtoError::Protocol("bad request version"));
    }
    let cmd = hdr[1];
    let atyp = hdr[3];

    // BIND / UDP ASSOCIATE (and any unknown command) → 0x07.
    if cmd == CMD_BIND || cmd == CMD_UDP || cmd != CMD_CONNECT {
        consume_address(stream, atyp).await?;
        let _port = read_port(stream).await?;
        return Ok(Err(REP_CMD_NOT_SUPPORTED));
    }

    match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let _port = read_port(stream).await?;
            Ok(Err(REP_ATYP_NOT_SUPPORTED))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let _port = read_port(stream).await?;
            Ok(Err(REP_ATYP_NOT_SUPPORTED))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            if !host.is_empty() {
                stream.read_exact(&mut host).await?;
            }
            let port = read_port(stream).await?;
            let host =
                String::from_utf8(host).map_err(|_| ProtoError::Protocol("domain not utf-8"))?;
            Ok(Ok(ConnectRequest { host, port }))
        }
        _ => Ok(Err(REP_ATYP_NOT_SUPPORTED)),
    }
}

async fn consume_address<S: AsyncRead + Unpin>(stream: &mut S, atyp: u8) -> Result<(), ProtoError> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize];
            if !b.is_empty() {
                stream.read_exact(&mut b).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn read_port<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u16, ProtoError> {
    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

/// Write a SOCKS5 reply with a zeroed bound address (IPv4 0.0.0.0:0).
pub async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, rep: u8) -> Result<(), ProtoError> {
    // VER REP RSV ATYP IPv4 PORT
    let mut buf = [0u8; 10];
    buf[0] = VER;
    buf[1] = rep;
    buf[2] = 0x00;
    buf[3] = ATYP_IPV4;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Resolve a SOCKS DOMAINNAME ending in `.x0x` to an [`crate::identity::AgentId`].
///
/// Slice 4 accepts `<64-hex-agent-id>.x0x` (ADR: hex AgentId stays valid
/// everywhere). Named labels arrive with #1386.
pub fn resolve_x0x_host(host: &str) -> Result<crate::identity::AgentId, u8> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !host.ends_with(".x0x") {
        return Err(REP_HOST_UNREACHABLE);
    }
    let label = host.trim_end_matches(".x0x");
    // Empty (".x0x") and dotted names (studio.machine.me.x0x) are not a hex AgentId.
    if label.is_empty() || label.contains('.') {
        return Err(REP_HOST_UNREACHABLE);
    }
    crate::exec::acl::parse_agent_id(label).map_err(|_| REP_HOST_UNREACHABLE)
}
