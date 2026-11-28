//! Opt-in outbound signed webhook push for inbound x0x events.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use rand::Rng;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate as x0x;
use crate::groups::{
    public_topic_for, GroupConfidentiality, GroupPublicMessage, GroupPublicMessageKind,
};
use crate::history::{classify::DmPayloadClass, Direction, HistoryQuery, Provenance, Scope};
use crate::profile::CertMode;

use super::delivery_gate;
use super::state::AppState;
use super::ws::MentionFrame;

const WEBHOOK_STATE_DB_NAME: &str = "webhook_state.db";
const DEDUPE_TTL_SECS: i64 = 7 * 86_400;
const DM_DEDUPE_WINDOW_MS: i64 = 60_000;
const DEDUPE_BACKFILL_MARGIN_MS: i64 = 60_000;
const BACKFILL_OVERLAP_MS: i64 = 2_000;
const DEDUPE_PRUNE_INTERVAL_SECS: i64 = 3_600;
const MAX_QUEUE_ITEMS: usize = 512;
const MAX_BATCH_ITEMS: usize = 100;
const MENTION_TEE_CAPACITY: usize = 256;
const PUBLIC_MSG_TEE_CAPACITY: usize = 256;
const DM_BACKFILL_LIMIT: usize = 200;
const GROUP_BACKFILL_LIMIT: usize = 200;
const MAX_4XX_ATTEMPTS: u32 = 3;
pub(crate) const MAX_RETRYABLE_ATTEMPTS: u32 = 24;
const BACKOFF_MIN_MS: u64 = 2_000;
const BACKOFF_MAX_MS: u64 = 300_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(2);
const ABORT_DRAIN_GRACE: Duration = Duration::from_millis(500);
const DEFAULT_FAST_WINDOW_MS: u64 = 5_000;
const DEFAULT_BATCH_WINDOW_MS: u64 = 60_000;
const DEFAULT_MAX_PER_HOUR: u32 = 6;
const DEFAULT_MAX_PER_DAY: u32 = 60;
const DEFAULT_MAX_TEXT_CHARS: usize = 2_000;

/// `[notify]` TOML section holding opt-in outbound notification sinks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Outbound signed HTTP webhook targets (`[[notify.webhook]]`).
    #[serde(default)]
    pub webhook: Vec<WebhookConfig>,
}

/// Payload body verbosity mode for outbound webhook notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookBodyMode {
    /// Include message text truncated to `max_text_chars`.
    #[default]
    Full,
    /// Omit message text from every item.
    Metadata,
}

/// Configuration for a single `[[notify.webhook]]` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique name identifying this webhook in payloads and diagnostics.
    pub name: String,
    /// Destination URL (must be `https://`).
    pub url: String,
    /// Optional explicit host allowlist; destination host must match when non-empty.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Optional path to a `0600` file containing the `Authorization: Bearer` token.
    #[serde(default)]
    pub bearer_token_file: Option<PathBuf>,
    /// Optional path to a `0600` file containing the `X-X0x-Signature` HMAC secret.
    #[serde(default)]
    pub signing_secret_file: Option<PathBuf>,
    /// Event selectors (`dm`, `mention`, `group:<group_id>`, `topic:<topic>`).
    #[serde(default)]
    pub events: Vec<String>,
    /// Optional 64-hex sender allowlist; when non-empty, only verified DMs from listed senders are delivered.
    #[serde(default)]
    pub dm_allowlist: Vec<String>,
    /// Coalescing window in milliseconds for fast-lane items (verified DMs, mentions).
    #[serde(default = "default_fast_window_ms")]
    pub fast_window_ms: u64,
    /// Coalescing window in milliseconds for batched items (groups, topics).
    #[serde(default = "default_batch_window_ms")]
    pub batch_window_ms: u64,
    /// Hard maximum number of POST requests per rolling hour.
    #[serde(default = "default_max_per_hour")]
    pub max_per_hour: u32,
    /// Hard maximum number of POST requests per rolling 24 hours.
    #[serde(default = "default_max_per_day")]
    pub max_per_day: u32,
    /// Whether to include truncated message text (`full`) or omit it (`metadata`).
    #[serde(default)]
    pub body_mode: WebhookBodyMode,
    /// Maximum Unicode scalar characters retained in `text` under `full` mode.
    #[serde(default = "default_max_text_chars")]
    pub max_text_chars: usize,
    #[cfg(test)]
    #[serde(skip)]
    pub(crate) allow_insecure_loopback_for_test: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            allowed_hosts: Vec::new(),
            bearer_token_file: None,
            signing_secret_file: None,
            events: Vec::new(),
            dm_allowlist: Vec::new(),
            fast_window_ms: default_fast_window_ms(),
            batch_window_ms: default_batch_window_ms(),
            max_per_hour: default_max_per_hour(),
            max_per_day: default_max_per_day(),
            body_mode: WebhookBodyMode::Full,
            max_text_chars: default_max_text_chars(),
            #[cfg(test)]
            allow_insecure_loopback_for_test: false,
        }
    }
}

fn default_fast_window_ms() -> u64 {
    DEFAULT_FAST_WINDOW_MS
}

fn default_batch_window_ms() -> u64 {
    DEFAULT_BATCH_WINDOW_MS
}

fn default_max_per_hour() -> u32 {
    DEFAULT_MAX_PER_HOUR
}

fn default_max_per_day() -> u32 {
    DEFAULT_MAX_PER_DAY
}

fn default_max_text_chars() -> usize {
    DEFAULT_MAX_TEXT_CHARS
}

/// Typed validation and secret-loading errors for a webhook configuration entry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WebhookConfigError {
    #[error("webhook name must not be empty")]
    EmptyName,
    #[error("duplicate webhook name `{0}`")]
    DuplicateName(String),
    #[error("invalid webhook url: {0}")]
    InvalidUrl(String),
    #[error("webhook url must use https scheme")]
    NonHttpsUrl,
    #[error("webhook url must not include userinfo")]
    UrlContainsCredentials,
    #[error("webhook url is missing a host")]
    MissingHost,
    #[error("webhook host `{0}` is not in allowed_hosts")]
    HostNotAllowed(String),
    #[error("webhook target ip `{0}` is blocked by SSRF policy")]
    BlockedIp(IpAddr),
    #[error("invalid event selector `{0}`")]
    InvalidEvent(String),
    #[error("invalid dm_allowlist agent id `{0}` (expected 64 hex chars)")]
    InvalidAllowlistEntry(String),
    #[error("max_per_hour and max_per_day must both be >= 1")]
    InvalidRateCap,
    #[error("secret file `{field}` unreadable at `{path}`: {source}")]
    SecretFileUnreadable {
        field: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("secret file `{field}` at `{path}` is not a regular file")]
    SecretNotRegularFile { field: &'static str, path: PathBuf },
    #[error("secret file `{field}` at `{path}` has insecure permissions (must not be group/world accessible)")]
    InsecureSecretPermissions { field: &'static str, path: PathBuf },
    #[error("secret file `{field}` at `{path}` is empty after trimming whitespace")]
    EmptySecretFile { field: &'static str, path: PathBuf },
    #[error("bearer_token_file `{path}` contains invalid HTTP header bytes")]
    InvalidBearerToken { path: PathBuf },
}

#[derive(Clone)]
struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
    sha256_prefix: String,
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl SecretBytes {
    fn from_raw(mut raw: Vec<u8>) -> Option<Self> {
        while raw
            .last()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            raw.pop();
        }
        if raw.is_empty() {
            return None;
        }
        let digest = Sha256::digest(&raw);
        let sha256_prefix = hex::encode(&digest[..4]);
        Some(Self {
            bytes: Zeroizing::new(raw),
            sha256_prefix,
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn sha256_prefix(&self) -> &str {
        &self.sha256_prefix
    }
}

fn load_secret_file(field: &'static str, path: &Path) -> Result<SecretBytes, WebhookConfigError> {
    let mut file =
        std::fs::File::open(path).map_err(|source| WebhookConfigError::SecretFileUnreadable {
            field,
            path: path.to_path_buf(),
            source,
        })?;
    let meta = file
        .metadata()
        .map_err(|source| WebhookConfigError::SecretFileUnreadable {
            field,
            path: path.to_path_buf(),
            source,
        })?;
    if !meta.is_file() {
        return Err(WebhookConfigError::SecretNotRegularFile {
            field,
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(WebhookConfigError::InsecureSecretPermissions {
                field,
                path: path.to_path_buf(),
            });
        }
    }
    let mut raw = Zeroizing::new(Vec::new());
    file.read_to_end(&mut raw)
        .map_err(|source| WebhookConfigError::SecretFileUnreadable {
            field,
            path: path.to_path_buf(),
            source,
        })?;
    let owned = std::mem::take(&mut *raw);
    SecretBytes::from_raw(owned).ok_or_else(|| WebhookConfigError::EmptySecretFile {
        field,
        path: path.to_path_buf(),
    })
}

fn load_bearer_token(path: &Path) -> Result<SecretBytes, WebhookConfigError> {
    let secret = load_secret_file("bearer_token_file", path)?;
    let token_str = std::str::from_utf8(secret.as_bytes()).map_err(|_| {
        WebhookConfigError::InvalidBearerToken {
            path: path.to_path_buf(),
        }
    })?;
    let header_text = Zeroizing::new(format!("Bearer {token_str}"));
    if HeaderValue::from_str(&header_text).is_err() {
        return Err(WebhookConfigError::InvalidBearerToken {
            path: path.to_path_buf(),
        });
    }
    Ok(secret)
}

/// RFC 2104 HMAC-SHA256 over `sha2::Sha256`.
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k_pad = Zeroizing::new([0u8; BLOCK_SIZE]);
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        k_pad[..32].copy_from_slice(&hashed);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0u8; BLOCK_SIZE]);
    let mut opad = Zeroizing::new([0u8; BLOCK_SIZE]);
    for i in 0..BLOCK_SIZE {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(*ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(*opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Build the `X-X0x-Signature` header value for a timestamp and raw body.
pub(crate) fn sign_payload(secret: &[u8], timestamp_secs: u64, raw_body: &[u8]) -> String {
    let prefix = format!("{timestamp_secs}.");
    let mut signed = Vec::with_capacity(prefix.len() + raw_body.len());
    signed.extend_from_slice(prefix.as_bytes());
    signed.extend_from_slice(raw_body);
    let mac = hmac_sha256(secret, &signed);
    format!("t={timestamp_secs},v1={}", hex::encode(mac))
}

fn is_ipv4_ssrf_blocked(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240
}

fn is_ipv6_ssrf_blocked(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_ipv4_ssrf_blocked(v4);
    }
    let segs = ip.segments();
    if segs[0] == 0x0064
        && segs[1] == 0xff9b
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        let v4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return is_ipv4_ssrf_blocked(v4);
    }
    if segs[0..6] == [0, 0, 0, 0, 0, 0] && (segs[6] != 0 || segs[7] > 1) {
        let v4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return is_ipv4_ssrf_blocked(v4);
    }
    // 6to4 (2002::/16) embeds an IPv4 address in segments 1..=2.
    if segs[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        );
        return is_ipv4_ssrf_blocked(v4);
    }
    // Teredo (2001:0000::/32) embeds server IPv4 in segments 2..=3 and inverted client IPv4 in 6..=7.
    if segs[0] == 0x2001 && segs[1] == 0x0000 {
        let server_v4 = Ipv4Addr::new(
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
            (segs[3] >> 8) as u8,
            (segs[3] & 0xff) as u8,
        );
        let client_v4 = Ipv4Addr::new(
            !((segs[6] >> 8) as u8),
            !((segs[6] & 0xff) as u8),
            !((segs[7] >> 8) as u8),
            !((segs[7] & 0xff) as u8),
        );
        return is_ipv4_ssrf_blocked(server_v4) || is_ipv4_ssrf_blocked(client_v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segs[0] & 0xfe00) == 0xfc00
        || (segs[0] & 0xffc0) == 0xfe80
        || (segs[0] & 0xffc0) == 0xfec0
        || (segs[0] == 0x2001 && segs[1] == 0x0db8)
        || (segs[0] == 0x2001 && segs[1] == 0x0002 && segs[2] == 0)
        || (segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001)
        || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
}

/// Returns `true` if connecting to `ip` must be refused by SSRF policy.
pub(crate) fn is_ip_ssrf_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_ipv4_ssrf_blocked(v4),
        IpAddr::V6(v6) => is_ipv6_ssrf_blocked(v6),
    }
}

fn check_ip_allowed(ip: IpAddr, allow_loopback_for_test: bool) -> Result<(), WebhookConfigError> {
    if allow_loopback_for_test && ip.is_loopback() {
        return Ok(());
    }
    if is_ip_ssrf_blocked(ip) {
        return Err(WebhookConfigError::BlockedIp(ip));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_ssrf_resolver(allow_loopback_for_test: bool) -> impl Resolve {
    SsrfCheckedResolver {
        allow_loopback_for_test,
    }
}

struct SsrfCheckedResolver {
    allow_loopback_for_test: bool,
}

impl Resolve for SsrfCheckedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow_loopback_for_test = self.allow_loopback_for_test;
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .collect();
            if resolved.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "DNS returned no addresses",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            for addr in &resolved {
                if let Err(err) = check_ip_allowed(addr.ip(), allow_loopback_for_test) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        err.to_string(),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
            }
            let addrs: Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventFilter {
    Dm,
    Mention,
    Group(String),
    Topic(String),
}

fn parse_event_filter(raw: &str) -> Result<EventFilter, WebhookConfigError> {
    if raw == "dm" {
        return Ok(EventFilter::Dm);
    }
    if raw == "mention" {
        return Ok(EventFilter::Mention);
    }
    if let Some(gid) = raw.strip_prefix("group:") {
        if !gid.is_empty() {
            return Ok(EventFilter::Group(gid.to_string()));
        }
    }
    if let Some(topic) = raw.strip_prefix("topic:") {
        if !topic.is_empty() {
            return Ok(EventFilter::Topic(topic.to_string()));
        }
    }
    Err(WebhookConfigError::InvalidEvent(raw.to_string()))
}

fn is_hex_agent_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug)]
pub(crate) struct ValidatedWebhook {
    pub(crate) name: String,
    pub(crate) url: reqwest::Url,
    pub(crate) url_host: String,
    bearer_token: Option<SecretBytes>,
    signing_secret: Option<SecretBytes>,
    events: Vec<EventFilter>,
    dm_allowlist: HashSet<String>,
    fast_window_ms: u64,
    batch_window_ms: u64,
    max_per_hour: u32,
    max_per_day: u32,
    body_mode: WebhookBodyMode,
    max_text_chars: usize,
    allow_insecure_loopback_for_test: bool,
}

impl ValidatedWebhook {
    pub(crate) fn validate(cfg: &WebhookConfig) -> Result<Self, WebhookConfigError> {
        let name = cfg.name.trim().to_string();
        if name.is_empty() {
            return Err(WebhookConfigError::EmptyName);
        }
        #[cfg(test)]
        let allow_test_loopback = cfg.allow_insecure_loopback_for_test;
        #[cfg(not(test))]
        let allow_test_loopback = false;

        let url = reqwest::Url::parse(&cfg.url)
            .map_err(|e| WebhookConfigError::InvalidUrl(e.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(WebhookConfigError::UrlContainsCredentials);
        }
        let raw_host = url.host_str().ok_or(WebhookConfigError::MissingHost)?;
        let url_host = normalize_host(raw_host);
        if url_host.is_empty() {
            return Err(WebhookConfigError::MissingHost);
        }

        let scheme_ok = url.scheme() == "https"
            || (allow_test_loopback
                && url.scheme() == "http"
                && (url_host == "localhost"
                    || url_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())));
        if !scheme_ok {
            return Err(WebhookConfigError::NonHttpsUrl);
        }

        if let Ok(ip) = url_host.parse::<IpAddr>() {
            check_ip_allowed(ip, allow_test_loopback)?;
        }

        if !cfg.allowed_hosts.is_empty() {
            let matched = cfg
                .allowed_hosts
                .iter()
                .any(|allowed| normalize_host(allowed) == url_host);
            if !matched {
                return Err(WebhookConfigError::HostNotAllowed(url_host));
            }
        }

        if cfg.max_per_hour == 0 || cfg.max_per_day == 0 {
            return Err(WebhookConfigError::InvalidRateCap);
        }

        let mut events = Vec::with_capacity(cfg.events.len());
        for raw in &cfg.events {
            events.push(parse_event_filter(raw)?);
        }

        let mut dm_allowlist = HashSet::with_capacity(cfg.dm_allowlist.len());
        for id in &cfg.dm_allowlist {
            let trimmed = id.trim();
            if !is_hex_agent_id(trimmed) {
                return Err(WebhookConfigError::InvalidAllowlistEntry(id.clone()));
            }
            dm_allowlist.insert(trimmed.to_ascii_lowercase());
        }

        let bearer_token = match &cfg.bearer_token_file {
            Some(path) => Some(load_bearer_token(path)?),
            None => None,
        };
        let signing_secret = match &cfg.signing_secret_file {
            Some(path) => Some(load_secret_file("signing_secret_file", path)?),
            None => None,
        };

        Ok(Self {
            name,
            url,
            url_host,
            bearer_token,
            signing_secret,
            events,
            dm_allowlist,
            fast_window_ms: cfg.fast_window_ms,
            batch_window_ms: cfg.batch_window_ms,
            max_per_hour: cfg.max_per_hour,
            max_per_day: cfg.max_per_day,
            body_mode: cfg.body_mode,
            max_text_chars: cfg.max_text_chars,
            allow_insecure_loopback_for_test: allow_test_loopback,
        })
    }

    fn wants_dm(&self) -> bool {
        self.events.iter().any(|e| matches!(e, EventFilter::Dm))
    }

    fn wants_mention(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, EventFilter::Mention))
    }

    fn group_ids(&self) -> Vec<String> {
        let mut out = Vec::new();
        for e in &self.events {
            if let EventFilter::Group(gid) = e {
                if !out.contains(gid) {
                    out.push(gid.clone());
                }
            }
        }
        out
    }

    fn topics(&self) -> Vec<String> {
        let mut out = Vec::new();
        for e in &self.events {
            if let EventFilter::Topic(t) = e {
                if !out.contains(t) {
                    out.push(t.clone());
                }
            }
        }
        out
    }

    fn build_http_client(&self) -> Result<reqwest::Client, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_TOTAL_TIMEOUT)
            .no_proxy()
            .dns_resolver(Arc::new(SsrfCheckedResolver {
                allow_loopback_for_test: self.allow_insecure_loopback_for_test,
            }));
        if !self.allow_insecure_loopback_for_test {
            builder = builder.https_only(true);
        }
        builder.build()
    }
}

/// Persistent SQLite dedupe store at `<data_dir>/webhook_state.db`.
pub(crate) struct WebhookDedupeStore {
    conn: rusqlite::Connection,
    last_prune_secs: i64,
}

impl WebhookDedupeStore {
    pub(crate) fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = rusqlite::Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS delivered_keys (
                 webhook_name TEXT NOT NULL,
                 dedupe_key TEXT NOT NULL,
                 delivered_at INTEGER NOT NULL,
                 PRIMARY KEY (webhook_name, dedupe_key)
             );
             CREATE INDEX IF NOT EXISTS idx_webhook_delivered_at
                 ON delivered_keys (delivered_at);
             CREATE TABLE IF NOT EXISTS webhook_meta (
                 webhook_name TEXT PRIMARY KEY,
                 cursor_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sent_log (
                 webhook_name TEXT NOT NULL,
                 sent_at_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_webhook_sent_log
                 ON sent_log (webhook_name, sent_at_ms);
             CREATE TABLE IF NOT EXISTS dm_deliveries (
                 webhook_name TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 receipt_ms INTEGER NOT NULL,
                 delivered_at INTEGER NOT NULL,
                 PRIMARY KEY (webhook_name, content_hash, receipt_ms)
             );
             CREATE INDEX IF NOT EXISTS idx_webhook_dm_delivered_at
                 ON dm_deliveries (delivered_at);",
        )?;
        let now_secs = unix_now_secs() as i64;
        let mut store = Self {
            conn,
            last_prune_secs: 0,
        };
        store.prune_expired(now_secs)?;
        Ok(store)
    }

    pub(crate) fn prune_expired(&mut self, now_secs: i64) -> Result<usize, rusqlite::Error> {
        let cutoff = now_secs.saturating_sub(DEDUPE_TTL_SECS);
        let deleted_keys = self.conn.execute(
            "DELETE FROM delivered_keys WHERE delivered_at < ?1",
            rusqlite::params![cutoff],
        )?;
        let deleted_dms = self.conn.execute(
            "DELETE FROM dm_deliveries WHERE delivered_at < ?1",
            rusqlite::params![cutoff],
        )?;
        let sent_cutoff_ms = now_secs.saturating_mul(1_000).saturating_sub(DAY_MS as i64);
        let _ = self.conn.execute(
            "DELETE FROM sent_log WHERE sent_at_ms < ?1",
            rusqlite::params![sent_cutoff_ms],
        )?;
        self.last_prune_secs = now_secs;
        Ok(deleted_keys + deleted_dms)
    }

    /// Return `(cursor_ms, is_first_enable)` for `webhook_name`.
    /// On first enable, persists `now_ms` so pre-enable history is never replayed.
    pub(crate) fn init_or_get_cursor_ms(
        &mut self,
        webhook_name: &str,
        now_ms: i64,
    ) -> Result<(i64, bool), rusqlite::Error> {
        let existing: Option<i64> = {
            let mut stmt = self
                .conn
                .prepare_cached("SELECT cursor_ms FROM webhook_meta WHERE webhook_name = ?1")?;
            match stmt.query_row(rusqlite::params![webhook_name], |row| row.get(0)) {
                Ok(val) => Some(val),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(err) => return Err(err),
            }
        };
        if let Some(cursor_ms) = existing {
            return Ok((cursor_ms, false));
        }
        self.conn.execute(
            "INSERT INTO webhook_meta (webhook_name, cursor_ms) VALUES (?1, ?2)",
            rusqlite::params![webhook_name, now_ms],
        )?;
        Ok((now_ms, true))
    }

    pub(crate) fn load_sent_timestamps(
        &self,
        webhook_name: &str,
        now_ms: i64,
    ) -> Result<Vec<u64>, rusqlite::Error> {
        let day_cutoff = now_ms.saturating_sub(DAY_MS as i64);
        let mut stmt = self.conn.prepare_cached(
            "SELECT sent_at_ms FROM sent_log
             WHERE webhook_name = ?1 AND sent_at_ms > ?2
             ORDER BY sent_at_ms ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![webhook_name, day_cutoff], |row| {
            row.get::<_, i64>(0)
        })?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(ts) = u64::try_from(row?) {
                out.push(ts);
            }
        }
        Ok(out)
    }

    pub(crate) fn record_sent(
        &mut self,
        webhook_name: &str,
        sent_at_ms: i64,
    ) -> Result<(), rusqlite::Error> {
        let day_cutoff = sent_at_ms.saturating_sub(DAY_MS as i64);
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO sent_log (webhook_name, sent_at_ms) VALUES (?1, ?2)",
            rusqlite::params![webhook_name, sent_at_ms],
        )?;
        tx.execute(
            "DELETE FROM sent_log WHERE webhook_name = ?1 AND sent_at_ms <= ?2",
            rusqlite::params![webhook_name, day_cutoff],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn is_dm_delivered(
        &self,
        webhook_name: &str,
        content_hash: &str,
        receipt_ms: i64,
        now_secs: i64,
    ) -> Result<bool, rusqlite::Error> {
        let cutoff = now_secs.saturating_sub(DEDUPE_TTL_SECS);
        let lo = receipt_ms.saturating_sub(DM_DEDUPE_WINDOW_MS);
        let hi = receipt_ms.saturating_add(DM_DEDUPE_WINDOW_MS);
        let mut stmt = self.conn.prepare_cached(
            "SELECT 1 FROM dm_deliveries
             WHERE webhook_name = ?1
               AND content_hash = ?2
               AND receipt_ms BETWEEN ?3 AND ?4
               AND delivered_at >= ?5
             LIMIT 1",
        )?;
        stmt.exists(rusqlite::params![
            webhook_name,
            content_hash,
            lo,
            hi,
            cutoff
        ])
    }

    pub(crate) fn is_delivered(
        &self,
        webhook_name: &str,
        dedupe_key: &str,
        now_secs: i64,
    ) -> Result<bool, rusqlite::Error> {
        if let Some((content_hash, receipt_ms)) = parse_dm_dedupe_key(dedupe_key) {
            return self.is_dm_delivered(webhook_name, content_hash, receipt_ms, now_secs);
        }
        let cutoff = now_secs.saturating_sub(DEDUPE_TTL_SECS);
        let mut stmt = self.conn.prepare_cached(
            "SELECT 1 FROM delivered_keys
             WHERE webhook_name = ?1 AND dedupe_key = ?2 AND delivered_at >= ?3
             LIMIT 1",
        )?;
        let exists = stmt.exists(rusqlite::params![webhook_name, dedupe_key, cutoff])?;
        Ok(exists)
    }

    #[cfg(test)]
    pub(crate) fn mark_delivered(
        &mut self,
        webhook_name: &str,
        keys: &[String],
        now_secs: i64,
    ) -> Result<(), rusqlite::Error> {
        self.mark_delivered_and_advance(webhook_name, keys, now_secs, None)
    }

    pub(crate) fn mark_delivered_and_advance(
        &mut self,
        webhook_name: &str,
        keys: &[String],
        now_secs: i64,
        advance_cursor_ms: Option<i64>,
    ) -> Result<(), rusqlite::Error> {
        if keys.is_empty() && advance_cursor_ms.is_none() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        if !keys.is_empty() {
            let mut key_stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO delivered_keys (webhook_name, dedupe_key, delivered_at)
                 VALUES (?1, ?2, ?3)",
            )?;
            let mut dm_stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO dm_deliveries
                 (webhook_name, content_hash, receipt_ms, delivered_at)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for key in keys {
                if let Some((content_hash, receipt_ms)) = parse_dm_dedupe_key(key) {
                    dm_stmt.execute(rusqlite::params![
                        webhook_name,
                        content_hash,
                        receipt_ms,
                        now_secs
                    ])?;
                } else {
                    key_stmt.execute(rusqlite::params![webhook_name, key, now_secs])?;
                }
            }
        }
        if let Some(cursor_ms) = advance_cursor_ms {
            tx.execute(
                "INSERT INTO webhook_meta (webhook_name, cursor_ms) VALUES (?1, ?2)
                 ON CONFLICT(webhook_name) DO UPDATE
                 SET cursor_ms = MAX(cursor_ms, excluded.cursor_ms)",
                rusqlite::params![webhook_name, cursor_ms],
            )?;
        }
        tx.commit()?;
        if now_secs.saturating_sub(self.last_prune_secs) >= DEDUPE_PRUNE_INTERVAL_SECS {
            let _ = self.prune_expired(now_secs);
        }
        Ok(())
    }
}

fn dm_content_hash(sender_hex: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sender_hex.to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

pub(crate) fn dm_dedupe_key(sender_hex: &str, receipt_ms: u64, payload: &[u8]) -> String {
    format!("dm:{}:{receipt_ms}", dm_content_hash(sender_hex, payload))
}

fn parse_dm_dedupe_key(key: &str) -> Option<(&str, i64)> {
    let rest = key.strip_prefix("dm:")?;
    let (content_hash, ts_str) = rest.split_once(':')?;
    if content_hash.len() != 64 {
        return None;
    }
    let receipt_ms = ts_str.parse::<i64>().ok()?;
    Some((content_hash, receipt_ms))
}

pub(crate) fn group_dedupe_key(author: &str, timestamp: u64, signature: &str) -> String {
    let sig_prefix = signature.get(..12).unwrap_or(signature);
    format!(
        "group:{}:{timestamp}:{sig_prefix}",
        author.to_ascii_lowercase()
    )
}

pub(crate) fn mention_dedupe_key(msg_id: &str) -> String {
    format!("mention:{msg_id}")
}

fn topic_dedupe_key(topic: &str, origin: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(topic.as_bytes());
    hasher.update(b"|");
    hasher.update(origin.to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(payload);
    format!("topic:{}", hex::encode(hasher.finalize()))
}

fn truncate_text(raw: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    raw.chars().take(max_chars).collect()
}

fn format_item_text(raw: &str, mode: WebhookBodyMode, max_text_chars: usize) -> Option<String> {
    match mode {
        WebhookBodyMode::Full => Some(truncate_text(raw, max_text_chars)),
        WebhookBodyMode::Metadata => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lane {
    Fast,
    Batch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WebhookPayloadItem {
    pub(crate) kind: String,
    pub(crate) from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) from_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) topic: Option<String>,
    pub(crate) ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) msg_id: Option<String>,
    pub(crate) flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct WebhookPostBody {
    pub(crate) source: String,
    pub(crate) version: u32,
    pub(crate) webhook: String,
    pub(crate) agent_id: String,
    pub(crate) batch_id: String,
    pub(crate) sent_at: u64,
    pub(crate) rate_limited: bool,
    pub(crate) items: Vec<WebhookPayloadItem>,
}

#[derive(Debug, Clone)]
pub(crate) struct QueuedWebhookItem {
    pub(crate) dedupe_key: String,
    pub(crate) lane: Lane,
    pub(crate) enqueued_at_ms: u64,
    pub(crate) item: WebhookPayloadItem,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingBatch {
    pub(crate) batch_id: String,
    pub(crate) items: Vec<QueuedWebhookItem>,
    pub(crate) rate_limited: bool,
    pub(crate) attempts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryOutcome {
    Success(u16),
    ClientError(u16),
    RetryableError(Option<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BatchDisposition {
    Committed {
        keys: Vec<String>,
        status: u16,
        max_enqueued_ms: Option<u64>,
    },
    RetryScheduled {
        retry_at_ms: u64,
        attempts: u32,
    },
    Dropped4xx {
        batch_id: String,
        status: u16,
        item_count: usize,
    },
    DroppedExpired {
        batch_id: String,
        last_status: Option<u16>,
        attempts: u32,
        item_count: usize,
    },
}

/// Pure virtual-clock scheduler for one webhook target.
pub(crate) struct WebhookScheduler {
    fast_window_ms: u64,
    batch_window_ms: u64,
    max_per_hour: u32,
    max_per_day: u32,
    max_queue_items: usize,
    fast_queue: VecDeque<QueuedWebhookItem>,
    batch_queue: VecDeque<QueuedWebhookItem>,
    queued_keys: HashSet<String>,
    fast_deadline_ms: Option<u64>,
    batch_deadline_ms: Option<u64>,
    sent_timestamps_ms: VecDeque<u64>,
    rate_limited_pending: bool,
    rate_limit_counted_for_hold: bool,
    in_flight: Option<PendingBatch>,
    retry_at_ms: Option<u64>,
}

impl WebhookScheduler {
    pub(crate) fn new(
        fast_window_ms: u64,
        batch_window_ms: u64,
        max_per_hour: u32,
        max_per_day: u32,
        max_queue_items: usize,
    ) -> Self {
        Self {
            fast_window_ms,
            batch_window_ms,
            max_per_hour,
            max_per_day,
            max_queue_items: max_queue_items.max(1),
            fast_queue: VecDeque::new(),
            batch_queue: VecDeque::new(),
            queued_keys: HashSet::new(),
            fast_deadline_ms: None,
            batch_deadline_ms: None,
            sent_timestamps_ms: VecDeque::new(),
            rate_limited_pending: false,
            rate_limit_counted_for_hold: false,
            in_flight: None,
            retry_at_ms: None,
        }
    }

    pub(crate) fn seed_sent_timestamps(
        &mut self,
        timestamps_ms: impl IntoIterator<Item = u64>,
        now_ms: u64,
    ) {
        let day_cutoff = now_ms.saturating_sub(DAY_MS);
        let mut ts: Vec<u64> = timestamps_ms
            .into_iter()
            .filter(|&t| t > day_cutoff)
            .collect();
        ts.sort_unstable();
        self.sent_timestamps_ms = VecDeque::from(ts);
    }

    pub(crate) fn queue_depth(&self) -> usize {
        self.fast_queue.len()
            + self.batch_queue.len()
            + self.in_flight.as_ref().map_or(0, |b| b.items.len())
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.queued_keys.contains(key)
    }

    /// Enqueue an item. Returns `false` if dropped because the queue was full.
    pub(crate) fn enqueue(&mut self, item: QueuedWebhookItem, now_ms: u64) -> bool {
        if self.queued_keys.contains(&item.dedupe_key) {
            return true;
        }
        if let Some((content_hash, receipt_ms)) = parse_dm_dedupe_key(&item.dedupe_key) {
            let dup_dm = self.queued_keys.iter().any(|existing| {
                parse_dm_dedupe_key(existing).is_some_and(|(h, existing_ms)| {
                    h == content_hash
                        && existing_ms.abs_diff(receipt_ms) <= DM_DEDUPE_WINDOW_MS as u64
                })
            });
            if dup_dm {
                return true;
            }
        }
        let current_queued = self.fast_queue.len() + self.batch_queue.len();
        if current_queued >= self.max_queue_items {
            if item.lane == Lane::Fast {
                if let Some(evicted) = self.batch_queue.pop_front() {
                    self.queued_keys.remove(&evicted.dedupe_key);
                    if self.batch_queue.is_empty() {
                        self.batch_deadline_ms = None;
                    }
                    self.queued_keys.insert(item.dedupe_key.clone());
                    let was_empty = self.fast_queue.is_empty();
                    self.fast_queue.push_back(item);
                    if was_empty {
                        self.fast_deadline_ms = Some(now_ms.saturating_add(self.fast_window_ms));
                    }
                    return false;
                }
            }
            return false;
        }
        self.queued_keys.insert(item.dedupe_key.clone());
        match item.lane {
            Lane::Fast => {
                let was_empty = self.fast_queue.is_empty();
                self.fast_queue.push_back(item);
                if was_empty {
                    self.fast_deadline_ms = Some(now_ms.saturating_add(self.fast_window_ms));
                }
            }
            Lane::Batch => {
                let was_empty = self.batch_queue.is_empty();
                self.batch_queue.push_back(item);
                if was_empty {
                    self.batch_deadline_ms = Some(now_ms.saturating_add(self.batch_window_ms));
                }
            }
        }
        true
    }

    fn prune_rate_window(&mut self, now_ms: u64) {
        let day_cutoff = now_ms.saturating_sub(DAY_MS);
        while self
            .sent_timestamps_ms
            .front()
            .is_some_and(|&t| t <= day_cutoff)
        {
            self.sent_timestamps_ms.pop_front();
        }
    }

    fn next_rate_allowed_ms(&mut self, now_ms: u64) -> Option<u64> {
        self.prune_rate_window(now_ms);
        let hour_cutoff = now_ms.saturating_sub(HOUR_MS);
        let hour_timestamps: Vec<u64> = self
            .sent_timestamps_ms
            .iter()
            .copied()
            .filter(|&t| t > hour_cutoff)
            .collect();
        let mut wait_until: Option<u64> = None;
        if hour_timestamps.len() >= self.max_per_hour as usize {
            if let Some(&oldest_hour) = hour_timestamps.first() {
                let target = oldest_hour.saturating_add(HOUR_MS);
                wait_until = Some(wait_until.map_or(target, |w| w.max(target)));
            }
        }
        if self.sent_timestamps_ms.len() >= self.max_per_day as usize {
            if let Some(&oldest_day) = self.sent_timestamps_ms.front() {
                let target = oldest_day.saturating_add(DAY_MS);
                wait_until = Some(wait_until.map_or(target, |w| w.max(target)));
            }
        }
        wait_until.filter(|&t| t > now_ms)
    }

    pub(crate) fn next_wakeup_ms(&mut self, now_ms: u64) -> Option<u64> {
        if self.in_flight.is_some() {
            let retry = self.retry_at_ms.unwrap_or(now_ms);
            let rate = self.next_rate_allowed_ms(now_ms).unwrap_or(now_ms);
            return Some(retry.max(rate));
        }
        let lane_due = match (self.fast_deadline_ms, self.batch_deadline_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }?;
        let rate = self.next_rate_allowed_ms(now_ms).unwrap_or(now_ms);
        Some(lane_due.max(rate))
    }

    /// Returns `(Option<PendingBatch>, rate_limit_hit_newly)`.
    pub(crate) fn poll_ready(&mut self, now_ms: u64) -> (Option<PendingBatch>, bool) {
        if self.in_flight.is_some() {
            if self.retry_at_ms.is_some_and(|t| now_ms < t) {
                return (None, false);
            }
            if self.next_rate_allowed_ms(now_ms).is_some() {
                let newly = !self.rate_limit_counted_for_hold;
                self.rate_limited_pending = true;
                self.rate_limit_counted_for_hold = true;
                if let Some(batch) = self.in_flight.as_mut() {
                    batch.rate_limited = true;
                }
                return (None, newly);
            }
            self.retry_at_ms = None;
            self.rate_limit_counted_for_hold = false;
            self.sent_timestamps_ms.push_back(now_ms);
            return (self.in_flight.clone(), false);
        }

        let fast_due = self.fast_deadline_ms.is_some_and(|d| now_ms >= d);
        let batch_due = self.batch_deadline_ms.is_some_and(|d| now_ms >= d);
        if !fast_due && !batch_due {
            return (None, false);
        }

        if self.next_rate_allowed_ms(now_ms).is_some() {
            let newly = !self.rate_limit_counted_for_hold;
            self.rate_limited_pending = true;
            self.rate_limit_counted_for_hold = true;
            return (None, newly);
        }

        let mut items = Vec::new();
        while items.len() < MAX_BATCH_ITEMS {
            if let Some(item) = self.fast_queue.pop_front() {
                items.push(item);
            } else {
                break;
            }
        }
        while items.len() < MAX_BATCH_ITEMS {
            if let Some(item) = self.batch_queue.pop_front() {
                items.push(item);
            } else {
                break;
            }
        }

        self.fast_deadline_ms = if self.fast_queue.is_empty() {
            None
        } else {
            Some(now_ms.saturating_add(self.fast_window_ms))
        };
        self.batch_deadline_ms = if self.batch_queue.is_empty() {
            None
        } else {
            Some(now_ms.saturating_add(self.batch_window_ms))
        };

        if items.is_empty() {
            return (None, false);
        }

        let rate_limited = self.rate_limited_pending;
        self.rate_limited_pending = false;
        self.rate_limit_counted_for_hold = false;
        self.sent_timestamps_ms.push_back(now_ms);

        let batch = PendingBatch {
            batch_id: Uuid::new_v4().to_string(),
            items,
            rate_limited,
            attempts: 0,
        };
        self.in_flight = Some(batch.clone());
        (Some(batch), false)
    }

    pub(crate) fn record_outcome(
        &mut self,
        outcome: DeliveryOutcome,
        now_ms: u64,
        jitter_unit: f64,
    ) -> Option<BatchDisposition> {
        let mut batch = self.in_flight.take()?;
        match outcome {
            DeliveryOutcome::Success(status) => {
                let mut keys = Vec::with_capacity(batch.items.len());
                let mut max_enqueued_ms: Option<u64> = None;
                for item in batch.items {
                    self.queued_keys.remove(&item.dedupe_key);
                    max_enqueued_ms = Some(
                        max_enqueued_ms.map_or(item.enqueued_at_ms, |m| m.max(item.enqueued_at_ms)),
                    );
                    keys.push(item.dedupe_key);
                }
                self.retry_at_ms = None;
                Some(BatchDisposition::Committed {
                    keys,
                    status,
                    max_enqueued_ms,
                })
            }
            DeliveryOutcome::ClientError(status) => {
                batch.attempts = batch.attempts.saturating_add(1);
                if batch.attempts >= MAX_4XX_ATTEMPTS {
                    let count = batch.items.len();
                    for item in batch.items {
                        self.queued_keys.remove(&item.dedupe_key);
                    }
                    self.retry_at_ms = None;
                    Some(BatchDisposition::Dropped4xx {
                        batch_id: batch.batch_id,
                        status,
                        item_count: count,
                    })
                } else {
                    let delay = compute_backoff_ms(batch.attempts, jitter_unit);
                    let retry_at_ms = now_ms.saturating_add(delay);
                    let attempts = batch.attempts;
                    self.in_flight = Some(batch);
                    self.retry_at_ms = Some(retry_at_ms);
                    Some(BatchDisposition::RetryScheduled {
                        retry_at_ms,
                        attempts,
                    })
                }
            }
            DeliveryOutcome::RetryableError(status) => {
                batch.attempts = batch.attempts.saturating_add(1);
                if batch.attempts >= MAX_RETRYABLE_ATTEMPTS {
                    let count = batch.items.len();
                    for item in batch.items {
                        self.queued_keys.remove(&item.dedupe_key);
                    }
                    self.retry_at_ms = None;
                    Some(BatchDisposition::DroppedExpired {
                        batch_id: batch.batch_id,
                        last_status: status,
                        attempts: batch.attempts,
                        item_count: count,
                    })
                } else {
                    let delay = compute_backoff_ms(batch.attempts, jitter_unit);
                    let retry_at_ms = now_ms.saturating_add(delay);
                    let attempts = batch.attempts;
                    self.in_flight = Some(batch);
                    self.retry_at_ms = Some(retry_at_ms);
                    Some(BatchDisposition::RetryScheduled {
                        retry_at_ms,
                        attempts,
                    })
                }
            }
        }
    }
}

/// Exponential backoff starting at 2 s up to 5 min with ±20 % jitter.
pub(crate) fn compute_backoff_ms(attempt: u32, jitter_unit: f64) -> u64 {
    let shift = attempt.saturating_sub(1).min(20);
    let base = BACKOFF_MIN_MS
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_MAX_MS);
    let clamped_unit = jitter_unit.clamp(0.0, 1.0);
    let factor = 0.8 + 0.4 * clamped_unit;
    let jittered = ((base as f64) * factor).round() as u64;
    jittered.clamp(BACKOFF_MIN_MS, BACKOFF_MAX_MS)
}

#[derive(Debug)]
struct WebhookStats {
    name: String,
    url_host: String,
    active: bool,
    error: Option<String>,
    bearer_token_configured: bool,
    bearer_token_sha256_prefix: Option<String>,
    signing_secret_configured: bool,
    signing_secret_sha256_prefix: Option<String>,
    queue_depth: AtomicUsize,
    sent: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
    rate_limited: AtomicU64,
    last_status: AtomicU32,
    last_success_at: AtomicI64,
}

impl WebhookStats {
    fn from_validated(cfg: &ValidatedWebhook) -> Self {
        Self {
            name: cfg.name.clone(),
            url_host: cfg.url_host.clone(),
            active: true,
            error: None,
            bearer_token_configured: cfg.bearer_token.is_some(),
            bearer_token_sha256_prefix: cfg
                .bearer_token
                .as_ref()
                .map(|s| s.sha256_prefix().to_string()),
            signing_secret_configured: cfg.signing_secret.is_some(),
            signing_secret_sha256_prefix: cfg
                .signing_secret
                .as_ref()
                .map(|s| s.sha256_prefix().to_string()),
            queue_depth: AtomicUsize::new(0),
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            last_status: AtomicU32::new(0),
            last_success_at: AtomicI64::new(0),
        }
    }

    fn from_failed(cfg: &WebhookConfig, err: &WebhookConfigError) -> Self {
        let url_host = reqwest::Url::parse(&cfg.url)
            .ok()
            .and_then(|u| u.host_str().map(normalize_host))
            .unwrap_or_default();
        Self {
            name: cfg.name.clone(),
            url_host,
            active: false,
            error: Some(err.to_string()),
            bearer_token_configured: false,
            bearer_token_sha256_prefix: None,
            signing_secret_configured: false,
            signing_secret_sha256_prefix: None,
            queue_depth: AtomicUsize::new(0),
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            last_status: AtomicU32::new(0),
            last_success_at: AtomicI64::new(0),
        }
    }

    fn snapshot(&self) -> WebhookDiagnosticEntry {
        let raw_status = self.last_status.load(Ordering::Relaxed);
        let raw_success = self.last_success_at.load(Ordering::Relaxed);
        WebhookDiagnosticEntry {
            name: self.name.clone(),
            url_host: self.url_host.clone(),
            active: self.active,
            error: self.error.clone(),
            bearer_token_configured: self.bearer_token_configured,
            bearer_token_sha256_prefix: self.bearer_token_sha256_prefix.clone(),
            signing_secret_configured: self.signing_secret_configured,
            signing_secret_sha256_prefix: self.signing_secret_sha256_prefix.clone(),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            last_status: if raw_status == 0 {
                None
            } else {
                Some(raw_status as u16)
            },
            last_success_at: if raw_success == 0 {
                None
            } else {
                Some(raw_success as u64)
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WebhookDiagnosticEntry {
    pub(crate) name: String,
    pub(crate) url_host: String,
    pub(crate) active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    pub(crate) bearer_token_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bearer_token_sha256_prefix: Option<String>,
    pub(crate) signing_secret_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signing_secret_sha256_prefix: Option<String>,
    pub(crate) queue_depth: usize,
    pub(crate) sent: u64,
    pub(crate) failed: u64,
    pub(crate) dropped: u64,
    pub(crate) rate_limited: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_success_at: Option<u64>,
}

#[derive(Debug, Clone)]
struct MentionTeeEvent {
    topic: String,
    group_id: String,
    msg_id: String,
    author_agent_id: String,
    reason: String,
    timestamp: u64,
    body: Option<String>,
}

#[derive(Debug, Clone)]
struct PublicMessageTeeEvent {
    stable_group_id: String,
    msg: GroupPublicMessage,
}

#[derive(Clone)]
struct TargetSubscriber {
    config: Arc<ValidatedWebhook>,
    stats: Arc<WebhookStats>,
    tx: mpsc::Sender<QueuedWebhookItem>,
    backfill_since_ms: Option<i64>,
}

struct ActiveTarget {
    config: Arc<ValidatedWebhook>,
    stats: Arc<WebhookStats>,
    item_tx: mpsc::Sender<QueuedWebhookItem>,
    item_rx: Option<mpsc::Receiver<QueuedWebhookItem>>,
    client: reqwest::Client,
}

/// Daemon-owned outbound webhook push service.
pub(crate) struct WebhookService {
    stats: Vec<Arc<WebhookStats>>,
    mention_tx: Option<mpsc::Sender<MentionTeeEvent>>,
    mention_dropped: AtomicU64,
    public_msg_tx: Option<mpsc::Sender<PublicMessageTeeEvent>>,
    public_msg_dropped: AtomicU64,
    dedupe: Option<Arc<StdMutex<WebhookDedupeStore>>>,
    targets: Mutex<Vec<ActiveTarget>>,
    mention_rx: Mutex<Option<mpsc::Receiver<MentionTeeEvent>>>,
    public_msg_rx: Mutex<Option<mpsc::Receiver<PublicMessageTeeEvent>>>,
    cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
}

impl WebhookService {
    /// Build the service from `[notify]` config. Returns `None` when no
    /// `[[notify.webhook]]` entries are configured (feature fully inert).
    pub(crate) fn new(config: &NotifyConfig, data_dir: &Path) -> Option<Arc<Self>> {
        if config.webhook.is_empty() {
            return None;
        }
        let mut seen_names = HashSet::new();
        let mut stats = Vec::with_capacity(config.webhook.len());
        let mut active_targets = Vec::new();
        let mut any_wants_mention = false;
        let mut any_wants_group = false;

        for raw in &config.webhook {
            let trimmed = raw.name.trim().to_string();
            let validated = if !trimmed.is_empty() && !seen_names.insert(trimmed.clone()) {
                Err(WebhookConfigError::DuplicateName(trimmed))
            } else {
                ValidatedWebhook::validate(raw)
            };

            match validated {
                Ok(valid) => match valid.build_http_client() {
                    Ok(client) => {
                        if valid.wants_mention() {
                            any_wants_mention = true;
                        }
                        if !valid.group_ids().is_empty() {
                            any_wants_group = true;
                        }
                        let st = Arc::new(WebhookStats::from_validated(&valid));
                        stats.push(Arc::clone(&st));
                        let (item_tx, item_rx) = mpsc::channel(MAX_QUEUE_ITEMS);
                        active_targets.push(ActiveTarget {
                            config: Arc::new(valid),
                            stats: st,
                            item_tx,
                            item_rx: Some(item_rx),
                            client,
                        });
                    }
                    Err(err) => {
                        let wrapped = WebhookConfigError::InvalidUrl(err.to_string());
                        tracing::error!(
                            webhook = %valid.name,
                            error = %wrapped,
                            "refusing to start webhook: HTTP client build failed"
                        );
                        stats.push(Arc::new(WebhookStats::from_failed(raw, &wrapped)));
                    }
                },
                Err(err) => {
                    tracing::error!(
                        webhook = %raw.name,
                        error = %err,
                        "refusing to start webhook: invalid configuration"
                    );
                    stats.push(Arc::new(WebhookStats::from_failed(raw, &err)));
                }
            }
        }

        let dedupe = if active_targets.is_empty() {
            None
        } else {
            let db_path = data_dir.join(WEBHOOK_STATE_DB_NAME);
            match WebhookDedupeStore::open(&db_path) {
                Ok(store) => Some(Arc::new(StdMutex::new(store))),
                Err(err) => {
                    tracing::error!(
                        path = %db_path.display(),
                        error = %err,
                        "refusing to start webhooks: failed to open webhook_state.db"
                    );
                    for target in active_targets.drain(..) {
                        tracing::error!(
                            webhook = %target.config.name,
                            "webhook disabled because webhook_state.db failed to open"
                        );
                    }
                    None
                }
            }
        };

        let (mention_tx, mention_rx) = if any_wants_mention && dedupe.is_some() {
            let (tx, rx) = mpsc::channel(MENTION_TEE_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let (public_msg_tx, public_msg_rx) = if any_wants_group && dedupe.is_some() {
            let (tx, rx) = mpsc::channel(PUBLIC_MSG_TEE_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        Some(Arc::new(Self {
            stats,
            mention_tx,
            mention_dropped: AtomicU64::new(0),
            public_msg_tx,
            public_msg_dropped: AtomicU64::new(0),
            dedupe,
            targets: Mutex::new(active_targets),
            mention_rx: Mutex::new(mention_rx),
            public_msg_rx: Mutex::new(public_msg_rx),
            cancel: CancellationToken::new(),
            tasks: Mutex::new(JoinSet::new()),
        }))
    }

    /// Non-blocking tee called from `emit_mention_event` before `ws_topics`.
    pub(crate) fn try_send_mention(&self, frame: &MentionFrame) {
        if frame.reason != "mention" {
            return;
        }
        let Some(ref tx) = self.mention_tx else {
            return;
        };
        let event = MentionTeeEvent {
            topic: frame.topic.clone(),
            group_id: frame.group_id.clone(),
            msg_id: frame.msg_id.clone(),
            author_agent_id: frame.author_agent_id.clone(),
            reason: frame.reason.clone(),
            timestamp: frame.timestamp,
            body: frame.body.clone(),
        };
        if tx.try_send(event).is_err() {
            self.mention_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Non-blocking tee called from `ingest_public_message` only after full
    /// signature, membership, ban, write-policy, rider, and send-as validation.
    pub(in crate::server) fn try_send_public_message(
        &self,
        stable_group_id: &str,
        msg: &GroupPublicMessage,
    ) {
        if !matches!(msg.kind, GroupPublicMessageKind::Chat) {
            return;
        }
        let Some(ref tx) = self.public_msg_tx else {
            return;
        };
        let event = PublicMessageTeeEvent {
            stable_group_id: stable_group_id.to_string(),
            msg: msg.clone(),
        };
        if tx.try_send(event).is_err() {
            self.public_msg_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Start background event taps and per-webhook delivery loops.
    pub(crate) async fn start(self: &Arc<Self>, state: Arc<AppState>) {
        let Some(dedupe) = self.dedupe.clone() else {
            return;
        };
        let mut active = {
            let mut guard = self.targets.lock().await;
            std::mem::take(&mut *guard)
        };
        if active.is_empty() {
            return;
        }

        let now_ms_i64 = i64::try_from(unix_now_ms()).unwrap_or(i64::MAX);
        let dedupe_floor_ms = now_ms_i64
            .saturating_sub(DEDUPE_TTL_SECS.saturating_mul(1_000) - DEDUPE_BACKFILL_MARGIN_MS);

        let mut tasks = self.tasks.lock().await;
        let mut dm_subscribers: Vec<TargetSubscriber> = Vec::new();
        let mut mention_subscribers: Vec<TargetSubscriber> = Vec::new();
        let mut group_subscribers: std::collections::HashMap<String, Vec<TargetSubscriber>> =
            std::collections::HashMap::new();
        let mut group_query_aliases: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut topic_subscribers: std::collections::HashMap<String, Vec<TargetSubscriber>> =
            std::collections::HashMap::new();
        let mut groups_to_reconcile: Vec<String> = Vec::new();

        for target in &mut active {
            let backfill_since_ms =
                match dedupe_init_or_get_cursor(&dedupe, target.config.name.clone(), now_ms_i64)
                    .await
                {
                    Some((_cursor_ms, true)) => None,
                    Some((cursor_ms, false)) => Some(cursor_ms.max(dedupe_floor_ms)),
                    None => None,
                };

            let make_sub = || TargetSubscriber {
                config: Arc::clone(&target.config),
                stats: Arc::clone(&target.stats),
                tx: target.item_tx.clone(),
                backfill_since_ms,
            };

            if target.config.wants_dm() {
                dm_subscribers.push(make_sub());
            }
            if target.config.wants_mention() {
                mention_subscribers.push(make_sub());
            }
            for raw_gid in target.config.group_ids() {
                let resolved = {
                    let groups = state.named_groups.read().await;
                    crate::server::resolve_group_entry_locked(&groups, &raw_gid).map(
                        |(local_key, info)| {
                            (
                                local_key.to_string(),
                                info.stable_group_id().to_string(),
                                info.policy.confidentiality == GroupConfidentiality::MlsEncrypted,
                                info.withdrawn,
                            )
                        },
                    )
                };
                let (subscribe_key, aliases) = match resolved {
                    Some((local_key, stable_id, is_mls, withdrawn)) => {
                        if is_mls || withdrawn {
                            tracing::warn!(
                                webhook = %target.config.name,
                                group_id = %raw_gid,
                                stable_group_id = %stable_id,
                                "webhook group selector targets an MLS-encrypted or withdrawn group; public messages will not be delivered"
                            );
                        } else if !groups_to_reconcile.contains(&stable_id) {
                            groups_to_reconcile.push(stable_id.clone());
                        }
                        let mut aliases = vec![stable_id.clone(), local_key, raw_gid];
                        aliases.sort();
                        aliases.dedup();
                        (stable_id, aliases)
                    }
                    None => {
                        tracing::warn!(
                            webhook = %target.config.name,
                            group_id = %raw_gid,
                            "webhook group selector does not match any currently known named group"
                        );
                        (raw_gid.clone(), vec![raw_gid])
                    }
                };
                let entry_aliases = group_query_aliases
                    .entry(subscribe_key.clone())
                    .or_default();
                for alias in aliases {
                    if !entry_aliases.contains(&alias) {
                        entry_aliases.push(alias);
                    }
                }
                group_subscribers
                    .entry(subscribe_key)
                    .or_default()
                    .push(make_sub());
            }
            for topic in target.config.topics() {
                topic_subscribers.entry(topic).or_default().push(make_sub());
            }

            if let Some(item_rx) = target.item_rx.take() {
                let worker_state = Arc::clone(&state);
                let worker_cfg = Arc::clone(&target.config);
                let worker_stats = Arc::clone(&target.stats);
                let worker_client = target.client.clone();
                let worker_dedupe = Arc::clone(&dedupe);
                let worker_cancel = self.cancel.clone();
                tasks.spawn(async move {
                    run_webhook_worker(
                        worker_state,
                        worker_cfg,
                        worker_stats,
                        worker_client,
                        worker_dedupe,
                        item_rx,
                        worker_cancel,
                    )
                    .await;
                });
            }
        }

        for stable_id in groups_to_reconcile {
            crate::server::routes::named_groups::reconcile_public_message_listener(
                &state, &stable_id,
            )
            .await;
        }

        if !dm_subscribers.is_empty() {
            let dm_state = Arc::clone(&state);
            let dm_dedupe = Arc::clone(&dedupe);
            let dm_cancel = self.cancel.clone();
            tasks.spawn(async move {
                run_dm_source(dm_state, dm_subscribers, dm_dedupe, dm_cancel).await;
            });
        }

        if !mention_subscribers.is_empty() {
            if let Some(rx) = self.mention_rx.lock().await.take() {
                let m_state = Arc::clone(&state);
                let m_dedupe = Arc::clone(&dedupe);
                let m_cancel = self.cancel.clone();
                tasks.spawn(async move {
                    run_mention_source(m_state, mention_subscribers, m_dedupe, rx, m_cancel).await;
                });
            }
        }

        if !group_subscribers.is_empty() {
            if let Some(rx) = self.public_msg_rx.lock().await.take() {
                let g_state = Arc::clone(&state);
                let g_dedupe = Arc::clone(&dedupe);
                let g_cancel = self.cancel.clone();
                tasks.spawn(async move {
                    run_group_source(
                        g_state,
                        group_subscribers,
                        group_query_aliases,
                        g_dedupe,
                        rx,
                        g_cancel,
                    )
                    .await;
                });
            }
        }

        for (topic, subs) in topic_subscribers {
            let t_state = Arc::clone(&state);
            let t_dedupe = Arc::clone(&dedupe);
            let t_cancel = self.cancel.clone();
            tasks.spawn(async move {
                run_topic_source(t_state, topic, subs, t_dedupe, t_cancel).await;
            });
        }
    }

    /// Cancel in-flight HTTP and source tasks and wait within the shutdown drain grace.
    pub(crate) async fn shutdown_and_wait(&self) {
        self.cancel.cancel();
        let mut set = {
            let mut guard = self.tasks.lock().await;
            std::mem::take(&mut *guard)
        };
        if set.is_empty() {
            return;
        }
        let timed_out = tokio::time::timeout(SHUTDOWN_DRAIN_GRACE, async {
            while set.join_next().await.is_some() {}
        })
        .await
        .is_err();
        if timed_out {
            set.abort_all();
            let _ = tokio::time::timeout(ABORT_DRAIN_GRACE, async {
                while set.join_next().await.is_some() {}
            })
            .await;
        }
    }

    pub(crate) fn diagnostics(&self) -> Vec<WebhookDiagnosticEntry> {
        self.stats.iter().map(|s| s.snapshot()).collect()
    }
}

/// `GET /diagnostics/webhooks` — owner/durable-token only snapshot of outbound webhooks.
pub(super) async fn webhooks_diagnostics(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let (enabled, webhooks) = match &state.webhook_service {
        Some(service) => (true, service.diagnostics()),
        None => (false, Vec::new()),
    };
    Json(serde_json::json!({
        "ok": true,
        "enabled": enabled,
        "webhooks": webhooks,
    }))
}

async fn is_echo_author(state: &AppState, author_hex: &str, rider_sub_id: Option<&str>) -> bool {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let author_lower = author_hex.to_ascii_lowercase();
    if author_lower == local_hex {
        return true;
    }
    let certs = state.agent.owner_issued_certificates().await;
    is_echo_author_with_roster(&local_hex, &certs, &author_lower, rider_sub_id)
}

pub(crate) fn is_echo_author_with_roster(
    local_hex: &str,
    certs: &[x0x::OwnerIssuedCert],
    author_hex: &str,
    rider_sub_id: Option<&str>,
) -> bool {
    let author_lower = author_hex.to_ascii_lowercase();
    if author_lower == local_hex.to_ascii_lowercase() {
        return true;
    }
    let rider_sub_lower = rider_sub_id.map(str::to_ascii_lowercase);
    certs.iter().any(|c| {
        c.mode == CertMode::Rider
            && (c.agent_id.eq_ignore_ascii_case(&author_lower)
                || rider_sub_lower
                    .as_deref()
                    .is_some_and(|sub| c.agent_id.eq_ignore_ascii_case(sub)))
    })
}

async fn resolve_from_name(state: &AppState, agent_hex: &str) -> Option<String> {
    let bytes = hex::decode(agent_hex).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    let id = x0x::identity::AgentId(arr);
    if let Ok(Some(discovered)) = state.agent.discovered_agent(id).await {
        if let Some(name) = discovered.self_name {
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    let contacts = state.contacts.read().await;
    contacts
        .get(&id)
        .and_then(|c| c.label.clone())
        .filter(|l| !l.is_empty())
}

async fn dedupe_init_or_get_cursor(
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
    webhook_name: String,
    now_ms: i64,
) -> Option<(i64, bool)> {
    let store = Arc::clone(dedupe);
    tokio::task::spawn_blocking(move || match store.lock() {
        Ok(mut guard) => match guard.init_or_get_cursor_ms(&webhook_name, now_ms) {
            Ok(res) => Some(res),
            Err(err) => {
                tracing::warn!(
                    webhook = %webhook_name,
                    error = %err,
                    "failed to initialize webhook backfill cursor"
                );
                None
            }
        },
        Err(_) => None,
    })
    .await
    .ok()
    .flatten()
}

async fn dedupe_load_sent_timestamps(
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
    webhook_name: String,
    now_ms: i64,
) -> Vec<u64> {
    let store = Arc::clone(dedupe);
    tokio::task::spawn_blocking(move || match store.lock() {
        Ok(guard) => guard
            .load_sent_timestamps(&webhook_name, now_ms)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    })
    .await
    .unwrap_or_default()
}

async fn dedupe_record_sent(
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
    webhook_name: String,
    sent_at_ms: i64,
) {
    let store = Arc::clone(dedupe);
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut guard) = store.lock() {
            if let Err(err) = guard.record_sent(&webhook_name, sent_at_ms) {
                tracing::warn!(
                    webhook = %webhook_name,
                    error = %err,
                    "failed to persist webhook sent timestamp"
                );
            }
        }
    })
    .await;
}

async fn dedupe_already_delivered(
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
    webhook_name: String,
    key: String,
) -> bool {
    let store = Arc::clone(dedupe);
    let now_secs = unix_now_secs() as i64;
    tokio::task::spawn_blocking(move || match store.lock() {
        Ok(guard) => guard
            .is_delivered(&webhook_name, &key, now_secs)
            .unwrap_or(false),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
}

async fn dedupe_commit(
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
    webhook_name: String,
    keys: Vec<String>,
    advance_cursor_ms: Option<i64>,
) {
    let store = Arc::clone(dedupe);
    let now_secs = unix_now_secs() as i64;
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut guard) = store.lock() {
            if let Err(err) =
                guard.mark_delivered_and_advance(&webhook_name, &keys, now_secs, advance_cursor_ms)
            {
                tracing::warn!(
                    webhook = %webhook_name,
                    error = %err,
                    "failed to persist webhook dedupe keys"
                );
            }
        }
    })
    .await;
}

fn try_enqueue_to_target(
    stats: &WebhookStats,
    tx: &mpsc::Sender<QueuedWebhookItem>,
    item: QueuedWebhookItem,
) {
    if tx.try_send(item).is_err() {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn build_dm_queued_item(
    cfg: &ValidatedWebhook,
    sender_hex: &str,
    from_name: Option<String>,
    received_at: u64,
    payload: &[u8],
    verified: bool,
) -> Option<QueuedWebhookItem> {
    if !verified {
        return None;
    }
    let sender_lower = sender_hex.to_ascii_lowercase();
    if !cfg.dm_allowlist.is_empty() && !cfg.dm_allowlist.contains(&sender_lower) {
        return None;
    }
    let text_raw = String::from_utf8_lossy(payload);
    let text = format_item_text(&text_raw, cfg.body_mode, cfg.max_text_chars);
    Some(QueuedWebhookItem {
        dedupe_key: dm_dedupe_key(&sender_lower, received_at, payload),
        lane: Lane::Fast,
        enqueued_at_ms: received_at,
        item: WebhookPayloadItem {
            kind: "dm".to_string(),
            from: sender_lower,
            from_name,
            group_id: None,
            topic: None,
            ts: received_at,
            text,
            msg_id: None,
            flags: Vec::new(),
        },
    })
}

async fn run_dm_source(
    state: Arc<AppState>,
    subscribers: Vec<TargetSubscriber>,
    dedupe: Arc<StdMutex<WebhookDedupeStore>>,
    cancel: CancellationToken,
) {
    // Live tap before history backfill (same seam as sse.rs).
    let mut rx = state.agent.subscribe_direct();
    let mut shutdown_rx = state.shutdown_notify.subscribe();

    let min_since_ms = subscribers.iter().filter_map(|s| s.backfill_since_ms).min();

    if let (Some(since_ms), Some(history)) = (min_since_ms, state.agent.history()) {
        let store = Arc::clone(history.store());
        let query = HistoryQuery {
            scope_kind: Some(0),
            since_ms: Some(since_ms),
            limit: DM_BACKFILL_LIMIT,
            ..Default::default()
        };
        if let Ok(Ok(mut rows)) = tokio::task::spawn_blocking(move || store.query(&query)).await {
            rows.reverse();
            for row in rows {
                if cancel.is_cancelled() || state.shutdown_started.is_cancelled() {
                    return;
                }
                let record = row.record;
                if record.direction != Direction::Inbound {
                    continue;
                }
                if !matches!(record.provenance, Provenance::VerifiedEnvelope) {
                    continue;
                }
                if delivery_gate::stored_dm_delivery_refused(
                    &state,
                    record.author_agent.as_deref(),
                    record.author_machine.as_deref(),
                )
                .await
                {
                    continue;
                }
                let Some(sender_hex) = record.author_agent.as_deref() else {
                    continue;
                };
                if is_echo_author(&state, sender_hex, None).await {
                    continue;
                }
                let received_at = u64::try_from(record.seen_at_ms).unwrap_or(0);
                let from_name = resolve_from_name(&state, sender_hex).await;
                let key = dm_dedupe_key(sender_hex, received_at, &record.payload);
                for sub in &subscribers {
                    let Some(sub_since_ms) = sub.backfill_since_ms else {
                        continue;
                    };
                    if record.seen_at_ms < sub_since_ms {
                        continue;
                    }
                    let Some(queued) = build_dm_queued_item(
                        &sub.config,
                        sender_hex,
                        from_name.clone(),
                        received_at,
                        &record.payload,
                        true,
                    ) else {
                        continue;
                    };
                    if dedupe_already_delivered(&dedupe, sub.config.name.clone(), key.clone()).await
                    {
                        continue;
                    }
                    try_enqueue_to_target(&sub.stats, &sub.tx, queued);
                }
            }
        }
    }

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = state.shutdown_started.cancelled() => break,
            _ = shutdown_rx.changed() => break,
            maybe_msg = rx.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };
                if !msg.verified {
                    continue;
                }
                if !matches!(
                    x0x::history::classify::classify_dm_payload(&msg.payload),
                    DmPayloadClass::Durable(_)
                ) {
                    continue;
                }
                let sender_hex = hex::encode(msg.sender.as_bytes());
                let machine_hex = hex::encode(msg.machine_id.as_bytes());
                if delivery_gate::stored_dm_delivery_refused(
                    &state,
                    Some(&sender_hex),
                    Some(&machine_hex),
                )
                .await
                {
                    continue;
                }
                if is_echo_author(&state, &sender_hex, None).await {
                    continue;
                }
                let from_name = resolve_from_name(&state, &sender_hex).await;
                for sub in &subscribers {
                    let Some(queued) = build_dm_queued_item(
                        &sub.config,
                        &sender_hex,
                        from_name.clone(),
                        msg.received_at,
                        &msg.payload,
                        true,
                    ) else {
                        continue;
                    };
                    if !dedupe_already_delivered(
                        &dedupe,
                        sub.config.name.clone(),
                        queued.dedupe_key.clone(),
                    )
                    .await
                    {
                        try_enqueue_to_target(&sub.stats, &sub.tx, queued);
                    }
                }
            }
        }
    }
}

async fn run_mention_source(
    state: Arc<AppState>,
    subscribers: Vec<TargetSubscriber>,
    dedupe: Arc<StdMutex<WebhookDedupeStore>>,
    mut rx: mpsc::Receiver<MentionTeeEvent>,
    cancel: CancellationToken,
) {
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = state.shutdown_started.cancelled() => break,
            _ = shutdown_rx.changed() => break,
            maybe_ev = rx.recv() => {
                let Some(ev) = maybe_ev else {
                    break;
                };
                if ev.reason != "mention" {
                    continue;
                }
                if delivery_gate::stored_sender_delivery_refused(&state, &ev.author_agent_id).await {
                    continue;
                }
                if is_echo_author(&state, &ev.author_agent_id, None).await {
                    continue;
                }
                let from_name = resolve_from_name(&state, &ev.author_agent_id).await;
                let dedupe_key = mention_dedupe_key(&ev.msg_id);
                let now_ms = unix_now_ms();
                for sub in &subscribers {
                    if dedupe_already_delivered(&dedupe, sub.config.name.clone(), dedupe_key.clone()).await {
                        continue;
                    }
                    let text = ev
                        .body
                        .as_deref()
                        .and_then(|b| format_item_text(b, sub.config.body_mode, sub.config.max_text_chars));
                    let queued = QueuedWebhookItem {
                        dedupe_key: dedupe_key.clone(),
                        lane: Lane::Fast,
                        enqueued_at_ms: now_ms,
                        item: WebhookPayloadItem {
                            kind: "mention".to_string(),
                            from: ev.author_agent_id.to_ascii_lowercase(),
                            from_name: from_name.clone(),
                            group_id: Some(ev.group_id.clone()),
                            topic: Some(ev.topic.clone()),
                            ts: ev.timestamp,
                            text,
                            msg_id: Some(ev.msg_id.clone()),
                            flags: Vec::new(),
                        },
                    };
                    try_enqueue_to_target(&sub.stats, &sub.tx, queued);
                }
            }
        }
    }
}

async fn emit_group_public_message(
    state: &AppState,
    stable_group_id: &str,
    pm: &GroupPublicMessage,
    enqueued_at_ms: u64,
    backfill_row_seen_ms: Option<i64>,
    subscribers: &[TargetSubscriber],
    dedupe: &Arc<StdMutex<WebhookDedupeStore>>,
) {
    if !matches!(pm.kind, GroupPublicMessageKind::Chat) {
        return;
    }
    if delivery_gate::stored_sender_delivery_refused(state, &pm.author_agent_id).await {
        return;
    }
    let rider_sub = pm
        .rider_provenance
        .as_ref()
        .map(|rp| rp.sub_agent_id.as_str());
    if is_echo_author(state, &pm.author_agent_id, rider_sub).await {
        return;
    }
    let topic = public_topic_for(stable_group_id);
    let from_name = resolve_from_name(state, &pm.author_agent_id).await;
    let dedupe_key = group_dedupe_key(&pm.author_agent_id, pm.timestamp, &pm.signature);
    let msg_id = pm.msg_id();
    for sub in subscribers {
        if let Some(seen_ms) = backfill_row_seen_ms {
            let Some(sub_since_ms) = sub.backfill_since_ms else {
                continue;
            };
            if seen_ms < sub_since_ms {
                continue;
            }
        }
        if dedupe_already_delivered(dedupe, sub.config.name.clone(), dedupe_key.clone()).await {
            continue;
        }
        let text = format_item_text(&pm.body, sub.config.body_mode, sub.config.max_text_chars);
        let queued = QueuedWebhookItem {
            dedupe_key: dedupe_key.clone(),
            lane: Lane::Batch,
            enqueued_at_ms,
            item: WebhookPayloadItem {
                kind: "group".to_string(),
                from: pm.author_agent_id.to_ascii_lowercase(),
                from_name: from_name.clone(),
                group_id: Some(stable_group_id.to_string()),
                topic: Some(topic.clone()),
                ts: pm.timestamp,
                text,
                msg_id: Some(msg_id.clone()),
                flags: Vec::new(),
            },
        };
        try_enqueue_to_target(&sub.stats, &sub.tx, queued);
    }
}

async fn run_group_source(
    state: Arc<AppState>,
    group_subscribers: std::collections::HashMap<String, Vec<TargetSubscriber>>,
    group_query_aliases: std::collections::HashMap<String, Vec<String>>,
    dedupe: Arc<StdMutex<WebhookDedupeStore>>,
    mut rx: mpsc::Receiver<PublicMessageTeeEvent>,
    cancel: CancellationToken,
) {
    let mut shutdown_rx = state.shutdown_notify.subscribe();

    // Bounded backfill for returning webhooks only; first-enable webhooks skip pre-enable history.
    for (group_id, subs) in &group_subscribers {
        let Some(min_since_ms) = subs.iter().filter_map(|s| s.backfill_since_ms).min() else {
            continue;
        };
        let aliases: Vec<String> = group_query_aliases
            .get(group_id)
            .cloned()
            .unwrap_or_else(|| vec![group_id.clone()]);
        let cached: Vec<GroupPublicMessage> = {
            let guard = state.public_messages.read().await;
            let mut out = Vec::new();
            let mut seen_sig = HashSet::new();
            for alias in &aliases {
                if let Some(msgs) = guard.get(alias) {
                    for m in msgs {
                        if seen_sig.insert(m.signature.clone()) {
                            out.push(m.clone());
                        }
                    }
                }
            }
            out
        };
        let backfill_msgs: Vec<(GroupPublicMessage, i64)> = match state.agent.history() {
            Some(history) => {
                let store = Arc::clone(history.store());
                let query_aliases = aliases.clone();
                match tokio::task::spawn_blocking(move || {
                    let mut all_rows = Vec::new();
                    for gid in query_aliases {
                        let q = HistoryQuery {
                            scope: Some(Scope::Group(gid)),
                            since_ms: Some(min_since_ms),
                            limit: GROUP_BACKFILL_LIMIT,
                            ..Default::default()
                        };
                        if let Ok(rows) = store.query(&q) {
                            all_rows.extend(rows);
                        }
                    }
                    all_rows
                })
                .await
                {
                    Ok(rows) => {
                        let mut merged: Vec<(GroupPublicMessage, i64)> = Vec::new();
                        let mut seen: HashSet<String> = HashSet::new();
                        for r in &rows {
                            if let Some(artifact) = r.record.signed_artifact.as_deref() {
                                if let Ok(pm) =
                                    serde_json::from_slice::<GroupPublicMessage>(artifact)
                                {
                                    if seen.insert(pm.signature.clone()) {
                                        merged.push((pm, r.record.seen_at_ms));
                                    }
                                }
                            }
                        }
                        let now_i64 = i64::try_from(unix_now_ms()).unwrap_or(i64::MAX);
                        for m in cached {
                            let ts_i64 = i64::try_from(m.timestamp).unwrap_or(now_i64).min(now_i64);
                            if ts_i64 >= min_since_ms && seen.insert(m.signature.clone()) {
                                merged.push((m, ts_i64));
                            }
                        }
                        merged.sort_by_key(|(m, _)| m.timestamp);
                        merged
                    }
                    Err(_) => {
                        let now_i64 = i64::try_from(unix_now_ms()).unwrap_or(i64::MAX);
                        cached
                            .into_iter()
                            .filter_map(|m| {
                                let ts_i64 =
                                    i64::try_from(m.timestamp).unwrap_or(now_i64).min(now_i64);
                                (ts_i64 >= min_since_ms).then_some((m, ts_i64))
                            })
                            .collect()
                    }
                }
            }
            None => {
                let now_i64 = i64::try_from(unix_now_ms()).unwrap_or(i64::MAX);
                cached
                    .into_iter()
                    .filter_map(|m| {
                        let ts_i64 = i64::try_from(m.timestamp).unwrap_or(now_i64).min(now_i64);
                        (ts_i64 >= min_since_ms).then_some((m, ts_i64))
                    })
                    .collect()
            }
        };

        for (pm, seen_ms) in backfill_msgs {
            if cancel.is_cancelled() || state.shutdown_started.is_cancelled() {
                return;
            }
            let enqueued_ms = u64::try_from(seen_ms).unwrap_or_else(|_| unix_now_ms());
            emit_group_public_message(
                &state,
                group_id,
                &pm,
                enqueued_ms,
                Some(seen_ms),
                subs,
                &dedupe,
            )
            .await;
        }
    }

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = state.shutdown_started.cancelled() => break,
            _ = shutdown_rx.changed() => break,
            maybe_ev = rx.recv() => {
                let Some(ev) = maybe_ev else {
                    break;
                };
                let now_ms = unix_now_ms();
                if let Some(subs) = group_subscribers.get(&ev.stable_group_id) {
                    emit_group_public_message(
                        &state,
                        &ev.stable_group_id,
                        &ev.msg,
                        now_ms,
                        None,
                        subs,
                        &dedupe,
                    )
                    .await;
                }
                if ev.msg.group_id != ev.stable_group_id {
                    if let Some(subs) = group_subscribers.get(&ev.msg.group_id) {
                        emit_group_public_message(
                            &state,
                            &ev.stable_group_id,
                            &ev.msg,
                            now_ms,
                            None,
                            subs,
                            &dedupe,
                        )
                        .await;
                    }
                }
            }
        }
    }
}

async fn run_topic_source(
    state: Arc<AppState>,
    topic: String,
    subscribers: Vec<TargetSubscriber>,
    dedupe: Arc<StdMutex<WebhookDedupeStore>>,
    cancel: CancellationToken,
) {
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let sub_res = tokio::select! {
        biased;
        () = cancel.cancelled() => return,
        () = state.shutdown_started.cancelled() => return,
        _ = shutdown_rx.changed() => return,
        res = state.agent.subscribe(&topic) => res,
    };
    let mut sub = match sub_res {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(topic = %topic, error = %err, "webhook topic subscribe failed");
            return;
        }
    };

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = state.shutdown_started.cancelled() => break,
            _ = shutdown_rx.changed() => break,
            maybe_msg = sub.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };
                if !msg.verified {
                    continue;
                }
                let Some(sender) = msg.sender.as_ref() else {
                    continue;
                };
                let origin = hex::encode(sender.as_bytes());
                if delivery_gate::stored_sender_delivery_refused(&state, &origin).await {
                    continue;
                }
                if is_echo_author(&state, &origin, None).await {
                    continue;
                }
                let from_name = resolve_from_name(&state, &origin).await;
                let dedupe_key = topic_dedupe_key(&topic, &origin, &msg.payload);
                let now_ms = unix_now_ms();
                let payload_text = String::from_utf8_lossy(&msg.payload);
                for sub in &subscribers {
                    if dedupe_already_delivered(&dedupe, sub.config.name.clone(), dedupe_key.clone()).await {
                        continue;
                    }
                    let text = format_item_text(
                        &payload_text,
                        sub.config.body_mode,
                        sub.config.max_text_chars,
                    );
                    let queued = QueuedWebhookItem {
                        dedupe_key: dedupe_key.clone(),
                        lane: Lane::Batch,
                        enqueued_at_ms: now_ms,
                        item: WebhookPayloadItem {
                            kind: "topic".to_string(),
                            from: origin.clone(),
                            from_name: from_name.clone(),
                            group_id: None,
                            topic: Some(topic.clone()),
                            ts: now_ms,
                            text,
                            msg_id: None,
                            flags: Vec::new(),
                        },
                    };
                    try_enqueue_to_target(&sub.stats, &sub.tx, queued);
                }
            }
        }
    }
}

async fn run_webhook_worker(
    state: Arc<AppState>,
    cfg: Arc<ValidatedWebhook>,
    stats: Arc<WebhookStats>,
    client: reqwest::Client,
    dedupe: Arc<StdMutex<WebhookDedupeStore>>,
    mut rx: mpsc::Receiver<QueuedWebhookItem>,
    cancel: CancellationToken,
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut scheduler = WebhookScheduler::new(
        cfg.fast_window_ms,
        cfg.batch_window_ms,
        cfg.max_per_hour,
        cfg.max_per_day,
        MAX_QUEUE_ITEMS,
    );
    let startup_ms = unix_now_ms();
    let persisted_sent = dedupe_load_sent_timestamps(
        &dedupe,
        cfg.name.clone(),
        i64::try_from(startup_ms).unwrap_or(i64::MAX),
    )
    .await;
    scheduler.seed_sent_timestamps(persisted_sent, startup_ms);
    let mut shutdown_rx = state.shutdown_notify.subscribe();

    loop {
        let now_ms = unix_now_ms();
        let (ready_batch, newly_rate_limited) = scheduler.poll_ready(now_ms);
        if newly_rate_limited {
            stats.rate_limited.fetch_add(1, Ordering::Relaxed);
        }
        stats
            .queue_depth
            .store(scheduler.queue_depth(), Ordering::Relaxed);

        if let Some(batch) = ready_batch {
            dedupe_record_sent(
                &dedupe,
                cfg.name.clone(),
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            )
            .await;
            let outcome = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                () = state.shutdown_started.cancelled() => break,
                _ = shutdown_rx.changed() => break,
                res = post_webhook_batch(&client, &cfg, &local_agent_hex, &batch) => res,
            };
            let done_ms = unix_now_ms();
            let jitter: f64 = rand::thread_rng().gen_range(0.0..=1.0);
            if let Some(disp) = scheduler.record_outcome(outcome, done_ms, jitter) {
                match disp {
                    BatchDisposition::Committed {
                        keys,
                        status,
                        max_enqueued_ms,
                    } => {
                        stats.sent.fetch_add(1, Ordering::Relaxed);
                        stats
                            .last_status
                            .store(u32::from(status), Ordering::Relaxed);
                        stats
                            .last_success_at
                            .store((done_ms / 1_000) as i64, Ordering::Relaxed);
                        let advance_cursor = max_enqueued_ms.map(|ts| {
                            i64::try_from(ts.min(done_ms))
                                .unwrap_or(i64::MAX)
                                .saturating_sub(BACKFILL_OVERLAP_MS)
                        });
                        dedupe_commit(&dedupe, cfg.name.clone(), keys, advance_cursor).await;
                    }
                    BatchDisposition::RetryScheduled { attempts, .. } => {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        if let DeliveryOutcome::ClientError(code)
                        | DeliveryOutcome::RetryableError(Some(code)) = outcome
                        {
                            stats.last_status.store(u32::from(code), Ordering::Relaxed);
                        }
                        tracing::warn!(
                            webhook = %cfg.name,
                            host = %cfg.url_host,
                            attempts,
                            "webhook delivery failed; scheduled retry with backoff"
                        );
                    }
                    BatchDisposition::Dropped4xx {
                        batch_id,
                        status,
                        item_count,
                    } => {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        stats
                            .dropped
                            .fetch_add(item_count as u64, Ordering::Relaxed);
                        stats
                            .last_status
                            .store(u32::from(status), Ordering::Relaxed);
                        tracing::warn!(
                            webhook = %cfg.name,
                            host = %cfg.url_host,
                            batch_id = %batch_id,
                            status,
                            dropped_items = item_count,
                            "webhook batch dropped after 4xx retry limit"
                        );
                    }
                    BatchDisposition::DroppedExpired {
                        batch_id,
                        last_status,
                        attempts,
                        item_count,
                    } => {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        stats
                            .dropped
                            .fetch_add(item_count as u64, Ordering::Relaxed);
                        if let Some(code) = last_status {
                            stats.last_status.store(u32::from(code), Ordering::Relaxed);
                        }
                        tracing::warn!(
                            webhook = %cfg.name,
                            host = %cfg.url_host,
                            batch_id = %batch_id,
                            attempts,
                            dropped_items = item_count,
                            "webhook batch dropped after retry limit exceeded"
                        );
                    }
                }
            }
            stats
                .queue_depth
                .store(scheduler.queue_depth(), Ordering::Relaxed);
            continue;
        }

        let wakeup_ms = scheduler.next_wakeup_ms(now_ms);
        match wakeup_ms {
            Some(target_ms) => {
                let sleep_dur = Duration::from_millis(target_ms.saturating_sub(now_ms));
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = state.shutdown_started.cancelled() => break,
                    _ = shutdown_rx.changed() => break,
                    _ = tokio::time::sleep(sleep_dur) => {}
                    maybe_item = rx.recv() => {
                        let Some(item) = maybe_item else {
                            break;
                        };
                        if !scheduler.enqueue(item, unix_now_ms()) {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        stats.queue_depth.store(scheduler.queue_depth(), Ordering::Relaxed);
                    }
                }
            }
            None => {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = state.shutdown_started.cancelled() => break,
                    _ = shutdown_rx.changed() => break,
                    maybe_item = rx.recv() => {
                        let Some(item) = maybe_item else {
                            break;
                        };
                        if !scheduler.enqueue(item, unix_now_ms()) {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        stats.queue_depth.store(scheduler.queue_depth(), Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

async fn post_webhook_batch(
    client: &reqwest::Client,
    cfg: &ValidatedWebhook,
    local_agent_hex: &str,
    batch: &PendingBatch,
) -> DeliveryOutcome {
    if let Ok(ip) = cfg.url_host.parse::<IpAddr>() {
        if check_ip_allowed(ip, cfg.allow_insecure_loopback_for_test).is_err() {
            return DeliveryOutcome::ClientError(403);
        }
    }
    let sent_at = unix_now_secs();
    let body = WebhookPostBody {
        source: "x0x".to_string(),
        version: 1,
        webhook: cfg.name.clone(),
        agent_id: local_agent_hex.to_string(),
        batch_id: batch.batch_id.clone(),
        sent_at,
        rate_limited: batch.rate_limited,
        items: batch.items.iter().map(|q| q.item.clone()).collect(),
    };
    let Ok(raw_body) = serde_json::to_vec(&body) else {
        return DeliveryOutcome::ClientError(400);
    };

    let mut req = client
        .post(cfg.url.clone())
        .header(CONTENT_TYPE, "application/json");

    if let Some(ref bearer) = cfg.bearer_token {
        if let Ok(token_str) = std::str::from_utf8(bearer.as_bytes()) {
            let header_val = Zeroizing::new(format!("Bearer {token_str}"));
            if let Ok(mut hv) = HeaderValue::from_str(&header_val) {
                hv.set_sensitive(true);
                req = req.header(AUTHORIZATION, hv);
            }
        }
    }

    if let Some(ref secret) = cfg.signing_secret {
        let sig = sign_payload(secret.as_bytes(), sent_at, &raw_body);
        if let Ok(hv) = HeaderValue::from_str(&sig) {
            req = req.header("X-X0x-Signature", hv);
        }
    }

    match req.body(raw_body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if resp.status().is_success() {
                DeliveryOutcome::Success(status)
            } else if status == 408 || status == 429 || status >= 500 {
                DeliveryOutcome::RetryableError(Some(status))
            } else if (400..500).contains(&status) {
                DeliveryOutcome::ClientError(status)
            } else {
                DeliveryOutcome::RetryableError(Some(status))
            }
        }
        Err(_) => DeliveryOutcome::RetryableError(None),
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
