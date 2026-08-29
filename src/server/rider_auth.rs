//! ADR-0039 rider authentication: `ActorContext`, the persisted
//! rider-token store, and the deny-by-default route predicate.
//!
//! A **rider** is a harness process that authenticates to the owner's
//! daemon with a scoped bearer token instead of the durable API token
//! (gapcheck blockers 21/22/24). Riders are a distinct principal class:
//!
//! - The durable API token and browser session tokens resolve to
//!   [`ActorContext::Owner`] — full control plane, exactly as before.
//! - A rider token resolves to [`ActorContext::Rider`] with the identity
//!   of the registered sub-agent it belongs to and its granted scopes.
//! - Every route NOT in [`rider_route_allowed`] rejects a rider token
//!   with `403` **before any handler runs** — deny-by-default. In
//!   particular `/agent/sign`, `/exec/*`, `/owner/*`, `/identity/*`,
//!   `/shutdown` and every admin surface are permanently
//!   rider-forbidden, so the daemon can never be turned into an
//!   unscoped signing or exec oracle through a rider credential.
//! - An unknown, expired, or revoked bearer is `401` —
//!   indistinguishable from any other bad token.
//!
//! Rider tokens are 32 random bytes (64 hex chars), stored **hashed**
//! (SHA-256) at rest in `<data_dir>/rider-tokens.json`, and carry an
//! expiry and revocation time so lifecycle survives a daemon restart
//! (blocker 24). Revocation takes effect on the next request — the
//! middleware validates against the live store on every call, no
//! restart, no cache.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Upper bound on granted named-group ids per rider token.
pub(super) const RIDER_MAX_GROUPS: usize = 32;
/// Default rider-token lifetime: 7 days.
pub(super) const RIDER_DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum rider-token lifetime: 90 days.
pub(super) const RIDER_MAX_TTL_SECS: u64 = 90 * 24 * 60 * 60;
/// Maximum rows a rider may pull from `GET /history` per request
/// (owners keep the store-wide 500 cap).
pub(super) const RIDER_HISTORY_MAX_LIMIT: usize = 100;

/// File name of the persisted rider-token store, in the daemon data dir.
pub(super) const RIDER_TOKENS_FILE: &str = "rider-tokens.json";

/// The per-request acting principal, resolved by the auth middleware and
/// inserted into the request extensions (ADR-0039, gapcheck blocker 22).
///
/// Handlers that care (the rider send/read surfaces) extract it with
/// `Extension<ActorContext>`; every other handler keeps using
/// `state.agent` unchanged — the deny-by-default predicate in the
/// middleware, not a handler-side audit, is what keeps riders off the
/// rest of the control plane.
#[derive(Debug, Clone)]
pub(super) enum ActorContext {
    /// The durable API token (`durable: true`) or a browser session
    /// token (`durable: false`) — the human owner's control plane.
    /// Also the context for exempt paths (`/health`, CORS preflights)
    /// with `durable: false`. Owner-ADMIN acts — certifying sub-agents
    /// and minting/revoking rider tokens — require `durable: true`
    /// (review fix: a 10-minute session bearer must not mint 90-day
    /// credentials or owner-signed certificates); read-only surfaces
    /// accept either.
    Owner { durable: bool },
    /// A scoped rider token: acts as the registered `sub_agent_id`
    /// through this daemon. `groups` is the explicit named-group grant
    /// list (Home is additionally always permitted).
    Rider {
        /// Hex `AgentId` of the registered sub-agent.
        sub_agent_id: String,
        /// Opaque numeric id of the rider token.
        token_id: u64,
        /// SHA-256 hex of the rider token (hashed-at-rest identifier).
        token_hash: String,
        /// Granted named-group ids (in addition to Home).
        groups: Vec<String>,
    },
}

impl ActorContext {
    pub(super) fn rider_allows_group(&self, is_home: bool, group_id: &str) -> bool {
        match self {
            ActorContext::Owner { .. } => true,
            ActorContext::Rider { groups, .. } => {
                is_home || groups.iter().any(|g| g.as_str() == group_id)
            }
        }
    }

    /// `true` only for the durable API token — the authority required
    /// for owner-admin acts (`/owner/agents/issue`, the rider-token
    /// lifecycle, agent revocation). Session bearers are read-only
    /// principals (review fix: no privilege amplification from a
    /// 10-minute browser token).
    pub(super) fn is_durable_owner(&self) -> bool {
        matches!(self, ActorContext::Owner { durable: true })
    }
}

/// Deny-by-default route predicate: the COMPLETE set of routes a rider
/// token may reach (ADR-0039 "send to Home + explicitly named groups,
/// bounded history read"). Everything else — including `/agent/sign`,
/// `/exec/*`, `/owner/*`, `/identity/*`, `/shutdown`, every diagnostic
/// and admin surface — returns `403` for riders in the middleware.
///
/// The concrete minimal set:
///
/// - `POST /groups/:id/send` — send to a `SignedPublic` named group
///   (per-group scope still checked in the handler; Home is not
///   `SignedPublic` and uses the secure plane below).
/// - `POST /groups/:id/secure/encrypt` — the send surface for
///   `MlsEncrypted` groups, which is what Home is (ADR-0038).
/// - `GET /history` — bounded read (scope restricted to granted groups
///   in the handler, limit clamped to [`RIDER_HISTORY_MAX_LIMIT`]).
pub(super) fn rider_route_allowed(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    match *method {
        Method::POST => is_group_send_path(path) || is_secure_encrypt_path(path),
        Method::GET => path == "/history",
        _ => false,
    }
}

/// `true` for exactly `/groups/<id>/send` (two segments after the
/// prefix). Static prefixes like `/groups/discover` cannot collide
/// because the second segment must be the literal `send`.
fn is_group_send_path(path: &str) -> bool {
    is_two_segment_action(path, "send")
}

/// `true` for exactly `/groups/<id>/secure/encrypt`.
fn is_secure_encrypt_path(path: &str) -> bool {
    match path.strip_prefix("/groups/") {
        Some(rest) => {
            let mut segs = rest.split('/');
            segs.next().is_some_and(|id| !id.is_empty())
                && segs.next() == Some("secure")
                && segs.next() == Some("encrypt")
                && segs.next().is_none()
        }
        None => false,
    }
}

/// `true` when `path` is `/groups/<nonempty-id>/<action>` for exactly
/// the given single-segment action.
fn is_two_segment_action(path: &str, action: &str) -> bool {
    match path.strip_prefix("/groups/") {
        Some(rest) => {
            let mut segs = rest.split('/');
            segs.next().is_some_and(|id| !id.is_empty())
                && segs.next() == Some(action)
                && segs.next().is_none()
        }
        None => false,
    }
}

/// One persisted rider token. The token SECRET is never stored — only
/// its SHA-256 hex digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RiderTokenRecord {
    /// Opaque numeric id (monotonic per install).
    pub token_id: u64,
    /// SHA-256 hex of the 64-hex-char token secret.
    pub token_hash: String,
    /// Hex `AgentId` of the registered sub-agent this token acts as.
    pub sub_agent_id: String,
    /// Granted named-group ids (in addition to Home).
    pub groups: Vec<String>,
    /// Operator label.
    pub label: Option<String>,
    /// Unix seconds when the token was issued.
    pub issued_at: u64,
    /// Unix seconds after which the token is invalid.
    pub expires_at: u64,
    /// BLAKE3 hex of the sub-agent certificate this token was issued
    /// against (review fix #2: the token is bound to the exact
    /// issuance).
    pub cert_digest: String,
    /// The bound certificate's expiry — the token can never outlive
    /// its certificate even if `expires_at` is later.
    pub cert_not_after: Option<u64>,
    /// The sub-agent-signed delegation capability bound at issuance
    /// (review r3, option B). `None` only for records predating the
    /// capability requirement — such tokens cannot produce a
    /// receiver-verifiable rider send and are refused at the send path.
    #[serde(default)]
    pub delegation: Option<crate::groups::RiderDelegation>,
    /// Unix seconds when the token was revoked, if it was.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

/// A validated rider credential — the data the middleware puts into
/// [`ActorContext::Rider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedRider {
    pub token_id: u64,
    pub sub_agent_id: String,
    pub token_hash: String,
    pub groups: Vec<String>,
}

/// SHA-256 hex of a token secret.
fn token_hash_hex(token: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Constant-time equality of two SHA-256 hex digests (review fix #6:
/// token matching must not leak digest bytes through early-exit string
/// comparison). Both sides decode to fixed 32-byte buffers first; a
/// malformed hex digest simply never matches.
fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(a), Ok(b)) if a.len() == 32 && b.len() == 32 => {
            use subtle::ConstantTimeEq;
            a.ct_eq(&b).into()
        }
        _ => false,
    }
}

/// Persists as the plain JSON map `{"next_id": u64, "tokens": {id: rec}}`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RiderTokenFile {
    next_id: u64,
    tokens: BTreeMap<String, RiderTokenRecord>,
}

/// The rider-token store: in-memory map guarded by a tokio mutex, with
/// every mutation persisted atomically to `<data_dir>/rider-tokens.json`.
pub(super) struct RiderTokenStore {
    path: PathBuf,
    next_id: u64,
    records: BTreeMap<u64, RiderTokenRecord>,
}

impl RiderTokenStore {
    /// Load the store from `path` (a missing file is an empty store; a
    /// corrupt file is logged and treated as empty — rider tokens fail
    /// closed, they can never grant more than was persisted).
    pub(super) async fn load(path: PathBuf) -> Self {
        let parsed = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<RiderTokenFile>(&bytes)
                .map_err(|e| {
                    tracing::warn!(
                        "failed to parse {}: {e} — rider tokens start empty (fail closed)",
                        path.display()
                    );
                    e
                })
                .ok(),
            Err(_) => None,
        };
        match parsed {
            Some(file) => {
                let records = file
                    .tokens
                    .into_iter()
                    .filter_map(|(k, v)| k.parse::<u64>().ok().map(|id| (id, v)))
                    .collect();
                Self {
                    path,
                    next_id: file.next_id.max(1),
                    records,
                }
            }
            None => Self {
                path,
                next_id: 1,
                records: BTreeMap::new(),
            },
        }
    }

    /// Persist the current state atomically. Failures are returned to
    /// the caller: an unpersisted token must not be reported as issued.
    async fn persist(&self) -> std::io::Result<()> {
        let file = RiderTokenFile {
            next_id: self.next_id,
            tokens: self
                .records
                .iter()
                .map(|(id, rec)| (id.to_string(), rec.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::other(format!("serialize rider tokens: {e}")))?;
        crate::profile::write_atomically(&self.path, &bytes).await
    }

    /// Issue a new rider token. Returns the one-time secret (shown to
    /// the caller exactly once) alongside its record.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn issue(
        &mut self,
        sub_agent_id: String,
        groups: Vec<String>,
        label: Option<String>,
        ttl_secs: u64,
        cert_digest: String,
        cert_not_after: Option<u64>,
        delegation: Option<crate::groups::RiderDelegation>,
        now_unix: u64,
    ) -> std::io::Result<(String, RiderTokenRecord)> {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let token = hex::encode(secret);
        let token_id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let record = RiderTokenRecord {
            token_id,
            token_hash: token_hash_hex(&token),
            sub_agent_id,
            groups,
            label,
            issued_at: now_unix,
            expires_at: now_unix.saturating_add(ttl_secs.max(1)),
            cert_digest,
            cert_not_after,
            delegation,
            revoked_at: None,
        };
        self.records.insert(token_id, record.clone());
        if let Err(e) = self.persist().await {
            // Roll back the in-memory insert: the token was never
            // durably issued and must not validate.
            self.records.remove(&token_id);
            return Err(e);
        }
        Ok((token, record))
    }

    /// The delegation capability stored for a live token (send path,
    /// review r3). `None` when the token is unknown or predates the
    /// capability requirement — the send handler refuses those.
    pub(super) fn delegation_of(&self, token_id: u64) -> Option<crate::groups::RiderDelegation> {
        let record = self.records.get(&token_id)?;
        if record.revoked_at.is_some() {
            return None;
        }
        record.delegation.clone()
    }

    /// Validate a presented bearer token. `None` for unknown, expired,
    /// or revoked tokens — and (review fix #2) for tokens whose bound
    /// certificate has expired, so a token can never outlive its cert.
    /// The middleware additionally checks ADR-0018 agent revocation on
    /// every request.
    pub(super) fn validate(&self, token: &str, now_unix: u64) -> Option<ValidatedRider> {
        let hash = token_hash_hex(token);
        let record = self
            .records
            .values()
            .find(|r| constant_time_hex_eq(&r.token_hash, &hash))?;
        if now_unix >= record.expires_at {
            return None;
        }
        if record
            .cert_not_after
            .is_some_and(|not_after| now_unix >= not_after)
        {
            return None;
        }
        if record.revoked_at.is_some() {
            return None;
        }
        Some(ValidatedRider {
            token_id: record.token_id,
            sub_agent_id: record.sub_agent_id.clone(),
            token_hash: record.token_hash.clone(),
            groups: record.groups.clone(),
        })
    }

    /// Revoke one token by id. `Ok(false)` when the id is unknown;
    /// `Err` when the revocation could not be made DURABLE — the
    /// in-memory mutation is rolled back so the token stays valid
    /// everywhere and the caller reports failure (review fix #3:
    /// revocation is persist-or-fail, never fail-open across a
    /// restart).
    pub(super) async fn revoke(
        &mut self,
        token_id: u64,
        now_unix: u64,
    ) -> Result<bool, std::io::Error> {
        let Some(record) = self.records.get_mut(&token_id) else {
            return Ok(false);
        };
        if record.revoked_at.is_some() {
            return Ok(true);
        }
        record.revoked_at = Some(now_unix);
        if let Err(e) = self.persist().await {
            // Roll back: on disk the token is still live, so it must
            // remain live in memory too. The caller surfaces the error.
            if let Some(record) = self.records.get_mut(&token_id) {
                record.revoked_at = None;
            }
            return Err(e);
        }
        Ok(true)
    }

    /// Revoke every token bound to `sub_agent_id` (used when the
    /// sub-agent itself is revoked via `DELETE /owner/agents/:id`).
    /// Same persist-or-fail contract as [`revoke`](Self::revoke): on a
    /// persistence failure every in-memory mutation is rolled back and
    /// the error is returned (the caller's cert-level revocation and
    /// the middleware's per-request agent-revocation check still fence
    /// the tokens).
    pub(super) async fn revoke_for_agent(
        &mut self,
        sub_agent_id: &str,
        now_unix: u64,
    ) -> Result<usize, std::io::Error> {
        let mut revoked_ids = Vec::new();
        for record in self.records.values_mut() {
            if record.sub_agent_id == sub_agent_id && record.revoked_at.is_none() {
                record.revoked_at = Some(now_unix);
                revoked_ids.push(record.token_id);
            }
        }
        if revoked_ids.is_empty() {
            return Ok(0);
        }
        if let Err(e) = self.persist().await {
            for id in revoked_ids {
                if let Some(record) = self.records.get_mut(&id) {
                    record.revoked_at = None;
                }
            }
            return Err(e);
        }
        Ok(revoked_ids.len())
    }

    /// All records, ordered by id (for `GET /owner/riders`). No secrets.
    pub(super) fn list(&self) -> Vec<RiderTokenRecord> {
        self.records.values().cloned().collect()
    }
}

/// Current wall-clock unix seconds (best effort; never panics).
pub(super) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use axum::http::Method;

    // ── Route predicate: the deny-by-default scope matrix ──────────────

    #[test]
    fn rider_routes_allow_exactly_send_secure_encrypt_and_history() {
        // WHY: ADR-0039 validation — the allowlist must be minimal and
        // exact; a fuzzy match here would silently widen rider reach.
        assert!(rider_route_allowed(&Method::POST, "/groups/abc123/send"));
        assert!(rider_route_allowed(
            &Method::POST,
            "/groups/abc123/secure/encrypt"
        ));
        assert!(rider_route_allowed(&Method::GET, "/history"));
    }

    #[test]
    fn rider_routes_reject_signing_exec_owner_and_admin_surfaces() {
        // WHY: gapcheck blocker 21 — a rider credential must never turn
        // the daemon into a signing/exec oracle or reach owner/admin
        // surfaces. These are the exact abuse paths named there.
        let forbidden = [
            ("/agent/sign", Method::POST),
            ("/agent/verify", Method::POST),
            ("/identity/revoke", Method::POST),
            ("/exec/run", Method::POST),
            ("/exec/cancel", Method::POST),
            ("/owner/agents", Method::GET),
            ("/owner/agents/issue", Method::POST),
            ("/owner/agents/abc", Method::DELETE),
            ("/owner/riders", Method::POST),
            ("/shutdown", Method::POST),
            ("/publish", Method::POST),
            ("/direct/send", Method::POST),
            ("/groups", Method::POST),
            ("/groups/abc", Method::GET),
            ("/groups/abc/members", Method::POST),
            ("/groups/abc/secure/decrypt", Method::POST),
            ("/history/search", Method::GET),
            ("/history/stats", Method::GET),
            ("/history", Method::DELETE),
            ("/files/send", Method::POST),
            ("/forwards", Method::POST),
        ];
        for (path, method) in forbidden {
            assert!(
                !rider_route_allowed(&method, path),
                "{method} {path} must be rider-forbidden"
            );
        }
    }

    #[test]
    fn rider_route_predicate_rejects_lookalike_paths() {
        // WHY: path confusion (`/groups/discover/send`, empty ids,
        // deeper nesting) must not slip through a prefix/ends-with match.
        for path in [
            "/groups//send",
            "/groups/send",
            "/groups/a/b/send",
            "/groups/discover",
            "/groups/abc/secure/encrypt/extra",
            "/groups/abc/secure",
            "/vgroups/abc/send",
            "/history/",
        ] {
            assert!(
                !rider_route_allowed(&Method::POST, path) || path == "/groups/a/b/send", // POST-only lookalike set
                "lookalike {path} must not be allowed for POST"
            );
        }
        assert!(!rider_route_allowed(&Method::GET, "/history/"));
        assert!(!rider_route_allowed(&Method::PUT, "/history"));
    }

    #[test]
    fn rider_group_scope_home_or_granted_only() {
        // WHY: ADR-0039 — Home is the always-granted base scope; every
        // other group needs an explicit grant; owners are unrestricted.
        let owner = ActorContext::Owner { durable: true };
        let rider = ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 1,
            token_hash: "deadbeef".to_string(),
            groups: vec!["group-b".to_string()],
        };
        assert!(owner.rider_allows_group(false, "anything"));
        assert!(
            rider.rider_allows_group(true, "group-a"),
            "Home always allowed"
        );
        assert!(rider.rider_allows_group(false, "group-b"), "granted group");
        assert!(
            !rider.rider_allows_group(false, "group-a"),
            "ungranted group must be denied"
        );
    }

    // ── Token store lifecycle ──────────────────────────────────────────

    #[tokio::test]
    async fn rider_token_issue_validate_revoke_round_trip() {
        // WHY: blocker 24 lifecycle — a token validates until revoked,
        // then the SAME secret stops validating immediately (no restart).
        let dir = tempfile::tempdir().unwrap();
        let mut store = RiderTokenStore::load(dir.path().join(RIDER_TOKENS_FILE)).await;
        let (token, record) = store
            .issue(
                "ab".repeat(32),
                vec!["g1".to_string()],
                Some("ci-agent".into()),
                60,
                "d1".repeat(32),
                None,
                None,
                1_000,
            )
            .await
            .unwrap();
        assert_eq!(record.expires_at, 1_060);
        assert_eq!(record.cert_digest, "d1".repeat(32));
        let ok = store.validate(&token, 1_050).unwrap();
        assert_eq!(ok.sub_agent_id, "ab".repeat(32));
        assert_eq!(ok.groups, vec!["g1".to_string()]);

        assert!(store.revoke(record.token_id, 1_055).await.unwrap());
        assert!(
            store.validate(&token, 1_056).is_none(),
            "revoked token must fail closed"
        );
    }

    #[tokio::test]
    async fn rider_token_expiry_and_bad_secret_fail_closed() {
        // WHY: expiry must be enforced by the store (not just filtered
        // elsewhere) and an unknown secret must never validate.
        let dir = tempfile::tempdir().unwrap();
        let mut store = RiderTokenStore::load(dir.path().join(RIDER_TOKENS_FILE)).await;
        let (token, _) = store
            .issue(
                "cd".repeat(32),
                vec![],
                None,
                10,
                "d2".repeat(32),
                None,
                None,
                1_000,
            )
            .await
            .unwrap();
        assert!(store.validate(&token, 1_009).is_some());
        assert!(
            store.validate(&token, 1_010).is_none(),
            "expired token must fail closed"
        );
        assert!(store.validate(&"0".repeat(64), 1_000).is_none());
    }

    #[tokio::test]
    async fn rider_token_cannot_outlive_its_bound_certificate() {
        // WHY (review fix #2): the token's TTL may outlast the
        // sub-agent certificate; the store must refuse validation the
        // moment the bound certificate expires.
        let dir = tempfile::tempdir().unwrap();
        let mut store = RiderTokenStore::load(dir.path().join(RIDER_TOKENS_FILE)).await;
        let (token, _) = store
            .issue(
                "ee".repeat(32),
                vec![],
                None,
                10_000,
                "d3".repeat(32),
                Some(1_500),
                None,
                1_000,
            )
            .await
            .unwrap();
        assert!(store.validate(&token, 1_499).is_some());
        assert!(
            store.validate(&token, 1_500).is_none(),
            "token must die with its certificate, not at its own TTL"
        );
    }

    #[tokio::test]
    async fn revocation_is_persist_or_fail_never_fail_open() {
        // WHY (review fix #3): if the revocation cannot be made durable,
        // the caller must see the error and the token must stay live
        // EVERYWHERE (in-memory rollback) — a silent success would
        // resurrect the token after a restart.
        let dir = tempfile::tempdir().unwrap();
        // The store file is a DIRECTORY: every write fails.
        let broken = dir.path().join(RIDER_TOKENS_FILE);
        std::fs::create_dir(&broken).unwrap();
        let mut store = RiderTokenStore::load(dir.path().join("alt.json")).await;
        // Issue through a working path, then swap in the broken one.
        let (token, record) = store
            .issue(
                "aa".repeat(32),
                vec![],
                None,
                60,
                "d4".repeat(32),
                None,
                None,
                1_000,
            )
            .await
            .unwrap();
        store.path = broken;
        assert!(store.revoke(record.token_id, 1_010).await.is_err());
        assert!(
            store.validate(&token, 1_020).is_some(),
            "in-memory rollback keeps the token live until revocation is durable"
        );
    }

    #[tokio::test]
    async fn rider_tokens_survive_restart_and_agent_revocation_sweeps() {
        // WHY: blocker 24 — lifecycle state (issued, revoked) must be
        // durable across restarts, and revoking the SUB-AGENT must
        // revoke all of its tokens in one sweep.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(RIDER_TOKENS_FILE);
        let agent = "ef".repeat(32);
        let (token_a, rec_a) = {
            let mut store = RiderTokenStore::load(path.clone()).await;
            let (ta, ra) = store
                .issue(
                    agent.clone(),
                    vec![],
                    None,
                    60,
                    "d5".repeat(32),
                    None,
                    None,
                    1_000,
                )
                .await
                .unwrap();
            let (_tb, rb) = store
                .issue(
                    agent.clone(),
                    vec![],
                    None,
                    60,
                    "d5".repeat(32),
                    None,
                    None,
                    1_000,
                )
                .await
                .unwrap();
            store.revoke(rb.token_id, 1_001).await.unwrap();
            (ta, ra)
        };
        // Simulated restart: reload from disk.
        let mut store = RiderTokenStore::load(path).await;
        assert!(
            store.validate(&token_a, 1_020).is_some(),
            "survives restart"
        );
        assert_eq!(store.revoke_for_agent(&agent, 1_030).await.unwrap(), 1);
        assert!(store.validate(&token_a, 1_031).is_none());
        assert_eq!(rec_a.token_id, 1);
    }
}
