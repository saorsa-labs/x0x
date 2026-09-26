//! #946: GROUP-SCOPED roster-certificate fetch for digest-only seats.
//!
//! A digest-only seat (`certificate == None && certificate_digest.is_some()`)
//! blocks an OwnerCertified seal while the certificate's bytes are in no
//! local cache. The seal PUBLISHES a request for the seat's roster digest
//! on the GROUP'S OWN metadata topic — never the global identity topic,
//! whose responder serves only its own pair (#656) — and returns without
//! waiting (no network wait under the membership lock). That seal still
//! refuses; the joiner's MemberJoined retry re-drives it.
//!
//! Who answers: only a daemon that (1) holds the group, (2) received the
//! request from a VERIFIED sender who is an ACTIVE ROSTER member of the
//! topic's group, (3) is itself an active roster member, (4) finds the
//! digest in the group's CURRENT roster, and (5) holds a cached pair whose
//! certificate hashes to the digest, binds that roster member, and whose
//! user is the group's OwnerCertified owner. Per (stable group id,
//! digest) it answers at most once per 30 s and suppresses a miss for
//! 60 s; that suppression check runs BEFORE the cache hash scan.
//!
//! The requester considers a response only when it is VERIFIED, arrives
//! on the topic of the group it names, carries a digest this node itself
//! requested in the last 60 s, hashes to that digest, and names a seat
//! that is still digest-only. All of that is checked without the write
//! lock, before the durable persist. The persist re-checks the seat, the
//! agent binding and the owner user; a pair that fails any check is
//! dropped, never cached. The next seal retry finds the hydrated seat.

use serde::{Deserialize, Serialize};

use super::{now_millis_u64, LogHexId};
use crate::server::state::AppState;

/// Wire domain for a group-scoped roster-certificate request.
pub(in crate::server) const GROUP_CERT_FETCH_DOMAIN: &[u8] = b"x0x/group-cert-fetch-v1\0";
/// Wire domain for the answer.
pub(in crate::server) const GROUP_CERT_FETCH_RESPONSE_DOMAIN: &[u8] =
    b"x0x/group-cert-fetch-response-v1\0";
/// Requester: how long a requested digest is suppressed after a publish
/// (in-flight dedup), and how long a response for it is accepted.
pub(in crate::server) const CERT_FETCH_REQUESTED_TTL_MS: u64 = 60_000;
/// Responder: minimum spacing between answers for one digest in one group.
pub(in crate::server) const CERT_FETCH_ANSWER_INTERVAL_MS: u64 = 30_000;
/// Responder: how long a failed roster/cache lookup is negatively cached.
pub(in crate::server) const CERT_FETCH_MISS_TTL_MS: u64 = 60_000;
/// Absolute cap on the responder suppression map and the deadline-stamp
/// map (both are keyed by peer-supplied values).
pub(in crate::server) const CERT_FETCH_CACHE_MAX_ENTRIES: usize = 4096;
/// How long a certificate-unobtainable seal refusal stays RETRYABLE
/// before the typed (terminal) refusal is staged.
pub(in crate::server) const CERT_EVIDENCE_DEADLINE_MS: u64 = 10 * 60_000;

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::server) struct GroupCertFetchRequest {
    pub group_id: String,
    pub cert_digest: String,
    pub requester: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(in crate::server) struct GroupCertFetchResponse {
    pub group_id: String,
    pub cert_digest: String,
    /// serde_json bytes of the verified `AgentCertificate`.
    pub cert_json_b64: String,
}

/// One continuous window of certificate-unobtainable seal refusals for a
/// (stable group id, joining member) pair.
#[derive(Debug, Clone)]
pub(in crate::server) struct CertEvidenceStamp {
    /// First refusal of the current window (unix ms).
    pub(in crate::server) first_ms: u64,
    /// Most recent refusal (unix ms). A gap longer than
    /// [`CERT_EVIDENCE_DEADLINE_MS`] ends the window.
    pub(in crate::server) last_ms: u64,
    /// The join attempt the window belongs to. A different attempt (a
    /// re-invite) starts a new window.
    pub(in crate::server) attempt_id: String,
}

/// The ONE key spelling for a deadline stamp: the group's STABLE id (never
/// the local map key) and the joining member's agent hex.
pub(in crate::server) fn cert_evidence_stamp_key(
    stable_group_id: &str,
    member_agent_id: &str,
) -> String {
    format!("{stable_group_id}\u{0}{member_agent_id}")
}

/// blake3(bincode(cert)) — the roster-seat digest rule (mirrors
/// `announce_blob::find_by_cert_digest`).
fn cert_digest_bincode(cert: &crate::identity::AgentCertificate) -> [u8; 32] {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    *blake3::hash(&bytes).as_bytes()
}

/// A roster digest is 32 bytes of lowercase-or-uppercase hex.
fn parse_digest_hex(digest_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(digest_hex).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

/// The seal-side entry — PUBLISH the request and return; never wait.
/// `digest_hex` is the seat's committed roster digest. Suppressed per
/// digest while a request from the last [`CERT_FETCH_REQUESTED_TTL_MS`]
/// is outstanding.
pub(in crate::server) fn publish_group_cert_fetch(
    state: &AppState,
    metadata_topic: &str,
    stable_group_id: &str,
    digest_hex: &str,
) {
    let now = std::time::Instant::now();
    {
        let mut requested = state
            .cert_fetch_requested
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Sweep expired entries while we hold the lock (bounded by the
        // roster-scale digest universe).
        requested.retain(|_, at| {
            let elapsed_ms = now.duration_since(*at).as_millis() as u64;
            elapsed_ms < CERT_FETCH_REQUESTED_TTL_MS
        });
        if requested.contains_key(digest_hex) {
            return;
        }
        requested.insert(digest_hex.to_string(), now);
    }
    let request = GroupCertFetchRequest {
        group_id: stable_group_id.to_string(),
        cert_digest: digest_hex.to_string(),
        requester: hex::encode(state.agent.agent_id().as_bytes()),
    };
    let Ok(json) = serde_json::to_vec(&request) else {
        return;
    };
    let mut payload = Vec::with_capacity(GROUP_CERT_FETCH_DOMAIN.len() + json.len());
    payload.extend_from_slice(GROUP_CERT_FETCH_DOMAIN);
    payload.extend_from_slice(&json);
    let topic = metadata_topic.to_string();
    let pubsub = state.agent.pubsub();
    let digest_hex = digest_hex.to_string();
    tokio::spawn(async move {
        let Some(pubsub) = pubsub else { return };
        if let Err(e) = pubsub.publish(topic, bytes::Bytes::from(payload)).await {
            tracing::debug!(
                cert_digest = %digest_hex,
                %e,
                "#946: group-scoped certificate fetch publish failed"
            );
        }
    });
}

/// `true` while this node's own request for `digest_hex` is in flight.
fn cert_fetch_in_flight(state: &AppState, digest_hex: &str) -> bool {
    let now = std::time::Instant::now();
    state
        .cert_fetch_requested
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(digest_hex)
        .is_some_and(|at| {
            (now.duration_since(*at).as_millis() as u64) < CERT_FETCH_REQUESTED_TTL_MS
        })
}

/// Responder suppression key: (stable group id, digest).
fn responder_key(stable_group_id: &str, digest_hex: &str) -> String {
    format!("{stable_group_id}\u{0}{digest_hex}")
}

/// `true` while `key` is suppressed (a recent answer or miss).
fn responder_suppressed(state: &AppState, key: &str, now: std::time::Instant) -> bool {
    state
        .cert_fetch_answered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .is_some_and(|until| *until > now)
}

/// Suppress `key` for `ttl_ms` unless it is already suppressed. Returns
/// `true` when this call set the suppression. The map stores each key's
/// suppression deadline; expired entries are swept on every call and the
/// map is capped at [`CERT_FETCH_CACHE_MAX_ENTRIES`] (oldest deadline
/// evicted first).
fn responder_try_suppress(
    state: &AppState,
    key: String,
    now: std::time::Instant,
    ttl_ms: u64,
) -> bool {
    let mut suppressed = state
        .cert_fetch_answered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    suppressed.retain(|_, until| *until > now);
    if suppressed.contains_key(&key) {
        return false;
    }
    if suppressed.len() >= CERT_FETCH_CACHE_MAX_ENTRIES {
        if let Some(oldest) = suppressed
            .iter()
            .min_by_key(|(_, until)| **until)
            .map(|(k, _)| k.clone())
        {
            suppressed.remove(&oldest);
        }
    }
    suppressed.insert(key, now + std::time::Duration::from_millis(ttl_ms));
    true
}

/// The responder branch. Returns `true` when it answered. The metadata
/// listener calls this for every GROUP_CERT_FETCH message; the payload has
/// already been domain-matched by the caller.
pub(in crate::server) async fn handle_group_cert_fetch_request(
    state: &std::sync::Arc<AppState>,
    raw: &[u8],
    sender: Option<&crate::identity::AgentId>,
    verified: bool,
    topic_group_key: &str,
) -> bool {
    // Unverified or anonymous senders are ignored outright.
    if !verified {
        return false;
    }
    let Some(sender) = sender else {
        return false;
    };
    let Ok(request) = serde_json::from_slice::<GroupCertFetchRequest>(raw) else {
        return false;
    };
    let Some(digest_arr) = parse_digest_hex(&request.cert_digest) else {
        return false;
    };
    let now = std::time::Instant::now();
    // Resolve the group (either spelling) and validate the request against
    // the CURRENT owner-signed roster under one read. The lock is released
    // BEFORE the cache hash scan.
    let (stable_group_id, metadata_topic, owner_user, member_agent_hex) = {
        let groups = state.named_groups.read().await;
        let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, &request.group_id)
        else {
            return false;
        };
        if info.withdrawn {
            return false;
        }
        // The request's group must BE the topic's group (compare stable
        // ids: the map key may spell differently), and the SENDER must be
        // an ACTIVE ROSTER member of it — a stranger relaying a request
        // onto the topic gets nothing.
        let Some((_, topic_info)) =
            crate::server::resolve_group_entry_locked(&groups, topic_group_key)
        else {
            return false;
        };
        if info.stable_group_id() != topic_info.stable_group_id() {
            return false;
        }
        if !info.has_active_member(&hex::encode(sender.as_bytes())) {
            return false;
        }
        // We only answer for groups we are an active member of.
        if !info.has_active_member(&hex::encode(state.agent.agent_id().as_bytes())) {
            return false;
        }
        let Some(owner) = info.policy.admission.owner_certified_user_id().copied() else {
            return false;
        };
        // The digest must be in the CURRENT roster; it identifies the
        // member seat it belongs to.
        let member_agent_hex = info.members_v2.values().find_map(|seat| {
            (seat.certificate_digest.as_deref() == Some(request.cert_digest.as_str()))
                .then(|| seat.agent_id.clone())
        });
        (
            info.stable_group_id().to_string(),
            info.metadata_topic.clone(),
            owner,
            member_agent_hex,
        )
    };
    // C5: a recent answer or miss for this (group, digest) suppresses the
    // request BEFORE any hash scan of the cache.
    let key = responder_key(&stable_group_id, &request.cert_digest);
    if responder_suppressed(state, &key, now) {
        return false;
    }
    let Some(member_agent_hex) = member_agent_hex else {
        responder_try_suppress(state, key, now, CERT_FETCH_MISS_TTL_MS);
        return false;
    };
    // A cached pair whose certificate hashes to the digest — scanned with
    // NO named_groups lock held.
    let blob = state
        .agent
        .announce_blob_cache
        .find_by_cert_digest(&digest_arr)
        .await;
    let Some(cert) = blob
        .as_ref()
        .and_then(|blob| blob.agent_certificate.as_ref())
    else {
        responder_try_suppress(state, key, now, CERT_FETCH_MISS_TTL_MS);
        return false;
    };
    // The pair's user must be the group's OWNER user, and the certificate
    // must bind the roster member the digest belongs to.
    let user_is_owner = blob
        .as_ref()
        .is_some_and(|blob| blob.user_id.as_ref() == Some(&owner_user));
    if !user_is_owner
        || !cert
            .agent_id()
            .is_ok_and(|id| hex::encode(id.as_bytes()) == member_agent_hex)
    {
        tracing::debug!(
            group_id = %LogHexId::group(&stable_group_id),
            "#946: cached pair for a roster digest fails the owner/binding check; not served"
        );
        responder_try_suppress(state, key, now, CERT_FETCH_MISS_TTL_MS);
        return false;
    }
    let cert = cert.clone();
    // Rate limit: claim the answer slot (1 answer per digest per interval
    // per group); a concurrent request that claimed it first wins.
    if !responder_try_suppress(state, key, now, CERT_FETCH_ANSWER_INTERVAL_MS) {
        return false;
    }
    let response = GroupCertFetchResponse {
        group_id: stable_group_id.clone(),
        cert_digest: request.cert_digest.clone(),
        cert_json_b64: {
            use base64::Engine as _;
            let json = serde_json::to_vec(&cert).unwrap_or_default();
            base64::engine::general_purpose::STANDARD.encode(json)
        },
    };
    let Ok(json) = serde_json::to_vec(&response) else {
        return false;
    };
    let mut payload = Vec::with_capacity(GROUP_CERT_FETCH_RESPONSE_DOMAIN.len() + json.len());
    payload.extend_from_slice(GROUP_CERT_FETCH_RESPONSE_DOMAIN);
    payload.extend_from_slice(&json);
    let pubsub = state.agent.pubsub();
    tokio::spawn(async move {
        let Some(pubsub) = pubsub else { return };
        if let Err(e) = pubsub
            .publish(metadata_topic, bytes::Bytes::from(payload))
            .await
        {
            tracing::debug!(
                group_id = %LogHexId::group(&stable_group_id),
                %e,
                "#946: group-scoped certificate answer publish failed"
            );
        }
    });
    true
}

/// The requester's response branch: verify the certificate against the
/// live group's roster seat and OWNER user, then hydrate the seat
/// DURABLY. A pair that fails any check is dropped — never cached.
pub(in crate::server) async fn handle_group_cert_fetch_response(
    state: &std::sync::Arc<AppState>,
    raw: &[u8],
    verified: bool,
    topic_group_key: &str,
) -> bool {
    use base64::Engine as _;
    // C5: every check before the persist is cheap and takes no write
    // lock. The persist clones the whole groups map under the global
    // write lock, so only a response this node is actually waiting for
    // may reach it.
    if !verified {
        return false;
    }
    let Ok(response) = serde_json::from_slice::<GroupCertFetchResponse>(raw) else {
        return false;
    };
    if !cert_fetch_in_flight(state, &response.cert_digest) {
        return false;
    }
    let Ok(cert_json) = base64::engine::general_purpose::STANDARD.decode(&response.cert_json_b64)
    else {
        return false;
    };
    let Ok(cert) = serde_json::from_slice::<crate::identity::AgentCertificate>(&cert_json) else {
        return false;
    };
    // The certificate must hash to the response's own digest claim.
    if hex::encode(cert_digest_bincode(&cert)) != response.cert_digest {
        tracing::debug!("#946: certificate does not hash to the claimed digest; dropped");
        return false;
    }
    // Read-lock pre-check: the named group is the topic's group and still
    // has a digest-only seat with this digest.
    let stable_group_id = {
        let groups = state.named_groups.read().await;
        let Some((_, info)) =
            crate::server::resolve_group_entry_locked(&groups, &response.group_id)
        else {
            return false;
        };
        let Some((_, topic_info)) =
            crate::server::resolve_group_entry_locked(&groups, topic_group_key)
        else {
            return false;
        };
        if info.withdrawn || info.stable_group_id() != topic_info.stable_group_id() {
            return false;
        }
        let pending = info.members_v2.values().any(|seat| {
            seat.certificate.is_none()
                && seat.certificate_digest.as_deref() == Some(response.cert_digest.as_str())
        });
        if !pending {
            return false;
        }
        info.stable_group_id().to_string()
    };
    // Verify + hydrate under one mutation: the seat must still be
    // digest-only with THIS digest, the certificate must bind the seat's
    // agent, and the pair's user must be the group's owner.
    let mutate_group_id = stable_group_id.clone();
    let cert_digest = response.cert_digest.clone();
    let mutate =
        move |groups: &mut std::collections::HashMap<String, crate::groups::GroupInfo>| -> bool {
            let Some((key, info)) =
                crate::server::resolve_group_entry_locked(groups, &mutate_group_id)
            else {
                return false;
            };
            if info.withdrawn {
                return false;
            }
            let Some(owner) = info.policy.admission.owner_certified_user_id().copied() else {
                return false;
            };
            let seat_agent = info.members_v2.values().find_map(|seat| {
                (seat.certificate.is_none()
                    && seat.certificate_digest.as_deref() == Some(cert_digest.as_str()))
                .then(|| seat.agent_id.clone())
            });
            let Some(seat_agent) = seat_agent else {
                return false;
            };
            if !cert
                .agent_id()
                .is_ok_and(|id| hex::encode(id.as_bytes()) == seat_agent)
            {
                return false;
            }
            if cert.user_id().ok() != Some(owner) {
                tracing::debug!("#946: fetched certificate's user is not the group owner; dropped");
                return false;
            }
            let key = key.to_string();
            let Some(info) = groups.get_mut(&key) else {
                return false;
            };
            info.set_member_certificate(&seat_agent, cert).is_ok()
        };
    match super::persist_named_groups_mutation(state, mutate).await {
        Ok(super::AtomicWriteOutcome::Durable) => {
            // C3: the unavailability is over — a later gap (or a rejoin)
            // starts a fresh window instead of going instantly terminal.
            clear_cert_evidence_stamps(state, &stable_group_id, None);
            // Nothing further is awaited for this digest.
            state
                .cert_fetch_requested
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&response.cert_digest);
            tracing::info!(
                group_id = %LogHexId::group(&stable_group_id),
                "#946: group-scoped fetch hydrated a digest-only seat"
            );
            true
        }
        _ => false,
    }
}

/// Record a certificate-unobtainable refusal for `member_agent_id`'s join
/// `attempt_id` and report whether the typed (terminal) refusal may be
/// staged: `true` only once the refusals have continued for
/// [`CERT_EVIDENCE_DEADLINE_MS`]. A window ends when no refusal is seen
/// for longer than the deadline, or when a different join attempt (a
/// re-invite) arrives.
pub(in crate::server) fn cert_evidence_deadline_elapsed(
    state: &AppState,
    stable_group_id: &str,
    member_agent_id: &str,
    attempt_id: &str,
) -> bool {
    let key = cert_evidence_stamp_key(stable_group_id, member_agent_id);
    let now_ms = now_millis_u64();
    let mut since = state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    since.retain(|_, stamp| now_ms.saturating_sub(stamp.last_ms) <= CERT_EVIDENCE_DEADLINE_MS);
    if let Some(stamp) = since.get_mut(&key) {
        if stamp.attempt_id == attempt_id {
            stamp.last_ms = now_ms;
            return now_ms.saturating_sub(stamp.first_ms) >= CERT_EVIDENCE_DEADLINE_MS;
        }
    }
    if since.len() >= CERT_FETCH_CACHE_MAX_ENTRIES && !since.contains_key(&key) {
        if let Some(oldest) = since
            .iter()
            .min_by_key(|(_, stamp)| stamp.last_ms)
            .map(|(k, _)| k.clone())
        {
            since.remove(&oldest);
        }
    }
    since.insert(
        key,
        CertEvidenceStamp {
            first_ms: now_ms,
            last_ms: now_ms,
            attempt_id: attempt_id.to_string(),
        },
    );
    false
}

/// Clear deadline stamps for `stable_group_id`: one member's, or every
/// member's when `member_agent_id` is `None`.
pub(in crate::server) fn clear_cert_evidence_stamps(
    state: &AppState,
    stable_group_id: &str,
    member_agent_id: Option<&str>,
) {
    let mut since = state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match member_agent_id {
        Some(member) => {
            since.remove(&cert_evidence_stamp_key(stable_group_id, member));
        }
        None => {
            let prefix = cert_evidence_stamp_key(stable_group_id, "");
            since.retain(|key, _| !key.starts_with(&prefix));
        }
    }
}

/// [`clear_cert_evidence_stamps`] for a group named by either spelling
/// (map key or stable id). Takes the `named_groups` read lock, so callers
/// must not hold it.
pub(in crate::server) async fn clear_cert_evidence_stamps_for(
    state: &AppState,
    group_id: &str,
    member_agent_id: Option<&str>,
) {
    let stable_group_id = {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, group_id)
            .map(|(_, info)| info.stable_group_id().to_string())
    };
    // An unresolvable spelling is taken as the stable id itself.
    let stable_group_id = stable_group_id.unwrap_or_else(|| group_id.to_string());
    clear_cert_evidence_stamps(state, &stable_group_id, member_agent_id);
}
