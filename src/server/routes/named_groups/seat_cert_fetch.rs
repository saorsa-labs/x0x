//! #946 r2 (Root design): GROUP-SCOPED roster-certificate fetch.
//!
//! A digest-only seat (`certificate == None && certificate_digest.is_some()`)
//! blocks an OwnerCertified seal while the certificate's bytes are in no
//! local cache. The seal now PUBLISHES a request for the seat's roster
//! digest on the GROUP'S OWN metadata topic — never the global identity
//! topic — and continues without waiting (no network wait under the
//! membership lock, #946 review item D).
//!
//! Who answers (item A — #656 is preserved for the global responder):
//! only a daemon that (1) holds the group live, (2) has its OWN agent as
//! an ACTIVE ROSTER member of that group, (3) finds the requested digest
//! in that group's CURRENT owner-signed roster, and (4) holds a VERIFIED
//! cached pair (the announce-blob cache) whose certificate hashes to the
//! digest, binds the roster member, and whose `user_id` equals the
//! group's OwnerCertified owner user (item C). Answers are rate-limited
//! to one per digest per 30 s per group, and lookups that miss are
//! negatively cached for 60 s so a missing certificate cannot be polled
//! into a storm.
//!
//! The requester marks each requested digest for 60 s (in-flight dedup +
//! negative cache) and hydrates a seat ONLY from a response that passes
//! the full verification (hash, agent binding, owner user) — a pair that
//! failed any check is never cached (item C). The next seal retry (the
//! MemberJoined cadence) finds the hydrated seat and succeeds; the
//! existing retry loop is the re-drive, so the serial apply loop never
//! blocks on the network (item D).

use serde::{Deserialize, Serialize};

use super::{now_millis_u64, LogHexId};
use crate::server::state::AppState;

/// Wire domain for a group-scoped roster-certificate request.
pub(in crate::server) const GROUP_CERT_FETCH_DOMAIN: &[u8] = b"x0x/group-cert-fetch-v1\0";
/// Wire domain for the answer.
pub(in crate::server) const GROUP_CERT_FETCH_RESPONSE_DOMAIN: &[u8] =
    b"x0x/group-cert-fetch-response-v1\0";
/// Requester: how long a requested digest is suppressed after a publish
/// (in-flight dedup) or a miss (negative cache).
pub(in crate::server) const CERT_FETCH_REQUESTED_TTL_MS: u64 = 60_000;
/// Responder: minimum spacing between answers for one digest in one group.
pub(in crate::server) const CERT_FETCH_ANSWER_INTERVAL_MS: u64 = 30_000;
/// Responder: how long a failed roster/cache lookup is negatively cached.
pub(in crate::server) const CERT_FETCH_MISS_TTL_MS: u64 = 60_000;
/// C5: absolute cap on the (attacker-keyed) responder cache map.
pub(in crate::server) const CERT_FETCH_CACHE_MAX_ENTRIES: usize = 4096;
/// Item B: how long a certificate-unobtainable seal refusal stays
/// RETRYABLE before the typed (terminal) refusal is staged.
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

/// blake3(bincode(cert)) — the roster-seat digest rule (mirrors
/// `announce_blob::find_by_cert_digest`).
fn cert_digest_bincode(cert: &crate::identity::AgentCertificate) -> [u8; 32] {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    *blake3::hash(&bytes).as_bytes()
}

/// Item D: the seal-side entry — PUBLISH the request and return; never
/// wait. `digest_hex` is the seat's committed roster digest. Suppressed
/// per digest while a recent request is outstanding or negatively cached.
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

/// The REAL responder branch (item A). Returns `true` when it answered.
/// Routing: the metadata listener calls this for every GROUP_CERT_FETCH
/// message; the payload has already been domain-matched by the caller.
pub(in crate::server) async fn handle_group_cert_fetch_request(
    state: &std::sync::Arc<AppState>,
    raw: &[u8],
    sender: Option<&crate::identity::AgentId>,
    verified: bool,
    topic_group_key: &str,
) -> bool {
    let Ok(request) = serde_json::from_slice::<GroupCertFetchRequest>(raw) else {
        return false;
    };
    // C1 (security): unverified senders are ignored outright.
    if !verified {
        return false;
    }
    let Some(sender) = sender else {
        return false;
    };
    let now = std::time::Instant::now();
    // Resolve the group (both spellings) and validate the requester's
    // target against the CURRENT owner-signed roster, all under one read;
    // the lock is released BEFORE the cache hash scan (C5).
    let (metadata_topic, owner_user, member_agent_hex) = {
        let groups = state.named_groups.read().await;
        let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, &request.group_id)
        else {
            return false;
        };
        if info.withdrawn {
            return false;
        }
        // C1: the request's group id must BE the topic's group (the
        // stable id may spell differently than the map key, so compare
        // stable ids), and the SENDER must be an ACTIVE ROSTER member of
        // this same group — a stranger relaying a request onto the topic
        // gets nothing.
        let Some(topic_info) = groups.get(topic_group_key) else {
            return false;
        };
        if info.stable_group_id() != topic_info.stable_group_id() {
            return false;
        }
        let sender_hex = hex::encode(sender.as_bytes());
        if !info.has_active_member(&sender_hex) {
            return false;
        }
        // (2) our own agent must be an ACTIVE ROSTER member of this group
        // (we only answer for groups we are in).
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        if !info.has_active_member(&local_hex) {
            return false;
        }
        // (3) the digest must be in the CURRENT roster, and identify
        // exactly the member seat it belongs to. C5: the negative cache
        // fires BEFORE any hash scan.
        let Some(owner) = info.policy.admission.owner_certified_user_id().copied() else {
            return false;
        };
        let Some(member_agent_hex) = info.members_v2.values().find_map(|seat| {
            (seat.certificate_digest.as_deref() == Some(&request.cert_digest))
                .then(|| seat.agent_id.clone())
        }) else {
            record_responder_miss(state, &request.group_id, &request.cert_digest, now);
            return false;
        };
        (info.metadata_topic.clone(), owner, member_agent_hex)
    };
    // (4) a VERIFIED cached pair whose certificate hashes to the digest —
    // scanned with NO named_groups lock held (C5).
    let Ok(digest_bytes) = hex::decode(&request.cert_digest) else {
        return false;
    };
    let Ok(digest_arr): Result<[u8; 32], _> = <[u8; 32]>::try_from(digest_bytes) else {
        return false;
    };
    let blob = state
        .agent
        .announce_blob_cache
        .find_by_cert_digest(&digest_arr)
        .await;
    let Some(blob) = blob else {
        record_responder_miss(state, &request.group_id, &request.cert_digest, now);
        return false;
    };
    let Some(cert) = blob.agent_certificate.as_ref() else {
        record_responder_miss(state, &request.group_id, &request.cert_digest, now);
        return false;
    };
    // Item C: the pair's user must be the group's OWNER user, and the
    // certificate must bind the roster member the digest belongs to.
    if blob.user_id.as_ref() != Some(&owner_user)
        || !cert
            .agent_id()
            .is_ok_and(|id| hex::encode(id.as_bytes()) == member_agent_hex)
    {
        tracing::debug!(
            group_id = %LogHexId::group(&request.group_id),
            "#946: cached pair for a roster digest fails the owner/binding check; not served"
        );
        record_responder_miss(state, &request.group_id, &request.cert_digest, now);
        return false;
    }
    let cert = cert.clone();
    // Responder rate limit: 1 answer per digest per interval per group.
    {
        let key = format!("{}\u{0}{}", request.group_id, request.cert_digest);
        let mut answered = state
            .cert_fetch_answered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Sweep entries past the negative-cache TTL so the map stays
        // bounded by the live (group, digest) universe.
        answered.retain(|_, at| {
            let elapsed_ms = now.duration_since(*at).as_millis() as u64;
            elapsed_ms < CERT_FETCH_MISS_TTL_MS
        });
        if answered.get(&key).is_some_and(|at| {
            let elapsed_ms = now.duration_since(*at).as_millis() as u64;
            elapsed_ms < CERT_FETCH_ANSWER_INTERVAL_MS
        }) {
            return false;
        }
        answered.insert(key, now);
    }
    let response = GroupCertFetchResponse {
        group_id: request.group_id.clone(),
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
    let group_id = request.group_id.clone();
    tokio::spawn(async move {
        let Some(pubsub) = pubsub else { return };
        if let Err(e) = pubsub
            .publish(metadata_topic, bytes::Bytes::from(payload))
            .await
        {
            tracing::debug!(
                group_id = %LogHexId::group(&group_id),
                %e,
                "#946: group-scoped certificate answer publish failed"
            );
        }
    });
    true
}

fn record_responder_miss(state: &AppState, group_id: &str, digest: &str, now: std::time::Instant) {
    let key = format!("{}\u{0}{}", group_id, digest);
    let mut answered = state
        .cert_fetch_answered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // C5: the map is ATTACKER-KEYED (a stranger can request arbitrary
    // digests) — sweep expired entries on every insert so it stays
    // bounded by the live universe, and cap it absolutely.
    answered.retain(|_, at| {
        let elapsed_ms = now.duration_since(*at).as_millis() as u64;
        elapsed_ms < CERT_FETCH_MISS_TTL_MS
    });
    if answered.len() >= CERT_FETCH_CACHE_MAX_ENTRIES && !answered.contains_key(&key) {
        if let Some(oldest) = answered
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        {
            answered.remove(&oldest);
        }
    }
    answered.insert(key, now);
}

/// The requester's response branch (items A + C): verify the certificate
/// against the live group's roster seat and OWNER user, then hydrate the
/// seat DURABLY. A pair that fails any check is dropped — never cached.
pub(in crate::server) async fn handle_group_cert_fetch_response(
    state: &std::sync::Arc<AppState>,
    raw: &[u8],
) -> bool {
    use base64::Engine as _;
    let Ok(response) = serde_json::from_slice::<GroupCertFetchResponse>(raw) else {
        return false;
    };
    let Ok(cert_json) = base64::engine::general_purpose::STANDARD.decode(&response.cert_json_b64)
    else {
        return false;
    };
    let Ok(cert) = serde_json::from_slice::<crate::identity::AgentCertificate>(&cert_json) else {
        return false;
    };
    // Hash check FIRST (item C): the certificate must hash to the
    // response's own digest claim.
    if hex::encode(cert_digest_bincode(&cert)) != response.cert_digest {
        tracing::debug!("#946: certificate does not hash to the claimed digest; dropped");
        return false;
    }
    // Verify + hydrate under one mutation: the seat must still be
    // digest-only with THIS digest, the certificate must bind the seat's
    // agent, and the pair's user must be the group's owner.
    let group_id = response.group_id.clone();
    let cert_digest = response.cert_digest.clone();
    let cert = cert.clone();
    let mutate =
        move |groups: &mut std::collections::HashMap<String, crate::groups::GroupInfo>| -> bool {
            let Some((_, info)) = crate::server::resolve_group_entry_locked(groups, &group_id)
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
                    && seat.certificate_digest.as_deref() == Some(&cert_digest))
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
            // Mutate the resolved entry.
            let Some(key) = groups
                .iter()
                .find(|(_, i)| i.stable_group_id() == info.stable_group_id())
                .map(|(k, _)| k.clone())
            else {
                return false;
            };
            let Some(info) = groups.get_mut(&key) else {
                return false;
            };
            info.set_member_certificate(&seat_agent, cert).is_ok()
        };
    match super::persist_named_groups_mutation(state, mutate).await {
        Ok(super::AtomicWriteOutcome::Durable) => {
            // C3: the unavailability is OVER — clear the retryable-refusal
            // deadline stamp for this group so a LATER gap (or a rejoin)
            // starts a fresh 10-minute window instead of going instantly
            // terminal.
            {
                let mut since = state
                    .cert_unresolvable_since
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let prefix = format!("{}:", response.group_id);
                since.retain(|k, _| !k.starts_with(&prefix));
            }
            // The hydrate persisted; clear the requester's negative mark
            // so nothing delays a later re-request for other seats.
            state
                .cert_fetch_requested
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&response.cert_digest);
            tracing::info!(
                group_id = %LogHexId::group(&response.group_id),
                "#946: group-scoped fetch hydrated a digest-only seat"
            );
            true
        }
        _ => false,
    }
}

/// Item B: record + consult the certificate-unobtainable deadline. Returns
/// `true` when the typed (terminal) refusal may be staged — i.e. the
/// condition has persisted past [`CERT_EVIDENCE_DEADLINE_MS`].
pub(in crate::server) fn cert_evidence_deadline_elapsed(
    state: &AppState,
    group_key: &str,
    member_agent_id: &str,
) -> bool {
    let key = format!("{group_key}:{member_agent_id}");
    let mut since = state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now_ms = now_millis_u64();
    let first = *since.entry(key).or_insert(now_ms);
    now_ms.saturating_sub(first) >= CERT_EVIDENCE_DEADLINE_MS
}
