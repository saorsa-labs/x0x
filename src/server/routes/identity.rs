//! Identity route handlers (`category: "identity"`) for the x0x daemon:
//! `/agent`, `/introduction`, `/announce`, `/agent/card`,
//! `/.well-known/agent-card.json`, `/agent/card/import`, `/agent/sign`,
//! `/agent/verify`, `/agent/user-id`.
//!
//! Extracted verbatim from `server/mod.rs` (#125 / WS1.4 routes-1).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::state::AppState;
use super::super::{
    api_error, bad_request, has_withdrawn_same_stable_group_record, parse_optional_json,
    ApiResponse,
};

/// POST /agent/sign request body — a caller payload to sign with the
/// agent's ML-DSA-65 secret key under a mandatory external domain.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AgentSignRequest {
    /// Required domain-separation string naming the caller's application
    /// protocol (e.g. `"x0x-symphony-handoff-v1"`). The daemon signs the
    /// length-prefixed external DST `[0xF0] | magic | len(context) | context |
    /// payload` (see [`crate::api::agent_signing`]), which is provably disjoint
    /// from every internal x0x signing input. Must match `[a-z0-9._-]{1,64}`
    /// and must not name an internal signing domain (issue #133).
    context: String,
    /// Base64-encoded bytes to sign. The signature is computed over the DST
    /// assembled from `context` and these bytes; callers should canonicalize
    /// structured payloads.
    payload_b64: String,
}

/// POST /agent/verify request body — a detached ML-DSA-65 signature to
/// verify against caller-supplied public key material.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AgentVerifyRequest {
    /// Base64-encoded bytes the signature was computed over. Same caveat
    /// as `/agent/sign`: the bytes are taken verbatim, so the caller must
    /// reproduce the exact canonical serialization that was signed.
    payload_b64: String,
    /// Base64-encoded detached ML-DSA-65 signature (3309 bytes decoded).
    signature_b64: String,
    /// Base64-encoded ML-DSA-65 public key (1952 bytes decoded).
    public_key_b64: String,
    /// Required domain-separation string; verification is performed over
    /// the same external DST as `/agent/sign`
    /// (`[0xF0] | magic | len(context) | context | payload`, issue #133), so a
    /// signature produced by `/agent/sign` round-trips through `/agent/verify`.
    context: String,
    /// Optional signing-scheme identifier. When the field is present —
    /// including as JSON null — it must be exactly
    /// `x0x.agent-sign.v2.ml-dsa-65`; anything else is rejected with 400
    /// so a future scheme migration is explicit rather than silent.
    /// Deserialized via `deserialize_present` because a plain
    /// `Option<String>` folds present-but-null into `None` and would
    /// silently accept `"algorithm": null`.
    #[serde(default, deserialize_with = "deserialize_present")]
    algorithm: Option<serde_json::Value>,
}

/// POST /announce request body.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct AnnounceIdentityRequest {
    #[serde(default)]
    include_user_identity: bool,
    #[serde(default)]
    human_consent: bool,
}

/// GET /agent
pub(in crate::server) async fn agent_info(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<AgentData>> {
    use base64::Engine as _;
    Json(ApiResponse {
        ok: true,
        data: AgentData {
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            machine_id: hex::encode(state.agent.machine_id().as_bytes()),
            user_id: state.agent.user_id().map(|u| hex::encode(u.as_bytes())),
            kem_public_key_b64: BASE64.encode(&state.agent_kem_keypair.public_bytes),
        },
    })
}

/// Query parameters for GET /introduction.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct IntroductionQuery {
    /// Connecting peer's agent ID (hex). Determines trust-gated response.
    #[serde(default)]
    peer: Option<String>,
}

/// GET /introduction — serve this agent's introduction card, trust-gated.
///
/// Pass `?peer=<hex agent_id>` to receive a card filtered by the peer's
/// trust level. Without `?peer`, the response is the public (Unknown) view.
///
/// - **Blocked**: 403 Forbidden
/// - **Unknown**: display name, identity words, public services only
/// - **Known**: above + machine_id, certificate status, broader services
/// - **Trusted**: everything — all services, full details
pub(in crate::server) async fn introduction(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<IntroductionQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Resolve the peer's trust level.
    let peer_trust = if let Some(ref peer_hex) = query.peer {
        let Ok(peer_bytes) = hex::decode(peer_hex) else {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid peer agent_id hex"})),
            )
                .into_response();
        };
        if peer_bytes.len() != 32 {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "peer agent_id must be 32 bytes"})),
            )
                .into_response();
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&peer_bytes);
        let peer_id = x0x::identity::AgentId(id_bytes);
        state.contacts.read().await.trust_level(&peer_id)
    } else {
        x0x::contacts::TrustLevel::Unknown
    };

    // Blocked peers get nothing.
    if peer_trust == x0x::contacts::TrustLevel::Blocked {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "blocked"})),
        )
            .into_response();
    }

    let identity = state.agent.identity();

    // Full service catalogue — filtered below by peer trust.
    let all_services = vec![
        x0x::identity::ServiceEntry {
            name: "presence".to_string(),
            description: "Online/offline presence visibility".to_string(),
            min_trust: "unknown".to_string(),
        },
        x0x::identity::ServiceEntry {
            name: "direct-message".to_string(),
            description: "Send and receive direct encrypted messages".to_string(),
            min_trust: "known".to_string(),
        },
        x0x::identity::ServiceEntry {
            name: "mls-group".to_string(),
            description: "Join MLS encrypted group conversations".to_string(),
            min_trust: "known".to_string(),
        },
        x0x::identity::ServiceEntry {
            name: "file-transfer".to_string(),
            description: "Send and receive files".to_string(),
            min_trust: "trusted".to_string(),
        },
        x0x::identity::ServiceEntry {
            name: "payment".to_string(),
            description: "Payment address exchange".to_string(),
            min_trust: "trusted".to_string(),
        },
    ];

    // Filter services: only return those where peer trust >= min_trust.
    let peer_rank = peer_trust.rank();
    let visible_services: Vec<_> = all_services
        .into_iter()
        .filter(|s| {
            s.min_trust
                .parse::<x0x::contacts::TrustLevel>()
                .map(|t| peer_rank >= t.rank())
                .unwrap_or(false)
        })
        .collect();

    let card =
        match x0x::identity::IntroductionCard::from_identity(identity, None, visible_services) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("failed to build introduction card: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": "failed to build introduction card",
                        "detail": format!("{e}"),
                    })),
                )
                    .into_response();
            }
        };

    // Build response — Unknown gets a minimal card, Known/Trusted get progressively more.
    let data = match peer_trust {
        x0x::contacts::TrustLevel::Unknown => IntroductionCardData {
            agent_id: hex::encode(card.agent_id.as_bytes()),
            machine_id: None,
            user_id: None,
            certificate: None,
            display_name: card.display_name,
            identity_words: card.identity_words,
            services: card
                .services
                .iter()
                .map(|s| ServiceEntryData {
                    name: s.name.clone(),
                    description: s.description.clone(),
                    min_trust: s.min_trust.clone(),
                })
                .collect(),
            signature: None,
        },
        x0x::contacts::TrustLevel::Known => IntroductionCardData {
            agent_id: hex::encode(card.agent_id.as_bytes()),
            machine_id: Some(hex::encode(card.machine_id.as_bytes())),
            user_id: card.user_id.map(|u| hex::encode(u.as_bytes())),
            certificate: card.certificate.as_ref().map(|_| "(present)".to_string()),
            display_name: card.display_name,
            identity_words: card.identity_words,
            services: card
                .services
                .iter()
                .map(|s| ServiceEntryData {
                    name: s.name.clone(),
                    description: s.description.clone(),
                    min_trust: s.min_trust.clone(),
                })
                .collect(),
            signature: Some(hex::encode(&card.signature[..8])),
        },
        // Trusted — full card.
        _ => IntroductionCardData {
            agent_id: hex::encode(card.agent_id.as_bytes()),
            machine_id: Some(hex::encode(card.machine_id.as_bytes())),
            user_id: card.user_id.map(|u| hex::encode(u.as_bytes())),
            certificate: card.certificate.as_ref().map(|_| "(present)".to_string()),
            display_name: card.display_name,
            identity_words: card.identity_words,
            services: card
                .services
                .iter()
                .map(|s| ServiceEntryData {
                    name: s.name.clone(),
                    description: s.description.clone(),
                    min_trust: s.min_trust.clone(),
                })
                .collect(),
            signature: Some(hex::encode(&card.signature[..8])),
        },
    };

    axum::Json(ApiResponse { ok: true, data }).into_response()
}

/// POST /announce — accepts optional JSON body (empty body defaults to no user identity).
pub(in crate::server) async fn announce_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let req: AnnounceIdentityRequest = match parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp.into_response(),
    };
    match state
        .agent
        .announce_identity(req.include_user_identity, req.human_consent)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "include_user_identity": req.include_user_identity,
            })),
        )
            .into_response(),
        Err(e) => bad_request(format!("{e}")).into_response(),
    }
}

/// Request body for POST /agent/card/import.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct ImportCardRequest {
    /// Card link (`x0x://agent/...`) or raw base64.
    card: String,
    /// Trust level to assign (default: "known").
    #[serde(default = "default_import_trust")]
    trust_level: String,
}

fn default_import_trust() -> String {
    "known".to_string()
}

/// Request body for GET /agent/card query params.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CardQuery {
    /// Display name to include in the card.
    #[serde(default)]
    pub(in crate::server) display_name: Option<String>,
    /// Whether to include group invites.
    #[serde(default)]
    pub(in crate::server) include_groups: Option<bool>,
    /// Include loopback/private interface addresses for local testnet cards.
    ///
    /// The default remains false so copy-pasteable cards do not leak
    /// unroutable RFC1918/loopback addresses to remote recipients.
    #[serde(default)]
    pub(in crate::server) include_local_addresses: bool,
}

/// Populate `addresses` with locally-discovered globally-routable interfaces.
///
/// Agent cards are copy-pasteable identity links (`x0x://agent/...`) that can
/// be shared anywhere. They must only carry globally-advertisable addresses —
/// a card minted inside a Vultr VPC must not embed `10.200.0.1:5483` or
/// recipients in London will spend ~50s dialing a black hole.
fn discover_local_card_addresses(port: u16, addresses: &mut Vec<String>, include_local: bool) {
    for addr in x0x::collect_local_interface_addrs(port) {
        if !include_local && !x0x::is_publicly_advertisable(addr) {
            continue;
        }
        let s = addr.to_string();
        if !addresses.contains(&s) {
            addresses.push(s);
        }
    }
}

fn prioritize_local_card_addresses(addresses: &mut [String]) {
    addresses.sort_by_key(|addr| {
        addr.parse::<std::net::SocketAddr>()
            .map(x0x::is_publicly_advertisable)
            .unwrap_or(true)
    });
}

pub(in crate::server) fn populate_invite_base_state_from_group_info(
    invite: &mut x0x::groups::invite::SignedInvite,
    info: &x0x::groups::GroupInfo,
) {
    invite.stable_group_id = Some(info.stable_group_id().to_string());
    invite.group_created_at = Some(info.created_at);
    invite.group_description = Some(info.description.clone());
    invite.policy = Some(info.policy.clone());
    invite.genesis_creation_nonce = info.genesis.as_ref().map(|g| g.creation_nonce.clone());
    invite.base_state_revision = Some(info.state_revision);
    invite.base_state_hash = Some(info.state_hash.clone());
    invite.base_members_v2 = Some(info.members_v2.clone());
    invite.base_prev_state_hash = info.prev_state_hash.clone();
    invite.secure_plane = Some(info.secure_plane);
    invite.base_secret_epoch = Some(info.secret_epoch);
    invite.base_security_binding = info.security_binding.clone();
}

/// GET /agent/card — generate a shareable identity card.
pub(in crate::server) async fn get_agent_card(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<CardQuery>,
) -> impl IntoResponse {
    let agent_id = state.agent.agent_id();
    let machine_id = hex::encode(state.agent.machine_id().as_bytes());
    let display_name = query.display_name.unwrap_or_default();

    let mut card = x0x::groups::card::AgentCard::new(display_name, &agent_id, &machine_id);
    card.dm_capabilities = Some(x0x::dm::DmCapabilities::v1_gossip_ready(
        state.agent_kem_keypair.public_bytes.clone(),
    ));

    // Add user ID if available
    card.user_id = state.agent.user_id().map(|u| hex::encode(u.as_bytes()));

    // Add external addresses from ant-quic NodeStatus, filtered to
    // globally-advertisable scope only (see discover_local_card_addresses
    // doc-comment), then augment with local probes so cards remain useful
    // before the first observed-address frame arrives from another peer.
    if let Some(network) = state.agent.network() {
        if let Some(ns) = network.node_status().await {
            card.addresses = ns
                .external_addrs
                .iter()
                .filter(|a| query.include_local_addresses || x0x::is_publicly_advertisable(**a))
                .map(|a| a.to_string())
                .collect();
            discover_local_card_addresses(
                ns.local_addr.port(),
                &mut card.addresses,
                query.include_local_addresses,
            );
            if query.include_local_addresses {
                prioritize_local_card_addresses(&mut card.addresses);
            }
        }
    }

    // Optionally include group invite links
    if query.include_groups.unwrap_or(false) {
        let groups = state.named_groups.read().await;
        for info in groups.values() {
            if info.withdrawn
                || has_withdrawn_same_stable_group_record(
                    &groups,
                    &info.mls_group_id,
                    Some(info.stable_group_id()),
                )
            {
                continue;
            }
            let mut invite = x0x::groups::invite::SignedInvite::new(
                info.mls_group_id.clone(),
                info.name.clone(),
                &agent_id,
                x0x::groups::invite::DEFAULT_EXPIRY_SECS,
            );
            populate_invite_base_state_from_group_info(&mut invite, info);
            card.groups.push(x0x::groups::card::CardGroup {
                name: info.name.clone(),
                invite_link: invite.to_link(),
            });
        }
    }

    // Include stores
    let stores = state.kv_stores.read().await;
    for (topic, _) in stores.iter() {
        card.stores.push(x0x::groups::card::CardStore {
            name: topic.clone(),
            topic: topic.clone(),
        });
    }

    // Sign the card (ADR-0017) so its reachability hints and capability
    // advertisements are tamper-evident in transit. Signing should not fail
    // for a valid keypair; degrade to an unsigned card with a warning rather
    // than failing the request.
    if let Err(e) = card.sign(state.agent.identity().agent_keypair()) {
        tracing::warn!("failed to sign agent card: {e}");
    }

    let link = card.to_link();

    Json(serde_json::json!({
        "ok": true,
        "card": card,
        "link": link,
    }))
}

/// GET /.well-known/agent-card.json — A2A-compatible discovery card (ADR-0017).
///
/// Serves the local agent's identity as a Google A2A Agent Card so the agent
/// is discoverable by the A2A ecosystem. The underlying x0x card is signed,
/// and the signature/public key are surfaced as `x0x`-namespaced extensions.
pub(in crate::server) async fn get_a2a_agent_card(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let agent_id = state.agent.agent_id();
    let machine_id = hex::encode(state.agent.machine_id().as_bytes());

    let mut card = x0x::groups::card::AgentCard::new(String::new(), &agent_id, &machine_id);
    card.dm_capabilities = Some(x0x::dm::DmCapabilities::v1_gossip_ready(
        state.agent_kem_keypair.public_bytes.clone(),
    ));
    card.user_id = state.agent.user_id().map(|u| hex::encode(u.as_bytes()));

    // Only globally-advertisable addresses belong in a publicly-served card.
    if let Some(network) = state.agent.network() {
        if let Some(ns) = network.node_status().await {
            card.addresses = ns
                .external_addrs
                .iter()
                .filter(|a| x0x::is_publicly_advertisable(**a))
                .map(|a| a.to_string())
                .collect();
        }
    }

    // Public stores become A2A skills.
    {
        let stores = state.kv_stores.read().await;
        for (topic, _) in stores.iter() {
            card.stores.push(x0x::groups::card::CardStore {
                name: topic.clone(),
                topic: topic.clone(),
            });
        }
    }

    if let Err(e) = card.sign(state.agent.identity().agent_keypair()) {
        tracing::warn!("failed to sign A2A agent card: {e}");
    }

    let certificate_b64 = state.agent.identity().agent_certificate().and_then(|c| {
        use base64::Engine;
        bincode::serialize(c)
            .ok()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
    });

    let ctx = x0x::a2a::A2aContext {
        version: env!("CARGO_PKG_VERSION").to_string(),
        exec_enabled: state.exec_service.enabled(),
        certificate_b64,
    };

    // `Json` sets `content-type: application/json`.
    Json(x0x::a2a::a2a_card_from(&card, &ctx))
}

/// POST /agent/card/import — import an agent card to contacts.
pub(in crate::server) async fn import_agent_card(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportCardRequest>,
) -> impl IntoResponse {
    // Parse card
    let card = match x0x::groups::card::AgentCard::from_link(&req.card) {
        Ok(c) => c,
        Err(e) => {
            return bad_request(format!("invalid card: {e}"));
        }
    };

    // ADR-0017: reject tampered signed cards. A signed card whose signature
    // fails verification (or whose embedded key does not match its agent_id)
    // is dropped. Legacy unsigned cards (signature == None) remain importable
    // for backward compatibility.
    if card.signature.is_some() {
        if let Err(e) = card.verify_signature() {
            return bad_request(format!("agent card signature invalid: {e}"));
        }
    }

    // Parse trust level — surface the FromStr error rather than silently
    // coercing unknown values to Known. Matches the AddContactRequest path.
    let trust: x0x::contacts::TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    // Parse agent ID
    let agent_id_bytes: [u8; 32] = match hex::decode(&card.agent_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid agent_id in card");
        }
    };
    let agent_id = x0x::identity::AgentId(agent_id_bytes);

    // Add to contacts
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let contact = x0x::contacts::Contact {
        agent_id,
        trust_level: trust,
        label: Some(card.display_name.clone()),
        added_at: now,
        last_seen: None,
        identity_type: x0x::contacts::IdentityType::default(),
        machines: Vec::new(),
        dm_capabilities: card.dm_capabilities.clone(),
    };

    state.contacts.write().await.add(contact);

    // Also populate the identity discovery cache so connect_to_agent / send_direct
    // can find this agent without waiting for gossip announcements.
    let machine_id_bytes: [u8; 32] = hex::decode(&card.machine_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0u8; 32]);
    let addresses: Vec<std::net::SocketAddr> = card
        .addresses
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();

    let capability_store = state.agent.capability_store();
    let mut inserted_dm_capability = false;
    if machine_id_bytes != [0u8; 32] {
        if let Some(caps) = card.dm_capabilities.clone() {
            if caps.gossip_inbox && !caps.kem_public_key.is_empty() {
                capability_store.insert(
                    agent_id,
                    x0x::identity::MachineId(machine_id_bytes),
                    caps,
                    x0x::dm_capability::now_unix_ms(),
                );
                inserted_dm_capability = true;
            }
        }
    }
    tracing::debug!(
        target: "dm.trace",
        stage = "agent_card_import_capability",
        agent_id = %hex::encode(agent_id.as_bytes()),
        machine_id = %hex::encode(machine_id_bytes),
        card_has_capability = card.dm_capabilities.is_some(),
        inserted = inserted_dm_capability,
        capability_store_entries = capability_store.len(),
    );

    if machine_id_bytes != [0u8; 32] || !addresses.is_empty() {
        state
            .agent
            .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
                agent_id,
                machine_id: x0x::identity::MachineId(machine_id_bytes),
                user_id: None,
                addresses,
                announced_at: now,
                last_seen: now,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
            })
            .await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "agent_id": card.agent_id,
            "display_name": card.display_name,
            "trust_level": format!("{trust:?}"),
            "groups": card.groups.len(),
            "stores": card.stores.len(),
        })),
    )
}

/// Maximum payload size accepted by `POST /agent/sign` / `/agent/verify`,
/// in bytes. External signing is for hashes, manifests, and audit records —
/// not blobs. Mirrors [`crate::api::agent_signing::MAX_PAYLOAD_BYTES`] (kept
/// as a local const so the 413 path can format the limit without importing
/// the helper into every handler call site).
const AGENT_SIGN_MAX_PAYLOAD_BYTES: usize = crate::api::agent_signing::MAX_PAYLOAD_BYTES;

/// Stable scheme identifier returned by `POST /agent/sign` and accepted by
/// `/agent/verify`. The `v2` scheme signs the domain-separated external DST
/// (issue #133); the pre-#133 `v1` scheme (optional `domain || 0x00 ||
/// payload` / raw payload) is no longer produced.
const AGENT_SIGN_SCHEME_ID: &str = crate::api::agent_signing::SCHEME_ID;

/// POST /agent/sign — produce a detached ML-DSA-65 signature over a
/// caller-supplied payload using this agent's signing key.
///
/// Rationale. x0xd already signs gossip frames at the transport layer
/// (saorsa-gossip-identity), but transport-layer signatures don't survive
/// a database read. Applications that persist signed records to disk or
/// to distributed storage (audit logs, governance votes, content
/// metadata) need a detached signature that can be verified later from
/// the stored bytes alone, by a verifier that may have never been on the
/// network when the signature was issued. This endpoint provides that
/// primitive without exposing the secret key itself.
///
/// Authentication. Bearer-token authenticated like every other endpoint
/// — only callers with the agent's local API token can sign as the agent.
///
/// Payload. `payload_b64` is base64-decoded to the raw payload, which is
/// taken verbatim (the caller owns the canonical serialization of any
/// structured payload — e.g. `serde_canonical_json`, `postcard`, or an
/// explicit field-order convention). Payloads are capped at 64 KiB:
/// external signing is for hashes, manifests, and audit records, not blobs.
///
/// Domain separation (issue #133, mandatory). The signature is *never*
/// computed over the raw payload. A required `context` string — matching
/// `[a-z0-9._-]{1,64}` and not naming an internal x0x signing domain
/// (see `INTERNAL_CONTEXT_DENYLIST` in `src/api/agent_signing.rs`) — binds
/// the signature to a single application protocol. The canonical signed
/// bytes are the external DST
///
/// ```text
/// [0xF0] | b"x0x.external-agent-sign.v1" | len(context):u32 BE | context | payload
/// ```
///
/// That prologue is provably disjoint from every internal x0x signing
/// input (none begins with `[0xF0] | magic`), so an external signature
/// can never be replayed as a protocol message; the `0xF0` namespace tag
/// and the length-prefixed context make the boundary unambiguous. The
/// `context` is echoed in the response so a verifier knows the
/// canonical-bytes shape without out-of-band information.
///
/// Scheme. Returns the stable identifier `x0x.agent-sign.v2.ml-dsa-65`.
/// The `.v2` pins the API-envelope version; the magic's `.v1` pins the DST
/// byte layout — two independent axes (see `src/api/agent_signing.rs`). A
/// future scheme migration is therefore explicit in the response, not
/// silent.
///
/// Response. Returns the agent_id (hex, 32 bytes), the agent's public
/// key (base64), the signature (base64), the context (echoed), and the
/// scheme identifier. All values are wire-format ready for inclusion in
/// the signed record.
pub(in crate::server) async fn agent_sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AgentSignRequest>,
) -> impl IntoResponse {
    let payload = match BASE64.decode(&req.payload_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid base64 payload: {e}"));
        }
    };

    if payload.is_empty() {
        return bad_request("payload must be non-empty");
    }

    if payload.len() > AGENT_SIGN_MAX_PAYLOAD_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "payload exceeds maximum signable size of {} bytes",
                AGENT_SIGN_MAX_PAYLOAD_BYTES
            ),
        );
    }

    // Mandatory external domain separation (issue #133): sign the
    // length-prefixed external DST `[0xF0] | magic | len(context) | context |
    // payload`, which is provably disjoint from every internal x0x signing
    // input (see `src/api/agent_signing.rs`). `context` is required and
    // validated — there is no raw-payload signing path.
    if let Err(e) = crate::api::agent_signing::validate_context(&req.context) {
        return bad_request(e.to_string());
    }
    let canonical = crate::api::agent_signing::assemble_buffer(&req.context, &payload);

    let identity = state.agent.identity();
    let keypair = identity.agent_keypair();

    let signature = match ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        keypair.secret_key(),
        &canonical,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("signing failed: {e:?}"),
            );
        }
    };

    let signature_b64 = BASE64.encode(signature.as_bytes());
    let public_key_b64 = BASE64.encode(keypair.public_key().as_bytes());
    let agent_id_hex = hex::encode(state.agent.agent_id().as_bytes());

    let mut resp = serde_json::json!({
        "ok": true,
        "agent_id": agent_id_hex,
        "public_key_b64": public_key_b64,
        "signature_b64": signature_b64,
        "algorithm": AGENT_SIGN_SCHEME_ID,
    });
    // Echo the context so a verifier knows the canonical-bytes shape
    // without out-of-band context.
    resp["context"] = serde_json::Value::String(req.context);

    (StatusCode::OK, Json(resp))
}

/// POST /agent/verify — verify a detached ML-DSA-65 signature against a
/// caller-supplied public key (issue #106).
///
/// Rationale. The counterpart to `POST /agent/sign`: applications that
/// persist signed records read them back — often on machines that never
/// authored them — and must verify from the stored bytes alone. Without
/// this endpoint every consumer would bundle its own FIPS-204 library and
/// re-derive x0x's canonical external DST framing, which would drift the
/// moment the convention evolves.
///
/// Statelessness. Verification uses only caller-supplied public material:
/// no key access, no identity state. The handler deliberately takes no
/// `State` extractor so this property is enforced at compile time.
///
/// Authentication. Bearer-token authenticated like every other endpoint.
///
/// Semantics. A failed signature check is a *result*, not an error:
/// `200` with `valid: false`. `400` is reserved for malformed input (bad
/// base64, empty payload, wrong key or signature length, an invalid or
/// internal-reserved `context`, or an unknown `algorithm`); `413` for
/// payloads over the 64 KiB cap — mirroring `/agent/sign` exactly.
/// Verification is performed over the *same* external DST as signing,
/// `[0xF0] | magic | len(context):u32 BE | context | payload`, using the
/// caller-supplied `context` (required, validated identically to
/// `/agent/sign`). A signature produced for one context therefore does
/// not verify under any other — and raw-payload verification is no longer
/// a valid input.
pub(in crate::server) async fn agent_verify(
    Json(req): Json<AgentVerifyRequest>,
) -> impl IntoResponse {
    let payload = match BASE64.decode(&req.payload_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid base64 payload: {e}"));
        }
    };

    if payload.is_empty() {
        return bad_request("payload must be non-empty");
    }

    if payload.len() > AGENT_SIGN_MAX_PAYLOAD_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "payload exceeds maximum verifiable size of {} bytes",
                AGENT_SIGN_MAX_PAYLOAD_BYTES
            ),
        );
    }

    // Same canonical-bytes assembly as `agent_sign`: the verifier must
    // reconstruct exactly the bytes the signer committed to.
    if let Err(e) = crate::api::agent_signing::validate_context(&req.context) {
        return bad_request(e.to_string());
    }
    let canonical = crate::api::agent_signing::assemble_buffer(&req.context, &payload);

    // A present `algorithm` must be exactly the supported scheme string;
    // JSON null and non-string values are present-but-wrong, not omitted.
    if let Some(algorithm) = req.algorithm.as_ref() {
        if algorithm.as_str() != Some(AGENT_SIGN_SCHEME_ID) {
            return bad_request(format!(
                "unsupported algorithm: {algorithm} (expected {AGENT_SIGN_SCHEME_ID})"
            ));
        }
    }

    let signature_bytes = match BASE64.decode(&req.signature_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid base64 signature: {e}"));
        }
    };

    // A wrong-length signature is malformed input, not a failed check —
    // reject it with 400 so a truncated paste never reads as `valid: false`.
    if signature_bytes.len() != ant_quic::crypto::raw_public_keys::pqc::ML_DSA_65_SIGNATURE_SIZE {
        return bad_request(format!(
            "signature must be exactly {} bytes for ML-DSA-65, got {}",
            ant_quic::crypto::raw_public_keys::pqc::ML_DSA_65_SIGNATURE_SIZE,
            signature_bytes.len()
        ));
    }

    let signature = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
        &signature_bytes,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return bad_request(format!("invalid signature format: {e:?}"));
        }
    };

    let public_key_bytes = match BASE64.decode(&req.public_key_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid base64 public key: {e}"));
        }
    };

    // An ML-DSA-65 public key is exactly 1952 bytes; anything else is a
    // wrong-key-type paste and gets 400, never a confusing `valid: false`.
    if public_key_bytes.len() != ant_quic::crypto::raw_public_keys::pqc::ML_DSA_65_PUBLIC_KEY_SIZE {
        return bad_request(format!(
            "public key must be exactly {} bytes for ML-DSA-65, got {}",
            ant_quic::crypto::raw_public_keys::pqc::ML_DSA_65_PUBLIC_KEY_SIZE,
            public_key_bytes.len()
        ));
    }

    let public_key =
        match ant_quic::crypto::raw_public_keys::pqc::MlDsaPublicKey::from_bytes(&public_key_bytes)
        {
            Ok(pk) => pk,
            Err(e) => {
                return bad_request(format!("invalid public key format: {e:?}"));
            }
        };

    let valid = ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        &canonical,
        &signature,
    )
    .is_ok();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "valid": valid,
            "algorithm": AGENT_SIGN_SCHEME_ID,
        })),
    )
}

/// GET /agent/user-id
pub(in crate::server) async fn agent_user_id_handler(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let user_id = state.agent.user_id().map(|uid| hex::encode(uid.0));
    Json(serde_json::json!({
        "ok": true,
        "user_id": user_id,
    }))
}

/// Deserialize a field as `Some(value)` whenever the field is present —
/// even when the value is JSON null — so present-but-null can be
/// distinguished from an omitted field (serde's `Option<T>` maps both
/// to `None`).
fn deserialize_present<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Agent identity response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct AgentData {
    agent_id: String,
    machine_id: String,
    user_id: Option<String>,
    /// Base64 of the agent's ML-KEM-768 public key. Used by other daemons to
    /// seal group-shared-secret envelopes to this agent.
    kem_public_key_b64: String,
}

/// Introduction card response (fields vary by trust level).
#[derive(Debug, Serialize)]
pub(in crate::server) struct IntroductionCardData {
    agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    display_name: Option<String>,
    identity_words: String,
    services: Vec<ServiceEntryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// Service entry in an introduction card.
#[derive(Debug, Serialize)]
pub(in crate::server) struct ServiceEntryData {
    name: String,
    description: String,
    min_trust: String,
}
