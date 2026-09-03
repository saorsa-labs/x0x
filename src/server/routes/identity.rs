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
use super::super::{api_error, bad_request, parse_optional_json};
use super::named_groups::has_withdrawn_same_stable_group_record;
use super::status::ApiResponse;

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
    let profile = state.profile.read().await;
    Json(ApiResponse {
        ok: true,
        data: AgentData {
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            machine_id: hex::encode(state.agent.machine_id().as_bytes()),
            user_id: state.agent.user_id().map(|u| hex::encode(u.as_bytes())),
            kem_public_key_b64: BASE64.encode(&state.agent_kem_keypair.public_bytes),
            human_name: profile.human_name.clone(),
            display_name: profile.display_name.clone(),
            machine_name: profile.machine_name.clone(),
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
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let req: AnnounceIdentityRequest = match parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp.into_response(),
    };
    // Issue #446: binding the HUMAN user identity into the public
    // announce is an owner act — the binding propagates through the
    // network and cannot be retracted by expiring the token that
    // minted it. A session bearer may still announce the agent alone
    // (`include_user_identity` unset/false).
    if req.include_user_identity && !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "announcing the human user identity requires the durable API token (owner act)",
        )
        .into_response();
    }
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
    /// Display name to include in the card. DEPRECATED (ADR-0036): the
    /// daemon-persisted profile (`PUT /profile`) takes precedence; this
    /// parameter is only a fallback for installs that never stored one.
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

/// #469 A1b: v4 mint population — the SAME base-state fields plus the v4
/// additions (public-meta snapshot, roster projection, explicit signed
/// creator, intended joiner) and NO legacy fat roster. Signing and the
/// size/secret bookkeeping happen in `mint_signed_invite`
/// (named_groups.rs) — the single mint authority; this only assembles.
pub(in crate::server) fn populate_invite_base_state_v4(
    invite: &mut x0x::groups::invite::SignedInvite,
    info: &x0x::groups::GroupInfo,
    intended_joiner: Option<x0x::identity::AgentId>,
) {
    invite.stable_group_id = Some(info.stable_group_id().to_string());
    invite.group_created_at = Some(info.created_at);
    invite.group_description = Some(info.description.clone());
    invite.policy = Some(info.policy.clone());
    invite.genesis_creation_nonce = info.genesis.as_ref().map(|g| g.creation_nonce.clone());
    invite.base_state_revision = Some(info.state_revision);
    invite.base_state_hash = Some(info.state_hash.clone());
    // #458 r3: the base hash commits to the Home metadata digest — carry
    // the metadata so the joiner's stub can actually recompute it.
    invite.base_home = info.home.clone();
    // #469 A1: the v4 roster carrier is the PROJECTION — exactly what
    // `roster_root_of_projection` hashes (role, state, TreeKEM key-package
    // hash, certificate digest). No certificate BYTES, no KEM/TreeKEM
    // material: the base-consistency recompute works from the projection
    // alone (D2 makes digest-only members hash identically on the joiner),
    // and the size budget holds at a roster cap instead of the 3rd member
    // (issue #188/#205). The legacy fat `base_members_v2` is never set on
    // v4 invites — the E1 view constructor refuses it.
    invite.base_roster = Some(x0x::groups::state_commit::roster_projection(
        &info.members_v2,
    ));
    invite.base_members_v2 = None;
    // #469 D1: exact public-meta snapshot — the precise input of
    // `compute_public_meta_hash`, so the joiner recomputes the base state
    // hash bit-for-bit even for non-default tags/avatar/banner.
    invite.public_meta = Some(info.public_meta());
    // #469 D1: explicit signed creator — genesis creator when known (the
    // genesis record is the stable identity), else the local creator field.
    invite.creator = Some(
        info.genesis
            .as_ref()
            .map(|g| g.creator_agent_id.clone())
            .unwrap_or_else(|| hex::encode(info.creator.as_bytes())),
    );
    // #469 A4: addressed invites carry the intended joiner.
    invite.intended_joiner = intended_joiner.map(|agent| hex::encode(agent.as_bytes()));
    invite.base_prev_state_hash = info.prev_state_hash.clone();
    invite.secure_plane = Some(info.secure_plane);
    invite.base_secret_epoch = Some(info.secret_epoch);
    invite.base_security_binding = info.security_binding.clone();
}

/// GET /agent/card — generate a shareable identity card.
///
/// r3 (Fable 1): owner-axis groups (Home metadata or an OwnerCertified
/// admission axis) mint/reuse a countersigned invite link ONLY under a
/// DURABLE-owner actor — the countersigned link is a device-admission
/// credential, exactly like `POST /groups/:id/invite` (its #446 durable
/// fence). A session bearer (or a rider, or a direct handler call with
/// no actor context) gets the group OMITTED with a recorded reason.
pub(in crate::server) async fn get_agent_card(
    State(state): State<Arc<AppState>>,
    actor: Option<axum::extract::Extension<crate::server::rider_auth::ActorContext>>,
    axum::extract::Query(query): axum::extract::Query<CardQuery>,
) -> impl IntoResponse {
    let agent_id = state.agent.agent_id();
    let machine_id = hex::encode(state.agent.machine_id().as_bytes());
    // ADR-0036: the stored profile's display_name is the source of truth.
    // `?display_name=` is DEPRECATED — still accepted as a fallback for
    // callers that never set a profile, but a stored name always wins, so
    // cards can no longer disagree with what the daemon announces.
    let profile = state.profile.read().await;
    let display_name = profile
        .display_name
        .clone()
        .or(query.display_name)
        .unwrap_or_default();

    let mut card = x0x::groups::card::AgentCard::new(display_name, &agent_id, &machine_id);
    card.owner_name = profile.human_name.clone();
    // ADR 0030 §3: the card must carry the same protocol version the mesh
    // advert claims. Hardcoding v1 here made an imported card contradict the
    // live advert, and a lower-version card import would then have to be
    // ignored by the capability store.
    card.dm_capabilities = Some(
        state
            .agent
            .current_dm_capabilities()
            .with_kem_public_key(state.agent_kem_keypair.public_bytes.clone()),
    );

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

    // Optionally include group invite links (#469 E3 transaction):
    // reuse-or-mint under the group's membership lock, durably persisted
    // before the link is returned; a group that cannot be served is
    // OMITTED with a diagnostic — never fails the whole card.
    if query.include_groups.unwrap_or(false) {
        // r3 (Fable 1): owner-axis mint/reuse authority. The card surface
        // is reachable by browser SESSION bearers; the countersigned
        // owner-axis link is a device-admission credential and demands
        // the same durable-owner proof as the explicit mint route.
        let durable_owner = actor.as_ref().is_some_and(|a| a.is_durable_owner());
        // Phase 1 (read-only): pick candidate groups and REUSE links that
        // need no mutation.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let mut mint_candidates: Vec<String> = Vec::new();
        {
            let groups = state.named_groups.read().await;
            for (map_key, info) in groups.iter() {
                if info.withdrawn
                    || has_withdrawn_same_stable_group_record(
                        &groups,
                        &info.mls_group_id,
                        Some(info.stable_group_id()),
                    )
                {
                    continue;
                }
                let inviter_hex = hex::encode(agent_id.as_bytes());
                // Only active admins may mint; others are skipped silently.
                if crate::server::routes::named_groups::require_admin_or_above(info, &inviter_hex)
                    .is_err()
                {
                    state
                        .groups_diagnostics
                        .record_invite_refusal(map_key, "card_invite_omitted_non_admin");
                    continue;
                }
                // r3 (Fable 1): owner-axis fence keyed on the SAME policy
                // axis as `home_mutation_requires_durable` — Home metadata
                // OR an OwnerCertified admission. Without a durable owner
                // the group is omitted entirely (no mint, no REUSE — an
                // already-recorded Card link is equally a device-admission
                // credential).
                let owner_axis = info.home.is_some()
                    || info.policy.admission.owner_certified_user_id().is_some();
                if owner_axis && !durable_owner {
                    state.groups_diagnostics.record_invite_refusal(
                        map_key,
                        "card_invite_omitted_owner_axis_no_durable_owner",
                    );
                    continue;
                }
                if let Some(reusable) = info.reusable_card_invite(now_secs) {
                    if let Some(link) = reusable.signed_link.clone() {
                        card.groups.push(x0x::groups::card::CardGroup {
                            name: info.name.clone(),
                            invite_link: link,
                        });
                        continue;
                    }
                }
                mint_candidates.push(map_key.clone());
            }
        }
        // Phase 2 (mutating): mint each candidate through the single v4
        // authority under its membership lock, then persist durably before
        // the link is returned.
        for map_key in mint_candidates {
            let membership_lock =
                crate::server::routes::named_groups::group_membership_lock(&state, &map_key).await;
            let _guard = membership_lock.lock().await;
            let inviter_hex = hex::encode(agent_id.as_bytes());
            // r1 (Codex 9): re-check admin authority UNDER the
            // membership lock — the phase-1 preselection ran under a
            // read lock and a demotion could have landed in between
            // (TOCTOU).
            {
                let groups = state.named_groups.read().await;
                let Some(info) = groups.get(&map_key) else {
                    continue;
                };
                if crate::server::routes::named_groups::require_admin_or_above(info, &inviter_hex)
                    .is_err()
                {
                    state
                        .groups_diagnostics
                        .record_invite_refusal(&map_key, "card_invite_omitted_non_admin");
                    continue;
                }
            }
            // r5 (Codex 4): re-run the REUSE check inside the serialized
            // section too — phase 1's scan ran unlocked, so two
            // concurrent card GETs can both miss reuse and each mint.
            // The second getter under the lock must serve the link the
            // first one minted, not a second issuance record.
            {
                let groups = state.named_groups.read().await;
                if let Some(reused) = groups
                    .get(&map_key)
                    .and_then(|info| info.reusable_card_invite(now_secs))
                    .and_then(|record| record.signed_link.clone())
                {
                    let name = groups
                        .get(&map_key)
                        .map(|info| info.name.clone())
                        .unwrap_or_default();
                    card.groups.push(x0x::groups::card::CardGroup {
                        name,
                        invite_link: reused,
                    });
                    continue;
                }
            }
            // r4 (addendum item 6): the card mint runs through the SAME
            // single actor-aware mint transaction as the explicit route
            // — owner-axis durable fence, live cap, signed v4 assembly,
            // secret recording and the durable persist are one unit
            // (with the Card origin so the link is reusable).
            match crate::server::routes::named_groups::mint_invite_transaction(
                &state,
                &map_key,
                x0x::groups::invite::DEFAULT_EXPIRY_SECS,
                None,
                x0x::groups::InviteOrigin::Card,
                durable_owner,
            )
            .await
            {
                Ok((_invite, link)) => {
                    let name = {
                        let groups = state.named_groups.read().await;
                        groups
                            .get(&map_key)
                            .map(|info| info.name.clone())
                            .unwrap_or_default()
                    };
                    card.groups.push(x0x::groups::card::CardGroup {
                        name,
                        invite_link: link,
                    });
                }
                Err(refusal) => {
                    let reason = match refusal {
                        crate::server::routes::named_groups::MintInviteRefusal::CapReached {
                            ..
                        } => "card_invite_omitted_cap_reached",
                        crate::server::routes::named_groups::MintInviteRefusal::OwnerAxisNoDurableOwner => {
                            "card_invite_omitted_owner_axis_no_durable_owner"
                        }
                        crate::server::routes::named_groups::MintInviteRefusal::OwnerKeyUnavailable => {
                            "card_invite_omitted_owner_axis"
                        }
                        crate::server::routes::named_groups::MintInviteRefusal::NotDurable => {
                            "card_invite_omitted_not_durable"
                        }
                        crate::server::routes::named_groups::MintInviteRefusal::TooLarge { .. }
                        | crate::server::routes::named_groups::MintInviteRefusal::TooLargeBytes {
                            ..
                        }
                        | crate::server::routes::named_groups::MintInviteRefusal::Signing(_) => {
                            "card_invite_omitted_mint_failed"
                        }
                    };
                    tracing::warn!(
                        group_id = %map_key,
                        "card invite mint refused; omitting group from card: {refusal:?}"
                    );
                    state
                        .groups_diagnostics
                        .record_invite_refusal(&map_key, reason);
                }
            }
        }
    }

    // Include stores
    let stores = state.kv_stores.read().await;
    for topic in stores.keys() {
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
    // ADR 0030 §3: the card must carry the same protocol version the mesh
    // advert claims. Hardcoding v1 here made an imported card contradict the
    // live advert, and a lower-version card import would then have to be
    // ignored by the capability store.
    card.dm_capabilities = Some(
        state
            .agent
            .current_dm_capabilities()
            .with_kem_public_key(state.agent_kem_keypair.public_bytes.clone()),
    );
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
        for topic in stores.keys() {
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

    // Add to contacts.
    //
    // Import must never change an existing deliberate trust decision. Two
    // rules protect prior intent:
    //   1. Blocked is sticky — a deliberately blocked agent (gossip/DMs
    //      silently dropped) cannot be un-blocked by a card re-import.
    //   2. Floor at existing level — for non-blocked contacts the effective
    //      trust is max(existing, requested), so a re-import (default
    //      "known") never downgrades a Trusted peer.
    // Explicit changes (upgrade, downgrade, un-block) remain available via
    // PATCH /contacts/:id or POST /contacts/trust.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let (effective_trust, change_ignored) = {
        let mut store = state.contacts.write().await;
        let existing = store.get(&agent_id).cloned();

        let (eff, ignored) = match &existing {
            // Blocked is an explicit deny — sticky on import regardless of
            // the requested level.
            Some(c) if c.trust_level == trust => (trust, false),
            Some(c) if c.trust_level == x0x::contacts::TrustLevel::Blocked => {
                (x0x::contacts::TrustLevel::Blocked, true)
            }
            // For non-blocked existing contacts, floor at existing level.
            Some(c) if c.trust_level.rank() >= trust.rank() => (c.trust_level, true),
            _ => (trust, false),
        };

        let contact = x0x::contacts::Contact {
            agent_id,
            trust_level: eff,
            label: Some(card.display_name.clone()),
            // Preserve provenance from any prior add.
            added_at: existing.as_ref().map_or(now, |c| c.added_at),
            last_seen: existing.as_ref().and_then(|c| c.last_seen),
            identity_type: existing
                .as_ref()
                .map_or(x0x::contacts::IdentityType::default(), |c| c.identity_type),
            machines: existing.as_ref().map_or(Vec::new(), |c| c.machines.clone()),
            // Card-derived fields always refresh on re-import.
            dm_capabilities: card.dm_capabilities.clone(),
        };

        store.add(contact);
        (eff, ignored)
    };

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
                // ADR 0030 §3: card imports go through `insert_from_card`, so a
                // stale or legacy card cannot lower a live signed advert's
                // protocol version and quarantine strict sends to that peer.
                inserted_dm_capability = capability_store.insert_from_card(
                    agent_id,
                    x0x::identity::MachineId(machine_id_bytes),
                    caps,
                    x0x::dm_capability::now_unix_ms(),
                );
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
                self_name: None,
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
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: Vec::new(),
                cert_digest: None,
            })
            .await;
    }

    // ADR-0023 §4: agent cards are Replaceable — latest per agent id. Signed
    // cards were verified above; legacy unsigned imports are recorded as a
    // locally-accepted fact.
    if let Some(history) = state.agent.history() {
        if let Ok(card_json) = serde_json::to_vec(&card) {
            let now_ms = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
            let provenance = if card.signature.is_some() {
                x0x::history::Provenance::VerifiedEnvelope
            } else {
                x0x::history::Provenance::LocalAppDecrypt
            };
            history.record(x0x::history::HistoryRecord {
                msg_id: x0x::history::HistoryRecord::compute_msg_id(None, &card_json),
                scope: x0x::history::Scope::Dm(card.agent_id.clone()),
                author_agent: Some(card.agent_id.clone()),
                author_machine: Some(card.machine_id.clone()),
                author_pubkey: card
                    .agent_public_key
                    .as_ref()
                    .and_then(|pk| hex::decode(pk).ok()),
                sent_at_ms: now_ms,
                seen_at_ms: now_ms,
                direction: x0x::history::Direction::Inbound,
                content_type: "application/json".to_string(),
                payload: card_json,
                signed_artifact: None,
                signature: None,
                sig_context: None,
                provenance,
                replace_key: Some(format!("agent-card:{}", card.agent_id)),
                thread_root: None,
                thread_parent: None,
                ingress_sender_agent: None,
                logical_request_id: None,
            });
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "agent_id": card.agent_id,
            "display_name": card.display_name,
            "trust_level": format!("{effective_trust:?}"),
            "trust_change_ignored": change_ignored,
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
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<AgentSignRequest>,
) -> impl IntoResponse {
    // Issue #446: signing mints PERMANENT detached ML-DSA-65 signatures
    // that outlive any token by design — the owner.rs rationale ("a
    // 10-minute session bearer must not mint 90-day credentials")
    // applies verbatim. Riders never reach this handler (ADR-0039
    // deny-by-default); session bearers are fenced here.
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "agent signing requires the durable API token (detached signatures outlive any session token)",
        );
    }
    let payload = match BASE64.decode(&req.payload_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid base64 payload: {e}"));
        }
    };

    // ADR-0043 AgentSigningGate (§6): `may_sign = holds_key ∧ custodian ==
    // this machine`. This daemon's agent with NO move log fails open
    // (pre-0043 behavior); once a log exists, quiesced (mid-move /
    // retire-pending source) and quarantined (un-activated target) states
    // refuse to sign — zero live signers during a transfer is derived, not
    // tracked.
    let signing_agent = state.agent.agent_id();
    if !state.agent.signing_gate_allows(&signing_agent).await {
        return api_error(
            StatusCode::CONFLICT,
            "signing refused: this machine is not the agent's custodian (ADR-0043 signing gate — quiesced or quarantined)",
        );
    }

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
    /// ADR-0036 self-profile names (daemon-persisted, `PUT /profile`).
    #[serde(skip_serializing_if = "Option::is_none")]
    human_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_name: Option<String>,
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

// ── Key lifecycle — revocation ────────────────────────────────────────────────

/// POST /identity/revoke — request body.
///
/// The caller identifies the subject to revoke and provides an optional reason.
/// The daemon uses its own agent keypair as the issuer.  Self-revocation
/// (revoking own agent-id or own machine-id) always succeeds.  Revoking a
/// third-party subject requires that a user keypair previously signed an
/// `AgentCertificate` for that subject (user-authority revocation).
#[derive(Debug, Clone, Deserialize)]
pub(in crate::server) struct RevokeRequest {
    /// Which subject to revoke. Exactly one field must be present for
    /// Agent/Machine subjects; BOTH `agent_id` and `machine_id` (with
    /// `move_epoch`) select the ADR-0043 binding form — an owner-key
    /// issued, permanent `(agent, machine)` tombstone on the v2 carrier.
    agent_id: Option<String>,
    machine_id: Option<String>,
    /// Binding form only: the move epoch ordering the tombstone against
    /// placement records (§7.1). Required when both ids are present.
    move_epoch: Option<u64>,
    /// Optional human-readable reason string (stored in the record).
    reason: Option<String>,
}

/// POST /identity/revoke — issue and publish a signed revocation.
///
/// Returns `200 OK` with the serialised revocation record on success.
/// Returns `400` if neither or both subject fields are set, or if the
/// hex-encoded id is malformed.  Returns `403` if the issuer lacks authority
/// to revoke the requested subject.
pub(in crate::server) async fn identity_revoke(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(body): Json<RevokeRequest>,
) -> impl IntoResponse {
    use x0x::revocation::RevokedSubject;
    // ADR-0043 both-fields form: owner-key issued binding tombstone.
    if let (Some(agent_hex), Some(machine_hex)) =
        (body.agent_id.as_deref(), body.machine_id.as_deref())
    {
        if !actor.is_durable_owner() {
            return api_error(
                StatusCode::FORBIDDEN,
                "binding revocation requires the durable API token (owner-key signing act)",
            );
        }
        let Some(epoch) = body.move_epoch else {
            return bad_request("binding revocation requires move_epoch");
        };
        let agent = hex::decode(agent_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(x0x::identity::AgentId);
        let machine = hex::decode(machine_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(x0x::identity::MachineId);
        let (Some(agent), Some(machine)) = (agent, machine) else {
            return bad_request("agent_id and machine_id must be 32-byte hex");
        };
        return match state
            .agent
            .revoke_binding(&agent, &machine, epoch, body.reason.clone())
            .await
        {
            Ok(record) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "subject": record.subject_hex(),
                    "subject_kind": record.subject_kind(),
                    "issuer": hex::encode(record.issuer_public_key_hash()),
                    "revoked_at": record.revoked_at,
                    "reason": record.reason,
                })),
            ),
            Err(e) => api_error(
                StatusCode::FORBIDDEN,
                format!("binding revocation rejected (owner key + certificate required): {e}"),
            ),
        };
    }

    let subject = match (body.agent_id.as_deref(), body.machine_id.as_deref()) {
        (Some(hex), None) => {
            let bytes = hex::decode(hex)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(x0x::identity::AgentId);
            match bytes {
                Some(id) => RevokedSubject::Agent(id),
                None => return bad_request("agent_id must be 32-byte hex"),
            }
        }
        (None, Some(hex)) => {
            let bytes = hex::decode(hex)
                .ok()
                .and_then(|b| b.try_into().ok())
                .map(x0x::identity::MachineId);
            match bytes {
                Some(id) => RevokedSubject::Machine(id),
                None => return bad_request("machine_id must be 32-byte hex"),
            }
        }
        (Some(_), Some(_)) => return bad_request("supply exactly one of agent_id or machine_id"),
        (None, None) => return bad_request("supply exactly one of agent_id or machine_id"),
    };

    let issuer_keypair = state.agent.identity().agent_keypair();
    match state
        .agent
        .revoke(issuer_keypair, subject, body.reason, None)
        .await
    {
        Ok(record) => {
            let resp = serde_json::json!({
                "ok": true,
                "subject": record.subject_hex(),
                "subject_kind": record.subject_kind(),
                "issuer": hex::encode(record.issuer_public_key_hash()),
                "revoked_at": record.revoked_at,
                "reason": record.reason,
            });
            (StatusCode::OK, Json(resp))
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("authority") || msg.contains("rejected") {
                api_error(
                    StatusCode::FORBIDDEN,
                    format!("issuer lacks authority to revoke this subject: {e}"),
                )
            } else {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("revocation failed: {e}"),
                )
            }
        }
    }
}

/// GET /identity/revocations — list all revocation records held by this daemon.
pub(in crate::server) async fn identity_revocations(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let records = state.agent.revocation_records().await;
    let items: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "subject": r.subject_hex(),
                "subject_kind": r.subject_kind(),
                "issuer": hex::encode(r.issuer_public_key_hash()),
                "revoked_at": r.revoked_at,
                "reason": r.reason,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "revocations": items })),
    )
}

#[cfg(test)]
mod owner_act_tests {
    //! Issue #446: the owner-act matrix, end-to-end through the REAL
    //! `auth_middleware` and the REAL handlers on a mini-router — no
    //! test-only shims. Every surface listed here must:
    //!
    //! - 403 a browser SESSION bearer (typed error naming the durable
    //!   requirement),
    //! - 403 a rider token (ADR-0039 deny-by-default middleware),
    //! - admit the DURABLE token past the gate (the asserted non-403
    //!   outcome is whatever the handler does next with the given body).
    //!
    //! `owner_act_matrix_universal` below asserts all three arms for
    //! every static gated surface in ONE test. Target-conditional
    //! surfaces (`PATCH /groups/:id` and `PATCH /groups/:id/policy` on a
    //! Home-metadata group) are pinned in `routes::home::tests`.
    use super::*;
    use crate::server::rider_auth::ActorContext;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::{delete, post};
    use tower::ServiceExt;

    /// The fixture's durable API token (`secure_endpoint_test_state_at`
    /// hard-codes `"test-token"`).
    const DURABLE: &str = "test-token";

    async fn matrix_state() -> anyhow::Result<(Arc<AppState>, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let state = crate::server::routes::home::tests::owned_state(dir.path(), [0x42; 32]).await?;
        Ok((state, dir))
    }

    fn matrix_router(state: Arc<AppState>) -> axum::Router {
        use crate::server::auth::auth_middleware;
        use crate::server::delegations::delegate_group_authority;
        use crate::server::routes::direct::direct_send;
        use crate::server::routes::exec::{exec_cancel, exec_run};
        use crate::server::routes::home::rename_home;
        use crate::server::routes::status::shutdown_handler;
        use crate::server::routes::sync::{enroll_device, unenroll_device};
        use crate::server::routes::upgrade::apply_upgrade;
        axum::Router::new()
            .route("/agent/sign", post(agent_sign))
            .route("/announce", post(announce_identity))
            .route("/exec/run", post(exec_run))
            .route("/exec/cancel", post(exec_cancel))
            .route("/shutdown", post(shutdown_handler))
            .route("/sync/devices/enroll", post(enroll_device))
            .route("/sync/devices/:machine_id", delete(unenroll_device))
            .route("/groups/:id/delegate", post(delegate_group_authority))
            .route("/home/rename", post(rename_home))
            .route("/upgrade/apply", post(apply_upgrade))
            .route("/direct/send", post(direct_send))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(state)
    }

    async fn call(
        app: &axum::Router,
        method: &str,
        path: &str,
        bearer: &str,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request builds");
        let resp = app.clone().oneshot(req).await.expect("router answers");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body reads");
        let json = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, json)
    }

    async fn session_token(state: &AppState) -> String {
        state.sessions.issue(std::time::Instant::now())
    }

    async fn rider_token(state: &AppState) -> String {
        let mut store = state.rider_tokens.lock().await;
        let (token, _record) = store
            .issue(
                "aa".repeat(32),
                Vec::new(),
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await
            .expect("rider token issues");
        token
    }

    fn assert_durable_403(json: &serde_json::Value) {
        let err = json["error"].as_str().unwrap_or_default();
        assert!(
            err.contains("durable API token"),
            "typed 403 must name the durable requirement, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn owner_act_matrix_agent_sign() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let body = serde_json::json!({
            "context": "example.test",
            "payload_b64": BASE64.encode(b"matrix payload"),
        });

        let (status, json) = call(
            &app,
            "POST",
            "/agent/sign",
            &session_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);

        let (status, json) = call(
            &app,
            "POST",
            "/agent/sign",
            &rider_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        assert!(json["error"].as_str().unwrap_or_default().contains("rider"));

        let (status, json) = call(&app, "POST", "/agent/sign", DURABLE, body).await;
        assert_eq!(status, StatusCode::OK, "durable bearer: {json}");
        assert_eq!(json["ok"], true);
        assert!(json["signature_b64"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_exec() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        // Empty argv: the handler's own validation must be REACHED by the
        // durable bearer (400) but never by the session bearer (403 fires
        // first — the gate precedes validation).
        let run_body = serde_json::json!({ "agent_id": "ab".repeat(32), "argv": [] });
        let (status, json) = call(
            &app,
            "POST",
            "/exec/run",
            &session_token(&state).await,
            run_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/exec/run",
            &rider_token(&state).await,
            run_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        let (status, json) = call(&app, "POST", "/exec/run", DURABLE, run_body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "durable reaches validation: {json}"
        );

        let cancel_body = serde_json::json!({ "request_id": "not-hex" });
        let (status, json) = call(
            &app,
            "POST",
            "/exec/cancel",
            &session_token(&state).await,
            cancel_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/exec/cancel",
            &rider_token(&state).await,
            cancel_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        let (status, json) = call(&app, "POST", "/exec/cancel", DURABLE, cancel_body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "durable reaches validation: {json}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_shutdown() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let empty = serde_json::json!({});

        let (status, json) = call(
            &app,
            "POST",
            "/shutdown",
            &session_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/shutdown",
            &rider_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");

        let (status, json) = call(&app, "POST", "/shutdown", DURABLE, empty).await;
        assert_eq!(status, StatusCode::OK, "durable bearer: {json}");
        assert_eq!(json["ok"], true);
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_sync_devices() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let empty = serde_json::json!({});

        let (status, json) = call(
            &app,
            "POST",
            "/sync/devices/enroll",
            &session_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/sync/devices/enroll",
            &rider_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");

        // Durable: a true end-to-end enrollment of THIS machine.
        let (status, json) =
            call(&app, "POST", "/sync/devices/enroll", DURABLE, empty.clone()).await;
        assert_eq!(status, StatusCode::OK, "durable bearer: {json}");
        assert_eq!(json["ok"], true);
        let machine = json["machine_id"].as_str().expect("machine_id").to_string();

        let path = format!("/sync/devices/{machine}");
        let (status, json) = call(
            &app,
            "DELETE",
            &path,
            &session_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "DELETE",
            &path,
            &rider_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        let (status, json) = call(&app, "DELETE", &path, DURABLE, empty).await;
        assert_eq!(status, StatusCode::OK, "durable bearer: {json}");
        assert_eq!(json["ok"], true);
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_delegate() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        // Well-formed body so ONLY the gate can produce the 403; the
        // durable arm reaches the group lookup (404 — no such group).
        let body = serde_json::json!({
            "to_agent": "cd".repeat(32),
            "scope": "send_as",
            "expiry_ms": 1735689600000_u64,
        });
        let (status, json) = call(
            &app,
            "POST",
            "/groups/some-group/delegate",
            &session_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/groups/some-group/delegate",
            &rider_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        let (status, json) = call(&app, "POST", "/groups/some-group/delegate", DURABLE, body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "durable reaches group lookup: {json}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_announce_user_identity() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let with_identity =
            serde_json::json!({ "include_user_identity": true, "human_consent": true });
        let without_identity = serde_json::json!({ "include_user_identity": false });

        let (status, json) = call(
            &app,
            "POST",
            "/announce",
            &session_token(&state).await,
            with_identity.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/announce",
            &rider_token(&state).await,
            with_identity.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");

        // Durable passes the gate; the fixture agent has no gossip
        // runtime, so the handler's own error (400) is the proof the
        // gate was cleared — a 200 needs a networked daemon, which the
        // ignored daemon_api suite covers with the durable token.
        let (status, json) = call(&app, "POST", "/announce", DURABLE, with_identity).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "durable clears the gate: {json}"
        );

        // The gate is body-conditional: announcing the agent ALONE
        // stays session-allowed (unchanged behavior, not a 403).
        let (status, _json) = call(
            &app,
            "POST",
            "/announce",
            &session_token(&state).await,
            without_identity,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "plain announce stays session-allowed (400 = gossip runtime absent, NOT 403)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_home_rename() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        crate::server::routes::home::provision_home(&state).await;
        let app = matrix_router(Arc::clone(&state));
        let body = serde_json::json!({ "name": "Round 2 Home" });

        let (status, json) = call(
            &app,
            "POST",
            "/home/rename",
            &session_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        let (status, json) = call(
            &app,
            "POST",
            "/home/rename",
            &rider_token(&state).await,
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        let (status, json) = call(&app, "POST", "/home/rename", DURABLE, body).await;
        assert_eq!(status, StatusCode::OK, "durable bearer renames: {json}");
        assert_eq!(json["ok"], true);
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_upgrade_apply() -> anyhow::Result<()> {
        // Verdict item 3: /upgrade/apply swaps the binary and drives the
        // SAME shutdown channels as /shutdown — it must not be reachable
        // with a session token. Gated at the ROUTE layer (auth.rs
        // classification) so the upgrade handler itself is untouched
        // (sibling session HS-F4 owns the rollback work).
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let empty = serde_json::json!({});

        let (status, json) = call(
            &app,
            "POST",
            "/upgrade/apply",
            &session_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session bearer: {json}");
        assert_durable_403(&json);
        let (status, json) = call(
            &app,
            "POST",
            "/upgrade/apply",
            &rider_token(&state).await,
            empty.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider token: {json}");
        // Durable clears the route gate; the fixture has self-update
        // disabled, so the handler reports its own (non-403) outcome —
        // the point is that the lifecycle gate was passed only with
        // the durable token.
        let (status, json) = call(&app, "POST", "/upgrade/apply", DURABLE, empty).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "durable clears the route gate: {json}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_direct_send_exec_prefix() -> anyhow::Result<()> {
        // Verdict item 1: reserved exec frames ride DMs behind
        // `x0x-exec-v1\0`; the receiver routes them into the exec
        // service. Crafting that prefix through the generic /direct/send
        // egress must require the durable owner, while ordinary DM
        // payloads stay session-allowed.
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        let exec_payload = {
            let mut bytes = x0x::exec::EXEC_DM_PREFIX.to_vec();
            bytes.extend_from_slice(b"bincode-frame-bytes");
            serde_json::json!({
                "agent_id": "ab".repeat(32),
                "payload": BASE64.encode(bytes),
            })
        };
        let plain_payload = serde_json::json!({
            "agent_id": "ab".repeat(32),
            "payload": BASE64.encode(b"an ordinary dm"),
        });

        let (status, json) = call(
            &app,
            "POST",
            "/direct/send",
            &session_token(&state).await,
            exec_payload.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session bearer must not craft exec frames: {json}"
        );
        assert!(json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("durable"));

        // The same session bearer may still send an ordinary DM (the
        // fixture agent has no route to the peer, so the handler
        // reports a send failure — anything but 403).
        let (status, json) = call(
            &app,
            "POST",
            "/direct/send",
            &session_token(&state).await,
            plain_payload.clone(),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "ordinary DM payloads stay session-allowed: {json}"
        );

        // Durable may carry the reserved prefix (its /exec/* authority
        // subsumes the transport); with no route the send fails past
        // the gate.
        let (status, json) = call(&app, "POST", "/direct/send", DURABLE, exec_payload).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "durable clears the exec-prefix egress gate: {json}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn owner_act_matrix_session_403_precedes_body_extraction() -> anyhow::Result<()> {
        // Verdict item 4: the typed 403 must be universal for the routed
        // surfaces — the route-layer gate fires BEFORE axum's Json
        // extractor, so even a MALFORMED body cannot surface an
        // extraction error in front of the authorization decision.
        let (state, _dir) = matrix_state().await?;
        let app = matrix_router(Arc::clone(&state));
        for path in [
            "/agent/sign",
            "/exec/run",
            "/exec/cancel",
            "/home/rename",
            "/upgrade/apply",
            "/groups/x/delegate",
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    "authorization",
                    format!("Bearer {}", session_token(&state).await),
                )
                .header("content-type", "application/json")
                .body(axum::body::Body::from("this is {{{ not json"))
                .expect("request builds");
            let resp = app.clone().oneshot(req).await.expect("router answers");
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{path} with a session bearer and a malformed body must be 403 pre-extractor"
            );
        }
        Ok(())
    }

    /// Review round 3 (verdict item 4): the universal typed-403 proof in
    /// ONE matrix test — every static gated surface through the REAL
    /// `auth_middleware` + real handler: session → typed 403, rider →
    /// 403, durable → past the gate. This is the production decision
    /// path itself; the auth.rs matrix pins the pure route table.
    #[tokio::test]
    async fn owner_act_matrix_universal() -> anyhow::Result<()> {
        let (state, _dir) = matrix_state().await?;
        crate::server::routes::home::provision_home(&state).await;
        let app = matrix_router(Arc::clone(&state));
        let exec_payload = {
            let mut bytes = x0x::exec::EXEC_DM_PREFIX.to_vec();
            bytes.extend_from_slice(b"bincode");
            serde_json::json!({
                "agent_id": "ab".repeat(32),
                "payload": BASE64.encode(bytes),
            })
        };
        // (method, path, body). The durable arm asserts ≠403 — the exact
        // past-gate outcome is pinned per surface in the tests above.
        let surfaces: &[(&str, &str, serde_json::Value)] = &[
            (
                "POST",
                "/agent/sign",
                serde_json::json!({
                    "context": "example.test",
                    "payload_b64": BASE64.encode(b"universal"),
                }),
            ),
            (
                "POST",
                "/exec/run",
                serde_json::json!({
                    "agent_id": "ab".repeat(32), "argv": []
                }),
            ),
            (
                "POST",
                "/exec/cancel",
                serde_json::json!({ "request_id": "not-hex" }),
            ),
            ("POST", "/shutdown", serde_json::json!({})),
            ("POST", "/upgrade/apply", serde_json::json!({})),
            ("POST", "/sync/devices/enroll", serde_json::json!({})),
            (
                "DELETE",
                &format!("/sync/devices/{}", "00".repeat(32)),
                serde_json::json!({}),
            ),
            (
                "POST",
                "/groups/some-group/delegate",
                serde_json::json!({
                    "to_agent": "cd".repeat(32),
                    "scope": "send_as",
                    "expiry_ms": 1735689600000_u64,
                }),
            ),
            (
                "POST",
                "/home/rename",
                serde_json::json!({ "name": "Universal" }),
            ),
            ("POST", "/direct/send", exec_payload),
        ];
        for (method, path, body) in surfaces {
            let (status, json) = call(
                &app,
                method,
                path,
                &session_token(&state).await,
                body.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} session: {json}"
            );
            assert!(
                json["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("durable API token"),
                "{method} {path} session 403 must name the durable requirement: {json}"
            );

            let (status, json) =
                call(&app, method, path, &rider_token(&state).await, body.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} rider: {json}"
            );

            let (status, json) = call(&app, method, path, DURABLE, body.clone()).await;
            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} durable must clear the gate: {json}"
            );
        }
        Ok(())
    }

    /// Belt-and-braces: the resolved actor for the durable token is
    /// `Owner { durable: true }` and for a session bearer
    /// `Owner { durable: false }` — the exact predicate the gates use.
    #[test]
    fn actor_context_durability_predicate() {
        assert!(ActorContext::Owner { durable: true }.is_durable_owner());
        assert!(!ActorContext::Owner { durable: false }.is_durable_owner());
        assert!(!ActorContext::Rider {
            sub_agent_id: String::new(),
            token_id: 1,
            token_hash: String::new(),
            groups: Vec::new(),
        }
        .is_durable_owner());
    }
}
