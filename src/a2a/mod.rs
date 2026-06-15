//! A2A (Agent2Agent) interoperability — Agent Card adapter.
//!
//! Maps x0x's native [`AgentCard`](crate::groups::card::AgentCard) onto a
//! Google A2A-shaped Agent Card so x0x agents are discoverable by the A2A
//! ecosystem. Served by the daemon at `GET /.well-known/agent-card.json`.
//!
//! This is the *discovery* half of A2A interop (ADR-0017,
//! `docs/design/a2a-agent-card-adapter.md`). The *delivery* half — the
//! A2A-over-x0x message binding — is a tracked follow-up and is intentionally
//! NOT implemented here; `capabilities.streaming` / `pushNotifications` stay
//! `false` until that lands.

use crate::groups::card::AgentCard;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Transport token advertised in the A2A card for the x0x binding.
const X0X_TRANSPORT: &str = "x0x";

fn default_modes() -> Vec<String> {
    vec!["text/plain".to_string(), "application/json".to_string()]
}

/// Context the adapter needs beyond the x0x [`AgentCard`] itself.
#[derive(Debug, Clone)]
pub struct A2aContext {
    /// Crate version string (e.g. from `CARGO_PKG_VERSION`).
    pub version: String,
    /// Whether remote-exec is enabled (gates the `exec` skill, §8).
    pub exec_enabled: bool,
    /// Base64 `AgentCertificate` if the agent has a user identity.
    pub certificate_b64: Option<String>,
}

/// An A2A-compatible Agent Card derived from an x0x [`AgentCard`].
///
/// Field names follow the A2A convention (camelCase). x0x-native data is
/// carried under `x0x`-prefixed extension members, which generic A2A clients
/// ignore and x0x-aware clients use for self-authenticating verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentCard {
    /// Human-readable agent name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Agent/software version.
    pub version: String,
    /// Primary endpoint URL (the x0x agent link).
    pub url: String,
    /// Preferred transport token.
    pub preferred_transport: String,
    /// All supported transport interfaces, in preference order.
    pub supported_interfaces: Vec<A2aInterface>,
    /// Optional provider/organization block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<A2aProvider>,
    /// Capabilities advertised as A2A skills.
    pub skills: Vec<A2aSkill>,
    /// Security schemes the agent supports.
    pub security_schemes: BTreeMap<String, A2aSecurityScheme>,
    /// Coarse capability flags.
    pub capabilities: A2aCapabilities,
    /// Default accepted input media types.
    pub default_input_modes: Vec<String>,
    /// Default produced output media types.
    pub default_output_modes: Vec<String>,

    // ── x0x-namespaced extensions (A2A permits additive members) ──────────
    /// x0x AgentId (hex) — the self-authenticating address.
    #[serde(rename = "x0xAgentId")]
    pub x0x_agent_id: String,
    /// x0x MachineId (hex).
    #[serde(rename = "x0xMachineId")]
    pub x0x_machine_id: String,
    /// x0x UserId (hex), if a human identity is present.
    #[serde(rename = "x0xUserId", skip_serializing_if = "Option::is_none")]
    pub x0x_user_id: Option<String>,
    /// Agent ML-DSA-65 public key (hex) for signature verification.
    #[serde(rename = "x0xAgentPublicKey", skip_serializing_if = "Option::is_none")]
    pub x0x_agent_public_key: Option<String>,
    /// Detached ML-DSA-65 signature (hex) over the source x0x card.
    #[serde(rename = "x0xSignature", skip_serializing_if = "Option::is_none")]
    pub x0x_signature: Option<String>,
    /// Base64 `AgentCertificate` binding the agent to a user, if present.
    #[serde(rename = "x0xCertificate", skip_serializing_if = "Option::is_none")]
    pub x0x_certificate: Option<String>,
}

/// A declared transport interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct A2aInterface {
    /// Transport token (e.g. `"x0x"`).
    pub transport: String,
    /// Endpoint URL for this transport.
    pub url: String,
}

/// Provider/organization metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct A2aProvider {
    /// Organization name.
    pub organization: String,
    /// Organization URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// An A2A skill (capability) advertised by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct A2aSkill {
    /// Stable skill id.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Search/classification tags.
    pub tags: Vec<String>,
}

/// Coarse capability flags.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct A2aCapabilities {
    /// Whether streaming responses are supported.
    pub streaming: bool,
    /// Whether push notifications are supported.
    pub push_notifications: bool,
}

/// A security scheme entry (subset of the A2A/OpenAPI model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct A2aSecurityScheme {
    /// Scheme type (e.g. `"apiKey"`).
    #[serde(rename = "type")]
    pub scheme_type: String,
    /// Location of the credential (e.g. `"header"`).
    #[serde(rename = "in", skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Credential field name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Build an A2A Agent Card from an x0x [`AgentCard`] and adapter context.
///
/// Pure function — no I/O. The `card` SHOULD already be signed
/// ([`AgentCard::sign`]) so `x0xSignature` / `x0xAgentPublicKey` are populated;
/// an unsigned card simply omits those extension members.
#[must_use]
pub fn a2a_card_from(card: &AgentCard, ctx: &A2aContext) -> A2aAgentCard {
    let id_prefix: String = card.agent_id.chars().take(8).collect();
    let name = if card.display_name.is_empty() {
        format!("x0x-agent-{id_prefix}")
    } else {
        card.display_name.clone()
    };

    let mut skills: Vec<A2aSkill> = Vec::new();
    for store in &card.stores {
        skills.push(A2aSkill {
            id: format!("kv:{}", store.topic),
            name: store.name.clone(),
            description: format!("Replicated x0x KV store on topic '{}'", store.topic),
            tags: vec!["kv".to_string(), "storage".to_string()],
        });
    }
    for group in &card.groups {
        skills.push(A2aSkill {
            id: format!("group:{}", group.name),
            name: group.name.clone(),
            description: format!("x0x group '{}'", group.name),
            tags: vec!["group".to_string(), "messaging".to_string()],
        });
    }
    // §8: the exec skill MUST NOT appear unless remote-exec is enabled.
    if ctx.exec_enabled {
        skills.push(A2aSkill {
            id: "exec".to_string(),
            name: "Remote exec".to_string(),
            description: "ACL-gated remote command execution".to_string(),
            tags: vec!["exec".to_string(), "command".to_string()],
        });
    }

    let mut security_schemes = BTreeMap::new();
    security_schemes.insert(
        "x0x-agent-signature".to_string(),
        A2aSecurityScheme {
            scheme_type: "apiKey".to_string(),
            location: Some("header".to_string()),
            name: Some("X-X0X-Agent-Signature".to_string()),
            description: Some(
                "ML-DSA-65 detached signature over the canonical agent card; \
                 verify against x0xAgentPublicKey (SHA-256 of which equals x0xAgentId)."
                    .to_string(),
            ),
        },
    );

    let url = card.to_link();

    A2aAgentCard {
        name,
        description: format!("x0x agent {id_prefix}"),
        version: ctx.version.clone(),
        url: url.clone(),
        preferred_transport: X0X_TRANSPORT.to_string(),
        supported_interfaces: vec![A2aInterface {
            transport: X0X_TRANSPORT.to_string(),
            url,
        }],
        provider: Some(A2aProvider {
            organization: "x0x".to_string(),
            url: Some("https://github.com/saorsa-labs".to_string()),
        }),
        skills,
        security_schemes,
        capabilities: A2aCapabilities {
            // Flipped on when the A2A-over-x0x binding (follow-up) ships.
            streaming: false,
            push_notifications: false,
        },
        default_input_modes: default_modes(),
        default_output_modes: default_modes(),
        x0x_agent_id: card.agent_id.clone(),
        x0x_machine_id: card.machine_id.clone(),
        x0x_user_id: card.user_id.clone(),
        x0x_agent_public_key: card.agent_public_key.clone(),
        x0x_signature: card.signature.clone(),
        x0x_certificate: ctx.certificate_b64.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::card::{CardGroup, CardStore};
    use crate::identity::AgentKeypair;

    fn ctx(exec: bool) -> A2aContext {
        A2aContext {
            version: "9.9.9".to_string(),
            exec_enabled: exec,
            certificate_b64: None,
        }
    }

    fn signed_card(kp: &AgentKeypair) -> AgentCard {
        let mut card = AgentCard::new("Ada".to_string(), &kp.agent_id(), &hex::encode([7u8; 32]));
        card.stores.push(CardStore {
            name: "docs".to_string(),
            topic: "docs-topic".to_string(),
        });
        card.groups.push(CardGroup {
            name: "team".to_string(),
            invite_link: "x0x://invite/abc".to_string(),
        });
        card.sign(kp).expect("sign");
        card
    }

    #[test]
    fn maps_core_fields_and_extensions() {
        let kp = AgentKeypair::generate().expect("kp");
        let card = signed_card(&kp);
        let a2a = a2a_card_from(&card, &ctx(false));

        assert_eq!(a2a.name, "Ada");
        assert_eq!(a2a.version, "9.9.9");
        assert_eq!(a2a.preferred_transport, "x0x");
        assert_eq!(a2a.supported_interfaces.len(), 1);
        assert_eq!(a2a.supported_interfaces[0].transport, "x0x");
        // The self-authenticating identity must round-trip into the A2A card.
        assert_eq!(a2a.x0x_agent_id, card.agent_id);
        assert!(a2a.x0x_agent_public_key.is_some());
        assert!(a2a.x0x_signature.is_some());
    }

    #[test]
    fn derives_skills_from_stores_and_groups() {
        let kp = AgentKeypair::generate().expect("kp");
        let card = signed_card(&kp);
        let a2a = a2a_card_from(&card, &ctx(false));

        assert!(a2a.skills.iter().any(|s| s.id == "kv:docs-topic"));
        assert!(a2a.skills.iter().any(|s| s.id == "group:team"));
    }

    #[test]
    fn exec_skill_gated_on_config() {
        let kp = AgentKeypair::generate().expect("kp");
        let card = signed_card(&kp);

        // Disabled: exec MUST NOT be advertised (§8) — leaking it would
        // invite unauthorized command-execution attempts.
        let disabled = a2a_card_from(&card, &ctx(false));
        assert!(!disabled.skills.iter().any(|s| s.id == "exec"));

        // Enabled: exec appears.
        let enabled = a2a_card_from(&card, &ctx(true));
        assert!(enabled.skills.iter().any(|s| s.id == "exec"));
    }

    #[test]
    fn serializes_with_a2a_and_x0x_keys() {
        let kp = AgentKeypair::generate().expect("kp");
        let card = signed_card(&kp);
        let a2a = a2a_card_from(&card, &ctx(false));
        let json = serde_json::to_string(&a2a).expect("serialize");

        // A2A camelCase keys present.
        assert!(json.contains("\"preferredTransport\""));
        assert!(json.contains("\"defaultInputModes\""));
        // x0x extension keys present and correctly namespaced.
        assert!(json.contains("\"x0xAgentId\""));
        assert!(json.contains("\"x0xSignature\""));
    }
}
