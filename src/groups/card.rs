//! Shareable identity cards for x0x agents.
//!
//! An `AgentCard` is a portable, shareable representation of an agent's
//! identity. It can be encoded as a `x0x://agent/<base64url>` link and
//! shared via email, chat, QR code, or any out-of-band channel.
//!
//! When imported, the card adds the agent to the local contact store
//! so they can be discovered, trusted, and communicated with.

use crate::error::IdentityError;
use crate::identity::{AgentId, AgentKeypair};
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

/// Domain separator for agent card signatures (ADR-0017).
const AGENT_CARD_SIGNATURE_DOMAIN: &[u8] = b"x0x-agent-card-v1";

/// A shareable identity card for an x0x agent.
///
/// Contains everything someone needs to find and trust you on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Human-readable display name (e.g., "David", "alice-bot").
    pub display_name: String,

    /// Agent ID (hex-encoded, 64 chars).
    pub agent_id: String,

    /// Machine ID (hex-encoded, 64 chars). The ant-quic raw public key hash.
    pub machine_id: String,

    /// User ID (hex-encoded, 64 chars). Only present if the agent has a
    /// human identity and chose to include it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Network addresses where this agent can be reached (IP:port).
    /// May be empty if the agent hasn't announced yet.
    #[serde(default)]
    pub addresses: Vec<String>,

    /// Groups this agent belongs to, with invite links.
    /// Allows one-click "add me AND join my groups".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CardGroup>,

    /// KvStore topics this agent wants to share.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stores: Vec<CardStore>,

    /// Unix seconds when this card was generated.
    pub created_at: u64,

    /// Direct-messaging transport capabilities advertised by this agent.
    /// Added in x0x 0.18 (C — DM over gossip). Cards predating 0.18 carry
    /// `None`, interpreted by senders as "raw-QUIC / legacy only".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dm_capabilities: Option<crate::dm::DmCapabilities>,

    /// Hex ML-DSA-65 public key of the signing agent. Present on signed
    /// cards (x0x ≥ 0.24, ADR-0017) so verifiers can check `signature` and
    /// bind it to `agent_id` (which is SHA-256 of this key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_public_key: Option<String>,

    /// Hex ML-DSA-65 signature over [`AgentCard::signable_bytes`]. Present on
    /// signed cards; legacy unsigned cards carry `None` and still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A group reference inside an agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardGroup {
    /// Group name.
    pub name: String,
    /// Invite link (`x0x://invite/...`).
    pub invite_link: String,
}

/// A store reference inside an agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardStore {
    /// Store name.
    pub name: String,
    /// Gossip topic for the store.
    pub topic: String,
}

impl AgentCard {
    /// Create a new agent card.
    #[must_use]
    pub fn new(display_name: String, agent_id: &AgentId, machine_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            display_name,
            agent_id: hex::encode(agent_id.as_bytes()),
            machine_id: machine_id.to_string(),
            user_id: None,
            addresses: Vec::new(),
            groups: Vec::new(),
            stores: Vec::new(),
            created_at: now,
            // AgentCard is created without knowing the KEM pubkey; callers
            // that want a full advert populate via with_kem_public_key.
            dm_capabilities: Some(crate::dm::DmCapabilities::pending()),
            agent_public_key: None,
            signature: None,
        }
    }

    /// Encode this card as a shareable link.
    ///
    /// Format: `x0x://agent/<base64url(json)>`
    #[must_use]
    pub fn to_link(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("x0x://agent/{b64}")
    }

    /// Parse a card from a link string.
    ///
    /// Accepts `x0x://agent/<base64>` or raw base64.
    ///
    /// # Errors
    ///
    /// Returns an error if the link is malformed.
    pub fn from_link(link: &str) -> std::result::Result<Self, String> {
        let b64 = link.strip_prefix("x0x://agent/").unwrap_or(link).trim();

        use base64::Engine;
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("invalid base64: {e}"))?;

        let json_str = String::from_utf8(json_bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;

        serde_json::from_str(&json_str).map_err(|e| format!("invalid card JSON: {e}"))
    }

    /// Get a short display string for this card.
    #[must_use]
    pub fn short_display(&self) -> String {
        let id_short = if self.agent_id.len() >= 8 {
            &self.agent_id[..8]
        } else {
            &self.agent_id
        };
        format!("{} ({}…)", self.display_name, id_short)
    }

    /// Canonical bytes signed by the agent to produce [`AgentCard::signature`].
    ///
    /// Deterministic, domain-prefixed, length-prefixed encoding of every
    /// semantic field plus `agent_public_key`. Excludes `signature` itself.
    /// Mirrors the `GroupCard` signing scheme for consistency.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(AGENT_CARD_SIGNATURE_DOMAIN);
        push_len_prefixed(&mut buf, self.display_name.as_bytes());
        push_len_prefixed(&mut buf, self.agent_id.as_bytes());
        push_len_prefixed(&mut buf, self.machine_id.as_bytes());
        push_len_prefixed(&mut buf, self.user_id.as_deref().unwrap_or("").as_bytes());
        buf.extend_from_slice(&(self.addresses.len() as u32).to_le_bytes());
        for a in &self.addresses {
            push_len_prefixed(&mut buf, a.as_bytes());
        }
        buf.extend_from_slice(&(self.groups.len() as u32).to_le_bytes());
        for g in &self.groups {
            push_len_prefixed(&mut buf, g.name.as_bytes());
            push_len_prefixed(&mut buf, g.invite_link.as_bytes());
        }
        buf.extend_from_slice(&(self.stores.len() as u32).to_le_bytes());
        for s in &self.stores {
            push_len_prefixed(&mut buf, s.name.as_bytes());
            push_len_prefixed(&mut buf, s.topic.as_bytes());
        }
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        let dm_bytes = bincode::serialize(&self.dm_capabilities).unwrap_or_default();
        push_len_prefixed(&mut buf, &dm_bytes);
        push_len_prefixed(
            &mut buf,
            self.agent_public_key.as_deref().unwrap_or("").as_bytes(),
        );
        buf
    }

    /// Sign this card with the agent keypair (ADR-0017).
    ///
    /// Populates `agent_public_key` and `signature`. The signature commits to
    /// the agent public key, binding it to `agent_id` (SHA-256 of that key) so
    /// a recipient cannot swap in a foreign key.
    ///
    /// # Errors
    /// Returns an error if ML-DSA-65 signing fails.
    pub fn sign(&mut self, keypair: &AgentKeypair) -> Result<(), IdentityError> {
        self.agent_public_key = Some(hex::encode(keypair.public_key().as_bytes()));
        self.signature = None;
        let sig = sign_with_ml_dsa(keypair.secret_key(), &self.signable_bytes()).map_err(|e| {
            IdentityError::CertificateVerification(format!("agent card sign: {e:?}"))
        })?;
        self.signature = Some(hex::encode(sig.as_bytes()));
        Ok(())
    }

    /// Verify the agent signature on this card.
    ///
    /// Checks the embedded `agent_public_key` hashes to `agent_id` and that
    /// `signature` verifies over [`AgentCard::signable_bytes`].
    ///
    /// # Errors
    /// Returns an error if the card is unsigned, the key/id binding fails, or
    /// the signature is invalid.
    pub fn verify_signature(&self) -> Result<(), IdentityError> {
        let (Some(sig_hex), Some(pk_hex)) =
            (self.signature.as_ref(), self.agent_public_key.as_ref())
        else {
            return Err(IdentityError::CertificateVerification(
                "agent card is not signed".to_string(),
            ));
        };
        let pubkey_bytes = hex::decode(pk_hex)
            .map_err(|e| IdentityError::CertificateVerification(format!("bad pubkey hex: {e}")))?;
        let pubkey = MlDsaPublicKey::from_bytes(&pubkey_bytes)
            .map_err(|e| IdentityError::CertificateVerification(format!("bad pubkey: {e:?}")))?;
        let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
        if derived != self.agent_id {
            return Err(IdentityError::CertificateVerification(format!(
                "agent_id {} does not match key-derived id {derived}",
                self.agent_id
            )));
        }
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| IdentityError::CertificateVerification(format!("bad sig hex: {e}")))?;
        let sig = MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|e| IdentityError::CertificateVerification(format!("bad sig: {e:?}")))?;
        verify_with_ml_dsa(&pubkey, &self.signable_bytes(), &sig).map_err(|e| {
            IdentityError::CertificateVerification(format!("agent card verify: {e:?}"))
        })?;
        Ok(())
    }
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_new_card() {
        let card = AgentCard::new("David".to_string(), &agent(1), &hex::encode([2u8; 32]));
        assert_eq!(card.display_name, "David");
        assert_eq!(card.agent_id.len(), 64);
        assert_eq!(card.machine_id.len(), 64);
        assert!(card.user_id.is_none());
        assert!(card.addresses.is_empty());
        assert!(card.groups.is_empty());
        assert!(card.created_at > 0);
    }

    #[test]
    fn test_link_roundtrip() {
        let mut card = AgentCard::new("Alice".to_string(), &agent(1), &hex::encode([2u8; 32]));
        card.user_id = Some(hex::encode([3u8; 32]));
        card.addresses = vec!["1.2.3.4:5483".to_string()];
        card.groups.push(CardGroup {
            name: "Team".to_string(),
            invite_link: "x0x://invite/abc123".to_string(),
        });
        card.stores.push(CardStore {
            name: "Shared".to_string(),
            topic: "shared-kv".to_string(),
        });

        let link = card.to_link();
        assert!(link.starts_with("x0x://agent/"));

        let restored = AgentCard::from_link(&link).expect("parse");
        assert_eq!(card.display_name, restored.display_name);
        assert_eq!(card.agent_id, restored.agent_id);
        assert_eq!(card.machine_id, restored.machine_id);
        assert_eq!(card.user_id, restored.user_id);
        assert_eq!(card.addresses, restored.addresses);
        assert_eq!(card.groups.len(), 1);
        assert_eq!(card.stores.len(), 1);
    }

    #[test]
    fn test_from_link_raw_base64() {
        let card = AgentCard::new("Bob".to_string(), &agent(5), &hex::encode([6u8; 32]));
        let link = card.to_link();
        let raw = link.strip_prefix("x0x://agent/").expect("prefix");
        let restored = AgentCard::from_link(raw).expect("parse raw");
        assert_eq!(card.agent_id, restored.agent_id);
    }

    #[test]
    fn test_from_link_invalid() {
        assert!(AgentCard::from_link("garbage!!!").is_err());
    }

    #[test]
    fn test_short_display() {
        let card = AgentCard::new("David".to_string(), &agent(1), &hex::encode([2u8; 32]));
        let display = card.short_display();
        assert!(display.starts_with("David ("));
        assert!(display.contains('…'));
    }

    #[test]
    fn test_minimal_card_no_optional_fields() {
        let card = AgentCard::new("Minimal".to_string(), &agent(1), &hex::encode([2u8; 32]));
        let json = serde_json::to_string(&card).expect("serialize");
        // user_id, groups, stores should NOT appear in JSON when empty
        assert!(!json.contains("user_id"));
        assert!(!json.contains("groups"));
        assert!(!json.contains("stores"));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp = AgentKeypair::generate().expect("keypair");
        let mut card = AgentCard::new(
            "Signer".to_string(),
            &kp.agent_id(),
            &hex::encode([9u8; 32]),
        );
        card.addresses = vec!["1.2.3.4:5483".to_string()];
        card.sign(&kp).expect("sign");
        assert!(card.signature.is_some());
        assert!(card.agent_public_key.is_some());
        card.verify_signature().expect("verify");
    }

    #[test]
    fn test_signature_detects_tamper() {
        let kp = AgentKeypair::generate().expect("keypair");
        let mut card = AgentCard::new(
            "Signer".to_string(),
            &kp.agent_id(),
            &hex::encode([9u8; 32]),
        );
        card.sign(&kp).expect("sign");

        // Tampering with any signed field must invalidate the signature —
        // this is WHY the card is signed: reachability hints and capabilities
        // cannot be forged by a relay.
        let mut bad = card.clone();
        bad.display_name = "Mallory".to_string();
        assert!(bad.verify_signature().is_err());

        let mut bad = card.clone();
        bad.addresses.push("9.9.9.9:1".to_string());
        assert!(bad.verify_signature().is_err());
    }

    #[test]
    fn test_signature_rejects_forged_pubkey() {
        // Swapping in another agent's public key must fail: the key no longer
        // hashes to the card's agent_id, so the binding check rejects it.
        let kp = AgentKeypair::generate().expect("kp");
        let other = AgentKeypair::generate().expect("kp2");
        let mut card = AgentCard::new(
            "Signer".to_string(),
            &kp.agent_id(),
            &hex::encode([9u8; 32]),
        );
        card.sign(&kp).expect("sign");
        card.agent_public_key = Some(hex::encode(other.public_key().as_bytes()));
        assert!(card.verify_signature().is_err());
    }

    #[test]
    fn test_unsigned_legacy_card_parses_but_verify_fails() {
        let card = AgentCard::new("Legacy".to_string(), &agent(1), &hex::encode([2u8; 32]));
        assert!(card.signature.is_none());
        assert!(card.verify_signature().is_err());
        let link = card.to_link();
        let restored = AgentCard::from_link(&link).expect("parse");
        assert!(restored.signature.is_none());
    }

    #[test]
    fn test_signed_card_link_roundtrip_verifies() {
        // The signature must survive the base64-link transport that carries
        // cards between agents, or import-time verification is pointless.
        let kp = AgentKeypair::generate().expect("kp");
        let mut card = AgentCard::new(
            "Signer".to_string(),
            &kp.agent_id(),
            &hex::encode([9u8; 32]),
        );
        card.stores.push(CardStore {
            name: "s".to_string(),
            topic: "t".to_string(),
        });
        card.sign(&kp).expect("sign");
        let link = card.to_link();
        let restored = AgentCard::from_link(&link).expect("parse");
        restored
            .verify_signature()
            .expect("verify after link roundtrip");
    }
}
