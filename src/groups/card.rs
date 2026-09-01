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

/// Domain separator for v1 agent card signatures (ADR-0017, pre-0036).
/// FROZEN: v1 bytes are exactly the pre-0036 encoding — see
/// [`AgentCard::signable_bytes`].
const AGENT_CARD_SIGNATURE_DOMAIN: &[u8] = b"x0x-agent-card-v1";

/// Domain separator for v2 agent card signatures (ADR-0036): the v1 fields
/// plus `owner_name`, under a distinct domain so a v2 signature can never
/// verify under the v1 rule (and vice versa). Old verifiers fail CLOSED on
/// v2 cards — an explicit version error, never a silent domain change.
const AGENT_CARD_SIGNATURE_DOMAIN_V2: &[u8] = b"x0x-agent-card-v2";

/// Stable scheme identifier recorded on v2-signed cards (mirrors the
/// `x0x.agent-sign.v2.ml-dsa-65` convention from `/agent/sign`).
pub const AGENT_CARD_SIGNATURE_SCHEME_V2: &str = "x0x.agent-card.v2.ml-dsa-65";

/// A shareable identity card for an x0x agent.
///
/// ACCEPTED v1 LIMITATION (review R2, documented not built): pre-0036
/// peers REJECT owner-named (v2) cards outright — they verify under v1
/// only and fail closed. This is the same posture as ADR-0029 (fail-closed
/// on unknown versions) and converges via fleet self-update; ownerless
/// cards remain fully interoperable both ways. Unicode normalization of
/// names is likewise deferred (names are stored/compared verbatim).
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

    /// Human-readable name of the owner behind this agent (ADR-0036),
    /// e.g. "David Irvine". Populated from the daemon's stored self-profile
    /// (`human_name`); absent on cards from installs without one. A card
    /// carrying an owner_name is signed under the v2 domain
    /// (`AGENT_CARD_SIGNATURE_DOMAIN_V2`) and records
    /// [`AGENT_CARD_SIGNATURE_SCHEME_V2`] in `signature_scheme`; cards
    /// without one keep the exact v1 encoding, so pre-0036 verifiers only
    /// ever see byte-compatible v1 cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,

    /// Signing scheme marker. `None` (or absent) = v1 (pre-0036) signature;
    /// `Some(AGENT_CARD_SIGNATURE_SCHEME_V2)` = v2. The marker is itself a
    /// v2-signed field, so stripping it from a v2 card invalidates the
    /// signature (fail-closed), and a v1 card cannot gain one without a new
    /// signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
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
            owner_name: None,
            signature_scheme: None,
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

    /// Canonical v1 bytes signed by the agent to produce
    /// [`AgentCard::signature`] (ADR-0017, pre-0036).
    ///
    /// Deterministic, domain-prefixed, length-prefixed encoding of every
    /// semantic field plus `agent_public_key`. Excludes `signature` itself.
    /// Mirrors the `GroupCard` signing scheme for consistency.
    ///
    /// FROZEN (review P0): `owner_name` and `signature_scheme` are NOT
    /// encoded here, even as empty strings — `push_len_prefixed("")`
    /// appends four zero bytes and would break every pre-0036 signature in
    /// both directions. v1 bytes must remain byte-identical to the
    /// pre-0036 encoder; `signable_bytes_v1_matches_frozen_pre0036_vector`
    /// pins them against a hardcoded vector.
    ///
    /// FROZEN (#450): `dm_capabilities` is bincode-encoded in its
    /// pre-#437 five-field projection (see the encoding site below) so a
    /// card signed with `digest_support: true` still verifies on a
    /// v0.40.4 reader that drops the field. Post-v1 caps fields must
    /// never enter this encoding.
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
        buf.extend_from_slice(&(self.created_at).to_le_bytes());
        // #450: the caps encoding is FROZEN to the pre-#437 five-field
        // shape. Cards travel as JSON; a v0.40.4 reader's `DmCapabilities`
        // has no `digest_support` field and no `deny_unknown_fields`, so
        // serde drops the bit and the verifier rebuilds bincode from the
        // five surviving fields. Signing exactly those bytes means the
        // recomputation matches on old AND new peers. The bit itself is
        // therefore unsigned in cards and is clamped untrusted at
        // `CapabilityStore::insert_from_card`.
        let dm_bytes = bincode::serialize(
            &self
                .dm_capabilities
                .as_ref()
                .map(crate::dm::DmCapabilities::to_v1_wire),
        )
        .unwrap_or_default();
        push_len_prefixed(&mut buf, &dm_bytes);
        push_len_prefixed(
            &mut buf,
            self.agent_public_key.as_deref().unwrap_or("").as_bytes(),
        );
        buf
    }

    /// Canonical v2 bytes (ADR-0036): the v1 field set, under the v2
    /// domain, plus `owner_name` and the scheme identifier — both
    /// committed, so neither can be stripped or swapped without breaking
    /// the signature.
    #[must_use]
    pub fn signable_bytes_v2(&self) -> Vec<u8> {
        let mut buf = self.signable_bytes();
        // Re-prefix under the v2 domain: the v1 builder started with the v1
        // domain bytes; swap them so the rest of the encoding is shared.
        let v1_len = AGENT_CARD_SIGNATURE_DOMAIN.len();
        let v2_len = AGENT_CARD_SIGNATURE_DOMAIN_V2.len();
        buf.splice(0..v1_len, AGENT_CARD_SIGNATURE_DOMAIN_V2.iter().copied());
        buf.reserve(v2_len - v1_len + 4 + self.owner_name.as_deref().map_or(0, str::len));
        push_len_prefixed(
            &mut buf,
            self.owner_name.as_deref().unwrap_or("").as_bytes(),
        );
        push_len_prefixed(&mut buf, AGENT_CARD_SIGNATURE_SCHEME_V2.as_bytes());
        buf
    }

    /// Sign this card with the agent keypair (ADR-0017).
    ///
    /// Populates `agent_public_key` and `signature`. The signature commits to
    /// the agent public key, binding it to `agent_id` (SHA-256 of that key) so
    /// a recipient cannot swap in a foreign key.
    ///
    /// ADR-0036 domain selection: a card with an `owner_name` signs the v2
    /// encoding and records [`AGENT_CARD_SIGNATURE_SCHEME_V2`]; a card
    /// without one signs the v1 encoding exactly as pre-0036 did. The
    /// scheme marker is itself signed, so it cannot be stripped.
    ///
    /// # Errors
    /// Returns an error if ML-DSA-65 signing fails.
    pub fn sign(&mut self, keypair: &AgentKeypair) -> Result<(), IdentityError> {
        self.agent_public_key = Some(hex::encode(keypair.public_key().as_bytes()));
        self.signature = None;
        // The v2 encoding commits the SCHEME CONSTANT (not this field), so
        // the field is purely a verifier-facing marker set here.
        if self.owner_name.is_some() {
            self.signature_scheme = Some(AGENT_CARD_SIGNATURE_SCHEME_V2.to_string());
        } else {
            self.signature_scheme = None;
        }
        let bytes = if self.owner_name.is_some() {
            self.signable_bytes_v2()
        } else {
            self.signable_bytes()
        };
        let sig = sign_with_ml_dsa(keypair.secret_key(), &bytes).map_err(|e| {
            IdentityError::CertificateVerification(format!("agent card sign: {e:?}"))
        })?;
        self.signature = Some(hex::encode(sig.as_bytes()));
        Ok(())
    }

    /// Verify the agent signature on this card.
    ///
    /// Checks the embedded `agent_public_key` hashes to `agent_id` and that
    /// `signature` verifies under the card's recorded signing scheme.
    ///
    /// ADR-0036 scheme dispatch:
    /// - `signature_scheme: None` → v1 verification over
    ///   [`AgentCard::signable_bytes`] (byte-identical to pre-0036). A v1
    ///   card that carries an `owner_name` is REJECTED: v1 bytes do not
    ///   cover that field, so the name would ride unsigned (fail closed).
    /// - `signature_scheme: Some(AGENT_CARD_SIGNATURE_SCHEME_V2)` → v2
    ///   verification over [`AgentCard::signable_bytes_v2`], which commits
    ///   the owner name and the scheme marker.
    /// - any other scheme → explicit unknown-scheme error (never a silent
    ///   fallback).
    ///
    /// # Errors
    /// Returns an error if the card is unsigned, the key/id binding fails,
    /// the scheme is unknown, an unsigned field is present on a v1 card, or
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
        let bytes = match self.signature_scheme.as_deref() {
            None => {
                if self.owner_name.is_some() {
                    return Err(IdentityError::CertificateVerification(
                        "v1-signed card carries an unsigned owner_name; rejecting (ADR-0036)"
                            .to_string(),
                    ));
                }
                self.signable_bytes()
            }
            Some(AGENT_CARD_SIGNATURE_SCHEME_V2) => self.signable_bytes_v2(),
            Some(other) => {
                return Err(IdentityError::CertificateVerification(format!(
                    "unknown agent card signature scheme: {other}"
                )));
            }
        };
        verify_with_ml_dsa(&pubkey, &bytes, &sig).map_err(|e| {
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

    #[test]
    fn signable_bytes_v1_matches_frozen_pre0036_vector() {
        // A card whose v1 signable bytes are pinned to a HARDCODED pre-0036
        // vector (review P0: `push_len_prefixed("")` appends four zero
        // bytes, so a well-meant "encode None as empty" broke every pre-0036
        // signature in both directions — this test makes that class of
        // break impossible to reintroduce silently).
        let mut card = AgentCard::new("fae".to_string(), &agent(1), &hex::encode([2u8; 32]));
        card.addresses = vec!["203.0.113.7:5483".to_string()];
        card.created_at = 1_700_000_000;
        card.dm_capabilities = None; // bincode: single 0x00 None tag
        card.agent_public_key = Some("aabb".to_string());
        // Fields that must NEVER enter v1 bytes, even as empty strings.
        card.owner_name = Some("David Irvine".to_string());
        card.signature_scheme = Some(AGENT_CARD_SIGNATURE_SCHEME_V2.to_string());
        const FROZEN_PRE0036: &[u8] = &[
            120, 48, 120, 45, 97, 103, 101, 110, 116, 45, 99, 97, 114, 100, 45, 118, 49, 3, 0, 0,
            0, 102, 97, 101, 64, 0, 0, 0, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49,
            48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49,
            48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49,
            48, 49, 48, 49, 48, 49, 64, 0, 0, 0, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50,
            48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50,
            48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50, 48, 50,
            48, 50, 48, 50, 48, 50, 48, 50, 0, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0, 50, 48, 51, 46,
            48, 46, 49, 49, 51, 46, 55, 58, 53, 52, 56, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 83,
            101, 0, 0, 0, 0, 1, 0, 0, 0, 0, 4, 0, 0, 0, 97, 97, 98, 98,
        ];
        assert_eq!(
            card.signable_bytes(),
            FROZEN_PRE0036,
            "v1 bytes must stay byte-identical to the pre-0036 encoder"
        );
    }

    #[test]
    fn test_owner_name_is_signed_under_v2_domain_and_round_trips() {
        // WHY (ADR-0036): owner_name is display metadata shared out-of-band
        // — an unsigned name could be swapped by a relay to impersonate the
        // owner, so a named card signs the v2 domain (which commits the
        // name AND the scheme marker) and must survive the link transport.
        let kp = AgentKeypair::generate().expect("kp");
        let mut card = AgentCard::new("fae".to_string(), &kp.agent_id(), &hex::encode([9u8; 32]));
        card.owner_name = Some("David Irvine".to_string());
        card.sign(&kp).expect("sign");
        assert_eq!(
            card.signature_scheme.as_deref(),
            Some(AGENT_CARD_SIGNATURE_SCHEME_V2)
        );
        assert!(card.verify_signature().is_ok());

        let restored = AgentCard::from_link(&card.to_link()).expect("parse");
        assert_eq!(restored.owner_name.as_deref(), Some("David Irvine"));
        assert_eq!(
            restored.signature_scheme.as_deref(),
            Some(AGENT_CARD_SIGNATURE_SCHEME_V2)
        );
        restored.verify_signature().expect("named card verifies");

        // Tampering with the owner name must fail — it is a v2-signed field.
        let mut bad = restored.clone();
        bad.owner_name = Some("Mallory".to_string());
        assert!(bad.verify_signature().is_err());

        // Stripping the scheme marker must fail — the v2 bytes commit it.
        let mut stripped = restored;
        stripped.signature_scheme = None;
        assert!(
            stripped.verify_signature().is_err(),
            "scheme strip must not downgrade to a passing v1 verify"
        );
    }

    #[test]
    fn test_v1_card_with_injected_owner_name_is_rejected() {
        // WHY: v1 bytes do not cover owner_name, so an attacker could append
        // a name to a legitimately v1-signed card and have it display as if
        // the owner wrote it. New verifiers fail closed on that shape.
        let kp = AgentKeypair::generate().expect("kp");
        let mut card = AgentCard::new("fae".to_string(), &kp.agent_id(), &hex::encode([9u8; 32]));
        card.sign(&kp).expect("sign");
        assert!(card.signature_scheme.is_none());
        assert!(card.verify_signature().is_ok());

        let mut forged = card;
        forged.owner_name = Some("Mallory".to_string());
        let err = forged
            .verify_signature()
            .expect_err("v1 card + unsigned owner_name must be rejected");
        assert!(
            err.to_string().contains("unsigned owner_name"),
            "error names the reason: {err}"
        );
    }

    #[test]
    fn test_ownerless_card_stays_v1_and_verifies_like_pre0036() {
        // WHY: cards without an owner_name must remain v1 — byte-compatible
        // with every pre-0036 signer and verifier (no scheme field, no v2
        // domain), so the rollout only affects named cards.
        let kp = AgentKeypair::generate().expect("kp");
        let mut card = AgentCard::new("fae".to_string(), &kp.agent_id(), &hex::encode([9u8; 32]));
        card.sign(&kp).expect("sign");
        assert!(card.owner_name.is_none());
        assert!(card.signature_scheme.is_none());
        assert!(card.verify_signature().is_ok());
        let restored = AgentCard::from_link(&card.to_link()).expect("parse");
        restored
            .verify_signature()
            .expect("ownerless card round-trips as v1");
    }

    // ------------------------------------------------------------------
    // #450 mixed-fleet fixtures: EXACT frozen replicas of tag v0.40.4
    // (git show v0.40.4:src/groups/card.rs), outer card and nested types
    // copied verbatim — no post-v0.40.4 fields, no current-type leakage.
    // ------------------------------------------------------------------

    /// v0.40.4 `DmCapabilities`: five fields, no `digest_support`, no
    /// `deny_unknown_fields` — its JSON decode DROPS the unknown field
    /// and its signable recompute uses these five only.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct V0404DmCapabilities {
        max_protocol_version: u16,
        gossip_inbox: bool,
        kem_algorithm: String,
        max_envelope_bytes: usize,
        #[serde(default)]
        kem_public_key: Vec<u8>,
    }

    /// v0.40.4 `CardGroup`.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct V0404CardGroup {
        name: String,
        invite_link: String,
    }

    /// v0.40.4 `CardStore`.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct V0404CardStore {
        name: String,
        topic: String,
    }

    /// v0.40.4 `AgentCard`, copied field-for-field from the tag (review
    /// r3): `display_name`, `agent_id`, `machine_id`, `user_id`,
    /// `addresses`, `groups`, `stores`, `created_at`, `dm_capabilities`
    /// (with the frozen five-field caps), `agent_public_key`,
    /// `signature` — and NOTHING else (no `owner_name`, no
    /// `signature_scheme`; both are post-0.40.4 ADR-0036 fields).
    /// Deserializing THIS build's card JSON through this type reproduces
    /// bit-for-bit what an old peer's serde sees: unknown post-v0.40.4
    /// fields and the caps' `digest_support` are silently dropped.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct V0404AgentCard {
        display_name: String,
        agent_id: String,
        machine_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
        #[serde(default)]
        addresses: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        groups: Vec<V0404CardGroup>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        stores: Vec<V0404CardStore>,
        created_at: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        dm_capabilities: Option<V0404DmCapabilities>,
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_public_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    }

    /// v0.40.4 `AgentCard::signable_bytes`, copied verbatim from the tag:
    /// the same length-prefixed grammar, with
    /// `bincode(Option<V0404DmCapabilities>)` as the caps encoding —
    /// exactly what a v0.40.4 binary recomputes from what it decoded.
    fn v0404_signable_bytes(card: &V0404AgentCard) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(AGENT_CARD_SIGNATURE_DOMAIN);
        push_len_prefixed(&mut buf, card.display_name.as_bytes());
        push_len_prefixed(&mut buf, card.agent_id.as_bytes());
        push_len_prefixed(&mut buf, card.machine_id.as_bytes());
        push_len_prefixed(&mut buf, card.user_id.as_deref().unwrap_or("").as_bytes());
        buf.extend_from_slice(&(card.addresses.len() as u32).to_le_bytes());
        for a in &card.addresses {
            push_len_prefixed(&mut buf, a.as_bytes());
        }
        buf.extend_from_slice(&(card.groups.len() as u32).to_le_bytes());
        for g in &card.groups {
            push_len_prefixed(&mut buf, g.name.as_bytes());
            push_len_prefixed(&mut buf, g.invite_link.as_bytes());
        }
        buf.extend_from_slice(&(card.stores.len() as u32).to_le_bytes());
        for s in &card.stores {
            push_len_prefixed(&mut buf, s.name.as_bytes());
            push_len_prefixed(&mut buf, s.topic.as_bytes());
        }
        buf.extend_from_slice(&card.created_at.to_le_bytes());
        let dm_bytes = bincode::serialize(&card.dm_capabilities).unwrap_or_default();
        push_len_prefixed(&mut buf, &dm_bytes);
        push_len_prefixed(
            &mut buf,
            card.agent_public_key.as_deref().unwrap_or("").as_bytes(),
        );
        buf
    }

    /// v0.40.4 `AgentCard::verify_signature`, copied verbatim from the
    /// tag: unsigned check, hex decode, key→`agent_id` binding, and the
    /// ML-DSA-65 verify over the old signable bytes — key and signature
    /// taken from the DECODED replica object, exactly as an old peer
    /// reads them off its own parse.
    fn v0404_verify_signature(card: &V0404AgentCard) -> Result<(), String> {
        let (Some(sig_hex), Some(pk_hex)) =
            (card.signature.as_ref(), card.agent_public_key.as_ref())
        else {
            return Err("agent card is not signed".to_string());
        };
        let pubkey_bytes = hex::decode(pk_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
        let pubkey =
            MlDsaPublicKey::from_bytes(&pubkey_bytes).map_err(|e| format!("bad pubkey: {e:?}"))?;
        let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
        if derived != card.agent_id {
            return Err(format!(
                "agent_id {} does not match key-derived id {derived}",
                card.agent_id
            ));
        }
        let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("bad sig hex: {e}"))?;
        let sig = MlDsaSignature::from_bytes(&sig_bytes).map_err(|e| format!("bad sig: {e:?}"))?;
        verify_with_ml_dsa(&pubkey, &v0404_signable_bytes(card), &sig)
            .map_err(|e| format!("agent card verify: {e:?}"))
    }

    /// #450 direction 1: an OWNERLESS (v1-domain) card signed by THIS
    /// build with `digest_support: true` must be ACCEPTED by the frozen
    /// v0.40.4 decoder replica. The card JSON is deserialized through the
    /// exact tag-copied `V0404AgentCard` (old peer's parse: the
    /// `digest_support` field is dropped), and verification uses the key
    /// and signature AS DECODED INTO that replica, through the tag's own
    /// verifier logic. Before the freeze, the true bit entered
    /// `bincode(dm_capabilities)`, the old recompute dropped it, and
    /// every card from a new binary failed verification on old peers.
    ///
    /// Scope note: v0.40.4 has no card-signature v2 domain at all; cards
    /// from newer builds carrying `owner_name`/`signature_scheme` fail
    /// closed there by design. This fixture pins the ownerless v1 path,
    /// the only shape old and new builds share.
    #[test]
    fn true_digest_card_verifies_under_frozen_v0404_decoder() {
        let kp = AgentKeypair::generate().expect("kp");
        let mut card = AgentCard::new("fae".to_string(), &kp.agent_id(), &hex::encode([9u8; 32]));
        card.addresses = vec!["203.0.113.7:5483".to_string()];
        card.groups.push(CardGroup {
            name: "grp".to_string(),
            invite_link: "x0x://invite/ab".to_string(),
        });
        card.stores.push(CardStore {
            name: "s".to_string(),
            topic: "t".to_string(),
        });
        card.dm_capabilities = Some(crate::dm::DmCapabilities::v2_durable_gossip_ready(vec![
            7u8;
            1184
        ]));
        assert!(card
            .dm_capabilities
            .as_ref()
            .is_some_and(|c| c.digest_support));
        assert!(card.owner_name.is_none(), "fixture pins the v1 domain");
        card.sign(&kp).expect("sign");

        // Old-peer transport: JSON, decoded through the EXACT frozen
        // v0.40.4 card type. The replica's caps struct has no
        // `digest_support`, so serde silently drops the field — the
        // old peer's parse, not a simulation of it.
        let json = serde_json::to_string(&card).expect("card json");
        let as_old: V0404AgentCard = serde_json::from_str(&json).expect("frozen v0.40.4 decode");
        assert!(as_old.dm_capabilities.is_some());

        // The frozen v0.40.4 recompute from the OLD type must equal the
        // NEW signer's bytes byte-for-byte...
        assert_eq!(
            v0404_signable_bytes(&as_old),
            card.signable_bytes(),
            "v0.40.4 recompute must match the frozen signed bytes"
        );
        // ...and the tag-copied old verifier, reading the key and
        // signature from its own decoded object, accepts the card.
        v0404_verify_signature(&as_old).expect(
            "a digest_support=true card signed by this build must verify on a v0.40.4 peer",
        );
    }

    /// #450 direction 2: a card signed by a v0.40.4 agent must keep
    /// verifying on THIS build. The old signer is simulated END-TO-END:
    /// the card is built and SIGNED as the exact replica type, serialized
    /// FROM the replica (genuinely old-shaped JSON: no post-0.40.4
    /// fields, caps without the digest bit), then decoded by the current
    /// `AgentCard` and verified by the current verifier.
    #[test]
    fn old_signed_card_verifies_on_new_decoder() {
        let kp = AgentKeypair::generate().expect("kp");
        // Build the card the way the v0.40.4 binary held it.
        let mut as_old = V0404AgentCard {
            display_name: "old".to_string(),
            agent_id: hex::encode(kp.agent_id().as_bytes()),
            machine_id: hex::encode([9u8; 32]),
            user_id: None,
            addresses: vec!["203.0.113.9:5483".to_string()],
            groups: vec![V0404CardGroup {
                name: "grp".to_string(),
                invite_link: "x0x://invite/cd".to_string(),
            }],
            stores: vec![V0404CardStore {
                name: "s".to_string(),
                topic: "t".to_string(),
            }],
            created_at: 1_700_000_999,
            dm_capabilities: Some(V0404DmCapabilities {
                max_protocol_version: 2,
                gossip_inbox: true,
                kem_algorithm: "ML-KEM-768".to_string(),
                max_envelope_bytes: crate::dm::MAX_ENVELOPE_BYTES,
                kem_public_key: vec![3u8; 1184],
            }),
            agent_public_key: Some(hex::encode(kp.public_key().as_bytes())),
            signature: None,
        };
        // Sign with the old binary's own encoding.
        let bytes = v0404_signable_bytes(&as_old);
        let sig = sign_with_ml_dsa(kp.secret_key(), &bytes).expect("old-style sign");
        as_old.signature = Some(hex::encode(sig.as_bytes()));

        // Old wire form: serialized FROM the replica type.
        let json = serde_json::to_string(&as_old).expect("old card json");
        assert!(!json.contains("digest_support"));
        assert!(!json.contains("owner_name"));
        let restored: AgentCard = serde_json::from_str(&json).expect("new decode");
        assert!(restored
            .dm_capabilities
            .as_ref()
            .is_some_and(|c| !c.digest_support));
        restored
            .verify_signature()
            .expect("v0.40.4-signed card must verify on this build");
    }

    /// The freeze is load-bearing in exactly one direction: encoding the
    /// FULL caps struct with a true bit produces different (longer) bytes
    /// than the old decoder can rebuild. Pin that difference so nobody
    /// "simplifies" the projection away and silently reintroduces #450.
    #[test]
    fn frozen_projection_is_the_only_old_compatible_encoding() {
        let caps = crate::dm::DmCapabilities::v2_durable_gossip_ready(vec![7u8; 1184]);
        let frozen = bincode::serialize(&Some(caps.clone().to_v1_wire())).expect("frozen encode");
        let full = bincode::serialize(&Some(caps)).expect("full encode");
        assert_eq!(
            frozen.len() + 1,
            full.len(),
            "the true bit appends one byte"
        );
        assert_ne!(frozen, full);
    }
}
