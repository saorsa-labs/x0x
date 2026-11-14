//! ADR 0079: the share-grant v2 envelope that carries owner and machine
//! names as ADR-0074 §1 name defaults.
//!
//! The envelope is a new typed DM (`x0x-sharegrant-v2\0` ‖ bincode of three
//! fields): the unchanged v1 [`ShareGrant`] with its v1 signature, a
//! [`GrantNames`] section, and a second signature by the same owner **user**
//! key over [`names_signed_bytes`]. The names signature binds the names to
//! exactly this grant (by the SHA-256 of the grant's signed bytes) and to
//! the key that `grant.owner` hashes to, so names can never be moved to
//! another grant or attributed to another user.
//!
//! Receivers verify the grant by the unchanged v1 rules, then the names
//! signature under `grant.owner_public_key`. If either fails the whole
//! envelope is refused (Malformed; ACK withheld). The grant is stored
//! byte-identical to a v1 delivery, so a v1 copy and a v2 copy of one
//! `grant_id` are an idempotent `Duplicate`. The names go only into the
//! grantee's local name store ([`crate::names::NameStore`]) as defaults,
//! which never silently rebind a pinned label.
//!
//! Old peers never see this envelope: senders gate it on the recipient's
//! verified [`crate::dm::CapabilityRegistry::SHARE_GRANT_NAMES_V1`] bit and
//! send the v1 payload otherwise. Names are never broadcast; they travel
//! only inside the end-to-end encrypted grant DM.

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{strict_decode, ShareGrant, ShareGrantError, MAX_GRANT_AGENTS};
use crate::identity::{MachineId, UserId, UserKeypair};

/// Versioned, NUL-terminated DM prefix of a v2 (names-carrying) share-grant
/// delivery (ADR 0079 §1).
pub const SHARE_GRANT_V2_DM_PREFIX: &[u8] = b"x0x-sharegrant-v2\0";

/// Domain separation for the names signature (ADR 0079 §1).
const GRANT_NAMES_SIG_DOMAIN: &[u8] = b"x0x-sharegrant-names-v1";

/// Upper bound on one encoded v2 envelope. The worst case (a maximal v1
/// grant plus 64 named machines at 128 bytes each and a second ML-DSA-65
/// signature) is about 22 KiB, so the decode bound rises from the v1
/// 32 KiB to 48 KiB for this prefix only (ADR 0079 §1).
pub const MAX_SHARE_GRANT_V2_BYTES: usize = 48 * 1024;

/// Longest `owner_name` or `machine_name`, in bytes (the ADR-0036
/// `SelfProfile::MAX_NAME_LEN` rule).
pub const MAX_GRANT_NAME_BYTES: usize = crate::profile::SelfProfile::MAX_NAME_LEN;

/// One machine the grant names: a machine that hosts at least one of the
/// granted agents, with the owner's synced ADR-0036 `machine_name` for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMachineName {
    /// The machine.
    pub machine_id: MachineId,
    /// The owner's display name for it (not yet a DNS label).
    pub machine_name: String,
}

/// The names section of a v2 grant envelope (ADR 0079 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantNames {
    /// The owner's ADR-0036 `human_name`, trimmed. `None` when the owner
    /// has none set.
    pub owner_name: Option<String>,
    /// Machines hosting granted agents, sorted by id, unique, at most
    /// [`MAX_GRANT_AGENTS`] entries.
    pub machines: Vec<GrantMachineName>,
}

/// One display name by the ADR-0036 rule, already in canonical (trimmed)
/// form so the signed bytes are unambiguous.
fn validate_display_name(field: &str, value: &str) -> Result<(), ShareGrantError> {
    crate::profile::SelfProfile::validate_name(field, value).map_err(ShareGrantError::Invalid)?;
    if value.trim() != value {
        return Err(ShareGrantError::Invalid(format!("{field} must be trimmed")));
    }
    Ok(())
}

impl GrantNames {
    /// Structural validation (ADR 0079 §1): at least one name, bounded
    /// counts and lengths, machines sorted by id and unique.
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`].
    pub fn validate(&self) -> Result<(), ShareGrantError> {
        if self.owner_name.is_none() && self.machines.is_empty() {
            return Err(ShareGrantError::Invalid(
                "a names section must carry an owner name or at least one machine".into(),
            ));
        }
        if let Some(name) = &self.owner_name {
            validate_display_name("owner_name", name)?;
        }
        if self.machines.len() > MAX_GRANT_AGENTS {
            return Err(ShareGrantError::Invalid(format!(
                "too many named machines (max {MAX_GRANT_AGENTS})"
            )));
        }
        for pair in self.machines.windows(2) {
            if pair[0].machine_id.0 >= pair[1].machine_id.0 {
                return Err(ShareGrantError::Invalid(
                    "machine names must be sorted by machine id and unique".into(),
                ));
            }
        }
        for machine in &self.machines {
            validate_display_name("machine_name", &machine.machine_name)?;
        }
        Ok(())
    }
}

/// The bytes the names signature covers (ADR 0079 §1):
/// `"x0x-sharegrant-names-v1" ‖ SHA-256(grant.signed_bytes()) ‖ presence
/// tag ‖ [u64 LE length ‖ owner_name] ‖ u32 LE machine count ‖ per machine
/// (32-byte id ‖ u64 LE length ‖ machine_name)`. Length prefixes and
/// fixed-width ids make the encoding injective.
#[must_use]
pub fn names_signed_bytes(grant: &ShareGrant, names: &GrantNames) -> Vec<u8> {
    let grant_digest = Sha256::digest(grant.signed_bytes());
    let mut out =
        Vec::with_capacity(GRANT_NAMES_SIG_DOMAIN.len() + 32 + 1 + 8 + MAX_GRANT_NAME_BYTES + 4);
    out.extend_from_slice(GRANT_NAMES_SIG_DOMAIN);
    out.extend_from_slice(&grant_digest);
    match &names.owner_name {
        Some(name) => {
            out.push(1);
            out.extend_from_slice(&(name.len() as u64).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(names.machines.len() as u32).to_le_bytes());
    for machine in &names.machines {
        out.extend_from_slice(machine.machine_id.as_bytes());
        out.extend_from_slice(&(machine.machine_name.len() as u64).to_le_bytes());
        out.extend_from_slice(machine.machine_name.as_bytes());
    }
    out
}

/// A v2 share-grant envelope (ADR 0079 §1): the unchanged v1 grant, the
/// names section, and the owner's names signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareGrantV2 {
    /// The unchanged v1 grant with its v1 signature.
    pub grant: ShareGrant,
    /// Owner and machine names.
    pub names: GrantNames,
    /// ML-DSA-65 signature by the owner user key over
    /// [`names_signed_bytes`].
    pub names_signature: Vec<u8>,
}

impl ShareGrantV2 {
    /// Wrap a signed v1 grant with a names section signed by the same
    /// owner user key.
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] when `owner_key` is not the grant's
    /// owner or the names fail [`GrantNames::validate`];
    /// [`ShareGrantError::BadSignature`] when signing fails.
    pub fn sign(
        owner_key: &UserKeypair,
        grant: ShareGrant,
        names: GrantNames,
    ) -> Result<Self, ShareGrantError> {
        if owner_key.user_id() != grant.owner {
            return Err(ShareGrantError::Invalid(
                "names must be signed by the grant's owner key".into(),
            ));
        }
        names.validate()?;
        let signature =
            sign_with_ml_dsa(owner_key.secret_key(), &names_signed_bytes(&grant, &names)).map_err(
                |e| ShareGrantError::BadSignature(format!("names signing failed: {e:?}")),
            )?;
        Ok(Self {
            grant,
            names,
            names_signature: signature.as_bytes().to_vec(),
        })
    }

    /// Full verification: the grant by the unchanged v1 rules
    /// ([`ShareGrant::verify`]), the names structurally, and the names
    /// signature under `grant.owner_public_key`.
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] or [`ShareGrantError::BadSignature`].
    pub fn verify(&self) -> Result<(), ShareGrantError> {
        self.grant.verify()?;
        self.names.validate()?;
        let key = MlDsaPublicKey::from_bytes(&self.grant.owner_public_key)
            .map_err(|_| ShareGrantError::BadSignature("invalid owner public key".into()))?;
        let signature = MlDsaSignature::from_bytes(&self.names_signature)
            .map_err(|e| ShareGrantError::BadSignature(format!("names signature format: {e:?}")))?;
        verify_with_ml_dsa(
            &key,
            &names_signed_bytes(&self.grant, &self.names),
            &signature,
        )
        .map_err(|e| ShareGrantError::BadSignature(format!("names signature: {e:?}")))
    }

    /// Typed DM payload: `SHARE_GRANT_V2_DM_PREFIX ‖ bincode(envelope)`.
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`] on encode failure.
    pub fn to_dm_payload(&self) -> Result<Vec<u8>, ShareGrantError> {
        let body = bincode::serialize(self)
            .map_err(|e| ShareGrantError::Malformed(format!("encode: {e}")))?;
        let mut out = Vec::with_capacity(SHARE_GRANT_V2_DM_PREFIX.len() + body.len());
        out.extend_from_slice(SHARE_GRANT_V2_DM_PREFIX);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strictly decode a typed DM payload: the v2 prefix, the 48 KiB bound,
    /// and a canonical bincode body (re-encoding must reproduce it exactly,
    /// so trailing or non-canonical bytes are refused). Verification is a
    /// separate step ([`Self::verify`]).
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`].
    pub fn from_dm_payload(payload: &[u8]) -> Result<Self, ShareGrantError> {
        let body = payload
            .strip_prefix(SHARE_GRANT_V2_DM_PREFIX)
            .ok_or_else(|| ShareGrantError::Malformed("missing v2 prefix".into()))?;
        if body.len() > MAX_SHARE_GRANT_V2_BYTES {
            return Err(ShareGrantError::Malformed("oversized".into()));
        }
        let envelope: Self = strict_decode(body, MAX_SHARE_GRANT_V2_BYTES as u64).map_err(|e| {
            ShareGrantError::Malformed(format!(
                "decode: {}",
                crate::wire_compat::classify_bincode("ShareGrantV2", &e)
            ))
        })?;
        let canonical = bincode::serialize(&envelope)
            .map_err(|e| ShareGrantError::Malformed(format!("re-encode: {e}")))?;
        if canonical != body {
            return Err(ShareGrantError::Malformed("non-canonical encoding".into()));
        }
        Ok(envelope)
    }

    /// The grant-names defaults this envelope carries, for
    /// [`crate::names::NameStore::apply_grant_names`]. `verified_hosts` is
    /// the caller's local hosting evidence
    /// ([`crate::Agent::verified_grant_hosts`]); it is never taken from the
    /// envelope.
    #[must_use]
    pub fn name_defaults(
        &self,
        verified_hosts: std::collections::BTreeSet<[u8; 32]>,
    ) -> crate::names::GrantNameDefaults {
        crate::names::GrantNameDefaults {
            verified_hosts,
            owner: self.grant.owner,
            owner_name: self.names.owner_name.clone(),
            machines: self
                .names
                .machines
                .iter()
                .map(|m| (m.machine_id, m.machine_name.clone()))
                .collect(),
        }
    }
}

/// Handle one typed v2 share-grant DM (ADR 0079 §1): decode and verify the
/// envelope, refuse a revoked grant, store the grant exactly as a v1
/// delivery would ([`super::handle_share_grant_dm_checked`] semantics), then
/// apply the names as ADR-0074 §1 defaults to `name_store`.
///
/// `local_user` is this install's owner, when it has one: names from the
/// local owner's own grants are skipped (the local owner is always `me`).
/// `owner_trusted` says whether the grant's owner is a Known or Trusted
/// contact (ADR 0079 §2 contact gate); a stranger's names are kept as a
/// suggestion, never applied. `verified_hosts` gives the machines with
/// local hosting evidence for the grant
/// ([`crate::Agent::verified_grant_hosts`]); a machine default for any other
/// machine is kept as a suggestion, never pinned.
///
/// The completion resolves `Inserted`/`Duplicate` only once the grant is
/// stored AND the name store holds the outcome durably; a name-store write
/// failure withholds the ACK so the sender's outbox retries the same bytes
/// (a replay is idempotent on both stores). A name store that failed to
/// load (`names.json` unreadable or corrupt) cannot recover by a retry, so
/// the grant is ACKed and its names are skipped; otherwise the sender would
/// retry forever. Name conflicts and suggestions are normal outcomes, not
/// failures.
pub async fn handle_share_grant_v2_dm<F, Fut, H, HFut>(
    store: Option<&super::ShareGrantStore>,
    revocations: Option<&tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    name_store: &crate::names::NameStore,
    local_user: Option<UserId>,
    owner_trusted: F,
    verified_hosts: H,
    typed: crate::dm_inbox::DmTypedPayload,
) -> crate::dm_inbox::DmTypedPayloadCompletionResult
where
    F: FnOnce(UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
    H: FnOnce(ShareGrant) -> HFut,
    HFut: std::future::Future<Output = std::collections::BTreeSet<[u8; 32]>>,
{
    let crate::dm_inbox::DmTypedPayload {
        sender,
        payload,
        completion,
        ..
    } = typed;
    let result = handle_v2_bytes(
        store,
        revocations,
        name_store,
        local_user,
        owner_trusted,
        verified_hosts,
        &payload,
    )
    .await;
    match &result {
        Ok(outcome) => tracing::info!(
            sender = %hex::encode(sender.as_bytes()),
            ?outcome,
            "v2 share grant received and stored; names applied"
        ),
        Err(reason) => tracing::info!(
            sender = %hex::encode(sender.as_bytes()),
            reason = %reason,
            "v2 share grant refused; ACK withheld"
        ),
    }
    if let Some(completion) = completion {
        let _ = completion.send(result.clone());
    }
    result
}

async fn handle_v2_bytes<F, Fut, H, HFut>(
    store: Option<&super::ShareGrantStore>,
    revocations: Option<&tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    name_store: &crate::names::NameStore,
    local_user: Option<UserId>,
    owner_trusted: F,
    verified_hosts: H,
    payload: &[u8],
) -> crate::dm_inbox::DmTypedPayloadCompletionResult
where
    F: FnOnce(UserId) -> Fut,
    Fut: std::future::Future<Output = bool>,
    H: FnOnce(ShareGrant) -> HFut,
    HFut: std::future::Future<Output = std::collections::BTreeSet<[u8; 32]>>,
{
    let Some(store) = store else {
        return Err("share grants are not enabled on this daemon".to_string());
    };
    let envelope = ShareGrantV2::from_dm_payload(payload).map_err(|e| e.to_string())?;
    if let Some(set) = revocations {
        let revoked = set
            .read()
            .await
            .is_share_grant_revoked(&envelope.grant.grant_id, &envelope.grant.owner);
        if revoked {
            return Err("share grant is revoked; not stored".to_string());
        }
    }
    envelope.verify().map_err(|e| e.to_string())?;
    let owner = envelope.grant.owner;
    let outcome = store
        .accept_reporting(envelope.grant.clone(), super::unix_now_secs())
        .await
        .map_err(|refusal| refusal.error.to_string())?;
    // ADR 0079 §2/§3: the names go only into the grantee's name store. The
    // local owner's own grants carry no useful default (`me` is reserved).
    if local_user == Some(owner) {
        return Ok(outcome);
    }
    // An unloadable name store fails every write until the operator repairs
    // names.json, so withholding the ACK would only make the sender retry
    // forever. ACK the stored grant and skip its names.
    if let Some(load_error) = name_store.load_error() {
        tracing::warn!(
            owner = %hex::encode(owner.as_bytes()),
            load_error,
            "grant stored; name defaults skipped because the name store did not load"
        );
        return Ok(outcome);
    }
    let trusted = owner_trusted(owner).await;
    let hosts = verified_hosts(envelope.grant.clone()).await;
    let defaults = envelope.name_defaults(hosts);
    match name_store
        .apply_grant_names(&defaults, trusted, super::unix_now_secs())
        .await
    {
        Ok(applied) => {
            tracing::info!(
                owner = %hex::encode(owner.as_bytes()),
                trusted,
                owner_label = applied.owner_label.as_deref().unwrap_or(""),
                owner_bound = applied.owner_bound,
                machine_pins = applied.machine_pins.len(),
                suggested = applied.suggested,
                conflicts = applied.conflicts,
                "grant name defaults processed"
            );
            Ok(outcome)
        }
        // A name-store write failure withholds the ACK: the sender retries
        // the same bytes and both stores take the replay idempotently.
        Err(e) => Err(format!("grant stored, but name defaults not durable: {e}")),
    }
}

// ─── Sender side (ADR 0079 §1 "Who gets v2") ────────────────────────────────

/// The owner-signed names attachment, as the sender and the redelivery
/// outbox persist it. Rebuilding the envelope from the same grant and
/// attachment reproduces the exact v2 bytes (bincode is deterministic), so
/// every retry resends the same bytes (ADR 0079 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrantNames {
    /// The names section.
    pub names: GrantNames,
    /// ML-DSA-65 signature by the owner user key over
    /// [`names_signed_bytes`].
    pub signature: Vec<u8>,
}

impl ShareGrantV2 {
    /// Rebuild the envelope a persisted attachment was taken from.
    #[must_use]
    pub fn from_parts(grant: ShareGrant, attachment: SignedGrantNames) -> Self {
        Self {
            grant,
            names: attachment.names,
            names_signature: attachment.signature,
        }
    }

    /// The attachment the redelivery outbox persists.
    #[must_use]
    pub fn attachment(&self) -> SignedGrantNames {
        SignedGrantNames {
            names: self.names.clone(),
            signature: self.names_signature.clone(),
        }
    }
}

/// The v2 counterpart of [`super::grant_delivery_request`]: the typed DM
/// payload and its logical request id (the BLAKE3 of the payload, so every
/// resend of the same bytes is the same idempotent logical request).
///
/// # Errors
/// [`ShareGrantError::Malformed`] on encode failure.
pub fn grant_delivery_request_v2(
    envelope: &ShareGrantV2,
) -> Result<(Vec<u8>, [u8; 16]), ShareGrantError> {
    let payload = envelope.to_dm_payload()?;
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(&blake3::hash(&payload).as_bytes()[..16]);
    Ok((payload, request_id))
}

/// The machines a grant names (ADR 0079 §1): machines with a current,
/// owner-verified ADR-0041 enrollment AND a synced, valid `machine_name`
/// AND (per `hosts`, the current announcements) at least one of the granted
/// agents. Sorted by id, unique, bounded by [`MAX_GRANT_AGENTS`].
#[must_use]
pub fn grant_machine_names(
    owner: &UserId,
    enrollments: &[crate::owner_sync::OwnerEnrollment],
    named: &[(MachineId, String)],
    hosts: &[(crate::identity::AgentId, MachineId)],
    now_ms: u64,
) -> Vec<GrantMachineName> {
    let enrolled: std::collections::BTreeSet<[u8; 32]> = enrollments
        .iter()
        .filter(|e| e.verify_owner(owner).is_ok() && e.is_current_at(now_ms))
        .map(|e| e.machine_id)
        .collect();
    let hosting: std::collections::BTreeSet<[u8; 32]> = hosts.iter().map(|(_, m)| m.0).collect();
    let mut out: std::collections::BTreeMap<[u8; 32], String> = std::collections::BTreeMap::new();
    for (machine, name) in named {
        if !enrolled.contains(&machine.0) || !hosting.contains(&machine.0) {
            continue;
        }
        if validate_display_name("machine_name", name).is_err() {
            continue;
        }
        out.entry(machine.0).or_insert_with(|| name.clone());
    }
    out.into_iter()
        .take(MAX_GRANT_AGENTS)
        .map(|(machine_id, machine_name)| GrantMachineName {
            machine_id: MachineId(machine_id),
            machine_name,
        })
        .collect()
}

/// The machines section of a grant this install issues (ADR 0079 §1):
/// [`grant_machine_names`] over the other owner machines, plus this
/// machine (`own_machine`) under its profile `machine_name` when it hosts a
/// granted agent. This machine's name always comes from the profile; a
/// synced record for it is ignored, because that record can be older than
/// the profile. With no valid profile name, this machine is not named.
#[must_use]
pub fn assemble_grant_machine_names(
    owner: &UserId,
    enrollments: &[crate::owner_sync::OwnerEnrollment],
    synced: &[(MachineId, String)],
    hosts: &[(crate::identity::AgentId, MachineId)],
    own_machine: MachineId,
    own_machine_name: Option<String>,
    now_ms: u64,
) -> Vec<GrantMachineName> {
    let others: Vec<(MachineId, String)> = synced
        .iter()
        .filter(|(machine, _)| *machine != own_machine)
        .cloned()
        .collect();
    let mut machines = grant_machine_names(owner, enrollments, &others, hosts, now_ms);
    let own_machine_name = own_machine_name
        .map(|name| name.trim().to_string())
        .filter(|name| validate_display_name("machine_name", name).is_ok());
    if let Some(name) = own_machine_name {
        if hosts.iter().any(|(_, machine)| *machine == own_machine)
            && machines.len() < MAX_GRANT_AGENTS
        {
            machines.push(GrantMachineName {
                machine_id: own_machine,
                machine_name: name,
            });
            machines.sort_by_key(|m| m.machine_id.0);
        }
    }
    machines
}

impl crate::Agent {
    /// The authority machine currently hosting each of the grant's agents:
    /// this install's own machine for its own agent, and the authorized
    /// routing machine of each announced agent otherwise.
    pub async fn granted_agent_hosts(
        &self,
        grant: &ShareGrant,
    ) -> Vec<(crate::identity::AgentId, MachineId)> {
        let mut out = Vec::with_capacity(grant.agents.len());
        for agent in &grant.agents {
            let machine = if *agent == self.agent_id() {
                Some(self.machine_id())
            } else {
                let hinted = self
                    .identity_discovery_cache
                    .read()
                    .await
                    .get(agent)
                    .map(|entry| entry.machine_id);
                self.authorized_routing_machine(agent, hinted).await
            };
            if let Some(machine) = machine {
                out.push((*agent, machine));
            }
        }
        out
    }

    /// The names section for a grant this install's owner is issuing
    /// (ADR 0079 §1), or `None` when there is nothing valid to carry (the
    /// grant is then sent as v1). `owner_name` and `own_machine_name` are
    /// the ADR-0036 profile `human_name` and `machine_name`; other machines
    /// come from the owner's current enrollments, the synced machine names
    /// in `devices`, and the current announcements hosting the granted
    /// agents. This daemon's own machine needs no enrollment record: the
    /// issuing install signs the section with the owner key, which vouches
    /// for its own profile name directly. Its name is always the profile
    /// `machine_name`; a synced record for it is ignored, because that
    /// record can be older than the profile.
    pub async fn grant_names_for(
        &self,
        devices: Option<&crate::owner_sync::OwnerSyncStore>,
        owner_name: Option<String>,
        own_machine_name: Option<String>,
        grant: &ShareGrant,
    ) -> Option<GrantNames> {
        if self.user_id() != Some(grant.owner) {
            return None;
        }
        let owner_name = owner_name
            .map(|name| name.trim().to_string())
            .filter(|name| validate_display_name("owner_name", name).is_ok());
        let hosts = self.granted_agent_hosts(grant).await;
        let (enrollments, synced) = match devices {
            None => (Vec::new(), Vec::new()),
            Some(devices) => {
                let mut named = Vec::new();
                for record in devices.records_snapshot().await {
                    if let crate::owner_sync::SyncValue::MachineNames {
                        machine_name: Some(machine_name),
                        ..
                    } = &record.value
                    {
                        let Ok(bytes) = hex::decode(&record.key) else {
                            continue;
                        };
                        let Ok(bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                            continue;
                        };
                        if record.verify_owner(&grant.owner).is_ok() {
                            named.push((MachineId(bytes), machine_name.clone()));
                        }
                    }
                }
                (devices.enrolled_devices().await, named)
            }
        };
        let machines = assemble_grant_machine_names(
            &grant.owner,
            &enrollments,
            &synced,
            &hosts,
            self.machine_id(),
            own_machine_name,
            super::unix_now_secs().saturating_mul(1000),
        );
        if owner_name.is_none() && machines.is_empty() {
            return None;
        }
        Some(GrantNames {
            owner_name,
            machines,
        })
    }

    /// Sign `names` onto `grant` with this install's owner key (ADR 0079 §1).
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`] without an owner key or on invalid
    /// names; [`ShareGrantError::BadSignature`] when signing fails.
    pub fn sign_grant_names(
        &self,
        grant: ShareGrant,
        names: GrantNames,
    ) -> Result<ShareGrantV2, ShareGrantError> {
        let key = self.identity().user_keypair().ok_or_else(|| {
            ShareGrantError::Invalid("signing grant names needs the owner key".into())
        })?;
        ShareGrantV2::sign(key, grant, names)
    }
}

#[cfg(test)]
mod tests;
