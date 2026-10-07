//! ADR 0115: identity discovery authority.
//!
//! An identity announcement (V2 `X0A2`, V3 `X0A3`/`X0A4`) is signed by a
//! machine key only, and an `AgentCertificate` carries no consent from the
//! agent it names. So a valid announcement proves only that its machine
//! signed it. This module holds the rules that decide what such an
//! announcement may change.
//!
//! §1 [`classify`]: only an agent-authenticated announcement (class A), or
//! one from the agent's authenticated machine (class B), may set the
//! discovery entry's authority fields. Any other one (class C) changes
//! nothing for the agent.

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) mod quarantine;

use crate::dm_inbox::AuthenticatedMachineBinding;
use crate::identity::MachineId;

/// ADR 0115 §1: the provenance class of one verified identity announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnnouncementClass {
    /// Class A: the verified pubsub envelope author is the announced agent.
    AgentAuthenticated,
    /// Class B: not class A, but the announcing machine is the agent's
    /// authenticated pairing.
    BoundMachine,
    /// Class C: neither. It sets no authority field and writes no
    /// authority store.
    Unauthenticated,
}

impl AnnouncementClass {
    /// Whether this class may set or replace authority fields.
    pub(crate) const fn grants_authority(self) -> bool {
        !matches!(self, Self::Unauthenticated)
    }
}

/// ADR 0115 §1: classify one verified identity announcement for agent X,
/// signed by `machine`.
///
/// - `direct_origin`: `identity_announcement_has_direct_agent_origin`.
/// - `attested`: X's entry in the authenticated-binding store. Its writers
///   are class A announcements, ADR 0021 origin attestations and one local
///   source: the local user's card import (`Agent::pin_card_binding`, a
///   token-authenticated REST action that no network input reaches).
/// - `pairing_revoked`: `machine` or the (X, `machine`) binding is revoked.
/// - `evidence_pairs`: whether a usable ADR 0089 evidence record exists for
///   exactly (X, `machine`). It runs only when nothing else decides, so the
///   evidence store's use counters see only the announcements that need it.
///
/// The pairing is authenticated when the attested binding names `machine`,
/// its certificate expiry has not passed, and the pairing is not revoked;
/// or when the evidence record exists (its own check covers revocation and
/// expiry).
pub(crate) fn classify(
    direct_origin: bool,
    machine: MachineId,
    attested: Option<AuthenticatedMachineBinding>,
    pairing_revoked: bool,
    evidence_pairs: impl FnOnce() -> bool,
    now_secs: u64,
) -> AnnouncementClass {
    if direct_origin {
        return AnnouncementClass::AgentAuthenticated;
    }
    let attested_pairs = !pairing_revoked
        && attested.is_some_and(|binding| {
            binding.machine_id == machine
                && !crate::identity::is_expired(binding.cert_not_after, now_secs)
        });
    if attested_pairs || evidence_pairs() {
        AnnouncementClass::BoundMachine
    } else {
        AnnouncementClass::Unauthenticated
    }
}

/// ADR 0115 §1: [`classify`] one verified identity announcement with the
/// node's live stores. Each lock is taken alone.
pub(crate) async fn classify_announcement(
    msg: &crate::gossip::PubSubMessage,
    announcement: &crate::IdentityAnnouncement,
    revocation_set: &tokio::sync::RwLock<crate::revocation::RevocationSet>,
    attested_store: &crate::dm_inbox::AuthenticatedMachineBindings,
    evidence: &crate::peer_evidence::EvidenceRuntime,
) -> AnnouncementClass {
    let (agent, machine) = (announcement.agent_id, announcement.machine_id);
    let pairing_revoked = {
        let revoked = revocation_set.read().await;
        revoked.is_machine_revoked(&machine) || revoked.is_binding_revoked(&agent, &machine)
    };
    let attested = attested_store.read().await.peek(&agent);
    classify(
        crate::identity_announcement_has_direct_agent_origin(msg, announcement),
        machine,
        attested,
        pairing_revoked,
        || {
            evidence
                .usable(agent, machine, crate::dm_capability::now_unix_ms())
                .is_some()
        },
        crate::Agent::unix_timestamp_secs(),
    )
}

/// ADR 0115 §2: the machine that an agent's authority stores name.
///
/// `announced` is the agent's announced-binding store record (written only
/// by class A and B announcements); `attested` is its authenticated-binding
/// store record (class A announcements and ADR 0021 origin attestations).
/// The newer record wins; on a tie the announced record wins, as in
/// `select_pinned_binding`. A zero machine names nothing. Expiry stays with
/// the caller, which applies its own certificate check.
pub(crate) fn authority_machine(
    announced: Option<AuthenticatedMachineBinding>,
    attested: Option<AuthenticatedMachineBinding>,
) -> Option<MachineId> {
    let real = |binding: &AuthenticatedMachineBinding| binding.machine_id.0 != [0u8; 32];
    match (announced.filter(real), attested.filter(real)) {
        (Some(announced), Some(attested)) => {
            Some(if attested.announced_at > announced.announced_at {
                attested.machine_id
            } else {
                announced.machine_id
            })
        }
        (Some(binding), None) | (None, Some(binding)) => Some(binding.machine_id),
        (None, None) => None,
    }
}

/// ADR 0115 §2: whether an authority store confirms that the agent lives
/// on `machine`: its announced-binding record (class A and B only), its
/// authenticated binding, or a usable ADR 0089 evidence record for exactly
/// (agent, `machine`). `evidence` runs only when neither record names the
/// machine. A zero machine is never confirmed.
pub(crate) fn confirms(
    machine: MachineId,
    announced: Option<AuthenticatedMachineBinding>,
    attested: Option<AuthenticatedMachineBinding>,
    evidence: impl FnOnce() -> bool,
) -> bool {
    if machine.0 == [0u8; 32] {
        return false;
    }
    let names = |binding: Option<AuthenticatedMachineBinding>| {
        binding.is_some_and(|binding| binding.machine_id == machine)
    };
    names(announced) || names(attested) || evidence()
}

/// ADR 0115 §2 (strict): the machine a security reader may use for an
/// agent whose discovery entry routes to `routing`. The routing machine
/// counts only when `routing_confirmed` (see [`confirms`]); otherwise the
/// authority machine is used, and with neither the reader has no machine.
pub(crate) fn authorized_machine(
    routing: Option<MachineId>,
    routing_confirmed: bool,
    authority: Option<MachineId>,
) -> Option<MachineId> {
    match routing {
        Some(routing) if routing_confirmed => Some(routing),
        _ => authority,
    }
}

/// The digest an announcement commits to for this certificate.
pub(crate) fn certificate_digest(cert: &crate::identity::AgentCertificate) -> [u8; 32] {
    crate::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone()))
}

/// ADR 0115 §3: whether `cert` has authenticated provenance, given the
/// subject's announced-binding store record. Only class A and B
/// announcements write that store, and it keeps the certificate digest the
/// latest one committed to.
pub(crate) fn has_authenticated_provenance(
    cert: &crate::identity::AgentCertificate,
    announced: Option<AuthenticatedMachineBinding>,
) -> bool {
    announced
        .and_then(|binding| binding.cert_digest)
        .is_some_and(|digest| digest == certificate_digest(cert))
}

/// ADR 0115 §4: whether two certificates have the same owner (`UserId`).
/// An unreadable owner never matches.
pub(crate) fn same_owner(
    a: &crate::identity::AgentCertificate,
    b: &crate::identity::AgentCertificate,
) -> bool {
    match (a.user_id(), b.user_id()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

static UNAUTHENTICATED_ANNOUNCES: AtomicU64 = AtomicU64::new(0);
static BUNDLE_OWNER_UNAUTHENTICATED: AtomicU64 = AtomicU64::new(0);
static REVOCATION_FUTURE_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Count one class C announcement (`identity_announce_unauthenticated`).
pub(crate) fn note_unauthenticated_announce() {
    UNAUTHENTICATED_ANNOUNCES.fetch_add(1, Ordering::Relaxed);
}

/// Count one bundle rejected by §4 (`activation_bundle_owner_unauthenticated`).
pub(crate) fn note_bundle_owner_unauthenticated() {
    BUNDLE_OWNER_UNAUTHENTICATED.fetch_add(1, Ordering::Relaxed);
}

/// Count revocation records rejected or dropped by §5
/// (`revocation_future_dropped`).
pub(crate) fn note_revocation_future_dropped(count: u64) {
    REVOCATION_FUTURE_DROPPED.fetch_add(count, Ordering::Relaxed);
}

/// The ADR 0115 counters (process-wide), for `GET /diagnostics/gossip`.
pub(crate) fn counters_json() -> serde_json::Value {
    serde_json::json!({
        "identity_announce_unauthenticated": UNAUTHENTICATED_ANNOUNCES.load(Ordering::Relaxed),
        "activation_bundle_owner_unauthenticated":
            BUNDLE_OWNER_UNAUTHENTICATED.load(Ordering::Relaxed),
        "revocation_future_dropped": REVOCATION_FUTURE_DROPPED.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm_inbox::AuthenticatedMachineBindingCache;
    use crate::identity::AgentId;

    pub(super) fn binding(
        machine: MachineId,
        announced_at: u64,
        digest: Option<[u8; 32]>,
        not_after: Option<u64>,
    ) -> AuthenticatedMachineBinding {
        let agent = AgentId([7; 32]);
        let mut store = AuthenticatedMachineBindingCache::default();
        store.record_announcement(agent, machine, announced_at, digest, not_after);
        store.peek(&agent).expect("recorded binding")
    }

    #[test]
    fn classify_follows_the_three_classes() {
        let bound = MachineId([1; 32]);
        let other = MachineId([2; 32]);
        let now = 10_000;
        let attested = Some(binding(bound, 100, None, None));
        assert_eq!(
            classify(true, other, None, false, || false, now),
            AnnouncementClass::AgentAuthenticated
        );
        assert_eq!(
            classify(false, bound, attested, false, || false, now),
            AnnouncementClass::BoundMachine
        );
        assert_eq!(
            classify(false, other, attested, false, || false, now),
            AnnouncementClass::Unauthenticated
        );
        assert_eq!(
            classify(false, other, None, false, || true, now),
            AnnouncementClass::BoundMachine,
            "a usable ADR 0089 record authenticates the pairing"
        );
        assert_eq!(
            classify(false, bound, attested, true, || false, now),
            AnnouncementClass::Unauthenticated,
            "a revoked pairing authenticates nothing"
        );
        let expired = Some(binding(bound, 100, None, Some(1)));
        assert_eq!(
            classify(false, bound, expired, false, || false, now),
            AnnouncementClass::Unauthenticated,
            "an expired binding authenticates nothing"
        );
        assert!(AnnouncementClass::AgentAuthenticated.grants_authority());
        assert!(AnnouncementClass::BoundMachine.grants_authority());
        assert!(!AnnouncementClass::Unauthenticated.grants_authority());
    }

    #[test]
    fn authority_machine_prefers_the_newer_record_and_ties_to_announced() {
        let first = MachineId([1; 32]);
        let second = MachineId([2; 32]);
        let zero = MachineId([0; 32]);
        assert_eq!(authority_machine(None, None), None);
        assert_eq!(
            authority_machine(Some(binding(first, 10, None, None)), None),
            Some(first)
        );
        assert_eq!(
            authority_machine(None, Some(binding(second, 10, None, None))),
            Some(second)
        );
        assert_eq!(
            authority_machine(
                Some(binding(first, 10, None, None)),
                Some(binding(second, 11, None, None))
            ),
            Some(second)
        );
        assert_eq!(
            authority_machine(
                Some(binding(first, 10, None, None)),
                Some(binding(second, 10, None, None))
            ),
            Some(first)
        );
        assert_eq!(
            authority_machine(Some(binding(zero, 99, None, None)), None),
            None
        );
        // Strict readers: an unconfirmed route never counts.
        assert_eq!(authorized_machine(Some(second), true, None), Some(second));
        assert_eq!(
            authorized_machine(Some(second), false, Some(first)),
            Some(first)
        );
        assert_eq!(authorized_machine(Some(second), false, None), None);
        assert_eq!(authorized_machine(None, false, Some(first)), Some(first));
        let announced = Some(binding(first, 10, None, None));
        assert!(confirms(first, announced, None, || false));
        assert!(confirms(
            second,
            None,
            Some(binding(second, 1, None, None)),
            || false
        ));
        assert!(
            confirms(second, announced, None, || true),
            "usable evidence"
        );
        assert!(!confirms(second, announced, None, || false));
        assert!(!confirms(
            zero,
            Some(binding(zero, 1, None, None)),
            None,
            || true
        ));
    }

    #[test]
    fn provenance_follows_the_committed_digest() {
        let agent = crate::identity::AgentKeypair::generate().expect("agent key");
        let owner = crate::identity::UserKeypair::generate().expect("owner key");
        let other = crate::identity::UserKeypair::generate().expect("other key");
        let genuine =
            crate::identity::AgentCertificate::issue(&owner, &agent).expect("genuine certificate");
        let foreign = crate::identity::AgentCertificate::issue_for_public_key(
            &other,
            agent.public_key().as_bytes(),
            None,
        )
        .expect("foreign certificate");
        let committed = Some(binding(
            MachineId([1; 32]),
            1,
            Some(certificate_digest(&genuine)),
            None,
        ));
        assert!(has_authenticated_provenance(&genuine, committed));
        assert!(!has_authenticated_provenance(&foreign, committed));
        assert!(!has_authenticated_provenance(&genuine, None));
        assert!(same_owner(&genuine, &genuine));
        assert!(!same_owner(&genuine, &foreign));
    }
}
