#![cfg(test)]

//! #1107: an announcement that names the stored certificate's digest but
//! carries no certificate bytes keeps the stored certificate.
//!
//! A V3 identity announcement carries only the digest of the owner
//! certificate; the bytes come by a separate fetch. Before this rule, the
//! first post-restart gossip announcement of an owner device replaced its
//! stored record with a certificate-less one, and owner trust failed until
//! the fetch completed. The rule: an ingest without certificate bytes keeps
//! the stored certificate if and only if the announcement's signed
//! `cert_digest` equals the digest of that certificate, for the same agent
//! and the same machine.

use super::tests::{setup, Peer};
use super::*;
use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};

/// Same constant as the store tests: far enough ahead of the wall clock that
/// a certificate issued now is never "issued in the future".
const NOW: u64 = 2_000_000_000_000;
const EARLIER: u64 = NOW - 5_000;

fn owner() -> UserKeypair {
    UserKeypair::from_seed(&[0x5a; 32]).unwrap()
}

/// A record for `agent` on `machine` whose announcement names `named`'s
/// digest; the certificate bytes are attached only when `with_bytes`.
fn announce(
    agent: &AgentKeypair,
    machine: &MachineKeypair,
    named: Option<&AgentCertificate>,
    with_bytes: bool,
    at: u64,
) -> EvidenceRecordV1 {
    let mut record = record_with_certificate_for_test(agent, machine, named, at, at);
    if !with_bytes {
        record.certificate = None;
    }
    record
}

fn certificate_of(
    store: &PeerEvidenceStore,
    agent: AgentId,
    machine: MachineId,
) -> Option<Vec<u8>> {
    store
        .usable(agent, machine, NOW)?
        .certificate
        .as_ref()
        .map(|c| c.to_storage_bytes().unwrap())
}

fn stored_with(
    peer: &Peer,
    cert: &AgentCertificate,
) -> (
    tempfile::TempDir,
    Arc<super::tests::Policy>,
    PeerEvidenceStore,
) {
    let (dir, policy, store) = setup(peer);
    store
        .ingest(
            announce(&peer.agent, &peer.machine, Some(cert), true, EARLIER),
            IngestSource::Hello,
            NOW,
        )
        .unwrap();
    assert!(
        certificate_of(&store, peer.a(), peer.m()).is_some(),
        "setup: C stored"
    );
    (dir, policy, store)
}

/// The cause of the cold-restart window: a newer gossip announcement that
/// names C's digest without C's bytes must keep C.
#[test]
fn same_digest_announcement_without_bytes_keeps_the_stored_certificate() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    store
        .ingest(
            announce(&peer.agent, &peer.machine, Some(&cert), false, NOW),
            IngestSource::Gossip,
            NOW,
        )
        .unwrap();
    assert_eq!(
        certificate_of(&store, peer.a(), peer.m()),
        Some(cert.to_storage_bytes().unwrap()),
        "the stored certificate must survive a same-digest announcement"
    );
    let live = store.live(peer.a(), NOW).expect("live record");
    assert_eq!(
        announce_v3::deserialize_v3(&live.announcement)
            .unwrap()
            .announced_at,
        NOW / 1000,
        "the newer announcement is live"
    );
    assert_eq!(
        live.certificate,
        Some(cert.to_storage_bytes().unwrap()),
        "the live record carries the stored bytes"
    );
}

/// An anonymous announcement (no user identity: consent withdrawn) drops C.
#[test]
fn anonymous_announcement_drops_the_stored_certificate() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    store
        .ingest(
            announce(&peer.agent, &peer.machine, None, false, NOW),
            IngestSource::Gossip,
            NOW,
        )
        .unwrap();
    assert_eq!(certificate_of(&store, peer.a(), peer.m()), None);
}

/// An announcement naming a different certificate drops C; the fetch of the
/// new certificate brings it.
#[test]
fn different_digest_announcement_drops_the_stored_certificate() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let renewed =
        AgentCertificate::issue_with_expiry(&owner(), &peer.agent, Some(NOW / 1000 + 86_400))
            .unwrap();
    assert_ne!(
        cert.to_storage_bytes().unwrap(),
        renewed.to_storage_bytes().unwrap()
    );
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    store
        .ingest(
            announce(&peer.agent, &peer.machine, Some(&renewed), false, NOW),
            IngestSource::Gossip,
            NOW,
        )
        .unwrap();
    assert_eq!(certificate_of(&store, peer.a(), peer.m()), None);
}

/// The same agent announced from another machine, naming C's digest: C is
/// not carried to the new machine's record. The carry is for one exact
/// (agent, machine) pair.
#[test]
fn same_digest_from_another_machine_does_not_carry_the_certificate() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    let other = MachineKeypair::generate().unwrap();
    store
        .ingest(
            announce(&peer.agent, &other, Some(&cert), false, NOW),
            IngestSource::Gossip,
            NOW,
        )
        .unwrap();
    assert_eq!(certificate_of(&store, peer.a(), other.machine_id()), None);
}

/// A foreign agent on a foreign machine names the digest of C (another
/// agent's certificate). There is no stored certificate for that pair, so
/// none is attached, and the owner's record keeps C.
#[test]
fn foreign_announcement_naming_the_digest_attaches_nothing() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, policy, store) = stored_with(&peer, &cert);
    let foreign = Peer::new();
    policy.peers.lock().unwrap().insert(foreign.a(), GROUP);
    // The foreign announcement names C's digest; its own advert is signed by
    // its own agent key, so the record verifies as the foreign agent's.
    let _ = store.ingest(
        announce(&foreign.agent, &foreign.machine, Some(&cert), false, NOW),
        IngestSource::Gossip,
        NOW,
    );
    assert_eq!(certificate_of(&store, foreign.a(), foreign.m()), None);
    assert_eq!(
        certificate_of(&store, peer.a(), peer.m()),
        Some(cert.to_storage_bytes().unwrap()),
        "the owner's record is untouched"
    );
}

fn anonymous_at(peer: &Peer, at: u64) -> EvidenceRecordV1 {
    announce(&peer.agent, &peer.machine, None, false, at)
}

/// A carry decided before an anonymous announcement (consent withdrawn) is
/// stored must not re-store the certificate afterwards. The carried record
/// ties the anonymous one on announcement second and advert time; the store
/// decides the carry again under its mutation lock and refuses it.
#[test]
fn carry_decided_before_an_anonymous_ingest_is_refused_at_store_time() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    let mut carried = announce(&peer.agent, &peer.machine, Some(&cert), false, NOW);
    assert!(
        store.carry_certificate(&mut carried, NOW),
        "carry decided while C is stored"
    );
    store
        .ingest(anonymous_at(&peer, NOW), IngestSource::Gossip, NOW)
        .unwrap();
    assert_eq!(
        certificate_of(&store, peer.a(), peer.m()),
        None,
        "setup: C dropped"
    );
    let view = Arc::new(carried.verify(NOW, W_MS).unwrap());
    let result = store.ingest_verified_after_carry(carried, view, IngestSource::Gossip, NOW, true);
    assert!(result.is_err(), "the stale carry must be refused");
    assert_eq!(certificate_of(&store, peer.a(), peer.m()), None);
    assert_eq!(store.live(peer.a(), NOW).and_then(|r| r.certificate), None);
}

/// An older digest-bearing announcement replayed after an anonymous one
/// gets nothing: the stored record is anonymous.
#[test]
fn replayed_older_announcement_after_an_anonymous_one_carries_nothing() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    store
        .ingest(anonymous_at(&peer, NOW - 1_000), IngestSource::Gossip, NOW)
        .unwrap();
    let mut replay = announce(&peer.agent, &peer.machine, Some(&cert), false, NOW - 3_000);
    assert!(!store.carry_certificate(&mut replay, NOW));
    let _ = store.ingest(replay, IngestSource::Gossip, NOW);
    assert_eq!(certificate_of(&store, peer.a(), peer.m()), None);
    assert_eq!(store.live(peer.a(), NOW).and_then(|r| r.certificate), None);
}

/// An expired stored certificate is not carried.
#[test]
fn expired_stored_certificate_is_not_carried() {
    let peer = Peer::new();
    let then = NOW - 1_000_000;
    let skew = crate::identity::EXPIRY_CLOCK_SKEW_SECS;
    let cert =
        AgentCertificate::issue_with_expiry(&owner(), &peer.agent, Some(NOW / 1000 - skew - 100))
            .unwrap();
    let (_dir, _policy, store) = setup(&peer);
    store
        .ingest(
            announce(&peer.agent, &peer.machine, Some(&cert), true, then),
            IngestSource::Hello,
            then,
        )
        .unwrap();
    let mut fresh = announce(&peer.agent, &peer.machine, Some(&cert), false, NOW);
    assert!(!store.carry_certificate(&mut fresh, NOW));
    assert_eq!(fresh.certificate, None);
}

/// A record suspended by a move in progress is not a source for a carry.
#[test]
fn suspended_record_is_not_carried() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    store.state.lock().unwrap().suspended.insert(peer.a());
    let mut fresh = announce(&peer.agent, &peer.machine, Some(&cert), false, NOW);
    assert!(!store.carry_certificate(&mut fresh, NOW));
    assert_eq!(fresh.certificate, None);
}

/// P1 (Greptile on #1882): gossip decides "nothing to carry" while the store
/// is empty; a Hello then stores the same announcement and advert WITH the
/// certificate; the gossip copy without bytes reaches the store after. The
/// store must not replace the Hello's certificate with nothing.
#[test]
fn hello_stored_between_gossip_carry_decision_and_store_keeps_its_certificate() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = setup(&peer);
    let with_bytes = announce(&peer.agent, &peer.machine, Some(&cert), true, NOW);
    let mut gossip = with_bytes.clone();
    gossip.certificate = None;
    assert!(
        !store.carry_certificate(&mut gossip, NOW),
        "nothing stored yet"
    );
    let view = Arc::new(gossip.verify(NOW, W_MS).unwrap());
    store.ingest(with_bytes, IngestSource::Hello, NOW).unwrap();
    let _ = store.ingest_verified_after_carry(gossip, view, IngestSource::Gossip, NOW, false);
    assert_eq!(
        certificate_of(&store, peer.a(), peer.m()),
        Some(cert.to_storage_bytes().unwrap()),
        "the Hello's certificate must survive the late gossip copy"
    );
    assert_eq!(
        store.live(peer.a(), NOW).and_then(|r| r.certificate),
        Some(cert.to_storage_bytes().unwrap())
    );
}

/// The same window for a different digest: C is stored; gossip names C2
/// without bytes (nothing to carry); a Hello stores C2 with bytes; the late
/// gossip copy must keep C2.
#[test]
fn hello_with_a_new_certificate_stored_in_the_window_keeps_it() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let renewed =
        AgentCertificate::issue_with_expiry(&owner(), &peer.agent, Some(NOW / 1000 + 86_400))
            .unwrap();
    let (_dir, _policy, store) = stored_with(&peer, &cert);
    let with_bytes = announce(&peer.agent, &peer.machine, Some(&renewed), true, NOW);
    let mut gossip = with_bytes.clone();
    gossip.certificate = None;
    assert!(
        !store.carry_certificate(&mut gossip, NOW),
        "C2 is not stored yet"
    );
    let view = Arc::new(gossip.verify(NOW, W_MS).unwrap());
    store.ingest(with_bytes, IngestSource::Hello, NOW).unwrap();
    let _ = store.ingest_verified_after_carry(gossip, view, IngestSource::Gossip, NOW, false);
    assert_eq!(
        certificate_of(&store, peer.a(), peer.m()),
        Some(renewed.to_storage_bytes().unwrap())
    );
}

/// Consent withdrawal still wins in the window: an anonymous gossip record
/// decided before a Hello with C was stored, and stored after it, leaves
/// no certificate. A newer certificate-less record is never overridden.
#[test]
fn newer_anonymous_record_stored_after_a_hello_with_certificate_still_wins() {
    let peer = Peer::new();
    let cert = AgentCertificate::issue(&owner(), &peer.agent).unwrap();
    let (_dir, _policy, store) = setup(&peer);
    let mut anonymous = anonymous_at(&peer, NOW);
    assert!(!store.carry_certificate(&mut anonymous, NOW));
    let view = Arc::new(anonymous.verify(NOW, W_MS).unwrap());
    store
        .ingest(
            announce(&peer.agent, &peer.machine, Some(&cert), true, EARLIER),
            IngestSource::Hello,
            NOW,
        )
        .unwrap();
    store
        .ingest_verified_after_carry(anonymous, view, IngestSource::Gossip, NOW, false)
        .unwrap();
    assert_eq!(certificate_of(&store, peer.a(), peer.m()), None);
    assert_eq!(store.live(peer.a(), NOW).and_then(|r| r.certificate), None);
}
