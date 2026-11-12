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
