#![cfg(test)]

//! #1107: the consent to disclose the user identity is durable.
//!
//! A consented announce (`announce_identity(true, true)`) writes
//! `user-consent.bin` in the identity directory. The next start loads it
//! before the first announce, so the startup announce and the heartbeats
//! carry the user ID and the agent certificate with no manual step. The
//! record applies only to the identity it was given for, and a withdrawal
//! removes it.
//!
//! Each test uses one loopback agent with no peers. "Restart" is: shut the
//! agent down, then build a new agent on the same directory.

use super::*;
use std::path::Path;
use std::time::Duration;

const CONSENT_FILE: &str = "user-consent.bin";

async fn agent_on(dir: &Path) -> Agent {
    let config = network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        network_id: Some(format!("consent-persist-{}", rand::random::<u32>())),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..network::NetworkConfig::default()
    };
    Agent::builder()
        .with_identity_dir(dir)
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_agent_cert_path(dir.join("agent.cert"))
        .with_user_key_path(dir.join("user.key"))
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .with_network_config(config)
        .build()
        .await
        .expect("a loopback agent builds")
}

async fn write_user_key(dir: &Path) -> identity::UserId {
    let key = identity::UserKeypair::generate().expect("user key");
    let user_id = key.user_id();
    storage::save_user_keypair_to(&key, dir.join("user.key"))
        .await
        .expect("user key saved");
    user_id
}

/// Build an agent on `dir`, make the consented announce and shut down.
async fn consent_then_stop(dir: &Path) {
    let agent = agent_on(dir).await;
    agent
        .announce_identity(true, true)
        .await
        .expect("the consented disclosure publishes");
    assert!(agent.user_identity_consented());
    agent.shutdown().await;
}

async fn next_second_boundary() {
    let start = Agent::unix_timestamp_secs();
    while Agent::unix_timestamp_secs() == start {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The next X0A3 identity announce frame published on the announce topic.
/// The v3 `payload_version` is `announced_at` for an identity announce and
/// `0` for an anonymous one.
async fn next_v3_announcement(
    wire: &mut gossip::pubsub::Subscription,
) -> announce_v3::IdentityAnnouncementV3 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout_at(deadline, wire.recv())
            .await
            .expect("an identity announcement was published")
            .expect("the wire subscription stays open");
        if !announce_v3::is_v3_payload(&msg.payload) {
            continue;
        }
        return announce_v3::deserialize_v3(&msg.payload)
            .expect("the identity announce wire frame decodes");
    }
}

/// What a restarted agent does with no manual step: the startup announce
/// of `join_network`, then one heartbeat-style beat in a later second.
struct RestartAnnounces {
    consented: bool,
    startup_is_identity: bool,
    beat_is_identity: bool,
    discovered_user: Option<identity::UserId>,
}

async fn restart_and_observe(dir: &Path) -> RestartAnnounces {
    let agent = agent_on(dir).await;
    let consented = agent.user_identity_consented();
    let mut wire = agent
        .gossip_runtime
        .as_ref()
        .expect("a networked agent has a gossip runtime")
        .pubsub()
        .subscribe(IDENTITY_ANNOUNCE_TOPIC.to_string())
        .await;
    agent.join_network().await.expect("join");
    let startup = next_v3_announcement(&mut wire).await;
    let discovered_user = agent
        .discovered_agent(agent.agent_id())
        .await
        .expect("discovery lookup")
        .and_then(|entry| entry.user_id);
    // `reannounce_identity` runs the same `HeartbeatContext::announce` as
    // the 3 s delayed beat and the 600 s heartbeat. A later second, so the
    // beat is strictly fresher than the startup announce.
    next_second_boundary().await;
    agent
        .reannounce_identity()
        .await
        .expect("the beat publishes");
    // The 3 s delayed beat of `join_network` can also arrive here; it runs
    // the same code with the same flag, so either frame gives the answer.
    let beat = next_v3_announcement(&mut wire).await;
    agent.shutdown().await;
    RestartAnnounces {
        consented,
        startup_is_identity: startup.payload_version != 0,
        beat_is_identity: beat.payload_version != 0,
        discovered_user,
    }
}

fn assert_anonymous(seen: &RestartAnnounces, why: &str) {
    assert!(!seen.consented, "{why}: consent must not be loaded");
    assert!(
        !seen.startup_is_identity,
        "{why}: the startup announce must be anonymous"
    );
    assert!(
        !seen.beat_is_identity,
        "{why}: the heartbeat must be anonymous"
    );
    assert_eq!(
        seen.discovered_user, None,
        "{why}: no user ID in the own discovery record"
    );
}

/// (a) Consent, stop, start on the same directory: the startup announce
/// and the first heartbeat are identity announces. RED on main, where the
/// flag is memory-only and the startup announce is always anonymous.
#[tokio::test]
async fn consent_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let user_id = write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;

    let record_path = dir.path().join(CONSENT_FILE);
    let record = storage::load_user_disclosure_consent(&record_path)
        .await
        .expect("the consent record decodes")
        .expect("a consented announce writes the consent record");
    assert_eq!(record.user_id, user_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&record_path)
            .expect("record metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the consent record is private");
    }

    let seen = restart_and_observe(dir.path()).await;
    assert!(
        seen.startup_is_identity,
        "the startup announce carries the identity, not the anonymous digest"
    );
    assert!(seen.consented, "the recorded consent is loaded at build");
    assert!(
        seen.beat_is_identity,
        "the first heartbeat after a restart is an identity beat"
    );
    assert_eq!(
        seen.discovered_user,
        Some(user_id),
        "the startup announce disclosed the user ID"
    );
}

/// (b) No consent recorded: still anonymous after a restart, even with a
/// user key and a certificate on disk.
#[tokio::test]
async fn no_consent_stays_anonymous_after_a_restart() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    let agent = agent_on(dir.path()).await;
    agent
        .announce_identity(false, false)
        .await
        .expect("the anonymous announce publishes");
    agent.shutdown().await;
    assert!(
        !dir.path().join(CONSENT_FILE).exists(),
        "an anonymous announce writes no consent record"
    );

    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "no consent was given");
}

/// (c) Consent recorded for user A; the directory now holds user B's key.
/// The record does not apply, and the agent starts.
#[tokio::test]
async fn consent_for_another_user_does_not_apply() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let user_a = write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;

    let user_b = write_user_key(dir.path()).await;
    assert_ne!(user_a, user_b);
    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "the consent was user A's, the key is user B's");
}

/// (c) Consent recorded for user A; the user key and the certificate are
/// gone. The record does not apply, and the agent starts.
#[tokio::test]
async fn consent_without_user_key_and_certificate_does_not_apply() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;

    std::fs::remove_file(dir.path().join("user.key")).expect("remove user key");
    std::fs::remove_file(dir.path().join("agent.cert")).expect("remove certificate");
    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "no user key and no certificate on disk");
}

/// (c) The record names the agent too: the same user with a new agent key
/// has not consented for that agent.
#[tokio::test]
async fn consent_for_another_agent_does_not_apply() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;

    std::fs::remove_file(dir.path().join("agent.key")).expect("remove agent key");
    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "the consent was given for another agent key");
}

/// (d) A corrupt consent record: the agent starts and stays anonymous.
#[tokio::test]
async fn corrupt_consent_record_means_not_consented() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;
    let record_path = dir.path().join(CONSENT_FILE);

    // A valid record with one trailing byte, then plain garbage.
    let mut trailing = std::fs::read(&record_path).expect("read record");
    trailing.push(0);
    for bytes in [trailing, b"not a consent record".to_vec(), Vec::new()] {
        std::fs::write(&record_path, &bytes).expect("corrupt the record");
        let seen = restart_and_observe(dir.path()).await;
        assert_anonymous(&seen, "the consent record is corrupt");
    }
}

/// (e) Withdrawal clears the durable record and the flag, across a
/// restart. A new consented announce records consent again.
#[tokio::test]
async fn withdrawal_clears_the_record_across_a_restart() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let user_id = write_user_key(dir.path()).await;
    consent_then_stop(dir.path()).await;
    let record_path = dir.path().join(CONSENT_FILE);
    assert!(record_path.exists());

    // The restarted agent loaded the consent; withdraw it there.
    let agent = agent_on(dir.path()).await;
    assert!(agent.user_identity_consented());
    agent
        .withdraw_user_identity_consent()
        .await
        .expect("withdrawal");
    assert!(!agent.user_identity_consented());
    assert!(!record_path.exists(), "withdrawal removes the record");
    // A second withdrawal with no record is not an error.
    agent
        .withdraw_user_identity_consent()
        .await
        .expect("withdrawal is idempotent");
    agent.shutdown().await;

    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "the consent was withdrawn");

    // Consent again: recorded again, and applied on the next start.
    consent_then_stop(dir.path()).await;
    let seen = restart_and_observe(dir.path()).await;
    assert!(seen.consented && seen.startup_is_identity && seen.beat_is_identity);
    assert_eq!(seen.discovered_user, Some(user_id));
}

/// A withdrawal that completes while a consented announce is in flight
/// wins: the announce, which published before the withdrawal, must not
/// write the record again or turn the flag back on. The gate stops the
/// announce between its publish and its consent record, so the order is
/// fixed without a sleep.
#[tokio::test]
async fn withdrawal_wins_over_an_announce_in_flight() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    let record_path = dir.path().join(CONSENT_FILE);
    let agent = std::sync::Arc::new(agent_on(dir.path()).await);
    agent
        .announce_identity(true, true)
        .await
        .expect("the consented disclosure publishes");
    assert!(record_path.exists());

    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    *agent.consented_publish_test_gate.lock().expect("gate lock") = Some((reached_tx, resume_rx));
    // The cert-renewal path: it sees the consent and announces with it.
    let in_flight = tokio::spawn({
        let agent = std::sync::Arc::clone(&agent);
        async move { agent.reannounce_identity_if_consented().await }
    });
    reached_rx.await.expect("the announce published");

    agent
        .withdraw_user_identity_consent()
        .await
        .expect("withdrawal");
    assert!(!record_path.exists(), "the withdrawal removed the record");

    resume_tx.send(()).expect("the announce is waiting");
    in_flight
        .await
        .expect("announce task")
        .expect("the announce itself succeeded");
    assert!(
        !agent.user_identity_consented(),
        "the older announce must not turn the consent back on"
    );
    assert!(
        !record_path.exists(),
        "the older announce must not write the record again"
    );
    agent.shutdown().await;

    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(
        &seen,
        "the withdrawal completed after the announce published",
    );
}

/// A directory with one file in it at the record path: the record can be
/// neither written, removed nor emptied.
fn block_record_path(record_path: &Path) {
    std::fs::create_dir(record_path).expect("directory at the record path");
    std::fs::write(record_path.join("blocker"), b"x").expect("blocker file");
}

/// The record write fails once. The consent still holds for this run, and
/// the next consented announce writes the record.
#[tokio::test]
async fn failed_record_write_is_retried_by_the_next_consented_announce() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let user_id = write_user_key(dir.path()).await;
    let record_path = dir.path().join(CONSENT_FILE);
    block_record_path(&record_path);

    let agent = agent_on(dir.path()).await;
    assert!(!agent.user_identity_consented());
    agent
        .announce_identity(true, true)
        .await
        .expect("the announce succeeds when the record write fails");
    assert!(agent.user_identity_consented());
    assert!(record_path.is_dir(), "the record was not written");

    std::fs::remove_dir_all(&record_path).expect("clear the record path");
    agent
        .announce_identity(true, true)
        .await
        .expect("the second consented announce publishes");
    let record = storage::load_user_disclosure_consent(&record_path)
        .await
        .expect("the consent record decodes")
        .expect("the second consented announce writes the record");
    assert_eq!(record.user_id, user_id);
    agent.shutdown().await;

    let seen = restart_and_observe(dir.path()).await;
    assert!(seen.consented && seen.startup_is_identity);
}

/// The record can be neither removed nor emptied: the withdrawal reports
/// the error, and this run is still anonymous.
#[tokio::test]
async fn withdrawal_reports_a_record_it_cannot_remove() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    block_record_path(&dir.path().join(CONSENT_FILE));

    let agent = agent_on(dir.path()).await;
    agent
        .announce_identity(true, true)
        .await
        .expect("the consented disclosure publishes");
    assert!(agent.user_identity_consented());
    assert!(
        agent.withdraw_user_identity_consent().await.is_err(),
        "the failed removal is an error"
    );
    assert!(!agent.user_identity_consented());
    agent.shutdown().await;
}

/// A read-only identity directory: the record cannot be removed, so the
/// withdrawal empties it. The next start does not bring the consent back.
#[cfg(unix)]
#[tokio::test]
async fn withdrawal_empties_a_record_it_cannot_remove() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tmpdir");
    write_user_key(dir.path()).await;
    let record_path = dir.path().join(CONSENT_FILE);
    let agent = agent_on(dir.path()).await;
    agent
        .announce_identity(true, true)
        .await
        .expect("the consented disclosure publishes");
    assert!(record_path.exists());

    let set_mode = |mode: u32| {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
            .expect("set the directory mode");
    };
    set_mode(0o500);
    let withdrawn = agent.withdraw_user_identity_consent().await;
    set_mode(0o700);
    withdrawn.expect("the withdrawal empties the record");
    assert!(!agent.user_identity_consented());
    // A privileged test user can still remove the file; both results mean
    // "not consented".
    let left = std::fs::metadata(&record_path).map(|meta| meta.len()).ok();
    assert!(
        matches!(left, None | Some(0)),
        "record bytes left: {left:?}"
    );
    agent.shutdown().await;

    let seen = restart_and_observe(dir.path()).await;
    assert_anonymous(&seen, "the record was emptied by the withdrawal");
}

/// The record format: `X0UC` + bincode(version, user, agent, time), 77
/// bytes. Wrong magic, an unknown version, short and long inputs fail.
#[test]
fn consent_record_format_is_exact() {
    let record = storage::UserDisclosureConsent {
        user_id: identity::UserId([7; 32]),
        agent_id: identity::AgentId([9; 32]),
        consented_at: 1_700_000_000,
    };
    let bytes = storage::serialize_user_disclosure_consent(&record).expect("encode");
    assert_eq!(bytes.len(), 77);
    assert_eq!(&bytes[..4], b"X0UC");
    assert_eq!(bytes[4], 1, "format version");
    assert_eq!(
        storage::deserialize_user_disclosure_consent(&bytes).expect("decode"),
        record
    );

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] = b'Y';
    let mut wrong_version = bytes.clone();
    wrong_version[4] = 2;
    let mut long = bytes.clone();
    long.push(0);
    for bad in [wrong_magic, wrong_version, long, bytes[..76].to_vec()] {
        assert!(storage::deserialize_user_disclosure_consent(&bad).is_err());
    }
}
