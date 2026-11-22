#![cfg(test)]
//! #2158: a renewed or live-seen certificate keeps a rider's roster mode
//! and label; only a later owner issuance changes them.
//!
//! Inert: each owner agent is built with no network configuration (no
//! sockets, gossip runtime or daemon) on a temporary identity directory.
//! Live certificates are put straight into the discovery caches.
use super::*;

struct Owner {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    user_key: (Vec<u8>, Vec<u8>),
}

impl Owner {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("isolated identity directory");
        let path = dir.path().to_path_buf();
        let user_key = identity::UserKeypair::generate()
            .expect("owner key")
            .to_bytes();
        Self {
            _dir: dir,
            path,
            user_key,
        }
    }

    fn user_keypair(&self) -> identity::UserKeypair {
        identity::UserKeypair::from_bytes(&self.user_key.0, &self.user_key.1).expect("owner key")
    }

    /// An offline owner agent on this directory (a restart builds it again).
    async fn agent(&self) -> Agent {
        Agent::builder()
            .with_machine_key(self.path.join("machine.key"))
            .with_agent_key_path(self.path.join("agent.key"))
            .with_agent_cert_path(self.path.join("agent.cert"))
            .with_contact_store_path(self.path.join("contacts.json"))
            .with_identity_dir(&self.path)
            .with_user_key(self.user_keypair())
            .build()
            .await
            .expect("offline owner")
    }
}

/// The line `POST /owner/agents/issue` writes, dated `issued_at`.
fn issuance(
    owner: &identity::UserKeypair,
    cert: &identity::AgentCertificate,
    mode: profile::CertMode,
    label: &str,
    issued_at: u64,
) -> profile::IssuedCertRecord {
    let mut record = profile::IssuedCertRecord::from_cert_with_mode(
        &owner.user_id(),
        cert,
        mode,
        Some(label.to_string()),
    )
    .expect("issuance record");
    record.issued_at = issued_at;
    record
}

async fn journal(agent: &Agent, record: &profile::IssuedCertRecord) {
    profile::IssuedCertRecord::append(agent.cert_journal_path().expect("journal"), record)
        .await
        .expect("journal append");
}

async fn entry(agent: &Agent, subject: &identity::AgentKeypair) -> OwnerIssuedCert {
    let id = hex::encode(subject.agent_id().as_bytes());
    agent
        .owner_issued_certificates()
        .await
        .into_iter()
        .find(|e| e.agent_id == id)
        .expect("subject on the roster")
}

fn assert_rider(entry: &OwnerIssuedCert, context: &str) {
    assert_eq!(entry.mode, profile::CertMode::Rider, "{context}: {entry:?}");
    assert_eq!(
        entry.label.as_deref(),
        Some("pi rider"),
        "{context}: {entry:?}"
    );
}

/// A live-announced renewal (identity discovery) wins the roster entry but
/// keeps the rider mode and label, on the call that journals it, on the
/// next call, and after a restart.
#[tokio::test]
async fn live_announced_renewal_keeps_rider_mode_across_calls_and_restart() {
    let owner = Owner::new();
    let user = owner.user_keypair();
    let subject = identity::AgentKeypair::generate().expect("rider key");
    let first = identity::AgentCertificate::issue(&user, &subject).expect("rider certificate");
    let renewed = identity::AgentCertificate::issue_with_expiry(
        &user,
        &subject,
        Some(first.issued_at() + 86_400),
    )
    .expect("renewed certificate");
    let agent = owner.agent().await;
    // The rider line is older than the renewal, so the renewal wins.
    journal(
        &agent,
        &issuance(
            &user,
            &first,
            profile::CertMode::Rider,
            "pi rider",
            renewed.issued_at() - 10,
        ),
    )
    .await;
    let mut seen = discovered_agent_fixture(0x31, renewed.issued_at(), &[], Some(user.user_id()));
    seen.agent_id = subject.agent_id();
    seen.agent_certificate = Some(renewed.clone());
    agent
        .identity_discovery_cache
        .write()
        .await
        .insert(subject.agent_id(), seen);

    let live = entry(&agent, &subject).await;
    assert_eq!(live.digest, profile::cert_storage_digest(&renewed));
    assert!(!live.from_journal, "the renewal is newer than the journal");
    assert_rider(&live, "live renewal");
    // The first call journaled the renewal as a plain sighting line.
    let journaled = entry(&agent, &subject).await;
    assert_eq!(journaled.digest, profile::cert_storage_digest(&renewed));
    assert_rider(&journaled, "journaled renewal");
    // The daemon's own certificate stays ACP with no label.
    let own = hex::encode(agent.agent_id().as_bytes());
    let own_entry = agent
        .owner_issued_certificates()
        .await
        .into_iter()
        .find(|e| e.agent_id == own)
        .expect("own agent on the roster");
    assert_eq!(own_entry.mode, profile::CertMode::Acp);
    assert_eq!(own_entry.label, None);
    agent.shutdown().await;
    drop(agent);

    // Restart: no live caches, the journal alone keeps the rider.
    let restarted = owner.agent().await;
    let after = entry(&restarted, &subject).await;
    assert!(after.from_journal);
    assert_eq!(after.digest, profile::cert_storage_digest(&renewed));
    assert_rider(&after, "after restart");
    restarted.shutdown().await;
}

/// A renewal carried by the owner's user announcement (the owner's own
/// roster of certificates) keeps the rider mode too.
#[tokio::test]
async fn user_announcement_renewal_keeps_rider_mode() {
    let owner = Owner::new();
    let user = owner.user_keypair();
    let subject = identity::AgentKeypair::generate().expect("rider key");
    let first = identity::AgentCertificate::issue(&user, &subject).expect("rider certificate");
    let renewed = identity::AgentCertificate::issue_with_expiry(
        &user,
        &subject,
        Some(first.issued_at() + 86_400),
    )
    .expect("renewed certificate");
    let agent = owner.agent().await;
    journal(
        &agent,
        &issuance(
            &user,
            &first,
            profile::CertMode::Rider,
            "pi rider",
            renewed.issued_at() - 10,
        ),
    )
    .await;
    agent.user_discovery_cache.write().await.insert(
        user.user_id(),
        DiscoveredUser {
            user_id: user.user_id(),
            user_public_key: user.public_key().as_bytes().to_vec(),
            agent_certificates: vec![renewed.clone()],
            agent_ids: vec![subject.agent_id()],
            announced_at: renewed.issued_at(),
            last_seen: renewed.issued_at(),
        },
    );
    for call in ["first call", "second call"] {
        let renewed_entry = entry(&agent, &subject).await;
        assert_eq!(renewed_entry.digest, profile::cert_storage_digest(&renewed));
        assert_rider(&renewed_entry, call);
    }
    agent.shutdown().await;
}

/// The roster tie rule still holds: a live certificate issued in the same
/// second as the journal line does not displace it, and the rider mode
/// survives the sighting line that the tie journals.
#[tokio::test]
async fn equal_second_sighting_keeps_journal_digest_and_rider_mode() {
    let owner = Owner::new();
    let user = owner.user_keypair();
    let subject = identity::AgentKeypair::generate().expect("rider key");
    let first = identity::AgentCertificate::issue(&user, &subject).expect("rider certificate");
    let same_second = identity::AgentCertificate::issue_with_expiry(
        &user,
        &subject,
        Some(first.issued_at() + 86_400),
    )
    .expect("same-second certificate");
    let agent = owner.agent().await;
    journal(
        &agent,
        &issuance(
            &user,
            &first,
            profile::CertMode::Rider,
            "pi rider",
            same_second.issued_at(),
        ),
    )
    .await;
    let mut seen =
        discovered_agent_fixture(0x32, same_second.issued_at(), &[], Some(user.user_id()));
    seen.agent_id = subject.agent_id();
    seen.agent_certificate = Some(same_second.clone());
    agent
        .identity_discovery_cache
        .write()
        .await
        .insert(subject.agent_id(), seen);

    let tie = entry(&agent, &subject).await;
    assert!(
        tie.from_journal,
        "journal is authoritative on ties: {tie:?}"
    );
    assert_eq!(tie.digest, profile::cert_storage_digest(&first));
    assert_rider(&tie, "equal-second tie");
    let next = entry(&agent, &subject).await;
    assert!(next.from_journal);
    assert_rider(&next, "after the tie journals a sighting line");
    agent.shutdown().await;
}

/// A later owner issuance in the other mode is an intended change and
/// applies, in both directions, and a renewal after it keeps the new mode.
#[tokio::test]
async fn later_owner_issuance_changes_the_mode() {
    let owner = Owner::new();
    let user = owner.user_keypair();
    let agent = owner.agent().await;
    let now = Agent::unix_timestamp_secs();

    // Rider re-issued as ACP.
    let former_rider = identity::AgentKeypair::generate().expect("former rider");
    let rider_cert =
        identity::AgentCertificate::issue(&user, &former_rider).expect("rider certificate");
    let acp_cert =
        identity::AgentCertificate::issue_with_expiry(&user, &former_rider, Some(now + 86_400))
            .expect("ACP certificate");
    journal(
        &agent,
        &issuance(
            &user,
            &rider_cert,
            profile::CertMode::Rider,
            "pi rider",
            now - 20,
        ),
    )
    .await;
    journal(
        &agent,
        &issuance(
            &user,
            &acp_cert,
            profile::CertMode::Acp,
            "harness",
            now - 10,
        ),
    )
    .await;
    let renewed =
        identity::AgentCertificate::issue_with_expiry(&user, &former_rider, Some(now + 2 * 86_400))
            .expect("renewal after the ACP issuance");
    let mut seen = discovered_agent_fixture(0x33, now, &[], Some(user.user_id()));
    seen.agent_id = former_rider.agent_id();
    seen.agent_certificate = Some(renewed.clone());
    agent
        .identity_discovery_cache
        .write()
        .await
        .insert(former_rider.agent_id(), seen);
    for call in ["first call", "second call"] {
        let reissued = entry(&agent, &former_rider).await;
        assert_eq!(reissued.digest, profile::cert_storage_digest(&renewed));
        assert_eq!(
            reissued.mode,
            profile::CertMode::Acp,
            "{call}: {reissued:?}"
        );
        assert_eq!(reissued.label.as_deref(), Some("harness"), "{call}");
    }

    // ACP re-issued as a rider.
    let former_acp = identity::AgentKeypair::generate().expect("former ACP agent");
    let acp_first = identity::AgentCertificate::issue(&user, &former_acp).expect("ACP certificate");
    let rider_later =
        identity::AgentCertificate::issue_with_expiry(&user, &former_acp, Some(now + 86_400))
            .expect("rider certificate");
    journal(
        &agent,
        &issuance(
            &user,
            &acp_first,
            profile::CertMode::Acp,
            "harness",
            now - 20,
        ),
    )
    .await;
    journal(
        &agent,
        &issuance(
            &user,
            &rider_later,
            profile::CertMode::Rider,
            "pi rider",
            now - 10,
        ),
    )
    .await;
    assert_rider(&entry(&agent, &former_acp).await, "ACP re-issued as rider");
    agent.shutdown().await;
}
