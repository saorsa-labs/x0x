//! ADR 0115 D214: quarantine of pre-upgrade issuer revocations
//! and bundle tombstones.
//!
//! Records persisted by an earlier build carry no certificate provenance,
//! so they cannot be checked against the ADR 0115 sources at load.
//!
//! On the first start of an ADR 0115 build, this module moves every
//! persisted issuer revocation (an `Agent` revocation that is not a
//! self-revocation, or an `AgentMachineBinding` tombstone) and every held
//! bundle into a quarantine, unless the local user issued it:
//! - a quarantined item is kept, in `revocation-quarantine.bin`, but is not
//!   enforced;
//! - it is enforced again once authenticated evidence confirms its issuer:
//!   a certificate for its subject with ADR 0115 §3 provenance whose owner
//!   is the item's issuer;
//! - an item still unconfirmed [`QUARANTINE_LAPSE_SECS`] after the
//!   quarantine started lapses: it is removed, and its hash is kept so the
//!   copy still on disk is filtered at every later load;
//! - an agent Blocked in `contacts.json` and revoked by a quarantined record
//!   is unblocked when the quarantine starts, and blocked again only if that
//!   record is confirmed.
//!
//! The file is versioned (ADR 0085). An unreadable file is never
//! overwritten; the quarantine is then off and every loaded record is
//! enforced, as before ADR 0115.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::contacts::{ContactStore, TrustLevel};
use crate::identity::{AgentCertificate, AgentId, UserId};
use crate::key_move::{ChainedRecord, MoveRecord, MoveState};
use crate::revocation::{RevocationRecord, RevocationSet, RevokedSubject};

/// The quarantine file, next to the revocation stores.
pub(crate) const QUARANTINE_FILE: &str = "revocation-quarantine.bin";
/// Magic of layout 1 (ADR 0085 rule 1).
const QUARANTINE_MAGIC_V1: &[u8; 4] = b"X0Q1";
/// D214: an unconfirmed item lapses 7 days after the quarantine starts.
pub(crate) const QUARANTINE_LAPSE_SECS: u64 = 7 * 24 * 3600;
/// How often the running daemon tries to confirm or lapse items.
pub(crate) const QUARANTINE_TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// One quarantined revocation with the certificate it was verified with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct QuarantinedRecord {
    record: RevocationRecord,
    subject_cert: Option<AgentCertificate>,
}

/// The persisted quarantine (layout 1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct QuarantineState {
    /// Unix seconds when the quarantine started.
    started_at: u64,
    /// Pending issuer revocations.
    records: Vec<QuarantinedRecord>,
    /// Pending bundles.
    bundles: Vec<ChainedRecord>,
    /// Agents unblocked because a pending record had blocked them.
    blocked: Vec<AgentId>,
    /// Hashes of lapsed records and bundles, filtered at every load.
    lapsed: Vec<[u8; 32]>,
    /// Whether the agents in `blocked` were unblocked (a start that crashed
    /// after writing the file finishes it on the next start).
    unblocked: bool,
}

/// What [`QuarantineState::tick`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TickOutcome {
    /// The quarantine file must be rewritten.
    pub(crate) state_changed: bool,
    /// A restored record must reach `revocations.bin`.
    pub(crate) v1_changed: bool,
    /// A restored binding tombstone must reach `revocations-v2.bin`.
    pub(crate) v2_changed: bool,
    /// A restored bundle must reach `move-bundles.bin`.
    pub(crate) bundles_changed: bool,
}

fn bundle_issuer(chained: &ChainedRecord) -> Option<(AgentId, UserId)> {
    match &chained.record {
        MoveRecord::ActivationBundle {
            authorization,
            agent_certificate,
            ..
        } => Some((authorization.agent_id, agent_certificate.user_id().ok()?)),
        _ => None,
    }
}

impl QuarantineState {
    /// The items to quarantine on the first start of an ADR 0115 build.
    /// Nothing is removed here; [`Self::apply_at_load`] does that once the
    /// file is durable.
    pub(crate) fn plan(
        now: u64,
        local_user: Option<UserId>,
        revoked: &RevocationSet,
        moves: &MoveState,
        contacts: &ContactStore,
    ) -> Self {
        let records: Vec<QuarantinedRecord> = revoked
            .records_with_certs()
            .filter(|(record, _)| {
                record.needs_certificate_authority().is_some()
                    && record.issuer_user_id() != local_user
            })
            .map(|(record, subject_cert)| QuarantinedRecord {
                record: record.clone(),
                subject_cert: subject_cert.cloned(),
            })
            .collect();
        let bundles: Vec<ChainedRecord> = moves
            .held_bundles()
            .filter(|chained| bundle_issuer(chained).map(|(_, owner)| owner) != local_user)
            .cloned()
            .collect();
        let blocked: Vec<AgentId> = records
            .iter()
            .filter_map(|quarantined| match quarantined.record.subject {
                RevokedSubject::Agent(agent) => Some(agent),
                _ => None,
            })
            .filter(|agent| contacts.trust_level(agent) == TrustLevel::Blocked)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        Self {
            started_at: now,
            records,
            bundles,
            blocked,
            lapsed: Vec::new(),
            unblocked: false,
        }
    }

    /// Remove every pending or lapsed item from the loaded stores. Bundle
    /// tombstones are recomputed from the bundles that stay held.
    pub(crate) fn apply_at_load(&self, revoked: &mut RevocationSet, moves: &mut MoveState) {
        let mut hashes: HashSet<[u8; 32]> = self.lapsed.iter().copied().collect();
        hashes.extend(
            self.records
                .iter()
                .map(|quarantined| quarantined.record.record_hash()),
        );
        hashes.extend(self.bundles.iter().map(ChainedRecord::record_hash));
        revoked.take_records_where(|record, _| hashes.contains(&record.record_hash()));
        let taken = moves.take_bundles_where(|chained| hashes.contains(&chained.record_hash()));
        if !taken.is_empty() {
            revoked.reset_bundle_retired(&moves.bundle_tombstones());
        }
    }

    /// Unblock the agents a pending record had blocked, once (the first
    /// start, or the next start after a crash before it finished).
    /// Returns whether it ran. D214 cannot tell a Blocked flag that such a
    /// revocation set from one the user set by hand.
    pub(crate) fn unblock(&mut self, contacts: &mut ContactStore) -> bool {
        if self.unblocked {
            return false;
        }
        for agent in &self.blocked {
            contacts.set_trust(agent, TrustLevel::Unknown);
        }
        self.unblocked = true;
        true
    }

    /// Whether any item is still pending.
    pub(crate) fn is_pending(&self) -> bool {
        !self.records.is_empty() || !self.bundles.is_empty()
    }

    /// The subjects of pending items, for the caller's certificate lookup.
    pub(crate) fn pending_subjects(&self) -> Vec<AgentId> {
        let mut subjects: HashSet<AgentId> = self
            .records
            .iter()
            .filter_map(|quarantined| quarantined.record.needs_certificate_authority())
            .collect();
        subjects.extend(
            self.bundles
                .iter()
                .filter_map(|chained| bundle_issuer(chained).map(|(agent, _)| agent)),
        );
        subjects.into_iter().collect()
    }

    /// Confirm every pending item whose issuer owns `certs[subject]` (a
    /// certificate with ADR 0115 §3 provenance), and lapse what is still
    /// pending [`QUARANTINE_LAPSE_SECS`] after the start. A confirmed agent
    /// revocation's subject is pushed to `evict`, and to `reblock` when the
    /// quarantine had unblocked it; the caller applies both after it
    /// releases the stores (each lock alone).
    pub(crate) fn tick(
        &mut self,
        now: u64,
        certs: &std::collections::HashMap<AgentId, Vec<AgentCertificate>>,
        revoked: &mut RevocationSet,
        moves: &mut MoveState,
        reblock: &mut Vec<AgentId>,
        evict: &mut Vec<AgentId>,
    ) -> TickOutcome {
        let mut outcome = TickOutcome::default();
        let mut pending_records = Vec::new();
        for quarantined in std::mem::take(&mut self.records) {
            let issuer = quarantined.record.issuer_user_id();
            let confirmed_by = quarantined
                .record
                .needs_certificate_authority()
                .and_then(|subject| certs.get(&subject))
                .and_then(|candidates| {
                    candidates
                        .iter()
                        .find(|cert| issuer.is_some() && cert.user_id().ok() == issuer)
                });
            let Some(cert) = confirmed_by else {
                pending_records.push(quarantined);
                continue;
            };
            outcome.state_changed = true;
            if revoked
                .verify_and_insert(quarantined.record.clone(), Some(cert))
                .is_err()
            {
                // The confirmed certificate does not authorize the record:
                // it can never be confirmed, so it lapses now.
                self.lapsed.push(quarantined.record.record_hash());
                continue;
            }
            match quarantined.record.subject {
                RevokedSubject::Agent(agent) => {
                    outcome.v1_changed = true;
                    if self.blocked.contains(&agent) {
                        reblock.push(agent);
                    }
                    evict.push(agent);
                }
                _ => outcome.v2_changed = true,
            }
        }
        self.records = pending_records;

        let mut pending_bundles = Vec::new();
        for chained in std::mem::take(&mut self.bundles) {
            let Some((agent, owner)) = bundle_issuer(&chained) else {
                outcome.state_changed = true;
                self.lapsed.push(chained.record_hash());
                continue;
            };
            if !certs.get(&agent).is_some_and(|candidates| {
                candidates
                    .iter()
                    .any(|cert| cert.user_id().ok() == Some(owner))
            }) {
                pending_bundles.push(chained);
                continue;
            }
            outcome.state_changed = true;
            match moves.ingest_bundle(&agent, &chained, revoked) {
                Ok(_) => outcome.bundles_changed = true,
                Err(_) => self.lapsed.push(chained.record_hash()),
            }
        }
        self.bundles = pending_bundles;

        if self.is_pending() && now >= self.started_at.saturating_add(QUARANTINE_LAPSE_SECS) {
            outcome.state_changed = true;
            self.lapsed.extend(
                self.records
                    .iter()
                    .map(|quarantined| quarantined.record.record_hash()),
            );
            self.lapsed
                .extend(self.bundles.iter().map(ChainedRecord::record_hash));
            self.records.clear();
            self.bundles.clear();
        }
        if !self.is_pending() && !self.blocked.is_empty() {
            outcome.state_changed = true;
            self.blocked.clear();
        }
        outcome
    }

    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        use bincode::Options;
        let body = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(self)
            .map_err(|e| format!("quarantine encode: {e}"))?;
        let mut out = Vec::with_capacity(QUARANTINE_MAGIC_V1.len() + body.len());
        out.extend_from_slice(QUARANTINE_MAGIC_V1);
        out.extend_from_slice(&body);
        Ok(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        use bincode::Options;
        let body = bytes
            .strip_prefix(QUARANTINE_MAGIC_V1.as_slice())
            .ok_or_else(|| "unknown quarantine file magic".to_string())?;
        // Positional layout: the body must be consumed exactly (ADR 0085).
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize::<Self>(body)
            .map_err(|e| format!("quarantine decode: {e}"))
    }
}

/// The running quarantine of one daemon.
#[derive(Debug, Default)]
pub(crate) struct Quarantine {
    /// Where the quarantine file lives; `None` when there is no data dir.
    dir: Option<PathBuf>,
    /// `None` when the quarantine is off (no dir, or an unreadable file).
    state: Option<QuarantineState>,
}

impl Quarantine {
    /// Diagnostics: whether the quarantine is on and what it holds.
    pub(crate) fn summary(&self) -> serde_json::Value {
        match &self.state {
            Some(state) => serde_json::json!({
                "enabled": true,
                "started_at": state.started_at,
                "pending_records": state.records.len(),
                "pending_bundles": state.bundles.len(),
                "lapsed": state.lapsed.len(),
            }),
            None => serde_json::json!({ "enabled": false }),
        }
    }

    /// The quarantine state, when it is on.
    pub(crate) fn state_mut(&mut self) -> Option<&mut QuarantineState> {
        self.state.as_mut()
    }

    /// Persist the quarantine state (atomic replace).
    pub(crate) async fn save(&self) {
        let (Some(dir), Some(state)) = (&self.dir, &self.state) else {
            return;
        };
        if let Err(e) = write(dir, state).await {
            tracing::warn!("failed to persist the ADR 0115 revocation quarantine: {e}");
        }
    }
}

/// The stores the running quarantine reads and restores into.
pub(crate) struct TickInputs {
    pub(crate) quarantine: std::sync::Arc<tokio::sync::Mutex<Quarantine>>,
    pub(crate) discovery: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
    >,
    pub(crate) machines: std::sync::Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<crate::identity::MachineId, crate::DiscoveredMachine>,
        >,
    >,
    pub(crate) announced: crate::dm_inbox::AuthenticatedMachineBindings,
    pub(crate) revoked: std::sync::Arc<tokio::sync::RwLock<RevocationSet>>,
    pub(crate) moves: std::sync::Arc<tokio::sync::RwLock<MoveState>>,
    pub(crate) contacts: std::sync::Arc<tokio::sync::RwLock<ContactStore>>,
    /// The revocation stores' directory (`None` uses the default, as the
    /// identity listener does).
    pub(crate) identity_dir: Option<PathBuf>,
    /// ADR 0115 §3 provenance sources beyond the discovery cache.
    pub(crate) evidence: std::sync::Arc<crate::peer_evidence::EvidenceRuntime>,
    pub(crate) local_user: Option<UserId>,
    pub(crate) journal_path: Option<PathBuf>,
    pub(crate) shutdown: tokio_util::sync::CancellationToken,
}

/// Confirm or lapse quarantined items every [`QUARANTINE_TICK`] until
/// shutdown or until nothing is pending.
pub(crate) async fn run(inputs: TickInputs) {
    loop {
        tokio::select! {
            () = inputs.shutdown.cancelled() => return,
            () = tokio::time::sleep(QUARANTINE_TICK) => {}
        }
        if !run_once(&inputs, crate::Agent::unix_timestamp_secs()).await {
            return;
        }
    }
}

/// One confirm-or-lapse pass. Returns whether anything is still pending.
pub(crate) async fn run_once(inputs: &TickInputs, now: u64) -> bool {
    let subjects = {
        let mut quarantine = inputs.quarantine.lock().await;
        match quarantine.state_mut() {
            Some(state) if state.is_pending() => state.pending_subjects(),
            _ => return false,
        }
    };
    // ADR 0115 §3: the same provenance as revocation ingest.
    let certs: std::collections::HashMap<AgentId, Vec<AgentCertificate>> = {
        let journal = crate::load_journal_certs(inputs.journal_path.as_deref()).await;
        let announced = inputs.announced.read().await;
        let discovery = inputs.discovery.read().await;
        crate::collect_subject_certs(
            &crate::ProvenanceSources {
                cache: &discovery,
                announced: &announced,
                evidence: Some(&inputs.evidence),
                local_user: inputs.local_user,
                journal: &journal,
            },
            subjects,
        )
    };
    let (mut reblock, mut evict) = (Vec::new(), Vec::new());
    let pending = {
        let mut quarantine = inputs.quarantine.lock().await;
        let Some(state) = quarantine.state_mut() else {
            return false;
        };
        let outcome = {
            let mut moves = inputs.moves.write().await;
            let mut revoked = inputs.revoked.write().await;
            state.tick(
                now,
                &certs,
                &mut revoked,
                &mut moves,
                &mut reblock,
                &mut evict,
            )
        };
        let pending = state.is_pending();
        // Restore durability: the restored stores reach disk first; the
        // quarantine file, which would no longer list the items, second.
        persist_restored(inputs, outcome).await;
        if outcome.state_changed {
            quarantine.save().await;
        }
        pending
    };
    if !reblock.is_empty() {
        let mut contacts = inputs.contacts.write().await;
        for agent in &reblock {
            contacts.set_trust(agent, TrustLevel::Blocked);
        }
    }
    for agent in &evict {
        let removed = inputs.discovery.write().await.remove(agent);
        if let Some(entry) = removed {
            inputs.machines.write().await.remove(&entry.machine_id);
        }
    }
    pending
}

/// Persist the stores a tick restored items into, as the identity
/// listener persists remote records.
async fn persist_restored(inputs: &TickInputs, outcome: TickOutcome) {
    if outcome.v1_changed {
        let bytes = inputs.revoked.read().await.to_bytes();
        match bytes {
            Ok(bytes) => {
                if let Err(e) =
                    crate::storage::save_revocation_set_bytes(bytes, inputs.identity_dir.as_deref())
                        .await
                {
                    tracing::warn!("failed to persist a confirmed revocation: {e}");
                }
            }
            Err(e) => tracing::warn!("failed to encode the revocation set: {e}"),
        }
    }
    let Some(dir) = inputs.identity_dir.as_deref() else {
        return;
    };
    if outcome.v2_changed {
        if let Ok(bytes) = inputs.revoked.read().await.to_bytes_v2() {
            let _ =
                crate::storage::save_private_bytes_to(&dir.join("revocations-v2.bin"), bytes).await;
        }
    }
    if outcome.bundles_changed {
        let (bundles, placements) = {
            let moves = inputs.moves.read().await;
            (moves.bundles_to_bytes(), moves.placements_to_bytes())
        };
        if let Ok(bytes) = bundles {
            let _ =
                crate::storage::save_private_bytes_to(&dir.join("move-bundles.bin"), bytes).await;
        }
        if let Ok(bytes) = placements {
            let _ = crate::storage::save_private_bytes_to(&dir.join("placement-blobs.bin"), bytes)
                .await;
        }
    }
}

async fn write(dir: &Path, state: &QuarantineState) -> Result<(), String> {
    let bytes = state.to_bytes()?;
    crate::storage::save_private_bytes_to(&dir.join(QUARANTINE_FILE), bytes)
        .await
        .map_err(|e| format!("quarantine write: {e}"))
}

/// Load the quarantine at daemon start, after every revocation store and
/// move bundle is loaded and before anything reads them.
///
/// - No file: plan the quarantine, make it durable, then remove its items
///   from the loaded stores and unblock its agents. If the file cannot be
///   written, nothing is quarantined on this start (the next start retries).
/// - A readable file: remove its pending and lapsed items again.
/// - An unreadable file: leave it untouched and enforce everything.
pub(crate) async fn start(
    dir: Option<&Path>,
    local_user: Option<UserId>,
    revoked: &tokio::sync::RwLock<RevocationSet>,
    moves: &tokio::sync::RwLock<MoveState>,
    contacts: &tokio::sync::RwLock<ContactStore>,
    now: u64,
) -> Quarantine {
    let Some(dir) = dir else {
        return Quarantine::default();
    };
    let path = dir.join(QUARANTINE_FILE);
    match tokio::fs::read(&path).await {
        Ok(bytes) => match QuarantineState::from_bytes(&bytes) {
            Ok(mut state) => {
                {
                    let mut moves = moves.write().await;
                    let mut revoked = revoked.write().await;
                    state.apply_at_load(&mut revoked, &mut moves);
                }
                if state.unblock(&mut *contacts.write().await) {
                    if let Err(e) = write(dir, &state).await {
                        tracing::warn!("failed to persist the ADR 0115 quarantine: {e}");
                    }
                }
                Quarantine {
                    dir: Some(dir.to_path_buf()),
                    state: Some(state),
                }
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    "unreadable ADR 0115 revocation quarantine left untouched; quarantine off: {e}"
                );
                Quarantine::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut state = {
                let moves = moves.read().await;
                let revoked = revoked.read().await;
                let contacts = contacts.read().await;
                QuarantineState::plan(now, local_user, &revoked, &moves, &contacts)
            };
            if let Err(e) = write(dir, &state).await {
                tracing::error!("ADR 0115 revocation quarantine not started: {e}");
                return Quarantine::default();
            }
            {
                let mut moves = moves.write().await;
                let mut revoked = revoked.write().await;
                state.apply_at_load(&mut revoked, &mut moves);
            }
            if state.unblock(&mut *contacts.write().await) {
                if let Err(e) = write(dir, &state).await {
                    tracing::warn!("failed to persist the ADR 0115 quarantine: {e}");
                }
            }
            if state.is_pending() {
                tracing::warn!(
                    records = state.records.len(),
                    bundles = state.bundles.len(),
                    "quarantined pre-upgrade issuer revocations and bundles (ADR 0115 D214)"
                );
            }
            Quarantine {
                dir: Some(dir.to_path_buf()),
                state: Some(state),
            }
        }
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                "ADR 0115 revocation quarantine unreadable; quarantine off: {e}"
            );
            Quarantine::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};
    use crate::key_move::{MoveAuthorization, Placement, PlacementRecord};
    use crate::revocation::AgentMachineBinding;

    fn issuer_revocation(owner: &UserKeypair, subject: RevokedSubject) -> RevocationRecord {
        RevocationRecord::sign(subject, owner.public_key(), owner.secret_key(), 1_000, None)
            .expect("issuer revocation")
    }

    fn bundle(
        subject: AgentId,
        from: crate::identity::MachineId,
        owner: &UserKeypair,
        cert: &AgentCertificate,
    ) -> ChainedRecord {
        let to = MachineKeypair::generate().expect("target").machine_id();
        let authorization = MoveAuthorization {
            agent_id: subject,
            move_epoch: 1,
            from_machine: from,
            to_machine: to,
            placement: Placement::Pinned(to),
            issued_at: 1_000,
        };
        let placement_record = PlacementRecord::sign(
            subject,
            owner.public_key().as_bytes(),
            Placement::Pinned(to),
            1,
            1_000,
            owner.secret_key(),
        )
        .expect("placement");
        ChainedRecord::sign(
            [0u8; 32],
            MoveRecord::ActivationBundle {
                authorization,
                retired_bindings: vec![AgentMachineBinding {
                    agent: subject,
                    machine: from,
                    move_epoch: 1,
                }],
                placement_record,
                agent_certificate: cert.clone(),
            },
            owner.public_key().as_bytes(),
            owner.secret_key(),
        )
        .expect("bundle")
    }

    /// D214 end to end on the in-memory stores: plan, apply, confirm and
    /// lapse, with the local user's own records never quarantined.
    #[test]
    fn quarantine_holds_confirms_and_lapses_pre_upgrade_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let local = UserKeypair::generate().expect("local user");
        let foreign = UserKeypair::generate().expect("foreign user");
        let confirmed = AgentKeypair::generate().expect("confirmed subject");
        let unconfirmed = AgentKeypair::generate().expect("unconfirmed subject");
        let mine = AgentKeypair::generate().expect("local subject");
        let selfish = AgentKeypair::generate().expect("self-revoked");
        let moved = AgentKeypair::generate().expect("moved subject");
        let confirmed_cert = AgentCertificate::issue(&foreign, &confirmed).expect("cert");
        let unconfirmed_cert = AgentCertificate::issue(&foreign, &unconfirmed).expect("cert");
        let mine_cert = AgentCertificate::issue(&local, &mine).expect("cert");
        let moved_cert = AgentCertificate::issue(&foreign, &moved).expect("cert");
        let moved_from = MachineKeypair::generate().expect("machine").machine_id();

        let mut revoked = RevocationSet::new();
        for (record, cert) in [
            (
                issuer_revocation(&foreign, RevokedSubject::Agent(confirmed.agent_id())),
                &confirmed_cert,
            ),
            (
                issuer_revocation(&foreign, RevokedSubject::Agent(unconfirmed.agent_id())),
                &unconfirmed_cert,
            ),
            (
                issuer_revocation(&local, RevokedSubject::Agent(mine.agent_id())),
                &mine_cert,
            ),
        ] {
            revoked
                .verify_and_insert(record, Some(cert))
                .expect("pre-upgrade insert");
        }
        revoked
            .verify_and_insert(
                RevocationRecord::sign(
                    RevokedSubject::Agent(selfish.agent_id()),
                    selfish.public_key(),
                    selfish.secret_key(),
                    1_000,
                    None,
                )
                .expect("self revocation"),
                None,
            )
            .expect("self insert");
        let mut moves = MoveState::new();
        moves
            .ingest_bundle(
                &moved.agent_id(),
                &bundle(moved.agent_id(), moved_from, &foreign, &moved_cert),
                &mut revoked,
            )
            .expect("pre-upgrade bundle");
        assert!(revoked.is_binding_revoked(&moved.agent_id(), &moved_from));
        let mut contacts = ContactStore::new(dir.path().join("contacts.json"));
        contacts.set_trust(&confirmed.agent_id(), TrustLevel::Blocked);
        contacts.set_trust(&unconfirmed.agent_id(), TrustLevel::Blocked);

        let start = 10_000;
        let mut state =
            QuarantineState::plan(start, Some(local.user_id()), &revoked, &moves, &contacts);
        assert_eq!(state.records.len(), 2, "foreign issuer revocations only");
        assert_eq!(state.bundles.len(), 1);
        let bytes = state.to_bytes().expect("encode");
        assert_eq!(
            QuarantineState::from_bytes(&bytes).expect("decode"),
            state,
            "the layout round-trips"
        );
        assert!(QuarantineState::from_bytes(b"X0Q9garbage").is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(QuarantineState::from_bytes(&trailing).is_err());

        state.apply_at_load(&mut revoked, &mut moves);
        assert!(state.unblock(&mut contacts));
        assert!(!state.unblock(&mut contacts), "unblock runs once");
        assert!(!revoked.is_agent_revoked(&confirmed.agent_id()));
        assert!(!revoked.is_agent_revoked(&unconfirmed.agent_id()));
        assert!(revoked.is_agent_revoked(&mine.agent_id()), "local issuer");
        assert!(
            revoked.is_agent_revoked(&selfish.agent_id()),
            "self-revocation"
        );
        assert!(!revoked.is_binding_revoked(&moved.agent_id(), &moved_from));
        assert!(moves.bundle(&moved.agent_id()).is_none());
        assert!(moves.placement(&moved.agent_id()).is_none());
        assert_eq!(
            contacts.trust_level(&confirmed.agent_id()),
            TrustLevel::Unknown
        );

        // Authenticated evidence confirms one record and the bundle.
        let mut certs = std::collections::HashMap::new();
        certs.insert(confirmed.agent_id(), vec![confirmed_cert.clone()]);
        certs.insert(moved.agent_id(), vec![moved_cert.clone()]);
        let (mut reblock, mut evict) = (Vec::new(), Vec::new());
        let outcome = state.tick(
            start + 60,
            &certs,
            &mut revoked,
            &mut moves,
            &mut reblock,
            &mut evict,
        );
        assert!(outcome.state_changed && outcome.v1_changed && outcome.bundles_changed);
        assert_eq!(evict, vec![confirmed.agent_id()]);
        assert_eq!(reblock, vec![confirmed.agent_id()], "it had been blocked");
        assert!(revoked.is_agent_revoked(&confirmed.agent_id()));
        assert!(revoked.is_binding_revoked(&moved.agent_id(), &moved_from));
        assert_eq!(state.records.len(), 1);
        assert!(state.bundles.is_empty());

        // A different owner's certificate never confirms.
        let other = AgentCertificate::issue(&local, &unconfirmed).expect("other owner");
        certs.insert(unconfirmed.agent_id(), vec![other]);
        state.tick(
            start + 120,
            &certs,
            &mut revoked,
            &mut moves,
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(!revoked.is_agent_revoked(&unconfirmed.agent_id()));

        // Seven days later the rest lapses and stays filtered at load.
        let lapsed_hash = state.records[0].record.record_hash();
        let outcome = state.tick(
            start + QUARANTINE_LAPSE_SECS,
            &std::collections::HashMap::new(),
            &mut revoked,
            &mut moves,
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(outcome.state_changed);
        assert!(!state.is_pending());
        assert!(state.lapsed.contains(&lapsed_hash));
        assert_eq!(
            contacts.trust_level(&unconfirmed.agent_id()),
            TrustLevel::Unknown
        );
        let mut reloaded = RevocationSet::new();
        reloaded
            .verify_and_insert(
                issuer_revocation(&foreign, RevokedSubject::Agent(unconfirmed.agent_id())),
                Some(&unconfirmed_cert),
            )
            .expect("the copy still on disk");
        state.apply_at_load(&mut reloaded, &mut MoveState::new());
        assert!(!reloaded.is_agent_revoked(&unconfirmed.agent_id()));
    }

    /// A first start writes the file before it removes anything; a later
    /// start applies the same file; an unreadable file is left untouched.
    #[tokio::test]
    async fn start_is_durable_first_and_never_overwrites_an_unreadable_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let foreign = UserKeypair::generate().expect("foreign user");
        let subject = AgentKeypair::generate().expect("subject");
        let cert = AgentCertificate::issue(&foreign, &subject).expect("cert");
        let mut set = RevocationSet::new();
        set.verify_and_insert(
            issuer_revocation(&foreign, RevokedSubject::Agent(subject.agent_id())),
            Some(&cert),
        )
        .expect("insert");
        let revoked = tokio::sync::RwLock::new(set.clone());
        let moves = tokio::sync::RwLock::new(MoveState::new());
        let contacts =
            tokio::sync::RwLock::new(ContactStore::new(dir.path().join("contacts.json")));

        let quarantine = start(Some(dir.path()), None, &revoked, &moves, &contacts, 5).await;
        assert!(quarantine.state.is_some());
        assert!(!revoked.read().await.is_agent_revoked(&subject.agent_id()));
        assert!(dir.path().join(QUARANTINE_FILE).exists());

        // The next start reloads the same stores from disk.
        let reloaded = tokio::sync::RwLock::new(set.clone());
        let again = start(Some(dir.path()), None, &reloaded, &moves, &contacts, 6).await;
        assert!(again.state.is_some());
        assert!(!reloaded.read().await.is_agent_revoked(&subject.agent_id()));

        let unreadable = tempfile::tempdir().expect("tempdir");
        let path = unreadable.path().join(QUARANTINE_FILE);
        tokio::fs::write(&path, b"X0Q2 from a newer build")
            .await
            .expect("seed");
        let enforced = tokio::sync::RwLock::new(set);
        let off = start(
            Some(unreadable.path()),
            None,
            &enforced,
            &moves,
            &contacts,
            7,
        )
        .await;
        assert!(off.state.is_none());
        assert!(enforced.read().await.is_agent_revoked(&subject.agent_id()));
        assert_eq!(
            tokio::fs::read(&path).await.expect("still there"),
            b"X0Q2 from a newer build"
        );
    }
}
