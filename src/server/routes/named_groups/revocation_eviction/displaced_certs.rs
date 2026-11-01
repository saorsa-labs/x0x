//! ADR 0110 §4a (#1650): the retained displaced rebind certificates.
//!
//! An applied `CertificateRebindV1` (or an installed SignedPublic
//! catch-up head) displaces a seat's parent certificate. The displaced
//! bytes are the evidence a later competing sibling rebind on the same
//! parent is checked against, so they are kept verifiable; without them
//! the sibling is refused with `rebind_certificate_evidence_missing`
//! and records nothing (#1533 r11). The retention lives in memory on
//! [`GroupInfo`](crate::groups::GroupInfo) and NEVER serializes with the
//! record — ADR 0110 §5: neither legacy JSON format changes — so it
//! persists here, in S4's own sidecar, and reloads at startup.
//!
//! - **File.** `<data_dir>/revocation-evictions.rdc`. It is local state,
//!   not a wire format: the header `X0XRDC1\0`, the postcard
//!   [`DisplacedCertsV1`], then the BLAKE3 hash of that body (the layout
//!   of the kept expiry hand-offs, [`encode_local_file`]).
//! - **Write.** A projection of the live map, refreshed after every
//!   roster save that landed: group deletions and cap evictions retire
//!   with it, so the file never accumulates orphans. Temp write, fsync,
//!   atomic rename and directory fsync. §5: no write inside an ADR 0094
//!   trial, and a file with a newer layout is never rewritten. Best
//!   effort — a failed write loses retained evidence (the pre-#1650
//!   refusals) and never fails the roster save.
//! - **Load.** Entries whose certificate does not hash to their digest
//!   key are dropped: a retained entry is evidence only for the digest
//!   the parent roster signed. A damaged file is quarantined
//!   (ADR 0108 §5a) and its evidence is lost (inside an ADR 0094 trial
//!   it is left in place and the first save after host commit replaces
//!   it); a newer layout stays on disk, not loaded.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path as FsPath, PathBuf};

use serde::{Deserialize, Serialize};

use crate::groups::cert_rebind::{enforce_displaced_certificate_cap, RetainedCertificate};
use crate::groups::eviction::SidecarDecodeError;
use crate::groups::GroupInfo;
use crate::identity::AgentCertificate;
use crate::server::state::AppState;

use super::rebind::replay_log::{decode_local_file, encode_local_file};

/// The file name in the data directory.
const FILE_NAME: &str = "revocation-evictions.rdc";
const PREFIX: &[u8] = b"X0XRDC";
const HEADER_V1: &[u8; 8] = b"X0XRDC1\0";
const MAX_SUPPORTED_VERSION: u8 = 1;

/// One retained entry of the frozen v1 body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DisplacedCertEntryV1 {
    certificate: AgentCertificate,
    retained_seq: u64,
}

/// The frozen v1 file body: every group's retained entries, keyed by
/// stable group ID and the displaced certificate's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DisplacedCertsV1 {
    groups: BTreeMap<String, BTreeMap<String, DisplacedCertEntryV1>>,
}

fn path(data_dir: &FsPath) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// The file body of the live map. Deterministic: map iteration is
/// unordered, so the keys are visited in sorted order and two entries
/// that share a stable ID (a transient re-seat staging slot never
/// reaches a save) merge by keeping the higher `retained_seq`.
fn project(groups: &HashMap<String, GroupInfo>) -> DisplacedCertsV1 {
    let mut keys: Vec<&String> = groups.keys().collect();
    keys.sort();
    let mut file = DisplacedCertsV1 {
        groups: BTreeMap::new(),
    };
    for key in keys {
        let Some(info) = groups.get(key) else {
            continue;
        };
        if info.displaced_certificates.is_empty() {
            continue;
        }
        let entries = file
            .groups
            .entry(info.stable_group_id().to_string())
            .or_default();
        for (digest, retained) in &info.displaced_certificates {
            let entry = DisplacedCertEntryV1 {
                certificate: retained.certificate.clone(),
                retained_seq: retained.retained_seq,
            };
            entries
                .entry(digest.clone())
                .and_modify(|existing| {
                    if existing.retained_seq < entry.retained_seq {
                        *existing = entry.clone();
                    }
                })
                .or_insert(entry);
        }
    }
    file
}

fn encode(file: &DisplacedCertsV1) -> Result<Vec<u8>, postcard::Error> {
    encode_local_file(HEADER_V1, file)
}

fn decode(
    bytes: &[u8],
) -> Result<BTreeMap<String, BTreeMap<String, RetainedCertificate>>, SidecarDecodeError> {
    let file: DisplacedCertsV1 = decode_local_file(PREFIX, MAX_SUPPORTED_VERSION, bytes)?;
    Ok(file
        .groups
        .into_iter()
        .map(|(stable, entries)| {
            (
                stable,
                entries
                    .into_iter()
                    .map(|(digest, entry)| {
                        (
                            digest,
                            RetainedCertificate {
                                certificate: entry.certificate,
                                retained_seq: entry.retained_seq,
                            },
                        )
                    })
                    .collect(),
            )
        })
        .collect())
}

/// Refresh the sidecar after a roster save that landed. See the module
/// doc for the write rules.
pub(in crate::server) async fn sync_after_save(state: &AppState) {
    // §5: no write inside an ADR 0094 trial; the evidence then stays in
    // memory only until the first save after the gate opens.
    if !super::host_commit_gate_open(state) {
        return;
    }
    let file = {
        // The same view the legacy encode uses (#1699): inside a re-seat
        // scope the scoped read is the staging slot, which never reaches
        // disk — projecting it would retire other groups' durable
        // evidence.
        let groups = state.named_groups.live_read().await;
        project(&groups)
    };
    let file_path = path(&state.data_dir);
    let existing = crate::w3h_inline::fs::read(&file_path).await.ok();
    if let Some(bytes_on_disk) = existing.as_deref() {
        if let Err(SidecarDecodeError::NewerFormat(version)) = decode(bytes_on_disk) {
            tracing::warn!(
                version,
                path = %file_path.display(),
                "ADR 0110 S4: displaced rebind certificates have a newer layout; not rewritten"
            );
            return;
        }
    }
    if file.groups.is_empty() {
        if existing.is_some() {
            super::remove_file_durably(&file_path).await;
        }
        return;
    }
    let Ok(bytes) = encode(&file) else {
        tracing::warn!("ADR 0110 S4: displaced rebind certificate encode failed");
        return;
    };
    if existing.as_deref() == Some(bytes.as_slice()) {
        return;
    }
    if let Err(error) = super::write_bytes_durably(&file_path, &bytes, None).await {
        tracing::warn!(
            %error,
            path = %file_path.display(),
            "ADR 0110 S4: displaced rebind certificate write failed; the evidence stays in memory only"
        );
    }
}

/// Load the sidecar into the freshly loaded groups at startup. Entries
/// of a group the map does not hold are dropped with the next rewrite.
pub(in crate::server) async fn load_into(
    groups: &mut HashMap<String, GroupInfo>,
    data_dir: &FsPath,
) {
    let file_path = path(data_dir);
    let Ok(bytes) = crate::w3h_inline::fs::read(&file_path).await else {
        return;
    };
    let loaded = match decode(&bytes) {
        Ok(loaded) => loaded,
        Err(SidecarDecodeError::NewerFormat(version)) => {
            tracing::warn!(
                version,
                path = %file_path.display(),
                "ADR 0110 S4: displaced rebind certificates have a newer layout; not loaded"
            );
            return;
        }
        Err(SidecarDecodeError::Damaged(reason)) if !super::host_commit_gate_open_at(data_dir) => {
            tracing::warn!(
                reason,
                path = %file_path.display(),
                "ADR 0110 S4: damaged displaced rebind certificates inside an ADR 0094 trial; not loaded, and the first save after host commit replaces the file"
            );
            return;
        }
        Err(SidecarDecodeError::Damaged(reason)) => {
            tracing::warn!(
                reason,
                path = %file_path.display(),
                "ADR 0110 S4: damaged displaced rebind certificates; quarantining (ADR 0108 §5a); they are lost"
            );
            match super::quarantine_file(&file_path, &bytes).await {
                Ok((_, pending)) => {
                    super::finalize_quarantine(&pending).await;
                }
                Err(step) => {
                    tracing::warn!(
                        step,
                        path = %file_path.display(),
                        "ADR 0110 S4: displaced rebind certificate quarantine failed"
                    );
                }
            }
            return;
        }
    };
    for info in groups.values_mut() {
        let Some(entries) = loaded.get(info.stable_group_id()) else {
            continue;
        };
        for (digest, retained) in entries {
            if crate::groups::owner_cert::certificate_digest_hex(&retained.certificate) != *digest {
                tracing::warn!(
                    digest = %digest,
                    "ADR 0110 S4: a displaced rebind certificate does not hash to its digest key; dropped"
                );
                continue;
            }
            info.displaced_certificates
                .insert(digest.clone(), retained.clone());
        }
        enforce_displaced_certificate_cap(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_group() -> (String, GroupInfo, AgentCertificate) {
        let admin = crate::identity::AgentKeypair::generate().expect("admin");
        let owner = crate::identity::UserKeypair::generate().expect("owner");
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "ab".repeat(16),
        );
        let certificate = crate::identity::AgentCertificate::issue(&owner, &admin)
            .expect("a displaced certificate");
        let digest = crate::groups::owner_cert::certificate_digest_hex(&certificate);
        info.displaced_certificates.insert(
            digest.clone(),
            RetainedCertificate {
                certificate: certificate.clone(),
                retained_seq: 4,
            },
        );
        (digest, info, certificate)
    }

    /// The v1 file round-trips the projection, and a flipped byte or a
    /// newer version digit never loads as evidence (fail closed, as the
    /// other S4 files).
    #[test]
    fn displaced_certs_round_trip_and_reject_damage() {
        let (digest, info, _) = retained_group();
        let stable = info.stable_group_id().to_string();
        let bytes = encode(&project(&HashMap::from([("g".to_string(), info)]))).expect("encode");
        let back = decode(&bytes).expect("decode");
        let entries = back.get(&stable).expect("the group's entries");
        let retained = entries.get(&digest).expect("the retained entry");
        assert_eq!(retained.retained_seq, 4);
        let mut damaged = bytes.clone();
        if let Some(last) = damaged.last_mut() {
            *last ^= 1;
        }
        assert!(matches!(
            decode(&damaged),
            Err(SidecarDecodeError::Damaged(_))
        ));
        let mut newer = bytes;
        newer[PREFIX.len()] = b'2';
        assert!(matches!(
            decode(&newer),
            Err(SidecarDecodeError::NewerFormat(2))
        ));
    }

    /// The load keeps only entries whose certificate hashes to their
    /// digest key — the evidence is only for the digest the parent
    /// roster signed — and an oversized file is capped on install.
    #[tokio::test]
    async fn load_drops_digest_mismatches_and_caps_oversized_files() {
        let dir = tempfile::tempdir().expect("dir");
        let (digest, info, certificate) = retained_group();
        let stable = info.stable_group_id().to_string();
        let forged = crate::groups::owner_cert::certificate_digest_hex(
            &crate::identity::AgentCertificate::issue(
                &crate::identity::UserKeypair::generate().expect("owner"),
                &crate::identity::AgentKeypair::generate().expect("agent"),
            )
            .expect("another certificate"),
        );
        let mut file = project(&HashMap::from([("g".to_string(), info.clone())]));
        let entries = file.groups.get_mut(&stable).expect("entries");
        // The legitimate entry is the newest retention, so the cap keeps
        // it and drops the oldest filler instead.
        entries
            .get_mut(&digest)
            .expect("the legit entry")
            .retained_seq = 30;
        entries.insert(
            forged.clone(),
            DisplacedCertEntryV1 {
                certificate,
                retained_seq: 5,
            },
        );
        for seq in 0..crate::groups::cert_rebind::DISPLACED_CERTIFICATE_CAP as u64 {
            let filler = crate::identity::AgentCertificate::issue(
                &crate::identity::UserKeypair::generate().expect("owner"),
                &crate::identity::AgentKeypair::generate().expect("agent"),
            )
            .expect("filler");
            let digest = crate::groups::owner_cert::certificate_digest_hex(&filler);
            entries.insert(
                digest.clone(),
                DisplacedCertEntryV1 {
                    certificate: filler,
                    retained_seq: 10 + seq,
                },
            );
        }
        let bytes = encode(&file).expect("encode");
        tokio::fs::write(path(dir.path()), &bytes)
            .await
            .expect("write");
        let mut groups = HashMap::from([("g".to_string(), info)]);
        load_into(&mut groups, dir.path()).await;
        let loaded = &groups["g"].displaced_certificates;
        assert!(
            !loaded.contains_key(&forged),
            "an entry whose certificate does not hash to its key is dropped"
        );
        assert_eq!(
            loaded.len(),
            crate::groups::cert_rebind::DISPLACED_CERTIFICATE_CAP,
            "the oversized file is capped on install"
        );
        assert!(
            loaded.contains_key(&digest),
            "the legitimate entry survives"
        );
    }

    /// The sync writes the projection once the map holds retained
    /// evidence, and the projection retires the file when the last
    /// entry leaves the map (a group deletion leaves no orphan).
    #[tokio::test]
    async fn sync_projects_the_live_map_and_retires_an_empty_file() {
        let dir = tempfile::tempdir().expect("dir");
        let receiver = super::super::rebind::restart_tests::offline_daemon(dir.path(), None)
            .await
            .expect("daemon");
        let (digest, info, _) = retained_group();
        let key = info.stable_group_id().to_string();
        receiver
            .named_groups
            .write()
            .await
            .insert(key.clone(), info);
        sync_after_save(&receiver).await;
        let bytes = crate::w3h_inline::fs::read(path(dir.path()))
            .await
            .expect("the sidecar holds the projection");
        assert!(
            decode(&bytes)
                .expect("decode")
                .get(&key)
                .is_some_and(|entries| entries.contains_key(&digest)),
            "the retained entry is projected under its stable group id"
        );
        // Unchanged content is not rewritten, and the file leaves with
        // the last entry.
        let before = tokio::fs::metadata(path(dir.path()))
            .await
            .expect("metadata")
            .modified()
            .expect("mtime");
        sync_after_save(&receiver).await;
        let after = tokio::fs::metadata(path(dir.path()))
            .await
            .expect("metadata")
            .modified()
            .expect("mtime");
        assert_eq!(
            before, after,
            "an unchanged projection does not rewrite the file"
        );
        receiver.named_groups.write().await.remove(&key);
        sync_after_save(&receiver).await;
        assert!(
            !tokio::fs::try_exists(path(dir.path()))
                .await
                .unwrap_or(false),
            "an empty projection retires the file"
        );
        receiver.agent.shutdown().await;
    }

    /// #1699 (round-2 self-review): inside a re-seat staging scope the
    /// scoped read is the staging slot, which never reaches disk — the
    /// legacy encode reads the live map there. The projection must do
    /// the same: a save from inside a staging scope must not retire or
    /// shrink the durable evidence of the live groups.
    #[tokio::test]
    async fn sync_inside_a_reseat_scope_keeps_the_live_projection() {
        let dir = tempfile::tempdir().expect("dir");
        let receiver = super::super::rebind::restart_tests::offline_daemon(dir.path(), None)
            .await
            .expect("daemon");
        let (digest, info, _) = retained_group();
        let key = info.stable_group_id().to_string();
        receiver
            .named_groups
            .live_write()
            .await
            .insert(key.clone(), info);
        sync_after_save(&receiver).await;
        let durable = crate::w3h_inline::fs::read(path(dir.path()))
            .await
            .expect("the sidecar holds the live projection");
        // The staged record holds no retained evidence of its own.
        let mut staged = receiver.named_groups.live_read().await[&key].clone();
        staged.displaced_certificates.clear();
        receiver.reseat_stagings.open(&key, &key);
        receiver
            .named_groups
            .staging_write()
            .await
            .insert(key.clone(), staged);
        receiver
            .reseat_stagings
            .run_in_staging_of(&key, sync_after_save(&receiver))
            .await;
        let after = crate::w3h_inline::fs::read(path(dir.path()))
            .await
            .expect("the sidecar survives the staging-scope save");
        assert_eq!(
            durable, after,
            "a staging-scope save projects the live map, not the staging slot"
        );
        assert!(
            decode(&after)
                .expect("decode")
                .get(&key)
                .is_some_and(|entries| entries.contains_key(&digest)),
            "the live group's evidence is still durable"
        );
        receiver.agent.shutdown().await;
    }
}
