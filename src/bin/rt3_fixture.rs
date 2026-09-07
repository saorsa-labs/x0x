//! Typed fixture/witness for the #491 RT3 restart-hydration diagnostic.
//!
//! This diagnostic binary reads the same public x0x types used by the daemon.
//! It never starts networking and never prints certificate or key bytes.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use x0x::announce_blob::CachedBlob;
use x0x::groups::GroupInfo;

#[derive(Debug, Serialize)]
struct WitnessReceipt {
    group_id: String,
    remote_agent_id: String,
    owner_user_id: String,
    roster_root: String,
    state_hash: String,
    matching_cache_entries: usize,
    certificate_present: bool,
    certificate_digest_present: bool,
    state_hash_current: bool,
}

fn normalize_hex(label: &str, value: &str) -> Result<String> {
    let normalized = value.to_ascii_lowercase();
    let bytes = hex::decode(&normalized).with_context(|| format!("{label} is not hex"))?;
    if bytes.len() != 32 {
        bail!("{label} must encode exactly 32 bytes");
    }
    Ok(normalized)
}

fn load_groups(path: &Path) -> Result<HashMap<String, GroupInfo>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("cannot read sidecar {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("cannot decode sidecar {}", path.display()))
}

fn find_group_mut<'a>(
    groups: &'a mut HashMap<String, GroupInfo>,
    group_id: &str,
) -> Result<&'a mut GroupInfo> {
    groups
        .get_mut(group_id)
        .with_context(|| format!("group {group_id} is absent from authoritative sidecar"))
}

fn find_group<'a>(groups: &'a HashMap<String, GroupInfo>, group_id: &str) -> Result<&'a GroupInfo> {
    groups
        .get(group_id)
        .with_context(|| format!("group {group_id} is absent from authoritative sidecar"))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no UTF-8 file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.rt3-new"));
    std::fs::write(&temporary, bytes)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("cannot replace {}", path.display()))
}

fn witness(
    cache_path: &Path,
    sidecar_path: &Path,
    group_id: &str,
    remote_agent: &str,
    owner_user: &str,
) -> Result<WitnessReceipt> {
    let remote_agent = normalize_hex("remote agent id", remote_agent)?;
    let owner_user = normalize_hex("owner user id", owner_user)?;
    let groups = load_groups(sidecar_path)?;
    let info = find_group(&groups, group_id)?;
    if !info.state_hash_is_current() {
        bail!("authoritative group state hash is not current");
    }
    let member = info
        .members_v2
        .get(&remote_agent)
        .context("remote member is absent from authoritative roster")?;
    if !member.is_active() {
        bail!("remote member is not active");
    }
    let committed_digest = member
        .certificate_digest
        .as_deref()
        .context("remote member has no committed certificate digest")?;
    let cache_bytes = std::fs::read(cache_path)
        .with_context(|| format!("cannot read cache {}", cache_path.display()))?;
    let blobs: Vec<CachedBlob> = bincode::deserialize(&cache_bytes)
        .with_context(|| format!("cannot decode cache {}", cache_path.display()))?;
    let matching = blobs
        .iter()
        .filter(|blob| {
            let Some(cert) = blob.agent_certificate.as_ref() else {
                return false;
            };
            cert.verify().is_ok()
                && cert
                    .agent_id()
                    .is_ok_and(|id| hex::encode(id.as_bytes()) == remote_agent)
                && cert
                    .user_id()
                    .is_ok_and(|id| hex::encode(id.as_bytes()) == owner_user)
                && blob
                    .user_id
                    .is_some_and(|id| hex::encode(id.as_bytes()) == owner_user)
                && x0x::groups::owner_cert::certificate_digest_hex(cert) == committed_digest
        })
        .count();
    if matching != 1 {
        bail!("expected exactly one verified cache entry for remote seat, found {matching}");
    }
    Ok(WitnessReceipt {
        group_id: group_id.to_string(),
        remote_agent_id: remote_agent,
        owner_user_id: owner_user,
        roster_root: x0x::groups::compute_roster_root(&info.members_v2),
        state_hash: info.state_hash.clone(),
        matching_cache_entries: matching,
        certificate_present: member.certificate.is_some(),
        certificate_digest_present: true,
        state_hash_current: true,
    })
}

fn strip_certificate(sidecar_path: &Path, group_id: &str, remote_agent: &str) -> Result<()> {
    let remote_agent = normalize_hex("remote agent id", remote_agent)?;
    let mut groups = load_groups(sidecar_path)?;
    let info = find_group_mut(&mut groups, group_id)?;
    if !info.state_hash_is_current() {
        bail!("pre-strip group state hash is not current");
    }
    let before_root = x0x::groups::compute_roster_root(&info.members_v2);
    let before_hash = info.state_hash.clone();
    let member = info
        .members_v2
        .get_mut(&remote_agent)
        .context("remote member is absent from authoritative roster")?;
    if !member.is_active() {
        bail!("remote member is not active");
    }
    let cert = member
        .certificate
        .take()
        .context("remote member certificate bytes are already absent")?;
    let committed = member
        .certificate_digest
        .as_deref()
        .context("remote member has no committed certificate digest")?;
    let actual = x0x::groups::owner_cert::certificate_digest_hex(&cert);
    if committed != actual {
        bail!("remote certificate bytes contradict the committed digest");
    }
    let after_root = x0x::groups::compute_roster_root(&info.members_v2);
    if after_root != before_root {
        bail!("certificate stripping changed the signed roster root");
    }
    if info.state_hash != before_hash || !info.state_hash_is_current() {
        bail!("certificate stripping changed or invalidated the signed state hash");
    }
    let encoded = serde_json::to_vec(&groups).context("cannot encode authoritative sidecar")?;
    atomic_write(sidecar_path, &encoded)
}

fn state_check(
    sidecar_path: &Path,
    group_id: &str,
    remote_agent: &str,
    expected: &str,
) -> Result<WitnessReceipt> {
    let remote_agent = normalize_hex("remote agent id", remote_agent)?;
    let groups = load_groups(sidecar_path)?;
    let info = find_group(&groups, group_id)?;
    if !info.state_hash_is_current() {
        bail!("authoritative group state hash is not current");
    }
    let member = info
        .members_v2
        .get(&remote_agent)
        .context("remote member is absent from authoritative roster")?;
    if !member.is_active() {
        bail!("remote member is not active");
    }
    let certificate_present = member.certificate.is_some();
    let certificate_digest_present = member.certificate_digest.is_some();
    match expected {
        "byte-bearing" if certificate_present && certificate_digest_present => {}
        "digest-only" if !certificate_present && certificate_digest_present => {}
        "byte-bearing" | "digest-only" => {
            bail!("remote member does not have expected certificate shape {expected}")
        }
        _ => bail!("expected shape must be byte-bearing or digest-only"),
    }
    Ok(WitnessReceipt {
        group_id: group_id.to_string(),
        remote_agent_id: remote_agent,
        owner_user_id: String::new(),
        roster_root: x0x::groups::compute_roster_root(&info.members_v2),
        state_hash: info.state_hash.clone(),
        matching_cache_entries: 0,
        certificate_present,
        certificate_digest_present,
        state_hash_current: true,
    })
}

fn exact_args(args: &[String], count: usize, usage: &str) -> Result<()> {
    if args.len() != count {
        bail!("usage: {usage}");
    }
    Ok(())
}

fn run(args: &[String]) -> Result<WitnessReceipt> {
    let Some(command) = args.first().map(String::as_str) else {
        bail!("usage: rt3_fixture <cache-check|strip-cert|state-check> ...");
    };
    match command {
        "cache-check" => {
            exact_args(
                args,
                6,
                "rt3_fixture cache-check CACHE SIDECAR GROUP REMOTE_AGENT OWNER_USER",
            )?;
            witness(
                Path::new(&args[1]),
                Path::new(&args[2]),
                &args[3],
                &args[4],
                &args[5],
            )
        }
        "strip-cert" => {
            exact_args(args, 4, "rt3_fixture strip-cert SIDECAR GROUP REMOTE_AGENT")?;
            strip_certificate(Path::new(&args[1]), &args[2], &args[3])?;
            state_check(Path::new(&args[1]), &args[2], &args[3], "digest-only")
        }
        "state-check" => {
            exact_args(
                args,
                5,
                "rt3_fixture state-check SIDECAR GROUP REMOTE_AGENT SHAPE",
            )?;
            state_check(Path::new(&args[1]), &args[2], &args[3], &args[4])
        }
        _ => bail!("unknown command {command}"),
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(receipt) => match serde_json::to_string(&receipt) {
            Ok(json) => {
                println!("{json}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: cannot encode receipt: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x0x::groups::{GroupAdmission, GroupPolicyPreset};
    use x0x::identity::{AgentCertificate, AgentKeypair, UserKeypair};

    fn fixture() -> Result<(
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
        String,
        String,
    )> {
        let root = tempfile::tempdir()?;
        let sidecar = root.path().join("home-suite-groups.json");
        let cache = root.path().join("announce-blob-cache.bin");
        let owner = UserKeypair::generate()?;
        let remote = AgentKeypair::generate()?;
        let cert = AgentCertificate::issue(&owner, &remote)?;
        let remote_hex = hex::encode(remote.agent_id().as_bytes());
        let owner_hex = hex::encode(owner.user_id().as_bytes());
        let group_id = "ab".repeat(32);
        let mut policy = GroupPolicyPreset::PrivateSecure.to_policy();
        policy.admission = GroupAdmission::OwnerCertified(owner.user_id());
        let creator = AgentKeypair::generate()?;
        let mut info = GroupInfo::with_policy(
            "rt3".to_string(),
            String::new(),
            creator.agent_id(),
            group_id.clone(),
            policy,
        );
        info.add_member(
            remote_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info.set_member_certificate(&remote_hex, cert.clone())
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        info.recompute_state_hash();
        let mut groups = HashMap::new();
        groups.insert(group_id.clone(), info);
        std::fs::write(&sidecar, serde_json::to_vec(&groups)?)?;
        let blob = CachedBlob {
            digest: x0x::announce_v3::cert_digest(&Some(owner.user_id()), &Some(cert.clone())),
            payload_version: 1,
            user_id: Some(owner.user_id()),
            agent_certificate: Some(cert),
            fetched_at_unix: 1,
        };
        std::fs::write(&cache, bincode::serialize(&vec![blob])?)?;
        Ok((root, sidecar, cache, group_id, remote_hex, owner_hex))
    }

    #[test]
    fn verified_cache_and_strip_preserve_signed_state() -> Result<()> {
        let (_root, sidecar, cache, group, remote, owner) = fixture()?;
        let before = witness(&cache, &sidecar, &group, &remote, &owner)?;
        assert!(before.certificate_present);
        strip_certificate(&sidecar, &group, &remote)?;
        let after = state_check(&sidecar, &group, &remote, "digest-only")?;
        assert_eq!(after.roster_root, before.roster_root);
        assert_eq!(after.state_hash, before.state_hash);
        let cached = witness(&cache, &sidecar, &group, &remote, &owner)?;
        assert!(!cached.certificate_present);
        assert_eq!(cached.matching_cache_entries, 1);
        Ok(())
    }

    #[test]
    fn cache_binding_mismatch_fails_closed() -> Result<()> {
        let (_root, sidecar, cache, group, remote, _owner) = fixture()?;
        let wrong_owner = "cd".repeat(32);
        let error = witness(&cache, &sidecar, &group, &remote, &wrong_owner)
            .expect_err("wrong owner must fail");
        assert!(error.to_string().contains("expected exactly one"));
        Ok(())
    }

    #[test]
    fn strip_refuses_absent_bytes_and_bad_shape() -> Result<()> {
        let (_root, sidecar, _cache, group, remote, _owner) = fixture()?;
        strip_certificate(&sidecar, &group, &remote)?;
        assert!(strip_certificate(&sidecar, &group, &remote).is_err());
        assert!(state_check(&sidecar, &group, &remote, "byte-bearing").is_err());
        Ok(())
    }
}
