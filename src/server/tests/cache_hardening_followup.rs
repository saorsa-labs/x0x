use super::*;

struct TreeKemCacheWriterHookGuard {
    path: PathBuf,
}

impl Drop for TreeKemCacheWriterHookGuard {
    fn drop(&mut self) {
        if let Ok(mut hooks) = TREEKEM_CACHE_WRITER_HOOKS.lock() {
            hooks.remove(&self.path);
        }
    }
}

#[tokio::test]
async fn recovery_cache_duplicates_upgrade_once_and_keep_newest_authority() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xa9, 0xaa).await?;
    let raw = without_recovery_attestation(fixture.event.clone());
    let key = join_result_key(&fixture.group_id, &fixture.member_hex);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("canonical-recovery.json");
    let (cache, _) =
        TreeKemMemberKeyPackageCache::from_entries(path.clone(), BTreeMap::new(), false)?;

    cache.insert(key.clone(), raw.clone(), false).await?;
    let provisional_revision = cache.diagnostics().await.revision;
    cache.insert(key.clone(), raw.clone(), false).await?;
    let after_provisional_retry = cache.diagnostics().await;
    assert_eq!(after_provisional_retry.entries, 1);
    assert_eq!(after_provisional_retry.revision, provisional_revision);

    cache
        .insert(key.clone(), fixture.event.clone(), true)
        .await?;
    let authoritative_revision = cache.diagnostics().await.revision;
    assert_eq!(
        authoritative_revision,
        provisional_revision.saturating_add(1)
    );

    let mut authority_info = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .expect("fixture group exists")
        .clone();
    authority_info.security_binding =
        treekem_recovery_security_binding(authority_info.secret_epoch, &raw);
    let _ = authority_info.seal_commit(
        fixture.state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )?;
    authority_info.security_binding =
        treekem_recovery_security_binding(authority_info.secret_epoch, &raw);
    let newer_commit = authority_info.seal_commit(
        fixture.state.agent.identity().agent_keypair(),
        now_millis_u64().saturating_add(1),
    )?;
    let newer = attest_member_joined_recovery_event(
        &raw,
        fixture.state.agent.identity().agent_keypair(),
        &newer_commit,
    )?;
    cache.insert(key.clone(), newer.clone(), true).await?;
    let newest_revision = cache.diagnostics().await.revision;
    assert_eq!(newest_revision, authoritative_revision.saturating_add(1));

    cache
        .insert(key.clone(), fixture.event.clone(), true)
        .await?;
    cache.insert(key.clone(), newer.clone(), true).await?;
    let after_retries = cache.diagnostics().await;
    assert_eq!(after_retries.entries, 1);
    assert_eq!(after_retries.revision, newest_revision);
    let retained = cache.get(&key).await.expect("canonical recovery retained");
    assert_eq!(
        recovery_attestation_revision(&retained),
        Some(newer_commit.revision),
        "stale and duplicate deliveries cannot displace the newest authority attestation"
    );
    assert_eq!(durable_cache_keys(&path).await?, HashSet::from([key]));
    assert!(after_retries.entries <= after_retries.max_entries);
    assert!(after_retries.encoded_bytes <= after_retries.max_encoded_bytes);
    Ok(())
}

/// Codex blocker: an authority-attested `MemberJoined` recovery record is
/// only valid when its authority commit is *exactly retained* in the live
/// `GroupInfo.commit_log`. A signed, structurally valid commit the accepted
/// chain never retained must fail full verification; the same commit, once
/// admitted to `commit_log`, must pass.
#[tokio::test]
async fn recovery_attestation_rejects_authority_commit_absent_from_commit_log() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xc1, 0xc2).await?;
    let inviter = fixture.state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let authority_kp = fixture.state.agent.identity().agent_keypair();
    let group_id = fixture.group_id.clone();
    let stable_group_id = fixture.stable_group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let raw = without_recovery_attestation(fixture.event.clone());
    let kp_b64 = match &raw {
        NamedGroupMetadataEvent::MemberJoined {
            treekem_key_package_b64: Some(kp),
            ..
        } => kp.clone(),
        _ => unreachable!("fixture event carries a TreeKEM key package"),
    };

    // Live roster where the joining member is active with the matching
    // package, so every verifier clause except `commit_log` membership holds.
    let mut info = treekem_metadata_group_info(inviter, &group_id, &stable_group_id);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(inviter_hex.clone()),
        None,
    );
    info.set_member_treekem_key_package(&member_hex, kp_b64);
    info.secret_epoch = fixture.initial_epoch.saturating_add(1);
    info.security_binding = treekem_recovery_security_binding(info.secret_epoch, &raw);
    info.recompute_state_hash();

    // Mint a fully signed authority commit on a clone so the live `info`
    // never retains it in `commit_log`.
    let mut minter = info.clone();
    let signed_commit = minter.seal_commit(authority_kp, now_millis_u64())?;
    let retained = minter
        .commit_log
        .last()
        .cloned()
        .expect("seal_commit retains the authored commit");
    assert_eq!(retained.commit, signed_commit);
    assert!(
        info.commit_log
            .iter()
            .all(|entry| entry.commit != signed_commit),
        "precondition: live commit_log does not yet retain the signed commit"
    );

    let absent = attest_member_joined_recovery_event(&raw, authority_kp, &signed_commit)?;
    assert!(
        !verify_authority_attested_member_joined_recovery(&info, &absent),
        "a signed authority commit absent from commit_log must be rejected"
    );

    // Admit the exact same signed commit into the accepted chain; the only
    // failing clause clears and the record verifies.
    info.commit_log.push(retained);
    let admitted = attest_member_joined_recovery_event(&raw, authority_kp, &signed_commit)?;
    assert!(
        verify_authority_attested_member_joined_recovery(&info, &admitted),
        "the same commit, once retained in commit_log, verifies"
    );
    Ok(())
}

/// Codex blocker: when a live group canonicalizes cache keys to its stable
/// id, two authority-attested recovery records for the same logical
/// group/member delivered under different signed MLS aliases collapse to a
/// single canonical durable entry, and catch-up lookup across aliases
/// selects the highest accepted authority revision rather than first-alias
/// arrival order.
#[tokio::test]
async fn canonical_alias_records_collapse_and_keep_highest_authority_revision() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xd1, 0xd2).await?;
    let state = &fixture.state;
    let stable_group_id = fixture.stable_group_id.clone();
    let authority_kp = state.agent.identity().agent_keypair();
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member_hex = hex::encode(member_kp.agent_id().as_bytes());
    let canonical_key = join_result_key(&stable_group_id, &member_hex);

    // Build a member-signed `MemberJoined` under a given MLS alias and
    // countersign it with an authority commit of a chosen revision. Each
    // alias shares the stable id, so both collapse to one canonical key.
    fn attest_alias_for_member(
        member_kp: &x0x::identity::AgentKeypair,
        authority_kp: &x0x::identity::AgentKeypair,
        alias_group_id: &str,
        stable_group_id: &str,
        inviter_hex: &str,
        epoch: u64,
    ) -> Result<NamedGroupMetadataEvent> {
        let member_id = member_kp.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_pub_b64 = BASE64.encode(member_kp.public_key().as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[epoch as u8; 32])?;
        let kp_b64 = BASE64.encode(prepared.key_package_bytes());
        let invite_secret = format!("alias-{alias_group_id}-e{epoch}");
        let now_ms = 10_000 + epoch;
        let canonical = canonical_member_joined_bytes(
            alias_group_id,
            Some(stable_group_id),
            &member_hex,
            &member_pub_b64,
            x0x::groups::GroupRole::Member,
            None,
            inviter_hex,
            &invite_secret,
            now_ms,
            Some(&kp_b64),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            member_kp.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign alias member event: {e:?}"))?;
        let raw = NamedGroupMetadataEvent::MemberJoined {
            group_id: alias_group_id.to_string(),
            stable_group_id: Some(stable_group_id.to_string()),
            member_agent_id: member_hex,
            member_public_key_b64: member_pub_b64,
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_hex.to_string(),
            invite_secret,
            ts_ms: now_ms,
            treekem_key_package_b64: Some(kp_b64),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        let mut info =
            treekem_metadata_group_info(authority_kp.agent_id(), alias_group_id, stable_group_id);
        info.state_revision = epoch;
        info.secret_epoch = epoch;
        info.security_binding = treekem_recovery_security_binding(epoch, &raw);
        info.recompute_state_hash();
        let commit = info.seal_commit(authority_kp, now_ms)?;
        attest_member_joined_recovery_event(&raw, authority_kp, &commit)
    }

    let alias_a = "da".repeat(32);
    let alias_b = "db".repeat(32);
    // The higher revision arrives FIRST under alias_b; a lower revision
    // under alias_a arrives second. Highest-revision-wins must keep it.
    let higher = attest_alias_for_member(
        &member_kp,
        authority_kp,
        &alias_b,
        &stable_group_id,
        &inviter_hex,
        22,
    )?;
    let lower = attest_alias_for_member(
        &member_kp,
        authority_kp,
        &alias_a,
        &stable_group_id,
        &inviter_hex,
        11,
    )?;
    let higher_rev = recovery_attestation_revision(&higher).expect("attested");
    let lower_rev = recovery_attestation_revision(&lower).expect("attested");
    assert!(higher_rev > lower_rev);

    let first = cache_treekem_member_key_package(
        state,
        join_result_key(&alias_b, &member_hex),
        higher.clone(),
        true,
    )
    .await;
    assert!(matches!(
        first,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    let second = cache_treekem_member_key_package(
        state,
        join_result_key(&alias_a, &member_hex),
        lower.clone(),
        true,
    )
    .await;
    assert!(matches!(
        second,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));

    let diagnostics = state.treekem_member_key_packages.diagnostics().await;
    assert_eq!(
        diagnostics.entries, 1,
        "two alias records collapsed to one canonical entry"
    );
    assert_eq!(
        durable_cache_keys(&state.treekem_member_key_packages.path).await?,
        HashSet::from([canonical_key.clone()]),
        "exactly one canonical durable key; no alias keys leaked"
    );

    let catchup = state
        .treekem_member_key_packages
        .find_for_member(&[alias_b, alias_a, stable_group_id.clone()], &member_hex)
        .await
        .expect("catch-up lookup resolves the collapsed canonical record");
    assert_eq!(
        recovery_attestation_revision(&catchup),
        Some(higher_rev),
        "highest authority revision wins, not first-alias arrival order"
    );
    Ok(())
}

/// Codex blocker: the per-group provisional cap cannot be bypassed by
/// minting alternate signed stable aliases. With live-group
/// canonicalization, every alias provisional record collapses onto the one
/// canonical stable group, so the cap is enforced across all of them.
#[tokio::test]
async fn canonical_cache_key_prevents_provisional_cap_bypass_via_stable_aliases() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xd3, 0xd4).await?;
    let state = &fixture.state;
    let stable_group_id = fixture.stable_group_id.clone();
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let canonical_prefix = format!("{stable_group_id}:");

    // Each provisional record uses a distinct member under a distinct MLS
    // alias group id, but all share the same stable id. Without
    // canonicalization each alias would form its own provisional group.
    let overflow = 3;
    let total = TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP + overflow;
    for sequence in 1..=total {
        let alias = format!("{sequence:02x}").repeat(32);
        let (key, event) = signed_provisional_recovery_event_for_test(
            &alias,
            &stable_group_id,
            &inviter_hex,
            sequence as u64,
        )?;
        let status = cache_treekem_member_key_package(state, key, event, false).await;
        assert!(
            matches!(status, TreeKemCachePersistenceStatus::Durable { .. }),
            "alias provisional record admitted"
        );
    }

    let provisional = state
        .treekem_member_key_packages
        .events_matching(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberJoined {
                    recovery_authority_signature_b64: None,
                    ..
                }
            ) && recovery_cache_group_identity(event) == stable_group_id
        })
        .await;
    assert_eq!(
        provisional.len(),
        TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP,
        "alternate stable aliases cannot bypass the per-group provisional cap"
    );

    let durable = durable_cache_keys(&state.treekem_member_key_packages.path).await?;
    assert_eq!(
        durable.len(),
        TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP,
        "canonical compaction is durable"
    );
    assert!(
        durable.iter().all(|key| key.starts_with(&canonical_prefix)),
        "no non-canonical alias durable keys survive canonicalization"
    );
    Ok(())
}

// ---------------------------------------------------------------------
// TreeKEM member key-package cache: loader quarantine, bounds, and
// lifecycle regression coverage (WP-TK2 findings 3-6).
//
// `synthetic_member_joined` builds deliberately NON-verifying
// `MemberJoined` events used only to size the cache via `from_entries`,
// which enforces count/byte bounds without signature verification. Tests
// that exercise the load path or `insert()` use real signed
// `member_joined_treekem_fixture` events, since those paths authenticate
// the member signature.
// ---------------------------------------------------------------------

/// Compact, deliberately NON-verifying `MemberJoined` for cache *sizing*
/// tests. `from_entries` never calls `verify_member_joined_key_package_event`,
/// so these events exist purely to control entry count, `ts_ms` ordering,
/// and encoded byte size. Must never be passed to `insert()`.
fn synthetic_member_joined(
    group_id: &str,
    member: &str,
    ts_ms: u64,
    key_package_payload_len: usize,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.to_string(),
        stable_group_id: Some(group_id.to_string()),
        member_agent_id: member.to_string(),
        member_public_key_b64: BASE64.encode([0xA5u8; 48]),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: format!("inviter-{group_id}"),
        invite_secret: format!("invite-{group_id}-{member}"),
        ts_ms,
        treekem_key_package_b64: Some(BASE64.encode(vec![0xA5u8; key_package_payload_len])),
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: BASE64.encode([0xA5u8; 64]),
    }
}

/// Locate the `<base>.corrupt-<uuid>` quarantine sibling written when the
/// loader quarantines an unparseable cache file.
async fn quarantine_sibling(dir: &FsPath, base: &str) -> Option<PathBuf> {
    let prefix = format!("{base}.corrupt-");
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(entry)) = rd.next_entry().await {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            return Some(entry.path());
        }
    }
    None
}

/// WP-TK2: an unparseable or schema-incompatible recovery cache must NOT
/// abort startup or overwrite the corrupt bytes. The loader renames the
/// file to a quarantine sibling (preserving it verbatim) and starts from
/// an empty cache, rewriting the active path as `{}`.
#[tokio::test]
async fn treekem_recovery_cache_quarantines_corrupt_json_without_overwrite() -> Result<()> {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("malformed JSON", b"{not valid json".to_vec()),
        ("truncated JSON", b"{\"g:m\":".to_vec()),
        ("schema-incompatible value", b"{\"g:m\":123}".to_vec()),
        ("JSON array (not object)", b"[]".to_vec()),
    ];
    let empty_roster: HashMap<String, x0x::groups::GroupInfo> = HashMap::new();

    for (label, corpus) in &cases {
        let dir = tempfile::tempdir()?;
        let base = "member-key-packages.json";
        let path = dir.path().join(base);
        tokio::fs::write(&path, corpus.as_slice()).await?;

        let cache = load_treekem_member_key_packages(&path, &empty_roster)
            .await
            .expect("corrupt cache quarantines and loads empty, not a fatal startup error");

        assert_eq!(
            cache.diagnostics().await.entries,
            0,
            "{label}: in-memory cache empty after quarantine"
        );

        // Original corrupt bytes are preserved verbatim in a quarantine
        // sibling (rename, not overwrite).
        let quarantine = quarantine_sibling(dir.path(), base)
            .await
            .unwrap_or_else(|| panic!("{label}: quarantine sibling exists"));
        let preserved = tokio::fs::read(&quarantine).await?;
        assert_eq!(
            preserved, *corpus,
            "{label}: quarantine preserves the original corrupt bytes verbatim"
        );

        // The active path is rewritten as an empty cache (no corrupt residue).
        assert!(
            durable_cache_keys(&path).await?.is_empty(),
            "{label}: active path rewritten as an empty cache"
        );
    }
    Ok(())
}

/// WP-TK2: a read error other than `NotFound` (here: the path is a
/// directory, so `read_to_string` fails with EISDIR) is fatal — the loader
/// surfaces the error and must NOT quarantine or silently start empty.
#[tokio::test]
async fn treekem_recovery_cache_non_notfound_read_error_is_fatal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("unreadable.json");
    // A directory exists but cannot be read as a file -> error kind != NotFound.
    tokio::fs::create_dir(&path).await?;

    let empty_roster: HashMap<String, x0x::groups::GroupInfo> = HashMap::new();
    let result = load_treekem_member_key_packages(&path, &empty_roster).await;
    assert!(
        result.is_err(),
        "non-NotFound read error must be fatal, not quarantined to empty"
    );

    // The fatal branch neither quarantines (renames) nor touches the path.
    let metadata = tokio::fs::metadata(&path)
        .await
        .expect("path still present");
    assert!(
        metadata.is_dir(),
        "unreadable directory left in place, not quarantined"
    );
    Ok(())
}

/// Rebasing TK1 witness recovery with TK2 startup pruning: a valid
/// provisional witness record is pruned when its group no longer exists,
/// but retained for a live non-withdrawn group even before the target is in
/// that witness's roster. Authority-attested records are separately gated
/// by the committed active-member incarnation.
#[tokio::test]
async fn treekem_recovery_cache_startup_prunes_roster_irrelevant_signed_records() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x91, 0x92).await?;
    let group_id = fixture.group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let key = join_result_key(&group_id, &member_hex);
    let provisional = without_recovery_attestation(fixture.event.clone());
    let persisted: BTreeMap<String, NamedGroupMetadataEvent> =
        [(key.clone(), provisional)].into_iter().collect();
    let json = serde_json::to_string(&persisted)?;

    // Case A: no live group -> validly signed witness record is pruned.
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("kp.json");
        tokio::fs::write(&path, &json).await?;
        let empty_roster: HashMap<String, x0x::groups::GroupInfo> = HashMap::new();

        let cache = load_treekem_member_key_packages(&path, &empty_roster).await?;
        assert_eq!(
            cache.diagnostics().await.entries,
            0,
            "group-irrelevant witness record pruned from memory"
        );
        assert!(
            cache.get(&key).await.is_none(),
            "pruned record absent from memory"
        );
        assert!(
            durable_cache_keys(&path).await?.is_empty(),
            "durable JSON rewritten empty after startup prune"
        );
    }

    // Case B: the group remains live, so independently retained witness
    // evidence survives restart without requiring target admission first.
    {
        let inviter = fixture.state.agent.agent_id();
        let roster_kp = match &fixture.event {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp),
                ..
            } => kp.clone(),
            _ => unreachable!("fixture event is MemberJoined with a key package"),
        };
        let mut info = treekem_metadata_group_info(inviter, &group_id, &fixture.stable_group_id);
        let mut member = x0x::groups::GroupMember::new_member(
            member_hex.clone(),
            None,
            Some(hex::encode(inviter.as_bytes())),
            1,
        );
        member.treekem_key_package_b64 = Some(roster_kp);
        info.members_v2.insert(member_hex.clone(), member);
        let roster: HashMap<String, x0x::groups::GroupInfo> =
            [(group_id.clone(), info)].into_iter().collect();

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("kp.json");
        tokio::fs::write(&path, &json).await?;

        let cache = load_treekem_member_key_packages(&path, &roster).await?;
        assert_eq!(
            cache.diagnostics().await.entries,
            1,
            "live-group witness record retained"
        );
        assert!(
            cache.get(&key).await.is_some(),
            "retained record present in memory"
        );
        let canonical_key = join_result_key(&fixture.stable_group_id, &member_hex);
        let durable_keys_after_load = durable_cache_keys(&path).await?;
        assert!(
            durable_keys_after_load.contains(&canonical_key),
            "loader rewrites the persisted record under the canonical stable group key"
        );
        assert!(
            !durable_keys_after_load.contains(&key),
            "legacy MLS-alias durable key dropped after the canonicalizing rewrite"
        );
    }
    Ok(())
}

/// WP-TK2: group/member lifecycle removals must evict both the in-memory
/// entry and the durable JSON record. `remove_groups` covers the
/// group-deletion lifecycle; `remove_member` covers per-member removal.
#[tokio::test]
async fn treekem_recovery_cache_lifecycle_prune_removes_memory_and_durable() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x93, 0x94).await?;
    let group_id = fixture.group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let key = join_result_key(&group_id, &member_hex);
    let aliases = HashSet::from([group_id.clone()]);

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, _) = TreeKemMemberKeyPackageCache::from_entries(path, BTreeMap::new(), false)?;

    // Group lifecycle: remove_groups drops memory + durable JSON.
    cache
        .insert(key.clone(), fixture.event.clone(), true)
        .await?;
    assert_eq!(cache.diagnostics().await.entries, 1, "seeded one record");
    let removed_groups = cache.remove_groups(&aliases).await;
    assert_eq!(
        removed_groups.evicted, 1,
        "group lifecycle pruned the record"
    );
    assert!(
        cache.get(&key).await.is_none(),
        "group prune cleared memory"
    );
    assert!(
        durable_cache_keys(&cache.path).await?.is_empty(),
        "group prune cleared durable JSON"
    );

    // Member lifecycle: remove_member drops memory + durable JSON.
    cache
        .insert(key.clone(), fixture.event.clone(), true)
        .await?;
    assert!(
        cache.get(&key).await.is_some(),
        "re-seeded before member prune"
    );
    let removed_member = cache.remove_member(&aliases, &member_hex).await;
    assert_eq!(
        removed_member.evicted, 1,
        "member lifecycle pruned the record"
    );
    assert!(
        cache.get(&key).await.is_none(),
        "member prune cleared memory"
    );
    assert!(
        cache
            .find_for_member(std::slice::from_ref(&group_id), &member_hex)
            .await
            .is_none(),
        "member prune cleared find_for_member"
    );
    assert!(
        durable_cache_keys(&cache.path).await?.is_empty(),
        "member prune cleared durable JSON"
    );
    Ok(())
}

/// PR #219 review finding #4: the shared retained-tombstone path used by
/// GroupDeleted/withdraw/import must prune signed recovery records only
/// after terminal state commits. Seed an authenticated cache record, then
/// exercise the real signed GroupDeleted production apply path.
#[tokio::test]
async fn group_deleted_tombstone_prunes_recovery_cache_memory_and_disk() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xb1, 0xb2).await?;
    let state = &fixture.state;
    let cache_key = join_result_key(&fixture.group_id, &fixture.member_hex);

    state
        .treekem_member_key_packages
        .insert(cache_key.clone(), fixture.event.clone(), true)
        .await?;
    assert!(
        state
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .is_some(),
        "precondition: authority-attested recovery record seeded"
    );
    assert!(
        durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&cache_key),
        "precondition: signed recovery record is durable before terminality"
    );

    let parent = state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .expect("fixture group retained after MemberJoined")
        .clone();
    let mut terminal = parent.clone();
    terminal.withdrawn = true;
    let commit = sign_metadata_terminality_commit(&parent, &terminal, state, 1_000);
    assert!(commit.withdrawn);
    let event = NamedGroupMetadataEvent::GroupDeleted {
        group_id: fixture.stable_group_id.clone(),
        revision: parent.roster_revision.saturating_add(1),
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        commit: Some(commit),
    };

    let applied =
        apply_named_group_metadata_event_inner(state, event, state.agent.agent_id(), true, true)
            .await;
    assert!(
        applied,
        "GroupDeleted committed through the production apply path"
    );
    {
        let groups = state.named_groups.read().await;
        let tombstone = groups
            .get(&fixture.group_id)
            .expect("terminal tombstone retained under storage alias");
        assert!(
            tombstone.withdrawn,
            "terminal state committed before cache pruning"
        );
        assert_eq!(tombstone.shared_secret, None);
    }
    assert!(
        state
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .is_none(),
        "GroupDeleted tombstone pruned the in-memory signed recovery record"
    );
    assert!(
        !durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&cache_key),
        "GroupDeleted tombstone pruned the durable signed recovery record"
    );
    Ok(())
}

#[tokio::test]
async fn group_deleted_tombstone_prunes_independent_witness_memory_and_disk() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xb5, 0xb6).await?;
    let (witness, _witness_dir) = secure_endpoint_test_state().await?;
    add_active_witness_to_treekem_fixture(&fixture, &witness).await?;
    let raw = without_recovery_attestation(fixture.event.clone());
    let cache_key = join_result_key(&fixture.group_id, &fixture.member_hex);
    assert!(
        !apply_named_group_metadata_event(&witness, raw, fixture.member_id, true).await,
        "independent witness retains without authoring membership"
    );
    assert!(witness
        .treekem_member_key_packages
        .get(&cache_key)
        .await
        .is_some());
    let canonical_key = join_result_key(&fixture.stable_group_id, &fixture.member_hex);
    let durable = durable_cache_keys(&witness.treekem_member_key_packages.path).await?;
    assert!(
        durable.contains(&canonical_key),
        "witness retains the canonical stable durable recovery record"
    );
    if canonical_key != cache_key {
        assert!(
            !durable.contains(&cache_key),
            "legacy MLS alias durable key is not retained post-canonicalization"
        );
    }

    let parent = witness
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .expect("witness group exists")
        .clone();
    let mut terminal = parent.clone();
    terminal.withdrawn = true;
    let commit = sign_metadata_terminality_commit(&parent, &terminal, &fixture.state, 2_000);
    let authority = fixture.state.agent.agent_id();
    let event = NamedGroupMetadataEvent::GroupDeleted {
        group_id: fixture.stable_group_id.clone(),
        revision: parent.roster_revision.saturating_add(1),
        actor: hex::encode(authority.as_bytes()),
        commit: Some(commit),
    };
    assert!(
        apply_named_group_metadata_event_inner(&witness, event, authority, true, true).await,
        "signed GroupDeleted commits on the independent witness"
    );
    assert!(witness
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .is_some_and(|info| info.withdrawn));
    assert!(
        witness
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .is_none(),
        "shared tombstone path prunes witness memory"
    );
    assert!(
        !durable_cache_keys(&witness.treekem_member_key_packages.path)
            .await?
            .contains(&cache_key),
        "shared tombstone path prunes witness durability"
    );
    Ok(())
}

/// Codex blocker: TreeKEM active-leave and local-only group-drop must prune
/// the recovery cache across ALL aliases of the stable group. Because
/// records are canonicalized to the stable id, pruning by the MLS alias
/// (the only id the leave/drop handlers hold) still evicts the canonical
/// memory entry and rewrites the durable JSON.
#[tokio::test]
async fn treekem_leave_and_drop_prune_canonical_cache_across_aliases() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xe1, 0xe2).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    let stable_group_id = fixture.stable_group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let canonical_key = join_result_key(&stable_group_id, &member_hex);

    let seed = cache_treekem_member_key_package(
        state,
        join_result_key(&group_id, &member_hex),
        fixture.event.clone(),
        true,
    )
    .await;
    assert!(matches!(
        seed,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    assert!(
        durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&canonical_key),
        "precondition: record canonicalized to the stable durable key"
    );
    assert_eq!(
        state
            .treekem_member_key_packages
            .diagnostics()
            .await
            .entries,
        1,
        "precondition: one canonical record seeded"
    );

    // Active leave: the production member-prune helper is invoked with the
    // MLS alias only; it expands to the full alias set and evicts the
    // canonical record from memory and durability.
    let leave = prune_treekem_cache_member(state, &group_id, &member_hex, "active_leave").await;
    assert!(matches!(
        leave,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    assert_eq!(
        state
            .treekem_member_key_packages
            .diagnostics()
            .await
            .entries,
        0,
        "active leave pruned the canonical memory entry"
    );
    assert!(
        !durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&canonical_key),
        "active leave pruned the canonical durable record"
    );

    // Re-seed, then exercise the local-only group drop with the alias set
    // the production handler computes from the MLS alias.
    let reseed = cache_treekem_member_key_package(
        state,
        join_result_key(&group_id, &member_hex),
        fixture.event.clone(),
        true,
    )
    .await;
    assert!(matches!(
        reseed,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    let aliases = treekem_cache_group_aliases(state, &group_id).await;
    assert!(
        aliases.contains(&stable_group_id),
        "alias set expands the MLS alias to the canonical stable id"
    );
    let drop_status = prune_treekem_cache_groups(state, &aliases, "local_drop").await;
    assert!(matches!(
        drop_status,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    assert_eq!(
        state
            .treekem_member_key_packages
            .diagnostics()
            .await
            .entries,
        0,
        "local drop pruned the canonical memory entry"
    );
    assert!(
        durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .is_empty(),
        "local drop pruned every canonical durable record"
    );
    Ok(())
}

/// Codex blocker: a withdrawn group-card imported with NO local GroupInfo
/// must still prune an existing canonical durable recovery record. The
/// no-local handler knows only the card's stable group id; because the
/// cache record was canonicalized to that same stable id, the prune reaches
/// it.
#[tokio::test]
async fn withdrawn_card_import_without_local_group_prunes_canonical_record() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xe3, 0xe4).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    let stable_group_id = fixture.stable_group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let canonical_key = join_result_key(&stable_group_id, &member_hex);

    let seed = cache_treekem_member_key_package(
        state,
        join_result_key(&group_id, &member_hex),
        fixture.event.clone(),
        true,
    )
    .await;
    assert!(matches!(
        seed,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    assert!(
        durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&canonical_key),
        "precondition: canonical durable record seeded"
    );

    // Drop the live roster entry so the import takes the no-local branch.
    state.named_groups.write().await.remove(&group_id);
    assert!(
        state
            .named_groups
            .read()
            .await
            .values()
            .all(|info| info.stable_group_id() != stable_group_id),
        "precondition: no local group remains for the stable id"
    );

    let creator = x0x::identity::AgentKeypair::generate()?;
    let mut card = sample_group_card(&stable_group_id, 2, 5_000);
    card.withdrawn = true;
    card.sign(&creator)?;

    let response = import_group_card(State(Arc::clone(state)), Json(card))
        .await
        .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "withdrawn card import accepted on the no-local path"
    );

    assert!(
        !durable_cache_keys(&state.treekem_member_key_packages.path)
            .await?
            .contains(&canonical_key),
        "no-local withdrawn-card import pruned the canonical durable record"
    );
    assert_eq!(
        state
            .treekem_member_key_packages
            .diagnostics()
            .await
            .entries,
        0,
        "no-local withdrawn-card import pruned the canonical memory entry"
    );
    Ok(())
}

/// WP-TK2: the entry-count cap is enforced on `from_entries` and overflow
/// is shed oldest-`ts_ms`-first until the cache fits.
#[tokio::test]
async fn treekem_recovery_cache_count_limit_evicts_oldest() -> Result<()> {
    let cap = TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_ENTRIES;
    let overflow = 3;
    let total = cap + overflow;

    let mut entries = BTreeMap::new();
    for i in 0..total {
        let g = format!("g{i:04x}");
        let m = format!("m{i:04x}");
        entries.insert(
            format!("{g}:{m}"),
            synthetic_member_joined(&g, &m, i as u64, 8),
        );
    }

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, evicted) = TreeKemMemberKeyPackageCache::from_entries(path, entries, true)?;
    let diag = cache.diagnostics().await;

    assert_eq!(evicted, overflow, "excess entries evicted to reach the cap");
    assert_eq!(diag.entries, cap, "entry count held at MAX_ENTRIES");
    assert!(
        diag.encoded_bytes <= diag.max_encoded_bytes,
        "byte budget respected after count compaction"
    );
    // Eviction is oldest-ts first: the three smallest-ts records (i=0,1,2)
    // are evicted; i=3 is the first retained and the newest survives.
    assert!(cache.get("g0000:m0000").await.is_none(), "i=0 evicted");
    assert!(
        cache.get("g0002:m0002").await.is_none(),
        "i=2 evicted (last of overflow trio)"
    );
    assert!(
        cache.get("g0003:m0003").await.is_some(),
        "i=3 retained (first inside the cap)"
    );
    let last_idx = total - 1;
    assert!(
        cache
            .get(&format!("g{last_idx:04x}:m{last_idx:04x}"))
            .await
            .is_some(),
        "newest-ts record retained"
    );
    Ok(())
}

/// WP-TK2: the encoded-byte cap is enforced independently of the count
/// cap. With a handful of oversized records (count well under MAX_ENTRIES
/// but combined bytes over MAX_BYTES), the oldest-ts record is evicted so
/// the durable snapshot fits the byte budget.
#[tokio::test]
async fn treekem_recovery_cache_encoded_byte_limit_evicts_to_fit() -> Result<()> {
    let payload_len = 2_500_000;
    let ev_a = synthetic_member_joined("ga", "ma", 100, payload_len);
    let ev_b = synthetic_member_joined("gb", "mb", 200, payload_len);
    let ev_c = synthetic_member_joined("gc", "mc", 300, payload_len);
    let (key_a, key_b, key_c) = (
        "ga:ma".to_string(),
        "gb:mb".to_string(),
        "gc:mc".to_string(),
    );

    // Assert the byte budget — not the count cap — is the trigger, using
    // the cache's own encoded-size function (mirrors cache_snapshot_encoded_bytes).
    let bytes_a = cache_entry_encoded_bytes(&key_a, &ev_a)?;
    let bytes_b = cache_entry_encoded_bytes(&key_b, &ev_b)?;
    let bytes_c = cache_entry_encoded_bytes(&key_c, &ev_c)?;
    let snapshot = |n: usize, sum: usize| {
        2usize
            .saturating_add(sum)
            .saturating_add(n.saturating_sub(1))
    };
    let triple = snapshot(3, bytes_a + bytes_b + bytes_c);
    let surviving_pair = snapshot(2, bytes_b + bytes_c);
    assert!(
        triple > TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES,
        "precondition: three oversized records exceed the byte budget"
    );
    assert!(
        surviving_pair <= TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES,
        "precondition: the two newest records fit the byte budget"
    );

    let mut entries = BTreeMap::new();
    entries.insert(key_a.clone(), ev_a);
    entries.insert(key_b.clone(), ev_b);
    entries.insert(key_c.clone(), ev_c);

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, evicted) = TreeKemMemberKeyPackageCache::from_entries(path, entries, true)?;
    let diag = cache.diagnostics().await;

    assert_eq!(evicted, 1, "one record evicted to fit the byte budget");
    assert_eq!(diag.entries, 2, "two records remain");
    assert!(
        diag.encoded_bytes <= diag.max_encoded_bytes,
        "encoded bytes within budget after compaction"
    );
    // Oldest-ts (ev_a) is the victim; the two newer records survive.
    assert!(
        cache.get(&key_a).await.is_none(),
        "oldest-ts record evicted"
    );
    assert!(cache.get(&key_b).await.is_some(), "newer record retained");
    assert!(cache.get(&key_c).await.is_some(), "newest record retained");
    Ok(())
}

/// WP-TK2: eviction is deterministic — victim selection is min `ts_ms`,
/// then min key. With one eviction forced (`cap + 1` entries) and three
/// entries sharing the smallest `ts_ms`, the lexicographically smallest key
/// is the victim while its equal-ts siblings survive.
#[tokio::test]
async fn treekem_recovery_cache_eviction_tiebreak_is_timestamp_then_key() -> Result<()> {
    let cap = TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_ENTRIES;
    let mut entries = BTreeMap::new();
    // Three equal-ts (ts=10) records with distinct keys.
    for k in ["tie-a", "tie-b", "tie-c"] {
        entries.insert(
            k.to_string(),
            synthetic_member_joined(k, &format!("mem-{k}"), 10, 8),
        );
    }
    // `cap - 2` newer records (distinct ts) fill the cache to `cap + 1`,
    // forcing exactly one eviction.
    for i in 0..(cap - 2) {
        let g = format!("ng{i:04x}");
        entries.insert(
            format!("{g}:m"),
            synthetic_member_joined(&g, "m", 100 + i as u64, 8),
        );
    }
    assert_eq!(entries.len(), cap + 1, "precondition: one over the cap");

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, evicted) = TreeKemMemberKeyPackageCache::from_entries(path, entries, true)?;
    assert_eq!(evicted, 1, "exactly one record evicted");
    assert_eq!(cache.diagnostics().await.entries, cap);

    // Tie broken by smallest key: "tie-a" is the victim; "tie-b"/"tie-c"
    // (equal ts, larger keys) survive.
    assert!(
        cache.get("tie-a").await.is_none(),
        "smallest-key victim evicted on tie"
    );
    assert!(
        cache.get("tie-b").await.is_some(),
        "larger-key sibling survives the tie"
    );
    assert!(
        cache.get("tie-c").await.is_some(),
        "largest-key sibling survives the tie"
    );
    Ok(())
}

fn install_treekem_cache_writer_hook(
    path: &FsPath,
    release: Option<Arc<tokio::sync::Notify>>,
    force_error: Option<std::io::Error>,
) -> (Arc<tokio::sync::Notify>, TreeKemCacheWriterHookGuard) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut hooks = TREEKEM_CACHE_WRITER_HOOKS
        .lock()
        .expect("TreeKEM cache writer hook poisoned");
    hooks.insert(
        path.to_path_buf(),
        TreeKemCacheWriterHookControl {
            entered: Arc::clone(&entered),
            release,
            force_error,
        },
    );
    (
        entered,
        TreeKemCacheWriterHookGuard {
            path: path.to_path_buf(),
        },
    )
}

async fn signed_cache_fixture_entries() -> Result<(
    MemberJoinedTreeKemFixture,
    MemberJoinedTreeKemFixture,
    String,
    String,
)> {
    let first = member_joined_treekem_fixture(0xa1, 0xa2).await?;
    let second = member_joined_treekem_fixture(0xa3, 0xa4).await?;
    let first_key = join_result_key(&first.group_id, &first.member_hex);
    let second_key = join_result_key(&second.group_id, &second.member_hex);
    Ok((first, second, first_key, second_key))
}

/// WP-TK2 #5: the persistence mutex serializes disk writes without holding
/// the cache map lock. While the first writer is deterministically parked,
/// readers observe both the first mutation and a concurrent newer mutation;
/// after release, the coalescing writer persists the newest snapshot.
#[tokio::test]
async fn treekem_recovery_cache_slow_writer_does_not_block_readers_and_newest_wins() -> Result<()> {
    let (first, second, first_key, second_key) = signed_cache_fixture_entries().await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, _) =
        TreeKemMemberKeyPackageCache::from_entries(path.clone(), BTreeMap::new(), false)?;
    let cache = Arc::new(cache);
    let release = Arc::new(tokio::sync::Notify::new());
    let (entered, _hook_guard) =
        install_treekem_cache_writer_hook(&path, Some(Arc::clone(&release)), None);

    let first_cache = Arc::clone(&cache);
    let first_key_for_write = first_key.clone();
    let first_event = first.event.clone();
    let first_write = tokio::spawn(async move {
        first_cache
            .insert(first_key_for_write, first_event, true)
            .await
    });
    entered.notified().await;

    assert!(
        cache.get(&first_key).await.is_some(),
        "reader proceeds while the first disk writer is parked"
    );

    let second_cache = Arc::clone(&cache);
    let second_key_for_write = second_key.clone();
    let second_event = second.event.clone();
    let second_write = tokio::spawn(async move {
        second_cache
            .insert(second_key_for_write, second_event, true)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while cache.get(&second_key).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("newer in-memory mutation blocked behind slow disk writer")?;
    assert!(
        cache.get(&first_key).await.is_some(),
        "readers remain available after the concurrent mutation"
    );

    release.notify_one();
    let first_result = first_write.await??;
    let second_result = second_write.await??;
    assert!(matches!(
        first_result.persistence,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    assert!(matches!(
        second_result.persistence,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));

    let durable = durable_cache_keys(&path).await?;
    assert_eq!(
        durable,
        HashSet::from([first_key, second_key]),
        "serialized/coalesced persistence leaves the newest complete snapshot on disk"
    );
    let diagnostics = cache.diagnostics().await;
    assert!(!diagnostics.dirty);
    assert_eq!(diagnostics.persisted_revision, diagnostics.revision);
    Ok(())
}

#[tokio::test]
async fn slow_cache_persistence_does_not_cycle_with_membership_lock() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xbd, 0xbe).await?;
    let state = Arc::clone(&fixture.state);
    let key = join_result_key(&fixture.group_id, &fixture.member_hex);
    let release = Arc::new(tokio::sync::Notify::new());
    let (entered, _hook_guard) = install_treekem_cache_writer_hook(
        &state.treekem_member_key_packages.path,
        Some(Arc::clone(&release)),
        None,
    );

    let writer_state = Arc::clone(&state);
    let writer_event = fixture.event.clone();
    let writer = tokio::spawn(async move {
        cache_treekem_member_key_package(&writer_state, key, writer_event, true).await
    });
    entered.notified().await;

    let membership_lock = group_membership_lock(&state, &fixture.group_id).await;
    let membership_guard = tokio::time::timeout(Duration::from_secs(5), membership_lock.lock())
        .await
        .context("cache persistence introduced a persistence-to-membership lock cycle")?;
    assert!(
        state
            .treekem_member_key_packages
            .get(&join_result_key(&fixture.group_id, &fixture.member_hex))
            .await
            .is_some(),
        "cache map remains readable while persistence is parked"
    );

    release.notify_one();
    let status = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .context("membership lock introduced a membership-to-persistence lock cycle")??;
    assert!(matches!(
        status,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    drop(membership_guard);
    Ok(())
}

/// WP-TK2 #6: a failed durable write returns structured `Dirty`, retains
/// failure diagnostics, and remains retryable. A later mutation retries the
/// entire newest snapshot and clears dirty state only after disk success.
#[tokio::test]
async fn treekem_recovery_cache_failed_write_stays_dirty_and_retry_persists_newest() -> Result<()> {
    let (first, second, first_key, second_key) = signed_cache_fixture_entries().await?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("kp.json");
    let (cache, _) =
        TreeKemMemberKeyPackageCache::from_entries(path.clone(), BTreeMap::new(), false)?;
    let (entered, _hook_guard) = install_treekem_cache_writer_hook(
        &path,
        None,
        Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected TreeKEM cache persistence failure",
        )),
    );

    let failed = cache
        .insert(first_key.clone(), first.event.clone(), true)
        .await?;
    entered.notified().await;
    let TreeKemCachePersistenceStatus::Dirty {
        revision: failed_revision,
        error,
    } = failed.persistence
    else {
        anyhow::bail!("injected persistence failure was falsely reported durable");
    };
    assert!(error.contains("injected TreeKEM cache persistence failure"));
    let dirty = cache.diagnostics().await;
    assert!(dirty.dirty, "failed write remains explicitly dirty");
    assert_eq!(dirty.revision, failed_revision);
    assert_eq!(dirty.write_failures, 1);
    assert!(dirty
        .last_error
        .as_deref()
        .is_some_and(|last| { last.contains("injected TreeKEM cache persistence failure") }));
    assert!(
        cache.get(&first_key).await.is_some(),
        "failed persistence does not discard the retryable in-memory record"
    );
    assert!(
        tokio::fs::try_exists(&path)
            .await
            .is_ok_and(|exists| !exists),
        "failed writer did not create a falsely durable snapshot"
    );

    let retried = cache
        .insert(second_key.clone(), second.event.clone(), true)
        .await?;
    assert!(matches!(
        retried.persistence,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    let durable = durable_cache_keys(&path).await?;
    assert_eq!(
        durable,
        HashSet::from([first_key, second_key]),
        "successful retry persists the newest snapshot, including the prior dirty record"
    );
    let clean = cache.diagnostics().await;
    assert!(!clean.dirty, "successful retry clears dirty state");
    assert_eq!(clean.persisted_revision, clean.revision);
    assert_eq!(
        clean.write_failures, 1,
        "failure history remains observable"
    );
    assert_eq!(
        clean.last_error, None,
        "active error clears after durability succeeds"
    );
    Ok(())
}

#[tokio::test]
async fn provisional_witness_duplicate_retries_dirty_snapshot_and_survives_restart() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xbb, 0xbc).await?;
    let raw = without_recovery_attestation(fixture.event.clone());
    let key = join_result_key(&fixture.group_id, &fixture.member_hex);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("witness-dirty.json");
    let (cache, _) =
        TreeKemMemberKeyPackageCache::from_entries(path.clone(), BTreeMap::new(), false)?;
    let (entered, _hook_guard) = install_treekem_cache_writer_hook(
        &path,
        None,
        Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected witness persistence failure",
        )),
    );

    let failed = cache.insert(key.clone(), raw.clone(), false).await?;
    entered.notified().await;
    assert!(matches!(
        failed.persistence,
        TreeKemCachePersistenceStatus::Dirty { .. }
    ));
    let dirty_revision = cache.diagnostics().await.revision;

    let retried = cache.insert(key.clone(), raw, false).await?;
    assert!(matches!(
        retried.persistence,
        TreeKemCachePersistenceStatus::Durable { .. }
    ));
    let clean = cache.diagnostics().await;
    assert_eq!(clean.entries, 1);
    assert_eq!(
        clean.revision, dirty_revision,
        "duplicate retry is not a new record"
    );
    assert_eq!(clean.persisted_revision, clean.revision);

    let groups = fixture.state.named_groups.read().await.clone();
    let restarted = load_treekem_member_key_packages(&path, &groups).await?;
    let restored = restarted.get(&key).await.expect("witness record restored");
    assert!(verify_member_joined_key_package_event(&restored));
    assert!(recovery_attestation_revision(&restored).is_none());
    assert_eq!(restarted.diagnostics().await.entries, 1);
    Ok(())
}

/// Codex blocker: a production cache mutation whose first durable write
/// fails must become durable via the scheduled background retry — with no
/// second mutation or API call — clearing active diagnostics while
/// persisting the newest snapshot.
#[tokio::test]
async fn dirty_cache_write_becomes_durable_via_autonomous_retry() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xf1, 0xf2).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    let stable_group_id = fixture.stable_group_id.clone();
    let member_hex = fixture.member_hex.clone();
    let canonical_key = join_result_key(&stable_group_id, &member_hex);
    let cache_path = state.treekem_member_key_packages.path.clone();

    // One-shot: the FIRST write fails; the hook is consumed so the
    // autonomous retry's next write reaches the disk.
    let (entered, _hook_guard) = install_treekem_cache_writer_hook(
        &cache_path,
        None,
        Some(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected autonomous-retry persistence failure",
        )),
    );

    // A SINGLE production mutation; no second mutation or API call follows.
    let failed = cache_treekem_member_key_package(
        state,
        join_result_key(&group_id, &member_hex),
        fixture.event.clone(),
        true,
    )
    .await;
    entered.notified().await;
    let TreeKemCachePersistenceStatus::Dirty {
        revision: failed_revision,
        error,
    } = failed
    else {
        anyhow::bail!("injected persistence failure was falsely reported durable");
    };
    assert!(error.contains("injected autonomous-retry persistence failure"));
    assert_eq!(
        failed_revision,
        state
            .treekem_member_key_packages
            .diagnostics()
            .await
            .revision
    );
    assert!(
        tokio::fs::try_exists(&cache_path)
            .await
            .is_ok_and(|exists| !exists),
        "failed first write left no durable snapshot"
    );

    // Wait for the production-spawned retry to settle. No further mutation
    // drives it.
    let settled = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if !state.treekem_member_key_packages.diagnostics().await.dirty {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "autonomous retry made the dirty cache durable without a second mutation"
    );

    let clean = state.treekem_member_key_packages.diagnostics().await;
    assert!(
        !clean.dirty,
        "active dirty flag cleared by autonomous retry"
    );
    assert_eq!(
        clean.last_error, None,
        "active error cleared after durability"
    );
    assert_eq!(
        clean.persisted_revision, clean.revision,
        "autonomous retry persisted the newest snapshot"
    );
    assert_eq!(
        clean.write_failures, 1,
        "the single injected failure remains in failure history"
    );
    assert_eq!(
        durable_cache_keys(&cache_path).await?,
        HashSet::from([canonical_key]),
        "autonomous retry persisted the canonical newest snapshot"
    );
    Ok(())
}

/// Codex-discovered race: a non-inviter provisional witness insert and
/// terminal group pruning must share the per-group membership
/// serialization boundary. When the cache durable writer is parked
/// mid-insert the membership guard stays held, so a concurrent terminal
/// GroupDeleted cannot pass the boundary until the insert completes.
/// After release, pruning wins and leaves both cache memory and durable
/// JSON empty — no deferred-outer-insertion resurrection. Fails under the
/// old code that deferred the insert past the guard.
#[tokio::test]
async fn non_inviter_witness_insert_blocks_terminal_pruning_at_membership_boundary() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0xc5, 0xc6).await?;
    let (witness, _witness_dir) = secure_endpoint_test_state().await?;
    add_active_witness_to_treekem_fixture(&fixture, &witness).await?;

    let raw = without_recovery_attestation(fixture.event.clone());
    let cache_key = join_result_key(&fixture.group_id, &fixture.member_hex);
    let cache_path = witness.treekem_member_key_packages.path.clone();
    let group_id = fixture.group_id.clone();

    // Park the witness insert's durable writer. The membership guard stays
    // held while the writer is blocked because the production fix moved
    // the provisional cache insert inside the guard.
    let release = Arc::new(tokio::sync::Notify::new());
    let (entered, _hook_guard) =
        install_treekem_cache_writer_hook(&cache_path, Some(Arc::clone(&release)), None);

    // Witness side: non-inviter applies MemberJoined through the real
    // public wrapper. The durable write parks on the hook, so the
    // membership guard remains held.
    let apply_state = Arc::clone(&witness);
    let apply_member = fixture.member_id;
    let witness_apply = tokio::spawn(async move {
        apply_named_group_metadata_event(&apply_state, raw, apply_member, true).await
    });
    entered.notified().await;

    assert!(
        witness
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .is_some(),
        "witness provisional insert updated memory before parking on durability"
    );

    // Build the terminal GroupDeleted event with a signed terminal commit,
    // following the same construction as the existing tombstone tests.
    let parent = witness
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("witness holds the live group")
        .clone();
    let mut terminal_info = parent.clone();
    terminal_info.withdrawn = true;
    let commit = sign_metadata_terminality_commit(&parent, &terminal_info, &fixture.state, 2_000);
    let authority = fixture.state.agent.agent_id();
    let terminal_event = NamedGroupMetadataEvent::GroupDeleted {
        group_id: fixture.stable_group_id.clone(),
        revision: parent.roster_revision.saturating_add(1),
        actor: hex::encode(authority.as_bytes()),
        commit: Some(commit),
    };

    // Terminal side: GroupDeleted through the same public wrapper. This
    // acquires the SAME per-group membership mutex and cannot proceed
    // while the witness insert is in flight.
    let terminal_state = Arc::clone(&witness);
    let terminal_authority = authority;
    let terminal = tokio::spawn(async move {
        apply_named_group_metadata_event(&terminal_state, terminal_event, terminal_authority, true)
            .await
    });

    // Prove the membership boundary is held: a direct probe of the same
    // mutex cannot acquire within a bounded window while the witness
    // insert is parked. This deterministically demonstrates that the
    // terminal task — which needs the same lock — is also blocked.
    let probe_lock = group_membership_lock(&witness, &group_id).await;
    let probe = tokio::time::timeout(Duration::from_millis(200), probe_lock.lock()).await;
    assert!(
        probe.is_err(),
        "membership boundary is held by the in-flight witness insert; \
         terminal pruning cannot proceed"
    );

    // Release the parked durable writer. The witness insert completes and
    // drops the membership guard, allowing the terminal GroupDeleted to
    // acquire it, commit the terminal tombstone, and prune the cache.
    release.notify_one();

    let witness_applied = tokio::time::timeout(Duration::from_secs(5), witness_apply)
        .await
        .context("witness apply did not complete after releasing the durable writer")??;
    assert!(
        !witness_applied,
        "non-inviter witness retains without authoring membership"
    );

    let terminal_applied = tokio::time::timeout(Duration::from_secs(5), terminal)
        .await
        .context(
            "terminal GroupDeleted did not complete after the witness insert released the boundary",
        )??;
    assert!(
        terminal_applied,
        "signed GroupDeleted committed through the production apply path"
    );

    // Terminal pruning completes last: both in-memory and durable JSON
    // are empty. No deferred-outer-insertion resurrection occurred.
    assert_eq!(
        witness
            .treekem_member_key_packages
            .diagnostics()
            .await
            .entries,
        0,
        "terminal pruning emptied cache memory after the witness insert completed"
    );
    assert!(
        witness
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .is_none(),
        "terminal pruning evicted the provisional witness record from memory"
    );
    assert!(
        durable_cache_keys(&cache_path).await?.is_empty(),
        "terminal pruning emptied the durable JSON after the witness insert completed"
    );
    Ok(())
}
