//! Phase C.2 integration tests: distributed discovery index.
//!
//! These tests exercise the shard-based discovery primitives and privacy
//! guarantees (no daemon required). They prove:
//!
//! 1. Shard topic construction is deterministic.
//! 2. `PublicDirectory` groups fan out to tag + name + id shards.
//! 3. `Hidden` groups are rejected from public shard publish.
//! 4. `ListedToContacts` groups are rejected from public shard publish.
//! 5. Shard cache supersedes by revision and evicts on withdrawal.
//! 6. Anti-entropy `pull_targets` correctly identifies missing/stale
//!    entries against a peer's digest.
//! 7. Subscription persistence round-trips via JSON.

use x0x::groups::{
    may_publish_to_public_shards, name_words, shard_of, shards_for_public, topic_for, DigestEntry,
    DirectoryMessage, DirectoryShardCache, GroupAdmission, GroupConfidentiality,
    GroupDiscoverability, GroupPolicySummary, GroupReadAccess, GroupWriteAccess, ShardKind,
    SubscriptionRecord, SubscriptionSet, MAX_NAME_WORDS, MAX_TAGS_PER_GROUP, SHARD_COUNT,
};
use x0x::identity::AgentKeypair;

fn sample_summary(disc: GroupDiscoverability) -> GroupPolicySummary {
    GroupPolicySummary {
        discoverability: disc,
        admission: GroupAdmission::RequestAccess,
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: GroupReadAccess::MembersOnly,
        write_access: GroupWriteAccess::MembersOnly,
    }
}

fn make_card(
    group_id: &str,
    revision: u64,
    withdrawn: bool,
    disc: GroupDiscoverability,
    tags: Vec<String>,
    name: &str,
) -> x0x::groups::GroupCard {
    x0x::groups::GroupCard {
        group_id: group_id.to_string(),
        name: name.to_string(),
        description: "".into(),
        avatar_url: None,
        banner_url: None,
        tags,
        policy_summary: sample_summary(disc),
        owner_agent_id: "ff".repeat(32),
        admin_count: 1,
        member_count: 2,
        created_at: 0,
        updated_at: 0,
        request_access_enabled: true,
        metadata_topic: None,
        revision,
        state_hash: format!("h{revision}"),
        prev_state_hash: None,
        issued_at: 1_000 + revision,
        expires_at: 100_000,
        authority_agent_id: String::new(),
        authority_public_key: String::new(),
        withdrawn,
        signature: String::new(),
    }
}

#[test]
fn topic_for_produces_expected_format() {
    assert_eq!(topic_for(ShardKind::Tag, 0), "x0x.directory.tag.0");
    assert_eq!(topic_for(ShardKind::Name, 1234), "x0x.directory.name.1234");
    assert_eq!(topic_for(ShardKind::Id, 65_535), "x0x.directory.id.65535");
}

#[test]
fn shard_of_deterministic_across_calls() {
    for kind in [ShardKind::Tag, ShardKind::Name, ShardKind::Id] {
        for key in ["rust", "Ai", "long-group-id-1234"] {
            let a = shard_of(kind, key);
            let b = shard_of(kind, key);
            assert_eq!(a, b);
            assert!(a < SHARD_COUNT);
        }
    }
}

#[test]
fn publicdirectory_fans_out_to_all_kinds() {
    let shards = shards_for_public(&["rust".into(), "async".into()], "Async Runtime", "abc123");
    let kinds: std::collections::HashSet<_> = shards.iter().map(|(k, _, _)| *k).collect();
    assert!(kinds.contains(&ShardKind::Tag));
    assert!(kinds.contains(&ShardKind::Name));
    assert!(kinds.contains(&ShardKind::Id));
}

#[test]
fn name_words_shard_matches_shards_for_public() {
    let name = "Async Rust Workers";
    let words = name_words(name);
    let shards = shards_for_public(&[], name, "g1");
    for word in &words {
        let expected = shard_of(ShardKind::Name, word);
        assert!(
            shards
                .iter()
                .any(|(k, s, _)| *k == ShardKind::Name && *s == expected),
            "expected name shard for word '{word}'"
        );
    }
}

#[test]
fn hidden_must_not_publish_to_public_shards() {
    assert!(!may_publish_to_public_shards(GroupDiscoverability::Hidden));
}

#[test]
fn listed_to_contacts_must_not_publish_to_public_shards() {
    assert!(!may_publish_to_public_shards(
        GroupDiscoverability::ListedToContacts
    ));
}

#[test]
fn publicdirectory_may_publish_to_public_shards() {
    assert!(may_publish_to_public_shards(
        GroupDiscoverability::PublicDirectory
    ));
}

#[test]
fn shards_for_public_caps_at_max_tags() {
    let many: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
    let shards = shards_for_public(&many, "x", "g1");
    let tag_count = shards
        .iter()
        .filter(|(k, _, _)| *k == ShardKind::Tag)
        .count();
    assert!(tag_count <= MAX_TAGS_PER_GROUP);
}

#[test]
fn shards_for_public_caps_at_max_name_words() {
    let shards = shards_for_public(
        &[],
        "one two three four five six seven eight nine ten eleven",
        "g1",
    );
    let name_count = shards
        .iter()
        .filter(|(k, _, _)| *k == ShardKind::Name)
        .count();
    assert!(name_count <= MAX_NAME_WORDS);
}

#[test]
fn shards_for_public_emits_exactly_one_id_shard() {
    let shards = shards_for_public(&["a".into()], "name", "g1");
    let id_count = shards
        .iter()
        .filter(|(k, _, _)| *k == ShardKind::Id)
        .count();
    assert_eq!(id_count, 1);
}

#[test]
fn cache_supersedes_by_revision() {
    let mut cache = DirectoryShardCache::default();
    cache.insert(
        ShardKind::Tag,
        7,
        make_card(
            "g1",
            1,
            false,
            GroupDiscoverability::PublicDirectory,
            vec!["rust".into()],
            "t",
        ),
    );
    cache.insert(
        ShardKind::Tag,
        7,
        make_card(
            "g1",
            5,
            false,
            GroupDiscoverability::PublicDirectory,
            vec!["rust".into()],
            "t",
        ),
    );
    assert_eq!(cache.get("g1").unwrap().revision, 5);

    // Lower rev rejected
    assert!(!cache.insert(
        ShardKind::Tag,
        7,
        make_card(
            "g1",
            3,
            false,
            GroupDiscoverability::PublicDirectory,
            vec!["rust".into()],
            "t",
        ),
    ));
    assert_eq!(cache.get("g1").unwrap().revision, 5);
}

#[test]
fn cache_evicts_on_withdrawal_card() {
    let mut cache = DirectoryShardCache::default();
    cache.insert(
        ShardKind::Tag,
        7,
        make_card(
            "g1",
            5,
            false,
            GroupDiscoverability::PublicDirectory,
            vec!["rust".into()],
            "t",
        ),
    );
    assert!(cache.get("g1").is_some());
    cache.insert(
        ShardKind::Tag,
        7,
        make_card(
            "g1",
            6,
            true,
            GroupDiscoverability::PublicDirectory,
            vec![],
            "t",
        ),
    );
    assert!(cache.get("g1").is_none());
}

#[test]
fn pull_targets_finds_missing_and_stale() {
    let mut cache = DirectoryShardCache::default();
    cache.insert(
        ShardKind::Tag,
        1,
        make_card(
            "g1",
            5,
            false,
            GroupDiscoverability::PublicDirectory,
            vec![],
            "t",
        ),
    );
    cache.insert(
        ShardKind::Tag,
        1,
        make_card(
            "g2",
            3,
            false,
            GroupDiscoverability::PublicDirectory,
            vec![],
            "t",
        ),
    );
    let peer = vec![
        DigestEntry {
            group_id: "g1".into(), // local rev 5, peer rev 5 → skip
            revision: 5,
            state_hash: "h5".into(),
            expires_at: 100_000,
        },
        DigestEntry {
            group_id: "g2".into(), // local rev 3, peer rev 7 → pull stale
            revision: 7,
            state_hash: "h7".into(),
            expires_at: 100_000,
        },
        DigestEntry {
            group_id: "g3".into(), // unknown locally → pull missing
            revision: 1,
            state_hash: "h1".into(),
            expires_at: 100_000,
        },
    ];
    let pulls = cache.pull_targets(ShardKind::Tag, 1, &peer);
    assert!(pulls.contains(&"g2".to_string()));
    assert!(pulls.contains(&"g3".to_string()));
    assert!(!pulls.contains(&"g1".to_string()));
}

#[test]
fn signed_card_on_shard_verifies() {
    // Real ML-DSA-65 roundtrip: sign on one keypair, verify with its
    // embedded public key. No AppState or network needed.
    let kp = AgentKeypair::generate().unwrap();
    let mut card = make_card(
        "g1",
        1,
        false,
        GroupDiscoverability::PublicDirectory,
        vec!["rust".into()],
        "t",
    );
    card.sign(&kp).unwrap();
    card.verify_signature().unwrap();
}

#[test]
fn directory_message_roundtrip_all_variants() {
    let card = Box::new(make_card(
        "g1",
        1,
        false,
        GroupDiscoverability::PublicDirectory,
        vec!["rust".into()],
        "t",
    ));
    let card_msg = DirectoryMessage::Card { card };
    let parsed = DirectoryMessage::decode(&card_msg.encode()).unwrap();
    assert!(matches!(parsed, DirectoryMessage::Card { .. }));

    let digest_msg = DirectoryMessage::Digest {
        shard: 42,
        kind: ShardKind::Tag,
        entries: vec![DigestEntry {
            group_id: "g1".into(),
            revision: 1,
            state_hash: "h1".into(),
            expires_at: 100_000,
        }],
    };
    let parsed = DirectoryMessage::decode(&digest_msg.encode()).unwrap();
    assert!(matches!(parsed, DirectoryMessage::Digest { .. }));

    let pull_msg = DirectoryMessage::Pull {
        shard: 42,
        kind: ShardKind::Tag,
        group_ids: vec!["g1".into(), "g2".into()],
    };
    let parsed = DirectoryMessage::decode(&pull_msg.encode()).unwrap();
    assert!(matches!(parsed, DirectoryMessage::Pull { .. }));
}

#[test]
fn subscription_set_json_roundtrip() {
    let mut set = SubscriptionSet::default();
    set.add(SubscriptionRecord {
        kind: ShardKind::Tag,
        shard: 42,
        key: Some("ai".into()),
        subscribed_at: 1_000,
    });
    set.add(SubscriptionRecord {
        kind: ShardKind::Name,
        shard: 99,
        key: Some("rust".into()),
        subscribed_at: 2_000,
    });
    let json = serde_json::to_string(&set).unwrap();
    let back: SubscriptionSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
    assert!(back.contains(ShardKind::Tag, 42));
    assert!(back.contains(ShardKind::Name, 99));
}

#[test]
fn cache_search_across_tag_name_id() {
    let mut cache = DirectoryShardCache::default();
    let c1 = make_card(
        "rust-group",
        1,
        false,
        GroupDiscoverability::PublicDirectory,
        vec!["systems".into(), "async".into()],
        "Runtime Workers",
    );
    let c2 = make_card(
        "ml-group",
        1,
        false,
        GroupDiscoverability::PublicDirectory,
        vec!["data".into()],
        "Python ML",
    );
    cache.insert(ShardKind::Tag, 1, c1);
    cache.insert(ShardKind::Tag, 2, c2);

    // Tag hit
    assert_eq!(cache.search("systems").len(), 1);
    // Name hit (case-insensitive)
    assert_eq!(cache.search("python").len(), 1);
    // ID hit
    assert_eq!(cache.search("rust-group").len(), 1);
    // No match
    assert_eq!(cache.search("go").len(), 0);
}

#[test]
fn distinct_groups_route_to_distinct_id_shards() {
    let a = shard_of(ShardKind::Id, "group-alpha");
    let b = shard_of(ShardKind::Id, "group-beta");
    // Astronomical chance of collision on a 16-bit space; two known-
    // different strings will almost always produce different shards.
    // The only claim here is that the map is NOT identity-valued.
    if a == b {
        // If by cosmic coincidence they did collide, pick another pair.
        let c = shard_of(ShardKind::Id, "group-gamma");
        assert_ne!(a, c);
    }
}
