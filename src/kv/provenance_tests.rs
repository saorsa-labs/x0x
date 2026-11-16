#![cfg(test)]
//! #1094 slice P1: the per-entry writer mark.

use super::*;
use crate::identity::AgentKeypair;

fn store(n: u8) -> KvStoreId {
    KvStoreId::new([n; 32])
}

fn entry() -> KvEntry {
    KvEntry::new("note".to_string(), b"hello".to_vec(), "text/plain".into())
}

fn marked(kp: &AgentKeypair, rider: Option<&str>) -> KvEntry {
    let mut e = entry();
    mark(&mut e, &store(1), kp.public_key(), kp.secret_key(), rider).expect("mark");
    e
}

#[test]
fn a_mark_verifies_for_its_writer_and_rider() {
    let kp = AgentKeypair::generate().expect("key");
    assert_eq!(
        verify(&store(1), &marked(&kp, None)),
        EntryWriter::Verified {
            agent: kp.agent_id(),
            rider: None
        }
    );
    assert_eq!(
        verify(&store(1), &marked(&kp, Some("claude-desktop"))),
        EntryWriter::Verified {
            agent: kp.agent_id(),
            rider: Some("claude-desktop".to_string())
        }
    );
    assert_eq!(verify(&store(1), &entry()), EntryWriter::Unsigned);
}

type Edit = Box<dyn Fn(&mut KvEntry)>;

/// The relay case the slice exists for: an entry moved to another store,
/// re-pointed at another key, given new bytes, a new `updated_at`, a new
/// content type, other metadata or another rider label no longer verifies.
#[test]
fn a_mark_binds_store_key_content_time_and_rider() {
    let kp = AgentKeypair::generate().expect("key");
    let good = marked(&kp, Some("rider-a"));
    assert!(matches!(
        verify(&store(2), &good),
        EntryWriter::Invalid { .. }
    ));
    let edits: Vec<Edit> = vec![
        Box::new(|e| e.key = "other".to_string()),
        Box::new(|e| {
            e.value = b"forged".to_vec();
            e.content_hash = *blake3::hash(&e.value).as_bytes();
        }),
        Box::new(|e| e.value = b"forged".to_vec()),
        Box::new(|e| e.updated_at += 1),
        Box::new(|e| e.content_type = "text/html".to_string()),
        Box::new(|e| {
            e.metadata.insert("label".to_string(), "x".to_string());
        }),
        Box::new(|e| {
            e.metadata
                .insert(WRITER_RIDER_KEY.to_string(), "rider-b".to_string());
        }),
        Box::new(|e| {
            e.metadata.remove(WRITER_RIDER_KEY);
        }),
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut e = good.clone();
        edit(&mut e);
        assert!(
            matches!(verify(&store(1), &e), EntryWriter::Invalid { .. }),
            "edit {i} must break the mark"
        );
    }
    // `created_at` is outside the mark: a merge keeps the earliest one.
    let mut e = good.clone();
    e.created_at = 1;
    assert!(matches!(
        verify(&store(1), &e),
        EntryWriter::Verified { .. }
    ));
}

/// Another agent's key cannot claim the mark, a partial mark is invalid,
/// and junk in the mark keys is invalid.
#[test]
fn a_forged_or_broken_mark_is_invalid() {
    let writer = AgentKeypair::generate().expect("writer");
    let forger = AgentKeypair::generate().expect("forger");
    let mut e = marked(&writer, None);
    e.metadata.insert(
        WRITER_KEY.to_string(),
        base64::engine::general_purpose::STANDARD.encode(forger.public_key().as_bytes()),
    );
    assert!(matches!(verify(&store(1), &e), EntryWriter::Invalid { .. }));

    let mut partial = marked(&writer, None);
    partial.metadata.remove(WRITER_SIG_KEY);
    assert_eq!(
        verify(&store(1), &partial),
        EntryWriter::Invalid {
            reason: "incomplete writer mark"
        }
    );
    let mut rider_only = entry();
    rider_only
        .metadata
        .insert(WRITER_RIDER_KEY.to_string(), "r".to_string());
    assert!(matches!(
        verify(&store(1), &rider_only),
        EntryWriter::Invalid { .. }
    ));
    for key in [WRITER_KEY, WRITER_SIG_KEY] {
        let mut junk = marked(&writer, None);
        junk.metadata
            .insert(key.to_string(), "not base64!".to_string());
        assert!(matches!(
            verify(&store(1), &junk),
            EntryWriter::Invalid { .. }
        ));
    }
}

/// Re-marking replaces the old mark; a long rider label is cut to its bound
/// at a character boundary; an empty label is no rider.
#[test]
fn remarking_replaces_and_rider_labels_are_bounded() {
    let first = AgentKeypair::generate().expect("first");
    let second = AgentKeypair::generate().expect("second");
    let mut e = marked(&first, Some("old-rider"));
    mark(
        &mut e,
        &store(1),
        second.public_key(),
        second.secret_key(),
        None,
    )
    .expect("mark");
    assert_eq!(
        verify(&store(1), &e),
        EntryWriter::Verified {
            agent: second.agent_id(),
            rider: None
        }
    );
    let long = "é".repeat(MAX_RIDER_LABEL_BYTES);
    let e = marked(&first, Some(&long));
    let EntryWriter::Verified {
        rider: Some(rider), ..
    } = verify(&store(1), &e)
    else {
        panic!("a long rider label is cut, not refused");
    };
    assert!(rider.len() <= MAX_RIDER_LABEL_BYTES && long.starts_with(&rider));
    assert_eq!(
        verify(&store(1), &marked(&first, Some(""))),
        EntryWriter::Verified {
            agent: first.agent_id(),
            rider: None
        }
    );
}

/// An older peer stores and relays the mark unchanged: it is ordinary
/// metadata in the encoded entry.
#[test]
fn the_mark_survives_the_entry_encoding() {
    let kp = AgentKeypair::generate().expect("key");
    let e = marked(&kp, Some("r"));
    let decoded: KvEntry =
        bincode::deserialize(&bincode::serialize(&e).expect("encode")).expect("decode");
    assert_eq!(
        verify(&store(1), &decoded),
        EntryWriter::Verified {
            agent: kp.agent_id(),
            rider: Some("r".to_string())
        }
    );
}

/// A rewrite drops the old writer's mark: it no longer covers the content.
#[test]
fn a_rewrite_drops_the_previous_mark() {
    let kp = AgentKeypair::generate().expect("key");
    let mut e = marked(&kp, Some("r"));
    e.metadata.insert("user".to_string(), "kept".to_string());
    e.update_value(b"new".to_vec(), "text/plain".to_string());
    assert_eq!(verify(&store(1), &e), EntryWriter::Unsigned);
    assert_eq!(e.metadata.get("user").map(String::as_str), Some("kept"));
}

/// Two marks over the same bytes at the same time (two writers): every
/// replica keeps the same one, whatever order the entries arrive in.
#[test]
fn equal_entries_with_different_marks_merge_to_one_winner() {
    let a = AgentKeypair::generate().expect("a");
    let b = AgentKeypair::generate().expect("b");
    let base = entry();
    let mut from_a = base.clone();
    mark(&mut from_a, &store(1), a.public_key(), a.secret_key(), None).expect("mark");
    let mut from_b = base;
    mark(&mut from_b, &store(1), b.public_key(), b.secret_key(), None).expect("mark");

    let mut first = from_a.clone();
    first.merge(&from_b);
    let mut second = from_b.clone();
    second.merge(&from_a);
    assert_eq!(
        first.metadata, second.metadata,
        "one winner in either order"
    );
    assert!(matches!(
        verify(&store(1), &first),
        EntryWriter::Verified { .. }
    ));
}

fn loopback() -> crate::network::NetworkConfig {
    crate::network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..crate::network::NetworkConfig::default()
    }
}

async fn agent(dir: &std::path::Path) -> crate::Agent {
    crate::Agent::builder()
        .with_identity_dir(dir)
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key(AgentKeypair::generate().expect("key"))
        .with_agent_cert_path(dir.join("agent.cert"))
        .with_peer_cache_disabled()
        .with_contact_store_path(dir.join("contacts.json"))
        .with_network_config(loopback())
        .build()
        .await
        .expect("agent")
}

/// #1094 P1 end to end on one daemon: a put on a group store carries this
/// agent's verified mark, in the stored entry and in the published delta;
/// a put on a store outside `x0x/group/` is not marked. A replica that
/// takes the entry from another holder (the retained-image and full-serve
/// case) still sees the original writer.
#[tokio::test]
async fn a_group_store_put_is_marked_by_its_writer() {
    let dir = tempfile::tempdir().expect("dir");
    let agent = agent(dir.path()).await;
    let (_, topic) = crate::kv::encrypted::group_store_identity(&"1a".repeat(16), "scratch");
    let handle = agent
        .create_kv_store("scratch", &topic)
        .await
        .expect("store");
    let outcome = handle
        .put_with_outcome("note".to_string(), b"hi".to_vec(), "text/plain".into())
        .await
        .expect("put");
    let writer = EntryWriter::Verified {
        agent: agent.agent_id(),
        rider: None,
    };
    let store_id = handle.store_id().await;
    assert_eq!(handle.entry_writer("note").await, Some(writer.clone()));
    let delta_entry = outcome
        .delta
        .added
        .values()
        .map(|(entry, _)| entry)
        .next()
        .expect("the delta carries the entry");
    assert_eq!(
        verify(&store_id, delta_entry),
        writer,
        "the mark is published"
    );

    // A relay's copy: the entry moved through another holder unchanged.
    let relayed: KvEntry =
        bincode::deserialize(&bincode::serialize(delta_entry).expect("encode")).expect("decode");
    let mut replica = KvEntry::new("note".to_string(), b"older".to_vec(), "text/plain".into());
    replica.updated_at = 0;
    replica.merge(&relayed);
    assert_eq!(verify(&store_id, &replica), writer);

    let plain = agent
        .create_kv_store("plain", "app/plain-store")
        .await
        .expect("plain store");
    plain
        .put_with_outcome("k".to_string(), b"v".to_vec(), "text/plain".into())
        .await
        .expect("put");
    assert_eq!(plain.entry_writer("k").await, Some(EntryWriter::Unsigned));
    assert_eq!(plain.entry_writer("absent").await, None);
}
