#![cfg(test)]
//! #1094 slice P1: the per-entry writer mark.

use super::*;
use crate::identity::AgentKeypair;
use crate::kv::store::{AccessPolicy, KvStore};
use crate::kv::KvStoreDelta;
use saorsa_gossip_types::PeerId;

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

fn verified(kp: &AgentKeypair, rider: Option<&str>) -> EntryWriter {
    EntryWriter::Verified {
        agent: kp.agent_id(),
        rider: rider.map(str::to_string),
    }
}

fn signed_store(n: u8, owner: &AgentKeypair) -> KvStore {
    KvStore::new(
        store(n),
        "s".to_string(),
        owner.agent_id(),
        AccessPolicy::Signed,
    )
    .expect("store")
}

#[test]
fn a_mark_verifies_for_its_writer_and_rider() {
    let kp = AgentKeypair::generate().expect("key");
    assert_eq!(
        verify(&store(1), "note", &marked(&kp, None)),
        verified(&kp, None)
    );
    assert_eq!(
        verify(&store(1), "note", &marked(&kp, Some("claude-desktop"))),
        verified(&kp, Some("claude-desktop"))
    );
    assert_eq!(verify(&store(1), "note", &entry()), EntryWriter::Unsigned);
    // Review of #1963: the entry carries no public key.
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_key().as_bytes());
    assert!(marked(&kp, None)
        .metadata
        .values()
        .all(|v| !v.contains(&pk_b64[..64])));
}

/// Review of #1963: an unknown writer key is `Unverified`, never `Verified`.
#[test]
fn an_unknown_key_is_unverified() {
    let kp = AgentKeypair::generate().expect("key");
    let e = marked(&kp, None);
    assert_eq!(
        verify_with(&store(1), "note", &e, |_| None),
        EntryWriter::Unverified {
            agent: kp.agent_id()
        }
    );
    // Another agent's key under this agent's id never verifies.
    let other = AgentKeypair::generate().expect("other");
    assert!(matches!(
        verify_with(&store(1), "note", &e, |_| Some(other.public_key().clone())),
        EntryWriter::Invalid { .. }
    ));
}

type Edit = Box<dyn Fn(&mut KvEntry)>;

/// The relay case the slice exists for: an entry moved to another store,
/// re-pointed at another key, given new bytes, a new content type, other
/// metadata, another rider label or another writer id no longer verifies.
#[test]
fn a_mark_binds_store_key_content_writer_and_rider() {
    let kp = AgentKeypair::generate().expect("key");
    let other = AgentKeypair::generate().expect("other");
    let good = marked(&kp, Some("rider-a"));
    assert!(matches!(
        verify(&store(2), "note", &good),
        EntryWriter::Invalid { .. }
    ));
    // The other agent's key is known here, so naming it is checked, and fails.
    note_agent_key(other.public_key());
    let other_hex = hex::encode(other.agent_id().as_bytes());
    let edits: Vec<Edit> = vec![
        Box::new(|e| e.key = "other".to_string()),
        Box::new(|e| e.value = b"forged".to_vec()),
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
        Box::new(move |e| {
            e.metadata
                .insert(WRITER_AGENT_KEY.to_string(), other_hex.clone());
        }),
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut e = good.clone();
        edit(&mut e);
        let key = e.key.clone();
        assert!(
            matches!(verify(&store(1), &key, &e), EntryWriter::Invalid { .. }),
            "edit {i} must break the mark"
        );
    }
    // `created_at` is outside the mark: a merge keeps the earliest one.
    let mut e = good.clone();
    e.created_at = 1;
    assert!(matches!(
        verify(&store(1), "note", &e),
        EntryWriter::Verified { .. }
    ));
}

/// MAJOR 1 of the review of #1963: the entry's map slot is part of the
/// check. A's entry for `vote/p1` held under `vote/p2` is not verified.
#[test]
fn a_mark_does_not_move_to_another_slot() {
    let kp = AgentKeypair::generate().expect("key");
    let mut e = KvEntry::new("vote/p1".to_string(), b"yes".to_vec(), "text/plain".into());
    mark(&mut e, &store(1), kp.public_key(), kp.secret_key(), None).expect("mark");
    assert_eq!(verify(&store(1), "vote/p1", &e), verified(&kp, None));
    assert_eq!(
        verify(&store(1), "vote/p2", &e),
        EntryWriter::Invalid {
            reason: "the entry is not under its own key"
        }
    );
}

/// MAJOR 1: a delta that holds an entry under another key is refused.
#[test]
fn a_delta_with_an_entry_under_another_key_is_refused() {
    let writer = AgentKeypair::generate().expect("writer");
    let mut target = signed_store(9, &writer);
    let peer = PeerId::new([7; 32]);
    let mut e = KvEntry::new("vote/p1".to_string(), b"yes".to_vec(), "text/plain".into());
    mark(
        &mut e,
        &store(9),
        writer.public_key(),
        writer.secret_key(),
        None,
    )
    .expect("mark");
    let mut delta = KvStoreDelta::new(1);
    delta
        .added
        .insert("vote/p2".to_string(), (e.clone(), (peer, 1)));
    target
        .merge_delta(&delta, peer, Some(&writer.agent_id()))
        .expect("merge call");
    assert!(
        target.get("vote/p2").is_none(),
        "the misplaced entry is refused"
    );

    let mut good = KvStoreDelta::new(1);
    good.added.insert("vote/p1".to_string(), (e, (peer, 2)));
    target
        .merge_delta(&good, peer, Some(&writer.agent_id()))
        .expect("merge call");
    assert!(
        target.get("vote/p1").is_some(),
        "the entry in its own slot lands"
    );
}

/// A partial mark is invalid; junk in the mark keys is invalid.
#[test]
fn a_broken_mark_is_invalid() {
    let writer = AgentKeypair::generate().expect("writer");
    let mut partial = marked(&writer, None);
    partial.metadata.remove(WRITER_SIG_KEY);
    assert_eq!(
        verify(&store(1), "note", &partial),
        EntryWriter::Invalid {
            reason: "incomplete writer mark"
        }
    );
    let mut rider_only = entry();
    rider_only
        .metadata
        .insert(WRITER_RIDER_KEY.to_string(), "r".to_string());
    assert!(matches!(
        verify(&store(1), "note", &rider_only),
        EntryWriter::Invalid { .. }
    ));
    for key in [WRITER_AGENT_KEY, WRITER_SIG_KEY] {
        let mut junk = marked(&writer, None);
        junk.metadata
            .insert(key.to_string(), "zzzz not valid".to_string());
        assert!(matches!(
            verify(&store(1), "note", &junk),
            EntryWriter::Invalid { .. }
        ));
    }
}

/// MINOR of the review of #1963: a rewrite by a writer that does not mark
/// (an older peer keeps the metadata) reads `Unsigned`, not `Invalid`; a
/// rewrite here drops the mark.
#[test]
fn a_stale_mark_reads_unsigned() {
    let kp = AgentKeypair::generate().expect("key");
    // What an older peer's `update_value` does: new bytes, new time,
    // metadata kept.
    let mut old_peer_rewrite = marked(&kp, Some("r"));
    old_peer_rewrite.value = b"new".to_vec();
    old_peer_rewrite.content_hash = *blake3::hash(b"new").as_bytes();
    old_peer_rewrite.updated_at += 5;
    assert_eq!(
        verify(&store(1), "note", &old_peer_rewrite),
        EntryWriter::Unsigned
    );

    let mut e = marked(&kp, Some("r"));
    e.metadata.insert("user".to_string(), "kept".to_string());
    e.update_value(b"new".to_vec(), "text/plain".to_string());
    assert_eq!(verify(&store(1), "note", &e), EntryWriter::Unsigned);
    assert_eq!(e.metadata.get("user").map(String::as_str), Some("kept"));
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
    assert_eq!(verify(&store(1), "note", &e), verified(&second, None));
    let long = "é".repeat(MAX_RIDER_LABEL_BYTES);
    let e = marked(&first, Some(&long));
    let EntryWriter::Verified {
        rider: Some(rider), ..
    } = verify(&store(1), "note", &e)
    else {
        panic!("a long rider label is cut, not refused");
    };
    assert!(rider.len() <= MAX_RIDER_LABEL_BYTES && long.starts_with(&rider));
    assert_eq!(
        verify(&store(1), "note", &marked(&first, Some(""))),
        verified(&first, None)
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
        verify(&store(1), "note", &decoded),
        verified(&kp, Some("r"))
    );
}

/// MAJOR 2 of the review of #1963, attack 1: a relay resends A's entry
/// with a junk mark that sorts higher. Inside the store, a valid mark is
/// never replaced by an invalid one, in either arrival order.
#[test]
fn a_junk_mark_never_beats_a_valid_one() {
    let a = AgentKeypair::generate().expect("a");
    let good = marked(&a, None);
    let mut junk = good.clone();
    junk.metadata
        .insert(WRITER_SIG_KEY.to_string(), "zzzz".repeat(16));
    junk.metadata
        .insert(WRITER_AGENT_KEY.to_string(), "ff".repeat(32));
    for (first, second) in [(&good, &junk), (&junk, &good)] {
        let mut held = first.clone();
        held.merge_in_store(second, &store(1));
        assert_eq!(verify(&store(1), "note", &held), verified(&a, None));
    }
}

/// MAJOR 2, attack 2: W re-signs A's exact bytes. Between two valid marks
/// the rule is deterministic (both arrival orders agree), so the mark then
/// proves "a member signed these bytes at this time", not first authorship.
#[test]
fn two_valid_marks_over_the_same_bytes_merge_to_one_winner() {
    let a = AgentKeypair::generate().expect("a");
    let w = AgentKeypair::generate().expect("w");
    let from_a = marked(&a, None);
    let mut from_w = from_a.clone();
    mark(&mut from_w, &store(1), w.public_key(), w.secret_key(), None).expect("mark");
    let mut first = from_a.clone();
    first.merge_in_store(&from_w, &store(1));
    let mut second = from_w.clone();
    second.merge_in_store(&from_a, &store(1));
    assert_eq!(
        first.metadata, second.metadata,
        "one winner in either order"
    );
    assert!(matches!(
        verify(&store(1), "note", &first),
        EntryWriter::Verified { .. }
    ));
}

/// MAJOR 3 of the review of #1963: the mark's encoded size is within the
/// bound the image check uses.
#[test]
fn writer_mark_bytes_bound_the_mark() {
    let kp = AgentKeypair::generate().expect("key");
    let plain = bincode::serialized_size(&entry()).expect("size");
    let with_mark =
        bincode::serialized_size(&marked(&kp, Some(&"r".repeat(MAX_RIDER_LABEL_BYTES))))
            .expect("size");
    let mark_bytes = with_mark - plain;
    assert!(
        mark_bytes as usize <= crate::kv::store::WRITER_MARK_BYTES,
        "a mark is {mark_bytes} bytes"
    );
    assert!(mark_bytes > 4_000, "the signature dominates: {mark_bytes}");
}

/// MAJOR 3: a put that would take the store image over the retained-image
/// limit is refused with `StoreFull`; the image stays within the limit, and
/// the refusal comes near it, not early.
#[test]
fn a_put_past_the_image_limit_is_refused() {
    let writer = AgentKeypair::generate().expect("writer");
    let mut s = signed_store(3, &writer);
    let peer = PeerId::new([7; 32]);
    let value = vec![b'v'; 60_000];
    let max = crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES as u64;
    let mut i = 0u32;
    loop {
        let key = format!("k{i:05}");
        match s.check_image_room(&key, value.len(), 10, true) {
            Ok(()) => {
                s.put(key, value.clone(), "text/plain".into(), peer)
                    .expect("put");
                i += 1;
            }
            Err(crate::kv::KvError::StoreFull { image, .. }) => {
                assert!(image > max);
                break;
            }
            Err(other) => panic!("unexpected {other}"),
        }
    }
    let size = bincode::serialized_size(&s).expect("size");
    assert!(size <= max, "the image stayed within the limit: {size}");
    assert!(
        size + 2 * 70_000 > max,
        "the refusal came near the limit, not early: {size}"
    );
    // Replacing a key with a value of the same size still fits.
    assert!(s.check_image_room("k00000", value.len(), 10, false).is_ok());
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
        verify(&store_id, "note", delta_entry),
        writer,
        "the mark is published"
    );

    // A relay's copy: the entry moved through another holder unchanged.
    let relayed: KvEntry =
        bincode::deserialize(&bincode::serialize(delta_entry).expect("encode")).expect("decode");
    let mut replica = KvEntry::new("note".to_string(), b"older".to_vec(), "text/plain".into());
    replica.updated_at = 0;
    replica.merge_in_store(&relayed, &store_id);
    assert_eq!(verify(&store_id, "note", &replica), writer);

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
