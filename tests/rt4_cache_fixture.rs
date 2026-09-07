// #491 RT-4 fixture controls: REAL serializer round-trip through the
// pinned ant-quic 0.27.49 public BootstrapCache API. No hand-written JSON.
// The generated bootstrap_cache.json is the exact serializer output the
// x0xd daemon's loader sees — valid SystemTime, SocketAddr, capabilities,
// statistics, PeerSource, hex peer-map keys, and a finalized checksum.
//
// The x0xd process harness (RT-4 runtime phases) is in the harness module;
// these controls establish the load oracle before any daemon phase.
#![cfg(test)]

use ant_quic::bootstrap_cache::{BootstrapCache, BootstrapCacheConfig};
use ant_quic::PeerId;
use std::net::SocketAddr;

const LOOPBACK: &str = "127.0.0.1:51820";

fn config_for(dir: &std::path::Path) -> BootstrapCacheConfig {
    BootstrapCacheConfig::builder()
        .cache_dir(dir.to_path_buf())
        .min_peers_to_save(1)
        .persist(true)
        .enable_file_locking(false) // fixture writer; daemon uses its normal setting
        .build()
}

async fn write_fixture(
    dir: &std::path::Path,
    peer_ids: &[([u8; 32], &str)],
) -> std::io::Result<()> {
    let config = config_for(dir);
    let address: SocketAddr = LOOPBACK.parse().expect("loopback addr");
    let cache = BootstrapCache::open(config).await?;
    for (bytes, _label) in peer_ids {
        cache.add_seed(PeerId(*bytes), vec![address]).await;
    }
    assert_eq!(
        cache.peer_count().await,
        peer_ids.len(),
        "fixture writer: all peers added"
    );
    cache.save().await?;
    Ok(())
}

/// Load oracle: write a self-only fixture through the public serializer,
/// reopen, and assert the loader ACCEPTED it (count=1, correct key,
/// get_peer returns a record with the correct embedded peer_id).
#[tokio::test]
async fn rt4_self_only_fixture_load_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let self_id = [0xaa; 32];
    write_fixture(dir.path(), &[(self_id, "self")])
        .await
        .unwrap();

    // Reopen and verify the load oracle.
    let config = config_for(dir.path());
    let reopened = BootstrapCache::open(config).await.unwrap();
    assert_eq!(
        reopened.peer_count().await,
        1,
        "self-only: exactly 1 peer loaded"
    );
    let peer_id = PeerId(self_id);
    assert!(
        reopened.contains(&peer_id).await,
        "self-only: contains(self)"
    );
    let peer = reopened
        .get_peer(&peer_id)
        .await
        .expect("self-only: get_peer returns a record");
    assert_eq!(
        peer.peer_id, peer_id,
        "self-only: embedded peer_id matches the cache key"
    );
    assert!(!peer.addresses.is_empty(), "self-only: peer has addresses");
}

/// Mixed fixture: self + nonself, both load, both retrievable, distinct keys.
#[tokio::test]
async fn rt4_mixed_fixture_load_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let self_id = [0xaa; 32];
    let nonself_id = [0xbb; 32];
    write_fixture(dir.path(), &[(self_id, "self"), (nonself_id, "nonself")])
        .await
        .unwrap();

    let config = config_for(dir.path());
    let reopened = BootstrapCache::open(config).await.unwrap();
    assert_eq!(
        reopened.peer_count().await,
        2,
        "mixed: exactly 2 peers loaded"
    );

    let self_peer_id = PeerId(self_id);
    let nonself_peer_id = PeerId(nonself_id);
    assert!(
        reopened.contains(&self_peer_id).await,
        "mixed: contains(self)"
    );
    assert!(
        reopened.contains(&nonself_peer_id).await,
        "mixed: contains(nonself)"
    );
    assert!(
        reopened.get_peer(&self_peer_id).await.is_some(),
        "mixed: get_peer(self)"
    );
    assert!(
        reopened.get_peer(&nonself_peer_id).await.is_some(),
        "mixed: get_peer(nonself)"
    );
}

/// Checksum negative control: corrupt the top-level checksum AFTER a valid
/// save, reopen, and assert the loader's fail-safe behavior (open succeeds
/// but peer_count == 0). This is SEPARATE from the valid load oracle — an
/// empty result from a corrupted checksum is NOT evidence of self pruning.
#[tokio::test]
async fn rt4_corrupted_checksum_yields_empty_load() {
    let dir = tempfile::tempdir().unwrap();
    let self_id = [0xaa; 32];

    // First: valid save (proves the file is loadable).
    write_fixture(dir.path(), &[(self_id, "self")])
        .await
        .unwrap();
    let valid_config = config_for(dir.path());
    let valid = BootstrapCache::open(valid_config).await.unwrap();
    assert_eq!(
        valid.peer_count().await,
        1,
        "pre-corruption: valid 1-peer load"
    );

    // Drop the valid cache handle before corrupting.
    drop(valid);

    // Corrupt the top-level checksum in the saved JSON.
    let file = dir.path().join("bootstrap_cache.json");
    let json_bytes = std::fs::read(&file).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
    let original_checksum = json["checksum"].as_u64().unwrap();
    json["checksum"] = serde_json::Value::from(
        original_checksum
            .checked_add(1)
            .unwrap_or(original_checksum.saturating_sub(1)),
    );
    let corrupted = serde_json::to_vec_pretty(&json).unwrap();
    std::fs::write(&file, corrupted).unwrap();

    // Reopen: the loader's fail-safe is open-succeeds-but-empty.
    let config = config_for(dir.path());
    let reopened = BootstrapCache::open(config).await.unwrap();
    assert_eq!(
        reopened.peer_count().await,
        0,
        "corrupted checksum: loader fail-safe yields 0 peers (NOT evidence of pruning)"
    );
}

/// Prune-predicate: after removing self from a mixed 2-peer cache, the
/// remaining count is 1 (the file is NOT unlinked); after removing self
/// from a self-only cache, remaining is 0 (the file IS unlinked by x0x).
/// This exercises the actual `remove` + `peer_count` public API.
#[tokio::test]
async fn rt4_prune_remaining_predicate() {
    // Mixed: remove self → remaining=1 → no unlink.
    let dir = tempfile::tempdir().unwrap();
    let self_id = [0xaa; 32];
    let nonself_id = [0xbb; 32];
    write_fixture(dir.path(), &[(self_id, "self"), (nonself_id, "nonself")])
        .await
        .unwrap();
    let config = config_for(dir.path());
    let cache = BootstrapCache::open(config).await.unwrap();
    assert_eq!(cache.peer_count().await, 2);
    let removed = cache.remove(&PeerId(self_id)).await;
    assert!(removed.is_some(), "mixed: self was removed from memory");
    assert_eq!(
        cache.peer_count().await,
        1,
        "mixed: remaining=1 after self removal (no unlink expected)"
    );
    drop(cache);

    // Self-only: remove self → remaining=0 → x0x unlinks the file.
    let dir2 = tempfile::tempdir().unwrap();
    write_fixture(dir2.path(), &[(self_id, "self")])
        .await
        .unwrap();
    let config2 = config_for(dir2.path());
    let cache2 = BootstrapCache::open(config2).await.unwrap();
    assert_eq!(cache2.peer_count().await, 1);
    let removed2 = cache2.remove(&PeerId(self_id)).await;
    assert!(
        removed2.is_some(),
        "self-only: self was removed from memory"
    );
    assert_eq!(
        cache2.peer_count().await,
        0,
        "self-only: remaining=0 after self removal (x0x unlinks the file)"
    );
}
