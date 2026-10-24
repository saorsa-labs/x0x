// Expanded in the library; fixtures open no endpoint and start no network tasks.
#[allow(unused_macros)]
macro_rules! upgrade_cache_flush_tests {
    () => {
        #[cfg(all(test, unix))]
        mod upgrade_cache_flush_tests {
            use super::*;

            async fn fixture(
                persist: bool,
            ) -> (
                tempfile::TempDir,
                Agent,
                std::sync::Arc<ant_quic::BootstrapCache>,
            ) {
                let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("target/upgrade-cache-tests");
                std::fs::create_dir_all(&root).unwrap();
                let dir = tempfile::tempdir_in(root).unwrap();
                let mut agent = Agent::builder()
                    .with_machine_key(dir.path().join("machine.key"))
                    .with_agent_key_path(dir.path().join("agent.key"))
                    .with_contact_store_path(dir.path().join("contacts.json"))
                    .build()
                    .await
                    .unwrap();
                assert!(agent.network.is_none());
                let cache = std::sync::Arc::new(
                    ant_quic::BootstrapCache::open(
                        ant_quic::BootstrapCacheConfig::builder()
                            .cache_dir(dir.path().join("peers"))
                            .min_peers_to_save(1)
                            .persist(persist)
                            .build(),
                    )
                    .await
                    .unwrap(),
                );
                cache
                    .add_seed(
                        ant_quic::PeerId([7; 32]),
                        vec!["8.8.8.8:5483".parse().unwrap()],
                    )
                    .await;
                agent.bootstrap_cache = Some(cache.clone());
                (dir, agent, cache)
            }

            #[tokio::test]
            async fn upgrade_cache_flush_propagates_save_failure() {
                let (dir, agent, _) = fixture(true).await;
                std::fs::create_dir(dir.path().join("peers/bootstrap_cache.tmp")).unwrap();
                let failure = agent
                    .try_shutdown()
                    .await
                    .expect_err("cache write failure must refuse shutdown");
                assert!(failure.to_string().contains("bootstrap cache"));
            }

            #[tokio::test]
            async fn upgrade_cache_flush_requires_parent_durability() {
                let (dir, agent, _) = fixture(true).await;
                let path = dir.path().join("peers/bootstrap_cache.json");
                let _fault = storage::arm_fail_parent_dir_fsync_for_testing(&path);
                let failure = agent
                    .try_shutdown()
                    .await
                    .expect_err("visible file is not a durable acknowledgment");
                assert!(failure.to_string().contains("bootstrap cache"));
            }

            #[tokio::test]
            async fn upgrade_cache_flush_removes_stale_empty_snapshot() {
                let (dir, agent, cache) = fixture(true).await;
                cache.save().await.unwrap();
                cache.remove(&ant_quic::PeerId([7; 32])).await;
                agent.try_shutdown().await.unwrap();
                assert!(!dir.path().join("peers/bootstrap_cache.json").exists());
            }

            #[tokio::test]
            async fn upgrade_cache_flush_persists_enabled_and_skips_disabled() {
                for persist in [true, false] {
                    let (dir, agent, cache) = fixture(persist).await;
                    agent.try_shutdown().await.unwrap();
                    let path = dir.path().join("peers/bootstrap_cache.json");
                    assert_eq!(path.exists(), persist);
                    if persist {
                        let loaded = ant_quic::BootstrapCache::open(cache.config().clone())
                            .await
                            .unwrap();
                        assert_eq!(loaded.peer_count().await, 1);
                    } else {
                        assert!(!dir.path().join("peers").exists());
                    }
                }
            }
        }
    };
}
