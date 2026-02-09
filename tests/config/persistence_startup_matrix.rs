use x0x::config::{PersistenceConfig, StartupConfig};
use x0x::crdt::persistence::{resolve_strict_startup_manifest, ManifestError, StoreManifest};

#[test]
fn startup_matrix_strict_resolution_allows_missing_init_intent() {
    let config = StartupConfig {
        persistence: PersistenceConfig {
            enabled: true,
            mode: Some("strict".to_string()),
            strict_initialize_if_missing: Some(false),
            ..PersistenceConfig::default()
        },
    };

    let resolved = config
        .resolve_persistence()
        .expect("strict config resolution should allow missing init intent");
    assert_eq!(resolved.policy.mode.as_str(), "strict");
    assert!(!resolved.policy.strict_initialization.initialize_if_missing);
}

#[test]
fn startup_matrix_strict_without_init_intent_requires_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = StoreManifest::v1("matrix-store");

    let err = resolve_strict_startup_manifest(temp.path(), false, &manifest)
        .expect_err("strict startup should fail when manifest is missing");
    assert!(matches!(err, ManifestError::PersistenceNotInitialized(_)));
}

#[test]
fn startup_matrix_strict_with_init_intent_bootstraps_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = StoreManifest::v1("matrix-store");

    let resolved = resolve_strict_startup_manifest(temp.path(), true, &manifest)
        .expect("strict startup should initialize manifest");
    assert_eq!(resolved, manifest);
}
