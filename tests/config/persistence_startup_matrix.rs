use x0x::crdt::persistence::{resolve_strict_startup_manifest, ManifestError, StoreManifest};

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
