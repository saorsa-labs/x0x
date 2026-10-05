#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ADR 0094 slice H red controls. These tests never start a daemon or use a network.
//! The compile fixture declares the future feature locally, so phase 1 needs no
//! production feature, verifier change, or test-only verifier stub.

use std::path::{Path, PathBuf};
use std::process::Command;

use saorsa_pqc::api::sig::ml_dsa_65;
use tempfile::TempDir;
use x0x::upgrade::signature::{
    sign_with_context, verify_bytes_signature_with_key, verify_manifest_signature,
    RELEASE_SIGNING_KEY,
};

fn signed_manifest() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (public, secret) = ml_dsa_65().generate_keypair().expect("throwaway keypair");
    // Deliberately retain original JSON bytes, including whitespace and channel.
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "version": "0.46.4",
        "channel": "stable",
        "timestamp": 1791158400u64,
        "assets": [],
        "skill_sha256": vec![0u8; 32],
        "skill_url": "",
    }))
    .expect("original manifest JSON");
    let signature = sign_with_context(&secret.to_bytes(), &manifest).expect("sign manifest");
    let public = public.to_bytes();
    assert_ne!(public.as_slice(), RELEASE_SIGNING_KEY.as_slice());
    verify_bytes_signature_with_key(&manifest, &signature, &public)
        .expect("positive control: valid signature under its own key");
    (public, manifest, signature)
}

#[test]
fn throwaway_manifest_is_rejected_by_default() {
    let (_, manifest, signature) = signed_manifest();
    assert!(
        verify_manifest_signature(&manifest, &signature).is_err(),
        "a fresh unrelated key must not enter the default trust set"
    );
}

/// Compile the real verifier source with a per-run, compile-time fixture key.
/// Phase 2's debug seam must read this OUT_DIR file, replacing the production
/// key. A runtime argument or environment variable never selects a trusted key.
fn prepare_verifier(root: &Path, public_key: &[u8]) {
    std::fs::create_dir_all(root.join("src")).expect("fixture source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "m2-signing-fixture"
version = "0.0.0"
edition = "2021"
[workspace]
[features]
upgrade-test-signing = []
[dependencies]
saorsa-pqc = "0.5"
thiserror = "2.0"
tracing = "0.1"
[dev-dependencies]
tempfile = "3.14"
"#,
    )
    .expect("fixture manifest");
    // Reuse the reviewed graph; any resolution updates stay in the scratch crate.
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
        root.join("Cargo.lock"),
    )
    .expect("fixture lockfile");
    std::fs::write(root.join("public-key.bin"), public_key).expect("fixture public key");
    std::fs::write(
        root.join("build.rs"),
        r#"fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::copy("public-key.bin", output.join("upgrade-test-signing-public-key.bin")).unwrap();
    println!("cargo:rerun-if-changed=public-key.bin");
}
"#,
    )
    .expect("fixture build script");
    let verifier = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/upgrade/signature.rs");
    std::fs::write(
        root.join("src/main.rs"),
        format!(
            r#"#[allow(dead_code)]
#[path = {verifier:?}]
mod signature;
fn main() {{
    assert!(cfg!(debug_assertions), "fixture must be a debug build");
    let args: Vec<_> = std::env::args_os().collect();
    let manifest = std::fs::read(&args[1]).unwrap();
    let signature = std::fs::read(&args[2]).unwrap();
    std::process::exit(if signature::verify_manifest_signature(&manifest, &signature).is_ok() {{ 0 }} else {{ 1 }});
}}
"#
        ),
    )
    .expect("fixture entry point");
}

fn compile_verifier(root: &Path, test_feature: bool) -> PathBuf {
    let target = root.join("target");
    let mut cargo = Command::new("cargo");
    cargo
        .args(["build", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .current_dir(root);
    if test_feature {
        cargo.args(["--features", "upgrade-test-signing"]);
    }
    let build = cargo.output().expect("compile verifier fixture");
    assert!(
        build.status.success(),
        "fixture must compile before checking trust (feature={test_feature}):\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    target.join("debug/m2-signing-fixture")
}

fn verify_fixture(binary: &Path, manifest: &Path, signature: &Path) -> i32 {
    let output = Command::new(binary)
        .arg(manifest)
        .arg(signature)
        .output()
        .expect("run inert manifest verifier");
    output.status.code().unwrap_or_else(|| {
        panic!(
            "verifier terminated by signal: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn throwaway_manifest_is_accepted_only_by_debug_feature_build() {
    let scratch = TempDir::new().expect("private compile fixture");
    let (public, manifest, signature) = signed_manifest();
    let manifest_path = scratch.path().join("manifest.json");
    let signature_path = scratch.path().join("manifest.sig");
    std::fs::write(&manifest_path, &manifest).expect("fixture manifest bytes");
    std::fs::write(&signature_path, &signature).expect("fixture signature bytes");
    let root = scratch.path().join("verifier");
    prepare_verifier(&root, &public);

    let default = compile_verifier(&root, false);
    assert_eq!(verify_fixture(&default, &manifest_path, &signature_path), 1);

    let enabled = compile_verifier(&root, true);
    assert_eq!(
        verify_fixture(&enabled, &manifest_path, &signature_path),
        0,
        "debug + upgrade-test-signing must replace the production key with the embedded fixture key"
    );

    // The seam must preserve original-byte verification and trust only its key.
    let (_, _, foreign_signature) = signed_manifest();
    std::fs::write(&signature_path, foreign_signature).expect("unrelated signature");
    assert_eq!(verify_fixture(&enabled, &manifest_path, &signature_path), 1);
    std::fs::write(&signature_path, signature).expect("restore fixture signature");
    let mut tampered = manifest;
    tampered.push(b' ');
    std::fs::write(&manifest_path, tampered).expect("tampered original bytes");
    assert_eq!(verify_fixture(&enabled, &manifest_path, &signature_path), 1);
}

#[test]
fn release_build_with_test_signing_feature_is_refused() {
    let scratch = TempDir::new().expect("private release compile fixture");
    let (public, _, _) = signed_manifest();
    prepare_verifier(scratch.path(), &public);
    let build = Command::new("cargo")
        .args([
            "check",
            "--offline",
            "--release",
            "--features",
            "upgrade-test-signing",
        ])
        .arg("--manifest-path")
        .arg(scratch.path().join("Cargo.toml"))
        .arg("--target-dir")
        .arg(scratch.path().join("target"))
        .current_dir(scratch.path())
        .output()
        .expect("check release feature prohibition");
    let diagnostic = String::from_utf8_lossy(&build.stderr);
    assert!(
        !build.status.success()
            && diagnostic.contains("upgrade-test-signing requires debug_assertions"),
        "release feature must fail compilation with its named diagnostic:\n{diagnostic}"
    );
}
