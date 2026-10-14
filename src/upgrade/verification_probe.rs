//! Inert packaged-binary check of the compiled manifest trust root (ADR 0094).

/// Handle `--verify-release-manifest MANIFEST SIGNATURE` before initializing
/// the application. Reads only the two files; does not parse or reserialize
/// the manifest, create identity/configuration, contact peers, or install bytes.
#[doc(hidden)]
pub fn run_if_requested() -> Option<anyhow::Result<()>> {
    // Both x0xd and x0x call this at start: keep the release marker in the
    // binary so a later writer can read this release from the bytes
    // (#1106 review R2/R3).
    std::hint::black_box(super::RELEASE_MARKER);
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--verify-release-manifest")) {
        return None;
    }
    Some((|| {
        let (Some(manifest), Some(signature), None) = (args.next(), args.next(), args.next())
        else {
            anyhow::bail!("usage: --verify-release-manifest MANIFEST SIGNATURE");
        };
        super::signature::verify_manifest_signature(
            &std::fs::read(manifest)?,
            &std::fs::read(signature)?,
        )?;
        Ok(())
    })())
}
