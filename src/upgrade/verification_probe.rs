//! Inert packaged-binary checks, dispatched before all initialization (ADR 0094).

/// Handle `--verify-release-manifest MANIFEST SIGNATURE` before initializing
/// the application. Reads only the two files; does not parse or reserialize
/// the manifest, create identity/configuration, contact peers, or install bytes.
#[doc(hidden)]
pub fn run_if_requested() -> Option<anyhow::Result<()>> {
    let mut args = std::env::args_os().skip(1);
    let flag = args.next();
    if flag.as_deref() == Some(std::ffi::OsStr::new("--upgrade-probe")) {
        return Some((|| {
            // This optional flag keeps the regression control inert on old
            // binaries, whose existing --version branch handles it.
            if args.any(|arg| arg != "--version") {
                anyhow::bail!("usage: --upgrade-probe [--version]");
            }
            let platform = super::manifest::current_platform_target()
                .ok_or_else(|| anyhow::anyhow!("unsupported upgrade probe platform"))?;
            let output = serde_json::json!({
                "version": crate::VERSION,
                "platform": platform,
            });
            // No tracing, configuration, runtime, filesystem or networking.
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &output)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            Ok(())
        })());
    }
    if flag.as_deref() != Some(std::ffi::OsStr::new("--verify-release-manifest")) {
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
