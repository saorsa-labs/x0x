//! Deprecated compatibility shim for `x0x user-id create`.
//!
//! This binary remains buildable from source for scripts that invoke it
//! directly. New code should use `x0x user-id create [PATH]`.

use anyhow::{Context, Result};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("warning: x0x-user-keygen is deprecated; use `x0x user-id create [PATH]` instead.");

    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: x0x-user-keygen <output-path>")?;

    let resolved = x0x::cli::commands::user_id::create(Some(output), None).await?;
    println!("{}", resolved.display());
    Ok(())
}
