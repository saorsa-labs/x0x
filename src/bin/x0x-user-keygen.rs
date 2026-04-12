use anyhow::{Context, Result};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let output = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("usage: x0x-user-keygen <output-path>")?;

    let keypair = x0x::identity::UserKeypair::generate()
        .map_err(|e| anyhow::anyhow!("failed to generate user keypair: {e}"))?;

    x0x::storage::save_user_keypair_to(&keypair, &output)
        .await
        .with_context(|| format!("failed to write user keypair to {}", output.display()))?;

    println!("{}", output.display());
    Ok(())
}
