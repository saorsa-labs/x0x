//! x0x-keygen — ML-DSA-65 key generation and signing tool for release archives.
//!
//! ## Usage
//!
//! ```bash
//! x0x-keygen generate --output keypair.secret
//! x0x-keygen sign --key keypair.secret --input archive.tar.gz --output archive.tar.gz.sig --context "x0x-release-v1"
//! x0x-keygen verify --key public.key --input archive.tar.gz --signature archive.tar.gz.sig --context "x0x-release-v1"
//! x0x-keygen export-public --key keypair.secret --output public.key
//! x0x-keygen embed-rust --key public.key
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use fips204::traits::{SerDes, Signer};
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};
use sha2::{Digest, Sha256};

use x0x::upgrade::manifest::{PlatformAsset, ReleaseManifest, SCHEMA_VERSION};

#[derive(Parser)]
#[command(name = "x0x-keygen")]
#[command(about = "ML-DSA-65 key generation and signing for x0x releases")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ML-DSA-65 keypair.
    Generate {
        /// Output path for the secret key file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a file with ML-DSA-65.
    Sign {
        /// Path to the secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Path to the file to sign.
        #[arg(long)]
        input: PathBuf,
        /// Output path for the detached signature.
        #[arg(long)]
        output: PathBuf,
        /// Signing context for domain separation.
        #[arg(long, default_value = "x0x-release-v1")]
        context: String,
    },
    /// Verify a detached ML-DSA-65 signature.
    Verify {
        /// Path to the public key file.
        #[arg(long)]
        key: PathBuf,
        /// Path to the file to verify.
        #[arg(long)]
        input: PathBuf,
        /// Path to the detached signature file.
        #[arg(long)]
        signature: PathBuf,
        /// Signing context for domain separation.
        #[arg(long, default_value = "x0x-release-v1")]
        context: String,
    },
    /// Export the public key from a secret key file.
    ExportPublic {
        /// Path to the secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Output path for the public key file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the public key as a Rust `const` for embedding in source code.
    EmbedRust {
        /// Path to the public key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Generate and sign a release manifest from built assets.
    Manifest {
        /// Release version (e.g. "0.5.0").
        #[arg(long)]
        version: String,
        /// Directory containing the release archive files.
        #[arg(long)]
        assets_dir: PathBuf,
        /// Path to the SKILL.md file.
        #[arg(long)]
        skill_path: PathBuf,
        /// Path to the ML-DSA-65 secret key for signing.
        #[arg(long)]
        key: PathBuf,
        /// Output directory for manifest and signature files.
        #[arg(long)]
        output_dir: PathBuf,
        /// Base URL for asset download links (row 7b rehearsal tooling).
        /// DEFAULT UNCHANGED: without this flag the URLs are exactly the
        /// GitHub release form the release workflow has always produced;
        /// with it, archive/signature/SKILL URLs point under the given
        /// base (e.g. http://127.0.0.1:8443). Tooling only — the daemon
        /// and release workflow are untouched.
        #[arg(long)]
        base_url: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output } => {
            let dsa = ml_dsa_65();
            let (public_key, secret_key) = dsa.generate_keypair()?;

            // Write secret key (contains both secret and public portions)
            write_secret_key(&output, &secret_key.to_bytes())?;

            // Also write the public key alongside
            let public_path = output.with_extension("pub");
            std::fs::write(&public_path, public_key.to_bytes())?;

            eprintln!("Generated ML-DSA-65 keypair:");
            eprintln!("  Secret key: {}", output.display());
            eprintln!("  Public key: {}", public_path.display());
            eprintln!(
                "  Public key hex (first 32 bytes): {}",
                hex::encode(&public_key.to_bytes()[..32])
            );
        }
        Commands::Sign {
            key,
            input,
            output,
            context,
        } => {
            let sk_bytes = std::fs::read(&key)?;
            let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)?;
            let data = std::fs::read(&input)?;

            let dsa = ml_dsa_65();
            let signature = dsa.sign_with_context(&secret_key, &data, context.as_bytes())?;

            std::fs::write(&output, signature.to_bytes())?;
            eprintln!(
                "Signed {} ({} bytes) -> {}",
                input.display(),
                data.len(),
                output.display()
            );
        }
        Commands::Verify {
            key,
            input,
            signature,
            context,
        } => {
            let pk_bytes = std::fs::read(&key)?;
            let public_key = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes)?;
            let data = std::fs::read(&input)?;
            let sig_bytes = std::fs::read(&signature)?;
            let sig = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)?;

            let dsa = ml_dsa_65();
            let valid = dsa.verify_with_context(&public_key, &data, &sig, context.as_bytes())?;

            if valid {
                eprintln!("Signature is VALID for {}", input.display());
            } else {
                eprintln!("Signature is INVALID for {}", input.display());
                std::process::exit(1);
            }
        }
        Commands::ExportPublic { key, output } => {
            let sk_bytes = std::fs::read(&key)?;
            let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)?;
            let public_key_bytes = derive_public_key_bytes(&secret_key)?;
            std::fs::write(&output, public_key_bytes)?;
            eprintln!("Exported public key to {}", output.display());
        }
        Commands::Manifest {
            version,
            assets_dir,
            skill_path,
            key,
            output_dir,
            base_url,
        } => {
            generate_manifest(
                &version,
                &assets_dir,
                &skill_path,
                &key,
                &output_dir,
                base_url,
            )?;
        }
        Commands::EmbedRust { key } => {
            let pk_bytes = std::fs::read(&key)?;
            if pk_bytes.len() != 1952 {
                return Err(format!(
                    "Expected 1952 bytes for ML-DSA-65 public key, got {}",
                    pk_bytes.len()
                )
                .into());
            }

            println!("/// Embedded ML-DSA-65 release signing public key (1952 bytes).");
            println!(
                "/// Generated by: x0x-keygen embed-rust --key {}",
                key.display()
            );
            println!(
                "pub const RELEASE_SIGNING_KEY: &[u8; {}] = &[",
                pk_bytes.len()
            );
            for (i, chunk) in pk_bytes.chunks(16).enumerate() {
                let hex_bytes: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
                if i == pk_bytes.chunks(16).count() - 1 {
                    println!("    {}", hex_bytes.join(", "));
                } else {
                    println!("    {},", hex_bytes.join(", "));
                }
            }
            println!("];");
        }
    }

    Ok(())
}

fn write_secret_key(path: &Path, key_bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(key_bytes)?;
    file.sync_all()
}

fn derive_public_key_bytes(
    secret_key: &MlDsaSecretKey,
) -> Result<[u8; fips204::ml_dsa_65::PK_LEN], Box<dyn std::error::Error>> {
    let secret_key_bytes: [u8; fips204::ml_dsa_65::SK_LEN] =
        secret_key.to_bytes().try_into().map_err(|bytes: Vec<u8>| {
            format!(
                "Expected {} bytes for ML-DSA-65 secret key, got {}",
                fips204::ml_dsa_65::SK_LEN,
                bytes.len()
            )
        })?;
    let secret_key = fips204::ml_dsa_65::PrivateKey::try_from_bytes(secret_key_bytes)
        .map_err(|err| format!("invalid ML-DSA-65 secret key: {err}"))?;

    Ok(secret_key.get_public_key().into_bytes())
}

/// Known platform archive mappings: (target triple, archive prefix, extension).
const PLATFORM_ARCHIVES: &[(&str, &str, &str)] = &[
    ("x86_64-unknown-linux-gnu", "x0x-linux-x64-gnu", "tar.gz"),
    ("x86_64-unknown-linux-musl", "x0x-linux-x64-musl", "tar.gz"),
    ("aarch64-unknown-linux-gnu", "x0x-linux-arm64-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "x0x-macos-x64", "tar.gz"),
    ("aarch64-apple-darwin", "x0x-macos-arm64", "tar.gz"),
    ("x86_64-pc-windows-msvc", "x0x-windows-x64", "zip"),
];

/// The release asset origin the workflow has always used. Kept as a
/// const so the flagless output stays byte-identical to it.
const RELEASE_ASSET_BASE: &str = "https://github.com/saorsa-labs/x0x/releases/download";

/// Normalize a `--base-url` value: reject empty input and non-http(s)
/// schemes, and strip trailing slashes so `http://h:1/` and `http://h:1`
/// produce identical URLs.
fn normalize_base_url(base: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let Some(base) = base else {
        return Ok(RELEASE_ASSET_BASE.to_string());
    };
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(
            format!("--base-url must start with http:// or https:// (got {base:?})").into(),
        );
    }
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("--base-url must not be only slashes".into());
    }
    Ok(trimmed.to_string())
}

/// The (archive, signature) URL pair for one asset name under `base`.
fn asset_urls(base: &str, version: &str, name: &str) -> (String, String) {
    (
        format!("{base}/v{version}/{name}"),
        format!("{base}/v{version}/{name}.sig"),
    )
}

fn generate_manifest(
    version: &str,
    assets_dir: &Path,
    skill_path: &Path,
    key_path: &Path,
    output_dir: &Path,
    base_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_version = semver::Version::parse(version)?;
    if !parsed_version.pre.is_empty() {
        return Err("prerelease manifests remain prohibited (ADR 0087, D186)".into());
    }
    let sk_bytes = std::fs::read(key_path)?;
    let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)?;
    let repo_url = normalize_base_url(base_url.as_deref())?;

    let mut assets = Vec::new();
    for (target, prefix, ext) in PLATFORM_ARCHIVES {
        let archive_name = format!("{prefix}.{ext}");
        let archive_path = assets_dir.join(&archive_name);
        if !archive_path.exists() {
            eprintln!("  Skipping {target}: {archive_name} not found");
            continue;
        }

        let archive_data = std::fs::read(&archive_path)?;
        let archive_sha256: [u8; 32] = Sha256::digest(&archive_data).into();

        let sig_name = format!("{archive_name}.sig");
        let sig_path = assets_dir.join(&sig_name);
        if !sig_path.is_file() {
            return Err(format!(
                "signature file missing for {archive_name}: {}",
                sig_path.display()
            )
            .into());
        }

        let (archive_url, signature_url) = asset_urls(&repo_url, version, &archive_name);
        let _ = &sig_name;

        assets.push(PlatformAsset {
            target: target.to_string(),
            archive_url,
            archive_sha256,
            signature_url,
        });

        eprintln!(
            "  Added {target}: {archive_name} (SHA-256: {})",
            hex::encode(archive_sha256)
        );
    }

    if assets.is_empty() {
        return Err("no platform archives found in assets directory".into());
    }

    // Compute SKILL.md SHA-256
    let skill_data = std::fs::read(skill_path)?;
    let skill_sha256: [u8; 32] = Sha256::digest(&skill_data).into();
    let skill_url = format!("{repo_url}/v{version}/SKILL.md");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let manifest = ReleaseManifest {
        schema_version: SCHEMA_VERSION,
        channel: "stable".into(),
        version: version.to_string(),
        timestamp,
        assets,
        skill_url,
        skill_sha256,
    };

    x0x::upgrade::monitor::validate_manifest_timestamp(&manifest)?;
    let manifest_json = serde_json::to_string_pretty(&manifest)?;

    // Sign the manifest JSON
    let dsa = ml_dsa_65();
    let signature = dsa.sign_with_context(
        &secret_key,
        manifest_json.as_bytes(),
        x0x::upgrade::signature::SIGNING_CONTEXT,
    )?;

    // Write manifest and signature
    let manifest_path = output_dir.join("release-manifest.json");
    let sig_path = output_dir.join("release-manifest.json.sig");
    std::fs::write(&manifest_path, &manifest_json)?;
    std::fs::write(&sig_path, signature.to_bytes())?;

    eprintln!("Generated release manifest:");
    eprintln!("  Manifest: {}", manifest_path.display());
    eprintln!("  Signature: {}", sig_path.display());
    eprintln!("  Version: {version}");
    eprintln!("  Platforms: {}", manifest.assets.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn manifest_generation_refuses_prerelease_before_key_read() {
        let unused = std::path::Path::new("unused-test-key-path");
        let result = super::generate_manifest("99.0.0-rc.1", unused, unused, unused, unused, None);
        assert!(
            matches!(result, Err(error) if error.to_string().contains("prerelease manifests remain prohibited"))
        );
    }
}
