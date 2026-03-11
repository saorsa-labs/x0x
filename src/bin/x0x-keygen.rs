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

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output } => {
            let dsa = ml_dsa_65();
            let (public_key, secret_key) = dsa.generate_keypair()?;

            // Write secret key (contains both secret and public portions)
            std::fs::write(&output, secret_key.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }

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

            // ML-DSA-65: the public key can be derived from the secret key.
            // The secret key file contains the full secret key (4032 bytes).
            // We re-derive the public key by generating from the same bytes.
            // Actually, saorsa_pqc doesn't have a direct extract-public function,
            // so we read the .pub file that was generated alongside.
            let pub_path = key.with_extension("pub");
            if pub_path.exists() {
                let pk_bytes = std::fs::read(&pub_path)?;
                std::fs::write(&output, &pk_bytes)?;
                eprintln!("Exported public key to {}", output.display());
            } else {
                // Fallback: the last 1952 bytes of a 4032-byte ML-DSA-65 secret key
                // are NOT the public key in all implementations. Instead, generate a
                // new keypair and instruct user to use the .pub file.
                drop(secret_key);
                return Err(format!(
                    "Public key file not found at {}. \
                     The .pub file is created alongside the secret key during generation.",
                    pub_path.display()
                )
                .into());
            }
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
