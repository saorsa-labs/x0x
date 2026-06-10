use std::error::Error;
use std::path::Path;
use std::process::{Command, Output};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x-keygen")
}

fn command_failure(output: &Output) -> String {
    format!(
        "status: {:?}\nstderr: {}\nstdout: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    )
}

fn run_generate(secret_path: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(bin_path())
        .args(["generate", "--output"])
        .arg(secret_path)
        .output()?)
}

fn run_export_public(secret_path: &Path, public_path: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(bin_path())
        .args(["export-public", "--key"])
        .arg(secret_path)
        .args(["--output"])
        .arg(public_path)
        .output()?)
}

fn run_sign(
    secret_path: &Path,
    input_path: &Path,
    signature_path: &Path,
) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(bin_path())
        .args(["sign", "--key"])
        .arg(secret_path)
        .args(["--input"])
        .arg(input_path)
        .args(["--output"])
        .arg(signature_path)
        .output()?)
}

fn run_verify(
    public_path: &Path,
    input_path: &Path,
    signature_path: &Path,
) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(bin_path())
        .args(["verify", "--key"])
        .arg(public_path)
        .args(["--input"])
        .arg(input_path)
        .args(["--signature"])
        .arg(signature_path)
        .output()?)
}

#[test]
fn export_public_derives_public_key_from_secret() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let first_secret = tempdir.path().join("first.secret");
    let second_secret = tempdir.path().join("second.secret");

    let output = run_generate(&first_secret)?;
    if !output.status.success() {
        return Err(format!("first key generation failed\n{}", command_failure(&output)).into());
    }

    let output = run_generate(&second_secret)?;
    if !output.status.success() {
        return Err(format!("second key generation failed\n{}", command_failure(&output)).into());
    }

    let first_sibling_public = first_secret.with_extension("pub");
    let first_public = std::fs::read(&first_sibling_public)?;
    let second_public = std::fs::read(second_secret.with_extension("pub"))?;
    if first_public == second_public {
        return Err("generated identical public keys; cannot exercise stale sibling case".into());
    }

    std::fs::write(&first_sibling_public, &second_public)?;
    let stale_sibling_export = tempdir.path().join("stale-sibling.pub");
    let output = run_export_public(&first_secret, &stale_sibling_export)?;
    if !output.status.success() {
        return Err(format!(
            "export with stale sibling failed\n{}",
            command_failure(&output)
        )
        .into());
    }

    let exported = std::fs::read(&stale_sibling_export)?;
    if exported != first_public {
        return Err("export-public copied a stale sibling public key".into());
    }

    std::fs::remove_file(&first_sibling_public)?;
    let no_sibling_export = tempdir.path().join("no-sibling.pub");
    let output = run_export_public(&first_secret, &no_sibling_export)?;
    if !output.status.success() {
        return Err(format!(
            "export without sibling failed\n{}",
            command_failure(&output)
        )
        .into());
    }

    let exported = std::fs::read(&no_sibling_export)?;
    if exported != first_public {
        return Err("export-public did not derive the public key from the secret key".into());
    }

    let input_path = tempdir.path().join("payload.bin");
    let signature_path = tempdir.path().join("payload.sig");
    std::fs::write(&input_path, b"x0x release payload")?;

    let output = run_sign(&first_secret, &input_path, &signature_path)?;
    if !output.status.success() {
        return Err(format!("sign failed\n{}", command_failure(&output)).into());
    }

    let output = run_verify(&no_sibling_export, &input_path, &signature_path)?;
    if !output.status.success() {
        return Err(format!("verify failed\n{}", command_failure(&output)).into());
    }

    Ok(())
}
