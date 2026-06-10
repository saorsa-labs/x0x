#![cfg(unix)]

use std::error::Error;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

use std::os::unix::fs::PermissionsExt;

static UMASK_LOCK: Mutex<()> = Mutex::new(());

struct UmaskGuard {
    previous: libc::mode_t,
    _lock: MutexGuard<'static, ()>,
}

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Result<Self, Box<dyn Error>> {
        let lock = UMASK_LOCK
            .lock()
            .map_err(|_| "failed to lock umask guard")?;
        // SAFETY: The mutex serializes umask changes within this test process,
        // and Drop restores the previous process umask before the lock is released.
        let previous = unsafe { libc::umask(mask) };
        Ok(Self {
            previous,
            _lock: lock,
        })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: Restores the process umask captured by UmaskGuard::set.
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_x0x-keygen")
}

fn run_generate(secret_path: &Path) -> Result<Output, Box<dyn Error>> {
    let output = Command::new(bin_path())
        .args(["generate", "--output"])
        .arg(secret_path)
        .output()?;
    Ok(output)
}

fn command_failure(output: &Output) -> String {
    format!(
        "status: {:?}\nstderr: {}\nstdout: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    )
}

#[test]
fn generate_creates_secret_key_private_under_permissive_umask() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let secret_path = tempdir.path().join("keypair.secret");
    let _umask = UmaskGuard::set(0)?;

    let output = run_generate(&secret_path)?;
    if !output.status.success() {
        return Err(format!("key generation failed\n{}", command_failure(&output)).into());
    }

    let mode = std::fs::metadata(&secret_path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!("secret key mode was {mode:o}, expected 600").into());
    }

    Ok(())
}

#[test]
fn generate_refuses_to_overwrite_existing_secret_key() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let secret_path = tempdir.path().join("keypair.secret");
    std::fs::write(&secret_path, b"existing secret")?;

    let output = run_generate(&secret_path)?;
    if output.status.success() {
        return Err("key generation unexpectedly overwrote an existing secret key".into());
    }

    let existing = std::fs::read(&secret_path)?;
    if existing != b"existing secret" {
        return Err("existing secret key contents changed".into());
    }

    Ok(())
}
