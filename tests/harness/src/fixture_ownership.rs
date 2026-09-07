//! Local fixture resource ownership. This does not provide network isolation.

use std::io;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use tempfile::TempDir;

pub(crate) struct FixtureDirectory {
    directory: Option<TempDir>,
    preserve: bool,
}

impl FixtureDirectory {
    pub(crate) fn new_in(parent: &Path) -> io::Result<Self> {
        Ok(Self {
            directory: Some(
                tempfile::Builder::new()
                    .prefix("x0x-test-")
                    .tempdir_in(parent)?,
            ),
            // Setup failures and cancelled startup futures retain diagnostics.
            preserve: true,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory
            .as_ref()
            .expect("owned fixture directory")
            .path()
    }

    pub(crate) fn allow_cleanup(&mut self) {
        self.preserve = false;
    }

    pub(crate) fn preserve(&mut self) {
        self.preserve = true;
    }

    pub(crate) fn clear_api_advertisement(&self) -> io::Result<()> {
        match std::fs::remove_file(self.path().join("api.port")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn advertises_api(
        &self,
        expected: &str,
        last_observed: &mut Option<String>,
    ) -> io::Result<bool> {
        match std::fs::read_to_string(self.path().join("api.port")) {
            Ok(address) => {
                // The daemon publishes with create/truncate then write. Even a
                // valid-looking shorter port can be an incomplete publication.
                let ready = address.trim() == expected;
                *last_observed = Some(address);
                Ok(ready)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if self.preserve || std::thread::panicking() {
            if let Some(directory) = self.directory.take() {
                let path: PathBuf = directory.keep();
                eprintln!("[cluster] retained fixture diagnostics: {}", path.display());
            }
        }
    }
}

/// Temporary admission checks, held until immediately before child spawn.
/// The daemon cannot inherit these listeners, so its own bind remains decisive.
pub(crate) struct PortReservations {
    api: TcpListener,
    quic: UdpSocket,
}

impl PortReservations {
    pub(crate) fn bind(api_port: u16, quic_port: u16) -> io::Result<Self> {
        let api = TcpListener::bind(("127.0.0.1", api_port)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("fixture TCP API port {api_port}: {error}"),
            )
        })?;
        let quic = UdpSocket::bind(("0.0.0.0", quic_port)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("fixture UDP QUIC port {quic_port}: {error}"),
            )
        })?;
        Ok(Self { api, quic })
    }

    pub(crate) fn ports(&self) -> io::Result<(u16, u16)> {
        Ok((
            self.api.local_addr()?.port(),
            self.quic.local_addr()?.port(),
        ))
    }
}

pub(crate) struct OwnedChild(Child);

impl OwnedChild {
    pub(crate) fn new(child: Child) -> Self {
        Self(child)
    }

    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.0.try_wait()
    }

    pub(crate) fn require_stopped(&mut self) -> io::Result<()> {
        match self.try_wait()? {
            Some(_) => Ok(()),
            None => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "refusing to replace a running fixture child; stop it first",
            )),
        }
    }

    pub(crate) fn require_running(&mut self) -> io::Result<()> {
        match self.try_wait()? {
            None => Ok(()),
            Some(status) => Err(io::Error::other(format!(
                "owned fixture child exited: {status}"
            ))),
        }
    }

    pub(crate) fn stop(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.try_wait()? {
            return Ok(status);
        }
        if let Err(error) = self.0.kill() {
            // A child can exit between try_wait and kill. Reap that child only.
            return match self.try_wait() {
                Ok(Some(status)) => Ok(status),
                _ => Err(error),
            };
        }
        self.0.wait()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "[cluster] could not reap owned child {}: {error}",
                self.id()
            );
        }
    }
}
