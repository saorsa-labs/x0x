//! Stable M2 recovery actor. Installation and activation remain held.

#[cfg(unix)]
#[path = "../upgrade/launcher/mod.rs"]
mod launcher;

fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "M2 launcher activation is held; no child was started",
    ))
}
