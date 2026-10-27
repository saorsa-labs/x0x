//! W3-H (#1245) keeps filesystem work on the calling task.
//!
//! `tokio::fs` waits on the blocking pool. On a paused runtime that wait is
//! idle, so virtual time auto-advances until the pool thread replies. The
//! reply is a wall-clock race, and the same case moves a different distance.
//! When `W3H_SHIM_ACTIVE=1`, these calls use `std::fs` on the caller.
//! Production builds re-export `tokio::fs` unchanged.

/// Whether this process is a W3-H run with the entropy and clock shim.
pub(crate) fn shim_active() -> bool {
    #[cfg(test)]
    {
        std::env::var_os("W3H_SHIM_ACTIVE").as_deref() == Some(std::ffi::OsStr::new("1"))
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(not(test))]
pub(crate) mod fs {
    pub use tokio::fs::{
        create_dir_all, metadata, read, read_dir, read_to_string, remove_file, rename,
        set_permissions, try_exists, write, File, OpenOptions,
    };
}

#[cfg(test)]
pub(crate) mod fs {
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use super::shim_active;

    pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        if shim_active() {
            std::fs::read(path)
        } else {
            tokio::fs::read(path).await
        }
    }

    pub async fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
        if shim_active() {
            std::fs::read_to_string(path)
        } else {
            tokio::fs::read_to_string(path).await
        }
    }

    pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
        if shim_active() {
            std::fs::write(path, contents)
        } else {
            tokio::fs::write(path, contents).await
        }
    }

    pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        if shim_active() {
            std::fs::rename(from, to)
        } else {
            tokio::fs::rename(from, to).await
        }
    }

    pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
        if shim_active() {
            std::fs::remove_file(path)
        } else {
            tokio::fs::remove_file(path).await
        }
    }

    pub async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
        if shim_active() {
            std::fs::create_dir_all(path)
        } else {
            tokio::fs::create_dir_all(path).await
        }
    }

    pub async fn try_exists(path: impl AsRef<Path>) -> io::Result<bool> {
        if shim_active() {
            match std::fs::metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        } else {
            tokio::fs::try_exists(path).await
        }
    }

    pub async fn metadata(path: impl AsRef<Path>) -> io::Result<std::fs::Metadata> {
        if shim_active() {
            std::fs::metadata(path)
        } else {
            tokio::fs::metadata(path).await
        }
    }

    pub async fn set_permissions(
        path: impl AsRef<Path>,
        perms: std::fs::Permissions,
    ) -> io::Result<()> {
        if shim_active() {
            std::fs::set_permissions(path, perms)
        } else {
            tokio::fs::set_permissions(path, perms).await
        }
    }

    /// Directory entries. Under the shim, names are sorted so a later pass
    /// does not follow filesystem readdir order.
    pub struct ReadDir {
        inner: ReadDirInner,
    }

    enum ReadDirInner {
        Std(std::vec::IntoIter<DirEntry>),
        Tokio(tokio::fs::ReadDir),
    }

    pub struct DirEntry {
        path: PathBuf,
        file_name: OsString,
    }

    impl DirEntry {
        pub fn path(&self) -> PathBuf {
            self.path.clone()
        }

        pub fn file_name(&self) -> OsString {
            self.file_name.clone()
        }
    }

    pub(super) fn sorted_entries(path: &Path) -> io::Result<Vec<DirEntry>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            entries.push(DirEntry {
                path: entry.path(),
                file_name: entry.file_name(),
            });
        }
        entries.sort_by(|left, right| left.file_name.cmp(&right.file_name));
        Ok(entries)
    }

    pub async fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
        if shim_active() {
            return Ok(ReadDir {
                inner: ReadDirInner::Std(sorted_entries(path.as_ref())?.into_iter()),
            });
        }
        Ok(ReadDir {
            inner: ReadDirInner::Tokio(tokio::fs::read_dir(path).await?),
        })
    }

    impl ReadDir {
        pub async fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
            match &mut self.inner {
                ReadDirInner::Std(entries) => Ok(entries.next()),
                ReadDirInner::Tokio(entries) => match entries.next_entry().await? {
                    Some(entry) => Ok(Some(DirEntry {
                        path: entry.path(),
                        file_name: entry.file_name(),
                    })),
                    None => Ok(None),
                },
            }
        }
    }

    pub struct File {
        inner: FileInner,
    }

    enum FileInner {
        Std(std::fs::File),
        Tokio(tokio::fs::File),
    }

    impl File {
        pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
            if shim_active() {
                return Ok(Self {
                    inner: FileInner::Std(std::fs::File::open(path)?),
                });
            }
            Ok(Self {
                inner: FileInner::Tokio(tokio::fs::File::open(path).await?),
            })
        }

        pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
            if shim_active() {
                return Ok(Self {
                    inner: FileInner::Std(std::fs::File::create(path)?),
                });
            }
            Ok(Self {
                inner: FileInner::Tokio(tokio::fs::File::create(path).await?),
            })
        }

        pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            match &mut self.inner {
                FileInner::Std(file) => {
                    use std::io::Write;
                    file.write_all(buf)
                }
                FileInner::Tokio(file) => {
                    use tokio::io::AsyncWriteExt;
                    file.write_all(buf).await
                }
            }
        }

        pub async fn sync_all(&self) -> io::Result<()> {
            match &self.inner {
                FileInner::Std(file) => file.sync_all(),
                FileInner::Tokio(file) => file.sync_all().await,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct OpenOptions {
        write: bool,
        create_new: bool,
        #[cfg(unix)]
        mode: Option<u32>,
    }

    impl OpenOptions {
        pub fn new() -> Self {
            Self {
                write: false,
                create_new: false,
                #[cfg(unix)]
                mode: None,
            }
        }

        pub fn write(&mut self, write: bool) -> &mut Self {
            self.write = write;
            self
        }

        pub fn create_new(&mut self, create_new: bool) -> &mut Self {
            self.create_new = create_new;
            self
        }

        #[cfg(unix)]
        pub fn mode(&mut self, mode: u32) -> &mut Self {
            self.mode = Some(mode);
            self
        }

        pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
            if shim_active() {
                let mut options = std::fs::OpenOptions::new();
                options.write(self.write).create_new(self.create_new);
                #[cfg(unix)]
                if let Some(mode) = self.mode {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(mode);
                }
                return Ok(File {
                    inner: FileInner::Std(options.open(path)?),
                });
            }
            let mut options = tokio::fs::OpenOptions::new();
            options.write(self.write).create_new(self.create_new);
            #[cfg(unix)]
            if let Some(mode) = self.mode {
                options.mode(mode);
            }
            Ok(File {
                inner: FileInner::Tokio(options.open(path).await?),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn directory_entries_are_sorted_by_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("b"), b"b").expect("write b");
        std::fs::write(dir.path().join("a"), b"a").expect("write a");
        let listed = super::fs::sorted_entries(dir.path()).expect("list");
        let names: Vec<_> = listed.into_iter().map(|entry| entry.file_name()).collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("a"), std::ffi::OsString::from("b")]
        );
    }
}
