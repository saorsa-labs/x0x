//! The allocator `x0xd` runs with, and the jemalloc options it asks for
//! (#1172).
//!
//! `x0xd` uses jemalloc as its global allocator only when it is built with
//! `--features jemalloc` (and without `profile-heap`). Release builds do not
//! enable that feature yet, so released binaries use the system allocator.
//!
//! `tikv-jemalloc-sys` builds jemalloc with the `_rjem_` symbol prefix, so
//! jemalloc reads its compile-time options from the symbol
//! `_rjem_malloc_conf` (and the environment variable `_RJEM_MALLOC_CONF`),
//! not from `malloc_conf`. The `export_jemalloc_conf!` macro (jemalloc
//! builds only) defines that symbol in the calling binary.

use serde::Serialize;
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use std::ffi::CStr;
use std::sync::OnceLock;

/// The jemalloc options `x0xd` asks for: return dirty pages to the OS
/// after about one second and skip the muzzy stage. On Linux glibc a
/// background thread does the purging. jemalloc has no background-thread
/// support on macOS or musl, and asking for it there makes jemalloc fail to
/// initialise, so those targets leave it out and purge on the allocation
/// path instead.
#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    target_os = "linux",
    target_env = "gnu"
))]
pub const JEMALLOC_CONF: &CStr = c"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0";

/// The jemalloc options `x0xd` asks for (no background thread on this
/// target; see the Linux glibc variant).
#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(all(target_os = "linux", target_env = "gnu"))
))]
pub const JEMALLOC_CONF: &CStr = c"dirty_decay_ms:1000,muzzy_decay_ms:0";

/// Define the `_rjem_malloc_conf` symbol in the calling crate, pointing at
/// [`JEMALLOC_CONF`]. Invoke it once, at item level, in the binary that
/// installs jemalloc as its global allocator. It must be in the binary
/// crate itself so the linker always keeps the definition, which then
/// replaces jemalloc's weak default.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[doc(hidden)]
#[macro_export]
macro_rules! export_jemalloc_conf {
    () => {
        #[allow(non_upper_case_globals, dead_code)]
        #[export_name = "_rjem_malloc_conf"]
        static X0X_JEMALLOC_MALLOC_CONF: ::core::option::Option<&'static ::core::ffi::c_char> =
            // SAFETY: JEMALLOC_CONF is a 'static NUL-terminated string, so
            // the pointer is non-null, aligned and valid for the program's
            // lifetime; jemalloc reads it as a C string.
            ::core::option::Option::Some(unsafe { &*$crate::allocator::JEMALLOC_CONF.as_ptr() });
    };
}

/// The jemalloc options in effect, read back from jemalloc at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JemallocOptions {
    /// `opt.background_thread`.
    pub background_thread: bool,
    /// `opt.dirty_decay_ms` (-1 means never purge).
    pub dirty_decay_ms: i64,
    /// `opt.muzzy_decay_ms` (-1 means never purge).
    pub muzzy_decay_ms: i64,
}

/// Read the effective jemalloc options. This initialises jemalloc if no
/// allocation has used it yet.
///
/// # Errors
///
/// Returns the `mallctl` error if jemalloc rejects a read.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
pub fn jemalloc_options() -> Result<JemallocOptions, tikv_jemalloc_ctl::Error> {
    use tikv_jemalloc_ctl::raw;
    // SAFETY: each name is a NUL-terminated `opt.*` key and the type
    // matches jemalloc's declared type (bool / ssize_t).
    let (background_thread, dirty, muzzy) = unsafe {
        (
            raw::read::<bool>(b"opt.background_thread\0")?,
            raw::read::<libc::ssize_t>(b"opt.dirty_decay_ms\0")?,
            raw::read::<libc::ssize_t>(b"opt.muzzy_decay_ms\0")?,
        )
    };
    Ok(JemallocOptions {
        background_thread,
        dirty_decay_ms: dirty as i64,
        muzzy_decay_ms: muzzy as i64,
    })
}

/// The allocator `x0xd` uses in this build, reported in `GET /status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AllocatorInfo {
    /// `"jemalloc"` or `"system"`.
    pub name: &'static str,
    /// The effective jemalloc options when `name` is `"jemalloc"` and the
    /// read succeeded; otherwise `null`.
    pub jemalloc: Option<JemallocOptions>,
}

/// The allocator `x0xd` uses in this build. jemalloc's options are fixed
/// at initialisation, so they are read once and cached.
pub fn allocator_info() -> AllocatorInfo {
    static INFO: OnceLock<AllocatorInfo> = OnceLock::new();
    *INFO.get_or_init(|| {
        #[cfg(all(
            feature = "jemalloc",
            not(feature = "profile-heap"),
            not(target_env = "msvc")
        ))]
        {
            AllocatorInfo {
                name: "jemalloc",
                jemalloc: jemalloc_options().ok(),
            }
        }
        #[cfg(not(all(
            feature = "jemalloc",
            not(feature = "profile-heap"),
            not(target_env = "msvc")
        )))]
        {
            AllocatorInfo {
                name: "system",
                jemalloc: None,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    crate::export_jemalloc_conf!();

    /// #1172: the options in `JEMALLOC_CONF` must reach jemalloc. Before the
    /// fix the static was exported as `malloc_conf`, which the prefixed
    /// jemalloc never reads, so it ran with its defaults
    /// (dirty_decay_ms 10000, no background thread).
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    #[test]
    fn jemalloc_reads_the_exported_conf() {
        let options = super::jemalloc_options().expect("mallctl opt.* reads");
        assert_eq!(options.dirty_decay_ms, 1000, "{options:?}");
        assert_eq!(options.muzzy_decay_ms, 0, "{options:?}");
        let expect_background = cfg!(all(target_os = "linux", target_env = "gnu"));
        assert_eq!(options.background_thread, expect_background, "{options:?}");
    }

    #[test]
    fn allocator_info_names_the_build_allocator() {
        let info = super::allocator_info();
        let jemalloc_build = cfg!(all(
            feature = "jemalloc",
            not(feature = "profile-heap"),
            not(target_env = "msvc")
        ));
        assert_eq!(info.name == "jemalloc", jemalloc_build, "{info:?}");
        assert_eq!(info.jemalloc.is_some(), jemalloc_build, "{info:?}");
        let json = serde_json::to_value(info).expect("serializes");
        assert!(json.get("name").is_some() && json.get("jemalloc").is_some());
    }
}
