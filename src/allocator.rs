//! The allocator `x0xd` runs with, and the jemalloc options it asks for
//! (#1172).
//!
//! `x0xd` uses jemalloc as its global allocator only when it is built with
//! `--features jemalloc` (and without `profile-heap`). Release builds enable
//! it on Linux and macOS; Windows (MSVC) release builds use the system
//! allocator.
//! jemalloc is prefixed, so only Rust allocations move to it; C code in the
//! process keeps the system `malloc`.
//!
//! `tikv-jemalloc-sys` builds jemalloc with the `_rjem_` symbol prefix, so
//! jemalloc reads its compile-time options from the symbol
//! `_rjem_malloc_conf` (and the environment variable `_RJEM_MALLOC_CONF`),
//! not from `malloc_conf`. The `export_jemalloc_conf!` macro (jemalloc
//! builds only) defines that symbol in the calling binary.

use serde::Serialize;
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use std::alloc::{GlobalAlloc, Layout};
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static JEMALLOC_SERVED: AtomicBool = AtomicBool::new(false);

/// tikv-jemallocator's allocator, which also records that it has served an
/// allocation, so [`allocator_info`] reports the allocator the process
/// really installed rather than the crate feature. Install it with
/// `#[global_allocator]`.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
pub struct GlobalJemalloc;

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
// SAFETY: every method forwards to tikv_jemallocator::Jemalloc with the
// caller's arguments, so its GlobalAlloc contract carries over.
unsafe impl GlobalAlloc for GlobalJemalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        mark_jemalloc_served();
        // SAFETY: forwarded unchanged; see the impl.
        unsafe { tikv_jemallocator::Jemalloc.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        mark_jemalloc_served();
        // SAFETY: forwarded unchanged; see the impl.
        unsafe { tikv_jemallocator::Jemalloc.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; see the impl.
        unsafe { tikv_jemallocator::Jemalloc.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged; see the impl.
        unsafe { tikv_jemallocator::Jemalloc.realloc(ptr, layout, new_size) }
    }
}

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[inline]
fn mark_jemalloc_served() {
    if !JEMALLOC_SERVED.load(Ordering::Relaxed) {
        JEMALLOC_SERVED.store(true, Ordering::Relaxed);
    }
}

/// True once [`GlobalJemalloc`] has served an allocation in this process.
pub fn jemalloc_is_global() -> bool {
    JEMALLOC_SERVED.load(Ordering::Relaxed)
}

/// The jemalloc options `x0xd` asks for: return dirty pages to the OS
/// after about one second and skip the muzzy stage. On Linux glibc a
/// background thread does the purging. Other targets leave it out and purge
/// on the allocation path. On macOS jemalloc has no background-thread
/// support: with `background_thread:true` it prints "option
/// background_thread currently supports pthread only", its initialisation
/// returns an error and the process carries on with jemalloc partly
/// initialised (`opt.narenas` 0, one arena). On musl jemalloc itself has the
/// support, but tikv-jemalloc-sys marks musl as not supported, so it is left
/// off; run-time behaviour on musl is untested.
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

/// The process's global allocator, reported in `GET /status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AllocatorInfo {
    /// `"jemalloc"` or `"system"`.
    pub name: &'static str,
    /// The effective jemalloc options when `name` is `"jemalloc"` and the
    /// read succeeded; otherwise `null`.
    pub jemalloc: Option<JemallocOptions>,
}

/// The process's global allocator: `"jemalloc"` when [`GlobalJemalloc`] is
/// installed (it has served an allocation), otherwise `"system"`.
/// jemalloc's options are fixed at initialisation, so the answer is read
/// once and cached. A call before the first allocation would cache
/// `"system"` for good; `x0xd` allocates long before it serves `/status`.
/// In a single-process `cargo test` run, `global_jemalloc_records_that_it_served`
/// sets the flag, so a later first call there may report `"jemalloc"`.
pub fn allocator_info() -> AllocatorInfo {
    static INFO: OnceLock<AllocatorInfo> = OnceLock::new();
    *INFO.get_or_init(|| allocator_info_for(jemalloc_is_global()))
}

fn allocator_info_for(jemalloc_global: bool) -> AllocatorInfo {
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    if jemalloc_global {
        return AllocatorInfo {
            name: "jemalloc",
            jemalloc: jemalloc_options().ok(),
        };
    }
    let _ = jemalloc_global;
    AllocatorInfo {
        name: "system",
        jemalloc: None,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    crate::export_jemalloc_conf!();

    /// #1172: the options in `JEMALLOC_CONF` must reach jemalloc. Before the
    /// fix the static was exported as `malloc_conf`, which the prefixed
    /// jemalloc never reads, so it ran with its defaults
    /// (dirty_decay_ms 10000, no background thread). The muzzy assertion
    /// catches nothing on its own: jemalloc 5.3 already defaults
    /// muzzy_decay_ms to 0. Dropping the Linux-glibc gate on
    /// `background_thread:true` fails this test only on a non-glibc host
    /// (macOS); hosted Linux CI cannot see that mutation.
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    #[test]
    fn jemalloc_reads_the_exported_conf() {
        let options = super::jemalloc_options().expect("mallctl opt.* reads");
        assert_eq!(options.dirty_decay_ms, 1000, "{options:?}");
        assert_eq!(options.muzzy_decay_ms, 0, "{options:?}");
        let expect_background = cfg!(all(target_os = "linux", target_env = "gnu"));
        assert_eq!(options.background_thread, expect_background, "{options:?}");
    }

    /// The jemalloc branch must report the values read back from jemalloc.
    /// It is driven directly, because the lib test binary's global
    /// allocator is the system one.
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    #[test]
    fn allocator_info_reports_read_back_jemalloc_options() {
        let info = super::allocator_info_for(true);
        assert_eq!(info.name, "jemalloc");
        let read_back = super::jemalloc_options().expect("mallctl opt.* reads");
        assert_eq!(info.jemalloc, Some(read_back), "{info:?}");
    }

    /// The env var is read after the exported symbol, so the child's
    /// read-back (2345) differs from `JEMALLOC_CONF` (1000).
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    #[test]
    fn allocator_info_reports_env_overridden_dirty_decay() {
        const CHILD: &str = "X0X_ALLOCATOR_TEST_CHILD";
        const NAME: &str = "allocator::tests::allocator_info_reports_env_overridden_dirty_decay";
        if std::env::var_os(CHILD).is_some() {
            let info = super::allocator_info_for(true);
            let options = info.jemalloc.expect("jemalloc options");
            assert_eq!(options.dirty_decay_ms, 2345, "{info:?}");
            return;
        }
        let exe = std::env::current_exe().expect("test executable");
        let out = std::process::Command::new(exe)
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("_RJEM_MALLOC_CONF", "dirty_decay_ms:2345")
            .output()
            .expect("re-run the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child failed:\n{stdout}\n{stderr}"
        );
    }

    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    fn thread_counters() -> (u64, u64) {
        // SAFETY: NUL-terminated keys; jemalloc declares both as uint64_t.
        unsafe {
            (
                tikv_jemalloc_ctl::raw::read::<u64>(b"thread.allocated\0").expect("allocated"),
                tikv_jemalloc_ctl::raw::read::<u64>(b"thread.deallocated\0").expect("deallocated"),
            )
        }
    }

    /// Every path must reach jemalloc: jemalloc's per-thread counters move
    /// only for its own allocations, so a forward to the system allocator
    /// fails here (or aborts on the foreign pointer).
    #[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
    #[test]
    fn global_jemalloc_records_that_it_served() {
        use std::alloc::{GlobalAlloc, Layout};
        let jem = super::GlobalJemalloc;
        let small = Layout::from_size_align(64, 8).expect("layout");
        const BIG: usize = 64 * 1024;
        // SAFETY: non-zero layouts; each pointer is resized and freed with
        // the layout it currently has, through the same allocator.
        unsafe {
            let (a0, _) = thread_counters();
            let ptr = jem.alloc(small);
            assert!(!ptr.is_null());
            let (a1, _) = thread_counters();
            assert!(a1 > a0, "alloc did not reach jemalloc");
            std::ptr::write_bytes(ptr, 0xAB, small.size());

            let grown = jem.realloc(ptr, small, BIG);
            assert!(!grown.is_null());
            let (a2, _) = thread_counters();
            assert!(a2 > a1, "growing realloc did not reach jemalloc");
            assert_eq!(*grown.add(63), 0xAB);

            let big = Layout::from_size_align(BIG, 8).expect("layout");
            let (a3, d3) = thread_counters();
            let shrunk = jem.realloc(grown, big, 16);
            assert!(!shrunk.is_null());
            let (a4, d4) = thread_counters();
            assert!(
                a4 > a3 || d4 > d3,
                "shrinking realloc did not reach jemalloc"
            );
            assert_eq!(*shrunk.add(15), 0xAB);
            let tiny = Layout::from_size_align(16, 8).expect("layout");
            jem.dealloc(shrunk, tiny);
            let (_, d5) = thread_counters();
            assert!(d5 > d4, "dealloc did not reach jemalloc");

            let (z0, _) = thread_counters();
            let zeroed = jem.alloc_zeroed(big);
            assert!(!zeroed.is_null());
            let (z1, _) = thread_counters();
            assert!(z1 > z0, "alloc_zeroed did not reach jemalloc");
            assert!(std::slice::from_raw_parts(zeroed, BIG)
                .iter()
                .all(|b| *b == 0));
            jem.dealloc(zeroed, big);
        }
        assert!(super::jemalloc_is_global());
    }

    #[test]
    fn allocator_info_follows_the_installed_allocator() {
        let system = super::allocator_info_for(false);
        assert_eq!(system.name, "system");
        assert_eq!(system.jemalloc, None);
        let json = serde_json::to_value(system).expect("serializes");
        assert!(json.get("name").is_some() && json.get("jemalloc").is_some());
        let info = super::allocator_info();
        assert_eq!(info.name == "jemalloc", info.jemalloc.is_some(), "{info:?}");
    }
}
