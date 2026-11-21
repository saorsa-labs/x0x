//! The thread and Tokio runtime that drive the `x0xd` daemon (#2083).
//!
//! `x0xd` used to poll its top-level future with `block_on` on the process
//! main thread. The main-thread stack is set by the platform: 8 MiB on Linux
//! and macOS, but 1 MiB on Windows. The startup future (`serve_with_options`)
//! needed more than 1 MiB of stack in an unoptimised build, so a debug
//! `x0xd` on Windows overflowed at start. [`run_daemon_runtime`] runs the
//! future on a new thread with an explicit stack size instead, so the stack
//! the daemon gets no longer depends on the platform.

use std::future::Future;

use anyhow::Context;

/// Stack size for the thread that drives the daemon's top-level future and
/// for every Tokio worker and blocking-pool thread.
///
/// The Tokio default is 2 MiB. On macOS arm64 a debug x0xd overflowed it when
/// a group owner applied a TreeKEM join: the metadata-apply future chain plus
/// `TreeKemGroup::add_member` signing with ML-DSA-65 (large stack arrays)
/// needed more, and the daemon aborted. Release builds use less stack on this
/// path, but the margin is not measured. 8 MiB matches the main-thread stack
/// on macOS and Linux. It is a virtual reservation; pages are committed only
/// when they are used.
pub const DAEMON_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Name of the thread that drives the daemon's top-level future.
pub const DAEMON_MAIN_THREAD_NAME: &str = "x0xd-main";

/// Run the future that `make` returns to completion on a new multi-thread
/// Tokio runtime, and return its result.
///
/// The future is built and polled on a new thread named
/// [`DAEMON_MAIN_THREAD_NAME`] with a [`DAEMON_THREAD_STACK_BYTES`] stack.
/// The runtime's worker and blocking-pool threads get the same stack size.
/// The calling thread only waits, so its own stack size does not matter.
///
/// # Errors
///
/// Returns an error if the thread cannot be spawned, if the runtime cannot be
/// built, or if the daemon thread panics. Otherwise returns the future's own
/// result.
pub fn run_daemon_runtime<F, Fut, T>(make: F) -> anyhow::Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<T>>,
    T: Send + 'static,
{
    let daemon_thread = std::thread::Builder::new()
        .name(DAEMON_MAIN_THREAD_NAME.to_string())
        .stack_size(DAEMON_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(DAEMON_THREAD_STACK_BYTES)
                .build()
                .context("failed to build the daemon Tokio runtime")?
                .block_on(make())
        })
        .context("failed to spawn the daemon main thread")?;
    daemon_thread
        .join()
        .map_err(|_| anyhow::anyhow!("the daemon main thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{serve_with_options, DaemonConfig, ServeOptions};

    /// A caller stack smaller than any platform main-thread default (Windows
    /// gives 1 MiB). Before #2083 `x0xd` polled the startup future on the
    /// caller's stack, which needed more than 1 MiB in a debug build.
    const SMALL_CALLER_STACK_BYTES: usize = 256 * 1024;

    /// Stack the probes touch: more than the 2 MiB Tokio and libtest
    /// defaults, less than [`DAEMON_THREAD_STACK_BYTES`].
    const PROBE_STACK_BYTES: usize = 3 * 1024 * 1024;

    /// Write `PROBE_STACK_BYTES` of a stack array, so the probe fails with a
    /// stack overflow unless the current thread has that much stack.
    #[inline(never)]
    fn touch_probe_stack() -> u8 {
        let mut buf = [0u8; PROBE_STACK_BYTES];
        let buf = std::hint::black_box(&mut buf);
        for i in (0..PROBE_STACK_BYTES).step_by(4096) {
            buf[i] = 1;
        }
        buf[PROBE_STACK_BYTES - 1] = 1;
        std::hint::black_box(buf[PROBE_STACK_BYTES - 1])
    }

    fn hermetic_config(data_dir: &std::path::Path) -> DaemonConfig {
        let mut config = DaemonConfig {
            data_dir: data_dir.to_path_buf(),
            identity_dir: Some(data_dir.join("identity")),
            api_address: "127.0.0.1:0".parse().expect("loopback api address"),
            bind_address: "127.0.0.1:0".parse().expect("loopback quic address"),
            bootstrap_peers: Some(Vec::new()),
            network_id: Some("issue-2083.daemon-runtime".to_string()),
            mdns_enabled: false,
            ..DaemonConfig::default()
        };
        config.history.enabled = false;
        config
    }

    /// #2083: the daemon future runs on the explicit daemon stack, not on
    /// the caller's. A full hermetic serve and shutdown, driven from a
    /// caller thread with a stack far below the Windows 1 MiB main-thread
    /// default, must complete.
    #[test]
    fn daemon_runtime_serves_from_a_small_caller_stack() {
        let caller = std::thread::Builder::new()
            .name("small-caller".to_string())
            .stack_size(SMALL_CALLER_STACK_BYTES)
            .spawn(|| {
                run_daemon_runtime(|| async {
                    let dir = tempfile::tempdir().context("tempdir")?;
                    let options = ServeOptions {
                        skip_update_check: true,
                        cli_no_port_mapping: true,
                        cli_disable_peer_cache: true,
                        ..ServeOptions::default()
                    };
                    let handle = serve_with_options(hermetic_config(dir.path()), options).await?;
                    handle.shutdown_and_wait().await
                })
            })
            .expect("spawn the small caller thread");
        let result = caller
            .join()
            .expect("the small caller thread must not panic");
        assert!(result.is_ok(), "hermetic serve and shutdown: {result:?}");
    }

    /// #2083: the daemon thread and the runtime's worker threads both have
    /// [`DAEMON_THREAD_STACK_BYTES`]. Each probe uses more stack than the
    /// 2 MiB defaults, so dropping either explicit size fails this test on
    /// every platform.
    #[test]
    fn daemon_and_worker_threads_have_the_explicit_stack() {
        let (main_name, main_probe, worker_probe) = run_daemon_runtime(|| async {
            let main_name = std::thread::current().name().map(str::to_string);
            let main_probe = touch_probe_stack();
            let worker_probe = tokio::spawn(async { touch_probe_stack() })
                .await
                .context("worker probe task")?;
            Ok((main_name, main_probe, worker_probe))
        })
        .expect("daemon runtime");
        assert_eq!(main_name.as_deref(), Some(DAEMON_MAIN_THREAD_NAME));
        assert_eq!((main_probe, worker_probe), (1, 1));
    }

    /// A panic on the daemon thread is returned as an error, not re-raised
    /// on the caller.
    #[test]
    fn daemon_thread_panic_is_an_error() {
        let result: anyhow::Result<()> = run_daemon_runtime(|| async {
            panic!("deliberate daemon-thread panic");
        });
        let err = result.expect_err("a daemon-thread panic must be an error");
        assert!(
            err.to_string().contains("daemon main thread panicked"),
            "{err}"
        );
    }
}
