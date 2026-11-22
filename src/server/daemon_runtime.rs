//! The thread and Tokio runtime that drive the `x0xd` daemon (#2083).
//!
//! `x0xd` used to poll its top-level future with `block_on` on the process
//! main thread. The main-thread stack is set by the platform: 8 MiB on Linux
//! and macOS, but 1 MiB on Windows. On a macOS arm64 debug build the
//! `poll` frame of the startup future (`serve_with_options`) alone was
//! 1,380,656 bytes, so a debug `x0xd` on Windows would overflow at start.
//! That is inferred from the frame size; no Windows launch was done.
//! [`run_daemon_runtime`] runs the future on a new thread with an explicit
//! stack size instead, so the stack the daemon gets no longer depends on the
//! platform.
//!
//! The `x0x` CLI had the same fault (#1764): `#[tokio::main]` polled its
//! top-level future on the main thread, and a debug `x0x autostart` on a
//! hosted Windows runner exited with `STATUS_STACK_OVERFLOW`. The CLI uses
//! [`run_cli_runtime`], which shares the thread and runtime setup.

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

/// Name of the thread that drives the `x0x` CLI's top-level future.
pub const CLI_MAIN_THREAD_NAME: &str = "x0x-main";

/// Spawn `thread_name` with a [`DAEMON_THREAD_STACK_BYTES`] stack. On it,
/// build a multi-thread Tokio runtime whose workers have the same stack, and
/// block on the future that `make` returns.
fn spawn_runtime_thread<F, Fut>(
    thread_name: &str,
    role: &'static str,
    make: F,
) -> anyhow::Result<std::thread::JoinHandle<anyhow::Result<Fut::Output>>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future,
    Fut::Output: Send + 'static,
{
    std::thread::Builder::new()
        .name(thread_name.to_string())
        .stack_size(DAEMON_THREAD_STACK_BYTES)
        .spawn(move || {
            Ok(tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(DAEMON_THREAD_STACK_BYTES)
                .build()
                .with_context(|| format!("failed to build the {role} Tokio runtime"))?
                .block_on(make()))
        })
        .with_context(|| format!("failed to spawn the {role} main thread"))
}

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
    spawn_runtime_thread(DAEMON_MAIN_THREAD_NAME, "daemon", make)?
        .join()
        .map_err(|_| anyhow::anyhow!("the daemon main thread panicked"))??
}

/// Run the `x0x` CLI's top-level future like [`run_daemon_runtime`], on a
/// thread named [`CLI_MAIN_THREAD_NAME`], and return its output.
///
/// A panic on the CLI thread is re-raised on the caller with
/// [`std::panic::resume_unwind`]. The panic hook has already printed the
/// message once on the CLI thread, so the process exits with the same status
/// (101) and prints the same message as a panic on the main thread did.
///
/// # Errors
///
/// Returns an error if the thread cannot be spawned or the runtime cannot be
/// built.
pub fn run_cli_runtime<F, Fut>(make: F) -> anyhow::Result<Fut::Output>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future,
    Fut::Output: Send + 'static,
{
    match spawn_runtime_thread(CLI_MAIN_THREAD_NAME, "CLI", make)?.join() {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
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

    /// Set in the child run of
    /// [`daemon_and_worker_threads_have_the_explicit_stack`].
    const PROBE_CHILD_ENV: &str = "X0X_2083_STACK_PROBE_CHILD";

    /// #2083: the daemon thread and the runtime's worker threads both have
    /// [`DAEMON_THREAD_STACK_BYTES`].
    ///
    /// The CI lanes set `RUST_MIN_STACK` to 16 MiB, and std uses it for every
    /// thread spawned without an explicit size, so a probe in this process
    /// would pass without the explicit sizes. This test therefore re-runs
    /// itself in a child process of this test binary with `RUST_MIN_STACK`
    /// removed. In the child, a thread without an explicit size has the
    /// 2 MiB std default, and each 3 MiB probe overflows it and aborts the
    /// child. The parent fails unless the child exits with success.
    #[test]
    fn daemon_and_worker_threads_have_the_explicit_stack() {
        if std::env::var_os(PROBE_CHILD_ENV).is_some() {
            probe_daemon_and_worker_stacks();
            return;
        }
        let output = std::process::Command::new(
            std::env::current_exe().expect("path of this test binary"),
        )
        .args([
            "--exact",
            "server::daemon_runtime::tests::daemon_and_worker_threads_have_the_explicit_stack",
            "--test-threads=1",
            "--nocapture",
        ])
        .env_remove("RUST_MIN_STACK")
        .env(PROBE_CHILD_ENV, "1")
        .output()
        .expect("run the stack-probe child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stack-probe child failed ({}):\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn probe_daemon_and_worker_stacks() {
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

    /// #1764: the CLI future runs on [`CLI_MAIN_THREAD_NAME`], and it and
    /// the runtime's workers have [`DAEMON_THREAD_STACK_BYTES`]. Same child
    /// re-run as [`daemon_and_worker_threads_have_the_explicit_stack`].
    #[test]
    fn cli_and_worker_threads_have_the_explicit_stack() {
        if std::env::var_os(PROBE_CHILD_ENV).is_some() {
            let (name, main, worker) = run_cli_runtime(|| async {
                let name = std::thread::current().name().map(str::to_string);
                let main = touch_probe_stack();
                let worker = tokio::spawn(async { touch_probe_stack() }).await;
                (name, main, worker.ok())
            })
            .expect("CLI runtime");
            assert_eq!(name.as_deref(), Some(CLI_MAIN_THREAD_NAME));
            assert_eq!((main, worker), (1, Some(1)));
            return;
        }
        let output =
            std::process::Command::new(std::env::current_exe().expect("path of this test binary"))
                .args([
                    "--exact",
                    "server::daemon_runtime::tests::cli_and_worker_threads_have_the_explicit_stack",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env_remove("RUST_MIN_STACK")
                .env(PROBE_CHILD_ENV, "1")
                .output()
                .expect("run the stack-probe child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stack-probe child failed ({}):\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// #1764: a CLI-thread panic is re-raised on the caller with its own
    /// payload, so the process keeps the main-thread panic exit status.
    #[test]
    fn cli_thread_panic_is_re_raised_with_its_payload() {
        let caught = std::panic::catch_unwind(|| {
            run_cli_runtime(|| async {
                panic!("deliberate CLI-thread panic");
            })
        });
        let payload = caught.expect_err("a CLI-thread panic must be re-raised");
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some("deliberate CLI-thread panic")
        );
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
