//! #478: the CLI must not panic when its stdout closes early.
//!
//! `x0x routes | head` (or any consumer that exits before reading
//! everything) used to end with `failed printing to stdout: Broken pipe`
//! — the panic replaced the real output and laundered a harness row. The
//! contract is: writing into a closed pipe ends the process silently, the
//! way every other Unix CLI does.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

#[test]
fn routes_into_closed_stdout_exits_silently() {
    // A pipe whose read end is already gone: the very first write hits
    // EPIPE, which is exactly what an early-exiting `| head` produces.
    let (reader, writer) = std::io::pipe().expect("create pipe");
    drop(reader);

    let output = Command::new(env!("CARGO_BIN_EXE_x0x"))
        .arg("routes")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .expect("spawn x0x routes");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
        "x0x routes panicked on EPIPE; stderr: {stderr}"
    );
    let status = output.status;
    assert!(
        status.code() == Some(0) || status.signal() == Some(libc::SIGPIPE),
        "expected silent exit (0 or SIGPIPE), got {status:?}; stderr: {stderr}"
    );
}
