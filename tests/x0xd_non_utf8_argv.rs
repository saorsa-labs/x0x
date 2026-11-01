//! x0xd collects argv as OS strings: a non-UTF-8 argument must be refused
//! by the flag that consumes it, never panic at collection (#1375).
#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

#[test]
fn x0xd_refuses_a_non_utf8_instance_name_without_panicking() {
    let raw = OsString::from_vec(b"alice\xff".to_vec());
    let output = Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .arg("--name")
        .arg(&raw)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the invalid name must be refused; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "argv collection must not panic; stderr: {stderr}"
    );
    assert!(
        stderr.contains("UTF-8"),
        "the refusal must name the encoding; stderr: {stderr}"
    );
}
