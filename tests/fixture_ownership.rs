//! Disposable controls for fixture ownership; these never start x0xd.
#![cfg(unix)]

#[path = "harness/src/fixture_ownership.rs"]
mod ownership;

use ownership::{FixtureDirectory, OwnedChild, PortReservations};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn exclusive_directories_preserve_foreign_sentinel() {
    let outer = tempfile::tempdir().unwrap();
    let foreign = outer.path().join("x0x-test-same-name");
    std::fs::create_dir(&foreign).unwrap();
    let sentinel = foreign.join("sentinel");
    std::fs::write(&sentinel, b"unrelated fixture").unwrap();
    let mut first = FixtureDirectory::new_in(outer.path()).unwrap();
    let mut second = FixtureDirectory::new_in(outer.path()).unwrap();
    let first_path = first.path().to_path_buf();
    let second_path = second.path().to_path_buf();
    assert_ne!(first_path, second_path);
    assert_ne!(first_path, foreign);
    std::fs::write(first.path().join("owned"), b"one").unwrap();
    std::fs::write(second.path().join("owned"), b"two").unwrap();
    first.allow_cleanup();
    second.allow_cleanup();
    drop(first);
    assert!(!first_path.exists());
    assert!(second_path.join("owned").exists());
    drop(second);
    assert!(!second_path.exists());
    assert_eq!(std::fs::read(sentinel).unwrap(), b"unrelated fixture");
}

#[test]
fn incomplete_startup_retains_owned_diagnostics() {
    let outer = tempfile::tempdir().unwrap();
    let directory = FixtureDirectory::new_in(outer.path()).unwrap();
    let log = directory.path().join("startup.log");
    std::fs::write(&log, b"failed before readiness").unwrap();
    drop(directory);
    assert_eq!(std::fs::read(log).unwrap(), b"failed before readiness");
}

#[test]
fn panic_and_explicit_preservation_retain_owned_diagnostics() {
    let outer = tempfile::tempdir().unwrap();
    let mut directory = FixtureDirectory::new_in(outer.path()).unwrap();
    let retained = directory.path().to_path_buf();
    directory.allow_cleanup();
    let failure = std::panic::catch_unwind(move || {
        let _owned = directory;
        panic!("intentional disposable fixture failure");
    });
    assert!(failure.is_err());
    assert!(retained.exists());

    let mut directory = FixtureDirectory::new_in(outer.path()).unwrap();
    let retained = directory.path().to_path_buf();
    directory.allow_cleanup();
    directory.preserve();
    drop(directory);
    assert!(retained.exists());
}

#[test]
fn restart_requires_fresh_matching_advertisement_without_deleting_token() {
    let outer = tempfile::tempdir().unwrap();
    let mut directory = FixtureDirectory::new_in(outer.path()).unwrap();
    let advertisement = directory.path().join("api.port");
    let mut last_observed = None;
    let token = directory.path().join("api-token");
    std::fs::write(&advertisement, b"127.0.0.1:29581").unwrap();
    std::fs::write(&token, b"disposable-persistent-token").unwrap();
    assert!(directory
        .advertises_api("127.0.0.1:29581", &mut last_observed)
        .unwrap());
    directory.clear_api_advertisement().unwrap();
    assert!(!directory
        .advertises_api("127.0.0.1:29581", &mut last_observed)
        .unwrap());
    assert_eq!(
        std::fs::read(token).unwrap(),
        b"disposable-persistent-token"
    );
    std::fs::write(&advertisement, b"127.0.0.1:29582").unwrap();
    for _ in 0..3 {
        assert!(!directory
            .advertises_api("127.0.0.1:29581", &mut last_observed)
            .unwrap());
    }
    assert_eq!(last_observed.as_deref(), Some("127.0.0.1:29582"));
    directory.clear_api_advertisement().unwrap();
    std::fs::write(&advertisement, b"127.0.0.1:29581").unwrap();
    assert!(directory
        .advertises_api("127.0.0.1:29581", &mut last_observed)
        .unwrap());
    directory.allow_cleanup();
}

#[test]
fn incomplete_advertisement_waits_for_complete_matching_publication() {
    let outer = tempfile::tempdir().unwrap();
    let mut directory = FixtureDirectory::new_in(outer.path()).unwrap();
    let advertisement = directory.path().join("api.port");
    let expected = "127.0.0.1:29581";
    let mut last_observed = None;
    // Includes empty creation and parseable but incomplete port values.
    for length in 0..expected.len() {
        let partial = &expected[..length];
        std::fs::write(&advertisement, partial).unwrap();
        assert!(!directory
            .advertises_api(expected, &mut last_observed)
            .unwrap());
        assert_eq!(last_observed.as_deref(), Some(partial));
    }
    std::fs::write(&advertisement, expected).unwrap();
    assert!(directory
        .advertises_api(expected, &mut last_observed)
        .unwrap());
    assert_eq!(last_observed.as_deref(), Some(expected));
    directory.allow_cleanup();
}

#[test]
fn occupied_tcp_port_is_refused_without_harming_listener() {
    // Binding fails before any control if this reviewed witness port is in use.
    let listener = TcpListener::bind("127.0.0.1:29581").unwrap();
    let refused = PortReservations::bind(29581, 0);
    assert_eq!(refused.err().unwrap().kind(), std::io::ErrorKind::AddrInUse);
    let mut client =
        TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
            .unwrap();
    client.write_all(b"sentinel").unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 8];
    accepted.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"sentinel");
}

#[test]
fn occupied_udp_port_is_refused_without_harming_listener() {
    let listener = UdpSocket::bind("127.0.0.1:29582").unwrap();
    let refused = PortReservations::bind(0, 29582);
    assert_eq!(refused.err().unwrap().kind(), std::io::ErrorKind::AddrInUse);
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"sentinel", listener.local_addr().unwrap())
        .unwrap();
    listener
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 8];
    let (len, _) = listener.recv_from(&mut bytes).unwrap();
    assert_eq!(len, bytes.len());
    assert_eq!(&bytes, b"sentinel");
}

#[test]
fn reservations_hold_then_release_only_their_own_ports() {
    let reservations = PortReservations::bind(0, 0).unwrap();
    let (api, quic) = reservations.ports().unwrap();
    assert!(TcpListener::bind(("127.0.0.1", api)).is_err());
    assert!(UdpSocket::bind(("0.0.0.0", quic)).is_err());
    drop(reservations);
    let _api = TcpListener::bind(("127.0.0.1", api)).unwrap();
    let _quic = UdpSocket::bind(("0.0.0.0", quic)).unwrap();
}

// Cleanup for a deliberately broken Drop implementation in negative controls.
// waitpid first proves the PID is still OUR unreaped child; ECHILD never signals.
struct UnreapedWitness(libc::pid_t);
impl Drop for UnreapedWitness {
    fn drop(&mut self) {
        // SAFETY: all PIDs come from children spawned by this test. Null status
        // is allowed; a zero waitpid result proves this child is still ours.
        unsafe {
            if libc::waitpid(self.0, std::ptr::null_mut(), libc::WNOHANG) == 0 {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn harmless_child() -> (OwnedChild, UnreapedWitness) {
    let child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let witness = UnreapedWitness(child.id().try_into().unwrap());
    (OwnedChild::new(child), witness)
}

#[test]
fn dropping_owned_child_reaps_it_and_preserves_other_child() {
    let (owned, _owned_witness) = harmless_child();
    let (mut other, _other_witness) = harmless_child();
    let pid: libc::pid_t = owned.id().try_into().unwrap();
    drop(owned);
    // SAFETY: read-only wait on the exact child PID created above.
    let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(result, -1, "fixture Drop must itself reap its child");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(other.try_wait().unwrap().is_none());
    other.stop().unwrap();
}

#[test]
fn live_child_cannot_be_replaced_and_stopped_child_cannot_report_ready() {
    let (mut child, _witness) = harmless_child();
    child.require_running().unwrap();
    assert_eq!(
        child.require_stopped().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(child.try_wait().unwrap().is_none());
    child.stop().unwrap();
    child.require_stopped().unwrap();
    assert!(child.require_running().is_err());
}
