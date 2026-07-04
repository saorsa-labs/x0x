#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Property-based soundness tests for the connect ACL (matrix E from the plan).
//!
//! Four properties:
//!
//! 1. **`parse_target_never_panics`** — arbitrary String input never panics;
//!    the function always returns `Ok` or `Err`.
//! 2. **`parse_target_soundness_ipv4`** — for arbitrary `(u8,u8,u8,u8)` + `u16`
//!    port, `parse_target` accepts **iff** `first_octet == 127` **and** `port != 0`.
//!    This is the loopback-only crown jewel for IPv4.
//! 3. **`parse_target_soundness_ipv6`** — for arbitrary `Ipv6Addr` + `u16` port,
//!    `parse_target` accepts **iff** `ip == ::1` **and** `port != 0`.
//!    Automatically proves v4-mapped IPv6 rejection (v4-mapped is never `::1`).
//! 4. **`parse_target_accepted_round_trips`** — any target `parse_target` accepts
//!    re-formats to a string and re-parses to an equal `SocketAddr`.
//! 5. **`matcher_soundness_no_false_accepts`** — `is_allowed(a, m, t) == true`
//!    implies the exact `(agent_id, machine_id, target)` triple is present in
//!    the allowlist. No false accepts, ever.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;

use proptest::prelude::*;
use x0x::connect::{parse_target, ConnectAcl, ConnectAllowEntry};
use x0x::identity::{AgentId, MachineId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal `ConnectAcl` from raw entry tuples.
fn make_acl(entries: Vec<([u8; 32], [u8; 32], Vec<SocketAddr>)>) -> ConnectAcl {
    ConnectAcl {
        loaded_from: PathBuf::from("/tmp/proptest.toml"),
        loaded_at_unix_ms: 0,
        allow: entries
            .into_iter()
            .map(|(a, m, targets)| ConnectAllowEntry {
                description: None,
                agent_id: AgentId(a),
                machine_id: MachineId(m),
                targets,
            })
            .collect(),
    }
}

/// Build a loopback `SocketAddr` with port clamped to `1..=65535`.
fn loopback_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port.max(1)))
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    // --- Property 1: parse_target never panics on arbitrary String --------

    /// `parse_target` must never panic, regardless of input. Any rejection
    /// must surface as `Err(String)`, not as a `panic!` / `unwrap` / assertion.
    #[test]
    fn parse_target_never_panics(s in ".*") {
        let _ = parse_target(&s);
    }

    // --- Property 2a: IPv4 soundness — the loopback crown jewel ----------

    /// For any 4-octet IPv4 address and any `u16` port, `parse_target` accepts
    /// the address **iff** `first_octet == 127` **and** `port != 0`.
    ///
    /// `Ipv4Addr::is_loopback()` covers all of `127.0.0.0/8`, so any first
    /// octet of `127` is loopback regardless of the remaining octets.
    #[test]
    fn parse_target_soundness_ipv4(
        o1 in any::<u8>(),
        o2 in any::<u8>(),
        o3 in any::<u8>(),
        o4 in any::<u8>(),
        port in any::<u16>(),
    ) {
        let ip = Ipv4Addr::new(o1, o2, o3, o4);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let raw = addr.to_string();
        let result = parse_target(&raw);

        let should_accept = o1 == 127 && port != 0;
        if should_accept {
            prop_assert!(
                result.is_ok(),
                "expected accept for {raw} (first_octet={o1}, port={port}), got: {:?}",
                result
            );
        } else {
            prop_assert!(
                result.is_err(),
                "expected reject for {raw} (first_octet={o1}, port={port}), got Ok({:?})",
                result
            );
        }
    }

    // --- Property 2b: IPv6 soundness — also proves v4-mapped rejection ---

    /// For any `Ipv6Addr` and any `u16` port, `parse_target` accepts **iff**
    /// `ip == ::1` **and** `port != 0`.
    ///
    /// This automatically proves that IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
    /// is rejected: it is never `::1`, so the property fails for it — exactly
    /// what the security model requires.
    #[test]
    fn parse_target_soundness_ipv6(
        a in any::<u16>(),
        b in any::<u16>(),
        c in any::<u16>(),
        d in any::<u16>(),
        e in any::<u16>(),
        f in any::<u16>(),
        g in any::<u16>(),
        h in any::<u16>(),
        port in any::<u16>(),
    ) {
        let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
        let raw = addr.to_string();
        let result = parse_target(&raw);

        let is_loopback_v6 = ip == Ipv6Addr::LOCALHOST; // exactly ::1
        let should_accept = is_loopback_v6 && port != 0;
        if should_accept {
            prop_assert!(
                result.is_ok(),
                "expected accept for {raw} (ip={ip}, port={port}), got: {:?}",
                result
            );
        } else {
            prop_assert!(
                result.is_err(),
                "expected reject for {raw} (ip={ip}, port={port}), got Ok({:?})",
                result
            );
        }
    }

    // --- Property 3: round-trip ------------------------------------------

    /// Any target `parse_target` accepts re-formats to a canonical string and
    /// re-parses to the identical `SocketAddr`. The set of accepted targets is
    /// stable under the `Display` → `parse_target` round-trip.
    ///
    /// Uses the IPv4 loopback range directly (all of `127.x.x.x`, port `1..=65535`)
    /// as the accepted domain — simpler than filtering with `prop_assume`.
    #[test]
    fn parse_target_accepted_round_trips(
        o2 in any::<u8>(),
        o3 in any::<u8>(),
        o4 in any::<u8>(),
        port in 1u16..=65535u16,
    ) {
        let ip = Ipv4Addr::new(127, o2, o3, o4);
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let raw = addr.to_string();

        let first = parse_target(&raw)
            .expect("127.x.x.x with port 1-65535 must be accepted");
        let second = parse_target(&first.to_string())
            .expect("re-formatted accepted target must parse again");

        prop_assert_eq!(first, second);
    }

    // --- Property 4: matcher soundness — no false accepts ----------------

    /// `ConnectAcl::is_allowed(a, m, t) == true` implies the exact
    /// `(agent_id, machine_id, target)` triple is present in the allowlist.
    ///
    /// This is a membership / no-false-accept test: the matcher must never
    /// grant access to a triple that was not explicitly inserted. It does NOT
    /// test that every inserted triple is granted (that is a unit-test concern);
    /// it asserts the security invariant — allowlist membership is necessary.
    #[test]
    fn matcher_soundness_no_false_accepts(
        entries in prop::collection::vec(
            (
                prop::array::uniform32(any::<u8>()), // agent_id bytes
                prop::array::uniform32(any::<u8>()), // machine_id bytes
                prop::collection::vec(1u16..=65535u16, 1..=3usize), // port list
            ),
            0..=5usize,
        ),
        query_agent  in prop::array::uniform32(any::<u8>()),
        query_machine in prop::array::uniform32(any::<u8>()),
        query_port   in 1u16..=65535u16,
    ) {
        // Build the ACL from the generated allowlist.
        let allow_entries: Vec<([u8; 32], [u8; 32], Vec<SocketAddr>)> = entries
            .iter()
            .map(|(a, m, ports)| {
                let targets = ports.iter().map(|&p| loopback_addr(p)).collect();
                (*a, *m, targets)
            })
            .collect();

        let acl = make_acl(allow_entries);
        let query_addr     = loopback_addr(query_port);
        let query_agent_id = AgentId(query_agent);
        let query_machine_id = MachineId(query_machine);

        let allowed = acl.is_allowed(&query_agent_id, &query_machine_id, &query_addr);

        if allowed {
            // Security invariant: the exact triple must exist in the source list.
            let found = entries.iter().any(|(a, m, ports)| {
                *a == query_agent
                    && *m == query_machine
                    && ports.iter().any(|&p| loopback_addr(p) == query_addr)
            });
            prop_assert!(
                found,
                "is_allowed returned true for ({:?}, {:?}, {query_addr}) \
                 but the triple is not in the allowlist",
                AgentId(query_agent),
                MachineId(query_machine),
            );
        }
    }
}
