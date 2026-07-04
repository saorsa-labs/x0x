//! Connection ACL (default-closed connectivity policy).
//!
//! v1 delivers a fail-closed policy engine, loopback-only target validation,
//! and a pure gate function — fully tested but **not yet wired** to a runtime
//! forwarder. The T4 forwarder (issue #132) will call
//! [`gate::evaluate_connect_gate`] at its inbound-accept seam after the peer
//! is verified + trusted and before `TcpStream::connect`. No stream code in
//! `network.rs` changes in v1.
//!
//! See ADR-0019 (`docs/adr/0019-connect-acl-default-closed.md`) and the
//! implementation plan
//! (`docs/plans/2026-07-issue-131-connect-acl-plan.md`).
//!
//! # Security model
//! - Default = [`acl::ConnectPolicy::Disabled`] (default-deny for embedders).
//! - Targets are **loopback only** (`127.0.0.0/8`, `::1`) and **numeric IP
//!   only** (no `localhost`); enforced at load time as a hard error.
//! - Matching is **exact** `(agent, machine, SocketAddr)` triples — no ranges,
//!   no CIDR. `127.0.0.1:22` does not grant `\[::1\]:22`.
//! - [`LoadMode`] is **reused** from `exec::acl` so the
//!   missing-at-default-vs-explicit semantics stay bit-identical forever.

pub mod acl;
pub mod diagnostics;
pub mod gate;

pub use crate::exec::acl::LoadMode;
pub use acl::{
    default_connect_acl_path, is_loopback, load_connect_policy, parse_connect_policy, parse_target,
    ConnectAcl, ConnectAclError, ConnectAclSummary, ConnectAllowEntry, ConnectPolicy,
};
pub use diagnostics::{ConnectDiagnostics, ConnectDiagnosticsSnapshot};
pub use gate::{evaluate_connect_gate, ConnectDenialReason};
