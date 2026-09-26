//! Connect gate — the enforcement seam the forwarder calls.
//!
//! Pure and synchronous (no service, no I/O) so the whole #141-style denial
//! matrix ports as fast unit tests. The T4 forwarder (issue #132) calls
//! [`evaluate_connect_gate`] at its inbound-accept seam **after** the peer is
//! verified + trusted and **before** `TcpStream::connect`.
//!
//! ## Gate order is a security property
//! The order of checks below means an unverified or untrusted peer learns
//! nothing about whether connect is enabled, whether they are listed, or
//! which targets exist. This mirrors `exec/service.rs::handle_request` and
//! its tranche-2 order-pinning tests. Do not reorder without an ADR.

use std::net::SocketAddr;

use serde::Serialize;

use crate::connect::acl::ConnectPolicy;
use crate::identity::{AgentId, MachineId};
use crate::trust::TrustDecision;

/// Why a connect request was denied. Distinct buckets so diagnostics can
/// break denials down without leaking group/target existence to an
/// unverified/untrusted peer (see gate order).
///
/// Mirrors the `DenialReason` trait set from exec (`Serialize`, `Eq`, `Copy`,
/// snake_case) so it drops into the diagnostics map and, in T4, typed error
/// frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectDenialReason {
    /// Peer not cryptographically verified — always the first check.
    UnverifiedSender,
    /// Trust decision was not `Accept` (includes `None` ⇒ rejected, like exec).
    TrustRejected,
    /// No connect ACL configured / `ConnectPolicy::Disabled`.
    ConnectDisabled,
    /// Requested target is not loopback (runtime defense-in-depth; the
    /// allowlist already makes a non-loopback match impossible).
    TargetNotLoopback,
    /// The (agent, machine) pair is not in the ACL.
    AgentMachineNotInAcl,
    /// The pair is in the ACL but the requested target is not in its entry.
    TargetNotAllowed,
    /// ForwardV2 attestation: no valid agent signature / key binding (#204).
    /// Covers missing signature, unknown agent key, key↔id mismatch, and
    /// signature verification failure.
    AttestationFailed,
    /// ForwardV2 attestation: the agent's signature is valid but the agent is
    /// not on the transport-authenticated machine (#204).
    AgentNotOnMachine,
}

/// Pure gate evaluation. The thing v1 must get perfect.
///
/// # Arguments
/// * `verified` — whether the requesting peer is cryptographically verified.
/// * `trust_decision` — local trust decision for the peer (`None` ⇒ reject,
///   mirroring exec).
/// * `policy` — the loaded [`ConnectPolicy`].
/// * `agent_id` / `machine_id` — the requesting peer's identity pair.
/// * `target` — the requested loopback target.
///
/// # Returns
/// `Ok(())` to allow; `Err(reason)` to deny. The caller records the reason
/// in diagnostics and, in T4, surfaces it to the peer as a typed frame.
///
/// # Gate order (do not reorder — see module docs)
/// 1. `!verified` ⇒ [`ConnectDenialReason::UnverifiedSender`]
/// 2. `trust_decision != Some(Accept)` ⇒ [`ConnectDenialReason::TrustRejected`]
/// 3. `ConnectPolicy::Disabled` ⇒ [`ConnectDenialReason::ConnectDisabled`]
/// 4. `!target.ip().is_loopback()` ⇒ [`ConnectDenialReason::TargetNotLoopback`]
/// 5. pair not in ACL ⇒ [`ConnectDenialReason::AgentMachineNotInAcl`]
/// 6. target not in that entry ⇒ [`ConnectDenialReason::TargetNotAllowed`]
///
/// Exact-pair entries only; `principal = "owner"` entries never match here.
/// Use [`evaluate_connect_gate_for_principal`] where owner trust is known.
pub fn evaluate_connect_gate(
    verified: bool,
    trust_decision: Option<TrustDecision>,
    policy: &ConnectPolicy,
    agent_id: &AgentId,
    machine_id: &MachineId,
    target: &SocketAddr,
) -> Result<(), ConnectDenialReason> {
    evaluate_connect_gate_for_principal(
        verified,
        trust_decision,
        policy,
        agent_id,
        machine_id,
        false,
        target,
    )
}

/// [`evaluate_connect_gate`] with the ADR-0070 §1 owner-trust input.
///
/// Same gate order. Steps 5–6 additionally match `principal = "owner"`
/// entries, but only when `owner_trusted` (established by
/// [`crate::owner_trust`]). Owner trust without an owner entry grants
/// nothing: the pair must still be listed, and every target is exact.
pub fn evaluate_connect_gate_for_principal(
    verified: bool,
    trust_decision: Option<TrustDecision>,
    policy: &ConnectPolicy,
    agent_id: &AgentId,
    machine_id: &MachineId,
    owner_trusted: bool,
    target: &SocketAddr,
) -> Result<(), ConnectDenialReason> {
    // 1. Unverified peers learn nothing.
    if !verified {
        return Err(ConnectDenialReason::UnverifiedSender);
    }
    // 2. None ⇒ rejected (same as exec: absence of an accept decision denies).
    if trust_decision != Some(TrustDecision::Accept) {
        return Err(ConnectDenialReason::TrustRejected);
    }
    // 3. Disabled policy.
    let ConnectPolicy::Enabled(acl) = policy else {
        return Err(ConnectDenialReason::ConnectDisabled);
    };
    // 4. Runtime defense-in-depth: re-check loopback at the gate so the
    //    invariant stays local even if a future matcher generalizes.
    if !crate::connect::acl::is_loopback(target.ip()) {
        return Err(ConnectDenialReason::TargetNotLoopback);
    }
    // 5 + 6. Exact-pair (or owner principal) + exact-target match.
    if !acl.is_allowed_for_principal(agent_id, machine_id, owner_trusted, target) {
        // Distinguish "pair unknown" from "pair known, target wrong" only for
        // diagnostics — both are deny. We split because the T4 forwarder's
        // diagnostics surface benefits from the distinction, and the peer has
        // already passed verified+trust+disabled+loopback by here, so revealing
        // the pair-vs-target split leaks nothing an authenticated member
        // couldn't already derive.
        return Err(
            if acl.has_entry_for_principal(agent_id, machine_id, owner_trusted) {
                ConnectDenialReason::TargetNotAllowed
            } else {
                ConnectDenialReason::AgentMachineNotInAcl
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::connect::acl::{ConnectAcl, ConnectAllowEntry, ConnectPolicy};
    use crate::exec::acl::{parse_agent_id, parse_machine_id};
    use crate::trust::TrustDecision;
    use std::net::SocketAddr;
    use std::path::Path;

    fn enabled_acl_with(agent: &str, machine: &str, targets: &[&str]) -> ConnectPolicy {
        let agent_id = parse_agent_id(&agent.repeat(32)).unwrap();
        let machine_id = parse_machine_id(&machine.repeat(32)).unwrap();
        let targets: Vec<SocketAddr> = targets.iter().map(|t| t.parse().unwrap()).collect();
        ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: Path::new("/tmp/x").to_path_buf(),
            loaded_at_unix_ms: 0,
            allow: vec![ConnectAllowEntry {
                description: None,
                agent_id,
                machine_id,
                targets,
            }],
            owner_allow: Vec::new(),
        })
    }

    fn pair() -> (crate::identity::AgentId, crate::identity::MachineId) {
        (
            parse_agent_id(&"ab".repeat(32)).unwrap(),
            parse_machine_id(&"cd".repeat(32)).unwrap(),
        )
    }

    const T22: &str = "127.0.0.1:22";

    // ── Per-gate tests ────────────────────────────────────────────────────

    #[test]
    fn gate_denies_unverified_sender_before_policy() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        // Even with a valid ACL + accept trust, unverified ⇒ UnverifiedSender.
        let r = evaluate_connect_gate(false, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::UnverifiedSender));
    }

    #[test]
    fn gate_denies_non_accept_trust_decision() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        // AcceptWithFlag is NOT Accept ⇒ reject.
        let r = evaluate_connect_gate(
            true,
            Some(TrustDecision::AcceptWithFlag),
            &policy,
            &a,
            &m,
            &target,
        );
        assert_eq!(r, Err(ConnectDenialReason::TrustRejected));
    }

    #[test]
    fn gate_denies_verified_sender_with_no_trust_decision() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        // None ⇒ TrustRejected (same as exec).
        let r = evaluate_connect_gate(true, None, &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::TrustRejected));
    }

    #[test]
    fn gate_denies_when_policy_disabled() {
        let (a, m) = pair();
        let policy = ConnectPolicy::Disabled {
            path: Path::new("/tmp/x").to_path_buf(),
            reason: "test".to_string(),
            loaded_at_unix_ms: 0,
        };
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::ConnectDisabled));
    }

    #[test]
    fn gate_denies_non_loopback_requested_target() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &["10.0.0.1:22"]); // non-loopback in ACL (shouldn't happen post-validation, but test defense-in-depth)
        let target: SocketAddr = "10.0.0.1:22".parse().unwrap();
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::TargetNotLoopback));
    }

    #[test]
    fn gate_denies_pair_not_in_acl() {
        let (a, m) = pair();
        // ACL has a DIFFERENT pair.
        let policy = enabled_acl_with("ff", "ee", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::AgentMachineNotInAcl));
    }

    #[test]
    fn gate_denies_listed_pair_wrong_target() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = "127.0.0.1:23".parse().unwrap(); // wrong port
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::TargetNotAllowed));
    }

    #[test]
    fn gate_denies_wrong_machine_same_agent() {
        let (a, _m) = pair();
        let wrong_machine = parse_machine_id(&"99".repeat(32)).unwrap();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(
            true,
            Some(TrustDecision::Accept),
            &policy,
            &a,
            &wrong_machine,
            &target,
        );
        assert_eq!(r, Err(ConnectDenialReason::AgentMachineNotInAcl));
    }

    #[test]
    fn gate_v4_and_v6_loopback_are_distinct_grants() {
        let (a, m) = pair();
        // ACL grants 127.0.0.1:22 only.
        let policy = enabled_acl_with("ab", "cd", &["127.0.0.1:22"]);
        let v6: SocketAddr = "[::1]:22".parse().unwrap();
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &v6);
        assert_eq!(r, Err(ConnectDenialReason::TargetNotAllowed));
    }

    #[test]
    fn gate_allows_exact_triple() {
        let (a, m) = pair();
        let policy = enabled_acl_with("ab", "cd", &[T22]);
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(true, Some(TrustDecision::Accept), &policy, &a, &m, &target);
        assert!(r.is_ok());
    }

    // ── Gate-order security property (tranche-2) ──────────────────────────

    #[test]
    fn gate_order_unverified_beats_trust_and_disabled() {
        // All-bad input: unverified + non-accept trust + disabled policy.
        // The ONLY surfaced reason must be UnverifiedSender — an unverified
        // peer learns nothing about trust/policy/targets.
        let (a, m) = pair();
        let policy = ConnectPolicy::default(); // Disabled
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(false, None, &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::UnverifiedSender));
    }

    #[test]
    fn gate_order_trust_beats_disabled() {
        // Verified but untrusted + disabled: TrustRejected, not ConnectDisabled.
        let (a, m) = pair();
        let policy = ConnectPolicy::default();
        let target: SocketAddr = T22.parse().unwrap();
        let r = evaluate_connect_gate(true, None, &policy, &a, &m, &target);
        assert_eq!(r, Err(ConnectDenialReason::TrustRejected));
    }

    fn owner_only_acl(targets: &[&str]) -> ConnectPolicy {
        ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: Path::new("/tmp/x").to_path_buf(),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow: vec![crate::connect::acl::ConnectOwnerEntry {
                description: None,
                targets: targets.iter().map(|t| t.parse().unwrap()).collect(),
            }],
        })
    }

    #[test]
    fn owner_principal_gate_matrix() {
        // ADR-0070 §1 + PR #896 decision 1: owner trust opens connect only
        // through an explicit `principal = "owner"` entry, only to its exact
        // targets, and never for a pair that is not owner-trusted.
        let (a, m) = pair();
        let t22: SocketAddr = T22.parse().unwrap();
        let t80: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let accept = Some(TrustDecision::Accept);

        // Owner-trusted, no owner entry ⇒ denied.
        let no_owner = enabled_acl_with("cd", "ef", &[T22]);
        assert_eq!(
            evaluate_connect_gate_for_principal(true, accept, &no_owner, &a, &m, true, &t22),
            Err(ConnectDenialReason::AgentMachineNotInAcl)
        );

        let owner = owner_only_acl(&[T22]);
        assert_eq!(
            evaluate_connect_gate_for_principal(true, accept, &owner, &a, &m, true, &t22),
            Ok(())
        );
        // Not owner-trusted ⇒ the owner entry does not name this pair.
        assert_eq!(
            evaluate_connect_gate_for_principal(true, accept, &owner, &a, &m, false, &t22),
            Err(ConnectDenialReason::AgentMachineNotInAcl)
        );
        // Ports stay explicit.
        assert_eq!(
            evaluate_connect_gate_for_principal(true, accept, &owner, &a, &m, true, &t80),
            Err(ConnectDenialReason::TargetNotAllowed)
        );
        // The legacy entry point never matches owner entries.
        assert_eq!(
            evaluate_connect_gate(true, accept, &owner, &a, &m, &t22),
            Err(ConnectDenialReason::AgentMachineNotInAcl)
        );
        // The gate does not raise trust itself: a non-Accept decision is
        // still refused first.
        assert_eq!(
            evaluate_connect_gate_for_principal(
                true,
                Some(TrustDecision::Unknown),
                &owner,
                &a,
                &m,
                true,
                &t22
            ),
            Err(ConnectDenialReason::TrustRejected)
        );
    }
}
