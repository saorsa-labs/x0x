# Implementation plan — Issue #131: Connection ACL (default-closed connectivity policy)
(Produced by plan-131 read-only planning agent, 2026-07-03. Hand verbatim to the implementation agent.)
(ORCHESTRATOR NOTE: ADR number collision with plan-130 — use ADR-0019 for this one, docs/adr/0019-connect-acl-default-closed.md; key lifecycle takes 0018.)

## 0. Scoping decision (read first)

**What v1 can genuinely enforce today: nothing at runtime — and that is by design.** The per-peer byte-stream API is Tailnet Phase 1 (#132/T1) and does not exist yet: `src/network.rs` exposes only message-level `Node::send`/`recv` (framing `[0x10][agent_id:32][payload]`, `network.rs:2313-2360`); ant-quic's `open_bi()/accept_bi()` are public but unused by x0x. There is **no existing inbound flow to gate**: direct-message streams, exec frames, gossip, and file transfer are message surfaces with their own gates — do **not** touch them. The release plan doc (`docs/plans/2026-07-production-hardening-and-tailnet.md:183-192`, section T3) confirms this: T3 (this issue) is a hard prereq gate that "blocks T4 enablement"; enforcement is wired in T4's forward-accept path.

**The v1 deliverable is therefore:** a fail-closed policy engine (`ConnectPolicy`), the config-file surface (`connect-acl.toml`), `--connect-acl` flag + `x0xd --check` validation, a `/diagnostics/connect` counter surface, and — critically — a **pure gate-evaluation function** that encodes the full deny-gate ordering, fully tested against the exec ACL's default-deny matrix. The T4 forwarder's accept path calls that one function; nothing else changes when enforcement lands. The enforcement hook is stubbed at that seam (a callable function with no caller yet), not as dead code in `network.rs`.

Everything below is modeled line-by-line on the exec ACL: `src/exec/acl.rs` (937 lines), `src/exec/service.rs` gate order (`service.rs:756-800`), `src/exec/diagnostics.rs`, and the #124/#141 tranche-2 test matrix (`service.rs:~2643-2700`, `tests/exec_acl_unit.rs`).

---

## 1. New module: `src/connect/`

Register `pub mod connect;` in `src/lib.rs` (insert near `pub mod exec;` at `lib.rs:157`; rustdoc required — CI uses `RUSTDOCFLAGS="-D warnings"`). Note: `src/cli/commands/connect.rs` already exists (four-word `x0x connect` command) — no code collision (different namespace), but don't rename it and don't put the new CLI handler there (see §4).

### 1.1 `src/connect/acl.rs` — policy types, load, parse, validate

Mirror `src/exec/acl.rs` structurally, item for item:

| Exec item (src/exec/acl.rs) | Connect mirror |
|---|---|
| `default_exec_acl_path()` (acl.rs:10-19) | `default_connect_acl_path()` → `/usr/local/etc/x0x/connect-acl.toml` (macOS), `/etc/x0x/connect-acl.toml` (elsewhere) |
| `LoadMode` (acl.rs:23-28) | **reused, not duplicated** — see below |
| `ExecPolicy::{Disabled{path,reason,loaded_at_unix_ms}, Enabled(ExecAcl)}` (acl.rs:32-39) | `ConnectPolicy::{Disabled{…}, Enabled(ConnectAcl)}` |
| `Default for ExecPolicy` = Disabled (acl.rs:41-52) | `Default for ConnectPolicy` = `Disabled{reason: "no connect ACL configured"}` — makes embedded `serve()` (issue #110) default-deny with zero host effort |
| `enabled()/path()/summary()` (acl.rs:57-94) | same; `ConnectAclSummary { enabled, loaded_from, loaded_at_unix_ms, allow_entry_count, target_entry_count, disabled_reason }` |
| `ExecAcl` (acl.rs:112-119) | `ConnectAcl { loaded_from: PathBuf, loaded_at_unix_ms: u64, allow: Vec<ConnectAllowEntry> }` — **no caps struct in v1** (per-peer stream limits are T4 forwarder config, not ACL policy — Rule 2) |
| `AllowEntry` (acl.rs:155-161) | `ConnectAllowEntry { description: Option<String>, agent_id: AgentId, machine_id: MachineId, targets: Vec<SocketAddr> }` |
| `AclError` (acl.rs:188-207) | `ConnectAclError::{Missing, Read, Parse, Invalid}` (thiserror, same shapes) |
| `load_exec_policy()` (acl.rs:289-313) | `load_connect_policy(path: Option<&Path>, mode: LoadMode) -> Result<ConnectPolicy, ConnectAclError>` — **byte-for-byte same control flow**: `!exists()` + `ExplicitPath` → `Err(Missing)`; `!exists()` + `DefaultPath` → `Ok(Disabled{reason:"acl_missing"})`; read error → `Err(Read)`; then parse |
| `parse_exec_policy()` (acl.rs:315-402) | `parse_connect_policy(path, loaded_at_unix_ms, text)` — pub for tests and `--check`; TOML parse error → `Err(Parse)`; missing `[connect]` section → `Disabled{"missing_connect_section"}`; `enabled = false` (serde default false) → `Disabled{"connect_disabled"}`; per-entry validation failure → `Err(Invalid)` with `allow[{idx}].targets[{tidx}]: …` context |
| `has_agent_machine()` (acl.rs:490-497) | `ConnectAcl::entry_for(agent_id, machine_id) -> Option<&ConnectAllowEntry>` (exact pair equality) + `is_allowed(agent_id, machine_id, target: &SocketAddr) -> bool` (exact triple) |
| `parse_agent_id/parse_machine_id/parse_32_byte_hex` (acl.rs:560-580) | **reuse the exec ones** — already `pub` in `exec::acl`; import, don't copy |

**LoadMode decision: reuse `crate::exec::acl::LoadMode`, re-exported as `x0x::connect::LoadMode`.** The missing-at-default-vs-explicit semantics MUST stay bit-identical between the two ACLs forever; one type enforces that at compile time and prevents drift. Cost: generalize its two doc comments (acl.rs:24, acl.rs:26 say "disables exec safely" / "configuration error") to ACL-generic wording — a 2-line doc edit, justified Rule-3 deviation to note in the PR. Do **not** hoist to a new shared module — churn for one enum.

**TOML file format** (documented in §5):

```toml
# /etc/x0x/connect-acl.toml
[connect]
enabled = true   # defaults to false when absent

[[connect.allow]]
description = "laptop → this box sshd"
agent_id = "<64 hex chars>"
machine_id = "<64 hex chars>"
targets = ["127.0.0.1:22", "127.0.0.1:5900", "[::1]:8080"]
```

Serde structs: `ConnectFileToml { connect: Option<ConnectSectionToml> }`, `ConnectSectionToml { enabled (default false), allow (default empty) }`, `ConnectAllowEntryToml { description, agent_id: String, machine_id: String, targets: Vec<String> }` — with **one deliberate divergence from exec: `#[serde(deny_unknown_fields)]` on all three structs.** Rationale: in a security allowlist, a misspelled key (`taregts = [...]`, `enable = true`) must fail loudly, not silently yield a different policy. Strictly more fail-closed; the brief's rule is "default-deny in every ambiguous case", and an unrecognized key is ambiguity. Flag in the PR that exec ACL should get the same treatment as a follow-up issue (not in this PR — Rule 3).

### 1.2 Target validation — the loopback-only crown jewel

Validation function `parse_target(raw: &str) -> Result<SocketAddr, String>` (pub, unit- and property-tested in isolation):

1. `raw.parse::<SocketAddr>()` — **numeric IP literals only**. Any parse failure → error. This eliminates the hostname problem class:
   - **`localhost` is rejected** (doesn't parse as `SocketAddr`). Justification for docs + error message: name resolution is ambiguous (`localhost` may resolve to `::1`, `127.0.0.1`, or — via `/etc/hosts` tampering — a non-loopback address; classic rebinding trick). Numeric-only removes the resolver from the TCB. Error must be actionable: `targets must be numeric IP:port (e.g. "127.0.0.1:22" or "[::1]:22"); hostnames such as "localhost" are not accepted`.
   - Rust's parser already rejects leading-zero octets (`127.000.000.1` — octal ambiguity); cover with a test anyway.
2. `addr.port() == 0` → error ("port 0 is not a connectable target").
3. `!addr.ip().is_loopback()` → error naming the address and the v1 policy ("only loopback targets (127.0.0.0/8, ::1) are permitted in this release; LAN/subnet targets are not supported"). `Ipv4Addr::is_loopback()` covers all of 127.0.0.0/8; `Ipv6Addr::is_loopback()` covers exactly `::1`.
4. IPv4-**mapped** IPv6 (`[::ffff:127.0.0.1]:22`): `Ipv6Addr::is_loopback()` is `false` for it, so step 3 already rejects it — fail-closed falls out for free — but add an explicit pinning test, plus a targeted error branch (`ip.to_ipv4_mapped().is_some()`) whose message says "write it as 127.0.0.1:PORT" (diagnosability, not correctness).

**Target grammar decision: exact `host:port` literals only — no port ranges, no port lists, no CIDR.** The plan doc's T3 sketch mentions `"localhost-port-range:8000-8100"`; the release brief overrides to minimal, and that's right: (a) matches exec's exact-argv philosophy; (b) ranges introduce matcher/overlap/fencepost ambiguity in the security-critical path for zero v1 need; (c) a dozen ports is a dozen TOML lines; (d) extension is backward-compatible later (new optional entry key), while removing shipped range syntax would be breaking. State this in the ADR.

Additional entry validation in `parse_connect_policy`: empty `targets` → `Invalid` ("allow[{idx}] must contain at least one target" — mirrors exec's empty-commands rejection at acl.rs:369-374). Duplicate targets within an entry: permitted (harmless; exec doesn't dedup either).

Store validated targets as `Vec<SocketAddr>`; matching is exact `SocketAddr` equality — `127.0.0.1:22` does not grant `[::1]:22`; pin with a test and document.

### 1.3 `src/connect/gate.rs` — the enforcement seam

The function the T4 forwarder will call; the thing v1 must get perfect. Pure and synchronous — no service, no I/O — so the whole #141 matrix ports as fast unit tests:

```rust
pub enum ConnectDenialReason {
    UnverifiedSender, TrustRejected, ConnectDisabled,
    AgentMachineNotInAcl, TargetNotLoopback, TargetNotAllowed,
}

pub fn evaluate_connect_gate(
    verified: bool,
    trust_decision: Option<TrustDecision>,
    policy: &ConnectPolicy,
    agent_id: &AgentId,
    machine_id: &MachineId,
    target: &SocketAddr,
) -> Result<(), ConnectDenialReason>
```

Gate order — a security property in itself, copied from `exec/service.rs::handle_request` (service.rs:756-800) and its tranche-2 order-pinning tests:

1. `!verified` → `UnverifiedSender`
2. `trust_decision != Some(TrustDecision::Accept)` → `TrustRejected` (**`None` falls through to TrustRejected** — same as exec)
3. `ConnectPolicy::Disabled` → `ConnectDisabled`
4. `!target.ip().is_loopback()` → `TargetNotLoopback` — **runtime defense-in-depth**: in T4 the requested target arrives off the wire from the peer; exact-equality matching against a loopback-only allowlist already makes a non-loopback match impossible, but this explicit check keeps the invariant local to the gate, survives any future matcher generalization, and gives a distinct diagnostics bucket
5. pair `(agent_id, machine_id)` not in ACL → `AgentMachineNotInAcl`
6. target not in that entry's `targets` → `TargetNotAllowed`

Write the same block comment exec has (service.rs tranche-2 header): the order means an unverified/untrusted peer learns nothing about whether connect is enabled, whether they're listed, or which targets exist. Mirror exec `DenialReason` traits (`Serialize`, `Hash`, `Eq`, `Copy`, snake_case) so it drops into the diagnostics map and, in T4, typed error frames.

### 1.4 `src/connect/diagnostics.rs` — counter surface

Mirror `src/exec/diagnostics.rs:15-28` at minimal scope: `ConnectDiagnostics { streams_allowed: AtomicU64, streams_denied: AtomicU64, denial_breakdown: Mutex<HashMap<ConnectDenialReason, u64>>, acl_summary: ConnectAclSummary }` with `new(summary)`, `record_allowed()`, `record_denied(reason)` (mirrors diagnostics.rs:60-66), and a `Serialize` snapshot type. No warnings/sessions machinery — that's T4. Counters read 0 until T4 wires calls; that is the intended "counter surface for future connect denials".

### 1.5 `src/connect/mod.rs`

Module rustdoc (state loopback-only v1 and the T4 relationship) + re-exports mirroring `src/exec/mod.rs`: `default_connect_acl_path, load_connect_policy, parse_connect_policy, parse_target, ConnectAcl, ConnectPolicy, ConnectAclSummary, ConnectDenialReason, evaluate_connect_gate, ConnectDiagnostics, ConnectDiagnosticsSnapshot, LoadMode` (re-export of `exec::acl::LoadMode`).

---

## 2. x0xd wiring (`src/bin/x0xd.rs`)

Mirror the exec ACL sites exactly:

- Help text: add `--connect-acl <PATH>  Override default connect ACL path` next to `--exec-acl` (x0xd.rs:75).
- Flag parse: copy the `--exec-acl` block (x0xd.rs:95-109) → `connect_acl_override: Option<PathBuf>` + `connect_acl_load_mode` (`ExplicitPath` iff flag present, else `DefaultPath`).
- Load: immediately after the exec load (x0xd.rs:221-224): `let connect_policy = x0x::connect::load_connect_policy(connect_acl_override.as_deref(), connect_acl_load_mode).await.context("failed to load connect ACL")?;` Placement **before** the `check_only`/`doctor` branches (like exec) means: malformed file, missing-at-explicit-path, or any non-loopback target **prevents daemon startup and fails `--check`** — exactly the issue's requirement (reject at load/--check time, never silently at runtime).
- `--check` block (x0xd.rs:229-234): add `println!("Connect ACL summary: {:#?}", connect_policy.summary());`.
- `ServeOptions` construction (x0xd.rs:246-253): pass `connect_policy`.

**Config-section clarification** (brief said "mirror a `[connect]` config section"): the exec precedent is that the `[exec]` section lives **in the ACL file**, not in the daemon config TOML — the daemon config knows nothing about exec. Mirror exactly: `[connect]` is the section header inside `connect-acl.toml`; no `DaemonConfig` changes. State this in docs so nobody adds a redundant config knob.

## 3. Server state + diagnostics endpoint

- `ServeOptions` (`src/server/state.rs:38-60`): add `pub connect_policy: x0x::connect::ConnectPolicy` with rustdoc noting the `Default` (= Disabled) keeps embedded `serve()` default-deny. `ServeOptions` is `#[derive(Default)]` — `ConnectPolicy`'s Default impl satisfies it.
- `AppState` (same file, `pub(super)`): add `pub(super) connect_policy: Arc<ConnectPolicy>` and `pub(super) connect_diagnostics: Arc<ConnectDiagnostics>`; construct near the `ExecService::spawn` site (`src/server/mod.rs:1011`, AppState fill at :1075): `Arc::new(ConnectDiagnostics::new(options.connect_policy.summary()))`. No service to spawn, no shutdown-ordering impact (pure data — do not touch the #116 teardown sequence at mod.rs:1081-1100).
- Route: `.route("/diagnostics/connect", get(connect_diagnostics_handler))` beside `/diagnostics/exec` (`src/server/mod.rs:1747`); handler mirrors `exec_diagnostics` (mod.rs:15582) — returns the snapshot JSON.
- Registry (`src/api/mod.rs`, entry shape at :239-244): add `EndpointDef { method: Get, path: "/diagnostics/connect", cli_name: "diagnostics connect", description: "Connection-ACL policy summary and stream allow/deny counters", category: "connect" }`. The registry's coverage tests (`tests/api_coverage.rs` / `api_manifest.rs`) will demand route + CLI both exist — that's the point.

**Coordination warning:** the routes/ extraction from `server/mod.rs` (WS1.4, task #3) is in progress on another branch. Keep the `server/mod.rs` diff minimal (one route line, one handler fn, two AppState fields + init) and rebase late; if diagnostics routes have moved to `src/server/routes/` by implementation time, follow wherever `/diagnostics/exec` lives then.

## 4. CLI

`x0x diagnostics connect` — mirror `src/cli/commands/exec.rs:102-106` (`client.get("/diagnostics/exec")` + `print_value`). Do **not** put it in `src/cli/commands/connect.rs` (that's the four-word `x0x connect` command); place the function wherever the `diagnostics` subcommand dispatcher in `src/cli/mod.rs` routes `diagnostics exec`, following that pattern.

## 5. Tests (the security deliverable — mirror the #141 matrices exactly)

**A. Fail-closed load matrix** — unit tests in `src/connect/acl.rs` mirroring `exec/acl.rs:744-841` names one-for-one:
- `load_policy_missing_file_at_default_path_is_disabled`
- `load_policy_missing_file_at_explicit_path_is_hard_error`
- `load_policy_malformed_toml_is_hard_error`
- `load_policy_missing_connect_section_is_disabled`
- `load_policy_enabled_false_is_disabled`
- `default_connect_acl_path_returns_expected`, `connect_policy_path_*`, `connect_policy_enabled_flag`, `connect_policy_default_is_disabled` (pins the embedded-serve default)
- new: `load_policy_unknown_key_is_hard_error` (pins `deny_unknown_fields`)

**B. Loopback-only validation matrix** — every one a **load-time hard error** (`Invalid`), each its own test: `192.168.1.10:80`, `10.0.0.1:22`, `0.0.0.0:80`, `8.8.8.8:53`, `[::]:80`, `[2001:db8::1]:443`, `[fe80::1]:22`, `[::ffff:127.0.0.1]:22` (v4-mapped), `localhost:22` (hostname), `127.0.0.1:0` (port 0), `127.000.000.1:22` (leading zeros), `127.0.0.1` (no port), empty `targets = []`, empty-string target. Accept side: `127.0.0.1:22`, `127.255.255.254:9`, `[::1]:8080` load successfully.

**C. Gate-order matrix** — unit tests on `evaluate_connect_gate` mirroring exec's per-gate + tranche-2 tests (service.rs:2438-2700):
- `gate_denies_unverified_sender_before_policy`
- `gate_denies_non_accept_trust_decision`
- `gate_denies_verified_sender_with_no_trust_decision` (None → TrustRejected)
- `gate_order_unverified_beats_trust_and_disabled` (all-bad input surfaces `UnverifiedSender` only — pins evaluation order; copy exec's comment on why order is a security property)
- `gate_order_trust_beats_disabled`, `gate_denies_when_policy_disabled`, `gate_denies_pair_not_in_acl`, `gate_denies_listed_pair_wrong_target` (same pair, port 23 vs allowed 22 → `TargetNotAllowed`), `gate_denies_wrong_machine_same_agent` + vice versa (exact-pair semantics), `gate_denies_non_loopback_requested_target` (re-check fires even with Enabled policy → `TargetNotLoopback`), `gate_v4_and_v6_loopback_are_distinct_grants`, `gate_allows_exact_triple`.

**D. Integration file** `tests/connect_acl_unit.rs` mirroring `tests/exec_acl_unit.rs` (crate-public-API level: `parse_connect_policy` from TOML strings; `invalid_hex_fails_closed`, `disabled_policy_when_connect_section_missing_or_false`, `missing_default_acl_disables_but_explicit_missing_errors` with tempdir).

**E. Property tests** `tests/connect_acl_proptest.rs` (proptest at `Cargo.toml:103`; pattern precedent `tests/direct_msg_proptest.rs`):
1. `parse_target` never panics on arbitrary `String`.
2. Soundness (crown jewel): for arbitrary `(u32 → Ipv4Addr, u16 port)`, `parse_target` accepts **iff** first octet == 127 **and** port != 0; same for arbitrary `Ipv6Addr` (accepts iff `ip == ::1 && port != 0` — automatically proves v4-mapped rejection).
3. Round-trip: any accepted target re-formats (`to_string`) and re-parses to an equal `SocketAddr`.
4. Matcher soundness: for a random allowlist and random query triples, `is_allowed(a,m,t) == true` ⟹ the exact triple is present (no false accepts, ever).

**F. `--check` end-to-end (small but real):** spawn `x0xd --check --connect-acl <tmp>` (precedent: `X0XD_TEST_BINARY` in daemon integration tests) asserting exit 0 + summary line for a valid file and non-zero for malformed / non-loopback / missing-explicit. If binary-spawn plumbing is disproportionate, cover the same behavior at `load_connect_policy` level (matrices A/B already do) and assert only the valid-file `--check` path in one shell smoke — either way, don't skip silently (Rule 12).

## 6. Docs + ADR

- **`docs/connect-acl.md`** modeled on `docs/exec.md` (what it is / security model / ACL location + LoadMode semantics equivalent to exec.md:27-40 / minimal ACL example / v1 loopback-only rationale incl. the `localhost` and exact-target decisions / relationship to #132 forwarder / diagnostics endpoint). Add to the On-Demand Reference list in `x0x/CLAUDE.md`.
- **`docs/api-reference.md`**: `/diagnostics/connect` entry.
- **ADR `docs/adr/0019-connect-acl-default-closed.md`** (status **Proposed**): decisions = per-flow default-closed ACL mirrored on exec; sibling file `connect-acl.toml`; shared `LoadMode` fail-closed semantics; loopback-only v1 with non-loopback as load-time validation error (LAN/subnet-router = out of scope, future revision); exact `SocketAddr` targets only (extension is additive); numeric-IP-only (no hostname resolution in the TCB); gate order as security property; `deny_unknown_fields` divergence; restart-loaded only (hot-reload explicitly deferred — the issue lists it as an "option"; exec is restart-loaded and v1 mirrors it). The tailnet epic ADR (#132/T8) should reference this ADR rather than restate it.
- Obsidian vault mirror per repo convention after docs land.

## 7. Stepwise task breakdown

| # | Step | Acceptance criteria | Security review? |
|---|------|---------------------|------------------|
| 1 | `src/connect/acl.rs`: types, LoadMode reuse (+2-line doc generalization in exec/acl.rs), `load_connect_policy`, `parse_connect_policy`, `parse_target` | Matrices **A + B** green; clippy `-D warnings`; no unwrap/expect in prod paths; rustdoc complete | **YES — independent review required** (fail-closed load matrix + loopback validation are the crown jewels; every ambiguous case must land on deny/error) |
| 2 | `src/connect/gate.rs`: `ConnectDenialReason` + `evaluate_connect_gate` | Matrix **C** green, incl. all-bad-input order test | **YES** (gate order = information-leak property) |
| 3 | `src/connect/diagnostics.rs` + `mod.rs` re-exports + `lib.rs` registration | record/snapshot round-trip test; denial_breakdown keyed correctly | no |
| 4 | x0xd wiring: flag, help, load-before-check, `--check` summary, `ServeOptions.connect_policy` (+ `server/state.rs` field) | Matrix **F**; manual: `x0xd --check` shows both ACL summaries; malformed file blocks startup, not just --check | **YES** (verify startup-blocking) |
| 5 | AppState fields + `/diagnostics/connect` route/handler + registry entry + CLI `diagnostics connect` | `x0x routes` lists it; api-coverage/manifest tests green; CLI round-trip against live daemon returns snapshot with `enabled:false` by default | no |
| 6 | Property tests (matrix **E**) | all 4 properties pass at default case count; no `#[ignore]` | **YES** (review the properties themselves — a weak property is false assurance) |
| 7 | Docs + ADR 0019 + CLAUDE.md pointer + vault sync | doc TOML examples fed through `parse_connect_policy` in a test; ADR follows TEMPLATE.md | ADR maintainer sign-off |

Steps 1-3 = one PR-sized unit (pure library code, no daemon behavior change); 4-5 a second; 6-7 ride with either. Full gate before each merge: `just check` (fmt, clippy `-D warnings`, nextest all-features, doc build).

## 8. Explicit non-goals (state in the PR)

- No enforcement caller: `evaluate_connect_gate` gets its first caller in T4 (#132 forwarder inbound-accept, after verified+trust, before `TcpStream::connect`). No stream code in `network.rs`.
- No gating of existing DM/exec/gossip/file surfaces — they are not connection-forwarding.
- No hot-reload (restart-loaded, like exec). No port ranges/CIDR/LAN targets. No caps in the ACL file. No `DaemonConfig` section.
- Typed deny **frames** to the peer are T4 (no wire protocol yet); v1's deny output is the `ConnectDenialReason` value + diagnostics counter.

## 9. Risks / open flags

1. **`server/mod.rs` contention** with the in-flight WS1.4 routes extraction (task #3) — keep step 5's diff minimal and rebase last.
2. **`deny_unknown_fields` divergence from exec** — deliberate and safer, but a pattern fork (Rule 7): approve explicitly or strike; if approved, file the exec follow-up issue.
3. **Plan-doc drift**: `docs/plans/2026-07-production-hardening-and-tailnet.md:186` sketches port-range syntax; this plan overrides to exact-only per the release brief — update the plan doc's T3 bullet when this lands so the two documents don't conflict.
4. The 2-line `LoadMode` doc generalization touches `src/exec/acl.rs` — trivially safe, but a touch outside the new module; noted per Rule 3.
