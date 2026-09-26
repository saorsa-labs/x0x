# x0x

Agent-to-agent gossip network for AI systems. Built on `ant-quic` (QUIC with
post-quantum crypto and NAT traversal) and `saorsa-gossip` (epidemic broadcast,
CRDT sync, pub/sub). Shipped as the `x0x` crate, the `x0xd` daemon (local REST +
WebSocket API) and the `x0x` CLI. Non-Rust apps talk to `x0xd` over HTTP; there
are no FFI bindings.

## Reference docs (read when relevant)
- REST + WebSocket API: `docs/api-reference.md`
- Tests, e2e harnesses, VPS ports: `tests/AGENTS.md`, `TEST_SUITE_GUIDE.md`
- Self-update: `docs/upgrade-system.md` · CI/CD: `docs/cicd.md`
- Trust, connectivity, announcements: `docs/trust-and-connectivity.md`
- Remote exec + ACL: `docs/exec.md`, `docs/design/x0x-exec.md` · Connect ACL: `docs/connect-acl.md`
- Signed-KV legacy compatibility: `docs/legacy-compat.md`
- Named groups: `docs/design/named-groups-full-model.md` · Symphony: `docs/symphony-integration.md`
- Non-Rust integration: `docs/local-apps.md`

## Build and test
- `just --list` for recipes. CI gate: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, and
  `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`.
- `ant-quic` and `saorsa-gossip` are sibling path dependencies (`../ant-quic`,
  `../saorsa-gossip`); CI symlinks them from `.deps/`. `Cargo.lock` is gitignored,
  so a new upstream publish can break a fresh resolve without any x0x change.
- **Running tests needs isolation.** Test daemons join the real network, so test
  execution only runs inside a fresh loopback-only Linux network namespace with
  dropped privileges; macOS/Windows fail closed. Use `just test` / `just test-full`
  or `python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'test(identity)'`
  (contract: `nextest <build flags> -- <runtime flags>`). Plain `cargo test` /
  `cargo nextest run` bypasses the isolation — only use it on a selector you've
  confirmed is inert. Evidence lands in `target/dev-isolation/run-*`.
- Linux cross-build: `cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd`.

## Architecture

Identity is three layers; every ID is SHA-256 of an ML-DSA-65 public key:
- **Machine** (`~/.x0x/machine.key`, auto-generated) — QUIC transport identity; equals the ant-quic PeerId.
- **Agent** (`~/.x0x/agent.key`, auto-generated) — portable across machines.
- **User** (`~/.x0x/user.key`) — optional human identity, **never auto-generated**; issues an `AgentCertificate` binding agent to user.

Keys are bincode-serialized via `storage.rs`, not JSON.

Stack, bottom to top:
1. `network.rs` — wraps `ant_quic::Node`, implements `GossipTransport`. ant-quic owns mDNS, UPnP, bootstrap cache and connection orchestration.
2. `bootstrap.rs` — hard-coded global peers (`DEFAULT_BOOTSTRAP_PEERS`, UDP 5483) are seed hints only, with retry/backoff.
3. `gossip/` — thin orchestration over `saorsa-gossip-*`; `GossipRuntime` owns `PubSubManager`.
4. `presence.rs` — beacons on the Bulk stream, phi-accrual failure detection, FOAF discovery with trust-scoped visibility.
5. `crdt/` (task lists), `kv/` (replicated KV with access policies), `mls/` (group encryption), `groups/` (named groups; DHT-free discovery via social propagation, BLAKE3 tag shards and presence).
6. `server/` + `api/` — `x0xd` REST/WS; `src/api/mod.rs` is the shared endpoint registry that keeps routes and CLI subcommands (`src/cli/`) in sync. `gui/` is embedded HTML via `include_str!`.

Errors: `IdentityError`, `NetworkError`, `PresenceError` in `error.rs`.
`lib.rs` allows `unwrap_used`/`expect_used` crate-wide for tests; production paths still use `?`.

`x0x exec` is off unless the exec ACL (`/etc/x0x/exec-acl.toml`, macOS `/usr/local/etc/x0x/exec-acl.toml`) sets `[exec].enabled = true`.

`x0xd` flags worth knowing: `--name` (multi-instance), `--api-port`,
`--no-hard-coded-bootstrap` (config peers kept), `--relay`, `--check`, `--doctor`.
Example: `x0xd --name alice --api-port 12701 --no-hard-coded-bootstrap`.

## Architecture decisions (ADRs)
Before changing architecture, protocols, storage formats, crypto, network
behaviour, public APIs or operational invariants, check `docs/adr/`. New or
changed decisions go in a Proposed ADR (`docs/adr/TEMPLATE.md`). Accepted ADRs are
immutable — supersede them instead — and only a human marks an ADR Accepted.
