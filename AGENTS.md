# x0x

Agent-to-agent gossip network. Built on `ant-quic` (QUIC, post-quantum crypto,
NAT traversal) and `saorsa-gossip` (pub/sub, CRDT sync). Ships as the `x0x`
crate, the `x0xd` daemon (local REST + WebSocket API) and the `x0x` CLI.
Non-Rust apps talk to `x0xd` over HTTP; there are no FFI bindings.

Docs are in `docs/` (start with `docs/api-reference.md`); test detail is in
`tests/AGENTS.md`.

## Build and test
- `just --list` shows the recipes.
- Required checks on `main`: Format Check, Clippy Lint
  (`cargo clippy --all-targets --all-features -- -D warnings`), Test Suite,
  Documentation (`RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`)
  and Build linux-x64-gnu. CI runs more jobs than these (coverage, parity,
  integration, deployment authority); see `.github/workflows/`.
- `ant-quic` and `saorsa-gossip-*` are exact-pinned crates.io versions and
  `Cargo.lock` is tracked; CI builds with `--locked`. A local `[patch]` to a
  sibling checkout must not be committed.
- Tests can reach the real network: test daemons join it, and some in-process
  tests (for example the `--ignored` VPS tests) dial the real seeds. Run tests
  with `just test` or
  `python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'test(name)'`
  (Linux network namespace; macOS and Windows fail closed). Plain `cargo test`
  or `cargo nextest run` is only for a selector confirmed to open no network.
- Linux cross-build: `cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd`.

## Architecture
Every ID is SHA-256 of an ML-DSA-65 public key:
- **Machine** (`~/.x0x/machine.key`, auto-generated): the QUIC transport identity.
- **Agent** (`~/.x0x/agent.key`, auto-generated): portable across machines.
- **User** (`~/.x0x/user.key`): optional human identity, never auto-generated;
  it issues the `AgentCertificate` that binds an agent to a user.

Keys are bincode via `storage.rs`. Production paths avoid
`unwrap`/`expect`/`panic!` by convention: `lib.rs` allows those clippy lints
crate-wide for tests, so clippy does not catch one.

Layers, bottom to top: `network.rs` (wraps `ant_quic::Node`; seeds in
`DEFAULT_BOOTSTRAP_PEERS` are hints only), `gossip/`, `presence.rs`, then
`crdt/`, `kv/`, `mls/`, `groups/`, then `server/` + `api/` (`src/api/mod.rs` is
the endpoint registry shared by routes and CLI).

`x0x exec` is off unless the exec ACL sets `[exec].enabled = true`
(`/etc/x0x/exec-acl.toml`; macOS `/usr/local/etc/x0x/exec-acl.toml`).

Multi-instance daemon: `x0xd --name alice --api-port 12701 --no-hard-coded-bootstrap`.

## Decisions
- The decision record is the 15 slots A01–A15 in `docs/adr/consolidated/`.
  There are no new ADR files; older numbered records are in `docs/adr-archive/`.
- A slot change is a dated paragraph in the slot plus its sha256 pin in
  `index.json`. Check with `python3 scripts/check-adr-consolidation.py` and
  `python3 scripts/check-adr-count.py`.
- David delegated design and scope decisions on 10 Nov 2026. A PR that changes
  a slot, the wire format or the public API says so in its body.
- Writing style: `docs/documentation-style.md`.
