# AGENTS.md

This file gives operational guidance to agents working in the x0x repository.

## Repository purpose

- Rust crate (`x0x`) for decentralized agent communication and collaboration.
- `x0xd` local daemon exposing REST APIs on `127.0.0.1:12700`.
- Install and verification scripts for agent onboarding.
- Agent-facing docs in `docs/` and root capability descriptors (`SKILL.md`, `.well-known/agent.json`).

## Build and test

Build release artifacts:

```bash
cargo build --release
```

Run tests:

```bash
cargo test
```

Recommended local checks before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Key project structure

- `src/` - Core Rust library and binaries.
- `src/bin/x0xd.rs` - Local daemon entrypoint.
- `bindings/nodejs/` - Node.js bindings.
- `bindings/python/` - Python bindings (currently partial/stubbed behavior).
- `scripts/` - Install and release-support scripts.
- `docs/` - Agent-facing documentation chunks served at `https://x0x.md/docs/`.
- `.well-known/agent.json` - Machine-readable agent card.
- `SKILL.md` - Agent Skills format capability/instruction file.

## Documentation locations

- Main overview: https://x0x.md/docs/overview.md
- API reference: https://x0x.md/docs/api.md
- Usage patterns: https://x0x.md/docs/patterns.md
- Troubleshooting: https://x0x.md/docs/troubleshooting.md
- Install flow: https://x0x.md/docs/install.md

## Contribution guidance

- Use focused branches (for example: `feat/...`, `fix/...`, `docs/...`).
- Keep changes scoped and atomic; avoid mixing unrelated edits.
- Run build/test checks for touched areas before submitting.
- Open a pull request against `main` with a clear problem statement, change summary, and validation notes.
- Align behavior claims with `docs/overview.md` status markers (`[working]`, `[stub]`, `[planned]`).

## Agent execution notes

- Prefer `x0xd` REST API behavior as the current integration contract.
- Treat planned/stubbed capabilities as non-production unless explicitly implemented and verified.
- When editing agent-facing docs, keep links pointing to `https://x0x.md/...` and keep status markers honest.
