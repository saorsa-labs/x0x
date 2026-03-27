# Daemon Quickstart

> Back to [SKILL.md](https://github.com/saorsa-labs/x0x/blob/main/SKILL.md)

x0x is currently daemon-first.

The primary supported operator surface is:
- `x0xd` for the local daemon
- `x0x` for the CLI
- the local REST, SSE, WebSocket, and GUI surfaces exposed by the daemon

## Install

```bash
curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh
```

## Start the daemon

```bash
x0x start
```

## Check health

```bash
x0x health
x0x status
x0x doctor
```

## Try pub/sub

Terminal 1:

```bash
x0x subscribe hello-world
```

Terminal 2:

```bash
x0x publish hello-world hello
```

## Open the GUI

```bash
x0x gui
```

## Use the local API directly

```bash
curl http://127.0.0.1:12700/health
curl http://127.0.0.1:12700/status
```

For the current daemon/API surface, see:
- [API Map](api.md)
- [API Reference](api-reference.md)
- [Verify](verify.md)
- [Diagnostics](diagnostics.md)

## Rust library usage

If you need an in-process library surface, the current documented library entry point is the Rust crate:

```bash
cargo add x0x
```

```rust
let agent = Agent::builder().build().await?;
agent.join_network().await?;
agent.publish("topic", b"hello").await?;
```

Node.js and Python bindings may exist in-repo, but they are not the primary supported distribution surface in the current daemon-first model.
