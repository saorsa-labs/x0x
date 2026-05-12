# x0x-symphony Integration

A decentralized, harness-agnostic agent work orchestration runner lives in
the sibling repo [`../x0x-symphony`](../x0x-symphony). It does not link x0x
as a Rust crate; it consumes x0xd's local REST/WebSocket API.

From x0x's perspective:

- **What x0x ships for symphony**: the existing TaskList CRDT (`src/crdt/`),
  the `/task-lists` and `/stores` REST endpoints, the GUI board view
  (`renderSpaceBoard` in `src/gui/x0x-gui.html`), and MLS group encryption.
  These are the v1.0 backbone for symphony per
  `../x0x-symphony/docs/adr/0004-x0x-tasklist-as-backbone.md`.
- **What symphony adds in M3** (planned, not yet implemented): symphony-aware
  filters and claim badges on the existing GUI board view; metadata
  extensions on TaskItems for `shard`, `claim`, `handoff`, `validation`.
- **No new x0x crates, endpoints, or CRDTs are required** for v1.0 symphony.
  Symphony rides existing primitives. See
  `../x0x-symphony/docs/design/symphony.md` for the full architecture.

This repo's `WORKFLOW.md` and `issues/` directory are the bootstrap tracker
that the M1 symphony runner consumes. M3 retires this JSONL database in
favour of x0x's CRDT TaskList.
