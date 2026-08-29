# ADR-0023 mechanics — Durable local history rationale and validation

> Extracted 2026-08-29 from the immutable [ADR 0023](../adr/0023-durable-local-history.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the considered-options rationale and validation inventory
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Considered Options

1. **Durable history as a core, default-on x0xd capability (SQLite).**
2. Durable history as an opt-in feature flag, default off.
3. Keep history an application concern (each app ships its own store, as the
   nostr-bridge did).
4. Extend the existing bincode-file persistence (no SQL dependency).

Option 2 makes the flagship use case (agent memory) a configuration
afterthought and forks the ecosystem into daemons-with-memory and
daemons-without. Option 3 duplicates a hard-to-get-right store (write-path
backpressure, retention, search) into every app and loses the shared CLI/API
surface. Option 4 cannot serve bounded-latency scoped queries or full-text
search, which are the point.

---

## Validation

- Unit: insert/query/replace/ephemeral-never-stored/retention-eviction/FTS
  round-trips.
- Integration: send DM → restart daemon → `GET /history` returns it
  (the restart-survival test that is impossible today).
- Backpressure: flood the gossip plane; assert the receive pump never
  blocks on the writer and `history_dropped_full` counts the shed.
- Parity: `api_coverage.rs` / `parity_cli.rs` enforce endpoint + CLI
  coverage automatically once registered.
- Product: tic-tac-toe's acceptance suite reads history-after-restart and
  search as its first two assertions — the proof point this exists for.
- Review trigger: if cross-node backfill is proposed, it requires a new ADR;
  this ADR's local-only privacy claim is load-bearing.
