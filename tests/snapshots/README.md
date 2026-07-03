# Server decomposition characterization guard (#125 / WS1.4 P0)

This directory holds the **byte-exact snapshots** that prove every extraction
PR in the `src/server/mod.rs` decomposition series (#125) is behavior-preserving.
The series must keep these identical; any deviation is a regression, not a move.

## Snapshots

| File | Source command | What it pins |
|---|---|---|
| `server-routes.txt` | `x0x routes` | Full endpoint table (method/path/CLI/description) from the registry |
| `server-routes.json` | `x0x routes --json` | Structured form (135 endpoints) |

After each extraction PR, re-run both commands and `diff` against the committed
files — output must be **byte-identical**.

## Automated guards (already in CI)

The snapshots are the human-readable rendering; the runtime parity chain is
enforced by existing tests:

- `tests/api_manifest.rs::manifest_matches_registry` — committed
  `docs/design/api-manifest.json` ⟷ live `ENDPOINTS` registry.
- `tests/api_coverage.rs::route_set_matches_registry` — live `ENDPOINTS`
  registry ⟷ the actual router's route set (runs the real `build_router()`).

A mechanical move that drops or renames a route breaks `route_set_matches_registry`
even if the snapshot text is unchanged (the snapshot reads the registry, not the
router; the test closes that gap).

## Public API surface to preserve

`src/server/` is a `pub mod`. The public items reachable as `x0x::server::*`
must not move or change signature across the series:

- Structs: `ServeOptions`, `ServerHandle`, `DaemonConfig` (+ public methods/fields).
- Consts: `DEFAULT_QUIC_PORT`.
- Free functions: `default_bind_address`, `default_api_address`,
  `default_data_dir`, `run`, `run_update_check_and_report`, `serve`,
  `serve_with_options`, `validate_instance_name`, `list_instances`.

Handlers, middleware, and helpers are private and move freely between submodules.
`cargo doc --no-deps` building cleanly is the public-API compile guard.

## Methodology

Each extraction PR is **moves + `use` fixes only**. Never fold a behavior change
into a move. If a behavior change is warranted, it lands as a separate PR before
or after the move, never inside one.
