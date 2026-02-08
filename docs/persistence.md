## Persistence Runtime Controls (Node/Python)

Persistence remains plaintext-only in this phase. Snapshots are stored as plaintext payload envelopes, and bindings must not imply at-rest encryption guarantees.

### Defaults and observability

- Use the same core contract in both bindings for persistence observability: `health`, `checkpoint_frequency`, and `checkpoint_frequency_bounds`.
- `health` includes: `mode`, `state`, `degraded`, `last_recovery_outcome`, `last_error`, and `budget_pressure`.
- `checkpoint_frequency` reports current runtime values: `mutation_threshold`, `dirty_time_floor_secs`, `debounce_floor_secs`.
- `checkpoint_frequency_bounds` reports host envelope limits and `allow_runtime_checkpoint_frequency_adjustment`.

### Runtime adjustment behavior

- Runtime checkpoint-frequency updates are bounded by host policy envelope values.
- Out-of-range or disallowed requests return deterministic invalid-request errors with stable codes:
  - `runtime_checkpoint_adjustment_not_allowed`
  - `mutation_threshold_out_of_bounds`
  - `dirty_time_floor_out_of_bounds`
  - `debounce_floor_out_of_bounds`
  - `invalid_host_policy_envelope`

### Example flow (binding semantics)

1. Query observability contract.
2. Inspect `checkpoint_frequency_bounds`.
3. Submit a bounded update request.
4. If rejected, branch on deterministic error `code` and surface operator guidance.

This keeps Node/Python behavior parity-locked to core runtime semantics while preserving plaintext scope language.
