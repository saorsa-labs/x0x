# T-0089-evidence-worker-shutdown-grace: bound the evidence worker drain

- **Status:** Proposed
- **Target slot:** A03
- **Date:** 2026-10-19
- **Decision owners:** David Irvine
- **Reviewers:** Claude exact-head review and independent consensus acceptance pending
- **Supersedes:** none
- **Related:** [ADR 0089](../0089-relationship-peer-evidence-survives-restart.md), [ordinary-send clarification](T-0089-ordinary-send-load-barrier-fallback.md), [#1239](https://github.com/saorsa-labs/x0x/issues/1239), [#1453](https://github.com/saorsa-labs/x0x/pull/1453)

## Context

The evidence runtime owns the store-load worker, bounded point-of-use reads
and Lookup workers. A send deadline can stop waiting for a read, but it
cannot abort a synchronous read that has started. A store writer stalled on
disk can hold that read indefinitely. The current shutdown closes admission
and cancels work, then joins every worker without a deadline. This wait
prevents the agent from reaching later cleanup steps.

PR #1453 retained worker handles across caller cancellation. Engineer assigned
the bounded drain as a separate follow-up. Keep that custody guarantee while
limiting the shutdown wait. An abort request does not prove completion.

## Decision

Give the evidence registry one five-second shutdown grace. Start its absolute
deadline when the first drain call closes admission. Store the deadline with
the worker handles. A cancelled, concurrent or repeated shutdown uses that
same deadline. It cannot extend the grace. Five seconds matches the existing
history-writer drain allowance; it is an internal evidence cleanup budget.

Continue to cancel queued and asynchronous work. Join workers that finish
within the grace. If the deadline expires, retain every unfinished handle in
the closed registry and return the unfinished count to the agent. Do not
release their permits or mark them complete. The agent continues its other
cleanup steps and includes that count in its existing incomplete-shutdown
`NetworkError::NodeError`. The compatibility `shutdown` method logs that
existing error. Neither public method signature changes.

A later drain polls the retained handles even after the deadline. It succeeds
only when all evidence workers have actually finished. Until then it reports
unfinished work immediately. The store-load worker uses the same rule.

## Alternatives and consequences

An unlimited join can hang cleanup. Dropping handles or treating timeout as
success hides live work. A new grace for every caller lets cancellation defer
failure indefinitely. Retaining handles with one deadline avoids these cases.

This decision bounds only the evidence drain. It does not make synchronous
disk work abortable, bound other shutdown stages, or guarantee that dropping
the Tokio runtime terminates. A worker may remain alive until its lock or disk
operation completes. An embedder must respect the incomplete-shutdown error.

Wire formats, storage formats and public APIs remain unchanged. ADR 0089 and
its accepted ordinary-send clarification stay unchanged. Send selection,
fallback, errors and the 16-read and 16-Lookup limits are preserved.

## Validation

Hold real store reads after their callers time out. Prove that shutdown ends
within one grace, reports unfinished work, continues cleanup and refuses new
reads. Cancel one shutdown during the grace and verify that the next caller
keeps its original deadline. Release the holds and prove a later drain joins
the workers. Apply the same check to a started store-load worker. Keep the
existing prompt-completion, queued-cancellation and admission-race controls.
