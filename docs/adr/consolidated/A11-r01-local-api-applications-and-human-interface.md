# A11 Local API Applications and Human Interface

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

The local API and human interface expose the same x0x capabilities and permission rules. A successful interface action must reflect the actual result of the operation.

## Context

x0xd provides REST, WebSocket and Server-Sent Events interfaces. It also embeds a GUI. The command-line client uses the daemon API. Local applications need a stable way to discover the daemon and use the correct credential.

## Decision

We will keep x0xd as the primary integration point for non-Rust applications. Rust applications may use the library or embed the supported server surface.

Bind the normal control plane to loopback. Remote access requires an explicitly designed and authorized path. Do not expose the owner control API to a network as an integration shortcut.

Use the shared endpoint registry to keep the daemon and command-line surfaces aligned. Each supported operation must document its request, permission, response, error and relevant event.

## Authentication

Keep distinct credentials for owner control, human GUI sessions and API riders. Each route states the token classes and scopes it accepts.

A browser session is not the owner token. A rider's receive permission must be implemented as a scoped event surface, not unrestricted access to every WebSocket topic.

Protect local browser access against unauthorized origins and credential disclosure. A page loaded from an unrelated site must not gain daemon authority simply because the daemon runs on localhost.

Credentials and private keys must not appear in ordinary logs, diagnostics, copied links or event payloads.

A lapsed GUI session token may be exchanged at `POST /auth/session/refresh` only, for `SESSION_REFRESH_GRACE` = 4 h after expiry, single use; the original mint time is carried over so the 12 h cap (`SESSION_MAX_LIFETIME`) from the `x0x gui` mint is unchanged; a lapsed token receives 401 on every other route; lapsed entries are retained for the grace and pruned on every operation. Trade-off accepted (decided under A15 by the orchestrator, 18 Nov 2026): a session token that was never rotated can be swapped for up to 4 h 10 min after issue instead of 10 min (`SESSION_REFRESH_GRACE` + `SESSION_TOKEN_TTL`), and session tokens have no logout or revoke route.

18 Nov 2026 (David: "an actual inactivity timer and not simply time out every 12 hours"), superseding the 12 h cap and the 4 h grace in the paragraph above; that paragraph stays as history. A GUI session is a sliding session with no absolute lifetime cap. It ends after `gui_idle_timeout_minutes` (default 60, range 1 to 1440; flag `--gui-idle-timeout-minutes`, env `X0X_GUI_IDLE_TIMEOUT_MINUTES`) without user activity. The daemon records `last_activity` per session chain and carries it across token rotations; a mint sets it. `POST /auth/session/refresh` may carry `{"idle_ms": n}`, the client's time since its last user input (a body over 1 024 bytes returns 400); the daemon moves `last_activity` to `now - idle_ms` when that is later, never past `now`. A refresh without `idle_ms` (GUI timers, `x0x auth refresh`) rotates the token and does not move it. The idle check uses the recorded `last_activity` before the claim is applied, so a claim cannot revive a timed-out session. A session token is valid only while unexpired and `now - last_activity < idle timeout`; a lapsed token may still be exchanged at `POST /auth/session/refresh` only, while `now - last_activity < idle timeout`, single use, constant-time compare, bearer header only, entries pruned at the idle limit. The GUI counts pointer, key, wheel, touch, input, focus and reveal events (at most one update per 30 s, no request per event), and ends a hidden tab locally at the idle limit. `POST /auth/session/revoke` ends the caller's own session: every token of its lineage (a lineage ID is set at mint and carried across rotations), so a refresh that won a race with sign-out is ended too. It accepts any session token refresh would accept (live, or lapsed inside the idle timeout), or a token a refresh replaced while its session is live (replaced tokens are remembered until the idle limit, at most 4096); on the exact method and path; the durable token gets 403. A replaced token opens nothing else, but a holder of one can end that session (a denial of service by someone who already held the session). The GUI has a Sign out control, and when it ends a session on its own idle check it revokes the token (best effort) and clears sessionStorage; a refresh that returns after the session ended is revoked and not stored. Known limit: Open WebSocket and SSE streams of a revoked or idle-expired session are not closed: such a stream can outlive sign-out until the client disconnects, with no time bound. Streams were authenticated at connect, and SSE streams keep no link to the token. Trade-off accepted (decided under A15, 18 Nov 2026): the activity signal is client-asserted, so whoever holds the CURRENT session token can keep the session alive indefinitely by refreshing with activity claims. Mitigations: the API is loopback-only; the GUI keeps the token in sessionStorage only; every refresh rotates the token single-use, so a stolen superseded token is useless, and a race between a thief and the owner signs the owner out visibly; the owner can end a session with Sign out. The daemon measures token expiry and idle time on the wall clock (`SystemTime`), not a monotonic clock, because a monotonic clock stops while macOS or Linux is suspended; time asleep counts toward the idle timeout. A forward clock step ages the session by the step (it can end early). The store keeps a high-water mark of the wall clock. A backward step of at most 60 s freezes the store's time at the high-water mark until the wall clock passes it; expiry and idle timers are suspended for the whole duration the clock spends below that mark. A backward step of more than 60 s (for example a forward jump that is later corrected) ends every session and forgets replaced tokens, and the mark resets to the wall clock; users sign in again with `x0x gui`. This fails closed: a long freeze would stop token expiry and idle timers for sessions minted during it.

GUI session streams and clock-step log (amendment of 20 Nov 2026, #2079; Claude under David's delegation of 10 Nov 2026 and A15 as amended on 12 Nov 2026). This replaces the known limit on open streams in the paragraph above. A request authenticated by a session token carries the session's lineage. An SSE response to it ends when the session ends, and a WebSocket closes with code 1008 and reason `session ended`. The session ends on sign-out (`POST /auth/session/revoke`, with any token the route accepts), at the idle limit, or when a clock step ends every session. A stream re-reads its session's state at least every 30 s, so a stream of an idle-expired session closes within 30 s of the idle limit. A stream follows the session, not the token: a refresh keeps it open. Streams opened with the durable token or a rider token are not affected. The GUI does not reconnect a WebSocket closed with 1008; it shows that the session ended. Residual limit: a WebSocket command already running when the session ends (for example a `subscribe` that reads history, or the `/ws/direct` backfill read before the reader loop) finishes before the 1008 close is sent, so the close can wait for that read. The command is not cancelled, because a cancelled subscribe could leave a topic subscription that the session teardown does not remove. A stream's session link is the lineage of the exact token that authenticated the request, taken from the same lookup, so a junk bearer header beside a valid `?token=` cannot leave the stream unbound. When a backward clock step ends every session, the daemon logs a warning with the number of sessions it ended and the size of the step.

Embedded GUI static shell loading on reload and direct navigation (amendment of 26 Nov 2026; directed by David Irvine on 26 Nov 2026, recorded under A15 as amended on 12 Nov 2026). `GET /gui` and `GET /gui/` return a static compile-time HTML shell that holds no credentials, keys, or daemon state. When requested by `GET` with no `Authorization` header and no `?token=` query parameter (for example on browser reload after the GUI strips `?token=` from the URL, on a bookmark, or on direct navigation to `/gui`), `authorize` returns `Grant::Open` and `serve_gui` serves the HTML shell with `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` instead of `401`. When a `?token=` query parameter or `Authorization` header is present on `/gui` or `/gui/`, `authorize` still enforces the existing validation and returns `401` for a durable API token in `?token=`, a replaced token, or an expired or unknown credential, preserving the #127 URL-credential invariant. Non-`GET` methods on `/gui` and every API, WebSocket, and SSE route remain strictly authenticated. On load, the GUI reuses a live session token stored in `sessionStorage` so browser reload works without losing the session. When no session token is present, or when a session ends or receives `401`, the GUI does not start or continue authenticated polling and shows a sign-in overlay directing the user to run `x0x gui` or paste a session token minted via `x0x auth session` (verified through `POST /auth/session/refresh`, which rejects the durable API token). Owner-act prompts (`ownerApi`) clear a rejected owner token on durable-required `403` as well as `401`, and state the platform `api-token` paths.

## API behavior

Return typed failures that tell the caller what happened and whether a retry is valid. Use stable request identities for operations whose outcome can be uncertain.

An HTTP success must not imply a stronger delivery, persistence or execution result than the operation achieved. [A07](A07-r01-messages-receipts-history-and-retry.md) owns the receipt vocabulary.

Live events must carry enough identity and scope for correct routing. Applications that require recovery use the durable consumer contract. A live display can use a separate documented best-effort stream.

State-changing actions must recheck current permissions. A previous successful read is not authority for a later write.

## Human interaction

The GUI must show the real operation state: waiting, refused, committed or failed. It must not hide unresolved joins, missing keys or failed upgrades behind a general success message.

An agent can request an approved view for its human under the GUI-show policy. The request identifies the allowed view and target device. It must not return a privileged session token to the agent.

Opening a view does not grant the agent permission to approve an authority change on the human's behalf.

Headless devices return a clear no-display result. They do not block the daemon while waiting for an unavailable interface.

## Consequences

Applications can use one local service from different languages. Token scope and browser checks add work to each route. The human interface must expose failures that a simple connected indicator would hide.

## Alternatives

Separate permission rules in the GUI, CLI and REST routes would make behavior difficult to audit.

A remote public control service would simplify browser-only access but would create a new exposure and account boundary. It is not implied by the local API.

## Current implementation

The local API, embedded GUI, CLI registry and application integration exist. The agent-opened-view design remains on hold and has no route implementation. Scoped rider subscriptions require new work under [A04](A04-r01-agent-attachment-and-inbound-events.md).

Daemon thread stack (21 Nov 2026, #2083; decided by the orchestrator session under A15, 21 Nov 2026). `x0xd` does not poll its top-level future on the process main thread, whose stack the platform sets (1 MiB on Windows, 8 MiB on Linux and macOS). `main` calls the additive library function `x0x::server::run_daemon_runtime`, which builds and polls that future on a new thread named `x0xd-main` with an explicit `DAEMON_THREAD_STACK_BYTES` (8 MiB) stack, on a multi-thread Tokio runtime whose worker and blocking-pool threads get the same size. A panic on that thread is returned to `main` as an error, so `x0xd` exits with code 1 and an error that says the daemon main thread panicked; the panic message itself names `thread 'x0xd-main'`. Before, a panic unwound the main thread and the exit code was 101. Measured on a macOS arm64 debug test build: the `poll` frame of the `serve_with_options` future was 1,380,656 bytes before this change. Against the 1 MiB Windows main-thread stack this means a debug `x0xd` on Windows would overflow at start; that is inferred from the macOS frame size, and no Windows launch was done. Release frame sizes were not measured. The `serve_with_options` future that a caller holds is now small, because the startup future is built on the heap. Its `poll` frame is now 463,120 bytes on the same build, because the route table, the spawned tasks and the largest awaited futures are built in short frames of their own. A hermetic serve on a current-thread runtime then needs less than 1.5 MiB of stack; before, it needed more than 2 MiB. No route, wire format or stored format changes.

CLI thread stack (22 Nov 2026, #1764; decided by the orchestrator session under A15, 22 Nov 2026). The #2083 rule now covers the `x0x` CLI too. `x0x` does not poll its top-level future on the process main thread. `main` calls the additive library function `x0x::server::run_cli_runtime`, which shares the thread and runtime setup of `run_daemon_runtime`: a thread named `x0x-main` with a `DAEMON_THREAD_STACK_BYTES` (8 MiB) stack and a multi-thread Tokio runtime whose workers get the same size. Found by the hosted Windows acceptance run (run 45031711251): a debug `x0x autostart` exited with `STATUS_STACK_OVERFLOW`. On a macOS arm64 debug build, building the clap command tree (`Cli::command()`, 62 subcommands) overflowed a 1.5 MiB thread and fitted in 2 MiB, and the old debug `x0x --version` aborted with the main stack limited to 1 MiB; the `run_cli` future itself is 7,088 bytes. Release frames were not measured. A panic on the CLI thread is re-raised on `main` with `std::panic::resume_unwind`, so the exit status stays 101 and the message is printed once (it now names `thread 'x0x-main'`). A failure to spawn the thread or build the runtime prints an error and exits 1; `#[tokio::main]` panicked in that case. On Unix `run_cli_runtime` blocks SIGPIPE on the calling thread and unblocks it on `x0x-main` before the runtime starts, so the CLI thread and its workers take a broken-pipe SIGPIPE under the default disposition the CLI sets: `x0x routes | head` still ends silently by SIGPIPE (#478). Without it, macOS delivered the signal to the waiting main thread and the writing thread panicked on `EPIPE` first. `x0xd` keeps Rust's ignored SIGPIPE, so the #2083 move changed nothing there. `x0x-launcher` is unchanged: it has no clap and no Tokio runtime, and it stays minimal. No CLI argument, route, wire format or stored format changes.

## Validation

Check the token-class matrix for every route and event subscription. Verify that the CLI and GUI report the same underlying outcome.

Exercise an invalid browser origin, revoked session, slow subscriber and headless view request. Confirm that no response leaks a credential.

## Matters to settle

Define the new rider event endpoints with [A04](A04-r01-agent-attachment-and-inbound-events.md). Record any remaining GUI/API parity gaps as implementation work, not new architectural decisions.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0044 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0044-daemon-local-rest-ws-sse-control-plane.md) · [ADR 0052 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0052-embedded-gui-in-daemon-binary.md) · [ADR 0057 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0057-embedded-serve-library-local-apps.md) · [ADR 0083 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0083-agent-initiated-gui-show.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
