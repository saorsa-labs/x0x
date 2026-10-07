# A11 Local API Applications and Human Interface

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

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

The local API, embedded GUI, CLI registry and application integration exist. The agent-opened-view design has its own implementation hold. Scoped rider subscriptions require new work under [A04](A04-r01-agent-attachment-and-inbound-events.md).

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

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
