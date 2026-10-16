# T-open-envelope-actor: durable-owner envelope opening

- **Status:** Proposed
- **Target slot:** A03
- **Date:** 2026-10-15
- **Decision owners:** David Irvine
- **Reviewers:** Claude, Codex, ZCode
- **Supersedes:** none
- **Superseded by:** none
- **Related:** #1228, A09, ADR 0027
- **Direction:** David chose owner-only access, relayed by Engineer in the local mailbox on 15 October 2026 at 11:46 London. This record remains Proposed pending its separate review and publication.

## Context

`POST /groups/secure/open-envelope` uses this daemon's private KEM key to attempt to open a supplied `SecureShareDelivered` envelope. The production route accepts the durable API token and browser sessions. Rider middleware already refuses the route. The handler has no actor check. A browser session can therefore request this key operation despite the separate limits on other owner operations.

ADR 0027 requires active-recipient checks when a production path selects someone to receive current group key material. It expressly leaves this opening endpoint's product disposition to a later decision. This record resolves that deferred endpoint choice. It does not edit ADR 0027 or weaken its sealing rule.

## Decision Drivers

- Access to the daemon's envelope diagnostic must require explicit owner authority.
- Refusal must precede body parsing and key use.
- Existing cryptographic and withdrawn-record checks must remain effective.

## Considered Options

1. Keep browser sessions eligible. Rejected: session access is too broad for this key operation.
2. Keep the production diagnostic and restrict it to the durable owner token. Chosen.
3. Exclude the route from production builds. Rejected for this change: the owner diagnostic remains available.

## Decision

The exact POST route requires a valid durable owner API bearer. A valid browser session or rider credential receives a typed HTTP 403 before JSON extraction. Missing or invalid credentials retain the authentication layer's HTTP 401 response. The handler repeats the durable-owner check before inspecting the supplied envelope or using the daemon key.

Owner authority permits an attempt only. Preserve envelope decoding, recipient-key validation and the existing withdrawn-group checks. Do not add a roster-presence requirement: this diagnostic is intentionally roster-agnostic. It does not select a new recipient, distribute a new envelope, install a group secret, or grant a group seat.

## Consequences

Browser clients must obtain explicit owner authority for this operation. The durable token remains a sensitive local capability. The rule does not contain a compromised host or a principal that already holds the raw secret. It establishes neither historical-key entitlement nor global epoch currency. There is no wire-envelope, stored-format or dependency change.

## Validation

Use the real middleware with valid session, rider and durable credentials. Malformed input must produce the actor refusal for session and rider before JSON parsing. The durable control must reach normal parsing. Exercise the handler directly with each actor class. Keep a valid owner envelope-opening control and the existing withdrawn-record refusal controls. Removing each new guard separately must make its corresponding control fail. Test execution must follow repository network-isolation rules; offline tests must not start a daemon or join the network.

## Notes for AI-assisted work

Keep this record Proposed. Keep the current ADR pack at 15 slots. Engineer must publish this record to main before merging the governed code, under the repository ADR-before-code rule.
