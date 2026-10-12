# A02 Identity Keys and Device Enrollment

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x uses separate identities for a human owner, an agent and a machine. This separation lets the owner grant authority to an agent without giving that agent the owner's key.

## Context

A machine can run several agents. An agent can represent work for a person. A model name, a process ID and an agent identity are not interchangeable. Permission checks must use verified identity evidence.

## Decision

We will retain three identity layers:

- A machine identity authenticates a transport endpoint.
- An agent identity identifies a participant and its signed actions.
- An optional user identity represents the human owner.

The current identities are derived from ML-DSA-65 public keys using SHA-256. Any future change to identity derivation requires a versioned migration under [A15](A15-r01-compatibility-validation-and-decision-rules.md).

Machine and agent keys may be created for a new installation. A user key must never be created without an explicit owner action. An AgentCertificate binds an agent key to its owner. Device enrollment establishes which machines belong to that owner's device set.

Authentication must prove the relevant agent and machine binding. A transport signature alone must not turn an unverified agent name into an authenticated sender.

## Key custody and placement

A key-owning harness keeps its own agent key. An API rider uses a scoped delegation through a daemon, as defined in [A04](A04-r01-agent-attachment-and-inbound-events.md). Both forms retain clear attribution.

Pinned agents remain bound to their approved machine. Existing placement records and denials remain effective. This draft does not activate roaming or the disabled key-move ceremony.

Enrollment and certificate issuance must require owner authority. Discovery provides possible addresses; it does not grant ownership or permission.

Names are labels for verified identities. Changing a display name must not change the identity or silently replace a pinned target.

## Local protection and recovery

The current local-state policy uses operating-system permissions and disk encryption. Network encryption does not protect plaintext in a member's local files or backups.

We retain that baseline. Platform key storage for the owner root is a separate proposed enhancement. It must define headless operation, recovery and migration before it becomes a product requirement.

A lost-device procedure must distinguish a lost machine key, a lost agent key and a lost owner key. Recovery must use approved authority evidence. An agent cannot repair an authority failure by deleting a denial record or creating a replacement owner.

No recovery procedure can erase data that another device already received. The product must state this limit.

## Consequences

Separate keys keep transport identity distinct from the agent and owner. Enrollment and recovery must preserve these bindings. Operators must manage more than one key and understand which authority each key carries.

## Alternatives

One identity per machine would make it difficult to give different agents different permissions.

One shared owner key in every harness would make each harness an owner-level security boundary. Scoped identities and delegation provide a smaller boundary.

Automatic key movement would make placement easier, but would require a complete transfer and revocation protocol. It remains outside this draft.

## Current implementation

The three identity types, certificates, enrollment and placement checks exist. Some custody and placement records describe historical or disabled mechanisms. The archive map must retain those distinctions.

[A03](A03-r01-trust-permissions-sharing-and-revocation.md) owns revocation effects. [A05](A05-r01-connectivity-discovery-and-names.md) owns name resolution and reachability. [A15](A15-r01-compatibility-validation-and-decision-rules.md) owns format compatibility.

## Validation

Tests must reject a forged owner chain, a mismatched machine binding, an expired certificate and an unauthorized placement change. Restart must preserve identity and enrollment.

The owner must be able to identify which keys exist, which process holds them, and what recovery can and cannot do.

## Matters to settle

Choose the owner-key storage and recovery policy before replacing the current operating-system protection rule. Do not reopen roaming as part of this documentation reset.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0007 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0007-three-layer-identity-model.md) · [ADR 0015 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0015-no-app-layer-at-rest-encryption.md) · [ADR 0036 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0036-owner-singleton-and-naming-registry.md) · [ADR 0037 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0037-agent-placement-and-key-custody.md) · [ADR 0043 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0043-agent-key-move-protocol.md) · [ADR 0054 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0054-external-agent-signing-dst.md) · [ADR 0084 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0084-enrolled-owner-sync-admission.md)

David placed [ADR 0115](../0115-identity-discovery-authority.md) in A02 on 10 Oct 2026. It amends ADR 0043. It also touches [A03](A03-r01-trust-permissions-sharing-and-revocation.md). That touch is not a second placement.

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
