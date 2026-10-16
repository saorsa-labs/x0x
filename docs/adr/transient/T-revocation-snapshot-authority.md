# T-revocation-snapshot-authority: a trusted authority reopens a corrupt revocation carrier

- **Status:** Proposed
- **Target slot:** A02
- **Date:** 2026-10-15
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1116, PR #1336, `docs/adr/transient/T-revocation-store-corrupt.md`

## Context

The Accepted record `T-revocation-store-corrupt` (slot A03, David, 2026-10-13) stays unchanged. It says membership stays closed until revocation state is rebuilt or resynced from the group. It says a carrier opens only when every record in the snapshot has verified. It does not name the sender.

After quarantine the known set starts empty. Two free agent keys can publish the same throwaway self-revocation. The old rule treats that match as the group, opens the carrier, and writes the short set.

David confirmed the sender rule on 15 Oct 2026. This Proposed record states that rule. It does not edit the Accepted file.

## Decision Drivers

- An incomplete set must not become the live revocation file.
- A restart must not admit a revoked agent from that incomplete file.
- An enrolled machine of the local owner, and an Active owner or admin of a group this node belongs to, must still be able to rebuild the carrier.
- Two free agent keys must not be enough.

## Considered Options

1. Count two anonymous senders that publish the same snapshot.
2. Open a carrier only after an operator places a readable live file and restarts.
3. Open a carrier only from a trusted authority, and only when every record has verified.

## Decision

A snapshot reopens one waiting revocation carrier only when both of these are true. The sender is a trusted authority. Every record in that snapshot has verified. The snapshot must include every revocation this node has already verified for that carrier.

A trusted authority is a machine enrolled to the local owner, or an Active owner or admin in the local journal of a non-withdrawn group where the local agent is also Active. Enrollment uses the authenticated binding and a current owner enrollment. The resync hold does not reject that machine. An explicit revocation of that agent, machine, or binding does. Either condition is enough.

The node's own publish does not open a carrier. An empty snapshot does not open it. A snapshot that omits a known revocation does not open it. Two free agent keys do not open it. Otherwise the carrier stays closed until an operator places a readable file on the live path and restarts.

The durable rebuild runs only after the carrier opens under this rule. An incomplete snapshot from an untrusted sender is not written. The quarantine file stays.

## Consequences

### Positive

- A lost revocation cannot be dropped by two free keys.
- An enrolled machine and a group owner or admin can still rebuild the carrier.

### Negative / Trade-offs

- Without an enrolled machine or an Active owner or admin in a local group, the network cannot reopen the carrier. The operator rebuild remains the path.

### Neutral / Operational

- This file does not change the Accepted record. The status stays Proposed until David accepts it. Do not fold it until David asks.

## Validation

Isolated tests must show four results. Two free agent keys do not open a carrier. An incomplete set stays closed. A restart does not admit the revoked agent from that incomplete carrier. A trusted authority can open the carrier, and the live file keeps the revoked subject.

## Notes for AI-assisted work

Do not mark this record Accepted. Do not edit `T-revocation-store-corrupt.md`. Do not fold this file.
