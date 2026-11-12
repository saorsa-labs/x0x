# A15 Compatibility Validation and Decision Rules

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

x0x will have no more than 15 current ADR slots. The new set must preserve important decisions and evidence while making the current architecture easier to read.

## Context

The original snapshot contains 100 numbered ADRs. The transfer map also includes ADR 0115 and ADR 0116, for 102 mapped records. Their bytes are now in `docs/adr-archive/`; their old paths are links. Many mix decisions with implementation plans, detailed protocols and review history.

Current CI protects accepted ADR text and associated frozen evidence. Code, tests and open PRs refer to those records. A file move alone would not create a safe replacement.

## Decision

Use stable current IDs [A01](A01-r01-purpose-and-product-limits.md)–A15. Archived records and previous accepted revisions do not count towards the limit.

David's 19 Oct 2026 ruling prohibits new ADR files, including transient
records and folded overlays. Keep the pack at 15. Put rationale in the PR
body and existing documentation or code doc comments. Wire-format or
public-API changes need a `FOR ENGINEER:` line for David's decision. Record
his approval in the PR body or comment. An approved additive API needs no
new ADR. Preserve Accepted bytes and frozen evidence. See the
[current authoring rule](../transient/README.md).

David accepted all 15 slots at revision r01 on 7 November 2026
(course-correction directive, ruling 2). The accepted slots are the live
decision authority. The gate supports one accepted revision file per slot;
an agent cannot change a slot's acceptance or create A16. David directs any
later change; earlier Accepted text remains unchanged.

Decision gate for slot, wire-format and public-API changes (amendment of 12 Nov 2026). David directed this amendment on 12 Nov 2026. It replaces two rules in this section from that date: that a wire-format or public-API change needs David's decision before merge, and that David directs each later change to a slot. David delegated design decisions on 10 Nov 2026. Under that delegation a slot change is a dated paragraph in the slot that names the delegation, with the `index.json` pin updated; it needs no separate ruling. A wire-format or public-API change needs no separate ruling either. Its PR body carries a `FOR ENGINEER:` line that states the change, so that the release notes and the other teams see it. The merge gate does not change: exact-commit review approval and green required checks. These rules stay: the pack stays at 15, there are no new ADR files, an agent cannot create A16 or change a slot's acceptance status, and earlier Accepted text stays unchanged. David can overrule any change made under the delegation.

Target 500–1,000 words per ADR. Review records above 1,500 words. Keep the key guarantees, alternatives and consequences in the decision record.

Supporting specifications contain wire layouts, complete state machines, schemas and test detail. They may evolve only within the accepted guarantees. A material authority or compatibility change needs its existing decision gate. Explain the rationale in the PR and existing documentation. Route wire-format or public-API questions to Engineer for David. Preserve reserved numbers and existing team gates; do not add a record.

## Language

Use approximately 80% ASD-STE100 style in ADRs, other documentation, and communication with David. Use short sentences, common words, clear actions and consistent terms. Keep necessary technical terms. This is a writing target, not a claim of formal compliance. Follow the [documentation style guide](../../documentation-style.md).

## Archive transfer

Draft the new set beside the old set. For each old record and important clause, record one disposition: retained, changed by a later accepted decision, retired, or unresolved.

A Proposed old design remains unresolved until it is explicitly accepted. A summary must not turn it into an accepted or shipped feature.

Retain exact old accepted text and frozen evidence. Preserve old paths during the initial transition. Update code and documentation references through a complete mapping.

Existing team work keeps its original acceptance gates until the replacement decisions take effect. Do not combine the archive move with a protocol change.

Update governance CI before changing the governed layout. The new checks must preserve the old protections, not disable them.

## Compatibility

Version persisted and wire formats. Refuse malformed or unsupported data with
a clear result. Do not replace unreadable authority state with empty permissive
state. Retain ADR 0085 rule 2: every released binary layout stays readable
through a frozen copy of that release's serde shape, never the live type.
Consume each body exactly; trailing bytes are an error. Allow a fallback
only when at most one candidate layout can consume the body exactly.

Gate incompatible behavior on verified capability evidence. Unknown capability is not proof of support.

A send that carries a durable obligation must wait for that evidence. The sends are a ShareGrant (v1 or the names envelope), a predecessor relay and a requester offer. When the recipient has no current verified capability advert, the sender does not send. It asks the recipient for a targeted advert refresh, keeps the obligation queued, and reports the typed state `recipient_capability_pending`. It retries when a verified advert arrives. After one advert period (600 s) with no advert, the typed state is `recipient_capability_unavailable`; the obligation stays queued and nothing is sent. A stored peer-evidence view, an expired advert and a contact card are not current verified adverts. A current advert that lacks the bit keeps the `recipient_upgrade_required` hold. Ordinary DMs and all other typed payloads keep the archived rule. This amends the rule "unknown capability sends as before" of archived ADR 0093 for these sends only (David's ruling A on #1158, 20 Oct 2026; the 600 s wait is one `ADVERT_PUBLISH_INTERVAL_SECS`; D35 covers the change). The change is local send policy: it changes no wire format, signed content or stored format.

Two accepted records set the TreeKEM removal compatibility rule (David, 16 Oct 2026, PR #1337; archived as [T-self-leave-relay-commit-binding](../../adr-archive/transient/T-self-leave-relay-commit-binding.md) and [T-self-leave-mixed-version-break](../../adr-archive/transient/T-self-leave-mixed-version-break.md)). A third-party catch-up relay may apply TreeKEM removal bytes only when the signed binding equals `treekem:epoch=<n>:commit=<digest>` for those exact bytes; the roster signature must not authorize bytes it does not cover. The legacy form `treekem:epoch=<n>` stays valid only when the authenticated author delivers the event, and the admin remove route keeps sealing that legacy form. A roster-only self-leave has no TreeKEM payload and may still be relayed by a third party.

A self-leave rekey binds `treekem:epoch=<n>:commit=<blake3>`, and David accepted the documented mixed-version break this creates: a v0.48 receiver cannot rebuild the digest string, hits `StateHashMismatch`, and leaves a group that contains an upgraded member until it upgrades and catch-up serves the same event. The leaf removal does not wait for a capability bit. `StateHashMismatch` is not fork evidence, although a later `PrevHashMismatch` can enter fork-evidence evaluation. [A09](A09-r01-group-encryption-and-key-changes.md) carries the committer and catch-up author rules.

Document upgrade and downgrade limits. Test state produced by a real supported older release. Preserve retained data when a downgrade cannot read it.

Release builds must use the tested dependency graph and lockfile. A source-level test result does not establish that a different published binary passed.

## Repository and release governance

ADR 0087 remains in force, including these rules:

- Only David promotes releases. Agents change release tags or approve a
  release environment deployment only on his instruction for that action.
- David merges release-workflow changes (`release.yml`,
  `publish-promoted-release.yml`, and `sign-skill.yml`).
- An ADR-governed change has a Proposed ADR on main before its code merges
  to any branch. Wire, network-protocol and qualifying dependency changes
  also need an Accepted ADR before their code merges to main. ADR 0087 rule 8
  defines qualifying dependency changes; routine unchanged-behavior refreshes
  remain outside that definition.
- An after-the-fact record of shipped behavior uses `Accepted (record)` and
  names the accepting ruling. It does not waive the ADR-before-code rule.

## Validation

Each architectural guarantee has an owning test or evidence path. Important tests exercise the real dispatch and failure boundaries, including meaningful negative controls.

Keep test traffic isolated from production. Tests that can join the real network must use the approved isolated Linux environment.

Separate design acceptance, code merge, CI results, publication and deployed service evidence. None is a substitute for the others.

The frozen-layout requirement is not fully implemented. Task snapshots have versioned envelopes. `SnapshotBody` and `SnapshotBodyV2` still decode the live `TaskList` type. They do not use frozen release-specific types.

## Consequences

Readers get a small stable set of decisions. Detailed specifications and historical records remain available. The transfer needs careful review before the new set can replace the rules used by current teams.

## Alternatives

Deleting the old records would remove rationale and make existing references difficult to interpret.

Keeping the old set as the only guide preserves history but retains the reading burden.

Compressing all detail into 15 large records would change the file count without simplifying the architecture. We reject that approach.

## Acceptance

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). The accepted slots are the live decision authority. The archived numbered records and rulings digest remain the historical record and the primary sources; where a slot is silent on a detail an archived accepted record settles, that archived record still answers it.

The clause-level transfer review in [TRANSFER.md](TRANSFER.md) remains open as documentation work. It verifies coverage; it no longer gates slot acceptance. Archived hashes, frozen evidence and the 15-slot limit stay checked by CI.

## Matters to settle

Complete the clause-level transfer review as documentation follow-up. Publish one short current capability guide. Keep the repository instructions and documentation mirror aligned with the accepted set.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These are the primary sources. Their clause-level transfer remains open under Acceptance above.

[ADR 0025 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0025-required-gates-prove-observation-completeness.md) · [ADR 0063 Rejected](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md) · [ADR 0085 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0085-persisted-binary-formats-are-versioned.md) · [ADR 0087 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0087-repository-and-release-governance.md) · [ADR 0093 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0093-capability-advert-registry.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
