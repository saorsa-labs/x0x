# Architecture review on 5 October 2026

x0x connects people, machines and their chosen agents. It supplies identity,
permissions, peer communication, shared data and work coordination. Users bring
their own agent runtimes. A supported agent attachment needs a recoverable
inbox as well as permission to send.

## Read the review

- [Full review in Markdown](x0x-review.md), readable in GitHub.
- [Original HTML review](x0x-review.html), retained byte for byte. Download it
  and open it in a browser to use its interactive tables. GitHub shows source.
- [Documentation inventory](documentation-inventory.json), with the source
  file list and all 100 ADR mappings.
- [The 15 Proposed review drafts](../../adr/consolidated/README.md).
- [Documentation and communication style](../../documentation-style.md).

The review used source commit
`eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Main still had that commit when
this PR was prepared. Coverage is a corpus inventory, ADR status and decision
review, and targeted deep documentation and source review. It is not a claim
that every historical line was manually read.

The research compares primary sources for agent protocols, durable delivery,
group encryption, shared data, connectivity, media and update security. It is
a dated comparison, not a claim that x0x leads every field. The full review
contains the source links and the limits of each comparison.

## Confirmed direction

The 15-slot direction is confirmed by David (D198). A04 and A07 make reliable
agent delivery explicit: scoped live events, replay after restart, durable
consumer acknowledgment, and separate delivery and task-completion results.
Adapters connect those events to ACP sessions or hosted model APIs.

A15 proposes a limit of 15 current slots after transfer. During transfer,
new or changed decisions use the numbered ADR series only (D199, ADR 0087).
Slot revisions remain drafts until David accepts the transfer. The approximately
80% ASD-STE100 style target is confirmed by David (D198) for ADRs, documentation
and PR text; it also applies to communication with David.

This PR captures the direction and the review drafts. It does not activate
replacement rules before their transfer checks pass. It does not move or edit
the accepted source ADRs. It does not change runtime behavior or release status.

## Work already in progress

The source snapshot and historical report keep their original dates. GitHub
state can change after this PR is prepared. Recheck each lane before action.
At preparation, these PRs were open:

- [#1243](https://github.com/saorsa-labs/x0x/pull/1243): group access checks.
- [#1237](https://github.com/saorsa-labs/x0x/pull/1237): release-signing gate.
- [#1235](https://github.com/saorsa-labs/x0x/pull/1235): safe-update validation.
- [#1234](https://github.com/saorsa-labs/x0x/pull/1234): group simulation harness.
- [#1222](https://github.com/saorsa-labs/x0x/pull/1222): restart-cold DM resolution.
- [#1188](https://github.com/saorsa-labs/x0x/pull/1188): durable-write outcomes.
- [#1184](https://github.com/saorsa-labs/x0x/pull/1184): old bootstrap removal.

These lanes keep their existing owners, decisions and acceptance conditions.
The consolidation creates no new implementation permission for parked work.
