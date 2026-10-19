# ADR Tooling and AI Harness Setup

## Use the 15 slot plan

Read [the consolidation rules](consolidated/README.md) and the
[current authoring rule](transient/README.md#current-authoring-rule-19-oct-2026).
Do not add ADR files, including transient records or folded overlays. Keep
A01 through A15; do not allocate A16 or a second consolidated series.
Put the rationale in the PR body and existing docs or code doc comments.
A wire-format or public-API change needs a `FOR ENGINEER:` line for David's
decision. Record his approval in the PR body or comment. An approved additive
API does not need a new ADR.

Existing Accepted records and frozen evidence remain unchanged. The tools
below inspect the retained collection; their support for the earlier numbered
and transient formats is not permission to create files. Follow
[the writing guide](../documentation-style.md) for changed prose.

We use ADRs as engineering memory, not paperwork. They capture *why* a decision was made, what alternatives were rejected, and what consequences we accept.

## Install `adrs`

`adrs` can list, search and check the existing ADR collection. Do not use it
to create a record.

```bash
cargo install adrs
# or, if the repo has a Rust toolchain wrapper, use that wrapper's cargo equivalent.
```

Useful commands:

```bash
adrs list
adrs search "post-quantum"
adrs doctor
```

## Install `adr-kit`

`adr-kit` is used for agent-aware ADR analysis and policy/lint generation where available.

Recommended isolated install:

```bash
uv tool install adr-kit
# fallback
uvx adr-kit --help
```

If the published package name differs on your machine, install from the project source used by the team and keep it isolated with `uv tool` or `pipx` rather than a global Python environment.

## AI harness guidance: pi, Codex, Claude Code, OpenCode

Add this project instruction to every AI coding harness profile (`AGENTS.md`, `CLAUDE.md`, Codex/OpenCode project rules, pi harness prompts, etc.):

```text
Before changing architecture, protocols, storage formats, crypto, network behaviour, public APIs, data models or operational invariants, inspect docs/adr/ and its status overlay.
Keep the ADR pack at 15. Do not add ADR files, including transient T-*.md records or folded overlays (David's 19 Oct 2026 ruling).
Put the rationale in the PR body and existing documentation or code doc comments.
If a change touches the wire format or public API, write a FOR ENGINEER: line for David's decision. Record his approval in the PR body/comment; an approved additive API needs no new ADR.
Preserve Accepted records and frozen evidence. Do not create a successor record or change an acceptance status as a workaround.
Use approximately 80% ASD-STE100 style. Follow docs/documentation-style.md.
During review, check correctness, alternatives, evidence, consequences and unchanged Accepted bytes. Existing release, security and independent-review gates still apply.
```

## Review standard

Review the rationale where it lives: the PR body and existing docs or code
comments. State the context, alternatives, consequences and validation.
Keep an unresolved David decision visible; a document or a green CI run does
not grant approval. Preserve the existing Accepted text and frozen evidence.

## Transition check coverage

`python3 scripts/check-adr-consolidation.py` checks the index shape, exactly
15 distinct slots, matching indexed titles and file revisions, regular
record paths, required section headings, and a leading Proposed status token.
It rejects unindexed files and early activation. Status annotations are
allowed, as in `adr-governance.py`; Accepted annotations remain rejected.

`python3 scripts/check-adr-count.py` fails when the current count exceeds
15. The plan is `docs/adr/consolidated/README.md`. Records in the transfer
map keep their exact paths as links and stay outside that count. The count
excludes a path only when that path is an approved historical source and
`docs/adr-archive/move.json` records it as that archive link. A new
`move.json` entry outside that set is rejected. Files under
`docs/adr/transient/` do not count (D242). The validator still understands
the existing `T-<slug>.md` format and its lifecycle. It checks structure and
immutability, not reviewer identity, approval scope or the current prohibition
on new ADR files. Review must enforce that prohibition separately.
An Accepted transient body stays frozen. Existing folded overlays refer to
that body without changing it. A nested
file that reuses a mapped number counts. A legal run prints the pass line
only. It does not name an unplaced record.

A recorded consolidation move may replace a numbered path with a symlink
to `docs/adr-archive/` when `docs/adr-archive/move.json` records the path,
link, and sha256. The archived bytes must match the frozen Accepted
snapshot. Any other content change still fails.

The check does not validate clause or ruling coverage in TRANSFER.md, link
targets, source status claims, body/header revision agreement, prose meaning,
or the writing target. It does not check frozen hashes, accepted revision
history, supersession chains, or human acceptance of a slot. It supports only
one indexed draft file per slot; an extra revision file is rejected. Add
revision-aware controls before accepting or storing multiple revisions.
`adr-governance.py` remains required for numbered ADRs and frozen evidence.
Editorial and transfer review remain required for the gaps above.
