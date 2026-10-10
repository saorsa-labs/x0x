# ADR Tooling and AI Harness Setup

## Use the 15 slot plan

Read [the consolidation rules](consolidated/README.md) before creating a record.
During transfer, new or changed decisions use the numbered ADR series only,
through [the template](TEMPLATE.md) and ADR 0087 (D199). Slot revisions are
drafts until David accepts the transfer. Do not allocate A16 or start a
second consolidated series. Keep reserved numbers 0090/0091 (D18), 0097
(D20), 0098 (D35), and 0084–0105 (D63). Slices 0109–0114 continue to
acceptance as numbered ADRs. The tools below support that numbered series.
Use [the writing guide](../documentation-style.md) for new and changed prose.

We use ADRs as engineering memory, not paperwork. They capture *why* a decision was made, what alternatives were rejected, and what consequences we accept.

## Install `adrs`

`adrs` is the preferred local CLI for creating, searching, and checking ADRs.

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
Before changing architecture, protocols, storage formats, crypto, network behaviour, public APIs, data models, or operational invariants, inspect docs/adr/.
D199: during transfer, new or changed decisions use the numbered ADR series only, through docs/adr/TEMPLATE.md and ADR 0087.
A01-A15 slot revisions are drafts until David accepts the transfer. Do not create A16 or a second consolidated series.
Keep reserved numbers 0090/0091 (D18), 0097 (D20), 0098 (D35), and 0084–0105 (D63); slices 0109–0114 continue to numbered acceptance. Keep their current gates.
Use approximately 80% ASD-STE100 style in ADRs, docs and communication with David. Follow docs/documentation-style.md.
Never edit an Accepted ADR. Create a superseding ADR instead.
Never mark an ADR Accepted autonomously; that requires human engineering review and debate.
During review, check ADR correctness, rejected alternatives, evidence, consequences, and immutable-Accepted compliance.
```

## Review standard

Do **not** "vibe code" ADRs. A useful ADR must show clear thinking: context, options, trade-offs, consequences, and validation. AI can help prepare a draft, but humans must debate and own the decision.

## Transition check coverage

`python3 scripts/check-adr-consolidation.py` checks the index shape, exactly
15 distinct slots, matching indexed titles and file revisions, regular
record paths, required section headings, and a leading Proposed status token.
It rejects unindexed files and early activation. Status annotations are
allowed, as in `adr-governance.py`; Accepted annotations remain rejected.

`python3 scripts/check-adr-count.py` fails when the current count exceeds
15. The plan is `docs/adr/consolidated/README.md`. Records in the transfer
map keep their paths as links and stay outside that count. A legal run
prints the pass line only. It does not name an unplaced record.

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
