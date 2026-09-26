---
# x0x Symphony workflow profile.
#
# This intentionally does NOT use Linear. It defines a small tracker extension
# that can be implemented by x0x-symphony before we replace it with native x0x
# CRDT task lists.
#
# Compatibility note: OpenAI Symphony draft v1 only standardizes
# tracker.kind=linear. Stock v1 runners will reject tracker.kind=git_issues
# unless they implement this extension.
tracker:
  kind: git_issues
  path: issues/issues.jsonl
  project_slug: x0x
  active_states:
    - todo
    - in_progress
  terminal_states:
    - done
    - cancelled
    - duplicate
  review_states:
    - review
  blocked_states:
    - blocked
  id_prefix: X0X
  lock_mode: git

# GitHub Issues adapter is intentionally NOT a v1.0 target for x0x-symphony.
# See ../x0x-symphony/docs/adr/0003-no-external-tracker-v1.md — v1.0 ships
# with one tracker (x0x_crdt) and nothing else. The block below is left for
# reference only; setting enabled=true does not engage any runner.
github_issues:
  enabled: false
  owner: saorsa-labs
  repo: x0x

polling:
  interval_ms: 30000

workspace:
  # Each issue workspace contains sibling checkouts:
  #   <root>/<issue>/x0x
  #   <root>/<issue>/ant-quic
  #   <root>/<issue>/saorsa-gossip
  # This preserves x0x's existing Cargo path dependencies from x0x/ to
  # ../ant-quic and ../saorsa-gossip while keeping issue work isolated.
  root: ~/x0x-symphony/workspaces

hooks:
  timeout_ms: 120000

  after_create: |
    set -euo pipefail

    clone_repo() {
      local name="$1"
      local url="$2"
      local local_path_var="$3"
      local local_path="${!local_path_var:-}"

      if [ -n "$local_path" ]; then
        git clone "$local_path" "$name"
      else
        git clone "$url" "$name"
      fi
    }

    clone_repo x0x "${X0X_REPO_URL:-https://github.com/saorsa-labs/x0x.git}" X0X_REPO_PATH
    clone_repo ant-quic "${ANT_QUIC_REPO_URL:-https://github.com/saorsa-labs/ant-quic.git}" ANT_QUIC_REPO_PATH
    clone_repo saorsa-gossip "${SAORSA_GOSSIP_REPO_URL:-https://github.com/saorsa-labs/saorsa-gossip.git}" SAORSA_GOSSIP_REPO_PATH

    git -C x0x status --short
    git -C ant-quic status --short
    git -C saorsa-gossip status --short

  before_run: |
    set -euo pipefail

    test -d x0x/.git
    test -d ant-quic/.git
    test -d saorsa-gossip/.git
    test -f x0x/AGENTS.md
    test -f x0x/justfile
    test -f x0x/issues/issues.jsonl

  after_run: |
    set +e

    if [ -d x0x ]; then
      (
        cd x0x
        just fmt-check
        just lint
      )
    fi

  before_remove: |
    set +e
    git -C x0x status --short || true

agent:
  max_concurrent_agents: 2
  max_concurrent_agents_by_state:
    todo: 1
    in_progress: 1
  max_turns: 8
  max_retry_backoff_ms: 300000

# Runner configuration. x0x-symphony is harness-agnostic: the canonical runner
# is `shell`, with thin presets for codex, claude_code, kimi, glm, minimax, and
# pi. See ../x0x-symphony/docs/design/symphony.md §5.2 and
# ../x0x-symphony/docs/adr/0001-tracker-abstraction.md.
runner:
  kind: shell
  preset: claude_code
  approval_policy: untrusted
  turn_timeout_ms: 3600000
  read_timeout_ms: 5000
  stall_timeout_ms: 300000

# Legacy codex: block. Preserved for backward compatibility with the bootstrap
# scaffold; superseded by runner: above. Will be deprecated in M4.
codex:
  command: codex app-server
  approval_policy: untrusted
  turn_timeout_ms: 3600000
  read_timeout_ms: 5000
  stall_timeout_ms: 300000
---
# x0x Agent Workflow

You are working on x0x issue `{{ issue.identifier }}`: **{{ issue.title }}**.

The Symphony workspace root for this issue contains three sibling checkouts:

- `x0x/` — primary repository. Make issue changes here unless explicitly instructed otherwise.
- `ant-quic/` — path dependency used by x0x.
- `saorsa-gossip/` — path dependency used by x0x.

## Issue context

- State: `{{ issue.state }}`
- Priority: `{{ issue.priority }}`
- Labels: `{{ issue.labels }}`
- URL/source: `{{ issue.url }}`
- Attempt: `{{ attempt }}`

Description:

{{ issue.description }}

## Required orientation

Before editing code:

1. Read `x0x/AGENTS.md`.
2. Read any docs or modules directly relevant to the issue.
3. Check `x0x/issues/schema.md` so issue state updates stay machine-readable.

## Project rules

- Use `just` recipes from `x0x/justfile`.
- Keep changes focused on this issue.
- Prefer small, reviewable commits/patches.
- Production Rust must avoid `unwrap`, `expect`, and `panic!`; tests may use them for clarity.
- Use structured errors (`thiserror`, context-rich results) instead of panics in production paths.
- Preserve x0x's architecture:
  - `x0xd` is the daemon and local REST/WebSocket API boundary.
  - non-Rust integrations talk to the daemon, not FFI.
  - transport is `ant-quic`; gossip/CRDT/pubsub is `saorsa-gossip`.
  - user/group data must remain partition-tolerant and not depend on a global DHT.
- Do not edit secrets, local keys, or machine-specific config.
- Do not change files outside this issue workspace.

## Validation expectations

Run the narrowest useful validation while developing, then run broader checks before handoff when practical:

```bash
cd x0x
just fmt-check
just lint
just test
```

For documentation-only changes, at minimum run:

```bash
cd x0x
just fmt-check
```

If a check cannot run because of missing local dependencies, credentials, or host limits, record that explicitly in the handoff.

## Issue database handoff

The canonical non-Linear issue database is `x0x/issues/issues.jsonl`.

When you finish useful work:

1. Update the issue record for `{{ issue.identifier }}`.
2. Set `state` to `review` for human review, or leave it active if more agent work is required.
3. Update `updated_at`.
4. Add a concise `handoff` object with:
   - `summary`
   - `files_changed`
   - `validation`
   - `follow_up`
5. Do not mark the issue `done`; humans close issues after review.

## Final response

Summarize:

- what changed
- files touched
- validation run and result
- any risks or follow-up
