---
name: e2e-prove
description: Run and prove x0x end-to-end tests across VPS, LAN, and local. Uses haiku to run tests, sonnet to evaluate results, opus for code fixes. Generates proof reports with round-trip verification.
---

# /e2e-prove - End-to-End Test & Proof Suite

Run x0x E2E tests, evaluate results, fix issues, and generate proof reports.

## Usage

```bash
/e2e-prove              # Interactive — asks which suite to run
/e2e-prove vps          # VPS all-pairs matrix (6 bootstrap nodes)
/e2e-prove lan          # LAN suite (studio1 + LAN_PEER_HOST, e.g. the MacBook)
/e2e-prove local        # Local loopback (alice + bob)
/e2e-prove all          # Run all suites sequentially
/e2e-prove status       # Show latest proof reports
```

---

## Model Delegation Strategy

This skill uses three model tiers for cost-efficiency:

| Phase | Model | Why |
|-------|-------|-----|
| **Run tests** | Haiku | Cheap, fast — just executes bash scripts and captures output |
| **Evaluate results** | Sonnet | Mid-tier analysis — parses logs, identifies failure patterns, writes proof reports |
| **Fix issues** | Opus | Heavy lifting — only invoked when code changes are needed |

---

## Phase 1: Pre-Flight (runs inline, no subagent)

Before launching any test suite, verify prerequisites:

```
1. Check binary exists:
   - cargo build --release (if target/release/x0xd missing or stale)
   - Verify: target/release/x0xd and target/release/x0x both exist

2. Check proof-reports directory:
   - mkdir -p tests/proof-reports

3. Generate run ID:
   - RUN_ID = "suite_{suite}_{timestamp}_{pid}"
   - LOG_FILE = "tests/proof-reports/${RUN_ID}.log"
   - PROOF_FILE = "tests/proof-reports/PROOF_REPORT_${RUN_ID}.md"
```

---

## Phase 2: Run Tests (Haiku subagent)

Launch a **haiku** subagent to execute the test script and capture raw output.

### For VPS suite:
```
Agent(model: haiku, description: "Run VPS E2E tests"):
  prompt: |
    Execute the VPS end-to-end test suite and capture all output.

    Run this command and capture ALL stdout+stderr:
      bash tests/e2e_vps.sh 2>&1 | tee tests/proof-reports/{RUN_ID}.log

    IMPORTANT:
    - Do NOT interpret or fix failures — just run and capture
    - If the script exits non-zero, that's expected (means failures occurred)
    - Capture the ENTIRE output including the summary line
    - After the script completes, run: echo "EXIT_CODE=$?"
    - Also capture the proof token from the output (grep for "PROOF TOKEN:")

    When done, report:
    1. The exit code
    2. The PASS/FAIL/SKIP counts from the summary line
    3. The proof token
    4. The full path to the log file
```

### For LAN suite:
```
Agent(model: haiku, description: "Run LAN E2E tests"):
  prompt: |
    Execute the LAN end-to-end test suite and capture all output.

    Run: bash tests/e2e_lan.sh 2>&1 | tee tests/proof-reports/{RUN_ID}.log

    Same rules as VPS: capture everything, report exit code + counts + proof token.
```

### For local suite:
```
Agent(model: haiku, description: "Run local E2E tests"):
  prompt: |
    Execute the local self-contained proof suite and capture all output.

    Run:
      bash tests/e2e_full_audit.sh 2>&1 | tee tests/proof-reports/{RUN_ID}.log

    IMPORTANT:
    - tests/e2e_full_audit.sh is self-contained: it starts fresh local daemons,
      verifies REST + CLI + SSE + WebSocket + GUI + file transfer + shutdown,
      then cleans up.
    - Do NOT substitute older local scripts unless the main script is missing.

    Capture everything, report exit code + counts + proof token.
```

---

## Phase 3: Evaluate Results (Sonnet subagent)

Launch a **sonnet** subagent to analyse the test output and produce a proof report.

```
Agent(model: sonnet, description: "Evaluate E2E test results"):
  prompt: |
    You are evaluating x0x end-to-end test results. Read the log file at:
      tests/proof-reports/{RUN_ID}.log

    Produce a structured proof report at:
      tests/proof-reports/PROOF_REPORT_{RUN_ID}.md

    The report MUST contain these sections:

    ## Header
    - Suite: {vps|lan|local}
    - Run ID: {RUN_ID}
    - Timestamp: {ISO 8601}
    - Version: (extract from log)
    - Proof Token: (extract from log — this proves the test actually ran)

    ## Summary
    - Total / Pass / Fail / Skip counts
    - Overall verdict: PASS (0 failures), PARTIAL (some failures), FAIL (critical failures)

    ## Interface Proof Matrix (VPS only)
    Create a table showing which interfaces were proven:

    | Interface | Send Proven | Receive Proven | Evidence |
    |-----------|------------|----------------|----------|
    | REST API (POST /direct/send) | Yes/No | Yes/No | line numbers |
    | CLI (x0x direct send) | Yes/No | Yes/No | line numbers |
    | GUI (/gui + /ws/direct) | Yes/No | Yes/No | line numbers |

    ## All-Pairs Matrix (VPS only)
    Create a 6x6 matrix showing connect + send + receive status:

    |          | NYC | SFO | Helsinki | Nuremberg | Singapore | Tokyo |
    |----------|-----|-----|----------|-----------|-----------|-------|
    | NYC      | -   | ... | ...      | ...       | ...       | ...   |
    | SFO      | ... | -   | ...      | ...       | ...       | ...   |
    | ...      |     |     |          |           |           |       |

    Use: OK (connected+sent), SEND (sent but unverified receipt), FAIL (connection failed), SKIP (not attempted)

    ## Failures
    For each failure, extract:
    - Test name
    - Expected vs actual
    - Category (connect/send/receive/api/trust/mls/etc.)
    - Likely root cause (network timeout, auth, endpoint error, etc.)

    ## Proof Artifacts
    List all proof tokens found in the output with their line numbers.

    ## Recommendations
    - If 0 failures: "Suite fully proven. Ready for release."
    - If failures are environmental (timeouts, SSH): "Retry recommended — failures are transient."
    - If failures are systematic (same endpoint, same error): "Code fix needed — escalate to Opus."

    IMPORTANT: Only report what the log file actually shows. Never fabricate results.
    Cross-reference every claim with a line number from the log file.
```

---

## Phase 4: Triage & Fix (Opus subagent, conditional)

Only invoke if the sonnet evaluator recommends "Code fix needed".

```
IF evaluation.verdict == "Code fix needed":
  Agent(model: opus, description: "Fix E2E test failures"):
    prompt: |
      The x0x E2E test suite has systematic failures that need code fixes.

      Read the proof report at: tests/proof-reports/PROOF_REPORT_{RUN_ID}.md
      Read the raw log at: tests/proof-reports/{RUN_ID}.log

      The evaluator identified these failures as requiring code changes (not environmental):
      {list of systematic failures from the report}

      Your job:
      1. Diagnose the root cause for each systematic failure
      2. Read the relevant source files
      3. Make minimal, targeted fixes
      4. Run: cargo fmt --all -- --check
      5. Run: RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features -- -D warnings
      6. Both MUST pass with zero warnings

      RULES:
      - Fix only what's broken — don't refactor surrounding code
      - No .unwrap() or .expect() in production code
      - If a test script has a bug (vs the daemon), fix the test script
      - After fixing, report what changed and why

      DO NOT re-run the full test suite — that will be done in a follow-up /e2e-prove run.
```

---

## Phase 5: Report (runs inline)

After all phases complete, present the results to the user:

```
1. Read the proof report: tests/proof-reports/PROOF_REPORT_{RUN_ID}.md

2. Print a concise summary:
   - Suite: VPS/LAN/Local
   - Verdict: PASS/PARTIAL/FAIL
   - Pass/Fail/Skip counts
   - Interface proofs confirmed (VPS)
   - All-pairs matrix summary (VPS)
   - Any fixes applied (if Opus was invoked)
   - Proof token for verification

3. If fixes were applied:
   - List files changed
   - Suggest: "Run /e2e-prove {suite} again to verify fixes"

4. If all passed:
   - Suggest: "Ready for /gsd-commit"
```

---

## Behavior: /e2e-prove status

Show the latest proof reports without running tests:

```
1. List all proof reports:
   ls -lt tests/proof-reports/PROOF_REPORT_*.md | head -10

2. Read the most recent one and print its Summary section

3. Show a timeline of recent runs:
   - Date, suite, verdict, pass/fail counts
```

---

## API Coverage Auto-Detection

Before generating the proof report, always run the coverage tool:

```
bash tests/api-coverage.sh
```

This automatically extracts all routes from `src/bin/x0xd.rs`, compares them against the full E2E shell suite (`full_audit`, `comprehensive`, `full`, `vps`, `lan`, `live`, `stress`), and reports gaps. The evaluator should include the coverage percentage in the proof report and must call out any non-zero UNTESTED count explicitly.

Use `-v` for verbose (shows which suites cover each route), `--test-endpoints` to debug extraction.

---

## Test Script Locations

| Suite | Script | Scope |
|-------|--------|-------|
| VPS | tests/e2e_vps.sh | 6 bootstrap nodes, all-pairs matrix |
| LAN | tests/e2e_lan.sh | studio1 + LAN_PEER_HOST (second LAN node) |
| Local | tests/e2e_full_audit.sh | Self-contained local loopback proof: 83 endpoints + CLI + GUI + SSE + WS + file transfer + shutdown + swarm |
| Local (alt) | tests/e2e_comprehensive.sh | Local loopback (older) |
| Coverage | tests/api-coverage.sh | Auto-detect untested routes |

## Proof Report Location

All reports go to `tests/proof-reports/`:
- `suite_{name}_{timestamp}.log` — raw test output
- `PROOF_REPORT_suite_{name}_{timestamp}.md` — structured analysis

---

## Important Notes

- **Proof tokens**: Every test run generates a unique proof token embedded in payloads. The token proves tests actually executed (not cached/faked results).
- **SSE receive verification**: VPS tests start SSE listeners on each node before sending, then check for proof tokens in the captured SSE output. SSH-tunneled SSE can be flaky — receipt failures are warned, not hard failures.
- **Build before test**: Always ensure `target/release/x0xd` and `target/release/x0x` are current before running LAN/local tests. VPS tests use already-deployed binaries.
- **Token acquisition**: VPS tests read API tokens from `tests/.vps-tokens.env` or via SSH fallback. LAN tests read from the daemon's data directory.
- **GUI proof**: The local suite performs real browser automation against `/gui`, imports an agent card through the GUI, sends a direct message through the GUI, and verifies receive-side delivery.
- **Proof levels**: Distinguish route-hit proof from functional proof. Prefer receive-side or round-trip verification (`events`, `direct/events`, file accept/complete, WS receive, GUI send) over "HTTP 200" smoke checks.
