//! #1174 agent-usability eval: the deterministic scripted test agent.
//!
//! No LLM. The agent walks a fixed six-step decision tree — `health`,
//! `identity`, `import-inviter-card`, `send-dm`, `join-group`,
//! `scratch-write` — and may use only two supplied texts: the stdout of
//! `x0x onboard` (the inviter's recipe) and the core SKILL.md, plus
//! ambient self-knowledge (its own daemon's API address and bearer token,
//! the `x0x` CLI path, the inviter's out-of-band card file contents).
//!
//! Doc-presence discipline is structural, not vibes: every command, flag,
//! endpoint, header, error code and remediation the tree executes is first
//! located verbatim in those texts through the [`FACTS`] table (see
//! [`require`] and [`locate`]). A fact that cannot be located fails its
//! step by name; that failure is the eval working, so no step papers over
//! a gap with product knowledge. [`check_doc_surface`] runs the same
//! table against the texts without executing anything, so a SKILL.md
//! regression fails CI on its own.
//!
//! The tree is deterministic: fixed payloads ([`DM_PAYLOAD`],
//! [`SCRATCH_VALUE`]), fixed retry counts and intervals, no randomness.
//! Agent-action failures become `Fail` step results and the tree moves on
//! to the next independent step; only harness faults (missing CLI binary,
//! unusable HTTP client) panic.
//!
//! Three response details the texts do not spell out are pinned to the
//! repo sources that define them and named here as accepted inferences:
//! `x0x agent` text output labels the id `agent_id: <64-hex>` (SKILL.md
//! documents that the command prints the agent_id, not the label format);
//! the members response carries each roster entry under
//! `members[].agent_id` / `.state` with the seated state `active`
//! (SKILL.md documents the state word); the store readback returns the
//! value under the same `value` field the documented PUT body writes. If
//! any inference stops holding, the affected step fails by name instead of
//! guessing.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use reqwest::Method;
use serde_json::{json, Value};

/// Fixed DM payload (step `send-dm`).
pub const DM_PAYLOAD: &str = "hello from agent-usability-eval";
/// Fixed scratch value (step `scratch-write`).
pub const SCRATCH_VALUE: &str = "agent-usability-eval scratch entry";

/// Success signal the texts document for CLI JSON responses (`ok: true`).
const OK_SIGNAL: &str = "ok: true";
/// Member state the skill names for a seated joiner ("until your
/// `agent_id` is `active`").
const MEMBER_STATE_ACTIVE: &str = "active";

/// Scratch store names, taken from the skill's own example so the command
/// the tree runs is the command the docs show.
const SCRATCH_STORE_NAME: &str = "scratch";
const SCRATCH_TOPIC: &str = "scratch-pad";
const SCRATCH_KEY: &str = "note";

// Fixed budgets: identical on every run.
const HEALTH_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// One durable send can take tens of seconds (the daemon's internal
/// durable-ACK budget), so the call itself gets more than the plain CLI
/// timeout.
const DM_SEND_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Documented patience for the 409 `recipient_ack_semantics_unavailable`
/// (capabilities converge slowly after a cold start): fixed retry count,
/// fixed interval, fixed overall budget.
const DM_RETRY_MAX: u32 = 10;
const DM_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const DM_TOTAL_BUDGET: Duration = Duration::from_secs(180);
/// Lookup-form discovery retries: the recipe note says discovery "may take
/// several minutes"; bounded to keep the run deterministic in wall clock.
const FIND_RETRY_MAX: u32 = 6;
const FIND_RETRY_INTERVAL: Duration = Duration::from_secs(10);
const FIND_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Member seating after a join: poll budget and interval per the skill's
/// "poll members until your `agent_id` is `active`".
const MEMBERS_POLL_BUDGET: Duration = Duration::from_secs(60);
const MEMBERS_POLL_INTERVAL: Duration = Duration::from_secs(2);
const REST_TIMEOUT: Duration = Duration::from_secs(15);

/// What the inviter sends in-band alongside the invite (a real inviter
/// names the group when handing over an invite; the link itself is opaque).
pub struct InviterGroup {
    pub group_id: String,
    pub invite: String,
}

/// Everything the scripted agent is allowed to know.
pub struct DocContext {
    /// stdout of `x0x onboard` run by the inviter (the markdown recipe).
    pub onboard_text: String,
    /// The core SKILL.md, verbatim.
    pub skill_text: String,
    /// The inviter's signed card link handed over out-of-band (file contents).
    pub inviter_card: String,
    /// The fresh agent's own daemon API address (ambient self-knowledge).
    pub my_api_addr: String,
    /// The fresh agent's own daemon bearer token (ambient self-knowledge).
    pub my_api_token: String,
    /// Path to the `x0x` CLI binary.
    pub cli_bin: PathBuf,
    /// The inviter's group handover.
    pub inviter_group: InviterGroup,
}

pub enum StepOutcome {
    Pass,
    Fail,
}

pub struct StepResult {
    pub step: &'static str,
    pub outcome: StepOutcome,
    pub detail: String,
}

pub struct ScoreCard {
    pub steps: Vec<StepResult>,
}

impl ScoreCard {
    /// No `Fail` outcomes.
    pub fn all_passed(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.outcome, StepOutcome::Pass))
    }

    /// One line per step (`PASS send-dm — ...` / `FAIL join-group — ...`)
    /// plus a final `N/6 steps passed` line.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            let tag = match step.outcome {
                StepOutcome::Pass => "PASS",
                StepOutcome::Fail => "FAIL",
            };
            out.push_str(&format!("{tag} {} — {}\n", step.step, step.detail));
        }
        let passed = self
            .steps
            .iter()
            .filter(|s| matches!(s.outcome, StepOutcome::Pass))
            .count();
        out.push_str(&format!("{passed}/{} steps passed\n", self.steps.len()));
        out
    }
}

// ── Doc-presence fact table ────────────────────────────────────────────────

/// Which supplied text a fact must live in.
#[derive(Clone, Copy)]
enum DocSource {
    Skill,
    Onboard,
    Either,
}

/// One fact the decision tree consumes: a step, a name, and the verbatim
/// needle that must appear in the source text before the tree may rely on
/// the fact. [`check_doc_surface`] and every step share this table, so the
/// runtime lookups and the no-daemon check cannot drift apart.
struct DocFact {
    step: &'static str,
    fact: &'static str,
    source: DocSource,
    needle: &'static str,
}

/// The one fact a step locates individually (to cite where the
/// `--no-durable-ack` fallback was found).
const FACT_NO_DURABLE_ACK: &str = "the documented non-durable resend flag (`--no-durable-ack`)";

const FACTS: &[DocFact] = &[
    // health
    DocFact {
        step: "health",
        fact: "a health-check CLI command (`x0x health`)",
        source: DocSource::Skill,
        needle: "x0x health",
    },
    DocFact {
        step: "health",
        fact: "daemon targeting via `--api` paired with `X0X_API_TOKEN`",
        source: DocSource::Skill,
        needle: "X0X_API_TOKEN=<token> x0x --api",
    },
    DocFact {
        step: "health",
        fact: "the documented health output signal (`ok: true`)",
        source: DocSource::Skill,
        needle: "# -> ok: true",
    },
    // identity
    DocFact {
        step: "identity",
        fact: "`x0x agent` prints the caller's agent_id",
        source: DocSource::Skill,
        needle: "prints your `agent_id`",
    },
    // import-inviter-card (which of the three recipe forms is present is
    // checked by the step itself, not by this always-required set)
    DocFact {
        step: "import-inviter-card",
        fact: "the card-import trust flag (`--trust known`)",
        source: DocSource::Onboard,
        needle: "--trust known",
    },
    // send-dm
    DocFact {
        step: "send-dm",
        fact: "the direct-send CLI form (`x0x direct send <agent_id> \"hello\"`)",
        source: DocSource::Skill,
        needle: "x0x direct send <agent_id> \"hello\"",
    },
    DocFact {
        step: "send-dm",
        fact: "the durable-commit success signal for `x0x direct send` (`ok: true`)",
        source: DocSource::Skill,
        needle: "`ok: true` means the recipient daemon durably committed",
    },
    DocFact {
        step: "send-dm",
        fact: "the documented 404 failure code (`recipient_key_unavailable`)",
        source: DocSource::Skill,
        needle: "recipient_key_unavailable",
    },
    DocFact {
        step: "send-dm",
        fact: "the documented 409 failure code (`recipient_ack_semantics_unavailable`)",
        source: DocSource::Skill,
        needle: "recipient_ack_semantics_unavailable",
    },
    DocFact {
        step: "send-dm",
        fact: "the documented remediation for both codes (retry later)",
        source: DocSource::Skill,
        needle: "Retry later",
    },
    DocFact {
        step: "send-dm",
        fact: FACT_NO_DURABLE_ACK,
        source: DocSource::Either,
        needle: "--no-durable-ack",
    },
    DocFact {
        step: "send-dm",
        fact: "the inviter's agent id in the recipe header (`I am agent <64-hex>.`)",
        source: DocSource::Onboard,
        needle: "I am agent ",
    },
    // join-group
    DocFact {
        step: "join-group",
        fact: "the group-join endpoint (`POST /groups/join`)",
        source: DocSource::Skill,
        needle: "/groups/join",
    },
    DocFact {
        step: "join-group",
        fact: "the group-join request body field (`{\"invite\": \"x0x://invite/<...>\"}`)",
        source: DocSource::Skill,
        needle: "{\"invite\":\"x0x://invite/<...>\"}",
    },
    DocFact {
        step: "join-group",
        fact: "the REST bearer auth header (`Authorization: Bearer $TOKEN`)",
        source: DocSource::Skill,
        needle: "Authorization: Bearer $TOKEN",
    },
    DocFact {
        step: "join-group",
        fact: "the REST JSON content type (`Content-Type: application/json`)",
        source: DocSource::Skill,
        needle: "Content-Type: application/json",
    },
    DocFact {
        step: "join-group",
        fact: "the group members endpoint (`GET /groups/<gid>/members`)",
        source: DocSource::Skill,
        needle: "/groups/<gid>/members",
    },
    DocFact {
        step: "join-group",
        fact: "the member state string for a seated joiner (`active`)",
        source: DocSource::Skill,
        needle: "is `active`",
    },
    // scratch-write
    DocFact {
        step: "scratch-write",
        fact: "the store-create CLI form (`x0x store create scratch scratch-pad`)",
        source: DocSource::Skill,
        needle: "x0x store create scratch scratch-pad",
    },
    DocFact {
        step: "scratch-write",
        fact: "the scratch put endpoint (`PUT /stores/scratch-pad/note`)",
        source: DocSource::Skill,
        needle: "curl -X PUT \"http://$API/stores/scratch-pad/note\"",
    },
    DocFact {
        step: "scratch-write",
        fact: "the scratch put body `value` field (base64)",
        source: DocSource::Skill,
        needle: "{\"value\":\"'$(echo -n",
    },
    DocFact {
        step: "scratch-write",
        fact: "the scratch put body `content_type` field (`text/plain`)",
        source: DocSource::Skill,
        needle: "\"content_type\":\"text/plain\"}",
    },
    DocFact {
        step: "scratch-write",
        fact: "the scratch readback endpoint (`GET /stores/scratch-pad/note`)",
        source: DocSource::Skill,
        needle: "curl \"http://$API/stores/scratch-pad/note\"",
    },
    DocFact {
        step: "scratch-write",
        fact: "the unwrapped-base64 requirement for store values",
        source: DocSource::Skill,
        needle: "wrap long lines",
    },
];

/// Recipe card-import forms (`onboard.rs` emits exactly one per recipe:
/// file default, `--inline-card`, `--no-card` lookup).
const IMPORT_FILE_FORM: &str = "x0x agent import \"$(cat '";
const IMPORT_INLINE_FORM: &str = "x0x agent import '";
const IMPORT_LOOKUP_FORM: &str = "x0x contacts add ";
const IMPORT_FORMS: [&str; 3] = [IMPORT_FILE_FORM, IMPORT_INLINE_FORM, IMPORT_LOOKUP_FORM];

/// Fail with a named gap when `needle` is absent from `haystack`.
///
/// Returns the haystack on success so callers can chain off it.
fn require<'a>(haystack: &'a str, needle: &str, fact: &str) -> Result<&'a str, String> {
    if haystack.contains(needle) {
        Ok(haystack)
    } else {
        Err(format!(
            "requires information not present in the onboard output or core skill: {fact}"
        ))
    }
}

/// Locate fact `name` in the supplied texts through [`FACTS`].
///
/// Returns where the needle was found (for the step's detail line) or the
/// named-gap error. Panics only on an unknown fact name — a code bug in
/// this module, never an agent-action failure.
fn locate(onboard: &str, skill: &str, name: &str) -> Result<&'static str, String> {
    let fact = FACTS
        .iter()
        .find(|f| f.fact == name)
        .expect("doc-fact name must exist in FACTS; keep step lookups in sync");
    match fact.source {
        DocSource::Skill => require(skill, fact.needle, name).map(|_| "SKILL.md"),
        DocSource::Onboard => require(onboard, fact.needle, name).map(|_| "the onboard recipe"),
        DocSource::Either => match require(onboard, fact.needle, name) {
            Ok(_) => Ok("the onboard recipe"),
            Err(_) => require(skill, fact.needle, name).map(|_| "SKILL.md"),
        },
    }
}

/// Locate every fact registered for `step`, failing on the first miss.
fn require_step_facts(onboard: &str, skill: &str, step: &str) -> Result<(), String> {
    for fact in FACTS.iter().filter(|f| f.step == step) {
        locate(onboard, skill, fact.fact)?;
    }
    Ok(())
}

/// Name every doc fact the decision tree needs but cannot find in the
/// supplied texts. Empty = the documented surface is complete. Runs the
/// same [`FACTS`] table the tree consumes, without executing anything.
pub fn check_doc_surface(onboard_text: &str, skill_text: &str) -> Vec<String> {
    let mut missing: Vec<String> = FACTS
        .iter()
        .filter_map(|f| locate(onboard_text, skill_text, f.fact).err())
        .collect();
    // The import step accepts any one of the three documented recipe
    // forms; which one appears depends on the inviter's delivery choice.
    if !IMPORT_FORMS
        .into_iter()
        .any(|needle| onboard_text.contains(needle))
    {
        missing.push(
            "requires information not present in the onboard output or core skill: a \
             card-import step (file, inline, or lookup form)"
                .to_string(),
        );
    }
    missing
}

// ── Execution helpers ──────────────────────────────────────────────────────

/// Result of one CLI call: exit status folded to a bool plus the combined
/// stdout and stderr (error paths print the typed code on stderr).
struct CliOutcome {
    exit_ok: bool,
    output: String,
}

/// Run the `x0x` CLI against the fresh agent's own daemon, composing the
/// skill's documented targeting form for a non-default daemon (`--api
/// <addr>` plus `X0X_API_TOKEN` in the environment, §1.2) into EVERY call.
/// The recipe's bare commands assume default-instance discovery; this
/// daemon is not the default instance, and one call that omitted the form
/// reached the machine's default daemon and was refused 401 with this
/// daemon's token. A timeout or a non-zero exit is an outcome, not a
/// panic; only a spawn failure (missing binary) is a harness fault.
async fn run_cli(ctx: &DocContext, args: &[&str], timeout: Duration) -> CliOutcome {
    let mut cmd = tokio::process::Command::new(&ctx.cli_bin);
    cmd.arg("--api")
        .arg(&ctx.my_api_addr)
        .args(args)
        .env("X0X_API_TOKEN", &ctx.my_api_token);
    let printed = format!("x0x --api <addr> {}", args.join(" "));
    match tokio::time::timeout(timeout, cmd.output()).await {
        Ok(Ok(out)) => {
            let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
            output.push('\n');
            output.push_str(&String::from_utf8_lossy(&out.stderr));
            CliOutcome {
                exit_ok: out.status.success(),
                output,
            }
        }
        Ok(Err(error)) => panic!(
            "harness fault: cannot run {} ({error})",
            ctx.cli_bin.display()
        ),
        Err(_) => CliOutcome {
            exit_ok: false,
            output: format!("timed out after {timeout:?} running `{printed}`"),
        },
    }
}

/// Result of one REST call: status code, success bool (2xx), body text.
struct RestOutcome {
    status: u16,
    ok: bool,
    body: String,
}

/// One bearer-authenticated REST call against the fresh agent's own
/// daemon, shaped like the skill's curl lines (`Authorization: Bearer`,
/// `Content-Type: application/json` for JSON bodies). Transport errors are
/// outcomes (status 0), not panics.
async fn rest(ctx: &DocContext, method: Method, path: &str, body: Option<Value>) -> RestOutcome {
    let base = if ctx.my_api_addr.starts_with("http://") || ctx.my_api_addr.starts_with("https://")
    {
        ctx.my_api_addr.clone()
    } else {
        format!("http://{}", ctx.my_api_addr)
    };
    let url = format!("{base}{path}");
    let client = reqwest::Client::builder()
        .timeout(REST_TIMEOUT)
        .build()
        .expect("harness fault: reqwest client build failed");
    let mut request = client.request(method, &url).bearer_auth(&ctx.my_api_token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    match request.send().await {
        Ok(resp) => RestOutcome {
            status: resp.status().as_u16(),
            ok: resp.status().is_success(),
            body: resp.text().await.unwrap_or_default(),
        },
        Err(error) => RestOutcome {
            status: 0,
            ok: false,
            body: format!("request failed: {error}"),
        },
    }
}

// ── Parsing helpers ────────────────────────────────────────────────────────

/// First run of exactly 64 hex characters after `marker` in `text`.
/// All agent and user ids are SHA-256 hashes rendered as 64 hex chars.
fn hex64_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let rest = text.split_once(marker)?.1;
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start == 64 {
                // Hex runs are ASCII, so the slice boundary is char-safe.
                return Some(&rest[start..i]);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The inviter's agent id: the recipe header (`I am agent <64-hex>.`)
/// with the direct-send command line as fallback.
fn inviter_agent_id(onboard: &str) -> Option<String> {
    hex64_after(onboard, "I am agent ")
        .or_else(|| hex64_after(onboard, "x0x direct send "))
        .map(String::from)
}

/// This agent's roster state in a members response, or `None` when the
/// entry is absent or the body is not the documented members shape.
fn member_state(members_body: &str, agent_id: &str) -> Option<String> {
    let value: Value = serde_json::from_str(members_body).ok()?;
    value
        .get("members")?
        .as_array()?
        .iter()
        .find(|m| m.get("agent_id").and_then(Value::as_str) == Some(agent_id))
        .and_then(|m| m.get("state"))
        .and_then(Value::as_str)
        .map(String::from)
}

/// Decode the store readback: the `value` field, standard base64,
/// unwrapped. `None` also when the response carries no `value` field.
fn readback_bytes(get_body: &str) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_str(get_body).ok()?;
    base64::engine::general_purpose::STANDARD
        .decode(value.get("value")?.as_str()?)
        .ok()
}

/// Cap captured output so a step detail stays readable in the score card.
fn excerpt(text: &str) -> String {
    const MAX_CHARS: usize = 400;
    let trimmed = text.trim();
    if trimmed.chars().count() <= MAX_CHARS {
        trimmed.to_string()
    } else {
        let cut: String = trimmed.chars().take(MAX_CHARS).collect();
        format!("{cut} [...truncated]")
    }
}

fn pass(step: &'static str, detail: String) -> StepResult {
    StepResult {
        step,
        outcome: StepOutcome::Pass,
        detail,
    }
}

fn fail(step: &'static str, detail: String) -> StepResult {
    StepResult {
        step,
        outcome: StepOutcome::Fail,
        detail,
    }
}

// ── The decision tree ──────────────────────────────────────────────────────

/// Run the deterministic decision tree. Never panics on an agent-action
/// failure: each step records a `Fail` `StepResult` and the tree continues
/// with the next independent step. Only harness faults (the CLI binary
/// missing, an unusable HTTP client) panic.
pub async fn run(ctx: DocContext) -> ScoreCard {
    let mut steps = Vec::with_capacity(6);
    steps.push(step_health(&ctx).await);
    let (identity, my_agent_id) = step_identity(&ctx).await;
    steps.push(identity);
    steps.push(step_import_inviter_card(&ctx).await);
    steps.push(step_send_dm(&ctx).await);
    steps.push(step_join_group(&ctx, my_agent_id.as_deref()).await);
    steps.push(step_scratch_write(&ctx).await);
    ScoreCard { steps }
}

/// Step `health`: the doc-located targeting form (`--api` + env
/// `X0X_API_TOKEN`), then `x0x health` must exit 0 with the documented
/// `ok: true` signal.
async fn step_health(ctx: &DocContext) -> StepResult {
    const STEP: &str = "health";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let out = run_cli(ctx, &["health"], HEALTH_CALL_TIMEOUT).await;
    if out.exit_ok && out.output.contains(OK_SIGNAL) {
        pass(
            STEP,
            format!(
                "`x0x --api <addr> health` with X0X_API_TOKEN in the environment exited 0 and \
                 printed the documented `{OK_SIGNAL}` signal"
            ),
        )
    } else {
        fail(
            STEP,
            format!(
                "health check did not meet the required signal (exit 0 + `{OK_SIGNAL}` in \
                 output); exit ok: {}; output: {}",
                out.exit_ok,
                excerpt(&out.output)
            ),
        )
    }
}

/// Step `identity`: run `x0x agent`, parse the own 64-hex agent_id (needed
/// by `join-group`). Returns the parsed id on success.
async fn step_identity(ctx: &DocContext) -> (StepResult, Option<String>) {
    const STEP: &str = "identity";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return (fail(STEP, gap), None);
    }
    let out = run_cli(ctx, &["agent"], CLI_CALL_TIMEOUT).await;
    let parsed = hex64_after(&out.output, "agent_id").map(String::from);
    if out.exit_ok && parsed.is_some() {
        let detail = format!(
            "parsed own agent_id {} (64-hex) from `x0x agent` output",
            // The guard above makes the empty default unreachable.
            parsed.as_deref().unwrap_or_default()
        );
        return (pass(STEP, detail), parsed);
    }
    (
        fail(
            STEP,
            format!(
                "could not parse a 64-hex agent_id from `x0x agent` output (exit ok: {}); \
                 SKILL.md documents that the command prints the agent_id but not the output \
                 format; output: {}",
                out.exit_ok,
                excerpt(&out.output)
            ),
        ),
        None,
    )
}

/// Step `import-inviter-card`: run whichever card-import form the recipe
/// contains, substituting the handed-over card contents into the
/// doc-located command shape. Success = exit 0.
async fn step_import_inviter_card(ctx: &DocContext) -> StepResult {
    const STEP: &str = "import-inviter-card";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let card = ctx.inviter_card.trim();
    if card.is_empty() {
        return fail(
            STEP,
            "the handed-over inviter card is empty; nothing to import".to_string(),
        );
    }
    let onboard = &ctx.onboard_text;
    // File form: `x0x agent import "$(cat '<file>')" --trust known`. The
    // quoted `$(cat '<file>')` expands to the card file's contents as one
    // argument, so the handed-over contents substitute for it directly.
    // Inline form: `x0x agent import '<link>' --trust known`, same argv.
    let file_form = onboard.contains(IMPORT_FILE_FORM);
    let inline_form = onboard.contains(IMPORT_INLINE_FORM);
    if file_form || inline_form {
        let form = if file_form {
            IMPORT_FILE_FORM
        } else {
            IMPORT_INLINE_FORM
        };
        let out = run_cli(
            ctx,
            &["agent", "import", card, "--trust", "known"],
            CLI_CALL_TIMEOUT,
        )
        .await;
        return if out.exit_ok {
            pass(
                STEP,
                format!(
                    "recipe form `{form}...` located; ran `x0x agent import <inviter card, {} \
                     bytes> --trust known` (the handed-over card contents substituted for the \
                     quoted argument); exit 0",
                    card.len()
                ),
            )
        } else {
            fail(
                STEP,
                format!(
                    "`x0x agent import <inviter card> --trust known` failed; output: {}",
                    excerpt(&out.output)
                ),
            )
        };
    }
    // Lookup form: `x0x agents find <id>` then
    // `x0x contacts add <id> --trust known --label inviter`.
    if onboard.contains(IMPORT_LOOKUP_FORM) {
        let Some(inviter) = inviter_agent_id(onboard) else {
            return fail(
                STEP,
                "lookup form located but the inviter's agent id could not be parsed from the \
                 recipe header"
                    .to_string(),
            );
        };
        // The recipe note permits repeating `x0x agents find` (discovery
        // takes minutes); retries run only when that note is present.
        let retries = if require(
            onboard,
            "repeat `x0x agents find`",
            "the documented retry rule for `x0x agents find`",
        )
        .is_ok()
        {
            FIND_RETRY_MAX
        } else {
            1
        };
        let mut find_ok = false;
        let mut find_output = String::new();
        for attempt in 1..=retries {
            let out = run_cli(
                ctx,
                &["agents", "find", inviter.as_str()],
                FIND_CALL_TIMEOUT,
            )
            .await;
            if out.exit_ok {
                find_ok = true;
                break;
            }
            find_output = out.output;
            if attempt < retries {
                tokio::time::sleep(FIND_RETRY_INTERVAL).await;
            }
        }
        if !find_ok {
            return fail(
                STEP,
                format!(
                    "lookup form: `x0x agents find <inviter>` did not succeed within the \
                     budget the recipe describes for network discovery; last output: {}",
                    excerpt(&find_output)
                ),
            );
        }
        let out = run_cli(
            ctx,
            &[
                "contacts",
                "add",
                inviter.as_str(),
                "--trust",
                "known",
                "--label",
                "inviter",
            ],
            CLI_CALL_TIMEOUT,
        )
        .await;
        return if out.exit_ok {
            pass(
                STEP,
                "lookup form: `x0x agents find <inviter>` and `x0x contacts add <inviter> \
                 --trust known --label inviter` both exited 0"
                    .to_string(),
            )
        } else {
            fail(
                STEP,
                format!(
                    "lookup form: `x0x contacts add <inviter> --trust known --label inviter` \
                     failed; output: {}",
                    excerpt(&out.output)
                ),
            )
        };
    }
    fail(
        STEP,
        "requires information not present in the onboard output or core skill: a card-import \
         step (file, inline, or lookup form)"
            .to_string(),
    )
}

/// Step `send-dm`: doc-located `x0x direct send <inviter> "<payload>"`.
/// Documented remediation only: patience for the 409 (fixed retries in
/// the fixed budget), then the `--no-durable-ack` fallback, and for the
/// 404 the recipe's remedy (card import) is already `import-inviter-card`,
/// so a 404 that never clears fails by name. Required success signal:
/// exit 0 plus `ok: true` in the output.
async fn step_send_dm(ctx: &DocContext) -> StepResult {
    const STEP: &str = "send-dm";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let Some(inviter) = inviter_agent_id(&ctx.onboard_text) else {
        return fail(
            STEP,
            "could not parse the inviter's agent id from the recipe header (`I am agent \
             <64-hex>.`) or the direct-send command line"
                .to_string(),
        );
    };
    let mut attempts = 0u32;
    let mut last = String::new();
    let deadline = tokio::time::Instant::now() + DM_TOTAL_BUDGET;
    while attempts < DM_RETRY_MAX {
        attempts += 1;
        let out = run_cli(
            ctx,
            &["direct", "send", inviter.as_str(), DM_PAYLOAD],
            DM_SEND_CALL_TIMEOUT,
        )
        .await;
        if out.exit_ok && out.output.contains(OK_SIGNAL) {
            return pass(
                STEP,
                format!(
                    "`x0x direct send <inviter> \"{DM_PAYLOAD}\"` succeeded on attempt \
                     {attempts}; required signal met: exit 0 plus `{OK_SIGNAL}` in output \
                     (the documented durable-commit signal)"
                ),
            );
        }
        last = out.output;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(DM_RETRY_INTERVAL).await;
    }
    if last.contains("recipient_key_unavailable") {
        return fail(
            STEP,
            format!(
                "named gap: the documented 404 recipient_key_unavailable never cleared after \
                 {attempts} attempts over the ~180 s budget; the recipe's remedy (import the \
                 inviter's card) was already applied in step import-inviter-card; last output: \
                 {}",
                excerpt(&last)
            ),
        );
    }
    if last.contains("recipient_ack_semantics_unavailable") {
        // The texts must name the CLI flag spelling before it is used.
        return match locate(&ctx.onboard_text, &ctx.skill_text, FACT_NO_DURABLE_ACK) {
            Ok(found_in) => {
                let out = run_cli(
                    ctx,
                    &[
                        "direct",
                        "send",
                        inviter.as_str(),
                        DM_PAYLOAD,
                        "--no-durable-ack",
                    ],
                    DM_SEND_CALL_TIMEOUT,
                )
                .await;
                if out.exit_ok && out.output.contains(OK_SIGNAL) {
                    pass(
                        STEP,
                        format!(
                            "durable sends returned the documented 409 \
                             recipient_ack_semantics_unavailable for {attempts} attempts over \
                             the ~180 s budget; the documented fallback `--no-durable-ack` \
                             (located in {found_in}) succeeded with exit 0 plus `{OK_SIGNAL}`"
                        ),
                    )
                } else {
                    fail(
                        STEP,
                        format!(
                            "the documented fallback `--no-durable-ack` (located in \
                             {found_in}) also failed; output: {}",
                            excerpt(&out.output)
                        ),
                    )
                }
            }
            Err(gap) => fail(STEP, gap),
        };
    }
    fail(
        STEP,
        format!(
            "direct send did not meet the required signal (exit 0 plus `{OK_SIGNAL}` in \
             output) within {attempts} attempts over the ~180 s budget; last output: {}",
            excerpt(&last)
        ),
    )
}

/// Step `join-group`: POST /groups/join with the invite body, then poll
/// GET /groups/<gid>/members until this agent's entry is `active`.
async fn step_join_group(ctx: &DocContext, my_agent_id: Option<&str>) -> StepResult {
    const STEP: &str = "join-group";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let Some(my_id) = my_agent_id else {
        return fail(
            STEP,
            "cannot confirm membership: step identity produced no agent_id to match against \
             the member list"
                .to_string(),
        );
    };
    let join = rest(
        ctx,
        Method::POST,
        "/groups/join",
        Some(json!({ "invite": ctx.inviter_group.invite })),
    )
    .await;
    if !join.ok {
        return fail(
            STEP,
            format!(
                "POST /groups/join returned HTTP {} (body: {})",
                join.status,
                excerpt(&join.body)
            ),
        );
    }
    let members_path = format!("/groups/{}/members", ctx.inviter_group.group_id);
    let deadline = tokio::time::Instant::now() + MEMBERS_POLL_BUDGET;
    let mut last_observed = String::from("no members entry for this agent yet");
    loop {
        let members = rest(ctx, Method::GET, &members_path, None).await;
        let seated = if members.ok {
            member_state(&members.body, my_id)
        } else {
            None
        };
        if let Some(state) = seated {
            if state == MEMBER_STATE_ACTIVE {
                return pass(
                    STEP,
                    format!(
                        "POST /groups/join returned HTTP {}; GET /groups/<gid>/members \
                             then listed this agent ({my_id}) with the documented \
                             `{MEMBER_STATE_ACTIVE}` state",
                        join.status
                    ),
                );
            }
            last_observed = format!("entry state `{state}`");
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(MEMBERS_POLL_INTERVAL).await;
    }
    fail(
        STEP,
        format!(
            "joined (POST /groups/join returned HTTP {}) but the member list never showed \
             this agent with the documented `{MEMBER_STATE_ACTIVE}` state within the ~60 s \
             poll budget (last observed: {last_observed})",
            join.status
        ),
    )
}

/// Step `scratch-write`: create the store via the CLI, PUT the fixed value
/// via REST, then GET the readback and decode it. Success = the readback
/// decodes to exactly [`SCRATCH_VALUE`].
async fn step_scratch_write(ctx: &DocContext) -> StepResult {
    const STEP: &str = "scratch-write";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let create = run_cli(
        ctx,
        &["store", "create", SCRATCH_STORE_NAME, SCRATCH_TOPIC],
        CLI_CALL_TIMEOUT,
    )
    .await;
    if !create.exit_ok {
        return fail(
            STEP,
            format!(
                "`x0x store create {SCRATCH_STORE_NAME} {SCRATCH_TOPIC}` failed; output: {}",
                excerpt(&create.output)
            ),
        );
    }
    // Standard alphabet, unwrapped: SKILL.md warns GNU/BSD base64 wrap
    // long lines (`tr -d '\n'`); a wrapped value breaks the JSON body.
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(SCRATCH_VALUE.as_bytes());
    let key_path = format!("/stores/{SCRATCH_TOPIC}/{SCRATCH_KEY}");
    let put = rest(
        ctx,
        Method::PUT,
        &key_path,
        Some(json!({ "value": value_b64, "content_type": "text/plain" })),
    )
    .await;
    if !put.ok {
        return fail(
            STEP,
            format!(
                "PUT {key_path} returned HTTP {} (body: {})",
                put.status,
                excerpt(&put.body)
            ),
        );
    }
    let get = rest(ctx, Method::GET, &key_path, None).await;
    if !get.ok {
        return fail(
            STEP,
            format!(
                "GET {key_path} readback returned HTTP {} (body: {})",
                get.status,
                excerpt(&get.body)
            ),
        );
    }
    match readback_bytes(&get.body) {
        Some(bytes) if bytes == SCRATCH_VALUE.as_bytes() => pass(
            STEP,
            format!(
                "store created via CLI (exit 0); PUT {key_path} returned HTTP {}; GET readback \
                 decoded to exactly the scratch value ({SCRATCH_VALUE:?})",
                put.status
            ),
        ),
        Some(other) => fail(
            STEP,
            format!(
                "GET readback decoded to {:?}, expected {SCRATCH_VALUE:?}",
                String::from_utf8_lossy(&other)
            ),
        ),
        None => fail(
            STEP,
            "requires information not present in the onboard output or core skill: the GET \
             /stores/<topic>/<key> response shape (the readback `value` field)"
                .to_string(),
        ),
    }
}
