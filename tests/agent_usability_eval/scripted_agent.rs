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
//! [`require`] and [`locate`]). Each needle states the COMPLETE command
//! shape — the curl line with its `-X` method for REST facts, the
//! `x0x ...` command words for CLI facts — and the tree DERIVES what it
//! executes from the located needle ([`needle_rest`], [`needle_argv`]),
//! so no step runs a second, hard-coded copy of a documented command. A
//! doc that changes a documented method or swaps a command for one that
//! does not exist therefore fails its step by name before anything runs;
//! that failure is the eval working, so no step papers over a gap with
//! product knowledge. [`check_doc_surface`] runs the same table against
//! the texts without executing anything, so a SKILL.md regression fails
//! CI on its own.
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
use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use reqwest::Method;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

/// Fixed DM payload (step `send-dm`).
pub const DM_PAYLOAD: &str = "hello from agent-usability-eval";
/// Fixed scratch value (step `scratch-write`).
pub const SCRATCH_VALUE: &str = "agent-usability-eval scratch entry";

/// Success signal the texts document for CLI JSON responses (`ok: true`).
const OK_SIGNAL: &str = "ok: true";
/// Member state the skill names for a seated joiner ("until your
/// `agent_id` is `active`").
const MEMBER_STATE_ACTIVE: &str = "active";

// Fact names the tree also derives executable command shapes from. Shared
// consts keep the FACTS entries and the step lookups pointing at the same
// fact, so a renamed fact fails loudly instead of silently skipping its
// check.
const FACT_HEALTH_CMD: &str = "a health-check CLI command (`x0x health`)";
const FACT_IDENTITY_CMD: &str = "`x0x agent` prints the caller's agent_id";
const FACT_DIRECT_SEND_CMD: &str =
    "the direct-send CLI form (`x0x direct send <agent_id> \"hello\"`)";
const FACT_STORE_CREATE_CMD: &str =
    "the store-create CLI form (`x0x store create scratch scratch-pad`)";
const FACT_JOIN_ENDPOINT: &str = "the group-join endpoint (`POST /groups/join`)";
const FACT_MEMBERS_ENDPOINT: &str = "the group members endpoint (`GET /groups/<gid>/members`)";
const FACT_STORE_PUT_ENDPOINT: &str = "the scratch put endpoint (`PUT /stores/scratch-pad/note`)";
const FACT_STORE_READBACK_ENDPOINT: &str =
    "the scratch readback endpoint (`GET /stores/scratch-pad/note`)";
/// The one fact a step locates individually (to cite where the
/// `--no-durable-ack` fallback was found).
const FACT_NO_DURABLE_ACK: &str = "the documented non-durable resend flag (`--no-durable-ack`)";

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

const FACTS: &[DocFact] = &[
    // health
    DocFact {
        step: "health",
        fact: FACT_HEALTH_CMD,
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
        fact: FACT_IDENTITY_CMD,
        // The needle pins the command itself, not just the promise: a doc
        // that renames the command makes this fact a named gap before the
        // step runs anything.
        source: DocSource::Skill,
        needle: "`x0x agent` prints your `agent_id`",
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
        fact: FACT_DIRECT_SEND_CMD,
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
        // The needle is the complete curl line with its method: a doc that
        // changes the documented method (say POST to DELETE) makes this
        // fact a named gap before the step executes anything.
        fact: FACT_JOIN_ENDPOINT,
        source: DocSource::Skill,
        needle: "curl -X POST \"http://$API/groups/join\"",
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
        // Plain `curl "URL"` (no `-X`) is the documented GET shape; the
        // needle pins it so a rewritten method breaks the fact by name.
        fact: FACT_MEMBERS_ENDPOINT,
        source: DocSource::Skill,
        needle: "curl \"http://$API/groups/<gid>/members\"",
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
        fact: FACT_STORE_CREATE_CMD,
        source: DocSource::Skill,
        needle: "x0x store create scratch scratch-pad",
    },
    DocFact {
        step: "scratch-write",
        fact: FACT_STORE_PUT_ENDPOINT,
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
        fact: FACT_STORE_READBACK_ENDPOINT,
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
/// The lookup recipe's discovery command line (`x0x agents find <id>`).
const IMPORT_FIND_FORM: &str = "x0x agents find ";
/// The recipe's note permitting repeated `x0x agents find` (discovery
/// takes minutes); it extends the attempt budget but is not the command
/// source.
const IMPORT_FIND_NOTE: &str = "repeat `x0x agents find`";

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

/// The FACTS entry named `name`. Panics on an unknown name — a code bug
/// in this module, never an agent-action failure.
fn fact_named(name: &str) -> &'static DocFact {
    FACTS
        .iter()
        .find(|f| f.fact == name)
        .expect("doc-fact name must exist in FACTS; keep step lookups in sync")
}

/// Locate fact `name` in the supplied texts through [`FACTS`].
///
/// Returns where the needle was found (for the step's detail line) or the
/// named-gap error.
fn locate(onboard: &str, skill: &str, name: &str) -> Result<&'static str, String> {
    let fact = fact_named(name);
    match fact.source {
        DocSource::Skill => require(skill, fact.needle, name).map(|_| "SKILL.md"),
        DocSource::Onboard => require(onboard, fact.needle, name).map(|_| "the onboard recipe"),
        DocSource::Either => match require(onboard, fact.needle, name) {
            Ok(_) => Ok("the onboard recipe"),
            Err(_) => require(skill, fact.needle, name).map(|_| "SKILL.md"),
        },
    }
}

/// The argv (without the `x0x` program word) that a command needle
/// prescribes, so the tree executes the command shape the texts state
/// instead of a second, hard-coded copy. The leading command is the
/// first backticked `x0x ...` span when the needle carries one, else the
/// needle's leading bare words; derivation stops at the first operand
/// marker (`<...>`, a quote, a `$` form) so callers append their own
/// concrete operands. Panics on a needle with no `x0x` command — a
/// FACTS-table bug, never an agent outcome.
fn needle_argv(needle: &'static str) -> Vec<&'static str> {
    let command = match needle.split('`').nth(1) {
        Some(backticked) => backticked,
        None => {
            let cut = needle
                .find(|c: char| ['<', '"', '\'', '$'].contains(&c))
                .unwrap_or(needle.len());
            needle[..cut].trim_end()
        }
    };
    let words: Vec<&str> = command.split_whitespace().collect();
    assert!(
        words.first() == Some(&"x0x"),
        "harness bug: doc-fact needle must lead with an `x0x` command: {needle}"
    );
    words[1..].to_vec()
}

/// The HTTP method and URL path that a REST fact's curl-line needle
/// prescribes: an `-X <METHOD>` word states the method, a plain
/// `curl "URL"` line is a GET. The path keeps the doc's placeholders
/// (for example `<gid>`); the caller substitutes the concrete value.
/// Panics on a needle that is not such a curl line — a FACTS-table bug,
/// never an agent outcome.
fn needle_rest(needle: &'static str) -> (Method, &'static str) {
    let url = needle
        .split('"')
        .nth(1)
        .unwrap_or_else(|| panic!("harness bug: REST needle must quote its URL: {needle}"));
    let path = url.strip_prefix("http://$API").unwrap_or_else(|| {
        panic!("harness bug: REST needle URL must start with http://$API: {needle}")
    });
    let method = match needle.find("-X ") {
        Some(at) => {
            let word = needle[at + 3..]
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("harness bug: a method word must follow `-X`: {needle}"));
            Method::from_bytes(word.as_bytes()).unwrap_or_else(|_| {
                panic!("harness bug: documented `-X` method must be valid HTTP: {needle}")
            })
        }
        None => Method::GET,
    };
    (method, path)
}

/// Locate `fact` and derive the CLI argv its needle prescribes. The
/// locate runs first, so a doc that swapped the command for a
/// nonexistent one fails the step by name before anything executes.
fn located_cli_argv(onboard: &str, skill: &str, fact: &str) -> Result<Vec<&'static str>, String> {
    let entry = fact_named(fact);
    locate(onboard, skill, fact)?;
    Ok(needle_argv(entry.needle))
}

/// Locate `fact` and derive the REST method and path its needle
/// prescribes. Same rule: the complete curl-line needle (method
/// included) must be present first, so a doc that changed the
/// documented method fails the step by name.
fn located_rest(onboard: &str, skill: &str, fact: &str) -> Result<(Method, &'static str), String> {
    let entry = fact_named(fact);
    locate(onboard, skill, fact)?;
    Ok(needle_rest(entry.needle))
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

/// Result of one CLI call: exit status folded to a bool, the combined
/// stdout and stderr (error paths print the typed code on stderr), and
/// the child's OS pid so tests can prove the deadline discipline.
pub struct CliOutcome {
    pub exit_ok: bool,
    pub output: String,
    pub pid: Option<u32>,
}

/// Run the `x0x` CLI against the fresh agent's own daemon, composing the
/// skill's documented targeting form for a non-default daemon (`--api
/// <addr>` plus `X0X_API_TOKEN` in the environment, §1.2) into EVERY call.
/// The recipe's bare commands assume default-instance discovery; this
/// daemon is not the default instance, and one call that omitted the form
/// reached the machine's default daemon and was refused 401 with this
/// daemon's token. When the deadline passes, the child is killed AND
/// reaped (a kill alone would leave a zombie holding the pid), so no
/// process outlives its budget to overlap later steps or retries. A
/// timeout or a non-zero exit is an outcome, not a panic; only a spawn
/// failure (missing binary) is a harness fault.
pub async fn run_cli(ctx: &DocContext, args: &[&str], timeout: Duration) -> CliOutcome {
    let mut cmd = tokio::process::Command::new(&ctx.cli_bin);
    cmd.arg("--api")
        .arg(&ctx.my_api_addr)
        .args(args)
        .env("X0X_API_TOKEN", &ctx.my_api_token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Backstop for panic paths; the timeout branch below kills and
        // reaps explicitly.
        .kill_on_drop(true);
    let printed = format!("x0x --api <addr> {}", args.join(" "));
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => panic!(
            "harness fault: cannot run {} ({error})",
            ctx.cli_bin.display()
        ),
    };
    let pid = child.id();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    // Drain both pipes while waiting, so a chatty child cannot block on a
    // full pipe, and keep the Child handle so a timeout can still reach it.
    let collected = async {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        // join! yields in argument order: stdout read, stderr read, exit
        // status. The read results drop; a failed read leaves the partial
        // buffer, which is all the detail line needs.
        let (_, _, status) = tokio::join!(
            async {
                match stdout_pipe.as_mut() {
                    Some(pipe) => pipe.read_to_end(&mut stdout).await,
                    None => Ok(0),
                }
            },
            async {
                match stderr_pipe.as_mut() {
                    Some(pipe) => pipe.read_to_end(&mut stderr).await,
                    None => Ok(0),
                }
            },
            child.wait(),
        );
        (status, stdout, stderr)
    };
    match tokio::time::timeout(timeout, collected).await {
        Ok((Ok(status), stdout, stderr)) => {
            let mut output = String::from_utf8_lossy(&stdout).into_owned();
            output.push('\n');
            output.push_str(&String::from_utf8_lossy(&stderr));
            CliOutcome {
                exit_ok: status.success(),
                output,
                pid,
            }
        }
        Ok((Err(error), ..)) => panic!("harness fault: waiting for `{printed}` failed ({error})"),
        Err(_) => {
            // The deadline passed: kill, then reap. Nothing of the child
            // outlives this call.
            let _ = child.start_kill();
            let reaped = child.wait().await;
            CliOutcome {
                exit_ok: false,
                output: format!(
                    "timed out after {timeout:?} running `{printed}`; killed and reaped the \
                     child (pid {pid:?}, wait status {reaped:?})"
                ),
                pid,
            }
        }
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
/// `X0X_API_TOKEN`), then the doc-derived health command must exit 0
/// with the documented `ok: true` signal.
async fn step_health(ctx: &DocContext) -> StepResult {
    const STEP: &str = "health";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let argv = match located_cli_argv(&ctx.onboard_text, &ctx.skill_text, FACT_HEALTH_CMD) {
        Ok(argv) => argv,
        Err(gap) => return fail(STEP, gap),
    };
    let out = run_cli(ctx, &argv, HEALTH_CALL_TIMEOUT).await;
    if out.exit_ok && out.output.contains(OK_SIGNAL) {
        pass(
            STEP,
            format!(
                "`x0x --api <addr> {}` with X0X_API_TOKEN in the environment exited 0 and \
                 printed the documented `{OK_SIGNAL}` signal",
                argv.join(" ")
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

/// Step `identity`: run the doc-derived identity command, parse the own
/// 64-hex agent_id (needed by `join-group`). Returns the parsed id on
/// success.
async fn step_identity(ctx: &DocContext) -> (StepResult, Option<String>) {
    const STEP: &str = "identity";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return (fail(STEP, gap), None);
    }
    let argv = match located_cli_argv(&ctx.onboard_text, &ctx.skill_text, FACT_IDENTITY_CMD) {
        Ok(argv) => argv,
        Err(gap) => return (fail(STEP, gap), None),
    };
    let out = run_cli(ctx, &argv, CLI_CALL_TIMEOUT).await;
    let parsed = hex64_after(&out.output, "agent_id").map(String::from);
    if out.exit_ok && parsed.is_some() {
        let detail = format!(
            "parsed own agent_id {} (64-hex) from `x0x {}` output",
            // The guard above makes the empty default unreachable.
            parsed.as_deref().unwrap_or_default(),
            argv.join(" ")
        );
        return (pass(STEP, detail), parsed);
    }
    (
        fail(
            STEP,
            format!(
                "could not parse a 64-hex agent_id from `x0x {}` output (exit ok: {}); \
                 SKILL.md documents that the command prints the agent_id but not the output \
                 format; output: {}",
                argv.join(" "),
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
        // The subcommand words come from the located form; the card
        // contents and the (separately located) `--trust known` flag are
        // the operands.
        let mut argv: Vec<&str> = needle_argv(form).into_iter().collect();
        argv.push(card);
        argv.extend(["--trust", "known"]);
        let out = run_cli(ctx, &argv, CLI_CALL_TIMEOUT).await;
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
        // The lookup recipe states the find command itself; the retry note
        // (checked after it) only extends the attempt budget.
        if !onboard.contains(IMPORT_FIND_FORM) {
            return fail(
                STEP,
                "requires information not present in the onboard output or core skill: the \
                 lookup form's `x0x agents find` command"
                    .to_string(),
            );
        }
        let find_argv = needle_argv(IMPORT_FIND_FORM);
        let retries = if require(
            onboard,
            IMPORT_FIND_NOTE,
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
            let mut argv: Vec<&str> = find_argv.clone();
            argv.push(inviter.as_str());
            let out = run_cli(ctx, &argv, FIND_CALL_TIMEOUT).await;
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
        let mut contacts_argv: Vec<&str> = needle_argv(IMPORT_LOOKUP_FORM).into_iter().collect();
        contacts_argv.push(inviter.as_str());
        contacts_argv.extend(["--trust", "known", "--label", "inviter"]);
        let out = run_cli(ctx, &contacts_argv, CLI_CALL_TIMEOUT).await;
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

/// Step `send-dm`: the doc-derived `x0x direct send` form with the
/// inviter id and the fixed payload as operands. Documented remediation
/// only: patience for the 409 (fixed retries in the fixed budget), then
/// the `--no-durable-ack` fallback, and for the 404 the recipe's remedy
/// (card import) is already `import-inviter-card`, so a 404 that never
/// clears fails by name. Required success signal: exit 0 plus `ok: true`
/// in the output.
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
    let send_argv: Vec<&str> =
        match located_cli_argv(&ctx.onboard_text, &ctx.skill_text, FACT_DIRECT_SEND_CMD) {
            Ok(argv) => {
                let mut argv: Vec<&str> = argv.into_iter().collect();
                argv.push(inviter.as_str());
                argv.push(DM_PAYLOAD);
                argv
            }
            Err(gap) => return fail(STEP, gap),
        };
    let mut attempts = 0u32;
    let mut last = String::new();
    let deadline = tokio::time::Instant::now() + DM_TOTAL_BUDGET;
    while attempts < DM_RETRY_MAX {
        attempts += 1;
        let out = run_cli(ctx, &send_argv, DM_SEND_CALL_TIMEOUT).await;
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
                let mut argv: Vec<&str> = send_argv.clone();
                argv.push("--no-durable-ack");
                let out = run_cli(ctx, &argv, DM_SEND_CALL_TIMEOUT).await;
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

/// Step `join-group`: the doc-derived join call (`POST /groups/join`
/// today — method and path both come from the located curl line) with
/// the invite body, then the doc-derived members call (GET
/// `/groups/<gid>/members` with `<gid>` substituted) until this agent's
/// entry is `active`.
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
    let (join_method, join_path) =
        match located_rest(&ctx.onboard_text, &ctx.skill_text, FACT_JOIN_ENDPOINT) {
            Ok(rest) => rest,
            Err(gap) => return fail(STEP, gap),
        };
    let join = rest(
        ctx,
        join_method.clone(),
        join_path,
        Some(json!({ "invite": ctx.inviter_group.invite })),
    )
    .await;
    if !join.ok {
        return fail(
            STEP,
            format!(
                "`{} {join_path}` returned HTTP {} (body: {})",
                join_method,
                join.status,
                excerpt(&join.body)
            ),
        );
    }
    let (members_method, members_path_doc) =
        match located_rest(&ctx.onboard_text, &ctx.skill_text, FACT_MEMBERS_ENDPOINT) {
            Ok(rest) => rest,
            Err(gap) => return fail(STEP, gap),
        };
    let members_path = members_path_doc.replace("<gid>", &ctx.inviter_group.group_id);
    let deadline = tokio::time::Instant::now() + MEMBERS_POLL_BUDGET;
    let mut last_observed = String::from("no members entry for this agent yet");
    loop {
        let members = rest(ctx, members_method.clone(), &members_path, None).await;
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
                        "`{} {join_path}` returned HTTP {}; `{} {members_path}` then listed \
                             this agent ({my_id}) with the documented `{MEMBER_STATE_ACTIVE}` \
                             state",
                        join_method, join.status, members_method
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
            "joined (`{} {join_path}` returned HTTP {}) but the member list never showed \
             this agent with the documented `{MEMBER_STATE_ACTIVE}` state within the ~60 s \
             poll budget (last observed: {last_observed})",
            join_method, join.status
        ),
    )
}

/// Step `scratch-write`: create the store via the doc-derived CLI
/// command, PUT the fixed value via the doc-derived path and method,
/// then GET the readback and decode it. Success = the readback decodes
/// to exactly [`SCRATCH_VALUE`].
async fn step_scratch_write(ctx: &DocContext) -> StepResult {
    const STEP: &str = "scratch-write";
    if let Err(gap) = require_step_facts(&ctx.onboard_text, &ctx.skill_text, STEP) {
        return fail(STEP, gap);
    }
    let create_argv =
        match located_cli_argv(&ctx.onboard_text, &ctx.skill_text, FACT_STORE_CREATE_CMD) {
            Ok(argv) => argv,
            Err(gap) => return fail(STEP, gap),
        };
    let create = run_cli(ctx, &create_argv, CLI_CALL_TIMEOUT).await;
    if !create.exit_ok {
        return fail(
            STEP,
            format!(
                "`x0x {}` failed; output: {}",
                create_argv.join(" "),
                excerpt(&create.output)
            ),
        );
    }
    // Standard alphabet, unwrapped: SKILL.md warns GNU/BSD base64 wrap
    // long lines (`tr -d '\n'`); a wrapped value breaks the JSON body.
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(SCRATCH_VALUE.as_bytes());
    let (put_method, put_path) =
        match located_rest(&ctx.onboard_text, &ctx.skill_text, FACT_STORE_PUT_ENDPOINT) {
            Ok(rest) => rest,
            Err(gap) => return fail(STEP, gap),
        };
    let put = rest(
        ctx,
        put_method.clone(),
        put_path,
        Some(json!({ "value": value_b64, "content_type": "text/plain" })),
    )
    .await;
    if !put.ok {
        return fail(
            STEP,
            format!(
                "`{} {put_path}` returned HTTP {} (body: {})",
                put_method,
                put.status,
                excerpt(&put.body)
            ),
        );
    }
    let (get_method, get_path) = match located_rest(
        &ctx.onboard_text,
        &ctx.skill_text,
        FACT_STORE_READBACK_ENDPOINT,
    ) {
        Ok(rest) => rest,
        Err(gap) => return fail(STEP, gap),
    };
    let get = rest(ctx, get_method.clone(), get_path, None).await;
    if !get.ok {
        return fail(
            STEP,
            format!(
                "`{} {get_path}` readback returned HTTP {} (body: {})",
                get_method,
                get.status,
                excerpt(&get.body)
            ),
        );
    }
    match readback_bytes(&get.body) {
        Some(bytes) if bytes == SCRATCH_VALUE.as_bytes() => pass(
            STEP,
            format!(
                "store created via CLI (exit 0); `{} {put_path}` returned HTTP {}; `{} \
                 {get_path}` readback decoded to exactly the scratch value ({SCRATCH_VALUE:?})",
                put_method, put.status, get_method
            ),
        ),
        Some(other) => fail(
            STEP,
            format!(
                "readback decoded to {:?}, expected {SCRATCH_VALUE:?}",
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
