//! Agent-usability eval for issue #1174.
//!
//! This eval proves that a fresh agent, given ONLY the stdout of
//! `x0x onboard` (run by an inviter) plus the core SKILL.md, can do the
//! three first actions: (1) send a first DM to the inviter, (2) join a
//! group, (3) write a scratch KV entry. The agent under test is the
//! deterministic `scripted_agent` module
//! (tests/agent_usability_eval/scripted_agent.rs, no LLM): it may act
//! only on facts present in those two documents, so a missing doc fact
//! fails the eval instead of being papered over by prior knowledge.
//!
//! `agent_usability_first_actions_from_onboard_and_skill` is `#[ignore]`
//! — it boots real x0xd daemons. CI runs it inside the isolated loopback
//! runtime via scripts/ci/nextest-isolated.sh, in the `agent-usability`
//! job; run it locally with the same isolation, because plain
//! `cargo nextest run` bypasses what daemon tests require:
//! python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'test(agent_usability)'
//! The fast half needs no daemon and runs in the ordinary suite: the
//! doc-surface check renders the REAL `x0x onboard` recipe through a
//! loopback stub, the negative controls prove that mutated docs fail by
//! name, and the timeout proof pins `run_cli`'s kill-and-reap duty.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use scripted_agent::{DocContext, InviterGroup, DM_PAYLOAD};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[path = "harness/src/cluster.rs"]
mod cluster;

// A test crate root resolves `mod` paths beside itself (tests/), so the
// submodule is pinned with #[path] like the cluster include above; leaving
// it in tests/agent_usability_eval/ keeps it out of test auto-discovery.
#[path = "agent_usability_eval/scripted_agent.rs"]
mod scripted_agent;

/// The #1174 eval: a fresh agent completes the three first actions from
/// the onboard output and the core skill alone, and the inviter's daemon
/// holds durable proof that the actions landed.
#[tokio::test]
#[ignore]
async fn agent_usability_first_actions_from_onboard_and_skill() {
    // alice is the inviter; bob is the fresh agent. `pair()` is hermetic:
    // private gossip plane, mDNS off, `--no-hard-coded-bootstrap`, loopback
    // bootstrap, `[update]` disabled. The eval is loopback-only.
    let pair = cluster::pair().await;

    // The inviter's card file travels out-of-band (#894); a temp dir keeps
    // it out of the repository.
    let card_dir = tempfile::tempdir().expect("create temp dir for onboard card");
    let card_path = card_dir.path().join("x0x-invite-card.txt");

    // Inviter-side onboard with the real CLI against alice's daemon.
    let onboard_text = run_inviter_onboard(&pair.alice, &card_path).await;

    // The handed-over card file: the `x0x://agent/...` link.
    let inviter_card = std::fs::read_to_string(&card_path)
        .unwrap_or_else(|e| panic!("read onboard card {}: {e}", card_path.display()));

    // SKILL.md IS the core skill post-#1173 split. Read it verbatim so the
    // eval scores the shipped bytes, not a copy.
    let skill_text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/SKILL.md"))
        .expect("read SKILL.md");

    // Inviter-side group setup. These are EXACTLY the creator calls the
    // core SKILL.md documents under "Join a group": `POST /groups
    // {"name": ...}`, `POST /groups/<gid>/invite` with an empty JSON body,
    // and member polling via `GET /groups/<gid>/members`. No preset is
    // passed; the daemon default applies, because that is the call the
    // skill documents.
    let create = fixture_json(
        pair.alice
            .post("/groups", serde_json::json!({ "name": "usability-eval" }))
            .await,
        reqwest::StatusCode::CREATED,
        "group create",
    )
    .await;
    let group_id = create["group_id"].as_str().unwrap_or_default().to_string();
    if group_id.is_empty() {
        panic!("group create response has no group_id: {create}");
    }

    let invite = fixture_json(
        pair.alice
            .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
            .await,
        reqwest::StatusCode::OK,
        "group invite",
    )
    .await;
    let invite_link = invite["invite_link"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if !invite_link.starts_with("x0x://invite/") {
        panic!("invite response has no x0x://invite/ link: {invite}");
    }

    // The group id and the invite reach the fresh agent the way a real
    // inviter sends them: in the same message. The invite alone is
    // opaque — a joiner cannot read the group id out of it — so both
    // travel together (see `InviterGroup`).
    //
    // Warm the durable-DM path the way the harness is allowed to
    // (harness-side knowledge, not agent knowledge): wait for a peer
    // capability advert to converge on bob. The scripted agent's DM step
    // STILL keeps its own generous retry budget: per the
    // `wait_for_durable_capability` doc comment
    // (tests/harness/src/cluster.rs), the first durable send to a peer
    // can take ~17.5 s after this returns.
    pair.bob
        .wait_for_durable_capability(Duration::from_secs(90))
        .await;

    let ctx = DocContext {
        onboard_text,
        skill_text,
        inviter_card,
        my_api_addr: pair.bob.api_addr.clone(),
        my_api_token: pair.bob.api_token.clone(),
        cli_bin: PathBuf::from(env!("CARGO_BIN_EXE_x0x")),
        inviter_group: InviterGroup {
            group_id: group_id.clone(),
            invite: invite_link,
        },
    };
    let score = scripted_agent::run(ctx).await;
    eprintln!("{}", score.render());
    assert!(
        score.all_passed(),
        "agent-usability eval failed (a step required information or behaviour not present in the onboard output or core skill):\n{}",
        score.render()
    );

    // Root-side delivery evidence. The scorecard says the agent acted;
    // these assertions prove the actions landed, so a Pass verdict cannot
    // be CLI theatre. Propagation is eventual, so poll with deadlines.
    let bob_agent_id = pair.bob.agent_id().await;

    // (a) alice received the DM: her durable history for the `dm:<bob>`
    // scope holds an inbound row with a non-empty payload.
    let dm_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let dm_payload = loop {
        if let Some(payload) = inbound_dm_payload(&pair.alice, &bob_agent_id).await {
            break payload;
        }
        assert!(
            tokio::time::Instant::now() < dm_deadline,
            "the scripted agent's DM never reached alice's durable history \
             (dm:{bob_agent_id}) within 60s — the Pass verdict did not match reality"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    // The payload is the scripted agent's fixed pub const, so only the
    // agent under test can have produced this row.
    assert_eq!(
        dm_payload, DM_PAYLOAD,
        "alice's inbound DM payload differs from the scripted agent's fixed payload — \
         the Pass verdict did not match reality"
    );
    eprintln!("[agent-usability] alice received the scripted DM payload verbatim");

    // (b) the group roster lists bob as an active member — the state the
    // core skill tells a joiner to poll `GET /groups/<gid>/members` for.
    let member_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(state) = member_state(&pair.alice, &group_id, &bob_agent_id).await {
            if state == "active" {
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < member_deadline,
            "bob ({bob_agent_id}) never became an active member of {group_id} within 60s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Drain an exited child's output pipe into `bytes`. This is called only
/// after `wait()` returned, so the pipe sits at EOF and the read cannot
/// block.
async fn read_child_pipe(pipe: &mut Option<impl AsyncRead + Unpin>, bytes: &mut Vec<u8>) {
    if let Some(pipe) = pipe.as_mut() {
        pipe.read_to_end(bytes)
            .await
            .unwrap_or_else(|e| panic!("read the CLI child's output pipe: {e}"));
    }
}

/// Run the inviter's `x0x onboard --card-file <path>` against the
/// inviter's daemon and return the recipe stdout. A nonzero exit, a hang
/// past `ONBOARD_TIMEOUT`, or a missing card file is a fixture fault:
/// panic with the captured stderr, never an agent failure. The hang path
/// kills AND reaps the CLI child before panicking, so the test process
/// leaves no killed-but-unreaped child behind.
async fn run_inviter_onboard(inviter: &cluster::AgentInstance, card_path: &Path) -> String {
    const ONBOARD_TIMEOUT: Duration = Duration::from_secs(60);
    // Format strings capture identifiers only; hoist the field access.
    let inviter_api_addr = &inviter.api_addr;
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_x0x"));
    command
        .arg("--api")
        .arg(inviter_api_addr)
        .arg("onboard")
        .arg("--card-file")
        .arg(card_path)
        .env("X0X_API_TOKEN", &inviter.api_token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Belt and braces for a panic that drops the handle mid-wait; the
        // timeout branch below kills AND reaps explicitly.
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} onboard: {e}", env!("CARGO_BIN_EXE_x0x")));
    // The pipes come out of the child before waiting, so `wait()` keeps
    // borrowing the handle and the timeout branch can still kill and reap
    // through it. Both outputs are far below pipe capacity, so the child
    // cannot block on a full pipe while it is waited on.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    // The awaited result is bound before the match, so the `child.wait()`
    // borrow inside the timeout future is over once an arm runs.
    let outcome = tokio::time::timeout(ONBOARD_TIMEOUT, child.wait()).await;
    let status = match outcome {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => panic!("wait for `x0x onboard`: {e}"),
        Err(_) => {
            child
                .kill()
                .await
                .unwrap_or_else(|e| panic!("kill the hung `x0x onboard`: {e}"));
            let reaped = child
                .wait()
                .await
                .unwrap_or_else(|e| panic!("reap the killed `x0x onboard`: {e}"));
            panic!(
                "`x0x onboard` did not finish within {ONBOARD_TIMEOUT:?} against \
                 {inviter_api_addr} (killed and reaped, exit: {reaped})"
            );
        }
    };
    // The child has exited, so both pipes sit at EOF and drain at once.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    read_child_pipe(&mut stdout_pipe, &mut stdout).await;
    read_child_pipe(&mut stderr_pipe, &mut stderr).await;
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        status.success(),
        "inviter `x0x onboard` failed (fixture fault, not an agent failure); stderr: {stderr}"
    );
    assert!(
        card_path.is_file(),
        "`x0x onboard` exited 0 but wrote no card file at {}; stderr: {stderr}",
        card_path.display()
    );
    String::from_utf8_lossy(&stdout).into_owned()
}

/// Consume an inviter-side response or declare a fixture fault. The
/// agent's own steps start only after every fixture call has succeeded,
/// so a fixture failure can never read as an agent failure.
async fn fixture_json(
    resp: reqwest::Response,
    expected_status: reqwest::StatusCode,
    what: &str,
) -> Value {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, expected_status,
        "inviter-side {what} failed (fixture fault, not an agent failure): {body}"
    );
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("inviter-side {what} returned invalid JSON ({e}): {body}"))
}

/// The payload text of the first inbound row in alice's `dm:<sender>`
/// history scope, when one exists. `/history` serves `records` with base64
/// `payload` values; an inbound row in this scope proves delivery, because
/// only a DM from that sender makes alice's daemon commit one.
async fn inbound_dm_payload(alice: &cluster::AgentInstance, sender_hex: &str) -> Option<String> {
    let resp = alice.get(&format!("/history?scope=dm:{sender_hex}")).await;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v["records"].as_array()?.iter().find_map(|record| {
        if record["direction"].as_str() != Some("Inbound") {
            return None;
        }
        let payload = BASE64.decode(record["payload"].as_str()?).ok()?;
        let text = String::from_utf8_lossy(&payload).into_owned();
        (!text.trim().is_empty()).then_some(text)
    })
}

/// The roster state string the inviter's daemon holds for `agent_hex` in
/// `group_id`, when the roster lists it at all. `GET /groups/<gid>/members`
/// serves `members[]` entries with `agent_id` and `state`; `active` is the
/// joined state.
async fn member_state(
    alice: &cluster::AgentInstance,
    group_id: &str,
    agent_hex: &str,
) -> Option<String> {
    let resp = alice.get(&format!("/groups/{group_id}/members")).await;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v["members"].as_array()?.iter().find_map(|member| {
        if member["agent_id"].as_str() == Some(agent_hex) {
            Some(member["state"].as_str().unwrap_or_default().to_string())
        } else {
            None
        }
    })
}

// ── Fast no-daemon half ─────────────────────────────────────────────────────

/// Inviter identity served by the stub API below: a 64-hex agent id and
/// a card link that pass `x0x onboard`'s validation (the id must be 64
/// hex chars; the link must start `x0x://agent/` and carry only
/// alphanumerics or `:` `/` `-` `_`).
const STUB_INVITER_AGENT_ID: &str =
    "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const STUB_INVITER_CARD_LINK: &str = "x0x://agent/eyJhZ2VudF9pZCI6ImFiMTIifQ";

/// Render the onboard recipe through the REAL shipped CLI binary: this is
/// the actual renderer output (`recipe_text()` in
/// src/cli/commands/onboard.rs reached through the shipped binary), so
/// removing instructions from the shipped recipe turns the doc-surface
/// test red instead of scoring a hand-copied sample. A loopback stub
/// serves only the two GETs `x0x onboard` makes, binds `127.0.0.1:0`
/// only, and is inert: no x0xd runs and nothing joins any network. A
/// nonzero exit, a hang past `ONBOARD_TIMEOUT`, or a missing card file
/// is a fixture fault, never an agent failure.
async fn real_onboard_recipe() -> String {
    const ONBOARD_TIMEOUT: Duration = Duration::from_secs(60);
    let card_dir = tempfile::tempdir().expect("create temp dir for onboard card");
    let card_path = card_dir.path().join("x0x-invite-card.txt");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback stub API listener");
    let port = listener
        .local_addr()
        .expect("read the stub listener's local address")
        .port();
    let stub = tokio::spawn(serve_onboard_requests(listener));
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_x0x"));
    command
        .arg("--api")
        .arg(format!("127.0.0.1:{port}"))
        .arg("onboard")
        .arg("--card-file")
        .arg(&card_path)
        .env("X0X_API_TOKEN", "stub-token")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Belt and braces for a panic that drops the handle mid-wait; the
        // timeout branch below kills AND reaps explicitly.
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} onboard: {e}", env!("CARGO_BIN_EXE_x0x")));
    // The pipes come out of the child before waiting, so `wait()` keeps
    // borrowing the handle and the timeout branch can still kill and reap
    // through it.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    // The awaited result is bound before the match, so the `child.wait()`
    // borrow inside the timeout future is over once an arm runs.
    let outcome = tokio::time::timeout(ONBOARD_TIMEOUT, child.wait()).await;
    let status = match outcome {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => panic!("wait for `x0x onboard`: {e}"),
        Err(_) => {
            child
                .kill()
                .await
                .unwrap_or_else(|e| panic!("kill the hung `x0x onboard`: {e}"));
            let reaped = child
                .wait()
                .await
                .unwrap_or_else(|e| panic!("reap the killed `x0x onboard`: {e}"));
            panic!(
                "`x0x onboard` did not finish within {ONBOARD_TIMEOUT:?} against the stub at \
                 127.0.0.1:{port} (killed and reaped, exit: {reaped})"
            );
        }
    };
    // The CLI has exited, so the stub's work is done.
    stub.abort();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    // The child has exited, so both pipes sit at EOF and drain at once.
    read_child_pipe(&mut stdout_pipe, &mut stdout).await;
    read_child_pipe(&mut stderr_pipe, &mut stderr).await;
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        status.success(),
        "`x0x onboard` against the stub failed (fixture fault, not an agent failure); stderr: \
         {stderr}"
    );
    assert!(
        card_path.is_file(),
        "`x0x onboard` exited 0 but wrote no card file at {}; stderr: {stderr}",
        card_path.display()
    );
    String::from_utf8_lossy(&stdout).into_owned()
}

/// Serve the stub API: one connection at a time, forever — the caller
/// aborts this task once the CLI has exited. An accept error ends the
/// task; the CLI then fails its health probe and the test fails as a
/// fixture fault instead of hanging.
async fn serve_onboard_requests(listener: tokio::net::TcpListener) {
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        // A connection that errors mid-request is closed and forgotten;
        // the accept loop keeps serving.
        let _ = serve_one_onboard_request(&mut stream).await;
    }
}

/// Answer exactly one request. The head is read to its `\r\n\r\n`
/// terminator (these requests carry no body) and only the request line is
/// looked at; the response closes the connection.
async fn serve_one_onboard_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&head);
    let path = head.split(' ').nth(1).unwrap_or_default();
    let (status, body) = match path {
        "/health" => ("200 OK", serde_json::json!({ "ok": true }).to_string()),
        "/agent/card" => (
            "200 OK",
            serde_json::json!({
                "card": { "agent_id": STUB_INVITER_AGENT_ID },
                "link": STUB_INVITER_CARD_LINK
            })
            .to_string(),
        ),
        _ => ("404 Not Found", serde_json::json!({}).to_string()),
    };
    let content_length = body.len();
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// The core SKILL.md, verbatim: the fast tests score the shipped bytes,
/// not a copy.
fn core_skill_text() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/SKILL.md"))
        .expect("read SKILL.md")
}

/// Fast doc-presence check, no daemons: the decision tree in
/// `scripted_agent` must find every fact it needs in the REAL recipe the
/// shipped CLI renders plus the core SKILL.md. A doc regression then
/// fails the ordinary test suite even outside the daemon job.
#[tokio::test]
async fn agent_usability_docs_surface_the_first_actions() {
    let recipe = real_onboard_recipe().await;
    let skill = core_skill_text();
    let missing = scripted_agent::check_doc_surface(&recipe, &skill);
    assert!(
        missing.is_empty(),
        "core docs no longer surface: {missing:?}"
    );
}

/// Negative control from the review: changing the documented join method
/// (POST mutated to DELETE on the join line only — the invite line keeps
/// its POST) must surface as a named missing fact, not pass silently.
#[tokio::test]
async fn doc_surface_names_a_changed_join_method() {
    let recipe = real_onboard_recipe().await;
    let skill = core_skill_text();
    let mutated = skill.replacen(
        "-X POST \"http://$API/groups/join\"",
        "-X DELETE \"http://$API/groups/join\"",
        1,
    );
    // A silent no-op mutation would make this control worthless.
    assert_ne!(
        mutated, skill,
        "the join-method mutation did not apply to SKILL.md as shipped"
    );
    let missing = scripted_agent::check_doc_surface(&recipe, &mutated);
    assert!(
        missing
            .iter()
            .any(|gap| gap.contains("the group-join endpoint (`POST /groups/join`)")),
        "a changed join method must surface as the named join-endpoint fact; missing: {missing:?}"
    );
}

/// Negative control from the review: replacing the documented identity
/// command with one that does not exist must surface as a named missing
/// fact, not pass silently.
#[tokio::test]
async fn doc_surface_names_a_nonexistent_identity_command() {
    let recipe = real_onboard_recipe().await;
    let skill = core_skill_text();
    let mutated = skill.replacen(
        "`x0x agent` prints your `agent_id`",
        "`x0x identity-show` prints your `agent_id`",
        1,
    );
    // A silent no-op mutation would make this control worthless.
    assert_ne!(
        mutated, skill,
        "the identity-command mutation did not apply to SKILL.md as shipped"
    );
    let missing = scripted_agent::check_doc_surface(&recipe, &mutated);
    assert!(
        missing
            .iter()
            .any(|gap| gap.contains("`x0x agent` prints the caller's agent_id")),
        "a nonexistent identity command must surface as the named identity fact; missing: \
         {missing:?}"
    );
}

/// Timeout discipline proof from the review: when a CLI call passes its
/// deadline, `run_cli` must kill AND reap the child. The script `exec`s
/// into `sleep 300` (so the child pid IS the sleeper — a plain `sleep`
/// would fork a grandchild that survives the shell's death and the probe
/// below would say nothing about it) and ignores its arguments, so only
/// the deadline can end the call.
#[cfg(unix)]
#[tokio::test]
async fn run_cli_deadline_kills_and_reaps_the_child() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("create temp dir for the hang script");
    let hang = dir.path().join("hang.sh");
    std::fs::write(&hang, "#!/bin/sh\nexec sleep 300\n").expect("write the hang script");
    std::fs::set_permissions(&hang, std::fs::Permissions::from_mode(0o755))
        .expect("make the hang script executable");
    let ctx = DocContext {
        onboard_text: String::new(),
        skill_text: String::new(),
        inviter_card: String::new(),
        my_api_addr: "127.0.0.1:1".into(),
        my_api_token: "unused".into(),
        cli_bin: hang,
        inviter_group: InviterGroup {
            group_id: String::new(),
            invite: String::new(),
        },
    };
    let started = Instant::now();
    let out = scripted_agent::run_cli(&ctx, &["health"], Duration::from_secs(1)).await;
    assert!(
        !out.exit_ok,
        "a hung CLI call must fold its deadline into a failed outcome"
    );
    let Some(pid) = out.pid else {
        panic!("run_cli must report the OS pid of the child it spawned");
    };
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "run_cli must not wait out the 300 s script; elapsed {:?} against a 1 s deadline",
        started.elapsed()
    );
    // `kill -0` succeeds for a live process AND for a killed-but-unreaped
    // zombie, so its failure proves the child was both killed and reaped:
    // a plain drop would leave a live process; kill without reap would
    // leave a zombie.
    let pid_string = pid.to_string();
    let probe = std::process::Command::new("kill")
        .arg("-0")
        .arg(&pid_string)
        .status()
        .expect("run the `kill -0` probe");
    assert!(
        !probe.success(),
        "`kill -0 {pid_string}` still succeeds: the hung child was neither fully killed nor \
         reaped by run_cli's deadline path"
    );
}
