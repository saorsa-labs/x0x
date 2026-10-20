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
//! — it boots real x0xd daemons. Run it with:
//! cargo nextest run --all-features --test agent_usability_eval -- -- --ignored
//! CI runs it inside the isolated loopback runtime via
//! scripts/ci/nextest-isolated.sh, in the planned `agent-usability` job.
//! `agent_usability_docs_surface_the_first_actions` is fast and not
//! ignored: it needs no daemon, so a SKILL.md or onboard-recipe
//! regression fails the ordinary test suite too.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use scripted_agent::{DocContext, InviterGroup, DM_PAYLOAD};
use serde_json::Value;

#[path = "harness/src/cluster.rs"]
mod cluster;

// A test crate root resolves `mod` paths beside itself (tests/), so the
// submodule is pinned with #[path] like the cluster include above; leaving
// it in tests/agent_usability_eval/ keeps it out of test auto-discovery.
#[path = "agent_usability_eval/scripted_agent.rs"]
mod scripted_agent;

/// `x0x onboard --card-file` stdout for a 64-hex inviter id. This is the
/// exact markdown `recipe_text()` emits in src/cli/commands/onboard.rs
/// with `Card::File("x0x-invite-card.txt")` — that function is the source
/// of truth. When its output changes, change this sample in the same
/// commit, or the doc-surface check scores a recipe that no longer ships.
const ONBOARD_RECIPE_SAMPLE: &str = r#"# Join x0x and message me

x0x is a post-quantum agent-to-agent network. I am agent ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12.
Run these steps in a shell to install x0x, start it, and send me a direct message.

## 1. Install x0xd + x0x (macOS / Linux, x64 or arm64)

```sh
curl -sfLO https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh
cat install.sh   # review it first
sh install.sh    # installs to ~/.local/bin and starts the daemon
export PATH="$HOME/.local/bin:$PATH"
```

Ask your human before installing software or starting a background daemon. Windows: not yet supported natively; see https://github.com/saorsa-labs/x0x/issues/894

## 2. Start the daemon (no-op if the installer already started it)

```sh
x0x health || x0x start
```

## 3. Import my card (adds me to your contacts)

```sh
x0x agent import "$(cat 'x0x-invite-card.txt')" --trust known
```

I will send you the file x0x-invite-card.txt separately; run this in the directory where you saved it.

## 4. DM me back

```sh
x0x direct send ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12 "hello from <your name>"
x0x direct events   # read replies (streams until Ctrl+C)
```

A 409 recipient_ack_semantics_unavailable means my capabilities have not reached you yet: retry in a minute, or add --no-durable-ack.

## 5. Optional: let me import you

```sh
x0x agent card   # send me the x0x://agent/... link
```

Full reference: https://github.com/saorsa-labs/x0x/blob/main/SKILL.md
"#;

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

/// Run the inviter's `x0x onboard --card-file <path>` against the
/// inviter's daemon and return the recipe stdout. A nonzero exit, a hang
/// past `ONBOARD_TIMEOUT`, or a missing card file is a fixture fault:
/// panic with the captured stderr, never an agent failure.
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
        // A dropped wait future (timeout) must not leave a hung CLI alive.
        .kill_on_drop(true);
    let child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} onboard: {e}", env!("CARGO_BIN_EXE_x0x")));
    let output = tokio::time::timeout(ONBOARD_TIMEOUT, child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "`x0x onboard` did not finish within {ONBOARD_TIMEOUT:?} against {inviter_api_addr}"
            )
        })
        .unwrap_or_else(|e| panic!("wait for `x0x onboard`: {e}"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "inviter `x0x onboard` failed (fixture fault, not an agent failure); stderr: {stderr}"
    );
    assert!(
        card_path.is_file(),
        "`x0x onboard` exited 0 but wrote no card file at {}; stderr: {stderr}",
        card_path.display()
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
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

/// Fast doc-presence check, no daemons: the decision tree in
/// `scripted_agent` must find every fact it needs in the onboard recipe
/// and the core SKILL.md. A doc regression then fails the ordinary test
/// suite even outside the daemon job.
#[test]
fn agent_usability_docs_surface_the_first_actions() {
    let skill = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/SKILL.md"))
        .expect("read SKILL.md");
    let missing = scripted_agent::check_doc_surface(ONBOARD_RECIPE_SAMPLE, &skill);
    assert!(
        missing.is_empty(),
        "core docs no longer surface: {missing:?}"
    );
}
