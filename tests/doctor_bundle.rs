//! Redaction proof for `x0x doctor --bundle` (issue #1354 slice 1).
//!
//! Issue done-when: "A bundle has no keys, tokens or message content (a
//! test checks this)." Seeds a real daemon fixture with every secret class
//! — a KV value carrying a unique canary (message content), a live session
//! token, the durable API token, and the machine/agent key files — runs the
//! real `x0x` CLI, and proves none of it appears in the written bundle.
//! Positive controls prove the secrets really were in daemon state first,
//! so the absence is redaction, not a seeding failure. The companion
//! failure-mode test pins the `--json` stdout contract — exactly one
//! doctor report — even when the bundle write itself fails (#1997 review
//! finding 2). `#[ignore]`d like every daemon-backed test: run with
//! `cargo nextest run --test doctor_bundle -- --ignored`.

#[path = "harness/src/daemon.rs"]
mod daemon;

use base64::Engine;
use daemon::DaemonFixture;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Subprocess timeout for one `x0x doctor` run (hang guard only).
const CLI_TIMEOUT: Duration = Duration::from_secs(120);

/// Length of the key-file byte canaries.
const KEY_CANARY_LEN: usize = 48;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Case-sensitive substring search over raw bytes.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A 48-byte slice from the middle of a key file. The bincode layout
/// (`{public_key, secret_key}`) puts this inside the embedded secret-key
/// half for real ML-DSA-65 key files, so it is a private-key canary even
/// if the file prefix is public-half material.
fn mid_key_slice(file: &[u8]) -> &[u8] {
    &file[file.len() / 2..file.len() / 2 + KEY_CANARY_LEN]
}

/// Every secret seeded into the daemon; the bundle must contain none of
/// them in any form.
struct SecretCanaries {
    /// Message-content class: a KV value PUT through the REST API.
    kv_value: String,
    /// Short-lived token minted by POST /auth/session.
    session_token: String,
    /// The fixture's durable API token — valid auth material.
    api_token: String,
    /// Raw bytes of <identity_dir>/machine.key.
    machine_key: Vec<u8>,
    /// Raw bytes of <identity_dir>/agent.key.
    agent_key: Vec<u8>,
}

impl SecretCanaries {
    /// Text needles searched over the bundle bytes: the string canaries
    /// raw (the kv canary also in base64 — the encoding its PUT wire form
    /// carries, so an embedded request body leaks it), plus the key
    /// canaries as lowercase hex and as base64 at all three encoder
    /// phases. Base64 maps 3 bytes to 4 chars, so a raw needle only
    /// surfaces verbatim inside an embedded base64 key blob when its
    /// start offset lands on the encoder's 3-byte grid; one of three
    /// consecutive starts always does, whatever the blob's alignment.
    fn text_needles(&self) -> Vec<(&'static str, String)> {
        let mut needles = vec![
            ("kv canary value (raw)", self.kv_value.clone()),
            ("kv canary value (base64)", b64(self.kv_value.as_bytes())),
            ("session token (raw)", self.session_token.clone()),
            ("api token (raw)", self.api_token.clone()),
            (
                "machine.key secret-half (hex)",
                hex::encode(mid_key_slice(&self.machine_key)),
            ),
            (
                "agent.key secret-half (hex)",
                hex::encode(mid_key_slice(&self.agent_key)),
            ),
        ];
        for (name, file) in [
            ("machine.key", &self.machine_key),
            ("agent.key", &self.agent_key),
        ] {
            for phase in 0..3 {
                let start = file.len() / 2 + phase;
                let label = match (name, phase) {
                    ("machine.key", 0) => "machine.key secret-half (base64, phase 0)",
                    ("machine.key", 1) => "machine.key secret-half (base64, phase 1)",
                    ("machine.key", 2) => "machine.key secret-half (base64, phase 2)",
                    (_, 0) => "agent.key secret-half (base64, phase 0)",
                    (_, 1) => "agent.key secret-half (base64, phase 1)",
                    _ => "agent.key secret-half (base64, phase 2)",
                };
                needles.push((label, b64(&file[start..start + KEY_CANARY_LEN])));
            }
        }
        needles
    }

    /// Byte needles searched over the raw bundle bytes: the key-file
    /// secret-half slices, catching non-UTF8 embeddings a text scan
    /// over the lossy string could miss.
    fn byte_needles(&self) -> Vec<(&'static str, &[u8])> {
        vec![
            ("machine.key secret-half", mid_key_slice(&self.machine_key)),
            ("agent.key secret-half", mid_key_slice(&self.agent_key)),
        ]
    }
}

/// Create a signed KV store and write a message-content canary value into
/// it (src/server/routes/stores.rs: `POST /stores` `{"name","topic"}`,
/// `PUT /stores/:id/:key` `{"value": <base64>, "content_type"}` — the
/// route base64-decodes `value`). Positive control: the canary
/// round-trips through GET, so it is really in daemon state.
async fn seed_kv_canary(d: &DaemonFixture, canary: &str) {
    let client = d.authed_client(Duration::from_secs(10));
    let topic = format!("doctor-bundle-{}", rand::random::<u32>());

    let created = client
        .post(d.url("/stores"))
        .json(&json!({ "name": "doctor-bundle-redaction", "topic": topic }))
        .send()
        .await
        .expect("POST /stores request");
    assert!(
        created.status().is_success(),
        "create signed store: HTTP {} — {:?}",
        created.status(),
        created.text().await
    );

    let key = "canary";
    let put = client
        .put(d.url(&format!("/stores/{topic}/{key}")))
        .json(&json!({ "value": b64(canary.as_bytes()), "content_type": "text/plain" }))
        .send()
        .await
        .expect("PUT /stores/:id/:key request");
    assert!(
        put.status().is_success(),
        "owner PUT of the canary value: HTTP {} — {:?}",
        put.status(),
        put.text().await
    );

    let fetched: Value = client
        .get(d.url(&format!("/stores/{topic}/{key}")))
        .send()
        .await
        .expect("GET /stores/:id/:key request")
        .json()
        .await
        .expect("GET /stores/:id/:key body json");
    let stored = base64::engine::general_purpose::STANDARD
        .decode(fetched["value"].as_str().expect("value field (base64)"))
        .expect("stored value base64");
    assert_eq!(
        stored,
        canary.as_bytes(),
        "kv canary must be in daemon state before doctor runs"
    );
}

/// Read a fixture identity file; the fixture's start-up wait covers the
/// initial write, so one bounded retry covers a slow disk flush.
async fn read_identity_file(dir: &Path, file: &str) -> Vec<u8> {
    let path = dir.join(file);
    for _ in 0..10 {
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() >= KEY_CANARY_LEN * 2 {
                return bytes;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "fixture identity file {} missing or shorter than {} bytes",
        path.display(),
        KEY_CANARY_LEN * 2
    );
}

/// Run the real `x0x` CLI binary (CARGO_BIN_EXE_x0x) as a subprocess
/// against the fixture daemon. The token rides the child environment only
/// (X0X_API_TOKEN), so no in-process env races with other tests.
///
/// Panics when the run exits non-zero; [`run_x0x_allow_failure`] is the
/// variant for runs whose failure is the point.
async fn run_x0x(
    api_addr: &str,
    token: &str,
    args: &[&str],
    cwd: Option<&Path>,
) -> std::process::ExitStatus {
    let output = run_x0x_allow_failure(api_addr, token, args, cwd).await;
    let code = output.status;
    if !code.success() {
        panic!(
            "`x0x doctor {}` exited {code:?}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    code
}

/// [`run_x0x`] without the success assert: returns the captured output
/// untouched, so a test can pin what a failing run printed on each stream.
async fn run_x0x_allow_failure(
    api_addr: &str,
    token: &str,
    args: &[&str],
    cwd: Option<&Path>,
) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_x0x"));
    command
        .arg("--api")
        .arg(api_addr)
        .args(args)
        .env("X0X_API_TOKEN", token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {} doctor: {e}", env!("CARGO_BIN_EXE_x0x")));
    tokio::time::timeout(CLI_TIMEOUT, child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "`x0x --api {api_addr} doctor {}` hung past {CLI_TIMEOUT:?}",
                args.join(" ")
            )
        })
        .expect("wait for `x0x doctor`")
}

/// Contract shape of the bundle: pretty JSON with the pinned envelope,
/// the redacted /health body and the four doctor checks. The presence
/// assertions keep the absence scan non-vacuous — they prove the bundle
/// really diagnosed this fixture daemon.
fn assert_bundle_shape(label: &str, bytes: &[u8]) {
    let bundle: Value = serde_json::from_slice(bytes)
        .unwrap_or_else(|e| panic!("{label}: bundle must parse as JSON: {e}"));
    assert_eq!(bundle["schema"], "x0x-doctor-bundle", "{label}: schema");
    assert_eq!(bundle["version"], 1, "{label}: version");
    assert!(
        bundle["created_unix"].as_u64().unwrap_or(0) > 0,
        "{label}: created_unix must be a positive unix timestamp"
    );
    assert_eq!(bundle["generator"]["name"], "x0x", "{label}: generator");
    // Pretty JSON: serde_json's compact form has no raw newline bytes.
    assert!(
        contains_subslice(bytes, b"\n"),
        "{label}: bundle must be pretty-printed JSON"
    );
    assert!(
        !bundle["health"]["status"].is_null(),
        "{label}: health.status must be present"
    );
    let doctor = &bundle["doctor"];
    assert!(
        doctor["ok"].is_boolean(),
        "{label}: doctor.ok must be a bool"
    );
    for check in ["connectivity", "key_health", "store_integrity", "upgrade"] {
        assert!(
            doctor[check]["status"].is_string(),
            "{label}: doctor.{check}.status must be a string — got {}",
            doctor[check]
        );
    }
    // The public hex agent id is not secret; the raw key bytes are, and
    // those are checked in assert_no_secrets.
    let agent_id = doctor["key_health"]["evidence"]["agent_id"]
        .as_str()
        .unwrap_or("");
    assert!(
        !agent_id.is_empty(),
        "{label}: doctor.key_health.evidence.agent_id must be non-empty"
    );
}

/// The core of the done-when: NONE of the seeded secrets may appear in
/// the bundle bytes, in any of their encodings.
fn assert_no_secrets(label: &str, bytes: &[u8], secrets: &SecretCanaries) {
    let text = String::from_utf8_lossy(bytes);
    for (what, needle) in secrets.text_needles() {
        assert!(
            !text.contains(&needle),
            "{label}: bundle contains the {what} — redaction is broken"
        );
    }
    for (what, needle) in secrets.byte_needles() {
        assert!(
            !contains_subslice(bytes, needle),
            "{label}: bundle contains raw bytes of the {what} — redaction is broken"
        );
    }
}

/// Seed a real daemon with secret material, then prove none of it appears
/// in the bundle file(s) written by `x0x doctor --bundle`.
#[tokio::test]
#[ignore]
async fn doctor_bundle_contains_no_keys_tokens_or_message_content() {
    let d = DaemonFixture::start("doctor-bundle").await;

    // ── Seed every secret class into the daemon ─────────────────────────
    let kv_canary = format!("x0x-doctor-bundle-canary-kv-{:016x}", rand::random::<u64>());
    seed_kv_canary(&d, &kv_canary).await;

    // Session token (the fixture helper panics if the exchange fails —
    // its own positive control).
    let session_token = d.session_token().await;
    assert!(!session_token.is_empty(), "session token canary");

    let api_token = d.api_token().to_string();
    assert!(!api_token.is_empty(), "api token canary");

    let identity_dir = d.data_dir().join("identity");
    let secrets = SecretCanaries {
        kv_value: kv_canary,
        session_token,
        api_token,
        machine_key: read_identity_file(&identity_dir, "machine.key").await,
        agent_key: read_identity_file(&identity_dir, "agent.key").await,
    };

    // ── `doctor --bundle <path>` with an explicit path ──────────────────
    let out_dir = tempfile::TempDir::new().expect("temp dir for explicit-path bundle");
    let bundle_path = out_dir.path().join("doctor-bundle.json");
    run_x0x(
        d.api_addr(),
        &secrets.api_token,
        &[
            "doctor",
            "--bundle",
            bundle_path.to_str().expect("utf-8 bundle path"),
        ],
        None,
    )
    .await;
    let bundle_bytes = std::fs::read(&bundle_path)
        .unwrap_or_else(|e| panic!("read bundle {}: {e}", bundle_path.display()));
    assert_bundle_shape("doctor --bundle <path>", &bundle_bytes);
    assert_no_secrets("doctor --bundle <path>", &bundle_bytes, &secrets);

    // ── bare `doctor --bundle`: timestamped file in the current dir ─────
    let cwd = tempfile::TempDir::new().expect("temp dir for bare --bundle run");
    run_x0x(
        d.api_addr(),
        &secrets.api_token,
        &["doctor", "--bundle"],
        Some(cwd.path()),
    )
    .await;
    let found: Vec<PathBuf> = std::fs::read_dir(cwd.path())
        .expect("read bare-run temp current dir")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("x0x-doctor-bundle-") && name.ends_with(".json")
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "bare `--bundle` must write exactly one x0x-doctor-bundle-*.json in the \
         current dir, found: {found:?}"
    );
    let bare_bytes = std::fs::read(&found[0])
        .unwrap_or_else(|e| panic!("read bare bundle {}: {e}", found[0].display()));
    assert_bundle_shape("bare --bundle", &bare_bytes);
    assert_no_secrets("bare --bundle", &bare_bytes, &secrets);
}

/// WHY PR #1997 review finding 2: the report contract — `x0x doctor
/// --json --bundle <path>` prints exactly one JSON value (the doctor
/// report) to stdout — holds even when the bundle write fails; the bundle
/// error still exits non-zero and names the bundle on stderr. Here the
/// write fails because the target directory is read-only.
#[tokio::test]
#[ignore]
async fn doctor_json_stdout_survives_bundle_write_failure() {
    if !cfg!(unix) {
        // No portable way to make a directory unwritable; the
        // daemon-backed suite runs on Linux CI.
        return;
    }
    let d = DaemonFixture::start("doctor-bundle-stdout").await;
    let token = d.api_token().to_string();

    let dir = tempfile::TempDir::new().expect("temp dir made read-only below");
    let bundle_path = dir.path().join("bundle.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .expect("make the bundle target dir read-only (0o555)");
    }

    let output = run_x0x_allow_failure(
        d.api_addr(),
        &token,
        &[
            "--json",
            "doctor",
            "--bundle",
            bundle_path.to_str().expect("utf-8 bundle path"),
        ],
        None,
    )
    .await;

    // Restore write permission before any assertion can fail, so the
    // temp dir's own cleanup can always remove the read-only directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("restore the bundle target dir to writable (0o755)");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failed bundle write must exit non-zero — got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    // `from_str` rejects trailing characters, so this pins exactly one
    // JSON value on stdout, not one-plus-noise. The fields mirror the
    // doctor checks assert_bundle_shape pins inside a written bundle.
    let report: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be one JSON value (the doctor report): {e}\nstdout:\n{stdout}")
    });
    assert!(report.is_object(), "doctor report must be a JSON object");
    assert!(
        report["connectivity"]["status"].is_string(),
        "doctor report must carry the connectivity check, got: {report}"
    );
    assert!(
        stderr.contains("doctor bundle"),
        "stderr must carry the bundle write error, got:\n{stderr}"
    );
}
