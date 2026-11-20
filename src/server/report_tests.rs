#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! #1354 slice 2: `POST /report` bundle redaction, bounds, storage and
//! rate limit.

use super::*;
use std::sync::Arc;

/// Secrets planted in the temporary data directory and log file. None of
/// them may appear in any byte of the bundle.
struct Planted {
    api_token: String,
    agent_id_hex: String,
    machine_id_hex: String,
    user_id_hex: String,
    user_name: String,
    contact_label: String,
    message_payload: String,
    kv_value: String,
    mls_secret_b64: String,
    agent_key_marker: String,
}

impl Planted {
    fn new() -> Self {
        Self {
            api_token: "9f1c2e3d4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0".into(),
            agent_id_hex: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
            machine_id_hex: "0fedcba98765432100112233445566778899aabbccddeeff0123456789abcdef"
                .into(),
            user_id_hex: "5566778899aabbcc5566778899aabbcc5566778899aabbcc5566778899aabbcc".into(),
            user_name: "zorblaxuser".into(),
            contact_label: "Zebediah Quillfeather".into(),
            message_payload: "meet me at the old mill at midnight".into(),
            kv_value: "kv secret recipe: two eggs and saffron".into(),
            mls_secret_b64: "c2VjcmV0LWdyb3VwLWtleS1tYXRlcmlhbC0xMjM0NTY3ODkw".into(),
            agent_key_marker: "AGENT-KEY-SECRET-MATERIAL-7f3a".into(),
        }
    }

    /// Every planted string, with a label for the failure message.
    fn all(&self) -> Vec<(&'static str, &str)> {
        vec![
            ("api token", self.api_token.as_str()),
            ("full agent id", self.agent_id_hex.as_str()),
            ("full machine id", self.machine_id_hex.as_str()),
            ("full user id", self.user_id_hex.as_str()),
            ("user name", self.user_name.as_str()),
            ("contact label", self.contact_label.as_str()),
            ("message payload", self.message_payload.as_str()),
            ("kv value", self.kv_value.as_str()),
            ("mls secret", self.mls_secret_b64.as_str()),
            ("agent key marker", self.agent_key_marker.as_str()),
        ]
    }

    /// The planted strings that reach the builder through the log file, so
    /// a disabled redactor must let them through (red proof).
    fn in_logs(&self) -> Vec<&str> {
        vec![
            self.api_token.as_str(),
            self.agent_id_hex.as_str(),
            self.machine_id_hex.as_str(),
            self.user_id_hex.as_str(),
            self.user_name.as_str(),
            self.contact_label.as_str(),
            self.message_payload.as_str(),
            self.kv_value.as_str(),
            self.mls_secret_b64.as_str(),
        ]
    }
}

/// A fake home `<tmp>/Users/<user_name>` with an x0x data directory and a
/// log file full of planted secrets.
struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    data_dir: PathBuf,
    log_file: PathBuf,
}

fn plant(p: &Planted) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("Users").join(&p.user_name);
    let data_dir = home.join("Library/Application Support/x0x");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("api-token"), &p.api_token).unwrap();
    let mut key = p.agent_key_marker.as_bytes().to_vec();
    key.extend_from_slice(&[0xAB; 64]);
    std::fs::write(data_dir.join("agent.key"), &key).unwrap();
    std::fs::write(data_dir.join("machine.key"), &key).unwrap();
    std::fs::write(
        data_dir.join("contacts.json"),
        format!("{{\"label\":\"{}\"}}", p.contact_label),
    )
    .unwrap();
    std::fs::write(data_dir.join("mls-group.secret"), &p.mls_secret_b64).unwrap();
    // A file whose NAME carries an id: the listing must cut it.
    std::fs::write(data_dir.join(format!("group-{}.kv", p.user_id_hex)), b"x").unwrap();

    let log_dir = tmp.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    let log_file = log_dir.join("x0xd-4242.log");
    let home_s = home.display().to_string();
    let lines = [
        format!(
            "2026-11-20T10:00:00Z  INFO x0x::server::auth: API token loaded from {}/api-token",
            data_dir.display()
        ),
        format!(
            "2026-11-20T10:00:01Z  WARN x0x::server: bearer {} refused",
            p.api_token
        ),
        format!(
            "2026-11-20T10:00:02Z  INFO x0x::identity: agent_id={} machine_id={} user={}",
            p.agent_id_hex, p.machine_id_hex, p.user_id_hex
        ),
        format!(
            "2026-11-20T10:00:03Z  INFO x0x::dm: delivered payload=\"{}\"",
            p.message_payload
        ),
        format!(
            "2026-11-20T10:00:04Z ERROR x0x::contacts: contact {} unreachable",
            p.contact_label
        ),
        format!(
            "2026-11-20T10:00:05Z DEBUG x0x::mls: installed epoch secret {}",
            p.mls_secret_b64
        ),
        format!(
            "2026-11-20T10:00:06Z  INFO x0x::upgrade: staging in {home_s}/.local/share/x0x and /Users/{}/Downloads",
            p.user_name
        ),
        serde_json::json!({
            "timestamp": "2026-11-20T10:00:07Z",
            "level": "WARN",
            "target": "x0x::kv",
            "fields": {
                "message": format!("put rejected for \"{}\"", p.kv_value),
                "value": p.kv_value,
                "owner": p.contact_label,
            }
        })
        .to_string(),
        format!("plain line by {} on host", p.user_name),
    ];
    std::fs::write(&log_file, lines.join("\n")).unwrap();
    Fixture {
        _tmp: tmp,
        home,
        data_dir,
        log_file,
    }
}

fn inputs_for(p: &Planted, f: &Fixture) -> ReportInputs {
    ReportInputs {
        data_dir: f.data_dir.clone(),
        log_file: Some(f.log_file.clone()),
        health: serde_json::json!({
            "ok": true,
            "data": { "status": "healthy", "note": format!("seen {}", p.agent_id_hex) }
        }),
        agent_id_hex: p.agent_id_hex.clone(),
        machine_id_hex: p.machine_id_hex.clone(),
        uptime_secs: 42,
        created_unix: 1_763_600_000,
    }
}

/// The redactor the route builds, for the fixture: the API token comes
/// from the planted `api-token` file, the contact label from the contact
/// list.
fn redactor_for(p: &Planted, f: &Fixture) -> Redactor {
    let mut secrets = vec![p.contact_label.clone()];
    secrets.extend(read_api_token(&f.data_dir));
    Redactor::new(
        secrets,
        Some(&f.data_dir),
        Some(&f.home),
        Some(p.user_name.clone()),
    )
}

/// #1354 core rule: a bundle holds no keys, tokens, ids, names, paths with
/// the user name, or message/KV content — checked against every byte.
/// The second half is the red proof: with redaction disabled the same
/// builder leaks every log-borne secret, so this test can see a leak.
#[test]
fn report_bundle_contains_no_planted_secret() {
    let p = Planted::new();
    let f = plant(&p);
    let inputs = inputs_for(&p, &f);

    let built = build_report(&inputs, &redactor_for(&p, &f)).unwrap();
    let text = String::from_utf8_lossy(&built.bytes);
    for (label, secret) in p.all() {
        assert!(
            !text.contains(secret),
            "bundle leaks the planted {label}: {secret}\n{text}"
        );
    }
    let home_s = f.home.display().to_string();
    assert!(!text.contains(&home_s), "bundle leaks the home path");

    // The bundle is still useful: it parses, keeps the log lines, and
    // names the ids by short prefix only.
    let value: serde_json::Value = serde_json::from_slice(&built.bytes).unwrap();
    assert_eq!(value["schema"], REPORT_SCHEMA);
    assert_eq!(value["identity"]["agent_id_prefix"], &p.agent_id_hex[..8]);
    assert_eq!(
        value["identity"]["machine_id_prefix"],
        &p.machine_id_hex[..8]
    );
    assert_eq!(built.log_lines, 9);
    assert!(text.contains("API token loaded from <x0x-data>/api-token"));
    assert!(text.contains("x0x::kv: put rejected for"));
    let names: Vec<&str> = value["data_dir"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    assert!(
        names.contains(&"agent.key"),
        "listing names key files: {names:?}"
    );

    // Red proof: the same build with redaction off leaks every log-borne
    // secret, so the assertions above can fail.
    let leaky = build_report(&inputs, &redactor_for(&p, &f).disabled_for_red_proof()).unwrap();
    let leaky_text = String::from_utf8_lossy(&leaky.bytes);
    for secret in p.in_logs() {
        assert!(
            leaky_text.contains(secret),
            "red proof: with redaction off the bundle must carry {secret}"
        );
    }
    // Key file contents are never read, redaction on or off.
    assert!(!leaky_text.contains(&p.agent_key_marker));
}

/// Bounded size: a huge log file is read only from its end, at most
/// MAX_LOG_LINES lines are kept, and the bundle fits MAX_BUNDLE_BYTES.
#[test]
fn report_bundle_is_bounded_for_a_huge_log() {
    let p = Planted::new();
    let f = plant(&p);
    let line = format!(
        "2026-11-20T10:00:00Z  INFO x0x::gossip: {}\n",
        "word ".repeat(150)
    );
    let mut big = String::with_capacity(line.len() * 2_000);
    for _ in 0..2_000 {
        big.push_str(&line);
    }
    std::fs::write(&f.log_file, big).unwrap();
    let built = build_report(&inputs_for(&p, &f), &redactor_for(&p, &f)).unwrap();
    assert!(built.bytes.len() <= MAX_BUNDLE_BYTES);
    assert!(built.log_lines <= MAX_LOG_LINES);
    assert!(built.log_lines > 0);
    let value: serde_json::Value = serde_json::from_slice(&built.bytes).unwrap();
    for row in value["log_tail"]["lines"].as_array().unwrap() {
        assert!(row.as_str().unwrap().chars().count() <= MAX_LOG_LINE_CHARS + " [cut]".len());
    }
}

/// Lines that do not fit the byte bound are dropped oldest first.
#[test]
fn report_bundle_drops_oldest_log_lines_to_fit() {
    let p = Planted::new();
    let f = plant(&p);
    // A control byte serializes as a 6-byte `\u0001` escape, so 200 lines
    // of 400 such bytes are ~480 KB of JSON, over the bound.
    let line = format!("{}\n", "\u{1}".repeat(MAX_LOG_LINE_CHARS));
    std::fs::write(&f.log_file, line.repeat(2 * MAX_LOG_LINES)).unwrap();
    let built = build_report(&inputs_for(&p, &f), &redactor_for(&p, &f)).unwrap();
    assert!(built.bytes.len() <= MAX_BUNDLE_BYTES);
    assert!(built.log_lines_dropped > 0, "the bound must have cut lines");
    assert!(built.log_lines > 0);
    assert_eq!(built.log_lines + built.log_lines_dropped, MAX_LOG_LINES);
}

#[test]
fn scrub_rules() {
    let r = Redactor::new(
        vec!["tok3n-secret".to_string(), "ab".to_string()],
        None,
        None,
        None,
    );
    // Long hex is cut to an 8-character prefix; short hex stays.
    assert_eq!(
        r.scrub("id 0123456789abcdef0123456789abcdef end"),
        "id 01234567… end"
    );
    assert_eq!(r.scrub("port 9a3f"), "port 9a3f");
    // Long base64-like runs go; plain words stay.
    assert_eq!(
        r.scrub("k=c2VjcmV0LWdyb3VwLWtleS1tYXRlcmlhbC0xMjM0 ok"),
        "k=[redacted] ok"
    );
    assert_eq!(r.scrub("x0x::server::routes"), "x0x::server::routes");
    // Known secrets go; a too-short secret is ignored, not applied.
    assert_eq!(r.scrub("t=tok3n-secret ab"), "t=[redacted] ab");
    // User directories lose the user segment on every platform.
    assert_eq!(
        r.scrub("/Users/alice/x and /home/bob/y and C:\\Users\\carol\\z"),
        "/Users/<user>/x and /home/<user>/y and C:\\Users\\<user>\\z"
    );
    // Quoted log values are removed, escapes included.
    assert_eq!(
        r.scrub_log_line(r#"INFO a: sent body="hi \"there\"" to=x"#),
        r#"INFO a: sent body="[redacted]" to=x"#
    );
    assert_eq!(
        r.scrub_log_line(r#"INFO a: open "unterminated"#),
        r#"INFO a: open "[redacted]"#
    );
}

#[test]
fn store_report_is_new_0600_and_prune_keeps_newest() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(REPORTS_DIR);
    for secs in 1..=12u64 {
        store_report(&dir, secs, b"{}").unwrap();
    }
    // The same second again is refused, never overwritten.
    assert!(store_report(&dir, 12, b"{\"x\":1}").is_err());
    assert_eq!(
        std::fs::read(dir.join(report_file_name(12))).unwrap(),
        b"{}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(report_file_name(1)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }
    // An unrelated file in the directory is never touched.
    std::fs::write(dir.join("notes.txt"), b"keep").unwrap();
    assert_eq!(prune_reports(&dir, MAX_STORED_REPORTS), 2);
    assert!(!dir.join(report_file_name(1)).exists());
    assert!(!dir.join(report_file_name(2)).exists());
    assert!(dir.join(report_file_name(3)).exists());
    assert!(dir.join(report_file_name(12)).exists());
    assert!(dir.join("notes.txt").exists());
}

#[test]
fn report_rate_limit_is_per_data_dir() {
    let slots = Mutex::new(HashMap::new());
    let a = Path::new("/tmp/x0x-a");
    let b = Path::new("/tmp/x0x-b");
    let t0 = Instant::now();
    assert!(claim_report_slot(&slots, a, t0).is_ok());
    let wait = claim_report_slot(&slots, a, t0 + Duration::from_secs(10)).unwrap_err();
    assert_eq!(wait, 50);
    assert!(claim_report_slot(&slots, b, t0).is_ok());
    assert!(claim_report_slot(&slots, a, t0 + REPORT_MIN_INTERVAL).is_ok());
    // A failed build gives its slot back.
    let t1 = t0 + REPORT_MIN_INTERVAL;
    release_report_slot(&slots, a, t1);
    assert!(claim_report_slot(&slots, a, t1 + Duration::from_secs(1)).is_ok());
}

async fn route_test_state() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let agent = Arc::new(
        crate::Agent::builder()
            .with_identity_dir(&data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await
            .unwrap(),
    );
    let state =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .unwrap();
    (state, dir)
}

async fn body_json(response: Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// `POST /report` end to end on a test daemon state: a session bearer is
/// refused, the durable owner gets a stored 0600 bundle with no API token
/// and no full agent id, and a second report inside a minute is 429.
#[tokio::test]
async fn post_report_route_writes_a_redacted_local_bundle() {
    let (state, _dir) = route_test_state().await;

    let (status, body) = body_json(
        create_report(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: false }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "durable_owner_required");

    let (status, body) = body_json(
        create_report(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["sent"], false);
    let path = PathBuf::from(body["path"].as_str().unwrap());
    assert!(path.starts_with(state.data_dir.join(REPORTS_DIR)));
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(body["size_bytes"].as_u64().unwrap() as usize, bytes.len());
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(&state.api_token));
    let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    assert!(!text.contains(&agent_hex));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["identity"]["agent_id_prefix"], &agent_hex[..8]);
    assert!(value["health"].is_object());

    let (status, body) = body_json(
        create_report(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
}
