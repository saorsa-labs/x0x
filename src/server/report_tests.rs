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
            no_body(),
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
            no_body(),
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
            no_body(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
}

/// Hardening (#2114 review): a symlinked log path is never followed, and
/// (unix) a FIFO is skipped without blocking. The bundle is still built,
/// with a note in `log_tail.source`.
#[cfg(unix)]
#[test]
fn report_skips_a_symlinked_or_fifo_log() {
    let p = Planted::new();
    let f = plant(&p);
    let link = f.log_file.with_file_name("x0xd-link.log");
    std::os::unix::fs::symlink(&f.log_file, &link).unwrap();
    let mut inputs = inputs_for(&p, &f);
    inputs.log_file = Some(link);
    let built = build_report(&inputs, &redactor_for(&p, &f)).unwrap();
    assert_eq!(built.log_lines, 0);
    let value: serde_json::Value = serde_json::from_slice(&built.bytes).unwrap();
    assert!(value["log_tail"]["source"]
        .as_str()
        .unwrap()
        .starts_with("skipped: the daemon log path is not a regular file"));

    {
        use std::os::unix::ffi::OsStrExt;
        let fifo = f.log_file.with_file_name("x0xd-fifo.log");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path for this call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo");
        inputs.log_file = Some(fifo);
        // No writer ever opens the FIFO: a blocking open would hang here.
        let built = build_report(&inputs, &redactor_for(&p, &f)).unwrap();
        assert_eq!(built.log_lines, 0);
        let value: serde_json::Value = serde_json::from_slice(&built.bytes).unwrap();
        assert!(value["log_tail"]["source"]
            .as_str()
            .unwrap()
            .starts_with("skipped: the daemon log path is not a regular file"));
    }
}

/// Hardening (#2114 review): a symlinked `reports/` is refused, nothing is
/// written through it; a fresh `reports/` is created 0700.
#[cfg(unix)]
#[test]
fn store_report_refuses_a_symlinked_reports_dir() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    let reports = tmp.path().join(REPORTS_DIR);
    std::os::unix::fs::symlink(&target, &reports).unwrap();
    let err = store_report(&reports, 7, b"{}").unwrap_err();
    assert!(
        format!("{err:#}").contains("not a plain directory"),
        "{err:#}"
    );
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);

    let fresh = tmp.path().join("data").join(REPORTS_DIR);
    store_report(&fresh, 7, b"{}").unwrap();
    let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

/// A rider token is refused with 403 and writes nothing.
#[tokio::test]
async fn post_report_route_refuses_a_rider() {
    let (state, _dir) = route_test_state().await;
    let rider = ActorContext::Rider {
        sub_agent_id: "00".repeat(32),
        token_id: 1,
        token_hash: "11".repeat(32),
        groups: Vec::new(),
        scopes: Vec::new(),
    };
    let (status, body) = body_json(
        create_report(
            State(Arc::clone(&state)),
            axum::extract::Extension(rider),
            no_body(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "durable_owner_required");
    assert!(!state.data_dir.join(REPORTS_DIR).exists());
}

// ---------------------------------------------------------------------------
// #1354 slice 3: the sent copy and its delivery to an owner device
// ---------------------------------------------------------------------------

/// The request body the route gets when the caller sends none.
fn no_body() -> std::result::Result<Json<ReportRequest>, axum::extract::rejection::JsonRejection> {
    Ok(Json(ReportRequest::default()))
}

fn deliver_to(
    hex_id: &str,
) -> std::result::Result<Json<ReportRequest>, axum::extract::rejection::JsonRejection> {
    Ok(Json(ReportRequest {
        deliver_to: Some(hex_id.to_string()),
    }))
}

/// Text the local redactor keeps (peer address, four-word address, free
/// text in a log message, a file name), planted so the sent copy can be
/// checked for it.
const KEPT_BY_REDACTOR: [&str; 4] = [
    "203.0.113.77:5483",
    "ocean-tiger-maple-river",
    "zorgflask",
    "private-diary-notes.txt",
];

fn plant_kept_text(f: &Fixture) {
    let mut log = std::fs::read_to_string(&f.log_file).unwrap();
    log.push_str(
        "\n2026-11-20T10:00:08Z  INFO x0x::network: peer 203.0.113.77:5483 \
         (ocean-tiger-maple-river) said zorgflask",
    );
    std::fs::write(&f.log_file, log).unwrap();
    std::fs::write(f.data_dir.join("private-diary-notes.txt"), b"x").unwrap();
}

/// WHY (#1354 slice 3): the copy that leaves the machine must carry no
/// planted secret and none of the text the local redactor keeps; the
/// log tail and the data-directory listing are withheld whole, and the
/// rest still passes the redactor (the red half shows the redactor is
/// what removes the full agent id from the health body).
#[test]
fn sent_report_withholds_log_and_listing_and_is_redacted() {
    let p = Planted::new();
    let f = plant(&p);
    plant_kept_text(&f);
    let inputs = inputs_for(&p, &f);

    // The local bundle does keep that text: the sent copy has to drop it.
    let local = build_report(&inputs, &redactor_for(&p, &f)).unwrap();
    let local_text = String::from_utf8_lossy(&local.bytes);
    for kept in KEPT_BY_REDACTOR {
        assert!(local_text.contains(kept), "fixture: local keeps {kept}");
    }

    let sent = build_sent_report(&inputs, &redactor_for(&p, &f), MAX_SENT_REPORT_BYTES).unwrap();
    assert!(sent.len() <= MAX_SENT_REPORT_BYTES);
    let text = String::from_utf8_lossy(&sent);
    for (label, secret) in p.all() {
        assert!(!text.contains(secret), "sent copy leaks the {label}");
    }
    for kept in KEPT_BY_REDACTOR {
        assert!(!text.contains(kept), "sent copy leaks kept text {kept}");
    }
    assert!(!text.contains(&f.home.display().to_string()));
    let value: serde_json::Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(value["schema"], REPORT_SCHEMA);
    assert_eq!(value["profile"], "sent");
    assert_eq!(value["withheld"], serde_json::json!(SENT_REPORT_WITHHELD));
    for section in SENT_REPORT_WITHHELD {
        assert!(value.get(section).is_none(), "{section} must be withheld");
    }
    assert_eq!(value["identity"]["agent_id_prefix"], &p.agent_id_hex[..8]);
    assert_eq!(value["health"]["data"]["status"], "healthy");

    // Red proof: with the redactor off, the full agent id in the health
    // body reaches the sent bytes.
    let leaky = build_sent_report(
        &inputs,
        &redactor_for(&p, &f).disabled_for_red_proof(),
        MAX_SENT_REPORT_BYTES,
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&leaky).contains(&p.agent_id_hex));
}

/// WHY: the sent copy rides one DM, so it has a hard bound below the DM
/// payload limit; an oversized copy is refused, never cut silently.
#[test]
fn sent_report_over_its_bound_is_refused() {
    const _: () = assert!(MAX_SENT_REPORT_BYTES <= crate::dm::MAX_PAYLOAD_BYTES);
    let p = Planted::new();
    let f = plant(&p);
    let mut inputs = inputs_for(&p, &f);
    inputs.health = serde_json::json!({ "pad": "word ".repeat(MAX_SENT_REPORT_BYTES / 5 + 1) });
    match build_sent_report(&inputs, &redactor_for(&p, &f), MAX_SENT_REPORT_BYTES) {
        Err(SentReportError::TooLarge(len)) => assert!(len > MAX_SENT_REPORT_BYTES),
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

fn roster_entry(
    agent: &crate::identity::AgentId,
    mode: crate::profile::CertMode,
) -> crate::OwnerIssuedCert {
    crate::OwnerIssuedCert {
        agent_id: hex::encode(agent.as_bytes()),
        issued_at: 1,
        not_after: None,
        digest: "00".repeat(32),
        from_journal: true,
        mode,
        label: None,
    }
}

/// WHY: a report goes only to one of the owner's own devices: an agent
/// on the owner's issued-certificate roster, not a rider, not this
/// daemon, not with an expired certificate.
#[test]
fn deliver_to_must_be_an_owner_device() {
    use crate::identity::AgentId;
    use crate::profile::CertMode;
    let own = AgentId([1; 32]);
    let device = AgentId([2; 32]);
    let rider = AgentId([3; 32]);
    let expired = AgentId([4; 32]);
    let mut expired_entry = roster_entry(&expired, CertMode::Acp);
    expired_entry.not_after = Some(100);
    let roster = vec![
        roster_entry(&own, CertMode::Acp),
        roster_entry(&device, CertMode::Acp),
        roster_entry(&rider, CertMode::Rider),
        expired_entry,
    ];
    let code = |hex_id: &str| {
        check_owner_recipient(hex_id, &own, &roster, &[], 1_000)
            .err()
            .map(|(_, code, _)| code)
    };
    assert_eq!(
        check_owner_recipient(
            &hex::encode([2; 32]).to_uppercase(),
            &own,
            &roster,
            &[],
            1_000
        )
        .ok(),
        Some(device)
    );
    assert_eq!(code("zz"), Some("invalid_agent_id"));
    assert_eq!(code(&hex::encode([2; 16])), Some("invalid_agent_id"));
    assert_eq!(code(&hex::encode([1; 32])), Some("deliver_to_self"));
    assert_eq!(code(&hex::encode([9; 32])), Some("not_an_owner_device"));
    assert_eq!(code(&hex::encode([3; 32])), Some("not_an_owner_device"));
    assert_eq!(code(&hex::encode([4; 32])), Some("certificate_expired"));
}

/// A transport whose recipient is offline until `online` is set; it
/// records the payloads it carried.
#[derive(Default)]
struct OfflineDevice {
    online: std::sync::atomic::AtomicBool,
    attempts: std::sync::atomic::AtomicUsize,
    delivered: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl super::super::routes::direct_outbox::DirectSendTransport for OfflineDevice {
    fn recipient_blocked(
        &self,
        _recipient: crate::identity::AgentId,
    ) -> super::super::routes::direct_outbox::TransportFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn send(
        &self,
        _recipient: crate::identity::AgentId,
        payload: Vec<u8>,
        _config: crate::dm::DmSendConfig,
        _budget: Duration,
    ) -> super::super::routes::direct_outbox::TransportFuture<'_, Result<(), crate::dm::DmError>>
    {
        use std::sync::atomic::Ordering;
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let result = if self.online.load(Ordering::SeqCst) {
            self.delivered.lock().unwrap().push(payload);
            Ok(())
        } else {
            Err(crate::dm::DmError::PeerLikelyOffline {
                phi: 12.0,
                last_seen_ms_ago: Some(60_000),
            })
        };
        Box::pin(async move { result })
    }
}

/// WHY (#1354 done-when): a report reaches an owner device that was
/// offline when it was sent. The sent copy is queued on the durable
/// direct-send outbox; attempts while the device is offline keep it, a
/// daemon restart keeps it, and the first attempt after the device comes
/// back delivers exactly the queued bytes.
#[tokio::test]
async fn sent_report_reaches_an_owner_device_that_was_offline() {
    use super::super::routes::direct_outbox::{
        DirectSendNow, DirectSendOutbox, EnqueueOutcome, LedgerReceipt, DIRECT_SEND_OUTBOX_FILE,
        DIRECT_SEND_RETRY_SECS,
    };
    use std::sync::atomic::Ordering;
    let p = Planted::new();
    let f = plant(&p);
    let payload = build_sent_report(
        &inputs_for(&p, &f),
        &redactor_for(&p, &f),
        MAX_SENT_REPORT_BYTES,
    )
    .unwrap();
    let sender = crate::identity::AgentId([1; 32]);
    let device = crate::identity::AgentId([2; 32]);
    let now_ms = super::super::routes::direct_outbox::now_unix_ms();
    let obligation =
        report_obligation(sender, device, 1_763_600_000, payload.clone(), now_ms).unwrap();
    assert_eq!(obligation.logical_id, "x0x-report-1763600000");
    assert!(obligation.deliver_until_ms > now_ms);
    let rid = obligation.request_id_bytes().unwrap();
    let no_record = |_: &[u8; 16]| LedgerReceipt {
        status: crate::dm::DmReceiptStatus::Unknown,
        digest: None,
        machine: None,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DIRECT_SEND_OUTBOX_FILE);
    let outbox = DirectSendOutbox::new(path.clone());
    assert_eq!(
        outbox.enqueue(obligation, no_record(&rid)).await,
        EnqueueOutcome::Queued
    );

    let device_link = OfflineDevice::default();
    let at = |mono_ms| DirectSendNow {
        wall_ms: super::super::routes::direct_outbox::now_unix_ms(),
        mono_ms,
    };
    outbox.step(at(0), &no_record, &device_link).await;
    assert_eq!(device_link.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(outbox.snapshot().await.len(), 1, "offline: still queued");
    let queued = outbox.receipt(&device, &rid, no_record(&rid)).await;
    assert_eq!(queued.status, "queued");

    // The daemon restarts while the device is still offline.
    drop(outbox);
    let outbox = DirectSendOutbox::new(path);
    outbox.load(0).await.unwrap();
    assert_eq!(outbox.snapshot().await.len(), 1, "restart keeps the report");
    outbox.step(at(0), &no_record, &device_link).await;
    assert_eq!(device_link.attempts.load(Ordering::SeqCst), 2);
    assert!(device_link.delivered.lock().unwrap().is_empty());

    // The device reconnects: the next due attempt delivers.
    device_link.online.store(true, Ordering::SeqCst);
    let later = DIRECT_SEND_RETRY_SECS[DIRECT_SEND_RETRY_SECS.len() - 1] * 1000 + 1;
    outbox.step(at(later), &no_record, &device_link).await;
    assert_eq!(*device_link.delivered.lock().unwrap(), vec![payload]);
    assert!(outbox.snapshot().await.is_empty());
    assert_eq!(
        outbox.receipt(&device, &rid, no_record(&rid)).await.status,
        "delivered"
    );
}

/// A route state whose daemon has an owner identity, plus the agent id of
/// a second owner device on the owner's certificate journal.
async fn owner_route_state() -> (
    Arc<AppState>,
    tempfile::TempDir,
    crate::identity::AgentKeypair,
) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let seed = [0x5A; 32];
    let issuer = crate::identity::UserKeypair::from_seed(&seed).unwrap();
    let device = crate::identity::AgentKeypair::generate().unwrap();
    let cert = crate::identity::AgentCertificate::issue(&issuer, &device).unwrap();
    let record = crate::profile::IssuedCertRecord::from_cert(&issuer.user_id(), &cert).unwrap();
    crate::profile::IssuedCertRecord::append(
        &data_dir.join(crate::profile::CERT_JOURNAL_FILE),
        &record,
    )
    .await
    .unwrap();
    let agent = Arc::new(
        crate::Agent::builder()
            .with_identity_dir(&data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(crate::identity::UserKeypair::from_seed(&seed).unwrap())
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await
            .unwrap(),
    );
    let state =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .unwrap();
    (state, dir, device)
}

/// The real route with a durable-owner actor, for requests with a body.
async fn post_report_http(
    state: &Arc<AppState>,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let app = axum::Router::new()
        .route("/report", axum::routing::post(create_report))
        .layer(axum::Extension(ActorContext::Owner { durable: true }))
        .with_state(Arc::clone(state));
    let mut request = axum::http::Request::post("/report");
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(axum::body::Body::from(body.unwrap_or_default().to_string()))
        .unwrap();
    body_json(app.oneshot(request).await.unwrap()).await
}

/// WHY (#1354 slice 3): with `deliver_to` naming an owner device, the
/// route stores the bundle and queues the sent copy (redacted, withheld
/// sections absent) on the durable outbox under the report's logical id.
#[tokio::test]
async fn post_report_deliver_to_queues_the_sent_copy() {
    let (state, _dir, device) = owner_route_state().await;
    let device = device.agent_id();
    let device_hex = hex::encode(device.as_bytes());
    let (status, body) = post_report_http(
        &state,
        Some(&serde_json::json!({ "deliver_to": device_hex }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["sent"], false);
    let delivery = &body["delivery"];
    assert_eq!(delivery["outcome"], "queued");
    assert_eq!(delivery["agent_id"], device_hex.as_str());
    let created = body["created_unix"].as_u64().unwrap();
    assert_eq!(delivery["logical_id"], report_logical_id(created).as_str());
    assert!(PathBuf::from(body["path"].as_str().unwrap()).exists());

    let held = state.direct_send_outbox.snapshot().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].recipient, device_hex);
    assert_eq!(
        delivery["size_bytes"].as_u64().unwrap() as usize,
        held[0].payload.len()
    );
    let text = String::from_utf8_lossy(&held[0].payload);
    assert!(!text.contains(&state.api_token));
    assert!(!text.contains(&hex::encode(state.agent.agent_id().as_bytes())));
    let value: serde_json::Value = serde_json::from_slice(&held[0].payload).unwrap();
    assert_eq!(value["profile"], "sent");
    for section in SENT_REPORT_WITHHELD {
        assert!(value.get(section).is_none());
    }
}

/// WHY: a refused `deliver_to` is answered before the rate slot is taken
/// and queues nothing; a body with an unknown field is a 400, not a
/// silent local-only report; no body is still the local-only report.
#[tokio::test]
async fn post_report_refuses_a_bad_target_without_using_the_slot() {
    let (state, _dir, _device) = owner_route_state().await;
    for (body, code) in [
        (r#"{"deliver_to":"zz"}"#.to_string(), "invalid_agent_id"),
        (
            serde_json::json!({ "deliver_to": "ab".repeat(32) }).to_string(),
            "not_an_owner_device",
        ),
        (
            serde_json::json!({
                "deliver_to": hex::encode(state.agent.agent_id().as_bytes())
            })
            .to_string(),
            "deliver_to_self",
        ),
        (
            r#"{"send_to_maintainers":true}"#.to_string(),
            "invalid_request",
        ),
    ] {
        let (status, reply) = post_report_http(&state, Some(&body)).await;
        assert!(status.is_client_error(), "{body}: {status} {reply}");
        assert_eq!(reply["error"], code, "{body}: {reply}");
    }
    assert!(state.direct_send_outbox.snapshot().await.is_empty());
    assert!(!state.data_dir.join(REPORTS_DIR).exists());

    let (status, reply) = post_report_http(&state, None).await;
    assert_eq!(status, StatusCode::CREATED, "{reply}");
    assert!(reply["delivery"].is_null());
    assert!(state.direct_send_outbox.snapshot().await.is_empty());
}

/// WHY: without an owner identity there is no owner device to send to.
#[tokio::test]
async fn post_report_deliver_to_needs_an_owner_identity() {
    let (state, _dir) = route_test_state().await;
    let (status, body) = body_json(
        create_report(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
            deliver_to(&"ab".repeat(32)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "no_owner_identity");
}

/// WHY (#2156 review): the roster resets the mode of a renewed or
/// live-announced certificate to ACP, so a rider would pass on the roster
/// mode alone. Any journal line of this owner in rider mode refuses it;
/// another owner's rider lines do not count.
#[test]
fn a_rider_reset_to_acp_on_the_roster_is_still_refused() {
    use crate::identity::AgentId;
    use crate::profile::{CertMode, IssuedCertRecord};
    let own = AgentId([1; 32]);
    let rider = AgentId([3; 32]);
    let roster = vec![roster_entry(&rider, CertMode::Acp)];
    let line = |user: &str, mode| IssuedCertRecord {
        user_id: user.to_string(),
        agent_id: hex::encode(rider.as_bytes()),
        cert_digest: "11".repeat(32),
        issued_at: 1,
        not_after: None,
        mode,
        label: None,
        cert_b64: None,
    };
    let owner_hex = "aa".repeat(32);
    let journal = vec![
        line(&owner_hex, CertMode::Rider),
        line(&owner_hex, CertMode::Acp),
        line(&"bb".repeat(32), CertMode::Rider),
    ];
    let riders = journal_riders(&journal, &owner_hex);
    assert_eq!(riders, vec![hex::encode(rider.as_bytes())]);
    let rider_hex = hex::encode(rider.as_bytes());
    assert_eq!(
        check_owner_recipient(&rider_hex, &own, &roster, &riders, 1_000)
            .err()
            .map(|(_, code, _)| code),
        Some("not_an_owner_device")
    );
    assert!(journal_riders(&journal[1..2], &owner_hex).is_empty());
    assert!(journal_riders(&journal[2..], &owner_hex).is_empty());
}

/// WHY (#2156 review): a recipient the owner revoked (owner delete, lost
/// device) or the contact store blocked can never take the copy, so the
/// route refuses it before the slot is taken and queues nothing.
#[tokio::test]
async fn post_report_refuses_a_revoked_or_blocked_device() {
    let (state, _dir, device) = owner_route_state().await;
    let device_id = device.agent_id();
    let body = serde_json::json!({ "deliver_to": hex::encode(device_id.as_bytes()) }).to_string();

    let record = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::Agent(device_id),
        device.public_key(),
        device.secret_key(),
        1_000,
        None,
    )
    .unwrap();
    assert!(state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)
        .unwrap());
    let (status, reply) = post_report_http(&state, Some(&body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(reply["error"], "recipient_revoked");

    let (state, _dir, device) = owner_route_state().await;
    let device_id = device.agent_id();
    let body = serde_json::json!({ "deliver_to": hex::encode(device_id.as_bytes()) }).to_string();
    state
        .contacts
        .write()
        .await
        .set_trust(&device_id, crate::contacts::TrustLevel::Blocked);
    let (status, reply) = post_report_http(&state, Some(&body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(reply["error"], "recipient_blocked");
    assert!(state.direct_send_outbox.snapshot().await.is_empty());
    assert!(!state.data_dir.join(REPORTS_DIR).exists());
    assert!(claim_report_slot(report_slots(), &state.data_dir, Instant::now()).is_ok());
}

/// WHY (#2156 review): a sent copy over its bound stores nothing, queues
/// nothing and gives the one-per-minute slot back.
#[tokio::test]
async fn post_report_too_large_to_send_stores_nothing_and_frees_the_slot() {
    let (state, _dir, device) = owner_route_state().await;
    sent_limit_overrides()
        .lock()
        .unwrap()
        .insert(state.data_dir.clone(), 16);
    let body =
        serde_json::json!({ "deliver_to": hex::encode(device.agent_id().as_bytes()) }).to_string();
    let (status, reply) = post_report_http(&state, Some(&body)).await;
    sent_limit_overrides()
        .lock()
        .unwrap()
        .remove(&state.data_dir);
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{reply}");
    assert_eq!(reply["error"], "report_too_large_to_send");
    assert!(!state.data_dir.join(REPORTS_DIR).exists());
    assert!(state.direct_send_outbox.snapshot().await.is_empty());
    assert!(claim_report_slot(report_slots(), &state.data_dir, Instant::now()).is_ok());
}

/// WHY (#2156 review): when the outbox refuses the copy (here: full for
/// the device), the stored bundle is kept, its path is in the body, and
/// the slot goes back so the owner can retry.
#[tokio::test]
async fn post_report_failed_enqueue_keeps_the_bundle_and_frees_the_slot() {
    use super::super::routes::direct_outbox::{
        EnqueueOutcome, LedgerReceipt, DIRECT_SEND_OUTBOX_CAPS,
    };
    let (state, _dir, device) = owner_route_state().await;
    let device_id = device.agent_id();
    let now_ms = super::super::routes::direct_outbox::now_unix_ms();
    for i in 0..DIRECT_SEND_OUTBOX_CAPS.per_partition {
        let filler =
            report_obligation(state.agent.agent_id(), device_id, i as u64, vec![0], now_ms)
                .unwrap();
        let none = LedgerReceipt {
            status: crate::dm::DmReceiptStatus::Unknown,
            digest: None,
            machine: None,
        };
        assert_eq!(
            state.direct_send_outbox.enqueue(filler, none).await,
            EnqueueOutcome::Queued
        );
    }
    let body = serde_json::json!({ "deliver_to": hex::encode(device_id.as_bytes()) }).to_string();
    let (status, reply) = post_report_http(&state, Some(&body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{reply}");
    assert_eq!(reply["error"], "outbox_full");
    assert!(reply["delivery"].is_null());
    assert!(PathBuf::from(reply["path"].as_str().unwrap()).exists());
    assert!(claim_report_slot(report_slots(), &state.data_dir, Instant::now()).is_ok());
}

/// WHY (#2156 review): `outbox_not_durable` means the copy is held and may
/// still be sent, so the refusal keeps the slot (an at-once retry would
/// queue a second report) and still describes the held delivery; every
/// other refusal gives the slot back.
#[test]
fn queue_refusals_keep_the_slot_only_when_the_copy_may_still_be_sent() {
    use super::super::routes::direct_outbox::EnqueueOutcome;
    let delivery = || serde_json::json!({ "outcome": "queued", "logical_id": "x0x-report-1" });
    let held = queue_outcome(EnqueueOutcome::NotDurable("fsync".into()), delivery()).unwrap_err();
    assert_eq!(held.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(held.code, "outbox_not_durable");
    assert!(held.keep_slot);
    assert_eq!(held.delivery.unwrap()["outcome"], "held_not_durable");
    for (outcome, code) in [
        (EnqueueOutcome::Full, "outbox_full"),
        (EnqueueOutcome::Conflict, "idempotency_conflict"),
        (EnqueueOutcome::InFlight, "idempotency_conflict"),
        (
            EnqueueOutcome::WriteFailed("disk".into()),
            "outbox_write_failed",
        ),
    ] {
        let refusal = queue_outcome(outcome, delivery()).unwrap_err();
        assert_eq!(refusal.code, code);
        assert!(!refusal.keep_slot, "{code} must give the slot back");
        assert!(refusal.delivery.is_none());
    }
    assert_eq!(
        queue_outcome(EnqueueOutcome::Queued, delivery()).unwrap()["outcome"],
        "queued"
    );
}
