#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State as AxumState;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use tokio::sync::{mpsc, Notify};
use tower::ServiceExt as _;

use crate::history::{Direction, HistoryRecord, Provenance, Scope};
use crate::identity::{AgentId, MachineId};
use crate::profile::CertMode;
use crate::server::config::analyze;
use crate::server::rider_auth::unix_now_secs;
use crate::server::webhook::{
    compute_backoff_ms, dm_dedupe_key, group_dedupe_key, hmac_sha256, is_echo_author_with_roster,
    is_ip_ssrf_blocked, mention_dedupe_key, sign_payload, BatchDisposition, DeliveryOutcome, Lane,
    NotifyConfig, QueuedWebhookItem, ValidatedWebhook, WebhookBodyMode, WebhookConfig,
    WebhookConfigError, WebhookDedupeStore, WebhookPayloadItem, WebhookPostBody, WebhookScheduler,
    WebhookService, MAX_RETRYABLE_ATTEMPTS,
};
use crate::server::ws::{emit_mention_event, MentionFrame};
use crate::server::{serve_with_options, DaemonConfig, ServeOptions};
use crate::OwnerIssuedCert;

#[cfg(unix)]
fn write_secret_file(dir: &std::path::Path, name: &str, content: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write secret file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod secret");
    path
}

#[cfg(not(unix))]
fn write_secret_file(dir: &std::path::Path, name: &str, content: &str, _mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write secret file");
    path
}

fn sample_item(key: &str, lane: Lane, kind: &str, text: Option<&str>) -> QueuedWebhookItem {
    QueuedWebhookItem {
        dedupe_key: key.to_string(),
        lane,
        enqueued_at_ms: 1_700_000_000_000,
        item: WebhookPayloadItem {
            kind: kind.to_string(),
            from: "aa".repeat(32),
            from_name: Some("alice".to_string()),
            group_id: None,
            topic: None,
            ts: 1_700_000_000_000,
            text: text.map(str::to_string),
            msg_id: None,
            flags: Vec::new(),
        },
    }
}

#[test]
fn hmac_sha256_matches_rfc4231_case2_and_long_key_and_header_format() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex::encode(mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );

    let long_key = vec![0xaa; 131];
    let long_msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let long_mac = hmac_sha256(&long_key, long_msg);
    assert_eq!(
        hex::encode(long_mac),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );

    let body = br#"{"source":"x0x","version":1}"#;
    let ts = 1_732_698_000u64;
    let header = sign_payload(b"top-secret", ts, body);
    let expected_mac = hmac_sha256(b"top-secret", br#"1732698000.{"source":"x0x","version":1}"#);
    assert_eq!(header, format!("t={ts},v1={}", hex::encode(expected_mac)));
}

#[test]
fn config_toml_parse_validation_and_empty_inert() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bearer_path = write_secret_file(tmp.path(), "bearer.txt", "tok-123\n", 0o600);
    let sig_path = write_secret_file(tmp.path(), "sig.txt", "sec-456  \n", 0o600);

    let toml_src = format!(
        r#"
[[notify.webhook]]
name = "feynman"
url = "https://api2.cursor.sh/automations/webhook/abc"
allowed_hosts = ["api2.cursor.sh"]
bearer_token_file = "{}"
signing_secret_file = "{}"
events = ["dm", "mention", "group:g1", "topic:news"]
dm_allowlist = ["{}"]
fast_window_ms = 5000
batch_window_ms = 60000
max_per_hour = 6
max_per_day = 60
body_mode = "metadata"
max_text_chars = 1000
"#,
        bearer_path.display(),
        sig_path.display(),
        "ab".repeat(32)
    );

    let (cfg, findings) = analyze(&toml_src).expect("toml parses");
    assert!(findings.is_clean(), "unexpected findings: {findings:?}");
    assert_eq!(cfg.notify.webhook.len(), 1);
    let wh = &cfg.notify.webhook[0];
    assert_eq!(wh.name, "feynman");
    assert_eq!(wh.body_mode, WebhookBodyMode::Metadata);
    let validated = ValidatedWebhook::validate(wh).expect("valid config");
    assert_eq!(validated.url_host, "api2.cursor.sh");
    assert!(!format!("{validated:?}").contains("tok-123"));
    assert!(!format!("{validated:?}").contains("sec-456"));

    let mut http_cfg = wh.clone();
    http_cfg.url = "http://api2.cursor.sh/hook".to_string();
    assert!(matches!(
        ValidatedWebhook::validate(&http_cfg),
        Err(WebhookConfigError::NonHttpsUrl)
    ));

    let mut wrong_host = wh.clone();
    wrong_host.allowed_hosts = vec!["other.example.com".to_string()];
    assert!(matches!(
        ValidatedWebhook::validate(&wrong_host),
        Err(WebhookConfigError::HostNotAllowed(_))
    ));

    #[cfg(unix)]
    {
        let loose = write_secret_file(tmp.path(), "loose.txt", "secret\n", 0o644);
        let mut loose_cfg = wh.clone();
        loose_cfg.signing_secret_file = Some(loose);
        assert!(matches!(
            ValidatedWebhook::validate(&loose_cfg),
            Err(WebhookConfigError::InsecureSecretPermissions { .. })
        ));
    }

    let mut missing_cfg = wh.clone();
    missing_cfg.bearer_token_file = Some(tmp.path().join("does-not-exist"));
    assert!(matches!(
        ValidatedWebhook::validate(&missing_cfg),
        Err(WebhookConfigError::SecretFileUnreadable { .. })
    ));

    let empty_data = tmp.path().join("empty-data");
    assert!(WebhookService::new(&NotifyConfig::default(), &empty_data).is_none());
    assert!(!empty_data.join("webhook_state.db").exists());
}

#[test]
fn ssrf_ip_classifier_blocks_non_public_and_allows_public() {
    let blocked: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("fe80::1".parse().expect("ipv6")),
        IpAddr::V6("fc00::1".parse().expect("ipv6")),
        IpAddr::V6("fd12:3456:789a::1".parse().expect("ipv6")),
        IpAddr::V6("ff02::1".parse().expect("ipv6")),
        IpAddr::V6("::ffff:127.0.0.1".parse().expect("ipv6")),
        IpAddr::V6("::ffff:10.0.0.1".parse().expect("ipv6")),
        IpAddr::V6("64:ff9b::127.0.0.1".parse().expect("ipv6")),
        IpAddr::V6("2002:7f00:0001::1".parse().expect("ipv6")),
        IpAddr::V6("2002:0a00:0001::1".parse().expect("ipv6")),
        IpAddr::V6(
            "2001:0000:0101:0101:0000:0000:80ff:fffe"
                .parse()
                .expect("ipv6"),
        ),
        IpAddr::V6(
            "2001:0000:0a00:0001:0000:0000:fefe:fefe"
                .parse()
                .expect("ipv6"),
        ),
    ];
    for &ip in blocked {
        assert!(is_ip_ssrf_blocked(ip), "expected SSRF block for {ip}");
    }

    let allowed: &[IpAddr] = &[
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V4(Ipv4Addr::new(100, 63, 255, 254)),
        IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1)),
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        IpAddr::V6("2002:0101:0101::1".parse().expect("ipv6")),
    ];
    for &ip in allowed {
        assert!(!is_ip_ssrf_blocked(ip), "expected public IP allowed: {ip}");
    }
}

#[test]
fn scheduler_lanes_batching_rate_cap_rollover_and_priority_with_virtual_clock() {
    let mut sched = WebhookScheduler::new(5_000, 60_000, 2, 4, 16);

    assert!(sched.enqueue(sample_item("b1", Lane::Batch, "group", Some("g1")), 0));
    assert_eq!(sched.next_wakeup_ms(0), Some(60_000));
    assert!(sched.poll_ready(59_999).0.is_none());

    let (batch1, rl1) = sched.poll_ready(60_000);
    assert!(!rl1);
    let batch1 = batch1.expect("batch due at 60s");
    assert!(!batch1.rate_limited);
    assert_eq!(batch1.items.len(), 1);
    assert!(matches!(
        sched.record_outcome(DeliveryOutcome::Success(200), 60_000, 0.5),
        Some(BatchDisposition::Committed { .. })
    ));

    assert!(sched.enqueue(sample_item("f1", Lane::Fast, "dm", Some("hi")), 70_000));
    assert_eq!(sched.next_wakeup_ms(70_000), Some(75_000));
    assert!(sched.poll_ready(74_999).0.is_none());

    let (batch2, rl2) = sched.poll_ready(75_000);
    assert!(!rl2);
    let batch2 = batch2.expect("fast due at 75s");
    assert!(!batch2.rate_limited);
    assert!(matches!(
        sched.record_outcome(DeliveryOutcome::Success(200), 75_000, 0.5),
        Some(BatchDisposition::Committed { .. })
    ));

    assert!(sched.enqueue(sample_item("b2", Lane::Batch, "group", Some("g2")), 80_000));
    assert!(sched.enqueue(
        sample_item("f2", Lane::Fast, "mention", Some("@me")),
        81_000
    ));

    let (held, newly_rl) = sched.poll_ready(86_000);
    assert!(held.is_none());
    assert!(newly_rl);
    assert_eq!(sched.next_wakeup_ms(86_000), Some(3_660_000));

    let (batch3, newly_rl_after) = sched.poll_ready(3_660_000);
    assert!(!newly_rl_after);
    let batch3 = batch3.expect("released after hourly rollover");
    assert!(batch3.rate_limited);
    assert_eq!(batch3.items.len(), 2);
    assert_eq!(batch3.items[0].dedupe_key, "f2");
    assert_eq!(batch3.items[1].dedupe_key, "b2");
}

#[test]
fn scheduler_backoff_schedule_4xx_drop_after_3_and_queue_bound() {
    assert_eq!(compute_backoff_ms(1, 0.5), 2_000);
    assert_eq!(compute_backoff_ms(2, 0.5), 4_000);
    assert_eq!(compute_backoff_ms(3, 0.5), 8_000);
    assert_eq!(compute_backoff_ms(20, 0.5), 300_000);
    assert!(compute_backoff_ms(1, 0.0) >= 2_000);
    assert!(compute_backoff_ms(20, 1.0) <= 300_000);

    let mut sched = WebhookScheduler::new(100, 1_000, 100, 100, 2);
    assert!(sched.enqueue(sample_item("b1", Lane::Batch, "group", Some("1")), 0));
    assert!(sched.enqueue(sample_item("b2", Lane::Batch, "group", Some("2")), 0));
    assert!(!sched.enqueue(sample_item("b3", Lane::Batch, "group", Some("3")), 0));
    assert!(!sched.enqueue(sample_item("f1", Lane::Fast, "dm", Some("fast")), 0));
    assert!(!sched.contains_key("b1"));
    assert!(sched.contains_key("f1"));

    let (batch, _) = sched.poll_ready(100);
    assert!(batch.is_some());
    let d1 = sched.record_outcome(DeliveryOutcome::ClientError(400), 100, 0.5);
    assert!(matches!(
        d1,
        Some(BatchDisposition::RetryScheduled { attempts: 1, .. })
    ));
    let retry1 = sched.next_wakeup_ms(100).expect("retry 1");
    assert!(sched.poll_ready(retry1).0.is_some());
    let d2 = sched.record_outcome(DeliveryOutcome::ClientError(422), retry1, 0.5);
    assert!(matches!(
        d2,
        Some(BatchDisposition::RetryScheduled { attempts: 2, .. })
    ));
    let retry2 = sched.next_wakeup_ms(retry1).expect("retry 2");
    assert!(sched.poll_ready(retry2).0.is_some());
    let d3 = sched.record_outcome(DeliveryOutcome::ClientError(404), retry2, 0.5);
    assert!(matches!(
        d3,
        Some(BatchDisposition::Dropped4xx {
            status: 404,
            item_count: 2,
            ..
        })
    ));
    assert_eq!(sched.queue_depth(), 0);
}

#[test]
fn echo_filtering_drops_self_and_riders_but_keeps_acp_and_external() {
    let local = "11".repeat(32);
    let rider = "22".repeat(32);
    let acp = "33".repeat(32);
    let external = "44".repeat(32);
    let certs = vec![
        OwnerIssuedCert {
            agent_id: rider.clone(),
            issued_at: 100,
            not_after: None,
            digest: "d1".to_string(),
            from_journal: true,
            mode: CertMode::Rider,
            label: Some("r1".to_string()),
        },
        OwnerIssuedCert {
            agent_id: acp.clone(),
            issued_at: 100,
            not_after: None,
            digest: "d2".to_string(),
            from_journal: true,
            mode: CertMode::Acp,
            label: Some("a1".to_string()),
        },
    ];
    assert!(is_echo_author_with_roster(&local, &certs, &local, None));
    assert!(is_echo_author_with_roster(
        &local,
        &certs,
        &local.to_ascii_uppercase(),
        None
    ));
    assert!(is_echo_author_with_roster(&local, &certs, &rider, None));
    assert!(is_echo_author_with_roster(
        &local,
        &certs,
        &external,
        Some(&rider)
    ));
    assert!(!is_echo_author_with_roster(&local, &certs, &acp, None));
    assert!(!is_echo_author_with_roster(&local, &certs, &external, None));
}

#[test]
fn dedupe_store_persists_across_reopen_isolates_webhooks_and_expires_after_7_days() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("webhook_state.db");
    let dm_key = dm_dedupe_key(&"aa".repeat(32), b"hello");
    let grp_key = group_dedupe_key(&"bb".repeat(32), 1_700_000_000_123, "0123456789abcdef9999");
    let m_key = mention_dedupe_key("msg-42");

    let t0 = unix_now_secs() as i64;
    {
        let mut store = WebhookDedupeStore::open(&db_path).expect("open db");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&db_path)
                .expect("stat db")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(!store.is_delivered("hook-a", &dm_key, t0).expect("query"));
        store
            .mark_delivered(
                "hook-a",
                &[dm_key.clone(), grp_key.clone(), m_key.clone()],
                t0,
            )
            .expect("commit");
    }

    let mut reopened = WebhookDedupeStore::open(&db_path).expect("reopen db");
    assert!(reopened
        .is_delivered("hook-a", &dm_key, t0 + 60)
        .expect("dm"));
    assert!(reopened
        .is_delivered("hook-a", &grp_key, t0 + 60)
        .expect("grp"));
    assert!(reopened
        .is_delivered("hook-a", &m_key, t0 + 60)
        .expect("mention"));
    assert!(!reopened
        .is_delivered("hook-b", &dm_key, t0 + 60)
        .expect("isolated"));

    let after_7d = t0 + 7 * 86_400 + 1;
    assert!(!reopened
        .is_delivered("hook-a", &dm_key, after_7d)
        .expect("expired"));
    let pruned = reopened.prune_expired(after_7d).expect("prune");
    assert_eq!(pruned, 3);
}

#[test]
fn metadata_mode_omits_text_field_in_serialized_post_body() {
    let body = WebhookPostBody {
        source: "x0x".to_string(),
        version: 1,
        webhook: "meta".to_string(),
        agent_id: "aa".repeat(32),
        batch_id: "00000000-0000-0000-0000-000000000001".to_string(),
        sent_at: 1_732_698_000,
        rate_limited: false,
        items: vec![WebhookPayloadItem {
            kind: "dm".to_string(),
            from: "bb".repeat(32),
            from_name: None,
            group_id: None,
            topic: None,
            ts: 1_732_698_000_000,
            text: None,
            msg_id: None,
            flags: vec!["unknown_sender".to_string()],
        }],
    };
    let val = serde_json::to_value(&body).expect("serialize");
    let item = val["items"][0].as_object().expect("item object");
    assert!(!item.contains_key("text"));
    assert!(!item.contains_key("group_id"));
    assert!(!item.contains_key("topic"));
}

#[derive(Clone)]
struct CapturedPost {
    headers: HeaderMap,
    body: Bytes,
}

async fn start_capture_receiver() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<CapturedPost>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new()
        .route(
            "/hook/secret-path-id",
            post(
                |AxumState(tx): AxumState<mpsc::UnboundedSender<CapturedPost>>,
                 headers: HeaderMap,
                 body: Bytes| async move {
                    let _ = tx.send(CapturedPost { headers, body });
                    StatusCode::OK
                },
            ),
        )
        .with_state(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let addr = listener.local_addr().expect("receiver addr");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, rx, task)
}

fn hermetic_daemon_config(
    root: &std::path::Path,
    plane: &str,
    webhooks: Vec<WebhookConfig>,
) -> DaemonConfig {
    let mut cfg: DaemonConfig = serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": plane
    }))
    .expect("daemon config");
    cfg.notify = NotifyConfig { webhook: webhooks };
    cfg
}

fn test_serve_options() -> ServeOptions {
    ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    }
}

fn verify_signed_post(
    post: &CapturedPost,
    expected_bearer: &str,
    signing_secret: &[u8],
) -> WebhookPostBody {
    let auth = post
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .expect("Authorization header");
    assert_eq!(auth, format!("Bearer {expected_bearer}"));

    let sig_header = post
        .headers
        .get("x-x0x-signature")
        .and_then(|v| v.to_str().ok())
        .expect("X-X0x-Signature header");
    let mut parts = sig_header.split(',');
    let t_part = parts.next().expect("t part");
    let v1_part = parts.next().expect("v1 part");
    let ts: u64 = t_part
        .strip_prefix("t=")
        .expect("t= prefix")
        .parse()
        .expect("unix ts");
    let sig_hex = v1_part.strip_prefix("v1=").expect("v1= prefix");
    let expected = sign_payload(signing_secret, ts, &post.body);
    assert_eq!(sig_header, expected);
    assert_eq!(sig_hex.len(), 64);

    serde_json::from_slice(&post.body).expect("valid webhook JSON body")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhook_dm_mention_restart_dedupe_end_to_end() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bearer_val = "cursor-bearer-top-secret-value";
    let signing_val = "hmac-signing-top-secret-value";
    let bearer_file =
        write_secret_file(tmp.path(), "bearer.tok", &format!("{bearer_val}\n"), 0o600);
    let signing_file = write_secret_file(
        tmp.path(),
        "signing.sec",
        &format!("{signing_val}\n"),
        0o600,
    );

    let (recv_addr, mut posts, recv_task) = start_capture_receiver().await;
    let sender_agent = AgentId([0x77; 32]);
    let sender_machine = MachineId([0x88; 32]);
    let sender_hex = hex::encode(sender_agent.as_bytes());

    let webhook_cfg = WebhookConfig {
        name: "feynman".to_string(),
        url: format!("http://{recv_addr}/hook/secret-path-id"),
        allowed_hosts: vec!["127.0.0.1".to_string()],
        bearer_token_file: Some(bearer_file),
        signing_secret_file: Some(signing_file),
        events: vec!["dm".to_string(), "mention".to_string()],
        dm_allowlist: vec![sender_hex.clone()],
        fast_window_ms: 80,
        batch_window_ms: 500,
        max_per_hour: 20,
        max_per_day: 100,
        body_mode: WebhookBodyMode::Full,
        max_text_chars: 2000,
        allow_insecure_loopback_for_test: true,
    };

    let plane = format!("x0x.test.webhook.e2e.{}", std::process::id());
    let cfg1 = hermetic_daemon_config(tmp.path(), &plane, vec![webhook_cfg.clone()]);
    let handle = serve_with_options(cfg1, test_serve_options())
        .await
        .expect("serve daemon 1");
    let state = handle.test_state.upgrade().expect("live state");

    tokio::time::sleep(Duration::from_millis(80)).await;

    let dm_payload = b"hello from verified peer".to_vec();
    let dm_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    if let Some(history) = state.agent.history() {
        history.record(HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(None, &dm_payload),
            scope: Scope::Dm(sender_hex.clone()),
            author_agent: Some(sender_hex.clone()),
            author_machine: Some(hex::encode(sender_machine.as_bytes())),
            author_pubkey: None,
            sent_at_ms: dm_ts,
            seen_at_ms: dm_ts,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload: dm_payload.clone(),
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance: Provenance::VerifiedEnvelope,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        });
    }
    state
        .agent
        .direct_messaging_for_test()
        .handle_incoming(sender_machine, sender_agent, dm_payload, true, None, None)
        .await;

    let dm_post = tokio::time::timeout(Duration::from_secs(3), posts.recv())
        .await
        .expect("dm webhook timeout")
        .expect("dm webhook post");
    let dm_body = verify_signed_post(&dm_post, bearer_val, signing_val.as_bytes());
    assert_eq!(dm_body.source, "x0x");
    assert_eq!(dm_body.version, 1);
    assert_eq!(dm_body.webhook, "feynman");
    assert!(!dm_body.rate_limited);
    assert_eq!(dm_body.items.len(), 1);
    assert_eq!(dm_body.items[0].kind, "dm");
    assert_eq!(dm_body.items[0].from, sender_hex);
    assert_eq!(
        dm_body.items[0].text.as_deref(),
        Some("hello from verified peer")
    );
    assert!(dm_body.items[0].flags.is_empty());

    assert!(state.ws_topics.read().await.is_empty());
    emit_mention_event(
        &state,
        MentionFrame {
            topic: "x0x.groups.public.g1".to_string(),
            group_id: "g1".to_string(),
            msg_id: "mention-msg-1".to_string(),
            author_agent_id: sender_hex.clone(),
            reason: "mention".to_string(),
            mentions: vec![hex::encode(state.agent.agent_id().as_bytes())],
            timestamp: 1_732_698_001_000,
            body: Some("@agent please review".to_string()),
        },
    )
    .await;

    let mention_post = tokio::time::timeout(Duration::from_secs(3), posts.recv())
        .await
        .expect("mention webhook timeout")
        .expect("mention webhook post");
    let mention_body = verify_signed_post(&mention_post, bearer_val, signing_val.as_bytes());
    assert_eq!(mention_body.items.len(), 1);
    assert_eq!(mention_body.items[0].kind, "mention");
    assert_eq!(
        mention_body.items[0].msg_id.as_deref(),
        Some("mention-msg-1")
    );
    assert_eq!(
        mention_body.items[0].text.as_deref(),
        Some("@agent please review")
    );

    drop(state);
    handle.shutdown_and_wait().await.expect("shutdown 1");

    let cfg2 = hermetic_daemon_config(tmp.path(), &plane, vec![webhook_cfg]);
    let handle2 = serve_with_options(cfg2, test_serve_options())
        .await
        .expect("serve daemon 2");
    let replay = tokio::time::timeout(Duration::from_millis(400), posts.recv()).await;
    assert!(
        replay.is_err(),
        "restart must not replay already delivered DM"
    );

    handle2.shutdown_and_wait().await.expect("shutdown 2");
    recv_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhook_shutdown_drain_cancels_hanging_receiver() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let hit = Arc::new(Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let hit_route = Arc::clone(&hit);
    let hits_route = Arc::clone(&hits);

    let app = Router::new().route(
        "/hang",
        post(move |_body: Bytes| {
            let hit = Arc::clone(&hit_route);
            let hits = Arc::clone(&hits_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                hit.notify_waiters();
                tokio::time::sleep(Duration::from_secs(30)).await;
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hanging server");
    let addr = listener.local_addr().expect("hanging addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let wh = WebhookConfig {
        name: "hang-test".to_string(),
        url: format!("http://{addr}/hang"),
        allowed_hosts: vec!["127.0.0.1".to_string()],
        events: vec!["mention".to_string()],
        fast_window_ms: 20,
        batch_window_ms: 200,
        max_per_hour: 10,
        max_per_day: 100,
        allow_insecure_loopback_for_test: true,
        ..WebhookConfig::default()
    };

    let plane = format!("x0x.test.webhook.hang.{}", std::process::id());
    let cfg = hermetic_daemon_config(tmp.path(), &plane, vec![wh]);
    let handle = serve_with_options(cfg, test_serve_options())
        .await
        .expect("serve daemon");
    let weak_state = handle.test_state.clone();
    let state = weak_state.upgrade().expect("live state");

    emit_mention_event(
        &state,
        MentionFrame {
            topic: "x0x.groups.public.g1".to_string(),
            group_id: "g1".to_string(),
            msg_id: "hang-msg".to_string(),
            author_agent_id: "99".repeat(32),
            reason: "mention".to_string(),
            mentions: vec![hex::encode(state.agent.agent_id().as_bytes())],
            timestamp: 1_732_698_002_000,
            body: Some("hang test".to_string()),
        },
    )
    .await;

    tokio::time::timeout(Duration::from_secs(3), hit.notified())
        .await
        .expect("hanging receiver received in-flight POST");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(state);

    let start = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), handle.shutdown_and_wait())
        .await
        .expect("shutdown completed without waiting on 30s receiver")
        .expect("shutdown Ok");
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "shutdown took too long: {:?}",
        start.elapsed()
    );
    assert!(
        weak_state.upgrade().is_none(),
        "AppState must drop cleanly after shutdown drain"
    );
    srv.abort();
}

#[tokio::test]
async fn webhook_diagnostics_enforces_owner_auth_and_redacts_secrets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bearer_val = "super-secret-bearer-token-do-not-leak";
    let signing_val = "super-secret-hmac-key-do-not-leak";
    let bearer_file = write_secret_file(tmp.path(), "b.tok", &format!("{bearer_val}\n"), 0o600);
    let signing_file = write_secret_file(tmp.path(), "s.sec", &format!("{signing_val}\n"), 0o600);

    let wh = WebhookConfig {
        name: "feynman".to_string(),
        url: "https://api2.cursor.sh/automations/webhook/secret-webhook-id-xyz".to_string(),
        allowed_hosts: vec!["api2.cursor.sh".to_string()],
        bearer_token_file: Some(bearer_file),
        signing_secret_file: Some(signing_file),
        events: vec!["dm".to_string()],
        ..WebhookConfig::default()
    };

    let plane = format!("x0x.test.webhook.diag.{}", std::process::id());
    let cfg = hermetic_daemon_config(tmp.path(), &plane, vec![wh]);
    let handle = serve_with_options(cfg, test_serve_options())
        .await
        .expect("serve daemon");
    let state = handle.test_state.upgrade().expect("live state");
    let router = handle.test_router.clone();
    let durable_token = state.api_token.clone();
    let session_token = state.sessions.issue();

    let (rider_plaintext, _) = state
        .rider_tokens
        .lock()
        .await
        .issue(
            "55".repeat(32),
            vec!["g1".to_string()],
            Some("rider".to_string()),
            3600,
            "dd".repeat(32),
            None,
            None,
            unix_now_secs(),
            vec!["gui:show".to_string()],
        )
        .await
        .expect("issue rider token");

    let resp_unauth = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/diagnostics/webhooks")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);

    let resp_rider = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/diagnostics/webhooks")
                .header("Authorization", format!("Bearer {rider_plaintext}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp_rider.status(), StatusCode::FORBIDDEN);

    let resp_session = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/diagnostics/webhooks")
                .header("Authorization", format!("Bearer {session_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp_session.status(), StatusCode::FORBIDDEN);

    let resp_owner = router
        .oneshot(
            Request::builder()
                .uri("/diagnostics/webhooks")
                .header("Authorization", format!("Bearer {durable_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp_owner.status(), StatusCode::OK);
    let raw = to_bytes(resp_owner.into_body(), 1024 * 64)
        .await
        .expect("body bytes");
    let raw_str = String::from_utf8(raw.to_vec()).expect("utf8");
    assert!(!raw_str.contains(bearer_val));
    assert!(!raw_str.contains(signing_val));
    assert!(!raw_str.contains("secret-webhook-id-xyz"));

    let json: serde_json::Value = serde_json::from_str(&raw_str).expect("json");
    assert_eq!(json["ok"], true);
    assert_eq!(json["enabled"], true);
    let entry = &json["webhooks"][0];
    assert_eq!(entry["name"], "feynman");
    assert_eq!(entry["url_host"], "api2.cursor.sh");
    assert_eq!(entry["active"], true);
    assert_eq!(entry["bearer_token_configured"], true);
    assert_eq!(entry["signing_secret_configured"], true);
    assert_eq!(
        entry["bearer_token_sha256_prefix"].as_str().map(str::len),
        Some(8)
    );
    assert_eq!(
        entry["signing_secret_sha256_prefix"].as_str().map(str::len),
        Some(8)
    );

    drop(state);
    handle.shutdown_and_wait().await.expect("shutdown");
}

#[test]
fn scheduler_expires_retryable_batch_and_persists_rate_cap_and_cursor() {
    let mut sched = WebhookScheduler::new(100, 1_000, 100, 100, 8);
    assert!(sched.enqueue(sample_item("r1", Lane::Fast, "dm", Some("retry")), 0));
    let mut t = 100u64;
    for attempt in 1..MAX_RETRYABLE_ATTEMPTS {
        let (batch, _) = sched.poll_ready(t);
        assert!(batch.is_some(), "attempt {attempt} should poll");
        let disp = sched.record_outcome(DeliveryOutcome::RetryableError(Some(429)), t, 0.5);
        assert!(matches!(
            disp,
            Some(BatchDisposition::RetryScheduled { attempts, .. }) if attempts == attempt
        ));
        t = sched.next_wakeup_ms(t).expect("next retry wakeup");
    }
    let (final_batch, _) = sched.poll_ready(t);
    assert!(final_batch.is_some());
    let disp = sched.record_outcome(DeliveryOutcome::RetryableError(Some(503)), t, 0.5);
    assert!(matches!(
        disp,
        Some(BatchDisposition::DroppedExpired {
            last_status: Some(503),
            attempts,
            item_count: 1,
            ..
        }) if attempts == MAX_RETRYABLE_ATTEMPTS
    ));
    assert_eq!(sched.queue_depth(), 0);

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("webhook_state.db");
    let now_ms = (unix_now_secs() as i64) * 1_000;
    {
        let mut store = WebhookDedupeStore::open(&db_path).expect("open");
        assert_eq!(
            store.init_or_get_cursor_ms("hook-a", now_ms).expect("init"),
            (now_ms, true)
        );
        store
            .mark_delivered_and_advance(
                "hook-a",
                &["k1".to_string()],
                now_ms / 1_000,
                Some(now_ms + 5_000),
            )
            .expect("advance");
        store.record_sent("hook-a", now_ms + 1_000).expect("sent 1");
        store.record_sent("hook-a", now_ms + 2_000).expect("sent 2");
    }

    let mut reopened = WebhookDedupeStore::open(&db_path).expect("reopen");
    assert_eq!(
        reopened
            .init_or_get_cursor_ms("hook-a", now_ms + 10_000)
            .expect("existing"),
        (now_ms + 5_000, false)
    );
    let persisted_sent = reopened
        .load_sent_timestamps("hook-a", now_ms + 10_000)
        .expect("load sent");
    assert_eq!(persisted_sent.len(), 2);

    let mut restarted = WebhookScheduler::new(100, 1_000, 2, 10, 8);
    restarted.seed_sent_timestamps(persisted_sent, (now_ms + 10_000) as u64);
    assert!(restarted.enqueue(
        sample_item("after-restart", Lane::Fast, "dm", Some("hi")),
        (now_ms + 10_000) as u64
    ));
    let (held, newly_rl) = restarted.poll_ready((now_ms + 10_200) as u64);
    assert!(
        held.is_none(),
        "persisted hourly cap must hold after restart"
    );
    assert!(newly_rl);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhook_first_enable_skips_preexisting_history_and_filters_dms() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (recv_addr, mut posts, recv_task) = start_capture_receiver().await;
    let allowed_agent = AgentId([0x41; 32]);
    let allowed_machine = MachineId([0x42; 32]);
    let allowed_hex = hex::encode(allowed_agent.as_bytes());
    let stranger_agent = AgentId([0x51; 32]);
    let stranger_machine = MachineId([0x52; 32]);
    let plane = format!("x0x.test.webhook.filter.{}", std::process::id());

    // Pre-seed a historical DM before the webhook is ever enabled.
    let cfg_no_wh = hermetic_daemon_config(tmp.path(), &plane, Vec::new());
    let handle0 = serve_with_options(cfg_no_wh, test_serve_options())
        .await
        .expect("serve daemon 0");
    let state0 = handle0.test_state.upgrade().expect("state0");
    let old_ts = (unix_now_secs() as i64 - 30) * 1_000;
    if let Some(history) = state0.agent.history() {
        let old_payload = b"pre-enable historical dm".to_vec();
        history
            .record_committed(HistoryRecord {
                msg_id: HistoryRecord::compute_msg_id(None, &old_payload),
                scope: Scope::Dm(allowed_hex.clone()),
                author_agent: Some(allowed_hex.clone()),
                author_machine: Some(hex::encode(allowed_machine.as_bytes())),
                author_pubkey: None,
                sent_at_ms: old_ts,
                seen_at_ms: old_ts,
                direction: Direction::Inbound,
                content_type: "text/plain".to_string(),
                payload: old_payload,
                signed_artifact: None,
                signature: None,
                sig_context: None,
                provenance: Provenance::VerifiedEnvelope,
                replace_key: None,
                thread_root: None,
                thread_parent: None,
                ingress_sender_agent: None,
                logical_request_id: None,
            })
            .await
            .expect("commit historical dm");
    }
    drop(state0);
    handle0.shutdown_and_wait().await.expect("shutdown 0");

    let wh = WebhookConfig {
        name: "filtered".to_string(),
        url: format!("http://{recv_addr}/hook/secret-path-id"),
        allowed_hosts: vec!["127.0.0.1".to_string()],
        events: vec!["dm".to_string()],
        dm_allowlist: vec![allowed_hex.clone()],
        fast_window_ms: 60,
        batch_window_ms: 200,
        max_per_hour: 20,
        max_per_day: 100,
        allow_insecure_loopback_for_test: true,
        ..WebhookConfig::default()
    };
    let cfg1 = hermetic_daemon_config(tmp.path(), &plane, vec![wh]);
    let handle1 = serve_with_options(cfg1, test_serve_options())
        .await
        .expect("serve daemon 1");
    let state1 = handle1.test_state.upgrade().expect("state1");

    // Pre-enable history must NOT be replayed on first enable.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), posts.recv())
            .await
            .is_err(),
        "first enable must not backfill pre-enable history"
    );

    // Unverified DM from allowlisted sender must be dropped.
    state1
        .agent
        .direct_messaging_for_test()
        .handle_incoming(
            allowed_machine,
            allowed_agent,
            b"unverified dm".to_vec(),
            false,
            None,
            None,
        )
        .await;

    // Verified DM from non-allowlisted stranger must be dropped.
    state1
        .agent
        .direct_messaging_for_test()
        .handle_incoming(
            stranger_machine,
            stranger_agent,
            b"stranger dm".to_vec(),
            true,
            None,
            None,
        )
        .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(300), posts.recv())
            .await
            .is_err(),
        "unverified and non-allowlisted DMs must be dropped"
    );

    // Verified DM from allowlisted sender must be delivered.
    state1
        .agent
        .direct_messaging_for_test()
        .handle_incoming(
            allowed_machine,
            allowed_agent,
            b"allowed verified dm".to_vec(),
            true,
            None,
            None,
        )
        .await;

    let delivered = tokio::time::timeout(Duration::from_secs(3), posts.recv())
        .await
        .expect("allowed dm timeout")
        .expect("allowed dm post");
    let body: WebhookPostBody = serde_json::from_slice(&delivered.body).expect("json");
    assert_eq!(body.items.len(), 1);
    assert_eq!(body.items[0].from, allowed_hex);
    assert_eq!(body.items[0].text.as_deref(), Some("allowed verified dm"));

    drop(state1);
    handle1.shutdown_and_wait().await.expect("shutdown 1");
    recv_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webhook_retries_429_and_408_and_drops_forged_group_messages() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_route = Arc::clone(&attempts);
    let (tx, mut posts) = mpsc::unbounded_channel::<CapturedPost>();

    let app = Router::new().route(
        "/flaky",
        post(move |headers: HeaderMap, body: Bytes| {
            let attempts = Arc::clone(&attempts_route);
            let tx = tx.clone();
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    StatusCode::TOO_MANY_REQUESTS
                } else if n == 1 {
                    StatusCode::REQUEST_TIMEOUT
                } else {
                    let _ = tx.send(CapturedPost { headers, body });
                    StatusCode::OK
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind flaky receiver");
    let addr = listener.local_addr().expect("flaky addr");
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let forged_group_id = "forged-group-test-id".to_string();
    let wh = WebhookConfig {
        name: "retry-and-forged".to_string(),
        url: format!("http://{addr}/flaky"),
        allowed_hosts: vec!["127.0.0.1".to_string()],
        events: vec!["mention".to_string(), format!("group:{forged_group_id}")],
        fast_window_ms: 40,
        batch_window_ms: 40,
        max_per_hour: 20,
        max_per_day: 100,
        allow_insecure_loopback_for_test: true,
        ..WebhookConfig::default()
    };

    let plane = format!("x0x.test.webhook.retry.{}", std::process::id());
    let cfg = hermetic_daemon_config(tmp.path(), &plane, vec![wh]);
    let handle = serve_with_options(cfg, test_serve_options())
        .await
        .expect("serve daemon");
    let state = handle.test_state.upgrade().expect("live state");

    // Publish a forged GroupPublicMessage directly on the raw public topic;
    // webhooks consume the post-validation ingest tee, so it must never fire.
    let forged = serde_json::json!({
        "group_id": forged_group_id,
        "author_agent_id": "cc".repeat(32),
        "author_public_key": "",
        "body": "spoofed author message",
        "timestamp": unix_now_secs() * 1_000,
        "signature": "00".repeat(64),
        "kind": "chat"
    });
    let _ = state
        .agent
        .publish(
            &crate::groups::public_topic_for(&forged_group_id),
            serde_json::to_vec(&forged).expect("forged json"),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "forged group message must never trigger webhook delivery"
    );

    // Emit a valid mention and verify 429 + 408 are retried until 200 succeeds.
    emit_mention_event(
        &state,
        MentionFrame {
            topic: "x0x.groups.public.g1".to_string(),
            group_id: "g1".to_string(),
            msg_id: "retry-mention-1".to_string(),
            author_agent_id: "66".repeat(32),
            reason: "mention".to_string(),
            mentions: vec![hex::encode(state.agent.agent_id().as_bytes())],
            timestamp: unix_now_secs() * 1_000,
            body: Some("please retry 429/408".to_string()),
        },
    )
    .await;

    let delivered = tokio::time::timeout(Duration::from_secs(12), posts.recv())
        .await
        .expect("429/408 retry must eventually succeed")
        .expect("delivered post");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    let body: WebhookPostBody = serde_json::from_slice(&delivered.body).expect("json");
    assert_eq!(body.items.len(), 1);
    assert_eq!(body.items[0].msg_id.as_deref(), Some("retry-mention-1"));

    drop(state);
    handle.shutdown_and_wait().await.expect("shutdown");
    srv.abort();
}
