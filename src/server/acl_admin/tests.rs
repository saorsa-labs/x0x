//! ADR-0070 §5 slice-2 intent tests for the ACL overlay manager.
//!
//! Each test states WHY the behaviour matters; together they pin: API add
//! reaches the effective ACL and survives restart, the TOML floor cannot be
//! removed via the API, a malformed or widening reload keeps the last good
//! ACL, API entries are validated exactly like TOML entries, and an owner
//! entry only matches owner-trusted pairs (slice 1).

use super::*;
use std::net::SocketAddr;
use x0x::exec::acl::{parse_agent_id, parse_machine_id, PrincipalMatch};

fn hex32(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn ids(agent: u8, machine: u8) -> (x0x::identity::AgentId, x0x::identity::MachineId) {
    (
        parse_agent_id(&hex32(agent)).expect("agent id"),
        parse_machine_id(&hex32(machine)).expect("machine id"),
    )
}

fn target(raw: &str) -> SocketAddr {
    raw.parse().expect("socket addr")
}

fn connect_floor_toml(extra: &str) -> String {
    format!(
        "[connect]\nenabled = true\n[[connect.allow]]\nagent_id = \"{}\"\nmachine_id = \"{}\"\n\
         targets = [\"127.0.0.1:22\"]\n{extra}",
        hex32(0xaa),
        hex32(0xbb)
    )
}

fn exec_floor_toml(dir: &Path, audit: &str) -> String {
    format!(
        "[exec]\nenabled = true\naudit_log_path = \"{}\"\n[[exec.allow]]\nagent_id = \"{}\"\n\
         machine_id = \"{}\"\n[[exec.allow.commands]]\nargv = [\"uptime\"]\n",
        dir.join(audit).display(),
        hex32(0xaa),
        hex32(0xbb)
    )
}

struct Fixture {
    dir: tempfile::TempDir,
    connect_path: PathBuf,
    exec_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let connect_path = dir.path().join("connect-acl.toml");
        let exec_path = dir.path().join("exec-acl.toml");
        std::fs::write(&connect_path, connect_floor_toml("")).expect("write connect floor");
        std::fs::write(&exec_path, exec_floor_toml(dir.path(), "exec.log"))
            .expect("write exec floor");
        Self {
            dir,
            connect_path,
            exec_path,
        }
    }

    /// Simulate daemon startup: load both floors, then the overlays.
    async fn start(&self) -> AclAdmin {
        let connect =
            x0x::connect::load_connect_policy(Some(&self.connect_path), LoadMode::ExplicitPath)
                .await
                .expect("connect floor");
        let exec = x0x::exec::load_exec_policy(Some(&self.exec_path), LoadMode::ExplicitPath)
            .await
            .expect("exec floor");
        AclAdmin::load(self.dir.path(), connect, exec).await
    }

    fn overlay_path(&self, plane: &str) -> PathBuf {
        self.dir
            .path()
            .join(OVERLAY_DIR)
            .join(format!("{plane}-overlay.json"))
    }
}

fn connect_allowed(policy: &Arc<ConnectPolicy>, agent: u8, machine: u8, raw: &str) -> bool {
    let ConnectPolicy::Enabled(acl) = policy.as_ref() else {
        return false;
    };
    let (a, m) = ids(agent, machine);
    acl.is_allowed(&a, &m, &target(raw))
}

fn exec_allowed(policy: &Arc<ExecPolicy>, agent: u8, machine: u8, argv: &[&str]) -> bool {
    let ExecPolicy::Enabled(acl) = policy.as_ref() else {
        return false;
    };
    let (a, m) = ids(agent, machine);
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
    acl.match_command(&a, &m, &argv).is_some()
}

fn connect_pair(agent: u8, machine: u8, raw: &str) -> ConnectAclEntrySpec {
    ConnectAclEntrySpec {
        description: Some("api test".to_string()),
        principal: None,
        agent_id: Some(hex32(agent)),
        machine_id: Some(hex32(machine)),
        targets: vec![raw.to_string()],
    }
}

fn exec_pair(agent: u8, machine: u8, argv: &[&str]) -> ExecAclEntrySpec {
    ExecAclEntrySpec {
        description: None,
        principal: None,
        agent_id: Some(hex32(agent)),
        machine_id: Some(hex32(machine)),
        max_duration_secs: None,
        commands: vec![x0x::exec::ExecAclCommandSpec {
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
        }],
    }
}

fn entry_ids(listing: &serde_json::Value, origin: &str) -> Vec<String> {
    listing["entries"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|e| e["origin"] == origin)
                .filter_map(|e| e["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// WHY (slice-2 intent "add via API, connect succeeds without restart;
/// delete, connect denied"): the API must change the policy the gate
/// consults immediately, and the change must persist — an entry that
/// vanished on restart would silently revoke access an operator granted.
#[tokio::test]
async fn api_connect_entry_is_effective_immediately_and_survives_restart() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    assert!(!connect_allowed(
        &admin.effective_connect().await,
        0xcc,
        0xdd,
        "127.0.0.1:8080"
    ));

    let added = admin
        .add_connect(connect_pair(0xcc, 0xdd, "127.0.0.1:8080"), false)
        .await
        .expect("add");
    assert_eq!(added["created"], serde_json::json!(true));
    let id = added["id"].as_str().expect("id").to_string();
    let effective = admin.effective_connect().await;
    assert!(connect_allowed(&effective, 0xcc, 0xdd, "127.0.0.1:8080"));
    assert!(
        connect_allowed(&effective, 0xaa, 0xbb, "127.0.0.1:22"),
        "the floor stays in force"
    );
    assert!(
        !connect_allowed(&effective, 0xcc, 0xdd, "127.0.0.1:22"),
        "targets stay exact"
    );

    // Re-adding the identical entry is idempotent.
    let again = admin
        .add_connect(connect_pair(0xcc, 0xdd, "127.0.0.1:8080"), false)
        .await
        .expect("re-add");
    assert_eq!(again["created"], serde_json::json!(false));
    assert_eq!(again["id"].as_str(), Some(id.as_str()));

    // Restart: a fresh load from the same data dir keeps the entry.
    drop(admin);
    let admin = fx.start().await;
    assert!(connect_allowed(
        &admin.effective_connect().await,
        0xcc,
        0xdd,
        "127.0.0.1:8080"
    ));
    assert_eq!(
        entry_ids(&admin.list_connect().await, "api"),
        vec![id.clone()]
    );

    // Delete: denied immediately and after restart.
    admin.remove_connect(&id).await.expect("remove");
    assert!(!connect_allowed(
        &admin.effective_connect().await,
        0xcc,
        0xdd,
        "127.0.0.1:8080"
    ));
    drop(admin);
    let admin = fx.start().await;
    assert!(!connect_allowed(
        &admin.effective_connect().await,
        0xcc,
        0xdd,
        "127.0.0.1:8080"
    ));
    assert_eq!(
        admin.remove_connect(&id).await,
        Err(AclAdminError::NotFound(format!(
            "no API-managed connect ACL entry with id {id}"
        )))
    );
}

/// WHY: same contract on the exec plane — an API entry is matched by the
/// argv allowlist at once, persists across restart, and removal denies.
#[tokio::test]
async fn api_exec_entry_is_effective_immediately_and_survives_restart() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    let added = admin
        .add_exec(exec_pair(0xcc, 0xdd, &["df", "-h"]), false)
        .await
        .expect("add");
    let id = added["id"].as_str().expect("id").to_string();
    let effective = admin.effective_exec().await;
    assert!(exec_allowed(&effective, 0xcc, 0xdd, &["df", "-h"]));
    assert!(!exec_allowed(&effective, 0xcc, 0xdd, &["df"]), "argv exact");
    assert!(
        exec_allowed(&effective, 0xaa, 0xbb, &["uptime"]),
        "floor kept"
    );

    drop(admin);
    let admin = fx.start().await;
    assert!(exec_allowed(
        &admin.effective_exec().await,
        0xcc,
        0xdd,
        &["df", "-h"]
    ));
    admin.remove_exec(&id).await.expect("remove");
    assert!(!exec_allowed(
        &admin.effective_exec().await,
        0xcc,
        0xdd,
        &["df", "-h"]
    ));
}

/// WHY (slice-2 intent "deleting a file-floor entry returns 409 and access
/// persists"): the operator's TOML is the floor; the API may only extend
/// it, never remove what the operator granted.
#[tokio::test]
async fn api_cannot_remove_a_floor_entry() {
    let fx = Fixture::new();
    let admin = fx.start().await;

    let floor_ids = entry_ids(&admin.list_connect().await, "file");
    assert_eq!(floor_ids.len(), 1, "one floor entry listed");
    let err = admin
        .remove_connect(&floor_ids[0])
        .await
        .expect_err("floor removal refused");
    assert!(matches!(err, AclAdminError::Conflict(_)), "{err}");
    assert!(connect_allowed(
        &admin.effective_connect().await,
        0xaa,
        0xbb,
        "127.0.0.1:22"
    ));

    let floor_ids = entry_ids(&admin.list_exec().await, "file");
    assert_eq!(floor_ids.len(), 1);
    let err = admin
        .remove_exec(&floor_ids[0])
        .await
        .expect_err("floor removal refused");
    assert!(matches!(err, AclAdminError::Conflict(_)), "{err}");
    assert!(exec_allowed(
        &admin.effective_exec().await,
        0xaa,
        0xbb,
        &["uptime"]
    ));
    // The operator's file is never rewritten.
    assert_eq!(
        std::fs::read_to_string(&fx.connect_path).expect("read floor"),
        connect_floor_toml("")
    );
}

/// WHY (slice-2 intent "a malformed reload keeps last-good and does not
/// widen access"; PR #896 decision 2): a typo in the operator's file must
/// never drop the ACL or open the plane. The error is surfaced, and a
/// later valid reload still applies.
#[tokio::test]
async fn malformed_or_widening_floor_reload_keeps_last_good_acl() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    admin
        .add_connect(connect_pair(0xcc, 0xdd, "127.0.0.1:8080"), false)
        .await
        .expect("add");
    let before = admin.effective_connect().await;

    // 1. Malformed TOML.
    std::fs::write(&fx.connect_path, "[connect\nenabled = tru").expect("corrupt floor");
    let report = admin.reload().await;
    assert!(!report.ok);
    assert!(!report.connect.ok);
    assert!(report.connect.error.is_some());
    assert!(report.exec.ok, "planes reload independently");
    let after = admin.effective_connect().await;
    assert!(Arc::ptr_eq(&before, &after), "last good ACL still active");
    assert!(connect_allowed(&after, 0xaa, 0xbb, "127.0.0.1:22"));
    assert!(connect_allowed(&after, 0xcc, 0xdd, "127.0.0.1:8080"));
    let listing = admin.list_connect().await;
    assert_eq!(listing["reload"]["reloads_failed"], serde_json::json!(1));
    assert!(listing["reload"]["last_error"].is_string(), "{listing}");

    // 2. Disabling the plane would lift the stream-accept constraint:
    //    refused, still enabled.
    std::fs::write(&fx.connect_path, "[connect]\nenabled = false\n").expect("disable floor");
    let report = admin.reload().await;
    assert!(!report.connect.ok, "enabled→disabled needs a restart");
    assert!(admin.effective_connect().await.enabled());

    // 3. An invalid (non-loopback) entry is refused like at startup.
    std::fs::write(
        &fx.connect_path,
        connect_floor_toml(&format!(
            "[[connect.allow]]\nagent_id = \"{}\"\nmachine_id = \"{}\"\n\
             targets = [\"10.0.0.1:22\"]\n",
            hex32(0x11),
            hex32(0x22)
        )),
    )
    .expect("invalid floor");
    assert!(!admin.reload().await.connect.ok);
    assert!(!connect_allowed(
        &admin.effective_connect().await,
        0x11,
        0x22,
        "10.0.0.1:22"
    ));

    // 4. A valid edit applies without restart and clears the error.
    std::fs::write(
        &fx.connect_path,
        connect_floor_toml(&format!(
            "[[connect.allow]]\nagent_id = \"{}\"\nmachine_id = \"{}\"\n\
             targets = [\"127.0.0.1:9000\"]\n",
            hex32(0x11),
            hex32(0x22)
        )),
    )
    .expect("valid floor");
    let report = admin.reload().await;
    assert!(report.ok, "{report:?}");
    let effective = admin.effective_connect().await;
    assert!(connect_allowed(&effective, 0x11, 0x22, "127.0.0.1:9000"));
    assert!(
        connect_allowed(&effective, 0xcc, 0xdd, "127.0.0.1:8080"),
        "API entries survive a floor reload"
    );
    let listing = admin.list_connect().await;
    assert_eq!(listing["reload"]["reloads_ok"], serde_json::json!(1));
    assert!(listing["reload"]["last_error"].is_null(), "{listing}");
}

/// WHY: overlay entries only ever ADD access, so a malformed overlay must
/// not take the daemon (and the owner's other agents) down: running on the
/// TOML floor alone is already fail-closed. The broken file must survive
/// untouched for the operator to inspect, the failure must be visible, and
/// API writes must be refused so a rewrite from memory cannot silently
/// replace it. A successful reload after the fix lifts the block.
#[tokio::test]
async fn malformed_overlay_at_startup_runs_on_floor_and_blocks_api_writes() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.dir.path().join(OVERLAY_DIR)).expect("overlay dir");
    let corrupt = b"{ not json";
    std::fs::write(fx.overlay_path("connect"), corrupt).expect("corrupt connect overlay");
    let invalid_entry = serde_json::json!({
        "version": 1,
        "entries": [{
            "added_at_unix_ms": 1,
            "entry": {
                "agent_id": hex32(0xcc),
                "machine_id": hex32(0xdd),
                "commands": [{ "argv": ["sh", "<CMD>"] }]
            }
        }]
    })
    .to_string();
    std::fs::write(fx.overlay_path("exec"), &invalid_entry).expect("invalid exec overlay");

    // The daemon ACL loads (no error path exists any more).
    let admin = fx.start().await;

    // Effective ACL == the floor, entry for entry.
    let floor_connect =
        x0x::connect::load_connect_policy(Some(&fx.connect_path), LoadMode::ExplicitPath)
            .await
            .expect("floor");
    let ConnectPolicy::Enabled(floor_acl) = &floor_connect else {
        panic!("floor enabled");
    };
    let ConnectPolicy::Enabled(effective) = &*admin.effective_connect().await else {
        panic!("connect stays enabled on the floor");
    };
    assert_eq!(effective.entry_specs(), floor_acl.entry_specs());
    let ExecPolicy::Enabled(exec_effective) = &*admin.effective_exec().await else {
        panic!("exec stays enabled on the floor");
    };
    assert_eq!(exec_effective.entry_specs().len(), 1, "floor entry only");
    assert!(!exec_allowed(
        &admin.effective_exec().await,
        0xcc,
        0xdd,
        &["sh", "x"]
    ));

    // Surfaced: error + counter in the status that feeds /diagnostics.
    for listing in [admin.list_connect().await, admin.list_exec().await] {
        assert_eq!(listing["reload"]["overlay_load_failures"], 1, "{listing}");
        assert!(listing["reload"]["overlay_error"].is_string(), "{listing}");
    }

    // API writes refused; the files are byte-for-byte untouched.
    for result in [
        admin
            .add_connect(connect_pair(0x11, 0x22, "127.0.0.1:9000"), false)
            .await,
        admin.remove_connect("api-0011223344556677").await,
        admin.add_exec(exec_pair(0x11, 0x22, &["id"]), false).await,
        admin.remove_exec("api-0011223344556677").await,
    ] {
        assert!(
            matches!(result, Err(AclAdminError::Conflict(_))),
            "{result:?}"
        );
    }
    assert_eq!(
        std::fs::read(fx.overlay_path("connect")).expect("read"),
        corrupt
    );
    assert_eq!(
        std::fs::read_to_string(fx.overlay_path("exec")).expect("read"),
        invalid_entry
    );

    // A reload that still sees the broken file keeps blocking writes.
    let report = admin.reload().await;
    assert!(!report.connect.ok && !report.exec.ok);
    assert!(admin
        .add_connect(connect_pair(0x11, 0x22, "127.0.0.1:9000"), false)
        .await
        .is_err());

    // Operator moves the connect file aside and reloads: writes resume.
    std::fs::remove_file(fx.overlay_path("connect")).expect("move aside");
    let report = admin.reload().await;
    assert!(report.connect.ok, "{report:?}");
    admin
        .add_connect(connect_pair(0x11, 0x22, "127.0.0.1:9000"), false)
        .await
        .expect("writes allowed after a successful reload");
    assert!(admin.list_connect().await["reload"]["overlay_error"].is_null());
}

/// WHY: an overlay corrupted while the daemon runs must be rejected on
/// reload with the last good ACL kept, and must block API writes so the
/// in-memory copy never overwrites the file under inspection.
#[tokio::test]
async fn malformed_overlay_on_reload_keeps_last_good_and_blocks_writes() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    admin
        .add_exec(exec_pair(0xcc, 0xdd, &["df", "-h"]), false)
        .await
        .expect("add");
    let before = admin.effective_exec().await;
    std::fs::write(fx.overlay_path("exec"), b"{ not json").expect("corrupt overlay");
    let report = admin.reload().await;
    assert!(!report.exec.ok);
    assert!(Arc::ptr_eq(&before, &admin.effective_exec().await));
    assert_eq!(report.exec.status.overlay_load_failures, 1);
    assert!(matches!(
        admin.add_exec(exec_pair(0x11, 0x22, &["id"]), false).await,
        Err(AclAdminError::Conflict(_))
    ));
    assert_eq!(
        std::fs::read(fx.overlay_path("exec")).expect("read"),
        b"{ not json"
    );
}

/// WHY: "validate every entry exactly as the TOML parser does" — the API
/// is not a side door around the loopback-only / exact-argv / principal
/// rules, and a refused entry leaves nothing on disk.
#[tokio::test]
async fn api_entries_are_validated_like_toml_entries() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    let mut non_loopback = connect_pair(0xcc, 0xdd, "10.0.0.1:22");
    let err = admin
        .add_connect(non_loopback.clone(), false)
        .await
        .expect_err("non-loopback refused");
    assert!(matches!(err, AclAdminError::BadRequest(_)), "{err}");
    non_loopback.targets = vec!["localhost:22".to_string()];
    assert!(admin.add_connect(non_loopback, false).await.is_err());

    let mut mixed = connect_pair(0xcc, 0xdd, "127.0.0.1:22");
    mixed.principal = Some("owner".to_string());
    assert!(matches!(
        admin.add_connect(mixed, true).await,
        Err(AclAdminError::BadRequest(_))
    ));
    let mut grant = connect_pair(0xcc, 0xdd, "127.0.0.1:22");
    grant.principal = Some("grant".to_string());
    grant.agent_id = None;
    grant.machine_id = None;
    assert!(matches!(
        admin.add_connect(grant, true).await,
        Err(AclAdminError::BadRequest(_))
    ));

    let shell = exec_pair(0xcc, 0xdd, &["sh", "<CMD>"]);
    assert!(matches!(
        admin.add_exec(shell, false).await,
        Err(AclAdminError::BadRequest(_))
    ));
    let mut empty = exec_pair(0xcc, 0xdd, &["id"]);
    empty.commands.clear();
    assert!(matches!(
        admin.add_exec(empty, false).await,
        Err(AclAdminError::BadRequest(_))
    ));

    assert!(!fx.overlay_path("connect").exists());
    assert!(!fx.overlay_path("exec").exists());
}

/// WHY (PR #896 decision 1 + ADR-0070 §1): owner trust opens connect/exec
/// only through an explicit `principal = "owner"` entry, the API can add
/// one only on an install that has an owner, and the entry matches only
/// pairs slice 1 established as owner-trusted.
#[tokio::test]
async fn api_owner_entry_needs_owner_identity_and_matches_only_owner_trusted_pairs() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    let owner_connect = ConnectAclEntrySpec {
        description: None,
        principal: Some("owner".to_string()),
        agent_id: None,
        machine_id: None,
        targets: vec!["127.0.0.1:2222".to_string()],
    };
    let err = admin
        .add_connect(owner_connect.clone(), false)
        .await
        .expect_err("ownerless install refused");
    assert!(matches!(err, AclAdminError::Conflict(_)), "{err}");
    assert!(!fx.overlay_path("connect").exists());

    admin
        .add_connect(owner_connect, true)
        .await
        .expect("owned install");
    let ConnectPolicy::Enabled(acl) = &*admin.effective_connect().await else {
        panic!("connect stays enabled");
    };
    let (a, m) = ids(0x77, 0x88);
    let t = target("127.0.0.1:2222");
    assert!(acl.is_allowed_for_principal(&a, &m, true, &t));
    assert!(
        !acl.is_allowed_for_principal(&a, &m, false, &t),
        "not owner-trusted ⇒ the owner entry does not match"
    );
    assert!(!acl.is_allowed(&a, &m, &t), "exact-pair API never sees it");

    let owner_exec = ExecAclEntrySpec {
        description: None,
        principal: Some("owner".to_string()),
        agent_id: None,
        machine_id: None,
        max_duration_secs: None,
        commands: vec![x0x::exec::ExecAclCommandSpec {
            argv: vec!["uptime".to_string()],
        }],
    };
    admin.add_exec(owner_exec, true).await.expect("owner exec");
    let ExecPolicy::Enabled(acl) = &*admin.effective_exec().await else {
        panic!("exec stays enabled");
    };
    let argv = vec!["uptime".to_string()];
    assert!(matches!(
        acl.match_command_for_principal(&a, &m, true, &argv),
        Some(PrincipalMatch::Owner(_))
    ));
    assert!(acl
        .match_command_for_principal(&a, &m, false, &argv)
        .is_none());
}

/// WHY: API entries extend an enabled floor only; they can never turn on a
/// plane the operator left disabled (default-closed stays default-closed).
#[tokio::test]
async fn disabled_floor_refuses_api_entries() {
    let fx = Fixture::new();
    std::fs::write(&fx.connect_path, "[connect]\nenabled = false\n").expect("disabled");
    let admin = fx.start().await;
    let err = admin
        .add_connect(connect_pair(0xcc, 0xdd, "127.0.0.1:22"), false)
        .await
        .expect_err("disabled plane");
    assert!(matches!(err, AclAdminError::Conflict(_)), "{err}");
    assert!(!admin.effective_connect().await.enabled());
}

/// WHY: the exec audit sink is bound at service start; a reload that moved
/// it would silently keep auditing to the old file, so it is refused.
#[tokio::test]
async fn exec_reload_refuses_an_audit_sink_change() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    std::fs::write(&fx.exec_path, exec_floor_toml(fx.dir.path(), "moved.log")).expect("move audit");
    let report = admin.reload().await;
    assert!(!report.exec.ok);
    let ExecPolicy::Enabled(acl) = &*admin.effective_exec().await else {
        panic!("exec stays enabled");
    };
    assert_eq!(acl.audit_log_path, fx.dir.path().join("exec.log"));
}

/// WHY: the overlay is additive only, which is what makes the floor-only
/// fallback for a bad overlay safe: dropping the overlay can only REMOVE
/// access, never widen it. For a floor F and overlay O,
/// effective(F, O) ⊇ effective(F, ∅), and effective(F, ∅) is exactly F. No
/// overlay entry (even one naming the same pair with other targets) can
/// narrow, override or remove a floor entry, and no "deny" entry type
/// exists.
#[tokio::test]
async fn overlay_is_additive_only_so_floor_fallback_never_widens() {
    let fx = Fixture::new();
    let connect_floor =
        x0x::connect::load_connect_policy(Some(&fx.connect_path), LoadMode::ExplicitPath)
            .await
            .expect("floor");
    let ConnectPolicy::Enabled(f) = &connect_floor else {
        panic!("floor enabled");
    };
    // O includes an entry for the SAME pair as the floor entry with a
    // different target, plus an owner entry.
    let overlay = vec![
        connect_pair(0xaa, 0xbb, "127.0.0.1:8080"),
        connect_pair(0xcc, 0xdd, "127.0.0.1:9000"),
        ConnectAclEntrySpec {
            description: None,
            principal: Some("owner".to_string()),
            agent_id: None,
            machine_id: None,
            targets: vec!["127.0.0.1:2222".to_string()],
        },
    ];
    let base = x0x::connect::compose_connect_policy(&connect_floor, &[]).expect("F+0");
    let full = x0x::connect::compose_connect_policy(&connect_floor, &overlay).expect("F+O");
    let (ConnectPolicy::Enabled(base), ConnectPolicy::Enabled(full)) = (&base, &full) else {
        panic!("both enabled");
    };
    assert_eq!(base.entry_specs(), f.entry_specs(), "effective(F, ∅) == F");
    let full_specs = full.entry_specs();
    for spec in base.entry_specs() {
        assert!(
            full_specs.contains(&spec),
            "floor entry kept verbatim: {spec:?}"
        );
    }
    // Every access effective(F, ∅) grants, effective(F, O) still grants.
    let (a, m) = ids(0xaa, 0xbb);
    let t = target("127.0.0.1:22");
    assert!(base.is_allowed(&a, &m, &t));
    assert!(
        full.is_allowed(&a, &m, &t),
        "overlay did not narrow the floor"
    );
    // No deny/negative selector exists in the schema.
    for principal in ["deny", "!owner", "none"] {
        let mut spec = connect_pair(0xaa, 0xbb, "127.0.0.1:22");
        spec.principal = Some(principal.to_string());
        spec.agent_id = None;
        spec.machine_id = None;
        assert!(x0x::connect::compose_connect_policy(&connect_floor, &[spec]).is_err());
    }

    // Same property on the exec plane.
    let exec_floor = x0x::exec::load_exec_policy(Some(&fx.exec_path), LoadMode::ExplicitPath)
        .await
        .expect("exec floor");
    let exec_overlay = vec![exec_pair(0xaa, 0xbb, &["df", "-h"])];
    let base = x0x::exec::compose_exec_policy(&exec_floor, &[]).expect("F+0");
    let full = x0x::exec::compose_exec_policy(&exec_floor, &exec_overlay).expect("F+O");
    let (ExecPolicy::Enabled(f), ExecPolicy::Enabled(base), ExecPolicy::Enabled(full)) =
        (&exec_floor, &base, &full)
    else {
        panic!("enabled");
    };
    assert_eq!(base.entry_specs(), f.entry_specs());
    let full_specs = full.entry_specs();
    for spec in base.entry_specs() {
        assert!(full_specs.contains(&spec));
    }
    let argv = vec!["uptime".to_string()];
    assert!(
        full.match_command(&a, &m, &argv).is_some(),
        "floor argv kept"
    );
}

/// WHY: the overlay is authorization state; like the key files it must be
/// owner-only on disk, and a crash mid-write must never leave a torn file
/// that would (now) silently drop every API grant at the next start.
#[tokio::test]
async fn overlay_writes_are_private_and_atomic() {
    let fx = Fixture::new();
    let admin = fx.start().await;
    admin
        .add_connect(connect_pair(0xcc, 0xdd, "127.0.0.1:8080"), false)
        .await
        .expect("add");
    let path = fx.overlay_path("connect");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "overlay file is 0600");
        let dir_mode = std::fs::metadata(fx.dir.path().join(OVERLAY_DIR))
            .expect("stat dir")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "overlay dir is 0700");
    }
    let good = std::fs::read(&path).expect("read overlay");

    // Simulate a write interrupted before the rename: a stray temp file
    // with partial bytes next to the real overlay.
    let stray = fx
        .dir
        .path()
        .join(OVERLAY_DIR)
        .join(".connect-overlay.json.99999.0.tmp");
    std::fs::write(&stray, b"{\"version\":1,\"entr").expect("stray temp");
    drop(admin);

    let admin = fx.start().await;
    assert_eq!(
        std::fs::read(&path).expect("read"),
        good,
        "previous overlay intact"
    );
    assert!(connect_allowed(
        &admin.effective_connect().await,
        0xcc,
        0xdd,
        "127.0.0.1:8080"
    ));
    assert!(admin.list_connect().await["reload"]["overlay_error"].is_null());
}
