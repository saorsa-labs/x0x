//! The released-binary harness for the ADR 0109 §10 H-S3-rm rows (#1572).
//!
//! Phase 1 runs the H-S3-c prefix (with M1) on the paused sim, stops each
//! node gracefully and copies its data and identity dirs. Phase 2 runs on
//! real loopback sockets on a new plane: candidate nodes run in-process on
//! the copies ([`serve_real`]), and the released v0.46.1 `x0xd` runs as a
//! child process ([`Released`]). A missing prerequisite is INFRA.

use super::*;
use std::path::{Path, PathBuf};

const STOP_ORDER: &[&str] = &["J", "M1", "X", "A", "O"];
/// A's verified advert cache lifetime (src/dm_capability.rs:81).
pub(super) const ADVERT_TTL: Duration =
    Duration::from_secs(crate::dm_capability::ADVERT_CACHE_TTL_SECS);
const ADVERT_WAIT: Duration = Duration::from_secs(120);

/// The setup checks and the row checks of phase 2.
pub(super) type Checks = (Vec<(&'static str, bool)>, Vec<(&'static str, bool)>);

/// What phase 1 leaves for phase 2.
pub(super) struct Exported {
    pub(super) group: String,
    pub(super) j_hex: String,
    pub(super) m_hex: String,
    /// O's head after it sealed J (r+2).
    pub(super) sealed: u64,
    /// The prefix and advance checks. They are setup: a failure is INFRA.
    pub(super) checks: Vec<(&'static str, bool)>,
}

/// The released v0.46.1 `x0xd`, as `tests/h_s3_home_released.rs` finds
/// it: `X0X_V0461_BIN`, else the path that
/// `scripts/ci/prepare-released-h-s3-home.sh` installs. Fails closed.
pub(super) fn released_bin() -> Result<PathBuf> {
    let path = std::env::var("X0X_V0461_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/released-pinned/v0.46.1/x0xd")
        });
    ensure!(
        path.is_file(),
        "INFRA: released x0xd v0.46.1 is not prepared ({}). Run \
         scripts/ci/prepare-released-h-s3-home.sh, or set X0X_V0461_BIN.",
        path.display()
    );
    Ok(path)
}

pub(super) fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Phase 1 on the paused sim: the prefix, the advance, the stops and the
/// export into `out/<label>/{data,identity}`.
async fn export_prefix(
    sim: &mut Sim,
    receipt: &mut Receipt,
    out: &Path,
    last: &str,
) -> Result<Exported> {
    let p = fork_prefix(sim, receipt, false, true, last).await?;
    let p = p.context("INFRA: the H-S3-c prefix lacks a prerequisite")?;
    let window = (GATE_WINDOW, "not_on_chain");
    let adv = advance(sim, receipt, &p, false, window, last).await?;
    let adv = adv.context("INFRA: the advance lacks a prerequisite")?;
    let m_hex = sim.agent_hex("M1")?;
    for label in STOP_ORDER {
        sim.stop(label, RestartMode::Graceful).await?;
    }
    for label in STOP_ORDER {
        let data = sim.data_dir(label)?;
        let node = data.parent().context("a sim data dir has a parent")?;
        copy_tree(&data, &out.join(label).join("data"))?;
        copy_tree(&node.join("identity"), &out.join(label).join("identity"))?;
    }
    Ok(Exported {
        group: p.group.clone(),
        j_hex: p.j_hex.clone(),
        m_hex,
        sealed: p.sealed.state_revision,
        checks: advance_checks(&p, &adv, false),
    })
}

/// Run phase 1 for `case`, then build the phase 2 runtime. The returned
/// dir holds the copies.
pub(super) fn phase1(
    case: &str,
    seed: u64,
    last: &str,
    receipt: &mut Receipt,
) -> Result<(tempfile::TempDir, Exported, tokio::runtime::Runtime)> {
    let out = tempfile::tempdir()?;
    let exported = crate::server::w3h::block_on_paused(async {
        let mut sim = Sim::empty(case, seed, D3_LABELS)?;
        let exported = export_prefix(&mut sim, receipt, out.path(), last).await;
        if let Err(error) = sim.finish().await {
            receipt.infra(format!("finish: {error:#}"), 0);
        }
        exported
    })?;
    receipt.setup_done(0);
    crate::peer_evidence::set_w3h_inline_lookups(false);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    Ok((out, exported, runtime))
}

/// Finish the receipt from the setup checks and the row checks. A failed
/// row check is RED only when every setup check passed; else INFRA.
pub(super) fn conclude_checks(
    receipt: &mut Receipt,
    (last, cause): (&str, &str),
    setup: &[(&'static str, bool)],
    row: &[(&'static str, bool)],
) {
    let failing: Vec<&str> = setup
        .iter()
        .chain(row)
        .filter(|c| !c.1)
        .map(|c| c.0)
        .collect();
    let red = setup.iter().all(|c| c.1);
    conclude_row(
        receipt,
        (last, cause),
        &failing,
        format!("failing {failing:?}"),
        red,
        0,
    );
}

/// Run `body`, classify a returned error as INFRA, emit the receipt and
/// require GREEN.
pub(super) fn released_test(
    case: &str,
    seed: u64,
    last: &str,
    note: &str,
    body: impl FnOnce(&mut Receipt) -> Result<()>,
) -> Result<()> {
    let mut receipt = Receipt::new(case, seed);
    receipt.note(note);
    if let Err(error) = body(&mut receipt) {
        receipt.infra(format!("{error:#}"), 0);
    }
    if receipt.verdict().is_none() || receipt.has_infra() {
        receipt.reclassify(last);
    }
    receipt.emit();
    ensure!(
        receipt.verdict() == Some(Verdict::Green),
        "{case}: expected Green, got {:?}",
        receipt.verdict()
    );
    Ok(())
}

/// A candidate daemon on real loopback sockets.
pub(super) struct Real {
    handle: ServerHandle,
    pub(super) state: Arc<AppState>,
    pub(super) udp: SocketAddr,
}

/// Serve `dir`'s copies in-process on `plane`, with no bootstrap peers
/// (the case dials explicitly). `grace_days` sets `[groups]
/// mandate_grace_days` when it is given.
pub(super) async fn serve_real(dir: &Path, plane: &str, grace_days: Option<u64>) -> Result<Real> {
    let mut config = DaemonConfig {
        api_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
        data_dir: dir.join("data"),
        identity_dir: Some(dir.join("identity")),
        network_id: Some(plane.to_string()),
        bootstrap_peers: Some(Vec::new()),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..DaemonConfig::default()
    };
    config.api_watchdog.enabled = false;
    if let Some(days) = grace_days {
        config.groups.mandate_grace_days = days;
    }
    let options = ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    let handle = serve_with_options(config, options).await?;
    let state = handle.test_state.upgrade().context("state dropped")?;
    let network = state.agent.network().context("no network")?;
    let udp = network.bound_addr().await.context("no bound UDP address")?;
    Ok(Real { handle, state, udp })
}

impl Real {
    pub(super) async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(u16, Value)> {
        let base = format!("http://{}", self.handle.local_addr());
        http(&base, &self.state.api_token, method, path, body).await
    }

    /// Dial `to`, then announce this node's identity with its certificate.
    pub(super) async fn join(&self, to: SocketAddr) -> Result<()> {
        let network = self.state.agent.network().context("no network")?;
        network.connect_addr(to).await?;
        let body = json!({"include_user_identity": true, "human_consent": true});
        let (code, answer) = self.call(Method::POST, "/announce", Some(body)).await?;
        ensure!(code < 300, "INFRA: announce {code} {answer}");
        Ok(())
    }

    /// This node's record of `group` (as `try_view_now`, from the state).
    pub(super) async fn view(&self, group: &str) -> Result<View> {
        let (key, view) = {
            let groups = self.state.named_groups.read().await;
            let (key, info) = crate::server::resolve_group_entry_locked(&groups, group)
                .context("no record of the group")?;
            let lineage = info.invite_lineage.as_ref();
            let view = View {
                state_revision: info.state_revision,
                roster_revision: info.roster_revision,
                state_hash: info.state_hash.clone(),
                owner_axis: info.policy.admission.owner_certified_user_id().is_some(),
                active: info.active_members().map(|m| m.agent_id.clone()).collect(),
                marker: info.fork_quarantine.as_ref().map(|marker| Marker {
                    revision: marker.revision,
                    no_anchor: marker.no_anchor,
                    classification: marker.snapshot.classification.clone(),
                    committed_by: marker.committed_by.clone(),
                }),
                fork_evidence: lineage.is_some_and(|l| l.fork_evidence.is_some()),
                gap_refusal: lineage
                    .and_then(|l| l.anchored_gap_refusal.as_ref())
                    .map(|record| record.reason.clone()),
                base_revision: lineage.map(|l| l.base_revision),
                epoch: None,
            };
            (key.to_string(), view)
        };
        let live = self.state.treekem_groups.read().await.get(&key).cloned();
        let epoch = match live {
            Some(live) => Some(live.lock().await.epoch()),
            None => None,
        };
        Ok(View { epoch, ..view })
    }

    /// This node's verified advert state for `agent`'s mandate bit,
    /// refreshed each second until it is `want` or `ADVERT_WAIT` ends.
    pub(super) async fn advert(&self, agent: &str, want: bool) -> Result<Option<bool>> {
        let raw: [u8; 32] = hex::decode(agent)?.try_into().map_err(|_| anyhow!("id"))?;
        let (agent, bit) = (
            crate::identity::AgentId(raw),
            crate::dm::CapabilityRegistry::GROUP_RESEAT_MANDATE_V1,
        );
        let started = tokio::time::Instant::now();
        let store = self.state.agent.capability_store();
        loop {
            let seen = store.verified_registry_supports(&agent, bit);
            if seen == Some(want) || started.elapsed() > ADVERT_WAIT {
                return Ok(seen);
            }
            self.state
                .agent
                .refresh_application_capability(agent, bit)
                .await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub(super) async fn stop(self) -> Result<()> {
        let Real { handle, state, .. } = self;
        drop(state);
        handle.shutdown_and_wait().await
    }
}

async fn http(
    base: &str,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<(u16, Value)> {
    let client = reqwest::Client::new();
    let method = reqwest::Method::from_bytes(method.as_str().as_bytes())?;
    let mut request = client
        .request(method, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.timeout(Duration::from_secs(25)).send().await?;
    let code = response.status().as_u16();
    Ok((code, response.json().await.unwrap_or(Value::Null)))
}

/// The released v0.46.1 daemon as a child process on `dir`'s copies.
pub(super) struct Released {
    child: std::process::Child,
    base: String,
    token: String,
}

impl Released {
    /// Start the daemon with `bootstrap` as its one peer; `extra` is
    /// appended to its config file.
    pub(super) async fn start(
        bin: &Path,
        dir: &Path,
        plane: &str,
        bootstrap: SocketAddr,
        extra: &str,
    ) -> Result<Self> {
        let data = dir.join("data");
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?.local_addr()?;
        let config = dir.join("released.toml");
        std::fs::write(
            &config,
            format!(
                "bind_address = \"{udp}\"\napi_address = \"127.0.0.1:0\"\n\
                 data_dir = \"{}\"\nidentity_dir = \"{}\"\nnetwork_id = \"{plane}\"\n\
                 mdns_enabled = false\nport_mapping_enabled = false\n\
                 rendezvous_enabled = false\nbootstrap_peers = [\"{bootstrap}\"]\n\
                 [update]\nenabled = false\n{extra}",
                data.display(),
                dir.join("identity").display(),
            ),
        )?;
        let _ = std::fs::remove_file(data.join("api.port"));
        let child = std::process::Command::new(bin)
            .arg("--config")
            .arg(&config)
            .args([
                "--no-hard-coded-bootstrap",
                "--disable-peer-cache",
                "--skip-update-check",
            ])
            .env("HOME", dir)
            .env("X0X_HOME", dir)
            .stdout(std::fs::File::create(dir.join("released-stdout.log"))?)
            .stderr(std::fs::File::create(dir.join("released-stderr.log"))?)
            .spawn()?;
        let mut released = Self {
            child,
            base: String::new(),
            token: String::new(),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let api = loop {
            if let Some(status) = released.child.try_wait()? {
                let log = std::fs::read_to_string(dir.join("released-stderr.log"))?;
                bail!("INFRA: v0.46.1 exited {status} before its API: {log}");
            }
            let port = std::fs::read_to_string(data.join("api.port")).unwrap_or_default();
            if let Ok(api) = port.trim().parse::<SocketAddr>() {
                break api;
            }
            if tokio::time::Instant::now() > deadline {
                released.stop().await;
                bail!("INFRA: the v0.46.1 API did not come up");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        released.base = format!("http://{api}");
        released.token = std::fs::read_to_string(data.join("api-token"))?
            .trim()
            .to_string();
        let (code, answer) = released
            .call(Method::POST, "/announce", Some(json!({})))
            .await?;
        ensure!(code < 300, "INFRA: v0.46.1 announce {code} {answer}");
        Ok(released)
    }

    pub(super) async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(u16, Value)> {
        http(&self.base, &self.token, method, path, body).await
    }

    /// SIGTERM, then a kill after 20 s.
    pub(super) async fn stop(mut self) {
        let pid = self.child.id().to_string();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status();
        for _ in 0..100 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A row that ends early (`?` or a panic) does not call [`Released::stop`].
/// Kill the child here, so no released daemon outlives its row.
impl Drop for Released {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The SHA-256 of each S3 sidecar file under `dir`, and the issued re-seats
/// for `subject` they hold.
pub(super) fn sidecar_state(dir: &Path, subject: &str) -> Result<(Vec<(PathBuf, String)>, usize)> {
    use crate::groups::recovery::{decode_sidecar, GROUP_RECOVERY_EXTENSION};
    use sha2::Digest as _;
    let (mut dirs, mut files, mut issued) = (vec![dir.to_path_buf()], Vec::new(), 0);
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path
                .extension()
                .is_some_and(|e| e == GROUP_RECOVERY_EXTENSION)
            {
                let bytes = std::fs::read(&path)?;
                if let Ok(body) = decode_sidecar(&bytes) {
                    let subject = |i: &&crate::groups::recovery::IssuedReseatV1| {
                        i.authorisation.fields.subject.eq_ignore_ascii_case(subject)
                    };
                    issued += body.issued_reseats.iter().filter(subject).count();
                }
                files.push((path, hex::encode(sha2::Sha256::digest(&bytes))));
            }
        }
    }
    files.sort();
    Ok((files, issued))
}
