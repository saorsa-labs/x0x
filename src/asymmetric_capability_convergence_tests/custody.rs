//! Closed, optional test evidence. Absence never skips fixture assertions.
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::result::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) const SELECTOR: &str =
    "asymmetric_capability_convergence_tests::asymmetric_signed_capability_convergence_over_relay";
const LIMIT: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema: String,
    run_nonce: String,
    source_head: String,
    source_tree: String,
    selector: String,
}

fn hex_field(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn safe_directory(path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(m) if m.file_type().is_dir() => Ok(true),
        _ => Err("unsafe_directory"),
    }
}

fn file_options(read: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    options
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "input_missing")?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err("unsafe_input");
    }
    let file = file_options(true).open(path).map_err(|_| "input_open")?;
    if !file.metadata().map_err(|_| "input_metadata")?.is_file() {
        return Err("unsafe_input");
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_read")?;
    if bytes.len() > limit {
        return Err("input_oversize");
    }
    Ok(bytes)
}

fn exclusive(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = file_options(false)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "exclusive_create")?;
    file.write_all(bytes).map_err(|_| "output_write")?;
    file.sync_all().map_err(|_| "output_sync")
}

fn binary_hash() -> Result<String, &'static str> {
    let mut file = File::open(std::env::current_exe().map_err(|_| "binary_path")?)
        .map_err(|_| "binary_open")?;
    let mut hasher = Sha256::new();
    let mut block = [0; 8192];
    loop {
        let n = file.read(&mut block).map_err(|_| "binary_read")?;
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) struct Sink {
    root: PathBuf,
    pub(super) value: Value,
}

impl Sink {
    pub(super) fn activate(manifest: &Path) -> Result<Option<Self>, &'static str> {
        let parent = manifest.join("ci-evidence");
        if !safe_directory(&parent)? {
            return Ok(None);
        }
        let root = parent.join("issue442");
        if !safe_directory(&root)? {
            return Ok(None);
        }
        for entry in fs::read_dir(&root).map_err(|_| "directory_read")? {
            let entry = entry.map_err(|_| "directory_read")?;
            if !matches!(
                entry.file_name().to_str(),
                Some("descriptor.json" | "claim.json" | "phases.json" | "phases.tmp")
            ) {
                return Err("unknown_input");
            }
        }
        let descriptor = root.join("descriptor.json");
        match fs::symlink_metadata(&descriptor) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("descriptor_metadata"),
            Ok(_) => {}
        }
        // Prepared custody is supported only where exclusive no-follow opens
        // are implemented. Ordinary absent-descriptor invocation is unchanged.
        if !cfg!(unix) {
            return Err("unsupported_custody_platform");
        }
        let d: Descriptor = serde_json::from_slice(&read_regular(&descriptor, 1024)?)
            .map_err(|_| "descriptor_schema")?;
        if d.schema != "x0x.issue442-descriptor/1"
            || d.selector != SELECTOR
            || !hex_field(&d.run_nonce, 32)
            || !hex_field(&d.source_head, 40)
            || !hex_field(&d.source_tree, 40)
        {
            return Err("descriptor_identity");
        }
        for name in ["claim.json", "phases.json", "phases.tmp"] {
            match fs::symlink_metadata(root.join(name)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("already_claimed_or_stale"),
            }
        }
        let binary_sha256 = binary_hash()?;
        let claim = json!({"schema":"x0x.issue442-claim/1", "run_nonce":d.run_nonce,
            "selector":SELECTOR, "binary_sha256":binary_sha256});
        exclusive(
            &root.join("claim.json"),
            &serde_json::to_vec(&claim).map_err(|_| "claim_encode")?,
        )?;
        let mut sink = Self {
            root,
            value: json!({
                "schema":"x0x.issue442-phases/1", "run_nonce":d.run_nonce,
                "source_head":d.source_head, "source_tree":d.source_tree,
                "selector":SELECTOR, "binary_sha256":binary_sha256,
                "status":"started", "checkpoint":"entry", "topology":null,
                "preconditions": {"relay_inbox_ready":null,"relay_watch_held":null,"sender_has_relay_base":null,
                    "sender_has_relay_extension":null,"relay_has_sender_extension":null,"relay_has_sender_v2_baseline":null},
                "phases":{"legacy":null,"bound":null,"downgrade":null},
                "service_observation":null, "relay_observations":{"s":null,"r":null,"d":null}
            }),
        };
        sink.write("started", "entry")?;
        Ok(Some(sink))
    }

    pub(super) fn write(&mut self, status: &str, checkpoint: &str) -> Result<(), &'static str> {
        self.value["status"] = json!(status);
        self.value["checkpoint"] = json!(checkpoint);
        let bytes = serde_json::to_vec(&self.value).map_err(|_| "phase_encode")?;
        if bytes.len() > LIMIT {
            return Err("phase_oversize");
        }
        if !safe_directory(&self.root)? {
            return Err("output_directory_missing");
        }
        let final_path = self.root.join("phases.json");
        match fs::symlink_metadata(&final_path) {
            Ok(meta) if !meta.is_file() => return Err("unsafe_output"),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err("output_metadata"),
            _ => {}
        }
        let tmp = self.root.join("phases.tmp");
        exclusive(&tmp, &bytes)?;
        fs::rename(&tmp, final_path).map_err(|_| "output_rename")?;
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(|_| "directory_sync")
    }

    /// Finalize the last asserted observation payload after successful cleanup.
    /// Consuming the sink without observer inputs prevents a teardown recapture.
    pub(super) fn complete_after_cleanup(mut self) -> Result<(), &'static str> {
        self.write("completed", "cleanup")
    }

    pub(super) fn capture(
        &mut self,
        agents: &[Agent],
        service: Option<&dm_capability_service::ConvergenceServiceObserver>,
    ) {
        for (name, index) in [("s", 2), ("r", 0), ("d", 1)] {
            if let Some(agent) = agents.get(index) {
                self.value["relay_observations"][name] = relay_projection(agent.peer_relay());
            }
        }
        if let Some(service) = service {
            self.value["service_observation"] = match service.snapshot() {
                Ok(events) => {
                    json!({"overflow":false,"poisoned":false,"events":events.iter().map(service_event).collect::<Vec<_>>()})
                }
                Err("service observer overflow") => {
                    json!({"overflow":true,"poisoned":false,"events":[]})
                }
                Err(_) => json!({"overflow":false,"poisoned":true,"events":[]}),
            };
        }
    }
}

fn service_event(event: &dm_capability_service::ServiceEvent) -> Value {
    use dm_capability_service::ServiceEvent;
    match event {
        ServiceEvent::Consumed => json!({"kind":"consumed"}),
        ServiceEvent::PendingSkip => json!({"kind":"pending_skip"}),
        ServiceEvent::Enqueue {
            requester,
            carrier,
            payload_hash,
            accepted,
        } => json!({"kind":"enqueue",
            "requester":hex::encode(requester),"carrier":carrier,"payload_sha256":hex::encode(payload_hash),"accepted":accepted}),
    }
}

fn refusal(reason: RelayRefusal) -> &'static str {
    match reason {
        RelayRefusal::BadSignature => "bad_signature",
        RelayRefusal::InnerDigestMismatch => "inner_digest_mismatch",
        RelayRefusal::MissingInnerDigest => "missing_inner_digest",
        RelayRefusal::Stale => "stale",
        RelayRefusal::PolicyDisabled => "policy_disabled",
        RelayRefusal::NotAContact => "not_a_contact",
        RelayRefusal::Blocked => "blocked",
        RelayRefusal::RateLimited => "rate_limited",
        RelayRefusal::BandwidthExceeded => "bandwidth_exceeded",
    }
}

// Classification is observed before the production revocation gate. It is
// not a terminal action; forward counters and D decryption are separate evidence.
fn relay_projection(relay: &peer_relay::PeerRelay) -> Value {
    let view = match relay.convergence_snapshot() {
        Ok(view) => view,
        Err("observer disabled") => return Value::Null,
        Err(_) => {
            return json!({"overflow":false,"poisoned":true,"decode_failed":false,"events":[]})
        }
    };
    let events: Vec<_> = view.events.iter().map(|e| {
        let classification = e.disposition.map(|d| match d {
            RelayDisposition::Forward { dst_agent_id } => json!({"kind":"forward","destination":hex::encode(dst_agent_id)}),
            RelayDisposition::DeliverLocally => json!({"kind":"deliver_locally"}),
            RelayDisposition::Refuse(reason) => json!({"kind":"refuse","reason":refusal(reason)}),
        });
        json!({"request_id":hex::encode(e.request_id),"sender":hex::encode(e.sender),"destination":hex::encode(e.destination),
            "digest_present":e.digest_present,"hop":hex::encode(e.hop),"prefix":hex::encode(e.prefix),
            "sent_wire":e.sent_wire.map(|(length,hash)|json!({"length":length,"sha256":hex::encode(hash)})),"classification":classification})
    }).collect();
    json!({"overflow":view.overflow,"poisoned":false,"decode_failed":view.decode_failed,"events":events})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn prepare(root: &Path) -> PathBuf {
        let path = root.join("ci-evidence/issue442");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("descriptor.json"), serde_json::to_vec(&json!({"schema":"x0x.issue442-descriptor/1",
            "selector":SELECTOR,"run_nonce":"11".repeat(16),"source_head":"22".repeat(20),"source_tree":"33".repeat(20)})).unwrap()).unwrap();
        path
    }
    #[test]
    fn descriptor_absence_activation_and_exclusive_claim() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Sink::activate(dir.path()).unwrap().is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let path = prepare(dir.path());
        let sink = Sink::activate(dir.path()).unwrap().unwrap();
        assert_eq!(sink.value["status"], "started");
        assert!(hex_field(sink.value["binary_sha256"].as_str().unwrap(), 64));
        assert!(Sink::activate(dir.path()).is_err());
        let retained: Value =
            serde_json::from_slice(&fs::read(path.join("phases.json")).unwrap()).unwrap();
        assert_eq!(retained, sink.value);
    }
    #[test]
    fn completion_preserves_frozen_observations_after_later_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare(dir.path());
        let mut sink = Sink::activate(dir.path()).unwrap().unwrap();
        let relay = peer_relay::PeerRelay::new();
        relay.enable_convergence_observer().unwrap();
        sink.value["relay_observations"]["r"] = relay_projection(&relay);
        sink.write("partial", "downgrade").unwrap();
        let frozen: Value =
            serde_json::from_slice(&fs::read(path.join("phases.json")).unwrap()).unwrap();
        // A real observer state change after the asserted cut must not leak
        // into the final artifact. No Agent, transport or service is created.
        relay.observe_convergence_sent(b"invalid after cut", [1; 32]);
        assert_ne!(relay_projection(&relay), frozen["relay_observations"]["r"]);
        sink.complete_after_cleanup().unwrap();
        let completed: Value =
            serde_json::from_slice(&fs::read(path.join("phases.json")).unwrap()).unwrap();
        let mut expected = frozen;
        expected["status"] = json!("completed");
        expected["checkpoint"] = json!("cleanup");
        assert_eq!(completed, expected);
    }
    #[test]
    fn malformed_foreign_and_unsafe_inputs_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare(dir.path());
        fs::write(path.join("descriptor.json"), b"{}").unwrap();
        assert!(Sink::activate(dir.path()).is_err());
        fs::remove_dir_all(dir.path().join("ci-evidence")).unwrap();
        let path = prepare(dir.path());
        let mut descriptor: Value =
            serde_json::from_slice(&fs::read(path.join("descriptor.json")).unwrap()).unwrap();
        descriptor["selector"] = json!("foreign");
        fs::write(path.join("descriptor.json"), descriptor.to_string()).unwrap();
        assert!(Sink::activate(dir.path()).is_err());
        fs::remove_file(path.join("descriptor.json")).unwrap();
        std::os::unix::fs::symlink("/dev/null", path.join("descriptor.json")).unwrap();
        assert!(Sink::activate(dir.path()).is_err());
        fs::remove_dir_all(dir.path().join("ci-evidence")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("ci-evidence")).unwrap();
        assert!(Sink::activate(dir.path()).is_err());
    }
    #[test]
    fn failed_and_oversize_writes_preserve_last_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare(dir.path());
        let mut sink = Sink::activate(dir.path()).unwrap().unwrap();
        sink.write("partial", "setup").unwrap();
        let before = fs::read(path.join("phases.json")).unwrap();
        fs::write(path.join("phases.tmp"), b"interrupted write").unwrap();
        assert!(sink.write("partial", "legacy").is_err());
        assert_eq!(fs::read(path.join("phases.json")).unwrap(), before);
        fs::remove_file(path.join("phases.tmp")).unwrap();
        sink.value["topology"] = json!("x".repeat(LIMIT));
        assert_eq!(
            sink.write("partial", "setup").unwrap_err(),
            "phase_oversize"
        );
        assert_eq!(fs::read(path.join("phases.json")).unwrap(), before);
    }
    #[test]
    fn closed_observer_projection_has_no_payloads_or_paths() {
        let relay = peer_relay::PeerRelay::new();
        assert!(relay_projection(&relay).is_null());
        relay.enable_convergence_observer().unwrap();
        relay.observe_convergence_sent(b"not a frame", [1; 32]);
        let projection = relay_projection(&relay);
        assert_eq!(projection["decode_failed"], true);
        assert_eq!(projection["events"], json!([]));
        // Valid encoded input exercises the actual sent/received projection;
        // fixed opaque test payload is never serialized into evidence.
        let relay = peer_relay::PeerRelay::new();
        relay.enable_convergence_observer().unwrap();
        let frame = peer_relay::RelayedDm {
            header: peer_relay::RelayHeader {
                version: peer_relay::RelayHeader::VERSION,
                dst_agent_id: [3; 32],
                sender_agent_id: [1; 32],
                sender_public_key: vec![],
                originated_at_unix_ms: 1_000,
                inner_digest: None,
                signature: vec![],
            },
            inner: DmEnvelope {
                protocol_version: 1,
                request_id: [7; 16],
                sender_agent_id: [1; 32],
                sender_machine_id: [2; 32],
                recipient_agent_id: [3; 32],
                created_at_unix_ms: 1_000,
                expires_at_unix_ms: 60_000,
                body: DmBody::Payload(dm::DmPayload {
                    kem_ciphertext: vec![0; 8],
                    body_nonce: [0; 12],
                    body_ciphertext: vec![0; 8],
                }),
                signature: vec![0; 8],
                origin_attestation: None,
            },
        };
        let wire = frame.to_postcard().unwrap();
        relay.observe_convergence_sent(&wire, [4; 32]);
        for disposition in [
            RelayDisposition::Forward {
                dst_agent_id: [3; 32],
            },
            RelayDisposition::DeliverLocally,
            RelayDisposition::Refuse(RelayRefusal::MissingInnerDigest),
        ] {
            relay.observe_convergence_received(&frame, [2; 32], [1; 32], disposition);
        }
        let projected = relay_projection(&relay);
        assert_eq!(projected["decode_failed"], false);
        let records = projected["events"].as_array().unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0]["request_id"], "07".repeat(16));
        assert_eq!(records[0]["hop"], "04".repeat(32));
        assert_eq!(
            records[0]["sent_wire"],
            json!({"length":wire.len(),"sha256":hex::encode(Sha256::digest(&wire))})
        );
        assert_eq!(records[1]["hop"], "02".repeat(32));
        assert_eq!(
            records[1]["classification"],
            json!({"kind":"forward","destination":"03".repeat(32)})
        );
        assert_eq!(
            records[2]["classification"],
            json!({"kind":"deliver_locally"})
        );
        assert_eq!(
            records[3]["classification"],
            json!({"kind":"refuse","reason":"missing_inner_digest"})
        );
        assert!(records.iter().all(|r| r.as_object().unwrap().len() == 8));
        assert!(records.iter().all(|r| r.get("disposition").is_none()));
        assert!(records[0]["classification"].is_null());

        assert_eq!(
            service_event(&dm_capability_service::ServiceEvent::Consumed),
            json!({"kind":"consumed"})
        );
        assert_eq!(
            service_event(&dm_capability_service::ServiceEvent::PendingSkip),
            json!({"kind":"pending_skip"})
        );
        for reason in [
            RelayRefusal::BadSignature,
            RelayRefusal::InnerDigestMismatch,
            RelayRefusal::MissingInnerDigest,
            RelayRefusal::Stale,
            RelayRefusal::PolicyDisabled,
            RelayRefusal::NotAContact,
            RelayRefusal::Blocked,
            RelayRefusal::RateLimited,
            RelayRefusal::BandwidthExceeded,
        ] {
            assert!(!refusal(reason).contains('/'));
        }
        let event = service_event(&dm_capability_service::ServiceEvent::Enqueue {
            requester: [1; 32],
            carrier: "critical",
            payload_hash: [2; 32],
            accepted: false,
        });
        assert_eq!(event.as_object().unwrap().len(), 5);
        assert_eq!(event["accepted"], false);
        assert_eq!(event["payload_sha256"], "02".repeat(32));
    }
}
