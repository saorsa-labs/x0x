use async_trait::async_trait;
use saorsa_gossip_types::PeerId;
use serde_json::Value;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tokio::fs;
use x0x::crdt::persistence::{
    recover_task_list_startup, BudgetDecision, CheckpointReason, CheckpointRequest,
    FileSnapshotBackend, PersistenceBackend, PersistenceBackendError, PersistenceHealth,
    PersistenceMode, PersistencePolicy, PersistenceSnapshot,
};
use x0x::crdt::{TaskList, TaskListId};

#[derive(Clone, Default)]
struct CaptureWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

struct CaptureGuard {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureGuard;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureGuard {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

impl Write for CaptureGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn parse_events(writer: &CaptureWriter) -> Vec<Value> {
    let bytes = writer
        .bytes
        .lock()
        .expect("capture writer lock")
        .clone();
    String::from_utf8(bytes)
        .expect("utf8 logs")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect()
}

#[derive(Clone, Default)]
struct EmptyBackend;

#[async_trait]
impl PersistenceBackend for EmptyBackend {
    async fn checkpoint(
        &self,
        _request: &CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        Err(PersistenceBackendError::SnapshotNotFound(
            entity_id.to_string(),
        ))
    }

    async fn delete_entity(&self, _entity_id: &str) -> Result<(), PersistenceBackendError> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn observability_logs_emit_startup_events_for_empty_store() {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = EmptyBackend;
    let _ = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        tempdir().expect("tempdir").path(),
        "observability-empty",
        TaskList::new(
            TaskListId::new([1; 32]),
            "empty".to_string(),
            PeerId::new([1; 32]),
        ),
    )
    .await
    .expect("empty store recovery succeeds");

    let events = parse_events(&writer);
    let names: Vec<&str> = events
        .iter()
        .filter_map(|entry| entry.get("fields")?.get("event")?.as_str())
        .collect();
    assert!(names.contains(&"persistence.init.started"));
    assert!(names.contains(&"persistence.init.empty_store"));
}

#[tokio::test(flavor = "current_thread")]
async fn observability_logs_emit_checkpoint_attempt_and_success() {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempdir().expect("tempdir");
    let backend = FileSnapshotBackend::new(dir.path().to_path_buf(), PersistenceMode::Degraded);
    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: "observability-checkpoint".to_string(),
                mutation_count: 12,
                reason: CheckpointReason::ExplicitRequest,
            },
            &PersistenceSnapshot {
                entity_id: "observability-checkpoint".to_string(),
                schema_version: 2,
                payload: vec![1, 2, 3],
            },
        )
        .await
        .expect("checkpoint succeeds");

    let events = parse_events(&writer);
    let names: Vec<&str> = events
        .iter()
        .filter_map(|entry| entry.get("fields")?.get("event")?.as_str())
        .collect();
    assert!(names.contains(&"persistence.checkpoint.attempt"));
    assert!(names.contains(&"persistence.checkpoint.success"));
}

#[tokio::test(flavor = "current_thread")]
async fn observability_logs_emit_legacy_artifact_detection_event() {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempdir().expect("tempdir");
    let entity_id = "observability-legacy";
    let entity_dir = dir.path().join(entity_id);
    fs::create_dir_all(&entity_dir).await.expect("create entity dir");
    fs::write(
        entity_dir.join("00000000000000000001.snapshot"),
        br#"{"ciphertext":"abc","nonce":"123","key_id":"k1"}"#,
    )
    .await
    .expect("write legacy artifact");

    let backend = FileSnapshotBackend::new(dir.path().to_path_buf(), PersistenceMode::Degraded);
    let err = backend
        .load_latest(entity_id)
        .await
        .expect_err("legacy artifact must fail load");
    assert!(matches!(err, PersistenceBackendError::NoLoadableSnapshot(_)));

    let events = parse_events(&writer);
    let detected = events.iter().any(|entry| {
        entry
            .get("fields")
            .and_then(|fields| fields.get("event"))
            .and_then(Value::as_str)
            .is_some_and(|name| name == "persistence.legacy_artifact.detected")
    });
    assert!(detected);
}

#[test]
fn observability_logs_emit_budget_threshold_crossings() {
    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut health = PersistenceHealth::new(PersistenceMode::Degraded);
    health.apply_budget_decision(BudgetDecision::Warning80);

    let events = parse_events(&writer);
    let budget_event = events.iter().find(|entry| {
        entry
            .get("fields")
            .and_then(|fields| fields.get("event"))
            .and_then(Value::as_str)
            .is_some_and(|name| name == "persistence.budget.threshold")
    });
    assert!(budget_event.is_some());
    let pressure = budget_event
        .and_then(|entry| entry.get("fields"))
        .and_then(|fields| fields.get("budget_pressure"))
        .and_then(Value::as_str)
        .expect("budget pressure field");
    assert_eq!(pressure, "warning");
}
