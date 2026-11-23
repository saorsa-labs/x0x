#![cfg(test)]
//! #2202: in the #1172 soak, re-adds seated in 203–248 s against a 180 s
//! limit. On the joiner the one Welcome listener awaited each `ChunkAck`
//! send (up to 24 s for its receipt), so queued chunks waited in series
//! (F2: ack failures 24 s apart, the next queued chunk handled 155 µs after
//! each). The joiner also finished only on the owner's `Complete`, which the
//! owner sends only after our acks arrive, and every repeated `FetchRequest`
//! restarted the owner's stream. Inert: no agent joins a network.

use super::super::{
    fetch_treekem_welcome_via, handle_welcome_blob_message, handle_welcome_fetch_request_via,
    welcome_ack_test_gate, welcome_id_for_bytes, PendingWelcomeReceive, WelcomeRef,
};
use super::adr0107_stuck_join_rearm as f;
use super::*;

const CHUNK: usize = x0x::files::DEFAULT_CHUNK_SIZE;

fn welcome_bytes(seed: u8) -> Vec<u8> {
    (0..(CHUNK * 2 + 17))
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn chunk(bytes: &[u8], welcome_id: &str, sequence: usize) -> WelcomeBlobMessage {
    WelcomeBlobMessage::Chunk {
        welcome_id: welcome_id.to_string(),
        sequence: sequence as u64,
        data: BASE64.encode(&bytes[sequence * CHUNK..((sequence + 1) * CHUNK).min(bytes.len())]),
    }
}

/// WHY: a `ChunkAck` whose send is slow must not hold the Welcome listener.
/// Red before the fix: the first chunk's held ack send blocks the handler,
/// so the next chunk is never handled.
#[tokio::test]
async fn a_held_chunk_ack_does_not_delay_later_chunks() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([0x5a; 32]);
    let bytes = welcome_bytes(1);
    let welcome_id = welcome_id_for_bytes(&bytes);
    state.pending_welcome_receives.write().await.insert(
        welcome_id.clone(),
        PendingWelcomeReceive {
            group_id: "g".into(),
            source: hex::encode(source.as_bytes()),
            byte_len: bytes.len() as u64,
            total_chunks: 3,
            chunks: BTreeMap::new(),
            received_bytes: 0,
        },
    );
    let release = welcome_ack_test_gate::hold(&welcome_id);
    for sequence in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(2),
            handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, sequence)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("chunk {sequence} waited on a held ack send"))?;
    }
    let held = state
        .pending_welcome_receives
        .read()
        .await
        .get(&welcome_id)
        .map(|receive| receive.chunks.len());
    assert_eq!(
        held,
        Some(2),
        "both chunks were handled while acks were held"
    );
    release.add_permits(16);
    Ok(())
}

/// WHY: a joiner that holds every chunk of its Welcome, with the right
/// content hash, has it; it does not wait for the owner's `Complete`. A
/// later `Complete` is ignored. Red before the fix: the fetch waits.
#[tokio::test]
async fn all_chunks_complete_the_fetch_without_complete() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([0x6b; 32]);
    let bytes = welcome_bytes(2);
    let welcome_id = welcome_id_for_bytes(&bytes);
    let reference = WelcomeRef {
        welcome_id: welcome_id.clone(),
        byte_len: bytes.len() as u64,
        source: hex::encode(source.as_bytes()),
    };
    let fetch_state = Arc::clone(&state);
    let fetch = tokio::spawn(async move {
        fetch_treekem_welcome_via(&fetch_state, "g", &reference, |_, _| async { Ok(()) }).await
    });
    for _ in 0..200 {
        if state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_id)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for sequence in 0..3 {
        handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, sequence)).await;
    }
    let fetched = tokio::time::timeout(Duration::from_secs(3), fetch)
        .await
        .map_err(|_| anyhow::anyhow!("the fetch waited for Complete"))??
        .map_err(|e| anyhow::anyhow!("fetch failed: {e}"))?;
    assert_eq!(fetched, bytes, "the exact Welcome bytes");
    handle_welcome_blob_message(
        &state,
        &source,
        WelcomeBlobMessage::Complete {
            welcome_id: welcome_id.clone(),
        },
    )
    .await;
    assert!(
        !state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_id),
        "a late Complete finds nothing to do"
    );
    Ok(())
}

/// The live stream for `welcome_id`: its task id and its ack slot.
async fn live_stream(
    authority: &AppState,
    welcome_id: &str,
) -> Option<(
    tokio::task::Id,
    Arc<crate::server::routes::files::FileChunkAckSlot>,
)> {
    let id = authority
        .pending_welcome_streams
        .lock()
        .await
        .as_ref()
        .and_then(|streams| streams.get(welcome_id))
        .filter(|handle| !handle.is_finished())
        .map(|handle| handle.id())?;
    let slot = authority
        .pending_welcome_acks
        .read()
        .await
        .get(welcome_id)
        .cloned()?;
    Some((id, slot))
}

/// WHY: a repeated `FetchRequest` from the verified recipient while its
/// stream is still live (waiting for its final ack) leaves that stream and
/// its ack slot alone. Red before the fix: the stream was aborted and
/// restarted with a fresh slot, dropping the acks it had.
#[tokio::test]
async fn a_repeated_fetch_keeps_the_live_stream_and_its_acks() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let welcome_id = f::welcome_id_of(&s.j1_add).expect("J1's Welcome by reference");
    let j1 = s.j1.agent.agent_id();
    let fetch = || {
        handle_welcome_fetch_request_via(
            &s.authority,
            &j1,
            s.stable.clone(),
            welcome_id.clone(),
            |_msg: WelcomeBlobMessage| async { Ok(()) },
        )
    };
    fetch().await;
    let mut first = None;
    for _ in 0..200 {
        first = live_stream(&s.authority, &welcome_id).await;
        if first.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (first_id, first_slot) = first.expect("the first fetch started a stream");
    fetch().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (second_id, second_slot) = live_stream(&s.authority, &welcome_id)
        .await
        .expect("a stream is still live");
    assert_eq!(second_id, first_id, "the live stream was not restarted");
    assert!(
        Arc::ptr_eq(&first_slot, &second_slot),
        "its ack slot is kept"
    );

    Ok(())
}
