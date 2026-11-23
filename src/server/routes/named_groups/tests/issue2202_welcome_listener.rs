#![cfg(test)]
//! #2202: in the #1172 soak, failed re-adds were slow seats against the
//! driver's 180 s limit. On the joiner the one Welcome listener awaited each `ChunkAck`
//! send (up to 24 s for its receipt), so queued chunks waited in series
//! (F2: ack failures 24 s apart, the next queued chunk handled 155 µs after
//! each). The joiner also finished only on the owner's `Complete`, which the
//! owner sends only after our acks arrive. Inert: no agent joins a network.

use super::super::{
    fetch_treekem_welcome_via, handle_welcome_blob_message, welcome_ack_test_gate,
    welcome_id_for_bytes, PendingWelcomeReceive, WelcomeRef,
};
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

fn register_receive(state: &AppState, welcome_id: &str, source: &AgentId, bytes: &[u8]) {
    let receive = PendingWelcomeReceive {
        group_id: "g".into(),
        source: hex::encode(source.as_bytes()),
        byte_len: bytes.len() as u64,
        total_chunks: 3,
        chunks: BTreeMap::new(),
        received_bytes: 0,
    };
    if let Ok(mut receives) = state.pending_welcome_receives.try_write() {
        receives.insert(welcome_id.to_string(), receive);
    }
}

/// WHY: moving the ack off the listener must not lose it: the joiner still
/// starts one ack send per chunk it handles.
#[tokio::test]
async fn every_chunk_still_gets_an_ack_send() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([0x7c; 32]);
    let bytes = welcome_bytes(3);
    let welcome_id = welcome_id_for_bytes(&bytes);
    register_receive(&state, &welcome_id, &source, &bytes);
    let release = welcome_ack_test_gate::hold(&welcome_id);
    for sequence in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(2),
            handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, sequence)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("chunk {sequence} waited on a held ack send"))?;
    }
    assert_eq!(
        welcome_ack_test_gate::counts(&welcome_id),
        (2, 0),
        "one ack send per chunk, none dropped"
    );
    release.add_permits(16);
    Ok(())
}

/// WHY: the ack sends are bounded. With every permit taken, a chunk's ack
/// is dropped (and logged), not spawned without limit; the chunk itself is
/// still kept.
#[tokio::test]
async fn ack_sends_are_bounded_and_drop_when_busy() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([0x8d; 32]);
    let bytes = welcome_bytes(4);
    let welcome_id = welcome_id_for_bytes(&bytes);
    register_receive(&state, &welcome_id, &source, &bytes);
    let all = Arc::clone(&state.welcome_ack_sends)
        .try_acquire_many_owned(super::super::WELCOME_ACK_SEND_PERMITS as u32)
        .map_err(|e| anyhow::anyhow!("take every permit: {e}"))?;
    handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, 0)).await;
    assert_eq!(
        welcome_ack_test_gate::counts(&welcome_id),
        (0, 1),
        "with no permit free the ack is dropped, not spawned"
    );
    assert_eq!(
        state
            .pending_welcome_receives
            .read()
            .await
            .get(&welcome_id)
            .map(|receive| receive.chunks.len()),
        Some(1),
        "the chunk is kept"
    );
    drop(all);
    Ok(())
}

/// WHY: a `Complete` that arrives before every chunk does not fail the
/// fetch; the missing chunks can still arrive and finish it. Before, the
/// fetch failed with "incomplete Welcome blob transfer".
#[tokio::test]
async fn an_early_complete_does_not_fail_the_fetch() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let source = AgentId([0x9e; 32]);
    let bytes = welcome_bytes(5);
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
    handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, 0)).await;
    handle_welcome_blob_message(
        &state,
        &source,
        WelcomeBlobMessage::Complete {
            welcome_id: welcome_id.clone(),
        },
    )
    .await;
    assert!(
        !fetch.is_finished(),
        "an early Complete does not end the fetch"
    );
    for sequence in 1..3 {
        handle_welcome_blob_message(&state, &source, chunk(&bytes, &welcome_id, sequence)).await;
    }
    let fetched = tokio::time::timeout(Duration::from_secs(3), fetch)
        .await
        .map_err(|_| anyhow::anyhow!("the fetch did not finish"))??
        .map_err(|e| anyhow::anyhow!("fetch failed: {e}"))?;
    assert_eq!(fetched, bytes);
    Ok(())
}
