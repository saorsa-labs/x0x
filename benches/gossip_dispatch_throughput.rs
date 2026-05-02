use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use saorsa_gossip_identity::MlDsaKeyPair;
use saorsa_gossip_pubsub::GossipMessage;
use saorsa_gossip_types::{MessageHeader, MessageKind, PeerId, TopicId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::runtime::Runtime;
use x0x::gossip::PubSubManager;
use x0x::network::{NetworkConfig, NetworkNode};

const BATCH_SIZE: usize = 256;

fn encode_v1_payload(topic: &str, payload: &[u8]) -> Bytes {
    let topic_bytes = topic.as_bytes();
    let mut buf = Vec::with_capacity(2 + topic_bytes.len() + payload.len());
    let topic_len = u16::try_from(topic_bytes.len()).expect("bench topic fits u16");
    buf.extend_from_slice(&topic_len.to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(payload);
    Bytes::from(buf)
}

fn peer(byte: u8) -> PeerId {
    PeerId::new([byte; 32])
}

fn message_id(sequence: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&sequence.to_be_bytes());
    id[8..16].copy_from_slice(&(!sequence).to_be_bytes());
    id
}

fn build_eager_wire(
    signing_key: &MlDsaKeyPair,
    topic_id: TopicId,
    topic: &str,
    sequence: u64,
) -> Bytes {
    let payload = encode_v1_payload(topic, format!("bench-message-{sequence}").as_bytes());
    let header = MessageHeader {
        version: 1,
        topic: topic_id,
        msg_id: message_id(sequence),
        kind: MessageKind::Eager,
        hop: 0,
        ttl: 10,
    };
    let header_bytes = postcard::to_stdvec(&header).expect("bench header serializes");
    let signature = signing_key.sign(&header_bytes).expect("bench header signs");
    let message = GossipMessage {
        header,
        payload: Some(payload),
        signature,
        public_key: signing_key.public_key().to_vec(),
    };
    Bytes::from(postcard::to_stdvec(&message).expect("bench message serializes"))
}

fn make_manager(rt: &Runtime) -> Arc<PubSubManager> {
    rt.block_on(async {
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("bench network starts");
        Arc::new(PubSubManager::new(Arc::new(network), None).expect("bench pubsub manager starts"))
    })
}

fn bench_handle_incoming(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime starts");
    let manager = make_manager(&rt);
    let signing_key = MlDsaKeyPair::generate().expect("bench signing key generates");
    let topic = "bench/gossip-dispatch";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    let from = peer(7);
    let sequence = AtomicU64::new(1);

    let mut group = c.benchmark_group("gossip_dispatch_throughput");
    group.throughput(Throughput::Elements(BATCH_SIZE as u64));
    group.bench_function("handle_incoming_eager_no_local_subscribers", |b| {
        b.iter_batched(
            || {
                (0..BATCH_SIZE)
                    .map(|_| {
                        let seq = sequence.fetch_add(1, Ordering::Relaxed);
                        build_eager_wire(&signing_key, topic_id, topic, seq)
                    })
                    .collect::<Vec<_>>()
            },
            |batch| {
                rt.block_on(async {
                    for data in batch {
                        manager.handle_incoming(from, data).await;
                    }
                });
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_handle_incoming);
criterion_main!(benches);
