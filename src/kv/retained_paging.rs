//! Bounded paging for retained group-store history images.
//!
//! Each payload is still authenticated by the surrounding group mutation.
//! The image digest binds every page to one immutable serialized CRDT image;
//! receivers assemble into a temporary buffer and merge only after the full
//! length and digest validate.

use super::{KvError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const PAGED_RETAINED_MAGIC: &[u8] = b"x0x.kv.retained.pages.v1\0";
pub(crate) const MAX_RETAINED_IMAGE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_RETAINED_PAGES: u32 = 64;
const MAX_INFLIGHT_IMAGES: usize = 4;
const MAX_INFLIGHT_BYTES: usize = 32 * 1024 * 1024;
const INFLIGHT_TTL: Duration = Duration::from_secs(120);
/// #811 r2 (review finding 2): how long a pending image must be IDLE
/// (no accepted progress: no new page, no manifest) before a NEW image
/// may displace it when the pool is at the in-flight cap. 30 s in EVERY
/// build — tests back-date `last_progress` (the deterministic pattern
/// already used for `created`), never wall-clock sleep.
const INFLIGHT_DISPLACE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RetainedPageBinding {
    pub store_id: [u8; 32],
    pub endorser: [u8; 32],
    pub authorization: [u8; 32],
    pub image_id: [u8; 32],
}

#[derive(Debug)]
struct PendingImage {
    created: Instant,
    /// #811 r2 (review finding 3): the last ACCEPTED progress (a new
    /// page or a manifest). Victim selection displaces by MAX IDLE on
    /// this, not by age — a large image still receiving pages is never
    /// the victim while a dead one is available.
    last_progress: Instant,
    manifest: Option<RetainedPageV1>,
    pages: BTreeMap<u32, Vec<u8>>,
    received_len: usize,
}

#[derive(Debug, Default)]
pub(crate) struct RetainedPagePool {
    images: BTreeMap<RetainedPageBinding, PendingImage>,
    received_len: usize,
}

impl RetainedPagePool {
    pub(crate) fn push(
        &mut self,
        binding: RetainedPageBinding,
        frame: RetainedPageV1,
    ) -> Result<Option<Vec<u8>>> {
        self.prune();
        match &frame {
            RetainedPageV1::Manifest { image_id, .. } => {
                if image_id != &binding.image_id {
                    return Err(KvError::Gossip(
                        "retained manifest binding mismatch".to_string(),
                    ));
                }
                RetainedPageAssembler::from_manifest(&frame)?;
            }
            RetainedPageV1::Page {
                image_id,
                index,
                bytes,
            } => {
                if image_id != &binding.image_id
                    || *index >= MAX_RETAINED_PAGES
                    || bytes.len() > MAX_RETAINED_IMAGE_BYTES
                {
                    return Err(KvError::Gossip(
                        "retained page binding or size mismatch".to_string(),
                    ));
                }
            }
        }
        let validation = (|| -> Result<()> {
            match (&frame, self.images.get(&binding)) {
                (RetainedPageV1::Manifest { .. }, Some(pending)) => {
                    let mut assembler = RetainedPageAssembler::from_manifest(&frame)?;
                    pending.pages.iter().try_for_each(|(&index, bytes)| {
                        assembler
                            .push(RetainedPageV1::Page {
                                image_id: binding.image_id,
                                index,
                                bytes: bytes.clone(),
                            })
                            .map(|_| ())
                    })
                }
                (
                    RetainedPageV1::Page { .. },
                    Some(PendingImage {
                        manifest: Some(manifest),
                        pages,
                        ..
                    }),
                ) => {
                    let mut assembler = RetainedPageAssembler::from_manifest(manifest)?;
                    for (&index, bytes) in pages {
                        assembler.push(RetainedPageV1::Page {
                            image_id: binding.image_id,
                            index,
                            bytes: bytes.clone(),
                        })?;
                    }
                    assembler.push(frame.clone()).map(|_| ())
                }
                _ => Ok(()),
            }
        })();
        if let Err(error) = validation {
            if let Some(pending) = self.images.remove(&binding) {
                self.received_len = self.received_len.saturating_sub(pending.received_len);
            }
            return Err(error);
        }
        let needs_slot = !self.images.contains_key(&binding);
        let is_new_page = match &frame {
            RetainedPageV1::Manifest { .. } => false,
            RetainedPageV1::Page { index, .. } => self
                .images
                .get(&binding)
                .is_none_or(|pending| !pending.pages.contains_key(index)),
        };
        if is_new_page {
            if let RetainedPageV1::Page { bytes, .. } = &frame {
                let image_len = self
                    .images
                    .get(&binding)
                    .map_or(0, |pending| pending.received_len)
                    .checked_add(bytes.len())
                    .ok_or_else(|| {
                        KvError::Gossip("retained page byte count overflow".to_string())
                    })?;
                if image_len > MAX_RETAINED_IMAGE_BYTES {
                    return Err(KvError::Gossip(
                        "retained page pool exceeds resource limits".to_string(),
                    ));
                }
            }
        }
        if needs_slot || is_new_page {
            let incoming_len = match &frame {
                RetainedPageV1::Manifest { .. } => 0,
                RetainedPageV1::Page { bytes, .. } => bytes.len(),
            };
            self.evict_superseded_for(&binding, incoming_len, needs_slot);
        }
        if let RetainedPageV1::Page { index, bytes, .. } = &frame {
            let pending = self.images.get(&binding);
            let is_new_page = pending.is_none_or(|pending| !pending.pages.contains_key(index));
            if is_new_page {
                let image_len = pending
                    .map_or(0, |pending| pending.received_len)
                    .checked_add(bytes.len())
                    .ok_or_else(|| {
                        KvError::Gossip("retained page byte count overflow".to_string())
                    })?;
                let global_len = self.received_len.checked_add(bytes.len()).ok_or_else(|| {
                    KvError::Gossip("retained inflight byte count overflow".to_string())
                })?;
                if image_len > MAX_RETAINED_IMAGE_BYTES || global_len > MAX_INFLIGHT_BYTES {
                    return Err(KvError::Gossip(
                        "retained page pool exceeds resource limits".to_string(),
                    ));
                }
            }
        }
        // #811 r2 (findings 2+3+4): the displacement runs AFTER the byte
        // gates above, so a victim is only evicted when the incoming
        // page is otherwise CERTAIN to be admitted. The victim is the
        // MAX-IDLE image (no accepted progress for the longest) that has
        // been idle at least INFLIGHT_DISPLACE_AFTER — a large image
        // still receiving pages is protected; a dead one (sender gone,
        // divergent endorser/epoch binding) is displaced. Within the
        // grace the bounded refusal stands, naming the store.
        //
        // Custody decision (#811 r2 finding 1, explicit): displacement
        // crosses endorser/epoch boundaries WITHIN one store — the R10
        // wedge was divergent bindings in ONE store. Other stores keep
        // independent custody. DoS note (finding 5): only authenticated
        // non-reader writers reach push; one writer's images share one
        // binding authority (evict_superseded_for keeps them to one
        // slot), so a lone attacker displaces at most one idle victim
        // per new image, never continuously; a flood of legitimate new
        // authorities can starve slow images — that is finding 3 again,
        // and idle-based selection is the mitigation.
        if !self.images.contains_key(&binding) && self.images.len() >= MAX_INFLIGHT_IMAGES {
            let mut idlest: Option<(RetainedPageBinding, Duration, usize)> = None;
            for (stuck, pending) in &self.images {
                let idle = pending.last_progress.elapsed();
                if idlest.as_ref().is_none_or(|(_, best, _)| idle > *best) {
                    idlest = Some((stuck.clone(), idle, pending.received_len));
                }
            }
            match idlest {
                Some((stuck, idle, victim_len)) if idle >= INFLIGHT_DISPLACE_AFTER => {
                    if let Some(pending) = self.images.remove(&stuck) {
                        self.received_len = self.received_len.saturating_sub(pending.received_len);
                        tracing::warn!(
                            store = %hex::encode(&stuck.store_id[..8]),
                            incoming_store = %hex::encode(&binding.store_id[..8]),
                            idle_secs = idle.as_secs(),
                            victim_bytes = victim_len,
                            "displacing an idle retained image awaiting pages (#811 r2)"
                        );
                    }
                }
                _ => {
                    return Err(KvError::Gossip(format!(
                        "too many retained images are awaiting pages for store {}",
                        hex::encode(&binding.store_id[..8])
                    )));
                }
            }
        }
        let pending = self
            .images
            .entry(binding.clone())
            .or_insert_with(|| PendingImage {
                created: Instant::now(),
                last_progress: Instant::now(),
                manifest: None,
                pages: BTreeMap::new(),
                received_len: 0,
            });
        match frame {
            manifest @ RetainedPageV1::Manifest { image_id, .. } => {
                if image_id != binding.image_id {
                    return Err(KvError::Gossip(
                        "retained manifest binding mismatch".to_string(),
                    ));
                }
                if let Some(existing) = pending.manifest.as_ref() {
                    if existing != &manifest {
                        return Err(KvError::Gossip("conflicting retained manifest".to_string()));
                    }
                } else {
                    RetainedPageAssembler::from_manifest(&manifest)?;
                    pending.manifest = Some(manifest);
                    pending.last_progress = Instant::now();
                }
            }
            RetainedPageV1::Page {
                image_id,
                index,
                bytes,
            } => {
                if image_id != binding.image_id || index >= MAX_RETAINED_PAGES {
                    return Err(KvError::Gossip(
                        "retained page binding mismatch".to_string(),
                    ));
                }
                if let Some(existing) = pending.pages.get(&index) {
                    if existing != &bytes {
                        return Err(KvError::Gossip(
                            "conflicting duplicate retained page".to_string(),
                        ));
                    }
                    return Ok(None);
                }
                let image_len = pending
                    .received_len
                    .checked_add(bytes.len())
                    .ok_or_else(|| {
                        KvError::Gossip("retained page byte count overflow".to_string())
                    })?;
                let global_len = self.received_len.checked_add(bytes.len()).ok_or_else(|| {
                    KvError::Gossip("retained inflight byte count overflow".to_string())
                })?;
                if image_len > MAX_RETAINED_IMAGE_BYTES || global_len > MAX_INFLIGHT_BYTES {
                    return Err(KvError::Gossip(
                        "retained page pool exceeds resource limits".to_string(),
                    ));
                }
                pending.pages.insert(index, bytes);
                pending.received_len = image_len;
                pending.last_progress = Instant::now();
                self.received_len = global_len;
            }
        }
        let Some(manifest) = pending.manifest.as_ref() else {
            return Ok(None);
        };
        let mut assembler = RetainedPageAssembler::from_manifest(manifest)?;
        let mut completed = None;
        for (&index, bytes) in &pending.pages {
            completed = assembler.push(RetainedPageV1::Page {
                image_id: binding.image_id,
                index,
                bytes: bytes.clone(),
            })?;
        }
        if completed.is_some() {
            if let Some(done) = self.images.remove(&binding) {
                self.received_len = self.received_len.saturating_sub(done.received_len);
            }
        }
        Ok(completed)
    }

    /// Make room for a newly arriving authenticated image from the same exact source.
    /// Other STORES retain independent resource custody and cannot be
    /// displaced by this binding. Custody WITHIN one store (across
    /// endorsers/epochs) lasts until the image is complete, idle beyond
    /// INFLIGHT_DISPLACE_AFTER (see the displacement in `push`), or the
    /// TTL — the explicit #811 r2 decision.
    fn evict_superseded_for(
        &mut self,
        binding: &RetainedPageBinding,
        incoming_len: usize,
        needs_slot: bool,
    ) {
        while (needs_slot && self.images.len() >= MAX_INFLIGHT_IMAGES)
            || self.received_len.saturating_add(incoming_len) > MAX_INFLIGHT_BYTES
        {
            let oldest = self
                .images
                .iter()
                .filter(|(candidate, _)| {
                    *candidate != binding
                        && candidate.store_id == binding.store_id
                        && candidate.endorser == binding.endorser
                        && candidate.authorization == binding.authorization
                })
                .min_by_key(|(_, pending)| pending.created)
                .map(|(candidate, _)| candidate.clone());
            let Some(oldest) = oldest else {
                break;
            };
            if let Some(pending) = self.images.remove(&oldest) {
                self.received_len = self.received_len.saturating_sub(pending.received_len);
            }
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .images
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.created) > INFLIGHT_TTL)
            .map(|(binding, _)| binding.clone())
            .collect();
        for binding in expired {
            if let Some(pending) = self.images.remove(&binding) {
                self.received_len = self.received_len.saturating_sub(pending.received_len);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum RetainedPageV1 {
    Manifest {
        image_id: [u8; 32],
        total_len: u64,
        page_count: u32,
    },
    Page {
        image_id: [u8; 32],
        index: u32,
        bytes: Vec<u8>,
    },
}

pub(crate) fn encode_page(page: &RetainedPageV1) -> Result<Vec<u8>> {
    let body = bincode::serialize(page)?;
    let mut encoded = Vec::with_capacity(PAGED_RETAINED_MAGIC.len() + body.len());
    encoded.extend_from_slice(PAGED_RETAINED_MAGIC);
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub(crate) fn decode_page(payload: &[u8]) -> Result<Option<RetainedPageV1>> {
    let Some(body) = payload.strip_prefix(PAGED_RETAINED_MAGIC) else {
        return Ok(None);
    };
    bincode::deserialize(body).map(Some).map_err(KvError::from)
}

pub(crate) fn split_image(image: &[u8], max_payload: usize) -> Result<Vec<Vec<u8>>> {
    if image.len() > MAX_RETAINED_IMAGE_BYTES {
        return Err(KvError::Gossip(
            "retained image exceeds paging resource limit".into(),
        ));
    }
    let image_id = *blake3::hash(image).as_bytes();
    let empty_page_overhead = encode_page(&RetainedPageV1::Page {
        image_id,
        index: 0,
        bytes: Vec::new(),
    })?
    .len();
    let chunk_len = max_payload
        .checked_sub(empty_page_overhead)
        .ok_or_else(|| {
            KvError::Gossip("retained page payload budget cannot hold framing".into())
        })?;
    if chunk_len == 0 {
        return Err(KvError::Gossip(
            "retained page payload budget is empty".into(),
        ));
    }
    let page_count_usize = image.len().div_ceil(chunk_len).max(1);
    let page_count = u32::try_from(page_count_usize)
        .map_err(|_| KvError::Gossip("retained page count overflow".into()))?;
    if page_count > MAX_RETAINED_PAGES {
        return Err(KvError::Gossip(
            "retained image requires too many pages".into(),
        ));
    }
    let total_len = u64::try_from(image.len())
        .map_err(|_| KvError::Gossip("retained image length overflow".into()))?;
    let mut payloads = vec![encode_page(&RetainedPageV1::Manifest {
        image_id,
        total_len,
        page_count,
    })?];
    if image.is_empty() {
        payloads.push(encode_page(&RetainedPageV1::Page {
            image_id,
            index: 0,
            bytes: Vec::new(),
        })?);
        return Ok(payloads);
    }
    for (index, bytes) in image.chunks(chunk_len).enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| KvError::Gossip("retained page index overflow".into()))?;
        let payload = encode_page(&RetainedPageV1::Page {
            image_id,
            index,
            bytes: bytes.to_vec(),
        })?;
        if payload.len() > max_payload {
            return Err(KvError::Gossip(
                "encoded retained page exceeds payload budget".into(),
            ));
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

#[derive(Debug)]
pub(crate) struct RetainedPageAssembler {
    image_id: [u8; 32],
    total_len: usize,
    page_count: u32,
    pages: BTreeMap<u32, Vec<u8>>,
    received_len: usize,
}

impl RetainedPageAssembler {
    pub(crate) fn from_manifest(manifest: &RetainedPageV1) -> Result<Self> {
        let RetainedPageV1::Manifest {
            image_id,
            total_len,
            page_count,
        } = manifest
        else {
            return Err(KvError::Gossip("retained paging manifest required".into()));
        };
        let total_len = usize::try_from(*total_len)
            .map_err(|_| KvError::Gossip("retained image length overflow".into()))?;
        if total_len > MAX_RETAINED_IMAGE_BYTES
            || *page_count == 0
            || *page_count > MAX_RETAINED_PAGES
        {
            return Err(KvError::Gossip(
                "retained paging manifest exceeds limits".into(),
            ));
        }
        Ok(Self {
            image_id: *image_id,
            total_len,
            page_count: *page_count,
            pages: BTreeMap::new(),
            received_len: 0,
        })
    }

    pub(crate) fn push(&mut self, page: RetainedPageV1) -> Result<Option<Vec<u8>>> {
        let RetainedPageV1::Page {
            image_id,
            index,
            bytes,
        } = page
        else {
            return Err(KvError::Gossip("retained paging page required".into()));
        };
        if image_id != self.image_id || index >= self.page_count {
            return Err(KvError::Gossip("retained page binding mismatch".into()));
        }
        if let Some(existing) = self.pages.get(&index) {
            if existing == &bytes {
                return Ok(None);
            }
            return Err(KvError::Gossip(
                "conflicting duplicate retained page".into(),
            ));
        }
        let next_len = self
            .received_len
            .checked_add(bytes.len())
            .ok_or_else(|| KvError::Gossip("retained page byte count overflow".into()))?;
        if next_len > self.total_len || next_len > MAX_RETAINED_IMAGE_BYTES {
            return Err(KvError::Gossip(
                "retained pages exceed declared image length".into(),
            ));
        }
        self.pages.insert(index, bytes);
        self.received_len = next_len;
        if self.pages.len() != self.page_count as usize {
            return Ok(None);
        }
        let mut image = Vec::with_capacity(self.total_len);
        for index in 0..self.page_count {
            let bytes = self
                .pages
                .get(&index)
                .ok_or_else(|| KvError::Gossip("retained page missing".into()))?;
            image.extend_from_slice(bytes);
            if image.len() > self.total_len {
                return Err(KvError::Gossip(
                    "retained pages exceed declared length".into(),
                ));
            }
        }
        if image.len() != self.total_len || blake3::hash(&image).as_bytes() != &self.image_id {
            return Err(KvError::Gossip("retained image digest mismatch".into()));
        }
        Ok(Some(image))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_reassemble_out_of_order_and_reject_tamper() {
        let image = vec![7; 4096];
        let payloads = split_image(&image, 512).expect("split");
        let manifest = decode_page(&payloads[0])
            .expect("decode")
            .expect("manifest");
        let mut assembler = RetainedPageAssembler::from_manifest(&manifest).expect("assembler");
        let mut pages: Vec<_> = payloads[1..]
            .iter()
            .map(|payload| decode_page(payload).expect("decode").expect("page"))
            .collect();
        pages.reverse();
        let mut complete = None;
        for page in pages {
            complete = assembler.push(page).expect("page").or(complete);
        }
        assert_eq!(complete.as_deref(), Some(image.as_slice()));

        let mut assembler = RetainedPageAssembler::from_manifest(&manifest).expect("assembler");
        let mut pages: Vec<_> = payloads[1..]
            .iter()
            .map(|payload| decode_page(payload).expect("decode").expect("page"))
            .collect();
        if let RetainedPageV1::Page { bytes, .. } = &mut pages[0] {
            bytes[0] ^= 1;
        }
        let mut result = Ok(None);
        for page in pages {
            result = assembler.push(page);
        }
        assert!(result.is_err());
    }

    #[test]
    fn assembler_rejects_oversize_and_conflicting_duplicate_before_completion() {
        let image_id = [3; 32];
        let manifest = RetainedPageV1::Manifest {
            image_id,
            total_len: 2,
            page_count: 2,
        };
        let mut assembler = RetainedPageAssembler::from_manifest(&manifest).expect("assembler");
        assembler
            .push(RetainedPageV1::Page {
                image_id,
                index: 0,
                bytes: vec![1],
            })
            .expect("first page");
        assert_eq!(assembler.received_len, 1);
        assert!(assembler
            .push(RetainedPageV1::Page {
                image_id,
                index: 0,
                bytes: vec![2],
            })
            .is_err());
        assert_eq!(assembler.received_len, 1);
        assert_eq!(assembler.pages.get(&0).map(Vec::as_slice), Some(&[1][..]));
        assert!(assembler
            .push(RetainedPageV1::Page {
                image_id,
                index: 1,
                bytes: vec![2, 3],
            })
            .is_err());
        assert_eq!(assembler.received_len, 1);
        assert!(!assembler.pages.contains_key(&1));
    }

    #[test]
    fn pool_accepts_pages_before_manifest_and_separates_authority_bindings() {
        let image = vec![9; 2048];
        let frames = split_image(&image, 512).expect("split");
        let decoded: Vec<_> = frames
            .iter()
            .map(|frame| decode_page(frame).expect("decode").expect("paged frame"))
            .collect();
        let image_id = match decoded[0] {
            RetainedPageV1::Manifest { image_id, .. } => image_id,
            RetainedPageV1::Page { .. } => panic!("manifest first"),
        };
        let binding = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id,
        };
        let mut pool = RetainedPagePool::default();
        for frame in decoded.iter().skip(1).cloned() {
            assert!(pool.push(binding.clone(), frame).expect("page").is_none());
        }
        let wrong_authority = RetainedPageBinding {
            authorization: [4; 32],
            ..binding.clone()
        };
        assert!(pool
            .push(wrong_authority, decoded[0].clone())
            .expect("separate manifest")
            .is_none());
        let completed = pool
            .push(binding, decoded[0].clone())
            .expect("manifest completes");
        assert_eq!(completed.as_deref(), Some(image.as_slice()));
    }

    #[test]
    fn pool_discards_pre_manifest_poison_and_recovers_accounting() {
        let image = vec![5; 32];
        let frames = split_image(&image, 256).expect("split");
        let manifest = decode_page(&frames[0]).expect("decode").expect("manifest");
        let valid_page = decode_page(&frames[1]).expect("decode").expect("page");
        let image_id = match manifest {
            RetainedPageV1::Manifest { image_id, .. } => image_id,
            RetainedPageV1::Page { .. } => panic!("manifest first"),
        };
        let binding = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id,
        };
        let poison = RetainedPageV1::Page {
            image_id,
            index: 1,
            bytes: vec![8; 7],
        };
        let mut pool = RetainedPagePool::default();
        assert!(pool
            .push(binding.clone(), poison)
            .expect("pending page")
            .is_none());
        assert_eq!(pool.received_len, 7);

        assert!(pool.push(binding.clone(), manifest.clone()).is_err());
        assert_eq!(pool.received_len, 0);
        assert!(!pool.images.contains_key(&binding));

        assert!(pool
            .push(binding.clone(), manifest)
            .expect("fresh manifest")
            .is_none());
        let completed = pool
            .push(binding, valid_page)
            .expect("valid page after poison");
        assert_eq!(completed.as_deref(), Some(image.as_slice()));
        assert_eq!(pool.received_len, 0);
    }

    #[test]
    fn pool_enforces_image_count_byte_limit_and_ttl() {
        let mut pool = RetainedPagePool::default();
        for tag in 0..MAX_INFLIGHT_IMAGES {
            let binding = RetainedPageBinding {
                store_id: [tag as u8; 32],
                endorser: [1; 32],
                authorization: [2; 32],
                image_id: [tag as u8; 32],
            };
            pool.push(
                binding,
                RetainedPageV1::Page {
                    image_id: [tag as u8; 32],
                    index: 0,
                    bytes: vec![tag as u8],
                },
            )
            .expect("bounded pending image");
        }
        let extra = RetainedPageBinding {
            store_id: [99; 32],
            endorser: [1; 32],
            authorization: [2; 32],
            image_id: [99; 32],
        };
        assert!(pool
            .push(
                extra.clone(),
                RetainedPageV1::Page {
                    image_id: extra.image_id,
                    index: 0,
                    bytes: vec![1],
                },
            )
            .is_err());

        for pending in pool.images.values_mut() {
            pending.created = Instant::now() - INFLIGHT_TTL - std::time::Duration::from_secs(1);
        }
        assert!(pool
            .push(
                extra.clone(),
                RetainedPageV1::Page {
                    image_id: extra.image_id,
                    index: 0,
                    bytes: vec![1],
                },
            )
            .expect("expired images pruned")
            .is_none());
        assert_eq!(pool.images.len(), 1);
        assert_eq!(pool.received_len, 1);

        let large_a = RetainedPageBinding {
            store_id: [10; 32],
            endorser: [1; 32],
            authorization: [2; 32],
            image_id: [10; 32],
        };
        let large_b = RetainedPageBinding {
            store_id: [11; 32],
            image_id: [11; 32],
            ..large_a.clone()
        };
        pool.push(
            large_a.clone(),
            RetainedPageV1::Page {
                image_id: large_a.image_id,
                index: 0,
                bytes: vec![0; MAX_RETAINED_IMAGE_BYTES],
            },
        )
        .expect("first bounded image");
        assert!(pool
            .push(
                large_b.clone(),
                RetainedPageV1::Page {
                    image_id: large_b.image_id,
                    index: 0,
                    bytes: vec![0; MAX_RETAINED_IMAGE_BYTES],
                },
            )
            .is_err());
        assert!(!pool.images.contains_key(&large_b));
    }

    /// #811 r2: a full pool of IDLE in-flight images must not wedge a
    /// NEW image. The victim is chosen by MAX IDLE (last_progress), the
    /// boundary is the REAL 30 s (back-dated, no wall-clock sleep), and
    /// the accounting is asserted: the victim's bytes leave received_len.
    /// Reverting the accounting (dropping the saturating_sub) fails the
    /// received_len assert; reverting idle-based selection fails the
    /// victim-identity assert (the fresh image would be evicted instead).
    #[test]
    fn full_pool_displaces_the_idlest_image_after_the_grace_period() {
        let mut pool = RetainedPagePool::default();
        // Four stuck bindings: tags 0..3. Tag 0 is the IDLEST (back-dated
        // past the real 30 s boundary); tags 1..3 are FRESH (idle 0).
        for tag in 0..MAX_INFLIGHT_IMAGES {
            let binding = RetainedPageBinding {
                store_id: [tag as u8; 32],
                endorser: [1; 32],
                authorization: [2; 32],
                image_id: [tag as u8; 32],
            };
            pool.push(
                binding,
                RetainedPageV1::Page {
                    image_id: [tag as u8; 32],
                    index: 0,
                    bytes: vec![tag as u8; 16],
                },
            )
            .expect("bounded pending image");
        }
        {
            let mut images = pool.images.iter_mut().collect::<Vec<_>>();
            images.sort_by_key(|(binding, _)| binding.store_id);
            images[0].1.last_progress =
                Instant::now() - INFLIGHT_DISPLACE_AFTER - Duration::from_secs(1);
        }
        let received_before = pool.received_len;

        // A NEW binding displaces the IDLE image (tag 0) and completes
        // end-to-end (manifest + every page).
        let image = b"late-joiner history".to_vec();
        let pages = split_image(&image, 256).expect("pages");
        let mut fifth = RetainedPageBinding {
            store_id: [99; 32],
            endorser: [1; 32],
            authorization: [2; 32],
            image_id: [99; 32],
        };
        let mut completed = None;
        for page in pages {
            let frame = decode_page(&page).expect("framed").expect("page frame");
            if let RetainedPageV1::Manifest { image_id, .. } = &frame {
                fifth.image_id = *image_id;
            }
            completed = pool
                .push(fifth.clone(), frame)
                .expect("#811: an idle pool must not wedge the new image")
                .or(completed);
        }
        assert_eq!(completed.as_deref(), Some(image.as_slice()));
        // Victim identity: tag 0 is GONE (displaced), the fresh ones stay.
        assert!(!pool.images.contains_key(&RetainedPageBinding {
            store_id: [0; 32],
            endorser: [1; 32],
            authorization: [2; 32],
            image_id: [0; 32],
        }));
        for tag in 1..MAX_INFLIGHT_IMAGES {
            assert!(
                pool.images.contains_key(&RetainedPageBinding {
                    store_id: [tag as u8; 32],
                    endorser: [1; 32],
                    authorization: [2; 32],
                    image_id: [tag as u8; 32],
                }),
                "fresh image {tag} must not be the victim"
            );
        }
        // Accounting (finding 4): the victim's 16 bytes left the pool's
        // received_len; the completed image's bytes left too.
        assert_eq!(
            pool.received_len,
            received_before - 16,
            "the displaced victim's bytes are subtracted from received_len"
        );
    }

    /// #811 (ask 1) + r2 (finding 2): the within-grace refusal NAMES THE
    /// STORE so testnet evidence can be attributed (R10's lines could not
    /// be), and it is DETERMINISTIC — the four pending images are FRESH
    /// (idle 0 < the real 30 s grace), so nothing races the clock.
    #[test]
    fn full_pool_refusal_names_the_store() {
        let mut pool = RetainedPagePool::default();
        for tag in 0..MAX_INFLIGHT_IMAGES {
            let binding = RetainedPageBinding {
                store_id: [tag as u8; 32],
                endorser: [1; 32],
                authorization: [2; 32],
                image_id: [tag as u8; 32],
            };
            pool.push(
                binding,
                RetainedPageV1::Page {
                    image_id: [tag as u8; 32],
                    index: 0,
                    bytes: vec![tag as u8],
                },
            )
            .expect("bounded pending image");
        }
        let extra = RetainedPageBinding {
            store_id: [0x79; 32],
            endorser: [1; 32],
            authorization: [2; 32],
            image_id: [99; 32],
        };
        // Within the grace period the refusal stands — now with the
        // store id in the message.
        let err = pool
            .push(
                extra,
                RetainedPageV1::Page {
                    image_id: [99; 32],
                    index: 0,
                    bytes: vec![1],
                },
            )
            .expect_err("within the grace the pool is still bounded");
        let expected = hex::encode([0x79u8; 8]);
        assert!(
            err.to_string().contains(&expected),
            "the refusal must name the store, got: {err}"
        );
    }

    #[test]
    fn newer_same_authority_image_replaces_stalled_capacity_and_completes() {
        let mut pool = RetainedPagePool::default();
        let source = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id: [0; 32],
        };
        for tag in 0..MAX_INFLIGHT_IMAGES {
            let binding = RetainedPageBinding {
                image_id: [tag as u8; 32],
                ..source.clone()
            };
            pool.push(
                binding.clone(),
                RetainedPageV1::Page {
                    image_id: binding.image_id,
                    index: 0,
                    bytes: vec![tag as u8],
                },
            )
            .expect("stalled authenticated image");
        }

        let image = vec![9; 1024];
        let frames = split_image(&image, 256).expect("split fresh image");
        let decoded: Vec<_> = frames
            .iter()
            .map(|frame| decode_page(frame).expect("decode").expect("page frame"))
            .collect();
        let image_id = match decoded[0] {
            RetainedPageV1::Manifest { image_id, .. } => image_id,
            RetainedPageV1::Page { .. } => panic!("manifest first"),
        };
        let fresh = RetainedPageBinding { image_id, ..source };
        let mut completed = None;
        for frame in decoded {
            completed = pool
                .push(fresh.clone(), frame)
                .expect("fresh frame")
                .or(completed);
        }
        assert_eq!(completed.as_deref(), Some(image.as_slice()));
        assert!(!pool.images.contains_key(&fresh));
        assert_eq!(pool.received_len, 3, "three stalled images remain bounded");
    }

    #[test]
    fn full_pool_crosses_authority_custody_only_after_the_grace() {
        // #811 r2 (finding 1, the EXPLICIT contract): custody across
        // authorities WITHIN one store lasts INFLIGHT_DISPLACE_AFTER
        // (30 s), not the TTL. Within the grace the bounded refusal
        // stands; past it, the idle image IS displaced — the R10 wedge
        // was exactly divergent authority bindings in one store.
        let mut pool = RetainedPagePool::default();
        for tag in 0..MAX_INFLIGHT_IMAGES {
            let binding = RetainedPageBinding {
                store_id: [1; 32],
                endorser: [tag as u8; 32],
                authorization: [tag as u8; 32],
                image_id: [tag as u8; 32],
            };
            pool.push(
                binding.clone(),
                RetainedPageV1::Page {
                    image_id: binding.image_id,
                    index: 0,
                    bytes: vec![tag as u8],
                },
            )
            .expect("independent authority");
        }
        let newcomer = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [99; 32],
            authorization: [99; 32],
            image_id: [99; 32],
        };
        // FRESH pool: within the grace — refuse (deterministic: idle 0).
        assert!(pool
            .push(
                newcomer.clone(),
                RetainedPageV1::Page {
                    image_id: newcomer.image_id,
                    index: 0,
                    bytes: vec![99],
                },
            )
            .is_err());
        // Past the grace (back-dated): the idlest is displaced and the
        // newcomer's page is admitted.
        for pending in pool.images.values_mut() {
            pending.last_progress =
                Instant::now() - INFLIGHT_DISPLACE_AFTER - Duration::from_secs(1);
        }
        assert!(pool
            .push(
                newcomer,
                RetainedPageV1::Page {
                    image_id: [99; 32],
                    index: 0,
                    bytes: vec![99],
                },
            )
            .expect("past the grace the idle image is displaced")
            .is_none());
    }

    #[test]
    fn fresh_manifest_reclaims_same_authority_bytes_when_its_page_arrives() {
        let mut pool = RetainedPagePool::default();
        let source = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id: [0; 32],
        };
        for tag in 1..=2 {
            let binding = RetainedPageBinding {
                image_id: [tag; 32],
                ..source.clone()
            };
            pool.push(
                binding.clone(),
                RetainedPageV1::Page {
                    image_id: binding.image_id,
                    index: 0,
                    bytes: vec![tag; MAX_RETAINED_IMAGE_BYTES],
                },
            )
            .expect("same-authority stalled page");
        }
        let image = vec![7];
        let image_id = *blake3::hash(&image).as_bytes();
        let fresh = RetainedPageBinding { image_id, ..source };
        pool.push(
            fresh.clone(),
            RetainedPageV1::Manifest {
                image_id,
                total_len: 1,
                page_count: 1,
            },
        )
        .expect("fresh manifest");
        let complete = pool
            .push(
                fresh,
                RetainedPageV1::Page {
                    image_id,
                    index: 0,
                    bytes: image.clone(),
                },
            )
            .expect("fresh page reclaims stale byte custody");
        assert_eq!(complete.as_deref(), Some(image.as_slice()));
        assert_eq!(pool.received_len, MAX_RETAINED_IMAGE_BYTES);
    }

    #[test]
    fn byte_pressure_does_not_evict_a_different_authority() {
        let mut pool = RetainedPagePool::default();
        for tag in 1..=2 {
            let binding = RetainedPageBinding {
                store_id: [1; 32],
                endorser: [tag; 32],
                authorization: [tag; 32],
                image_id: [tag; 32],
            };
            pool.push(
                binding.clone(),
                RetainedPageV1::Page {
                    image_id: binding.image_id,
                    index: 0,
                    bytes: vec![tag; MAX_RETAINED_IMAGE_BYTES],
                },
            )
            .expect("independent byte custody");
        }
        let image_id = *blake3::hash(&[9]).as_bytes();
        let fresh = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [9; 32],
            authorization: [9; 32],
            image_id,
        };
        pool.push(
            fresh.clone(),
            RetainedPageV1::Manifest {
                image_id,
                total_len: 1,
                page_count: 1,
            },
        )
        .expect("independent manifest");
        assert!(pool
            .push(
                fresh,
                RetainedPageV1::Page {
                    image_id,
                    index: 0,
                    bytes: vec![9],
                },
            )
            .is_err());
        assert_eq!(pool.received_len, MAX_INFLIGHT_BYTES);
    }

    #[test]
    fn per_image_overflow_does_not_evict_valid_same_authority_custody() {
        let mut pool = RetainedPagePool::default();
        let source = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id: [1; 32],
        };
        pool.push(
            source.clone(),
            RetainedPageV1::Page {
                image_id: source.image_id,
                index: 0,
                bytes: vec![1],
            },
        )
        .expect("valid same-authority custody");
        let overflowing = RetainedPageBinding {
            image_id: [2; 32],
            ..source.clone()
        };
        pool.push(
            overflowing.clone(),
            RetainedPageV1::Page {
                image_id: overflowing.image_id,
                index: 0,
                bytes: vec![2; MAX_RETAINED_IMAGE_BYTES],
            },
        )
        .expect("maximum pending image");
        assert!(pool
            .push(
                overflowing,
                RetainedPageV1::Page {
                    image_id: [2; 32],
                    index: 1,
                    bytes: vec![3],
                },
            )
            .is_err());
        assert!(pool.images.contains_key(&source));
        assert_eq!(pool.received_len, MAX_RETAINED_IMAGE_BYTES + 1);
    }

    #[test]
    fn duplicate_page_at_capacity_is_idempotent_without_eviction_or_charge() {
        let mut pool = RetainedPagePool::default();
        let binding = RetainedPageBinding {
            store_id: [1; 32],
            endorser: [2; 32],
            authorization: [3; 32],
            image_id: [4; 32],
        };
        let page = RetainedPageV1::Page {
            image_id: binding.image_id,
            index: 0,
            bytes: vec![4; MAX_RETAINED_IMAGE_BYTES],
        };
        pool.push(binding.clone(), page.clone())
            .expect("maximum page");
        for tag in 5..8 {
            let other = RetainedPageBinding {
                store_id: [tag; 32],
                endorser: [tag; 32],
                authorization: [tag; 32],
                image_id: [tag; 32],
            };
            pool.push(
                other.clone(),
                RetainedPageV1::Page {
                    image_id: other.image_id,
                    index: 0,
                    bytes: vec![tag],
                },
            )
            .expect("independent pending image");
        }
        let before_len = pool.received_len;
        let before_bindings: Vec<_> = pool.images.keys().cloned().collect();
        assert!(pool
            .push(binding, page)
            .expect("duplicate remains idempotent")
            .is_none());
        assert_eq!(pool.received_len, before_len);
        assert_eq!(
            pool.images.keys().cloned().collect::<Vec<_>>(),
            before_bindings
        );
    }
}
