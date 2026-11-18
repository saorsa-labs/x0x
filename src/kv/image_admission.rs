//! Retained-image admission state of a group store (#1970, A10 amendment of
//! 18 Nov 2026).
//!
//! A group store serves its complete state as one retained image, and every
//! receiver refuses an image above [`HARD_IMAGE_LIMIT_BYTES`]. Local puts
//! stop at [`SOFT_IMAGE_LIMIT_BYTES`]; a remote merge is admitted when the
//! merged canonical image is at most the hard limit. This module holds the
//! per-store state that makes a refused merge visible and lets it heal: the
//! cached content-size bound and the per-source refusal table with its
//! back-off.

use crate::identity::AgentId;
use serde::Serialize;
use std::collections::HashMap;

/// The hard bound: the largest canonical retained image a replica holds
/// after a remote merge and the largest any receiver accepts.
pub const HARD_IMAGE_LIMIT_BYTES: usize = crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES;

/// The soft bound: a local put that would take the image past it is refused
/// (HTTP 507). The 4 MiB between the two limits is the headroom for
/// concurrent honest writes; it holds one maximum-size leaf gossip frame
/// (4 194 303 bytes), so one delta cannot by itself cross it.
pub const SOFT_IMAGE_LIMIT_BYTES: usize = 12 * 1024 * 1024;

/// First retry window after a refusal from one source.
const BACKOFF_INITIAL_MS: u64 = 30_000;
/// Longest retry window; every source is retried at least this often.
const BACKOFF_CAP_MS: u64 = 30 * 60_000;
/// A source with no refusal for this long leaves the table.
const REFUSAL_MEMORY_MS: u64 = 60 * 60_000;
/// Most sources the table tracks; the stalest one leaves first.
const MAX_REFUSAL_SOURCES: usize = 64;

/// Admission state of a group store's retained image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageState {
    /// At or below the soft limit: puts and merges are admitted.
    Ok,
    /// Above the soft limit, at or below the hard limit: puts are refused,
    /// merges that stay at or below the hard limit are admitted, the image
    /// is served.
    Full,
    /// At least one remote merge was refused because the merged image would
    /// pass the hard limit. This replica can differ from the refused source
    /// until a removal makes room and the retry merges.
    FullDiverged,
    /// The image itself is above the hard limit (only a store saved by an
    /// earlier version can be): it is not served and admits only a merge
    /// whose result is at or below the hard limit.
    OverLimit,
}

/// The latest refusal of one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageRefusal {
    /// Hex agent id of the delta writer or the image endorser.
    pub source: String,
    /// Refusals of this source, retries in back-off included.
    pub refusals: u64,
    /// The merged image size of the last measured refusal.
    pub image_bytes: u64,
    /// Unix milliseconds of the last refusal.
    pub at_ms: u64,
    /// Unix milliseconds when a merge from this source is measured again.
    pub retry_after_ms: u64,
}

/// Retained-image status of a store, as `GET /stores` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageStatus {
    pub state: ImageState,
    /// The exact canonical retained image size.
    pub image_bytes: u64,
    pub soft_limit_bytes: u64,
    pub hard_limit_bytes: u64,
    /// Remote merges refused since the store was opened.
    pub refused_merges: u64,
    /// Sources with a refusal in the table.
    pub diverged_sources: usize,
    /// The most recent refusal, if any source is in the table.
    pub last_refusal: Option<ImageRefusal>,
}

#[derive(Debug, Clone, Copy)]
struct ContentBound {
    version: u64,
    keys_version: u64,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct Refusal {
    count: u64,
    last_image: u64,
    last_at_ms: u64,
    retry_after_ms: u64,
    backoff_ms: u64,
}

/// Non-persisted admission state carried by a `KvStore`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImageAdmission {
    /// An upper bound on the content part (OR-Set and live entries) of the
    /// canonical image, valid while the store and OR-Set versions match.
    content: Option<ContentBound>,
    refusals: HashMap<AgentId, Refusal>,
    refused_total: u64,
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

impl ImageAdmission {
    pub(crate) fn cached_content(&self, version: u64, keys_version: u64) -> Option<u64> {
        self.content
            .filter(|c| c.version == version && c.keys_version == keys_version)
            .map(|c| c.bytes)
    }

    pub(crate) fn set_content(&mut self, version: u64, keys_version: u64, bytes: u64) {
        self.content = Some(ContentBound {
            version,
            keys_version,
            bytes,
        });
    }

    pub(crate) fn invalidate_content(&mut self) {
        self.content = None;
    }

    /// The last measured image of `source` while its retry window is open.
    pub(crate) fn in_backoff(&self, source: &AgentId, now: u64) -> Option<u64> {
        self.refusals
            .get(source)
            .filter(|r| now < r.retry_after_ms)
            .map(|r| r.last_image)
    }

    /// Count a refusal made inside the source's retry window, unmeasured.
    pub(crate) fn note_suppressed(&mut self, source: &AgentId, now: u64) {
        self.refused_total = self.refused_total.saturating_add(1);
        if let Some(r) = self.refusals.get_mut(source) {
            r.count = r.count.saturating_add(1);
            r.last_at_ms = now;
        }
    }

    /// Record a measured refusal and open (or widen) the source's retry
    /// window. Returns whether to log it: once per source per window.
    pub(crate) fn note_refusal(&mut self, source: AgentId, image: u64, now: u64) -> bool {
        self.refused_total = self.refused_total.saturating_add(1);
        self.prune(now);
        if !self.refusals.contains_key(&source) && self.refusals.len() >= MAX_REFUSAL_SOURCES {
            if let Some(stalest) = self
                .refusals
                .iter()
                .min_by_key(|(_, r)| r.last_at_ms)
                .map(|(id, _)| *id)
            {
                self.refusals.remove(&stalest);
            }
        }
        let r = self.refusals.entry(source).or_insert(Refusal {
            count: 0,
            last_image: image,
            last_at_ms: now,
            retry_after_ms: 0,
            backoff_ms: 0,
        });
        r.count = r.count.saturating_add(1);
        r.last_image = image;
        r.last_at_ms = now;
        let log = now >= r.retry_after_ms;
        if log {
            r.backoff_ms = if r.backoff_ms == 0 {
                BACKOFF_INITIAL_MS
            } else {
                r.backoff_ms.saturating_mul(2).min(BACKOFF_CAP_MS)
            };
            r.retry_after_ms = now.saturating_add(r.backoff_ms);
        }
        log
    }

    /// A full image from `source` merged: this replica holds its state.
    pub(crate) fn clear(&mut self, source: &AgentId) {
        self.refusals.remove(source);
    }

    /// A removal made room: retry every refused source now, from the first
    /// window again.
    pub(crate) fn rearm(&mut self) {
        for r in self.refusals.values_mut() {
            r.retry_after_ms = 0;
            r.backoff_ms = 0;
        }
    }

    fn prune(&mut self, now: u64) {
        self.refusals
            .retain(|_, r| now < r.last_at_ms.saturating_add(REFUSAL_MEMORY_MS));
    }

    pub(crate) fn status(&self, image_bytes: u64, now: u64) -> ImageStatus {
        let live: Vec<(&AgentId, &Refusal)> = self
            .refusals
            .iter()
            .filter(|(_, r)| now < r.last_at_ms.saturating_add(REFUSAL_MEMORY_MS))
            .collect();
        let state = if image_bytes > HARD_IMAGE_LIMIT_BYTES as u64 {
            ImageState::OverLimit
        } else if !live.is_empty() {
            ImageState::FullDiverged
        } else if image_bytes > SOFT_IMAGE_LIMIT_BYTES as u64 {
            ImageState::Full
        } else {
            ImageState::Ok
        };
        let last_refusal = live
            .iter()
            .max_by_key(|(_, r)| r.last_at_ms)
            .map(|(id, r)| ImageRefusal {
                source: hex::encode(id.as_bytes()),
                refusals: r.count,
                image_bytes: r.last_image,
                at_ms: r.last_at_ms,
                retry_after_ms: r.retry_after_ms,
            });
        ImageStatus {
            state,
            image_bytes,
            soft_limit_bytes: SOFT_IMAGE_LIMIT_BYTES as u64,
            hard_limit_bytes: HARD_IMAGE_LIMIT_BYTES as u64,
            refused_merges: self.refused_total,
            diverged_sources: live.len(),
            last_refusal,
        }
    }
}
