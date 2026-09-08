//! Bounded, nonmutating observations of two independently sampled DM stores.

use crate::{dm_capability::CapabilityStore, peer_relay::PeerRelay};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Maximum distinct retained agents in the default diagnostic listing.
pub const MAX_PER_PEER_ROWS: usize = 512;

/// Parse the exact-agent diagnostic filter without allocating from input length.
///
/// # Errors
/// Returns an error unless the input is exactly 32 bytes of hexadecimal.
pub fn parse_agent_filter(value: &str) -> Result<[u8; 32], &'static str> {
    let mut bytes = [0; 32];
    if value.len() != 64 || hex::decode_to_slice(value, &mut bytes).is_err() {
        return Err("agent must be exactly 64 hexadecimal characters (32 bytes)");
    }
    Ok(bytes)
}

pub(crate) fn select_key(keys: &mut BTreeSet<[u8; 32]>, key: [u8; 32], filter: Option<[u8; 32]>) {
    if filter.is_some_and(|wanted| wanted != key) || keys.contains(&key) {
        return;
    }
    if keys.len() == MAX_PER_PEER_ROWS {
        if keys.last().is_some_and(|last| key >= *last) {
            return;
        }
        keys.pop_last();
    }
    keys.insert(key);
}

fn serialize_id<S: serde::Serializer>(id: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(id))
}

pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Serialize)]
pub(crate) struct CachedCapabilityObservation {
    pub digest_support: bool,
    #[serde(serialize_with = "serialize_id")]
    pub machine_id: [u8; 32],
    pub source: &'static str,
    pub state: &'static str,
    pub advert_created_unix_ms: u64,
    pub expires_in_ms: u64,
}

#[derive(Clone, Serialize)]
pub(crate) struct ExtensionObservation {
    pub digest_support: bool,
    #[serde(serialize_with = "serialize_id")]
    pub machine_id: [u8; 32],
    pub source: &'static str,
    pub state: &'static str,
    pub created_at_unix_ms: u64,
    pub expires_in_ms: u64,
    pub machine_matches_base: Option<bool>,
}

pub(crate) struct CapabilityObservation {
    pub base_advert: Option<CachedCapabilityObservation>,
    pub digest_extension: Option<ExtensionObservation>,
}

#[derive(Default, Serialize)]
pub(crate) struct CapabilityTotals {
    pub distinct_agents: usize,
    pub base_fresh: usize,
    pub base_expired_retained: usize,
    pub extension_present: usize,
    pub extension_fresh: usize,
    pub extension_expired_retained: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct BaselineObservation {
    pub state: &'static str,
    pub age_ms: u64,
}

#[derive(Default, Serialize)]
pub(crate) struct BaselineTotals {
    pub distinct_agents: usize,
    pub fresh: usize,
    pub expired_retained: usize,
}

pub(crate) struct StoreSnapshot<R, T> {
    // None means unavailable, never an empty or recovered poisoned store.
    pub totals: Option<T>,
    pub rows: BTreeMap<[u8; 32], R>,
}

impl<R, T> StoreSnapshot<R, T> {
    pub fn unavailable() -> Self {
        Self {
            totals: None,
            rows: BTreeMap::new(),
        }
    }
}

/// Sample retained capability and relay-baseline state without pruning either store.
///
/// Each store scans its map in O(n) time with at most 512 selected keys/rows;
/// the stores are sampled separately, not atomically. The default listing is
/// the first 512 distinct retained agent IDs. An exact filter also represents
/// absent (unknown-history) and unavailable state explicitly. This is not an
/// effective capability, forwarding decision, or fleet census.
pub fn snapshot(
    capabilities: &CapabilityStore,
    relay: &PeerRelay,
    agent: Option<[u8; 32]>,
) -> serde_json::Value {
    let capability = capabilities.digest_diagnostic_snapshot(Instant::now(), agent);
    let baseline = relay.digest_diagnostic_snapshot(Instant::now(), agent);
    join_snapshots(capability, baseline, agent)
}

fn record_state(available: bool, present: bool) -> &'static str {
    if !available {
        "unavailable"
    } else if present {
        "retained"
    } else {
        "absent_unknown_history"
    }
}

pub(crate) fn join_snapshots(
    capability: StoreSnapshot<CapabilityObservation, CapabilityTotals>,
    baseline: StoreSnapshot<BaselineObservation, BaselineTotals>,
    agent: Option<[u8; 32]>,
) -> serde_json::Value {
    let mut keys = BTreeSet::new();
    for key in capability.rows.keys().chain(baseline.rows.keys()) {
        select_key(&mut keys, *key, agent);
    }
    if let Some(agent) = agent {
        keys.insert(agent);
    }
    let cap_available = capability.totals.is_some();
    let relay_available = baseline.totals.is_some();
    // No exact global-union count: only compare each independently sampled
    // store's total with the number of its IDs represented in the final set.
    let truncated = agent.is_none()
        && (capability.totals.as_ref().is_some_and(|t| {
            t.distinct_agents
                > keys
                    .iter()
                    .filter(|k| capability.rows.contains_key(*k))
                    .count()
        }) || baseline.totals.as_ref().is_some_and(|t| {
            t.distinct_agents
                > keys
                    .iter()
                    .filter(|k| baseline.rows.contains_key(*k))
                    .count()
        }));
    let rows: Vec<_> = keys.iter().map(|key| {
        let cap = capability.rows.get(key);
        let observed = baseline.rows.get(key);
        serde_json::json!({
            "agent_id": hex::encode(key),
            "capability_record_state": record_state(cap_available, cap.is_some()),
            "relay_record_state": record_state(relay_available, observed.is_some()),
            "base_advert": cap.and_then(|c| c.base_advert.as_ref()),
            "digest_extension": cap.and_then(|c| c.digest_extension.as_ref()),
            "v2_observed": observed,
            "fresh_forward_downgrade_baseline": relay_available.then(|| observed.is_some_and(|b| b.state == "fresh")),
        })
    }).collect();
    serde_json::json!({
        "schema": 2,
        "store_state_capability": if cap_available { "available" } else { "unavailable" },
        "store_state_relay": if relay_available { "available" } else { "unavailable" },
        "rows": rows,
        "truncated": truncated,
        "totals": { "capability": capability.totals, "relay": baseline.totals },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u16) -> [u8; 32] {
        let mut key = [0; 32];
        key[30..].copy_from_slice(&i.to_be_bytes());
        key
    }

    #[test]
    fn bounded_join_overlap_and_disjoint_boundary() {
        for relay_start in [0, 256, 512] {
            let cap = StoreSnapshot {
                totals: Some(CapabilityTotals {
                    distinct_agents: 512,
                    ..Default::default()
                }),
                rows: (0..512)
                    .map(|i| {
                        (
                            key(i),
                            CapabilityObservation {
                                base_advert: None,
                                digest_extension: None,
                            },
                        )
                    })
                    .collect(),
            };
            let relay = StoreSnapshot {
                totals: Some(BaselineTotals {
                    distinct_agents: 512,
                    fresh: 512,
                    expired_retained: 0,
                }),
                rows: (relay_start..relay_start + 512)
                    .map(|i| {
                        (
                            key(i),
                            BaselineObservation {
                                state: "fresh",
                                age_ms: 0,
                            },
                        )
                    })
                    .collect(),
            };
            let view = join_snapshots(cap, relay, None);
            assert_eq!(view["rows"].as_array().unwrap().len(), 512);
            assert_eq!(view["truncated"], relay_start != 0);
            for i in 0..512 {
                assert_eq!(view["rows"][i]["agent_id"], hex::encode(key(i as u16)));
                assert_eq!(
                    view["rows"][i]["fresh_forward_downgrade_baseline"],
                    i >= usize::from(relay_start)
                );
            }
            assert!(view["totals"].get("union").is_none());
        }
    }

    #[test]
    fn exact_absent_unknown_history_and_filter_validation() {
        let caps = CapabilityStore::new();
        let relay = PeerRelay::default();
        let view = snapshot(&caps, &relay, Some(key(900)));
        assert_eq!(view["rows"].as_array().unwrap().len(), 1);
        assert_eq!(
            view["rows"][0]["capability_record_state"],
            "absent_unknown_history"
        );
        assert_eq!(
            view["rows"][0]["relay_record_state"],
            "absent_unknown_history"
        );
        assert_eq!(view["rows"][0]["fresh_forward_downgrade_baseline"], false);
        assert_eq!(view["totals"]["capability"]["distinct_agents"], 0);
        assert_eq!(parse_agent_filter(&"AB".repeat(32)), Ok([0xab; 32]));
        for input in [
            "".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            assert!(parse_agent_filter(&input).is_err());
        }
    }

    #[test]
    fn unavailable_capability_keeps_relay_union_and_derived_value() {
        let view = join_snapshots(
            StoreSnapshot::unavailable(),
            StoreSnapshot {
                totals: Some(BaselineTotals {
                    distinct_agents: 1,
                    fresh: 1,
                    expired_retained: 0,
                }),
                rows: [(
                    key(1),
                    BaselineObservation {
                        state: "fresh",
                        age_ms: 5,
                    },
                )]
                .into_iter()
                .collect(),
            },
            None,
        );
        assert_eq!(view["rows"][0]["capability_record_state"], "unavailable");
        assert_eq!(view["rows"][0]["fresh_forward_downgrade_baseline"], true);
        assert!(view["totals"]["capability"].is_null());
    }
}
