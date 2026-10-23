//! Remote GUI show typed DMs (ADR 0083 slice 3).
//!
//! The receiver decides owner trust before it decodes a body. A length
//! prefix must not allocate past the body cap.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use super::show::GuiShowOutcome;
use super::view_route;

/// Show-request typed DM prefix. The NUL stops a user DM from matching.
pub const SHOW_REQUEST_PREFIX: &[u8] = b"x0x-gui-show-v1\0";
/// Show-result typed DM prefix.
pub const SHOW_RESULT_PREFIX: &[u8] = b"x0x-gui-show-result-v1\0";
/// Activity query and reply share this prefix. The bincode enum index
/// selects the body.
pub const ACTIVITY_PREFIX: &[u8] = b"x0x-gui-activity-v1\0";
/// Registry name for [`crate::dm::CapabilityRegistry::GUI_SHOW_V1`].
pub const CAPABILITY_NAME: &str = "gui_show_v1";
/// How long a visible GUI still counts as the active machine.
pub const ACTIVE_WINDOW_SECS: u64 = 15 * 60;
/// Clock skew accepted for `issued_at` and for a future visibility stamp.
pub const FRESHNESS_SECS: u64 = 120;
/// How long the requester waits for a result or activity reply.
pub const RESULT_WAIT: Duration = Duration::from_secs(10);
/// Longest `view` the target will open. Longer views are `invalid_view`.
pub const MAX_VIEW_BYTES: usize = 256;
/// ADR 0050 replay cache window.
pub const REPLAY_SECS: u64 = 630;

/// `16 + 8 + MAX_VIEW_BYTES + 8 + 1`, rounded up. Bounds bincode allocation.
const SHOW_BODY_MAX: usize = 320;
/// Activity bodies are a request id plus a small reply. No view string.
const ACTIVITY_BODY_MAX: usize = 64;
/// Bound on remembered `(sender, request_id)` pairs.
const REPLAY_CAP: usize = 4096;

/// One remote show request. The view is a route, never a URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiShowDmRequest {
    pub request_id: [u8; 16],
    pub view: String,
    pub issued_at: u64,
    pub via_rider: bool,
}

/// Result returned to the requester. Names stay on the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiShowDmResult {
    pub request_id: [u8; 16],
    pub outcome: GuiShowOutcome,
}

/// One prefix, two bodies, as the ADR's `|` alternation. Bincode variant
/// index is the discriminant. Do not add other fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuiActivityBody {
    Query {
        request_id: [u8; 16],
    },
    Reply {
        request_id: [u8; 16],
        last_gui_visible_at: Option<u64>,
        remote_enabled: bool,
    },
}

/// Which gui-show prefix a payload claims. This does not decode the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmClass {
    ShowRequest,
    ShowResult,
    Activity,
}

/// Show-request decision before the opener runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShowIngress {
    /// Prefix matched, sender not owner-trusted. Body was not decoded.
    /// `request_id` is peeked when 16 body bytes are present.
    Untrusted {
        request_id: Option<[u8; 16]>,
    },
    Trusted(TrustedShow),
}

/// A show request from an owner-trusted sender, after a bounded decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedShow {
    pub request: GuiShowDmRequest,
    pub replay: bool,
    pub fresh: bool,
    pub view_ok: bool,
    /// Present only when [`TrustedShow::view_ok`] is true.
    pub route: Option<String>,
}

/// What the target does with one show request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveAction {
    /// Replay. No display and no result DM.
    Drop,
    /// Send this outcome. Do not display.
    Reply(GuiShowOutcome),
    /// Caller runs the opener or navigate path.
    Display { route: String, via_rider: bool },
}

/// Activity message after the trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityIngress {
    /// Not trusted, or not our message. No reply.
    Ignore,
    Query {
        request_id: [u8; 16],
    },
    /// Only the [`GuiActivityBody::Reply`] variant.
    Reply(GuiActivityBody),
}

/// One machine that answered an activity query, plus this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityCandidate {
    pub machine_id: [u8; 32],
    pub last_gui_visible_at: Option<u64>,
    pub remote_enabled: bool,
}

/// The machine whose GUI was visible most recently, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveChoice {
    Machine([u8; 32]),
    /// Hex machine ids, sorted. Includes machines that did not qualify.
    None {
        candidates: Vec<String>,
    },
}

/// `(sender, request_id)` seen inside [`REPLAY_SECS`].
#[derive(Debug, Default)]
pub struct ReplayCache {
    /// Expiry is unix seconds. The map drops the soonest expiry past 4096 entries.
    entries: HashMap<([u8; 32], [u8; 16]), u64>,
}

impl ReplayCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Returns true when this id was already seen and is still inside
    /// [`REPLAY_SECS`]. An expired id is recorded again and returns false.
    pub fn observe(&mut self, sender: &[u8; 32], request_id: [u8; 16], now_unix: u64) -> bool {
        let key = (*sender, request_id);
        if let Some(expires_at) = self.entries.get(&key).copied() {
            if now_unix < expires_at {
                return true;
            }
        }
        self.entries.retain(|_, expires_at| *expires_at > now_unix);
        if !self.entries.contains_key(&key) && self.entries.len() >= REPLAY_CAP {
            self.evict_soonest();
        }
        let expires_at = now_unix.saturating_add(REPLAY_SECS);
        self.entries.insert(key, expires_at);
        false
    }

    fn evict_soonest(&mut self) {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, expires_at)| *expires_at)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.entries.remove(&key);
    }
}

/// Waiters for in-flight show results and activity replies.
///
/// A second waiter for the same id drops the first sender. That does not panic.
#[derive(Debug, Default)]
pub struct RemoteHub {
    show: Mutex<HashMap<[u8; 16], oneshot::Sender<GuiShowDmResult>>>,
    activity: Mutex<HashMap<[u8; 16], oneshot::Sender<GuiActivityBody>>>,
}

impl RemoteHub {
    /// Empty hub.
    #[must_use]
    pub fn new() -> Self {
        Self {
            show: Mutex::new(HashMap::new()),
            activity: Mutex::new(HashMap::new()),
        }
    }

    /// Register a waiter. Replaces any waiter already bound to `request_id`.
    pub fn wait_show(&self, request_id: [u8; 16]) -> oneshot::Receiver<GuiShowDmResult> {
        let (tx, rx) = oneshot::channel();
        self.show
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(request_id, tx);
        rx
    }

    /// Deliver a result. No waiter means no work.
    pub fn complete_show(&self, result: GuiShowDmResult) {
        if let Some(tx) = self
            .show
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&result.request_id)
        {
            let _ = tx.send(result);
        }
    }

    /// Register a waiter for an activity reply.
    pub fn wait_activity(&self, request_id: [u8; 16]) -> oneshot::Receiver<GuiActivityBody> {
        let (tx, rx) = oneshot::channel();
        self.activity
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(request_id, tx);
        rx
    }

    /// Deliver an activity body. No waiter means no work.
    pub fn complete_activity(&self, body: GuiActivityBody) {
        let request_id = activity_request_id(&body);
        if let Some(tx) = self
            .activity
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&request_id)
        {
            let _ = tx.send(body);
        }
    }
}

fn activity_request_id(body: &GuiActivityBody) -> [u8; 16] {
    match body {
        GuiActivityBody::Query { request_id } | GuiActivityBody::Reply { request_id, .. } => {
            *request_id
        }
    }
}

/// Prefix only. Activity's request id is not the first 16 body bytes, so
/// this returns `None` for [`ACTIVITY_PREFIX`].
#[must_use]
pub fn classify_prefix(payload: &[u8]) -> Option<DmClass> {
    if payload.starts_with(SHOW_REQUEST_PREFIX) {
        Some(DmClass::ShowRequest)
    } else if payload.starts_with(SHOW_RESULT_PREFIX) {
        Some(DmClass::ShowResult)
    } else if payload.starts_with(ACTIVITY_PREFIX) {
        Some(DmClass::Activity)
    } else {
        None
    }
}

/// Copy the request id when the body is a show request or a show result.
///
/// Activity is not peeked. Its bincode enum index sits in front of the id.
#[must_use]
pub fn peek_request_id(payload: &[u8]) -> Option<[u8; 16]> {
    let body = if payload.starts_with(SHOW_RESULT_PREFIX) {
        payload.get(SHOW_RESULT_PREFIX.len()..)?
    } else if payload.starts_with(SHOW_REQUEST_PREFIX) {
        payload.get(SHOW_REQUEST_PREFIX.len()..)?
    } else {
        return None;
    };
    let bytes = body.get(..16)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(bytes);
    Some(id)
}

/// Classify a show request. `trusted` is the caller's owner-trust result.
///
/// When `trusted` is false the body is not deserialized.
///
/// Returns `None` when the payload is not a show request, or a trusted
/// body is unusable.
pub fn ingress_show(
    trusted: bool,
    payload: &[u8],
    sender: &[u8; 32],
    now_unix: u64,
    replay: &mut ReplayCache,
) -> Option<ShowIngress> {
    if classify_prefix(payload) != Some(DmClass::ShowRequest) {
        return None;
    }
    if !trusted {
        return Some(ShowIngress::Untrusted {
            request_id: peek_request_id(payload),
        });
    }
    let request = decode_show_request(payload).ok()?;
    let replay_hit = replay.observe(sender, request.request_id, now_unix);
    let fresh = request.issued_at.abs_diff(now_unix) <= FRESHNESS_SECS;
    // Length is its own check in `receive_action`. Parse still runs so a
    // long view that trims to a real route is not treated as a bad grammar.
    let parsed = view_route::parse(&request.view).ok();
    let view_ok = parsed.is_some();
    let route = parsed.map(|view| view.as_route());
    Some(ShowIngress::Trusted(TrustedShow {
        request,
        replay: replay_hit,
        fresh,
        view_ok,
        route,
    }))
}

/// Turn a trusted or untrusted ingress into a display decision.
///
/// Untrusted senders are refused before `remote_enabled` is read.
/// After trust the order is replay, freshness, remote enable, view,
/// block, rate limit, then display.
#[must_use]
pub fn receive_action(
    ingress: &ShowIngress,
    remote_enabled: bool,
    blocked: bool,
    rate_limited: bool,
) -> ReceiveAction {
    match ingress {
        ShowIngress::Untrusted { request_id: None } => ReceiveAction::Drop,
        ShowIngress::Untrusted {
            request_id: Some(_),
        } => ReceiveAction::Reply(GuiShowOutcome::Refused),
        ShowIngress::Trusted(show) => {
            action_for_trusted(show, remote_enabled, blocked, rate_limited)
        }
    }
}

fn action_for_trusted(
    show: &TrustedShow,
    remote_enabled: bool,
    blocked: bool,
    rate_limited: bool,
) -> ReceiveAction {
    if show.replay {
        return ReceiveAction::Drop;
    }
    if !show.fresh {
        return ReceiveAction::Reply(GuiShowOutcome::Refused);
    }
    if !remote_enabled {
        return ReceiveAction::Reply(GuiShowOutcome::Disabled);
    }
    if show.request.view.len() > MAX_VIEW_BYTES {
        return ReceiveAction::Reply(GuiShowOutcome::InvalidView);
    }
    if !show.view_ok {
        return ReceiveAction::Reply(GuiShowOutcome::InvalidView);
    }
    if blocked {
        return ReceiveAction::Reply(GuiShowOutcome::Refused);
    }
    if rate_limited {
        return ReceiveAction::Reply(GuiShowOutcome::RateLimited);
    }
    let route = show.route.clone().unwrap_or_default();
    ReceiveAction::Display {
        route,
        via_rider: show.request.via_rider,
    }
}

/// Classify an activity payload. A false `trusted` does not decode the body.
#[must_use]
pub fn ingress_activity(trusted: bool, payload: &[u8]) -> ActivityIngress {
    if classify_prefix(payload) != Some(DmClass::Activity) {
        return ActivityIngress::Ignore;
    }
    if !trusted {
        return ActivityIngress::Ignore;
    }
    match decode_activity(payload) {
        Ok(GuiActivityBody::Query { request_id }) => ActivityIngress::Query { request_id },
        Ok(body @ GuiActivityBody::Reply { .. }) => ActivityIngress::Reply(body),
        Err(()) => ActivityIngress::Ignore,
    }
}

/// Activity reply the target sends.
///
/// `remote_enabled == false` forces `last_gui_visible_at` to `None`, so a
/// disabled daemon does not advertise a visibility time.
#[must_use]
pub fn activity_reply(
    request_id: [u8; 16],
    remote_enabled: bool,
    last_visible: Option<u64>,
) -> GuiActivityBody {
    let last_gui_visible_at = if remote_enabled { last_visible } else { None };
    GuiActivityBody::Reply {
        request_id,
        last_gui_visible_at,
        remote_enabled,
    }
}

/// Pick the newest visible machine inside the active window.
///
/// A candidate with `remote_enabled == false` or no stamp does not win.
/// Its machine id is still listed when the result is [`ActiveChoice::None`].
/// Equal stamps keep the earlier candidate in `candidates`.
#[must_use]
pub fn select_active(now_unix: u64, candidates: &[ActivityCandidate]) -> ActiveChoice {
    let window_start = now_unix.saturating_sub(ACTIVE_WINDOW_SECS);
    let window_end = now_unix.saturating_add(FRESHNESS_SECS);
    let mut best: Option<(usize, u64)> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if !candidate.remote_enabled {
            continue;
        }
        let Some(stamp) = candidate.last_gui_visible_at else {
            continue;
        };
        if stamp < window_start || stamp > window_end {
            continue;
        }
        match best {
            Some((_, best_stamp)) if stamp <= best_stamp => {}
            _ => best = Some((index, stamp)),
        }
    }
    if let Some((index, _)) = best {
        return ActiveChoice::Machine(candidates[index].machine_id);
    }
    let mut ids: Vec<String> = candidates
        .iter()
        .map(|candidate| hex::encode(candidate.machine_id))
        .collect();
    ids.sort();
    ActiveChoice::None { candidates: ids }
}

impl GuiShowDmRequest {
    /// `SHOW_REQUEST_PREFIX` then canonical bincode.
    ///
    /// `None` when the value does not fit in the show body cap.
    pub fn to_dm_payload(&self) -> Option<Vec<u8>> {
        encode_prefixed(SHOW_REQUEST_PREFIX, self, SHOW_BODY_MAX).ok()
    }
}

impl GuiShowDmResult {
    /// `SHOW_RESULT_PREFIX` then canonical bincode.
    ///
    /// `None` when encode fails or the body exceeds the show cap.
    pub fn to_dm_payload(&self) -> Option<Vec<u8>> {
        encode_prefixed(SHOW_RESULT_PREFIX, self, SHOW_BODY_MAX).ok()
    }
}

impl GuiActivityBody {
    /// `ACTIVITY_PREFIX` then canonical bincode.
    ///
    /// `None` when encode fails or the body exceeds the activity cap.
    pub fn to_dm_payload(&self) -> Option<Vec<u8>> {
        encode_prefixed(ACTIVITY_PREFIX, self, ACTIVITY_BODY_MAX).ok()
    }
}

/// Decode a show result. Call only after owner trust.
///
/// `None` on a wrong prefix, a body over the cap, or non-canonical bincode.
pub(crate) fn decode_show_result(payload: &[u8]) -> Option<GuiShowDmResult> {
    decode_prefixed(SHOW_RESULT_PREFIX, payload, SHOW_BODY_MAX).ok()
}

fn decode_show_request(payload: &[u8]) -> Result<GuiShowDmRequest, ()> {
    let body = payload.strip_prefix(SHOW_REQUEST_PREFIX).ok_or(())?;
    if !show_string_len_bounded(body) {
        return Err(());
    }
    decode_body(body, SHOW_BODY_MAX)
}

fn decode_activity(payload: &[u8]) -> Result<GuiActivityBody, ()> {
    decode_prefixed(ACTIVITY_PREFIX, payload, ACTIVITY_BODY_MAX)
}

/// The view length sits at a fixed offset. Reject a huge length before
/// `bincode` can allocate it. Views over [`MAX_VIEW_BYTES`] but inside the
/// body cap still decode, so the target can answer `invalid_view`.
fn show_string_len_bounded(body: &[u8]) -> bool {
    if body.len() > SHOW_BODY_MAX {
        return false;
    }
    let Some(len_bytes) = body.get(16..24) else {
        return false;
    };
    let mut raw = [0u8; 8];
    raw.copy_from_slice(len_bytes);
    u64::from_le_bytes(raw) <= SHOW_BODY_MAX as u64
}

fn encode_prefixed<T: Serialize>(prefix: &[u8], value: &T, limit: usize) -> Result<Vec<u8>, ()> {
    let body = encode_body(value, limit)?;
    let mut out = Vec::with_capacity(prefix.len() + body.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Fixint little-endian bincode, same options for encode and the canonical check.
fn codec(limit: usize) -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(limit as u64)
        .reject_trailing_bytes()
}

fn encode_body<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, ()> {
    use bincode::Options;
    let body = codec(limit).serialize(value).map_err(|_| ())?;
    if body.len() > limit {
        return Err(());
    }
    Ok(body)
}

fn decode_prefixed<T>(prefix: &[u8], payload: &[u8], limit: usize) -> Result<T, ()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let body = payload.strip_prefix(prefix).ok_or(())?;
    decode_body(body, limit)
}

fn decode_body<T>(body: &[u8], limit: usize) -> Result<T, ()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if body.len() > limit {
        return Err(());
    }
    use bincode::Options;
    let value = codec(limit).deserialize(body).map_err(|_| ())?;
    let canonical = codec(limit).serialize(&value).map_err(|_| ())?;
    if canonical.as_slice() != body {
        return Err(());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot::error::TryRecvError;

    fn request(view: &str, issued_at: u64, id: [u8; 16]) -> Vec<u8> {
        GuiShowDmRequest {
            request_id: id,
            view: view.to_string(),
            issued_at,
            via_rider: false,
        }
        .to_dm_payload()
        .unwrap()
    }

    fn trusted_ingress(payload: &[u8], now: u64, cache: &mut ReplayCache) -> ShowIngress {
        ingress_show(true, payload, &[7; 32], now, cache).unwrap()
    }

    #[test]
    fn untrusted_show_is_refused_without_decoding_view() {
        let mut cache = ReplayCache::new();
        let mut bomb = SHOW_REQUEST_PREFIX.to_vec();
        bomb.extend_from_slice(&[9; 16]);
        bomb.extend_from_slice(&u64::MAX.to_le_bytes());
        let ingress = ingress_show(false, &bomb, &[1; 32], 1_000, &mut cache).unwrap();
        assert!(matches!(
            ingress,
            ShowIngress::Untrusted {
                request_id: Some(id)
            } if id == [9; 16]
        ));
        assert_eq!(
            receive_action(&ingress, false, false, false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
        assert!(ingress_show(true, &bomb, &[1; 32], 1_000, &mut cache).is_none());

        let url = request("https://evil.example", 1_000, [2; 16]);
        let ingress = ingress_show(false, &url, &[1; 32], 1_000, &mut cache).unwrap();
        assert!(matches!(ingress, ShowIngress::Untrusted { .. }));
        assert_eq!(
            receive_action(&ingress, false, false, false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );

        let short = SHOW_REQUEST_PREFIX.to_vec();
        let ingress = ingress_show(false, &short, &[1; 32], 1_000, &mut cache).unwrap();
        assert!(matches!(
            ingress,
            ShowIngress::Untrusted { request_id: None }
        ));
        assert_eq!(
            receive_action(&ingress, true, false, false),
            ReceiveAction::Drop
        );
    }

    #[test]
    fn replay_is_dropped() {
        let now = 5_000u64;
        let payload = request("people", now, [5; 16]);
        let sender = [9u8; 32];
        let mut cache = ReplayCache::new();
        let first = ingress_show(true, &payload, &sender, now, &mut cache).unwrap();
        assert!(matches!(
            receive_action(&first, true, false, false),
            ReceiveAction::Display { .. }
        ));
        let second = ingress_show(true, &payload, &sender, now + 200, &mut cache).unwrap();
        assert_eq!(
            receive_action(&second, true, false, false),
            ReceiveAction::Drop
        );
        let other = ingress_show(true, &payload, &[8; 32], now, &mut cache).unwrap();
        assert!(matches!(
            receive_action(&other, true, false, false),
            ReceiveAction::Display { .. }
        ));
    }

    #[test]
    fn stale_issued_at_is_refused() {
        let now = 10_000u64;
        let payload = request("people", now + 1_000, [3; 16]);
        let mut cache = ReplayCache::new();
        let ingress = trusted_ingress(&payload, now, &mut cache);
        let action = receive_action(&ingress, true, false, false);
        assert_eq!(action, ReceiveAction::Reply(GuiShowOutcome::Refused));
        assert!(!matches!(action, ReceiveAction::Display { .. }));
        // Freshness is before remote enable, so a stale request is Refused.
        assert_eq!(
            receive_action(&ingress, false, false, false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
    }

    #[test]
    fn url_view_is_invalid_on_target() {
        let now = 80u64;
        let payload = request("https://evil.example", now, [4; 16]);
        let mut cache = ReplayCache::new();
        let ingress = trusted_ingress(&payload, now, &mut cache);
        assert_eq!(
            receive_action(&ingress, true, false, false),
            ReceiveAction::Reply(GuiShowOutcome::InvalidView)
        );
        // View is checked before the block list.
        assert_eq!(
            receive_action(&ingress, true, true, false),
            ReceiveAction::Reply(GuiShowOutcome::InvalidView)
        );

        let mut long = String::from("people");
        long.push_str(&" ".repeat(MAX_VIEW_BYTES + 1 - long.len()));
        assert!(long.len() > MAX_VIEW_BYTES);
        let payload = request(&long, now, [6; 16]);
        let ingress = trusted_ingress(&payload, now, &mut cache);
        assert_eq!(
            receive_action(&ingress, true, false, false),
            ReceiveAction::Reply(GuiShowOutcome::InvalidView)
        );
    }

    #[test]
    fn remote_disabled_replies_disabled() {
        let now = 90u64;
        let payload = request("people", now, [1; 16]);
        let mut cache = ReplayCache::new();
        let ingress = trusted_ingress(&payload, now, &mut cache);
        assert_eq!(
            receive_action(&ingress, false, false, false),
            ReceiveAction::Reply(GuiShowOutcome::Disabled)
        );

        // Remote enable is before the view check.
        let url = request("https://evil.example", now, [2; 16]);
        let ingress = trusted_ingress(&url, now, &mut cache);
        assert_eq!(
            receive_action(&ingress, false, false, false),
            ReceiveAction::Reply(GuiShowOutcome::Disabled)
        );

        let body = activity_reply([1; 16], false, Some(123));
        match body {
            GuiActivityBody::Reply {
                last_gui_visible_at,
                remote_enabled,
                ..
            } => {
                assert!(last_gui_visible_at.is_none());
                assert!(!remote_enabled);
            }
            GuiActivityBody::Query { .. } => panic!("activity reply must be Reply"),
        }
    }

    #[test]
    fn select_active_picks_newest_inside_window_else_none() {
        let now = 1_000_000u64;
        let older = ActivityCandidate {
            machine_id: [1; 32],
            last_gui_visible_at: Some(now - 10),
            remote_enabled: true,
        };
        let newer = ActivityCandidate {
            machine_id: [2; 32],
            last_gui_visible_at: Some(now - 1),
            remote_enabled: true,
        };
        assert_eq!(
            select_active(now, &[older, newer]),
            ActiveChoice::Machine([2; 32])
        );

        let stale_hi = ActivityCandidate {
            machine_id: [2; 32],
            last_gui_visible_at: Some(now - ACTIVE_WINDOW_SECS - 1),
            remote_enabled: true,
        };
        let stale_lo = ActivityCandidate {
            machine_id: [1; 32],
            last_gui_visible_at: Some(now - ACTIVE_WINDOW_SECS - 5),
            remote_enabled: true,
        };
        assert_eq!(
            select_active(now, &[stale_hi, stale_lo]),
            ActiveChoice::None {
                candidates: vec![hex::encode([1; 32]), hex::encode([2; 32])],
            }
        );

        let disabled_newest = ActivityCandidate {
            machine_id: [3; 32],
            last_gui_visible_at: Some(now),
            remote_enabled: false,
        };
        let enabled_older = ActivityCandidate {
            machine_id: [1; 32],
            last_gui_visible_at: Some(now - 30),
            remote_enabled: true,
        };
        assert_eq!(
            select_active(now, &[disabled_newest, enabled_older]),
            ActiveChoice::Machine([1; 32])
        );
    }

    #[test]
    fn roundtrip_encode_decode_and_unknown_prefix_is_unclassified() {
        let id = [7u8; 16];
        let req = GuiShowDmRequest {
            request_id: id,
            view: "people".to_string(),
            issued_at: 42,
            via_rider: true,
        };
        let bytes = req.to_dm_payload().unwrap();
        assert_eq!(classify_prefix(&bytes), Some(DmClass::ShowRequest));
        assert_eq!(peek_request_id(&bytes), Some(id));
        let mut cache = ReplayCache::new();
        let ingress = ingress_show(true, &bytes, &[4; 32], 42, &mut cache).unwrap();
        match ingress {
            ShowIngress::Trusted(show) => {
                assert_eq!(show.request, req);
                assert!(show.fresh && show.view_ok && !show.replay);
                assert_eq!(show.route.as_deref(), Some("people"));
            }
            ShowIngress::Untrusted { .. } => panic!("trusted show decoded"),
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(ingress_show(true, &bad, &[4; 32], 42, &mut cache).is_none());

        let result = GuiShowDmResult {
            request_id: id,
            outcome: GuiShowOutcome::Opened,
        };
        let result_bytes = result.to_dm_payload().unwrap();
        assert_eq!(classify_prefix(&result_bytes), Some(DmClass::ShowResult));
        assert_eq!(peek_request_id(&result_bytes), Some(id));
        assert_eq!(decode_show_result(&result_bytes).unwrap(), result);

        let query = GuiActivityBody::Query { request_id: id };
        let query_bytes = query.to_dm_payload().unwrap();
        assert_eq!(classify_prefix(&query_bytes), Some(DmClass::Activity));
        assert_eq!(peek_request_id(&query_bytes), None);
        assert!(matches!(
            ingress_activity(true, &query_bytes),
            ActivityIngress::Query { request_id } if request_id == id
        ));

        let reply = GuiActivityBody::Reply {
            request_id: id,
            last_gui_visible_at: Some(9),
            remote_enabled: true,
        };
        let reply_bytes = reply.to_dm_payload().unwrap();
        assert_eq!(peek_request_id(&reply_bytes), None);
        assert_eq!(
            ingress_activity(true, &reply_bytes),
            ActivityIngress::Reply(reply)
        );
        assert!(matches!(
            ingress_activity(false, &reply_bytes),
            ActivityIngress::Ignore
        ));

        assert_eq!(classify_prefix(b"not-a-show"), None);
        assert_eq!(peek_request_id(b"not-a-show"), None);
        assert!(matches!(
            ingress_activity(true, b"not-a-show"),
            ActivityIngress::Ignore
        ));
        assert!(ingress_show(true, b"not-a-show", &[0; 32], 0, &mut cache).is_none());
    }

    #[test]
    fn blocked_and_rate_limited_do_not_display() {
        let now = 50u64;
        let payload = request("people", now, [8; 16]);
        let mut cache = ReplayCache::new();
        let ingress = ingress_show(true, &payload, &[7; 32], now, &mut cache).unwrap();
        assert_eq!(
            receive_action(&ingress, true, true, false),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
        assert_eq!(
            receive_action(&ingress, true, false, true),
            ReceiveAction::Reply(GuiShowOutcome::RateLimited)
        );
        assert_eq!(
            receive_action(&ingress, true, true, true),
            ReceiveAction::Reply(GuiShowOutcome::Refused)
        );
        assert!(matches!(
            receive_action(&ingress, true, false, false),
            ReceiveAction::Display { route, via_rider: false } if route == "people"
        ));
    }

    #[test]
    fn capability_bit_is_required_before_a_show_is_sent() {
        use crate::dm::CapabilityRegistry;
        assert!(CapabilityRegistry::current().supports(CapabilityRegistry::GUI_SHOW_V1));
        assert_eq!(CapabilityRegistry::GUI_SHOW_V1, 1 << 4);
        let payload = request("people", 1, [1; 16]);
        assert_eq!(
            CapabilityRegistry::required_for_payload(&payload),
            Some((CapabilityRegistry::GUI_SHOW_V1, "gui_show_v1"))
        );
        let missing = CapabilityRegistry {
            version: 1,
            bits: CapabilityRegistry::current().bits & !CapabilityRegistry::GUI_SHOW_V1,
        };
        assert!(missing.require_payload(&payload).is_err());
    }

    #[test]
    fn second_show_waiter_replaces_the_first() {
        let hub = RemoteHub::new();
        let id = [1u8; 16];
        let mut first = hub.wait_show(id);
        let mut second = hub.wait_show(id);
        assert_eq!(first.try_recv().unwrap_err(), TryRecvError::Closed);
        hub.complete_show(GuiShowDmResult {
            request_id: id,
            outcome: GuiShowOutcome::Navigated,
        });
        let got = second.try_recv().unwrap();
        assert_eq!(got.outcome, GuiShowOutcome::Navigated);
        hub.complete_show(GuiShowDmResult {
            request_id: id,
            outcome: GuiShowOutcome::Opened,
        });
    }
}
