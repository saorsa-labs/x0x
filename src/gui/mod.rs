//! Embedded GUI assets and the ADR 0083 show surface.
//!
//! The HTML shell lives beside this module (`x0x-gui.html`) and is served by
//! `GET /gui`. Slice 1 of ADR 0083 adds a Rust view grammar and the local
//! `POST /gui/show` runtime (config, rate limit, opener seam). Slice 3
//! adds the remote show typed DMs.

pub mod rate_limit;
pub mod remote;
pub mod show;
pub mod view_route;

pub use remote::{
    activity_reply, classify_prefix, ingress_activity, ingress_show, peek_request_id,
    receive_action, select_active, ActiveChoice, ActivityCandidate, ActivityIngress, DmClass,
    GuiActivityBody, GuiShowDmRequest, GuiShowDmResult, ReceiveAction, RemoteHub, ReplayCache,
    ShowIngress, TrustedShow, ACTIVE_WINDOW_SECS, ACTIVITY_PREFIX, CAPABILITY_NAME, FRESHNESS_SECS,
    MAX_VIEW_BYTES, REPLAY_SECS, RESULT_WAIT, SHOW_REQUEST_PREFIX, SHOW_RESULT_PREFIX,
};
pub use show::{
    new_request_id, origin_banner, parse_gui_ws_query, short_id_hex, startup_config_path,
    CapturingOpener, GuiShowConfig, GuiShowOutcome, GuiShowRequest, GuiShowResponse,
    GuiShowRuntime, PendingGuiShow, PlatformOpener, ShowOpener, LOCAL_SHOW_DISABLE_FAILED,
    LOCAL_SHOW_REENABLE, RIDER_SHOW_REENABLE,
};
pub use view_route::{parse, ParsedView, HASH_SPACE_APPS, HASH_VIEWS};
