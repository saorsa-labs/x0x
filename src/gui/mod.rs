//! Embedded GUI assets and the ADR 0083 show surface.
//!
//! The HTML shell lives beside this module (`x0x-gui.html`) and is served by
//! `GET /gui`. Slice 1 of ADR 0083 adds a Rust view grammar and the local
//! `POST /gui/show` runtime (config, rate limit, opener seam).

pub mod rate_limit;
pub mod show;
pub mod view_route;

pub use show::{
    new_request_id, origin_banner, parse_gui_ws_query, short_id_hex, startup_config_path,
    CapturingOpener, GuiShowConfig, GuiShowOutcome, GuiShowRequest, GuiShowResponse,
    GuiShowRuntime, PendingGuiShow, PlatformOpener, ShowOpener, SELF_GUI_BLOCK_REFUSED,
};
pub use view_route::{parse, ParsedView, HASH_SPACE_APPS, HASH_VIEWS};
