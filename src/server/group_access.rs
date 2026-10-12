//! Group-plane access admission — issue #1166 slices S1 (read family),
//! S2 (secure-write family), S3 (admin/mutation family) and S4 (the
//! long tail).
//!
//! One chokepoint owns the answer to "who may enter a group route" for
//! the group plane. Before this module every handler re-derived that
//! decision inline (durable bypass → rider 403 → session-membership 403,
//! each with its own hand-rolled body); #821/#870/#877 were all drift
//! between copies of that logic. The two halves of the design:
//!
//! - [`GROUP_PLANE_ROUTES`], a static classification table keyed by
//!   (method, path) covering EVERY group-plane route the router wires
//!   (`/groups*`, `/history*`, `/task-lists*`, `/mls/groups*`). Routes are
//!   either classified at their target [`AccessLevel`] or — through S4
//!   — explicitly pending classification until its slice landed.
//!   S5 migrated the last row (`POST /groups/:id/delegate`), retired
//!   the `Unmigrated` variant, and now a new group route lands
//!   CLASSIFIED: the parity test holds the table, the axum router
//!   (`src/server/mod.rs`) and the endpoint registry
//!   (`crate::api::ENDPOINTS`) to exactly the same route set, so no
//!   group route can be added without a classification row here.
//! - [`GroupAccess`], an axum extractor that resolves the `:id` group —
//!   percent-decoded through the same axum `Path` machinery the handlers
//!   used before this module existed — under the named-groups read lock,
//!   applies the route's admission rules, and either rejects with the
//!   exact status/body the inline code produced or hands the handler the
//!   resolved level plus the stable group id. Classification keys off
//!   the router's own `MatchedPath` pattern, so this module never
//!   re-implements route matching.
//!
//! Most classified routes cannot take the extractor: the S1 details and
//! delegations handlers, all five S2 secure-write handlers and the S3
//! mutation family are called DIRECTLY with positional extractor
//! arguments by regression tests that must not be edited (the
//! withdrawn-tombstone and lost-race tests in `routes/named_groups.rs`;
//! `routes/named_groups/tests/adr0066_delegations.rs`), or would have
//! their rejection PRECEDENCE reordered by an extractor argument that
//! necessarily runs before the body-consuming one (a malformed Json
//! body must keep answering 400 before any 404/403 admission), or run
//! gates the handler places before its lookup (the directory-durability
//! 503 on the request routes). Those handlers call the same admission
//! cores with the values they already hold under their own lock; the
//! decision cannot diverge from the extractor path because both ends
//! run the same function. `GET /groups/:id/requests` is the S3
//! exception: no body argument, no durability-first ordering and no
//! positional callers — its handler takes the extractor and re-runs
//! the core under its own lock (the `/members` pattern). The S4 stores
//! handlers join the pinned-signature family (~60 positional callers
//! in `routes/stores.rs`'s test module) and run the two S4 cores at
//! the inline checks' exact position; everything else S4 classifies
//! was already gated by shared helpers (`reject_quarantined_task_mutation`,
//! `ensure_task_list_access`, the history scope gates) or by nothing
//! at all, so those routes are classification-only — the table row
//! states the honest level and the handler keeps today's exact checks.
//!
//! Admission runs twice where the handler re-reads group data for its
//! body (`/members`, `/state/commits`): once in the extractor (an early
//! refusal that keeps cheap rejects away from the body) and once inside
//! the handler's own lock via the same pure core, so the served roster
//! or commit log is always admitted on the snapshot it is read from —
//! no read-check-serve window between two lock takes. `GET
//! /groups/:id/messages` is the deliberate exception: its unknown-group
//! fail-open and its stable-id resolution are one snapshot by design.
//! The S2 secure-write and S3 mutation handlers run their core ONCE,
//! under the write path's own lock take — exactly where the inline
//! gates stood — so the ADR-0066 epoch capture keeps the same guard.
//!
//! Behaviour is preserved (controller condition 3): same status codes,
//! same bodies, same precedence — 404 (unknown group; plus the withdrawn
//! 404 where today's handler 404s) → actor admission (rider 403 /
//! membership 403) → route-local policy gates (409 withdrawn, 400
//! MlsEncrypted, 403 members-only). A `:id` that does not
//! percent-decode keeps the `Path` extractor's own 400, and a missing
//! actor keeps axum's `Extension` 500 (unreachable behind the auth
//! middleware, which always inserts one). Error shapes come from the
//! shared builders in `crate::server` (`api_error`, `api_error_with_reason`,
//! `not_found`, `forbidden`, `bad_request`) or the canonical gate
//! helpers in `crate::server::routes::named_groups`
//! (`reject_fork_quarantined_for_actor`,
//! `reject_unverified_owner_certified_restore`,
//! `open_envelope_withdrawn_group_conflict`, `reject_withdrawn_group`),
//! which is what the inline code used.
//!
//! `POST /groups/:id/delegate` — the one S4 row left `Unmigrated` —
//! migrated in S5 with the same discipline: its handler
//! (`routes/delegations.rs`) keeps its signature (the Json body must
//! keep answering 400 before any gate) and calls the
//! [`admit_delegate_route`] core at the inline gates' exact position
//! under its own lock. S5 also activates the `clippy.toml`
//! `disallowed-methods` ceiling on the absorbed admission helpers
//! (`local_join_membership_state`, `require_admin_or_above`,
//! `reject_fork_quarantined_for_actor`,
//! `ActorContext::rider_allows_group`): they may be called freely in
//! this module (the one module-level allow below) and at an explicit,
//! commented allow site everywhere else — a new inline call anywhere
//! else is the #821/#870/#877 drift class and fails CI clippy.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::sync::Arc;

use crate as x0x;
use crate::server::rider_auth::ActorContext;
use crate::server::routes::named_groups::{
    local_join_membership_state, open_envelope_withdrawn_group_conflict, reject_fork_quarantined,
    reject_fork_quarantined_for_actor, reject_unverified_owner_certified_restore,
    reject_withdrawn_group, require_admin_or_above,
};
use crate::server::state::AppState;
use axum::extract::{Extension, FromRequestParts, MatchedPath, Path};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{api_error, api_error_with_reason, bad_request, forbidden, not_found};

// ─────────────────────── access levels (S1–S2) ───────────────────────
/// The local daemon's qualifying seat state for a session bearer — the
/// `local_join_membership_state` labels (#447/#458) that EARN something.
/// Refused labels (`pending`, `not_member`) are refusals, not levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MemberState {
    /// Roster lists the local agent as active.
    Active,
    /// Local join stub present, authority never committed its
    /// `MemberAdded` — the #821 limbo state that still earns the
    /// `GET /groups/:id` stub answer.
    PendingAuthorityCommit,
}

/// What a request was admitted at. S1 needs three levels; S2 adds
/// `SessionBearer`, `RiderScope` and `PublicWrite` for the
/// secure-write family; S3 adds `Admin` and `JoinSelf` for the
/// admin/mutation family; S4 classified the long tail at these same
/// levels (see the table's S4 section comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum AccessLevel {
    /// The durable API token — full authority, subsumes every other level.
    OwnerDurable,
    /// A local seat the admission core actually verified — which seat
    /// (whose, and what state qualifies) is the route's admission rule,
    /// not the caller's guess. On the S1 read family it is the session
    /// bearer's own seat (`local_join_membership_state`); on the S4
    /// task-list family it is the DAEMON's active seat, evaluated
    /// bearer-blind (`ensure_task_list_access` — a durable owner
    /// without the seat is refused too). A session bearer whose seat
    /// was NOT checked is [`AccessLevel::SessionBearer`].
    Member(MemberState),
    /// A session bearer admitted on bearer CLASS alone, no seat, no
    /// grant verified — the S2 secure-write family (`send`,
    /// `secure/encrypt|decrypt|reseal`: `send` admits seatless bearers
    /// where the write policy allows and `decrypt` still admits banned
    /// callers) and the S4 history/stores surfaces whose gates are
    /// scope-conditional (`GET /history`'s per-scope rider grant,
    /// `DELETE /history`'s fork-quarantine backstop) or rider-only
    /// defence-in-depth (the stores routes). Never read as "holds an
    /// active seat" or "no rider can enter".
    SessionBearer,
    /// A rider bearer on a write surface (`send`, `secure/encrypt`). The
    /// level LABELS the actor class — it asserts no verified token grant:
    /// the ADR-0039 grant/ban/role/delegation ladder runs in the handler
    /// under its own lock (S2 keeps it there; its per-route order is
    /// pinned by the rider tests, and `send` checks ban BEFORE the grant
    /// while `secure/encrypt` checks the grant first).
    RiderScope,
    /// The local daemon's roster seat is Admin-or-higher — exactly
    /// today's `require_admin_or_above`
    /// (`caller_role(local_agent_hex).at_least(GroupRole::Admin)`). The
    /// seat evaluated is the DAEMON's, never the bearer's class: a
    /// durable-owner bearer without an admin seat is still refused
    /// (`membership_handlers_reject_non_admin_local_caller` pins it),
    /// and the bearer's class re-enters only through the Home durable
    /// fence the handlers keep at entry. Honest label, not an actor
    /// authority claim.
    Admin,
    /// The self-directed surface whose subject IS the local daemon:
    /// `DELETE /groups/:id` (leave) admits when the daemon itself holds
    /// an ACTIVE seat, any role — the #446 round-5 gate. The bearer
    /// class is never consulted.
    JoinSelf,
    /// No actor-based gate: no property of the bearer can refuse the
    /// request (riders are unreachable through the auth middleware's
    /// deny-by-default allowlist; owner-class bearers are never
    /// refused). What the route serves — and any filtering of it, like
    /// the task-list collection's seat filter or the history surfaces'
    /// session marker visibility — is local policy, not principal
    /// identity.
    PublicRead,
    /// No actor-based gate on a write surface; remaining gates are local
    /// policy or data checks, not principal identity — the write-side
    /// member of the no-actor class (S2's `open-envelope`, S3's
    /// display-name and request create/cancel). Issue #1228 tracks
    /// that `POST /groups/:id/quarantine/clear` and the `/mls/groups*`
    /// routes ALSO sit here with no gate at all: S4 classifies them at
    /// that reality without tightening; each fix is a separate reviewed
    /// change, pinned by the `s4_pins_the_no_actor_check_routes_as_unchanged`
    /// test.
    PublicWrite,
}

/// An admission decision: the granted level, or the exact rejection
/// (status + body) the pre-extractor handler returned for that case.
pub(in crate::server) type Admission = Result<AccessLevel, (StatusCode, Json<serde_json::Value>)>;

// ─────────────────────── classification table ────────────────────────────

/// One row of the classification table. Every group-plane route is
/// classified (S5 migrated the last `Unmigrated` row and retired that
/// variant with its now-unread wrapper enum): a new route lands here
/// at its real [`AccessLevel`] or it does not land — the parity test
/// fails. The level is the route's NOMINAL class (the slice plan's
/// inventory target); per-route rules (policy arms, withdrawn-shell
/// exemptions, pending-join stubs) live in the admission cores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct RouteAccess {
    /// HTTP method.
    pub(in crate::server) method: Method,
    /// Path in router syntax (`/groups/:id/members`), identical to the
    /// axum route pattern and the `ENDPOINTS` registry path.
    pub(in crate::server) path: &'static str,
    /// The access level this route is admitted at.
    pub(in crate::server) level: AccessLevel,
}

/// The complete group-plane route set: every `/groups*`, `/history*`,
/// `/task-lists*` and `/mls/groups*` (method, path) wired in the axum
/// router. The parity test pins this table against BOTH the router
/// (`src/server/mod.rs`) and the endpoint registry
/// (`crate::api::ENDPOINTS`).
///
/// S1 classified the read family — `GET /groups/:id`, `/members`,
/// `/messages`, `/state`, `/state/commits`, `/delegations`; S2 the
/// secure-write family — `POST /groups/:id/send`,
/// `secure/encrypt|decrypt|reseal`, `secure/open-envelope`; S3 the
/// admin/mutation family; S4 the long tail (both section comments
/// carry the honest labels); S5 `POST /groups/:id/delegate`
/// (`routes/delegations.rs`) at `OwnerDurable` — the #446 durable
/// gate its handler runs first is the only actor-based check; the
/// SignedPublic/ban/write-policy/to_agent gates after admission are
/// data checks, keyed on the local daemon.
pub(in crate::server) static GROUP_PLANE_ROUTES: &[RouteAccess] = &[
    // ── S1 read family: classified ────────────────────────────────────
    // `/groups/:id` additionally serves the pending_authority_commit stub
    // arm (200 short body); `/messages` is Member only under a MembersOnly
    // read policy — see the admission cores.
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/members",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/messages",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/state",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/state/commits",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/delegations",
        level: AccessLevel::Member(MemberState::Active),
    },
    // ── S2 secure-write family: classified ────────────────────────────
    // The inventory target is "Member + RiderScope", but the S2 entry
    // cores verify NEITHER: no seat lookup, no token grant. The rows
    // label the bearer class honestly — SessionBearer / RiderScope —
    // because Member(..) claims a verified seat (see `AccessLevel`).
    // Ban state, write policy, send-as, the member gate and the
    // ADR-0039 grant/delegation/provenance ladder stay in the
    // handlers, under their lock, in their per-route order.
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/send",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/encrypt",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/decrypt",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/secure/reseal",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/secure/open-envelope",
        level: AccessLevel::PublicWrite,
    },
    // ── S3 admin/mutation family: classified ──────────────────────────
    // `Admin` is today's `require_admin_or_above`: the LOCAL DAEMON's
    // roster seat at Admin+, never the bearer's class (a durable owner
    // without an admin seat is refused — the authority test pins it);
    // the bearer matters only through the Home durable fence the
    // handlers keep at entry. The requests LISTING carries the same
    // seat gate but NO withdrawn check (today's shape — a withdrawn
    // shell's requests stay listable). Issue #1228's no-actor family is
    // classified at its REAL level, not the inventory's target:
    // display-name and request create/cancel have no actor gate at all
    // (PublicWrite — their data gates are the handler's, keyed on the
    // local daemon), and leave is the daemon's own active seat
    // (JoinSelf). Tightening any of these is a separate reviewed PR.
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/invite",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/members",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/members/:agent_id",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id/members/:agent_id/role",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/ban/:agent_id",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/ban/:agent_id",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/groups/:id/policy",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::PUT,
        path: "/groups/:id/display-name",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/state/seal",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/state/withdraw",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id",
        level: AccessLevel::JoinSelf,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/requests",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests/:request_id/approve",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/requests/:request_id/reject",
        level: AccessLevel::Admin,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/:id/requests/:request_id",
        level: AccessLevel::PublicWrite,
    },
    // ── S4 long tail: classified ─────────────────────────────────────
    // Honest labels, nothing tightened (every gate below is today's,
    // kept exactly where it stood):
    // - Discovery, cards, group create/list, join, join-status and the
    //   plain history reads (message/scopes/search/stats) refuse NO
    //   bearer — PublicRead / PublicWrite by the no-actor rule.
    // - `GET /history` (the one rider-reachable history surface, via
    //   the ADR-0039 allowlist) and `DELETE /history` CAN refuse on
    //   the actor — the per-scope rider grant 403, and the #877
    //   fork-quarantine-for-actor backstop on a purge — while sessions
    //   pass with nothing verified: SessionBearer, gates handler-side
    //   (they consume the query's scope, so they cannot move into an
    //   extractor).
    // - stores: `POST /groups/:id/stores` keeps its rider-grant 403
    //   (`admit_group_store_route`) and the legacy-import trio its
    //   owner-class 403 (`admit_legacy_import_route`), both now via
    //   the S4 cores at the inline checks' exact position; nominal
    //   SessionBearer.
    // - task-lists: the `:id` is a task-list id, not a group id — the
    //   group (and every gate) is parsed OUT of it. A group-scoped id
    //   requires the LOCAL DAEMON's active seat, bearer-blind
    //   (`ensure_task_list_access`; a durable owner without the seat
    //   is refused too) plus the QUAR mutation gate
    //   (`reject_quarantined_task_mutation`, which runs FIRST so an
    //   alias-keyed group fails for the right reason); a plain id is
    //   ungated. Rows label the scoped case (Member = the verified
    //   daemon seat); the collection never refuses — it FILTERS by the
    //   same seat rule — so it is PublicRead.
    // - #1228's unchecked surfaces — `quarantine/clear` and every
    //   `/mls/groups*` route — are classified at their REAL no-actor
    //   level; tightening them is a separate reviewed PR, pinned by
    //   `s4_pins_the_no_actor_check_routes_as_unchanged`.
    RouteAccess {
        method: Method::POST,
        path: "/groups",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover/nearby",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/discover/subscriptions",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/discover/subscribe",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/groups/discover/subscribe/:kind/:shard",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/cards/import",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/cards/:id",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/join",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/join-status",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/quarantine/clear",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/stores",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/stores/:app/legacy-imports",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::GET,
        path: "/groups/:id/stores/:app/legacy-imports/:source_id",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/stores/:app/legacy-imports/:source_id",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/history",
        level: AccessLevel::SessionBearer,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/message/:msg_id",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/scopes",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/search",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/history/stats",
        level: AccessLevel::PublicRead,
    },
    // ADR 0116 §3: owner-only (durable token, enforced by the auth
    // middleware's durable-owner table); sessions 403, riders never reach
    // the handler.
    RouteAccess {
        method: Method::GET,
        path: "/history/policy",
        level: AccessLevel::OwnerDurable,
    },
    // ADR 0116 §4: the runtime trim, owner-only like the policy read.
    RouteAccess {
        method: Method::POST,
        path: "/history/retain",
        level: AccessLevel::OwnerDurable,
    },
    RouteAccess {
        method: Method::GET,
        path: "/task-lists",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::POST,
        path: "/task-lists",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::GET,
        path: "/task-lists/:id/tasks",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::POST,
        path: "/task-lists/:id/tasks",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::PATCH,
        path: "/task-lists/:id/tasks/:tid",
        level: AccessLevel::Member(MemberState::Active),
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::GET,
        path: "/mls/groups",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::GET,
        path: "/mls/groups/:id",
        level: AccessLevel::PublicRead,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/members",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::DELETE,
        path: "/mls/groups/:id/members/:agent_id",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/encrypt",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/decrypt",
        level: AccessLevel::PublicWrite,
    },
    RouteAccess {
        method: Method::POST,
        path: "/mls/groups/:id/welcome",
        level: AccessLevel::PublicWrite,
    },
    // ── S5 delegate mint: classified ────────────────────────────────
    // The #446 durable gate the handler runs FIRST (mirrored by the
    // auth middleware's durable-owner requirement) is the only
    // actor-based check — sessions 403, riders never reach the
    // handler. Everything after the lookup/withdrawn/QUAR admission
    // (SignedPublic 400, ban 403, write policy, to_agent member 400)
    // is a data check keyed on the local daemon.
    RouteAccess {
        method: Method::POST,
        path: "/groups/:id/delegate",
        level: AccessLevel::OwnerDurable,
    },
];

// ─────────────────────── table lookup ────────────────────────────────────

/// Resolve a request to its classification row plus the percent-DECODED
/// path parameters (r2/P2-2), or the exact rejection the pre-extractor
/// `Path` extractor arguments produced.
///
/// Classification keys off the router's own `MatchedPath` — the route
/// pattern (`/groups/:id/members`) axum already resolved, static-beats-
/// param priority included — so this module never re-implements route
/// matching. The lookup is a plain `(method, pattern)` comparison; the
/// parity test pins the table's pattern strings byte-for-byte to the
/// router's, so a renamed parameter cannot slip past normalisation.
///
/// Parameters decode through the same `Path` extractor the handlers had
/// as extractor arguments before this module: the axum router itself
/// percent-decodes when it captures (so a raw `/groups/%61bc…` request
/// arrives here already decoded to `abc…`, and the extractor's group
/// lookup sees the same id the old handler's `Path<String>` saw), and a
/// segment that does not decode to UTF-8 (`/groups/%FF/messages`) rejects
/// with `Path`'s own 400 — generated by the router's decoder before serde
/// is involved, hence byte-identical to the old `Path<String>` rejection.
async fn resolve_route(
    parts: &mut Parts,
) -> Result<(&'static RouteAccess, HashMap<String, String>), Response> {
    let params = match Path::<HashMap<String, String>>::from_request_parts(parts, &()).await {
        Ok(Path(params)) => params,
        Err(rejection) => return Err(rejection.into_response()),
    };
    let Some(matched) = parts.extensions.get::<MatchedPath>() else {
        return Err(unclassified(&parts.method, parts.uri.path()));
    };
    let row = GROUP_PLANE_ROUTES
        .iter()
        .find(|row| row.method == parts.method && row.path == matched.as_str());
    let Some(row) = row else {
        return Err(unclassified(&parts.method, parts.uri.path()));
    };
    Ok((row, params))
}

// ─────────────────────── admission cores (pure) ──────────────────────────

/// The membership-403 the read family shares: same status, same body,
/// same `reason` marker as the inline checks #821 pinned
/// (`routes/named_groups/tests/issue821_read_auth.rs`, the #870 session
/// tests in `routes/history.rs`).
fn membership_required() -> (StatusCode, Json<serde_json::Value>) {
    api_error_with_reason(
        StatusCode::FORBIDDEN,
        "active local group membership required",
        "group_membership_required",
    )
}

/// `GET /groups/:id` admission. Durable owners bypass; riders are refused
/// (defence in depth — the ADR-0039 middleware already denies riders this
/// route, the body is kept for parity); a session bearer needs an active
/// seat, EXCEPT that the #447/#458 `pending_authority_commit` limbo earns
/// the stub arm — the handler answers that level with the 200 short body.
pub(in crate::server) fn admit_named_group_details(
    actor: &ActorContext,
    membership_state: &str,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Rider { .. } => {
            Err(forbidden("rider tokens cannot read named-group details"))
        }
        ActorContext::Owner { durable: false } => match membership_state {
            "active" => Ok(AccessLevel::Member(MemberState::Active)),
            "pending_authority_commit" => {
                Ok(AccessLevel::Member(MemberState::PendingAuthorityCommit))
            }
            _ => Err(membership_required()),
        },
    }
}

/// `GET /groups/:id/members` admission. Same shape as the details route
/// minus the stub arm: a pending seat (either kind) is a refusal here —
/// the roster itself is member content (#821 pins the pending case).
pub(in crate::server) fn admit_named_group_members(
    actor: &ActorContext,
    membership_state: &str,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Rider { .. } => {
            Err(forbidden("rider tokens cannot read named-group members"))
        }
        ActorContext::Owner { durable: false } => match membership_state {
            "active" => Ok(AccessLevel::Member(MemberState::Active)),
            _ => Err(membership_required()),
        },
    }
}

/// The details admission with the #447/#458 seat label resolved INSIDE
/// this module (#1166 S5): the handler (pinned signature) used to call
/// `local_join_membership_state` by hand and feed the pure core; the
/// label read is now single-sourced here, under the caller's own lock.
/// The label is RETURNED because it is response data on this route —
/// the 200 body embeds `membership_state` for EVERY admitted actor
/// arm (durable owners included) — so unlike the members sibling it
/// is computed unconditionally, exactly as the inline code did.
pub(in crate::server) async fn admit_named_group_details_of_state(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
) -> (String, Admission) {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let label = local_join_membership_state(state, info, &local_hex).await;
    let admission = admit_named_group_details(actor, label);
    (label.to_string(), admission)
}

/// The members sibling of [`admit_named_group_details_of_state`]: the
/// label is only read for session bearers (the other arms ignore it),
/// exactly the arm shape the handler and extractor arm shared.
pub(in crate::server) async fn admit_named_group_members_of_state(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: false } => {
            let local_hex = hex::encode(state.agent.agent_id().as_bytes());
            let label = local_join_membership_state(state, info, &local_hex).await;
            admit_named_group_members(actor, label)
        }
        _ => admit_named_group_members(actor, "not_member"),
    }
}

/// `GET /groups/:id/delegations` admission (ADR-0040 list, ADR-0066 §3b
/// row 16 annotate-class). Order is today's: withdrawn → 404 (a withdrawn
/// shell exposes no delegation authority), session bearer without an
/// active seat → membership 403, rider → 403, then the group's own read
/// policy — which binds even durable owners when they hold no seat
/// (`members-only read policy`).
pub(in crate::server) fn admit_group_delegations(
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Admission {
    if info.withdrawn {
        return Err(not_found("group is withdrawn"));
    }
    let is_member = info.has_active_member(local_agent_hex);
    let level = match actor {
        ActorContext::Owner { durable: true } => AccessLevel::OwnerDurable,
        ActorContext::Owner { durable: false } if is_member => {
            AccessLevel::Member(MemberState::Active)
        }
        ActorContext::Owner { durable: false } => return Err(membership_required()),
        ActorContext::Rider { .. } => {
            return Err(forbidden("rider tokens cannot read group delegations"))
        }
    };
    // Durable owners retain the existing group read policy.
    if !is_member && info.policy.read_access != x0x::groups::GroupReadAccess::Public {
        return Err(forbidden("members-only read policy"));
    }
    Ok(level)
}

/// `GET /groups/:id/state/commits` admission (#111): retained roster
/// projections are member content while the group is live; a withdrawn
/// shell stays readable so members keep their keyless audit history after
/// terminal delete.
pub(in crate::server) fn admit_state_commits(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> Admission {
    if !info.withdrawn && !info.has_active_member(local_agent_hex) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
        ));
    }
    Ok(if info.withdrawn {
        AccessLevel::PublicRead
    } else {
        AccessLevel::Member(MemberState::Active)
    })
}

/// `GET /groups/:id/messages` admission for a locally-known group. The
/// order is today's: withdrawn → 409 (`reject_withdrawn_group`'s CONFLICT,
/// not a 404), MlsEncrypted → 400 (no plaintext history exists), then the
/// MembersOnly read policy on the LOCAL daemon's seat (the actor is
/// irrelevant to these gates — this surface never had an actor check).
pub(in crate::server) fn admit_public_messages(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> Admission {
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted {
        return Err(bad_request(
            "MlsEncrypted groups do not publish a plaintext message history",
        ));
    }
    let members_only = info.policy.read_access == x0x::groups::GroupReadAccess::MembersOnly;
    if members_only && !info.has_active_member(local_agent_hex) {
        return Err(forbidden("members-only read policy"));
    }
    Ok(if members_only {
        AccessLevel::Member(MemberState::Active)
    } else {
        AccessLevel::PublicRead
    })
}

// ─────────────────────── admission cores (S2 secure-write) ───────────────

/// The ACTING PRINCIPAL's hex — the identity ban state, roster role and
/// (for riders) token grants are checked against. The send path's
/// review-fix-#1 rule: an owner bearer acts as the DAEMON's own agent
/// (the key that signs), a rider as its SUB-AGENT — so a rider can never
/// inherit the daemon-admin's privileges. Actor-less local-seat
/// surfaces (messages, state/commits) evaluate the LOCAL daemon's seat,
/// which is the same principal for every caller.
pub(in crate::server) fn acting_principal_hex(
    actor: &ActorContext,
    local_agent_hex: &str,
) -> String {
    match actor {
        ActorContext::Owner { .. } => local_agent_hex.to_string(),
        ActorContext::Rider { sub_agent_id, .. } => sub_agent_id.clone(),
    }
}

/// The S2 actor classification shared by `send` and the secure
/// encrypt/decrypt/reseal endpoints: the level LABELS the actor class
/// the request entered as — honestly: a session owner is
/// `SessionBearer`, not `Member`, because this core looks up no seat
/// (`send` admits seatless bearers where the write policy allows and
/// `decrypt` still admits banned callers) — and the acting hex names
/// the principal the handler's remaining gates evaluate. Neither
/// asserts a verified seat or grant — the member gate, ban state,
/// write policy and the ADR-0039 grant/delegation ladder keep their
/// per-route order in the handler, under its own lock.
fn secure_write_access(
    info: &x0x::groups::GroupInfo,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> GroupAccess {
    let level = match actor {
        ActorContext::Owner { durable: true } => AccessLevel::OwnerDurable,
        ActorContext::Owner { durable: false } => AccessLevel::SessionBearer,
        ActorContext::Rider { .. } => AccessLevel::RiderScope,
    };
    GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        acting_hex: acting_principal_hex(actor, local_agent_hex),
    }
}

/// `POST /groups/:id/send` entry admission, in today's order: the raw-id
/// lookup (404 on a miss; the waiver sits at the site, where the
/// guard reads it) → the withdrawn 409 → the #877
/// fork-quarantine-for-actor gate (a session bearer without an active
/// local seat is refused with the bare membership 403 BEFORE any marker
/// body is built). Everything after — the SignedPublic 400, ban check,
/// write policy, send-as authorization and the rider grant/delegation/
/// provenance ladder — stays in the handler, in its order, under this
/// same lock.
///
/// The fork-quarantine gate is injected because it needs the whole
/// `AppState` (the agent id for the seat check, the diagnostics
/// counter); the public wrapper wires the canonical
/// `reject_fork_quarantined_for_actor`, the unit tests pin its position
/// in the order with a stub, and the end-to-end #877 contract is pinned
/// by `routes/named_groups/tests/issue877_error_body_session.rs`.
fn send_admission<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    actor: &ActorContext,
    local_agent_hex: &str,
    fork_quarantine: impl FnOnce(
        &x0x::groups::GroupInfo,
    ) -> Option<(StatusCode, Json<serde_json::Value>)>,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    // ADR0066-LOOKUP-WAIVER: the route's own group lookup (404 on a miss, so
    // no contested roster is ever served); the fork-quarantine gate below
    // consumes the `info` it found. Widening the route's id semantics is out
    // of #732's scope — the waiver the inline handler lookup carried pre-S2.
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if let Some(resp) = fork_quarantine(info) {
        return Err(resp);
    }
    Ok((info, secure_write_access(info, actor, local_agent_hex)))
}

/// The entry admission shared by the GSS secure endpoints
/// (`secure/encrypt`, `secure/decrypt`, `secure/reseal`), in today's
/// order: raw-id lookup 404 → withdrawn 409 → the ADR-0038
/// restore-quarantine 409 → the #877 fork-quarantine-for-actor gate.
/// The member gate (its three per-route shapes), the rider ladder and
/// the crypto follow in the handler under the same lock; the ADR-0066
/// epoch capture keeps its position immediately after this admission.
fn secure_endpoint_admission<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    actor: &ActorContext,
    local_agent_hex: &str,
    fork_quarantine: impl FnOnce(
        &x0x::groups::GroupInfo,
    ) -> Option<(StatusCode, Json<serde_json::Value>)>,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    // ADR0066-LOOKUP-WAIVER: GSS route lookup: a miss is a 404 before any
    // gate, so it fails closed, and the gates below consume this same `info`.
    // Out of #732's scope — the waiver the encrypt/decrypt/reseal handler
    // lookups carried pre-S2.
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if let Some(resp) = reject_unverified_owner_certified_restore(info) {
        return Err(resp);
    }
    if let Some(resp) = fork_quarantine(info) {
        return Err(resp);
    }
    Ok((info, secure_write_access(info, actor, local_agent_hex)))
}

/// `POST /groups/:id/send` entry admission for the handler (which holds
/// the named-groups read lock for the whole build+sign critical
/// section): runs [`send_admission`] with the canonical
/// fork-quarantine gate. `route_id` is the RAW route `:id` — the same
/// key the inline gate used for the marker body and the diagnostics
/// bump.
pub(in crate::server) fn admit_group_send<'a>(
    state: &AppState,
    route_id: &str,
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    send_admission(groups, route_id, actor, local_agent_hex, |info| {
        reject_fork_quarantined_for_actor(state, route_id, info, actor)
    })
}

/// The secure encrypt/decrypt/reseal entry admission for the handlers
/// (each holds the named-groups read lock): runs
/// [`secure_endpoint_admission`] with the canonical fork-quarantine
/// gate. `route_id` is the RAW route `:id`, as above.
pub(in crate::server) fn admit_secure_endpoint<'a>(
    state: &AppState,
    route_id: &str,
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    actor: &ActorContext,
    local_agent_hex: &str,
) -> Result<(&'a x0x::groups::GroupInfo, GroupAccess), (StatusCode, Json<serde_json::Value>)> {
    secure_endpoint_admission(groups, route_id, actor, local_agent_hex, |info| {
        reject_fork_quarantined_for_actor(state, route_id, info, actor)
    })
}

/// `POST /groups/secure/open-envelope` admission: the withdrawn-record
/// conflict (a withdrawn record with no live same-stable-keyed alias →
/// 409) on the BODY's `group_id` — this surface never had an actor or
/// membership gate, and an unknown group fails OPEN to the crypto (the
/// envelope itself refuses). Body of the conflict comes from the
/// canonical `open_envelope_withdrawn_group_conflict`.
pub(in crate::server) fn admit_open_envelope(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Admission {
    if let Some(resp) = open_envelope_withdrawn_group_conflict(groups, group_id) {
        return Err(resp);
    }
    Ok(AccessLevel::PublicWrite)
}

// ─────────────────────── admission cores (S3 admin/mutation) ─────────────

/// The Admin-family gate pair, in today's order: the local daemon's
/// seat at Admin+ (`require_admin_or_above`'s "admin role required"
/// 403) THEN the withdrawn 409. Given the already-borrowed group, for
/// the sites that hold `info` through a lookup of their own —
/// `PATCH …/members/:agent_id/role` (whose target-entry checks come
/// FIRST today), `approve_join_request`'s write-lock block, and (S5)
/// the four TreeKEM delegation helpers `add/remove/ban_treekem_*` and
/// `approve_treekem_join_request`, whose inline pairs this core
/// absorbed at their exact positions under their own locks.
pub(in crate::server) fn admin_route_gate(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    require_admin_or_above(info, local_agent_hex)?;
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    Ok(())
}

/// Entry admission for the admin-mutated group routes (invite, member
/// add/remove/role, ban/unban, PATCH, policy, seal, request
/// approve/reject), in today's order: raw-id lookup 404 →
/// [`admin_route_gate`]. The Home durable fence the handlers run at
/// ENTRY (before the membership lock, before body parse where it
/// stood) is deliberately NOT here — see [`is_home_or_owner_certified`].
pub(in crate::server) fn admit_admin_group_route<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    local_agent_hex: &str,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    admin_route_gate(info, local_agent_hex)?;
    Ok(info)
}

/// `GET /groups/:id/requests`: raw-id lookup 404 → the admin seat
/// gate — and NO withdrawn check, today's shape exactly (a withdrawn
/// shell's request list stays readable for its admins). Tightening
/// that belongs to a reviewed change, not this slice.
pub(in crate::server) fn admit_join_request_listing<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    local_agent_hex: &str,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    require_admin_or_above(info, local_agent_hex)?;
    Ok(info)
}

/// `DELETE /groups/:id` (leave): raw-id lookup 404 → withdrawn 409 →
/// the local ACTIVE-seat gate (any role — member self-leave is this
/// surface's purpose; the admin gate guards the shared
/// terminal-withdrawal routing instead, where the sole-member leave
/// path waives it by design).
pub(in crate::server) fn admit_self_leave<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    local_agent_hex: &str,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    if info.caller_role(local_agent_hex).is_none() {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "leaving a group requires active membership in it",
        ));
    }
    Ok(info)
}

/// Entry admission for issue #1228's no-actor family — `PUT
/// /groups/:id/display-name`, request create and request cancel: raw-id
/// lookup 404 → withdrawn 409. No actor, no seat, no role; the routes'
/// remaining gates are data checks keyed on the local daemon's identity
/// (request ownership, admission policy, the display-name write itself)
/// and stay in the handlers, in their per-route order.
pub(in crate::server) fn admit_live_group_route<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return Err(resp);
    }
    Ok(info)
}

/// The Home/owner-certified durable-fence predicate (issue #446's
/// central fence, `home_mutation_requires_durable`): a group carrying
/// Home metadata OR an OwnerCertified-capable admission axis is an
/// owner act to mutate, whatever its current policy axes. The ONE
/// definition — the fence itself (the actor test and its typed 403,
/// called by that shared helper at every mutating handler's entry)
/// keeps its entry position in the handlers (before body parse where
/// it stood), so no S3 core runs it.
pub(in crate::server) fn is_home_or_owner_certified(info: &x0x::groups::GroupInfo) -> bool {
    info.home.is_some() || info.policy.admission.owner_certified_user_id().is_some()
}

// ─────────────────────── admission cores (S4 long tail) ──────────────────

/// `POST /groups/:id/stores`: the rider grant on the binding's STABLE
/// group id — owner-class bearers pass on class, a rider only with its
/// token's explicit grant (ADR-0039). Riders cannot reach this route
/// through the auth middleware (deny-by-default allowlist), so the
/// grant arm is defence in depth, exactly as the inline check kept it;
/// the body is byte-identical (`forbidden`). Runs at the inline
/// check's position: after the plane/binding resolution's lock block,
/// on the resolved `binding.stable_group_id`.
pub(in crate::server) fn admit_group_store_route(
    actor: &ActorContext,
    stable_group_id: &str,
) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Owner { durable: false } => Ok(AccessLevel::SessionBearer),
        ActorContext::Rider { .. } if actor.rider_allows_group(stable_group_id) => {
            Ok(AccessLevel::RiderScope)
        }
        ActorContext::Rider { .. } => Err(forbidden("rider token is not granted this group")),
    }
}

/// The legacy-import trio (`GET /groups/:id/stores/:app/legacy-imports`,
/// `GET+POST …/legacy-imports/:source_id`): the local owner-authority
/// gate — an Owner-CLASS bearer (durable or session) passes, every
/// rider is refused, grant or not. The inline code followed the owner
/// match with a `rider_allows_group` check that only Owners could
/// reach and that is `true` for every Owner, so it could never fire;
/// folding it away is behaviour-identical, and the stores rider test
/// pins the observable contract (a GRANTED rider still gets this 403).
/// Runs at the inline pair's position: inside the named-groups lock
/// block, after `find_store_group` and the canonical-id 400.
pub(in crate::server) fn admit_legacy_import_route(actor: &ActorContext) -> Admission {
    match actor {
        ActorContext::Owner { durable: true } => Ok(AccessLevel::OwnerDurable),
        ActorContext::Owner { durable: false } => Ok(AccessLevel::SessionBearer),
        ActorContext::Rider { .. } => Err(forbidden(
            "legacy source export requires the local owner authority",
        )),
    }
}

// ─────────────────────── admission cores (S5 delegate) ──────────────────

/// `POST /groups/:id/delegate` entry admission (ADR-0040 mint, ADR-0066
/// §3b row 15), in today's order: raw-id lookup 404 → withdrawn **404**
/// (a withdrawn shell exposes no delegation authority — the S1
/// delegations-list disposition, NOT the mutation family's 409) → the
/// actor-BLIND fork-quarantine 409 (row 15's gate; the #446 durable
/// gate the handler runs first means a session bearer can never reach
/// it, so the for-actor seat shape is unreachable here by design).
/// Everything after — the SignedPublic 400, the ban 403, the write
/// policy, the to_agent member 400 — is data/policy the handler keeps,
/// in its order, under this same lock.
///
/// The fork-quarantine gate is injected (the S2 pattern) so the pure
/// core stays AppState-free; the public wrapper wires the canonical
/// `reject_fork_quarantined`, and the unit tests pin the order with
/// stubs.
fn delegate_admission<'a>(
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
    fork_quarantine: impl FnOnce(
        &x0x::groups::GroupInfo,
    ) -> Option<(StatusCode, Json<serde_json::Value>)>,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    // ADR0066-LOOKUP-WAIVER: row 15 (mint) resolves the group for the WHOLE
    // route: a miss is a 404 before any marker is read, so it fails closed,
    // and the §3b gate below consumes this same `info`. Same disposition as
    // row 16. (Carried from the inline handler lookup — #1166 S5.)
    let Some(info) = groups.get(route_id) else {
        return Err(not_found("group not found"));
    };
    if info.withdrawn {
        return Err(not_found("group is withdrawn"));
    }
    if let Some(resp) = fork_quarantine(info) {
        return Err(resp);
    }
    Ok(info)
}

/// The delegate-mint entry admission for the handler (`routes/
/// delegations.rs`, which holds the named-groups read lock for the
/// snapshot block): runs [`delegate_admission`] with the canonical
/// actor-blind fork-quarantine gate. `route_id` is the RAW route
/// `:id`, the same key the inline gate used for the marker body and
/// the diagnostics bump.
pub(in crate::server) fn admit_delegate_route<'a>(
    state: &AppState,
    groups: &'a HashMap<String, x0x::groups::GroupInfo>,
    route_id: &str,
) -> Result<&'a x0x::groups::GroupInfo, (StatusCode, Json<serde_json::Value>)> {
    delegate_admission(groups, route_id, |info| {
        reject_fork_quarantined(state, route_id, info)
    })
}

// ─────────────────────── extractor ───────────────────────────────────────

/// The admission result handed to a handler: the resolved access level,
/// the stable group id the route's `:id` resolved to (the DECODED
/// `:id` when the messages route falls through for a group unknown
/// locally — the public-cache fail-open that predates this module),
/// and the ACTING PRINCIPAL's hex (S2) — the identity the handler's
/// ban/policy gates evaluate.
///
/// This is the extractor's admission snapshot, not the final word:
/// handlers that re-read group data for their body re-run the pure core
/// under their own lock (r2/P2-1), so what gets served is always
/// admitted on the snapshot it was read from.
pub(in crate::server) struct GroupAccess {
    level: AccessLevel,
    stable_id: String,
    acting_hex: String,
}

impl GroupAccess {
    /// The level this request was admitted at.
    // No production reader yet: every extractor-wired handler so far
    // (S1 reads, the S3 requests listing) is admitted-or-refused and
    // re-runs its core under its own lock; the S2 secure-write and S3
    // mutation handlers match on the `ActorContext` they already hold
    // (pinned signatures) and consume only `acting_hex`. The classified
    // level is pinned by the table + tests; the first handler that
    // branches on it deletes this allow.
    #[allow(dead_code)]
    pub(in crate::server) fn level(&self) -> AccessLevel {
        self.level
    }

    /// Stable id the route's `:id` resolved to.
    pub(in crate::server) fn stable_id(&self) -> &str {
        &self.stable_id
    }

    /// The ACTING PRINCIPAL's hex (S2): the local daemon's agent for
    /// owner bearers and actor-less local-seat surfaces, the sub-agent
    /// for riders — the subject of the handler-side ban/policy gates.
    pub(in crate::server) fn acting_hex(&self) -> &str {
        &self.acting_hex
    }
}

/// Fail closed when the extractor meets a request the classification
/// table does not carry — a wiring bug, not a public capability.
fn unclassified(method: &Method, path: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": format!("{method} {path} is not classified for group access"),
        })),
    )
        .into_response()
}

/// Fail closed when a CLASSIFIED row cannot be served by this
/// extractor: most classified routes run their admission cores
/// directly under their own lock and never take [`GroupAccess`], and a
/// classified row without a `:id` parameter (open-envelope) is not
/// extractor-shaped. Wiring bugs, not public capabilities — the text
/// names the wiring, not the classification.
fn extractor_not_wired(method: &Method, path: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": format!("{method} {path} does not take the GroupAccess extractor"),
        })),
    )
        .into_response()
}

/// `GET /groups/:id/members`. The extractor's admission snapshot; the
/// handler re-runs [`admit_named_group_members`] under its own lock
/// before serving the roster (r2/P2-1), so this pass is an early
/// refusal, not the last word.
async fn admit_members_route(
    state: &AppState,
    actor: &ActorContext,
    id: &str,
) -> Result<GroupAccess, Response> {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Session bearers need the #447/#458 seat label; the other actors are
    // decided without it (the arm they take ignores the label) — the
    // same `admit_named_group_members_of_state` arm the handler re-runs
    // under its own lock (S5 single-sourced the shape).
    let level = admit_named_group_members_of_state(state, info, actor)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok(GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        acting_hex: acting_principal_hex(actor, &local_hex),
    })
}

/// `GET /groups/:id/messages` — no actor gate; an unknown group fails
/// OPEN to the public cache with the caller-supplied id as stable id,
/// exactly as the pre-extractor handler did.
async fn admit_messages_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    match groups.get(id) {
        Some(info) => {
            let level =
                admit_public_messages(info, &local_hex).map_err(IntoResponse::into_response)?;
            Ok(GroupAccess {
                level,
                stable_id: info.stable_group_id().to_string(),
                // Actor-less surface: the local daemon's seat is the
                // policy subject.
                acting_hex: local_hex.clone(),
            })
        }
        None => Ok(GroupAccess {
            level: AccessLevel::PublicRead,
            stable_id: id.to_string(),
            acting_hex: local_hex,
        }),
    }
}

/// `GET /groups/:id/state` — the public projection; unknown group 404.
async fn admit_state_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    Ok(GroupAccess {
        level: AccessLevel::PublicRead,
        stable_id: info.stable_group_id().to_string(),
        // Actor-less public projection: the local daemon is the subject.
        acting_hex: hex::encode(state.agent.agent_id().as_bytes()),
    })
}

/// `GET /groups/:id/state/commits`.
async fn admit_state_commits_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(id) else {
        return Err(not_found("group not found").into_response());
    };
    let level = admit_state_commits(info, &local_hex).map_err(IntoResponse::into_response)?;
    Ok(GroupAccess {
        level,
        stable_id: info.stable_group_id().to_string(),
        // Actor-less retained history: the local daemon's seat is the
        // membership subject.
        acting_hex: local_hex,
    })
}

/// `GET /groups/:id/requests` — the one S3 route that takes the
/// extractor: no body argument to keep first, no directory-durability
/// gate before the lookup, and no actor argument ever (the seat gate
/// evaluates the local daemon, not the bearer — the route never read
/// the actor and still does not). The handler re-runs
/// [`admit_join_request_listing`] under its own lock before serving
/// (the `/members` pattern, r2/P2-1).
async fn admit_join_requests_route(state: &AppState, id: &str) -> Result<GroupAccess, Response> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let info =
        admit_join_request_listing(&groups, id, &local_hex).map_err(IntoResponse::into_response)?;
    Ok(GroupAccess {
        level: AccessLevel::Admin,
        stable_id: info.stable_group_id().to_string(),
        // Actor-less seat gate: the local daemon is the subject.
        acting_hex: local_hex,
    })
}

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for GroupAccess {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let (row, params) = resolve_route(parts).await?;
        // (S5 removed the Unmigrated arm: every row is classified now,
        // so a table hit always has a real admission rule and a MISS
        // already failed closed in `resolve_route` above.)
        // The router's pattern is byte-identical to the row's (the
        // parity test pins it), so the group id's parameter NAME comes
        // from the row's own template: the first `:param` segment. Every
        // classified S1 route is `/groups/:id/...`.
        let id_param = row
            .path
            .strip_prefix("/groups/")
            .and_then(|rest| rest.split('/').next())
            .and_then(|segment| segment.strip_prefix(':'));
        let Some(id_param) = id_param else {
            return Err(extractor_not_wired(&parts.method, parts.uri.path()));
        };
        let Some(id) = params.get(id_param) else {
            return Err(extractor_not_wired(&parts.method, parts.uri.path()));
        };
        let id = id.clone();
        match (row.method.as_str(), row.path) {
            ("GET", "/groups/:id/members") => {
                // The actor is always present behind the auth
                // middleware, which inserts one on every admitted
                // request (auth.rs:171 durable, auth.rs:215 rider) — and
                // the members handler's own `Extension` argument runs
                // before this extractor and rejects a missing actor with
                // the same `Extension` 500 the pre-S1 handler produced,
                // so this extraction is a typed re-read, never a live
                // 401 path (r2/P3-4).
                let Extension(actor) = Extension::<ActorContext>::from_request_parts(parts, state)
                    .await
                    .map_err(|rejection| rejection.into_response())?;
                admit_members_route(state.as_ref(), &actor, &id).await
            }
            ("GET", "/groups/:id/messages") => admit_messages_route(state.as_ref(), &id).await,
            ("GET", "/groups/:id/state") => admit_state_route(state.as_ref(), &id).await,
            ("GET", "/groups/:id/state/commits") => {
                admit_state_commits_route(state.as_ref(), &id).await
            }
            ("GET", "/groups/:id/requests") => admit_join_requests_route(state.as_ref(), &id).await,
            // Classified routes deliberately left without an arm: the
            // S1 `GET /groups/:id` + `/delegations`, the five S2
            // secure-write handlers, the S3 mutation family, the four
            // S4 stores handlers and the S5 delegate mint all run
            // their cores directly under their own lock — their
            // signatures are pinned by positional test callers, or an
            // extractor argument would reorder rejection precedence
            // (body-parse 400s, the request routes' durability 503,
            // the delegate's #446 403-before-parse and side-effect
            // orderings all precede the gates today). Every other S4
            // route has NO `:id`-shaped admission at all
            // (discovery/cards/join, the history scope gates, the
            // task-list id parsers, the #1228 no-actor surfaces) —
            // classification-only, the handler keeps today's exact
            // checks. If a future handler wires this extractor to any
            // of them, this fails closed instead of guessing — and
            // note `send` could not take this extractor anyway without
            // reordering its body validations (kind/size/thread)
            // after the entry gates.
            _ => Err(extractor_not_wired(&parts.method, parts.uri.path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::any;
    use tower::ServiceExt as _;

    // ────────────────── parity fixtures ──────────────────

    /// Whether a router/registry path belongs to the group plane this
    /// table governs (the slice plan's §5 predicate).
    fn is_group_plane(path: &str) -> bool {
        path == "/groups"
            || path.starts_with("/groups/")
            || path == "/history"
            || path.starts_with("/history/")
            || path == "/task-lists"
            || path.starts_with("/task-lists/")
            || path == "/mls/groups"
            || path.starts_with("/mls/groups/")
    }

    /// `:param` segments collapse to `*` so table, router and registry
    /// keys agree regardless of parameter naming.
    fn normalize(path: &str) -> String {
        path.split('/')
            .map(|segment| {
                if segment.starts_with(':') {
                    "*"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The first string literal of a `.route(..)` call body (the path).
    fn first_string_literal(call: &str) -> Option<String> {
        let bytes = call.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let mut literal = String::new();
                let mut j = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' && j + 1 < bytes.len() {
                        literal.push(bytes[j] as char);
                        literal.push(bytes[j + 1] as char);
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'"' {
                        return Some(literal);
                    }
                    literal.push(bytes[j] as char);
                    j += 1;
                }
                return None;
            }
            i += 1;
        }
        None
    }

    /// The method-router names (`get(..)`, `.post(..)`, …) a `.route(..)`
    /// call wires, with string literals stripped so handler names can
    /// never be mistaken for method routers.
    fn method_routers(call: &str) -> Vec<&'static str> {
        let mut stripped = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for character in call.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
            } else if character == '"' {
                in_string = true;
            } else {
                stripped.push(character);
            }
        }
        let mut found = Vec::new();
        for name in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let needle = format!("{name}(");
            let mut from = 0;
            while let Some(found_at) = stripped[from..].find(&needle) {
                let at = from + found_at;
                let preceded_by_word_char = at > 0
                    && (stripped.as_bytes()[at - 1].is_ascii_alphanumeric()
                        || stripped.as_bytes()[at - 1] == b'_');
                if !preceded_by_word_char {
                    found.push(name);
                }
                from = at + name.len();
            }
        }
        found
    }

    /// Every group-plane (METHOD, RAW path) wired in the daemon's one
    /// router builder, parsed out of `src/server/mod.rs`. RAW means the
    /// pattern literal verbatim — parameter names included — because
    /// [`resolve_route`] compares the router's `MatchedPath` pattern to the
    /// table row byte-for-byte. A group-plane `.route(..)` whose methods
    /// the parser cannot recognise fails LOUDLY here rather than
    /// vanishing from parity (r2/P3-3).
    fn router_group_plane_raw() -> Vec<(String, String)> {
        let source = include_str!("mod.rs");
        let bytes = source.as_bytes();
        let mut routes = Vec::new();
        let mut search = 0;
        while let Some(found) = source[search..].find(".route(") {
            let call_start = search + found + ".route(".len();
            let mut depth = 1usize;
            let mut in_string = false;
            let mut escaped = false;
            let mut i = call_start;
            while i < bytes.len() && depth > 0 {
                let byte = bytes[i];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                } else if byte == b'"' {
                    in_string = true;
                } else if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    depth -= 1;
                }
                i += 1;
            }
            let call_end = if i > call_start { i - 1 } else { call_start };
            let call = &source[call_start..call_end];
            if let Some(path) = first_string_literal(call) {
                if is_group_plane(&path) {
                    let methods = method_routers(call);
                    assert!(
                        !methods.is_empty(),
                        "group-plane route {path} wires no method router the parity parser \
                         recognises — extend the parser, do not let the route vanish from parity"
                    );
                    for method in methods {
                        routes.push((method.to_uppercase(), path.clone()));
                    }
                }
            }
            search = i;
        }
        routes.sort();
        routes.dedup();
        routes
    }

    /// Normalized (parameter names collapsed) view of the router's
    /// group plane, for parity against the registry.
    fn router_group_plane() -> Vec<(String, String)> {
        router_group_plane_raw()
            .into_iter()
            .map(|(method, path)| (method, normalize(&path)))
            .collect()
    }

    /// The group-plane (METHOD, normalized path) set the CLI/daemon
    /// endpoint registry declares.
    fn registry_group_plane() -> Vec<(String, String)> {
        let mut routes: Vec<(String, String)> = crate::api::ENDPOINTS
            .iter()
            .filter(|endpoint| is_group_plane(endpoint.path))
            .map(|endpoint| (endpoint.method.to_string(), normalize(endpoint.path)))
            .collect();
        routes.sort();
        routes.dedup();
        routes
    }

    fn table_keys() -> Vec<(String, String)> {
        let mut keys: Vec<(String, String)> = GROUP_PLANE_ROUTES
            .iter()
            .map(|row| (row.method.as_str().to_string(), normalize(row.path)))
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    // ────────────────── parity + classification ──────────────────

    /// Controller condition 1: the classification table lives here (not
    /// in `EndpointDef`), and parity holds against BOTH the router and
    /// the registry — no group route can be wired without a row, and no
    /// row can name a route that does not exist. This is the ceiling
    /// every later slice migrates under.
    #[test]
    fn classification_table_parity_with_router_and_registry() {
        let table = table_keys();
        assert_eq!(
            table,
            router_group_plane(),
            "classification table must list exactly the group-plane routes wired in src/server/mod.rs"
        );
        assert_eq!(
            table,
            registry_group_plane(),
            "classification table must match the group-plane entries of crate::api::ENDPOINTS"
        );
    }

    /// r2/P3-3: the router-source parser sees the whole picture. A
    /// nested or merged router — or a `.route(..)` whose method wiring
    /// the parser fails to recognise — would each silently shrink the
    /// parsed plane while parity still passed against the shrunken
    /// set. The no-method case is asserted inside
    /// [`router_group_plane_raw`]; nesting/merging cannot be scoped to
    /// group paths (their subtree is opaque), so the tokens themselves
    /// are banned from the one router builder.
    #[test]
    fn parity_source_parser_blind_spots_stay_shut() {
        let source = include_str!("mod.rs");
        assert!(
            !source.contains(".nest("),
            "a nested router's group-plane routes would be invisible to the parity parser"
        );
        assert!(
            !source.contains(".merge("),
            "a merged router's group-plane routes would be invisible to the parity parser"
        );
    }

    /// r2/P2-2: the table's pattern strings are byte-identical to the
    /// router's, because [`resolve_route`] compares the router's
    /// `MatchedPath` pattern to the row with a plain string equality —
    /// a parameter rename must hit both sides or this fails.
    #[test]
    fn table_patterns_are_byte_identical_to_the_router() {
        let mut table: Vec<(String, String)> = GROUP_PLANE_ROUTES
            .iter()
            .map(|row| (row.method.as_str().to_string(), row.path.to_string()))
            .collect();
        table.sort();
        table.dedup();
        assert_eq!(
            table,
            router_group_plane_raw(),
            "MatchedPath classification compares patterns byte-for-byte"
        );
    }

    /// S5: the `clippy.toml` ceiling is build configuration — `cargo
    /// test` never reads it, so silently deleting or emptying it would
    /// re-open the inline-admission drift class (#821/#870/#877) with
    /// every behavioural suite still green. The config is PARSED, not
    /// text-matched, so a commented-out entry or a reformatting
    /// (bare string vs `{ path = ... }` table) cannot slip past: the
    /// exact `disallowed-methods` set is pinned — the four #1166 paths
    /// present, the controller's two deliberate exclusions (review-d
    /// condition 2 extended by the S5 caller audit) absent, and no
    /// fifth entry — so touching the ceiling is a visible, deliberate
    /// edit.
    #[test]
    fn disallowed_methods_ceiling_is_pinned() {
        let config: toml::Table =
            toml::from_str(include_str!("../../clippy.toml")).expect("clippy.toml parses as TOML");
        let entries = config
            .get("disallowed-methods")
            .and_then(|value| value.as_array())
            .expect("clippy.toml carries a `disallowed-methods` array");
        // clippy accepts bare-string entries and `{ path = ... }`
        // tables; every entry must yield a path or the pin under-counts.
        let listed: std::collections::BTreeSet<&str> = entries
            .iter()
            .map(|entry| match entry {
                toml::Value::String(path) => Ok(path.as_str()),
                toml::Value::Table(table) => table
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| format!("entry without a `path` key: {entry}")),
                other => Err(format!("unsupported entry shape: {other}")),
            })
            .collect::<Result<_, _>>()
            .expect("every disallowed-methods entry carries a path");
        let ceiling = [
            "x0x::server::routes::named_groups::local_join_membership_state",
            "x0x::server::routes::named_groups::require_admin_or_above",
            "x0x::server::routes::named_groups::reject_fork_quarantined_for_actor",
            "x0x::server::rider_auth::ActorContext::rider_allows_group",
        ];
        for path in ceiling {
            assert!(
                listed.contains(path),
                "clippy.toml must keep {path} on disallowed-methods — the #1166 ceiling"
            );
        }
        for excluded in [
            "x0x::server::rider_auth::ActorContext::is_durable_owner",
            "x0x::groups::GroupInfo::has_active_member",
        ] {
            assert!(
                !listed.contains(excluded),
                "{excluded} is deliberately NOT ceiling-listed (legitimate non-group / \
                 domain callers — see clippy.toml's header); listing it needs a new ruling"
            );
        }
        // Exact set, not just membership: an unruled fifth entry fails too.
        assert_eq!(
            listed,
            ceiling.into_iter().collect(),
            "disallowed-methods must be exactly the four #1166 paths"
        );
    }

    /// The slice contract: every family through S4 is classified, at
    /// honest levels (the S2 rows label the bearer class, the S3 rows
    /// the seat/no-actor reality, the S4 rows the long tail's actual
    /// gates — see the table comments), and S5 migrated the last row
    /// (`POST /groups/:id/delegate` at OwnerDurable) and retired the
    /// `Unmigrated` class — a new group-plane route MUST land with a
    /// row and an entry here.
    #[test]
    fn s1_through_s5_families_fully_classified() {
        let expected: &[(Method, &str, AccessLevel)] = &[
            (
                Method::GET,
                "/groups/:id",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::GET,
                "/groups/:id/members",
                AccessLevel::Member(MemberState::Active),
            ),
            (Method::GET, "/groups/:id/messages", AccessLevel::PublicRead),
            (Method::GET, "/groups/:id/state", AccessLevel::PublicRead),
            (
                Method::GET,
                "/groups/:id/state/commits",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::GET,
                "/groups/:id/delegations",
                AccessLevel::Member(MemberState::Active),
            ),
            (Method::POST, "/groups/:id/send", AccessLevel::SessionBearer),
            (
                Method::POST,
                "/groups/:id/secure/encrypt",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/:id/secure/decrypt",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/:id/secure/reseal",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/secure/open-envelope",
                AccessLevel::PublicWrite,
            ),
            (Method::POST, "/groups/:id/invite", AccessLevel::Admin),
            (Method::POST, "/groups/:id/members", AccessLevel::Admin),
            (
                Method::DELETE,
                "/groups/:id/members/:agent_id",
                AccessLevel::Admin,
            ),
            (
                Method::PATCH,
                "/groups/:id/members/:agent_id/role",
                AccessLevel::Admin,
            ),
            (
                Method::POST,
                "/groups/:id/ban/:agent_id",
                AccessLevel::Admin,
            ),
            (
                Method::DELETE,
                "/groups/:id/ban/:agent_id",
                AccessLevel::Admin,
            ),
            (Method::PATCH, "/groups/:id", AccessLevel::Admin),
            (Method::PATCH, "/groups/:id/policy", AccessLevel::Admin),
            (
                Method::PUT,
                "/groups/:id/display-name",
                AccessLevel::PublicWrite,
            ),
            (Method::POST, "/groups/:id/state/seal", AccessLevel::Admin),
            (
                Method::POST,
                "/groups/:id/state/withdraw",
                AccessLevel::Admin,
            ),
            (Method::DELETE, "/groups/:id", AccessLevel::JoinSelf),
            (Method::GET, "/groups/:id/requests", AccessLevel::Admin),
            (
                Method::POST,
                "/groups/:id/requests",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/groups/:id/requests/:request_id/approve",
                AccessLevel::Admin,
            ),
            (
                Method::POST,
                "/groups/:id/requests/:request_id/reject",
                AccessLevel::Admin,
            ),
            (
                Method::DELETE,
                "/groups/:id/requests/:request_id",
                AccessLevel::PublicWrite,
            ),
            (Method::POST, "/groups", AccessLevel::PublicWrite),
            (Method::GET, "/groups", AccessLevel::PublicRead),
            (Method::GET, "/groups/discover", AccessLevel::PublicRead),
            (
                Method::GET,
                "/groups/discover/nearby",
                AccessLevel::PublicRead,
            ),
            (
                Method::GET,
                "/groups/discover/subscriptions",
                AccessLevel::PublicRead,
            ),
            (
                Method::POST,
                "/groups/discover/subscribe",
                AccessLevel::PublicWrite,
            ),
            (
                Method::DELETE,
                "/groups/discover/subscribe/:kind/:shard",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/groups/cards/import",
                AccessLevel::PublicWrite,
            ),
            (Method::GET, "/groups/cards/:id", AccessLevel::PublicRead),
            (Method::POST, "/groups/join", AccessLevel::PublicWrite),
            (
                Method::GET,
                "/groups/:id/join-status",
                AccessLevel::PublicRead,
            ),
            (
                Method::POST,
                "/groups/:id/quarantine/clear",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/groups/:id/stores",
                AccessLevel::SessionBearer,
            ),
            (
                Method::GET,
                "/groups/:id/stores/:app/legacy-imports",
                AccessLevel::SessionBearer,
            ),
            (
                Method::GET,
                "/groups/:id/stores/:app/legacy-imports/:source_id",
                AccessLevel::SessionBearer,
            ),
            (
                Method::POST,
                "/groups/:id/stores/:app/legacy-imports/:source_id",
                AccessLevel::SessionBearer,
            ),
            (Method::GET, "/history", AccessLevel::SessionBearer),
            (Method::DELETE, "/history", AccessLevel::SessionBearer),
            (
                Method::GET,
                "/history/message/:msg_id",
                AccessLevel::PublicRead,
            ),
            (Method::GET, "/history/scopes", AccessLevel::PublicRead),
            (Method::GET, "/history/search", AccessLevel::PublicRead),
            (Method::GET, "/history/stats", AccessLevel::PublicRead),
            (Method::GET, "/history/policy", AccessLevel::OwnerDurable),
            (Method::POST, "/history/retain", AccessLevel::OwnerDurable),
            (Method::GET, "/task-lists", AccessLevel::PublicRead),
            (
                Method::POST,
                "/task-lists",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::GET,
                "/task-lists/:id/tasks",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::POST,
                "/task-lists/:id/tasks",
                AccessLevel::Member(MemberState::Active),
            ),
            (
                Method::PATCH,
                "/task-lists/:id/tasks/:tid",
                AccessLevel::Member(MemberState::Active),
            ),
            (Method::POST, "/mls/groups", AccessLevel::PublicWrite),
            (Method::GET, "/mls/groups", AccessLevel::PublicRead),
            (Method::GET, "/mls/groups/:id", AccessLevel::PublicRead),
            (
                Method::POST,
                "/mls/groups/:id/members",
                AccessLevel::PublicWrite,
            ),
            (
                Method::DELETE,
                "/mls/groups/:id/members/:agent_id",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/mls/groups/:id/encrypt",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/mls/groups/:id/decrypt",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/mls/groups/:id/welcome",
                AccessLevel::PublicWrite,
            ),
            (
                Method::POST,
                "/groups/:id/delegate",
                AccessLevel::OwnerDurable,
            ),
        ];
        assert_eq!(
            GROUP_PLANE_ROUTES.len(),
            expected.len(),
            "every group-plane row is classified (S1–S5); anything new needs a row AND an entry here"
        );
        for (method, path, level) in expected {
            let row = GROUP_PLANE_ROUTES
                .iter()
                .find(|row| row.method == *method && row.path == *path)
                .unwrap_or_else(|| panic!("{method} {path} missing from the table"));
            assert_eq!(row.level, *level, "{method} {path}");
        }
    }

    /// Issue #1228's still-unchecked surfaces, pinned at their REAL
    /// level: `POST /groups/:id/quarantine/clear` and every
    /// `/mls/groups*` route carry NO actor-based check today — any
    /// valid bearer (a 10-minute session token included) reaches them;
    /// only riders are stopped, by the auth middleware's
    /// deny-by-default allowlist. S4 classifies them PublicRead /
    /// PublicWrite — the no-actor class — WITHOUT tightening: each fix
    /// is a separate reviewed change, and fixing it means editing this
    /// list and the row together, deliberately.
    #[test]
    fn s4_pins_the_no_actor_check_routes_as_unchanged() {
        let unchecked: &[(Method, &str)] = &[
            (Method::POST, "/groups/:id/quarantine/clear"),
            (Method::POST, "/mls/groups"),
            (Method::GET, "/mls/groups"),
            (Method::GET, "/mls/groups/:id"),
            (Method::POST, "/mls/groups/:id/members"),
            (Method::DELETE, "/mls/groups/:id/members/:agent_id"),
            (Method::POST, "/mls/groups/:id/encrypt"),
            (Method::POST, "/mls/groups/:id/decrypt"),
            (Method::POST, "/mls/groups/:id/welcome"),
        ];
        for (method, path) in unchecked {
            let row = GROUP_PLANE_ROUTES
                .iter()
                .find(|row| row.method == *method && row.path == *path)
                .unwrap_or_else(|| panic!("{method} {path} missing from the table"));
            let expected = if *method == Method::GET {
                AccessLevel::PublicRead
            } else {
                AccessLevel::PublicWrite
            };
            assert_eq!(
                row.level, expected,
                "{method} {path}: #1228 unchecked surface — classifying it any tighter is a \
                 behaviour change that needs its own reviewed PR"
            );
        }
    }

    // ────────────────── router-level resolution (r2) ──────────────────

    /// Probe handler: runs [`resolve_route`] on the parts a REAL axum
    /// router produced (MatchedPath + captured, percent-decoded
    /// UrlParams) and answers with the resolved row pattern plus the
    /// decoded params, or the rejection response itself.
    async fn resolve_probe(request: Request<Body>) -> Response {
        let (mut parts, _) = request.into_parts();
        match resolve_route(&mut parts).await {
            Ok((row, params)) => (
                StatusCode::OK,
                Json(serde_json::json!({ "path": row.path, "params": params })),
            )
                .into_response(),
            Err(response) => response,
        }
    }

    /// The pre-extractor oracle: what the old `Path(id): Path<String>`
    /// handler arguments did with the same request.
    async fn legacy_path_probe(request: Request<Body>) -> Response {
        let (mut parts, _) = request.into_parts();
        match Path::<String>::from_request_parts(&mut parts, &()).await {
            Ok(Path(id)) => (StatusCode::OK, Json(serde_json::json!({ "id": id }))).into_response(),
            Err(rejection) => rejection.into_response(),
        }
    }

    async fn probe_body(response: Response) -> serde_json::Value {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("non-JSON body {bytes:?} ({status})"))
    }

    /// r2/P2-2: classification rides the router's own `MatchedPath`
    /// pattern — literal-vs-param priority is the real router's, not a
    /// re-implementation — and an off-table wiring fails closed.
    #[tokio::test]
    async fn classification_rides_the_routers_matched_path() {
        let app = axum::Router::new()
            .route("/groups/discover", any(resolve_probe))
            .route("/groups/:id", any(resolve_probe))
            .route("/groups/:id/members", any(resolve_probe))
            // Off-table wiring: mounted, so the probe (not the router's
            // own 404) answers.
            .route("/calls/:id", any(resolve_probe));

        // Static literal beats the parameterised row (matchit priority).
        let response = app
            .clone()
            .oneshot(
                Request::get("/groups/discover")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = probe_body(response).await;
        assert_eq!(body["path"], "/groups/discover");
        assert_eq!(body["params"], serde_json::json!({}));

        // Parameterised rows capture the decoded id by param name.
        let response = app
            .clone()
            .oneshot(
                Request::get("/groups/abc123/members")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = probe_body(response).await;
        assert_eq!(body["path"], "/groups/:id/members");
        assert_eq!(body["params"]["id"], "abc123");

        // A wired pattern whose METHOD has no table row (PUT members —
        // the POST row exists, but no PUT) and off-table wiring both
        // fail closed in `resolve_route` with the 403 `unclassified`
        // body (S5: rows no longer carry a class check — every row is
        // classified).
        for (method, path) in [("PUT", "/groups/abc123/members"), ("GET", "/calls/abc123")] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("request");
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        }
    }

    /// r2/P2-2: a percent-encoded `:id` decodes to exactly the value the
    /// old `Path<String>` handler argument produced — so
    /// `/groups/%61bc…` resolves the group (and its gates) instead of
    /// slipping past the unknown-group lookup into the messages
    /// public-cache fail-open.
    #[tokio::test]
    async fn percent_encoded_ids_decode_exactly_like_the_old_path_extractor() {
        let new = axum::Router::new()
            .route("/groups/:id/messages", any(resolve_probe))
            .oneshot(
                Request::get("/groups/issue%3821-%6Bnown/messages")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let old = axum::Router::new()
            .route("/groups/:id/messages", any(legacy_path_probe))
            .oneshot(
                Request::get("/groups/issue%3821-%6Bnown/messages")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(new.status(), StatusCode::OK);
        assert_eq!(old.status(), StatusCode::OK);
        let new_body = probe_body(new).await;
        let old_body = probe_body(old).await;
        assert_eq!(new_body["params"]["id"], old_body["id"]);
        assert_eq!(new_body["params"]["id"], "issue821-known");
        assert_eq!(new_body["path"], "/groups/:id/messages");
    }

    /// r2/P2-2: an id that does not percent-decode to UTF-8 keeps the
    /// old 400 — byte-identical to the `Path<String>` rejection the
    /// pre-extractor handler argument produced (the router's own
    /// decoder rejects before serde is involved).
    #[tokio::test]
    async fn invalid_percent_encoding_keeps_the_old_400() {
        for raw in ["/groups/%FF/messages", "/groups/%C3%28/messages"] {
            let new = axum::Router::new()
                .route("/groups/:id/messages", any(resolve_probe))
                .clone()
                .oneshot(Request::get(raw).body(Body::empty()).expect("request"))
                .await
                .expect("response");
            let old = axum::Router::new()
                .route("/groups/:id/messages", any(legacy_path_probe))
                .clone()
                .oneshot(Request::get(raw).body(Body::empty()).expect("request"))
                .await
                .expect("response");
            assert_eq!(new.status(), StatusCode::BAD_REQUEST, "{raw}");
            assert_eq!(old.status(), StatusCode::BAD_REQUEST, "{raw}");
            let new_bytes = to_bytes(new.into_body(), 1 << 16).await.expect("body");
            let old_bytes = to_bytes(old.into_body(), 1 << 16).await.expect("body");
            assert_eq!(new_bytes, old_bytes, "{raw}");
        }
    }

    // ────────────────── admission bodies ──────────────────

    fn durable() -> ActorContext {
        ActorContext::Owner { durable: true }
    }

    fn session() -> ActorContext {
        ActorContext::Owner { durable: false }
    }

    fn rider() -> ActorContext {
        ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 1,
            token_hash: "bb".repeat(32),
            groups: Vec::new(),
        }
    }

    fn assert_refusal(admission: Admission, status: StatusCode, error: &str, reason: Option<&str>) {
        match admission {
            Ok(level) => panic!("expected refusal, admitted at {level:?}"),
            Err((actual_status, Json(body))) => {
                assert_eq!(actual_status, status, "{body}");
                assert_eq!(body["ok"], serde_json::json!(false), "{body}");
                assert_eq!(body["error"], error, "{body}");
                match reason {
                    Some(reason) => assert_eq!(body["reason"], reason, "{body}"),
                    None => assert!(body.get("reason").is_none(), "{body}"),
                }
            }
        }
    }

    fn fixture_group(id: &str) -> x0x::groups::GroupInfo {
        x0x::groups::GroupInfo::new(
            "fixture".to_string(),
            "fixture".to_string(),
            x0x::identity::AgentId([0x11; 32]),
            id.to_string(),
        )
    }

    fn local_agent_hex() -> String {
        "22".repeat(32)
    }

    fn group_with_local_seat(id: &str) -> x0x::groups::GroupInfo {
        let mut info = fixture_group(id);
        info.add_member(
            local_agent_hex(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info
    }

    /// The #821/#447 contract for `GET /groups/:id`, per actor and seat
    /// label, including the stub arm a session bearer in join limbo
    /// earns and the exact rider body.
    #[test]
    fn details_admission_reproduces_the_inline_decisions() {
        for label in [
            "active",
            "pending",
            "not_member",
            "pending_authority_commit",
        ] {
            assert_eq!(
                admit_named_group_details(&durable(), label).unwrap(),
                AccessLevel::OwnerDurable,
                "durable owner bypasses every seat label ({label})"
            );
        }
        assert_eq!(
            admit_named_group_details(&session(), "active").unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        assert_eq!(
            admit_named_group_details(&session(), "pending_authority_commit").unwrap(),
            AccessLevel::Member(MemberState::PendingAuthorityCommit),
            "the #447 limbo earns the stub arm"
        );
        for label in ["pending", "not_member"] {
            assert_refusal(
                admit_named_group_details(&session(), label),
                StatusCode::FORBIDDEN,
                "active local group membership required",
                Some("group_membership_required"),
            );
        }
        assert_refusal(
            admit_named_group_details(&rider(), "active"),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read named-group details",
            None,
        );
    }

    /// `GET /groups/:id/members`: no stub arm — a pending seat (either
    /// kind) refuses, exactly as `issue821_read_auth.rs` pins.
    #[test]
    fn members_admission_reproduces_the_inline_decisions() {
        for label in [
            "active",
            "pending",
            "not_member",
            "pending_authority_commit",
        ] {
            assert_eq!(
                admit_named_group_members(&durable(), label).unwrap(),
                AccessLevel::OwnerDurable,
                "durable owner bypasses every seat label ({label})"
            );
        }
        assert_eq!(
            admit_named_group_members(&session(), "active").unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        for label in ["pending", "not_member", "pending_authority_commit"] {
            assert_refusal(
                admit_named_group_members(&session(), label),
                StatusCode::FORBIDDEN,
                "active local group membership required",
                Some("group_membership_required"),
            );
        }
        assert_refusal(
            admit_named_group_members(&rider(), "active"),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read named-group members",
            None,
        );
    }

    /// The ADR-0040/#870 contract for `GET /groups/:id/delegations`:
    /// withdrawn 404, session-membership 403 before any payload, rider
    /// 403, and the read policy that binds even durable non-members.
    #[test]
    fn delegations_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();

        // Withdrawn shell: 404 for everyone, before any authority is read.
        let mut withdrawn = group_with_local_seat("del");
        withdrawn.withdrawn = true;
        for actor in [durable(), session(), rider()] {
            assert_refusal(
                admit_group_delegations(&withdrawn, &actor, &local_hex),
                StatusCode::NOT_FOUND,
                "group is withdrawn",
                None,
            );
        }

        // Live, local seat: every owner admitted.
        let membered = group_with_local_seat("del");
        assert_eq!(
            admit_group_delegations(&membered, &durable(), &local_hex).unwrap(),
            AccessLevel::OwnerDurable
        );
        assert_eq!(
            admit_group_delegations(&membered, &session(), &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        assert_refusal(
            admit_group_delegations(&membered, &rider(), &local_hex),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read group delegations",
            None,
        );

        // Live, no seat: session refused on membership; the durable owner
        // walks into the policy gate instead (issue #870's durable case
        // relied on the fixture group being Public).
        let bare = fixture_group("del");
        assert_refusal(
            admit_group_delegations(&bare, &session(), &local_hex),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        assert_refusal(
            admit_group_delegations(&bare, &rider(), &local_hex),
            StatusCode::FORBIDDEN,
            "rider tokens cannot read group delegations",
            None,
        );
        let mut members_only = fixture_group("del");
        members_only.policy.read_access = x0x::groups::GroupReadAccess::MembersOnly;
        assert_refusal(
            admit_group_delegations(&members_only, &durable(), &local_hex),
            StatusCode::FORBIDDEN,
            "members-only read policy",
            None,
        );
        let mut public = fixture_group("del");
        public.policy.read_access = x0x::groups::GroupReadAccess::Public;
        assert_eq!(
            admit_group_delegations(&public, &durable(), &local_hex).unwrap(),
            AccessLevel::OwnerDurable,
            "durable non-member retains public read policy"
        );
    }

    /// #111: live retained history is member content; a withdrawn shell
    /// keeps serving its keyless audit history.
    #[test]
    fn state_commits_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        assert_refusal(
            admit_state_commits(&fixture_group("sc"), &local_hex),
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
            None,
        );
        assert_eq!(
            admit_state_commits(&group_with_local_seat("sc"), &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active)
        );
        let mut withdrawn = fixture_group("sc");
        withdrawn.withdrawn = true;
        assert_eq!(
            admit_state_commits(&withdrawn, &local_hex).unwrap(),
            AccessLevel::PublicRead,
            "withdrawn shells keep their audit history readable"
        );
    }

    /// The messages gates in today's order: withdrawn 409 (CONFLICT, not
    /// 404) before the MlsEncrypted 400 before the MembersOnly 403; the
    /// actor never matters on this surface.
    #[test]
    fn public_messages_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut info = fixture_group("msgs");
        info.policy.read_access = x0x::groups::GroupReadAccess::Public;
        info.policy.confidentiality = x0x::groups::GroupConfidentiality::SignedPublic;
        assert_eq!(
            admit_public_messages(&info, &local_hex).unwrap(),
            AccessLevel::PublicRead,
            "public SignedPublic group serves non-members"
        );

        let mut members_only = info.clone();
        members_only.policy.read_access = x0x::groups::GroupReadAccess::MembersOnly;
        assert_refusal(
            admit_public_messages(&members_only, &local_hex),
            StatusCode::FORBIDDEN,
            "members-only read policy",
            None,
        );
        let mut membered = members_only;
        membered.add_member(
            local_agent_hex(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        assert_eq!(
            admit_public_messages(&membered, &local_hex).unwrap(),
            AccessLevel::Member(MemberState::Active),
            "MembersOnly + local seat serves at Member"
        );

        let mut mls = info;
        mls.policy.confidentiality = x0x::groups::GroupConfidentiality::MlsEncrypted;
        assert_refusal(
            admit_public_messages(&mls, &local_hex),
            StatusCode::BAD_REQUEST,
            "MlsEncrypted groups do not publish a plaintext message history",
            None,
        );
        let mut withdrawn_and_mls = mls;
        withdrawn_and_mls.withdrawn = true;
        assert_refusal(
            admit_public_messages(&withdrawn_and_mls, &local_hex),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
            // withdrawn outranks the MlsEncrypted arm — today's order.
        );
    }

    // ────────────────── S2 secure-write admission ──────────────────

    /// `assert_refusal` for the S2 cores, whose Ok side is the admitted
    /// `(group, access)` pair rather than a bare level.
    fn assert_secure_refusal<T>(
        admission: Result<T, (StatusCode, Json<serde_json::Value>)>,
        status: StatusCode,
        error: &str,
        reason: Option<&str>,
    ) {
        match admission {
            Ok(_) => panic!("expected refusal, admitted"),
            Err((actual_status, Json(body))) => {
                assert_eq!(actual_status, status, "{body}");
                assert_eq!(body["ok"], serde_json::json!(false), "{body}");
                assert_eq!(body["error"], error, "{body}");
                match reason {
                    Some(reason) => assert_eq!(body["reason"], reason, "{body}"),
                    None => assert!(body.get("reason").is_none(), "{body}"),
                }
            }
        }
    }

    /// The two #877 gate shapes the stub tests propagate verbatim.
    fn quarantine_membership_403() -> (StatusCode, Json<serde_json::Value>) {
        api_error_with_reason(
            StatusCode::FORBIDDEN,
            "active local group membership required",
            "group_membership_required",
        )
    }

    fn quarantine_marker_409() -> (StatusCode, Json<serde_json::Value>) {
        api_error_with_reason(
            StatusCode::CONFLICT,
            "fork quarantine active",
            "fork_quarantined",
        )
    }

    /// `POST /groups/:id/send` entry admission: raw-id lookup 404 →
    /// withdrawn 409 → the #877 gate (whose refusal propagates
    /// verbatim, membership 403 before marker 409), then the actor
    /// class + acting principal with NO seat or grant asserted.
    #[test]
    fn send_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate runs.
        assert_secure_refusal(
            send_admission(&groups, "missing", &durable(), &local_hex, |_| {
                panic!("the lookup 404 must fire before the quarantine gate")
            }),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // Withdrawn shell: the 409 fires before the gate.
        let mut withdrawn = group_with_local_seat("send");
        withdrawn.withdrawn = true;
        groups.insert("send".to_string(), withdrawn);
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                panic!("the withdrawn 409 must fire before the quarantine gate")
            }),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        groups.insert("send".to_string(), group_with_local_seat("send"));

        // A gate refusal propagates verbatim — both #877 shapes.
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                Some(quarantine_membership_403())
            }),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        assert_secure_refusal(
            send_admission(&groups, "send", &session(), &local_hex, |_| {
                Some(quarantine_marker_409())
            }),
            StatusCode::CONFLICT,
            "fork quarantine active",
            Some("fork_quarantined"),
        );

        // Admission: the actor class plus the acting principal. A
        // session bearer is labelled SessionBearer — NOT Member: no
        // seat lookup happened — and a rider RiderScope WITHOUT a
        // grant lookup; those gates run in the handler, in their
        // per-route order.
        let (_, access) = send_admission(&groups, "send", &durable(), &local_hex, |_| None)
            .expect("durable owner admitted");
        assert_eq!(access.level(), AccessLevel::OwnerDurable);
        assert_eq!(access.acting_hex(), local_hex);
        assert_eq!(access.stable_id(), "send");

        let (_, access) = send_admission(&groups, "send", &session(), &local_hex, |_| None)
            .expect("session bearer admitted (no seat asserted)");
        assert_eq!(access.level(), AccessLevel::SessionBearer);
        assert_eq!(access.acting_hex(), local_hex);

        let (_, access) = send_admission(&groups, "send", &rider(), &local_hex, |_| None)
            .expect("rider admitted at RiderScope");
        assert_eq!(access.level(), AccessLevel::RiderScope);
        assert_eq!(access.acting_hex(), "aa".repeat(32));
    }

    /// The secure encrypt/decrypt/reseal entry admission: raw-id lookup
    /// 404 → withdrawn 409 (outranking the restore quarantine) → the
    /// ADR-0038 restore-quarantine 409 → the #877 gate; then the same
    /// actor classification as send.
    #[test]
    fn secure_endpoint_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate runs.
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "missing", &durable(), &local_hex, |_| {
                panic!("the lookup 404 must fire before any gate")
            }),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // A withdrawn shell answers "group is withdrawn" even when the
        // restore quarantine is also set — withdrawn is checked first.
        let mut withdrawn = group_with_local_seat("enc");
        withdrawn.withdrawn = true;
        withdrawn.owner_cert_reverify_required = true;
        groups.insert("enc".to_string(), withdrawn);
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &durable(), &local_hex, |_| {
                panic!("withdrawn must outrank the restore quarantine")
            }),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        // The ADR-0038 restore quarantine fires before the fork gate.
        let mut restored = group_with_local_seat("enc");
        restored.owner_cert_reverify_required = true;
        groups.insert("enc".to_string(), restored);
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &durable(), &local_hex, |_| {
                panic!("the restore quarantine must fire before the fork gate")
            }),
            StatusCode::CONFLICT,
            "owner-certified group requires state re-verification after restore: \
             POST /groups/:id/state/seal",
            None,
        );

        // Clean group: the gate refusal propagates; admission classifies
        // exactly like send.
        groups.insert("enc".to_string(), group_with_local_seat("enc"));
        assert_secure_refusal(
            secure_endpoint_admission(&groups, "enc", &session(), &local_hex, |_| {
                Some(quarantine_membership_403())
            }),
            StatusCode::FORBIDDEN,
            "active local group membership required",
            Some("group_membership_required"),
        );
        let (_, access) = secure_endpoint_admission(&groups, "enc", &rider(), &local_hex, |_| None)
            .expect("rider admitted at RiderScope");
        assert_eq!(access.level(), AccessLevel::RiderScope);
        assert_eq!(access.acting_hex(), "aa".repeat(32));
    }

    /// `POST /groups/secure/open-envelope`: no actor gate at all — an
    /// unknown group fails OPEN to the crypto (the envelope itself
    /// refuses), and only the withdrawn-record conflict (no live keyed
    /// alias) rejects.
    #[test]
    fn open_envelope_admission_reproduces_the_inline_decisions() {
        let mut groups = HashMap::new();
        assert_eq!(
            admit_open_envelope(&groups, "unknown").unwrap(),
            AccessLevel::PublicWrite,
            "unknown group fails open to the crypto"
        );

        let mut withdrawn = fixture_group("oe");
        withdrawn.withdrawn = true;
        groups.insert("oe".to_string(), withdrawn);
        assert_refusal(
            admit_open_envelope(&groups, "oe"),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        // A live same-stable-keyed alias lifts the conflict.
        let mut live = fixture_group("oe");
        live.shared_secret = Some(vec![0x33; 32]);
        groups.insert("oe-live".to_string(), live);
        assert_eq!(
            admit_open_envelope(&groups, "oe").unwrap(),
            AccessLevel::PublicWrite,
            "a live keyed alias keeps the envelope openable"
        );
    }

    // ────────────────── S3 admin/mutation admission ──────────────────

    fn group_with_admin_seat(id: &str) -> x0x::groups::GroupInfo {
        let mut info = fixture_group(id);
        info.add_member(local_agent_hex(), x0x::groups::GroupRole::Admin, None, None);
        info
    }

    /// The admin-family entry admission (invite, member
    /// add/remove/role, ban/unban, PATCH, policy, seal, request
    /// approve/reject): raw-id lookup 404 → the local seat gate → the
    /// withdrawn 409, in that order. The seat gate is the DAEMON's —
    /// `membership_handlers_reject_non_admin_local_caller` pins a
    /// durable-owner bearer faring no better than a session here, so
    /// no actor appears in this core at all.
    #[test]
    fn admin_mutation_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate.
        assert_secure_refusal(
            admit_admin_group_route(&groups, "missing", &local_hex),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // Plain-member seat (or none): today's "admin role required".
        groups.insert("adm".to_string(), group_with_local_seat("adm"));
        assert_secure_refusal(
            admit_admin_group_route(&groups, "adm", &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            None,
        );
        groups.insert("bare".to_string(), fixture_group("bare"));
        assert_secure_refusal(
            admit_admin_group_route(&groups, "bare", &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            None,
        );

        // Withdrawn: the 409 — but only after the seat gate (a
        // withdrawn group with a plain-member caller answers the 403).
        let mut withdrawn_member = group_with_local_seat("wm");
        withdrawn_member.withdrawn = true;
        groups.insert("wm".to_string(), withdrawn_member);
        assert_secure_refusal(
            admit_admin_group_route(&groups, "wm", &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            None,
        );
        let mut withdrawn_admin = group_with_admin_seat("adm");
        withdrawn_admin.withdrawn = true;
        groups.insert("adm".to_string(), withdrawn_admin);
        assert_secure_refusal(
            admit_admin_group_route(&groups, "adm", &local_hex),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        // Admin seat, live group: admitted, yielding the group itself.
        groups.insert("adm".to_string(), group_with_admin_seat("adm"));
        let info = admit_admin_group_route(&groups, "adm", &local_hex).expect("admin admitted");
        assert_eq!(info.mls_group_id, "adm");
    }

    /// The gate pair the role and approve sites hold an `info` for:
    /// seat 403 before withdrawn 409, exactly the inline order.
    #[test]
    fn admin_route_gate_reproduces_the_role_and_approve_pair() {
        let local_hex = local_agent_hex();

        assert_secure_refusal(
            admin_route_gate(&group_with_local_seat("g"), &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            None,
        );
        let mut withdrawn = group_with_local_seat("g");
        withdrawn.withdrawn = true;
        assert_secure_refusal(
            admin_route_gate(&withdrawn, &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            // The seat gate outranks the withdrawn 409 — the case that
            // distinguishes this pair's order.
            None,
        );
        let mut withdrawn_admin = group_with_admin_seat("g");
        withdrawn_admin.withdrawn = true;
        assert_secure_refusal(
            admin_route_gate(&withdrawn_admin, &local_hex),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );
        assert!(admin_route_gate(&group_with_admin_seat("g"), &local_hex).is_ok());
    }

    /// `GET /groups/:id/requests`: lookup 404 → the seat gate — and
    /// NO withdrawn arm. A withdrawn shell's request list stays
    /// readable for its admins today; pin that so a future tightening
    /// is a deliberate change, not a silent one.
    #[test]
    fn join_request_listing_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        assert_secure_refusal(
            admit_join_request_listing(&groups, "missing", &local_hex),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );
        groups.insert("req".to_string(), group_with_local_seat("req"));
        assert_secure_refusal(
            admit_join_request_listing(&groups, "req", &local_hex),
            StatusCode::FORBIDDEN,
            "admin role required",
            None,
        );
        groups.insert("req".to_string(), group_with_admin_seat("req"));
        assert!(
            admit_join_request_listing(&groups, "req", &local_hex).is_ok(),
            "admin seat lists the requests"
        );
        let mut withdrawn = group_with_admin_seat("req");
        withdrawn.withdrawn = true;
        groups.insert("req".to_string(), withdrawn);
        assert!(
            admit_join_request_listing(&groups, "req", &local_hex).is_ok(),
            "NO withdrawn check on the listing — today's shape"
        );
    }

    /// `DELETE /groups/:id` (leave): lookup 404 → withdrawn 409 → the
    /// ACTIVE-seat gate. Any active role qualifies; a banned seat does
    /// not (`caller_role` filters on `is_active`).
    #[test]
    fn self_leave_admission_reproduces_the_inline_decisions() {
        let local_hex = local_agent_hex();
        let mut groups = HashMap::new();

        assert_secure_refusal(
            admit_self_leave(&groups, "missing", &local_hex),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        let mut withdrawn = group_with_local_seat("lv");
        withdrawn.withdrawn = true;
        groups.insert("lv".to_string(), withdrawn);
        assert_secure_refusal(
            admit_self_leave(&groups, "lv", &local_hex),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );

        groups.insert("lv".to_string(), fixture_group("lv"));
        assert_secure_refusal(
            admit_self_leave(&groups, "lv", &local_hex),
            StatusCode::FORBIDDEN,
            "leaving a group requires active membership in it",
            None,
        );

        let mut banned_seat = group_with_local_seat("lv");
        banned_seat.ban_member(&local_agent_hex(), None);
        groups.insert("lv".to_string(), banned_seat);
        assert_secure_refusal(
            admit_self_leave(&groups, "lv", &local_hex),
            StatusCode::FORBIDDEN,
            "leaving a group requires active membership in it",
            None,
        );

        // Any ACTIVE role qualifies — member AND admin alike.
        groups.insert("lv".to_string(), group_with_local_seat("lv"));
        assert!(admit_self_leave(&groups, "lv", &local_hex).is_ok());
        groups.insert("lv".to_string(), group_with_admin_seat("lv"));
        assert!(admit_self_leave(&groups, "lv", &local_hex).is_ok());
    }

    /// #1228's no-actor family (display-name, request create/cancel):
    /// lookup 404 → withdrawn 409, nothing else — no seat, no role,
    /// no actor.
    #[test]
    fn live_group_admission_reproduces_the_inline_decisions() {
        let mut groups = HashMap::new();
        assert_secure_refusal(
            admit_live_group_route(&groups, "missing"),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );
        let mut withdrawn = fixture_group("live");
        withdrawn.withdrawn = true;
        groups.insert("live".to_string(), withdrawn);
        assert_secure_refusal(
            admit_live_group_route(&groups, "live"),
            StatusCode::CONFLICT,
            "group is withdrawn",
            None,
        );
        groups.insert("live".to_string(), fixture_group("live"));
        assert!(admit_live_group_route(&groups, "live").is_ok());
    }

    /// `POST /groups/:id/stores`: the rider grant on the resolved
    /// binding's stable id — owners pass on class (durable or session,
    /// nothing else verified), a rider only with its token's grant.
    #[test]
    fn group_store_admission_reproduces_the_inline_decisions() {
        assert_eq!(
            admit_group_store_route(&durable(), "stable").unwrap(),
            AccessLevel::OwnerDurable
        );
        assert_eq!(
            admit_group_store_route(&session(), "stable").unwrap(),
            AccessLevel::SessionBearer
        );

        let granted = ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 1,
            token_hash: "hash".to_string(),
            groups: vec!["stable".to_string()],
        };
        assert_eq!(
            admit_group_store_route(&granted, "stable").unwrap(),
            AccessLevel::RiderScope,
            "a granted rider passes — the token's explicit grant is the check"
        );
        assert_refusal(
            admit_group_store_route(&rider(), "stable"),
            StatusCode::FORBIDDEN,
            "rider token is not granted this group",
            None,
        );
        // The grant is exact, not prefix-wise: `stab` does not lift
        // `stable`.
        let near_miss = ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 2,
            token_hash: "hash".to_string(),
            groups: vec!["stab".to_string()],
        };
        assert_refusal(
            admit_group_store_route(&near_miss, "stable"),
            StatusCode::FORBIDDEN,
            "rider token is not granted this group",
            None,
        );
    }

    /// The legacy-import trio's owner-authority gate: owner-class
    /// bearers pass (durable or session), every rider is refused —
    /// GRANT OR NOT, because the grant check the inline code ran after
    /// the owner match was unreachable for riders and always-true for
    /// owners (the stores rider test pins the granted-rider 403
    /// end-to-end).
    #[test]
    fn legacy_import_admission_reproduces_the_inline_decisions() {
        assert_eq!(
            admit_legacy_import_route(&durable()).unwrap(),
            AccessLevel::OwnerDurable
        );
        assert_eq!(
            admit_legacy_import_route(&session()).unwrap(),
            AccessLevel::SessionBearer
        );

        assert_refusal(
            admit_legacy_import_route(&rider()),
            StatusCode::FORBIDDEN,
            "legacy source export requires the local owner authority",
            None,
        );
        let granted = ActorContext::Rider {
            sub_agent_id: "aa".repeat(32),
            token_id: 3,
            token_hash: "hash".to_string(),
            groups: vec!["stable".to_string()],
        };
        // The grant cannot lift the owner-class requirement.
        assert_refusal(
            admit_legacy_import_route(&granted),
            StatusCode::FORBIDDEN,
            "legacy source export requires the local owner authority",
            None,
        );
    }

    // ────────────────── S5 delegate admission ──────────────────

    /// `POST /groups/:id/delegate` entry admission: raw-id lookup 404 →
    /// withdrawn **404** (the delegations-family disposition — NOT the
    /// mutation family's 409: a withdrawn shell mints no authority) →
    /// the actor-blind ADR-0066 §3b row-15 quarantine gate (the #446
    /// durable gate the handler runs first means the for-actor seat
    /// shape cannot fire here); admission hands the borrowed group
    /// back for the handler's data gates. Order pinned with stubs,
    /// bodies are the inline handler's exact ones.
    #[test]
    fn delegate_admission_reproduces_the_inline_decisions() {
        let mut groups = HashMap::new();

        // Unknown group: the raw-id lookup 404s before any gate runs.
        assert_secure_refusal(
            delegate_admission(&groups, "missing", |_| {
                panic!("the lookup 404 must fire before the quarantine gate")
            }),
            StatusCode::NOT_FOUND,
            "group not found",
            None,
        );

        // Withdrawn shell: the 404 fires before the gate.
        let mut withdrawn = group_with_local_seat("del");
        withdrawn.withdrawn = true;
        groups.insert("del".to_string(), withdrawn);
        assert_secure_refusal(
            delegate_admission(&groups, "del", |_| {
                panic!("the withdrawn 404 must fire before the quarantine gate")
            }),
            StatusCode::NOT_FOUND,
            "group is withdrawn",
            None,
        );

        groups.insert("del".to_string(), group_with_local_seat("del"));

        // A gate refusal propagates verbatim — the row-15 409 shape.
        assert_secure_refusal(
            delegate_admission(&groups, "del", |_| Some(quarantine_marker_409())),
            StatusCode::CONFLICT,
            "fork quarantine active",
            Some("fork_quarantined"),
        );

        // Admission returns the borrowed group for the handler's data
        // gates (SignedPublic 400, ban 403, write policy, to_agent).
        let info = delegate_admission(&groups, "del", |_| None).expect("live group admitted");
        assert_eq!(info.stable_group_id(), "del");
    }
}
