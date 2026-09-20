//! ADR-0066 §1 coverage-map EXHAUSTIVENESS fixture (slice 2).
//!
//! WHY this file exists at all: the §1 coverage map calls itself
//! *normative*, and row 25 (the WebSocket plane) was missed by the first
//! draft of that map and found only in cross-model review. A
//! hand-maintained enumeration degrades — silently, and in the direction of
//! leaving a path ungated. The ADR's Validation section therefore requires
//! a fixture rather than a reading: "the only durable guarantee that a
//! route added later cannot silently join the ungated set".
//!
//! Two halves, and the second is the load-bearing one:
//!
//! 1. **The map itself** — the 26 normative rows, their dispositions and
//!    the ADR's own counts, encoded so that editing the map without
//!    editing the test (or vice versa) fails. Each row also names its
//!    source anchor, which is checked to exist, and a `Gated` row's file is
//!    checked to actually consult the marker.
//! 2. **The registry surface** — every endpoint in the shared registry
//!    (`crate::api::ENDPOINTS`) that touches a surface §1 enumerated must
//!    carry an explicit classification. A route added later is in NEITHER
//!    the coverage map NOR the classification table, so the test fails
//!    until somebody decides what the marker should do to it. That is the
//!    whole point: the failure is the design review being demanded.
//!
//! Inert by construction: no `AppState`, no `Agent`, no sockets. A fixture
//! that guards an enumeration must be one that always runs.

use crate::api::{EndpointDef, Method, RequestSpec, ENDPOINTS};

/// The disposition classes of ADR-0066 §1. One class per row; no row is
/// counted twice (the ADR's own rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// Already consults the marker on the path that performs the act
    /// (rows 1–12) — "Keep" in the ADR table.
    Gated,
    /// 409 `fork_quarantined` while quarantined (§3).
    Refuse,
    /// Mutations refuse, reads annotate (row 20).
    Split,
    /// Serves, but carries `fork_quarantined: true` — never refused,
    /// because containment must not blind the operator.
    Annotate,
    /// A mechanism that does not exist yet (row 22, the §4 epoch token).
    Introduce,
    /// Enumerated for completeness, deliberately not gated (row 23).
    OutOfScope,
    /// Deliberately ungated so the anchored clearing commit can arrive
    /// (row 24). Gating this would make some quarantines unclearable.
    KeepUngated,
}

/// One row of the §1 table.
struct CoverageRow {
    /// The ADR's own row number — the identifier reviewers cite.
    row: u8,
    /// What the path is, in the ADR's words.
    path: &'static str,
    /// Source file the ADR anchors the row to, relative to the crate root.
    anchor: &'static str,
    disposition: Disposition,
    /// The implementation slice that owns this row's behaviour change,
    /// or `None` for a row that needs none (already gated, deliberately
    /// ungated, or out of scope).
    closed_by_slice: Option<u8>,
    /// Is that change IN THE TREE?
    ///
    /// WHY this is a separate field from `closed_by_slice` rather than
    /// clearing the slice number on landing: the slice that owns a row is
    /// a fact about the ADR and stays true forever, while "has it landed"
    /// is a fact about the tree and changes once. Keeping both means a
    /// reviewer of a later slice can still see which slice was supposed
    /// to close a row that regressed, and the OPEN_ROWS equality below
    /// turns "somebody shipped a row without saying so" — or reverted one
    /// — into a failing test rather than a quiet drift.
    closed: bool,
    /// ADR-0067: does the §1 Decision column for this row ask for the §4
    /// re-check *before the effect*, on top of the entry gate?
    ///
    /// WHY this is a separate field from `closed`. Rows 1, 2, 4 and 6 read
    /// "Keep; add §4 re-check" — they are `Gated` at entry and therefore
    /// already `closed: true`, so the `closed`/`OPEN_ROWS` machinery is
    /// structurally blind to whether the re-check ever landed. Slice 7 landed
    /// the mechanism (row 22) and the KV-plane re-check, but David deferred
    /// those four outbound paths to a later slice: they perform no roster
    /// mutation and take no persistence lock, so "inside the same critical
    /// section as the mutation" does not define a site for them and ADR-0066
    /// defines no critical section for an outbound publish (ADR-0067,
    /// "Deferral"). **Slice 9 landed all four**, at the site those rows do
    /// have — the last suspension-free point before the irreversible effect.
    ///
    /// Without this field that deferral would ship invisible — the fixture
    /// would pass either way. `PENDING_RECHECK` below turns it into an
    /// asserted, exact fact instead, so `OPEN_ROWS` can be empty without the
    /// map quietly claiming more coverage than the tree has.
    recheck_before_effect: RecheckState,
}

/// ADR-0067: the state of a row's §4 "re-check before the effect"
/// obligation, as distinct from its entry gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecheckState {
    /// The §1 Decision column asks for no §4 re-check on this row.
    NotRequired,
    /// Asked for, and the re-check is in the tree.
    Landed,
    /// Asked for, deferred to a later slice, and held visible by
    /// `PENDING_RECHECK`.
    Pending,
}

/// The §1 table, transcribed. Deliberately verbatim: a divergence between
/// this array and the ADR is a defect in one of the two, and the
/// assertions below are what surface it.
const COVERAGE_MAP: &[CoverageRow] = &[
    CoverageRow {
        row: 1,
        path: "POST /groups/:id/send — signed-public outbound send",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 2,
        path: "TreeKEM group encrypt",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 3,
        path: "TreeKEM group decrypt",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 4,
        path: "POST /groups/:id/secure/encrypt (GSS)",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 5,
        path: "POST /groups/:id/secure/decrypt (GSS)",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 6,
        path: "POST /groups/:id/secure/reseal (GSS)",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 7,
        path: "TreeKEM group-store resolution",
        anchor: "src/server/routes/stores.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 8,
        path: "TreeKEM group-store live info re-read",
        anchor: "src/server/routes/stores.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 9,
        path: "KV group-writer predicate",
        anchor: "src/server/routes/stores.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 10,
        path: "Signed-public KV authorization snapshot (bind-time only)",
        anchor: "src/groups/kv_context.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 11,
        path: "TreeKEM KV authorization context construct",
        anchor: "src/groups/kv_context.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 12,
        path: "TreeKEM KV authorization context refresh",
        anchor: "src/groups/kv_context.rs",
        disposition: Disposition::Gated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 13,
        path: "History list / message / search / scopes / stats",
        anchor: "src/server/routes/history.rs",
        disposition: Disposition::Annotate,
        closed_by_slice: Some(4),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 14,
        path: "History purge",
        anchor: "src/server/routes/history.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(4),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 15,
        path: "POST /groups/:id/delegate — grant delegation",
        anchor: "src/server/delegations.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(3),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 16,
        path: "GET /groups/:id/delegations — list",
        anchor: "src/server/delegations.rs",
        disposition: Disposition::Annotate,
        closed_by_slice: Some(3),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 17,
        path: "Delegation authorization predicate",
        anchor: "src/server/delegations.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(3),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 18,
        path: "Delegated send-as authorization",
        anchor: "src/server/delegations.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(3),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 19,
        path: "Committed-delegation registry rebuild / index",
        anchor: "src/server/delegations.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(3),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 20,
        path: "Group task-list read/mutate",
        anchor: "src/server/routes/tasks.rs",
        disposition: Disposition::Split,
        closed_by_slice: Some(5),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 21,
        path: "Signed-public bootstrap outbox publish",
        anchor: "src/server/routes/public_group_bootstrap_outbox.rs",
        disposition: Disposition::Refuse,
        closed_by_slice: Some(5),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 22,
        path: "Ratchet / persist lifecycle epoch re-check",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::Introduce,
        closed_by_slice: Some(7),
        recheck_before_effect: RecheckState::Landed,
        closed: true,
    },
    CoverageRow {
        row: 23,
        path: "File transfer (ADR-0055 DM plane, not group-state bound)",
        anchor: "src/server/routes/files.rs",
        disposition: Disposition::OutOfScope,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 24,
        path: "Inbound metadata / state-commit apply",
        anchor: "src/server/routes/named_groups.rs",
        disposition: Disposition::KeepUngated,
        closed_by_slice: None,
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 25,
        path: "WebSocket fan-out — Mention events and ADR-0023 backfill",
        anchor: "src/server/ws.rs",
        disposition: Disposition::Annotate,
        closed_by_slice: Some(6),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
    CoverageRow {
        row: 26,
        path: "History diagnostics",
        anchor: "src/server/routes/history.rs",
        disposition: Disposition::Annotate,
        closed_by_slice: Some(4),
        recheck_before_effect: RecheckState::NotRequired,
        closed: true,
    },
];

/// How one registry endpoint relates to the §1 map.
///
/// Every class here is a DECISION somebody made and can be argued with in
/// review — which is exactly what an unclassified route denies. The point
/// of the enum is that "nobody looked at it yet" is not one of the options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteClass {
    /// Covered by these §1 rows: the disposition (gate, refusal or
    /// annotation) lives there, not here.
    Covered(&'static [u8]),
    /// Group CONTROL plane: membership, lifecycle, policy, invites,
    /// discovery, and the quarantine clear itself. §1 enumerates the DATA
    /// plane; ADR-0064 §3 and ADR-0066 deliberately leave the control
    /// plane ungated — a quarantined group must still be administrable,
    /// and gating the clear route would make containment permanent.
    ControlPlane,
    /// Observability: reports the marker rather than acting under it.
    /// Refusing here would hide the incident from the operator, which is
    /// the failure mode ADR-0066's Drivers single out.
    Observability,
    /// Reached without consulting group authority state at all, so the
    /// marker has nothing to gate.
    NotStateBound,
    /// A group-scoped path the §1 map does NOT name, recorded as a gap in
    /// the map rather than quietly folded into a neighbouring row.
    ///
    /// **Currently unused, deliberately kept.** The one entry slice 2
    /// found (`GET /groups/:id/messages`) was an annotate-class READ on
    /// the history store, so slice 4 annotated it and moved it to row 13.
    /// The variant stays because it is the classification the NEXT
    /// unmapped route gets while review decides: a read joins the annotate
    /// class (§3a/§3d); anything carrying authority needs a superseding
    /// ADR before it may be left ungated. The set is asserted EXACTLY, so
    /// a new unmapped route fails this fixture instead of joining a
    /// growing list.
    #[allow(dead_code)]
    MapGap,
}

/// The classification table for the registry's data-plane candidate
/// surface. Keyed `"METHOD /path"` exactly as the registry spells it.
const ROUTE_CLASSIFICATION: &[(&str, RouteClass)] = &[
    // ── §1 rows 1–6: the shipped owner-axis gates ───────────────────────
    ("POST /groups/:id/send", RouteClass::Covered(&[1])),
    ("POST /mls/groups/:id/encrypt", RouteClass::Covered(&[2])),
    ("POST /mls/groups/:id/decrypt", RouteClass::Covered(&[3])),
    ("POST /groups/:id/secure/encrypt", RouteClass::Covered(&[4])),
    ("POST /groups/:id/secure/decrypt", RouteClass::Covered(&[5])),
    ("POST /groups/:id/secure/reseal", RouteClass::Covered(&[6])),
    // ── §1 rows 7–12: the KV / store surface ────────────────────────────
    ("POST /groups/:id/stores", RouteClass::Covered(&[7, 9])),
    (
        "GET /groups/:id/stores/:app/legacy-imports",
        RouteClass::Covered(&[7]),
    ),
    (
        "POST /groups/:id/stores/:app/legacy-imports/:source_id",
        RouteClass::Covered(&[7]),
    ),
    (
        "GET /groups/:id/stores/:app/legacy-imports/:source_id",
        RouteClass::Covered(&[7]),
    ),
    ("GET /stores", RouteClass::Covered(&[8])),
    ("POST /stores", RouteClass::Covered(&[7, 9])),
    ("POST /stores/:id/join", RouteClass::Covered(&[7, 10, 11])),
    ("GET /stores/:id/keys", RouteClass::Covered(&[8, 10, 11])),
    ("PUT /stores/:id/:key", RouteClass::Covered(&[8, 9, 10])),
    ("GET /stores/:id/:key", RouteClass::Covered(&[8, 10, 11])),
    ("DELETE /stores/:id/:key", RouteClass::Covered(&[8, 9, 10])),
    // ── §1 rows 13, 14, 26: history ─────────────────────────────────────
    ("GET /history", RouteClass::Covered(&[13])),
    ("GET /history/message/:msg_id", RouteClass::Covered(&[13])),
    ("GET /history/scopes", RouteClass::Covered(&[13])),
    ("GET /history/search", RouteClass::Covered(&[13])),
    ("GET /history/stats", RouteClass::Covered(&[13])),
    ("DELETE /history", RouteClass::Covered(&[14])),
    ("GET /diagnostics/history", RouteClass::Covered(&[26])),
    // The §1 map gap slice 2 recorded, ABSORBED by slice 4: this is the
    // group plane's own ADR-0023 read (it queries the same history store
    // for `group:<stable_id>` rows), so it is row 13's surface even though
    // its handler lives in `named_groups.rs`. It carries the identical
    // annotation, reusing `history::annotate` rather than a second
    // dialect. Envelope-level only — its payload is `GroupPublicMessage`
    // objects, not store rows, so there is no per-row `seen_at_ms` for the
    // R3 ingest tag.
    ("GET /groups/:id/messages", RouteClass::Covered(&[13])),
    // ── §1 rows 15, 16: delegations ─────────────────────────────────────
    ("POST /groups/:id/delegate", RouteClass::Covered(&[15])),
    ("GET /groups/:id/delegations", RouteClass::Covered(&[16])),
    // ── §1 row 20: tasks ────────────────────────────────────────────────
    ("GET /task-lists", RouteClass::Covered(&[20])),
    ("POST /task-lists", RouteClass::Covered(&[20])),
    ("GET /task-lists/:id/tasks", RouteClass::Covered(&[20])),
    ("POST /task-lists/:id/tasks", RouteClass::Covered(&[20])),
    (
        "PATCH /task-lists/:id/tasks/:tid",
        RouteClass::Covered(&[20]),
    ),
    // ── §1 row 23: the DM-plane file transfer, enumerated not gated ─────
    ("POST /files/send", RouteClass::Covered(&[23])),
    ("GET /files/transfers", RouteClass::Covered(&[23])),
    ("GET /files/transfers/:id", RouteClass::Covered(&[23])),
    ("POST /files/accept/:id", RouteClass::Covered(&[23])),
    ("POST /files/reject/:id", RouteClass::Covered(&[23])),
    // ── Group control plane ─────────────────────────────────────────────
    ("POST /groups", RouteClass::ControlPlane),
    ("GET /groups", RouteClass::ControlPlane),
    ("GET /groups/:id", RouteClass::ControlPlane),
    ("PATCH /groups/:id", RouteClass::ControlPlane),
    ("DELETE /groups/:id", RouteClass::ControlPlane),
    ("GET /groups/:id/members", RouteClass::ControlPlane),
    ("POST /groups/:id/members", RouteClass::ControlPlane),
    (
        "DELETE /groups/:id/members/:agent_id",
        RouteClass::ControlPlane,
    ),
    (
        "PATCH /groups/:id/members/:agent_id/role",
        RouteClass::ControlPlane,
    ),
    ("PATCH /groups/:id/policy", RouteClass::ControlPlane),
    ("POST /groups/:id/ban/:agent_id", RouteClass::ControlPlane),
    ("DELETE /groups/:id/ban/:agent_id", RouteClass::ControlPlane),
    ("POST /groups/:id/invite", RouteClass::ControlPlane),
    ("POST /groups/join", RouteClass::ControlPlane),
    ("GET /groups/:id/join-status", RouteClass::ControlPlane),
    ("PUT /groups/:id/display-name", RouteClass::ControlPlane),
    ("GET /groups/:id/state", RouteClass::ControlPlane),
    ("GET /groups/:id/state/commits", RouteClass::ControlPlane),
    ("POST /groups/:id/state/seal", RouteClass::ControlPlane),
    ("POST /groups/:id/state/withdraw", RouteClass::ControlPlane),
    ("GET /groups/:id/requests", RouteClass::ControlPlane),
    ("POST /groups/:id/requests", RouteClass::ControlPlane),
    (
        "POST /groups/:id/requests/:request_id/approve",
        RouteClass::ControlPlane,
    ),
    (
        "POST /groups/:id/requests/:request_id/reject",
        RouteClass::ControlPlane,
    ),
    (
        "DELETE /groups/:id/requests/:request_id",
        RouteClass::ControlPlane,
    ),
    ("GET /groups/discover", RouteClass::ControlPlane),
    ("GET /groups/discover/nearby", RouteClass::ControlPlane),
    (
        "GET /groups/discover/subscriptions",
        RouteClass::ControlPlane,
    ),
    ("POST /groups/discover/subscribe", RouteClass::ControlPlane),
    (
        "DELETE /groups/discover/subscribe/:kind/:shard",
        RouteClass::ControlPlane,
    ),
    ("GET /groups/cards/:id", RouteClass::ControlPlane),
    ("POST /groups/cards/import", RouteClass::ControlPlane),
    // The remedy the §5 message names: gating it would make every
    // `no_anchor` quarantine permanent.
    (
        "POST /groups/:id/quarantine/clear",
        RouteClass::ControlPlane,
    ),
    // The MLS plane's own membership surface.
    ("POST /mls/groups", RouteClass::ControlPlane),
    ("GET /mls/groups", RouteClass::ControlPlane),
    ("GET /mls/groups/:id", RouteClass::ControlPlane),
    ("POST /mls/groups/:id/members", RouteClass::ControlPlane),
    (
        "DELETE /mls/groups/:id/members/:agent_id",
        RouteClass::ControlPlane,
    ),
    ("POST /mls/groups/:id/welcome", RouteClass::ControlPlane),
    // ── Observability ───────────────────────────────────────────────────
    ("GET /diagnostics/groups", RouteClass::Observability),
    // ── Not bound to group authority state ──────────────────────────────
    // The adversarial confidentiality-proof endpoint: it opens an envelope
    // with THIS daemon's own KEM key and reads no group authority state
    // beyond a withdrawn check.
    (
        "POST /groups/secure/open-envelope",
        RouteClass::NotStateBound,
    ),
    // ── Gaps in the §1 map (read paths only — see RouteClass::MapGap) ───
    // Empty: slice 4 absorbed the one gap slice 2 found
    // (`GET /groups/:id/messages`, reclassified as row 13 above).
];

/// The exact, complete set of §1 map gaps. Asserted as an equality, not a
/// subset: a newly discovered gap must be argued for, not appended.
///
/// Empty since slice 4: the single gap slice 2 recorded
/// (`GET /groups/:id/messages`) was an annotate-class read on the history
/// store, so slice 4 annotated it and reclassified it as row 13 rather
/// than leaving the map permanently one route short.
const KNOWN_MAP_GAPS: &[&str] = &[];

/// The surfaces ADR-0066 §1 censused. A registry route under any of these
/// prefixes is part of the data-plane candidate surface and must be
/// classified; anything else (contacts, presence, exec, …) is outside the
/// ADR's subject matter.
const CANDIDATE_PREFIXES: &[&str] = &[
    "/groups",
    "/mls/groups",
    "/stores",
    "/task-lists",
    "/history",
    "/files",
    "/diagnostics/groups",
    "/diagnostics/history",
];

fn is_candidate(path: &str) -> bool {
    CANDIDATE_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

fn registry_key(endpoint: &EndpointDef) -> String {
    format!("{} {}", endpoint.method, endpoint.path)
}

/// The classifier, taken as a function of one endpoint so that a
/// SYNTHETIC endpoint can be pushed through the exact same code path the
/// real registry takes — that is what makes the negative control below a
/// control rather than a comment.
fn classify(endpoint: &EndpointDef) -> Option<RouteClass> {
    let key = registry_key(endpoint);
    ROUTE_CLASSIFICATION
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, class)| *class)
}

fn read_anchor(anchor: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(anchor);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("§1 anchor {anchor} must exist: {error}"))
}

/// WHY: the §1 map is normative, so its own shape has to be machine-held.
/// A row that loses its disposition, a duplicated row number, a count that
/// no longer matches the ADR's stated totals, or an anchor file that was
/// renamed away are all ways the enumeration rots without anyone noticing.
#[test]
fn adr0066_coverage_map_matches_the_adr_counts_and_anchors() {
    assert_eq!(
        COVERAGE_MAP.len(),
        26,
        "ADR-0066 §1 enumerates 26 data-plane paths"
    );
    for (index, row) in COVERAGE_MAP.iter().enumerate() {
        assert_eq!(
            row.row as usize,
            index + 1,
            "rows are transcribed in the ADR's order so a reviewer can diff them side by side"
        );
        assert!(!row.path.is_empty(), "row {} has no description", row.row);
    }

    let count = |disposition: Disposition| {
        COVERAGE_MAP
            .iter()
            .filter(|row| row.disposition == disposition)
            .count()
    };
    // The ADR's own totals: 12 gated today, 1 deliberately ungated, and
    // the 13 ungated rows split 6 refuse / 1 split / 4 annotate /
    // 1 introduce / 1 out-of-scope.
    assert_eq!(count(Disposition::Gated), 12, "ADR-0066 §1 Counts");
    assert_eq!(count(Disposition::KeepUngated), 1, "row 24");
    assert_eq!(count(Disposition::Refuse), 6, "§1 disposition table");
    assert_eq!(count(Disposition::Split), 1, "§1 disposition table");
    assert_eq!(count(Disposition::Annotate), 4, "§1 disposition table");
    assert_eq!(count(Disposition::Introduce), 1, "§1 disposition table");
    assert_eq!(count(Disposition::OutOfScope), 1, "§1 disposition table");

    // A row that claims to be gated today must actually consult the
    // marker in the file the ADR anchors it to. This is the clause that
    // fails if a gate is deleted or a module is split out from under the
    // map.
    for row in COVERAGE_MAP
        .iter()
        .filter(|row| row.disposition == Disposition::Gated)
    {
        let source = read_anchor(row.anchor);
        assert!(
            source.contains("is_fork_quarantined") || source.contains("reject_fork_quarantined"),
            "§1 row {} claims {} is gated, but {} consults no marker",
            row.row,
            row.path,
            row.anchor
        );
    }
    // Every other row's anchor must at least still exist: the map's
    // `file:line` promise is worthless if the file is gone.
    for row in COVERAGE_MAP.iter() {
        let _ = read_anchor(row.anchor);
    }
    // Every row still open names the slice that closes it, so "not done
    // yet" is never indistinguishable from "forgotten".
    for row in COVERAGE_MAP.iter() {
        match row.disposition {
            Disposition::Gated | Disposition::KeepUngated | Disposition::OutOfScope => {
                assert!(
                    row.closed_by_slice.is_none(),
                    "row {} needs no further slice",
                    row.row
                );
                assert!(
                    row.closed,
                    "row {} needs no behaviour change, so it is closed by definition",
                    row.row
                );
            }
            _ => assert!(
                row.closed_by_slice.is_some(),
                "row {} changes behaviour, so it must name the slice that closes it",
                row.row
            ),
        }
    }

    // The EXACT open set. Asserted as an equality rather than a count so
    // that closing a row and reopening another cannot cancel out, and so
    // that a slice which lands its code without updating this map fails
    // here instead of leaving the map quietly describing a tree that no
    // longer exists. Slice 3 closed 15–19, slice 4 closed 13, 14 and 26,
    // slice 5 closed 20 and 21, slice 6 closed 25 and slice 7 closed 22 —
    // so EVERY §1 row has now landed and the open set is EMPTY. That was a
    // milestone, not a licence: until slice 9 an empty open set still did not
    // mean ADR-0066 §4 was discharged, which is what PENDING_RECHECK below
    // exists to say. Slice 9 emptied that ledger too, and both assertions
    // stay so neither fact can regress unnoticed.
    let open: Vec<u8> = COVERAGE_MAP
        .iter()
        .filter(|row| !row.closed)
        .map(|row| row.row)
        .collect();
    assert_eq!(
        open, OPEN_ROWS,
        "the §1 rows still awaiting their slice — update this list in the slice that closes one"
    );

    // ADR-0066 §1 is now fully landed, asserted as its OWN clause rather than
    // left implicit in the equality above. Spelling it out means a future
    // change that reopens a row fails with a message saying what was lost, and
    // it records the milestone slice 7 completes.
    assert!(
        open.is_empty(),
        "every §1 row's behaviour is supposed to be in the tree after slice 7 — these are \
         open again: {open:?}. Coverage must not shrink; if a row genuinely needs reopening, \
         say so in OPEN_ROWS and explain why."
    );

    // ADR-0067: the §4 "re-check before the effect" ledger, kept SEPARATE
    // from `closed` because rows 1/2/4/6 are `Gated` at entry and so are
    // already closed — the `OPEN_ROWS` machinery is structurally incapable of
    // noticing whether their re-check landed.
    //
    // Asserted as an exact equality, in row order, for the same reason
    // `OPEN_ROWS` is: a later slice that lands one of these must move it out
    // of this list, and a slice that quietly drops a landed re-check fails
    // here. Slice 9 landed rows 1, 2, 4 and 6, so this set is now EMPTY and
    // ADR-0066 §4 is discharged across the §1 surface.
    let pending: Vec<u8> = COVERAGE_MAP
        .iter()
        .filter(|row| row.recheck_before_effect == RecheckState::Pending)
        .map(|row| row.row)
        .collect();
    assert_eq!(
        pending, PENDING_RECHECK,
        "the §1 rows whose Decision column asks for a §4 re-check that is NOT in the tree \
         yet. Slice 9 emptied this list by landing rows 1, 2, 4 and 6 (outbound send / \
         TreeKEM encrypt / GSS encrypt / GSS reseal). A row appearing here again means a \
         re-check was dropped or a new row needs one; update the list in the slice that \
         lands it, and do not delete the assertion."
    );

    // §4 is discharged, asserted as its OWN clause rather than left implicit
    // in the equality above — so a change that re-defers a row fails with a
    // message saying what was lost, exactly as `OPEN_ROWS` does for §1.
    assert!(
        pending.is_empty(),
        "ADR-0066 §4 is supposed to be discharged across the §1 surface after slice 9 — \
         these rows are awaiting a re-check again: {pending:?}"
    );

    // A row cannot claim a LANDED re-check while still being open: "the
    // re-check is in the tree" presupposes the row's behaviour is.
    for row in COVERAGE_MAP.iter() {
        if row.recheck_before_effect == RecheckState::Landed {
            assert!(
                row.closed,
                "§1 row {} claims a landed §4 re-check but is still open",
                row.row
            );
        }
    }

    // The clause that gives an empty `PENDING_RECHECK` teeth: rows 1, 2, 4 and
    // 6 must each have a before-effect re-check CALL in their anchor file.
    //
    // Counted rather than merely searched for, because all four share one
    // anchor with the helper's own definition — `source.contains(symbol)`
    // would be satisfied by that definition alone and would not notice a
    // deleted call, leaving the fixture green while §4 was quietly undone.
    // One call per row: `send_group_public_message`, `treekem_group_encrypt`,
    // `secure_group_encrypt`, `secure_group_reseal`.
    //
    // The other `Landed` rows are deliberately NOT checked this way. Row 22's
    // mechanism is `persist_named_groups_mutation_epoch_checked`, asserted by
    // the `adr0066_epoch_token` fixtures at the site itself, and rows 10/12's
    // is a REFRESH TRIGGER in `kv_context.rs` — a marker making a cached
    // authorization context re-derive — which has no single call symbol to
    // count and is already covered by their `Gated` anchor clause above.
    let send_path_rows: Vec<u8> = COVERAGE_MAP
        .iter()
        .filter(|row| {
            row.recheck_before_effect == RecheckState::Landed && matches!(row.row, 1 | 2 | 4 | 6)
        })
        .map(|row| row.row)
        .collect();
    assert_eq!(
        send_path_rows,
        vec![1u8, 2, 4, 6],
        "the four send-path rows must all claim a landed re-check; slice 9 landed them and \
         nothing since should have re-deferred one"
    );
    let send_path_source = read_anchor("src/server/routes/named_groups.rs");
    let call_sites = send_path_source
        .lines()
        .filter(|line| {
            line.contains(SEND_PATH_RECHECK_CALL)
                && !line.contains("fn ")
                && !line.trim_start().starts_with("//")
        })
        .count();
    assert_eq!(
        call_sites,
        send_path_rows.len(),
        "ADR-0066 §1 rows {send_path_rows:?} each need exactly one before-effect re-check \
         call in src/server/routes/named_groups.rs, and {call_sites} were found. A missing \
         call means a row's §4 obligation was dropped; an extra one means a site was added \
         without a row, so say which row it serves."
    );

    // A row that claims to be CLOSED and whose disposition is a refusal,
    // a split or an annotation must actually consult the marker in its
    // anchor file. This is the clause that catches a landed gate being
    // deleted or refactored out from under the map — the same guarantee
    // the `Gated` rows above get, extended to every row a slice has
    // shipped. Rows that need no behaviour change (out-of-scope,
    // deliberately ungated) are excluded: for them, consulting the marker
    // would be the defect.
    for row in COVERAGE_MAP.iter().filter(|row| {
        row.closed
            && matches!(
                row.disposition,
                Disposition::Refuse | Disposition::Split | Disposition::Annotate
            )
    }) {
        let source = read_anchor(row.anchor);
        assert!(
            source.contains("fork_quarantine") || source.contains("is_fork_quarantined"),
            "§1 row {} ({}) is marked closed by slice {:?}, but {} consults no marker",
            row.row,
            row.path,
            row.closed_by_slice,
            row.anchor
        );
    }
}

/// The §1 rows whose behaviour change has not landed yet, in row order.
///
/// **EMPTY, and that is the point of this slice.** Slice 5 closed rows 20 and
/// 21 and slice 7 closed row 22, so every one of the 26 normative §1 rows now
/// has its behaviour in the tree. The emptiness is asserted explicitly below
/// rather than merely observed, so a later change that reopens a row — or
/// deletes a landed gate — fails here instead of quietly shrinking coverage.
///
/// Since slice 9 an empty open set is ALSO an empty [`PENDING_RECHECK`], so
/// ADR-0066 §1 and §4 are both discharged across the censused surface. The two
/// ledgers stay separate anyway: they answer different questions, and
/// collapsing them would delete the only machinery that can notice a re-check
/// regressing on a row which is gated at entry and therefore always `closed`.
const OPEN_ROWS: &[u8] = &[];

/// ADR-0067 deferral ledger: the §1 rows whose Decision column asks for the
/// §4 re-check *before the effect* and whose re-check is NOT in the tree yet,
/// in row order.
///
/// **EMPTY as of slice 9, which is the slice that exists to empty it.** Rows
/// 1, 2, 4 and 6 — signed-public outbound send, TreeKEM encrypt, GSS encrypt,
/// GSS reseal — were carried here by slice 7 because all four are `Gated` at
/// entry and therefore already `closed: true`, so nothing in the
/// `closed`/`OPEN_ROWS` machinery could notice that their re-check was
/// missing. They perform no roster mutation and take no persistence lock, so
/// ADR-0066 §4's "inside the same critical section as the mutation" named no
/// site for them and David deferred them to their own slice on 2026-09-20
/// (ADR-0067, "Deferral"). Slice 9 applies §4's *rule* at the site those rows
/// do have — the last suspension-free point before the irreversible effect —
/// through `reject_fork_quarantine_installed_before_effect`.
///
/// Emptiness is not self-proving, so it is defended twice below: by the
/// exact-equality assertion (a future row needing a re-check must be listed
/// here or fail) and by the anchor clause, which requires every `Landed` row's
/// anchor file to actually contain a re-check call — so deleting the re-check
/// fails this fixture instead of silently un-discharging §4.
const PENDING_RECHECK: &[u8] = &[];

/// The before-effect re-check call that rows 1, 2, 4 and 6 must each make.
///
/// Counting these call sites is what keeps an empty [`PENDING_RECHECK`] honest.
/// Without it the ledger would be a comment: a refactor that dropped a re-check
/// would leave the fixture green and §4 quietly undone, which is the exact
/// failure mode slice 7 introduced `recheck_before_effect` to prevent.
const SEND_PATH_RECHECK_CALL: &str = "reject_fork_quarantine_installed_before_effect(";

/// WHY (ADR-0066 Validation, the fixture's whole reason for existing):
/// every route on the censused surface must be explicitly classified. Row
/// 25 proves that a map defended only by reading degrades; this test is
/// the defence that does not.
///
/// The failure mode it prevents is specific and silent: somebody adds a
/// group data-plane route, nobody asks what a quarantined group should do
/// with it, and the route joins the ungated set — which is precisely how
/// ordinary groups came to be 0-of-26 gated in the first place.
#[test]
fn adr0066_every_group_data_plane_route_is_classified() {
    let unclassified: Vec<String> = ENDPOINTS
        .iter()
        .filter(|endpoint| is_candidate(endpoint.path))
        .filter(|endpoint| classify(endpoint).is_none())
        .map(registry_key)
        .collect();
    assert!(
        unclassified.is_empty(),
        "ADR-0066 §1 is normative and these registry routes are on the censused data-plane \
         surface with no classification: {unclassified:?}. Decide what a fork-quarantined \
         group does on each (gate it, annotate it, or record why the marker does not apply) \
         and add it to ROUTE_CLASSIFICATION — do not delete this assertion."
    );

    // Every classification must point at rows that exist, so a typo'd row
    // number cannot launder a route as covered.
    for (key, class) in ROUTE_CLASSIFICATION {
        if let RouteClass::Covered(rows) = class {
            assert!(
                !rows.is_empty(),
                "{key} claims coverage without naming a §1 row"
            );
            for row in *rows {
                assert!(
                    COVERAGE_MAP.iter().any(|entry| entry.row == *row),
                    "{key} cites §1 row {row}, which does not exist"
                );
            }
        }
    }

    // The classification table must not accumulate entries for routes the
    // registry no longer serves: a stale entry would mask a deletion and,
    // worse, could silently "classify" a future route that reuses the
    // path.
    let stale: Vec<&str> = ROUTE_CLASSIFICATION
        .iter()
        .map(|(key, _)| *key)
        .filter(|key| {
            !ENDPOINTS
                .iter()
                .any(|endpoint| registry_key(endpoint) == *key)
        })
        .collect();
    assert!(
        stale.is_empty(),
        "ROUTE_CLASSIFICATION entries with no registry route: {stale:?}"
    );

    // Gaps in the ADR's own map are held to an EXACT set. A new one is a
    // finding for review, not a line to append quietly.
    let gaps: Vec<&str> = ROUTE_CLASSIFICATION
        .iter()
        .filter(|(_, class)| *class == RouteClass::MapGap)
        .map(|(key, _)| *key)
        .collect();
    assert_eq!(
        gaps, KNOWN_MAP_GAPS,
        "a group-scoped route not named by the §1 map is a finding: if it is a READ path it \
         joins the annotate class (slices 4/6); if it carries authority it needs a superseding \
         ADR before it can be left ungated"
    );
}

/// WHY: a guard nobody has seen fail is a guard nobody can trust. This is
/// the NEGATIVE CONTROL for the fixture above — a synthetic new group
/// data-plane route, pushed through the same `is_candidate` + `classify`
/// pair the real test uses, must come back unclassified.
///
/// Without this control, `adr0066_every_group_data_plane_route_is_classified`
/// could pass for the wrong reason: a classifier that matched everything,
/// a prefix list that matched nothing, or a table lookup that silently
/// defaulted. Each of those would make the fixture decorative while
/// reading exactly as green.
#[test]
fn adr0066_exhaustiveness_fixture_fails_on_an_unclassified_route() {
    let newcomer = EndpointDef {
        method: Method::Post,
        path: "/groups/:id/brand-new-data-plane-verb",
        cli_name: "group brand-new",
        description: "a route a future slice adds without classifying it",
        category: "named-groups",
        request: RequestSpec::None,
    };
    assert!(
        is_candidate(newcomer.path),
        "a new /groups route is on the censused surface — if this fails, the prefix list is \
         too narrow and the real fixture is blind"
    );
    assert!(
        classify(&newcomer).is_none(),
        "an unclassified route must NOT be treated as covered — this is the assertion that \
         proves the real fixture can fail"
    );

    // And the positive half of the control: a route that IS classified
    // resolves, so the lookup is not simply always-None.
    let classified = ENDPOINTS
        .iter()
        .find(|endpoint| registry_key(endpoint) == "POST /groups/:id/send")
        .expect("the signed-public send route is in the registry");
    assert_eq!(
        classify(classified),
        Some(RouteClass::Covered(&[1])),
        "§1 row 1 is the shipped gate on the outbound send path"
    );

    // A route outside the censused surface is deliberately NOT demanded to
    // carry a classification: the fixture guards the group data plane, not
    // the whole API.
    assert!(
        !is_candidate("/contacts/:agent_id"),
        "contacts are not group state"
    );
}
