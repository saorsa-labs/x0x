//! ADR 0109 §10 H-S3-rm3 (older receiver after the seal, D156, #1572).
//! The harness and phase 1 are those of H-S3-rm1 ([`super::harness`]).
//!
//! Setup. O, A, J and M (M1) run the candidate on real sockets, with
//! `[groups] mandate_grace_days = 1`. A verifies O's and M's current
//! adverts. Stop O. A removes J (r+3), and M reaches r+3, then stops.
//! In (i) only, test configuration then records A as mandate-capable on M,
//! first seen two days ago, so M is past grace; in (ii) M never observed
//! A. A calls the re-seat while M is offline, and J reaches r+4. Each
//! variant is its own test with its own phase 1.
//!
//! Row. The released v0.46.1 starts on M's dirs with A as its peer. M has
//! no open path to r+4: a `MemberAdded` has no resend schedule. So, once
//! A has M's advert, A seals a rename, and M must fetch the chain from A
//! (r+4 first). This is how the row releases the chain to M on real
//! sockets. A v0.46.1 that starts minutes later is not given r+4 (seen in
//! a run), so each variant starts it at once. In (i), M then restarts on
//! the candidate, and A seals one more rename.
//!
//! Desired result. (i) v0.46.1 refuses r+4 as `owner_mandate_missing` and
//! keeps r+3; the candidate then applies r+4. (ii) v0.46.1 warn-accepts
//! r+4 (`owner_mandate_absent`): today's exposure for an unmandated add.
//! A failed row check is RED; a missing prerequisite is INFRA.

use super::*;
use std::path::Path;

const SEED: u64 = 0x1356_0153;
const FINAL_RM3: &str = "released_m_refuses_r_plus_4_past_grace_and_warn_accepts_unobserved";
const CAUSE_RM3: &str = "v0.46.1 past grace did not refuse r+4 as owner_mandate_missing at r+3, \
                         the candidate did not then apply r+4, or v0.46.1 with no record of A \
                         did not warn-accept r+4";
const GRACE_DAYS: u64 = 1;
const GRACE_TOML: &str = "[groups]\nmandate_grace_days = 1\n";
/// Two days: past the one-day grace window.
const FIRST_SEEN_AGO_MS: u64 = 2 * 86_400_000;
/// How long the released M has to receive A's chain.
const CHAIN_WAIT: Duration = Duration::from_secs(180);
/// How long the refusing M is watched after its first refusal.
const HOLD: Duration = Duration::from_secs(30);

/// Wait until A's head is past `revision`, or `RESEAT_BOUND` ends.
async fn head_past(a: &Real, group: &str, revision: u64) -> Result<View> {
    let deadline = tokio::time::Instant::now() + RESEAT_BOUND;
    loop {
        let view = a.view(group).await?;
        if view.state_revision > revision || tokio::time::Instant::now() > deadline {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait until `node` holds the commit with `hash` (its head or its commit
/// log), or `RESEAT_BOUND` ends.
async fn applies(node: &Real, group: &str, hash: &str) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + RESEAT_BOUND;
    loop {
        let held = {
            let groups = node.state.named_groups.read().await;
            let (_, info) = crate::server::resolve_group_entry_locked(&groups, group)
                .context("no record of the group")?;
            info.state_hash == hash || info.commit_log.iter().any(|c| c.commit.state_hash == hash)
        };
        if held || tokio::time::Instant::now() > deadline {
            return Ok(held);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A seals a rename (retried for 60 s); returns A's new head.
async fn rename(a: &Real, group: &str, name: &str) -> Result<View> {
    let before = a.view(group).await?.state_revision;
    let path = format!("/groups/{group}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (code, body) = a
            .call(Method::PATCH, &path, Some(json!({"name": name})))
            .await?;
        if code < 300 {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "INFRA: A renames: {code} {body}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    head_past(a, group, before).await
}

/// Wait until `node` holds `head`'s state hash, or `RESEAT_BOUND` ends.
async fn reach(node: &Real, group: &str, head: &View) -> Result<View> {
    let deadline = tokio::time::Instant::now() + RESEAT_BOUND;
    loop {
        let view = node.view(group).await?;
        if view.state_hash == head.state_hash || tokio::time::Instant::now() > deadline {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Test configuration: `m` records `authority` as mandate-capable, first
/// seen `FIRST_SEEN_AGO_MS` ago, through the daemon's own persistence.
async fn record_capable(m: &Real, group: &str, authority: &str) -> Result<()> {
    let key = {
        let groups = m.state.named_groups.read().await;
        let (key, _) = crate::server::resolve_group_entry_locked(&groups, group)
            .context("M has no record of the group")?;
        key.to_string()
    };
    let now_ms = u64::try_from(std::time::UNIX_EPOCH.elapsed()?.as_millis())?;
    let capability = crate::groups::MandateCapabilityState {
        first_seen_ms: now_ms.saturating_sub(FIRST_SEEN_AGO_MS),
        ..Default::default()
    };
    let persisted =
        crate::server::routes::named_groups::persist_named_groups_mutation(&m.state, |groups| {
            groups.get_mut(&key).is_some_and(|info| {
                info.mandate_capability
                    .insert(authority.to_string(), capability);
                true
            })
        })
        .await;
    persisted.context("INFRA: persist M's capability record")?;
    Ok(())
}

/// The released M's state revision and its `group` mandate counters
/// `(missing, absent)`, with the raw diagnostic for the receipt.
async fn released_state(m: &Released, group: &str) -> Result<(u64, u64, u64, Value)> {
    let path = format!("/groups/{group}/state");
    let (_, state) = m.call(Method::GET, &path, None).await?;
    let (_, diag) = m.call(Method::GET, "/diagnostics/groups", None).await?;
    let entry = diag["groups"]
        .as_array()
        .and_then(|groups| {
            groups.iter().find(|g| {
                g["group_id"]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(group))
            })
        })
        .cloned()
        .unwrap_or(Value::Null);
    let count = |key: &str| entry[key].as_u64().unwrap_or(0);
    let revision = state["state_revision"].as_u64().unwrap_or(0);
    let (missing, absent) = (
        count("owner_mandate_missing"),
        count("owner_mandate_absent"),
    );
    let summary = json!({
        "state": state,
        "owner_mandate_missing": missing,
        "owner_mandate_absent": absent,
        "mandate_capability": entry["mandate_capability"],
        "nonzero": entry.as_object().map(|map| {
            map.iter()
                .filter(|(_, v)| v.as_u64().is_some_and(|n| n > 0))
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
        }),
    });
    Ok((revision, missing, absent, summary))
}

/// Whether the released M's diagnostic lists `authority` as observed.
fn records(raw: &Value, authority: &str) -> bool {
    raw["mandate_capability"].as_array().is_some_and(|list| {
        list.iter().any(|entry| {
            entry["agent_id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(authority))
        })
    })
}

/// Run v0.46.1 on `dir` with A as its peer. Once A has M's released
/// advert, A seals the rename `name`. Read M until `done` holds for its
/// state or `CHAIN_WAIT` ends; then hold `hold` and read it again.
async fn run_released(
    (bin, dir, plane): (&Path, &Path, &str),
    a: &Real,
    (group, m_hex, name): (&str, &str, &str),
    hold: Duration,
    done: impl Fn(u64, u64, u64) -> bool,
) -> Result<(u64, u64, u64, Value)> {
    let m = Released::start(bin, dir, plane, a.udp, GRACE_TOML).await?;
    let advert = a.advert(m_hex, false).await?;
    if advert != Some(false) {
        m.stop().await;
        bail!("INFRA: A lacks the released M's advert ({advert:?})");
    }
    rename(a, group, name).await?;
    let deadline = tokio::time::Instant::now() + CHAIN_WAIT;
    let mut seen = released_state(&m, group).await?;
    while !done(seen.0, seen.1, seen.2) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        seen = released_state(&m, group).await?;
    }
    tokio::time::sleep(hold).await;
    let last = released_state(&m, group).await;
    m.stop().await;
    let (rev, missing, absent, mut raw) = last?;
    raw["log"] = json!(released_log(dir));
    Ok((rev, missing, absent, raw))
}

/// The released daemon's group-apply log lines, for the receipt.
fn released_log(dir: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    for name in ["released-stdout.log", "released-stderr.log"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        lines.extend(
            text.lines()
                .filter(|l| {
                    l.contains("MemberAdded")
                        || l.contains("reject")
                        || l.contains("catch")
                        || l.contains("gap")
                })
                .map(|l| l.chars().take(400).collect::<String>()),
        );
    }
    let skip = lines.len().saturating_sub(30);
    lines.split_off(skip)
}

/// The two variants. Each runs on its own phase 1: the released M must
/// start soon after the re-seat, while A still has r+4 to give it.
#[derive(Clone, Copy, PartialEq)]
enum Variant {
    /// (i) M recorded A as mandate-capable and is past grace.
    Recorded,
    /// (ii) M never observed A.
    Unobserved,
}

/// Phase 2: the row on real sockets.
async fn older_receiver(
    out: &Path,
    ex: &Exported,
    bin: &Path,
    receipt: &mut Receipt,
    variant: Variant,
) -> Result<Checks> {
    let plane = format!("x0x.test.h-s3-rm3.{:032x}", rand::random::<u128>());
    let (group, j_hex, m_hex) = (ex.group.as_str(), ex.j_hex.as_str(), ex.m_hex.as_str());
    let grace = Some(GRACE_DAYS);
    let a = serve_real(&out.join("A"), &plane, grace).await?;
    let o = serve_real(&out.join("O"), &plane, grace).await?;
    let j = serve_real(&out.join("J"), &plane, grace).await?;
    let m = serve_real(&out.join("M1"), &plane, grace).await?;
    a.join(o.udp).await?;
    o.join(a.udp).await?;
    j.join(a.udp).await?;
    m.join(a.udp).await?;
    a.join(m.udp).await?;
    let a_hex = hex::encode(a.state.agent.agent_id().as_bytes());
    let o_hex = hex::encode(o.state.agent.agent_id().as_bytes());
    let (o_advert, m_advert) = (a.advert(&o_hex, true).await?, a.advert(m_hex, true).await?);
    receipt.note(format!("A's adverts: O {o_advert:?}, M {m_advert:?}"));
    ensure!(o_advert == Some(true), "INFRA: A lacks O's mandate advert");
    ensure!(m_advert == Some(true), "INFRA: A lacks M's current advert");

    // Stop O. A removes J (r+3); M reaches r+3, then goes offline.
    o.stop().await?;
    let path = format!("/groups/{group}/members/{j_hex}");
    let (code, body) = a.call(Method::DELETE, &path, None).await?;
    ensure!(code < 300, "INFRA: A removes J: {code} {body}");
    let removal = a.view(group).await?;
    let m_r3 = reach(&m, group, &removal).await?;
    m.stop().await?;
    if variant == Variant::Recorded {
        let m = serve_real(&out.join("M1"), &plane, grace).await?;
        record_capable(&m, group, &a_hex).await?;
        m.stop().await?;
    }

    // The re-seat while M is offline; J reaches A's r+4 head.
    let reseat = format!("/groups/{group}/members/{j_hex}/reseat");
    let (code, answer) = a
        .call(Method::POST, &reseat, Some(reseat_body(&removal)))
        .await?;
    let head = head_past(&a, group, removal.state_revision).await?;
    let jv = reach(&j, group, &head).await?;
    receipt.note(format!(
        "re-seat {code} {answer}; A removal {}; M at r+3 {}; A {}; J {}",
        removal.describe(),
        m_r3.describe(),
        head.describe(),
        jv.describe()
    ));
    let (r3, r4) = (removal.state_revision, removal.state_revision + 1);
    let mut setup = vec![
        ("a_removes_j_at_r_plus_3", r3 == ex.sealed + 1),
        (
            "m_reaches_r_plus_3_before_going_offline",
            m_r3.state_hash == removal.state_hash,
        ),
        (
            "reseat_succeeds_while_m_is_offline",
            (200..300).contains(&code),
        ),
        (
            "j_reaches_r_plus_4",
            head.state_revision == r4 && jv.state_hash == head.state_hash,
        ),
    ];

    // The released M; A's rename (r+5) releases the chain to it.
    let m_dir = out.join("M1");
    let files = (bin, m_dir.as_path(), plane.as_str());
    let names = (group, m_hex, "w3h rm3 released");
    let row = if variant == Variant::Recorded {
        let (rev, missing, _, raw) =
            run_released(files, &a, names, HOLD, |_, missing, _| missing > 0).await?;
        // Restarted on the candidate; A's next rename (r+6) releases the
        // chain again.
        let m = serve_real(&m_dir, &plane, grace).await?;
        m.join(a.udp).await?;
        a.join(m.udp).await?;
        let latest = rename(&a, group, "w3h rm3 candidate").await?;
        let applied = applies(&m, group, &head.state_hash).await?;
        let after = m.view(group).await?;
        m.stop().await?;
        // Catch-up past r+4 is not the row's claim; the note records it.
        receipt.note(format!(
            "(i) v0.46.1 {raw}; candidate after {} (A's head {}, reached {})",
            after.describe(),
            latest.describe(),
            after.state_hash == latest.state_hash
        ));
        setup.push(("i_released_holds_the_record_of_a", records(&raw, &a_hex)));
        vec![
            ("i_released_refuses_owner_mandate_missing", missing > 0),
            ("i_released_stays_at_r_plus_3", rev == r3),
            ("i_candidate_applies_r_plus_4", applied),
        ]
    } else {
        let r5 = r4 + 1;
        let (rev, missing, absent, raw) =
            run_released(files, &a, names, Duration::ZERO, |rev, _, _| rev >= r5).await?;
        receipt.note(format!("(ii) v0.46.1 {raw}"));
        setup.push(("ii_released_has_no_record_of_a", !records(&raw, &a_hex)));
        vec![
            ("ii_released_warn_accepts_r_plus_4", rev == r5 && absent > 0),
            ("ii_released_refuses_nothing", missing == 0),
        ]
    };
    for node in [j, a] {
        node.stop().await?;
    }
    Ok((setup, row))
}

fn row(receipt: &mut Receipt, case: &str, variant: Variant) -> Result<()> {
    let bin = released_bin()?;
    let (out, exported, runtime) = phase1(case, SEED, FINAL_RM3, receipt)?;
    let started = std::time::Instant::now();
    let phase2 = older_receiver(out.path(), &exported, &bin, receipt, variant);
    let (setup, row) = runtime.block_on(phase2)?;
    receipt.note(format!("real-socket phase {:?}", started.elapsed()));
    let setup: Vec<_> = exported.checks.iter().copied().chain(setup).collect();
    conclude_checks(receipt, (FINAL_RM3, CAUSE_RM3), &setup, &row);
    Ok(())
}

/// H-S3-rm3 (i) (older receiver after the seal, D156): a control.
#[test]
#[ignore = "released-binary row: needs X0X_V0461_BIN; runs in its own CI job (#1572)"]
fn released_s3_rm3_i_past_grace_refuses_then_candidate_applies() -> Result<()> {
    let case = "released_s3_rm3_i_past_grace_refuses_then_candidate_applies";
    let note = "ADR 0109 S3 (#1356, #1572) H-S3-rm3 (i); M runs the released v0.46.1, \
                then the candidate";
    released_test(case, SEED, FINAL_RM3, note, |r| {
        row(r, case, Variant::Recorded)
    })
}

/// H-S3-rm3 (ii): M never observed A, so v0.46.1 warn-accepts r+4.
#[test]
#[ignore = "released-binary row: needs X0X_V0461_BIN; runs in its own CI job (#1572)"]
fn released_s3_rm3_ii_unobserved_warn_accepts() -> Result<()> {
    let case = "released_s3_rm3_ii_unobserved_warn_accepts";
    let note = "ADR 0109 S3 (#1356, #1572) H-S3-rm3 (ii); M runs the released v0.46.1";
    released_test(case, SEED + 1, FINAL_RM3, note, |r| {
        row(r, case, Variant::Unobserved)
    })
}
