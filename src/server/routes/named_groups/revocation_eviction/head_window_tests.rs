//! #1597 item 5b: retained-window head classification (ADR 0110 §2 as
//! changed by David's ruling of 7 Nov 2026).

use super::*;

/// The number of commits each fixture seals.
const SEALED: u64 = 6;
/// The number of oldest retained commits each fixture drops.
const DROPPED: usize = 3;

/// A group with an admin and one member, signed by `kp`.
fn group_for(kp: &x0x::identity::AgentKeypair, member: [u8; 32]) -> GroupInfo {
    let admin = *kp.agent_id().as_bytes();
    let mut info = GroupInfo::new(
        "g".into(),
        String::new(),
        x0x::identity::AgentId(admin),
        "mls-g".into(),
    );
    info.add_member(hex::encode(admin), GroupRole::Admin, None, None);
    info.add_member(hex::encode(member), GroupRole::Member, None, None);
    info
}

/// A capped window fixture. It seals revisions 1 to [`SEALED`], and
/// records the head hash at each revision. Then it drops the
/// [`DROPPED`] oldest retained commits, as the cap does. Index `n` of the
/// returned hashes is the head at revision `n` (index 0 is the genesis
/// head).
fn capped_window() -> anyhow::Result<(GroupInfo, Vec<String>)> {
    let kp = x0x::identity::AgentKeypair::generate()?;
    let mut info = group_for(&kp, [2; 32]);
    let mut heads = vec![info.state_hash.clone()];
    for at in 1..=SEALED {
        info.seal_commit(&kp, at)?;
        heads.push(info.state_hash.clone());
    }
    assert_eq!(info.state_revision, SEALED);
    info.commit_log.drain(..DROPPED);
    Ok((info, heads))
}

/// A hash that no chain in these tests produces.
fn unlinkable() -> String {
    hex::encode([0xab; 32])
}

/// The floor is the parent revision of the oldest retained commit. The
/// fixture keeps revisions 4, 5 and 6, so the floor is 3.
#[test]
fn the_floor_is_the_parent_of_the_oldest_retained_commit() -> anyhow::Result<()> {
    let (info, _) = capped_window()?;
    let oldest = info.commit_log.first().expect("a retained commit");
    assert_eq!(oldest.commit.revision, DROPPED as u64 + 1);
    assert_eq!(retained_window_floor(&info), oldest.commit.revision - 1);
    assert_eq!(retained_window_floor(&info), DROPPED as u64);
    Ok(())
}

/// A retained commit with no parent link starts the window at its own
/// revision: this node does not know the head before it.
#[test]
fn a_commit_without_a_parent_sets_the_floor_at_its_own_revision() -> anyhow::Result<()> {
    let (mut info, _) = capped_window()?;
    let oldest = info.commit_log.first_mut().expect("a retained commit");
    oldest.commit.prev_state_hash = None;
    assert_eq!(retained_window_floor(&info), DROPPED as u64 + 1);
    Ok(())
}

/// An empty commit log knows only the current head. The floor is the
/// current revision. A lower revision is below the window; the current
/// revision with another hash is a sibling and stays unknown.
#[test]
fn an_empty_commit_log_sets_the_floor_at_the_current_revision() -> anyhow::Result<()> {
    let (mut info, heads) = capped_window()?;
    info.commit_log.clear();
    assert_eq!(retained_window_floor(&info), info.state_revision);
    assert_eq!(
        classify_head_report(&info, &unlinkable(), Some(SEALED - 1)),
        HeadReport::BelowRetainedWindow
    );
    assert_eq!(
        classify_head_report(&info, &heads[1], Some(1)),
        HeadReport::BelowRetainedWindow
    );
    assert_eq!(
        classify_head_report(&info, &unlinkable(), Some(SEALED)),
        HeadReport::Unknown
    );
    assert_eq!(
        classify_head_report(&info, &info.state_hash, Some(0)),
        HeadReport::OnLocalChain
    );
    Ok(())
}

/// The window boundary. Below the floor, a hash this node cannot link
/// is a far-behind holder. At the floor this node knows the head, so
/// another hash there is a sibling and stays unknown. Above the floor it
/// stays unknown too.
#[test]
fn only_a_revision_strictly_below_the_floor_is_below_the_window() -> anyhow::Result<()> {
    let (info, heads) = capped_window()?;
    let floor = retained_window_floor(&info);
    let other = unlinkable();

    // Below the floor: a dropped head, and any other hash.
    assert_eq!(
        classify_head_report(&info, &other, Some(floor - 1)),
        HeadReport::BelowRetainedWindow
    );
    assert_eq!(
        classify_head_report(&info, &other, Some(0)),
        HeadReport::BelowRetainedWindow
    );
    for (revision, dropped) in heads.iter().enumerate().take(DROPPED) {
        assert_eq!(
            classify_head_report(&info, dropped, Some(revision as u64)),
            HeadReport::BelowRetainedWindow,
            "the dropped head at revision {revision}"
        );
    }

    // At the floor: the boundary stays unknown.
    assert_eq!(
        classify_head_report(&info, &other, Some(floor)),
        HeadReport::Unknown
    );
    // Above the floor, inside the window, and above the local head.
    assert_eq!(
        classify_head_report(&info, &other, Some(floor + 1)),
        HeadReport::Unknown
    );
    assert_eq!(
        classify_head_report(&info, &other, Some(SEALED)),
        HeadReport::Unknown
    );
    assert_eq!(
        classify_head_report(&info, &other, Some(SEALED + 1)),
        HeadReport::Unknown
    );
    assert_eq!(
        classify_head_report(&info, &other, Some(u64::MAX)),
        HeadReport::Unknown
    );
    Ok(())
}

/// An old peer sends no revision. Every hash this node cannot link stays
/// unknown, also a dropped head. This is main's behaviour.
#[test]
fn a_report_without_a_revision_keeps_the_legacy_classification() -> anyhow::Result<()> {
    let (info, heads) = capped_window()?;
    assert_eq!(
        classify_head_report(&info, &unlinkable(), None),
        HeadReport::Unknown
    );
    for dropped in heads.iter().take(DROPPED) {
        assert_eq!(
            classify_head_report(&info, dropped, None),
            HeadReport::Unknown
        );
    }
    Ok(())
}

/// A head on the local chain stays on the local chain for every
/// reported revision. The revision is only a claim; the hash link wins.
#[test]
fn a_linked_head_stays_on_the_local_chain_for_any_revision() -> anyhow::Result<()> {
    let (info, heads) = capped_window()?;
    let floor = retained_window_floor(&info);
    // The local head, every retained head, and the parent of the oldest
    // retained commit (the head at the floor).
    for linked in heads.iter().skip(DROPPED) {
        for revision in [None, Some(0), Some(floor - 1), Some(floor), Some(u64::MAX)] {
            assert_eq!(
                classify_head_report(&info, linked, revision),
                HeadReport::OnLocalChain,
                "a linked head with revision {revision:?}"
            );
        }
    }
    Ok(())
}

/// A holder first reports a head this node cannot link, with no proof
/// that it is old. It blocks the seal. Then it reports a revision below
/// the window. Its evidence clears, but the claim does not confirm the
/// round. So the round syncs only when the bounded wait has passed.
#[test]
fn a_below_window_report_clears_evidence_but_does_not_confirm() -> anyhow::Result<()> {
    let (info, _) = capped_window()?;
    let head = info.state_hash.clone();
    let floor = retained_window_floor(&info);
    let wait = Duration::from_secs(13);
    let now = Instant::now();
    let later = now + wait;
    let holder = [8; 32];
    let mut rounds = HashMap::new();
    let mut asks = HeadRoundAsks::new();
    refresh_head_round(&mut rounds, &mut asks, "g", &head, &[holder], now, wait);

    let first = classify_head_report(&info, &unlinkable(), Some(floor));
    assert_eq!(first, HeadReport::Unknown);
    note_head_report(&mut rounds, &mut asks, "g", &head, holder, first, now);
    let round = rounds.get("g").expect("round");
    assert!(round.conflicting.contains(&holder));
    assert!(!round.synced(&head, 1, false, true, later, wait));

    let second = classify_head_report(&info, &unlinkable(), Some(floor - 1));
    assert_eq!(second, HeadReport::BelowRetainedWindow);
    note_head_report(&mut rounds, &mut asks, "g", &head, holder, second, now);
    let round = rounds.get("g").expect("round");
    assert!(round.conflicting.is_empty(), "the evidence clears");
    assert!(!round.confirmed, "a claimed revision confirms nothing");
    assert!(
        asks.get("g").expect("asks").answered.contains(&holder),
        "the holder answered this round"
    );
    assert!(!round.synced(&head, 1, false, true, now, wait));
    assert!(round.synced(&head, 1, false, true, later, wait));
    // Higher-head evidence from elsewhere still blocks.
    assert!(!round.synced(&head, 1, true, true, later, wait));
    Ok(())
}

/// A holder that only reports below the window never becomes
/// conflicting. It does not block the bounded wait.
#[test]
fn a_below_window_holder_never_becomes_conflicting() -> anyhow::Result<()> {
    let (info, heads) = capped_window()?;
    let head = info.state_hash.clone();
    let wait = Duration::from_secs(13);
    let now = Instant::now();
    let holder = [9; 32];
    let mut rounds = HashMap::new();
    let mut asks = HeadRoundAsks::new();
    refresh_head_round(&mut rounds, &mut asks, "g", &head, &[holder], now, wait);
    for revision in 0..DROPPED as u64 {
        let report = classify_head_report(&info, &heads[revision as usize], Some(revision));
        assert_eq!(report, HeadReport::BelowRetainedWindow);
        note_head_report(&mut rounds, &mut asks, "g", &head, holder, report, now);
        let round = rounds.get("g").expect("round");
        assert!(round.conflicting.is_empty());
        assert!(!round.confirmed);
    }
    // The next pass asks nobody new in this round and keeps it.
    let ask = refresh_head_round(&mut rounds, &mut asks, "g", &head, &[holder], now, wait);
    assert!(ask.is_empty(), "the holder answered: it is not asked again");
    let round = rounds.get("g").expect("round");
    assert!(!round.synced(&head, 1, false, true, now, wait));
    assert!(round.synced(&head, 1, false, true, now + wait, wait));
    Ok(())
}

/// The real entry point. A holder is conflicting. An old peer's answer
/// (a hash this node cannot link and no revision) keeps it conflicting.
/// The same hash with a revision below the window clears it, and does
/// not confirm the round.
#[tokio::test]
async fn note_catchup_head_clears_evidence_only_with_a_below_window_revision() -> anyhow::Result<()>
{
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let holder = [7; 32];
    let holder_hex = hex::encode(holder);
    let (mut info, _) = capped_window()?;
    // Seat the holder on the roster the answer is judged against.
    info.add_member(holder_hex.clone(), GroupRole::Member, None, None);
    let group_id = info.mls_group_id.clone();
    let stable = info.stable_group_id().to_string();
    let floor = retained_window_floor(&info);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .head_rounds
        .insert(
            stable.clone(),
            HeadRound {
                head: info.state_hash.clone(),
                started: Instant::now(),
                asked: BTreeSet::new(),
                confirmed: false,
                conflicting: BTreeSet::from([holder]),
            },
        );
    let other = unlinkable();

    // An old peer: no revision. The evidence stays.
    note_catchup_head(
        &state,
        std::slice::from_ref(&group_id),
        &holder_hex,
        Some(&other),
        None,
    )
    .await;
    {
        let inner = state.revocation_evictions.inner.lock().await;
        let round = inner.head_rounds.get(&stable).expect("the round");
        assert!(
            round.conflicting.contains(&holder),
            "legacy stays conflicting"
        );
        assert!(!round.confirmed);
    }

    // At the floor: still a sibling. The evidence stays.
    note_catchup_head(
        &state,
        std::slice::from_ref(&group_id),
        &holder_hex,
        Some(&other),
        Some(floor),
    )
    .await;
    {
        let inner = state.revocation_evictions.inner.lock().await;
        let round = inner.head_rounds.get(&stable).expect("the round");
        assert!(
            round.conflicting.contains(&holder),
            "at the floor stays conflicting"
        );
    }

    // Below the floor: the evidence clears, the round is not confirmed.
    note_catchup_head(
        &state,
        std::slice::from_ref(&group_id),
        &holder_hex,
        Some(&other),
        Some(floor - 1),
    )
    .await;
    {
        let inner = state.revocation_evictions.inner.lock().await;
        let round = inner.head_rounds.get(&stable).expect("the round");
        assert!(
            !round.conflicting.contains(&holder),
            "below the window clears"
        );
        assert!(!round.confirmed, "a claimed revision confirms nothing");
    }
    Ok(())
}
