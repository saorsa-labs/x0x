use super::*;

// ADR 0107 (0088 slice S8 (a), ruling D55): a Home device whose join timed out
// AFTER the authority sealed its add, but before it installed its Welcome,
// keeps a durable `not_member` carry remnant (#1148's `UnseatedJoinRemnant`).
// A fresh invite whose verified base seats the device must RE-ARM that
// remnant: keep the pre-seat revision, register a new bound attempt and
// re-fetch the authority's STILL-STAGED original join result and Welcome.
// The authority serves those artifacts only to a requester that is Active,
// not banned and certificate-valid on the CURRENT committed roster.
//
// Every fixture here is in-process: agents are built without a network
// config (no `join_network`, no bootstrap peers), so every transport send
// fails locally. The authority's serve decision is read from the test-only
// `join_result_serves` witness (FetchRequest arm) and from the Welcome
// stream registry (`pending_welcome_streams`).

const OWNER_SEED: [u8; 32] = [0x07; 32];

fn hex_of(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// One of the owner's own devices (the owner key certifies it), in-process.
async fn device(
    dir: &std::path::Path,
    name: &str,
    kp: x0x::identity::AgentKeypair,
) -> anyhow::Result<Arc<AppState>> {
    let jdir = dir.join(name);
    tokio::fs::create_dir_all(&jdir).await?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.join("machine.key"))
            .with_agent_key(kp)
            .with_agent_cert_path(jdir.join("agent.cert"))
            .with_user_key(x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.join("contacts.json"))
            .build()
            .await?,
    );
    secure_endpoint_test_state_at(&jdir, agent).await
}

fn keypair(bytes: &(Vec<u8>, Vec<u8>)) -> anyhow::Result<x0x::identity::AgentKeypair> {
    Ok(x0x::identity::AgentKeypair::from_bytes(&bytes.0, &bytes.1)?)
}

fn owner_pin_of(authority: &AppState) -> String {
    hex::encode(
        authority
            .agent
            .identity()
            .user_keypair()
            .expect("owned authority")
            .user_id()
            .as_bytes(),
    )
}

/// A fresh invite minted by the authority (the original sealer) for `joiner`.
async fn mint_for(
    authority: &AppState,
    group_key: &str,
    joiner: &AppState,
) -> anyhow::Result<String> {
    let (_invite, link) = mint_invite_transaction(
        authority,
        group_key,
        3_600,
        Some(joiner.agent.agent_id()),
        x0x::groups::InviteOrigin::Explicit,
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("mint invite: {e:?}"))?;
    Ok(link)
}

/// Run the REAL join route; `home_pin` selects Home mode.
async fn join(
    joiner: &Arc<AppState>,
    link: String,
    home_pin: Option<String>,
) -> anyhow::Result<(StatusCode, serde_json::Value)> {
    let response = join_group_via_invite(
        State(Arc::clone(joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: home_pin.as_ref().map(|_| "home".to_string()),
            expected_owner_user_id: home_pin,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, body))
}

fn join_state_of(body: &serde_json::Value) -> &str {
    body.get("join_state")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>")
}

/// The joiner's live attempt id and its stored `MemberJoined`, if any.
fn attempt_of(
    joiner: &AppState,
    stable: &str,
) -> Option<(String, Option<NamedGroupMetadataEvent>)> {
    joiner
        .pending_join_attempts
        .lock()
        .expect("attempt registry")
        .get(&join_result_key(stable, &hex_of(joiner)))
        .map(|a| {
            (
                a.attempt_id.clone(),
                a.stored_resend.as_ref().map(|r| r.event.clone()),
            )
        })
}

async fn staged(
    authority: &AppState,
    stable: &str,
    member_hex: &str,
) -> Option<super::super::PendingJoinResult> {
    authority
        .pending_join_results
        .read()
        .await
        .get(&join_result_key(stable, member_hex))
        .cloned()
}

fn welcome_id_of(event: &NamedGroupMetadataEvent) -> Option<String> {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(reference),
            ..
        } => Some(reference.welcome_id.clone()),
        _ => None,
    }
}

fn revision_of(event: &NamedGroupMetadataEvent) -> Option<u64> {
    named_group_metadata_event_commit(event).map(|c| c.revision)
}

async fn local_state(joiner: &AppState, group_key: &str) -> &'static str {
    let info = joiner.named_groups.read().await.get(group_key).cloned();
    match info {
        Some(info) => local_join_membership_state(joiner, &info, &hex_of(joiner)).await,
        None => "no_row",
    }
}

async fn keyed(joiner: &AppState, group_key: &str) -> bool {
    joiner.treekem_groups.read().await.contains_key(group_key)
}

/// The typed failed re-arm on the join-status surface: `timed_out`, with
/// the cause named.
fn assert_rearm_timed_out(joiner: &AppState, group_key: &str, ctx: &str) {
    let outcome = joiner
        .last_join_outcomes
        .lock()
        .expect("outcomes")
        .get(group_key)
        .map(|o| (o.outcome, o.reason));
    assert_eq!(
        outcome,
        Some(("timed_out", Some(super::super::JOIN_REARM_TIMEOUT_REASON))),
        "[{ctx}] a failed re-arm ends with the typed timed_out outcome and its cause"
    );
}

/// The authority's PRODUCTION `FetchRequest` arm for `joiner`; returns the
/// join result it decided to serve, if any.
pub(super) async fn serve_result(
    authority: &Arc<AppState>,
    joiner: &AppState,
    stable: &str,
    attempt: &str,
    from_revision: Option<u64>,
) -> Option<JoinResultMessage> {
    let member = hex_of(joiner);
    authority
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .clear();
    super::super::handle_join_result_message(
        authority,
        &joiner.agent.agent_id(),
        true,
        JoinResultMessage::FetchRequest {
            group_id: stable.to_string(),
            member_agent_id: member.clone(),
            from_revision,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: true,
            attempt_id: Some(attempt.to_string()),
        },
    )
    .await;
    let payload = authority
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .iter()
        .rev()
        .find(|(to, group, _)| *to == member && group == stable)
        .map(|(_, _, payload)| payload.clone());
    payload.and_then(|payload| serde_json::from_slice(&payload).ok())
}

/// The authority's PRODUCTION Welcome serve path for `joiner`; true when it
/// started a stream for the staged Welcome.
pub(super) async fn serve_welcome(
    authority: &Arc<AppState>,
    joiner: &AppState,
    stable: &str,
    welcome_id: &str,
) -> bool {
    let previous = authority
        .pending_welcome_streams
        .lock()
        .await
        .as_mut()
        .and_then(|streams| streams.remove(welcome_id));
    if let Some(previous) = previous {
        previous.abort();
        let _ = previous.await;
    }
    authority
        .pending_welcome_acks
        .write()
        .await
        .remove(welcome_id);
    super::super::handle_welcome_blob_message(
        authority,
        &joiner.agent.agent_id(),
        WelcomeBlobMessage::FetchRequest {
            group_id: stable.to_string(),
            welcome_id: welcome_id.to_string(),
        },
    )
    .await;
    authority
        .pending_welcome_streams
        .lock()
        .await
        .as_ref()
        .is_some_and(|streams| streams.contains_key(welcome_id))
}

/// Pull a staged Welcome through the REAL transfer callbacks: the joiner's
/// production receive path (`fetch_treekem_welcome_via`) sends its
/// FetchRequest to the authority's production fetch handler, whose guarded
/// stream carries every Offer, Chunk and Complete frame to the joiner's real
/// handlers (and each ChunkAck back) in process.
async fn pull_welcome_through_guarded_stream(
    authority: &Arc<AppState>,
    joiner: &Arc<AppState>,
    stable: &str,
    welcome_ref: &super::super::WelcomeRef,
) -> anyhow::Result<Vec<u8>> {
    let owner = Arc::clone(authority);
    let receiver = Arc::clone(joiner);
    let owner_id = authority.agent.agent_id();
    let joiner_id = joiner.agent.agent_id();
    let pull =
        super::super::fetch_treekem_welcome_via(joiner, stable, welcome_ref, move |_, request| {
            let owner = Arc::clone(&owner);
            let receiver = Arc::clone(&receiver);
            async move {
                let WelcomeBlobMessage::FetchRequest {
                    group_id,
                    welcome_id,
                } = request
                else {
                    return Ok(());
                };
                let transport = {
                    let owner = Arc::clone(&owner);
                    move |msg: WelcomeBlobMessage| {
                        let owner = Arc::clone(&owner);
                        let receiver = Arc::clone(&receiver);
                        async move {
                            match msg {
                                WelcomeBlobMessage::Chunk {
                                    welcome_id,
                                    sequence,
                                    data,
                                } => {
                                    super::super::handle_welcome_blob_chunk(
                                        &receiver,
                                        &owner_id,
                                        welcome_id.clone(),
                                        sequence,
                                        data,
                                    )
                                    .await;
                                    super::super::handle_welcome_blob_message(
                                        &owner,
                                        &joiner_id,
                                        WelcomeBlobMessage::ChunkAck {
                                            welcome_id,
                                            sequence,
                                        },
                                    )
                                    .await;
                                }
                                other => {
                                    super::super::handle_welcome_blob_message(
                                        &receiver, &owner_id, other,
                                    )
                                    .await;
                                }
                            }
                            Ok(())
                        }
                    }
                };
                super::super::handle_welcome_fetch_request_via(
                    &owner, &joiner_id, group_id, welcome_id, transport,
                )
                .await;
                Ok(())
            }
        });
    tokio::time::timeout(Duration::from_secs(30), pull)
        .await
        .map_err(|_| anyhow::anyhow!("the guarded Welcome transfer never completed"))?
        .map_err(|e| anyhow::anyhow!("Welcome pull failed: {e}"))
}

/// Replace the served result's Welcome reference with the bytes the joiner
/// pulled through the real guarded transfer (the join-result apply path's
/// own pull uses the direct-message transport, which fails in process).
async fn with_pulled_welcome(
    authority: &Arc<AppState>,
    joiner: &Arc<AppState>,
    stable: &str,
    result: JoinResultMessage,
) -> JoinResultMessage {
    match result {
        JoinResultMessage::Result {
            mut event,
            chain,
            head_attestation,
            roster_certificates_b64,
            intervening_events,
        } => {
            if let NamedGroupMetadataEvent::MemberAdded {
                treekem_welcome_b64,
                welcome_ref,
                ..
            } = event.as_mut()
            {
                if let Some(reference) = welcome_ref.take() {
                    let bytes =
                        pull_welcome_through_guarded_stream(authority, joiner, stable, &reference)
                            .await
                            .expect("the guarded Welcome transfer delivers the original Welcome");
                    assert_eq!(
                        super::super::welcome_id_for_bytes(&bytes),
                        reference.welcome_id,
                        "the exact staged Welcome arrived"
                    );
                    *treekem_welcome_b64 = Some(BASE64.encode(bytes));
                }
            }
            JoinResultMessage::Result {
                event,
                chain,
                head_attestation,
                roster_certificates_b64,
                intervening_events,
            }
        }
        other => other,
    }
}

async fn deliver(
    joiner: &Arc<AppState>,
    sender: &AgentId,
    result: JoinResultMessage,
    attempt: &str,
) {
    super::super::handle_join_result_message_bound(joiner, sender, true, result, Some(attempt))
        .await;
}

struct Fixture {
    dir: std::path::PathBuf,
    authority: Arc<AppState>,
    authority_id: AgentId,
    group_key: String,
    stable: String,
    /// The invite base both first invites carried (r).
    base: u64,
    j1: Arc<AppState>,
    j2: Arc<AppState>,
    j2_kp: (Vec<u8>, Vec<u8>),
    j1_attempt: String,
    j2_attempt: String,
    /// J1's sealed add at r+1, as the authority staged it.
    j1_add: NamedGroupMetadataEvent,
    /// J2's sealed add at r+2 (Welcome by reference), as staged.
    j2_add: NamedGroupMetadataEvent,
}

/// Two Home devices join through the REAL route with two invites minted from
/// the same base r; the authority seals both through its REAL `MemberJoined`
/// apply (r+1 for J1, r+2 for J2), staging each join result and Welcome.
async fn build(dir: &std::path::Path) -> anyhow::Result<Fixture> {
    let authority = super::super::super::home::tests::owned_state(dir, OWNER_SEED).await?;
    super::super::super::home::provision_home(&authority).await;
    let owner = authority
        .agent
        .identity()
        .user_keypair()
        .expect("owned Home")
        .user_id();
    let (_, home) = super::super::super::home::find_home(&authority, &owner)
        .await
        .expect("provisioned Home");
    let group_key = home.mls_group_id.clone();
    let stable = home.stable_group_id().to_string();
    let base = home.state_revision;

    let j1_kp = x0x::identity::AgentKeypair::generate()?;
    let j2_kp = x0x::identity::AgentKeypair::generate()?;
    let j2_bytes = j2_kp.to_bytes();
    let j1 = device(dir, "j1", j1_kp).await?;
    let j2 = device(dir, "j2", j2_kp).await?;
    let link1 = mint_for(&authority, &group_key, &j1).await?;
    let link2 = mint_for(&authority, &group_key, &j2).await?;
    let pin = owner_pin_of(&authority);
    for (joiner, link) in [(&j1, link1), (&j2, link2)] {
        let (status, body) = join(joiner, link, Some(pin.clone())).await?;
        anyhow::ensure!(
            status == StatusCode::OK && join_state_of(&body) == "pending_authority_commit",
            "first join: {status} {body}"
        );
    }
    let (j1_attempt, Some(j1_joined)) = attempt_of(&j1, &stable).expect("J1 attempt") else {
        anyhow::bail!("J1 stored no MemberJoined");
    };
    let (j2_attempt, Some(j2_joined)) = attempt_of(&j2, &stable).expect("J2 attempt") else {
        anyhow::bail!("J2 stored no MemberJoined");
    };
    anyhow::ensure!(
        matches!(
            &j2_joined,
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(_),
                ..
            }
        ),
        "J2's MemberJoined carries its KeyPackage"
    );
    for (joiner, joined) in [(&j1, j1_joined), (&j2, j2_joined)] {
        anyhow::ensure!(
            apply_named_group_metadata_event(
                &authority,
                joined,
                joiner.agent.agent_id(),
                true,
                None
            )
            .await
            .accepted,
            "the authority seals the add through its real MemberJoined apply"
        );
    }
    let j1_add = staged(&authority, &stable, &hex_of(&j1))
        .await
        .map(|p| p.event)
        .ok_or_else(|| anyhow::anyhow!("J1 result staged"))?;
    let j2_add = staged(&authority, &stable, &hex_of(&j2))
        .await
        .map(|p| p.event)
        .ok_or_else(|| anyhow::anyhow!("J2 result staged"))?;
    anyhow::ensure!(revision_of(&j1_add) == Some(base + 1), "J1 sealed at r+1");
    anyhow::ensure!(revision_of(&j2_add) == Some(base + 2), "J2 sealed at r+2");
    anyhow::ensure!(
        welcome_id_of(&j2_add).is_some(),
        "J2's Welcome is staged by reference"
    );
    Ok(Fixture {
        dir: dir.to_path_buf(),
        authority_id: authority.agent.agent_id(),
        authority,
        group_key,
        stable,
        base,
        j1,
        j2,
        j2_kp: j2_bytes,
        j1_attempt,
        j2_attempt,
        j1_add,
        j2_add,
    })
}

/// Shape A: only the ADR 0106 carry (J1's r+1) reaches J2, then its attempt
/// times out — a durable `not_member` remnant at r+1 with no own seat.
async fn stuck_with_carry(s: &Fixture) -> anyhow::Result<()> {
    super::super::apply_join_result_intervening_events(
        &s.j2,
        &s.authority_id,
        true,
        &s.stable,
        Some(s.base + 2),
        Some(s.j2_attempt.as_str()),
        vec![s.j1_add.clone()],
    )
    .await;
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable,
        &hex_of(&s.j2),
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    anyhow::ensure!(
        local_state(&s.j2, &s.group_key).await == "not_member",
        "stuck precondition: durable not_member remnant"
    );
    anyhow::ensure!(
        remnant_revision(&s.j2, &s.group_key).await == Some(s.base + 1),
        "the carry left the remnant at r+1"
    );
    Ok(())
}

async fn remnant_revision(joiner: &AppState, group_key: &str) -> Option<u64> {
    joiner
        .named_groups
        .read()
        .await
        .get(group_key)
        .map(|i| i.state_revision)
}

/// The re-arm contract on J2's row: the pre-seat prefix is unchanged.
async fn assert_pre_seat_prefix_kept(s: &Fixture, joiner: &AppState, ctx: &str) {
    let row = joiner
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("the remnant row is kept");
    let j1_hash = named_group_metadata_event_commit(&s.j1_add)
        .map(|c| c.state_hash.clone())
        .expect("J1 commit");
    assert_eq!(
        row.state_revision,
        s.base + 1,
        "[{ctx}] re-arm keeps the pre-seat revision (no base-seat shortcut)"
    );
    assert_eq!(
        row.state_hash, j1_hash,
        "[{ctx}] re-arm keeps the verified chain prefix"
    );
    assert!(
        row.invite_lineage
            .as_ref()
            .is_some_and(|l| l.seated_at_revision.is_none()),
        "[{ctx}] the lineage is not marked seated from the invite base"
    );
    assert!(
        !row.members_v2.contains_key(&hex_of(joiner)),
        "[{ctx}] the invite base's seat for this device was not installed"
    );
}

async fn seed_leftover_treekem(joiner: &AppState, group_key: &str) -> anyhow::Result<()> {
    let group_bytes = hex::decode(group_key)?;
    let seed = agent_treekem_seed(&joiner.agent, &group_bytes);
    let leftover = x0x::mls::TreeKemMlsGroup::create(group_bytes, joiner.agent.agent_id(), &seed)?;
    joiner.treekem_groups.write().await.insert(
        group_key.to_string(),
        Arc::new(tokio::sync::Mutex::new(leftover)),
    );
    Ok(())
}

/// Redeem a fresh base-seated invite from the original sealer, then return
/// the new attempt (if one was registered) with the route's body.
async fn redeem_fresh_invite(
    s: &Fixture,
    joiner: &Arc<AppState>,
    minted_by: &AppState,
) -> anyhow::Result<(StatusCode, serde_json::Value, Option<String>)> {
    let link = mint_for(minted_by, &s.group_key, joiner).await?;
    redeem_link(s, joiner, link).await
}

async fn redeem_link(
    s: &Fixture,
    joiner: &Arc<AppState>,
    link: String,
) -> anyhow::Result<(StatusCode, serde_json::Value, Option<String>)> {
    let before = attempt_of(joiner, &s.stable).map(|(id, _)| id);
    let (status, body) = join(joiner, link, Some(owner_pin_of(&s.authority))).await?;
    let after = attempt_of(joiner, &s.stable)
        .map(|(id, _)| id)
        .filter(|id| Some(id) != before.as_ref());
    Ok((status, body, after))
}

/// WHY (ADR 0107 Validation, Shape A red/green): the #1150 mechanism. The
/// authority sealed J2's add and still holds the ORIGINAL staged result and
/// Welcome; J2 kept only the carry. A fresh base-seated invite from the
/// original sealer must re-arm the remnant (new bound attempt, pre-seat
/// prefix kept, clear and base-seat shortcut both skipped, leftover TreeKEM
/// entry dropped) so the authority's original artifacts apply gaplessly and
/// the Welcome installs. Red before S8 (a): the base-seat shortcut reports
/// `active` from the snapshot and the original r+2 add is then stale, so the
/// device stays keyless.
#[tokio::test]
async fn s8a_1150_carry_remnant_rearms_and_installs_the_original_welcome() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let j2_hex = hex_of(&s.j2);
    let original = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .expect("the original result is still staged");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(s
        .authority
        .pending_welcomes
        .read()
        .await
        .contains_key(&welcome_id));
    let authority_revision = remnant_revision(&s.authority, &s.group_key).await;
    seed_leftover_treekem(&s.j2, &s.group_key).await?;

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "a base-seated fresh invite re-arms the carry remnant instead of reporting the \
         snapshot seat: {body}"
    );
    let new_attempt = new_attempt.expect("re-arm registered a NEW bound attempt");
    assert_ne!(new_attempt, s.j2_attempt);
    assert_pre_seat_prefix_kept(&s, &s.j2, "after re-arm").await;
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "re-arm drops the leftover TreeKEM entry: it must not satisfy the poll"
    );
    assert_ne!(local_state(&s.j2, &s.group_key).await, "active");

    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the authority serves the still-staged ORIGINAL result");
    let JoinResultMessage::Result { event, .. } = &served else {
        panic!("a Result is served");
    };
    assert_eq!(
        revision_of(event),
        Some(s.base + 2),
        "the original add, not a new one"
    );
    assert!(
        serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
        "the authority streams the original Welcome"
    );
    let served = with_pulled_welcome(&s.authority, &s.j2, &s.stable, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(
        keyed(&s.j2, &s.group_key).await,
        "the recovered Welcome installed usable TreeKEM keys"
    );
    assert_eq!(
        remnant_revision(&s.authority, &s.group_key).await,
        authority_revision,
        "recovery needed no new membership commit"
    );
    let after = staged(&s.authority, &s.stable, &j2_hex).await;
    assert!(
        after.is_none_or(|p| p.created_at == original.created_at),
        "a retry never restarts the staged result's lifetime"
    );
    Ok(())
}

/// WHY (ADR 0107 Validation, joiner restart): the TreeKEM identity is
/// re-derived from the agent secret (ADR 0012), so a RESTARTED joiner with the
/// same agent key re-arms its durable remnant and decrypts the ORIGINAL
/// Welcome — and nothing secret was written to disk to make that possible.
#[tokio::test]
async fn s8a_1150_rearm_recovers_after_joiner_restart_without_stored_secrets() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    // Restart J2: a new daemon over the same data dir and agent key.
    let restarted = device(&s.dir, "j2", keypair(&s.j2_kp)?).await?;
    assert_eq!(
        local_state(&restarted, &s.group_key).await,
        "not_member",
        "the durable carry remnant survives the restart"
    );
    // The TreeKEM identity is re-derived from the agent secret and group id
    // (a re-prepared KeyPackage carries a fresh signature, so only the
    // Welcome decryption below proves the identity matches). No serialized
    // PreparedMember secret: the derivation seed appears in no file the
    // joiner wrote.
    let group_bytes = hex::decode(&s.group_key)?;
    let seed = agent_treekem_seed(&restarted.agent, &group_bytes);
    let needles = [
        seed.to_vec(),
        hex::encode(seed).into_bytes(),
        BASE64.encode(seed).into_bytes(),
    ];
    let mut stack = vec![s.dir.join("j2")];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            for needle in &needles {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "{} holds TreeKEM secret material",
                    entry.path().display()
                );
            }
        }
    }

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &restarted, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "the restarted joiner re-arms: {body}"
    );
    let new_attempt = new_attempt.expect("re-arm registered a new attempt");
    assert_pre_seat_prefix_kept(&s, &restarted, "restarted").await;
    let served = serve_result(
        &s.authority,
        &restarted,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the original result is served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &restarted, &s.stable, &welcome_id).await);
    let served = with_pulled_welcome(&s.authority, &restarted, &s.stable, served).await;
    deliver(&restarted, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&restarted, &s.group_key).await, "active");
    assert!(
        keyed(&restarted, &s.group_key).await,
        "the original Welcome decrypted under the re-derived identity"
    );
    Ok(())
}

/// WHY (ADR 0107 bounds): the re-armed attempt is bound — a result delivered
/// for the OLD attempt or by a device other than the invite's inviter applies
/// nothing — and the re-arm sends no `MemberJoined` volley (the authority's
/// step 7 would only reject it as an Active replay).
#[tokio::test]
async fn s8a_1150_rearm_rejects_stale_attempts_and_sends_no_volley() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    s.j2.named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish witness")
        .clear();
    s.j2.named_group_test_recorders
        .direct_deliveries
        .lock()
        .expect("delivery witness")
        .clear();

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "pending_authority_commit",
        "re-armed: {body}"
    );
    let new_attempt = new_attempt.expect("new attempt");
    let published_member_joined =
        s.j2.named_group_test_recorders
            .publish_bytes
            .lock()
            .expect("publish witness")
            .iter()
            .filter_map(|(_, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
            .any(|e| matches!(e, NamedGroupMetadataEvent::MemberJoined { .. }));
    let delivered_member_joined =
        s.j2.named_group_test_recorders
            .direct_deliveries
            .lock()
            .expect("delivery witness")
            .iter()
            .any(|(_, _, kind, _)| *kind == "member_joined");
    assert!(
        !published_member_joined && !delivered_member_joined,
        "the re-arm suppresses the redundant MemberJoined volley"
    );

    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_pulled_welcome(&s.authority, &s.j2, &s.stable, served).await;
    // The OLD (finalized) attempt is stale: nothing applies.
    deliver(&s.j2, &s.authority_id, served.clone(), &s.j2_attempt).await;
    assert!(!keyed(&s.j2, &s.group_key).await, "stale attempt applied");
    // A copy from a device that is not the invite's inviter is ignored.
    deliver(&s.j2, &s.j1.agent.agent_id(), served.clone(), &new_attempt).await;
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "a result from a non-inviter applied"
    );
    assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
    // The current attempt from the original sealer converges.
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert!(keyed(&s.j2, &s.group_key).await);
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    Ok(())
}

/// WHY (ADR 0107 Validation, "disabling re-arm reproduces the keyless
/// failure"): with the re-arm switched off, the same fixture takes the
/// pre-S8 (a) path — the remnant is cleared, the base-seat shortcut reports
/// the snapshot seat, and the authority's ORIGINAL add is stale at the base
/// revision, so its Welcome is never consumed and the device stays keyless
/// (#1150).
#[tokio::test]
async fn s8a_1150_disabling_rearm_reproduces_the_keyless_failure() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let _disabled = super::super::disable_rearm_for_test(&s.group_key);
    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        join_state_of(&body),
        "active",
        "without re-arm the base-seat shortcut reports the snapshot seat: {body}"
    );
    let new_attempt = new_attempt.expect("the ordinary path registered an attempt");
    let from = remnant_revision(&s.j2, &s.group_key).await;
    assert_eq!(from, Some(s.base + 2), "the row jumped to the invite base");
    let served = serve_result(&s.authority, &s.j2, &s.stable, &new_attempt, from)
        .await
        .expect("the eligible device is still served its original result");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_pulled_welcome(&s.authority, &s.j2, &s.stable, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(
        !keyed(&s.j2, &s.group_key).await,
        "#1150: the original add is stale at the base revision; the device stays keyless"
    );
    Ok(())
}

/// WHY (ADR 0107 bounds): re-arm restores the ORIGINAL seat only. A commit
/// the authority sealed after J2's add (a third device at r+3) is not part of
/// the recovered result: J2 ends keyed at r+2 and still needs ordinary
/// catch-up (#818) to reach the authority's head.
#[tokio::test]
async fn s8a_1150_rearm_restores_the_original_seat_and_post_seal_commits_need_catch_up(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    stuck_with_carry(&s).await?;
    let j3 = device(&s.dir, "j3", x0x::identity::AgentKeypair::generate()?).await?;
    let link = mint_for(&s.authority, &s.group_key, &j3).await?;
    let (status, body) = join(&j3, link, Some(owner_pin_of(&s.authority))).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, Some(j3_joined)) = attempt_of(&j3, &s.stable).expect("J3 attempt") else {
        panic!("J3 stored its MemberJoined");
    };
    assert!(
        apply_named_group_metadata_event(&s.authority, j3_joined, j3.agent.agent_id(), true, None)
            .await
            .accepted,
        "the authority seals a post-seal commit"
    );
    assert_eq!(
        remnant_revision(&s.authority, &s.group_key).await,
        Some(s.base + 3)
    );

    let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(join_state_of(&body), "pending_authority_commit", "{body}");
    let new_attempt = new_attempt.expect("re-arm attempt");
    let served = serve_result(
        &s.authority,
        &s.j2,
        &s.stable,
        &new_attempt,
        Some(s.base + 1),
    )
    .await
    .expect("the original result is served");
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let served = with_pulled_welcome(&s.authority, &s.j2, &s.stable, served).await;
    deliver(&s.j2, &s.authority_id, served, &new_attempt).await;
    assert_eq!(local_state(&s.j2, &s.group_key).await, "active");
    assert!(keyed(&s.j2, &s.group_key).await);
    assert_eq!(
        remnant_revision(&s.j2, &s.group_key).await,
        Some(s.base + 2),
        "restoring the Welcome alone does not reach the authority's r+3 head"
    );
    Ok(())
}

/// The operator exit after a failed re-arm (ADR 0107): owner remove-member,
/// then a fresh invite (whose base no longer seats the device) clears the
/// remnant and admits the device again through the ordinary join — served by
/// the guarded paths, ending keyed-active.
async fn owner_remove_and_reinvite_restores_keys(s: &Fixture, ctx: &str) -> anyhow::Result<()> {
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    anyhow::ensure!(
        removed.status().is_success(),
        "[{ctx}] owner remove-member: {}",
        removed.status()
    );
    let (status, body, attempt) = redeem_fresh_invite(s, &s.j2, &s.authority).await?;
    anyhow::ensure!(
        status == StatusCode::OK && join_state_of(&body) == "pending_authority_commit",
        "[{ctx}] re-invite: {status} {body}"
    );
    let attempt = attempt.ok_or_else(|| anyhow::anyhow!("[{ctx}] no new attempt"))?;
    let Some((_, Some(joined))) = attempt_of(&s.j2, &s.stable) else {
        anyhow::bail!("[{ctx}] the ordinary join stored its MemberJoined");
    };
    anyhow::ensure!(
        apply_named_group_metadata_event(&s.authority, joined, s.j2.agent.agent_id(), true, None)
            .await
            .accepted,
        "[{ctx}] the authority re-admits the removed device"
    );
    let staged_add = staged(&s.authority, &s.stable, &hex_of(&s.j2))
        .await
        .ok_or_else(|| anyhow::anyhow!("[{ctx}] re-admission staged"))?
        .event;
    let from = remnant_revision(&s.j2, &s.group_key).await;
    let served = serve_result(&s.authority, &s.j2, &s.stable, &attempt, from)
        .await
        .ok_or_else(|| anyhow::anyhow!("[{ctx}] the re-admitted device is served"))?;
    let welcome_id =
        welcome_id_of(&staged_add).ok_or_else(|| anyhow::anyhow!("[{ctx}] welcome ref"))?;
    anyhow::ensure!(
        serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
        "[{ctx}] the re-admission Welcome is streamed"
    );
    let served = with_pulled_welcome(&s.authority, &s.j2, &s.stable, served).await;
    deliver(&s.j2, &s.authority_id, served, &attempt).await;
    anyhow::ensure!(
        local_state(&s.j2, &s.group_key).await == "active" && keyed(&s.j2, &s.group_key).await,
        "[{ctx}] owner remove-member + re-invite restores membership WITH keys"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LostStaging {
    ResultExpired,
    WelcomeExpired,
    AuthorityRestarted,
}

/// WHY (ADR 0107 bounds): the re-arm depends on the original sealer's
/// in-memory caches. An expired result, an expired Welcome or an authority
/// restart loses the route: the joiner must never claim recovery or
/// confirmation, and the attempt ends with the typed `timed_out` outcome.
#[tokio::test]
async fn s8a_1150_lost_staging_never_claims_recovery() -> anyhow::Result<()> {
    for case in [
        LostStaging::ResultExpired,
        LostStaging::WelcomeExpired,
        LostStaging::AuthorityRestarted,
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        stuck_with_carry(&s).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        let expired = Instant::now()
            .checked_sub(super::super::PENDING_JOIN_RESULT_TTL + Duration::from_secs(1))
            .expect("monotonic clock far enough from boot");
        let serving = match case {
            LostStaging::ResultExpired => {
                if let Some(p) = s
                    .authority
                    .pending_join_results
                    .write()
                    .await
                    .get_mut(&join_result_key(&s.stable, &j2_hex))
                {
                    p.created_at = expired;
                }
                Arc::clone(&s.authority)
            }
            LostStaging::WelcomeExpired => {
                if let Some(w) = s
                    .authority
                    .pending_welcomes
                    .write()
                    .await
                    .get_mut(&welcome_id)
                {
                    w.created_at = expired;
                }
                Arc::clone(&s.authority)
            }
            LostStaging::AuthorityRestarted => {
                super::super::super::home::tests::owned_state(&s.dir, OWNER_SEED).await?
            }
        };
        let (status, body, new_attempt) = redeem_fresh_invite(&s, &s.j2, &serving).await?;
        assert_eq!(status, StatusCode::OK, "[{case:?}] {body}");
        assert_ne!(
            join_state_of(&body),
            "active",
            "[{case:?}] a base-seated invite must not claim confirmed membership: {body}"
        );
        let new_attempt = new_attempt.expect("re-arm registered an attempt");
        let served = serve_result(&serving, &s.j2, &s.stable, &new_attempt, Some(s.base + 1)).await;
        match case {
            // Without the result the device never learns the Welcome
            // reference, so it has nothing to pull.
            LostStaging::ResultExpired => {
                assert!(served.is_none(), "[{case:?}] no result to serve");
            }
            LostStaging::WelcomeExpired => {
                assert!(served.is_some(), "[{case:?}] the result is still staged");
                assert!(
                    !serve_welcome(&serving, &s.j2, &s.stable, &welcome_id).await,
                    "[{case:?}] no Welcome to stream"
                );
            }
            LostStaging::AuthorityRestarted => {
                assert!(served.is_none(), "[{case:?}] no result to serve");
                assert!(
                    !serve_welcome(&serving, &s.j2, &s.stable, &welcome_id).await,
                    "[{case:?}] no Welcome to stream"
                );
            }
        }
        assert!(!keyed(&s.j2, &s.group_key).await, "[{case:?}] keyed");
        assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
        super::super::finalize_join_attempt(
            &s.j2,
            &s.group_key,
            &s.stable,
            &j2_hex,
            &new_attempt,
            super::super::JoinAttemptOutcome::TimedOut,
            super::super::JoinFinalizeGuard::Unlocked,
        )
        .await;
        assert_rearm_timed_out(&s.j2, &s.group_key, &format!("{case:?}"));
        assert_eq!(
            local_state(&s.j2, &s.group_key).await,
            "not_member",
            "[{case:?}] a failed re-arm leaves the remnant for owner remove-member + re-invite"
        );
        // The eligible-device exit works from that state (an authority that
        // restarted reloads no TreeKEM group in this fixture, so its exit is
        // the same route and is not repeated here).
        if !matches!(case, LostStaging::AuthorityRestarted) {
            owner_remove_and_reinvite_restores_keys(&s, &format!("{case:?}")).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PostSeal {
    Banned,
    Removed,
    CertificateRevoked,
}

async fn revoke_agent(authority: &AppState, kp: &(Vec<u8>, Vec<u8>)) -> anyhow::Result<()> {
    let kp = keypair(kp)?;
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(kp.agent_id()),
        kp.public_key(),
        kp.secret_key(),
        x0x::groups::owner_cert::restore_clock_now(),
        Some("adr0107 revocation".to_string()),
    )?;
    authority
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)?;
    Ok(())
}

async fn apply_post_seal(s: &Fixture, case: PostSeal) -> anyhow::Result<()> {
    let j2_hex = hex_of(&s.j2);
    match case {
        PostSeal::Banned => {
            s.authority
                .named_groups
                .write()
                .await
                .get_mut(&s.group_key)
                .expect("authority group")
                .ban_member(&j2_hex, None);
        }
        PostSeal::Removed => {
            s.authority
                .named_groups
                .write()
                .await
                .get_mut(&s.group_key)
                .expect("authority group")
                .remove_member(&j2_hex, None);
        }
        PostSeal::CertificateRevoked => revoke_agent(&s.authority, &s.j2_kp).await?,
    }
    Ok(())
}

/// WHY (ADR 0107 Validation, #1149 + carry, must not gain keys): the
/// authority mints a base-seated invite, THEN bans, removes or revokes J2
/// while its ORIGINAL result and Welcome stay staged. J2 redeems the old
/// invite: the re-arm must not report the snapshot seat, neither serving path
/// may hand the ineligible device anything, and J2 must never end
/// keyed-active (typed `timed_out`, row back to `not_member`). Red before
/// S8 (a): J2 reports `active` from the snapshot alone.
#[tokio::test]
async fn s8a_1149_carry_remnant_never_gains_keys_after_post_seal_ineligibility(
) -> anyhow::Result<()> {
    for case in [
        PostSeal::Banned,
        PostSeal::Removed,
        PostSeal::CertificateRevoked,
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        stuck_with_carry(&s).await?;
        let link = mint_for(&s.authority, &s.group_key, &s.j2).await?;
        apply_post_seal(&s, case).await?;
        assert!(
            staged(&s.authority, &s.stable, &hex_of(&s.j2))
                .await
                .is_some(),
            "[{case:?}] original caches intact"
        );
        let (status, body, new_attempt) = redeem_link(&s, &s.j2, link).await?;
        assert_eq!(status, StatusCode::OK, "[{case:?}] {body}");
        assert_ne!(
            join_state_of(&body),
            "active",
            "[{case:?}] a stale base-seated invite is not current admission: {body}"
        );
        assert_ne!(local_state(&s.j2, &s.group_key).await, "active");
        let new_attempt = new_attempt.expect("re-arm registered an attempt");
        assert!(
            serve_result(
                &s.authority,
                &s.j2,
                &s.stable,
                &new_attempt,
                Some(s.base + 1)
            )
            .await
            .is_none(),
            "[{case:?}] no join result may be served to an ineligible member"
        );
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        assert!(
            !serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await,
            "[{case:?}] no Welcome may be streamed to an ineligible member"
        );
        super::super::finalize_join_attempt(
            &s.j2,
            &s.group_key,
            &s.stable,
            &hex_of(&s.j2),
            &new_attempt,
            super::super::JoinAttemptOutcome::TimedOut,
            super::super::JoinFinalizeGuard::Unlocked,
        )
        .await;
        assert_rearm_timed_out(&s.j2, &s.group_key, &format!("{case:?}"));
        assert_eq!(local_state(&s.j2, &s.group_key).await, "not_member");
        assert!(
            !keyed(&s.j2, &s.group_key).await,
            "[{case:?}] never keyed-active"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Ineligible {
    Banned,
    Removed,
    Expired,
    ForeignOwner,
    DigestPending,
    InGrace,
    Revoked,
}

/// Insert a VALID owner certificate for `agent` into the authority's
/// announce/discovery cache — which the serving guard must NOT consult.
async fn announce_valid_cert(authority: &AppState, cert: x0x::identity::AgentCertificate) {
    let agent_id = cert.agent_id().expect("cert agent id");
    let user_id = cert.user_id().ok();
    insert_discovery_entry(authority, agent_id, user_id, Some(cert), None).await;
}

/// Seed the authority's announce/discovery cache for `agent_id` the way a
/// verified announce leaves it: an announced certificate digest, with the
/// certificate bytes resolved or still in flight.
async fn insert_discovery_entry(
    authority: &AppState,
    agent_id: AgentId,
    user_id: Option<x0x::identity::UserId>,
    cert: Option<x0x::identity::AgentCertificate>,
    cert_digest: Option<[u8; 32]>,
) {
    authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(
            agent_id,
            x0x::DiscoveredAgent {
                agent_id,
                machine_id: x0x::identity::MachineId([0u8; 32]),
                user_id,
                self_name: None,
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: cert.as_ref().and_then(|c| c.not_after()),
                agent_certificate: cert,
                agent_public_key: Vec::new(),
                cert_digest,
            },
        );
}

/// Put the authority's ORIGINAL staged result and Welcome back (a definitive
/// refusal purges both), and prove they are present.
async fn restore_staged_artifacts(
    authority: &AppState,
    stable: &str,
    member_hex: &str,
    result: &super::super::PendingJoinResult,
    welcome_id: &str,
    welcome: &super::super::PendingWelcome,
) {
    authority
        .pending_join_results
        .write()
        .await
        .insert(join_result_key(stable, member_hex), result.clone());
    authority
        .pending_welcomes
        .write()
        .await
        .insert(welcome_id.to_string(), welcome.clone());
    assert!(staged(authority, stable, member_hex).await.is_some());
    assert!(authority
        .pending_welcomes
        .read()
        .await
        .contains_key(welcome_id));
}

/// WHY (ADR 0107 serving guard): both serving paths serve a requester only
/// while it is Active, not banned and certificate-valid on the CURRENT
/// committed roster. The roster is mutated directly here (no route, so no
/// purge runs): the guard alone must refuse. OwnerCertified serving uses the
/// ROSTER-EMBEDDED certificate with the current revocation set and clock — a
/// valid certificate in the announce/discovery cache never rescues an
/// expired or foreign one — and DigestPending and the missing-evidence InGrace
/// shape fail closed (InGrace also covers stale evidence mid-rotation). The
/// control (an eligible, inline-certified first join with no announce) is
/// served on both paths.
#[tokio::test]
async fn s8a_serving_guard_refuses_ineligible_requesters_on_both_paths() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let roster = s
        .authority
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("authority group");
    let result = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .expect("staged");
    let welcome = s
        .authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .cloned()
        .expect("staged Welcome");
    assert!(
        roster
            .members_v2
            .get(&j2_hex)
            .is_some_and(|m| m.certificate.is_some()),
        "the seal embedded J2's inline (#842) certificate in the roster"
    );
    assert!(
        s.authority
            .agent
            .identity_discovery_cache()
            .read()
            .await
            .get(&s.j2.agent.agent_id())
            .is_none_or(|d| d.agent_certificate.is_none()),
        "no announce for J2 reached the authority"
    );

    let restore = || async {
        s.authority
            .named_groups
            .write()
            .await
            .insert(s.group_key.clone(), roster.clone());
        s.authority
            .pending_join_results
            .write()
            .await
            .insert(join_result_key(&s.stable, &j2_hex), result.clone());
        s.authority
            .pending_welcomes
            .write()
            .await
            .insert(welcome_id.clone(), welcome.clone());
        s.authority
            .agent
            .identity_discovery_cache()
            .write()
            .await
            .remove(&s.j2.agent.agent_id());
    };
    // Each guard is exercised on its OWN intact caches: a definitive refusal
    // on the result path purges the Welcome too, so the caches are restored
    // (and asserted present) before each path — the Welcome refusal is the
    // Welcome guard's, never a missing cache entry.
    let served = |ctx: String| {
        let s = &s;
        let welcome_id = welcome_id.clone();
        let result = result.clone();
        let welcome = welcome.clone();
        let j2_hex = j2_hex.clone();
        async move {
            restore_staged_artifacts(
                &s.authority,
                &s.stable,
                &j2_hex,
                &result,
                &welcome_id,
                &welcome,
            )
            .await;
            let result_served =
                serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
                    .await
                    .is_some();
            restore_staged_artifacts(
                &s.authority,
                &s.stable,
                &j2_hex,
                &result,
                &welcome_id,
                &welcome,
            )
            .await;
            let welcome_served = serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await;
            (ctx, result_served, welcome_served)
        }
    };

    let (ctx, result_served, welcome_served) = served("eligible control".into()).await;
    assert!(
        result_served && welcome_served,
        "[{ctx}] an eligible first join is served on both paths"
    );

    let mut leaks = Vec::new();
    for case in [
        Ineligible::Banned,
        Ineligible::Removed,
        Ineligible::Expired,
        Ineligible::ForeignOwner,
        Ineligible::DigestPending,
        Ineligible::InGrace,
        Ineligible::Revoked,
    ] {
        restore().await;
        let (ctx, result_served, welcome_served) = served(format!("{case:?} control")).await;
        assert!(result_served && welcome_served, "[{ctx}] restored");
        {
            let j2_kp = keypair(&s.j2_kp)?;
            let mut groups = s.authority.named_groups.write().await;
            let info = groups.get_mut(&s.group_key).expect("authority group");
            match case {
                Ineligible::Banned => {
                    info.ban_member(&j2_hex, None);
                }
                Ineligible::Removed => {
                    info.remove_member(&j2_hex, None);
                }
                Ineligible::Expired => {
                    let past = x0x::groups::owner_cert::restore_clock_now() - 30 * 86_400;
                    let expired = x0x::identity::AgentCertificate::issue_with_expiry(
                        &owner_kp,
                        &j2_kp,
                        Some(past),
                    )?;
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = Some(expired);
                    }
                }
                Ineligible::ForeignOwner => {
                    let stranger = x0x::identity::UserKeypair::generate()?;
                    let foreign = x0x::identity::AgentCertificate::issue(&stranger, &j2_kp)?;
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = Some(foreign);
                    }
                }
                Ineligible::DigestPending => {
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = None;
                    }
                }
                Ineligible::InGrace => {
                    if let Some(m) = info.members_v2.get_mut(&j2_hex) {
                        m.certificate = None;
                        m.certificate_digest = None;
                    }
                }
                Ineligible::Revoked => {}
            }
            let status = info
                .clone()
                .owner_cert_verdict(&x0x::groups::owner_cert::OwnerCertEvidence::new(
                    x0x::groups::owner_cert::restore_clock_now(),
                ))
                .per_member
                .get(&j2_hex)
                .cloned();
            match case {
                Ineligible::DigestPending => assert_eq!(
                    status,
                    Some(x0x::groups::owner_cert::MemberCertStatus::DigestPending)
                ),
                Ineligible::InGrace => assert!(
                    matches!(
                        status,
                        Some(x0x::groups::owner_cert::MemberCertStatus::InGrace { .. })
                    ),
                    "fixture shape is InGrace: {status:?}"
                ),
                _ => {}
            }
        }
        match case {
            Ineligible::Expired | Ineligible::ForeignOwner => {
                announce_valid_cert(
                    &s.authority,
                    x0x::identity::AgentCertificate::issue(&owner_kp, &keypair(&s.j2_kp)?)?,
                )
                .await;
            }
            Ineligible::Revoked => revoke_agent(&s.authority, &s.j2_kp).await?,
            _ => {}
        }
        let (ctx, result_served, welcome_served) = served(format!("{case:?}")).await;
        if result_served {
            leaks.push(format!("{ctx}: FetchRequest arm served a join result"));
        }
        if welcome_served {
            leaks.push(format!("{ctx}: Welcome path streamed key material"));
        }
    }
    assert!(
        leaks.is_empty(),
        "ineligible requesters were served: {leaks:#?}"
    );
    Ok(())
}

/// WHY (ADR 0107 purge): an owner removal or ban through the production
/// routes drops that member's staged join result and Welcome and cancels its
/// unsent Welcome transfer, so a previously copied cache entry cannot bypass
/// the guard. The streams are parked at the test gate (registered, not yet
/// sent) when the mutation lands.
#[tokio::test]
async fn s8a_owner_remove_and_ban_purge_staged_artifacts_and_cancel_transfers() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let gates = super::super::WELCOME_STREAM_TEST_GATES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut parked = Vec::new();
    for (joiner, add) in [(&s.j1, &s.j1_add), (&s.j2, &s.j2_add)] {
        let welcome_id = welcome_id_of(add).expect("welcome ref");
        gates
            .lock()
            .map_err(|_| anyhow::anyhow!("gate map"))?
            .insert(welcome_id.clone(), Arc::new(tokio::sync::Notify::new()));
        assert!(serve_welcome(&s.authority, joiner, &s.stable, &welcome_id).await);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !s
                .authority
                .pending_welcome_acks
                .read()
                .await
                .contains_key(&welcome_id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        parked.push((Arc::clone(joiner), welcome_id));
    }

    let owner =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        owner.clone(),
        Path((s.group_key.clone(), hex_of(&s.j1))),
    )
    .await
    .into_response();
    assert!(
        removed.status().is_success(),
        "remove: {}",
        removed.status()
    );
    let banned = ban_group_member(
        State(Arc::clone(&s.authority)),
        owner,
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    assert!(banned.status().is_success(), "ban: {}", banned.status());

    for (joiner, welcome_id) in &parked {
        let who = if Arc::ptr_eq(joiner, &s.j1) {
            "removed J1"
        } else {
            "banned J2"
        };
        assert!(
            staged(&s.authority, &s.stable, &hex_of(joiner))
                .await
                .is_none(),
            "[{who}] the staged join result is dropped"
        );
        assert!(
            !s.authority
                .pending_welcomes
                .read()
                .await
                .contains_key(welcome_id),
            "[{who}] the staged Welcome is dropped"
        );
        assert!(
            !s.authority
                .pending_welcome_streams
                .lock()
                .await
                .as_ref()
                .is_some_and(|streams| streams.contains_key(welcome_id)),
            "[{who}] the unsent Welcome transfer is cancelled"
        );
        assert!(
            !s.authority
                .pending_welcome_acks
                .read()
                .await
                .contains_key(welcome_id),
            "[{who}] the transfer's ack slot is released"
        );
        if let Ok(mut gates) = gates.lock() {
            gates.remove(welcome_id);
        }
    }
    Ok(())
}

/// WHY (ADR 0107 serving non-regression, TreeKEM): ordinary eligible first
/// joins — certified INLINE (#842) with no announce at the authority — still
/// receive their staged results and Welcomes, and the #1139 / ADR 0106
/// intervening-events carry is still served and applied before the joiner's
/// own event.
#[tokio::test]
async fn s8a_serving_non_regression_treekem_first_joins_and_adr0106_carry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    for (joiner, attempt, add, carried) in [
        (&s.j1, &s.j1_attempt, &s.j1_add, Vec::<u64>::new()),
        (&s.j2, &s.j2_attempt, &s.j2_add, vec![s.base + 1]),
    ] {
        assert!(
            s.authority
                .agent
                .identity_discovery_cache()
                .read()
                .await
                .get(&joiner.agent.agent_id())
                .is_none_or(|d| d.agent_certificate.is_none()),
            "announce absent"
        );
        let served = serve_result(&s.authority, joiner, &s.stable, attempt, Some(s.base))
            .await
            .expect("an eligible first join is served");
        let JoinResultMessage::Result {
            event,
            intervening_events,
            ..
        } = &served
        else {
            panic!("a Result is served");
        };
        assert_eq!(revision_of(event), revision_of(add));
        assert_eq!(
            intervening_events
                .iter()
                .filter_map(revision_of)
                .collect::<Vec<_>>(),
            carried,
            "the ADR 0106 carry is unchanged"
        );
        let welcome_id = welcome_id_of(add).expect("welcome ref");
        assert!(serve_welcome(&s.authority, joiner, &s.stable, &welcome_id).await);
        let served = with_pulled_welcome(&s.authority, joiner, &s.stable, served).await;
        deliver(joiner, &s.authority_id, served, attempt).await;
        assert_eq!(local_state(joiner, &s.group_key).await, "active");
        assert!(keyed(joiner, &s.group_key).await);
    }
    Ok(())
}

struct GssFixture {
    dir: std::path::PathBuf,
    authority: Arc<AppState>,
    group_key: String,
    stable: String,
    joiner: Arc<AppState>,
    attempt: String,
}

/// A GSS-plane group (MlsEncrypted, not Hidden) on an owned authority, with
/// one device joined through the REAL route and sealed through the
/// authority's REAL `MemberJoined` apply (its join result staged, its
/// secure share published).
async fn build_gss(dir: &std::path::Path, owner_certified: bool) -> anyhow::Result<GssFixture> {
    let authority = super::super::super::home::tests::owned_state(dir, OWNER_SEED).await?;
    let owner_id = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?.user_id();
    let policy = x0x::groups::GroupPolicy {
        discoverability: x0x::groups::GroupDiscoverability::ListedToContacts,
        admission: if owner_certified {
            x0x::groups::GroupAdmission::OwnerCertified(owner_id)
        } else {
            x0x::groups::GroupAdmission::InviteOnly
        },
        confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    };
    let created = create_named_group(
        State(Arc::clone(&authority)),
        Json(CreateGroupRequest {
            name: "gss".to_string(),
            description: String::new(),
            display_name: None,
            preset: None,
            policy: Some(policy),
        }),
    )
    .await
    .into_response();
    let status = created.status();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(created.into_body(), usize::MAX).await?)?;
    anyhow::ensure!(status == StatusCode::CREATED, "create: {status} {body}");
    let group_key = body["group_id"].as_str().unwrap_or_default().to_string();
    let stable = {
        let groups = authority.named_groups.read().await;
        let info = groups
            .get(&group_key)
            .ok_or_else(|| anyhow::anyhow!("created group"))?;
        anyhow::ensure!(info.secure_plane == x0x::mls::SecureGroupPlane::Gss);
        info.stable_group_id().to_string()
    };
    let joiner = device(dir, "g", x0x::identity::AgentKeypair::generate()?).await?;
    let link = mint_for(&authority, &group_key, &joiner).await?;
    let (status, body) = join(
        &joiner,
        link,
        owner_certified.then(|| owner_pin_of(&authority)),
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "[oc={owner_certified}] {body}");
    let Some((attempt, Some(joined))) = attempt_of(&joiner, &stable) else {
        anyhow::bail!("stored MemberJoined");
    };
    anyhow::ensure!(
        apply_named_group_metadata_event(&authority, joined, joiner.agent.agent_id(), true, None)
            .await
            .accepted,
        "[oc={owner_certified}] the authority seals the GSS add"
    );
    anyhow::ensure!(
        staged(&authority, &stable, &hex_of(&joiner))
            .await
            .is_some(),
        "GSS result staged"
    );
    Ok(GssFixture {
        dir: dir.to_path_buf(),
        authority,
        group_key,
        stable,
        joiner,
        attempt,
    })
}

/// The `SecureShareDelivered` the authority published for `recipient`.
fn published_secure_share(
    authority: &AppState,
    recipient: &str,
) -> Option<NamedGroupMetadataEvent> {
    // D60 (r5, G11): a share is a class-K delivery to its recipient, never a
    // gossip publish; read the scheduled delivery's exact payload.
    authority
        .named_group_test_recorders
        .secure_share_scheduled
        .lock()
        .expect("secure-share witness")
        .iter()
        .filter(|(_, to, _)| to == recipient)
        .find_map(|(_, _, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
}

/// WHY (ADR 0107 serving non-regression, GSS): GSS-plane first joins are
/// served too — an OwnerCertified group whose joiner is certified inline with
/// no announce, and an ordinary invite-only group that needs no certificate —
/// and the joiner ends with USABLE key material: the served result seats it
/// and the authority's sealed secure share installs the group's current
/// secret.
#[tokio::test]
async fn s8a_serving_non_regression_gss_first_joins() -> anyhow::Result<()> {
    for owner_certified in [true, false] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), owner_certified).await?;
        let authority_id = g.authority.agent.agent_id();
        let from = remnant_revision(&g.joiner, &g.group_key).await;
        let served = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from)
            .await
            .unwrap_or_else(|| {
                panic!("[oc={owner_certified}] an eligible GSS first join is served")
            });
        deliver(&g.joiner, &authority_id, served, &g.attempt).await;
        assert_eq!(
            local_state(&g.joiner, &g.group_key).await,
            "active",
            "[oc={owner_certified}] the served result seats the joiner"
        );
        let share = published_secure_share(&g.authority, &hex_of(&g.joiner))
            .unwrap_or_else(|| panic!("[oc={owner_certified}] the authority sealed a share"));
        assert!(
            apply_named_group_metadata_event(&g.joiner, share, authority_id, true, None)
                .await
                .accepted,
            "[oc={owner_certified}] the joiner opens the sealed share"
        );
        let (authority_secret, authority_epoch) = {
            let groups = g.authority.named_groups.read().await;
            let info = groups.get(&g.group_key).expect("authority group");
            (info.shared_secret.clone(), info.secret_epoch)
        };
        let (joiner_secret, joiner_epoch) = {
            let groups = g.joiner.named_groups.read().await;
            let info = groups.get(&g.group_key).expect("joiner group");
            (info.shared_secret.clone(), info.secret_epoch)
        };
        assert!(authority_secret.is_some());
        assert_eq!(
            (joiner_secret, joiner_epoch),
            (authority_secret, authority_epoch),
            "[oc={owner_certified}] the joiner holds the group's current secret"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Review r2 (Codex, PR #1190): every remaining egress of a join artifact —
// control-blob staging and chunks, the inline result send, Welcome frames —
// is linearized with membership mutations; purge runs inside the mutation's
// critical section on every path (API, apply, replay); and the Welcome
// listener never blocks on a group lock.
// ---------------------------------------------------------------------------

type BlobRef = super::super::control_blob::ControlBlobRef;

fn egress_count(state: &AppState, recipient: &str, kind: &str) -> usize {
    state
        .named_group_test_recorders
        .join_artifact_egress
        .lock()
        .expect("egress witness")
        .iter()
        .filter(|(to, _, k)| to == recipient && *k == kind)
        .count()
}

fn clear_egress(state: &AppState) {
    state
        .named_group_test_recorders
        .join_artifact_egress
        .lock()
        .expect("egress witness")
        .clear();
}

/// Wait (bounded) for `kind` egress to `recipient`; false when none happens.
async fn egress_happens(state: &AppState, recipient: &str, kind: &str, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if egress_count(state, recipient, kind) > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    egress_count(state, recipient, kind) > 0
}

async fn wait_reached(gate: &super::super::join_egress_test_barrier::Gate, what: &str) {
    let reached = tokio::time::timeout(Duration::from_secs(10), async {
        while !gate.reached() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "{what}: the barrier was never reached");
}

/// The eligible J2's oversized join result, staged as a control blob by the
/// production FetchRequest arm.
async fn staged_join_result_blob(s: &Fixture) -> anyhow::Result<BlobRef> {
    anyhow::ensure!(
        serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
            .await
            .is_some(),
        "the eligible device is served"
    );
    let j2_hex = hex_of(&s.j2);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(reference) = s
                .authority
                .control_blobs
                .staged_join_result_refs_for_test(&j2_hex)
                .into_iter()
                .next()
            {
                return reference;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("the oversized result was never staged"))
}

async fn fetch_chunk(s: &Fixture, reference: &BlobRef) {
    super::super::control_blob::handle_control_blob_message(
        &s.authority,
        &s.j2.agent.agent_id(),
        true,
        super::super::control_blob::ControlBlobMessage::Fetch {
            reference: reference.clone(),
            sequence: 0,
        },
    )
    .await;
}

async fn ban_via_route(authority: &Arc<AppState>, group_key: &str, member_hex: &str) -> StatusCode {
    ban_group_member(
        State(Arc::clone(authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((group_key.to_string(), member_hex.to_string())),
    )
    .await
    .into_response()
    .status()
}

/// WHY (review r2 P1-1): a staged JoinResult control blob is a copy of the
/// result. Chunk egress must pass the same current-roster guard as the
/// FetchRequest arm: a recipient banned, or whose roster certificate has
/// expired, since the blob was staged gets no chunk.
#[tokio::test]
async fn s8a_r2_join_result_chunks_refuse_ineligible_recipients() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let reference = staged_join_result_blob(&s).await?;
    clear_egress(&s.authority);
    fetch_chunk(&s, &reference).await;
    assert!(
        egress_happens(
            &s.authority,
            &j2_hex,
            "join_result_chunk",
            Duration::from_secs(5)
        )
        .await,
        "control: an eligible recipient pulls its chunk"
    );
    let roster = s
        .authority
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("authority group");
    let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let mut leaks = Vec::new();
    for case in ["banned", "certificate_expired"] {
        s.authority
            .named_groups
            .write()
            .await
            .insert(s.group_key.clone(), roster.clone());
        {
            let mut groups = s.authority.named_groups.write().await;
            let info = groups.get_mut(&s.group_key).expect("authority group");
            if case == "banned" {
                info.ban_member(&j2_hex, None);
            } else if let Some(seat) = info.members_v2.get_mut(&j2_hex) {
                let past = x0x::groups::owner_cert::restore_clock_now() - 30 * 86_400;
                seat.certificate = Some(x0x::identity::AgentCertificate::issue_with_expiry(
                    &owner_kp,
                    &keypair(&s.j2_kp)?,
                    Some(past),
                )?);
            }
        }
        // The roster changed directly (no route, no purge): only the chunk
        // guard stands between the copied blob and the recipient.
        assert!(!s
            .authority
            .control_blobs
            .staged_join_result_refs_for_test(&j2_hex)
            .is_empty());
        clear_egress(&s.authority);
        fetch_chunk(&s, &reference).await;
        if egress_happens(
            &s.authority,
            &j2_hex,
            "join_result_chunk",
            Duration::from_secs(1),
        )
        .await
        {
            leaks.push(case);
        }
    }
    assert!(
        leaks.is_empty(),
        "a staged join-result blob was chunked to an ineligible recipient: {leaks:?}"
    );
    Ok(())
}

/// WHY (review r2 P1-1): an owner ban drops the member's staged JoinResult
/// control blobs too, not only the result and Welcome caches.
#[tokio::test]
async fn s8a_r2_owner_ban_purges_staged_join_result_blobs() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    staged_join_result_blob(&s).await?;
    assert!(ban_via_route(&s.authority, &s.group_key, &j2_hex)
        .await
        .is_success());
    assert!(
        s.authority
            .control_blobs
            .staged_join_result_refs_for_test(&j2_hex)
            .is_empty(),
        "the banned member's staged join-result blob is purged"
    );
    Ok(())
}

/// WHY (review r2 P1-1): the bounded staging of an oversized result runs
/// after the FetchRequest arm's check. A ban that commits while the staging
/// is pending must stop it: no blob is (re)created and no reference leaves.
#[tokio::test]
async fn s8a_r2_delayed_join_result_staging_cannot_recreate_purged_blobs() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_stage");
    clear_egress(&s.authority);
    assert!(
        serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
            .await
            .is_some(),
        "the eligible device's fetch is accepted"
    );
    wait_reached(&armed.gate, "staging").await;
    assert!(ban_via_route(&s.authority, &s.group_key, &j2_hex)
        .await
        .is_success());
    drop(armed);
    let referenced = egress_happens(
        &s.authority,
        &j2_hex,
        "join_result_reference",
        Duration::from_secs(2),
    )
    .await;
    let staged = s
        .authority
        .control_blobs
        .staged_join_result_refs_for_test(&j2_hex);
    assert!(
        !referenced && staged.is_empty(),
        "a staging that resumed after the ban recreated the blob (referenced={referenced}, staged={})",
        staged.len()
    );
    Ok(())
}

/// WHY (review r2 P1-1/P1-2): a chunk send that passed its check when the
/// ban committed must not deliver: the ban cancels the outstanding send.
#[tokio::test]
async fn s8a_r2_ban_racing_join_result_chunk_egress_sends_nothing() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let reference = staged_join_result_blob(&s).await?;
    let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_chunk");
    clear_egress(&s.authority);
    fetch_chunk(&s, &reference).await;
    wait_reached(&armed.gate, "chunk egress").await;
    assert!(ban_via_route(&s.authority, &s.group_key, &j2_hex)
        .await
        .is_success());
    drop(armed);
    assert!(
        !egress_happens(
            &s.authority,
            &j2_hex,
            "join_result_chunk",
            Duration::from_secs(2)
        )
        .await,
        "a chunk left after the ban committed"
    );
    Ok(())
}

/// WHY (review r2 P1-2): the inline join-result send happens after the
/// arm's eligibility check. A ban that commits in between must cancel it.
#[tokio::test]
async fn s8a_r2_ban_racing_inline_join_result_egress_sends_nothing() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
    clear_egress(&g.authority);
    let serve = {
        let authority = Arc::clone(&g.authority);
        let joiner = Arc::clone(&g.joiner);
        let stable = g.stable.clone();
        let attempt = g.attempt.clone();
        tokio::spawn(
            async move { serve_result(&authority, &joiner, &stable, &attempt, from).await },
        )
    };
    wait_reached(&armed.gate, "inline result egress").await;
    assert!(ban_via_route(&g.authority, &g.group_key, &g_hex)
        .await
        .is_success());
    drop(armed);
    let _ = tokio::time::timeout(Duration::from_secs(10), serve).await;
    assert!(
        !egress_happens(&g.authority, &g_hex, "join_result", Duration::from_secs(1)).await,
        "the join result left after the ban committed"
    );
    Ok(())
}

/// WHY (review r2 P1-2): a Welcome frame that passed its check must not leave
/// once a ban commits — before r2 the ban's purge ran only after the
/// mutation released its lock, so the frame could leave in between.
#[tokio::test]
async fn s8a_r2_ban_racing_welcome_frame_egress_sends_nothing() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let frame = super::super::join_egress_test_barrier::arm(&j2_hex, "welcome_frame");
    let purge = super::super::join_egress_test_barrier::arm(&j2_hex, "purge");
    clear_egress(&s.authority);
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    wait_reached(&frame.gate, "Welcome frame egress").await;
    let ban = {
        let authority = Arc::clone(&s.authority);
        let group_key = s.group_key.clone();
        let j2_hex = j2_hex.clone();
        tokio::spawn(async move { ban_via_route(&authority, &group_key, &j2_hex).await })
    };
    // The ban has committed once it reaches its purge (or finished).
    tokio::time::timeout(Duration::from_secs(10), async {
        while !(ban.is_finished() || purge.gate.reached()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    drop(frame);
    let leaked = egress_happens(
        &s.authority,
        &j2_hex,
        "welcome_frame",
        Duration::from_millis(500),
    )
    .await;
    drop(purge);
    assert!(ban.await?.is_success());
    assert!(!leaked, "a Welcome frame left after the ban committed");
    Ok(())
}

/// WHY (review r2 P2-3): the removal's purge must belong to the removal's
/// critical section. A purge that runs after the lock is released can erase
/// the artifacts of a LEGITIMATE re-admission that committed in between.
#[tokio::test]
async fn s8a_r2_removal_purge_cannot_erase_a_concurrent_readmission() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    // J2's first attempt ends; it then holds a fresh invite and its signed
    // MemberJoined, ready to be re-admitted after the removal.
    super::super::finalize_join_attempt(
        &s.j2,
        &s.group_key,
        &s.stable,
        &j2_hex,
        &s.j2_attempt,
        super::super::JoinAttemptOutcome::TimedOut,
        super::super::JoinFinalizeGuard::Unlocked,
    )
    .await;
    let link = mint_for(&s.authority, &s.group_key, &s.j2).await?;
    let (status, body) = join(&s.j2, link, Some(owner_pin_of(&s.authority))).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let Some((_, Some(rejoin))) = attempt_of(&s.j2, &s.stable) else {
        panic!("J2 stored its re-join MemberJoined");
    };

    let purge = super::super::join_egress_test_barrier::arm(&j2_hex, "purge");
    let removal = {
        let authority = Arc::clone(&s.authority);
        let group_key = s.group_key.clone();
        let j2_hex = j2_hex.clone();
        tokio::spawn(async move {
            remove_named_group_member(
                State(authority),
                axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                    durable: true,
                }),
                Path((group_key, j2_hex)),
            )
            .await
            .into_response()
            .status()
        })
    };
    wait_reached(&purge.gate, "removal purge").await;
    let readmission = {
        let authority = Arc::clone(&s.authority);
        let sender = s.j2.agent.agent_id();
        tokio::spawn(async move {
            apply_named_group_metadata_event(&authority, rejoin, sender, true, None)
                .await
                .accepted
        })
    };
    // Give the re-admission every chance to commit while the purge waits
    // (it cannot while the removal still holds the group lock).
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !readmission.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    drop(purge);
    assert!(removal.await?.is_success());
    assert!(readmission.await?, "the re-admission is accepted");
    let removed_at = s.base + 3;
    let restaged = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .map(|p| revision_of(&p.event));
    assert!(
        restaged.is_some_and(|revision| revision > Some(removed_at)),
        "the re-admission's staged result survived the removal's purge: {restaged:?}"
    );
    Ok(())
}

/// WHY (review r2 P2-3): a removal applied through the REPLAY entry point
/// (`apply_named_group_metadata_event_inner`, used by the TreeKEM pending
/// replay) purges the removed member's staged artifacts too.
#[tokio::test]
async fn s8a_r2_replayed_member_removal_purges_staged_artifacts() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    // A second daemon over the SAME identity and roster authors the removal
    // (the authority's own signed MemberRemoved, as it arrives on replay).
    let author = super::super::super::home::tests::owned_state(&g.dir, OWNER_SEED).await?;
    let removed = remove_named_group_member(
        State(Arc::clone(&author)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((g.group_key.clone(), g_hex.clone())),
    )
    .await
    .into_response();
    assert!(
        removed.status().is_success(),
        "author: {}",
        removed.status()
    );
    let removal = author
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish witness")
        .iter()
        .filter_map(|(_, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find(|e| {
            matches!(e, NamedGroupMetadataEvent::MemberRemoved { agent_id, .. } if *agent_id == g_hex)
        })
        .expect("the author published the removal");
    assert!(staged(&g.authority, &g.stable, &g_hex).await.is_some());
    let applied = super::super::apply_named_group_metadata_event_inner(
        &g.authority,
        removal,
        g.authority.agent.agent_id(),
        true,
        false,
        None,
    )
    .await;
    assert!(applied.accepted, "the replayed removal applies");
    assert!(
        staged(&g.authority, &g.stable, &g_hex).await.is_none(),
        "a replayed removal must purge the member's staged join result"
    );
    Ok(())
}

/// WHY (review r2 P2-4): the single Welcome listener must keep receiving
/// while a FetchRequest waits on a group lock — otherwise the Offer, Chunk
/// and Complete frames a lock holder may itself be waiting for queue behind
/// it (a dependency cycle).
#[tokio::test]
async fn s8a_r2_welcome_listener_progresses_while_a_group_lock_is_held() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let lock = super::super::group_membership_lock_for_known_group(&s.authority, &s.stable)
        .await
        .expect("known group");
    let held = lock.lock().await;
    let dispatched = tokio::time::timeout(
        Duration::from_secs(2),
        super::super::dispatch_welcome_blob_message(
            &s.authority,
            &s.j2.agent.agent_id(),
            WelcomeBlobMessage::FetchRequest {
                group_id: s.stable.clone(),
                welcome_id: welcome_id.clone(),
            },
        ),
    )
    .await;
    assert!(
        dispatched.is_ok(),
        "the listener blocked on a FetchRequest waiting for the group lock"
    );
    // Receive-side frames still flow (an unsolicited Offer is ignored).
    let offer = tokio::time::timeout(
        Duration::from_secs(2),
        super::super::dispatch_welcome_blob_message(
            &s.authority,
            &s.j2.agent.agent_id(),
            WelcomeBlobMessage::Offer {
                group_id: s.stable.clone(),
                welcome_id: "ab".repeat(32),
                byte_len: 1,
                chunk_size: x0x::files::DEFAULT_CHUNK_SIZE,
                total_chunks: 1,
                blake3_hex: "ab".repeat(32),
            },
        ),
    )
    .await;
    assert!(
        offer.is_ok(),
        "a receive-side frame queued behind the fetch"
    );
    drop(held);
    // The fetch completes once the lock is free: its stream hands a Welcome
    // frame to the transport. (r5 G9: a finished stream removes its own
    // handle, so the stream map is no longer a durable witness.)
    let j2_hex = hex_of(&s.j2);
    assert!(
        transport_seen(&s.authority, &j2_hex, "welcome_frame").await,
        "the parked fetch never streamed once the lock was free"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 3 (ADR 0107 accepted, D57): line 64 conformance. OwnerCertified
// serving requires the roster-embedded certificate to verify AND the
// recipient's current roster verdict to be Clean; DigestPending, InGrace and
// Failed verdicts fail closed.
// ---------------------------------------------------------------------------

/// The recipient's current roster verdict on the authority, from the same
/// ladder the seal paths use (`GroupInfo::owner_cert_verdict`) with the
/// current evidence (revocation set, clock, announce/discovery state).
async fn roster_verdict(
    authority: &AppState,
    group_key: &str,
    member_hex: &str,
) -> Option<x0x::groups::owner_cert::MemberCertStatus> {
    let info = authority
        .named_groups
        .read()
        .await
        .get(group_key)
        .cloned()
        .expect("authority group");
    let evidence = super::super::owner_cert_evidence_for(authority, &[member_hex]).await;
    info.clone()
        .owner_cert_verdict(&evidence)
        .per_member
        .get(member_hex)
        .cloned()
}

/// WHY (ADR 0107 line 64; line 110 for the control): an #842 inline-certified
/// first join with no announce has a CLEAN roster verdict at serve time and
/// is served on both paths. A recipient whose verdict is DigestPending,
/// InGrace (here: stale evidence mid-rotation, the embedded certificate
/// still verifying) or Failed (an announced certificate that does not chain
/// to the owner, the embedded one still verifying) is refused on BOTH paths,
/// each exercised on an intact cache.
#[tokio::test]
async fn s8a_r3_non_clean_roster_verdicts_are_refused_on_both_paths() -> anyhow::Result<()> {
    use x0x::groups::owner_cert::MemberCertStatus;
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let j2_id = s.j2.agent.agent_id();
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let owner_id = owner_kp.user_id();
    let roster = s
        .authority
        .named_groups
        .read()
        .await
        .get(&s.group_key)
        .cloned()
        .expect("authority group");
    let result = staged(&s.authority, &s.stable, &j2_hex)
        .await
        .expect("staged");
    let welcome = s
        .authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .cloned()
        .expect("staged Welcome");
    let embedded = roster
        .members_v2
        .get(&j2_hex)
        .and_then(|m| m.certificate.clone())
        .expect("the #842 seal embedded J2's inline certificate");

    let both_paths = |ctx: &'static str| {
        let s = &s;
        let result = result.clone();
        let welcome = welcome.clone();
        let welcome_id = welcome_id.clone();
        let j2_hex = j2_hex.clone();
        async move {
            restore_staged_artifacts(
                &s.authority,
                &s.stable,
                &j2_hex,
                &result,
                &welcome_id,
                &welcome,
            )
            .await;
            let result_served =
                serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
                    .await
                    .is_some();
            restore_staged_artifacts(
                &s.authority,
                &s.stable,
                &j2_hex,
                &result,
                &welcome_id,
                &welcome,
            )
            .await;
            let welcome_served = serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await;
            (ctx, result_served, welcome_served)
        }
    };

    // Control (ADR 0107 line 110): the #842 first join, announce absent.
    assert!(s
        .authority
        .agent
        .identity_discovery_cache()
        .read()
        .await
        .get(&j2_id)
        .is_none());
    let control = roster_verdict(&s.authority, &s.group_key, &j2_hex).await;
    assert_eq!(
        control,
        Some(MemberCertStatus::Clean),
        "an #842 inline-cert first join with no announce is Clean at serve time"
    );
    let (ctx, result_served, welcome_served) = both_paths("#842 control").await;
    assert!(
        result_served && welcome_served,
        "[{ctx}] served on both paths"
    );

    let rotated = x0x::identity::AgentCertificate::issue_with_expiry(
        &owner_kp,
        &keypair(&s.j2_kp)?,
        Some(x0x::groups::owner_cert::restore_clock_now() + 365 * 86_400),
    )?;
    let foreign_owner = x0x::identity::UserKeypair::generate()?;
    let foreign = x0x::identity::AgentCertificate::issue(&foreign_owner, &keypair(&s.j2_kp)?)?;
    let mut leaks = Vec::new();
    for case in ["digest_pending", "in_grace_rotation", "failed_verdict"] {
        s.authority
            .named_groups
            .write()
            .await
            .insert(s.group_key.clone(), roster.clone());
        s.authority
            .agent
            .identity_discovery_cache()
            .write()
            .await
            .remove(&j2_id);
        match case {
            "digest_pending" => {
                if let Some(seat) = s
                    .authority
                    .named_groups
                    .write()
                    .await
                    .get_mut(&s.group_key)
                    .and_then(|info| info.members_v2.get_mut(&j2_hex))
                {
                    seat.certificate = None;
                }
            }
            "in_grace_rotation" => {
                // J2 announced a ROTATED certificate whose bytes are still
                // in flight: the embedded one is stale but still verifies.
                let digest = x0x::announce_v3::cert_digest(&Some(owner_id), &Some(rotated.clone()));
                insert_discovery_entry(&s.authority, j2_id, Some(owner_id), None, Some(digest))
                    .await;
            }
            _ => {
                let digest =
                    x0x::announce_v3::cert_digest(&foreign.user_id().ok(), &Some(foreign.clone()));
                insert_discovery_entry(
                    &s.authority,
                    j2_id,
                    foreign.user_id().ok(),
                    Some(foreign.clone()),
                    Some(digest),
                )
                .await;
            }
        }
        let verdict = roster_verdict(&s.authority, &s.group_key, &j2_hex).await;
        let shape_ok = match case {
            "digest_pending" => verdict == Some(MemberCertStatus::DigestPending),
            "in_grace_rotation" => matches!(verdict, Some(MemberCertStatus::InGrace { .. })),
            _ => matches!(verdict, Some(MemberCertStatus::Failed { .. })),
        };
        assert!(shape_ok, "[{case}] fixture verdict: {verdict:?}");
        if case != "digest_pending" {
            assert!(
                x0x::groups::owner_cert::verify_cert_against_owner(
                    &owner_id,
                    &j2_hex,
                    &embedded,
                    false,
                    x0x::groups::owner_cert::restore_clock_now(),
                )
                .is_ok(),
                "[{case}] the embedded certificate alone still verifies"
            );
        }
        let (ctx, result_served, welcome_served) = both_paths(case).await;
        if result_served {
            leaks.push(format!("{ctx}: FetchRequest arm served a join result"));
        }
        if welcome_served {
            leaks.push(format!("{ctx}: Welcome path streamed key material"));
        }
    }
    assert!(
        leaks.is_empty(),
        "recipients with a non-Clean roster verdict were served: {leaks:#?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 4 (Codex review of 42dea10, ADR 0107 accepted): eligibility and
// expiry are enforced at transport admission; join artifacts never take a
// delivery path that can hand their bytes to a detached gossip retry; a
// copied blob dies with its original; Welcome fetch admission is fair; and
// aborted or finished egress leaves no bookkeeping behind.
// ---------------------------------------------------------------------------

async fn withdraw_via_route(authority: &Arc<AppState>, group_key: &str) -> StatusCode {
    withdraw_group_state(
        State(Arc::clone(authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_key.to_string()),
    )
    .await
    .into_response()
    .status()
}

/// WHY (review r2 P1-1): revocation has no mutation event, so the only
/// place it can be enforced for an in-flight serve is the transport's own
/// admission. A recipient revoked AFTER the egress task's final check but
/// BEFORE its bytes are handed to the transport gets nothing — on the
/// inline result, Welcome frame and result-chunk paths.
#[tokio::test]
async fn s8a_r4_revocation_landing_before_transport_admission_sends_nothing() -> anyhow::Result<()>
{
    let mut leaks = Vec::new();
    // Inline join result (GSS).
    {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        let from = remnant_revision(&g.joiner, &g.group_key).await;
        let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
        clear_egress(&g.authority);
        let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
        wait_reached(&armed.gate, "inline result").await;
        let kp = g.joiner.agent.identity().agent_keypair().to_bytes();
        revoke_agent(&g.authority, &kp).await?;
        drop(armed);
        if egress_happens(&g.authority, &g_hex, "join_result", Duration::from_secs(1)).await {
            leaks.push("inline join result");
        }
    }
    // Welcome frame and result chunk (Home).
    for (point, what) in [
        ("welcome_frame", "Welcome frame"),
        ("join_result_chunk", "join-result chunk"),
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let reference = if point == "join_result_chunk" {
            Some(staged_join_result_blob(&s).await?)
        } else {
            None
        };
        let armed = super::super::join_egress_test_barrier::arm(&j2_hex, point);
        clear_egress(&s.authority);
        match &reference {
            Some(reference) => fetch_chunk(&s, reference).await,
            None => {
                let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
                assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
            }
        }
        wait_reached(&armed.gate, what).await;
        revoke_agent(&s.authority, &s.j2_kp).await?;
        drop(armed);
        if egress_happens(&s.authority, &j2_hex, point, Duration::from_secs(1)).await {
            leaks.push(what);
        }
    }
    assert!(
        leaks.is_empty(),
        "bytes were handed to the transport after the recipient was revoked: {leaks:?}"
    );
    Ok(())
}

/// WHY (review r2 P1-1): withdrawal (group deletion) is a terminal mutation:
/// it must quiesce ALL of the group's in-flight join-artifact egress before
/// it commits, and nothing may leave afterwards.
#[tokio::test]
async fn s8a_r4_withdrawal_landing_before_transport_admission_sends_nothing() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
    clear_egress(&g.authority);
    let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
    wait_reached(&armed.gate, "inline result").await;
    let withdrawn = tokio::time::timeout(
        Duration::from_secs(10),
        withdraw_via_route(&g.authority, &g.group_key),
    )
    .await?;
    assert!(withdrawn.is_success(), "withdraw: {withdrawn}");
    drop(armed);
    assert!(
        !egress_happens(&g.authority, &g_hex, "join_result", Duration::from_secs(1)).await,
        "the join result left after the group was withdrawn"
    );
    Ok(())
}

/// WHY (review r2 P1-2): the gossip inbox's stranded-publish retry
/// (saorsa-gossip-pubsub 0.5.86) runs DETACHED, beyond any abort of ours.
/// Join artifacts — the inline result, Welcome frames and result chunks —
/// must only ever be handed to a delivery path that cannot reach gossip.
#[tokio::test]
async fn s8a_r4_join_artifacts_never_take_a_gossip_capable_path() -> anyhow::Result<()> {
    let paths = |state: &AppState, recipient: &str| -> Vec<(&'static str, bool)> {
        state
            .named_group_test_recorders
            .join_artifact_delivery_paths
            .lock()
            .expect("delivery-path witness")
            .iter()
            .filter(|(to, _, _)| to == recipient)
            .map(|(_, kind, gossip)| (*kind, *gossip))
            .collect()
    };
    let wait_for = |state: Arc<AppState>, recipient: String, kind: &'static str| async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if state
                    .named_group_test_recorders
                    .join_artifact_delivery_paths
                    .lock()
                    .expect("delivery-path witness")
                    .iter()
                    .any(|(to, k, _)| *to == recipient && *k == kind)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    };
    let mut observed = Vec::new();
    {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        let from = remnant_revision(&g.joiner, &g.group_key).await;
        assert!(
            serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from)
                .await
                .is_some()
        );
        assert!(
            wait_for(Arc::clone(&g.authority), g_hex.clone(), "join_result").await,
            "the inline result reached a transport"
        );
        observed.extend(paths(&g.authority, &g_hex));
    }
    {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
        assert!(
            wait_for(Arc::clone(&s.authority), j2_hex.clone(), "welcome_frame").await,
            "a Welcome frame reached a transport"
        );
        let reference = staged_join_result_blob(&s).await?;
        fetch_chunk(&s, &reference).await;
        assert!(
            wait_for(
                Arc::clone(&s.authority),
                j2_hex.clone(),
                "join_result_chunk"
            )
            .await,
            "a result chunk reached a transport"
        );
        observed.extend(paths(&s.authority, &j2_hex));
    }
    let gossip_capable: Vec<_> = observed.iter().filter(|(_, gossip)| *gossip).collect();
    assert!(
        gossip_capable.is_empty(),
        "join artifacts were handed to a gossip-capable delivery path: {gossip_capable:?}"
    );
    Ok(())
}

/// WHY (review r2 P2-4, ADR 0107 line 70): a staged control-blob copy of a
/// join result is bound to the ORIGINAL artifact and its deadline. Once the
/// original expires — whether it expires after the copy was staged, or the
/// copy was staged moments before the deadline — no chunk is served.
#[tokio::test]
async fn s8a_r4_copied_join_result_blob_expires_with_the_original() -> anyhow::Result<()> {
    let ttl = super::super::PENDING_JOIN_RESULT_TTL;
    let mut leaks = Vec::new();
    for case in [
        "original_expires_after_staging",
        "staged_just_before_deadline",
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let key = join_result_key(&s.stable, &j2_hex);
        if case == "staged_just_before_deadline" {
            if let Some(p) = s.authority.pending_join_results.write().await.get_mut(&key) {
                p.created_at = Instant::now()
                    .checked_sub(ttl - Duration::from_millis(1500))
                    .expect("monotonic clock far enough from boot");
            }
        }
        let reference = staged_join_result_blob(&s).await?;
        match case {
            "original_expires_after_staging" => {
                if let Some(p) = s.authority.pending_join_results.write().await.get_mut(&key) {
                    p.created_at = Instant::now()
                        .checked_sub(ttl + Duration::from_secs(1))
                        .expect("monotonic clock far enough from boot");
                }
            }
            _ => tokio::time::sleep(Duration::from_millis(2000)).await,
        }
        clear_egress(&s.authority);
        fetch_chunk(&s, &reference).await;
        if egress_happens(
            &s.authority,
            &j2_hex,
            "join_result_chunk",
            Duration::from_secs(1),
        )
        .await
        {
            leaks.push(case);
        }
    }
    assert!(
        leaks.is_empty(),
        "a copied join-result blob outlived the original's deadline: {leaks:?}"
    );
    Ok(())
}

/// WHY (review r2 P2-5): Welcome fetch admission is validated, coalesced and
/// fair. Duplicate and bogus FetchRequests aimed at ONE group whose lock is
/// held must not use up the slots another group's legitimate fetch needs.
#[tokio::test]
async fn s8a_r4_welcome_fetch_admission_is_fair_across_groups() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    // A second group on the same authority with a staged Welcome for J1.
    let other_group = "c4".repeat(32);
    {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "other".to_string(),
            String::new(),
            s.authority_id,
            other_group.clone(),
            x0x::groups::GroupPolicy::default(),
        );
        info.add_member(
            hex_of(&s.j1),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(s.authority_id.as_bytes())),
            None,
        );
        s.authority
            .named_groups
            .write()
            .await
            .insert(other_group.clone(), info);
    }
    let other_bytes = b"the other group's Welcome".to_vec();
    let other_welcome = super::super::welcome_id_for_bytes(&other_bytes);
    s.authority.pending_welcomes.write().await.insert(
        other_welcome.clone(),
        super::super::PendingWelcome {
            group_id: other_group.clone(),
            joiner_agent: hex_of(&s.j1),
            bytes: other_bytes,
            created_at: Instant::now(),
        },
    );

    let lock = super::super::group_membership_lock_for_known_group(&s.authority, &s.stable)
        .await
        .expect("known group");
    let held = lock.lock().await;
    let j2_id = s.j2.agent.agent_id();
    for n in 0..24u32 {
        let id = if n % 3 == 0 {
            welcome_id.clone()
        } else {
            hex::encode(blake3::hash(&n.to_le_bytes()).as_bytes())
        };
        super::super::dispatch_welcome_blob_message(
            &s.authority,
            &j2_id,
            WelcomeBlobMessage::FetchRequest {
                group_id: s.stable.clone(),
                welcome_id: id,
            },
        )
        .await;
    }
    super::super::dispatch_welcome_blob_message(
        &s.authority,
        &s.j1.agent.agent_id(),
        WelcomeBlobMessage::FetchRequest {
            group_id: other_group.clone(),
            welcome_id: other_welcome.clone(),
        },
    )
    .await;
    // The other group's fetch streams its Welcome (r5 G9: a finished
    // stream leaves the stream map, so observe the transport witness).
    let j1_hex = hex_of(&s.j1);
    let admitted = transport_seen(&s.authority, &j1_hex, "welcome_frame").await;
    drop(held);
    assert!(
        admitted,
        "another group's legitimate Welcome fetch was starved by one locked group's flood"
    );
    Ok(())
}

/// WHY (review r2 P3): a staging task cancelled by a removal or ban releases
/// its per-recipient staging guard itself (RAII), not only on a later
/// acquire.
#[tokio::test]
async fn s8a_r4_aborted_staging_releases_its_staging_guard() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_stage");
    assert!(
        serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
            .await
            .is_some()
    );
    wait_reached(&armed.gate, "staging").await;
    let key = (s.stable.clone(), s.j2.agent.agent_id());
    assert!(s
        .authority
        .join_result_staging_guards
        .lock()
        .expect("staging guards")
        .contains_key(&key));
    assert!(ban_via_route(&s.authority, &s.group_key, &j2_hex)
        .await
        .is_success());
    drop(armed);
    assert!(
        !s.authority
            .join_result_staging_guards
            .lock()
            .expect("staging guards")
            .contains_key(&key),
        "the aborted staging task left its staging guard behind"
    );
    Ok(())
}

/// WHY (review r2 registry hygiene): a finished egress task leaves the
/// egress registry when it completes, not only when a later egress spawns.
#[tokio::test]
async fn s8a_r4_finished_egress_tasks_leave_the_registry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    assert!(
        serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from)
            .await
            .is_some()
    );
    let key = (g.stable.clone(), g_hex.clone());
    // The GSS fixture's class-K share deliveries (two writes, 8 s apart)
    // share this key.
    let finished = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let done = g
                .authority
                .join_artifact_egress
                .lock()
                .expect("egress registry")
                .get(&key)
                .is_none_or(|tasks| tasks.iter().all(tokio::task::JoinHandle::is_finished));
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(finished.is_ok(), "the egress task never finished");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !g.authority
            .join_artifact_egress
            .lock()
            .expect("egress registry")
            .contains_key(&key),
        "a finished egress task stayed in the registry"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 5 (lifecycle note r3, `docs/design/join-artifact-serving-lifecycle.md`):
// the class-R transport admits every physical exchange (G3), checks the
// resolved machine (G2), is bounded by per-exchange and per-task deadlines,
// and records DM metrics (G14).
// ---------------------------------------------------------------------------

fn transports_for(state: &AppState, recipient: &str) -> Vec<(&'static str, &'static str)> {
    state
        .named_group_test_recorders
        .join_artifact_transports
        .lock()
        .expect("transport witness")
        .iter()
        .filter(|(to, _, _)| to == recipient)
        .map(|(_, kind, transport)| (*kind, *transport))
        .collect()
}

async fn transport_seen(state: &AppState, recipient: &str, kind: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !transports_for(state, recipient)
            .iter()
            .any(|(k, _)| *k == kind)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// Make the authority resolve `recipient` to its REAL machine through the
/// announce/discovery cache, as it would for an announced peer (the same
/// ingest a verified identity announcement takes).
async fn pin_recipient_machine(authority: &AppState, recipient: &AppState) {
    let agent_id = recipient.agent.agent_id();
    authority
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            agent_id,
            machine_id: recipient.agent.machine_id(),
            user_id: None,
            self_name: None,
            addresses: Vec::new(),
            announced_at: 0,
            last_seen: 0,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: None,
        })
        .await;
}

/// Self-revoke `owner`'s MACHINE (not its agent) in the authority's
/// revocation set.
async fn revoke_machine(authority: &AppState, owner: &AppState) -> anyhow::Result<()> {
    let machine = owner.agent.identity().machine_keypair();
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Machine(owner.agent.machine_id()),
        machine.public_key(),
        machine.secret_key(),
        x0x::groups::owner_cert::restore_clock_now(),
        Some("adr0107 r5 machine revocation".to_string()),
    )?;
    authority
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)?;
    Ok(())
}

async fn age_staged_result(state: &AppState, key: &str, remaining: Duration) {
    if let Some(p) = state.pending_join_results.write().await.get_mut(key) {
        p.created_at = Instant::now()
            .checked_sub(super::super::PENDING_JOIN_RESULT_TTL - remaining)
            .expect("monotonic clock far enough from boot");
    }
}

/// WHY (note r3 G3): pinned ant-quic's ACK-v2 send retries internally and
/// x0x's X0X-0053 path reissues on `Replaced`, so a write can happen with no
/// admission at all. Every class-R kind must take the single-exchange
/// transport, where each physical write is admitted at the stream seam.
#[tokio::test]
async fn s8a_r5_g3_recovery_responses_take_one_admitted_exchange() -> anyhow::Result<()> {
    let mut observed = Vec::new();
    {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        let from = remnant_revision(&g.joiner, &g.group_key).await;
        let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
        assert!(transport_seen(&g.authority, &g_hex, "join_result").await);
        observed.extend(transports_for(&g.authority, &g_hex));
    }
    {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
        assert!(transport_seen(&s.authority, &j2_hex, "welcome_frame").await);
        let reference = staged_join_result_blob(&s).await?;
        fetch_chunk(&s, &reference).await;
        assert!(transport_seen(&s.authority, &j2_hex, "join_result_chunk").await);
        observed.extend(transports_for(&s.authority, &j2_hex));
    }
    let unadmitted: Vec<_> = observed
        .iter()
        .filter(|(_, transport)| *transport != "pinned_single_exchange")
        .collect();
    assert!(
        unadmitted.is_empty(),
        "class-R exchanges took a transport with unadmitted resends: {unadmitted:?}"
    );
    Ok(())
}

/// WHY (note r3 G2): the guard checks the recipient AGENT; the transport
/// resolves a MACHINE. A machine revoked after the egress task's checks but
/// before the write must get nothing, on the same admission as the agent.
#[tokio::test]
async fn s8a_r5_g2_machine_revocation_before_admission_sends_nothing() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    // Control: the pinned, unrevoked machine is served.
    clear_egress(&g.authority);
    let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
    assert!(
        egress_happens(&g.authority, &g_hex, "join_result", Duration::from_secs(5)).await,
        "control: the eligible recipient on an unrevoked machine is served"
    );
    // The machine is revoked between the task's checks and the write.
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
    clear_egress(&g.authority);
    let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
    wait_reached(&armed.gate, "inline result").await;
    revoke_machine(&g.authority, &g.joiner).await?;
    drop(armed);
    assert!(
        !egress_happens(&g.authority, &g_hex, "join_result", Duration::from_secs(1)).await,
        "bytes were handed to the transport for a revoked machine"
    );
    Ok(())
}

/// WHY (note r3, section 2.7 item 6): without the ACK-v2 exchange there is
/// no whole-exchange timeout. A stalled exchange (here: parked inside the
/// exchange) must be cut by the artifact's deadline, and its egress task
/// must end, on the inline, Welcome and chunk paths.
#[tokio::test]
async fn s8a_r5_deadline_cuts_stalled_exchanges() -> anyhow::Result<()> {
    let mut outlived = Vec::new();
    let all_finished = |state: &AppState, key: &(String, String)| {
        state
            .join_artifact_egress
            .lock()
            .expect("egress registry")
            .get(key)
            .is_none_or(|tasks| tasks.iter().all(tokio::task::JoinHandle::is_finished))
    };
    // Inline result.
    {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        let from = remnant_revision(&g.joiner, &g.group_key).await;
        age_staged_result(
            &g.authority,
            &join_result_key(&g.stable, &g_hex),
            Duration::from_millis(1500),
        )
        .await;
        let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
        let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
        wait_reached(&armed.gate, "inline result").await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        // The GSS fixture's class-K share deliveries share this registry
        // key; check the inline-result task itself.
        if !lifecycle_of(&g.authority)
            .iter()
            .any(|e| *e == format!("egress_ended:{}:{}:join_result", g.stable, g_hex))
        {
            outlived.push("inline join result");
        }
        drop(armed);
    }
    // Result chunk (the copy shares the original's deadline).
    {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        age_staged_result(
            &s.authority,
            &join_result_key(&s.stable, &j2_hex),
            Duration::from_millis(2500),
        )
        .await;
        let reference = staged_join_result_blob(&s).await?;
        let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_chunk");
        fetch_chunk(&s, &reference).await;
        wait_reached(&armed.gate, "result chunk").await;
        tokio::time::sleep(Duration::from_millis(3000)).await;
        if !all_finished(&s.authority, &(s.stable.clone(), j2_hex.clone())) {
            outlived.push("join-result chunk");
        }
        drop(armed);
    }
    // Welcome stream.
    {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        if let Some(w) = s
            .authority
            .pending_welcomes
            .write()
            .await
            .get_mut(&welcome_id)
        {
            w.created_at = Instant::now()
                .checked_sub(super::super::PENDING_WELCOME_TTL - Duration::from_millis(1500))
                .expect("monotonic clock far enough from boot");
        }
        let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "welcome_frame");
        assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
        wait_reached(&armed.gate, "Welcome frame").await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let stream_live = s
            .authority
            .pending_welcome_streams
            .lock()
            .await
            .as_ref()
            .and_then(|streams| streams.get(&welcome_id).map(|h| !h.is_finished()))
            .unwrap_or(false);
        if stream_live {
            outlived.push("Welcome stream");
        }
        drop(armed);
    }
    assert!(
        outlived.is_empty(),
        "a stalled exchange outlived its artifact's deadline: {outlived:?}"
    );
    Ok(())
}

/// WHY (note r3 G14): the class-R transport is a logical DM send and must
/// show up in the DM metrics like every other send.
#[tokio::test]
async fn s8a_r5_g14_recovery_response_sends_record_dm_metrics() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    // Let the fixture's own background deliveries (the +8 s delayed sends)
    // finish, so the delta below is this serve's alone.
    let settle_started = tokio::time::Instant::now();
    let mut last = g
        .authority
        .agent
        .direct_messaging()
        .diagnostics_snapshot()
        .stats
        .outgoing_send_total;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = g
            .authority
            .agent
            .direct_messaging()
            .diagnostics_snapshot()
            .stats
            .outgoing_send_total;
        if now == last && settle_started.elapsed() >= Duration::from_secs(9) {
            break;
        }
        assert!(
            settle_started.elapsed() < Duration::from_secs(30),
            "DM metrics never settled"
        );
        last = now;
    }
    let before = g.authority.agent.direct_messaging().diagnostics_snapshot();
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    let _ = serve_result(&g.authority, &g.joiner, &g.stable, &g.attempt, from).await;
    assert!(transport_seen(&g.authority, &g_hex, "join_result").await);
    let recorded = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let now = g.authority.agent.direct_messaging().diagnostics_snapshot();
            if now.stats.outgoing_send_total > before.stats.outgoing_send_total
                && now.stats.outgoing_send_failed + now.stats.outgoing_send_succeeded
                    > before.stats.outgoing_send_failed + before.stats.outgoing_send_succeeded
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        recorded.is_ok(),
        "the class-R send was not recorded in the DM metrics"
    );
    Ok(())
}

/// WHY (note r3 G9): a Welcome stream that ends on its own (here: its
/// chunk send fails in process) leaves `pending_welcome_streams` itself,
/// not only when a later fetch, stop or wipe replaces it.
#[tokio::test]
async fn s8a_r5_g9_finished_welcome_stream_leaves_its_handle() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let gone = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let present = s
                .authority
                .pending_welcome_streams
                .lock()
                .await
                .as_ref()
                .is_some_and(|streams| streams.contains_key(&welcome_id));
            if !present {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        gone.is_ok(),
        "a finished Welcome stream left its handle behind"
    );
    Ok(())
}

/// WHY (note r3 G9): a Welcome stream that panics releases its ACK slot and
/// its stream handle, generation-safely, and the panic is reported.
#[tokio::test]
async fn s8a_r5_g9_panicking_welcome_stream_releases_its_bookkeeping() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    super::super::handle_welcome_fetch_request_via(
        &s.authority,
        &s.j2.agent.agent_id(),
        s.stable.clone(),
        welcome_id.clone(),
        |msg: WelcomeBlobMessage| async move {
            if matches!(msg, WelcomeBlobMessage::Chunk { .. }) {
                panic!("injected Welcome transport panic");
            }
            Ok(())
        },
    )
    .await;
    let released = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let stream = s
                .authority
                .pending_welcome_streams
                .lock()
                .await
                .as_ref()
                .is_some_and(|streams| streams.contains_key(&welcome_id));
            let ack = s
                .authority
                .pending_welcome_acks
                .read()
                .await
                .contains_key(&welcome_id);
            if !stream && !ack {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "a panicking Welcome stream left its ACK slot or stream handle behind"
    );
    Ok(())
}

fn lifecycle_of(state: &AppState) -> Vec<String> {
    state
        .named_group_test_recorders
        .join_artifact_lifecycle
        .lock()
        .expect("lifecycle witness")
        .clone()
}

/// WHY (note r3 G4): withdrawal is a terminal mutation. Before it commits
/// the tombstone it must stop ALL of the group's in-flight egress — every
/// registered task and every Welcome stream, for every recipient — and
/// await each one, so nothing is still running when the commit lands.
#[tokio::test]
async fn s8a_r5_g4_withdrawal_quiesces_all_group_egress_before_its_commit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    // A parked chunk egress (registered) and a parked Welcome stream.
    let reference = staged_join_result_blob(&s).await?;
    let chunk = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_chunk");
    fetch_chunk(&s, &reference).await;
    wait_reached(&chunk.gate, "result chunk").await;
    let frame = super::super::join_egress_test_barrier::arm(&j2_hex, "welcome_frame");
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    wait_reached(&frame.gate, "Welcome frame").await;
    s.authority
        .named_group_test_recorders
        .join_artifact_lifecycle
        .lock()
        .expect("lifecycle witness")
        .clear();
    let withdrawn = tokio::time::timeout(
        Duration::from_secs(10),
        withdraw_via_route(&s.authority, &s.group_key),
    )
    .await?;
    assert!(withdrawn.is_success(), "withdraw: {withdrawn}");
    let events = lifecycle_of(&s.authority);
    let commit = events
        .iter()
        .position(|e| e.starts_with("tombstone_persist:"))
        .expect("the withdrawal committed its tombstone");
    let chunk_ended = events
        .iter()
        .position(|e| *e == format!("egress_ended:{}:{}:join_result_chunk", s.stable, j2_hex));
    let stream_ended = events
        .iter()
        .position(|e| *e == format!("welcome_stream_ended:{welcome_id}"));
    drop(chunk);
    drop(frame);
    let mut late = Vec::new();
    if chunk_ended.is_none_or(|at| at > commit) {
        late.push("registered chunk egress");
    }
    if stream_ended.is_none_or(|at| at > commit) {
        late.push("Welcome stream");
    }
    assert!(
        late.is_empty(),
        "egress was still running when the withdrawal committed: {late:?} (events: {events:?})"
    );
    Ok(())
}

/// WHY (note r3 G5): a local drop of the group (here the production delete
/// path a non-Active TreeKEM leave uses) stops every in-flight egress of
/// the group, awaited, and purges its staged originals and copies under
/// every spelling, instead of leaving them to expire at the TTL.
#[tokio::test]
async fn s8a_r5_g5_local_drop_quiesces_and_purges_the_groups_join_artifacts() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let reference = staged_join_result_blob(&s).await?;
    let chunk = super::super::join_egress_test_barrier::arm(&j2_hex, "join_result_chunk");
    fetch_chunk(&s, &reference).await;
    wait_reached(&chunk.gate, "result chunk").await;
    s.authority
        .named_group_test_recorders
        .join_artifact_lifecycle
        .lock()
        .expect("lifecycle witness")
        .clear();
    let dropped = tokio::time::timeout(
        Duration::from_secs(10),
        super::super::tests::drop_local_named_group_state_for_test(
            &s.authority,
            &s.group_key,
            Some(&s.stable),
            "adr0107_r5_local_drop",
        ),
    )
    .await?;
    assert!(dropped, "the local drop committed");
    let mut left = Vec::new();
    if !lifecycle_of(&s.authority)
        .iter()
        .any(|e| *e == format!("egress_ended:{}:{}:join_result_chunk", s.stable, j2_hex))
    {
        left.push("a registered chunk egress kept running");
    }
    let aliases = [s.stable.clone(), s.group_key.clone()];
    if s.authority
        .pending_join_results
        .read()
        .await
        .keys()
        .any(|key| aliases.iter().any(|a| key.starts_with(&format!("{a}:"))))
    {
        left.push("staged join results");
    }
    if s.authority
        .pending_welcomes
        .read()
        .await
        .get(&welcome_id)
        .is_some()
    {
        left.push("staged Welcome");
    }
    if !s
        .authority
        .control_blobs
        .staged_join_result_refs_for_test(&j2_hex)
        .is_empty()
    {
        left.push("staged join-result copy");
    }
    drop(chunk);
    assert!(
        left.is_empty(),
        "the local drop left join-artifact serving state behind: {left:?}"
    );
    Ok(())
}

fn serves_to(state: &AppState, recipient: &str) -> usize {
    state
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .iter()
        .filter(|(to, _, _)| to == recipient)
        .count()
}

/// WHY (note r3 G7): the join-result listener is shared by every group. A
/// `FetchRequest` (selection, owner-certificate retry) must never hold the
/// listener while it waits for one group's lock, and a flood of duplicate
/// fetches for one recipient coalesces into ONE in-flight handler.
#[tokio::test]
async fn s8a_r5_g7_join_result_listener_never_waits_on_a_group_lock() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let fetch = || JoinResultMessage::FetchRequest {
        group_id: s.stable.clone(),
        member_agent_id: j2_hex.clone(),
        from_revision: Some(s.base),
        base_state_hash: None,
        accepts_refusal: true,
        accepts_control_blob_ref: true,
        attempt_id: Some(s.j2_attempt.clone()),
    };
    s.authority
        .named_group_test_recorders
        .join_result_serves
        .lock()
        .expect("serve witness")
        .clear();
    let lock = super::super::group_membership_lock_for_known_group(&s.authority, &s.stable)
        .await
        .expect("known group");
    let held = lock.lock().await;
    let mut blocked = 0usize;
    for _ in 0..12 {
        let dispatched = tokio::time::timeout(
            Duration::from_millis(500),
            super::super::dispatch_join_result_message(
                &s.authority,
                &s.j2.agent.agent_id(),
                true,
                fetch(),
            ),
        )
        .await;
        if dispatched.is_err() {
            blocked += 1;
            break;
        }
    }
    drop(held);
    assert_eq!(
        blocked, 0,
        "the join-result listener blocked on a FetchRequest waiting for the group lock"
    );
    // The fetches coalesce: exactly one serve once the lock is free.
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        while serves_to(&s.authority, &j2_hex) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(served.is_ok(), "the parked fetch was never served");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        serves_to(&s.authority, &j2_hex),
        1,
        "duplicate fetches for one recipient were not coalesced"
    );
    Ok(())
}

/// WHY (note r3 G8): chunk fetches for one group whose lock is held —
/// duplicates and out-of-range sequences — must not take the shared chunk
/// slots another group's legitimate chunk fetch needs. Fetches are
/// validated (the copy is staged, the sequence exists) before they take a
/// slot, coalesce per chunk, and each group gets only its share.
#[tokio::test]
async fn s8a_r5_g8_chunk_fetch_admission_is_validated_and_fair() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    // Group B's member: a fresh agent with no other staged copies.
    let b_member = x0x::identity::AgentKeypair::generate()?.agent_id();
    let j1_hex = hex::encode(b_member.as_bytes());
    // Group A: J2's real staged copy.
    let reference_a = staged_join_result_blob(&s).await?;
    // Group B (same authority): its member is Active and has a staged
    // original and a bound copy of it.
    let group_b = "c5".repeat(32);
    {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "b".to_string(),
            String::new(),
            s.authority_id,
            group_b.clone(),
            x0x::groups::GroupPolicy::default(),
        );
        info.add_member(
            j1_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(s.authority_id.as_bytes())),
            None,
        );
        s.authority
            .named_groups
            .write()
            .await
            .insert(group_b.clone(), info);
    }
    let staged_at = Instant::now();
    s.authority.pending_join_results.write().await.insert(
        join_result_key(&group_b, &j1_hex),
        super::super::PendingJoinResult {
            event: s.j1_add.clone(),
            head_attestation: None,
            created_at: staged_at,
        },
    );
    let reference_b = super::super::control_blob::stage_reference(
        &s.authority.control_blobs,
        &s.authority.agent,
        &b_member,
        super::super::control_blob::ControlBlobKind::JoinResult,
        &group_b,
        Some("adr0107-r5-g8-attempt"),
        vec![0x5b; x0x::dm::MAX_PAYLOAD_BYTES + 4096],
        Some(super::super::control_blob::StagedOrigin {
            staged_at,
            deadline: staged_at + super::super::PENDING_JOIN_RESULT_TTL,
        }),
    )
    .map_err(|e| anyhow::anyhow!("stage group B copy: {e}"))?;
    // Control: with no flood, group B's chunk is served.
    clear_egress(&s.authority);
    super::super::control_blob::handle_control_blob_message(
        &s.authority,
        &b_member,
        true,
        super::super::control_blob::ControlBlobMessage::Fetch {
            reference: reference_b.clone(),
            sequence: 0,
        },
    )
    .await;
    assert!(
        egress_happens(
            &s.authority,
            &j1_hex,
            "join_result_chunk",
            Duration::from_secs(5)
        )
        .await,
        "control: group B's chunk is served without a flood"
    );
    clear_egress(&s.authority);
    let lock = super::super::group_membership_lock_for_known_group(&s.authority, &s.stable)
        .await
        .expect("known group");
    let held = lock.lock().await;
    // The flood for group A: in-range duplicates and out-of-range sequences.
    for sequence in 0..24u32 {
        super::super::control_blob::handle_control_blob_message(
            &s.authority,
            &s.j2.agent.agent_id(),
            true,
            super::super::control_blob::ControlBlobMessage::Fetch {
                reference: reference_a.clone(),
                sequence: sequence % 12,
            },
        )
        .await;
    }
    // Group B's legitimate fetch.
    super::super::control_blob::handle_control_blob_message(
        &s.authority,
        &b_member,
        true,
        super::super::control_blob::ControlBlobMessage::Fetch {
            reference: reference_b,
            sequence: 0,
        },
    )
    .await;
    let served = egress_happens(
        &s.authority,
        &j1_hex,
        "join_result_chunk",
        Duration::from_secs(5),
    )
    .await;
    drop(held);
    assert!(
        served,
        "another group's legitimate chunk fetch was starved by one locked group's flood"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 5, G11 (D60): every delivery and resend of a class-K GSS share needs
// the recipient's CURRENT eligibility and the CURRENT secret epoch. A share
// is withheld (still pending) while the condition can clear, and purged
// when it cannot.
// ---------------------------------------------------------------------------

/// Every write of a `SecureShareDelivered` to `recipient` any path made: a
/// metadata-topic gossip publish, a direct-delivery schedule, or an admitted
/// class-K exchange.
fn share_writes(state: &AppState, recipient: &str) -> usize {
    let recorders = &state.named_group_test_recorders;
    let published = recorders
        .publish_bytes
        .lock()
        .expect("publish witness")
        .iter()
        .filter(|(_, bytes)| {
            matches!(
                serde_json::from_slice::<NamedGroupMetadataEvent>(bytes),
                Ok(NamedGroupMetadataEvent::SecureShareDelivered { recipient: to, .. }) if to == recipient
            )
        })
        .count();
    let scheduled = recorders
        .direct_deliveries
        .lock()
        .expect("direct-delivery witness")
        .iter()
        .filter(|(to, _, kind, _)| to == recipient && *kind == "secure_share_delivered")
        .count();
    published + scheduled + egress_count(state, recipient, "secure_share")
}

fn clear_share_witnesses(state: &AppState) {
    let recorders = &state.named_group_test_recorders;
    recorders
        .publish_bytes
        .lock()
        .expect("publish witness")
        .clear();
    recorders
        .direct_deliveries
        .lock()
        .expect("direct-delivery witness")
        .clear();
    clear_egress(state);
}

fn live_egress_tasks(state: &AppState, key: &(String, String)) -> usize {
    state
        .join_artifact_egress
        .lock()
        .expect("egress registry")
        .get(key)
        .map_or(0, |tasks| tasks.iter().filter(|t| !t.is_finished()).count())
}

/// Re-deliver the group's CURRENT share to the GSS joiner through the
/// production producer.
async fn deliver_current_share(g: &GssFixture) -> anyhow::Result<()> {
    let (topic, secret, epoch) = {
        let groups = g.authority.named_groups.read().await;
        let info = groups.get(&g.group_key).expect("authority group");
        let secret: [u8; 32] = info
            .shared_secret
            .clone()
            .ok_or_else(|| anyhow::anyhow!("the authority holds the secret"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("32-byte secret"))?;
        (info.metadata_topic.clone(), secret, info.secret_epoch)
    };
    let _ = super::super::publish_secure_share(
        &g.authority,
        &topic,
        &g.stable,
        &hex_of(&g.joiner),
        &BASE64.encode(&g.joiner.agent_kem_keypair.public_bytes),
        &hex_of(&g.authority),
        &secret,
        epoch,
    )
    .await;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShareInvalidation {
    AgentRevoked,
    MachineRevoked,
    CertificateExpired,
    VerdictInGrace,
    Quarantined,
}

impl ShareInvalidation {
    /// Can the condition still clear (withhold) or not (purge)?
    fn can_clear(self) -> bool {
        matches!(
            self,
            Self::MachineRevoked | Self::VerdictInGrace | Self::Quarantined
        )
    }
}

async fn invalidate_share_recipient(g: &GssFixture, case: ShareInvalidation) -> anyhow::Result<()> {
    let g_hex = hex_of(&g.joiner);
    match case {
        ShareInvalidation::AgentRevoked => {
            let kp = g.joiner.agent.identity().agent_keypair().to_bytes();
            revoke_agent(&g.authority, &kp).await?;
        }
        ShareInvalidation::MachineRevoked => revoke_machine(&g.authority, &g.joiner).await?,
        ShareInvalidation::CertificateExpired => {
            let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
            let past = x0x::groups::owner_cert::restore_clock_now() - 30 * 86_400;
            let expired = x0x::identity::AgentCertificate::issue_with_expiry(
                &owner_kp,
                g.joiner.agent.identity().agent_keypair(),
                Some(past),
            )?;
            if let Some(seat) = g
                .authority
                .named_groups
                .write()
                .await
                .get_mut(&g.group_key)
                .and_then(|info| info.members_v2.get_mut(&g_hex))
            {
                seat.certificate = Some(expired);
            }
        }
        ShareInvalidation::VerdictInGrace => {
            // The joiner announced a ROTATED certificate whose bytes are
            // still in flight: the embedded one is stale (InGrace).
            let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
            let rotated = x0x::identity::AgentCertificate::issue_with_expiry(
                &owner_kp,
                g.joiner.agent.identity().agent_keypair(),
                Some(x0x::groups::owner_cert::restore_clock_now() + 365 * 86_400),
            )?;
            let owner_id = owner_kp.user_id();
            let digest = x0x::announce_v3::cert_digest(&Some(owner_id), &Some(rotated));
            insert_discovery_entry(
                &g.authority,
                g.joiner.agent.agent_id(),
                Some(owner_id),
                None,
                Some(digest),
            )
            .await;
        }
        ShareInvalidation::Quarantined => {
            if let Some(info) = g.authority.named_groups.write().await.get_mut(&g.group_key) {
                info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
                    revision: 7,
                    state_hash: info.state_hash.clone(),
                    committed_by: "9e".repeat(32),
                    observed_at_ms: 1_726_000_000_000,
                    snapshot: x0x::groups::ForkSnapshot {
                        terminal_commit: info.terminal_commit_header(),
                        conflicting_commit: info.terminal_commit_header(),
                        classification: None,
                    },
                    no_anchor: true,
                });
            }
        }
    }
    Ok(())
}

/// A class-K share delivery with `case` landing between the producer and
/// the write: nothing is written, and the share is withheld (still
/// pending) when the condition can clear, purged when it cannot.
async fn share_delivery_case(case: ShareInvalidation) -> anyhow::Result<Option<String>> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), true).await?;
    let g_hex = hex_of(&g.joiner);
    if case == ShareInvalidation::MachineRevoked {
        pin_recipient_machine(&g.authority, &g.joiner).await;
    }
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "secure_share");
    clear_share_witnesses(&g.authority);
    deliver_current_share(&g).await?;
    // The share's producer has run; the invalidation lands before its write.
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        while !armed.gate.reached() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    invalidate_share_recipient(&g, case).await?;
    if reached {
        clear_share_witnesses(&g.authority);
    }
    drop(armed);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let writes = share_writes(&g.authority, &g_hex);
    if writes > 0 {
        return Ok(Some(format!(
            "{case:?}: {writes} share write(s) after the invalidation"
        )));
    }
    let key = (g.stable.clone(), g_hex.clone());
    if case.can_clear() {
        if live_egress_tasks(&g.authority, &key) == 0 {
            return Ok(Some(format!(
                "{case:?}: the share was purged, not withheld"
            )));
        }
    } else {
        // The fixture's own +8 s resend task re-checks too.
        let purged = tokio::time::timeout(Duration::from_secs(12), async {
            while live_egress_tasks(&g.authority, &key) > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();
        if !purged {
            return Ok(Some(format!(
                "{case:?}: the share was withheld, not purged"
            )));
        }
        if share_writes(&g.authority, &g_hex) > 0 {
            return Ok(Some(format!("{case:?}: a resend wrote the share")));
        }
    }
    Ok(None)
}

/// WHY (D60, G11): agent revocation before a share's write.
#[tokio::test]
async fn s8a_r5_g11_agent_revocation_withholds_nothing_and_purges_the_share() -> anyhow::Result<()>
{
    let failure = share_delivery_case(ShareInvalidation::AgentRevoked).await?;
    assert!(failure.is_none(), "{failure:?}");
    Ok(())
}

/// WHY (D60, G11): machine revocation before a share's write.
#[tokio::test]
async fn s8a_r5_g11_machine_revocation_withholds_the_share() -> anyhow::Result<()> {
    let failure = share_delivery_case(ShareInvalidation::MachineRevoked).await?;
    assert!(failure.is_none(), "{failure:?}");
    Ok(())
}

/// WHY (D60, G11): certificate expiry before a share's write.
#[tokio::test]
async fn s8a_r5_g11_certificate_expiry_purges_the_share() -> anyhow::Result<()> {
    let failure = share_delivery_case(ShareInvalidation::CertificateExpired).await?;
    assert!(failure.is_none(), "{failure:?}");
    Ok(())
}

/// WHY (D60, G11): a verdict change (InGrace) before a share's write.
#[tokio::test]
async fn s8a_r5_g11_verdict_change_withholds_the_share() -> anyhow::Result<()> {
    let failure = share_delivery_case(ShareInvalidation::VerdictInGrace).await?;
    assert!(failure.is_none(), "{failure:?}");
    Ok(())
}

/// WHY (D60, G11): fork quarantine before a share's write.
#[tokio::test]
async fn s8a_r5_g11_quarantine_withholds_the_share() -> anyhow::Result<()> {
    let failure = share_delivery_case(ShareInvalidation::Quarantined).await?;
    assert!(failure.is_none(), "{failure:?}");
    Ok(())
}

/// WHY (D60, G11): a share's RESEND (the +8 s second delivery) is admitted
/// afresh: it is never scheduled outside admission, and an invalidation
/// after the first write stops it.
#[tokio::test]
async fn s8a_r5_g11_share_resend_is_admitted_afresh() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), true).await?;
    let g_hex = hex_of(&g.joiner);
    clear_share_witnesses(&g.authority);
    deliver_current_share(&g).await?;
    let unadmitted_resends = g
        .authority
        .named_group_test_recorders
        .direct_deliveries
        .lock()
        .expect("direct-delivery witness")
        .iter()
        .filter(|(to, _, kind, label)| {
            *to == g_hex && *kind == "secure_share_delivered" && *label == "delayed"
        })
        .count();
    assert_eq!(
        unadmitted_resends, 0,
        "a share resend was scheduled outside per-send admission"
    );
    // The first write happened; the recipient is revoked before the resend.
    assert!(
        egress_happens(&g.authority, &g_hex, "secure_share", Duration::from_secs(5)).await,
        "the first share write"
    );
    let kp = g.joiner.agent.identity().agent_keypair().to_bytes();
    revoke_agent(&g.authority, &kp).await?;
    clear_share_witnesses(&g.authority);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        share_writes(&g.authority, &g_hex),
        0,
        "the resend wrote the share after the recipient was revoked"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 5, G13: the class-R/class-K transport on a REAL loopback QUIC pair.
// These tests join a loopback-only network and are NOT run locally: CI runs
// them inside its isolated network namespace (scripts/ci/nextest-isolated.sh).
// ---------------------------------------------------------------------------

struct TransportPair {
    alice: Arc<AppState>,
    _alice_dir: tempfile::TempDir,
    bob: Arc<AppState>,
    _bob_dir: tempfile::TempDir,
}

async fn transport_pair(tag: &str) -> anyhow::Result<TransportPair> {
    let plane = format!("adr0107-r5-{tag}-{}", rand::random::<u32>());
    let (alice, alice_dir) = super::networked_test_state(&plane).await?;
    let (bob, bob_dir) = super::networked_test_state(&plane).await?;
    super::wait_connected(&alice.agent, &bob.agent).await?;
    pin_recipient_machine(&alice, &bob).await;
    Ok(TransportPair {
        alice,
        _alice_dir: alice_dir,
        bob,
        _bob_dir: bob_dir,
    })
}

/// An admission whose phases are counted; `pre` refuses in the pre-phase,
/// `seam` decides at the stream seam, and `before_seam` runs inside the
/// pre-phase after its checks (to land an invalidation between the two).
fn counted_admission(
    pre_calls: Arc<std::sync::atomic::AtomicUsize>,
    seam_calls: Arc<std::sync::atomic::AtomicUsize>,
    pre: bool,
    seam: bool,
    before_seam: Option<Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>>,
) -> x0x::dm::ArtifactAdmission {
    Arc::new(move || {
        let pre_calls = Arc::clone(&pre_calls);
        let seam_calls = Arc::clone(&seam_calls);
        let before_seam = before_seam.clone();
        Box::pin(async move {
            pre_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !pre {
                return None;
            }
            if let Some(before_seam) = before_seam {
                before_seam().await;
            }
            let seam_check: x0x::dm::SeamAdmission = Box::new(move || {
                seam_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                seam
            });
            Some(seam_check)
        })
    })
}

/// Copies of `marker` Bob's receive pipeline delivers within `within`.
async fn bob_receives(
    rx: &mut x0x::DirectMessageReceiver,
    marker: &[u8],
    within: Duration,
) -> usize {
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(message)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if message.payload == marker {
            count += 1;
        }
    }
    count
}

/// WHY (G13, F1/F5 inspection rows): on the real raw path, one pinned call
/// runs the pre-phase once and the seam once, writes once, and Bob's
/// ordinary receive pipeline (no ACK-v2 needed) gets exactly one copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8a_r5_g13_real_pinned_exchange_is_admitted_once_and_delivered_once() -> anyhow::Result<()>
{
    let pair = transport_pair("once").await?;
    let mut rx = pair.bob.agent.subscribe_direct();
    let (pre, seam) = (Arc::default(), Arc::default());
    let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
    let marker = b"adr0107-r5-g13-once".to_vec();
    let sent = pair
        .alice
        .agent
        .send_direct_pinned_admitted(
            &pair.bob.agent.agent_id(),
            &marker,
            &admission,
            x0x::dm::PINNED_RESOLUTION_WAIT,
        )
        .await;
    assert!(sent.is_ok(), "the admitted exchange writes: {sent:?}");
    assert_eq!(
        bob_receives(&mut rx, &marker, Duration::from_secs(5)).await,
        1
    );
    assert_eq!(pre.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(seam.load(std::sync::atomic::Ordering::SeqCst), 1);
    pair.alice.agent.shutdown().await;
    pair.bob.agent.shutdown().await;
    Ok(())
}

/// WHY (G13): a refusal at the seam (after `open_uni`) or in the pre-phase
/// writes nothing on the real path, and is reported as an admission
/// refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8a_r5_g13_real_refusals_write_nothing() -> anyhow::Result<()> {
    let pair = transport_pair("refuse").await?;
    let mut rx = pair.bob.agent.subscribe_direct();
    for (case, pre_ok) in [("seam", true), ("pre-phase", false)] {
        let (pre, seam) = (Arc::default(), Arc::default());
        let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), pre_ok, false, None);
        let marker = format!("adr0107-r5-g13-refuse-{case}").into_bytes();
        let sent = pair
            .alice
            .agent
            .send_direct_pinned_admitted(
                &pair.bob.agent.agent_id(),
                &marker,
                &admission,
                x0x::dm::PINNED_RESOLUTION_WAIT,
            )
            .await;
        assert!(
            sent.as_ref()
                .is_err_and(|e| e.to_string().contains(x0x::dm::PINNED_ADMISSION_REFUSED)),
            "[{case}] reported as an admission refusal: {sent:?}"
        );
        assert_eq!(
            bob_receives(&mut rx, &marker, Duration::from_secs(2)).await,
            0,
            "[{case}] nothing reached Bob"
        );
    }
    pair.alice.agent.shutdown().await;
    pair.bob.agent.shutdown().await;
    Ok(())
}

/// WHY (G13, G2): Bob's MACHINE revoked between the pre-phase and the seam
/// on the real path: the transport's own seam check refuses the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8a_r5_g13_real_machine_revocation_before_the_seam_writes_nothing() -> anyhow::Result<()> {
    let pair = transport_pair("machine").await?;
    let mut rx = pair.bob.agent.subscribe_direct();
    let alice = Arc::clone(&pair.alice);
    let bob = Arc::clone(&pair.bob);
    let revoke: Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync> =
        Arc::new(move || {
            let alice = Arc::clone(&alice);
            let bob = Arc::clone(&bob);
            Box::pin(async move {
                let _ = revoke_machine(&alice, &bob).await;
            })
        });
    let (pre, seam) = (Arc::default(), Arc::default());
    let admission = counted_admission(
        Arc::clone(&pre),
        Arc::clone(&seam),
        true,
        true,
        Some(revoke),
    );
    let marker = b"adr0107-r5-g13-machine".to_vec();
    let sent = pair
        .alice
        .agent
        .send_direct_pinned_admitted(
            &pair.bob.agent.agent_id(),
            &marker,
            &admission,
            x0x::dm::PINNED_RESOLUTION_WAIT,
        )
        .await;
    assert!(sent.is_err(), "the revoked machine is refused: {sent:?}");
    assert_eq!(
        bob_receives(&mut rx, &marker, Duration::from_secs(2)).await,
        0
    );
    pair.alice.agent.shutdown().await;
    pair.bob.agent.shutdown().await;
    Ok(())
}

/// WHY (G13, section 2.7 item 6): the server's class-R wrapper on the real
/// path. A stalled exchange is cut by its deadline and writes nothing; the
/// next exchange on the same connection is admitted and delivered once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s8a_r5_g13_real_deadline_cuts_a_stalled_exchange() -> anyhow::Result<()> {
    let pair = transport_pair("deadline").await?;
    let mut rx = pair.bob.agent.subscribe_direct();
    let bob_id = pair.bob.agent.agent_id();
    let stall: Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync> =
        Arc::new(|| Box::pin(futures::future::pending::<()>()));
    let (pre, seam) = (Arc::default(), Arc::default());
    let stalled = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, Some(stall));
    let marker = b"adr0107-r5-g13-stalled".to_vec();
    let started = tokio::time::Instant::now();
    let outcome = super::super::send_join_artifact(
        &pair.alice,
        &bob_id,
        &marker,
        "adr0107-r5-g13",
        "join_result",
        stalled,
        Instant::now() + Duration::from_secs(2),
    )
    .await;
    assert!(outcome.is_err(), "the stalled exchange fails: {outcome:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cut by its deadline"
    );
    assert_eq!(seam.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        bob_receives(&mut rx, &marker, Duration::from_secs(2)).await,
        0
    );
    let (pre2, seam2) = (Arc::default(), Arc::default());
    let healthy = counted_admission(pre2, Arc::clone(&seam2), true, true, None);
    let next = b"adr0107-r5-g13-next".to_vec();
    let outcome = super::super::send_join_artifact(
        &pair.alice,
        &bob_id,
        &next,
        "adr0107-r5-g13",
        "join_result",
        healthy,
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(outcome.is_ok(), "the next exchange writes: {outcome:?}");
    assert_eq!(
        bob_receives(&mut rx, &next, Duration::from_secs(5)).await,
        1
    );
    assert_eq!(seam2.load(std::sync::atomic::Ordering::SeqCst), 1);
    pair.alice.agent.shutdown().await;
    pair.bob.agent.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 6 (Codex review of a8acd0d).
// ---------------------------------------------------------------------------

/// WHY (r6 P1): the seam must take the roster verdict at the SEAM's clock,
/// not the pre-phase snapshot's. J2's resolved announced certificate (a
/// rotation, so the embedded one is stale) expires between the pre-phase
/// and the seam while the embedded certificate stays valid: the snapshot
/// still says Clean, the seam must refuse.
#[tokio::test]
async fn s8a_r6_verdict_expiry_between_pre_phase_and_seam_is_refused() -> anyhow::Result<()> {
    use x0x::groups::owner_cert::MemberCertStatus;
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
    let owner_id = owner_kp.user_id();
    let announced = x0x::identity::AgentCertificate::issue_with_expiry(
        &owner_kp,
        &keypair(&s.j2_kp)?,
        Some(x0x::groups::owner_cert::restore_clock_now() + 120),
    )?;
    let digest = x0x::announce_v3::cert_digest(&Some(owner_id), &Some(announced.clone()));
    insert_discovery_entry(
        &s.authority,
        s.j2.agent.agent_id(),
        Some(owner_id),
        Some(announced),
        Some(digest),
    )
    .await;
    assert_eq!(
        roster_verdict(&s.authority, &s.group_key, &j2_hex).await,
        Some(MemberCertStatus::Clean),
        "control: the resolved announced certificate is Clean now"
    );
    // The seam runs an hour later than the pre-phase: past the announced
    // certificate's expiry and its 300 s clock-skew tolerance, while the
    // embedded one is still valid.
    s.authority
        .named_group_test_recorders
        .seam_clock_skew_secs
        .store(3600, std::sync::atomic::Ordering::SeqCst);
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    clear_egress(&s.authority);
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    assert!(
        transport_seen(&s.authority, &j2_hex, "welcome_frame").await,
        "the Welcome chunk reached the transport"
    );
    assert!(
        !egress_happens(
            &s.authority,
            &j2_hex,
            "welcome_frame",
            Duration::from_secs(1)
        )
        .await,
        "the seam admitted bytes on a verdict that expired after the pre-phase"
    );
    Ok(())
}

/// WHY (r6 P2): the synchronous stream seam must never block. With the
/// staging registry's lock held elsewhere, the seam's staged-copy check
/// refuses at once (a retryable withhold) instead of blocking the executor
/// until the lock frees — a block no timeout or abort can interrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s8a_r6_seam_staged_copy_check_never_blocks() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let reference = staged_join_result_blob(&s).await?;
    assert!(
        super::super::join_result_blob_staged_now(&s.authority, &reference),
        "control: the staged copy passes when uncontended"
    );
    let held = s
        .authority
        .control_blobs
        .hold_registry_for_test(Duration::from_secs(2));
    held.recv_timeout(Duration::from_secs(5))
        .map_err(|_| anyhow::anyhow!("the holder never took the lock"))?;
    let started = std::time::Instant::now();
    let admitted = super::super::join_result_blob_staged_now(&s.authority, &reference);
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_millis(500) && !admitted,
        "the seam blocked on the staging registry ({waited:?}, admitted: {admitted})"
    );
    Ok(())
}

/// WHY (r6 P3): G7 admits one fetch HANDLER per (group, member), but the
/// handler spawns the inline egress and returns, releasing its ticket. A
/// flood of duplicate fetches while one inline egress is stalled must
/// still leave exactly ONE in-flight egress for that (group, recipient).
#[tokio::test]
async fn s8a_r6_duplicate_fetches_never_overlap_inline_egress() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
    for _ in 0..6 {
        super::super::dispatch_join_result_message(
            &g.authority,
            &g.joiner.agent.agent_id(),
            true,
            JoinResultMessage::FetchRequest {
                group_id: g.stable.clone(),
                member_agent_id: g_hex.clone(),
                from_revision: from,
                base_state_hash: None,
                accepts_refusal: true,
                accepts_control_blob_ref: true,
                attempt_id: Some(g.attempt.clone()),
            },
        )
        .await;
        // Witness, not a sleep: the handler has finished and released its
        // G7 ticket, so the NEXT duplicate is admitted by G7 and only the
        // egress admission can stop it.
        g7_tickets_released(&g.authority).await;
    }
    wait_reached(&armed.gate, "inline result").await;
    let parked = armed.gate.parked();
    drop(armed);
    assert_eq!(
        parked, 1,
        "duplicate fetches started overlapping inline egress for one (group, recipient)"
    );
    Ok(())
}

/// WHY (r6 P4, D60): a withholding refusal (quarantine) must not mask a
/// terminal one. Quarantine together with agent revocation, or together
/// with a moved secret epoch, purges the pending share — it is not
/// withheld until the horizon.
#[tokio::test]
async fn s8a_r6_terminal_share_invalidations_outrank_withholding() -> anyhow::Result<()> {
    let mut masked = Vec::new();
    for case in ["quarantine_and_agent_revoked", "quarantine_and_epoch_moved"] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), true).await?;
        let g_hex = hex_of(&g.joiner);
        let armed = super::super::join_egress_test_barrier::arm(&g_hex, "secure_share");
        clear_share_witnesses(&g.authority);
        deliver_current_share(&g).await?;
        wait_reached(&armed.gate, "secure share").await;
        invalidate_share_recipient(&g, ShareInvalidation::Quarantined).await?;
        if case == "quarantine_and_agent_revoked" {
            invalidate_share_recipient(&g, ShareInvalidation::AgentRevoked).await?;
        } else if let Some(info) = g.authority.named_groups.write().await.get_mut(&g.group_key) {
            info.secret_epoch += 1;
        }
        clear_share_witnesses(&g.authority);
        drop(armed);
        let key = (g.stable.clone(), g_hex.clone());
        let purged = tokio::time::timeout(Duration::from_secs(12), async {
            while live_egress_tasks(&g.authority, &key) > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();
        if !purged {
            masked.push(case);
        }
        if share_writes(&g.authority, &g_hex) > 0 {
            masked.push("a share was written");
        }
    }
    assert!(
        masked.is_empty(),
        "a withholding refusal masked a terminal share invalidation: {masked:?}"
    );
    Ok(())
}

/// Wait (bounded) until every G7 join-result fetch handler has released its
/// admission ticket.
async fn g7_tickets_released(state: &AppState) {
    let released = tokio::time::timeout(Duration::from_secs(10), async {
        while state.join_result_fetch_admission.in_flight() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "a G7 fetch handler never released its ticket"
    );
}

/// WHY (r6 boundary): certificate expiry carries a 300 s clock-skew
/// tolerance (`now > not_after + 300` is expired). At the seam's clock, an
/// announced certificate just inside the tolerance still admits, and just
/// outside it refuses.
#[tokio::test]
async fn s8a_r6_seam_verdict_honours_the_expiry_tolerance_boundary() -> anyhow::Result<()> {
    let mut wrong = Vec::new();
    // (skew past the pre-phase, expected to admit)
    for (case, skew, admit) in [
        ("inside", 120 + 300 - 10, true),
        ("outside", 120 + 300 + 10, false),
    ] {
        let dir = tempfile::tempdir()?;
        let s = build(dir.path()).await?;
        let j2_hex = hex_of(&s.j2);
        let owner_kp = x0x::identity::UserKeypair::from_seed(&OWNER_SEED)?;
        let owner_id = owner_kp.user_id();
        let announced = x0x::identity::AgentCertificate::issue_with_expiry(
            &owner_kp,
            &keypair(&s.j2_kp)?,
            Some(x0x::groups::owner_cert::restore_clock_now() + 120),
        )?;
        let digest = x0x::announce_v3::cert_digest(&Some(owner_id), &Some(announced.clone()));
        insert_discovery_entry(
            &s.authority,
            s.j2.agent.agent_id(),
            Some(owner_id),
            Some(announced),
            Some(digest),
        )
        .await;
        s.authority
            .named_group_test_recorders
            .seam_clock_skew_secs
            .store(skew, std::sync::atomic::Ordering::SeqCst);
        let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
        clear_egress(&s.authority);
        assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
        assert!(
            transport_seen(&s.authority, &j2_hex, "welcome_frame").await,
            "[{case}] the Welcome chunk reached the transport"
        );
        let admitted = egress_happens(
            &s.authority,
            &j2_hex,
            "welcome_frame",
            Duration::from_secs(1),
        )
        .await;
        if admitted != admit {
            wrong.push((case, admitted));
        }
    }
    assert!(
        wrong.is_empty(),
        "the seam misjudged the 300 s expiry tolerance boundary: {wrong:?}"
    );
    Ok(())
}

/// WHY (r6 boundary): once an in-flight inline egress is cancelled (here:
/// quiesced, as a removal or ban would), its egress ticket is released and
/// the recipient's next fetch is admitted again.
#[tokio::test]
async fn s8a_r6_a_fetch_after_a_cancelled_egress_is_admitted() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let from = remnant_revision(&g.joiner, &g.group_key).await;
    let fetch = || JoinResultMessage::FetchRequest {
        group_id: g.stable.clone(),
        member_agent_id: g_hex.clone(),
        from_revision: from,
        base_state_hash: None,
        accepts_refusal: true,
        accepts_control_blob_ref: true,
        attempt_id: Some(g.attempt.clone()),
    };
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "join_result");
    super::super::dispatch_join_result_message(
        &g.authority,
        &g.joiner.agent.agent_id(),
        true,
        fetch(),
    )
    .await;
    wait_reached(&armed.gate, "inline result").await;
    g7_tickets_released(&g.authority).await;
    assert_eq!(g.authority.join_result_egress_admission.in_flight(), 1);
    // Cancel the in-flight egress (aborted and awaited).
    super::super::quiesce_member_join_egress(&g.authority, &g.stable, &g_hex).await;
    assert_eq!(armed.gate.parked(), 0, "the egress was cancelled");
    assert_eq!(
        g.authority.join_result_egress_admission.in_flight(),
        0,
        "the cancelled egress released its egress ticket"
    );
    // The next fetch is admitted and starts a new egress.
    super::super::dispatch_join_result_message(
        &g.authority,
        &g.joiner.agent.agent_id(),
        true,
        fetch(),
    )
    .await;
    let readmitted = tokio::time::timeout(Duration::from_secs(10), async {
        while armed.gate.parked() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    drop(armed);
    assert!(
        readmitted,
        "a fetch after a cancelled egress was not admitted"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// g10-1190a (ephemeral testnet, 2026-10-04): an owner that restarted 12–22 s
// before acting has a cold discovery cache, DM registry and peer evidence.
// The pinned path must resolve the recipient's machine from a VERIFIED
// source before its single admitted exchange, waiting a bounded time inside
// the exchange deadline for one to learn the recipient. An unresolved
// recipient is a typed, retryable error. The authority's in-process stand-in
// runs the real path's resolution (strict mode).
// ---------------------------------------------------------------------------

/// The authority restarted: what it held about `recipient`'s machine (its
/// discovery cache entry, its DM registry entry) is gone, its egress for the
/// recipient is not running, and its pinned stand-in resolves as the real
/// path does.
async fn restart_cold(authority: &AppState, recipient: &AppState, group: &str) {
    let id = recipient.agent.agent_id();
    super::super::quiesce_member_join_egress(authority, group, &hex_of(recipient)).await;
    authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .remove(&id);
    authority
        .agent
        .direct_messaging()
        .mark_disconnected(&id)
        .await;
    authority
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
}

fn unix_secs_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// WHY (g10-1190a, class K, case 1): the owner restarted just before
/// approving, so nothing it holds names the new member's machine. The
/// member's identity announcement lands 300 ms into the share's exchange,
/// inside the bound: that exchange delivers the share. Before the fix it
/// gave up at once (`err_agent_not_found`) and the share waited out the
/// transport backoff (8, 16, 32, 64 s on the testnet run, against the
/// joiner's 120 s deadline).
#[tokio::test]
async fn s8a_r7_owner_restart_class_k_share_lands_when_discovery_arrives_within_the_bound(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    let armed = super::super::join_egress_test_barrier::arm(&g_hex, "secure_share");
    clear_share_witnesses(&g.authority);
    deliver_current_share(&g).await?;
    wait_reached(&armed.gate, "the share's exchange").await;
    armed.gate.release();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let early = share_writes(&g.authority, &g_hex);
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let delivered =
        egress_happens(&g.authority, &g_hex, "secure_share", Duration::from_secs(3)).await;
    drop(armed);
    assert_eq!(early, 0, "a share was written before any machine was known");
    assert!(
        delivered,
        "the share was not delivered on the exchange whose bound the discovery landed in"
    );
    Ok(())
}

/// WHY (g10-1190a, class R, case 2): the owner restarted, so its discovery
/// cache and DM registry are cold. The Welcome fetch it answers was verified
/// by J2's ADR-0021 origin attestation (the gossip inbox records that
/// binding): it is the only verified source of J2's machine, and it lands
/// 300 ms into the first chunk's exchange, inside the bound. That exchange
/// delivers the chunk. Before the fix the pinned path never read
/// authenticated bindings and gave up at once ("failed to send Welcome blob
/// chunk: recipient_undiscovered"), so the stream ended.
#[tokio::test]
async fn s8a_r7_owner_restart_welcome_chunk_lands_on_the_requesters_attested_binding(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    restart_cold(&s.authority, &s.j2, &s.stable).await;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let armed = super::super::join_egress_test_barrier::arm(&j2_hex, "welcome_frame");
    clear_egress(&s.authority);
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    wait_reached(&armed.gate, "the first chunk's exchange").await;
    armed.gate.release();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let early = egress_count(&s.authority, &j2_hex, "welcome_frame");
    s.authority
        .agent
        .record_authenticated_binding_for_testing(
            s.j2.agent.agent_id(),
            s.j2.agent.machine_id(),
            unix_secs_now(),
        )
        .await;
    let delivered = egress_happens(
        &s.authority,
        &j2_hex,
        "welcome_frame",
        Duration::from_secs(3),
    )
    .await;
    drop(armed);
    assert_eq!(early, 0, "a chunk was written before any machine was known");
    assert!(
        delivered,
        "the Welcome chunk was not delivered on the requester's attested binding"
    );
    Ok(())
}

/// WHY (g10-1190a control): a machine learned during the bounded wait gets
/// the same checks as any other. The binding that arrives names a REVOKED
/// machine: the pre-phase runs once after resolution, the seam refuses (an
/// admission refusal, a retryable withhold for the caller), nothing is
/// written.
#[tokio::test]
async fn s8a_r7_a_machine_learned_during_the_wait_is_refused_at_the_seam_when_revoked(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    revoke_machine(&g.authority, &g.joiner).await?;
    let (pre, seam) = (Arc::default(), Arc::default());
    let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
    let arrival = {
        let authority = Arc::clone(&g.authority);
        let joiner = Arc::clone(&g.joiner);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            pin_recipient_machine(&authority, &joiner).await;
        })
    };
    clear_egress(&g.authority);
    let outcome = super::super::send_join_artifact(
        &g.authority,
        &g.joiner.agent.agent_id(),
        b"adr0107-r7-revoked-machine",
        &g.stable,
        "join_result",
        admission,
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    arrival.await?;
    assert!(
        outcome
            .as_ref()
            .is_err_and(|reason| reason.contains(x0x::dm::PINNED_ADMISSION_REFUSED)),
        "the revoked machine is refused at the seam: {outcome:?}"
    );
    assert_eq!(
        pre.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the pre-phase ran once, after resolution"
    );
    assert_eq!(
        seam.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the agent's own machine-revocation check refused before the caller's seam"
    );
    assert_eq!(egress_count(&g.authority, &g_hex, "join_result"), 0);
    Ok(())
}

/// WHY (g10-1190a control): when no verified source learns the recipient,
/// the exchange gets its bounded wait (half of its 3 s budget here), then
/// ends in the typed, retryable `recipient_undiscovered` inside the exchange
/// deadline (not as a deadline cut), before any admission ran and with
/// nothing written.
#[tokio::test]
async fn s8a_r7_an_unresolved_recipient_ends_in_a_typed_error_within_the_bound(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    let (pre, seam) = (Arc::default(), Arc::default());
    let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
    clear_egress(&g.authority);
    let started = std::time::Instant::now();
    let outcome = super::super::send_join_artifact(
        &g.authority,
        &g.joiner.agent.agent_id(),
        b"adr0107-r7-unresolved",
        &g.stable,
        "join_result",
        admission,
        Instant::now() + Duration::from_secs(3),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        outcome
            .as_ref()
            .is_err_and(|reason| reason.starts_with("recipient_undiscovered")),
        "a typed, retryable resolution error: {outcome:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1_200),
        "the recipient got no bounded wait: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2_800),
        "the typed error did not land inside the exchange deadline: {elapsed:?}"
    );
    assert_eq!(pre.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(seam.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(egress_count(&g.authority, &g_hex, "join_result"), 0);
    Ok(())
}

/// The class-R/class-K exchanges to `recipient` of `kind` started so far
/// (each is recorded when it is handed to the pinned transport).
fn exchange_starts(state: &AppState, recipient: &str, kind: &str) -> usize {
    transports_for(state, recipient)
        .iter()
        .filter(|(k, _)| *k == kind)
        .count()
}

/// Forget every recorded exchange start and outcome.
fn clear_exchanges(state: &AppState) {
    let recorders = &state.named_group_test_recorders;
    recorders
        .join_artifact_transports
        .lock()
        .expect("transport witness")
        .clear();
    recorders
        .join_artifact_outcomes
        .lock()
        .expect("outcome witness")
        .clear();
}

/// Wait (bounded) until an exchange of `kind` to `recipient` has ended
/// with an error text starting with `prefix`.
async fn exchange_ended_with(
    state: &AppState,
    recipient: &str,
    kind: &str,
    prefix: &str,
    within: Duration,
) -> bool {
    let ended = || {
        state
            .named_group_test_recorders
            .join_artifact_outcomes
            .lock()
            .expect("outcome witness")
            .iter()
            .any(|(to, k, reason)| to == recipient && *k == kind && reason.starts_with(prefix))
    };
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if ended() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ended()
}

/// WHY (g10-1190a, class K; r7b P3): a share exchange that ends
/// `recipient_undiscovered` (nothing learned the member within its bound)
/// is resent promptly, not after the transport backoff, because the bounded
/// wait already paces it. The test waits for that first exchange to END
/// undiscovered, then lets discovery land, and requires a SECOND exchange to
/// deliver the share within the resend pause plus a margin.
#[tokio::test]
async fn s8a_r7_class_k_share_resends_promptly_after_an_undiscovered_exchange() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    clear_share_witnesses(&g.authority);
    clear_exchanges(&g.authority);
    deliver_current_share(&g).await?;
    assert!(
        exchange_ended_with(
            &g.authority,
            &g_hex,
            "secure_share",
            "recipient_undiscovered",
            Duration::from_secs(15),
        )
        .await,
        "the first share exchange never ended recipient_undiscovered"
    );
    let undiscovered_at = std::time::Instant::now();
    let first = exchange_starts(&g.authority, &g_hex, "secure_share");
    let early = share_writes(&g.authority, &g_hex);
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let delivered =
        egress_happens(&g.authority, &g_hex, "secure_share", Duration::from_secs(3)).await;
    let resent_after = undiscovered_at.elapsed();
    let starts = exchange_starts(&g.authority, &g_hex, "secure_share");
    assert_eq!(first, 1, "one exchange before discovery");
    assert_eq!(early, 0, "a share was written before any machine was known");
    assert!(
        delivered,
        "no second exchange delivered the share within 3 s of the undiscovered one ({resent_after:?})"
    );
    assert!(
        starts >= 2,
        "the share was not delivered by a second exchange ({starts} exchanges)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// r7b (Codex review of e645ce2..a3c85dd): binding provenance survives repair
// and redial and is re-validated at the seam; the whole resolution, lock
// waits included, is bounded.
// ---------------------------------------------------------------------------

/// WHY (r7b P2-1): the seam re-validates the binding too. The send resolves
/// J's machine from its current attestation; between the pre-phase and the
/// seam, a newer attestation moves J to another machine, or J's binding now
/// carries an expired certificate. The seam refuses (an admission refusal),
/// and nothing is written.
#[tokio::test]
async fn s8a_r7b_a_binding_that_changes_before_the_seam_is_refused_at_the_seam(
) -> anyhow::Result<()> {
    let mut wrong = Vec::new();
    for case in ["moved", "certificate expired"] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        restart_cold(&g.authority, &g.joiner, &g.stable).await;
        let joiner_id = g.joiner.agent.agent_id();
        let joiner_machine = g.joiner.agent.machine_id();
        let now = unix_secs_now();
        g.authority
            .agent
            .record_authenticated_binding_for_testing(joiner_id, joiner_machine, now - 10)
            .await;
        let authority = Arc::clone(&g.authority);
        let change: Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync> =
            Arc::new(move || {
                let authority = Arc::clone(&authority);
                Box::pin(async move {
                    if case == "moved" {
                        authority
                            .agent
                            .record_authenticated_binding_for_testing(
                                joiner_id,
                                x0x::identity::MachineId([0x5b; 32]),
                                now,
                            )
                            .await;
                    } else {
                        authority
                            .agent
                            .record_authenticated_binding_with_expiry_for_testing(
                                joiner_id,
                                joiner_machine,
                                now,
                                Some(now - 86_400),
                            )
                            .await;
                    }
                })
            });
        let (pre, seam) = (Arc::default(), Arc::default());
        let admission = counted_admission(
            Arc::clone(&pre),
            Arc::clone(&seam),
            true,
            true,
            Some(change),
        );
        clear_egress(&g.authority);
        let outcome = super::super::send_join_artifact(
            &g.authority,
            &joiner_id,
            b"adr0107-r7b-binding-changes",
            &g.stable,
            "join_result",
            admission,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        let refused = outcome
            .as_ref()
            .is_err_and(|reason| reason.contains(x0x::dm::PINNED_ADMISSION_REFUSED));
        let written = egress_count(&g.authority, &g_hex, "join_result");
        if !refused || written != 0 || seam.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            wrong.push(format!("[{case}] {outcome:?}, {written} written"));
        }
    }
    assert!(
        wrong.is_empty(),
        "the seam admitted a binding that changed after the pre-phase: {wrong:?}"
    );
    Ok(())
}

/// WHY (r7b P2-2): the whole resolution is bounded, lock waits included. A
/// held source lock (the announced bindings, then the authenticated
/// bindings; r7d: the discovery cache is no longer a resolver source)
/// must not stretch resolution to the exchange deadline. The send still
/// ends with the typed, retryable `recipient_undiscovered` inside the
/// deadline, before any admission, with nothing written.
#[tokio::test]
async fn s8a_r7b_a_held_source_lock_ends_in_the_typed_error_within_the_bound() -> anyhow::Result<()>
{
    let mut wrong = Vec::new();
    for case in ["announced bindings", "authenticated bindings"] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        let g_hex = hex_of(&g.joiner);
        restart_cold(&g.authority, &g.joiner, &g.stable).await;
        let announced = g.authority.agent.announced_machine_bindings_for_testing();
        let bindings = g
            .authority
            .agent
            .authenticated_machine_bindings_for_testing();
        let (pre, seam) = (Arc::default(), Arc::default());
        let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
        clear_egress(&g.authority);
        let started = std::time::Instant::now();
        let outcome = {
            let _announced_held = if case == "announced bindings" {
                Some(announced.write().await)
            } else {
                None
            };
            let _bindings_held = if case == "authenticated bindings" {
                Some(bindings.write().await)
            } else {
                None
            };
            super::super::send_join_artifact(
                &g.authority,
                &g.joiner.agent.agent_id(),
                b"adr0107-r7b-held-lock",
                &g.stable,
                "join_result",
                admission,
                Instant::now() + Duration::from_secs(3),
            )
            .await
        };
        let elapsed = started.elapsed();
        let typed = outcome
            .as_ref()
            .is_err_and(|reason| reason.starts_with("recipient_undiscovered"));
        if !typed
            || elapsed >= Duration::from_millis(2_800)
            || pre.load(std::sync::atomic::Ordering::SeqCst) != 0
            || egress_count(&g.authority, &g_hex, "join_result") != 0
        {
            wrong.push(format!("[{case}] {outcome:?} after {elapsed:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a held source lock escaped the resolution bound: {wrong:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// r7c (Codex review of a3c85dd..dc1eb49): verified announcement bindings stay
// apart from mutable routing state; the bound covers revalidation after
// repair; the evidence policy never blocks a non-blocking check.
// ---------------------------------------------------------------------------

/// WHY (r7c, Codex NEW 1): stale routing state never becomes pinned
/// authority. J's verified announcement names its machine B; the DM registry
/// still names an older machine A, which is connected. B is not connected
/// and does not repair, so the send redials. The PRODUCTION redial
/// (`redial_direct_machine_from_discovery`, here over a scripted connection
/// state) reconciles the discovery cache to the connected registry machine:
/// the cache then names A under B's announcement timestamp. Neither that
/// send nor the next one may write to A. The general connector rewriting
/// the cache directly (as `connect_to_agent` does) must not move the pinned
/// target either.
#[tokio::test]
async fn s8a_r7c_stale_routing_state_never_becomes_pinned_authority() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    let joiner_id = g.joiner.agent.agent_id();
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let stale = x0x::identity::MachineId([0xa7; 32]);
    g.authority
        .agent
        .direct_messaging()
        .mark_connected(joiner_id, stale)
        .await;
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(x0x::PinnedTransportScript::connected_only(
            &[stale],
            false,
        ));
    clear_egress(&g.authority);
    let mut admitted = Vec::new();
    for attempt in ["first", "resend", "after a connector rewrite"] {
        if attempt == "after a connector rewrite" {
            if let Some(entry) = g
                .authority
                .agent
                .identity_discovery_cache()
                .write()
                .await
                .get_mut(&joiner_id)
            {
                entry.machine_id = stale;
            }
        }
        let (pre, seam) = (Arc::default(), Arc::default());
        let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
        let outcome = super::super::send_join_artifact(
            &g.authority,
            &joiner_id,
            b"adr0107-r7c-stale-routing",
            &g.stable,
            "join_result",
            admission,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        if pre.load(std::sync::atomic::Ordering::SeqCst) != 0
            || outcome
                .as_ref()
                .is_err_and(|reason| reason.contains(x0x::dm::PINNED_STANDIN_ADMITTED))
        {
            admitted.push(format!("[{attempt}] {outcome:?}"));
        }
    }
    assert!(
        admitted.is_empty(),
        "a stale routing machine was admitted as the pinned target: {admitted:?}"
    );
    assert_eq!(egress_count(&g.authority, &g_hex, "join_result"), 0);
    Ok(())
}

/// WHY (r7c, Codex NEW 2): the bound covers revalidation after repair too.
/// The binding resolves at once from J's attestation; while the
/// send-readiness repair runs, a writer takes the authenticated-binding
/// store and holds it. The post-repair re-read must end in the typed,
/// retryable `recipient_undiscovered` inside the resolution bound, not wait
/// out the exchange deadline.
#[tokio::test]
async fn s8a_r7c_a_source_lock_held_after_resolution_ends_typed_within_the_bound(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    let g_hex = hex_of(&g.joiner);
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    g.authority
        .agent
        .record_authenticated_binding_for_testing(
            g.joiner.agent.agent_id(),
            g.joiner.agent.machine_id(),
            unix_secs_now(),
        )
        .await;
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(&[], true)
                .with_repair_delay(Duration::from_millis(600)),
        );
    let bindings = g
        .authority
        .agent
        .authenticated_machine_bindings_for_testing();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _held = bindings.write().await;
        let _ = tokio::time::timeout(Duration::from_secs(8), release_rx).await;
    });
    let (pre, seam) = (Arc::default(), Arc::default());
    let admission = counted_admission(Arc::clone(&pre), Arc::clone(&seam), true, true, None);
    clear_egress(&g.authority);
    let started = std::time::Instant::now();
    let outcome = super::super::send_join_artifact(
        &g.authority,
        &g.joiner.agent.agent_id(),
        b"adr0107-r7c-held-after-resolution",
        &g.stable,
        "join_result",
        admission,
        Instant::now() + Duration::from_secs(3),
    )
    .await;
    let elapsed = started.elapsed();
    let _ = release_tx.send(());
    holder.await?;
    assert!(
        outcome
            .as_ref()
            .is_err_and(|reason| reason.starts_with("recipient_undiscovered")),
        "a typed, retryable refusal: {outcome:?} after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2_800),
        "the post-repair re-read waited out the exchange deadline: {elapsed:?}"
    );
    assert_eq!(pre.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(egress_count(&g.authority, &g_hex, "join_result"), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// r7h (real-network re-run g10-1190b, finding 3): after an owner restart the
// Welcome stalled 85.8 s on the Offer and Complete frames, which still took
// the general DM path's resolver. Every owner Welcome frame must take the
// bounded, admitted, single-exchange path.
// ---------------------------------------------------------------------------

/// WHY (r7h): a cold-cache owner restart, then a Welcome fetch verified by
/// J2's attestation, whose binding lands 300 ms in. The Offer, and after
/// J2's final ChunkAck the Complete, must each be handed to the admitted
/// single-exchange transport, within the resolution bound. Before the fix,
/// both took `send_direct_with_config` (gossip inbox, ACK-v2 receipt with
/// internal retries).
#[tokio::test]
async fn s8a_r7h_owner_restart_welcome_offer_and_complete_take_the_admitted_path(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    let j2_hex = hex_of(&s.j2);
    let j2_id = s.j2.agent.agent_id();
    restart_cold(&s.authority, &s.j2, &s.stable).await;
    let welcome_id = welcome_id_of(&s.j2_add).expect("welcome ref");
    let total_chunks = {
        let welcomes = s.authority.pending_welcomes.read().await;
        let pending = welcomes
            .get(&welcome_id)
            .ok_or_else(|| anyhow::anyhow!("staged Welcome"))?;
        x0x::files::total_chunks_for_size(
            pending.bytes.len() as u64,
            x0x::files::DEFAULT_CHUNK_SIZE,
        )
    };
    clear_egress(&s.authority);
    clear_exchanges(&s.authority);
    let started = std::time::Instant::now();
    assert!(serve_welcome(&s.authority, &s.j2, &s.stable, &welcome_id).await);
    let authority = Arc::clone(&s.authority);
    let j2_machine = s.j2.agent.machine_id();
    let attest = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        authority
            .agent
            .record_authenticated_binding_for_testing(j2_id, j2_machine, unix_secs_now())
            .await;
    });
    let offered = egress_happens(
        &s.authority,
        &j2_hex,
        "welcome_offer",
        Duration::from_secs(4),
    )
    .await;
    let offered_after = started.elapsed();
    if offered && total_chunks > 0 {
        super::super::handle_welcome_blob_message(
            &s.authority,
            &j2_id,
            WelcomeBlobMessage::ChunkAck {
                welcome_id: welcome_id.clone(),
                sequence: total_chunks - 1,
            },
        )
        .await;
    }
    let completed = egress_happens(
        &s.authority,
        &j2_hex,
        "welcome_complete",
        Duration::from_secs(4),
    )
    .await;
    attest.await?;
    let wrong_transport: Vec<_> = transports_for(&s.authority, &j2_hex)
        .into_iter()
        .filter(|(kind, transport)| {
            kind.starts_with("welcome") && *transport != "pinned_single_exchange"
        })
        .collect();
    assert!(
        offered,
        "the Welcome Offer never reached the admitted transport ({offered_after:?})"
    );
    assert!(
        completed,
        "the Welcome Complete never reached the admitted transport"
    );
    assert!(wrong_transport.is_empty(), "{wrong_transport:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// #1207 / #1217 (v0.46.4): the GENERAL direct-send path failed at once with
// `err_agent_not_found` when a restart left the discovery cache cold. Opted-in
// sends (`Agent::send_direct_with_config_cold_wait`) now wait, within one absolute
// deadline, for a verified binding, as the pinned path does, and re-validate it
// against the final machine. Every other send still fails at once. The strict
// stand-in runs the general path's production resolution in process; the
// `general_cold_barrier` synchronises a test with the send's entry into the
// cold wait.
// ---------------------------------------------------------------------------

/// The general raw-QUIC payloads `from`'s strict stand-in delivered to `to`.
fn general_deliveries(from: &AppState, to: &AppState) -> Vec<Vec<u8>> {
    let to_id = to.agent.agent_id();
    from.agent
        .general_raw_standin_deliveries_for_testing()
        .into_iter()
        .filter(|(recipient, ..)| *recipient == to_id)
        .map(|(_, _, payload)| payload)
        .collect()
}

/// `holder` ingests `of`'s verified announcement, freshly seen (a stale
/// `last_seen` would trip the likely-offline gate, which is not under test).
async fn announce_fresh(holder: &AppState, of: &AppState) {
    let now = unix_secs_now();
    holder
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            agent_id: of.agent.agent_id(),
            machine_id: of.agent.machine_id(),
            user_id: None,
            self_name: None,
            addresses: Vec::new(),
            announced_at: now,
            last_seen: now,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: None,
        })
        .await;
}

/// Whether a general delivery carries `MemberRemoved`: inline, or (an
/// oversized event) as a control-blob reference to the staged event.
fn carries_member_removed(state: &AppState, payload: &[u8]) -> bool {
    if matches!(
        serde_json::from_slice::<NamedGroupMetadataEvent>(payload),
        Ok(NamedGroupMetadataEvent::MemberRemoved { .. })
    ) {
        return true;
    }
    match serde_json::from_slice::<super::super::control_blob::ControlBlobMessage>(payload) {
        Ok(super::super::control_blob::ControlBlobMessage::Reference { reference }) => state
            .control_blobs
            .staged_chunk(&reference, 0)
            .is_some_and(|chunk| chunk.starts_with(br#"{"event":"member_removed""#)),
        _ => false,
    }
}

/// Wait (bounded, generously) for a send from `sender` to `recipient` to
/// enter the general path's cold-recipient wait.
async fn entered_cold_wait(gate: &x0x::general_cold_barrier::Gate, what: &str) {
    let entered = tokio::time::timeout(Duration::from_secs(20), gate.reached.acquire()).await;
    match entered {
        Ok(Ok(permit)) => permit.forget(),
        _ => panic!("{what}: the send never entered the cold-recipient wait"),
    }
}

/// Wait (bounded, generously) for the scripted send-readiness repair to
/// enter (and park at) `gate`.
async fn repair_entered(gate: &x0x::PinnedRepairGate, what: &str) {
    let entered = tokio::time::timeout(Duration::from_secs(20), gate.reached.acquire()).await;
    match entered {
        Ok(Ok(permit)) => permit.forget(),
        _ => panic!("{what}: the send never reached the send-readiness repair"),
    }
}

/// J2's own Welcome `FetchRequest` for its sealed add (the exact payload the
/// apply sends).
fn j2_welcome_fetch_request(s: &Fixture) -> anyhow::Result<Vec<u8>> {
    let NamedGroupMetadataEvent::MemberAdded { group_id, .. } = &s.j2_add else {
        anyhow::bail!("J2's add is a MemberAdded");
    };
    let welcome_id =
        welcome_id_of(&s.j2_add).ok_or_else(|| anyhow::anyhow!("J2's Welcome by reference"))?;
    Ok(serde_json::to_vec(&WelcomeBlobMessage::FetchRequest {
        group_id: group_id.clone(),
        welcome_id,
    })?)
}

/// A restarted J2, cold to the authority, applies its own sealed add
/// (Welcome by reference, with the ADR 0106 carry) through the REAL
/// join-result path in a task, so the apply fetches the Welcome from the
/// authority. `gate` must already be armed for the fetch's cold wait. The
/// authority never answers the stand-in's FetchRequest, so the caller
/// aborts the task when done.
async fn apply_with_cold_welcome_fetch(s: &Fixture) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let served = serve_result(&s.authority, &s.j2, &s.stable, &s.j2_attempt, Some(s.base))
        .await
        .ok_or_else(|| anyhow::anyhow!("the authority serves J2's result"))?;
    let (j2, authority_id, attempt) = (Arc::clone(&s.j2), s.authority_id, s.j2_attempt.clone());
    Ok(tokio::spawn(async move {
        deliver(&j2, &authority_id, served, &attempt).await;
    }))
}

/// Wait (bounded, generously) until `from`'s stand-in delivered `payload`
/// to `to`.
async fn delivered_within(from: &AppState, to: &AppState, payload: &[u8], bound: Duration) -> bool {
    tokio::time::timeout(bound, async {
        while !general_deliveries(from, to).iter().any(|p| p == payload) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

/// WHY (#1207): a joiner that restarted recently has a cold view of the
/// authority. The Welcome FetchRequest of its own sealed add used to fail at
/// once (`err_agent_not_found`), and the retries stalled
/// (`fetch_retry_stalled`). Driven through the real join-result apply: the
/// authority's announcement is injected only after the fetch's cold wait
/// began; the FetchRequest must then reach the authority.
#[tokio::test]
async fn s8b_1207_restarted_joiner_fetch_request_reaches_the_authority_within_the_bound(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let expected = j2_welcome_fetch_request(&s)?;
    // Only the cold wait for THIS FetchRequest parks (its payload length, or
    // the resolve-only warm-up for it).
    let gate =
        x0x::general_cold_barrier::arm(s.j2.agent.agent_id(), s.authority_id, Some(expected.len()));
    let apply = apply_with_cold_welcome_fetch(&s).await?;
    entered_cold_wait(&gate, "the Welcome fetch").await;
    announce_fresh(&s.j2, &s.authority).await;
    gate.release();
    let delivered = delivered_within(&s.j2, &s.authority, &expected, Duration::from_secs(10)).await;
    x0x::general_cold_barrier::disarm(s.j2.agent.agent_id(), s.authority_id);
    apply.abort();
    assert!(delivered, "the FetchRequest never reached the authority");
    Ok(())
}

/// WHY (#1207, lock rule): a cold wait must never run under a lock. The
/// Welcome fetch runs inside the apply, under the group's membership lock,
/// so the wait for a restart-cold authority's binding must happen before
/// any guard is taken; the FetchRequest under the lock then waits for
/// nothing. While the fetch's cold wait is in progress: the group's
/// membership lock, the global roster-persistence lock and the
/// GSS-publication gate are free, and a mutation on another group
/// completes. The FetchRequest still reaches the authority afterwards.
#[tokio::test]
async fn s8b_1207_cold_welcome_fetch_waits_outside_the_membership_lock() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let expected = j2_welcome_fetch_request(&s)?;
    let gate =
        x0x::general_cold_barrier::arm(s.j2.agent.agent_id(), s.authority_id, Some(expected.len()));
    let apply = apply_with_cold_welcome_fetch(&s).await?;
    entered_cold_wait(&gate, "the Welcome fetch").await;

    let membership = super::super::group_membership_lock(&s.j2, &s.group_key).await;
    let membership_held = membership.try_lock().is_err();
    let roster_held = s.j2.named_groups_persistence_lock.try_lock().is_err();
    let gss_held = s.j2.gss_publication_gate.try_write().is_err();
    let other_group = tokio::time::timeout(
        Duration::from_secs(10),
        create_named_group(
            State(Arc::clone(&s.j2)),
            Json(CreateGroupRequest {
                name: "concurrent".to_string(),
                description: String::new(),
                display_name: None,
                preset: None,
                policy: None,
            }),
        ),
    )
    .await
    .map(|response| response.into_response().status());

    announce_fresh(&s.j2, &s.authority).await;
    gate.release();
    let delivered = delivered_within(&s.j2, &s.authority, &expected, Duration::from_secs(10)).await;
    x0x::general_cold_barrier::disarm(s.j2.agent.agent_id(), s.authority_id);
    apply.abort();
    assert!(
        !membership_held,
        "the group's membership lock was held during the cold wait"
    );
    assert!(
        !roster_held,
        "the roster-persistence lock was held during the cold wait"
    );
    assert!(
        !gss_held,
        "the GSS-publication gate was held during the cold wait"
    );
    assert!(
        matches!(other_group, Ok(status) if status == StatusCode::CREATED),
        "a mutation on another group did not complete during the cold wait: {other_group:?}"
    );
    assert!(delivered, "the FetchRequest never reached the authority");
    Ok(())
}

/// WHY (#1207, lock rule, causal replay; Codex r3 P3): the ADR 0028 replay
/// applies a queued `JoinRequestApproved` under the group's membership lock,
/// the queue-persistence lock, the global roster-persistence lock and the
/// GSS-publication gate. A VALID approval that seats THIS agent in a TreeKEM
/// group (the real authority approval, with its Welcome by reference) makes
/// the replay fetch the Welcome from the authority, cold to this agent. That
/// wait must run before the replay takes any guard; the FetchRequest must
/// then reach the authority. (The ADR 0028 queue writer admits only
/// non-TreeKEM approvals today, so the entry stands for a sidecar entry.)
#[tokio::test]
async fn s8b_1207_causal_replay_waits_for_a_cold_welcome_authority_before_its_guards(
) -> anyhow::Result<()> {
    let fixture = super::member_joined_treekem_fixture(0xd1, 0xd2).await?;
    let authority = Arc::clone(&fixture.state);
    let authority_id = authority.agent.agent_id();
    let authority_hex = hex::encode(authority_id.as_bytes());
    let (requester, _requester_dir) = super::secure_endpoint_test_state().await?;
    let requester_id = requester.agent.agent_id();
    let requester_hex = hex::encode(requester_id.as_bytes());
    requester
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    // R's pending request (with R's own TreeKEM KeyPackage) at the authority;
    // R holds the same pre-approval state.
    let group_bytes = hex::decode(&fixture.group_id)?;
    let seed = agent_treekem_seed(requester.agent.as_ref(), &group_bytes);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(requester_id, &seed)?;
    let mut request = x0x::groups::JoinRequest::new(
        fixture.group_id.clone(),
        requester_hex.clone(),
        None,
        now_millis_u64(),
    );
    request.treekem_key_package_b64 = Some(BASE64.encode(prepared.key_package_bytes()));
    let request_id = request.request_id.clone();
    let pre_approval = {
        let mut groups = authority.named_groups.write().await;
        let info = groups
            .get_mut(&fixture.group_id)
            .ok_or_else(|| anyhow::anyhow!("the authority's group"))?;
        info.join_requests.insert(request_id.clone(), request);
        info.clone()
    };
    requester
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), pre_approval);
    let (status, _) = super::super::approve_treekem_join_request(
        Arc::clone(&authority),
        fixture.group_id.clone(),
        request_id.clone(),
        authority_hex,
    )
    .await;
    anyhow::ensure!(status == StatusCode::OK, "the authority approves: {status}");
    let approval = authority
        .treekem_event_log
        .read()
        .await
        .get(&fixture.stable_group_id)
        .and_then(|events| {
            events
                .iter()
                .rev()
                .find(|event| {
                    matches!(
                        event,
                        NamedGroupMetadataEvent::JoinRequestApproved {
                            requester_agent_id, ..
                        } if *requester_agent_id == requester_hex
                    )
                })
                .cloned()
        })
        .ok_or_else(|| anyhow::anyhow!("the authority logged the approval"))?;
    let NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: event_group_id,
        revision,
        welcome_ref: Some(welcome_ref),
        ..
    } = &approval
    else {
        anyhow::bail!("a TreeKEM approval with a Welcome by reference");
    };
    let expected = serde_json::to_vec(&WelcomeBlobMessage::FetchRequest {
        group_id: event_group_id.clone(),
        welcome_id: welcome_ref.welcome_id.clone(),
    })?;
    let now_ms = now_millis_u64();
    let revision = *revision;
    requester
        .causal_approval_queue
        .write()
        .await
        .entry(fixture.group_id.clone())
        .or_default()
        .push_back(PendingCausalApproval {
            envelope_bytes: Vec::new(),
            digest: [0x5a; 32],
            byte_size: 0,
            event: approval,
            sender: authority_id,
            first_seen_ms: now_ms,
            expires_at_ms: now_ms + 600_000,
            request_id,
            requester_agent_id: requester_hex,
            revision,
            conflicted: false,
            conflicted_with: None,
        });
    // The cold wait for THIS FetchRequest parks here, wherever it runs.
    let gate = x0x::general_cold_barrier::arm(requester_id, authority_id, Some(expected.len()));
    let replay = {
        let (requester, group_key) = (Arc::clone(&requester), fixture.group_id.clone());
        tokio::spawn(async move {
            let mut cleared = std::collections::BTreeSet::new();
            super::super::replay_pending_causal_approvals(&requester, &group_key, &mut cleared)
                .await;
        })
    };
    entered_cold_wait(&gate, "the replay's Welcome fetch").await;
    let membership = super::super::group_membership_lock(&requester, &fixture.group_id).await;
    let membership_held = membership.try_lock().is_err();
    let queue_held = requester
        .causal_approval_queue_persistence_lock
        .try_lock()
        .is_err();
    let roster_held = requester.named_groups_persistence_lock.try_lock().is_err();
    let gss_held = requester.gss_publication_gate.try_write().is_err();
    announce_fresh(&requester, &authority).await;
    gate.release();
    let delivered =
        delivered_within(&requester, &authority, &expected, Duration::from_secs(10)).await;
    x0x::general_cold_barrier::disarm(requester_id, authority_id);
    replay.abort();
    assert!(
        !membership_held,
        "the replay held the membership lock during the wait"
    );
    assert!(
        !queue_held,
        "the replay held the queue-persistence lock during the wait"
    );
    assert!(
        !roster_held,
        "the replay held the roster-persistence lock during the wait"
    );
    assert!(
        !gss_held,
        "the replay held the GSS-publication gate during the wait"
    );
    assert!(
        delivered,
        "the replay's FetchRequest never reached the authority"
    );
    Ok(())
}

/// J2's sealed add, with its Welcome reference naming `source`.
fn j2_add_from_source(s: &Fixture, source: &str) -> anyhow::Result<NamedGroupMetadataEvent> {
    let mut event = s.j2_add.clone();
    let NamedGroupMetadataEvent::MemberAdded {
        welcome_ref: Some(welcome_ref),
        ..
    } = &mut event
    else {
        anyhow::bail!("J2's add carries a Welcome by reference");
    };
    welcome_ref.source = source.to_string();
    Ok(event)
}

/// An event for a group of J2's own, unrelated to the Home group, as the
/// shared listener would next apply it.
async fn unrelated_group_event(s: &Fixture) -> anyhow::Result<NamedGroupMetadataEvent> {
    let created = create_named_group(
        State(Arc::clone(&s.j2)),
        Json(CreateGroupRequest {
            name: "unrelated".to_string(),
            description: String::new(),
            display_name: None,
            preset: None,
            policy: None,
        }),
    )
    .await
    .into_response();
    let status = created.status();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(created.into_body(), usize::MAX).await?)?;
    anyhow::ensure!(status == StatusCode::CREATED, "create: {status} {body}");
    let key = body["group_id"].as_str().unwrap_or_default().to_string();
    let stable =
        s.j2.named_groups
            .read()
            .await
            .get(&key)
            .map(|info| info.stable_group_id().to_string())
            .ok_or_else(|| anyhow::anyhow!("the unrelated group"))?;
    let mut event = s.j1_add.clone();
    if let NamedGroupMetadataEvent::MemberAdded { group_id, .. } = &mut event {
        *group_id = stable;
    }
    Ok(event)
}

/// Apply `events` one after another, as the shared direct metadata listener
/// does (inline), then `next`. Returns when `next` was applied, measured
/// from the start.
async fn listener_reaches(
    s: &Fixture,
    events: Vec<NamedGroupMetadataEvent>,
    next: NamedGroupMetadataEvent,
) -> Duration {
    let started = std::time::Instant::now();
    for event in events {
        let _ = apply_named_group_metadata_event(&s.j2, event, s.authority_id, true, None).await;
    }
    let _ = apply_named_group_metadata_event(&s.j2, next, s.authority_id, true, None).await;
    started.elapsed()
}

/// WHY (#1207, Codex r3 P2-2(a)): an authenticated admin can send
/// self-seating events whose Welcome reference names a source that cannot
/// be the group's authority. The node must reject them before any wait, so
/// they cannot hold up the shared listener and, with it, an unrelated
/// group's event.
#[tokio::test]
async fn s8b_1207_bogus_self_seating_events_do_not_delay_an_unrelated_group() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let j2_id = s.j2.agent.agent_id();
    let mut bogus = Vec::new();
    let mut gates = Vec::new();
    for _ in 0..4 {
        let unknown = x0x::identity::AgentKeypair::generate()?.agent_id();
        bogus.push(j2_add_from_source(&s, &hex::encode(unknown.as_bytes()))?);
        // Count the cold waits (a released gate counts each and lets it pass).
        let gate = x0x::general_cold_barrier::arm(
            j2_id,
            unknown,
            Some(x0x::general_cold_barrier::WARM_UP),
        );
        gate.release();
        gates.push((unknown, gate));
    }
    let next = unrelated_group_event(&s).await?;
    let reached = listener_reaches(&s, bogus, next).await;
    let waits: usize = gates
        .iter()
        .map(|(_, gate)| gate.reached.available_permits())
        .sum();
    for (unknown, _) in &gates {
        x0x::general_cold_barrier::disarm(j2_id, *unknown);
    }
    assert_eq!(waits, 0, "bogus Welcome sources were waited for");
    assert!(
        reached < Duration::from_secs(3),
        "an unrelated group's event waited {reached:?} behind bogus self-seating events"
    );
    Ok(())
}

/// WHY (#1207, Codex r3 P2-2(b)): repeated self-seating events that name a
/// real admin of the group as the Welcome source, but are rejected by the
/// apply (here: a tampered commit), must not each cost a cold wait on the
/// shared listener. At most one wait per source runs within the cap.
#[tokio::test]
async fn s8b_1207_waits_for_one_cold_admin_source_are_capped() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let mut rejected = Vec::new();
    for attempt in 0..4u64 {
        let mut event = j2_add_from_source(&s, &hex_of(&s.authority))?;
        if let NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } = &mut event
        {
            commit.committed_at = commit.committed_at.saturating_add(attempt + 1);
        }
        rejected.push(event);
    }
    let next = unrelated_group_event(&s).await?;
    let gate = x0x::general_cold_barrier::arm(
        s.j2.agent.agent_id(),
        s.authority_id,
        Some(x0x::general_cold_barrier::WARM_UP),
    );
    gate.release();
    let reached = listener_reaches(&s, rejected, next).await;
    let waits = gate.reached.available_permits();
    x0x::general_cold_barrier::disarm(s.j2.agent.agent_id(), s.authority_id);
    assert!(
        waits <= 1,
        "{waits} cold waits ran for one cold admin source (listener reached the next event after {reached:?})"
    );
    assert!(
        reached < super::super::COLD_RECIPIENT_WAIT + Duration::from_secs(4),
        "the listener reached the next event only after {reached:?}"
    );
    Ok(())
}

/// WHY (#1217): after an owner restart, the class-D `MemberRemoved` notice
/// to a member removed just after it joined goes through the general direct
/// path (opted in) plus gossip. Its direct leg failed `recipient_undiscovered`
/// at once, and the next attempts are due at +6 s and +8 s. The member's
/// announcement is injected after the initial leg entered the cold wait, so
/// that leg must deliver the notice.
#[tokio::test]
async fn s8b_1217_restarted_owner_member_removed_direct_delivers_within_the_bound(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.authority, &s.j2, &s.stable).await;
    // Every cold send to J2 parks while armed, so none can deliver before
    // the announcement; MemberRemoved's initial leg is among them.
    let gate = x0x::general_cold_barrier::arm(s.authority_id, s.j2.agent.agent_id(), None);
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), hex_of(&s.j2))),
    )
    .await
    .into_response();
    anyhow::ensure!(
        removed.status().is_success(),
        "owner remove-member: {}",
        removed.status()
    );
    entered_cold_wait(&gate, "MemberRemoved").await;
    // The removal spawned its initial leg before it returned; let every
    // spawned leg reach the barrier (it cannot pass while armed).
    tokio::time::sleep(Duration::from_millis(500)).await;
    announce_fresh(&s.authority, &s.j2).await;
    let released = std::time::Instant::now();
    gate.release();
    let delivered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if general_deliveries(&s.authority, &s.j2)
                .iter()
                .any(|payload| carries_member_removed(&s.authority, payload))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    x0x::general_cold_barrier::disarm(s.authority_id, s.j2.agent.agent_id());
    assert!(
        delivered,
        "the parked MemberRemoved leg never delivered ({:?} after release)",
        released.elapsed()
    );
    Ok(())
}

/// WHY (#1207 control): an OPTED-IN send to a truly unknown agent gets its
/// bounded wait (5 s), then the typed, retryable `RecipientUndiscovered`.
/// It must wait at least the bound and then complete; the upper limit is
/// deliberately loose for loaded runners.
#[tokio::test]
async fn s8b_1207_unknown_agent_ends_in_the_typed_error_within_the_bound() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    g.authority
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    let unknown = x0x::identity::AgentId([0x3c; 32]);
    let started = std::time::Instant::now();
    let outcome = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &unknown,
            b"adr0107-1207-unknown".to_vec(),
            direct_message_send_config(),
            super::super::COLD_RECIPIENT_WAIT,
        )
        .await;
    let elapsed = started.elapsed();
    assert!(
        matches!(outcome, Err(x0x::dm::DmError::RecipientUndiscovered(_))),
        "a typed, retryable error: {outcome:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(4_500),
        "the unknown recipient got no bounded wait: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "the wait did not complete: {elapsed:?}"
    );
    Ok(())
}

/// WHY (#1207 control, opt-in): a send that does NOT opt in keeps today's
/// behaviour for an unknown recipient: the typed error at once, never
/// entering the cold wait.
#[tokio::test]
async fn s8b_1207_a_send_that_does_not_opt_in_still_fails_at_once() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    g.authority
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    let unknown = x0x::identity::AgentId([0x3d; 32]);
    let gate = x0x::general_cold_barrier::arm(g.authority.agent.agent_id(), unknown, None);
    gate.release();
    let started = std::time::Instant::now();
    let outcome = g
        .authority
        .agent
        .send_direct_with_config(
            &unknown,
            b"adr0107-1207-not-opted-in".to_vec(),
            direct_message_send_config(),
        )
        .await;
    let elapsed = started.elapsed();
    let entered = gate.reached.available_permits();
    x0x::general_cold_barrier::disarm(g.authority.agent.agent_id(), unknown);
    assert!(
        matches!(outcome, Err(x0x::dm::DmError::RecipientUndiscovered(_))),
        "a typed, retryable error: {outcome:?}"
    );
    assert_eq!(
        entered, 0,
        "a send that did not opt in entered the cold wait"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "a send that did not opt in waited: {elapsed:?}"
    );
    Ok(())
}

/// WHY (#1207 control): an opted-in DM to a KNOWN agent never enters the
/// cold wait, so its latency is unchanged.
#[tokio::test]
async fn s8b_1207_known_agent_send_latency_is_unchanged() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    g.authority
        .agent
        .set_pinned_standin_strict_resolution_for_testing(true);
    // A freshly seen, announced peer (a stale `last_seen` would trip the
    // likely-offline gate, which is not under test here).
    let now = unix_secs_now();
    g.authority
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            agent_id: g.joiner.agent.agent_id(),
            machine_id: g.joiner.agent.machine_id(),
            user_id: None,
            self_name: None,
            addresses: Vec::new(),
            announced_at: now,
            last_seen: now,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: None,
        })
        .await;
    let gate = x0x::general_cold_barrier::arm(
        g.authority.agent.agent_id(),
        g.joiner.agent.agent_id(),
        None,
    );
    gate.release();
    let payload = b"adr0107-1207-known".to_vec();
    let started = std::time::Instant::now();
    let outcome = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &g.joiner.agent.agent_id(),
            payload.clone(),
            direct_message_send_config(),
            super::super::COLD_RECIPIENT_WAIT,
        )
        .await;
    let elapsed = started.elapsed();
    let entered = gate.reached.available_permits();
    x0x::general_cold_barrier::disarm(g.authority.agent.agent_id(), g.joiner.agent.agent_id());
    assert!(outcome.is_ok(), "the known agent's DM failed: {outcome:?}");
    assert!(
        general_deliveries(&g.authority, &g.joiner).contains(&payload),
        "the known agent's DM never reached it"
    );
    assert_eq!(entered, 0, "a known agent's send entered the cold wait");
    assert!(
        elapsed < Duration::from_secs(3),
        "known-agent latency changed: {elapsed:?}"
    );
    Ok(())
}

/// How the binding or the machine changes during the general path's repair
/// (or before it), for the re-validation control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdBindingChange {
    /// The retained machine was revoked before the send.
    MachineRevokedBefore,
    /// The recipient's agent was revoked before the send.
    AgentRevokedBefore,
    /// The machine is revoked while the send-readiness repair runs.
    MachineRevokedDuringRepair,
    /// A newer attestation with an expired certificate lands during repair.
    ExpiredDuringRepair,
    /// A connected DM-registry machine appears during repair, and the
    /// production redial switches to it (final-machine substitution).
    SubstitutedDuringRepair,
}

/// WHY (#1207 control, P1): the bounded wait reads retained verified bindings
/// (the announced-binding store, ADR-0021 attestations), which revocation
/// does not evict, and further awaits (repair, redial) follow it. The
/// binding must be re-validated against the FINAL machine before
/// transmission: agent and machine revocation, certificate expiry, a changed
/// binding, a substituted machine. In every case nothing is delivered.
#[tokio::test]
async fn s8b_1207_a_revoked_machine_learned_by_the_wait_is_refused() -> anyhow::Result<()> {
    let mut wrong = Vec::new();
    for case in [
        ColdBindingChange::MachineRevokedBefore,
        ColdBindingChange::AgentRevokedBefore,
        ColdBindingChange::MachineRevokedDuringRepair,
        ColdBindingChange::ExpiredDuringRepair,
        ColdBindingChange::SubstitutedDuringRepair,
    ] {
        let dir = tempfile::tempdir()?;
        let g = build_gss(dir.path(), false).await?;
        restart_cold(&g.authority, &g.joiner, &g.stable).await;
        pin_recipient_machine(&g.authority, &g.joiner).await;
        let joiner_id = g.joiner.agent.agent_id();
        let authority_id = g.authority.agent.agent_id();
        g.authority
            .agent
            .identity_discovery_cache()
            .write()
            .await
            .remove(&joiner_id);
        let substitute = x0x::identity::MachineId([0xa9; 32]);
        let repair = x0x::PinnedRepairGate::new();
        let during_repair = matches!(
            case,
            ColdBindingChange::MachineRevokedDuringRepair
                | ColdBindingChange::ExpiredDuringRepair
                | ColdBindingChange::SubstitutedDuringRepair
        );
        if during_repair {
            // B is not connected; the repair parks on entry until the
            // change below has landed. It connects B, except in the
            // substitution case, where it fails so that the production
            // redial runs and switches to the connected substitute.
            let repair_connects = case != ColdBindingChange::SubstitutedDuringRepair;
            g.authority
                .agent
                .script_pinned_standin_transport_for_testing(
                    x0x::PinnedTransportScript::connected_only(&[substitute], repair_connects)
                        .with_repair_gate(Arc::clone(&repair)),
                );
        }
        match case {
            ColdBindingChange::MachineRevokedBefore => {
                revoke_machine(&g.authority, &g.joiner).await?;
            }
            ColdBindingChange::AgentRevokedBefore => {
                let kp = g.joiner.agent.identity().agent_keypair().to_bytes();
                revoke_agent(&g.authority, &kp).await?;
            }
            _ => {}
        }
        let gate = x0x::general_cold_barrier::arm(authority_id, joiner_id, None);
        let payload = format!("adr0107-1207-{case:?}").into_bytes();
        let send = {
            let (authority, payload) = (Arc::clone(&g.authority), payload.clone());
            tokio::spawn(async move {
                authority
                    .agent
                    .send_direct_with_config_cold_wait(
                        &joiner_id,
                        payload,
                        direct_message_send_config(),
                        super::super::COLD_RECIPIENT_WAIT,
                    )
                    .await
            })
        };
        entered_cold_wait(&gate, &format!("{case:?}")).await;
        gate.release();
        if during_repair {
            // The binding resolved; the repair is under way (parked).
            repair_entered(&repair, &format!("{case:?}")).await;
            match case {
                ColdBindingChange::MachineRevokedDuringRepair => {
                    revoke_machine(&g.authority, &g.joiner).await?;
                }
                ColdBindingChange::ExpiredDuringRepair => {
                    let now = unix_secs_now();
                    g.authority
                        .agent
                        .record_authenticated_binding_with_expiry_for_testing(
                            joiner_id,
                            g.joiner.agent.machine_id(),
                            now,
                            Some(now - 86_400),
                        )
                        .await;
                }
                ColdBindingChange::SubstitutedDuringRepair => {
                    g.authority
                        .agent
                        .direct_messaging()
                        .mark_connected(joiner_id, substitute)
                        .await;
                }
                _ => {}
            }
            repair.release();
        }
        let outcome = send.await?;
        x0x::general_cold_barrier::disarm(authority_id, joiner_id);
        if outcome.is_ok() || general_deliveries(&g.authority, &g.joiner).contains(&payload) {
            wrong.push(format!("[{case:?}] delivered: {outcome:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "a send was delivered past a revoked, expired, changed or substituted binding: {wrong:?}"
    );
    Ok(())
}

/// WHY (#1207, P2): ONE absolute deadline bounds every resolution read of an
/// opted-in send, including the ADR-0043 B/P check after re-validation,
/// which reads the move-state store. A writer holding that store must end
/// the send by the deadline (a typed, retryable error), never hold it on
/// indefinitely. The store is taken while the repair is parked, after the
/// first B/P check passed.
#[tokio::test]
async fn s8b_1207_a_held_pairing_store_ends_the_send_by_the_deadline() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let joiner_id = g.joiner.agent.agent_id();
    g.authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .remove(&joiner_id);
    let repair = x0x::PinnedRepairGate::new();
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(&[], true)
                .with_repair_gate(Arc::clone(&repair)),
        );
    let payload = b"adr0107-1207-held-pairing-store".to_vec();
    let started = std::time::Instant::now();
    let mut send = {
        let (authority, payload) = (Arc::clone(&g.authority), payload.clone());
        tokio::spawn(async move {
            authority
                .agent
                .send_direct_with_config_cold_wait(
                    &joiner_id,
                    payload,
                    direct_message_send_config(),
                    super::super::COLD_RECIPIENT_WAIT,
                )
                .await
        })
    };
    repair_entered(&repair, "held pairing store").await;
    let move_state = g.authority.agent.move_state();
    let held = move_state.write().await;
    repair.release();
    // The deadline, plus generous slack for a loaded runner.
    let bound = super::super::COLD_RECIPIENT_WAIT + Duration::from_secs(3);
    let ended = tokio::time::timeout(bound.saturating_sub(started.elapsed()), &mut send).await;
    let ended_after = started.elapsed();
    drop(held);
    let outcome = match ended {
        Ok(joined) => Some(joined?),
        Err(_) => {
            let _ = send.await;
            None
        }
    };
    let delivered = general_deliveries(&g.authority, &g.joiner).contains(&payload);
    assert!(
        outcome.is_some(),
        "the send was still waiting on the held store {ended_after:?} after it started"
    );
    assert!(
        matches!(outcome, Some(Err(_))) && !delivered,
        "a send past a held pairing store must fail, not deliver: {outcome:?}"
    );
    Ok(())
}

/// WHY (#1207, lock rule): a send under a lock opts in with a ZERO cold
/// wait. It must wait for nothing, yet find a verified binding that the
/// pre-lock wait learned, including one that only an ADR-0021 attestation
/// holds (no discovery-cache or DM-registry entry), which an ordinary send
/// cannot use. A truly unknown recipient still fails at once.
#[tokio::test]
async fn s8b_1207_a_zero_wait_send_finds_an_attested_binding_without_waiting() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    let joiner_id = g.joiner.agent.agent_id();
    let now = unix_secs_now();
    g.authority
        .agent
        .record_authenticated_binding_with_expiry_for_testing(
            joiner_id,
            g.joiner.agent.machine_id(),
            now,
            Some(now + 86_400),
        )
        .await;
    let payload = b"adr0107-1207-zero-wait-attested".to_vec();
    let started = std::time::Instant::now();
    let attested = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &joiner_id,
            payload.clone(),
            direct_message_send_config(),
            Duration::ZERO,
        )
        .await;
    let attested_took = started.elapsed();
    let unknown = x0x::identity::AgentId([0x7c; 32]);
    let started = std::time::Instant::now();
    let unknown_outcome = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &unknown,
            b"adr0107-1207-zero-wait-unknown".to_vec(),
            direct_message_send_config(),
            Duration::ZERO,
        )
        .await;
    let unknown_took = started.elapsed();
    // No wait at all; the limit is loose for loaded runners, and far below
    // the 5 s cold wait.
    let no_wait = Duration::from_millis(2_500);
    assert!(
        attested.is_ok() && general_deliveries(&g.authority, &g.joiner).contains(&payload),
        "a zero-wait send did not use the attested binding: {attested:?}"
    );
    assert!(
        attested_took < no_wait,
        "the zero-wait send waited {attested_took:?}"
    );
    assert!(
        matches!(
            unknown_outcome,
            Err(x0x::dm::DmError::RecipientUndiscovered(_))
        ),
        "an unknown recipient: {unknown_outcome:?}"
    );
    assert!(
        unknown_took < no_wait,
        "a zero-wait send to an unknown recipient waited {unknown_took:?}"
    );
    Ok(())
}

/// WHY (#1207, Codex r3 P2-1): the one deadline also bounds the resolution
/// reads of the discovery redial that follows a failed repair. A writer
/// holding the DM registry while the repair runs (after the first reads)
/// must end the send by the deadline, not hold it in the redial's registry
/// read. (Codex r4: the recipient is a known one, whose send redials; a
/// cold-recipient binding is never redialled.)
#[tokio::test]
async fn s8b_1207_a_held_registry_during_the_redial_ends_the_send_by_the_deadline(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    announce_fresh(&g.authority, &g.joiner).await;
    let joiner_id = g.joiner.agent.agent_id();
    let repair = x0x::PinnedRepairGate::new();
    // The repair fails, so the production redial runs.
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(&[], false)
                .with_repair_gate(Arc::clone(&repair)),
        );
    let payload = b"adr0107-1207-held-registry-redial".to_vec();
    let started = std::time::Instant::now();
    let mut send = {
        let (authority, payload) = (Arc::clone(&g.authority), payload.clone());
        tokio::spawn(async move {
            authority
                .agent
                .send_direct_with_config_cold_wait(
                    &joiner_id,
                    payload,
                    direct_message_send_config(),
                    super::super::COLD_RECIPIENT_WAIT,
                )
                .await
        })
    };
    repair_entered(&repair, "held registry").await;
    let registry = Arc::clone(g.authority.agent.direct_messaging());
    let held = registry.hold_registry_for_testing().await;
    repair.release();
    let bound = super::super::COLD_RECIPIENT_WAIT + Duration::from_secs(3);
    let ended = tokio::time::timeout(bound.saturating_sub(started.elapsed()), &mut send).await;
    let ended_after = started.elapsed();
    drop(held);
    let outcome = match ended {
        Ok(joined) => Some(joined?),
        Err(_) => {
            let _ = send.await;
            None
        }
    };
    let delivered = general_deliveries(&g.authority, &g.joiner).contains(&payload);
    assert!(
        outcome.is_some(),
        "the send was still waiting on the held registry {ended_after:?} after it started"
    );
    assert!(
        matches!(outcome, Some(Err(_))) && !delivered,
        "a send past a held registry must fail, not deliver: {outcome:?}"
    );
    Ok(())
}

/// WHY (#1207, Codex r4 (ii)): under a lock (a ZERO cold wait) a binding the
/// read-once found for a cold recipient is used only while its machine is
/// connected. The send must not repair or redial it (a wait, and the
/// redial's reads, newly on this path), and fails at once, retryably.
#[tokio::test]
async fn s8b_1207_a_zero_wait_send_never_repairs_or_redials_a_cold_binding() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    let joiner_id = g.joiner.agent.agent_id();
    let now = unix_secs_now();
    g.authority
        .agent
        .record_authenticated_binding_with_expiry_for_testing(
            joiner_id,
            g.joiner.agent.machine_id(),
            now,
            Some(now + 86_400),
        )
        .await;
    let repair = x0x::PinnedRepairGate::new();
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(&[], true)
                .with_repair_gate(Arc::clone(&repair)),
        );
    let payload = b"adr0107-1207-zero-wait-cold-unconnected".to_vec();
    let started = std::time::Instant::now();
    let mut send = {
        let (authority, payload) = (Arc::clone(&g.authority), payload.clone());
        tokio::spawn(async move {
            authority
                .agent
                .send_direct_with_config_cold_wait(
                    &joiner_id,
                    payload,
                    direct_message_send_config(),
                    Duration::ZERO,
                )
                .await
        })
    };
    let ended = tokio::time::timeout(Duration::from_secs(2), &mut send).await;
    let ended_after = started.elapsed();
    let repaired = repair.reached.available_permits();
    repair.release();
    let outcome = match ended {
        Ok(joined) => Some(joined?),
        Err(_) => {
            let _ = send.await;
            None
        }
    };
    assert_eq!(repaired, 0, "the zero-wait send repaired a cold binding");
    assert!(
        matches!(
            outcome,
            Some(Err(x0x::dm::DmError::RecipientUndiscovered(_)))
        ),
        "a zero-wait send to an unconnected cold binding must fail at once, retryably \
         ({ended_after:?}): {outcome:?}"
    );
    assert!(!general_deliveries(&g.authority, &g.joiner).contains(&payload));
    Ok(())
}

/// WHY (#1207, Codex r4 P3): the cooldown map for pre-lock Welcome waits has
/// an aggregate bound (256 sources). While it is full of sources still in
/// their cooldown, a new source gets no wait; once their cooldowns expire,
/// they are evicted and a new source waits again.
#[tokio::test]
async fn s8b_1207_the_cold_wait_map_is_capped() -> anyhow::Result<()> {
    const BOUND: usize = 256;
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let rejected = |attempt: u64| -> anyhow::Result<NamedGroupMetadataEvent> {
        let mut event = j2_add_from_source(&s, &hex_of(&s.authority))?;
        if let NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } = &mut event
        {
            commit.committed_at = commit.committed_at.saturating_add(attempt + 1);
        }
        Ok(event)
    };
    let fill = |at: std::time::Instant| -> anyhow::Result<()> {
        let mut waits =
            s.j2.cold_welcome_waits
                .lock()
                .map_err(|_| anyhow::anyhow!("cold wait map"))?;
        waits.clear();
        for _ in 0..BOUND {
            waits.insert(
                x0x::identity::AgentKeypair::generate()?.agent_id(),
                Some(at),
            );
        }
        Ok(())
    };
    let j2_id = s.j2.agent.agent_id();
    // Full of sources still cooling: no wait for a new source.
    fill(std::time::Instant::now())?;
    let gate = x0x::general_cold_barrier::arm(
        j2_id,
        s.authority_id,
        Some(x0x::general_cold_barrier::WARM_UP),
    );
    gate.release();
    let started = std::time::Instant::now();
    let _ = apply_named_group_metadata_event(&s.j2, rejected(0)?, s.authority_id, true, None).await;
    let full_took = started.elapsed();
    let waits_when_full = gate.reached.available_permits();
    let len_when_full = s.j2.cold_welcome_waits.lock().map(|w| w.len()).unwrap_or(0);
    // Full of expired cooldowns: they are evicted, and the new source waits.
    let expired = std::time::Instant::now().checked_sub(Duration::from_secs(61));
    let mut waits_when_expired = None;
    if let Some(expired) = expired {
        fill(expired)?;
        let _ =
            apply_named_group_metadata_event(&s.j2, rejected(1)?, s.authority_id, true, None).await;
        waits_when_expired = Some(gate.reached.available_permits() - waits_when_full);
    }
    let len_after = s.j2.cold_welcome_waits.lock().map(|w| w.len()).unwrap_or(0);
    x0x::general_cold_barrier::disarm(j2_id, s.authority_id);
    assert_eq!(
        waits_when_full, 0,
        "a full cooldown map still admitted a wait ({full_took:?})"
    );
    assert!(
        len_when_full <= BOUND,
        "the map grew past its bound: {len_when_full}"
    );
    if let Some(waits) = waits_when_expired {
        assert_eq!(
            waits, 1,
            "expired cooldowns were not evicted for a new wait"
        );
        assert!(len_after <= 1, "expired cooldowns were kept: {len_after}");
    }
    Ok(())
}

/// WHY (#1207, Codex r5 P2-2): a binding that the wait found for a cold
/// recipient is newly repaired (unreachable at v0.46.3). That repair must
/// end at the same absolute deadline, not with a fresh three-second budget.
/// The repair never completes here; the send uses a 1 s wait.
#[tokio::test]
async fn s8b_1207_a_cold_binding_repair_ends_at_the_deadline() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let joiner_id = g.joiner.agent.agent_id();
    g.authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .remove(&joiner_id);
    let repair = x0x::PinnedRepairGate::new();
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(
            x0x::PinnedTransportScript::connected_only(&[], true)
                .with_repair_gate(Arc::clone(&repair)),
        );
    let payload = b"adr0107-1207-cold-binding-repair".to_vec();
    let started = std::time::Instant::now();
    let outcome = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &joiner_id,
            payload.clone(),
            direct_message_send_config(),
            Duration::from_secs(1),
        )
        .await;
    let took = started.elapsed();
    let repaired = repair.reached.available_permits();
    repair.release();
    assert!(
        repaired >= 1,
        "control: the send repaired the bound machine"
    );
    assert!(
        took < Duration::from_millis(2_200),
        "the cold binding's repair ran past the 1 s deadline: {took:?}"
    );
    assert!(
        matches!(outcome, Err(x0x::dm::DmError::RecipientUndiscovered(_))),
        "{outcome:?}"
    );
    assert!(!general_deliveries(&g.authority, &g.joiner).contains(&payload));
    Ok(())
}

/// WHY (#1207, Codex r5 P3): while the cooldown map is full, a new Welcome
/// source gets no wait, but it must still make progress: the node starts a
/// background Lookup for it (permit-bounded, nothing waits on it), so a
/// zero-wait FetchRequest retry can find the evidence later. The source is
/// a second admin of the group, which nothing else on the node contacts.
#[tokio::test]
async fn s8b_1207_a_full_cold_wait_map_still_starts_a_lookup() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = build(dir.path()).await?;
    restart_cold(&s.j2, &s.authority, &s.stable).await;
    let authority_id = s.authority_id;
    let source = x0x::identity::AgentKeypair::generate()?.agent_id();
    let source_hex = hex::encode(source.as_bytes());
    s.j2.named_groups
        .write()
        .await
        .get_mut(&s.group_key)
        .ok_or_else(|| anyhow::anyhow!("J2's group row"))?
        .add_member(
            source_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(hex_of(&s.authority)),
            None,
        );
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let lookups = Arc::clone(&lookups);
        let responder = Arc::new(
            move |agent: x0x::identity::AgentId| -> futures::future::BoxFuture<'static, ()> {
                if agent == source {
                    lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Box::pin(async {})
            },
        );
        anyhow::ensure!(
            s.j2.agent
                .peer_evidence()
                .lookup_responder
                .set(responder)
                .is_ok(),
            "lookup responder"
        );
    }
    {
        let mut waits =
            s.j2.cold_welcome_waits
                .lock()
                .map_err(|_| anyhow::anyhow!("cold wait map"))?;
        let now = std::time::Instant::now();
        for _ in 0..256 {
            waits.insert(
                x0x::identity::AgentKeypair::generate()?.agent_id(),
                Some(now),
            );
        }
    }
    let mut event = j2_add_from_source(&s, &source_hex)?;
    if let NamedGroupMetadataEvent::MemberAdded {
        commit: Some(commit),
        ..
    } = &mut event
    {
        commit.committed_at = commit.committed_at.saturating_add(1);
    }
    let gate = x0x::general_cold_barrier::arm(
        s.j2.agent.agent_id(),
        source,
        Some(x0x::general_cold_barrier::WARM_UP),
    );
    gate.release();
    let started = std::time::Instant::now();
    let _ = apply_named_group_metadata_event(&s.j2, event, authority_id, true, None).await;
    let took = started.elapsed();
    let waits = gate.reached.available_permits();
    let kicked = tokio::time::timeout(Duration::from_secs(5), async {
        while lookups.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    x0x::general_cold_barrier::disarm(s.j2.agent.agent_id(), source);
    assert_eq!(waits, 0, "a full cooldown map admitted a wait ({took:?})");
    assert!(
        kicked,
        "a source refused by a full cooldown map got no Lookup: no progress"
    );
    Ok(())
}

/// WHY (#1207, #1217, Codex r5 P2-2 control): why a cold binding's repair is
/// bounded by the deadline rather than skipped. The wait finds the
/// recipient's binding (here at once, from its announced identity) but its
/// machine is not connected: the wait's own connect attempt ran before the
/// binding was known. The repair, inside the deadline, is the step that
/// connects it, so the send must deliver.
#[tokio::test]
async fn s8b_1207_a_cold_binding_whose_repair_connects_is_delivered() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let g = build_gss(dir.path(), false).await?;
    restart_cold(&g.authority, &g.joiner, &g.stable).await;
    pin_recipient_machine(&g.authority, &g.joiner).await;
    let joiner_id = g.joiner.agent.agent_id();
    g.authority
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .remove(&joiner_id);
    g.authority
        .agent
        .script_pinned_standin_transport_for_testing(x0x::PinnedTransportScript::connected_only(
            &[],
            true,
        ));
    let payload = b"adr0107-1207-cold-binding-repaired".to_vec();
    let outcome = g
        .authority
        .agent
        .send_direct_with_config_cold_wait(
            &joiner_id,
            payload.clone(),
            direct_message_send_config(),
            super::super::COLD_RECIPIENT_WAIT,
        )
        .await;
    assert!(
        outcome.is_ok() && general_deliveries(&g.authority, &g.joiner).contains(&payload),
        "a cold binding whose repair connects was not delivered: {outcome:?}"
    );
    Ok(())
}
