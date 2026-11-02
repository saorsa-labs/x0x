//! A live flush reply and a waited OLD child together permit start. Neither
//! a record read nor a PID supplied by a caller can construct this receipt.
//! The reply is bound to the frozen plan; the socket peer itself is not
//! authenticated (SO_PEERCRED is an S3c prerequisite).
use super::*;
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Child;
use std::time::{Duration, Instant};

pub(super) struct Reaped {
    instance: String,
    binding: Binding,
    old: Identity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    receipt: Receipt,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    binding: ReceiptBinding,
    receipt_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBinding {
    transaction_id: String,
    generation: u64,
    plan_sha256: [u8; 32],
}

pub(super) fn fixture_receipt(bytes: &[u8]) -> io::Result<serde_json::Value> {
    #[derive(Deserialize)]
    struct Request {
        token: String,
        transaction_id: String,
        generation: u64,
        instance_id: String,
        plan: journal::FrozenPlan,
    }
    let r: Request = serde_json::from_slice(bytes)?;
    if r.token != "inert launcher fixture" {
        return Err(invalid("bad fixture credential"));
    }
    Ok(
        serde_json::json!({"binding": {"transaction_id": r.transaction_id,
        "generation": r.generation, "plan_sha256": digest(&(r.instance_id, r.plan))?},
        "receipt_id": "fixture-flush"}),
    )
}

/// The stable parent already owns this OLD Child. This function never adopts
/// an unrelated PID. It persists the original budget before requesting stop.
pub(super) fn flush_and_reap(
    host: &recovery::Host,
    trial: &Trial,
    trial_path: &Path,
    child: &mut Child,
    token: &str,
) -> io::Result<Reaped> {
    let plan = host.plan();
    let p = plan
        .participants
        .iter()
        .find(|p| p.instance_id == trial.instance)
        .ok_or_else(|| invalid("old participant missing"))?;
    let old = child::identity(child.id())?;
    if Some(old.pid) != p.old_pid
        || Some(old.start) != p.process_start
        || old.boot != p.boot_id
        || trial.binding != host.binding()?
        || trial.phase != Phase::Armed
    {
        return Err(invalid("old child differs from frozen ownership"));
    }
    host.locked(|_| trial.save(trial_path))?;
    let result = (|| {
        let mut socket = UnixStream::connect(p.data_root.join("upgrade-flush.sock"))?;
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut request = serde_json::to_vec(&serde_json::json!({
            "token": token, "transaction_id": trial.binding.transaction,
            "generation": trial.binding.generation, "instance_id": p.instance_id,
            "plan": plan
        }))?;
        request.push(b'\n');
        socket.write_all(&request)?;
        let mut bytes = Vec::new();
        std::io::BufReader::new(socket)
            .take(1024 * 1024)
            .read_until(b'\n', &mut bytes)?;
        check_reply(&bytes, &trial.binding, &p.instance_id, plan)?;
        let end = Instant::now() + Duration::from_millis(REAP_MS);
        while child.try_wait()?.is_none() {
            if Instant::now() >= end {
                return Err(invalid("OLD child did not exit after flush"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(Reaped {
            instance: p.instance_id.clone(),
            binding: trial.binding.clone(),
            old,
        })
    })();
    result.map_err(|error| keep_cause(error, child::stop_and_reap(child)))
}

/// The flush failure is the cause; a reap failure must not mask it.
fn keep_cause(error: io::Error, reap: io::Result<()>) -> io::Error {
    match reap {
        Ok(()) => error,
        Err(reap) => io::Error::other(format!("{error}; reap also failed: {reap}")),
    }
}

/// The reply must name this transaction, generation and participant plan,
/// and carry a receipt id. Any other reply refuses the start.
fn check_reply(
    bytes: &[u8],
    expected: &Binding,
    instance: &str,
    plan: &journal::FrozenPlan,
) -> io::Result<()> {
    let reply: Reply = serde_json::from_slice(bytes)?;
    let binding = reply.receipt.binding;
    if binding.transaction_id != expected.transaction
        || binding.generation != expected.generation
        || binding.plan_sha256 != digest(&(instance, plan))?
        || reply.receipt.receipt_id.is_empty()
    {
        return Err(invalid("flush reply does not bind this participant"));
    }
    Ok(())
}

pub(super) fn authorize(
    host: &recovery::Host,
    trial: &mut Trial,
    path: &Path,
    reaped: &[Reaped],
) -> io::Result<()> {
    host.locked(|record| {
        trial.check_budget(&Clock::now()?)?;
        if trial.phase != Phase::Armed
            || trial.binding != host.binding()?
            || !matches!(
                record.phase,
                journal::Phase::SwappedCli | journal::Phase::HandoffArmed
            )
        {
            return Err(invalid("host is not ready for protected start"));
        }
        for p in &host.plan().participants {
            if !p.was_running {
                continue;
            }
            let receipt = reaped
                .iter()
                .find(|r| r.instance == p.instance_id)
                .ok_or_else(|| invalid("all-OLD reap receipts are required"))?;
            if receipt.binding != trial.binding
                || Some(receipt.old.pid) != p.old_pid
                || Some(receipt.old.start) != p.process_start
                || receipt.old.boot != p.boot_id
                || !child::absent(&receipt.old)?
            {
                return Err(invalid(
                    "OLD reap receipt does not bind the frozen participant",
                ));
            }
        }
        host.verify_candidate()?;
        trial.phase = Phase::Authorized;
        trial.save(path)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::testkit::fixture;
    use super::*;

    fn reply(host: &recovery::Host, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let binding = host.binding().unwrap();
        let request = serde_json::json!({
            "token": "inert launcher fixture", "transaction_id": binding.transaction,
            "generation": binding.generation, "instance_id": "alice", "plan": host.plan()
        });
        let mut receipt = fixture_receipt(&serde_json::to_vec(&request).unwrap()).unwrap();
        edit(&mut receipt);
        serde_json::to_vec(&serde_json::json!({ "receipt": receipt })).unwrap()
    }

    #[test]
    fn a_flush_reply_binds_transaction_generation_plan_and_receipt_id() {
        let (_dir, _root, host, _record) = fixture(journal::Phase::SwappedCli);
        let binding = host.binding().unwrap();
        let check = |bytes: Vec<u8>| check_reply(&bytes, &binding, "alice", host.plan());
        check(reply(&host, |_| {})).unwrap();
        let refusals: [fn(&mut serde_json::Value); 4] = [
            |r| r["binding"]["transaction_id"] = "another".into(),
            |r| r["binding"]["generation"] = 2.into(),
            |r| r["binding"]["plan_sha256"] = serde_json::json!(vec![0u8; 32]),
            |r| r["receipt_id"] = "".into(),
        ];
        for edit in refusals {
            let error = check(reply(&host, edit)).unwrap_err().to_string();
            assert!(error.contains("does not bind"), "{error}");
        }
        // A reply for another participant of the same plan is refused too.
        let error = check_reply(&reply(&host, |_| {}), &binding, "bob", host.plan())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not bind"), "{error}");
    }

    #[test]
    fn authorize_refuses_a_receipt_for_another_old_process() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let clock = Clock::now().unwrap();
        let mut trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
        trial.save(&path).unwrap();
        let p = &host.plan().participants[0];
        let receipt = |pid: u32, binding: Binding| Reaped {
            instance: "alice".into(),
            binding,
            old: Identity {
                pid,
                start: p.process_start.unwrap(),
                boot: p.boot_id.clone(),
            },
        };
        let mut stale = trial.binding.clone();
        stale.generation += 1;
        for reaped in [
            receipt(p.old_pid.unwrap() + 1, trial.binding.clone()),
            receipt(p.old_pid.unwrap(), stale),
        ] {
            let error = authorize(&host, &mut trial, &path, &[reaped])
                .unwrap_err()
                .to_string();
            assert!(error.contains("does not bind"), "{error}");
            assert_eq!(trial.phase, Phase::Armed);
        }
    }

    /// The OLD identity in the plan is a live process here, so a receipt
    /// that names it cannot prove the reap.
    #[cfg(target_os = "linux")]
    #[test]
    fn authorize_refuses_while_the_old_child_is_alive() {
        let mut old = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let live = child::identity(old.id()).unwrap();
        let (_dir, root, _host, mut record) = fixture(journal::Phase::SwappedCli);
        let p = &mut record.plan.participants[0];
        p.old_pid = Some(live.pid);
        p.process_start = Some(live.start);
        p.boot_id = live.boot.clone();
        journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        let path = root.join("trial.json");
        let mut trial = Trial::new(
            host.binding().unwrap(),
            "alice".into(),
            &Clock::now().unwrap(),
        )
        .unwrap();
        trial.save(&path).unwrap();
        let reaped = Reaped {
            instance: "alice".into(),
            binding: trial.binding.clone(),
            old: live,
        };
        let error = authorize(&host, &mut trial, &path, &[reaped])
            .unwrap_err()
            .to_string();
        old.kill().unwrap();
        old.wait().unwrap();
        assert!(error.contains("does not bind"), "{error}");
        assert_eq!(trial.phase, Phase::Armed);
    }

    #[test]
    fn a_reap_failure_does_not_hide_the_flush_cause() {
        let flush = || io::Error::new(io::ErrorKind::ConnectionRefused, "flush refused");
        let kept = keep_cause(flush(), Ok(()));
        assert_eq!(kept.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(kept.to_string(), "flush refused");
        let both = keep_cause(flush(), Err(invalid("child reap timeout"))).to_string();
        assert_eq!(both, "flush refused; reap also failed: child reap timeout");
    }

    fn refused(result: io::Result<Reaped>) -> io::Error {
        match result {
            Ok(_) => panic!("flush_and_reap must refuse"),
            Err(error) => error,
        }
    }

    /// Without /proc the launcher cannot prove custody of the OLD child, so
    /// it refuses before it persists the budget or sends the token.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn flush_and_reap_refuses_without_linux_process_custody() {
        let (_dir, root, host, _record) = fixture(journal::Phase::SwappedCli);
        let path = root.join("trial.json");
        let clock = Clock::now().unwrap();
        let trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
        let mut old = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let result = flush_and_reap(&host, &trial, &path, &mut old, "inert launcher fixture");
        old.kill().unwrap();
        old.wait().unwrap();
        assert_eq!(refused(result).kind(), io::ErrorKind::Unsupported);
        assert!(!path.exists());
    }

    /// A real OLD child whose identity the frozen plan names.
    #[cfg(target_os = "linux")]
    mod custody {
        use super::super::super::testkit::fixture_with;
        use super::*;
        use std::os::unix::net::UnixListener;
        use std::process::Command;
        use std::thread::JoinHandle;

        const TOKEN: &str = "inert launcher fixture";

        fn owned(
            edit: impl FnOnce(&mut journal::Participant),
        ) -> (tempfile::TempDir, PathBuf, recovery::Host, Trial, Child) {
            let old = Command::new("sleep").arg("30").spawn().unwrap();
            let live = child::identity(old.id()).unwrap();
            let (dir, root, host, _record) = fixture_with(journal::Phase::SwappedCli, |record| {
                let p = &mut record.plan.participants[0];
                p.old_pid = Some(live.pid);
                p.process_start = Some(live.start);
                p.boot_id = live.boot;
                edit(p);
            });
            let clock = Clock::now().unwrap();
            let trial = Trial::new(host.binding().unwrap(), "alice".into(), &clock).unwrap();
            (dir, root, host, trial, old)
        }

        /// The daemon side: answers one flush request with the fixture
        /// receipt (after `edit`), then, if `exit` names it, kills the OLD
        /// child as a daemon that exits after its flush. Returns the request.
        fn serve(
            root: &Path,
            edit: fn(&mut serde_json::Value),
            exit: Option<u32>,
        ) -> JoinHandle<serde_json::Value> {
            let listener = UnixListener::bind(root.join("upgrade-flush.sock")).unwrap();
            std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                std::io::BufReader::new(&socket)
                    .read_until(b'\n', &mut request)
                    .unwrap();
                let mut receipt = fixture_receipt(&request).unwrap();
                edit(&mut receipt);
                let mut reply =
                    serde_json::to_vec(&serde_json::json!({ "receipt": receipt })).unwrap();
                reply.push(b'\n');
                (&socket).write_all(&reply).unwrap();
                if let Some(pid) = exit {
                    let status = Command::new("kill")
                        .args(["-KILL", &pid.to_string()])
                        .status()
                        .unwrap();
                    assert!(status.success());
                }
                serde_json::from_slice(&request).unwrap()
            })
        }

        fn stop(mut old: Child) {
            old.kill().unwrap();
            old.wait().unwrap();
        }

        #[test]
        fn flush_and_reap_refuses_an_old_child_the_plan_does_not_name() {
            let (_dir, root, host, trial, mut old) = owned(|p| {
                p.old_pid = p.old_pid.map(|pid| pid + 1);
            });
            let path = root.join("trial.json");
            let error = refused(flush_and_reap(&host, &trial, &path, &mut old, TOKEN));
            assert!(
                error.to_string().contains("differs from frozen ownership"),
                "{error}"
            );
            // An unrelated process is never killed, and no budget is spent.
            assert!(old.try_wait().unwrap().is_none());
            assert!(!path.exists());
            stop(old);
        }

        #[test]
        fn flush_and_reap_refuses_a_trial_that_is_not_armed() {
            let (_dir, root, host, mut trial, mut old) = owned(|_| {});
            trial.phase = Phase::Authorized;
            let path = root.join("trial.json");
            let error = refused(flush_and_reap(&host, &trial, &path, &mut old, TOKEN));
            assert!(
                error.to_string().contains("differs from frozen ownership"),
                "{error}"
            );
            assert!(old.try_wait().unwrap().is_none());
            assert!(!path.exists());
            stop(old);
        }

        #[test]
        fn a_flush_without_a_daemon_socket_persists_the_budget_and_reaps() {
            let (_dir, root, host, trial, mut old) = owned(|_| {});
            let path = root.join("trial.json");
            let error = refused(flush_and_reap(&host, &trial, &path, &mut old, TOKEN));
            assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
            assert!(old.try_wait().unwrap().is_some());
            let saved = Trial::load(&path, &trial.binding, "alice").unwrap();
            assert_eq!(saved.phase, Phase::Armed);
        }

        #[test]
        fn a_flush_reply_for_another_generation_or_transaction_reaps_and_refuses() {
            let edits: [fn(&mut serde_json::Value); 2] = [
                |r| r["binding"]["generation"] = 2.into(),
                |r| r["binding"]["transaction_id"] = "another".into(),
            ];
            for edit in edits {
                let (_dir, root, host, trial, mut old) = owned(|_| {});
                let path = root.join("trial.json");
                let server = serve(&root, edit, None);
                let error = refused(flush_and_reap(&host, &trial, &path, &mut old, TOKEN));
                server.join().unwrap();
                assert!(
                    error
                        .to_string()
                        .contains("flush reply does not bind this participant"),
                    "{error}"
                );
                assert!(old.try_wait().unwrap().is_some());
            }
        }

        /// The daemon flushes, replies and exits: the waited OLD child and
        /// the bound reply together let `authorize` permit the start.
        #[test]
        fn a_bound_flush_and_a_waited_old_child_authorize_the_start() {
            let (_dir, root, host, mut trial, mut old) = owned(|_| {});
            let path = root.join("trial.json");
            let server = serve(&root, |_| {}, Some(old.id()));
            let reaped = match flush_and_reap(&host, &trial, &path, &mut old, TOKEN) {
                Ok(reaped) => reaped,
                Err(error) => panic!("{error}"),
            };
            let request = server.join().unwrap();
            assert_eq!(request["token"], TOKEN);
            assert_eq!(request["instance_id"], "alice");
            assert_eq!(request["generation"], trial.binding.generation);
            assert_eq!(request["plan"], serde_json::to_value(host.plan()).unwrap());
            assert!(old.try_wait().unwrap().is_some());
            assert_eq!(reaped.binding, trial.binding);
            authorize(&host, &mut trial, &path, &[reaped]).unwrap();
            assert_eq!(trial.phase, Phase::Authorized);
            let saved = Trial::load(&path, &trial.binding, "alice").unwrap();
            assert_eq!(saved.phase, Phase::Authorized);
        }
    }
}
