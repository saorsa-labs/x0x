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
    if let Err(error) = result {
        // The flush failure is the cause; a reap failure must not mask it.
        if let Err(reap) = child::stop_and_reap(child) {
            return Err(io::Error::other(format!(
                "{error}; reap also failed: {reap}"
            )));
        }
        return Err(error);
    }
    result
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
}
