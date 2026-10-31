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
        let reply: Reply = serde_json::from_slice(&bytes)?;
        let binding = reply.receipt.binding;
        if binding.transaction_id != trial.binding.transaction
            || binding.generation != trial.binding.generation
            || binding.plan_sha256 != digest(&(p.instance_id.clone(), plan))?
            || reply.receipt.receipt_id.is_empty()
        {
            return Err(invalid("flush reply does not bind this participant"));
        }
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
