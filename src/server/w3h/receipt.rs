//! W3-H red-baseline receipts (plan §3f, Codex P2-f).
//!
//! A red case is only evidence when its own run shows it reached the
//! implicated state. Each run records, in order:
//!
//! 1. `setup_done` — the scenario reached its starting state;
//! 2. one `evidence` stage per declared precondition (e.g. "A holds O's
//!    certificate bytes"), each checked, not assumed;
//! 3. `request_delivered` — the triggering request reached its target,
//!    checked against the fabric trace;
//! 4. `cause` — the exact refusal/cause the case names, observed;
//! 5. `final` — the desired-behaviour assertion, passed or failed.
//!
//! The preconditions are `setup_done`, at least one `evidence` stage with
//! every `evidence` stage true, and a true `request_delivered`. The verdict
//! is GREEN when the preconditions hold and `final` passed; RED when the
//! preconditions hold, every `cause` stage (at least one) is true, and
//! `final` failed; INFRA otherwise (a setup error, a panic before the
//! receipt was finished, a harness timeout, a missing or false
//! precondition, an unexpected cause). A control that passes without its
//! preconditions proves nothing, so it is INFRA, not GREEN. Only RED counts
//! as a red baseline. The receipt is printed (`W3H-RECEIPT {json}`) and written to
//! `$W3H_TRACE_DIR/<case>-<pid>.receipt.json`, where
//! `scripts/ci/w3h-trace-check.py` checks it.

#![cfg(test)]

use serde::Serialize;

/// The schema id written into every receipt.
pub(crate) const RECEIPT_SCHEMA: &str = "w3h.receipt/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum Verdict {
    Green,
    Red,
    Infra,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
enum Stage {
    SetupDone {
        at_us: u128,
    },
    Evidence {
        name: String,
        ok: bool,
        detail: String,
        at_us: u128,
    },
    RequestDelivered {
        name: String,
        ok: bool,
        detail: String,
        at_us: u128,
    },
    Cause {
        expected: String,
        observed: Option<String>,
        ok: bool,
        at_us: u128,
    },
    Final {
        name: String,
        passed: bool,
        at_us: u128,
    },
    Infra {
        error: String,
        at_us: u128,
    },
}

/// One run's receipt.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Receipt {
    schema: &'static str,
    case: String,
    seed: String,
    stages: Vec<Stage>,
    verdict: Option<Verdict>,
    /// Fidelity caveats that apply to this run (never affect the verdict).
    notes: Vec<String>,
}

impl Receipt {
    pub(crate) fn new(case: &str, seed: u64) -> Self {
        Self {
            schema: RECEIPT_SCHEMA,
            case: case.to_string(),
            seed: format!("{seed:#x}"),
            stages: Vec::new(),
            verdict: None,
            notes: Vec::new(),
        }
    }

    /// Record a fidelity caveat for whoever reads this receipt.
    pub(crate) fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    pub(crate) fn setup_done(&mut self, at_us: u128) {
        self.stages.push(Stage::SetupDone { at_us });
    }

    pub(crate) fn evidence(
        &mut self,
        name: &str,
        ok: bool,
        detail: impl Into<String>,
        at_us: u128,
    ) {
        self.stages.push(Stage::Evidence {
            name: name.to_string(),
            ok,
            detail: detail.into(),
            at_us,
        });
    }

    pub(crate) fn request_delivered(
        &mut self,
        name: &str,
        ok: bool,
        detail: impl Into<String>,
        at_us: u128,
    ) {
        self.stages.push(Stage::RequestDelivered {
            name: name.to_string(),
            ok,
            detail: detail.into(),
            at_us,
        });
    }

    pub(crate) fn cause(
        &mut self,
        expected: &str,
        observed: Option<String>,
        ok: bool,
        at_us: u128,
    ) {
        self.stages.push(Stage::Cause {
            expected: expected.to_string(),
            observed,
            ok,
            at_us,
        });
    }

    pub(crate) fn infra(&mut self, error: impl Into<String>, at_us: u128) {
        self.stages.push(Stage::Infra {
            error: error.into(),
            at_us,
        });
    }

    /// Record the desired-behaviour assertion and compute the verdict.
    pub(crate) fn finish(&mut self, name: &str, passed: bool, at_us: u128) -> Verdict {
        self.stages.push(Stage::Final {
            name: name.to_string(),
            passed,
            at_us,
        });
        let verdict = self.classify();
        self.verdict = Some(verdict);
        verdict
    }

    fn classify(&self) -> Verdict {
        if self
            .stages
            .iter()
            .any(|stage| matches!(stage, Stage::Infra { .. }))
        {
            return Verdict::Infra;
        }
        let final_passed = self.stages.iter().rev().find_map(|stage| match stage {
            Stage::Final { passed, .. } => Some(*passed),
            _ => None,
        });
        let setup = self
            .stages
            .iter()
            .any(|stage| matches!(stage, Stage::SetupDone { .. }));
        let evidence_ok = self.stages.iter().all(|stage| match stage {
            Stage::Evidence { ok, .. } => *ok,
            _ => true,
        });
        let delivered = self
            .stages
            .iter()
            .any(|stage| matches!(stage, Stage::RequestDelivered { ok: true, .. }));
        let causes: Vec<bool> = self
            .stages
            .iter()
            .filter_map(|stage| match stage {
                Stage::Cause { ok, .. } => Some(*ok),
                _ => None,
            })
            .collect();
        let cause = !causes.is_empty() && causes.iter().all(|ok| *ok);
        let any_evidence = self
            .stages
            .iter()
            .any(|stage| matches!(stage, Stage::Evidence { .. }));
        let preconditions = setup && any_evidence && evidence_ok && delivered;
        match final_passed {
            Some(true) if preconditions => Verdict::Green,
            Some(false) if preconditions && cause => Verdict::Red,
            _ => Verdict::Infra,
        }
    }

    /// Whether an INFRA stage was recorded.
    pub(crate) fn has_infra(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| matches!(stage, Stage::Infra { .. }))
    }

    /// Recompute the verdict after a late stage (e.g. an INFRA error while
    /// stopping the daemons); finishes the receipt if it was not.
    pub(crate) fn reclassify(&mut self, final_name: &str) -> Verdict {
        if self.verdict.is_none() {
            return self.finish(final_name, false, 0);
        }
        let verdict = self.classify();
        self.verdict = Some(verdict);
        verdict
    }

    /// The verdict, once [`Self::finish`] ran.
    pub(crate) fn verdict(&self) -> Option<Verdict> {
        self.verdict
    }

    /// Print `W3H-RECEIPT {json}` and write the receipt file when
    /// `W3H_TRACE_DIR` is set.
    pub(crate) fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|e| {
            format!("{{\"schema\":\"{RECEIPT_SCHEMA}\",\"serialize_error\":\"{e}\"}}")
        });
        eprintln!("W3H-RECEIPT {json}");
        if let Ok(dir) = std::env::var("W3H_TRACE_DIR") {
            let dir = std::path::PathBuf::from(dir);
            if std::fs::create_dir_all(&dir).is_ok() {
                let file = dir.join(format!("{}-{}.receipt.json", self.case, std::process::id()));
                let _ = std::fs::write(file, &json);
            }
        }
    }
}

mod receipt_tests {
    use super::*;

    fn red_shaped() -> Receipt {
        let mut receipt = Receipt::new("w3h_case", 1);
        receipt.setup_done(1);
        receipt.evidence("holds bytes", true, "", 2);
        receipt.request_delivered("join reached A", true, "", 3);
        receipt.cause("OwnerCertMemberPending[O]", Some("…[O]".into()), true, 4);
        receipt
    }

    #[test]
    fn w3h_receipt_red_requires_every_stage() {
        assert_eq!(red_shaped().finish("J active", false, 5), Verdict::Red);
    }

    #[test]
    fn w3h_receipt_final_pass_is_green() {
        assert_eq!(red_shaped().finish("J active", true, 5), Verdict::Green);
        // The cause stage is RED-specific: a control needs no cause.
        let mut control = Receipt::new("w3h_case", 1);
        control.setup_done(1);
        control.evidence("A saw consented announce", true, "", 2);
        control.request_delivered("join reached A", true, "", 3);
        assert_eq!(control.finish("J active", true, 5), Verdict::Green);
    }

    #[test]
    fn w3h_receipt_green_requires_every_precondition() {
        let mut false_evidence = red_shaped();
        false_evidence.evidence("A holds O's certificate bytes", false, "", 3);
        assert_eq!(false_evidence.finish("J active", true, 5), Verdict::Infra);

        let mut no_evidence = Receipt::new("w3h_case", 1);
        no_evidence.setup_done(1);
        no_evidence.request_delivered("join reached A", true, "", 3);
        assert_eq!(no_evidence.finish("J active", true, 5), Verdict::Infra);

        let mut undelivered = Receipt::new("w3h_case", 1);
        undelivered.setup_done(1);
        undelivered.evidence("holds bytes", true, "", 2);
        undelivered.request_delivered("join reached A", false, "", 3);
        assert_eq!(undelivered.finish("J active", true, 5), Verdict::Infra);

        let mut no_setup = Receipt::new("w3h_case", 1);
        no_setup.evidence("holds bytes", true, "", 2);
        no_setup.request_delivered("join reached A", true, "", 3);
        assert_eq!(no_setup.finish("J active", true, 5), Verdict::Infra);
    }

    #[test]
    fn w3h_receipt_missing_or_false_stage_is_infra() {
        let mut no_cause = Receipt::new("w3h_case", 1);
        no_cause.setup_done(1);
        no_cause.evidence("holds bytes", true, "", 2);
        no_cause.request_delivered("join reached A", true, "", 3);
        assert_eq!(no_cause.finish("J active", false, 5), Verdict::Infra);

        let mut wrong_cause = red_shaped();
        wrong_cause.cause("OwnerCertMemberPending[O]", Some("other".into()), false, 4);
        // Any cause stage true is not enough if evidence failed.
        wrong_cause.evidence("A saw anonymous announce", false, "", 4);
        assert_eq!(wrong_cause.finish("J active", false, 5), Verdict::Infra);

        let mut infra = red_shaped();
        infra.infra("barrier timeout during setup", 3);
        assert_eq!(infra.finish("J active", false, 5), Verdict::Infra);

        assert_eq!(Receipt::new("w3h_case", 1).classify(), Verdict::Infra);
    }
}
