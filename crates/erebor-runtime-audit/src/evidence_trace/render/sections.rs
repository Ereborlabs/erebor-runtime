use std::collections::{BTreeMap, BTreeSet};

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ActorIdentity, ActorKind, ExecutionSurface};
use erebor_runtime_policy::Decision;

use super::{
    labels::{md, surface_name, EvidenceTraceRecordView},
    rows::EvidenceTraceRows,
};
use crate::evidence_trace::EvidenceTraceRequest;

#[derive(Clone, Copy, Debug)]
pub(super) struct EvidenceTraceMarkdownBody<'a> {
    session_id: &'a str,
    records: &'a [&'a AuditRecord],
    request: &'a EvidenceTraceRequest,
}

impl<'a> EvidenceTraceMarkdownBody<'a> {
    pub(super) const fn new(
        session_id: &'a str,
        records: &'a [&'a AuditRecord],
        request: &'a EvidenceTraceRequest,
    ) -> Self {
        Self {
            session_id,
            records,
            request,
        }
    }

    pub(super) fn render(self) -> String {
        let actor = self.records.first().map(|record| &record.event.actor);
        let first_timestamp = self
            .records
            .first()
            .map_or("unknown", |record| record.event.timestamp.as_str());
        let last_timestamp = self
            .records
            .last()
            .map_or("unknown", |record| record.event.timestamp.as_str());
        let counts = EvidenceTraceDecisionCounts::from_records(self.records);
        let rule_ids = self.observed_rule_ids();
        let allowed_timeline = self.interesting_allowed();
        let transitions = self.authority_transitions();
        let runner = self
            .request
            .config()
            .pointer("/session/runner/kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");

        format!(
            r#"# Governed OpenClaw Evidence Trace

## Executive Summary

This trace summarizes one governed OpenClaw run inside Erebor Runtime. The run
used a shared session audit to record browser CDP and terminal/process actions
under one session id. The strongest evidence in this report is action/resource
provenance: what resources were exposed, what the agent attempted, which policy
rule applied, and whether Erebor allowed, mediated, held, or denied the action.

No semantic PII classifier enabled. This v1 trace does not claim that the agent
never read personal data, does not certify GDPR/HIPAA compliance, and is not
legal advice.

## Session Purpose And Actor

| Field | Value |
| --- | --- |
| Purpose | {} |
| Session id | {} |
| Actor | {} |
| Session runner | {} |
| Audit window | {} to {} |
| Record count | {} |
| Surfaces observed | {} |
| Decisions observed | {} |

## Controls And Non-Claims

{}

## Governed Resources Exposed

{}

## Allowed Action Timeline

{}

## Denied, Held, Or Mediated Authority Transitions

{}

Summary counts: allowed={}, denied={}, held={}, mediated={}.

## Policy Package And Rule Evidence

{}

## Residual Risk

- No semantic PII classifier enabled. The report proves governed
  action/resource provenance, not semantic content classification.
- Linux-host process governance applies to the enrolled session process tree and
  reports residual risk; it is not a claim of whole-host containment.
- The OpenClaw browser profile can contain existing cookies or login state. The
  demo should use a throwaway GitHub account and throwaway OAuth app.
- Browser URL/resource provenance comes from CDP commands/events and observed
  targets. The raw JSONL remains the evidence attachment for deeper review.
- This report is a technical evidence trace for privacy, GRC, security, and AI
  platform review. It is not legal advice, a DPIA, or a compliance certificate.

## Intended Reviewers And Retention

- Intended reviewers: DPO/privacy, GRC, security, AI platform, and counsel when
  an agent workflow approaches regulated or personal-data-bearing systems.
- Suggested retention: store the report with the JSONL audit, policy, config,
  and prompt artifacts for the same retention period as the reviewed support or
  incident workflow.
- Review question: would this evidence be enough to approve the agent workflow,
  or is semantic data classification, stronger sandboxing, or human approval
  still required?

## Artifact Integrity

{}
"#,
            md(self.request.purpose()),
            md(self.session_id),
            md(&Self::actor_label(actor)),
            md(runner),
            md(first_timestamp),
            md(last_timestamp),
            self.records.len(),
            md(&self.count_by(|record| surface_name(&record.event.surface))),
            md(&self.count_by(|record| { EvidenceTraceRecordView::new(record).decision_type() })),
            EvidenceTraceRows::controls(self.records),
            EvidenceTraceRows::resources(self.records),
            EvidenceTraceRows::action_rows(
                if allowed_timeline.is_empty() {
                    self.records
                } else {
                    &allowed_timeline
                },
                12,
                true,
            ),
            EvidenceTraceRows::action_rows(&transitions, 12, false),
            counts.allowed,
            counts.denied,
            counts.held,
            counts.mediated,
            EvidenceTraceRows::rules(self.request.policy(), &rule_ids),
            EvidenceTraceRows::artifacts(self.request.artifacts()),
        )
    }

    fn observed_rule_ids(self) -> BTreeSet<String> {
        self.records
            .iter()
            .flat_map(|record| {
                [
                    record.policy_decision.rule_id().map(ToOwned::to_owned),
                    record.final_decision.rule_id().map(ToOwned::to_owned),
                ]
            })
            .flatten()
            .collect()
    }

    fn interesting_allowed(self) -> Vec<&'a AuditRecord> {
        self.records
            .iter()
            .filter(|record| {
                matches!(record.final_decision, Decision::Allow { .. })
                    && (record.event.surface == ExecutionSurface::BrowserCdp
                        || record
                            .final_decision
                            .rule_id()
                            .is_some_and(|rule| rule.contains("process-interception"))
                        || matches!(
                            record.event.action,
                            ActionKind::BrowserNavigate
                                | ActionKind::BrowserTargetManage
                                | ActionKind::NetworkRequest
                        ))
            })
            .copied()
            .collect()
    }

    fn authority_transitions(self) -> Vec<&'a AuditRecord> {
        self.records
            .iter()
            .filter(|record| {
                !matches!(record.final_decision, Decision::Allow { .. })
                    || matches!(
                        record.policy_decision,
                        Decision::Deny { .. }
                            | Decision::RequireApproval { .. }
                            | Decision::Mediate { .. }
                    )
            })
            .copied()
            .collect()
    }

    fn count_by(self, key: impl Fn(&AuditRecord) -> &'static str) -> String {
        let mut counts = BTreeMap::<&'static str, usize>::new();
        for record in self.records {
            *counts.entry(key(record)).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(key, count)| format!("{key}: {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn actor_label(actor: Option<&ActorIdentity>) -> String {
        actor.map_or_else(
            || String::from("unknown (unknown)"),
            |actor| format!("{} ({})", actor.id, Self::actor_kind_name(&actor.kind)),
        )
    }

    fn actor_kind_name(kind: &ActorKind) -> &'static str {
        match kind {
            ActorKind::Agent => "agent",
            ActorKind::User => "user",
            ActorKind::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvidenceTraceDecisionCounts {
    allowed: usize,
    denied: usize,
    held: usize,
    mediated: usize,
}

impl EvidenceTraceDecisionCounts {
    fn from_records(records: &[&AuditRecord]) -> Self {
        let mut counts = Self::default();
        for record in records {
            match record.final_decision {
                Decision::Allow { .. } => counts.allowed += 1,
                Decision::Deny { .. } => counts.denied += 1,
                Decision::RequireApproval { .. } => counts.held += 1,
                Decision::Mediate { .. } => counts.mediated += 1,
            }
        }
        counts
    }
}
