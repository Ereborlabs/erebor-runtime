use std::collections::BTreeSet;

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ExecutionSurface};
use erebor_runtime_policy::Decision;
use serde_json::Value;

use super::labels::{md, surface_name, truncate, EvidenceTraceRecordView};
use crate::evidence_trace::EvidenceTraceArtifact;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct EvidenceTraceRows;

impl EvidenceTraceRows {
    pub(super) fn controls(records: &[&AuditRecord]) -> String {
        let has_browser = records
            .iter()
            .any(|record| record.event.surface == ExecutionSurface::BrowserCdp);
        let has_terminal = records
            .iter()
            .any(|record| record.event.surface == ExecutionSurface::Terminal);
        let has_callback_block = records.iter().any(|record| {
            record.event.action == ActionKind::NetworkRequest
                && record
                    .final_decision
                    .rule_id()
                    .is_some_and(|rule| rule == "deny-oauth-callback-network-request")
        });
        let rows = [
            (
                "Browser CDP endpoint",
                if has_browser { "enforced" } else { "deferred" },
                if has_browser {
                    "Browser CDP audit records are present."
                } else {
                    "No browser CDP audit records are present in this run."
                },
            ),
            (
                "OAuth callback handoff",
                if has_callback_block { "enforced" } else { "observed" },
                if has_callback_block {
                    "Callback network request was blocked before local callback completion."
                } else {
                    "No callback block record is present in this run."
                },
            ),
            (
                "Terminal/process execution",
                if has_terminal { "enforced" } else { "deferred" },
                if has_terminal {
                    "Process execution records are present for the governed session process tree."
                } else {
                    "No terminal/process records are present in this run."
                },
            ),
            (
                "OpenClaw browser profile/login state",
                "cooperative",
                "The demo uses the normal OpenClaw browser profile; Erebor does not copy or certify cookies.",
            ),
            (
                "OAuth lab event stream",
                "observed",
                "Lab events are supporting evidence, not the enforcement boundary.",
            ),
            (
                "Semantic PII classifier",
                "deferred",
                "No semantic PII classifier enabled. This report proves governed action/resource provenance, not content classification.",
            ),
            (
                "Host-wide network/process containment",
                "deferred",
                "The pilot controls the governed session path and reports residual risk; it does not claim whole-device containment.",
            ),
        ];

        let mut output = String::from("| Control | Label | Evidence |\n| --- | --- | --- |\n");
        for (control, label, evidence) in rows {
            output.push_str(&format!(
                "| {} | {} | {} |\n",
                md(control),
                md(label),
                md(evidence)
            ));
        }
        output
    }

    pub(super) fn resources(records: &[&AuditRecord]) -> String {
        let resources = records
            .iter()
            .filter(|record| matches!(record.final_decision, Decision::Allow { .. }))
            .map(|record| {
                format!(
                    "{}: {}",
                    surface_name(&record.event.surface),
                    EvidenceTraceRecordView::new(record).target_text()
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(16)
            .collect::<Vec<_>>();

        if resources.is_empty() {
            return String::from("- No allowed governed resources were recorded for this session.");
        }

        resources
            .iter()
            .map(|resource| format!("- {}", truncate(resource, 180)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub(super) fn action_rows(
        records: &[&AuditRecord],
        limit: usize,
        only_allowed: bool,
    ) -> String {
        let rows = records
            .iter()
            .filter(|record| {
                !only_allowed || matches!(record.final_decision, Decision::Allow { .. })
            })
            .take(limit)
            .copied()
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return String::from("No records in this category.");
        }

        let mut output = String::from(
            "| Time | Surface | Action | Target | Decision |\n| --- | --- | --- | --- | --- |\n",
        );
        for record in &rows {
            let view = EvidenceTraceRecordView::new(record);
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md(&record.event.timestamp),
                md(surface_name(&record.event.surface)),
                md(&view.action_label()),
                truncate(&view.target_text(), 140),
                md(&view.decision_label()),
            ));
        }
        let omitted = records.len().saturating_sub(rows.len());
        if omitted > 0 {
            output.push_str(&format!(
                "\nAdditional records omitted from this summary: {omitted}.\n"
            ));
        }
        output
    }

    pub(super) fn rules(policy: &Value, observed_rule_ids: &BTreeSet<String>) -> String {
        if observed_rule_ids.is_empty() {
            return String::from("No policy rule ids were observed in this session.");
        }
        let rules = policy
            .get("rules")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let mut rows = String::from(
            "| Rule id | Surface | Action | Decision | Reason |\n| --- | --- | --- | --- | --- |\n",
        );
        for rule_id in observed_rule_ids {
            if let Some(rule) = rules
                .iter()
                .find(|rule| rule.get("id").and_then(Value::as_str) == Some(rule_id.as_str()))
            {
                rows.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    md(rule_id),
                    md(json_str(rule.pointer("/match/surface")).unwrap_or("")),
                    md(json_str(rule.pointer("/match/action")).unwrap_or("")),
                    md(json_str(rule.get("decision")).unwrap_or("")),
                    truncate(json_str(rule.get("reason")).unwrap_or(""), 140),
                ));
            } else {
                rows.push_str(&format!(
                    "| {} | internal/runtime | n/a | observed | Runtime-generated decision id. |\n",
                    md(rule_id)
                ));
            }
        }
        rows
    }

    pub(super) fn artifacts(artifacts: &[EvidenceTraceArtifact]) -> String {
        let mut output = String::from("| Artifact | Path | SHA-256 |\n| --- | --- | --- |\n");
        for artifact in artifacts {
            output.push_str(&format!(
                "| {} | `{}` | `{}` |\n",
                md(artifact.label()),
                md(&artifact.path().display().to_string()),
                artifact.sha256()
            ));
        }
        output
    }
}

fn json_str(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}
