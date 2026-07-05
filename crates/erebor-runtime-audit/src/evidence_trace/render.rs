mod labels;
mod rows;
mod sections;

use std::collections::BTreeMap;

use erebor_runtime_core::AuditRecord;
use snafu::OptionExt;

use crate::{
    error::{EvidenceNoSessionRecordsSnafu, EvidenceUnknownSessionSnafu},
    EvidenceTraceError,
};

use super::{
    EvidenceHasher, EvidenceTraceReport, EvidenceTraceRequest, EvidenceTraceSessionSummary,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MarkdownEvidenceTraceRenderer;

impl MarkdownEvidenceTraceRenderer {
    pub fn render(
        &self,
        request: &EvidenceTraceRequest,
    ) -> Result<EvidenceTraceReport, EvidenceTraceError> {
        let session_id =
            EvidenceTraceSessionSelector::new(request.records(), request.session_id()).select()?;
        let records = request
            .records()
            .iter()
            .filter(|record| record.event.session_id.as_str() == session_id)
            .collect::<Vec<_>>();
        let markdown_without_report_hash =
            sections::EvidenceTraceMarkdownBody::new(&session_id, &records, request).render();
        let report_hash = EvidenceHasher::sha256_hex(markdown_without_report_hash.as_bytes());
        let markdown = format!(
            "{markdown_without_report_hash}| Report body | generated markdown before this hash row | `{report_hash}` |\n\n"
        );
        Ok(EvidenceTraceReport::new(session_id, markdown, report_hash))
    }
}

#[derive(Clone, Copy, Debug)]
struct EvidenceTraceSessionSelector<'a> {
    records: &'a [AuditRecord],
    requested: Option<&'a str>,
}

impl<'a> EvidenceTraceSessionSelector<'a> {
    const fn new(records: &'a [AuditRecord], requested: Option<&'a str>) -> Self {
        Self { records, requested }
    }

    fn select(self) -> Result<String, EvidenceTraceError> {
        if let Some(requested) = self.requested {
            return self.select_requested(requested);
        }

        let mut summaries = BTreeMap::<&str, EvidenceTraceSessionSummary>::new();
        for (index, record) in self.records.iter().enumerate() {
            summaries
                .entry(record.event.session_id.as_str())
                .or_default()
                .observe(index, record);
        }

        summaries
            .into_iter()
            .max_by_key(|(_session_id, summary)| {
                (
                    summary.browser_count > 0 && summary.non_allow_count > 0,
                    summary.browser_count > 0,
                    summary.last_index,
                )
            })
            .map(|(session_id, _summary)| session_id.to_owned())
            .context(EvidenceNoSessionRecordsSnafu)
    }

    fn select_requested(self, requested: &str) -> Result<String, EvidenceTraceError> {
        if self
            .records
            .iter()
            .any(|record| record.event.session_id.as_str() == requested)
        {
            Ok(requested.to_owned())
        } else {
            EvidenceUnknownSessionSnafu {
                session_id: requested.to_owned(),
            }
            .fail()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::evidence_trace::{
        test_support::request_with_records, MarkdownEvidenceTraceRenderer,
    };
    use erebor_runtime_events::{ActionKind, ExecutionSurface};
    use erebor_runtime_policy::Decision;

    #[test]
    fn markdown_trace_contains_dpo_fields_and_non_claims() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = request_with_records([
            (
                "allow-nav",
                ExecutionSurface::BrowserCdp,
                ActionKind::BrowserNavigate,
                "http://127.0.0.1:5105/repro",
                Decision::Allow {
                    rule_id: Some(String::from("allow-oauth-lab-navigation")),
                },
                Decision::Allow {
                    rule_id: Some(String::from("allow-oauth-lab-navigation")),
                },
            ),
            (
                "deny-callback",
                ExecutionSurface::BrowserCdp,
                ActionKind::NetworkRequest,
                "http://127.0.0.1:5105/oauth/callback?code=secret&state=secret",
                Decision::Deny {
                    reason: String::from("callback denied"),
                    rule_id: Some(String::from("deny-oauth-callback-network-request")),
                },
                Decision::Deny {
                    reason: String::from("callback denied"),
                    rule_id: Some(String::from("deny-oauth-callback-network-request")),
                },
            ),
        ]);

        let report = MarkdownEvidenceTraceRenderer.render(&request)?;

        assert!(report
            .markdown()
            .contains("No semantic PII classifier enabled"));
        assert!(report.markdown().contains("session-1"));
        assert!(report
            .markdown()
            .contains("deny-oauth-callback-network-request"));
        assert!(report.markdown().contains("code=redacted"));
        assert!(report.markdown().contains("Report body"));
        Ok(())
    }
}
