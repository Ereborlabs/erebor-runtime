use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use serde::Serialize;
use snafu::ResultExt;

use crate::{error::ReviewEncodeJsonSnafu, SessionReviewError};

use super::SessionSummary;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SessionReviewOutput;

impl SessionReviewOutput {
    pub(crate) fn summary_table(summaries: &[SessionSummary]) -> String {
        let mut table = Self::standard_table();
        table.set_header([
            "SESSION", "STATUS", "ACTOR", "RUNNER", "SURFACES", "ALLOW", "DENY", "APPROVAL",
            "MEDIATE", "RISK", "START",
        ]);
        for summary in summaries {
            table.add_row([
                summary.session_id.clone(),
                summary.status.clone(),
                summary.actor.clone(),
                summary.runner.clone(),
                summary.surfaces.join(","),
                summary.allowed.to_string(),
                summary.denied.to_string(),
                summary.require_approval.to_string(),
                summary.mediated.to_string(),
                summary.max_risk.clone(),
                summary.start.clone(),
            ]);
        }
        format!("{table}\n")
    }

    pub(crate) fn json<T: Serialize>(value: &T) -> Result<String, SessionReviewError> {
        let mut output = serde_json::to_string_pretty(value).context(ReviewEncodeJsonSnafu)?;
        output.push('\n');
        Ok(output)
    }

    fn standard_table() -> Table {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);
        table
    }
}
