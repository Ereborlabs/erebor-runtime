use super::*;
use std::sync::LazyLock;

impl AnalysisStore {
    pub(super) fn finding_selection() -> &'static str {
        static SQL: LazyLock<String> = LazyLock::new(|| {
            format!(
                "{} SELECT result_id, finding_id
                 FROM current_findings
                 WHERE (? IS NULL OR finding_id > ?) AND (? IS NULL OR finding_id = ?)
                 ORDER BY finding_id LIMIT ?",
                AnalysisStore::current_findings("")
            )
        });
        SQL.as_str()
    }

    pub(super) fn finding_heads_selection(count: usize) -> String {
        let filter = format!(
            "WHERE finding.finding_id IN ({})",
            std::iter::repeat_n("?", count)
                .collect::<Vec<_>>()
                .join(", ")
        );
        format!(
            "{} SELECT result_id, finding_id FROM current_findings ORDER BY finding_id",
            Self::current_findings(&filter)
        )
    }

    fn current_findings(filter: &str) -> String {
        format!(
            "WITH heads AS (
            SELECT result_id, commit_revision FROM main.analysis_results
            WHERE tenant_id = ? AND processor_id = ? AND method_version = ?
                AND stream_key IS NOT NULL
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY stream_key, first_cursor
                ORDER BY commit_revision DESC, result_id DESC) = 1
         ), current_findings AS (
            SELECT v.result_id, finding.finding_id
            FROM heads h JOIN graph_versions v ON v.result_id = h.result_id
            JOIN graph_finding_membership m ON m.lineage_id = v.lineage_id
                AND m.valid_from <= v.commit_revision
                AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
            JOIN graph_finding_values finding USING (value_id)
            {filter}
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY finding.finding_id
                ORDER BY h.commit_revision DESC, v.result_id DESC) = 1
         )"
        )
    }

    pub(super) fn finding_query(count: usize) -> String {
        let columns = GraphRows::finding_columns("finding");
        let values = std::iter::repeat_n("(?, ?, ?)", count)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "WITH selected(result_id, finding_id, selected_index) AS (VALUES {values})
             SELECT {columns}, selected.selected_index
             FROM selected JOIN graph_findings finding
                ON finding.result_id = selected.result_id
                AND finding.finding_id = selected.finding_id
             ORDER BY selected.selected_index"
        )
    }
}
