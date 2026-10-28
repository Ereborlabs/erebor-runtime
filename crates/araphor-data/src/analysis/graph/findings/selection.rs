use super::*;

impl AnalysisStore {
    pub(super) fn finding_selection() -> &'static str {
        "WITH heads AS (
            SELECT result_id, commit_revision FROM main.analysis_results
            WHERE tenant_id = ? AND processor_id = ? AND method_version = ?
                AND stream_key IS NOT NULL
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY stream_key, first_cursor
                ORDER BY commit_revision DESC, result_id DESC) = 1
         ), current_findings AS (
            SELECT finding.result_id, finding.finding_id
            FROM graph_findings finding JOIN heads USING (result_id)
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY finding_id
                ORDER BY commit_revision DESC, finding.result_id DESC) = 1
         )
         SELECT result_id, finding_id
         FROM current_findings
         WHERE (? IS NULL OR finding_id > ?) AND (? IS NULL OR finding_id = ?)
         ORDER BY finding_id LIMIT ?"
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
