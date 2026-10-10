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
         SELECT CASE WHEN octet_length(encode(result_id)) BETWEEN 1 AND 256
                THEN result_id END,
            CASE WHEN octet_length(encode(finding_id)) <= 4096 THEN finding_id END
         FROM current_findings
         WHERE (? IS NULL OR finding_id > ?) AND (? IS NULL OR finding_id = ?)
         ORDER BY finding_id LIMIT ?"
    }

    pub(super) fn finding_preflight(count: usize) -> String {
        let values = std::iter::repeat_n("(?)", count)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "WITH requested(result_id) AS (VALUES {values}),
             analysis_results AS (
                SELECT metadata.result_id, metadata.tenant_id
                FROM main.analysis_results metadata JOIN requested USING (result_id)
             ), charges AS (
                SELECT result_id, coalesce(sum(bytes), 0)::UBIGINT AS stored_bytes
                FROM ({}) GROUP BY result_id
             ), headers AS (
                SELECT coalesce(sum(coalesce(octet_length(metadata.body), 0)
                    + octet_length(metadata.stream_key)
                    + octet_length(encode(metadata.result_id))), 0) <= ? AS included
                FROM main.analysis_results metadata JOIN requested USING (result_id)
             )
             SELECT CASE WHEN octet_length(encode(metadata.result_id)) BETWEEN 1 AND 256
                    THEN metadata.result_id END AS result_id,
                CASE WHEN headers.included AND octet_length(metadata.body) <= ?
                    THEN metadata.body END AS graph_header,
                CASE WHEN headers.included AND octet_length(metadata.stream_key) <= ?
                    THEN metadata.stream_key END AS graph_stream,
                metadata.method_version, metadata.first_cursor,
                coalesce(charges.stored_bytes, 0)::UBIGINT, headers.included
             FROM main.analysis_results metadata JOIN requested USING (result_id)
             LEFT JOIN charges USING (result_id) CROSS JOIN headers
             ORDER BY metadata.result_id",
            GraphRows::CHARGES
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
