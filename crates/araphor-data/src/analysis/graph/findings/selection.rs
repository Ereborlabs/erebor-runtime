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
            SELECT finding.result_id, finding.finding_id,
                (256 + octet_length(encode(finding.result_id))
                + octet_length(finding.tenant_id) + octet_length(encode(finding.finding_id))
                + octet_length(encode(finding.package_id)) + octet_length(finding.subject_id)
                + octet_length(encode(finding.state)) + octet_length(finding.evidence)
                + octet_length(finding.required_coverage_interval_ids)
                + octet_length(finding.policy_provenance) + octet_length(finding.effects)
                + octet_length(encode(finding.reason)) + octet_length(encode(finding.severity))
                + octet_length(encode(finding.sensitivity))
                + coalesce(octet_length(encode(finding.required_action)), 0)
                + octet_length(finding.limits))::UBIGINT AS finding_bytes
            FROM graph_findings finding JOIN heads USING (result_id)
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY finding_id
                ORDER BY commit_revision DESC, finding.result_id DESC) = 1
         )
         SELECT result_id,
            finding_id,
            finding_bytes
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
             ), subject_counts AS (
                SELECT result_id, count(*)::UBIGINT AS subjects
                FROM graph_subjects JOIN requested USING (result_id) GROUP BY result_id
             ), edge_counts AS (
                SELECT result_id, count(*)::UBIGINT AS edges
                FROM graph_relationships JOIN requested USING (result_id) GROUP BY result_id
             ), finding_counts AS (
                SELECT result_id, count(*)::UBIGINT AS findings
                FROM graph_findings JOIN requested USING (result_id) GROUP BY result_id
             ), headers AS (
                SELECT coalesce(sum(coalesce(octet_length(metadata.body), 0)
                    + octet_length(metadata.stream_key)
                    + octet_length(encode(metadata.result_id))), 0) <= ? AS included
                FROM main.analysis_results metadata JOIN requested USING (result_id)
             )
             SELECT metadata.result_id,
                CASE WHEN headers.included AND octet_length(metadata.body) <= ?
                    THEN metadata.body END AS graph_header,
                CASE WHEN headers.included AND octet_length(metadata.stream_key) <= ?
                    THEN metadata.stream_key END AS graph_stream,
                metadata.method_version, metadata.first_cursor,
                coalesce(charges.stored_bytes, 0)::UBIGINT, headers.included,
                octet_length(metadata.body)::UBIGINT,
                coalesce(subject_counts.subjects, 0)::UBIGINT,
                coalesce(edge_counts.edges, 0)::UBIGINT,
                coalesce(finding_counts.findings, 0)::UBIGINT
             FROM main.analysis_results metadata JOIN requested USING (result_id)
             LEFT JOIN charges USING (result_id)
             LEFT JOIN subject_counts USING (result_id)
             LEFT JOIN edge_counts USING (result_id)
             LEFT JOIN finding_counts USING (result_id) CROSS JOIN headers
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
