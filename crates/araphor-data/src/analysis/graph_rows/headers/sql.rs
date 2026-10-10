use duckdb::types::Value;

use super::GraphRows;

impl GraphRows {
    pub(super) fn header_values(tenant: [u8; 16], ids: &[String]) -> Vec<Value> {
        let mut values = ids.iter().cloned().map(Value::Text).collect::<Vec<_>>();
        values.extend([
            Value::Blob(tenant.to_vec()),
            Value::Text(crate::GRAPH_PROCESSOR.to_owned()),
            Value::UBigInt(crate::GRAPH_SCHEMA_VERSION as u64),
        ]);
        values
    }

    pub(super) fn header_bounds_sql(count: usize) -> String {
        let requested = Self::header_requested(count);
        format!(
            "WITH requested(result_id) AS (VALUES {requested}),
         analysis_results AS (
            SELECT metadata.result_id, metadata.tenant_id FROM main.analysis_results metadata
            JOIN requested USING (result_id)
            WHERE metadata.tenant_id = ? AND metadata.processor_id = ?
                AND metadata.method_version = ?
                AND metadata.stream_key IS NOT NULL
         ), charges AS (
            SELECT result_id, coalesce(sum(bytes), 0)::UBIGINT AS stored
            FROM ({}) GROUP BY result_id
         )
         SELECT metadata.result_id, metadata.method_version, metadata.first_cursor,
            metadata.commit_revision, octet_length(metadata.body),
            octet_length(metadata.stream_key), coalesce(charges.stored, 0)::UBIGINT
         FROM main.analysis_results metadata JOIN analysis_results selected USING (result_id)
         LEFT JOIN charges USING (result_id) ORDER BY metadata.result_id",
            Self::CHARGES
        )
    }

    pub(super) fn header_payload_sql(count: usize) -> String {
        let requested = Self::header_requested(count);
        format!(
            "WITH requested(result_id) AS (VALUES {requested})
         SELECT metadata.result_id, metadata.body, metadata.stream_key
         FROM main.analysis_results metadata JOIN requested USING (result_id)
         WHERE metadata.tenant_id = ? AND metadata.processor_id = ?
            AND metadata.method_version = ?
            AND metadata.stream_key IS NOT NULL ORDER BY metadata.result_id"
        )
    }

    fn header_requested(count: usize) -> String {
        std::iter::repeat_n("(?)", count)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
