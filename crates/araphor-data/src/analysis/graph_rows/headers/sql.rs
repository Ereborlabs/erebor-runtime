use duckdb::types::Value;

use super::GraphRows;

impl GraphRows {
    pub(super) fn header_values(tenant: [u8; 16], ids: &[String]) -> Vec<Value> {
        let mut values = ids.iter().cloned().map(Value::Text).collect::<Vec<_>>();
        values.extend([
            Value::UBigInt(crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64),
            Value::Blob(tenant.to_vec()),
            Value::Text(crate::GRAPH_PROCESSOR.to_owned()),
            Value::UBigInt(crate::GRAPH_SCHEMA_VERSION as u64),
        ]);
        values
    }

    pub(super) fn header_sql(count: usize) -> String {
        let requested = Self::header_requested(count);
        format!(
            "WITH requested(result_id) AS (VALUES {requested})
         SELECT metadata.result_id, metadata.body,
            CASE WHEN octet_length(metadata.stream_key) <= ?
                THEN metadata.stream_key ELSE NULL END,
            metadata.method_version, metadata.first_cursor, metadata.commit_revision
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
