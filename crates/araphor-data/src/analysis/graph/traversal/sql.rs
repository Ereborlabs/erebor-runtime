use duckdb::types::Value;
use snafu::ResultExt as _;

use super::read::{GraphWalk, WalkRows};
use crate::analysis::graph_rows::GraphRows;
use crate::{GraphEncodingSnafu, GraphTraversalDirectionV1, Result};

impl GraphWalk<'_> {
    pub(super) fn query(&self) -> Result<(String, Vec<Value>)> {
        let requested = std::iter::repeat_n("(?)", self.result_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let seeds = std::iter::repeat_n("(?, ?, ?, ?, ?)", self.request.seeds.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut values = self
            .result_ids
            .iter()
            .cloned()
            .map(Value::Text)
            .collect::<Vec<_>>();
        for seed in &self.request.seeds {
            values.push(Value::Blob(
                serde_json::to_vec(seed).context(GraphEncodingSnafu)?,
            ));
            values.extend(GraphRows::subject_fields(seed)?);
        }
        values.push(Value::Boolean(self.binding_scope));
        let filter = if self.request.edge_types.is_empty() {
            String::new()
        } else {
            let parameters = std::iter::repeat_n("?", self.request.edge_types.len())
                .collect::<Vec<_>>()
                .join(", ");
            for kind in &self.request.edge_types {
                values.push(Value::Text(GraphRows::edge_name(kind)?));
            }
            format!("WHERE e.edge_type IN ({parameters})")
        };
        let links = match self.request.direction {
            GraphTraversalDirectionV1::Outgoing => {
                "SELECT from_subject_id AS source, to_subject_id AS target FROM edges"
            }
            GraphTraversalDirectionV1::Incoming => {
                "SELECT to_subject_id AS source, from_subject_id AS target FROM edges"
            }
            GraphTraversalDirectionV1::Both => {
                "SELECT from_subject_id AS source, to_subject_id AS target FROM edges
                 UNION ALL SELECT to_subject_id, from_subject_id FROM edges"
            }
        };
        // NULL removes the early stop when its value does not fit native BIGINT.
        let edge_limit = self
            .request
            .max_relationships
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .map_or(Value::Null, Value::BigInt);
        values.extend([
            Value::BigInt(self.request.max_hops as i64),
            Value::UBigInt(self.request.max_subjects.saturating_add(1) as u64),
            Value::BigInt(self.request.max_hops as i64),
            edge_limit,
            Value::BigInt(self.request.max_hops as i64),
            Value::BigInt(std::mem::size_of::<WalkRows>() as i64),
            Value::BigInt(std::mem::size_of::<(crate::GraphSubjectKeyV1, u32)>() as i64),
            Value::BigInt(std::mem::size_of::<(String, u32)>() as i64),
            Value::UBigInt(self.request.max_subjects as u64),
            Value::UBigInt(self.request.max_relationships as u64),
            Value::BigInt(self.input_bytes.min(i64::MAX as usize) as i64),
        ]);
        let subject_permission = GraphRows::subject_permission(self.binding_scope);
        let query = format!(
            "WITH RECURSIVE requested(result_id) AS (VALUES {requested}),
             seeds(subject_id, tenant_id, subject_kind, authority, identity) AS (VALUES {seeds}),
             eligible_edges AS NOT MATERIALIZED (
                 SELECT e.result_id, e.ordinal,
                     struct_pack(tenant_id := source.tenant_id, subject_kind := source.subject_kind,
                         authority := source.authority, identity := source.identity) AS from_subject_id,
                     struct_pack(tenant_id := target.tenant_id, subject_kind := target.subject_kind,
                         authority := target.authority, identity := target.identity) AS to_subject_id,
                     e.edge_type
                 FROM graph_relationships e JOIN requested USING (result_id)
                 LEFT JOIN graph_subjects source ON source.result_id = e.result_id
                     AND source.ordinal = e.from_subject_id
                 LEFT JOIN graph_subjects target ON target.result_id = e.result_id
                     AND target.ordinal = e.to_subject_id
                 WHERE NOT ? OR array_length(e.evidence) > 0
             ), edges AS MATERIALIZED (
                 SELECT result_id, ordinal, from_subject_id, to_subject_id
                 FROM eligible_edges e {filter}
             ), links AS ({links}),
             reach(subject_id, depth) USING KEY (subject_id) AS (
                 SELECT DISTINCT struct_pack(tenant_id := seed.tenant_id,
                     subject_kind := seed.subject_kind, authority := seed.authority,
                     identity := seed.identity), 0::UINTEGER
                 FROM seeds seed WHERE EXISTS (
                     SELECT 1 FROM graph_subjects subject JOIN requested USING (result_id)
                     WHERE subject.tenant_id = seed.tenant_id
                         AND subject.subject_kind = seed.subject_kind
                         AND subject.authority = seed.authority AND subject.identity = seed.identity
                         AND ({subject_permission})
                 )
                 UNION ALL (
                     SELECT link.target, (min(frontier.depth) + 1)::UINTEGER
                     FROM reach frontier JOIN links link ON link.source = frontier.subject_id
                     WHERE frontier.depth < ? AND NOT EXISTS (
                         SELECT 1 FROM recurring.reach visited
                         WHERE visited.subject_id = link.target
                     )
                     GROUP BY link.target
                     QUALIFY row_number() OVER (ORDER BY link.target)
                         <= ? - (SELECT count(*) FROM recurring.reach)
                 )
             ), edge_keys AS (
                 SELECT DISTINCT edge.result_id, edge.ordinal
                 FROM edges edge WHERE ? > 0
                     AND EXISTS (SELECT 1 FROM reach WHERE subject_id = edge.from_subject_id)
                     AND EXISTS (SELECT 1 FROM reach WHERE subject_id = edge.to_subject_id)
                 ORDER BY edge.result_id, edge.ordinal LIMIT ?
             ), summary AS (
                 SELECT (SELECT count(*) FROM reach) AS subject_count,
                     (SELECT count(*) FROM edge_keys) AS edge_count,
                     EXISTS (SELECT 1 FROM reach boundary
                         JOIN links link ON link.source = boundary.subject_id
                         WHERE boundary.depth = ? AND NOT EXISTS (
                             SELECT 1 FROM reach visited WHERE visited.subject_id = link.target
                         )) AS hop_boundary,
                     ? + 2 * (coalesce((SELECT sum(octet_length(subject_id.tenant_id)
                             + octet_length(encode(subject_id.subject_kind))
                             + octet_length(subject_id.authority)
                             + octet_length(subject_id.identity)) FROM reach), 0)
                         + (SELECT count(*) FROM reach) * ?
                         + coalesce((SELECT sum(octet_length(encode(result_id))) FROM edge_keys), 0)
                         + (SELECT count(*) FROM edge_keys) * ?) AS bytes
             ), bounded AS (
                 SELECT *, subject_count <= ? AND edge_count <= ? AND bytes <= ? AS included
                 FROM summary
             ), output AS (
                 SELECT 0::UTINYINT AS kind, NULL::STRUCT(tenant_id BLOB, subject_kind VARCHAR,
                         authority BLOB, identity BLOB) AS subject_id,
                     NULL::UINTEGER AS depth, NULL::VARCHAR AS result_id, NULL::UINTEGER AS ordinal,
                     subject_count, edge_count, hop_boundary, bytes FROM bounded
                 UNION ALL SELECT 1, CASE WHEN included THEN subject_id END, depth, NULL, NULL,
                     subject_count, edge_count, hop_boundary, bytes FROM reach CROSS JOIN bounded
                 UNION ALL SELECT 2, NULL, NULL, CASE WHEN included THEN result_id END, ordinal,
                     subject_count, edge_count, hop_boundary, bytes FROM edge_keys CROSS JOIN bounded
             ) SELECT kind, subject_id.tenant_id, subject_id.subject_kind,
                 subject_id.authority, subject_id.identity, depth, result_id, ordinal,
                 subject_count, edge_count, hop_boundary, bytes
             FROM output ORDER BY kind, depth, subject_id, result_id, ordinal"
        );
        Ok((query, values))
    }
}
