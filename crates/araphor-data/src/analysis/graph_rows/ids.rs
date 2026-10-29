use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::relationships::StoredEdge;
use super::{GraphRows, GraphValueIds};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisContractSnafu, AnalysisDatabaseSnafu, DiscoveryRecordIdV1, GraphInvalidSnafu,
    GraphSnapshotV1, GraphSubjectKeyV1, Result,
};
use araphor_analysis_builtins::graph::RelationshipIdentity;
use std::collections::BTreeMap;

impl GraphRows {
    pub(in crate::analysis) fn retained_ids(
        writer: &Connection,
        result: &PackageResultRefV1,
        graph: &GraphSnapshotV1,
    ) -> Result<GraphValueIds> {
        let (lineage, revision): (u64, u64) = writer
            .query_row(
                "SELECT lineage_id, commit_revision FROM graph_versions WHERE result_id = ?",
                params![result.result_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read retained Graph version",
            })?;
        if revision != result.commit_revision {
            return GraphInvalidSnafu {
                field: "retained Graph revision",
            }
            .fail();
        }

        let mut evidence = BTreeMap::new();
        let mut evidence_by_id = BTreeMap::new();
        let mut statement = writer
            .prepare(
                "SELECT e.evidence_id, s.stream_key, s.tenant_id, e.cpu_id, e.durable_cursor
             FROM graph_evidence_membership m JOIN graph_evidence e USING (evidence_id)
             JOIN graph_sources s USING (source_ref)
             WHERE m.lineage_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retained Graph evidence",
            })?;
        let mut rows = statement
            .query(params![lineage, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read retained Graph evidence",
            })?;
        let source_key = graph.scope.identity.key();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance retained Graph evidence",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let key: Vec<u8> = Self::column(row, 1)?;
            let tenant: Vec<u8> = Self::column(row, 2)?;
            let cpu: u32 = Self::column(row, 3)?;
            let cursor: u64 = Self::column(row, 4)?;
            if key != source_key
                || tenant.as_slice() != graph.scope.identity.tenant_id.as_slice()
                || evidence.insert((cpu, cursor), id).is_some()
                || evidence_by_id
                    .insert(
                        id,
                        DiscoveryRecordIdV1 {
                            stream: graph.scope.identity.clone(),
                            cpu_id: cpu,
                            durable_cursor: cursor,
                        },
                    )
                    .is_some()
            {
                return GraphInvalidSnafu {
                    field: "retained Graph evidence identity",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        if evidence.len() != graph.input_manifest.evidence.len()
            || graph.input_manifest.evidence.iter().any(|record| {
                record.stream != graph.scope.identity
                    || !evidence.contains_key(&(record.cpu_id, record.durable_cursor))
            })
        {
            return GraphInvalidSnafu {
                field: "retained Graph evidence",
            }
            .fail();
        }

        let mut subjects = BTreeMap::new();
        let mut subject_by_id = BTreeMap::<u64, GraphSubjectKeyV1>::new();
        let mut statement = writer
            .prepare(
                "SELECT s.subject_id, s.tenant_id, s.authority_rank, s.authority_text,
                s.authority_boot, s.authority_epoch, s.subject_kind, s.identity
             FROM graph_subject_membership m JOIN graph_subject_values s USING (subject_id)
             WHERE m.lineage_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retained Graph subjects",
            })?;
        let mut rows = statement
            .query(params![lineage, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read retained Graph subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance retained Graph subjects",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let key = Self::decode_subject(row)?;
            if subjects.insert(key.clone(), id).is_some() || subject_by_id.insert(id, key).is_some()
            {
                return GraphInvalidSnafu {
                    field: "retained Graph subject identity",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        if subjects.len() != graph.graph.subjects.len()
            || graph
                .graph
                .subjects
                .iter()
                .any(|key| !subjects.contains_key(key))
        {
            return GraphInvalidSnafu {
                field: "retained Graph subjects",
            }
            .fail();
        }

        let mut edges = BTreeMap::new();
        let mut statement = writer
            .prepare(
                "SELECT e.edge_id, e.from_ref, e.to_ref, e.edge_type, e.package_id, e.cause,
                e.evidence_refs, e.proof_quality.source_authority,
                e.proof_quality.local_subject_binding, e.proof_quality.remote_subject_binding,
                e.proof_quality.operation_result_authority, e.proof_quality.temporal_coverage,
                e.proof_quality.integrity, e.required_coverage_interval_ids,
                e.first_boottime_ns, e.edge_type_rank, e.cause_rank, e.last_boottime_ns
             FROM graph_edge_membership m JOIN graph_edge_values_expanded e USING (edge_id)
             WHERE m.lineage_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retained Graph edges",
            })?;
        let mut rows = statement
            .query(params![lineage, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read retained Graph edges",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance retained Graph edges",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let key = StoredEdge::from_row(row)?.identity(&subject_by_id, &evidence_by_id)?;
            if edges.insert(key, id).is_some() {
                return GraphInvalidSnafu {
                    field: "retained Graph edge identity",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        if edges.len() != graph.graph.edges.len() {
            return GraphInvalidSnafu {
                field: "retained Graph edges",
            }
            .fail();
        }
        for edge in &graph.graph.edges {
            let key = RelationshipIdentity::from_keys(
                &edge.key,
                &graph.graph.subjects,
                &graph.input_manifest.evidence,
            )
            .context(AnalysisContractSnafu)?;
            if !edges.contains_key(&key) {
                return GraphInvalidSnafu {
                    field: "retained Graph edge",
                }
                .fail();
            }
        }

        let mut findings = BTreeMap::new();
        let mut statement = writer
            .prepare(
                "SELECT f.value_id, f.finding_id
             FROM graph_finding_membership m JOIN graph_finding_values f USING (value_id)
             WHERE m.lineage_id = ? AND m.valid_from <= ?
                 AND (m.valid_to IS NULL OR m.valid_to > ?)",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retained Graph findings",
            })?;
        let mut rows = statement
            .query(params![lineage, revision, revision])
            .context(AnalysisDatabaseSnafu {
                operation: "read retained Graph findings",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance retained Graph findings",
        })? {
            let id: u64 = Self::column(row, 0)?;
            let key: String = Self::column(row, 1)?;
            if findings.insert(key, id).is_some() {
                return GraphInvalidSnafu {
                    field: "retained Graph finding identity",
                }
                .fail();
            }
        }
        if findings.len() != graph.findings.len()
            || graph
                .findings
                .iter()
                .any(|finding| !findings.contains_key(&finding.finding_id))
        {
            return GraphInvalidSnafu {
                field: "retained Graph findings",
            }
            .fail();
        }
        Ok(GraphValueIds {
            evidence,
            subjects,
            edges,
            findings,
        })
    }
}
