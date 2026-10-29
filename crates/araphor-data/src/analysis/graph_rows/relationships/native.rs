use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::{
    discovery::DiscoveryRecordIdV1,
    graph::{Anchor, RelationshipChange, RelationshipIdentity},
};

use duckdb::arrow::array::{Array as _, UInt64Array};
use duckdb::{params, Connection, Row};
use serde::Serialize;
use sha2::{Digest, Sha256};
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{
    AnalysisContractSnafu, AnalysisDatabaseSnafu, GraphCauseV1, GraphEdgeTypeV1, GraphEdgeV1,
    GraphInvalidSnafu, GraphSnapshotV1, GraphSubjectKeyV1, ProofQualityV1, Result,
};

mod arrays;

#[derive(PartialEq, Serialize)]
pub(in crate::analysis::graph_rows) struct StoredEdge {
    pub(in crate::analysis::graph_rows) from: u64,
    pub(in crate::analysis::graph_rows) to: u64,
    edge_type: GraphEdgeTypeV1,
    package_id: String,
    pub(in crate::analysis::graph_rows) evidence: Vec<u64>,
    cause: GraphCauseV1,
    proof_quality: ProofQualityV1,
    coverage: Vec<[u8; 16]>,
    first: u64,
    last: u64,
}

impl StoredEdge {
    fn new(
        row: &GraphEdgeV1,
        graph: &GraphSnapshotV1,
        subjects: &std::collections::BTreeMap<GraphSubjectKeyV1, u64>,
        evidence: &std::collections::BTreeMap<(u32, u64), u64>,
    ) -> Result<Self> {
        let subject = |index: u32| {
            graph
                .graph
                .subjects
                .get(index as usize)
                .and_then(|key| subjects.get(key))
                .copied()
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph edge subject reference",
                    }
                    .build()
                })
        };
        let evidence = row
            .key
            .evidence
            .iter()
            .map(|index| {
                graph
                    .input_manifest
                    .evidence
                    .get(*index as usize)
                    .filter(|record| record.stream == graph.scope.identity)
                    .and_then(|record| evidence.get(&(record.cpu_id, record.durable_cursor)))
                    .copied()
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph edge evidence reference",
                        }
                        .build()
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            from: subject(row.key.from)?,
            to: subject(row.key.to)?,
            edge_type: row.key.edge_type,
            package_id: row.key.package_id.clone(),
            evidence,
            cause: row.key.cause,
            proof_quality: row.proof_quality.clone(),
            coverage: row.required_coverage_interval_ids.clone(),
            first: row.first_boottime_ns,
            last: row.last_boottime_ns,
        })
    }

    fn hash(&self) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        self.serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph edge value encoding",
                }
                .build()
            })?;
        Ok(digest.finalize().into())
    }

    pub(in crate::analysis::graph_rows) fn from_row(row: &Row<'_>) -> Result<Self> {
        let refs = GraphRows::list_column(row, 6)?;
        let refs = refs
            .as_any()
            .downcast_ref::<UInt64Array>()
            .filter(|refs| refs.null_count() == 0)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph edge evidence references",
                }
                .build()
            })?;
        let edge_type: GraphEdgeTypeV1 = GraphRows::label_column(row, 3)?;
        let cause: GraphCauseV1 = GraphRows::label_column(row, 5)?;
        let type_rank: u8 = GraphRows::column(row, 15)?;
        let cause_rank: u8 = GraphRows::column(row, 16)?;
        if type_rank != edge_type as u8 || cause_rank != cause as u8 {
            return GraphInvalidSnafu {
                field: "graph edge type rank",
            }
            .fail();
        }
        let stored = Self {
            from: GraphRows::column(row, 1)?,
            to: GraphRows::column(row, 2)?,
            edge_type,
            package_id: GraphRows::column(row, 4)?,
            evidence: refs.values().to_vec(),
            cause,
            proof_quality: ProofQualityV1 {
                source_authority: GraphRows::enum_column(row, 7)?,
                local_subject_binding: GraphRows::enum_column(row, 8)?,
                remote_subject_binding: GraphRows::enum_column(row, 9)?,
                operation_result_authority: GraphRows::enum_column(row, 10)?,
                temporal_coverage: GraphRows::enum_column(row, 11)?,
                integrity: GraphRows::enum_column(row, 12)?,
            },
            coverage: GraphRows::coverage_column(row, 13)?,
            first: GraphRows::column(row, 14)?,
            last: GraphRows::column(row, 17)?,
        };
        if stored.first > stored.last {
            return GraphInvalidSnafu {
                field: "graph edge time order",
            }
            .fail();
        }
        Ok(stored)
    }

    pub(in crate::analysis::graph_rows) fn into_change(
        self,
        anchor: Anchor,
        subjects: &BTreeMap<u64, GraphSubjectKeyV1>,
        evidence: &BTreeMap<u64, DiscoveryRecordIdV1>,
    ) -> Result<RelationshipChange> {
        let key = self.identity(subjects, evidence)?;
        Ok(RelationshipChange {
            anchor,
            key,
            proof_quality: self.proof_quality,
            required_coverage_interval_ids: self.coverage,
            first_boottime_ns: self.first,
            last_boottime_ns: self.last,
        })
    }

    pub(in crate::analysis::graph_rows) fn identity(
        &self,
        subjects: &BTreeMap<u64, GraphSubjectKeyV1>,
        evidence: &BTreeMap<u64, DiscoveryRecordIdV1>,
    ) -> Result<RelationshipIdentity> {
        let subject = |id: u64| {
            subjects.get(&id).cloned().ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "Graph call edge subject",
                }
                .build()
            })
        };
        let evidence = self
            .evidence
            .iter()
            .map(|id| {
                evidence.get(id).cloned().ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "Graph call edge evidence",
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RelationshipIdentity {
            from: subject(self.from)?,
            to: subject(self.to)?,
            edge_type: self.edge_type,
            package_id: self.package_id.clone(),
            evidence,
            cause: self.cause,
        })
    }
}

impl GraphRows {
    pub(in crate::analysis) fn validate_edge_values(writer: &Connection) -> Result<()> {
        let mut statement = writer
            .prepare(
                "SELECT edge_id, from_ref, to_ref, edge_type, package_id, cause,
                evidence_refs, proof_quality.source_authority,
                proof_quality.local_subject_binding, proof_quality.remote_subject_binding,
                proof_quality.operation_result_authority, proof_quality.temporal_coverage,
                proof_quality.integrity, required_coverage_interval_ids,
                first_boottime_ns, edge_type_rank, cause_rank, last_boottime_ns, value_hash
             FROM graph_edge_values",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare graph edge value validation",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read graph edge values for validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance graph edge value validation",
        })? {
            let value = StoredEdge::from_row(row)?;
            let hash: Vec<u8> = Self::column(row, 18)?;
            if hash.as_slice() != value.hash()? {
                return GraphInvalidSnafu {
                    field: "graph edge value hash",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn insert_edge_values(
        writer: &Connection,
        graph: &GraphSnapshotV1,
        subjects: &std::collections::BTreeMap<GraphSubjectKeyV1, u64>,
        evidence: &std::collections::BTreeMap<(u32, u64), u64>,
        lineage: u64,
        revision: u64,
    ) -> Result<BTreeMap<RelationshipIdentity, u64>> {
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(edge_id), 0) FROM graph_edge_values",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read next graph edge ID",
            })?;
        let mut candidates = writer
            .prepare(
                "SELECT edge_id, from_ref, to_ref, edge_type, package_id, cause,
                evidence_refs, proof_quality.source_authority,
                proof_quality.local_subject_binding, proof_quality.remote_subject_binding,
                proof_quality.operation_result_authority, proof_quality.temporal_coverage,
                proof_quality.integrity, required_coverage_interval_ids,
                first_boottime_ns, edge_type_rank, cause_rank, last_boottime_ns
             FROM graph_edge_values WHERE value_hash = ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare graph edge value lookup",
            })?;
        let mut selected = BTreeSet::new();
        let mut values = BTreeMap::new();
        let mut added = Vec::new();
        for edge in &graph.graph.edges {
            let value = StoredEdge::new(edge, graph, subjects, evidence)?;
            let hash = value.hash()?;
            let mut found = None;
            let mut rows =
                candidates
                    .query(params![hash.as_slice()])
                    .context(AnalysisDatabaseSnafu {
                        operation: "read graph edge value candidates",
                    })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance graph edge value candidates",
            })? {
                let candidate = StoredEdge::from_row(row)?;
                if candidate == value {
                    if found.replace(GraphRows::column(row, 0)?).is_some() {
                        return GraphInvalidSnafu {
                            field: "duplicate graph edge value",
                        }
                        .fail();
                    }
                }
            }
            drop(rows);
            let id = if let Some(id) = found {
                id
            } else {
                next = next.checked_add(1).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph edge ID",
                    }
                    .build()
                })?;
                added.push((next, value, hash));
                next
            };
            if !selected.insert(id) {
                return GraphInvalidSnafu {
                    field: "duplicate graph edge membership",
                }
                .fail();
            }
            let key = RelationshipIdentity::from_keys(
                &edge.key,
                &graph.graph.subjects,
                &graph.input_manifest.evidence,
            )
            .context(AnalysisContractSnafu)?;
            if values.insert(key, id).is_some() {
                return GraphInvalidSnafu {
                    field: "duplicate stable graph edge identity",
                }
                .fail();
            }
        }
        drop(candidates);
        if !added.is_empty() {
            let mut appender =
                writer
                    .appender("graph_edge_values")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare graph edge value insert",
                    })?;
            Self::append_edge_values(&mut appender, &added)?;
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush graph edge values",
            })?;
        }
        let mut active = BTreeSet::new();
        let mut statement = writer
            .prepare(
                "SELECT edge_id FROM graph_edge_membership
             WHERE lineage_id = ? AND valid_to IS NULL",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare active graph edges",
            })?;
        let mut rows = statement
            .query(params![lineage])
            .context(AnalysisDatabaseSnafu {
                operation: "read active graph edges",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance active graph edges",
        })? {
            if !active.insert(GraphRows::column(row, 0)?) {
                return GraphInvalidSnafu {
                    field: "duplicate active graph edge",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for id in active.difference(&selected) {
            let changed = writer
                .execute(
                    "UPDATE graph_edge_membership SET valid_to = ?
                 WHERE lineage_id = ? AND edge_id = ? AND valid_to IS NULL",
                    params![revision, lineage, id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "close graph edge membership",
                })?;
            if changed != 1 {
                return GraphInvalidSnafu {
                    field: "graph edge membership",
                }
                .fail();
            }
        }
        let mut appender =
            writer
                .appender("graph_edge_membership")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare graph edge membership insert",
                })?;
        for id in selected.difference(&active) {
            appender
                .append_row(params![lineage, id, revision, None::<u64>])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert graph edge membership",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush graph edge membership",
        })?;
        Ok(values)
    }
}
