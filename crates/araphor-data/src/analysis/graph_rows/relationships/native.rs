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

const PROPERTY_COLUMNS: &str = "property_ref, edge_type, package_id, cause,
    proof_quality.source_authority, proof_quality.local_subject_binding,
    proof_quality.remote_subject_binding, proof_quality.operation_result_authority,
    proof_quality.temporal_coverage, proof_quality.integrity,
    required_coverage_interval_ids, edge_type_rank, cause_rank, property_hash";

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

#[derive(Clone, PartialEq, Serialize)]
struct StoredEdgeProperty {
    edge_type: GraphEdgeTypeV1,
    package_id: String,
    cause: GraphCauseV1,
    proof_quality: ProofQualityV1,
    coverage: Vec<[u8; 16]>,
}

impl StoredEdgeProperty {
    fn hash(&self) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        self.serialize(&mut rmp_serde::Serializer::new(&mut digest))
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph edge property encoding",
                }
                .build()
            })?;
        Ok(digest.finalize().into())
    }

    fn from_row(row: &Row<'_>) -> Result<Self> {
        let edge_type: GraphEdgeTypeV1 = GraphRows::label_column(row, 1)?;
        let cause: GraphCauseV1 = GraphRows::label_column(row, 3)?;
        let type_rank: u8 = GraphRows::column(row, 11)?;
        let cause_rank: u8 = GraphRows::column(row, 12)?;
        if type_rank != edge_type as u8 || cause_rank != cause as u8 {
            return GraphInvalidSnafu {
                field: "graph edge property rank",
            }
            .fail();
        }
        Ok(Self {
            edge_type,
            package_id: GraphRows::column(row, 2)?,
            cause,
            proof_quality: ProofQualityV1 {
                source_authority: GraphRows::enum_column(row, 4)?,
                local_subject_binding: GraphRows::enum_column(row, 5)?,
                remote_subject_binding: GraphRows::enum_column(row, 6)?,
                operation_result_authority: GraphRows::enum_column(row, 7)?,
                temporal_coverage: GraphRows::enum_column(row, 8)?,
                integrity: GraphRows::enum_column(row, 9)?,
            },
            coverage: GraphRows::coverage_column(row, 10)?,
        })
    }
}

impl StoredEdge {
    fn property(&self) -> StoredEdgeProperty {
        StoredEdgeProperty {
            edge_type: self.edge_type,
            package_id: self.package_id.clone(),
            cause: self.cause,
            proof_quality: self.proof_quality.clone(),
            coverage: self.coverage.clone(),
        }
    }

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
            .prepare(&format!(
                "SELECT {PROPERTY_COLUMNS} FROM graph_edge_properties"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare graph edge property validation",
            })?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read graph edge properties for validation",
        })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance graph edge property validation",
        })? {
            let value = StoredEdgeProperty::from_row(row)?;
            let hash: Vec<u8> = Self::column(row, 13)?;
            if hash.as_slice() != value.hash()? {
                return GraphInvalidSnafu {
                    field: "graph edge property hash",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        let mut statement = writer
            .prepare(
                "SELECT edge_id, from_ref, to_ref, edge_type, package_id, cause,
                evidence_refs, proof_quality.source_authority,
                proof_quality.local_subject_binding, proof_quality.remote_subject_binding,
                proof_quality.operation_result_authority, proof_quality.temporal_coverage,
                proof_quality.integrity, required_coverage_interval_ids,
                first_boottime_ns, edge_type_rank, cause_rank, last_boottime_ns, value_hash
             FROM graph_edge_values_expanded",
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

    fn stage_lookup_hashes(writer: &Connection, hashes: &BTreeSet<[u8; 32]>) -> Result<()> {
        let mut appender = writer
            .appender_to_catalog_and_db("graph_value_lookup_hashes", "temp", "main")
            .context(AnalysisDatabaseSnafu {
                operation: "prepare graph value lookup hashes",
            })?;
        for hash in hashes {
            appender
                .append_row(params![hash.as_slice()])
                .context(AnalysisDatabaseSnafu {
                    operation: "append graph value lookup hash",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush graph value lookup hashes",
        })?;
        drop(appender);
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
        let requested = graph
            .graph
            .edges
            .iter()
            .map(|edge| {
                let value = StoredEdge::new(edge, graph, subjects, evidence)?;
                let hash = value.hash()?;
                let key = RelationshipIdentity::from_keys(
                    &edge.key,
                    &graph.graph.subjects,
                    &graph.input_manifest.evidence,
                )
                .context(AnalysisContractSnafu)?;
                Ok((key, value, hash))
            })
            .collect::<Result<Vec<_>>>()?;
        let hashes = requested
            .iter()
            .map(|(_, _, hash)| *hash)
            .collect::<BTreeSet<_>>();
        let properties = requested
            .iter()
            .map(|(_, value, _)| value.property())
            .collect::<Vec<_>>();
        let property_hashes = properties
            .iter()
            .map(StoredEdgeProperty::hash)
            .collect::<Result<BTreeSet<_>>>()?;
        let mut property_ids = Vec::with_capacity(properties.len());
        let mut candidates = BTreeMap::<[u8; 32], Vec<(u64, StoredEdge)>>::new();
        if !hashes.is_empty() {
            writer
                .execute_batch(
                    "CREATE TEMPORARY TABLE temp.main.graph_value_lookup_hashes
                    (value_hash BLOB PRIMARY KEY)",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "create graph value lookup",
                })?;
            let lookup = (|| -> Result<()> {
                Self::stage_lookup_hashes(writer, &property_hashes)?;
                let mut property_candidates =
                    BTreeMap::<[u8; 32], Vec<(u64, StoredEdgeProperty)>>::new();
                let mut statement = writer
                    .prepare(&format!(
                        "SELECT {PROPERTY_COLUMNS} FROM graph_edge_properties p
                        JOIN temp.main.graph_value_lookup_hashes h
                            ON p.property_hash = h.value_hash"
                    ))
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare graph edge property lookup",
                    })?;
                let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                    operation: "read graph edge property candidates",
                })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "advance graph edge property candidates",
                })? {
                    let id = GraphRows::column(row, 0)?;
                    let value = StoredEdgeProperty::from_row(row)?;
                    let hash: [u8; 32] = GraphRows::column::<Vec<u8>>(row, 13)?
                        .try_into()
                        .map_err(|_| {
                            GraphInvalidSnafu {
                                field: "graph edge property hash",
                            }
                            .build()
                        })?;
                    if value.hash()? != hash
                        || property_candidates
                            .entry(hash)
                            .or_default()
                            .iter()
                            .any(|(_, known)| known == &value)
                    {
                        return GraphInvalidSnafu {
                            field: "duplicate graph edge property",
                        }
                        .fail();
                    }
                    property_candidates
                        .entry(hash)
                        .or_default()
                        .push((id, value));
                }
                drop(rows);
                drop(statement);
                let mut next_property: u64 = writer
                    .query_row(
                        "SELECT coalesce(max(property_ref), 0) FROM graph_edge_properties",
                        [],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read next graph edge property ID",
                    })?;
                let mut new_properties: Vec<(u64, StoredEdgeProperty, [u8; 32])> = Vec::new();
                let mut new_by_hash = BTreeMap::<[u8; 32], Vec<usize>>::new();
                for property in properties {
                    let hash = property.hash()?;
                    let mut found = property_candidates.get(&hash).and_then(|bucket| {
                        bucket
                            .iter()
                            .find(|(_, candidate)| candidate == &property)
                            .map(|(id, _)| *id)
                    });
                    for index in new_by_hash.get(&hash).into_iter().flatten() {
                        if new_properties[*index].1 == property
                            && found.replace(new_properties[*index].0).is_some()
                        {
                            return GraphInvalidSnafu {
                                field: "duplicate graph edge property",
                            }
                            .fail();
                        }
                    }
                    let id = if let Some(id) = found {
                        id
                    } else {
                        next_property = next_property.checked_add(1).ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "graph edge property ID",
                            }
                            .build()
                        })?;
                        new_by_hash
                            .entry(hash)
                            .or_default()
                            .push(new_properties.len());
                        new_properties.push((next_property, property, hash));
                        next_property
                    };
                    property_ids.push(id);
                }
                if !new_properties.is_empty() {
                    let mut appender = writer.appender("graph_edge_properties").context(
                        AnalysisDatabaseSnafu {
                            operation: "prepare graph edge property insert",
                        },
                    )?;
                    Self::append_edge_properties(&mut appender, &new_properties)?;
                    appender.flush().context(AnalysisDatabaseSnafu {
                        operation: "flush graph edge properties",
                    })?;
                    drop(appender);
                }
                writer
                    .execute_batch("DELETE FROM temp.main.graph_value_lookup_hashes")
                    .context(AnalysisDatabaseSnafu {
                        operation: "clear graph value lookup",
                    })?;
                Self::stage_lookup_hashes(writer, &hashes)?;
                let mut statement = writer
                    .prepare(
                        "SELECT edge_id, from_ref, to_ref, edge_type, package_id, cause,
                        evidence_refs, proof_quality.source_authority,
                        proof_quality.local_subject_binding, proof_quality.remote_subject_binding,
                        proof_quality.operation_result_authority, proof_quality.temporal_coverage,
                        proof_quality.integrity, required_coverage_interval_ids,
                        first_boottime_ns, edge_type_rank, cause_rank, last_boottime_ns, value_hash
                        FROM graph_edge_values_expanded
                        JOIN temp.main.graph_value_lookup_hashes USING (value_hash)",
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare graph edge value lookup",
                    })?;
                let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
                    operation: "read graph edge value candidates",
                })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "advance graph edge value candidates",
                })? {
                    let id = GraphRows::column(row, 0)?;
                    let value = StoredEdge::from_row(row)?;
                    let hash: [u8; 32] = GraphRows::column::<Vec<u8>>(row, 18)?
                        .try_into()
                        .map_err(|_| {
                            GraphInvalidSnafu {
                                field: "graph edge value hash",
                            }
                            .build()
                        })?;
                    if value.hash()? != hash
                        || candidates
                            .entry(hash)
                            .or_default()
                            .iter()
                            .any(|(_, known)| known == &value)
                    {
                        return GraphInvalidSnafu {
                            field: "duplicate graph edge value",
                        }
                        .fail();
                    }
                    candidates.entry(hash).or_default().push((id, value));
                }
                Ok(())
            })();
            let cleanup = writer
                .execute_batch("DROP TABLE temp.main.graph_value_lookup_hashes")
                .context(AnalysisDatabaseSnafu {
                    operation: "drop graph value lookup",
                });
            lookup?;
            cleanup?;
        }
        let mut selected = BTreeSet::new();
        let mut values = BTreeMap::new();
        let mut added: Vec<(u64, StoredEdge, [u8; 32], u64)> = Vec::new();
        let mut new_by_hash = BTreeMap::<[u8; 32], Vec<usize>>::new();
        for ((key, value, hash), property_ref) in requested.into_iter().zip(property_ids) {
            let mut found = candidates.get(&hash).and_then(|bucket| {
                bucket
                    .iter()
                    .find(|(_, candidate)| candidate == &value)
                    .map(|(id, _)| *id)
            });
            for index in new_by_hash.get(&hash).into_iter().flatten() {
                if added[*index].1 == value {
                    if found.replace(added[*index].0).is_some() {
                        return GraphInvalidSnafu {
                            field: "duplicate graph edge value",
                        }
                        .fail();
                    }
                }
            }
            let id = if let Some(id) = found {
                id
            } else {
                next = next.checked_add(1).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph edge ID",
                    }
                    .build()
                })?;
                new_by_hash.entry(hash).or_default().push(added.len());
                added.push((next, value, hash, property_ref));
                next
            };
            if !selected.insert(id) {
                return GraphInvalidSnafu {
                    field: "duplicate graph edge membership",
                }
                .fail();
            }
            if values.insert(key, id).is_some() {
                return GraphInvalidSnafu {
                    field: "duplicate stable graph edge identity",
                }
                .fail();
            }
        }
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
