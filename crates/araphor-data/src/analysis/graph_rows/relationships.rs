use super::GraphRows;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphEdgeKeyV1, GraphEdgeV1, GraphInvalidSnafu,
    Result,
};
use duckdb::{params, params_from_iter, types::Value, Connection, Row, Statement};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelationshipRow {
    from: Vec<u8>,
    to: Vec<u8>,
    edge_type: String,
    package: String,
    cause: String,
    evidence: Vec<u8>,
    proof: Vec<u8>,
    coverage: Vec<u8>,
    first: u64,
    last: u64,
}

impl RelationshipRow {
    pub(super) const COLUMNS: &str = "ordinal, from_subject_id, to_subject_id, edge_type,
        package_id, cause, evidence, proof_quality, required_coverage_interval_ids,
        first_boottime_ns, last_boottime_ns";
    pub(super) const INSERT: &str =
        "INSERT INTO graph_relationships VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    pub(super) fn encode(edge: &GraphEdgeV1) -> Result<Self> {
        Ok(Self {
            from: GraphRows::json(&edge.key.from)?,
            to: GraphRows::json(&edge.key.to)?,
            edge_type: GraphRows::label(&edge.key.edge_type)?,
            package: edge.key.package_id.clone(),
            cause: GraphRows::label(&edge.key.cause)?,
            evidence: GraphRows::json(&edge.key.evidence)?,
            proof: GraphRows::json(&edge.proof_quality)?,
            coverage: GraphRows::json(&edge.required_coverage_interval_ids)?,
            first: edge.first_boottime_ns,
            last: edge.last_boottime_ns,
        })
    }

    pub(super) fn insert(
        &self,
        writer: &mut Statement<'_>,
        result_id: &str,
        ordinal: usize,
    ) -> Result<()> {
        writer
            .execute(params![
                result_id,
                ordinal as u32,
                &self.from,
                &self.to,
                &self.edge_type,
                &self.package,
                &self.cause,
                &self.evidence,
                &self.proof,
                &self.coverage,
                self.first,
                self.last
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph relationship",
            })?;
        Ok(())
    }

    pub(super) fn bytes(&self) -> usize {
        256 + self.from.len()
            + self.to.len()
            + self.edge_type.len()
            + self.package.len()
            + self.cause.len()
            + self.evidence.len()
            + self.proof.len()
            + self.coverage.len()
    }

    fn columns(row: &Row<'_>) -> duckdb::Result<Self> {
        Ok(Self {
            from: row.get(1)?,
            to: row.get(2)?,
            edge_type: row.get(3)?,
            package: row.get(4)?,
            cause: row.get(5)?,
            evidence: row.get(6)?,
            proof: row.get(7)?,
            coverage: row.get(8)?,
            first: row.get(9)?,
            last: row.get(10)?,
        })
    }

    fn decode(self) -> Result<GraphEdgeV1> {
        let edge = GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: GraphRows::decode(&self.from)?,
                to: GraphRows::decode(&self.to)?,
                edge_type: GraphRows::parse(&self.edge_type)?,
                package_id: self.package,
                evidence: GraphRows::decode(&self.evidence)?,
                cause: GraphRows::parse(&self.cause)?,
            },
            proof_quality: GraphRows::decode(&self.proof)?,
            required_coverage_interval_ids: GraphRows::decode(&self.coverage)?,
            first_boottime_ns: self.first,
            last_boottime_ns: self.last,
        };
        edge.key.from.validate()?;
        edge.key.to.validate()?;
        if edge.first_boottime_ns > edge.last_boottime_ns {
            return GraphInvalidSnafu {
                field: "relationship time order",
            }
            .fail();
        }
        Ok(edge)
    }
}

impl GraphRows {
    pub(in crate::analysis) fn edge_name(kind: &crate::GraphEdgeTypeV1) -> Result<String> {
        Self::label(kind)
    }

    pub(in crate::analysis) fn selected_edges(
        reader: &Connection,
        result_id: &str,
        ordinals: &[u32],
        control: &AnalysisReadControl,
    ) -> Result<Vec<GraphEdgeV1>> {
        if ordinals.len() > 4096 || ordinals.windows(2).any(|pair| pair[0] >= pair[1]) {
            return GraphInvalidSnafu {
                field: "selected graph edge ordinals",
            }
            .fail();
        }
        let mut selected = Vec::new();
        for ordinals in ordinals.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            control.check()?;
            let values = std::iter::repeat_n("(?)", ordinals.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut parameters = ordinals
                .iter()
                .map(|ordinal| Value::UInt(*ordinal))
                .collect::<Vec<_>>();
            parameters.push(Value::Text(result_id.to_owned()));
            let columns = RelationshipRow::COLUMNS
                .split(',')
                .map(|column| format!("edge.{}", column.trim()))
                .collect::<Vec<_>>()
                .join(", ");
            let mut statement = reader
                .prepare(&format!(
                    "WITH requested(ordinal) AS (VALUES {values}) SELECT {columns}
                 FROM graph_relationships edge JOIN requested USING (ordinal)
                 WHERE result_id = ? ORDER BY edge.ordinal"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected graph relationships",
                })?;
            let mut rows = statement
                .query(params_from_iter(parameters.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected graph relationships",
                })?;
            let start = selected.len();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance selected graph relationships",
            })? {
                control.check()?;
                let ordinal: u32 = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode selected graph edge ordinal",
                })?;
                if ordinals.get(selected.len() - start) != Some(&ordinal) {
                    return GraphInvalidSnafu {
                        field: "selected graph edge ordinals",
                    }
                    .fail();
                }
                selected.push(
                    RelationshipRow::columns(row)
                        .context(AnalysisDatabaseSnafu {
                            operation: "decode selected graph relationship columns",
                        })?
                        .decode()?,
                );
            }
            if selected.len() - start != ordinals.len() {
                return GraphInvalidSnafu {
                    field: "selected graph edge ordinals",
                }
                .fail();
            }
        }
        control.check()?;
        Ok(selected)
    }

    pub(in crate::analysis) fn read_edges(
        writer: &Connection,
        result_id: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphEdgeV1>> {
        Self::load(
            writer,
            "graph_relationships",
            RelationshipRow::COLUMNS,
            result_id,
            4096,
            control,
            RelationshipRow::columns,
        )?
        .into_iter()
        .map(|row| {
            if let Some(control) = control {
                control.check()?;
            }
            row.decode()
        })
        .collect()
    }
}
