use super::GraphRows;
use crate::GraphValidate as _;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphEdgeKeyV1, GraphEdgeV1, GraphInvalidSnafu,
    Result,
};
use duckdb::{params, params_from_iter, types::Value, Appender, Connection, Row};
use snafu::ResultExt as _;

const COLUMNS: &str = "ordinal, from_subject_id, to_subject_id, edge_type,
        package_id, cause, evidence, proof_quality, required_coverage_interval_ids,
        first_boottime_ns, last_boottime_ns";

impl GraphRows {
    pub(super) fn insert_edge(
        writer: &mut Appender<'_>,
        result_id: &str,
        ordinal: usize,
        edge: &GraphEdgeV1,
    ) -> Result<()> {
        writer
            .append_row(params![
                result_id,
                u32::try_from(ordinal).map_err(|_| GraphInvalidSnafu {
                    field: "graph row ordinal"
                }
                .build())?,
                Self::json(&edge.key.from)?,
                Self::json(&edge.key.to)?,
                Self::label(&edge.key.edge_type)?,
                &edge.key.package_id,
                Self::label(&edge.key.cause)?,
                Self::json(&edge.key.evidence)?,
                Self::json(&edge.proof_quality)?,
                Self::json(&edge.required_coverage_interval_ids)?,
                edge.first_boottime_ns,
                edge.last_boottime_ns
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph relationship",
            })?;
        Ok(())
    }

    fn decode_edge(row: &Row<'_>) -> Result<GraphEdgeV1> {
        let edge = GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: Self::json_column(row, 1)?,
                to: Self::json_column(row, 2)?,
                edge_type: Self::label_column(row, 3)?,
                package_id: Self::column(row, 4)?,
                evidence: Self::json_column(row, 6)?,
                cause: Self::label_column(row, 5)?,
            },
            proof_quality: Self::json_column(row, 7)?,
            required_coverage_interval_ids: Self::json_column(row, 8)?,
            first_boottime_ns: Self::column(row, 9)?,
            last_boottime_ns: Self::column(row, 10)?,
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
    pub(in crate::analysis) fn edge_name(kind: &crate::GraphEdgeTypeV1) -> Result<String> {
        Self::label(kind)
    }

    pub(in crate::analysis) fn selected_edges(
        reader: &Connection,
        result_id: &str,
        ordinals: &[u32],
        control: &AnalysisReadControl,
    ) -> Result<Vec<GraphEdgeV1>> {
        if ordinals.windows(2).any(|pair| pair[0] >= pair[1]) {
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
            let columns = COLUMNS
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
                selected.push(Self::column_operation(
                    Self::decode_edge(row),
                    "decode selected graph relationship columns",
                )?);
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
            COLUMNS,
            result_id,
            control,
            Self::decode_edge,
        )
    }
}
