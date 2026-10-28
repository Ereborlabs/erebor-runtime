use super::GraphRows;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphEdgeKeyV1, GraphEdgeV1, GraphInvalidSnafu,
    ProofQualityV1, Result,
};
use araphor_analysis_sdk::arrow_array::{
    Array, ArrayRef, BinaryArray, LargeBinaryArray, UInt32Array,
};
use duckdb::{
    params_from_iter,
    types::{ListType, Value, ValueRef},
    Connection, Row,
};
use serde::de::DeserializeOwned;

mod arrays;
use snafu::ResultExt as _;

const COLUMNS: &str = "ordinal, from_subject_id, to_subject_id, edge_type,
        package_id, cause, evidence, proof_quality.source_authority,
        proof_quality.local_subject_binding, proof_quality.remote_subject_binding,
        proof_quality.operation_result_authority, proof_quality.temporal_coverage,
        proof_quality.integrity, required_coverage_interval_ids,
        first_boottime_ns, last_boottime_ns";

impl GraphRows {
    fn enum_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        let value: u8 = Self::column(row, index)?;
        T::deserialize(
            serde::de::value::U32Deserializer::<serde::de::value::Error>::new(u32::from(value)),
        )
        .map_err(|_| {
            GraphInvalidSnafu {
                field: "graph proof quality",
            }
            .build()
        })
    }

    fn list_column(row: &Row<'_>, index: usize) -> Result<ArrayRef> {
        match row.get_ref(index).context(AnalysisDatabaseSnafu {
            operation: "read native graph list",
        })? {
            ValueRef::List(ListType::Regular(list), at) => Ok(list.value(at)),
            ValueRef::List(ListType::Large(list), at) => Ok(list.value(at)),
            _ => GraphInvalidSnafu {
                field: "graph list column",
            }
            .fail(),
        }
    }

    fn evidence_column(row: &Row<'_>, index: usize) -> Result<Vec<u32>> {
        let values = Self::list_column(row, index)?;
        let values = values
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph evidence indices",
                }
                .build()
            })?;
        if values.null_count() != 0 {
            return GraphInvalidSnafu {
                field: "graph evidence indices",
            }
            .fail();
        }
        let mut evidence = Vec::new();
        evidence.try_reserve_exact(values.len()).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph allocation byte bound",
            }
            .build()
        })?;
        evidence.extend(values.values().iter().copied());
        if evidence.windows(2).any(|pair| pair[0] >= pair[1]) {
            return GraphInvalidSnafu {
                field: "graph edge proof",
            }
            .fail();
        }
        Ok(evidence)
    }

    fn coverage_column(row: &Row<'_>, index: usize) -> Result<Vec<[u8; 16]>> {
        let values = Self::list_column(row, index)?;
        if values.null_count() != 0 {
            return GraphInvalidSnafu {
                field: "graph coverage interval bytes",
            }
            .fail();
        }
        let normal = values.as_any().downcast_ref::<BinaryArray>();
        let large = values.as_any().downcast_ref::<LargeBinaryArray>();
        if normal.is_none() && large.is_none() {
            return GraphInvalidSnafu {
                field: "graph coverage interval bytes",
            }
            .fail();
        }
        let mut coverage = Vec::new();
        coverage.try_reserve_exact(values.len()).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph allocation byte bound",
            }
            .build()
        })?;
        for at in 0..values.len() {
            let bytes = if let Some(values) = normal {
                values.value(at)
            } else {
                large
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph coverage interval bytes",
                        }
                        .build()
                    })?
                    .value(at)
            };
            coverage.push(bytes.try_into().map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph coverage interval bytes",
                }
                .build()
            })?);
        }
        Ok(coverage)
    }

    fn decode_edge(row: &Row<'_>) -> Result<GraphEdgeV1> {
        let edge = GraphEdgeV1 {
            key: GraphEdgeKeyV1 {
                from: Self::column(row, 1)?,
                to: Self::column(row, 2)?,
                edge_type: Self::label_column(row, 3)?,
                package_id: Self::column(row, 4)?,
                evidence: Self::evidence_column(row, 6)?,
                cause: Self::label_column(row, 5)?,
            },
            proof_quality: ProofQualityV1 {
                source_authority: Self::enum_column(row, 7)?,
                local_subject_binding: Self::enum_column(row, 8)?,
                remote_subject_binding: Self::enum_column(row, 9)?,
                operation_result_authority: Self::enum_column(row, 10)?,
                temporal_coverage: Self::enum_column(row, 11)?,
                integrity: Self::enum_column(row, 12)?,
            },
            required_coverage_interval_ids: Self::coverage_column(row, 13)?,
            first_boottime_ns: Self::column(row, 14)?,
            last_boottime_ns: Self::column(row, 15)?,
        };
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
        expected_count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphEdgeV1>> {
        Self::load(
            writer,
            "graph_relationships",
            COLUMNS,
            result_id,
            expected_count,
            control,
            Self::decode_edge,
        )
    }
}
