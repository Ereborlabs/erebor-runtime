use std::sync::Arc;

use araphor_analysis_sdk::arrow_array::{
    builder::{LargeBinaryBuilder, LargeListBuilder, UInt32Builder},
    ArrayRef, LargeStringArray, RecordBatch, StructArray, UInt32Array, UInt64Array, UInt8Array,
};
use araphor_analysis_sdk::arrow_schema::{DataType, Field, Schema};
use duckdb::Appender;
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{AnalysisDatabaseSnafu, GraphEdgeV1, GraphInvalidSnafu, Result};

impl GraphRows {
    pub(in crate::analysis::graph_rows) fn insert_edges(
        writer: &mut Appender<'_>,
        result_id: &str,
        edges: &[GraphEdgeV1],
    ) -> Result<()> {
        let mut first = 0usize;
        for rows in edges.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            let evidence_count = rows
                .iter()
                .try_fold(0usize, |count, row| {
                    count.checked_add(row.key.evidence.len())
                })
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            let coverage_count = rows
                .iter()
                .try_fold(0usize, |count, row| {
                    count.checked_add(row.required_coverage_interval_ids.len())
                })
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            let coverage_bytes = coverage_count.checked_mul(16).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph native array offsets",
                }
                .build()
            })?;
            for count in [
                evidence_count,
                coverage_count,
                coverage_bytes,
                result_id.len().checked_mul(rows.len()).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?,
            ] {
                i64::try_from(count).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            }
            let mut ordinal = Vec::new();
            ordinal.try_reserve_exact(rows.len()).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
            for at in 0..rows.len() {
                ordinal.push(
                    u32::try_from(first.checked_add(at).ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph row ordinal",
                        }
                        .build()
                    })?)
                    .map_err(|_| {
                        GraphInvalidSnafu {
                            field: "graph row ordinal",
                        }
                        .build()
                    })?,
                );
            }
            let mut evidence = LargeListBuilder::with_capacity(
                UInt32Builder::with_capacity(evidence_count),
                rows.len(),
            );
            let mut coverage = LargeListBuilder::with_capacity(
                LargeBinaryBuilder::with_capacity(coverage_count, coverage_bytes),
                rows.len(),
            );
            let mut edge_types = Vec::new();
            let mut causes = Vec::new();
            edge_types.try_reserve_exact(rows.len()).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
            causes.try_reserve_exact(rows.len()).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph allocation byte bound",
                }
                .build()
            })?;
            for row in rows {
                evidence.values().append_slice(&row.key.evidence);
                evidence.append(true);
                for interval in &row.required_coverage_interval_ids {
                    coverage.values().append_value(interval);
                }
                coverage.append(true);
                edge_types.push(Self::label(&row.key.edge_type)?);
                causes.push(Self::label(&row.key.cause)?);
            }
            for length in [
                edge_types
                    .iter()
                    .try_fold(0usize, |count, value| count.checked_add(value.len())),
                causes
                    .iter()
                    .try_fold(0usize, |count, value| count.checked_add(value.len())),
                rows.iter().try_fold(0usize, |count, row| {
                    count.checked_add(row.key.package_id.len())
                }),
            ] {
                let length = length.ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
                i64::try_from(length).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            }
            let proof = StructArray::from(vec![
                (
                    Arc::new(Field::new("source_authority", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|row| row.proof_quality.source_authority as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("local_subject_binding", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|row| row.proof_quality.local_subject_binding as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("remote_subject_binding", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|row| row.proof_quality.remote_subject_binding as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new(
                        "operation_result_authority",
                        DataType::UInt8,
                        false,
                    )),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|row| row.proof_quality.operation_result_authority as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("temporal_coverage", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|row| row.proof_quality.temporal_coverage as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("integrity", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter().map(|row| row.proof_quality.integrity as u8),
                    )) as ArrayRef,
                ),
            ]);
            let arrays: Vec<ArrayRef> = vec![
                Arc::new(LargeStringArray::from_iter_values(std::iter::repeat_n(
                    result_id,
                    rows.len(),
                ))),
                Arc::new(UInt32Array::from(ordinal)),
                Arc::new(UInt32Array::from_iter_values(
                    rows.iter().map(|row| row.key.from),
                )),
                Arc::new(UInt32Array::from_iter_values(
                    rows.iter().map(|row| row.key.to),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    edge_types.iter().map(String::as_str),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    rows.iter().map(|row| row.key.package_id.as_str()),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    causes.iter().map(String::as_str),
                )),
                Arc::new(evidence.finish()),
                Arc::new(proof),
                Arc::new(coverage.finish()),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|row| row.first_boottime_ns),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|row| row.last_boottime_ns),
                )),
            ];
            let names = [
                "result_id",
                "ordinal",
                "from_subject_id",
                "to_subject_id",
                "edge_type",
                "package_id",
                "cause",
                "evidence",
                "proof_quality",
                "required_coverage_interval_ids",
                "first_boottime_ns",
                "last_boottime_ns",
            ];
            let fields: Vec<Field> = names
                .iter()
                .zip(&arrays)
                .map(|(name, array)| Field::new(*name, array.data_type().clone(), false))
                .collect();
            let batch =
                RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph native record batch",
                    }
                    .build()
                })?;
            writer
                .append_record_batch(batch)
                .context(AnalysisDatabaseSnafu {
                    operation: "insert native graph relationships",
                })?;
            first = first.checked_add(rows.len()).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph row ordinal",
                }
                .build()
            })?;
        }
        Ok(())
    }
}
