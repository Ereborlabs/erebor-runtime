use std::sync::Arc;

use araphor_analysis_sdk::arrow_array::{
    builder::{LargeBinaryBuilder, LargeListBuilder, UInt64Builder},
    ArrayRef, LargeStringArray, RecordBatch, StructArray, UInt64Array, UInt8Array,
};
use araphor_analysis_sdk::arrow_schema::{DataType, Field, Schema};
use duckdb::Appender;
use snafu::ResultExt as _;

use super::{GraphRows, StoredEdge};
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, Result};

impl GraphRows {
    pub(super) fn append_edge_values(
        writer: &mut Appender<'_>,
        added: &[(u64, StoredEdge, [u8; 32])],
    ) -> Result<()> {
        for rows in added.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            let evidence_count = rows
                .iter()
                .try_fold(0usize, |total, (_, edge, _)| {
                    total.checked_add(edge.evidence.len())
                })
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            let coverage_count = rows
                .iter()
                .try_fold(0usize, |total, (_, edge, _)| {
                    total.checked_add(edge.coverage.len())
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
            for count in [evidence_count, coverage_count, coverage_bytes] {
                i64::try_from(count).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph native array offsets",
                    }
                    .build()
                })?;
            }
            let mut hashes = LargeBinaryBuilder::with_capacity(rows.len(), rows.len() * 32);
            let mut evidence = LargeListBuilder::with_capacity(
                UInt64Builder::with_capacity(evidence_count),
                rows.len(),
            );
            let mut coverage = LargeListBuilder::with_capacity(
                LargeBinaryBuilder::with_capacity(coverage_count, coverage_bytes),
                rows.len(),
            );
            for (_, edge, hash) in rows {
                hashes.append_value(hash);
                evidence.values().append_slice(&edge.evidence);
                evidence.append(true);
                for interval in &edge.coverage {
                    coverage.values().append_value(interval);
                }
                coverage.append(true);
            }
            let proof = StructArray::from(vec![
                (
                    Arc::new(Field::new("source_authority", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|(_, edge, _)| edge.proof_quality.source_authority as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("local_subject_binding", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(rows.iter().map(
                        |(_, edge, _)| edge.proof_quality.local_subject_binding as u8,
                    ))) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("remote_subject_binding", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(rows.iter().map(
                        |(_, edge, _)| edge.proof_quality.remote_subject_binding as u8,
                    ))) as ArrayRef,
                ),
                (
                    Arc::new(Field::new(
                        "operation_result_authority",
                        DataType::UInt8,
                        false,
                    )),
                    Arc::new(UInt8Array::from_iter_values(rows.iter().map(
                        |(_, edge, _)| edge.proof_quality.operation_result_authority as u8,
                    ))) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("temporal_coverage", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|(_, edge, _)| edge.proof_quality.temporal_coverage as u8),
                    )) as ArrayRef,
                ),
                (
                    Arc::new(Field::new("integrity", DataType::UInt8, false)),
                    Arc::new(UInt8Array::from_iter_values(
                        rows.iter()
                            .map(|(_, edge, _)| edge.proof_quality.integrity as u8),
                    )) as ArrayRef,
                ),
            ]);
            let edge_types = rows
                .iter()
                .map(|(_, edge, _)| GraphRows::label(&edge.edge_type))
                .collect::<Result<Vec<_>>>()?;
            let causes = rows
                .iter()
                .map(|(_, edge, _)| GraphRows::label(&edge.cause))
                .collect::<Result<Vec<_>>>()?;
            let arrays: Vec<ArrayRef> = vec![
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|(id, _, _)| *id),
                )),
                Arc::new(hashes.finish()),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.from),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.to),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    edge_types.iter().map(String::as_str),
                )),
                Arc::new(UInt8Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.edge_type as u8),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.package_id.as_str()),
                )),
                Arc::new(LargeStringArray::from_iter_values(
                    causes.iter().map(String::as_str),
                )),
                Arc::new(UInt8Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.cause as u8),
                )),
                Arc::new(evidence.finish()),
                Arc::new(proof),
                Arc::new(coverage.finish()),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.first),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|(_, edge, _)| edge.last),
                )),
            ];
            let names = [
                "edge_id",
                "value_hash",
                "from_ref",
                "to_ref",
                "edge_type",
                "edge_type_rank",
                "package_id",
                "cause",
                "cause_rank",
                "evidence_refs",
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
                    operation: "insert native graph edge values",
                })?;
        }
        Ok(())
    }
}
