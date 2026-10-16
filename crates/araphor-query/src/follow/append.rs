use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, StorePositionV1};
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryViewArray, RecordBatch, StringViewArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::compute::interleave_record_batch;
use datafusion::arrow::datatypes::DataType;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::common::{Column, DataFusionError};
use datafusion::datasource::source_as_provider;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder};
use datafusion::physical_plan::SendableRecordBatchStream;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use super::State;
use crate::sources::ArrowSnapshot;
use crate::sources::SourceProvider;
use crate::{Result, SqlSnafu};

impl State {
    pub(super) fn page_plan(plan: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        let LogicalPlan::Projection(projection) = plan else {
            return Ok(None);
        };
        let mut has_subquery = false;
        plan.apply_with_subqueries(|node| {
            if matches!(node, LogicalPlan::Subquery(_)) {
                has_subquery = true;
                Ok(TreeNodeRecursion::Stop)
            } else {
                Ok(TreeNodeRecursion::Continue)
            }
        })
        .context(SqlSnafu)?;
        if has_subquery {
            return Ok(None);
        }
        let mut input = projection.input.as_ref();
        loop {
            input = match input {
                LogicalPlan::Filter(filter) => &filter.input,
                LogicalPlan::SubqueryAlias(alias) => &alias.input,
                LogicalPlan::TableScan(scan)
                    if matches!(scan.table_name.table(), "events" | "trace_output")
                        && scan.fetch.is_none()
                        && source_as_provider(&scan.source)
                            .is_ok_and(|provider| provider.as_any().is::<SourceProvider>()) =>
                {
                    // These sources emit at most one row per position. The accepted operators do not add rows.
                    break;
                }
                _ => return Ok(None),
            };
        }
        let schema = projection.input.schema();
        let (Ok((revision, revision_field)), Ok((ordinal, ordinal_field))) = (
            schema.qualified_field_with_unqualified_name("commit_revision"),
            schema.qualified_field_with_unqualified_name("ordinal"),
        ) else {
            return Ok(None);
        };
        if revision_field.data_type() != &DataType::UInt64
            || ordinal_field.data_type() != &DataType::UInt32
        {
            return Ok(None);
        }
        let mut revision_name = "__follow_revision".to_owned();
        let mut ordinal_name = "__follow_ordinal".to_owned();
        while plan
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == &revision_name)
        {
            revision_name.push('_');
        }
        while plan
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == &ordinal_name)
        {
            ordinal_name.push('_');
        }
        let mut expressions = projection.expr.clone();
        expressions.push(
            Expr::Column(Column::new(
                revision.cloned(),
                revision_field.name().clone(),
            ))
            .alias(&revision_name),
        );
        expressions.push(
            Expr::Column(Column::new(ordinal.cloned(), ordinal_field.name().clone()))
                .alias(&ordinal_name),
        );
        LogicalPlanBuilder::from(projection.input.as_ref().clone())
            .project(expressions)
            .and_then(|builder| {
                builder.sort(vec![
                    Expr::Column(Column::new_unqualified(revision_name)).sort(true, true),
                    Expr::Column(Column::new_unqualified(ordinal_name)).sort(true, true),
                ])
            })
            .and_then(LogicalPlanBuilder::build)
            .map(Some)
            .context(SqlSnafu)
    }

    pub(super) async fn append(
        &mut self,
        stream: &mut SendableRecordBatchStream,
        control: &AnalysisReadControl,
        reservation: &mut MemoryReservation,
        snapshot: &ArrowSnapshot,
    ) -> Result<(
        Vec<RecordBatch>,
        Vec<StorePositionV1>,
        StorePositionV1,
        bool,
    )> {
        let width = self.plan.schema().fields().len();
        let projection = (0..width).collect::<Vec<_>>();
        let schema = Arc::clone(self.plan.schema().inner());
        let mut captured = Vec::new();
        let mut positions = Vec::new();
        let mut logical = 0usize;
        let mut limited = false;
        'batches: while let Some(batch) = control
            .query_async(async { stream.try_next().await.context(SqlSnafu) })
            .await?
        {
            if batch.num_rows() == 0 {
                continue;
            }
            let revisions = batch
                .column(width)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(Self::output_error)?;
            let ordinals = batch
                .column(width + 1)
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or_else(Self::output_error)?;
            captured.push(
                batch
                    .project(&projection)
                    .map_err(datafusion::common::DataFusionError::from)
                    .context(SqlSnafu)?,
            );
            let public = captured.last().ok_or_else(|| crate::Error::Sql {
                source: DataFusionError::Internal("append batch is absent".into()),
            })?;
            for row in 0..batch.num_rows() {
                control.check()?;
                let bytes = Self::row_bytes(public, row)?;
                if positions.len() == self.engine.limits().output_rows
                    || logical.saturating_add(bytes) > self.engine.limits().output_bytes
                {
                    if positions.is_empty() {
                        return Err(Self::output_error());
                    }
                    limited = true;
                    break 'batches;
                }
                logical = logical.saturating_add(bytes);
                positions.push(StorePositionV1 {
                    commit_revision: revisions.value(row),
                    ordinal: ordinals.value(row),
                });
                let staging = captured
                    .capacity()
                    .saturating_mul(size_of::<RecordBatch>())
                    .saturating_add(
                        positions
                            .capacity()
                            .saturating_mul(size_of::<StorePositionV1>()),
                    )
                    .saturating_add(
                        captured
                            .iter()
                            .map(|batch| batch.num_columns() * size_of::<ArrayRef>())
                            .sum::<usize>(),
                    );
                if staging > self.engine.limits().output_bytes {
                    return Err(Self::output_error());
                }
            }
        }
        let mut batches = Vec::new();
        if !positions.is_empty() {
            let scratch_bytes = captured
                .len()
                .saturating_mul(size_of::<&RecordBatch>())
                .saturating_add(positions.len().saturating_mul(size_of::<(usize, usize)>()));
            let staging = captured
                .capacity()
                .saturating_mul(size_of::<RecordBatch>())
                .saturating_add(
                    positions
                        .capacity()
                        .saturating_mul(size_of::<StorePositionV1>()),
                )
                .saturating_add(
                    captured
                        .iter()
                        .map(|batch| batch.num_columns() * size_of::<ArrayRef>())
                        .sum::<usize>(),
                )
                .saturating_add(scratch_bytes);
            if staging > self.engine.limits().output_bytes {
                return Err(Self::output_error());
            }
            let scratch = reservation.split(scratch_bytes.min(reservation.size()));
            scratch
                .try_resize(scratch_bytes)
                .map_err(|source| crate::Error::Capacity {
                    resource: "shared output",
                    source,
                })?;
            let inputs = captured.iter().collect::<Vec<_>>();
            let mut indices = Vec::with_capacity(positions.len());
            indices.extend(
                captured
                    .iter()
                    .enumerate()
                    .flat_map(|(index, batch)| (0..batch.num_rows()).map(move |row| (index, row)))
                    .take(positions.len()),
            );
            loop {
                control.check()?;
                let compact = if width == 0 {
                    RecordBatch::try_new_with_options(
                        Arc::clone(&schema),
                        Vec::new(),
                        &datafusion::arrow::array::RecordBatchOptions::new()
                            .with_row_count(Some(positions.len())),
                    )
                } else {
                    interleave_record_batch(&inputs, &indices)
                }
                .map_err(datafusion::common::DataFusionError::from)
                .context(SqlSnafu)?;
                let columns = compact
                    .columns()
                    .iter()
                    .map(|column| {
                        if let Some(view) = column.as_any().downcast_ref::<StringViewArray>() {
                            Arc::new(view.gc()) as ArrayRef
                        } else if let Some(view) = column.as_any().downcast_ref::<BinaryViewArray>()
                        {
                            Arc::new(view.gc()) as ArrayRef
                        } else {
                            Arc::clone(column)
                        }
                    })
                    .collect();
                let compact = RecordBatch::try_new_with_options(
                    Arc::clone(&schema),
                    columns,
                    &datafusion::arrow::array::RecordBatchOptions::new()
                        .with_row_count(Some(positions.len())),
                )
                .map_err(datafusion::common::DataFusionError::from)
                .context(SqlSnafu)?;
                if compact.get_array_memory_size() <= self.engine.limits().output_bytes {
                    self.engine
                        .memory()
                        .retain_output(&compact, reservation)
                        .context(SqlSnafu)?;
                    batches.push(compact);
                    break;
                }
                positions.pop();
                indices.pop();
                limited = true;
                if positions.is_empty() {
                    return Err(Self::output_error());
                }
            }
        }
        let position = if limited {
            positions.last().copied().ok_or_else(Self::output_error)?
        } else {
            snapshot.page.scanned_through
        };
        Ok((batches, positions, position, limited))
    }

    pub(super) fn row_bytes(batch: &RecordBatch, row: usize) -> Result<usize> {
        let mut bytes = 0usize;
        for column in batch.columns() {
            bytes = bytes.saturating_add(
                if let Some(view) = column.as_any().downcast_ref::<StringViewArray>() {
                    view.slice(row, 1).total_bytes_len().saturating_add(16)
                } else if let Some(view) = column.as_any().downcast_ref::<BinaryViewArray>() {
                    view.slice(row, 1).total_bytes_len().saturating_add(16)
                } else {
                    column
                        .to_data()
                        .slice(row, 1)
                        .get_slice_memory_size()
                        .map_err(datafusion::common::DataFusionError::from)
                        .context(SqlSnafu)?
                },
            );
        }
        if row == 0 {
            bytes = bytes.saturating_add(
                batch
                    .columns()
                    .iter()
                    .map(|column| size_of_val(column.as_ref()))
                    .sum::<usize>(),
            );
        }
        Ok(bytes)
    }
}
