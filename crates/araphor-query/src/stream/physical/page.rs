use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, StorePositionV1};
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryViewArray, RecordBatch, StringViewArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::compute::interleave_record_batch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_expr::expressions::Column;
use datafusion::physical_expr::projection::ProjectionExpr;
use datafusion::physical_plan::coalesce_partitions::CoalescePartitionsExec;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::empty::EmptyExec;
use datafusion::physical_plan::filter::{FilterExec, FilterExecBuilder};
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use super::SubscribeExec;
use crate::execution::{Engine, Permit};
use crate::sources::{ArrowSnapshot, SourceData};
use crate::stream::Output;
use crate::{Result, SqlSnafu};

impl SubscribeExec {
    pub(super) fn page_input(
        input: &Arc<dyn ExecutionPlan>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        if let Some(source) = SourceData::from_plan(input.as_ref()) {
            return source.positioned();
        }
        if input.as_any().is::<EmptyExec>() {
            return Ok(Arc::clone(input));
        }
        let children = input.children();
        let [child] = children.as_slice() else {
            return Err(DataFusionError::NotImplemented(
                "positioned unary plan".into(),
            ));
        };
        let projection = input.as_any().downcast_ref::<ProjectionExec>();
        let filter = input.as_any().downcast_ref::<FilterExec>();
        let transparent = input.as_any().is::<CooperativeExec>()
            || (input.as_any().is::<CoalescePartitionsExec>()
                && child.properties().partitioning.partition_count() == 1);
        if projection.is_none() && filter.is_none() && !transparent {
            return Err(DataFusionError::NotImplemented(
                "positioned native operator".into(),
            ));
        }
        let positioned = Self::page_input(child)?;
        let width = child.schema().fields().len();
        let schema = positioned.schema();
        if schema.fields().len() == width {
            return Ok(Arc::clone(input));
        }
        if schema.fields().len() != width + 2 {
            return Err(DataFusionError::Execution(
                "positioned input schema changed".into(),
            ));
        }
        if let Some(projection) = projection {
            let mut expressions = projection.expr().to_vec();
            for index in width..width + 2 {
                let field = schema.field(index);
                expressions.push(ProjectionExpr::new(
                    Arc::new(Column::new(field.name(), index)),
                    field.name().clone(),
                ));
            }
            return Ok(Arc::new(ProjectionExec::try_new(expressions, positioned)?));
        }
        if let Some(filter) = filter {
            let mut builder = FilterExecBuilder::from(filter).with_input(positioned);
            if let Some(projection) = filter.projection() {
                let mut indices = projection.to_vec();
                indices.extend([width, width + 1]);
                builder = builder
                    .apply_projection(None)?
                    .apply_projection(Some(indices))?;
            }
            return Ok(Arc::new(builder.build()?));
        }
        Arc::clone(input).with_new_children(vec![positioned])
    }
}

impl Output {
    pub(super) async fn page(
        engine: &Arc<Engine>,
        schema: SchemaRef,
        stream: &mut SendableRecordBatchStream,
        control: Arc<AnalysisReadControl>,
        mut reservation: MemoryReservation,
        snapshot: Arc<ArrowSnapshot>,
        permit: Arc<Permit>,
    ) -> Result<Self> {
        let width = schema.fields().len();
        let projection = (0..width).collect::<Vec<_>>();
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
            if batch.num_columns() != width + 2 {
                return Err(Self::page_error());
            }
            let revisions = batch
                .column(width)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(Self::page_error)?;
            let ordinals = batch
                .column(width + 1)
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or_else(Self::page_error)?;
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
                if positions.len() == engine.limits().output_rows
                    || logical.saturating_add(bytes) > engine.limits().output_bytes
                {
                    if positions.is_empty() {
                        return Err(Self::page_error());
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
                if staging > engine.limits().output_bytes {
                    return Err(Self::page_error());
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
            if staging > engine.limits().output_bytes {
                return Err(Self::page_error());
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
                if compact.get_array_memory_size() <= engine.limits().output_bytes {
                    engine
                        .memory()
                        .retain_output(&compact, &mut reservation)
                        .context(SqlSnafu)?;
                    batches.push(compact);
                    break;
                }
                positions.pop();
                indices.pop();
                limited = true;
                if positions.is_empty() {
                    return Err(Self::page_error());
                }
            }
        }
        let position = if limited {
            positions.last().copied().ok_or_else(Self::page_error)?
        } else {
            snapshot.page.scanned_through
        };
        control.query_async(engine.check_read(&snapshot)).await?;
        let retained = positions
            .capacity()
            .saturating_mul(size_of::<StorePositionV1>())
            .saturating_add(batches.capacity().saturating_mul(size_of::<RecordBatch>()))
            .saturating_add(
                batches
                    .iter()
                    .map(|batch| batch.num_columns() * size_of::<ArrayRef>())
                    .sum::<usize>(),
            );
        reservation
            .try_resize(retained)
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })?;
        Ok(Self {
            snapshot,
            batches: Some(batches),
            positions,
            position,
            limited,
            _memory: reservation,
            _permit: Some(permit),
            _control: control,
        })
    }

    fn page_error() -> crate::Error {
        crate::Error::Sql {
            source: DataFusionError::ResourcesExhausted("query output".into()),
        }
    }

    pub(crate) fn row_bytes(batch: &RecordBatch, row: usize) -> Result<usize> {
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
