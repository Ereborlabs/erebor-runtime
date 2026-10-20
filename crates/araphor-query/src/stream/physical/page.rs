use std::mem::{size_of, size_of_val};
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, StorePositionV1};
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryViewArray, RecordBatch, StringViewArray, UInt32Array, UInt64Array,
};
use datafusion::arrow::compute::interleave_record_batch;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_plan::SendableRecordBatchStream;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use crate::execution::{Permit, Session};
use crate::sources::ArrowSnapshot;
use crate::stream::Output;
use crate::{Result, SqlSnafu};

impl Output {
    pub(super) async fn page(
        session: &Session,
        schema: SchemaRef,
        stream: &mut SendableRecordBatchStream,
        control: Arc<AnalysisReadControl>,
        reservation: MemoryReservation,
        snapshot: Arc<ArrowSnapshot>,
        permit: Arc<Permit>,
    ) -> Result<Self> {
        let (output_rows, output_bytes) = session.output();
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
                if positions.len() == output_rows || logical.saturating_add(bytes) > output_bytes {
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
                if staging > output_bytes {
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
            if staging > output_bytes {
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
                if compact.get_array_memory_size() <= output_bytes {
                    session
                        .memory()
                        .retain_output(&compact, &reservation)
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
        control.query_async(session.check_read(&snapshot)).await?;
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
