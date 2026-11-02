use std::mem::size_of;

use datafusion::arrow::array::{ArrayRef, RecordBatch};
use datafusion::common::DataFusionError;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_plan::coop::make_cooperative;
use datafusion::physical_plan::SendableRecordBatchStream;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use crate::execution::Session;
use crate::stream::Output;
use crate::{Result, SqlSnafu};

impl Output {
    pub(crate) async fn complete(
        mut self,
        session: &Session,
        stream: SendableRecordBatchStream,
    ) -> Result<Self> {
        self._control.check()?;
        let stream = make_cooperative(stream);
        let permit = self._permit.take().ok_or_else(|| crate::Error::Sql {
            source: DataFusionError::Internal("completed output permit is absent".into()),
        })?;
        let memory = self._memory.split(self._memory.size());
        let mut stream =
            Box::pin(session.bounded(stream, permit, self._control.clone(), &memory, None));
        let mut batches = Vec::<RecordBatch>::new();
        let mut arrays = 0usize;
        while let Some(batch) = stream.try_next().await.context(SqlSnafu)? {
            if batch.num_rows() == 0 {
                continue;
            }
            arrays = arrays.saturating_add(batch.num_columns() * size_of::<ArrayRef>());
            let capacity = if batches.len() == batches.capacity() {
                batches.capacity().saturating_mul(2).max(1)
            } else {
                batches.capacity()
            };
            Self::charge(
                &memory,
                capacity
                    .saturating_mul(size_of::<RecordBatch>())
                    .saturating_add(arrays),
            )?;
            if capacity > batches.capacity() {
                batches.reserve_exact(capacity - batches.len());
            }
            batches.push(batch);
        }
        drop(stream);
        self._control
            .query_async(session.check_read(&self.snapshot))
            .await?;
        let headers = batches
            .capacity()
            .saturating_mul(size_of::<RecordBatch>())
            .saturating_add(arrays);
        memory
            .try_resize(headers)
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })?;
        self.batches = Some(batches);
        self._memory = memory;
        Ok(self)
    }

    pub(crate) fn count_bytes() -> usize {
        size_of::<RecordBatch>() + size_of::<ArrayRef>()
    }

    fn charge(memory: &MemoryReservation, bytes: usize) -> Result<()> {
        memory
            .try_grow(bytes.saturating_sub(memory.size()))
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })
    }
}

#[cfg(test)]
mod tests;
