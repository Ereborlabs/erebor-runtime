use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::mem::size_of;

use datafusion::arrow::array::{ArrayRef, RecordBatch};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, ScalarValue};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_plan::coop::make_cooperative;
use datafusion::physical_plan::SendableRecordBatchStream;
use futures_util::TryStreamExt as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::execution::{Retention, Session};
use crate::stream::Output;
use crate::{Result, SqlSnafu};

impl Output {
    pub(crate) async fn complete(
        mut self,
        session: &Session,
        stream: SendableRecordBatchStream,
        previous: &mut Option<[u8; 32]>,
    ) -> Result<Self> {
        self._control.check()?;
        let schema = stream.schema();
        let stream = make_cooperative(stream);
        let permit = self._permit.take().ok_or_else(|| crate::Error::Sql {
            source: DataFusionError::Internal("completed output permit is absent".into()),
        })?;
        let memory = self._memory.new_empty();
        let mut stream = Box::pin(session.bounded(
            stream,
            permit,
            self._control.clone(),
            &self._memory,
            Retention::Output,
            None,
        ));
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
            self.charge(
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
            .query_async(session.engine().check_read(&self.snapshot))
            .await?;
        let headers = batches
            .capacity()
            .saturating_mul(size_of::<RecordBatch>())
            .saturating_add(arrays);
        let digest = self.fingerprint(&schema, &batches, &memory, headers)?;
        let unchanged = *previous == Some(digest);
        self.charge(&memory, if unchanged { 0 } else { headers })?;
        *previous = Some(digest);
        self.batches = (!unchanged).then_some(batches);
        self._memory = memory;
        Ok(self)
    }

    fn charge(&self, memory: &MemoryReservation, bytes: usize) -> Result<()> {
        let credit = bytes.saturating_sub(memory.size()).min(self._memory.size());
        self._memory.shrink(credit);
        memory
            .try_resize(bytes)
            .map_err(|source| crate::Error::Capacity {
                resource: "shared output",
                source,
            })
    }

    fn fingerprint(
        &self,
        schema: &SchemaRef,
        batches: &[RecordBatch],
        memory: &MemoryReservation,
        headers: usize,
    ) -> Result<[u8; 32]> {
        let mut hash = Fingerprint::new();
        schema.hash(&mut hash);
        batches
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>()
            .hash(&mut hash);
        for batch in batches {
            for row in 0..batch.num_rows() {
                self._control.check()?;
                self.charge(
                    memory,
                    headers
                        .saturating_add(Self::row_bytes(batch, row)?)
                        .saturating_add(size_of::<ScalarValue>()),
                )?;
                for column in batch.columns() {
                    ScalarValue::try_from_array(column, row)
                        .context(SqlSnafu)?
                        .hash(&mut hash);
                }
            }
        }
        Ok(hash.finish_digest())
    }
}

pub(crate) struct Fingerprint(Sha256);

impl Fingerprint {
    pub(crate) fn new() -> Self {
        Self(Sha256::new())
    }

    pub(crate) fn finish_digest(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Hasher for Fingerprint {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_le_bytes(bytes)
    }
}

impl Write for Fingerprint {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
