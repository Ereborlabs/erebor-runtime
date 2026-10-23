use std::io::{self, Write};
use std::sync::Arc;

use arrow_array::{make_array, RecordBatchOptions};
use arrow_buffer::Buffer;
use arrow_data::transform::MutableArrayData;
use arrow_ipc::{reader::StreamDecoder, writer::StreamWriter};

use crate::{Error, ErrorCode, RecordBatch, Result, Schema};

use super::Dataset;

mod allocation;
use allocation::ArrayBudget;

impl Dataset {
    /// Validate message lengths and the uncompressed IPC storage format.
    pub fn validate_envelope(&self) -> Result<()> {
        super::framing::IpcFrames::validate_envelope(&self.arrow_ipc)
    }

    /// Return the number of record batch messages in the IPC stream.
    pub fn batch_count(&self) -> Result<usize> {
        super::framing::IpcFrames::validate(&self.arrow_ipc)
    }

    /// Return the buffer bound for IPC decode and owned normalization.
    /// Charge schema and dataset metadata with the decoded value.
    pub fn decoding_bytes(ipc: &[u8]) -> Result<usize> {
        super::framing::IpcFrames::decoding_bytes(ipc)
    }

    pub fn encoding_scratch(batch: &RecordBatch) -> Result<usize> {
        let arrays = batch
            .columns()
            .iter()
            .map(|array| array.to_data())
            .collect::<Vec<_>>();
        Ok(ArrayBudget::new(&arrays, None)?.scratch)
    }

    pub fn encode(data: &crate::Dataset, schema: &Schema) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut writer = StreamWriter::try_new(&mut bytes, schema)?;
        for batch in &data.batches {
            if batch.schema().as_ref() != schema {
                return Err(Error::contract(ErrorCode::Invalid, "dataset schema"));
            }
            writer.write(batch)?;
        }
        writer.finish()?;
        drop(writer);
        Ok(Self {
            name: data.name.clone(),
            arrow_ipc: bytes,
        })
    }

    pub fn decode(&self, schema: &Schema) -> Result<crate::Dataset> {
        Self::decode_ipc(&self.name, &self.arrow_ipc, Some(schema))
    }

    pub fn decode_any(&self) -> Result<crate::Dataset> {
        Self::decode_ipc(&self.name, &self.arrow_ipc, None)
    }

    pub fn decode_ipc(name: &str, ipc: &[u8], schema: Option<&Schema>) -> Result<crate::Dataset> {
        Self::decode_ipc_bounded(name, ipc, schema, None)
    }

    pub(super) fn decode_ipc_bounded(
        name: &str,
        ipc: &[u8],
        schema: Option<&Schema>,
        copy_bytes: Option<usize>,
    ) -> Result<crate::Dataset> {
        if copy_bytes.is_some_and(|limit| ipc.len() > limit) {
            return Err(Error::contract(ErrorCode::Limit, "encoded dataset bytes"));
        }
        super::framing::IpcFrames::validate(ipc)?;
        let mut reader = StreamDecoder::new();
        let mut input = Buffer::from(ipc);
        let mut batches = Vec::new();
        let mut bytes = 0_usize;
        while !input.is_empty() {
            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reader.decode(&mut input)
            }))
            .map_err(|_| Error::contract(ErrorCode::Invalid, "arrow stream"))??;
            let Some(batch) = decoded else { continue };
            if schema.is_some_and(|expected| expected != batch.schema().as_ref()) {
                return Err(Error::contract(ErrorCode::Invalid, "dataset schema"));
            }
            let remaining = copy_bytes.map(|limit| limit.saturating_sub(bytes));
            let batch = Self::owned_batch(&batch, remaining)?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size())
                .ok_or_else(|| Error::contract(ErrorCode::Limit, "decoded dataset"))?;
            if copy_bytes.is_some_and(|limit| bytes > limit) {
                return Err(Error::contract(ErrorCode::Limit, "decoded dataset"));
            }
            batches
                .try_reserve_exact(1)
                .map_err(|_| Error::contract(ErrorCode::Limit, "decoded allocation"))?;
            batches.push(batch);
        }
        reader.finish()?;
        let decoded = reader
            .schema()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "dataset schema"))?;
        if schema.is_some_and(|expected| expected != decoded.as_ref()) {
            return Err(Error::contract(ErrorCode::Invalid, "dataset schema"));
        }
        if batches.is_empty() {
            batches.push(RecordBatch::new_empty(Arc::clone(&decoded)));
        }
        Ok(crate::Dataset {
            name: name.into(),
            batches,
        })
    }

    pub(crate) fn owned_batch(
        batch: &RecordBatch,
        copy_bytes: Option<usize>,
    ) -> Result<RecordBatch> {
        let arrays = batch
            .columns()
            .iter()
            .map(|array| array.to_data())
            .collect::<Vec<_>>();
        ArrayBudget::new(&arrays, copy_bytes)?;
        let mut columns = Vec::with_capacity(arrays.len());
        for array in &arrays {
            array.validate_full()?;
            // Zero capacity avoids excess allocation for empty list children.
            let mut owned = MutableArrayData::new(vec![array], false, 0);
            owned.extend(0, 0, array.len());
            columns.push(make_array(owned.freeze()));
        }
        Ok(RecordBatch::try_new_with_options(
            batch.schema(),
            columns,
            &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
        )?)
    }
}

pub struct BoundedBuffer<W = Vec<u8>> {
    writer: W,
    written: u64,
    limit: u64,
}

impl BoundedBuffer {
    pub fn new(limit: u64) -> Self {
        Self::from_writer(Vec::new(), limit)
    }
}

impl<W> BoundedBuffer<W> {
    pub fn from_writer(writer: W, limit: u64) -> Self {
        Self {
            writer,
            written: 0,
            limit,
        }
    }

    pub fn finish(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for BoundedBuffer<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len() as u64)
            .is_none_or(|size| size > self.limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "package encoding byte limit",
            ));
        }
        let written = self.writer.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub(super) struct Codec {
    copied: usize,
    copy_bytes: Option<usize>,
}

impl Codec {
    pub(super) fn new(copy_bytes: Option<usize>) -> Self {
        Self {
            copied: 0,
            copy_bytes,
        }
    }

    fn remaining(&self) -> Option<usize> {
        self.copy_bytes
            .map(|limit| limit.saturating_sub(self.copied))
    }

    fn account(&mut self, data: &crate::Dataset) -> Result<()> {
        self.copied = self
            .copied
            .checked_add(data.allocated_bytes())
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "decoded allocation"))?;
        if self.copy_bytes.is_some_and(|limit| self.copied > limit) {
            return Err(Error::contract(ErrorCode::Limit, "decoded allocation"));
        }
        Ok(())
    }

    pub(super) fn decode<'a>(
        &mut self,
        data: &Dataset,
        ports: impl IntoIterator<Item = &'a crate::Port>,
    ) -> Result<crate::Dataset> {
        let decoded = Dataset::decode_ipc_bounded(
            &data.name,
            &data.arrow_ipc,
            Some(Self::schema(ports, &data.name)?),
            self.remaining(),
        )?;
        self.account(&decoded)?;
        Ok(decoded)
    }

    pub(super) fn single(
        &mut self,
        name: &str,
        bytes: &[u8],
        schema: &Schema,
        field: &str,
    ) -> Result<RecordBatch> {
        let mut data = Dataset::decode_ipc_bounded(name, bytes, Some(schema), self.remaining())?;
        self.account(&data)?;
        if data.batches.len() != 1 || data.batches[0].num_rows() != 1 {
            return Err(Error::contract(ErrorCode::Invalid, field));
        }
        Ok(data.batches.remove(0))
    }

    pub(super) fn schema<'a>(
        ports: impl IntoIterator<Item = &'a crate::Port>,
        name: &str,
    ) -> Result<&'a Schema> {
        ports
            .into_iter()
            .find(|port| port.name == name)
            .map(|port| &port.schema)
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "dataset name"))
    }
}

#[cfg(test)]
mod buffer_tests {
    use super::*;

    #[derive(Default)]
    struct PartialWriter {
        failed: bool,
        flushed: bool,
    }

    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.failed {
                return Err(io::Error::other("writer failure"));
            }
            Ok(usize::from(!bytes.is_empty()))
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.failed {
                return Err(io::Error::other("flush failure"));
            }
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn bounded_partial_writes() -> io::Result<()> {
        let mut writer = BoundedBuffer::from_writer(PartialWriter::default(), 3);
        assert_eq!(writer.write(b"abc")?, 1);
        assert_eq!(writer.write(b"bc")?, 1);
        assert_eq!(writer.write(b"c")?, 1);
        assert_eq!(
            writer.write(b"d").err().map(|error| error.kind()),
            Some(io::ErrorKind::FileTooLarge)
        );
        writer.flush()?;
        assert!(writer.finish().flushed);
        Ok(())
    }

    #[test]
    fn bounded_writer_errors() -> io::Result<()> {
        let mut writer = BoundedBuffer::from_writer(PartialWriter::default(), 2);
        assert_eq!(writer.write(b"a")?, 1);
        writer.writer.failed = true;
        assert_eq!(
            writer.write(b"b").err().map(|error| error.kind()),
            Some(io::ErrorKind::Other)
        );
        assert_eq!(
            writer.flush().err().map(|error| error.kind()),
            Some(io::ErrorKind::Other)
        );
        assert_eq!(writer.written, 1);
        writer.writer.failed = false;
        assert_eq!(writer.write(b"b")?, 1);
        Ok(())
    }

    #[test]
    fn bounded_writer_overflow() -> io::Result<()> {
        let mut writer = BoundedBuffer::from_writer(io::sink(), u64::MAX);
        writer.written = u64::MAX - 1;
        assert_eq!(
            writer.write(b"ab").err().map(|error| error.kind()),
            Some(io::ErrorKind::FileTooLarge)
        );
        assert_eq!(writer.written, u64::MAX - 1);
        assert_eq!(writer.write(b"a")?, 1);
        assert_eq!(
            writer.write(b"b").err().map(|error| error.to_string()),
            Some("package encoding byte limit".into())
        );
        Ok(())
    }
}
