use std::io::{self, Write};
use std::sync::Arc;

use arrow_array::{make_array, RecordBatchOptions};
use arrow_buffer::Buffer;
use arrow_data::transform::MutableArrayData;
use arrow_ipc::{reader::StreamDecoder, writer::StreamWriter};

use crate::{Error, ErrorCode, Limits, RecordBatch, Result, Schema};

use super::Dataset;

mod allocation;
use allocation::ArrayBudget;

impl Dataset {
    pub(crate) fn encoding_scratch(batch: &RecordBatch) -> Result<usize> {
        let arrays = batch
            .columns()
            .iter()
            .map(|array| array.to_data())
            .collect::<Vec<_>>();
        Ok(ArrayBudget::new(&arrays, u64::MAX)?.scratch)
    }

    pub fn encode(data: &crate::Dataset, schema: &Schema, limits: Limits) -> Result<Self> {
        let mut bytes = BoundedBuffer::new(limits.max_bytes);
        let mut writer = StreamWriter::try_new(&mut bytes, schema)?;
        let mut rows = 0_u64;
        let mut size = 0_u64;
        for (index, batch) in data.batches.iter().enumerate() {
            rows = rows.saturating_add(batch.num_rows() as u64);
            size = size.saturating_add(batch.get_array_memory_size() as u64);
            if rows > limits.max_rows
                || size > limits.max_bytes
                || index >= limits.max_batches as usize
            {
                return Err(Error::contract(ErrorCode::Limit, "encoded dataset"));
            }
            if batch.schema().as_ref() != schema {
                return Err(Error::contract(ErrorCode::Invalid, "dataset schema"));
            }
            writer.write(batch)?;
        }
        writer.finish()?;
        drop(writer);
        Ok(Self {
            name: data.name.clone(),
            arrow_ipc: bytes.finish(),
        })
    }

    pub fn decode(&self, schema: &Schema, limits: Limits) -> Result<crate::Dataset> {
        Self::decode_ipc(&self.name, &self.arrow_ipc, Some(schema), limits)
    }

    pub fn decode_any(&self, limits: Limits) -> Result<crate::Dataset> {
        Self::decode_ipc(&self.name, &self.arrow_ipc, None, limits)
    }

    pub fn decode_ipc(
        name: &str,
        ipc: &[u8],
        schema: Option<&Schema>,
        limits: Limits,
    ) -> Result<crate::Dataset> {
        if ipc.len() as u64 > limits.max_bytes {
            return Err(Error::contract(ErrorCode::Limit, "encoded dataset bytes"));
        }
        super::framing::IpcFrames::validate(ipc, limits)?;
        let mut reader = StreamDecoder::new();
        let mut input = Buffer::from(ipc);
        let mut batches = Vec::new();
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        while !input.is_empty() {
            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reader.decode(&mut input)
            }))
            .map_err(|_| Error::contract(ErrorCode::Invalid, "arrow stream"))??;
            let Some(batch) = decoded else { continue };
            if schema.is_some_and(|expected| expected != batch.schema().as_ref()) {
                return Err(Error::contract(ErrorCode::Invalid, "dataset schema"));
            }
            rows = rows.saturating_add(batch.num_rows() as u64);
            if rows > limits.max_rows || batches.len() >= limits.max_batches as usize {
                return Err(Error::contract(ErrorCode::Limit, "decoded dataset"));
            }
            let batch = Self::owned_batch(&batch, limits.max_bytes.saturating_sub(bytes))?;
            bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
            if bytes > limits.max_bytes {
                return Err(Error::contract(ErrorCode::Limit, "decoded dataset"));
            }
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

    fn owned_batch(batch: &RecordBatch, limit: u64) -> Result<RecordBatch> {
        let arrays = batch
            .columns()
            .iter()
            .map(|array| array.to_data())
            .collect::<Vec<_>>();
        ArrayBudget::new(&arrays, limit)?;
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

pub struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: u64,
}

impl BoundedBuffer {
    pub fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if (self.bytes.len() as u64).saturating_add(bytes.len() as u64) > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "package encoding byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct Codec {
    limits: Limits,
    encoded: u64,
    decoded: u64,
    rows: u64,
    batches: u32,
}

impl Codec {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            encoded: 0,
            decoded: 0,
            rows: 0,
            batches: 0,
        }
    }

    fn remaining(&self) -> Limits {
        Limits {
            max_bytes: self
                .limits
                .max_bytes
                .saturating_sub(self.encoded.max(self.decoded)),
            max_rows: self.limits.max_rows.saturating_sub(self.rows),
            max_batches: self.limits.max_batches.saturating_sub(self.batches),
            ..self.limits
        }
    }

    fn account(&mut self, data: &crate::Dataset, encoded: usize) {
        self.encoded = self.encoded.saturating_add(encoded as u64);
        for batch in &data.batches {
            self.decoded = self
                .decoded
                .saturating_add(batch.get_array_memory_size() as u64);
            self.rows = self.rows.saturating_add(batch.num_rows() as u64);
            self.batches = self.batches.saturating_add(1);
        }
    }

    pub(super) fn encode(&mut self, data: &crate::Dataset, schema: &Schema) -> Result<Dataset> {
        let encoded = Dataset::encode(data, schema, self.remaining())?;
        self.account(data, encoded.arrow_ipc.len());
        Ok(encoded)
    }

    pub(super) fn decode(&mut self, data: &Dataset, schema: &Schema) -> Result<crate::Dataset> {
        let decoded = data.decode(schema, self.remaining())?;
        self.account(&decoded, data.arrow_ipc.len());
        Ok(decoded)
    }

    pub(super) fn single(
        &mut self,
        name: &str,
        bytes: &[u8],
        schema: &Schema,
    ) -> Result<RecordBatch> {
        let mut data = Dataset::decode_ipc(name, bytes, Some(schema), self.remaining())?;
        self.account(&data, bytes.len());
        if data.batches.len() != 1 || data.batches[0].num_rows() != 1 {
            return Err(Error::contract(ErrorCode::Invalid, "single row batch"));
        }
        Ok(data.batches.remove(0))
    }

    pub(super) fn schema<'a>(ports: &'a [crate::Port], name: &str) -> Result<&'a Schema> {
        ports
            .iter()
            .find(|port| port.name == name)
            .map(|port| &port.schema)
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "dataset name"))
    }
}
