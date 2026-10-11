use std::io::{self, Write};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use arrow_ipc::{reader::StreamDecoder, writer::StreamWriter};
use duckdb::arrow::buffer::Buffer;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::PackageErrorCodeV1 as Code;
use crate::Result;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDatasetV1 {
    pub name: String,
    pub ipc: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInputV1 {
    pub data: PackageDatasetV1,
    pub revision: sdk::Revision,
    pub coverage: sdk::Coverage,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOutputV1 {
    pub datasets: Vec<PackageDatasetV1>,
    pub evidence: Vec<sdk::EvidenceLink>,
    pub reasons: Vec<PackageReasonV1>,
    pub checkpoint: Option<PackageCheckpointV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageReasonV1 {
    pub output: sdk::RowRef,
    pub code: String,
    pub details: PackageDatasetV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCheckpointV1 {
    pub version: u32,
    pub datasets: Vec<PackageDatasetV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFixtureV1 {
    pub name: String,
    pub export: String,
    #[serde(default)]
    pub time_utc_ns: i64,
    #[serde(default)]
    pub seed: Option<u64>,
    pub inputs: Vec<PackageInputV1>,
    pub parameters: Option<serde_json::Value>,
    pub checkpoint: Option<PackageCheckpointV1>,
    pub expected: PackageOutputV1,
}

impl PackageFixtureV1 {
    pub(super) fn evaluation_context(&self, model: &sdk::Model) -> sdk::EvaluationContext {
        sdk::EvaluationContext {
            id: format!("fixture:{}", self.name),
            time_utc_ns: self.time_utc_ns,
            seed: self.seed,
            limits: model.limits,
        }
    }
}

impl PackageDatasetV1 {
    pub fn encode(data: &sdk::Dataset, schema: &sdk::Schema, limits: sdk::Limits) -> Result<Self> {
        let mut bytes = PackageBuffer::new(limits.max_bytes);
        let mut writer =
            StreamWriter::try_new(&mut bytes, schema).context(crate::PackageArrowSnafu)?;
        for batch in &data.batches {
            writer.write(batch).context(crate::PackageArrowSnafu)?;
        }
        writer.finish().context(crate::PackageArrowSnafu)?;
        drop(writer);
        Ok(Self {
            name: data.name.clone(),
            ipc: bytes.finish(),
        })
    }

    pub fn decode(&self, schema: &sdk::Schema, limits: sdk::Limits) -> Result<sdk::Dataset> {
        let data = self.decode_any(limits)?;
        if data
            .batches
            .iter()
            .any(|batch| batch.schema().as_ref() != schema)
        {
            return Err(Code::Invalid.error("dataset schema"));
        }
        Ok(data)
    }

    pub(super) fn decode_any(&self, limits: sdk::Limits) -> Result<sdk::Dataset> {
        if self.ipc.len() as u64 > limits.max_bytes {
            return Err(Code::Limit.error("encoded dataset bytes"));
        }
        let mut reader = StreamDecoder::new();
        let mut input = Buffer::from(self.ipc.as_slice());
        let mut batches = Vec::new();
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        while !input.is_empty() {
            let Some(batch) = reader
                .decode(&mut input)
                .context(crate::PackageArrowSnafu)?
            else {
                continue;
            };
            rows = rows.saturating_add(batch.num_rows() as u64);
            bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
            if rows > limits.max_rows
                || bytes > limits.max_bytes
                || batches.len() >= limits.max_batches as usize
            {
                return Err(Code::Limit.error("decoded dataset"));
            }
            batches.push(batch);
        }
        reader.finish().context(crate::PackageArrowSnafu)?;
        let schema = reader
            .schema()
            .ok_or_else(|| Code::Invalid.error("dataset schema"))?;
        if batches.is_empty() {
            batches.push(sdk::RecordBatch::new_empty(Arc::clone(&schema)));
        }
        Ok(sdk::Dataset {
            name: self.name.clone(),
            batches,
        })
    }
}

pub(super) struct PackageBuffer {
    bytes: Vec<u8>,
    limit: u64,
}

impl PackageBuffer {
    pub(super) fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for PackageBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if (self.bytes.len() as u64).saturating_add(bytes.len() as u64) > self.limit {
            return Err(io::Error::other("package encoding byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
