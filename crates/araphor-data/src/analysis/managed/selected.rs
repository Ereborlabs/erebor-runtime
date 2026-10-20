use std::io::Cursor;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use crate::{PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub(super) fn encode_selected(
        data: &sdk::Dataset,
        schema: &sdk::Schema,
        limits: sdk::Limits,
    ) -> Result<sdk::wire::Dataset> {
        let mut buffer = Vec::new();
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut buffer, schema)
            .context(crate::PackageArrowSnafu)?;
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        for (index, batch) in data.batches.iter().enumerate() {
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Code::Invalid.error("native selected row count"))?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size() as u64)
                .ok_or_else(|| Code::Invalid.error("native selected byte count"))?;
            if rows > limits.max_rows
                || bytes > limits.max_bytes
                || index as u64 >= u64::from(limits.max_batches)
            {
                return Err(Code::Limit.error("native selected relation"));
            }
            if batch.schema().as_ref() != schema {
                return Err(Code::Invalid.error("native selected schema"));
            }
            for column in batch.columns() {
                column
                    .to_data()
                    .validate_full()
                    .context(crate::PackageArrowSnafu)?;
            }
            writer.write(batch).context(crate::PackageArrowSnafu)?;
        }
        writer.finish().context(crate::PackageArrowSnafu)?;
        drop(writer);
        Ok(sdk::wire::Dataset {
            name: data.name.clone(),
            arrow_ipc: buffer,
        })
    }

    pub(super) fn decode_selected(packet: &sdk::wire::Dataset) -> Result<sdk::Dataset> {
        // Selected storage uses the native writer's uncompressed format.
        packet
            .validate_envelope()
            .context(crate::AnalysisContractSnafu)?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut input = Cursor::new(&packet.arrow_ipc);
            let mut reader = arrow_ipc::reader::StreamReader::try_new(&mut input, None)
                .context(crate::PackageArrowSnafu)?;
            let schema = reader.schema();
            let mut batches = Vec::new();
            let mut rows = 0_u64;
            for batch in &mut reader {
                let batch = batch.context(crate::PackageArrowSnafu)?;
                rows = rows
                    .checked_add(batch.num_rows() as u64)
                    .ok_or_else(|| Code::Invalid.error("native selected row count"))?;
                for column in batch.columns() {
                    column
                        .to_data()
                        .validate_full()
                        .context(crate::PackageArrowSnafu)?;
                }
                batches.push(batch);
            }
            if !reader.is_finished() {
                return Err(Code::Invalid.error("native selected IPC stream"));
            }
            drop(reader);
            if input.position() != packet.arrow_ipc.len() as u64 {
                return Err(Code::Invalid.error("native selected trailing bytes"));
            }
            if batches.is_empty() {
                batches.push(sdk::RecordBatch::new_empty(schema));
            }
            Ok(sdk::Dataset {
                name: packet.name.clone(),
                batches,
            })
        }))
        .map_err(|_| Code::Invalid.error("native selected IPC stream"))?
    }
}
