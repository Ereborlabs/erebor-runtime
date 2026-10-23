use std::io::Cursor;

use araphor_analysis_sdk as sdk;
use duckdb::Connection;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::model::{Attempt, Step};
use crate::{PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    pub(super) fn validate_selected_header(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
        step: &Step,
        revision: u64,
    ) -> Result<(Attempt, sdk::Schema)> {
        let attempt = Self::managed_attempt_from(reader, tenant, &step.instance, &step.attempt)?
            .ok_or_else(|| Code::Missing.error("managed selected attempt"))?;
        let spec =
            Self::managed_version_from(reader, tenant, &step.instance, attempt.capture.generation)?;
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed selected result"))?;
        attempt.capture.grant.validate()?;
        if attempt.capture.grant.selection
            != Self::managed_scope_from(reader, tenant, &step.instance, attempt.capture.generation)?
            || receipt.instance != step.instance
            || receipt.attempt != step.attempt
            || receipt.selected.result_id != id
            || receipt.selected.commit_revision != revision
            || receipt.commit_revision != revision
            || !receipt.matches_frontier(&attempt.request.frontier)
            || attempt.terminal.is_some()
            || attempt.registered == 0
            || revision <= attempt.registered
            || receipt.results.iter().any(|(call, reference)| {
                !spec.manifest.calls.contains_key(call)
                    || reference.result_id.is_empty()
                    || (reference.commit_revision != revision
                        && !attempt.retains(&spec, *call, reference))
            })
            || step.witnesses != attempt.capture.witnesses
            || step.contexts != attempt.capture.contexts
        {
            return Err(Code::Invalid.error("retained managed selected contract"));
        }
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(receipt.results.values().cloned());
        dependencies.sort_by(|left, right| left.result_id.cmp(&right.result_id));
        dependencies.dedup();
        if step.dependencies != dependencies {
            return Err(Code::Invalid.error("managed selected dependencies"));
        }
        for (call, reference) in &receipt.results {
            let (record, _, saved) =
                Self::managed_header_from(reader, tenant, &reference.result_id)?;
            let retained = attempt.retains(&spec, *call, reference);
            if saved != reference.commit_revision
                || (!retained && saved != revision)
                || record.call != *call
                || (!retained && record.attempt != step.attempt)
                || record.instance != step.instance
                || spec.manifest.calls.get(call) != Some(&record.declaration)
            {
                return Err(Code::Invalid.error("managed selected call binding"));
            }
            if retained {
                Self::validate_managed_header(
                    reader,
                    tenant,
                    &reference.result_id,
                    &record,
                    saved,
                )?;
            }
        }
        Ok((attempt, spec.manifest.selected_schema))
    }

    pub(super) fn decode_selected_record(
        packet: &sdk::wire::Dataset,
        schema: &sdk::Schema,
        rows: u64,
    ) -> Result<sdk::Dataset> {
        let data = Self::decode_selected(packet)?;
        if data.rows() != rows
            || data
                .batches
                .iter()
                .any(|batch| batch.schema().as_ref() != schema)
        {
            return Err(Code::Invalid.error("managed selected result schema"));
        }
        Ok(data)
    }

    pub(super) fn encode_selected(
        data: &sdk::Dataset,
        schema: &sdk::Schema,
    ) -> Result<sdk::wire::Dataset> {
        let mut buffer = Vec::new();
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut buffer, schema)
            .context(crate::PackageArrowSnafu)?;
        let mut rows = 0_u64;
        for batch in &data.batches {
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Code::Invalid.error("native selected row count"))?;
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
