use std::io::Cursor;

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::super::graph_rows::GraphHeader;
use super::super::AnalysisStore;
use super::model::{Attempt, ManagedAttempt, ManagedDestination, ManagedReceipt, Step};
use crate::{
    AnalysisDatabaseSnafu, EvidenceIntakeIdentityV1, GraphSnapshotV1, PackageErrorCodeV1 as Code,
    Result, GRAPH_PROCESSOR, GRAPH_SCHEMA_VERSION,
};

impl AnalysisStore {
    pub(in crate::analysis) fn managed_graph_base(
        reader: &Connection,
        attempt: &ManagedAttempt,
        graph: &GraphSnapshotV1,
    ) -> Result<Option<ManagedReceipt>> {
        let captured = &attempt.0.capture;
        if captured.completed == 0
            || captured.rebuild
            || captured.generation != captured.expected_generation
            || graph.previous_result_id.is_none()
        {
            return Ok(None);
        }
        let key: Option<String> = reader
            .query_row(
                "SELECT attempt_id FROM managed_attempts
                 WHERE tenant_id = ? AND instance_id = ?
                    AND generation = ? AND completed = ?",
                params![
                    captured.tenant.as_slice(),
                    captured.instance,
                    captured.generation,
                    captured.completed
                ],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read prior managed Graph publication",
            })?;
        let Some(key) = key else {
            return Ok(None);
        };
        let Some(prior) =
            Self::managed_attempt_from(reader, captured.tenant, &captured.instance, &key)?
        else {
            return Ok(None);
        };
        let Some(receipt) = prior.receipt else {
            return Ok(None);
        };
        if prior.terminal.is_some()
            || prior.capture.generation != captured.generation
            || receipt.commit_revision != captured.completed
            || receipt.graph.as_ref().is_none_or(|reference| {
                graph.previous_result_id.as_ref() != Some(&reference.result_id)
            })
        {
            return Ok(None);
        }
        let (step, _, revision) =
            Self::managed_step_header(reader, captured.tenant, &receipt.selected.result_id)?;
        Self::validate_selected_header(
            reader,
            captured.tenant,
            &receipt.selected.result_id,
            &step,
            revision,
        )?;
        Ok(Some(receipt))
    }

    pub(super) fn check_graph_publication(
        reader: &Connection,
        tenant: [u8; 16],
        source: &EvidenceIntakeIdentityV1,
        reference: &super::super::PackageResultRefV1,
        selected_revision: u64,
    ) -> Result<()> {
        if !source.valid()
            || source.tenant_id != tenant
            || reference.result_id.is_empty()
            || reference.commit_revision == 0
            || reference.commit_revision > selected_revision
        {
            return Err(Code::Invalid.error("managed Graph publication"));
        }
        let retained: Option<(Vec<u8>, Vec<u8>, u64, u64)> = reader
            .query_row(
                "SELECT r.body, r.stream_key, r.method_version, r.first_cursor
                 FROM analysis_results r
                    JOIN graph_versions v USING (result_id)
                    WHERE r.result_id = ? AND r.tenant_id = ?
                        AND r.processor_id = ? AND r.method_version = ?
                        AND r.stream_key = ? AND r.commit_revision = ?
                        AND v.commit_revision = r.commit_revision",
                params![
                    reference.result_id,
                    tenant.as_slice(),
                    GRAPH_PROCESSOR,
                    GRAPH_SCHEMA_VERSION,
                    source.key().as_slice(),
                    reference.commit_revision,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read managed Graph publication",
            })?;
        let (body, stream, method, first) =
            retained.ok_or_else(|| Code::Invalid.error("managed Graph publication"))?;
        GraphHeader::decode(&body)?.check_index(tenant, &stream, method, first)?;
        Ok(())
    }

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
        match (&spec.destination, &receipt.graph) {
            (ManagedDestination::Graph { source, .. }, Some(reference)) => {
                Self::check_graph_publication(reader, tenant, source, reference, revision)?;
            }
            (ManagedDestination::Graph { .. }, None)
                if receipt.results.is_empty() && step.rows == 0 => {}
            (ManagedDestination::Graph { .. }, None) | (_, Some(_)) => {
                return Err(Code::Invalid.error("managed Graph publication"));
            }
            (_, None) => {}
        }
        let mut dependencies = attempt.capture.dependencies.clone();
        dependencies.extend(receipt.results.values().cloned());
        dependencies.extend(receipt.graph.iter().cloned());
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
