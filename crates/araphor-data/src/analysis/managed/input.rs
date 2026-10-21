use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisDatabaseSnafu, AnalysisExtractLimits, AnalysisExtractionV1, AnalysisReadControl,
    AnalysisSelectionV1, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedInputRef {
    tenant: [u8; 16],
    instance: String,
    generation: u64,
    call: u64,
    result: PackageResultRefV1,
    output: sdk::OutputRef,
}

impl ManagedInputRef {
    pub fn result(&self) -> &PackageResultRefV1 {
        &self.result
    }

    pub fn output(&self) -> &sdk::OutputRef {
        &self.output
    }

    pub fn allocation_bytes(&self) -> Option<usize> {
        [
            self.instance.capacity(),
            self.result.result_id.capacity(),
            self.output.package.capacity(),
            self.output.revision.capacity(),
            self.output.export.capacity(),
            self.output.output.capacity(),
        ]
        .into_iter()
        .try_fold(std::mem::size_of::<Self>(), usize::checked_add)
    }
}

impl AnalysisStore {
    pub fn managed_input(
        &self,
        selection: &AnalysisSelectionV1,
        instance: &str,
        reference: &PackageResultRefV1,
        dataset: &str,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(ManagedInputRef, sdk::Port)> {
        if !selection.valid()
            || instance.is_empty()
            || dataset.is_empty()
            || reference.result_id.is_empty()
            || reference.commit_revision == 0
        {
            return Err(Code::Invalid.error("managed input reference"));
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let bytes: Option<u64> = reader.query_row(
                "SELECT octet_length(request_meta) + octet_length(body) FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND commit_revision = ? AND processor_id = 'managed-package-v1'",
                params![selection.tenant_id.as_slice(), reference.result_id, reference.commit_revision], |row| row.get(0),
            ).optional().context(AnalysisDatabaseSnafu { operation: "bound managed input header" })?;
            let bytes = bytes.ok_or_else(|| Code::Missing.error("managed input result"))?;
            if usize::try_from(bytes).unwrap_or(usize::MAX) > limits.input_bytes {
                return crate::AnalysisInputTooLargeSnafu { resource: "selected input bytes" }.fail();
            }
            let (record, _, revision) =
                Self::managed_header_from(reader, selection.tenant_id, &reference.result_id)?;
            let producer = Self::managed_instance_from(reader, selection.tenant_id, instance)?
                .ok_or_else(|| Code::Missing.error("managed input instance"))?;
            producer.spec.grant.permitted_by(selection)?;
            let descriptor = Self::validate_managed_header(
                reader, selection.tenant_id, &reference.result_id, &record, revision,
            )?;
            if record.instance != instance || revision != reference.commit_revision {
                return Err(Code::Denied.error("managed input identity"));
            }
            let port = descriptor.exports.iter()
                .find(|model| model.name == record.declaration.export)
                .and_then(|model| model.outputs.iter().find(|port| port.name == dataset))
                .ok_or_else(|| Code::Missing.error("managed input dataset"))?;
            let reference = ManagedInputRef {
                tenant: selection.tenant_id,
                instance: instance.into(),
                generation: producer.generation,
                call: record.call,
                result: reference.clone(),
                output: sdk::OutputRef {
                    package: record.declaration.package.package_id,
                    revision: record.declaration.package.revision,
                    export: record.declaration.export,
                    output: dataset.into(),
                },
            };
            let bytes = usize::try_from(bytes).unwrap_or(usize::MAX)
                .saturating_add(descriptor.allocated_bytes())
                .saturating_add(port.allocated_bytes());
            if bytes > limits.input_bytes {
                return crate::AnalysisInputTooLargeSnafu { resource: "selected input bytes" }.fail();
            }
            Ok((reference, port.clone()))
        })
    }

    pub(in crate::analysis) fn captured_managed_input(
        &self,
        reader: &Connection,
        reference: &ManagedInputRef,
        selection: &AnalysisSelectionV1,
        now: u64,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<(sdk::Dataset, sdk::Coverage)> {
        self.check_managed_input(reader, reference, selection, now, output, control)?;
        let bytes: u64 = reader.query_row(
            "SELECT octet_length(request_meta) + octet_length(body) + coalesce((SELECT sum(octet_length(ipc)) FROM managed_arrow WHERE result_id = r.result_id), 0) FROM analysis_results r WHERE tenant_id = ? AND result_id = ? AND commit_revision = ? AND processor_id = 'managed-package-v1'",
            params![reference.tenant.as_slice(), reference.result.result_id, reference.result.commit_revision], |row| row.get(0),
        ).context(AnalysisDatabaseSnafu { operation: "bound captured managed input" })?;
        let before = output.input_bytes;
        output.charge(usize::try_from(bytes).unwrap_or(usize::MAX))?;
        let (record, packet, revision) =
            Self::managed_record_from(reader, reference.tenant, &reference.result.result_id)?;
        if record.instance != reference.instance
            || record.call != reference.call
            || revision != reference.result.commit_revision
            || record.declaration.package.package_id != reference.output.package
            || record.declaration.package.revision != reference.output.revision
            || record.declaration.export != reference.output.export
        {
            return Err(Code::Invalid.error("captured managed input identity"));
        }
        let limits = record.context.context.limits;
        let mut bytes = 0usize;
        for data in packet.datasets.iter().chain(record.parameters.iter()) {
            control.check()?;
            bytes = bytes
                .checked_add(
                    sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc, limits)
                        .context(crate::AnalysisContractSnafu)?,
                )
                .ok_or_else(|| Code::Limit.error("managed input decode"))?;
        }
        for data in packet.checkpoint.iter().flat_map(|state| &state.datasets) {
            let checkpoint = sdk::Limits {
                max_bytes: limits.max_checkpoint_bytes,
                ..limits
            };
            bytes = bytes
                .checked_add(
                    sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc, checkpoint)
                        .context(crate::AnalysisContractSnafu)?,
                )
                .ok_or_else(|| Code::Limit.error("managed input decode"))?;
        }
        for reason in &packet.reasons {
            bytes = bytes
                .checked_add(
                    sdk::wire::Dataset::decoding_bytes(&reason.details, limits)
                        .context(crate::AnalysisContractSnafu)?,
                )
                .ok_or_else(|| Code::Limit.error("managed input decode"))?;
        }
        output.charge(bytes)?;
        let (mut decoded, _) = Self::validate_managed_record(
            reader,
            reference.tenant,
            &reference.result.result_id,
            &record,
            &packet,
            revision,
        )?;
        let index = decoded
            .datasets
            .iter()
            .position(|data| data.name == reference.output.output)
            .ok_or_else(|| Code::Missing.error("managed input dataset"))?;
        let data = decoded.datasets.swap_remove(index);
        let coverage = record.context.coverage.clone();
        drop(decoded);
        drop(packet);
        drop(record);
        output.input_bytes = before;
        for batch in &data.batches {
            output.charge(batch.get_array_memory_size())?;
        }
        Ok((data, coverage))
    }
    pub(in crate::analysis) fn check_managed_input(
        &self,
        reader: &Connection,
        reference: &ManagedInputRef,
        selection: &AnalysisSelectionV1,
        now: u64,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if reference.tenant != selection.tenant_id {
            return Err(Code::Denied.error("managed input tenant"));
        }
        let producer = Self::managed_instance_from(reader, reference.tenant, &reference.instance)?
            .ok_or_else(|| Code::Missing.error("managed input instance"))?;
        producer.spec.grant.permitted_by(selection)?;
        let call = producer
            .spec
            .manifest
            .calls
            .get(&reference.call)
            .ok_or_else(|| Code::Missing.error("managed input call"))?;
        if producer.generation != reference.generation
            || call.package.package_id != reference.output.package
            || call.package.revision != reference.output.revision
            || call.export != reference.output.export
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if !self.managed_source_current(
            reader,
            &producer.spec,
            (
                &reference.result.result_id,
                reference.result.commit_revision,
            ),
            now,
            control,
            Some(output),
        )? {
            return Err(Code::Incomplete.error("managed input freshness"));
        }
        Ok(())
    }
}
