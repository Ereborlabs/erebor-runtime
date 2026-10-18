use std::collections::BTreeMap;

use araphor_analysis_builtins::discovery as builtin;
use snafu::ResultExt as _;

use super::{pages::RecordedPages, Adapter, Result};
use crate::*;

impl DiscoveryOwner {
    pub fn derive_recorded(
        input: &DiscoveryInputManifestV1,
        execution: &crate::InstalledAnalysis,
    ) -> Result<DiscoveryRecordedResultV1> {
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(60))?;
        let mut pages = RecordedPages::new(input, 128, &control)?;
        let execution = execution.snapshot(input.tenant_id)?;
        let revision = Adapter::revision(input)?;
        control.check()?;
        let mut result = {
            let first = pages.next().ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "recorded pages",
                }
                .build()
            })??;
            Self::derive_page(&first, &execution, &revision, &control)?
        };
        for page in pages {
            let next = Self::derive_page(&page?, &execution, &revision, &control)?;
            crate::discovery::model::add(
                &mut result.duplicate_deliveries,
                next.duplicate_deliveries,
            )?;
            result.snapshot = Self::merge_control(
                &result.snapshot,
                &next.snapshot,
                &execution,
                &revision,
                &control,
            )?;
        }
        Adapter::validate_recorded(input, &result)?;
        control.check()?;
        Ok(result)
    }

    fn derive_page(
        input: &DiscoveryInputManifestV1,
        execution: &crate::InstalledAnalysis,
        revision: &str,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryRecordedResultV1> {
        control.check()?;
        input.validate()?;
        let original: BTreeMap<_, _> = input.records.iter().map(|row| (&row.id, row)).collect();
        let records = input
            .records
            .iter()
            .map(Adapter::observation)
            .collect::<Result<Vec<_>>>()?;
        let contexts = input
            .contexts
            .iter()
            .map(|row| {
                Adapter::context(input.proof_kind, row, original.get(&row.record_id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        let output = Adapter::run_control(
            execution,
            input.tenant_id,
            "atoms",
            vec![
                builtin::Record::encode(&records).context(AnalysisContractSnafu)?,
                Adapter::dataset("contexts", &contexts)?,
                Adapter::dataset("coverage", &input.coverage)?,
                Adapter::dataset("lifecycle", &input.lifecycle)?,
                Adapter::dataset("exclusions", &input.exclusions)?,
                Adapter::dataset(
                    "observed",
                    &[input.proof_kind == DiscoveryProofKindV1::ObservedRuntime],
                )?,
            ],
            revision.into(),
            control,
        )?;
        let result = Adapter::snapshot(
            &output.output,
            input.tenant_id,
            input.source_revision.clone(),
            input.proof_kind,
        )?;
        Adapter::validate_recorded(input, &result)?;
        control.check()?;
        Ok(result)
    }
}

impl Adapter {
    fn observation(record: &DiscoveryRecordV1) -> Result<builtin::Record<'_>> {
        let wire = record.decode()?;
        Ok(builtin::Record {
            id: record.id.clone(),
            bytes: std::borrow::Cow::Borrowed(&record.wire_record),
            temporal: wire.temporal_coverage,
            effect: (&wire).into(),
            generation: wire.profile_generation_ref_id,
            original_sequence: record.original_kernel_sequence,
            source: wire
                .decision_context
                .as_ref()
                .map(|source| builtin::Lifetime {
                    process: source.process_instance_id.clone(),
                    entry: source.entry_instance_id.clone(),
                    binding: source.binding_id.clone(),
                    role: source.role_id,
                    state: source.state_id,
                    rule: source.entry_rule_id,
                    sequence: source.original_kernel_sequence,
                }),
        })
    }

    fn context(
        proof: DiscoveryProofKindV1,
        context: &DiscoveryContextBindingV1,
        record: Option<&DiscoveryRecordV1>,
    ) -> Result<builtin::Context> {
        Ok(builtin::Context {
            atom_key: record
                .map(|record| Self::atom_key(record, context, proof))
                .transpose()?,
            record_id: context.record_id.clone(),
        })
    }
    pub(super) fn atom_key(
        record: &DiscoveryRecordV1,
        context: &DiscoveryContextBindingV1,
        proof: DiscoveryProofKindV1,
    ) -> Result<BehaviorAtomKeyV1> {
        let wire = record.decode()?;
        Ok(BehaviorAtomKeyV1 {
            stream: record.id.stream.clone(),
            cpu_id: record.id.cpu_id,
            subject_revision: context.subject_revision.clone(),
            image_digest: context.image_digest.clone(),
            configuration_digest: context.configuration_digest.clone(),
            process_instance_id: context.process_instance_id,
            entry_instance_id: context.entry_instance_id,
            binding_id: context.binding_id,
            role_id: context.role_id,
            state_id: context.state_id,
            entry_rule_id: context.entry_rule_id,
            catalog_revision: context.catalog_revision,
            static_key: context.static_key.clone(),
            policy_revision: context.policy_revision.clone(),
            generation: wire.profile_generation_ref_id.unwrap_or_default(),
            coverage_interval_id: wire.coverage_interval_id.as_ref().try_into().map_err(|_| {
                DiscoveryInvalidSnafu {
                    field: "record fields",
                }
                .build()
            })?,
            temporal_coverage: wire.temporal_coverage,
            effect: (&wire).into(),
            physical_result: DiscoveryPhysicalResultV1::Unknown,
            proof_kind: proof,
        })
    }
}

#[cfg(test)]
mod tests;
