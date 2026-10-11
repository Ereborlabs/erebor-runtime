use std::collections::BTreeMap;

use araphor_analysis_builtins::discovery as builtin;

use super::{Adapter, Result};
use crate::*;

impl DiscoveryOwner {
    pub fn derive_recorded(input: &DiscoveryInputManifestV1) -> Result<DiscoveryRecordedResultV1> {
        input.validate()?;
        let adapter = Adapter::new(
            input
                .records
                .iter()
                .map(|row| &row.id)
                .chain(input.contexts.iter().map(|row| &row.record_id))
                .chain(input.exclusions.iter().map(|row| &row.record_id)),
        );
        let original: BTreeMap<_, _> = input.records.iter().map(|row| (&row.id, row)).collect();
        let records = input
            .records
            .iter()
            .map(|row| adapter.observation(input, row))
            .collect::<Result<Vec<_>>>()?;
        let contexts = input
            .contexts
            .iter()
            .map(|row| {
                Adapter::context(input.proof_kind, row, original.get(&row.record_id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        let coverage = input
            .coverage
            .iter()
            .map(Adapter::coverage)
            .collect::<Result<Vec<_>>>()?;
        let lifecycle = input
            .lifecycle
            .iter()
            .map(|row| adapter.lifecycle(row))
            .collect::<Result<Vec<_>>>()?;
        let exclusions = input
            .exclusions
            .iter()
            .map(|row| adapter.disposition(row))
            .collect::<Result<Vec<_>>>()?;
        let output = Adapter::run(
            "atoms",
            vec![
                Adapter::dataset("records", &records)?,
                Adapter::dataset("contexts", &contexts)?,
                Adapter::dataset("coverage", &coverage)?,
                Adapter::dataset("lifecycle", &lifecycle)?,
                Adapter::dataset("exclusions", &exclusions)?,
                Adapter::dataset(
                    "observed",
                    &[input.proof_kind == DiscoveryProofKindV1::ObservedRuntime],
                )?,
            ],
            Adapter::revision(input)?,
        )?;
        adapter.snapshot(
            &output,
            input.tenant_id,
            input.source_revision.clone(),
            input.proof_kind,
        )
    }
}

impl Adapter {
    fn observation(
        &self,
        input: &DiscoveryInputManifestV1,
        record: &DiscoveryRecordV1,
    ) -> Result<builtin::Record> {
        let wire = record.decode()?;
        let range = input
            .coverage
            .iter()
            .position(|range| {
                range.stream == record.id.stream
                    && range.cpu_id == record.id.cpu_id
                    && range.first_cursor <= record.id.durable_cursor
                    && range.last_cursor >= record.id.durable_cursor
            })
            .ok_or_else(|| {
                DiscoveryInvalidSnafu {
                    field: "record range",
                }
                .build()
            })?;
        Ok(builtin::Record {
            id: self.identity(&record.id)?,
            bytes: Self::json(record)?,
            cursor: record.id.durable_cursor,
            range: range as u64,
            temporal: wire.temporal_coverage,
            operation: builtin::Operation {
                family: wire.effect_family,
                operation: wire.operation,
                argument: wire.operation_argument.unwrap_or_default(),
                wildcard: false,
            },
            generation: wire.profile_generation_ref_id,
            object: wire.exact_object_id.to_vec(),
            decision: wire.decision,
            kernel_result: wire.kernel_result,
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
            record: Self::json(&context.record_id)?,
            operation: builtin::Operation {
                family: u32::from(context.static_key.effect_family),
                operation: u32::from(context.static_key.operation),
                argument: context.static_key.operation_argument,
                wildcard: context.static_key.argument_wildcard,
            },
            lifetime: builtin::Lifetime {
                process: context.process_instance_id.to_vec(),
                entry: context.entry_instance_id.to_vec(),
                binding: context.binding_id.to_vec(),
                role: context.role_id,
                state: context.state_id,
                rule: context.entry_rule_id,
                sequence: 0,
            },
        })
    }
    fn atom_key(
        record: &DiscoveryRecordV1,
        context: &DiscoveryContextBindingV1,
        proof: DiscoveryProofKindV1,
    ) -> Result<String> {
        let wire = record.decode()?;
        Self::json(&BehaviorAtomKeyV1 {
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
