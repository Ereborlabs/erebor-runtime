use std::collections::{BTreeMap, BTreeSet};

use erebor_interceptor_abi::{EffectPhysicalResultV1, KernelEffectFamilyV1};

use super::*;
use crate::{
    CompiledOperationV1, CoverageStateV1, EffectFamilyV1, PolicyCompiler, PolicyDocumentV1,
    PolicySimulator, Result,
};

pub struct DiscoveryOwner {
    pub(super) live: super::live::DiscoveryLive,
}

impl DiscoveryOwner {
    pub fn derive_recorded(input: &DiscoveryInputManifestV1) -> Result<DiscoveryRecordedResultV1> {
        // ponytail: offline input stays in memory; use bounded pages before live derivation.
        input.validate()?;
        let mut records = BTreeMap::new();
        let mut duplicates = 0;
        for record in &input.records {
            if let Some(previous) = records.insert(&record.id, record) {
                DiscoveryInputManifestV1::require(previous == record, "CONFLICTING_RECORD")?;
                duplicates += 1;
            }
        }
        let mut contexts = BTreeMap::new();
        for context in &input.contexts {
            DiscoveryInputManifestV1::require(
                records.contains_key(&context.record_id),
                "ORPHAN_CONTEXT",
            )?;
            if let Some(previous) = contexts.insert(&context.record_id, context) {
                DiscoveryInputManifestV1::require(previous == context, "CONFLICTING_CONTEXT")?;
            }
        }
        let mut coverage = input.coverage.clone();
        coverage
            .sort_by(|left, right| (&left.stream, left.cpu_id).cmp(&(&right.stream, right.cpu_id)));
        for range in &mut coverage {
            range.gap_reasons.sort();
            range.gap_reasons.dedup();
        }
        let input_digest = DiscoveryDigestV1::of(&(
            input.schema_version,
            input.tenant_id,
            &input.source_revision,
            input.proof_kind,
            &coverage,
            records.values().collect::<Vec<_>>(),
            contexts.values().collect::<Vec<_>>(),
        ))?;
        let mut input_counts = BTreeMap::<_, (u64, bool, bool)>::new();
        for (id, record) in &records {
            let summary = input_counts.entry((&id.stream, id.cpu_id)).or_default();
            summary.0 += 1;
            summary.1 |= record.observation.temporal_coverage == crate::TemporalCoverageV1::Gapped;
            summary.2 |= record.observation.temporal_coverage == crate::TemporalCoverageV1::Unknown;
        }
        for range in &mut coverage {
            let (count, gapped, unknown) = input_counts
                .get(&(&range.stream, range.cpu_id))
                .copied()
                .unwrap_or_default();
            if count != range.expected_records {
                range.state = CoverageStateV1::Gapped;
                range.gap_reasons.push("INPUT_RANGE_INCOMPLETE".into());
            }
            if gapped {
                range.state = CoverageStateV1::Gapped;
                range.gap_reasons.push("OBSERVATION_COVERAGE_GAPPED".into());
            }
            if unknown {
                if range.state != CoverageStateV1::Gapped {
                    range.state = CoverageStateV1::Unknown;
                }
                range
                    .gap_reasons
                    .push("OBSERVATION_COVERAGE_UNKNOWN".into());
            }
            range.gap_reasons.sort();
            range.gap_reasons.dedup();
        }
        let mut atoms = BTreeMap::<DiscoveryDigestV1, BehaviorAtomV1>::new();
        let mut unresolved = Vec::new();
        let mut included = 0;
        for (id, record) in &records {
            let Some(context) = contexts.get(id) else {
                unresolved.push(DiscoveryUnresolvedV1 {
                    record_id: (*id).clone(),
                    reason: "MISSING_RECORDED_CONTEXT".into(),
                });
                continue;
            };
            let observation = &record.observation;
            if observation
                .profile_generation_ref_id
                .is_none_or(|generation| generation == 0)
                || observation
                    .effect
                    .exact_object_id
                    .is_none_or(|id| id.is_zero())
            {
                unresolved.push(DiscoveryUnresolvedV1 {
                    record_id: (*id).clone(),
                    reason: "MISSING_EXACT_OBJECT_OR_GENERATION".into(),
                });
                continue;
            }
            let key = BehaviorAtomKeyV1::from_record(record, context, input.proof_kind)?;
            let digest = DiscoveryDigestV1::of(&key)?;
            let atom = atoms.entry(digest.clone()).or_insert_with(|| {
                BehaviorAtomV1::from_key(
                    digest,
                    key.clone(),
                    0,
                    id.durable_cursor,
                    id.durable_cursor,
                    Vec::new(),
                )
            });
            DiscoveryInputManifestV1::require(atom.key == key, "ATOM_DIGEST_COLLISION")?;
            atom.count += 1;
            atom.first_cursor = atom.first_cursor.min(id.durable_cursor);
            atom.last_cursor = atom.last_cursor.max(id.durable_cursor);
            if atom.evidence_sample.len() < 8 {
                atom.evidence_sample.push((*id).clone());
            }
            included += 1;
            DiscoveryInputManifestV1::require(atoms.len() <= MAX_DISCOVERY_ATOMS, "ATOM_LIMIT")?;
        }
        let atoms: Vec<_> = atoms.into_values().collect();
        let accepted_records = records.len() as u64;
        let content_digest =
            DiscoveryDigestV1::of(&(&input_digest, &atoms, &unresolved, &coverage))?;
        Ok(DiscoveryRecordedResultV1 {
            duplicate_deliveries: duplicates,
            snapshot: BehaviorSnapshotV1 {
                schema_version: DISCOVERY_SCHEMA_VERSION,
                input_digest,
                content_digest,
                proof_kind: input.proof_kind,
                accepted_records,
                included_records: included,
                unresolved_records: unresolved.len() as u64,
                excluded_records: 0,
                coverage,
                atoms,
                unresolved,
            },
        })
    }

    pub fn simulate_recorded(
        input: &DiscoveryInputManifestV1,
        candidate: &PolicyDocumentV1,
    ) -> Result<DiscoveryStaticPreviewV1> {
        let derived = Self::derive_recorded(input)?;
        let compiled = PolicyCompiler.compile(candidate)?;
        let keys: BTreeSet<_> = derived
            .snapshot
            .atoms
            .iter()
            .map(|atom| &atom.static_key)
            .collect();
        let simulator = PolicySimulator::new(&compiled);
        let simulations = keys
            .into_iter()
            .map(|key| {
                DiscoveryInputManifestV1::require(
                    matches!(
                        key.effect_family,
                        EffectFamilyV1::File | EffectFamilyV1::Exec
                    ),
                    "STATIC_FAMILY_UNSUPPORTED",
                )?;
                DiscoveryInputManifestV1::require(
                    !compiled
                        .compiled_cells
                        .iter()
                        .any(|cell| &cell.key == key && cell.consuming_exception_id.is_some()),
                    "DYNAMIC_EXCEPTION_UNSUPPORTED",
                )?;
                Ok(simulator.simulate(key.clone(), None))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DiscoveryStaticPreviewV1 {
            input_digest: derived.snapshot.input_digest,
            snapshot_digest: derived.snapshot.content_digest,
            source_policy_digest: compiled.source_policy_digest,
            proof_kind: input.proof_kind,
            unresolved_records: derived.snapshot.unresolved_records,
            simulations,
        })
    }
}

impl BehaviorAtomV1 {
    pub(crate) fn from_key(
        id: DiscoveryDigestV1,
        key: BehaviorAtomKeyV1,
        count: u64,
        first_cursor: u64,
        last_cursor: u64,
        evidence_sample: Vec<DiscoveryRecordIdV1>,
    ) -> Self {
        Self {
            id,
            count,
            first_cursor,
            last_cursor,
            source_reason: key.effect.reason,
            source_decision: key.effect.decision,
            kernel_result: key.effect.kernel_result,
            physical_result: if key.effect.decision
                == EffectPhysicalResultV1::DeniedBeforeEffect as u8
                && key.effect.kernel_result < 0
            {
                DiscoveryPhysicalResultV1::Prevented
            } else {
                DiscoveryPhysicalResultV1::Unknown
            },
            static_key: key.static_key.clone(),
            key,
            evidence_sample,
        }
    }
}

impl BehaviorAtomKeyV1 {
    pub(crate) fn from_record(
        record: &DiscoveryRecordV1,
        context: &DiscoveryContextBindingV1,
        proof_kind: DiscoveryProofKindV1,
    ) -> Result<Self> {
        let observation = &record.observation;
        let operation = CompiledOperationV1::try_from(context.static_key.operation_id.as_str());
        DiscoveryInputManifestV1::require(
            context.record_id == record.id
                && u16::from(KernelEffectFamilyV1::from(context.static_key.effect_family) as u8)
                    == observation.effect.effect_family
                && operation.is_ok_and(|operation| {
                    operation.kernel_id as u16 == observation.effect.operation
                        && (operation.argument_wildcard
                            || observation.effect.operation_argument.unwrap_or_default()
                                == operation.argument)
                }),
            "CONTEXT_OPERATION_MISMATCH",
        )?;
        Ok(Self {
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
            generation: observation.profile_generation_ref_id.unwrap_or_default(),
            coverage_interval_id: observation.coverage_interval_id,
            temporal_coverage: observation.temporal_coverage,
            effect: observation.effect.clone(),
            proof_kind,
        })
    }
}
