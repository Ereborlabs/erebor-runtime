use erebor_interceptor_abi::{EffectObservationV1, KernelEffectOperationV1};
use sha2::{Digest as _, Sha256};

use crate::error::IdentityStateSnafu;
use crate::Result;

pub use mithril_control::{
    CoverageGapReasonV1, CoverageStateV1, EvidenceDigestV1, EvidenceFieldKeyV1, EvidenceIdV1,
    EvidenceSensitivityV1 as SensitivityV1, KernelEffectEvidenceV1, LocalSubjectBindingV1,
    ObservationEnvelopeV1, OperationResultAuthorityV1, ProofIntegrityV1 as IntegrityV1,
    ProofQualityV1, RemoteSubjectBindingV1, SourceAuthorityV1, TemporalCoverageV1,
};

#[derive(Clone, Copy, Debug)]
pub struct ObservationCanonicalizer {
    tenant_id: EvidenceIdV1,
    source_id: EvidenceIdV1,
    source_epoch: u64,
    node_boot_id: EvidenceIdV1,
}

impl ObservationCanonicalizer {
    pub fn new(
        tenant_id: EvidenceIdV1,
        source_id: EvidenceIdV1,
        source_epoch: u64,
        node_boot_id: EvidenceIdV1,
    ) -> Result<Self> {
        if tenant_id.is_zero() || source_id.is_zero() || source_epoch == 0 || node_boot_id.is_zero()
        {
            return IdentityStateSnafu {
                reason: "observation canonicalizer requires nonzero tenant, source, epoch, and boot identities"
                    .to_owned(),
            }
            .fail();
        }
        Ok(Self {
            tenant_id,
            source_id,
            source_epoch,
            node_boot_id,
        })
    }

    #[must_use]
    pub const fn source_epoch(self) -> u64 {
        self.source_epoch
    }

    pub fn normalize_kernel(
        self,
        event: EffectObservationV1,
        coverage_interval_id: EvidenceIdV1,
        temporal_coverage: TemporalCoverageV1,
        ingested_utc_ns: i64,
    ) -> Result<ObservationEnvelopeV1> {
        if event.source_sequence == 0 || coverage_interval_id.is_zero() {
            return IdentityStateSnafu {
                reason:
                    "kernel observation requires a nonzero source sequence and coverage interval"
                        .to_owned(),
            }
            .fail();
        }
        let source_id = self.cpu_source_id(event.source_cpu_id);
        let effect = kernel_effect(&event);
        let context_id = |id: EvidenceIdV1| {
            if id.is_zero() {
                Vec::new()
            } else {
                id.to_be_bytes().to_vec()
            }
        };
        let observation = ObservationEnvelopeV1 {
            tenant_id: self.tenant_id,
            node_boot_id: self.node_boot_id,
            source_id,
            source_epoch: self.source_epoch,
            source_sequence: event.source_sequence,
            cpu_id: event.source_cpu_id,
            observed_boottime_ns: event.observed_boottime_ns,
            ingested_utc_ns,
            coverage_interval_id,
            profile_generation_ref_id: (event.profile_generation_ref_id > 0)
                .then_some(event.profile_generation_ref_id),
            temporal_coverage,
            effect,
            decision_context: Some(mithril_control::EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: event.source_sequence,
                process_instance_id: context_id(event.process_instance_id),
                entry_instance_id: context_id(event.entry_instance_id),
                binding_id: context_id(event.binding_id),
                profile_generation_ref_id: event.profile_generation_ref_id,
                role_id: event.active_role_id,
                state_id: event.process_state_vector_id,
                entry_rule_id: event.admitted_entry_rule_id,
                exact_file_object: (event.exact_object_key_id != 0)
                    .then(|| event.file_object.into()),
                exact_object_key_id: event.exact_object_key_id,
                composite_atom_id: event.composite_atom_id,
            }),
        };
        observation.validate()?;
        Ok(observation)
    }

    pub(crate) fn cpu_source_id(self, cpu_id: u32) -> EvidenceIdV1 {
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-KERNEL-SOURCE-V1\0");
        digest.update(self.source_id.to_be_bytes());
        digest.update(cpu_id.to_be_bytes());
        let digest: EvidenceDigestV1 = digest.finalize().into();
        digest.into()
    }
}

fn kernel_effect(event: &EffectObservationV1) -> KernelEffectEvidenceV1 {
    let exact_object_id = if event.exact_object_key_id > 0 {
        Some(
            mithril_control::EvidenceExactFileObject::from(event.file_object)
                .observation_id(event.exact_object_key_id),
        )
    } else {
        None
    };
    KernelEffectEvidenceV1 {
        task_cookie: event.task_cookie,
        target_task_cookie: (event.target_task_cookie > 0).then_some(event.target_task_cookie),
        process_lineage_id: (!event.process_lineage_id.is_zero())
            .then_some(event.process_lineage_id),
        authority_domain_id: (!event.authority_domain_id.is_zero())
            .then_some(event.authority_domain_id),
        execution_set_id: (!event.execution_set_id.is_zero()).then_some(event.execution_set_id),
        exact_object_id,
        destination_id: (event.network_destination_policy_handle > 0)
            .then_some(event.network_destination_policy_handle),
        policy_rule_id: (event.composite_atom_id > 0).then_some(event.composite_atom_id),
        reason: event.reason,
        decision: event.physical_result,
        effect_family: event.effect_family,
        operation: event.operation,
        operation_argument: (event.operation == KernelEffectOperationV1::Ioctl as u16
            || event.operation == KernelEffectOperationV1::IpcAccess as u16
            || event.operation == KernelEffectOperationV1::Ptrace as u16
            || event.operation == KernelEffectOperationV1::Signal as u16
            || event.operation == KernelEffectOperationV1::Capability as u16)
            .then_some(event.operation_argument),
        configured_errno: event.configured_errno,
        kernel_result: event.kernel_result,
    }
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{
        EffectObservationReasonV1, EffectObservationV1, Id128V1, KernelEffectFamilyV1,
        KernelEffectOperationV1,
    };

    use super::{EvidenceIdV1, ObservationCanonicalizer, TemporalCoverageV1};

    fn canonicalizer() -> crate::Result<ObservationCanonicalizer> {
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            5,
            EvidenceIdV1::new(6, 7),
        )
    }

    fn event(cpu_id: u32) -> EffectObservationV1 {
        EffectObservationV1 {
            observed_boottime_ns: 10,
            source_sequence: 11,
            source_cpu_id: cpu_id,
            task_cookie: 12,
            profile_generation_ref_id: 13,
            process_lineage_id: Id128V1::new(14, 15),
            authority_domain_id: Id128V1::new(16, 17),
            execution_set_id: Id128V1::new(18, 19),
            exact_object_key_id: 20,
            composite_atom_id: 21,
            network_destination_policy_handle: 22,
            effect_family: 1,
            operation: 2,
            configured_errno: -13,
            kernel_result: -13,
            reason: 9,
            physical_result: 1,
            ..EffectObservationV1::default()
        }
    }

    #[test]
    fn discovery_context_preserves_kernel_coordinates_without_inventing_catalog_facts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut event = event(2);
        event.process_instance_id = Id128V1::new(31, 32);
        event.entry_instance_id = Id128V1::new(33, 34);
        event.binding_id = Id128V1::new(35, 36);
        event.active_role_id = 7;
        event.process_state_vector_id = 8;
        event.admitted_entry_rule_id = 9;
        event.file_object = erebor_interceptor_abi::ExactFileObjectKeyV1 {
            profile_generation_ref_id: 13,
            mount_id_unique: 41,
            inode: 42,
            inode_generation: 43,
            mount_namespace_inode: 44,
            filesystem_device: 45,
        };
        let observation = canonicalizer()?.normalize_kernel(
            event,
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let record = observation.to_wire_record()?;
        let restored = mithril_control::ObservationEnvelopeV1::from_wire_record(
            observation.tenant_id,
            observation.node_boot_id,
            observation.source_id,
            observation.source_epoch,
            1,
            observation.cpu_id,
            &record,
        )?;
        assert_eq!(restored.source_sequence, 1);
        let context = restored
            .decision_context
            .as_ref()
            .ok_or("missing context")?;
        assert_eq!(context.original_kernel_sequence, 11);
        assert_eq!(
            context.process_instance_id,
            event.process_instance_id.to_be_bytes()
        );
        assert_eq!(
            context.entry_instance_id,
            event.entry_instance_id.to_be_bytes()
        );
        assert_eq!(context.binding_id, event.binding_id.to_be_bytes());
        assert_eq!(
            (context.role_id, context.state_id, context.entry_rule_id),
            (7, 8, 9)
        );
        assert_eq!(context.exact_file_object, Some(event.file_object.into()));
        assert_eq!(context.exact_object_key_id, 20);
        assert_eq!(context.composite_atom_id, 21);
        assert_eq!(context.profile_generation_ref_id, 13);
        assert_eq!(restored.to_wire_record()?, record);
        for mutation in 0..7 {
            let mut changed = restored.clone();
            let context = changed.decision_context.as_mut().ok_or("missing context")?;
            match mutation {
                0 => context.schema_version = 2,
                1 => context.original_kernel_sequence = 0,
                2 => context.profile_generation_ref_id += 1,
                3 => context.composite_atom_id += 1,
                4 => context.exact_object_key_id += 1,
                5 => context.binding_id = vec![1; 15],
                _ => {
                    context
                        .exact_file_object
                        .as_mut()
                        .ok_or("missing object")?
                        .inode += 1
                }
            }
            assert!(changed.validate().is_err(), "mutation {mutation}");
        }
        Ok(())
    }

    #[test]
    fn kernel_observation_has_stable_complete_identity() -> Result<(), Box<dyn std::error::Error>> {
        let first = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let second = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            200,
        )?;
        assert_eq!(first.observation_id()?, second.observation_id()?);
        assert_ne!(first.canonical_bytes()?, second.canonical_bytes()?);
        assert!(first.supports_negative_claim());
        assert_eq!(first.effect.operation, 2);
        assert_eq!(first.effect.kernel_result, -13);
        let display = serde_json::to_string(&first)?;
        assert!(!display.contains("argv"));
        assert!(!display.contains("secret"));
        Ok(())
    }

    #[test]
    fn missing_identity_observation_does_not_invent_a_subject() -> crate::Result<()> {
        let event = EffectObservationV1 {
            observed_boottime_ns: 10,
            source_sequence: 11,
            source_cpu_id: 2,
            effect_family: KernelEffectFamilyV1::File as u16,
            operation: KernelEffectOperationV1::OpenRead as u16,
            configured_errno: -13,
            kernel_result: -13,
            reason: EffectObservationReasonV1::MissingIdentity as u8,
            physical_result: 1,
            ..EffectObservationV1::default()
        };

        let observation = canonicalizer()?.normalize_kernel(
            event,
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        assert_eq!(observation.effect.task_cookie, 0);
        assert!(observation.effect.process_lineage_id.is_none());
        Ok(())
    }

    #[test]
    fn operation_and_kernel_result_change_observation_identity() -> crate::Result<()> {
        let original = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let mut changed_operation = event(2);
        changed_operation.operation = 3;
        let changed_operation = canonicalizer()?.normalize_kernel(
            changed_operation,
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let mut changed_result = event(2);
        changed_result.kernel_result = 0;
        let changed_result = canonicalizer()?.normalize_kernel(
            changed_result,
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        assert_ne!(
            original.observation_id()?,
            changed_operation.observation_id()?
        );
        assert_ne!(original.observation_id()?, changed_result.observation_id()?);
        Ok(())
    }

    #[test]
    fn each_cpu_is_an_independent_ordered_source() -> crate::Result<()> {
        let first = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Complete,
            100,
        )?;
        let second = canonicalizer()?.normalize_kernel(
            event(3),
            EvidenceIdV1::new(32, 33),
            TemporalCoverageV1::Complete,
            100,
        )?;
        assert_ne!(first.source_id, second.source_id);
        assert_ne!(first.observation_id()?, second.observation_id()?);
        Ok(())
    }

    #[test]
    fn gapped_observation_cannot_support_a_negative_claim() -> crate::Result<()> {
        let observation = canonicalizer()?.normalize_kernel(
            event(2),
            EvidenceIdV1::new(30, 31),
            TemporalCoverageV1::Gapped,
            100,
        )?;
        assert!(!observation.supports_negative_claim());
        Ok(())
    }
}
