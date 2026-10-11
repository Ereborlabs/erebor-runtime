use super::*;

impl GraphDerivation<'_> {
    pub(super) fn proof(&self, record: &DiscoveryRecordV1) -> ProofQualityV1 {
        let range = self
            .input
            .coverage
            .iter()
            .filter(|range| {
                range.stream == record.id.stream
                    && range.cpu_id == record.id.cpu_id
                    && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
            })
            .max_by_key(|range| range.coverage_revision);
        let has_gap = self.input.coverage.iter().any(|range| {
            range.stream == record.id.stream
                && range.cpu_id == record.id.cpu_id
                && (range.first_cursor..=range.last_cursor).contains(&record.id.durable_cursor)
                && range.state == DiscoveryCoverageStateV1::Gapped
        });
        let temporal = if !self.input.missing_ranges.is_empty() || has_gap {
            TemporalCoverageV1::Gapped
        } else {
            match range.map(|range| range.state) {
                Some(DiscoveryCoverageStateV1::Healthy | DiscoveryCoverageStateV1::Closed) => {
                    TemporalCoverageV1::Complete
                }
                Some(DiscoveryCoverageStateV1::Gapped) => TemporalCoverageV1::Gapped,
                _ => TemporalCoverageV1::Unknown,
            }
        };
        let mut proof = ProofQualityV1::kernel_decision(temporal);
        proof.integrity = ProofIntegrityV1::AuthenticatedChannel;
        if record.decode().is_ok_and(|wire| wire.task_cookie == 0) {
            proof.local_subject_binding = LocalSubjectBindingV1::None;
        }
        proof
    }

    pub(super) fn effect(
        &self,
        record: &DiscoveryRecordV1,
        wire: &EvidenceRecord,
    ) -> GraphEffectV1 {
        let context = wire.decision_context.as_ref();
        GraphEffectV1 {
            evidence: record.id.clone(),
            process_instance_id: context
                .and_then(|context| context.process_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            entry_instance_id: context
                .and_then(|context| context.entry_instance_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            binding_id: context
                .and_then(|context| context.binding_id.as_slice().try_into().ok())
                .filter(|id| *id != [0; 16]),
            role_id: context
                .map(|context| context.role_id)
                .filter(|role| *role > 0),
            state_id: context
                .map(|context| context.state_id)
                .filter(|state| *state > 0),
            entry_rule_id: context
                .map(|context| context.entry_rule_id)
                .filter(|rule| *rule > 0),
            profile_generation_ref_id: wire.profile_generation_ref_id,
            original_kernel_sequence: record.original_kernel_sequence,
            effect_family: wire.effect_family,
            operation: wire.operation,
            source_decision: wire.decision,
            source_reason: wire.reason,
            configured_errno: wire.configured_errno,
            kernel_result: wire.kernel_result,
            physical_result: match wire.decision {
                result
                    if result == EffectPhysicalResultV1::DeniedBeforeEffect as u32
                        && wire.kernel_result < 0 =>
                {
                    GraphPhysicalResultV1::Prevented
                }
                result if result == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u32 => {
                    GraphPhysicalResultV1::PacketDropped
                }
                result
                    if result == EffectPhysicalResultV1::TerminationQueuedBeforeUserMode as u32 =>
                {
                    GraphPhysicalResultV1::TerminationQueued
                }
                _ => GraphPhysicalResultV1::Unknown,
            },
            proof_quality: self.proof(record),
        }
    }

    pub(super) fn qualified_result(proof: ProofQualityV1) -> bool {
        matches!(
            proof.source_authority,
            SourceAuthorityV1::KernelDecision
                | SourceAuthorityV1::AuthoritativeProvider
                | SourceAuthorityV1::SignedCoordinator
                | SourceAuthorityV1::AuthenticatedMeasurement
        ) && matches!(
            proof.local_subject_binding,
            LocalSubjectBindingV1::ExactTask | LocalSubjectBindingV1::ExactProcess
        ) && proof.temporal_coverage == TemporalCoverageV1::Complete
            && matches!(
                proof.integrity,
                ProofIntegrityV1::Signed
                    | ProofIntegrityV1::AuthenticatedChannel
                    | ProofIntegrityV1::LocalAttested
            )
    }
}
