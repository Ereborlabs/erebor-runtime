use erebor_interceptor_abi::{EffectObservationV1, Id128V1};
use sha2::{Digest as _, Sha256};
use zerocopy::IntoBytes as _;

use crate::error::IdentityStateSnafu;
use crate::Result;

pub use mithril_control::{
    CoverageGapReasonV1, CoverageStateV1, EvidenceDigestV1, EvidenceFieldKeyV1, EvidenceFieldV1,
    EvidenceIdV1, EvidencePayloadV1, EvidenceSensitivityV1 as SensitivityV1, EvidenceValueV1,
    LocalSubjectBindingV1, ObservationEnvelopeV1, OperationResultAuthorityV1,
    ProofIntegrityV1 as IntegrityV1, ProofQualityV1, RemoteSubjectBindingV1, SourceAuthorityV1,
    TemporalCoverageV1, MAX_EVIDENCE_FIELDS_V1, MAX_PROVENANCE_OBSERVATIONS_V1,
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
        let proof_quality = ProofQualityV1::kernel_decision(temporal_coverage);
        let payload = kernel_payload(&event, proof_quality)?;
        ObservationEnvelopeV1 {
            schema_version: 1,
            tenant_id: self.tenant_id,
            observation_id: [0; 32],
            source_id,
            source_epoch: self.source_epoch,
            source_sequence: event.source_sequence,
            stable_provider_event_id: None,
            node_boot_id: Some(self.node_boot_id),
            cpu_id: Some(event.source_cpu_id),
            hook_or_adapter_id: u32::from(event.effect_family),
            payload_schema_id: 1,
            abi_or_api_version: 1,
            profile_generation_ref_id: (event.profile_generation_ref_id > 0)
                .then_some(event.profile_generation_ref_id),
            boottime_ns: Some(event.observed_boottime_ns),
            projected_utc_ns: None,
            time_uncertainty_ns: u64::MAX,
            ingested_utc_ns,
            payload,
            proof_quality,
            coverage_interval_id,
            transport_integrity_digest: Sha256::digest(event.as_bytes()).into(),
            signature_or_batch_digest: None,
        }
        .finalize()
        .map_err(Into::into)
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

fn kernel_payload(
    event: &EffectObservationV1,
    proof_quality: ProofQualityV1,
) -> Result<EvidencePayloadV1> {
    let mut fields = vec![
        field(
            EvidenceFieldKeyV1::ReasonCode,
            EvidenceValueV1::ReasonCode(u32::from(event.reason)),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::Decision,
            EvidenceValueV1::Decision(u32::from(event.physical_result)),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::EffectFamily,
            EvidenceValueV1::EffectFamily(event.effect_family),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::Operation,
            EvidenceValueV1::Operation(event.operation),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::Errno,
            EvidenceValueV1::Errno(event.configured_errno),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::KernelResult,
            EvidenceValueV1::KernelResult(event.kernel_result),
            proof_quality,
        ),
        field(
            EvidenceFieldKeyV1::TaskCookie,
            EvidenceValueV1::TaskCookie(event.task_cookie),
            proof_quality,
        ),
    ];
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::ProcessLineageId,
        event.process_lineage_id,
        proof_quality,
    );
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::AuthorityDomainId,
        event.authority_domain_id,
        proof_quality,
    );
    push_id(
        &mut fields,
        EvidenceFieldKeyV1::ExecutionSetId,
        event.execution_set_id,
        proof_quality,
    );
    if event.exact_object_key_id > 0 {
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-EXACT-OBJECT-V1\0");
        digest.update(event.file_object.as_bytes());
        digest.update(event.exact_object_key_id.to_be_bytes());
        fields.push(field(
            EvidenceFieldKeyV1::ExactObjectId,
            EvidenceValueV1::Id(EvidenceDigestV1::from(digest.finalize()).into()),
            proof_quality,
        ));
    }
    if event.network_destination_policy_handle > 0 {
        fields.push(field(
            EvidenceFieldKeyV1::DestinationId,
            EvidenceValueV1::Destination(event.network_destination_policy_handle),
            proof_quality,
        ));
    }
    if event.composite_atom_id > 0 {
        fields.push(field(
            EvidenceFieldKeyV1::PolicyRuleIds,
            EvidenceValueV1::PolicyRules(vec![event.composite_atom_id]),
            proof_quality,
        ));
    }
    EvidencePayloadV1::new(fields).map_err(Into::into)
}

fn field(
    key: EvidenceFieldKeyV1,
    value: EvidenceValueV1,
    proof_quality: ProofQualityV1,
) -> EvidenceFieldV1 {
    EvidenceFieldV1 {
        key,
        sensitivity: SensitivityV1::Internal,
        provenance_observation_ids: Vec::new(),
        proof_quality,
        value,
    }
}

fn push_id(
    fields: &mut Vec<EvidenceFieldV1>,
    key: EvidenceFieldKeyV1,
    value: Id128V1,
    proof_quality: ProofQualityV1,
) {
    if !value.is_zero() {
        fields.push(field(key, EvidenceValueV1::Id(value), proof_quality));
    }
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{EffectObservationV1, Id128V1};

    use super::{
        EvidenceFieldKeyV1, EvidenceIdV1, EvidenceValueV1, ObservationCanonicalizer,
        TemporalCoverageV1,
    };

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
        assert_eq!(first.observation_id, second.observation_id);
        assert_ne!(first.canonical_bytes()?, second.canonical_bytes()?);
        assert!(first.supports_negative_claim());
        assert!(first.payload.fields.iter().any(|field| {
            field.key == EvidenceFieldKeyV1::Operation
                && field.value == EvidenceValueV1::Operation(2)
        }));
        assert!(first.payload.fields.iter().any(|field| {
            field.key == EvidenceFieldKeyV1::KernelResult
                && field.value == EvidenceValueV1::KernelResult(-13)
        }));
        let display = serde_json::to_string(&first)?;
        assert!(!display.contains("argv"));
        assert!(!display.contains("secret"));
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
        assert_ne!(original.observation_id, changed_operation.observation_id);
        assert_ne!(original.observation_id, changed_result.observation_id);
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
        assert_ne!(first.observation_id, second.observation_id);
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
