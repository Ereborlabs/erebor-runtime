use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::super::*;
use super::invalid;
use super::variants::{AuthorityRow, FactValueRow};
use crate::discovery;
use araphor_analysis_sdk as sdk;

pub(super) fn id(value: ByteBuf) -> sdk::Result<[u8; 16]> {
    value
        .into_vec()
        .try_into()
        .map_err(|_| invalid("graph native identity bytes"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProofRow {
    pub source_authority: u8,
    pub local_subject_binding: u8,
    pub remote_subject_binding: u8,
    pub operation_result_authority: u8,
    pub temporal_coverage: u8,
    pub integrity: u8,
}
impl From<&ProofQualityV1> for ProofRow {
    fn from(v: &ProofQualityV1) -> Self {
        Self {
            source_authority: v.source_authority as u8,
            local_subject_binding: v.local_subject_binding as u8,
            remote_subject_binding: v.remote_subject_binding as u8,
            operation_result_authority: v.operation_result_authority as u8,
            temporal_coverage: v.temporal_coverage as u8,
            integrity: v.integrity as u8,
        }
    }
}
impl TryFrom<ProofRow> for ProofQualityV1 {
    type Error = sdk::Error;
    fn try_from(v: ProofRow) -> sdk::Result<Self> {
        Ok(Self {
            source_authority: serde::Deserialize::deserialize(serde::de::value::U32Deserializer::<
                serde::de::value::Error,
            >::new(
                v.source_authority as u32
            ))
            .map_err(|_| invalid("graph native proof"))?,
            local_subject_binding: serde::Deserialize::deserialize(
                serde::de::value::U32Deserializer::<serde::de::value::Error>::new(
                    v.local_subject_binding as u32,
                ),
            )
            .map_err(|_| invalid("graph native proof"))?,
            remote_subject_binding: serde::Deserialize::deserialize(
                serde::de::value::U32Deserializer::<serde::de::value::Error>::new(
                    v.remote_subject_binding as u32,
                ),
            )
            .map_err(|_| invalid("graph native proof"))?,
            operation_result_authority: serde::Deserialize::deserialize(
                serde::de::value::U32Deserializer::<serde::de::value::Error>::new(
                    v.operation_result_authority as u32,
                ),
            )
            .map_err(|_| invalid("graph native proof"))?,
            temporal_coverage: serde::Deserialize::deserialize(
                serde::de::value::U32Deserializer::<serde::de::value::Error>::new(
                    v.temporal_coverage as u32,
                ),
            )
            .map_err(|_| invalid("graph native proof"))?,
            integrity: serde::Deserialize::deserialize(serde::de::value::U32Deserializer::<
                serde::de::value::Error,
            >::new(v.integrity as u32))
            .map_err(|_| invalid("graph native proof"))?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceRow {
    pub tenant_id: ByteBuf,
    pub node_id: String,
    pub node_boot_id: ByteBuf,
    pub label_epoch: u64,
    pub source_id: ByteBuf,
    pub source_epoch: u64,
}
impl From<&discovery::EvidenceIntakeIdentityV1> for SourceRow {
    fn from(v: &discovery::EvidenceIntakeIdentityV1) -> Self {
        Self {
            tenant_id: ByteBuf::from(v.tenant_id.to_vec()),
            node_id: v.node_id.clone(),
            node_boot_id: ByteBuf::from(v.node_boot_id.to_vec()),
            label_epoch: v.label_epoch,
            source_id: ByteBuf::from(v.source_id.to_vec()),
            source_epoch: v.source_epoch,
        }
    }
}
impl TryFrom<SourceRow> for discovery::EvidenceIntakeIdentityV1 {
    type Error = sdk::Error;
    fn try_from(v: SourceRow) -> sdk::Result<Self> {
        Ok(Self {
            tenant_id: id(v.tenant_id)?,
            node_id: v.node_id,
            node_boot_id: id(v.node_boot_id)?,
            label_epoch: v.label_epoch,
            source_id: id(v.source_id)?,
            source_epoch: v.source_epoch,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordIdRow {
    pub stream: SourceRow,
    pub cpu_id: u32,
    pub durable_cursor: u64,
}
impl From<&discovery::DiscoveryRecordIdV1> for RecordIdRow {
    fn from(v: &discovery::DiscoveryRecordIdV1) -> Self {
        Self {
            stream: SourceRow::from(&v.stream),
            cpu_id: v.cpu_id,
            durable_cursor: v.durable_cursor,
        }
    }
}
impl TryFrom<RecordIdRow> for discovery::DiscoveryRecordIdV1 {
    type Error = sdk::Error;
    fn try_from(v: RecordIdRow) -> sdk::Result<Self> {
        Ok(Self {
            stream: v.stream.try_into()?,
            cpu_id: v.cpu_id,
            durable_cursor: v.durable_cursor,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextKeyRow {
    pub tenant_id: ByteBuf,
    pub owner_id: String,
    pub entity_key: ByteBuf,
    pub lifetime_key: ByteBuf,
    pub owner_revision: u64,
}
impl From<&AnalysisContextKeyV1> for ContextKeyRow {
    fn from(v: &AnalysisContextKeyV1) -> Self {
        Self {
            tenant_id: ByteBuf::from(v.tenant_id.to_vec()),
            owner_id: v.owner_id.clone(),
            entity_key: ByteBuf::from(v.entity_key.clone()),
            lifetime_key: ByteBuf::from(v.lifetime_key.clone()),
            owner_revision: v.owner_revision,
        }
    }
}
impl TryFrom<ContextKeyRow> for AnalysisContextKeyV1 {
    type Error = sdk::Error;
    fn try_from(v: ContextKeyRow) -> sdk::Result<Self> {
        Ok(Self {
            tenant_id: id(v.tenant_id)?,
            owner_id: v.owner_id,
            entity_key: v.entity_key.into_vec(),
            lifetime_key: v.lifetime_key.into_vec(),
            owner_revision: v.owner_revision,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubjectKeyRow {
    pub tenant_id: ByteBuf,
    pub authority: AuthorityRow,
    pub kind: GraphSubjectKindV1,
    pub identity: ByteBuf,
}
impl From<&GraphSubjectKeyV1> for SubjectKeyRow {
    fn from(v: &GraphSubjectKeyV1) -> Self {
        Self {
            tenant_id: ByteBuf::from(v.tenant_id.to_vec()),
            authority: AuthorityRow::from(&v.authority),
            kind: v.kind,
            identity: ByteBuf::from(v.identity.clone()),
        }
    }
}
impl TryFrom<SubjectKeyRow> for GraphSubjectKeyV1 {
    type Error = sdk::Error;
    fn try_from(v: SubjectKeyRow) -> sdk::Result<Self> {
        Ok(Self {
            tenant_id: id(v.tenant_id)?,
            authority: v.authority.try_into()?,
            kind: v.kind,
            identity: v.identity.into_vec(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyRow {
    pub source: SourceRow,
    pub profile_generation_ref_id: u64,
    pub observations: Vec<RecordIdRow>,
    pub policy_source_revision_id: Option<String>,
    pub candidate_content_id: Option<String>,
    pub target_snapshot_digest: Option<String>,
    pub node_bound_generation_digest: Option<String>,
    pub activation_acknowledgement: Option<ContextKeyRow>,
    pub state: PolicyProvenanceStateV1,
    pub limits: Vec<String>,
}
impl From<&PolicyObservationProvenanceV1> for PolicyRow {
    fn from(v: &PolicyObservationProvenanceV1) -> Self {
        Self {
            source: SourceRow::from(&v.source),
            profile_generation_ref_id: v.profile_generation_ref_id,
            observations: v.observations.iter().map(RecordIdRow::from).collect(),
            policy_source_revision_id: v.policy_source_revision_id.clone(),
            candidate_content_id: v.candidate_content_id.clone(),
            target_snapshot_digest: v.target_snapshot_digest.clone(),
            node_bound_generation_digest: v.node_bound_generation_digest.clone(),
            activation_acknowledgement: v
                .activation_acknowledgement
                .as_ref()
                .map(ContextKeyRow::from),
            state: v.state,
            limits: v.limits.clone(),
        }
    }
}
impl TryFrom<PolicyRow> for PolicyObservationProvenanceV1 {
    type Error = sdk::Error;
    fn try_from(v: PolicyRow) -> sdk::Result<Self> {
        Ok(Self {
            source: v.source.try_into()?,
            profile_generation_ref_id: v.profile_generation_ref_id,
            observations: v
                .observations
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            policy_source_revision_id: v.policy_source_revision_id,
            candidate_content_id: v.candidate_content_id,
            target_snapshot_digest: v.target_snapshot_digest,
            node_bound_generation_digest: v.node_bound_generation_digest,
            activation_acknowledgement: v
                .activation_acknowledgement
                .map(TryInto::try_into)
                .transpose()?,
            state: v.state,
            limits: v.limits,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletionRow {
    pub admission_record: RecordIdRow,
    pub owner: String,
    pub completion_id: String,
    pub task_cookie: u64,
    pub process_instance_id: ByteBuf,
    pub object_id: ByteBuf,
    pub file_description_id: String,
    pub path: GraphReadPathV1,
    pub result: i64,
    pub byte_count: u64,
    pub credential_lease_id: Option<String>,
    pub principal_id: Option<String>,
}
impl From<&GraphReadCompletionV1> for CompletionRow {
    fn from(v: &GraphReadCompletionV1) -> Self {
        Self {
            admission_record: RecordIdRow::from(&v.admission_record),
            owner: v.owner.clone(),
            completion_id: v.completion_id.clone(),
            task_cookie: v.task_cookie,
            process_instance_id: ByteBuf::from(v.process_instance_id.to_vec()),
            object_id: ByteBuf::from(v.object_id.to_vec()),
            file_description_id: v.file_description_id.clone(),
            path: v.path,
            result: v.result,
            byte_count: v.byte_count,
            credential_lease_id: v.credential_lease_id.clone(),
            principal_id: v.principal_id.clone(),
        }
    }
}
impl TryFrom<CompletionRow> for GraphReadCompletionV1 {
    type Error = sdk::Error;
    fn try_from(v: CompletionRow) -> sdk::Result<Self> {
        Ok(Self {
            admission_record: v.admission_record.try_into()?,
            owner: v.owner,
            completion_id: v.completion_id,
            task_cookie: v.task_cookie,
            process_instance_id: id(v.process_instance_id)?,
            object_id: id(v.object_id)?,
            file_description_id: v.file_description_id,
            path: v.path,
            result: v.result,
            byte_count: v.byte_count,
            credential_lease_id: v.credential_lease_id,
            principal_id: v.principal_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KubernetesRow {
    pub cluster_id: String,
    pub carried_request_id: Option<String>,
    pub audit_id: Option<String>,
    pub object_uid: Option<String>,
    pub resource_version: Option<String>,
    pub owner_uid: Option<String>,
    pub pod_uid: Option<String>,
    pub node_id: Option<String>,
    pub full_container_id: Option<String>,
    pub remote_admission_id: Option<String>,
    pub proof_quality: ProofRow,
}
impl From<&KubernetesStageProofV1> for KubernetesRow {
    fn from(v: &KubernetesStageProofV1) -> Self {
        Self {
            cluster_id: v.cluster_id.clone(),
            carried_request_id: v.carried_request_id.clone(),
            audit_id: v.audit_id.clone(),
            object_uid: v.object_uid.clone(),
            resource_version: v.resource_version.clone(),
            owner_uid: v.owner_uid.clone(),
            pod_uid: v.pod_uid.clone(),
            node_id: v.node_id.clone(),
            full_container_id: v.full_container_id.clone(),
            remote_admission_id: v.remote_admission_id.clone(),
            proof_quality: ProofRow::from(&v.proof_quality),
        }
    }
}
impl TryFrom<KubernetesRow> for KubernetesStageProofV1 {
    type Error = sdk::Error;
    fn try_from(v: KubernetesRow) -> sdk::Result<Self> {
        Ok(Self {
            cluster_id: v.cluster_id,
            carried_request_id: v.carried_request_id,
            audit_id: v.audit_id,
            object_uid: v.object_uid,
            resource_version: v.resource_version,
            owner_uid: v.owner_uid,
            pod_uid: v.pod_uid,
            node_id: v.node_id,
            full_container_id: v.full_container_id,
            remote_admission_id: v.remote_admission_id,
            proof_quality: v.proof_quality.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationRow {
    pub tenant_id: String,
    pub node_id: String,
    pub node_boot_id: ByteBuf,
    pub label_epoch: u64,
    pub candidate_content_id: String,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub state: String,
    pub node_bound_generation_digest: Option<String>,
    pub profile_generation_ref_id: Option<u64>,
    pub readback_digest: Option<String>,
    pub probe_result_digest: Option<String>,
    pub reason_code: Option<String>,
    pub observed_utc_ns: i64,
}
impl From<&GraphPolicyActivationV1> for ActivationRow {
    fn from(v: &GraphPolicyActivationV1) -> Self {
        Self {
            tenant_id: v.tenant_id.clone(),
            node_id: v.node_id.clone(),
            node_boot_id: ByteBuf::from(v.node_boot_id.clone()),
            label_epoch: v.label_epoch,
            candidate_content_id: v.candidate_content_id.clone(),
            policy_source_revision_id: v.policy_source_revision_id.clone(),
            target_snapshot_digest: v.target_snapshot_digest.clone(),
            state: v.state.clone(),
            node_bound_generation_digest: v.node_bound_generation_digest.clone(),
            profile_generation_ref_id: v.profile_generation_ref_id,
            readback_digest: v.readback_digest.clone(),
            probe_result_digest: v.probe_result_digest.clone(),
            reason_code: v.reason_code.clone(),
            observed_utc_ns: v.observed_utc_ns,
        }
    }
}
impl TryFrom<ActivationRow> for GraphPolicyActivationV1 {
    type Error = sdk::Error;
    fn try_from(v: ActivationRow) -> sdk::Result<Self> {
        Ok(Self {
            tenant_id: v.tenant_id,
            node_id: v.node_id,
            node_boot_id: v.node_boot_id.into_vec(),
            label_epoch: v.label_epoch,
            candidate_content_id: v.candidate_content_id,
            policy_source_revision_id: v.policy_source_revision_id,
            target_snapshot_digest: v.target_snapshot_digest,
            state: v.state,
            node_bound_generation_digest: v.node_bound_generation_digest,
            profile_generation_ref_id: v.profile_generation_ref_id,
            readback_digest: v.readback_digest,
            probe_result_digest: v.probe_result_digest,
            reason_code: v.reason_code,
            observed_utc_ns: v.observed_utc_ns,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EffectRow {
    pub evidence: RecordIdRow,
    pub process_instance_id: Option<ByteBuf>,
    pub entry_instance_id: Option<ByteBuf>,
    pub binding_id: Option<ByteBuf>,
    pub role_id: Option<u32>,
    pub state_id: Option<u32>,
    pub entry_rule_id: Option<u32>,
    pub profile_generation_ref_id: Option<u64>,
    pub original_kernel_sequence: Option<u64>,
    pub effect_family: u32,
    pub operation: u32,
    pub source_decision: u32,
    pub source_reason: u32,
    pub configured_errno: i32,
    pub kernel_result: i32,
    pub physical_result: GraphPhysicalResultV1,
    pub proof_quality: ProofRow,
}
impl From<&GraphEffectV1> for EffectRow {
    fn from(v: &GraphEffectV1) -> Self {
        Self {
            evidence: RecordIdRow::from(&v.evidence),
            process_instance_id: v
                .process_instance_id
                .map(|value| ByteBuf::from(value.to_vec())),
            entry_instance_id: v
                .entry_instance_id
                .map(|value| ByteBuf::from(value.to_vec())),
            binding_id: v.binding_id.map(|value| ByteBuf::from(value.to_vec())),
            role_id: v.role_id,
            state_id: v.state_id,
            entry_rule_id: v.entry_rule_id,
            profile_generation_ref_id: v.profile_generation_ref_id,
            original_kernel_sequence: v.original_kernel_sequence,
            effect_family: v.effect_family,
            operation: v.operation,
            source_decision: v.source_decision,
            source_reason: v.source_reason,
            configured_errno: v.configured_errno,
            kernel_result: v.kernel_result,
            physical_result: v.physical_result,
            proof_quality: ProofRow::from(&v.proof_quality),
        }
    }
}
impl TryFrom<EffectRow> for GraphEffectV1 {
    type Error = sdk::Error;
    fn try_from(v: EffectRow) -> sdk::Result<Self> {
        Ok(Self {
            evidence: v.evidence.try_into()?,
            process_instance_id: v.process_instance_id.map(id).transpose()?,
            entry_instance_id: v.entry_instance_id.map(id).transpose()?,
            binding_id: v.binding_id.map(id).transpose()?,
            role_id: v.role_id,
            state_id: v.state_id,
            entry_rule_id: v.entry_rule_id,
            profile_generation_ref_id: v.profile_generation_ref_id,
            original_kernel_sequence: v.original_kernel_sequence,
            effect_family: v.effect_family,
            operation: v.operation,
            source_decision: v.source_decision,
            source_reason: v.source_reason,
            configured_errno: v.configured_errno,
            kernel_result: v.kernel_result,
            physical_result: v.physical_result,
            proof_quality: v.proof_quality.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EdgeRow {
    pub key: GraphEdgeKeyV1,
    pub proof_quality: ProofRow,
    pub required_coverage_interval_ids: Vec<ByteBuf>,
    pub first_boottime_ns: u64,
    pub last_boottime_ns: u64,
}
impl From<&GraphEdgeV1> for EdgeRow {
    fn from(v: &GraphEdgeV1) -> Self {
        Self {
            key: v.key.clone(),
            proof_quality: ProofRow::from(&v.proof_quality),
            required_coverage_interval_ids: v
                .required_coverage_interval_ids
                .iter()
                .map(|value| ByteBuf::from(value.to_vec()))
                .collect(),
            first_boottime_ns: v.first_boottime_ns,
            last_boottime_ns: v.last_boottime_ns,
        }
    }
}
impl TryFrom<EdgeRow> for GraphEdgeV1 {
    type Error = sdk::Error;
    fn try_from(v: EdgeRow) -> sdk::Result<Self> {
        Ok(Self {
            key: v.key,
            proof_quality: v.proof_quality.try_into()?,
            required_coverage_interval_ids: v
                .required_coverage_interval_ids
                .into_iter()
                .map(id)
                .collect::<sdk::Result<_>>()?,
            first_boottime_ns: v.first_boottime_ns,
            last_boottime_ns: v.last_boottime_ns,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateRow {
    tag: String,
    declared: Option<String>,
}
impl From<&GraphPackageStateV1> for StateRow {
    fn from(value: &GraphPackageStateV1) -> Self {
        let tag = match value {
            GraphPackageStateV1::Waiting => "WAITING",
            GraphPackageStateV1::NativeEffect => "NATIVE_EFFECT",
            GraphPackageStateV1::CredentialObserved => "CREDENTIAL_OBSERVED",
            GraphPackageStateV1::AuthorityChannel => "AUTHORITY_CHANNEL",
            GraphPackageStateV1::DirectPivot => "DIRECT_PIVOT",
            GraphPackageStateV1::ContextualPivot => "CONTEXTUAL_PIVOT",
            GraphPackageStateV1::Contradicted => "CONTRADICTED",
            GraphPackageStateV1::CoverageInsufficient => "COVERAGE_INSUFFICIENT",
            GraphPackageStateV1::KubernetesProofMissing => "KUBERNETES_PROOF_MISSING",
            GraphPackageStateV1::KubernetesRequest => "KUBERNETES_REQUEST",
            GraphPackageStateV1::KubernetesAudit => "KUBERNETES_AUDIT",
            GraphPackageStateV1::KubernetesObject => "KUBERNETES_OBJECT",
            GraphPackageStateV1::KubernetesScheduled => "KUBERNETES_SCHEDULED",
            GraphPackageStateV1::RemoteAdmission => "REMOTE_ADMISSION",
            GraphPackageStateV1::Declared(_) => "DECLARED",
        };
        Self {
            tag: tag.into(),
            declared: if let GraphPackageStateV1::Declared(value) = value {
                Some(value.clone())
            } else {
                None
            },
        }
    }
}
impl TryFrom<StateRow> for GraphPackageStateV1 {
    type Error = sdk::Error;
    fn try_from(value: StateRow) -> sdk::Result<Self> {
        if value.tag == "DECLARED" {
            return value
                .declared
                .map(Self::Declared)
                .ok_or_else(|| invalid("graph native package state"));
        }
        if value.declared.is_some() {
            return Err(invalid("graph native package state"));
        }
        match value.tag.as_str() {
            "WAITING" => Ok(Self::Waiting),
            "NATIVE_EFFECT" => Ok(Self::NativeEffect),
            "CREDENTIAL_OBSERVED" => Ok(Self::CredentialObserved),
            "AUTHORITY_CHANNEL" => Ok(Self::AuthorityChannel),
            "DIRECT_PIVOT" => Ok(Self::DirectPivot),
            "CONTEXTUAL_PIVOT" => Ok(Self::ContextualPivot),
            "CONTRADICTED" => Ok(Self::Contradicted),
            "COVERAGE_INSUFFICIENT" => Ok(Self::CoverageInsufficient),
            "KUBERNETES_PROOF_MISSING" => Ok(Self::KubernetesProofMissing),
            "KUBERNETES_REQUEST" => Ok(Self::KubernetesRequest),
            "KUBERNETES_AUDIT" => Ok(Self::KubernetesAudit),
            "KUBERNETES_OBJECT" => Ok(Self::KubernetesObject),
            "KUBERNETES_SCHEDULED" => Ok(Self::KubernetesScheduled),
            "REMOTE_ADMISSION" => Ok(Self::RemoteAdmission),
            _ => Err(invalid("graph native package state")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageRow {
    pub package_id: String,
    pub package_version: u64,
    pub required_inputs: Vec<String>,
    pub state: StateRow,
    pub maximum_lateness_ns: u64,
    pub retention_ttl_ns: u64,
    pub clock_uncertainty_ns: Option<u64>,
    pub late_action: String,
    pub window_ns: u64,
    pub coverage_predicate: String,
    pub replay_contract_id: String,
    pub result_states: Vec<FindingStateV1>,
    pub accepted_cursor_watermark: u64,
    pub observed_boottime_watermark_ns: u64,
}
impl From<&GraphPackageCheckpointV1> for PackageRow {
    fn from(v: &GraphPackageCheckpointV1) -> Self {
        Self {
            package_id: v.package_id.clone(),
            package_version: v.package_version,
            required_inputs: v.required_inputs.clone(),
            state: StateRow::from(&v.state),
            maximum_lateness_ns: v.maximum_lateness_ns,
            retention_ttl_ns: v.retention_ttl_ns,
            clock_uncertainty_ns: v.clock_uncertainty_ns,
            late_action: v.late_action.clone(),
            window_ns: v.window_ns,
            coverage_predicate: v.coverage_predicate.clone(),
            replay_contract_id: v.replay_contract_id.clone(),
            result_states: v.result_states.clone(),
            accepted_cursor_watermark: v.accepted_cursor_watermark,
            observed_boottime_watermark_ns: v.observed_boottime_watermark_ns,
        }
    }
}
impl TryFrom<PackageRow> for GraphPackageCheckpointV1 {
    type Error = sdk::Error;
    fn try_from(v: PackageRow) -> sdk::Result<Self> {
        Ok(Self {
            package_id: v.package_id,
            package_version: v.package_version,
            required_inputs: v.required_inputs,
            state: v.state.try_into()?,
            maximum_lateness_ns: v.maximum_lateness_ns,
            retention_ttl_ns: v.retention_ttl_ns,
            clock_uncertainty_ns: v.clock_uncertainty_ns,
            late_action: v.late_action,
            window_ns: v.window_ns,
            coverage_predicate: v.coverage_predicate,
            replay_contract_id: v.replay_contract_id,
            result_states: v.result_states,
            accepted_cursor_watermark: v.accepted_cursor_watermark,
            observed_boottime_watermark_ns: v.observed_boottime_watermark_ns,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObservationRow {
    pub id: RecordIdRow,
    pub effect: discovery::DiscoveryEffectKeyV1,
    pub ingested_utc_ns: i64,
    pub observed_boottime_ns: u64,
    pub profile_generation_ref_id: Option<u64>,
    pub original_kernel_sequence: Option<u64>,
    pub coverage_interval_id: ByteBuf,
    pub process_instance_id: Option<ByteBuf>,
    pub entry_instance_id: Option<ByteBuf>,
    pub binding_id: Option<ByteBuf>,
    pub role_id: Option<u32>,
    pub state_id: Option<u32>,
    pub entry_rule_id: Option<u32>,
    pub proof_quality: ProofRow,
}
impl From<&Observation> for ObservationRow {
    fn from(v: &Observation) -> Self {
        Self {
            id: RecordIdRow::from(&v.id),
            effect: v.effect.clone(),
            ingested_utc_ns: v.ingested_utc_ns,
            observed_boottime_ns: v.observed_boottime_ns,
            profile_generation_ref_id: v.profile_generation_ref_id,
            original_kernel_sequence: v.original_kernel_sequence,
            coverage_interval_id: ByteBuf::from(v.coverage_interval_id.clone()),
            process_instance_id: v
                .process_instance_id
                .map(|value| ByteBuf::from(value.to_vec())),
            entry_instance_id: v
                .entry_instance_id
                .map(|value| ByteBuf::from(value.to_vec())),
            binding_id: v.binding_id.map(|value| ByteBuf::from(value.to_vec())),
            role_id: v.role_id,
            state_id: v.state_id,
            entry_rule_id: v.entry_rule_id,
            proof_quality: ProofRow::from(&v.proof_quality),
        }
    }
}
impl TryFrom<ObservationRow> for Observation {
    type Error = sdk::Error;
    fn try_from(v: ObservationRow) -> sdk::Result<Self> {
        Ok(Self {
            id: v.id.try_into()?,
            effect: v.effect,
            ingested_utc_ns: v.ingested_utc_ns,
            observed_boottime_ns: v.observed_boottime_ns,
            profile_generation_ref_id: v.profile_generation_ref_id,
            original_kernel_sequence: v.original_kernel_sequence,
            coverage_interval_id: v.coverage_interval_id.into_vec(),
            process_instance_id: v.process_instance_id.map(id).transpose()?,
            entry_instance_id: v.entry_instance_id.map(id).transpose()?,
            binding_id: v.binding_id.map(id).transpose()?,
            role_id: v.role_id,
            state_id: v.state_id,
            entry_rule_id: v.entry_rule_id,
            proof_quality: v.proof_quality.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FactRow {
    pub record: u32,
    pub key: ContextKeyRow,
    pub sensitivity: ContextSensitivityV1,
    pub value: FactValueRow,
}
impl From<&Fact> for FactRow {
    fn from(v: &Fact) -> Self {
        Self {
            record: v.record,
            key: ContextKeyRow::from(&v.key),
            sensitivity: v.sensitivity,
            value: FactValueRow::from(&v.value),
        }
    }
}
impl TryFrom<FactRow> for Fact {
    type Error = sdk::Error;
    fn try_from(v: FactRow) -> sdk::Result<Self> {
        Ok(Self {
            record: v.record,
            key: v.key.try_into()?,
            sensitivity: v.sensitivity,
            value: v.value.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MetadataRow {
    pub record_ids: Vec<RecordIdRow>,
    pub facts: Vec<FactRow>,
    pub package: PackageRow,
}
impl From<&Metadata> for MetadataRow {
    fn from(v: &Metadata) -> Self {
        Self {
            record_ids: v.record_ids.iter().map(RecordIdRow::from).collect(),
            facts: v.facts.iter().map(FactRow::from).collect(),
            package: PackageRow::from(&v.package),
        }
    }
}
impl TryFrom<MetadataRow> for Metadata {
    type Error = sdk::Error;
    fn try_from(v: MetadataRow) -> sdk::Result<Self> {
        Ok(Self {
            record_ids: v
                .record_ids
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            facts: v
                .facts
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            package: v.package.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubjectRow {
    pub record: u32,
    pub context: Option<u32>,
    pub key: SubjectKeyRow,
}
impl From<&Subject> for SubjectRow {
    fn from(v: &Subject) -> Self {
        Self {
            record: v.record,
            context: v.context,
            key: SubjectKeyRow::from(&v.key),
        }
    }
}
impl TryFrom<SubjectRow> for Subject {
    type Error = sdk::Error;
    fn try_from(v: SubjectRow) -> sdk::Result<Self> {
        Ok(Self {
            record: v.record,
            context: v.context,
            key: v.key.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelationshipRow {
    pub record: u32,
    pub fact: Option<u32>,
    pub edge: EdgeRow,
}
impl From<&Relationship> for RelationshipRow {
    fn from(v: &Relationship) -> Self {
        Self {
            record: v.record,
            fact: v.fact,
            edge: EdgeRow::from(&v.edge),
        }
    }
}
impl TryFrom<RelationshipRow> for Relationship {
    type Error = sdk::Error;
    fn try_from(v: RelationshipRow) -> sdk::Result<Self> {
        Ok(Self {
            record: v.record,
            fact: v.fact,
            edge: v.edge.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingRow {
    pub record: u32,
    pub context: Option<u32>,
    pub tenant_id: ByteBuf,
    pub finding_id: String,
    pub package_id: String,
    pub package_version: u64,
    pub subject_id: SubjectKeyRow,
    pub state: FindingStateV1,
    pub window_start_utc_ns: i64,
    pub window_end_utc_ns: i64,
    pub evidence: Vec<RecordIdRow>,
    pub required_coverage_interval_ids: Vec<ByteBuf>,
    pub policy_provenance: Vec<PolicyRow>,
    pub effects: Vec<EffectRow>,
    pub reason_code: String,
    pub severity: FindingSeverityV1,
    pub sensitivity: ContextSensitivityV1,
    pub required_action: Option<String>,
    pub limits: Vec<String>,
}
impl From<&Finding> for FindingRow {
    fn from(v: &Finding) -> Self {
        Self {
            record: v.record,
            context: v.context,
            tenant_id: ByteBuf::from(v.tenant_id.to_vec()),
            finding_id: v.finding_id.clone(),
            package_id: v.package_id.clone(),
            package_version: v.package_version,
            subject_id: SubjectKeyRow::from(&v.subject_id),
            state: v.state,
            window_start_utc_ns: v.window_start_utc_ns,
            window_end_utc_ns: v.window_end_utc_ns,
            evidence: v.evidence.iter().map(RecordIdRow::from).collect(),
            required_coverage_interval_ids: v
                .required_coverage_interval_ids
                .iter()
                .map(|value| ByteBuf::from(value.to_vec()))
                .collect(),
            policy_provenance: v.policy_provenance.iter().map(PolicyRow::from).collect(),
            effects: v.effects.iter().map(EffectRow::from).collect(),
            reason_code: v.reason_code.clone(),
            severity: v.severity,
            sensitivity: v.sensitivity,
            required_action: v.required_action.clone(),
            limits: v.limits.clone(),
        }
    }
}
impl TryFrom<FindingRow> for Finding {
    type Error = sdk::Error;
    fn try_from(v: FindingRow) -> sdk::Result<Self> {
        Ok(Self {
            record: v.record,
            context: v.context,
            tenant_id: id(v.tenant_id)?,
            finding_id: v.finding_id,
            package_id: v.package_id,
            package_version: v.package_version,
            subject_id: v.subject_id.try_into()?,
            state: v.state,
            window_start_utc_ns: v.window_start_utc_ns,
            window_end_utc_ns: v.window_end_utc_ns,
            evidence: v
                .evidence
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            required_coverage_interval_ids: v
                .required_coverage_interval_ids
                .into_iter()
                .map(id)
                .collect::<sdk::Result<_>>()?,
            policy_provenance: v
                .policy_provenance
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            effects: v
                .effects
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            reason_code: v.reason_code,
            severity: v.severity,
            sensitivity: v.sensitivity,
            required_action: v.required_action,
            limits: v.limits,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BranchRow {
    pub package_id: String,
    pub seed: SubjectKeyRow,
    pub evidence: Vec<RecordIdRow>,
    pub state: GraphBranchStateV1,
    pub missing_fields: Vec<String>,
}
impl From<&GraphBranchV1> for BranchRow {
    fn from(v: &GraphBranchV1) -> Self {
        Self {
            package_id: v.package_id.clone(),
            seed: SubjectKeyRow::from(&v.seed),
            evidence: v.evidence.iter().map(RecordIdRow::from).collect(),
            state: v.state,
            missing_fields: v.missing_fields.clone(),
        }
    }
}
impl TryFrom<BranchRow> for GraphBranchV1 {
    type Error = sdk::Error;
    fn try_from(v: BranchRow) -> sdk::Result<Self> {
        Ok(Self {
            package_id: v.package_id,
            seed: v.seed.try_into()?,
            evidence: v
                .evidence
                .into_iter()
                .map(TryInto::try_into)
                .collect::<sdk::Result<_>>()?,
            state: v.state,
            missing_fields: v.missing_fields,
        })
    }
}
