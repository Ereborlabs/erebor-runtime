use std::mem::size_of;

use super::*;
use crate::graph::Progress;

fn strings(values: &Vec<String>) -> usize {
    values
        .capacity()
        .saturating_mul(size_of::<String>())
        .saturating_add(values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value.capacity())
        }))
}

fn records(values: &Vec<DiscoveryRecordIdV1>) -> usize {
    values
        .capacity()
        .saturating_mul(size_of::<DiscoveryRecordIdV1>())
        .saturating_add(values.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(value.allocated_bytes())
        }))
}

fn optional(value: &Option<String>) -> usize {
    value.as_ref().map_or(0, String::capacity)
}

impl DiscoveryRecordIdV1 {
    pub fn allocated_bytes(&self) -> usize {
        self.stream.node_id.capacity()
    }
}

impl GraphSubjectKeyV1 {
    pub fn allocated_bytes(&self) -> usize {
        let authority = match &self.authority {
            GraphSubjectAuthorityV1::Native { node_id, .. } => node_id.capacity(),
            GraphSubjectAuthorityV1::Provider { authority_id }
            | GraphSubjectAuthorityV1::External { authority_id } => authority_id.capacity(),
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => cluster_id.capacity(),
        };
        authority.saturating_add(self.identity.capacity())
    }
}

impl AnalysisContextKeyV1 {
    fn allocated_bytes(&self) -> usize {
        self.owner_id
            .capacity()
            .saturating_add(self.entity_key.capacity())
            .saturating_add(self.lifetime_key.capacity())
    }
}

impl PolicyObservationProvenanceV1 {
    fn allocated_bytes(&self) -> usize {
        self.source
            .node_id
            .capacity()
            .saturating_add(records(&self.observations))
            .saturating_add(optional(&self.policy_source_revision_id))
            .saturating_add(optional(&self.candidate_content_id))
            .saturating_add(optional(&self.target_snapshot_digest))
            .saturating_add(optional(&self.node_bound_generation_digest))
            .saturating_add(
                self.activation_acknowledgement
                    .as_ref()
                    .map_or(0, AnalysisContextKeyV1::allocated_bytes),
            )
            .saturating_add(strings(&self.limits))
    }
}

impl GraphReadCompletionV1 {
    fn allocated_bytes(&self) -> usize {
        self.admission_record
            .allocated_bytes()
            .saturating_add(self.owner.capacity())
            .saturating_add(self.completion_id.capacity())
            .saturating_add(self.file_description_id.capacity())
            .saturating_add(optional(&self.credential_lease_id))
            .saturating_add(optional(&self.principal_id))
    }
}

impl GraphFactValueV1 {
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Policy(value) => value.allocated_bytes(),
            Self::Activation(value) => value
                .tenant_id
                .capacity()
                .saturating_add(value.node_id.capacity())
                .saturating_add(value.node_boot_id.capacity())
                .saturating_add(value.candidate_content_id.capacity())
                .saturating_add(value.policy_source_revision_id.capacity())
                .saturating_add(value.target_snapshot_digest.capacity())
                .saturating_add(value.state.capacity())
                .saturating_add(optional(&value.node_bound_generation_digest))
                .saturating_add(optional(&value.readback_digest))
                .saturating_add(optional(&value.probe_result_digest))
                .saturating_add(optional(&value.reason_code)),
            Self::Context {
                subject, action_id, ..
            } => subject
                .allocated_bytes()
                .saturating_add(action_id.capacity()),
            Self::Credential {
                reviewed_policy_revision,
                completion,
                principal_id,
                ..
            } => reviewed_policy_revision
                .capacity()
                .saturating_add(
                    completion
                        .as_ref()
                        .map_or(0, GraphReadCompletionV1::allocated_bytes),
                )
                .saturating_add(optional(principal_id)),
            Self::Baseline {
                reviewed_policy_revision,
                ..
            } => reviewed_policy_revision.capacity(),
            Self::NativeParent { parent, child, .. } => parent
                .allocated_bytes()
                .saturating_add(child.allocated_bytes()),
            Self::AuthorityUse {
                authority_id,
                request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                workload_binding,
                ..
            } => authority_id
                .capacity()
                .saturating_add(optional(request_id))
                .saturating_add(optional(credential_lease_id))
                .saturating_add(principal_id.capacity())
                .saturating_add(operation_id.capacity())
                .saturating_add(
                    workload_binding
                        .as_ref()
                        .map_or(0, GraphSubjectKeyV1::allocated_bytes),
                ),
            Self::Channel {
                authority_id,
                carried_request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                ..
            } => authority_id
                .capacity()
                .saturating_add(carried_request_id.capacity())
                .saturating_add(credential_lease_id.capacity())
                .saturating_add(principal_id.capacity())
                .saturating_add(operation_id.capacity()),
            Self::Kubernetes(value) => value
                .cluster_id
                .capacity()
                .saturating_add(optional(&value.carried_request_id))
                .saturating_add(optional(&value.audit_id))
                .saturating_add(optional(&value.object_uid))
                .saturating_add(optional(&value.resource_version))
                .saturating_add(optional(&value.owner_uid))
                .saturating_add(optional(&value.pod_uid))
                .saturating_add(optional(&value.node_id))
                .saturating_add(optional(&value.full_container_id))
                .saturating_add(optional(&value.remote_admission_id)),
        }
    }
}

impl FactAnchor {
    fn allocated_bytes(&self) -> usize {
        self.record
            .allocated_bytes()
            .saturating_add(self.key.allocated_bytes())
            .saturating_add(self.value.allocated_bytes())
    }
}

impl Anchor {
    fn allocated_bytes(&self) -> usize {
        self.record
            .allocated_bytes()
            .saturating_add(self.fact.as_ref().map_or(0, FactAnchor::allocated_bytes))
    }
}

impl SubjectChange {
    pub fn allocated_bytes(&self) -> usize {
        self.anchor
            .allocated_bytes()
            .saturating_add(self.key.allocated_bytes())
    }
}

impl RelationshipIdentity {
    pub fn allocated_bytes(&self) -> usize {
        self.from
            .allocated_bytes()
            .saturating_add(self.to.allocated_bytes())
            .saturating_add(self.package_id.capacity())
            .saturating_add(records(&self.evidence))
    }
}

impl RelationshipChange {
    pub fn allocated_bytes(&self) -> usize {
        self.anchor
            .allocated_bytes()
            .saturating_add(self.key.allocated_bytes())
            .saturating_add(
                self.required_coverage_interval_ids
                    .capacity()
                    .saturating_mul(size_of::<[u8; 16]>()),
            )
    }
}

impl FindingReasonV1 {
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Declared(value) => value
                .code
                .capacity()
                .saturating_add(araphor_analysis_sdk::schema_allocated_bytes(&value.schema))
                .saturating_add(value.ipc.capacity()),
            _ => 0,
        }
    }
}

impl FindingChange {
    pub fn allocated_bytes(&self) -> usize {
        let policies = self
            .policy_provenance
            .capacity()
            .saturating_mul(size_of::<PolicyObservationProvenanceV1>())
            .saturating_add(self.policy_provenance.iter().fold(0usize, |bytes, value| {
                bytes.saturating_add(value.allocated_bytes())
            }));
        let effects = self
            .effects
            .capacity()
            .saturating_mul(size_of::<GraphEffectV1>())
            .saturating_add(self.effects.iter().fold(0usize, |bytes, value| {
                bytes.saturating_add(value.evidence.allocated_bytes())
            }));
        self.anchor
            .allocated_bytes()
            .saturating_add(
                self.prior_reason
                    .as_ref()
                    .map_or(0, FindingReasonV1::allocated_bytes),
            )
            .saturating_add(self.finding_id.capacity())
            .saturating_add(self.package_id.capacity())
            .saturating_add(self.subject_id.allocated_bytes())
            .saturating_add(records(&self.evidence))
            .saturating_add(
                self.required_coverage_interval_ids
                    .capacity()
                    .saturating_mul(size_of::<[u8; 16]>()),
            )
            .saturating_add(policies)
            .saturating_add(effects)
            .saturating_add(self.reason_code.capacity())
            .saturating_add(optional(&self.required_action))
            .saturating_add(strings(&self.limits))
    }
}

impl Progress {
    pub fn allocated_bytes(&self) -> usize {
        self.record
            .allocated_bytes()
            .saturating_add(self.digest.capacity())
            .saturating_add(optional(&self.state))
    }
}
