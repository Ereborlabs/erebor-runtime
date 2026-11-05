use std::collections::BTreeSet;
use erebor_interceptor_abi::{
    EffectPhysicalResultV1, KernelEffectFamilyV1, KernelEffectOperationV1,
};

use crate::values::*;

impl Observation {
    pub fn exact_identity(&self) -> bool {
        self.effect.task_cookie > 0
            && self.process_instance_id.is_some()
            && self.entry_instance_id.is_some()
            && self.binding_id.is_some()
            && self.role_id.is_some()
            && self.state_id.is_some()
            && self.entry_rule_id.is_some()
    }

    pub fn complete(&self) -> bool {
        self.proof_quality.temporal_coverage == TemporalCoverageV1::Complete
    }

    pub fn network(&self) -> bool {
        self.effect.effect_family == KernelEffectFamilyV1::Network as u32
    }

    pub fn denied(&self) -> bool {
        self.effect.decision == EffectPhysicalResultV1::DeniedBeforeEffect as u32
    }

    pub fn admitted(&self) -> bool {
        self.effect.decision == EffectPhysicalResultV1::UnknownAfterPreEffect as u32
    }

    pub fn operation(&self) -> Operation {
        match self.effect.operation {
            value if value == KernelEffectOperationV1::Read as u32 => Operation::Read,
            value if value == KernelEffectOperationV1::OpenRead as u32 => Operation::OpenRead,
            value if value == KernelEffectOperationV1::MmapRead as u32 => Operation::MmapRead,
            _ => Operation::Other,
        }
    }

    pub fn physical(&self) -> Physical {
        match self.effect.decision {
            value
                if value == EffectPhysicalResultV1::DeniedBeforeEffect as u32
                    && self.effect.kernel_result < 0 =>
            {
                Physical::Prevented
            }
            value if value == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u32 => {
                Physical::PacketDropped
            }
            value if value == EffectPhysicalResultV1::TerminationQueuedBeforeUserMode as u32 => {
                Physical::TerminationQueued
            }
            _ => Physical::Unknown,
        }
    }

    pub fn resolved_effect(&self) -> GraphEffectV1 {
        GraphEffectV1 {
            evidence: self.id.clone(),
            process_instance_id: self.process_instance_id,
            entry_instance_id: self.entry_instance_id,
            binding_id: self.binding_id,
            role_id: self.role_id,
            state_id: self.state_id,
            entry_rule_id: self.entry_rule_id,
            profile_generation_ref_id: self.profile_generation_ref_id,
            original_kernel_sequence: self.original_kernel_sequence,
            effect_family: self.effect.effect_family,
            operation: self.effect.operation,
            source_decision: self.effect.decision,
            source_reason: self.effect.reason,
            configured_errno: self.effect.configured_errno,
            kernel_result: self.effect.kernel_result,
            physical_result: match self.physical() {
                Physical::Prevented => GraphPhysicalResultV1::Prevented,
                Physical::PacketDropped => GraphPhysicalResultV1::PacketDropped,
                Physical::TerminationQueued => GraphPhysicalResultV1::TerminationQueued,
                Physical::Unknown => GraphPhysicalResultV1::Unknown,
            },
            proof_quality: self.proof_quality,
        }
    }

    pub fn task_subject(&self) -> GraphSubjectKeyV1 {
        if self.effect.task_cookie > 0 {
            GraphSubjectKeyV1::native(
                &self.id.stream,
                GraphSubjectKindV1::Task,
                self.effect.task_cookie.to_be_bytes().to_vec(),
            )
        } else {
            GraphSubjectKeyV1 {
                tenant_id: self.id.stream.tenant_id,
                authority: GraphSubjectAuthorityV1::External {
                    authority_id: "unresolved-native-observation".into(),
                },
                kind: GraphSubjectKindV1::External,
                identity: self
                    .id
                    .stream
                    .key()
                    .into_iter()
                    .chain(self.id.durable_cursor.to_be_bytes())
                    .collect(),
            }
        }
    }

    pub fn same_lifetime(&self, other: &Self) -> bool {
        self.id.stream.node_id == other.id.stream.node_id
            && self.id.stream.node_boot_id == other.id.stream.node_boot_id
            && self.id.stream.label_epoch == other.id.stream.label_epoch
    }

    pub fn same_task(&self, other: &Self) -> bool {
        if self.effect.task_cookie > 0 && other.effect.task_cookie > 0 {
            self.effect.task_cookie == other.effect.task_cookie
        } else {
            self.process_instance_id.is_some()
                && self.process_instance_id == other.process_instance_id
        }
    }
}

impl Observation {
    pub fn policies<'a>(
        &self,
        facts: impl Iterator<Item = &'a Fact>,
    ) -> Vec<PolicyObservationProvenanceV1> {
        let generation = self.profile_generation_ref_id.unwrap_or_default();
        let policies: Vec<_> = facts
            .filter_map(|fact| match &fact.value {
                FactValue::Policy(policy) if policy.profile_generation_ref_id == generation => {
                    Some(policy.clone())
                }
                _ => None,
            })
            .collect();
        let exact: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    policy.policy_source_revision_id.clone(),
                    policy.candidate_content_id.clone(),
                    policy.target_snapshot_digest.clone(),
                )
            })
            .collect();
        policies
            .into_iter()
            .filter(|policy| {
                policy.state != PolicyProvenanceStateV1::Missing
                    || !exact.contains(&(
                        policy.policy_source_revision_id.clone(),
                        policy.candidate_content_id.clone(),
                        policy.target_snapshot_digest.clone(),
                    ))
            })
            .collect()
    }
}
