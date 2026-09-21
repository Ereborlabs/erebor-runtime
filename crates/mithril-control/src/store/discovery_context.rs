use super::*;
use crate::{
    error::DiscoverySnafu, DiscoveryContextBindingV1, DiscoveryRecordV1, EvidenceIdV1,
    WorkloadTargetFactV1,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPinnedContextV1 {
    pub binding: DiscoveryContextBindingV1,
    pub workload: WorkloadTargetFactV1,
    pub policy_source_revision_id: String,
    pub target_snapshot_digest: String,
    pub signed_profile_digest: String,
    pub control_commit_index: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextUnavailableV1 {
    MissingSourceCpu,
    ContextLimit,
    MissingDecisionCatalog,
    MissingProcessLifetime,
    MissingWorkloadFact,
    AmbiguousWorkloadFact,
    PolicyContextMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryContextJoinV1 {
    Available(Box<DiscoveryPinnedContextV1>),
    Unresolved(DiscoveryContextUnavailableV1),
}

impl ControlStore {
    pub fn discovery_context(&self, record: &DiscoveryRecordV1) -> Result<DiscoveryContextJoinV1> {
        use DiscoveryContextUnavailableV1 as Missing;
        let unresolved = DiscoveryContextJoinV1::Unresolved;
        record.observation.validate().map_err(|error| {
            DiscoverySnafu {
                code: "CONTEXT_OBSERVATION",
                reason: error.to_string(),
            }
            .build()
        })?;
        let stream = &record.id.stream;
        let observation = &record.observation;
        if stream.tenant_id != observation.tenant_id.to_be_bytes()
            || stream.node_boot_id != observation.node_boot_id.to_be_bytes()
            || stream.source_id != observation.source_id.to_be_bytes()
            || stream.source_epoch != observation.source_epoch
            || record.id.cpu_id != observation.cpu_id
            || stream.node_id.is_empty()
            || stream.node_id.len() > 256
            || stream.label_epoch == 0
            || record.id.durable_cursor == 0
        {
            return DiscoverySnafu {
                code: "CONTEXT_RECORD_IDENTITY",
                reason: "the discovery record differs from its observation identity",
            }
            .fail();
        }
        let Some(context) = &observation.decision_context else {
            return Ok(unresolved(Missing::MissingDecisionCatalog));
        };
        if record.original_kernel_sequence != Some(context.original_kernel_sequence) {
            return DiscoverySnafu {
                code: "CONTEXT_KERNEL_SEQUENCE",
                reason: "the original kernel sequence differs from the retained context",
            }
            .fail();
        }
        let Some(catalog) = context.catalog().map_err(|error| {
            DiscoverySnafu {
                code: "CONTEXT_CATALOG",
                reason: error.to_string(),
            }
            .build()
        })?
        else {
            return Ok(unresolved(Missing::MissingDecisionCatalog));
        };
        let process = <[u8; 16]>::try_from(context.process_instance_id.as_slice()).ok();
        let entry = <[u8; 16]>::try_from(context.entry_instance_id.as_slice()).ok();
        let (Some(process), Some(entry)) = (process, entry) else {
            return Ok(unresolved(Missing::MissingProcessLifetime));
        };
        if process == [0; 16] || entry == [0; 16] || context.entry_rule_id == 0 {
            return Ok(unresolved(Missing::MissingProcessLifetime));
        }
        let tenant = uuid::Uuid::from_bytes(stream.tenant_id).to_string();
        let boot = hex::encode(stream.node_boot_id);
        let binding = uuid::Uuid::from_bytes(catalog.binding_id.to_be_bytes()).to_string();
        if observation.effect.execution_set_id.is_none()
            || observation.effect.authority_domain_id.is_some_and(|id| {
                uuid::Uuid::from_bytes(id.to_be_bytes()).to_string()
                    != catalog.static_key.protected_scope_id
            })
        {
            return Ok(unresolved(Missing::PolicyContextMismatch));
        }
        let mut selected: Option<DiscoveryPinnedContextV1> = None;
        let inner = self.evidence_lock()?;
        for snapshot in inner.state.target_snapshots.values() {
            let Some(source) = inner
                .state
                .source_revisions
                .get(&snapshot.policy_source_revision_id)
            else {
                continue;
            };
            if source.tenant_id != tenant {
                continue;
            }
            let Some(artifact) = inner
                .state
                .compiled_artifacts
                .get(&snapshot.policy_source_revision_id)
            else {
                continue;
            };
            if artifact.header.profile_id != catalog.profile_id
                || artifact.header.profile_version != catalog.profile_version
                || artifact.header.policy_document_digest != catalog.policy_document_digest
            {
                continue;
            }
            for target in &snapshot.targets {
                if target.tenant_id != tenant || target.node_id != stream.node_id {
                    continue;
                }
                for workload in &target.workload_targets {
                    let Some(identity) = &workload.kubernetes else {
                        continue;
                    };
                    if workload.node_id != stream.node_id
                        || identity.node_boot_id != boot
                        || identity.label_epoch != stream.label_epoch
                        || identity.binding_id != binding
                        || identity.profile_id != catalog.profile_id
                        || identity.policy_source_revision_id != snapshot.policy_source_revision_id
                    {
                        continue;
                    }
                    if observation
                        .effect
                        .execution_set_id
                        .map(|id| uuid::Uuid::from_bytes(id.to_be_bytes()).to_string())
                        .as_ref()
                        != Some(&workload.execution_set_id)
                        || !artifact
                            .policy_document
                            .protected_universe
                            .execution_set_ids
                            .contains(&catalog.static_key.execution_set_id)
                        || identity.protected_scope_id != catalog.static_key.protected_scope_id
                        || identity.workload_selector_id != catalog.static_key.workload_selector_id
                        || !artifact
                            .compiled_profile
                            .compiled_cells
                            .iter()
                            .any(|cell| cell.key == catalog.static_key)
                    {
                        return Ok(unresolved(Missing::PolicyContextMismatch));
                    }
                    if serde_json::to_writer(
                        crate::discovery::InputByteLimit(crate::MAX_DISCOVERY_PIN_BYTES),
                        workload,
                    )
                    .is_err()
                    {
                        return Ok(unresolved(Missing::ContextLimit));
                    }
                    let next = DiscoveryPinnedContextV1 {
                        binding: DiscoveryContextBindingV1 {
                            record_id: record.id.clone(),
                            subject_revision: workload.workload_binding_generation_digest.clone(),
                            image_digest: workload.image_digest.clone(),
                            configuration_digest: catalog.policy_document_digest.clone(),
                            process_instance_id: EvidenceIdV1::from(process),
                            entry_instance_id: EvidenceIdV1::from(entry),
                            binding_id: catalog.binding_id,
                            role_id: catalog.role_id,
                            state_id: catalog.state_id,
                            entry_rule_id: catalog.entry_rule_id,
                            catalog_revision: catalog.profile_version,
                            static_key: catalog.static_key.clone(),
                        },
                        workload: workload.clone(),
                        policy_source_revision_id: snapshot.policy_source_revision_id.clone(),
                        target_snapshot_digest: snapshot.target_snapshot_digest.clone(),
                        signed_profile_digest: snapshot.signed_profile_digest.clone(),
                        control_commit_index: inner.state.commit_index,
                    };
                    if let Some(previous) = &selected {
                        if previous.workload != next.workload
                            || previous.signed_profile_digest != next.signed_profile_digest
                            || previous.policy_source_revision_id != next.policy_source_revision_id
                        {
                            return Ok(unresolved(Missing::AmbiguousWorkloadFact));
                        }
                    } else {
                        selected = Some(next);
                    }
                }
            }
        }
        drop(inner);
        if let Some(pin) = selected {
            if crate::workload_target_fact_digest(&pin.workload)? != pin.binding.subject_revision {
                return Ok(unresolved(Missing::PolicyContextMismatch));
            }
            Ok(DiscoveryContextJoinV1::Available(Box::new(pin)))
        } else {
            Ok(unresolved(Missing::MissingWorkloadFact))
        }
    }
}
