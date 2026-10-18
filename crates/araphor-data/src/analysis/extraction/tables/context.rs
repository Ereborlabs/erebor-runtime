use super::*;
use crate::{
    AnalysisContextVersionV1, DiscoveryContextKindV1, DiscoveryContextRevisionV1, TargetContextV1,
};

impl Capture<'_> {
    pub(in crate::analysis::extraction) fn context(
        &mut self,
        context: &AnalysisContextVersionV1,
        budget: &mut ReadBudget<'_>,
    ) -> Result<bool> {
        let document = if self.read.projected("context").is_some()
            && context.key.owner_id == "discovery-context-v1"
        {
            budget.charge(context.body.len().saturating_mul(2))?;
            Some(DiscoveryContextRevisionV1::try_from(context)?)
        } else {
            None
        };
        for relation in ["context_versions", "context"] {
            if !self.context_row(relation, context, document.as_ref(), budget)? {
                return Ok(false);
            }
        }
        if self.read.requests.contains_key("targets")
            && context.key.owner_id == "mithril-control/target"
        {
            budget.charge(context.body.len().saturating_mul(2))?;
            let target: TargetContextV1 =
                serde_json::from_slice(&context.body).map_err(|source| {
                    crate::Error::PackageEncoding {
                        source,
                        location: snafu::location!(),
                    }
                })?;
            self.target(context, &target, budget)
        } else {
            Ok(true)
        }
    }

    table_row! {
        fn target(
            &mut self,
            context: &AnalysisContextVersionV1,
            target: &TargetContextV1,
            budget: &mut ReadBudget<'_>,
        );
        schema target_fields;
        row(self, "targets", budget);
        setup {
            let fact = &target.workload;
            let kube = fact.kubernetes.as_ref();
            let boot = kube.and_then(|value| uuid::Uuid::parse_str(&value.node_boot_id).ok());
            let binding = kube.and_then(|value| uuid::Uuid::parse_str(&value.binding_id).ok());
            if (!self.scope.nodes.is_empty() && !self.scope.nodes.contains(&fact.node_id))
                || (!self.scope.binding_ids.is_empty()
                    && binding
                        .as_ref()
                        .is_none_or(|binding| !self.scope.binding_ids.contains(binding.as_bytes())))
            {
                return Ok(true);
            }
        }
        fields {
            tenant_id => Binary(false):Some(&context.key.tenant_id),
            entity_key => Binary(false):Some(&context.key.entity_key),
            lifetime_key => Binary(false):Some(&context.key.lifetime_key),
            owner_revision => UInt64(false):Some(context.key.owner_revision),
            node_id => Utf8(false):Some(&fact.node_id),
            node_boot_id => Binary(true):boot.as_ref().map(|value|value.as_bytes().as_slice()),
            label_epoch => UInt64(true):kube.map(|value|value.label_epoch),
            binding_id => Binary(true):binding.as_ref().map(|value|value.as_bytes().as_slice()),
            workload_binding_generation_digest => Utf8(false):Some(&fact.workload_binding_generation_digest),
            execution_set_id => Utf8(false):Some(&fact.execution_set_id),
            cluster_uid => Utf8(false):Some(&fact.cluster_uid),
            namespace_uid => Utf8(false):Some(&fact.namespace_uid),
            controller_uid => Utf8(false):Some(&fact.controller_uid),
            service_account_uid => Utf8(false):Some(&fact.service_account_uid),
            pod_uid => Utf8(false):Some(&fact.pod_uid),
            container_id => Utf8(false):Some(&fact.container_id),
            container_name => Utf8(false):Some(&fact.container_name),
            container_kind => Utf8(false):Some(match fact.container_kind {crate::ContainerKindV1::Init=>"INIT",crate::ContainerKindV1::Sidecar=>"SIDECAR",crate::ContainerKindV1::Application=>"APPLICATION",crate::ContainerKindV1::Ephemeral=>"EPHEMERAL"}),
            image_digest => Utf8(false):Some(&fact.image_digest),
            pod_labels => Json(false):Some(&fact.pod_labels),
            namespace_name => Utf8(true):kube.map(|value|value.namespace_name.as_str()),
            pod_name => Utf8(true):kube.map(|value|value.pod_name.as_str()),
            profile_id => Utf8(true):kube.map(|value|value.profile_id.as_str()),
            policy_source_revision_id => Utf8(true):kube.map(|value|value.policy_source_revision_id.as_str()),
            source_revision_id => Utf8(false):Some(&target.policy_source_revision_id),
            target_snapshot_digest => Utf8(false):Some(&target.target_snapshot_digest),
            signed_profile_digest => Utf8(false):Some(&target.signed_profile_digest),
            protected_scope_id => Utf8(true):kube.map(|value|value.protected_scope_id.as_str()),
            workload_selector_id => Utf8(true):kube.map(|value|value.workload_selector_id.as_str()),
            kubernetes_node_name => Utf8(true):kube.map(|value|value.kubernetes_node_name.as_str()),
            kubernetes_node_uid => Utf8(true):kube.map(|value|value.kubernetes_node_uid.as_str()),
        }
    }

    table_row! {
        fn context_row(
            &mut self,
            relation: &str,
            context: &AnalysisContextVersionV1,
            document: Option<&DiscoveryContextRevisionV1>,
            budget: &mut ReadBudget<'_>,
        );
        schema context_fields;
        prefix version_fields {
            tenant_id => Binary(false):Some(&context.key.tenant_id),
            owner_id => Utf8(false):Some(&context.key.owner_id),
            entity_key => Binary(false):Some(&context.key.entity_key),
            lifetime_key => Binary(false):Some(&context.key.lifetime_key),
            owner_revision => UInt64(false):Some(context.key.owner_revision),
            valid_from_utc_ns => UInt64(true):context.valid_from_utc_ns,
            valid_until_utc_ns => UInt64(true):context.valid_until_utc_ns,
            sensitivity => Utf8(false):Some(<&str>::from(context.sensitivity)),
            body => Binary(false):Some(&context.body),
        }
        row(self, relation, budget);
        setup {
            let doc = document.map(|value| &value.document);
        }
        fields {
            kind => Utf8(true):doc.map(|value|match value.kind {
                DiscoveryContextKindV1::Runbook=>"RUNBOOK",
                DiscoveryContextKindV1::WorkloadOwnership=>"WORKLOAD_OWNERSHIP",
                DiscoveryContextKindV1::DeploymentChange=>"DEPLOYMENT_CHANGE",
                DiscoveryContextKindV1::ReviewedAssessment=>"REVIEWED_ASSESSMENT",
                DiscoveryContextKindV1::ThreatReference=>"THREAT_REFERENCE",
            }),
            subject_owner_id => Utf8(true):doc.map(|value|value.subject.owner_id.as_str()),
            subject_entity_key => Binary(true):doc.map(|value|value.subject.entity_key.as_slice()),
            subject_lifetime_key => Binary(true):doc.map(|value|value.subject.lifetime_key.as_slice()),
            subject_revision => UInt64(true):doc.map(|value|value.subject.owner_revision),
            method_id => Utf8(true):doc.map(|value|value.method.id.as_str()),
            method_revision => UInt64(true):doc.map(|value|value.method.revision),
            origin => Utf8(true):doc.map(|value|value.origin.as_str()),
            trust => Utf8(true):doc.map(|value|if value.approver.is_some(){"REVIEWED"}else{"UNREVIEWED"}),
            imported_utc_ns => UInt64(true):document.as_ref().map(|value|value.imported_utc_ns),
            approver => Utf8(true):doc.and_then(|value|value.approver.as_deref()),
            text => Utf8(true):doc.map(|value|value.text.as_str()),
        }
    }
}
