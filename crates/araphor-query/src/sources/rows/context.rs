use araphor_data::{
    AnalysisContextVersionV1, DiscoveryContextKindV1, DiscoveryContextRevisionV1, ProjectionSink,
    WorkloadTargetFactV1,
};
use datafusion::common::ScalarValue;

use super::{ArrowBatch, Capture};

impl Capture<'_> {
    pub(super) fn context(
        &mut self,
        context: &AnalysisContextVersionV1,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        let document = if self.requested.contains_key("context")
            && context.key.owner_id == "discovery-context-v1"
        {
            sink.charge(context.body.len().saturating_mul(2))?;
            Some(DiscoveryContextRevisionV1::try_from(context)?)
        } else {
            None
        };
        for table in ["context_versions", "context"] {
            if !self.append(table, sink, |name, _kind, sink| {
                let doc = document.as_ref().map(|value| &value.document);
                match name {
                    "tenant_id" => Self::binary(Some(&context.key.tenant_id), sink),
                    "owner_id" => Self::text(Some(&context.key.owner_id), sink),
                    "entity_key" => Self::binary(Some(&context.key.entity_key), sink),
                    "lifetime_key" => Self::binary(Some(&context.key.lifetime_key), sink),
                    "owner_revision" => Ok(ScalarValue::UInt64(Some(context.key.owner_revision))),
                    "valid_from_utc_ns" => Ok(ScalarValue::UInt64(context.valid_from_utc_ns)),
                    "valid_until_utc_ns" => Ok(ScalarValue::UInt64(context.valid_until_utc_ns)),
                    "sensitivity" => Self::text(Some(context.sensitivity.into()), sink),
                    "body" => Self::binary(Some(&context.body), sink),
                    "kind" => Self::text(
                        doc.map(|value| match value.kind {
                            DiscoveryContextKindV1::Runbook => "RUNBOOK",
                            DiscoveryContextKindV1::WorkloadOwnership => "WORKLOAD_OWNERSHIP",
                            DiscoveryContextKindV1::DeploymentChange => "DEPLOYMENT_CHANGE",
                            DiscoveryContextKindV1::ReviewedAssessment => "REVIEWED_ASSESSMENT",
                            DiscoveryContextKindV1::ThreatReference => "THREAT_REFERENCE",
                        }),
                        sink,
                    ),
                    "subject_owner_id" => {
                        Self::text(doc.map(|value| value.subject.owner_id.as_str()), sink)
                    }
                    "subject_entity_key" => {
                        Self::binary(doc.map(|value| value.subject.entity_key.as_slice()), sink)
                    }
                    "subject_lifetime_key" => {
                        Self::binary(doc.map(|value| value.subject.lifetime_key.as_slice()), sink)
                    }
                    "subject_revision" => Ok(ScalarValue::UInt64(
                        doc.map(|value| value.subject.owner_revision),
                    )),
                    "method_id" => Self::text(doc.map(|value| value.method.id.as_str()), sink),
                    "method_revision" => {
                        Ok(ScalarValue::UInt64(doc.map(|value| value.method.revision)))
                    }
                    "origin" => Self::text(doc.map(|value| value.origin.as_str()), sink),
                    "trust" => Self::text(
                        doc.map(|value| {
                            if value.approver.is_some() {
                                "REVIEWED"
                            } else {
                                "UNREVIEWED"
                            }
                        }),
                        sink,
                    ),
                    "imported_utc_ns" => Ok(ScalarValue::UInt64(
                        document.as_ref().map(|value| value.imported_utc_ns),
                    )),
                    "approver" => Self::text(doc.and_then(|value| value.approver.as_deref()), sink),
                    "text" => Self::text(doc.map(|value| value.text.as_str()), sink),
                    _ => Err(ArrowBatch::invalid(
                        "the native source field has no adapter",
                    )),
                }
            })? {
                return Ok(false);
            }
        }
        if self.sources.contains("targets") && context.key.owner_id == "mithril-control/target" {
            sink.charge(context.body.len().saturating_mul(2))?;
            let fact: WorkloadTargetFactV1 =
                serde_json::from_slice(&context.body).map_err(|source| {
                    araphor_data::Error::PackageEncoding {
                        source,
                        location: snafu::location!(),
                    }
                })?;
            self.target(context, &fact, sink)
        } else {
            Ok(true)
        }
    }

    pub(super) fn target(
        &mut self,
        context: &AnalysisContextVersionV1,
        fact: &WorkloadTargetFactV1,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
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
        self.append("targets", sink, |name, _kind, sink| match name {
            "tenant_id" => Self::binary(Some(&context.key.tenant_id), sink),
            "entity_key" => Self::binary(Some(&context.key.entity_key), sink),
            "lifetime_key" => Self::binary(Some(&context.key.lifetime_key), sink),
            "owner_revision" => Ok(ScalarValue::UInt64(Some(context.key.owner_revision))),
            "node_id" => Self::text(Some(&fact.node_id), sink),
            "node_boot_id" => {
                Self::binary(boot.as_ref().map(|value| value.as_bytes().as_slice()), sink)
            }
            "label_epoch" => Ok(ScalarValue::UInt64(kube.map(|value| value.label_epoch))),
            "binding_id" => Self::binary(
                binding.as_ref().map(|value| value.as_bytes().as_slice()),
                sink,
            ),
            "workload_binding_generation_digest" => {
                Self::text(Some(&fact.workload_binding_generation_digest), sink)
            }
            "execution_set_id" => Self::text(Some(&fact.execution_set_id), sink),
            "cluster_uid" => Self::text(Some(&fact.cluster_uid), sink),
            "namespace_uid" => Self::text(Some(&fact.namespace_uid), sink),
            "controller_uid" => Self::text(Some(&fact.controller_uid), sink),
            "service_account_uid" => Self::text(Some(&fact.service_account_uid), sink),
            "pod_uid" => Self::text(Some(&fact.pod_uid), sink),
            "container_id" => Self::text(Some(&fact.container_id), sink),
            "container_name" => Self::text(Some(&fact.container_name), sink),
            "container_kind" => Self::text(
                Some(match fact.container_kind {
                    araphor_data::ContainerKindV1::Init => "INIT",
                    araphor_data::ContainerKindV1::Sidecar => "SIDECAR",
                    araphor_data::ContainerKindV1::Application => "APPLICATION",
                    araphor_data::ContainerKindV1::Ephemeral => "EPHEMERAL",
                }),
                sink,
            ),
            "image_digest" => Self::text(Some(&fact.image_digest), sink),
            "pod_labels" => Self::json(&fact.pod_labels, sink),
            "namespace_name" => Self::text(kube.map(|value| value.namespace_name.as_str()), sink),
            "pod_name" => Self::text(kube.map(|value| value.pod_name.as_str()), sink),
            "profile_id" => Self::text(kube.map(|value| value.profile_id.as_str()), sink),
            "policy_source_revision_id" => Self::text(
                kube.map(|value| value.policy_source_revision_id.as_str()),
                sink,
            ),
            "protected_scope_id" => {
                Self::text(kube.map(|value| value.protected_scope_id.as_str()), sink)
            }
            "workload_selector_id" => {
                Self::text(kube.map(|value| value.workload_selector_id.as_str()), sink)
            }
            "kubernetes_node_name" => {
                Self::text(kube.map(|value| value.kubernetes_node_name.as_str()), sink)
            }
            "kubernetes_node_uid" => {
                Self::text(kube.map(|value| value.kubernetes_node_uid.as_str()), sink)
            }
            _ => Err(ArrowBatch::invalid(
                "the native source field has no adapter",
            )),
        })
    }
}
