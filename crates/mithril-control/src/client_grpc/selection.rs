use araphor_data::AnalysisSelectionV1;
use tonic::Status;

use super::{proto, ClientGrpcOwner};
use crate::WorkloadTargetFactV1;

struct Locator<'a> {
    kind: &'a str,
    namespace: Option<&'a str>,
    name: &'a str,
}

impl<'a> TryFrom<&'a str> for Locator<'a> {
    type Error = Status;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let parts: Vec<_> = value.split('/').collect();
        let locator = match parts.as_slice() {
            ["pod", namespace, name] => Self {
                kind: "pod",
                namespace: Some(namespace),
                name,
            },
            [kind @ ("node" | "binding" | "pod-uid" | "controller"), name] => Self {
                kind,
                namespace: None,
                name,
            },
            _ => {
                return Err(Status::invalid_argument(
                    "The target locator is unsupported.",
                ))
            }
        };
        if parts
            .iter()
            .any(|part| part.is_empty() || part.len() > 256 || part.chars().any(char::is_control))
        {
            return Err(Status::invalid_argument("The target locator is invalid."));
        }
        Ok(locator)
    }
}

impl Locator<'_> {
    fn matches(&self, fact: &WorkloadTargetFactV1) -> bool {
        match self.kind {
            "node" => fact.node_id == self.name,
            "pod-uid" => fact.pod_uid == self.name,
            "controller" => fact.controller_uid == self.name,
            "binding" => fact
                .kubernetes
                .as_ref()
                .is_some_and(|identity| identity.binding_id == self.name),
            "pod" => fact.kubernetes.as_ref().is_some_and(|identity| {
                Some(identity.namespace_name.as_str()) == self.namespace
                    && identity.pod_name == self.name
            }),
            _ => false,
        }
    }
}

impl ClientGrpcOwner {
    pub(super) fn select(
        &self,
        input: Option<proto::InputSelection>,
        tenant: [u8; 16],
    ) -> Result<AnalysisSelectionV1, Status> {
        let mut selection = AnalysisSelectionV1::tenant(tenant);
        let Some(input) = input else {
            return Ok(selection);
        };
        Self::selection_shape(&input)?;
        if input.target.is_empty() {
            if !input.cluster.is_empty() || !input.container.is_empty() {
                return Err(Status::invalid_argument(
                    "Cluster and container require a target.",
                ));
            }
            selection.nodes = input.node_ids;
            return Ok(selection);
        }
        let locator = Locator::try_from(input.target.as_str())?;
        if locator.kind == "node" && input.cluster.is_empty() && input.container.is_empty() {
            if self.control.evidence_tenant(locator.name).ok() != Some(tenant) {
                return Err(Status::not_found(
                    "The target Node is absent from this tenant.",
                ));
            }
            if !input.node_ids.is_empty() && !input.node_ids.iter().any(|node| node == locator.name)
            {
                return Err(Status::invalid_argument(
                    "The selected nodes exclude the target.",
                ));
            }
            selection.nodes = vec![locator.name.to_owned()];
            return Ok(selection);
        }
        let facts = self.facts(&input, tenant)?;
        selection.nodes = facts.iter().map(|fact| fact.node_id.clone()).collect();
        selection.nodes.sort();
        selection.nodes.dedup();
        if !input.node_ids.is_empty() {
            selection.nodes.retain(|node| input.node_ids.contains(node));
            if selection.nodes.is_empty() {
                return Err(Status::invalid_argument(
                    "The selected nodes exclude the target.",
                ));
            }
        }
        if !input.target.starts_with("node/") {
            for fact in facts {
                let binding = fact.kubernetes.as_ref().ok_or_else(|| {
                    Status::unimplemented("This target has no retained evidence binding.")
                })?;
                let id = uuid::Uuid::parse_str(&binding.binding_id).map_err(|_| {
                    Status::failed_precondition("The inventory binding ID is invalid.")
                })?;
                selection.binding_ids.push(*id.as_bytes());
            }
            selection.binding_ids.sort();
            selection.binding_ids.dedup();
        }
        Ok(selection)
    }

    pub(super) fn facts(
        &self,
        input: &proto::InputSelection,
        tenant: [u8; 16],
    ) -> Result<Vec<WorkloadTargetFactV1>, Status> {
        Self::selection_shape(input)?;
        let locator = Locator::try_from(input.target.as_str())?;
        let mut facts = Vec::new();
        for fact in self.control.workload_inventory() {
            if self.control.evidence_tenant(&fact.node_id).ok() != Some(tenant)
                || !locator.matches(&fact)
                || (!input.cluster.is_empty() && input.cluster != fact.cluster_uid)
                || (!input.container.is_empty() && input.container != fact.container_name)
            {
                continue;
            }
            facts.push(fact);
            if facts.len() > crate::MAX_TRACE_TARGETS {
                return Err(Status::resource_exhausted(
                    "The selected target cohort is too large.",
                ));
            }
        }
        if facts.is_empty() {
            return Err(Status::not_found(
                "No retained tenant inventory matches this target.",
            ));
        }
        let clusters: std::collections::BTreeSet<_> =
            facts.iter().map(|fact| &fact.cluster_uid).collect();
        if clusters.len() != 1 {
            return Err(Status::invalid_argument(
                "The target requires an exact cluster UID.",
            ));
        }
        facts.sort();
        Ok(facts)
    }

    pub(super) fn selection_shape(input: &proto::InputSelection) -> Result<(), Status> {
        for value in [&input.target, &input.cluster, &input.container] {
            if value.len() > 256 || value.chars().any(char::is_control) {
                return Err(Status::invalid_argument("The input selection is invalid."));
            }
        }
        if input.node_ids.len() > 1024
            || input
                .node_ids
                .iter()
                .any(|node| !araphor_data::node_id_is_valid(node))
            || input
                .node_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != input.node_ids.len()
        {
            return Err(Status::invalid_argument(
                "The input node selection is invalid.",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_grpc_locator() {
        for value in [
            "pod/team/api",
            "pod-uid/uid",
            "node/node-1",
            "binding/id",
            "controller/uid",
        ] {
            assert!(Locator::try_from(value).is_ok(), "{value}");
        }
        for value in [
            "",
            "pod/api",
            "pod//api",
            "pod/team/api/extra",
            "unknown/id",
            "node/\n",
        ] {
            assert!(Locator::try_from(value).is_err(), "{value:?}");
        }
    }
}
