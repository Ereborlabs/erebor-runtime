use super::*;

impl Computation {
    pub(super) fn kubernetes(&mut self) -> sdk::Result<()> {
        for index in 0..self.facts.len() {
            let fact = self.facts[index].clone();
            let FactValue::Kubernetes(stage) = fact.value else {
                continue;
            };
            self.record(fact.record)?;
            self.subject(fact.record, None)?;
            let qualified = stage.proof_quality.kubernetes_qualified();
            let mut missing = Vec::new();
            for (proved, name) in [
                (
                    stage.carried_request_id.is_some(),
                    "CARRIED_REQUEST_MISSING",
                ),
                (stage.audit_id.is_some(), "KUBERNETES_AUDIT_MISSING"),
                (
                    stage.object_uid.is_some() && stage.resource_version.is_some(),
                    "OBJECT_VERSION_MISSING",
                ),
                (
                    stage.owner_uid.is_some() && stage.pod_uid.is_some(),
                    "OWNER_POD_BRIDGE_MISSING",
                ),
                (stage.node_id.is_some(), "SCHEDULER_NODE_MISSING"),
                (
                    stage.full_container_id.is_some() && stage.remote_admission_id.is_some(),
                    "REMOTE_RUNTIME_ADMISSION_MISSING",
                ),
                (qualified, "KUBERNETES_SOURCE_QUALIFICATION_MISSING"),
            ] {
                if !proved {
                    missing.push(name.into());
                }
            }
            self.state.value = if !qualified {
                "KUBERNETES_PROOF_MISSING"
            } else if stage.full_container_id.is_some() && stage.remote_admission_id.is_some() {
                "REMOTE_ADMISSION"
            } else if stage.node_id.is_some() {
                "KUBERNETES_SCHEDULED"
            } else if stage.object_uid.is_some() && stage.resource_version.is_some() {
                "KUBERNETES_OBJECT"
            } else if stage.audit_id.is_some() {
                "KUBERNETES_AUDIT"
            } else if stage.carried_request_id.is_some() {
                "KUBERNETES_REQUEST"
            } else {
                "KUBERNETES_PROOF_MISSING"
            }
            .into();
            if stage.object_uid.is_some() {
                self.edge(
                    fact.record,
                    Some(index as u32),
                    EdgeKind::Kubernetes,
                    Cause::Contextual,
                    vec![fact.record],
                )?;
            }
            missing.push("CROSS_NODE_CAUSALITY_UNQUALIFIED".into());
            missing.sort();
            self.finding(
                fact.record,
                "KUBERNETES_PROOF_MISSING",
                false,
                vec![fact.record],
                missing,
            )?;
        }
        Ok(())
    }
}
