use super::*;

impl Computation {
    pub(super) fn kubernetes(&mut self) -> sdk::Result<()> {
        for index in 0..self.facts.len() {
            let fact = self.facts[index].clone();
            let FactValue::Kubernetes(stage) = fact.value else {
                continue;
            };
            self.record(fact.record)?;
            self.subjects.push(Subject {
                record: fact.record,
                context: None,
            });
            let mut missing = Vec::new();
            for (proved, name) in [
                (stage.request, "CARRIED_REQUEST_MISSING"),
                (stage.audit, "KUBERNETES_AUDIT_MISSING"),
                (stage.object && stage.version, "OBJECT_VERSION_MISSING"),
                (stage.owner && stage.pod, "OWNER_POD_BRIDGE_MISSING"),
                (stage.node, "SCHEDULER_NODE_MISSING"),
                (
                    stage.container && stage.admission,
                    "REMOTE_RUNTIME_ADMISSION_MISSING",
                ),
                (stage.qualified, "KUBERNETES_SOURCE_QUALIFICATION_MISSING"),
            ] {
                if !proved {
                    missing.push(name.into());
                }
            }
            self.state.value = if !stage.qualified {
                "KUBERNETES_PROOF_MISSING"
            } else if stage.container && stage.admission {
                "REMOTE_ADMISSION"
            } else if stage.node {
                "KUBERNETES_SCHEDULED"
            } else if stage.object && stage.version {
                "KUBERNETES_OBJECT"
            } else if stage.audit {
                "KUBERNETES_AUDIT"
            } else if stage.request {
                "KUBERNETES_REQUEST"
            } else {
                "KUBERNETES_PROOF_MISSING"
            }
            .into();
            if stage.object {
                self.edge(
                    fact.record,
                    Some(index as u64),
                    EdgeKind::Kubernetes,
                    Cause::Contextual,
                    vec![fact.record],
                );
            }
            missing.push("CROSS_NODE_CAUSALITY_UNQUALIFIED".into());
            missing.sort();
            self.finding(
                fact.record,
                "KUBERNETES_PROOF_MISSING",
                false,
                vec![fact.record],
                missing,
            );
        }
        Ok(())
    }
}
