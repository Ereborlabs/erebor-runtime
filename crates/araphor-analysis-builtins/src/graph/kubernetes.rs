use super::*;

impl Computation {
    pub(super) fn kubernetes_unit(&mut self, row: u32) -> sdk::Result<Option<UnitState>> {
        let mut state = None;
        for index in self.fact_rows[row as usize].clone() {
            if let Some(marker) = self.kubernetes_fact(index)? {
                state = Some(UnitState {
                    state: GraphPackageStateV1::from_marker(marker)?,
                    position: self.records[row as usize].position,
                    fact: Some(self.facts[index].key.clone()),
                });
            }
        }
        Ok(state)
    }

    fn kubernetes_fact(&mut self, index: usize) -> sdk::Result<Option<&'static str>> {
        let FactValue::Kubernetes(stage) = &self.facts[index].value else {
            return Ok(None);
        };
        let stage = stage.clone();
        let record = self.facts[index].record;
        self.record(record)?;
        self.subject(record, None)?;
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
        if stage.object_uid.is_some() {
            self.edge(
                record,
                Some(index as u32),
                EdgeKind::Kubernetes,
                Cause::Contextual,
                vec![record],
            )?;
        }
        missing.push("CROSS_NODE_CAUSALITY_UNQUALIFIED".into());
        missing.sort();
        self.finding(
            record,
            "KUBERNETES_PROOF_MISSING",
            false,
            vec![record],
            missing,
        )?;
        Ok(Some(Self::kubernetes_state(&stage)))
    }

    fn kubernetes_state(stage: &KubernetesStageProofV1) -> &'static str {
        if !stage.proof_quality.kubernetes_qualified() {
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
    }
}
