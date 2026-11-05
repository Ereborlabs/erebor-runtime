use super::*;

impl Computation {
    pub(super) fn policies(&self, row: u32) -> sdk::Result<Vec<PolicyObservationProvenanceV1>> {
        Ok(self
            .record(row)?
            .policies(self.facts(row).map(|(_, fact)| fact)))
    }

    pub(super) fn reviewed(&self, fact: &Fact) -> sdk::Result<bool> {
        let revision = match &fact.value {
            FactValue::Baseline {
                reviewed_policy_revision,
                ..
            }
            | FactValue::Credential {
                reviewed_policy_revision,
                ..
            } => reviewed_policy_revision,
            _ => return Ok(false),
        };
        let policies: Vec<_> = self
            .policies(fact.record)?
            .into_iter()
            .filter(|policy| policy.policy_source_revision_id.as_ref() == Some(revision))
            .collect();
        let exact: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    &policy.candidate_content_id,
                    &policy.target_snapshot_digest,
                    &policy.node_bound_generation_digest,
                )
            })
            .collect();
        Ok(exact.len() == 1
            && policies
                .iter()
                .all(|policy| policy.state != PolicyProvenanceStateV1::Contradicted))
    }

    pub(super) fn policy_conflict(&self, row: u32) -> sdk::Result<bool> {
        let policies = self.policies(row)?;
        let exact: BTreeSet<_> = policies
            .iter()
            .filter(|policy| policy.state == PolicyProvenanceStateV1::Exact)
            .map(|policy| {
                (
                    &policy.policy_source_revision_id,
                    &policy.candidate_content_id,
                    &policy.target_snapshot_digest,
                    &policy.node_bound_generation_digest,
                )
            })
            .collect();
        Ok(exact.len() > 1
            || policies
                .iter()
                .any(|policy| policy.state == PolicyProvenanceStateV1::Contradicted))
    }
}
