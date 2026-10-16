use super::*;

impl GraphDerivation<'_> {
    pub(super) fn facts(&self, record: &DiscoveryRecordV1) -> Vec<GraphFactV1> {
        self.facts
            .iter()
            .filter(|fact| fact.record_id == record.id)
            .cloned()
            .collect()
    }

    pub(super) fn policies(
        &self,
        record: &DiscoveryRecordV1,
    ) -> Vec<PolicyObservationProvenanceV1> {
        let generation = record
            .decode()
            .ok()
            .and_then(|wire| wire.profile_generation_ref_id)
            .unwrap_or_default();
        let policies: Vec<_> = self
            .facts(record)
            .into_iter()
            .filter_map(|fact| match fact.value {
                GraphFactValueV1::Policy(policy)
                    if policy.profile_generation_ref_id == generation =>
                {
                    Some(policy)
                }
                _ => None,
            })
            .collect();
        let exact_chains: BTreeSet<_> = policies
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
                    || !exact_chains.contains(&(
                        policy.policy_source_revision_id.clone(),
                        policy.candidate_content_id.clone(),
                        policy.target_snapshot_digest.clone(),
                    ))
            })
            .collect()
    }

    pub(super) fn reviewed_policy(&self, record: &DiscoveryRecordV1, revision: &str) -> bool {
        let policies: Vec<_> = self
            .policies(record)
            .into_iter()
            .filter(|policy| policy.policy_source_revision_id.as_deref() == Some(revision))
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
        exact.len() == 1
            && policies
                .iter()
                .all(|policy| policy.state != PolicyProvenanceStateV1::Contradicted)
    }

    pub(super) fn policy_conflict(&self, record: &DiscoveryRecordV1) -> bool {
        let policies = self.policies(record);
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
        exact.len() > 1
            || policies
                .iter()
                .any(|policy| policy.state == PolicyProvenanceStateV1::Contradicted)
    }
}
