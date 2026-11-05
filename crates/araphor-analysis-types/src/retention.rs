use crate::{FindingMember,FindingStateV1,GraphCauseV1,RelationshipChange,TemporalCoverageV1};

impl RelationshipChange {
    pub fn retained_expiry(&self) -> Self {
        let mut value = self.clone();
        value.key.cause = GraphCauseV1::Superseded;
        value.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
        value
    }
}

impl FindingMember {
    pub fn retained_expiry(&self) -> Self {
        let mut value = self.clone();
        value.value.state = FindingStateV1::CoverageInsufficient;
        value.value.limits.extend(["RETAINED_INPUT_EXPIRED".into(),"LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into()]);
        value.value.limits.sort();
        value.value.limits.dedup();
        for effect in &mut value.value.effects {
            effect.proof_quality.temporal_coverage = TemporalCoverageV1::Unknown;
        }
        value
    }
}
