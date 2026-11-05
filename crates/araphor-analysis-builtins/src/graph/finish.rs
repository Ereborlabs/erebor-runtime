use super::*;

impl Detector {
    fn required_inputs(self) -> &'static [&'static str] {
        match self {
            Self::Credentials => &[
                "reviewed-credential",
                "exact-local-channel",
                "authoritative-operation",
                "source-coverage",
            ],
        }
    }
}

pub trait CheckpointExt {
    fn from_package(
        package: &sdk::Package,
        model: &sdk::Model,
        state: GraphPackageStateV1,
        accepted: u64,
        observed: u64,
    ) -> Self;
}
impl CheckpointExt for GraphPackageCheckpointV1 {
    fn from_package(
        package: &sdk::Package,
        model: &sdk::Model,
        state: GraphPackageStateV1,
        accepted: u64,
        observed: u64,
    ) -> Self {
        Self {
            package_id: package.id.clone(),
            package_version: 1,
            required_inputs: Detector::from_id(&package.id).map_or_else(
                |_| {
                    model
                        .inputs
                        .iter()
                        .map(|input| input.port.name.clone())
                        .collect()
                },
                |detector| {
                    detector
                        .required_inputs()
                        .iter()
                        .map(|value| (*value).into())
                        .collect()
                },
            ),
            state,
            maximum_lateness_ns: GRAPH_WITNESS_TTL_NS,
            retention_ttl_ns: GRAPH_WITNESS_TTL_NS,
            clock_uncertainty_ns: None,
            late_action: "append-exact-revision-or-report-expired-input".into(),
            window_ns: GRAPH_WINDOW_NS,
            coverage_predicate:
                "complete-required-source-intervals-and-qualified-operation-results".into(),
            replay_contract_id: format!("{}/v{}", package.id, package.revision),
            result_states: vec![
                FindingStateV1::Provisional,
                FindingStateV1::Confirmed,
                FindingStateV1::Superseded,
                FindingStateV1::Retracted,
                FindingStateV1::CoverageInsufficient,
            ],
            accepted_cursor_watermark: accepted,
            observed_boottime_watermark_ns: observed,
        }
    }
}

impl Computation {
    pub(super) fn canonical(evidence: &mut Vec<u32>) {
        evidence.sort_unstable();
        evidence.dedup();
    }
}

pub trait BranchExt {
    fn from_finding(finding: &Finding, reason: &FindingReasonV1) -> Self;
    fn from_value(finding: &FindingV1) -> Self;
    fn from_parts(
        package_id: &str,
        subject_id: &GraphSubjectKeyV1,
        evidence: &[crate::discovery::DiscoveryRecordIdV1],
        limits: &[String],
        reason: &FindingReasonV1,
    ) -> Self;
}
impl BranchExt for GraphBranchV1 {
    fn from_finding(finding: &Finding, reason: &FindingReasonV1) -> Self {
        Self::from_parts(
            &finding.package_id,
            &finding.subject_id,
            &finding.evidence,
            &finding.limits,
            reason,
        )
    }

    fn from_value(finding: &FindingV1) -> Self {
        Self::from_parts(
            &finding.package_id,
            &finding.subject_id,
            &finding.evidence,
            &finding.limits,
            &finding.reason,
        )
    }

    fn from_parts(
        package_id: &str,
        subject_id: &GraphSubjectKeyV1,
        evidence: &[crate::discovery::DiscoveryRecordIdV1],
        limits: &[String],
        reason: &FindingReasonV1,
    ) -> Self {
        Self {
            package_id: package_id.into(),
            seed: subject_id.clone(),
            evidence: evidence.to_vec(),
            state: if matches!(reason, FindingReasonV1::OutsideAuthority) {
                GraphBranchStateV1::OutsideAuthority
            } else if limits.iter().any(|limit| {
                limit.contains("COVERAGE")
                    || limit.contains("MISSING")
                    || limit.contains("UNAVAILABLE")
            }) {
                GraphBranchStateV1::CoverageUnknown
            } else if matches!(reason, FindingReasonV1::ContextualCredentialPivot) {
                GraphBranchStateV1::ContextualOnly
            } else {
                GraphBranchStateV1::Open
            },
            missing_fields: limits.to_vec(),
        }
    }
}
